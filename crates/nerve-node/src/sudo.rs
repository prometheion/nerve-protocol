//! The node's sudo switch (docs/dev/spec/node-local.md §4, docs/dev/spec/protocol.md §7.4.1).
//!
//! The switch is on only while the node holds a sudo password that `sudo -v`
//! accepted. On Linux the password lives in memory only: a restarted node
//! starts with the switch off. It is never part of a document, a result or
//! the audit log, and every outgoing frame is scrubbed of it.
//!
//! On Windows the password is the one of the account the commands run as,
//! checked by a logon that must hold the Administrators group, and the node
//! also keeps it with DPAPI in its config folder, which a restart reads
//! again (crate::winsudo).

use nerve_policy::config::Sudo;
use nerve_policy::{SetError, Writer};

use crate::daemon::{Shared, lock};

/// A password that is overwritten when it is dropped.
pub(crate) struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8.
        unsafe { self.0.as_bytes_mut().fill(0) };
    }
}

/// Why a center may not turn the switch on while root is the owner.
pub const ROOT_SUDO: &str = "root is the owner of this node, and sudo checks no password of root's, so no center turns sudo on here; root does, with `nerve-node sudo on` on this machine";

/// What stands in for the password where it would have appeared.
pub const REDACTED: &str = "[redacted]";

/// The copies of `secret` a text may carry: plain and JSON-escaped; none
/// for an empty one.
pub(crate) fn copies(secret: &str) -> Vec<String> {
    if secret.is_empty() {
        return Vec::new();
    }
    let quoted = serde_json::to_string(secret).unwrap_or_default();
    let escaped = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(secret)
        .to_string();
    vec![secret.to_string(), escaped]
}

/// `text` with every copy of `secret`, plain and JSON-escaped, replaced by
/// [`REDACTED`]; `None` when there is none.
pub fn scrub(text: &str, secret: &str) -> Option<String> {
    let mut out: Option<String> = None;
    for needle in copies(secret) {
        let cur = out.as_deref().unwrap_or(text);
        if cur.contains(&needle) {
            out = Some(cur.replace(&needle, REDACTED));
        }
    }
    out
}

impl Shared {
    /// Whether the switch is on: set in the config and a checked password
    /// held.
    pub fn sudo_on(&self) -> bool {
        // The store is always locked before the password, never after.
        let store = lock(&self.store);
        let held = lock(&self.sudo).is_some();
        held && store.config().machine.sudo == Sudo::On && self.same_account(&store)
    }

    /// Whether the owner is still the account the held password was checked
    /// for: a password is one account's.
    fn same_account(&self, store: &nerve_policy::SettingsStore) -> bool {
        *lock(&self.sudo_for) == self.owner_name(store.config())
    }

    /// The password for one allowed sudo command, while the switch is on.
    pub fn sudo_password(&self) -> Option<String> {
        let store = lock(&self.store);
        if store.config().machine.sudo != Sudo::On || !self.same_account(&store) {
            return None;
        }
        lock(&self.sudo).as_ref().map(|s| s.expose().to_string())
    }

    /// The sudo program (`machine.sudo_path`, else `sudo` from `PATH`).
    pub fn sudo_path(&self) -> String {
        self.config()
            .machine
            .sudo_path
            .unwrap_or_else(|| "sudo".into())
    }

    /// A copy of the sudo password the node holds, for what scrubs output
    /// as it comes (crate::tap).
    pub(crate) fn held_secret(&self) -> Option<Secret> {
        lock(&self.sudo)
            .as_ref()
            .map(|s| Secret::new(s.expose().to_string()))
    }

    /// `text` without the sudo password.
    pub fn scrub(&self, text: String) -> String {
        match lock(&self.sudo).as_ref() {
            Some(s) => scrub(&text, s.expose()).unwrap_or(text),
            None => text,
        }
    }

    /// Keeps `password` (or nothing) out of the log, whatever a message
    /// carries.
    fn log_secret(&self, password: Option<&str>) {
        if let Some(log) = &self.log {
            log.set_secret("sudo", password);
        }
    }

    /// Turns the switch on once `sudo -v` accepts `password`. A wrong
    /// password leaves the switch as it was.
    pub async fn sudo_switch_on(&self, by: Writer<'_>, password: String) -> Result<u64, SetError> {
        let password = Secret::new(password);
        if !cfg!(any(target_os = "linux", windows)) {
            return Err(SetError::Invalid(
                "the sudo switch works on Linux and Windows only".into(),
            ));
        }
        if let Writer::Center(c) = by {
            let grant = self.config().center(c).map(|e| e.settings);
            if grant != Some(nerve_policy::config::SettingsGrant::Write) {
                return Err(SetError::Forbidden(
                    "this node does not let this center change its settings".into(),
                ));
            }
        }
        // `sudo -v` as root takes any password, so with root as the owner
        // a password shows nothing: only root itself turns the switch on,
        // at the node (`nerve-node sudo on`), never a center.
        if let Writer::Center(_) = by
            && crate::owner::is_root(self.owner_name(&self.config()).as_deref())
        {
            return Err(SetError::Forbidden(ROOT_SUDO.into()));
        }
        if password.expose().is_empty() || password.expose().contains('\n') {
            return Err(SetError::Invalid(
                "the sudo password is empty or has a line break".into(),
            ));
        }
        // The password is the owner's, and sudo checks it: it shows that the
        // owner, who lets the sudo list run as root, may run commands as
        // root here. The sudo commands of the owner's own pairings run
        // through the owner's sudo with it; those of `nerve-run`'s pairings
        // are started as root by the node and do not use it (crate::link).
        let checked_for = self.owner_name(&self.config());
        let account = self
            .owner_account(&self.config())
            .map_err(SetError::Invalid)?;
        #[cfg(windows)]
        self.windows_check(account.as_ref(), &password).await?;
        #[cfg(not(windows))]
        crate::exec::sudo_check(&self.sudo_path(), password.expose(), account.as_ref())
            .await
            .map_err(SetError::Invalid)?;
        // Password and config change together, so `settle_sudo` never sees
        // one without the other.
        self.log_secret(Some(password.expose()));
        let r = {
            let mut store = lock(&self.store);
            *lock(&self.sudo) = Some(password);
            *lock(&self.sudo_for) = checked_for;
            let r = store.set_sudo(by, Sudo::On);
            if r.is_err() {
                *lock(&self.sudo) = None;
                #[cfg(windows)]
                let _ = crate::winsudo::forget(&self.paths);
            }
            r
        };
        if r.is_err() {
            self.log_secret(None);
        }
        self.bump();
        r
    }

    /// [`Shared::sudo_switch_on`]'s check on Windows (crate::winsudo): the
    /// installed node, and a logon of `account` with `password` that holds
    /// the Administrators group. The password is then kept with DPAPI.
    #[cfg(windows)]
    async fn windows_check(
        &self,
        account: Option<&crate::service::Account>,
        password: &Secret,
    ) -> Result<(), SetError> {
        let (account, paths) = (account.cloned(), self.paths.clone());
        let pw = Secret::new(password.expose().to_string());
        // A logon takes a moment; it does not hold up the other links.
        tokio::task::spawn_blocking(move || {
            let host = crate::win_host::WinHost;
            crate::winsudo::check(&host, account.as_ref(), pw.expose())?;
            let name = &account.as_ref().expect("checked").name;
            crate::winsudo::keep(&paths, &host, name, pw.expose())?;
            tracing::warn!("{}", crate::winsudo::warning(name));
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| SetError::Invalid(e.to_string()))?
        .map_err(SetError::Invalid)
    }

    /// Turns the switch off and drops the password and any open offer.
    pub fn sudo_switch_off(&self, by: Writer<'_>) -> Result<u64, SetError> {
        if let Writer::Center(c) = by {
            let grant = self.config().center(c).map(|e| e.settings);
            if grant != Some(nerve_policy::config::SettingsGrant::Write) {
                return Err(SetError::Forbidden(
                    "this node does not let this center change its settings".into(),
                ));
            }
        }
        // The kept password goes first: a node that stops now starts with
        // none (crate::winsudo).
        #[cfg(windows)]
        if let Err(e) = crate::winsudo::forget(&self.paths) {
            tracing::warn!("cannot remove the kept sudo password: {e}");
        }
        let r = {
            let mut store = lock(&self.store);
            *lock(&self.sudo) = None;
            store.set_sudo(by, Sudo::Off)
        };
        self.log_secret(None);
        lock(&self.sudo_offers).clear();
        self.bump();
        r
    }

    /// Brings the config and the held password in line: a config that says
    /// on without a password (a restart, an edited file) is switched off; a
    /// config that says off drops the password. On Windows the password kept
    /// with DPAPI is held first, and one held that is no longer kept is
    /// dropped (crate::winsudo).
    pub fn settle_sudo(&self) {
        let mut store = lock(&self.store);
        let on = store.config().machine.sudo == Sudo::On;
        let mut held = lock(&self.sudo);
        #[cfg(windows)]
        {
            use crate::winsudo::{Settle, kept, settle, stored};
            let user = store.config().machine.user.clone();
            match settle(on, held.is_some(), on && kept(&self.paths)) {
                Settle::Load => {
                    let host = crate::win_host::WinHost;
                    if let Some(pw) = stored(&self.paths, &host, user.as_deref()) {
                        self.log_secret(Some(&pw));
                        *held = Some(Secret::new(pw));
                        *lock(&self.sudo_for) = user;
                    }
                }
                Settle::Drop => {
                    *held = None;
                    self.log_secret(None);
                }
                Settle::Nothing => {}
            }
        }
        if on && held.is_none() {
            drop(held);
            if let Err(e) = store.set_sudo(Writer::Local, Sudo::Off) {
                tracing::warn!("cannot switch sudo off: {e:?}");
            }
            drop(store);
            self.bump();
        } else if !on && held.is_some() {
            *held = None;
            self.log_secret(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_plain_and_escaped_copies() {
        assert_eq!(scrub("no secret here", "pw\"1"), None);
        assert_eq!(
            scrub("a pw\"1 b", "pw\"1").as_deref(),
            Some("a [redacted] b")
        );
        let frame = serde_json::json!({"stdout": "pw\"1\n"}).to_string();
        let out = scrub(&frame, "pw\"1").unwrap();
        assert!(!out.contains("pw"), "{out}");
        assert_eq!(scrub("x", ""), None);
    }
}
