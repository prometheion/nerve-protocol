//! The node's secrets (docs/dev/spec/node-local.md §1 and §2).
//!
//! The values of the proxy's header lines, a `Proxy-Authorization` made from a
//! user name and password in the proxy URL among them, are always in the
//! system keyring: `node.toml` names the headers, and their values are never
//! in a file, a log, an error text or the audit log. The installed node on
//! Windows keeps them, and its keys where they are in the keyring, in the
//! Credential Manager of its own account, which only the service reads and
//! writes ([`vault`]).
//!
//! The node's own keys, the key of the config's MAC, the node key per
//! center, the relay's TLS key and the password of an `https://` proxy (a
//! relay token), are where `machine.secret_storage` says: 0600 files
//! (`file`, the default) or the system keyring (`keyring`). A change moves them once,
//! through the settings store ([`NodeSecrets`]): copied, read back, then the
//! old copies go.
//!
//! There is no fallback. Where the keyring cannot be reached (a headless
//! Linux has no Secret Service), storing fails and `proxy set` refuses, a
//! link whose proxy needs a value it cannot read fails closed, and a node
//! whose keys are in the keyring does not start. Tests put an in-memory store
//! in place of the system's; it is compiled into test builds only, so a
//! release never holds a secret anywhere but the keyring.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nerve_policy::NodeConfig;
use nerve_policy::config::SecretStorage;
use nerve_policy::settings::Secrets;
use nerve_transport::keys::{MacKey, NodeKey};

use crate::paths::NodePaths;

/// The keyring service every entry of the node is filed under.
pub const SERVICE: &str = "nerve";

/// One entry of the node in the keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    account: String,
}

impl Entry {
    /// The entry with the proxy's header values. One per node: the account
    /// names the node's config folder after `proxy:`, so two nodes of one
    /// user keep theirs apart.
    pub fn proxy(paths: &NodePaths) -> Entry {
        let dir = absolute(&paths.config_dir);
        Entry {
            account: format!("proxy:{}", dir.display()),
        }
    }

    /// The entry with the key of the config's MAC, named after the state
    /// folder that would hold its file.
    pub fn config_key(paths: &NodePaths) -> Entry {
        Entry {
            account: format!("config-key:{}", absolute(&paths.state_dir).display()),
        }
    }

    /// The entry with the node key for `center`, named after the config
    /// folder that would hold its file.
    pub fn center_key(paths: &NodePaths, center: &str) -> Entry {
        Entry {
            account: format!(
                "center-key:{center}:{}",
                absolute(&paths.config_dir).display()
            ),
        }
    }

    /// The entry with the new node key for `center` while its rotation is
    /// under way.
    pub fn center_next_key(paths: &NodePaths, center: &str) -> Entry {
        Entry {
            account: format!(
                "center-key-next:{center}:{}",
                absolute(&paths.config_dir).display()
            ),
        }
    }

    /// The entry with the relay's TLS certificate and key.
    pub fn relay_tls(paths: &NodePaths) -> Entry {
        Entry {
            account: format!("relay-tls:{}", absolute(&paths.config_dir).display()),
        }
    }

    /// The entry with the web UI's TLS certificate and key.
    pub fn ui_tls(paths: &NodePaths) -> Entry {
        Entry {
            account: format!("ui-tls:{}", absolute(&paths.config_dir).display()),
        }
    }

    /// The entry with the password of an `https://` proxy.
    pub fn proxy_login(paths: &NodePaths) -> Entry {
        Entry {
            account: format!("proxy-login:{}", absolute(&paths.config_dir).display()),
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    /// Whether `account` names one of the entries of the node at `paths`:
    /// one of the kinds above, after its prefix the node's config folder
    /// (its state folder for the config key's).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn is_of(paths: &NodePaths, account: &str) -> bool {
        let (config, state) = (
            absolute(&paths.config_dir).display().to_string(),
            absolute(&paths.state_dir).display().to_string(),
        );
        let Some((kind, rest)) = account.split_once(':') else {
            return false;
        };
        match kind {
            "proxy" | "relay-tls" | "ui-tls" | "proxy-login" => rest == config,
            "config-key" => rest == state,
            "center-key" | "center-key-next" => rest.split_once(':').is_some_and(|(c, dir)| {
                nerve_policy::config::valid_center_name(c) && dir == config
            }),
            _ => false,
        }
    }
}

/// How errors name the entry: the service, then the account.
impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SERVICE}/{}", self.account)
    }
}

fn absolute(p: &Path) -> std::path::PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Puts the proxy's header values into the node's keyring entry, replacing
/// what it held.
pub fn store_proxy_headers(paths: &NodePaths, headers: &[(String, String)]) -> Result<(), String> {
    let entry = Entry::proxy(paths);
    let map: BTreeMap<&str, &str> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let text = serde_json::to_string(&map).map_err(|e| e.to_string())?;
    vault::set(paths, entry.account(), &text).map_err(|e| {
        format!(
            "cannot store the proxy's header values in the system keyring (entry {entry}): {e}. The node keeps them nowhere else, so nothing was changed; on a machine without a keyring (a Linux without a desktop has no Secret Service) use a proxy that needs no header"
        )
    })
}

/// The proxy's header lines: the names `node.toml` gives, with their values
/// from the keyring. No names, no keyring call. A missing or unreadable entry,
/// or one without a value for a name, is an error that names the entry.
pub fn proxy_headers(paths: &NodePaths, names: &[String]) -> Result<Vec<(String, String)>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let entry = Entry::proxy(paths);
    let again = "run `nerve-node proxy set` again";
    let text = match vault::get(paths, entry.account()) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err(format!(
                "the system keyring has no entry {entry} with the proxy's header values; {again}"
            ));
        }
        Err(e) => {
            return Err(format!(
                "cannot read the proxy's header values from the system keyring (entry {entry}): {e}"
            ));
        }
    };
    // The parse error is not shown: it could quote the value.
    let mut map: BTreeMap<String, String> = serde_json::from_str(&text)
        .map_err(|_| format!("the keyring entry {entry} is not one nerve-node wrote; {again}"))?;
    names
        .iter()
        .map(|n| match map.remove(n) {
            Some(v) => Ok((n.clone(), v)),
            None => Err(format!(
                "the keyring entry {entry} holds no value for the header {n}; {again}"
            )),
        })
        .collect()
}

/// Deletes the node's proxy entry; `Ok(false)` when there was none.
pub fn remove_proxy_headers(paths: &NodePaths) -> Result<bool, String> {
    let entry = Entry::proxy(paths);
    vault::delete(paths, entry.account())
        .map_err(|e| format!("cannot delete the keyring entry {entry}: {e}"))
}

/// One of the node's own keys, in its file or its keyring entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key<'a> {
    /// The key of the config's MAC.
    Config,
    /// The node key for a center.
    Center(&'a str),
    /// The new node key for a center while its rotation is under way.
    CenterNext(&'a str),
    /// The relay's TLS certificate and key, as PEM.
    RelayTls,
    /// The web UI's TLS certificate and key, as PEM.
    UiTls,
    /// The password of an `https://` proxy: the relay token.
    ProxyLogin,
}

impl Key<'_> {
    pub(crate) fn file(self, paths: &NodePaths) -> std::path::PathBuf {
        match self {
            Key::Config => paths.config_key(),
            Key::Center(c) => paths.key_file(c),
            Key::CenterNext(c) => paths.next_key_file(c),
            Key::RelayTls => paths.relay_tls_file(),
            Key::UiTls => paths.ui_tls_file(),
            Key::ProxyLogin => paths.proxy_login_file(),
        }
    }

    pub(crate) fn entry(self, paths: &NodePaths) -> Entry {
        match self {
            Key::Config => Entry::config_key(paths),
            Key::Center(c) => Entry::center_key(paths, c),
            Key::CenterNext(c) => Entry::center_next_key(paths, c),
            Key::RelayTls => Entry::relay_tls(paths),
            Key::UiTls => Entry::ui_tls(paths),
            Key::ProxyLogin => Entry::proxy_login(paths),
        }
    }

    /// How a message names it.
    pub(crate) fn what(self) -> String {
        match self {
            Key::Config => "the key of the config's MAC".into(),
            Key::Center(c) => format!("the node key for center {c}"),
            Key::CenterNext(c) => format!("the new node key for center {c}"),
            Key::RelayTls => "the relay's TLS key".into(),
            Key::UiTls => "the web UI's TLS key".into(),
            Key::ProxyLogin => "the proxy's password (a relay token)".into(),
        }
    }
}

/// Every key of the node `cfg` describes: the config's, one per center and
/// the new one of a rotation under way, the relay's and the web UI's TLS
/// keys once they have a pin, and the proxy's password while the config
/// names its user.
/// A key that is not there is passed over.
pub(crate) fn keys(cfg: &NodeConfig) -> Vec<Key<'_>> {
    std::iter::once(Key::Config)
        .chain(
            cfg.centers
                .iter()
                .flat_map(|c| [Key::Center(&c.name), Key::CenterNext(&c.name)]),
        )
        .chain(cfg.relay.pin.is_some().then_some(Key::RelayTls))
        .chain(cfg.ui.pin.is_some().then_some(Key::UiTls))
        .chain(cfg.connection.login.is_some().then_some(Key::ProxyLogin))
        .collect()
}

/// The other place.
pub(crate) fn other(storage: SecretStorage) -> SecretStorage {
    match storage {
        SecretStorage::File => SecretStorage::Keyring,
        SecretStorage::Keyring => SecretStorage::File,
    }
}

/// How a message names a place.
fn place(storage: SecretStorage) -> &'static str {
    match storage {
        SecretStorage::File => "its file",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// The text of `key` in `storage`, trimmed; `None` when it is not there.
/// Errors name the file or the entry, never the text.
pub(crate) fn get(
    paths: &NodePaths,
    storage: SecretStorage,
    key: Key,
) -> Result<Option<String>, String> {
    match storage {
        SecretStorage::File => {
            let file = key.file(paths);
            match std::fs::read_to_string(&file) {
                Ok(t) => Ok(Some(t.trim().to_string())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!(
                    "cannot read {} {}: {e}",
                    key.what(),
                    file.display()
                )),
            }
        }
        SecretStorage::Keyring => {
            let entry = key.entry(paths);
            vault::get(paths, entry.account())
                .map(|t| t.map(|t| t.trim().to_string()))
                .map_err(|e| {
                    format!(
                        "cannot read {} from the system keyring (entry {entry}): {e}",
                        key.what()
                    )
                })
        }
    }
}

/// Keeps `text` as `key` in `storage`, replacing what was there, and reads
/// it back: a copy that does not read back as written is an error.
pub(crate) fn put(
    paths: &NodePaths,
    storage: SecretStorage,
    key: Key,
    text: &str,
) -> Result<(), String> {
    match storage {
        SecretStorage::File => {
            let file = key.file(paths);
            if let Some(dir) = file.parent() {
                nerve_transport::files::create_private_dir(dir)
                    .map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            nerve_transport::files::write_private(&file, format!("{text}\n").as_bytes())
                .map_err(|e| format!("cannot write {} {}: {e}", key.what(), file.display()))?;
        }
        SecretStorage::Keyring => {
            let entry = key.entry(paths);
            vault::set(paths, entry.account(), text).map_err(|e| {
                format!(
                    "cannot keep {} in the system keyring (entry {entry}): {e}",
                    key.what()
                )
            })?;
        }
    }
    if get(paths, storage, key)?.as_deref() != Some(text) {
        return Err(format!(
            "{} in {} does not read back as it was written",
            key.what(),
            place(storage)
        ));
    }
    Ok(())
}

/// Deletes `key` from `storage`; `Ok(false)` when it was not there.
pub(crate) fn delete(paths: &NodePaths, storage: SecretStorage, key: Key) -> Result<bool, String> {
    match storage {
        SecretStorage::File => {
            let file = key.file(paths);
            match std::fs::remove_file(&file) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(format!("cannot delete {}: {e}", file.display())),
            }
        }
        SecretStorage::Keyring => {
            let entry = key.entry(paths);
            vault::delete(paths, entry.account())
                .map_err(|e| format!("cannot delete the keyring entry {entry}: {e}"))
        }
    }
}

/// The node's `node.toml` as it stands, read without checking its MAC: for
/// the service, which wrote it, to name its own entries.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn stated_config(paths: &NodePaths) -> Result<NodeConfig, String> {
    let file = paths.config_file();
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    NodeConfig::parse(&text)
}

/// Where the node's `node.toml` says its keys are, read without checking
/// its MAC: the key that checks it is looked for there. No file, or one
/// that does not parse: `file`.
pub fn stated_storage(paths: &NodePaths) -> SecretStorage {
    std::fs::read_to_string(paths.config_file())
        .map(|t| nerve_policy::settings::stated_storage(&t))
        .unwrap_or_default()
}

/// Whether the node at `paths` is the installed node on Windows, whose
/// keyring is its service account's ([`vault`]). Its folders are found in
/// any spelling: Windows does not tell `C:\ProgramData` from
/// `c:\programdata`.
pub fn windows_service(paths: &NodePaths) -> bool {
    #[cfg(test)]
    if for_tests::windows_service(paths) {
        return true;
    }
    cfg!(windows)
        && (crate::service::is_service_node(paths)
            || same_folders_ignoring_case(paths, &crate::service::Layout::system().paths))
}

/// Whether `a` and `b` name the same folders when case and a trailing
/// separator do not count.
fn same_folders_ignoring_case(a: &NodePaths, b: &NodePaths) -> bool {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_lowercase()
    };
    norm(&a.config_dir) == norm(&b.config_dir) && norm(&a.state_dir) == norm(&b.state_dir)
}

/// What a test has the other code take for the installed node on Windows,
/// per node and on every platform.
#[cfg(test)]
pub(crate) mod for_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex};

    use crate::paths::NodePaths;

    #[derive(Default)]
    struct Pretended {
        windows_service: bool,
        service_runs: bool,
        service_account: bool,
    }

    static NODES: LazyLock<Mutex<HashMap<PathBuf, Pretended>>> = LazyLock::new(Mutex::default);

    fn with<T>(paths: &NodePaths, f: impl FnOnce(&mut Pretended) -> T) -> T {
        let mut nodes = nerve_transport::sync::lock(&NODES);
        f(nodes.entry(paths.config_dir.clone()).or_default())
    }

    /// The node at `paths` counts as the installed node on Windows.
    pub fn pretend_windows_service(paths: &NodePaths) {
        with(paths, |p| p.windows_service = true);
    }

    /// The service of the node at `paths` runs (`true`), and takes
    /// `vault.*` calls as the account whose vault it is, or does not.
    pub fn pretend_service_runs(paths: &NodePaths, runs: bool) {
        with(paths, |p| p.service_runs = runs);
    }

    /// The calls a process that is not the service makes to it
    /// (crate::secrets::vault): what the running service answers, else that
    /// it does not run.
    pub fn service_call(
        paths: &NodePaths,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        if !with(paths, |p| p.service_runs) {
            return Err(nerve_transport::ctl::NOT_RUNNING.into());
        }
        super::vault::serve(paths, method, &params)
    }

    /// This process counts as the service's account for the node at
    /// `paths`, whose vault is its own: a daemon of a test.
    pub fn pretend_service_account(paths: &NodePaths) {
        with(paths, |p| p.service_account = true);
    }

    pub fn service_account(paths: &NodePaths) -> bool {
        with(paths, |p| p.service_account)
    }

    pub fn windows_service(paths: &NodePaths) -> bool {
        with(paths, |p| p.windows_service)
    }
}

/// The node key for `center` from where `storage` keeps it.
pub fn center_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
) -> Result<NodeKey, String> {
    let key = Key::Center(center);
    let text = match storage {
        // The file, with its own messages.
        SecretStorage::File => {
            let path = key.file(paths);
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read the node key {}: {e}", path.display()))?;
            return NodeKey::from_text(text.trim())
                .map_err(|e| format!("bad node key {}: {e}", path.display()));
        }
        SecretStorage::Keyring => match get(paths, storage, key)? {
            Some(t) => t,
            // The keyring answered and holds none: a key whose move has not
            // finished is still in its file. An unreachable keyring is an
            // error above, never a reason to read the file.
            None => get(paths, SecretStorage::File, key)?.ok_or_else(|| {
                format!(
                    "the system keyring has no entry {} with the node key for center {center}; pair the center again",
                    key.entry(paths)
                )
            })?,
        },
    };
    NodeKey::from_text(&text).map_err(|e| {
        format!(
            "bad node key for center {center} in the keyring entry {}: {e}",
            key.entry(paths)
        )
    })
}

/// Keeps a new node key for `center` where `storage` says.
pub fn store_center_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
    key: &NodeKey,
) -> Result<(), String> {
    put(paths, storage, Key::Center(center), key.to_text().trim())
}

/// Deletes the node key for `center`, and the new one of a rotation under
/// way: from where `storage` keeps them, a file left from before a move, and
/// while a move waits (`keys.moving`) the copy in the other place, which the
/// start that finishes the move no longer looks for once the center is gone.
pub fn remove_center_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
) -> Result<(), String> {
    remove_secret(paths, storage, Key::Center(center))?;
    remove_secret(paths, storage, Key::CenterNext(center))
}

/// The new node key for `center` while a rotation of it is under way
/// (crate::rotate); `None` when none is.
pub fn center_next_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
) -> Result<Option<NodeKey>, String> {
    let Some(text) = read_secret(paths, storage, Key::CenterNext(center))? else {
        return Ok(None);
    };
    NodeKey::from_text(&text).map(Some).map_err(|e| {
        format!(
            "bad new node key for center {center} in {}: {e}",
            place(storage)
        )
    })
}

/// Keeps the new node key for `center` before its rotation is sent, so a
/// rotation the center took is never lost with the process.
pub fn store_center_next_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
    key: &NodeKey,
) -> Result<(), String> {
    put(
        paths,
        storage,
        Key::CenterNext(center),
        key.to_text().trim(),
    )
}

/// Deletes the new node key for `center`: the rotation is over, taken or
/// refused.
pub fn remove_center_next_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
) -> Result<(), String> {
    remove_secret(paths, storage, Key::CenterNext(center))
}

/// The text of `key` from where `storage` keeps it: with `keyring`, a key
/// the keyring answers it does not hold is looked for in its file, where a
/// move that has not finished left it. An unreachable keyring is an error,
/// never a reason to read the file.
pub(crate) fn read_secret(
    paths: &NodePaths,
    storage: SecretStorage,
    key: Key,
) -> Result<Option<String>, String> {
    match get(paths, storage, key)? {
        Some(t) => Ok(Some(t)),
        None if storage == SecretStorage::Keyring => get(paths, SecretStorage::File, key),
        None => Ok(None),
    }
}

/// Deletes `key` where `storage` keeps it, and the copy in the other place
/// a move may have left ([`remove_center_key`]).
fn remove_secret(paths: &NodePaths, storage: SecretStorage, key: Key) -> Result<(), String> {
    delete(paths, storage, key)?;
    if storage == SecretStorage::Keyring || paths.keys_moving().exists() {
        delete(paths, other(storage), key)?;
    }
    Ok(())
}

/// The relay's TLS identity, `None` when it has none yet.
pub fn relay_tls(
    paths: &NodePaths,
    storage: SecretStorage,
) -> Result<Option<nerve_transport::tls::ServerIdentity>, String> {
    let Some(text) = read_secret(paths, storage, Key::RelayTls)? else {
        return Ok(None);
    };
    nerve_transport::tls::ServerIdentity::from_pem(&text)
        .map(Some)
        .map_err(|e| format!("bad relay TLS key in {}: {e}", place(storage)))
}

/// Keeps the relay's TLS identity where `storage` says.
pub fn store_relay_tls(
    paths: &NodePaths,
    storage: SecretStorage,
    id: &nerve_transport::tls::ServerIdentity,
) -> Result<(), String> {
    put(paths, storage, Key::RelayTls, id.to_pem().trim())
}

/// The web UI's TLS identity, if it has one.
pub fn ui_tls(
    paths: &NodePaths,
    storage: SecretStorage,
) -> Result<Option<nerve_transport::tls::ServerIdentity>, String> {
    let Some(text) = read_secret(paths, storage, Key::UiTls)? else {
        return Ok(None);
    };
    nerve_transport::tls::ServerIdentity::from_pem(&text)
        .map(Some)
        .map_err(|e| format!("bad web UI TLS key in {}: {e}", place(storage)))
}

/// Keeps the web UI's TLS identity where `storage` says.
pub fn store_ui_tls(
    paths: &NodePaths,
    storage: SecretStorage,
    id: &nerve_transport::tls::ServerIdentity,
) -> Result<(), String> {
    put(paths, storage, Key::UiTls, id.to_pem().trim())
}

/// The password of the `https://` proxy, the relay token. Missing is an
/// error that says how to set it again; the text never shows it.
pub fn proxy_login(paths: &NodePaths, storage: SecretStorage) -> Result<String, String> {
    read_secret(paths, storage, Key::ProxyLogin)?.ok_or_else(|| {
        format!(
            "{} holds no password for the proxy's user; run `nerve-node proxy set` again",
            match storage {
                SecretStorage::File => format!("{}", paths.proxy_login_file().display()),
                SecretStorage::Keyring =>
                    format!("the system keyring entry {}", Entry::proxy_login(paths)),
            }
        )
    })
}

/// Keeps the password of the `https://` proxy where `storage` says. Where
/// that is the keyring and none answers, this fails as storing any of the
/// node's keys does, and nothing is kept elsewhere.
pub fn store_proxy_login(
    paths: &NodePaths,
    storage: SecretStorage,
    password: &str,
) -> Result<(), String> {
    put(paths, storage, Key::ProxyLogin, password)
}

/// Deletes the password of the `https://` proxy, wherever it is.
pub fn remove_proxy_login(paths: &NodePaths, storage: SecretStorage) -> Result<(), String> {
    remove_secret(paths, storage, Key::ProxyLogin)
}

/// The node's own keys where `machine.secret_storage` says, for the
/// settings store: the MAC key, and a move of every key when a saved config
/// names the other place.
///
/// A move writes `keys.moving` in the state folder first, then copies every
/// key and reads each copy back; the config is saved; then the old copies go
/// and so does the mark. Whatever stops it in between, the next start of the
/// node ([`settle`]) finds the mark and finishes or undoes the move by the
/// config in force.
///
/// A running node holds [`KeysLock`]. A CLI that writes `node.toml` itself
/// moves the keys only while it holds that lock too; when a node holds it
/// (on Windows, which has no control socket to ask that node, or one that is
/// starting), the old copies stay for that node to read until its next
/// start, which finishes the move. On Linux a move into the keyring is
/// refused then (`defers_keyring`).
pub struct NodeSecrets {
    paths: NodePaths,
    storage: SecretStorage,
    /// Whether a write takes [`KeysLock`] first: the CLI's. The daemon holds
    /// it already.
    locks: bool,
    /// The lock while a write holds it.
    held: Option<KeysLock>,
    /// The move in progress leaves the old copies to the next start.
    defer: bool,
    /// Whether a move into the keyring may be left to the next start of a node
    /// that holds [`KeysLock`]. Not on Linux: that node did not answer on its
    /// control socket (it starts, or its socket stopped), so it goes on with
    /// the keys in files in memory, and every `folder` mode command it starts
    /// gets a sandbox that leaves the session bus open while the keys are in
    /// the keyring; its count of such commands is not in this process either.
    /// On Windows `folder` mode runs no command.
    defers_keyring: bool,
    /// The running node's count of commands its Landlock does not keep off
    /// the session bus (crate::daemon::Shared::open_to_bus): while one runs,
    /// the keys do not go into the keyring.
    open_to_bus: Option<Arc<AtomicUsize>>,
}

impl NodeSecrets {
    /// The keys of the node at `paths`, where its `node.toml` says they are
    /// ([`stated_storage`]). The store checks the file with the key found
    /// there, so a file that names another place than its own key's does
    /// not pass.
    pub fn new(paths: &NodePaths) -> NodeSecrets {
        NodeSecrets {
            paths: paths.clone(),
            storage: stated_storage(paths),
            locks: false,
            held: None,
            defer: false,
            defers_keyring: false,
            open_to_bus: None,
        }
    }

    /// For the running node: a move into the keyring is refused while
    /// `open` counts a command that could reach it there.
    pub fn for_node(paths: &NodePaths, open: Arc<AtomicUsize>) -> NodeSecrets {
        NodeSecrets {
            open_to_bus: Some(open),
            ..NodeSecrets::new(paths)
        }
    }

    /// For a CLI that writes `node.toml` itself: each write takes
    /// [`KeysLock`] and is refused when the file changed since it was read,
    /// and a move leaves the old copies to a node that holds the lock; on
    /// Linux a move into the keyring is refused then.
    pub fn for_cli(paths: &NodePaths) -> NodeSecrets {
        NodeSecrets {
            locks: true,
            defers_keyring: !cfg!(target_os = "linux"),
            ..NodeSecrets::new(paths)
        }
    }

    /// For `config accept` without a running node: the file was edited, so
    /// its `machine.secret_storage` may not say where the key is. When the
    /// place it names holds no key and the other one does, the keys are
    /// taken to be there, and accepting the file moves them. With `file`
    /// named and its key file there, the keyring is not asked.
    pub fn for_accept(paths: &NodePaths) -> NodeSecrets {
        let mut s = NodeSecrets::for_cli(paths);
        let found = |storage| match storage {
            SecretStorage::File => paths.config_key().exists(),
            SecretStorage::Keyring => {
                matches!(get(paths, SecretStorage::Keyring, Key::Config), Ok(Some(_)))
            }
        };
        if !found(s.storage) && found(other(s.storage)) {
            s.storage = other(s.storage);
        }
        s
    }

    /// For a restore from a backup ([`crate::backup`]): the MAC key where the
    /// restored config keeps the keys, `storage`. No store moves anything
    /// here: the restore writes every key itself.
    pub(crate) fn for_restore(paths: &NodePaths, storage: SecretStorage) -> NodeSecrets {
        NodeSecrets {
            storage,
            ..NodeSecrets::new(paths)
        }
    }

    /// Moves every key of `cfg` into `into` from the other place: a key
    /// only there is copied over and read back, and a copy there that
    /// equals the one in `into` is deleted. Says what it could not do.
    fn gather(&self, cfg: &NodeConfig, into: SecretStorage) -> Vec<String> {
        let from = other(into);
        let mut left = Vec::new();
        for key in keys(cfg) {
            let r = (|| {
                let Some(old) = get(&self.paths, from, key)? else {
                    return Ok(());
                };
                match get(&self.paths, into, key)? {
                    None => put(&self.paths, into, key, &old)?,
                    Some(new) if new != old => {
                        return Err(format!(
                            "{} in {} differs from the one in {}, so it was left there",
                            key.what(),
                            place(from),
                            place(into)
                        ));
                    }
                    Some(_) => {}
                }
                delete(&self.paths, from, key).map(drop)
            })();
            if let Err(e) = r {
                left.push(e);
            }
        }
        left
    }

    /// With the keys going `to` the keyring while the running node counts
    /// `folder` mode commands that started with them in files: how many
    /// run and why that keeps the keys out, then how a message says they
    /// ended. Such a command got its sandbox while the keys were in their
    /// files, and a Landlock domain does not change while it runs: with the
    /// keys in the keyring it would reach them for the rest of its life.
    /// The store lock a move or a reload holds keeps a new one from
    /// starting until it is over.
    fn open_commands(&self, to: SecretStorage) -> Option<(String, &'static str)> {
        let open = self
            .open_to_bus
            .as_ref()
            .map_or(0, |n| n.load(Ordering::SeqCst));
        if to != SecretStorage::Keyring || open == 0 {
            return None;
        }
        let one = open == 1;
        Some((
            format!(
                "{open} folder mode {} that started while the node's keys were in their files, and {} sandbox does not keep {} off the session bus the keyring answers on",
                if one { "command runs" } else { "commands run" },
                if one { "its" } else { "their" },
                if one { "it" } else { "them" },
            ),
            if one { "it has" } else { "they have" },
        ))
    }

    /// Ends a move: without anything left behind, the mark goes.
    fn finish(&self, left: Vec<String>) {
        for e in &left {
            tracing::warn!("moving the node's keys: {e}");
        }
        if left.is_empty() {
            let _ = std::fs::remove_file(self.paths.keys_moving());
        }
    }
}

impl Secrets for NodeSecrets {
    fn storage(&self) -> SecretStorage {
        self.storage
    }

    fn mac_key(&self) -> Result<Option<MacKey>, String> {
        let file = self.paths.config_key();
        match self.storage {
            SecretStorage::File => MacKey::load(&file),
            SecretStorage::Keyring => {
                let entry = Entry::config_key(&self.paths);
                let text = vault::get(&self.paths, entry.account())
                    .map_err(|e| unreachable_keyring(&entry, &e))?;
                match text {
                    Some(t) => MacKey::from_text(&t)
                        .map(Some)
                        .map_err(|e| format!("the keyring entry {entry}: {e}")),
                    // A key whose move has not finished is still in its file.
                    None => MacKey::load(&file),
                }
            }
        }
    }

    fn mac_key_or_new(&self) -> Result<MacKey, String> {
        match self.storage {
            SecretStorage::File => MacKey::load_or_create(&self.paths.config_key()),
            SecretStorage::Keyring => {
                if let Some(k) = self.mac_key()? {
                    return Ok(k);
                }
                let (key, text) = MacKey::generate();
                put(&self.paths, SecretStorage::Keyring, Key::Config, &text)?;
                Ok(key)
            }
        }
    }

    fn accepted_version(&self) -> Result<Option<u64>, String> {
        nerve_policy::settings::read_version(&self.paths.config_version())
    }

    fn accept_version(&self, version: u64) -> Result<(), String> {
        nerve_policy::settings::record_version(&self.paths.config_version(), version)
    }

    fn copy(&mut self, cfg: &NodeConfig) -> Result<(), String> {
        let to = cfg.machine.secret_storage;
        if let Some((open, ended)) = self.open_commands(to) {
            return Err(format!(
                "{open}; the node's keys stay in their files, and nothing was changed. Wait until {ended} ended, or end every command with `nerve-node panic`, change it again, then `nerve-node unlock`"
            ));
        }
        if to == SecretStorage::Keyring && self.defer && !self.defers_keyring {
            return Err(format!(
                "another nerve-node holds {}: a node runs for this state folder but does not answer on its control socket, or a command moves its keys. That node would go on with its keys in files and give its folder mode commands a sandbox for that, so the node's keys stay in their files, and nothing was changed. Stop the node, or wait until it has started, then change it again",
                self.paths.keys_lock().display()
            ));
        }
        nerve_transport::files::write_private(
            &self.paths.keys_moving(),
            format!("moving the node's keys to {}\n", place(to)).as_bytes(),
        )
        .map_err(|e| format!("{}: {e}", self.paths.keys_moving().display()))?;
        // The keys this move wrote in the new place, the one being written
        // included: a write that fails half way (its read-back does not
        // answer) may have left a copy there all the same.
        let mut written = Vec::new();
        for key in keys(cfg) {
            let r = get(&self.paths, self.storage, key).and_then(|text| {
                let Some(t) = text else {
                    return Ok(());
                };
                // A copy there that equals it is left as it is: a node may
                // still read it, from a move left to its next start.
                if get(&self.paths, to, key).ok().flatten().as_deref() == Some(t.as_str()) {
                    return Ok(());
                }
                written.push(key);
                put(&self.paths, to, key, &t)
            });
            if let Err(e) = r {
                // Nothing is saved: what was copied goes again.
                for key in written {
                    let _ = delete(&self.paths, to, key);
                }
                let _ = std::fs::remove_file(self.paths.keys_moving());
                let hint = match to {
                    // The keyring crate keeps a failure to reach the
                    // keyring for the life of the process: a running node
                    // that met one asks no keyring installed after it.
                    SecretStorage::Keyring if !self.locks && store::failed() => {
                        " (this running node found no keyring and does not look again until it is restarted; on a Linux without a desktop, `nerve-node config set machine.secret_storage keyring` at a terminal offers to install one; then restart the node, `nerve-node service restart`, and run it again)"
                    }
                    SecretStorage::Keyring => {
                        " (on a Linux without a desktop, `nerve-node config set machine.secret_storage keyring` at a terminal offers to install a keyring)"
                    }
                    SecretStorage::File => "",
                };
                return Err(format!(
                    "{e}; the node's keys stay in {}, and nothing was changed{hint}",
                    match self.storage {
                        SecretStorage::File => "their files",
                        SecretStorage::Keyring => "the system keyring",
                    }
                ));
            }
        }
        Ok(())
    }

    /// Another writer moved the keys into the keyring: the running node
    /// does not follow while it counts a command that would reach them
    /// there.
    fn may_reload(&self, cfg: &NodeConfig) -> Result<(), String> {
        match self.open_commands(cfg.machine.secret_storage) {
            Some((open, ended)) => Err(format!(
                "node.toml keeps the node's keys in the system keyring, but {open}; the node goes on with the config in force, which keeps them in their files. Wait until {ended} ended, then reload again"
            )),
            None => Ok(()),
        }
    }

    fn moved(&mut self, cfg: &NodeConfig) {
        self.storage = cfg.machine.secret_storage;
        if !self.defer {
            self.finish(self.gather(cfg, self.storage));
        }
    }

    fn not_moved(&mut self, cfg: &NodeConfig) {
        self.finish(self.gather(cfg, self.storage));
    }

    /// The CLI's: every write it makes holds [`KeysLock`] where no node
    /// holds it, so a move and a write of another CLI do not cross; a move
    /// made while a node holds it leaves the old copies to that node, or is
    /// refused (`defers_keyring`).
    fn begin(&mut self) -> Result<bool, String> {
        if !self.locks {
            return Ok(false);
        }
        self.held = KeysLock::try_take_soon(&self.paths)?;
        self.defer = self.held.is_none();
        Ok(true)
    }

    fn end(&mut self) {
        self.held = None;
        self.defer = false;
    }
}

/// The refusal of a node whose keys are in a keyring it cannot reach.
fn unreachable_keyring(entry: &Entry, e: &str) -> String {
    format!(
        "machine.secret_storage is \"keyring\", but the system keyring cannot be reached (entry {entry}): {e}. The node keeps its keys nowhere else, so it cannot read its config; start the keyring (on a Linux without a desktop, `nerve-node setup` can install one)"
    )
}

/// At the start of the node, with its config checked and [`KeysLock`]
/// held: finishes a move of its keys that stopped half way, or one a CLI
/// left to this start ([`NodeSecrets::for_cli`]), by the config in force;
/// and with `keyring`, takes into the keyring every key still in a file.
/// With `file` and no move pending, the keyring is not asked. A file that
/// names another place than `cfg` was changed since the node read it; its
/// move is left to the next start.
pub fn settle(paths: &NodePaths, cfg: &NodeConfig) {
    let storage = cfg.machine.secret_storage;
    if storage == SecretStorage::File && !paths.keys_moving().exists() {
        return;
    }
    if stated_storage(paths) != storage {
        return;
    }
    let s = NodeSecrets {
        storage,
        ..NodeSecrets::new(paths)
    };
    s.finish(s.gather(cfg, storage));
}

/// How long [`KeysLock::try_take_soon`] tries: a forked command execs within
/// milliseconds, even on a loaded machine.
const FORKED_COPY_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

/// `keys.lock` in the state folder, held by a running node for its life and
/// by a CLI while it moves the keys: a move never runs while a node reads
/// them. It is released when its holder ends, however it ends.
pub struct KeysLock {
    _file: std::fs::File,
}

impl KeysLock {
    /// The lock, when nobody holds it; `None` when someone does.
    pub fn try_take(paths: &NodePaths) -> Result<Option<KeysLock>, String> {
        let path = paths.keys_lock();
        nerve_transport::files::create_private_dir(&paths.state_dir)
            .map_err(|e| format!("{}: {e}", paths.state_dir.display()))?;
        let mut o = std::fs::OpenOptions::new();
        o.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;
            o.mode(0o600);
            let file = o
                .open(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Some(KeysLock { _file: file }));
            }
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            Err(format!("{}: {e}", path.display()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Opened without sharing: nobody else opens it while it is held.
            const SHARING_VIOLATION: i32 = 32;
            match o.share_mode(0).open(&path) {
                Ok(file) => Ok(Some(KeysLock { _file: file })),
                Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => Ok(None),
                Err(e) => Err(format!("{}: {e}", path.display())),
            }
        }
    }

    /// Whether a node holds the lock, asked without making anything: no
    /// state folder or no lock file is a node that never ran, and a lock
    /// that cannot be tried counts as held (the safe answer for a caller that
    /// writes behind a node).
    #[cfg(any(windows, test))]
    pub fn node_runs(paths: &NodePaths) -> bool {
        // Only a file known to be missing is "no node": an entry that cannot
        // be looked at goes on to the lock, whose error counts as held.
        if matches!(paths.keys_lock().try_exists(), Ok(false)) {
            return false;
        }
        !matches!(KeysLock::try_take(paths), Ok(Some(_)))
    }

    /// The lock, trying again for a moment when someone holds it. A process
    /// that released it a moment ago may have forked a command meanwhile: the
    /// child holds a copy of the descriptor, and so the lock, until it execs.
    /// A node or a CLI that holds it for real keeps it far longer.
    pub fn try_take_soon(paths: &NodePaths) -> Result<Option<KeysLock>, String> {
        let until = std::time::Instant::now() + FORKED_COPY_WAIT;
        loop {
            if let Some(l) = KeysLock::try_take(paths)? {
                return Ok(Some(l));
            }
            if std::time::Instant::now() >= until {
                return Ok(None);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The lock, waiting up to `wait` for a CLI that moves the keys.
    pub async fn take(
        paths: &NodePaths,
        wait: std::time::Duration,
    ) -> Result<Option<KeysLock>, String> {
        let until = tokio::time::Instant::now() + wait;
        loop {
            if let Some(l) = KeysLock::try_take(paths)? {
                return Ok(Some(l));
            }
            if tokio::time::Instant::now() >= until {
                return Ok(None);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// For tests: the keys' lock held as a running node holds it, until this is
/// dropped. On Linux another process holds it, which opens and locks the
/// file itself and keeps nothing else of the test process; dropped, it ends,
/// and the lock is free. A lock taken in the test process could stay held
/// after it is dropped: a command another test forks meanwhile holds a copy
/// of every descriptor until its exec.
#[cfg(test)]
pub(crate) struct HeldByANode {
    #[cfg(target_os = "linux")]
    pid: libc::pid_t,
    #[cfg(not(target_os = "linux"))]
    _lock: KeysLock,
}

#[cfg(test)]
impl HeldByANode {
    pub(crate) fn take(paths: &NodePaths) -> HeldByANode {
        nerve_transport::files::create_private_dir(&paths.state_dir).unwrap();
        #[cfg(not(target_os = "linux"))]
        return HeldByANode {
            _lock: KeysLock::try_take(paths)
                .unwrap()
                .expect("the lock is free"),
        };
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            use std::os::fd::FromRawFd;
            use std::os::unix::ffi::OsStrExt;
            let lock = std::ffi::CString::new(paths.keys_lock().as_os_str().as_bytes()).unwrap();
            let mut fds = [0; 2];
            // SAFETY: a pipe into an array of two descriptors.
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            // SAFETY: the child makes plain system calls only and stays
            // until it is killed.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                // SAFETY: as above.
                unsafe {
                    keep_only(fds[1]);
                    let fd = libc::open(
                        lock.as_ptr(),
                        libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
                        0o600 as libc::c_uint,
                    );
                    // Waits while a forked copy of an earlier holder's
                    // lock is still there.
                    let ok = fd >= 0 && libc::flock(fd, libc::LOCK_EX) == 0;
                    libc::write(fds[1], [u8::from(ok)].as_ptr().cast(), 1);
                    loop {
                        libc::pause();
                    }
                }
            }
            // SAFETY: the write end is the child's; the read end is ours.
            let mut ready = unsafe {
                libc::close(fds[1]);
                std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fds[0]))
            };
            let mut ok = [0u8];
            ready.read_exact(&mut ok).unwrap();
            assert_eq!(ok, [1], "the holder did not take the lock");
            HeldByANode { pid }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for HeldByANode {
    fn drop(&mut self) {
        // SAFETY: ends and reaps the child `take` started; its descriptors,
        // the lock among them, are closed once the wait returns.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

/// For tests: closes every descriptor of a forked child but stdin, stdout,
/// stderr and `fd`, so a child that stays holds no copy of what another test
/// judges (a pipe's ends, a lock). Plain system calls only.
///
/// # Safety
/// For a child between `fork` and its end, which uses no other descriptor.
#[cfg(all(test, target_os = "linux"))]
pub(crate) unsafe fn keep_only(fd: i32) {
    let fd = fd as libc::c_uint;
    // SAFETY: close_range on numbers only.
    unsafe {
        if fd > 3 {
            libc::syscall(libc::SYS_close_range, 3, fd - 1, 0);
        }
        libc::syscall(libc::SYS_close_range, fd + 1, libc::c_uint::MAX, 0);
    }
}

/// The keyring of a node as this process reaches it. The installed node on
/// Windows keeps its keyring secrets in the Credential Manager of its own
/// account, `nerve`, which is one per account (Q8): the service writes and
/// reads them itself, and any other process (the CLI and the app of an
/// administrator) asks the running service over its control pipe
/// (`vault.get`, `vault.set`, `vault.delete`), never its own vault. While no
/// service runs (a restore, an install), what goes into the vault waits in
/// [`PENDING`], sealed with DPAPI, and the service takes it at its start
/// ([`take_pending`]). Everywhere else this is the keyring itself
/// ([`super::store`]).
pub(crate) mod vault {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::{Entry, NodePaths, store};

    /// The file in the config folder's `keys` that holds, sealed, what goes
    /// into the service's vault once it runs: each entry with its new text,
    /// or none for one to delete.
    pub const PENDING: &str = "vault.pending";

    /// What a read of the vault says while no service runs and nothing
    /// waits for it.
    pub const NOT_RUNNING: &str = "the node keeps this in the Credential Manager of its service account nerve, which only the running node reads: start the node on the app's Overview, then try again";

    pub fn pending_file(paths: &NodePaths) -> PathBuf {
        paths.config_dir.join("keys").join(PENDING)
    }

    /// Whether this process reaches the keyring of the node at `paths`
    /// through its service: the installed node on Windows, from a process
    /// that is not the service's account.
    pub fn through_service(paths: &NodePaths) -> bool {
        super::windows_service(paths) && !service_account(paths)
    }

    /// Whether this process runs as the service's own account, whose vault
    /// is the node's.
    fn service_account(paths: &NodePaths) -> bool {
        #[cfg(test)]
        return super::for_tests::service_account(paths);
        #[cfg(not(test))]
        let _ = paths;
        #[cfg(all(windows, not(test)))]
        return crate::win_user::current_user()
            .is_ok_and(|n| n.eq_ignore_ascii_case(crate::service::USER));
        #[cfg(all(not(windows), not(test)))]
        false
    }

    /// One call to the running service, from code that does not wait
    /// (`get` is called inside and outside the runtime): on a thread of its
    /// own with a runtime of its own.
    fn call(paths: &NodePaths, method: &str, params: Value) -> Result<Value, String> {
        #[cfg(test)]
        return super::for_tests::service_call(paths, method, params);
        #[cfg(all(windows, not(test)))]
        {
            let (paths, method) = (paths.clone(), method.to_string());
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?
                    .block_on(crate::pipe::call(&paths, &method, params))
            })
            .join()
            .map_err(|_| "the call to the node ended".to_string())?
        }
        #[cfg(all(not(windows), not(test)))]
        {
            let _ = (paths, method, params);
            Err(nerve_transport::ctl::NOT_RUNNING.into())
        }
    }

    fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(windows)]
        return crate::win_user::protect(plain).map_err(|e| format!("DPAPI: {e}"));
        #[cfg(not(windows))]
        Ok(plain.to_vec())
    }

    fn unseal(sealed: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(windows)]
        return crate::win_user::unprotect(sealed).map_err(|e| format!("DPAPI: {e}"));
        #[cfg(not(windows))]
        Ok(sealed.to_vec())
    }

    type Pending = BTreeMap<String, Option<String>>;

    /// What waits for the service; nothing when no file is there. The error
    /// names the file, never a value.
    fn read_pending(paths: &NodePaths) -> Result<Pending, String> {
        let file = pending_file(paths);
        let sealed = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Pending::new()),
            Err(e) => return Err(format!("{}: {e}", file.display())),
        };
        unseal(&sealed)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| format!("{} cannot be read", file.display()))
    }

    fn write_pending(paths: &NodePaths, p: &Pending) -> Result<(), String> {
        let file = pending_file(paths);
        if p.is_empty() {
            return match std::fs::remove_file(&file) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("{}: {e}", file.display())),
            };
        }
        if let Some(dir) = file.parent() {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let plain = serde_json::to_vec(p).map_err(|e| e.to_string())?;
        nerve_transport::files::write_private(&file, &seal(&plain)?)
            .map_err(|e| format!("{}: {e}", file.display()))
    }

    /// Whether the service did not take the call because it does not run.
    fn not_running(e: &str) -> bool {
        e == nerve_transport::ctl::NOT_RUNNING
    }

    /// Keeps `value` (or, with `None`, deletes the entry) for the service
    /// to take at its start.
    fn stage(paths: &NodePaths, account: &str, value: Option<&str>) -> Result<(), String> {
        let mut p = read_pending(paths)?;
        p.insert(account.into(), value.map(String::from));
        write_pending(paths, &p)
    }

    pub fn get(paths: &NodePaths, account: &str) -> Result<Option<String>, String> {
        if !through_service(paths) {
            return store::get(account);
        }
        match call(paths, "vault.get", json!({"account": account})) {
            Ok(v) => Ok(v["value"].as_str().map(String::from)),
            Err(e) if not_running(&e) => match read_pending(paths)?.remove(account) {
                Some(v) => Ok(v),
                None => Err(NOT_RUNNING.into()),
            },
            Err(e) => Err(e),
        }
    }

    pub fn set(paths: &NodePaths, account: &str, value: &str) -> Result<(), String> {
        if !through_service(paths) {
            return store::set(account, value);
        }
        match call(
            paths,
            "vault.set",
            json!({"account": account, "value": value}),
        ) {
            Ok(_) => Ok(()),
            Err(e) if not_running(&e) => stage(paths, account, Some(value)),
            Err(e) => Err(e),
        }
    }

    /// `Ok(false)` when there was none; one staged while no service runs
    /// counts as there.
    pub fn delete(paths: &NodePaths, account: &str) -> Result<bool, String> {
        if !through_service(paths) {
            return store::delete(account);
        }
        match call(paths, "vault.delete", json!({"account": account})) {
            Ok(v) => Ok(v["deleted"] == true),
            Err(e) if not_running(&e) => stage(paths, account, None).map(|()| true),
            Err(e) => Err(e),
        }
    }

    /// What the service does with a `vault.*` request for the node at
    /// `paths`, as the account whose vault it is: an entry that is not one
    /// of this node's is refused. `vault.stage` copies every entry of the
    /// node's into [`PENDING`], for an install that gives the account a new
    /// password (Windows then cannot open what it kept before) and an
    /// uninstall that keeps the data.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn serve(paths: &NodePaths, method: &str, params: &Value) -> Result<Value, String> {
        if method == "vault.stage" {
            let cfg = super::stated_config(paths)?;
            let mut p = read_pending(paths)?;
            let mut n = 0;
            let accounts = super::keys(&cfg)
                .into_iter()
                .map(|k| k.entry(paths))
                .chain(std::iter::once(Entry::proxy(paths)));
            for e in accounts {
                if let Some(v) = store::get(e.account())? {
                    p.insert(e.account().into(), Some(v));
                    n += 1;
                }
            }
            write_pending(paths, &p)?;
            return Ok(json!({"staged": n}));
        }
        let account = params["account"].as_str().ok_or("account is missing")?;
        if !Entry::is_of(paths, account) {
            return Err(format!("{account:?} is no entry of this node"));
        }
        match method {
            "vault.get" => Ok(json!({"value": store::get(account)?})),
            "vault.set" => {
                let value = params["value"].as_str().ok_or("value is missing")?;
                store::set(account, value)?;
                Ok(json!({}))
            }
            "vault.delete" => Ok(json!({"deleted": store::delete(account)?})),
            m => Err(format!("unknown method {m}")),
        }
    }

    /// Has the running service copy its entries aside ([`serve`]'s
    /// `vault.stage`); how many.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn stage_in_service(paths: &NodePaths) -> Result<u64, String> {
        call(paths, "vault.stage", json!({})).map(|v| v["staged"].as_u64().unwrap_or(0))
    }

    /// Puts what waits in [`PENDING`] into the vault of this process, the
    /// service's, at its start, then deletes the file; what fails stays
    /// there for the next start and is said.
    pub fn take_pending(paths: &NodePaths) -> Result<usize, String> {
        let p = read_pending(paths)?;
        let mut left = Pending::new();
        let mut errors = Vec::new();
        let mut n = 0;
        for (account, value) in p {
            let r = match &value {
                Some(v) => store::set(&account, v),
                None => store::delete(&account).map(|_| ()),
            };
            match r {
                Ok(()) => n += 1,
                Err(e) => {
                    errors.push(format!("{account}: {e}"));
                    left.insert(account, value);
                }
            }
        }
        write_pending(paths, &left)?;
        match errors.is_empty() {
            true => Ok(n),
            false => Err(format!(
                "cannot put into the Credential Manager: {}",
                errors.join("; ")
            )),
        }
    }
}

/// The system keyring: Keychain on macOS, Credential Manager on Windows, the
/// Secret Service elsewhere.
#[cfg(not(test))]
pub(crate) mod store {
    use super::SERVICE;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Whether this process asked the keyring at all.
    static ASKED: AtomicBool = AtomicBool::new(false);

    /// Whether this process asked the keyring and none answered: the
    /// keyring crate connects once per process and keeps that failure for
    /// its life, so only a new process sees a keyring installed after it.
    pub fn failed() -> bool {
        ASKED.load(Ordering::Relaxed) && keyring::Entry::store_status().is_err()
    }

    fn entry(account: &str) -> Result<keyring::Entry, String> {
        ASKED.store(true, Ordering::Relaxed);
        keyring::Entry::new(SERVICE, account).map_err(|e| {
            match (&e, keyring::Entry::store_status()) {
                // The store failed to start; its own error says why.
                (keyring::Error::NoDefaultStore, Err(why)) => why.to_string(),
                _ => e.to_string(),
            }
        })
    }

    pub fn get(account: &str) -> Result<Option<String>, String> {
        match entry(account)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn set(account: &str, value: &str) -> Result<(), String> {
        entry(account)?
            .set_password(value)
            .map_err(|e| e.to_string())
    }

    pub fn delete(account: &str) -> Result<bool, String> {
        match entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The test builds' keyring: a map in memory, shared by every thread of the
/// test process (each test's node has its own config folder, so its own
/// account), and a switch per thread that makes it unreachable, as on a
/// machine without a Secret Service.
#[cfg(test)]
pub(crate) mod store {
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    static ENTRIES: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);

    thread_local! {
        static UNREACHABLE: Cell<bool> = const { Cell::new(false) };
        static FAILED: Cell<bool> = const { Cell::new(false) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static UNREADABLE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }

    /// How often this thread asked the keyring.
    pub fn calls() -> usize {
        CALLS.with(Cell::get)
    }

    /// What the Secret Service crate says on a Linux without a desktop session.
    pub const NO_SERVICE: &str =
        "Couldn't access platform storage: SS error: result not returned from SS API";

    /// Makes the keyring unreachable on this thread (`true`) or reachable.
    pub fn set_unreachable(on: bool) {
        UNREACHABLE.with(|u| u.set(on));
        if !on {
            FAILED.with(|f| f.set(false));
        }
    }

    /// Whether a call on this thread found the keyring unreachable since it
    /// was last made reachable, as the real store keeps such a failure.
    pub fn failed() -> bool {
        FAILED.with(Cell::get)
    }

    /// Makes reading `account` fail on this thread, as a read that does not
    /// answer in time; writing it still works.
    pub fn set_unreadable(account: Option<&str>) {
        UNREADABLE.with(|u| *u.borrow_mut() = account.map(String::from));
    }

    fn reach() -> Result<std::sync::MutexGuard<'static, HashMap<String, String>>, String> {
        CALLS.with(|c| c.set(c.get() + 1));
        if UNREACHABLE.with(Cell::get) {
            FAILED.with(|f| f.set(true));
            return Err(NO_SERVICE.into());
        }
        Ok(nerve_transport::sync::lock(&ENTRIES))
    }

    pub fn get(account: &str) -> Result<Option<String>, String> {
        let entries = reach()?;
        if UNREADABLE.with(|u| u.borrow().as_deref() == Some(account)) {
            return Err("the keyring did not answer in time".into());
        }
        Ok(entries.get(account).cloned())
    }

    pub fn set(account: &str, value: &str) -> Result<(), String> {
        reach()?.insert(account.into(), value.into());
        Ok(())
    }

    pub fn delete(account: &str) -> Result<bool, String> {
        Ok(reach()?.remove(account).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_policy::SettingsStore;
    use nerve_policy::audit::AuditLog;

    fn node() -> (tempfile::TempDir, NodePaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        (d, paths)
    }

    /// Asking whether a node runs makes no state folder and no lock file
    /// where none ever ran, and sees a node that holds the lock.
    #[test]
    fn asking_whether_a_node_runs_makes_nothing() {
        let (_d, paths) = node();
        assert!(!KeysLock::node_runs(&paths));
        assert!(!paths.state_dir.exists(), "the question made the folder");
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        assert!(!KeysLock::node_runs(&paths));
        assert!(!paths.keys_lock().exists(), "the question made the lock");
        let held = HeldByANode::take(&paths);
        assert!(KeysLock::node_runs(&paths));
        drop(held);
        assert!(!KeysLock::node_runs(&paths));
    }

    /// A state folder that cannot be looked into is not proof that no node
    /// runs: the answer is the safe one, held.
    #[cfg(unix)]
    #[test]
    fn a_lock_that_cannot_be_looked_at_counts_as_held() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, paths) = node();
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let set =
            |m| std::fs::set_permissions(&paths.state_dir, std::fs::Permissions::from_mode(m));
        set(0o000).unwrap();
        let looked = paths.keys_lock().try_exists().is_ok();
        let runs = KeysLock::node_runs(&paths);
        set(0o700).unwrap();
        // A superuser can look anyway; then there is nothing to prove.
        if !looked {
            assert!(runs, "a lock that cannot be looked at counted as no node");
        }
    }

    fn in_keyring(paths: &NodePaths, key: Key) -> Option<String> {
        store::get(key.entry(paths).account()).unwrap()
    }

    fn open(paths: &NodePaths) -> Result<SettingsStore, String> {
        SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets::new(paths)),
            AuditLog::new(paths.audit_log()),
        )
    }

    fn peek(paths: &NodePaths) -> Result<NodeConfig, String> {
        SettingsStore::peek_with(&paths.config_file(), &NodeSecrets::new(paths))
    }

    /// A node with `centers` paired (their keys stored) under `storage`.
    fn paired(paths: &NodePaths, storage: SecretStorage, centers: &[&str]) -> SettingsStore {
        let mut s = open(paths).unwrap();
        if storage == SecretStorage::Keyring {
            s.update(|c| {
                c.machine.secret_storage = storage;
                Ok(())
            })
            .unwrap();
        }
        for name in centers {
            let key = NodeKey::generate().unwrap();
            store_center_key(paths, storage, name, &key).unwrap();
            s.update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: name.to_string(),
                    url: "https://center.example".into(),
                    pin: None,
                    center_id: format!("id-{name}"),
                    node_id: key.node_id(),
                    settings: Default::default(),
                    paused: false,
                    revoked: false,
                    unknown: false,
                    public_key: None,
                    key_rotations: 0,
                    pin_rotations: 0,
                    old_pin: None,
                    policy: Default::default(),
                    capabilities: Vec::new(),
                });
                Ok(())
            })
            .unwrap();
        }
        s
    }

    fn set_storage(s: &mut SettingsStore, storage: SecretStorage) -> Result<u64, String> {
        s.update(|c| {
            c.machine.secret_storage = storage;
            Ok(())
        })
        .map_err(|e| e.to_string())
    }

    #[test]
    fn each_key_is_stored_read_rotated_and_removed_in_either_place() {
        for storage in [SecretStorage::File, SecretStorage::Keyring] {
            let (_d, paths) = node();
            // The center's key.
            let first = NodeKey::generate().unwrap();
            store_center_key(&paths, storage, "home", &first).unwrap();
            let read = center_key(&paths, storage, "home").unwrap();
            assert_eq!(read.public_key(), first.public_key());
            let second = NodeKey::generate().unwrap();
            store_center_key(&paths, storage, "home", &second).unwrap();
            let read = center_key(&paths, storage, "home").unwrap();
            assert_eq!(read.public_key(), second.public_key());
            remove_center_key(&paths, storage, "home").unwrap();
            assert!(center_key(&paths, storage, "home").is_err());
            // The config's key.
            let secrets = NodeSecrets {
                storage,
                ..NodeSecrets::new(&paths)
            };
            assert!(secrets.mac_key().unwrap().is_none());
            let mac = secrets.mac_key_or_new().unwrap().sign(b"node.toml");
            let again = secrets.mac_key().unwrap().unwrap();
            assert!(again.verify(b"node.toml", &mac));
            // Never replaced by asking again.
            assert!(secrets.mac_key_or_new().unwrap().verify(b"node.toml", &mac));
            let (_, text) = MacKey::generate();
            put(&paths, storage, Key::Config, &text).unwrap();
            let rotated = secrets.mac_key().unwrap().unwrap();
            assert!(!rotated.verify(b"node.toml", &mac));
            assert!(delete(&paths, storage, Key::Config).unwrap());
            assert!(secrets.mac_key().unwrap().is_none());
            // Each place holds only its own: the keyring's keys never touch
            // a file, the files' never the keyring.
            store_center_key(&paths, storage, "lab", &first).unwrap();
            secrets.mac_key_or_new().unwrap();
            let files = paths.config_key().exists() || paths.key_file("lab").exists();
            let keyring = in_keyring(&paths, Key::Config).is_some()
                || in_keyring(&paths, Key::Center("lab")).is_some();
            assert_eq!(files, storage == SecretStorage::File, "{storage:?}");
            assert_eq!(keyring, storage == SecretStorage::Keyring, "{storage:?}");
        }
    }

    /// The installed node on Windows keeps its keyring secrets in the vault
    /// of its service account: another process asks the running service,
    /// and while none runs what it writes waits in a sealed file that the
    /// service takes at its start; a read then finds what waits, or says
    /// to start the node. An entry of another node is refused.
    #[test]
    fn the_installed_node_on_windows_keeps_its_secrets_in_its_services_vault() {
        let (_d, paths) = node();
        let headers = [("X-Key".to_string(), "s3cret-value".to_string())];
        let names = ["X-Key".to_string()];
        for_tests::pretend_windows_service(&paths);
        assert!(vault::through_service(&paths));
        // The service runs: the values go to its vault, through it.
        for_tests::pretend_service_runs(&paths, true);
        store_proxy_headers(&paths, &headers).unwrap();
        assert_eq!(proxy_headers(&paths, &names).unwrap(), headers);
        let entry = Entry::proxy(&paths);
        assert!(store::get(entry.account()).unwrap().is_some());
        assert!(!vault::pending_file(&paths).exists());
        // It does not run: a key written now waits for it, sealed, and is
        // read from there; an entry nothing waits for says to start it.
        for_tests::pretend_service_runs(&paths, false);
        put(
            &paths,
            SecretStorage::Keyring,
            Key::ProxyLogin,
            "t0ken-value",
        )
        .unwrap();
        let file = vault::pending_file(&paths);
        assert!(file.exists());
        assert_eq!(
            get(&paths, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .as_deref(),
            Some("t0ken-value")
        );
        let e = get(&paths, SecretStorage::Keyring, Key::RelayTls).unwrap_err();
        assert!(e.contains("start the node"), "{e}");
        assert!(remove_proxy_headers(&paths).unwrap());
        assert!(
            store::get(Key::ProxyLogin.entry(&paths).account())
                .unwrap()
                .is_none()
        );
        // Its start takes them, as the service.
        let n = vault::take_pending(&paths).unwrap();
        assert_eq!(n, 2);
        assert!(!file.exists());
        assert_eq!(
            store::get(Key::ProxyLogin.entry(&paths).account())
                .unwrap()
                .as_deref(),
            Some("t0ken-value")
        );
        assert_eq!(store::get(entry.account()).unwrap(), None);
        // The service serves its own node's entries only.
        let (_d2, other) = node();
        let e = vault::serve(
            &paths,
            "vault.get",
            &serde_json::json!({"account": Entry::proxy(&other).account()}),
        )
        .unwrap_err();
        assert!(e.contains("no entry of this node"), "{e}");
        for (account, mine) in [
            (Entry::center_key(&paths, "lab").account().to_string(), true),
            (Entry::config_key(&paths).account().to_string(), true),
            (format!("config-key:{}", paths.config_dir.display()), false),
            (
                Entry::center_key(&other, "lab").account().to_string(),
                false,
            ),
            ("center-key:../x:".to_string(), false),
            ("anything".to_string(), false),
        ] {
            assert_eq!(Entry::is_of(&paths, &account), mine, "{account}");
        }
        // A node on other folders keeps using the keyring itself.
        assert!(!vault::through_service(&other));
    }

    /// Before an install gives the service account a new password (Windows
    /// then no longer opens what it kept), and before an uninstall that
    /// keeps the data, the service copies its node's entries into the file
    /// its next start takes.
    #[test]
    fn the_service_stages_its_entries_for_a_new_install() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::Keyring, &["home"]));
        let headers = [("X-Key".to_string(), "s3cret-value".to_string())];
        store_proxy_headers(&paths, &headers).unwrap();
        let v = vault::serve(&paths, "vault.stage", &serde_json::json!({})).unwrap();
        assert_eq!(v["staged"], 3, "{v}");
        let key = Key::Center("home").entry(&paths);
        let kept = store::get(key.account()).unwrap();
        assert!(kept.is_some());
        // The account's vault is gone with its old password.
        store::delete(key.account()).unwrap();
        store::delete(Entry::proxy(&paths).account()).unwrap();
        vault::take_pending(&paths).unwrap();
        assert_eq!(store::get(key.account()).unwrap(), kept);
        assert!(
            store::get(Entry::proxy(&paths).account())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn without_a_keyring_a_node_with_keys_there_refuses_and_reads_no_file() {
        let (_d, paths) = node();
        paired(&paths, SecretStorage::Keyring, &["home"]);
        // Files with the same names, as if left behind: never read instead.
        std::fs::write(paths.config_key(), "00".repeat(32)).unwrap();
        let key = NodeKey::generate().unwrap();
        store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        store::set_unreachable(true);
        let e = open(&paths).err().unwrap();
        assert!(e.contains("machine.secret_storage is \"keyring\""), "{e}");
        assert!(e.contains("cannot be reached"), "{e}");
        assert!(e.contains(store::NO_SERVICE), "{e}");
        assert!(peek(&paths).is_err());
        let e = center_key(&paths, SecretStorage::Keyring, "home")
            .err()
            .unwrap();
        assert!(e.contains("from the system keyring"), "{e}");
        // Nor is a new key written to a file instead.
        let e = store_center_key(&paths, SecretStorage::Keyring, "lab", &key)
            .err()
            .unwrap();
        assert!(e.contains("system keyring"), "{e}");
        assert!(!paths.key_file("lab").exists());
        store::set_unreachable(false);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn keys_move_to_the_keyring_and_back_once() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home", "lab"]);
        let mac_text = get(&paths, SecretStorage::File, Key::Config)
            .unwrap()
            .unwrap();
        let home = center_key(&paths, SecretStorage::File, "home").unwrap();
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        // In the keyring, read back, and the files are gone.
        assert_eq!(in_keyring(&paths, Key::Config), Some(mac_text.clone()));
        assert!(in_keyring(&paths, Key::Center("lab")).is_some());
        assert!(!paths.config_key().exists());
        assert!(!paths.key_file("home").exists() && !paths.key_file("lab").exists());
        assert!(!paths.keys_moving().exists());
        // The node starts on them: the file's MAC checks with the keyring's
        // key, and the center keys are the same.
        drop(s);
        let mut s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::Keyring);
        let back = center_key(&paths, SecretStorage::Keyring, "home").unwrap();
        assert_eq!(back.public_key(), home.public_key());
        // And back to files.
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert_eq!(
            get(&paths, SecretStorage::File, Key::Config).unwrap(),
            Some(mac_text)
        );
        assert!(paths.key_file("lab").exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        assert!(!paths.keys_moving().exists());
        drop(s);
        let s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        let back = center_key(&paths, SecretStorage::File, "home").unwrap();
        assert_eq!(back.public_key(), home.public_key());
        // The change is audited as a setting.
        let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(audit.contains("machine.secret_storage"), "{audit}");
    }

    /// The relay's TLS key and an https:// proxy's password are keys of the
    /// node like the others: they move with `machine.secret_storage`, both
    /// ways, and read back the same.
    #[test]
    fn the_relay_key_and_the_proxy_password_move_with_the_other_keys() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home"]);
        let id = nerve_transport::tls::ServerIdentity::generate(&[]).unwrap();
        store_relay_tls(&paths, SecretStorage::File, &id).unwrap();
        store_proxy_login(&paths, SecretStorage::File, "t0ken").unwrap();
        s.update(|c| {
            c.relay.pin = Some(id.pin());
            c.connection.proxy = Some("https://relay.example:7490".into());
            c.connection.login = Some("lab".into());
            Ok(())
        })
        .unwrap();
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        assert!(in_keyring(&paths, Key::RelayTls).is_some());
        assert_eq!(
            in_keyring(&paths, Key::ProxyLogin).as_deref(),
            Some("t0ken")
        );
        assert!(!paths.relay_tls_file().exists() && !paths.proxy_login_file().exists());
        let back = relay_tls(&paths, SecretStorage::Keyring).unwrap().unwrap();
        assert_eq!(back.pin(), id.pin());
        assert_eq!(
            proxy_login(&paths, SecretStorage::Keyring).unwrap(),
            "t0ken"
        );
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert_eq!(in_keyring(&paths, Key::RelayTls), None);
        assert_eq!(in_keyring(&paths, Key::ProxyLogin), None);
        assert_eq!(
            relay_tls(&paths, SecretStorage::File)
                .unwrap()
                .unwrap()
                .pin(),
            id.pin()
        );
        assert_eq!(proxy_login(&paths, SecretStorage::File).unwrap(), "t0ken");
        remove_proxy_login(&paths, SecretStorage::File).unwrap();
        let e = proxy_login(&paths, SecretStorage::File).unwrap_err();
        assert!(e.contains("proxy set") && !e.contains("t0ken"), "{e}");
    }

    #[test]
    fn a_move_to_a_keyring_that_does_not_answer_changes_nothing() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home"]);
        let before = std::fs::read(paths.config_file()).unwrap();
        store::set_unreachable(true);
        let e = set_storage(&mut s, SecretStorage::Keyring).unwrap_err();
        store::set_unreachable(false);
        assert!(e.contains("cannot keep"), "{e}");
        assert!(
            e.contains("stay in their files, and nothing was changed"),
            "{e}"
        );
        // The command that offers a keyring: setup asks none while the keys
        // are in files.
        assert!(
            e.contains("`nerve-node config set machine.secret_storage keyring` at a terminal"),
            "{e}"
        );
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert!(!paths.keys_moving().exists());
        // A CLI that moves them itself, not the running node: the same
        // command, and no restart.
        drop(s);
        let mut cli = cli_store(&paths);
        store::set_unreachable(true);
        let e = set_storage(&mut cli, SecretStorage::Keyring).unwrap_err();
        store::set_unreachable(false);
        assert!(
            e.contains("`nerve-node config set machine.secret_storage keyring` at a terminal")
                && !e.contains("restart"),
            "{e}"
        );
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn a_move_left_to_the_next_start_is_finished_there() {
        let (_d, paths) = node();
        paired(&paths, SecretStorage::File, &["home"]);
        // A running node holds the lock: a CLI that writes the file itself
        // (on Windows) leaves it the old copies.
        let running = KeysLock::try_take_soon(&paths).unwrap().unwrap();
        assert!(KeysLock::try_take(&paths).unwrap().is_none());
        let mut s = windows_cli_store(&paths);
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(paths.keys_moving().exists());
        let cfg = s.config().clone();
        drop(s);
        // The node reads its key where it was, then its next start takes
        // the config and finishes the move.
        assert!(center_key(&paths, SecretStorage::File, "home").is_ok());
        drop(running);
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert_eq!(cfg.machine.secret_storage, SecretStorage::Keyring);
        assert!(!paths.config_key().exists() && !paths.key_file("home").exists());
        assert!(in_keyring(&paths, Key::Config).is_some());
        assert!(!paths.keys_moving().exists());
    }

    /// A copy whose write went through but whose read-back did not answer
    /// goes with the copies before it: neither place keeps anything of the
    /// move.
    #[test]
    fn a_copy_that_fails_after_its_write_leaves_nothing_in_the_new_place() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home", "lab"]);
        let before = std::fs::read(paths.config_file()).unwrap();
        // The second key is written, then its read-back fails.
        store::set_unreadable(Some(Entry::center_key(&paths, "home").account()));
        let e = set_storage(&mut s, SecretStorage::Keyring).unwrap_err();
        store::set_unreadable(None);
        assert!(e.contains("nothing was changed"), "{e}");
        for key in [Key::Config, Key::Center("home"), Key::Center("lab")] {
            assert_eq!(in_keyring(&paths, key), None, "{key:?}");
            assert!(key.file(&paths).exists(), "{key:?}");
        }
        assert!(!paths.keys_moving().exists());
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
    }

    /// Two CLIs with no node: one moves the keys, the other saves a change
    /// it made on the file before the move. That one is refused, so the
    /// file keeps naming where the keys are.
    #[test]
    fn a_cli_write_on_a_file_another_cli_changed_meanwhile_is_refused() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::File, &["home"]));
        let mut a = cli_store(&paths);
        let mut b = cli_store(&paths);
        set_storage(&mut a, SecretStorage::Keyring).unwrap();
        assert!(!paths.key_file("home").exists());
        let e = b
            .update(|c| {
                c.node.name = Some("lab-pc".into());
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(e, nerve_policy::SetError::Conflict { .. }), "{e}");
        drop((a, b));
        let s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::Keyring);
        assert!(center_key(&paths, SecretStorage::Keyring, "home").is_ok());
        // Opened again, the write goes through.
        let mut b = cli_store(&paths);
        b.update(|c| {
            c.node.name = Some("lab-pc".into());
            Ok(())
        })
        .unwrap();
    }

    /// A center removed while a move waits for the next start loses its key
    /// in the old place too: that start no longer looks for it.
    #[test]
    fn a_center_removed_while_a_move_waits_leaves_no_key_behind() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::Keyring, &["lab"]));
        let running = KeysLock::try_take_soon(&paths).unwrap().unwrap();
        let mut s = cli_store(&paths);
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert!(paths.keys_moving().exists());
        assert!(paths.key_file("lab").exists());
        assert!(in_keyring(&paths, Key::Center("lab")).is_some());
        s.update(|c| {
            c.centers.clear();
            Ok(())
        })
        .unwrap();
        remove_center_key(&paths, SecretStorage::File, "lab").unwrap();
        assert!(!paths.key_file("lab").exists());
        assert_eq!(in_keyring(&paths, Key::Center("lab")), None);
        drop((s, running));
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert!(!paths.keys_moving().exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
    }

    fn cli_store(paths: &NodePaths) -> SettingsStore {
        SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets::for_cli(paths)),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap()
    }

    /// The CLI's store as on Windows, where a move into the keyring is left
    /// to the next start of a node that holds the lock.
    fn windows_cli_store(paths: &NodePaths) -> SettingsStore {
        SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets {
                defers_keyring: true,
                ..NodeSecrets::for_cli(paths)
            }),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap()
    }

    /// On Linux a CLI that finds a node holding the lock does not move the
    /// keys into the keyring: that node did not answer on its control
    /// socket, so it would go on giving its folder mode commands a sandbox
    /// for keys in files.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_cli_does_not_move_the_keys_into_the_keyring_past_a_silent_node() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::File, &["home"]));
        let files = || {
            [
                paths.config_file(),
                paths.config_key(),
                paths.key_file("home"),
            ]
            .map(|f| std::fs::read(f).unwrap())
        };
        let before = files();
        let running = KeysLock::try_take_soon(&paths).unwrap().unwrap();
        let mut s = cli_store(&paths);
        let asked = store::calls();
        let e = set_storage(&mut s, SecretStorage::Keyring).unwrap_err();
        assert_eq!(store::calls(), asked, "the keyring was asked");
        assert!(e.contains("does not answer on its control socket"), "{e}");
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(files(), before);
        assert!(!paths.keys_moving().exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        // Once no node holds the lock, the move goes through.
        drop(running);
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(!paths.key_file("home").exists());
    }

    /// A command that another thread of the process forks holds a copy of
    /// keys.lock's descriptor until it execs, so a lock released a moment ago
    /// can look held (#73). The CLI's take must not read that as a node that
    /// holds it: its writes go on while commands are being started
    /// (`is_service_node` runs `getent` the way a daemon's start does).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_cli_takes_the_lock_while_commands_are_being_forked() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::File, &["home"]));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let forking = {
            let (paths, stop) = (paths.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    crate::service::is_service_node(&paths);
                }
            })
        };
        let mut s = NodeSecrets::for_cli(&paths);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut takes = 0;
        while std::time::Instant::now() < until {
            assert!(s.begin().unwrap(), "no lock was asked for");
            assert!(!s.defer, "the lock looked held after {takes} takes");
            s.end();
            takes += 1;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        forking.join().unwrap();
    }

    /// A running node does not take in a file that another writer saved
    /// with the keys in the keyring while it counts a folder mode command
    /// that started with them in files.
    #[test]
    fn a_reload_into_the_keyring_waits_for_the_commands_that_reach_the_bus() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::File, &["home"]));
        let count = Arc::new(AtomicUsize::new(1));
        let mut running = SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets::for_node(&paths, count.clone())),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        let mut other = open(&paths).unwrap();
        set_storage(&mut other, SecretStorage::Keyring).unwrap();
        let e = running.reload().unwrap_err();
        assert!(e.contains("1 folder mode command runs"), "{e}");
        assert!(e.contains("reload again"), "{e}");
        assert_eq!(running.config().machine.secret_storage, SecretStorage::File);
        count.store(0, Ordering::SeqCst);
        assert!(running.reload().unwrap());
        assert_eq!(
            running.config().machine.secret_storage,
            SecretStorage::Keyring
        );
    }

    /// A CLI with no node running moves the keys at once, holding the lock
    /// meanwhile; a node that read the config before that, and starts
    /// after it, leaves the keys alone.
    #[test]
    fn a_start_on_a_config_changed_since_it_was_read_moves_nothing() {
        let (_d, paths) = node();
        let s = paired(&paths, SecretStorage::Keyring, &["home"]);
        let read_before = s.config().clone();
        drop(s);
        let mut s = cli_store(&paths);
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert!(!paths.keys_moving().exists());
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        // The lock went with the move.
        assert!(KeysLock::try_take_soon(&paths).unwrap().is_some());
        settle(&paths, &read_before);
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        drop(s);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn copies_of_a_move_that_never_saved_its_config_go_at_the_next_start() {
        let (_d, paths) = node();
        let s = paired(&paths, SecretStorage::File, &["home"]);
        // Copied to the keyring, then stopped before node.toml was saved.
        let mut secrets = NodeSecrets::new(&paths);
        let mut target = s.config().clone();
        target.machine.secret_storage = SecretStorage::Keyring;
        secrets.copy(&target).unwrap();
        assert!(in_keyring(&paths, Key::Config).is_some());
        drop(s);
        let s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        settle(&paths, s.config());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert!(!paths.keys_moving().exists());
    }

    #[test]
    fn a_node_on_the_keyring_takes_keys_still_in_files_at_start() {
        let (_d, paths) = node();
        paired(&paths, SecretStorage::File, &["home"]);
        // Saved with `keyring`, the old copies left, and no mark of it.
        let running = KeysLock::try_take_soon(&paths).unwrap().unwrap();
        let mut s = windows_cli_store(&paths);
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        drop((s, running));
        std::fs::remove_file(paths.keys_moving()).unwrap();
        store::delete(Entry::center_key(&paths, "home").account()).unwrap();
        // Until the start, the key still in its file is read there.
        assert!(center_key(&paths, SecretStorage::Keyring, "home").is_ok());
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(!paths.config_key().exists() && !paths.key_file("home").exists());
    }

    #[test]
    fn an_edited_file_that_names_the_other_place_moves_the_keys_when_accepted() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::File, &["home"]));
        let edit = |from: &str, to: &str| {
            let text = std::fs::read_to_string(paths.config_file()).unwrap();
            let line = |s| format!("secret_storage = \"{s}\"");
            assert!(text.contains(&line(from)), "{text}");
            std::fs::write(paths.config_file(), text.replace(&line(from), &line(to))).unwrap();
        };
        let accept = || {
            SettingsStore::open_accepting_with(
                paths.config_file(),
                Box::new(NodeSecrets::for_accept(&paths)),
                AuditLog::new(paths.audit_log()),
            )
            .map(|(s, _)| s.config().machine.secret_storage)
        };
        edit("file", "keyring");
        // Changed by hand, so its MAC no longer checks.
        assert!(open(&paths).is_err());
        assert_eq!(accept(), Ok(SecretStorage::Keyring));
        assert!(in_keyring(&paths, Key::Config).is_some());
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(!paths.config_key().exists() && !paths.key_file("home").exists());
        assert!(open(&paths).is_ok());
        // And back: the key is found in the keyring.
        edit("keyring", "file");
        assert_eq!(accept(), Ok(SecretStorage::File));
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn with_the_default_the_keyring_is_never_asked() {
        // A keyring that would fail every call: a node with files works on
        // as it did, from its first start to its last key, and never asks
        // it.
        store::set_unreachable(true);
        let asked = store::calls();
        let (_d, paths) = node();
        assert_eq!(stated_storage(&paths), SecretStorage::File);
        let mut s = paired(&paths, SecretStorage::File, &["home"]);
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        s.update(|c| {
            c.node.name = Some("lab-pc".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert!(center_key(&paths, SecretStorage::File, "home").is_ok());
        remove_center_key(&paths, SecretStorage::File, "home").unwrap();
        assert!(peek(&paths).is_ok());
        // The key file is where it always was.
        assert!(paths.config_key().is_file());
        assert!(!paths.keys_moving().exists());
        assert_eq!(store::calls(), asked);
        // A file that does not parse names the default too.
        std::fs::write(paths.config_file(), "not toml [").unwrap();
        assert_eq!(stated_storage(&paths), SecretStorage::File);
        store::set_unreachable(false);
    }

    /// On Linux the keys may go into the keyring on every kernel: the
    /// commands of the installed node run as other accounts than the node's
    /// own, which do not reach its keyring (issue #135).
    #[cfg(not(windows))]
    #[test]
    fn the_keyring_holds_the_keys_on_every_linux_kernel() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home"]);
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::Keyring);
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert!(paths.key_file("home").exists());
    }

    /// The installed node's folders on Windows in another spelling are
    /// still its folders.
    #[test]
    fn folders_differing_in_case_are_the_same_folders() {
        let a = NodePaths::new(
            "C:\\ProgramData\\Nerve\\config",
            "C:\\ProgramData\\Nerve\\state",
        );
        let b = NodePaths::new(
            "c:/programdata/nerve/config/",
            "c:\\PROGRAMDATA\\nerve\\state",
        );
        assert!(same_folders_ignoring_case(&a, &b));
        let c = NodePaths::new(
            "C:\\ProgramData\\Nerve\\config2",
            "C:\\ProgramData\\Nerve\\state",
        );
        assert!(!same_folders_ignoring_case(&a, &c));
    }
}
