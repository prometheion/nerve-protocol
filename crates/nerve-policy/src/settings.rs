//! The settings store: `node.toml` with a version, written by the owner (CLI,
//! control socket) and, with the settings grant `write`, by a center for its
//! own [`CenterDocument`] (docs/dev/settings-and-config.md; spec §7.4).
//!
//! Every change is whole-document with `if_version`, so two writers never
//! overwrite each other unseen, is validated before it is saved, and lands in
//! the audit log with its old and new values and who made it.
//!
//! The node keeps the config in memory and signs every file it writes with a
//! MAC whose key no command of a center can read. The file is read at start-up
//! and when the owner asks for it; a file the node did not sign (one a command
//! rewrote, say) is refused, audited, and changes nothing. So is a signed file
//! older than the last one the node saved or took: the node keeps that version
//! in the state folder ([`VERSION_FILE`]), so an earlier file put back in the
//! config folder is refused at the next start as it is on a reload.
//!
//! Where the MAC key is kept is not the store's business: it asks a
//! [`Secrets`], which also moves the node's other secrets when
//! `machine.secret_storage` changes.

use std::path::{Path, PathBuf};

use nerve_transport::keys::MacKey;
use serde_json::Value;

use crate::audit::{AuditLog, Change, diff};
use crate::config::{
    Access, CapSetting, CenterDocument, Folder, NodeConfig, ProtectedOptions, SecretStorage,
    SettingsGrant, Sudo,
};
use crate::paths::to_wire;
use crate::protected::Protected;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetError {
    /// `if_version` is not the current version.
    Conflict { current: u64 },
    /// A client-only field changed, or the center has no settings grant.
    Forbidden(String),
    /// The new document does not parse or validate.
    Invalid(String),
    /// Saving failed.
    Io(String),
}

impl std::fmt::Display for SetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetError::Conflict { current } => {
                write!(f, "the settings changed; the current version is {current}")
            }
            SetError::Forbidden(s) | SetError::Invalid(s) | SetError::Io(s) => write!(f, "{s}"),
        }
    }
}

/// Who changes the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer<'a> {
    Local,
    Center(&'a str),
}

impl Writer<'_> {
    pub fn label(&self) -> String {
        match self {
            Writer::Local => "local".into(),
            Writer::Center(n) => format!("center {n}"),
        }
    }
}

/// The first line of a `node.toml` the node wrote: the MAC over the rest of
/// the file, then a note for whoever opens it.
const MAC_LINE: &str = "# mac hmac-sha256 ";
const MAC_NOTE: &str = " (nerve-node refuses this file once it is changed outside nerve-node)";

/// Goes into the MAC before the text, so the key signs nothing but a config.
const MAC_CONTEXT: &[u8] = b"nerve node.toml\n";

fn mac_input(body: &str) -> Vec<u8> {
    [MAC_CONTEXT, body.as_bytes()].concat()
}

/// The file the node writes for `c`: the MAC line, then the TOML. A restore
/// from a backup writes the config through it, with the key of the node it
/// restores into.
pub fn sealed(key: &MacKey, c: &NodeConfig) -> String {
    let body = c.to_toml();
    let mac = key.sign(&mac_input(&body));
    format!("{MAC_LINE}{mac}{MAC_NOTE}\n{body}")
}

/// A file's MAC (when its first line is a MAC line) and the TOML after it.
fn unseal(text: &str) -> (Option<&str>, &str) {
    match text.strip_prefix(MAC_LINE) {
        Some(rest) => {
            let (line, body) = rest.split_once('\n').unwrap_or((rest, ""));
            (Some(line.split(' ').next().unwrap_or_default()), body)
        }
        None => (None, text),
    }
}

/// `text` as a config, when the node signed it with `key`.
fn verified(text: &str, key: &MacKey) -> Result<NodeConfig, String> {
    match unseal(text) {
        (None, _) => Err("it carries no MAC, so nerve-node did not write it".into()),
        (Some(mac), body) if !key.verify(&mac_input(body), mac) => {
            Err("its MAC does not match, so it was changed outside nerve-node".into())
        }
        (Some(_), body) => NodeConfig::parse(body),
    }
}

/// The file in the state folder that holds the highest version of `node.toml`
/// the node has saved or taken (docs/dev/spec/node-local.md §1). The config
/// folder holds the signed files, the state folder the version that says
/// which of them is the last: whoever puts an earlier signed file back in the
/// config folder does not reach it.
pub const VERSION_FILE: &str = "config.version";

/// The version recorded at `path`; `None` when there is no record. A record
/// that is no number is an error: it is not taken for none, which would let
/// whoever damaged it have an older file accepted.
pub fn read_version(path: &Path) -> Result<Option<u64>, String> {
    let Some(text) = read_file(path)? else {
        return Ok(None);
    };
    text.trim().parse().map(Some).map_err(|_| {
        format!(
            "{} holds no version number; delete it and the node records the version of node.toml again",
            path.display()
        )
    })
}

/// Raises the record at `path` to `version`. A record that is as high already
/// stays, so the version never goes down; one that cannot be read is
/// written again.
pub fn record_version(path: &Path, version: u64) -> Result<(), String> {
    if matches!(read_version(path), Ok(Some(last)) if last >= version) {
        return Ok(());
    }
    nerve_transport::files::write_private(path, format!("{version}\n").as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Whether a signed file of this `version` may be taken: not when it is
/// older than the last one the node saved or took. The text says what to
/// tell the owner.
fn not_older(secrets: &dyn Secrets, version: u64) -> Result<(), String> {
    match secrets.accepted_version()? {
        Some(last) if version < last => Err(format!(
            "its version {version} is older than the last this node accepted ({last}), so an earlier file was put back"
        )),
        _ => Ok(()),
    }
}

/// Where the node keeps the key of its config's MAC and its other secrets
/// (`machine.secret_storage`, docs/dev/spec/node-local.md §1), as the store
/// sees it: the key, and a move of everything when a saved config names
/// another place.
pub trait Secrets: Send {
    /// Where the secrets are now.
    fn storage(&self) -> SecretStorage;
    /// The key; `None` when there is none yet.
    fn mac_key(&self) -> Result<Option<MacKey>, String>;
    /// The key, made and kept first when there is none. An existing key is
    /// never replaced: it would turn every file it signed into one the node
    /// refuses.
    fn mac_key_or_new(&self) -> Result<MacKey, String>;
    /// The highest version of `node.toml` the node has saved or taken
    /// ([`VERSION_FILE`]); `None` before there is one. A signed file below it
    /// is an older one put back.
    fn accepted_version(&self) -> Result<Option<u64>, String>;
    /// Raises that version to `version` ([`record_version`]).
    fn accept_version(&self, version: u64) -> Result<(), String>;
    /// Before `cfg`, whose `machine.secret_storage` differs from
    /// [`Secrets::storage`], is saved: copies every secret there and reads
    /// each copy back. An error refuses the change; nothing is saved then.
    fn copy(&mut self, cfg: &NodeConfig) -> Result<(), String>;
    /// Before [`SettingsStore::reload`] takes in `cfg`, which another
    /// writer saved with the secrets in another place than
    /// [`Secrets::storage`]: an error refuses the reload, and the config in
    /// force stays as it is.
    fn may_reload(&self, _cfg: &NodeConfig) -> Result<(), String> {
        Ok(())
    }
    /// `cfg` is saved: the secrets are in its place from now on, and the
    /// old copies go.
    fn moved(&mut self, cfg: &NodeConfig);
    /// `cfg` could not be saved: the copies [`Secrets::copy`] made go, and
    /// the secrets stay where they were.
    fn not_moved(&mut self, cfg: &NodeConfig);
    /// Before the store writes the file: keeps other writers off until
    /// [`Secrets::end`] where it can, and says whether another process may
    /// have written the file since this store read it (the CLI's store,
    /// opened for one command while another may run). The store then
    /// refuses a change made on a version that is no longer the file's.
    fn begin(&mut self) -> Result<bool, String> {
        Ok(false)
    }
    /// After that write, saved or not.
    fn end(&mut self) {}
}

/// The MAC key in a file of its own, and no other secret: a store opened on
/// a key path. It cannot move the key anywhere.
pub struct KeyFile(pub PathBuf);

impl Secrets for KeyFile {
    fn storage(&self) -> SecretStorage {
        SecretStorage::File
    }

    fn mac_key(&self) -> Result<Option<MacKey>, String> {
        MacKey::load(&self.0)
    }

    fn mac_key_or_new(&self) -> Result<MacKey, String> {
        MacKey::load_or_create(&self.0)
    }

    /// The record is beside the key, in the state folder.
    fn accepted_version(&self) -> Result<Option<u64>, String> {
        read_version(&self.0.with_file_name(VERSION_FILE))
    }

    fn accept_version(&self, version: u64) -> Result<(), String> {
        record_version(&self.0.with_file_name(VERSION_FILE), version)
    }

    fn copy(&mut self, _cfg: &NodeConfig) -> Result<(), String> {
        Err(format!(
            "this store keeps the config's key in {} and cannot move it to the system keyring",
            self.0.display()
        ))
    }

    fn moved(&mut self, _cfg: &NodeConfig) {}

    fn not_moved(&mut self, _cfg: &NodeConfig) {}
}

/// Where a config file says the node's secrets are, read without checking
/// its MAC: the key that checks it is looked for there. A file that cannot
/// be read says `file`, the default.
pub fn stated_storage(text: &str) -> SecretStorage {
    let table: Option<toml::Table> = toml::from_str(unseal(text).1).ok();
    match table
        .as_ref()
        .and_then(|t| t.get("machine"))
        .and_then(|m| m.get("secret_storage"))
        .and_then(toml::Value::as_str)
    {
        Some("keyring") => SecretStorage::Keyring,
        _ => SecretStorage::File,
    }
}

/// The file's text; `None` when there is no file.
fn read_file(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Told of each change to the settings: who made it, the new version and the
/// leaves that differ.
type Observer = Box<dyn Fn(&str, u64, &[Change]) + Send>;

pub struct SettingsStore {
    path: PathBuf,
    key: MacKey,
    secrets: Box<dyn Secrets>,
    audit: AuditLog,
    config: NodeConfig,
    observer: Option<Observer>,
    /// The account of the person whose local changes these are, for the
    /// audit ([`SettingsStore::set_user`]).
    user: Option<String>,
}

impl SettingsStore {
    /// Loads `path` (a missing file is the default config) and checks its MAC
    /// with the key at `key_path`. A file whose MAC does not match is refused
    /// and audited. The key is made when there is none; a file without
    /// a MAC line is then taken once, as it is, and signed.
    pub fn open(
        path: impl Into<PathBuf>,
        key_path: impl AsRef<Path>,
        audit: AuditLog,
    ) -> Result<SettingsStore, String> {
        let secrets = KeyFile(key_path.as_ref().to_path_buf());
        SettingsStore::open_with(path, Box::new(secrets), audit)
    }

    /// [`SettingsStore::open`] with the key where `secrets` keeps it.
    pub fn open_with(
        path: impl Into<PathBuf>,
        secrets: Box<dyn Secrets>,
        audit: AuditLog,
    ) -> Result<SettingsStore, String> {
        let path = path.into();
        let text = read_file(&path)?;
        let first = secrets.mac_key()?.is_none();
        let key = secrets.mac_key_or_new()?;
        let mut s = SettingsStore {
            path,
            key,
            secrets,
            audit,
            config: NodeConfig::default(),
            observer: None,
            user: None,
        };
        // The versions a file of this node had stay behind it: the next one
        // continues them, or the node would refuse its own file at its next
        // start.
        let last = s.secrets.accepted_version()?.unwrap_or(0);
        let Some(text) = text else {
            s.config.version = last;
            return Ok(s);
        };
        if first && unseal(&text).0.is_none() {
            let mut c =
                NodeConfig::parse(&text).map_err(|e| format!("{}: {e}", s.path.display()))?;
            c.version = c.version.max(last);
            s.write(&c, None).map_err(|e| e.to_string())?;
            s.config = c;
            let _ = s
                .audit
                .config("signed", &s.path, "has no MAC; signed as it was");
            return Ok(s);
        }
        let cfg = verified(&text, &s.key).map_err(|why| s.refuse(&why))?;
        not_older(s.secrets.as_ref(), cfg.version).map_err(|why| s.refuse(&why))?;
        // A file saved without a record (a state folder made new, or a
        // record that could not be written).
        s.remember(cfg.version);
        s.config = cfg;
        Ok(s)
    }

    /// Opens the store for `nerve-node config accept` while no daemon runs:
    /// the file is taken as it is ([`SettingsStore::accept`]).
    pub fn open_accepting(
        path: impl Into<PathBuf>,
        key_path: impl AsRef<Path>,
        audit: AuditLog,
    ) -> Result<(SettingsStore, u64), String> {
        let secrets = KeyFile(key_path.as_ref().to_path_buf());
        SettingsStore::open_accepting_with(path, Box::new(secrets), audit)
    }

    /// [`SettingsStore::open_accepting`] with the key where `secrets` keeps
    /// it. When the file names another place, the secrets move there.
    pub fn open_accepting_with(
        path: impl Into<PathBuf>,
        secrets: Box<dyn Secrets>,
        audit: AuditLog,
    ) -> Result<(SettingsStore, u64), String> {
        let mut s = SettingsStore {
            path: path.into(),
            key: secrets.mac_key_or_new()?,
            secrets,
            audit,
            config: NodeConfig::default(),
            observer: None,
            user: None,
        };
        let v = s.accept().map_err(|e| e.to_string())?;
        Ok((s, v))
    }

    /// The config at `path` as [`SettingsStore::open`] would take it, without
    /// writing anything (what the CLI shows while no daemon runs).
    pub fn peek(path: &Path, key_path: &Path) -> Result<NodeConfig, String> {
        SettingsStore::peek_with(path, &KeyFile(key_path.to_path_buf()))
    }

    /// [`SettingsStore::peek`] with the key where `secrets` keeps it.
    pub fn peek_with(path: &Path, secrets: &dyn Secrets) -> Result<NodeConfig, String> {
        let Some(text) = read_file(path)? else {
            return Ok(NodeConfig::default());
        };
        let refused = |why: String| {
            format!(
                "{} is refused: {why}; check it, then `nerve-node config accept` takes it as it is",
                path.display()
            )
        };
        match secrets.mac_key()? {
            Some(key) => verified(&text, &key)
                .and_then(|c| not_older(secrets, c.version).map(|()| c))
                .map_err(refused),
            // The node signs such a file the first time it opens it.
            None if unseal(&text).0.is_none() => {
                NodeConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
            }
            None => Err(refused(
                "it is signed with a key this node does not have".into(),
            )),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Calls `f` after every change the store writes (not after bookkeeping
    /// the node sets itself). The daemon logs them; the CLI, which opens the
    /// store for one command, has no observer.
    pub fn on_change(&mut self, f: impl Fn(&str, u64, &[Change]) + Send + 'static) {
        self.observer = Some(Box::new(f));
    }

    /// Names the account of the person who makes the next local changes
    /// (`None`: not known), which the audit records beside `local`.
    pub fn set_user(&mut self, user: Option<String>) {
        self.user = user;
    }

    /// Audits a change that was saved and tells the observer.
    fn changed(&self, by: &str, version: u64, changes: &[Change]) {
        let user = (by == Writer::Local.label())
            .then_some(self.user.as_deref())
            .flatten();
        // The change is saved; an audit log that cannot be written is no
        // reason to undo it.
        let _ = self.audit.settings_by(by, user, version, changes);
        if let Some(f) = &self.observer {
            f(by, version, changes);
        }
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn version(&self) -> u64 {
        self.config.version
    }

    /// Reads the file again because the owner asks (SIGHUP, the control
    /// socket's `reload`). Only a file the node signed is applied, and never
    /// an older version than the one in force or the last one recorded
    /// ([`VERSION_FILE`]); anything else is refused and
    /// audited, and the old config stays in force. It stays too while a
    /// move of the secrets the file names is refused
    /// ([`Secrets::may_reload`]).
    pub fn reload(&mut self) -> Result<bool, String> {
        let text = read_file(&self.path)?.ok_or_else(|| self.refuse("the file is missing"))?;
        let fresh = verified(&text, &self.key).map_err(|why| self.refuse(&why))?;
        if fresh.version < self.config.version {
            return Err(self.refuse(&format!(
                "its version {} is older than the one in force ({})",
                fresh.version, self.config.version
            )));
        }
        // The in-force version can lag the record: a CLI that wrote the file
        // itself raised it.
        not_older(self.secrets.as_ref(), fresh.version).map_err(|why| self.refuse(&why))?;
        // Another writer saved a file that keeps the secrets elsewhere, and
        // copied them there first.
        if fresh.machine.secret_storage != self.secrets.storage() {
            self.secrets.may_reload(&fresh)?;
            self.secrets.moved(&fresh);
        }
        let changed = fresh != self.config;
        self.remember(fresh.version);
        self.config = fresh;
        Ok(changed)
    }

    /// Takes the file as it is now, after the node refused it (`nerve-node
    /// config accept`: the owner has looked at it). Its MAC is not checked;
    /// it must still parse and validate, and the node signs it.
    pub fn accept(&mut self) -> Result<u64, SetError> {
        self.accept_with(|_, _| ()).map(|(v, _)| v)
    }

    /// [`SettingsStore::accept`], with `change(before, taken)` made to the
    /// file's config before it is written and in force, so one write
    /// carries both: no reader, and no node that stops between two writes,
    /// sees the file without the change. Returns the version and what
    /// `change` returned.
    pub fn accept_with<T>(
        &mut self,
        change: impl FnOnce(&NodeConfig, &mut NodeConfig) -> T,
    ) -> Result<(u64, T), SetError> {
        let missing = || SetError::Invalid(format!("{} is missing", self.path.display()));
        let text = read_file(&self.path)
            .map_err(SetError::Io)?
            .ok_or_else(missing)?;
        let mut new = NodeConfig::parse(unseal(&text).1)
            .map_err(|e| SetError::Invalid(format!("{}: {e}", self.path.display())))?;
        // Above every version the node has had, so an earlier file the owner
        // takes is the newest one now, and the record never goes down. A
        // record that cannot be read is written again.
        let last = self.secrets.accepted_version().ok().flatten().unwrap_or(0);
        new.version = self.config.version.max(new.version).max(last) + 1;
        let made = change(&self.config, &mut new);
        // Taken as it is: whoever wrote it last.
        self.write(&new, None)?;
        let changes = diff(&to_json(&self.config), &to_json(&new));
        let version = new.version;
        self.config = new;
        let _ = self
            .audit
            .config("accepted", &self.path, "the owner took the file as it was");
        self.changed(&Writer::Local.label(), version, &changes);
        Ok((version, made))
    }

    /// Audits a refused file and says why it was refused.
    fn refuse(&self, why: &str) -> String {
        // The refusal stands even when the audit log cannot be written.
        let _ = self.audit.config("refused", &self.path, why);
        format!(
            "{} is refused: {why}; check it, then `nerve-node config accept` takes it as it is",
            self.path.display()
        )
    }

    /// Writes `c`, moving the node's secrets first when it keeps them in
    /// another place: copied there and read back, then the file, then the
    /// old copies go. A move that fails saves nothing.
    ///
    /// `opened` is the version `c` was made from. Where another process may
    /// have written the file meanwhile ([`Secrets::begin`]), a file that is
    /// no longer that version is a conflict and nothing is written: a
    /// change made on the old file would undo the other one, and with it a
    /// move of the keys that one made.
    fn write(&mut self, c: &NodeConfig, opened: Option<u64>) -> Result<(), SetError> {
        let shared = self.secrets.begin().map_err(SetError::Io)?;
        let r = (|| {
            if let Some(opened) = opened.filter(|_| shared) {
                let now = self.version_on_disk().map_err(SetError::Io)?;
                if now != opened {
                    return Err(SetError::Conflict { current: now });
                }
            }
            if c.machine.secret_storage == self.secrets.storage() {
                return self.write_file(c).map_err(SetError::Io);
            }
            self.secrets.copy(c).map_err(SetError::Io)?;
            if let Err(e) = self.write_file(c) {
                self.secrets.not_moved(c);
                return Err(SetError::Io(e));
            }
            self.secrets.moved(c);
            Ok(())
        })();
        self.secrets.end();
        r
    }

    /// The version of the file as it is now, read without checking its MAC
    /// (the version a write must not go behind): 0 for no file, and for one
    /// that names none.
    pub fn version_on_disk(&self) -> Result<u64, String> {
        let Some(text) = read_file(&self.path)? else {
            return Ok(0);
        };
        let table: Option<toml::Table> = toml::from_str(unseal(&text).1).ok();
        Ok(table
            .as_ref()
            .and_then(|t| t.get("version"))
            .and_then(toml::Value::as_integer)
            .map_or(0, |v| v as u64))
    }

    /// Writes `c` atomically, signed.
    fn write_file(&self, c: &NodeConfig) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        nerve_transport::files::write_private(&self.path, sealed(&self.key, c).as_bytes())
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        // After the file, never before: a record ahead of a file that was not
        // saved would make the node refuse the file it has.
        self.remember(c.version);
        Ok(())
    }

    /// Raises the record of the last version saved or taken. The file is
    /// saved by now, so a record that cannot be written is audited and no
    /// reason to undo anything: it only lags, and the next start records
    /// the version.
    fn remember(&self, version: u64) {
        if let Err(e) = self.secrets.accept_version(version) {
            let _ = self.audit.config(
                "not_recorded",
                &self.path,
                &format!("version {version} is not recorded: {e}"),
            );
        }
    }

    /// Replaces the whole config as the owner; `if_version` guards against a
    /// concurrent writer.
    pub fn set_local(&mut self, new: NodeConfig, if_version: Option<u64>) -> Result<u64, SetError> {
        if let Some(v) = if_version
            && v != self.config.version
        {
            return Err(SetError::Conflict {
                current: self.config.version,
            });
        }
        self.commit(Writer::Local, new)
    }

    /// Changes the config as the owner through a closure (CLI commands).
    pub fn update(
        &mut self,
        f: impl FnOnce(&mut NodeConfig) -> Result<(), String>,
    ) -> Result<u64, SetError> {
        let mut new = self.config.clone();
        f(&mut new).map_err(SetError::Invalid)?;
        self.commit(Writer::Local, new)
    }

    /// Updates bookkeeping the node itself sets (revoked, unknown) without
    /// counting it as a settings change by anyone.
    pub fn mark(&mut self, f: impl FnOnce(&mut NodeConfig)) -> Result<(), String> {
        let mut new = self.config.clone();
        f(&mut new);
        if new == self.config {
            return Ok(());
        }
        new.version = self.next_version();
        self.write(&new, Some(self.config.version))
            .map_err(|e| e.to_string())?;
        self.config = new;
        Ok(())
    }

    /// The document `settings.get` shows `center`.
    pub fn center_document(&self, center: &str) -> Option<CenterDocument> {
        self.config.center(center).map(|c| CenterDocument {
            paused: c.paused,
            policy: c.policy.clone(),
        })
    }

    /// `settings.set` from `center`: the whole document, checked against
    /// `if_version`. `owner_only(scope)` says whether a capability (`cap`) or
    /// an action (`cap.action`) senses (camera, microphone, screen) or
    /// actuates (a lamp, a lock), or may for all the node knows: only the
    /// owner may turn those on. It gets the whole scope of a `caps` key or an
    /// allow rule.
    /// `protected(opts)` is this node's protected list with a center's
    /// options: only the owner may release an entry of it.
    pub fn set_center_document(
        &mut self,
        center: &str,
        document: Value,
        if_version: u64,
        owner_only: impl Fn(&str) -> bool,
        protected: impl Fn(&ProtectedOptions) -> Protected,
    ) -> Result<u64, SetError> {
        let entry = self
            .config
            .center(center)
            .ok_or_else(|| SetError::Forbidden(format!("no center {center}")))?;
        if entry.settings != SettingsGrant::Write {
            return Err(SetError::Forbidden(
                "this node does not let this center change its settings".into(),
            ));
        }
        if if_version != self.config.version {
            return Err(SetError::Conflict {
                current: self.config.version,
            });
        }
        let mut new: CenterDocument =
            serde_json::from_value(document).map_err(|e| SetError::Invalid(e.to_string()))?;
        // The record of the folders' real places is the owner's: whatever the
        // document says, it stays as it was, less the folders the center
        // removed (validation drops those).
        new.policy.places = entry.policy.places.clone();
        new.policy
            .validate()
            .map_err(|e| SetError::Invalid(e.to_string()))?;
        let old = CenterDocument {
            paused: entry.paused,
            policy: entry.policy.clone(),
        };
        client_only(&old, &new, &owner_only, &protected).map_err(SetError::Forbidden)?;
        let mut cfg = self.config.clone();
        let e = cfg.center_mut(center).expect("checked above");
        e.paused = new.paused;
        e.policy = new.policy;
        self.commit(Writer::Center(center), cfg)
    }

    /// Sets the node's sudo switch: the one machine setting a center with the
    /// `write` grant may change. The caller has checked the password before
    /// it turns the switch on.
    pub fn set_sudo(&mut self, by: Writer, sudo: Sudo) -> Result<u64, SetError> {
        if let Writer::Center(center) = by {
            let entry = self
                .config
                .center(center)
                .ok_or_else(|| SetError::Forbidden(format!("no center {center}")))?;
            if entry.settings != SettingsGrant::Write {
                return Err(SetError::Forbidden(
                    "this node does not let this center change its settings".into(),
                ));
            }
        }
        let mut cfg = self.config.clone();
        cfg.machine.sudo = sudo;
        self.commit(by, cfg)
    }

    fn commit(&mut self, by: Writer, mut new: NodeConfig) -> Result<u64, SetError> {
        // A center's pin changed by hand to another one (after a rotation
        // of the center's key the node missed) counts as a rotation the node
        // took: a restore then keeps it over a backup's older pin.
        // Pins are compared by their bytes: the same pin written with base64
        // padding is no change.
        let same_pin = |a: &str, b: &str| match (
            nerve_transport::tls::decode_pin(a),
            nerve_transport::tls::decode_pin(b),
        ) {
            (Ok(x), Ok(y)) => x == y,
            _ => a == b,
        };
        for c in new.centers.iter_mut() {
            if let Some(o) = self.config.center(&c.name)
                && o.center_id == c.center_id
                && o.pin_rotations == c.pin_rotations
                && let (Some(was), Some(now)) = (o.pin.as_deref(), c.pin.as_deref())
                && !same_pin(was, now)
            {
                c.pin_rotations += 1;
            }
        }
        new.version = self.config.version;
        new.validate().map_err(SetError::Invalid)?;
        if new == self.config {
            return Ok(self.config.version);
        }
        new.version = self.next_version();
        self.write(&new, Some(self.config.version))?;
        let changes = diff(&to_json(&self.config), &to_json(&new));
        let version = new.version;
        self.config = new;
        self.changed(&by.label(), version, &changes);
        Ok(version)
    }

    /// The version of the file this store saves next: above the one in force
    /// and above the record. Another writer may have saved the file
    /// meanwhile and raised the record past the version in force (the CLI on
    /// Windows, which has no socket to ask the node, or on Linux before the
    /// node's socket is up). This store's save replaces that file, as it
    /// always did; but numbered by its own version alone it would land below
    /// the record, and the node would refuse its own file at its next start
    /// as an earlier one put back. A record that cannot be read counts as
    /// none; the save writes it again.
    fn next_version(&self) -> u64 {
        let last = self.secrets.accepted_version().ok().flatten().unwrap_or(0);
        self.config.version.max(last) + 1
    }
}

fn to_json(c: &NodeConfig) -> Value {
    let mut v = serde_json::to_value(c).expect("the node config serializes");
    if let Some(o) = v.as_object_mut() {
        o.remove("version");
    }
    v
}

/// The fields of its own document a center may not change
/// (docs/dev/settings-and-config.md). The whole document is refused, naming
/// the first such field.
fn client_only(
    old: &CenterDocument,
    new: &CenterDocument,
    owner_only: &dyn Fn(&str) -> bool,
    protected: &dyn Fn(&ProtectedOptions) -> Protected,
) -> Result<(), String> {
    if old.paused && !new.paused {
        return Err("paused: only the owner can unpause".into());
    }
    let (o, n) = (&old.policy, &new.policy);
    for (key, setting) in &n.caps {
        if *setting == CapSetting::On && o.caps.get(key) != Some(&CapSetting::On) && owner_only(key)
        {
            return Err(format!(
                "policy.caps.{key}: only the owner can turn on what senses or actuates, and a capability the node does not offer now may do either"
            ));
        }
    }
    // An `off` or `hidden` entry, kept or set by the owner under a wider
    // `on`, is what keeps a sense or actuate action off: taking it away
    // turns it on as surely as an `on` would.
    for (key, setting) in &o.caps {
        let kept = matches!(setting, CapSetting::Off | CapSetting::Hidden);
        let still = matches!(n.caps.get(key), Some(CapSetting::Off | CapSetting::Hidden));
        if kept && !still && owner_only(key) {
            return Err(format!(
                "policy.caps.{key}: only the owner can turn on what senses or actuates, and a capability the node does not offer now may do either"
            ));
        }
    }
    // An allow rule would let such a capability through in allowlist mode,
    // whatever `caps` says; so adding one for it is the owner's call as well.
    for rule in n.allow.iter().filter(|r| !o.allow.contains(r)) {
        let scope = crate::rules::scope_of(rule);
        if owner_only(scope) {
            return Err(format!(
                "policy.allow {rule}: only the owner can turn on what senses or actuates, and a capability the node does not offer now may do either"
            ));
        }
    }
    // And so is taking away a deny rule that keeps one off under a wider
    // allow rule or mode.
    for rule in o.deny.iter().filter(|r| !n.deny.contains(r)) {
        let scope = crate::rules::scope_of(rule);
        if owner_only(scope) {
            return Err(format!(
                "policy.deny {rule}: only the owner can turn on what senses or actuates, and a capability the node does not offer now may do either"
            ));
        }
    }
    if n.protected.allow != o.protected.allow {
        // Releasing a protected path is the owner's call; adding more is fine.
        return Err("policy.protected.allow: only the owner can release protected paths".into());
    }
    // Extra protected paths hold in User mode too: dropping one is a release
    // as well.
    if let Some(gone) = o
        .protected
        .extra
        .iter()
        .find(|p| !n.protected.extra.contains(p))
    {
        return Err(format!(
            "policy.protected.extra {gone}: only the owner can release protected paths"
        ));
    }
    // A folder at or inside a protected entry releases it (Protected::check),
    // and the deepest folder there gives that place its flags. So at every
    // place where the access may change, each old and each new folder, the
    // new folders may give a protected place no flag the old ones did not:
    // no release where the old folders released nothing, and no wider access
    // where they did. Places are compared by path with the list's own rules,
    // so neither another spelling of the owner's folder, nor a folder inside
    // it, nor dropping a narrower one inside it widens anything.
    let prot = protected(&n.protected);
    for place in n.folders.iter().chain(&o.folders) {
        let path = Path::new(&place.path);
        let Some(entry) = prot.check(path, true, &[]) else {
            continue;
        };
        // The flags the deepest folder at or inside the entry gives `path`.
        let given = |folders: &[Folder]| {
            prot.deepest(folders, path)
                .filter(|f| prot.holds(entry, Path::new(&f.path)))
                .map(|f| f.access)
        };
        // The node's own folders are never released, whatever a folder says.
        let before = given(&o.folders).filter(|_| prot.own(path).is_none());
        let why = match (before, given(&n.folders)) {
            (None, Some(_)) => "only the owner can release protected paths",
            (Some(old), Some(new)) if widens(old, new) => {
                "only the owner can widen the access of a folder there"
            }
            _ => continue,
        };
        return Err(format!(
            "policy.folders {}: {} is protected; {why}",
            place.path,
            to_wire(entry)
        ));
    }
    // Landlock follows a link, so a folder is also judged where it really
    // leads: a new or wider one that is, or passes through, a link into a
    // protected entry needs the owner's folders to release that place with
    // its flags. A folder the old document had with the same or more
    // access changes nothing here; one that became a link since is left
    // out of the command's sandbox (`exec::landlock_spec`).
    for f in &n.folders {
        let kept = o
            .folders
            .iter()
            .any(|g| g.path == f.path && !widens(g.access, f.access));
        if kept {
            continue;
        }
        if let Err(why) = prot.real_folder(f, &o.folders) {
            return Err(format!(
                "policy.folders {}: {why}; only the owner can release protected paths",
                f.path
            ));
        }
    }
    Ok(())
}

/// Whether `new` sets a flag `old` does not.
fn widens(old: Access, new: Access) -> bool {
    (new.read && !old.read) || (new.write && !old.write) || (new.execute && !old.execute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CenterEntry, CenterPolicy, Mode};
    use serde_json::json;

    fn store(dir: &Path, grant: SettingsGrant) -> SettingsStore {
        let mut s = SettingsStore::open(
            dir.join("node.toml"),
            dir.join("config.key"),
            AuditLog::new(dir.join("audit.jsonl")),
        )
        .unwrap();
        s.update(|c| {
            c.centers.push(CenterEntry {
                name: "home".into(),
                url: "https://center.example".into(),
                pin: None,
                center_id: "c".into(),
                node_id: "n".into(),
                settings: grant,
                paused: false,
                revoked: false,
                unknown: false,
                public_key: None,
                key_rotations: 0,
                pin_rotations: 0,
                old_pin: None,
                policy: CenterPolicy::default(),
            });
            Ok(())
        })
        .unwrap();
        s
    }

    /// The daemon hangs its log on this: each saved change is reported with
    /// who made it, the version and what differs; a change that is not
    /// saved, and one that changes nothing, is not.
    #[test]
    fn an_observer_hears_of_each_saved_change() {
        use std::sync::{Arc, Mutex};
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        type Heard = (String, u64, Vec<String>);
        let heard: Arc<Mutex<Vec<Heard>>> = Arc::default();
        let sink = heard.clone();
        s.on_change(move |by, version, changes| {
            let keys = changes.iter().map(|c| c.key.clone()).collect();
            sink.lock().unwrap().push((by.to_string(), version, keys));
        });
        let before = s.version();
        s.update(|c| {
            c.log.level = nerve_transport::log::Level::Debug;
            Ok(())
        })
        .unwrap();
        // The same again changes nothing and is not reported.
        s.update(|c| {
            c.log.level = nerve_transport::log::Level::Debug;
            Ok(())
        })
        .unwrap();
        let mut doc = serde_json::to_value(s.center_document("home").unwrap()).unwrap();
        doc["policy"]["allow"] = json!(["fs.read:/tmp/x"]);
        s.set_center_document("home", doc, s.version(), |_| false, unix)
            .unwrap();
        // A refused write is not a change.
        let stale = serde_json::to_value(s.center_document("home").unwrap()).unwrap();
        assert!(
            s.set_center_document("home", stale, 1, |_| false, unix)
                .is_err()
        );
        s.set_sudo(Writer::Local, Sudo::Off).unwrap();
        s.mark(|c| c.centers[0].revoked = true).unwrap();
        let heard = heard.lock().unwrap();
        assert_eq!(
            *heard,
            [
                (
                    "local".to_string(),
                    before + 1,
                    vec!["log.level".to_string()]
                ),
                (
                    "center home".to_string(),
                    before + 2,
                    vec!["center".to_string()]
                ),
            ]
        );
    }

    /// The protected list of a Unix node at `/home/u`.
    fn unix(opts: &ProtectedOptions) -> Protected {
        Protected::new(
            &crate::protected::Platform::Unix,
            Path::new("/home/u"),
            &[],
            opts,
        )
    }

    /// A home that is absolute on the platform the tests run on, so a
    /// folder below it passes validation there and reaches the check under
    /// test (Windows refuses `/home/u` as not absolute).
    fn host_home() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            "C:\\Users\\u"
        } else {
            "/home/u"
        })
    }

    /// `rel` (with `/`) below [`host_home`], in the platform's own form.
    fn at_home(rel: &str) -> PathBuf {
        rel.split('/').fold(host_home(), |p, seg| p.join(seg))
    }

    /// The protected list of a node at [`host_home`] on this platform.
    fn host(opts: &ProtectedOptions) -> Protected {
        let platform = if cfg!(windows) {
            crate::protected::Platform::Windows(Default::default())
        } else {
            crate::protected::Platform::Unix
        };
        Protected::new(&platform, &host_home(), &[], opts)
    }

    fn doc(s: &SettingsStore) -> Value {
        serde_json::to_value(s.center_document("home").unwrap()).unwrap()
    }

    /// The record of the folders' real places is the owner's: a center's
    /// document cannot add an entry, take one away or rewrite it, and an
    /// entry goes only with its folder.
    #[test]
    fn a_center_cannot_change_the_record_of_real_places() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let (work, bin) = (at_home("work"), at_home("work/bin"));
        let path = |p: &Path| p.to_string_lossy().into_owned();
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            for (at, access) in [(&work, "rw"), (&bin, "r")] {
                p.folders.push(crate::config::Folder {
                    path: path(at),
                    access: crate::config::Access::parse(access).unwrap(),
                });
            }
            p.set_placed(&path(&bin), true);
            Ok(())
        })
        .unwrap();
        let placed = |s: &SettingsStore| s.config().center("home").unwrap().policy.places.clone();
        assert_eq!(placed(&s), [path(&bin)]);
        // The document shows it; the same document back, one without it, and
        // one that names others, change nothing about it.
        assert_eq!(doc(&s)["policy"]["places"], json!([path(&bin)]));
        for places in [
            Some(json!([])),
            None,
            Some(json!([path(&work), "/nowhere"])),
        ] {
            let mut new = doc(&s);
            new["policy"]["caps"] = json!({"exec": "off"});
            match places {
                Some(p) => new["policy"]["places"] = p,
                None => {
                    new["policy"].as_object_mut().unwrap().remove("places");
                }
            }
            let v = s.version();
            s.set_center_document("home", new, v, |_| false, host)
                .unwrap();
            assert_eq!(placed(&s), [path(&bin)]);
            // Back to the way it was for the next round.
            let mut new = doc(&s);
            new["policy"]["caps"] = json!({});
            let v = s.version();
            s.set_center_document("home", new, v, |_| false, host)
                .unwrap();
        }
        // A folder the center removes takes its entry along, and one it
        // adds again is not recorded.
        let mut new = doc(&s);
        new["policy"]["folders"] = json!([{"path": path(&work), "access": "rw"}]);
        let v = s.version();
        s.set_center_document("home", new, v, |_| false, host)
            .unwrap();
        assert!(placed(&s).is_empty());
        let mut new = doc(&s);
        new["policy"]["folders"] = json!([
            {"path": path(&work), "access": "rw"},
            {"path": path(&bin), "access": "r"}
        ]);
        new["policy"]["places"] = json!([path(&bin)]);
        let v = s.version();
        s.set_center_document("home", new, v, |_| false, host)
            .unwrap();
        assert!(placed(&s).is_empty());
    }

    #[test]
    fn only_a_writing_center_switches_sudo() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        assert!(matches!(
            s.set_sudo(Writer::Center("home"), Sudo::On),
            Err(SetError::Forbidden(_))
        ));
        assert_eq!(s.config().machine.sudo, Sudo::Off);
        s.set_sudo(Writer::Local, Sudo::On).unwrap();
        assert_eq!(s.config().machine.sudo, Sudo::On);
        let mut s = store(&d.path().join("w"), SettingsGrant::Write);
        let v = s.set_sudo(Writer::Center("home"), Sudo::On).unwrap();
        assert_eq!(s.version(), v);
        let log = s.audit().read().unwrap();
        let last = log.last().unwrap();
        assert_eq!(last["by"], "center home");
        assert!(
            last["changes"].to_string().contains("machine.sudo"),
            "{last}"
        );
    }

    #[test]
    fn center_sets_with_version_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["mode"] = json!("user");
        new["policy"]["until"] = json!(1000);
        let v2 = s
            .set_center_document("home", new.clone(), v, |_| false, unix)
            .unwrap();
        assert_eq!(v2, v + 1);
        assert_eq!(s.config().center("home").unwrap().policy.mode, Mode::User);
        // A stale version conflicts.
        assert_eq!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Conflict { current: v2 })
        );
        // Saved and reloaded.
        let again = SettingsStore::open(
            d.path().join("node.toml"),
            d.path().join("config.key"),
            AuditLog::new(d.path().join("a")),
        )
        .unwrap();
        assert_eq!(again.version(), v2);
        let log = s.audit().read().unwrap();
        let last = log.last().unwrap();
        assert_eq!(last["by"], "center home");
        assert_eq!(last["changes"][0]["key"], "center");
    }

    /// What keeps a sense action off under a wider entry of the owner (an
    /// `off` or `hidden` switch for it under a capability that is on, a deny
    /// rule for it under an allow rule for the capability) is the owner's to
    /// take away: without it the sense action runs. The same entries for
    /// what does not sense are the center's.
    #[test]
    fn a_center_may_not_take_away_what_keeps_sensing_off() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.centers[0].policy;
            p.caps.insert("camera".into(), CapSetting::On);
            p.caps.insert("camera.snap".into(), CapSetting::Off);
            p.caps.insert("camera.film".into(), CapSetting::Hidden);
            p.caps.insert("fs.write".into(), CapSetting::Off);
            p.allow = vec!["camera".into()];
            p.deny = vec!["camera.snap".into(), "exec.run:rm *".into()];
            Ok(())
        })
        .unwrap();
        let senses = |scope: &str| scope.split('.').next() == Some("camera");
        let v = s.version();
        for (what, change) in [
            (
                "policy.caps.camera.snap",
                json!({"caps": {"camera": "on", "camera.film": "hidden", "fs.write": "off"}}),
            ),
            (
                "policy.caps.camera.snap",
                json!({"caps": {"camera": "on", "camera.snap": "on", "camera.film": "hidden", "fs.write": "off"}}),
            ),
            (
                "policy.caps.camera.film",
                json!({"caps": {"camera": "on", "camera.snap": "off", "fs.write": "off"}}),
            ),
            (
                "policy.deny camera.snap",
                json!({"deny": ["exec.run:rm *"]}),
            ),
        ] {
            let mut new = doc(&s);
            for (k, val) in change.as_object().unwrap() {
                new["policy"][k] = val.clone();
            }
            let e = s
                .set_center_document("home", new, v, senses, unix)
                .unwrap_err();
            assert!(
                matches!(&e, SetError::Forbidden(m) if m.contains(what)),
                "{what}: {e:?}"
            );
        }
        // Hidden instead of off still keeps it off; what does not sense goes.
        let mut new = doc(&s);
        new["policy"]["caps"] =
            json!({"camera": "on", "camera.snap": "hidden", "camera.film": "off"});
        new["policy"]["deny"] = json!(["camera.snap"]);
        s.set_center_document("home", new, v, senses, unix).unwrap();
    }

    /// A rule of the guard covers `exec.run`, which does not sense: the
    /// center may take it away as it may any other command rule.
    #[test]
    fn a_rule_of_the_guard_is_a_command_rule_here() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        s.update(|c| {
            c.centers[0].policy.deny = vec!["guard:node-service".into()];
            Ok(())
        })
        .unwrap();
        // As the node judges: what it does not know may sense.
        let senses = |scope: &str| !matches!(scope.split('.').next(), Some("exec" | "fs"));
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["deny"] = json!([]);
        s.set_center_document("home", new, v, senses, unix).unwrap();
    }

    #[test]
    fn refuses_client_only_fields_and_missing_grant() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["caps"] = json!({"camera": "on"});
        let e = s
            .set_center_document(
                "home",
                new,
                v,
                |c| c.split('.').next() == Some("camera"),
                unix,
            )
            .unwrap_err();
        assert!(matches!(&e, SetError::Forbidden(m) if m.contains("policy.caps.camera")));
        // An allow rule is no way round that.
        let mut new = doc(&s);
        new["policy"]["allow"] = json!(["camera.snap"]);
        let e = s
            .set_center_document(
                "home",
                new,
                v,
                |c| c.split('.').next() == Some("camera"),
                unix,
            )
            .unwrap_err();
        assert!(matches!(&e, SetError::Forbidden(m) if m.contains("policy.allow")));
        // The check gets the whole scope: an action of a capability can be
        // the owner's alone while another action of it is not.
        let snap = |scope: &str| scope == "lamp.snap";
        for (key, value) in [
            ("allow", json!(["lamp.snap"])),
            ("caps", json!({"lamp.snap": "on"})),
        ] {
            let mut new = doc(&s);
            new["policy"][key] = value;
            let e = s
                .set_center_document("home", new, v, snap, unix)
                .unwrap_err();
            assert!(
                matches!(&e, SetError::Forbidden(m) if m.contains("lamp.snap")),
                "{e:?}"
            );
        }
        let mut new = doc(&s);
        new["policy"]["allow"] = json!(["fs.read:/a/*", "exec.run:ls", "lamp.on:lamp.on"]);
        s.set_center_document(
            "home",
            new,
            v,
            |c| c.split('.').next() == Some("camera") || snap(c),
            unix,
        )
        .unwrap();
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["protected"] = json!({"allow": ["~/.ssh"]});
        assert!(matches!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Forbidden(_))
        ));
        let mut new = doc(&s);
        new["policy"]["nope"] = json!(1);
        assert!(matches!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Invalid(_))
        ));
        // The center may pause, not unpause.
        let mut new = doc(&s);
        new["paused"] = json!(true);
        let v = s
            .set_center_document("home", new, v, |_| false, unix)
            .unwrap();
        let mut new = doc(&s);
        new["paused"] = json!(false);
        assert!(matches!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Forbidden(_))
        ));
        assert_eq!(s.version(), v);

        let d2 = tempfile::tempdir().unwrap();
        let mut off = store(d2.path(), SettingsGrant::Off);
        let v = off.version();
        let new = doc(&off);
        assert!(matches!(
            off.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Forbidden(_))
        ));
    }

    /// The owner's extra protected paths hold in User mode too; a center may
    /// add one but never take one away.
    #[test]
    fn a_center_cannot_drop_an_owner_protected_path() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.mode = Mode::User;
            p.protected.extra = vec!["~/secret".into()];
            Ok(())
        })
        .unwrap();
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["protected"]["extra"] = json!([]);
        let e = s.set_center_document("home", new, v, |_| false, unix);
        assert!(
            matches!(&e, Err(SetError::Forbidden(m)) if m.contains("policy.protected.extra")),
            "{e:?}"
        );
        assert_eq!(
            s.config().center("home").unwrap().policy.protected.extra,
            ["~/secret"]
        );
        // Adding one more is fine.
        let mut new = doc(&s);
        new["policy"]["protected"]["extra"] = json!(["~/secret", "~/more"]);
        s.set_center_document("home", new, v, |_| false, unix)
            .unwrap();
        assert_eq!(
            s.config().center("home").unwrap().policy.protected.extra,
            ["~/secret", "~/more"]
        );
    }

    /// A folder at or inside a protected entry releases it, so adding one is
    /// a release as well: a center may not, the owner may. The paths are this
    /// platform's own, so the check runs on Windows as well.
    #[test]
    fn a_center_cannot_release_a_protected_path_by_adding_a_folder() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.mode = Mode::User;
            p.protected.extra = vec!["~/secret".into()];
            Ok(())
        })
        .unwrap();
        let v = s.version();
        let shown = |rel: &str| to_wire(&at_home(rel)).to_lowercase();
        for (path, entry) in [
            ("secret", "secret"),
            ("secret/inner", "secret"),
            (".ssh", ".ssh"),
            (".local/bin", ".local/bin"),
        ] {
            let mut new = doc(&s);
            new["policy"]["folders"] = json!([{"path": at_home(path), "access": "r"}]);
            let e = s.set_center_document("home", new, v, |_| false, host);
            assert!(
                matches!(&e, Err(SetError::Forbidden(m))
                    if m.contains("policy.folders") && m.to_lowercase().contains(&shown(entry))),
                "{path}: {e:?}"
            );
        }
        assert!(s.config().center("home").unwrap().policy.folders.is_empty());
        // Spellings that would slip past the check and then match nothing
        // are no folder path at all.
        let odd: &[&str] = if cfg!(windows) {
            &[
                "C:\\Users\\U~1\\.ssh",
                "C:\\Users\\u\\.ssh.",
                "C:\\Users\\u\\.ssh ",
                "C:\\Users\\u\\x\\..\\.ssh",
            ]
        } else {
            &["/home/u/x/../.ssh"]
        };
        for path in odd {
            let mut new = doc(&s);
            new["policy"]["folders"] = json!([{"path": path, "access": "r"}]);
            let e = s.set_center_document("home", new, v, |_| false, host);
            assert!(
                matches!(&e, Err(SetError::Invalid(m)) if m.contains("use the full name")),
                "{path}: {e:?}"
            );
        }
        // A folder that holds a protected entry releases nothing.
        let mut new = doc(&s);
        new["policy"]["folders"] = json!([{"path": host_home(), "access": "rw"}]);
        s.set_center_document("home", new, v, |_| false, host)
            .unwrap();
        // The owner may release it.
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.folders.push(crate::config::Folder {
                path: at_home("secret").to_string_lossy().into_owned(),
                access: crate::config::Access::parse("r").unwrap(),
            });
            Ok(())
        })
        .unwrap();
        // Inside what the owner released a center may add a folder, but it
        // may not widen the owner's folder there.
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["folders"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path": at_home("secret/inner"), "access": "r"}));
        let v = s
            .set_center_document("home", new, v, |_| false, host)
            .unwrap();
        let mut new = doc(&s);
        new["policy"]["folders"][1]["access"] = json!("rw");
        let e = s.set_center_document("home", new, v, |_| false, host);
        let named = format!("policy.folders {}", at_home("secret").display());
        assert!(
            matches!(&e, Err(SetError::Forbidden(m)) if m.contains(&named)),
            "{e:?}"
        );
    }

    fn acc(s: &str) -> Access {
        Access::parse(s).unwrap()
    }

    fn folder(path: &str, access: &str) -> crate::config::Folder {
        crate::config::Folder {
            path: path.into(),
            access: acc(access),
        }
    }

    /// Folder mode, with the owner's `folders`.
    fn owner_folders(dir: &Path, folders: &[(&str, &str)]) -> SettingsStore {
        let mut s = store(dir, SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.mode = Mode::Folder;
            p.folders = folders.iter().map(|(f, a)| folder(f, a)).collect();
            Ok(())
        })
        .unwrap();
        s
    }

    /// The decision on writing `file` under the center's policy now.
    fn write_to(s: &SettingsStore, file: &Path) -> crate::decide::Decision {
        let policy = &s.config().center("home").unwrap().policy;
        let prot = host(&policy.protected);
        let home = host_home();
        let env = crate::decide::Env {
            home: &home,
            protected: &prot,
            unconfined: None,
            sudo: false,
            shell: crate::command::Shell::native(),
            reads: crate::decide::Reads::Folders,
        };
        let targets = [crate::decide::Target {
            path: file.into(),
            access: crate::decide::PathAccess::Write,
            holds: true,
        }];
        let call = crate::decide::Call {
            cap: "fs",
            action: "write",
            effect: nerve_proto::Effect::Write,
            targets: &targets,
            command: None,
            cwd: None,
            now_ms: 0,
        };
        crate::decide::decide(policy, &env, &call)
    }

    fn with_folders(s: &SettingsStore, folders: Value) -> Value {
        let mut new = doc(s);
        new["policy"]["folders"] = folders;
        new
    }

    /// `rel` (with `/`) below [`host_home`], as the string a folder is
    /// given by. These tests use this platform's own paths, so the check
    /// under test runs on Windows as well.
    fn home_str(rel: &str) -> String {
        at_home(rel).to_string_lossy().into_owned()
    }

    /// The owner released `~/.ssh` read-only; another spelling of that
    /// folder gives a center no more.
    #[test]
    fn a_center_cannot_widen_a_protected_folder_by_another_spelling() {
        let d = tempfile::tempdir().unwrap();
        let ssh = home_str(".ssh");
        let mut s = owner_folders(d.path(), &[(&ssh, "r")]);
        let keys = at_home(".ssh/authorized_keys");
        assert!(matches!(
            write_to(&s, &keys),
            crate::decide::Decision::Forbidden(_)
        ));
        let v = s.version();
        let home = host_home().to_string_lossy().into_owned();
        let mut spellings = vec![format!("{home}/.ssh/"), format!("{home}//.ssh")];
        if cfg!(windows) {
            // Windows ignores case and takes either separator; it refuses a
            // `.` part as a name that ends in a dot.
            spellings.push("c:/users/u/.SSH".into());
        } else {
            spellings.push(format!("{home}/./.ssh"));
        }
        for spelling in &spellings {
            // Next to the owner's folder ...
            let both = json!([{"path": ssh, "access": "r"},
                {"path": spelling, "access": "rw"}]);
            let e = s.set_center_document("home", with_folders(&s, both), v, |_| false, host);
            assert!(e.is_err(), "{spelling}: {e:?}");
            // ... or in its place.
            let only = json!([{"path": spelling, "access": "rw"}]);
            let e = s.set_center_document("home", with_folders(&s, only), v, |_| false, host);
            assert!(
                matches!(&e, Err(SetError::Forbidden(m)) if m.to_lowercase().contains(&ssh.to_lowercase())),
                "{spelling}: {e:?}"
            );
        }
        assert_eq!(s.version(), v);
        assert!(matches!(
            write_to(&s, &keys),
            crate::decide::Decision::Forbidden(_)
        ));
        // A folder elsewhere is the center's to add, in any spelling; it is
        // kept in one form, and the protected file stays refused.
        let work = home_str("work");
        let elsewhere = json!([{"path": ssh, "access": "r"},
            {"path": format!("{work}/"), "access": "rw"}]);
        let v = s
            .set_center_document("home", with_folders(&s, elsewhere), v, |_| false, host)
            .unwrap();
        let folders = &s.config().center("home").unwrap().policy.folders;
        assert_eq!(folders[1].path, work);
        assert_eq!(
            write_to(&s, &at_home("work/a")),
            crate::decide::Decision::Allow
        );
        assert!(matches!(
            write_to(&s, &keys),
            crate::decide::Decision::Forbidden(_)
        ));
        // The owner may widen it, in their own spelling.
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.folders[0] = folder(&format!("{ssh}/"), "rw");
            Ok(())
        })
        .unwrap();
        assert!(s.version() > v);
        let folders = &s.config().center("home").unwrap().policy.folders;
        assert_eq!(folders[0].path, ssh);
        assert_eq!(write_to(&s, &keys), crate::decide::Decision::Allow);
    }

    /// A folder inside the owner's read-only `~/.ssh` gets no flag the
    /// owner's folder lacks.
    #[test]
    fn a_center_cannot_widen_a_protected_folder_by_an_inner_one() {
        let d = tempfile::tempdir().unwrap();
        let (ssh, inner) = (home_str(".ssh"), home_str(".ssh/inner"));
        let mut s = owner_folders(d.path(), &[(&ssh, "r")]);
        let v = s.version();
        for access in ["rwx", "rw", "w", "x", "rx"] {
            let wider = json!([{"path": ssh, "access": "r"},
                {"path": inner, "access": access}]);
            let e = s.set_center_document("home", with_folders(&s, wider), v, |_| false, host);
            let named = format!("policy.folders {inner}");
            assert!(
                matches!(&e, Err(SetError::Forbidden(m)) if m.contains(&named)),
                "{access}: {e:?}"
            );
        }
        assert_eq!(s.version(), v);
        assert!(matches!(
            write_to(&s, &at_home(".ssh/inner/x")),
            crate::decide::Decision::Forbidden(_)
        ));
        // As narrow as the owner's folder, or narrower, is fine.
        let narrow = json!([{"path": ssh, "access": "r"},
            {"path": format!("{inner}/"), "access": "r"}]);
        s.set_center_document("home", with_folders(&s, narrow), v, |_| false, host)
            .unwrap();
        assert!(matches!(
            write_to(&s, &at_home(".ssh/inner/x")),
            crate::decide::Decision::Forbidden(_)
        ));
    }

    /// The owner's narrower folder inside a protected entry stays: dropping
    /// it would hand that place the wider access of the folder around it.
    #[test]
    fn a_center_cannot_widen_a_protected_place_by_dropping_a_folder() {
        let d = tempfile::tempdir().unwrap();
        let (ssh, keys) = (home_str(".ssh"), home_str(".ssh/keys"));
        let mut s = owner_folders(d.path(), &[(&ssh, "rw"), (&keys, "r")]);
        let v = s.version();
        let dropped = json!([{"path": ssh, "access": "rw"}]);
        let e = s.set_center_document("home", with_folders(&s, dropped), v, |_| false, host);
        let named = format!("policy.folders {keys}");
        assert!(
            matches!(&e, Err(SetError::Forbidden(m)) if m.contains(&named)),
            "{e:?}"
        );
        assert!(matches!(
            write_to(&s, &at_home(".ssh/keys/id")),
            crate::decide::Decision::Forbidden(_)
        ));
        // Dropping the outer one narrows.
        let outer = json!([{"path": keys, "access": "r"}]);
        s.set_center_document("home", with_folders(&s, outer), v, |_| false, host)
            .unwrap();
    }

    /// The same checks on Windows paths, which ignore case and take either
    /// separator. `client_only` goes by the protected list's platform, so
    /// this runs everywhere.
    #[test]
    fn windows_spellings_of_a_protected_folder_widen_nothing() {
        let win = |opts: &ProtectedOptions| {
            Protected::new(
                &crate::protected::Platform::Windows(Default::default()),
                Path::new("C:\\Users\\u"),
                &[],
                opts,
            )
        };
        let policy = |folders: &[(&str, &str)]| CenterDocument {
            paused: false,
            policy: CenterPolicy {
                mode: Mode::Folder,
                folders: folders.iter().map(|(f, a)| folder(f, a)).collect(),
                ..Default::default()
            },
        };
        let old = policy(&[("C:\\Users\\u\\.ssh", "r")]);
        let check = |new: &[(&str, &str)]| client_only(&old, &policy(new), &|_| false, &win);
        for new in [
            &[("C:\\Users\\u\\.ssh", "r"), ("C:\\Users\\u\\.ssh\\", "rw")][..],
            &[("c:/users/u/.ssh", "rw")][..],
            &[("C:\\Users\\u\\.SSH\\\\", "rw")][..],
            &[
                ("C:\\Users\\u\\.ssh", "r"),
                ("c:\\users\\U\\.ssh\\inner", "rwx"),
            ][..],
        ] {
            assert!(check(new).is_err(), "{new:?}");
        }
        assert_eq!(
            check(&[("C:\\Users\\u\\.ssh", "r"), ("C:/Users/u/.ssh/inner", "r")]),
            Ok(())
        );
        assert_eq!(
            check(&[("C:\\Users\\u\\.ssh", "r"), ("C:\\Users\\u\\work", "rwx")]),
            Ok(())
        );
    }

    fn reopen(dir: &Path) -> Result<SettingsStore, String> {
        SettingsStore::open(
            dir.join("node.toml"),
            dir.join("config.key"),
            AuditLog::new(dir.join("audit.jsonl")),
        )
    }

    fn refusals(s: &SettingsStore) -> usize {
        let log = s.audit().read().unwrap();
        log.iter().filter(|v| v["event"] == "refused").count()
    }

    /// Secrets that record each step of a move and what the file said at
    /// that step, and fail their copy when told to.
    struct Moves {
        key: PathBuf,
        file: PathBuf,
        storage: SecretStorage,
        fail: bool,
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Moves {
        fn note(&self, step: &str) {
            let text = std::fs::read_to_string(&self.file).unwrap_or_default();
            self.log
                .lock()
                .unwrap()
                .push(format!("{step} {:?}", stated_storage(&text)));
        }
    }

    impl Secrets for Moves {
        fn storage(&self) -> SecretStorage {
            self.storage
        }
        fn mac_key(&self) -> Result<Option<MacKey>, String> {
            MacKey::load(&self.key)
        }
        fn mac_key_or_new(&self) -> Result<MacKey, String> {
            MacKey::load_or_create(&self.key)
        }
        fn accepted_version(&self) -> Result<Option<u64>, String> {
            read_version(&self.key.with_file_name(VERSION_FILE))
        }
        fn accept_version(&self, version: u64) -> Result<(), String> {
            record_version(&self.key.with_file_name(VERSION_FILE), version)
        }
        fn copy(&mut self, _cfg: &NodeConfig) -> Result<(), String> {
            self.note("copy");
            if self.fail {
                return Err("no keyring".into());
            }
            Ok(())
        }
        fn moved(&mut self, cfg: &NodeConfig) {
            self.note("moved");
            self.storage = cfg.machine.secret_storage;
        }
        fn not_moved(&mut self, _cfg: &NodeConfig) {
            self.note("not_moved");
        }
    }

    /// A config that keeps the secrets elsewhere is saved between their
    /// copy and the removal of the old ones; a failed copy saves nothing.
    #[test]
    fn the_secrets_move_around_the_save_of_a_config_that_names_another_place() {
        let d = tempfile::tempdir().unwrap();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let file = d.path().join("node.toml");
        let open = |fail, storage| {
            SettingsStore::open_with(
                &file,
                Box::new(Moves {
                    key: d.path().join("config.key"),
                    file: file.clone(),
                    storage,
                    fail,
                    log: log.clone(),
                }),
                AuditLog::new(d.path().join("audit.jsonl")),
            )
            .unwrap()
        };
        let to_keyring = |c: &mut NodeConfig| {
            c.machine.secret_storage = SecretStorage::Keyring;
            Ok(())
        };
        let mut s = open(true, SecretStorage::File);
        s.update(|c| {
            c.node.name = Some("a".into());
            Ok(())
        })
        .unwrap();
        // Nothing moves for a change that keeps the place.
        assert!(log.lock().unwrap().is_empty());
        let v = s.version();
        let e = s.update(to_keyring).unwrap_err();
        assert_eq!(e, SetError::Io("no keyring".into()));
        assert_eq!(s.version(), v);
        assert_eq!(*log.lock().unwrap(), ["copy File"]);
        log.lock().unwrap().clear();
        let mut s = open(false, SecretStorage::File);
        s.update(to_keyring).unwrap();
        assert_eq!(*log.lock().unwrap(), ["copy File", "moved Keyring"]);
        assert_eq!(
            stated_storage(&std::fs::read_to_string(&file).unwrap()),
            SecretStorage::Keyring
        );
        // A file that cannot be written leaves the secrets where they were.
        log.lock().unwrap().clear();
        let mut s = open(false, SecretStorage::Keyring);
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        s.update(|c| {
            c.machine.secret_storage = SecretStorage::File;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(*log.lock().unwrap(), ["copy File", "not_moved File"]);
    }

    #[test]
    fn a_file_without_a_mac_is_signed_once() {
        let d = tempfile::tempdir().unwrap();
        let mut old = NodeConfig::default();
        old.limits.max_running = 3;
        old.save(&d.path().join("node.toml")).unwrap();
        // Readable as it is before the node first opens it ...
        let peeked = SettingsStore::peek(&d.path().join("node.toml"), &d.path().join("config.key"));
        assert_eq!(peeked.unwrap(), old);
        // ... and signed when it does.
        let s = reopen(d.path()).unwrap();
        assert_eq!(s.config(), &old);
        let text = std::fs::read_to_string(s.path()).unwrap();
        assert!(text.starts_with(MAC_LINE), "{text}");
        let log = s.audit().read().unwrap();
        assert_eq!(log.last().unwrap()["event"], "signed");
        // Once there is a key, an unsigned file is refused.
        old.save(s.path()).unwrap();
        assert!(reopen(d.path()).err().unwrap().contains("refused"));
        let e = SettingsStore::peek(s.path(), &d.path().join("config.key")).unwrap_err();
        assert!(e.contains("nerve-node config accept"), "{e}");
    }

    #[test]
    fn reload_takes_only_a_newer_signed_file_in_reach() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let mut other = reopen(d.path()).unwrap();
        // Signed by the owner's path elsewhere (the CLI while no socket
        // answers): taken.
        other
            .update(|c| {
                c.limits.max_running = 2;
                Ok(())
            })
            .unwrap();
        assert_eq!(s.reload(), Ok(true));
        assert_eq!(s.config().limits.max_running, 2);
        assert_eq!(s.reload(), Ok(false));
        // An older signed file is refused: it would undo owner changes.
        let older = std::fs::read(s.path()).unwrap();
        s.update(|c| {
            c.limits.max_running = 5;
            Ok(())
        })
        .unwrap();
        std::fs::write(s.path(), older).unwrap();
        assert!(s.reload().unwrap_err().contains("older"));
        assert_eq!(s.config().limits.max_running, 5);
        // A missing file changes nothing either.
        std::fs::remove_file(s.path()).unwrap();
        assert!(s.reload().is_err());
        assert_eq!(s.config().limits.max_running, 5);
        assert_eq!(refusals(&s), 2);
    }

    /// `s` changed once more, so that its version goes up by one.
    fn bump(s: &mut SettingsStore) -> u64 {
        let n = s.config().limits.max_running;
        s.update(|c| {
            c.limits.max_running = n + 1;
            Ok(())
        })
        .unwrap()
    }

    fn recorded(dir: &Path) -> Option<u64> {
        read_version(&dir.join(VERSION_FILE)).unwrap()
    }

    /// An earlier signed `node.toml` put back in the config folder passes the
    /// MAC, so only the version the node recorded in the state folder tells
    /// it from the file it saved last: a start refuses it, audits that, and
    /// the owner can still take it with `config accept`.
    #[test]
    fn an_earlier_signed_file_put_back_is_refused_at_open() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let earlier = std::fs::read(s.path()).unwrap();
        let earlier_cfg = s.config().clone();
        let last = bump(&mut s);
        assert!(last > earlier_cfg.version);
        assert_eq!(recorded(d.path()), Some(last));
        drop(s);

        std::fs::write(d.path().join("node.toml"), &earlier).unwrap();
        let e = reopen(d.path()).err().expect("the earlier file is refused");
        assert!(
            e.contains("older than the last this node accepted") && e.contains("config accept"),
            "{e}"
        );
        // The CLI's read-only view refuses it the same way.
        let e = SettingsStore::peek(&d.path().join("node.toml"), &d.path().join("config.key"))
            .unwrap_err();
        assert!(e.contains("older"), "{e}");
        let log = AuditLog::new(d.path().join("audit.jsonl")).read().unwrap();
        let refused: Vec<_> = log.iter().filter(|v| v["event"] == "refused").collect();
        assert_eq!(refused.len(), 1, "{log:?}");
        assert!(refused[0]["reason"].as_str().unwrap().contains("older"));
        // Nothing was changed by the refusal.
        assert_eq!(std::fs::read(d.path().join("node.toml")).unwrap(), earlier);
        assert_eq!(recorded(d.path()), Some(last));

        // The owner looks at it and takes it: its content is in force, under
        // a version above every one before, so the next-older file is
        // refused in turn.
        let (taken, v) = SettingsStore::open_accepting(
            d.path().join("node.toml"),
            d.path().join("config.key"),
            AuditLog::new(d.path().join("audit.jsonl")),
        )
        .unwrap();
        assert!(v > last, "{v} {last}");
        assert_eq!(taken.config().limits, earlier_cfg.limits);
        assert_eq!(recorded(d.path()), Some(v));
        assert_eq!(reopen(d.path()).unwrap().version(), v);
    }

    /// The record follows every saved change, and a file the node did not
    /// record (the record was deleted) is taken and recorded.
    #[test]
    fn the_version_is_recorded_with_every_save() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(recorded(d.path()), None);
        let mut s = store(d.path(), SettingsGrant::Off);
        assert_eq!(recorded(d.path()), Some(s.version()));
        let v = bump(&mut s);
        assert_eq!(recorded(d.path()), Some(v));
        // A change that changes nothing saves nothing.
        s.update(|_| Ok(())).unwrap();
        assert_eq!(recorded(d.path()), Some(v));
        // The record holds no secret and is private to the owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.path().join(VERSION_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        drop(s);
        // No record: the file in the config folder is the last one there is.
        std::fs::remove_file(d.path().join(VERSION_FILE)).unwrap();
        assert_eq!(reopen(d.path()).unwrap().version(), v);
        assert_eq!(recorded(d.path()), Some(v));
        // A newer file that another writer saved raises it when the node
        // takes it on a reload.
        let mut s = reopen(d.path()).unwrap();
        let mut cfg = s.config().clone();
        cfg.version += 3;
        std::fs::write(s.path(), sealed(&s.key, &cfg)).unwrap();
        assert_eq!(s.reload(), Ok(true));
        assert_eq!(recorded(d.path()), Some(cfg.version));
    }

    /// With no `node.toml` (the owner removed the config folder to start
    /// over, the state folder stayed) the versions go on from the record:
    /// the next file the node saves is not an older one.
    #[test]
    fn a_node_without_a_file_goes_on_from_the_record() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let last = bump(&mut s);
        drop(s);
        std::fs::remove_file(d.path().join("node.toml")).unwrap();
        let mut s = reopen(d.path()).unwrap();
        assert_eq!(s.version(), last);
        let v = bump(&mut s);
        assert!(v > last);
        drop(s);
        assert_eq!(reopen(d.path()).unwrap().version(), v);

        // A hand-written file with no MAC, taken once when there is no key
        // yet, is saved above the record as well.
        std::fs::remove_file(d.path().join("config.key")).unwrap();
        let mut plain = NodeConfig::default();
        plain.limits.max_running = 3;
        plain.save(&d.path().join("node.toml")).unwrap();
        let s = reopen(d.path()).unwrap();
        assert_eq!(s.config().limits.max_running, 3);
        assert!(s.version() >= v);
        let again = s.version();
        drop(s);
        assert_eq!(reopen(d.path()).unwrap().version(), again);
    }

    /// A reload takes no file below the record either, also when it is not
    /// below the version in force: a CLI that wrote the file itself raised
    /// the record past a node that did not see it yet.
    #[test]
    fn reload_refuses_a_file_below_the_record() {
        let d = tempfile::tempdir().unwrap();
        let mut running = store(d.path(), SettingsGrant::Off);
        let middle = std::fs::read(running.path()).unwrap();
        let mut cli = reopen(d.path()).unwrap();
        bump(&mut cli);
        let newest = bump(&mut cli);
        assert_eq!(recorded(d.path()), Some(newest));
        // `middle` is the version `running` holds, so it is not older than
        // the one in force.
        std::fs::write(running.path(), middle).unwrap();
        let e = running.reload().unwrap_err();
        assert!(e.contains("older than the last this node accepted"), "{e}");
        assert_eq!(refusals(&running), 1);
        // The newest file is taken, and the record stays where it is.
        std::fs::write(running.path(), sealed(&cli.key, cli.config())).unwrap();
        assert_eq!(running.reload(), Ok(true));
        assert_eq!(running.version(), newest);
        assert_eq!(recorded(d.path()), Some(newest));
    }

    /// Another writer saved the file while a node holds its config in memory
    /// (the CLI on Windows, which has no socket to ask the node), and raised
    /// the record by more than one. The node's own next save must go above
    /// the record, or its next start refuses the node's own file as an
    /// earlier one put back, whatever kind of write it was.
    #[test]
    fn a_running_nodes_save_goes_above_the_record_another_writer_raised() {
        type Save = fn(&mut SettingsStore) -> Result<(), String>;
        let saves: [(&str, Save); 4] = [
            ("mark", |s| s.mark(|c| c.centers[0].revoked = true)),
            ("update", |s| {
                s.update(|c| {
                    c.limits.max_running = 9;
                    Ok(())
                })
                .map(drop)
                .map_err(|e| e.to_string())
            }),
            ("sudo of a center", |s| {
                s.set_sudo(Writer::Center("home"), Sudo::On)
                    .map(drop)
                    .map_err(|e| e.to_string())
            }),
            ("settings.set of a center", |s| {
                let v = s.version();
                let mut new = doc(s);
                new["policy"]["caps"] = json!({"exec": "off"});
                s.set_center_document("home", new, v, |_| false, unix)
                    .map(drop)
                    .map_err(|e| e.to_string())
            }),
        ];
        for (what, save) in saves {
            let d = tempfile::tempdir().unwrap();
            let mut running = store(d.path(), SettingsGrant::Write);
            let mut cli = reopen(d.path()).unwrap();
            bump(&mut cli);
            let newest = bump(&mut cli);
            assert!(newest > running.version() + 1, "{what}");
            save(&mut running).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(running.version() > newest, "{what}");
            assert_eq!(recorded(d.path()), Some(running.version()), "{what}");
            let v = running.version();
            drop(running);
            // Its own file starts again, and nothing was refused.
            let again = reopen(d.path()).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(again.version(), v, "{what}");
            assert_eq!(refusals(&again), 0, "{what}");
        }
    }

    /// A record that is no number is not taken for none: it would let
    /// whoever damaged it have an older file accepted. The owner takes the
    /// file, or deletes the record.
    #[test]
    fn a_damaged_record_is_refused_and_taking_the_file_writes_it_again() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let v = bump(&mut s);
        std::fs::write(d.path().join(VERSION_FILE), "x7\n").unwrap();
        let e = reopen(d.path()).err().expect("a damaged record is refused");
        assert!(
            e.contains(VERSION_FILE) && e.contains("version number"),
            "{e}"
        );
        let (_, taken) = SettingsStore::open_accepting(
            d.path().join("node.toml"),
            d.path().join("config.key"),
            AuditLog::new(d.path().join("audit.jsonl")),
        )
        .unwrap();
        assert_eq!(taken, v + 1);
        assert_eq!(recorded(d.path()), Some(taken));
        assert!(reopen(d.path()).is_ok());
    }

    /// The file is saved first: a record that cannot be written afterwards is
    /// audited and does not undo the change.
    #[test]
    fn a_record_that_cannot_be_written_is_audited_and_the_change_stays() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let before = recorded(d.path()).unwrap();
        std::fs::remove_file(d.path().join(VERSION_FILE)).unwrap();
        std::fs::create_dir(d.path().join(VERSION_FILE)).unwrap();
        let v = bump(&mut s);
        assert!(v > before);
        assert_eq!(s.version(), v);
        let log = s.audit().read().unwrap();
        let note = log
            .iter()
            .find(|e| e["event"] == "not_recorded")
            .expect("the failure is audited");
        assert!(
            note["reason"].as_str().unwrap().contains(VERSION_FILE),
            "{note}"
        );
        // The record lags until the next start, which records the version.
        std::fs::remove_dir(d.path().join(VERSION_FILE)).unwrap();
        drop(s);
        assert_eq!(reopen(d.path()).unwrap().version(), v);
        assert_eq!(recorded(d.path()), Some(v));
    }

    #[test]
    fn a_time_limit_is_the_owners_choice_and_has_no_cap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let now = nerve_proto::msg::now_ms();
        let year = 365 * 24 * 3_600_000;
        let set = |mode: Mode, until: Option<u64>| {
            move |c: &mut NodeConfig| {
                let p = &mut c.centers[0].policy;
                p.mode = mode;
                p.until = until;
                Ok(())
            }
        };
        // User mode with no limit, and with one a year ahead, are both fine.
        s.update(set(Mode::User, None)).unwrap();
        s.update(set(Mode::User, Some(now + year))).unwrap();
        s.update(set(Mode::Folder, Some(now + 10 * year))).unwrap();
        // A signed file that reaches far ahead is applied on reload as well.
        let mut far = s.config().clone();
        far.version += 1;
        far.centers[0].policy.mode = Mode::User;
        far.centers[0].policy.until = Some(now + 10 * year);
        std::fs::write(s.path(), sealed(&s.key, &far)).unwrap();
        assert_eq!(s.reload(), Ok(true));
        let p = &s.config().centers[0].policy;
        assert_eq!(p.until, Some(now + 10 * year));
        assert_eq!(p.mode_at(now), Mode::User);
        // A center may set the limit in its own document too.
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["mode"] = json!("user");
        new["policy"]["until"] = json!(now + year);
        s.set_center_document("home", new, v, |_| false, unix)
            .unwrap();
        // Once the limit has passed, the center is back in default deny.
        let past = s.config().centers[0].policy.clone();
        assert_eq!(past.mode_at(now + year), Mode::Allowlist);
        assert_eq!(refusals(&s), 0);
    }

    #[test]
    fn accept_takes_a_refused_file_and_signs_it() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let v = s.version();
        let mut edited = s.config().clone();
        edited.limits.max_running = 7;
        edited.save(s.path()).unwrap();
        assert!(s.reload().is_err());
        assert_eq!(s.accept().unwrap(), v + 1);
        assert_eq!(s.config().limits.max_running, 7);
        assert_eq!(reopen(d.path()).unwrap().config(), s.config());
        let log = s.audit().read().unwrap();
        assert!(log.iter().any(|e| e["event"] == "accepted"));
        assert!(
            log.last().unwrap()["changes"]
                .to_string()
                .contains("max_running")
        );
        // Without a running store: the file is taken as it is.
        let mut edited = s.config().clone();
        edited.limits.max_running = 9;
        edited.save(s.path()).unwrap();
        assert!(reopen(d.path()).is_err());
        let (t, v) = SettingsStore::open_accepting(
            s.path(),
            d.path().join("config.key"),
            AuditLog::new(d.path().join("audit.jsonl")),
        )
        .unwrap();
        assert_eq!(t.config().limits.max_running, 9);
        assert_eq!(reopen(d.path()).unwrap().version(), v);
        // What does not validate is not taken.
        std::fs::write(s.path(), "[limits]\nmax_running = 0\n").unwrap();
        assert!(matches!(s.accept(), Err(SetError::Invalid(_))));
    }

    /// A folder that is a link into a protected entry, or passes through
    /// one, is judged where it leads, since Landlock follows the link: a
    /// center may add it only where the owner's folders release that place
    /// with its flags. The protected entry is the `.ssh` of a home in a temp
    /// dir.
    #[cfg(unix)]
    #[test]
    fn a_center_cannot_reach_a_protected_path_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        let ssh = home.join(".ssh");
        let work = home.join("work");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(work.join("plain")).unwrap();
        std::os::unix::fs::symlink(&ssh, work.join("link")).unwrap();
        let at = |p: &Path| p.display().to_string();
        let prot =
            |o: &ProtectedOptions| Protected::new(&crate::protected::Platform::Unix, &home, &[], o);
        let mut s = owner_folders(d.path(), &[]);
        let refused = |s: &mut SettingsStore, path: &Path, access: &str| {
            let new = with_folders(s, json!([{"path": at(path), "access": access}]));
            let e = s.set_center_document("home", new, s.version(), |_| false, prot);
            matches!(&e, Err(SetError::Forbidden(m))
                if m.contains("policy.folders") && m.contains(&at(&ssh)))
        };
        assert!(refused(&mut s, &work.join("link"), "rw"));
        assert!(refused(&mut s, &work.join("link"), "r"));
        assert!(refused(&mut s, &work.join("link/not-yet"), "x"));
        assert!(!refused(&mut s, &work.join("plain"), "rwx"));
        // The owner released `.ssh` for reading: a link there may read, and
        // no more.
        s.update(|c| {
            c.center_mut("home").unwrap().policy.folders = vec![folder(&at(&ssh), "r")];
            Ok(())
        })
        .unwrap();
        let owner = json!({"path": at(&ssh), "access": "r"});
        for (access, ok) in [("r", true), ("rw", false), ("rx", false)] {
            let link = json!({"path": at(&work.join("link")), "access": access});
            let new = with_folders(&s, json!([owner.clone(), link]));
            let e = s.set_center_document("home", new, s.version(), |_| false, prot);
            assert_eq!(e.is_ok(), ok, "{access}: {e:?}");
        }
    }

    #[test]
    fn local_writes_check_version_and_validate() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let v = s.version();
        let mut c = s.config().clone();
        c.limits.max_running = 0;
        assert!(matches!(s.set_local(c, Some(v)), Err(SetError::Invalid(_))));
        let mut c = s.config().clone();
        c.limits.max_running = 2;
        assert_eq!(
            s.set_local(c.clone(), Some(v + 7)),
            Err(SetError::Conflict { current: v })
        );
        assert_eq!(s.set_local(c, Some(v)).unwrap(), v + 1);
        let log = s.audit().read().unwrap();
        assert_eq!(log.last().unwrap()["by"], "local");
        // An unchanged config is no new version.
        let same = s.config().clone();
        assert_eq!(s.set_local(same, None).unwrap(), v + 1);
    }
}
