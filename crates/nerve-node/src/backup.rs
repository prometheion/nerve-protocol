//! Backup and restore of a node (docs/dev/backup.md, docs/user/backup.md).
//!
//! A backup holds `node.toml` as the node reads it, the node's keys (one per
//! center, the relay's TLS key, the password of an `https://` proxy) and the
//! proxy's header values. It holds no more: the key of the config's MAC is
//! made again by the node that restores (a MAC key is not worth carrying
//! around: it only checks that the file was written by this node), the sudo
//! password is never at rest, and the audit log, the log and the control
//! socket belong to the machine.
//!
//! What sits in the system keyring leaves it only with the owner's consent
//! (`--include-keyring`). A restore never touches a node that runs, and
//! refuses a backup of another node unless the owner says so.
//!
//! No message here carries the text of a key, a password or a passphrase;
//! they name the center, the file or the keyring entry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use nerve_policy::audit::AuditLog;
use nerve_policy::config::{SecretStorage, Sudo, valid_center_name};
use nerve_policy::settings::{Secrets, sealed};
use nerve_policy::{NodeConfig, SettingsStore};
use nerve_transport::backup::{self, Contents, Kind, Passphrase};
use nerve_transport::keys::{MacKey, NodeKey};

use crate::paths::NodePaths;
use crate::secrets::{self, Entry, Key, KeysLock, NodeSecrets};

/// The logical names of the texts in a node backup. A file carries no path:
/// where each goes is decided here.
const CONFIG: &str = "node.toml";
const KEY_PREFIX: &str = "key/";
const RELAY_TLS: &str = "relay-tls";
const PROXY_LOGIN: &str = "proxy-login";
const PROXY_HEADERS: &str = "proxy-headers";

/// Whether `key` is the node key `e` pairs with: the one its node id comes
/// from, or after a rotation the one the config names.
fn pairs(e: &nerve_policy::CenterEntry, key: &NodeKey) -> bool {
    match &e.public_key {
        Some(k) => *k == key.public_hex(),
        None => key.node_id() == e.node_id,
    }
}

/// What the owner chose for a backup.
#[derive(Debug, Clone, Copy)]
pub struct BackupOpts {
    /// Take the keys that sit in the system keyring into the file.
    pub include_keyring: bool,
    /// Replace the file when it exists.
    pub overwrite: bool,
    /// PBKDF2 rounds ([`backup::ITERATIONS`]; a test uses fewer).
    pub rounds: u32,
}

/// What a backup took and what it left out.
#[derive(Debug, Default)]
pub struct BackupReport {
    /// The centers the config names.
    pub centers: Vec<String>,
    /// The keys in the file, as a message names them.
    pub saved: Vec<String>,
    /// What was not taken, and why.
    pub left_out: Vec<LeftOut>,
}

/// A key a backup did not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftOut {
    /// The key, as a message names it.
    pub what: String,
    pub why: Why,
}

/// Why a backup did not take a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// It does not fit the config.
    DoesNotFit,
    /// It is in the system keyring, and the backup was not told to take it.
    Keyring,
    /// This node has none.
    Missing,
}

impl Why {
    /// Its name in `backup --json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Why::DoesNotFit => "does-not-fit",
            Why::Keyring => "keyring",
            Why::Missing => "missing",
        }
    }
}

impl std::fmt::Display for LeftOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = &self.what;
        match self.why {
            Why::DoesNotFit => write!(f, "{what} (it does not fit the config, so it was left out)"),
            Why::Keyring => write!(
                f,
                "{what} (it is in the system keyring; --include-keyring takes it out)"
            ),
            Why::Missing => write!(f, "{what} (this node has none)"),
        }
    }
}

/// Writes the backup of the node `cfg` describes at `paths` to `file`.
pub fn backup(
    paths: &NodePaths,
    cfg: &NodeConfig,
    file: &Path,
    pass: &Passphrase,
    opts: &BackupOpts,
) -> Result<BackupReport, String> {
    pass.check_new()?;
    let (contents, report) = collect(paths, cfg, opts.include_keyring)?;
    let bytes = backup::seal_with(&contents, pass, opts.rounds)?;
    crate::caller_file::write(file, &bytes, opts.overwrite)?;
    Ok(report)
}

/// What a key is read as: its text, still in the keyring, or not there.
enum Fetch {
    Text(String),
    /// It sits in the keyring and the owner did not consent to take it out.
    Keyring,
    Missing,
}

fn fetch(
    paths: &NodePaths,
    storage: SecretStorage,
    consent: bool,
    key: Key,
) -> Result<Fetch, String> {
    if storage == SecretStorage::Keyring && !consent {
        return Ok(Fetch::Keyring);
    }
    Ok(match secrets::read_secret(paths, storage, key)? {
        Some(t) => Fetch::Text(t),
        None => Fetch::Missing,
    })
}

fn collect(
    paths: &NodePaths,
    cfg: &NodeConfig,
    consent: bool,
) -> Result<(Contents, BackupReport), String> {
    let storage = cfg.machine.secret_storage;
    let mut files = BTreeMap::new();
    let mut report = BackupReport::default();
    files.insert(CONFIG.to_string(), cfg.to_toml());

    // One key: into the file when it is there and fits the config, else a
    // line in the report that says why it is not.
    let mut take = |name: String,
                    what: String,
                    got: Fetch,
                    fits: &dyn Fn(&str) -> bool,
                    report: &mut BackupReport| {
        match got {
            Fetch::Text(t) if fits(&t) => {
                files.insert(name, t);
                report.saved.push(what);
            }
            Fetch::Text(_) => report.left_out.push(LeftOut {
                what,
                why: Why::DoesNotFit,
            }),
            Fetch::Keyring => report.left_out.push(LeftOut {
                what,
                why: Why::Keyring,
            }),
            Fetch::Missing => report.left_out.push(LeftOut {
                what,
                why: Why::Missing,
            }),
        }
    };

    for e in &cfg.centers {
        report.centers.push(e.name.clone());
        let e = e.clone();
        take(
            format!("{KEY_PREFIX}{}", e.name),
            format!("the node key for {}", e.name),
            fetch(paths, storage, consent, Key::Center(&e.name))?,
            &move |t: &str| NodeKey::from_text(t).is_ok_and(|k| pairs(&e, &k)),
            &mut report,
        );
    }
    if let Some(pin) = &cfg.relay.pin {
        let pin = pin.clone();
        take(
            RELAY_TLS.into(),
            "the relay's TLS key".into(),
            fetch(paths, storage, consent, Key::RelayTls)?,
            &move |t: &str| {
                nerve_transport::tls::ServerIdentity::from_pem(t).is_ok_and(|i| i.pin() == pin)
            },
            &mut report,
        );
    }
    if cfg.connection.login.is_some() {
        take(
            PROXY_LOGIN.into(),
            "the proxy's password".into(),
            fetch(paths, storage, consent, Key::ProxyLogin)?,
            &|t: &str| !t.is_empty(),
            &mut report,
        );
    }
    // The header values are in the keyring whatever `secret_storage` says,
    // except on the installed node on Windows, which takes none.
    if !cfg.connection.headers.is_empty() && !secrets::windows_service(paths) {
        let entry = Entry::proxy(paths);
        let got = if consent {
            match secrets::store::get(entry.account()) {
                Ok(Some(t)) => Fetch::Text(t),
                Ok(None) => Fetch::Missing,
                Err(e) => {
                    return Err(format!(
                        "cannot read the proxy's header values from the system keyring (entry {entry}): {e}"
                    ));
                }
            }
        } else {
            Fetch::Keyring
        };
        let names = cfg.connection.headers.clone();
        take(
            PROXY_HEADERS.into(),
            "the proxy's header values".into(),
            got,
            &move |t: &str| header_map(t).is_some_and(|m| names.iter().all(|n| m.contains_key(n))),
            &mut report,
        );
    }

    Ok((
        Contents {
            kind: Kind::Node,
            created_ms: crate::now_ms(),
            program: format!("nerve-node {}", env!("CARGO_PKG_VERSION")),
            files,
        },
        report,
    ))
}

/// The proxy's header values as the keyring entry holds them.
fn header_map(text: &str) -> Option<BTreeMap<String, String>> {
    serde_json::from_str(text).ok()
}

/// A node backup that was opened and checked, ready to be restored.
pub struct Parsed {
    cfg: NodeConfig,
    /// The node key per center, by the center's name.
    keys: BTreeMap<String, String>,
    relay_tls: Option<String>,
    proxy_login: Option<String>,
    proxy_headers: Option<BTreeMap<String, String>>,
    pub created_ms: u64,
    pub program: String,
}

impl Parsed {
    /// The same backup without its proxy: the config names none, and the
    /// password and header values in it are dropped.
    fn without_proxy(&self) -> Parsed {
        let mut cfg = self.cfg.clone();
        cfg.connection = Default::default();
        Parsed {
            cfg,
            keys: self.keys.clone(),
            relay_tls: self.relay_tls.clone(),
            proxy_login: None,
            proxy_headers: None,
            created_ms: self.created_ms,
            program: self.program.clone(),
        }
    }

    /// The centers the backup's config names.
    pub fn centers(&self) -> Vec<&str> {
        self.cfg.centers.iter().map(|c| c.name.as_str()).collect()
    }
}

/// Checks what [`backup::open`] returned: that it is a node backup, that its
/// config is one this node would take, and that every key in it belongs to
/// the config (a key of another pairing, or a text that is no key, would be
/// a backup mixed up or damaged).
pub fn parse(contents: Contents) -> Result<Parsed, String> {
    if contents.kind != Kind::Node {
        return Err(format!(
            "this is the backup of a {}, not of a node",
            contents.kind.word()
        ));
    }
    let mut files = contents.files;
    let text = files
        .remove(CONFIG)
        .ok_or("the backup holds no node.toml")?;
    let cfg = NodeConfig::parse(&text).map_err(|e| format!("the backup's node.toml: {e}"))?;
    let mut keys = BTreeMap::new();
    let mut relay_tls = None;
    let mut proxy_login = None;
    let mut proxy_headers = None;
    for (name, text) in files {
        if let Some(center) = name.strip_prefix(KEY_PREFIX) {
            let entry = cfg
                .center(center)
                .filter(|_| valid_center_name(center))
                .ok_or_else(|| {
                    format!("the backup holds a key for {center:?}, which its config does not pair")
                })?;
            let key = NodeKey::from_text(&text)
                .map_err(|_| format!("the node key for {center} in the backup is not a key"))?;
            if !pairs(entry, &key) {
                return Err(format!(
                    "the node key for {center} in the backup is not the one its config pairs with (another node id)"
                ));
            }
            keys.insert(center.to_string(), text);
            continue;
        }
        match name.as_str() {
            RELAY_TLS => {
                let pin = cfg
                    .relay
                    .pin
                    .as_deref()
                    .ok_or("the backup holds a relay TLS key, but its config has no relay")?;
                let id = nerve_transport::tls::ServerIdentity::from_pem(&text)
                    .map_err(|_| "the relay's TLS key in the backup is not a key".to_string())?;
                if id.pin() != pin {
                    return Err(
                        "the relay's TLS key in the backup is not the one its config pins".into(),
                    );
                }
                relay_tls = Some(text);
            }
            PROXY_LOGIN => {
                if cfg.connection.login.is_none() {
                    return Err(
                        "the backup holds a proxy password, but its config has no proxy user"
                            .into(),
                    );
                }
                proxy_login = Some(text);
            }
            PROXY_HEADERS => {
                let map = header_map(&text)
                    .ok_or("the proxy's header values in the backup are not what a node writes")?;
                if let Some(n) = cfg
                    .connection
                    .headers
                    .iter()
                    .find(|n| !map.contains_key(*n))
                {
                    return Err(format!(
                        "the backup holds no value for the proxy header {n}"
                    ));
                }
                proxy_headers = Some(map);
            }
            other => {
                return Err(format!(
                    "the backup holds {other:?}, which this program does not know; it was made by a newer one?"
                ));
            }
        }
    }
    Ok(Parsed {
        cfg,
        keys,
        relay_tls,
        proxy_login,
        proxy_headers,
        created_ms: contents.created_ms,
        program: contents.program,
    })
}

/// Opens a backup file's bytes with the passphrase and checks them.
pub fn open(bytes: &[u8], pass: &Passphrase) -> Result<Parsed, String> {
    parse(backup::open(bytes, pass)?)
}

/// What the owner chose for a restore.
#[derive(Debug, Clone, Copy, Default)]
pub struct RestoreOpts {
    /// Replace a node here that is not the one the backup is of.
    pub replace: bool,
    /// Keep the keys here instead of where the backup's config says.
    pub secret_storage: Option<SecretStorage>,
    /// Leave the proxy out of the restored config, with its password and
    /// header values: nothing of it is kept or needed, so nothing can be sent
    /// to the wrong proxy, and the owner sets it again on this machine.
    pub without_proxy: bool,
}

/// What a restore did, for the owner.
#[derive(Debug, Default)]
pub struct RestoreReport {
    pub centers: Vec<String>,
    /// Centers whose key is not in the backup and not here: they cannot dial
    /// until the owner pairs them again.
    pub no_key: Vec<String>,
    /// Centers whose key was not in the backup, and the one already here fits.
    pub kept: Vec<String>,
    /// Things the owner should know, one line each.
    pub notes: Vec<String>,
    /// The notes that ask the owner to set something again, by their
    /// index in `notes`: what (`proxy`, `sudo`, `sudo-file`, `pin`,
    /// `relay`) and for which center. A program words these itself, with
    /// its own way to do it (`restore --json`).
    pub fixes: Vec<(usize, &'static str, Option<String>)>,
}

impl RestoreReport {
    /// The last note asks for `what` to be set again.
    fn fix(&mut self, what: &'static str, center: Option<&str>) {
        if let Some(i) = self.notes.len().checked_sub(1) {
            self.fixes.push((i, what, center.map(str::to_string)));
        }
    }
}

/// What the folders hold before a restore.
enum Target {
    /// No `node.toml`: a machine the node is moved to.
    Empty,
    Node(Box<NodeConfig>),
    /// A `node.toml` this node cannot read (changed outside the owner's path,
    /// or its keys are out of reach).
    Unreadable(String),
}

fn inspect(paths: &NodePaths) -> Target {
    if !paths.config_file().exists() {
        return Target::Empty;
    }
    match SettingsStore::peek_with(&paths.config_file(), &NodeSecrets::new(paths)) {
        Ok(c) => Target::Node(Box::new(c)),
        Err(e) => Target::Unreadable(e),
    }
}

/// The first setting of [`crate::owner::ROOT_ONLY`] that restoring `b`
/// would change at `paths`; a config here that cannot be read counts as
/// none set.
pub fn root_only_change(paths: &NodePaths, b: &Parsed) -> Option<&'static str> {
    let here = match inspect(paths) {
        Target::Node(c) => *c,
        Target::Empty | Target::Unreadable(_) => NodeConfig::default(),
    };
    crate::owner::root_only_change(&here, &b.cfg)
}

/// The pairings of a config: which node it is, to the centers.
fn pairings(cfg: &NodeConfig) -> BTreeSet<(&str, &str)> {
    cfg.centers
        .iter()
        .map(|e| (e.center_id.as_str(), e.node_id.as_str()))
        .collect()
}

/// A node here with pairings must share one with the backup to be the node
/// it is of. A node without any is nothing a restore could mix up.
fn same_node(here: &NodeConfig, backup: &NodeConfig) -> bool {
    let here = pairings(here);
    here.is_empty() || !here.is_disjoint(&pairings(backup))
}

fn names(cfg: &NodeConfig) -> String {
    if cfg.centers.is_empty() {
        return "no center".into();
    }
    cfg.centers
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// How one key written or deleted by a restore is put back when a later one
/// fails: the key, the place it was in, and what it held there.
enum Undo<'a> {
    Key(Key<'a>, SecretStorage, Option<String>),
    Headers(Option<String>),
}

/// Puts the backup's config and keys in place of the node at `paths`.
///
/// Takes [`KeysLock`] for its whole run: a node that runs holds it, and a
/// restore never goes under a running node. Everything that can be checked
/// is checked before the first byte is written; the keys go first, then the
/// config, and a key that cannot be written puts the ones before it back.
pub fn restore(paths: &NodePaths, b: &Parsed, opts: &RestoreOpts) -> Result<RestoreReport, String> {
    let _lock = KeysLock::try_take_soon(paths)?.ok_or_else(|| {
        format!(
            "a nerve-node runs on these folders (it holds {}), or a command of nerve-node is moving its keys. A restore never goes under a running node: stop it ({}), then restore",
            paths.keys_lock().display(),
            // Windows has no node run by hand: only the service, which the app stops.
            if cfg!(windows) {
                "Stop on the app's Overview"
            } else {
                "`nerve-node` is a service: stop the service; otherwise end `nerve-node run`"
            }
        )
    })?;

    let stripped;
    let had_proxy = b.cfg.connection.proxy.is_some();
    let b = if opts.without_proxy {
        stripped = b.without_proxy();
        &stripped
    } else {
        b
    };

    let target = inspect(paths);
    match &target {
        Target::Node(here) if !opts.replace && !same_node(here, &b.cfg) => {
            return Err(format!(
                "the node here is paired with {} and the backup is of a node paired with {}: they are not the same node, and a restore would replace the one here. If you mean that, add --replace",
                names(here),
                names(&b.cfg)
            ));
        }
        Target::Unreadable(why) if !opts.replace => {
            return Err(format!(
                "the config here cannot be read ({why}). A restore replaces it; add --replace to do that"
            ));
        }
        _ => {}
    }

    let mut cfg = b.cfg.clone();
    let to = opts.secret_storage.unwrap_or(cfg.machine.secret_storage);
    cfg.machine.secret_storage = to;
    if to == SecretStorage::Keyring
        && let Some(n) = secrets::no_keyring(paths)
    {
        return Err(format!(
            "this node cannot keep its keys in the system keyring: {}. Restore with --secret-storage file",
            n.why()
        ));
    }
    if secrets::windows_service(paths) && !cfg.connection.headers.is_empty() {
        return Err(format!(
            "the backup's config names header values for the proxy, but {}. Restore with --without-proxy, or remove the proxy from the backup's node first, or restore on a node that is not the installed one on Windows",
            secrets::PROXY_WINDOWS_SERVICE
        ));
    }
    let mut report = RestoreReport {
        centers: cfg.centers.iter().map(|c| c.name.clone()).collect(),
        ..RestoreReport::default()
    };
    if opts.without_proxy && had_proxy {
        report.notes.push(
            "the proxy is left out of the restored config, with its pin, password and header values: set it again on this machine with `nerve-node proxy set`, which needs the address, the `--pin` of an https:// proxy and its login. For a relay, `nerve-node relay token <name>` on the relay prints the command with a new token and the pin".into(),
        );
        report.fix("proxy", None);
    }
    // The password of the sudo switch is in no backup and never at rest on
    // Linux: a node restored with the switch on would claim it.
    if cfg.machine.sudo == Sudo::On {
        cfg.machine.sudo = Sudo::Off;
        report.notes.push(
            "the sudo switch is off: its password is not in a backup. `nerve-node sudo on` turns it on".into(),
        );
        report.fix("sudo", None);
    }
    // A pairing whose keys were rotated after the backup was made: the config
    // here is further along (it counts more rotations) and names the keys
    // the center holds now, the node's and the center's; the backup holds
    // older ones, which the center takes only until their grace ends. Those
    // here stay: the node key when it is still on this machine, the
    // center's pins always. An older copy of the node here (fewer
    // rotations) gives way to the backup.
    if let Target::Node(here) = &target {
        for e in cfg.centers.iter_mut() {
            let Some(h) = here
                .centers
                .iter()
                .find(|h| h.name == e.name && h.center_id == e.center_id && h.node_id == e.node_id)
            else {
                continue;
            };
            if let Some(rotated) = h
                .public_key
                .clone()
                .filter(|k| e.public_key.as_ref() != Some(k))
            {
                let on_this_machine = [to, secrets::other(to)].into_iter().any(|place| {
                    secrets::get(paths, place, Key::Center(&e.name))
                        .ok()
                        .flatten()
                        .and_then(|t| NodeKey::from_text(&t).ok())
                        .is_some_and(|k| k.public_hex() == rotated)
                });
                if h.key_rotations > e.key_rotations && on_this_machine {
                    e.public_key = Some(rotated);
                    e.key_rotations = h.key_rotations;
                    report.notes.push(format!(
                        "the node key for {} was rotated after the backup was made: the restore keeps the rotated key here, which the center holds, not the backup's older one",
                        e.name
                    ));
                } else if h.key_rotations == e.key_rotations {
                    report.notes.push(format!(
                        "the node key for {} here is another one than the backup's after as many rotations: the restore takes the backup's. If the center refuses it, pair {} again",
                        e.name, e.name
                    ));
                }
            }
            if h.pin_rotations > e.pin_rotations && h.pin != e.pin {
                e.pin = h.pin.clone();
                e.old_pin = h.old_pin.clone();
                e.pin_rotations = h.pin_rotations;
                report.notes.push(format!(
                    "center {} rotated its key after the backup was made: the restore keeps the center's pin here, which it was told or which was set here, not the backup's older one",
                    e.name
                ));
            } else if h.pin_rotations == e.pin_rotations && h.pin != e.pin {
                report.notes.push(format!(
                    "the pin of center {} here is another one than the backup's: the restore takes the backup's. If the node cannot link, set the center's pin with `nerve-node config set center.{}.pin <pin>`",
                    e.name, e.name
                ));
                report.fix("pin", Some(&e.name));
            } else if h.pin_rotations == e.pin_rotations
                && h.pin == e.pin
                && let Some(backed_up) = &e.old_pin
            {
                // The same pin. An old pin here that is gone, or whose time
                // is over, ended after the backup was made (the center ended
                // its grace, maybe because that key leaked): it does not come
                // back. One here that still runs and ends a little sooner
                // (a later notice of the same grace) is taken as it is.
                let now = crate::now_ms();
                match &h.old_pin {
                    Some(o) if now < o.until_ms => {
                        if o.until_ms < backed_up.until_ms {
                            e.old_pin = Some(o.clone());
                        }
                    }
                    _ => {
                        e.old_pin = None;
                        report.notes.push(format!(
                            "the grace of center {}'s old key ended after the backup was made: the restore does not bring its old pin back",
                            e.name
                        ));
                    }
                }
            }
        }
    }
    cfg.validate()?;

    let own = NodeSecrets::for_restore(paths, to);
    // Above every version this node had, so the file is the newest and the
    // record, which only goes up, does not refuse it.
    let last = own.accepted_version().ok().flatten().unwrap_or(0);
    let here = match &target {
        Target::Node(c) => c.version,
        _ => 0,
    };
    cfg.version = cfg.version.max(last).max(here) + 1;

    // Out of the keyring a restore writes to, before anything is written.
    secrets::get(paths, to, Key::Config)?;

    let mut undo: Vec<Undo> = Vec::new();
    let old = match &target {
        Target::Node(c) => Some(&**c),
        _ => None,
    };
    let key = match write_keys(paths, to, &cfg, old, b, &mut undo, &mut report) {
        Ok(k) => k,
        Err(e) => {
            roll_back(paths, undo);
            return Err(format!("{e}; nothing was restored"));
        }
    };
    let written =
        nerve_transport::files::write_private(&paths.config_file(), sealed(&key, &cfg).as_bytes());
    if let Err(e) = written {
        roll_back(paths, undo);
        return Err(format!(
            "cannot write {}: {e}; nothing was restored",
            paths.config_file().display()
        ));
    }
    if let Err(e) = own.accept_version(cfg.version) {
        report.notes.push(format!(
            "the version {} of node.toml is not recorded: {e}. The node records it at its next start",
            cfg.version
        ));
    }
    // The sudo switch is off now, and on the installed node on Windows the
    // administrator's password it kept is at rest in the config folder, with
    // DPAPI, only while the switch is on (`sudo off` removes it).
    if cfg!(windows) && crate::winsudo::kept(paths) {
        match crate::winsudo::forget(paths) {
            Ok(()) => report.notes.push(format!(
                "{} is deleted: the sudo switch is off, so the administrator's password it held is not kept",
                crate::winsudo::SUDO_FILE
            )),
            Err(e) => {
                report.notes.push(format!(
                    "the sudo switch is off, but the administrator's password it held could not be deleted ({e}): delete {}, or run `nerve-node sudo on` and `sudo off`",
                    crate::winsudo::SUDO_FILE
                ));
                report.fix("sudo-file", None);
            }
        }
    }
    let _ = AuditLog::new(paths.audit_log()).config(
        "restored",
        &paths.config_file(),
        &format!(
            "the owner restored the config and keys of {} from a backup made by {}",
            names(&cfg),
            b.program
        ),
    );

    if let Target::Node(old) = &target {
        for e in forget_old(paths, old, &cfg, to) {
            report.notes.push(e);
        }
    }
    Ok(report)
}

/// Writes every key of the backup where `to` keeps them, and gives back the
/// key that signs the restored config. A key the backup lacks stays if the
/// one here fits the config, in the place `to` or in the other one, which
/// the restore is about to empty: it is taken over, not left to be deleted.
fn write_keys<'a>(
    paths: &NodePaths,
    to: SecretStorage,
    cfg: &'a NodeConfig,
    old: Option<&NodeConfig>,
    b: &Parsed,
    undo: &mut Vec<Undo<'a>>,
    report: &mut RestoreReport,
) -> Result<MacKey, String> {
    // The key must be in `to` itself. Reading it the way the node does would
    // fall back to the file where a move of the keys never finished, and sign
    // the config with a key that the clean-up of the old place then deletes.
    let mac = match secrets::get(paths, to, Key::Config)? {
        Some(t) => {
            MacKey::from_text(&t).map_err(|e| format!("{} here: {e}", Key::Config.what()))?
        }
        None => {
            let (mac, text) = MacKey::generate();
            undo.push(Undo::Key(Key::Config, to, None));
            secrets::put(paths, to, Key::Config, &text)?;
            mac
        }
    };
    let mut put = |key: Key<'a>, text: &str| -> Result<(), String> {
        let prev = secrets::get(paths, to, key)?;
        // Already as it should be: nothing to write, nothing to put back.
        if prev.as_deref() == Some(text) {
            return Ok(());
        }
        undo.push(Undo::Key(key, to, prev));
        secrets::put(paths, to, key, text)
    };
    // What is here already for `key`: in `to`, else in the other place. A
    // keyring that does not answer is no key.
    let here = |key: Key, fits: &dyn Fn(&str) -> bool| -> Option<(SecretStorage, String)> {
        [to, secrets::other(to)].into_iter().find_map(|place| {
            secrets::get(paths, place, key)
                .ok()
                .flatten()
                .filter(|t| fits(t))
                .map(|t| (place, t))
        })
    };
    for e in &cfg.centers {
        let key = Key::Center(&e.name);
        // A backup's key that is not the one the config names now (it was
        // rotated after the backup) gives way to the one here.
        let backed_up = b
            .keys
            .get(&e.name)
            .filter(|t| NodeKey::from_text(t).is_ok_and(|k| pairs(e, &k)));
        match backed_up {
            Some(t) => put(key, t)?,
            None => {
                let fits = |t: &str| NodeKey::from_text(t).is_ok_and(|k| pairs(e, &k));
                match here(key, &fits) {
                    Some((place, text)) => {
                        if place != to {
                            put(key, &text)?;
                        }
                        report.kept.push(e.name.clone());
                    }
                    None => report.no_key.push(e.name.clone()),
                }
            }
        }
    }
    match (&b.relay_tls, &cfg.relay.pin) {
        (Some(t), _) => put(Key::RelayTls, t)?,
        (None, Some(pin)) => {
            let fits = |t: &str| {
                nerve_transport::tls::ServerIdentity::from_pem(t).is_ok_and(|i| i.pin() == *pin)
            };
            match here(Key::RelayTls, &fits) {
                Some((place, text)) if place != to => put(Key::RelayTls, &text)?,
                Some(_) => {}
                None => {
                    report.notes.push(
                        "the relay's TLS key is not in the backup and not here: the relay does not listen until `nerve-node relay set <address>` makes a new key and pin, which the nodes behind it must take".into(),
                    );
                    report.fix("relay", None);
                }
            }
        }
        (None, None) => {}
    }
    // The web UI's TLS key is never in a backup: a browser takes a new
    // certificate after one warning. One here that fits the pin stays.
    let mut ui_key = false;
    if let Some(pin) = &cfg.ui.pin {
        let fits = |t: &str| {
            nerve_transport::tls::ServerIdentity::from_pem(t).is_ok_and(|i| i.pin() == *pin)
        };
        if let Some((place, text)) = here(Key::UiTls, &fits) {
            if place != to {
                put(Key::UiTls, &text)?;
            }
            ui_key = true;
        }
    }
    // A backup carries the UI's settings and its tokens, so the restored
    // node may serve it at once; the owner hears of it here.
    if let Some(at) = cfg
        .ui
        .listen
        .as_deref()
        .filter(|_| cfg!(target_os = "linux"))
    {
        report.notes.push(ui_note(at, cfg.ui.tokens.len(), ui_key));
    }
    match (&b.proxy_login, &cfg.connection.login) {
        (Some(t), _) => put(Key::ProxyLogin, t)?,
        (None, Some(_)) => {
            // Nothing in the password says which proxy and user it is for,
            // so it stays only where the config it belonged to, the one
            // being replaced, names the same proxy, pin and user. Another
            // one would send the credential of one proxy to another.
            let same = |o: &NodeConfig| {
                (&o.connection.proxy, &o.connection.pin, &o.connection.login)
                    == (
                        &cfg.connection.proxy,
                        &cfg.connection.pin,
                        &cfg.connection.login,
                    )
            };
            let carried = old.filter(|o| same(o)).and_then(|o| {
                let place = o.machine.secret_storage;
                secrets::get(paths, place, Key::ProxyLogin)
                    .ok()
                    .flatten()
                    .filter(|t| !t.is_empty())
                    .map(|t| (place, t))
            });
            let key = Key::ProxyLogin;
            let other = secrets::other(to);
            // Whatever is not carried into `to` is deleted, in both places:
            // the node reads the file when the keyring holds none, and a
            // move of the keys copies what it finds in the other place. One
            // that is left would be sent to a proxy it was not made for.
            let mut gone = false;
            match &carried {
                Some((place, text)) => {
                    if *place != to {
                        put(key, text)?;
                    }
                }
                None => {
                    if let Some(prev) = secrets::get(paths, to, key)? {
                        undo.push(Undo::Key(key, to, Some(prev)));
                        secrets::delete(paths, to, key)?;
                        gone = true;
                    }
                }
            }
            // A keyring that does not answer holds no copy to read.
            if let Some(prev) = secrets::get(paths, other, key).ok().flatten() {
                undo.push(Undo::Key(key, other, Some(prev)));
                secrets::delete(paths, other, key)?;
                gone = true;
            }
            if carried.is_none() {
                report.notes.push(if gone {
                    "the proxy's password here is not for the proxy and user that the restored config names, so it was deleted: run `nerve-node proxy set` again".into()
                } else {
                    "the proxy's password is not in the backup and not here: run `nerve-node proxy set` again".into()
                });
                report.fix("proxy", None);
            }
        }
        (None, None) => {}
    }
    if b.proxy_headers.is_none() && !cfg.connection.headers.is_empty() {
        // The values are credentials that nothing in them ties to a proxy,
        // and the node sends them by header name to whichever proxy the
        // config names. They stay only where the replaced config named the
        // same proxy, pin and header names; others are deleted.
        let names = |c: &NodeConfig| {
            let mut v = c.connection.headers.clone();
            v.sort();
            v
        };
        let same = old.is_some_and(|o| {
            o.connection.proxy == cfg.connection.proxy
                && o.connection.pin == cfg.connection.pin
                && names(o) == names(cfg)
        });
        // Whose the values are cannot be told without asking the keyring,
        // and a keyring that does not answer is not an empty one: its entry
        // would be sent to the restored proxy once it answers again. So when
        // the replaced config does not vouch for them, a keyring that cannot
        // be asked stops the restore. Where it does, they are the same
        // proxy's whatever the keyring says, and the note is all there is.
        let account = Entry::proxy(paths);
        let here = if same {
            secrets::store::get(account.account()).ok().flatten()
        } else {
            secrets::store::get(account.account()).map_err(|e| {
                let how = "start or unlock the keyring (on a Linux without a desktop, `nerve-node setup` can install one if you answer `keyring` where it asks where the keys go)";
                format!(
                    "cannot read the proxy's header values in the system keyring (entry {account}) to check whose they are: {e}. Restore with --without-proxy and set the proxy again on this machine; or {how}; or take the proxy's header values off the node you back up (`nerve-node proxy rm` there, then back it up again)"
                )
            })?
        };
        let complete = |t: &str| {
            header_map(t).is_some_and(|m| cfg.connection.headers.iter().all(|n| m.contains_key(n)))
        };
        match here {
            Some(t) if same && complete(&t) => {}
            Some(t) if !same => {
                undo.push(Undo::Headers(Some(t)));
                secrets::remove_proxy_headers(paths)?;
                report.notes.push(
                    "the proxy's header values here are not for the proxy and header names that the restored config names, so they were deleted: run `nerve-node proxy set` again".into(),
                );
                report.fix("proxy", None);
            }
            Some(_) => {
                report.notes.push(
                    "the proxy's header values were left out of the backup (they are in the keyring), and the ones here lack a value the restored config names: run `nerve-node proxy set` again".into(),
                );
                report.fix("proxy", None);
            }
            None => {
                report.notes.push(
                    "the proxy's header values were left out of the backup (they are in the keyring); if this machine's keyring lacks them too, run `nerve-node proxy set` again".into(),
                );
                report.fix("proxy", None);
            }
        }
    }
    if let Some(map) = &b.proxy_headers {
        let account = Entry::proxy(paths);
        let prev = secrets::store::get(account.account())
            .map_err(|e| {
                format!(
                    "cannot read the keyring entry {account}: {e}. The backup holds the header values, and they go into that keyring: give the machine a keyring that answers, or restore with --without-proxy and set the proxy again"
                )
            })?;
        let headers: Vec<(String, String)> =
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        undo.push(Undo::Headers(prev));
        secrets::store_proxy_headers(paths, &headers)?;
    }
    Ok(mac)
}

/// Puts back what the keys held before, last first. A key that cannot be put
/// back is left; the message of the restore already says it failed.
fn roll_back(paths: &NodePaths, undo: Vec<Undo>) {
    for u in undo.into_iter().rev() {
        match u {
            Undo::Key(key, place, Some(text)) => {
                let _ = secrets::put(paths, place, key, &text);
            }
            Undo::Key(key, place, None) => {
                let _ = secrets::delete(paths, place, key);
            }
            Undo::Headers(Some(text)) => {
                let _ = secrets::store::set(Entry::proxy(paths).account(), &text);
            }
            Undo::Headers(None) => {
                let _ = secrets::remove_proxy_headers(paths);
            }
        }
    }
}

/// What a restore says of a config that turns the web UI on at `at`, with
/// `tokens` tokens, and the TLS key it needs beyond loopback here or not.
fn ui_note(at: &str, tokens: usize, key_here: bool) -> String {
    let loopback = at
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback());
    if loopback || key_here {
        let on = format!("the restored config turns the web UI on at {at}");
        if tokens == 0 {
            // Nothing can log in until the owner makes a token.
            return format!(
                "{on}, but the backup has no token for it: `nerve-node ui token add <label>` makes one, `nerve-node ui off` turns it off"
            );
        }
        let tokens = if tokens == 1 {
            "its token".to_string()
        } else {
            format!("its {tokens} tokens")
        };
        format!(
            "{on}, and {tokens} from the backup log in to it: `nerve-node ui token ls` lists them, `nerve-node ui off` turns it off"
        )
    } else {
        format!(
            "the restored config turns the web UI on at {at}, but its TLS key is not in the backup and not here: it does not listen until `nerve-node ui on --listen {at} --new-cert` makes one (or `nerve-node ui off`)"
        )
    }
}

/// Deletes what the replaced config kept and the restored one does not name:
/// the keys of pairings that are gone, and every key in the place the keys
/// left. Says what it could not delete.
fn forget_old(
    paths: &NodePaths,
    old: &NodeConfig,
    new: &NodeConfig,
    to: SecretStorage,
) -> Vec<String> {
    let from = old.machine.secret_storage;
    let keep = secrets::keys(new);
    let mut notes = Vec::new();
    for key in secrets::keys(old) {
        if from == to && keep.contains(&key) {
            continue;
        }
        if let Err(e) = secrets::delete(paths, from, key) {
            notes.push(format!("{} of the replaced node was left: {e}", key.what()));
        }
    }
    if !old.connection.headers.is_empty()
        && new.connection.headers.is_empty()
        && !secrets::windows_service(paths)
        && let Err(e) = secrets::remove_proxy_headers(paths)
    {
        notes.push(format!(
            "the proxy's header values of the replaced node were left: {e}"
        ));
    }
    notes
}

/// Says what a backup did.
pub fn print_backup(r: &BackupReport, file: &Path, out: &mut dyn std::io::Write) {
    let _ = writeln!(out, "backed up to {}", file.display());
    let _ = writeln!(
        out,
        "  node.toml, with {}",
        match r.centers.len() {
            0 => "no center".to_string(),
            1 => format!("the center {}", r.centers[0]),
            _ => format!("the centers {}", r.centers.join(", ")),
        }
    );
    for s in &r.saved {
        let _ = writeln!(out, "  {s}");
    }
    for s in &r.left_out {
        let _ = writeln!(out, "  left out: {s}");
    }
    let _ = writeln!(
        out,
        "The file is encrypted with your passphrase. Keep both; nobody can recover the file without it."
    );
}

/// What a backup did, as data: the file, the centers, the keys it took,
/// and the ones it left out with why.
pub fn backup_data(r: &BackupReport, file: &Path) -> serde_json::Value {
    let left_out: Vec<serde_json::Value> = r
        .left_out
        .iter()
        .map(|l| serde_json::json!({"what": l.what, "why": l.why.as_str()}))
        .collect();
    serde_json::json!({
        "file": file.display().to_string(),
        "centers": r.centers,
        "saved": r.saved,
        "left_out": left_out,
    })
}

/// What a restore did, as data: the centers, the keys kept or missing,
/// and each note with what it asks to be set again (`fix`, `center`).
pub fn restore_data(r: &RestoreReport, b: &Parsed) -> serde_json::Value {
    let notes: Vec<serde_json::Value> = r
        .notes
        .iter()
        .enumerate()
        .map(|(i, text)| {
            let fix = r.fixes.iter().find(|f| f.0 == i);
            serde_json::json!({
                "text": text,
                "fix": fix.map(|f| f.1),
                "center": fix.and_then(|f| f.2.clone()),
            })
        })
        .collect();
    serde_json::json!({
        "centers": r.centers,
        "kept": r.kept,
        "no_key": r.no_key,
        "notes": notes,
        "program": b.program,
    })
}

/// Says what a restore did and what comes next.
pub fn print_restore(r: &RestoreReport, b: &Parsed, out: &mut dyn std::io::Write) {
    let _ = writeln!(
        out,
        "restored the config and keys of {} (backup made by {})",
        if r.centers.is_empty() {
            "a node with no center".to_string()
        } else {
            format!("the centers {}", r.centers.join(", "))
        },
        b.program
    );
    for c in &r.kept {
        let _ = writeln!(
            out,
            "  the node key for {c} was not in the backup; the one already here fits and stays"
        );
    }
    for c in &r.no_key {
        let _ = writeln!(
            out,
            "  no node key for {c}: it was not in the backup. Pair it again: `nerve-node center rm --center {c}`, then `nerve-node center add`"
        );
    }
    for n in &r.notes {
        let _ = writeln!(out, "  {n}");
    }
    // For an owner the node restores while it is stopped and starts again
    // by itself (crate::owner).
    let start = if crate::owner::owner_running().is_some() {
        "The node starts again with it now."
    } else {
        "Start the node."
    };
    let _ = writeln!(
        out,
        "{start} It keeps the pins and the keys it had, so a center that still knows it takes it back; check the folders and the account that commands run as (docs/user/backup.md)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_policy::CenterEntry;

    const PASS: &str = "correct horse battery";

    fn pass() -> Passphrase {
        Passphrase::new(PASS.into())
    }

    fn node() -> (tempfile::TempDir, NodePaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        (d, paths)
    }

    fn open_store(paths: &NodePaths) -> SettingsStore {
        SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets::new(paths)),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap()
    }

    fn entry(name: &str, key: &NodeKey) -> CenterEntry {
        CenterEntry {
            name: name.into(),
            url: "https://center.example:7443".into(),
            pin: Some("A".repeat(43)),
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
        }
    }

    /// After a rotation the key no longer hashes to the node id; the key the
    /// config names belongs to the pairing, and no other.
    #[test]
    fn a_rotated_key_pairs_by_the_key_the_config_names() {
        let (first, rotated, other) = (
            NodeKey::generate().unwrap(),
            NodeKey::generate().unwrap(),
            NodeKey::generate().unwrap(),
        );
        let mut e = entry("lab", &first);
        assert!(pairs(&e, &first));
        assert!(!pairs(&e, &rotated));
        e.public_key = Some(rotated.public_hex());
        assert!(pairs(&e, &rotated));
        assert!(!pairs(&e, &first));
        assert!(!pairs(&e, &other));
    }

    /// A node paired with `centers`, keys kept where `storage` says. Returns
    /// the keys' texts by center.
    fn paired(
        paths: &NodePaths,
        storage: SecretStorage,
        centers: &[&str],
    ) -> BTreeMap<String, String> {
        let mut s = open_store(paths);
        if storage == SecretStorage::Keyring {
            s.update(|c| {
                c.machine.secret_storage = storage;
                Ok(())
            })
            .unwrap();
        }
        let mut texts = BTreeMap::new();
        for name in centers {
            let key = NodeKey::generate().unwrap();
            secrets::store_center_key(paths, storage, name, &key).unwrap();
            s.update(|c| {
                c.centers.push(entry(name, &key));
                Ok(())
            })
            .unwrap();
            texts.insert(name.to_string(), key.to_text().trim().to_string());
        }
        texts
    }

    fn config(paths: &NodePaths) -> NodeConfig {
        SettingsStore::peek_with(&paths.config_file(), &NodeSecrets::new(paths)).unwrap()
    }

    fn opts(include_keyring: bool) -> BackupOpts {
        BackupOpts {
            include_keyring,
            overwrite: false,
            rounds: 4,
        }
    }

    /// Backs `paths` up and opens the file again, as a restore would.
    fn roundtrip(
        paths: &NodePaths,
        include_keyring: bool,
    ) -> (tempfile::TempDir, Parsed, BackupReport) {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("n.bak");
        let r = backup(
            paths,
            &config(paths),
            &file,
            &pass(),
            &opts(include_keyring),
        )
        .unwrap();
        let bytes = backup::read_file(&file).unwrap();
        (d, open(&bytes, &pass()).unwrap(), r)
    }

    fn key_text(paths: &NodePaths, storage: SecretStorage, center: &str) -> String {
        secrets::center_key(paths, storage, center)
            .unwrap()
            .to_text()
            .trim()
            .to_string()
    }

    #[test]
    fn a_node_moves_to_an_empty_machine_with_its_keys_and_pins() {
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::File, &["home", "work"]);
        let (_f, parsed, report) = roundtrip(&from, false);
        assert_eq!(report.centers, ["home", "work"]);
        assert_eq!(report.saved.len(), 2);
        assert!(report.left_out.is_empty());

        let (_b, to) = node();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(r.centers, ["home", "work"]);
        assert!(r.no_key.is_empty() && r.kept.is_empty());
        // The same keys, so the centers know the node by the same ids, and
        // the pins in the config are the ones the node had.
        for (name, text) in &keys {
            assert_eq!(&key_text(&to, SecretStorage::File, name), text);
        }
        let (was, now) = (config(&from), config(&to));
        for name in ["home", "work"] {
            let (w, n) = (was.center(name).unwrap(), now.center(name).unwrap());
            assert_eq!(
                (&w.pin, &w.url, &w.node_id, &w.center_id),
                (&n.pin, &n.url, &n.node_id, &n.center_id)
            );
        }
        // The node reads its own config: signed with a key of its own.
        assert!(to.config_key().exists());
        assert!(now.version > 0);
    }

    #[test]
    fn every_file_a_restore_writes_is_private() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [
                to.config_file(),
                to.key_file("home"),
                to.config_key(),
                to.config_version(),
            ] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{}", p.display());
            }
        }
    }

    #[test]
    fn the_backup_file_holds_no_key_in_the_clear() {
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::File, &["home"]);
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("n.bak");
        backup(&from, &config(&from), &file, &pass(), &opts(false)).unwrap();
        let bytes = std::fs::read(&file).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(&keys["home"]) && !text.contains("center.example"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn keys_in_the_keyring_stay_there_without_consent() {
        let (_a, from) = node();
        paired(&from, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, report) = roundtrip(&from, false);
        assert!(report.saved.is_empty(), "{report:?}");
        assert_eq!(report.left_out.len(), 1);
        assert!(
            report.left_out[0].to_string().contains("--include-keyring"),
            "{report:?}"
        );
        assert!(parsed.keys.is_empty());
        // The config alone goes: the restore says the key is missing.
        let (_b, to) = node();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(r.no_key, ["home"]);
        assert!(!to.key_file("home").exists());
    }

    #[test]
    fn the_keyring_is_not_asked_without_consent() {
        // Only the MAC key that checks node.toml is read: a key per center
        // is not.
        let (_a, from) = node();
        paired(&from, SecretStorage::Keyring, &["home", "work"]);
        let cfg = config(&from);
        let before = secrets::store::calls();
        let d = tempfile::tempdir().unwrap();
        backup(&from, &cfg, &d.path().join("n.bak"), &pass(), &opts(false)).unwrap();
        assert_eq!(
            secrets::store::calls(),
            before,
            "the backup asked the keyring"
        );
    }

    #[test]
    fn with_consent_the_keyring_keys_go_into_the_file_and_come_back() {
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, report) = roundtrip(&from, true);
        assert_eq!(report.saved, ["the node key for home"]);
        assert!(report.left_out.is_empty());

        // Back into a keyring on another machine, as the config says.
        let (_b, to) = node();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert!(r.no_key.is_empty());
        assert_eq!(
            &key_text(&to, SecretStorage::Keyring, "home"),
            &keys["home"]
        );
        assert!(!to.key_file("home").exists(), "no copy in a file");
        assert!(
            !to.config_key().exists(),
            "the MAC key is in the keyring too"
        );
        assert_eq!(config(&to).machine.secret_storage, SecretStorage::Keyring);

        // Or into files, where a machine has no keyring.
        let (_c, files) = node();
        restore(
            &files,
            &parsed,
            &RestoreOpts {
                secret_storage: Some(SecretStorage::File),
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        assert_eq!(
            &key_text(&files, SecretStorage::File, "home"),
            &keys["home"]
        );
        assert_eq!(config(&files).machine.secret_storage, SecretStorage::File);
    }

    #[test]
    fn a_keyring_that_cannot_be_reached_fails_before_anything_is_written() {
        let (_a, from) = node();
        paired(&from, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, true);
        let (_b, to) = node();
        secrets::store::set_unreachable(true);
        let err = restore(&to, &parsed, &RestoreOpts::default())
            .err()
            .unwrap();
        secrets::store::set_unreachable(false);
        assert!(!err.contains(&key_text(&from, SecretStorage::Keyring, "home")));
        assert!(!to.config_file().exists() && !to.key_file("home").exists());
    }

    #[test]
    fn a_node_that_cannot_use_the_keyring_is_not_restored_into_it() {
        let (_a, from) = node();
        paired(&from, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, true);
        let (_b, to) = node();
        secrets::for_tests::pretend_windows_service(&to);
        let err = restore(&to, &parsed, &RestoreOpts::default())
            .err()
            .unwrap();
        assert!(err.contains("--secret-storage file"), "{err}");
        assert!(!to.config_file().exists());
        // With files it works.
        restore(
            &to,
            &parsed,
            &RestoreOpts {
                secret_storage: Some(SecretStorage::File),
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        assert!(to.key_file("home").exists());
    }

    #[test]
    fn a_restore_never_goes_under_a_running_node() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        paired(&to, SecretStorage::File, &["other"]);
        let before = std::fs::read(to.config_file()).unwrap();
        // A running node holds the keys lock for its life.
        let lock = KeysLock::try_take(&to).unwrap().unwrap();
        let err = restore(
            &to,
            &parsed,
            &RestoreOpts {
                replace: true,
                ..RestoreOpts::default()
            },
        )
        .err()
        .unwrap();
        assert!(err.contains("runs on these folders"), "{err}");
        // Windows has no node run by hand to end: its advice is the app's Stop.
        assert_eq!(err.contains("`nerve-node run`"), !cfg!(windows), "{err}");
        assert_eq!(
            err.contains("Stop on the app's Overview"),
            cfg!(windows),
            "{err}"
        );
        assert_eq!(std::fs::read(to.config_file()).unwrap(), before);
        assert!(to.key_file("other").exists() && !to.key_file("home").exists());
        drop(lock);
        restore(
            &to,
            &parsed,
            &RestoreOpts {
                replace: true,
                ..RestoreOpts::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn another_node_is_refused_unless_the_owner_says_so() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);

        // A node paired with other centers.
        let (_b, other) = node();
        let theirs = paired(&other, SecretStorage::File, &["lab"]);
        let before = std::fs::read(other.config_file()).unwrap();
        let err = restore(&other, &parsed, &RestoreOpts::default())
            .err()
            .unwrap();
        assert!(
            err.contains("not the same node") && err.contains("lab") && err.contains("home"),
            "{err}"
        );
        assert!(err.contains("--replace"), "{err}");
        assert_eq!(std::fs::read(other.config_file()).unwrap(), before);
        assert!(!other.key_file("home").exists());

        // With --replace the node here is the backup's, and the keys of the
        // pairing that is gone are deleted with it.
        let r = restore(
            &other,
            &parsed,
            &RestoreOpts {
                replace: true,
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        assert!(r.notes.is_empty(), "{r:?}");
        assert!(other.key_file("home").exists());
        assert!(
            !other.key_file("lab").exists(),
            "the key of lab is gone: {theirs:?}"
        );
        assert!(config(&other).center("lab").is_none());
    }

    #[test]
    fn the_same_node_is_restored_without_a_flag_and_goes_back_in_time() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home", "work"]);
        let (_f, parsed, _) = roundtrip(&n, false);
        // Since the backup: a third pairing, and changes.
        paired(&n, SecretStorage::File, &["later"]);
        let mut s = open_store(&n);
        s.update(|c| {
            c.centers[0].paused = true;
            Ok(())
        })
        .unwrap();
        let newest = s.version();
        drop(s);

        restore(&n, &parsed, &RestoreOpts::default()).unwrap();
        let cfg = config(&n);
        assert!(cfg.center("later").is_none() && !cfg.center("home").unwrap().paused);
        assert!(
            !n.key_file("later").exists(),
            "the key of a pairing the backup lacks goes"
        );
        assert!(n.key_file("home").exists() && n.key_file("work").exists());
        // An older config would be refused as one put back; this one is
        // above everything the node had, so it is the newest.
        assert!(cfg.version > newest, "{} {}", cfg.version, newest);
    }

    #[test]
    fn a_config_here_that_cannot_be_read_needs_the_flag() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        paired(&to, SecretStorage::File, &["home"]);
        // Changed outside the owner's path.
        let mut text = std::fs::read_to_string(to.config_file()).unwrap();
        text.push_str("# edited\n");
        std::fs::write(to.config_file(), text).unwrap();
        let err = restore(&to, &parsed, &RestoreOpts::default())
            .err()
            .unwrap();
        assert!(
            err.contains("cannot be read") && err.contains("--replace"),
            "{err}"
        );
        restore(
            &to,
            &parsed,
            &RestoreOpts {
                replace: true,
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        // It reads again.
        config(&to);
    }

    #[test]
    fn a_node_without_pairings_is_nothing_to_mix_up() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        let mut s = open_store(&to);
        s.update(|c| {
            c.limits.max_running = 3;
            Ok(())
        })
        .unwrap();
        restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(config(&to).limits.max_running, 16);
    }

    #[test]
    fn a_restore_goes_above_the_version_the_node_had_recorded() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        // A machine whose node saved its config many times.
        nerve_policy::settings::record_version(&to.config_version(), 500).unwrap();
        restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        let cfg = config(&to);
        assert_eq!(cfg.version, 501);
        assert_eq!(
            nerve_policy::settings::read_version(&to.config_version()).unwrap(),
            Some(501)
        );
    }

    #[test]
    fn the_sudo_switch_comes_back_off() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let mut s = open_store(&from);
        s.set_sudo(nerve_policy::Writer::Local, Sudo::On).unwrap();
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(config(&to).machine.sudo, Sudo::Off);
        assert!(r.notes.iter().any(|n| n.contains("sudo")), "{r:?}");
    }

    #[test]
    fn the_key_that_is_already_here_stays_when_the_backup_lacks_it() {
        // The keys were in the keyring when the backup was made, without
        // consent; the restore is on the same machine, which still has them.
        let (_a, n) = node();
        let keys = paired(&n, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, _) = roundtrip(&n, false);
        let r = restore(&n, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(r.kept, ["home"]);
        assert!(r.no_key.is_empty());
        assert_eq!(&key_text(&n, SecretStorage::Keyring, "home"), &keys["home"]);
    }

    #[test]
    fn a_key_here_that_fits_no_pairing_does_not_count_as_kept() {
        let (_a, from) = node();
        paired(&from, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        // A key of the same name, but another node's.
        let wrong = NodeKey::generate().unwrap();
        secrets::store_center_key(&to, SecretStorage::Keyring, "home", &wrong).unwrap();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(r.no_key, ["home"]);
        assert!(r.kept.is_empty());
    }

    /// Restores `parsed` over `to` with the keys going to `storage`, and gives
    /// back what the node reads afterwards.
    fn restore_into(
        to: &NodePaths,
        parsed: &Parsed,
        storage: Option<SecretStorage>,
    ) -> RestoreReport {
        let r = restore(
            to,
            parsed,
            &RestoreOpts {
                secret_storage: storage,
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        // Whatever the place of its keys, the node reads and verifies the
        // config it was given, as it does at its start.
        let again = open_store(to);
        assert!(
            again.config().machine.secret_storage
                == storage.unwrap_or(parsed.cfg.machine.secret_storage)
        );
        r
    }

    #[test]
    fn a_config_is_signed_with_a_key_that_is_in_the_place_of_the_keys() {
        // A node whose keys are in files, restored from a backup that keeps
        // them in the keyring: the MAC key goes into the keyring, and the
        // key file of the old place goes without taking the signature's key.
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, true);
        let (_b, to) = node();
        let mut s = open_store(&to);
        s.update(|c| {
            c.limits.max_running = 3;
            Ok(())
        })
        .unwrap();
        drop(s);
        assert!(to.config_key().exists());
        restore_into(&to, &parsed, None);
        assert!(!to.config_key().exists(), "the old key file is gone");
        assert!(
            secrets::get(&to, SecretStorage::Keyring, Key::Config)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            &key_text(&to, SecretStorage::Keyring, "home"),
            &keys["home"]
        );
        assert_eq!(config(&to).limits.max_running, 16);

        // And the other way: a node whose keys are in the keyring, restored
        // from a backup that keeps them in files.
        let (_c, from) = node();
        let keys = paired(&from, SecretStorage::File, &["home"]);
        let (_g, parsed, _) = roundtrip(&from, false);
        let (_d, to) = node();
        let mut s = open_store(&to);
        s.update(|c| {
            c.machine.secret_storage = SecretStorage::Keyring;
            Ok(())
        })
        .unwrap();
        drop(s);
        assert!(
            secrets::get(&to, SecretStorage::Keyring, Key::Config)
                .unwrap()
                .is_some()
        );
        restore_into(&to, &parsed, None);
        assert!(
            secrets::get(&to, SecretStorage::Keyring, Key::Config)
                .unwrap()
                .is_none()
        );
        assert!(to.config_key().exists());
        assert_eq!(&key_text(&to, SecretStorage::File, "home"), &keys["home"]);
    }

    #[test]
    fn a_key_the_backup_lacks_is_taken_over_when_the_keys_change_place() {
        // The keys are in the keyring and the backup, made without consent,
        // has none; the restore on the same machine keeps them in files.
        let (_a, n) = node();
        let keys = paired(&n, SecretStorage::Keyring, &["home"]);
        let (_f, parsed, _) = roundtrip(&n, false);
        assert!(parsed.keys.is_empty());
        let r = restore_into(&n, &parsed, Some(SecretStorage::File));
        assert_eq!(r.kept, ["home"], "{r:?}");
        assert!(r.no_key.is_empty());
        assert_eq!(&key_text(&n, SecretStorage::File, "home"), &keys["home"]);
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::Center("home"))
                .unwrap()
                .is_none(),
            "the old copy goes once the new one is there"
        );

        // The other way: the node moved its keys into files since.
        let (_b, n) = node();
        let keys = paired(&n, SecretStorage::Keyring, &["home"]);
        let (_g, parsed, _) = roundtrip(&n, false);
        let mut s = open_store(&n);
        s.update(|c| {
            c.machine.secret_storage = SecretStorage::File;
            Ok(())
        })
        .unwrap();
        drop(s);
        assert!(n.key_file("home").exists());
        let r = restore_into(&n, &parsed, None);
        assert_eq!(r.kept, ["home"], "{r:?}");
        assert_eq!(&key_text(&n, SecretStorage::Keyring, "home"), &keys["home"]);
        assert!(!n.key_file("home").exists());
    }

    /// Rotates the key for `center` here the way the node settles a
    /// rotation: the config names the new key, which replaces the old one.
    fn rotate_here(paths: &NodePaths, storage: SecretStorage, center: &str) -> NodeKey {
        let k = NodeKey::generate().unwrap();
        let mut s = open_store(paths);
        s.update(|c| {
            let e = c.center_mut(center).unwrap();
            e.public_key = Some(k.public_hex());
            e.key_rotations += 1;
            Ok(())
        })
        .unwrap();
        drop(s);
        secrets::store_center_key(paths, storage, center, &k).unwrap();
        k
    }

    /// A restore over an older copy of the node (fewer rotations) takes the
    /// backup's newer key, not the older rotated one here.
    #[test]
    fn a_restore_over_an_older_copy_takes_the_backups_newer_key() {
        let (_a, n1) = node();
        paired(&n1, SecretStorage::File, &["home"]);
        rotate_here(&n1, SecretStorage::File, "home");
        let (_f1, b1, _) = roundtrip(&n1, false);
        let k2 = rotate_here(&n1, SecretStorage::File, "home");
        let (_f2, b2, _) = roundtrip(&n1, false);

        let (_b, n2) = node();
        restore_into(&n2, &b1, None);
        let r = restore_into(&n2, &b2, None);
        assert!(r.no_key.is_empty(), "{r:?}");
        assert!(
            !r.notes
                .iter()
                .any(|t| t.contains("rotated after the backup")),
            "{r:?}"
        );
        assert_eq!(
            key_text(&n2, SecretStorage::File, "home"),
            k2.to_text().trim()
        );
        let cfg = open_store(&n2).config().clone();
        assert_eq!(cfg.centers[0].public_key, Some(k2.public_hex()));
        assert_eq!(cfg.centers[0].key_rotations, 2);
    }

    /// A restore does not bring back a center's old pin whose grace ended
    /// (the center told the node so) after the backup was made.
    #[test]
    fn a_restore_does_not_bring_back_an_old_pin_whose_grace_ended() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        let (p0, p1) = ("A".repeat(43), "B".repeat(43));
        let in_grace = |c: &mut NodeConfig| {
            let e = c.center_mut("home").unwrap();
            e.pin = Some(p1.clone());
            e.old_pin = Some(nerve_policy::OldPin {
                pin: p0.clone(),
                until_ms: crate::now_ms() + 86_400_000,
            });
            e.pin_rotations = 1;
        };
        let mut s = open_store(&n);
        s.mark(in_grace).unwrap();
        drop(s);
        let (_f, parsed, _) = roundtrip(&n, false);
        let mut s = open_store(&n);
        s.mark(|c| c.center_mut("home").unwrap().old_pin = None)
            .unwrap();
        drop(s);
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|t| t.contains("does not bring its old pin back")),
            "{r:?}"
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].pin.as_deref(), Some(p1.as_str()));
        assert_eq!(cfg.centers[0].old_pin, None);

        // An old pin here that still runs and ends a little sooner (a later
        // notice of the same grace) is no end of the grace: it stays, without
        // that note.
        let (_b, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        let mut s = open_store(&n);
        s.mark(in_grace).unwrap();
        drop(s);
        let (_g, parsed, _) = roundtrip(&n, false);
        let mut s = open_store(&n);
        s.mark(|c| {
            let o = c.center_mut("home").unwrap().old_pin.as_mut().unwrap();
            o.until_ms -= 5;
        })
        .unwrap();
        let here = s.config().centers[0].old_pin.clone();
        drop(s);
        let r = restore_into(&n, &parsed, None);
        assert!(
            !r.notes
                .iter()
                .any(|t| t.contains("does not bring its old pin back")),
            "{r:?}"
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].old_pin, here);
        assert!(
            cfg.centers[0]
                .pins_at(crate::now_ms())
                .contains(&p0.as_str())
        );
    }

    /// The same pin set again with base64 padding is no rotation: its count
    /// stays, and a restore of a backup from the grace still leaves out the
    /// old pin whose grace ended here.
    #[test]
    fn the_same_pin_padded_counts_no_rotation() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        // Canonical base64url pins (the last character carries no stray bits).
        let (p0, p1) = ("A".repeat(43), format!("{}E", "A".repeat(42)));
        let mut s = open_store(&n);
        s.mark(|c| {
            let e = c.center_mut("home").unwrap();
            e.pin = Some(p1.clone());
            e.old_pin = Some(nerve_policy::OldPin {
                pin: p0.clone(),
                until_ms: crate::now_ms() + 86_400_000,
            });
            e.pin_rotations = 1;
        })
        .unwrap();
        drop(s);
        let (_f, parsed, _) = roundtrip(&n, false);
        let mut s = open_store(&n);
        s.mark(|c| c.center_mut("home").unwrap().old_pin = None)
            .unwrap();
        s.update(|c| {
            c.center_mut("home").unwrap().pin = Some(format!("{p1}="));
            Ok(())
        })
        .unwrap();
        let e = s.config().centers[0].clone();
        assert_eq!(e.pin.as_deref(), Some(p1.as_str()));
        assert_eq!(e.pin_rotations, 1, "the same pin padded is no rotation");
        drop(s);
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|t| t.contains("does not bring its old pin back")),
            "{r:?}"
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].old_pin, None);
        assert!(
            !cfg.centers[0]
                .pins_at(crate::now_ms())
                .contains(&p0.as_str())
        );
    }

    /// A center's pin set by hand counts as a rotation the node took: a
    /// restore of a backup from before keeps it.
    #[test]
    fn a_restore_keeps_a_center_pin_set_by_hand() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&n, false);
        let by_hand = "C".repeat(43);
        let mut s = open_store(&n);
        s.update(|c| {
            c.center_mut("home").unwrap().pin = Some(by_hand.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(s.config().centers[0].pin_rotations, 1);
        drop(s);
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes.iter().any(|t| t.contains("keeps the center's pin")),
            "{r:?}"
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].pin.as_deref(), Some(by_hand.as_str()));
    }

    /// A restore of a backup made before a rotation of the center's key
    /// keeps the center's pin the node was told, not the backup's older one.
    #[test]
    fn a_restore_from_before_a_center_rotation_keeps_the_new_pin() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&n, false);
        let before = open_store(&n).config().centers[0].pin.clone();
        let new_pin = "B".repeat(43);
        let mut s = open_store(&n);
        s.update(|c| {
            let e = c.center_mut("home").unwrap();
            e.pin = Some(new_pin.clone());
            e.old_pin = None;
            e.pin_rotations += 1;
            Ok(())
        })
        .unwrap();
        drop(s);
        assert_ne!(before.as_deref(), Some(new_pin.as_str()));
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes.iter().any(|t| t.contains("keeps the center's pin")),
            "{r:?}"
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].pin.as_deref(), Some(new_pin.as_str()));
        assert_eq!(cfg.centers[0].pin_rotations, 1);
    }

    /// A backup made before a rotation of the node's key holds the older
    /// key: the restore keeps the rotated key here, which the center holds,
    /// and the config goes on naming it.
    #[test]
    fn a_restore_of_a_backup_from_before_a_rotation_keeps_the_rotated_key() {
        // The keys in files, the old key in the backup.
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&n, false);
        assert_eq!(parsed.keys.len(), 1);
        let rotated = rotate_here(&n, SecretStorage::File, "home");
        let r = restore_into(&n, &parsed, None);
        assert!(r.no_key.is_empty(), "{r:?}");
        assert!(
            r.notes
                .iter()
                .any(|t| t.contains("rotated after the backup")),
            "{r:?}"
        );
        assert_eq!(
            key_text(&n, SecretStorage::File, "home"),
            rotated.to_text().trim()
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].public_key, Some(rotated.public_hex()));

        // The keys in the keyring, none in the backup, moved into files.
        let (_b, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        let (_g, parsed, _) = roundtrip(&n, false);
        assert!(parsed.keys.is_empty());
        let rotated = rotate_here(&n, SecretStorage::Keyring, "home");
        let r = restore_into(&n, &parsed, Some(SecretStorage::File));
        assert_eq!(r.kept, ["home"], "{r:?}");
        assert!(r.no_key.is_empty(), "{r:?}");
        assert_eq!(
            key_text(&n, SecretStorage::File, "home"),
            rotated.to_text().trim()
        );
        let cfg = open_store(&n).config().clone();
        assert_eq!(cfg.centers[0].public_key, Some(rotated.public_hex()));
    }

    /// A rotated key the backup lacks is taken over as well: it does not
    /// hash to the node id, but it is the key the config names.
    #[test]
    fn a_rotated_key_the_backup_lacks_is_taken_over_too() {
        let (_a, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        let rotated = NodeKey::generate().unwrap();
        secrets::store_center_key(&n, SecretStorage::Keyring, "home", &rotated).unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.centers[0].public_key = Some(rotated.public_hex());
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_f, parsed, _) = roundtrip(&n, false);
        assert!(parsed.keys.is_empty());
        let r = restore_into(&n, &parsed, Some(SecretStorage::File));
        assert_eq!(r.kept, ["home"], "{r:?}");
        assert!(r.no_key.is_empty(), "{r:?}");
        assert_eq!(
            key_text(&n, SecretStorage::File, "home").trim(),
            rotated.to_text().trim()
        );
    }

    #[test]
    fn the_relay_key_and_the_proxy_password_the_backup_lacks_are_taken_over_too() {
        let (_a, n) = node();
        let keys = paired(&n, SecretStorage::Keyring, &["home"]);
        let relay =
            nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()]).unwrap();
        secrets::store_relay_tls(&n, SecretStorage::Keyring, &relay).unwrap();
        secrets::store_proxy_login(&n, SecretStorage::Keyring, "s3cret-token").unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.relay.pin = Some(relay.pin());
            c.relay.listen = Some("127.0.0.1:7490".into());
            c.connection.proxy = Some("https://relay.example:7490".into());
            c.connection.pin = Some(relay.pin());
            c.connection.login = Some("node-a".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_f, parsed, report) = roundtrip(&n, false);
        assert_eq!(report.left_out.len(), 3, "{report:?}");
        let r = restore_into(&n, &parsed, Some(SecretStorage::File));
        assert!(r.notes.is_empty(), "{r:?}");
        assert_eq!(&key_text(&n, SecretStorage::File, "home"), &keys["home"]);
        assert_eq!(
            secrets::proxy_login(&n, SecretStorage::File).unwrap(),
            "s3cret-token"
        );
        assert_eq!(
            secrets::relay_tls(&n, SecretStorage::File)
                .unwrap()
                .unwrap()
                .pin(),
            relay.pin()
        );
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::RelayTls)
                .unwrap()
                .is_none()
        );
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_restore_says_that_the_restored_config_turns_the_web_ui_on() {
        let (_a, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        let ui = nerve_transport::tls::ServerIdentity::generate(&["node.example".into()]).unwrap();
        secrets::store_ui_tls(&n, SecretStorage::Keyring, &ui).unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.ui.listen = Some("0.0.0.0:7470".into());
            c.ui.pin = Some(ui.pin());
            c.ui.tokens.push(nerve_policy::config::UiToken {
                label: "laptop".into(),
                token_sha256: "d".repeat(64),
                made: String::new(),
            });
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_f, parsed, _) = roundtrip(&n, false);
        // Here, with the keys moved to their files: the UI's key is taken
        // along, so the UI listens on, and the owner is told.
        let r = restore_into(&n, &parsed, Some(SecretStorage::File));
        assert_eq!(
            secrets::ui_tls(&n, SecretStorage::File)
                .unwrap()
                .unwrap()
                .pin(),
            ui.pin()
        );
        // On another machine there is no key.
        let (_b, m) = node();
        let elsewhere = restore_into(&m, &parsed, None);
        if cfg!(target_os = "linux") {
            assert_eq!(
                r.notes,
                [
                    "the restored config turns the web UI on at 0.0.0.0:7470, and its token from the backup log in to it: `nerve-node ui token ls` lists them, `nerve-node ui off` turns it off"
                ]
            );
            assert_eq!(elsewhere.notes.len(), 1, "{elsewhere:?}");
            assert!(
                elsewhere.notes[0].contains("`nerve-node ui on --listen 0.0.0.0:7470 --new-cert`"),
                "{elsewhere:?}"
            );
        }
        assert!(ui_note("127.0.0.1:7470", 2, false).contains("its 2 tokens"));
        // A backup whose tokens were all revoked brings none to log in with.
        let none = ui_note("127.0.0.1:7470", 0, false);
        assert!(
            none.contains("no token") && none.contains("ui token add"),
            "{none}"
        );
        assert!(!none.contains("log in to it"), "{none}");
    }

    /// A node that uses relay A as its proxy, with a password for it.
    fn with_proxy(n: &NodePaths, host: &str, user: &str, token: &str, pin: &str) -> SettingsStore {
        secrets::store_proxy_login(n, SecretStorage::Keyring, token).unwrap();
        let mut s = open_store(n);
        let (host, user, pin) = (host.to_string(), user.to_string(), pin.to_string());
        s.update(|c| {
            c.connection.proxy = Some(format!("https://{host}:7490"));
            c.connection.pin = Some(pin.clone());
            c.connection.login = Some(user.clone());
            Ok(())
        })
        .unwrap();
        s
    }

    #[test]
    fn a_proxy_password_stays_only_for_the_proxy_and_user_it_belonged_to() {
        let pin = nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()])
            .unwrap()
            .pin();
        let (_a, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        drop(with_proxy(&n, "relay-a.example", "node-a", "a-token", &pin));
        let (_f, parsed, _) = roundtrip(&n, false);

        // The same proxy and user: the password stays, and nothing is said.
        let r = restore_into(&n, &parsed, None);
        assert!(r.notes.is_empty(), "{r:?}");
        assert_eq!(
            secrets::proxy_login(&n, SecretStorage::Keyring).unwrap(),
            "a-token"
        );

        // Since then the node moved to relay B, with B's user and token. The
        // restore names relay A again; B's token is not A's and goes.
        drop(with_proxy(&n, "relay-b.example", "node-b", "b-token", &pin));
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("proxy's password") && n.contains("proxy set")),
            "{r:?}"
        );
        let cfg = config(&n);
        assert_eq!(cfg.connection.login.as_deref(), Some("node-a"));
        assert!(secrets::proxy_login(&n, SecretStorage::Keyring).is_err());
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );

        // Another user of the same proxy is another credential too.
        drop(with_proxy(
            &n,
            "relay-a.example",
            "node-other",
            "other-token",
            &pin,
        ));
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes.iter().any(|n| n.contains("proxy's password")),
            "{r:?}"
        );
        assert!(secrets::proxy_login(&n, SecretStorage::Keyring).is_err());

        // A password on a machine with no config of its own, for no known
        // proxy, is not taken either.
        let (_b, to) = node();
        secrets::store_proxy_login(&to, SecretStorage::Keyring, "stray").unwrap();
        let r = restore_into(&to, &parsed, None);
        assert!(
            r.notes.iter().any(|n| n.contains("proxy's password")),
            "{r:?}"
        );
        assert!(
            secrets::get(&to, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_proxy_password_in_the_other_place_is_deleted_too() {
        let pin = nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()])
            .unwrap()
            .pin();
        let (_a, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        drop(with_proxy(&n, "relay-a.example", "node-a", "a-token", &pin));
        let (_f, parsed, _) = roundtrip(&n, false);

        // The node moved its keys into files and to relay B, and its
        // node.toml was edited by hand since: the restore wants --replace.
        let mut s = open_store(&n);
        s.update(|c| {
            c.machine.secret_storage = SecretStorage::File;
            Ok(())
        })
        .unwrap();
        secrets::store_proxy_login(&n, SecretStorage::File, "b-token").unwrap();
        s.update(|c| {
            c.connection.proxy = Some("https://relay-b.example:7490".into());
            c.connection.login = Some("node-b".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let mut text = std::fs::read_to_string(n.config_file()).unwrap();
        text.push_str("# edited\n");
        std::fs::write(n.config_file(), text).unwrap();
        let err = restore(&n, &parsed, &RestoreOpts::default()).err().unwrap();
        assert!(err.contains("--replace"), "{err}");
        let r = restore(
            &n,
            &parsed,
            &RestoreOpts {
                replace: true,
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("proxy's password") && n.contains("deleted")),
            "{r:?}"
        );
        // Relay B's token is nowhere the node reads it: not in the file it
        // falls back to, and not in what a start copies into the keyring.
        assert!(!n.proxy_login_file().exists());
        assert!(secrets::proxy_login(&n, SecretStorage::Keyring).is_err());
        secrets::settle(&n, &config(&n));
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );
        assert_eq!(config(&n).connection.login.as_deref(), Some("node-a"));

        // The same on a machine with no config and a password left in a
        // file, where the keys go into the keyring.
        let (_b, to) = node();
        secrets::store_proxy_login(&to, SecretStorage::File, "stray").unwrap();
        let r = restore_into(&to, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("proxy's password") && n.contains("deleted")),
            "{r:?}"
        );
        assert!(!to.proxy_login_file().exists());
        assert!(secrets::proxy_login(&to, SecretStorage::Keyring).is_err());

        // And the other way: the keys go into files, and the keyring holds
        // a password that a move of the keys could take over.
        let (_c, to) = node();
        secrets::store_proxy_login(&to, SecretStorage::Keyring, "stray").unwrap();
        let r = restore_into(&to, &parsed, Some(SecretStorage::File));
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("proxy's password") && n.contains("deleted")),
            "{r:?}"
        );
        assert!(
            secrets::get(&to, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );
        assert!(secrets::proxy_login(&to, SecretStorage::File).is_err());
    }

    #[test]
    fn the_password_that_stays_leaves_no_copy_in_the_other_place() {
        let pin = nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()])
            .unwrap()
            .pin();
        let (_a, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        drop(with_proxy(&n, "relay-a.example", "node-a", "a-token", &pin));
        let (_f, parsed, _) = roundtrip(&n, false);
        // A copy in a file, left from a move that did not finish.
        secrets::store_proxy_login(&n, SecretStorage::File, "old-copy").unwrap();
        let r = restore_into(&n, &parsed, None);
        assert!(r.notes.is_empty(), "{r:?}");
        assert_eq!(
            secrets::proxy_login(&n, SecretStorage::Keyring).unwrap(),
            "a-token"
        );
        assert!(!n.proxy_login_file().exists());
    }

    #[test]
    fn proxy_header_values_stay_only_for_the_proxy_and_header_names_they_belonged_to() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        let set = |proxy: &str, names: &[&str]| {
            let mut s = open_store(&n);
            let (proxy, names) = (
                proxy.to_string(),
                names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            );
            s.update(|c| {
                c.connection.proxy = Some(proxy.clone());
                c.connection.headers = names.clone();
                Ok(())
            })
            .unwrap();
        };
        let values = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            secrets::store_proxy_headers(&n, &pairs).unwrap();
        };
        values(&[("Proxy-Authorization", "Basic A")]);
        set("http://proxy-a.example:3128", &["Proxy-Authorization"]);
        let (_f, parsed, report) = roundtrip(&n, false);
        assert!(
            report
                .left_out
                .iter()
                .any(|l| l.what.contains("header values")),
            "{report:?}"
        );

        // The same proxy and header names: the values stay, and nothing is said.
        let r = restore_into(&n, &parsed, None);
        assert!(r.notes.is_empty(), "{r:?}");
        let got = secrets::proxy_headers(&n, &["Proxy-Authorization".into()]).unwrap();
        assert_eq!(
            got,
            [("Proxy-Authorization".to_string(), "Basic A".to_string())]
        );

        // The node moved to proxy B since; B's credential must not go to A.
        values(&[("Proxy-Authorization", "Basic B")]);
        set("http://proxy-b.example:3128", &["Proxy-Authorization"]);
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("header values") && n.contains("deleted")),
            "{r:?}"
        );
        assert_eq!(
            config(&n).connection.proxy.as_deref(),
            Some("http://proxy-a.example:3128")
        );
        assert!(secrets::proxy_headers(&n, &["Proxy-Authorization".into()]).is_err());
        assert!(
            secrets::store::get(Entry::proxy(&n).account())
                .unwrap()
                .is_none()
        );

        // The same proxy with other header names is other values.
        values(&[("X-Token", "t")]);
        set("http://proxy-a.example:3128", &["X-Token"]);
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("header values") && n.contains("deleted")),
            "{r:?}"
        );
        assert!(
            secrets::store::get(Entry::proxy(&n).account())
                .unwrap()
                .is_none()
        );

        // Values that lack one of the names: kept as they are, and said.
        values(&[("X-Other", "t")]);
        set("http://proxy-a.example:3128", &["Proxy-Authorization"]);
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("header values") && n.contains("lack a value")),
            "{r:?}"
        );
        // They are for the right proxy: kept, not deleted, so what they do
        // hold is still there.
        let kept = secrets::store::get(Entry::proxy(&n).account()).unwrap();
        assert_eq!(header_map(&kept.unwrap()).unwrap()["X-Other"], "t");

        // A machine with no config of its own and a stray entry.
        let (_b, to) = node();
        secrets::store_proxy_headers(&to, &[("Proxy-Authorization".into(), "Basic X".into())])
            .unwrap();
        let r = restore_into(&to, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("header values") && n.contains("deleted")),
            "{r:?}"
        );
        assert!(
            secrets::store::get(Entry::proxy(&to).account())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_keyring_that_does_not_answer_stops_a_restore_that_cannot_say_whose_header_values_are() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        secrets::store_proxy_headers(&n, &[("Proxy-Authorization".into(), "Basic A".into())])
            .unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy-a.example:3128".into());
            c.connection.headers = vec!["Proxy-Authorization".into()];
            Ok(())
        })
        .unwrap();
        let (_f, parsed, _) = roundtrip(&n, false);

        // The same proxy: the values are its own, so the restore goes on and
        // says what it knows.
        secrets::store::set_unreachable(true);
        let r = restore(&n, &parsed, &RestoreOpts::default());
        secrets::store::set_unreachable(false);
        let r = r.unwrap();
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("header values were left out")),
            "{r:?}"
        );

        // The node moved to proxy B since. With the keyring out of reach the
        // restore cannot tell whose the values are, and stops: nothing is
        // written, and B's credential is not left to be sent to A.
        secrets::store_proxy_headers(&n, &[("Proxy-Authorization".into(), "Basic B".into())])
            .unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy-b.example:3128".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let before = std::fs::read(n.config_file()).unwrap();
        secrets::store::set_unreachable(true);
        let err = restore(&n, &parsed, &RestoreOpts::default());
        secrets::store::set_unreachable(false);
        let err = err.err().unwrap();
        assert!(
            err.contains("to check whose they are")
                && err.contains("nerve-node setup")
                && err.contains("--without-proxy"),
            "{err}"
        );
        assert!(err.contains("nothing was restored"), "{err}");
        assert!(!err.contains("Basic"), "{err}");
        assert_eq!(std::fs::read(n.config_file()).unwrap(), before);
        // A backup made with --include-keyring is no way round it: its values
        // are written into the same keyring, which does not answer either.
        let (_g, with, report) = roundtrip(&n, true);
        assert!(
            report.saved.iter().any(|l| l.contains("header values")),
            "{report:?}"
        );
        for storage in [None, Some(SecretStorage::File)] {
            secrets::store::set_unreachable(true);
            let err = restore(
                &n,
                &with,
                &RestoreOpts {
                    secret_storage: storage,
                    ..RestoreOpts::default()
                },
            );
            secrets::store::set_unreachable(false);
            let err = err.err().unwrap();
            assert!(
                err.contains("cannot read the keyring entry") && err.contains("--without-proxy"),
                "{err}"
            );
            assert!(!err.contains("Basic"), "{err}");
        }
        assert_eq!(std::fs::read(n.config_file()).unwrap(), before);
        // Once the keyring answers, the restore deletes them.
        let r = restore_into(&n, &parsed, None);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("header values") && n.contains("deleted")),
            "{r:?}"
        );
        assert!(secrets::proxy_headers(&n, &["Proxy-Authorization".into()]).is_err());

        // A machine with no config of its own and an entry in the keyring.
        let (_b, to) = node();
        secrets::store_proxy_headers(&to, &[("Proxy-Authorization".into(), "Basic X".into())])
            .unwrap();
        secrets::store::set_unreachable(true);
        let err = restore(&to, &parsed, &RestoreOpts::default());
        secrets::store::set_unreachable(false);
        assert!(err.err().unwrap().contains("to check whose they are"));
        assert!(!to.config_file().exists(), "nothing was written");
        assert!(
            secrets::store::get(Entry::proxy(&to).account())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_restore_without_the_proxy_keeps_nothing_of_it_and_needs_no_keyring() {
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        secrets::store_proxy_headers(&n, &[("Proxy-Authorization".into(), "Basic A".into())])
            .unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy-a.example:3128".into());
            c.connection.headers = vec!["Proxy-Authorization".into()];
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_f, plain, _) = roundtrip(&n, false);
        let (_g, with, _) = roundtrip(&n, true);
        assert!(with.proxy_headers.is_some() && plain.proxy_headers.is_none());

        // The node moved to proxy B, and the keyring does not answer: the
        // restore that cannot say whose the values are is refused, and the
        // one that leaves the proxy out is not.
        secrets::store_proxy_headers(&n, &[("Proxy-Authorization".into(), "Basic B".into())])
            .unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy-b.example:3128".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let without = RestoreOpts {
            without_proxy: true,
            ..RestoreOpts::default()
        };
        secrets::store::set_unreachable(true);
        let refused = restore(&n, &plain, &RestoreOpts::default());
        let r = restore(&n, &plain, &without);
        secrets::store::set_unreachable(false);
        assert!(refused.is_err());
        let r = r.unwrap();
        let cfg = config(&n);
        assert_eq!(
            cfg.connection,
            Default::default(),
            "no proxy, pin, user or header names"
        );
        assert_eq!(cfg.centers.len(), 1);
        let notes = r.notes.join("\n");
        assert!(
            notes.contains("proxy is left out") && notes.contains("proxy set"),
            "{notes}"
        );
        // The pin goes with the proxy, and the note says what `proxy set`
        // needs then.
        assert!(
            notes.contains("its pin") && notes.contains("--pin") && notes.contains("relay token"),
            "{notes}"
        );
        // The keyring could not be asked to delete B's values; they are
        // said to be left, and no config names them.
        assert!(
            notes.contains("header values of the replaced node were left"),
            "{notes}"
        );

        // A backup that holds the values: they are not written either, and
        // the ones of the replaced node go.
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy-b.example:3128".into());
            c.connection.headers = vec!["Proxy-Authorization".into()];
            Ok(())
        })
        .unwrap();
        drop(s);
        secrets::store_proxy_headers(&n, &[("Proxy-Authorization".into(), "Basic B".into())])
            .unwrap();
        let r = restore(&n, &with, &without).unwrap();
        assert!(
            r.notes.iter().any(|n| n.contains("proxy is left out")),
            "{r:?}"
        );
        assert!(
            secrets::store::get(Entry::proxy(&n).account())
                .unwrap()
                .is_none()
        );
        assert_eq!(config(&n).connection, Default::default());

        // Without a proxy in the backup the flag says nothing.
        let (_b, plain_node) = node();
        paired(&plain_node, SecretStorage::File, &["home"]);
        let (_h, nothing, _) = roundtrip(&plain_node, false);
        let r = restore(&plain_node, &nothing, &without).unwrap();
        assert!(r.notes.is_empty(), "{r:?}");
    }

    #[test]
    fn a_restore_without_the_proxy_writes_none_of_its_credentials_on_an_empty_machine() {
        let without = RestoreOpts {
            without_proxy: true,
            ..RestoreOpts::default()
        };
        let account = |p: &NodePaths| Entry::proxy(p).account().to_string();

        // The header values of an http:// proxy, in a backup that holds them.
        let (_a, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        secrets::store_proxy_headers(&n, &[("Proxy-Authorization".into(), "Basic A".into())])
            .unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy-a.example:3128".into());
            c.connection.headers = vec!["Proxy-Authorization".into()];
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_f, with, _) = roundtrip(&n, true);
        assert!(with.proxy_headers.is_some());

        // A keyring that does not answer is no obstacle: nothing is written
        // to it, so the remedy the refusals name works.
        let (_b, to) = node();
        secrets::store::set_unreachable(true);
        let r = restore(&to, &with, &without);
        secrets::store::set_unreachable(false);
        r.unwrap();
        assert_eq!(config(&to).connection, Default::default());
        // And one that answers is not given the credential of a proxy the
        // restored config does not name.
        let (_c, to) = node();
        restore(&to, &with, &without).unwrap();
        assert!(secrets::store::get(&account(&to)).unwrap().is_none());
        // Without the flag the values go in.
        let (_d, to) = node();
        restore(&to, &with, &RestoreOpts::default()).unwrap();
        assert!(secrets::store::get(&account(&to)).unwrap().is_some());

        // The password of an https:// proxy, in files, in a default backup.
        let pin = nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()])
            .unwrap()
            .pin();
        let (_e, n) = node();
        paired(&n, SecretStorage::File, &["home"]);
        secrets::store_proxy_login(&n, SecretStorage::File, "a-token").unwrap();
        let mut s = open_store(&n);
        s.update(|c| {
            c.connection.proxy = Some("https://relay-a.example:7490".into());
            c.connection.pin = Some(pin.clone());
            c.connection.login = Some("node-a".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_g, plain, _) = roundtrip(&n, false);
        assert!(plain.proxy_login.is_some());
        let (_h, to) = node();
        restore(&to, &plain, &without).unwrap();
        assert!(!to.proxy_login_file().exists());
        assert!(
            secrets::get(&to, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );
        assert_eq!(config(&to).connection, Default::default());
        // Without the flag it is written.
        let (_i, to) = node();
        restore(&to, &plain, &RestoreOpts::default()).unwrap();
        assert_eq!(
            secrets::proxy_login(&to, SecretStorage::File).unwrap(),
            "a-token"
        );
    }

    #[test]
    fn a_restore_without_the_proxy_drops_its_password() {
        let pin = nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()])
            .unwrap()
            .pin();
        let (_a, n) = node();
        paired(&n, SecretStorage::Keyring, &["home"]);
        drop(with_proxy(&n, "relay-a.example", "node-a", "a-token", &pin));
        let (_f, with, _) = roundtrip(&n, true);
        assert!(with.proxy_login.is_some());
        let r = restore(
            &n,
            &with,
            &RestoreOpts {
                without_proxy: true,
                ..RestoreOpts::default()
            },
        )
        .unwrap();
        assert!(
            r.notes.iter().any(|n| n.contains("proxy is left out")),
            "{r:?}"
        );
        assert_eq!(config(&n).connection, Default::default());
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::ProxyLogin)
                .unwrap()
                .is_none()
        );
        assert!(!n.proxy_login_file().exists());
        // The node key is restored as usual.
        assert!(
            secrets::get(&n, SecretStorage::Keyring, Key::Center("home"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn what_is_not_in_the_backup_and_not_here_is_said() {
        let (_a, from) = node();
        paired(&from, SecretStorage::Keyring, &["home"]);
        let relay =
            nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()]).unwrap();
        secrets::store_relay_tls(&from, SecretStorage::Keyring, &relay).unwrap();
        secrets::store_proxy_login(&from, SecretStorage::Keyring, "s3cret-token").unwrap();
        secrets::store_proxy_headers(&from, &[("X-Token".into(), "tok-value".into())]).unwrap();
        let mut s = open_store(&from);
        s.update(|c| {
            c.relay.pin = Some(relay.pin());
            c.relay.listen = Some("127.0.0.1:7490".into());
            c.connection.proxy = Some("https://relay.example:7490".into());
            c.connection.pin = Some(relay.pin());
            c.connection.login = Some("node-a".into());
            c.connection.headers = vec!["X-Token".into()];
            Ok(())
        })
        .unwrap();
        drop(s);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        let notes = r.notes.join("\n");
        assert!(
            notes.contains("relay's TLS key") && notes.contains("relay set"),
            "{notes}"
        );
        assert!(notes.contains("proxy's password"), "{notes}");
        assert!(notes.contains("header values"), "{notes}");
        assert_eq!(r.no_key, ["home"]);
    }

    /// The sudo password the installed node on Windows keeps with DPAPI is at
    /// rest only while the switch is on.
    #[cfg(windows)]
    #[test]
    fn a_restore_deletes_the_dpapi_password_of_the_sudo_switch() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        let (_b, to) = node();
        let file = to.config_dir.join(crate::winsudo::SUDO_FILE);
        std::fs::create_dir_all(&to.config_dir).unwrap();
        std::fs::write(&file, b"sealed password").unwrap();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert!(!file.exists());
        assert!(r.notes.iter().any(|n| n.contains("sudo.dpapi")), "{r:?}");
    }

    #[test]
    fn a_failing_key_puts_back_the_ones_before_it() {
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::File, &["alpha", "beta"]);
        let (_f, parsed, _) = roundtrip(&from, false);
        // Another node here, with keys of its own for the same names.
        let (_b, to) = node();
        paired(&to, SecretStorage::File, &["alpha", "beta"]);
        let old_alpha = std::fs::read(to.key_file("alpha")).unwrap();
        // beta's key file is a directory: it cannot be written.
        std::fs::remove_file(to.key_file("beta")).unwrap();
        std::fs::create_dir(to.key_file("beta")).unwrap();
        let replace = RestoreOpts {
            replace: true,
            ..RestoreOpts::default()
        };
        let err = restore(&to, &parsed, &replace).err().unwrap();
        assert!(err.contains("nothing was restored"), "{err}");
        assert!(!err.contains(&keys["alpha"]) && !err.contains(&keys["beta"]));
        assert_eq!(
            std::fs::read(to.key_file("alpha")).unwrap(),
            old_alpha,
            "alpha is back as it was"
        );
        assert!(
            std::fs::read_to_string(to.config_file())
                .unwrap()
                .contains("beta")
        );
    }

    #[test]
    fn a_backup_that_does_not_fit_itself_is_refused() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let cfg = config(&from);
        let key = key_text(&from, SecretStorage::File, "home");
        let seal = |files: Vec<(&str, String)>| {
            parse(Contents {
                kind: Kind::Node,
                created_ms: 1,
                program: "t".into(),
                files: files.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            })
        };
        let toml = cfg.to_toml();
        // The good one parses.
        assert!(seal(vec![("node.toml", toml.clone()), ("key/home", key.clone())]).is_ok());
        let other = NodeKey::generate().unwrap().to_text();
        for (what, files, want) in [
            ("no config", vec![("key/home", key.clone())], "no node.toml"),
            (
                "a bad config",
                vec![("node.toml", "version = [".into())],
                "node.toml",
            ),
            (
                "a key of no pairing",
                vec![("node.toml", toml.clone()), ("key/lab", key.clone())],
                "does not pair",
            ),
            (
                "a path as a name",
                vec![("node.toml", toml.clone()), ("key/../x", key.clone())],
                "does not pair",
            ),
            (
                "a text that is no key",
                vec![("node.toml", toml.clone()), ("key/home", "nope".into())],
                "not a key",
            ),
            (
                "another node's key",
                vec![("node.toml", toml.clone()), ("key/home", other)],
                "another node id",
            ),
            (
                "a relay key without a relay",
                vec![("node.toml", toml.clone()), ("relay-tls", "x".into())],
                "no relay",
            ),
            (
                "a proxy password without a user",
                vec![("node.toml", toml.clone()), ("proxy-login", "x".into())],
                "no proxy user",
            ),
            (
                "a name nobody knows",
                vec![("node.toml", toml.clone()), ("../etc/passwd", "x".into())],
                "does not know",
            ),
        ] {
            let err = seal(files)
                .err()
                .unwrap_or_else(|| panic!("{what} was taken"));
            assert!(err.contains(want), "{what}: {err}");
            assert!(!err.contains(&key), "{what}: {err}");
        }
        // A center's backup is not a node's.
        let err = parse(Contents {
            kind: Kind::Center,
            created_ms: 1,
            program: "t".into(),
            files: BTreeMap::new(),
        })
        .err()
        .unwrap();
        assert!(err.contains("of a center, not of a node"), "{err}");
    }

    #[test]
    fn a_wrong_passphrase_and_a_short_one_say_so_without_the_secret() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("n.bak");
        let err = backup(
            &from,
            &config(&from),
            &file,
            &Passphrase::new("hunter2".into()),
            &opts(false),
        )
        .unwrap_err();
        assert!(
            err.contains("12 characters") && !err.contains("hunter2"),
            "{err}"
        );
        assert!(!file.exists());
        backup(&from, &config(&from), &file, &pass(), &opts(false)).unwrap();
        let bytes = backup::read_file(&file).unwrap();
        let err = open(&bytes, &Passphrase::new("wrong horse battery".into()))
            .err()
            .unwrap();
        assert!(
            err.contains("passphrase is wrong") && !err.contains("wrong horse"),
            "{err}"
        );
    }

    #[test]
    fn an_existing_file_is_kept_unless_the_owner_overwrites() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("n.bak");
        std::fs::write(&file, b"precious").unwrap();
        let err = backup(&from, &config(&from), &file, &pass(), &opts(false)).unwrap_err();
        assert!(err.contains("exists already"), "{err}");
        assert_eq!(std::fs::read(&file).unwrap(), b"precious");
        let o = BackupOpts {
            overwrite: true,
            ..opts(false)
        };
        backup(&from, &config(&from), &file, &pass(), &o).unwrap();
        assert!(backup::kind_of(&std::fs::read(&file).unwrap()).is_ok());
    }

    #[test]
    fn the_relay_and_the_proxy_keys_travel_too() {
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::File, &["home"]);
        let relay =
            nerve_transport::tls::ServerIdentity::generate(&["relay.example".into()]).unwrap();
        secrets::store_relay_tls(&from, SecretStorage::File, &relay).unwrap();
        secrets::store_proxy_login(&from, SecretStorage::File, "s3cret-token").unwrap();
        let mut s = open_store(&from);
        s.update(|c| {
            c.relay.pin = Some(relay.pin());
            c.relay.listen = Some("127.0.0.1:7490".into());
            c.connection.proxy = Some("https://relay.example:7490".into());
            c.connection.pin = Some(relay.pin());
            c.connection.login = Some("node-a".into());
            Ok(())
        })
        .unwrap();
        let (_f, parsed, report) = roundtrip(&from, false);
        assert_eq!(report.saved.len(), 3, "{report:?}");
        let (_b, to) = node();
        restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        assert_eq!(&key_text(&to, SecretStorage::File, "home"), &keys["home"]);
        assert_eq!(
            secrets::proxy_login(&to, SecretStorage::File).unwrap(),
            "s3cret-token"
        );
        assert_eq!(
            secrets::relay_tls(&to, SecretStorage::File)
                .unwrap()
                .unwrap()
                .pin(),
            relay.pin(),
            "the relay keeps the certificate its nodes pin"
        );
    }

    #[test]
    fn proxy_header_values_leave_the_keyring_only_with_consent() {
        let (_a, from) = node();
        paired(&from, SecretStorage::File, &["home"]);
        secrets::store_proxy_headers(&from, &[("X-Token".into(), "tok-value".into())]).unwrap();
        let mut s = open_store(&from);
        s.update(|c| {
            c.connection.proxy = Some("http://proxy.example:3128".into());
            c.connection.headers = vec!["X-Token".into()];
            Ok(())
        })
        .unwrap();
        let (_f, without, report) = roundtrip(&from, false);
        assert!(
            report
                .left_out
                .iter()
                .any(|l| l.what.contains("header values") && l.why == Why::Keyring),
            "{report:?}"
        );
        assert!(without.proxy_headers.is_none());

        let (_g, with, report) = roundtrip(&from, true);
        assert!(
            report.saved.iter().any(|l| l.contains("header values")),
            "{report:?}"
        );
        let (_b, to) = node();
        restore(&to, &with, &RestoreOpts::default()).unwrap();
        let got = secrets::proxy_headers(&to, &["X-Token".into()]).unwrap();
        assert_eq!(got, [("X-Token".to_string(), "tok-value".to_string())]);
    }

    #[test]
    fn nothing_prints_a_secret() {
        let (_a, from) = node();
        let keys = paired(&from, SecretStorage::File, &["home", "work"]);
        let (_f, parsed, report) = roundtrip(&from, false);
        let mut out = Vec::new();
        print_backup(&report, Path::new("/x/n.bak"), &mut out);
        let (_b, to) = node();
        let r = restore(&to, &parsed, &RestoreOpts::default()).unwrap();
        print_restore(&r, &parsed, &mut out);
        let text = String::from_utf8(out).unwrap();
        for k in keys.values() {
            assert!(!text.contains(k));
        }
        assert!(text.contains("home") && text.contains("work"));
        // The audit log says that it happened, and names no key.
        let audit = std::fs::read_to_string(to.audit_log()).unwrap();
        assert!(audit.contains("\"restored\""), "{audit}");
        for k in keys.values() {
            assert!(!audit.contains(k));
        }
    }
}
