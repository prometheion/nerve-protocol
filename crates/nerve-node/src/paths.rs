//! Where a node keeps its files, and the system folders its protected list
//! hangs off.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use nerve_policy::protected::{Platform, WinFolders};

/// The pipe name for a state folder: a hash of the folder, so the name says
/// nothing of the account's paths and is never too long.
fn pipe_name(dir: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, dir.to_lowercase().as_bytes());
    let hex: String = digest.as_ref()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(r"\\.\pipe\nerve-node-{hex}")
}

/// The node's config directory (`node.toml`, keys) and state directory
/// (control socket, audit log, log, the config's MAC key). Tests point both at
/// temporary folders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePaths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

/// The node's folders by variable (`--config-dir`, `--state-dir`).
pub const CONFIG_DIR_VAR: &str = "NERVE_NODE_CONFIG_DIR";
pub const STATE_DIR_VAR: &str = "NERVE_NODE_STATE_DIR";

/// The node's variables before they had a prefix of their own, and their
/// names now: the node does not start while an old one is set
/// ([`refuse_old_names`]), so a folder is never taken from it without a word.
pub const OLD_NAMES: &[(&str, &str)] = &[
    ("NERVE_CONFIG_DIR", CONFIG_DIR_VAR),
    ("NERVE_STATE_DIR", STATE_DIR_VAR),
];

/// Refuses an old name of [`OLD_NAMES`] that `var` finds set, with its new
/// name and where it is set.
pub fn refuse_old_names(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> Result<(), String> {
    match OLD_NAMES.iter().find(|(old, _)| var(old).is_some()) {
        None => Ok(()),
        Some((old, new)) => Err(format!(
            "rename {old} to {new} where you set it (your shell, a script, a unit's Environment=); the node does not start while the old name is set"
        )),
    }
}

impl NodePaths {
    pub fn new(config_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> NodePaths {
        NodePaths {
            config_dir: config_dir.into(),
            state_dir: state_dir.into(),
        }
    }

    /// `--config-dir`/`NERVE_NODE_CONFIG_DIR`, else `~/.config/nerve`;
    /// likewise `--state-dir`/`NERVE_NODE_STATE_DIR`, else
    /// `~/.local/state/nerve`. When
    /// neither folder is named and `nerve-node install` put the node on this
    /// machine as a service, both are the installed node's
    /// ([`crate::service::Layout`]): the commands then reach the node that
    /// runs.
    pub fn from_args(config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> NodePaths {
        let config_dir = config_dir.or_else(|| env_dir(CONFIG_DIR_VAR));
        let state_dir = state_dir.or_else(|| env_dir(STATE_DIR_VAR));
        if config_dir.is_none() && state_dir.is_none() {
            let layout = crate::service::Layout::system();
            if layout.installed() {
                return layout.paths;
            }
        }
        Self::by_hand_or(config_dir, state_dir)
    }

    /// The folders of a node this user runs by hand, without naming them:
    /// [`NodePaths::from_args`] with none given, also once a service is
    /// installed.
    pub fn by_hand() -> NodePaths {
        Self::by_hand_or(env_dir(CONFIG_DIR_VAR), env_dir(STATE_DIR_VAR))
    }

    fn by_hand_or(config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> NodePaths {
        let home = home_dir();
        NodePaths {
            config_dir: config_dir.unwrap_or_else(|| home.join(".config/nerve")),
            state_dir: state_dir.unwrap_or_else(|| home.join(".local/state/nerve")),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("node.toml")
    }

    /// The node's private key for `center` (a 0600 file).
    pub fn key_file(&self, center: &str) -> PathBuf {
        self.config_dir.join("keys").join(format!("{center}.key"))
    }

    /// The node's new key for `center` while a rotation of it is under way
    /// (crate::rotate); a center name holds no `.`, so no center's key.
    pub fn next_key_file(&self, center: &str) -> PathBuf {
        self.config_dir
            .join("keys")
            .join(format!("{center}.next.key"))
    }

    /// The relay's TLS certificate and key (crate::relay), beside the
    /// center keys; not a `.key` name, so no center's.
    pub fn relay_tls_file(&self) -> PathBuf {
        self.config_dir.join("keys").join("relay-tls.pem")
    }

    /// The web UI's TLS certificate and key (crate::webui), beside the
    /// relay's.
    pub fn ui_tls_file(&self) -> PathBuf {
        self.config_dir.join("keys").join("ui-tls.pem")
    }

    /// The password of an `https://` proxy, a relay token above all.
    pub fn proxy_login_file(&self) -> PathBuf {
        self.config_dir.join("keys").join("proxy-login.secret")
    }

    pub fn ctl_socket(&self) -> PathBuf {
        self.state_dir.join("run").join("ctl.sock")
    }

    /// The control pipe of a node on Windows (crate::pipe): one per state
    /// folder, as the socket is. The folder is named by its real path,
    /// whatever spelling the CLI was given, and without case, as Windows
    /// treats it.
    pub fn ctl_pipe(&self) -> String {
        let dir = std::fs::canonicalize(&self.state_dir)
            .or_else(|_| std::path::absolute(&self.state_dir))
            .unwrap_or_else(|_| self.state_dir.clone());
        pipe_name(&dir.to_string_lossy())
    }

    pub fn audit_log(&self) -> PathBuf {
        self.state_dir.join("audit.jsonl")
    }

    /// The log (docs/dev/logging.md): what the node did, apart from the audit
    /// log, which is what it decided.
    pub fn log_file(&self) -> PathBuf {
        nerve_transport::log::file_in(&self.state_dir)
    }

    /// The key of the MAC over `node.toml`. It is not beside the file it
    /// signs: whatever could read the config folder would hold both, and the
    /// key must not depend on a setting in the file it checks.
    pub fn config_key(&self) -> PathBuf {
        self.state_dir.join("config.key")
    }

    /// The highest version of `node.toml` the node has saved or taken: an
    /// older signed file put back in the config folder is refused against it
    /// (`nerve_policy::settings::VERSION_FILE`). It holds no secret.
    pub fn config_version(&self) -> PathBuf {
        self.state_dir.join(nerve_policy::settings::VERSION_FILE)
    }

    /// Says that a move of the node's keys between their files and the
    /// system keyring is not finished: the other place may still hold
    /// copies ([`crate::secrets::settle`]). It holds no secret.
    pub fn keys_moving(&self) -> PathBuf {
        self.state_dir.join("keys.moving")
    }

    /// Held by a running node, and by a CLI while it moves the keys
    /// ([`crate::secrets::KeysLock`]).
    pub fn keys_lock(&self) -> PathBuf {
        self.state_dir.join("keys.lock")
    }

    /// The node's own files: no center reaches them, whatever its policy.
    pub fn own(&self) -> Vec<PathBuf> {
        vec![self.config_dir.clone(), self.state_dir.clone()]
    }
}

/// A folder named by the environment variable `key`, if it is set.
fn env_dir(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Where a Linux node whose keys are in the system keyring has them, or a
/// way to them, beside its own folders: no center reaches these either. The
/// D-Bus session the Secret Service answers on, which hands every entry to
/// any process of the user that asks (its runtime folder, `/run/user/<uid>`
/// where a D-Bus library looks when nothing names one, and the socket a
/// `unix:path=` bus address names), and the folder GNOME Keyring keeps its
/// keyrings in, which holds the keys in plain text when the keyring opens
/// without a password (`crate::keyring_setup`). `home` is the node's user's
/// home, `uid` its id and `var` reads the node's environment.
pub fn keyring_places(
    home: &Path,
    uid: u32,
    var: impl Fn(&str) -> Option<OsString>,
) -> Vec<PathBuf> {
    let dir = |k: &str| var(k).map(PathBuf::from).filter(|p| p.is_absolute());
    let mut out = Vec::new();
    out.extend(dir("XDG_RUNTIME_DIR"));
    out.push(PathBuf::from(format!("/run/user/{uid}")));
    if let Some(address) = var("DBUS_SESSION_BUS_ADDRESS") {
        out.extend(bus_sockets(&address.to_string_lossy()));
    }
    out.extend(dir("XDG_DATA_HOME").map(|d| d.join("keyrings")));
    out.push(home.join(".local/share/keyrings"));
    let mut seen = Vec::new();
    out.retain(|p| {
        let new = !seen.contains(p);
        seen.push(p.clone());
        new
    });
    out
}

/// The sockets a D-Bus address names (`unix:path=…`, `;` between the
/// addresses tried in turn). An abstract socket has no path; Landlock keeps
/// a command off those anyway.
fn bus_sockets(address: &str) -> Vec<PathBuf> {
    address
        .split(';')
        .filter_map(|a| a.strip_prefix("unix:"))
        .filter_map(|keys| {
            keys.split(',')
                .find_map(|kv| kv.strip_prefix("path="))
                .map(unescape)
        })
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .collect()
}

/// A D-Bus address value with its `%xx` escapes undone.
fn unescape(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The owner's home directory.
pub fn home_dir() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("/").to_path_buf())
}

/// The platform the protected list follows: this one, on Windows with its
/// system folders from the environment and the Documents folder from the
/// known-folder API.
pub fn platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows(windows_folders(|k| std::env::var_os(k), documents()))
    } else {
        Platform::Unix
    }
}

/// The platform the protected list follows for the node at `paths`: on the
/// installed Windows service the owner's ([`owners_platform`]), whose
/// Documents folder the service's own account does not see; elsewhere
/// [`platform`], with the folders of whoever runs the node. Read anew at
/// each call, as the owner's registry is there only while the owner is
/// signed in.
pub fn platform_for(paths: &NodePaths) -> Platform {
    #[cfg(windows)]
    if crate::service::is_service_node(paths)
        && let Ok(Some(sid)) = crate::win_host::owner()
    {
        return owners_platform(paths, &sid);
    }
    let _ = paths;
    platform()
}

/// [`platform_for`] on the installed service, for the owner whose SID is
/// `sid`: the Documents folder where the owner's registry puts it
/// ([`owners_documents`], remembered in the state folder for when that
/// cannot be read, [`seen_documents`]), and the usual place below the
/// owner's profile. The machine's folders (`%ProgramData%`,
/// `%SystemRoot%`, `%ProgramFiles%`) are the same for every account.
#[cfg(windows)]
fn owners_platform(paths: &NodePaths, sid: &str) -> Platform {
    let profile = crate::win_user::profile_of_sid(sid);
    // Only a thread that acts as the owner may read the owner's registry
    // (the node's own account may not): one that does not takes the
    // remembered place without a word.
    let (read, quiet) = match owners_documents(sid, profile.as_deref(), &mut warn_once) {
        Ok(d) => (Ok(d), false),
        Err(Unread::Denied(why)) => (Err(why), true),
        Err(Unread::Other(why)) => (Err(why), false),
    };
    let mut debug = |m: String| tracing::debug!("{m}");
    let say: &mut dyn FnMut(String) = if quiet { &mut debug } else { &mut warn_once };
    let documents = seen_documents(&documents_file(paths), sid, read, say);
    let var = |k: &str| {
        if k.eq_ignore_ascii_case("USERPROFILE") {
            profile.clone().map(OsString::from)
        } else {
            std::env::var_os(k)
        }
    };
    Platform::Windows(windows_folders(var, documents))
}

/// Logs `message` unless it is the one logged last: the service reads the
/// owner's folders before every command.
#[cfg(windows)]
fn warn_once(message: String) {
    static LAST: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let mut last = nerve_transport::sync::lock(&LAST);
    if last.as_deref() != Some(message.as_str()) {
        tracing::warn!("{message}");
        *last = Some(message);
    }
}

/// Where the installed node remembers the owner's Documents folder
/// ([`seen_documents`]).
#[cfg(any(windows, test))]
fn documents_file(paths: &NodePaths) -> PathBuf {
    paths.state_dir.join("owner-documents.json")
}

#[cfg(any(windows, test))]
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct SeenDocuments {
    #[serde(default)]
    format: nerve_transport::files::Format,
    sid: String,
    /// `None`: in its usual place below the profile.
    documents: Option<PathBuf>,
}

/// The owner's Documents folder for the protected list: `read` from the
/// owner's registry (`Ok(None)` where it is in its usual place), which is
/// remembered in `file` for the owner `sid`. Where it cannot be read (the
/// owner's registry is loaded only while the owner is signed in, or a
/// process of the owner's runs), the place remembered for the same owner,
/// and `say` is told why; with nothing remembered, `None`: the usual place
/// alone is protected, as before.
#[cfg(any(windows, test))]
fn seen_documents(
    file: &Path,
    sid: &str,
    read: Result<Option<PathBuf>, String>,
    say: &mut dyn FnMut(String),
) -> Option<PathBuf> {
    use nerve_transport::files::Format;
    let remembered = || -> Option<SeenDocuments> {
        let b = as_node(|| std::fs::read(file)).ok()?;
        Format::of_json(&b).check().ok()?;
        serde_json::from_slice::<SeenDocuments>(&b)
            .ok()
            .filter(|s| s.sid == sid)
    };
    match read {
        Ok(documents) => {
            let now = SeenDocuments {
                format: Format::CURRENT,
                sid: sid.to_string(),
                documents,
            };
            if remembered().as_ref() != Some(&now) {
                let json = serde_json::to_vec_pretty(&now).expect("a path serialises");
                // The CLI may not write the node's state folder: the node
                // remembers it at its next read.
                if let Err(e) = as_node(|| nerve_transport::files::write_private(file, &json)) {
                    tracing::debug!("cannot remember the owner's Documents folder: {e}");
                }
            }
            now.documents
        }
        Err(why) => match remembered() {
            Some(SeenDocuments {
                documents: Some(d), ..
            }) => {
                say(format!(
                    "cannot read the owner's Documents folder ({why}); protecting PowerShell's profiles in {}, where it was last seen, and below %USERPROFILE%\\Documents",
                    d.display()
                ));
                Some(d)
            }
            Some(_) => None,
            None => {
                say(format!(
                    "cannot read the owner's Documents folder ({why}); protecting PowerShell's profiles below %USERPROFILE%\\Documents only"
                ));
                None
            }
        },
    }
}

/// Runs `f`, a look at the node's state folder, as the node itself: on
/// the installed Windows service the thread may act as the owner, who may
/// not open that folder ([`crate::win_user::as_process`]).
#[cfg(any(windows, test))]
fn as_node<T>(f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    #[cfg(windows)]
    {
        crate::win_user::as_process(f)?
    }
    #[cfg(not(windows))]
    {
        f()
    }
}

/// Why [`owners_documents`] could not read the owner's folder.
#[cfg(windows)]
enum Unread {
    /// This thread may not read the owner's registry: it does not act as
    /// the owner.
    Denied(String),
    Other(String),
}

/// The owner's Documents folder as the owner's registry has it
/// (`User Shell Folders`, `Personal`, which OneDrive's backup and a
/// redirect change), written out with the owner's variables
/// ([`OwnerVars`]) and taken where it is on this machine
/// ([`documents_at`]); `Ok(None)` where the owner's registry names none
/// (the usual place). An error where the registry is not loaded, as before
/// the owner signs in, may not be read, or the value cannot be written out.
#[cfg(windows)]
fn owners_documents(
    sid: &str,
    profile: Option<&Path>,
    say: &mut dyn FnMut(String),
) -> Result<Option<PathBuf>, Unread> {
    const FOLDERS: &str =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
    match reg::has_key(sid) {
        Ok(true) => {}
        Ok(false) => {
            return Err(Unread::Other(
                "the owner's registry is not loaded: the owner has not signed in since Windows started"
                    .into(),
            ));
        }
        Err(e) => {
            return Err(Unread::Denied(format!(
                "the node may not read the owner's registry as itself ({e})"
            )));
        }
    }
    let Some(value) = reg::text(&format!("{sid}\\{FOLDERS}"), "Personal").map_err(Unread::Other)?
    else {
        return Ok(None);
    };
    let name = crate::win_user::name_of_sid(sid).ok();
    let vars = OwnerVars {
        profile,
        name: name.as_deref(),
        volatile: reg::texts(&format!("{sid}\\Volatile Environment")),
        environment: reg::texts(&format!("{sid}\\Environment")),
        system: &|k| std::env::var(k).ok(),
    };
    let path = expand_vars(&value, &|k| vars.get(k)).ok_or_else(|| {
        Unread::Other(format!("{value} names a variable the owner does not have"))
    })?;
    documents_at(path, say).map_err(Unread::Other)
}

/// The owner's Documents folder `path`, written out, as the protected list
/// takes it: a whole path on a drive of this machine. One on another
/// machine (a share, where a domain's folder redirection puts it) is not
/// taken, and `say` is told: the list resolves its entries, which would
/// connect there as whoever the node acts as, for every command, and send
/// that account's NTLM answer to whatever host the value names. No
/// container reaches a share (#149's probe), so the usual place is
/// protected only. An error for a path that is not whole.
#[cfg(any(windows, test))]
fn documents_at(path: String, say: &mut dyn FnMut(String)) -> Result<Option<PathBuf>, String> {
    if nerve_policy::paths::remote_target(&path) {
        say(format!(
            "the owner's Documents folder {path} is on another machine, which the node does not connect to; protecting PowerShell's profiles below %USERPROFILE%\\Documents only"
        ));
        return Ok(None);
    }
    let rest = path.strip_prefix(r"\\?\").unwrap_or(&path).as_bytes();
    let on_drive = rest.len() >= 3
        && rest[0].is_ascii_alphabetic()
        && rest[1] == b':'
        && matches!(rest[2], b'\\' | b'/');
    if on_drive {
        Ok(Some(PathBuf::from(path)))
    } else {
        Err(format!("{path} is not a whole path"))
    }
}

/// `value` with each `%NAME%` in it replaced by what `var` gives for the
/// name; `None` where a name has nothing, or a `%` is not closed.
#[cfg(any(windows, test))]
fn expand_vars(value: &str, var: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = value;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after.find('%')?;
        let name = &after[..end];
        if name.is_empty() {
            return None;
        }
        out.push_str(&var(name)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// The variables of the owner's processes as Windows makes them for a
/// sign-in: those of the owner's session (`volatile`), then the owner's own
/// (`environment`, written out with what follows), then those of the
/// profile (`USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `USERNAME`), then the
/// machine's (`system`). Names compare without case.
#[cfg(any(windows, test))]
struct OwnerVars<'a> {
    profile: Option<&'a Path>,
    name: Option<&'a str>,
    volatile: Vec<(String, String)>,
    environment: Vec<(String, String)>,
    system: &'a dyn Fn(&str) -> Option<String>,
}

#[cfg(any(windows, test))]
impl OwnerVars<'_> {
    fn get(&self, k: &str) -> Option<String> {
        let find = |list: &[(String, String)]| {
            list.iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
        };
        find(&self.volatile)
            .or_else(|| find(&self.environment).and_then(|v| expand_vars(&v, &|n| self.base(n))))
            .or_else(|| self.base(k))
    }

    /// The profile's variables and the machine's.
    fn base(&self, k: &str) -> Option<String> {
        let profile = self.profile.map(|p| p.to_string_lossy().into_owned());
        // `C:\Users\u` is `C:` and `\Users\u`.
        let split = profile
            .as_deref()
            .filter(|p| p.as_bytes().get(1) == Some(&b':'))
            .map(|p| p.split_at(2));
        match k.to_ascii_uppercase().as_str() {
            "USERPROFILE" => profile.clone(),
            "HOMEDRIVE" => split.map(|(d, _)| d.to_string()),
            "HOMEPATH" => split.map(|(_, r)| r.to_string()),
            "USERNAME" => self.name.map(str::to_string),
            _ => (self.system)(k),
        }
    }
}

/// The owner's registry below `HKEY_USERS`, read as this process may.
#[cfg(windows)]
mod reg {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_USERS, KEY_READ, REG_EXPAND_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ,
        RRF_RT_REG_SZ, RegCloseKey, RegEnumValueW, RegGetValueW, RegOpenKeyExW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn text_of(buf: &[u16]) -> String {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..n])
    }

    /// The key `path` below `HKEY_USERS`, open for reading; the error
    /// Windows gives where it is not.
    fn open_key(path: &str) -> Result<HKEY, u32> {
        let mut h = std::ptr::null_mut();
        // SAFETY: a NUL-terminated name and a place for the handle.
        match unsafe { RegOpenKeyExW(HKEY_USERS, wide(path).as_ptr(), 0, KEY_READ, &mut h) } {
            0 => Ok(h),
            e => Err(e),
        }
    }

    /// The key `path` below `HKEY_USERS`, open for reading.
    fn open(path: &str) -> Option<HKEY> {
        open_key(path).ok()
    }

    /// Whether the key `path` is there (a user's hive is while it is
    /// loaded); an error where it may not be opened.
    pub fn has_key(path: &str) -> std::io::Result<bool> {
        match open_key(path) {
            Ok(h) => {
                // SAFETY: the key just opened.
                unsafe { RegCloseKey(h) };
                Ok(true)
            }
            Err(ERROR_FILE_NOT_FOUND) => Ok(false),
            Err(e) => Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// The string value `name` of the key `path`, as written (`%…%` not
    /// expanded); `None` where it is not there.
    pub fn text(path: &str, name: &str) -> Result<Option<String>, String> {
        let (key, value) = (wide(path), wide(name));
        let mut buf = vec![0u16; 260];
        loop {
            let mut len = (buf.len() * 2) as u32;
            // SAFETY: NUL-terminated names and a buffer of the size given.
            let r = unsafe {
                RegGetValueW(
                    HKEY_USERS,
                    key.as_ptr(),
                    value.as_ptr(),
                    RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            match r {
                0 => return Ok(Some(text_of(&buf))),
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_MORE_DATA => buf.resize((len as usize).div_ceil(2) + 1, 0),
                e => {
                    return Err(format!(
                        "HKEY_USERS\\{path}\\{name}: {}",
                        std::io::Error::from_raw_os_error(e as i32)
                    ));
                }
            }
        }
    }

    /// Every string value of the key `path`, as written; none where it is
    /// not there.
    pub fn texts(path: &str) -> Vec<(String, String)> {
        let Some(h) = open(path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0.. {
            let mut name = vec![0u16; 16_384];
            let mut data = vec![0u16; 16_384];
            let (mut nlen, mut dlen, mut kind) = (name.len() as u32, (data.len() * 2) as u32, 0u32);
            // SAFETY: an open key and buffers of the sizes given.
            let r = unsafe {
                RegEnumValueW(
                    h,
                    i,
                    name.as_mut_ptr(),
                    &mut nlen,
                    std::ptr::null(),
                    &mut kind,
                    data.as_mut_ptr().cast(),
                    &mut dlen,
                )
            };
            if r == ERROR_NO_MORE_ITEMS {
                break;
            }
            if r == 0 && (kind == REG_SZ || kind == REG_EXPAND_SZ) {
                data.truncate((dlen as usize) / 2);
                out.push((
                    String::from_utf16_lossy(&name[..nlen as usize]),
                    text_of(&data),
                ));
            }
            if r != 0 && r != ERROR_MORE_DATA {
                break;
            }
        }
        // SAFETY: the key opened above.
        unsafe { RegCloseKey(h) };
        out
    }
}

/// The Documents folder as Windows has it, wherever OneDrive's backup or a
/// redirect moved it; `None`, logged, when it cannot be read (the usual
/// place below the profile is protected all the same).
fn documents() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let found = known_documents();
        if found.is_none() {
            tracing::warn!(
                "cannot read the Documents known folder; protecting PowerShell's profiles below %USERPROFILE%\\Documents only"
            );
        }
        found
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// `SHGetKnownFolderPath(FOLDERID_Documents)`, which PowerShell's
/// `$PROFILE` follows.
#[cfg(windows)]
fn known_documents() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Documents, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: the GUID is a static, a null token means the calling user,
    // and the call sets `raw` to a string it allocated (or to null).
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Documents,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut raw,
        )
    };
    let path = (hr >= 0 && !raw.is_null()).then(|| {
        // SAFETY: on success `raw` is a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        let wide = unsafe { std::slice::from_raw_parts(raw, len) };
        PathBuf::from(OsString::from_wide(wide))
    });
    // SAFETY: the string is freed with the allocator that made it, also
    // after a failure, as the API asks; freeing null does nothing.
    unsafe { CoTaskMemFree(raw as *const _) };
    path.filter(|p| p.is_absolute())
}

/// Each path once, ignoring case as Windows does, in the order given.
fn distinct(paths: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        let same = |o: &PathBuf| {
            o.to_string_lossy()
                .eq_ignore_ascii_case(&p.to_string_lossy())
        };
        if !out.iter().any(same) {
            out.push(p);
        }
    }
    out
}

/// `%ProgramData%`, `%SystemRoot%` and `%ProgramFiles%` as `var` reads them,
/// each with its usual place as well: a center does not set the node's
/// environment, but an odd one must not leave `C:\ProgramData\ssh`
/// unprotected. Likewise `documents`, the Documents folder where Windows
/// has it, and `%USERPROFILE%\Documents`.
pub fn windows_folders(
    var: impl Fn(&str) -> Option<OsString>,
    documents: Option<PathBuf>,
) -> WinFolders {
    let var = |n: &str| var(n).filter(|v| !v.is_empty()).map(PathBuf::from);
    let all = |names: &[&str], usual: &str| -> Vec<PathBuf> {
        distinct(
            names
                .iter()
                .filter_map(|n| var(n))
                .chain(std::iter::once(PathBuf::from(usual))),
        )
    };
    WinFolders {
        program_data: all(&["ProgramData", "ALLUSERSPROFILE"], "C:\\ProgramData"),
        system_root: all(&["SystemRoot", "windir"], "C:\\Windows"),
        // A 32-bit process sees the x86 folder as `ProgramFiles` and the
        // 64-bit one as `ProgramW6432`; both hold a PowerShell 7 of their own.
        program_files: all(
            &["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"],
            "C:\\Program Files",
        ),
        // Joined with `\` as on Windows, also when a test runs elsewhere.
        documents: distinct(documents.into_iter().chain(var("USERPROFILE").map(|h| {
            let h = h
                .to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .to_string();
            PathBuf::from(format!("{h}\\Documents"))
        }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node does not start while an old variable name is set, and says
    /// the new one; the new names pass.
    #[test]
    fn an_old_variable_name_is_refused() {
        let only = |names: &'static [&'static str]| {
            move |k: &str| names.contains(&k).then(|| std::ffi::OsString::from("/x"))
        };
        assert!(refuse_old_names(only(&[])).is_ok());
        assert!(refuse_old_names(only(&["NERVE_NODE_STATE_DIR"])).is_ok());
        let e = refuse_old_names(only(&["NERVE_STATE_DIR"])).unwrap_err();
        assert!(
            e.starts_with("rename NERVE_STATE_DIR to NERVE_NODE_STATE_DIR"),
            "{e}"
        );
        let e = refuse_old_names(only(&["NERVE_CONFIG_DIR"])).unwrap_err();
        assert!(
            e.starts_with("rename NERVE_CONFIG_DIR to NERVE_NODE_CONFIG_DIR"),
            "{e}"
        );
    }

    /// One pipe per state folder, the same for every spelling of it.
    #[test]
    fn the_pipe_is_the_state_folders() {
        let name = pipe_name(r"C:\ProgramData\nerve\state");
        assert!(name.starts_with(r"\\.\pipe\nerve-node-"), "{name}");
        assert_eq!(name.len(), r"\\.\pipe\nerve-node-".len() + 32);
        assert_eq!(name, pipe_name(r"c:\programdata\NERVE\state"));
        assert_ne!(name, pipe_name(r"C:\ProgramData\nerve\state2"));
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let given = NodePaths::new(d.path().join("config"), &state);
        let other = NodePaths::new("x", d.path().join("state/../state"));
        assert_eq!(given.ctl_pipe(), other.ctl_pipe());
    }

    #[test]
    fn windows_folders_come_from_the_environment_and_their_usual_place() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let f = windows_folders(
            env(&[
                ("ProgramData", "D:\\ProgramData"),
                ("SystemRoot", "D:\\WINDOWS"),
                ("windir", "D:\\WINDOWS"),
                ("ProgramFiles", "D:\\Program Files"),
                ("ProgramW6432", "D:\\Program Files"),
                ("ProgramFiles(x86)", "D:\\Program Files (x86)"),
            ]),
            None,
        );
        assert_eq!(
            f.program_data,
            [PathBuf::from("D:\\ProgramData"), "C:\\ProgramData".into()]
        );
        assert_eq!(
            f.system_root,
            [PathBuf::from("D:\\WINDOWS"), "C:\\Windows".into()]
        );
        assert_eq!(
            f.program_files,
            [
                PathBuf::from("D:\\Program Files"),
                "D:\\Program Files (x86)".into(),
                "C:\\Program Files".into()
            ]
        );
        // A 32-bit process: each folder once, however often it is named.
        let f = windows_folders(
            env(&[
                ("ProgramFiles", "C:\\Program Files (x86)"),
                ("ProgramW6432", "C:\\Program Files"),
                ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
            ]),
            None,
        );
        assert_eq!(
            f.program_files,
            [
                PathBuf::from("C:\\Program Files (x86)"),
                "C:\\Program Files".into()
            ]
        );
        // An empty or missing environment still protects the usual places.
        let f = windows_folders(env(&[("ProgramData", "")]), None);
        assert_eq!(f.program_data, [PathBuf::from("C:\\ProgramData")]);
        assert_eq!(f.system_root, [PathBuf::from("C:\\Windows")]);
        assert_eq!(f.program_files, [PathBuf::from("C:\\Program Files")]);
        let f = windows_folders(env(&[("SystemRoot", "c:\\windows")]), None);
        assert_eq!(f.system_root, [PathBuf::from("c:\\windows")]);
        assert_eq!(platform() == Platform::Unix, cfg!(not(windows)));
    }

    /// The Documents folder where the known-folder API puts it (OneDrive's
    /// backup, a redirect), and its usual place below the profile as well.
    #[test]
    fn the_documents_folder_comes_from_the_known_folder_and_the_profile() {
        let env = |k: &str| (k == "USERPROFILE").then(|| OsString::from("C:\\Users\\u"));
        let moved = PathBuf::from("C:\\Users\\u\\OneDrive\\Documents");
        let f = windows_folders(env, Some(moved.clone()));
        assert_eq!(f.documents, [moved, "C:\\Users\\u\\Documents".into()]);
        // When the known folder cannot be read, the usual place is left.
        let f = windows_folders(env, None);
        assert_eq!(f.documents, [PathBuf::from("C:\\Users\\u\\Documents")]);
        // Not moved: once.
        let f = windows_folders(env, Some("c:\\users\\u\\documents".into()));
        assert_eq!(f.documents, [PathBuf::from("c:\\users\\u\\documents")]);
    }

    /// A value of the owner's registry is written out with the owner's
    /// variables: the session's before the owner's own (which are written
    /// out with the profile's), then the profile's, then the machine's;
    /// names without case. A name without a value, or a `%` not closed,
    /// writes out nothing.
    #[test]
    fn the_owners_documents_are_written_out_with_the_owners_variables() {
        let pairs = |l: &[(&str, &str)]| -> Vec<(String, String)> {
            l.iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect()
        };
        let system = |k: &str| {
            match k {
                "SystemDrive" => Some("C:"),
                // The service's own, which is not the owner's.
                "USERPROFILE" => Some("C:\\Windows\\ServiceProfiles\\nerve"),
                "OneDrive" => Some("C:\\Windows\\ServiceProfiles\\nerve\\OneDrive"),
                _ => None,
            }
            .map(str::to_string)
        };
        let vars = OwnerVars {
            profile: Some(Path::new("C:\\Users\\u")),
            name: Some("u"),
            volatile: pairs(&[("HOMESHARE", "\\\\server\\u")]),
            environment: pairs(&[
                ("OneDrive", "%USERPROFILE%\\OneDrive"),
                ("TEMP", "%nothing%"),
            ]),
            system: &system,
        };
        let get = |k: &str| vars.get(k);
        for (value, written) in [
            ("%USERPROFILE%\\Documents", Some("C:\\Users\\u\\Documents")),
            (
                "%onedrive%\\Documents",
                Some("C:\\Users\\u\\OneDrive\\Documents"),
            ),
            ("%HOMEDRIVE%%HOMEPATH%\\Docs", Some("C:\\Users\\u\\Docs")),
            ("%SystemDrive%\\%USERNAME%", Some("C:\\u")),
            ("%HOMESHARE%\\Docs", Some("\\\\server\\u\\Docs")),
            ("D:\\Documents", Some("D:\\Documents")),
            ("%TEMP%\\x", None),
            ("%NOPE%\\Documents", None),
            ("C:\\50%\\x", None),
        ] {
            assert_eq!(expand_vars(value, &get).as_deref(), written, "{value}");
        }
        // Without a profile, none of the profile's variables.
        let bare = OwnerVars {
            profile: None,
            name: None,
            volatile: Vec::new(),
            environment: Vec::new(),
            system: &system,
        };
        assert_eq!(bare.get("HOMEDRIVE"), None);
        assert_eq!(bare.get("USERPROFILE"), None);
    }

    /// The owner's Documents folder read from the owner's registry is
    /// remembered in the state folder; where the registry cannot be read
    /// (the owner not signed in since Windows started), the place
    /// remembered for the same owner is protected, and the log says so.
    /// Another owner's place is not taken, and with nothing remembered the
    /// usual place alone is.
    #[test]
    fn the_owners_documents_are_remembered_for_when_they_cannot_be_read() {
        let d = tempfile::tempdir().unwrap();
        let file = documents_file(&NodePaths::new(d.path(), d.path()));
        let mut said = Vec::new();
        let mut say = |m: String| said.push(m);
        let moved = PathBuf::from("D:\\OneDrive\\Documents");
        let gone = || Err("not loaded".to_string());
        assert_eq!(seen_documents(&file, "S-1-5-21-1", gone(), &mut say), None);
        assert_eq!(
            seen_documents(&file, "S-1-5-21-1", Ok(Some(moved.clone())), &mut say),
            Some(moved.clone())
        );
        assert_eq!(
            seen_documents(&file, "S-1-5-21-1", gone(), &mut say),
            Some(moved.clone())
        );
        assert_eq!(seen_documents(&file, "S-1-5-21-2", gone(), &mut say), None);
        // Back in its usual place, protected anyway: nothing to say.
        assert_eq!(
            seen_documents(&file, "S-1-5-21-1", Ok(None), &mut say),
            None
        );
        assert_eq!(seen_documents(&file, "S-1-5-21-1", gone(), &mut say), None);
        assert_eq!(said.len(), 3, "{said:?}");
        assert!(
            said[0].contains("not loaded") && said[0].ends_with("only"),
            "{said:?}"
        );
        assert!(said[1].contains("D:\\OneDrive\\Documents"), "{said:?}");
        assert!(said[2].ends_with("only"), "{said:?}");
    }

    /// A Documents folder on another machine (a domain's folder
    /// redirection, or a value a process of the owner's wrote) is not taken
    /// for the protected list, which would connect there to resolve it: the
    /// usual place is protected, and the log says why. One on a drive is
    /// taken; one that is not a whole path is an error.
    #[test]
    fn the_owners_documents_on_another_machine_are_not_taken() {
        let mut said = Vec::new();
        for share in [
            r"\\server\share\u\Documents",
            r"\\?\UNC\server\share\Documents",
            r"//server/share/Documents",
        ] {
            let got = documents_at(share.to_string(), &mut |m| said.push(m));
            assert_eq!(got, Ok(None), "{share}");
        }
        assert_eq!(said.len(), 3, "{said:?}");
        assert!(said[0].contains("another machine"), "{said:?}");
        for local in [r"C:\Users\u\OneDrive\Documents", r"\\?\D:\Docs", "E:/Docs"] {
            let got = documents_at(local.to_string(), &mut |m| said.push(m));
            assert_eq!(got, Ok(Some(PathBuf::from(local))), "{local}");
        }
        assert!(documents_at("Documents".into(), &mut |_| {}).is_err());
        assert_eq!(said.len(), 3, "{said:?}");
    }

    /// The real read of the owner's registry: for this process' own user,
    /// whose registry is loaded, it finds the folder the known-folder API
    /// gives (or none, where that is the usual place). Only a Windows run
    /// reaches it.
    #[cfg(windows)]
    #[test]
    fn the_owners_documents_are_read_from_the_owners_registry() {
        let o = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let sid = line
            .rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_string();
        assert!(sid.starts_with("S-1-5-"), "{line}");
        let profile = crate::win_user::profile_of_sid(&sid).expect("a profile");
        let known = known_documents().expect("the Documents known folder");
        let Ok(read) = owners_documents(&sid, Some(&profile), &mut |_| {}) else {
            panic!("the own registry is read");
        };
        let read = read.unwrap_or_else(|| profile.join("Documents"));
        assert!(
            read.to_string_lossy()
                .eq_ignore_ascii_case(&known.to_string_lossy()),
            "{read:?} {known:?}"
        );
        assert!(owners_documents("S-1-5-21-1-2-3-4242", None, &mut |_| {}).is_err());
    }

    /// With the keys in the keyring, the session bus and GNOME Keyring's folder
    /// are the node's own too. Unix only: the places are Linux's (the daemon
    /// asks for them on Linux alone), and the paths here are Unix paths, which
    /// are not absolute on Windows.
    #[cfg(unix)]
    #[test]
    fn the_keyring_places_are_the_session_bus_and_the_keyring_folder() {
        let env = |k: &str| {
            match k {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000"),
                "DBUS_SESSION_BUS_ADDRESS" => {
                    Some("unix:abstract=/tmp/x;unix:guid=1,path=/tmp/dbus%2dabc")
                }
                "XDG_DATA_HOME" => Some("/data/bob"),
                _ => None,
            }
            .map(OsString::from)
        };
        assert_eq!(
            keyring_places(Path::new("/home/bob"), 1000, env),
            [
                PathBuf::from("/run/user/1000"),
                "/tmp/dbus-abc".into(),
                "/data/bob/keyrings".into(),
                "/home/bob/.local/share/keyrings".into()
            ]
        );
        // Nothing named: the usual places of the installed node's user.
        assert_eq!(
            keyring_places(Path::new("/var/lib/nerve"), 990, |_| None),
            [
                PathBuf::from("/run/user/990"),
                "/var/lib/nerve/.local/share/keyrings".into()
            ]
        );
        // A relative folder in the environment names nothing.
        let odd = |k: &str| (k == "XDG_RUNTIME_DIR").then(|| OsString::from("run"));
        assert_eq!(keyring_places(Path::new("/h"), 7, odd).len(), 2);
    }

    /// The real known-folder read; only a Windows run reaches it.
    #[cfg(windows)]
    #[test]
    fn the_known_documents_folder_is_read() {
        let docs = known_documents().expect("the Documents known folder");
        assert!(docs.is_absolute(), "{docs:?}");
    }
}
