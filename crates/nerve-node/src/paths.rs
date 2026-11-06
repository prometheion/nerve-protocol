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

    /// The log (docs/user/logs.md): what the node did, apart from the audit
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
