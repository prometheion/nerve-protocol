//! The owner token: the one secret that logs in to the web UI.
//!
//! It is not a harness token. A harness keeps its token in its own MCP
//! entry, where an agent with a file tool can read it, and the web UI can
//! switch the action checker off and change what the machines allow; so a
//! harness token opens `/mcp` only, and the UI asks for this one.
//!
//! The center makes it at its first start and keeps it in `owner-token` in
//! the state folder (mode 0600), where the owner reads it again; it says so
//! on stderr and in the log at once. `nerve-center owner-token --new`, run
//! on the machine as the center's account (or as root), makes a new one: the
//! running center reads the file again when it changed, and the sessions of
//! the old token end at their next request. A backup does not carry it; a
//! restored center makes its own.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::util;

/// The file in the state folder.
pub const FILE: &str = "owner-token";
/// What an owner token starts with. `nrv_` keeps it out of the log as a
/// harness token is ([`nerve_transport::log::redact`]); `owner_` tells the
/// two apart at a glance.
pub const PREFIX: &str = "nrv_owner_";
/// The longest token the file may hold: the center's own are 50
/// characters, and an owner may write one of their own.
const MAX_LEN: usize = 200;
/// The shortest one: a wrong token's answer waits, but that does not bound
/// how fast a short one is guessed.
pub const MIN_LEN: usize = 20;

pub fn path(state: &Path) -> PathBuf {
    state.join(FILE)
}

/// A new owner token.
pub fn generate() -> String {
    format!("{PREFIX}{}", nerve_transport::keys::random_token(40))
}

/// The token the file holds, or none when there is no file. A file that
/// holds no token (empty, more than one line, too short or too long) is an
/// error, not a missing token: the center must not make a new one over what
/// the owner wrote there.
pub fn read(state: &Path) -> Result<Option<String>, String> {
    let p = path(state);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", p.display())),
    };
    let token = text.trim();
    if !token.is_empty() && token.chars().count() < MIN_LEN {
        return Err(format!(
            "{} holds an owner token shorter than {MIN_LEN} characters, which is too easy to guess; `nerve-center owner-token --new` writes a new one",
            p.display()
        ));
    }
    if token.is_empty()
        || token.len() > MAX_LEN
        || token.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "{} holds no owner token; `nerve-center owner-token --new` writes a new one",
            p.display()
        ));
    }
    Ok(Some(token.to_string()))
}

/// Writes a new token in place of the old one and gives it.
pub fn renew(state: &Path) -> Result<String, String> {
    let token = generate();
    let p = path(state);
    nerve_transport::files::write_private(&p, format!("{token}\n").as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    Ok(token)
}

/// The token, made when there is none; says whether it was made now.
pub fn ensure(state: &Path) -> Result<(String, bool), String> {
    match read(state)? {
        Some(t) => Ok((t, false)),
        None => renew(state).map(|t| (t, true)),
    }
}

/// `nerve-center owner-token`: says the token and where it is kept, after
/// making a new one with `new`. Run as the state folder's owner (the caller
/// settled that).
pub fn run(state: &Path, new: bool, out: &mut dyn std::io::Write) -> Result<(), String> {
    // A folder no center ran in yet gets no token: the wrong --state-dir
    // (the installed center's is /var/lib/nerve-center) would hand out a
    // token that opens nothing.
    if !state.join(crate::store::FILE).exists() && !path(state).exists() {
        return Err(format!(
            "no center has run in {} yet, and it makes its owner token at its first start; give the state folder with --state-dir (the installed center's is /var/lib/nerve-center)",
            state.display()
        ));
    }
    let (token, made) = if new {
        (renew(state)?, true)
    } else {
        ensure(state)?
    };
    let p = path(state);
    if made {
        let _ = writeln!(out, "made a new owner token, kept in {}:", p.display());
    } else {
        let _ = writeln!(out, "the owner token, kept in {}:", p.display());
    }
    let _ = writeln!(out, "{token}");
    let _ = writeln!(
        out,
        "It logs in to the web UI. A running center takes a new one at once, and the sessions of the old one end."
    );
    Ok(())
}

/// The owner token as the web UI checks it: the file's hash, read again
/// whenever the file changed, so a new token works at once and the old one
/// stops.
pub struct OwnerToken {
    path: PathBuf,
    /// The file as last read (its stamp) and the hash of its token.
    seen: Mutex<Option<(Stamp, Option<String>)>>,
}

/// What tells that the file changed: a new token is written to a new file
/// that takes the old one's place.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: u64,
}

impl Stamp {
    fn of(path: &Path) -> Option<Stamp> {
        let m = std::fs::metadata(path).ok()?;
        Some(Stamp {
            len: m.len(),
            modified: m.modified().ok(),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(&m),
        })
    }
}

impl OwnerToken {
    pub fn new(state: &Path) -> OwnerToken {
        OwnerToken {
            path: path(state),
            seen: Mutex::new(None),
        }
    }

    /// The SHA-256 (hex) of the token now; none while the file is missing
    /// or holds no token, and then nobody logs in.
    pub fn hash(&self) -> Option<String> {
        let stamp = Stamp::of(&self.path);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Without an inode (Windows) a token written within one tick of the
        // clock has the old one's length and time, so the file is read each
        // time there.
        if cfg!(unix)
            && let (Some(now), Some((was, hash))) = (&stamp, &*seen)
            && now == was
        {
            return hash.clone();
        }
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let hash = read(dir)
            .ok()
            .flatten()
            .map(|t| util::sha256_hex(t.as_bytes()));
        *seen = stamp.map(|s| (s, hash.clone()));
        hash
    }

    /// Whether `given` is the owner token.
    pub fn ok(&self, given: &str) -> bool {
        self.hash_ok(&util::sha256_hex(given.as_bytes()))
    }

    /// [`ok`](Self::ok) for a token known by its hash, as a session keeps
    /// it.
    pub fn hash_ok(&self, hash: &str) -> bool {
        self.hash()
            .is_some_and(|h| util::ct_eq(h.as_bytes(), hash.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_made_once_and_kept_private() {
        let d = tempfile::tempdir().unwrap();
        let (t, made) = ensure(d.path()).unwrap();
        assert!(made);
        assert!(t.starts_with(PREFIX) && t.len() == PREFIX.len() + 40, "{t}");
        assert_eq!(ensure(d.path()).unwrap(), (t.clone(), false));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path(d.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // It never reaches the log, as a harness token does not.
        assert!(!nerve_transport::log::redact(&format!("token {t}")).contains(&t));
    }

    #[test]
    fn a_file_without_a_token_is_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        for bad in [
            "",
            "\n",
            "two words but long enough",
            &"x".repeat(MAX_LEN + 1),
            &"x".repeat(MIN_LEN - 1),
        ] {
            std::fs::write(path(d.path()), bad).unwrap();
            let e = ensure(d.path()).unwrap_err();
            assert!(e.contains("owner-token --new"), "{e}");
            assert_eq!(std::fs::read_to_string(path(d.path())).unwrap(), bad);
        }
        // One of the owner's own, with a line break after it, is taken.
        std::fs::write(path(d.path()), "my-own-secret-of-20-chars\n").unwrap();
        assert_eq!(
            read(d.path()).unwrap().as_deref(),
            Some("my-own-secret-of-20-chars")
        );
    }

    /// A new token works at once and the old one stops, with no restart;
    /// without the file nobody logs in.
    #[test]
    fn the_check_follows_the_file() {
        let d = tempfile::tempdir().unwrap();
        let owner = OwnerToken::new(d.path());
        assert!(!owner.ok(""));
        let (old, _) = ensure(d.path()).unwrap();
        assert!(owner.ok(&old));
        assert!(!owner.ok("nrv_owner_wrong"));
        let new = renew(d.path()).unwrap();
        assert!(owner.ok(&new));
        assert!(!owner.ok(&old));
        std::fs::remove_file(path(d.path())).unwrap();
        assert!(!owner.ok(&new));
    }

    #[test]
    fn the_command_says_the_token_and_where_it_is() {
        let d = tempfile::tempdir().unwrap();
        let e = run(d.path(), false, &mut Vec::new()).unwrap_err();
        assert!(e.contains("--state-dir"), "{e}");
        assert!(!path(d.path()).exists());
        std::fs::write(d.path().join(crate::store::FILE), "{}").unwrap();
        let mut out = Vec::new();
        run(d.path(), false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let t = read(d.path()).unwrap().unwrap();
        assert!(text.contains(&t), "{text}");
        assert!(
            text.contains(&path(d.path()).display().to_string()),
            "{text}"
        );
        let mut out = Vec::new();
        run(d.path(), true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let new = read(d.path()).unwrap().unwrap();
        assert_ne!(new, t);
        assert!(text.contains("made a new owner token") && text.contains(&new));
    }
}
