//! Backup and restore of the center (docs/dev/backup.md, docs/user/backup.md).
//!
//! The center keeps two files in its state folder that a move or a rebuilt
//! machine must not lose: `tls.pem`, its certificate and private key, whose
//! pin every node holds, and `state.json`, its id and name, the paired nodes
//! with their public keys, the hashes of the harness tokens and the
//! statistics. With both, the nodes find the same center again and need not
//! pair. The log and the sockets belong to the machine and are not taken.
//!
//! While a rotation of its key is in its grace, the center also keeps the
//! new key, `tls.next.pem`, which the nodes it told pin already: the backup
//! takes it then, or a restore would lose it and with it those nodes.
//!
//! A backup can be made while the center runs: both files are written whole
//! (a temporary file and a rename), so the copy is one the center had, at
//! most five seconds behind in its statistics. A restore never runs while a
//! center holds the state folder.
//!
//! No message here carries the private key or the passphrase.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use nerve_transport::backup::{self, Contents, Kind, Passphrase};
use nerve_transport::tls::ServerIdentity;

use crate::center::{IDENTITY_FILE, NEXT_IDENTITY_FILE};
use crate::store::{self, Store};

/// What a backup of the center holds, by logical name.
const IDENTITY: &str = "tls.pem";
const STATE: &str = "state.json";
/// The new key of a center key rotation in its grace.
const NEXT_IDENTITY: &str = "tls.next.pem";

/// What was backed up, for the owner.
#[derive(Debug)]
pub struct BackupReport {
    pub name: String,
    pub id: String,
    pub pin: String,
    pub nodes: usize,
}

/// Writes the backup of the center in `state` to `file`.
pub fn backup(
    state: &Path,
    file: &Path,
    pass: &Passphrase,
    overwrite: bool,
    rounds: u32,
) -> Result<BackupReport, String> {
    pass.check_new()?;
    let read = |name: &str| {
        std::fs::read_to_string(state.join(name)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "{} is not there: no center has run in {}",
                    state.join(name).display(),
                    state.display()
                )
            } else {
                format!("cannot read {}: {e}", state.join(name).display())
            }
        })
    };
    // The new key is read first: a rotation that ends meanwhile moves it to
    // `tls.pem` and marks the state finished, so the state read last says
    // whether it still belongs. One that starts meanwhile is taken on a
    // second try.
    let mut files = BTreeMap::new();
    for _ in 0..3 {
        let next = std::fs::read_to_string(state.join(NEXT_IDENTITY_FILE)).ok();
        let identity = read(IDENTITY_FILE)?;
        let state_text = read(store::FILE)?;
        let rotating = serde_json::from_str::<Store>(&state_text)
            .ok()
            .and_then(|s| s.key_rotation)
            .filter(|r| r.finished_ms.is_none());
        let next = rotating.as_ref().and(next);
        let complete = rotating.is_none() || next.is_some();
        files = BTreeMap::from([
            (IDENTITY.to_string(), identity),
            (STATE.to_string(), state_text),
        ]);
        if let Some(n) = next {
            files.insert(NEXT_IDENTITY.to_string(), n);
        }
        if complete {
            break;
        }
    }
    let contents = Contents {
        kind: Kind::Center,
        created_ms: crate::util::now_ms(),
        program: format!("nerve-center {}", env!("CARGO_PKG_VERSION")),
        files,
    };
    // The same checks a restore makes: a backup that would not restore is
    // not written.
    let parsed = parse(contents.clone())?;
    let bytes = backup::seal_with(&contents, pass, rounds)?;
    backup::write_file(file, &bytes, overwrite)?;
    Ok(BackupReport {
        name: parsed.store.center_name.clone(),
        id: parsed.store.center_id.clone(),
        pin: parsed.identity.pin(),
        nodes: parsed.store.nodes.len(),
    })
}

/// A center backup that was opened and checked.
pub struct Parsed {
    identity_text: String,
    state_text: String,
    /// The new key of a center key rotation in its grace.
    next_text: Option<String>,
    identity: ServerIdentity,
    store: Store,
    pub created_ms: u64,
    pub program: String,
}

impl Parsed {
    pub fn name(&self) -> &str {
        &self.store.center_name
    }

    pub fn pin(&self) -> String {
        self.identity.pin()
    }
}

/// Checks what [`backup::open`] returned: that it is a center backup that
/// holds a certificate with its key and a state file that reads.
pub fn parse(contents: Contents) -> Result<Parsed, String> {
    if contents.kind != Kind::Center {
        return Err(format!(
            "this is the backup of a {}, not of a center: restore it with `nerve-node restore`",
            contents.kind.word()
        ));
    }
    let mut files = contents.files;
    let identity_text = files
        .remove(IDENTITY)
        .ok_or("the backup holds no certificate and key")?;
    let state_text = files.remove(STATE).ok_or("the backup holds no state")?;
    let next_text = files.remove(NEXT_IDENTITY);
    if let Some(other) = files.keys().next() {
        return Err(format!(
            "the backup holds {other:?}, which this program does not know; it was made by a newer one?"
        ));
    }
    let identity = ServerIdentity::from_pem(&identity_text)
        .map_err(|e| format!("the certificate and key in the backup: {e}"))?;
    // The key must be the certificate's: a server that cannot sign with it
    // would refuse every node.
    identity
        .server_config()
        .map_err(|_| "the key in the backup does not go with its certificate".to_string())?;
    let store: Store = serde_json::from_str(&state_text)
        .map_err(|e| format!("the state in the backup is not valid: {e}"))?;
    if store.center_id.is_empty() {
        return Err("the state in the backup has no center id".into());
    }
    // The new key of a rotation must be the one its state told the nodes.
    if let Some(t) = &next_text {
        let next = ServerIdentity::from_pem(t)
            .map_err(|e| format!("the new key of the rotation in the backup: {e}"))?;
        let told = store
            .key_rotation
            .as_ref()
            .filter(|r| r.finished_ms.is_none())
            .map(|r| r.new_spki.clone());
        if told != Some(nerve_transport::tls::b64url(&next.spki())) {
            return Err(
                "the backup holds a new key of a rotation its state does not tell the nodes".into(),
            );
        }
    }
    Ok(Parsed {
        identity_text,
        state_text,
        next_text,
        identity,
        store,
        created_ms: contents.created_ms,
        program: contents.program,
    })
}

/// Opens a backup file's bytes with the passphrase and checks them.
pub fn open(bytes: &[u8], pass: &Passphrase) -> Result<Parsed, String> {
    parse(backup::open(bytes, pass)?)
}

/// What a restore did.
#[derive(Debug, Default)]
pub struct RestoreReport {
    pub notes: Vec<String>,
    /// The pin of the certificate the restore wrote: the backup's, or the
    /// newer one here it kept.
    pub pin: String,
}

/// What the state folder holds before a restore.
enum Target {
    Empty,
    Center { id: String, name: String },
    Unreadable(String),
}

fn inspect(state: &Path) -> Target {
    match Store::load(state) {
        Ok(None) => Target::Empty,
        Ok(Some(s)) => Target::Center {
            id: s.center_id,
            name: s.center_name,
        },
        Err(e) => Target::Unreadable(e.to_string()),
    }
}

/// Puts the certificate, the key and the state of the backup in `state`.
///
/// Holds the center lock for its whole run: a center that runs holds it, and
/// one that starts meanwhile finds the state folder taken. Both files are
/// written whole; when the second cannot be, the first goes back.
pub fn restore(state: &Path, b: &Parsed, replace: bool) -> Result<RestoreReport, String> {
    let _lock = crate::attach::claim(state)?.ok_or_else(|| {
        format!(
            "a nerve-center runs on {}: a restore never goes under a running center. Stop it (end the harness that started it, or the process that runs it), then restore",
            state.display()
        )
    })?;
    let mut report = RestoreReport::default();
    let id_path = state.join(IDENTITY_FILE);
    match inspect(state) {
        Target::Center { id, name } if id != b.store.center_id && !replace => {
            return Err(format!(
                "the center here is {name} ({id}); the backup is of {} ({}). They are not the same center, and a restore would replace the one here: every node paired with it would have to pair again. If you mean that, add --replace",
                b.store.center_name, b.store.center_id
            ));
        }
        Target::Unreadable(why) if !replace => {
            return Err(format!(
                "the state here cannot be read ({why}). A restore replaces it; add --replace to do that"
            ));
        }
        Target::Center { id, .. } if id != b.store.center_id => report.notes.push(
            "the center here was another one: the nodes paired with it must pair again".into(),
        ),
        _ => {}
    }

    // What is here now: put back when a write fails.
    let old = std::fs::read_to_string(&id_path).ok();
    let next_path = state.join(NEXT_IDENTITY_FILE);
    let old_next = std::fs::read_to_string(&next_path).ok();

    // What goes in: the backup's, unless the center here is further along.
    // Its key rotated since the backup was made: its nodes were told the new
    // key and stop taking the backup's when their old pin's time is over, so
    // the new key and the rotation stay. A node's key rotated since: the
    // node holds only its new key, so its record here stays.
    let mut identity_text = b.identity_text.clone();
    let mut next_text = b.next_text.clone();
    let mut state_text = b.state_text.clone();
    let here_store = Store::load(state)
        .ok()
        .flatten()
        .filter(|h| h.center_id == b.store.center_id);
    let mut st = b.store.clone();
    let mut changed = false;
    let kept_rotation = here_store
        .as_ref()
        .and_then(|h| rotated_since(h, b, old.as_deref(), old_next.as_deref()));
    let kept_any = kept_rotation.is_some();
    if let Some(kept) = kept_rotation {
        st.key_rotation = kept.rotation;
        st.key_rotations = kept.rotations;
        changed = true;
        if let Some(t) = kept.identity {
            identity_text = t;
        }
        next_text = kept.next;
        report.notes.push(
            "the center's key was rotated after the backup was made, and its nodes were told: the restore keeps the new key and the rotation, not the backup's older key".into(),
        );
    }
    if let Some(h) = &here_store {
        for (id, n) in st.nodes.iter_mut() {
            let Some(hn) = h.nodes.get(id) else {
                continue;
            };
            if hn.key_rotations > n.key_rotations {
                n.public_key = hn.public_key.clone();
                n.old_key = hn.old_key.clone();
                n.key_rotations = hn.key_rotations;
                changed = true;
                report.notes.push(format!(
                    "the node {} rotated its key after the backup was made: the restore keeps its new key here, the only one it holds",
                    n.name
                ));
            } else if hn.key_rotations == n.key_rotations && hn.public_key == n.public_key {
                // The same key, but its old one's grace ended here sooner
                // (the node ended it, maybe because that key leaked): the
                // old key does not come back.
                let sooner = match (&hn.old_key, &n.old_key) {
                    (_, None) => false,
                    (None, Some(_)) => true,
                    (Some(h), Some(b)) => h.until_ms < b.until_ms,
                };
                if sooner {
                    n.old_key = hn.old_key.clone();
                    changed = true;
                    report.notes.push(format!(
                        "the grace of the old key of node {} ended after the backup was made: the restore does not bring that key back",
                        n.name
                    ));
                }
            }
        }
    }
    if changed {
        state_text = serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?;
    }

    // The pin the nodes hold: said when the certificate here is another.
    let pin = ServerIdentity::from_pem(&identity_text)
        .map(|i| i.pin())
        .unwrap_or_default();
    if let Some(old_pin) = old
        .as_deref()
        .and_then(|t| ServerIdentity::from_pem(t).ok())
        .map(|i| i.pin())
        && old_pin != pin
    {
        report.notes.push(format!(
            "the certificate here had the pin {old_pin}; it has the backup's pin {pin} now, which is the one the nodes of the backup hold"
        ));
    }

    nerve_transport::files::create_private_dir(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))?;
    nerve_transport::files::write_private(&id_path, identity_text.as_bytes()).map_err(|e| {
        format!(
            "cannot write {}: {e}; nothing was restored",
            id_path.display()
        )
    })?;
    // The new key of a rotation in its grace, or none: a new key left here
    // from another rotation is not the backup's.
    let next_written = match &next_text {
        Some(t) => nerve_transport::files::write_private(&next_path, t.as_bytes()),
        None => match std::fs::remove_file(&next_path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
    };
    let state_path = state.join(store::FILE);
    let written = next_written
        .map_err(|e| (next_path.clone(), e))
        .and_then(|()| {
            nerve_transport::files::write_private(&state_path, state_text.as_bytes())
                .map_err(|e| (state_path.clone(), e))
        });
    if let Err((path, e)) = written {
        // What was here goes back, the new key of a rotation in its grace
        // with the certificate: the old state, which stays, holds that
        // rotation, and its nodes were told the new key.
        let put_back = |at: &Path, text: &Option<String>| match text {
            Some(t) => {
                let _ = nerve_transport::files::write_private(at, t.as_bytes());
            }
            None => {
                let _ = std::fs::remove_file(at);
            }
        };
        put_back(&next_path, &old_next);
        put_back(&id_path, &old);
        return Err(format!(
            "cannot write {}: {e}; nothing was restored",
            path.display()
        ));
    }
    if b.next_text.is_some() && !kept_any {
        report.notes.push(
            "the backup was made during the grace of a rotation of the center's key: its new key is restored too, and the center serves it when the grace ends. If that grace was ended after the backup was made, end it again (Settings, Center key, Serve the new key now): the machines that were told take only the new key".into(),
        );
    }
    report.pin = pin;
    Ok(report)
}

/// What a restore keeps of a rotation of the center's key made after the
/// backup.
struct KeptRotation {
    /// The rotation record here, if it still has one.
    rotation: Option<store::KeyRotation>,
    /// The count of rotations here.
    rotations: u32,
    /// The certificate and key here, which the center serves.
    identity: Option<String>,
    /// The new key here of a rotation still in its grace.
    next: Option<String>,
}

/// The center's keys here, when the state here is further along than the
/// backup's: it started more rotations of its key, or it ended the rotation
/// the backup was made in the grace of. The keys come from here only, and
/// only when they are the ones the state here names (served, and the new key
/// of a rotation in its grace). `None` otherwise.
fn rotated_since(
    here: &Store,
    b: &Parsed,
    here_identity: Option<&str>,
    here_next: Option<&str>,
) -> Option<KeptRotation> {
    let spki_of = |t: &str| {
        ServerIdentity::from_pem(t)
            .ok()
            .map(|i| nerve_transport::tls::b64url(&i.spki()))
    };
    let identity = here_identity?.to_string();
    let served = spki_of(&identity)?;
    // A rotation whose new key is served here has ended, also when that end
    // could not be saved: the next start settles it so, as
    // `settle_rotation` does.
    let ended = |r: &store::KeyRotation| r.finished_ms.is_some() || served == r.new_spki;
    let further = here.key_rotations > b.store.key_rotations;
    // A backup made in the grace of the rotation that ended here (also
    // early): the same count, but further along here.
    let ended_here = b.next_text.is_some()
        && here.key_rotation.as_ref().is_some_and(|r| {
            ended(r)
                && b.store
                    .key_rotation
                    .as_ref()
                    .is_some_and(|br| br.new_spki == r.new_spki)
        });
    if !further && !ended_here {
        return None;
    }
    let r = here.key_rotation.clone();
    let next = match &r {
        // In the grace: the old key served, the new one aside.
        Some(r) if !ended(r) => {
            if served != r.old_spki {
                return None;
            }
            Some(
                here_next
                    .filter(|t| spki_of(t).as_ref() == Some(&r.new_spki))?
                    .to_string(),
            )
        }
        // After it: the new key served.
        Some(r) => {
            if served != r.new_spki {
                return None;
            }
            None
        }
        // A rotation older than its record: the key served is its newest.
        None => None,
    };
    Some(KeptRotation {
        rotation: r,
        rotations: here.key_rotations,
        identity: Some(identity),
        next,
    })
}

/// Root's backup of another user's state folder runs as that user
/// ([`crate::service::settle_user`]), who may not reach every place root
/// named. The two places that fail for that reason alone, the backup's
/// folder and the passphrase file, are checked first and said with what to
/// do; every other error is the backup's own.
fn as_owner_may_reach(state: &Path, file: &Path, pass_file: Option<&Path>) -> Result<(), String> {
    let who = format!(
        "the owner of {} (uid {}), whom root's command on that folder runs as",
        state.display(),
        nerve_transport::net::euid()
    );
    let dir = file
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if denied(dir, Access::Write) {
        return Err(format!(
            "the backup is written as {who}, and that user may not write in {}: name a file in a folder it may use, such as {}, and copy it from there as root",
            dir.display(),
            state.join("center.bak").display()
        ));
    }
    if let Some(p) = pass_file
        && denied(p, Access::Read)
    {
        return Err(format!(
            "the passphrase file is read as {who}, and that user may not read {}: put it where that user may read it (private to it), or leave out --passphrase-file and type the passphrase",
            p.display()
        ));
    }
    Ok(())
}

enum Access {
    Read,
    Write,
}

/// Whether this process lacks the right to `how` at `path` (or to a folder
/// on the way). A path that is not there is not denied: what it is used for
/// says so.
fn denied(path: &Path, how: Access) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let mode = match how {
            Access::Read => libc::R_OK,
            Access::Write => libc::W_OK | libc::X_OK,
        };
        // SAFETY: a valid C string; access only reads it. All the ids are
        // the owner's after the switch, so the real ids access checks are
        // the ones the backup runs with.
        let r = unsafe { libc::access(c.as_ptr(), mode) };
        r != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, how);
        false
    }
}

/// Runs `nerve-center backup` or `nerve-center restore` on `state`.
/// `settle` is called before anything in the state folder is touched
/// ([`crate::service::settle_user`]: root works there as the folder's
/// owner) and says whether it switched to that owner. A restore reads the
/// backup and the passphrase before it, as the caller, so that they may be
/// where only root can read. A backup is written as the owner: what that
/// user may not reach is said first ([`as_owner_may_reach`]).
pub fn run(
    state: &Path,
    cmd: &crate::config::Cmd,
    settle: &dyn Fn(&Path) -> Result<bool, String>,
    out: &mut dyn Write,
) -> Result<(), String> {
    use crate::config::Cmd;
    match cmd {
        Cmd::Backup {
            file,
            overwrite,
            passphrase_file,
        } => {
            if settle(state)? {
                as_owner_may_reach(state, file, passphrase_file.as_deref())?;
            }
            let pass = nerve_node::prompt::passphrase(passphrase_file.as_deref(), out, true)?;
            let r = backup(state, file, &pass, *overwrite, backup::ITERATIONS)?;
            print_backup(&r, file, out);
        }
        Cmd::Restore {
            file,
            replace,
            passphrase_file,
        } => {
            let bytes = backup::read_file(file)?;
            let kind = backup::kind_of(&bytes)?;
            if kind != Kind::Center {
                return Err(format!(
                    "this is the backup of a {}, not of a center: restore it with `nerve-node restore`",
                    kind.word()
                ));
            }
            let pass = nerve_node::prompt::passphrase(passphrase_file.as_deref(), out, false)?;
            let parsed = open(&bytes, &pass)?;
            settle(state)?;
            let r = restore(state, &parsed, *replace)?;
            print_restore(&r, &parsed, out);
        }
        // `main` gives these to the service (crate::service::execute).
        Cmd::Install | Cmd::Update { .. } | Cmd::Uninstall { .. } => {
            return Err("install, update and uninstall are not backup commands".into());
        }
    }
    Ok(())
}

/// Says what a backup did.
pub fn print_backup(r: &BackupReport, file: &Path, out: &mut dyn Write) {
    let _ = writeln!(out, "backed up to {}", file.display());
    let _ = writeln!(
        out,
        "  the center {} ({}), pin {}, with {} paired {}",
        r.name,
        r.id,
        r.pin,
        r.nodes,
        if r.nodes == 1 { "node" } else { "nodes" }
    );
    let _ = writeln!(out, "  its certificate and private key, and its state");
    let _ = writeln!(
        out,
        "The file is encrypted with your passphrase. Keep both; nobody can recover the file without it."
    );
}

/// Says what a restore did and what comes next.
pub fn print_restore(r: &RestoreReport, b: &Parsed, out: &mut dyn Write) {
    let _ = writeln!(
        out,
        "restored the center {} ({}), pin {} (backup made by {})",
        b.name(),
        b.store.center_id,
        if r.pin.is_empty() {
            b.pin()
        } else {
            r.pin.clone()
        },
        b.program
    );
    for n in &r.notes {
        let _ = writeln!(out, "  {n}");
    }
    let _ = writeln!(
        out,
        "Start the center. The nodes that paired with it find it again by the same pin; if it now answers under another address, set --public-url and change `center.<name>.url` on each node (docs/user/backup.md)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NodeRecord;

    const PASS: &str = "correct horse battery";

    fn pass() -> Passphrase {
        Passphrase::new(PASS.into())
    }

    fn record(id: &str) -> NodeRecord {
        NodeRecord {
            id: id.into(),
            name: id.into(),
            public_key: "00".into(),
            old_key: None,
            key_rotations: 0,
            platform: "linux".into(),
            arch: "x86_64".into(),
            paired_ms: 1,
            disabled: false,
            last_seen_ms: 0,
            going_away: None,
            descriptor: None,
            catalog: Default::default(),
        }
    }

    /// `run` switches to the state folder's owner before a backup touches
    /// it, and in a restore only after it has read the backup and the
    /// passphrase as the caller, who may be root reading a file in its own
    /// home.
    #[test]
    fn run_settles_the_user_before_the_state_folder_and_after_reading_a_backup() {
        use crate::config::Cmd;
        use std::cell::RefCell;
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        center(&state, "c1");
        let pass_file = |name: &str, text: &str| {
            let p = d.path().join(name);
            nerve_transport::files::write_private(&p, text.as_bytes()).unwrap();
            p
        };
        let right = pass_file("pass", PASS);
        let wrong = pass_file("wrong", "not the passphrase at all");
        let settled = RefCell::new(Vec::new());
        let refuse = |s: &Path| {
            settled.borrow_mut().push(s.to_path_buf());
            Err::<bool, _>("settled".to_string())
        };
        let file = d.path().join("c.bak");
        let backup = |pass: &Path| Cmd::Backup {
            file: file.clone(),
            overwrite: false,
            passphrase_file: Some(pass.into()),
        };
        // A backup settles first: refused there, nothing is read or written.
        let e = run(&state, &backup(&right), &refuse, &mut Vec::new()).unwrap_err();
        assert_eq!(e, "settled");
        assert_eq!(*settled.borrow(), std::slice::from_ref(&state));
        assert!(!file.exists());
        // Switched to the owner, an error that the switch did not cause is
        // said as it is: a folder that is not there, and below a backup that
        // is there already and a short passphrase.
        let to = |file: &Path, pass: &Path| Cmd::Backup {
            file: file.into(),
            overwrite: false,
            passphrase_file: Some(pass.into()),
        };
        let advice = "name a file in a folder";
        let e = run(
            &state,
            &to(&d.path().join("no/such/c.bak"), &right),
            &|_| Ok(true),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.contains("does not exist") && !e.contains(advice), "{e}");
        run(&state, &backup(&right), &|_| Ok(false), &mut Vec::new()).unwrap();
        let e = run(&state, &backup(&right), &|_| Ok(true), &mut Vec::new()).unwrap_err();
        assert!(e.contains("exists already") && !e.contains(advice), "{e}");
        let short = pass_file("short", "short");
        let e = run(
            &state,
            &to(&d.path().join("s.bak"), &short),
            &|_| Ok(true),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.contains("at least") && !e.contains(advice), "{e}");
        let restore = |pass: &Path| Cmd::Restore {
            file: file.clone(),
            replace: false,
            passphrase_file: Some(pass.into()),
        };
        // A restore opens the backup before it settles.
        let e = run(&state, &restore(&wrong), &refuse, &mut Vec::new()).unwrap_err();
        assert!(e.contains("passphrase"), "{e}");
        assert_eq!(settled.borrow().len(), 1);
        let e = run(&state, &restore(&right), &refuse, &mut Vec::new()).unwrap_err();
        assert_eq!(e, "settled");
        assert_eq!(settled.borrow().len(), 2);
    }

    /// Root's backup runs as the state folder's owner. A backup folder that
    /// user may not write, or a passphrase file it may not read, is said
    /// with what to do; without the switch the error is the plain one. (Root
    /// reaches every file, so this needs another user.)
    #[cfg(unix)]
    #[test]
    fn a_backup_as_the_owner_says_what_that_owner_may_not_reach() {
        use crate::config::Cmd;
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        center(&state, "c1");
        let pass = d.path().join("pass");
        nerve_transport::files::write_private(&pass, PASS.as_bytes()).unwrap();
        let closed = d.path().join("closed");
        std::fs::create_dir(&closed).unwrap();
        let hidden = closed.join("pass");
        nerve_transport::files::write_private(&hidden, PASS.as_bytes()).unwrap();
        let read_only = d.path().join("read-only");
        std::fs::create_dir(&read_only).unwrap();
        let mode =
            |p: &Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        mode(&closed, 0o000);
        mode(&read_only, 0o500);
        let backup = |file: &Path, pass: &Path, switched: bool| {
            run(
                &state,
                &Cmd::Backup {
                    file: file.into(),
                    overwrite: false,
                    passphrase_file: Some(pass.into()),
                },
                &|_| Ok(switched),
                &mut Vec::new(),
            )
        };
        let folder = backup(&read_only.join("c.bak"), &pass, true);
        let pass_file = backup(&d.path().join("c.bak"), &hidden, true);
        let plain = backup(&d.path().join("c.bak"), &hidden, false);
        mode(&closed, 0o700);
        mode(&read_only, 0o700);
        let e = folder.unwrap_err();
        assert!(e.contains("may not write in"), "{e}");
        assert!(
            e.contains(&state.join("center.bak").display().to_string()),
            "{e}"
        );
        let e = pass_file.unwrap_err();
        assert!(
            e.contains("the passphrase file is read as the owner"),
            "{e}"
        );
        assert!(
            e.contains("type the passphrase") && !e.contains("name a file"),
            "{e}"
        );
        assert!(!d.path().join("c.bak").exists());
        let e = plain.unwrap_err();
        assert!(e.starts_with("cannot open") && !e.contains("owner"), "{e}");
    }

    /// A state folder of a center that has run: its identity, a paired node
    /// and a harness token.
    fn center(dir: &Path, id: &str) -> ServerIdentity {
        let identity = ServerIdentity::generate(&["center.example".into()]).unwrap();
        nerve_transport::files::write_private(
            &dir.join(IDENTITY_FILE),
            identity.to_pem().as_bytes(),
        )
        .unwrap();
        let mut s = Store::new(id.into(), format!("center-{id}"));
        s.nodes.insert("n1".into(), record("n1"));
        s.harness_tokens.push(store::TokenRecord {
            id: "t1".into(),
            label: "harness".into(),
            hash: "ab".repeat(32),
            created_ms: 1,
        });
        s.save(dir).unwrap();
        identity
    }

    fn backup_of(dir: &Path) -> (tempfile::TempDir, Parsed, BackupReport) {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("c.bak");
        let r = backup(dir, &file, &pass(), false, 4).unwrap();
        let parsed = open(&backup::read_file(&file).unwrap(), &pass()).unwrap();
        (d, parsed, r)
    }

    #[test]
    fn a_center_moves_with_its_pin_its_nodes_and_its_tokens() {
        let a = tempfile::tempdir().unwrap();
        let identity = center(a.path(), "c1");
        let (_f, parsed, report) = backup_of(a.path());
        assert_eq!((report.id.as_str(), report.nodes), ("c1", 1));
        assert_eq!(report.pin, identity.pin());

        let b = tempfile::tempdir().unwrap();
        let state = b.path().join("state");
        let r = restore(&state, &parsed, false).unwrap();
        assert!(r.notes.is_empty(), "{r:?}");
        // The same certificate, so the pin the nodes hold still fits.
        let back =
            ServerIdentity::from_pem(&std::fs::read_to_string(state.join("tls.pem")).unwrap())
                .unwrap();
        assert_eq!(back.pin(), identity.pin());
        let s = Store::load(&state).unwrap().unwrap();
        assert_eq!(
            (s.center_id.as_str(), s.nodes.len(), s.harness_tokens.len()),
            ("c1", 1, 1)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["tls.pem", "state.json"] {
                let mode = std::fs::metadata(state.join(f))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{f}");
            }
        }
    }

    #[test]
    fn the_backup_holds_no_key_in_the_clear() {
        let a = tempfile::tempdir().unwrap();
        let identity = center(a.path(), "c1");
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("c.bak");
        backup(a.path(), &file, &pass(), false, 4).unwrap();
        let bytes = std::fs::read(&file).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("PRIVATE KEY") && !text.contains(&identity.pin()));
        assert!(!text.contains("center-c1"));
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
    fn nothing_to_back_up_says_so() {
        let a = tempfile::tempdir().unwrap();
        let d = tempfile::tempdir().unwrap();
        let err = backup(a.path(), &d.path().join("c.bak"), &pass(), false, 4).unwrap_err();
        assert!(err.contains("no center has run"), "{err}");
        assert!(!d.path().join("c.bak").exists());
    }

    #[test]
    fn a_restore_never_goes_under_a_running_center() {
        let a = tempfile::tempdir().unwrap();
        center(a.path(), "c1");
        let (_f, parsed, _) = backup_of(a.path());
        let b = tempfile::tempdir().unwrap();
        center(b.path(), "c1");
        let before = std::fs::read(b.path().join("state.json")).unwrap();
        // A running center holds the lock.
        let lock = crate::attach::claim(b.path()).unwrap().unwrap();
        let err = restore(b.path(), &parsed, true).err().unwrap();
        assert!(err.contains("runs on"), "{err}");
        assert_eq!(std::fs::read(b.path().join("state.json")).unwrap(), before);
        drop(lock);
        restore(b.path(), &parsed, true).unwrap();
    }

    #[test]
    fn another_center_is_refused_unless_the_owner_says_so() {
        let a = tempfile::tempdir().unwrap();
        let theirs = center(a.path(), "c1");
        let (_f, parsed, _) = backup_of(a.path());

        let b = tempfile::tempdir().unwrap();
        let mine = center(b.path(), "c2");
        let before = std::fs::read(b.path().join("state.json")).unwrap();
        let err = restore(b.path(), &parsed, false).err().unwrap();
        assert!(
            err.contains("not the same center") && err.contains("c1") && err.contains("c2"),
            "{err}"
        );
        assert!(
            err.contains("--replace") && err.contains("pair again"),
            "{err}"
        );
        assert_eq!(std::fs::read(b.path().join("state.json")).unwrap(), before);
        let still = std::fs::read_to_string(b.path().join("tls.pem")).unwrap();
        assert_eq!(ServerIdentity::from_pem(&still).unwrap().pin(), mine.pin());

        let r = restore(b.path(), &parsed, true).unwrap();
        assert!(
            r.notes.iter().any(|n| n.contains("must pair again")),
            "{r:?}"
        );
        assert!(r.notes.iter().any(|n| n.contains(&mine.pin())), "{r:?}");
        let s = Store::load(b.path()).unwrap().unwrap();
        assert_eq!(s.center_id, "c1");
        let back = std::fs::read_to_string(b.path().join("tls.pem")).unwrap();
        assert_eq!(ServerIdentity::from_pem(&back).unwrap().pin(), theirs.pin());
    }

    #[test]
    fn the_same_center_comes_back_to_its_old_certificate() {
        // The certificate was deleted and the center made a new one, so its
        // nodes refuse it by the old pin. The restore puts the old one back.
        let a = tempfile::tempdir().unwrap();
        let old = center(a.path(), "c1");
        let (_f, parsed, _) = backup_of(a.path());
        let fresh = ServerIdentity::generate(&["center.example".into()]).unwrap();
        nerve_transport::files::write_private(&a.path().join("tls.pem"), fresh.to_pem().as_bytes())
            .unwrap();
        let r = restore(a.path(), &parsed, false).unwrap();
        let back = std::fs::read_to_string(a.path().join("tls.pem")).unwrap();
        assert_eq!(ServerIdentity::from_pem(&back).unwrap().pin(), old.pin());
        assert!(r.notes.iter().any(|n| n.contains(&fresh.pin())), "{r:?}");
    }

    #[test]
    fn state_here_that_cannot_be_read_needs_the_flag() {
        let a = tempfile::tempdir().unwrap();
        center(a.path(), "c1");
        let (_f, parsed, _) = backup_of(a.path());
        let b = tempfile::tempdir().unwrap();
        std::fs::write(b.path().join("state.json"), b"{ not json").unwrap();
        let err = restore(b.path(), &parsed, false).err().unwrap();
        assert!(
            err.contains("cannot be read") && err.contains("--replace"),
            "{err}"
        );
        restore(b.path(), &parsed, true).unwrap();
        assert!(Store::load(b.path()).unwrap().is_some());
    }

    #[test]
    fn a_failing_second_file_puts_the_first_back() {
        let a = tempfile::tempdir().unwrap();
        center(a.path(), "c1");
        let (_f, parsed, _) = backup_of(a.path());
        let b = tempfile::tempdir().unwrap();
        let mine = center(b.path(), "c1");
        // state.json cannot be replaced: a folder stands in its way.
        std::fs::remove_file(b.path().join("state.json")).unwrap();
        std::fs::create_dir(b.path().join("state.json")).unwrap();
        let err = restore(b.path(), &parsed, true).err().unwrap();
        assert!(
            err.contains("nothing was restored") && !err.contains("PRIVATE KEY"),
            "{err}"
        );
        let kept = std::fs::read_to_string(b.path().join("tls.pem")).unwrap();
        assert_eq!(ServerIdentity::from_pem(&kept).unwrap().pin(), mine.pin());
    }

    #[test]
    fn a_node_backup_is_not_a_center_backup_and_the_other_way_round() {
        let err = parse(Contents {
            kind: Kind::Node,
            created_ms: 1,
            program: "t".into(),
            files: BTreeMap::new(),
        })
        .err()
        .unwrap();
        assert!(
            err.contains("of a node, not of a center") && err.contains("nerve-node restore"),
            "{err}"
        );
    }

    #[test]
    fn a_backup_that_does_not_fit_itself_is_refused() {
        let a = tempfile::tempdir().unwrap();
        let identity = center(a.path(), "c1");
        let pem = identity.to_pem();
        let state = std::fs::read_to_string(a.path().join("state.json")).unwrap();
        let other = ServerIdentity::generate(&["x.example".into()]).unwrap();
        // The certificate of one center with the key of another.
        let cert_of_one = pem
            .split("-----BEGIN PRIVATE KEY-----")
            .next()
            .unwrap()
            .to_string();
        let key_of_other = format!(
            "-----BEGIN PRIVATE KEY-----{}",
            other
                .to_pem()
                .split("-----BEGIN PRIVATE KEY-----")
                .nth(1)
                .unwrap()
        );
        let mixed = format!("{cert_of_one}{key_of_other}");
        let make = |files: Vec<(&str, String)>| {
            parse(Contents {
                kind: Kind::Center,
                created_ms: 1,
                program: "t".into(),
                files: files.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            })
        };
        assert!(
            make(vec![
                ("tls.pem", pem.clone()),
                ("state.json", state.clone())
            ])
            .is_ok()
        );
        for (what, files, want) in [
            (
                "no key",
                vec![("state.json", state.clone())],
                "no certificate",
            ),
            ("no state", vec![("tls.pem", pem.clone())], "no state"),
            (
                "a bad pem",
                vec![("tls.pem", "junk".into()), ("state.json", state.clone())],
                "certificate and key",
            ),
            (
                "a key of another",
                vec![("tls.pem", mixed), ("state.json", state.clone())],
                "does not go with",
            ),
            (
                "a bad state",
                vec![("tls.pem", pem.clone()), ("state.json", "{".into())],
                "not valid",
            ),
            (
                "no id",
                vec![
                    ("tls.pem", pem.clone()),
                    ("state.json", r#"{"center_id":"","center_name":"x"}"#.into()),
                ],
                "no center id",
            ),
            (
                "a name nobody knows",
                vec![
                    ("tls.pem", pem.clone()),
                    ("state.json", state.clone()),
                    ("../x", "y".into()),
                ],
                "does not know",
            ),
        ] {
            let err = make(files)
                .err()
                .unwrap_or_else(|| panic!("{what} was taken"));
            assert!(err.contains(want), "{what}: {err}");
            assert!(!err.contains("PRIVATE KEY"), "{what}: {err}");
        }
    }

    #[test]
    fn a_wrong_passphrase_and_a_short_one_say_so_without_the_secret() {
        let a = tempfile::tempdir().unwrap();
        center(a.path(), "c1");
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("c.bak");
        let err = backup(
            a.path(),
            &file,
            &Passphrase::new("hunter2".into()),
            false,
            4,
        )
        .unwrap_err();
        assert!(
            err.contains("12 characters") && !err.contains("hunter2"),
            "{err}"
        );
        backup(a.path(), &file, &pass(), false, 4).unwrap();
        let err = open(
            &backup::read_file(&file).unwrap(),
            &Passphrase::new("wrong horse battery".into()),
        )
        .err()
        .unwrap();
        assert!(
            err.contains("passphrase is wrong") && !err.contains("wrong horse"),
            "{err}"
        );
    }
}
