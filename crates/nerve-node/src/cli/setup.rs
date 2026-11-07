//! `nerve-node setup`: its questions, for the link, the mode, a folder, the
//! network and the keyring, also asked once after `install`.

use super::*;

/// `setup`: [`setup`] with the keyring of the installed program and the
/// questions at a terminal.
pub(super) async fn setup_cmd(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    owner_check(&[&paths]).await?;
    let mut input = std::io::BufReader::new(std::io::stdin());
    // The installed program, which the node's user can run, asks
    // its keyring.
    let (machine, keyring) = keyring_of(&paths);
    // Asked whether to install a keyring as root only at a
    // terminal: the owner's own, for a setup the node runs for its
    // owner (crate::owner).
    let terminal = crate::owner::at_terminal();
    setup(&paths, machine, &keyring, &mut input, terminal, out).await
}

/// `setup`: the first-run steps in the terminal: the node's name, where it
/// keeps its keys, its first center, that center's mode and a folder. Each
/// answer is saved when it is given, through the same owner path as the
/// other commands (the running node, or the signed `node.toml`), so setup
/// can stop anywhere and run again; Enter keeps what is there. The steps
/// done are audited. `machine` is there on the installed node, which setup
/// restarts once a keyring it installed answers. Keys in the system keyring
/// need one that answers; `keyring` checks it, and installs one when the
/// owner says yes to it at a terminal (`terminal`, [`crate::keyring_setup`]).
pub async fn setup(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: &mut dyn BufRead,
    terminal: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let mut steps = Vec::new();
    let r = setup_steps(paths, machine, keyring, input, terminal, out, &mut steps).await;
    let log = AuditLog::new(paths.audit_log());
    if let Err(e) = log.node("setup", &steps, r.as_ref().err().map(String::as_str)) {
        let _ = writeln!(out, "the audit log cannot be written: {e}");
    }
    r
}

/// The service manager and the keyring program of the node at `paths`: the
/// installed program for the installed node on Linux, which the node's user
/// can run, else this one.
pub(super) fn keyring_of(
    paths: &NodePaths,
) -> (
    Option<&'static dyn crate::service::System>,
    crate::keyring_setup::HostKeyring,
) {
    let layout = Layout::system();
    let machine = (!cfg!(windows) && layout.installed() && *paths == layout.paths)
        .then_some(&Host as &dyn crate::service::System);
    let keyring = match machine {
        Some(_) => crate::keyring_setup::HostKeyring {
            exe: layout.bin.clone(),
        },
        None => crate::keyring_setup::HostKeyring::this_program(),
    };
    (machine, keyring)
}

/// `config set machine.secret_storage keyring` at a terminal (`input`):
/// where no keyring answers for the node's keys, offers to install one, and
/// a node that found none before is restarted once it answers. Nothing for
/// keys that are there already, or where they may not be (the installed
/// node on Windows, which `config set` refuses).
pub(super) async fn offer_keyring(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (now, _) = read_config(paths).await?;
    if now.machine.secret_storage == SecretStorage::Keyring
        || crate::secrets::no_keyring(paths).is_some()
    {
        return Ok(());
    }
    let me = crate::keyring_setup::me()?;
    crate::keyring_setup::ensure(keyring, &me, input, out)?;
    after_keyring_answers(paths, machine, out).await
}

/// Once the keyring answers setup, whether setup installed it or it came some
/// other way: a node that runs and found none before does not look again
/// (`keyring_failed` in its status, [`crate::secrets::store::failed`]), so it
/// would refuse the move. The installed node is restarted; a node run by hand
/// is left to its owner.
pub(super) async fn after_keyring_answers(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    out: &mut dyn Write,
) -> Result<(), String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(status) => {
            let for_owner = crate::owner::owner_running().is_some();
            return restart_for_keyring(&status, paths, machine, for_owner, out);
        }
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
        Err(e) => {
            let _ = writeln!(
                out,
                "the running node was not asked whether it found a keyring ({e}); restart it if it did not"
            );
            return Ok(());
        }
    }
    #[cfg(not(unix))]
    let _ = (paths, machine, out);
    Ok(())
}

/// What [`after_keyring_answers`] does with the running node's `status`;
/// `for_owner`: setup runs in the node, for its owner (crate::owner).
#[cfg_attr(not(unix), allow(dead_code))]
fn restart_for_keyring(
    status: &Value,
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    for_owner: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    if status["keyring_failed"] != true {
        return Ok(());
    }
    // Run by the node for its owner, setup would end with the node it runs
    // in.
    if for_owner {
        return Err("the system keyring answers now, but the node found none when it started and does not look again until it is restarted; `nerve-node service restart`, then run this again".into());
    }
    let Some(sys) = machine else {
        return Err("the system keyring answers now, but the node that runs for this folder found none before and does not look again until it is restarted; restart it, then run this again".into());
    };
    sys.systemctl(&["restart", crate::service::UNIT_NAME])?;
    sys.wait_running(paths)?;
    let _ = writeln!(
        out,
        "restarted the node, which had found no keyring before this one answered"
    );
    Ok(())
}

async fn setup_steps(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: &mut dyn BufRead,
    terminal: bool,
    out: &mut dyn Write,
    steps: &mut Vec<String>,
) -> Result<(), String> {
    // Keys in a keyring that does not answer: nothing can be read, so that
    // comes first, also where the keys may not stay there, so that they can go
    // into files below. The installed node on Windows asks none: the keyring
    // setup reaches is not the service's.
    let no_keyring = crate::secrets::no_keyring(paths);
    if crate::secrets::stated_storage(paths) == SecretStorage::Keyring
        && no_keyring != Some(crate::secrets::NoKeyring::WindowsService)
    {
        let me = crate::keyring_setup::me()?;
        crate::keyring_setup::ensure(keyring, &me, terminal.then_some(&mut *input), out)?;
        after_keyring_answers(paths, machine, out).await?;
    }
    // Where the keys may not be in the keyring (the installed node on
    // Windows), keys left there go into files.
    if let Some(n) = no_keyring
        && read_config(paths).await?.0.machine.secret_storage == SecretStorage::Keyring
    {
        let _ = writeln!(out, "Warning: {}.", n.why());
        edit(paths, |c| {
            c.machine.secret_storage = SecretStorage::File;
            Ok(())
        })
        .await?;
        let step = format!(
            "the node's keys are in {} now",
            storage_place(SecretStorage::File)
        );
        let _ = writeln!(out, "{step}");
        steps.push(step);
    }
    // The node's name and where its keys go keep their defaults: `config
    // set node.name` and `config set machine.secret_storage` change them.
    // The question that matters comes first.
    let _ = writeln!(out, "Set up this node. Enter keeps what is in [brackets].");
    let link = ask(
        input,
        out,
        "Pairing link from the center's web UI (Enter to skip): ",
    )?;
    let mut center = None;
    if !link.is_empty() {
        let link = PairLink::parse(&link)?;
        let _ = writeln!(out, "{}", crate::pair::preview(&link, None));
        if confirm(input, out)? {
            let e = crate::pair::pair(paths, &link, None).await?;
            let _ = writeln!(out, "paired with {} as {}", e.url, e.name);
            steps.push(format!("paired with {} as {}", e.url, e.name));
            tell_pairings_apart(paths, out).await;
            center = Some(e.name);
        } else {
            let _ = writeln!(out, "not paired");
        }
    }
    let center = match center {
        Some(c) => c,
        None => match read_config(paths).await?.0.centers.as_slice() {
            [one] => one.name.clone(),
            [] => {
                let _ = writeln!(
                    out,
                    "No center is paired; `nerve-node center add -` pairs one (paste the link)."
                );
                return Ok(());
            }
            _ => {
                let _ = writeln!(
                    out,
                    "Several centers are paired; `nerve-node mode <mode> --center <name>` sets the mode of each."
                );
                return Ok(());
            }
        },
    };

    let (cfg, _) = read_config(paths).await?;
    let entry = cfg
        .center(&center)
        .ok_or_else(|| no_center_named(&cfg, &center))?;
    let now = entry.policy.mode_at(crate::now_ms()).as_str().to_string();
    let mode = ask(
        input,
        out,
        &format!(
            "Mode for {center}: folder (writes and commands in the folders you give it, as nerve-run; reads also where every account may), allowlist (only what allow rules name) or user (all you may do, as you) [{now}]: "
        ),
    )?;
    let mode = if mode.is_empty() { now.clone() } else { mode };
    let which = CenterArg {
        center: Some(center.clone()),
    };
    if mode != now {
        set_mode(paths, &mode, None, false, &which, out).await?;
        steps.push(format!("{center}: mode {mode}"));
    }
    if mode == "folder" {
        let folder = ask(
            input,
            out,
            &format!("A folder {center} may use (Enter to skip): "),
        )?;
        // `~` is the home of whoever runs setup, also through sudo.
        let folder = typed_folder(&folder, &invoker_home());
        let folder = folder.display().to_string();
        if !folder.is_empty() {
            let rights = ask(
                input,
                out,
                "What it may do there: r reads, w writes, x runs commands, as one word like rx [rwx]: ",
            )?;
            // Folder mode runs a command only where it may run one, so
            // Enter gives a folder commands can work in.
            let rights = if rights.is_empty() {
                "rwx".to_string()
            } else {
                rights
            };
            add_folder(paths, Path::new(&folder), &rights, &which, out).await?;
            steps.push(format!("{center}: folder {folder} {rights}"));
        }
    }
    // The network switch: in user mode, and in allowlist mode as you, no
    // command runs while it is off, which is said before it is saved.
    let (cfg, _) = read_config(paths).await?;
    let policy = cfg.center(&center).expect("picked above").policy.clone();
    let now = if policy.no_network { "off" } else { "on" };
    let net = ask(
        input,
        out,
        &format!("Network for {center}'s commands: on or off [{now}]: "),
    )?;
    let net = if net.is_empty() { now.to_string() } else { net };
    if net != now {
        if net == "off" && policy.runs_as_owner(crate::now_ms()) {
            let _ = writeln!(
                out,
                "Warning: {center} is in {} mode, where its commands run as you: with the network off, none of them runs.",
                policy.mode_at(crate::now_ms()).as_str()
            );
        }
        set_network(paths, &net, &which, out).await?;
        steps.push(format!("{center}: network {net}"));
    }
    let _ = writeln!(
        out,
        "Done. `nerve-node status` shows the node and what to do next; `nerve-node --help` lists the commands."
    );
    Ok(())
}

/// What `install` runs at a terminal once the service runs: setup's
/// questions, as the person who ran sudo or pkexec, so that `~` is their
/// home and the answers go the way their own commands go (crate::owner).
/// Setup that does not finish leaves the install as it is, and says what
/// to run.
#[cfg(unix)]
pub(super) fn setup_after_install(layout: &Layout, invoker: &str, out: &mut dyn Write) {
    let _ = writeln!(
        out,
        "Now pair a first center and give it a folder; Enter skips a question."
    );
    let _ = out.flush();
    let ran = match crate::account::lookup(invoker) {
        Ok(Some(a)) => setup_run(&layout.bin, &a)
            .command()
            .status()
            .map_err(|e| format!("cannot start {}: {e}", layout.bin.display()))
            .and_then(|s| match s.success() {
                true => Ok(()),
                false => Err(format!("it ended with {s}")),
            }),
        Ok(None) => Err(format!("no account {invoker}")),
        Err(e) => Err(e),
    };
    if let Err(e) = ran {
        let _ = writeln!(
            out,
            "setup did not finish ({e}); `nerve-node setup` asks again.\n{}",
            crate::service::NEXT
        );
    }
}

/// How `install` starts setup: the installed program, as `account`, with
/// its home and names.
#[cfg(unix)]
#[derive(Debug, PartialEq)]
struct SetupRun {
    program: PathBuf,
    uid: u32,
    gid: u32,
    home: PathBuf,
    user: String,
}

#[cfg(unix)]
fn setup_run(bin: &Path, account: &crate::service::Account) -> SetupRun {
    SetupRun {
        program: bin.to_path_buf(),
        uid: account.uid,
        gid: account.gid,
        home: account.home.clone(),
        user: account.name.clone(),
    }
}

#[cfg(unix)]
impl SetupRun {
    fn command(&self) -> std::process::Command {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new(&self.program);
        c.arg("setup")
            .env("HOME", &self.home)
            .env("USER", &self.user)
            .env("LOGNAME", &self.user)
            .current_dir(&self.home);
        // Dropped from root to the account (std clears root's other
        // groups); root itself stays root.
        if self.uid != 0 {
            c.gid(self.gid).uid(self.uid);
        }
        c
    }
}

/// A folder as typed at setup's question: `~` and `~/…` are in `home`,
/// the rest as typed.
fn typed_folder(text: &str, home: &Path) -> PathBuf {
    match text.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with('/') => home.join(rest.trim_start_matches('/')),
        _ => PathBuf::from(text),
    }
}

/// The home of the person who runs this command: through sudo or pkexec
/// the home of the account that ran it, not root's; for the owner of the
/// installed node, whose commands the node runs as its own user, the
/// owner's, not the node's.
pub(crate) fn invoker_home() -> PathBuf {
    #[cfg(unix)]
    let root = nerve_transport::net::euid() == 0;
    #[cfg(not(unix))]
    let root = false;
    home_of_invoker(
        root,
        crate::owner::owner_running().is_some(),
        || {
            crate::account::lookup(&invoker())
                .ok()
                .flatten()
                .map(|a| a.home)
        },
        crate::paths::home_dir(),
    )
}

/// [`invoker_home`] with what it reads given: whether this runs as root,
/// whether the node runs it for its owner, the home of the account that ran
/// it, and `HOME`.
fn home_of_invoker(
    root: bool,
    for_owner: bool,
    account_home: impl FnOnce() -> Option<PathBuf>,
    home: PathBuf,
) -> PathBuf {
    match root || for_owner {
        true => account_home().unwrap_or(home),
        false => home,
    }
}

/// How setup names where the keys are.
fn storage_place(s: SecretStorage) -> &'static str {
    match s {
        SecretStorage::File => "files",
        SecretStorage::Keyring => "the system keyring",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{load, run, setup, setup_keyring, setup_with};
    use nerve_policy::config::Access;

    /// Setup's folder step gives a folder commands can work in where the
    /// owner presses Enter: `rwx`, as folder mode runs a command only where
    /// it may run one.
    #[test]
    fn setup_gives_a_folder_every_right_on_enter() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let (r, out) = setup_with(&paths, &format!("\nfolder\n{}\n\n\n", work.display()));
        r.unwrap();
        assert!(out.contains("[rwx]: "), "{out}");
        let folders = &load(&paths).centers[0].policy.folders;
        assert_eq!(folders.len(), 1, "{folders:?}");
        assert_eq!(folders[0].access, Access::parse("rwx").unwrap());
    }

    /// `config set machine.secret_storage keyring` offers a keyring only at
    /// a terminal: without one it is refused and installs nothing.
    #[test]
    fn the_keyring_is_offered_only_at_a_terminal() {
        let (_d, paths) = setup(&[]);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let mut out = Vec::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let e = rt
            .block_on(offer_keyring(&paths, None, &k, None, &mut out))
            .unwrap_err();
        assert!(
            e.contains("run in a terminal, offers to install one"),
            "{e}"
        );
        assert!(
            e.contains("config set machine.secret_storage keyring"),
            "{e}"
        );
        assert!(!String::from_utf8_lossy(&out).contains("Install it now?"));
        assert!(k.installed.borrow().is_empty());
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
    }

    /// Setup chooses no account: it has no flags, and asks for none.
    #[test]
    fn setup_chooses_no_account() {
        for flag in ["--create-user", "--account-only"] {
            assert!(Cli::try_parse_from(["nerve-node", "setup", flag, "bob"]).is_err());
        }
        let (_d, paths) = setup(&["home"]);
        let (r, out) = setup_with(&paths, "\nuser\n\n");
        r.unwrap();
        assert!(!out.contains("Account that commands"), "{out}");
    }

    fn node_audit(paths: &NodePaths) -> Vec<Value> {
        AuditLog::new(paths.audit_log())
            .read()
            .unwrap()
            .into_iter()
            .filter(|v| v["kind"] == "node")
            .collect()
    }

    /// Setup asks the link, the mode, a folder with its rights, and the
    /// network, in that order and nothing else; Enter keeps each, and every
    /// answer goes through the owner's path into the signed file and the
    /// audit log.
    #[test]
    fn setup_asks_link_mode_folder_and_network() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        // No new center (the one paired is the first), folder mode with one
        // folder, and no network.
        let answers = format!("\nfolder\n{}\nrx\noff\n", dir.display());
        let (r, out) = setup_with(&paths, &answers);
        r.unwrap();
        let link = out.find("Pairing link").unwrap();
        let mode = out.find("Mode for home").unwrap();
        let folder = out.find("A folder home may use").unwrap();
        let net = out
            .find("Network for home's commands: on or off [on]")
            .unwrap();
        assert!(link < mode && mode < folder && folder < net, "{out}");
        for gone in ["Name of this node", "Where the node keeps its keys"] {
            assert!(!out.contains(gone), "{gone}: {out}");
        }
        assert!(out.contains("home: mode folder"), "{out}");
        let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
        assert_eq!(cfg.node.name, None);
        let c = cfg.center("home").unwrap();
        assert_eq!(c.policy.mode, Mode::Folder);
        assert_eq!(c.policy.folders.len(), 1);
        assert_eq!(c.policy.folders[0].access.to_string(), "rx");
        assert!(c.policy.no_network);
        let a = node_audit(&paths);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "setup");
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 3, "{}", a[0]);
        // Again with Enter everywhere: nothing changes.
        let before = std::fs::read(paths.config_file()).unwrap();
        let (r, _) = setup_with(&paths, "\n\n\n\n");
        r.unwrap();
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        // A short input stops it, and the audit log says so.
        let (r, _) = setup_with(&paths, "");
        assert!(r.unwrap_err().contains("input ended"));
        let a = node_audit(&paths);
        assert!(
            a.last().unwrap()["error"]
                .as_str()
                .unwrap()
                .contains("input ended")
        );
        let shown = run(&paths, &["audit"]).unwrap();
        assert!(shown.contains("setup: home: mode folder"), "{shown}");
    }

    /// User mode with no network runs nothing: setup says so before it
    /// saves the switch.
    #[test]
    fn setup_warns_that_user_mode_without_network_runs_nothing() {
        let (_d, paths) = setup(&["home"]);
        let (r, out) = setup_with(&paths, "\nuser\noff\n");
        r.unwrap();
        let warned = out
            .find("Warning: home is in user mode, where its commands run as you: with the network off, none of them runs.")
            .unwrap_or_else(|| panic!("{out}"));
        let saved = out.find(NO_NETWORK_LINE).unwrap_or_else(|| panic!("{out}"));
        assert!(warned < saved, "{out}");
        assert!(load(&paths).centers[0].policy.no_network);
        // In folder mode nothing of the kind.
        let (_d, paths) = setup(&["home"]);
        let (r, out) = setup_with(&paths, "\nfolder\n\noff\n");
        r.unwrap();
        assert!(!out.contains("none of them runs"), "{out}");
    }

    /// `~` at setup's folder question is the home of whoever runs it, also
    /// through sudo, where root's own home is not meant; `install` starts
    /// setup as that person, with their home.
    #[test]
    fn the_home_of_setup_is_the_person_who_ran_it() {
        let home = Path::new("/home/alice");
        assert_eq!(typed_folder("~/proj", home), home.join("proj"));
        assert_eq!(typed_folder("~", home), home);
        assert_eq!(typed_folder("/srv/x", home), Path::new("/srv/x"));
        assert_eq!(typed_folder("~bob/x", home), Path::new("~bob/x"));
        let root = PathBuf::from("/root");
        let alice = || Some(PathBuf::from("/home/alice"));
        assert_eq!(home_of_invoker(true, false, alice, root.clone()), home);
        assert_eq!(home_of_invoker(false, false, alice, root.clone()), root);
        assert_eq!(home_of_invoker(true, false, || None, root.clone()), root);
        // The installed node runs setup for its owner as its own user, whose
        // HOME is the node's folder: `~` is the owner's home still.
        let node = PathBuf::from("/var/lib/nerve");
        assert_eq!(home_of_invoker(false, true, alice, node), home);
        #[cfg(unix)]
        {
            let account = crate::service::Account {
                name: "alice".into(),
                uid: 1000,
                gid: 1000,
                comment: String::new(),
                home: home.to_path_buf(),
                groups: vec![1000],
            };
            let run = setup_run(Path::new("/usr/local/bin/nerve-node"), &account);
            assert_eq!(
                run,
                SetupRun {
                    program: "/usr/local/bin/nerve-node".into(),
                    uid: 1000,
                    gid: 1000,
                    home: home.to_path_buf(),
                    user: "alice".into(),
                }
            );
            let c = run.command();
            let envs: Vec<_> = c.get_envs().collect();
            assert!(
                envs.contains(&(
                    std::ffi::OsStr::new("HOME"),
                    Some(std::ffi::OsStr::new("/home/alice"))
                )),
                "{envs:?}"
            );
            assert_eq!(c.get_args().collect::<Vec<_>>(), ["setup"]);
        }
    }

    /// A running node that found no keyring keeps that failure: after
    /// setup installed one, the installed node is restarted before the keys
    /// move, and the owner of a node run by hand is told to restart it. A
    /// node that never failed is left alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_node_that_found_no_keyring_is_restarted_after_one_is_installed() {
        let (_d, paths) = setup(&[]);
        let failed = json!({"version": 1, "keyring_failed": true});
        let sys = crate::service::tests::Fake::new();
        let mut out = Vec::new();
        restart_for_keyring(&failed, &paths, Some(&sys), false, &mut out).unwrap();
        assert!(
            sys.calls()
                .contains(&format!("systemctl restart {}", crate::service::UNIT_NAME)),
            "{:?}",
            sys.calls()
        );
        assert!(String::from_utf8_lossy(&out).contains("restarted the node"));
        let e = restart_for_keyring(&failed, &paths, None, false, &mut out).unwrap_err();
        assert!(e.contains("restart it, then run this again"), "{e}");
        let sys = crate::service::tests::Fake::new();
        let fine = json!({"version": 1, "keyring_failed": false});
        restart_for_keyring(&fine, &paths, Some(&sys), false, &mut out).unwrap();
        restart_for_keyring(&fine, &paths, None, false, &mut out).unwrap();
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        // Run by the node for its owner, setup does not restart the node it
        // runs in: it says how, and to run it again.
        let e = restart_for_keyring(&failed, &paths, Some(&sys), true, &mut out).unwrap_err();
        assert!(
            e.contains("`nerve-node service restart`, then run this again"),
            "{e}"
        );
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        restart_for_keyring(&fine, &paths, Some(&sys), true, &mut out).unwrap();
    }

    /// Setup restarts a node that found no keyring also when the keyring
    /// answers without setup installing it, e.g. installed by hand.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_node_that_found_no_keyring_is_restarted_when_one_answers() {
        let (d, paths) = setup(&[]);
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let node = {
            let (home, paths) = (d.path().to_path_buf(), paths.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                // This node asked a keyring that was not there yet, and
                // keeps that answer.
                crate::secrets::store::set_unreachable(true);
                assert!(crate::secrets::store::get("any").is_err());
                let mut opts = NodeOptions::new(paths);
                opts.home = home;
                opts.full_rights = Some(false);
                let daemon = rt.block_on(Daemon::start(opts)).unwrap();
                ready_tx.send(()).unwrap();
                rt.block_on(async {
                    while stop_rx.try_recv().is_err() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    daemon.stop().await;
                });
            })
        };
        ready.recv().unwrap();
        // The keyring answers `config set … keyring`: nothing to install.
        let k = crate::keyring_setup::tests::FakeKeyring::new(true);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let offer = |sys: Option<&dyn crate::service::System>| {
            let mut out = Vec::new();
            let mut input = std::io::Cursor::new(Vec::new());
            let r = rt.block_on(offer_keyring(&paths, sys, &k, Some(&mut input), &mut out));
            (r, String::from_utf8(out).unwrap())
        };
        let (r, _) = offer(None);
        let e = r.unwrap_err();
        assert!(e.contains("restart it, then run this again"), "{e}");
        assert!(k.installed.borrow().is_empty());
        let sys = crate::service::tests::Fake::new();
        let (r, out) = offer(Some(&sys));
        assert!(
            sys.calls()
                .contains(&format!("systemctl restart {}", crate::service::UNIT_NAME)),
            "{:?} {r:?} {out}",
            sys.calls()
        );
        stop.send(()).unwrap();
        node.join().unwrap();
    }

    /// A node whose keys are in a keyring that no longer answers: setup
    /// asks about that before anything else, and a no stops it.
    #[test]
    fn setup_on_keys_in_a_keyring_that_does_not_answer_asks_first() {
        let (_d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "machine.secret_storage", "keyring"],
        )
        .unwrap();
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_keyring(&paths, None, &k, "\n");
        assert!(r.unwrap_err().contains("no system keyring answers"));
        assert!(!out.contains("Pairing link"), "{out}");
        assert!(run(&paths, &["status"]).is_err());
        let (r, out) = setup_keyring(&paths, None, &k, "y\n\n\n\n");
        r.unwrap();
        assert!(out.contains("Pairing link"), "{out}");
        assert!(run(&paths, &["status"]).is_ok());
    }

    #[test]
    fn setup_without_a_center_stops_after_the_link() {
        let (_d, paths) = setup(&[]);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("No center is paired"), "{out}");
        let (_d, paths) = setup(&["a", "b"]);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("Several centers are paired"), "{out}");
        // A link that does not parse pairs nothing.
        let (r, _) = setup_with(&paths, "not a link\n");
        assert!(r.unwrap_err().contains("nerve://pair"));
    }
}
