//! The owner of the installed node and the owner's way in without root
//! (docs/user/service.md, "Who may change the node").
//!
//! The owner is the account that ran `install` (on Linux through sudo or
//! pkexec): the unit names it ([`OWNER_VAR`]), and only `install` writes
//! the unit. Root is always let in as well. On Windows the owners are the
//! SIDs in the service's registry value [`OWNERS_VALUE`].
//!
//! The running node serves an owner endpoint beside its control socket: on
//! Linux [`socket`] (open to everyone, in the unit's runtime folder), on
//! Windows the pipe [`pipe_name`] (open to the owners, SYSTEM and the
//! administrators). It takes one request, `cli {args, cwd}`: the node
//! checks the caller and the command, then runs its own program with those
//! arguments as its own user, as `sudo nerve-node …` runs after
//! [`crate::service::become_owner`], with the caller's input and output
//! passed through the connection and [`OWNER_ENV`] naming the caller for the
//! audit. So the commands keep every check of the CLI, and the CLI of the
//! owner sends its command there by itself ([`forward_if_needed`]).
//!
//! `backup` and `restore` come with their file, opened by the owner's own
//! program and handed over ([`send_file`]: the open file on Linux, its bytes
//! on Windows), so the node never opens a path in the owner's folders as
//! itself. A restore runs while the node is stopped, which then starts again
//! ([`crate::daemon::Daemon::run_until`]).
//!
//! Who is let in is decided by the account the kernel names for the caller:
//! a command the node runs as `nerve-run` is not the owner and is refused.
//! A command of `user` mode runs as the owner, and so is the owner, by the
//! owner's choice of mode; the checks of the caller's process (not below a
//! command of the node, no `no_new_privs`) catch the simple cases of such a
//! command changing the node, nothing more (docs/user/modes.md).

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use crate::cli::{Cli, Cmd, FolderCmd, SudoCmd};
use crate::paths::NodePaths;

/// The variable of the installed unit that names the owner's account
/// (Linux), which `install` writes ([`crate::service::Layout::unit_text`]).
pub const OWNER_VAR: &str = "NERVE_NODE_OWNER";

/// Set by the node for a command it runs for an owner: the owner's name,
/// for the audit ([`crate::cli`]'s invoker) and the settings that stay
/// root's ([`root_only_change`]).
pub const OWNER_ENV: &str = "NERVE_OWNER";

/// Set to `1` by the node for a command it runs for an owner whose own
/// input is a terminal's: the input the command gets is the connection's,
/// and only an owner at a terminal is asked what needs one (the keyring
/// that `setup` installs as root, crate::keyring_setup).
pub const TERMINAL_ENV: &str = "NERVE_OWNER_TERMINAL";

/// The installed unit's runtime folder (`RuntimeDirectory=`), where the
/// owner socket is.
pub const RUNTIME_DIR: &str = "/run/nerve-node";

/// The owner socket's file name in [`RUNTIME_DIR`].
pub const SOCKET_NAME: &str = "owner.sock";

/// The registry value under the service's key that lists the owners' SIDs
/// on Windows (`Parameters`, REG_MULTI_SZ). It goes with the service.
pub const OWNERS_VALUE: &str = "Owners";

/// The owner socket of the installed node on Linux.
pub fn socket() -> PathBuf {
    Path::new(RUNTIME_DIR).join(SOCKET_NAME)
}

/// The owner pipe of the installed node on Windows. Its name is fixed, not
/// made from the state folder as the control pipe's is: an owner who is no
/// administrator cannot open that folder to learn its real path. The node
/// makes it first, and the CLI talks to it only when the node's account
/// owns it.
pub fn pipe_name() -> String {
    r"\\.\pipe\nerve-node-owner".into()
}

/// The settings that decide which account and which programs a command
/// runs as. Through them an owner would get the rights of another account
/// or of root, so they stay root's: the node refuses them from an owner.
pub const ROOT_ONLY: [&str; 4] = [
    "machine.user",
    "machine.allow_root",
    "machine.sudo_path",
    "machine.shell",
];

/// The first of [`ROOT_ONLY`] that differs between `old` and `new`.
pub fn root_only_change(
    old: &nerve_policy::NodeConfig,
    new: &nerve_policy::NodeConfig,
) -> Option<&'static str> {
    let (o, n) = (&old.machine, &new.machine);
    [
        o.user != n.user,
        o.allow_root != n.allow_root,
        o.sudo_path != n.sudo_path,
        o.shell != n.shell,
    ]
    .iter()
    .position(|d| *d)
    .map(|i| ROOT_ONLY[i])
}

/// The owner a command runs for, when the node runs it for one.
pub fn owner_running() -> Option<String> {
    std::env::var(OWNER_ENV).ok().filter(|o| !o.is_empty())
}

/// Whether the one who runs this command is at a terminal: its own input,
/// or for a command the node runs for its owner, the owner's
/// ([`TERMINAL_ENV`]).
pub fn at_terminal() -> bool {
    use std::io::IsTerminal;
    told_terminal(
        owner_running().is_some(),
        std::env::var(TERMINAL_ENV).ok().as_deref(),
        std::io::stdin().is_terminal(),
    )
}

/// [`at_terminal`] from what it reads: whether the node runs this command
/// for its owner, the value of [`TERMINAL_ENV`], and whether this process's
/// own input is a terminal. For the owner only what the node was told
/// counts: its input is the connection's.
fn told_terminal(for_owner: bool, told: Option<&str>, stdin_is_terminal: bool) -> bool {
    if for_owner {
        return told == Some("1");
    }
    stdin_is_terminal
}

/// Whether [`forward_if_needed`] tells the node that the owner is at a
/// terminal: only where it passes this process's own input, and that input
/// is a terminal's. A text it passes is no person typing.
pub fn terminal_of(input: &Input, stdin_is_terminal: bool) -> bool {
    matches!(input, Input::Stdin) && stdin_is_terminal
}

/// Refuses a change of the settings that stay root's when this command runs
/// for an owner ([`OWNER_ENV`]).
pub fn check_change(
    old: &nerve_policy::NodeConfig,
    new: &nerve_policy::NodeConfig,
) -> Result<(), String> {
    if owner_running().is_none() {
        return Ok(());
    }
    match root_only_change(old, new) {
        Some(key) => Err(format!(
            "{key} decides which account or program commands run as, so only {} changes it: {}",
            admin(),
            with_rights("config set …")
        )),
        None => Ok(()),
    }
}

/// What the refusal of an owner's restore that would change a setting of
/// [`ROOT_ONLY`] says; the desktop app then asks for an administrator.
pub const RESTORE_BY_ADMIN: &str = "a backup that changes it is restored by";

/// Why an owner may not restore a backup that changes `key` of
/// [`ROOT_ONLY`].
pub fn restore_needs_admin(key: &str) -> String {
    format!(
        "the backup sets {key} other than it is here, and {key} decides which account or program commands run as: {RESTORE_BY_ADMIN} {}; {}",
        admin(),
        with_rights("restore …")
    )
}

/// Who may do what an owner may not.
fn admin() -> &'static str {
    if cfg!(windows) {
        "an administrator"
    } else {
        "root"
    }
}

/// How to run `command` with the rights it needs.
fn with_rights(command: &str) -> String {
    let program = crate::edition::get().program;
    if cfg!(windows) {
        format!("run `{program} {command}` in a terminal opened with \"Run as administrator\"")
    } else {
        format!("run `sudo {program} {command}`")
    }
}

/// Why the node does not run `cmd` for an owner, if it does not: what
/// changes the program, the service, the accounts or the machine settings
/// stays root's (or an administrator's).
pub fn refused(cmd: &Cmd) -> Option<String> {
    let (what, why) = match cmd {
        Cmd::Run => ("run", "it starts a node of its own"),
        Cmd::Install { .. } => ("install", "it installs the program and the service"),
        Cmd::Update { .. } => ("update", "it replaces the program"),
        Cmd::Uninstall { .. } => ("uninstall", "it removes the program and the service"),
        Cmd::Service(_) => (
            "service",
            "the service manager decides who may start and stop the service",
        ),
        // On Linux the node runs setup for its owner too: its one step that
        // needs root, installing a keyring for the node's user, takes root
        // by the service's own rights (crate::keyring_setup).
        Cmd::Setup if cfg!(windows) => (
            "setup",
            "it can install a system keyring and restart the service",
        ),
        Cmd::Sudo(SudoCmd::On) => (
            "sudo on",
            if cfg!(windows) {
                "it lets commands run with an administrator's rights"
            } else {
                "it lets commands run as root"
            },
        ),
        _ => return None,
    };
    Some(format!(
        "`{what}` needs {}: {why}; {}",
        admin(),
        with_rights(&format!("{what} …"))
    ))
}

/// Whether a program that runs `cmd` on the installed node needs an
/// administrator's rights, even for an owner: what the node refuses its
/// owners ([`refused`]), and a change of a setting of [`ROOT_ONLY`]. Starting
/// and stopping the service does not: the service manager lets the owners.
pub fn needs_admin(cmd: &Cmd) -> bool {
    use crate::cli::ConfigCmd;
    match cmd {
        Cmd::Service(_) => false,
        Cmd::Config(
            ConfigCmd::Set { key, .. }
            | ConfigCmd::Unset { key }
            | ConfigCmd::Add { key, .. }
            | ConfigCmd::Remove { key, .. },
        ) => ROOT_ONLY.contains(&key.as_str()),
        c => refused(c).is_some(),
    }
}

/// [`needs_admin`] for a command line without the program's name; one that
/// does not parse needs none (it does nothing).
pub fn args_need_admin(args: &[String]) -> bool {
    use clap::Parser;
    let argv = std::iter::once("nerve-node").chain(args.iter().map(String::as_str));
    Cli::try_parse_from(argv).is_ok_and(|cli| needs_admin(&cli.cmd))
}

/// The owner of the node on `paths`, as its unit names it in the running
/// service's environment ([`OWNER_VAR`]); `None` for a node run by hand,
/// which belongs to whoever runs it, and on Windows.
pub fn of_service(paths: &NodePaths) -> Option<String> {
    if cfg!(windows) || !crate::service::is_service_node(paths) {
        return None;
    }
    std::env::var(OWNER_VAR)
        .ok()
        .filter(|n| nerve_policy::config::valid_account_name(n))
}

/// Whether `owner`, the installed node's owner, is root (Linux), which
/// `install` makes it only after root confirmed it
/// (crate::service::RootOwner): what runs as the owner then runs as root.
pub fn is_root(owner: Option<&str>) -> bool {
    !cfg!(windows) && owner == Some(crate::service::ROOT)
}

/// What `status` and the app say of root as the owner.
pub const ROOT_OWNER_NOTE: &str = "root is the owner: commands of user mode, and of allowlist mode as the owner, run as root and can do everything on this machine, Nerve and its keys included";

/// Whether the account running this is the owner of the installed node: the
/// one its unit names on Linux, one of the service's owners on Windows.
pub fn is_owner_here() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: a plain getter.
        let me = unsafe { libc::getuid() };
        let owner = crate::service::owner_of(&crate::service::Layout::system().paths);
        owner.is_some_and(|o| crate::account::name_of(me).as_deref() == Some(o.as_str()))
    }
    #[cfg(windows)]
    {
        let me = crate::win_user::own_sid()
            .ok()
            .and_then(|s| crate::win_host::sid_text(&s).ok());
        me.is_some_and(|me| crate::win_host::owners().is_ok_and(|o| o.contains(&me)))
    }
    #[cfg(not(any(unix, windows)))]
    false
}

/// Whether the CLI sends `cli`'s command to the owner endpoint: the node is
/// installed, the command works on its folders, and this process may not
/// open them (neither root, an administrator, nor the node's own user).
fn wanted(cli: &Cli) -> bool {
    if cli.cmd.is_service() || matches!(cli.cmd, Cmd::Run) {
        return false;
    }
    let paths = NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
    let layout = crate::service::Layout::system();
    paths == layout.paths && crate::service::check_access(&paths).is_err()
}

/// Runs `cli`'s command through the owner endpoint when this process may not
/// open the installed node's folders ([`wanted`]): the exit code, or `None`
/// when the command runs here.
pub fn forward_if_needed(cli: &Cli) -> Option<i32> {
    if !wanted(cli) {
        return None;
    }
    let args = match forwarded_args(
        cli,
        std::env::args_os().skip(1),
        std::env::current_dir().ok(),
    ) {
        Ok(a) => a,
        Err(e) => return Some(fail(cli.json, &e)),
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return Some(fail(cli.json, &format!("cannot start the runtime: {e}"))),
    };
    let cwd = std::env::current_dir()
        .ok()
        .map(|d| d.display().to_string());
    let paths = NodePaths::from_args(None, None);
    if let Some(file) = FileJob::of(&cli.cmd, std::env::current_dir().ok()) {
        return Some(rt.block_on(forward_file(&paths, args, cwd, file, cli.json)));
    }
    let input = input_for(&cli.cmd);
    // The command is told whether the input it gets is a terminal's.
    let terminal = terminal_of(&input, std::io::IsTerminal::is_terminal(&std::io::stdin()));
    Some(rt.block_on(forward(&paths, args, cwd, input, terminal, cli.json)))
}

/// What this process passes to the node's command as its input.
#[derive(Clone)]
pub enum Input {
    None,
    /// This process's own, as it comes.
    Stdin,
    /// This text, then its end.
    Text(String),
}

/// The input [`forward_if_needed`] passes for `cmd`.
pub fn input_for(cmd: &Cmd) -> Input {
    if reads_input(cmd) {
        Input::Stdin
    } else {
        Input::None
    }
}

/// The backup file of an owner's `backup` or `restore`, which this
/// process opens itself and hands to the node with the request: the node
/// never opens a path in the owner's folders as itself. The passphrase is
/// asked here too, and goes to the node as the command's input.
pub struct FileJob {
    /// The file, made whole.
    pub path: PathBuf,
    /// `Some(overwrite)` for a backup, `None` for a restore.
    pub backup: Option<bool>,
    pub passphrase_file: Option<PathBuf>,
}

impl FileJob {
    /// The file job of `cmd`, with a relative path made whole with `cwd`.
    pub fn of(cmd: &Cmd, cwd: Option<PathBuf>) -> Option<FileJob> {
        let (file, backup, passphrase_file) = match cmd {
            Cmd::Backup {
                file,
                overwrite,
                passphrase_file,
                ..
            } => (file, Some(*overwrite), passphrase_file),
            Cmd::Restore {
                file,
                passphrase_file,
                ..
            } => (file, None, passphrase_file),
            _ => return None,
        };
        let whole = |p: &Path| match &cwd {
            Some(c) if p.is_relative() => c.join(p),
            _ => p.to_path_buf(),
        };
        Some(FileJob {
            path: whole(file),
            backup,
            passphrase_file: passphrase_file.as_deref().map(whole),
        })
    }
}

/// Whether `cmd` reads this process's input: the questions of `setup`, the
/// question of `center add` without `--yes`, and what `proxy set` takes
/// from stdin. Only then is the input passed to the node; for any other
/// command it stays unread, as a script that pipes lines into a loop of
/// commands expects.
pub fn reads_input(cmd: &Cmd) -> bool {
    use crate::cli::{CenterCmd, ProxyCmd};
    match cmd {
        Cmd::Setup => true,
        Cmd::Center(CenterCmd::Add { yes, .. }) => !yes,
        Cmd::Proxy(ProxyCmd::Set {
            password_stdin,
            headers_stdin,
            ..
        }) => *password_stdin || *headers_stdin,
        _ => false,
    }
}

/// Says `e` as `main` says an error; exit code 1.
fn fail(json: bool, e: &str) -> i32 {
    if json {
        let _ = writeln!(std::io::stdout(), "{}", json!({ "error": e }));
    }
    eprintln!("nerve-node: {e}");
    1
}

/// The arguments the node gets: those given, without `--config-dir` and
/// `--state-dir` (the node names its own folders), and a folder given by a
/// relative path made whole with `cwd`, as the node's program does not run
/// in this folder.
pub fn forwarded_args(
    cli: &Cli,
    given: impl IntoIterator<Item = std::ffi::OsString>,
    cwd: Option<PathBuf>,
) -> Result<Vec<String>, String> {
    let relative = match &cli.cmd {
        Cmd::Folder(
            FolderCmd::Add { path, .. } | FolderCmd::Set { path, .. } | FolderCmd::Rm { path, .. },
        ) if path.is_relative() => Some(path.clone()),
        // Only a name to the node, which never opens it, but the one it
        // says it wrote.
        Cmd::Backup { file, .. } | Cmd::Restore { file, .. } if file.is_relative() => {
            Some(file.clone())
        }
        _ => None,
    };
    // The passphrase comes from this process: the node may not read a file
    // of the owner's.
    let own_passphrase = FileJob::of(&cli.cmd, None).is_some();
    let mut out = Vec::new();
    let mut skip = false;
    let mut made_whole = false;
    for a in given {
        if std::mem::take(&mut skip) {
            continue;
        }
        let Some(s) = a.to_str() else {
            return Err(format!(
                "{} is not UTF-8, which the node's owner path takes only",
                a.to_string_lossy()
            ));
        };
        if s == "--config-dir" || s == "--state-dir" || (own_passphrase && s == "--passphrase-file")
        {
            skip = true;
            continue;
        }
        if s.starts_with("--config-dir=")
            || s.starts_with("--state-dir=")
            || (own_passphrase && s.starts_with("--passphrase-file="))
        {
            continue;
        }
        if let Some(r) = &relative
            && !made_whole
            && Path::new(s) == r
        {
            let cwd = cwd
                .as_ref()
                .ok_or("give the folder by its full path: this folder cannot be read")?;
            out.push(cwd.join(r).display().to_string());
            made_whole = true;
            continue;
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// What the CLI of someone who is no owner, or of an owner while the node
/// does not run, is told.
fn not_reached(e: &str) -> String {
    if e == nerve_transport::ctl::NOT_RUNNING {
        return format!(
            "the node is installed as a service and does not run; while it is stopped only {} changes it: start it with `{} service start`, or {}",
            admin(),
            crate::edition::get().program,
            with_rights("…")
        );
    }
    e.to_string()
}

/// Sends `args` to the owner endpoint of the node at `paths`, passes this
/// process's input to it and its output here; the command's exit code.
/// `terminal`: the input is a terminal's ([`TERMINAL_ENV`]).
async fn forward(
    paths: &NodePaths,
    args: Vec<String>,
    cwd: Option<String>,
    input: Input,
    terminal: bool,
    json: bool,
) -> i32 {
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let mut io = Io {
        out: &mut out,
        err: &mut err,
    };
    let r = match connect(paths).await {
        Ok(conn) => ask_once(conn, &args, cwd, input, terminal, &mut io).await,
        Err(e) => Err(not_reached(&e)),
    };
    r.unwrap_or_else(|e| fail(json, &e))
}

/// The owner's `args` on the owner socket `at`: the command's exit code, or
/// why it did not run. `terminal`: the input is a terminal's.
#[cfg(unix)]
pub async fn ask_at(
    at: &Path,
    args: &[String],
    cwd: Option<String>,
    input: Input,
    terminal: bool,
    io: &mut Io<'_>,
) -> Result<i32, String> {
    let conn = connect_at(at).await.map_err(|e| not_reached(&e))?;
    ask_once(conn, args, cwd, input, terminal, io).await
}

/// One request of [`forward`] on `conn`: the command's exit code, or why it
/// did not run.
async fn ask_once<S>(
    mut conn: S,
    args: &[String],
    cwd: Option<String>,
    input: Input,
    terminal: bool,
    io: &mut Io<'_>,
) -> Result<i32, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = request_line(args, cwd, false, terminal);
    {
        use tokio::io::AsyncWriteExt;
        conn.write_all(request.as_bytes())
            .await
            .map_err(|e| format!("cannot reach the node: {e}"))?;
    }
    session(conn, Vec::new(), input, None, io).await
}

/// The `cli` request for `args` in `cwd`, as its line; `streamed` says that
/// its file comes in the session ([`Handed::Streamed`]), `terminal` that
/// the input passed is a terminal's ([`TERMINAL_ENV`]).
pub fn request_line(
    args: &[String],
    cwd: Option<String>,
    streamed: bool,
    terminal: bool,
) -> String {
    let mut params = json!({"args": args, "cwd": cwd});
    if streamed {
        params["file"] = json!(STREAMED);
    }
    if terminal {
        params["terminal"] = json!(true);
    }
    let request = json!({"method": "cli", "params": params});
    format!("{request}\n")
}

/// Where a session's output goes: this process's own, or a test's.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// An owner's `backup` or `restore` through the node at `paths`: the file
/// opened here, as this user, handed over with the request, and the
/// passphrase asked here; a backup is put in place here once the node's
/// command made it.
async fn forward_file(
    paths: &NodePaths,
    args: Vec<String>,
    cwd: Option<String>,
    file: FileJob,
    json: bool,
) -> i32 {
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let mut io = Io {
        out: &mut out,
        err: &mut err,
    };
    let pass = crate::prompt::passphrase(
        file.passphrase_file.as_deref(),
        io.out,
        file.backup.is_some(),
    );
    let pass = match pass {
        Ok(p) => p,
        Err(e) => return fail(json, &e),
    };
    let conn = match connect(paths).await {
        Ok(c) => c,
        Err(e) => return fail(json, &not_reached(&e)),
    };
    send_file(conn, &args, cwd, &file, pass.text(), &mut io)
        .await
        .unwrap_or_else(|e| fail(json, &e))
}

/// The client's side of an owner's `backup` or `restore` on `conn`: `file`
/// opened as this process's user and handed to the node with the request
/// (Linux: the descriptor; Windows: its bytes in the session), `passphrase`
/// as the command's input, and a backup put in place once it is written.
/// The command's exit code.
#[cfg(unix)]
pub async fn send_file(
    mut conn: tokio::net::UnixStream,
    args: &[String],
    cwd: Option<String>,
    file: &FileJob,
    passphrase: &str,
    io: &mut Io<'_>,
) -> Result<i32, String> {
    use std::os::fd::AsFd;
    let opened = Opened::open(file)?;
    let request = request_line(args, cwd, false, false);
    let sent =
        nerve_transport::ctl::send_files(&mut conn, request.as_bytes(), &[opened.file.as_fd()])
            .await
            .map_err(|e| format!("cannot reach the node: {e}"));
    let code = match sent {
        Ok(()) => {
            session(
                conn,
                Vec::new(),
                Input::Text(format!("{passphrase}\n")),
                None,
                io,
            )
            .await
        }
        Err(e) => Err(e),
    };
    opened.finish(code)
}

/// [`send_file`] on Windows: the node's pipe carries the file's bytes.
#[cfg(windows)]
pub async fn send_file<S>(
    mut conn: S,
    args: &[String],
    cwd: Option<String>,
    file: &FileJob,
    passphrase: &str,
    io: &mut Io<'_>,
) -> Result<i32, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut first = Vec::new();
    match file.backup {
        None => {
            let bytes = nerve_transport::backup::read_file(&file.path)?;
            for chunk in bytes.chunks(FILE_CHUNK) {
                first.push(json!({ "file": B64.encode(chunk) }));
            }
            first.push(json!({"file_end": true}));
        }
        Some(overwrite) => can_write(&file.path, overwrite)?,
    }
    let request = request_line(args, cwd, true, false);
    conn.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("cannot reach the node: {e}"))?;
    let mut made = Vec::new();
    let back = file.backup.is_some().then_some(&mut made);
    let code = session(
        conn,
        first,
        Input::Text(format!("{passphrase}\n")),
        back,
        io,
    )
    .await?;
    if code == 0
        && let Some(overwrite) = file.backup
    {
        nerve_transport::backup::write_file(&file.path, &made, overwrite)?;
    }
    Ok(code)
}

/// Whether a backup may go to `path`: its folder is there, and without
/// `overwrite` no file is.
fn can_write(path: &Path, overwrite: bool) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        match std::fs::metadata(dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} is not a folder", dir.display())),
            Err(e) => return Err(format!("cannot use the folder {}: {e}", dir.display())),
        }
    }
    if !overwrite && std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "{} exists already; name another file or pass --overwrite",
            path.display()
        ));
    }
    Ok(())
}

/// The file of a [`FileJob`], opened by this process (Linux).
#[cfg(unix)]
struct Opened {
    file: std::fs::File,
    /// A backup's new file, and where it goes once complete: the same path
    /// (a new file), or the path it replaces (`--overwrite`).
    made: Option<(PathBuf, PathBuf)>,
}

#[cfg(unix)]
impl Opened {
    fn open(job: &FileJob) -> Result<Opened, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let name = job.path.display();
        let Some(overwrite) = job.backup else {
            let file =
                std::fs::File::open(&job.path).map_err(|e| format!("cannot open {name}: {e}"))?;
            let meta = file
                .metadata()
                .map_err(|e| format!("cannot read {name}: {e}"))?;
            if !meta.is_file() {
                return Err(format!("{name} is not a file"));
            }
            return Ok(Opened { file, made: None });
        };
        can_write(&job.path, overwrite)?;
        // With --overwrite through a new file beside it and a rename, so
        // the old backup stays whole until the new one is.
        let at = if overwrite {
            let dir = job.path.parent().unwrap_or(Path::new("."));
            let base = job
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            dir.join(format!(
                ".{base}.{}.tmp",
                nerve_transport::keys::random_token(8)
            ))
        } else {
            job.path.clone()
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&at)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!("{name} exists already; name another file or pass --overwrite")
                } else {
                    format!("cannot write {name}: {e}")
                }
            })?;
        Ok(Opened {
            file,
            made: Some((at, job.path.clone())),
        })
    }

    /// Puts a backup in place once the command wrote it, or takes away
    /// what this process made when it did not.
    fn finish(self, code: Result<i32, String>) -> Result<i32, String> {
        let Some((at, path)) = self.made else {
            return code;
        };
        drop(self.file);
        match code {
            Ok(0) if at == path => Ok(0),
            Ok(0) => std::fs::rename(&at, &path).map(|()| 0).map_err(|e| {
                let _ = std::fs::remove_file(&at);
                format!("cannot write {}: {e}", path.display())
            }),
            other => {
                let _ = std::fs::remove_file(&at);
                other
            }
        }
    }
}

/// The client's side of one `cli` request on `conn`, sent already: `before`
/// goes to the node right after its answer, then the input; the output goes
/// to `io`, and a streamed file the node gives back to `file`.
async fn session<S>(
    conn: S,
    before: Vec<Value>,
    input: Input,
    mut file: Option<&mut Vec<u8>>,
    io: &mut Io<'_>,
) -> Result<i32, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let (r, mut w) = tokio::io::split(conn);
    let mut lines = tokio::io::BufReader::new(r).lines();
    let first = lines
        .next_line()
        .await
        .map_err(|e| format!("cannot reach the node: {e}"))?
        .ok_or("the node closed without answering")?;
    let first: Value =
        serde_json::from_str(&first).map_err(|_| "the node closed without answering")?;
    if let Some(e) = first["error"].as_str() {
        return Err(e.to_string());
    }
    for v in before {
        w.write_all(format!("{v}\n").as_bytes())
            .await
            .map_err(|e| format!("cannot reach the node: {e}"))?;
    }
    // The input goes on its own thread: a read of a terminal blocks, and the
    // command may never ask for it.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(16);
    match input {
        Input::Stdin => {
            std::thread::spawn(move || read_input(std::io::stdin(), &tx));
        }
        Input::Text(text) => {
            let _ = tx.send(json!({ "in": text })).await;
            let _ = tx.send(json!({"eof": true})).await;
        }
        Input::None => {
            let _ = tx.send(json!({"eof": true})).await;
        }
    }
    let feeding = async move {
        while let Some(v) = rx.recv().await {
            let line = format!("{v}\n");
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
        // Kept open: the node ends the session.
        std::future::pending::<()>().await;
    };
    let reading = async {
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(s) = v["out"].as_str() {
                let _ = io.out.write_all(s.as_bytes());
                let _ = io.out.flush();
            } else if let Some(s) = v["err"].as_str() {
                let _ = io.err.write_all(s.as_bytes());
            } else if let Some(chunk) = v["file"].as_str() {
                let Some(file) = file.as_deref_mut() else {
                    continue;
                };
                let bytes = B64
                    .decode(chunk)
                    .map_err(|_| "the node sent the backup in another form".to_string())?;
                if file.len() + bytes.len() > FILE_MAX {
                    return Err("the node sent more than a backup holds".into());
                }
                file.extend_from_slice(&bytes);
            } else if let Some(code) = v["exit"].as_i64() {
                return Ok(code as i32);
            }
        }
        Err("the node ended the command before it said how it ended".to_string())
    };
    tokio::select! {
        r = reading => r,
        () = feeding => unreachable!("the input never ends the session"),
    }
}

/// Reads `input` until its end and sends it as `{"in": text}` lines, then
/// `{"eof": true}`.
fn read_input(mut input: impl std::io::Read, tx: &tokio::sync::mpsc::Sender<Value>) {
    let mut buf = [0u8; 8192];
    let mut pending = Vec::new();
    loop {
        match input.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = tx.blocking_send(json!({"eof": true}));
                return;
            }
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                let text = take_text(&mut pending);
                if !text.is_empty() && tx.blocking_send(json!({ "in": text })).is_err() {
                    return;
                }
            }
        }
    }
}

/// The text at the start of `pending`, taken out of it: all of it but a
/// character cut at its end, which waits for its next bytes. Bytes that are
/// no UTF-8 become U+FFFD.
pub fn take_text(pending: &mut Vec<u8>) -> String {
    let cut = match std::str::from_utf8(pending) {
        Ok(_) => pending.len(),
        // An incomplete character at the end (no error length) waits.
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => pending.len(),
    };
    let rest = pending.split_off(cut);
    let text = String::from_utf8_lossy(pending).into_owned();
    *pending = rest;
    text
}

/// The owner socket this process talks to: the installed node's, or the one
/// `NERVE_OWNER_SOCKET` names.
#[cfg(unix)]
pub fn socket_here() -> PathBuf {
    std::env::var_os("NERVE_OWNER_SOCKET").map_or_else(socket, PathBuf::from)
}

#[cfg(unix)]
async fn connect(_paths: &NodePaths) -> Result<tokio::net::UnixStream, String> {
    connect_at(&socket_here()).await
}

/// The owner socket at `at`, connected.
#[cfg(unix)]
async fn connect_at(at: &Path) -> Result<tokio::net::UnixStream, String> {
    tokio::net::UnixStream::connect(at)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                nerve_transport::ctl::NOT_RUNNING.to_string()
            }
            _ => format!("cannot reach the node at {}: {e}", at.display()),
        })
}

#[cfg(windows)]
async fn connect(
    paths: &NodePaths,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    win::connect(paths).await
}

#[cfg(not(any(unix, windows)))]
async fn connect(_paths: &NodePaths) -> Result<tokio::io::DuplexStream, String> {
    Err(nerve_transport::ctl::NOT_RUNNING.into())
}

/// Who is an owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owners {
    /// Linux: the account of this name, looked up at each request, and
    /// root.
    Named(String),
    /// These uids (a test's; root always is one on Linux).
    Uids(Vec<u32>),
    /// Windows: these SIDs, as text.
    Sids(Vec<String>),
}

/// Where the node takes its owners' commands, and who they are.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The socket (Linux) or the pipe's name (Windows).
    pub at: PathBuf,
    pub owners: Owners,
    /// The program the node runs for them: its own.
    pub program: PathBuf,
}

impl Endpoint {
    /// The provider socket beside the owner socket (Linux;
    /// crate::provider::serve).
    #[cfg(target_os = "linux")]
    pub fn provider_socket(&self) -> PathBuf {
        self.at.with_file_name(crate::provider::SOCKET_NAME)
    }

    /// The installed node's, when the node at `paths` is it: on Linux in the
    /// runtime folder systemd made for it (`RUNTIME_DIRECTORY`), for the
    /// owner the unit names ([`of_service`]), on Windows
    /// the pipe for the owners `install` wrote. `None` for a node run by
    /// hand, and on Windows when the service names no owner.
    pub fn of_service(paths: &NodePaths) -> Option<Endpoint> {
        if !crate::service::is_service_node(paths) {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            let dir = std::env::var_os("RUNTIME_DIRECTORY")?;
            // Several folders are separated by ':'; the unit names one.
            let dir = PathBuf::from(dir.to_string_lossy().split(':').next()?);
            // Without an owner only root is let in.
            Some(Endpoint {
                at: dir.join(SOCKET_NAME),
                owners: of_service(paths).map_or(Owners::Uids(Vec::new()), Owners::Named),
                program: "/proc/self/exe".into(),
            })
        }
        #[cfg(windows)]
        {
            let sids = crate::win_host::owners().ok()?;
            if sids.is_empty() {
                return None;
            }
            Some(Endpoint {
                at: pipe_name().into(),
                owners: Owners::Sids(sids),
                program: std::env::current_exe().ok()?,
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        None
    }
}

/// The owner pipe's DACL in SDDL (Windows): SYSTEM, the administrators, the
/// node's own account (`own`, which makes the pipe's further instances) and
/// the owners. No AppContainer gets in: no entry names a package.
pub fn dacl_text(own: &str, owners: &[String]) -> String {
    let mut s = crate::pipe::dacl_text(own);
    for o in owners {
        s.push_str(&format!("(A;;GA;;;{o})"));
    }
    s
}

/// Whether the process `pid` runs with `no_new_privs`, which every confined
/// command of the node keeps, whatever it starts or leaves.
#[cfg(target_os = "linux")]
fn keeps_no_new_privs(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|s| {
        s.lines().any(|l| {
            l.strip_prefix("NoNewPrivs:")
                .is_some_and(|v| v.trim() == "1")
        })
    })
}

/// Why the node refuses an owner request from a process of a center's
/// command.
pub(crate) const FROM_A_COMMAND: &str = "refused: this request comes from a command the node runs for a center, or a program it started";

/// The backup file that came with an owner's request: opened by the
/// owner's own program and handed over, so the node never opens a path in
/// the owner's folders as itself.
pub(crate) enum Handed {
    None,
    /// Linux: the open file, sent with the request (SCM_RIGHTS).
    #[cfg(unix)]
    File(std::os::fd::OwnedFd),
    /// Windows: its bytes come in the session, `{"file": base64}` lines and
    /// then `{"file_end": true}`, and a backup's go back the same way before
    /// the exit code. The request says `"file": "stream"`.
    #[cfg_attr(unix, allow(dead_code))]
    Streamed,
}

/// The `file` a request says for [`Handed::Streamed`].
pub const STREAMED: &str = "stream";

/// The largest backup a session carries, as `nerve_transport::backup`
/// reads.
const FILE_MAX: usize = nerve_transport::backup::MAX_FILE as usize;

/// The bytes of a streamed file per line: well within a line's limit once
/// in base64.
const FILE_CHUNK: usize = 256 * 1024;

/// One request on the owner endpoint from `who` (`None`: no owner):
/// `status` answers anyone that the node runs; `cli` runs a command for an
/// owner. `from_command` says whether the caller is a process of a center's
/// command, as far as the node can tell. `handed` is the file that came
/// with it.
pub(crate) async fn answer(
    shared: &std::sync::Arc<crate::daemon::Shared>,
    program: &Path,
    req: nerve_transport::ctl::CtlRequest,
    who: Option<String>,
    from_command: bool,
    handed: Handed,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    match req.method.as_str() {
        // Anyone may ask whether the node runs: `service restart` of an
        // owner, who cannot open the control socket, waits for it
        // (`service.rs` `wait_running`).
        "status" => Reply::Ok(json!({"running": true})),
        "cli" => {
            let Some(who) = who else {
                return Reply::Err(not_an_owner());
            };
            if from_command {
                return Reply::Err(FROM_A_COMMAND.into());
            }
            run_for(shared, program, &who, &req.params, handed).await
        }
        other => Reply::Err(format!("unknown method {other}")),
    }
}

/// What someone who is no owner is told.
fn not_an_owner() -> String {
    if cfg!(windows) {
        format!(
            "you are not an owner of the installed node: {}",
            with_rights("…")
        )
    } else {
        format!(
            "you are not the owner of the installed node, the account that ran `install`: {}",
            with_rights("…")
        )
    }
}

/// Whether `cmd` works on a backup file: `backup` and `restore`.
fn takes_a_file(cmd: &Cmd) -> bool {
    matches!(cmd, Cmd::Backup { .. } | Cmd::Restore { .. })
}

/// Runs the command `params` names (`args`, `cwd`) for the owner `who`: the
/// node's own program, as the node's user, on the node's folders. A
/// `restore` runs while the node is stopped, which then starts again
/// ([`crate::daemon::NodeOptions::aside`]).
async fn run_for(
    shared: &std::sync::Arc<crate::daemon::Shared>,
    program: &Path,
    who: &str,
    params: &Value,
    handed: Handed,
) -> nerve_transport::ctl::Reply {
    use clap::Parser;
    use nerve_transport::ctl::Reply;
    let Some(args) = params["args"].as_array().and_then(|a| {
        a.iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<String>>>()
    }) else {
        return Reply::Err("args is missing".into());
    };
    // Parsed as the program will: a command that stays root's is refused
    // here, before anything runs. One that does not parse runs, and the
    // program says what is wrong with it.
    let name = crate::edition::get().program;
    let (mut backup, mut restore) = (false, false);
    // A command that only reads: the app asks these every few seconds.
    let mut reads = false;
    let mut handed = handed;
    match Cli::try_parse_from(std::iter::once(name.to_string()).chain(args.clone())) {
        Ok(cli) => {
            reads = only_reads(&cli.cmd);
            if cli.config_dir.is_some() || cli.state_dir.is_some() {
                return Reply::Err("the node runs its commands on its own folders".into());
            }
            if let Some(why) = refused(&cli.cmd) {
                return Reply::Err(why);
            }
            if takes_a_file(&cli.cmd) && matches!(handed, Handed::None) {
                return Reply::Err(format!(
                    "the backup file comes with the request, opened by your own program: `{name}` does that"
                ));
            }
            if !takes_a_file(&cli.cmd) {
                handed = Handed::None;
            }
            backup = matches!(cli.cmd, Cmd::Backup { .. });
            restore = matches!(cli.cmd, Cmd::Restore { .. });
        }
        // Nothing to hand a file to.
        Err(_) => handed = Handed::None,
    }
    let aside = match (&shared.aside, restore) {
        (Some(a), true) => Some(a.clone()),
        (None, true) => {
            return Reply::Err(
                "this node cannot stop for a restore and start again by itself; stop it and restore as an administrator"
                    .into(),
            );
        }
        (_, false) => None,
    };
    // A change is the owner's to find in the log; the reads the app makes
    // all the time would only bury it, so they are detail.
    let line = format!("{who} runs `{name} {}` as an owner", words(&args));
    if reads {
        tracing::debug!("{line}");
    } else {
        tracing::info!("{line}");
    }
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Value>(64);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Value>(16);
    let job = command(Job {
        paths: shared.paths.clone(),
        program: program.to_path_buf(),
        who: who.to_string(),
        args,
        cwd: params["cwd"].as_str().map(PathBuf::from),
        terminal: params["terminal"] == true,
        handed,
        backup,
        out: out_tx,
        input: in_rx,
    });
    match aside {
        Some(aside) => {
            if aside.send(Box::pin(job)).is_err() {
                return Reply::Err("the node is stopping".into());
            }
        }
        None => {
            tokio::spawn(job);
        }
    }
    Reply::Session {
        ok: json!({}),
        out: out_rx,
        inbound: in_tx,
    }
}

/// Whether `cmd` only reads: it changes nothing of the node.
fn only_reads(cmd: &Cmd) -> bool {
    use crate::cli::{
        CapCmd, CenterCmd, ConfigCmd, ProviderCmd, ProxyCmd, RelayCmd, RuleCmd, ServiceCmd,
    };
    matches!(
        cmd,
        Cmd::Status
            | Cmd::Audit { clear: None, .. }
            | Cmd::Log { clear: None, .. }
            | Cmd::Center(CenterCmd::Ls)
            | Cmd::Folder(FolderCmd::Ls { .. })
            | Cmd::Rule(RuleCmd::Ls { .. })
            | Cmd::Cap(CapCmd::Ls { .. } | CapCmd::Provider(ProviderCmd::Ls))
            | Cmd::Config(ConfigCmd::Get { .. })
            | Cmd::Proxy(ProxyCmd::Ls)
            | Cmd::Relay(RelayCmd::Ls)
            | Cmd::Sudo(SudoCmd::Status)
            | Cmd::Service(ServiceCmd::Status)
    )
}

/// What the log says an owner ran: the command's words, and for `config`
/// the setting's name, never a value, which can be a secret (a proxy URL, a
/// pairing link).
fn words(args: &[String]) -> String {
    let words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let n = if words.first() == Some(&"config") {
        3
    } else {
        2
    };
    words[..words.len().min(n)].join(" ")
}

/// One command an owner asked for, with its session's ends.
struct Job {
    paths: NodePaths,
    program: PathBuf,
    who: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    /// The caller's input is a terminal's ([`TERMINAL_ENV`]).
    terminal: bool,
    handed: Handed,
    /// A backup, whose streamed file goes back to the caller.
    backup: bool,
    out: tokio::sync::mpsc::Sender<Value>,
    input: tokio::sync::mpsc::Receiver<Value>,
}

/// Runs `job`'s command and passes its output and input through, then its
/// exit code. A streamed file is taken in first (a restore's), or given back
/// before the exit code (a backup's).
async fn command(job: Job) {
    let Job {
        paths,
        program,
        who,
        args,
        cwd,
        terminal,
        handed,
        backup,
        out,
        mut input,
    } = job;
    let name = crate::edition::get().program;
    let failed = |e: String| {
        let out = out.clone();
        async move {
            let _ = out.send(json!({ "err": format!("{name}: {e}\n") })).await;
            let _ = out.send(json!({ "exit": 1 })).await;
        }
    };
    // The bytes of a streamed file go through a file of the node's own, in
    // its state folder, which only it may open.
    let carried = match &handed {
        Handed::Streamed => Some(paths.state_dir.join(format!(
            "owner-file.{}",
            nerve_transport::keys::random_token(8)
        ))),
        _ => None,
    };
    if let Some(at) = &carried
        && !backup
        && let Err(e) = take_streamed(&mut input, at).await
    {
        let _ = std::fs::remove_file(at);
        return failed(e).await;
    }
    let file_env = match (&handed, &carried) {
        #[cfg(unix)]
        (Handed::File(_), _) => Some(format!("fd:{HANDED_FD}")),
        (_, Some(at)) => Some(at.display().to_string()),
        _ => None,
    };
    let mut env: Vec<(&str, String)> = Vec::new();
    if let Some(v) = file_env {
        env.push((crate::caller_file::OWNER_FILE_ENV, v));
    }
    if terminal {
        env.push((TERMINAL_ENV, "1".into()));
    }
    #[cfg(unix)]
    let fd = match handed {
        Handed::File(f) => Some(f),
        _ => None,
    };
    #[cfg(not(unix))]
    let fd: Option<()> = None;
    let mut child = match spawn(&paths, &program, &who, &args, cwd.as_deref(), &env, fd) {
        Ok(c) => c,
        Err(e) => {
            if let Some(at) = &carried {
                let _ = std::fs::remove_file(at);
            }
            return failed(format!("cannot run {name}: {e}")).await;
        }
    };
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pumped = async {
        tokio::join!(
            pump(stdout, "out", out.clone()),
            pump(stderr, "err", out.clone())
        );
        child.wait().await
    };
    let fed = feed(input, stdin);
    tokio::pin!(fed);
    let status = tokio::select! {
        s = pumped => s,
        // The caller went: the command ends with it.
        () = &mut fed => {
            if let Some(at) = &carried {
                let _ = std::fs::remove_file(at);
            }
            return;
        }
    };
    let code = status.ok().and_then(|s| s.code()).unwrap_or(1);
    if let Some(at) = &carried {
        if backup && code == 0 {
            match std::fs::read(at) {
                Ok(bytes) => {
                    for chunk in bytes.chunks(FILE_CHUNK) {
                        let _ = out.send(json!({ "file": B64.encode(chunk) })).await;
                    }
                }
                Err(e) => {
                    let _ = std::fs::remove_file(at);
                    return failed(format!("the backup the command wrote: {e}")).await;
                }
            }
        }
        let _ = std::fs::remove_file(at);
    }
    let _ = out.send(json!({ "exit": code })).await;
}

/// The descriptor a handed file has in the program the node runs.
#[cfg(unix)]
const HANDED_FD: i32 = 3;

/// Takes a streamed file from the session into `at`: `{"file": base64}`
/// lines until `{"file_end": true}`.
async fn take_streamed(
    input: &mut tokio::sync::mpsc::Receiver<Value>,
    at: &Path,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    loop {
        let v = input
            .recv()
            .await
            .ok_or("the caller went before its file came")?;
        if v["file_end"] == true {
            break;
        }
        let chunk = v["file"]
            .as_str()
            .and_then(|c| B64.decode(c).ok())
            .ok_or("the file came in another form than the node takes")?;
        bytes.extend_from_slice(&chunk);
        if bytes.len() > FILE_MAX {
            return Err("the file is larger than a Nerve backup".into());
        }
    }
    nerve_transport::files::write_private(at, &bytes).map_err(|e| format!("{}: {e}", at.display()))
}

/// Starts the program for `who`: its output and input piped, ended when
/// dropped. The caller's folder is its working folder when the node may
/// enter it, else the root. A handed file is its descriptor
/// [`HANDED_FD`] (Linux), named in `env` by
/// [`crate::caller_file::OWNER_FILE_ENV`]; `env` also says whether the
/// caller is at a terminal ([`TERMINAL_ENV`]).
fn spawn<F: HandedFd>(
    paths: &NodePaths,
    program: &Path,
    who: &str,
    args: &[String],
    cwd: Option<&Path>,
    env: &[(&str, String)],
    fd: Option<F>,
) -> std::io::Result<tokio::process::Child> {
    let make = |dir: &Path| {
        let mut c = tokio::process::Command::new(program);
        c.arg("--config-dir")
            .arg(&paths.config_dir)
            .arg("--state-dir")
            .arg(&paths.state_dir)
            .args(args)
            .current_dir(dir)
            .env(OWNER_ENV, who)
            // Who asked is the owner, not whoever these name.
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .env_remove(crate::cli::DESKTOP_USER_SID)
            .env_remove("NERVE_CONFIG_DIR")
            .env_remove("NERVE_STATE_DIR")
            .env_remove(crate::caller_file::OWNER_FILE_ENV)
            .env_remove(TERMINAL_ENV)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Some(f) = &fd {
            f.give_to(&mut c);
        }
        #[cfg(windows)]
        c.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        c
    };
    let root = if cfg!(windows) {
        paths.state_dir.clone()
    } else {
        PathBuf::from("/")
    };
    match cwd.filter(|d| d.is_absolute()) {
        // A folder the node may not enter fails the start: then the root.
        Some(d) => make(d).spawn().or_else(|_| make(&root).spawn()),
        None => make(&root).spawn(),
    }
}

/// A file the program the node runs gets as a descriptor of its own.
trait HandedFd {
    fn give_to(&self, c: &mut tokio::process::Command);
}

#[cfg(not(unix))]
impl HandedFd for () {
    fn give_to(&self, _c: &mut tokio::process::Command) {}
}

#[cfg(unix)]
impl HandedFd for std::os::fd::OwnedFd {
    /// As [`HANDED_FD`], open in the program alone: the node's own copy
    /// keeps closing on exec.
    fn give_to(&self, c: &mut tokio::process::Command) {
        use std::os::fd::AsRawFd;
        let raw = self.as_raw_fd();
        // SAFETY: between fork and exec only async-signal-safe calls (dup2,
        // fcntl) on descriptors of this process.
        unsafe {
            c.pre_exec(move || {
                if raw == HANDED_FD {
                    let flags = libc::fcntl(raw, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(raw, HANDED_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// Sends what `from` gives as `{kind: text}` values until it ends.
async fn pump<R: tokio::io::AsyncRead + Unpin>(
    from: Option<R>,
    kind: &'static str,
    to: tokio::sync::mpsc::Sender<Value>,
) {
    use tokio::io::AsyncReadExt;
    let Some(mut from) = from else {
        return;
    };
    let mut buf = vec![0u8; 8192];
    let mut pending = Vec::new();
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                let text = take_text(&mut pending);
                if !text.is_empty() && to.send(json!({ kind: text })).await.is_err() {
                    return;
                }
            }
        }
    }
    if !pending.is_empty() {
        let _ = to
            .send(json!({ kind: String::from_utf8_lossy(&pending) }))
            .await;
    }
}

/// Passes the caller's `{"in": text}` to the program's input and closes it
/// at `{"eof": true}`; ends when the caller goes.
async fn feed(
    mut from: tokio::sync::mpsc::Receiver<Value>,
    mut stdin: Option<tokio::process::ChildStdin>,
) {
    use tokio::io::AsyncWriteExt;
    while let Some(v) = from.recv().await {
        if let Some(text) = v["in"].as_str() {
            if let Some(s) = stdin.as_mut()
                && s.write_all(text.as_bytes()).await.is_err()
            {
                stdin = None;
            }
        } else if v["eof"] == true {
            stdin = None;
        }
    }
}

/// Serves the owner endpoint of the node `shared` until the task is
/// aborted. On Linux the socket is open to everyone, in a folder everyone
/// may enter: who may run a command is decided by the account the kernel
/// names for the caller.
#[cfg(unix)]
pub(crate) async fn serve(
    shared: std::sync::Arc<crate::daemon::Shared>,
    endpoint: Endpoint,
) -> Result<tokio::task::JoinHandle<()>, String> {
    if tokio::net::UnixStream::connect(&endpoint.at).await.is_ok() {
        return Err(format!(
            "{} is in use: is the node running already?",
            endpoint.at.display()
        ));
    }
    let listener = nerve_transport::ctl::bind_open(&endpoint.at)
        .await
        .map_err(|e| format!("{}: {e}", endpoint.at.display()))?;
    let task = tokio::spawn(async move {
        let program = endpoint.program.clone();
        let owners = endpoint.owners.clone();
        let r = nerve_transport::ctl::serve_anyone(listener, move |req, peer, mut files| {
            let s = shared.clone();
            let program = program.clone();
            let owners = owners.clone();
            async move {
                // Asked only for a command: the lookup runs programs.
                let (who, from_command) = if req.method == "cli" {
                    (owner_name(&owners, peer.uid), from_a_command(&s, peer.pid))
                } else {
                    (None, false)
                };
                // One file at most; any other is closed.
                let handed = if files.is_empty() {
                    Handed::None
                } else {
                    Handed::File(files.swap_remove(0))
                };
                answer(&s, &program, req, who, from_command, handed).await
            }
        })
        .await;
        if let Err(e) = r {
            tracing::error!("the owner socket stopped: {e}");
        }
    });
    Ok(task)
}

/// The owner's name when the account `uid` is one.
#[cfg(unix)]
pub(crate) fn owner_name(owners: &Owners, uid: u32) -> Option<String> {
    let owner = match owners {
        Owners::Named(n) => {
            uid == 0
                || crate::account::lookup(n)
                    .ok()
                    .flatten()
                    .is_some_and(|a| a.uid == uid)
        }
        Owners::Uids(u) => uid == 0 || u.contains(&uid),
        Owners::Sids(_) => false,
    };
    owner.then(|| crate::account::name_of(uid).unwrap_or_else(|| format!("uid {uid}")))
}

/// Whether the caller `pid` is a process of a center's command: below one
/// the node runs, or with `no_new_privs`, which a confined command keeps
/// wherever its processes go. An unknown caller is one. Only a guard
/// against mistakes: `pid` is the process that connected, which may have
/// ended before the request came on its connection.
#[cfg(unix)]
pub(crate) fn from_a_command(shared: &crate::daemon::Shared, pid: Option<u32>) -> bool {
    let Some(pid) = pid else {
        return true;
    };
    #[cfg(target_os = "linux")]
    if keeps_no_new_privs(pid) {
        return true;
    }
    shared.below_command(Some(pid))
}

/// [`from_a_command`] with its reason, for a program that asks to attach as
/// a provider: one that runs with `no_new_privs` but below no command of the
/// node is told so, since the owner may start a program of theirs that way
/// (a unit's `NoNewPrivileges=`, a sandbox) and must know why it is refused.
#[cfg(unix)]
pub(crate) fn command_refusal(
    shared: &crate::daemon::Shared,
    pid: Option<u32>,
) -> Option<&'static str> {
    let Some(pid) = pid else {
        return Some(FROM_A_COMMAND);
    };
    if shared.below_command(Some(pid)) {
        return Some(FROM_A_COMMAND);
    }
    #[cfg(target_os = "linux")]
    if keeps_no_new_privs(pid) {
        return Some(NO_NEW_PRIVS);
    }
    None
}

/// Why the node refuses a program that runs with `no_new_privs` and below
/// none of its commands.
#[cfg(target_os = "linux")]
pub(crate) const NO_NEW_PRIVS: &str = "refused: this program runs with no_new_privs, as every command the node runs for a center does, so the node cannot tell it from one; start it without no_new_privs (no NoNewPrivileges= in its unit, no sandbox that sets it)";

#[cfg(windows)]
pub(crate) use win::serve;

#[cfg(windows)]
mod win {
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    use super::{Endpoint, NodePaths, Owners, answer, not_an_owner, pipe_name};
    use crate::pipe::{Descriptor, client_pid, instance};

    /// The SID of the client of the connected `pipe`, read at
    /// identification level after its request was read.
    fn client_sid(pipe: HANDLE) -> Option<String> {
        // SAFETY: a connected pipe the server read from; the thread's
        // token is opened while impersonating, then reverted at once.
        unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                return None;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
            RevertToSelf();
            if opened == 0 {
                return None;
            }
            let mut buf = vec![0u8; 256];
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut len,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let user = &*buf.as_ptr().cast::<TOKEN_USER>();
            let len = windows_sys::Win32::Security::GetLengthSid(user.User.Sid) as usize;
            let sid = std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), len).to_vec();
            crate::win_host::sid_text(&sid).ok()
        }
    }

    /// Who is on the other end of an owner connection.
    #[derive(Clone, Copy)]
    struct Caller {
        pid: Option<u32>,
        pipe: usize,
    }

    /// Serves the owner pipe until the task is aborted; the first instance
    /// is made before this returns.
    pub(crate) async fn serve(
        shared: Arc<crate::daemon::Shared>,
        endpoint: Endpoint,
    ) -> Result<tokio::task::JoinHandle<()>, String> {
        let Owners::Sids(owners) = endpoint.owners.clone() else {
            return Err("the owner pipe takes owners by SID".into());
        };
        let name = endpoint.at.display().to_string();
        let own = crate::win_user::own_sid()
            .map_err(|e| e.to_string())
            .and_then(|s| crate::win_host::sid_text(&s))
            .map_err(|e| format!("the owner pipe: cannot read this account's SID: {e}"))?;
        let sd = Descriptor::from_sddl(&super::dacl_text(&own, &owners))
            .map_err(|e| format!("the owner pipe: cannot make its DACL: {e}"))?;
        let first =
            instance(&name, &sd, true).map_err(|e| format!("the owner pipe {name}: {e}"))?;
        Ok(tokio::spawn(accept(shared, endpoint, owners, sd, first)))
    }

    async fn accept(
        shared: Arc<crate::daemon::Shared>,
        endpoint: Endpoint,
        owners: Vec<String>,
        sd: Descriptor,
        mut listening: NamedPipeServer,
    ) {
        let name = endpoint.at.display().to_string();
        let places = Arc::new(tokio::sync::Semaphore::new(
            nerve_transport::ctl::MAX_CONNECTIONS,
        ));
        loop {
            if listening.connect().await.is_err() {
                let _ = listening.disconnect();
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let next = loop {
                match instance(&name, &sd, false) {
                    Ok(n) => break n,
                    Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            };
            let conn = std::mem::replace(&mut listening, next);
            let Ok(place) = places.clone().try_acquire_owned() else {
                continue;
            };
            let caller = Caller {
                pid: client_pid(&conn),
                pipe: conn.as_raw_handle() as usize,
            };
            let s = shared.clone();
            let program = endpoint.program.clone();
            let owners = owners.clone();
            tokio::spawn(async move {
                let _place = place;
                let handler = Arc::new(move |req: nerve_transport::ctl::CtlRequest, c: Caller| {
                    let s = s.clone();
                    let program = program.clone();
                    let owners = owners.clone();
                    async move {
                        let (who, from_command) = if req.method == "cli" {
                            // The pipe lives while its request is answered.
                            let sid = client_sid(c.pipe as HANDLE);
                            let who = sid
                                .filter(|s| owners.contains(s) || is_admin_sid(s))
                                .map(|s| crate::win_user::name_of_sid(&s).unwrap_or(s));
                            (who, crate::win::from_a_command(c.pid))
                        } else {
                            (None, false)
                        };
                        let handed = if req.params["file"] == super::STREAMED {
                            super::Handed::Streamed
                        } else {
                            super::Handed::None
                        };
                        answer(&s, &program, req, who, from_command, handed).await
                    }
                });
                let _ = nerve_transport::ctl::serve_stream(conn, caller, handler).await;
            });
        }
    }

    /// SYSTEM, whom the DACL lets in besides the owners and the
    /// administrators; an administrator's own SID is not known by itself
    /// here, so an elevated administrator who is no owner is refused as one.
    fn is_admin_sid(sid: &str) -> bool {
        sid == "S-1-5-18"
    }

    /// Opens the owner pipe of the node at `paths`, for identification only,
    /// and only when the node's account (or SYSTEM, the administrators) owns
    /// it.
    pub(super) async fn connect(paths: &NodePaths) -> Result<NamedPipeClient, String> {
        let name = pipe_name();
        let mut busy = 0;
        let client = loop {
            match ClientOptions::new()
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&name)
            {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(nerve_transport::ctl::NOT_RUNNING.into());
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && busy < 50 => {
                    busy += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    return Err(not_an_owner());
                }
                Err(e) => return Err(format!("cannot reach the running node: {e}")),
            }
        };
        crate::pipe::check_owner(paths, &client, &name)?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    /// The owner's program tells the node of a terminal only for its own
    /// input at one; a command run for the owner believes only that (#142).
    #[test]
    fn the_terminal_signal_holds_at_both_ends() {
        use super::{Input, terminal_of, told_terminal};
        assert!(terminal_of(&Input::Stdin, true));
        assert!(!terminal_of(&Input::Stdin, false));
        assert!(!terminal_of(&Input::None, true));
        assert!(!terminal_of(&Input::Text("y\n".into()), true));
        // For the owner: what the node was told, never its own input, which
        // is the connection's.
        for stdin in [true, false] {
            assert!(!told_terminal(true, None, stdin), "unset");
            assert!(!told_terminal(true, Some("0"), stdin), "0");
            assert!(!told_terminal(true, Some(""), stdin), "empty");
            assert!(told_terminal(true, Some("1"), stdin), "1");
            // Not for an owner: its own input, whatever the variable says.
            assert_eq!(told_terminal(false, Some("1"), stdin), stdin);
            assert_eq!(told_terminal(false, None, stdin), stdin);
        }
    }

    /// [`super::at_terminal`] reads the node's variables: run again in a
    /// process of its own with them set, and its input not a terminal.
    #[test]
    fn at_terminal_reads_what_the_node_told_it() {
        const NAME: &str = "owner::tests::at_terminal_reads_what_the_node_told_it";
        if std::env::var_os("NERVE_TEST_AT_TERMINAL").is_some() {
            println!("at_terminal={}", super::at_terminal());
            return;
        }
        let ask = |owner: Option<&str>, told: Option<&str>| {
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env("NERVE_TEST_AT_TERMINAL", "1")
                .env_remove(super::OWNER_ENV)
                .env_remove(super::TERMINAL_ENV)
                .stdin(std::process::Stdio::null());
            if let Some(o) = owner {
                c.env(super::OWNER_ENV, o);
            }
            if let Some(t) = told {
                c.env(super::TERMINAL_ENV, t);
            }
            let o = c.output().unwrap();
            let out = String::from_utf8_lossy(&o.stdout).into_owned();
            assert!(o.status.success(), "{out}");
            if out.contains("at_terminal=true") {
                true
            } else {
                assert!(out.contains("at_terminal=false"), "{out}");
                false
            }
        };
        assert!(!ask(Some("alice"), None), "unset");
        assert!(!ask(Some("alice"), Some("0")), "0");
        assert!(ask(Some("alice"), Some("1")), "1");
        // Not run for an owner: its own input, here none.
        assert!(!ask(None, Some("1")));
    }

    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("nerve-node").chain(args.iter().copied())).unwrap()
    }

    /// The app reads the node every few seconds: those reads are no lines
    /// at info, while every change is, with its words and no value.
    #[test]
    fn reads_are_told_apart_from_changes_for_the_log() {
        for args in [
            &["status"][..],
            &["audit", "--last", "200"],
            &["log", "--problems"],
            &["center", "ls"],
            &["rule", "ls", "--center", "home"],
            &["config", "get", "log.level"],
            &["relay", "ls"],
            &["service", "status"],
        ] {
            assert!(only_reads(&cli(args).cmd), "{args:?}");
        }
        for args in [
            &["config", "set", "log.level", "debug"][..],
            &["rule", "add", "allow", "git status"],
            &["center", "pause", "--center", "home"],
            &["panic"],
            &["log", "clear"],
            &["audit", "clear"],
        ] {
            assert!(!only_reads(&cli(args).cmd), "{args:?}");
        }
        let w = |a: &[&str]| words(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            w(&["config", "set", "log.level", "debug"]),
            "config set log.level"
        );
        assert_eq!(
            w(&["proxy", "set", "https://n:secret@relay:7490", "--pin", "x"]),
            "proxy set"
        );
        assert_eq!(w(&["--json", "status"]), "status");
    }

    /// What changes the program, the service, the accounts or the machine
    /// settings is refused; settings, pairing and rules are not.
    #[test]
    fn the_commands_that_stay_roots_are_refused() {
        for args in [
            &["run"][..],
            &["install"],
            &["update"],
            &["uninstall", "--purge"],
            &["service", "restart"],
            &["sudo", "on"],
        ] {
            assert!(refused(&cli(args).cmd).is_some(), "{args:?}");
        }
        // Setup's one step that needs root takes it on Linux by the node's
        // own rights.
        assert_eq!(refused(&cli(&["setup"]).cmd).is_some(), cfg!(windows));
        for args in [
            &["status"][..],
            &["center", "ls"],
            &["center", "add", "nerve://pair?x", "--yes"],
            &["rule", "add", "allow", "ls"],
            &["mode", "set", "folder"],
            &["config", "set", "log.level", "debug"],
            &["sudo", "off"],
            &["sudo", "status"],
            &["audit", "--last", "5"],
            &["log", "--follow"],
            &["panic"],
            &["unlock"],
            &["proxy", "rm"],
            // With the file the owner's program hands over (item 14).
            &["backup", "/tmp/b"],
            &["restore", "/tmp/b"],
        ] {
            assert_eq!(refused(&cli(args).cmd), None, "{args:?}");
        }
    }

    /// A program asks for an administrator for what the node refuses its
    /// owners and for the settings that stay root's, not for the service.
    #[test]
    fn what_needs_an_administrator() {
        for args in [
            &["sudo", "on"][..],
            &["update"],
            &["uninstall"],
            &["config", "set", "machine.user", "bob"],
            &["config", "unset", "machine.shell"],
        ] {
            assert!(needs_admin(&cli(args).cmd), "{args:?}");
        }
        for args in [
            &["service", "restart"][..],
            &["service", "status"],
            &["config", "set", "log.level", "debug"],
            &["rule", "add", "deny", "rm"],
            &["sudo", "off"],
            &["backup", "/tmp/b", "--overwrite"],
            &["restore", "/tmp/b"],
        ] {
            assert!(!needs_admin(&cli(args).cmd), "{args:?}");
        }
    }

    /// The settings that pick the account and the programs of the commands
    /// are root's; the others are not.
    #[test]
    fn the_settings_that_pick_the_account_are_roots() {
        let old = nerve_policy::NodeConfig::default();
        let changed = |f: &dyn Fn(&mut nerve_policy::NodeConfig)| {
            let mut new = old.clone();
            f(&mut new);
            root_only_change(&old, &new)
        };
        assert_eq!(
            changed(&|c| c.machine.user = Some("bob".into())),
            Some("machine.user")
        );
        assert_eq!(
            changed(&|c| c.machine.allow_root = !c.machine.allow_root),
            Some("machine.allow_root")
        );
        assert_eq!(
            changed(&|c| c.machine.sudo_path = Some("/tmp/sudo".into())),
            Some("machine.sudo_path")
        );
        assert_eq!(
            changed(&|c| c.machine.shell = Some("/tmp/sh".into())),
            Some("machine.shell")
        );
        assert_eq!(changed(&|c| c.locked = true), None);
    }

    /// The folders' flags go (the node gives its own), and a relative folder
    /// is made whole with the caller's folder, once.
    #[test]
    fn forwarded_arguments_name_no_folders_of_the_callers() {
        let os = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        // A whole path of this platform: `C:\home\a` on Windows.
        let abs = |p: &str| {
            if cfg!(windows) {
                format!("C:{}", p.replace('/', "\\"))
            } else {
                p.to_string()
            }
        };
        let home = PathBuf::from(abs("/home/a"));
        let given = ["--config-dir", "/etc/nerve", "--json", "status"];
        let c = cli(&given);
        assert_eq!(
            forwarded_args(&c, os(&given), None).unwrap(),
            ["--json", "status"]
        );
        let given = [
            "--state-dir=/var/lib/nerve/state",
            "folder",
            "add",
            "src",
            "+r",
        ];
        let c = cli(&given);
        let whole = home.join("src");
        assert_eq!(
            forwarded_args(&c, os(&given), Some(home.clone())).unwrap(),
            ["folder", "add", &*whole.to_string_lossy(), "+r"]
        );
        // Without a folder to make it whole, it is refused.
        assert!(forwarded_args(&c, os(&given), None).is_err());
        // A whole one goes as it is.
        let srv = abs("/srv/x");
        let given = ["folder", "rm", srv.as_str()];
        assert_eq!(
            forwarded_args(&cli(&given), os(&given), None).unwrap(),
            given
        );
        // A backup's file is named whole, and its passphrase file stays
        // here: this process reads it and hands the passphrase on.
        let given = [
            "backup",
            "n.backup",
            "--passphrase-file",
            "pass",
            "--overwrite",
        ];
        let c = cli(&given);
        let file = home.join("n.backup");
        assert_eq!(
            forwarded_args(&c, os(&given), Some(home.clone())).unwrap(),
            ["backup", &*file.to_string_lossy(), "--overwrite"]
        );
        let job = FileJob::of(&c.cmd, Some(home.clone())).unwrap();
        assert_eq!(job.path, file);
        assert_eq!(job.backup, Some(true));
        assert_eq!(job.passphrase_file, Some(home.join("pass")));
        let backup = abs("/srv/n.backup");
        let pass = format!("--passphrase-file={}", abs("/p"));
        let given = ["restore", backup.as_str(), pass.as_str(), "--replace"];
        let c = cli(&given);
        assert_eq!(
            forwarded_args(&c, os(&given), None).unwrap(),
            ["restore", backup.as_str(), "--replace"]
        );
        assert_eq!(FileJob::of(&c.cmd, None).unwrap().backup, None);
        assert!(FileJob::of(&cli(&["status"]).cmd, None).is_none());
    }

    /// Only the commands that read the input get it.
    #[test]
    fn only_a_command_that_asks_reads_the_input() {
        assert!(reads_input(&cli(&["center", "add", "nerve://pair?x"]).cmd));
        assert!(!reads_input(
            &cli(&["center", "add", "nerve://pair?x", "--yes"]).cmd
        ));
        assert!(reads_input(
            &cli(&["proxy", "set", "http://u@h:1", "--password-stdin"]).cmd
        ));
        assert!(!reads_input(&cli(&["proxy", "set", "http://h:1"]).cmd));
        // Setup asks its questions: its input goes to the node.
        assert!(reads_input(&cli(&["setup"]).cmd));
        assert!(matches!(input_for(&cli(&["setup"]).cmd), Input::Stdin));
        assert!(matches!(input_for(&cli(&["status"]).cmd), Input::None));
        for args in [
            &["status"][..],
            &["rule", "add", "allow", "ls"],
            &["log", "--follow"],
        ] {
            assert!(!reads_input(&cli(args).cmd), "{args:?}");
        }
    }

    /// The owner pipe lets in SYSTEM, the administrators, the node's account,
    /// which makes its instances, and the owners; no one else.
    #[test]
    fn the_owner_pipe_names_the_owners_and_the_nodes_account() {
        let d = dacl_text("S-1-5-21-1-2-3-1057", &["S-1-5-21-1-2-3-1056".into()]);
        assert_eq!(
            d,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1057)(A;;GA;;;S-1-5-21-1-2-3-1056)"
        );
        for other in ["WD", "BU", "AU", "IU", "AC", "S-1-15-"] {
            assert!(!d.contains(other), "{other}");
        }
    }

    /// A character cut between two reads waits for its other bytes.
    #[test]
    fn text_is_cut_between_characters_only() {
        let mut p = "aé".as_bytes().to_vec();
        let last = p.pop().unwrap();
        assert_eq!(take_text(&mut p), "a");
        p.push(last);
        assert_eq!(take_text(&mut p), "é");
        assert!(p.is_empty());
        let mut bad = vec![b'x', 0xff, b'y'];
        assert_eq!(take_text(&mut bad), "x\u{fffd}y");
    }

    /// The owner's request is the command line and its folder, nothing
    /// more.
    #[test]
    fn a_request_is_the_command_and_its_folder() {
        let line = request_line(&["status".into()], Some("/w".into()), false, false);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["method"], "cli");
        assert_eq!(v["params"]["args"], json!(["status"]));
        assert_eq!(v["params"]["cwd"], "/w");
        assert!(v.get("token").is_none(), "{v}");
        let v: Value = serde_json::from_str(&request_line(&[], None, true, false)).unwrap();
        assert_eq!(v["params"]["file"], STREAMED);
        assert!(v["params"].get("terminal").is_none(), "{v}");
        let v: Value = serde_json::from_str(&request_line(&[], None, false, true)).unwrap();
        assert_eq!(v["params"]["terminal"], true);
    }

    /// The owner of the unit is let in, and root; anyone else is not.
    #[cfg(unix)]
    #[test]
    fn only_the_owner_and_root_are_let_in() {
        // SAFETY: a plain getter.
        let me = unsafe { libc::getuid() };
        let Some(name) = crate::account::name_of(me) else {
            eprintln!("skipped: this account has no name");
            return;
        };
        let owner = Owners::Named(name.clone());
        assert_eq!(owner_name(&owner, me), Some(name.clone()));
        assert!(owner_name(&owner, 0).is_some(), "root is always let in");
        assert_eq!(owner_name(&owner, me.wrapping_add(4242)), None);
        let other = Owners::Named("nerve-no-such-owner-for-a-test".into());
        if me != 0 {
            assert_eq!(owner_name(&other, me), None);
        }
        // A node without an owner lets root in alone.
        assert!(owner_name(&Owners::Uids(Vec::new()), 0).is_some());
        if me != 0 {
            assert_eq!(owner_name(&Owners::Uids(Vec::new()), me), None);
        }
    }

    /// Windows: no AppContainer opens the owner pipe, whose DACL names no
    /// package, while the owner, whose SID it names, does. A pipe that also
    /// names every package lets the container in: the refusal is the DACL's.
    #[cfg(windows)]
    #[test]
    fn no_appcontainer_opens_the_owner_pipe() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let me = crate::win_user::own_sid()
                .map_err(|e| e.to_string())
                .and_then(|s| crate::win_host::sid_text(&s))
                .unwrap();
            let base = format!(r"\\.\pipe\nerve-test-owner-{}", std::process::id());
            let (closed, open) = (format!("{base}-closed"), format!("{base}-open"));
            let owners = dacl_text(&me, std::slice::from_ref(&me));
            let sd = crate::pipe::Descriptor::from_sddl(&owners).unwrap();
            let every =
                crate::pipe::Descriptor::from_sddl(&format!("{owners}(A;;GA;;;S-1-15-2-1)"))
                    .unwrap();
            let _closed = crate::pipe::instance(&closed, &sd, true).unwrap();
            let _open = crate::pipe::instance(&open, &every, true).unwrap();

            let work = tempfile::tempdir().unwrap();
            let name = format!("nerve.test.owner.{}", std::process::id());
            nerve_sandbox::appcontainer::set(
                work.path(),
                &name,
                Some(nerve_sandbox::acl::masks(true, true, true)),
                false,
            )
            .unwrap();
            let in_container = |pipe: &str| {
                let out = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "owner::tests::helper_writes_to_a_pipe_in_a_container",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("NERVE_TEST_CONTAINER", &name)
                    .env("NERVE_TEST_PIPE", pipe)
                    .current_dir(work.path())
                    .output()
                    .unwrap();
                String::from_utf8_lossy(&out.stdout).into_owned()
            };
            let said = in_container(&closed);
            assert!(!said.contains("exit code: 0\n"), "{said}");
            assert!(said.contains("exit code: "), "{said}");
            let said = in_container(&open);
            assert!(said.contains("exit code: 0\n"), "{said}");
            // The owner's own program opens it.
            let _second = crate::pipe::instance(&closed, &sd, false).unwrap();
            tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&closed)
                .expect("the owner opens the owner pipe");
            nerve_sandbox::appcontainer::remove_profile(&name).unwrap();
        });
    }

    /// Run by [`no_appcontainer_opens_the_owner_pipe`] in a process of its
    /// own, in a folder granted to the container: writes a line to the pipe
    /// from cmd in the container.
    #[cfg(windows)]
    #[test]
    #[ignore = "a helper of no_appcontainer_opens_the_owner_pipe"]
    fn helper_writes_to_a_pipe_in_a_container() {
        let var = |k: &str| std::env::var(k).unwrap();
        let args = [
            "/C".to_string(),
            format!("echo x> {}", var("NERVE_TEST_PIPE")),
        ];
        match nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &args,
            &var("NERVE_TEST_CONTAINER"),
        ) {
            Ok(code) => println!("exit code: {code}"),
            Err(e) => println!("exit code: {}\n{e}", u32::MAX),
        }
    }
}
