//! A `/proc` of a command's own (Linux, #199): the shim puts the command in a
//! PID namespace with its own `/proc` mounted, so `ps`, `top` and
//! `/proc/<pid>/cmdline` show its own processes and none of another
//! pairing's. Every pairing's commands run as one account, `nerve-run`, and
//! `/proc/<pid>/cmdline` is open to every account, so without this one
//! pairing's command reads the command lines of the others.
//!
//! The node has no `CAP_SYS_ADMIN`, so the shim makes a user namespace
//! first, unprivileged, in which it may make the other two. The namespace
//! maps the command's own user and group to themselves and nothing else:
//! there is no root inside, a file of another account shows as `nobody`,
//! and the kernel still checks every access as the real account. A node
//! that runs as root maps every id it sees instead ([`id_map`]): in a
//! namespace the kernel lets root override file permissions only over ids
//! the namespace maps, and root's command would lose its rights over the
//! files of everyone else. Three
//! processes then stand for the command:
//!
//! - the shim, in the node's namespace, which the node waits for: it waits
//!   for the next and ends as the command ended, by the same signal too;
//! - the namespace's first process, its init: it mounts the new `/proc`,
//!   reaps what is left to it and passes the command's end back;
//! - the command, which the shim's caller confines and starts.
//!
//! A signal the node sends the command's process group reaches the command
//! and what it started as before; the shim and the init let it pass (the
//! kernel does not hand an init a signal it has no handler for). When the
//! command ends, the init ends, and the kernel kills what is left in the
//! namespace, as the node kills what is left in the command's cgroup.

use std::io;

/// Where a process stands after [`enter`].
pub enum Entered {
    /// The command's own process, in the new namespace: the caller confines
    /// it and starts the command.
    Inside,
    /// The shim, once the command ended: the code to end with. A command
    /// ended by a signal has ended the shim by it already.
    Ended(i32),
}

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// Puts what follows in a PID namespace of its own with its own `/proc`.
/// Must run before any thread starts in the process, as the user
/// namespace it makes needs.
pub fn enter() -> io::Result<Entered> {
    // SAFETY: plain getters.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // The parent's maps are read before the unshare changes what
    // `/proc/self` says.
    let (uids, gids) = (parent_map("uid_map"), parent_map("gid_map"));
    // SAFETY: unshare with flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS) } != 0 {
        return Err(last());
    }
    // The command's own ids, and no others: nobody is root inside. Root
    // keeps its rights, and may leave `setgroups` as it is.
    std::fs::write("/proc/self/uid_map", id_map(uid, &uids))?;
    if uid != 0 {
        std::fs::write("/proc/self/setgroups", "deny")?;
    }
    std::fs::write("/proc/self/gid_map", id_map(gid, &gids))?;
    let mut ends = [0; 2];
    // SAFETY: a pipe into an array of two descriptors.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(last());
    }
    let [read, write] = ends;
    // SAFETY: the process is single-threaded (above), so the child may go
    // on in Rust.
    match unsafe { libc::fork() } {
        -1 => Err(last()),
        0 => {
            // SAFETY: the end this process does not use.
            unsafe { libc::close(read) };
            init(write)
        }
        first => {
            // SAFETY: the end this process does not use.
            unsafe { libc::close(write) };
            Ok(Entered::Ended(shim(first, read)))
        }
    }
}

/// The ids the process sees, as `/proc/self/{uid,gid}_map` says: its text,
/// empty where it cannot be read (the namespace then maps the one id).
fn parent_map(file: &str) -> String {
    std::fs::read_to_string(format!("/proc/self/{file}")).unwrap_or_default()
}

/// What the new namespace maps, for the process whose id is `own` and
/// whose namespace's map is `parent` (`inside outside count` lines, the
/// first column being what this process sees). A process that is not root
/// maps its own id to itself and nothing else. Root maps every id it sees
/// to itself: there it keeps `CAP_DAC_OVERRIDE` and the like over the
/// files of everyone else, which a map of one id would take from it (they
/// show as `nobody`, and root's own rights stop at the files it owns).
fn id_map(own: u32, parent: &str) -> String {
    let all: Vec<String> = parent
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (inside, _outside, count) = (w.next()?, w.next()?, w.next()?);
            Some(format!("{inside} {inside} {count}\n"))
        })
        .collect();
    if own != 0 || all.is_empty() {
        return format!("{own} {own} 1\n");
    }
    all.concat()
}

/// The name of the node's AppArmor profile, which `nerve-node install` puts
/// where AppArmor holds user namespaces back from an account (Ubuntu
/// 24.04): it lets the node's own program, the shim, make the namespace.
pub const APPARMOR_PROFILE: &str = "nerve-node";

/// Whether `label`, what `/proc/self/attr/current` says, is the node's
/// profile in any mode (`nerve-node (unconfined)`, `nerve-node (enforce)`,
/// a stacked label starting with it).
fn in_profile(label: &[u8]) -> bool {
    label
        .strip_prefix(APPARMOR_PROFILE.as_bytes())
        .is_some_and(|rest| matches!(rest.first(), None | Some(b' ' | b'\n' | 0)))
}

/// Reads at most `buf.len()` bytes of the file at `path` into `buf`: how
/// many, or `None` where it cannot be opened or read. Plain system calls
/// only, so it may run between `fork` and `exec`.
fn read_small(path: &std::ffi::CStr, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: open, read into a buffer of this size, close.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return None;
        }
        let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
        libc::close(fd);
        usize::try_from(n).ok()
    }
}

/// Writes `text` to the file at `path`. Plain system calls only.
fn write_small(path: &std::ffi::CStr, text: &[u8]) -> bool {
    // SAFETY: open, write from a buffer of this size, close.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return false;
        }
        let n = libc::write(fd, text.as_ptr().cast(), text.len());
        libc::close(fd);
        usize::try_from(n) == Ok(text.len())
    }
}

/// Makes the next `exec` of this process leave the node's AppArmor profile
/// for none, where the process is in it. The profile lets the node's own
/// program make a user namespace and is passed on through every `exec`
/// otherwise; a command that kept it could make user namespaces with all
/// their capabilities, which Ubuntu holds back from every other program
/// (`kernel.apparmor_restrict_unprivileged_userns`). With none, the system
/// treats the command as it treats any program of an account. Nothing
/// happens where the process is not in the profile or AppArmor is not
/// there. Before Landlock, which would refuse the write. Plain system
/// calls only, so it may run between `fork` and `exec`.
pub fn leave_profile() -> io::Result<()> {
    let mut label = [0u8; 160];
    match read_small(c"/proc/self/attr/current", &mut label) {
        Some(n) if in_profile(&label[..n]) => {}
        _ => return Ok(()),
    }
    // The AppArmor-only file first (kernels that stack security modules),
    // then the general one.
    for path in [c"/proc/self/attr/apparmor/exec", c"/proc/self/attr/exec"] {
        if write_small(path, b"exec unconfined") {
            return Ok(());
        }
    }
    Err(last())
}

/// The signals the node may send a command's group that would end the shim
/// before the command: the shim lets them pass to the command.
const PASSED: [i32; 7] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGALRM,
];

/// The shim's part: waits for the init `first` and the command's end it
/// reports on `read`, and ends as the command did.
fn shim(first: libc::pid_t, read: i32) -> i32 {
    // SAFETY: dispositions of this process's own signals.
    unsafe {
        for s in PASSED {
            libc::signal(s, libc::SIG_IGN);
        }
    }
    let mut status = [0u8; 4];
    let mut got = 0;
    while got < status.len() {
        // SAFETY: reads into the rest of a buffer of this size.
        let n = unsafe { libc::read(read, status[got..].as_mut_ptr().cast(), status.len() - got) };
        if n > 0 {
            got += n as usize;
        } else if n == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
    }
    let mut init = 0;
    // SAFETY: waits for this process's own child.
    while unsafe { libc::waitpid(first, &mut init, 0) } < 0
        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
    {}
    // The command's end where the init told it, else the init's own.
    let end = if got == status.len() {
        i32::from_ne_bytes(status)
    } else {
        init
    };
    if libc::WIFSIGNALED(end) {
        let sig = libc::WTERMSIG(end);
        // SAFETY: the default action of the signal that ended the command,
        // on this process, which is not dumped for it.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return 128 + sig;
    }
    if libc::WIFEXITED(end) {
        libc::WEXITSTATUS(end)
    } else {
        crate::SHIM_FAILED
    }
}

/// The init's part: mounts the namespace's `/proc`, starts the command's
/// own process (which returns [`Entered::Inside`]), and ends when the
/// command ends, with its wait status sent on `write` first.
fn init(write: i32) -> io::Result<Entered> {
    // SAFETY: plain prctl and mount calls with constant, terminated strings.
    unsafe {
        // It ends with the shim, and the namespace with it.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
            || libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            ) != 0
        {
            let e = last();
            eprintln!("nerve-node: cannot give the command a /proc of its own: {e}");
            libc::_exit(crate::SHIM_FAILED);
        }
    }
    // SAFETY: as in `enter`; the init stays single-threaded.
    let command = match unsafe { libc::fork() } {
        -1 => {
            eprintln!("nerve-node: cannot start the command: {}", last());
            // SAFETY: ends this process.
            unsafe { libc::_exit(crate::SHIM_FAILED) }
        }
        0 => {
            // SAFETY: the pipe is the init's alone.
            unsafe { libc::close(write) };
            return Ok(Entered::Inside);
        }
        pid => pid,
    };
    loop {
        let mut status = 0;
        // SAFETY: reaps any child of the init, the namespace's orphans too.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == command {
            let bytes = status.to_ne_bytes();
            // SAFETY: writes four bytes of a local buffer, then ends.
            unsafe {
                libc::write(write, bytes.as_ptr().cast(), bytes.len());
                libc::_exit(0);
            }
        }
        if pid < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            // SAFETY: ends this process.
            unsafe { libc::_exit(crate::SHIM_FAILED) };
        }
    }
}

/// Whether the shim at `exe` can give a command a `/proc` of its own on
/// this machine: it runs a command that way once, which must find itself
/// right after the init in that `/proc`. The kernel
/// may not let an account make a user namespace (a sysctl, or AppArmor's
/// restriction on Ubuntu 24.04 without the node's profile), or may not let
/// it mount `/proc` there (inside some containers).
pub fn works(exe: &std::path::Path) -> bool {
    use std::io::Write;
    let spec = crate::ShimSpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "cat /proc/self/stat".into()],
        parent: std::process::id(),
        landlock: None,
        container: None,
        own_proc: true,
    };
    let Ok(json) = serde_json::to_vec(&spec) else {
        return false;
    };
    let child = std::process::Command::new(exe)
        .arg(crate::SHIM_ARG)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return false;
    };
    let sent = child
        .stdin
        .take()
        .is_some_and(|mut s| s.write_all(&json).is_ok());
    // `cat` under the init (1): pid 2 where the shell became it, else 3
    // under the shell. No process of the node's own namespace has such a
    // pid.
    child.wait_with_output().is_ok_and(|o| {
        let out = String::from_utf8_lossy(&o.stdout);
        let pid = out.split(' ').next();
        let parent = out
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1));
        sent && o.status.success()
            && matches!(
                (pid, parent),
                (Some("2"), Some("1")) | (Some("3"), Some("2"))
            )
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    /// Root keeps its rights in the namespace: it maps every id it sees,
    /// as the kernel gives root's override of file permissions only over
    /// ids the namespace maps (round 1, correctness 1). Any other account
    /// maps itself alone.
    #[test]
    fn a_root_node_maps_every_id_it_sees_and_another_account_its_own() {
        assert_eq!(super::id_map(0, "0 0 4294967295\n"), "0 0 4294967295\n");
        // A node in a container sees what its map shows it.
        assert_eq!(
            super::id_map(0, "         0     100000      65536\n"),
            "0 0 65536\n"
        );
        assert_eq!(super::id_map(0, "0 1000 1\n5 1005 3\n"), "0 0 1\n5 5 3\n");
        assert_eq!(super::id_map(1000, "0 0 4294967295\n"), "1000 1000 1\n");
        // A map that cannot be read leaves root its own id.
        assert_eq!(super::id_map(0, ""), "0 0 1\n");
    }

    /// Only the node's own profile is left at exec, in any of its modes.
    #[test]
    fn the_node_leaves_its_own_profile_and_no_other() {
        for label in [
            "nerve-node (unconfined)\n",
            "nerve-node (enforce)\n",
            "nerve-node\n",
            "nerve-node",
            "nerve-node (unconfined)//child\n",
        ] {
            assert!(super::in_profile(label.as_bytes()), "{label}");
        }
        for label in [
            "unconfined\n",
            "",
            "nerve-node-other (enforce)\n",
            "my-nerve-node (enforce)\n",
            "/usr/bin/bwrap (enforce)\n",
        ] {
            assert!(!super::in_profile(label.as_bytes()), "{label}");
        }
    }

    /// A shim that runs the command in the node's own namespace is no
    /// namespace: the probe says so by the pid the command finds, not by
    /// its exit code.
    #[test]
    fn the_probe_takes_only_a_command_right_after_the_init() {
        let d = tempfile::tempdir().unwrap();
        let shim = |name: &str, body: &str| {
            let p = d.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\ncat > /dev/null\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        assert!(!super::works(&shim("plain", "cat /proc/self/stat")));
        assert!(!super::works(&shim("failed", "exit 126")));
        assert!(super::works(&shim("became", "echo '2 (cat) R 1 0 0'")));
        assert!(super::works(&shim("under", "echo '3 (cat) R 2 0 0'")));
        assert!(!super::works(&shim("other", "echo '3 (cat) R 1 0 0'")));
        assert!(!super::works(&d.path().join("missing")));
    }
}
