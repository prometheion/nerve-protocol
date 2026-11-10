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
//! and the kernel still checks every access as the real account. Root makes
//! none ([`wants_namespace`]). Three processes then stand for the command:
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
    if !wants_namespace(uid) {
        return Ok(Entered::Inside);
    }
    // SAFETY: unshare with flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS) } != 0 {
        return Err(last());
    }
    // The command's own ids, and no others: nobody is root inside.
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))?;
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))?;
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

/// Whether the shim run by `uid` makes a namespace. Root does not: in a user
/// namespace the kernel lets root override file permissions only over ids the
/// namespace maps, and the one id the shim may map is its own, so root's
/// command would lose its rights over the files of every other account (they
/// show as `nobody`). A map of every id has to be written from outside the
/// namespace, which the shim cannot. A node that runs as root (`allow_root`)
/// holds its commands apart by Landlock alone, and `status` warns of the
/// processes they see.
fn wants_namespace(uid: u32) -> bool {
    uid != 0
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

/// Whether this process is in the node's AppArmor profile now.
pub fn in_own_profile() -> bool {
    let mut label = [0u8; 160];
    read_small(c"/proc/self/attr/current", &mut label).is_some_and(|n| in_profile(&label[..n]))
}

/// Whether AppArmor holds user namespaces back from an account here
/// (`kernel.apparmor_restrict_unprivileged_userns`, Ubuntu 24.04), which
/// the node's profile lifts for the node's own program.
pub fn userns_restricted() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|v| v.trim() == "1")
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

/// Whether nobody reads the other end of the pipe `write` any more: the
/// shim holds it until it ends, so a pipe that reports no reader says the
/// shim is gone. The init's own parent id is 0 in its namespace, so the
/// check the shim's start makes cannot be used here.
fn shim_gone(write: i32) -> bool {
    let mut p = libc::pollfd {
        fd: write,
        events: 0,
        revents: 0,
    };
    // SAFETY: polls one descriptor of this process without waiting.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n == 1 && p.revents & libc::POLLERR != 0
}

/// The init's part: mounts the namespace's `/proc`, starts the command's
/// own process (which returns [`Entered::Inside`]), and ends when the
/// command ends, with its wait status sent on `write` first.
fn init(write: i32) -> io::Result<Entered> {
    // SAFETY: plain prctl and mount calls with constant, terminated strings.
    unsafe {
        // It ends with the shim, and the namespace with it.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        // A shim that died before the line above sends no signal: the
        // command would run on with no node watching it.
        if shim_gone(write) {
            let said = b"nerve-node: the shim is gone before its command started\n";
            libc::write(2, said.as_ptr().cast(), said.len());
            libc::_exit(crate::SHIM_FAILED);
        }
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
        cwd: None,
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
    /// Root makes no namespace, so that it keeps its rights over the files
    /// of other accounts; any other account does (round 1, correctness 1).
    #[test]
    fn root_makes_no_namespace_and_another_account_does() {
        assert!(!super::wants_namespace(0));
        assert!(super::wants_namespace(1000));
    }

    /// The init sees that the shim is gone before it starts the command: a
    /// pipe with no reader says so, one with a reader does not, and an init
    /// whose shim is gone ends before it mounts or forks.
    #[test]
    fn the_init_ends_where_the_shim_is_gone() {
        use std::io::{Read, Seek};
        use std::os::fd::AsRawFd;
        let mut ends = [0; 2];
        // SAFETY: a pipe into an array of two descriptors.
        assert_eq!(
            unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let [read, write] = ends;
        assert!(!super::shim_gone(write), "a reader holds the pipe");
        // SAFETY: both ends are this test's.
        unsafe {
            libc::close(read);
            libc::close(write);
        }
        // What the child says goes to a file, read once it ended: a pipe
        // would wait for every copy of its write end.
        let mut said = tempfile::tempfile().unwrap();
        // SAFETY: the child makes plain system calls and runs the init's
        // own code, which is made to run in a forked process, and then
        // ends.
        match unsafe { libc::fork() } {
            0 => unsafe {
                libc::dup2(said.as_raw_fd(), 2);
                // Nothing else of the test process stays here, and the pipe
                // is made here, where no other test forks: one that forked
                // while the pipe was this process's would hold a copy of its
                // read end, a reader the init would see.
                libc::syscall(libc::SYS_close_range, 3, libc::c_uint::MAX, 0);
                let mut ends = [0; 2];
                if libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                    libc::_exit(1);
                }
                libc::close(ends[0]);
                let _ = super::init(ends[1]);
                libc::_exit(0);
            },
            pid => {
                let mut status = 0;
                // SAFETY: waits for the child above.
                unsafe { libc::waitpid(pid, &mut status, 0) };
                let mut text = String::new();
                said.rewind().unwrap();
                said.read_to_string(&mut text).unwrap();
                assert!(text.contains("the shim is gone"), "{text}");
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), crate::SHIM_FAILED);
            }
        }
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
        // Each written by a shell of its own, so this process never holds it
        // open for writing: a command another test forks meanwhile would
        // hold it so until its exec, and Linux runs no file that is open
        // for writing.
        let shim = |name: &str, body: &str| {
            let p = d.path().join(name);
            let mut sh = std::process::Command::new("/bin/sh")
                .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
                .arg(&p)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let text = format!("#!/bin/sh\ncat > /dev/null\n{body}\n");
            let mut input = sh.stdin.take().unwrap();
            std::io::Write::write_all(&mut input, text.as_bytes()).unwrap();
            drop(input);
            assert!(sh.wait().unwrap().success());
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
