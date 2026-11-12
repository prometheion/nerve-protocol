//! Limits per command (docs/dev/sandbox-linux.md): on Linux every command runs in
//! a cgroup of its own, with the memory, CPU and processes its call was
//! granted ([`nerve_policy::config::CommandLimits::grant`]).
//!
//! The node needs a cgroup v2 that is delegated to it: the installed
//! service gets one from systemd (`Delegate=` in its unit), and a node of
//! the owner's own gets one from `systemd-run --user --scope -p
//! Delegate=yes`. A cgroup that holds processes cannot pass controllers on
//! to cgroups below it, so at start the node moves itself into a leaf,
//! `node`, and makes one `cmd-<n>` beside it per command. The command joins
//! its cgroup in the forked child before it runs anything, so whatever it
//! starts is in it too. When the command ends, everything left in its
//! cgroup is killed (`cgroup.kill`), also what left its process group, and
//! the cgroup is removed.
//!
//! A command run as another account than the node's and root cannot write
//! its cgroup's files, which are the node's user's, so it cannot leave its
//! cgroup or raise its limits that way. A command of the node's own user
//! could, outside folder mode's Landlock, and so could a root one (the
//! account root, a sudo command). Every command can still have work started
//! outside its cgroup by a service manager of its account (`systemd-run
//! --user`, `at`, cron); that work is not held to its limits.
//!
//! Without such a cgroup (no systemd, a cgroup v1 machine, a node started
//! in a terminal) commands run without these limits; `status` and the log
//! say why.
//!
//! On Windows every command's job object holds it to them (crate::job,
//! [`job_limits`]): its memory, its CPU rate, which Windows counts as a
//! share of every CPU of the machine, and its processes, which Windows
//! counts without their threads. A command past its memory is ended, as
//! on Linux. What a command has started outside its job (the task
//! scheduler, WMI, a service) is not held to them.

use std::sync::Arc;

use nerve_policy::config::CommandLimits;
use serde_json::{Value, json};

/// Where this node holds commands to their limits, or why it cannot.
pub type Found = Result<Arc<Cgroups>, String>;

/// What `status` says of the limits: the node's settings, what holds them
/// (`held_by`: the cgroup on Linux, the command's job object on Windows)
/// and which of them it holds, or why none is.
pub fn status(limits: &CommandLimits, found: &Found) -> Value {
    json!({
        "memory_mb": limits.memory_mb,
        "memory_max_mb": limits.memory_max_mb,
        "cpu_percent": limits.cpu_percent,
        "cpu_max_percent": limits.cpu_max_percent,
        "processes": limits.processes,
        "processes_max": limits.processes_max,
        "held_by": found.as_ref().ok().map(|c| c.name().to_string()),
        "enforced": found.as_ref().map_or_else(|_| Vec::new(), |c| c.enforced()),
        "lost": found.as_ref().map_or_else(|_| Vec::new(), |c| c.lost()),
        "off": found.as_ref().err(),
    })
}

/// What a command's job object holds it to on Windows: the limits it was
/// granted, the CPU's as Windows counts it on a machine of `cpus`
/// (nerve_service::win::job::cpu_rate). The processes have room for what
/// runs in the job besides the command's own: the console host of its
/// console, the helper that asks the command to end (crate::win_stop) and
/// the shim of folder mode (`shim`, which starts the command in its
/// container).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn job_limits(
    granted: &nerve_policy::config::Granted,
    cpus: u32,
    shim: bool,
) -> nerve_service::win::job::JobLimits {
    nerve_service::win::job::JobLimits {
        memory_bytes: Some(granted.memory_mb.saturating_mul(1024 * 1024)),
        cpu_rate: nerve_service::win::job::cpu_rate(granted.cpu_percent, cpus),
        processes: Some(
            granted
                .processes
                .saturating_add(2)
                .saturating_add(u32::from(shim)),
        ),
    }
}

/// The text of a command killed for its memory limit of `mb` MiB, in its
/// result and its audit entry.
pub fn memory_reason(mb: u64) -> String {
    format!("the command went past its memory limit of {mb} MiB and was killed")
}

#[cfg(target_os = "linux")]
pub use linux::{Cgroups, CommandCgroup, join};

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use nerve_policy::config::Granted;

    /// Where the cgroup v2 hierarchy is.
    const MOUNT: &str = "/sys/fs/cgroup";
    /// The leaf the node moves itself into.
    const LEAF: &str = "node";
    /// The start of a command's cgroup's name.
    const PREFIX: &str = "cmd-";
    /// The period `cpu.max` counts in, in microseconds.
    const CPU_PERIOD: u64 = 100_000;

    /// The cgroup delegated to the node, which holds a cgroup per command.
    #[derive(Debug)]
    pub struct Cgroups {
        /// Its folder below the mount.
        dir: PathBuf,
        /// Its path in the hierarchy, as `/proc/self/cgroup` names it.
        name: String,
        memory: bool,
        cpu: bool,
        pids: bool,
        next: AtomicU64,
    }

    impl Cgroups {
        /// The cgroup of this process, made ready for commands: the node
        /// moves into its leaf and turns the controllers on below it.
        pub fn find() -> Result<Cgroups, String> {
            let own = std::fs::read_to_string("/proc/self/cgroup")
                .map_err(|e| format!("cannot read /proc/self/cgroup: {e}"))?;
            let name = own
                .lines()
                .find_map(|l| l.strip_prefix("0::"))
                .ok_or("this machine has no cgroup v2 (unified hierarchy)")?;
            Cgroups::at(
                Path::new(MOUNT),
                name,
                std::process::id(),
                nerve_transport::net::euid(),
                &unit_delegates,
            )
        }

        /// [`Cgroups::find`] for process `me`, run by `euid`, in the cgroup
        /// `own` of the hierarchy mounted at `mount`. `delegates` answers
        /// whether the service manager that owns the cgroup of that path
        /// delegates its unit, for a cgroup without systemd's mark. A test hands it plain
        /// folders.
        pub fn at(
            mount: &Path,
            own: &str,
            me: u32,
            euid: u32,
            delegates: &dyn Fn(&str) -> bool,
        ) -> Result<Cgroups, String> {
            if !mount.join("cgroup.controllers").is_file() {
                return Err(format!(
                    "{} is no cgroup v2 (unified hierarchy)",
                    mount.display()
                ));
            }
            // A node that runs in its leaf already, started again in it.
            let name = match own.rsplit_once('/') {
                Some(("", LEAF)) => "/",
                Some((parent, LEAF)) => parent,
                _ => own,
            }
            .to_string();
            let dir = mount.join(name.trim_start_matches('/'));
            let procs = read_pids(&dir.join("cgroup.procs"))
                .map_err(|e| format!("cannot read the processes of the cgroup {name}: {e}"))?;
            // systemd marks a cgroup it delegates, but the user's own
            // systemd marks none, and a system one before 251 only with
            // `trusted.delegate`, which a process without CAP_SYS_ADMIN
            // does not see. The system's systemd gives a unit's cgroup to
            // its `User=` only with `Delegate=`, so there one that is this
            // user's (not root's) and holds only this process is delegated.
            // Below the user's own systemd every cgroup is the user's, so
            // there its unit says. One systemd did not delegate is
            // systemd's: it turns the controllers off again when it reloads.
            let owned = euid != 0 && std::fs::metadata(&dir).is_ok_and(|m| m.uid() == euid);
            let alone = procs.iter().all(|&p| p == me);
            // The root of what this process sees is the root of a cgroup
            // namespace, a unit's own with `ProtectControlGroups=private`:
            // its path names no unit, so the user's systemd is asked which
            // is the node's and whether it is delegated. The system's marks
            // its delegated cgroups there (257 and later).
            let root = name == "/";
            let ask = root || below_user_manager(&name);
            let handed = owned && alone && (!ask || delegates(&name));
            if !(delegated(&dir) || handed) {
                if root {
                    return Err(
                        "the node's cgroup is the root of a cgroup namespace (`ProtectControlGroups=private`) and is not delegated to it: a unit of your own systemd needs `Delegate=yes`, and systemd 256 or later, which names the node's unit (`systemctl --user whoami`); or leave `ProtectControlGroups=private` out".into(),
                    );
                }
                return Err(format!(
                    "the node's cgroup {name} is not delegated to it: the installed service has one (`sudo nerve-node install` writes its unit again); a node of your own gets one with `systemd-run --user --scope -p Delegate=yes nerve-node run`, or `Delegate=yes` in a unit of yours"
                ));
            }
            let leaf = dir.join(LEAF);
            match std::fs::create_dir(&leaf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("cannot make the cgroup {name}/{LEAF}: {e}")),
            }
            put(&leaf.join("cgroup.procs"), &me.to_string())
                .map_err(|e| format!("cannot move the node into the cgroup {name}/{LEAF}: {e}"))?;
            // What else is there belongs to the delegated cgroup, and keeps
            // the controllers from being passed on until it moved.
            for p in procs.into_iter().filter(|&p| p != me) {
                let _ = put(&leaf.join("cgroup.procs"), &p.to_string());
            }
            let offered =
                std::fs::read_to_string(dir.join("cgroup.controllers")).unwrap_or_default();
            let mut why = String::new();
            let mut on = |c: &str| {
                if !offered.split_whitespace().any(|o| o == c) {
                    return false;
                }
                match put(&dir.join("cgroup.subtree_control"), &format!("+{c}")) {
                    Ok(()) => true,
                    Err(e) => {
                        why = format!(": {e}");
                        false
                    }
                }
            };
            let (memory, cpu, pids) = (on("memory"), on("cpu"), on("pids"));
            if !(memory || cpu || pids) {
                return Err(format!(
                    "the node's cgroup {name} passes on no memory, cpu or pids controller{why}"
                ));
            }
            // A node that ended without removing them left these behind.
            let mut next = 0;
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let n = e.file_name();
                let Some(n) = n.to_str().and_then(|n| n.strip_prefix(PREFIX)) else {
                    continue;
                };
                if let Ok(n) = n.parse::<u64>() {
                    next = next.max(n + 1);
                }
                end(e.path());
            }
            Ok(Cgroups {
                dir,
                name,
                memory,
                cpu,
                pids,
                next: AtomicU64::new(next),
            })
        }

        /// Its path in the hierarchy.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// The limits it holds a command to now: the controllers it turned
        /// on at start that are still on.
        pub fn enforced(&self) -> Vec<&'static str> {
            let (memory, cpu, pids) = self.live();
            [(memory, "memory"), (cpu, "cpu"), (pids, "processes")]
                .into_iter()
                .filter_map(|(on, n)| on.then_some(n))
                .collect()
        }

        /// The limits it held a command to at start that something turned
        /// off since: while there are any, no command runs.
        pub fn lost(&self) -> Vec<&'static str> {
            let (memory, cpu, pids) = self.live();
            [
                (self.memory && !memory, "memory"),
                (self.cpu && !cpu, "cpu"),
                (self.pids && !pids, "processes"),
            ]
            .into_iter()
            .filter_map(|(lost, n)| lost.then_some(n))
            .collect()
        }

        /// Which of its controllers are on below it now. Something else
        /// that writes the cgroup, systemd for one that it did not
        /// delegate, can turn them off.
        fn live(&self) -> (bool, bool, bool) {
            let on = std::fs::read_to_string(self.dir.join("cgroup.subtree_control"))
                .unwrap_or_default();
            let has = |c: &str| {
                on.split_whitespace()
                    .any(|o| o.trim_start_matches('+') == c)
            };
            (
                self.memory && has("memory"),
                self.cpu && has("cpu"),
                self.pids && has("pids"),
            )
        }

        /// A fresh cgroup for one command, with `limits`. Swap does not
        /// count as room: a command past its memory is killed, not swapped
        /// out, and with it everything else of the command.
        pub fn command(&self, limits: &Granted) -> Result<CommandCgroup, String> {
            // A cgroup whose controllers went off would take no limit.
            if self.live() != (self.memory, self.cpu, self.pids) {
                return Err(format!(
                    "the cgroup {} no longer passes on the controllers the node turned on: something else turned them off; start the node again (`nerve-node status` shows what is left)",
                    self.name
                ));
            }
            let mut tries = 0;
            let dir = loop {
                let n = self.next.fetch_add(1, Ordering::Relaxed);
                let d = self.dir.join(format!("{PREFIX}{n}"));
                match std::fs::create_dir(&d) {
                    Ok(()) => break d,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 100 => {
                        tries += 1;
                    }
                    Err(e) => {
                        return Err(format!("cannot make a cgroup for the command: {e}"));
                    }
                }
            };
            let mut cg = CommandCgroup {
                dir,
                procs: None,
                memory_mb: limits.memory_mb,
                memory: self.memory,
            };
            let set = |file: &str, value: String| {
                put(&cg.dir.join(file), &value)
                    .map_err(|e| format!("cannot set {file} of the command's cgroup: {e}"))
            };
            if self.memory {
                set("memory.max", (limits.memory_mb << 20).to_string())?;
                set("memory.oom.group", "1".into())?;
                // Missing where the kernel keeps no account of swap.
                if cg.dir.join("memory.swap.max").exists() {
                    set("memory.swap.max", "0".into())?;
                }
            }
            if self.cpu {
                let quota = u64::from(limits.cpu_percent) * CPU_PERIOD / 100;
                set("cpu.max", format!("{quota} {CPU_PERIOD}"))?;
            }
            if self.pids {
                set("pids.max", limits.processes.to_string())?;
            }
            // Opened as `echo` would open it; the kernel made it with the cgroup.
            let procs = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(cg.dir.join("cgroup.procs"))
                .map_err(|e| format!("cannot open the command's cgroup: {e}"))?;
            cg.procs = Some(procs);
            Ok(cg)
        }
    }

    /// One command's cgroup, killed and removed when dropped.
    #[derive(Debug)]
    pub struct CommandCgroup {
        dir: PathBuf,
        /// Its `cgroup.procs`, opened by the node: the kernel checks the
        /// rights of who opened it, not of the child that writes to it.
        procs: Option<File>,
        memory_mb: u64,
        memory: bool,
    }

    impl CommandCgroup {
        /// What the forked child hands [`join`].
        pub fn procs_fd(&self) -> RawFd {
            self.procs.as_ref().map_or(-1, |f| f.as_raw_fd())
        }

        /// The memory limit it holds, in MiB.
        pub fn memory_mb(&self) -> u64 {
            self.memory_mb
        }

        /// Whether the kernel killed a process of it for its own memory
        /// limit. `oom_kill` also counts kills of an OOM that came from
        /// outside (the machine's, a cgroup above); then `oom`, the times
        /// it reached its own limit, stays 0.
        pub fn out_of_memory(&self) -> bool {
            if !self.memory {
                return false;
            }
            let Ok(t) = std::fs::read_to_string(self.dir.join("memory.events")) else {
                return false;
            };
            let count = |key: &str| {
                t.lines()
                    .filter_map(|l| l.split_once(' '))
                    .find(|(k, _)| *k == key)
                    .and_then(|(_, n)| n.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            };
            count("oom") > 0 && (count("oom_kill") > 0 || count("oom_group_kill") > 0)
        }
    }

    impl Drop for CommandCgroup {
        fn drop(&mut self) {
            self.procs = None;
            end(self.dir.clone());
        }
    }

    /// In the forked child, before exec: moves it into the cgroup whose
    /// `cgroup.procs` is open as `fd`. One system call.
    pub fn join(fd: RawFd) -> std::io::Result<()> {
        // SAFETY: a write of a static byte to a descriptor the node opened.
        let n = unsafe { libc::write(fd, b"0".as_ptr().cast(), 1) };
        if n == 1 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Kills what is left in the cgroup `dir` and removes it: at once when
    /// it is empty, else from a thread of its own once the processes are
    /// gone.
    fn end(dir: PathBuf) {
        kill(&dir);
        if gone(&dir) {
            return;
        }
        let name = dir.display().to_string();
        let spawned = std::thread::Builder::new()
            .name("cgroup-end".into())
            .spawn(move || {
                for _ in 0..250 {
                    std::thread::sleep(Duration::from_millis(20));
                    kill(&dir);
                    if gone(&dir) {
                        return;
                    }
                }
                tracing::warn!(
                    "the command's cgroup {} still holds processes and stays",
                    dir.display()
                );
            });
        if spawned.is_err() {
            tracing::warn!("cannot remove the command's cgroup {name}");
        }
    }

    /// `cgroup.kill` (Linux 5.14); before it, a SIGKILL to each process,
    /// as the account it runs as where that is not the node's: the
    /// installed node may not signal the command account's processes
    /// itself (crate::account::kill_pid_as).
    fn kill(dir: &Path) {
        if put(&dir.join("cgroup.kill"), "1").is_ok() {
            return;
        }
        let me = nerve_transport::net::euid();
        for p in read_pids(&dir.join("cgroup.procs")).unwrap_or_default() {
            match std::fs::metadata(format!("/proc/{p}")).map(|m| m.uid()) {
                Ok(uid) if uid != me && me != 0 => {
                    crate::account::kill_pid_as(uid, p, libc::SIGKILL)
                }
                // SAFETY: kill on a pid of the command's cgroup.
                _ => unsafe {
                    libc::kill(p as libc::pid_t, libc::SIGKILL);
                },
            }
        }
    }

    /// Whether the cgroup `path` is below a user's own systemd
    /// (`user@<uid>.service`).
    fn below_user_manager(path: &str) -> bool {
        path.split('/')
            .any(|p| p.starts_with("user@") && p.ends_with(".service"))
    }

    /// Whether the user's systemd delegates the unit of the cgroup `path`
    /// (`systemctl --user show -p Delegate`).
    /// At the root of a cgroup namespace (`/`) the path names no unit:
    /// the user's systemd names the node's own (`systemctl --user whoami`,
    /// systemd 256).
    fn unit_delegates(path: &str) -> bool {
        let run = |args: &[&str]| {
            std::process::Command::new("systemctl")
                .args(args)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(o.stdout.trim_ascii()).into_owned())
        };
        let own;
        let args = if path == "/" {
            let Some(unit) = run(&["--user", "whoami"]) else {
                return false;
            };
            own = unit;
            ask_unit(&own)
        } else {
            ask_delegate(path)
        };
        args.and_then(|a| run(&a)).is_some_and(|v| v == "yes")
    }

    /// The `systemctl` arguments that ask the user's systemd whether the
    /// unit of the cgroup `path`, its last part, is delegated.
    fn ask_delegate(path: &str) -> Option<Vec<&str>> {
        if !below_user_manager(path) {
            return None;
        }
        ask_unit(path.rsplit('/').next().unwrap_or_default())
    }

    /// The `systemctl` arguments that ask the user's systemd whether the
    /// unit `unit` is delegated; none for what names no unit.
    fn ask_unit(unit: &str) -> Option<Vec<&str>> {
        let bad = unit.is_empty()
            || unit.starts_with('-')
            || unit.starts_with('.')
            || unit.contains(char::is_whitespace);
        (!bad).then(|| vec!["--user", "show", "-p", "Delegate", "--value", "--", unit])
    }

    /// Removes `dir`; whether it is gone.
    fn gone(dir: &Path) -> bool {
        match std::fs::remove_dir(dir) {
            Ok(()) => true,
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }

    /// Whether systemd delegated the cgroup `dir`: it sets
    /// `trusted.delegate`, and from version 251 `user.delegate`, which a
    /// process without CAP_SYS_ADMIN can read.
    fn delegated(dir: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
            return false;
        };
        [c"user.delegate", c"trusted.delegate"].iter().any(|name| {
            let mut v = [0u8; 8];
            // SAFETY: NUL-terminated strings and a buffer of its length.
            let n = unsafe {
                libc::getxattr(path.as_ptr(), name.as_ptr(), v.as_mut_ptr().cast(), v.len())
            };
            n == 1 && v[0] == b'1'
        })
    }

    /// Writes `value` to the cgroup file `path`, as `echo` would.
    fn put(path: &Path, value: &str) -> std::io::Result<()> {
        std::fs::write(path, value)
    }

    fn read_pids(path: &Path) -> std::io::Result<Vec<u32>> {
        Ok(std::fs::read_to_string(path)?
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            // Never 0, which `kill` takes for the node's own group.
            .filter(|&p| p != 0)
            .collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A cgroup tree in plain folders: the files the kernel would have,
        /// as far as the node reads them.
        fn fake(own: &str, controllers: &str, procs: &str) -> (tempfile::TempDir, PathBuf) {
            let t = tempfile::tempdir().unwrap();
            std::fs::write(t.path().join("cgroup.controllers"), "cpu memory pids io").unwrap();
            let dir = t.path().join(own.trim_start_matches('/'));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cgroup.controllers"), controllers).unwrap();
            std::fs::write(dir.join("cgroup.procs"), procs).unwrap();
            (t, dir)
        }

        fn euid() -> u32 {
            nerve_transport::net::euid()
        }

        /// The user's systemd delegates every unit, or none.
        fn yes(_: &str) -> bool {
            true
        }
        fn no(_: &str) -> bool {
            false
        }

        /// What the kernel answers for `cgroup.subtree_control` once these
        /// are on; the plain file keeps only the last write.
        fn turned_on(dir: &Path, on: &str) {
            std::fs::write(dir.join("cgroup.subtree_control"), on).unwrap();
        }

        #[test]
        fn a_cgroup_of_the_node_alone_is_taken_and_a_shared_one_is_not() {
            if euid() == 0 {
                // Root's own folders count only with systemd's mark.
                eprintln!("skipped: root");
                return;
            }
            let own = "/user.slice/user-1000.slice/user@1000.service/app.slice/run-1.scope";
            let (t, dir) = fake(own, "cpu memory pids io", "42\n");
            let asked = std::cell::RefCell::new(Vec::new());
            let c = Cgroups::at(t.path(), own, 42, euid(), &|u| {
                asked.borrow_mut().push(u.to_string());
                true
            })
            .unwrap();
            assert_eq!(c.name(), own);
            // The cgroup's manager was asked whether its unit is delegated.
            assert_eq!(*asked.borrow(), [own]);
            // The node moved into its leaf; the controllers go below.
            assert_eq!(
                std::fs::read_to_string(dir.join("node/cgroup.procs")).unwrap(),
                "42"
            );
            assert_eq!(
                std::fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap(),
                "+pids",
                "the last of +memory, +cpu, +pids"
            );
            turned_on(&dir, "cpu memory pids");
            assert_eq!(c.enforced(), ["memory", "cpu", "processes"]);

            // A unit the user's systemd does not delegate is systemd's:
            // it would turn the controllers off again.
            let (t, dir) = fake(own, "cpu memory pids", "42\n");
            let e = Cgroups::at(t.path(), own, 42, euid(), &no).unwrap_err();
            assert!(e.contains("is not delegated to it"), "{e}");
            assert!(e.contains("`Delegate=yes` in a unit of yours"), "{e}");
            assert!(!dir.join("node").exists(), "it touched the cgroup");
            // Another process in it: that cgroup is not the node's to take.
            let (t, _) = fake(own, "cpu memory pids", "42\n43\n");
            let e = Cgroups::at(t.path(), own, 42, euid(), &yes).unwrap_err();
            assert!(e.contains("is not delegated to it"), "{e}");
            assert!(
                e.contains("systemd-run --user --scope -p Delegate=yes"),
                "{e}"
            );
            // Nor one of another user.
            let (t, _) = fake(own, "cpu memory pids", "42\n");
            let e = Cgroups::at(t.path(), own, 42, euid() + 1, &yes).unwrap_err();
            assert!(e.contains("is not delegated to it"), "{e}");
            // Nor a machine without cgroup v2.
            let t = tempfile::tempdir().unwrap();
            let e = Cgroups::at(t.path(), own, 42, euid(), &yes).unwrap_err();
            assert!(e.contains("no cgroup v2"), "{e}");
        }

        /// The installed service on a systemd before 251, whose mark the
        /// node's user cannot see: the system's systemd gave it the cgroup,
        /// which it does only with `Delegate=`, and nothing is asked, so a
        /// machine without a system bus takes it too.
        #[test]
        fn a_service_without_a_visible_mark_is_taken_by_its_owner() {
            if euid() == 0 {
                eprintln!("skipped: root");
                return;
            }
            let own = "/system.slice/nerve-node.service";
            let (t, _) = fake(own, "cpu memory pids", "7\n");
            let asked = std::cell::RefCell::new(Vec::new());
            let c = Cgroups::at(t.path(), own, 7, euid(), &|p| {
                asked.borrow_mut().push(p.to_string());
                false
            })
            .unwrap();
            assert_eq!(c.name(), own);
            assert!(asked.borrow().is_empty(), "{:?}", asked.borrow());
            // Still not one of another user, nor one shared.
            let (t, _) = fake(own, "cpu memory pids", "7\n");
            assert!(Cgroups::at(t.path(), own, 7, euid() + 1, &yes).is_err());
            let (t, _) = fake(own, "cpu memory pids", "7\n8\n");
            assert!(Cgroups::at(t.path(), own, 7, euid(), &yes).is_err());
            // Only the user's systemd is asked.
            assert_eq!(ask_delegate(own), None);
            assert_eq!(
                ask_delegate("/user.slice/user-1000.slice/user@1000.service/app.slice/run-1.scope")
                    .unwrap(),
                [
                    "--user",
                    "show",
                    "-p",
                    "Delegate",
                    "--value",
                    "--",
                    "run-1.scope"
                ]
            );
            assert_eq!(
                ask_delegate("/user.slice/user-1000.slice/user@1000.service/x/-u"),
                None
            );
        }

        /// The root of a cgroup namespace (a unit with
        /// `ProtectControlGroups=private`): its path names no unit, so the
        /// user's systemd is asked about the node's own; one it does not
        /// delegate is not taken, also not by its owner.
        #[test]
        fn the_root_of_a_cgroup_namespace_is_taken_only_when_delegated() {
            if euid() == 0 {
                eprintln!("skipped: root");
                return;
            }
            for own in ["/", "/node"] {
                let (t, dir) = fake("/", "cpu memory pids", "7\n");
                let asked = std::cell::RefCell::new(Vec::new());
                let e = Cgroups::at(t.path(), own, 7, euid(), &|p| {
                    asked.borrow_mut().push(p.to_string());
                    false
                })
                .unwrap_err();
                assert!(e.contains("the root of a cgroup namespace"), "{own}: {e}");
                assert!(e.contains("`Delegate=yes`, and systemd 256"), "{own}: {e}");
                assert!(
                    !dir.join("node/cgroup.procs").exists(),
                    "{own}: it touched it"
                );
                assert_eq!(*asked.borrow(), ["/"], "{own}");

                let (t, dir) = fake("/", "cpu memory pids", "7\n");
                let c = Cgroups::at(t.path(), own, 7, euid(), &yes).unwrap();
                assert_eq!(c.name(), "/");
                assert!(dir.join("node/cgroup.procs").exists(), "{own}");
                // Not another user's, nor a shared one, whatever is said.
                let (t, _) = fake("/", "cpu memory pids", "7\n");
                assert!(Cgroups::at(t.path(), own, 7, euid() + 1, &yes).is_err());
                let (t, _) = fake("/", "cpu memory pids", "7\n8\n");
                assert!(Cgroups::at(t.path(), own, 7, euid(), &yes).is_err());
            }
            assert_eq!(
                ask_unit("nerve.service").unwrap(),
                [
                    "--user",
                    "show",
                    "-p",
                    "Delegate",
                    "--value",
                    "--",
                    "nerve.service"
                ]
            );
            assert_eq!(ask_unit(""), None);
            assert_eq!(ask_unit("a b"), None);
        }

        #[test]
        fn a_node_in_its_leaf_already_takes_the_cgroup_above() {
            if euid() == 0 {
                eprintln!("skipped: root");
                return;
            }
            let (t, dir) = fake("/svc.service", "memory pids", "");
            std::fs::create_dir(dir.join("node")).unwrap();
            let c = Cgroups::at(t.path(), "/svc.service/node", 7, euid(), &yes).unwrap();
            assert_eq!(c.name(), "/svc.service");
            // Only the controllers the cgroup has.
            turned_on(&dir, "cpu memory pids");
            assert_eq!(c.enforced(), ["memory", "processes"]);
            let (t, _) = fake("/svc.service", "io", "");
            let e = Cgroups::at(t.path(), "/svc.service", 7, euid(), &yes).unwrap_err();
            assert!(
                e.contains("passes on no memory, cpu or pids controller"),
                "{e}"
            );
        }

        /// Controllers that something else turned off show in the status,
        /// and no command runs in a cgroup that would not hold it.
        #[test]
        fn a_cgroup_whose_controllers_went_off_takes_no_command() {
            if euid() == 0 {
                eprintln!("skipped: root");
                return;
            }
            let (t, dir) = fake("/svc.service", "cpu memory pids", "");
            let c = Cgroups::at(t.path(), "/svc.service", 7, euid(), &yes).unwrap();
            turned_on(&dir, "cpu memory pids");
            assert!(c.lost().is_empty());
            turned_on(&dir, "pids");
            assert_eq!(c.enforced(), ["processes"]);
            assert_eq!(c.lost(), ["memory", "cpu"]);
            let granted = Granted {
                memory_mb: 16,
                cpu_percent: 100,
                processes: 8,
            };
            let e = c.command(&granted).unwrap_err();
            assert!(
                e.contains("no longer passes on the controllers the node turned on"),
                "{e}"
            );
            turned_on(&dir, "memory cpu pids");
            assert!(c.command(&granted).is_ok());
        }

        #[test]
        fn a_command_cgroup_gets_its_limits_and_says_when_memory_killed() {
            if euid() == 0 {
                eprintln!("skipped: root");
                return;
            }
            let (t, dir) = fake("/svc.service", "cpu memory pids", "");
            // Left behind by a node before: numbered past.
            std::fs::create_dir(dir.join("cmd-4")).unwrap();
            let c = Cgroups::at(t.path(), "/svc.service", 7, euid(), &yes).unwrap();
            turned_on(&dir, "cpu memory pids");
            let granted = Granted {
                memory_mb: 16,
                cpu_percent: 150,
                processes: 32,
            };
            // A cgroup of that name is there already: the next one is fresh.
            std::fs::create_dir(dir.join("cmd-5")).unwrap();
            let cg = c.command(&granted).unwrap();
            let d = cg.dir.clone();
            assert_eq!(d.file_name().unwrap(), "cmd-6");
            let read = |f: &str| std::fs::read_to_string(d.join(f)).unwrap();
            assert_eq!(read("memory.max"), (16u64 << 20).to_string());
            assert_eq!(read("memory.oom.group"), "1");
            assert_eq!(read("cpu.max"), "150000 100000");
            assert_eq!(read("pids.max"), "32");
            assert!(cg.procs_fd() >= 0);
            assert!(!cg.out_of_memory());
            let events = |t: &str| std::fs::write(d.join("memory.events"), t).unwrap();
            events("low 0\nhigh 0\nmax 9\noom 1\noom_kill 0\n");
            assert!(
                !cg.out_of_memory(),
                "it was at its limit, nothing was killed"
            );
            // Killed by an OOM from outside: the machine's, or a cgroup
            // above. It never reached its own limit.
            events("max 0\noom 0\noom_kill 5\noom_group_kill 1\n");
            assert!(!cg.out_of_memory(), "not its own limit");
            events("max 9\noom 1\noom_kill 1\n");
            assert!(cg.out_of_memory());
            events("max 9\noom 2\noom_kill 0\noom_group_kill 1\n");
            assert!(cg.out_of_memory());
            assert_eq!(cg.memory_mb(), 16);
        }

        /// Without `cgroup.kill` (Linux before 5.14) each process left is
        /// killed by itself.
        #[test]
        fn without_cgroup_kill_each_process_is_killed() {
            let t = tempfile::tempdir().unwrap();
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            // A folder where the kernel's file would be: no write lands.
            std::fs::create_dir(t.path().join("cgroup.kill")).unwrap();
            std::fs::write(t.path().join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
            kill(t.path());
            let status = child.wait().unwrap();
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
        }
    }
}

/// On Windows no cgroup is needed: each command's job object holds it to
/// its limits ([`job_limits`]), wherever the node runs.
#[cfg(windows)]
#[derive(Debug)]
pub struct Cgroups(());

#[cfg(windows)]
impl Cgroups {
    pub fn find() -> Result<Cgroups, String> {
        Ok(Cgroups(()))
    }

    /// What holds the limits, for `status` and the log.
    pub fn name(&self) -> &str {
        "the command's job object"
    }

    pub fn enforced(&self) -> Vec<&'static str> {
        vec!["memory", "cpu", "processes"]
    }

    pub fn lost(&self) -> Vec<&'static str> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_policy::config::Granted;

    /// A command's job gets its memory in bytes, its CPU as Windows' share
    /// of every CPU, and room for the console host, the stop helper and the
    /// shim beside its processes; a CPU limit of the whole machine holds
    /// nothing.
    #[test]
    fn a_commands_job_gets_its_granted_limits() {
        let g = Granted {
            memory_mb: 512,
            cpu_percent: 200,
            processes: 3,
        };
        let l = job_limits(&g, 8, false);
        assert_eq!(l.memory_bytes, Some(512 << 20));
        assert_eq!(l.cpu_rate, Some(2_500));
        assert_eq!(l.processes, Some(5));
        assert_eq!(job_limits(&g, 8, true).processes, Some(6));
        assert_eq!(job_limits(&g, 2, false).cpu_rate, None);
        let most = Granted {
            memory_mb: u64::MAX,
            cpu_percent: u32::MAX,
            processes: u32::MAX,
        };
        let l = job_limits(&most, 8, true);
        assert_eq!(
            (l.memory_bytes, l.processes),
            (Some(u64::MAX), Some(u32::MAX))
        );
    }
}
