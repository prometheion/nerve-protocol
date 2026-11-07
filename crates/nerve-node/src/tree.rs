//! A command's process tree on Windows when Windows made no job object for
//! it (crate::job), best effort: the node polls the process table while the
//! command runs and remembers every process it saw below the shell, so a
//! grandchild whose parent already exited still counts when the command is
//! cancelled, times out or ends. It misses what never shows as a
//! descendant: a process started through WMI, a service or the task
//! scheduler (its parent is that service), and a child of a process that
//! started and exited between two polls. The job holds the last one too.
//!
//! The walk itself ([`Tree`]) is plain logic over a process list, so it is
//! tested on every platform; the process table and the kill are Windows only.

use std::collections::HashMap;

/// A process as the process table lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
}

/// The processes seen below a command's shell, by pid, with their creation
/// time. One that exited stays in until the poll that no longer lists it, so
/// the children it left behind are still found by their parent pid; after
/// that poll it can have no child that was not found.
#[derive(Debug, Clone)]
pub struct Tree {
    root: u32,
    known: HashMap<u32, u64>,
}

impl Tree {
    /// A tree of the shell `root`, created at `start`.
    pub fn new(root: u32, start: u64) -> Tree {
        Tree {
            root,
            known: HashMap::from([(root, start)]),
        }
    }

    /// Adds the processes of `procs` that are below a known one, through
    /// any number of levels; whether one was new. `start(pid)` is a
    /// process's creation time, `None` when it cannot be read (it exited,
    /// or it is not this user's): such a process is left out, the node
    /// could not end it either.
    ///
    /// Windows reuses pids, so a parent pid alone proves nothing: a child
    /// counts only when it started after the known parent, and, when the
    /// parent's pid now belongs to a newer process, before that one.
    pub fn grow(&mut self, procs: &[Proc], start: impl Fn(u32) -> Option<u64>) -> bool {
        let mut times: HashMap<u32, Option<u64>> = HashMap::new();
        let mut time = |pid: u32| *times.entry(pid).or_insert_with(|| start(pid));
        let mut grew = false;
        loop {
            let mut added = false;
            for p in procs {
                if p.pid == p.ppid || self.known.contains_key(&p.pid) {
                    continue;
                }
                let Some(&parent) = self.known.get(&p.ppid) else {
                    continue;
                };
                let Some(child) = time(p.pid) else {
                    continue;
                };
                if child < parent {
                    continue;
                }
                let holder = procs
                    .iter()
                    .any(|q| q.pid == p.ppid)
                    .then(|| time(p.ppid))
                    .flatten();
                if holder.is_some_and(|h| h != parent && child >= h) {
                    continue;
                }
                self.known.insert(p.pid, child);
                added = true;
            }
            if !added {
                break;
            }
            grew = true;
        }
        // What exited, or whose pid now names another process, is dropped;
        // its children were found above. An empty list is a table that could
        // not be read, not one without processes.
        if !procs.is_empty() {
            let root = self.root;
            self.known.retain(|pid, at| {
                *pid == root
                    || (procs.iter().any(|p| p.pid == *pid) && time(*pid).is_none_or(|t| t == *at))
            });
        }
        grew
    }

    /// Every process seen, with its creation time.
    pub fn members(&self) -> Vec<(u32, u64)> {
        let mut m: Vec<(u32, u64)> = self.known.iter().map(|(p, t)| (*p, *t)).collect();
        m.sort_unstable();
        m
    }
}

/// How often the process table is read while a command runs: a parent that
/// starts a child and exits within this is not seen.
#[cfg(windows)]
pub const POLL: std::time::Duration = std::time::Duration::from_millis(25);

#[cfg(windows)]
pub use watch::{Watch, watch};

#[cfg(windows)]
mod watch {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::{POLL, Tree};
    use crate::win;

    /// The record of one command's processes, held by its call: it goes by
    /// the creation times it saw, never by a pid alone, which Windows may
    /// have given to another process since.
    pub struct Watch {
        tree: Mutex<Tree>,
        stop: AtomicBool,
    }

    impl Watch {
        fn poll(&self) -> bool {
            let procs = win::processes();
            nerve_transport::sync::lock(&self.tree).grow(&procs, win::start_of)
        }

        /// Stops recording.
        pub fn forget(&self) {
            self.stop.store(true, Ordering::SeqCst);
        }

        /// Ends every process recorded and every one the process table shows
        /// below them now, the shell included. Rounds repeat while they find
        /// new processes, which catches a child started during the kill.
        pub fn kill(&self) {
            self.poll();
            for _ in 0..5 {
                let members = nerve_transport::sync::lock(&self.tree).members();
                for (p, start) in members {
                    win::terminate(p, start);
                }
                if !self.poll() {
                    break;
                }
            }
        }
    }

    /// Starts recording the processes below the shell `pid` on a thread of
    /// its own, until [`Watch::forget`]; `None` when the shell's creation
    /// time cannot be read, and then nothing can be ended safely.
    pub fn watch(pid: u32) -> Option<Arc<Watch>> {
        let start = win::start_of(pid)?;
        let w = Arc::new(Watch {
            tree: Mutex::new(Tree::new(pid, start)),
            stop: AtomicBool::new(false),
        });
        let polled = w.clone();
        let _ = std::thread::Builder::new()
            .name("nerve-exec-tree".into())
            .spawn(move || {
                while !polled.stop.load(Ordering::SeqCst) {
                    polled.poll();
                    std::thread::sleep(POLL);
                }
            });
        Some(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procs(list: &[(u32, u32)]) -> Vec<Proc> {
        list.iter().map(|&(pid, ppid)| Proc { pid, ppid }).collect()
    }

    fn times(list: &[(u32, u64)]) -> impl Fn(u32) -> Option<u64> + use<> {
        let m: HashMap<u32, u64> = list.iter().copied().collect();
        move |pid| m.get(&pid).copied()
    }

    fn pids(t: &Tree) -> Vec<u32> {
        t.members().into_iter().map(|(p, _)| p).collect()
    }

    /// A grandchild whose parent exited before the kill: the parent was
    /// seen by an earlier poll, so the grandchild is found by its parent
    /// pid (the case `taskkill /T` misses).
    #[test]
    fn a_grandchild_counts_after_its_parent_exited() {
        let mut t = Tree::new(10, 100);
        // Poll 1: the shell started a cmd.
        assert!(t.grow(&procs(&[(4, 0), (10, 4), (20, 10)]), times(&[(20, 200)])));
        // Poll 2: the cmd started ping and exited; its pid is gone.
        let now = procs(&[(4, 0), (10, 4), (30, 20), (99, 4)]);
        let start = times(&[(10, 100), (30, 300), (99, 50)]);
        assert!(t.grow(&now, &start));
        // The exited cmd is dropped once its child is found.
        assert_eq!(pids(&t), [10, 30]);
        // Nothing new: the unrelated 99 stays out.
        assert!(!t.grow(&now, &start));
        // A table that could not be read forgets nothing.
        t.grow(&[], &start);
        assert_eq!(pids(&t), [10, 30]);
    }

    /// Without a poll in between, the live links are walked to any depth.
    #[test]
    fn the_live_tree_is_walked_to_any_depth() {
        let mut t = Tree::new(10, 100);
        // Listed child before parent, so the walk needs a second round.
        let list = procs(&[(40, 30), (30, 20), (20, 10), (50, 1)]);
        t.grow(&list, times(&[(20, 200), (30, 300), (40, 400), (50, 150)]));
        assert_eq!(pids(&t), [10, 20, 30, 40]);
    }

    /// A pid Windows gave to a new process after a known one exited: the
    /// new one's children are not below the shell, the old one's are.
    #[test]
    fn a_reused_pid_does_not_adopt_strangers() {
        let mut t = Tree::new(10, 100);
        t.grow(&procs(&[(20, 10)]), times(&[(20, 200)]));
        // 20 exited; a stranger got pid 20 at 500 and started 60. The old 20
        // left 30 behind, started before the stranger.
        let list = procs(&[(10, 4), (20, 7), (60, 20), (30, 20)]);
        let start = times(&[(10, 100), (20, 500), (60, 600), (30, 300)]);
        t.grow(&list, &start);
        // The stranger is never taken for the old 20, which is forgotten.
        assert_eq!(pids(&t), [10, 30]);
        // So the stranger's children stay out also once it exited.
        t.grow(&procs(&[(10, 4), (60, 20), (30, 20)]), &start);
        assert_eq!(pids(&t), [10, 30]);
    }

    /// A process whose parent pid names the shell but that is older than
    /// the shell had another parent with that pid.
    #[test]
    fn a_process_older_than_its_parent_is_not_its_child() {
        let mut t = Tree::new(10, 100);
        t.grow(&procs(&[(20, 10)]), times(&[(20, 50)]));
        assert_eq!(pids(&t), [10]);
    }

    /// What the node cannot read the start of, it cannot end either; and a
    /// process started through WMI has the WMI host as its parent, so it is
    /// not below the shell (the gap only a Job Object closes).
    #[test]
    fn unreadable_and_foreign_processes_stay_out() {
        let mut t = Tree::new(10, 100);
        let list = procs(&[(20, 10), (800, 4), (81, 800)]);
        t.grow(&list, times(&[(800, 10), (81, 300)]));
        assert_eq!(pids(&t), [10]);
    }
}
