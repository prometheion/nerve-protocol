//! The job object a command runs in on Windows. The shell starts suspended,
//! is put in a job of its own before it runs anything, and only then runs;
//! every process it starts is in that job too, however deep, also when its
//! parent has exited. A cancel, `exec.signal` with `kill`, the session's end
//! and the call's end end the job, and with it every process in it. A
//! timeout and `exec.signal` with `term` or `int` first ask the processes to
//! end (crate::win_stop) and end the job only when they have not after
//! [`GRACE`]. The job closes with the node, so a node that dies leaves no
//! command running.
//!
//! What the job does not hold: a process another program starts on the
//! command's request, such as the WMI provider host (`Win32_Process.Create`),
//! a service or the task scheduler. That process is that program's child and
//! in that program's job. A job does not restrict file access either: it is
//! no confinement. Folder mode adds that with an AppContainer, which the
//! shim starts in the command's job (nerve_sandbox::appcontainer).
//!
//! When Windows makes no job, the command runs anyway and its processes are
//! ended by the walk of crate::tree, best effort. When it makes one but
//! cannot put the shell in it, the command does not run.
//!
//! The choices and their texts are plain logic, tested on every platform;
//! the job itself is crate::win::Job.

use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(windows)]
pub use nerve_service::win::job::Jobless;

/// How long the processes of a command that was asked to end have before
/// its job ends them.
pub const GRACE: Duration = Duration::from_secs(3);

/// How often a stop looks whether the asked processes have ended.
const GRACE_POLL: Duration = Duration::from_millis(50);

/// What the node logs when Windows made no job for a command: it then runs
/// with the walk.
pub fn no_job_warning(err: &dyn Display) -> String {
    format!(
        "cannot make a job object for a command ({err}); its processes are ended by a walk \
         of the process table instead, which misses some"
    )
}

/// Why a command did not run when Windows did not put its shell in its job.
/// `in_job` is whether the shell is in a job already: the node's own, under
/// a service or the task scheduler, which the shell was born into. Windows 8
/// and later nest a new job in that one; a job that allows neither nesting
/// nor breakaway is reported as what it is.
pub fn assign_error(in_job: Option<bool>, err: &dyn Display) -> String {
    match in_job {
        Some(true) => format!(
            "the command was not run: the node runs inside a job of its own (set up by a \
             service or the task scheduler) that lets a command neither have a job nested in \
             it nor break away from it, so the node could not hold the command's processes \
             ({err})"
        ),
        _ => format!(
            "the command was not run: Windows did not put its shell in a job object, so the \
             node could not hold the command's processes ({err})"
        ),
    }
}

/// Something that ends every process it holds: a job object, a fake in the
/// tests.
pub trait End {
    /// Whether the processes were ended.
    fn end(&self) -> bool;
    /// Asks the processes to end on their own; whether any was asked.
    fn ask(&self) -> bool;
    /// Whether no process is left.
    fn empty(&self) -> bool;
    /// Set while a stop of these processes runs ([`Ending::claim_stop`]).
    fn stopping(&self) -> &AtomicBool;
}

/// How one command's processes are ended: through its job, or, when Windows
/// made none, by the walk below its shell (`W`, the walk's record). The job
/// goes with the call, never with the shell's pid: tokio lets go of the
/// shell's handle once the shell has exited, while the call still waits for
/// output a background process of the command may hold, and from then on
/// Windows can give that pid to another process.
pub enum Ending<J, W> {
    Job(Arc<J>),
    Walk(W),
}

impl<J, W: Clone> Clone for Ending<J, W> {
    fn clone(&self) -> Self {
        match self {
            Ending::Job(j) => Ending::Job(j.clone()),
            Ending::Walk(w) => Ending::Walk(w.clone()),
        }
    }
}

impl<J: End, W> Ending<J, W> {
    /// Whether the command has a job.
    pub fn has_job(&self) -> bool {
        matches!(self, Ending::Job(_))
    }

    /// Ends the command's processes. A command with a job is ended through
    /// that job alone, also when Windows did not end it: the walk goes by the
    /// shell's pid, which may name another process by now.
    pub fn end(&self, walk: impl FnOnce(&W)) {
        match self {
            Ending::Job(j) => {
                if !j.end() {
                    tracing::warn!("{}", END_FAILED);
                }
            }
            Ending::Walk(w) => walk(w),
        }
    }

    /// Asks the command's processes to end on their own; whether any was
    /// asked. A command without a job is asked nothing: the walk knows its
    /// processes by pid alone, and a pid may name another process by now.
    pub fn ask(&self) -> bool {
        matches!(self, Ending::Job(j) if j.ask())
    }

    /// Whether a stop of the command may start now: one at a time, so a
    /// `term` sent again and again while a stop runs starts no more helpers
    /// and threads. [`Ending::stop`] lets go of it at its end. A command
    /// without a job is ended at once and claims nothing.
    pub fn claim_stop(&self) -> bool {
        match self {
            Ending::Job(j) => !j.stopping().swap(true, Ordering::SeqCst),
            Ending::Walk(_) => true,
        }
    }

    /// Asks the command's processes to end, gives them `grace` to do so,
    /// and then ends what is left (blocking). When none could be asked they
    /// are ended at once. Lets go of the claim of [`Ending::claim_stop`].
    pub fn stop(&self, grace: Duration, walk: impl FnOnce(&W)) {
        if let Ending::Job(j) = self
            && j.ask()
        {
            let until = Instant::now() + grace;
            while !j.empty() && Instant::now() < until {
                std::thread::sleep(GRACE_POLL);
            }
        }
        self.end(walk);
        if let Ending::Job(j) = self {
            j.stopping().store(false, Ordering::SeqCst);
        }
    }
}

/// What the node logs when Windows did not end a command's job.
const END_FAILED: &str = "Windows did not end a command's job object; its processes end when the \
     call has ended and the node closes the job";

#[cfg(windows)]
pub use sys::{CONSOLE, Held, SUSPENDED, adopt, make};

#[cfg(windows)]
mod sys {
    use std::os::windows::io::{BorrowedHandle, OwnedHandle};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use super::{End, assign_error, no_job_warning};
    use crate::win::{self, Job};
    use crate::win_stop::Asker;

    /// The creation flag that starts the shell suspended, so it runs nothing
    /// before it is in its job.
    pub const SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    /// The creation flag that gives the shell a console of its own, without
    /// a window: the Ctrl+C that asks the command to end goes to every
    /// process on its console (crate::win_stop), so the console must not be
    /// the node's, which a node started in a terminal has.
    pub const CONSOLE: u32 = windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    /// A command's job with what asks its processes to end: a handle to its
    /// shell, held so the shell's pid names no other process while the call
    /// lasts, and how the node starts the helper that asks (crate::win_stop).
    pub struct Held {
        job: Job,
        shell: Option<OwnedHandle>,
        asker: Asker,
        stopping: AtomicBool,
    }

    impl Held {
        pub fn new(job: Job, shell: Option<OwnedHandle>, asker: Asker) -> Held {
            Held {
                job,
                shell,
                asker,
                stopping: AtomicBool::new(false),
            }
        }

        /// Whether the job ended the command at its memory limit.
        pub fn out_of_memory(&self) -> bool {
            self.job.out_of_memory()
        }
    }

    impl End for Held {
        fn end(&self) -> bool {
            self.job.terminate()
        }

        fn ask(&self) -> bool {
            crate::win_stop::ask(&self.job, self.shell.as_ref(), &self.asker)
        }

        fn empty(&self) -> bool {
            self.job.active() == Some(0)
        }

        fn stopping(&self) -> &AtomicBool {
            &self.stopping
        }
    }

    /// A job for the next command; `None`, logged, when Windows makes none
    /// (the command then starts as it is and the walk ends its processes).
    pub fn make() -> Option<Job> {
        match Job::new() {
            Ok(j) => Some(j),
            Err(e) => {
                tracing::warn!("{}", no_job_warning(&e));
                None
            }
        }
    }

    /// Puts the suspended shell `child` in `job` and lets it run; the job is
    /// then the call's, which asks its processes to end with `asker`, ends
    /// it and closes it at its end. On an error the shell has run nothing
    /// and is ended.
    pub fn adopt(
        job: Job,
        child: &mut tokio::process::Child,
        asker: Asker,
    ) -> Result<Arc<Held>, String> {
        let (Some(pid), Some(handle)) = (child.id(), child.raw_handle()) else {
            return Err("the command was not run: its shell ended before it started".into());
        };
        let raw = handle;
        let handle = handle as win::Handle;
        if let Err(e) = job.assign(handle) {
            let why = assign_error(win::in_job(handle), &e);
            let _ = child.start_kill();
            return Err(why);
        }
        // The shell is suspended and the node holds its handle, so the pid
        // is still the shell's here.
        if let Err(e) = win::resume(pid) {
            job.terminate();
            return Err(format!(
                "the command was not run: its shell could not be resumed ({e})"
            ));
        }
        // A copy of its own: tokio lets go of the shell's handle once the
        // shell has exited. Without one the command is only asked through
        // the processes the node can open in its job.
        // SAFETY: the child's handle is open while `child` lives.
        let shell = unsafe { BorrowedHandle::borrow_raw(raw) }
            .try_clone_to_owned()
            .ok();
        Ok(Arc::new(Held::new(job, shell, asker)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A job that counts its ends and asks and ends, or not, as told. Its
    /// processes heed an ask (`heard`) when `heed` is set: they are gone
    /// after that many looks; otherwise they stay until the end.
    struct Fake {
        ends: Arc<AtomicUsize>,
        works: bool,
        asks: Arc<AtomicUsize>,
        heard: bool,
        heed: Option<usize>,
        looks: AtomicUsize,
        stopping: AtomicBool,
    }

    impl End for Fake {
        fn end(&self) -> bool {
            self.ends.fetch_add(1, Ordering::SeqCst);
            self.works
        }

        fn ask(&self) -> bool {
            self.asks.fetch_add(1, Ordering::SeqCst);
            self.heard
        }

        fn empty(&self) -> bool {
            let looks = self.looks.fetch_add(1, Ordering::SeqCst) + 1;
            self.heed.is_some_and(|n| looks >= n)
        }

        fn stopping(&self) -> &AtomicBool {
            &self.stopping
        }
    }

    fn fake(works: bool) -> (Fake, Arc<AtomicUsize>) {
        let (f, ends, _) = asked(false, None);
        (Fake { works, ..f }, ends)
    }

    /// A job whose processes hear an ask or not, and heed it after `heed`
    /// looks or never; with its count of ends and of asks.
    fn asked(heard: bool, heed: Option<usize>) -> (Fake, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let ends = Arc::new(AtomicUsize::new(0));
        let asks = Arc::new(AtomicUsize::new(0));
        (
            Fake {
                ends: ends.clone(),
                works: true,
                asks: asks.clone(),
                heard,
                heed,
                looks: AtomicUsize::new(0),
                stopping: AtomicBool::new(false),
            },
            ends,
            asks,
        )
    }

    /// A stop asks first and ends the job only after: at once when the
    /// processes heed the ask, after the grace when they ignore it, and
    /// without waiting when none could be asked.
    #[test]
    fn a_stop_asks_first_and_ends_after_the_grace() {
        let grace = Duration::from_millis(600);
        let timed = |f: Fake| {
            let e: Ending<Fake, u32> = Ending::Job(Arc::new(f));
            let t = Instant::now();
            e.stop(grace, |_| panic!("a command with a job was walked"));
            t.elapsed()
        };
        let (heeds, ends, asks) = asked(true, Some(2));
        let took = timed(heeds);
        assert_eq!(asks.load(Ordering::SeqCst), 1);
        assert_eq!(
            ends.load(Ordering::SeqCst),
            1,
            "what was left was not ended"
        );
        assert!(took < grace, "waited {took:?} for processes that had ended");
        let (ignores, ends, asks) = asked(true, None);
        let took = timed(ignores);
        assert_eq!(asks.load(Ordering::SeqCst), 1);
        assert_eq!(
            ends.load(Ordering::SeqCst),
            1,
            "an ignored ask ended nothing"
        );
        assert!(took >= grace, "ended after {took:?}, before the grace");
        let (deaf, ends, asks) = asked(false, None);
        let took = timed(deaf);
        assert_eq!(asks.load(Ordering::SeqCst), 1);
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        assert!(took < grace, "waited {took:?} though nothing was asked");
    }

    /// One stop at a time: a second claim while a stop runs is refused, and
    /// the stop lets go of its claim when it has ended the job. A command
    /// without a job claims nothing.
    #[test]
    fn a_command_has_one_stop_at_a_time() {
        let (f, ends, asks) = asked(true, Some(1));
        let e: Ending<Fake, u32> = Ending::Job(Arc::new(f));
        assert!(e.claim_stop());
        assert!(!e.claim_stop(), "a second stop was let in");
        assert!(!e.clone().claim_stop(), "a copy started a stop of its own");
        e.stop(Duration::from_secs(60), |_| panic!("walked"));
        assert_eq!(asks.load(Ordering::SeqCst), 1);
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        assert!(e.claim_stop(), "the claim outlived its stop");
        let w: Ending<Fake, u32> = Ending::Walk(20);
        assert!(w.claim_stop() && w.claim_stop());
    }

    /// A command without a job is asked nothing and walked at once: the
    /// walk knows its processes by pid alone.
    #[test]
    fn a_stop_walks_a_command_without_a_job_at_once() {
        let e: Ending<Fake, u32> = Ending::Walk(20);
        assert!(!e.ask());
        let mut walked = None;
        let t = Instant::now();
        e.stop(Duration::from_secs(60), |pid| walked = Some(*pid));
        assert_eq!(walked, Some(20));
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    /// A command with a job is ended through it, one without (Windows made
    /// none) by the walk.
    #[test]
    fn the_walk_ends_only_a_command_without_a_job() {
        let (job, ends) = fake(true);
        let with: Ending<Fake, u32> = Ending::Job(Arc::new(job));
        assert!(with.has_job());
        with.end(|_| panic!("a command with a job was walked"));
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        let without: Ending<Fake, u32> = Ending::Walk(20);
        assert!(!without.has_job());
        let mut walked = None;
        without.end(|pid| walked = Some(*pid));
        assert_eq!(walked, Some(20));
    }

    /// Two commands whose shells had the same pid, the first one's long
    /// exited while a background process still held its output: each call
    /// ends its own job and nothing else, and a job Windows did not end is
    /// not walked either, since the pid may be another process's by now.
    #[test]
    fn a_call_ends_its_own_job_whatever_pid_its_shell_had() {
        let (a, a_ends) = fake(true);
        let (b, b_ends) = fake(true);
        let a: Ending<Fake, u32> = Ending::Job(Arc::new(a));
        let b: Ending<Fake, u32> = Ending::Job(Arc::new(b));
        // `exec.signal` holds a copy; it ends the same job.
        let signal = a.clone();
        a.end(|_| panic!("walked"));
        signal.end(|_| panic!("walked"));
        assert_eq!(a_ends.load(Ordering::SeqCst), 2);
        assert_eq!(b_ends.load(Ordering::SeqCst), 0, "A's end ended B's job");
        drop((a, signal));
        b.end(|_| panic!("walked"));
        assert_eq!(b_ends.load(Ordering::SeqCst), 1);
        let (broken, ends) = fake(false);
        let broken: Ending<Fake, u32> = Ending::Job(Arc::new(broken));
        broken.end(|_| panic!("a job Windows did not end was walked"));
        assert_eq!(ends.load(Ordering::SeqCst), 1);
    }

    /// The texts say what happened and that the command did not run.
    #[test]
    fn the_texts_say_why() {
        let e = "Access is denied. (os error 5)";
        let nested = assign_error(Some(true), &e);
        assert!(nested.starts_with("the command was not run: "), "{nested}");
        assert!(
            nested.contains("neither have a job nested in it nor break away"),
            "{nested}"
        );
        assert!(
            nested.ends_with("(Access is denied. (os error 5))"),
            "{nested}"
        );
        for in_job in [Some(false), None] {
            let other = assign_error(in_job, &e);
            assert!(
                other.starts_with("the command was not run: Windows did not put its shell"),
                "{other}"
            );
            assert!(!other.contains("nested"), "{other}");
        }
        let w = no_job_warning(&"Not enough quota. (os error 1816)");
        assert!(w.contains("(Not enough quota. (os error 1816))"), "{w}");
        assert!(w.contains("walk of the process table"), "{w}");
    }
}
