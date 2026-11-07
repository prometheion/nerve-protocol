//! The job object a command of the node runs in on Windows: every process
//! it starts is in it, and it ends them all with it. The jobs open now are
//! listed, so the control pipe can tell a caller that is a command's
//! ([`from_a_command`]). A job also holds its processes to the command's
//! limits ([`Job::limit`]): memory, the CPU rate and processes at once.

use std::ffi::c_void;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_JOB_MEMORY_LIMIT;
use windows_sys::Win32::System::Threading::{
    ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, INFINITE,
};

use super::job::JobLimits;

pub type Handle = *mut c_void;

/// A job object of the node's own, closed when dropped. Its limit
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ends every process still in it when
/// the last handle closes, so a node that dies leaves no command behind. It
/// allows no breakaway: a process in it cannot start a child outside it.
/// Every job open is in [`LIVE`] from the moment it is made, before any
/// process is in it. A job with a memory limit has a [`Watch`] of its own.
pub struct Job(Handle, OnceLock<Watch>);

/// The handles of the jobs open now ([`Job`]): only commands run in one.
/// A job leaves the list under its lock before it is closed, so a handle
/// read under the lock is open.
static LIVE: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

fn live() -> std::sync::MutexGuard<'static, Vec<usize>> {
    nerve_transport::sync::lock(&LIVE)
}

/// Whether `caller` may be a process of a command the node runs
/// ([`super::job::from_a_command`]): it is in a job the node holds open, or
/// a command runs without a job, so its processes cannot be told apart.
pub fn from_a_command(caller: Option<u32>) -> bool {
    let live = live();
    let jobs: Vec<Listed> = live.iter().map(|&h| Listed(h as Handle)).collect();
    let jobless = std::iter::repeat_n(None, super::job::jobless());
    super::job::from_a_command(caller, jobs.iter().map(Some).chain(jobless))
}

/// A job of [`LIVE`], read while its lock is held.
struct Listed(Handle);

impl super::job::Members for Listed {
    fn pids(&self) -> io::Result<Vec<u32>> {
        process_ids(self.0)
    }
}

// The ids follow the counts where super::job::listed_ids reads them.
const _: () = assert!(
    std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList) == super::job::IDS_AT
);

/// The ids of the processes in job `job` now, those of jobs nested in it
/// included.
fn process_ids(job: Handle) -> io::Result<Vec<u32>> {
    let word = std::mem::size_of::<usize>();
    let mut room = 64usize;
    for _ in 0..8 {
        let bytes = super::job::IDS_AT + room * word;
        // Words, so the buffer is aligned for the structure.
        let mut buf = vec![0usize; bytes.div_ceil(word)];
        // SAFETY: the job is open; the buffer holds `bytes` bytes.
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr().cast(),
                bytes as u32,
                std::ptr::null_mut(),
            )
        } != 0;
        if !ok {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
                return Err(e);
            }
        }
        // SAFETY: the buffer holds `bytes` initialised bytes.
        let list = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
        match super::job::listed_ids(list) {
            Ok(Some(ids)) if ok => return Ok(ids),
            Err(e) if ok => return Err(io::Error::other(e)),
            // Processes came meanwhile: room for them and some more.
            _ => {
                let in_job = u32::from_ne_bytes(list[..4].try_into().expect("four bytes"));
                room = room.max(in_job as usize) * 2;
            }
        }
    }
    Err(io::Error::other("the job's processes kept changing"))
}

// SAFETY: a job handle may be used and closed from any thread.
unsafe impl Send for Job {}
// SAFETY: as above; the calls on a job handle are thread safe.
unsafe impl Sync for Job {}

impl Job {
    /// A new, empty, unnamed job.
    pub fn new() -> io::Result<Job> {
        // SAFETY: no security attributes and no name are valid arguments.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job(h, OnceLock::new());
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the job is open and the structure is the one this class
        // takes, with its size.
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0;
        if !ok {
            return Err(io::Error::last_os_error());
        }
        live().push(job.0 as usize);
        Ok(job)
    }

    /// Puts `process` (a handle with PROCESS_SET_QUOTA and PROCESS_TERMINATE,
    /// as a process the node started has) in the job. On Windows 8 and later
    /// a process already in a job (the node's, under a service or the task
    /// scheduler) gets this one nested inside that one.
    // A handle is no pointer this code reads: Windows checks it, and a closed
    // or wrong one is an error.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn assign(&self, process: Handle) -> io::Result<()> {
        // SAFETY: both handles are open.
        if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Ends every process in the job; whether Windows did.
    pub fn terminate(&self) -> bool {
        // SAFETY: the job is open.
        unsafe { TerminateJobObject(self.0, 1) != 0 }
    }

    /// How many processes in the job still run; `None` when Windows cannot
    /// say.
    pub fn active(&self) -> Option<u32> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: the job is open and the structure is the one this class
        // fills, with its size.
        let ok = unsafe {
            QueryInformationJobObject(
                self.0,
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } != 0;
        ok.then_some(info.ActiveProcesses)
    }

    /// The pids of the processes in the job now, nested jobs' included; at
    /// most [`MAX_JOB_PIDS`], none when Windows cannot say. A pid may name
    /// another process as soon as its process exits: the caller opens it
    /// and checks [`Job::holds`] before it trusts it.
    pub fn pids(&self) -> Vec<u32> {
        let mut pids = process_ids(self.0).unwrap_or_default();
        pids.truncate(MAX_JOB_PIDS);
        pids
    }

    /// Whether `process` (a handle with PROCESS_QUERY_LIMITED_INFORMATION)
    /// is in this job.
    // A handle is no pointer this code reads: Windows checks it, and a closed
    // or wrong one is an error.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn holds(&self, process: Handle) -> bool {
        let mut r = 0;
        // SAFETY: both handles are open.
        let ok = unsafe { IsProcessInJob(process, self.0, &mut r) } != 0;
        ok && r != 0
    }
}

/// The most pids [`Job::pids`] reads of one job.
pub const MAX_JOB_PIDS: usize = 1024;

impl Job {
    /// Holds the job's processes to `limits`, before any is in it. Past its
    /// memory Windows gives a process no more, and the job's [`Watch`]
    /// ends the job ([`Job::out_of_memory`] then says so). Past its CPU
    /// rate the processes wait for their next turn. Past its processes a
    /// new one does not start: Windows counts processes, not threads.
    pub fn limit(&self, limits: &JobLimits) -> io::Result<()> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(bytes) = limits.memory_bytes {
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = usize::try_from(bytes).unwrap_or(usize::MAX);
            // Watched before the limit holds, so no hit goes unheard.
            if self.1.get().is_none() {
                let _ = self.1.set(Watch::start(self.0)?);
            }
        }
        if let Some(n) = limits.processes {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = n;
        }
        info.BasicLimitInformation.LimitFlags = flags;
        // SAFETY: the job is open and the structure is the one this class
        // takes, with its size.
        if unsafe {
            SetInformationJobObject(
                self.0,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(rate) = limits.cpu_rate {
            let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                    | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                ..Default::default()
            };
            cpu.Anonymous.CpuRate = rate;
            // SAFETY: as above, for the CPU rate's class and structure.
            if unsafe {
                SetInformationJobObject(
                    self.0,
                    JobObjectCpuRateControlInformation,
                    (&raw const cpu).cast(),
                    std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Whether the job went past its memory limit, and was ended for it.
    /// What Windows said of the job until now is heard first.
    pub fn out_of_memory(&self) -> bool {
        self.1.get().is_some_and(Watch::hit)
    }
}

/// How many CPUs this machine has, in every processor group: what a job's
/// CPU rate is a share of.
pub fn cpus() -> u32 {
    // SAFETY: a plain query.
    unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) }.max(1)
}

/// The completion key of the job's own messages on its port.
const JOB_KEY: usize = 1;
/// The completion key that asks the watch to answer, once it has heard
/// what came before.
const FLUSH_KEY: usize = 2;
/// The completion key that ends the watch.
const STOP_KEY: usize = 3;

/// A thread that hears a job's messages on a completion port of its own and
/// ends the job when it goes past its memory limit
/// (JOB_OBJECT_MSG_JOB_MEMORY_LIMIT): Windows only refuses the memory, and
/// a command held to its limits is ended, as a cgroup's is on Linux.
pub struct Watch {
    port: usize,
    hit: Arc<AtomicBool>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    flushed: Mutex<mpsc::Receiver<()>>,
}

impl Watch {
    fn start(job: Handle) -> io::Result<Watch> {
        // SAFETY: a new port, for no file.
        let port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        if port.is_null() {
            return Err(io::Error::last_os_error());
        }
        let link = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_KEY as *mut c_void,
            CompletionPort: port,
        };
        // SAFETY: the job and the port are open; the structure is this
        // class's, with its size.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                (&raw const link).cast(),
                std::mem::size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        } == 0
        {
            let e = io::Error::last_os_error();
            // SAFETY: the port from above, closed once.
            unsafe { CloseHandle(port) };
            return Err(e);
        }
        let hit = Arc::new(AtomicBool::new(false));
        let (tx, flushed) = mpsc::channel();
        let (p, j, h) = (port as usize, job as usize, hit.clone());
        let thread = std::thread::Builder::new()
            .name("job memory".into())
            .spawn(move || listen(p as Handle, j as Handle, &h, &tx));
        let thread = match thread {
            Ok(t) => t,
            Err(e) => {
                // SAFETY: as above.
                unsafe { CloseHandle(port) };
                return Err(e);
            }
        };
        Ok(Watch {
            port: port as usize,
            hit,
            thread: Mutex::new(Some(thread)),
            flushed: Mutex::new(flushed),
        })
    }

    fn post(&self, key: usize) -> bool {
        // SAFETY: the port is open while the watch lives.
        unsafe { PostQueuedCompletionStatus(self.port as Handle, 0, key, std::ptr::null()) != 0 }
    }

    /// Whether the job hit its memory limit: asked after what came before
    /// is heard, or after a second at most.
    fn hit(&self) -> bool {
        let flushed = nerve_transport::sync::lock(&self.flushed);
        if self.post(FLUSH_KEY) {
            let _ = flushed.recv_timeout(Duration::from_secs(1));
        }
        self.hit.load(Ordering::SeqCst)
    }
}

/// The watch's thread: ends the job at its memory limit until it is asked
/// to stop.
fn listen(port: Handle, job: Handle, hit: &AtomicBool, flushed: &mpsc::Sender<()>) {
    loop {
        let (mut message, mut key, mut overlapped) = (0u32, 0usize, std::ptr::null_mut());
        // SAFETY: the port is open until this thread has ended; the three
        // places are written by the call.
        let ok = unsafe {
            GetQueuedCompletionStatus(port, &mut message, &mut key, &mut overlapped, INFINITE)
        };
        if ok == 0 {
            return;
        }
        match key {
            JOB_KEY if message == JOB_OBJECT_MSG_JOB_MEMORY_LIMIT => {
                hit.store(true, Ordering::SeqCst);
                // SAFETY: the job is open until this thread has ended
                // (Job's drop).
                unsafe { TerminateJobObject(job, 1) };
            }
            FLUSH_KEY => {
                let _ = flushed.send(());
            }
            STOP_KEY => return,
            _ => {}
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if self.post(STOP_KEY)
            && let Some(t) = nerve_transport::sync::lock(&self.thread).take()
        {
            let _ = t.join();
        }
        // SAFETY: the port from CreateIoCompletionPort, closed once, after
        // its thread has ended.
        unsafe { CloseHandle(self.port as Handle) };
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // The watch ends the job by its handle: it goes first.
        drop(self.1.take());
        live().retain(|&h| h != self.0 as usize);
        // SAFETY: the handle came from CreateJobObjectW and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Whether `process` is in some job already; `None` when Windows cannot say.
// A handle is no pointer this code reads: Windows checks it, and a closed
// or wrong one is an error.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn in_job(process: Handle) -> Option<bool> {
    let mut r = 0;
    // SAFETY: the process handle is open; a null job asks about any job.
    let ok = unsafe { IsProcessInJob(process, std::ptr::null_mut(), &mut r) } != 0;
    ok.then_some(r != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job takes the three limits as Windows reads them back: the memory
    /// of the whole job, the processes at once, and a hard cap on the CPU
    /// rate; it still ends its processes when it closes.
    #[test]
    fn a_job_takes_its_limits() {
        let job = Job::new().unwrap();
        job.limit(&JobLimits {
            memory_bytes: Some(256 << 20),
            cpu_rate: Some(2_500),
            processes: Some(7),
        })
        .unwrap();
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: the job is open; the structure is this class's.
        let ok = unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw mut info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        let flags = info.BasicLimitInformation.LimitFlags;
        for f in [
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        ] {
            assert_ne!(flags & f, 0, "{flags:#x} lacks {f:#x}");
        }
        assert_eq!(info.JobMemoryLimit, 256 << 20);
        assert_eq!(info.BasicLimitInformation.ActiveProcessLimit, 7);
        let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
        // SAFETY: as above, for the CPU rate.
        let ok = unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectCpuRateControlInformation,
                (&raw mut cpu).cast(),
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        assert_eq!(
            cpu.ControlFlags,
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        );
        // SAFETY: the union holds the rate under these flags.
        assert_eq!(unsafe { cpu.Anonymous.CpuRate }, 2_500);
        // Nothing ran into the limit, and the watch ends with the job.
        assert!(!job.out_of_memory());
        drop(job);
    }
}
