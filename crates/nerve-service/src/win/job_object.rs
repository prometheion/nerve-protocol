//! The job object a command of the node runs in on Windows: every process
//! it starts is in it, and it ends them all with it. The jobs open now are
//! listed, so the control pipe can tell a caller that is a command's
//! ([`from_a_command`]).

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};

pub type Handle = *mut c_void;

/// A job object of the node's own, closed when dropped. Its limit
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ends every process still in it when
/// the last handle closes, so a node that dies leaves no command behind. It
/// allows no breakaway: a process in it cannot start a child outside it.
/// Every job open is in [`LIVE`] from the moment it is made, before any
/// process is in it.
pub struct Job(Handle);

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
        let job = Job(h);
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

impl Drop for Job {
    fn drop(&mut self) {
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
