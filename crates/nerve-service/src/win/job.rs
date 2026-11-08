//! What the node knows of the jobs its commands run in on Windows, as plain
//! logic that the tests run on every platform: whether a caller is in one
//! ([`from_a_command`]), the process list Windows writes ([`listed_ids`]),
//! and the commands that run without a job ([`Jobless`]). The job object
//! itself is [`crate::win::job_object`].

use std::sync::atomic::{AtomicUsize, Ordering};

/// What a job object holds its processes to
/// ([`crate::win::job_object::Job::limit`]); each `None` is no limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobLimits {
    /// The memory all of them may commit, in bytes.
    pub memory_bytes: Option<u64>,
    /// Their CPU rate, in Windows' unit: hundredths of a percent of every
    /// CPU of the machine ([`cpu_rate`]).
    pub cpu_rate: Option<u32>,
    /// Processes at once; Windows counts processes, not threads.
    pub processes: Option<u32>,
}

/// Windows' CPU rate for `percent` of one CPU, the unit the node's limits
/// use on every platform (200 is two CPUs), on a machine of `cpus`:
/// hundredths of a percent of all of them, at least 1. `None` where it
/// would be all of them or more, which holds nothing.
pub fn cpu_rate(percent: u32, cpus: u32) -> Option<u32> {
    let all = u64::from(cpus.max(1)) * 100;
    let percent = u64::from(percent);
    if percent >= all {
        return None;
    }
    Some((percent * 10_000).div_ceil(all).max(1) as u32)
}

/// Something that lists the processes it holds: a job object, a fake in the
/// tests.
pub trait Members {
    /// The ids of the processes in it now, those of jobs nested in it
    /// included.
    fn pids(&self) -> std::io::Result<Vec<u32>>;
}

/// Whether `caller` (a process id; `None` when Windows did not tell it) may
/// be a process of a command the node runs: such a caller must not change
/// the node (crate::pipe). `commands` holds the job of each command running
/// now, `None` for one Windows made no job for.
///
/// It errs on the side of the refusal: a caller without an id, any command
/// without a job (its processes cannot be told apart from others) and a job
/// whose processes cannot be listed all refuse. A process stays in its job
/// for its whole life and its children are born into it, so one that is in
/// no job of a running command is no command's.
pub fn from_a_command<'a, J: Members + 'a>(
    caller: Option<u32>,
    commands: impl IntoIterator<Item = Option<&'a J>>,
) -> bool {
    let Some(caller) = caller else {
        return true;
    };
    commands.into_iter().any(|c| match c {
        Some(job) => job.pids().map_or(true, |pids| pids.contains(&caller)),
        None => true,
    })
}

/// Where the ids start in the JOBOBJECT_BASIC_PROCESS_ID_LIST Windows
/// writes: after its two counts, at a pointer's alignment (checked against
/// windows-sys in crate::win).
pub const IDS_AT: usize = 8;

/// The process ids in a JOBOBJECT_BASIC_PROCESS_ID_LIST that Windows wrote
/// into `list`: two u32 counts, the processes in the job and the ids
/// listed, then the ids, one pointer-sized word each. `None` when the job
/// holds more processes than are listed: ask again with more room. Whatever
/// does not add up is an error, so the caller refuses rather than taking an
/// id list that is shorter than the job.
pub fn listed_ids(list: &[u8]) -> Result<Option<Vec<u32>>, String> {
    let count = |at: usize| {
        list.get(at..at + 4)
            .map(|b| u32::from_ne_bytes(b.try_into().expect("four bytes")) as usize)
    };
    let (Some(in_job), Some(listed)) = (count(0), count(4)) else {
        return Err("the job's process list is cut short".into());
    };
    if in_job > listed {
        return Ok(None);
    }
    let word = std::mem::size_of::<usize>();
    let ids = list
        .get(IDS_AT..)
        .and_then(|rest| rest.get(..listed.checked_mul(word)?))
        .ok_or("the job's process list holds fewer ids than it says")?;
    ids.chunks_exact(word)
        .map(|w| {
            let id = usize::from_ne_bytes(w.try_into().expect("a word"));
            u32::try_from(id).map_err(|_| format!("{id} is no process id"))
        })
        .collect::<Result<Vec<u32>, String>>()
        .map(Some)
}

/// How many commands run now without a job of their own.
static JOBLESS: AtomicUsize = AtomicUsize::new(0);

/// Counts a command that runs without a job while it lives: the control
/// pipe cannot tell its processes from others meanwhile.
pub struct Jobless(());

impl Jobless {
    pub fn count() -> Jobless {
        JOBLESS.fetch_add(1, Ordering::SeqCst);
        Jobless(())
    }
}

impl Drop for Jobless {
    fn drop(&mut self) {
        JOBLESS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How many commands run now without a job of their own.
pub fn jobless() -> usize {
    JOBLESS.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Percent of one CPU becomes a share of every CPU: two CPUs of eight
    /// are a quarter; at least the smallest share; none where the limit is
    /// the whole machine or more.
    #[test]
    fn the_cpu_limit_is_a_share_of_every_cpu() {
        assert_eq!(cpu_rate(200, 8), Some(2_500));
        assert_eq!(cpu_rate(100, 1), None);
        assert_eq!(cpu_rate(50, 1), Some(5_000));
        assert_eq!(cpu_rate(1, 4096), Some(1));
        assert_eq!(cpu_rate(800, 8), None);
        assert_eq!(cpu_rate(900, 8), None);
        assert_eq!(cpu_rate(799, 8), Some(9_988));
        // A machine that says it has none counts as one.
        assert_eq!(cpu_rate(50, 0), Some(5_000));
    }

    /// A job that holds the processes it is told, or cannot list them.
    struct Holds(Option<Vec<u32>>);

    impl Members for Holds {
        fn pids(&self) -> std::io::Result<Vec<u32>> {
            self.0
                .clone()
                .ok_or_else(|| std::io::Error::other("Access is denied. (os error 5)"))
        }
    }

    /// A caller in the job of a running command is refused, one in none of
    /// them is let through; whatever the node cannot tell refuses.
    #[test]
    fn a_caller_in_a_commands_job_is_refused() {
        let (a, b, broken) = (
            Holds(Some(vec![10, 11])),
            Holds(Some(vec![20])),
            Holds(None),
        );
        let two = || [Some(&a), Some(&b)];
        assert!(from_a_command(Some(11), two()));
        assert!(from_a_command(Some(20), two()));
        assert!(!from_a_command(Some(30), two()));
        assert!(!from_a_command::<Holds>(Some(30), []));
        // Without the caller's id nothing can be told.
        assert!(from_a_command::<Holds>(None, []));
        assert!(from_a_command(None, two()));
        // A command without a job, or a job that cannot be listed.
        assert!(from_a_command(Some(30), [Some(&a), None]));
        assert!(from_a_command(Some(30), [Some(&a), Some(&broken)]));
    }

    /// The list Windows writes, as bytes.
    fn list(in_job: u32, ids: &[usize]) -> Vec<u8> {
        let mut b = in_job.to_ne_bytes().to_vec();
        b.extend((ids.len() as u32).to_ne_bytes());
        b.resize(IDS_AT, 0);
        for id in ids {
            b.extend(id.to_ne_bytes());
        }
        b
    }

    /// The ids come out as Windows listed them; a list shorter than the job
    /// asks for more room, and one that does not add up is an error, never
    /// a shorter list.
    #[test]
    fn the_jobs_process_list_is_read_as_windows_writes_it() {
        assert_eq!(listed_ids(&list(2, &[10, 4242])), Ok(Some(vec![10, 4242])));
        assert_eq!(listed_ids(&list(0, &[])), Ok(Some(vec![])));
        // More processes came than the room held.
        assert_eq!(listed_ids(&list(3, &[10, 11])), Ok(None));
        // Room to spare after the ids is not read.
        let mut spare = list(1, &[7]);
        spare.extend([0xff; 16]);
        assert_eq!(listed_ids(&spare), Ok(Some(vec![7])));
        // Counts that promise more ids than the buffer holds, a cut header,
        // an id no process has.
        let mut short = list(2, &[10, 11]);
        short.truncate(short.len() - 1);
        assert!(listed_ids(&short).is_err());
        assert!(listed_ids(&[0; 6]).is_err());
        let mut huge = list(1, &[]);
        huge[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(listed_ids(&huge).is_err());
        #[cfg(target_pointer_width = "64")]
        assert!(listed_ids(&list(1, &[1 << 40])).is_err());
    }

    /// A command without a job counts while it runs.
    #[test]
    fn a_command_without_a_job_counts_while_it_runs() {
        let before = jobless();
        let one = Jobless::count();
        let two = Jobless::count();
        // No other test counts one.
        assert_eq!(jobless(), before + 2);
        drop(one);
        assert_eq!(jobless(), before + 1);
        drop(two);
        assert_eq!(jobless(), before);
    }
}
