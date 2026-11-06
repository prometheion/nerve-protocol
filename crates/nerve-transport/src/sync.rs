//! What a poisoned lock means in the center and the node: the process ends.
//!
//! A thread that panics while it holds a std lock leaves it poisoned: what
//! the lock guards may be half changed. Going on with that state is worse
//! for a security tool than a clean start, so every lock of the programs is
//! taken through [`lock`], [`read`] or [`write`] (or [`try_lock`],
//! [`into_inner`]). On a poisoned lock they
//! write one line to the log that names the lock, and end the process with
//! [`POISONED`]. The service manager starts it again with clean state:
//! systemd's `Restart=on-failure`, the Windows service's failure actions
//! (docs/dev/service.md).
//!
//! The process ends with an exit code, not an abort: an abort could leave a
//! core dump with the keys and passwords the program holds.
//!
//! A lock that guards no data and only takes turns ([`turn`]) holds nothing
//! a panic could leave half changed, so its poisoning is cleared instead.

use std::cell::Cell;
use std::io::Write;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};

/// The exit code of a process that found a lock poisoned (`EX_SOFTWARE`).
pub const POISONED: i32 = 70;

thread_local! {
    /// Set while this thread says a lock is poisoned: the log's own lock
    /// may be the one, and the line then goes to stderr only.
    static TELLING: Cell<bool> = const { Cell::new(false) };
}

/// Locks `m`; a poisoned one ends the process.
#[track_caller]
pub fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        // The guard in the error goes first: the log's own lock may be the
        // one, and saying so takes it again.
        Err(p) => {
            drop(p);
            poisoned::<T>()
        }
    }
}

/// Locks `m` when no other holds it: `None` when one does. A poisoned one
/// ends the process.
#[track_caller]
pub fn try_lock<T: ?Sized>(m: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(p)) => {
            drop(p);
            poisoned::<T>()
        }
    }
}

/// What `m` held, once no other holds it; a poisoned one ends the process.
#[track_caller]
pub fn into_inner<T>(m: Mutex<T>) -> T {
    match m.into_inner() {
        Ok(v) => v,
        Err(_) => poisoned::<T>(),
    }
}

/// Takes `l` to read; a poisoned one ends the process.
#[track_caller]
pub fn read<T: ?Sized>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match l.read() {
        Ok(g) => g,
        Err(p) => {
            drop(p);
            poisoned::<T>()
        }
    }
}

/// Takes `l` to write; a poisoned one ends the process.
#[track_caller]
pub fn write<T: ?Sized>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match l.write() {
        Ok(g) => g,
        Err(p) => {
            drop(p);
            poisoned::<T>()
        }
    }
}

/// Takes the turn of a lock that guards no data, only who goes next. Its
/// poisoning says nothing about any state, so it is cleared: a walk whose
/// file is made to survive a crash in the middle goes on after one.
pub fn turn(m: &Mutex<()>) -> MutexGuard<'_, ()> {
    m.lock().unwrap_or_else(|p| {
        m.clear_poison();
        p.into_inner()
    })
}

/// [`turn`] when no other holds it: `None` when one does.
pub fn try_turn(m: &Mutex<()>) -> Option<MutexGuard<'_, ()>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(p)) => {
            m.clear_poison();
            Some(p.into_inner())
        }
    }
}

/// Says which lock is poisoned and ends the process. The lock is named by
/// what it holds and where it was taken.
#[cold]
#[track_caller]
fn poisoned<T: ?Sized>() -> ! {
    let at = std::panic::Location::caller();
    let line = format!(
        "the lock on {} taken at {}:{} is poisoned: a thread panicked while it held it, so what it guards may be half changed; the program ends and its service starts it again",
        std::any::type_name::<T>(),
        at.file(),
        at.line()
    );
    let again = TELLING.with(|t| t.replace(true));
    if again || crate::log::global().is_none() {
        // Not `eprintln!`: it panics when stderr cannot be written, and the
        // panic would unwind past the exit below.
        let _ = writeln!(std::io::stderr(), "{line}");
    } else {
        tracing::error!("{line}");
    }
    std::process::exit(POISONED);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Which poisoned lock a child test takes, and where it logs.
    const CHILD: &str = "NERVE_TEST_POISON";
    const LOG_DIR: &str = "NERVE_TEST_POISON_LOG";

    /// Poisons `m`: a thread panics while it holds it.
    fn poison<T: Send + 'static>(m: &Arc<Mutex<T>>) {
        let m = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m.lock().unwrap();
            panic!("a panic under the lock, on purpose");
        })
        .join();
    }

    /// Runs this test again in a child process with `what`; its exit code,
    /// its stderr and the log file it wrote. A child that hangs (a lock
    /// taken again while it is held) is killed after a while.
    fn child(name: &str, what: &str) -> (Option<i32>, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let mut c = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("sync::tests::{name}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, what)
            .env(LOG_DIR, dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while c.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > until {
                let _ = c.kill();
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let o = c.wait_with_output().unwrap();
        let log = std::fs::read_to_string(crate::log::file_in(dir.path())).unwrap_or_default();
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
            log,
        )
    }

    /// In a child: the process's log with its file, as a program has it.
    fn child_log() {
        let log = crate::log::install(crate::log::Level::Info, false);
        log.attach_file(crate::log::file_in(std::path::Path::new(
            &std::env::var_os(LOG_DIR).unwrap(),
        )))
        .unwrap();
    }

    #[test]
    fn a_poisoned_lock_ends_the_process_after_one_line_that_names_it() {
        match std::env::var(CHILD).as_deref() {
            Ok("mutex") => {
                child_log();
                let m = Arc::new(Mutex::new(vec![1u8]));
                poison(&m);
                let _held = lock(&m);
                unreachable!("the process went on");
            }
            Ok("rwlock") => {
                child_log();
                let l = Arc::new(RwLock::new(String::new()));
                let l2 = l.clone();
                let _ = std::thread::spawn(move || {
                    let _g = l2.write().unwrap();
                    panic!("a panic under the lock, on purpose");
                })
                .join();
                let _held = read(&l);
                unreachable!("the process went on");
            }
            Ok("rwlock_write") => {
                child_log();
                let l = Arc::new(RwLock::new(String::new()));
                let l2 = l.clone();
                let _ = std::thread::spawn(move || {
                    let _g = l2.write().unwrap();
                    panic!("a panic under the lock, on purpose");
                })
                .join();
                let _held = write(&l);
                unreachable!("the process went on");
            }
            Ok("try_lock") => {
                child_log();
                let m = Arc::new(Mutex::new(vec![1u8]));
                poison(&m);
                let _held = try_lock(&m);
                unreachable!("the process went on");
            }
            Ok("into_inner") => {
                child_log();
                let m = Arc::new(Mutex::new(vec![1u8]));
                poison(&m);
                let m = Arc::try_unwrap(m).unwrap();
                let _held = into_inner(m);
                unreachable!("the process went on");
            }
            Ok(_) => return,
            Err(_) => {}
        }
        for (what, holds) in [
            ("mutex", "alloc::vec::Vec<u8>"),
            ("rwlock", "alloc::string::String"),
            ("rwlock_write", "alloc::string::String"),
            ("try_lock", "alloc::vec::Vec<u8>"),
            ("into_inner", "alloc::vec::Vec<u8>"),
        ] {
            let (code, stderr, log) = child(
                "a_poisoned_lock_ends_the_process_after_one_line_that_names_it",
                what,
            );
            assert_eq!(code, Some(POISONED), "{what}: {stderr}");
            let lines: Vec<&str> = log.lines().filter(|l| l.contains("poisoned")).collect();
            assert_eq!(lines.len(), 1, "{what}: {log}");
            assert!(
                lines[0].contains(&format!("the lock on {holds} taken at "))
                    && lines[0].contains("sync.rs:")
                    && lines[0].contains("\"level\":\"error\""),
                "{what}: {log}"
            );
        }
    }

    /// The log's own lock poisoned: the line cannot go to the log, so it
    /// goes to stderr, and the process still ends.
    #[test]
    fn a_poisoned_log_says_so_on_stderr_and_ends() {
        if std::env::var(CHILD).is_ok() {
            let log = crate::log::install(crate::log::Level::Info, false);
            let held = log.clone();
            let _ = std::thread::spawn(move || held.poison_for_test()).join();
            tracing::error!("an entry after the panic");
            unreachable!("the process went on");
        }
        let (code, stderr, _) = child("a_poisoned_log_says_so_on_stderr_and_ends", "log");
        assert_eq!(code, Some(POISONED), "{stderr}");
        assert_eq!(stderr.matches("is poisoned").count(), 1, "{stderr}");
        assert!(
            stderr.contains("the lock on nerve_transport::log::Inner"),
            "{stderr}"
        );
    }

    #[test]
    fn a_turn_survives_a_panic_in_it() {
        let m = Arc::new(Mutex::new(()));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = turn(&m2);
            panic!("a panic in a turn, on purpose");
        })
        .join();
        drop(turn(&m));
        assert!(!m.is_poisoned());
        assert!(try_turn(&m).is_some());
        let _held = turn(&m);
        let m3 = m.clone();
        assert!(
            std::thread::spawn(move || try_turn(&m3).is_none())
                .join()
                .unwrap()
        );
    }

    #[test]
    fn try_lock_is_none_while_another_holds_it() {
        let m = Arc::new(Mutex::new(1));
        let _held = lock(&m);
        let m2 = m.clone();
        assert!(
            std::thread::spawn(move || try_lock(&m2).is_none())
                .join()
                .unwrap()
        );
    }

    /// The log's own lock poisoned and stderr unwritable (a pipe whose
    /// reader is gone): the process still ends with its code.
    #[test]
    #[cfg(unix)]
    fn a_poisoned_lock_ends_the_process_when_stderr_is_closed() {
        if std::env::var(CHILD).is_ok() {
            use std::os::fd::AsRawFd;
            let (r, w) = std::io::pipe().unwrap();
            drop(r);
            // SAFETY: dup2 onto stderr with a descriptor this child owns.
            unsafe extern "C" {
                fn dup2(a: i32, b: i32) -> i32;
                fn signal(sig: i32, h: usize) -> usize;
            }
            unsafe {
                signal(13, 1); // SIGPIPE ignored, as in a Rust program
                dup2(w.as_raw_fd(), 2);
            }
            let m = Arc::new(Mutex::new(()));
            poison(&m);
            let _held = lock(&m);
            unreachable!("the process went on");
        }
        let (code, stderr, _) = child(
            "a_poisoned_lock_ends_the_process_when_stderr_is_closed",
            "x",
        );
        assert_eq!(code, Some(POISONED), "{stderr}");
    }

    /// The rule stays in force: no production code of the programs takes a
    /// std lock around [`lock`] and friends, or shrugs a poisoning off.
    #[test]
    fn no_lock_of_the_programs_is_taken_around_the_rule() {
        let bad = locks_around_the_rule();
        assert!(
            bad.is_empty(),
            "locks taken around nerve_transport::sync:\n{}",
            bad.join("\n")
        );
    }

    /// Production source of the four crates (up to each file's test
    /// module) that calls a poisoning-aware lock method and handles the
    /// result itself.
    fn locks_around_the_rule() -> Vec<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut bad = Vec::new();
        let mut dirs: Vec<std::path::PathBuf> = [
            "nerve-center",
            "nerve-node",
            "nerve-policy",
            "nerve-transport",
        ]
        .iter()
        .map(|c| root.join(c).join("src"))
        .collect();
        while let Some(d) = dirs.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    dirs.push(p);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && !p.ends_with("nerve-transport/src/sync.rs")
                {
                    let text = std::fs::read_to_string(&p).unwrap();
                    // Up to the test module: a `#[cfg(...test...)]` before a `mod`.
                    let lines: Vec<&str> = text.lines().collect();
                    let end = (0..lines.len().saturating_sub(1))
                        .find(|&i| {
                            lines[i].starts_with("#[cfg(")
                                && lines[i].contains("test")
                                && lines[i + 1].contains("mod ")
                        })
                        .unwrap_or(lines.len());
                    let prod = lines[..end].join("\n");
                    let flat: String = prod.split_whitespace().collect::<Vec<_>>().join("");
                    for pat in [
                        "PoisonError",
                        ".lock().unwrap",
                        ".lock().expect",
                        ".lock().ok(",
                        ".try_lock()",
                        ".read().unwrap",
                        ".read().expect",
                        ".write().unwrap",
                        ".write().expect",
                        ".into_inner().unwrap",
                        ".clear_poison(",
                    ] {
                        if flat.contains(pat) {
                            bad.push(format!("{}: {pat}", p.display()));
                        }
                    }
                }
            }
        }
        bad
    }
}
