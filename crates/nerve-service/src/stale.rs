//! Whether a service still runs an older program than the file it starts
//! from: a package manager replaces the app's program in place, and its
//! script restarts the service that runs it; where that restart failed, the
//! service runs the program it was started with until it restarts. `status`
//! says so (design of #232, 1).
//!
//! Linux only: the service's process started before the file was put in
//! place. The file's change time counts, not its modification time, which a
//! package keeps from its archive; the process's start comes from
//! `/proc/<pid>/stat`, which any user may read. Windows does not replace a
//! running program: `update` moves it aside and restarts the service.

use std::path::Path;

/// The seconds the two times may lie apart without saying anything: the
/// boot time `/proc/stat` gives is whole seconds.
const SLACK: f64 = 2.0;

/// Whether the process `pid` runs an older program than `bin`; `false`
/// when either cannot be told.
pub fn runs_older(pid: u32, bin: &Path) -> bool {
    match (started(pid), changed(bin)) {
        (Some(s), Some(c)) => older(s, c),
        _ => false,
    }
}

/// Whether the running service `unit` (systemd's name, with `.service`)
/// runs an older program than `bin`: only where the unit starts `bin`
/// itself. A node a terminal `nerve-node` installed keeps running that file
/// when the app's package comes after it, and a restart changes nothing.
pub fn service_runs_older(unit: &str, bin: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        if !unit_starts(unit, bin) {
            return false;
        }
        let pid = std::process::Command::new("systemctl")
            .args(["show", "--property=MainPID", "--value", unit])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .filter(|p| *p != 0);
        pid.is_some_and(|p| runs_older(p, bin))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (unit, bin);
        false
    }
}

/// Whether the unit `unit` starts the program `bin`.
#[cfg(target_os = "linux")]
fn unit_starts(unit: &str, bin: &Path) -> bool {
    std::process::Command::new("systemctl")
        .args(["show", "--property=ExecStart", "--value", unit])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| starts(&String::from_utf8_lossy(&o.stdout), bin))
}

/// Whether `exec_start`, what `systemctl show --property=ExecStart` says
/// (`{ path=/usr/bin/nerve ; argv[]=... ; ... }`), starts `bin`.
pub fn starts(exec_start: &str, bin: &Path) -> bool {
    let Some(path) = exec_start
        .split_once("path=")
        .and_then(|(_, rest)| rest.split(" ;").next())
    else {
        return false;
    };
    let path = Path::new(path.trim());
    path == bin || matches!((path.canonicalize(), bin.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

/// Whether a process started at `started` runs an older program than a file
/// changed at `changed` (seconds since 1970).
pub fn older(started: f64, changed: f64) -> bool {
    changed > started + SLACK
}

/// When the process `pid` started, in seconds since 1970.
#[cfg(target_os = "linux")]
pub fn started(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let boot = std::fs::read_to_string("/proc/stat").ok()?;
    started_of(&stat, &boot, clock_ticks())
}

#[cfg(not(target_os = "linux"))]
pub fn started(_pid: u32) -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn clock_ticks() -> f64 {
    // SAFETY: a query without arguments.
    match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        t if t > 0 => t as f64,
        _ => 100.0,
    }
}

/// The start of the process whose `/proc/<pid>/stat` is `stat`, with the
/// machine's `/proc/stat` `boot` and the kernel's clock `ticks` a second.
pub fn started_of(stat: &str, boot: &str, ticks: f64) -> Option<f64> {
    // The program's name, in parentheses, may hold blanks and parentheses:
    // the fields count from its last ")". The start is field 22, the 20th
    // after it.
    let rest = &stat[stat.rfind(')')? + 1..];
    let since_boot: f64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let btime: f64 = boot
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(btime + since_boot / ticks)
}

/// When `bin` was last put in place, in seconds since 1970.
#[cfg(unix)]
pub fn changed(bin: &Path) -> Option<f64> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(bin).ok()?;
    Some(m.ctime() as f64 + m.ctime_nsec() as f64 / 1e9)
}

#[cfg(not(unix))]
pub fn changed(_bin: &Path) -> Option<f64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_put_in_place_after_the_start_is_newer() {
        assert!(older(1000.0, 1010.0));
        assert!(!older(1000.0, 1001.0));
        assert!(!older(1000.0, 900.0));
        let stat = "4242 (nerve (x) y) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 50000 1000 10 18446744073709551615";
        let boot = "cpu  1 2 3\nbtime 1700000000\nprocesses 5\n";
        assert_eq!(started_of(stat, boot, 100.0), Some(1_700_000_500.0));
        assert_eq!(started_of("4242 nerve", boot, 100.0), None);
        assert_eq!(started_of(stat, "cpu 1\n", 100.0), None);
    }

    #[test]
    fn a_service_started_from_another_file_is_not_older() {
        let show = |path: &str| {
            format!(
                "{{ path={path} ; argv[]={path} --state-dir /var/lib/nerve ; ignore_errors=no ; start_time=[n/a] }}"
            )
        };
        let bin = Path::new("/usr/bin/nerve");
        assert!(starts(&show("/usr/bin/nerve"), bin));
        assert!(!starts(&show("/usr/local/bin/nerve-node"), bin));
        assert!(!starts("", bin));
        // A link to the program is the program.
        #[cfg(unix)]
        {
            let d = tempfile::tempdir().unwrap();
            let (real, link) = (d.path().join("nerve"), d.path().join("nerve-center"));
            std::fs::write(&real, "").unwrap();
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(starts(&show(link.to_str().unwrap()), &real));
        }
    }

    /// This test's own process started before a file it writes now, which
    /// its program is not.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_started_before_a_file_written_later() {
        let me = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let s = started(me).unwrap();
        assert!(s <= now + SLACK && s > now - 3600.0, "{s} {now}");
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve");
        std::fs::write(&f, "").unwrap();
        assert!((changed(&f).unwrap() - now).abs() < 5.0);
        // The older of the two: this process's program is not the file.
        assert!(!runs_older(me, &std::env::current_exe().unwrap()));
        assert!(!runs_older(u32::MAX, &f));
    }
}
