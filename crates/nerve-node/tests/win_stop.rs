//! A stopped command on Windows is asked to end before its job ends it
//! (nerve_node::win_stop): one that heeds Ctrl+C ends and cleans up, on a
//! timeout and on `exec.signal`; one that ignores it is ended after the
//! grace. The helper that asks is the `nerve-node` program itself. The
//! tests run as a node started with Ctrl+C ignored, which its commands must
//! hear all the same. Windows only:
//!
//! ```text
//! cargo test -p nerve-node --test win_stop
//! ```
#![cfg(windows)]

use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};

use nerve_node::exec::{RunCall, RunOptions, Sig, run};
use nerve_proto::ErrorCode;
use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
use windows_sys::Win32::System::Console::{
    AllocConsole, GetConsoleProcessList, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    TerminateProcess,
};

/// How long an asked command has before its job is ended: the node's
/// `job::GRACE`.
const GRACE: Duration = Duration::from_secs(3);

/// A PowerShell command that notes it runs, sleeps, and notes its cleanup
/// in a `finally`, which runs when Ctrl+C stops it.
const HEEDS: &str = "try { Set-Content -Path started -Value 1; Start-Sleep 120 } \
     finally { Set-Content -Path cleaned -Value 1 }";

/// Runs once before any test starts a command. Ignores Ctrl+C in this
/// process, as ssh and cmd's `start /b` start a node: the processes a
/// process starts inherit that unless the node stops it
/// (nerve_node::win_stop::hear_ctrl_c). And starts the helper once with
/// nothing to ask: the first start of a freshly built program waits for the
/// virus scanner, which would count against the times the tests check.
fn setup() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: a plain call that sets this process's own Ctrl+C state.
        unsafe { SetConsoleCtrlHandler(None, 1) };
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_nerve-node"))
            .arg(nerve_node::win_stop::STOP_ARG)
            .status();
    });
}

fn opts() -> RunOptions {
    RunOptions {
        shell: None,
        landlock: None,
        container: None,
        exe: env!("CARGO_BIN_EXE_nerve-node").into(),
        output_cap: 64 * 1024,
        timeouts: Default::default(),
        sudo: None,
        account: None,
        separate: false,
        own: Vec::new(),
        root: None,
        limits: None,
        tap: None,
    }
}

fn call(cmd: &str, cwd: &Path, timeout: Duration) -> RunCall {
    RunCall {
        command: cmd.into(),
        cwd: cwd.to_path_buf(),
        timeout: Some(timeout),
        limits: Default::default(),
    }
}

/// Waits until `file` is there.
async fn appears(file: &Path) {
    for _ in 0..600 {
        if file.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no {}", file.display())
}

/// Whether process `pid` runs.
fn running(pid: u32) -> bool {
    // SAFETY: plain values; the handle is closed once.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let r = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32;
        CloseHandle(h);
        r
    }
}

/// Ends `pid` when a failed test left it running.
fn sweep(pid: u32) {
    // SAFETY: plain values; the handle is closed once.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !h.is_null() {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
}

/// A timeout asks the command first: PowerShell stops at Ctrl+C and runs
/// its `finally`, well before the grace is over.
#[tokio::test]
async fn a_timeout_lets_a_command_that_heeds_ctrl_c_clean_up() {
    setup();
    let d = tempfile::tempdir().unwrap();
    let timeout = Duration::from_secs(6);
    let t = Instant::now();
    let e = run(&call(HEEDS, d.path(), timeout), &opts(), |_| {})
        .await
        .unwrap_err();
    let took = t.elapsed();
    assert_eq!(e.kind(), ErrorCode::Timeout);
    assert!(d.path().join("started").exists(), "the command never ran");
    assert!(
        d.path().join("cleaned").exists(),
        "the command was ended without its cleanup"
    );
    assert!(
        took < timeout + GRACE,
        "the call waited out the grace ({took:?}) for a command that had ended"
    );
}

/// `exec.signal` with `term` asks the same way; the call then returns as
/// the command ended, with its output.
#[tokio::test]
async fn term_lets_a_command_that_heeds_ctrl_c_clean_up() {
    setup();
    let d = tempfile::tempdir().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let c = call(HEEDS, d.path(), Duration::from_secs(120));
    let task = tokio::spawn(async move {
        run(&c, &opts(), |e| {
            let _ = tx.send(e.clone());
        })
        .await
    });
    let ender = rx.await.unwrap();
    appears(&d.path().join("started")).await;
    let t = Instant::now();
    ender.signal(Sig::Term);
    let r = tokio::time::timeout(GRACE + Duration::from_secs(10), task)
        .await
        .expect("the command outlived term and the grace")
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(
        d.path().join("cleaned").exists(),
        "the command was ended without its cleanup"
    );
    assert!(t.elapsed() < GRACE, "term waited out the grace");
}

/// A command whose process has joined the node's own console is not sent
/// Ctrl+C there, which would reach the node (and stop it, as it hears
/// Ctrl+C): with nothing else to ask, `term` ends the job at once. The
/// shell leaves its own console for this test process's one.
#[tokio::test]
async fn a_command_on_the_nodes_console_is_not_sent_ctrl_c() {
    setup();
    let mut one = [0u32; 1];
    // SAFETY: the buffer holds one pid; AllocConsole takes nothing.
    unsafe {
        if GetConsoleProcessList(one.as_mut_ptr(), 1) == 0 {
            AllocConsole();
        }
    }
    let d = tempfile::tempdir().unwrap();
    let command = format!(
        "Add-Type -Namespace N -Name K -MemberDefinition \
         '[DllImport(\"kernel32.dll\")] public static extern bool FreeConsole(); \
         [DllImport(\"kernel32.dll\")] public static extern bool AttachConsole(uint p);'; \
         [void][N.K]::FreeConsole(); \
         if ([N.K]::AttachConsole({})) {{ Set-Content -Path attached -Value 1 }} \
         else {{ Set-Content -Path refused -Value 1 }}; \
         try {{ Start-Sleep 120 }} finally {{ Set-Content -Path cleaned -Value 1 }}",
        std::process::id()
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    let c = call(&command, d.path(), Duration::from_secs(120));
    let task = tokio::spawn(async move {
        run(&c, &opts(), |e| {
            let _ = tx.send(e.clone());
        })
        .await
    });
    let ender = rx.await.unwrap();
    let (attached, refused) = (d.path().join("attached"), d.path().join("refused"));
    for _ in 0..600 {
        if attached.exists() || refused.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        attached.exists(),
        "the shell did not join the test's console"
    );
    let t = Instant::now();
    ender.signal(Sig::Term);
    let r = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the command outlived term")
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(
        t.elapsed() < GRACE,
        "term waited out the grace ({:?}): something was asked",
        t.elapsed()
    );
    assert!(
        !d.path().join("cleaned").exists(),
        "the command heard Ctrl+C on the node's console"
    );
}

/// A process that ignores Ctrl+C (cmd's `start /b` starts it so) is ended
/// once the grace is over, without its cleanup; the shell, which heeds it,
/// has ended before.
#[tokio::test]
async fn a_command_that_ignores_ctrl_c_is_ended_after_the_grace() {
    setup();
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("ignorer.ps1"),
        "Set-Content -Path ignorer.pid -Value $PID\r\n\
         try { Start-Sleep 120 } finally { Set-Content -Path ignorer.cleaned -Value 1 }\r\n",
    )
    .unwrap();
    let command = "cmd /c start /b powershell -NoProfile -ExecutionPolicy Bypass -File ignorer.ps1; \
         Start-Sleep 120";
    let timeout = Duration::from_secs(6);
    let c = call(command, d.path(), timeout);
    let t = Instant::now();
    let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
    appears(&d.path().join("ignorer.pid")).await;
    let pid: u32 = std::fs::read_to_string(d.path().join("ignorer.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let e = task.await.unwrap().unwrap_err();
    let took = t.elapsed();
    let ended = !running(pid);
    sweep(pid);
    assert_eq!(e.kind(), ErrorCode::Timeout);
    assert!(ended, "the process that ignored Ctrl+C outlived the call");
    assert!(
        took >= timeout + GRACE - Duration::from_millis(200),
        "ended after {took:?}, before the grace was over"
    );
    assert!(
        !d.path().join("ignorer.cleaned").exists(),
        "the process heard Ctrl+C after all"
    );
}

/// `kill` asks nothing and ends the command at once.
#[tokio::test]
async fn kill_ends_a_command_at_once() {
    setup();
    let d = tempfile::tempdir().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let c = call(HEEDS, d.path(), Duration::from_secs(120));
    let task = tokio::spawn(async move {
        run(&c, &opts(), |e| {
            let _ = tx.send(e.clone());
        })
        .await
    });
    let ender = rx.await.unwrap();
    appears(&d.path().join("started")).await;
    ender.signal(Sig::Kill);
    let r = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the command outlived kill")
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(
        !d.path().join("cleaned").exists(),
        "kill let the command clean up"
    );
}
