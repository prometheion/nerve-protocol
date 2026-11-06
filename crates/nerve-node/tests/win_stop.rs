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
//!
//! The commands that are asked are this test program again, started for one
//! of its ignored `stand_in_*` tests: it is up and has its Ctrl+C handler in
//! place within moments of its start and reacts at once, where PowerShell's
//! start and its reaction to Ctrl+C take seconds on a busy machine, and the
//! grace is a fixed 3 s (#180).
#![cfg(windows)]

use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};

use nerve_node::exec::{RunCall, RunOptions, Sig, run};
use nerve_proto::ErrorCode;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
use windows_sys::Win32::System::Console::{
    AllocConsole, CTRL_C_EVENT, GetConsoleProcessList, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};
use windows_sys::core::BOOL;

/// How long an asked command has before its job is ended: the node's
/// `job::GRACE`.
const GRACE: Duration = Duration::from_secs(3);

/// The exit code of the stand-in that heard Ctrl+C and cleaned up. A
/// process the job ended leaves 1.
const HEARD: u32 = 42;

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
        separate: None,
        pass_env: Vec::new(),
        own: Vec::new(),
        root: None,
        limits: None,
        tap: None,
        no_network: false,
    }
}

fn call(cmd: &str, cwd: &Path, timeout: Duration) -> RunCall {
    RunCall {
        command: cmd.into(),
        argv: None,
        cwd: cwd.to_path_buf(),
        timeout: Some(timeout),
        limits: Default::default(),
    }
}

/// This test program as a command that runs only its test `test`.
fn stand_in_line(test: &str) -> String {
    format!(
        "\"{}\" --ignored --exact {test}",
        std::env::current_exe().unwrap().display()
    )
}

/// A call of the stand-in that heeds Ctrl+C ([`stand_in_heeds_ctrl_c`]) in
/// a folder of its own, marked for it.
fn heeding(timeout: Duration) -> (tempfile::TempDir, RunCall) {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("heeds"), "").unwrap();
    let argv = vec![
        std::env::current_exe().unwrap().display().to_string(),
        "--ignored".into(),
        "--exact".into(),
        "stand_in_heeds_ctrl_c".into(),
    ];
    let c = RunCall {
        command: argv.join(" "),
        argv: Some(argv),
        ..call("", d.path(), timeout)
    };
    (d, c)
}

/// When process `pid` exits, and its exit code: a handle opened now, while
/// the node holds the process, waited on by a thread of its own.
fn exit_of(pid: u32) -> std::sync::mpsc::Receiver<(Instant, u32)> {
    // SAFETY: plain values; the thread closes the handle once.
    let h = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    assert!(!h.is_null(), "cannot open the command's process {pid}");
    let h = h as usize;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let h = h as HANDLE;
        let mut code = 0u32;
        // SAFETY: the handle is open until the close below.
        let at = unsafe {
            WaitForSingleObject(h, INFINITE);
            let at = Instant::now();
            GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            at
        };
        let _ = tx.send((at, code));
    });
    rx
}

/// Asserts that the call that returned at `returned` did not wait out the
/// grace for its command, which exited at `exited`: the time is the node's
/// own, from the command's end to the call's, whatever the command and the
/// helper took before.
fn returned_with_its_command(returned: Instant, exited: Instant) {
    let after = returned.saturating_duration_since(exited);
    assert!(
        after < GRACE,
        "the call returned {after:?} after its command had ended: it waited out the grace"
    );
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

/// A timeout asks the command first: it cleans up and ends on its own,
/// before the job would end it, and the call returns as it ends.
#[tokio::test]
async fn a_timeout_lets_a_command_that_heeds_ctrl_c_clean_up() {
    setup();
    let (d, c) = heeding(Duration::from_secs(6));
    let mut exit = None;
    let e = run(&c, &opts(), |e| exit = Some(exit_of(e.pid())))
        .await
        .unwrap_err();
    let returned = Instant::now();
    assert_eq!(e.kind(), ErrorCode::Timeout);
    assert!(d.path().join("started").exists(), "the command never ran");
    let (exited, code) = exit.expect("started").recv().unwrap();
    assert_eq!(code, HEARD, "the command was ended before its cleanup");
    assert!(
        d.path().join("cleaned").exists(),
        "the command was ended without its cleanup"
    );
    returned_with_its_command(returned, exited);
}

/// `exec.signal` with `term` asks the same way; the call then returns as
/// the command ended, with its exit code.
#[tokio::test]
async fn term_lets_a_command_that_heeds_ctrl_c_clean_up() {
    setup();
    let (d, c) = heeding(Duration::from_secs(120));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        run(&c, &opts(), |e| {
            let _ = tx.send((e.clone(), exit_of(e.pid())));
        })
        .await
    });
    let (ender, exit) = rx.await.unwrap();
    appears(&d.path().join("started")).await;
    ender.signal(Sig::Term);
    let r = tokio::time::timeout(GRACE + Duration::from_secs(10), task)
        .await
        .expect("the command outlived term and the grace")
        .unwrap();
    let returned = Instant::now();
    let r = r.unwrap();
    assert_eq!(
        r["exit_code"], HEARD,
        "the command was ended before its cleanup: {r}"
    );
    assert!(
        d.path().join("cleaned").exists(),
        "the command was ended without its cleanup"
    );
    let (exited, _) = exit.recv().unwrap();
    returned_with_its_command(returned, exited);
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
/// once the grace is over, without its cleanup.
#[tokio::test]
async fn a_command_that_ignores_ctrl_c_is_ended_after_the_grace() {
    setup();
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("ignores"), "").unwrap();
    std::fs::write(
        d.path().join("ignore.cmd"),
        format!(
            "@start \"\" /b {}\r\n@ping -n 120 127.0.0.1 >nul\r\n",
            stand_in_line("stand_in_under_start_b")
        ),
    )
    .unwrap();
    let timeout = Duration::from_secs(6);
    let c = call("ignore.cmd", d.path(), timeout);
    let o = RunOptions {
        shell: Some("cmd.exe".into()),
        ..opts()
    };
    let t = Instant::now();
    let task = tokio::spawn(async move { run(&c, &o, |_| {}).await });
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
    let (d, c) = heeding(Duration::from_secs(120));
    let (tx, rx) = tokio::sync::oneshot::channel();
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

/// The command of the tests that ask one that heeds Ctrl+C: this program
/// again. Its handler is in place before it says it runs (`started`), so
/// it can be asked from then on; it cleans up (`cleaned`) and ends with
/// [`HEARD`]. It leaves whether it hears Ctrl+C at all to what it
/// inherited: only a node that lets its commands hear Ctrl+C reaches it.
/// Outside a folder marked `heeds` it does nothing.
#[test]
#[ignore = "a command the other tests run"]
fn stand_in_heeds_ctrl_c() {
    if !Path::new("heeds").exists() {
        return;
    }
    unsafe extern "system" fn heard(event: u32) -> BOOL {
        if event != CTRL_C_EVENT {
            return 0;
        }
        let _ = std::fs::write("cleaned", "1");
        std::process::exit(HEARD as i32)
    }
    // SAFETY: the handler is a plain function that lives as long as the
    // process.
    unsafe { SetConsoleCtrlHandler(Some(heard), 1) };
    std::fs::write("started", "1").unwrap();
    std::thread::sleep(Duration::from_secs(120));
}

/// The command [`a_command_that_ignores_ctrl_c_is_ended_after_the_grace`]
/// has cmd's `start /b` start, which has it ignore Ctrl+C. A Ctrl+C it
/// heard all the same would leave `ignorer.cleaned`. Its pid file is
/// written under another name and renamed, so it appears whole and closed:
/// a reader that met it while it was being written got a sharing violation
/// (os error 32). Outside a folder marked `ignores` it does nothing.
#[test]
#[ignore = "a command the other tests run"]
fn stand_in_under_start_b() {
    if !Path::new("ignores").exists() {
        return;
    }
    unsafe extern "system" fn heard(event: u32) -> BOOL {
        if event == CTRL_C_EVENT {
            let _ = std::fs::write("ignorer.cleaned", "1");
        }
        0
    }
    // SAFETY: as in stand_in_heeds_ctrl_c.
    unsafe { SetConsoleCtrlHandler(Some(heard), 1) };
    std::fs::write("ignorer.tmp", std::process::id().to_string()).unwrap();
    std::fs::rename("ignorer.tmp", "ignorer.pid").unwrap();
    std::thread::sleep(Duration::from_secs(120));
}
