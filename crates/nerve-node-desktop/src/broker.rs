//! The elevated broker: on a node installed as a service some commands need
//! the rights the owner gives in a terminal with `sudo` (install, update,
//! uninstall, sudo on and the others of `nerve_node::owner::needs_admin`),
//! and every command does for a user who is no owner of the node. The app
//! asks for them the way the desktop does (polkit's `pkexec` on Linux, the
//! UAC prompt on Windows), and starts this program elevated as the broker.
//! The broker runs the app's commands as `nerve-node --json …` (this
//! program, nothing else) and sends back what each answered, until the app
//! lets go of it: after that one command for an owner, at its end for
//! anyone else.
//!
//! The app and the broker speak JSON lines. A request is
//! `{"id", "args", "input", "follow"}` or `{"id", "cancel": true}`; the
//! broker answers `{"id", "line"}` for each line of a command that keeps
//! running and `{"id", "done": {"ok", "code", "stdout", "stderr"}}` when it
//! ends. Its first line is `{"hello": …}`, so the app knows it runs.
//!
//! Only the app reaches the broker: on Linux over the broker's stdin and
//! stdout, which pkexec hands from the app, with the app closed to the
//! other processes of its user ([`shut_out_the_user`]); on Windows over a
//! named pipe the broker makes, open to the app's user only, which it
//! serves to the app's process alone (`win`).
//!
//! For a user who is no owner, the broker lives as long as the app: the
//! rights are given once each time the app opens. A secret in each request
//! would add nothing on
//! Linux: it would travel over the same pipe, which any process that can
//! open it at all can also read.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};

use crate::runner::{Follow, Output, follow_process, run_process};

/// The argument that starts this program as the broker.
pub const ARG: &str = "__desktop-broker";

const HELLO: &str = "nerve-node-desktop broker";

type Out = Arc<Mutex<Box<dyn Write + Send>>>;

fn send(out: &Out, v: &Value) -> bool {
    let mut o = out.lock().unwrap_or_else(|p| p.into_inner());
    writeln!(o, "{v}").and_then(|_| o.flush()).is_ok()
}

fn done(o: &Output) -> Value {
    json!({
        "ok": o.ok,
        "code": o.code,
        "stdout": String::from_utf8_lossy(&o.stdout),
        "stderr": String::from_utf8_lossy(&o.stderr),
    })
}

fn output_of(v: &Value) -> Output {
    Output {
        ok: v["ok"] == true,
        code: v["code"].as_i64().map(|c| c as i32),
        stdout: v["stdout"].as_str().unwrap_or_default().as_bytes().to_vec(),
        stderr: v["stderr"].as_str().unwrap_or_default().as_bytes().to_vec(),
    }
}

/// The broker's side: answers the requests on `input` with `exe`, the
/// program itself, until `input` ends; then ends what still runs. With the
/// SID of the app's user (Windows), its commands take that user as the one
/// who asked ([`nerve_node::cli::DESKTOP_USER_SID_ARG`]), as an argument:
/// a variable would be one the account's unelevated programs may set.
pub fn serve(
    input: impl Read,
    output: Box<dyn Write + Send>,
    exe: PathBuf,
    app_user_sid: Option<&str>,
) {
    let named: Arc<Vec<String>> = Arc::new(
        app_user_sid
            .map(|sid| {
                vec![
                    nerve_node::cli::DESKTOP_USER_SID_ARG.to_string(),
                    sid.into(),
                ]
            })
            .unwrap_or_default(),
    );
    let out: Out = Arc::new(Mutex::new(output));
    if !send(&out, &json!({ "hello": HELLO })) {
        return;
    }
    let follows: Arc<Mutex<HashMap<u64, Follow>>> = Arc::default();
    for line in BufReader::new(input).lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = req["id"].as_u64() else {
            continue;
        };
        if req["cancel"] == true {
            follows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            continue;
        }
        let mut args: Vec<String> = req["args"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(str::to_string))
            .collect();
        // Commands of the node only: its options first, never one of the
        // helpers this program also is (the exec shim, this broker).
        if !args.first().is_some_and(|a| a.starts_with("--")) {
            let refused = Output {
                stderr: b"the broker runs nerve-node commands only".to_vec(),
                ..Output::default()
            };
            send(&out, &json!({ "id": id, "done": done(&refused) }));
            continue;
        }
        // Before the request's own arguments: given twice, clap refuses.
        args.splice(0..0, named.iter().cloned());
        let input = req["input"].as_str().map(str::to_string);
        let (out, exe) = (out.clone(), exe.clone());
        if req["follow"] == true {
            let (o1, o2) = (out.clone(), out.clone());
            let follow = follow_process(
                &exe,
                &args,
                Box::new(move |line| {
                    send(&o1, &json!({ "id": id, "line": line }));
                }),
                Box::new(move |end| {
                    send(&o2, &json!({ "id": id, "done": done(&end) }));
                }),
            );
            match follow {
                Ok(f) => {
                    follows
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(id, f);
                }
                Err(e) => {
                    let failed = Output {
                        stderr: e.into_bytes(),
                        ..Output::default()
                    };
                    send(&out, &json!({ "id": id, "done": done(&failed) }));
                }
            }
            continue;
        }
        std::thread::spawn(move || {
            let o = run_process(&exe, &args, input.as_deref()).unwrap_or_else(|e| Output {
                stderr: e.into_bytes(),
                ..Output::default()
            });
            send(&out, &json!({ "id": id, "done": done(&o) }));
        });
    }
    // The app ended: so does every command that keeps running.
    follows.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

enum Msg {
    Line(String),
    Done(Output),
    Gone,
}

/// The app's side of the broker.
pub struct Client {
    out: Out,
    waiting: Arc<Mutex<HashMap<u64, mpsc::Sender<Msg>>>>,
    next: AtomicU64,
    alive: Arc<AtomicBool>,
    // The broker's process, kept while the app talks to it.
    _process: Mutex<Option<std::process::Child>>,
}

/// Why a command did not go through the broker.
pub const GONE: &str = "the administrator rights ended; give them again to go on";

impl Client {
    /// Talks to a broker over `input` and `output`, once it said hello.
    pub fn start(
        input: Box<dyn Read + Send>,
        output: Box<dyn Write + Send>,
        process: Option<std::process::Child>,
    ) -> Result<Arc<Client>, String> {
        let mut lines = BufReader::new(input).lines();
        // Until the owner answered the system's question.
        match lines.next() {
            Some(Ok(l)) if serde_json::from_str::<Value>(&l).is_ok_and(|v| v["hello"] == HELLO) => {
            }
            _ => return Err("the administrator rights were not given".into()),
        }
        let waiting: Arc<Mutex<HashMap<u64, mpsc::Sender<Msg>>>> = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        {
            let (waiting, alive) = (waiting.clone(), alive.clone());
            std::thread::spawn(move || {
                for line in lines {
                    let Ok(line) = line else { break };
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    let Some(id) = v["id"].as_u64() else {
                        continue;
                    };
                    let mut w = waiting.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(l) = v["line"].as_str() {
                        if let Some(tx) = w.get(&id) {
                            let _ = tx.send(Msg::Line(l.to_string()));
                        }
                    } else if v.get("done").is_some()
                        && let Some(tx) = w.remove(&id)
                    {
                        let _ = tx.send(Msg::Done(output_of(&v["done"])));
                    }
                }
                alive.store(false, Ordering::SeqCst);
                for (_, tx) in waiting.lock().unwrap_or_else(|p| p.into_inner()).drain() {
                    let _ = tx.send(Msg::Gone);
                }
            });
        }
        Ok(Arc::new(Client {
            out: Arc::new(Mutex::new(output)),
            waiting,
            next: AtomicU64::new(1),
            alive,
            _process: Mutex::new(process),
        }))
    }

    /// Whether the broker still answers.
    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn ask(
        &self,
        args: Vec<String>,
        input: Option<&str>,
        follow: bool,
    ) -> Result<(u64, mpsc::Receiver<Msg>), String> {
        if !self.alive() {
            return Err(GONE.into());
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.waiting
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);
        let req = json!({ "id": id, "args": args, "input": input, "follow": follow });
        if !send(&self.out, &req) {
            self.waiting
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            return Err(GONE.into());
        }
        Ok((id, rx))
    }

    /// Runs one command and waits for its end.
    pub fn run(&self, args: Vec<String>, input: Option<&str>) -> Result<Output, String> {
        let (_, rx) = self.ask(args, input, false)?;
        loop {
            match rx.recv() {
                Ok(Msg::Done(o)) => return Ok(o),
                Ok(Msg::Line(_)) => {}
                Ok(Msg::Gone) | Err(_) => return Err(GONE.into()),
            }
        }
    }

    /// Runs a command that keeps answering; see [`follow_process`].
    pub fn follow(
        self: &Arc<Self>,
        args: Vec<String>,
        mut on_line: Box<dyn FnMut(String) + Send>,
        on_end: Box<dyn FnOnce(Output) + Send>,
    ) -> Result<Follow, String> {
        let (id, rx) = self.ask(args, None, true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        {
            let stopped = stopped.clone();
            std::thread::spawn(move || {
                loop {
                    match rx.recv() {
                        Ok(Msg::Line(l)) if !stopped.load(Ordering::SeqCst) => on_line(l),
                        Ok(Msg::Line(_)) => {}
                        Ok(Msg::Done(o)) => {
                            if !stopped.load(Ordering::SeqCst) {
                                on_end(o);
                            }
                            return;
                        }
                        Ok(Msg::Gone) | Err(_) => {
                            if !stopped.load(Ordering::SeqCst) {
                                on_end(Output {
                                    stderr: GONE.as_bytes().to_vec(),
                                    ..Output::default()
                                });
                            }
                            return;
                        }
                    }
                }
            });
        }
        let me = self.clone();
        Ok(Follow::new(Box::new(move || {
            stopped.store(true, Ordering::SeqCst);
            me.waiting
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            send(&me.out, &json!({ "id": id, "cancel": true }));
        })))
    }
}

/// How the broker is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// With the rights the desktop gives after asking.
    Elevated,
    /// As this user, for tests: the same broker, no question.
    Plain,
}

/// Starts this program as the broker and talks to it.
pub fn launch(exe: &Path, how: Launch) -> Result<Arc<Client>, String> {
    // Windows starts the broker without the app's stdin and stdout when it
    // asks for the rights, so it talks over pipes either way.
    #[cfg(windows)]
    return win::launch(exe, how == Launch::Elevated);
    #[cfg(not(windows))]
    launch_stdio(exe, how)
}

/// The broker on its stdin and stdout, which pkexec hands on.
#[cfg(not(windows))]
fn launch_stdio(exe: &Path, how: Launch) -> Result<Arc<Client>, String> {
    use std::process::{Command, Stdio};
    if how == Launch::Elevated {
        // Without pkexec there is nothing to ask with: the owner reads what
        // to install instead.
        return elevate(&crate::deps::pkexec_here()?, exe);
    }
    let mut child = Command::new(exe)
        .arg(ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start the broker: {e}"))?;
    let input = child.stdout.take().expect("piped");
    let output = child.stdin.take().expect("piped");
    Client::start(Box::new(input), Box::new(output), Some(child))
}

/// Starts the broker with `pkexec`, which hands it its stdin and stdout and
/// asks with the desktop's polkit agent. When no agent answers, pkexec says
/// so on stderr and ends ([`crate::deps::pkexec_failed`]): the owner reads
/// what to install. pkexec's own agent in a terminal is off, so the question
/// is the desktop's, never one in a terminal behind the window.
#[cfg(not(windows))]
fn elevate(pkexec: &Path, exe: &Path) -> Result<Arc<Client>, String> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    #[cfg(target_os = "linux")]
    shut_out_the_user()?;
    let mut child = Command::new(pkexec)
        .arg("--disable-internal-agent")
        .arg(exe)
        .arg(ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot ask for administrator rights: pkexec did not start ({e})"))?;
    // What pkexec says, read to its end on a thread of its own: the broker
    // keeps the pipe while it runs, and says nothing there.
    let mut stderr = child.stderr.take().expect("piped");
    let (tx, said) = mpsc::channel();
    std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = (&mut stderr).take(16 * 1024).read_to_end(&mut text);
        let _ = tx.send(String::from_utf8_lossy(&text).into_owned());
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    });
    let input = child.stdout.take().expect("piped");
    let output = child.stdin.take().expect("piped");
    match Client::start(Box::new(input), Box::new(output), None) {
        Ok(client) => {
            *client._process.lock().unwrap_or_else(|p| p.into_inner()) = Some(child);
            Ok(client)
        }
        Err(e) => {
            // pkexec ended without the broker, or soon will.
            let start = Instant::now();
            let code = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
            };
            let said = said
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_default();
            Err(crate::deps::pkexec_failed(code, &said).unwrap_or(e))
        }
    }
}

/// Closes this process to the other processes of its user, before it holds
/// the pipe to the root broker. Linux lets a process open the pipes of
/// another process of the same user through `/proc/<pid>/fd`, and trace
/// it, unless that process is not dumpable: then its `/proc` entries are
/// root's. It stays so for the rest of the app's life, as the broker does.
/// The desktop portal refuses a caller it cannot look at in `/proc`, so the
/// app's file dialogs run in a process of their own
/// ([`crate::dialog`]).
#[cfg(target_os = "linux")]
fn shut_out_the_user() -> Result<(), String> {
    // SAFETY: prctl with integer arguments only.
    let (set, now) = unsafe {
        (
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0),
            libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0),
        )
    };
    if set != 0 || now != 0 {
        return Err(format!(
            "cannot keep other programs away from the administrator rights: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The broker's start: `__desktop-broker`, on Windows with the pipe's name,
/// the app's process id and the SID of the app's user. The exit code.
pub fn main(args: &[String]) -> i32 {
    // The commands it runs elevated take the proxy and the trusted
    // certificates from the machine, not from the variables of the app's
    // account, which UAC gave this process and its unelevated programs may
    // set (windows-2); they inherit what this sets.
    #[cfg(windows)]
    // SAFETY: called first in `main`, before this process starts a thread.
    unsafe {
        nerve_node::folders::take_machine_environment()
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return 1,
    };
    #[cfg(windows)]
    if let [name, pid, sid] = args {
        return win::serve_pipe(name, pid, sid, exe);
    }
    if !args.is_empty() {
        return 2;
    }
    serve(std::io::stdin(), Box::new(std::io::stdout()), exe, None);
    0
}

/// The broker over a named pipe on Windows, where the UAC prompt starts a
/// program without handing it the app's stdin and stdout.
#[cfg(windows)]
pub mod win {
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_ATTRIBUTES, PIPE_ACCESS_INBOUND,
        PIPE_ACCESS_OUTBOUND, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, GetProcessId, OpenProcess, OpenProcessToken,
        PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use super::Client;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The SID of the user this process runs as, as text.
    pub(crate) fn own_sid() -> Result<String, String> {
        // SAFETY: the pseudo handle of this process, which needs no closing.
        user_of(unsafe { GetCurrentProcess() })
    }

    /// The SID of the user the process `pid` runs as, as text.
    pub(crate) fn sid_of(pid: u32) -> Result<String, String> {
        // SAFETY: a handle to query the process, closed again.
        unsafe {
            let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if p.is_null() {
                return Err(format!("process {pid}: error {}", GetLastError()));
            }
            let sid = user_of(p);
            CloseHandle(p);
            sid
        }
    }

    fn user_of(process: HANDLE) -> Result<String, String> {
        // SAFETY: the token of the process, read into a buffer of the size
        // Windows asks for.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return Err(format!("the process token: error {}", GetLastError()));
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(format!("the token's user: error {}", GetLastError()));
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            sid_text(user.User.Sid)
        }
    }

    /// `sid` as text.
    ///
    /// # Safety
    /// `sid` points to a valid SID.
    pub(crate) unsafe fn sid_text(sid: PSID) -> Result<String, String> {
        // SAFETY: the string Windows allocates is read and freed.
        unsafe {
            let mut text: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(sid, &mut text) == 0 {
                return Err(format!("the user's SID: error {}", GetLastError()));
            }
            let n = (0..).take_while(|i| *text.add(*i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
            LocalFree(text as HLOCAL);
            Ok(s)
        }
    }

    /// One end of the broker: a pipe one way, open to SYSTEM, the
    /// administrators and the app's user (`sid`) alone, connected to the
    /// app's process (`app`) only. Only a process of those may open it, and
    /// the one connected must be the app's; its user is not read again: a
    /// broker that is not elevated (an administrator's, for a standard user,
    /// whose token is filtered until UAC raises it) may not open another
    /// user's process. Each way has a pipe of its own: a synchronous pipe
    /// handle reads and writes one at a time, so a read that waits would
    /// hold up every write.
    fn serve_end(name: &str, sid: &str, inbound: bool, app: u32) -> Option<std::fs::File> {
        let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})"));
        // SAFETY: the descriptor Windows makes from the SDDL is freed after
        // the pipe took it; the handle becomes the File returned.
        let handle = unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let way = if inbound {
                PIPE_ACCESS_INBOUND
            } else {
                PIPE_ACCESS_OUTBOUND
            };
            let h = CreateNamedPipeW(
                wide(name).as_ptr(),
                way | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &sa,
            );
            LocalFree(sd as HLOCAL);
            if h == INVALID_HANDLE_VALUE {
                return None;
            }
            // ERROR_PIPE_CONNECTED: the client came before this call.
            if ConnectNamedPipe(h, std::ptr::null_mut()) == 0 && GetLastError() != 535 {
                CloseHandle(h);
                return None;
            }
            let mut client = 0u32;
            if GetNamedPipeClientProcessId(h, &mut client) == 0 || client != app {
                CloseHandle(h);
                return None;
            }
            h
        };
        // SAFETY: the pipe's handle, owned by this File from here on.
        Some(unsafe { std::fs::File::from_raw_handle(handle as _) })
    }

    /// The broker over its two pipes, `<name>-in` and `<name>-out`, for the
    /// app's process `pid` of the user `sid`. That user is not this
    /// process's when the app runs as a standard user: the UAC prompt then
    /// takes an administrator's name and password, and the broker runs as
    /// that administrator.
    pub fn serve_pipe(name: &str, pid: &str, sid: &str, exe: PathBuf) -> i32 {
        let Ok(app) = pid.parse::<u32>() else {
            return 2;
        };
        if !name.starts_with(r"\\.\pipe\nerve-desktop-") || !sid.starts_with("S-1-") {
            return 2;
        }
        // An app that never comes leaves no broker behind.
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waited = connected.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(60));
            if !waited.load(std::sync::atomic::Ordering::SeqCst) {
                std::process::exit(1);
            }
        });
        let Some(requests) = serve_end(&format!("{name}-in"), sid, true, app) else {
            return 1;
        };
        let Some(answers) = serve_end(&format!("{name}-out"), sid, false, app) else {
            return 1;
        };
        connected.store(true, std::sync::atomic::Ordering::SeqCst);
        // The commands' `install` takes the app's user for the account of
        // the commands, not the administrator (nerve_node::cli::invoker).
        super::serve(requests, Box::new(answers), exe, Some(sid));
        0
    }

    /// Opens one end of the broker's pipes once it is there, as long as the
    /// broker runs, and makes sure the broker made it.
    fn open_end(
        name: &str,
        inbound: bool,
        broker: u32,
        running: &dyn Fn() -> bool,
    ) -> Result<std::fs::File, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let file = loop {
            let mut o = std::fs::OpenOptions::new();
            if inbound {
                // Writing, and the attributes the check below reads.
                o.access_mode(GENERIC_WRITE | FILE_READ_ATTRIBUTES);
            } else {
                o.read(true);
            }
            // Whoever serves the pipe learns who connects, but cannot act
            // as the app.
            o.security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
            match o.open(name) {
                Ok(f) => break f,
                Err(e) if !running() => {
                    return Err(format!("the broker ended before it answered: {e}"));
                }
                Err(e) if std::time::Instant::now() > deadline => {
                    return Err(format!("the broker did not answer: {e}"));
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        };
        // The pipe must be the broker's, not one another process made of
        // the same name.
        let mut server = 0u32;
        // SAFETY: a query on the open pipe.
        let ok =
            unsafe { GetNamedPipeServerProcessId(file.as_raw_handle() as HANDLE, &mut server) };
        if ok == 0 || server != broker {
            return Err("the pipe is not the broker's".into());
        }
        Ok(file)
    }

    /// A new name for the broker's pipes, and the arguments that start this
    /// program as the broker on them for this process.
    pub fn broker_args() -> Result<(String, String), String> {
        let name = format!(
            r"\\.\pipe\nerve-desktop-{}",
            nerve_transport::keys::random_token(24)
        );
        let args = format!(
            "{} {name} {} {}",
            super::ARG,
            std::process::id(),
            own_sid()?
        );
        Ok((name, args))
    }

    /// Starts this program as the broker, with the UAC prompt when
    /// `elevated`, and talks to it over its pipes.
    pub fn launch(exe: &Path, elevated: bool) -> Result<Arc<Client>, String> {
        let (name, args) = broker_args()?;
        let (process, child) = if elevated {
            let params = wide(&args);
            let file = wide(&exe.display().to_string());
            let verb = wide("runas");
            // SAFETY: a filled SHELLEXECUTEINFOW whose strings live until the
            // call returns; the process handle it gives is closed below.
            let process = unsafe {
                let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
                info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
                info.fMask = SEE_MASK_NOCLOSEPROCESS;
                info.lpVerb = verb.as_ptr();
                info.lpFile = file.as_ptr();
                info.lpParameters = params.as_ptr();
                info.nShow = SW_HIDE;
                if ShellExecuteExW(&mut info) == 0 {
                    // ERROR_CANCELLED: the owner said no.
                    return Err(if GetLastError() == 1223 {
                        "the administrator rights were not given".into()
                    } else {
                        format!(
                            "cannot ask for administrator rights: error {}",
                            GetLastError()
                        )
                    });
                }
                info.hProcess
            };
            (process, None)
        } else {
            use std::os::windows::io::AsRawHandle;
            use std::process::{Command, Stdio};
            let child = Command::new(exe)
                .args(args.split(' '))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("cannot start the broker: {e}"))?;
            (child.as_raw_handle() as HANDLE, Some(child))
        };
        // SAFETY: the broker's process handle, of the child or given away.
        let (requests, answers) = unsafe { connect(&name, process, child.is_none())? };
        Client::start(Box::new(answers), Box::new(requests), child)
    }

    /// Opens the pipes `name` of the broker `process` (its handle, closed
    /// here when `close`) once it serves them: requests, then answers.
    ///
    /// # Safety
    /// `process` is a handle to a process, open until this returns, or
    /// given away when `close`.
    pub unsafe fn connect(
        name: &str,
        process: HANDLE,
        close: bool,
    ) -> Result<(std::fs::File, std::fs::File), String> {
        // SAFETY: queries on the broker's process handle, which lives until
        // it is closed below (or, for a child, with the child).
        let broker = unsafe { GetProcessId(process) };
        let running = || unsafe { WaitForSingleObject(process, 0) } != 0;
        let ends = open_end(&format!("{name}-in"), true, broker, &running)
            .and_then(|i| {
                Ok((
                    i,
                    open_end(&format!("{name}-out"), false, broker, &running)?,
                ))
            })
            .map_err(|e| {
                let mut code = 0u32;
                // SAFETY: a query on the broker's process handle.
                if !running() && unsafe { GetExitCodeProcess(process, &mut code) } != 0 {
                    format!("{e} (exit code {code})")
                } else {
                    e
                }
            });
        if close {
            // SAFETY: the handle the caller gave away.
            unsafe { CloseHandle(process) };
        }
        ends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe in memory: what one side writes, the other reads.
    fn pipe() -> (std::io::PipeReader, std::io::PipeWriter) {
        std::io::pipe().unwrap()
    }

    #[test]
    fn the_broker_refuses_anything_but_a_node_command() {
        let (req_r, mut req_w) = pipe();
        let (ans_r, ans_w) = pipe();
        // A program that is not this one would be refused before it ran;
        // here nothing must run at all.
        let t = std::thread::spawn(move || {
            serve(
                req_r,
                Box::new(ans_w),
                PathBuf::from("/nonexistent/program"),
                None,
            )
        });
        writeln!(req_w, "{}", json!({"id": 7, "args": ["__exec-shim", "x"]})).unwrap();
        drop(req_w);
        let lines: Vec<Value> = BufReader::new(ans_r)
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect();
        t.join().unwrap();
        assert_eq!(lines[0]["hello"], HELLO);
        assert_eq!(lines[1]["id"], 7);
        assert!(
            lines[1]["done"]["stderr"]
                .as_str()
                .unwrap()
                .contains("commands only")
        );
    }

    /// The broker's commands, run once or followed, take the app's user as
    /// the one who asked when the broker was given that user's SID (the
    /// broker on Windows, which may run as another account), and only
    /// then. The program here prints what it got.
    #[cfg(unix)]
    #[test]
    fn the_commands_carry_the_apps_user() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("node");
        let mut sh = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$0\" && chmod 755 \"$0\""])
            .arg(&exe)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = sh.stdin.take().unwrap();
        // The command says its arguments and whether the variable the app's
        // user used to come in is set: it must not be.
        input
            .write_all(b"#!/bin/sh\necho \"$* ${NERVE_DESKTOP_USER_SID-unset}\"\n")
            .unwrap();
        drop(input);
        assert!(sh.wait().unwrap().success());
        let got = |sid: Option<&'static str>| {
            let (req_r, mut req_w) = pipe();
            let (ans_r, ans_w) = pipe();
            let exe = exe.clone();
            let t = std::thread::spawn(move || serve(req_r, Box::new(ans_w), exe, sid));
            let mut said = Vec::new();
            let mut lines = BufReader::new(ans_r).lines();
            lines.next();
            writeln!(req_w, "{}", json!({"id": 1, "args": ["--json", "x"]})).unwrap();
            let done = serde_json::from_str::<Value>(&lines.next().unwrap().unwrap()).unwrap();
            said.push(done["done"]["stdout"].as_str().unwrap().trim().to_string());
            writeln!(
                req_w,
                "{}",
                json!({"id": 2, "args": ["--json", "x"], "follow": true})
            )
            .unwrap();
            let line = serde_json::from_str::<Value>(&lines.next().unwrap().unwrap()).unwrap();
            said.push(line["line"].as_str().unwrap().to_string());
            drop(req_w);
            t.join().unwrap();
            said
        };
        assert_eq!(
            got(Some("S-1-5-21-1-2-3-1001")),
            ["--desktop-user-sid S-1-5-21-1-2-3-1001 --json x unset"; 2]
        );
        assert_eq!(got(None), ["--json x unset"; 2]);
    }

    /// pkexec runs, and what it says when it does not start the broker
    /// tells a missing polkit agent from a refusal. Here pkexec is a script
    /// that answers as pkexec does, and the broker one that says hello.
    #[cfg(unix)]
    #[test]
    fn pkexec_runs_and_a_missing_agent_is_said() {
        let d = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            let p = d.path().join(name);
            // Written by a process of its own: were this process to hold the
            // file open for writing even for a moment, a child another test
            // forks then could keep it open, and Linux would refuse to run
            // it (ETXTBSY).
            let mut sh = std::process::Command::new("/bin/sh")
                .args(["-c", "cat > \"$0\" && chmod 755 \"$0\""])
                .arg(&p)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = sh.stdin.take().unwrap();
            input
                .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
                .unwrap();
            drop(input);
            assert!(sh.wait().unwrap().success());
            p
        };
        let broker = script(
            "broker",
            &format!("echo '{{\"hello\":\"{HELLO}\"}}'\ncat >/dev/null"),
        );
        let asked = d.path().join("asked");
        let agent = script(
            "pkexec-agent",
            &format!("echo \"$*\" > '{}'\nshift\nexec \"$@\"", asked.display()),
        );
        let client = elevate(&agent, &broker).unwrap();
        assert!(client.alive());
        assert_eq!(
            std::fs::read_to_string(&asked).unwrap().trim(),
            format!("--disable-internal-agent {} {ARG}", broker.display())
        );
        drop(client);

        let none = script(
            "pkexec-none",
            "echo 'Error executing command as another user: No authentication agent found.' >&2\nexit 127",
        );
        let e = elevate(&none, &broker).err().unwrap();
        assert!(e.contains("No polkit authentication agent"), "{e}");
        let dismissed = script(
            "pkexec-dismissed",
            "echo 'Error executing command as another user: Request dismissed' >&2\nexit 126",
        );
        let e = elevate(&dismissed, &broker).err().unwrap();
        assert!(e.contains("not given"), "{e}");
    }

    #[test]
    fn a_client_without_hello_has_no_rights() {
        let (r, w) = pipe();
        drop(w);
        let (_r2, w2) = pipe();
        let e = Client::start(Box::new(r), Box::new(w2), None)
            .err()
            .unwrap();
        assert!(e.contains("not given"), "{e}");
    }
}
