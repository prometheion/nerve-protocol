//! One window of the app for each user: a second start, or a `nerve://`
//! link the desktop opens with the app, goes to the window that is open
//! already. The first start listens on a socket only its user can reach
//! (in `$XDG_RUNTIME_DIR` on Linux, a named pipe open to that user on
//! Windows); a later start sends it one line, `{"link": …}`,
//! `{"uninstall": true}` or `{}`, and ends.
//!
//! A start the desktop opens with a link has it on its own command line,
//! which every account on the machine can read while the process lives
//! (`/proc/<pid>/cmdline`, a process list on Windows). So that start hands
//! the link at once to a new start of the app on that start's stdin
//! ([`hand_on`], [`LINK_ON_STDIN`]) and ends; the new start goes on as one
//! with the link would, to the open window or to a window of its own,
//! and its command line holds no link.
//!
//! A link can carry a pairing's code and pin, so a start sends nothing to
//! a socket or pipe that another user could have made: on Linux the
//! socket's folder is this user's alone and the window at the other end
//! runs as this user; on Windows the pipe's server runs as this user and
//! the pipe is this user's. Where that is not so, the start opens a window
//! of its own, which says why ([`Instance::note`]).

use std::io::{BufRead, BufReader, Write};

use serde_json::{Value, json};

/// What a start of the app does.
pub enum Claimed {
    /// It is the first: it opens the window and listens.
    First(Instance),
    /// An open window took the start.
    Forwarded,
}

/// What a start of the app asks of its window, or of the open one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asked {
    /// The `nerve://` link it was opened with.
    pub link: Option<String>,
    /// Its uninstall (crate::parts::UNINSTALL_ARG, from Apps & features).
    pub uninstall: bool,
    /// The program that was started, when it is not the installed one:
    /// the file just downloaded, say.
    pub program: Option<String>,
}

impl Asked {
    /// Opened with `link`.
    pub fn link(link: &str) -> Asked {
        Asked {
            link: Some(link.to_string()),
            ..Asked::default()
        }
    }
}

/// The argument of a start that takes its `nerve://` link from the first
/// line of stdin, not from its command line ([`hand_on`]).
pub const LINK_ON_STDIN: &str = "--link-on-stdin";

/// What a start with the arguments `words` (the program's name left out)
/// is: one with a `nerve://` link on its command line hands it on
/// ([`Start::HandOn`]); one with [`LINK_ON_STDIN`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// Opens the window, or hands what it asks to the open one.
    Window(Asked),
    /// Has a link on its command line: hands it to a new start and ends.
    HandOn(String),
    /// Takes the link from the first line of stdin.
    LinkOnStdin,
    /// None of these: a command of the node.
    Command,
}

impl Start {
    pub fn of(words: &[Option<&str>], uninstall_arg: &str) -> Start {
        match words {
            [Some(link)] if link.to_ascii_lowercase().starts_with("nerve://") => {
                Start::HandOn(link.to_string())
            }
            [Some(arg)] if *arg == LINK_ON_STDIN => Start::LinkOnStdin,
            [Some(arg)] if *arg == uninstall_arg => Start::Window(Asked {
                uninstall: true,
                ..Asked::default()
            }),
            [] => Start::Window(Asked::default()),
            _ => Start::Command,
        }
    }
}

/// Starts `program` (this one, in the app) with [`LINK_ON_STDIN`] and
/// `link` on its stdin, with `env` set for it, and lets it come to the
/// front on Windows; the caller then ends, and with it the command line
/// that held the link.
pub fn hand_on(
    program: &std::path::Path,
    link: &str,
    env: &[(&str, &str)],
) -> std::io::Result<std::process::Child> {
    let mut child = std::process::Command::new(program)
        .arg(LINK_ON_STDIN)
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    // The new start was not opened by the person, this one was: it may
    // bring its window up as this one could.
    #[cfg(windows)]
    // SAFETY: a plain call with a process id.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(child.id())
    };
    let mut stdin = child.stdin.take().expect("piped");
    writeln!(stdin, "{link}")?;
    Ok(child)
}

/// The link of a [`LINK_ON_STDIN`] start: the first line of its stdin;
/// none where that is empty or no `nerve://` link.
pub fn link_on_stdin() -> Option<String> {
    let mut text = String::new();
    std::io::stdin().lock().read_line(&mut text).ok()?;
    let link = text.trim();
    link.to_ascii_lowercase()
        .starts_with("nerve://")
        .then(|| link.to_string())
}

fn line(a: &Asked) -> String {
    let mut v = json!({});
    if let Some(l) = &a.link {
        v["link"] = json!(l);
    }
    if a.uninstall {
        v["uninstall"] = json!(true);
    }
    if let Some(p) = &a.program {
        v["program"] = json!(p);
    }
    v.to_string()
}

fn asked(line: &str) -> Option<Asked> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    Some(Asked {
        link: v["link"].as_str().map(str::to_string),
        uninstall: v["uninstall"] == true,
        program: v["program"].as_str().map(str::to_string),
    })
}

/// Claims the app for this user, or hands what this start asks to the
/// window that has it. Where no place for the socket is known, every start
/// opens a window.
pub fn claim(start: &Asked) -> Claimed {
    #[cfg(unix)]
    {
        let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) else {
            return Claimed::First(Instance::none());
        };
        unix::claim_at(
            &std::path::Path::new(&dir).join("nerve-node-desktop.sock"),
            start,
        )
    }
    #[cfg(windows)]
    {
        win::claim(start)
    }
}

/// The open window's claim; it ends, and lets another start have it, when
/// this is dropped.
pub struct Instance {
    #[cfg(unix)]
    listener: Option<(std::os::unix::net::UnixListener, std::path::PathBuf)>,
    #[cfg(windows)]
    pipe: Option<win::Pipe>,
    note: Option<&'static str>,
}

impl Instance {
    fn none() -> Instance {
        Instance {
            #[cfg(unix)]
            listener: None,
            #[cfg(windows)]
            pipe: None,
            note: None,
        }
    }

    /// A window that takes no later starts, for the reason `note` says.
    fn alone(note: &'static str) -> Instance {
        let mut i = Instance::none();
        i.note = Some(note);
        i
    }

    /// Why this window takes no later starts, when the owner should know.
    pub fn note(&self) -> Option<&'static str> {
        self.note
    }

    /// Hands what each later start asks to `on`, on a thread of its own.
    pub fn listen(&self, on: impl Fn(Asked) + Send + Sync + 'static) {
        #[cfg(unix)]
        if let Some((l, _)) = &self.listener
            && let Ok(l) = l.try_clone()
        {
            std::thread::spawn(move || {
                for conn in l.incoming() {
                    let Ok(conn) = conn else { break };
                    if !unix::peer_is_me(&conn) {
                        continue;
                    }
                    let mut text = String::new();
                    if BufReader::new(conn).read_line(&mut text).is_ok()
                        && let Some(a) = asked(&text)
                    {
                        on(a);
                    }
                }
            });
        }
        #[cfg(windows)]
        if let Some(p) = &self.pipe {
            p.listen(Box::new(move |text: String| {
                if let Some(a) = asked(&text) {
                    on(a);
                }
            }));
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some((_, path)) = self.listener.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    use super::*;

    pub(super) const NOT_PRIVATE: &str = "This window does not take later starts of Nerve and the nerve:// links opened while it is open: the folder its socket would be in ($XDG_RUNTIME_DIR) is not yours alone, so each opens a window of its own.";

    fn me() -> u32 {
        // SAFETY: a plain query.
        unsafe { libc::geteuid() }
    }

    /// Whether `dir` is a folder of this user's that nobody else may open,
    /// as `$XDG_RUNTIME_DIR` must be.
    fn private(dir: &Path) -> bool {
        std::fs::metadata(dir).is_ok_and(|m| m.is_dir() && m.uid() == me() && m.mode() & 0o077 == 0)
    }

    /// Whether the process at the other end of `s` runs as this user.
    pub fn peer_is_me(s: &UnixStream) -> bool {
        let mut cred = libc::ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the socket's credentials, into a buffer of their size.
        let got = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        got == 0 && cred.uid == me()
    }

    /// [`claim`] with the socket at `path`.
    pub fn claim_at(path: &Path, start: &Asked) -> Claimed {
        if !path.parent().is_some_and(private) {
            return Claimed::First(Instance::alone(NOT_PRIVATE));
        }
        if let Ok(mut s) = UnixStream::connect(path) {
            if !peer_is_me(&s) {
                return Claimed::First(Instance::alone(NOT_PRIVATE));
            }
            if writeln!(s, "{}", line(start)).is_ok() {
                return Claimed::Forwarded;
            }
        }
        // Nobody listens: a socket left by a window that crashed goes.
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(l) => Claimed::First(Instance {
                listener: Some((l, path.to_path_buf())),
                note: None,
            }),
            Err(_) => Claimed::First(Instance::none()),
        }
    }
}

#[cfg(windows)]
mod win {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_ATTRIBUTES, PIPE_ACCESS_INBOUND, READ_CONTROL,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::IO::CancelSynchronousIo;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        WaitNamedPipeW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

    use super::*;
    use crate::broker::win::{own_sid, sid_text};

    pub(super) const HELD: &str = "This window does not take later starts of Nerve and the nerve:// links opened while it is open: a program that is not your Nerve holds the name they would go to, so nothing is sent to it and each opens a window of its own.";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The first instance of the pipe, and its name and owner; the thread
    /// that takes the starts once it listens. Dropped, it lets the name go:
    /// the next start of the app is the first (crate::instance::Instance).
    pub struct Pipe {
        name: String,
        sid: String,
        first: std::sync::Mutex<Option<isize>>,
        listening: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            if let Some(h) = self
                .first
                .get_mut()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                // SAFETY: the instance this process made, which nothing
                // listens on.
                unsafe { CloseHandle(h as _) };
            }
            let Some(t) = self
                .listening
                .get_mut()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            else {
                return;
            };
            self.stop.store(true, Ordering::SeqCst);
            // The thread waits for a start in ConnectNamedPipe, or reads
            // one: its wait is cancelled until it sees `stop`, closes its
            // instances of the pipe and ends. Cancelled again and again, as
            // it may not be waiting yet.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !t.is_finished() && std::time::Instant::now() < deadline {
                // SAFETY: the thread's handle, which lives as long as `t`.
                unsafe { CancelSynchronousIo(t.as_raw_handle() as HANDLE) };
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if t.is_finished() {
                let _ = t.join();
            }
        }
    }

    /// An instance of the pipe, owned by this user and open to this user
    /// alone; the first one owns the name, and only this user may make the
    /// others.
    fn make(name: &str, sid: &str, first: bool) -> Option<isize> {
        let sddl = wide(&format!("O:{sid}D:P(A;;GA;;;{sid})"));
        // SAFETY: the descriptor Windows makes from the SDDL is freed after
        // the pipe took it.
        unsafe {
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
            let flags = PIPE_ACCESS_INBOUND
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            let h = CreateNamedPipeW(
                wide(name).as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                0,
                4096,
                0,
                &sa,
            );
            LocalFree(sd as HLOCAL);
            (h != INVALID_HANDLE_VALUE).then_some(h as isize)
        }
    }

    pub fn claim(start: &Asked) -> Claimed {
        let Ok(sid) = own_sid() else {
            return Claimed::First(Instance::none());
        };
        claim_at(&format!(r"\\.\pipe\nerve-node-desktop-{sid}"), &sid, start)
    }

    /// [`claim`] with the pipe `name`, for the user `sid`.
    pub(super) fn claim_at(name: &str, sid: &str, start: &Asked) -> Claimed {
        if send(name, sid, start) {
            return Claimed::Forwarded;
        }
        if let Some(h) = make(name, sid, true) {
            return Claimed::First(Instance {
                pipe: Some(Pipe {
                    name: name.to_string(),
                    sid: sid.to_string(),
                    first: std::sync::Mutex::new(Some(h)),
                    listening: std::sync::Mutex::default(),
                    stop: std::sync::Arc::default(),
                }),
                note: None,
            });
        }
        // The name is held: by a window of this user's that opened just
        // now, or by another program, which gets nothing.
        if send(name, sid, start) {
            return Claimed::Forwarded;
        }
        Claimed::First(Instance::alone(HELD))
    }

    /// Sends `start` to the window that holds the pipe `name`, if that is
    /// this user's (`sid`); whether it went.
    fn send(name: &str, sid: &str, start: &Asked) -> bool {
        let open = || {
            std::fs::OpenOptions::new()
                // Writing, and what the checks in `mine` read.
                .access_mode(GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL)
                // Whoever serves the pipe learns who connects, but cannot
                // act as this user.
                .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
                .open(name)
        };
        let f = match open() {
            // ERROR_PIPE_BUSY: the window is between two starts.
            Err(e) if e.raw_os_error() == Some(231) => {
                // SAFETY: a wait on the pipe's name, which lives until it
                // returns.
                unsafe { WaitNamedPipeW(wide(name).as_ptr(), 2000) };
                open()
            }
            other => other,
        };
        match f {
            Ok(mut f) => {
                let Some(server) = mine(&f, sid) else {
                    return false;
                };
                // This start came from the person, so it may hand the
                // foreground on: the open window comes to the front.
                // SAFETY: a plain call with the window's process id.
                unsafe { AllowSetForegroundWindow(server) };
                writeln!(f, "{}", line(start)).is_ok()
            }
            Err(_) => false,
        }
    }

    /// Whether the pipe `f` is open to is this user's (`sid`): the process
    /// that serves it runs as this user, and the pipe's owner is this user,
    /// which a program of another user cannot make it. Its process when so.
    fn mine(f: &std::fs::File, sid: &str) -> Option<u32> {
        let h = f.as_raw_handle() as HANDLE;
        let mut server = 0u32;
        // SAFETY: a query on the open pipe.
        if unsafe { GetNamedPipeServerProcessId(h, &mut server) } == 0 {
            return None;
        }
        (crate::broker::win::sid_of(server).as_deref() == Ok(sid)
            && owner_of(h).as_deref() == Ok(sid))
        .then_some(server)
    }

    /// The owner of the object `h` is open to, as a SID's text.
    fn owner_of(h: HANDLE) -> Result<String, String> {
        // SAFETY: the owner points into the descriptor Windows allocates,
        // which is freed after the owner was read.
        unsafe {
            let mut owner: PSID = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let e = GetSecurityInfo(
                h,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if e != 0 {
                return Err(format!("the pipe's owner: error {e}"));
            }
            let text = sid_text(owner);
            LocalFree(sd as HLOCAL);
            text
        }
    }

    impl Pipe {
        pub fn listen(&self, on: Box<dyn Fn(String) + Send + Sync>) {
            let Some(mut h) = self.first.lock().unwrap_or_else(|p| p.into_inner()).take() else {
                return;
            };
            let (name, sid) = (self.name.clone(), self.sid.clone());
            let stop = self.stop.clone();
            let t = std::thread::spawn(move || {
                loop {
                    // SAFETY: an instance of the pipe this process made.
                    let ok = unsafe { ConnectNamedPipe(h as _, std::ptr::null_mut()) } != 0
                        // ERROR_PIPE_CONNECTED: the client came first;
                        // ERROR_NO_DATA: and has gone already, its line
                        // still there to read.
                        || matches!(unsafe { GetLastError() }, 535 | 232);
                    // The window let the name go (Drop for Pipe).
                    if stop.load(std::sync::atomic::Ordering::SeqCst) {
                        // SAFETY: the instance this process made.
                        unsafe { CloseHandle(h as _) };
                        return;
                    }
                    // The next instance first, so the name stays this app's.
                    let next = make(&name, &sid, false);
                    if ok {
                        // SAFETY: the instance's handle, owned by the File.
                        let f = unsafe { std::fs::File::from_raw_handle(h as _) };
                        let mut text = String::new();
                        if BufReader::new(f).read_line(&mut text).is_ok() {
                            on(text);
                        }
                    } else {
                        // SAFETY: the instance this process made.
                        unsafe { CloseHandle(h as _) };
                    }
                    match next {
                        Some(n) => h = n,
                        None => return,
                    }
                }
            });
            *self.listening.lock().unwrap_or_else(|p| p.into_inner()) = Some(t);
        }
    }
}

#[cfg(test)]
mod start_tests {
    use super::*;

    /// A link on the command line is handed on, never kept by the window's
    /// process; the start that takes it reads it from stdin (#198).
    #[test]
    fn a_link_on_the_command_line_is_handed_on() {
        let link = "nerve://pair?center=x&code=c0de&pin=p1n";
        let of = |w: &[Option<&str>]| Start::of(w, "--uninstall");
        assert_eq!(of(&[Some(link)]), Start::HandOn(link.into()));
        assert_eq!(
            of(&[Some("NERVE://relay?address=x")]),
            Start::HandOn("NERVE://relay?address=x".into())
        );
        assert_eq!(of(&[Some(LINK_ON_STDIN)]), Start::LinkOnStdin);
        assert_eq!(of(&[]), Start::Window(Asked::default()));
        assert_eq!(
            of(&[Some("--uninstall")]),
            Start::Window(Asked {
                uninstall: true,
                ..Asked::default()
            })
        );
        for words in [
            vec![Some("status")],
            vec![Some(link), Some("x")],
            vec![None],
        ] {
            assert_eq!(of(&words), Start::Command, "{words:?}");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The link goes on the new start's stdin, its command line holds only
    /// [`LINK_ON_STDIN`] (#198).
    #[test]
    fn a_handed_on_link_is_on_stdin_not_on_the_command_line() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let program = d.path().join("app");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {0}/args\nprintf '%s' \"$WHO\" > {0}/env\ncat > {0}/input\n",
                d.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = "nerve://pair?center=x&code=c0de&pin=p1n";
        let mut child = hand_on(&program, link, &[("WHO", "software")]).unwrap();
        assert!(child.wait().unwrap().success());
        let read = |f: &str| std::fs::read_to_string(d.path().join(f)).unwrap();
        assert_eq!(read("args"), format!("{LINK_ON_STDIN}\n"));
        assert_eq!(read("input"), format!("{link}\n"));
        assert_eq!(read("env"), "software");
    }

    /// In a folder that other users may open, a socket there could be
    /// theirs: a start sends nothing to it and opens a window that says so.
    #[test]
    fn a_folder_others_may_open_gets_no_link() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o733)).unwrap();
        let sock = d.path().join("app.sock");
        let theirs = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        theirs.set_nonblocking(true).unwrap();
        let link = Asked::link("nerve://pair?center=x&code=c0de&pin=p1n");
        let Claimed::First(alone) = unix::claim_at(&sock, &link) else {
            panic!("the link went to a socket in a folder others may open");
        };
        assert_eq!(alone.note(), Some(unix::NOT_PRIVATE));
        assert!(theirs.accept().is_err(), "the start connected");
        // Nor does a start take the socket's place there.
        drop(theirs);
        std::fs::remove_file(&sock).unwrap();
        assert!(matches!(unix::claim_at(&sock, &link), Claimed::First(_)));
        assert!(!sock.exists());
    }

    #[test]
    fn a_second_start_goes_to_the_first() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        // Private, as $XDG_RUNTIME_DIR is.
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let sock = d.path().join("app.sock");
        let none = Asked::default();
        let Claimed::First(first) = unix::claim_at(&sock, &none) else {
            panic!("the first start is the first");
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        first.listen(move |a| {
            let _ = tx.lock().unwrap().send(a);
        });
        let starts = [
            Asked::link("nerve://pair?center=x"),
            none.clone(),
            Asked {
                uninstall: true,
                ..Asked::default()
            },
            Asked {
                program: Some("/home/alex/Downloads/nerve-node-desktop".into()),
                ..Asked::default()
            },
        ];
        for start in &starts {
            assert!(matches!(unix::claim_at(&sock, start), Claimed::Forwarded));
            let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(&got, start);
        }
        // Gone with the window: the next start is the first again, also
        // over a socket a crash left. That one is a datagram socket, which
        // no start can connect to: a listener closed here could still be
        // open a moment in a child another test forks.
        drop(first);
        assert!(!sock.exists());
        std::os::unix::net::UnixDatagram::bind(&sock)
            .map(drop)
            .unwrap();
        assert!(matches!(unix::claim_at(&sock, &none), Claimed::First(_)));
    }
}

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;

    /// A start sends nothing to a pipe of the name that is not this
    /// user's, and opens a window that says so. The pipe here is owned by
    /// the administrators, which only an elevated test can make; another
    /// user's program, the other way it could be not this user's, was run
    /// on the Windows test machine (review issue-10 r1).
    #[test]
    fn a_pipe_that_is_not_this_users_gets_nothing() {
        use std::io::Read;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::{HLOCAL, INVALID_HANDLE_VALUE, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND,
        };
        use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW};

        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let name = format!(
            r"\\.\pipe\nerve-node-desktop-test-{}",
            nerve_transport::keys::random_token(12)
        );
        // Owned by the administrators, open to everyone, as a squatter's
        // pipe would be open to its victim.
        let sddl = wide("O:BAD:P(A;;GA;;;WD)");
        // SAFETY: the descriptor is freed after the pipe took it.
        let h = unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                ),
                0
            );
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let h = CreateNamedPipeW(
                wide(&name).as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                0,
                1,
                0,
                4096,
                0,
                &sa,
            );
            LocalFree(sd as HLOCAL);
            h
        };
        if h == INVALID_HANDLE_VALUE {
            eprintln!("skipped: only an elevated test can give a pipe to the administrators");
            return;
        }
        let h = h as isize;
        let (tx, rx) = std::sync::mpsc::channel();
        let (end, ended) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            // SAFETY: the pipe this test made, owned by the File after.
            unsafe { ConnectNamedPipe(h as _, std::ptr::null_mut()) };
            let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
            let mut got = String::new();
            let _ = f.read_to_string(&mut got);
            let _ = tx.send(got);
            // The name stays held until the test is done.
            let _ = ended.recv();
        });
        let sid = crate::broker::win::own_sid().unwrap();
        let link = Asked::link("nerve://pair?center=x&code=c0de&pin=p1n");
        let Claimed::First(alone) = win::claim_at(&name, &sid, &link) else {
            panic!("the link went to a pipe that is not this user's");
        };
        assert_eq!(alone.note(), Some(win::HELD));
        // Whether the start connected or not, the pipe's server ends now.
        let _ = std::fs::OpenOptions::new().write(true).open(&name);
        let got = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        let _ = end.send(());
        assert_eq!(got, "", "the pipe got {got}");
    }

    /// A window that lets its claim go, listening or not, lets the next
    /// start be the first, as the start in software after a window error
    /// and the app the installer opens must be (review issue-10 r2).
    #[test]
    fn a_claim_let_go_makes_the_next_start_the_first() {
        let name = format!(
            r"\\.\pipe\nerve-node-desktop-test-{}",
            nerve_transport::keys::random_token(12)
        );
        let sid = crate::broker::win::own_sid().unwrap();
        for listening in [false, true] {
            let Claimed::First(first) = win::claim_at(&name, &sid, &Asked::default()) else {
                panic!("the first start is the first");
            };
            if listening {
                first.listen(|_| {});
            }
            drop(first);
            let Claimed::First(next) = win::claim_at(&name, &sid, &Asked::default()) else {
                panic!("a start after the window let go went to it (listening: {listening})");
            };
            drop(next);
        }
    }

    /// On the user's own pipe: run where the app is not open.
    #[test]
    fn a_second_start_goes_to_the_first_over_the_pipe() {
        let Claimed::First(first) = claim(&Asked::default()) else {
            panic!("the app is open: close it to run this test");
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        first.listen(move |a| {
            let _ = tx.lock().unwrap().send(a);
        });
        for start in [
            Asked::link("nerve://pair?center=x"),
            Asked::default(),
            Asked {
                uninstall: true,
                ..Asked::default()
            },
            Asked::link("nerve://pair?center=y"),
        ] {
            assert!(matches!(claim(&start), Claimed::Forwarded));
            let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(got, start);
        }
    }
}
