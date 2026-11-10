//! Providers on Windows, end to end on the installed service (#202): a
//! program of the owner attaches over the provider pipe, offers an action,
//! and the conformance fake center calls it. A program the owner did not
//! add, a name not allowed, another standard account's program (started
//! with `CreateProcessWithLogonW`, as broker_users.rs does) and a client
//! from the network are refused.
//!
//! It needs a Windows test machine: Nerve installed as a service (as CI's
//! `windows-installed` job installs it) whose owner is the account in
//! `NERVE_WIN_SUDO_ACCOUNT` with its password in `NERVE_WIN_SUDO_PASSWORD`,
//! another standard account in `NERVE_WIN_STD_ACCOUNT` and
//! `NERVE_WIN_STD_PASSWORD`, and an elevated terminal:
//!
//! ```text
//! cargo test -p nerve-node --test win_provider -- --ignored --exact the_owners_program_attaches_on_the_provider_pipe
//! ```
//!
//! The provider is this test program itself, copied to a folder every
//! account may read, run with [`PROVIDER`] set ([`provider_program`]). It
//! pairs the service with a center named `winprov` and allows the program
//! as the provider `wintest`, and takes both away again.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::edition::{DESKTOP_PROGRAM, Edition};
use nerve_node::service::Layout;
use nerve_policy::config::AllowedProvider;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW, LOGON_WITH_PROFILE,
    PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
};

const WAIT: Duration = Duration::from_secs(30);
const CENTER: &str = "winprov";
const NAME: &str = "wintest";
/// The provider pipe of the installed node (nerve-node's
/// `provider::PIPE_NAME`).
const PIPE: &str = r"\\.\pipe\nerve-node-provider";
/// The same pipe, reached as from another machine.
const REMOTE: &str = r"\\localhost\pipe\nerve-node-provider";
/// What makes this program a provider ([`provider_program`]):
/// `<name>|<pipe>|<log>`.
const PROVIDER: &str = "NERVE_W4_PROVIDER";
/// The folder every account may read the provider's copies from, and write
/// their logs to.
const DIR: &str = r"C:\nerve-w4-provider";

static APP: Edition = Edition {
    program: DESKTOP_PROGRAM,
    parts: None,
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A process started as another account, ended when dropped.
struct Started(HANDLE);

impl Drop for Started {
    fn drop(&mut self) {
        // SAFETY: the process handle CreateProcessWithLogonW gave.
        unsafe {
            TerminateProcess(self.0, 1);
            CloseHandle(self.0);
        }
    }
}

/// `exe` started as `user` with `password` as the provider `name`, writing
/// what the node answered to `log`; with no window, and an environment of
/// its own that names only what Windows needs and [`PROVIDER`].
fn start_as(user: &str, password: &str, exe: &Path, name: &str, log: &Path) -> Started {
    let _ = std::fs::remove_file(log);
    let mut line = wide(&format!(
        "\"{}\" --ignored --exact --nocapture provider_program",
        exe.display()
    ));
    let mut block = String::new();
    for k in ["SystemRoot", "SystemDrive", "windir"] {
        if let Ok(v) = std::env::var(k) {
            block.push_str(&format!("{k}={v}\0"));
        }
    }
    block.push_str(&format!("{PROVIDER}={name}|{PIPE}|{}\0\0", log.display()));
    let block: Vec<u16> = block.encode_utf16().collect();
    // SAFETY: filled structures and strings that live across the call; the
    // thread handle it gives is closed, the process handle is kept.
    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessWithLogonW(
            wide(user).as_ptr(),
            wide(".").as_ptr(),
            wide(password).as_ptr(),
            LOGON_WITH_PROFILE,
            std::ptr::null(),
            line.as_mut_ptr(),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            wide(DIR).as_ptr(),
            &si,
            &mut pi,
        );
        assert_ne!(ok, 0, "{user}: {}", std::io::Error::last_os_error());
        CloseHandle(pi.hThread);
        Started(pi.hProcess)
    }
}

/// The first line the provider at `log` wrote: the node's answer to its
/// hello, or why it could not ask.
fn said(log: &Path) -> String {
    let until = Instant::now() + WAIT;
    loop {
        if let Ok(s) = std::fs::read_to_string(log)
            && let Some(l) = s.lines().next()
        {
            return l.to_string();
        }
        assert!(Instant::now() < until, "{} stays empty", log.display());
        std::thread::sleep(Duration::from_millis(200));
    }
}

async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

/// The provider this program is when [`PROVIDER`] names one: it says hello
/// on the pipe, writes the first answer (or why it could not connect) to
/// its log, then answers each call of `wintest.echo` with what it was given
/// until the node lets it go.
#[tokio::test]
#[ignore = "the provider of the_owners_program_attaches_on_the_provider_pipe, which starts it"]
async fn provider_program() {
    let Ok(spec) = std::env::var(PROVIDER) else {
        return;
    };
    let mut parts = spec.splitn(3, '|');
    let (name, pipe, log) = (
        parts.next().unwrap().to_string(),
        parts.next().unwrap().to_string(),
        PathBuf::from(parts.next().unwrap()),
    );
    let write = |s: &str| std::fs::write(&log, format!("{s}\n")).unwrap();
    // As a plain open does: the node may act as this program, to look at
    // it as its account (tokio's default is identification only).
    let client = match tokio::net::windows::named_pipe::ClientOptions::new()
        .security_qos_flags(windows_sys::Win32::Storage::FileSystem::SECURITY_IMPERSONATION)
        .open(&pipe)
    {
        Ok(c) => c,
        Err(e) => return write(&format!("open: {e}")),
    };
    let (r, mut w) = tokio::io::split(client);
    let caps = json!([{"id": "wintest", "summary": "A test provider.",
        "actions": {"echo": {"effect": "read", "summary": "Says what it got.",
            "params": {"type": "object", "properties": {"text": {"type": "string"}}}}}}]);
    let hello = json!({"method": "hello",
        "params": {"role": "provider", "name": name, "capabilities": caps}});
    if let Err(e) = w.write_all(format!("{hello}\n").as_bytes()).await {
        return write(&format!("hello: {e}"));
    }
    let mut lines = BufReader::new(r).lines();
    let first = lines.next_line().await.ok().flatten().unwrap_or_default();
    write(&first);
    if !first.contains("\"ok\"") {
        return;
    }
    while let Ok(Some(line)) = lines.next_line().await {
        let m: Value = serde_json::from_str(&line).unwrap_or_default();
        if m["method"] != "invoke" {
            continue;
        }
        let answer = json!({"id": m["id"], "ok": {"echo": m["params"]["args"]["text"],
            "pid": std::process::id()}});
        if w.write_all(format!("{answer}\n").as_bytes()).await.is_err() {
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the node installed as a service on a Windows test machine"]
async fn the_owners_program_attaches_on_the_provider_pipe() {
    let owner = env("NERVE_WIN_SUDO_ACCOUNT");
    let owner_pw = env("NERVE_WIN_SUDO_PASSWORD");
    let other = env("NERVE_WIN_STD_ACCOUNT");
    let other_pw = env("NERVE_WIN_STD_PASSWORD");
    let layout = Layout::of(&APP);
    let paths = layout.paths.clone();

    // The program, and a copy under another name, where every account may
    // run them and write a log.
    let dir = Path::new(DIR);
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let ok = Command::new("icacls")
        .arg(dir)
        .args(["/grant", "*S-1-1-0:(OI)(CI)M"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "icacls");
    let me = std::env::current_exe().unwrap();
    let (exe, copy) = (dir.join("wintest.exe"), dir.join("other.exe"));
    std::fs::copy(&me, &exe).unwrap();
    std::fs::copy(&me, &copy).unwrap();

    let mut center = FakeCenter::start(false).await.unwrap();
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.centers.retain(|c| c.name != CENTER);
        cfg.providers.allowed.retain(|p| p.name != NAME);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let _ = std::fs::remove_file(paths.key_file(CENTER));
    nerve_node::pair::pair(&paths, &center.link(), Some(CENTER))
        .await
        .expect("pair");
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.providers.allowed.push(AllowedProvider {
            name: NAME.into(),
            exe: exe.display().to_string(),
        });
        let e = cfg.center_mut(CENTER).expect("paired");
        e.policy.mode = nerve_policy::Mode::Allowlist;
        e.policy.allow = vec!["wintest.echo".into()];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let mut conn = linked(&mut center).await;

    // A client from the network is refused by the pipe itself.
    let e = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(REMOTE)
        .map(|_| ())
        .expect_err("a remote client got in");
    eprintln!("a remote client: {e}");

    // Another standard account may not open the pipe.
    let log = dir.join("other-account.log");
    let p = start_as(&other, &other_pw, &exe, NAME, &log);
    let first = said(&log);
    assert!(first.starts_with("open:"), "{first}");
    drop(p);

    // The owner's other program under the allowed name, and the allowed
    // program under a name the owner did not add.
    let log = dir.join("copy.log");
    let p = start_as(&owner, &owner_pw, &copy, NAME, &log);
    let first = said(&log);
    assert!(first.contains("must be"), "{first}");
    drop(p);
    let log = dir.join("nobody.log");
    let p = start_as(&owner, &owner_pw, &exe, "nobody", &log);
    let first = said(&log);
    assert!(first.contains("names no provider nobody"), "{first}");
    drop(p);

    // The owner's program attaches.
    let log = dir.join("owner.log");
    let provider = start_as(&owner, &owner_pw, &exe, NAME, &log);
    let first = said(&log);
    assert!(first.contains("\"ok\""), "{first}");
    // `cap` of the installed program, as the app runs it, lists it.
    let o = Command::new(&layout.bin)
        .args(["cap", &format!("--center={CENTER}")])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains(&format!("program {NAME}: {}, attached", exe.display())),
        "{out}"
    );
    assert!(out.lines().any(|l| l.starts_with("wintest.echo")), "{out}");

    // The center sees its action and calls it; the call reaches the program.
    let until = Instant::now() + WAIT;
    let r = loop {
        let r = conn
            .call(
                "invoke",
                json!({"cap": "wintest", "action": "echo", "args": {"text": "hi"}}),
                WAIT,
            )
            .await
            .expect("an answer");
        match r {
            Ok(v) => break v,
            // The descriptor follows the attach a moment later.
            Err(e) if Instant::now() < until => {
                eprintln!("not yet: {}", e.message);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("{}", e.message),
        }
    };
    assert_eq!(r["echo"], "hi", "{r}");
    let d = conn
        .call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .expect("an answer")
        .expect("describe");
    assert!(d.to_string().contains("wintest"), "{d}");

    drop(provider);
    drop(conn);
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.centers.retain(|c| c.name != CENTER);
        cfg.providers.allowed.retain(|p| p.name != NAME);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let _ = std::fs::remove_dir_all(dir);
}
