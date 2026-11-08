//! Folder and allowlist mode as the command account on the installed Windows
//! service (#149), end to end: two pairings of the conformance fake center
//! run commands as `nerve-run`, each in its AppContainer. It checks that
//! - a command in its folder works, and one outside is refused and audited;
//! - one pairing reaches neither another's folders, nor its home, nor its
//!   processes;
//! - a folder without flags inside a `w` folder is closed;
//! - `nerve-run` itself opens neither the node's config and state folders,
//!   nor the owner's registry, nor the node's pipes;
//! - with the network off a connection and a sudo command are refused.
//!
//! It needs a Windows test machine: Nerve installed as a service by the
//! account in `NERVE_WIN_SUDO_ACCOUNT` (password in `NERVE_WIN_SUDO_PASSWORD`),
//! the network, and an elevated terminal (CI's `windows-installed` job):
//!
//! ```text
//! cargo test -p nerve-node --test win_account -- --ignored
//! ```
//!
//! It pairs the service with the centers `wina` and `winb`, and removes them
//! and its folder again.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::edition::{DESKTOP_PROGRAM, Edition};
use nerve_node::service::Layout;
use nerve_policy::config::{Access, Folder};
use nerve_proto::{ErrorCode, RpcError};
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(90);
const A: &str = "wina";
const B: &str = "winb";
/// The desktop app, whose program is the node's on Windows (#176).
static APP: Edition = Edition {
    program: DESKTOP_PROGRAM,
    parts: None,
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

/// The first link of the node's that completes the handshake.
async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let until = tokio::time::Instant::now() + WAIT;
    let mut ended = Vec::new();
    while let Some(mut inc) = center
        .next_link(until.saturating_duration_since(tokio::time::Instant::now()))
        .await
    {
        match fake_center::handshake(&mut inc.conn, &center.center_id, &paired).await {
            Ok(_) => return inc.conn,
            Err(e) => ended.push(e),
        }
    }
    panic!("no link of the node completed the handshake; those that ended: {ended:?}");
}

async fn run_in(conn: &mut Conn<TcpStream>, cwd: &Path, command: &str) -> Result<Value, RpcError> {
    let wire = nerve_policy::paths::to_wire(cwd);
    let id = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": command, "cwd": wire}}),
        )
        .await
        .unwrap();
    conn.answer(id, WAIT, &mut Vec::new()).await.unwrap()
}

fn out(r: &Value) -> String {
    format!(
        "{}{}",
        r["stdout"].as_str().unwrap_or_default(),
        r["stderr"].as_str().unwrap_or_default()
    )
}

fn folder(p: &Path, access: &str) -> Folder {
    Folder {
        path: p.display().to_string(),
        access: Access::parse(access).unwrap(),
    }
}

/// A folder only SYSTEM, the administrators and the owner may open, as a
/// folder of the owner's own: `nerve-run` and its containers reach what is
/// below only by the node's grants.
fn owners_folder(p: &Path, owner_sid: &str) {
    std::fs::create_dir_all(p).unwrap();
    let ok = Command::new("icacls")
        .arg(p)
        .args(["/inheritance:r", "/grant:r"])
        .args([
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            &format!("*{owner_sid}:(OI)(CI)F"),
        ])
        .status()
        .unwrap()
        .success();
    assert!(ok, "icacls {p:?}");
}

/// The command account's password, as the install stored it.
fn run_password(config: &Path) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};
    let blob = std::fs::read(config.join("run-account.dpapi")).unwrap();
    let entropy = b"nerve-node: the password of the account commands run as";
    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr().cast_mut(),
    };
    let e = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut plain = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: blobs of their sizes; the output is freed below.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &e,
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut plain,
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: DPAPI's buffer of `cbData` bytes, freed once.
    let bytes = unsafe {
        let v = std::slice::from_raw_parts(plain.pbData, plain.cbData as usize).to_vec();
        LocalFree(plain.pbData.cast());
        v
    };
    let at = bytes.iter().position(|&b| b == 0).unwrap();
    assert_eq!(&bytes[..at], b"nerve-run");
    String::from_utf8(bytes[at + 1..].to_vec()).unwrap()
}

/// A logon of `name` with `password`, as `kind` (LOGON32_LOGON_*).
fn logon(name: &str, password: &str, kind: u32) -> windows_sys::Win32::Foundation::HANDLE {
    use windows_sys::Win32::Security::{LOGON32_PROVIDER_DEFAULT, LogonUserW};
    let mut t = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings and a place for the token.
    let ok = unsafe {
        LogonUserW(
            wide(name).as_ptr(),
            wide(".").as_ptr(),
            wide(password).as_ptr(),
            kind,
            LOGON32_PROVIDER_DEFAULT,
            &mut t,
        )
    };
    assert_ne!(ok, 0, "logon {name}: {}", std::io::Error::last_os_error());
    t
}

/// What of `files`, `keys` (below HKEY_USERS) and `pipes` the account of
/// the token `t` opens.
fn opened_as(
    t: windows_sys::Win32::Foundation::HANDLE,
    files: &[PathBuf],
    keys: &[String],
) -> Vec<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Registry::{HKEY_USERS, KEY_READ, RegCloseKey, RegOpenKeyExW};
    let mut opened = Vec::new();
    // SAFETY: a logon token; RevertToSelf below ends it.
    assert_ne!(unsafe { ImpersonateLoggedOnUser(t) }, 0);
    for f in files {
        // SAFETY: a NUL-terminated path; the handle is closed at once.
        let h = unsafe {
            CreateFileW(
                wide(f).as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            // SAFETY: the handle just opened.
            unsafe { CloseHandle(h) };
            opened.push(f.display().to_string());
        }
    }
    for k in keys {
        let mut h = std::ptr::null_mut();
        // SAFETY: a NUL-terminated key name and a place for the handle.
        if unsafe { RegOpenKeyExW(HKEY_USERS, wide(k).as_ptr(), 0, KEY_READ, &mut h) } == 0 {
            // SAFETY: the key just opened.
            unsafe { RegCloseKey(h) };
            opened.push(format!("HKEY_USERS\\{k}"));
        }
    }
    // SAFETY: plain call.
    unsafe { RevertToSelf() };
    opened
}

/// Loads the profile of the logon `t` of `name`, as a sign-in does: the
/// owner's registry is there while the owner works.
fn load_profile(t: windows_sys::Win32::Foundation::HANDLE, name: &str) {
    use windows_sys::Win32::UI::Shell::{LoadUserProfileW, PROFILEINFOW};
    let mut user = wide(name);
    let mut info = PROFILEINFOW {
        dwSize: size_of::<PROFILEINFOW>() as u32,
        dwFlags: 1,
        lpUserName: user.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: a logon token and a filled PROFILEINFOW; it stays loaded for
    // the test.
    let ok = unsafe { LoadUserProfileW(t, &mut info) };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
}

async fn forget(paths: &nerve_node::NodePaths) {
    let _ = nerve_node::cli::edit(paths, |cfg| {
        cfg.centers.retain(|c| c.name != A && c.name != B);
        Ok(())
    })
    .await;
    for c in [A, B] {
        let _ = std::fs::remove_file(paths.key_file(c));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the node installed as a service on a Windows test machine"]
async fn folder_and_allowlist_mode_run_as_nerve_run_in_their_containers() {
    let layout = Layout::of(&APP);
    let paths = layout.paths.clone();
    let owner = env("NERVE_WIN_SUDO_ACCOUNT");
    let owner_password = env("NERVE_WIN_SUDO_PASSWORD");
    let owner_sid = env("NERVE_TEST_SID");
    let base =
        PathBuf::from(std::env::var("SystemDrive").unwrap_or("C:".into()) + "\\nerve-w2-test");
    let _ = std::fs::remove_dir_all(&base);
    owners_folder(&base, &owner_sid);
    let (a, closed, b) = (
        base.join("a"),
        base.join("a").join("closed"),
        base.join("b"),
    );
    for d in [&a, &closed, &b] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(b.join("secret.txt"), "b's").unwrap();
    std::fs::write(closed.join("kept.txt"), "closed").unwrap();
    forget(&paths).await;
    let mut ca = FakeCenter::start(false).await.unwrap();
    let mut cb = FakeCenter::start(false).await.unwrap();
    nerve_node::pair::pair(&paths, &ca.link(), Some(A))
        .await
        .expect("pair a");
    nerve_node::pair::pair(&paths, &cb.link(), Some(B))
        .await
        .expect("pair b");
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.mode = nerve_policy::Mode::Folder;
        ea.policy.folders = vec![folder(&a, "rwx"), folder(&closed, "")];
        let eb = cfg.center_mut(B).expect("paired");
        eb.policy.mode = nerve_policy::Mode::Folder;
        eb.policy.folders = vec![folder(&b, "rwx")];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let cfg = nerve_policy::SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
    let container_b = nerve_node::grants::container(&paths, &cfg.center(B).unwrap().node_id);
    let mut conn_a = linked(&mut ca).await;
    let mut conn_b = linked(&mut cb).await;

    // In its folder a command runs, as nerve-run, in its container, with
    // its home there.
    let r = run_in(
        &mut conn_a,
        &a,
        "Set-Content -Path ok.txt -Value ok; Get-Content ok.txt; whoami; $env:USERPROFILE",
    )
    .await
    .expect("a command in its folder");
    let said = out(&r);
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(
        said.contains("ok") && said.to_lowercase().contains("nerve-run"),
        "{r}"
    );
    assert!(said.contains("\\AC\\home"), "{r}");
    assert!(a.join("ok.txt").is_file());

    // Outside its folders it is refused, and that is in the audit log.
    let e = run_in(&mut conn_a, &b, "Get-ChildItem").await.unwrap_err();
    assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
    let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
    assert!(
        audit
            .lines()
            .any(|l| l.contains("\"forbidden\"") && l.contains(&nerve_policy::paths::to_wire(&b))),
        "no audit entry for the refused command"
    );

    // A command of one pairing reaches neither the other's folder, nor its
    // home, nor a folder without flags inside its own `w` folder.
    let ac = format!("C:\\Users\\nerve-run\\AppData\\Local\\Packages\\{container_b}\\AC");
    for (what, script) in [
        (
            "b's folder",
            format!("Get-Content '{}'", b.join("secret.txt").display()),
        ),
        ("b's home", format!("Get-ChildItem '{ac}'")),
        (
            "the closed folder",
            format!("Get-ChildItem '{}'", closed.display()),
        ),
        (
            "the closed folder's file",
            format!("Get-Content '{}'", closed.join("kept.txt").display()),
        ),
        (
            "a write to the closed folder",
            format!(
                "Set-Content -Path '{}' -Value x",
                closed.join("new.txt").display()
            ),
        ),
    ] {
        let r = run_in(&mut conn_a, &a, &format!("{script}; exit [int](-not $?)"))
            .await
            .expect(what);
        assert_ne!(r["exit_code"], 0, "{what}: {r}");
        assert!(
            !out(&r).contains("b's") && !out(&r).contains("closed\r\n"),
            "{what}: {r}"
        );
    }
    assert!(!closed.join("new.txt").exists());

    // Nor its processes: b's command waits, a's does not see or open it.
    let b_dir = b.clone();
    let waiting = tokio::spawn(async move {
        let r = run_in(
            &mut conn_b,
            &b_dir,
            "Set-Content -Path pid.txt -Value $PID; Start-Sleep -Seconds 40",
        )
        .await;
        (conn_b, r)
    });
    let pid_file = b.join("pid.txt");
    let until = std::time::Instant::now() + Duration::from_secs(60);
    let pid = loop {
        if let Some(p) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            break p;
        }
        assert!(
            std::time::Instant::now() < until,
            "b's command did not start"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let r = run_in(
        &mut conn_a,
        &a,
        &format!(
            "$all = @(Get-Process); 'count ' + $all.Count; \
             if ($all.Id -contains {pid}) {{ 'seen' }}; \
             try {{ Stop-Process -Id {pid} -Force -ErrorAction Stop; 'stopped' }} catch {{ 'not stopped' }}"
        ),
    )
    .await
    .expect("a's look at b's process");
    let said = out(&r);
    assert!(
        !said.contains("seen") && said.contains("not stopped"),
        "{r}"
    );
    let (mut conn_b, waited) = waiting.await.unwrap();
    assert_eq!(waited.expect("b's command")["exit_code"], 0);

    // nerve-run itself opens neither the node's folders, nor the owner's
    // registry, nor the node's pipes.
    let run_logon = logon("nerve-run", &run_password(&paths.config_dir), 4);
    let owner_logon = logon(&owner, &owner_password, 2);
    load_profile(owner_logon, &owner);
    let mut files = vec![
        paths.config_dir.clone(),
        paths.config_file(),
        paths.state_dir.clone(),
        paths.audit_log(),
    ];
    let pipes: Vec<PathBuf> = std::fs::read_dir(r"\\.\pipe\")
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().contains("nerve-node"))
        .collect();
    assert!(!pipes.is_empty(), "the node's pipes are not there");
    files.extend(pipes);
    let keys = vec![owner_sid.clone(), format!("{owner_sid}\\Environment")];
    let opened = opened_as(run_logon, &files, &keys);
    assert!(opened.is_empty(), "nerve-run opened {opened:?}");
    // The owner's registry was loaded, or that would prove nothing.
    let mut h = std::ptr::null_mut();
    // SAFETY: a NUL-terminated key name and a place for the handle.
    let loaded = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExW(
            windows_sys::Win32::System::Registry::HKEY_USERS,
            wide(&owner_sid).as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut h,
        )
    };
    assert_eq!(loaded, 0, "the owner's registry is not loaded");

    // With b's network off, its command connects nowhere, and no sudo
    // command runs; with it on again it connects.
    let connect = "try { $c = [Net.Sockets.TcpClient]::new(); $c.Connect('1.1.1.1', 443); 'connected' } catch { 'refused' }";
    let r = run_in(&mut conn_b, &b, connect)
        .await
        .expect("with the network");
    assert!(out(&r).contains("connected"), "{r}");
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.center_mut(B).expect("paired").policy.no_network = true;
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_in(&mut conn_b, &b, connect)
        .await
        .expect("without the network");
    assert!(
        out(&r).contains("refused") && !out(&r).contains("connected"),
        "{r}"
    );
    let e = run_in(&mut conn_b, &b, "sudo whoami").await.unwrap_err();
    assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
    assert!(e.message.contains("sudo list"), "{}", e.message);

    forget(&paths).await;
    let _ = std::fs::remove_dir_all(&base);
}
