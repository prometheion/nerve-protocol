//! Folder and allowlist mode as the command account on the installed Windows
//! service (#149), end to end: three pairings of the conformance fake center
//! run commands as `nerve-run`, each in its AppContainer, two in folder mode
//! and one in allowlist mode. It checks that
//! - a command in its folder works, and one outside is refused and audited;
//! - one pairing reaches neither another's folders, nor its home, nor its
//!   processes, nor `nerve-run`'s own profile, nor the node's pipes, by a
//!   command or by the node's file calls (read as its container, Q4);
//! - a folder without flags inside a `w` folder is closed;
//! - a project whose files are hard links to a store outside it gets its
//!   `w` grant, and those files are read but not written, through either
//!   name; closed with a folder that holds them, under both names;
//! - a file linked into that project after its grant, yours from a store or
//!   a command's from its own, gets its entries within the node's bound,
//!   with no Sync folders;
//! - a folder in the owner's profile that holds a protected entry gives
//!   its other entries, and the entry stays closed;
//! - the owner's Documents folder redirected elsewhere (as by OneDrive's
//!   backup) keeps PowerShell's profiles there protected;
//! - allowlist mode runs as `nerve-run` in its container, and `--as-owner`
//!   as the owner;
//! - a folder outside the owner's profile whose files `nerve-run` made
//!   changes its flags all the same, and one `nerve-run` made there can be
//!   closed;
//! - `nerve-run` itself opens neither the node's config and state folders,
//!   nor the owner's registry, nor the node's pipes;
//! - with the network off a connection and a sudo command are refused;
//! - a pairing's home stays when its last folder goes, and its container's
//!   profile goes with the pairing.
//!
//! It needs a Windows test machine: Nerve installed as a service by the
//! account in `NERVE_WIN_SUDO_ACCOUNT` (password in `NERVE_WIN_SUDO_PASSWORD`),
//! the network, and an elevated terminal (CI's `windows-installed` job):
//!
//! ```text
//! cargo test -p nerve-node --test win_account -- --ignored
//! ```
//!
//! It pairs the service with the centers `wina`, `winb` and `winc`, and
//! removes them and its folders again.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

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
const C: &str = "winc";
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
    call(
        conn,
        "exec",
        "run",
        json!({"command": command, "cwd": wire}),
    )
    .await
}

/// A command that starts in its pairing's home.
async fn run_home(conn: &mut Conn<TcpStream>, command: &str) -> Result<Value, RpcError> {
    call(conn, "exec", "run", json!({"command": command})).await
}

async fn call(
    conn: &mut Conn<TcpStream>,
    cap: &str,
    action: &str,
    args: Value,
) -> Result<Value, RpcError> {
    let id = conn
        .request(
            "invoke",
            json!({"cap": cap, "action": action, "args": args}),
        )
        .await
        .unwrap();
    conn.answer(id, WAIT, &mut Vec::new()).await.unwrap()
}

/// Waits until `done` holds, at most a minute.
async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(std::time::Instant::now() < end, "{what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
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

/// A folder made below the drive's root as the owner's, with the rights it
/// inherits there (on Windows: every signed-in user may change what is in
/// it, but not its permissions): what `nerve-run` makes in it is
/// `nerve-run`'s own, whose permissions the owner may not change.
fn open_folder(p: &Path, owner_sid: &str) {
    std::fs::create_dir_all(p).unwrap();
    let ok = Command::new("icacls")
        .arg(p)
        .args(["/setowner", &format!("*{owner_sid}")])
        .status()
        .unwrap()
        .success();
    assert!(ok, "icacls /setowner {p:?}");
}

/// The profile folder of the account `sid`, as Windows has it.
fn owner_profile(sid: &str) -> PathBuf {
    let said = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "(Get-CimInstance Win32_UserProfile | Where-Object SID -eq '{sid}').LocalPath"
        ))
        .output()
        .unwrap();
    let path = String::from_utf8_lossy(&said.stdout).trim().to_string();
    assert!(!path.is_empty(), "no profile of {sid}");
    PathBuf::from(path)
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
        cfg.centers
            .retain(|c| ![A, B, C].contains(&c.name.as_str()));
        Ok(())
    })
    .await;
    for c in [A, B, C] {
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
    let drive = std::env::var("SystemDrive").unwrap_or("C:".into());
    let base = PathBuf::from(drive.clone() + "\\nerve-w2-test");
    let open = PathBuf::from(drive + "\\nerve-w2-open");
    // In the owner's profile, with the rights it inherits there: only
    // SYSTEM, the administrators and the owner may list it.
    let mine = owner_profile(&owner_sid).join("nerve-w2-mine");
    for d in [&base, &open, &mine] {
        let _ = std::fs::remove_dir_all(d);
    }
    owners_folder(&base, &owner_sid);
    open_folder(&open, &owner_sid);
    let (a, closed, b, c) = (
        base.join("a"),
        base.join("a").join("closed"),
        base.join("b"),
        base.join("c"),
    );
    for d in [&a, &closed, &b, &c] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(b.join("secret.txt"), "b's").unwrap();
    std::fs::write(closed.join("kept.txt"), "closed").unwrap();
    forget(&paths).await;
    let mut ca = FakeCenter::start(false).await.unwrap();
    let mut cb = FakeCenter::start(false).await.unwrap();
    let mut cc = FakeCenter::start(false).await.unwrap();
    nerve_node::pair::pair(&paths, &ca.link(), Some(A))
        .await
        .expect("pair a");
    nerve_node::pair::pair(&paths, &cb.link(), Some(B))
        .await
        .expect("pair b");
    nerve_node::pair::pair(&paths, &cc.link(), Some(C))
        .await
        .expect("pair c");
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.mode = nerve_policy::Mode::Folder;
        ea.policy.folders = vec![folder(&a, "rwx"), folder(&closed, ""), folder(&open, "rwx")];
        let eb = cfg.center_mut(B).expect("paired");
        eb.policy.mode = nerve_policy::Mode::Folder;
        eb.policy.folders = vec![folder(&b, "rwx")];
        let ec = cfg.center_mut(C).expect("paired");
        ec.policy.mode = nerve_policy::Mode::Allowlist;
        ec.policy.folders = vec![folder(&c, "rwx")];
        ec.policy.allow = vec!["exec.run:*".into()];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let cfg = nerve_policy::SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
    let container_a = nerve_node::grants::container(&paths, &cfg.center(A).unwrap().node_id);
    let container_b = nerve_node::grants::container(&paths, &cfg.center(B).unwrap().node_id);
    // Its profile is where Windows put it: `C:\Users\nerve-run.<machine>`
    // where an earlier account of that name left its folder.
    let run_profile = nerve_node::account::lookup(nerve_node::account::RUN_USER)
        .unwrap()
        .expect("nerve-run")
        .home;
    let packages = run_profile.join(r"AppData\Local\Packages");
    let mut conn_a = linked(&mut ca).await;
    let mut conn_b = linked(&mut cb).await;
    let mut conn_c = linked(&mut cc).await;

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

    // Outside its folders it is refused, and that is in the audit log: the
    // node looks at the folder as a's container, which may not look into
    // b's, so it does not resolve.
    let e = run_in(&mut conn_a, &b, "Get-ChildItem").await.unwrap_err();
    assert_eq!(e.kind().as_str(), "bad_path", "{}", e.message);
    let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
    assert!(
        audit
            .lines()
            .any(|l| l.contains("\"forbidden\"") && l.contains(&nerve_policy::paths::to_wire(&b))),
        "no audit entry for the refused command"
    );

    // A command of one pairing reaches neither the other's folder, nor its
    // home, nor a folder without flags inside its own `w` folder.
    let ac = packages.join(&container_b).join("AC").display().to_string();
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
        // The account's own profile is closed to its containers (#167).
        (
            "nerve-run's profile",
            format!("Get-ChildItem '{}'", run_profile.display()),
        ),
        (
            "nerve-run's settings",
            format!(
                "Get-ChildItem '{}'",
                run_profile.join(r"AppData\Roaming").display()
            ),
        ),
        (
            "nerve-run's containers",
            format!("Get-ChildItem '{}'", packages.display()),
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

    // The node's own file calls for a read as a's container (Q4): neither
    // b's file, nor b's home, nor the closed folder, also not by a walk.
    for (what, action, args) in [
        (
            "b's file",
            "read",
            json!({"path": nerve_policy::paths::to_wire(&b.join("secret.txt"))}),
        ),
        (
            "b's home",
            "list",
            json!({"path": nerve_policy::paths::to_wire(&PathBuf::from(&ac))}),
        ),
        (
            "the closed folder",
            "list",
            json!({"path": nerve_policy::paths::to_wire(&closed)}),
        ),
        (
            "the closed folder's file",
            "read",
            json!({"path": nerve_policy::paths::to_wire(&closed.join("kept.txt"))}),
        ),
        (
            "a walk for b's file",
            "grep",
            json!({"path": nerve_policy::paths::to_wire(&base), "pattern": "b's"}),
        ),
        (
            "a walk for the closed folder's file",
            "grep",
            json!({"path": nerve_policy::paths::to_wire(&base), "pattern": "closed"}),
        ),
        (
            "a walk for the names",
            "find",
            json!({"path": nerve_policy::paths::to_wire(&base), "glob": "**/*.txt"}),
        ),
    ] {
        // Refused, or nothing of theirs in it.
        if let Ok(r) = call(&mut conn_a, "fs", action, args).await {
            let text = r.to_string();
            assert!(
                !text.contains("b's") && !text.contains("secret.txt") && !text.contains("kept.txt"),
                "{what}: {r}"
            );
        }
    }

    // A project whose files are linked to a store outside it, as pnpm's
    // `node_modules`: its `rw` grant goes on, and the commands run. The
    // linked file reads, but is written through neither name, and the store
    // gets no write entry for the container; the project's own files are
    // written. A command cannot link a file it may not write.
    let (proj, store) = (base.join("proj"), base.join("store"));
    let (in_proj, in_store) = (
        proj.join("node_modules").join("pkg").join("index.js"),
        store.join("pkg").join("index.js"),
    );
    for f in [&in_proj, &in_store] {
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    }
    std::fs::write(&in_store, "from the store").unwrap();
    std::fs::hard_link(&in_store, &in_proj).unwrap();
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.folders.push(folder(&proj, "rw"));
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_in(
        &mut conn_a,
        &proj,
        "Get-Content node_modules\\pkg\\index.js; Set-Content -Path own.txt -Value mine; Get-Content own.txt",
    )
    .await
    .expect("a's command in the linked project");
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(
        out(&r).contains("from the store") && out(&r).contains("mine"),
        "{r}"
    );
    for (what, script) in [
        (
            "a write through the project's name",
            format!("Add-Content -Path '{}' -Value x", in_proj.display()),
        ),
        (
            "a write through the store's name",
            format!("Add-Content -Path '{}' -Value x", in_store.display()),
        ),
        (
            "a link to the store's file",
            format!(
                "New-Item -ItemType HardLink -Path '{}' -Target '{}'",
                proj.join("again.js").display(),
                in_store.display()
            ),
        ),
    ] {
        let r = run_in(
            &mut conn_a,
            &proj,
            &format!("{script}; exit [int](-not $?)"),
        )
        .await
        .expect(what);
        assert_ne!(r["exit_code"], 0, "{what}: {r}");
    }
    assert_eq!(
        std::fs::read_to_string(&in_store).unwrap(),
        "from the store"
    );
    assert!(!proj.join("again.js").exists());
    // The container's entries on the file: none allows a write.
    let listed = Command::new("icacls").arg(&in_store).output().unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    let allows: Vec<&str> = listed
        .lines()
        .filter(|l| l.contains("S-1-15-2-") && !l.contains("(DENY)"))
        .collect();
    assert!(!allows.is_empty(), "{listed}");
    for l in &allows {
        assert!(
            !["(W", ",W", "(M)", "(F)"].iter().any(|w| l.contains(w)),
            "{listed}"
        );
    }
    // A file a command links from a store of its own: pnpm and uv keep
    // theirs in LOCALAPPDATA, which for a command is a folder below
    // `nerve-run`'s profile that the owner, as whom the node changes the
    // folders, may not open. A later change of the project's flags walks it
    // all the same (the node finds that name as `nerve-run`), and the
    // commands go on running.
    let r = run_in(
        &mut conn_a,
        &proj,
        "$s = Join-Path $env:LOCALAPPDATA 'nrv-store'; New-Item -ItemType Directory -Force -Path $s | Out-Null; Set-Content -Path (Join-Path $s 'f.js') -Value stored; New-Item -ItemType HardLink -Path linked.js -Target (Join-Path $s 'f.js') | Out-Null; exit [int](-not $?)",
    )
    .await
    .expect("a's link from its own store");
    assert_eq!(r["exit_code"], 0, "{r}");
    for flags in ["rwx", "rw"] {
        nerve_node::cli::edit(&paths, |cfg| {
            let ea = cfg.center_mut(A).expect("paired");
            for f in &mut ea.policy.folders {
                if Path::new(&f.path) == proj {
                    f.access = Access::parse(flags).unwrap();
                }
            }
            Ok(())
        })
        .await
        .expect("the owner's edit");
        let r = run_in(
            &mut conn_a,
            &proj,
            "Get-Content linked.js; exit [int](-not $?)",
        )
        .await
        .expect(flags);
        assert_eq!(r["exit_code"], 0, "{flags}: {r}");
        assert!(out(&r).contains("stored"), "{flags}: {r}");
    }
    // Installed into the project after its grant, with no Sync folders and
    // no change of the config: the node walks the project by itself soon
    // after the names stop changing (crate::grant_watch). A file you link
    // from your store becomes readable to a's commands, and one a's command
    // links from its own store gets the node's entries (among them its
    // denial of writes for the container), which give you its read where
    // you could not open it.
    let late = store.join("late.js");
    std::fs::write(&late, "late from the store").unwrap();
    std::fs::hard_link(&late, proj.join("late.js")).unwrap();
    let r = run_in(
        &mut conn_a,
        &proj,
        "$s = Join-Path $env:LOCALAPPDATA 'nrv-store'; Set-Content -Path (Join-Path $s 'g.js') -Value installed; New-Item -ItemType HardLink -Path agent.js -Target (Join-Path $s 'g.js') | Out-Null; exit [int](-not $?)",
    )
    .await
    .expect("a's install from its own store");
    assert_eq!(r["exit_code"], 0, "{r}");
    let capped = |p: &Path| {
        let listed = Command::new("icacls").arg(p).output().unwrap();
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|l| l.contains("S-1-15-2-") && l.contains("(DENY)"))
    };
    // The node's quiet time and bound, and the walk.
    let until = Instant::now() + Duration::from_secs(90);
    loop {
        let r = run_in(
            &mut conn_a,
            &proj,
            "Get-Content late.js; exit [int](-not $?)",
        )
        .await
        .expect("a's read of the late file");
        if out(&r).contains("late from the store") && capped(&proj.join("agent.js")) {
            break;
        }
        assert!(
            Instant::now() < until,
            "not walked by itself within 90 s: {r}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert_eq!(
        std::fs::read_to_string(proj.join("agent.js"))
            .unwrap()
            .trim(),
        "installed"
    );
    // Closing the folder that holds it: the commands go on running, and
    // the file is closed under both names, also after the project's
    // flags change (a change of the folder around it) and the next sync.
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy
            .folders
            .push(folder(&proj.join("node_modules"), ""));
        Ok(())
    })
    .await
    .expect("the owner's edit");
    for round in ["closed", "changed around it"] {
        let r = run_in(&mut conn_a, &proj, "Get-Content own.txt")
            .await
            .expect(round);
        assert!(out(&r).contains("mine"), "{round}: {r}");
        for name in [&in_proj, &in_store] {
            let r = run_in(
                &mut conn_a,
                &proj,
                &format!("Get-Content '{}'; exit [int](-not $?)", name.display()),
            )
            .await
            .expect(round);
            assert_ne!(r["exit_code"], 0, "{round}: {name:?}: {r}");
            assert!(
                !out(&r).contains("from the store"),
                "{round}: {name:?}: {r}"
            );
        }
        nerve_node::cli::edit(&paths, |cfg| {
            let ea = cfg.center_mut(A).expect("paired");
            for f in &mut ea.policy.folders {
                if Path::new(&f.path) == proj {
                    f.access = Access::parse("rwx").unwrap();
                }
            }
            Ok(())
        })
        .await
        .expect("the owner's edit");
    }
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy
            .folders
            .retain(|f| !Path::new(&f.path).starts_with(&proj));
        Ok(())
    })
    .await
    .expect("the owner's edit");

    // A folder in the owner's profile that holds a protected entry: the
    // service's account may not list it, so the node splits it around the
    // entry as the owner. A command reads a file beside the entry and is
    // refused at the entry.
    let keep = mine.join("keep");
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::write(mine.join("beside.txt"), "beside").unwrap();
    std::fs::write(keep.join("key.txt"), "kept").unwrap();
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.folders.push(folder(&mine, "r"));
        ea.policy.protected.extra = vec![keep.display().to_string()];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_in(
        &mut conn_a,
        &a,
        &format!("Get-Content '{}'", mine.join("beside.txt").display()),
    )
    .await
    .expect("a's read beside the protected entry");
    assert!(out(&r).contains("beside"), "{r}");
    let r = run_in(
        &mut conn_a,
        &a,
        &format!(
            "Get-Content '{}'; exit [int](-not $?)",
            keep.join("key.txt").display()
        ),
    )
    .await
    .expect("a's read of the protected entry");
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!out(&r).contains("kept"), "{r}");

    // The owner's Documents folder redirected (as OneDrive's backup does):
    // PowerShell's profiles there are protected as in the usual place, read
    // from the owner's registry by the service. A granted folder there is
    // given as its other entries.
    let docs =
        PathBuf::from(std::env::var("SystemDrive").unwrap_or("C:".into()) + "\\nerve-w2-docs");
    let _ = std::fs::remove_dir_all(&docs);
    owners_folder(&docs, &owner_sid);
    std::fs::create_dir(docs.join("WindowsPowerShell")).unwrap();
    std::fs::write(docs.join("WindowsPowerShell").join("profile.ps1"), "# mine").unwrap();
    std::fs::write(docs.join("beside.txt"), "before").unwrap();
    load_profile(logon(&owner, &owner_password, 2), &owner);
    let folders_key = format!(
        "HKU\\{owner_sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    );
    let reg = |args: &[&str]| {
        let o = Command::new("reg").args(args).output().unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
        )
    };
    let (_, before) = reg(&["query", &folders_key, "/v", "Personal"]);
    let before = before
        .lines()
        .find(|l| l.contains("Personal"))
        .and_then(|l| l.split("REG_EXPAND_SZ").nth(1).or(l.split("REG_SZ").nth(1)))
        .map(|v| v.trim().to_string())
        .unwrap_or("%USERPROFILE%\\Documents".into());
    let set = |value: &str| {
        let (ok, _) = reg(&[
            "add",
            &folders_key,
            "/v",
            "Personal",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            value,
            "/f",
        ]);
        assert!(ok, "reg add {value}");
    };
    set(&docs.display().to_string());
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.folders.push(folder(&docs, "rw"));
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let beside = run_in(
        &mut conn_a,
        &a,
        &format!(
            "Set-Content -Path '{}' -Value beside",
            docs.join("beside.txt").display()
        ),
    )
    .await;
    let profile = run_in(
        &mut conn_a,
        &a,
        &format!(
            "Set-Content -Path '{}' -Value taken; exit [int](-not $?)",
            docs.join("WindowsPowerShell").join("profile.ps1").display()
        ),
    )
    .await;
    // Remembered for when the owner's registry is not loaded, in the
    // node's state folder, which the owner the sync acts as may not write.
    let seen = std::fs::read_to_string(paths.state_dir.join("owner-documents.json"))
        .expect("the owner's Documents folder remembered");
    set(&before);
    assert!(seen.contains("nerve-w2-docs"), "{seen}");
    // Refused by the guard, or by the folder's missing entry.
    if let Ok(r) = &profile {
        assert_ne!(r["exit_code"], 0, "{r}");
    }
    assert_eq!(
        std::fs::read_to_string(docs.join("WindowsPowerShell").join("profile.ps1")).unwrap(),
        "# mine"
    );
    let beside = beside.expect("a's write beside the profiles");
    assert_eq!(beside["exit_code"], 0, "{beside}");
    assert!(
        std::fs::read_to_string(docs.join("beside.txt"))
            .unwrap()
            .contains("beside")
    );
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.folders.retain(|f| Path::new(&f.path) != docs);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let _ = std::fs::remove_dir_all(&docs);

    // Nor the node's pipes from a container.
    let pipe_names: Vec<String> = std::fs::read_dir(r"\\.\pipe\")
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("nerve-node"))
        .collect();
    assert!(!pipe_names.is_empty(), "the node's pipes are not there");
    for name in &pipe_names {
        let r = run_in(
            &mut conn_a,
            &a,
            &format!(
                "try {{ $p = [IO.Pipes.NamedPipeClientStream]::new('.', '{name}', 'InOut'); $p.Connect(3000); 'opened' }} catch {{ 'refused' }}"
            ),
        )
        .await
        .expect("a's look at the pipes");
        assert!(
            out(&r).contains("refused") && !out(&r).contains("opened"),
            "{name}: {r}"
        );
    }

    // Allowlist mode runs as nerve-run too, in its own container, with its
    // home there, and reaches no other pairing's folder.
    let r = run_in(
        &mut conn_c,
        &c,
        &format!(
            "whoami; $env:USERPROFILE; Get-Content '{}'",
            b.join("secret.txt").display()
        ),
    )
    .await
    .expect("an allowlist command");
    let said = out(&r);
    assert!(said.to_lowercase().contains("nerve-run"), "{r}");
    assert!(said.contains("\\AC\\home") && !said.contains("b's"), "{r}");
    // With `--as-owner` it runs as the owner.
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.center_mut(C).expect("paired").policy.as_owner = true;
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_in(&mut conn_c, &c, "whoami")
        .await
        .expect("an allowlist command as the owner");
    assert!(
        out(&r).to_lowercase().contains(&owner.to_lowercase())
            && !out(&r).to_lowercase().contains("nerve-run"),
        "{r}"
    );

    // A folder outside the owner's profile, where what nerve-run makes is
    // nerve-run's: its flags change all the same, and the commands run.
    let r = run_in(
        &mut conn_a,
        &open,
        "New-Item -ItemType Directory made | Out-Null; Set-Content -Path made\\f.txt -Value made",
    )
    .await
    .expect("a command in the open folder");
    assert_eq!(r["exit_code"], 0, "{r}");
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        for f in &mut ea.policy.folders {
            if Path::new(&f.path) == open {
                f.access = Access::parse("r").unwrap();
            }
        }
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_in(
        &mut conn_a,
        &open,
        "Get-Content made\\f.txt; Set-Content -Path made\\g.txt -Value x; exit [int](-not $?)",
    )
    .await
    .expect("a's command after its folder became read-only");
    assert!(out(&r).contains("made"), "{r}");
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!open.join("made").join("g.txt").exists());
    // Closed by the owner, the folder nerve-run made there is closed all
    // the same, and the commands run.
    let made = open.join("made");
    nerve_node::cli::edit(&paths, |cfg| {
        let ea = cfg.center_mut(A).expect("paired");
        ea.policy.folders.push(folder(&made, ""));
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_in(
        &mut conn_a,
        &open,
        "Get-Content made\\f.txt; exit [int](-not $?)",
    )
    .await
    .expect("a's command after the owner closed what it made");
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(
        !r["stdout"].as_str().unwrap_or_default().contains("made"),
        "{r}"
    );

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

    // A pairing's home stays when its last folder goes.
    nerve_node::cli::edit(&paths, |cfg| {
        let eb = cfg.center_mut(B).expect("paired");
        eb.policy.no_network = false;
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_home(&mut conn_b, "Set-Content -Path $HOME\\keep.txt -Value kept")
        .await
        .expect("b's command in its home");
    assert_eq!(r["exit_code"], 0, "{r}");
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.center_mut(B).expect("paired").policy.folders.clear();
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let r = run_home(&mut conn_b, "Get-Content $HOME\\keep.txt")
        .await
        .expect("b's command without folders");
    assert!(out(&r).contains("kept"), "{r}");
    // Its container's profile goes with the pairing, and a's stays.
    assert!(packages.join(&container_b).is_dir());
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.centers.retain(|e| e.name != B);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    // The node's next sync removes it: one comes with a's next command.
    let _ = run_in(&mut conn_a, &a, "exit 0").await;
    wait_for("b's container profile is still there", || {
        !packages.join(&container_b).exists()
    })
    .await;
    assert!(packages.join(&container_a).is_dir());

    forget(&paths).await;
    for d in [&base, &open, &mine] {
        let _ = std::fs::remove_dir_all(d);
    }
}
