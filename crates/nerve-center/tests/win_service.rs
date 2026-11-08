//! The center as a Windows service, end to end on a Windows test machine
//! (#64): `install` registers it as its virtual account with its settings
//! and its firewall rule, `status` says it runs, its web UI logs in with the
//! owner token and opens every page in Chrome, a second center a harness
//! starts on one state folder attaches to the first, `update` takes the
//! same program, and `uninstall --purge` leaves nothing behind. It also
//! shows what only a second account can: a standard account cannot read the
//! center's state and does not take the owner's places on its ports, and an
//! administrator's other account does not attach to the owner's pipe, nor
//! does a harness trust a pipe a standard account made. It needs an
//! elevated terminal on a machine without an installed center, the program
//! to install in `NERVE_CENTER_PROGRAM`, the two accounts the job makes in
//! `NERVE_WIN_SUDO_ACCOUNT` and `NERVE_WIN_SUDO_PASSWORD` (an
//! administrator) and `NERVE_WIN_STD_ACCOUNT` and `NERVE_WIN_STD_PASSWORD`
//! (a standard one), and for the browser Node.js, Chrome and
//! `.github/scripts/web-ui-smoke.mjs` in `NERVE_UI_SMOKE_NODE`,
//! `NERVE_UI_SMOKE_CHROME` and `NERVE_UI_SMOKE_SCRIPT`, as CI's
//! `windows-installed` job runs it:
//!
//! ```text
//! cargo test -p nerve-center --test win_service -- --ignored
//! ```
#![cfg(windows)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The node port of the installed center: not the default, so the
/// firewall rule shows it is the one the settings name.
const PORT: u16 = 7943;
const UI: &str = "127.0.0.1:7480";

fn program() -> PathBuf {
    PathBuf::from(std::env::var("NERVE_CENTER_PROGRAM").expect("NERVE_CENTER_PROGRAM is not set"))
}

/// What `nerve-center <args>` said, and whether it ended well.
fn center(args: &[&str]) -> (bool, String) {
    let o = Command::new(program())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    eprintln!("nerve-center {}:\n{said}", args.join(" "));
    (o.status.success(), said)
}

/// One request to the web UI on loopback; its status and body.
fn http(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(UI).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {UI}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    s.write_all(req.as_bytes()).unwrap();
    let mut answer = String::new();
    s.read_to_string(&mut answer).unwrap();
    let status = answer
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// What the tools say of the installed folders: `icacls` and `netsh`.
fn system(program: &str, args: &[&str]) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let o = Command::new(Path::new(&root).join("System32").join(program))
        .args(args)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// A center as a harness starts it, on `state`.
fn harness(state: &Path) -> std::process::Child {
    let mut c = Command::new(program());
    c.env_clear();
    if let Some(root) = std::env::var_os("SystemRoot") {
        c.env("SystemRoot", root);
    }
    c.env("NERVE_CENTER_STATE_DIR", state)
        .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
        .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
        .env("NERVE_CENTER_UI", "off")
        .env("NERVE_CENTER_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

/// One MCP request on a harness's stdio, and its answer.
fn ask(child: &mut std::process::Child, out: &mut impl BufRead, msg: Value) -> Value {
    let stdin = child.stdin.as_mut().unwrap();
    writeln!(stdin, "{msg}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
}

/// A local account the job made: its name and password.
type Account = (String, String);

/// The job's account of `kind` (`SUDO`, an administrator, or `STD`, a
/// standard user); `None` where the variables are not set.
fn account(kind: &str) -> Option<Account> {
    let var = |k: String| std::env::var(k).ok().filter(|v| !v.is_empty());
    Some((
        var(format!("NERVE_WIN_{kind}_ACCOUNT"))?,
        var(format!("NERVE_WIN_{kind}_PASSWORD"))?,
    ))
}

/// What a program that ran as another account did.
struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

/// Opens `dir` to `who` (modify), so a program of that account can use
/// what is made in it.
fn open_to(dir: &Path, who: &Account) {
    system(
        "icacls.exe",
        &[
            &dir.display().to_string(),
            "/grant",
            &format!("{}:(OI)(CI)(M)", who.0),
        ],
    );
}

/// Runs `program` with `args` (already quoted for a command line) as the
/// local account `who`, from a folder of `work` that account may use, with
/// `input` on its stdin; waits `limit` at most (then the exit code is 124).
/// The password goes to the helper through its environment, never an
/// argument.
fn as_account(
    who: &Account,
    work: &Path,
    program: &Path,
    args: &str,
    input: &str,
    limit: Duration,
) -> Ran {
    let (stdin, stdout, stderr) = (work.join("in"), work.join("out"), work.join("err"));
    std::fs::write(&stdin, input).unwrap();
    let script = work.join("run.ps1");
    std::fs::write(
        &script,
        r#"$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $env:NERVE_T_PASSWORD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential(".\$($env:NERVE_T_USER)", $secure)
$p = Start-Process -FilePath $env:NERVE_T_PROGRAM -ArgumentList $env:NERVE_T_ARGS -Credential $cred -LoadUserProfile -WorkingDirectory $env:SystemRoot -RedirectStandardInput $env:NERVE_T_IN -RedirectStandardOutput $env:NERVE_T_OUT -RedirectStandardError $env:NERVE_T_ERR -PassThru -WindowStyle Hidden
$null = $p.Handle
if (-not $p.WaitForExit([int]$env:NERVE_T_MS)) { $p.Kill(); exit 124 }
exit $p.ExitCode
"#,
    )
    .unwrap();
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let o =
        Command::new(Path::new(&root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script)
            .env("NERVE_T_USER", &who.0)
            .env("NERVE_T_PASSWORD", &who.1)
            .env("NERVE_T_PROGRAM", program)
            .env("NERVE_T_ARGS", args)
            .env("NERVE_T_IN", &stdin)
            .env("NERVE_T_OUT", &stdout)
            .env("NERVE_T_ERR", &stderr)
            .env("NERVE_T_MS", limit.as_millis().to_string())
            .stdin(Stdio::null())
            .output()
            .unwrap();
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    let ran = Ran {
        code: o.status.code(),
        out: read(&stdout),
        err: format!(
            "{}{}{}",
            read(&stderr),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    };
    eprintln!(
        "as {}: {} {args}: {:?}\n{}{}",
        who.0,
        program.display(),
        ran.code,
        ran.out,
        ran.err
    );
    ran
}

/// A Windows program of System32.
fn system32(name: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    Path::new(&root).join("System32").join(name)
}

/// Waits until `path` exists.
fn wait_for(path: &Path, what: &str) {
    let until = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < until,
            "{what}: {} did not appear",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The process id of the running service, from `sc queryex`.
fn service_pid() -> Option<u32> {
    system("sc.exe", &["queryex", "nerve-center"])
        .lines()
        .find_map(|l| l.trim().strip_prefix("PID"))
        .and_then(|l| l.trim_start_matches([' ', ':']).trim().parse().ok())
        .filter(|p| *p != 0)
}

/// Waits until the web UI of the installed center answers.
fn wait_for_ui() {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        if std::net::TcpStream::connect(UI).is_ok() && http("GET", "/", &[], "").0 == 200 {
            return;
        }
        assert!(Instant::now() < until, "the web UI does not answer at {UI}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "win-service-test", "version": "0"}}})
}

#[test]
#[ignore = "installs the center as a Windows service: a Windows test machine only"]
fn the_center_runs_as_a_windows_service() {
    let port = format!("0.0.0.0:{PORT}");
    // The center's folder, made first by another account (an unelevated
    // program of the installing person would do the same: it shares the
    // administrator's account), is refused and named, and the install
    // makes nothing in it (round 3, security 1).
    let data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    let home = Path::new(&data).join("nerve-center");
    match account("STD") {
        Some(std_user) => {
            let early = tempfile::tempdir().unwrap();
            open_to(early.path(), &std_user);
            let made = as_account(
                &std_user,
                early.path(),
                &system32("cmd.exe"),
                &format!("/d /c mkdir \"{}\"", home.display()),
                "",
                Duration::from_secs(60),
            );
            assert_eq!(made.code, Some(0), "{}", made.err);
            let (ok, said) = center(&["install", "--name", "win-test", "--listen", &port]);
            assert!(!ok, "{said}");
            assert!(said.contains("nerve-center: another account"), "{said}");
            assert!(!home.join("state").exists());
            std::fs::remove_dir(&home).unwrap();
        }
        None => eprintln!(
            "skipped: a folder another account made first, as NERVE_WIN_STD_ACCOUNT is not set"
        ),
    }
    let (ok, said) = center(&["install", "--name", "win-test", "--listen", &port]);
    assert!(ok, "{said}");
    assert!(said.contains("runs as NT SERVICE\\nerve-center"), "{said}");
    assert!(said.contains("the service nerve-center runs"), "{said}");
    let token = said
        .lines()
        .find_map(|l| l.strip_prefix("Owner token: "))
        .and_then(|l| l.split_whitespace().next())
        .expect("an owner token")
        .to_string();

    let r = std::panic::catch_unwind(|| {
        // The service runs, and `status` says so as the administrator asks.
        let (ok, said) = center(&["status"]);
        assert!(ok, "{said}");
        assert!(said.contains("center: running"), "{said}");
        assert!(
            said.contains("service: running, starts with the machine"),
            "{said}"
        );
        assert!(
            said.contains("in an administrator's terminal shows it"),
            "{said}"
        );
        // Its folders are its account's and the administrators', its
        // settings the administrators' (the service reads them).
        let state = Path::new(&data).join("nerve-center").join("state");
        let acl = system("icacls.exe", &[&state.display().to_string()]);
        assert!(
            acl.contains("NT SERVICE\\nerve-center:(OI)(CI)(F)"),
            "{acl}"
        );
        assert!(!acl.contains("Users") && !acl.contains("(I)"), "{acl}");
        let settings = Path::new(&data).join("nerve-center").join("settings");
        let acl = system("icacls.exe", &[&settings.display().to_string()]);
        assert!(
            acl.contains("NT SERVICE\\nerve-center:(OI)(CI)(R)"),
            "{acl}"
        );
        // The administrators own all three, whoever installed (round 3,
        // security 1): the service takes no other owner's at its start.
        for dir in [&home, &state, &settings] {
            let owner = system(
                "WindowsPowerShell\\v1.0\\powershell.exe",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("(Get-Acl -LiteralPath '{}').Owner", dir.display()),
                ],
            );
            assert_eq!(owner.trim(), "BUILTIN\\Administrators", "{}", dir.display());
        }
        // What the manager does when it fails: the restarts the poisoned
        // lock and a start that failed need (round 1, correctness 1), the
        // one privilege, the service's own SID in its token.
        let failure = system("sc.exe", &["qfailure", "nerve-center"]);
        // The last action is repeated for every later failure, so the
        // service is never left down for the day (round 2, correctness 3).
        let restarts: Vec<&str> = failure
            .lines()
            .filter(|l| l.contains("RESTART -- Delay"))
            .map(str::trim)
            .collect();
        assert_eq!(
            restarts,
            [
                "RESTART -- Delay = 5000 milliseconds.",
                "RESTART -- Delay = 5000 milliseconds.",
                "RESTART -- Delay = 60000 milliseconds.",
            ],
            "{failure}"
        );
        assert!(!failure.contains("NONE"), "{failure}");
        let flag = system("sc.exe", &["qfailureflag", "nerve-center"]);
        assert!(flag.contains("TRUE"), "{flag}");
        let privs = system("sc.exe", &["qprivs", "nerve-center"]);
        assert!(privs.contains("SeChangeNotifyPrivilege"), "{privs}");
        assert!(
            !privs.contains("SeImpersonatePrivilege") && !privs.contains("SeDebugPrivilege"),
            "{privs}"
        );
        let sidtype = system("sc.exe", &["qsidtype", "nerve-center"]);
        assert!(sidtype.contains("UNRESTRICTED"), "{sidtype}");
        // A standard account reads nothing of the state, the owner token
        // least (the point of the service's own account), where an
        // administrator reads it; the files the install made before the
        // folder was closed are closed too.
        let work = tempfile::tempdir().unwrap();
        let std_user = account("STD");
        match &std_user {
            Some(std_user) => {
                open_to(work.path(), std_user);
                let token_file = state.join("owner-token");
                let args = format!("/d /c type \"{}\"", token_file.display());
                let mine = as_account(
                    std_user,
                    work.path(),
                    &system32("cmd.exe"),
                    &args,
                    "",
                    Duration::from_secs(60),
                );
                assert_ne!(mine.code, Some(0), "{}", mine.out);
                assert!(!mine.out.contains("nrv_"), "{}", mine.out);
                let listed = as_account(
                    std_user,
                    work.path(),
                    &system32("cmd.exe"),
                    &format!("/d /c dir \"{}\"", state.display()),
                    "",
                    Duration::from_secs(60),
                );
                assert_ne!(listed.code, Some(0), "{}", listed.out);
                // The same read, by an administrator, works: the path is right.
                assert!(
                    std::fs::read_to_string(&token_file)
                        .unwrap()
                        .starts_with("nrv_"),
                    "owner-token"
                );
            }
            None => eprintln!(
                "skipped: the owner token as a standard account, as NERVE_WIN_STD_ACCOUNT is not set"
            ),
        }
        // The firewall lets others reach the node port, and that alone.
        let rule = system(
            "netsh.exe",
            &[
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=Nerve center",
                "verbose",
            ],
        );
        assert!(rule.contains(&PORT.to_string()), "{rule}");
        assert!(!rule.contains("7480") && !rule.contains("7481"), "{rule}");

        // The web UI: its page, a login with the owner token, the overview.
        let until = Instant::now() + Duration::from_secs(30);
        let (status, page) = loop {
            match std::net::TcpStream::connect(UI) {
                Ok(_) => break http("GET", "/", &[], ""),
                Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(250)),
                Err(e) => panic!("the web UI does not answer at {UI}: {e}"),
            }
        };
        assert_eq!(status, 200, "{page}");
        let (status, wrong) = http(
            "POST",
            "/login",
            &[("Content-Type", "application/json")],
            &json!({"token": "nrv_not-the-token"}).to_string(),
        );
        assert_eq!(status, 401, "{wrong}");
        assert!(wrong.contains("in an administrator's terminal"), "{wrong}");
        let (status, login) = http(
            "POST",
            "/login",
            &[("Content-Type", "application/json")],
            &json!({"token": token}).to_string(),
        );
        assert_eq!(status, 200, "{login}");
        let session = serde_json::from_str::<Value>(&login).unwrap()["session"]
            .as_str()
            .unwrap()
            .to_string();
        let (status, overview) = http("GET", "/api/overview", &[("X-Nerve-Session", &session)], "");
        assert_eq!(status, 200, "{overview}");
        let o: Value = serde_json::from_str(&overview).unwrap();
        assert_eq!(o["center"]["name"], "win-test");
        assert_eq!(o["center"]["os"], "windows");
        assert_eq!(o["mcp"]["mode"], "http", "{o}");
        // Another account's connections to a port are counted apart from
        // the owner's: the service may not open that account's process, so
        // it tells it apart by its session, from the system's list of
        // processes (round 1, security 1; round 3, security 4); two
        // accounts in one session share their places. A standard account holds more connections than a
        // peer has places for, and the owner's page still opens.
        if let Some(std_user) = &std_user {
            let hold = work.path().join("hold");
            std::fs::create_dir_all(&hold).unwrap();
            open_to(&hold, std_user);
            let ready = hold.join("ready");
            let held = hold.join("held");
            let ps1 = hold.join("hold.ps1");
            std::fs::write(
                &ps1,
                format!(
                    r#"$all = 1..24 | ForEach-Object {{ $t = New-Object Net.Sockets.TcpClient; $t.Connect('127.0.0.1', 7480); $t }}
Start-Sleep -Seconds 2
$open = @($all | Where-Object {{ -not ($_.Client.Poll(0, [Net.Sockets.SelectMode]::SelectRead) -and $_.Client.Available -eq 0) }}).Count
Set-Content -Path '{held}' -Value $open
Set-Content -Path '{session}' -Value ([Diagnostics.Process]::GetCurrentProcess().SessionId)
Set-Content -Path '{ready}' -Value 'ready'
Start-Sleep -Seconds 8
"#,
                    held = held.display(),
                    session = hold.join("session").display(),
                    ready = ready.display()
                ),
            )
            .unwrap();
            let who = std_user.clone();
            let dir = hold.clone();
            let ps = system32("WindowsPowerShell\\v1.0\\powershell.exe");
            let holder = std::thread::spawn(move || {
                as_account(
                    &who,
                    &dir,
                    &ps,
                    &format!(
                        "-NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                        ps1.display()
                    ),
                    "",
                    Duration::from_secs(90),
                )
            });
            wait_for(&ready, "the standard account's connections");
            // Its places are full (16 of its 24 stay open), the owner's are not.
            let open = std::fs::read_to_string(&held).unwrap();
            assert_eq!(
                open.trim(),
                "16",
                "the connections the standard account kept"
            );
            // The service is no administrator: it tells another account's
            // process by its session, not by its account (round 2,
            // correctness 1). The owner's page opens while the places of a
            // session of another sign-in are full; two accounts in one
            // session (as the job's accounts may be) share their places,
            // and then nothing but the 16 is asserted.
            let mine =
                std::process::Command::new(system32("WindowsPowerShell\\v1.0\\powershell.exe"))
                    .args([
                        "-NoProfile",
                        "-Command",
                        "[Diagnostics.Process]::GetCurrentProcess().SessionId",
                    ])
                    .output()
                    .unwrap();
            let mine = String::from_utf8_lossy(&mine.stdout).trim().to_string();
            let theirs = std::fs::read_to_string(hold.join("session")).unwrap();
            if mine != theirs.trim() {
                let (status, _) = http("GET", "/", &[], "");
                assert_eq!(
                    status, 200,
                    "the owner's page, while another session holds its places"
                );
            } else {
                eprintln!(
                    "note: the owner and the standard account run in session {mine}, which share their places"
                );
            }
            let ran = holder.join().unwrap();
            assert_eq!(ran.code, Some(0), "{}", ran.err);
        } else {
            eprintln!(
                "skipped: the places of another account, as NERVE_WIN_STD_ACCOUNT is not set"
            );
        }
        // Every page in a real browser, signed in as a person signs in.
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        match (
            var("NERVE_UI_SMOKE_NODE"),
            var("NERVE_UI_SMOKE_CHROME"),
            var("NERVE_UI_SMOKE_SCRIPT"),
        ) {
            (Some(node), Some(chrome), Some(script)) => {
                let o = Command::new(node)
                    .args([script, chrome, format!("http://{UI}"), token.clone()])
                    .output()
                    .unwrap();
                let said = String::from_utf8_lossy(&o.stdout).to_string()
                    + &String::from_utf8_lossy(&o.stderr);
                assert!(o.status.success(), "the web UI in Chrome: {said}");
            }
            _ => eprintln!(
                "skipped: the web UI in a browser, as NERVE_UI_SMOKE_NODE, NERVE_UI_SMOKE_CHROME and NERVE_UI_SMOKE_SCRIPT are not all set"
            ),
        }

        // A second center a harness starts on one state folder attaches to
        // the first over its pipe.
        let dir = tempfile::tempdir().unwrap();
        let mut first = harness(dir.path());
        let mut first_out = BufReader::new(first.stdout.take().unwrap());
        assert!(ask(&mut first, &mut first_out, initialize())["result"].is_object());
        let mut second = harness(dir.path());
        let mut second_out = BufReader::new(second.stdout.take().unwrap());
        assert!(ask(&mut second, &mut second_out, initialize())["result"].is_object());
        let list = ask(
            &mut second,
            &mut second_out,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        );
        assert_eq!(list["result"]["tools"][0]["name"], "list", "{list}");
        // An administrator's other account may open the pipe, and still
        // does not attach: the owner answers only its own account (round
        // 1, spec 1). Its harness gets no answer to its first request.
        if let Some(admin) = account("SUDO") {
            let bat = work.path().join("harness.cmd");
            std::fs::write(
                &bat,
                format!(
                    "@echo off\r\nset \"NERVE_CENTER_STATE_DIR={}\"\r\nset \"NERVE_CENTER_LISTEN=127.0.0.1:0\"\r\nset \"NERVE_CENTER_PLAIN_LOOPBACK=true\"\r\nset \"NERVE_CENTER_UI=off\"\r\nset \"NERVE_CENTER_LOG=warn\"\r\n\"{}\"\r\n",
                    dir.path().display(),
                    program().display()
                ),
            )
            .unwrap();
            open_to(work.path(), &admin);
            let ran = as_account(
                &admin,
                work.path(),
                &system32("cmd.exe"),
                &format!("/d /c \"\"{}\"\"", bat.display()),
                &format!("{}\n", initialize()),
                Duration::from_secs(60),
            );
            assert_ne!(ran.code, Some(124), "its harness did not end: {}", ran.err);
            assert!(
                !ran.out.contains("\"result\""),
                "another account attached: {}",
                ran.out
            );
        } else {
            eprintln!(
                "skipped: an administrator's other account at the attach pipe, as NERVE_WIN_SUDO_ACCOUNT is not set"
            );
        }
        // A pipe of the expected name that a standard account made is not
        // the center's: a harness checks its owner and sends nothing to it.
        if let Some(std_user) = &std_user {
            let other = tempfile::tempdir().unwrap();
            let state = other.path().join("state");
            // A center that holds the lock and made no pipe.
            let _lock = nerve_center::attach::try_lock(&state).unwrap().unwrap();
            let pipe = work.path().join("pipe");
            std::fs::create_dir_all(&pipe).unwrap();
            open_to(&pipe, std_user);
            let (ready, got) = (pipe.join("ready"), pipe.join("got"));
            let ps1 = pipe.join("pipe.ps1");
            std::fs::write(
                &ps1,
                format!(
                    r#"$name = '{name}'.Substring(9)
$sec = New-Object System.IO.Pipes.PipeSecurity
$sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule('Everyone', 'ReadWrite', 'Allow')))
$s = New-Object System.IO.Pipes.NamedPipeServerStream($name, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 4096, 4096, $sec)
Set-Content -Path '{ready}' -Value 'ready'
$wait = $s.WaitForConnectionAsync()
if ($wait.Wait(40000)) {{
  $buf = New-Object byte[] 64
  $n = $s.Read($buf, 0, 64)
  Set-Content -Path '{got}' -Value "read $n"
}} else {{
  Set-Content -Path '{got}' -Value 'no client'
}}
"#,
                    name = nerve_center::attach::pipe_name(&state),
                    ready = ready.display(),
                    got = got.display()
                ),
            )
            .unwrap();
            let who = std_user.clone();
            let dir = pipe.clone();
            let ps = system32("WindowsPowerShell\\v1.0\\powershell.exe");
            let server = std::thread::spawn(move || {
                as_account(
                    &who,
                    &dir,
                    &ps,
                    &format!(
                        "-NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                        ps1.display()
                    ),
                    "",
                    Duration::from_secs(90),
                )
            });
            wait_for(&ready, "the standard account's pipe");
            let mut c = harness(&state);
            let mut c_out = BufReader::new(c.stdout.take().unwrap());
            let _ = writeln!(c.stdin.as_mut().unwrap(), "{}", initialize());
            let mut line = String::new();
            c_out.read_line(&mut line).unwrap();
            assert!(
                !line.contains("\"result\""),
                "a foreign pipe answered: {line}"
            );
            drop(c.stdin.take());
            let until = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(st) = c.try_wait().unwrap() {
                    break st;
                }
                assert!(Instant::now() < until, "the harness did not end");
                std::thread::sleep(Duration::from_millis(100));
            };
            assert!(!status.success(), "the harness attached to a foreign pipe");
            let ran = server.join().unwrap();
            assert_eq!(ran.code, Some(0), "{}", ran.err);
            // It connected, and was sent nothing.
            assert_eq!(
                std::fs::read_to_string(&got).unwrap().trim(),
                "read 0",
                "what the foreign pipe was sent"
            );
        } else {
            eprintln!(
                "skipped: a pipe made by a standard account, as NERVE_WIN_STD_ACCOUNT is not set"
            );
        }
        drop(second.stdin.take());
        drop(first.stdin.take());
        for c in [&mut second, &mut first] {
            let until = Instant::now() + Duration::from_secs(20);
            while c.try_wait().unwrap().is_none() {
                assert!(Instant::now() < until, "a harness's center did not end");
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        // A backup of the running center, and a restore into it: the
        // service stops, the lock is free for the restore, the service
        // starts again on what was restored. Once with the folder spelled
        // another way, which must find the same folder (round 1,
        // correctness 2): the service keeps its place in the folder's
        // access list.
        let pass = work.path().join("pass");
        std::fs::write(&pass, "correct horse battery\n").unwrap();
        let (backup, pass) = (
            work.path().join("c.bak").display().to_string(),
            pass.display().to_string(),
        );
        let (ok, said) = center(&["backup", &backup, "--passphrase-file", &pass]);
        assert!(ok, "{said}");
        for spelled in [
            None,
            Some(format!(
                "{}/",
                state.display().to_string().replace('\\', "/")
            )),
        ] {
            let mut args = vec!["restore", &backup, "--passphrase-file", &pass];
            if let Some(s) = &spelled {
                args.extend(["--state-dir", s]);
            }
            let (ok, said) = center(&args);
            assert!(ok, "{said}");
            assert!(
                said.contains("stopped the service nerve-center for the restore"),
                "{said}"
            );
            assert!(
                said.contains("started the service nerve-center again"),
                "{said}"
            );
            wait_for_ui();
            let (_, said) = center(&["status"]);
            assert!(said.contains("center: running"), "{said}");
            let acl = system("icacls.exe", &[&state.display().to_string()]);
            assert!(
                acl.contains("NT SERVICE\\nerve-center:(OI)(CI)(F)"),
                "{acl}"
            );
        }

        // A value mistyped in center.env ends the service at its start, and
        // the reason is in the log of its state folder, where the service
        // has no terminal to say it (round 2, correctness 2). The manager
        // takes a center that ends before it reaches the manager for one
        // that did not answer, and runs no restart action for it (round 3,
        // correctness 1), so the file written back, the service is started
        // again here.
        let env = settings.join("center.env");
        let good = std::fs::read_to_string(&env).unwrap();
        let log = state.join(nerve_transport::log::FILE);
        let _ = system("sc.exe", &["stop", "nerve-center"]);
        let until = Instant::now() + Duration::from_secs(60);
        while service_pid().is_some() {
            assert!(Instant::now() < until, "the service did not stop");
            std::thread::sleep(Duration::from_millis(250));
        }
        std::fs::write(&env, format!("{good}\nNERVE_CENTER_MCP=htttp\n")).unwrap();
        let _ = system("sc.exe", &["start", "nerve-center"]);
        let until = Instant::now() + Duration::from_secs(60);
        while !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("the service cannot start")
        {
            assert!(Instant::now() < until, "the log names no reason");
            std::thread::sleep(Duration::from_millis(250));
        }
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("htttp"), "{text}");
        std::fs::write(&env, &good).unwrap();
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            let _ = system("sc.exe", &["start", "nerve-center"]);
            if std::net::TcpStream::connect(UI).is_ok() && http("GET", "/", &[], "").0 == 200 {
                break;
            }
            assert!(Instant::now() < until, "the service did not start again");
            std::thread::sleep(Duration::from_secs(2));
        }

        // A settings folder whose owner is none of SYSTEM and the
        // administrators is not read: the service ends at its start and the
        // log names the folder (round 4, correctness 1).
        let _ = system("sc.exe", &["stop", "nerve-center"]);
        let until = Instant::now() + Duration::from_secs(60);
        while service_pid().is_some() {
            assert!(Instant::now() < until, "the service did not stop");
            std::thread::sleep(Duration::from_millis(250));
        }
        let folder = settings.display().to_string();
        let _ = system("icacls.exe", &[&folder, "/setowner", "*S-1-5-32-545"]);
        let _ = system("sc.exe", &["start", "nerve-center"]);
        let until = Instant::now() + Duration::from_secs(60);
        while !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("another account")
        {
            assert!(Instant::now() < until, "the log names no foreign owner");
            std::thread::sleep(Duration::from_millis(250));
        }
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains(&folder), "{text}");
        let _ = system("icacls.exe", &[&folder, "/setowner", "*S-1-5-32-544"]);
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            let _ = system("sc.exe", &["start", "nerve-center"]);
            if std::net::TcpStream::connect(UI).is_ok() && http("GET", "/", &[], "").0 == 200 {
                break;
            }
            assert!(Instant::now() < until, "the service did not start again");
            std::thread::sleep(Duration::from_secs(2));
        }

        // The same program again: nothing to update.
        let (ok, said) = center(&["update", "--from", &program().display().to_string()]);
        assert!(ok, "{said}");
        assert!(said.contains("is that one already"), "{said}");
        // A program that is not the center is refused, by the check the
        // restricted token runs (round 1, spec 2), and the installed one
        // stays.
        let installed = Path::new(
            &std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()),
        )
        .join("Nerve")
        .join("nerve-center.exe");
        let kept = std::fs::read(&installed).unwrap();
        let (ok, said) = center(&[
            "update",
            "--from",
            &system32("whoami.exe").display().to_string(),
        ]);
        assert!(!ok, "{said}");
        assert!(said.contains("whoami.exe --version"), "{said}");
        assert_eq!(std::fs::read(&installed).unwrap(), kept);
        // Another build of the center replaces it, and the service runs
        // the new file: a copy with bytes after its end, which Windows
        // runs as it ran before.
        let next = work.path().join("nerve-center-next.exe");
        std::fs::copy(program(), &next).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&next)
            .unwrap();
        f.write_all(b"\0an update of the installed job's test")
            .unwrap();
        drop(f);
        let before = service_pid();
        let (ok, said) = center(&["update", "--from", &next.display().to_string()]);
        assert!(ok, "{said}");
        assert!(said.contains("replaced nerve-center"), "{said}");
        assert!(
            said.contains("restarted the service nerve-center"),
            "{said}"
        );
        wait_for_ui();
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            std::fs::read(&next).unwrap()
        );
        assert_ne!(service_pid(), before, "the service did not start again");

        // A process that dies is started again after the 5 seconds the
        // service asks for (a poisoned lock ends the process so).
        let pid = service_pid().expect("the service runs");
        system("taskkill.exe", &["/F", "/PID", &pid.to_string()]);
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if service_pid().is_some_and(|p| p != pid) {
                break;
            }
            assert!(
                Instant::now() < until,
                "the service was not started again after its process was killed"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        wait_for_ui();
    });

    let (ok, said) = center(&["uninstall", "--purge"]);
    if let Err(e) = r {
        std::panic::resume_unwind(e);
    }
    assert!(ok, "{said}");
    assert!(
        said.contains("stopped and removed the service nerve-center"),
        "{said}"
    );
    assert!(said.contains("removed the Windows Firewall rule"), "{said}");
    let (_, said) = center(&["status"]);
    assert!(said.contains("service: not installed"), "{said}");
    let rule = system(
        "netsh.exe",
        &[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=Nerve center",
        ],
    );
    assert!(!rule.contains(&PORT.to_string()), "{rule}");
}
