//! The installed node on a real machine: `install` makes `nerve-run` and
//! names the owner, a folder-mode command of a center runs as `nerve-run`
//! with the folder the owner gives it (a POSIX ACL), `/tmp` and its own home,
//! and nothing else of the owner's; the owner socket refuses it; `folder rm`
//! takes the ACL off; `uninstall` removes the account, its home and every
//! entry, also on what nerve-run made, which becomes the owner's (issue
//! #142). A file call reads, as nerve-run, beyond the folders what every
//! account may read, but not the owner's files that only the node's
//! pass-through entry lets nerve-run reach, nor the node's own files, and
//! writes only in the folders (issue #152). Where the kernel has no Landlock, folder mode runs as nerve-run all
//! the same, and the node says what that leaves of the owner's home open.
//! The owner runs `setup` without sudo, its answers passed on. An allowed sudo
//! command of nerve-run runs as root without the owner's password, in its
//! folder even where only the owner may enter it. For a
//! test machine only, as root: it installs the node as a service and removes
//! it again, and gives the owner a password and sudo.
//!
//! `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
//! with a home, the owner> cargo test -p nerve-node --test real_account --
//! --ignored --nocapture`
//!
//! The second test is the other half of issue #135, on a kernel of any age
//! (CI runs it on the 6.8 and 7.0 kernels of its Ubuntu 22.04 and 24.04
//! runners; the case without Landlock only on a test VM):
//! the installed node with its keys in the system keyring pairs a center,
//! starts again with the key it keeps there, and still runs a folder mode
//! command as `nerve-run`, which reaches neither the node's session bus nor
//! its keyring folder. It expects the node installed and `setup` done with the
//! keyring (`.github/scripts/keyring-end-to-end.sh` does both): `NERVE_REAL_KEYRING=1 NERVE_REAL_OWNER=<the owner>
//! ... --ignored --exact the_installed_node_with_its_keys_in_the_keyring_runs_folder_commands_as_nerve_run`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(20);
const BIN: &str = "/usr/local/bin/nerve-node";

fn sh(cmd: &mut Command) -> (bool, String) {
    let o = cmd.output().expect("starts");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.success(), text)
}

/// The installed program, run as `owner` (through the owner socket).
fn as_owner(owner: &str, args: &[&str]) -> (bool, String) {
    sh(Command::new("runuser")
        .args(["-u", owner, "--", BIN])
        .args(args)
        .current_dir("/"))
}

/// [`as_owner`] with `input` on stdin.
fn as_owner_typing(owner: &str, args: &[&str], input: &str) -> (bool, String) {
    typing(
        Command::new("runuser")
            .args(["-u", owner, "--", BIN])
            .args(args),
        input,
    )
}

/// `cmd` with `input` on stdin.
fn typing(cmd: &mut Command, input: &str) -> (bool, String) {
    use std::io::Write;
    let mut child = cmd
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.success(), text)
}

fn getfacl(p: &Path) -> String {
    sh(Command::new("getfacl").args(["-p", "-n"]).arg(p)).1
}

/// The `exec.run` of `command` in `cwd`, as a center sends it: its result,
/// or the refusal.
async fn run(conn: &mut Conn<TcpStream>, cwd: &Path, command: &str) -> Result<Value, String> {
    conn.call(
        "invoke",
        json!({"cap": "exec", "action": "run", "args": {
            "command": command, "cwd": cwd.display().to_string()}}),
        WAIT,
    )
    .await
    .expect("an answer")
    .map_err(|e| e.message)
}

/// The `fs` call `action` with `args`, as a center sends it: its result, or
/// the refusal.
async fn fs_call(conn: &mut Conn<TcpStream>, action: &str, args: Value) -> Result<Value, String> {
    conn.call(
        "invoke",
        json!({"cap": "fs", "action": action, "args": args}),
        WAIT,
    )
    .await
    .expect("an answer")
    .map_err(|e| e.message)
}

fn out(v: &Value) -> String {
    format!(
        "{}{}",
        v["stdout"].as_str().unwrap_or_default(),
        v["stderr"].as_str().unwrap_or_default()
    )
}

/// Waits until `f` holds, for up to 15 s.
fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..150 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what} did not happen");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL and NERVE_REAL_OWNER name it"]
async fn folder_mode_runs_as_nerve_run_on_this_machine() {
    let (Some(exe), Some(owner)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
    ) else {
        eprintln!("NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let home =
        sh(Command::new("sh").args(["-c", &format!("getent passwd {owner} | cut -d: -f6")])).1;
    let home = PathBuf::from(home.trim());
    assert!(home.is_dir(), "{home:?}");
    let chmod = |p: &Path, m: &str| assert!(sh(Command::new("chmod").arg(m).arg(p)).0);
    let landlock = nerve_sandbox::Confinement::detect().landlock_abi.is_some();
    // The owner has a password and sudo from the start, as a real owner
    // does: the node keeps the accounts it looked up for a few seconds.
    let pw = |p: &str| {
        let mut c = Command::new("chpasswd");
        c.stdin(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{owner}:{p}\n").as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    };
    pw("first-pass-142");
    assert!(sh(Command::new("usermod").args(["-aG", "sudo", &owner])).0);

    // Install, as the owner's sudo would: the owner is named, nerve-run is
    // made with its home. Without Landlock a home open to other accounts is
    // told; with Landlock nothing of it.
    chmod(&home, "755");
    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    assert!(
        said.contains(&format!("{owner} is the owner of the node")),
        "{said}"
    );
    let told = "Without Landlock, nerve-run can read every file in your home";
    assert_eq!(
        said.contains(told) && said.contains("mode 755"),
        !landlock,
        "{said}"
    );
    assert_eq!(
        said.contains("this kernel has no Landlock"),
        !landlock,
        "{said}"
    );
    let (_, st) = as_owner(&owner, &["status"]);
    assert_eq!(st.contains(&format!("warning: {told}")), !landlock, "{st}");
    chmod(&home, "750");
    let (_, st) = as_owner(&owner, &["status"]);
    assert!(!st.contains(told), "{st}");
    // The owner's setup, without sudo, gets the answers typed into it.
    let (ok, said) = as_owner_typing(&owner, &["setup"], "real-142\n\n\n");
    assert!(ok, "{said}");
    assert!(said.contains("No center is paired"), "{said}");
    let (_, name) = as_owner(&owner, &["config", "get", "node.name"]);
    assert!(name.contains("real-142"), "{name}");
    let (ok, id) = sh(Command::new("id").arg("nerve-run"));
    assert!(ok, "{id}");
    assert!(!id.contains("sudo") && !id.contains("docker"), "{id}");
    let unit = std::fs::read_to_string("/etc/systemd/system/nerve-node.service").unwrap();
    assert!(
        unit.contains(&format!("Environment=NERVE_NODE_OWNER={owner}")),
        "{unit}"
    );
    let run_home = Path::new("/var/lib/nerve-run");
    let (_, st) = sh(Command::new("stat").args(["-c", "%U %a"]).arg(run_home));
    assert_eq!(st.trim(), "nerve-run 700");
    // An update keeps the account.
    let (_, said) = sh(Command::new(BIN).args(["update", "--from"]).arg(&exe));
    assert!(
        said.contains("nothing to update") || said.contains("replaced"),
        "{said}"
    );
    assert!(sh(Command::new("id").arg("nerve-run")).0);

    // The owner's files: a folder to give, a file of each kind it does not
    // give, and a socket in a folder of its own.
    let base = home.join("nerve-real");
    let _ = std::fs::remove_dir_all(&base);
    let proj = base.join("proj");
    let private = base.join("private");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&private).unwrap();
    std::fs::write(proj.join("given.txt"), "given\n").unwrap();
    std::fs::write(base.join("open.txt"), "open-secret\n").unwrap();
    std::fs::write(base.join("closed.txt"), "closed-secret\n").unwrap();
    let sock = private.join("session.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let chown = |p: &Path| {
        assert!(
            sh(Command::new("chown")
                .args(["-R", &format!("{owner}:{owner}")])
                .arg(p))
            .0
        );
    };
    chown(&base);
    chmod(&home, "750");
    chmod(&base, "755");
    chmod(&base.join("open.txt"), "644");
    chmod(&base.join("closed.txt"), "600");
    chmod(&private, "700");
    // What a command reaches the owner socket with, by a path the guard
    // does not see.
    std::fs::write(
        proj.join("ask.py"),
        r#"import json, socket
s = socket.socket(socket.AF_UNIX)
s.connect("/run/" + "nerve-node/owner.sock")
s.sendall((json.dumps({"method": "cli", "params": {"args": ["mode", "set", "user"], "cwd": "/"}}) + "\n").encode())
print(s.makefile().readline())
"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("dial.py"),
        format!(
            r#"import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("{}")
    print("connected")
except OSError as e:
    print("refused:", e.strerror)
"#,
            sock.display()
        ),
    )
    .unwrap();
    // One program per call: allowlist mode, where Landlock is missing,
    // runs no chained command line.
    std::fs::write(proj.join("who.sh"), "#!/bin/sh\nid -un\necho \"$HOME\"\n").unwrap();
    std::fs::write(
        proj.join("rw.sh"),
        "#!/bin/sh\nset -e\ncat given.txt\necho made > made.txt\ncat made.txt\nmkdir made-dir\necho in > made-dir/in.txt\necho t > /tmp/nerve-real-t\ncat /tmp/nerve-real-t\nrm /tmp/nerve-real-t\necho h > \"$HOME/h\"\ncat \"$HOME/h\"\n",
    )
    .unwrap();
    // A folder below the grant closed to the owner: its grant fails.
    let shut = proj.join("shut");
    std::fs::create_dir_all(shut.join("inner")).unwrap();
    chown(&proj);
    for script in ["who.sh", "rw.sh"] {
        chmod(&proj.join(script), "755");
    }
    chmod(&shut, "000");

    // The owner pairs and gives the folder, without sudo: the closed folder
    // in it is told at once, and in `status`.
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "+rwx"]);
    assert!(ok, "{said}");
    assert!(
        said.contains("warning: nerve-run did not get every folder"),
        "{said}"
    );
    assert!(said.contains("shut"), "{said}");
    let (_, st) = as_owner(&owner, &["status"]);
    assert!(
        st.contains("warning: nerve-run did not get every folder") && st.contains("shut"),
        "{st}"
    );
    // Without Landlock, the folder in the home is told: nerve-run passes
    // through the home to it.
    assert_eq!(
        st.contains("as it passes through your home to"),
        !landlock,
        "{st}"
    );
    // Opened, the grant is tried again with the next change.
    chmod(&shut, "755");
    let p = proj.to_str().unwrap();
    assert!(as_owner(&owner, &["folder", "set", p, "-x"]).0);
    let (ok, said) = as_owner(&owner, &["folder", "set", p, "+x"]);
    assert!(ok && !said.contains("warning"), "{said}");
    let (_, st) = as_owner(&owner, &["status"]);
    assert!(!st.contains("did not get every folder"), "{st}");
    let (_, ls) = as_owner(&owner, &["--json", "center", "ls"]);
    let ls: Value = serde_json::from_str(ls.trim()).unwrap();
    assert_eq!(ls["centers"][0]["mode"], "folder", "{ls}");
    // Without Landlock folder mode runs as nerve-run all the same, and
    // `status` says so.
    let (_, st) = as_owner(&owner, &["status"]);
    let line = if landlock {
        "mode folder, as nerve-run\n"
    } else {
        "mode folder, as nerve-run, without Landlock"
    };
    assert!(st.contains(line), "{st}");
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    let mut conn = inc.conn;

    // As nerve-run, with its own home.
    let r = run(&mut conn, &proj, "./who.sh").await.unwrap();
    assert_eq!(out(&r), "nerve-run\n/var/lib/nerve-run\n", "{r}");
    // Its folder, /tmp and its home: read and write.
    let r = run(&mut conn, &proj, "./rw.sh").await.unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(out(&r), "given\nmade\nt\nh\n", "{r}");
    // What it made is the owner's to use: the default entry.
    assert_eq!(
        std::fs::read_to_string(proj.join("made.txt")).unwrap(),
        "made\n"
    );
    let acl = getfacl(&proj.join("made.txt"));
    assert!(acl.contains("user::rw-"), "{acl}");
    let (ok, said) = sh(Command::new("runuser")
        .args(["-u", &owner, "--", "sh", "-c"])
        .arg(format!("echo more >> {}", proj.join("made.txt").display())));
    assert!(ok, "the owner writes what nerve-run made: {said}");
    let run_id = sh(Command::new("id").args(["-u", "nerve-run"])).1;
    let acl = getfacl(&shut.join("inner"));
    assert!(
        acl.contains(&format!("\nuser:{}:rwx", run_id.trim())),
        "the grant reached the folder once open: {acl}"
    );
    // No other file of the owner's: one closed to others by its mode, and
    // with Landlock one open to them as well.
    let others: &[&str] = if landlock {
        &["open.txt", "closed.txt"]
    } else {
        &["closed.txt"]
    };
    for f in others {
        let r = run(&mut conn, &proj, &format!("cat ../{f}")).await;
        let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
        assert!(!shown.contains("secret"), "{f}: {shown}");
    }
    // Folder mode reads, as nerve-run, beyond the folders what is open to
    // every account: a file of the system, and one of the owner's in a
    // folder everyone may enter, but not one closed to others, nor one
    // open to them in the owner's home that only the node's pass-through
    // entry lets nerve-run into, nor the node's own. It writes only in its
    // folders. The descriptor says so, and the audit names each path.
    let public = PathBuf::from("/srv/nerve-real-public");
    let _ = std::fs::remove_dir_all(&public);
    std::fs::create_dir_all(&public).unwrap();
    std::fs::write(public.join("open.txt"), "public-secret\n").unwrap();
    std::fs::write(public.join("closed.txt"), "closed-secret\n").unwrap();
    chown(&public);
    chmod(&public, "755");
    chmod(&public.join("open.txt"), "644");
    chmod(&public.join("closed.txt"), "600");
    let d = conn
        .call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d["access"]["reads_by_account"], true, "{d}");
    let at = |p: &Path| json!({"path": p.display().to_string()});
    let r = fs_call(&mut conn, "read", at(&public.join("open.txt")))
        .await
        .unwrap();
    assert_eq!(r["content"], "public-secret\n", "{r}");
    assert!(
        fs_call(&mut conn, "read", at(Path::new("/etc/hostname")))
            .await
            .is_ok()
    );
    for closed in [
        public.join("closed.txt"),
        base.join("open.txt"),
        base.join("closed.txt"),
    ] {
        let r = fs_call(&mut conn, "read", at(&closed)).await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("not open to every account")),
            "{closed:?}: {r:?}"
        );
    }
    // The node's own folder is closed to nerve-run: the path does not even
    // resolve as that account, and the policy would refuse it anyway.
    let own = fs_call(&mut conn, "read", at(Path::new("/etc/nerve/node.toml"))).await;
    assert!(
        own.as_ref()
            .is_err_and(|e| e.contains("belongs to the node") || e.contains("Permission denied")),
        "{own:?}"
    );
    // The node's own process is not nerve-run's, though its files under
    // `/proc` are open to all by their mode: the kernel would let the node's
    // thread read them whatever account it acts as.
    for own in ["/proc/self/maps", "/proc/thread-self/stat"] {
        let r = fs_call(&mut conn, "read", at(Path::new(own))).await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("the node's own process")),
            "{own}: {r:?}"
        );
    }
    let r = fs_call(
        &mut conn,
        "grep",
        json!({"path": "/proc/self", "pattern": "x"}),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    let write = fs_call(
        &mut conn,
        "write",
        json!({"path": base.join("new.txt").display().to_string(), "content": "x"}),
    )
    .await;
    assert!(
        write
            .as_ref()
            .is_err_and(|e| e.contains("outside the folders that allow writing")),
        "{write:?}"
    );
    assert!(!base.join("new.txt").exists());
    // A walk finds what is open to every account, and passes over the
    // rest; the owner's home is not walked at all.
    let grep = |at: &Path| json!({"path": at.display().to_string(), "pattern": "secret"});
    let r = fs_call(&mut conn, "grep", grep(&public)).await.unwrap();
    let found: Vec<&str> = r["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["path"].as_str())
        .collect();
    assert_eq!(
        found,
        [public.join("open.txt").display().to_string()],
        "{r}"
    );
    let r = fs_call(&mut conn, "grep", grep(&base)).await;
    assert!(
        r.as_ref()
            .is_err_and(|e| e.contains("not open to every account")),
        "{r:?}"
    );
    let audit = std::fs::read_to_string(
        nerve_node::NodePaths::new("/etc/nerve", "/var/lib/nerve/state").audit_log(),
    )
    .unwrap();
    let decided = |target: &Path, decision: &str| {
        audit.lines().any(|l| {
            serde_json::from_str::<Value>(l).is_ok_and(|e| {
                e["cap"] == "fs"
                    && e["target"] == target.display().to_string()
                    && e["decision"] == decision
            })
        })
    };
    assert!(decided(&public.join("open.txt"), "allowed"), "{audit}");
    // Also a path that does not resolve as nerve-run: the node writes the
    // entry as itself, not as the account, which may not write its log.
    assert!(
        decided(Path::new("/etc/nerve/node.toml"), "forbidden"),
        "{audit}"
    );
    assert!(decided(&base.join("open.txt"), "forbidden"), "{audit}");
    assert!(decided(&base.join("closed.txt"), "forbidden"), "{audit}");
    let _ = std::fs::remove_dir_all(&public);
    assert!(decided(&base.join("new.txt"), "forbidden"), "{audit}");
    // No socket in a folder of the owner's own.
    let r = run(&mut conn, &proj, "python3 dial.py").await.unwrap();
    assert!(out(&r).contains("refused"), "{r}");
    // The owner socket refuses it: it is not the owner.
    let r = run(&mut conn, &proj, "python3 ask.py").await.unwrap();
    assert!(out(&r).contains("not the owner"), "{r}");
    let (_, ls) = as_owner(&owner, &["--json", "center", "ls"]);
    let ls: Value = serde_json::from_str(ls.trim()).unwrap();
    assert_eq!(ls["centers"][0]["mode"], "folder", "{ls}");

    // sudo: on with the owner's password (root's to switch on); an allowed
    // sudo command of nerve-run runs as root, started by the node, not
    // through the owner's sudo: it still works after the owner's password
    // changed. One the sudo
    // list does not name is refused.
    let (ok, said) = typing(Command::new(BIN).args(["sudo", "on"]), "first-pass-142\n");
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["rule", "add", "sudo", "id -un"]);
    assert!(ok, "{said}");
    pw("second-pass-142");
    let r = run(&mut conn, &proj, "sudo id -un").await.unwrap();
    assert_eq!(out(&r), "root\n", "{r}");
    // A leading `-n` goes; another option of sudo is refused with the
    // reason, also where the sudo list names the line.
    for line in ["-n id -un", "-E id -un"] {
        let (ok, said) = as_owner(&owner, &["rule", "add", "sudo", "--", line]);
        assert!(ok, "{said}");
    }
    let r = run(&mut conn, &proj, "sudo -n id -un").await.unwrap();
    assert_eq!(out(&r), "root\n", "{r}");
    let r = run(&mut conn, &proj, "sudo -E id -un").await;
    assert!(
        r.as_ref()
            .is_err_and(|e| e.contains("no sudo option but -n and --")),
        "{r:?}"
    );
    // It starts in its folder, here one closed to all but the owner, whose
    // odd name stays a name.
    let odd = proj.join("od d;$(touch ran)\n-x");
    std::fs::create_dir(&odd).unwrap();
    chown(&odd);
    chmod(&odd, "700");
    let (ok, said) = as_owner(&owner, &["rule", "add", "sudo", "pwd -P"]);
    assert!(ok, "{said}");
    let r = run(&mut conn, &odd, "sudo pwd -P").await.unwrap();
    assert_eq!(out(&r), format!("{}\n", odd.display()), "{r}");
    assert!(!proj.join("ran").exists() && !odd.join("ran").exists());
    let r = run(&mut conn, &proj, "sudo whoami").await;
    assert!(r.is_err(), "{r:?}");
    assert!(as_owner(&owner, &["sudo", "off"]).0);

    // The ACLs: on the folder and below, default ones for nerve-run and the
    // owner, a pass-through one on the closed home above it.
    let run_uid = sh(Command::new("id").args(["-u", "nerve-run"]))
        .1
        .trim()
        .to_string();
    let owner_uid = sh(Command::new("id").args(["-u", &owner]))
        .1
        .trim()
        .to_string();
    let acl = getfacl(&proj);
    assert!(acl.contains(&format!("\nuser:{run_uid}:rwx")), "{acl}");
    assert!(
        acl.contains(&format!("default:user:{run_uid}:rwx")),
        "{acl}"
    );
    assert!(
        acl.contains(&format!("default:user:{owner_uid}:rwx")),
        "{acl}"
    );
    let acl = getfacl(&home);
    assert!(acl.contains(&format!("\nuser:{run_uid}:--x")), "{acl}");
    // Revoked: the entries come off.
    let (ok, said) = as_owner(&owner, &["folder", "rm", proj.to_str().unwrap()]);
    assert!(ok, "{said}");
    until("the ACL comes off", || {
        !getfacl(&proj.join("given.txt")).contains(&format!("user:{run_uid}:"))
    });
    assert!(!getfacl(&proj).contains(&format!("user:{run_uid}:")));
    assert!(!getfacl(&home).contains(&format!("user:{run_uid}:")));
    let r = run(&mut conn, &proj, "cat given.txt").await;
    let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
    assert!(
        !shown.contains("given\n") || shown.contains("No such"),
        "{shown}"
    );
    // Given again, for uninstall to take off; `x` to run a command there.
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "+rx"]);
    assert!(ok, "{said}");
    let r = run(&mut conn, &proj, "cat given.txt").await.unwrap();
    assert_eq!(out(&r), "given\n", "{r}");
    // Allowlist mode as nerve-run: its folders count, and say nothing; as
    // the owner they do not, and nerve-run loses their entries.
    let other = base.join("other");
    std::fs::create_dir_all(&other).unwrap();
    chown(&other);
    assert!(as_owner(&owner, &["mode", "set", "allowlist"]).0);
    let (ok, said) = as_owner(&owner, &["folder", "add", other.to_str().unwrap(), "+r"]);
    assert!(ok && !said.contains("do not count"), "{said}");
    assert!(
        getfacl(&other).contains(&format!("\nuser:{run_uid}:r-x")),
        "{}",
        getfacl(&other)
    );
    assert!(as_owner(&owner, &["mode", "set", "allowlist", "--as-owner"]).0);
    let (ok, said) = as_owner(&owner, &["folder", "set", other.to_str().unwrap(), "+x"]);
    assert!(ok, "{said}");
    for p in [&proj, &other] {
        assert!(
            !getfacl(p).contains(&format!("user:{run_uid}:")),
            "{p:?}: {}",
            getfacl(p)
        );
    }
    let third = base.join("third");
    std::fs::create_dir_all(&third).unwrap();
    chown(&third);
    let (ok, said) = as_owner(&owner, &["folder", "add", third.to_str().unwrap(), "+r"]);
    assert!(ok && said.contains("do not count"), "{said}");
    assert!(as_owner(&owner, &["mode", "set", "folder"]).0);
    let r = run(&mut conn, &proj, "cat given.txt").await.unwrap();
    assert_eq!(out(&r), "given\n", "{r}");
    drop(conn);

    // What nerve-run made is its own until it goes.
    let user_of = |p: &Path| {
        sh(Command::new("stat").args(["-c", "%U"]).arg(p))
            .1
            .trim()
            .to_string()
    };
    assert_eq!(user_of(&proj.join("made-dir/in.txt")), "nerve-run");
    // A file of nerve-run's with a second name outside the folders is left
    // as it is: ownership goes with the file, not the name.
    let twin = proj.join("twin.txt");
    std::fs::write(&twin, "t").unwrap();
    std::fs::hard_link(&twin, base.join("twin-outside")).unwrap();
    assert!(sh(Command::new("chown").arg("nerve-run:nerve-run").arg(&twin)).0);

    // Uninstall: the account, its home and every entry go.
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    assert!(said.contains("removed the account nerve-run"), "{said}");
    assert!(
        said.contains("but not 1 file with more than one name"),
        "{said}"
    );
    assert!(!sh(Command::new("id").arg("nerve-run")).0);
    assert!(!run_home.exists());
    // Also on what nerve-run made, which was its own.
    for p in [
        &proj,
        &proj.join("given.txt"),
        &home,
        &proj.join("made.txt"),
        &proj.join("made-dir"),
        &proj.join("made-dir/in.txt"),
    ] {
        let acl = getfacl(p);
        assert!(!acl.contains(&format!("user:{run_uid}:")), "{p:?}: {acl}");
    }
    // What it made is the owner's now: no later account with its uid gets
    // it.
    for p in [
        proj.join("made.txt"),
        proj.join("made-dir"),
        proj.join("made-dir/in.txt"),
    ] {
        assert_eq!(user_of(&p), owner, "{p:?}");
    }
    let uid_of = |p: &Path| {
        sh(Command::new("stat").args(["-c", "%u"]).arg(p))
            .1
            .trim()
            .to_string()
    };
    assert_eq!(uid_of(&base.join("twin-outside")), run_uid);
    std::fs::remove_dir_all(&base).unwrap();
}

/// The program a confined command runs to reach the node's bus and keyring
/// folder: it says `refused` only for "Permission denied", and `failed` for
/// a path that is not there, so that a moved keyring cannot pass as isolated.
fn reach_py(bus: &str, keyring: &str) -> String {
    format!(
        r#"import errno, socket
for what, f in [
    ("bus", lambda: socket.socket(socket.AF_UNIX).connect("{bus}")),
    ("keyrings", lambda: open("{keyring}").read()),
]:
    try:
        f()
        print(what, "reached")
    except OSError as e:
        if e.errno in (errno.EACCES, errno.EPERM):
            print(what, "refused:", e.strerror)
        else:
            print(what, "failed:", e.strerror)
"#
    )
}

/// `reach_py` tells a path it may not enter from one that is not there.
#[test]
fn the_reach_program_requires_permission_denied() {
    use std::os::unix::fs::PermissionsExt;
    if nerve_transport::net::euid() == 0 {
        // Root reaches everything; the test is for the person who runs it.
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let closed = d.path().join("closed");
    std::fs::create_dir(&closed).unwrap();
    std::fs::write(closed.join("login.keyring"), "x").unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let open = d.path().join("open.keyring");
    std::fs::write(&open, "x").unwrap();
    let run = |bus: &Path, keyring: &Path| {
        let py = d.path().join("reach.py");
        std::fs::write(
            &py,
            reach_py(bus.to_str().unwrap(), keyring.to_str().unwrap()),
        )
        .unwrap();
        sh(Command::new("python3").arg(&py)).1
    };
    let gone = d.path().join("no-bus");
    let said = run(&gone, &closed.join("login.keyring"));
    assert!(said.contains("bus failed: No such file"), "{said}");
    assert!(
        said.contains("keyrings refused: Permission denied"),
        "{said}"
    );
    let said = run(&gone, &d.path().join("moved.keyring"));
    assert!(said.contains("keyrings failed: No such file"), "{said}");
    assert!(run(&gone, &open).contains("keyrings reached"));
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// The keys of an installed node whose `setup` moved them into the system
/// keyring (issue #135): no file holds one, the node starts again with the
/// key it keeps there, and a folder mode command runs as `nerve-run`, which
/// is not the node's account and so reaches neither its session bus nor its
/// keyring folder, on any kernel.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the node installed with its keys in the keyring; NERVE_REAL_KEYRING=1 and NERVE_REAL_OWNER"]
async fn the_installed_node_with_its_keys_in_the_keyring_runs_folder_commands_as_nerve_run() {
    let (Some(owner), Some(_)) = (
        std::env::var("NERVE_REAL_OWNER").ok(),
        std::env::var_os("NERVE_REAL_KEYRING"),
    ) else {
        eprintln!("NERVE_REAL_KEYRING or NERVE_REAL_OWNER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let home =
        sh(Command::new("sh").args(["-c", &format!("getent passwd {owner} | cut -d: -f6")])).1;
    let home = PathBuf::from(home.trim());
    assert!(home.is_dir(), "{home:?}");
    let (_, storage) = as_owner(&owner, &["config", "get", "machine.secret_storage"]);
    assert!(storage.contains("keyring"), "{storage}");
    let no_key_files = |when: &str| {
        let keys: Vec<PathBuf> = std::fs::read_dir("/etc/nerve/keys")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .chain(["/var/lib/nerve/state/config.key".into()])
            .filter(|p| p.is_file())
            .collect();
        assert!(keys.is_empty(), "{when}, key files are left: {keys:?}");
    };
    no_key_files("after setup");

    let base = home.join("nerve-real-keyring");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let nerve_uid = sh(Command::new("id").args(["-u", "nerve"])).1;
    let nerve_uid = nerve_uid.trim();
    std::fs::write(base.join("who.sh"), "#!/bin/sh\nid -un\n").unwrap();
    // What a command that wants the keys would try: the node's session bus,
    // and the folder GNOME Keyring keeps them in. Both must be there, or a
    // refusal would prove nothing.
    let bus = format!("/run/user/{nerve_uid}/bus");
    let keyring = "/var/lib/nerve/.local/share/keyrings/login.keyring";
    assert!(
        Path::new(&bus).exists() && Path::new(keyring).exists(),
        "nothing to reach: {bus} and {keyring} must exist"
    );
    std::fs::write(base.join("reach.py"), reach_py(&bus, keyring)).unwrap();
    let chmod = |p: &Path, m: &str| assert!(sh(Command::new("chmod").arg(m).arg(p)).0);
    assert!(
        sh(Command::new("chown")
            .args(["-R", &format!("{owner}:{owner}")])
            .arg(&base))
        .0
    );
    chmod(&base.join("who.sh"), "755");

    // The owner pairs: the node key of the center is made in the keyring.
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", base.to_str().unwrap(), "+rwx"]);
    assert!(ok, "{said}");
    no_key_files("after pairing");
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    drop(inc);

    // The node starts again with the keys it keeps in the keyring: it
    // dials the center again, and the center knows it by that key.
    let (ok, said) = sh(Command::new("systemctl").args(["restart", "nerve-node"]));
    assert!(ok, "{said}");
    let mut inc = center.next_link(WAIT).await.expect("the node dials again");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake with the key from the keyring");
    let mut conn = inc.conn;
    no_key_files("after the restart");

    let r = run(&mut conn, &base, "./who.sh").await.unwrap();
    assert_eq!(out(&r), "nerve-run\n", "{r}");
    let r = run(&mut conn, &base, "python3 reach.py").await.unwrap();
    let said = out(&r);
    assert!(
        said.contains("bus refused: Permission denied")
            && said.contains("keyrings refused: Permission denied"),
        "{r}"
    );
    drop(conn);
    std::fs::remove_dir_all(&base).unwrap();
}

/// A provider program: it attaches as `pathprov` on the socket its first
/// argument names (`-`: the installed node's, by a path the guard of a
/// command line does not see), prints the node's answer, and then serves `files.open`
/// (read; a file's first line, or a folder's names) and `files.save`
/// (write), each naming its path, logging every call it gets to the file
/// its second argument names. Each answer says the account it ran as.
const PROVIDER_PY: &str = r#"import json, os, socket, sys
at, log = sys.argv[1], sys.argv[2]
if at == "-":
    at = "/run/" + "nerve-node/provider.sock"
s = socket.socket(socket.AF_UNIX)
s.connect(at)
def path(mark):
    return {"type": "object", "required": ["path"],
            "properties": {"path": {"type": "string", "x-nerve-path": mark}}}
caps = [{"id": "files", "summary": "The owner's files.", "actions": {
    "open": {"effect": "read", "params": path("read")},
    "save": {"effect": "write", "params": path("write")}}}]
hello = {"method": "hello", "params": {"role": "provider", "name": "pathprov", "capabilities": caps}}
try:
    s.sendall((json.dumps(hello) + "\n").encode())
except OSError:
    pass
f = s.makefile()
first = f.readline().strip()
print(first, flush=True)
if '"ok"' not in first:
    sys.exit(0)
for line in f:
    m = json.loads(line)
    if m.get("method") != "invoke":
        continue
    p = m["params"]
    at = p["args"]["path"]
    with open(log, "a") as l:
        l.write(p["action"] + " " + at + "\n")
    try:
        if p["action"] == "save":
            with open(at, "w") as w:
                w.write("saved\n")
            ok = {"saved": at}
        elif os.path.isdir(at):
            ok = {"names": sorted(os.listdir(at))}
        else:
            with open(at) as r:
                ok = {"first": r.readline().strip()}
        ok["uid"] = os.getuid()
        s.sendall((json.dumps({"id": m["id"], "ok": ok}) + "\n").encode())
    except OSError as e:
        s.sendall((json.dumps({"id": m["id"], "error": str(e), "code": "io"}) + "\n").encode())
"#;

/// A program the test started, ended when it is dropped, also when the test
/// fails.
struct Started(std::process::Child);

impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A program started as `user` (through `runuser`) with `args`, and the
/// first line it printed: a provider's answer to its hello.
fn started_as(user: &str, args: &[&str]) -> (Started, String) {
    let mut child = Command::new("runuser")
        .args(["-u", user, "--"])
        .args(args)
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("starts");
    let out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut line = String::new();
        let _ = std::io::BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(WAIT).expect("a first line");
    (Started(child), line)
}

/// A provider's call `files.<action>` on `path`, as a center sends it.
async fn files_call(
    conn: &mut Conn<TcpStream>,
    action: &str,
    path: &Path,
) -> Result<Value, String> {
    conn.call(
        "invoke",
        json!({"cap": "files", "action": action, "ctx": {},
               "args": {"path": path.display().to_string()}}),
        WAIT,
    )
    .await
    .expect("an answer")
    .map_err(|e| e.message)
}

/// The installed node takes a program of its owner as a provider on its
/// provider socket (issue #152, B4): the owner allows it, it attaches as
/// the owner's process and serves a center's calls. Its paths count by the
/// folders the owner granted alone: `nerve-run`'s own folders (`/tmp`)
/// are not among them, and outside the folders it reads only what every
/// account may read. A folder `nerve-run` may not look into, which the
/// owner's program could, refuses a call that hands over the folder above
/// it. Another account's program, another program under the allowed name
/// and a process of a command the node runs are refused. For a test
/// machine only, as root: it installs the node and removes it again.
///
/// `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
/// with a home, the owner> NERVE_REAL_OTHER=<another account> cargo test -p
/// nerve-node --test real_account -- --ignored --exact
/// the_owners_program_attaches_and_is_held_to_the_folders`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL, NERVE_REAL_OWNER and NERVE_REAL_OTHER name it"]
async fn the_owners_program_attaches_and_is_held_to_the_folders() {
    let (Some(exe), Some(owner), Some(other)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
        std::env::var("NERVE_REAL_OTHER").ok(),
    ) else {
        eprintln!("NERVE_NODE_REAL, NERVE_REAL_OWNER or NERVE_REAL_OTHER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let home =
        sh(Command::new("sh").args(["-c", &format!("getent passwd {owner} | cut -d: -f6")])).1;
    let home = PathBuf::from(home.trim());
    let chmod = |p: &Path, m: &str| assert!(sh(Command::new("chmod").arg(m).arg(p)).0);
    let chown = |p: &Path| {
        assert!(
            sh(Command::new("chown")
                .args(["-R", &format!("{owner}:{owner}")])
                .arg(p))
            .0
        )
    };
    let python = sh(Command::new("python3").args([
        "-c",
        "import os, sys; print(os.path.realpath(sys.executable))",
    ]))
    .1
    .trim()
    .to_string();

    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    chmod(&home, "750");
    let (ok, said) = as_owner_typing(&owner, &["setup"], "real-b4\n\n\n");
    assert!(ok, "{said}");

    // The owner's files: a folder to give, with a subfolder only the owner
    // may look into that holds a link to a protected file, and files outside.
    let base = home.join("nerve-b4");
    let _ = std::fs::remove_dir_all(&base);
    let proj = base.join("proj");
    let shut = proj.join("shut");
    std::fs::create_dir_all(&shut).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/id_b4"), "key\n").unwrap();
    std::fs::write(proj.join("inside.txt"), "inside-line\n").unwrap();
    std::fs::write(base.join("script.py"), PROVIDER_PY).unwrap();
    std::os::unix::fs::symlink(home.join(".ssh/id_b4"), shut.join("key")).unwrap();
    chown(&base);
    chown(&home.join(".ssh"));
    chmod(&base, "755");
    chmod(&base.join("script.py"), "644");
    // Files in nerve-run's own /tmp: one only the owner may read.
    let tmp_closed = Path::new("/tmp/nerve-b4-closed");
    std::fs::write(tmp_closed, "closed-tmp\n").unwrap();
    chown(tmp_closed);
    chmod(tmp_closed, "600");
    let log = base.join("calls.log");

    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "+rw"]);
    assert!(ok, "{said}");
    // The owner closes the subfolder to everyone but itself after the grant:
    // nerve-run may not look into it, the owner's program may.
    chmod(&shut, "700");
    assert!(sh(Command::new("setfacl").arg("-b").arg(&shut)).0);
    let (ok, said) = as_owner(&owner, &["cap", "provider", "allow", "pathprov", &python]);
    assert!(ok, "{said}");
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    let mut conn = inc.conn;

    let at = "/run/nerve-node/provider.sock";
    let script = base.join("script.py");
    let script = script.to_str().unwrap();
    let log_s = log.to_str().unwrap();
    // Another account's program is refused as it connects. It runs a copy
    // of the script it may read.
    let open_copy = Path::new("/var/tmp/nerve-b4-provider.py");
    std::fs::write(open_copy, PROVIDER_PY).unwrap();
    chmod(open_copy, "644");
    let (c, first) = started_as(
        &other,
        &[&python, open_copy.to_str().unwrap(), at, "/dev/null"],
    );
    assert!(
        first.contains("only the owner of the installed node and root"),
        "{first}"
    );
    drop(c);
    // Another program under the allowed name: a copy of python.
    let copy = base.join("python-copy");
    std::fs::copy(&python, &copy).unwrap();
    chown(&copy);
    let (c, first) = started_as(&owner, &[copy.to_str().unwrap(), script, at, log_s]);
    assert!(first.contains("must be"), "{first}");
    drop(c);
    // The owner's program attaches.
    let (provider, first) = started_as(&owner, &[&python, script, at, log_s]);
    assert!(first.contains("\"ok\""), "{first}");
    let (_, st) = as_owner(&owner, &["status"]);
    assert!(st.contains("provider pathprov attached: files"), "{st}");
    let (_, ls) = as_owner(&owner, &["cap", "ls"]);
    assert!(
        ls.contains(&format!("program pathprov: {python}, attached")),
        "{ls}"
    );
    assert!(
        ls.lines().any(|l| l.split_whitespace().collect::<Vec<_>>()
            == [
                "files.save",
                "write",
                "program",
                "pathprov",
                "conformance-center:",
                "default"
            ]),
        "{ls}"
    );
    let owner_uid = sh(Command::new("id").args(["-u", &owner])).1;

    // In the folder: it reads and writes, as the owner.
    let r = files_call(&mut conn, "open", &proj.join("inside.txt"))
        .await
        .unwrap();
    assert_eq!(r["first"], "inside-line", "{r}");
    assert_eq!(r["uid"].to_string(), owner_uid.trim(), "{r}");
    let r = files_call(&mut conn, "save", &proj.join("new.txt"))
        .await
        .unwrap();
    assert!(r["saved"].is_string(), "{r}");
    // nerve-run's own /tmp is no folder of the program's.
    let e = files_call(&mut conn, "save", Path::new("/tmp/nerve-b4-made"))
        .await
        .unwrap_err();
    assert!(e.contains("outside the folders that allow writing"), "{e}");
    assert!(!Path::new("/tmp/nerve-b4-made").exists());
    let e = files_call(&mut conn, "open", tmp_closed).await.unwrap_err();
    assert!(e.contains("not open to every account"), "{e}");
    // A public file outside the folders is read.
    let r = files_call(&mut conn, "open", Path::new("/etc/hostname"))
        .await
        .unwrap();
    assert!(r["first"].is_string(), "{r}");
    // The folder holds a subfolder nerve-run may not look into: refused,
    // the protected file behind the link is never reached.
    let e = files_call(&mut conn, "open", &proj).await.unwrap_err();
    assert!(e.contains("may not look into"), "{e}");
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        calls,
        format!(
            "open {}\nsave {}\nopen /etc/hostname\n",
            proj.join("inside.txt").display(),
            proj.join("new.txt").display()
        ),
        "only the allowed calls reach the program"
    );
    let (_, audit) = as_owner(&owner, &["audit", "--last", "6"]);
    // One entry a line, its columns apart.
    let entry = |what: &str| {
        audit.lines().any(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            let want: Vec<&str> = what.split(' ').collect();
            words.windows(want.len()).any(|w| w == want.as_slice())
        })
    };
    assert!(entry("files.save /tmp/nerve-b4-made forbidden:"), "{audit}");
    assert!(entry("files.open /etc/hostname allowed"), "{audit}");
    assert!(
        entry(&format!("files.open {} forbidden:", proj.display())),
        "{audit}"
    );

    // A process of a command the node runs (user mode, as the owner) is
    // refused, though it runs the allowed program.
    assert!(as_owner(&owner, &["mode", "set", "user"]).0);
    let hello = format!("{python} {script} - /dev/null");
    let r = run(&mut conn, &proj, &hello).await.unwrap();
    assert!(
        out(&r).contains("comes from a command the node runs"),
        "{r}"
    );

    drop(provider);
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    let _ = std::fs::remove_file(tmp_closed);
    let _ = std::fs::remove_file(open_copy);
    std::fs::remove_dir_all(&base).unwrap();
    std::fs::remove_dir_all(home.join(".ssh")).unwrap();
}
