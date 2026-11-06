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
//! its keyring folder. It expects the node installed and its keys moved into the
//! keyring (`config set machine.secret_storage keyring`) (`.github/scripts/keyring-end-to-end.sh` does both): `NERVE_REAL_KEYRING=1 NERVE_REAL_OWNER=<the owner>
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
        eprintln!("skipped: NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
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
    let (ok, said) = as_owner_typing(&owner, &["setup"], "\n");
    assert!(ok, "{said}");
    assert!(said.contains("No center is paired"), "{said}");
    let (ok, said) = as_owner(&owner, &["config", "set", "node.name", "real-142"]);
    assert!(ok, "{said}");
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
    // A variable an operator put into the service's environment, as a
    // proxy's password or a token would be (#89).
    let drop_in = Path::new("/etc/systemd/system/nerve-node.service.d");
    std::fs::create_dir_all(drop_in).unwrap();
    std::fs::write(
        drop_in.join("nerve-real-env.conf"),
        "[Service]\nEnvironment=NERVE_REAL_SECRET=from-the-unit\n",
    )
    .unwrap();
    assert!(sh(Command::new("systemctl").arg("daemon-reload")).0);
    assert!(sh(Command::new("systemctl").args(["restart", "nerve-node"])).0);
    until("the node answers again", || as_owner(&owner, &["status"]).0);
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
s.sendall((json.dumps({"method": "cli", "params": {"args": ["mode", "user"], "cwd": "/"}}) + "\n").encode())
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
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "rwx"]);
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
    assert!(as_owner(&owner, &["folder", "add", p, "rw"]).0);
    let (ok, said) = as_owner(&owner, &["folder", "add", p, "rwx"]);
    assert!(ok && !said.contains("warning"), "{said}");
    let (_, st) = as_owner(&owner, &["status"]);
    assert!(!st.contains("did not get every folder"), "{st}");
    let (_, ls) = as_owner(&owner, &["--json", "center"]);
    let ls: Value = serde_json::from_str(ls.trim()).unwrap();
    assert_eq!(ls["centers"][0]["mode"], "folder", "{ls}");
    // A folder named like a word of the command, given by a relative path,
    // is that folder; the word stays a word.
    let named = base.join("folder");
    std::fs::create_dir_all(&named).unwrap();
    chown(&named);
    for args in [
        &["folder", "add", "folder", "r"][..],
        &["folder", "rm", "folder"],
    ] {
        let (ok, said) = sh(Command::new("runuser")
            .args(["-u", &owner, "--", BIN])
            .args(args)
            .current_dir(&base));
        assert!(ok, "{args:?}: {said}");
    }
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

    // As nerve-run, with its pairing's own home (#167).
    let r = run(&mut conn, &proj, "./who.sh").await.unwrap();
    assert_eq!(
        out(&r),
        "nerve-run\n/var/lib/nerve-run/conformance-center/home\n",
        "{r}"
    );
    // Of the service's environment only what a command always gets, and
    // what the owner names.
    let env = "./env.sh";
    std::fs::write(
        proj.join("env.sh"),
        "#!/bin/sh\necho \"${NERVE_REAL_SECRET-none}|${NERVE_NODE_OWNER-none}|${INVOCATION_ID-none}|${PATH:+path}\"\n",
    )
    .unwrap();
    chown(&proj.join("env.sh"));
    chmod(&proj.join("env.sh"), "755");
    let r = run(&mut conn, &proj, env).await.unwrap();
    assert_eq!(out(&r), "none|none|none|path\n", "{r}");
    let (ok, said) = as_owner(
        &owner,
        &["config", "add", "machine.command_env", "NERVE_REAL_SECRET"],
    );
    assert!(ok, "{said}");
    let r = run(&mut conn, &proj, env).await.unwrap();
    assert_eq!(out(&r), "from-the-unit|none|none|path\n", "{r}");
    let (ok, said) = as_owner(
        &owner,
        &["config", "rm", "machine.command_env", "NERVE_REAL_SECRET"],
    );
    assert!(ok, "{said}");
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
    let (_, ls) = as_owner(&owner, &["--json", "center"]);
    let ls: Value = serde_json::from_str(ls.trim()).unwrap();
    assert_eq!(ls["centers"][0]["mode"], "folder", "{ls}");

    // sudo: on with the owner's password (root's to switch on); an allowed
    // sudo command of nerve-run runs as root, started by the node, not
    // through the owner's sudo: it still works after the owner's password
    // changed. One the sudo
    // list does not name is refused.
    let (ok, said) = typing(Command::new(BIN).args(["sudo", "on"]), "first-pass-142\n");
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["rule", "add", "allow", "sudo id -un"]);
    assert!(ok, "{said}");
    pw("second-pass-142");
    let r = run(&mut conn, &proj, "sudo id -un").await.unwrap();
    assert_eq!(out(&r), "root\n", "{r}");
    // A leading `-n` goes; another option of sudo is refused with the
    // reason, also where the sudo list names the line.
    for line in ["sudo -n id -un", "sudo -E id -un"] {
        let (ok, said) = as_owner(&owner, &["rule", "add", "allow", "--", line]);
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
    let (ok, said) = as_owner(&owner, &["rule", "add", "allow", "sudo pwd -P"]);
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
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "rx"]);
    assert!(ok, "{said}");
    let r = run(&mut conn, &proj, "cat given.txt").await.unwrap();
    assert_eq!(out(&r), "given\n", "{r}");
    // A file moved in from outside keeps its own ACL; `folder sync` walks
    // the grants again and gives it the folder's entry.
    let moved = base.join("moved.txt");
    std::fs::write(&moved, "moved\n").unwrap();
    chown(&moved);
    chmod(&moved, "600");
    assert!(sh(Command::new("mv").arg(&moved).arg(proj.join("moved.txt"))).0);
    assert!(!getfacl(&proj.join("moved.txt")).contains(&format!("user:{run_uid}:")));
    let (ok, said) = as_owner(&owner, &["folder", "sync"]);
    assert!(
        ok && said.contains("nerve-run has its access to everything"),
        "{said}"
    );
    let r = run(&mut conn, &proj, "cat moved.txt").await.unwrap();
    assert_eq!(out(&r), "moved\n", "{r}");
    // Allowlist mode as nerve-run: its folders count, and say nothing; as
    // the owner they do not, and nerve-run loses their entries.
    let other = base.join("other");
    std::fs::create_dir_all(&other).unwrap();
    chown(&other);
    assert!(as_owner(&owner, &["mode", "allowlist"]).0);
    let (ok, said) = as_owner(&owner, &["folder", "add", other.to_str().unwrap(), "r"]);
    assert!(ok && !said.contains("do not count"), "{said}");
    assert!(
        getfacl(&other).contains(&format!("\nuser:{run_uid}:r-x")),
        "{}",
        getfacl(&other)
    );
    assert!(as_owner(&owner, &["mode", "allowlist", "--as-owner"]).0);
    let (ok, said) = as_owner(&owner, &["folder", "add", other.to_str().unwrap(), "rx"]);
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
    let (ok, said) = as_owner(&owner, &["folder", "add", third.to_str().unwrap(), "r"]);
    assert!(ok && said.contains("do not count"), "{said}");
    assert!(as_owner(&owner, &["mode", "folder"]).0);
    let r = run(&mut conn, &proj, "cat given.txt").await.unwrap();
    assert_eq!(out(&r), "given\n", "{r}");
    drop(conn);
    // The node walks every grant when it starts: what was moved in while it
    // ran gets its entry.
    let later = base.join("later.txt");
    std::fs::write(&later, "later\n").unwrap();
    chown(&later);
    assert!(sh(Command::new("mv").arg(&later).arg(proj.join("later.txt"))).0);
    assert!(sh(Command::new("systemctl").args(["restart", "nerve-node"])).0);
    until("the moved file gets its entry", || {
        getfacl(&proj.join("later.txt")).contains(&format!("user:{run_uid}:"))
    });

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

    // Another account that fills the owner socket with connections that
    // send nothing, as a command of any center may, keeps the owner out of
    // nothing: the owner's places stay its own.
    let hold = r#"import socket, time
held = []
for _ in range(80):
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/" + "nerve-node/owner.sock")
    held.append(s)
print("held", flush=True)
time.sleep(60)
"#;
    // As nerve-run itself, not through runuser, whose child a kill of it
    // leaves running.
    let run_gid: u32 = sh(Command::new("id").args(["-g", "nerve-run"]))
        .1
        .trim()
        .parse()
        .unwrap();
    let mut holder = {
        use std::os::unix::process::CommandExt;
        Command::new("python3")
            .args(["-c", hold])
            .current_dir("/")
            .gid(run_gid)
            .uid(run_uid.parse().unwrap())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(holder.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "held\n");
    }
    let (ok, st) = as_owner(&owner, &["status"]);
    let _ = holder.kill();
    let _ = holder.wait();
    assert!(ok && !st.contains("does not take connections"), "{st}");

    // What nerve-run's commands left in the folders every account may write
    // in goes with the account.
    let (ok, said) = sh(Command::new("runuser")
        .args(["-u", "nerve-run", "--", "sh", "-c"])
        .arg(
            "echo x > /var/tmp/nerve-real-left && mkdir -p /var/tmp/nerve-real-dir \
             && echo y > /var/tmp/nerve-real-dir/f && echo z > /dev/shm/nerve-real-shm \
             && echo w > /tmp/nerve-real-tmp",
        )
        .current_dir("/"));
    assert!(ok, "{said}");

    // Uninstall: the account, its home and every entry go.
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    assert!(said.contains("removed the account nerve-run"), "{said}");
    assert!(
        said.contains("files of nerve-run in /tmp, /var/tmp, /dev/shm"),
        "{said}"
    );
    std::fs::remove_dir_all(drop_in).unwrap();
    assert!(sh(Command::new("systemctl").arg("daemon-reload")).0);
    let (_, left) = sh(Command::new("find").args([
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "-xdev",
        "-uid",
        run_uid.as_str(),
    ]));
    assert!(left.trim().is_empty(), "{left}");
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
        eprintln!("skipped: NERVE_REAL_KEYRING or NERVE_REAL_OWNER is not set");
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
    let (ok, said) = as_owner(&owner, &["folder", "add", base.to_str().unwrap(), "rwx"]);
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
        eprintln!("skipped: NERVE_NODE_REAL, NERVE_REAL_OWNER or NERVE_REAL_OTHER is not set");
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
    let (ok, said) = as_owner_typing(&owner, &["setup"], "\n");
    assert!(ok, "{said}");

    // The owner's files: a folder to give, with a subfolder only the owner
    // may look into that holds a link to a protected file, and files outside.
    let base = home.join("nerve-b4");
    let _ = std::fs::remove_dir_all(&base);
    let proj = base.join("proj");
    let shut = proj.join("shut");
    std::fs::create_dir_all(&shut).unwrap();
    // The account may be one the tester logs in with: what its ~/.ssh held
    // stays as it was, and the folder goes again only where the test made it.
    let ssh = home.join(".ssh");
    let made_ssh = !ssh.exists();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_b4"), "key\n").unwrap();
    std::fs::write(proj.join("inside.txt"), "inside-line\n").unwrap();
    std::fs::write(base.join("script.py"), PROVIDER_PY).unwrap();
    std::os::unix::fs::symlink(home.join(".ssh/id_b4"), shut.join("key")).unwrap();
    chown(&base);
    chown(&ssh.join("id_b4"));
    if made_ssh {
        chown(&ssh);
        chmod(&ssh, "700");
    }
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
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "rw"]);
    assert!(ok, "{said}");
    // The owner closes the subfolder to everyone but itself after the grant:
    // nerve-run may not look into it, the owner's program may.
    chmod(&shut, "700");
    assert!(sh(Command::new("setfacl").arg("-b").arg(&shut)).0);
    let (ok, said) = as_owner(&owner, &["provider", "add", "pathprov", &python]);
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
    let (_, ls) = as_owner(&owner, &["cap"]);
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
                "on"
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

    // A folder the owner gives that holds nerve-run's home gives the program
    // no other pairing's folder: not a file in it, not the folder above it
    // (the program works below what it is handed, with the owner's rights),
    // and not a link in a folder of the grant that leads there.
    let other = Path::new("/var/lib/nerve-run/nrv167-other/home");
    std::fs::create_dir_all(other).unwrap();
    std::fs::write(other.join("x"), "other\n").unwrap();
    assert!(
        sh(Command::new("chown").args([
            "-R",
            "nerve-run:nerve-run",
            "/var/lib/nerve-run/nrv167-other"
        ]))
        .0
    );
    let linked = Path::new("/var/lib/nrv167-link");
    std::fs::create_dir_all(linked).unwrap();
    let _ = std::fs::remove_file(linked.join("to"));
    std::os::unix::fs::symlink(other, linked.join("to")).unwrap();
    chmod(linked, "755");
    let (ok, said) = as_owner(&owner, &["folder", "add", "/var/lib", "r"]);
    assert!(ok, "{said}");
    let e = files_call(&mut conn, "open", &other.join("x"))
        .await
        .unwrap_err();
    assert!(e.contains("another pairing"), "{e}");
    let e = files_call(&mut conn, "open", Path::new("/var/lib"))
        .await
        .unwrap_err();
    // The node's own folders under it refuse it first on an installed node.
    assert!(
        e.contains("holds") || e.contains("belongs to the node itself"),
        "{e}"
    );
    let _ = files_call(&mut conn, "open", linked).await.unwrap_err();
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        !calls.contains("/var/lib"),
        "no call reached the program: {calls}"
    );
    let (ok, said) = as_owner(&owner, &["folder", "rm", "/var/lib"]);
    assert!(ok, "{said}");
    // In allowlist mode a rule covers places the folders do not give: a
    // link in the handed folder into another pairing's home refuses the
    // call all the same (the program would follow it), one that stays in
    // the folder does not.
    for args in [
        &["mode", "allowlist"][..],
        // The rule an audit entry's button makes for the capability.
        &["rule", "add", "allow", "", "--action", "files.open"],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{said}");
    }
    let e = files_call(&mut conn, "open", linked).await.unwrap_err();
    assert!(
        e.contains("another pairing") && e.contains("nrv167-link/to"),
        "{e}"
    );
    std::fs::remove_file(linked.join("to")).unwrap();
    std::fs::write(linked.join("f"), "f\n").unwrap();
    chmod(&linked.join("f"), "644");
    std::os::unix::fs::symlink(linked.join("f"), linked.join("to")).unwrap();
    let r = files_call(&mut conn, "open", linked).await.unwrap();
    assert_eq!(r["names"], json!(["f", "to"]), "{r}");
    let _ = std::fs::remove_dir_all(linked);

    // A process of a command the node runs (user mode, as the owner) is
    // refused, though it runs the allowed program, and the name is free:
    // the owner lets the attached one go first.
    for args in [
        &["provider", "rm", "pathprov"][..],
        &["provider", "add", "pathprov", &python],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{said}");
    }
    let gone = std::time::Instant::now();
    while as_owner(&owner, &["status"])
        .1
        .contains("provider pathprov attached")
    {
        assert!(gone.elapsed() < WAIT, "the provider stays attached");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(as_owner(&owner, &["mode", "user"]).0);
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
    let _ = std::fs::remove_dir_all("/var/lib/nerve-run/nrv167-other");
    std::fs::remove_dir_all(&base).unwrap();
    std::fs::remove_file(ssh.join("id_b4")).unwrap();
    if made_ssh {
        std::fs::remove_dir(&ssh).unwrap();
    }
}

/// The config capability `name` with `args`, as a center calls it: its
/// result, or the refusal.
async fn config_call(conn: &mut Conn<TcpStream>, name: &str, args: Value) -> Result<Value, String> {
    let (cap, action) = name.split_once('.').unwrap();
    conn.call(
        "invoke",
        json!({"cap": cap, "action": action, "args": args, "ctx": {}}),
        WAIT,
    )
    .await
    .expect("an answer")
    .map_err(|e| e.message)
}

/// Capabilities of node.toml on the installed node (issue #152): the owner
/// declares them with `cap add`; one runs as `nerve-run` (its `id` says so)
/// from that account's home, with the call's arguments as whole arguments
/// that no shell reads; its path argument is held to the folders and read
/// with `nerve-run`'s access; under Landlock it reaches only the folders,
/// the system's and its own (CI's keyring job runs it there); its timeout
/// ends it; and in a pairing whose commands run as the owner it still runs
/// as `nerve-run`, held to its own folders (a granted folder open to every
/// account included), and the center is no longer told it is a command of
/// the pairing's account. None runs as the owner: `cap add` takes no
/// account. For a test machine only, as root: it installs the node and
/// removes it again.
///
/// `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
/// with a home, the owner> cargo test -p nerve-node --test real_account --
/// --ignored --exact a_config_capability_runs_as_nerve_run_in_a_folder_pairing`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL and NERVE_REAL_OWNER name it"]
async fn a_config_capability_runs_as_nerve_run_in_a_folder_pairing() {
    let (Some(exe), Some(owner)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
    ) else {
        eprintln!("skipped: NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
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

    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    chmod(&home, "750");
    let (ok, said) = as_owner_typing(&owner, &["setup"], "\n");
    assert!(ok, "{said}");

    // The owner's files: a folder to give, a file only the owner may read
    // outside it.
    let base = home.join("nerve-b5");
    let _ = std::fs::remove_dir_all(&base);
    let proj = base.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("inside.txt"), "inside-line\n").unwrap();
    std::fs::write(base.join("closed.txt"), "closed-line\n").unwrap();
    chown(&base);
    chmod(&base, "755");
    chmod(&base.join("closed.txt"), "600");
    // A file every account may read, outside the folders and the system's:
    // Landlock, where the kernel has it, holds a command away from it.
    let open = PathBuf::from("/srv/nerve-b5");
    let _ = std::fs::remove_dir_all(&open);
    std::fs::create_dir_all(&open).unwrap();
    std::fs::write(open.join("open.txt"), "open-line\n").unwrap();
    chmod(&open, "755");
    chmod(&open.join("open.txt"), "644");
    // A granted folder every account may read: only Landlock can hold a
    // command of nerve-run away from it.
    let shared = PathBuf::from("/srv/nerve-b5-shared");
    let _ = std::fs::remove_dir_all(&shared);
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(shared.join("shared.txt"), "shared-line\n").unwrap();
    chmod(&shared, "755");
    chmod(&shared.join("shared.txt"), "644");
    let scratch = "/tmp/nerve-b5-scratch";
    let _ = std::fs::remove_file(scratch);
    let landlock = nerve_sandbox::Confinement::detect().landlock_abi.is_some();

    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "rw"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", shared.to_str().unwrap(), "r"]);
    assert!(ok, "{said}");
    let path_params = r#"{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "read"}}, "required": ["path"]}"#;
    let word_params = r#"{"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}, "required": ["a", "b"]}"#;
    for args in [
        &["cap", "add", "who.am", "--effect", "read", "--", "id"][..],
        &["cap", "add", "who.where", "--effect", "read", "--", "pwd"],
        &[
            "cap",
            "add",
            "files.show",
            "--effect",
            "read",
            "--params",
            path_params,
            "--",
            "cat",
            "--",
            "{path}",
        ],
        &[
            "cap",
            "add",
            "say.back",
            "--effect",
            "read",
            "--params",
            word_params,
            "--",
            "printf",
            "[%s]\n",
            "{a}",
            "{b}",
        ],
        &[
            "cap",
            "add",
            "slow.wait",
            "--effect",
            "read",
            "--timeout",
            "1",
            "--",
            "sleep",
            "41.75",
        ],
        &[
            "cap",
            "add",
            "open.show",
            "--effect",
            "read",
            "--",
            "cat",
            "--",
            "/srv/nerve-b5/open.txt",
        ],
        &[
            "cap",
            "add",
            "scratch.put",
            "--effect",
            "write",
            "--",
            "sh",
            "-c",
            "echo put > /tmp/nerve-b5-scratch && cat /tmp/nerve-b5-scratch",
        ],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{args:?}: {said}");
    }
    // In folder mode a read that names no path needs `on`; one with its
    // path in the folders does not.
    for cap in ["who", "say", "slow", "open", "scratch"] {
        let (ok, said) = as_owner(&owner, &["cap", "set", cap, "on"]);
        assert!(ok, "{said}");
    }
    let (_, ls) = as_owner(&owner, &["cap"]);
    assert!(
        ls.lines().any(|l| l.split_whitespace().collect::<Vec<_>>()
            == ["files.show", "read", "config", "conformance-center:", "on"]),
        "{ls}"
    );
    assert!(ls.contains("capability who.am: id\n"), "{ls}");
    assert!(
        ls.contains(r#"capability say.back: printf "[%s]\n" {a} {b}"#),
        "{ls}"
    );
    // There is no other account to run one as.
    let (ok, said) = as_owner(
        &owner,
        &[
            "cap",
            "add",
            "own.run",
            "--effect",
            "read",
            "--account",
            "owner",
            "--",
            "id",
        ],
    );
    assert!(!ok && said.contains("--account"), "{said}");
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    let mut conn = inc.conn;
    // The node took the capabilities before the link came; they are offered
    // once it sees them.
    let mut who = Err(String::new());
    for _ in 0..100 {
        who = config_call(&mut conn, "who.am", json!({})).await;
        if who.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let who = who.unwrap();
    let who = who.as_str().unwrap();
    assert!(
        who.contains("(nerve-run)") && !who.contains(&owner),
        "{who}"
    );
    let r = config_call(&mut conn, "who.where", json!({}))
        .await
        .unwrap();
    assert_eq!(r, json!("/var/lib/nerve-run/conformance-center/home\n"));
    // The center is told it is a command of the pairing's command account,
    // which nerve-run is here.
    assert_eq!(as_account(&mut conn, "files.show").await, json!(true));

    // The arguments stay data.
    let a = "; touch /tmp/nerve-b5-ran";
    let b = "$(id) `id`";
    let r = config_call(&mut conn, "say.back", json!({"a": a, "b": b}))
        .await
        .unwrap();
    assert_eq!(r, json!(format!("[{a}]\n[{b}]\n")));
    assert!(!Path::new("/tmp/nerve-b5-ran").exists());

    // Its path: in the folder it reads; outside, what nerve-run may read,
    // never the owner's closed file.
    let r = config_call(
        &mut conn,
        "files.show",
        json!({"path": proj.join("inside.txt").to_str().unwrap()}),
    )
    .await
    .unwrap();
    assert_eq!(r, json!("inside-line\n"));
    let r = config_call(
        &mut conn,
        "files.show",
        json!({"path": shared.join("shared.txt").to_str().unwrap()}),
    )
    .await
    .unwrap();
    assert_eq!(r, json!("shared-line\n"));
    let e = config_call(
        &mut conn,
        "files.show",
        json!({"path": base.join("closed.txt").to_str().unwrap()}),
    )
    .await
    .unwrap_err();
    // Closed to other accounts: by the home (750) or by the file (600).
    assert!(
        e.contains("not open to every account") || e.contains("may not read"),
        "{e}"
    );
    let r = config_call(&mut conn, "files.show", json!({"path": "/etc/hostname"}))
        .await
        .unwrap();
    assert!(!r.as_str().unwrap().is_empty(), "{r}");
    let e = config_call(
        &mut conn,
        "files.show",
        json!({"path": "/etc/nerve/node.toml"}),
    )
    .await
    .unwrap_err();
    // `nerve-run` cannot even resolve it, or the node names it its own.
    assert!(
        e.contains("belongs to the node") || e.contains("Permission denied"),
        "{e}"
    );

    // Under Landlock it reaches the folders, the system's and its own
    // (`/tmp`), nothing else: a file every account may read outside them is
    // refused when it runs. Without Landlock nerve-run reads it.
    let r = config_call(&mut conn, "open.show", json!({})).await;
    if landlock {
        // cat's own refusal, in the system's language.
        let e = r.unwrap_err();
        assert!(e.contains("open.show failed: exit code 1"), "{e}");
    } else {
        assert_eq!(r.unwrap(), json!("open-line\n"));
    }
    let r = config_call(&mut conn, "scratch.put", json!({}))
        .await
        .unwrap();
    assert_eq!(r, json!("put\n"));

    // The timeout ends it, and nothing of it is left.
    let started = std::time::Instant::now();
    let e = config_call(&mut conn, "slow.wait", json!({}))
        .await
        .unwrap_err();
    assert!(e.contains("slow.wait ran past its limit of 1 s"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(10));
    let left = sh(Command::new("pgrep").args(["-f", "sleep 41.75"]));
    assert!(!left.0, "{}", left.1);

    // A pairing whose commands run as the owner: its commands run as the
    // owner once the node took the change, the capability still as
    // nerve-run.
    assert!(as_owner(&owner, &["mode", "user"]).0);
    let mut as_the_owner = false;
    for _ in 0..100 {
        if let Ok(r) = run(&mut conn, &home, "id -un").await
            && out(&r).trim() == owner
        {
            as_the_owner = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(as_the_owner, "exec.run runs as the owner in user mode");
    let who = config_call(&mut conn, "who.am", json!({})).await.unwrap();
    assert!(who.as_str().unwrap().contains("(nerve-run)"), "{who}");
    // Held to its own folders there, not the pairing's, which are the
    // owner's now.
    let _ = std::fs::remove_file(scratch);
    let r = config_call(&mut conn, "scratch.put", json!({}))
        .await
        .unwrap();
    assert_eq!(r, json!("put\n"));
    // A granted folder every account may read: the pairing's folders are
    // the owner's now, so Landlock holds the command away from it; without
    // Landlock nerve-run reads it.
    let r = config_call(
        &mut conn,
        "files.show",
        json!({"path": shared.join("shared.txt").to_str().unwrap()}),
    )
    .await;
    if landlock {
        let e = r.unwrap_err();
        assert!(e.contains("files.show failed: exit code 1"), "{e}");
    } else {
        assert_eq!(r.unwrap(), json!("shared-line\n"));
    }
    // The command account the center knows is the owner here: the action
    // is not marked as one of its commands.
    assert_eq!(as_account(&mut conn, "files.show").await, Value::Null);
    let audit = as_owner(&owner, &["audit"]).1;
    assert!(
        audit.contains("who.am  who.am  allowed (command: id)")
            && audit.contains(&format!(
                "files.show  {}  forbidden",
                base.join("closed.txt").display()
            )),
        "{audit}"
    );

    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    std::fs::remove_dir_all(&base).unwrap();
    std::fs::remove_dir_all(&open).unwrap();
    std::fs::remove_dir_all(&shared).unwrap();
    let _ = std::fs::remove_file(scratch);
}

/// The `as_account` mark of the action `name` in the descriptor the center
/// gets now (null when it is not there).
async fn as_account(conn: &mut Conn<TcpStream>, name: &str) -> Value {
    let (cap, action) = name.split_once('.').unwrap();
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    d["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == cap)
        .map(|c| c["actions"][action]["as_account"].clone())
        .unwrap_or_default()
}

/// Rules on a capability's arguments on the installed node (#152, C1): the
/// owner adds a capability of node.toml, then rules that pin its arguments;
/// each call is decided as the rule says (a deny pin wins over any allow, an
/// allow pin in allowlist mode covers its values only), the audit log keeps
/// the decision with the arguments, a rule naming an argument the action does
/// not take is refused, and `rule` says which rule no longer fits once the
/// capability changes. For a test machine only, as root: it installs the node
/// and removes it again.
///
/// `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
/// with a home, the owner> cargo test -p nerve-node --test real_account --
/// --ignored --exact argument_rules_decide_a_config_capability_on_the_installed_node`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL and NERVE_REAL_OWNER name it"]
async fn argument_rules_decide_a_config_capability_on_the_installed_node() {
    let (Some(exe), Some(owner)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
    ) else {
        eprintln!("skipped: NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    let (ok, said) = as_owner_typing(&owner, &["setup"], "\n");
    assert!(ok, "{said}");
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let params = r#"{"type": "object", "properties": {"room": {"type": "string"}, "level": {"type": "integer"}}, "required": ["room", "level"]}"#;
    let (ok, said) = as_owner(
        &owner,
        &[
            "cap", "add", "lamp.set", "--effect", "write", "--params", params, "--", "echo", "set",
            "{room}", "{level}",
        ],
    );
    assert!(ok, "{said}");
    // User mode: the deny pin refuses its room, every other one runs.
    for args in [
        &["mode", "user"][..],
        &["rule", "add", "deny", "lamp.set:room=bedroom"],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{args:?}: {said}");
    }
    let (ok, said) = as_owner(&owner, &["rule", "add", "deny", "lamp.set:size=1"]);
    assert!(
        !ok && said.contains("lamp.set has no argument size; it takes level, room"),
        "{said}"
    );
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    let mut conn = inc.conn;
    let lamp = |room: &str, level: i64| json!({"room": room, "level": level});
    let mut first = Err(String::new());
    for _ in 0..100 {
        first = config_call(&mut conn, "lamp.set", lamp("office", 3)).await;
        if first.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(first.unwrap(), json!("set office 3\n"));
    let e = config_call(&mut conn, "lamp.set", lamp("bedroom", 3))
        .await
        .unwrap_err();
    assert!(
        e.contains("lamp.set is denied (lamp.set:room=bedroom)"),
        "{e}"
    );

    // Allowlist mode: the allow pins cover their values only, and the deny
    // pin wins over an allow rule that covers its call.
    for args in [
        &["mode", "allowlist"][..],
        &["rule", "add", "allow", "lamp.set:level<=5"],
        &[
            "rule",
            "add",
            "allow",
            "",
            "--action",
            "lamp.set",
            "--arg",
            "room=kitchen",
        ],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{args:?}: {said}");
    }
    let (_, ls) = as_owner(&owner, &["rule"]);
    for line in [
        "allow  lamp.set:level<=5",
        "allow  lamp.set:room=kitchen",
        "deny  lamp.set:room=bedroom",
    ] {
        assert!(ls.lines().any(|l| l == line), "{line}: {ls}");
    }
    assert!(!ls.contains("warning"), "{ls}");
    assert_eq!(
        config_call(&mut conn, "lamp.set", lamp("office", 3))
            .await
            .unwrap(),
        json!("set office 3\n")
    );
    assert_eq!(
        config_call(&mut conn, "lamp.set", lamp("kitchen", 9))
            .await
            .unwrap(),
        json!("set kitchen 9\n")
    );
    let e = config_call(&mut conn, "lamp.set", lamp("office", 9))
        .await
        .unwrap_err();
    assert!(
        e.contains("no allow rule matches lamp.set with these arguments"),
        "{e}"
    );
    let e = config_call(&mut conn, "lamp.set", lamp("bedroom", 1))
        .await
        .unwrap_err();
    assert!(
        e.contains("lamp.set is denied (lamp.set:room=bedroom)"),
        "{e}"
    );

    // The audit log has each decision with the arguments.
    let audit = std::fs::read_to_string("/var/lib/nerve/state/audit.jsonl").unwrap();
    let calls: Vec<Value> = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["cap"] == "lamp" && e["action"] == "set")
        .collect();
    let seen: Vec<(String, Value)> = calls
        .iter()
        .map(|e| {
            (
                e["decision"].as_str().unwrap().to_string(),
                e["args"].clone(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("allowed".to_string(), lamp("office", 3)),
            ("forbidden".into(), lamp("bedroom", 3)),
            ("allowed".into(), lamp("office", 3)),
            ("allowed".into(), lamp("kitchen", 9)),
            ("forbidden".into(), lamp("office", 9)),
            ("forbidden".into(), lamp("bedroom", 1)),
        ],
        "{audit}"
    );
    assert_eq!(
        calls[1]["reason"],
        "lamp.set is denied (lamp.set:room=bedroom)"
    );

    // The capability takes no room now: the rules that name it stay, and
    // `rule` says what they do.
    let (ok, said) = as_owner(
        &owner,
        &[
            "cap",
            "edit",
            "lamp.set",
            "--params",
            r#"{"type": "object", "properties": {"level": {"type": "integer"}}, "required": ["level"]}"#,
            "--",
            "echo",
            "set",
            "{level}",
        ],
    );
    assert!(ok, "{said}");
    let (_, ls) = as_owner(&owner, &["rule"]);
    assert!(
        ls.contains("warning: the deny rule \"lamp.set:room=bedroom\" no longer fits: lamp.set has no argument room; it takes level; as a deny rule it may refuse calls of lamp.set it was not meant for until you change it"),
        "{ls}"
    );
    // It fails closed: a call that cannot give the room is refused by it.
    let e = config_call(&mut conn, "lamp.set", json!({"level": 1}))
        .await
        .unwrap_err();
    assert!(
        e.contains("lamp.set is denied (lamp.set:room=bedroom)"),
        "{e}"
    );

    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
}

/// The limits per command on the installed node (docs/dev/sandbox-linux.md): the
/// service's cgroup is delegated to it, so a folder mode command of
/// `nerve-run` runs in a cgroup of its own below the service, with the
/// memory, CPU and processes its call asked for; one past its memory is
/// killed by the kernel and its result says so; a call that asks for more
/// than the most is refused. For a test machine only, as root: it installs
/// the node and removes it again.
///
/// `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
/// with a home, the owner> cargo test -p nerve-node --test real_account --
/// --ignored --exact a_command_is_held_to_its_limits_on_the_installed_node`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL and NERVE_REAL_OWNER name it"]
async fn a_command_is_held_to_its_limits_on_the_installed_node() {
    let (Some(exe), Some(owner)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
    ) else {
        eprintln!("skipped: NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    let (ok, said) = as_owner_typing(&owner, &["setup"], "\n");
    assert!(ok, "{said}");
    // `status` says the service's cgroup holds all three.
    let (_, st) = as_owner(&owner, &["--json", "status"]);
    let st: Value = serde_json::from_str(&st[st.find('{').unwrap()..]).unwrap();
    let st = st.get("data").unwrap_or(&st).clone();
    let limits = &st["command_limits"];
    assert!(limits["off"].is_null(), "{limits}");
    assert!(
        limits["cgroup"]
            .as_str()
            .is_some_and(|c| c.contains("nerve-node.service")),
        "{limits}"
    );
    assert_eq!(
        limits["enforced"],
        json!(["memory", "cpu", "processes"]),
        "{limits}"
    );

    // The owner's folder, to give to the center.
    let work = PathBuf::from("/srv/nrv-limits");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    assert!(sh(Command::new("chown").arg(format!("{owner}:")).arg(&work)).0);
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", work.to_str().unwrap(), "rwx"]);
    assert!(ok, "{said}");
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    let mut conn = inc.conn;
    let run_with = |command: &str, limits: Value| {
        let mut args = json!({"command": command, "cwd": work.display().to_string()});
        args.as_object_mut()
            .unwrap()
            .extend(limits.as_object().unwrap().clone());
        args
    };

    // Its own cgroup, with what the call asked for. The cgroup's files are
    // the node's, so the test reads them while the command waits.
    let wait = "cut -d: -f3 /proc/self/cgroup > cgroup.txt; i=0; \
                while [ ! -e release ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done";
    let call = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": run_with(wait,
                json!({"memory_mb": 64, "cpu_percent": 50, "processes": 32}))}),
        )
        .await
        .unwrap();
    until("the command's cgroup is written", || {
        std::fs::read_to_string(work.join("cgroup.txt")).is_ok_and(|t| t.ends_with('\n'))
    });
    let cgroup = std::fs::read_to_string(work.join("cgroup.txt")).unwrap();
    let cgroup = cgroup.trim();
    assert!(
        cgroup.contains("/nerve-node.service/")
            && cgroup
                .rsplit('/')
                .next()
                .is_some_and(|c| c.starts_with("cmd-")),
        "not a cgroup of its own below the service: {cgroup}"
    );
    let file = |f: &str| {
        std::fs::read_to_string(Path::new("/sys/fs/cgroup").join(&cgroup[1..]).join(f))
            .unwrap()
            .trim()
            .to_string()
    };
    assert_eq!(file("memory.max"), (64u64 << 20).to_string());
    assert_eq!(file("cpu.max"), "50000 100000");
    assert_eq!(file("pids.max"), "32");
    std::fs::write(work.join("release"), b"").unwrap();
    let r = conn
        .answer(call, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect("the command ran");
    assert_eq!(r["exit_code"], 0, "{r}");

    // Past its memory the kernel kills it, and the result says why.
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": run_with(
                "x=$(head -c 268435456 /dev/zero | tr '\\0' a); echo survived",
                json!({"memory_mb": 64}))}),
            WAIT,
        )
        .await
        .expect("an answer")
        .expect("it ran");
    assert_eq!(r["killed"], "memory", "{r}");
    assert_eq!(
        r["reason"], "the command went past its memory limit of 64 MiB and was killed",
        "{r}"
    );
    assert!(!out(&r).contains("survived"), "{r}");

    // More than the most is refused before anything runs.
    let e = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": run_with(
                "touch ran", json!({"memory_mb": 1 << 20}))}),
            WAIT,
        )
        .await
        .expect("an answer")
        .expect_err("more than the most ran");
    assert!(e.message.contains("16384"), "{}", e.message);
    assert!(!work.join("ran").exists());

    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    std::fs::remove_dir_all(&work).unwrap();
}

/// Two pairings on the installed node each have a home and a temporary
/// folder of their own below `/var/lib/nerve-run` (#167): their commands'
/// `HOME` and `TMPDIR`, made 0700 as `nerve-run`, deleted with the pairing.
/// With Landlock one pairing's command cannot read the other's home;
/// without it it can, as the docs say, and the second pairing, `status` and
/// its JSON say that nothing keeps the pairings apart. With a pairing's
/// network turned off, its commands run under the node's filter, Landlock
/// or not, and open no TCP or UDP socket, which the other pairing's open;
/// no command of its sudo list runs meanwhile, while the other's does.
/// Where the node has no filter its commands do not run, and it says why.
/// For a test machine only, as root.
///
/// `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
/// with a home, the owner> cargo test -p nerve-node --test real_account --
/// --ignored --exact each_pairing_has_a_home_and_temporary_folder_of_its_own_on_this_machine`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL and NERVE_REAL_OWNER name it"]
async fn each_pairing_has_a_home_and_temporary_folder_of_its_own_on_this_machine() {
    let (Some(exe), Some(owner)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
    ) else {
        eprintln!("NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let abi = nerve_sandbox::Confinement::detect().landlock_abi;
    let landlock = abi.is_some();
    let filter = nerve_sandbox::net_filter::available();
    // The owner has a password and sudo, for the sudo list below.
    let mut pw = Command::new("chpasswd");
    pw.stdin(std::process::Stdio::piped());
    let mut child = pw.spawn().unwrap();
    {
        use std::io::Write;
        let line = format!("{owner}:pass-167\n");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
    }
    assert!(child.wait().unwrap().success());
    assert!(sh(Command::new("usermod").args(["-aG", "sudo", &owner])).0);
    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    let (ok, said) = as_owner_typing(&owner, &["setup"], "\n");
    assert!(ok, "{said}");
    let run_home = Path::new("/var/lib/nerve-run");
    // What an earlier version's command left under a center's name: never
    // taken for that pairing's home.
    // First one with no `home` in it (a `mkdir ~/home` of an earlier
    // version), then one with.
    let left = run_home.join("home/home");
    std::fs::create_dir_all(run_home.join("home")).unwrap();
    std::fs::write(run_home.join("home/notes"), "planted\n").unwrap();
    let chown_left = || {
        assert!(
            sh(Command::new("chown")
                .args(["-R", "nerve-run:nerve-run"])
                .arg(run_home.join("home")))
            .0
        );
    };
    chown_left();
    // A folder of the owner's for each center, outside the owner's home.
    let mut links = Vec::new();
    for name in ["lab", "home"] {
        let work = PathBuf::from(format!("/srv/nrv167-{name}"));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        assert!(
            sh(Command::new("chown")
                .arg(format!("{owner}:{owner}"))
                .arg(&work))
            .0
        );
        let mut center = FakeCenter::start(false).await.unwrap();
        let link = center.link().render();
        let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes", "--name", name]);
        assert!(ok, "{said}");
        // The second pairing of nerve-run (a new one is in folder mode) is
        // told that nothing keeps it apart from the first without Landlock.
        assert_eq!(
            said.contains("Warning: Without Landlock nothing keeps the pairings apart"),
            name == "home" && !landlock,
            "{name}: {said}"
        );
        for args in [
            &["mode", "folder", "--center", name][..],
            &[
                "folder",
                "add",
                work.to_str().unwrap(),
                "rwx",
                "--center",
                name,
            ],
        ] {
            let (ok, said) = as_owner(&owner, args);
            assert!(ok, "{args:?}: {said}");
        }
        let paired = center.paired().expect("paired");
        let mut inc = center.next_link(WAIT).await.expect("the node dials");
        fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
            .await
            .expect("handshake");
        links.push((name, work, inc.conn, center));
    }
    // The home pairing's commands do not run until it is gone.
    {
        let (_, work, conn, _) = &mut links[1];
        // A command that names no folder starts in the home that is not
        // there: it says why, not that a path is no directory.
        let e = conn
            .call(
                "invoke",
                json!({"cap": "exec", "action": "run", "args": {"command": "pwd"}}),
                WAIT,
            )
            .await
            .expect("an answer")
            .unwrap_err()
            .message;
        assert!(e.contains("the node did not make it"), "{e}");
        std::fs::create_dir_all(&left).unwrap();
        std::fs::write(left.join(".bashrc"), "planted\n").unwrap();
        chown_left();
        let e = run(conn, work, "echo ran").await.unwrap_err();
        assert!(e.contains("the node did not make it"), "{e}");
        assert!(left.join(".bashrc").exists());
        // Nor do its file calls read what an earlier pairing under its name
        // left in what looks like its home.
        let e = fs_call(
            conn,
            "read",
            json!({"path": left.join(".bashrc").display().to_string()}),
        )
        .await
        .unwrap_err();
        assert!(e.contains("the node did not make it"), "{e}");
    }
    assert!(sh(Command::new("rm").arg("-rf").arg(run_home.join("home"))).0);
    // Each command has its pairing's own home and temporary folder, and
    // leaves a file in each.
    for (name, work, conn, _) in &mut links {
        let r = run(
            conn,
            work,
            "id -un; echo \"$HOME|$TMPDIR|$XDG_CONFIG_HOME\"; pwd; \
             echo mine > \"$HOME/.gitconfig\" && echo t > \"$TMPDIR/t\" && echo made",
        )
        .await
        .unwrap();
        let at = run_home.join(*name);
        assert_eq!(
            out(&r),
            format!(
                "nerve-run\n{h}|{t}|{h}/.config\n{w}\nmade\n",
                h = at.join("home").display(),
                t = at.join("tmp").display(),
                w = work.display()
            ),
            "{name}: {r}"
        );
        for p in [at.clone(), at.join("home"), at.join("tmp")] {
            let (_, st) = sh(Command::new("stat").args(["-c", "%U %a"]).arg(&p));
            assert_eq!(st.trim(), "nerve-run 700", "{}", p.display());
        }
    }
    // Folders found gone are made again before the command, which starts
    // in its home when the call names no folder.
    assert!(sh(Command::new("rm").arg("-rf").arg(run_home.join("lab"))).0);
    let (_, _, conn, _) = &mut links[0];
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": "pwd"}}),
            WAIT,
        )
        .await
        .expect("an answer")
        .expect("it runs");
    assert_eq!(out(&r), "/var/lib/nerve-run/lab/home\n", "{r}");
    std::fs::write(run_home.join("lab/home/.gitconfig"), "mine\n").unwrap();
    // The other pairing's home: closed to it under Landlock, open to it
    // without, as the docs say.
    let lab_config = run_home.join("lab/home/.gitconfig");
    let (_, _, conn, _) = &mut links[1];
    let r = run(
        conn,
        &PathBuf::from("/srv/nrv167-home"),
        &format!("cat {}", lab_config.display()),
    )
    .await
    .unwrap();
    assert_eq!(out(&r) == "mine\n", !landlock, "{r}");
    // Opened to every account (a command of any pairing may change the
    // modes), it stays closed to the other pairing's file calls; the lab's
    // next command closes it again.
    for p in [run_home, &run_home.join("lab"), &run_home.join("lab/home")] {
        assert!(sh(Command::new("chmod").arg("755").arg(p)).0);
    }
    assert!(sh(Command::new("chmod").arg("644").arg(&lab_config)).0);
    let e = fs_call(
        conn,
        "read",
        json!({"path": lab_config.display().to_string()}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("another pairing's"), "{e}");
    // Nor does a walk from a folder open to all go into it.
    let r = fs_call(
        conn,
        "find",
        json!({"path": "/var/lib", "glob": "nerve-run/lab/home/.gitconfig"}),
    )
    .await
    .unwrap();
    assert_eq!(r["paths"], json!([]), "{r}");
    // A folder the owner gives that holds the account's home gives no other
    // pairing's folders: the grant is cut around it.
    let (ok, said) = as_owner(
        &owner,
        &["folder", "add", "/var/lib", "r", "--center", "home"],
    );
    assert!(ok, "{said}");
    let e = fs_call(
        conn,
        "read",
        json!({"path": lab_config.display().to_string()}),
    )
    .await
    .unwrap_err();
    assert!(!e.contains("mine"), "{e}");
    let r = fs_call(
        conn,
        "find",
        json!({"path": "/var/lib", "glob": "nerve-run/lab/home/.gitconfig"}),
    )
    .await
    .unwrap();
    assert_eq!(r["paths"], json!([]), "{r}");
    let (ok, said) = as_owner(&owner, &["folder", "rm", "/var/lib", "--center", "home"]);
    assert!(ok, "{said}");
    let (_, work, conn, _) = &mut links[0];
    run(conn, work, "true").await.unwrap();
    for p in [run_home, &run_home.join("lab"), &run_home.join("lab/home")] {
        let (_, st) = sh(Command::new("stat").args(["-c", "%U %a"]).arg(p));
        assert_eq!(st.trim(), "nerve-run 700", "{}", p.display());
    }
    // Allowlist mode judges a file call by the allow rules alone, and a rule
    // that covers every `fs` call is what an owner writes for a center that
    // may only read. The node opens the paths as the one account that owns
    // every pairing's folders, so they stay closed to the call all the same,
    // whatever the rules say; its own home is open.
    for args in [
        &["mode", "allowlist", "--center", "home"][..],
        &["config", "add", "center.home.policy.allow", "fs"],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{args:?}: {said}");
    }
    let (_, _, conn, _) = &mut links[1];
    let own_config = run_home.join("home/home/.gitconfig");
    let mut seen = Err(String::new());
    for _ in 0..50 {
        seen = fs_call(
            conn,
            "read",
            json!({"path": own_config.display().to_string()}),
        )
        .await;
        if seen.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(seen.unwrap()["content"], "mine\n");
    for (action, args) in [
        ("read", json!({"path": lab_config.display().to_string()})),
        (
            "write",
            json!({"path": run_home.join("lab/home/planted").display().to_string(), "content": "x"}),
        ),
    ] {
        let e = fs_call(conn, action, args).await.unwrap_err();
        assert!(e.contains("another pairing"), "{action}: {e}");
    }
    assert!(!run_home.join("lab/home/planted").exists());
    let r = fs_call(
        conn,
        "find",
        json!({"path": "/var/lib", "glob": "nerve-run/lab/home/.gitconfig"}),
    )
    .await
    .unwrap();
    assert_eq!(r["paths"], json!([]), "{r}");
    let r = fs_call(
        conn,
        "find",
        json!({"path": "/var/lib", "glob": "nerve-run/home/home/.gitconfig"}),
    )
    .await
    .unwrap();
    assert_eq!(r["paths"].as_array().map(Vec::len), Some(1), "{r}");
    for args in [
        &["config", "rm", "center.home.policy.allow", "fs"][..],
        &["mode", "folder", "--center", "home"],
    ] {
        let (ok, said) = as_owner(&owner, args);
        assert!(ok, "{args:?}: {said}");
    }
    // `status` says whether the machine has the filter that holds the
    // switch, and, without Landlock, that nothing keeps the pairings apart.
    let (_, st) = as_owner(&owner, &["--json", "status"]);
    let st: Value = serde_json::from_str(&st).unwrap();
    assert_eq!(st["network_rules"], filter, "{st}");
    assert_eq!(
        st["pairings_warning"]
            .as_str()
            .is_some_and(|w| w.contains("nothing keeps the pairings apart") && w.contains("lab")),
        !landlock,
        "{st}"
    );
    let (_, text) = as_owner(&owner, &["status"]);
    assert_eq!(
        text.contains("warning: Without Landlock nothing keeps the pairings apart"),
        !landlock,
        "{text}"
    );

    // The sudo switch on, and `id -un` on both pairings' sudo lists.
    let (ok, said) = typing(Command::new(BIN).args(["sudo", "on"]), "pass-167\n");
    assert!(ok, "{said}");
    for name in ["lab", "home"] {
        let (ok, said) = as_owner(
            &owner,
            &["rule", "add", "allow", "sudo id -un", "--center", name],
        );
        assert!(ok, "{said}");
    }

    // The lab's network off: held by the node's filter with or without
    // Landlock, so its commands run but open no TCP or UDP socket, which the
    // other pairing's still do, and no command of its sudo list runs. Without
    // the filter none of its commands runs, and the node says why.
    let (ok, said) = as_owner(&owner, &["network", "off", "--center", "lab"]);
    assert!(ok, "{said}");
    assert_eq!(
        said.contains("warning: the owner turned the network off"),
        !filter,
        "{said}"
    );
    let (_, ls) = as_owner(&owner, &["folder", "--center", "lab"]);
    assert!(ls.contains("its commands have no network"), "{ls}");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let tcp = format!("/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' && echo open");
    let send = format!("/bin/bash -c 'exec 3<>/dev/udp/127.0.0.1/{udp_port}' && echo open");
    let opened = |r: &Result<Value, String>| {
        r.as_ref()
            .is_ok_and(|v| out(v) == "open\n" && v["exit_code"] == 0)
    };
    // The node reads the owner's change a moment later.
    let mut first = Err(String::new());
    for _ in 0..50 {
        let (_, work, conn, _) = &mut links[0];
        first = run(conn, work, &tcp).await;
        if !opened(&first) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if filter {
        assert!(first.is_ok() && !opened(&first), "{first:?}");
        let (_, work, conn, _) = &mut links[0];
        let r = run(conn, work, &send).await;
        assert!(r.is_ok() && !opened(&r), "{r:?}");
        let r = run(conn, work, "echo ran").await.unwrap();
        assert_eq!(out(&r), "ran\n");
        let e = run(conn, work, "sudo id -un").await.unwrap_err();
        assert!(
            e.contains("a command on the sudo list runs outside what keeps them off it"),
            "{e}"
        );
    } else {
        let e = first.unwrap_err();
        assert!(
            e.contains("cannot keep them off it") && e.contains("seccomp filters"),
            "{e}"
        );
    }
    let (_, work, conn, _) = &mut links[1];
    for probe in [&tcp, &send] {
        let r = run(conn, work, probe).await;
        assert!(opened(&r), "{probe}: {r:?}");
    }
    let r = run(conn, work, "echo ran").await.unwrap();
    assert_eq!(out(&r), "ran\n");
    let r = run(conn, work, "sudo id -un").await.unwrap();
    assert_eq!(out(&r), "root\n", "{r}");
    drop((listener, udp));

    // The pairing goes, and its folders with what they hold; the other's
    // stay.
    let (ok, said) = as_owner(&owner, &["center", "rm", "home"]);
    assert!(ok, "{said}");
    until("the home pairing's folders go", || {
        !run_home.join("home").exists()
    });
    assert!(run_home.join("lab/home/.gitconfig").exists());

    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    assert!(!run_home.exists());
    for name in ["lab", "home"] {
        let _ = std::fs::remove_dir_all(format!("/srv/nrv167-{name}"));
    }
}
