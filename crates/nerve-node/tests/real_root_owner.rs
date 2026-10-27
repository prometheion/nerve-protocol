//! Root as the owner on a real machine (issue #151): `install` run by root
//! itself makes root the owner only after a yes at a terminal or with
//! `--owner=root --accept-root-owner`; piped input and a no leave the node
//! without one, so `user` mode runs nothing. With root as the owner a
//! `user` mode command, and one of `allowlist` mode as the owner, runs as
//! root; `folder` mode still runs as `nerve-run`. A later install keeps
//! root, `--owner=none` takes it back, and an install that changes the
//! owner (root to none, alice to root) takes nerve-run's entries off the
//! earlier owner's files first, so none stays on them, also after
//! `uninstall` frees its uid. For a test machine only,
//! as root and without sudo: it installs the node as a service and removes
//! it again.
//!
//! `NERVE_NODE_REAL=<the nerve-node to install> cargo test -p nerve-node
//! --test real_root_owner -- --ignored --nocapture`

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(20);
const BIN: &str = "/usr/local/bin/nerve-node";
const UNIT: &str = "/etc/systemd/system/nerve-node.service";

/// `cmd` run as root with `input` on stdin (piped, no terminal), without
/// `SUDO_USER`: as root runs it itself.
fn typing(cmd: &mut Command, input: &str) -> (bool, String) {
    use std::io::Write;
    // The test installs again and again within seconds, faster than
    // systemd's start limit (5 in 10 s) lets a unit start; a person who
    // installs does not.
    let _ = Command::new("systemctl")
        .args(["reset-failed", "nerve-node.service"])
        .stderr(Stdio::null())
        .status();
    let mut child = cmd
        .env_remove("SUDO_USER")
        .env_remove("PKEXEC_UID")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

fn sh(cmd: &mut Command) -> (bool, String) {
    typing(cmd, "")
}

/// The shell line `line` at a terminal (`script` gives it one), answering
/// `answer`; given up after a minute, as a question nobody sees would wait.
fn at_a_terminal(line: &str, answer: &str) -> (bool, String) {
    typing(
        Command::new("timeout").args(["60", "script", "-qec", line, "/dev/null"]),
        answer,
    )
}

/// `install` of `exe` with `args` at a terminal, answering `answer`.
fn install_at_a_terminal(exe: &Path, args: &str, answer: &str) -> (bool, String) {
    at_a_terminal(&format!("{} install {args}", exe.display()), answer)
}

/// The ACL of `path` with numeric ids (`getfacl -n`).
fn acl(path: &Path) -> String {
    let (ok, text) = sh(Command::new("getfacl").args(["-n", "-p"]).arg(path));
    assert!(ok, "{text}");
    text
}

/// Whether `path` has an entry for the uid `uid` (a line of [`id_u`]).
fn has_entry(path: &Path, uid: &str) -> bool {
    acl(path).contains(&format!("user:{}:", uid.trim()))
}

/// `id -u <name>`.
fn id_u(name: &str) -> String {
    let (ok, uid) = sh(Command::new("id").args(["-u", name]));
    assert!(ok, "{uid}");
    uid
}

fn owner_in_unit() -> Option<String> {
    std::fs::read_to_string(UNIT)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Environment=NERVE_NODE_OWNER="))
        .map(String::from)
}

fn status() -> Value {
    let (_, st) = sh(Command::new(BIN).args(["--json", "status"]));
    serde_json::from_str(st.trim()).unwrap_or_else(|e| panic!("{e}: {st}"))
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

fn out(v: &Value) -> String {
    format!(
        "{}{}",
        v["stdout"].as_str().unwrap_or_default(),
        v["stderr"].as_str().unwrap_or_default()
    )
}

/// The running node's link to `center`, once the handshake is through.
/// Each node an install started and stopped meanwhile dialled too: its link
/// waits in the queue, closed, and is passed over.
async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    for _ in 0..20 {
        let mut inc = center.next_link(WAIT).await.expect("the node dials");
        match fake_center::handshake(&mut inc.conn, &center.center_id, &paired).await {
            Ok(_) => return inc.conn,
            Err(e) => eprintln!("passed over a link of a node that stopped: {e:?}"),
        }
    }
    panic!("no link of the running node");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine as root; NERVE_NODE_REAL names it"]
async fn root_is_the_owner_only_when_it_says_so() {
    let Some(exe) = std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from) else {
        eprintln!("NERVE_NODE_REAL is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    assert!(!Path::new(UNIT).exists(), "the node is installed already");
    let question = "Make root the owner of this node? [y/N]";

    // Piped input is no terminal: nothing is asked, and there is no owner.
    let (ok, said) = typing(Command::new(&exe).arg("install"), "y\n");
    assert!(ok, "{said}");
    assert!(!said.contains(question), "{said}");
    assert!(said.contains("Warning: no owner"), "{said}");
    assert!(said.contains("--owner=root --accept-root-owner"), "{said}");
    assert_eq!(owner_in_unit(), None);
    // With --json, or with its output in a file, install asks nothing even
    // at a terminal, and waits for nothing: the answer is no at once, and
    // stderr says which flags make root the owner.
    let no_question =
        "here the answer is no. `--owner=root --accept-root-owner` makes root the owner";
    let started = std::time::Instant::now();
    let (ok, said) = at_a_terminal(&format!("{} --json install", exe.display()), "");
    assert!(ok, "{said}");
    assert!(!said.contains(question), "{said}");
    assert!(said.contains(no_question), "{said}");
    let log = Path::new("/var/tmp/nrv151-install.log");
    let (ok, said) = at_a_terminal(
        &format!("{} install > {}", exe.display(), log.display()),
        "",
    );
    assert!(ok, "{said}");
    assert!(said.contains(no_question), "{said}");
    let logged = std::fs::read_to_string(log).unwrap();
    assert!(!logged.contains(question), "{logged}");
    assert!(logged.contains("Warning: no owner"), "{logged}");
    let _ = std::fs::remove_file(log);
    assert!(started.elapsed() < Duration::from_secs(50), "it waited");
    assert_eq!(owner_in_unit(), None);
    // At a terminal, a no: no owner either, and user mode runs nothing.
    let (ok, said) = install_at_a_terminal(&exe, "", "n\n");
    assert!(ok, "{said}");
    assert!(said.contains(question), "{said}");
    assert!(
        said.contains("nothing in Nerve can hold them back"),
        "{said}"
    );
    assert!(said.contains("Warning: no owner"), "{said}");
    assert_eq!(owner_in_unit(), None);
    assert_eq!(status()["owner_is_root"], false);

    // A center paired by root, in user mode, and a folder of root's.
    let work = Path::new("/srv/nrv151");
    let _ = std::fs::remove_dir_all(work);
    std::fs::create_dir_all(work).unwrap();
    // Root's own file, which only the grant opens to nerve-run.
    let data = work.join("data.txt");
    std::fs::write(&data, "root's data\n").unwrap();
    assert!(sh(Command::new("chmod").arg("600").arg(&data)).0);
    let secret = Path::new("/srv/nrv151-secret");
    std::fs::write(secret, "nobody's\n").unwrap();
    assert!(sh(Command::new("chown").args(["nobody:nogroup"]).arg(secret)).0);
    assert!(sh(Command::new("chmod").arg("600").arg(secret)).0);
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = sh(Command::new(BIN).args(["center", "add", &link, "--yes"]));
    assert!(ok, "{said}");
    let (ok, said) = sh(Command::new(BIN).args(["mode", "set", "user"]));
    assert!(ok, "{said}");
    let mut conn = linked(&mut center).await;
    let e = run(&mut conn, work, "id -u").await.unwrap_err();
    assert!(e.contains("this node has no owner"), "{e}");
    drop(conn);

    // Either flag alone is refused before anything changes.
    let (ok, said) = sh(Command::new(&exe).args(["install", "--owner=root"]));
    assert!(!ok && said.contains("go together"), "{said}");
    assert_eq!(owner_in_unit(), None);

    // At a terminal, a yes: root is the owner, needs no polkit, and status
    // says so.
    let (ok, said) = install_at_a_terminal(&exe, "", "y\n");
    assert!(ok, "{said}");
    assert!(said.contains(question), "{said}");
    assert!(
        said.contains("Warning: root is the owner of the node, as you confirmed"),
        "{said}"
    );
    assert_eq!(owner_in_unit().as_deref(), Some("root"));
    assert!(!Path::new("/etc/polkit-1/rules.d/50-nerve-node.rules").exists());
    assert!(!Path::new("/usr/local/lib/nerve-node/service-control").exists());
    let st = status();
    assert_eq!(st["owner"], "root", "{st}");
    assert_eq!(st["owner_is_root"], true, "{st}");
    let (_, text) = sh(Command::new(BIN).arg("status"));
    assert!(
        text.contains("owner: root is the owner: commands of user mode"),
        "{text}"
    );
    assert!(text.contains("mode user, as root"), "{text}");
    // The settings grant gives a center root here, and says so.
    let warning = "Warning: root is the owner of this node, so";
    let (ok, said) = sh(Command::new(BIN).args(["center", "grant", "settings", "write"]));
    assert!(ok && said.contains(warning), "{said}");
    assert!(sh(Command::new(BIN).args(["center", "grant", "settings", "off"])).0);

    // User mode runs as root, with root's home.
    let mut conn = linked(&mut center).await;
    let r = run(&mut conn, work, "id -u").await.unwrap();
    assert_eq!(out(&r), "0\n", "{r}");
    let r = run(&mut conn, work, "printenv HOME").await.unwrap();
    assert_eq!(out(&r), "/root\n", "{r}");
    // Root as the owner can do what root can, beyond what the node itself
    // may: read another account's private file.
    let r = run(&mut conn, work, &format!("cat {}", secret.display()))
        .await
        .unwrap();
    assert_eq!(out(&r), "nobody's\n", "{r}");

    // Allowlist mode as the owner runs as root too, as nerve-run without.
    assert!(sh(Command::new(BIN).args(["rule", "add", "allow", "id -u"])).0);
    assert!(sh(Command::new(BIN).args(["mode", "set", "allowlist", "--as-owner"])).0);
    let r = run(&mut conn, work, "id -u").await.unwrap();
    assert_eq!(out(&r), "0\n", "{r}");
    assert!(sh(Command::new(BIN).args(["mode", "set", "allowlist"])).0);
    let run_uid = sh(Command::new("id").args(["-u", "nerve-run"])).1;
    let r = run(&mut conn, Path::new("/tmp"), "id -u").await.unwrap();
    assert_eq!(out(&r), run_uid, "{r}");

    // Folder mode runs as nerve-run, in the folder root gives it.
    assert!(sh(Command::new(BIN).args(["mode", "set", "folder"])).0);
    let (ok, said) = sh(Command::new(BIN).args(["folder", "add", "/srv/nrv151", "+rwx"]));
    assert!(ok, "{said}");
    let r = run(&mut conn, work, "id -un").await.unwrap();
    assert_eq!(out(&r), "nerve-run\n", "{r}");
    let r = run(&mut conn, work, "touch made-by-run").await.unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    let r = run(&mut conn, work, &format!("cat {}", secret.display())).await;
    let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
    assert!(!shown.contains("nobody's"), "{shown}");
    let r = run(&mut conn, work, "cat data.txt").await.unwrap();
    assert_eq!(out(&r), "root's data\n", "{r}");
    let run_uid = id_u("nerve-run");
    assert!(has_entry(&data, &run_uid), "{}", acl(&data));
    drop(conn);

    // Without a terminal, the flags keep root the owner, and so does an
    // install without them, at a terminal or not: root confirmed it before,
    // and is not asked again.
    let (ok, said) =
        sh(Command::new(&exe).args(["install", "--owner=root", "--accept-root-owner"]));
    assert!(ok, "{said}");
    assert!(!said.contains(question), "{said}");
    assert_eq!(owner_in_unit().as_deref(), Some("root"));
    let stays = "root stays the owner of the node, as confirmed at an earlier install";
    let (ok, said) = sh(Command::new(&exe).arg("install"));
    assert!(ok, "{said}");
    assert!(said.contains(stays), "{said}");
    let (ok, said) = install_at_a_terminal(&exe, "", "\n");
    assert!(ok, "{said}");
    assert!(!said.contains(question), "{said}");
    assert!(said.contains(stays), "{said}");
    assert_eq!(owner_in_unit().as_deref(), Some("root"));
    // The grant was not touched.
    assert!(has_entry(&data, &run_uid), "{}", acl(&data));

    // A stopped node says root is the owner too.
    assert!(sh(Command::new(BIN).args(["service", "stop"])).0);
    let st = status();
    assert_eq!(st["daemon"], "not running", "{st}");
    assert_eq!(st["owner_is_root"], true, "{st}");
    let (_, text) = sh(Command::new(BIN).arg("status"));
    assert!(
        text.contains("daemon: not running")
            && text.contains("owner: root is the owner: commands of user mode"),
        "{text}"
    );
    assert!(sh(Command::new(BIN).args(["service", "start"])).0);

    // --owner=none takes root back. The owner changes, so nerve-run's
    // entries come off root's files first, and the record goes.
    let (ok, said) = sh(Command::new(&exe).args(["install", "--owner=none"]));
    assert!(ok, "{said}");
    assert!(
        said.contains("root is no longer the owner of the node, as --owner=none says"),
        "{said}"
    );
    assert!(
        said.contains("the owner of the node changes, so took nerve-run's access"),
        "{said}"
    );
    assert!(
        said.contains("without an owner the node gives nerve-run no folders"),
        "{said}"
    );
    assert_eq!(owner_in_unit(), None);
    for p in [work, data.as_path()] {
        assert!(!has_entry(p, &run_uid), "{}", acl(p));
    }
    assert!(!Path::new("/var/lib/nerve/state/acl.json").exists());
    // The review's case: the folder goes, and no folder-mode command of the
    // center reads it any more.
    let (ok, said) = sh(Command::new(BIN).args(["folder", "rm", "/srv/nrv151"]));
    assert!(ok, "{said}");
    let mut conn = linked(&mut center).await;
    let r = run(&mut conn, Path::new("/tmp"), "cat /srv/nrv151/data.txt").await;
    let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
    assert!(!shown.contains("root's data"), "{shown}");
    drop(conn);

    // An owner alice, then root: alice's entries come off before root is
    // the owner, so folder mode still runs, and uninstall leaves no entry
    // of the freed uid on alice's files.
    let alice = "nrv151alice";
    let _ = sh(Command::new("userdel").args(["-r", alice]));
    assert!(sh(Command::new("useradd").args(["-m", alice])).0);
    let proj = PathBuf::from(format!("/home/{alice}/proj"));
    std::fs::create_dir_all(&proj).unwrap();
    let a = proj.join("a.txt");
    std::fs::write(&a, "alice's\n").unwrap();
    assert!(sh(Command::new("chmod").arg("600").arg(&a)).0);
    assert!(
        sh(Command::new("chown")
            .args(["-R", &format!("{alice}:{alice}")])
            .arg(&proj))
        .0
    );
    // As through alice's sudo: typing() takes SUDO_USER away, env puts it
    // back for install alone.
    let (ok, said) = sh(Command::new("env")
        .arg(format!("SUDO_USER={alice}"))
        .arg(&exe)
        .arg("install"));
    assert!(ok, "{said}");
    assert_eq!(owner_in_unit().as_deref(), Some(alice), "{said}");
    let (ok, said) = sh(Command::new(BIN)
        .args(["folder", "add"])
        .arg(&proj)
        .arg("+rwx"));
    assert!(ok, "{said}");
    let mut conn = linked(&mut center).await;
    let r = run(&mut conn, &proj, "cat a.txt").await.unwrap();
    assert_eq!(out(&r), "alice's\n", "{r}");
    drop(conn);
    assert!(has_entry(&a, &run_uid), "{}", acl(&a));
    // On alice's node the settings grant warns of nothing, but root, made
    // the owner, is told that the center has it.
    let (ok, said) = sh(Command::new(BIN).args(["center", "grant", "settings", "write"]));
    assert!(ok && !said.contains(warning), "{said}");
    let (ok, said) =
        sh(Command::new(&exe).args(["install", "--owner=root", "--accept-root-owner"]));
    assert!(ok, "{said}");
    assert!(
        said.contains(
            "has the settings grant already, so with root as the owner it can run commands as root"
        ),
        "{said}"
    );
    assert!(sh(Command::new(BIN).args(["center", "grant", "settings", "off"])).0);
    assert!(
        said.contains("the owner of the node changes, so took nerve-run's access"),
        "{said}"
    );
    assert_eq!(owner_in_unit().as_deref(), Some("root"));
    assert!(!has_entry(&a, &run_uid), "{}", acl(&a));
    let mut conn = linked(&mut center).await;
    let r = run(&mut conn, Path::new("/tmp"), "id -un").await;
    assert_eq!(r.as_ref().map(out).as_deref(), Ok("nerve-run\n"), "{r:?}");
    let r = run(
        &mut conn,
        Path::new("/tmp"),
        &format!("cat {}", a.display()),
    )
    .await;
    let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
    assert!(!shown.contains("alice's"), "{shown}");
    drop(conn);

    // Removed again, with everything it made.
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    assert!(!sh(Command::new("id").arg("nerve-run")).0);
    assert!(!sh(Command::new("id").arg("nerve")).0);
    assert!(!Path::new("/etc/nerve").exists());
    assert!(!Path::new("/var/lib/nerve").exists());
    assert!(!Path::new(UNIT).exists());
    assert!(!has_entry(&a, &run_uid), "{}", acl(&a));
    let _ = std::fs::remove_dir_all(work);
    let _ = std::fs::remove_file(secret);
    let _ = sh(Command::new("userdel").args(["-r", alice]));
}

/// A provider program: it attaches as `rootprov` on the socket its first
/// argument names, prints the node's answer, and serves `files.open` (read;
/// a file's first line), saying the account it ran as.
const PROVIDER_PY: &str = r#"import json, os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
caps = [{"id": "files", "actions": {"open": {"effect": "read", "params": {
    "type": "object", "required": ["path"],
    "properties": {"path": {"type": "string", "x-nerve-path": "read"}}}}}}]
hello = {"method": "hello", "params": {"role": "provider", "name": "rootprov", "capabilities": caps}}
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
    if m.get("method") == "invoke":
        with open(m["params"]["args"]["path"]) as r:
            ok = {"first": r.readline().strip(), "uid": os.getuid()}
        s.sendall((json.dumps({"id": m["id"], "ok": ok}) + "\n").encode())
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

/// `args` started (as `user`, through `runuser`, when one is named), and the
/// first line it printed.
fn started(user: Option<&str>, args: &[&str]) -> (Started, String) {
    let mut c = match user {
        Some(u) => {
            let mut c = Command::new("runuser");
            c.args(["-u", u, "--"]).args(args);
            c
        }
        None => {
            let mut c = Command::new(args[0]);
            c.args(&args[1..]);
            c
        }
    };
    let mut child = c
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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
    (Started(child), rx.recv_timeout(WAIT).expect("a first line"))
}

/// With root as the confirmed owner, root's own program attaches to the
/// installed node on its provider socket (issue #152, B4): the node, which
/// may not look at a process of root's itself, starts its helper as root to
/// tell the program. Another account's program is refused, as it is no
/// owner. A folder of another account the node may not look into refuses
/// a call that hands root's program the folder above it. For a test machine
/// only, as root: it installs the node and removes it again.
///
/// `NERVE_NODE_REAL=<the nerve-node to install> cargo test -p nerve-node
/// --test real_root_owner -- --ignored --exact a_program_of_root_attaches_as_a_provider`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine as root; NERVE_NODE_REAL names it"]
async fn a_program_of_root_attaches_as_a_provider() {
    let Some(exe) = std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from) else {
        eprintln!("NERVE_NODE_REAL is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    assert!(!Path::new(UNIT).exists(), "the node is installed already");
    let python = sh(Command::new("python3").args([
        "-c",
        "import os, sys; print(os.path.realpath(sys.executable))",
    ]))
    .1
    .trim()
    .to_string();
    let (ok, said) =
        sh(Command::new(&exe).args(["install", "--owner=root", "--accept-root-owner"]));
    assert!(ok, "{said}");
    assert_eq!(owner_in_unit().as_deref(), Some("root"));

    let work = Path::new("/srv/nrv152b4");
    let _ = std::fs::remove_dir_all(work);
    std::fs::create_dir_all(work).unwrap();
    let script = work.join("provider.py");
    std::fs::write(&script, PROVIDER_PY).unwrap();
    assert!(sh(Command::new("chmod").args(["755"]).arg(work)).0);
    assert!(sh(Command::new("chmod").args(["644"]).arg(&script)).0);
    // Root's own file, which only root may read.
    let secret = work.join("root-only.txt");
    std::fs::write(&secret, "root-line\n").unwrap();
    assert!(sh(Command::new("chmod").args(["600"]).arg(&secret)).0);

    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = sh(Command::new(BIN).args(["center", "add", &link, "--yes"]));
    assert!(ok, "{said}");
    assert!(sh(Command::new(BIN).args(["mode", "set", "user"])).0);
    let (ok, said) = sh(Command::new(BIN).args(["cap", "provider", "allow", "rootprov", &python]));
    assert!(ok, "{said}");
    let mut conn = linked(&mut center).await;

    let at = "/run/nerve-node/provider.sock";
    let script = script.to_str().unwrap();
    let (c, first) = started(Some("nobody"), &[&python, script, at]);
    assert!(
        first.contains("only the owner of the installed node and root"),
        "{first}"
    );
    drop(c);
    let (provider, first) = started(None, &[&python, script, at]);
    assert!(first.contains("\"ok\""), "{first}");
    let (_, st) = sh(Command::new(BIN).arg("status"));
    assert!(st.contains("provider rootprov attached: files"), "{st}");
    let r = conn
        .call(
            "invoke",
            json!({"cap": "files", "action": "open", "ctx": {},
                   "args": {"path": secret.display().to_string()}}),
            WAIT,
        )
        .await
        .expect("an answer")
        .expect("served");
    assert_eq!(r, json!({"first": "root-line", "uid": 0}));
    // A folder of another account that only it may look into, holding a
    // link to a protected file of root's. The walk runs with root's file
    // ids but the node's rights, so it cannot list the folder; root's
    // program could, and follow the link: handing it the folder above is
    // refused.
    let shut = work.join("shut");
    std::fs::create_dir(&shut).unwrap();
    std::os::unix::fs::symlink("/root/.ssh/id_b4", shut.join("key")).unwrap();
    assert!(
        sh(Command::new("chown")
            .args(["-h", "nobody"])
            .arg(shut.join("key")))
        .0
    );
    assert!(sh(Command::new("chown").arg("nobody").arg(&shut)).0);
    assert!(sh(Command::new("chmod").args(["700"]).arg(&shut)).0);
    let e = conn
        .call(
            "invoke",
            json!({"cap": "files", "action": "open", "ctx": {},
                   "args": {"path": work.display().to_string()}}),
            WAIT,
        )
        .await
        .expect("an answer")
        .expect_err("refused");
    assert!(e.message.contains("may not look into"), "{}", e.message);
    drop(conn);

    drop(provider);
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    std::fs::remove_dir_all(work).unwrap();
}
