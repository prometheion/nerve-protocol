//! The sudo switch end to end: a real node daemon, the conformance fake
//! center and a fake `sudo` (machine.sudo_path) that checks the password on
//! stdin like `sudo -S` does. Linux only: Windows has no sudo program
//! (crate::winsudo, tests/win_sudo.rs).
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::config::{SettingsGrant, Sudo};
use nerve_policy::rules;
use nerve_proto::{ErrorCode, Message, RpcError};
use nerve_transport::log::{Level, Log};
use nerve_transport::sudo::{Offer, Sealed, seal};
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);
const RIGHT: &str = "right-pw-7c1e";
/// A command line with a sudo in the middle; the node runs it without sudo's
/// help, and only an allow rule that names it exactly lets it start.
const CHAINED: &str = "echo a; sudo echo b";

/// Takes `-S -k -p PROMPT` and `-v` like sudo; prints the prompt to stderr,
/// reads the password line from stdin, refuses a wrong one, else runs the
/// command (or just succeeds for `-v`).
const FAKE_SUDO: &str = r#"#!/bin/sh
v=
while [ $# -gt 0 ]; do
  case "$1" in
    -S|-k) shift ;;
    -p) p="$2"; shift 2 ;;
    -v) v=1; shift ;;
    *) break ;;
  esac
done
printf %s "$p" >&2
IFS= read -r pw
if [ "$pw" != "RIGHT" ]; then echo "Sorry, try again." >&2; exit 1; fi
[ -n "$v" ] && exit 0
exec "$@"
"#;

fn fake_sudo(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-sudo");
    std::fs::write(&p, FAKE_SUDO.replace("RIGHT", RIGHT)).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// A node paired with `center` that lets it write settings, with an allow
/// rule for `echo *` (and one line that chains) and a sudo allow entry for
/// `sudo echo *`.
async fn node(root: &Path, center: &FakeCenter) -> Daemon {
    node_with(root, center, |_| Ok(())).await
}

/// [`node`], with `more` changing the config as well.
async fn node_with(
    root: &Path,
    center: &FakeCenter,
    more: impl Fn(&mut nerve_policy::NodeConfig) -> Result<(), String>,
) -> Daemon {
    node_of(root, center, None, more).await
}

/// [`node_with`] for the owner `owner`.
async fn node_of(
    root: &Path,
    center: &FakeCenter,
    owner: Option<&str>,
    more: impl Fn(&mut nerve_policy::NodeConfig) -> Result<(), String>,
) -> Daemon {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.owner = owner.map(String::from);
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    // Its own log, to see that the password stays out of it.
    o.log = Some(Log::new(Level::Debug));
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    let sudo = fake_sudo(root).display().to_string();
    // Through the owner's path: the node refuses a file it did not sign.
    nerve_node::cli::edit(&o.paths, |cfg| {
        cfg.machine.sudo_path = Some(sudo.clone());
        cfg.centers[0].settings = SettingsGrant::Write;
        let policy = &mut cfg.centers[0].policy;
        // The rules count in allowlist mode; a new pairing is in folder mode.
        policy.mode = nerve_policy::Mode::Allowlist;
        policy.sudo_allow.push("sudo echo *".into());
        policy.allow.push("exec.run:echo *".into());
        policy
            .allow
            .push(rules::rule_for("exec", "run", CHAINED, false)?);
        more(cfg)
    })
    .await
    .expect("the owner's edit");
    Daemon::start(o).await.expect("start")
}

async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

/// Every frame the node sends, as text, with the answer to one request.
struct Seen {
    frames: Vec<String>,
}

impl Seen {
    async fn call(
        &mut self,
        conn: &mut Conn<TcpStream>,
        method: &str,
        params: Value,
    ) -> Result<Value, RpcError> {
        let id = conn.request(method, params).await.unwrap();
        let mut others: Vec<Message> = Vec::new();
        let r = conn.answer(id, WAIT, &mut others).await.unwrap();
        self.frames.extend(others.iter().map(Message::encode));
        self.frames.push(match &r {
            Ok(v) => v.to_string(),
            Err(e) => serde_json::to_string(e).unwrap(),
        });
        r
    }

    async fn invoke(
        &mut self,
        conn: &mut Conn<TcpStream>,
        cap: &str,
        action: &str,
        args: Value,
    ) -> Result<Value, RpcError> {
        self.call(
            conn,
            "invoke",
            json!({"cap": cap, "action": action, "args": args}),
        )
        .await
    }

    async fn run(&mut self, conn: &mut Conn<TcpStream>, command: &str) -> Result<Value, RpcError> {
        self.invoke(conn, "exec", "run", json!({"command": command}))
            .await
    }

    async fn sudo_state(&mut self, conn: &mut Conn<TcpStream>) -> String {
        let v = self
            .call(conn, "get", json!({"cap": "settings", "keys": ["sudo"]}))
            .await
            .expect("settings state");
        v["sudo"].as_str().unwrap_or_default().to_string()
    }

    /// A fresh offer, its signature checked against the paired node key.
    async fn offer(&mut self, conn: &mut Conn<TcpStream>, center: &FakeCenter) -> Offer {
        let v = self
            .invoke(conn, "settings", "sudo-offer", json!({}))
            .await
            .expect("sudo-offer");
        let offer = Offer {
            offer: v["offer"].as_str().unwrap().into(),
            key: v["key"].as_str().unwrap().into(),
            ts: v["ts"].as_u64().unwrap(),
        };
        let public = center.paired().unwrap().request.public_key;
        assert!(nerve_transport::keys::verify_sudo_offer(
            &public,
            &center.center_id,
            &offer,
            v["sig"].as_str().unwrap()
        ));
        offer
    }

    async fn on(&mut self, conn: &mut Conn<TcpStream>, sealed: &Sealed) -> Result<Value, RpcError> {
        self.invoke(
            conn,
            "settings",
            "sudo",
            json!({"on": true, "sealed": sealed}),
        )
        .await
    }
}

fn code(r: &Result<Value, RpcError>) -> ErrorCode {
    match r {
        Ok(v) => panic!("succeeded with {v}"),
        Err(e) => e.kind(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sudo_switch() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let mut seen = Seen { frames: Vec::new() };
    seen.call(&mut conn, "sub", json!({"topics": ["audit/decision"]}))
        .await
        .expect("sub");

    // Off: the sudo allow list names the command, yet it is refused.
    assert_eq!(seen.sudo_state(&mut conn).await, "off");
    let r = seen.run(&mut conn, "sudo echo hi").await;
    assert_eq!(code(&r), ErrorCode::Forbidden);
    assert!(r.unwrap_err().message.contains("sudo is off"));

    // A wrong password is refused and the switch stays off.
    let offer = seen.offer(&mut conn, &center).await;
    let r = seen
        .on(&mut conn, &seal(&offer, "wrong", now()).unwrap())
        .await;
    assert_eq!(code(&r), ErrorCode::InvalidArgs);
    assert!(r.unwrap_err().message.contains("password is wrong"));
    assert_eq!(seen.sudo_state(&mut conn).await, "off");
    assert_eq!(node.config().machine.sudo, Sudo::Off);

    // The right one turns it on.
    let offer = seen.offer(&mut conn, &center).await;
    let sealed = seal(&offer, RIGHT, now()).unwrap();
    let r = seen.on(&mut conn, &sealed).await.expect("on");
    assert_eq!(r["sudo"], "on");
    assert_eq!(seen.sudo_state(&mut conn).await, "on");
    assert_eq!(node.config().machine.sudo, Sudo::On);
    // While the switch is on, a line that quotes the password is stripped of
    // it, in the window and in the file.
    let log = node.log().expect("a log").clone();
    log.record(Level::Warn, None, &format!("oops {RIGHT} on stderr"));
    let said = |log: &Log| {
        log.entries(&nerve_transport::log::Query {
            limit: 1,
            ..Default::default()
        })[0]
            .1
            .msg
            .clone()
    };
    assert_eq!(said(&log), "oops [redacted] on stderr");
    // The same box again finds its offer used up.
    let r = seen.on(&mut conn, &sealed).await;
    assert_eq!(code(&r), ErrorCode::InvalidArgs);
    assert!(r.unwrap_err().message.contains("no open sudo offer"));

    // On: what the sudo allow list names runs through sudo, nothing else.
    let r = seen.run(&mut conn, "sudo echo hi").await.expect("allowed");
    assert_eq!(r["stdout"], "hi\n", "{r}");
    assert_eq!(r["exit_code"], 0);
    let r = seen.run(&mut conn, "sudo id").await;
    assert_eq!(code(&r), ErrorCode::Forbidden);
    let r = seen.run(&mut conn, "sudo echo x; id").await;
    assert_eq!(code(&r), ErrorCode::Forbidden);
    // A sudo after the first word gets no password and cannot rise.
    let r = seen.run(&mut conn, CHAINED).await.expect("runs");
    assert_ne!(r["stdout"], "a\nb\n", "{r}");
    // The `echo *` rule is no way to chain a command on.
    let r = seen.run(&mut conn, "echo a; id").await;
    assert_eq!(code(&r), ErrorCode::Forbidden);
    // A normal allow rule does not allow a sudo command.
    let r = seen.run(&mut conn, "sudo id").await;
    assert_eq!(code(&r), ErrorCode::Forbidden);

    // A command that prints the password: the result, the audit event and
    // the local log carry no copy of it.
    let r = seen
        .run(&mut conn, &format!("echo {RIGHT}"))
        .await
        .expect("echo");
    assert_eq!(r["stdout"], "[redacted]\n", "{r}");

    // Off drops the password; a replayed box finds no offer.
    let r = seen
        .invoke(&mut conn, "settings", "sudo", json!({"on": false}))
        .await
        .expect("off");
    assert_eq!(r["sudo"], "off");
    assert_eq!(
        code(&seen.on(&mut conn, &sealed).await),
        ErrorCode::InvalidArgs
    );
    // Off, the node holds no password to keep out of anything.
    log.record(Level::Warn, None, &format!("again {RIGHT}"));
    assert_eq!(said(&log), format!("again {RIGHT}"));
    log.record(Level::Warn, None, "nothing");
    // Not even while a new offer is open.
    let _fresh = seen.offer(&mut conn, &center).await;
    let r = seen.on(&mut conn, &sealed).await;
    assert_eq!(code(&r), ErrorCode::InvalidArgs);
    assert_eq!(seen.sudo_state(&mut conn).await, "off");
    let r = seen.run(&mut conn, "sudo echo hi").await;
    assert_eq!(code(&r), ErrorCode::Forbidden);

    // Let the last audit events arrive.
    seen.call(&mut conn, "get", json!({"cap": "node"}))
        .await
        .unwrap();
    let frames = seen.frames.join("\n");
    assert!(frames.contains("[redacted]"), "{frames}");
    assert!(!frames.contains(RIGHT), "{frames}");
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    assert!(log.contains("[redacted]"), "{log}");
    assert!(!log.contains(RIGHT), "{log}");
    let file = std::fs::read_to_string(node.paths().config_file()).unwrap();
    assert!(!file.contains(RIGHT));
    // The log file saw the password only in the line that was stripped of it,
    // and the one after the switch went off.
    let written = std::fs::read_to_string(node.paths().log_file()).unwrap();
    assert!(written.contains("oops [redacted] on stderr"), "{written}");
    assert_eq!(written.matches(RIGHT).count(), 1, "{written}");

    node.stop().await;
}

/// A command's output stream is scrubbed of the password like its result,
/// also a copy two reads cut; a sudo command's output is not streamed at
/// all (protocol §7.3).
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_carries_no_password_and_a_sudo_command_none() {
    use nerve_conformance::wire::Recv;

    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (head, rest) = RIGHT.split_at(6);
    let prints = format!("printf 'a {head}'; sleep 0.6; printf '{rest} b\\n'; sleep 0.3");
    let node = node_with(dir.path(), &center, |cfg| {
        let rule = rules::rule_for("exec", "run", &prints, false)?;
        cfg.centers[0].policy.allow.push(rule);
        cfg.centers[0].policy.sudo_allow.push("sudo sleep *".into());
        Ok(())
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut seen = Seen { frames: Vec::new() };
    let offer = seen.offer(&mut conn, &center).await;
    seen.on(&mut conn, &seal(&offer, RIGHT, now()).unwrap())
        .await
        .expect("on");
    let output = |call: u64| json!({"cap": "exec", "stream": "output", "params": {"call": call}});

    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": prints}}),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sid = conn
        .call("stream.open", output(run), WAIT)
        .await
        .unwrap()
        .expect("opened")["sid"]
        .as_u64()
        .unwrap();
    let mut data: Vec<u8> = conn
        .take_frames()
        .into_iter()
        .flat_map(|f| f.payload)
        .collect();
    let (mut closed, mut ran) = (false, None);
    while !closed || ran.is_none() {
        match conn.recv(WAIT).await {
            Recv::Frame(f) => {
                assert_eq!(u64::from(f.id), sid);
                data.extend(f.payload);
            }
            Recv::Msg(Message::Request { id, method, .. }) if method == "stream.close" => {
                conn.send(&Message::result(id, json!({}))).await.unwrap();
                closed = true;
            }
            Recv::Msg(Message::Result { id, result }) if id == nerve_proto::Id::Num(run) => {
                ran = Some(result)
            }
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(String::from_utf8(data).unwrap(), "a [redacted] b\n");
    assert_eq!(ran.unwrap()["stdout"], "a [redacted] b\n");

    let sudo = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": "sudo sleep 1"}}),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let e = conn
        .call("stream.open", output(sudo), WAIT)
        .await
        .unwrap()
        .expect_err("a sudo command's output is not streamed");
    assert_eq!(e.kind(), ErrorCode::Unavailable, "{e:?}");
    let mut others = Vec::new();
    let r = conn
        .answer(sudo, WAIT, &mut others)
        .await
        .unwrap()
        .expect("ran");
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(conn.take_frames().is_empty());
    node.stop().await;
}

/// With root as the owner `sudo -v` checks no password, so no center turns
/// the switch on, with any password (#151).
#[tokio::test(flavor = "multi_thread")]
async fn no_center_turns_sudo_on_while_root_is_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = node_of(dir.path(), &center, Some("root"), |_| Ok(())).await;
    let mut conn = linked(&mut center).await;
    let mut seen = Seen { frames: Vec::new() };
    let offer = seen.offer(&mut conn, &center).await;
    let r = seen
        .on(&mut conn, &seal(&offer, RIGHT, now()).unwrap())
        .await;
    assert_eq!(code(&r), ErrorCode::Forbidden);
    let e = r.unwrap_err().message;
    assert!(e.contains("root is the owner of this node"), "{e}");
    assert!(e.contains("nerve-node sudo on"), "{e}");
    assert_eq!(seen.sudo_state(&mut conn).await, "off");
    assert_eq!(node.config().machine.sudo, Sudo::Off);
    node.stop().await;
}

/// A result kept while the link was down is scrubbed of the password held
/// when it was made: turning sudo off before the link resumes does not let
/// the password out in the replay (protocol §4.9).
#[tokio::test(flavor = "multi_thread")]
async fn a_result_kept_for_a_resume_carries_no_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    let waits =
        format!("touch started; while [ ! -e go ]; do sleep 0.05; done; echo {RIGHT}; touch done");
    let node = node_with(dir.path(), &center, |cfg| {
        let rule = rules::rule_for("exec", "run", &waits, false)?;
        cfg.centers[0].policy.allow.push(rule);
        Ok(())
    })
    .await;
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    let hello = fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    let offer = hello.resume.expect("a resume offer");
    let fresh = nerve_proto::msg::Resumed {
        resumed: false,
        got: 0,
    };
    fake_center::welcome(&mut inc.conn, Some(fresh))
        .await
        .expect("welcome");
    let mut conn = inc.conn;
    let mut seen = Seen { frames: Vec::new() };
    let offer_box = seen.offer(&mut conn, &center).await;
    let sealed = seal(&offer_box, RIGHT, now()).unwrap();
    seen.on(&mut conn, &sealed).await.expect("on");

    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": waits}}),
        )
        .await
        .unwrap();
    let exists = |f: &str| {
        let p = home.join(f);
        async move {
            for _ in 0..200 {
                if p.exists() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            false
        }
    };
    assert!(exists("started").await, "the command did not start");
    // The frames the center read, `ack` aside.
    let read = seen
        .frames
        .iter()
        .filter(|f| !f.contains("\"method\":\"ack\""))
        .count() as u64;
    drop(conn);
    std::fs::write(home.join("go"), "").unwrap();
    assert!(exists("done").await, "the command did not finish");
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Sudo goes off while the result waits for the resume.
    nerve_transport::ctl::call(&node.paths().ctl_socket(), "sudo.off", json!({}))
        .await
        .expect("sudo off");

    let mut inc = center.next_link(WAIT).await.expect("the node dials again");
    let hello = fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    assert_eq!(hello.resume.as_ref().map(|r| &r.link), Some(&offer.link));
    let again = nerve_proto::msg::Resumed {
        resumed: true,
        got: read,
    };
    fake_center::welcome(&mut inc.conn, Some(again))
        .await
        .expect("welcome");
    let mut conn = inc.conn;
    let mut others = Vec::new();
    let r = conn
        .answer(run, WAIT, &mut others)
        .await
        .unwrap()
        .expect("the command's result");
    assert_eq!(r["stdout"], "[redacted]\n", "{r}");
    let replayed: Vec<String> = others.iter().map(Message::encode).collect();
    assert!(!replayed.join("\n").contains(RIGHT), "{replayed:?}");
    node.stop().await;
}

/// A restarted node holds no password, so a file that says on starts off.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_turns_sudo_off() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let node = node(dir.path(), &center).await;
    let paths = node.paths().clone();
    node.stop().await;
    // The owner's path may write `on`; the password is still not there.
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.machine.sudo = Sudo::On;
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let mut o = NodeOptions::new(paths.clone());
    o.home = dir.path().join("home");
    let node = Daemon::start(o).await.expect("start");
    assert_eq!(node.config().machine.sudo, Sudo::Off);
    assert_eq!(node.status()["sudo"], "off");
    node.stop().await;
}
