//! The limits per command on the installed Windows service (#177), end to
//! end: the conformance fake center pairs with the service, and a command
//! that asks for more memory than its limit is ended by its job, with
//! `killed: "memory"` in its result; `status` says the job objects hold the
//! limits. It needs a Windows test machine: the node installed as a service
//! with an account for commands, and an elevated terminal (CI's
//! `windows-installed` job):
//!
//! ```text
//! cargo test -p nerve-node --test win_limits -- --ignored
//! ```
//!
//! It pairs the service with a center named `winlimits` and removes it again.
#![cfg(windows)]

use std::process::Command;
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::edition::{DESKTOP_PROGRAM, Edition};
use nerve_node::service::Layout;
use nerve_policy::rules;
use nerve_proto::RpcError;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(60);
const CENTER: &str = "winlimits";
/// PowerShell asks for 1 GiB at once: past the limit set below.
const BIG: &str = "$a = [byte[]]::new(1GB); 'took ' + $a.Length";
/// The desktop app, whose program is the node's on Windows (#176): the
/// install puts it where its `Layout` says.
static APP: Edition = Edition {
    program: DESKTOP_PROGRAM,
    parts: None,
};

async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

async fn run(conn: &mut Conn<TcpStream>, command: &str) -> Result<Value, RpcError> {
    let id = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": command, "timeout_ms": 120_000}}),
        )
        .await
        .unwrap();
    conn.answer(id, Duration::from_secs(150), &mut Vec::new())
        .await
        .unwrap()
}

/// What the installed program's `status` says, as the app asks it.
fn status(layout: &Layout) -> Value {
    let o = Command::new(&layout.bin)
        .args(["--json", "status"])
        .output()
        .unwrap();
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {o:?}"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the node installed as a service on a Windows test machine"]
async fn the_installed_service_holds_a_command_to_its_memory_limit() {
    let layout = Layout::of(&APP);
    let paths = layout.paths.clone();
    let st = status(&layout);
    let limits = &st["command_limits"];
    assert_eq!(
        limits["enforced"],
        json!(["memory", "cpu", "processes"]),
        "{st}"
    );
    assert_eq!(limits["off"], Value::Null, "{st}");
    let mut center = FakeCenter::start(false).await.unwrap();
    // What an earlier run paired goes first.
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.centers.retain(|c| c.name != CENTER);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let _ = std::fs::remove_file(paths.key_file(CENTER));
    nerve_node::pair::pair(&paths, &center.link(), Some(CENTER))
        .await
        .expect("pair");
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.limits.command.memory_mb = 400;
        let e = cfg.center_mut(CENTER).expect("paired");
        // A new pairing starts in folder mode, whose commands run only in a
        // folder with `x` and where allow rules do not count: this command
        // runs by its allow rule.
        e.policy.mode = nerve_policy::Mode::Allowlist;
        e.policy.allow = vec![rules::rule_for("exec", "run", BIG, false, None)?];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let mut conn = linked(&mut center).await;

    let r = run(&mut conn, BIG).await.expect("the command runs");
    // Back as they were, whatever the result.
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.limits.command = Default::default();
        cfg.centers.retain(|c| c.name != CENTER);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let _ = std::fs::remove_file(paths.key_file(CENTER));
    assert_eq!(r["killed"], "memory", "{r}");
    assert_eq!(
        r["reason"], "the command went past its memory limit of 400 MiB and was killed",
        "{r}"
    );
    assert!(
        !r["stdout"].as_str().unwrap_or_default().contains("took"),
        "{r}"
    );
}
