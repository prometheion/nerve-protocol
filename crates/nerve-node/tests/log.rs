//! The node's log file: what a running daemon writes in its state folder, at
//! the level `node.toml` sets. This file holds one test, since the log it
//! reads is the process's.

mod common;

use std::time::Duration;

use common::linked;
use nerve_conformance::fake_center::FakeCenter;
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_transport::log::{Entry, Level, Query};
use serde_json::json;
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

/// The call's error code, or `ok`.
async fn invoke(conn: &mut Conn<TcpStream>, action: &str, args: serde_json::Value) -> String {
    match conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": action, "args": args}),
            WAIT,
        )
        .await
        .unwrap()
    {
        Ok(_) => "ok".into(),
        Err(e) => nerve_conformance::wire::code_of(&e).to_string(),
    }
}

/// Every entry in the process's log, oldest first.
fn entries(log: &nerve_transport::log::Log) -> Vec<Entry> {
    let q = Query {
        limit: usize::MAX,
        ..Query::default()
    };
    log.entries(&q).into_iter().rev().map(|(_, e)| e).collect()
}

fn has(log: &nerve_transport::log::Log, level: Level, part: &str) -> bool {
    entries(log)
        .iter()
        .any(|e| e.level == level && e.msg.contains(part))
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_logs_its_links_changes_and_failed_calls() {
    // As `nerve-node` does at start: one log for the process, which the daemon
    // gives its file and its level.
    let log = nerve_transport::log::install(Level::Info, false);
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut o = NodeOptions::new(NodePaths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    o.home = std::fs::canonicalize(dir.path()).unwrap().join("home");
    // Not the rights of whoever runs the tests: an elevated run must pass.
    o.full_rights = Some(false);
    std::fs::create_dir_all(&o.home).unwrap();
    let home = nerve_policy::paths::to_wire(&o.home);
    let paths = o.paths.clone();
    nerve_node::pair::pair(&paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    let rule = format!("fs.read:{home}/*");
    nerve_node::cli::edit(&paths, |c| {
        // The rule counts in allowlist mode; a new pairing is in folder mode.
        c.centers[0].policy.mode = nerve_policy::Mode::Allowlist;
        c.centers[0].policy.allow.push(rule.clone());
        Ok(())
    })
    .await
    .unwrap();
    let existing = o.home.join("here.txt");
    std::fs::write(&existing, "x").unwrap();
    let existing = nerve_policy::paths::to_wire(&existing);
    let missing = format!("{home}/not-here.txt");

    let node = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    until("the link", || {
        has(&log, Level::Info, "linked to center lab")
    })
    .await;
    assert!(has(&log, Level::Info, "node daemon running (nerve-node "));

    // Calls: a refusal and a failure are told with their reason; one that
    // worked is not, it is in the audit log.
    assert_eq!(
        invoke(&mut conn, "read", json!({"path": existing})).await,
        "ok"
    );
    assert_eq!(
        invoke(
            &mut conn,
            "write",
            json!({"path": existing, "content": "y"})
        )
        .await,
        "forbidden"
    );
    let failed = invoke(&mut conn, "read", json!({"path": missing})).await;
    assert_ne!(failed, "ok");
    until("the calls", || has(&log, Level::Info, "fs.read failed")).await;
    assert!(has(
        &log,
        Level::Info,
        "center lab: fs.write was refused (forbidden): "
    ));
    let reads = entries(&log)
        .iter()
        .filter(|e| e.msg.contains("fs.read"))
        .count();
    assert_eq!(reads, 1, "{:?}", entries(&log));

    // The owner changes a rule while the node runs: who, what, which version.
    nerve_node::cli::edit(&paths, |c| {
        c.centers[0].policy.allow.push("fs.read:/srv/data/*".into());
        Ok(())
    })
    .await
    .unwrap();
    until("the change", || {
        has(
            &log,
            Level::Info,
            "settings changed by local (version 3): center.lab.policy.allow +fs.read:/srv/data/*",
        )
    })
    .await;

    // The level is a setting. Debug adds detail, from the next second on.
    nerve_node::cli::edit(&paths, |c| {
        c.log.level = Level::Debug;
        Ok(())
    })
    .await
    .unwrap();
    until("debug", || log.level() == Level::Debug).await;
    assert!(has(&log, Level::Info, "log.level: info -> debug"));

    // The link drops: told, with the wait before the node dials again, and
    // the dial that follows as detail.
    drop(conn);
    until("the drop", || {
        has(
            &log,
            Level::Warn,
            "center lab: the link closed without a bye",
        )
    })
    .await;
    until("the wait", || {
        has(&log, Level::Info, "center lab: dialling again in ")
    })
    .await;
    let mut conn = linked(&mut center).await;
    until("the second link", || {
        entries(&log)
            .iter()
            .filter(|e| e.msg == "linked to center lab")
            .count()
            == 2
    })
    .await;
    assert!(has(&log, Level::Debug, "center lab: dialling http://"));

    // A lower level keeps the lines below it out.
    nerve_node::cli::edit(&paths, |c| {
        c.log.level = Level::Error;
        Ok(())
    })
    .await
    .unwrap();
    until("error", || log.level() == Level::Error).await;
    let before = entries(&log).len();
    assert_eq!(
        invoke(
            &mut conn,
            "write",
            json!({"path": existing, "content": "z"})
        )
        .await,
        "forbidden"
    );
    assert_eq!(
        invoke(&mut conn, "read", json!({"path": existing})).await,
        "ok"
    );
    assert_eq!(entries(&log).len(), before);
    nerve_node::cli::edit(&paths, |c| {
        c.log.level = Level::Info;
        Ok(())
    })
    .await
    .unwrap();
    until("info", || log.level() == Level::Info).await;

    node.stop().await;

    // The file holds all of it, one JSON line each, oldest first, apart from
    // the audit log, whose decisions are not in it.
    let text = std::fs::read_to_string(paths.log_file()).unwrap();
    let file: Vec<Entry> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let msgs: Vec<&str> = file.iter().map(|e| e.msg.as_str()).collect();
    assert!(
        msgs[0].starts_with("node daemon running (nerve-node "),
        "{msgs:?}"
    );
    assert_eq!(*msgs.last().unwrap(), "node daemon stopped", "{msgs:?}");
    assert!(msgs.contains(&"node daemon stopping"));
    let at = |part: &str| {
        msgs.iter()
            .position(|m| m.contains(part))
            .unwrap_or_else(|| panic!("{part}: {msgs:?}"))
    };
    assert!(at("linked to center lab") < at("fs.write was refused"));
    assert!(at("fs.write was refused") < at("the link closed without a bye"));
    assert!(at("the link closed without a bye") < at("dialling again in"));
    assert_ne!(paths.log_file(), paths.audit_log());
    let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
    assert!(audit.contains("\"allowed\"") && !text.contains("\"allowed\""));
}
