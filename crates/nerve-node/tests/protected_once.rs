//! A call builds the protected list once (issue #193): its gate, the walk of
//! an `fs` call and the Landlock rules of a command go by the same list.
//! Each build resolves every entry, hundreds of `lstat`s.
//!
//! A test binary of its own with one test, since it counts every build of
//! the process.

#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{linked, owner_edit};
use nerve_conformance::fake_center::FakeCenter;
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::config::{Access, Folder};
use nerve_policy::protected::built;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

/// A node paired with `center` in folder mode with `work` as its folder.
async fn node(root: &Path, work: &Path, center: &FakeCenter) -> Daemon {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    let folder = work.display().to_string();
    owner_edit(&o.paths, |c| {
        c.centers[0].policy.folders = vec![Folder {
            path: folder.clone(),
            access: Access::ALL,
        }];
    })
    .await;
    Daemon::start(o).await.expect("start")
}

/// How many lists one call of `cap.action` built.
async fn builds(conn: &mut Conn<TcpStream>, cap: &str, action: &str, args: Value) -> u64 {
    let before = built();
    conn.call(
        "invoke",
        json!({"cap": cap, "action": action, "args": args}),
        WAIT,
    )
    .await
    .unwrap()
    .unwrap_or_else(|e| panic!("{cap}.{action}: {e:?}"));
    built() - before
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_builds_the_protected_list_once() {
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(work.join("sub")).unwrap();
    std::fs::write(work.join("sub/a.txt"), "hello").unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(&root, &work, &center).await;
    let mut conn = linked(&mut center).await;
    conn.call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let path = nerve_policy::paths::to_wire(&work);
    // The gate and the walk of a listing.
    assert_eq!(
        builds(&mut conn, "fs", "list", json!({"path": path})).await,
        1
    );
    let file = nerve_policy::paths::to_wire(&work.join("sub/a.txt"));
    assert_eq!(
        builds(&mut conn, "fs", "read", json!({"path": file})).await,
        1
    );
    // The gate and the command's Landlock rules, where Landlock is.
    let abi = nerve_sandbox::Confinement::detect().landlock_abi;
    if abi.is_some_and(|v| v >= nerve_sandbox::LANDLOCK_FLOOR) {
        assert_eq!(
            builds(
                &mut conn,
                "exec",
                "run",
                json!({"command": "echo hi", "cwd": path})
            )
            .await,
            1
        );
    } else {
        eprintln!("the command part is skipped: no Landlock here");
    }
    daemon.stop().await;
}
