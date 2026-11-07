//! `config accept` with a node running: the node takes the file itself, on
//! Windows over its control pipe as on Unix over its socket. A CLI that
//! signed the file behind the running node would put it ahead of the node,
//! which then refuses every change until it restarts.

mod common;

use std::path::Path;

use common::cli;
use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;

fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    // Not the rights of whoever runs the tests: an elevated run must pass.
    o.full_rights = Some(false);
    // NERVE_NODE_BIN lets the built tests run on another machine.
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    o
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_node_takes_the_file_the_owner_edited() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let node = Daemon::start(o.clone()).await.unwrap();
    let file = o.paths.config_file();
    let was = node.config().limits.max_running;
    // A change by hand, as a text editor makes it: plain TOML, no MAC.
    let mut edited = NodeConfig::load(&file).unwrap();
    edited.limits.max_running = was + 1;
    edited.save(&file).unwrap();

    let said = cli(&o.paths, &["config", "accept"]).await.unwrap();
    assert!(said.contains("accepted node.toml as version"), "{said}");
    // The running node has it now, and the file is the node's own version:
    // not ahead of it.
    assert_eq!(node.config().limits.max_running, was + 1, "{said}");
    assert_eq!(
        NodeConfig::load(&file).unwrap().version,
        node.config().version,
        "{said}"
    );
    // So a change made after goes through, with no restart.
    cli(&o.paths, &["config", "set", "limits.max_running", "9"])
        .await
        .unwrap();
    assert_eq!(node.config().limits.max_running, 9);
    node.stop().await;
}
