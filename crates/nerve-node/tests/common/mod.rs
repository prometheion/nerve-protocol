//! What the node's integration tests share: the handshake of a node's link
//! with the fake center, the CLI run in this process, and an edit of the
//! config as the owner. Each test file takes the parts it needs.
#![allow(dead_code)]

use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::NodePaths;
use nerve_policy::NodeConfig;
use tokio::net::TcpStream;

/// How long a test waits for the node to dial.
pub const WAIT: Duration = Duration::from_secs(15);

/// Accepts the node's link and runs the handshake.
pub async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

/// Runs `nerve-node <args>` on `paths` in this process: its output, or its
/// error.
pub async fn cli(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
    let mut argv: Vec<String> = vec![
        "nerve-node".into(),
        "--config-dir".into(),
        paths.config_dir.display().to_string(),
        "--state-dir".into(),
        paths.state_dir.display().to_string(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    let cli =
        <nerve_node::cli::Cli as clap::Parser>::try_parse_from(argv).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    nerve_node::cli::execute(cli, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

/// Changes the config as the owner does, through the running node.
pub async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}
