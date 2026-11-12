//! What the node's integration tests share: the handshake of a node's link
//! with the fake center, the CLI run in this process, an edit of the config
//! as the owner, and Windows' wide strings. Each test file takes the parts it
//! needs.
#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use tokio::net::TcpStream;

/// A node run by hand in `root`: its config, state and home folders there,
/// not the rights of whoever runs the tests (an elevated run must pass), and
/// this build's program, or the one `NERVE_NODE_BIN` names, which lets the
/// built tests run on another machine.
pub fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    o
}

/// How long a test waits for the node to dial.
pub const WAIT: Duration = Duration::from_secs(15);

/// Accepts the node's link and runs the handshake.
pub async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    linked_within(center, WAIT).await
}

/// [`linked`] for a node that may take `wait` to dial (an installed one).
pub async fn linked_within(center: &mut FakeCenter, wait: Duration) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(wait).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

/// The first link of the node's that completes the handshake. A link a node
/// opened before it stopped (a restart, an install that started and stopped
/// one) may still wait in the queue, closed before its hello: it is passed
/// over. The node has `wait` to dial.
pub async fn linked_skipping_ended(center: &mut FakeCenter, wait: Duration) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let until = tokio::time::Instant::now() + wait;
    let mut ended = Vec::new();
    while let Some(mut inc) = center
        .next_link(until.saturating_duration_since(tokio::time::Instant::now()))
        .await
    {
        match fake_center::handshake(&mut inc.conn, &center.center_id, &paired).await {
            Ok(_) => return inc.conn,
            Err(e) => ended.push(e),
        }
    }
    panic!("no link of the node completed the handshake; those that ended: {ended:?}");
}

/// `s` as Windows takes a text: UTF-16 with a closing NUL.
#[cfg(windows)]
pub fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_ref().encode_wide().chain(Some(0)).collect()
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
