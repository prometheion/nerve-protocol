//! `nerve-node setup` pairs the node with its first center and sets that
//! center's mode, through a running node as through the file (issue #21).

#![cfg(unix)]

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::{Mode, SettingsStore};

fn paths(root: &std::path::Path) -> NodePaths {
    NodePaths::new(root.join("config"), root.join("state"))
}

async fn setup(paths: &NodePaths, answers: &str) -> Result<String, String> {
    let mut out = Vec::new();
    let mut input = std::io::Cursor::new(answers.as_bytes().to_vec());
    let keyring = nerve_node::keyring_setup::HostKeyring::this_program();
    nerve_node::cli::setup(paths, None, &keyring, &mut input, true, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

#[tokio::test]
async fn setup_pairs_the_first_center_and_sets_its_mode() {
    let d = tempfile::tempdir().unwrap();
    let paths = paths(d.path());
    let center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let out = setup(&paths, &format!("{link}\ny\nuser\n\n"))
        .await
        .unwrap();
    assert!(out.contains("paired with"), "{out}");
    assert!(center.paired().is_some());
    let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
    assert_eq!(cfg.node.name, None, "the name stays the host name");
    assert_eq!(cfg.centers.len(), 1);
    assert_eq!(cfg.centers[0].policy.mode, Mode::User);
    assert!(paths.key_file(&cfg.centers[0].name).is_file());
}

/// With the node running, setup's changes reach it at once; a "no" to the
/// pairing pairs nothing.
#[tokio::test]
async fn setup_goes_through_the_running_node() {
    let d = tempfile::tempdir().unwrap();
    let paths = paths(d.path());
    let mut o = NodeOptions::new(paths.clone());
    o.home = d.path().to_path_buf();
    let daemon = Daemon::start(o).await.unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let out = setup(&paths, &format!("{link}\nn\n")).await.unwrap();
    assert!(out.contains("not paired"), "{out}");
    assert!(center.paired().is_none());
    assert!(daemon.config().centers.is_empty());
    daemon.stop().await;
}
