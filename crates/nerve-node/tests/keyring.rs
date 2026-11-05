//! The node's keys in the real system keyring (Credential Manager on
//! Windows, the Secret Service on Linux): what the unit tests do with an
//! in-memory keyring, once against the machine's own. It writes entries
//! there and deletes them again, so it runs only when asked:
//!
//! `cargo test -p nerve-node --test keyring -- --ignored`

use clap::Parser;
use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;

async fn run(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
    let mut argv = vec![
        "nerve-node".to_string(),
        "--config-dir".into(),
        paths.config_dir.display().to_string(),
        "--state-dir".into(),
        paths.state_dir.display().to_string(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    let cli = nerve_node::cli::Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    nerve_node::cli::execute(cli, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

/// The node's entries, as the keyring names them.
fn accounts(paths: &NodePaths, center: &str) -> [String; 2] {
    [
        format!("config-key:{}", paths.state_dir.display()),
        format!("center-key:{center}:{}", paths.config_dir.display()),
    ]
}

fn in_keyring(account: &str) -> bool {
    match keyring::Entry::new("nerve", account)
        .unwrap()
        .get_password()
    {
        Ok(_) => true,
        Err(keyring::Error::NoEntry) => false,
        Err(e) => panic!("the keyring: {e}"),
    }
}

/// Deletes what the test left in the keyring, however it ended.
struct Cleanup(Vec<String>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for a in &self.0 {
            if let Ok(e) = keyring::Entry::new("nerve", a) {
                let _ = e.delete_credential();
            }
        }
    }
}

async fn start(paths: &NodePaths, home: &std::path::Path) -> Daemon {
    let mut o = NodeOptions::new(paths.clone());
    o.home = home.to_path_buf();
    o.full_rights = Some(false);
    Daemon::start(o).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes to the system keyring"]
async fn the_keys_move_into_the_system_keyring_and_back() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().to_path_buf();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let _cleanup = Cleanup(accounts(&paths, "lab").into());
    NodeConfig::default().save(&paths.config_file()).unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    run(&paths, &["center", "add", &link, "--name", "lab", "--yes"])
        .await
        .unwrap();
    assert!(paths.config_key().is_file() && paths.key_file("lab").is_file());
    let [config_key, center_key] = accounts(&paths, "lab");
    assert!(!in_keyring(&config_key) && !in_keyring(&center_key));

    // Into the keyring while no node runs: copied and read back, then the
    // files go.
    run(
        &paths,
        &["config", "set", "machine.secret_storage", "keyring"],
    )
    .await
    .unwrap();
    assert!(in_keyring(&config_key) && in_keyring(&center_key));
    assert!(!paths.config_key().exists() && !paths.key_file("lab").exists());
    assert!(!paths.keys_moving().exists());
    // The node reads its config with the key from the keyring.
    let status = run(&paths, &["status"]).await.unwrap();
    assert!(status.contains("lab"), "{status}");

    // A new key for the center (pairing again) replaces the entry, and
    // removing the center deletes it.
    run(&paths, &["center", "rm", "--center", "lab"])
        .await
        .unwrap();
    assert!(!in_keyring(&center_key));
    let center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    run(&paths, &["center", "add", &link, "--name", "lab", "--yes"])
        .await
        .unwrap();
    assert!(in_keyring(&center_key) && !paths.key_file("lab").exists());

    // And back to files while the node runs and reads them from the
    // keyring. On Linux the running node moves them; on Windows, which
    // cannot ask it, the CLI leaves it the keyring's copies until its next
    // start.
    let node = start(&paths, &root).await;
    run(&paths, &["config", "set", "machine.secret_storage", "file"])
        .await
        .unwrap();
    assert!(paths.config_key().is_file() && paths.key_file("lab").is_file());
    assert_eq!(in_keyring(&config_key), cfg!(windows));
    node.stop().await;
    start(&paths, &root).await.stop().await;
    assert!(!in_keyring(&config_key) && !in_keyring(&center_key));
    assert!(!paths.keys_moving().exists());
    run(&paths, &["status"]).await.unwrap();
}
