//! Moving a node (issue #122): a node paired with a center is backed up while
//! it runs, restored on another machine's folders, and the restored node
//! dials the center with the key the center knows.

use std::path::Path;
use std::time::Duration;

use clap::Parser;
use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;

const WAIT: Duration = Duration::from_secs(15);
const PASS: &str = "correct horse battery\n";

async fn cli(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
    let mut argv: Vec<String> = vec![
        "nerve-node".into(),
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

fn machine(root: &Path, name: &str) -> (NodePaths, NodeOptions) {
    let home = root.join(name);
    std::fs::create_dir_all(&home).unwrap();
    let paths = NodePaths::new(home.join("config"), home.join("state"));
    let mut o = NodeOptions::new(paths.clone());
    o.home = home;
    o.full_rights = Some(false);
    (paths, o)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_moves_to_another_machine_and_the_center_knows_it() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (old, old_opts) = machine(root, "old");
    nerve_node::pair::pair(&old, &center.link(), Some("lab"))
        .await
        .unwrap();
    let pass = root.join("pass");
    nerve_transport::files::write_private(&pass, PASS.as_bytes()).unwrap();
    let pass = pass.to_str().unwrap();
    let file = root.join("node.bak");
    let file_arg = file.to_str().unwrap();

    // Backed up while it runs; a restore on the folders it holds is refused.
    let node = Daemon::start(old_opts).await.unwrap();
    let out = cli(&old, &["backup", file_arg, "--passphrase-file", pass])
        .await
        .unwrap();
    assert!(out.contains("backed up") && out.contains("lab"), "{out}");
    let err = cli(&old, &["restore", file_arg, "--passphrase-file", pass])
        .await
        .unwrap_err();
    assert!(err.contains("runs on these folders"), "{err}");
    node.stop().await;
    // The old node dialled the center while it was backed up, and the center
    // queued that link. Take it away, or `next_link` below would hand it
    // out as the restored node's and the test would not look at the restored
    // node at all.
    while center.next_link(Duration::from_millis(300)).await.is_some() {}

    // The file holds no key in the clear, and only its owner reads it.
    let key = std::fs::read_to_string(old.key_file("lab")).unwrap();
    let bytes = std::fs::read(&file).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(key.trim()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A backup is not overwritten unless asked.
    let err = cli(&old, &["backup", file_arg, "--passphrase-file", pass])
        .await
        .unwrap_err();
    assert!(err.contains("exists already"), "{err}");

    // On the new machine.
    let (new, new_opts) = machine(root, "new");
    let wrong = root.join("wrong");
    nerve_transport::files::write_private(&wrong, b"wrong horse battery\n").unwrap();
    let err = cli(
        &new,
        &[
            "restore",
            file_arg,
            "--passphrase-file",
            wrong.to_str().unwrap(),
        ],
    )
    .await
    .unwrap_err();
    assert!(err.contains("passphrase is wrong"), "{err}");
    assert!(
        !new.config_file().exists(),
        "a wrong passphrase wrote nothing"
    );
    let out = cli(&new, &["restore", file_arg, "--passphrase-file", pass])
        .await
        .unwrap();
    assert!(out.contains("lab") && !out.contains(key.trim()), "{out}");
    assert_eq!(std::fs::read_to_string(new.key_file("lab")).unwrap(), key);
    let (was, now) = (
        NodeConfig::load(&old.config_file()).unwrap(),
        cli(&new, &["config", "get", "center.lab.url"])
            .await
            .unwrap(),
    );
    assert_eq!(now.trim().trim_matches('"'), was.centers[0].url);

    // The address a moved center answers under is changed on the node by
    // name (docs/user/backup.md); the pin and the key stay.
    cli(
        &new,
        &[
            "config",
            "set",
            "center.lab.url",
            "https://moved.example:7443",
        ],
    )
    .await
    .unwrap();
    let moved = cli(&new, &["config", "get", "center.lab.url"])
        .await
        .unwrap();
    assert!(moved.contains("moved.example"), "{moved}");
    cli(
        &new,
        &["config", "set", "center.lab.url", &was.centers[0].url],
    )
    .await
    .unwrap();

    // The restored node dials the center, and the center checks its
    // signature against the key it stored at the pairing.
    let node = Daemon::start(new_opts).await.unwrap();
    let paired = center.paired().expect("paired");
    let mut inc = center
        .next_link(WAIT)
        .await
        .expect("the restored node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("the center accepts the restored node's key");
    drop(inc);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_backup_of_another_node_is_refused_without_replace() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let center_a = FakeCenter::start(false).await.unwrap();
    let center_b = FakeCenter::start(false).await.unwrap();
    let (a, _) = machine(root, "a");
    let (b, _) = machine(root, "b");
    nerve_node::pair::pair(&a, &center_a.link(), Some("one"))
        .await
        .unwrap();
    nerve_node::pair::pair(&b, &center_b.link(), Some("two"))
        .await
        .unwrap();
    let pass = root.join("pass");
    nerve_transport::files::write_private(&pass, PASS.as_bytes()).unwrap();
    let pass = pass.to_str().unwrap();
    let file = root.join("a.bak");
    let file_arg = file.to_str().unwrap();
    cli(&a, &["backup", file_arg, "--passphrase-file", pass])
        .await
        .unwrap();

    let keep = std::fs::read(b.config_file()).unwrap();
    let err = cli(
        &b,
        &[
            "restore",
            file_arg,
            "--secret-storage",
            "cloud",
            "--passphrase-file",
            pass,
        ],
    )
    .await
    .unwrap_err();
    assert!(err.contains("file or keyring"), "{err}");
    let err = cli(&b, &["restore", file_arg, "--passphrase-file", pass])
        .await
        .unwrap_err();
    assert!(
        err.contains("not the same node") && err.contains("--replace"),
        "{err}"
    );
    assert_eq!(std::fs::read(b.config_file()).unwrap(), keep);
    assert!(b.key_file("two").exists() && !b.key_file("one").exists());

    cli(
        &b,
        &["restore", file_arg, "--replace", "--passphrase-file", pass],
    )
    .await
    .unwrap();
    assert!(b.key_file("one").exists() && !b.key_file("two").exists());
    let list = cli(&b, &["center"]).await.unwrap();
    assert!(list.contains("one") && !list.contains("two"), "{list}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_that_is_not_a_node_backup_is_said_so() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = machine(d.path(), "n");
    let pass = d.path().join("pass");
    nerve_transport::files::write_private(&pass, PASS.as_bytes()).unwrap();
    let pass = pass.to_str().unwrap();
    let junk = d.path().join("junk");
    std::fs::write(&junk, b"just some text, long enough to have a header").unwrap();
    let err = cli(
        &paths,
        &["restore", junk.to_str().unwrap(), "--passphrase-file", pass],
    )
    .await
    .unwrap_err();
    assert!(err.contains("not a Nerve backup"), "{err}");
    let err = cli(
        &paths,
        &["restore", "/nonexistent/x.bak", "--passphrase-file", pass],
    )
    .await
    .unwrap_err();
    assert!(err.contains("cannot open"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restore_can_leave_the_proxy_out() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let center = FakeCenter::start(false).await.unwrap();
    let (old, _) = machine(root, "old");
    nerve_node::pair::pair(&old, &center.link(), Some("lab"))
        .await
        .unwrap();
    nerve_node::cli::edit(&old, |c| {
        c.connection.proxy = Some("http://proxy.example:3128".into());
        Ok(())
    })
    .await
    .unwrap();
    let pass = root.join("pass");
    nerve_transport::files::write_private(&pass, PASS.as_bytes()).unwrap();
    let pass = pass.to_str().unwrap();
    let file = root.join("node.bak");
    let file_arg = file.to_str().unwrap();
    cli(&old, &["backup", file_arg, "--passphrase-file", pass])
        .await
        .unwrap();

    // As it is, the proxy comes back with the node.
    let (kept, _) = machine(root, "kept");
    cli(&kept, &["restore", file_arg, "--passphrase-file", pass])
        .await
        .unwrap();
    let got = cli(&kept, &["config", "get", "connection.proxy"])
        .await
        .unwrap();
    assert!(got.contains("proxy.example"), "{got}");

    // With the flag it does not, and the restore says to set it again.
    let (bare, _) = machine(root, "bare");
    let out = cli(
        &bare,
        &[
            "restore",
            file_arg,
            "--without-proxy",
            "--passphrase-file",
            pass,
        ],
    )
    .await
    .unwrap();
    assert!(
        out.contains("proxy is left out") && out.contains("proxy set"),
        "{out}"
    );
    let err = cli(&bare, &["config", "get", "connection.proxy"])
        .await
        .unwrap_err();
    assert!(err.contains("not set"), "{err}");
    // The pairing is there all the same.
    assert!(cli(&bare, &["center"]).await.unwrap().contains("lab"));
}
