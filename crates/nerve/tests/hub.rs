//! The center role's pages ask a real center over its local owner channel,
//! as its CLI does, with its web UI off: the owner token checked at the
//! log-in and given with each call, a wrong token refused, a new owner
//! token ending the log-in.

use std::sync::Arc;

use nerve::hub::{Failed, Holder, Hub, Peer};
use nerve_center::config::Args;
use nerve_center::server::{self, Running};

/// A center of its own under `dir`, its web UI off and its owner endpoint
/// at [`endpoint`], on a runtime that outlives the test's calls.
fn center(dir: &std::path::Path) -> (tokio::runtime::Runtime, Running) {
    nerve_transport::init_crypto();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let argv = [
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--plain-loopback",
        "--mcp",
        "off",
        "--ui",
        "off",
    ];
    let mut args = Args::from_argv(argv).unwrap();
    args.owner_endpoint = Some(endpoint(dir));
    let lock = nerve_center::attach::try_lock(dir).unwrap().unwrap();
    let running = rt.block_on(server::start(&args, lock)).unwrap();
    (rt, running)
}

/// The owner endpoint of the test's center: a socket beside its state
/// folder, or a pipe of its own.
fn endpoint(dir: &std::path::Path) -> std::path::PathBuf {
    match cfg!(windows) {
        true => format!(
            r"\\.\pipe\nerve-center-owner-test-{}",
            nerve_transport::keys::random_token(12)
        )
        .into(),
        false => dir.join("owner.sock"),
    }
}

fn hub_of(r: &Running) -> Hub {
    Hub::new(
        r.owner_endpoint().expect("an owner endpoint").to_path_buf(),
        // The test's center runs as the test's user: the test plays the
        // service's check.
        Arc::new(|_: &Peer| Ok(Holder::Service)),
    )
}

#[test]
fn the_app_logs_in_with_the_owner_token_with_the_web_ui_off() {
    let d = tempfile::tempdir().unwrap();
    let (rt, r) = center(d.path());
    assert!(r.ui.is_none(), "the web UI is off");
    let hub = hub_of(&r);
    // Nothing before the log-in.
    assert_eq!(hub.get("/api/overview"), Err(Failed::LoggedOut));
    assert_eq!(
        hub.login("nrv_owner_not_it"),
        Err(Failed::Refused(401, nerve::hub::WRONG_TOKEN.into()))
    );
    assert!(!hub.logged_in());
    let token = nerve_center::owner::read(d.path()).unwrap().unwrap();
    hub.login(&token).unwrap();
    assert!(hub.logged_in());
    let v = hub.get("/api/overview").unwrap();
    assert!(v["center"]["id"].is_string(), "{v}");
    // A change goes through the same checks as the web UI's.
    let made = hub
        .post(
            "/api/tokens/create",
            &serde_json::json!({"label": "claude-code"}),
        )
        .unwrap();
    assert!(made["token"].as_str().unwrap().starts_with("nrv_"));
    let refused = hub.post("/api/center", &serde_json::json!({"retention_days": 999}));
    assert!(
        matches!(&refused, Err(Failed::Refused(400, e)) if e.contains("retention")),
        "{refused:?}"
    );
    // A new owner token ends the log-in: the page logs in again.
    nerve_center::owner::renew(d.path()).unwrap();
    assert_eq!(hub.get("/api/overview"), Err(Failed::LoggedOut));
    assert!(!hub.logged_in());
    // Logged out, the token is forgotten here.
    let token = nerve_center::owner::read(d.path()).unwrap().unwrap();
    hub.login(&token).unwrap();
    hub.logout();
    assert_eq!(hub.get("/api/overview"), Err(Failed::LoggedOut));
    // The log file, as the web UI downloads it.
    hub.login(&token).unwrap();
    let log = String::from_utf8(hub.log_file().unwrap()).unwrap();
    assert!(log.contains("signed in on this machine"), "{log}");
    rt.block_on(r.stop());
}
