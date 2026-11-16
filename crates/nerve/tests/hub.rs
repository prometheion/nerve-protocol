//! The center role's pages ask a real center over its web UI's API, as a
//! browser does: logged in with the owner token, the session kept, a wrong
//! token refused, a new owner token ending the session.

use std::sync::Arc;

use nerve::hub::{Address, Failed, Holder, Hub};
use nerve_center::config::Args;
use nerve_center::server::{self, Running};

/// A center of its own under `dir`, its web UI on a loopback port, on a
/// runtime that outlives the test's calls.
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
        "127.0.0.1:0",
    ];
    let args = Args::from_argv(argv).unwrap();
    let lock = nerve_center::attach::try_lock(dir).unwrap().unwrap();
    let running = rt.block_on(server::start(&args, lock)).unwrap();
    (rt, running)
}

fn hub_of(r: &Running) -> Hub {
    let at = r.ui.expect("a web UI");
    Hub::new(
        Address {
            url: format!("http://{at}"),
            at,
            pin: None,
        },
        // The test's center runs as the test's user: the test plays the
        // service's check.
        Arc::new(|_| Ok(Holder::Service)),
    )
}

#[test]
fn the_app_logs_in_with_the_owner_token_and_keeps_the_session() {
    let d = tempfile::tempdir().unwrap();
    let (rt, r) = center(d.path());
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
    // A new owner token ends the session: the page logs in again.
    nerve_center::owner::renew(d.path()).unwrap();
    assert_eq!(hub.get("/api/overview"), Err(Failed::LoggedOut));
    assert!(!hub.logged_in());
    // Logged out, the session is gone on the center too.
    let token = nerve_center::owner::read(d.path()).unwrap().unwrap();
    hub.login(&token).unwrap();
    hub.logout();
    assert_eq!(hub.get("/api/overview"), Err(Failed::LoggedOut));
    rt.block_on(r.stop());
}
