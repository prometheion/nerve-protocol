//! Key rotation (docs/dev/spec/protocol.md §4.10) on a real node daemon
//! against the conformance fake center, in process: the owner rotates the
//! node's key with `center rotate-key`, the center takes it, refuses it or
//! does not answer; the owner ends the grace of the old key; and the center
//! tells the node of its own new key.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{cli, options};
use nerve_conformance::fake_center::{self, FakeCenter, Paired};
use nerve_conformance::wire::{Conn, Recv};
use nerve_node::{Daemon, NodePaths};
use nerve_proto::Message;
use nerve_proto::msg::method;
use nerve_transport::keys::{NodeKey, verify_node_signature};
use nerve_transport::tls::{ServerIdentity, b64url, decode_pin};
use serde_json::{Map, Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

/// Pairs with `center` as `lab`, with `pin` stored as the center's pin
/// (the fake center speaks plain HTTP, so the link does not check it), and
/// starts the daemon.
async fn node(root: &Path, center: &FakeCenter, pin: Option<String>) -> Daemon {
    node_with(root, center, |e| e.pin = pin.clone()).await
}

/// [`node`], with the pairing's entry changed by `f` before the start.
async fn node_with(
    root: &Path,
    center: &FakeCenter,
    f: impl Fn(&mut nerve_policy::CenterEntry),
) -> Daemon {
    let o = options(root);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    nerve_node::cli::edit(&o.paths, |c| {
        f(&mut c.centers[0]);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    Daemon::start(o).await.expect("start")
}

/// Accepts the node's next link and runs the handshake against `public_key`.
async fn link(center: &mut FakeCenter, public_key: &str) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    // The node id stays the one of the pairing, whatever key signs.
    assert_eq!(inc.node_header, paired.node_id);
    let hello = fake_center::handshake_with(
        &mut inc.conn,
        &center.center_id,
        &paired.node_id,
        public_key,
    )
    .await
    .expect("handshake");
    // Key rotation is part of the baseline: no feature names it.
    assert!(hello.features.is_empty());
    inc.conn
}

/// The next notification `want` from the node; anything else is passed over.
async fn next(conn: &mut Conn<TcpStream>, want: &str) -> Option<Map<String, Value>> {
    let until = tokio::time::Instant::now() + WAIT;
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            Recv::Msg(Message::Notification { method: m, params }) if m == want => {
                return Some(params);
            }
            Recv::Msg(_) => continue,
            _ => return None,
        }
    }
}

/// `center rotate-key` in the background, so the test can play the center.
fn rotate(paths: &NodePaths, args: &[&str]) -> tokio::task::JoinHandle<Result<String, String>> {
    let paths = paths.clone();
    let mut all = vec!["center", "rotate-key"];
    all.extend_from_slice(args);
    let all: Vec<String> = all.iter().map(|s| s.to_string()).collect();
    // The CLI's future is not Send: it runs on a thread of its own, as the
    // owner's command runs in a process of its own.
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = all.iter().map(String::as_str).collect();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(cli(&paths, &args))
    })
}

fn key(paths: &NodePaths) -> NodeKey {
    NodeKey::from_text(&std::fs::read_to_string(paths.key_file("lab")).unwrap()).unwrap()
}

/// Waits until the audit log holds `text`: the node writes node.toml first
/// and its audit line after, so a test that saw the first may be early for
/// the second.
async fn audit_shows(paths: &NodePaths, text: &str) -> bool {
    for _ in 0..200 {
        if audit(paths).contains(text) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// Waits until the rotation to `new` is settled: the node keeps the new key
/// first and deletes the copy aside after, so a test that saw the first may
/// be early for the second.
async fn settled(paths: &NodePaths, new: &str) {
    for _ in 0..200 {
        if key(paths).public_hex() == new && !paths.next_key_file("lab").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(key(paths).public_hex(), new);
    assert!(!paths.next_key_file("lab").exists());
}

fn audit(paths: &NodePaths) -> String {
    std::fs::read_to_string(paths.audit_log()).unwrap_or_default()
}

fn paired(center: &FakeCenter) -> Paired {
    center.paired().expect("paired")
}

/// Checks a `key.rotate` as a center does: signed by `old` and by the new
/// key itself. Returns the new key.
fn check_rotate(p: &Map<String, Value>, center_id: &str, old: &str) -> String {
    let new = p["public_key"].as_str().unwrap().to_string();
    let raw = nerve_proto::msg::unhex(&new).unwrap();
    let message = nerve_proto::rotate_node_message(center_id, &raw);
    assert!(verify_node_signature(
        old,
        &message,
        p["sig"].as_str().unwrap()
    ));
    assert!(verify_node_signature(
        &new,
        &message,
        p["proof"].as_str().unwrap()
    ));
    new
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_takes_its_new_key_once_the_center_took_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    assert_ne!(new, old);
    // The new key is kept aside until the center answers.
    assert!(paths.next_key_file("lab").exists());
    assert_eq!(key(&paths).public_hex(), old);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    let out = run.await.unwrap().expect("the rotation");
    assert!(out.contains(&new), "{out}");
    assert!(out.contains("7 more days"), "{out}");
    assert_eq!(key(&paths).public_hex(), new);
    assert!(!paths.next_key_file("lab").exists());
    // The config names the new key, which a backup checks the key by; the
    // node id stays.
    let (cfg, _) = nerve_node::cli::read_config(&paths).await.unwrap();
    assert_eq!(cfg.centers[0].public_key.as_deref(), Some(new.as_str()));
    assert_eq!(cfg.centers[0].key_rotations, 1);
    assert_eq!(cfg.centers[0].node_id, paired(&center).node_id);
    let log = audit(&paths);
    assert!(log.contains("\"event\":\"node-key\""), "{log}");
    // No private key in the audit log, nor in the answer.
    assert!(!log.contains(key(&paths).to_text().trim()));
    assert!(!out.contains(key(&paths).to_text().trim()));

    // The next link is signed with the new key, under the same node id.
    conn.bye("shutdown").await;
    let mut conn = link(&mut center, &new).await;

    // The owner ends the grace of the old key; the current key signs that.
    let run = rotate(&paths, &["--end-grace"]);
    let p = next(&mut conn, method::KEY_RETIRE)
        .await
        .expect("key.retire");
    assert_eq!(p["public_key"], new.as_str());
    let message = nerve_proto::retire_node_message(
        &center.center_id,
        &nerve_proto::msg::unhex(&new).unwrap(),
    );
    assert!(verify_node_signature(
        &new,
        &message,
        p["sig"].as_str().unwrap()
    ));
    conn.notify(method::KEY_RETIRED, json!({})).await.unwrap();
    let out = run.await.unwrap().expect("the end of the grace");
    assert!(out.contains("no longer takes"), "{out}");
    assert!(audit(&paths).contains("node-key-grace-ended"));
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_rotation_keeps_the_old_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    conn.notify(
        method::KEY_ROTATED,
        json!({"public_key": new, "error": "another node holds this key"}),
    )
    .await
    .unwrap();
    let e = run.await.unwrap().expect_err("refused");
    assert!(e.contains("another node holds this key"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    assert!(!paths.next_key_file("lab").exists());
    assert!(audit(&paths).contains("node-key-refused"));
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_rotation_is_sent_again_on_the_next_link() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    // The link drops before the answer: the center may have taken the key.
    drop(conn);
    let e = run.await.unwrap().expect_err("no answer");
    assert!(e.contains("did not answer"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    assert!(paths.next_key_file("lab").exists());
    assert!(audit(&paths).contains("node-key-unanswered"));

    // The next link is still signed with the old key, and sends the same new
    // key again by itself.
    let mut conn = link(&mut center, &old).await;
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("sent again");
    assert_eq!(check_rotate(&p, &center.center_id, &old), new);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    settled(&paths, &new).await;
    drop(daemon);
}

/// A `key.rotated` that comes after the owner's command stopped waiting
/// still settles the rotation, on the link it came over.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_answer_settles_the_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    let e = run.await.unwrap().expect_err("no answer in time");
    assert!(e.contains("did not answer"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    settled(&paths, &new).await;
    assert!(audit(&paths).contains("\"event\":\"node-key\""));
    drop(daemon);
}

/// A center that took the new key but whose answer never came, and whose
/// grace for the old key has ended, refuses the old key's hello: the node
/// tries the new key next, and once that links the rotation is settled.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_hello_is_tried_with_the_new_key_kept_aside() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    drop(conn);
    run.await.unwrap().expect_err("no answer");

    // The center holds only the new key now: the old key's hello is refused.
    let paired = paired(&center);
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    let refused =
        fake_center::handshake_with(&mut inc.conn, &center.center_id, &paired.node_id, &new).await;
    assert!(refused.is_err(), "signed with the old key");
    drop(inc);
    // The next hello is signed with the new key, under the same node id.
    let _conn = link(&mut center, &new).await;
    settled(&paths, &new).await;
    drop(daemon);
}

/// An old pin whose time is over goes from node.toml.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_pin_whose_time_is_over_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (a, b) = (
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
    );
    let daemon = node_with(dir.path(), &center, |e| {
        e.pin = Some(b.pin());
        e.old_pin = Some(nerve_policy::OldPin {
            pin: a.pin(),
            until_ms: 1,
        });
    })
    .await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let _conn = link(&mut center, &old).await;
    let (cfg, _) = nerve_node::cli::read_config(&paths).await.unwrap();
    assert_eq!(cfg.centers[0].old_pin, None);
    assert_eq!(cfg.centers[0].pin, Some(b.pin()));
    drop(daemon);
}

/// A `center.rotate` from `old` to `new`, signed by `signer`.
fn center_rotate(
    center_id: &str,
    old: &ServerIdentity,
    new: &ServerIdentity,
    signer: &ServerIdentity,
    grace_ms: u64,
) -> Value {
    let new_pin = decode_pin(&new.pin()).unwrap();
    let sig = signer
        .sign(&nerve_proto::rotate_center_message(center_id, &new_pin))
        .unwrap();
    json!({
        "old_spki": b64url(&old.spki()),
        "new_spki": b64url(&new.spki()),
        "sig": b64url(&sig),
        "grace_ms": grace_ms,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_follows_a_center_key_its_old_key_signed() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (a, b, other) = (
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
    );
    let daemon = node(dir.path(), &center, Some(a.pin())).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;
    let pins = || {
        let (cfg, _) = futures_block(nerve_node::cli::read_config(&paths)).unwrap();
        let c = cfg.centers[0].clone();
        (c.pin, c.old_pin)
    };

    // Signed by another key than the pinned one: the pin stays.
    let id = center.center_id.clone();
    conn.notify(
        method::CENTER_ROTATE,
        center_rotate(&id, &a, &b, &other, 1000),
    )
    .await
    .unwrap();
    assert!(audit_shows(&paths, "center-key-refused").await);
    assert_eq!(pins(), (Some(a.pin()), None));

    // Signed by the pinned key: the new pin is taken, the old one for the
    // grace the center names, at most 7 days.
    let week = nerve_proto::ROTATE_GRACE_MS;
    let before = nerve_proto::msg::now_ms();
    conn.notify(
        method::CENTER_ROTATE,
        center_rotate(&id, &a, &b, &a, 10 * week),
    )
    .await
    .unwrap();
    let mut got = pins();
    for _ in 0..200 {
        if got.0 == Some(b.pin()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        got = pins();
    }
    let (pin, old_pin) = got;
    assert_eq!(pin, Some(b.pin()));
    let old_pin = old_pin.expect("the old pin is kept");
    assert_eq!(old_pin.pin, a.pin());
    assert!(
        old_pin.until_ms >= before + week && old_pin.until_ms <= nerve_proto::msg::now_ms() + week
    );
    assert!(audit_shows(&paths, "\"event\":\"center-key\"").await);
    let (cfg, _) = futures_block(nerve_node::cli::read_config(&paths)).unwrap();
    assert_eq!(cfg.centers[0].pin_rotations, 1);

    // Told again with no grace left (the center serves the new key): the
    // old pin goes.
    conn.notify(method::CENTER_ROTATE, center_rotate(&id, &a, &b, &a, 0))
        .await
        .unwrap();
    for _ in 0..200 {
        if pins().1.is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(pins(), (Some(b.pin()), None));
    assert!(audit_shows(&paths, "center-key-grace-ended").await);
    drop(daemon);
}

/// Runs `f` to its end from inside the test's runtime.
fn futures_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// When node.toml cannot record the new key, the rotation is not settled:
/// the old key stays, the new one stays aside, and the next link settles it
/// with the key recorded, so a backup knows it. Unix only: the test takes
/// the write right of the config folder away by its mode.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_new_key_node_toml_cannot_record_is_settled_on_the_next_link() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;
    let mode = |m| {
        std::fs::set_permissions(&paths.config_dir, std::fs::Permissions::from_mode(m)).unwrap()
    };
    mode(0o500);
    // Root writes anyway; then this test says nothing.
    let writable = std::fs::write(paths.config_dir.join("probe"), b"x").is_ok();
    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    let out = run.await.unwrap();
    mode(0o700);
    if writable {
        return;
    }
    let e = out.expect_err("not recorded");
    assert!(e.contains("could not record"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    assert!(paths.next_key_file("lab").exists());

    // The next link sends it again, and the center answers it the same.
    drop(conn);
    let mut conn = link(&mut center, &old).await;
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("sent again");
    assert_eq!(check_rotate(&p, &center.center_id, &old), new);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    for _ in 0..200 {
        if key(&paths).public_hex() == new {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(key(&paths).public_hex(), new);
    let (cfg, _) = nerve_node::cli::read_config(&paths).await.unwrap();
    assert_eq!(cfg.centers[0].public_key.as_deref(), Some(new.as_str()));
    drop(daemon);
}

/// A TLS front with `id`'s key in front of the fake center at `to`.
async fn tls_front(id: &ServerIdentity, to: u16) -> u16 {
    let acceptor = nerve_transport::tls::Acceptor::new(id).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", to)).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut up).await;
            });
        }
    });
    port
}

/// A connection the node opened under the center's old pin ends once that
/// pin's time is over: whoever holds the old key keeps no link.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_under_an_old_pin_ends_when_its_time_is_over() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (a, b) = (
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
    );
    // The old key A answers; the node pins B and takes A for a few seconds.
    let front = tls_front(&a, center.url.port).await;
    let until = nerve_proto::msg::now_ms() + 4000;
    let daemon = node_with(dir.path(), &center, |e| {
        e.url = format!("https://127.0.0.1:{front}");
        e.pin = Some(b.pin());
        e.old_pin = Some(nerve_policy::OldPin {
            pin: a.pin(),
            until_ms: until,
        });
    })
    .await;
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;
    assert!(
        nerve_proto::msg::now_ms() < until,
        "the link came up within the old pin's time"
    );
    // A short slack past its time: the center serves its new key within it.
    let left = until.saturating_sub(nerve_proto::msg::now_ms());
    assert!(
        conn.ends_within(Duration::from_millis(left + 8000))
            .await
            .is_none(),
        "the link under the old pin stays for the slack"
    );
    assert!(
        conn.ends_within(Duration::from_secs(20)).await.is_some(),
        "the link under the old pin ends after the slack"
    );
    assert!(nerve_proto::msg::now_ms() >= until + 15_000);
    drop(daemon);
}

/// A center pin written with base64 padding names the same key: the node
/// links under it and stays linked.
#[tokio::test(flavor = "multi_thread")]
async fn a_padded_pin_links_and_stays_linked() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let a = ServerIdentity::generate(&[]).unwrap();
    let front = tls_front(&a, center.url.port).await;
    let daemon = node_with(dir.path(), &center, |e| {
        e.url = format!("https://127.0.0.1:{front}");
        e.pin = Some(format!("{}=", a.pin()));
    })
    .await;
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old).await;
    assert!(
        conn.ends_within(Duration::from_secs(7)).await.is_none(),
        "the link under the padded pin stays"
    );
    drop(daemon);
}

/// A dial refused for the pin says to pair again only when it goes on: right
/// after a rotation the center may not serve its new key yet.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_pin_says_to_pair_again_only_when_it_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let (a, b) = (
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
    );
    let front = tls_front(&a, center.url.port).await;
    let daemon = node_with(dir.path(), &center, |e| {
        e.url = format!("https://127.0.0.1:{front}");
        e.pin = Some(b.pin());
    })
    .await;
    let paths = daemon.paths().clone();
    let status = || {
        let paths = paths.clone();
        async move { cli(&paths, &["status"]).await.unwrap_or_default() }
    };
    let mut first = String::new();
    for _ in 0..200 {
        first = status().await;
        if first.contains("cannot connect") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(first.contains("may not serve its new key yet"), "{first}");
    assert!(!first.contains("pair again"), "{first}");
    let mut later = String::new();
    for _ in 0..600 {
        later = status().await;
        if later.contains("pair again") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(later.contains("pair again"), "{later}");
    drop(daemon);
}
