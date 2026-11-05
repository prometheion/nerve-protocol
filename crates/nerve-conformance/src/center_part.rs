//! The center part: checks a center over the wire, acting as the echo node.
//!
//! The caller hands over a fresh pairing link of the center under test. The
//! part spends that code (and one wrong try against it).

use std::time::Duration;

use serde_json::json;

use nerve_proto::link::PairLink;
use nerve_proto::msg::{Welcome, method};
use nerve_proto::{Message, PROTOCOL_VERSION, rpc::params};
use nerve_transport::keys::NodeKey;
use nerve_transport::ws::ConnectError;

use crate::echo::{self, Echo};
use crate::wire::Recv;
use crate::{Report, ensure};

const WAIT: Duration = Duration::from_secs(15);

/// Runs every center check against the center behind `link`.
pub async fn run(link: &PairLink) -> Report {
    let mut r = Report::new("center");
    let url = &link.center;
    let pin = link.pin.as_deref();

    // §3.2: a wrong code is refused with 403.
    let key = NodeKey::generate().expect("a key");
    let mut body = json!({"code": "Wrong0000Code", "name": "conformance-echo",
        "platform": "linux", "arch": "x86_64", "public_key": key.public_hex()});
    let res = echo::post_pair(url, pin, &body).await;
    r.check(
        "3.2",
        "a wrong pairing code is answered with 403",
        match res {
            Ok((s, _)) => ensure(s == 403, format!("got {s}")),
            Err(e) => Err(e),
        },
    );

    // §3.2: unknown fields are refused with 400, and do not use up the code.
    body["code"] = json!(link.code);
    body["extra"] = json!(1);
    let res = echo::post_pair(url, pin, &body).await;
    r.check(
        "3.2",
        "a pair request with an unknown field is answered with 400",
        match res {
            Ok((s, _)) => ensure(s == 400, format!("got {s}")),
            Err(e) => Err(e),
        },
    );

    // §3.2: a good request pairs, and the center computes the node id itself.
    let node = match Echo::pair(link, "conformance-echo").await {
        Ok(n) => n,
        Err(e) => {
            r.check("3.2", "a good pair request is answered with 200", Err(e));
            for name in [
                "a used code is refused",
                "an unknown node is answered with 401",
                "the first frame is a challenge",
                "a wrong signature closes the link",
                "a version mismatch closes with unsupported_version",
                "a hello without features closes with protocol_error",
                "a good hello gets a welcome for version \"0\"",
                "the center fetches the descriptor after welcome",
            ] {
                r.skip("4", name, "pairing failed");
            }
            return r;
        }
    };
    r.check("3.2", "a good pair request is answered with 200", Ok(()));
    r.check(
        "2.2",
        "the node id is base32 of SHA-256 of the key",
        ensure(
            node.node_id == node.key.node_id(),
            format!(
                "center said {}, expected {}",
                node.node_id,
                node.key.node_id()
            ),
        ),
    );

    // §3.2: the code is single use.
    let other = NodeKey::generate().expect("a key");
    let again = json!({"code": link.code, "name": "conformance-echo-2", "platform": "linux",
        "arch": "x86_64", "public_key": other.public_hex()});
    r.check(
        "3.2",
        "a used code is refused",
        match echo::post_pair(url, pin, &again).await {
            Ok((s, _)) => ensure(s == 403, format!("got {s}")),
            Err(e) => Err(e),
        },
    );

    // §4.1: an unknown node id gets 401 on the upgrade.
    r.check(
        "4.1",
        "an unknown node is answered with 401",
        match node.dial(&other.node_id()).await {
            Err(ConnectError::Unknown) => Ok(()),
            Err(ConnectError::Other(e)) => Err(e),
            Ok(_) => Err("the center accepted an unknown node".into()),
        },
    );

    // §4.2: a wrong signature ends the link.
    match node.dial(&node.node_id).await {
        Ok(mut c) => match echo::read_challenge(&mut c).await {
            Ok(ch) => {
                r.check(
                    "4.2",
                    "the first frame is a challenge",
                    check_challenge(&ch, &node),
                );
                let _ = c.notify(method::HELLO, node.hello(&ch, &["0"], true)).await;
                r.check(
                    "4.2",
                    "a wrong signature closes the link",
                    match c.ends_within(WAIT).await {
                        Some(reason) => ensure(
                            reason.is_empty() || reason == "protocol_error",
                            format!("bye reason {reason}"),
                        ),
                        None => Err("the link stayed open".into()),
                    },
                );
            }
            Err(e) => {
                r.check("4.2", "the first frame is a challenge", Err(e));
                r.skip("4.2", "a wrong signature closes the link", "no challenge");
            }
        },
        Err(e) => {
            r.check("4.2", "the first frame is a challenge", Err(e.to_string()));
            r.skip("4.2", "a wrong signature closes the link", "no link");
        }
    }

    // §1: a node that speaks only another version is sent away.
    r.check(
        "1",
        "a version mismatch closes with unsupported_version",
        async {
            let mut c = node.dial(&node.node_id).await.map_err(|e| e.to_string())?;
            let ch = echo::read_challenge(&mut c).await?;
            c.notify(method::HELLO, node.hello(&ch, &["9"], false))
                .await?;
            match c.ends_within(WAIT).await {
                Some(reason) => ensure(
                    reason == "unsupported_version",
                    format!("bye reason {reason:?}"),
                ),
                None => Err("the link stayed open".into()),
            }
        }
        .await,
    );

    // §1.1: `features` is part of the hello's baseline, also when empty.
    r.check(
        "1.1",
        "a hello without features closes with protocol_error",
        async {
            let mut c = node.dial(&node.node_id).await.map_err(|e| e.to_string())?;
            let ch = echo::read_challenge(&mut c).await?;
            let mut hello = node.hello(&ch, &["0"], false);
            if let Some(h) = hello.as_object_mut() {
                h.remove("features");
            }
            c.notify(method::HELLO, hello).await?;
            match c.ends_within(WAIT).await {
                Some(reason) => {
                    ensure(reason == "protocol_error", format!("bye reason {reason:?}"))
                }
                None => Err("the link stayed open".into()),
            }
        }
        .await,
    );

    // §4.2: a good hello gets a welcome, then the center asks for the
    // descriptor.
    let welcome = async {
        let mut c = node.dial(&node.node_id).await.map_err(|e| e.to_string())?;
        let ch = echo::read_challenge(&mut c).await?;
        c.notify(method::HELLO, node.hello(&ch, &["0"], false))
            .await?;
        let w = match c.recv(WAIT).await {
            Recv::Msg(Message::Notification {
                method: m,
                params: p,
            }) if m == method::WELCOME => params::<Welcome>(&p).map_err(|e| e.message)?,
            other => return Err(format!("expected welcome, got {other:?}")),
        };
        Ok((c, w))
    }
    .await;
    let (mut conn, w) = match welcome {
        Ok(x) => x,
        Err(e) => {
            r.check(
                "4.2",
                "a good hello gets a welcome for version \"0\"",
                Err(e),
            );
            r.skip(
                "4.2",
                "the center fetches the descriptor after welcome",
                "no welcome",
            );
            return r;
        }
    };
    r.check(
        "4.2",
        "a good hello gets a welcome for version \"0\"",
        ensure(
            w.version == PROTOCOL_VERSION,
            format!("version {}", w.version),
        ),
    );
    let d = echo::descriptor(&node.node_id, &node.name);
    r.check(
        "4.2",
        "the center fetches the descriptor after welcome",
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Request {
                id,
                method: m,
                params: p,
            }) if m == method::DESCRIBE => {
                let reply = match echo::handle(&m, &p, &d) {
                    Ok(v) => Message::result(id, v),
                    Err(e) => Message::error(Some(id), e),
                };
                conn.send(&reply).await
            }
            other => Err(format!("expected describe, got {other:?}")),
        },
    );
    conn.bye("shutdown").await;
    r
}

fn check_challenge(ch: &nerve_proto::msg::Challenge, node: &Echo) -> Result<(), String> {
    ensure(
        ch.nonce.len() == 64 && nerve_proto::msg::unhex(&ch.nonce).is_some(),
        "the nonce is not 32 bytes of hex",
    )?;
    ensure(
        ch.center_id == node.center_id,
        "the challenge names another center id than pairing did",
    )
}
