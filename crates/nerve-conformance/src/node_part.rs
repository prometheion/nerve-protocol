//! The node part: checks a node, acting as a center ([`FakeCenter`]).
//!
//! The caller gets a pairing link and must pair the node under test with it
//! and start it (`start`). The node must then dial the fake center; the part
//! drives that link and ends with `bye revoked`, after which the node must not
//! dial again.
//!
//! With a [`Setup::folder`] and the settings grant `write` for the fake
//! center, the part also checks the profiles (§7.2 to §7.5): it writes its own
//! policy with `settings.set` and checks fs, exec, allow and deny rules, the
//! audit event and the sudo switch. The sudo checks send one wrong password, so a node with
//! a real `sudo` logs one failed attempt.

use std::future::Future;
use std::time::Duration;

use serde_json::{Value, json};

use nerve_proto::link::PairLink;
use nerve_proto::msg::method;
use nerve_proto::schema::{Role, check};
use nerve_proto::{Descriptor, ErrorCode, PROTOCOL_VERSION};

use nerve_transport::sudo::{Offer, seal};

use crate::fake_center::{self, FakeCenter};
use crate::wire::code_of;
use crate::{Report, ensure};

const WAIT: Duration = Duration::from_secs(15);

/// What the caller says about the node it started.
#[derive(Debug, Clone, Default)]
pub struct Setup {
    /// An empty folder on the node, in wire form, that the part may allow
    /// itself to read and write in. Without it the profile checks do not run.
    pub folder: Option<String>,
    /// The node's sudo password. With it the part also turns sudo on, runs
    /// a sudo command on the sudo allow list, turns sudo off and replays the
    /// password.
    pub sudo_password: Option<String>,
}

/// Runs every node check. `start` pairs the node under test with the link it
/// is given and starts it.
pub async fn run<F, Fut>(start: F) -> Report
where
    F: FnOnce(PairLink) -> Fut,
    Fut: Future<Output = Result<Setup, String>>,
{
    let mut r = Report::new("node");
    let mut center = match FakeCenter::start(false).await {
        Ok(c) => c,
        Err(e) => {
            r.check("4.1", "the fake center starts", Err(e.to_string()));
            return r;
        }
    };
    let setup = match start(center.link()).await {
        Ok(s) => s,
        Err(e) => {
            r.check("3.2", "the node pairs", Err(e));
            return r;
        }
    };
    let Some(paired) = center.paired() else {
        r.check(
            "3.2",
            "the node pairs",
            Err("no pair request arrived".into()),
        );
        return r;
    };
    r.check("3.2", "the node pairs", Ok(()));
    let req = &paired.request;
    r.check(
        "2.2",
        "the node name is 1 to 32 of a-z, 0-9 and -, starting and ending with a letter or digit",
        ensure(nerve_proto::valid_node_name(&req.name), req.name.clone()),
    );

    let Some(mut link) = center.next_link(Duration::from_secs(30)).await else {
        r.check(
            "4.1",
            "the node dials the center",
            Err("no link within 30 s".into()),
        );
        return r;
    };
    r.check("4.1", "the node dials the center", Ok(()));
    r.check(
        "4.1",
        "the Nerve-Node header names the paired node id",
        ensure(
            link.node_header == paired.node_id,
            format!("header {}", link.node_header),
        ),
    );
    let conn = &mut link.conn;
    let hello = match fake_center::handshake(conn, &center.center_id, &paired).await {
        Ok(h) => h,
        Err(e) => {
            r.check("4.2", "the hello is signed and names version \"0\"", Err(e));
            return r;
        }
    };
    r.check(
        "4.2",
        "the hello is signed and names version \"0\"",
        ensure(
            hello.versions.iter().any(|v| v == PROTOCOL_VERSION),
            "no version 0",
        ),
    );

    // §6: the descriptor.
    let d = conn
        .call(method::DESCRIBE, json!({"detail": "full"}), WAIT)
        .await;
    r.check(
        "6",
        "describe full returns a well-formed descriptor",
        match &d {
            Ok(Ok(v)) => check_descriptor(v, &paired.node_id, hello.rev),
            Ok(Err(e)) => Err(format!("error {}", e.message)),
            Err(e) => Err(e.clone()),
        },
    );

    // §5.1: `capability` detail needs a cap.
    r.check(
        "5.1",
        "describe capability without cap is invalid_args",
        expect_code(
            conn.call(method::DESCRIBE, json!({"detail": "capability"}), WAIT)
                .await,
            ErrorCode::InvalidArgs,
        ),
    );

    // §5.2: unknown methods are refused.
    r.check(
        "5.2",
        "an unknown method is method_not_found",
        expect_code(
            conn.call("frobnicate", json!({}), WAIT).await,
            ErrorCode::MethodNotFound,
        ),
    );

    // §5.3: unknown capabilities.
    r.check(
        "5.3",
        "invoke of an unknown capability is unknown_capability",
        expect_code(
            conn.call(
                method::INVOKE,
                json!({"cap": "no-such-cap", "action": "x", "args": {}, "ctx": {}}),
                WAIT,
            )
            .await,
            ErrorCode::UnknownCapability,
        ),
    );

    // §5.2: unknown fields in ctx are refused, so context can only narrow.
    r.check(
        "5.2",
        "an unknown ctx field is invalid_args",
        expect_code(
            conn.call(
                method::INVOKE,
                json!({"cap": "node", "action": "status", "args": {},
                       "ctx": {"session": "s1", "full_access": true}}),
                WAIT,
            )
            .await,
            ErrorCode::InvalidArgs,
        ),
    );

    // §5.2: `stream.open` carries the same strict ctx.
    r.check(
        "5.2",
        "an unknown ctx field of stream.open is invalid_args",
        expect_code(
            conn.call(
                method::STREAM_OPEN,
                json!({"cap": "exec", "stream": "output", "params": {"call": 1},
                       "ctx": {"session": "s1", "full_access": true}}),
                WAIT,
            )
            .await,
            ErrorCode::InvalidArgs,
        ),
    );

    if let Some(folder) = &setup.folder {
        let key = &paired.request.public_key;
        let pw = setup.sudo_password.as_deref();
        profiles(&mut r, conn, &center, key, folder, pw).await;
    }

    // §4.5: after `revoked` the node stops dialling.
    conn.bye("revoked").await;
    drop(link);
    r.check(
        "4.5",
        "after bye revoked the node does not dial again",
        match center.next_link(Duration::from_secs(4)).await {
            None => Ok(()),
            Some(_) => Err("the node dialled again".into()),
        },
    );
    r
}

/// The profile checks, in order; each needs the ones before it.
const PROFILE_CHECKS: &[(&str, &str)] = &[
    ("7.4", "settings get returns document and version"),
    ("7.4", "settings set with a stale if_version is conflict"),
    ("7.4", "settings set applies a document"),
    (
        "7.2",
        "fs read returns what fs write wrote, with the same etag",
    ),
    ("7.2", "fs read outside the allowed folder is forbidden"),
    ("7.3", "exec run of a command an allow rule names runs"),
    (
        "7.3",
        "a running command's output streams to its own session only: the stream gives it in order as frames, then stream.close",
    ),
    (
        "7.3",
        "a deny rule wins over an allow rule from the next call on",
    ),
    ("7.3", "exec run of a command nothing allows is forbidden"),
    ("7.5", "a refusal emits audit decision forbidden"),
    ("7.4.1", "sudo is off at first"),
    (
        "7.4.1",
        "with sudo off, a sudo command on the sudo allow list is forbidden",
    ),
    (
        "7.4.1",
        "sudo-offer is signed with the node's key for this center",
    ),
    (
        "7.4.1",
        "a wrong sudo password is invalid_args and sudo stays off",
    ),
];

/// The sudo checks that need the node's sudo password.
const SUDO_ON_CHECKS: &[(&str, &str)] = &[
    ("7.4.1", "the right sudo password turns sudo on"),
    (
        "7.4.1",
        "with sudo on, a sudo command on the sudo allow list runs",
    ),
    (
        "7.4.1",
        "with sudo on, a sudo command the sudo allow list does not name is forbidden",
    ),
    ("7.4.1", "sudo off turns sudo off"),
    (
        "7.4.1",
        "a replayed sealed password is invalid_args and sudo stays off",
    ),
    ("7.4.1", "no frame the node sent carries the sudo password"),
];

const ALLOWED: &str = "echo nerve-conformance-allowed";
/// A command that prints three lines over a second, in `sh` and in
/// PowerShell.
const STREAMED_SH: &str = "for i in 1 2 3; do echo line $i; sleep 0.3; done";
const STREAMED_PS: &str = "foreach ($i in 1..3) { \"line $i\"; Start-Sleep -Milliseconds 300 }";
const SUDO_ALLOWED: &str = "sudo echo nerve-conformance-sudo";

type Conn = crate::wire::Conn<tokio::net::TcpStream>;

/// One request; events that arrive meanwhile go to `events`.
async fn call_seen(
    conn: &mut Conn,
    method: &str,
    params: Value,
    events: &mut Vec<nerve_proto::Message>,
) -> Result<Result<Value, nerve_proto::RpcError>, String> {
    let id = conn.request(method, params).await?;
    conn.answer(id, WAIT, events).await
}

/// `s` as a glob that matches exactly `s`.
fn literal(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            out.extend(['[', c, ']']);
        } else {
            out.push(c);
        }
    }
    out
}

async fn invoke(
    conn: &mut Conn,
    cap: &str,
    action: &str,
    args: Value,
) -> Result<Result<Value, nerve_proto::RpcError>, String> {
    conn.call(
        method::INVOKE,
        json!({"cap": cap, "action": action, "args": args, "ctx": {}}),
        WAIT,
    )
    .await
}

fn ok(got: Result<Result<Value, nerve_proto::RpcError>, String>) -> Result<Value, String> {
    match got {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("error {} ({})", code_of(&e), e.message)),
        Err(e) => Err(e),
    }
}

async fn sudo_state(conn: &mut Conn) -> Result<String, String> {
    let v = ok(conn
        .call(
            method::GET,
            json!({"cap": "settings", "keys": ["sudo"]}),
            WAIT,
        )
        .await)?;
    Ok(v["sudo"].as_str().unwrap_or_default().to_string())
}

/// The command [`streams_output`] runs, in the node's shell: PowerShell on
/// Windows.
async fn streamed_command(conn: &mut Conn) -> Result<&'static str, String> {
    let d = ok(conn
        .call(method::DESCRIBE, json!({"detail": "summary"}), WAIT)
        .await)?;
    Ok(if d["node"]["platform"] == "windows" {
        STREAMED_PS
    } else {
        STREAMED_SH
    })
}

/// Runs `command` for one session, refuses its output stream to another
/// session and to none, then reads it: frames in order with all three lines,
/// and the node's `stream.close` with reason `ended`.
async fn streams_output(conn: &mut Conn, command: &str) -> Result<(), String> {
    let run = conn
        .request(
            method::INVOKE,
            json!({"cap": "exec", "action": "run", "args": {"command": command},
                   "ctx": {"session": "conformance-1"}}),
        )
        .await?;
    let open = |session: Option<&str>| {
        let mut p = json!({"cap": "exec", "stream": "output", "params": {"call": run}});
        if let Some(s) = session {
            p["ctx"] = json!({"session": s});
        }
        p
    };
    let mut others = Vec::new();
    // Not before the command runs; a short command may also have ended.
    tokio::time::sleep(Duration::from_millis(200)).await;
    for session in [Some("conformance-2"), None] {
        let id = conn.request(method::STREAM_OPEN, open(session)).await?;
        expect_code(
            conn.answer(id, WAIT, &mut others).await,
            ErrorCode::InvalidArgs,
        )
        .map_err(|e| format!("stream.open for another session: {e}"))?;
    }
    let id = conn
        .request(method::STREAM_OPEN, open(Some("conformance-1")))
        .await?;
    let sid = ok(conn.answer(id, WAIT, &mut others).await)?["sid"]
        .as_u64()
        .ok_or("stream.open answered no sid")?;
    let mut frames = conn.take_frames();
    let mut ran = others.iter().any(|m| answers(m, run));
    let mut closed = false;
    let deadline = tokio::time::Instant::now() + WAIT;
    while !(ran && closed) {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            crate::wire::Recv::Frame(f) => frames.push(f),
            crate::wire::Recv::Msg(m) if answers(&m, run) => ran = true,
            crate::wire::Recv::Msg(nerve_proto::Message::Request {
                id,
                method: m,
                params,
            }) if m == method::STREAM_CLOSE => {
                ensure(
                    params["sid"].as_u64() == Some(sid) && params["reason"] == "ended",
                    format!("stream.close {params:?}"),
                )?;
                conn.send(&nerve_proto::Message::result(id, json!({})))
                    .await?;
                closed = true;
            }
            crate::wire::Recv::Msg(_) => {}
            other => return Err(format!("waiting for the stream: {other:?}")),
        }
    }
    let mut text = Vec::new();
    for (n, f) in frames.iter().enumerate() {
        ensure(
            u64::from(f.id) == sid && f.seq as usize == n && f.gap_bytes().is_none(),
            format!("frame {n}: sid {} seq {}", f.id, f.seq),
        )?;
        text.extend_from_slice(&f.payload);
    }
    let text = String::from_utf8_lossy(&text).replace("\r\n", "\n");
    ensure(
        text.ends_with("line 1\nline 2\nline 3\n"),
        format!("the stream gave {text:?}"),
    )
}

/// Whether `m` is the answer to the request `id`.
fn answers(m: &nerve_proto::Message, id: u64) -> bool {
    let want = nerve_proto::Id::Num(id);
    matches!(m, nerve_proto::Message::Result { id, .. } | nerve_proto::Message::Error { id: Some(id), .. } if *id == want)
}

async fn profiles(
    r: &mut Report,
    conn: &mut Conn,
    center: &FakeCenter,
    key: &str,
    folder: &str,
    password: Option<&str>,
) {
    let mut checks = PROFILE_CHECKS.to_vec();
    if password.is_some() {
        checks.extend_from_slice(SUDO_ON_CHECKS);
    }
    let mut done = 0;
    let out = profile_steps(conn, center, key, folder, password, &mut |res| {
        let (section, name) = checks[done];
        done += 1;
        r.check(section, name, res);
    })
    .await;
    if let Err(why) = out {
        for (section, name) in &checks[done..] {
            r.skip(section, name, &why);
        }
    }
}

async fn sudo_offer(conn: &mut Conn, center: &FakeCenter, key: &str) -> Result<Offer, String> {
    let v = ok(invoke(conn, "settings", "sudo-offer", json!({})).await)?;
    let offer = Offer {
        offer: v["offer"].as_str().unwrap_or_default().into(),
        key: v["key"].as_str().unwrap_or_default().into(),
        ts: v["ts"].as_u64().unwrap_or_default(),
    };
    let sig = v["sig"].as_str().unwrap_or_default();
    ensure(
        nerve_transport::keys::verify_sudo_offer(key, &center.center_id, &offer, sig),
        format!("the signature does not verify: {v}"),
    )?;
    Ok(offer)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Runs the profile checks in [`PROFILE_CHECKS`] order, giving each result
/// to `check`; stops at the first failure.
async fn profile_steps(
    conn: &mut Conn,
    center: &FakeCenter,
    key: &str,
    folder: &str,
    password: Option<&str>,
    check: &mut dyn FnMut(Result<(), String>),
) -> Result<(), String> {
    let mut step = |res: Result<(), String>| {
        let failed = res
            .as_ref()
            .err()
            .map(|e| format!("an earlier check failed: {e}"));
        check(res);
        failed.map_or(Ok(()), Err)
    };

    let got = ok(conn
        .call(
            method::GET,
            json!({"cap": "settings", "keys": ["document", "version"]}),
            WAIT,
        )
        .await);
    let (mut doc, version) = match got {
        Ok(v) if v["document"].is_object() && v["version"].is_u64() => {
            (v["document"].clone(), v["version"].as_u64().unwrap_or(0))
        }
        Ok(v) => return step(Err(format!("got {v}"))),
        Err(e) => return step(Err(e)),
    };
    step(Ok(()))?;

    // A policy of its own, in default deny: allow rules for the folder and
    // one exact command, and the sudo allow list for another.
    let policy = &mut doc["policy"];
    policy["mode"] = json!("allowlist");
    if let Some(p) = policy.as_object_mut() {
        p.remove("until");
    }
    policy["folders"] = json!([]);
    let streamed = streamed_command(conn).await?;
    policy["allow"] = json!([
        format!("fs:{}/*", literal(folder.trim_end_matches('/'))),
        format!("exec.run:{ALLOWED}"),
        format!("exec.run:{}", literal(streamed)),
    ]);
    policy["deny"] = json!([]);
    policy["sudo_allow"] = json!([SUDO_ALLOWED]);
    let set = |if_version: u64| json!({"document": doc.clone(), "if_version": if_version});

    step(expect_code(
        invoke(conn, "settings", "set", set(version + 1000)).await,
        ErrorCode::Other("conflict".into()),
    ))?;
    let mut now = version;
    step(
        ok(invoke(conn, "settings", "set", set(version)).await).and_then(|v| {
            now = v["version"].as_u64().unwrap_or(0);
            ensure(now > version, format!("got {v}"))
        }),
    )?;

    let path = format!("{}/nerve-conformance.txt", folder.trim_end_matches('/'));
    let content = "nerve conformance\n";
    step(
        async {
            let w = ok(invoke(
                conn,
                "fs",
                "write",
                json!({"path": path, "content": content}),
            )
            .await)?;
            let r = ok(invoke(conn, "fs", "read", json!({"path": path})).await)?;
            ensure(r["content"] == content, format!("read {r}"))?;
            let etag = w["etag"].as_str().unwrap_or_default();
            ensure(
                etag.len() == 64 && r["etag"] == etag,
                format!("etag {etag} vs {}", r["etag"]),
            )
        }
        .await,
    )?;
    let parent = folder
        .trim_end_matches('/')
        .rsplit_once('/')
        .map_or("", |(p, _)| p);
    step(expect_code(
        invoke(
            conn,
            "fs",
            "read",
            json!({"path": format!("{parent}/nerve-conformance-outside")}),
        )
        .await,
        ErrorCode::Forbidden,
    ))?;

    step(
        ok(invoke(conn, "exec", "run", json!({"command": ALLOWED})).await).and_then(|v| {
            ensure(
                v["exit_code"] == 0
                    && v["stdout"].as_str().map(str::trim) == Some("nerve-conformance-allowed"),
                format!("got {v}"),
            )
        }),
    )?;

    step(streams_output(conn, streamed).await)?;

    // A rule edit counts from the next call on, and a deny rule wins over
    // the allow rule for the same command.
    let mut denied = doc.clone();
    denied["policy"]["deny"] = json!([format!("exec.run:{ALLOWED}")]);
    step(
        async {
            ok(invoke(
                conn,
                "settings",
                "set",
                json!({"document": denied, "if_version": now}),
            )
            .await)?;
            expect_code(
                invoke(conn, "exec", "run", json!({"command": ALLOWED})).await,
                ErrorCode::Forbidden,
            )
        }
        .await,
    )?;

    let mut events = Vec::new();
    step(expect_code(
        call_seen(
            conn,
            method::SUB,
            json!({"topics": ["audit/decision"]}),
            &mut events,
        )
        .await
        .and(
            call_seen(
                conn,
                method::INVOKE,
                json!({"cap": "exec", "action": "run",
                       "args": {"command": "echo nerve-conformance-other"}, "ctx": {}}),
                &mut events,
            )
            .await,
        ),
        ErrorCode::Forbidden,
    ))?;
    // An event sent right before the answer may trail it on a busy link.
    let _ = call_seen(conn, method::GET, json!({"cap": "node"}), &mut events).await;
    step(ensure(
        events.iter().any(|m| match m {
            nerve_proto::Message::Notification { method: m, params } => {
                m == method::EVENT
                    && params["cap"] == "audit"
                    && params["name"] == "decision"
                    && params["data"]["cap"] == "exec"
                    && params["data"]["decision"] == "forbidden"
            }
            _ => false,
        }),
        "no audit decision event for the refused run",
    ))?;

    step(
        sudo_state(conn)
            .await
            .and_then(|s| ensure(s == "off", format!("sudo is {s}"))),
    )?;
    step(expect_code(
        invoke(conn, "exec", "run", json!({"command": SUDO_ALLOWED})).await,
        ErrorCode::Forbidden,
    ))?;

    let offer = match sudo_offer(conn, center, key).await {
        Ok(o) => {
            step(Ok(()))?;
            o
        }
        Err(e) => return step(Err(e)),
    };
    let sealed = seal(&offer, "nerve-conformance-wrong-password", now_ms())?;
    let wrong = expect_code(
        invoke(
            conn,
            "settings",
            "sudo",
            json!({"on": true, "sealed": sealed}),
        )
        .await,
        ErrorCode::InvalidArgs,
    );
    let state = sudo_state(conn).await;
    step(wrong.and(state.and_then(|s| ensure(s == "off", format!("sudo is {s}")))))?;

    let Some(password) = password else {
        return Ok(());
    };
    // Every frame from here on, to look for the password in.
    let mut seen: Vec<String> = Vec::new();
    let mut call = async |conn: &mut Conn, cap: &str, action: &str, args: Value| {
        let mut others = Vec::new();
        let got = call_seen(
            conn,
            method::INVOKE,
            json!({"cap": cap, "action": action, "args": args, "ctx": {}}),
            &mut others,
        )
        .await;
        seen.extend(others.iter().map(nerve_proto::Message::encode));
        if let Ok(r) = &got {
            seen.push(match r {
                Ok(v) => v.to_string(),
                Err(e) => serde_json::to_string(e).unwrap_or_default(),
            });
        }
        got
    };
    let offer = sudo_offer(conn, center, key).await?;
    let on = json!({"on": true, "sealed": seal(&offer, password, now_ms())?});
    let turned = ok(call(conn, "settings", "sudo", on.clone()).await);
    let state = sudo_state(conn).await;
    step(
        turned
            .and_then(|v| ensure(v["sudo"] == "on", format!("got {v}")))
            .and(state.and_then(|s| ensure(s == "on", format!("sudo is {s}")))),
    )?;
    let ran = ok(call(conn, "exec", "run", json!({"command": SUDO_ALLOWED})).await);
    step(ran.and_then(|v| {
        ensure(
            v["exit_code"] == 0
                && v["stdout"].as_str().map(str::trim) == Some("nerve-conformance-sudo"),
            format!("got {v}"),
        )
    }))?;
    step(expect_code(
        call(
            conn,
            "exec",
            "run",
            json!({"command": "sudo echo nerve-conformance-other"}),
        )
        .await,
        ErrorCode::Forbidden,
    ))?;
    let off = ok(call(conn, "settings", "sudo", json!({"on": false})).await);
    let state = sudo_state(conn).await;
    step(off.and(state.and_then(|s| ensure(s == "off", format!("sudo is {s}")))))?;
    let replay = expect_code(
        call(conn, "settings", "sudo", on).await,
        ErrorCode::InvalidArgs,
    );
    let state = sudo_state(conn).await;
    step(replay.and(state.and_then(|s| ensure(s == "off", format!("sudo is {s}")))))?;
    step(ensure(
        !seen.iter().any(|f| f.contains(password)),
        "a frame carries the sudo password",
    ))
}

pub(crate) fn expect_code(
    got: Result<Result<Value, nerve_proto::RpcError>, String>,
    want: ErrorCode,
) -> Result<(), String> {
    match got {
        Ok(Err(e)) => ensure(
            e.kind() == want,
            format!(
                "got {} ({}), expected {}",
                code_of(&e),
                e.message,
                want.as_str()
            ),
        ),
        Ok(Ok(v)) => Err(format!("succeeded with {v}")),
        Err(e) => Err(e),
    }
}

fn check_descriptor(v: &Value, node_id: &str, rev: u64) -> Result<(), String> {
    let d: Descriptor =
        serde_json::from_value(v.clone()).map_err(|e| format!("not a descriptor: {e}"))?;
    ensure(d.nerve == PROTOCOL_VERSION, format!("nerve {:?}", d.nerve))?;
    ensure(d.node.id == node_id, format!("node.id {}", d.node.id))?;
    ensure(d.rev == rev, format!("rev {} but hello said {rev}", d.rev))?;
    ensure(
        nerve_proto::descriptor::summary_words(&d.summary) < 60,
        "the summary has 60 words or more",
    )?;
    ensure(d.capability("node").is_some(), "no node capability")?;
    d.check_names()?;
    let mut ids = std::collections::BTreeSet::new();
    for c in &d.capabilities {
        ensure(ids.insert(&c.id), format!("capability {} twice", c.id))?;
    }
    check_access(v)?;
    check_schemas(&d)
}

/// Whether the descriptor's `access` block (§6.2), when there is one, is
/// well formed: a known mode, folders only in folder mode, each an absolute
/// path in the center's form that reads the same on one line (a center
/// would show another one shown changed) with one to three of `r`, `w`, `x`
/// in that order (a closed folder is not named), `own` and `closed_below`
/// booleans, no place twice; `sudo` a boolean and `unnamed` a count, each
/// set only in folder mode. A `\` is part of a Unix name, so it is not
/// refused. A center reads a block it cannot take as none,
/// so a node that sends one tells the agent nothing. (An action's
/// `exposure` other than `on` or `off` fails the descriptor as a whole.)
fn check_access(v: &Value) -> Result<(), String> {
    let Some(a) = v.get("access") else {
        return Ok(());
    };
    let a = a.as_object().ok_or("access is not an object")?;
    let mode = a.get("mode").and_then(Value::as_str).unwrap_or_default();
    ensure(
        matches!(mode, "allowlist" | "folder" | "user"),
        format!("access mode {:?}", a.get("mode")),
    )?;
    if let Some(u) = a.get("until_ms") {
        ensure(u.is_u64(), format!("access until_ms {u}"))?;
    }
    if let Some(n) = a.get("account") {
        let n = n.as_str().unwrap_or_default();
        ensure(
            !n.is_empty() && !n.chars().any(char::is_control),
            format!("access account {n:?}"),
        )?;
    }
    if let Some(c) = a.get("confined") {
        ensure(
            c.as_bool().is_some_and(|c| !c || mode == "folder"),
            format!("access confined {c} in {mode} mode"),
        )?;
    }
    if let Some(s) = a.get("sudo") {
        ensure(
            s.as_bool().is_some_and(|s| !s || mode == "folder"),
            format!("access sudo {s} in {mode} mode"),
        )?;
    }
    if let Some(n) = a.get("unnamed") {
        ensure(
            n.as_u64().is_some_and(|n| n == 0 || mode == "folder"),
            format!("access unnamed {n} in {mode} mode"),
        )?;
    }
    let folders = match a.get("folders") {
        None => return Ok(()),
        Some(f) => f.as_array().ok_or("access folders is not a list")?,
    };
    ensure(
        folders.is_empty() || mode == "folder",
        format!("access names folders in {mode} mode"),
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for f in folders {
        let path = f["path"].as_str().unwrap_or_default();
        ensure(
            path.starts_with('/') && nerve_proto::descriptor::plain_line(path),
            format!("access folder path {:?}", f["path"]),
        )?;
        let flags = nerve_proto::descriptor::FolderAccess {
            path: path.into(),
            access: f["access"].as_str().unwrap_or("?").into(),
            own: false,
            closed_below: false,
        };
        ensure(
            flags.flags().is_some(),
            format!("access folder {path}: flags {:?}", f["access"]),
        )?;
        ensure(
            f.get("own").is_none_or(Value::is_boolean),
            format!("access folder {path}: own {}", f["own"]),
        )?;
        ensure(
            f.get("closed_below").is_none_or(Value::is_boolean),
            format!("access folder {path}: closed_below {}", f["closed_below"]),
        )?;
        ensure(seen.insert(path), format!("access folder {path} twice"))?;
    }
    Ok(())
}

/// Whether every schema of `d` keeps to the subset (§6): a center leaves out
/// what does not, so a node that publishes such a schema offers less than it
/// means to. An action without `params` takes any arguments; a result, event
/// data or state that is not given says nothing.
fn check_schemas(d: &Descriptor) -> Result<(), String> {
    for c in &d.capabilities {
        for (a, decl) in &c.actions {
            if !decl.params.is_null() {
                check(&decl.params, Role::Params)
                    .map_err(|e| format!("{}.{a} params: {e}", c.id))?;
            }
            if !decl.result.is_null() {
                check(&decl.result, Role::Result)
                    .map_err(|e| format!("{}.{a} result: {e}", c.id))?;
            }
        }
        for (n, ev) in &c.events {
            if !ev.data.is_null() {
                check(&ev.data, Role::Result).map_err(|e| format!("{}/{n} data: {e}", c.id))?;
            }
        }
        if !c.state.is_null() {
            check(&c.state, Role::Result).map_err(|e| format!("{} state: {e}", c.id))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo() -> Value {
        serde_json::to_value(crate::echo::descriptor("node-id", "echo-node")).unwrap()
    }

    #[test]
    fn a_descriptor_whose_schemas_keep_to_the_subset_passes() {
        check_descriptor(&echo(), "node-id", 1).unwrap();
    }

    /// A well-formed access block passes; each way of getting it wrong
    /// fails with what is wrong.
    #[test]
    fn the_access_block_must_be_well_formed() {
        let good = json!({"mode": "folder", "until_ms": 5, "account": "nerve-run",
                          "confined": true, "sudo": true, "unnamed": 2,
                          "folders": [{"path": "/home/me/proj", "access": "rw",
                                       "closed_below": true},
                                      {"path": "/c/Users/me", "access": "rwx"},
                                      {"path": "/srv/data\\2026", "access": "r"},
                                      {"path": "/tmp", "access": "rwx", "own": true}]});
        let mut d = echo();
        d["access"] = good.clone();
        check_descriptor(&d, "node-id", 1).unwrap();
        d["access"] = json!({"mode": "user", "account": "me"});
        check_descriptor(&d, "node-id", 1).unwrap();
        type Edit = fn(&mut Value);
        let cases: [(Edit, &str); 23] = [
            (|a| a["mode"] = json!("later"), "access mode"),
            (|a| a["until_ms"] = json!(-1), "access until_ms"),
            (|a| a["account"] = json!("me\nyou"), "access account"),
            (|a| a["account"] = json!(""), "access account"),
            (
                |a| {
                    a["mode"] = json!("user");
                    a["folders"] = json!([]);
                    a["confined"] = json!(true)
                },
                "access confined",
            ),
            (
                |a| {
                    a["mode"] = json!("user");
                    a["confined"] = json!(false)
                },
                "access sudo",
            ),
            (
                |a| {
                    a["mode"] = json!("user");
                    a["confined"] = json!(false);
                    a["sudo"] = json!(false)
                },
                "access unnamed",
            ),
            (
                |a| {
                    a["mode"] = json!("user");
                    a["confined"] = json!(false);
                    a["sudo"] = json!(false);
                    a["unnamed"] = json!(0)
                },
                "access names folders in user mode",
            ),
            (|a| a["sudo"] = json!("yes"), "access sudo"),
            (|a| a["unnamed"] = json!(-1), "access unnamed"),
            (
                |a| a["folders"][0]["path"] = json!("home/me"),
                "access folder path",
            ),
            (
                |a| a["folders"][0]["path"] = json!("C:\\Users"),
                "access folder path",
            ),
            (
                |a| a["folders"][0]["path"] = json!("/home/me/a\nb"),
                "access folder path",
            ),
            (
                |a| a["folders"][0]["path"] = json!("/home/me/a\u{2028}b"),
                "access folder path",
            ),
            (
                |a| a["folders"][0]["path"] = json!("/home/me/a "),
                "access folder path",
            ),
            (
                |a| a["folders"][0]["path"] = json!("/home/me/a\u{2029}"),
                "access folder path",
            ),
            (
                |a| a["folders"][0]["access"] = json!("wr"),
                "access folder /home/me/proj: flags",
            ),
            (
                |a| a["folders"][0]["access"] = json!(null),
                "access folder /home/me/proj: flags",
            ),
            (
                |a| a["folders"][0]["access"] = json!(""),
                "access folder /home/me/proj: flags",
            ),
            (
                |a| a["folders"][0]["own"] = json!("yes"),
                "access folder /home/me/proj: own",
            ),
            (
                |a| a["folders"][0]["closed_below"] = json!(1),
                "access folder /home/me/proj: closed_below",
            ),
            (
                |a| a["folders"][1]["path"] = json!("/home/me/proj"),
                "access folder /home/me/proj twice",
            ),
            (|a| *a = json!("folder"), "access is not an object"),
        ];
        for (edit, want) in cases {
            let mut d = echo();
            d["access"] = good.clone();
            edit(&mut d["access"]);
            let e = check_descriptor(&d, "node-id", 1).unwrap_err();
            assert!(e.starts_with(want), "{want}: {e}");
        }
        let mut d = echo();
        d["capabilities"][1]["actions"]["say"]["exposure"] = json!("hidden");
        let e = check_descriptor(&d, "node-id", 1).unwrap_err();
        assert!(e.starts_with("not a descriptor"), "{e}");
        d["capabilities"][1]["actions"]["say"]["exposure"] = json!("off");
        check_descriptor(&d, "node-id", 1).unwrap();
    }

    #[test]
    fn a_schema_outside_the_subset_fails_the_descriptor_check() {
        let cases = [
            (
                "/capabilities/1/actions/say/params/properties/text",
                json!({"oneOf": [{"type": "string"}, {"type": "integer"}]}),
                "echo.say params: /properties/text/oneOf: ",
            ),
            (
                "/capabilities/1/actions/say/result",
                json!({"$ref": "#/$defs/text"}),
                "echo.say result: /$ref: ",
            ),
            (
                "/capabilities/0/events/going_away/data",
                json!({"type": "object", "properties": {"reason": {"type": "string", "pattern": "^."}}}),
                "node/going_away data: /properties/reason/pattern: ",
            ),
            (
                "/capabilities/1/state",
                json!({"type": "object", "if": {"type": "object"}}),
                "echo state: /if: ",
            ),
        ];
        for (at, schema, want) in cases {
            let mut d = echo();
            // Index by index, as some of these fields are not there yet.
            let mut at_v = &mut d;
            for step in at.split('/').skip(1) {
                at_v = match step.parse::<usize>() {
                    Ok(i) => &mut at_v[i],
                    Err(_) => &mut at_v[step],
                };
            }
            *at_v = schema;
            let e = check_descriptor(&d, "node-id", 1).unwrap_err();
            assert!(e.starts_with(want), "{at}: {e}");
        }
    }
}
