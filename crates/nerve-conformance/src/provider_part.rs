//! The provider part: checks a node's provider attach
//! (docs/dev/spec/node-local.md §7), acting as a center ([`FakeCenter`])
//! and as a capability provider on the node's control socket at once.
//!
//! The caller gets a pairing link and must pair the node under test with
//! it, give the fake center the settings grant `write`, allow the program
//! that runs this part (`std::env::current_exe()`) as a provider under
//! [`Setup::provider`], and start the node. The part writes its own policy
//! with `settings.set` (`user` mode and a deny rule for `echo.shout` before
//! the provider comes, allow rules for `echo.say`, `echo.fail` and
//! `echo.peek` below one folder once it is there), attaches an echo
//! provider, and calls it through the center's link. One action of the
//! provider, `odd`, has a schema outside the subset a center can check
//! (protocol.md §6), so the node must leave it out. Another, `peek`, takes
//! a path it reads (`x-nerve-path`), which the node decides the call by.
//!
//! Unix only: the provider attaches on a Unix socket, the control socket
//! of a node run by hand (with its token) or the provider socket of the
//! installed node (by its peer credentials, [`Attach::Peer`]).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

use nerve_proto::link::PairLink;
use nerve_proto::msg::method;
use nerve_proto::{ErrorCode, Message};

use crate::fake_center::{self, FakeCenter};
use crate::node_part::expect_code;
use crate::wire::{Recv, code_of};
use crate::{Report, ensure};

const WAIT: Duration = Duration::from_secs(15);

/// The section of the node-local spec every check of this part tests.
const SECTION: &str = "node-local 7";

/// The capability the part's provider adds.
pub const CAP: &str = "echo";

/// The folder the allow rule for `echo.peek` names. It need not exist: the
/// node resolves a path whose end is missing as it is written.
const PEEK_INSIDE: &str = "/nerve-conformance/inside";

/// What the caller says about the node it started.
#[derive(Debug, Clone)]
pub struct Setup {
    /// The socket the provider attaches on.
    pub socket: PathBuf,
    /// How that socket tells who asks.
    pub attach: Attach,
    /// The name `providers.allowed` gives the program that runs this part.
    pub provider: String,
}

/// How the node's socket tells who asks to attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// The control socket: each request carries the token in `ctl.token`
    /// beside it.
    Token,
    /// A socket that tells the caller by the account and process the
    /// kernel names (the installed node's provider socket): no token.
    Peer,
}

/// Every check, in order; each needs the ones before it.
pub const CHECKS: &[&str] = &[
    "a center may not allow a capability no provider offers",
    "a program providers.allowed does not name is refused",
    "an allowed provider attaches",
    "a second provider of the same name is refused",
    "the node tells the center that its descriptor changed",
    "the descriptor lists the capability with its provider",
    "an action whose schema is outside the subset is left out with its reason, and the others attach",
    "a center may allow an offered capability that does not sense, and the descriptor follows",
    "a call the policy allows reaches the provider and its answer comes back",
    "a provider's error comes back with its code",
    "a call the policy refuses never reaches the provider",
    "a call whose arguments do not fit the action's schema is invalid_args and never reaches the provider",
    "a path argument keeps its x-nerve-path marker, and the node decides the call by that path",
    "when the provider exits its capability leaves the descriptor",
    "a call to a provider that left is unknown_capability",
];

type Conn = crate::wire::Conn<tokio::net::TcpStream>;

/// Runs every provider check. `start` pairs the node under test with the
/// link it is given, allows this program as a provider and starts the node.
pub async fn run<F, Fut>(start: F) -> Report
where
    F: FnOnce(PairLink) -> Fut,
    Fut: Future<Output = Result<Setup, String>>,
{
    let mut r = Report::new("provider");
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
    let Some(mut link) = center.next_link(Duration::from_secs(30)).await else {
        r.check(
            "4.1",
            "the node dials the center",
            Err("no link within 30 s".into()),
        );
        return r;
    };
    let conn = &mut link.conn;
    if let Err(e) = fake_center::handshake(conn, &center.center_id, &paired).await {
        r.check("4.2", "the handshake", Err(e));
        return r;
    }
    let mut done = 0;
    let out = steps(conn, &setup, &mut |res| {
        r.check(SECTION, CHECKS[done], res);
        done += 1;
    })
    .await;
    if let Err(why) = out {
        for name in &CHECKS[done..] {
            r.skip(SECTION, name, &why);
        }
    }
    conn.bye("shutdown").await;
    r
}

/// The provider's side of the control socket.
struct Provider {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    w: tokio::net::unix::OwnedWriteHalf,
}

/// Sends `hello` as the provider `name` with the echo fragment: the
/// connection, and the node's answer (`ok` or the error text). `say` takes
/// a string `text`; `odd` takes one of two types, which the subset cannot
/// say.
async fn hello(
    socket: &Path,
    attach: Attach,
    name: &str,
) -> Result<(Provider, Result<Value, String>), String> {
    let token = match attach {
        Attach::Token => Some(
            std::fs::read_to_string(socket.with_file_name("ctl.token"))
                .map_err(|e| format!("cannot read the control socket's token: {e}"))?
                .trim()
                .to_string(),
        ),
        Attach::Peer => None,
    };
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("cannot connect to {}: {e}", socket.display()))?;
    let (r, mut w) = stream.into_split();
    let read = |text: &str| {
        json!({"effect": "read", "summary": text,
                                   "params": {"type": "object"}})
    };
    let mut say = read("Return the arguments.");
    say["params"] = json!({"type": "object", "required": ["text"],
                           "properties": {"text": {"type": "string"}}});
    let mut odd = read("Never offered: its schema is outside the subset.");
    odd["params"]["properties"] =
        json!({"n": {"oneOf": [{"type": "string"}, {"type": "integer"}]}});
    let mut peek = read("Return the path it reads.");
    peek["params"] = json!({"type": "object", "required": ["path"],
                            "properties": {"path": {"type": "string", "x-nerve-path": "read"}}});
    let fragment = json!([{"id": CAP, "summary": "Says back what it is sent.",
        "actions": {"say": say,
                    "shout": read("Never called: no rule allows it."),
                    "fail": read("Fails with io."),
                    "odd": odd,
                    "peek": peek}}]);
    let mut line = json!({"method": "hello",
                          "params": {"role": "provider", "name": name, "capabilities": fragment}});
    if let Some(t) = token {
        line["token"] = json!(t);
    }
    // A socket that refuses the caller says so as it connects, and may
    // close before the line is written: its answer is read all the same.
    let _ = w.write_all(format!("{line}\n").as_bytes()).await;
    let mut lines = BufReader::new(r).lines();
    let first = tokio::time::timeout(WAIT, lines.next_line())
        .await
        .map_err(|_| "no answer to hello".to_string())?
        .map_err(|e| e.to_string())?
        .ok_or("the node closed without answering hello")?;
    let v: Value = serde_json::from_str(&first).map_err(|e| e.to_string())?;
    let answer = match (v.get("ok"), v.get("error").and_then(Value::as_str)) {
        (Some(ok), None) => Ok(ok.clone()),
        (_, Some(e)) => Err(e.to_string()),
        _ => Err(format!("neither ok nor error: {v}")),
    };
    Ok((Provider { lines, w }, answer))
}

/// Serves the provider's calls until `stop` fires, then closes: `say`
/// returns its arguments, `fail` fails with `io`. Every action it is called
/// for lands in `seen`.
async fn serve(mut p: Provider, seen: Arc<Mutex<Vec<String>>>, mut stop: oneshot::Receiver<()>) {
    loop {
        let line = tokio::select! {
            l = p.lines.next_line() => match l {
                Ok(Some(l)) => l,
                _ => return,
            },
            _ = &mut stop => return,
        };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if v["method"] != "invoke" {
            continue;
        }
        let action = v["params"]["action"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        seen.lock().unwrap().push(action.clone());
        let reply = if action == "fail" {
            json!({"id": v["id"], "error": "it failed on purpose", "code": "io"})
        } else {
            json!({"id": v["id"], "ok": v["params"]["args"]})
        };
        if p.w
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn invoke(
    conn: &mut Conn,
    action: &str,
    args: Value,
) -> Result<Result<Value, nerve_proto::RpcError>, String> {
    conn.call(
        method::INVOKE,
        json!({"cap": CAP, "action": action, "args": args, "ctx": {}}),
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

/// The descriptor's `rev` now.
async fn rev(conn: &mut Conn) -> Result<u64, String> {
    let d = ok(conn
        .call(method::DESCRIBE, json!({"detail": "summary"}), WAIT)
        .await)?;
    d["rev"].as_u64().ok_or_else(|| format!("no rev in {d}"))
}

/// Waits for a `node/descriptor_changed` that names another rev than
/// `before`, skipping everything else: one an earlier change sent (a
/// `settings.set`) names `before` itself, as `before` was read after it.
/// The rev it names must be the one `describe` gives then.
async fn descriptor_changed(conn: &mut Conn, before: u64) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    let changed = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            Recv::Msg(Message::Notification { method: m, params })
                if m == method::EVENT
                    && params["cap"] == "node"
                    && params["name"] == "descriptor_changed"
                    && params["data"]["rev"] != json!(before) =>
            {
                break params["data"]["rev"].clone();
            }
            Recv::Msg(_) => {}
            Recv::Timeout => {
                return Err(format!(
                    "no node/descriptor_changed from rev {before} within 15 s"
                ));
            }
            other => return Err(format!("the link ended: {other:?}")),
        }
    };
    let now = rev(conn).await?;
    ensure(
        changed == json!(now),
        format!("descriptor_changed named rev {changed}, describe gives {now}"),
    )
}

/// The capability `CAP` of the descriptor now, if listed.
async fn listed(conn: &mut Conn) -> Result<Option<Value>, String> {
    let d = ok(conn
        .call(method::DESCRIBE, json!({"detail": "full"}), WAIT)
        .await)?;
    Ok(d["capabilities"]
        .as_array()
        .and_then(|caps| caps.iter().find(|c| c["id"] == CAP))
        .cloned())
}

/// Changes this center's policy with `settings.set`: `f` edits it.
async fn set_policy(
    conn: &mut Conn,
    f: impl FnOnce(&mut Value),
) -> Result<Result<Value, nerve_proto::RpcError>, String> {
    let got = ok(conn
        .call(
            method::GET,
            json!({"cap": "settings", "keys": ["document", "version"]}),
            WAIT,
        )
        .await)
    .map_err(|e| format!("settings get (the fake center needs the settings grant write): {e}"))?;
    let mut doc = got["document"].clone();
    if let Some(p) = doc["policy"].as_object_mut() {
        p.remove("until");
    }
    f(&mut doc["policy"]);
    conn.call(
        method::INVOKE,
        json!({"cap": "settings", "action": "set", "ctx": {},
               "args": {"document": doc, "if_version": got["version"]}}),
        WAIT,
    )
    .await
}

/// The actions the descriptor lists for `CAP`, sorted, once it lists it
/// with `provider` as its provider.
async fn actions(conn: &mut Conn, provider: &str) -> Result<Vec<String>, String> {
    let cap = listed(conn)
        .await?
        .ok_or("the descriptor does not list it")?;
    ensure(
        cap["provider"] == json!(provider),
        format!("its provider is {}", cap["provider"]),
    )?;
    let mut actions: Vec<String> = cap["actions"]
        .as_object()
        .map(|a| a.keys().cloned().collect())
        .unwrap_or_default();
    actions.sort();
    Ok(actions)
}

/// Runs the checks in [`CHECKS`] order, giving each result to `check`;
/// stops at the first failure.
async fn steps(
    conn: &mut Conn,
    setup: &Setup,
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

    // Before it comes the node cannot tell whether `echo` senses, so only
    // the owner may allow it.
    step(expect_code(
        set_policy(conn, |p| {
            p["mode"] = json!("allowlist");
            p["allow"] = json!([format!("{CAP}.say")]);
        })
        .await,
        ErrorCode::Forbidden,
    ))?;
    // User mode shows every action of it once it comes; a deny rule (which
    // anyone may add) keeps `shout` from running.
    ok(set_policy(conn, |p| {
        p["mode"] = json!("user");
        p["deny"] = json!([format!("{CAP}.shout")]);
    })
    .await)
    .map_err(|e| format!("settings set: {e}"))?;

    // Read after that change, so only a later one names another rev.
    let before = rev(conn).await?;

    let stranger = format!("{}-stranger", setup.provider);
    step(match hello(&setup.socket, setup.attach, &stranger).await {
        Ok((_, Err(_))) => Ok(()),
        Ok((_, Ok(v))) => Err(format!("it attached: {v}")),
        Err(e) => Err(e),
    })?;

    let (provider, answer) = hello(&setup.socket, setup.attach, &setup.provider).await?;
    let left_out = answer
        .as_ref()
        .map(|v| v["broken"].clone())
        .unwrap_or_default();
    step(answer.and_then(|v| {
        ensure(
            v["capabilities"] == json!([CAP]),
            format!("the answer names {v}"),
        )
    }))?;

    step(
        match hello(&setup.socket, setup.attach, &setup.provider).await {
            Ok((_, Err(_))) => Ok(()),
            Ok((_, Ok(v))) => Err(format!("a second one attached: {v}")),
            Err(e) => Err(e),
        },
    )?;

    step(descriptor_changed(conn, before).await)?;

    step(actions(conn, &setup.provider).await.and_then(|actions| {
        ensure(
            ["say", "fail", "peek"]
                .iter()
                .all(|a| actions.contains(&a.to_string())),
            format!("its actions are {actions:?}"),
        )
    }))?;

    step(actions(conn, &setup.provider).await.and_then(|actions| {
        ensure(
            !actions.iter().any(|a| a == "odd"),
            format!("its actions are {actions:?}"),
        )?;
        let named = left_out.as_array().is_some_and(|b| {
            b.iter().any(|b| {
                b["name"] == format!("{CAP}.odd")
                    && b["reason"].as_str().is_some_and(|r| !r.is_empty())
            })
        });
        ensure(
            named,
            format!("the hello answer names as left out: {left_out}"),
        )
    }))?;

    // Default deny again, with rules for three of its actions, `peek` only
    // below one folder: `echo` is offered now and does not sense, so the
    // center may write them.
    step(
        async {
            ok(set_policy(conn, |p| {
                p["mode"] = json!("allowlist");
                p["allow"] = json!([
                    format!("{CAP}.say"),
                    format!("{CAP}.fail"),
                    format!("{CAP}.peek:{PEEK_INSIDE}/*")
                ]);
            })
            .await)?;
            let actions = actions(conn, &setup.provider).await?;
            // No rule allows shout, so the center is not shown it.
            ensure(
                actions == ["fail", "peek", "say"],
                format!("its actions are {actions:?}"),
            )
        }
        .await,
    )?;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let (stop, stopped) = oneshot::channel();
    let served = tokio::spawn(serve(provider, seen.clone(), stopped));

    step(
        ok(invoke(conn, "say", json!({"text": "hello provider"})).await)
            .and_then(|v| ensure(v["text"] == "hello provider", format!("got {v}"))),
    )?;

    step(match invoke(conn, "fail", json!({})).await {
        Ok(Err(e)) => ensure(
            code_of(&e) == "io" && e.message.contains("it failed on purpose"),
            format!("got {} ({})", code_of(&e), e.message),
        ),
        Ok(Ok(v)) => Err(format!("succeeded with {v}")),
        Err(e) => Err(e),
    })?;

    // Lines to the provider keep their order: had the refused call been
    // forwarded, the provider would see it before the next say.
    step(
        async {
            expect_code(invoke(conn, "shout", json!({})).await, ErrorCode::Forbidden)?;
            ok(invoke(conn, "say", json!({"text": "again"})).await)?;
            let seen = seen.lock().unwrap().clone();
            ensure(
                !seen.iter().any(|a| a == "shout"),
                format!("the provider was called for {seen:?}"),
            )
        }
        .await,
    )?;

    // As above, a call that had been forwarded would come before the next.
    step(
        async {
            let before = seen.lock().unwrap().len();
            expect_code(
                invoke(conn, "say", json!({"text": 5})).await,
                ErrorCode::InvalidArgs,
            )?;
            ok(invoke(conn, "say", json!({"text": "fits"})).await)?;
            let seen = seen.lock().unwrap().clone();
            ensure(
                seen.len() == before + 1,
                format!("the provider was called for {:?}", &seen[before..]),
            )
        }
        .await,
    )?;

    // The marker is published as the provider wrote it, and the path is
    // the call's rule target: below the folder the rule names the call
    // reaches the provider with that path; elsewhere it is refused and, as
    // above, never forwarded.
    step(
        async {
            let cap = listed(conn)
                .await?
                .ok_or("the descriptor does not list it")?;
            let mark = &cap["actions"]["peek"]["params"]["properties"]["path"]["x-nerve-path"];
            ensure(mark == "read", format!("peek's path is marked {mark}"))?;
            let inside = format!("{PEEK_INSIDE}/a");
            let v = ok(invoke(conn, "peek", json!({"path": inside})).await)?;
            ensure(v["path"] == json!(inside), format!("got {v}"))?;
            let before = seen.lock().unwrap().len();
            expect_code(
                invoke(
                    conn,
                    "peek",
                    json!({"path": "/nerve-conformance/outside/a"}),
                )
                .await,
                ErrorCode::Forbidden,
            )?;
            ok(invoke(conn, "say", json!({"text": "after"})).await)?;
            let seen = seen.lock().unwrap().clone();
            ensure(
                seen[before..] == ["say"],
                format!("the provider was called for {:?}", &seen[before..]),
            )
        }
        .await,
    )?;

    let before = rev(conn).await?;
    let _ = stop.send(());
    let _ = served.await;
    step(
        async {
            descriptor_changed(conn, before).await?;
            match listed(conn).await? {
                None => Ok(()),
                Some(c) => Err(format!("still listed: {c}")),
            }
        }
        .await,
    )?;

    step(expect_code(
        invoke(conn, "say", json!({"text": "gone"})).await,
        ErrorCode::UnknownCapability,
    ))?;
    Ok(())
}
