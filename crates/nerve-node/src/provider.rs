//! Capability providers (docs/dev/spec/node-local.md §7): local programs
//! the owner allowed in `providers.allowed` that add capabilities to the
//! node over its control socket.
//!
//! A provider sends `hello` with role `provider` and a descriptor fragment.
//! The node checks that the program on the other end is the one the owner
//! named, keeps the connection, and lists the fragment's capabilities with
//! `provider: <name>` to every center, each cut by that center's policy.
//! A center's call to one of them is decided and audited by the node like
//! any other; only an allowed call is forwarded. The capabilities go when
//! the connection does. A provider never talks to a center and changes no
//! policy.
//!
//! Every action's schemas must keep to the subset a center checks
//! (nerve_proto::schema). An action whose do not is left out with the
//! reason, which `status` shows; the provider's other actions attach. A call
//! whose arguments do not fit its action's schema is refused by the node and
//! never reaches the provider (crate::link).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot};

use nerve_policy::NodeConfig;
use nerve_proto::descriptor::{Action, Capability, Effect, Exposure, bad_member_name};
use nerve_proto::schema::{self, Role};
use nerve_proto::{ErrorCode, RpcError};

use crate::daemon::{Shared, lock};

/// The capabilities and profiles that are the node's own, and the ones the
/// center serves itself on every node (`job`, `stream`): a provider may not
/// take their names, so no call meant for them reaches it, and a center
/// never leaves its capability out for the name.
pub const BUILT_IN: &[&str] = &["node", "fs", "exec", "settings", "audit", "job", "stream"];

/// How many capabilities one provider may add, and actions one capability
/// may have: far past what a program offers, and a bound on what every
/// descriptor carries.
pub const MAX_CAPS: usize = 16;
pub const MAX_ACTIONS: usize = 64;

/// Lines queued for one provider before a call waits for room.
const QUEUE: usize = 64;

/// The `hello` of a provider (the params of its first request).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    role: String,
    name: String,
    capabilities: Vec<Fragment>,
}

/// One capability of a provider's fragment. It offers actions only: the
/// node forwards calls, not events, state or streams, so a fragment that
/// declares those is refused as an unknown field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    id: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    summary: String,
    actions: BTreeMap<String, FragmentAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FragmentAction {
    effect: Effect,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    result: Value,
}

/// An action of a fragment the node left out, as `cap.action`, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Broken {
    pub name: String,
    pub reason: String,
}

/// One attached provider. The registry holds the only lasting reference:
/// dropping it drops `tx`, which ends the connection, and `pending`, which
/// fails the calls that wait for an answer.
struct Attached {
    name: String,
    /// The program the node checked it against, as the config named it.
    exe: String,
    /// Tells this attachment from a later one of the same name.
    serial: u64,
    caps: Vec<Capability>,
    /// The actions of its fragment that were left out.
    broken: Vec<Broken>,
    tx: mpsc::Sender<Value>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, RpcError>>>>,
    next: AtomicU64,
}

/// The attached providers, by name.
#[derive(Default)]
pub(crate) struct Providers {
    attached: Mutex<BTreeMap<String, Arc<Attached>>>,
    serial: AtomicU64,
}

impl Providers {
    /// Every capability the attached providers add, by provider name.
    pub fn caps(&self) -> Vec<Capability> {
        lock(&self.attached)
            .values()
            .flat_map(|a| a.caps.iter().cloned())
            .collect()
    }

    /// What only the owner may turn on or allow, as a test of a `caps` key
    /// or an allow rule's scope (`cap` or `cap.action`): a capability an
    /// attached provider offers with an action that senses or actuates; one
    /// that is neither the node's own nor offered now; and an action that an
    /// offered capability does not have now. The node cannot tell what such
    /// a capability or action will do once a provider offers it, so a
    /// center's entry for it waits for the owner. An entry for an offered
    /// capability that neither senses nor actuates, or for one of its
    /// actions, passes; the node cannot check it ahead, so it still counts
    /// when a provider later offers that capability or action with a sense
    /// or actuate action under the same name.
    pub fn owner_only(&self) -> impl Fn(&str) -> bool + use<> {
        let mut sensing = BTreeSet::new();
        let mut offered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for c in lock(&self.attached).values().flat_map(|a| a.caps.iter()) {
            offered.insert(c.id.clone(), c.actions.keys().cloned().collect());
            if c.actions
                .values()
                .any(|a| matches!(a.effect, Effect::Sense | Effect::Actuate))
            {
                sensing.insert(c.id.clone());
            }
        }
        move |scope| {
            let (cap, action) = match scope.split_once('.') {
                Some((c, a)) => (c, Some(a)),
                None => (scope, None),
            };
            if BUILT_IN.contains(&cap) {
                return false;
            }
            if sensing.contains(cap) {
                return true;
            }
            match (offered.get(cap), action) {
                (None, _) => true,
                (Some(actions), Some(a)) => !actions.contains(a),
                (Some(_), None) => false,
            }
        }
    }

    /// What `status` shows of them: each one's capabilities, and the
    /// actions left out with their reasons.
    pub fn status(&self) -> Value {
        let list: Vec<Value> = lock(&self.attached)
            .values()
            .map(|a| {
                let caps: Vec<&str> = a.caps.iter().map(|c| c.id.as_str()).collect();
                json!({"name": a.name, "capabilities": caps, "broken": a.broken})
            })
            .collect();
        json!(list)
    }

    /// Detaches every provider (the node stops). Their connections end.
    pub fn detach_all(&self) {
        let gone = std::mem::take(&mut *lock(&self.attached));
        for name in gone.keys() {
            tracing::info!("provider {name} detached: the node stops");
        }
    }

    /// Detaches the providers that `cfg` no longer allows, or allows as
    /// another program than the one each was checked against. Whether any
    /// went.
    pub fn follow_config(&self, cfg: &NodeConfig) -> bool {
        let mut attached = lock(&self.attached);
        let before = attached.len();
        attached.retain(|name, a| {
            let kept = cfg.providers.get(name).is_some_and(|p| p.exe == a.exe);
            if !kept {
                tracing::info!(
                    "provider {name} detached: providers.allowed no longer names it with this program"
                );
            }
            kept
        });
        attached.len() != before
    }

    /// Removes the attachment `serial` of `name`, if it is still the one
    /// held. Whether it was.
    fn remove(&self, name: &str, serial: u64) -> bool {
        let mut attached = lock(&self.attached);
        if attached.get(name).is_some_and(|a| a.serial == serial) {
            attached.remove(name);
            true
        } else {
            false
        }
    }

    /// Forwards a call the node allowed to `provider` and waits for its
    /// answer. Dropping the future (a cancel, a deadline, the link's end)
    /// tells the provider to cancel it.
    pub async fn invoke(
        &self,
        provider: &str,
        cap: &str,
        action: &str,
        args: Map<String, Value>,
    ) -> Result<Value, RpcError> {
        let gone = || {
            RpcError::new(
                ErrorCode::Unavailable,
                format!("the provider {provider} is not attached now"),
            )
        };
        let (tx, rx, guard) = {
            let a = lock(&self.attached)
                .get(provider)
                .cloned()
                .ok_or_else(gone)?;
            let id = a.next.fetch_add(1, Ordering::Relaxed);
            let (answer, rx) = oneshot::channel();
            lock(&a.pending).insert(id, answer);
            let guard = Waiting {
                attached: Arc::downgrade(&a),
                id,
            };
            (a.tx.clone(), rx, guard)
        };
        let line = json!({"id": guard.id, "method": "invoke",
                          "params": {"cap": cap, "action": action, "args": args}});
        if tx.send(line).await.is_err() {
            return Err(gone());
        }
        drop(tx);
        let answer = rx.await;
        drop(guard);
        answer.unwrap_or_else(|_| Err(gone()))
    }
}

/// A call forwarded to a provider. Dropped while the call still waits for
/// its answer, it takes the call out and tells the provider to cancel it;
/// an answered call is out already.
struct Waiting {
    attached: Weak<Attached>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let Some(a) = self.attached.upgrade() else {
            return;
        };
        if lock(&a.pending).remove(&self.id).is_some() {
            let cancel = json!({"method": "cancel", "params": {"id": self.id}});
            let _ = a.tx.try_send(cancel);
        }
    }
}

impl Attached {
    /// One line from the provider: the answer to a call. Anything else is
    /// dropped; a call it does not name stays waiting.
    fn answer(&self, v: Value) {
        let Some(id) = v.get("id").and_then(Value::as_u64) else {
            tracing::debug!("provider {}: a line without an id was dropped", self.name);
            return;
        };
        let Some(waiting) = lock(&self.pending).remove(&id) else {
            return;
        };
        let r = match (v.get("ok"), v.get("error")) {
            (Some(ok), None) => Ok(ok.clone()),
            (None, Some(e)) => Err(provider_error(
                &self.name,
                v.get("code").and_then(Value::as_str),
                e.as_str().unwrap_or("the provider failed"),
            )),
            _ => Err(RpcError::internal(format!(
                "the provider {} answered neither ok nor error",
                self.name
            ))),
        };
        let _ = waiting.send(r);
    }
}

/// A provider's error as the center gets it. A provider may say what a
/// program can go wrong with; `forbidden`, `disabled` and the codes of the
/// link are the node's own words, and turn into `internal`.
fn provider_error(name: &str, code: Option<&str>, message: &str) -> RpcError {
    use ErrorCode::*;
    let code = match code.map(ErrorCode::parse) {
        Some(c @ (InvalidArgs | Unavailable | Busy | Timeout | TooLarge | Internal)) => c,
        Some(Other(c)) if matches!(c.as_str(), "conflict" | "bad_path" | "io") => Other(c),
        _ => Internal,
    };
    RpcError::new(code, format!("{name}: {message}"))
}

/// Why a hello is refused that comes from a program other than the one
/// the owner named.
fn other_program(name: &str, running: &Path, allowed: &Path) -> String {
    format!(
        "refused: the provider {name} must be {}, and this is {}",
        allowed.display(),
        running.display()
    )
}

/// The program `pid` runs, as the kernel resolved it. Linux only: elsewhere
/// the node cannot tell, and no provider attaches.
fn program_of(pid: u32) -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| format!("refused: the node cannot tell which program asks: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err("refused: providers attach on Linux only for now".into())
    }
}

/// Whether `running` (from the kernel) is the program `allowed` names,
/// once `allowed` is resolved. A program replaced while it runs reads as
/// `… (deleted)` and is not.
fn same_program(running: &Path, allowed: &Path) -> Result<bool, String> {
    let allowed =
        std::fs::canonicalize(allowed).map_err(|e| format!("{}: {e}", allowed.display()))?;
    Ok(running == allowed)
}

/// Why an action's schemas are outside the subset a center checks, if they
/// are. A missing `params` takes any arguments, a missing `result` says
/// nothing of the result. The reason is brief: `status`, the hello answer
/// and the log repeat it, and it holds the provider's own names.
fn outside_subset(params: &Value, result: &Value) -> Option<String> {
    if let Err(e) = schema::check(params, Role::Params) {
        return Some(schema::brief(&format!("params: {e}")));
    }
    if !result.is_null()
        && let Err(e) = schema::check(result, Role::Result)
    {
        return Some(schema::brief(&format!("result: {e}")));
    }
    None
}

/// Checks a fragment and makes its capabilities, each with `provider:
/// name`, and the actions left out because their schemas are outside the
/// subset; a capability left with no action goes too. `taken` holds the
/// capability ids of the other attached providers.
fn capabilities(
    name: &str,
    fragment: Vec<Fragment>,
    taken: &BTreeSet<String>,
) -> Result<(Vec<Capability>, Vec<Broken>), String> {
    if fragment.is_empty() || fragment.len() > MAX_CAPS {
        return Err(format!("a provider adds 1 to {MAX_CAPS} capabilities"));
    }
    let mut seen = BTreeSet::new();
    let mut caps = Vec::new();
    let mut broken = Vec::new();
    for f in fragment {
        // A center leaves out a longer name, and its agent would never see
        // it: refused here, the program learns why.
        if let Some(why) = bad_member_name(&f.id) {
            return Err(format!("capability {why}"));
        }
        if BUILT_IN.contains(&f.id.as_str()) {
            return Err(format!(
                "capability {}: the name is the node's or the center's own",
                f.id
            ));
        }
        if BUILT_IN.contains(&f.profile.as_str()) {
            return Err(format!(
                "capability {}: the profile {} is the node's or the center's own",
                f.id, f.profile
            ));
        }
        if taken.contains(&f.id) {
            return Err(format!(
                "capability {} is added by another provider already",
                f.id
            ));
        }
        if !seen.insert(f.id.clone()) {
            return Err(format!("capability {} is named twice", f.id));
        }
        if f.actions.is_empty() || f.actions.len() > MAX_ACTIONS {
            return Err(format!("capability {}: 1 to {MAX_ACTIONS} actions", f.id));
        }
        let mut actions = BTreeMap::new();
        for (a, decl) in f.actions {
            if let Some(why) = bad_member_name(&a) {
                return Err(format!("capability {}: action {why}", f.id));
            }
            // Arguments are always an object; no schema takes any.
            let params = match decl.params {
                Value::Null => json!({"type": "object"}),
                p => p,
            };
            if let Some(reason) = outside_subset(&params, &decl.result) {
                broken.push(Broken {
                    name: format!("{}.{a}", f.id),
                    reason,
                });
                continue;
            }
            actions.insert(
                a,
                Action {
                    effect: decl.effect,
                    summary: decl.summary,
                    params,
                    result: decl.result,
                    exposure: None,
                },
            );
        }
        if actions.is_empty() {
            continue;
        }
        caps.push(Capability {
            id: f.id,
            profile: f.profile,
            provider: name.to_string(),
            exposure: Exposure::On,
            summary: f.summary,
            actions,
            events: BTreeMap::new(),
            state: Value::Null,
            streams: BTreeMap::new(),
        });
    }
    if caps.is_empty() {
        let why: Vec<String> = broken
            .iter()
            .map(|b| format!("{}: {}", b.name, b.reason))
            .collect();
        return Err(format!(
            "no action has schemas a center can check: {}",
            why.join("; ")
        ));
    }
    Ok((caps, broken))
}

/// `hello` on the control socket from the process `pid`: attaches it as the
/// provider it names when `providers.allowed` names that provider with the
/// program it runs. The answer keeps the connection
/// ([`nerve_transport::ctl::Reply::Session`]); its end detaches it.
pub(crate) fn attach(
    shared: &Arc<Shared>,
    params: Value,
    pid: Option<u32>,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    match check(shared, params, pid) {
        Ok(reply) => reply,
        Err(e) => {
            tracing::warn!("a provider was not attached: {e}");
            Reply::Err(e)
        }
    }
}

fn check(
    shared: &Arc<Shared>,
    params: Value,
    pid: Option<u32>,
) -> Result<nerve_transport::ctl::Reply, String> {
    let hello: Hello = serde_json::from_value(params).map_err(|e| format!("bad hello: {e}"))?;
    if hello.role != "provider" {
        return Err(format!(
            "hello with role {:?}: only the role provider attaches",
            hello.role
        ));
    }
    let name = hello.name;
    let cfg = shared.config();
    let allowed = cfg
        .providers
        .get(&name)
        .ok_or_else(|| format!("refused: providers.allowed names no provider {name}"))?;
    let pid = pid.ok_or("refused: the node cannot tell which process asks")?;
    let running = program_of(pid)?;
    let want = Path::new(&allowed.exe);
    if !same_program(&running, want).map_err(|e| format!("refused: the provider {name}: {e}"))? {
        return Err(other_program(&name, &running, want));
    }
    let (out_tx, out_rx) = mpsc::channel(QUEUE);
    let (in_tx, mut in_rx) = mpsc::channel::<Value>(QUEUE);
    let attached = {
        let mut held = lock(&shared.providers.attached);
        if held.contains_key(&name) {
            return Err(format!("a provider {name} is attached already"));
        }
        let taken = held
            .values()
            .flat_map(|a| a.caps.iter().map(|c| c.id.clone()))
            .collect();
        let (caps, broken) = capabilities(&name, hello.capabilities, &taken)?;
        let a = Arc::new(Attached {
            name: name.clone(),
            exe: allowed.exe.clone(),
            serial: shared.providers.serial.fetch_add(1, Ordering::Relaxed),
            caps,
            broken,
            tx: out_tx,
            pending: Mutex::default(),
            next: AtomicU64::new(1),
        });
        held.insert(name.clone(), a.clone());
        a
    };
    let ids: Vec<String> = attached.caps.iter().map(|c| c.id.clone()).collect();
    let broken = attached.broken.clone();
    tracing::info!(
        "provider {name} attached ({}): {}",
        running.display(),
        ids.join(", ")
    );
    for b in &broken {
        tracing::warn!("provider {name}: {} left out: {}", b.name, b.reason);
    }
    let (weak, serial) = (Arc::downgrade(&attached), attached.serial);
    drop(attached);
    let s = shared.clone();
    let task_name = name.clone();
    tokio::spawn(async move {
        while let Some(v) = in_rx.recv().await {
            match weak.upgrade() {
                Some(a) => a.answer(v),
                None => break,
            }
        }
        // The connection ended: the provider went, or the node let it go.
        if s.providers.remove(&task_name, serial) {
            tracing::info!("provider {task_name} detached");
            s.bump();
        }
    });
    shared.bump();
    Ok(nerve_transport::ctl::Reply::Session {
        ok: json!({"name": name, "capabilities": ids, "broken": broken}),
        out: out_rx,
        inbound: in_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(v: Value) -> Vec<Fragment> {
        serde_json::from_value(v).unwrap()
    }

    fn echo() -> Value {
        json!([{"id": "echo", "summary": "Says it back.",
                "actions": {"say": {"effect": "read", "params": {"type": "object"}}}}])
    }

    #[test]
    fn a_fragment_becomes_capabilities_of_its_provider() {
        let (caps, broken) = capabilities("desk", fragment(echo()), &BTreeSet::new()).unwrap();
        assert_eq!(broken, []);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].id, "echo");
        assert_eq!(caps[0].provider, "desk");
        assert_eq!(caps[0].exposure, Exposure::On);
        assert_eq!(caps[0].actions["say"].effect, Effect::Read);
    }

    /// An action whose schemas a center cannot check is left out with the
    /// reason, and the rest attaches; one without params takes any
    /// arguments. A capability left with no action goes, and a fragment left
    /// with none is refused.
    #[test]
    fn an_action_outside_the_schema_subset_is_left_out() {
        let one_of = json!({"type": "object", "properties": {
            "level": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}});
        let frag = json!([
            {"id": "lamp", "actions": {
                "on": {"effect": "write"},
                "dim": {"effect": "write", "params": one_of},
                "get": {"effect": "read", "params": {"type": "object"},
                        "result": {"$ref": "#/defs/x"}}}},
            {"id": "fan", "actions": {"spin": {"effect": "write", "params": {"type": "string"}}}}
        ]);
        let (caps, broken) = capabilities("desk", fragment(frag), &BTreeSet::new()).unwrap();
        let ids: Vec<&str> = caps.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["lamp"]);
        let actions: Vec<&String> = caps[0].actions.keys().collect();
        assert_eq!(actions, ["on"]);
        assert_eq!(caps[0].actions["on"].params, json!({"type": "object"}));
        let names: Vec<&str> = broken.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["lamp.dim", "lamp.get", "fan.spin"]);
        assert!(
            broken[0]
                .reason
                .starts_with("params: /properties/level/oneOf: "),
            "{broken:?}"
        );
        assert!(
            broken[1].reason.starts_with("result: /$ref: "),
            "{broken:?}"
        );
        assert!(
            broken[2].reason.contains("must be type \"object\""),
            "{broken:?}"
        );

        let none = json!([{"id": "fan", "actions": {"spin": {"effect": "write", "params": {}}}}]);
        let e = capabilities("desk", fragment(none), &BTreeSet::new()).unwrap_err();
        assert!(
            e.contains("no action") && e.contains("fan.spin: params"),
            "{e}"
        );
    }

    /// The reason names the provider's own property names, so `status`
    /// shows it as one line of its own, cut.
    #[test]
    fn the_reason_for_leaving_out_an_action_is_one_short_line() {
        let long = "/".repeat(4000);
        let frag = json!([{"id": "lamp", "actions": {
            "on": {"effect": "write"},
            "dim": {"effect": "write", "params": {"type": "object", "properties": {
                "x\nprovider other attached: fake\u{1b}[2J": {"type": "string", "pattern": "a"}}}},
            "get": {"effect": "read", "result": {"type": "object", long: 1}}}}]);
        let (_, broken) = capabilities("desk", fragment(frag), &BTreeSet::new()).unwrap();
        let names: Vec<&str> = broken.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["lamp.dim", "lamp.get"]);
        for b in &broken {
            assert!(!b.reason.chars().any(char::is_control), "{b:?}");
            assert!(
                b.reason.chars().count() <= schema::BRIEF_MAX + 1,
                "{}",
                b.reason.len()
            );
        }
        assert!(
            broken[0]
                .reason
                .starts_with("params: /properties/x provider other attached: fake [2J/pattern"),
            "{broken:?}"
        );
        assert!(broken[1].reason.ends_with('…'), "{broken:?}");
    }

    #[test]
    fn a_bad_fragment_is_refused() {
        let taken: BTreeSet<String> = ["camera".to_string()].into();
        for (bad, why) in [
            (json!([]), "1 to 16"),
            (
                json!([{"id": "my.cap", "actions": {"a": {"effect": "read"}}}]),
                "capability name",
            ),
            (
                json!([{"id": "fs", "actions": {"a": {"effect": "read"}}}]),
                "capability fs: the name is the node's or the center's own",
            ),
            // The center serves `job.status` and `job.cancel` on every node,
            // and keeps `stream` for streams.
            (
                json!([{"id": "job", "actions": {"status": {"effect": "read"}}}]),
                "capability job: the name is the node's or the center's own",
            ),
            (
                json!([{"id": "stream", "actions": {"read": {"effect": "read"}}}]),
                "capability stream: the name",
            ),
            (
                json!([{"id": "x", "profile": "job", "actions": {"a": {"effect": "read"}}}]),
                "profile job",
            ),
            (
                json!([{"id": "x", "profile": "exec", "actions": {"a": {"effect": "read"}}}]),
                "profile exec",
            ),
            (
                json!([{"id": "camera", "actions": {"a": {"effect": "sense"}}}]),
                "another provider",
            ),
            (
                json!([{"id": "x", "actions": {"a": {"effect": "read"}}},
                    {"id": "x", "actions": {"a": {"effect": "read"}}}]),
                "twice",
            ),
            (json!([{"id": "x", "actions": {}}]), "1 to 64 actions"),
            (
                json!([{"id": "x", "actions": {"a.b": {"effect": "read"}}}]),
                "action name",
            ),
            // A name a center would leave out, said by its length.
            (
                json!([{"id": "c".repeat(65), "actions": {"a": {"effect": "read"}}}]),
                "capability name of 65 bytes: at most 64",
            ),
            (
                json!([{"id": "x", "actions": {"a".repeat(65): {"effect": "read"}}}]),
                "capability x: action name of 65 bytes: at most 64",
            ),
        ] {
            let e = capabilities("desk", fragment(bad.clone()), &taken).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // A provider offers actions only, and says nothing of who serves them.
        for extra in [
            json!({"events": {}}),
            json!({"state": {}}),
            json!({"streams": {}}),
            json!({"provider": "node"}),
            json!({"exposure": "on"}),
        ] {
            let mut cap = echo()[0].clone();
            cap.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(
                serde_json::from_value::<Vec<Fragment>>(json!([cap])).is_err(),
                "{extra}"
            );
        }
        let many: Vec<Value> = (0..17)
            .map(|i| json!({"id": format!("c{i}"), "actions": {"a": {"effect": "read"}}}))
            .collect();
        assert!(capabilities("desk", fragment(json!(many)), &BTreeSet::new()).is_err());
    }

    #[test]
    fn a_provider_error_keeps_only_codes_a_program_may_give() {
        for (code, want) in [
            (Some("invalid_args"), "invalid_args"),
            (Some("io"), "io"),
            (Some("conflict"), "conflict"),
            (Some("busy"), "busy"),
            (Some("forbidden"), "internal"),
            (Some("disabled"), "internal"),
            (Some("connection_lost"), "internal"),
            (Some("made-up"), "internal"),
            (None, "internal"),
        ] {
            let e = provider_error("desk", code, "no");
            assert_eq!(e.kind().as_str(), want, "{code:?}");
            assert_eq!(e.message, "desk: no");
        }
    }

    /// The program is compared once the allowed path is resolved: a link to
    /// it is the program, another program is not, and neither is a missing
    /// one.
    #[cfg(unix)]
    #[test]
    fn the_program_is_compared_by_its_real_path() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("provider");
        std::fs::write(&real, "").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let other = d.path().join("other");
        std::fs::write(&other, "").unwrap();
        let running = std::fs::canonicalize(&real).unwrap();
        assert_eq!(same_program(&running, &real), Ok(true));
        assert_eq!(same_program(&running, &link), Ok(true));
        assert_eq!(same_program(&running, &other), Ok(false));
        assert!(same_program(&running, &d.path().join("none")).is_err());
        let deleted = PathBuf::from(format!("{} (deleted)", running.display()));
        assert_eq!(same_program(&deleted, &real), Ok(false));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_program_of_this_process_is_its_exe() {
        let me = program_of(std::process::id()).unwrap();
        assert_eq!(
            me,
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        assert!(program_of(u32::MAX).is_err());
    }
}
