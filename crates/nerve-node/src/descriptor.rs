//! The descriptor one center sees (spec §6): the node's capabilities, cut to
//! what this center's policy shows.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use nerve_policy::config::{CapSetting, CenterPolicy, Mode, SettingsGrant};
use nerve_policy::{CenterEntry, NodeConfig, rules};
use nerve_proto::descriptor::{
    Action, Capability, Descriptor, Direction, Effect, EventDecl, Exposure, NodeInfo, Software,
    StreamDecl, StreamKind,
};

pub const SOFTWARE: &str = "nerve-node";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capabilities whose events need no `sub` (spec §5.1).
pub const IMPLICIT: &[&str] = &["node", "settings"];

/// The node's name: `[node] name`, else derived from the host name.
pub fn node_name(cfg: &NodeConfig) -> String {
    cfg.node
        .name
        .clone()
        .unwrap_or_else(|| nerve_proto::node_name_from_host(&host_name()))
}

pub fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
        })
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "node".into())
}

fn action(effect: Effect, summary: &str, params: Value, result: Value) -> Action {
    Action {
        effect,
        summary: summary.into(),
        params,
        result,
    }
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required,
           "additionalProperties": false})
}

/// An argument that may be left out. Its parser reads `null` as left out,
/// so the schema takes `null` as well: a center checks arguments against it
/// and must not refuse what the node takes.
fn opt(mut s: Value) -> Value {
    if let Some(t) = s.get("type").cloned() {
        s["type"] = json!([t, "null"]);
    }
    if let Some(Value::Array(e)) = s.get_mut("enum") {
        e.push(Value::Null);
    }
    s
}

fn event(summary: &str, implicit: bool, data: Value) -> EventDecl {
    EventDecl {
        summary: summary.into(),
        implicit,
        data,
    }
}

fn cap(id: &str, profile: &str, exposure: Exposure, summary: &str) -> Capability {
    Capability {
        id: id.into(),
        profile: profile.into(),
        provider: "node".into(),
        exposure,
        summary: summary.into(),
        actions: BTreeMap::new(),
        events: BTreeMap::new(),
        state: Value::Null,
        streams: BTreeMap::new(),
    }
}

fn node_cap() -> Capability {
    let mut c = cap(
        "node",
        "node",
        Exposure::On,
        "This node: its status and changes.",
    );
    c.state = obj(
        json!({"status": {"enum": ["online", "busy", "paused"]}}),
        &["status"],
    );
    c.events.insert(
        "descriptor_changed".into(),
        event(
            "The descriptor changed; fetch it again.",
            true,
            obj(json!({"rev": {"type": "integer"}}), &["rev"]),
        ),
    );
    c.events.insert(
        "going_away".into(),
        event(
            "The node is about to drop the link.",
            true,
            obj(json!({"reason": {"type": "string"}}), &["reason"]),
        ),
    );
    c.events.insert(
        "capability_changed".into(),
        event(
            "A capability changed.",
            true,
            obj(json!({"cap": {"type": "string"}}), &["cap"]),
        ),
    );
    c
}

/// The `path` argument of the `fs` actions. A Windows node says how its
/// drives are written, so a model does not send `C:\...`, a `bad_path`.
fn path_param(windows: bool) -> Value {
    let text = if windows {
        "absolute path, the drive as a folder: /c/Users/x for C:\\Users\\x"
    } else {
        "absolute path"
    };
    json!({"type": "string", "description": text})
}

/// The `cwd` argument of `exec.run`: it takes the same wire form as an `fs`
/// path, so a Windows node says so here as well. A Unix node's is unchanged.
fn cwd_param(windows: bool) -> Value {
    opt(if windows {
        json!({"type": "string",
               "description": "working folder, the drive as a folder: /c/Users/x for C:\\Users\\x"})
    } else {
        json!({"type": "string"})
    })
}

fn fs_cap(exposure: Exposure) -> Capability {
    let mut c = cap(
        "fs",
        "fs",
        exposure,
        "Files on this machine: stat, list, read, grep, find and write.",
    );
    let path = path_param(cfg!(windows));
    let ty = json!({"enum": ["file", "dir", "link", "other"]});
    let a = &mut c.actions;
    a.insert(
        "stat".into(),
        action(
            Effect::Read,
            "Type, size and modification time of a path.",
            obj(json!({"path": path}), &["path"]),
            obj(
                json!({"type": ty, "size": {"type": "integer"}, "mtime_ms": {"type": "integer"}}),
                &["type", "size", "mtime_ms"],
            ),
        ),
    );
    a.insert(
        "list".into(),
        action(
            Effect::Read,
            "The entries of a directory.",
            obj(json!({"path": path}), &["path"]),
            obj(
                json!({"entries": {"type": "array", "items": obj(
                    json!({"name": {"type": "string"}, "type": ty, "size": {"type": "integer"}}),
                    &["name", "type", "size"])}}),
                &["entries"],
            ),
        ),
    );
    a.insert(
        "read".into(),
        action(
            Effect::Read,
            "A file's content, utf8 or base64, with its etag.",
            obj(
                json!({"path": path, "offset": opt(json!({"type": "integer", "minimum": 0})),
                       "length": opt(json!({"type": "integer", "minimum": 0}))}),
                &["path"],
            ),
            obj(
                json!({"content": {"type": "string"}, "encoding": {"enum": ["utf8", "base64"]},
                       "size": {"type": "integer"}, "etag": {"type": "string"}}),
                &["content", "encoding", "size", "etag"],
            ),
        ),
    );
    a.insert(
        "grep".into(),
        action(
            Effect::Read,
            "Lines containing a literal pattern, below a path.",
            obj(
                json!({"path": path, "pattern": {"type": "string", "minLength": 1},
                       "glob": opt(json!({"type": "string"})),
                       "max": opt(json!({"type": "integer", "minimum": 1}))}),
                &["path", "pattern"],
            ),
            obj(
                json!({"matches": {"type": "array", "items": obj(
                    json!({"path": {"type": "string"}, "line": {"type": "integer"},
                           "text": {"type": "string"}}), &["path", "line", "text"])},
                       "truncated": {"type": "boolean"}}),
                &["matches", "truncated"],
            ),
        ),
    );
    a.insert(
        "find".into(),
        action(
            Effect::Read,
            "Paths below a path that match a glob.",
            obj(
                json!({"path": path, "glob": {"type": "string"},
                       "max": opt(json!({"type": "integer", "minimum": 1}))}),
                &["path", "glob"],
            ),
            obj(
                json!({"paths": {"type": "array", "items": {"type": "string"}},
                       "truncated": {"type": "boolean"}}),
                &["paths", "truncated"],
            ),
        ),
    );
    a.insert(
        "write".into(),
        action(
            Effect::Write,
            "Writes a whole file; if_match guards against a concurrent change.",
            obj(
                json!({"path": path, "content": {"type": "string"},
                       "encoding": opt(json!({"enum": ["utf8", "base64"]})),
                       "if_match": opt(json!({"type": "string"}))}),
                &["path", "content"],
            ),
            obj(
                json!({"etag": {"type": "string"}, "size": {"type": "integer"}}),
                &["etag", "size"],
            ),
        ),
    );
    c
}

/// `timeout_ms` with the run-time limits in it, as `memory_mb` has its own:
/// the params are what the model reads of this node's limits.
///
/// The most is said in words, not as `maximum`: a larger value is not
/// refused but cut to it, and 0 is the same as none (protocol.md §7.3), so
/// the schema takes every value the node does.
fn timeout_param(t: &crate::exec::Timeouts) -> Value {
    let ms = |d: std::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let max = ms(t.max);
    opt(
        json!({"type": "integer", "minimum": 0, "default": ms(t.limit(None).after),
           "description": format!("milliseconds, at most {max}: a larger value gets {max}; 0 gets the default")}),
    )
}

/// The `call` of `exec.signal` and of the `exit` event: the id of the
/// `invoke` that runs the command, which a center gives as a number.
fn call_param() -> Value {
    json!({"type": "integer", "minimum": 0})
}

/// `limits` give the defaults and the most of what a call may ask its
/// command to be held to, `timeouts` the time it gets.
fn exec_cap(
    exposure: Exposure,
    shell: Option<&str>,
    windows: bool,
    limits: &nerve_policy::config::CommandLimits,
    timeouts: &crate::exec::Timeouts,
) -> Capability {
    let mut c = cap(
        "exec",
        "exec",
        exposure,
        "Runs shell commands; output comes with the result.",
    );
    c.actions.insert(
        "run".into(),
        action(
            Effect::Execute,
            &format!(
                "{} {}",
                crate::exec::shell_summary(shell),
                crate::exec::timeout_summary(timeouts)
            ),
            obj(
                json!({"command": {"type": "string", "minLength": 1}, "cwd": cwd_param(windows),
                       "timeout_ms": timeout_param(timeouts),
                       "memory_mb": opt(json!({"type": "integer", "minimum": 1,
                                               "maximum": limits.memory_max_mb,
                                               "default": limits.memory_mb})),
                       "cpu_percent": opt(json!({"type": "integer", "minimum": 1,
                                                 "maximum": limits.cpu_max_percent,
                                                 "default": limits.cpu_percent})),
                       "processes": opt(json!({"type": "integer", "minimum": 1,
                                               "maximum": limits.processes_max,
                                               "default": limits.processes}))}),
                &["command"],
            ),
            obj(
                json!({"exit_code": {"type": ["integer", "null"]}, "signal": {"type": "string"},
                       "stdout": {"type": "string"}, "stderr": {"type": "string"},
                       "truncated": {"type": "boolean"},
                       "killed": {"enum": ["memory"]}, "reason": {"type": "string"}}),
                &["exit_code", "stdout", "stderr", "truncated"],
            ),
        ),
    );
    c.actions.insert(
        "signal".into(),
        action(
            Effect::Actuate,
            "Signals a running command of this center.",
            obj(
                json!({"call": call_param(), "signal": {"enum": ["term", "kill", "int"]}}),
                &["call", "signal"],
            ),
            obj(json!({}), &[]),
        ),
    );
    c.state = obj(
        json!({"shell": {"type": "string"}, "confinement": {"type": "string"}}),
        &["shell", "confinement"],
    );
    c.events.insert(
        "exit".into(),
        event(
            "A command ended.",
            false,
            obj(
                json!({"call": call_param(), "exit_code": {"type": ["integer", "null"]}}),
                &["call", "exit_code"],
            ),
        ),
    );
    // Declared for later; the output comes in the result.
    c.streams.insert(
        "output".into(),
        StreamDecl {
            kind: StreamKind::Reliable,
            direction: Direction::Up,
            summary: "Command output (not served).".into(),
        },
    );
    c
}

fn settings_cap() -> Capability {
    let mut c = cap(
        "settings",
        "settings",
        Exposure::On,
        "This center's entry of the node config.",
    );
    c.actions.insert(
        "set".into(),
        action(
            Effect::Write,
            "Replaces the document; if_version guards against a concurrent change.",
            obj(
                json!({"document": {"type": "object"}, "if_version": {"type": "integer"}}),
                &["document", "if_version"],
            ),
            obj(json!({"version": {"type": "integer"}}), &["version"]),
        ),
    );
    c.actions.insert(
        "pause".into(),
        action(
            Effect::Actuate,
            "Pauses this center's link; only the owner unpauses.",
            obj(json!({}), &[]),
            obj(json!({}), &[]),
        ),
    );
    c.actions.insert(
        "sudo-offer".into(),
        action(
            Effect::Write,
            "A one-shot key to seal the sudo password for this node (spec §7.4.1).",
            obj(json!({}), &[]),
            obj(
                json!({"offer": {"type": "string"}, "key": {"type": "string"},
                       "ts": {"type": "integer"}, "sig": {"type": "string"}}),
                &["offer", "key", "ts", "sig"],
            ),
        ),
    );
    c.actions.insert(
        "sudo".into(),
        action(
            Effect::Write,
            "Turns the sudo switch on (with the sealed password) or off.",
            obj(
                json!({"on": {"type": "boolean"},
                       "sealed": opt(json!({"type": "object", "properties": {
                           "offer": {"type": "string"}, "key": {"type": "string"},
                           "iv": {"type": "string"}, "ct": {"type": "string"}},
                        "required": ["offer", "key", "iv", "ct"]}))}),
                &["on"],
            ),
            obj(json!({"sudo": {"enum": ["on", "off"]}}), &["sudo"]),
        ),
    );
    c.state = obj(
        json!({"document": {"type": "object"}, "version": {"type": "integer"},
               "sudo": {"enum": ["on", "off"]}}),
        &["document", "version", "sudo"],
    );
    c.events.insert(
        "changed".into(),
        event(
            "The node config changed.",
            true,
            obj(json!({"version": {"type": "integer"}}), &["version"]),
        ),
    );
    c
}

fn audit_cap() -> Capability {
    let mut c = cap(
        "audit",
        "audit",
        Exposure::On,
        "The node's decisions about this center's calls.",
    );
    c.events.insert(
        "decision".into(),
        event(
            "One decision.",
            false,
            obj(
                json!({"ts": {"type": "integer"}, "cap": {"type": "string"},
                       "action": {"type": "string"}, "target": {"type": "string"},
                       "decision": {"enum": ["allowed", "forbidden", "killed"]},
                       "code": {"type": "string"},
                       "session": {"type": "string"}}),
                &["ts", "cap", "action", "target", "decision"],
            ),
        ),
    );
    c
}

/// How a policy-governed capability is offered: on, unless its setting says
/// off or hidden. What a call may do is decided per call, not here.
fn exposure(entry: &CenterEntry, id: &str) -> Option<Exposure> {
    match entry.policy.cap_setting(id, None) {
        Some(CapSetting::Hidden) => None,
        Some(CapSetting::Off) => Some(Exposure::Off),
        Some(CapSetting::On) | None => Some(Exposure::On),
    }
}

/// Whether the center is shown `cap.action`: not hidden, and in `allowlist`
/// mode only when an allow rule covers it (any pattern, each call is still
/// checked), and for `exec.run` also when the sudo allow list has an entry,
/// since a sudo command runs by that list alone. In `folder` and `user` mode
/// the allow rules do not count, so the action is offered, except `exec` in
/// `folder` mode on a machine that cannot confine a command, and an action
/// that senses or actuates (`exec.signal`), which no mode allows unless the
/// owner set it to on. An action set to off stays, and fails `disabled`.
///
/// A provider's action (`provided`) is decided like the governed ones: in
/// `allowlist` mode by the allow rules, sense and actuate only when on. It
/// names no path, so no folder holds it: `folder` mode offers it only where
/// the owner set it to on.
fn offered(
    policy: &CenterPolicy,
    view: View,
    cap: &str,
    action: &str,
    effect: Effect,
    provided: bool,
) -> bool {
    let View {
        mode,
        by_rules,
        confined,
    } = view;
    let setting = policy.cap_setting(cap, Some(action));
    match setting {
        Some(CapSetting::Hidden) => return false,
        Some(CapSetting::Off) => return true,
        _ => {}
    }
    // Only the policy-governed capabilities are decided by rules and modes;
    // `settings.pause` actuates as well and is no policy's business.
    let governed = provided || matches!(cap, "fs" | "exec");
    if by_rules
        && governed
        && mode != Mode::Allowlist
        && matches!(effect, Effect::Sense | Effect::Actuate)
        && setting != Some(CapSetting::On)
    {
        return false;
    }
    if by_rules && provided && mode == Mode::Folder && setting != Some(CapSetting::On) {
        return false;
    }
    // Folder mode refuses every command it cannot confine, so it offers none;
    // a sudo command still runs by the sudo allow list.
    if by_rules
        && cap == "exec"
        && mode == Mode::Folder
        && !confined
        && policy.sudo_allow.is_empty()
    {
        return false;
    }
    if !by_rules || mode != Mode::Allowlist || !governed {
        return true;
    }
    rules::offers(&policy.allow, cap, action)
        || (cap == "exec" && action == "run" && !policy.sudo_allow.is_empty())
}

/// What decides which actions a descriptor offers besides the policy.
#[derive(Debug, Clone, Copy)]
struct View {
    mode: Mode,
    /// Cut by the allow rules and by what the node cannot do ([`for_center`]).
    by_rules: bool,
    /// Whether this machine confines commands in `folder` mode.
    confined: bool,
}

/// The descriptor `entry` sees now; `rev` is derived from its content, so it
/// changes exactly when the view changes. The center lists what it offers
/// from it, so an action the policy cannot allow is not in it. `confined` says
/// whether this machine can confine a command in `folder` mode (Landlock,
/// a Windows AppContainer); where it cannot, folder mode offers no command.
/// `provided` are the capabilities the attached providers add
/// (crate::provider), each cut by the same policy.
pub fn for_center(
    cfg: &NodeConfig,
    entry: &CenterEntry,
    now_ms: u64,
    confined: bool,
    provided: &[Capability],
) -> Descriptor {
    build(cfg, entry, now_ms, true, confined, provided)
}

/// Every action a call may name: [`for_center`] without the cut by allow
/// rules. A call for an action no rule covers still reaches the policy, which
/// refuses it and writes the audit entry; only hidden ones are unknown.
pub fn for_call(
    cfg: &NodeConfig,
    entry: &CenterEntry,
    now_ms: u64,
    provided: &[Capability],
) -> Descriptor {
    build(cfg, entry, now_ms, false, true, provided)
}

/// The capabilities and their actions that `cap set` switches for `entry`,
/// the node's own: what a call may name with every switch on, the implicit
/// ones aside.
pub fn switchable(cfg: &NodeConfig, entry: &CenterEntry) -> Vec<(String, Vec<String>)> {
    let mut all = entry.clone();
    all.policy.caps.clear();
    for_call(cfg, &all, 0, &[])
        .capabilities
        .into_iter()
        .filter(|c| c.provider == "node" && !IMPLICIT.contains(&c.id.as_str()))
        .map(|c| (c.id, c.actions.into_keys().collect()))
        .collect()
}

fn build(
    cfg: &NodeConfig,
    entry: &CenterEntry,
    now_ms: u64,
    by_rules: bool,
    confined: bool,
    provided: &[Capability],
) -> Descriptor {
    let mut caps = vec![node_cap()];
    if let Some(e) = exposure(entry, "fs") {
        caps.push(fs_cap(e));
    }
    if let Some(e) = exposure(entry, "exec") {
        caps.push(exec_cap(
            e,
            cfg.machine.shell.as_deref(),
            cfg!(windows),
            &cfg.limits.command,
            &crate::exec::Timeouts::from_limits(&cfg.limits),
        ));
    }
    if entry.settings == SettingsGrant::Write {
        caps.push(settings_cap());
    }
    caps.push(audit_cap());
    // A provider's capability is offered like the node's own: hidden, off
    // or on by `caps`.
    for c in provided {
        if let Some(e) = exposure(entry, &c.id) {
            caps.push(Capability {
                exposure: e,
                ..c.clone()
            });
        }
    }
    // Actions the policy cannot allow are left out, so the center builds no
    // tool the node would refuse; off ones stay and fail `disabled`. A
    // capability with no action left goes too.
    let view = View {
        mode: entry.policy.mode_at(now_ms),
        by_rules,
        confined,
    };
    for c in &mut caps {
        let id = c.id.clone();
        let provided = c.provider != "node";
        c.actions
            .retain(|a, decl| offered(&entry.policy, view, &id, a, decl.effect, provided));
    }
    caps.retain(|c| {
        !((c.provider != "node" || matches!(c.id.as_str(), "fs" | "exec")) && c.actions.is_empty())
    });
    let name = node_name(cfg);
    let platform = std::env::consts::OS.to_string();
    let mut d = Descriptor {
        nerve: nerve_proto::PROTOCOL_VERSION.into(),
        node: NodeInfo {
            id: entry.node_id.clone(),
            name: name.clone(),
            platform: platform.clone(),
            arch: std::env::consts::ARCH.into(),
            software: Software {
                name: SOFTWARE.into(),
                version: VERSION.into(),
            },
        },
        rev: 0,
        summary: format!(
            "{platform} machine {name}: files and shell commands, under its owner's policy (mode {}).",
            entry.policy.mode_at(now_ms).as_str()
        ),
        capabilities: caps,
    };
    d.rev = rev_of(&d);
    d
}

/// A content hash of the descriptor, kept below 2^53 so every JSON reader
/// holds it exactly.
fn rev_of(d: &Descriptor) -> u64 {
    let bytes = serde_json::to_vec(d).unwrap_or_default();
    let h = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_ref()[..8]);
    (u64::from_be_bytes(b) & ((1 << 53) - 1)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    use nerve_policy::config::CenterPolicy;
    use nerve_proto::RpcError;
    use serde_json::Map;

    fn entry() -> CenterEntry {
        CenterEntry {
            name: "home".into(),
            url: "https://center.example".into(),
            pin: None,
            center_id: "c1".into(),
            node_id: "n1".into(),
            settings: SettingsGrant::Off,
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: CenterPolicy::default(),
        }
    }

    #[test]
    fn built_in_names_have_no_underscore() {
        let mut e = entry();
        e.settings = SettingsGrant::Write;
        // Default deny shows no fs or exec tool; the names are checked on all.
        e.policy.mode = Mode::User;
        let d = for_center(&NodeConfig::default(), &e, 0, true, &[]);
        assert_eq!(d.check_names(), Ok(()));
        assert!(d.capabilities.len() >= 5);
    }

    #[test]
    fn filtered_per_center() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.mode = Mode::User;
        let d = for_center(&cfg, &e, 0, true, &[]);
        let ids: Vec<&str> = d.capabilities.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["node", "fs", "exec", "audit"]);
        assert!(nerve_proto::descriptor::summary_words(&d.summary) < 60);
        assert_eq!(d.capability("fs").unwrap().exposure, Exposure::On);

        e.policy.caps.insert("fs".into(), CapSetting::Off);
        assert_eq!(
            for_center(&cfg, &e, 0, true, &[])
                .capability("fs")
                .unwrap()
                .exposure,
            Exposure::Off
        );

        e.policy.caps.insert("exec".into(), CapSetting::Hidden);
        e.policy.caps.insert("fs.write".into(), CapSetting::Hidden);
        e.settings = SettingsGrant::Write;
        let d2 = for_center(&cfg, &e, 0, true, &[]);
        assert!(d2.capability("exec").is_none());
        assert!(d2.capability("settings").is_some());
        assert!(!d2.capability("fs").unwrap().actions.contains_key("write"));
        assert_ne!(d.rev, d2.rev);
        assert_eq!(d2.rev, for_center(&cfg, &e, 0, true, &[]).rev);
    }

    fn actions(d: &Descriptor, cap: &str) -> Vec<String> {
        d.capability(cap)
            .map(|c| c.actions.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn rules(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn allowlist_without_rules_offers_no_tools() {
        let mut e = entry();
        e.settings = SettingsGrant::Write;
        let d = for_center(&NodeConfig::default(), &e, 0, true, &[]);
        assert!(d.capability("fs").is_none());
        assert!(d.capability("exec").is_none());
        assert!(d.capability("node").is_some());
        assert!(d.capability("audit").is_some());
        assert!(d.capability("settings").is_some());
    }

    #[test]
    fn allowlist_offers_what_a_rule_covers() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.allow = rules(&["exec.run:git *"]);
        let d = for_center(&cfg, &e, 0, true, &[]);
        assert_eq!(actions(&d, "exec"), ["run"]);
        assert!(d.capability("fs").is_none());

        // The scope decides, the pattern does not.
        e.policy.allow = rules(&["fs:~/notes/*"]);
        let d = for_center(&cfg, &e, 0, true, &[]);
        let mut fs = actions(&d, "fs");
        fs.sort();
        assert_eq!(fs, ["find", "grep", "list", "read", "stat", "write"]);
        assert!(d.capability("exec").is_none());

        e.policy.allow = rules(&["fs.read:/a/*"]);
        assert_eq!(actions(&for_center(&cfg, &e, 0, true, &[]), "fs"), ["read"]);

        e.policy.allow = rules(&["exec"]);
        assert_eq!(
            actions(&for_center(&cfg, &e, 0, true, &[]), "exec"),
            ["run", "signal"]
        );
    }

    #[test]
    fn a_sudo_entry_offers_exec_run_only() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.sudo_allow = rules(&["sudo apt *"]);
        let d = for_center(&cfg, &e, 0, true, &[]);
        assert_eq!(actions(&d, "exec"), ["run"]);
        assert!(d.capability("fs").is_none());
    }

    #[test]
    fn folder_and_user_mode_ignore_the_rules() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        for mode in [Mode::Folder, Mode::User] {
            e.policy.mode = mode;
            let d = for_center(&cfg, &e, 0, true, &[]);
            // `signal` actuates, which no mode allows by itself.
            assert_eq!(actions(&d, "exec"), ["run"]);
            assert_eq!(actions(&d, "fs").len(), 6);
        }
        // A folder or user mode that ran out is allowlist again.
        e.policy.until = Some(10);
        assert!(
            for_center(&cfg, &e, 9, true, &[])
                .capability("fs")
                .is_some()
        );
        assert!(
            for_center(&cfg, &e, 10, true, &[])
                .capability("fs")
                .is_none()
        );
    }

    /// Where commands cannot be confined (Linux without Landlock),
    /// folder mode refuses every command, so it offers no exec tool; a sudo
    /// entry still runs by its list.
    #[test]
    fn folder_mode_offers_no_exec_where_commands_cannot_be_confined() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        let d = for_center(&cfg, &e, 0, false, &[]);
        assert!(d.capability("exec").is_none());
        assert_eq!(actions(&d, "fs").len(), 6);
        // Confined, as with Landlock or an AppContainer: offered.
        let d = for_center(&cfg, &e, 0, true, &[]);
        assert_eq!(actions(&d, "exec"), ["run"]);
        // User mode runs commands unconfined anyway.
        e.policy.mode = Mode::User;
        let d = for_center(&cfg, &e, 0, false, &[]);
        assert_eq!(actions(&d, "exec"), ["run"]);
        // A sudo entry runs by its list in every mode.
        e.policy.mode = Mode::Folder;
        e.policy.sudo_allow = rules(&["sudo apt *"]);
        let d = for_center(&cfg, &e, 0, false, &[]);
        assert_eq!(actions(&d, "exec"), ["run"]);
        // A call still reaches the policy, which refuses and audits it.
        e.policy.sudo_allow.clear();
        assert!(for_call(&cfg, &e, 0, &[]).capability("exec").is_some());
    }

    /// `exec.signal` actuates: the descriptor offers it exactly where the
    /// policy lets a signal through, in folder and user mode only with
    /// `caps.exec.signal = on`, in allowlist mode by an allow rule.
    #[test]
    fn exec_signal_is_offered_where_the_policy_allows_it() {
        use nerve_policy::protected::{Platform, Protected};
        use nerve_policy::{Call, Decision, Env, decide};
        let home = std::path::Path::new("/h");
        let prot = Protected::new(&Platform::Unix, home, &[], &Default::default());
        let env = Env {
            home,
            protected: &prot,
            unconfined: None,
            sudo: false,
            shell: nerve_policy::command::Shell::native(),
        };
        let call = Call {
            cap: "exec",
            action: "signal",
            effect: Effect::Actuate,
            targets: &[],
            command: None,
            cwd: None,
            now_ms: 0,
        };
        let cfg = NodeConfig::default();
        let mut offered = Vec::new();
        for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
            for on in [false, true] {
                for allow in [&[][..], &["exec.signal"][..], &["exec"][..]] {
                    let mut e = entry();
                    e.policy.mode = mode;
                    e.policy.allow = rules(allow);
                    if on {
                        e.policy.caps.insert("exec.signal".into(), CapSetting::On);
                    }
                    let shown = actions(&for_center(&cfg, &e, 0, true, &[]), "exec")
                        .contains(&"signal".to_string());
                    let allowed = decide(&e.policy, &env, &call) == Decision::Allow;
                    assert_eq!(shown, allowed, "{mode:?} on={on} allow={allow:?}");
                    if shown && mode != Mode::Allowlist {
                        offered.push(mode);
                    }
                }
            }
        }
        // Both modes offer it once the owner set it on.
        assert!(offered.contains(&Mode::Folder) && offered.contains(&Mode::User));
        // `settings.pause` actuates too, and is not the policy's.
        let mut e = entry();
        e.settings = SettingsGrant::Write;
        e.policy.mode = Mode::User;
        assert!(
            actions(&for_center(&cfg, &e, 0, true, &[]), "settings").contains(&"pause".to_string())
        );
    }

    /// A provider's capability with one action of `effect`.
    fn provided(effect: Effect) -> Capability {
        let mut c = cap("echo", "", Exposure::On, "Says it back.");
        c.provider = "desk".into();
        c.actions.insert(
            "say".into(),
            action(effect, "Say it.", obj(json!({}), &[]), Value::Null),
        );
        c
    }

    /// A provider's action is offered exactly where the policy lets a call
    /// of it through, for every effect, mode, `on` and allow rule: so the
    /// center builds no tool for it that the node would refuse.
    #[test]
    fn a_provided_action_is_offered_where_the_policy_allows_it() {
        use nerve_policy::protected::{Platform, Protected};
        use nerve_policy::{Call, Decision, Env, decide};
        let home = std::path::Path::new("/h");
        let prot = Protected::new(&Platform::Unix, home, &[], &Default::default());
        let env = Env {
            home,
            protected: &prot,
            unconfined: None,
            sudo: false,
            shell: nerve_policy::command::Shell::native(),
        };
        let cfg = NodeConfig::default();
        let effects = [
            Effect::Read,
            Effect::Write,
            Effect::Execute,
            Effect::Sense,
            Effect::Actuate,
        ];
        for effect in effects {
            let provided = [provided(effect)];
            let call = Call {
                cap: "echo",
                action: "say",
                effect,
                targets: &[],
                command: None,
                cwd: None,
                now_ms: 0,
            };
            for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
                for on in [false, true] {
                    for allow in [
                        &[][..],
                        &["echo.say"][..],
                        &["echo"][..],
                        &["echo.other"][..],
                    ] {
                        let mut e = entry();
                        e.policy.mode = mode;
                        e.policy.allow = rules(allow);
                        if on {
                            e.policy.caps.insert("echo.say".into(), CapSetting::On);
                        }
                        let d = for_center(&cfg, &e, 0, true, &provided);
                        let shown = actions(&d, "echo") == ["say"];
                        let allowed = decide(&e.policy, &env, &call) == Decision::Allow;
                        let what = format!("{effect:?} {mode:?} on={on} allow={allow:?}");
                        assert_eq!(shown, allowed, "{what}");
                        // With no action left the capability is not listed.
                        assert_eq!(d.capability("echo").is_some(), shown, "{what}");
                        if shown {
                            assert_eq!(d.capability("echo").unwrap().provider, "desk");
                        }
                        // A call reaches the policy whatever is shown.
                        assert!(
                            for_call(&cfg, &e, 0, &provided)
                                .capability("echo")
                                .is_some()
                        );
                    }
                }
            }
        }
        // Hidden is absent, off is listed and fails `disabled`, as for the
        // node's own.
        let provided = [provided(Effect::Read)];
        let mut e = entry();
        e.policy.mode = Mode::User;
        e.policy.caps.insert("echo".into(), CapSetting::Off);
        let d = for_center(&cfg, &e, 0, true, &provided);
        assert_eq!(d.capability("echo").unwrap().exposure, Exposure::Off);
        e.policy.caps.insert("echo".into(), CapSetting::Hidden);
        assert!(
            for_center(&cfg, &e, 0, true, &provided)
                .capability("echo")
                .is_none()
        );
        assert!(
            for_call(&cfg, &e, 0, &provided)
                .capability("echo")
                .is_none()
        );
        // The rev follows: a provider that comes or goes is a new view.
        e.policy.caps.clear();
        let with = for_center(&cfg, &e, 0, true, &provided).rev;
        let without = for_center(&cfg, &e, 0, true, &[]).rev;
        assert_ne!(with, without);
    }

    #[test]
    fn off_and_hidden_keep_their_meaning_in_allowlist() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.caps.insert("fs".into(), CapSetting::Off);
        e.policy.allow = rules(&["exec.run"]);
        e.policy
            .caps
            .insert("exec.signal".into(), CapSetting::Hidden);
        let d = for_center(&cfg, &e, 0, true, &[]);
        assert_eq!(d.capability("fs").unwrap().exposure, Exposure::Off);
        assert_eq!(actions(&d, "fs").len(), 6);
        assert_eq!(actions(&d, "exec"), ["run"]);
    }

    /// A Windows node's `fs` tools say how a drive is written on the wire,
    /// so a model does not send `C:\...`.
    #[test]
    fn a_windows_node_shows_the_wire_form_of_a_path() {
        let win = path_param(true);
        let text = win["description"].as_str().unwrap();
        assert!(
            text.contains("/c/Users/") && text.contains("C:\\Users\\"),
            "{text}"
        );
        assert_eq!(path_param(false)["description"], "absolute path");
        let fs = fs_cap(Exposure::On);
        for a in ["stat", "list", "read", "write"] {
            assert_eq!(
                fs.actions[a].params["properties"]["path"],
                path_param(cfg!(windows)),
                "{a}"
            );
        }
    }

    /// `exec.run`'s `cwd` shows the same form on a Windows node, and stays
    /// a bare string (or null) on a Unix one.
    #[test]
    fn a_windows_node_shows_the_wire_form_of_a_working_folder() {
        let win = cwd_param(true);
        let text = win["description"].as_str().unwrap();
        assert!(
            text.contains("/c/Users/x") && text.contains("C:\\Users\\x"),
            "{text}"
        );
        assert_eq!(cwd_param(false), json!({"type": ["string", "null"]}));
        for windows in [true, false] {
            let exec = exec_cap(
                Exposure::On,
                None,
                windows,
                &Default::default(),
                &Default::default(),
            );
            assert_eq!(
                exec.actions["run"].params["properties"]["cwd"],
                cwd_param(windows)
            );
        }
    }

    /// The model reads the time a command gets from the `exec.run` text; a
    /// change of the owner's limits changes it, and with it the rev.
    #[test]
    fn exec_run_names_the_owners_run_time_limits() {
        let mut cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.mode = Mode::User;
        let text = |cfg: &NodeConfig| {
            let d = for_center(cfg, &e, 0, true, &[]);
            let run = &d.capability("exec").unwrap().actions["run"];
            (run.summary.clone(), d.rev)
        };
        let (before, rev) = text(&cfg);
        assert!(
            before.contains("after 10 min when you give none, and never runs longer than 1 h"),
            "{before}"
        );
        assert_eq!(
            timeout_ms(&cfg),
            json!({"type": ["integer", "null"], "minimum": 0, "default": 600_000,
                   "description": "milliseconds, at most 3600000: a larger value gets 3600000; 0 gets the default"})
        );
        cfg.limits.default_timeout_secs = 90;
        cfg.limits.max_timeout_secs = 120;
        let (after, changed) = text(&cfg);
        assert!(
            after.contains("after 1 min 30 s when you give none, and never runs longer than 2 min"),
            "{after}"
        );
        assert_ne!(changed, rev);
        assert_eq!(
            timeout_ms(&cfg),
            json!({"type": ["integer", "null"], "minimum": 0, "default": 90_000,
                   "description": "milliseconds, at most 120000: a larger value gets 120000; 0 gets the default"})
        );
        // The default shown is the one that applies: cut to the maximum.
        cfg.limits.max_timeout_secs = 30;
        assert_eq!(timeout_ms(&cfg)["default"], 30_000);
    }

    /// The `timeout_ms` parameter of `exec.run` as a center reads it.
    fn timeout_ms(cfg: &NodeConfig) -> Value {
        let mut e = entry();
        e.policy.mode = Mode::User;
        let d = for_center(cfg, &e, 0, true, &[]);
        d.capability("exec").unwrap().actions["run"].params["properties"]["timeout_ms"].clone()
    }

    /// Nodes that differ only in their run-time limits have different params
    /// for `exec.run`, so each node's details say its own limits; nodes with
    /// equal limits have equal ones.
    #[test]
    fn nodes_with_other_run_time_limits_have_other_params() {
        let params = |cfg: &NodeConfig| {
            let mut e = entry();
            e.policy.mode = Mode::User;
            let d = for_center(cfg, &e, 0, true, &[]);
            d.capability("exec").unwrap().actions["run"].params.clone()
        };
        let plain = NodeConfig::default();
        let mut long = NodeConfig::default();
        long.limits.max_timeout_secs = 86_400;
        let mut short_default = NodeConfig::default();
        short_default.limits.default_timeout_secs = 60;
        assert_eq!(params(&plain), params(&NodeConfig::default()));
        assert_ne!(params(&plain), params(&long));
        assert_ne!(params(&plain), params(&short_default));
    }

    /// A call sees the limits its command gets and the most it may ask
    /// for; the owner changing them changes the descriptor.
    #[test]
    fn exec_run_shows_the_limits_of_a_command() {
        let mut cfg = NodeConfig::default();
        let e = entry();
        let run = |cfg: &NodeConfig| {
            let d = for_call(cfg, &e, 0, &[]);
            let exec = d.capabilities.iter().find(|c| c.id == "exec").unwrap();
            (exec.actions["run"].params["properties"].clone(), d.rev)
        };
        let (p, rev) = run(&cfg);
        assert_eq!(
            p["memory_mb"],
            json!({"type": ["integer", "null"], "minimum": 1, "maximum": 16384, "default": 4096})
        );
        assert_eq!(p["cpu_percent"]["maximum"], 800);
        assert_eq!(p["cpu_percent"]["default"], 200);
        assert_eq!(p["processes"]["maximum"], 8192);
        assert_eq!(p["processes"]["default"], 1024);
        // A command killed for its memory is a decision of its own.
        let d = for_call(&cfg, &e, 0, &[]);
        let audit = d.capabilities.iter().find(|c| c.id == "audit").unwrap();
        assert_eq!(
            audit.events["decision"].data["properties"]["decision"]["enum"],
            json!(["allowed", "forbidden", "killed"])
        );
        cfg.limits.command.memory_max_mb = 8192;
        let (p, other) = run(&cfg);
        assert_eq!(p["memory_mb"]["maximum"], 8192);
        assert_ne!(rev, other);
    }

    #[test]
    fn a_rule_edit_changes_the_rev() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        let none = for_center(&cfg, &e, 0, true, &[]).rev;
        e.policy.allow = rules(&["exec.run:git *"]);
        let one = for_center(&cfg, &e, 0, true, &[]).rev;
        // Another pattern of the same scope shows the same tools.
        e.policy.allow = rules(&["exec.run:ls *"]);
        assert_eq!(for_center(&cfg, &e, 0, true, &[]).rev, one);
        e.policy.allow.clear();
        assert_eq!(for_center(&cfg, &e, 0, true, &[]).rev, none);
        assert_ne!(none, one);
    }

    /// Every schema the node publishes keeps to the subset a center checks
    /// (nerve_proto::schema), in every mode, settings grant and
    /// confinement, with every switch on, and with either platform's path
    /// and working-folder text.
    #[test]
    fn every_built_in_schema_passes_the_subset() {
        use nerve_proto::schema::{Role, check};
        let fits = |c: &Capability, what: &str| {
            for (a, decl) in &c.actions {
                let at = format!("{what}: {}.{a}", c.id);
                check(&decl.params, Role::Params).unwrap_or_else(|e| panic!("{at} params: {e}"));
                check(&decl.result, Role::Result).unwrap_or_else(|e| panic!("{at} result: {e}"));
            }
            for (n, ev) in &c.events {
                check(&ev.data, Role::Result)
                    .unwrap_or_else(|e| panic!("{what}: {}/{n} data: {e}", c.id));
            }
            if !c.state.is_null() {
                check(&c.state, Role::Result)
                    .unwrap_or_else(|e| panic!("{what}: {} state: {e}", c.id));
            }
        };
        let cfg = NodeConfig::default();
        let mut actions = std::collections::BTreeSet::new();
        for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
            for settings in [SettingsGrant::Off, SettingsGrant::Write] {
                for confined in [false, true] {
                    let mut e = entry();
                    e.policy.mode = mode;
                    e.settings = settings;
                    e.policy.allow = rules(&["fs", "exec"]);
                    e.policy.caps.insert("exec.signal".into(), CapSetting::On);
                    let what = format!("{mode:?} {settings:?} confined={confined}");
                    for d in [
                        for_center(&cfg, &e, 0, confined, &[]),
                        for_call(&cfg, &e, 0, &[]),
                    ] {
                        for c in &d.capabilities {
                            fits(c, &what);
                            for a in c.actions.keys() {
                                actions.insert(format!("{}.{a}", c.id));
                            }
                        }
                    }
                }
            }
        }
        // Each built-in action was looked at, `exec.signal` among them.
        assert_eq!(actions.len(), 12, "{actions:?}");
        // The path and working-folder text of the other platform too.
        let exec = |windows| {
            exec_cap(
                Exposure::On,
                None,
                windows,
                &Default::default(),
                &Default::default(),
            )
        };
        fits(&exec(true), "windows");
        fits(&exec(false), "unix");
        let mut fs = fs_cap(Exposure::On);
        for decl in fs.actions.values_mut() {
            decl.params["properties"]["path"] = path_param(!cfg!(windows));
        }
        fits(&fs, "the other platform's fs");
    }

    /// How a row of the agreement table below comes out.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Agree {
        /// The schema and the parser both take the arguments.
        Take,
        /// Both refuse them.
        Refuse,
        /// The schema takes them and the parser refuses them, for what the
        /// subset cannot say: the form of a path, a glob, base64, a command
        /// of blanks.
        Content,
        /// The schema refuses what the parser takes. No row wants this: a
        /// center checks the arguments against the schema, so the agent
        /// would be refused what the node does (an optional field sent as
        /// `null`, which the parser reads as left out, was one).
        Stricter,
    }

    /// The `fs` and `exec` schemas say what their parsers take: arguments
    /// a schema takes reach the action (unless their content is wrong in a
    /// way no schema of the subset can say), and arguments it refuses the
    /// parser refuses too. `exec.run` counts with the limits a command is
    /// granted, which refuse 0 and more than the most.
    #[test]
    fn fs_and_exec_schemas_agree_with_their_parsers() {
        use Agree::*;
        use nerve_proto::schema::validate;
        let dir = tempfile::tempdir().unwrap();
        let p = nerve_policy::paths::to_wire(dir.path());
        let cfg = NodeConfig::default();
        let d = for_call(&cfg, &entry(), 0, &[]);
        let limits = &cfg.limits.command;
        let parse = |cap: &str, action: &str, args: &Map<String, Value>| -> Result<(), RpcError> {
            match cap {
                "fs" => crate::fs::FsCall::parse(action, args).map(drop),
                _ if action == "run" => {
                    let run = crate::exec::RunCall::parse(args, dir.path())?;
                    let a = run.limits;
                    limits
                        .grant(a.memory_mb, a.cpu_percent, a.processes)
                        .map(drop)
                        .map_err(RpcError::invalid_args)
                }
                _ => {
                    let s: crate::exec::SignalArgs = nerve_proto::rpc::params(args)?;
                    crate::exec::Sig::parse(&s.signal)
                        .map(drop)
                        .ok_or_else(|| RpcError::invalid_args("no such signal"))
                }
            }
        };
        let rows = [
            ("fs.stat", json!({"path": p}), Take),
            ("fs.stat", json!({}), Refuse),
            ("fs.stat", json!({"path": 5}), Refuse),
            ("fs.stat", json!({"path": null}), Refuse),
            ("fs.stat", json!({"path": p, "other": 1}), Refuse),
            ("fs.stat", json!({"path": "relative/x"}), Content),
            ("fs.list", json!({"path": p}), Take),
            ("fs.list", json!({"path": [p]}), Refuse),
            (
                "fs.read",
                json!({"path": p, "offset": 0, "length": 10}),
                Take,
            ),
            ("fs.read", json!({"path": p, "length": u64::MAX}), Take),
            ("fs.read", json!({"path": p, "offset": -1}), Refuse),
            ("fs.read", json!({"path": p, "offset": 1.5}), Refuse),
            ("fs.read", json!({"path": p, "offset": 5.0}), Refuse),
            ("fs.read", json!({"path": p, "offset": "5"}), Refuse),
            ("fs.read", json!({"path": p, "offset": null}), Take),
            ("fs.read", json!({"path": p, "length": null}), Take),
            ("fs.grep", json!({"path": p, "pattern": "x"}), Take),
            (
                "fs.grep",
                json!({"path": p, "pattern": "x", "glob": "*.rs", "max": 1}),
                Take,
            ),
            (
                "fs.grep",
                json!({"path": p, "pattern": "x", "max": 1_000_000_000}),
                Take,
            ),
            (
                "fs.grep",
                json!({"path": p, "pattern": "x", "glob": null, "max": null}),
                Take,
            ),
            ("fs.grep", json!({"path": p, "pattern": ""}), Refuse),
            ("fs.grep", json!({"path": p}), Refuse),
            (
                "fs.grep",
                json!({"path": p, "pattern": "x", "max": 0}),
                Refuse,
            ),
            (
                "fs.grep",
                json!({"path": p, "pattern": "x", "glob": "["}),
                Content,
            ),
            ("fs.find", json!({"path": p, "glob": "*"}), Take),
            (
                "fs.find",
                json!({"path": p, "glob": "*", "max": null}),
                Take,
            ),
            ("fs.find", json!({"path": p, "glob": null}), Refuse),
            ("fs.find", json!({"path": p}), Refuse),
            ("fs.find", json!({"path": p, "glob": 3}), Refuse),
            ("fs.find", json!({"path": p, "glob": "*", "max": 0}), Refuse),
            ("fs.write", json!({"path": p, "content": "hi"}), Take),
            (
                "fs.write",
                json!({"path": p, "content": "aGk=", "encoding": "base64", "if_match": "e"}),
                Take,
            ),
            (
                "fs.write",
                json!({"path": p, "content": "hi", "encoding": "latin1"}),
                Refuse,
            ),
            (
                "fs.write",
                json!({"path": p, "content": "hi", "encoding": null, "if_match": null}),
                Take,
            ),
            ("fs.write", json!({"path": p}), Refuse),
            (
                "fs.write",
                json!({"path": p, "content": "!!", "encoding": "base64"}),
                Content,
            ),
            ("exec.run", json!({"command": "true"}), Take),
            ("exec.run", json!({"command": "true", "cwd": p}), Take),
            ("exec.run", json!({}), Refuse),
            ("exec.run", json!({"command": ""}), Refuse),
            ("exec.run", json!({"command": 1}), Refuse),
            ("exec.run", json!({"command": "true", "other": 1}), Refuse),
            ("exec.run", json!({"command": "  "}), Content),
            (
                "exec.run",
                json!({"command": "true", "cwd": "relative"}),
                Content,
            ),
            // 0 is the same as none; a larger one than the most is cut to it.
            (
                "exec.run",
                json!({"command": "true", "timeout_ms": 0}),
                Take,
            ),
            (
                "exec.run",
                json!({"command": "true", "timeout_ms": 1}),
                Take,
            ),
            (
                "exec.run",
                json!({"command": "true", "timeout_ms": 1_000_000_000_000u64}),
                Take,
            ),
            (
                "exec.run",
                json!({"command": "true", "timeout_ms": -1}),
                Refuse,
            ),
            (
                "exec.run",
                json!({"command": "true", "timeout_ms": 1.5}),
                Refuse,
            ),
            (
                "exec.run",
                json!({"command": "true", "timeout_ms": null}),
                Take,
            ),
            (
                "exec.run",
                json!({"command": "true", "cwd": null, "memory_mb": null,
                       "cpu_percent": null, "processes": null}),
                Take,
            ),
            ("exec.run", json!({"command": null}), Refuse),
            ("exec.run", json!({"command": "true", "memory_mb": 1}), Take),
            (
                "exec.run",
                json!({"command": "true", "memory_mb": limits.memory_max_mb}),
                Take,
            ),
            (
                "exec.run",
                json!({"command": "true", "memory_mb": limits.memory_max_mb + 1}),
                Refuse,
            ),
            (
                "exec.run",
                json!({"command": "true", "memory_mb": 0}),
                Refuse,
            ),
            (
                "exec.run",
                json!({"command": "true", "cpu_percent": limits.cpu_max_percent}),
                Take,
            ),
            (
                "exec.run",
                json!({"command": "true", "cpu_percent": 4_294_967_296u64}),
                Refuse,
            ),
            (
                "exec.run",
                json!({"command": "true", "processes": 0}),
                Refuse,
            ),
            (
                "exec.run",
                json!({"command": "true", "processes": limits.processes_max + 1}),
                Refuse,
            ),
            ("exec.signal", json!({"call": 3, "signal": "term"}), Take),
            ("exec.signal", json!({"call": 0, "signal": "kill"}), Take),
            (
                "exec.signal",
                json!({"call": "3", "signal": "term"}),
                Refuse,
            ),
            ("exec.signal", json!({"call": -1, "signal": "term"}), Refuse),
            (
                "exec.signal",
                json!({"call": 1.5, "signal": "term"}),
                Refuse,
            ),
            ("exec.signal", json!({"call": {}, "signal": "term"}), Refuse),
            (
                "exec.signal",
                json!({"call": null, "signal": "term"}),
                Refuse,
            ),
            ("exec.signal", json!({"call": 3, "signal": "hup"}), Refuse),
            ("exec.signal", json!({"call": 3}), Refuse),
            (
                "exec.signal",
                json!({"call": 3, "signal": "int", "other": 1}),
                Refuse,
            ),
        ];
        for (name, args, want) in rows {
            let (cap, action) = name.split_once('.').unwrap();
            let schema = &d.capability(cap).unwrap().actions[action].params;
            let by_schema = validate(schema, &args);
            let by_parser = parse(cap, action, args.as_object().unwrap());
            let got = match (&by_schema, &by_parser) {
                (Ok(()), Ok(())) => Take,
                (Err(_), Err(_)) => Refuse,
                (Ok(()), Err(_)) => Content,
                (Err(_), Ok(())) => Stricter,
            };
            assert_eq!(
                got, want,
                "{name} {args}: schema {by_schema:?}, parser {by_parser:?}"
            );
        }
    }
}
