//! The descriptor one center sees (spec §6): the node's capabilities, cut to
//! what this center's policy shows.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use nerve_policy::config::{CapSetting, CenterPolicy, Folder, Mode, SettingsGrant};
use nerve_policy::{CenterEntry, Need, NodeConfig, PathArgs, effect_rule, rules};
use nerve_proto::descriptor::{
    Access, AccessMode, Action, Capability, Descriptor, Direction, Effect, EventDecl, Exposure,
    FolderAccess, NodeInfo, Software, StreamDecl, StreamKind,
};
use nerve_proto::schema::PathMark;

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
        exposure: None,
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

/// The `path` argument of the `fs` actions, marked as a path the action
/// reads or writes (`mark`, `x-nerve-path`) as any capability's is. A
/// Windows node says how its drives are written, so a model does not send
/// `C:\...`, a `bad_path`.
fn path_param(windows: bool, mark: PathMark) -> Value {
    let text = if windows {
        "absolute path, the drive as a folder: /c/Users/x for C:\\Users\\x"
    } else {
        "absolute path"
    };
    json!({"type": "string", "description": text, "x-nerve-path": mark.as_str()})
}

/// The `cwd` argument of `exec.run`: it takes the same wire form as an `fs`
/// path, so a Windows node says so here as well. It is marked a path, read
/// only by its marker's words; the node holds a command's start to a folder
/// with `x` whatever it says.
fn cwd_param(windows: bool) -> Value {
    opt(if windows {
        json!({"type": "string", "x-nerve-path": "read",
               "description": "working folder, the drive as a folder: /c/Users/x for C:\\Users\\x"})
    } else {
        json!({"type": "string", "x-nerve-path": "read"})
    })
}

fn fs_cap(exposure: Exposure) -> Capability {
    let mut c = cap(
        "fs",
        "fs",
        exposure,
        "Files on this machine: stat, list, read, grep, find and write.",
    );
    let path = path_param(cfg!(windows), PathMark::Read);
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
                json!({"path": path_param(cfg!(windows), PathMark::Write),
                       "content": {"type": "string"},
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
    // A running command's output as it comes, for the session that started
    // it (`stream.open` with params `{call}`); the result still carries it.
    c.streams.insert(
        "output".into(),
        StreamDecl {
            kind: StreamKind::Reliable,
            direction: Direction::Up,
            summary: "A running command's output as it comes (params: call).".into(),
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

/// Whether the center is shown `cap.action`: not hidden, and allowed for
/// some call by the effect table ([`effect_rule`]), the one `decide` follows.
/// In `allowlist` mode an allow rule must cover it (any pattern, each call is
/// still checked), and for `exec.run` also when the sudo allow list has an
/// entry, since a sudo command runs by that list alone. In `folder` and
/// `user` mode the allow rules do not count, so the action is offered, except
/// `exec` in `folder` mode on a machine that cannot confine a command (all of
/// it: `exec.signal` too, though `decide` lets a call of it through when it is
/// on, since no command can run there to signal; the one place outside the
/// table), and an
/// action that senses or actuates (`exec.signal`), which no mode allows unless
/// the owner set it to on. An action set to off stays, and fails `disabled`.
///
/// An action that names paths (`paths`: `fs`, `exec.run`, a provider's
/// action whose schema marks some with `x-nerve-path`) names them per call,
/// so it is offered where a call with its paths in the folders is allowed.
/// One that names none lies in no folder: `folder` mode offers it only where
/// the owner set it to on, a read too. A write
/// whose marked paths are all ones it reads names no place it writes, and
/// counts as one with none (`paths` false).
fn offered(
    policy: &CenterPolicy,
    view: View,
    cap: &str,
    action: &str,
    effect: Effect,
    paths: bool,
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
    if !by_rules || !governed(cap) {
        return true;
    }
    // Folder mode refuses every command it cannot confine, so it offers none;
    // a sudo command still runs by the sudo allow list.
    let sudo = cap == "exec" && action == "run" && !policy.sudo_allow.is_empty();
    if cap == "exec" && mode == Mode::Folder && !confined && policy.sudo_allow.is_empty() {
        return false;
    }
    // A program's execute action with paths runs in the folders marked `x`,
    // and so, like a command, not where none can be confined.
    if cap != "exec" && effect == Effect::Execute && paths && mode == Mode::Folder && !confined {
        return false;
    }
    let paths = if paths {
        PathArgs::Some {
            all_in_folders: true,
        }
    } else {
        PathArgs::None
    };
    match effect_rule(mode, effect, paths, setting) {
        Need::Allowed => true,
        Need::AllowRule => rules::offers(&policy.allow, cap, action) || sudo,
        Need::InFolders | Need::NeedsOn | Need::Off => false,
    }
}

/// Whether the policy decides calls of `cap`: every capability but the
/// node's own `node`, `settings` and `audit` (`settings.pause` actuates as
/// well and is no policy's business).
fn governed(cap: &str) -> bool {
    !matches!(cap, "node" | "settings" | "audit")
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

/// What one center may do on this machine now, as its descriptor tells it
/// (the `access` block): built by the link from that center's own entry
/// alone, so no other pairing's folders reach it.
#[derive(Debug, Clone, PartialEq)]
pub struct Reach {
    /// The mode in force now ([`CenterPolicy::mode_at`]).
    pub mode: Mode,
    /// When a `folder` or `user` mode ends.
    pub until_ms: Option<u64>,
    /// The account this center's commands run as.
    pub account: Option<String>,
    /// Whether this machine confines commands in `folder` mode (Landlock, a
    /// Windows AppContainer, or `nerve-run` held by its own account);
    /// where it cannot, folder mode offers no command.
    pub confined: bool,
    /// Whether only the account they run as holds those commands back (the
    /// installed Linux node without Landlock): they then reach what that
    /// account may reach, more than the folders, so the block does not call
    /// them confined. Set by the daemon ([`crate::daemon::Shared::reach`]).
    pub held_by_account: bool,
    /// Whether the owner's sudo allow list for this center names commands,
    /// which run by that list alone, in any folder and unconfined, while
    /// the node's sudo switch is on and `exec.run` is neither hidden nor off
    /// for this center. The daemon clears it while the switch is off
    /// ([`crate::daemon::Shared::reach`]).
    pub sudo: bool,
    /// Whether the node reads this center's files as its command account
    /// (`nerve-run` on the installed Linux node), so in `folder` mode a read
    /// goes as far as that account may read ([`nerve_policy::decide::Reads`]).
    /// Set by the daemon.
    pub reads_by_account: bool,
    /// The folders the owner granted this center.
    pub folders: Vec<Folder>,
    /// The built-in folders of `nerve-run` where its commands run as that
    /// account ([`crate::account::built_in`]): the gate and the sandbox add
    /// them to `folders`, and the block marks them as the account's own.
    pub own: Vec<Folder>,
}

impl Reach {
    /// `entry`'s reach at `now_ms`. `run_home` is the home of `nerve-run`
    /// when this center's commands run as that account now, whose built-in
    /// folders ([`crate::account::built_in`]) the gate adds to the entry's.
    pub fn of(
        entry: &CenterEntry,
        now_ms: u64,
        account: Option<String>,
        confined: bool,
        run_home: Option<&std::path::Path>,
    ) -> Reach {
        let mode = entry.policy.mode_at(now_ms);
        Reach {
            mode,
            until_ms: entry.policy.until.filter(|_| mode != Mode::Allowlist),
            account,
            confined,
            held_by_account: false,
            reads_by_account: false,
            // A command on the list runs only through `exec.run`: where the
            // owner hid or turned that off for this center, none runs.
            sudo: !entry.policy.sudo_allow.is_empty()
                && !matches!(
                    entry.policy.cap_setting("exec", Some("run")),
                    Some(CapSetting::Hidden | CapSetting::Off)
                ),
            folders: entry.policy.folders.clone(),
            own: run_home.map(crate::account::built_in).unwrap_or_default(),
        }
    }

    /// The `access` block: in `folder` mode with the folders in the
    /// center's path form (`windows`: `C:\x` is `/c/x`), one entry per
    /// place with the flags of every grant of it together. A folder without
    /// a flag is never named: the node's file calls hide its name (a listing
    /// leaves it out, a refusal under it reads like any other), so the block
    /// does not give it away either. Where it lies inside a granted folder,
    /// which it closes (the deepest folder decides), the deepest such folder
    /// is marked `closed_below`. A folder whose name the center could not
    /// show as it is ([`nerve_proto::descriptor::plain_line`]) is left out
    /// and counted; it narrows like any other, so where it allows less than
    /// the deepest named folder around it, that one is marked too. Where the
    /// machine runs no folder-mode command, no folder is marked `x`: only
    /// a command on the sudo allow list runs then. Only folder mode names
    /// folders: in allowlist mode as `nerve-run` they still hold the allowed
    /// commands, which the block does not tell.
    fn access(&self, windows: bool) -> Access {
        // The folders hold a call only where the effect table holds its
        // paths to them.
        let folder = [Effect::Read, Effect::Write, Effect::Execute]
            .into_iter()
            .any(|e| {
                let paths = PathArgs::Some {
                    all_in_folders: false,
                };
                effect_rule(self.mode, e, paths, None) == Need::InFolders
            });
        let within = |p: &str, b: &str| {
            if windows {
                nerve_policy::paths::win::within(p, b)
            } else {
                nerve_policy::paths::within(std::path::Path::new(p), std::path::Path::new(b))
            }
        };
        // (the native path, the wire path, the flags, whether it is the
        // account's own)
        let mut folders: Vec<(&str, String, nerve_policy::config::Access, bool)> = Vec::new();
        let all = self.folders.iter().map(|f| (f, false));
        for (f, own) in all
            .chain(self.own.iter().map(|f| (f, true)))
            .filter(|_| folder)
        {
            let path = if windows {
                nerve_policy::paths::win::to_wire(&f.path)
            } else {
                f.path.clone()
            };
            match folders
                .iter_mut()
                .find(|(n, _, _, _)| within(n, &f.path) && within(&f.path, n))
            {
                Some((_, _, a, o)) => {
                    a.read |= f.access.read;
                    a.write |= f.access.write;
                    a.execute |= f.access.execute;
                    *o |= own;
                }
                None => folders.push((&f.path, path, f.access, own)),
            }
        }
        // A machine that cannot confine a folder-mode command refuses it
        // ([`crate::daemon::folder_refusal`]), and a program's execute action
        // with paths as well, so `x` lets nothing start.
        if !self.confined {
            for (_, _, a, _) in &mut folders {
                a.execute = false;
            }
        }
        let below = |n: &str, b: &str| within(n, b) && !within(b, n);
        let named: Vec<bool> = folders
            .iter()
            .map(|(_, path, a, _)| !a.is_none() && nerve_proto::descriptor::plain_line(path))
            .collect();
        let mut closed_below = vec![false; folders.len()];
        for (c, (n, _, a, _)) in folders.iter().enumerate() {
            if named[c] {
                continue;
            }
            let around: Vec<usize> = (0..folders.len())
                .filter(|&g| named[g] && below(n, folders[g].0))
                .collect();
            // The named folders around it nest, so the deepest one is the
            // one no other lies below.
            let Some(&g) = around
                .iter()
                .find(|&&g| !around.iter().any(|&o| below(folders[o].0, folders[g].0)))
            else {
                continue;
            };
            // A folder left out for its name that allows at least what the
            // one around it does takes nothing the agent was told of.
            let more = |x: bool, y: bool| x || !y;
            let g_a = folders[g].2;
            if a.is_none()
                || !(more(a.read, g_a.read)
                    && more(a.write, g_a.write)
                    && more(a.execute, g_a.execute))
            {
                closed_below[g] = true;
            }
        }
        let unnamed = folders
            .iter()
            .zip(&named)
            .filter(|((_, _, a, _), named)| !a.is_none() && !**named)
            .count() as u64;
        Access {
            mode: match self.mode {
                Mode::Allowlist => AccessMode::Allowlist,
                Mode::Folder => AccessMode::Folder,
                Mode::User => AccessMode::User,
            },
            until_ms: self.until_ms,
            account: self.account.clone(),
            confined: folder && self.confined && !self.held_by_account,
            sudo: folder && self.sudo,
            reads_by_account: folder && self.reads_by_account,
            folders: folders
                .into_iter()
                .zip(closed_below)
                .zip(named)
                // A name the center cannot show on one line as it is (a
                // control character or separator, a blank at either end)
                // would be shown changed, which names another place.
                .filter(|(_, named)| *named)
                .map(|(((_, path, a, own), closed_below), _)| FolderAccess {
                    path,
                    access: a.to_string(),
                    own,
                    closed_below,
                })
                .collect(),
            unnamed,
        }
    }
}

/// The descriptor `entry` sees now, with its `access` from `reach`; `rev`
/// is derived from its content, so it changes exactly when the view
/// changes. The center lists what it offers from it, so an action the
/// policy cannot allow is not in it. Where the machine cannot confine a
/// command (`reach.confined`), folder mode offers no command. `provided`
/// are the capabilities the attached providers add (crate::provider), each
/// cut by the same policy.
pub fn for_center(
    cfg: &NodeConfig,
    entry: &CenterEntry,
    reach: &Reach,
    provided: &[Capability],
) -> Descriptor {
    build(cfg, entry, reach, true, provided)
}

/// Every action a call may name: [`for_center`] without the cut by allow
/// rules. A call for an action no rule covers still reaches the policy, which
/// refuses it and writes the audit entry; only hidden ones are unknown. Its
/// reach names no account: no center sees it.
pub fn for_call(
    cfg: &NodeConfig,
    entry: &CenterEntry,
    now_ms: u64,
    provided: &[Capability],
) -> Descriptor {
    let reach = Reach::of(entry, now_ms, None, true, None);
    build(cfg, entry, &reach, false, provided)
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

/// The node's own capabilities that have actions, every action in: what
/// `cap ls` lists as built in (crate::provider::listing). `settings` among
/// them, which no switch but `center grant settings` governs.
pub fn built_in(cfg: &NodeConfig) -> Vec<Capability> {
    vec![
        fs_cap(Exposure::On),
        exec_cap(
            Exposure::On,
            cfg.machine.shell.as_deref(),
            cfg!(windows),
            &cfg.limits.command,
            &crate::exec::Timeouts::from_limits(&cfg.limits),
        ),
        settings_cap(),
    ]
}

fn build(
    cfg: &NodeConfig,
    entry: &CenterEntry,
    reach: &Reach,
    by_rules: bool,
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
    // Actions the policy cannot allow are left out, so the center offers
    // none the node would refuse; off ones stay, marked off, and fail
    // `disabled`. A capability with no action left goes too.
    let view = View {
        mode: reach.mode,
        by_rules,
        confined: reach.confined,
    };
    for c in &mut caps {
        let id = c.id.clone();
        let node = c.provider == "node";
        c.actions.retain(|a, decl| {
            let marks = nerve_proto::schema::path_args(&decl.params);
            let paths = node
                || if decl.effect == Effect::Write {
                    marks.iter().any(|(_, m)| *m == PathMark::Write)
                } else {
                    !marks.is_empty()
                };
            offered(&entry.policy, view, &id, a, decl.effect, paths)
        });
        for (a, decl) in &mut c.actions {
            if entry.policy.cap_setting(&id, Some(a)) == Some(CapSetting::Off) {
                decl.exposure = Some(Exposure::Off);
            }
        }
    }
    caps.retain(|c| !(governed(&c.id) && c.actions.is_empty()));
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
        // The mode is in `access`, which a center reads; the summary stays
        // the same through a mode change.
        summary: format!(
            "{platform} machine {name}: files and shell commands, under its owner's policy."
        ),
        capabilities: caps,
        access: Some(reach.access(cfg!(windows))),
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

    /// [`super::for_center`] with the reach of `e` at `now_ms`: no account,
    /// and its own folders only.
    fn for_center(
        cfg: &NodeConfig,
        e: &CenterEntry,
        now_ms: u64,
        confined: bool,
        provided: &[Capability],
    ) -> Descriptor {
        super::for_center(
            cfg,
            e,
            &Reach::of(e, now_ms, None, confined, None),
            provided,
        )
    }

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
            reads: nerve_policy::decide::Reads::Folders,
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

    /// The one place outside the effect table: on a machine that cannot
    /// confine a command, `folder` mode with an empty sudo allow list offers
    /// no `exec` action, `exec.signal` set to on included, though `decide`
    /// lets a call of it through (no command can run there to signal).
    /// Confined, or with a sudo allow list, it is offered as `decide` allows.
    #[test]
    fn exec_signal_goes_with_exec_where_commands_cannot_be_confined() {
        use nerve_policy::protected::{Platform, Protected};
        use nerve_policy::{Call, Decision, Env, decide};
        let home = std::path::Path::new("/h");
        let prot = Protected::new(&Platform::Unix, home, &[], &Default::default());
        let env = Env {
            home,
            protected: &prot,
            unconfined: Some("commands cannot be confined here"),
            sudo: false,
            shell: nerve_policy::command::Shell::native(),
            reads: nerve_policy::decide::Reads::Folders,
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
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.caps.insert("exec.signal".into(), CapSetting::On);
        assert_eq!(decide(&e.policy, &env, &call), Decision::Allow);
        assert!(actions(&for_center(&cfg, &e, 0, false, &[]), "exec").is_empty());
        let shown = |e: &CenterEntry, confined| {
            actions(&for_center(&cfg, e, 0, confined, &[]), "exec").contains(&"signal".into())
        };
        assert!(shown(&e, true));
        e.policy.sudo_allow = rules(&["sudo apt *"]);
        assert!(shown(&e, false));
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

    /// [`provided`] whose action takes a path it reads or writes (`mark`).
    fn provided_at(effect: Effect, mark: PathMark) -> Capability {
        let mut c = provided(effect);
        c.actions.get_mut("say").unwrap().params = obj(
            json!({"path": {"type": "string", "x-nerve-path": mark.as_str()}}),
            &["path"],
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
            reads: nerve_policy::decide::Reads::Folders,
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

    /// What a center is shown follows the effect table, for every mode,
    /// effect, setting, allow rule and confinement: a provider's action
    /// that names no path exactly where `decide` lets a call of it through;
    /// `fs.read`, `fs.write`, `exec.run` and a provider's action with a path
    /// it reads or writes exactly where the table allows a call with its
    /// paths in the folders, which `decide` then allows, while it allows one
    /// outside them as the table says. Where the command account holds the
    /// reads, a read call's path outside the folders is in its reach.
    #[test]
    fn what_is_offered_follows_the_effect_table() {
        use Need::{AllowRule, Allowed, InFolders, NeedsOn, Off};
        use nerve_policy::protected::{Platform, Protected};
        use nerve_policy::{Call, Decision, Env, PathAccess, Target, decide};
        let home = std::path::Path::new("/h");
        let prot = Protected::new(&Platform::Unix, home, &[], &Default::default());
        let env = |confined: bool| Env {
            home,
            protected: &prot,
            unconfined: (!confined).then_some("commands cannot be confined here"),
            sudo: false,
            shell: nerve_policy::command::Shell::Sh,
            reads: nerve_policy::decide::Reads::Folders,
        };
        let may = |_: &std::path::Path| Ok(());
        let by_account = |confined: bool| Env {
            reads: nerve_policy::decide::Reads::Account(&may),
            ..env(confined)
        };
        let cfg = NodeConfig::default();
        let effects = [
            Effect::Read,
            Effect::Write,
            Effect::Execute,
            Effect::Sense,
            Effect::Actuate,
        ];
        let settings = [
            None,
            Some(CapSetting::On),
            Some(CapSetting::Off),
            Some(CapSetting::Hidden),
        ];
        // The policy for one row; its only folder `/w` allows everything.
        let policy_of = |mode, key: &str, setting: Option<CapSetting>, allow: &[&str]| {
            let mut e = entry();
            e.policy.mode = mode;
            e.policy.folders = vec![folder("/w", "rwx")];
            e.policy.allow = rules(allow);
            if let Some(s) = setting {
                e.policy.caps.insert(key.into(), s);
            }
            e
        };
        // The table as policy-engine.md gives it: (mode, effect, no path,
        // paths in the folders, a path outside).
        #[rustfmt::skip]
        let table = [
            (Mode::Allowlist, Effect::Read, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Write, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Execute, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Sense, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Actuate, AllowRule, AllowRule, AllowRule),
            (Mode::Folder, Effect::Read, NeedsOn, Allowed, InFolders),
            (Mode::Folder, Effect::Write, NeedsOn, Allowed, InFolders),
            (Mode::Folder, Effect::Execute, NeedsOn, Allowed, InFolders),
            (Mode::Folder, Effect::Sense, NeedsOn, NeedsOn, InFolders),
            (Mode::Folder, Effect::Actuate, NeedsOn, NeedsOn, InFolders),
            (Mode::User, Effect::Read, Allowed, Allowed, Allowed),
            (Mode::User, Effect::Write, Allowed, Allowed, Allowed),
            (Mode::User, Effect::Execute, Allowed, Allowed, Allowed),
            (Mode::User, Effect::Sense, NeedsOn, NeedsOn, NeedsOn),
            (Mode::User, Effect::Actuate, NeedsOn, NeedsOn, NeedsOn),
        ];
        // The cell for a call, `on`, `off` and `hidden` applied; the table
        // function agrees.
        let need = |mode, effect, paths, setting| {
            let (.., none, inside, outside) = *table
                .iter()
                .find(|(m, e, ..)| *m == mode && *e == effect)
                .unwrap();
            let cell = match paths {
                PathArgs::None => none,
                PathArgs::Some {
                    all_in_folders: true,
                } => inside,
                PathArgs::Some {
                    all_in_folders: false,
                } => outside,
            };
            let cell = match (cell, setting) {
                (_, Some(CapSetting::Off | CapSetting::Hidden)) => Off,
                (NeedsOn, Some(CapSetting::On)) => Allowed,
                (cell, _) => cell,
            };
            assert_eq!(effect_rule(mode, effect, paths, setting), cell);
            cell
        };
        // Shown, and not marked off.
        let shown_on = |d: &Descriptor, cap: &str, action: &str| {
            d.capability(cap)
                .and_then(|c| c.actions.get(action))
                .is_some_and(|a| a.exposure != Some(Exposure::Off))
        };
        let mut rows = 0;
        for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
            for setting in settings {
                for confined in [true, false] {
                    // A provider's action: no path.
                    for effect in effects {
                        let provided = [provided(effect)];
                        for allow in [&[][..], &["echo.say"], &["echo"], &["echo.other"]] {
                            let e = policy_of(mode, "echo.say", setting, allow);
                            let what = format!(
                                "echo.say {effect:?} {mode:?} {setting:?} {allow:?} confined={confined}"
                            );
                            let d = for_center(&cfg, &e, 0, confined, &provided);
                            let call = Call {
                                cap: "echo",
                                action: "say",
                                effect,
                                targets: &[],
                                command: None,
                                cwd: None,
                                now_ms: 0,
                            };
                            let allowed =
                                decide(&e.policy, &env(confined), &call) == Decision::Allow;
                            assert_eq!(shown_on(&d, "echo", "say"), allowed, "{what}");
                            let want = match need(mode, effect, PathArgs::None, setting) {
                                Need::Allowed => true,
                                Need::AllowRule => allow.len() == 1 && allow[0] != "echo.other",
                                Need::InFolders | Need::NeedsOn | Need::Off => false,
                            };
                            assert_eq!(allowed, want, "{what}");
                            rows += 1;
                        }
                    }
                    // The built-in actions that name their paths per call,
                    // and a provider's that reads or writes a path.
                    let mut path_actions: Vec<(&str, &str, Effect, Option<PathMark>)> = vec![
                        ("fs", "read", Effect::Read, None),
                        ("fs", "write", Effect::Write, None),
                        ("exec", "run", Effect::Execute, None),
                    ];
                    for effect in effects {
                        for mark in [PathMark::Read, PathMark::Write] {
                            path_actions.push(("echo", "say", effect, Some(mark)));
                        }
                    }
                    for (cap, action, effect, mark) in path_actions {
                        let key = format!("{cap}.{action}");
                        let provided: Vec<Capability> =
                            mark.map(|m| provided_at(effect, m)).into_iter().collect();
                        let other = if cap == "echo" {
                            "echo.other"
                        } else {
                            "fs.stat"
                        };
                        for allow in [&[][..], &[key.as_str()], &[cap], &[other]] {
                            let e = policy_of(mode, &key, setting, allow);
                            let what = format!(
                                "{key} {effect:?} {mark:?} {mode:?} {setting:?} {allow:?} confined={confined}"
                            );
                            let d = for_center(&cfg, &e, 0, confined, &provided);
                            let covered = allow.len() == 1 && allow[0] != other;
                            // A write whose only path is one it reads names
                            // no place it writes: the table's no-path cell,
                            // while its path is in the folders.
                            let writes_nowhere =
                                effect == Effect::Write && mark == Some(PathMark::Read);
                            let by_table = |all_in_folders| {
                                let paths = if writes_nowhere && all_in_folders {
                                    PathArgs::None
                                } else {
                                    PathArgs::Some { all_in_folders }
                                };
                                match need(mode, effect, paths, setting) {
                                    // Folder mode runs no command and no
                                    // program's execute action with paths
                                    // where it cannot confine commands.
                                    Allowed => {
                                        confined
                                            || effect != Effect::Execute
                                            || mode != Mode::Folder
                                    }
                                    AllowRule => covered,
                                    InFolders | NeedsOn | Off => false,
                                }
                            };
                            assert_eq!(shown_on(&d, cap, action), by_table(true), "{what}");
                            for (path, all_in_folders) in [("/w", true), ("/elsewhere", false)] {
                                let access = match (mark, effect) {
                                    (Some(PathMark::Read), _) => PathAccess::Read,
                                    (Some(PathMark::Write), _) | (None, Effect::Write) => {
                                        PathAccess::Write
                                    }
                                    (None, Effect::Execute) => PathAccess::Run,
                                    (None, _) => PathAccess::Read,
                                };
                                let path = if cap == "exec" {
                                    path.to_string()
                                } else {
                                    format!("{path}/a")
                                };
                                let targets = [Target {
                                    path: path.clone().into(),
                                    access,
                                    holds: true,
                                }];
                                let run = cap == "exec";
                                let call = Call {
                                    cap,
                                    action,
                                    effect,
                                    targets: &targets,
                                    command: run.then_some("make"),
                                    cwd: run.then_some(std::path::Path::new(&path)),
                                    now_ms: 0,
                                };
                                let want = by_table(all_in_folders);
                                let allowed =
                                    decide(&e.policy, &env(confined), &call) == Decision::Allow;
                                assert_eq!(allowed, want, "{what} at {path}");
                                // Where the account holds the reads, a read
                                // call reads where it may, in the folders or
                                // not.
                                let reads = effect == Effect::Read && access == PathAccess::Read;
                                let want = if reads { by_table(true) } else { want };
                                let allowed = decide(&e.policy, &by_account(confined), &call)
                                    == Decision::Allow;
                                assert_eq!(allowed, want, "{what} at {path}, read by the account");
                            }
                            rows += 1;
                        }
                    }
                }
            }
        }
        // 3 modes × 4 settings × 2 confinements × (5 effects + 3 built-in
        // path actions + 5 effects × 2 marks) × 4 allow lists.
        assert_eq!(rows, 3 * 4 * 2 * 18 * 4);
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
    /// so a model does not send `C:\...`. Each marks its path with what it
    /// does there (`x-nerve-path`), as any capability's path is marked.
    #[test]
    fn a_windows_node_shows_the_wire_form_of_a_path() {
        let win = path_param(true, PathMark::Read);
        let text = win["description"].as_str().unwrap();
        assert!(
            text.contains("/c/Users/") && text.contains("C:\\Users\\"),
            "{text}"
        );
        assert_eq!(
            path_param(false, PathMark::Read)["description"],
            "absolute path"
        );
        let fs = fs_cap(Exposure::On);
        for (a, mark) in [
            ("stat", PathMark::Read),
            ("list", PathMark::Read),
            ("read", PathMark::Read),
            ("grep", PathMark::Read),
            ("find", PathMark::Read),
            ("write", PathMark::Write),
        ] {
            let params = &fs.actions[a].params;
            assert_eq!(
                params["properties"]["path"],
                path_param(cfg!(windows), mark),
                "{a}"
            );
            assert_eq!(
                nerve_proto::schema::path_args(params),
                [("path".to_string(), mark)],
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
        assert_eq!(
            cwd_param(false),
            json!({"type": ["string", "null"], "x-nerve-path": "read"})
        );
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
            assert_eq!(
                nerve_proto::schema::path_args(&exec.actions["run"].params),
                [("cwd".to_string(), PathMark::Read)]
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

    fn folder(path: &str, access: &str) -> Folder {
        Folder {
            path: path.into(),
            access: nerve_policy::config::Access::parse(access).unwrap(),
        }
    }

    fn folders(d: &Descriptor) -> Vec<(String, String)> {
        d.access
            .as_ref()
            .unwrap()
            .folders
            .iter()
            .map(|f| {
                (
                    f.path.clone(),
                    format!("{}{}", f.access, if f.own { " own" } else { "" }),
                )
            })
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(p, a)| (p.to_string(), a.to_string()))
            .collect()
    }

    /// A center is told its own mode, account and folders, and never
    /// another pairing's.
    #[test]
    fn access_names_only_this_centers_folders() {
        let mut cfg = NodeConfig::default();
        let mut a = entry();
        a.policy.mode = Mode::Folder;
        a.policy.until = Some(50);
        a.policy.folders = vec![folder("/home/me/proj", "rw")];
        let mut b = entry();
        b.name = "work".into();
        b.center_id = "c2".into();
        b.policy.mode = Mode::Folder;
        b.policy.folders = vec![folder("/home/me/secret", "rwx")];
        cfg.centers = vec![a.clone(), b];
        let reach = Reach::of(&a, 10, Some("nerve-run".into()), true, None);
        let d = super::for_center(&cfg, &a, &reach, &[]);
        let access = d.access.clone().unwrap();
        assert_eq!(access.mode, AccessMode::Folder);
        assert_eq!(access.until_ms, Some(50));
        assert_eq!(access.account.as_deref(), Some("nerve-run"));
        assert!(access.confined);
        assert_eq!(folders(&d), pairs(&[("/home/me/proj", "rw")]));
        let text = serde_json::to_string(&d).unwrap();
        assert!(!text.contains("secret"), "{text}");
        // The mode is told in the access block, not in the summary.
        assert!(!d.summary.contains("mode"), "{}", d.summary);
    }

    /// The built-in folders of `nerve-run` are named where the commands run
    /// as that account, with every flag and marked as its own, together
    /// with a grant of the same place; folders are named in folder mode
    /// only, and one with no flag outside every granted one grants nothing.
    #[test]
    fn built_in_folders_only_when_separate() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![
            folder("/srv/data", "r"),
            folder("/tmp", "r"),
            folder("/srv/none", ""),
        ];
        let home = std::path::Path::new("/var/lib/nerve-run");
        let separate = Reach::of(&e, 0, Some("nerve-run".into()), true, Some(home));
        assert_eq!(
            folders(&super::for_center(
                &NodeConfig::default(),
                &e,
                &separate,
                &[]
            )),
            pairs(&[
                ("/srv/data", "r"),
                ("/tmp", "rwx own"),
                ("/var/tmp", "rwx own"),
                ("/var/lib/nerve-run", "rwx own"),
            ])
        );
        let own = Reach::of(&e, 0, Some("me".into()), true, None);
        let d = super::for_center(&NodeConfig::default(), &e, &own, &[]);
        assert_eq!(folders(&d), pairs(&[("/srv/data", "r"), ("/tmp", "r")]));
        // Outside folder mode no folder is named, and nothing is confined.
        for mode in [Mode::Allowlist, Mode::User] {
            e.policy.mode = mode;
            let r = Reach::of(&e, 0, Some("nerve-run".into()), true, Some(home));
            let d = super::for_center(&NodeConfig::default(), &e, &r, &[]);
            let a = d.access.unwrap();
            assert!(a.folders.is_empty(), "{mode:?}");
            assert!(!a.confined, "{mode:?}");
            assert_eq!(a.mode.as_str(), mode.as_str());
        }
        // A folder mode that ran out is allowlist, with no end to tell.
        e.policy.mode = Mode::Folder;
        e.policy.until = Some(5);
        let r = Reach::of(&e, 5, None, true, None);
        let a = super::for_center(&NodeConfig::default(), &e, &r, &[])
            .access
            .unwrap();
        assert_eq!((a.mode, a.until_ms), (AccessMode::Allowlist, None));
        assert!(a.folders.is_empty());
    }

    /// A folder with no rights is never named, as the node's file calls
    /// hide its name too. Inside a granted one it closes what lies below
    /// it (the deepest folder decides), so the deepest granted folder
    /// around it says that something below is closed; on Windows too,
    /// where case does not tell places apart.
    #[test]
    fn a_closed_folder_is_not_named_and_its_granted_folder_says_so() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![
            folder("/home/me/docs", "r"),
            folder("/home/me/docs/medical", ""),
            folder("/home/me/proj", "rwx"),
            folder("/home/me/proj/app", "rw"),
            folder("/home/me/proj/app/secrets", ""),
            folder("/home/me/projects", ""),
            folder("/home/me/proj/app/secrets/open", "r"),
            folder("/home/me/cfg", "r"),
            folder("/home/me/cfg/a\nb", ""),
        ];
        let r = Reach::of(&e, 0, Some("me".into()), true, None);
        let d = super::for_center(&NodeConfig::default(), &e, &r, &[]);
        let marked = |d: &Descriptor| -> Vec<(String, String, bool)> {
            d.access
                .as_ref()
                .unwrap()
                .folders
                .iter()
                .map(|f| (f.path.clone(), f.access.clone(), f.closed_below))
                .collect()
        };
        let s = |p: &str, a: &str, c: bool| (p.to_string(), a.to_string(), c);
        assert_eq!(
            marked(&d),
            vec![
                s("/home/me/docs", "r", true),
                s("/home/me/proj", "rwx", false),
                s("/home/me/proj/app", "rw", true),
                s("/home/me/proj/app/secrets/open", "r", false),
                // A closed name that could not be shown still closes.
                s("/home/me/cfg", "r", true),
            ]
        );
        let text = serde_json::to_string(&d).unwrap();
        for never in ["medical", "secrets\"", "projects", "a\\nb"] {
            assert!(!text.contains(never), "{never}: {text}");
        }
        e.policy.folders = vec![
            folder("C:\\Work", "rw"),
            folder("c:\\work\\keys", ""),
            folder("c:\\WORK", "x"),
        ];
        let r = Reach::of(&e, 0, Some("me".into()), true, None);
        let got: Vec<(String, String, bool)> = r
            .access(true)
            .folders
            .into_iter()
            .map(|f| (f.path, f.access, f.closed_below))
            .collect();
        assert_eq!(got, vec![s("/c/Work", "rwx", true)]);
    }

    /// A folder whose name the center would change to show it on one line
    /// is left out: a control character or a line or paragraph separator,
    /// or a blank at either end. A changed name is another place.
    #[test]
    fn a_folder_named_with_a_control_character_is_left_out() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![
            folder("/srv/a\nb", "rw"),
            folder("/srv/data ", "rw"),
            folder("/srv/e\u{2028}f", "rw"),
            folder("/srv/g\u{2029}h", "rw"),
            folder("/srv/c\\d", "r"),
        ];
        let r = Reach::of(&e, 0, None, true, None);
        let named = |windows: bool| -> Vec<(String, String)> {
            r.access(windows)
                .folders
                .into_iter()
                .map(|f| (f.path, f.access))
                .collect()
        };
        // A backslash is part of a Unix name, and stays.
        assert_eq!(named(false), pairs(&[("/srv/c\\d", "r")]));
        e.policy.folders = vec![folder("C:\\a\tb", "rw"), folder("C:\\c", "r")];
        let r = Reach::of(&e, 0, None, true, None);
        assert_eq!(
            r.access(true)
                .folders
                .into_iter()
                .map(|f| (f.path, f.access))
                .collect::<Vec<_>>(),
            pairs(&[("/c/c", "r")])
        );
        assert_eq!(r.access(true).unnamed, 1);
    }

    /// A folder left out for its name still narrows the folder around it
    /// (the deepest one decides), so where it allows less, the named folder
    /// around it says some folders below allow less; and the folders left
    /// out are counted, so a block with none named does not read as no
    /// grant at all.
    #[test]
    fn a_folder_left_out_for_its_name_still_narrows_and_is_counted() {
        let marked = |list: Vec<Folder>| -> (Vec<(String, String, bool)>, u64) {
            let mut e = entry();
            e.policy.mode = Mode::Folder;
            e.policy.folders = list;
            let a = Reach::of(&e, 0, None, true, None).access(false);
            let named = a
                .folders
                .into_iter()
                .map(|f| (f.path, f.access, f.closed_below))
                .collect();
            (named, a.unnamed)
        };
        let s = |p: &str, a: &str, c: bool| (p.to_string(), a.to_string(), c);
        // Less than the folder around it: that one is marked.
        assert_eq!(
            marked(vec![folder("/srv", "rwx"), folder("/srv/data ", "r")]),
            (vec![s("/srv", "rwx", true)], 1)
        );
        // At least as much: nothing the agent was told is taken.
        assert_eq!(
            marked(vec![folder("/srv", "r"), folder("/srv/data ", "rw")]),
            (vec![s("/srv", "r", false)], 1)
        );
        // A closed folder inside a left-out one marks the named one around.
        assert_eq!(
            marked(vec![
                folder("/srv", "rw"),
                folder("/srv/data ", "rw"),
                folder("/srv/data /keys", ""),
            ]),
            (vec![s("/srv", "rw", true)], 1)
        );
        // None named, but one granted: counted. A closed one is not.
        assert_eq!(
            marked(vec![folder("/srv/data ", "rw"), folder("/srv/k", "")]),
            (vec![], 1)
        );
    }

    /// Where the machine runs no folder-mode command, no folder is marked
    /// `x` (a folder with `x` alone then allows nothing, like a closed
    /// one); and in folder mode the block says when the sudo allow list
    /// names commands, which run by that list alone.
    #[test]
    fn the_block_tells_where_commands_run_and_the_sudo_list() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![folder("/srv", "rwx"), folder("/srv/bin", "x")];
        let flags = |r: &Reach| -> Vec<(String, String, bool)> {
            r.access(false)
                .folders
                .into_iter()
                .map(|f| (f.path, f.access, f.closed_below))
                .collect()
        };
        let s = |p: &str, a: &str, c: bool| (p.to_string(), a.to_string(), c);
        let runs = Reach::of(&e, 0, None, true, None);
        assert_eq!(
            flags(&runs),
            vec![s("/srv", "rwx", false), s("/srv/bin", "x", false)]
        );
        assert!(!runs.access(false).sudo);
        let none = Reach::of(&e, 0, None, false, None);
        assert_eq!(flags(&none), vec![s("/srv", "rw", true)]);
        e.policy.sudo_allow = vec!["sudo apt update".into()];
        let none = Reach::of(&e, 0, None, false, None);
        assert!(none.access(false).sudo);
        let d = super::for_center(&NodeConfig::default(), &e, &none, &[]);
        assert!(actions(&d, "exec").contains(&"run".to_string()));
        // With `exec.run` hidden or off for this center no listed command
        // runs, so the block names no sudo list.
        for (key, setting) in [
            ("exec", CapSetting::Off),
            ("exec", CapSetting::Hidden),
            ("exec.run", CapSetting::Off),
            ("exec.run", CapSetting::Hidden),
        ] {
            e.policy.caps.insert(key.into(), setting);
            assert!(
                !Reach::of(&e, 0, None, false, None).access(false).sudo,
                "{key} {setting:?}"
            );
            e.policy.caps.clear();
        }
        e.policy.caps.insert("exec".into(), CapSetting::On);
        assert!(Reach::of(&e, 0, None, false, None).access(false).sudo);
        e.policy.caps.clear();
        // Outside folder mode the block names no folder, and no sudo list.
        e.policy.mode = Mode::Allowlist;
        let r = Reach::of(&e, 0, None, true, None);
        assert!(!r.access(false).sudo);
    }

    /// Where only the account they run as holds folder-mode commands back,
    /// they reach more than the folders: the block does not call them
    /// confined, though they run.
    #[test]
    fn commands_held_by_their_account_alone_are_not_called_confined() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![folder("/srv/data", "rwx")];
        let mut r = Reach::of(&e, 0, Some("nerve-run".into()), true, None);
        assert!(r.access(false).confined);
        r.held_by_account = true;
        let d = super::for_center(&NodeConfig::default(), &e, &r, &[]);
        assert!(!d.access.clone().unwrap().confined);
        assert!(actions(&d, "exec").contains(&"run".to_string()));
    }

    /// Where the node reads as the command account, the block says that a
    /// read goes as far as that account may read; only folder mode, where
    /// the folders hold the rest, says it.
    #[test]
    fn the_access_block_says_where_reads_go() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![folder("/srv/data", "rw")];
        let mut r = Reach::of(&e, 0, Some("nerve-run".into()), true, None);
        assert!(!r.access(false).reads_by_account);
        r.reads_by_account = true;
        assert!(r.access(false).reads_by_account);
        for mode in [Mode::User, Mode::Allowlist] {
            e.policy.mode = mode;
            let mut r = Reach::of(&e, 0, Some("nerve-run".into()), true, None);
            r.reads_by_account = true;
            assert!(!r.access(false).reads_by_account, "{mode:?}");
        }
    }

    /// A Windows node names its folders in the center's form, as its paths
    /// are given in calls.
    #[test]
    fn windows_folders_are_in_wire_form() {
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        e.policy.folders = vec![folder("C:\\Users\\me\\proj", "rwx"), folder("D:\\", "r")];
        let r = Reach::of(&e, 0, Some("me".into()), true, None);
        let a = r.access(true);
        let got: Vec<(&str, &str)> = a
            .folders
            .iter()
            .map(|f| (f.path.as_str(), f.access.as_str()))
            .collect();
        assert_eq!(got, [("/c/Users/me/proj", "rwx"), ("/d", "r")]);
        // A Unix node's stay as they are.
        assert_eq!(r.access(false).folders[0].path, "C:\\Users\\me\\proj");
    }

    /// An action the owner switched off is listed and marked off, so the
    /// center can tell it from one that is on.
    #[test]
    fn an_off_action_is_marked_off() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.mode = Mode::User;
        e.policy.caps.insert("fs.write".into(), CapSetting::Off);
        let d = for_center(&cfg, &e, 0, true, &[]);
        let fs = d.capability("fs").unwrap();
        assert_eq!(fs.exposure, Exposure::On);
        assert_eq!(fs.actions["write"].exposure, Some(Exposure::Off));
        assert_eq!(fs.actions["read"].exposure, None);
        assert_eq!(d.capability("exec").unwrap().actions["run"].exposure, None);
        // A capability set off marks its actions off as well.
        e.policy.caps.insert("exec".into(), CapSetting::Off);
        let d = for_center(&cfg, &e, 0, true, &[]);
        let exec = d.capability("exec").unwrap();
        assert_eq!(exec.exposure, Exposure::Off);
        assert_eq!(exec.actions["run"].exposure, Some(Exposure::Off));
        // A provider's action likewise.
        let provided = [provided(Effect::Read)];
        e.policy.caps.insert("echo.say".into(), CapSetting::Off);
        let d = for_center(&cfg, &e, 0, true, &provided);
        assert_eq!(
            d.capability("echo").unwrap().actions["say"].exposure,
            Some(Exposure::Off)
        );
    }

    /// What the access block names moves the rev, so the node tells the
    /// center: a folder grant in folder mode, the mode, its end, the
    /// account. A folder outside folder mode names nothing and leaves it.
    #[test]
    fn a_folder_grant_changes_the_rev() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        e.policy.mode = Mode::Folder;
        let rev = |e: &CenterEntry, account: Option<&str>| {
            let r = Reach::of(e, 0, account.map(str::to_string), true, None);
            super::for_center(&cfg, e, &r, &[]).rev
        };
        let none = rev(&e, Some("me"));
        e.policy.folders.push(folder("/home/me/proj", "rw"));
        let one = rev(&e, Some("me"));
        assert_ne!(none, one);
        e.policy.folders[0].access = nerve_policy::config::Access::parse("rwx").unwrap();
        assert_ne!(rev(&e, Some("me")), one);
        assert_ne!(rev(&e, Some("nerve-run")), rev(&e, Some("me")));
        e.policy.until = Some(1000);
        assert_ne!(
            rev(&e, Some("me")),
            rev(
                &{
                    let mut x = e.clone();
                    x.policy.until = None;
                    x
                },
                Some("me")
            )
        );
        e.policy.mode = Mode::User;
        let user = rev(&e, Some("me"));
        e.policy.folders.push(folder("/srv", "r"));
        assert_eq!(rev(&e, Some("me")), user);
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
            let mark = decl.params["properties"]["path"]["x-nerve-path"].clone();
            decl.params["properties"]["path"] = path_param(
                !cfg!(windows),
                if mark == "write" {
                    PathMark::Write
                } else {
                    PathMark::Read
                },
            );
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
