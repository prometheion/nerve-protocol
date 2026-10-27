//! The capabilities the owner declares in `node.toml` (`[[capability]]`,
//! nerve_policy::config::ConfigCapability, docs/user/config-capabilities.md):
//! what the node offers of them, and what a call's run returns. The link
//! decides a call like any other and runs the command itself (crate::link).
//!
//! The installed Linux node runs one as `nerve-run` (the default), held to
//! the folders like that account's commands, or as the owner where the entry
//! says so. A node run by hand has no `nerve-run`: it offers only those that
//! run as the owner, which is its own user. Windows reads them and offers
//! none yet.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use nerve_policy::NodeConfig;
use nerve_policy::config::{ConfigCapability, Output, RunsAs};
use nerve_proto::descriptor::{Action, Capability, Exposure};
use nerve_proto::{ErrorCode, RpcError};

/// The `provider` of a config capability in the descriptor and `cap ls`.
pub const PROVIDER: &str = "config";

/// The most of a failed command's stderr its error repeats.
const STDERR_MAX: usize = 16 * 1024;

/// The config's capabilities this node offers, one capability per `cap`
/// with its actions: [`offered_on`] for this platform.
pub fn offered(cfg: &NodeConfig, installed: bool) -> Vec<Capability> {
    offered_on(cfg, std::env::consts::OS, installed)
}

/// Why a node on `os` does not offer `c`, if it does not: it offers them on
/// Linux only for now, those of its platform, and on a node run by hand
/// (not `installed`) only those that run as the owner.
pub fn left_out(c: &ConfigCapability, os: &str, installed: bool) -> Option<String> {
    if os != "linux" {
        Some(format!(
            "a node on {os} offers no capability of node.toml yet (Linux only for now)"
        ))
    } else if !c.platform.takes(os) {
        Some(format!("for {} only", c.platform.as_str()))
    } else if !installed && c.account == RunsAs::NerveRun {
        Some(format!(
            "runs as {}, which a node run by hand does not have (account = \"owner\" runs it as you)",
            crate::account::RUN_USER
        ))
    } else {
        None
    }
}

/// The config's capabilities a node on `os` offers: those [`left_out`] does
/// not leave out.
pub fn offered_on(cfg: &NodeConfig, os: &str, installed: bool) -> Vec<Capability> {
    capabilities(
        cfg.capabilities
            .iter()
            .filter(|c| left_out(c, os, installed).is_none()),
    )
}

/// Every capability the config declares, offered here or not: what only
/// the owner may turn on goes by them (crate::provider::owner_only_of),
/// since the node knows ahead what each one will do once it is offered.
pub fn declared(cfg: &NodeConfig) -> Vec<Capability> {
    capabilities(cfg.capabilities.iter())
}

/// `entries` as capabilities, one per `cap` with its actions.
fn capabilities<'a>(entries: impl Iterator<Item = &'a ConfigCapability>) -> Vec<Capability> {
    let mut caps: BTreeMap<&str, Capability> = BTreeMap::new();
    for c in entries {
        let (cap, action) = c.split();
        let entry = caps.entry(cap).or_insert_with(|| Capability {
            id: cap.to_string(),
            profile: String::new(),
            provider: PROVIDER.into(),
            exposure: Exposure::On,
            summary: String::new(),
            actions: BTreeMap::new(),
            events: BTreeMap::new(),
            state: Value::Null,
            streams: BTreeMap::new(),
        });
        entry.actions.insert(
            action.to_string(),
            Action {
                effect: c.effect,
                summary: c.summary.clone(),
                params: c.params_schema(),
                result: c.result.schema(),
                exposure: None,
                // A center's advice on its paths follows the account.
                as_account: c.account == RunsAs::NerveRun,
            },
        );
    }
    caps.into_values().collect()
}

/// `caps` as a pairing is offered them: an action marked as a command of
/// the pairing's command account (`as_account`) keeps the mark only where
/// that pairing's commands run as `nerve-run` (`separate`). Elsewhere the
/// command account the center knows is the owner, which such an action
/// does not run as.
pub fn as_account_for(caps: &mut [Capability], separate: bool) {
    if !separate {
        for a in caps.iter_mut().flat_map(|c| c.actions.values_mut()) {
            a.as_account = false;
        }
    }
}

/// `c` as `cap ls --json` gives it: as the owner declared it, the schemas
/// as JSON.
pub fn entry(c: &ConfigCapability) -> Value {
    json!({
        "name": c.name,
        "summary": c.summary,
        "effect": c.effect,
        "command": c.command,
        "params": c.params,
        "result": match &c.result {
            Output::Text => json!(Output::Text.to_string()),
            Output::Json(s) => s.clone(),
        },
        "timeout_secs": c.timeout_secs,
        "account": c.account.as_str(),
        "platform": c.platform.as_str(),
    })
}

/// The folders Landlock holds a command of a config capability to as
/// `nerve-run`, from the pairing's `policy` (with the account's own folders
/// where the link added them): where the pairing's commands run as
/// `nerve-run` (`separate`), its folders; where they run as the owner, the
/// folders are the owner's and not `nerve-run`'s, so only the account's own
/// (`home` its home, none without one).
pub fn confined(
    policy: &nerve_policy::CenterPolicy,
    separate: bool,
    home: Option<&std::path::Path>,
) -> nerve_policy::CenterPolicy {
    let mut policy = policy.clone();
    if !separate {
        policy.folders = home.map(crate::account::built_in).unwrap_or_default();
    }
    policy
}

/// The file the program `program` of a command runs: as written where it
/// names a path, else the first file of that name in `path`, the `PATH` it
/// runs with, that this thread's account may execute (one it may not is
/// passed over, as `execvp` does). The node runs that file, so `PATH` is
/// looked up once, where [`written_by_centers`] judged it.
pub fn program_file(program: &str, path: Option<&std::ffi::OsStr>) -> Option<std::path::PathBuf> {
    if program.contains('/') {
        return Some(program.into());
    }
    path.and_then(|p| {
        std::env::split_paths(p)
            .map(|d| d.join(program))
            .find(|f| f.is_file() && executable(f))
    })
}

/// Why a command of `decl` that runs as the owner does not start: no file
/// of its program's name in `PATH` that the owner may execute.
pub fn no_program(decl: &ConfigCapability) -> String {
    format!(
        "{} runs as the owner and finds no program {} in the node's PATH that the owner may run",
        decl.name,
        decl.command.first().map_or("", String::as_str)
    )
}

/// Whether the account this thread acts as (crate::account::FsAs) may
/// execute `f`: asked with the effective ids, whose file system part that
/// account is, not with the real ones a plain `access` would take. That is
/// the `faccessat2` system call itself: where the kernel lacks it (before
/// 5.8), the C library's `faccessat` falls back to the plain call, which
/// asks with the real ids, the node's own, while they equal the effective
/// ones.
#[cfg(target_os = "linux")]
fn executable(f: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let Ok(c) = std::ffi::CString::new(f.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a C string that lives across the call, and integer flags.
    let asked = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    if asked == 0 {
        return true;
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
        return false;
    }
    // An older kernel: by the mode bits, for the file system ids and the
    // groups this thread has (ACLs are not read; execve refuses the rest).
    let Ok(m) = std::fs::metadata(f) else {
        return false;
    };
    // SAFETY: setfsuid and setfsgid with an impossible id change nothing
    // and answer the ids in force (as crate::account::FsAs reads them);
    // getgroups into a buffer of the size it asked for.
    let (uid, gid, groups) = unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut()).max(0);
        let mut groups = vec![0; n as usize];
        let n = libc::getgroups(n, groups.as_mut_ptr()).max(0);
        groups.truncate(n as usize);
        (
            libc::setfsuid(u32::MAX) as u32,
            libc::setfsgid(u32::MAX) as u32,
            groups,
        )
    };
    m.is_file()
        && if uid == 0 {
            m.mode() & 0o111 != 0
        } else {
            may(&m, uid, gid, &groups, 0o1)
        }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn executable(f: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(f.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a C string that lives across the call, and integer flags.
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

#[cfg(not(unix))]
fn executable(_: &std::path::Path) -> bool {
    true
}

/// Whether the account `uid` (in `gid` and `groups`) has `bits` (`0o1`
/// run or search, `0o2` write, `0o4` read) on the file of `m` by its mode,
/// from the class it is in: owner, group or other.
#[cfg(unix)]
fn may(m: &std::fs::Metadata, uid: u32, gid: u32, groups: &[u32], bits: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = m.mode();
    let class = if m.uid() == uid {
        mode >> 6
    } else if m.gid() == gid || groups.contains(&m.gid()) {
        mode >> 3
    } else {
        mode
    };
    class & bits == bits
}

/// Whether `place` (itself, not where it leads) belongs to the account
/// `run` or `run` may change it by its mode: a file it may write, a folder
/// it may add to or take from. A device or a socket, such as `/dev/null`,
/// is no code. ACLs are not read: the node's own grants are the `w`
/// folders, and it takes them away again.
#[cfg(unix)]
fn run_writes(place: &std::path::Path, run: &crate::service::Account) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = place.symlink_metadata() else {
        return false;
    };
    m.uid() == run.uid
        || (m.is_file() && may(&m, run.uid, run.gid, &run.groups, 0o2))
        || (m.is_dir() && may(&m, run.uid, run.gid, &run.groups, 0o3))
}

#[cfg(not(unix))]
fn run_writes(_: &std::path::Path, _: &crate::service::Account) -> bool {
    false
}

/// Why the command of `decl`, which runs with the owner's rights in `cwd`,
/// may not run: `cwd` itself, its program (looked up in `path` where it is a
/// bare name, [`program_file`]), or a place a fixed element names lies at
/// or below a folder of `writable`, where a center may write. A center
/// could put its own code there (the program, a script, a Makefile, a
/// module the program loads from where it starts) and have it run as the
/// owner. An element names a place where it is a full path, holds a `/`,
/// or names something that is there in `cwd`; so does the value in it of an
/// option or a variable (`--manifest-path=...`, `NAME=...`), the rest
/// of a short option that has its value attached (`-Cproj`, `-I/x`), the
/// file of `@file`, and each part of a list of paths (`a:b`) or of a URL
/// (`file:///x`). One that is not a full path counts from `cwd`. Each is
/// looked at where it leads (a link whose target is not there, where that
/// target would be), and a place not there yet where the nearest folder
/// above it leads, so a link out of such a folder counts too. The call's
/// arguments are judged by the gate.
///
/// On the installed node, `run` is `nerve-run`: a place that belongs to it,
/// that it may write, or in a folder (at any depth) that does or it may
/// change, counts too, as written and where it leads. What a center made
/// as that account while it had `w`, or replaced (`fs.write` writes aside
/// and renames over), stays that account's once the `w` is gone, and any
/// pairing whose commands run as `nerve-run` may change it. A file of the
/// owner's it wrote into in place, through the grant's ACL entry, stays the
/// owner's and is not told apart (the docs tell the owner to look).
pub fn written_by_centers(
    decl: &ConfigCapability,
    writable: &[std::path::PathBuf],
    run: Option<&crate::service::Account>,
    path: Option<&std::ffi::OsStr>,
    cwd: &std::path::Path,
) -> Option<String> {
    use std::path::{Path, PathBuf};
    // Where it leads; a place not there yet, where the nearest folder
    // above it that is there leads, since a center may put it there. A
    // link whose target is not there leads to that target all the same: a
    // center that may write there may take it away and put it back.
    let real = |p: &Path| {
        let mut rest = Vec::new();
        let mut at = p.to_path_buf();
        let mut hops = 0;
        loop {
            if let Ok(r) = std::fs::canonicalize(&at) {
                return rest.iter().rev().fold(r, |r, n| r.join(n));
            }
            // As many links as the kernel follows in one path.
            if hops < 40
                && let Ok(to) = std::fs::read_link(&at)
            {
                hops += 1;
                at = at.parent().map_or_else(|| to.clone(), |up| up.join(&to));
                continue;
            }
            match (at.parent(), at.file_name()) {
                (Some(up), Some(n)) => {
                    rest.push(n.to_os_string());
                    at = up.to_path_buf();
                }
                _ => return p.to_path_buf(),
            }
        }
    };
    let folders: Vec<PathBuf> = writable.iter().map(|f| real(f)).collect();
    let within = |place: &Path| {
        // Where it leads, and as it is written: a file not there yet may
        // still be put there.
        [real(place), place.to_path_buf()]
            .into_iter()
            .find_map(|seen| {
                folders
                    .iter()
                    .find(|f| nerve_policy::paths::within(&seen, f))
                    .cloned()
            })
    };
    let refused = |what: String, f: PathBuf| {
        format!(
            "{} runs as the owner and {what}, which lies in {}, where a center may write: that center's code would run with the owner's rights",
            decl.name,
            f.display()
        )
    };
    // The place itself or a folder above it, as written and where it
    // leads, that `run` owns or may change.
    let theirs = |place: &Path| {
        let run = run?;
        [place.to_path_buf(), real(place)]
            .into_iter()
            .find_map(|seen| {
                seen.ancestors()
                    .filter(|a| !a.as_os_str().is_empty())
                    .find(|a| run_writes(a, run))
                    .map(Path::to_path_buf)
            })
            .map(|p| (run.name.as_str(), p))
    };
    let judge = |what: String, place: &Path| {
        if let Some(f) = within(place) {
            return Some(refused(what, f));
        }
        theirs(place).map(|(name, p)| {
            format!(
                "{} runs as the owner and {what}, and {} is {name}'s or {name} may change it, so a center may write there: that center's code would run with the owner's rights",
                decl.name,
                p.display()
            )
        })
    };
    if let Some(why) = judge(format!("starts in {}", cwd.display()), cwd) {
        return Some(why);
    }
    let program = decl.command.first()?;
    let found = program_file(program, path);
    let named = decl.command[1..]
        .iter()
        .filter(|e| !(e.starts_with('{') && e.ends_with('}')))
        .flat_map(|e| {
            // The value of `--opt=value` or `NAME=value` names a place as
            // the element would, and so does the rest of `-Cdir` or
            // `-xf/path`: getopt reads a short option's value glued on.
            let value = e.split_once('=').map(|(_, v)| v);
            let short = e
                .strip_prefix('-')
                .filter(|r| !r.starts_with('-'))
                .and_then(|r| r.char_indices().nth(1))
                .map(|(i, _)| &e[1 + i..]);
            let slash = short.and_then(|_| e.find('/')).map(|i| &e[i..]);
            // `@file` reads more arguments from that file.
            let file = e.strip_prefix('@');
            // Each part of a list of paths (`PYTHONPATH=a:b`, `-cp a:b`)
            // names a place, and so does the path of a URL (`file:///x`).
            [Some(e.as_str()), value, short, slash, file]
                .into_iter()
                .flatten()
                .flat_map(|v| {
                    let parts = v.contains(':').then(|| v.split(':'));
                    std::iter::once(v).chain(parts.into_iter().flatten())
                })
                .filter(|v| !v.is_empty())
        })
        .filter_map(|e| {
            let place = cwd.join(e);
            (e.contains('/') || place.symlink_metadata().is_ok()).then_some(place)
        });
    for place in found.into_iter().chain(named) {
        if let Some(why) = judge(format!("its command names {}", place.display()), &place) {
            return Some(why);
        }
    }
    None
}

/// What the allow rules let a center write with the owner's rights, which
/// [`written_by_centers`] counts as places a center may write: those of
/// each center in `allowlist` mode at `now_ms` (a `folder` or `user` mode
/// whose time ran out is `allowlist` again, with the rules it kept). A
/// rule counts where it covers an action of `caps` that writes at a path
/// the call names (`fs.write`, or an action of any effect with a path
/// argument marked `write`) and runs with the owner's rights: a program's, and a
/// config capability's with `account = "owner"`, in every such pairing;
/// the node's own `fs` only where the center's writes run as the owner
/// (`as_owner`: `--as-owner` on the installed node, every pairing on a
/// node run by hand). What runs as `nerve-run` is held by that account's
/// own access. It counts its pattern up to the folder before its first
/// wildcard (`~/` is `home`), or `/` for a rule with no pattern, which
/// covers every path. Folder mode writes only in its `w` folders, and a
/// center in `user` mode has the owner's rights already.
pub fn written_by_rules(
    cfg: &NodeConfig,
    caps: &[Capability],
    home: &std::path::Path,
    now_ms: u64,
    as_owner: impl Fn(&nerve_policy::CenterPolicy) -> bool,
) -> Vec<std::path::PathBuf> {
    use nerve_proto::descriptor::Effect;
    use nerve_proto::schema::{PathMark, path_args};
    // Whether an action of `cap` (`action`, or any) writes at a path with
    // the owner's rights, for a center whose own writes run as the owner
    // where `fs_as_owner`.
    let writes = |cap: &str, action: Option<&str>, fs_as_owner: bool| {
        caps.iter()
            .filter(|c| c.id == cap)
            .flat_map(|c| c.actions.iter().map(move |(n, a)| (c, n, a)))
            .filter(|(_, n, _)| action.is_none_or(|x| x == n.as_str()))
            .any(|(c, n, a)| {
                let owners = match c.provider.as_str() {
                    "node" => fs_as_owner,
                    PROVIDER => find(cfg, cap, n).is_some_and(|d| d.account == RunsAs::Owner),
                    // A program runs with the owner's rights.
                    _ => true,
                };
                // What an action does at a path is its mark, whatever the
                // effect its author named: an `execute` action may write
                // where an argument marked `write` says.
                owners
                    && ((cap == "fs" && a.effect == Effect::Write)
                        || path_args(&a.params)
                            .iter()
                            .any(|(_, m)| *m == PathMark::Write))
            })
    };
    let home = home.display().to_string();
    let mut places = Vec::new();
    for e in cfg
        .centers
        .iter()
        .filter(|e| e.policy.mode_at(now_ms) == nerve_policy::Mode::Allowlist)
    {
        let fs_as_owner = as_owner(&e.policy);
        for rule in &e.policy.allow {
            let (scope, pattern) = match rule.split_once(':') {
                Some((s, p)) => (s, Some(p)),
                None => (rule.as_str(), None),
            };
            let (cap, action) = match scope.split_once('.') {
                Some((c, a)) => (c, Some(a)),
                None => (scope, None),
            };
            if !writes(cap, action, fs_as_owner) {
                continue;
            }
            let Some(p) = pattern else {
                places.push("/".into());
                continue;
            };
            let p = match p.strip_prefix('~') {
                Some(r) if r.is_empty() || r.starts_with('/') => format!("{home}{r}"),
                _ => p.to_string(),
            };
            // A wildcard, or a character a glob escapes, may stand for
            // anything after the folder it lies in.
            let fixed = match p.find(['*', '?', '[', '{', '\\']) {
                Some(i) => &p[..p[..i].rfind('/').map_or(0, |s| s + 1)],
                None => &p,
            };
            places.push(if fixed.starts_with('/') {
                fixed.into()
            } else {
                "/".into()
            });
        }
    }
    places
}

/// Whether `effect` senses or acts on the world, which only the owner turns
/// on for a center.
pub fn senses(effect: nerve_proto::descriptor::Effect) -> bool {
    use nerve_proto::descriptor::Effect;
    matches!(effect, Effect::Sense | Effect::Actuate)
}

/// Where an action of `after` has come to sense or actuate (new, or one
/// that did neither in `before`), switches it off for every center whose
/// earlier switch (`cap set` of its capability, or of the action while it
/// only read) or allow rule would let that center use it at once: such a
/// switch was set for what it did then, perhaps by the center itself, and
/// only the owner turns on what senses or actuates. A center cannot take
/// that `off` away. Returns those centers, each with the action. Whoever
/// changes the config's capabilities does it: `cap add` and `cap edit`, and
/// the node as it takes a file the owner wrote (`config accept`).
pub fn hold_new(before: &NodeConfig, after: &mut NodeConfig) -> Vec<(String, String)> {
    use nerve_policy::config::CapSetting;
    let came: Vec<ConfigCapability> = after
        .capabilities
        .iter()
        .filter(|c| senses(c.effect))
        .filter(|c| {
            !before
                .capabilities
                .iter()
                .any(|b| b.name == c.name && senses(b.effect))
        })
        .cloned()
        .collect();
    let mut held = Vec::new();
    for c in came {
        let (cap, action) = c.split();
        for e in &mut after.centers {
            // An `on` for this very action that the change itself brings is
            // the owner's: a center may set none for an action not offered.
            let on = |p: &nerve_policy::CenterPolicy| p.caps.get(&c.name) == Some(&CapSetting::On);
            if on(&e.policy) && before.center(&e.name).is_none_or(|b| !on(&b.policy)) {
                continue;
            }
            let p = &mut e.policy;
            let covered = match p.cap_setting(cap, Some(action)) {
                Some(CapSetting::Off | CapSetting::Hidden) => false,
                Some(CapSetting::On) => true,
                None => nerve_policy::rules::offers(&p.allow, cap, action),
            };
            if covered {
                p.caps.insert(c.name.clone(), CapSetting::Off);
                held.push((e.name.clone(), c.name.clone()));
            }
        }
    }
    held
}

/// The config's entry for `cap.action`.
pub fn find<'a>(cfg: &'a NodeConfig, cap: &str, action: &str) -> Option<&'a ConfigCapability> {
    cfg.capabilities.iter().find(|c| c.split() == (cap, action))
}

/// Whether the config declares a capability `cap` (any action, any
/// platform): no program may add one of that name.
pub fn names(cfg: &NodeConfig, cap: &str) -> bool {
    cfg.capabilities.iter().any(|c| c.split().0 == cap)
}

/// What a call of `decl` returns, from its command's result
/// (crate::exec::run): what it printed, as text or as JSON that fits the
/// result schema. A command that did not end with exit code 0, or was killed
/// for its memory limit (whatever its first process's exit), is an error
/// whose message gives its exit code (or signal, or the reason), with what
/// it printed to stderr in its data.
pub fn result(decl: &ConfigCapability, run: &Value) -> Result<Value, RpcError> {
    let stdout = run["stdout"].as_str().unwrap_or_default();
    let stderr = run["stderr"].as_str().unwrap_or_default();
    // Only stdout's own cut counts: stderr past the cap leaves it whole.
    let cut = run["stdout_truncated"] == true;
    let code = run["exit_code"].as_i64();
    if code != Some(0) || run["killed"].is_string() {
        let how = match (code, run["signal"].as_str(), run["reason"].as_str()) {
            (_, _, Some(reason)) => reason.to_string(),
            (Some(c), _, _) => format!("exit code {c}"),
            (None, Some(s), _) => format!("signal {s}"),
            (None, None, _) => "no exit code".into(),
        };
        let shown = match stderr.char_indices().nth(STDERR_MAX) {
            Some((end, _)) => format!("{}…", &stderr[..end]),
            None => stderr.to_string(),
        };
        // What it printed is the command's, not the node's words: it goes
        // in `data.stderr`, which the center hands on as content from this
        // machine (docs/dev/spec/protocol.md §6), never in the message.
        let text = format!("{} failed: {how}", decl.name);
        let e = RpcError::new(ErrorCode::Other("io".into()), text)
            .with("exit_code", run["exit_code"].clone());
        return Err(if shown.trim().is_empty() {
            e
        } else {
            e.with("stderr", Value::String(shown))
        });
    }
    match &decl.result {
        Output::Text if cut => Ok(Value::String(format!(
            "{stdout}\n[the output was longer and is cut here]"
        ))),
        Output::Text => Ok(Value::String(stdout.to_string())),
        Output::Json(_) if cut => Err(RpcError::new(
            ErrorCode::TooLarge,
            format!(
                "{} printed more than the node's limits.output_cap_bytes, so its JSON is cut",
                decl.name
            ),
        )),
        Output::Json(schema) => {
            let v: Value = serde_json::from_str(stdout).map_err(|e| {
                RpcError::new(
                    ErrorCode::Other("io".into()),
                    format!("{} printed no JSON: {e}", decl.name),
                )
            })?;
            nerve_proto::schema::validate(schema, &v).map_err(|e| {
                // A field the output names may be anything whoever wrote
                // that data chose; only the schema's own names, and an
                // array's index (`[2]`, which leaves `2]`), are the node's
                // words.
                let index = |n: &str| {
                    n.strip_suffix(']')
                        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                };
                let named = e
                    .field
                    .split(['.', '['])
                    .filter(|n| !n.is_empty() && !index(n))
                    .all(|n| schema_names(schema).contains(n));
                let why = if named {
                    e.to_string()
                } else {
                    format!("a field the schema does not name: expected {}", e.expected)
                };
                RpcError::new(
                    ErrorCode::Other("io".into()),
                    format!(
                        "{} printed JSON its result schema does not take: {why}",
                        decl.name
                    ),
                )
            })?;
            Ok(v)
        }
    }
}

/// Every property name `schema` declares, at any depth.
fn schema_names(schema: &Value) -> std::collections::BTreeSet<&str> {
    let mut names = std::collections::BTreeSet::new();
    let mut todo = vec![schema];
    while let Some(s) = todo.pop() {
        match s {
            Value::Object(m) => {
                if let Some(p) = m.get("properties").and_then(Value::as_object) {
                    names.extend(p.keys().map(String::as_str));
                }
                todo.extend(m.values());
            }
            Value::Array(a) => todo.extend(a),
            _ => {}
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_proto::descriptor::Effect;

    fn cfg(entries: &str) -> NodeConfig {
        NodeConfig::parse(entries).unwrap()
    }

    const TWO: &str = r#"
[[capability]]
name = "sensors.read"
effect = "sense"
command = ["sensors", "-j"]
result = '{"type": "object"}'

[[capability]]
name = "sensors.list"
effect = "read"
summary = "The sensors."
command = ["sensors", "-l"]
account = "owner"

[[capability]]
name = "win.only"
effect = "read"
command = ["whoami"]
platform = "windows"
account = "owner"

[[capability]]
name = "lin.only"
effect = "read"
command = ["id"]
platform = "linux"
account = "owner"
"#;

    fn ids(caps: &[Capability]) -> Vec<String> {
        caps.iter()
            .flat_map(|c| c.actions.keys().map(move |a| format!("{}.{a}", c.id)))
            .collect()
    }

    #[test]
    fn what_is_offered_follows_the_platform_and_the_account() {
        let c = cfg(TWO);
        assert_eq!(
            ids(&offered_on(&c, "linux", true)),
            ["lin.only", "sensors.list", "sensors.read"]
        );
        // By hand only those that run as the owner.
        assert_eq!(
            ids(&offered_on(&c, "linux", false)),
            ["lin.only", "sensors.list"]
        );
        // Windows reads them and offers none yet.
        assert!(offered_on(&c, "windows", true).is_empty());
        let caps = offered_on(&c, "linux", true);
        let sensors = caps.iter().find(|c| c.id == "sensors").unwrap();
        assert_eq!(sensors.provider, PROVIDER);
        assert_eq!(sensors.actions["read"].effect, Effect::Sense);
        assert_eq!(sensors.actions["read"].result, json!({"type": "object"}));
        assert_eq!(sensors.actions["list"].result, json!({"type": "string"}));
        assert_eq!(sensors.actions["list"].summary, "The sensors.");
        // The center tells the agent that one that runs as nerve-run is
        // held like fs, and one that runs as the owner like a program.
        assert!(sensors.actions["read"].as_account);
        assert!(!sensors.actions["list"].as_account);
        // Only for a pairing whose commands run as nerve-run.
        let mut kept = caps.clone();
        as_account_for(&mut kept, true);
        assert_eq!(kept, caps);
        let mut owners = caps.clone();
        as_account_for(&mut owners, false);
        assert!(
            owners
                .iter()
                .flat_map(|c| c.actions.values())
                .all(|a| !a.as_account)
        );
        assert_eq!(
            sensors.actions["list"].params,
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        );
        assert!(names(&c, "win") && names(&c, "sensors") && !names(&c, "lamp"));
        // Declared: also what this node leaves out.
        assert_eq!(
            ids(&declared(&c)),
            ["lin.only", "sensors.list", "sensors.read", "win.only"]
        );
        assert_eq!(find(&c, "sensors", "list").unwrap().name, "sensors.list");
        assert!(find(&c, "sensors", "other").is_none());
    }

    /// A command of `nerve-run` gets the pairing's folders where its
    /// commands run as that account, and only the account's own where they
    /// run as the owner: Landlock's rules are made of them.
    #[test]
    fn landlock_holds_a_nerve_run_command_to_the_right_folders() {
        use nerve_policy::config::{Access, Folder};
        use std::path::Path;
        let proj = Folder {
            path: "/srv/proj".into(),
            access: Access::parse("rw").unwrap(),
        };
        let home = Path::new("/var/lib/nerve-run");
        let mut folders = vec![proj.clone()];
        folders.extend(crate::account::built_in(home));
        let policy = nerve_policy::CenterPolicy {
            mode: nerve_policy::Mode::Folder,
            folders: folders.clone(),
            ..Default::default()
        };
        assert_eq!(confined(&policy, true, Some(home)).folders, folders);
        let own = confined(&policy, false, Some(home));
        assert_eq!(own.folders, crate::account::built_in(home));
        assert!(confined(&policy, false, None).folders.is_empty());
    }

    /// An owner's command whose program, script or other fixed path lies
    /// where a center may write is refused, also through `PATH` or a link,
    /// named from where it starts or as an option's value, and so is one that
    /// starts there; one that names only places outside, or takes its path
    /// from the call, is not.
    #[cfg(unix)]
    #[test]
    fn an_owners_command_may_not_name_what_a_center_writes() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, bin, other) = (root.join("work"), root.join("work/bin"), root.join("other"));
        for f in [&bin, &other] {
            std::fs::create_dir_all(f).unwrap();
        }
        std::fs::write(work.join("deploy.sh"), "true\n").unwrap();
        std::fs::write(bin.join("tool-b5"), "true\n").unwrap();
        std::fs::write(other.join("safe.sh"), "true\n").unwrap();
        std::os::unix::fs::symlink(work.join("deploy.sh"), other.join("link.sh")).unwrap();
        std::os::unix::fs::symlink(&work, other.join("into")).unwrap();
        std::os::unix::fs::symlink(work.join("proj"), other.join("gone")).unwrap();
        // A file of the program's name that may not be run is passed over,
        // as execvp does.
        std::fs::write(other.join("tool-b5"), "true\n").unwrap();
        let mode = |f: &std::path::Path, m: u32| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(m)).unwrap();
        };
        mode(&bin.join("tool-b5"), 0o755);
        mode(&other.join("tool-b5"), 0o644);
        let path = std::env::join_paths([&other, &bin]).unwrap();
        let decl = |command: &[&str]| ConfigCapability {
            name: "proj.deploy".into(),
            summary: String::new(),
            effect: nerve_proto::descriptor::Effect::Execute,
            command: command.iter().map(|s| s.to_string()).collect(),
            params: Value::Null,
            result: Output::Text,
            timeout_secs: None,
            account: RunsAs::Owner,
            platform: Default::default(),
        };
        let w = std::slice::from_ref(&work);
        let s = |p: &std::path::Path| p.display().to_string();
        for bad in [
            vec!["sh".to_string(), s(&work.join("deploy.sh"))],
            vec![s(&work.join("deploy.sh"))],
            vec!["make".into(), "-C".into(), s(&work)],
            vec!["tool-b5".into()],
            vec!["sh".into(), s(&other.join("link.sh"))],
            // Not there yet: a center may put it there.
            vec!["sh".into(), s(&work.join("later.sh"))],
            // From where it starts (`root`), and as an option's value.
            vec!["make".into(), "-C".into(), "work".into()],
            vec!["sh".into(), "work/deploy.sh".into()],
            vec!["sh".into(), "work/later.sh".into()],
            vec![
                "cargo".into(),
                "test".into(),
                format!("--manifest-path={}", s(&work.join("Cargo.toml"))),
            ],
            vec!["make".into(), "--directory=work".into()],
            // A short option's value glued on, and a variable's value.
            vec!["make".into(), "-Cwork".into(), "test".into()],
            vec!["make".into(), "-fwork/Makefile".into()],
            vec![
                "perl".into(),
                format!("-I{}", s(&work.join("lib"))),
                "/usr/bin/x".into(),
            ],
            vec!["tar".into(), format!("-xf{}", s(&work.join("a.tar")))],
            vec!["env".into(), "PYTHONPATH=work".into(), "python3".into()],
            // Not there yet, through a link that leads into such a folder.
            vec!["sh".into(), s(&other.join("into/later.sh"))],
            // A link whose target a center took away leads there still.
            vec!["make".into(), "-C".into(), s(&other.join("gone"))],
            vec![
                "make".into(),
                "-C".into(),
                "other/gone".into(),
                "test".into(),
            ],
            vec!["sh".into(), s(&other.join("gone/run.sh"))],
            // A list of paths, a URL and an `@file` name each place.
            vec![
                "env".into(),
                format!("PYTHONPATH={}:{}", s(&other), s(&work.join("lib"))),
                "python3".into(),
            ],
            vec![
                "java".into(),
                "-cp".into(),
                format!("{}:{}", s(&other.join("a.jar")), s(&work.join("plugins/*"))),
                "Main".into(),
            ],
            vec![
                "pip".into(),
                "install".into(),
                format!("file://{}", s(&work.join("pkg"))),
            ],
            vec!["java".into(), format!("@{}", s(&work.join("jvm.args")))],
            vec!["java".into(), "@work/jvm.args".into()],
        ] {
            let c = decl(&bad.iter().map(String::as_str).collect::<Vec<_>>());
            let why = written_by_centers(&c, w, None, Some(&path), &root);
            assert!(
                why.as_ref()
                    .is_some_and(|y| y.contains("where a center may write")),
                "{bad:?}: {why:?}"
            );
        }
        for good in [
            vec!["sh".to_string(), s(&other.join("safe.sh"))],
            vec!["id".into()],
            vec!["cat".into(), "--".into(), "{path}".into()],
            vec!["make".into(), "-C".into(), "other".into(), "test".into()],
            vec!["sh".into(), "--file=other/safe.sh".into()],
            vec!["make".into(), "-Cother".into(), "VAR=other".into()],
            vec!["sh".into(), s(&other.join("later.sh"))],
            vec![
                "env".into(),
                format!("PYTHONPATH={}:{}", s(&other), s(&other.join("lib"))),
                "python3".into(),
            ],
            vec!["curl".into(), "https://example.org/a:b".into()],
        ] {
            let c = decl(&good.iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(
                written_by_centers(&c, w, None, Some(&path), &root),
                None,
                "{good:?}"
            );
        }
        // One that starts where a center writes: `make`, `python3 -m` and
        // the like read their code from there.
        let why = written_by_centers(&decl(&["id"]), w, None, Some(&path), &work);
        assert!(
            why.as_ref().is_some_and(|y| y.contains("starts in")),
            "{why:?}"
        );
        // The file run is the one found in PATH.
        assert_eq!(
            program_file("tool-b5", Some(&path)),
            Some(bin.join("tool-b5"))
        );
        assert_eq!(program_file("/bin/sh", None), Some("/bin/sh".into()));
        assert_eq!(program_file("no-such-b5", Some(&path)), None);
    }

    /// What `nerve-run` owns or may change counts as a place a center may
    /// write, also once no folder gives it `w`: the file, a folder above it,
    /// as written or where a link leads. A device such as `/dev/null` does
    /// not, nor does anything on a node without that account.
    #[cfg(unix)]
    #[test]
    fn what_nerve_run_owns_or_may_change_counts_where_a_center_writes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::{Path, PathBuf};
        // Beside the test's own binary, whose folders no other account may
        // change (unlike a temporary folder in `/tmp` or `/var/tmp`).
        let exe = std::env::current_exe().unwrap();
        let d = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let mode = |f: &Path, m: u32| {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(m)).unwrap();
        };
        let shared = root.join("shared");
        std::fs::create_dir(&shared).unwrap();
        for (f, m) in [
            (root.join("safe.sh"), 0o644),
            (root.join("open.sh"), 0o646),
            (shared.join("x.sh"), 0o644),
            (root.join("mine.sh"), 0o444),
        ] {
            std::fs::write(&f, "true\n").unwrap();
            mode(&f, m);
        }
        mode(&shared, 0o757);
        mode(&root, 0o755);
        std::os::unix::fs::symlink(&shared, root.join("via")).unwrap();
        let account = |uid: u32| crate::service::Account {
            name: crate::account::RUN_USER.into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/var/lib/nerve-run".into(),
            groups: vec![uid],
        };
        // An account no file here belongs to.
        let run = account(4_242_424);
        let decl = |command: &[&str]| ConfigCapability {
            name: "proj.deploy".into(),
            summary: String::new(),
            effect: Effect::Execute,
            command: command.iter().map(|s| s.to_string()).collect(),
            params: Value::Null,
            result: Output::Text,
            timeout_secs: None,
            account: RunsAs::Owner,
            platform: Default::default(),
        };
        let judged = |command: &[&str], run: Option<&crate::service::Account>| {
            written_by_centers(&decl(command), &[], run, None, &root)
        };
        let s = |p: PathBuf| p.display().to_string();
        let good = s(root.join("safe.sh"));
        if judged(&["/bin/sh", &good], Some(&run)).is_some() {
            eprintln!(
                "skipped: a folder above {} is open to every account",
                root.display()
            );
            return;
        }
        assert_eq!(
            judged(&["/bin/sh", "-c", "true", "/dev/null"], Some(&run)),
            None
        );
        for bad in [
            s(root.join("open.sh")),
            s(shared.join("x.sh")),
            // Not there yet, in a folder it may add to.
            s(shared.join("later.sh")),
            // Through a link into that folder.
            s(root.join("via/x.sh")),
        ] {
            let why = judged(&["/bin/sh", &bad], Some(&run));
            assert!(
                why.as_ref()
                    .is_some_and(|y| y.contains("nerve-run's or nerve-run may change it")),
                "{bad}: {why:?}"
            );
            // A node without nerve-run has nothing of that account.
            assert_eq!(judged(&["/bin/sh", &bad], None), None, "{bad}");
        }
        // A file of its own, even one it has no write bit on: it may give
        // itself one.
        let mine = root.join("mine.sh");
        let me = account(mine.metadata().unwrap().uid());
        assert!(run_writes(&mine, &me));
        assert!(!run_writes(&mine, &run));
        assert!(!run_writes(Path::new("/dev/null"), &run));
    }

    /// What an allow rule lets a center write with the owner's rights
    /// counts as a place a center may write: up to the folder before the
    /// first wildcard, or everywhere for a rule with no pattern. Only a rule
    /// of an action that writes at a path counts, only in allowlist mode
    /// (also one a `--for` limit fell back to), and only where that write
    /// runs as the owner: a program's and an owner capability's in every
    /// pairing, `fs` where the center's writes run as the owner.
    #[test]
    fn an_allow_rule_that_writes_as_the_owner_counts() {
        let c = cfg(r#"
[[center]]
name = "lab"
center_id = "c1"
url = "https://lab.example"
pin = "sha256:00"
node_id = "n1"
[center.policy]
mode = "allowlist"
allow = ["fs.read:~/docs/**", "fs.write:~/site/**", "fs.write:~/one.txt", "fs:/srv/a*/x", "notes.save:~/notes/*.md", "notes.list:~/list/**", "exec.run:make *", "site.deploy", "site.fetch:/srv/site/**", "prog.edit:/srv/prog/**", "prog.look:/srv/look/**", "prog.build:/srv/build/**", "site.render:/srv/render/**", "notes.build:/srv/nbuild/**"]

[[center]]
name = "ops"
center_id = "c2"
url = "https://ops.example"
pin = "sha256:00"
node_id = "n1"
[center.policy]
mode = "folder"
allow = ["fs.write", "prog.edit"]

[[capability]]
name = "notes.save"
effect = "write"
command = ["save", "--", "{path}"]
params = '{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "write"}}, "required": ["path"]}'

[[capability]]
name = "notes.list"
effect = "read"
command = ["list", "--", "{path}"]
params = '{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "read"}}, "required": ["path"]}'

[[capability]]
name = "site.fetch"
effect = "write"
command = ["curl", "-o", "{out}", "--", "{url}"]
params = '{"type": "object", "properties": {"out": {"type": "string", "x-nerve-path": "write"}, "url": {"type": "string"}}, "required": ["out", "url"]}'
account = "owner"

[[capability]]
name = "site.render"
effect = "execute"
command = ["render", "--", "{tpl}", "{out}"]
params = '{"type": "object", "properties": {"tpl": {"type": "string"}, "out": {"type": "string", "x-nerve-path": "write"}}, "required": ["tpl", "out"]}'
account = "owner"

[[capability]]
name = "notes.build"
effect = "execute"
command = ["build", "--", "{out}"]
params = '{"type": "object", "properties": {"out": {"type": "string", "x-nerve-path": "write"}}, "required": ["out"]}'
"#);
        let mut caps = crate::descriptor::built_in(&c);
        caps.extend(declared(&c));
        // A program's actions: one that writes at a path, one that reads,
        // and one that runs something and writes where its mark says.
        use nerve_proto::descriptor::Effect;
        let marked = |effect: Effect, mark: &str| Action {
            effect,
            summary: String::new(),
            params: json!({"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": mark}}}),
            result: Value::Null,
            exposure: None,
            as_account: false,
        };
        caps.push(Capability {
            id: "prog".into(),
            profile: String::new(),
            provider: "prog".into(),
            exposure: Exposure::On,
            summary: String::new(),
            actions: [
                ("edit".into(), marked(Effect::Write, "write")),
                ("look".into(), marked(Effect::Read, "read")),
                ("build".into(), marked(Effect::Execute, "write")),
            ]
            .into(),
            events: BTreeMap::new(),
            state: Value::Null,
            streams: BTreeMap::new(),
        });
        let home = std::path::Path::new("/home/alice");
        let now = 1_000_000;
        let places =
            |c: &NodeConfig, as_owner: bool| written_by_rules(c, &caps, home, now, |_| as_owner);
        let paths = |p: &[&str]| -> Vec<std::path::PathBuf> { p.iter().map(Into::into).collect() };
        assert_eq!(
            places(&c, true),
            paths(&[
                "/home/alice/site/",
                "/home/alice/one.txt",
                "/srv/",
                "/srv/site/",
                "/srv/prog/",
                "/srv/build/",
                "/srv/render/",
            ])
        );
        // The node's `fs` writes as nerve-run there, held by that account's
        // own access, and so does a capability that runs as nerve-run; a
        // program and an owner capability write as the owner all the same,
        // whatever effect their action names.
        assert_eq!(
            places(&c, false),
            paths(&["/srv/site/", "/srv/prog/", "/srv/build/", "/srv/render/"])
        );
        // A mode set for a time that ran out is allowlist again; one whose
        // time runs on is not.
        let mut timed = c.clone();
        timed.centers[0].policy.mode = nerve_policy::Mode::User;
        timed.centers[0].policy.until = Some(now - 1);
        assert_eq!(places(&timed, true), places(&c, true));
        timed.centers[0].policy.mode = nerve_policy::Mode::Folder;
        assert_eq!(places(&timed, false), places(&c, false));
        timed.centers[0].policy.until = Some(now + 1);
        assert!(places(&timed, true).is_empty());
        // A write rule with no pattern covers every path.
        let mut any = c.clone();
        any.centers[0].policy.allow = vec!["fs".into()];
        assert_eq!(places(&any, true), [std::path::PathBuf::from("/")]);
        any.centers[0].policy.allow = vec!["fs.write:*.txt".into()];
        assert_eq!(places(&any, true), [std::path::PathBuf::from("/")]);
        any.centers[0].policy.allow = vec!["prog".into()];
        assert_eq!(places(&any, false), [std::path::PathBuf::from("/")]);
        any.centers[0].policy.allow = vec!["prog.build".into()];
        assert_eq!(places(&any, false), [std::path::PathBuf::from("/")]);
        any.centers[0].policy.allow = vec!["notes.build".into()];
        assert!(places(&any, false).is_empty());
    }

    /// Whoever brings an action that senses, an earlier switch or rule
    /// that covers it is switched off for it; one that sensed before, or an
    /// `on` for that very action the change brings itself, stays.
    #[test]
    fn an_action_that_comes_to_sense_is_held_whoever_brings_it() {
        use nerve_policy::config::CapSetting;
        let before = cfg(r#"
[[center]]
name = "lab"
center_id = "c1"
url = "https://lab.example"
pin = "sha256:00"
node_id = "n1"
[center.policy]
mode = "folder"
caps = { probe = "on" }

[[center]]
name = "ops"
center_id = "c2"
url = "https://ops.example"
pin = "sha256:00"
node_id = "n1"
[center.policy]
mode = "folder"

[[capability]]
name = "probe.list"
effect = "read"
command = ["sensors", "-l"]
"#);
        let with = |toml: &str| {
            let mut c = before.clone();
            c.capabilities
                .extend(cfg(&format!("[[capability]]\n{toml}")).capabilities);
            c
        };
        let cam = "name = \"probe.cam\"\neffect = \"sense\"\ncommand = [\"cam\"]";
        let mut after = with(cam);
        assert_eq!(
            hold_new(&before, &mut after),
            [("lab".to_string(), "probe.cam".to_string())]
        );
        assert_eq!(
            after.center("lab").unwrap().policy.caps.get("probe.cam"),
            Some(&CapSetting::Off)
        );
        assert!(after.center("ops").unwrap().policy.caps.is_empty());
        // Sensing before already: it was held when it came to.
        let mut again = after.clone();
        again.centers[0]
            .policy
            .caps
            .insert("probe.cam".into(), CapSetting::On);
        let kept = again.clone();
        assert!(hold_new(&kept, &mut again).is_empty());
        // A read that comes to sense, also where the center turned that
        // very action on while it read.
        let read = with("name = \"probe.cam\"\neffect = \"read\"\ncommand = [\"cam\"]");
        let mut sensing = with(cam);
        assert_eq!(hold_new(&read, &mut sensing).len(), 1);
        let (mut read_on, mut sensing_on) = (read.clone(), with(cam));
        for c in [&mut read_on, &mut sensing_on] {
            c.centers[1]
                .policy
                .caps
                .insert("probe.cam".into(), CapSetting::On);
        }
        assert_eq!(
            hold_new(&read_on, &mut sensing_on),
            [
                ("lab".to_string(), "probe.cam".to_string()),
                ("ops".to_string(), "probe.cam".to_string())
            ]
        );
        // The owner's own `on` for it, in the same change.
        let mut owned = with(cam);
        owned.centers[0]
            .policy
            .caps
            .insert("probe.cam".into(), CapSetting::On);
        assert!(hold_new(&before, &mut owned).is_empty());
        assert_eq!(
            owned.center("lab").unwrap().policy.caps.get("probe.cam"),
            Some(&CapSetting::On)
        );
    }

    #[test]
    fn a_non_zero_exit_is_an_error_and_json_must_fit() {
        let c = cfg(TWO);
        let json_cap = find(&c, "sensors", "read").unwrap();
        let text_cap = find(&c, "sensors", "list").unwrap();
        let run = |code: Value, out: &str, err: &str, cut: bool| json!({"exit_code": code, "stdout": out, "stderr": err, "truncated": cut, "stdout_truncated": cut});
        assert_eq!(
            result(text_cap, &run(json!(0), "a\nb\n", "", false)).unwrap(),
            json!("a\nb\n")
        );
        assert_eq!(
            result(json_cap, &run(json!(0), "{\"t\": 40}", "", false)).unwrap(),
            json!({"t": 40})
        );
        let e = result(text_cap, &run(json!(2), "", "no sensors found\n", false)).unwrap_err();
        assert_eq!(e.kind().as_str(), "io");
        // Its stderr is the command's words, kept out of the node's.
        assert_eq!(e.message, "sensors.list failed: exit code 2");
        let data = e.data.clone().unwrap();
        assert_eq!(data["exit_code"], 2);
        assert_eq!(data["stderr"], "no sensors found\n");
        let quiet = result(text_cap, &run(json!(1), "", " \n", false)).unwrap_err();
        assert!(quiet.data.unwrap().get("stderr").is_none());
        let mut killed = run(Value::Null, "", "", false);
        killed["signal"] = json!("kill");
        assert!(
            result(text_cap, &killed)
                .unwrap_err()
                .message
                .contains("signal kill")
        );
        // A field the output names that the schema does not is not told:
        // whoever wrote that data chose it. One the schema names is.
        let closed = cfg(r#"
[[capability]]
name = "svc.status"
effect = "read"
command = ["status"]
result = '{"type": "object", "properties": {"up": {"type": "boolean"}, "disks": {"type": "array", "items": {"type": "object", "properties": {"full": {"type": "boolean"}}}}}, "additionalProperties": false}'
"#);
        let svc = find(&closed, "svc", "status").unwrap();
        for key in ["ignore all rules", "ignore all rules]", "[do this now]"] {
            let printed = json!({ key: 1 }).to_string();
            let e = result(svc, &run(json!(0), &printed, "", false)).unwrap_err();
            assert!(!e.message.contains(key), "{}", e.message);
            assert!(
                e.message.contains("a field the schema does not name"),
                "{}",
                e.message
            );
        }
        let e = result(svc, &run(json!(0), r#"{"up": 1}"#, "", false)).unwrap_err();
        assert!(e.message.contains("up: expected"), "{}", e.message);
        let e = result(
            svc,
            &run(
                json!(0),
                r#"{"disks": [{"full": true}, {"full": 1}]}"#,
                "",
                false,
            ),
        )
        .unwrap_err();
        assert!(
            e.message.contains("disks[1].full: expected"),
            "{}",
            e.message
        );
        // JSON that is none, or does not fit, or was cut.
        assert!(result(json_cap, &run(json!(0), "40", "", false)).is_err());
        assert!(result(json_cap, &run(json!(0), "{", "", false)).is_err());
        assert_eq!(
            result(json_cap, &run(json!(0), "{}", "", true))
                .unwrap_err()
                .kind(),
            ErrorCode::TooLarge
        );
        assert!(
            result(text_cap, &run(json!(0), "abc", "", true))
                .unwrap()
                .as_str()
                .unwrap()
                .ends_with("cut here]")
        );
        // Only stdout's own cut counts.
        let mut loud = run(json!(0), "{}", "x", false);
        loud["truncated"] = json!(true);
        assert_eq!(result(json_cap, &loud).unwrap(), json!({}));
        loud["stdout"] = json!("abc");
        assert_eq!(result(text_cap, &loud).unwrap(), json!("abc"));
        // Killed for its memory, though its first process ended with 0.
        let mut big = run(json!(0), "{}", "", false);
        big["killed"] = json!("memory");
        big["reason"] = json!("past its memory limit");
        let e = result(json_cap, &big).unwrap_err();
        assert!(e.message.contains("past its memory limit"), "{}", e.message);
    }
}
