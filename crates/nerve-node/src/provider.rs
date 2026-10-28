//! Capability providers (docs/dev/spec/node-local.md §7): local programs
//! the owner allowed in `providers.allowed` that add capabilities to the
//! node: over the provider socket of the installed node ([`serve`]), which
//! the owner's programs and root's reach, or over the control socket of a
//! node run by hand.
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

use crate::daemon::Shared;
use crate::daemon::lock;

/// The capabilities and profiles that are the node's own, and the ones the
/// center serves itself on every node: a provider may not take their names
/// (nor a capability of the config).
pub use nerve_policy::config::BUILT_IN;

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
    /// The account its program runs as, as the kernel named it.
    uid: u32,
    /// Tells this attachment from a later one of the same name.
    serial: u64,
    caps: Vec<Capability>,
    /// The actions of its fragment that were left out.
    broken: Vec<Broken>,
    tx: mpsc::Sender<Value>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, RpcError>>>>,
    next: AtomicU64,
}

/// Why a provider is refused while the node stops (for an owner's restore,
/// too): it connects again to the node that runs next.
const STOPPING: &str = "refused: the node stops; connect again once it runs";

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

    /// The account the program of the provider `name` runs as, and which
    /// attachment of that name it is, while it is attached.
    pub fn held(&self, name: &str) -> Option<(u32, u64)> {
        lock(&self.attached).get(name).map(|a| (a.uid, a.serial))
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
    /// another program than the one each was checked against, and those
    /// that offer a capability the config now declares itself
    /// (`[[capability]]`), whose calls would no longer reach them. Whether
    /// any went.
    pub fn follow_config(&self, cfg: &NodeConfig) -> bool {
        let mut attached = lock(&self.attached);
        let before = attached.len();
        attached.retain(|name, a| {
            let kept = cfg.providers.get(name).is_some_and(|p| p.exe == a.exe);
            if !kept {
                tracing::info!(
                    "provider {name} detached: providers.allowed no longer names it with this program"
                );
                return false;
            }
            if let Some(c) = a
                .caps
                .iter()
                .find(|c| crate::config_cap::names(cfg, &c.id))
            {
                tracing::info!(
                    "provider {name} detached: its capability {} is declared in node.toml now",
                    c.id
                );
                return false;
            }
            true
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

    /// Holds the provider `name` as attached, for its program `exe` of the
    /// account `uid`, with the capabilities of `fragment`, unless one of
    /// that name is attached already, or the config `now` gives no longer
    /// names it with `exe`. The node looked at the program after it read
    /// the config, and the owner may have removed or changed the entry
    /// meanwhile: [`Providers::follow_config`] then found nothing to
    /// detach. `now` is read while the attachments are held, so a change
    /// after it finds this one. It gives none once the node stops: its
    /// stop detaches every provider once ([`Providers::detach_all`]), and
    /// one held after that would stay with the stopped node, never told.
    fn hold(
        &self,
        name: &str,
        exe: &str,
        uid: u32,
        fragment: Vec<Fragment>,
        tx: mpsc::Sender<Value>,
        now: impl FnOnce() -> Option<NodeConfig>,
    ) -> Result<Arc<Attached>, String> {
        let mut held = lock(&self.attached);
        let Some(now) = now() else {
            return Err(STOPPING.into());
        };
        if now.providers.get(name).is_none_or(|p| p.exe != exe) {
            return Err(format!(
                "refused: providers.allowed changed while the node looked at the provider {name}; try again"
            ));
        }
        if held.contains_key(name) {
            return Err(format!("a provider {name} is attached already"));
        }
        let taken = held
            .values()
            .flat_map(|a| a.caps.iter().map(|c| c.id.clone()))
            .collect();
        let (caps, broken) = capabilities(name, fragment, &taken, |id| {
            crate::config_cap::names(&now, id)
        })?;
        let a = Arc::new(Attached {
            name: name.to_string(),
            exe: exe.to_string(),
            uid,
            serial: self.serial.fetch_add(1, Ordering::Relaxed),
            caps,
            broken,
            tx,
            pending: Mutex::default(),
            next: AtomicU64::new(1),
        });
        held.insert(name.to_string(), a.clone());
        Ok(a)
    }

    /// Forwards a call the node allowed to the attachment `serial` of
    /// `provider` ([`Providers::held`]) and waits for its answer: the node
    /// decided the call for that program, so a later one of the same name
    /// never gets it. Dropping the future (a cancel, a deadline, the link's
    /// end) tells the provider to cancel it.
    pub async fn invoke(
        &self,
        provider: &str,
        serial: u64,
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
                .filter(|a| a.serial == serial)
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

/// What the node saw of the process that asks to attach, with the rights
/// of the account it looked as.
#[derive(Debug)]
pub(crate) struct Seen {
    /// The program it runs, as the kernel resolved it.
    pub running: PathBuf,
    /// Whether that is the program the owner allowed.
    pub same: bool,
    /// Whether it runs with `no_new_privs`, as every command of the node
    /// does (crate::owner::command_refusal).
    pub nnp: bool,
    /// Its pid, then its parent's and so on up, as far as could be read.
    pub chain: Vec<u32>,
}

/// What `pid` is ([`Seen`]), against the program `allowed` names, all as
/// this thread sees the files: a check of whether it comes from a command
/// that read less than the program's read would pass a command where
/// `/proc` hides other accounts' processes (`hidepid`), so it is read with
/// the same rights. A status that cannot be read refuses.
fn look(pid: u32, allowed: &Path) -> Result<Seen, String> {
    let running = program_of(pid)?;
    let same = same_program(&running, allowed)?;
    #[cfg(target_os = "linux")]
    let (nnp, chain) = (no_new_privs(pid)?, ancestry(pid));
    #[cfg(not(target_os = "linux"))]
    let (nnp, chain) = (false, vec![pid]);
    Ok(Seen {
        running,
        same,
        nnp,
        chain,
    })
}

/// Whether the process `pid` runs with `no_new_privs`, from its status. One
/// the node cannot read is refused rather than taken for one without.
#[cfg(target_os = "linux")]
fn no_new_privs(pid: u32) -> Result<bool, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| {
        format!("refused: the node cannot tell how the program that asks runs: {e}")
    })?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("NoNewPrivs:"))
        .map(|v| v.trim() == "1")
        .ok_or_else(|| "refused: the node cannot tell how the program that asks runs".into())
}

/// `pid` and its parents, up to the first one that cannot be read. One
/// that cannot be read, as the account that asks, belongs to another
/// account. A command that runs as the caller's account keeps
/// `no_new_privs`, so no process of it becomes another account's (a setuid
/// program cannot change it), and the caller is refused for that flag if
/// not for its chain. A command that runs as root (the sudo list, or root
/// as its account) sets no `no_new_privs`: a process it starts as the
/// caller's account through several of root's in between can lose the
/// command from its chain where `/proc` is mounted `hidepid`. The check is
/// a guard against mistakes, as the owner socket's is.
#[cfg(target_os = "linux")]
fn ancestry(pid: u32) -> Vec<u32> {
    let mut chain = vec![pid];
    let mut p = pid;
    while chain.len() < 256 {
        match nerve_transport::ctl::parent_of(p) {
            Some(pp) if pp != p && pp != 0 => {
                chain.push(pp);
                p = pp;
            }
            _ => break,
        }
    }
    chain
}

/// Who asks to attach: the account and the process the kernel names for
/// the caller, and that process's pidfd where the socket gave one.
#[cfg(unix)]
pub(crate) struct Caller {
    pub uid: u32,
    pub pid: Option<u32>,
    pub pidfd: Option<std::os::fd::OwnedFd>,
    /// Whether a process of a command the node runs, or one with
    /// `no_new_privs`, is refused from what the node saw of it
    /// (crate::owner::command_refusal): on the provider socket. The control
    /// socket, which takes a hello on a node run by hand only, checks its
    /// callers itself.
    pub refuse_commands: bool,
}

/// Why a program of root is refused where the node cannot tell which one
/// it is.
#[cfg(target_os = "linux")]
const ROOT_UNTOLD: &str = "refused: the node cannot tell which program of root asks";

/// What the process `pid` of the account `uid` is ([`Seen`]), looked at
/// with that account's rights: the kernel shows a process's program only to
/// its own account (or to a process that holds at least every right it
/// holds), where `/proc` is mounted `hidepid` its status and parents too,
/// and `allowed` may lie where only that account may look. The node's own processes and a node of root look
/// themselves. For another account the installed node takes its file ids
/// (crate::account::FsAs). For root it starts `exe` as root to look
/// ([`check_main`]), as it starts root's commands: the node itself holds
/// too few rights to see a process of root's. Blocks.
#[cfg(unix)]
fn identify(uid: u32, pid: u32, allowed: &Path, exe: Option<&Path>) -> Result<Seen, String> {
    let me = crate::account::own_uid();
    if me == 0 || uid == me {
        return look(pid, allowed);
    }
    #[cfg(target_os = "linux")]
    {
        if !crate::account::can_switch() {
            return Err(format!(
                "refused: the node may not look at the programs of another account (uid {uid})"
            ));
        }
        if uid == 0 {
            let exe = exe.ok_or(ROOT_UNTOLD)?;
            return as_root(exe, pid, allowed);
        }
        let account = crate::account::of_uid(uid)
            .and_then(|a| crate::account::lookup(&a.name).ok().flatten())
            .ok_or_else(|| format!("refused: the node cannot look up the account uid {uid}"))?;
        let _as = crate::account::FsAs::new(&account)
            .map_err(|e| format!("refused: the node cannot look as {}: {e}", account.name))?;
        look(pid, allowed)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (exe, allowed);
        Err("refused: providers attach on Linux only for now".into())
    }
}

/// [`identify`] for `caller`, which must name its process. A process that
/// ended while the node looked may have left its pid to another, so where
/// the socket gave its pidfd, an ended one refuses whatever was read: also
/// a failed read, since a pid that is gone is no answer either. Blocks.
#[cfg(unix)]
fn read_caller(caller: &Caller, allowed: &Path, exe: Option<&Path>) -> Result<Seen, String> {
    let pid = caller
        .pid
        .ok_or("refused: the node cannot tell which process asks")?;
    let looked = identify(caller.uid, pid, allowed, exe);
    #[cfg(target_os = "linux")]
    if caller.pidfd.as_ref().is_some_and(ended) {
        return Err(nerve_transport::ctl::PEER_ENDED.into());
    }
    looked
}

/// The argument that starts the node's program as the helper that tells
/// root's program ([`check_main`]). Not a command the owner types.
pub const CHECK_ARG: &str = "__provider-check";

/// Runs `exe` as root with [`CHECK_ARG`] for `pid` and `allowed`, and
/// reads its answer ([`Seen`]). The child takes root's ids before its program starts,
/// as a command of root does (crate::account::Switch), and so runs with
/// root's rights; it gets nothing from the node's environment.
#[cfg(target_os = "linux")]
fn as_root(exe: &Path, pid: u32, allowed: &Path) -> Result<Seen, String> {
    use std::os::unix::process::CommandExt;
    let switch = crate::account::Switch::new(&crate::account::root(), None, &[])
        .map_err(|e| format!("{ROOT_UNTOLD}: {e}"))?;
    let mut c = std::process::Command::new(exe);
    c.arg(CHECK_ARG)
        .arg(pid.to_string())
        .arg(allowed)
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    // SAFETY: plain system calls on memory moved into the closure.
    unsafe {
        c.pre_exec(move || switch.apply());
    }
    let out = c.output().map_err(|e| format!("{ROOT_UNTOLD}: {e}"))?;
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| format!("{ROOT_UNTOLD}: its helper did not answer"))?;
    if let Some(e) = v["error"].as_str() {
        return Err(e.to_string());
    }
    let untold = || format!("{ROOT_UNTOLD}: its helper did not answer");
    let chain: Option<Vec<u32>> = v["chain"].as_array().and_then(|c| {
        c.iter()
            .map(|p| p.as_u64().and_then(|p| u32::try_from(p).ok()))
            .collect()
    });
    match (
        v["running"].as_str(),
        v["same"].as_bool(),
        v["nnp"].as_bool(),
        chain,
    ) {
        (Some(r), Some(same), Some(nnp), Some(chain)) if !chain.is_empty() => Ok(Seen {
            running: PathBuf::from(r),
            same,
            nnp,
            chain,
        }),
        _ => Err(untold()),
    }
}

/// The helper [`as_root`] starts: `<CHECK_ARG> <pid> <allowed>` prints
/// `{"running": path, "same": bool, "nnp": bool, "chain": [pid, …]}`
/// ([`Seen`]), or `{"error": text}`. The exit code is 0 either way.
pub fn check_main() -> i32 {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    let answer = match (
        args.first()
            .and_then(|p| p.to_str())
            .and_then(|p| p.parse::<u32>().ok()),
        args.get(1),
    ) {
        (Some(pid), Some(allowed)) if args.len() == 2 => match look(pid, Path::new(allowed)) {
            Ok(seen) => json!({"running": seen.running.to_string_lossy(), "same": seen.same,
                               "nnp": seen.nnp, "chain": seen.chain}),
            Err(e) => json!({"error": e}),
        },
        _ => json!({"error": format!("usage: {CHECK_ARG} <pid> <program>")}),
    };
    println!("{answer}");
    0
}

/// Whether the process `pidfd` stands for has ended. One that has not
/// still holds its pid, so what was read under that pid was its own.
#[cfg(target_os = "linux")]
fn ended(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one pollfd, no wait. A pidfd is readable once its process
    // ended.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n != 0
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
/// capability ids of the other attached providers, and `config` tells the
/// ones the config declares (`[[capability]]`), which no program may add.
fn capabilities(
    name: &str,
    fragment: Vec<Fragment>,
    taken: &BTreeSet<String>,
    config: impl Fn(&str) -> bool,
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
        if config(&f.id) {
            return Err(format!(
                "capability {}: the owner declares it in node.toml ([[capability]])",
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
                    as_account: false,
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

/// `hello` from `caller`, on the provider socket or the control socket:
/// attaches it as the provider it names when `providers.allowed` names that
/// provider with the program it runs. The answer keeps the connection
/// ([`nerve_transport::ctl::Reply::Session`]); its end detaches it.
#[cfg(unix)]
pub(crate) async fn attach(
    shared: &Arc<Shared>,
    params: Value,
    caller: Caller,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    match check(shared, params, caller).await {
        Ok(reply) => reply,
        Err(e) => {
            tracing::warn!("a provider was not attached: {e}");
            Reply::Err(e)
        }
    }
}

#[cfg(unix)]
async fn check(
    shared: &Arc<Shared>,
    params: Value,
    caller: Caller,
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
        .ok_or_else(|| format!("refused: providers.allowed names no provider {name}"))?
        .clone();
    let want = PathBuf::from(&allowed.exe);
    let (uid, refuse_commands) = (caller.uid, caller.refuse_commands);
    let looked = {
        let (want, exe) = (want.clone(), shared.exe.clone());
        tokio::task::spawn_blocking(move || read_caller(&caller, &want, exe.as_deref()))
            .await
            .map_err(|e| e.to_string())?
    };
    let Seen {
        running,
        same,
        nnp,
        chain,
    } = looked.map_err(|e| match e.starts_with("refused:") {
        true => e,
        false => format!("refused: the provider {name}: {e}"),
    })?;
    if refuse_commands && let Some(why) = crate::owner::command_refusal(shared, &chain, nnp) {
        return Err(why.into());
    }
    if !same {
        return Err(other_program(&name, &running, &want));
    }
    let (out_tx, out_rx) = mpsc::channel(QUEUE);
    let (in_tx, mut in_rx) = mpsc::channel::<Value>(QUEUE);
    let attached =
        shared
            .providers
            .hold(&name, &allowed.exe, uid, hello.capabilities, out_tx, || {
                // Set before the stop detaches them all (daemon.rs `stop`).
                (!*shared.stop.borrow()).then(|| shared.config())
            })?;
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

/// What `cap ls` shows (docs/user/commands.md): every action of the node's
/// own capabilities and of the attached programs', each with its effect,
/// where it comes from and how each center has it set (`cap set`: `on`,
/// `off`, `hidden`, or `default` where the mode alone decides; for
/// `settings`, which no switch governs, `granted` or `not granted` by
/// `center grant settings`); an action a
/// program offered that the node left out, with the reason; and the
/// programs the owner allowed, attached or not. `live` is the running node:
/// without it no program's capabilities are known, and no row says whether
/// each center may use the action now (`now`: `on` where its descriptor
/// offers it and it is not off, else `off`), which its mode and machine
/// decide besides the switch.
///
/// The capabilities of the config (crate::config_cap) are listed with
/// source `config`, or, where this node does not offer one (`installed`
/// tells a node run by hand, which offers none), with why it is left out;
/// `config` holds each entry as the owner declared it.
pub(crate) fn listing(cfg: &NodeConfig, live: Option<&Shared>, installed: bool) -> Value {
    use nerve_policy::config::CapSetting;
    let attached = live.map(|s| &s.providers);
    // Each center's descriptor as it would see it now, built as the link
    // builds it.
    let seen: Option<BTreeMap<&str, Vec<Capability>>> = live.map(|s| {
        let provided = s.added_caps(cfg);
        cfg.centers
            .iter()
            .map(|c| {
                let reach = s.reach(cfg, c);
                let d = crate::descriptor::for_center(cfg, c, &reach, &provided);
                (c.name.as_str(), d.capabilities)
            })
            .collect()
    });
    let centers = |cap: &str, action: &str| -> Map<String, Value> {
        cfg.centers
            .iter()
            .map(|c| {
                // No switch: the center's grant offers it or not.
                if cap == "settings" {
                    let set = match c.settings {
                        nerve_policy::config::SettingsGrant::Write => "granted",
                        nerve_policy::config::SettingsGrant::Off => "not granted",
                    };
                    return (c.name.clone(), json!(set));
                }
                let set = match c.policy.cap_setting(cap, Some(action)) {
                    Some(CapSetting::On) => "on",
                    Some(CapSetting::Off) => "off",
                    Some(CapSetting::Hidden) => "hidden",
                    None => "default",
                };
                (c.name.clone(), json!(set))
            })
            .collect()
    };
    let now = |cap: &str, action: &str| -> Option<Map<String, Value>> {
        let seen = seen.as_ref()?;
        let on = |caps: &Vec<Capability>| {
            caps.iter().any(|c| {
                c.id == cap
                    && c.exposure == Exposure::On
                    && c.actions
                        .get(action)
                        .is_some_and(|a| a.exposure != Some(Exposure::Off))
            })
        };
        Some(
            seen.iter()
                .map(|(c, caps)| (c.to_string(), json!(if on(caps) { "on" } else { "off" })))
                .collect(),
        )
    };
    let row = |c: &Capability, source: &str| -> Vec<Value> {
        c.actions
            .iter()
            .map(|(a, decl)| {
                let mut r = json!({"name": format!("{}.{a}", c.id), "effect": decl.effect,
                                   "source": source, "summary": decl.summary,
                                   "centers": centers(&c.id, a)});
                if let Some(now) = now(&c.id, a) {
                    r["now"] = Value::Object(now);
                }
                r
            })
            .collect()
    };
    let mut rows: Vec<Value> = crate::descriptor::built_in(cfg)
        .iter()
        .flat_map(|c| row(c, "built-in"))
        .collect();
    let offered = crate::config_cap::offered(cfg, installed);
    for c in offered {
        rows.extend(row(&c, crate::config_cap::PROVIDER));
    }
    for decl in &cfg.capabilities {
        if let Some(why) = crate::config_cap::left_out(decl, std::env::consts::OS, installed) {
            let (cap, action) = decl.split();
            rows.push(json!({"name": decl.name, "effect": decl.effect,
                             "source": crate::config_cap::PROVIDER, "left_out": why,
                             "centers": centers(cap, action)}));
        }
    }
    let config: Vec<Value> = cfg
        .capabilities
        .iter()
        .map(crate::config_cap::entry)
        .collect();
    let held = attached.map(|p| lock(&p.attached).clone());
    for a in held.iter().flat_map(|h| h.values()) {
        let source = format!("program {}", a.name);
        for c in &a.caps {
            rows.extend(row(c, &source));
        }
        for b in &a.broken {
            let (cap, action) = b.name.split_once('.').unwrap_or((&b.name, ""));
            rows.push(json!({"name": b.name, "source": source, "broken": b.reason,
                             "centers": centers(cap, action)}));
        }
    }
    let programs: Vec<Value> = cfg
        .providers
        .allowed
        .iter()
        .map(|p| {
            let on = held.as_ref().map(|h| h.contains_key(&p.name));
            json!({"name": p.name, "exe": p.exe, "attached": on})
        })
        .collect();
    json!({"capabilities": rows, "programs": programs, "config": config,
           "running": live.is_some()})
}

/// The provider socket's file name, beside the owner socket in the
/// installed unit's runtime folder (crate::owner::RUNTIME_DIR).
pub const SOCKET_NAME: &str = "provider.sock";

/// Why the provider socket refuses an account that is neither an owner of
/// the node nor root.
pub const NOT_AN_OWNER: &str =
    "refused: only the owner of the installed node and root attach a provider to it";

/// How long the provider socket keeps the owner's uid before it looks the
/// account up again ([`Admits`]).
#[cfg(target_os = "linux")]
const OWNER_AGAIN: std::time::Duration = std::time::Duration::from_secs(60);

/// How [`Admits`] looks an account up: its uid by its name.
#[cfg(target_os = "linux")]
type Lookup = Box<dyn Fn(&str) -> Option<u32> + Send + Sync>;

/// Who the provider socket lets in, told by the caller's uid alone: the
/// check runs on the runtime for every connection, from any account, while
/// the caller holds one of the socket's places, so it looks nothing up. The
/// owner's account (`Owners::Named`) is looked up as the socket starts, and
/// again, off the runtime, by a connection that comes once the last lookup
/// is [`OWNER_AGAIN`] old: an account made or changed while the node runs
/// counts after that, and a flood of connections costs at most one lookup
/// in that time. Root is always let in.
#[cfg(target_os = "linux")]
struct Admits {
    owners: crate::owner::Owners,
    /// The owner's uid as last looked up, and when.
    known: Mutex<(Option<u32>, std::time::Instant)>,
    looking: std::sync::atomic::AtomicBool,
    again: std::time::Duration,
    lookup: Lookup,
}

#[cfg(target_os = "linux")]
impl Admits {
    /// Looks the owner up once now. Blocks.
    fn new(owners: crate::owner::Owners, again: std::time::Duration, lookup: Lookup) -> Arc<Self> {
        let uid = match &owners {
            crate::owner::Owners::Named(n) => lookup(n),
            _ => None,
        };
        Arc::new(Admits {
            owners,
            known: Mutex::new((uid, std::time::Instant::now())),
            looking: Default::default(),
            again,
            lookup,
        })
    }

    /// Whether `uid` may attach a provider. Never blocks.
    fn admits(self: &Arc<Self>, uid: u32) -> bool {
        use crate::owner::Owners;
        if uid == 0 {
            return true;
        }
        let name = match &self.owners {
            Owners::Named(n) => n,
            Owners::Uids(u) => return u.contains(&uid),
            Owners::Sids(_) => return false,
        };
        let (known, at) = *lock(&self.known);
        if at.elapsed() >= self.again && !self.looking.swap(true, Ordering::SeqCst) {
            let (me, name) = (self.clone(), name.clone());
            tokio::task::spawn_blocking(move || {
                let uid = (me.lookup)(&name);
                *lock(&me.known) = (uid, std::time::Instant::now());
                me.looking.store(false, Ordering::SeqCst);
            });
        }
        known == Some(uid)
    }
}

/// Serves the provider socket `at` of the installed node until the task is
/// aborted: open to every account, 0666, in a folder everyone may enter.
/// An account that is not one of `owners` (root always is) is refused as
/// it connects, told by its uid alone ([`Admits`]), so it holds a place
/// only for that comparison. The socket's places are its own
/// ([`nerve_transport::ctl::MAX_PROVIDERS`]): a provider's connection
/// stays, and neither this socket nor the owner socket can take the
/// other's. A process below a command of the node is refused, as on the
/// owner socket. The token-gated control socket stays the way in for a
/// node run by hand.
#[cfg(target_os = "linux")]
pub(crate) async fn serve(
    shared: Arc<Shared>,
    at: PathBuf,
    owners: crate::owner::Owners,
) -> Result<tokio::task::JoinHandle<()>, String> {
    use nerve_transport::ctl::Reply;
    let listener = nerve_transport::ctl::bind_open(&at)
        .await
        .map_err(|e| format!("{}: {e}", at.display()))?;
    let admits = tokio::task::spawn_blocking(move || {
        Admits::new(
            owners,
            OWNER_AGAIN,
            Box::new(|n| crate::account::lookup(n).ok().flatten().map(|a| a.uid)),
        )
    })
    .await
    .map_err(|e| e.to_string())?;
    let task = tokio::spawn(async move {
        let admit = move |peer: &nerve_transport::ctl::Peer| match admits.admits(peer.uid) {
            true => Ok(()),
            false => Err(NOT_AN_OWNER.to_string()),
        };
        let r = nerve_transport::ctl::serve_providers(
            listener,
            nerve_transport::ctl::MAX_PROVIDERS,
            admit,
            move |req, peer, pidfd| {
                let s = shared.clone();
                async move {
                    if req.method != "hello" {
                        return Reply::Err(format!(
                            "the provider socket takes a provider's hello only, not {:?}",
                            req.method
                        ));
                    }
                    // Below a command, or with no_new_privs: told from
                    // what the node sees of the process as its account.
                    let caller = Caller {
                        uid: peer.uid,
                        pid: peer.pid,
                        pidfd,
                        refuse_commands: true,
                    };
                    attach(&s, req.params, caller).await
                }
            },
        )
        .await;
        if let Err(e) = r {
            tracing::error!("the provider socket stopped: {e}");
        }
    });
    Ok(task)
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
///
/// `caps` are those the attached programs offer and those the config
/// declares (crate::config_cap::declared), offered now or not, which count
/// alike.
pub fn owner_only_of(caps: &[Capability]) -> impl Fn(&str) -> bool + use<> {
    let mut sensing = BTreeSet::new();
    let mut offered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in caps {
        offered
            .entry(c.id.clone())
            .or_default()
            .extend(c.actions.keys().cloned());
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
        let (caps, broken) =
            capabilities("desk", fragment(echo()), &BTreeSet::new(), |_| false).unwrap();
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
        let (caps, broken) =
            capabilities("desk", fragment(frag), &BTreeSet::new(), |_| false).unwrap();
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
        let e = capabilities("desk", fragment(none), &BTreeSet::new(), |_| false).unwrap_err();
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
        let (_, broken) =
            capabilities("desk", fragment(frag), &BTreeSet::new(), |_| false).unwrap();
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
            let e = capabilities("desk", fragment(bad.clone()), &taken, |_| false).unwrap_err();
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
        assert!(capabilities("desk", fragment(json!(many)), &BTreeSet::new(), |_| false).is_err());
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

    /// The pidfd of a process says when it ended, so a pid read before is
    /// known to be its own while it has not.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pidfd_tells_whether_its_process_ended() {
        use std::os::fd::FromRawFd;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        // SAFETY: pidfd_open of a child this test holds; the fd is new.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) };
        assert!(!ended(&pidfd));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(ended(&pidfd));
    }

    /// A pidfd of `sleep` that has ended.
    #[cfg(target_os = "linux")]
    fn ended_pidfd() -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        // SAFETY: pidfd_open of a child this test holds; the fd is new.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        child.kill().unwrap();
        child.wait().unwrap();
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }
    }

    /// A caller whose process that connected has ended is refused, however
    /// well its pid reads now: the pid may be another process's. While it
    /// runs, what its pid reads is its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_caller_whose_process_ended_is_refused_whatever_its_pid_reads() {
        use std::os::fd::FromRawFd;
        let me = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let caller = Caller {
            uid: crate::account::own_uid(),
            pid: Some(std::process::id()),
            pidfd: Some(ended_pidfd()),
            refuse_commands: true,
        };
        assert_eq!(
            read_caller(&caller, &me, None).unwrap_err(),
            nerve_transport::ctl::PEER_ENDED
        );
        // SAFETY: pidfd_open of this process; the fd is new.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let caller = Caller {
            pidfd: Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }),
            ..caller
        };
        assert!(read_caller(&caller, &me, None).unwrap().same);
    }

    /// The provider socket tells the owner by a uid it looked up before:
    /// however many connections come, from whichever account, the account
    /// is looked up again at most once a while, off the connections, and
    /// what that lookup finds counts from then on.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_provider_socket_looks_the_owner_up_once_a_while_only() {
        use std::sync::atomic::{AtomicU32, AtomicUsize};
        let looked = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(AtomicU32::new(1000));
        let lookup = |looked: Arc<AtomicUsize>, owner: Arc<AtomicU32>| {
            Box::new(move |n: &str| {
                assert_eq!(n, "own");
                looked.fetch_add(1, Ordering::SeqCst);
                Some(owner.load(Ordering::SeqCst))
            }) as Lookup
        };
        let named = || crate::owner::Owners::Named("own".into());
        let a = Admits::new(
            named(),
            std::time::Duration::from_secs(3600),
            lookup(looked.clone(), owner.clone()),
        );
        assert_eq!(looked.load(Ordering::SeqCst), 1);
        for _ in 0..100 {
            assert!(!a.admits(1001));
        }
        assert!(a.admits(1000));
        assert!(a.admits(0));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(looked.load(Ordering::SeqCst), 1, "looked up per connection");

        // Once the last lookup is old, a connection starts the next one and
        // is told by the old uid; the ones after it by the new.
        let looked = Arc::new(AtomicUsize::new(0));
        let a = Admits::new(
            named(),
            std::time::Duration::ZERO,
            lookup(looked.clone(), owner.clone()),
        );
        owner.store(1001, Ordering::SeqCst);
        assert!(!a.admits(1001));
        let t = std::time::Instant::now();
        while lock(&a.known).0 != Some(1001) {
            assert!(t.elapsed().as_secs() < 10, "not looked up again");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(a.admits(1001));
        assert!(!a.admits(1000));
        assert!(looked.load(Ordering::SeqCst) >= 2);

        let uids = Admits::new(
            crate::owner::Owners::Uids(vec![1002]),
            std::time::Duration::ZERO,
            lookup(Arc::new(AtomicUsize::new(0)), owner.clone()),
        );
        assert!(uids.admits(1002) && uids.admits(0) && !uids.admits(1001));
    }

    fn allowing(name: &str, exe: &str) -> NodeConfig {
        let mut cfg = NodeConfig::default();
        cfg.providers.allowed = vec![nerve_policy::config::AllowedProvider {
            name: name.into(),
            exe: exe.into(),
        }];
        cfg
    }

    /// A provider whose entry the owner removed or changed while the node
    /// looked at its program is not held: the config is read again as it is
    /// held. Nor is one while the node stops.
    #[test]
    fn a_provider_the_owner_dropped_while_it_was_checked_is_not_held() {
        let p = Providers::default();
        let (tx, _rx) = mpsc::channel(1);
        for now in [NodeConfig::default(), allowing("desk", "/opt/other")] {
            let e = p
                .hold(
                    "desk",
                    "/opt/desk",
                    1000,
                    fragment(echo()),
                    tx.clone(),
                    || Some(now),
                )
                .err()
                .expect("not held");
            assert!(e.contains("providers.allowed changed"), "{e}");
        }
        assert_eq!(p.held("desk"), None);
        let a = p
            .hold(
                "desk",
                "/opt/desk",
                1000,
                fragment(echo()),
                tx.clone(),
                || None,
            )
            .err()
            .expect("not held while the node stops");
        assert_eq!(a, STOPPING);
        assert_eq!(p.held("desk"), None);
        let a = p
            .hold("desk", "/opt/desk", 1000, fragment(echo()), tx, || {
                Some(allowing("desk", "/opt/desk"))
            })
            .unwrap();
        assert_eq!(p.held("desk"), Some((1000, a.serial)));
    }

    /// A call goes to the attachment it was decided for: once that one went,
    /// a later one of the same name does not get it.
    #[tokio::test]
    async fn a_call_goes_to_the_attachment_it_was_decided_for_only() {
        let p = Providers::default();
        let (tx, _rx) = mpsc::channel(4);
        let hold = |tx| {
            p.hold("desk", "/opt/desk", 1000, fragment(echo()), tx, || {
                Some(allowing("desk", "/opt/desk"))
            })
            .unwrap()
            .serial
        };
        let first = hold(tx.clone());
        assert!(p.remove("desk", first));
        let (later_tx, mut later) = mpsc::channel(4);
        let _later = hold(later_tx);
        let call = p.invoke("desk", first, "echo", "say", Map::new());
        let e = tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .expect("answered at once")
            .unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Unavailable);
        assert!(later.try_recv().is_err(), "the later one got the call");
    }

    /// The node's own program, and a program of its own account, is looked
    /// at as the node itself; the helper says the same for root.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_program_of_the_nodes_own_account_is_told_directly() {
        let me = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let seen = identify(crate::account::own_uid(), std::process::id(), &me, None).unwrap();
        assert_eq!((seen.running.as_path(), seen.same), (me.as_path(), true));
        assert!(!seen.nnp);
        assert_eq!(
            seen.chain[..2],
            [std::process::id(), std::os::unix::process::parent_id()]
        );
        let seen = identify(
            crate::account::own_uid(),
            std::process::id(),
            Path::new("/bin/sh"),
            None,
        )
        .unwrap();
        assert!(!seen.same);
    }

    /// A process whose status the node cannot read is refused, not taken
    /// for one without `no_new_privs`: where `/proc` hides it, a command's
    /// process would pass.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_status_the_node_cannot_read_refuses() {
        assert_eq!(no_new_privs(std::process::id()), Ok(false));
        let e = no_new_privs(u32::MAX).unwrap_err();
        assert!(e.starts_with("refused: the node cannot tell how"), "{e}");
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
