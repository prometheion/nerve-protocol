//! Long calls become jobs (docs/dev/spec/harness.md §4.4).
//!
//! `execute` waits for a call's result up to the center's call wait
//! (`--call-wait`, 20 s by default). A call still running then becomes a job:
//! `execute` answers its id at once, the call runs on, and `job.status` gives
//! its state, or its result once it ended. A harness gives up on a tool call
//! after a while (often a minute), so no call holds it longer than the wait.
//!
//! Every call of a session is an entry here from its start, so a call and the
//! job it may become are the same thing: the entry's task owns the call, and
//! the `execute` waiting for it only holds a receiver. A session has at most
//! [`RUNNING_MAX`] calls running. Finished results are kept in memory only,
//! cut as a result is, at most [`KEPT_MAX`] bytes of them per session, until
//! they are read or for [`KEEP_FOR`]. A call that is stopped (`job.cancel`,
//! the harness cancelling the request before it became a job, the session's
//! end) leaves the map at once: its task finds nothing to report to.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::{oneshot, watch};

use nerve_proto::{ErrorCode, RpcError};

use crate::link::{self, Link};
use crate::tools::Route;
use crate::util;

/// How long `execute` waits for a result before the call becomes a job.
pub const CALL_WAIT: Duration = Duration::from_secs(20);
/// The shortest and the longest call wait a center takes.
pub const CALL_WAIT_MIN: Duration = Duration::from_millis(10);
pub const CALL_WAIT_MAX: Duration = Duration::from_secs(600);
/// The most calls of one session that run at once, jobs or not.
pub const RUNNING_MAX: usize = 16;
/// The places beyond [`RUNNING_MAX`] only `exec.signal` of a job may take:
/// a session whose places all hold commands can still ask one to stop.
pub const SIGNAL_ROOM: usize = 4;
/// The most bytes of finished results one session keeps.
pub const KEPT_MAX: usize = 4 * 1024 * 1024;
/// How long a finished result is kept when nobody reads it.
pub const KEEP_FOR: Duration = Duration::from_secs(600);
/// The most `job.status` may be asked to wait, in milliseconds; it never
/// waits longer than the call wait.
pub const WAIT_MS_MAX: u64 = 600_000;
/// The most text of one result kept, as `execute` hands it to a model.
pub const RESULT_TEXT: usize = crate::listing::TEXT_MAX;

/// Why a running call was stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The harness cancelled its request before the call became a job.
    Abandoned,
    /// `job.cancel`.
    Cancelled,
    /// The session ended.
    SessionEnded,
    /// The node's owner disabled it in the center.
    Disabled,
}

impl Stop {
    /// The error a call stopped this way ends with.
    pub fn error(self) -> RpcError {
        let why = match self {
            Stop::Abandoned => "the harness cancelled the call",
            Stop::Cancelled => "the job was cancelled",
            Stop::SessionEnded => "the session ended",
            Stop::Disabled => "the node was disabled in the center",
        };
        RpcError::new(ErrorCode::Cancelled, why)
    }
}

/// How a job ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The node's result; `cut` when it was longer than a result may be, and
    /// `value` holds its text cut at [`RESULT_TEXT`].
    Done { value: Value, cut: bool },
    /// The node (or the center) refused the call or it failed.
    Failed(RpcError),
    /// The link to the node ended before the result came: the node ends a
    /// call whose link ends, so what the call did is not known.
    Lost,
    /// The result came but was not kept: the session's finished results
    /// would have passed [`KEPT_MAX`].
    Dropped { bytes: usize },
}

impl Outcome {
    /// The outcome of a call's result `r`, with the bytes it keeps.
    fn of(r: Result<Value, RpcError>) -> (Outcome, usize) {
        match r {
            Ok(v) => {
                let body = match &v {
                    Value::String(s) => s.clone(),
                    other => serde_json::to_string_pretty(other).unwrap_or_default(),
                };
                if body.len() > RESULT_TEXT {
                    let text = util::clip(&body, RESULT_TEXT);
                    let n = text.len();
                    (
                        Outcome::Done {
                            value: Value::String(text),
                            cut: true,
                        },
                        n,
                    )
                } else {
                    (
                        Outcome::Done {
                            value: v,
                            cut: false,
                        },
                        body.len(),
                    )
                }
            }
            // The link's own `connection_lost`, not one the node wrote.
            Err(e) if e.kind() == ErrorCode::ConnectionLost && !link::by_node(&e) => {
                (Outcome::Lost, 0)
            }
            Err(e) => {
                let n = e.message.len()
                    + e.data
                        .as_ref()
                        .map_or(0, |d| serde_json::to_string(d).map_or(0, |s| s.len()));
                (Outcome::Failed(e), n)
            }
        }
    }

    pub fn state(&self) -> &'static str {
        match self {
            Outcome::Done { .. } | Outcome::Dropped { .. } => "done",
            Outcome::Failed(_) => "failed",
            Outcome::Lost => "lost",
        }
    }
}

/// One call of a session, from its start until its result is handed over,
/// read or dropped.
struct Entry {
    route: Route,
    started: Instant,
    /// It became a job: the agent was given its id.
    job: bool,
    /// The `execute` waiting for the result, until the call becomes a job.
    waiter: Option<oneshot::Sender<Result<Value, RpcError>>>,
    /// Stops the call's task.
    stop: Option<oneshot::Sender<Stop>>,
    /// The link and `invoke` id the call was sent with, for `exec.signal`.
    sent: Option<(Arc<Link>, u64)>,
    /// How it ended, when, and the bytes its result keeps.
    end: Option<(Outcome, Instant, usize)>,
    /// Set to true when it ends, for `job.status` waiting on it.
    done: watch::Sender<bool>,
}

/// A job as `job.status` sees it.
#[derive(Debug)]
pub struct View {
    pub route: Route,
    /// How long it ran (until now, or until it ended).
    pub ran: Duration,
    /// None while it runs.
    pub outcome: Option<Outcome>,
}

/// Where `exec.signal` of a job goes: its link and the `invoke` id.
pub type Sent = (Arc<Link>, u64);

/// Why a job id names nothing `exec.signal` can signal.
#[derive(Debug, PartialEq, Eq)]
pub enum NoSignal {
    /// No running job of this session on that node has this id.
    Unknown,
    /// It is not a command.
    NotCommand(String),
    /// It has not reached the node yet.
    NotSent,
}

/// A session's calls and jobs, under the session's lock. Nothing else is
/// locked while it is held.
#[derive(Default)]
pub struct Jobs {
    entries: HashMap<String, Entry>,
    /// The bytes of the finished results kept.
    kept: usize,
    /// The session ended: no call starts any more.
    ended: bool,
}

impl Jobs {
    /// How many calls run.
    pub fn running(&self) -> usize {
        self.entries.values().filter(|e| e.end.is_none()).count()
    }

    /// The bytes of finished results kept.
    pub fn kept(&self) -> usize {
        self.kept
    }

    /// Starts the call `id` of `route`: the receiver of its result (until
    /// it becomes a job) and the one that stops its task. Refused when the
    /// session has [`RUNNING_MAX`] calls running (a `signal` of a job has
    /// [`SIGNAL_ROOM`] more), or has ended.
    #[allow(clippy::type_complexity)]
    pub fn start(
        &mut self,
        id: &str,
        route: &Route,
        signal: bool,
    ) -> Result<
        (
            oneshot::Receiver<Result<Value, RpcError>>,
            oneshot::Receiver<Stop>,
        ),
        RpcError,
    > {
        if self.ended {
            return Err(Stop::SessionEnded.error());
        }
        let most = RUNNING_MAX + if signal { SIGNAL_ROOM } else { 0 };
        if self.running() >= most {
            return Err(RpcError::new(
                ErrorCode::Busy,
                format!(
                    "this session has {} calls running, the most it may: wait for one with job.status, or stop one with job.cancel.{}",
                    self.running(),
                    self.named(Instant::now())
                ),
            ));
        }
        let (waiter, result) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        self.entries.insert(
            id.to_string(),
            Entry {
                route: route.clone(),
                started: Instant::now(),
                job: false,
                waiter: Some(waiter),
                stop: Some(stop),
                sent: None,
                end: None,
                done: watch::channel(false).0,
            },
        );
        Ok((result, stopped))
    }

    /// The session's running jobs, oldest first, as a refusal names them:
    /// a model whose context lost their ids finds them again here.
    fn named(&self, now: Instant) -> String {
        let mut jobs: Vec<(&String, &Entry)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.job && e.end.is_none())
            .collect();
        if jobs.is_empty() {
            return String::new();
        }
        jobs.sort_by_key(|(_, e)| e.started);
        let named: Vec<String> = jobs
            .iter()
            .map(|(id, e)| {
                format!(
                    "{id} ({}.{} on node {}, for {})",
                    e.route.cap,
                    e.route.action,
                    e.route.node_name,
                    util::span(now.saturating_duration_since(e.started))
                )
            })
            .collect();
        format!(" Its running jobs: {}.", named.join(", "))
    }

    /// The call `id` was sent on `link` as the `invoke` `invoke`.
    pub fn sent(&mut self, id: &str, link: &Arc<Link>, invoke: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            e.sent = Some((link.clone(), invoke));
        }
    }

    /// The call `id` becomes a job, unless its result was handed over
    /// meanwhile (or it was stopped): whether it did.
    pub fn detach(&mut self, id: &str) -> bool {
        let Some(e) = self.entries.get_mut(id) else {
            return false;
        };
        if e.waiter.take().is_none() {
            return false;
        }
        e.job = true;
        true
    }

    /// The `execute` waiting for the call `id` went away before the call
    /// ended or became a job: the call leaves the map, and the sender that
    /// stops it is given back.
    pub fn abandon(&mut self, id: &str) -> Option<oneshot::Sender<Stop>> {
        if !self.entries.get(id).is_some_and(|e| e.waiter.is_some()) {
            return None;
        }
        self.entries.remove(id).and_then(|e| e.stop)
    }

    /// The call `id` ended with `r`. While an `execute` waits for it, the
    /// call leaves the map and the waiter is given back with the result to
    /// send it. A job keeps its outcome for `job.status`, unless the
    /// session's finished results would pass [`KEPT_MAX`].
    #[allow(clippy::type_complexity)]
    pub fn finish(
        &mut self,
        id: &str,
        r: Result<Value, RpcError>,
        now: Instant,
    ) -> Option<(
        oneshot::Sender<Result<Value, RpcError>>,
        Result<Value, RpcError>,
    )> {
        let e = self.entries.get_mut(id)?;
        if let Some(w) = e.waiter.take() {
            self.entries.remove(id);
            return Some((w, r));
        }
        let (mut outcome, mut bytes) = Outcome::of(r);
        if self.kept + bytes > KEPT_MAX {
            outcome = Outcome::Dropped { bytes };
            bytes = 0;
        }
        self.kept += bytes;
        e.stop = None;
        e.end = Some((outcome, now, bytes));
        e.done.send_replace(true);
        None
    }

    /// Forgets the finished results older than [`KEEP_FOR`] at `now`.
    pub fn prune(&mut self, now: Instant) {
        let old: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.end
                    .as_ref()
                    .is_some_and(|(_, at, _)| now.saturating_duration_since(*at) >= KEEP_FOR)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in old {
            self.forget(&id);
        }
    }

    /// Forgets the result of the job `id` once it ended and nobody read
    /// it: the timer started at its end calls this after [`KEEP_FOR`].
    pub fn expire(&mut self, id: &str) {
        if self.entries.get(id).is_some_and(|e| e.end.is_some()) {
            self.forget(id);
        }
    }

    /// How many calls and kept results the session holds.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.entries.len()
    }

    fn forget(&mut self, id: &str) {
        if let Some(e) = self.entries.remove(id)
            && let Some((_, _, bytes)) = e.end
        {
            self.kept -= bytes;
        }
    }

    /// The job `id` of the node `node_id`, as it is now; a finished one is
    /// read once, and forgotten. None when there is no such job.
    pub fn status(&mut self, id: &str, node_id: &str, now: Instant) -> Option<View> {
        self.prune(now);
        let e = self
            .entries
            .get(id)
            .filter(|e| e.job && e.route.node_id == node_id)?;
        let view = View {
            route: e.route.clone(),
            ran: e
                .end
                .as_ref()
                .map_or(now, |(_, at, _)| *at)
                .saturating_duration_since(e.started),
            outcome: e.end.as_ref().map(|(o, _, _)| o.clone()),
        };
        if view.outcome.is_some() {
            self.forget(id);
        }
        Some(view)
    }

    /// What tells when the running job `id` of `node_id` ends; none when
    /// there is no such job or it ended.
    pub fn done(&self, id: &str, node_id: &str) -> Option<watch::Receiver<bool>> {
        self.entries
            .get(id)
            .filter(|e| e.job && e.route.node_id == node_id && e.end.is_none())
            .map(|e| e.done.subscribe())
    }

    /// Stops the running job `id` of `node_id`: it leaves the map, and the
    /// sender that stops it is given back with its route. `Err` with the
    /// job's view when it ended already (it stays), none when there is no
    /// such job.
    #[allow(clippy::type_complexity)]
    pub fn cancel(
        &mut self,
        id: &str,
        node_id: &str,
        now: Instant,
    ) -> Option<Result<(Route, Duration, Option<oneshot::Sender<Stop>>), View>> {
        self.prune(now);
        let e = self
            .entries
            .get(id)
            .filter(|e| e.job && e.route.node_id == node_id)?;
        if let Some((o, at, _)) = &e.end {
            return Some(Err(View {
                route: e.route.clone(),
                ran: at.saturating_duration_since(e.started),
                outcome: Some(o.clone()),
            }));
        }
        let e = self.entries.remove(id)?;
        Some(Ok((
            e.route,
            now.saturating_duration_since(e.started),
            e.stop,
        )))
    }

    /// Where `exec.signal` of the running job `id` of `node_id` goes.
    pub fn signal_target(&self, id: &str, node_id: &str) -> Result<Sent, NoSignal> {
        let e = self
            .entries
            .get(id)
            .filter(|e| e.job && e.route.node_id == node_id && e.end.is_none())
            .ok_or(NoSignal::Unknown)?;
        if (e.route.cap.as_str(), e.route.action.as_str()) != ("exec", "run") {
            return Err(NoSignal::NotCommand(format!(
                "{}.{}",
                e.route.cap, e.route.action
            )));
        }
        e.sent.clone().ok_or(NoSignal::NotSent)
    }

    /// The senders that stop the running calls on the node `node_id`, jobs
    /// or not. The calls stay: each ends with the error of its stop, which
    /// a waiting `execute` or `job.status` then gives.
    pub fn stop_on(&mut self, node_id: &str) -> Vec<oneshot::Sender<Stop>> {
        self.entries
            .values_mut()
            .filter(|e| e.route.node_id == node_id && e.end.is_none())
            .filter_map(|e| e.stop.take())
            .collect()
    }

    /// The session ended: no call starts any more, every finished result is
    /// dropped, and the senders that stop the running calls are given back.
    pub fn end(&mut self) -> Vec<oneshot::Sender<Stop>> {
        self.ended = true;
        self.kept = 0;
        self.entries.drain().filter_map(|(_, e)| e.stop).collect()
    }
}

/// A new job id.
pub fn new_id() -> String {
    format!("j-{}", nerve_transport::keys::random_token(12))
}

/// Reads a call wait: `20` or `20s` (seconds), or `500ms`, between
/// [`CALL_WAIT_MIN`] and [`CALL_WAIT_MAX`].
pub fn parse_wait(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (n, ms) = match s.strip_suffix("ms") {
        Some(n) => (n, true),
        None => (s.strip_suffix('s').unwrap_or(s), false),
    };
    let n: u64 = n.trim().parse().map_err(|_| {
        format!("{s:?}: a whole number of seconds (20, 20s) or of milliseconds (500ms)")
    })?;
    let d = if ms {
        Duration::from_millis(n)
    } else {
        Duration::from_secs(n)
    };
    if !(CALL_WAIT_MIN..=CALL_WAIT_MAX).contains(&d) {
        return Err(format!(
            "{s:?}: the call wait is at least {} and at most {}",
            util::span(CALL_WAIT_MIN),
            util::span(CALL_WAIT_MAX)
        ));
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_proto::Effect;
    use serde_json::json;

    fn route(node: &str, unit: &str) -> Route {
        let (cap, action) = unit.split_once('.').unwrap();
        Route {
            node_id: node.into(),
            node_name: node.into(),
            cap: cap.into(),
            action: action.into(),
            effect: Effect::Execute,
        }
    }

    /// A call that becomes a job keeps its result once it ends, for one
    /// read; one whose `execute` still waits hands it over and is gone.
    #[test]
    fn a_job_keeps_its_result_for_one_read() {
        let mut j = Jobs::default();
        let now = Instant::now();
        let (mut rx, _stop) = j.start("j-1", &route("n1", "exec.run"), false).unwrap();
        assert!(j.detach("j-1"));
        assert!(!j.detach("j-1"), "a job is detached once");
        assert_eq!(j.running(), 1);
        let v = j.status("j-1", "n1", now).unwrap();
        assert_eq!(v.outcome, None);
        assert!(j.finish("j-1", Ok(json!({"exit_code": 0})), now).is_none());
        assert!(rx.try_recv().is_err(), "nothing goes to the execute");
        assert_eq!(j.running(), 0);
        assert!(j.kept() > 0);
        let v = j.status("j-1", "n1", now).unwrap();
        assert_eq!(
            v.outcome,
            Some(Outcome::Done {
                value: json!({"exit_code": 0}),
                cut: false
            })
        );
        assert!(j.status("j-1", "n1", now).is_none(), "read once");
        assert_eq!(j.kept(), 0);

        let (_rx, _stop) = j.start("j-2", &route("n1", "fs.read"), false).unwrap();
        let (w, r) = j.finish("j-2", Ok(json!("x")), now).expect("handed over");
        assert!(w.send(r).is_ok());
        assert!(j.status("j-2", "n1", now).is_none(), "never a job");
        assert_eq!(j.running(), 0);
    }

    /// Only a job's id, on its own node, is seen: not a call that never
    /// became one, not one of another node.
    #[test]
    fn a_job_is_seen_on_its_node_only() {
        let mut j = Jobs::default();
        let now = Instant::now();
        let _a = j.start("j-1", &route("n1", "exec.run"), false).unwrap();
        assert!(j.status("j-1", "n1", now).is_none(), "not a job yet");
        assert!(j.detach("j-1"));
        assert!(j.status("j-1", "n2", now).is_none());
        assert!(j.cancel("j-1", "n2", now).is_none());
        assert!(j.done("j-1", "n2").is_none());
        assert_eq!(j.signal_target("j-1", "n2").err(), Some(NoSignal::Unknown));
        assert_eq!(j.signal_target("j-1", "n1").err(), Some(NoSignal::NotSent));
        assert!(j.status("j-1", "n1", now).is_some());
    }

    /// At most `RUNNING_MAX` calls run; a finished job frees its place.
    #[test]
    fn the_seventeenth_call_is_refused() {
        let mut j = Jobs::default();
        let now = Instant::now();
        let mut held = Vec::new();
        for i in 0..RUNNING_MAX {
            let id = format!("j-{i}");
            held.push(j.start(&id, &route("n1", "exec.run"), false).unwrap());
            assert!(j.detach(&id));
        }
        let e = j.start("j-x", &route("n1", "exec.run"), false).unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Busy);
        assert!(e.message.contains("job.cancel"), "{}", e.message);
        // The refusal names the running jobs, so a model that lost their
        // ids can stop one.
        assert!(e.message.contains(" Its running jobs: j-"), "{}", e.message);
        for id in ["j-0", "j-15"] {
            assert!(
                e.message
                    .contains(&format!("{id} (exec.run on node n1, for ")),
                "{}",
                e.message
            );
        }
        // A signal of a job has a few places more.
        let signal = route("n1", "exec.signal");
        for i in 0..SIGNAL_ROOM {
            held.push(j.start(&format!("s-{i}"), &signal, true).unwrap());
        }
        let e = j.start("s-x", &signal, true).unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Busy);
        for i in 0..SIGNAL_ROOM {
            j.finish(&format!("s-{i}"), Ok(json!({})), now);
        }
        j.finish("j-0", Ok(json!({})), now);
        held.push(j.start("j-x", &route("n1", "exec.run"), false).unwrap());
    }

    /// Finished results take at most `KEPT_MAX` bytes; one past it is
    /// named, not kept. Each one is cut as a result is.
    #[test]
    fn finished_results_are_bounded() {
        let mut j = Jobs::default();
        let now = Instant::now();
        let big = "x".repeat(RESULT_TEXT * 2);
        let mut i = 0;
        loop {
            let id = format!("j-{i}");
            let _ = j.start(&id, &route("n1", "exec.run"), false).unwrap();
            j.detach(&id);
            j.finish(&id, Ok(json!(big)), now);
            let v = j.entries[&id].end.as_ref().unwrap().0.clone();
            if let Outcome::Dropped { bytes } = v {
                assert!(bytes > RESULT_TEXT && bytes < RESULT_TEXT + 8);
                break;
            }
            let Outcome::Done { value, cut } = v else {
                panic!("{v:?}")
            };
            assert!(cut);
            assert!(value.as_str().unwrap().len() <= RESULT_TEXT + 3);
            i += 1;
            assert!(i < 100, "never dropped");
        }
        assert!(j.kept() <= KEPT_MAX, "{}", j.kept());
        assert_eq!(i, KEPT_MAX / (RESULT_TEXT + 3));
    }

    /// A finished result nobody reads is forgotten after `KEEP_FOR`.
    #[test]
    fn an_unread_result_is_forgotten_after_ten_minutes() {
        let mut j = Jobs::default();
        let now = Instant::now();
        let _ = j.start("j-1", &route("n1", "exec.run"), false).unwrap();
        j.detach("j-1");
        j.finish("j-1", Ok(json!("done")), now);
        j.prune(now + KEEP_FOR - Duration::from_secs(1));
        assert!(j.kept() > 0);
        assert!(j.status("j-1", "n1", now + KEEP_FOR).is_none(), "forgotten");
        assert_eq!(j.kept(), 0);
    }

    /// A stopped call leaves the map at once; the session's end stops every
    /// running call, drops the results and refuses new calls.
    #[test]
    fn stopping_and_the_sessions_end() {
        let mut j = Jobs::default();
        let now = Instant::now();
        let (_r1, mut s1) = j.start("j-1", &route("n1", "exec.run"), false).unwrap();
        assert!(j.abandon("j-1").unwrap().send(Stop::Abandoned).is_ok());
        assert_eq!(s1.try_recv().unwrap(), Stop::Abandoned);
        assert_eq!(j.running(), 0);
        let (_r2, _s2) = j.start("j-2", &route("n1", "exec.run"), false).unwrap();
        j.detach("j-2");
        assert!(
            j.abandon("j-2").is_none(),
            "a job is no longer the execute's"
        );
        let Some(Ok((r, _, Some(stop)))) = j.cancel("j-2", "n1", now) else {
            panic!("cancelled")
        };
        assert_eq!(r.cap, "exec");
        drop(stop);
        assert!(j.status("j-2", "n1", now).is_none());

        let (_r3, mut s3) = j.start("j-3", &route("n1", "exec.run"), false).unwrap();
        j.detach("j-3");
        let _ = j.start("j-4", &route("n1", "exec.run"), false).unwrap();
        j.detach("j-4");
        j.finish("j-4", Ok(json!("x")), now);
        let Some(Err(v)) = j.cancel("j-4", "n1", now) else {
            panic!("ended already")
        };
        assert_eq!(v.outcome.unwrap().state(), "done");
        for s in j.end() {
            let _ = s.send(Stop::SessionEnded);
        }
        assert_eq!(s3.try_recv().unwrap(), Stop::SessionEnded);
        assert_eq!((j.running(), j.kept()), (0, 0));
        assert!(j.status("j-4", "n1", now).is_none());
        assert_eq!(
            j.start("j-5", &route("n1", "exec.run"), false)
                .unwrap_err()
                .kind(),
            ErrorCode::Cancelled
        );
    }

    /// The link's own `connection_lost` marks a job lost; the same code
    /// written by the node is its failure.
    #[test]
    fn a_link_loss_is_lost_and_a_nodes_error_a_failure() {
        let lost = RpcError::new(ErrorCode::ConnectionLost, "the link to the node ended");
        assert_eq!(Outcome::of(Err(lost)).0, Outcome::Lost);
        let mut by_node = RpcError::new(ErrorCode::ConnectionLost, "x");
        by_node.data = Some(json!({"from": "node"}));
        assert_eq!(Outcome::of(Err(by_node)).0.state(), "failed");
    }

    #[test]
    fn the_call_wait_is_read_in_seconds_or_milliseconds() {
        assert_eq!(parse_wait("20"), Ok(Duration::from_secs(20)));
        assert_eq!(parse_wait("20s"), Ok(Duration::from_secs(20)));
        assert_eq!(parse_wait("100ms"), Ok(Duration::from_millis(100)));
        for bad in ["", "x", "1.5", "-1", "5ms", "601", "20m"] {
            assert!(parse_wait(bad).is_err(), "{bad}");
        }
    }
}
