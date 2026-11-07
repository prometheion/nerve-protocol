//! Calls to the nodes: a unit's call, its streams and events, through
//! the action checker and the call wait.

use nerve_transport::sync::lock;

use super::*;

/// How a call of a unit (an `execute`) came out within its wait.
#[derive(Debug)]
pub enum Ran {
    Done(Result<Value, CallError>),
    /// It runs on as the job with this id.
    Job(String),
}

/// Why a call of a unit (an `execute`) did not produce a result.
#[derive(Debug)]
pub enum CallError {
    Rpc(RpcError),
}

impl From<RpcError> for CallError {
    fn from(e: RpcError) -> CallError {
        CallError::Rpc(e)
    }
}

/// An `invoke` whose reply has not come. Dropped before it comes (the call
/// was stopped: `job.cancel`, the session's end, or the harness cancelled
/// its request before the call became a job), it tells the node to cancel
/// the request, so a command does not run on for nobody.
struct Waiting {
    link: Option<Arc<Link>>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(link) = self.link.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let id = self.id;
            rt.spawn(async move { link.cancel(id).await });
        }
    }
}

/// A stream of a session that `execute` adds before its node answered.
/// Dropped before its id was given (the harness cancelled the request, or
/// the node refused), it closes the stream again: nobody could name it to
/// close it, and it would hold one of the session's places and its
/// subscription on the link for as long as the session lives. It owns
/// what it needs, so that it can be made before the task that opens the
/// stream: a task aborted before it first ran drops it too.
struct Adding {
    sess: Arc<Session>,
    node_id: String,
    id: Option<String>,
    why: &'static str,
}

impl Adding {
    /// The id is given: the stream stays.
    fn keep(mut self) -> String {
        self.id.take().unwrap_or_default()
    }
}

impl Drop for Adding {
    fn drop(&mut self) {
        if let Some(id) = self.id.take()
            && let Some(c) = lock(&self.sess.streams).close(&id, &self.node_id)
        {
            c.close(self.why);
        }
    }
}

/// What `execute` of a program's event or stream gives: the id of the
/// session's stream it comes in, and whether it was still being opened
/// when the call wait passed.
#[derive(Debug)]
pub struct Opened {
    pub id: String,
    pub opening: bool,
}

/// Where the opening of a program's stream or subscription is
/// ([`Center::within_call_wait`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Its `execute` waits for it.
    Waited,
    /// The call wait passed: the stream's id was given, and the open goes
    /// on by itself.
    Given,
    /// It ended before the call wait passed: its `execute` has its result.
    Done,
}

/// Stops a task when dropped, unless it was let go (`None`).
struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

/// A stream taken out of its session while it opened: the agent closed
/// it, the session ended or the node was disabled. Its ring says which.
fn closed_while_opening(ring: &Ring) -> RpcError {
    RpcError::new(
        ErrorCode::Cancelled,
        format!(
            "the stream was closed while it opened ({})",
            ring.why().as_deref().unwrap_or("it was closed")
        ),
    )
}

/// Why a stream whose id was given did not open, for its `stream.read`:
/// the error on one line, a node's own words said to be its own, as
/// `execute` gives them.
fn not_opened_words(route: &Route, e: &RpcError) -> String {
    let whose = if crate::link::by_node(e) {
        format!("node {} answered: ", route.node_name)
    } else {
        String::new()
    };
    listing::one_line(&format!(
        "it did not open: error {}: {whose}{}",
        e.kind().as_str(),
        e.message
    ))
}

impl Center {
    // ---- Calls ----

    /// Runs a call of a unit (an `execute`) on its node and waits for its
    /// result: the node's policy decides.
    pub async fn call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
    ) -> Result<Value, CallError> {
        match self.run(sess, route, args, None, None).await {
            Ran::Done(r) => r,
            Ran::Job(_) => unreachable!("a call without a wait never becomes a job"),
        }
    }

    /// Runs a call of a unit (an `execute`) on its node, waiting at most
    /// `wait` for its result (docs/dev/spec/harness.md §4.4). A call still
    /// running then becomes a job of the session, and runs on: a task of its
    /// own owns it, so the `execute` that returns the job's id does not stop
    /// it. Dropped before that (the harness cancelled its request), the call
    /// is stopped, and the node is told to cancel it. `on` is the link a
    /// job's `exec.signal` must go on: the `invoke` id it names is that
    /// link's.
    pub async fn run(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        on: Option<Arc<Link>>,
        wait: Option<Duration>,
    ) -> Ran {
        self.run_dropped(sess, route, args, on, wait, Stop::Abandoned)
            .await
    }

    /// [`Center::run`] whose call stops `dropped` when it is dropped before
    /// it became a job.
    async fn run_dropped(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        on: Option<Arc<Link>>,
        wait: Option<Duration>,
        dropped: Stop,
    ) -> Ran {
        let id = jobs::new_id();
        let started = lock(&sess.jobs).start(&id, route, on.is_some());
        let (mut result, stop) = match started {
            Ok(s) => s,
            Err(e) => return Ran::Done(Err(self.refused(sess, route, e))),
        };
        sess.calls.fetch_add(1, Ordering::SeqCst);
        let mut held = Held {
            sess: sess.clone(),
            id: Some(id.clone()),
            why: dropped,
        };
        let (c, s, r, i) = (self.clone(), sess.clone(), route.clone(), id.clone());
        tokio::spawn(async move { c.run_call(&s, &r, args, &i, on, stop).await });
        let got = match wait {
            None => Some((&mut result).await),
            Some(w) => tokio::time::timeout(w, &mut result).await.ok(),
        };
        let got = match got {
            Some(got) => got,
            None => {
                let became = lock(&sess.jobs).detach(&id);
                held.id = None;
                if became {
                    return Ran::Job(id);
                }
                // The result came in between.
                result.await
            }
        };
        held.id = None;
        // The waiter goes away without a result only when the session's end
        // stopped the call.
        Ran::Done(
            got.unwrap_or_else(|_| Err(Stop::SessionEnded.error()))
                .map_err(CallError::Rpc),
        )
    }

    /// Names the output stream of the `exec.run` job `job` of `sess`, and
    /// opens it on its node once the command runs there
    /// (docs/dev/spec/harness.md §4.5, [`streams::open_on_node`]): its id,
    /// or why it has none.
    pub fn open_output(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        job: &str,
    ) -> Result<String, String> {
        let (room, gone) = lock(&sess.streams).room(Instant::now());
        for c in gone {
            c.close("too many streams");
        }
        if !room {
            return Err(format!(
                "this session holds {} streams already, the most it may: close one with stream.close",
                streams::STREAMS_MAX
            ));
        }
        let ring = Arc::new(Ring::default());
        let id = streams::new_id();
        if !lock(&sess.streams).add(&id, &route.node_id, job, ring.clone()) {
            return Err("the session ended".into());
        }
        let waits = *lock(&self.stream_waits);
        tokio::spawn(streams::open_on_node(
            Arc::downgrade(sess),
            route.node_id.clone(),
            job.to_string(),
            id.clone(),
            ring,
            waits,
        ));
        Ok(id)
    }

    /// The session read a command's output (`stream.read`): outside content,
    /// as the command's result is once it ends, so it taints the session.
    pub fn taint_by_output(&self, sess: &Session) {
        if self.checker().taint_on()
            && checker::taints(nerve_proto::Effect::Execute)
            && !sess.tainted()
        {
            sess.set_tainted();
            self.changed(Change::Sessions);
        }
    }

    /// The task that owns a call: it runs it until its result comes or it is
    /// stopped, counts it, and hands the result to the `execute` still
    /// waiting, or keeps it for the job's `job.status`. A stopped call drops
    /// its `invoke`, which tells the node to cancel it.
    async fn run_call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        id: &str,
        on: Option<Arc<Link>>,
        stop: tokio::sync::oneshot::Receiver<Stop>,
    ) {
        let started = Instant::now();
        let out = tokio::select! {
            r = self.call_inner(sess, route, args, id, on.as_ref()) => r.map_err(|CallError::Rpc(e)| e),
            s = stop => Err(s.unwrap_or(Stop::Abandoned).error()),
        };
        // Stats, taint and the log of a failure come with the end of the
        // call, also of one that became a job.
        self.count_call(sess, route, out.as_ref().err(), started);
        let handed = lock(&sess.jobs).finish(id, out, Instant::now());
        match handed {
            Some((waiter, out)) => {
                let _ = waiter.send(out);
            }
            None => {
                // A result kept for its job is forgotten after a while when
                // nobody reads it; the session may be gone by then.
                let weak = Arc::downgrade(sess);
                let id = id.to_string();
                tokio::spawn(async move {
                    tokio::time::sleep(jobs::KEEP_FOR).await;
                    if let Some(s) = weak.upgrade() {
                        lock(&s.jobs).expire(&id);
                        // Its output stream goes with it.
                        let stream = lock(&s.streams).of_job(&id);
                        if let Some(c) = stream {
                            c.close("its job was forgotten");
                        }
                    }
                });
            }
        }
    }

    /// A call the MCP side refused before `call` (its arguments do not fit
    /// the unit, or the unit is gone): counted and logged as a failed call
    /// of the unit, as when the node refused it, so the owner still sees a
    /// model that keeps getting its arguments wrong.
    pub fn refused(&self, sess: &Arc<Session>, route: &Route, e: RpcError) -> CallError {
        sess.calls.fetch_add(1, Ordering::SeqCst);
        self.count_call(sess, route, Some(&e), Instant::now());
        CallError::Rpc(e)
    }

    async fn call_inner(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        job: &str,
        on: Option<&Arc<Link>>,
    ) -> Result<Value, CallError> {
        let link = self.admit(sess, route, &args).await?;
        // A job's `invoke` id is its link's: on another link of the node it
        // would name some other call.
        if on.is_some_and(|on| !Arc::ptr_eq(on, &link)) {
            return Err(RpcError::invalid_args(
                "the job's call no longer runs on the node's link: the link to the node ended",
            )
            .into());
        }
        // A subscription's ring is on the link it was made on
        // (subscribe_events). The node may have come back on another link
        // while the checker was asked: there the events would reach no
        // ring, and no `unsub` would ever end the node's subscription.
        // The agent may have closed the stream meanwhile too, once its id
        // was given (Center::within_call_wait): then the link did not end.
        if route.kind == UnitKind::Event {
            let topic = format!("{}/{}", route.cap, route.action);
            let on = lock(&sess.streams).subscribed_on(&link, &topic);
            match on {
                streams::Subscribed::Here => {}
                streams::Subscribed::Closed => return Err(Stop::Closed.error().into()),
                streams::Subscribed::Elsewhere => {
                    return Err(RpcError::new(
                        ErrorCode::ConnectionLost,
                        "the link to the node ended",
                    )
                    .into());
                }
            }
        }
        let ctx = json!({"session": sess.id});
        lock(&sess.nodes).insert(route.node_id.clone());
        lock(&link.sessions).insert(sess.id.clone());
        // The agents' calls leave a few of the node's call places free, for
        // the owner's settings changes from the center and for a job's
        // `exec.signal`: jobs of many sessions could fill them all.
        let most = link.limits.calls as usize;
        let most = if on.is_some() {
            most
        } else {
            (most - calls_kept(most)).max(1)
        };
        // A program's state key is read with `get`, its event subscribed to
        // with `sub` (docs/dev/spec/harness.md §4.5); the node decides each
        // like a call.
        let (method, params) = match route.kind {
            UnitKind::State => (
                msg::method::GET,
                json!({"cap": route.cap, "keys": [route.action], "ctx": ctx}),
            ),
            UnitKind::Event => (
                msg::method::SUB,
                json!({"topics": [format!("{}/{}", route.cap, route.action)], "ctx": ctx}),
            ),
            UnitKind::Action | UnitKind::Stream => (
                msg::method::INVOKE,
                json!({"cap": route.cap, "action": route.action, "args": args, "ctx": ctx}),
            ),
        };
        let started = if method == msg::method::SUB {
            link.start_sub(params, most).await
        } else {
            link.start_within(method, params, most).await
        };
        let (id, rx) = started.map_err(|e| {
                if e.kind() != ErrorCode::Busy {
                    return e;
                }
                RpcError::new(
                    ErrorCode::Busy,
                    format!(
                        "node {} runs {} calls already, the most the center sends it for agents: try again when one ended, or stop a job of this session with job.cancel",
                        route.node_name, most
                    ),
                )
            })?;
        lock(&sess.jobs).sent(job, &link, id);
        let mut waiting = Waiting {
            link: Some(link),
            id,
        };
        let r = rx.await;
        waiting.link = None;
        let v = r
            .unwrap_or_else(|_| {
                Err(RpcError::new(
                    ErrorCode::ConnectionLost,
                    "the link to the node ended",
                ))
            })
            .map_err(CallError::Rpc)?;
        // The value of the key asked for, not the node's map of keys.
        if route.kind == UnitKind::State {
            return v.get(&route.action).cloned().ok_or_else(|| {
                RpcError::internal(format!(
                    "the node answered get without the state {}",
                    route.action
                ))
                .into()
            });
        }
        Ok(v)
    }

    /// Whether a call of `route` with `args` may go to its node now, and
    /// the link it goes on: the node is enabled and online, and the action
    /// checker (issue #17) lets it through; its refusal or allowance is in
    /// the center's audit.
    async fn admit(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: &Map<String, Value>,
    ) -> Result<Arc<Link>, CallError> {
        self.reachable(route)?;
        // The action checker (issue #17): the center's own gate, before the
        // node. It can only refuse; the node's policy still decides what it
        // lets through (design rule 1).
        let checker = self.checker();
        let (os, seen) = self.read(|s| {
            let n = s.nodes.get(&route.node_id);
            let os = n.map(|n| n.platform.clone()).unwrap_or_default();
            (os, n.map(|n| CheckerUnit::of(n, route)).unwrap_or_default())
        });
        let tainted = checker.taint_on() && sess.tainted();
        let paths = seen.paths(args);
        let target = checker_target(route, args, &paths);
        let endpoint = self.resolved_endpoint(&checker);
        let info = CallInfo {
            cap: &route.cap,
            action: &route.action,
            effect: route.effect,
            description: &seen.description,
            target: &target,
            paths: &paths,
            marked: &seen.marked,
            args,
            node_id: &route.node_id,
            os: &os,
            tainted,
        };
        match checker.check(&info, endpoint.as_ref()).await {
            Decision::Refuse {
                layer,
                scope,
                detail,
                message,
            } => {
                self.audit_checker(
                    sess,
                    route,
                    &target,
                    "forbidden",
                    layer,
                    scope,
                    &detail,
                    args,
                    &seen.marked,
                    &seen.params,
                );
                return Err(RpcError::forbidden(message).into());
            }
            Decision::Allowed {
                layer,
                scope,
                detail,
            } => {
                self.audit_checker(
                    sess,
                    route,
                    &target,
                    "allowed",
                    layer,
                    scope,
                    &detail,
                    args,
                    &seen.marked,
                    &seen.params,
                );
            }
            Decision::Pass => {}
        }
        // Looked up again: the node may have gone or come back on another
        // link while the model was asked.
        Ok(self
            .link(&route.node_id)
            .ok_or_else(|| offline(&route.node_name))?)
    }

    /// The link a call of `route` would go on now, before the checker: none
    /// for a disabled node, which is sent nothing, not even the session
    /// mark (`execute` refuses a disabled node before it gets here, but the
    /// switch may come in between), and none for a node that is offline. A
    /// call that cannot be sent is `unavailable`, not a checker refusal
    /// (with the model on and down, fail closed would say `forbidden`), and
    /// costs no model call.
    fn reachable(&self, route: &Route) -> Result<Arc<Link>, RpcError> {
        if self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled)) {
            return Err(RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is disabled in the center", route.node_name),
            ));
        }
        self.link(&route.node_id)
            .ok_or_else(|| offline(&route.node_name))
    }

    /// Room for one more stream in `sess`, or why there is none.
    fn stream_room(&self, sess: &Session) -> Result<(), String> {
        let (room, gone) = lock(&sess.streams).room(Instant::now());
        for c in gone {
            c.close("too many streams");
        }
        if !room {
            return Err(format!(
                "this session holds {} streams already, the most it may: close one with stream.close",
                streams::STREAMS_MAX
            ));
        }
        Ok(())
    }

    /// Adds the stream `id` of a program's unit `route` to `sess`, when
    /// there is room for it: taken in the one lock with the add
    /// ([`Streams::add_unit`](streams::Streams::add_unit)), so parallel
    /// `execute`s that all waited for the checker cannot pass the limit.
    /// `share`: the most of the node's stream places the session may hold,
    /// for a stream the node opens (a subscription takes none).
    fn add_unit_stream(
        &self,
        sess: &Session,
        route: &Route,
        id: &str,
        what: String,
        ring: Arc<Ring>,
        share: Option<usize>,
    ) -> Result<(), CallError> {
        let (added, gone) =
            lock(&sess.streams).add_unit(id, &route.node_id, what, ring, share, Instant::now());
        for c in gone {
            c.close("too many streams");
        }
        match added {
            Ok(()) => Ok(()),
            Err(streams::NotAdded::Ended) => Err(Stop::SessionEnded.error().into()),
            Err(streams::NotAdded::Full) => Err(RpcError::new(
                ErrorCode::Busy,
                format!(
                    "this session holds {} streams already, the most it may: close one with stream.close",
                    streams::STREAMS_MAX
                ),
            )
            .into()),
            Err(streams::NotAdded::Share) => Err(RpcError::new(
                ErrorCode::Busy,
                format!(
                    "this session holds {} streams on the node {} already, its share of the node's streams: close one with stream.close",
                    share.unwrap_or_default(),
                    route.node_name
                ),
            )
            .into()),
        }
    }

    /// `execute` of a program's event `route`: subscribes `sess` to it on
    /// its node (decided by the checker and the node like a call) and gives
    /// the id of the stream its events come in, one JSON line each, read
    /// with `stream.read` (docs/dev/spec/harness.md §4.5). The subscription
    /// ends with the stream: `stream.close`, the session's end, the link's.
    pub async fn subscribe_events(
        &self,
        sess: &Arc<Session>,
        route: &Route,
    ) -> Result<Opened, CallError> {
        self.stream_room(sess)
            .map_err(|why| self.refused(sess, route, RpcError::new(ErrorCode::Busy, why)))?;
        let topic = format!("{}/{}", route.cap, route.action);
        let id = streams::new_id();
        let ring = Arc::new(Ring::of(streams::Source::Events));
        let what = format!("the events of {}.{}", route.cap, route.action);
        let Some(link) = self.link(&route.node_id) else {
            let e = RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is offline", route.node_name),
            );
            return Err(self.refused(sess, route, e));
        };
        // The ring takes the topic's events before the node is asked: the
        // first may follow its answer at once. Until the checker and the
        // node took the subscription it keeps them from the session: they
        // are those another session's subscription of the topic brings, and
        // its id may be given before (Center::within_call_wait). Refused, it
        // ends without them.
        ring.hide();
        self.add_unit_stream(sess, route, &id, what, ring.clone(), None)
            .map_err(|CallError::Rpc(e)| self.refused(sess, route, e))?;
        link.subscribe(&topic, ring.clone());
        if !lock(&sess.streams).subscribed(&id, &link, &topic) {
            // Taken out meanwhile (the session ended, or the node was
            // disabled): its streams went without this subscription.
            link.unsubscribe(&topic, &ring);
            return Err(closed_while_opening(&ring).into());
        }
        let (c, s, r, rg) = (self.clone(), sess.clone(), route.clone(), ring.clone());
        let subscribe = async move {
            // Dropped, the open stops: its stream was closed (also when its
            // `execute` was cancelled, which closes it).
            match c
                .run_dropped(&s, &r, Map::new(), None, None, Stop::Closed)
                .await
            {
                Ran::Done(out) => out?,
                Ran::Job(_) => unreachable!("a call without a wait never becomes a job"),
            };
            rg.show();
            Ok(())
        };
        self.within_call_wait(sess, route, id, ring, subscribe)
            .await
    }

    /// `execute` of a program's stream `route` with `args`: opens it on its
    /// node (decided by the checker and the node like a call) and gives the
    /// id it is read by with `stream.read`. It ends when the program ends
    /// it, on `stream.close`, and with the session or the link.
    pub async fn open_unit_stream(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
    ) -> Result<Opened, CallError> {
        let started = Instant::now();
        // Looked at before the checker, which then costs no model call.
        self.stream_room(sess)
            .map_err(|why| self.refused(sess, route, RpcError::new(ErrorCode::Busy, why)))?;
        let link = self
            .reachable(route)
            .map_err(|e| self.refused(sess, route, e))?;
        let id = streams::new_id();
        let ring = Arc::new(Ring::of(streams::Source::Program));
        let what = format!("stream {}.{}", route.cap, route.action);
        // In the session before the checker decides, so its id can be
        // given once the call wait passed. The stream takes one of the
        // node's places, as a job's output stream does, so the session
        // keeps to its share of them and the other sessions find room.
        let share = streams::node_share(link.limits.streams);
        self.add_unit_stream(sess, route, &id, what, ring.clone(), Some(share))
            .map_err(|CallError::Rpc(e)| self.refused(sess, route, e))?;
        let (c, s, r) = (self.clone(), sess.clone(), route.clone());
        let (i, rg) = (id.clone(), ring.clone());
        let open = async move {
            s.calls.fetch_add(1, Ordering::SeqCst);
            let out = c.open_unit_stream_inner(&s, &r, args, &i, rg).await;
            c.count_call(
                &s,
                &r,
                out.as_ref().err().map(|CallError::Rpc(e)| e),
                started,
            );
            out
        };
        self.within_call_wait(sess, route, id, ring, open).await
    }

    async fn open_unit_stream_inner(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        id: &str,
        ring: Arc<Ring>,
    ) -> Result<(), CallError> {
        let link = self.admit(sess, route, &args).await?;
        // Looked at again, now that the checker decided: the owner may have
        // disabled the node meanwhile. A disable after this look finds the
        // stream in the session and closes it (`set_disabled`, which sets
        // the switch before it looks).
        let disabled = || {
            self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled))
                .then(|| {
                    RpcError::new(
                        ErrorCode::Unavailable,
                        format!("the node {} is disabled in the center", route.node_name),
                    )
                })
        };
        if let Some(e) = disabled() {
            return Err(e.into());
        }
        // The open takes one of the node's places until the node answers
        // it, and the session counts it till then, also once the stream is
        // closed or the open cancelled. Closed while the checker decided,
        // it is not opened: nobody would read it.
        let Some(place) = streams::Place::take(sess, id) else {
            return Err(closed_while_opening(&ring).into());
        };
        lock(&sess.nodes).insert(route.node_id.clone());
        lock(&link.sessions).insert(sess.id.clone());
        let params = json!({"cap": route.cap, "stream": route.action, "params": args,
                            "ctx": {"session": sess.id}});
        // A program may take its time to answer (the node waits for it up
        // to its own limit), unlike a node opening a command's output. The
        // `execute` does not wait that long (Center::within_call_wait).
        let wait = lock(&self.stream_waits).0.max(streams::PROGRAM_OPEN_WAIT);
        let sid = link
            .open_stream_in(params, ring.clone(), wait, Some(place))
            .await?;
        if !lock(&sess.streams).opened(id, &link, sid) {
            // Closed meanwhile (by the agent, the session's end, a
            // disable): so is the stream.
            if link.forget_stream(sid) {
                let l = link.clone();
                tokio::spawn(async move { l.close_stream(sid, "it was closed").await });
            }
            return Err(disabled()
                .unwrap_or_else(|| closed_while_opening(&ring))
                .into());
        }
        Ok(())
    }

    /// Runs `open`, which opens the stream `id` of `sess` on its node (a
    /// program's stream, or a subscription to a program's events; the
    /// stream is in the session already), in a task of its own, and waits
    /// for it at most the call wait: a harness gives up on a tool call
    /// after a while (docs/dev/spec/harness.md §4.4), and the checker and
    /// a program may each take longer. Once the wait passed, the stream's
    /// id is given while it still opens; if it then does not open, it ends
    /// with the words why, which `stream.read` gives. Dropped before (the
    /// harness cancelled its request), the open stops and the stream goes.
    async fn within_call_wait(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        id: String,
        ring: Arc<Ring>,
        open: impl Future<Output = Result<(), CallError>> + Send + 'static,
    ) -> Result<Opened, CallError> {
        let phase = Arc::new(Mutex::new(Phase::Waited));
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        // Nobody can name the stream before its id is given: if it does not
        // open by then, or its `execute` is cancelled, it goes again, so it
        // holds none of the session's places. Made here, not in the task:
        // the `execute` may be dropped before the task first ran.
        let adding = Adding {
            sess: sess.clone(),
            node_id: route.node_id.clone(),
            id: Some(id.clone()),
            why: "its execute was cancelled",
        };
        let task = {
            let (s, r, i, phase) = (sess.clone(), route.clone(), id.clone(), phase.clone());
            async move {
                let mut adding = adding;
                let out = open.await;
                let given = {
                    let mut p = lock(&phase);
                    if *p == Phase::Waited {
                        *p = Phase::Done;
                    }
                    *p == Phase::Given
                };
                match (&out, given) {
                    (Ok(()), _) => {
                        adding.keep();
                    }
                    (Err(CallError::Rpc(e)), true) => {
                        adding.keep();
                        let c = lock(&s.streams).not_opened(&i);
                        if let Some(c) = c {
                            c.close(&not_opened_words(&r, e));
                        }
                    }
                    (Err(_), false) => {
                        adding.why = "it did not open";
                        drop(adding);
                    }
                }
                let _ = tx.send(out);
            }
        };
        let handle = tokio::spawn(task);
        let mut stop = AbortOnDrop(Some(handle.abort_handle()));
        let out = match tokio::time::timeout(self.call_wait(), &mut rx).await {
            Ok(out) => out,
            Err(_) => {
                let done = {
                    let mut p = lock(&phase);
                    if *p == Phase::Waited {
                        *p = Phase::Given;
                    }
                    *p == Phase::Done
                };
                if !done {
                    // From now on the agent can close the stream, which
                    // stops its open (streams::Closer::close).
                    if let Some(h) = stop.0.take()
                        && !lock(&sess.streams).given(&id, h.clone())
                    {
                        h.abort();
                    }
                    return Ok(Opened { id, opening: true });
                }
                // It ended just now: its result follows at once.
                rx.await
            }
        };
        stop.0 = None;
        match out {
            Ok(Ok(())) => Ok(Opened { id, opening: false }),
            Ok(Err(e)) => Err(e),
            // The task went without a result: the runtime shuts down.
            Err(_) => Err(closed_while_opening(&ring).into()),
        }
    }

    /// Logs a call that was refused or that failed, with the reason.
    pub(super) fn log_failed_call(&self, route: &Route, e: &RpcError, took: Duration) {
        // A node the owner switched off answers `unavailable`.
        let disabled_here = e.kind() == ErrorCode::Unavailable
            && self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled));
        let what = format!("{}.{}", route.cap, route.action);
        let (level, line) = call_line(&what, e, took, disabled_here);
        self.note(level, Some(&route.node_id), line);
    }
}

/// What the checker matches on and the audit names: the command line for
/// `exec.run`, the path for an `fs` action, the path arguments of any other
/// action that takes paths (joined by `, `, as the node's audit names them),
/// else `<cap>.<action>`.
fn checker_target(
    route: &Route,
    args: &Map<String, Value>,
    paths: &[(PathMark, String)],
) -> String {
    match (route.cap.as_str(), route.action.as_str()) {
        ("exec", "run") => args
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        ("fs", _) => args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ if !paths.is_empty() => paths
            .iter()
            .map(|(_, p)| p.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => format!("{}.{}", route.cap, route.action),
    }
}

/// What the center's catalog says of the unit a call is for, as the action
/// checker is shown it. Empty for a unit the catalog no longer has: the
/// node refuses such a call anyway.
#[derive(Default)]
struct CheckerUnit {
    /// The action's own text and the capability's summary, on one line.
    description: String,
    /// The arguments the unit's schema marks as paths.
    marked: Vec<(String, PathMark)>,
    /// The unit's arguments schema, which tells the audit what a rule can
    /// name.
    params: Value,
}

impl CheckerUnit {
    fn of(n: &NodeRecord, route: &Route) -> CheckerUnit {
        let Some(u) = n.catalog.unit(&format!("{}.{}", route.cap, route.action)) else {
            return CheckerUnit::default();
        };
        // The unit's own description, when it has one, tells what this
        // action does; the capability's summary what it is for. The action
        // goes first: the model's state clips the end, and a long summary
        // must not push out the part that tells `unlock` from `status`. A
        // unit without a summary of its own carries its capability's
        // already.
        let cap = n
            .descriptor
            .as_ref()
            .and_then(|d| d.capability(&route.cap))
            .map(|c| catalog::described(&c.summary).to_string())
            .unwrap_or_default();
        let description = checker::unit_description(&route.action, &u.description, &cap);
        CheckerUnit {
            description,
            marked: nerve_proto::schema::path_args(&u.params),
            params: u.params.clone(),
        }
    }

    /// The values of the call's path arguments, in the schema's order. An
    /// argument that is absent or not a string names no path.
    fn paths(&self, args: &Map<String, Value>) -> Vec<(PathMark, String)> {
        self.marked
            .iter()
            .filter_map(|(field, mark)| Some((*mark, args.get(field)?.as_str()?.to_string())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::center::tests::{exec_route, lines, node_record, online, open, pair_body};

    /// A program's action that takes a path is audited by the checker under
    /// that path, as the node's audit names it, not as `cap.action`; the
    /// model and the blocklist see the path too, and the model is told what
    /// the capability says it does.
    #[tokio::test]
    async fn the_audit_target_of_a_path_capability_is_its_path() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"path": {"type": "string", "x-nerve-path": "write"},
                           "text": {"type": "string"}}});
        let mut notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        notes.provider = "notesd".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
            s.checker.allow_rules.push(AllowRule {
                rule: "notes.save".into(),
                node_id: None,
            });
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "notes".into(),
            action: "save".into(),
            effect: nerve_proto::Effect::Write,
            kind: nerve_proto::UnitKind::Action,
        };
        let save = |path: &str| {
            let mut m = Map::new();
            m.insert("path".into(), json!(path));
            m.insert("text".into(), json!("hello"));
            // Keys the schema does not name, which an open schema lets by.
            for i in 0..16 {
                m.insert(format!("a{i:02}"), json!(i));
            }
            m
        };
        // Into an ordinary file: the allow rule lets it go to the node, and
        // the audit names the file.
        let CallError::Rpc(e) = c
            .call(&sess, &route, save("/home/me/notes/today.md"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorCode::ConnectionLost, "{}", e.message);
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "allow rule");
        assert_eq!(last["target"], "/home/me/notes/today.md");
        // Its pin choices are the schema's arguments, not the junk keys.
        let kept: Vec<&String> = last["args"].as_object().unwrap().keys().collect();
        assert_eq!(kept, ["path", "text"]);
        // Into the SSH keys: the `fs.write` entry refuses it, under the path.
        let CallError::Rpc(e) = c
            .call(&sess, &route, save("/home/me/.ssh/authorized_keys"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "blocklist");
        assert_eq!(last["target"], "/home/me/.ssh/authorized_keys");
        // What the checker is shown of the unit.
        let seen = c.read(|s| CheckerUnit::of(&s.nodes["n1"], &route));
        assert_eq!(seen.description, "save: save it (notes summary)");
        assert_eq!(
            seen.paths(&save("/x")),
            vec![(PathMark::Write, "/x".to_string())]
        );
    }

    /// A unit without a summary of its own carries its capability's, which
    /// the checker shows once, however the summary is spaced.
    #[test]
    fn a_capability_summary_is_not_repeated_for_a_unit_without_its_own() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let mut lamp = cap(
            "lamp",
            "lamp",
            &[(
                "set",
                nerve_proto::Effect::Actuate,
                json!({"type": "object"}),
            )],
        );
        lamp.summary = "The office lamp.  Turns it on\n\nor off.".into();
        lamp.actions.get_mut("set").unwrap().summary = String::new();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![lamp]));
            s.nodes.insert("n1".into(), n);
        });
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "lamp".into(),
            action: "set".into(),
            effect: nerve_proto::Effect::Actuate,
            kind: nerve_proto::UnitKind::Action,
        };
        let seen = c.read(|s| CheckerUnit::of(&s.nodes["n1"], &route));
        assert_eq!(seen.description, "The office lamp.  Turns it on  or off.");
    }

    /// A capability summary longer than the model's state carries must not
    /// push out what the action itself does: that part goes first.
    #[test]
    fn a_long_capability_summary_does_not_crowd_out_the_actions_text() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let mut door = cap(
            "door",
            "door",
            &[(
                "unlock",
                nerve_proto::Effect::Actuate,
                json!({"type": "object"}),
            )],
        );
        door.summary = "The front door. ".repeat(30);
        door.actions.get_mut("unlock").unwrap().summary = "Unlocks it for a given time.".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![door]));
            s.nodes.insert("n1".into(), n);
        });
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "door".into(),
            action: "unlock".into(),
            effect: nerve_proto::Effect::Actuate,
            kind: nerve_proto::UnitKind::Action,
        };
        let seen = c.read(|s| CheckerUnit::of(&s.nodes["n1"], &route));
        assert!(seen.description.len() > checker::STATE_DESCRIPTION_MAX);
        let args = Map::new();
        let info = checker::CallInfo {
            cap: "door",
            action: "unlock",
            effect: nerve_proto::Effect::Actuate,
            description: &seen.description,
            target: "door.unlock",
            paths: &[],
            marked: &[],
            args: &args,
            node_id: "n1",
            os: "linux",
            tainted: false,
        };
        let state = checker::model_state(&info);
        assert!(
            state["description"]
                .as_str()
                .unwrap()
                .starts_with("unlock: Unlocks it for a given time."),
            "{}",
            state["description"]
        );
    }

    /// A call to a node that is offline or disabled is `unavailable` before
    /// the checker runs: with the model on, unreachable and failing closed,
    /// it is not refused as `forbidden`, and no checker decision is audited.
    /// Once the node is online the same call reaches the checker, which
    /// refuses and audits it as before.
    #[tokio::test]
    async fn an_offline_or_disabled_node_is_unavailable_before_the_checker() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.checker.model_on = true;
            s.checker.model.source = ModelSource::Endpoint;
            s.checker.model.endpoint_url = String::new();
        });
        c.rebuild_checker();
        let sess = c.new_session("test");
        let call = || {
            let mut args = Map::new();
            args.insert("command".into(), json!("echo hi > out.txt"));
            let (c, sess) = (&c, &sess);
            async move {
                let CallError::Rpc(e) = c.call(sess, &exec_route("n1"), args).await.unwrap_err();
                e
            }
        };
        let audited = || {
            c.audit()
                .iter()
                .filter(|e| e["by"] == "action checker")
                .count()
        };
        let e = call().await;
        assert_eq!(e.kind(), ErrorCode::Unavailable, "{}", e.message);
        assert!(e.message.contains("offline"), "{}", e.message);
        assert_eq!(audited(), 0);

        online(&c, "n1");
        c.update(|s| s.nodes.get_mut("n1").unwrap().disabled = true);
        let e = call().await;
        assert_eq!(e.kind(), ErrorCode::Unavailable, "{}", e.message);
        assert!(e.message.contains("disabled"), "{}", e.message);
        assert_eq!(audited(), 0);

        c.update(|s| s.nodes.get_mut("n1").unwrap().disabled = false);
        let e = call().await;
        assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
        assert!(e.message.contains("reach"), "{}", e.message);
        assert_eq!(audited(), 1);
    }

    /// A job's `exec.signal` goes only on the link its call runs on: the
    /// `invoke` id it names is that link's, and on the node's newer link it
    /// would name another call.
    #[tokio::test]
    async fn a_jobs_signal_goes_on_its_own_link_only() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut route = exec_route("n1");
        route.action = "signal".into();
        route.effect = nerve_proto::Effect::Actuate;
        let mut args = Map::new();
        args.insert("call".into(), json!(1));
        args.insert("signal".into(), json!("term"));
        let old = Arc::new(Link::for_test("n1"));
        let Ran::Done(Err(CallError::Rpc(e))) =
            c.run(&sess, &route, args.clone(), Some(old), None).await
        else {
            panic!("refused")
        };
        assert_eq!(e.kind(), ErrorCode::InvalidArgs, "{}", e.message);
        assert!(e.message.contains("no longer runs"), "{}", e.message);
        // On its own link it is sent (and this test link has lost it).
        let own = c.link("n1");
        let Ran::Done(Err(CallError::Rpc(e))) = c.run(&sess, &route, args, own, None).await else {
            panic!("sent")
        };
        assert_eq!(e.kind(), ErrorCode::ConnectionLost, "{}", e.message);
    }

    /// The result of a job nobody reads is forgotten after `KEEP_FOR` by a
    /// timer of its own: no later call of the session is needed for it. Its
    /// output stream goes with it.
    #[tokio::test(start_paused = true)]
    async fn an_unread_jobs_result_is_forgotten_without_another_call() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        // With no wait the call is a job before its task runs; it ends at
        // once, since this test link has lost it.
        let ran = c
            .run(
                &sess,
                &exec_route("n1"),
                Map::new(),
                None,
                Some(Duration::ZERO),
            )
            .await;
        let Ran::Job(job) = ran else {
            panic!("{ran:?}")
        };
        let ring = Arc::new(crate::streams::Ring::default());
        assert!(
            sess.streams
                .lock()
                .unwrap()
                .add("s-1", "n1", &job, ring.clone())
        );
        while sess.jobs.lock().unwrap().running() > 0 {
            tokio::task::yield_now().await;
        }
        let held = || sess.jobs.lock().unwrap().held();
        let streams = || sess.streams.lock().unwrap().len();
        assert_eq!((held(), streams()), (1, 1), "its result is kept");
        tokio::time::sleep(jobs::KEEP_FOR - Duration::from_secs(1)).await;
        assert_eq!((held(), streams()), (1, 1), "for ten minutes");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!((held(), streams()), (0, 0), "then forgotten");
        let r = ring.read(64);
        assert_eq!(r.why.as_deref(), Some("its job was forgotten"));
    }

    #[test]
    fn a_failed_call_says_what_it_was_and_why() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let id = nerve_transport::keys::node_id(&[7; 32]);
        let route = Route {
            node_id: id.clone(),
            node_name: "box-1".into(),
            cap: "fs".into(),
            action: "read".into(),
            effect: nerve_proto::Effect::Read,
            kind: nerve_proto::UnitKind::Action,
        };
        let took = Duration::from_millis(1500);
        let refusal = RpcError::forbidden("no allow rule matches /etc/hostname");
        c.log_failed_call(&route, &refusal, took);
        c.log_failed_call(
            &route,
            &RpcError::new(ErrorCode::Timeout, "the node did not answer in time"),
            Duration::from_secs(30),
        );
        c.log_failed_call(&route, &RpcError::internal("boom"), took);
        // Not a refusal, though the code is `unavailable`: the owner disabled it.
        c.set_disabled(&id, true).unwrap();
        c.log_failed_call(
            &route,
            &RpcError::new(
                ErrorCode::Unavailable,
                "the node box-1 is disabled in the center",
            ),
            took,
        );

        let got: Vec<(Level, String)> = lines(&c)
            .into_iter()
            .filter(|e| e.msg.starts_with("fs.read"))
            .map(|e| (e.level, e.msg))
            .collect();
        assert_eq!(
            got,
            [
                (
                    Level::Info,
                    "fs.read was refused (forbidden): no allow rule matches /etc/hostname"
                        .to_string()
                ),
                (
                    Level::Warn,
                    "fs.read failed (timeout) after 30 s: the node did not answer in time"
                        .to_string()
                ),
                (
                    Level::Error,
                    "fs.read failed (internal) after 1 s: boom".to_string()
                ),
                (
                    Level::Info,
                    "fs.read was refused (unavailable): the node box-1 is disabled in the center"
                        .to_string()
                ),
            ]
        );
    }
}
