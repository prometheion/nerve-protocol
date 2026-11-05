//! The decision-model client (step 3): one System One request per call
//! (docs/dev/action-checker.md).
//!
//! Decision models answer a typed yes/no question in one forward pass, no
//! tokens generated. `POST /v1/systemone` takes a `state` and a `questions`
//! map and returns, for a `noul` question, the probability that the answer is
//! `true`. The de-facto API is TypeSafe's; `llama-server` serves the same.
//!
//! The question is fixed by the center. The command or path only ever goes in
//! `state`, so a call cannot rephrase what is asked.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use nerve_proto::link::CenterUrl;

use super::config::ModelConfig;

/// Where the model is and how to reach it.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: CenterUrl,
    /// The bearer token, kept out of `state.json` and never shown back.
    pub token: Option<String>,
    /// The model name sent as `model`, if any.
    pub model: Option<String>,
    /// For the center's own local server: how much it reads within the
    /// timeout, so a call it cannot read in time is not sent. An endpoint
    /// has none, as the center does not know its machine.
    pub budget: Option<Arc<ReadBudget>>,
    /// For the center's own local server on Unix: the socket it listens on,
    /// in the state folder, in place of `url`'s address (which then only
    /// names the `Host`).
    pub socket: Option<PathBuf>,
}

impl Endpoint {
    /// Parses `url` (its path is fixed at `/v1/systemone`).
    pub fn parse(
        url: &str,
        token: Option<String>,
        model: Option<String>,
    ) -> Result<Endpoint, String> {
        let url = CenterUrl::parse(url)?;
        Ok(Endpoint {
            url,
            token: token.filter(|t| !t.is_empty()),
            model: model.filter(|m| !m.is_empty()),
            budget: None,
            socket: None,
        })
    }
}

/// A request of at most this many tokens is sent to the local server
/// whatever its measured speed: every release before #178 sent those (its
/// server read 512 tokens at a time), and sending ordinary calls keeps the
/// speed measured. Only a longer one is held to the timeout.
pub const ALWAYS_SENT_TOKENS: usize = 512;

/// Room in the context for the prompt template the server wraps around the
/// request (d1-2B's is about 30 tokens), as `/tokenize` counts the request's
/// text only.
const TEMPLATE_TOKENS: usize = 64;

/// The local server's speed, and with it the longest call it can judge in
/// time (#178). A decision model reads the whole prompt in one batch, which
/// the server does not stop when the center gives up on it: a call too long
/// to read within the timeout would hold the server's one slot past it, and
/// every other session's call queued behind it would time out too (refused,
/// or let through unjudged with allow-and-log). So the client counts the
/// request's tokens first (`/tokenize`, which the server answers at once)
/// and does not send one it cannot read in time; that call is refused as
/// too long, also with allow-and-log, so padding a call does not get it past
/// the model.
///
/// The client also holds the server's one slot itself (its `slot`):
/// a call is sent only once the call before it was answered, so a call
/// waits here, not in the server, and one that would not be read within
/// what is left of its timeout is not sent. Each call was estimated as if
/// it ran alone, and the calls ahead of it (of any session) decided whether
/// it timed out (review T1 of #178).
///
/// A token of a long prompt takes longer to read than one of a short prompt
/// (attention reads the whole prompt): d1-2B read 8,500 tokens at 1.5 times
/// a short call's time per token (review round 4). So the time is estimated
/// as a short call's time per token for `n * (1 + n / growth)` tokens, and a
/// call's speed is taken the same way.
#[derive(Debug)]
pub struct ReadBudget {
    /// The server's context, in tokens.
    context: usize,
    /// The milliseconds per token of a short call assumed until the server
    /// answered one: the model's speed on 2 vCPUs
    /// (`install::ModelPin::read_ms`).
    assumed: f64,
    /// The prompt length at which a token takes twice as long to read as in
    /// a short call (`install::ModelPin::read_growth`).
    growth: f64,
    state: Mutex<Flights>,
    /// The server's one slot (`-np 1`): held by the call it reads, until it
    /// answered, also after the caller gave up on it.
    slot: Arc<tokio::sync::Semaphore>,
}

/// A count in flight ([`ReadBudget::counting`]).
struct Counting<'a>(&'a ReadBudget);

impl Drop for Counting<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().counting -= 1;
    }
}

/// How many recent speeds are kept: the slowest of them counts, so one fast
/// call on a quiet machine does not raise the budget for a busy one.
const SPEEDS_KEPT: usize = 8;

#[derive(Debug, Default)]
struct Flights {
    /// Milliseconds per token of a short call, of the last calls that ran
    /// alone.
    speeds: VecDeque<f64>,
    in_flight: usize,
    /// Calls started so far, so a call can tell another one overlapped it.
    started: u64,
    /// The server went away while it read a call (the connection ended
    /// without an answer), and the process that replaced it has not come up
    /// yet.
    died_on_call: bool,
    /// How many times the mark was set, so a count can tell that the mark
    /// is newer than the count it is answering (review T4 of #178).
    marks: u64,
    /// Processes started so far, and the one the mark was set in.
    process: u64,
    marked_in: u64,
    /// The supervisor counts the process as ready. Set and cleared with its
    /// phase, under the phase's lock.
    ready: bool,
    /// Counts (`/tokenize`) in flight. A count is a request to the server
    /// too: one that ends the process has the same effect as a read that
    /// does (review T6 of #178).
    counting: usize,
    /// Calls go to the server only once the supervisor has checked that the
    /// process answering is the one it started ([`ReadBudget::vet_calls`]):
    /// on a port, where another process may answer.
    vet: bool,
    /// This process was checked to be the server's own.
    vetted: bool,
}

impl Flights {
    fn mark(&mut self) {
        self.died_on_call = true;
        self.marks += 1;
        self.marked_in = self.process;
    }
}

impl ReadBudget {
    pub fn new(context: u32, assumed_ms_per_token: f64, growth: f64) -> ReadBudget {
        ReadBudget {
            context: context as usize,
            assumed: assumed_ms_per_token,
            growth,
            state: Mutex::default(),
            slot: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    /// Forgets the speeds learned, for a restarted server: the new process
    /// may read at another speed than the one before it (it lost the GPU it
    /// had, the machine swaps after an out-of-memory kill), so until it
    /// answered a call it is held to the assumed speed again. A call the old
    /// process took teaches nothing (review T1 of #178).
    pub(super) fn restart(&self) {
        let mut s = self.state.lock().unwrap();
        s.speeds.clear();
        s.started += 1;
        s.process += 1;
        s.ready = false;
        s.vetted = false;
    }

    /// Calls are held back from now on until each process is
    /// [`vetted`](Self::vetted): the server listens on a port, where a
    /// process that took it after a crash would be sent the key and the
    /// text of every call the window of a restart lets through.
    pub(super) fn vet_calls(&self) {
        self.state.lock().unwrap().vet = true;
    }

    /// The process answering is the server's own (it refuses a key it was
    /// not given, and said it listens): calls may be sent to it.
    pub(super) fn vetted(&self) {
        self.state.lock().unwrap().vetted = true;
    }

    /// Whether a call may be sent: always, but on a port it has to wait for
    /// the current process to be [`vetted`](Self::vetted).
    fn may_send(&self) -> bool {
        let s = self.state.lock().unwrap();
        !s.vet || s.vetted
    }

    /// Whether the server went away while it read a call, and its
    /// replacement is not up yet. The calls in that window are refused as
    /// lost: the server is not just down, it ended on a call, and that call
    /// may be why (review T2 of #178).
    pub(crate) fn died_on_call(&self) -> bool {
        self.state.lock().unwrap().died_on_call
    }

    /// Whether a call is in the server (it holds the slot).
    fn reading(&self) -> bool {
        self.slot.available_permits() == 0
    }

    /// Whether a failure to reach the server may be the end of one that had
    /// a call: a call is in it, or one was and marked it. The slot is read
    /// first: `read_alone` marks before it frees the slot, so a caller that
    /// finds the slot free also finds the mark (review T3 of #178).
    fn lost_a_call(&self) -> bool {
        self.reading() || self.died_on_call()
    }

    /// The server process ended. If a call was in it, it ended on that call,
    /// and the mark is set here without waiting for the call's own task to
    /// see its connection end: the calls in between would meet a server
    /// that is neither ready nor marked (review T3 of #178).
    pub(super) fn ended(&self) {
        let mut s = self.state.lock().unwrap();
        s.ready = false;
        s.vetted = false;
        if self.reading() || s.counting > 0 {
            s.mark();
        }
    }

    /// A process ended before the supervisor counted it ready. A call that
    /// was sent to it (the server answers before the next probe) may be why:
    /// the mark is set as in [`ended`](Self::ended). Otherwise it is a
    /// restart that did not come up, and the mark of an earlier process
    /// goes: the model is down, which is not the same as ended on a call
    /// (review T3 and T4 of #178).
    pub(super) fn ended_before_ready(&self) {
        let mut s = self.state.lock().unwrap();
        s.vetted = false;
        if self.reading() || s.counting > 0 {
            s.mark();
        } else if s.marked_in < s.process {
            s.died_on_call = false;
        }
    }

    /// The process is ready: calls are sent to it, and the mark of the
    /// process before it no longer stands. A mark of this process stays: a
    /// call may have ended it between its answer to the probe and this step
    /// (a failed connect while it runs is cleared by the next count, now
    /// that it is ready; review T5 of #178).
    pub(super) fn became_ready(&self) {
        let mut s = self.state.lock().unwrap();
        s.ready = true;
        if s.marked_in < s.process {
            s.died_on_call = false;
        }
    }

    /// The process was stopped on purpose (an install's swap, Remove, a
    /// model or device switch). It is not up any more, and a count it cut
    /// off meets a model that is down, not one that failed (review T6 of
    /// #178). A call in it marks itself.
    pub(super) fn stopped(&self) {
        let mut s = self.state.lock().unwrap();
        s.ready = false;
        s.vetted = false;
    }

    /// A count is in flight until the returned guard drops.
    fn counting(&self) -> Counting<'_> {
        self.state.lock().unwrap().counting += 1;
        Counting(self)
    }

    /// A count failed. If the supervisor counts the process ready it is
    /// running and failed on the count, or has just ended on it: the call is
    /// refused (`true`), and when the connection was lost the process is
    /// marked, as an end on a read is, since the supervisor may have missed
    /// the end that this count's guard would have marked (review T5 and T6
    /// of #178). Decided under one lock, so a stop or an end in between is
    /// seen.
    pub(super) fn count_failed(&self, connection_lost: bool) -> bool {
        let mut s = self.state.lock().unwrap();
        if !s.ready {
            return false;
        }
        if connection_lost {
            s.mark();
        }
        true
    }

    /// The mark no longer stands: there is no process, and the model is
    /// down, which is not the same as ended on a call (review T3 of #178).
    pub(super) fn settled(&self) {
        self.state.lock().unwrap().died_on_call = false;
    }

    /// How often the mark was set. A count reads it before it asks the
    /// server and hands it to [`counted`](Self::counted).
    fn marks(&self) -> u64 {
        self.state.lock().unwrap().marks
    }

    /// A count the server answered, after `marks` marks: if the server is
    /// ready and nothing marked it since the count began, a mark left by a
    /// connection that failed on a server that went on running is stale.
    /// Not before the supervisor counts the process ready: the restarted
    /// process answers before its next probe, and the calls in between would
    /// meet a server that is neither ready nor marked (review T4 of #178).
    fn counted(&self, marks: u64) {
        let mut s = self.state.lock().unwrap();
        if s.ready && s.marks == marks {
            s.died_on_call = false;
        }
    }

    /// Marks the server as gone with a call, as a call that lost its
    /// connection does.
    #[cfg(test)]
    pub(crate) fn die_on_call(&self) {
        self.state.lock().unwrap().mark();
    }

    /// Holds the budget's lock, so a step that needs it waits.
    #[cfg(test)]
    pub(super) fn hold_state(&self) -> impl Sized + '_ {
        self.state.lock().unwrap()
    }

    /// Takes the slot, as a call in the server does.
    #[cfg(test)]
    pub(crate) fn hold_slot(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.slot
            .clone()
            .try_acquire_owned()
            .expect("the slot is free")
    }

    /// Lands a call of `tokens` that took `ms`, as an answered one does.
    #[cfg(all(test, unix))]
    pub(super) fn learn(&self, tokens: usize, ms: f64) {
        self.take_off().land(tokens, ms);
    }

    /// Waits until no call holds the slot.
    #[cfg(test)]
    pub(super) async fn idle(&self) {
        let _ = self.slot.acquire().await;
    }

    /// The context, the assumed speed and the growth it was built with.
    #[cfg(test)]
    pub(super) fn built_with(&self) -> (usize, f64, f64) {
        (self.context, self.assumed, self.growth)
    }

    /// A prompt of `tokens`, in tokens of a short call's speed.
    fn work(&self, tokens: usize) -> f64 {
        let n = tokens as f64;
        n * (1.0 + n / self.growth)
    }

    /// Milliseconds per token of a short call: the slowest recent call's,
    /// or the assumed speed before the first.
    pub fn ms_per_token(&self) -> f64 {
        let s = self.state.lock().unwrap();
        s.speeds
            .iter()
            .copied()
            .reduce(f64::max)
            .unwrap_or(self.assumed)
    }

    /// The milliseconds a request of `tokens` takes to read, with the
    /// prompt template the server reads too.
    fn read_ms(&self, tokens: usize) -> f64 {
        self.work(tokens + TEMPLATE_TOKENS) * self.ms_per_token()
    }

    /// Whether a request of `tokens` may be sent with `timeout_ms`.
    fn admit(&self, tokens: usize, timeout_ms: u64) -> Result<(), ModelError> {
        if tokens + TEMPLATE_TOKENS > self.context {
            return Err(ModelError::TooLong(format!(
                "about {tokens} tokens, more than the model's context of {} holds",
                self.context
            )));
        }
        if tokens <= ALWAYS_SENT_TOKENS {
            return Ok(());
        }
        let ms = self.read_ms(tokens);
        if ms <= timeout_ms as f64 {
            return Ok(());
        }
        Err(ModelError::TooLong(format!(
            "about {tokens} tokens, which the model reads here in about {:.0} s, longer than the timeout of {} ms",
            ms / 1000.0,
            timeout_ms
        )))
    }

    /// Whether a request of `tokens` that got the slot at once is read in
    /// the `left` of its timeout (counting its tokens took the rest). A call
    /// of up to 512 tokens is sent whatever the speed, as with [`admit`].
    fn admit_in(&self, tokens: usize, left: Duration) -> Result<(), ModelError> {
        if tokens <= ALWAYS_SENT_TOKENS {
            return Ok(());
        }
        let ms = self.read_ms(tokens);
        if ms <= left.as_millis() as f64 {
            return Ok(());
        }
        Err(ModelError::TooLong(format!(
            "about {tokens} tokens, which the model reads here in about {:.1} s, more than the {} ms left of the timeout after counting them",
            ms / 1000.0,
            left.as_millis()
        )))
    }

    /// Whether a request of `tokens` that waited `waited` for the slot is
    /// read in the `left` of its timeout. Unlike a call sent at once, one of
    /// up to 512 tokens is held to it too: it would only time out in the
    /// server, holding the slot for the next.
    fn admit_after_wait(
        &self,
        tokens: usize,
        waited: Duration,
        left: Duration,
    ) -> Result<(), ModelError> {
        let ms = self.read_ms(tokens);
        if ms <= left.as_millis() as f64 {
            return Ok(());
        }
        Err(ModelError::Busy(format!(
            "it read the calls sent before this one for {} ms, and this one of about {tokens} tokens takes it about {:.1} s, more than the {} ms left of the timeout",
            waited.as_millis(),
            ms / 1000.0,
            left.as_millis()
        )))
    }

    /// Marks a call as sent; its [`Flight`] takes its speed when it lands.
    fn take_off(&self) -> Flight<'_> {
        let mut s = self.state.lock().unwrap();
        let alone = s.in_flight == 0;
        s.in_flight += 1;
        s.started += 1;
        Flight {
            budget: self,
            alone,
            number: s.started,
        }
    }
}

/// A call on its way to the local server. Only a call that ran alone gives
/// a speed: one queued behind another (one slot) would count its wait.
struct Flight<'a> {
    budget: &'a ReadBudget,
    alone: bool,
    number: u64,
}

impl Flight<'_> {
    /// Takes the speed of a call whose prompt of `tokens` took `ms` (or,
    /// timed out, at least that long).
    fn land(&self, tokens: usize, ms: f64) {
        self.take(tokens, ms, false);
    }

    /// Like [`land`](Self::land) for a call the server did not answer even
    /// long after its timeout ([`STUCK_AFTER_TIMEOUTS`]). That speed is
    /// only a lower bound on the real one, and a call of up to 512 tokens
    /// was never checked against the timeout, so nothing else keeps it from
    /// being faster than the server: it never makes the budget faster, or a
    /// timeout the owner raised afterwards would turn it into a budget far
    /// above what the server reads (review round 5 of #178).
    fn land_timed_out(&self, tokens: usize, ms: f64) {
        self.take(tokens, ms, true);
    }

    /// The server went away while it read this call. A call that a restart
    /// came between does not say anything about the new process.
    fn died(&self) {
        let mut s = self.budget.state.lock().unwrap();
        if s.started == self.number {
            s.mark();
        }
    }

    fn take(&self, tokens: usize, ms: f64, timed_out: bool) {
        let work = self.budget.work(tokens);
        let mut s = self.budget.state.lock().unwrap();
        if self.alone && s.started == self.number && tokens > 0 {
            let mut speed = ms / work;
            if timed_out {
                let slowest = s.speeds.iter().copied().reduce(f64::max);
                speed = speed.max(slowest.unwrap_or(self.budget.assumed));
            }
            if s.speeds.len() == SPEEDS_KEPT {
                s.speeds.pop_front();
            }
            s.speeds.push_back(speed);
        }
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.budget.state.lock().unwrap().in_flight -= 1;
    }
}

/// Why a model call did not give an answer. An unreachable model and a bad
/// answer are a reason to refuse (fail closed) unless the owner switched that
/// off; the others are refused always.
#[derive(Debug)]
pub enum ModelError {
    /// The model could not be reached (DNS, connection, TLS, timeout).
    Unreachable(String),
    /// It answered, but not with a usable decision (bad JSON, missing field,
    /// an HTTP error such as 401, 422, 429 or 529).
    Bad(String),
    /// The call was not sent: the local model cannot read it within the
    /// timeout, or its context does not hold it ([`ReadBudget`]). Refused
    /// whatever the owner chose for an unreachable model.
    TooLong(String),
    /// The call was not sent: the local model was still reading the calls
    /// sent before it, and would not have read it within its timeout.
    /// Refused whatever the owner chose, as those calls are agents' calls
    /// too, and enough of them would otherwise get one through unjudged.
    Busy(String),
    /// The local model took the call and gave no answer within the timeout,
    /// or none that could be read. Refused whatever the owner chose for an
    /// unreachable model: the server was running (it had just counted the
    /// call's tokens), so the call itself may be why: its read took longer
    /// than the timeout, or the server failed on it (review T1 of #178).
    NotJudged(String),
    /// The call was not sent: the running local model failed to count its
    /// tokens. Refused whatever the owner chose, as the call may be why. A
    /// longer timeout does not change that (review T6 of #178).
    NotCounted(String),
    /// The call was not sent: the local model could not be reached while an
    /// earlier call was in it, so it most likely ended on that call and is
    /// starting again (or it stopped answering). Refused whatever the owner
    /// chose for an unreachable model, as that call may be why it ended
    /// (review T3 of #178).
    Lost(String),
}

impl ModelError {
    /// The reason alone, without the words of its kind.
    fn reason(&self) -> &str {
        match self {
            ModelError::Unreachable(e)
            | ModelError::Bad(e)
            | ModelError::TooLong(e)
            | ModelError::Busy(e)
            | ModelError::NotJudged(e)
            | ModelError::NotCounted(e)
            | ModelError::Lost(e) => e,
        }
    }
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::Unreachable(e) => {
                write!(f, "the action checker's model cannot be reached: {e}")
            }
            ModelError::Bad(e) => {
                write!(f, "the action checker's model gave no usable answer: {e}")
            }
            ModelError::TooLong(e) => {
                write!(
                    f,
                    "the call is too long for the action checker's model: {e}"
                )
            }
            ModelError::Busy(e) => {
                write!(f, "the action checker's model is busy: {e}")
            }
            ModelError::NotJudged(e) => {
                write!(
                    f,
                    "the action checker's model took the call but did not judge it: {e}"
                )
            }
            ModelError::NotCounted(e) => {
                write!(
                    f,
                    "the action checker's model failed to count the call: {e}"
                )
            }
            ModelError::Lost(e) => {
                write!(
                    f,
                    "the action checker's model was lost while it read an earlier call: {e}"
                )
            }
        }
    }
}

/// The largest answer body the client reads.
const MAX_BODY: usize = 64 * 1024;

/// The largest `/tokenize` answer for `text`: a token covers at least one
/// byte, and an id of the models' vocabularies is at most six digits and a
/// comma. A fixed limit would let a long enough question (one kept from an
/// endpoint source has no cap) make the answer unreadable, which is an
/// unreachable model, and allow-and-log lets that through unjudged while the
/// model runs (review T2 of #178).
fn tokens_body_limit(text: &str) -> usize {
    (8 * text.len() + 1024).max(MIN_TOKENS_BODY)
}

/// Room for the answer of a short text, which is mostly its framing.
const MIN_TOKENS_BODY: usize = 128 * 1024;

/// Asks the model whether the call described by `state` is dangerous, with the
/// question built from `cfg`. Returns the `noul` probability (0..=1).
pub async fn ask(endpoint: &Endpoint, cfg: &ModelConfig, state: Value) -> Result<f64, ModelError> {
    let mut body = json!({
        "state": state,
        "questions": {
            "danger": {
                "type": "noul",
                "instructions": cfg.instructions,
                "criteria": {"true": cfg.criteria_true, "false": cfg.criteria_false},
            }
        }
    });
    if let Some(m) = &endpoint.model {
        body["model"] = json!(m);
    }
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    if let Some(budget) = &endpoint.budget {
        return ask_local(endpoint, budget, body, timeout, cfg.timeout_ms).await;
    }
    let value = tokio::time::timeout(
        timeout,
        request(
            endpoint,
            "/v1/systemone",
            &body,
            timeout + Duration::from_secs(5),
            MAX_BODY,
        ),
    )
    .await
    .map_err(|_| ModelError::Unreachable(format!("timed out after {} ms", cfg.timeout_ms)))??;
    parse_noul(&value)
}

/// A call the local server took and has not answered after this many
/// timeouts is given up, and the slot freed: the server is taken to be
/// stuck. A call it reads is answered long before (the budget sends none it
/// estimates over the timeout).
const STUCK_AFTER_TIMEOUTS: u32 = 10;

/// [`ask`] for the center's own server: counted, held to the budget, and sent
/// once the slot is free.
async fn ask_local(
    endpoint: &Endpoint,
    budget: &Arc<ReadBudget>,
    body: Value,
    timeout: Duration,
    timeout_ms: u64,
) -> Result<f64, ModelError> {
    // On a port nothing is sent, not even the count, before the supervisor
    // has checked who answers: the window of a restart would otherwise hand
    // the key and the call's text to whatever took the port.
    if !budget.may_send() {
        let why = "the new server is not known to be the center's own yet, so nothing is sent"
            .to_string();
        return Err(if budget.died_on_call() {
            ModelError::Lost(format!(
                "the model ended while it read an earlier call and is starting again ({why})"
            ))
        } else {
            ModelError::Unreachable(why)
        });
    }
    // The timeout covers the wait for the slot as well as the read.
    let deadline = tokio::time::Instant::now() + timeout;
    // The count is also the probe of a server marked as ended on a call: one
    // that answers is up (a mark set by a failed connect while it ran
    // clears here), and one that does not is refused as lost, not sent. The
    // same when a call is in the server and it cannot be reached: it has
    // just ended on that call, whether or not the center saw it yet. The
    // center keeps the endpoint for the window, so the call does not meet
    // "not running" and its allow-and-log (review T2 and T3 of #178).
    let marks = budget.marks();
    let counting = budget.counting();
    let counted = tokenize(endpoint, &body.to_string(), timeout).await;
    // The guard lives through the arms below, so an end the supervisor sees
    // meanwhile marks the process (review T6 of #178).
    let tokens = match counted {
        Ok(tokens) => {
            budget.counted(marks);
            tokens
        }
        Err(e) if budget.lost_a_call() => {
            return Err(ModelError::Lost(format!(
                "the model ended while it read an earlier call and is starting again, or stopped answering ({})",
                e.reason()
            )));
        }
        // A server counted ready that fails the count is running and failed
        // on this call's text, or has just ended: either way the call is not
        // judged, and a model that is down is another case (review T5 of
        // #178).
        Err(e) if budget.count_failed(matches!(e, ModelError::Unreachable(_))) => {
            return Err(ModelError::NotCounted(format!(
                "the model, which is running, did not count the call's tokens ({})",
                e.reason()
            )));
        }
        Err(e) => return Err(e),
    };
    drop(counting);
    budget.admit(tokens, timeout_ms)?;
    let slot = match budget.slot.clone().try_acquire_owned() {
        Ok(slot) => {
            // Counting the tokens took part of the timeout.
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            budget.admit_in(tokens, left)?;
            slot
        }
        Err(_) => {
            let waiting = Instant::now();
            let slot = match tokio::time::timeout_at(deadline, budget.slot.clone().acquire_owned())
                .await
            {
                Ok(Ok(slot)) => slot,
                _ => {
                    return Err(ModelError::Busy(format!(
                        "it read the calls sent before this one for the whole timeout of {timeout_ms} ms"
                    )));
                }
            };
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            budget.admit_after_wait(tokens, waiting.elapsed(), left)?;
            slot
        }
    };
    // A call that held the slot, or one answered while this call was
    // counted, may have ended the server: it marks the process before it
    // frees the slot, so a call woken by that end finds the mark. It is
    // compared with the marks from before the count, not from after it: a
    // mark set while the count was in flight is one this call has to see
    // too. Whatever took the old port meanwhile is sent nothing, not the
    // key and not the text; this is the gate at the top for a call that was
    // already past it.
    if budget.marks() != marks || !budget.may_send() {
        return Err(ModelError::Lost(
            "the model ended while it read an earlier call and is starting again".into(),
        ));
    }
    let (done, answer) = tokio::sync::oneshot::channel();
    tokio::spawn(read_alone(
        endpoint.clone(),
        budget.clone(),
        body,
        tokens,
        timeout,
        slot,
        done,
    ));
    // From here on the server has the call, so whatever keeps it from
    // judging the call is refused, also with allow-and-log: the call's own
    // read took longer than the timeout, or the server failed on it (review
    // T1 of #178).
    let value = match tokio::time::timeout_at(deadline, answer).await {
        Ok(Ok(Ok(value))) => value,
        Ok(Ok(Err(e))) => return Err(ModelError::NotJudged(e.reason().into())),
        Ok(Err(_)) => {
            return Err(ModelError::NotJudged(
                "the read ended without an answer".into(),
            ));
        }
        Err(_) => {
            return Err(ModelError::NotJudged(format!(
                "no answer within the timeout of {timeout_ms} ms"
            )));
        }
    };
    parse_noul(&value).map_err(|e| ModelError::NotJudged(e.reason().into()))
}

/// Sends a call to the local server and reads its answer, holding the slot
/// until the server answered, also once the caller gave up at its timeout:
/// the server reads a call it took to the end, so the next call waits for
/// it here and not in the server past its own timeout, and the speed is
/// learned from the whole read rather than from a lower bound.
async fn read_alone(
    endpoint: Endpoint,
    budget: Arc<ReadBudget>,
    body: Value,
    tokens: usize,
    timeout: Duration,
    slot: tokio::sync::OwnedSemaphorePermit,
    done: tokio::sync::oneshot::Sender<Result<Value, ModelError>>,
) {
    let stuck = timeout * STUCK_AFTER_TIMEOUTS;
    let flight = budget.take_off();
    let sent = Instant::now();
    let answer = tokio::time::timeout(
        stuck,
        // The read's own limit sits past the outer one, so it is always the
        // outer that ends a stuck call: a read that gave up first would
        // surface as an error and teach the budget nothing.
        request(
            &endpoint,
            "/v1/systemone",
            &body,
            stuck + Duration::from_secs(5),
            MAX_BODY,
        ),
    )
    .await;
    let ms = sent.elapsed().as_secs_f64() * 1000.0;
    let answer = match answer {
        // The speed comes from the tokens the server says it read, not
        // from the count above: that count is only an upper bound, and
        // a call padded so that it is counted several times what the
        // server reads (a run of `<`) would teach a speed several times
        // too fast, which lets a long call through afterwards (review
        // round 4 of #178). An answer that does not say teaches nothing.
        Ok(Ok(value)) => {
            if let Some(read) = read_tokens(&value) {
                flight.land(read, ms);
            }
            Ok(value)
        }
        Ok(Err(e)) => {
            // A refused connection or one that ended without an answer is
            // the server gone (an HTTP error status is not).
            if matches!(e, ModelError::Unreachable(_)) {
                flight.died();
            }
            Err(e)
        }
        // A stuck call took at least this long for at most the tokens
        // counted (and the template); that is its speed's lower bound, so
        // a machine slower than assumed is learned from it.
        Err(_) => {
            flight.land_timed_out(tokens + TEMPLATE_TOKENS, ms);
            Err(ModelError::Unreachable(format!(
                "no answer within {} ms",
                stuck.as_millis()
            )))
        }
    };
    // Landed and free before the caller hears of it, so its next call sees
    // both.
    drop(flight);
    drop(slot);
    let _ = done.send(answer);
}

/// The tokens of `text` as the decision server reads them, by the model's
/// own tokenizer (`POST /tokenize`).
///
/// `/tokenize` reads a special token's spelling in the text (`<|im_start|>`)
/// as one token by default, but the decision server does not let the call's
/// text hold special tokens: d1-2B's breaks each spelling with a zero-width
/// space, Kev-4B's rewrites `<|x|>` to `<¦x¦>`, and either is several plain
/// tokens. So the text is counted as plain text, and each `<` (every special
/// spelling of both models starts with one) counts one more token for the
/// break, which is at most one (measured for every spelling of both models,
/// review round 3 of #178). Otherwise a call padded with spellings counts as
/// a fraction of what the server reads, and gets past the budget.
async fn tokenize(endpoint: &Endpoint, text: &str, wait: Duration) -> Result<usize, ModelError> {
    let body = json!({ "content": text, "parse_special": false });
    let value = tokio::time::timeout(
        wait,
        request(endpoint, "/tokenize", &body, wait, tokens_body_limit(text)),
    )
    .await
    .map_err(|_| ModelError::Unreachable("counting the tokens timed out".into()))??;
    value
        .get("tokens")
        .and_then(Value::as_array)
        .map(|tokens| tokens.len() + text.matches('<').count())
        .ok_or_else(|| ModelError::Bad("/tokenize answered without tokens".into()))
}

/// Sends one request to `path` and returns its JSON body, mapping HTTP
/// errors.
async fn request(
    endpoint: &Endpoint,
    path: &str,
    body: &Value,
    wait: Duration,
    max_body: usize,
) -> Result<Value, ModelError> {
    let url = &endpoint.url;
    let mut io = connect(endpoint).await.map_err(ModelError::Unreachable)?;
    let path = format!("{}{path}", url.base);
    let req = request_bytes(&url.authority(), &path, endpoint.token.as_deref(), body);
    use tokio::io::AsyncWriteExt;
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| ModelError::Unreachable(e.to_string()))?;
    // The model may think longer than the transport's usual head timeout (a
    // 4B model on a small CPU); the caller's own timeout around this call is
    // the limit, so this read does not cut it short at 15 s.
    let resp = nerve_transport::http::read_client_response(&mut io, max_body, wait)
        .await
        .map_err(ModelError::Unreachable)?;
    match resp.status {
        200 => serde_json::from_slice(&resp.body)
            .map_err(|e| ModelError::Bad(format!("not JSON: {e}"))),
        401 => Err(ModelError::Bad(
            "401: the model endpoint refused the token".into(),
        )),
        422 => Err(ModelError::Bad(
            "422: the model rejected the request".into(),
        )),
        429 => Err(ModelError::Bad(
            "429: the model endpoint is rate-limiting".into(),
        )),
        501 => Err(ModelError::Bad(
            "501: the loaded model is not a decision model (/v1/models has no \"decisions\")"
                .into(),
        )),
        529 => Err(ModelError::Bad(
            "529: the model endpoint is overloaded".into(),
        )),
        s => Err(ModelError::Bad(format!("HTTP {s}"))),
    }
}

/// Opens a connection to the endpoint: its socket, or its address.
async fn connect(endpoint: &Endpoint) -> Result<nerve_transport::net::BoxIo, String> {
    #[cfg(unix)]
    if let Some(p) = &endpoint.socket {
        let s = tokio::net::UnixStream::connect(p)
            .await
            .map_err(|e| format!("{}: {e}", p.display()))?;
        return Ok(Box::new(s));
    }
    let url = &endpoint.url;
    let proxy = if url.tls {
        nerve_transport::net::Proxy::from_env(&url.host)?
    } else {
        None
    };
    nerve_transport::net::open(url, None, proxy.as_ref()).await
}

/// `GET /v1/models`, with `token` as the bearer token when given.
async fn get_models(
    endpoint: &Endpoint,
    token: Option<&str>,
) -> Result<nerve_transport::http::ClientResponse, ModelError> {
    let url = &endpoint.url;
    let mut io = connect(endpoint).await.map_err(ModelError::Unreachable)?;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET {}/v1/models HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\n{auth}Connection: close\r\nUser-Agent: nerve/{}\r\n\r\n",
        url.base,
        url.authority(),
        env!("CARGO_PKG_VERSION")
    );
    use tokio::io::AsyncWriteExt;
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| ModelError::Unreachable(e.to_string()))?;
    nerve_transport::http::read_client_response(
        &mut io,
        MAX_BODY,
        nerve_transport::http::HEAD_TIMEOUT,
    )
    .await
    .map_err(ModelError::Unreachable)
}

/// Whether the server at `endpoint` refuses `/v1/models` to a token it was
/// not given: the center's own server, started with a key of its own, does.
/// One that answers anyone is not that server, but a process that took its
/// port. A server that is still loading (503) says neither yet.
pub async fn refuses_other_keys(endpoint: &Endpoint) -> Result<bool, ModelError> {
    let other = nerve_transport::keys::random_token(32);
    let resp = get_models(endpoint, Some(&other)).await?;
    if resp.status == 503 {
        return Err(ModelError::Unreachable(
            "the server is still loading".into(),
        ));
    }
    Ok(resp.status == 401)
}

/// The HTTP/1.1 request text, with the bearer token when there is one.
fn request_bytes(host: &str, path: &str, token: Option<&str>, body: &Value) -> String {
    let body = body.to_string();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\nUser-Agent: nerve-center/{}\r\n\r\n{body}",
        body.len(),
        env!("CARGO_PKG_VERSION"),
    )
}

/// The tokens the server read for an answer (`usage.input_tokens`).
fn read_tokens(v: &Value) -> Option<usize> {
    v.get("usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_u64)
        .map(|n| n as usize)
}

/// Pulls `answers.danger.noul` out of a System One response.
fn parse_noul(v: &Value) -> Result<f64, ModelError> {
    v.get("answers")
        .and_then(|a| a.get("danger"))
        .and_then(|d| d.get("noul"))
        .and_then(Value::as_f64)
        .filter(|p| p.is_finite() && (0.0..=1.0).contains(p))
        .ok_or_else(|| ModelError::Bad(format!("no noul answer in {v}")))
}

/// Reads `GET /v1/models` and reports whether the model is a decision model
/// (`architecture.output_modalities` contains `"decisions"`). Used before the
/// center trusts a local or endpoint model.
pub async fn is_decision_model(endpoint: &Endpoint) -> Result<bool, ModelError> {
    let resp = get_models(endpoint, endpoint.token.as_deref()).await?;
    if resp.status != 200 {
        return Err(ModelError::Bad(format!(
            "/v1/models answered HTTP {}",
            resp.status
        )));
    }
    let v: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| ModelError::Bad(format!("/v1/models is not JSON: {e}")))?;
    let has = v
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|m| {
            m.get("architecture")
                .and_then(|a| a.get("output_modalities"))
                .and_then(Value::as_array)
                .is_some_and(|m| m.iter().any(|v| v.as_str() == Some("decisions")))
        });
    Ok(has)
}

/// A loopback stand-in for the local server, for tests: `/tokenize` counts
/// `tokens` for every plain text, `/v1/systemone` answers 0.01 after `delay`,
/// having read as many.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The server's endpoint (without a budget) and how many decision
    /// requests it was sent.
    pub(crate) fn server(tokens: usize, delay: Duration) -> (Endpoint, Arc<AtomicUsize>) {
        server_reading(tokens, Some(tokens), delay)
    }

    /// The same, but its answers say it read `read` tokens (`None`: they do
    /// not say).
    pub(crate) fn server_reading(
        tokens: usize,
        read: Option<usize>,
        delay: Duration,
    ) -> (Endpoint, Arc<AtomicUsize>) {
        serve(
            tokens,
            read,
            delay,
            Reply::Noul(json!(0.01)),
            Duration::ZERO,
        )
    }

    /// The same, but `/tokenize` answers only after `count_delay`, as it does
    /// on a loaded machine.
    pub(crate) fn server_counting_slowly(
        tokens: usize,
        count_delay: Duration,
    ) -> (Endpoint, Arc<AtomicUsize>) {
        serve(
            tokens,
            Some(tokens),
            Duration::ZERO,
            Reply::Noul(json!(0.01)),
            count_delay,
        )
    }

    /// The same, but it answers every decision request with an HTTP 500,
    /// as a server that failed on the call does.
    pub(crate) fn server_failing(tokens: usize) -> (Endpoint, Arc<AtomicUsize>) {
        serve(
            tokens,
            Some(tokens),
            Duration::ZERO,
            Reply::Status(500),
            Duration::ZERO,
        )
    }

    /// The same, but its decision answers hold `noul` as the probability.
    pub(crate) fn server_answering(tokens: usize, noul: Value) -> (Endpoint, Arc<AtomicUsize>) {
        serve(
            tokens,
            Some(tokens),
            Duration::ZERO,
            Reply::Noul(noul),
            Duration::ZERO,
        )
    }

    /// The same, but it ends the connection of every decision request
    /// without an answer, as a server that was killed does.
    pub(crate) fn server_hanging_up(tokens: usize) -> (Endpoint, Arc<AtomicUsize>) {
        serve(
            tokens,
            Some(tokens),
            Duration::ZERO,
            Reply::HangUp,
            Duration::ZERO,
        )
    }

    /// How the fake answers `/tokenize`.
    #[derive(Clone)]
    enum Count {
        Tokens,
        /// This HTTP status, with an empty JSON object.
        Status(u16),
        /// No answer: the connection ends.
        HangUp,
    }

    /// The same, but `/tokenize` answers with this HTTP status.
    pub(crate) fn server_failing_to_count(status: u16) -> (Endpoint, Arc<AtomicUsize>) {
        serve_counting(Count::Status(status), 100)
    }

    /// The same, but it ends the connection of every `/tokenize` request
    /// without an answer.
    pub(crate) fn server_hanging_up_on_count() -> (Endpoint, Arc<AtomicUsize>) {
        serve_counting(Count::HangUp, 100)
    }

    /// The same, but it ends the connection only after `delay`, so the
    /// process can be reported ended while the count is in flight.
    pub(crate) fn server_hanging_up_on_count_after(
        delay: Duration,
    ) -> (Endpoint, Arc<AtomicUsize>) {
        serve_with(
            100,
            Some(100),
            Duration::ZERO,
            Reply::Noul(json!(0.01)),
            delay,
            Count::HangUp,
        )
    }

    fn serve_counting(count: Count, tokens: usize) -> (Endpoint, Arc<AtomicUsize>) {
        serve_with(
            tokens,
            Some(tokens),
            Duration::ZERO,
            Reply::Noul(json!(0.01)),
            Duration::ZERO,
            count,
        )
    }

    /// How the fake answers a decision request.
    #[derive(Clone)]
    enum Reply {
        /// A 200 answer with this `noul`.
        Noul(Value),
        /// This HTTP status, with the same body.
        Status(u16),
        /// No answer: the connection ends.
        HangUp,
    }

    fn serve(
        tokens: usize,
        read: Option<usize>,
        delay: Duration,
        reply: Reply,
        count_delay: Duration,
    ) -> (Endpoint, Arc<AtomicUsize>) {
        serve_with(tokens, read, delay, reply, count_delay, Count::Tokens)
    }

    fn serve_with(
        tokens: usize,
        read: Option<usize>,
        delay: Duration,
        reply: Reply,
        count_delay: Duration,
        count: Count,
    ) -> (Endpoint, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        // Each connection in a thread of its own, as llama-server answers
        // `/tokenize` while it reads a call.
        let answer = move |mut c: std::net::TcpStream,
                           counter: Arc<AtomicUsize>,
                           reply: Reply,
                           count: Count| {
            let mut got = Vec::new();
            let mut buf = [0u8; 8192];
            // The request is small; read until its body is in.
            while let Ok(n) = c.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got);
                let done = text.split_once("\r\n\r\n").is_some_and(|(head, body)| {
                    let want = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: ")?.parse().ok())
                        .unwrap_or(0usize);
                    body.len() >= want
                });
                if n == 0 || done {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&got);
            let (status, body) = if text.starts_with("POST /tokenize ") {
                match count {
                    Count::HangUp => {
                        std::thread::sleep(count_delay);
                        return;
                    }
                    Count::Status(status) => {
                        let _ = write!(
                            c,
                            "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                        );
                        return;
                    }
                    Count::Tokens => {}
                }
                // Like llama-server, it reads special spellings as one
                // token each unless asked not to; here as one for the
                // whole text.
                let plain = text.contains(r#""parse_special":false"#);
                // An id of six digits, as the models' vocabularies have.
                let tokens = vec![100_000; if plain { tokens } else { 1 }];
                std::thread::sleep(count_delay);
                (200, json!({ "tokens": tokens }).to_string())
            } else {
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(delay);
                let (status, noul) = match reply {
                    Reply::Noul(noul) => (200, noul),
                    Reply::Status(status) => (status, json!(0.01)),
                    Reply::HangUp => return,
                };
                let mut answer = json!({"answers": {"danger": {"type": "noul", "noul": noul}}});
                if let Some(read) = read {
                    answer["usage"] = json!({ "input_tokens": read, "output_tokens": 0 });
                }
                (status, answer.to_string())
            };
            let _ = write!(
                c,
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        };
        std::thread::spawn(move || {
            for c in listener.incoming().flatten() {
                let counter = counter.clone();
                let reply = reply.clone();
                let count = count.clone();
                std::thread::spawn(move || answer(c, counter, reply, count));
            }
        });
        let ep = Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None).unwrap();
        (ep, asked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn with_timeout(timeout_ms: u64) -> ModelConfig {
        ModelConfig {
            timeout_ms,
            ..Default::default()
        }
    }

    /// A budget whose calls take as long per token at any length, so the
    /// tests of everything else can count in plain sums.
    fn linear(context: u32, ms_per_token: f64) -> ReadBudget {
        ReadBudget::new(context, ms_per_token, f64::INFINITY)
    }

    /// The local server is not sent a call it cannot read within the
    /// timeout (#178): before its first answer at the assumed speed, then at
    /// the slowest speed it measured. A call of up to 512 tokens is sent
    /// whatever the speed, and one over the context never.
    #[tokio::test]
    async fn a_call_the_local_model_cannot_read_in_time_is_not_sent() {
        let budget = Arc::new(linear(4096, 20.0));
        let local = |tokens| {
            let (ep, asked) = fake::server(tokens, Duration::ZERO);
            let ep = Endpoint {
                budget: Some(budget.clone()),
                ..ep
            };
            (ep, asked)
        };
        // 1,000 tokens and the template's 64 at 20 ms each are 21 s, over
        // the 12 s timeout.
        let (ep, asked) = local(1000);
        let e = ask(&ep, &with_timeout(12_000), json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("about 21 s")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        // 512 tokens at 20 ms are 10.2 s, over a 10 s timeout, and are sent
        // even so; this one is answered at once, so the speed measured is
        // well under 20 ms per token.
        let (ep, asked) = local(ALWAYS_SENT_TOKENS);
        assert_eq!(
            ask(&ep, &with_timeout(10_000), json!({})).await.unwrap(),
            0.01
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // Now the 1,000 tokens fit.
        let (ep, asked) = local(1000);
        assert_eq!(
            ask(&ep, &with_timeout(12_000), json!({})).await.unwrap(),
            0.01
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // A call over the context (with room for the template) is never
        // sent, however fast the model.
        let (ep, asked) = local(4096 - TEMPLATE_TOKENS + 1);
        let e = ask(&ep, &with_timeout(12_000), json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("context")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        // An endpoint has no budget: the center sends it everything.
        let (ep, asked) = fake::server(100_000, Duration::ZERO);
        assert_eq!(
            ask(&ep, &with_timeout(12_000), json!({})).await.unwrap(),
            0.01
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    /// A call padded with special-token spellings is counted as the server
    /// reads it, where each spelling is broken into plain tokens, not as
    /// `/tokenize` counts it by default, one token per spelling (review
    /// round 3 of #178).
    #[tokio::test]
    async fn a_call_padded_with_special_spellings_is_counted_as_plain_text() {
        let budget = Arc::new(linear(4096, 20.0));
        let (ep, asked) = fake::server(300, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget),
            ..ep
        };
        // 300 plain tokens and 300 spellings, one more token each for the
        // break: 600 (and the template) at 20 ms are 13 s, over the 8 s
        // timeout.
        let padded = "<|img_row_10_col_10|>".repeat(300);
        let e = ask(&ep, &with_timeout(8000), json!({ "target": padded }))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("about 600 tokens")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    /// The slowest of the recent calls sets the speed, a timed-out call
    /// counts as at least its timeout, and a call that overlapped another
    /// one gives none (it may have waited for the server's one slot).
    #[test]
    fn the_budget_keeps_the_slowest_speed_of_the_calls_that_ran_alone() {
        let b = linear(8192, 20.0);
        assert_eq!(b.ms_per_token(), 20.0);
        b.take_off().land(1000, 5000.0);
        b.take_off().land(1000, 2000.0);
        assert_eq!(b.ms_per_token(), 5.0);
        assert!(b.admit(2000, 12_000).is_ok());
        assert!(b.admit(2500, 12_000).is_err());
        // Two at once: neither counts.
        let first = b.take_off();
        let second = b.take_off();
        second.land(100, 9000.0);
        first.land(100, 9000.0);
        drop((first, second));
        assert_eq!(b.ms_per_token(), 5.0);
        // A call that started while one was still in the air does not count
        // either, even after that one landed.
        let first = b.take_off();
        let second = b.take_off();
        first.land(100, 100.0);
        drop(first);
        second.land(100, 9000.0);
        drop(second);
        assert_eq!(b.ms_per_token(), 5.0);
        // Only the last few speeds are kept.
        for _ in 0..SPEEDS_KEPT {
            b.take_off().land(1000, 3000.0);
        }
        assert_eq!(b.ms_per_token(), 3.0);
    }

    /// A call that timed out is still read to the end, and its speed is
    /// learned from the whole read: the next long one is not sent at the
    /// speed assumed before (#178).
    #[tokio::test]
    async fn a_timed_out_call_slows_the_budget_down() {
        // 1,000 tokens and the template at the assumed 0.5 ms are 532 ms,
        // inside 600.
        let budget = Arc::new(linear(8192, 0.5));
        assert!(budget.admit(1000, 600).is_ok());
        let (ep, asked) = fake::server(1000, Duration::from_millis(1500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let e = ask(&ep, &with_timeout(600), json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::NotJudged(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // The server answers after 1.5 s, having read 1,000 tokens.
        budget.idle().await;
        assert!(budget.ms_per_token() >= 1.4, "{}", budget.ms_per_token());
        assert!(budget.admit(1000, 600).is_err());
    }

    /// A call the server did not answer even long after its timeout, a
    /// short one too, which was never checked against the timeout, teaches
    /// only a lower bound: a short timeout must not leave a budget that a
    /// raised one turns into a stall (review round 5 of #178).
    #[tokio::test]
    async fn timed_out_short_calls_do_not_make_the_budget_faster() {
        // Assumed 20 ms per token; a 300-token call given up after ten
        // timeouts of 100 ms would land about 2.7 ms per token.
        let budget = Arc::new(linear(100_000, 20.0));
        let (ep, _) = fake::server(300, Duration::from_millis(1500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        ask(&ep, &with_timeout(100), json!({})).await.unwrap_err();
        budget.idle().await;
        assert!(budget.ms_per_token() >= 20.0, "{}", budget.ms_per_token());
        // 2,500 tokens take 50 s at 20 ms; a raised timeout of 12 s refuses.
        assert!(budget.admit(2500, 12_000).is_err());
    }

    /// The local server reads one call at a time, and every call queued
    /// behind a slow one would time out in it: a call waits for the call
    /// before it in the client, and is refused as busy, without being sent,
    /// when that one is not answered within its own timeout. The one in the
    /// server is refused as not judged, not passed as an unreachable model
    /// (review T1 of #178).
    #[tokio::test]
    async fn a_call_behind_one_the_model_still_reads_is_not_sent() {
        let budget = Arc::new(linear(8192, 0.1));
        let (ep, asked) = fake::server(100, Duration::from_millis(1500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let cfg = with_timeout(600);
        let (first, second) = tokio::join!(
            ask(&ep, &cfg, json!({"command": "first"})),
            ask(&ep, &cfg, json!({"command": "second"}))
        );
        let mut errors = [first.unwrap_err(), second.unwrap_err()];
        errors.sort_by_key(|e| matches!(e, ModelError::Busy(_)));
        assert!(
            matches!(&errors[0], ModelError::NotJudged(_)),
            "{}",
            errors[0]
        );
        assert!(
            matches!(&errors[1], ModelError::Busy(why) if why.contains("whole timeout")),
            "{}",
            errors[1]
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    /// A call that got the slot after waiting is sent only when it is read
    /// in what is left of its timeout, a short one too: sent, it would only
    /// time out in the server and hold the slot for the next (review T1 of
    /// #178).
    #[tokio::test]
    async fn a_call_that_waited_is_held_to_the_rest_of_its_timeout() {
        // Each call takes the fake a second; 1,000 tokens and the template
        // at 1 ms are about 1.06 s, inside 2.5 s. The second call is sent
        // with 1.5 s left, the third would have 0.5 s.
        let budget = Arc::new(linear(8192, 1.0));
        let (ep, asked) = fake::server(1000, Duration::from_millis(1000));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let cfg = with_timeout(2500);
        let (a, b, c) = tokio::join!(
            ask(&ep, &cfg, json!({"command": "a"})),
            ask(&ep, &cfg, json!({"command": "b"})),
            ask(&ep, &cfg, json!({"command": "c"}))
        );
        let results = [a, b, c];
        let judged = results.iter().filter(|r| r.is_ok()).count();
        let busy = results
            .iter()
            .filter(
                |r| matches!(r, Err(ModelError::Busy(why)) if why.contains("left of the timeout")),
            )
            .count();
        assert_eq!((judged, busy), (2, 1), "{results:?}");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    /// A call that gets the slot at once is held to what is left of its
    /// timeout after `/tokenize` answered, as one that waited is (review T2
    /// of #178).
    #[tokio::test]
    async fn a_call_is_held_to_the_time_left_after_counting_its_tokens() {
        // 1,000 tokens and the template at 1 ms are about 1.06 s, inside the
        // 1.5 s timeout, but counting them took 0.6 s of it.
        let budget = Arc::new(linear(8192, 1.0));
        let (ep, asked) = fake::server_counting_slowly(1000, Duration::from_millis(600));
        let ep = Endpoint {
            budget: Some(budget),
            ..ep
        };
        let e = ask(&ep, &with_timeout(1500), json!({"command": "a"}))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("left of the timeout")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    /// A question far over the cap makes `/tokenize` answer with more than
    /// a fixed limit: it is still counted, and the call refused as too long
    /// (not as an unreachable model, which allow-and-log lets through) (review
    /// T2 of #178).
    #[tokio::test]
    async fn a_long_question_is_counted_and_refused_as_too_long() {
        let budget = Arc::new(linear(12_288, 0.1));
        // 80,000 tokens of a six-digit id are over half a megabyte.
        let (ep, asked) = fake::server(80_000, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget),
            ..ep
        };
        let e = ask(
            &ep,
            &with_timeout(12_000),
            json!({"command": "a".repeat(80_000)}),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, ModelError::TooLong(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    /// An endpoint on a port nothing listens on, with `budget`: a server that
    /// is down.
    fn nothing_listening(budget: &Arc<ReadBudget>) -> Endpoint {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        Endpoint {
            budget: Some(budget.clone()),
            ..Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None).unwrap()
        }
    }

    /// A server that ended without answering a call it took is gone, not
    /// slow: the calls after it are refused as lost, not sent, until the
    /// restarted server is up (review T2 and T3 of #178). An HTTP error is
    /// not that.
    #[tokio::test]
    async fn a_server_that_ended_on_a_call_gets_no_calls_until_it_is_back() {
        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server_hanging_up(100);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let cfg = with_timeout(2000);
        let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::NotJudged(_)), "{e}");
        assert!(budget.died_on_call());
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // The restarting process does not answer yet.
        let restarting = nothing_listening(&budget);
        let e = ask(&restarting, &cfg, json!({})).await.unwrap_err();
        assert!(
            matches!(&e, ModelError::Lost(why) if why.contains("ended")),
            "{e}"
        );
        assert!(budget.died_on_call());
        // It is up: a call is counted and sent. The budget is not ready
        // here, so the mark stays until the supervisor counts the process
        // ready.
        let _ = ask(&ep, &cfg, json!({})).await;
        assert_eq!(asked.load(Ordering::SeqCst), 2);

        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, _) = fake::server_failing(100);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::NotJudged(_)), "{e}");
        assert!(!budget.died_on_call());
    }

    /// A server that ends while a call is in it closes the connections of
    /// the calls counting their tokens at that moment, and of those that
    /// come before the center has seen it end: they cannot reach it, and are
    /// refused as lost, not reported as an unreachable model, which
    /// allow-and-log lets through. With no call in the server it is just
    /// down (review T3 of #178).
    #[tokio::test]
    async fn a_call_that_cannot_reach_a_server_with_a_call_in_it_is_lost() {
        let budget = Arc::new(linear(12_288, 0.1));
        let down = nothing_listening(&budget);
        let cfg = with_timeout(2000);
        let reading = budget.hold_slot();
        let e = ask(&down, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Lost(_)), "{e}");
        // Nothing is in the server and nothing marked it: it is just down.
        drop(reading);
        let e = ask(&down, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Unreachable(_)), "{e}");
    }

    /// A mark set by a connection that failed while the server went on
    /// running (the center ran out of file descriptors, say) does not refuse
    /// calls until the next restart: a server that counts a call's tokens is
    /// up, and the mark is gone (review T3 of #178).
    #[tokio::test]
    async fn a_mark_on_a_server_that_answers_is_cleared_by_the_next_call() {
        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server(100, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        budget.became_ready();
        budget.die_on_call();
        let _ = ask(&ep, &with_timeout(2000), json!({})).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(!budget.died_on_call());
    }

    /// A restarted process answers a count before the supervisor counts it
    /// ready (its next probe is up to half a second later). Until then the
    /// mark stays, or the calls in between would meet a server that is
    /// neither ready nor marked and be let through by allow-and-log (review
    /// T4 of #178).
    #[tokio::test]
    async fn a_count_before_the_server_is_ready_leaves_the_mark() {
        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server(100, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        budget.die_on_call();
        let _ = ask(&ep, &with_timeout(2000), json!({})).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(budget.died_on_call());
    }

    /// On a port nothing is sent to a process the supervisor has not checked
    /// is the server's own: not the count, not the call. The window after an
    /// end on a call is refused as lost without a connection, and a process
    /// that ends loses the check again.
    #[tokio::test]
    async fn on_a_port_a_call_waits_for_the_process_to_be_vetted() {
        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server(100, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        budget.vet_calls();
        budget.restart();
        budget.die_on_call();
        let cfg = with_timeout(2000);
        let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Lost(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        // Unmarked, it is a server that is down.
        budget.settled();
        let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Unreachable(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        budget.vetted();
        ask(&ep, &cfg, json!({})).await.expect("vetted: sent");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // The process ends: the next one is checked again.
        budget.ended();
        let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Unreachable(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // On a socket nothing waits.
        let socket = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server(100, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(socket.clone()),
            ..ep
        };
        socket.restart();
        ask(&ep, &cfg, json!({})).await.expect("sent");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    /// A call that waits for the slot behind the one that ends the server
    /// is sent nothing once it has it: the end is marked before the slot is
    /// free, and whatever took the old port meanwhile sees neither the key
    /// nor the text (review round 5 of the center's sign-in).
    #[tokio::test]
    async fn a_call_waiting_for_the_slot_is_not_sent_once_the_server_ended_on_the_call_before() {
        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server(100, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        budget.vet_calls();
        budget.restart();
        budget.vetted();
        budget.became_ready();
        let reading = budget.hold_slot();
        let cfg = with_timeout(5000);
        let (waiting, ()) = tokio::join!(ask(&ep, &cfg, json!({"command": "second"})), async {
            // The count has been answered and the call waits for the slot.
            tokio::time::sleep(Duration::from_millis(400)).await;
            // The call in the server lost its connection: the mark first,
            // then the slot, as `read_alone` does it.
            budget.die_on_call();
            drop(reading);
        });
        let e = waiting.unwrap_err();
        assert!(matches!(e, ModelError::Lost(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 0, "nothing was sent");
    }

    /// A call whose count is answered while the server ends on another call
    /// is sent nothing, though the slot is free by the time it asks for it:
    /// the mark that came during its own count counts too (review round 6 of
    /// the center's sign-in).
    #[tokio::test]
    async fn a_call_is_not_sent_once_the_server_ended_on_a_call_during_its_count() {
        let budget = Arc::new(linear(12_288, 0.1));
        let (ep, asked) = fake::server_counting_slowly(100, Duration::from_millis(500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        budget.vet_calls();
        budget.restart();
        budget.vetted();
        budget.became_ready();
        let cfg = with_timeout(5000);
        let (second, ()) = tokio::join!(ask(&ep, &cfg, json!({"command": "second"})), async {
            // The count is in flight: another call, which has already freed
            // the slot, marks the process as its connection ends.
            tokio::time::sleep(Duration::from_millis(150)).await;
            budget.die_on_call();
        });
        let e = second.unwrap_err();
        assert!(matches!(e, ModelError::Lost(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 0, "nothing was sent");
    }

    /// A count clears only a mark that was there when it began, and only
    /// while the server is ready: one that ends the server as the count is
    /// answered, or after the server left the ready phase, does not undo the
    /// mark of that end (review T4 of #178).
    #[test]
    fn a_count_leaves_the_mark_of_an_end_it_did_not_see() {
        let budget = linear(12_288, 0.1);
        budget.became_ready();
        let began = budget.marks();
        budget.die_on_call();
        budget.counted(began);
        assert!(budget.died_on_call(), "marked after the count began");
        // A later count sees the mark and clears it, the server being ready.
        budget.counted(budget.marks());
        assert!(!budget.died_on_call());
        // The server ended with a call in it: not ready any more.
        let reading = budget.hold_slot();
        budget.ended();
        budget.counted(budget.marks());
        assert!(budget.died_on_call(), "marked, and not ready");
        drop(reading);
    }

    /// The Ready step clears the mark of the process before it, not one the
    /// process it makes ready set itself: a call may have ended it between
    /// its answer to the probe and that step, and the end is then not seen
    /// again (review T5 of #178).
    #[test]
    fn the_ready_step_keeps_the_mark_of_its_own_process() {
        let budget = linear(12_288, 0.1);
        budget.restart();
        budget.die_on_call();
        budget.became_ready();
        assert!(budget.died_on_call(), "marked in this process");
        // The next count clears it, the budget being ready.
        budget.counted(budget.marks());
        assert!(!budget.died_on_call());
        // A mark of the process before goes with the Ready step.
        budget.die_on_call();
        budget.restart();
        budget.became_ready();
        assert!(!budget.died_on_call(), "marked in the process before");
    }

    /// A server counted ready that fails the count is not down: it failed on
    /// the call's text, or has just ended. The call is refused as not
    /// counted (it was not sent), whatever the owner chose for an unreachable model. A server
    /// not counted ready is down, and that case goes on as it was (review T5
    /// of #178).
    #[tokio::test]
    async fn a_ready_server_that_fails_the_count_does_not_judge_the_call() {
        let cfg = with_timeout(2000);
        for (name, (ep, asked)) in [
            ("an error status", fake::server_failing_to_count(500)),
            ("a hang-up", fake::server_hanging_up_on_count()),
        ] {
            let budget = Arc::new(linear(12_288, 0.1));
            let ep = Endpoint {
                budget: Some(budget.clone()),
                ..ep
            };
            let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
            assert!(
                matches!(e, ModelError::Unreachable(_) | ModelError::Bad(_)),
                "{name}, not ready: {e}"
            );
            budget.became_ready();
            let e = ask(&ep, &cfg, json!({})).await.unwrap_err();
            assert!(matches!(e, ModelError::NotCounted(_)), "{name}: {e}");
            assert_eq!(asked.load(Ordering::SeqCst), 0, "{name}: nothing is sent");
            // A lost connection may be an end, and marks the process; an
            // error status is a server that went on running (review T6).
            assert_eq!(budget.died_on_call(), name == "a hang-up", "{name}");
        }
    }

    /// A count that ends the process is a request that ended it, whoever
    /// sees the end first (review T6 of #178). The supervisor first: the
    /// guard of the count in flight marks, and the call is lost.
    #[tokio::test]
    async fn a_count_the_supervisor_saw_end_the_server_marks_the_process() {
        let budget = Arc::new(linear(12_288, 0.1));
        budget.became_ready();
        let (ep, _) = fake::server_hanging_up_on_count_after(Duration::from_millis(300));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let cfg = with_timeout(2000);
        let call = tokio::spawn({
            let ep = ep.clone();
            async move { ask(&ep, &cfg, json!({})).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        budget.ended();
        budget.restart();
        let e = call.await.unwrap().unwrap_err();
        assert!(matches!(e, ModelError::Lost(_)), "{e}");
        assert!(
            budget.died_on_call(),
            "the restart window is refused as lost"
        );
    }

    /// A stop is not an end on a call: a count it cuts off meets a model
    /// that is down (review T6 of #178).
    #[tokio::test]
    async fn a_count_cut_off_by_a_stop_meets_a_model_that_is_down() {
        let budget = Arc::new(linear(12_288, 0.1));
        budget.became_ready();
        let (ep, _) = fake::server_hanging_up_on_count_after(Duration::from_millis(300));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let cfg = with_timeout(2000);
        let call = tokio::spawn({
            let ep = ep.clone();
            async move { ask(&ep, &cfg, json!({})).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        budget.stopped();
        let e = call.await.unwrap().unwrap_err();
        assert!(matches!(e, ModelError::Unreachable(_)), "{e}");
        assert!(!budget.died_on_call());
    }

    /// The speed is learned from the tokens the server read, not from the
    /// count the call was let through with, which only bounds them: a call
    /// padded with plain `<` counts about four times what d1-2B reads, and
    /// such calls taught a speed fast enough to let a call through that held
    /// the server for a minute (review round 4 of #178). An answer that does
    /// not say what it read teaches nothing.
    #[tokio::test]
    async fn the_budget_learns_its_speed_from_the_tokens_the_server_read() {
        let budget = Arc::new(linear(100_000, 1.0));
        // Counted 2,000 tokens, read 500, in 250 ms: 0.5 ms per token read.
        let (ep, asked) = fake::server_reading(2000, Some(500), Duration::from_millis(250));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        ask(&ep, &with_timeout(5000), json!({})).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(budget.ms_per_token() >= 0.5, "{}", budget.ms_per_token());
        // 12,000 tokens at 0.5 ms are 6 s, over 5 s; at the 0.13 ms per
        // counted token they would have been 1.5 s.
        assert!(budget.admit(12_000, 5000).is_err());

        // An answer without the tokens read: the speed assumed stays.
        let budget = Arc::new(linear(100_000, 1.0));
        let (ep, asked) = fake::server_reading(2000, None, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        ask(&ep, &with_timeout(5000), json!({})).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(budget.ms_per_token(), 1.0);
    }

    /// A long call takes longer per token than the short calls the speed is
    /// learned from. With each model's pin, the measured long calls are
    /// refused at a timeout as long as they took, after the short call they
    /// followed (review round 4 of #178).
    #[test]
    fn a_long_call_is_held_to_the_slower_speed_of_its_length() {
        use crate::checker::config::LocalModel;
        use crate::checker::install::model_pin;
        // The model; the short call's tokens read and milliseconds; the long
        // call's tokens counted and milliseconds.
        let measured = [
            // Review round 4, 6 threads, the machine quiet: 240 tokens in
            // 1.15 s, then a call of control characters, the largest kind
            // of state, in 62.1 s.
            (LocalModel::D1_2b, 240, 1149.0, 8475, 62_100.0),
            // The evaluation's peak run (`raw/peak-d1-2b-c12288.server.log`),
            // 4 threads: 376 in 2.16 s, 8,070 read (about 8,045 counted) in
            // 59.9 s.
            (LocalModel::D1_2b, 376, 2159.0, 8045, 59_877.0),
            // Kev-4B's (`raw/peak-kev-4b-c8192.server.log`): 455 in 9.0 s,
            // 4,386 read in 134.9 s.
            (LocalModel::Kev4b, 455, 9043.0, 4361, 134_916.0),
        ];
        for (model, short, short_ms, long, long_ms) in measured {
            let pin = model_pin(model);
            let b = ReadBudget::new(pin.context, pin.read_ms, pin.read_growth);
            b.take_off().land(short, short_ms);
            assert!(
                b.admit(long, long_ms as u64).is_err(),
                "{model:?}: {long} tokens admitted in {long_ms} ms"
            );
        }
    }

    /// A model that thinks longer than the transport's usual 15 s head
    /// timeout is still read when the checker's own timeout allows it (a
    /// 4B model, or a 2B one on a small VM CPU, can take that long). Found on the
    /// Windows test VM, where every call was cut at 15 s.
    #[tokio::test]
    async fn a_slow_model_is_waited_for_up_to_the_checkers_timeout() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = c.read(&mut buf);
                std::thread::sleep(Duration::from_secs(16));
                let body = r#"{"answers":{"danger":{"type":"noul","noul":0.9}}}"#;
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let ep = Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None).unwrap();
        let cfg = ModelConfig {
            timeout_ms: 25_000,
            ..Default::default()
        };
        let score = ask(&ep, &cfg, json!({"command": "rm -rf /"}))
            .await
            .unwrap();
        assert_eq!(score, 0.9);
    }

    #[test]
    fn a_noul_answer_is_read() {
        let v = json!({"answers": {"danger": {"type": "noul", "noul": 0.93}}});
        assert_eq!(parse_noul(&v).unwrap(), 0.93);
    }

    #[test]
    fn a_missing_or_out_of_range_answer_is_bad() {
        assert!(parse_noul(&json!({"answers": {}})).is_err());
        assert!(parse_noul(&json!({"answers": {"danger": {"noul": 2.0}}})).is_err());
        assert!(parse_noul(&json!({"answers": {"danger": {"noul": "x"}}})).is_err());
    }

    #[test]
    fn the_request_carries_the_token_and_the_fixed_question() {
        let ep = Endpoint::parse(
            "https://h:9931",
            Some("secret".into()),
            Some("jev-latest".into()),
        )
        .unwrap();
        let body = json!({"state": {"command": "rm -rf /"}, "questions": {}});
        let text = request_bytes(
            &ep.url.authority(),
            "/v1/systemone",
            ep.token.as_deref(),
            &body,
        );
        assert!(text.contains("Authorization: Bearer secret"));
        assert!(text.contains("POST /v1/systemone HTTP/1.1"));
    }
}
