//! The local `llama-server` the center runs itself (docs/dev/action-checker.md).
//!
//! The center installs a prebuilt `llama-server` and the chosen model into its
//! state folder ([`super::install`]) and runs it from there. The server
//! listens on `127.0.0.1` on a free port, on the CPU or (the Vulkan build) the
//! GPU. The center checks `/v1/models` says `decisions` and refuses a
//! non-decision model. A server that dies is restarted with backoff; it ends
//! with the center, with no orphan.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinHandle;

use super::install::ModelPin;
use super::model::{self, Endpoint, ReadBudget};

/// How far along the local server is, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Starting,
    Downloading,
    Ready,
    Failed,
}

/// The local server's live state, shown in the UI.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub phase: Phase,
    /// The loopback endpoint, once it is listening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A reason, when it failed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// The last lines llama-server wrote, so a problem is visible.
    pub output: Vec<String>,
}

const OUTPUT_KEEP: usize = 20;

#[derive(Debug, Default)]
struct Inner {
    phase: Option<Phase>,
    url: Option<String>,
    message: String,
    output: std::collections::VecDeque<String>,
}

/// A running (or restarting) local llama-server. [`LocalServer::stop`] ends
/// the child and waits for it to exit (so its files can then be deleted, which
/// Windows refuses while it runs); dropping it only aborts the supervisor.
pub struct LocalServer {
    inner: Arc<Mutex<Inner>>,
    port: u16,
    task: JoinHandle<()>,
    /// Asked to end the server.
    shutdown: Arc<tokio::sync::Notify>,
    /// Fired by the supervisor once the child has exited and it is returning.
    exited: Arc<tokio::sync::Notify>,
    /// Its speed, kept across calls for as long as one process of it runs.
    budget: Arc<ReadBudget>,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        self.task.abort();
    }
}

impl LocalServer {
    /// Starts the supervisor for the installed `llama-server` at `bin` with
    /// the installed `model`, on the GPU (all layers, the Vulkan build) or the
    /// CPU, with the context of its `pin` ([`ModelPin::context`]). It returns
    /// at once; the status moves from starting to ready (or failed) as the
    /// server comes up. The model is already on disk (the one-click install
    /// fetched it), so there is no download at start.
    pub fn start(
        bin: PathBuf,
        model: PathBuf,
        gpu: bool,
        timeout_ms: u64,
        pin: &ModelPin,
    ) -> Result<LocalServer, String> {
        let context = pin.context;
        if !bin.exists() {
            return Err("the local model is not installed".into());
        }
        let port = free_port()?;
        let inner = Arc::new(Mutex::new(Inner::default()));
        let args = build_args(&model, gpu, port, context);
        let timeout = Duration::from_millis(timeout_ms.max(100));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let exited = Arc::new(tokio::sync::Notify::new());
        let budget = Arc::new(ReadBudget::new(context, pin.read_ms, pin.read_growth));
        let task = tokio::spawn(supervise(
            bin,
            args,
            port,
            timeout,
            inner.clone(),
            shutdown.clone(),
            exited.clone(),
            budget.clone(),
        ));
        Ok(LocalServer {
            inner,
            port,
            task,
            shutdown,
            exited,
            budget,
        })
    }

    /// Ends the server and waits for the child process to exit, up to a few
    /// seconds, so its files are free to delete or replace afterwards. Safe to
    /// call more than once.
    pub async fn stop(&self) {
        // A supervisor that already returned (a non-decision model) has no
        // child left to wait for.
        if self.task.is_finished() {
            return;
        }
        let exited = self.exited.clone();
        // Subscribe before asking, so a fast exit is not missed.
        let wait = exited.notified();
        tokio::pin!(wait);
        // `notify_one` keeps the request when the supervisor is not waiting at
        // this instant (it may be in a readiness probe), so it is not lost.
        self.shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(10), wait).await;
    }

    /// The endpoint for the client, once the server is listening.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint {
            budget: Some(self.budget.clone()),
            ..Endpoint::parse(&format!("http://127.0.0.1:{}", self.port), None, None)
                .expect("a loopback URL parses")
        }
    }

    /// Whether the server ended while it read a call and has not come up
    /// again ([`ReadBudget::died_on_call`]).
    pub fn died_on_call(&self) -> bool {
        self.budget.died_on_call()
    }

    pub fn ready(&self) -> bool {
        self.inner.lock().unwrap().phase == Some(Phase::Ready)
    }

    /// Whether calls are sent to the server: it is ready, or it ended on a
    /// call and is starting again, when the client refuses them as lost.
    /// Both are read under the lock the supervisor changes them under, so a
    /// call never meets the moment between "not ready" and "marked", or
    /// between "ready" and "unmarked" (review T3 of #178).
    pub fn takes_calls(&self) -> bool {
        let i = self.inner.lock().unwrap();
        i.phase == Some(Phase::Ready) || self.budget.died_on_call()
    }

    pub fn status(&self) -> Status {
        let i = self.inner.lock().unwrap();
        Status {
            phase: i.phase.unwrap_or(Phase::Starting),
            url: i.url.clone(),
            message: i.message.clone(),
            output: i.output.iter().cloned().collect(),
        }
    }
}

/// The llama-server command line (without the program itself): the installed
/// model file, all layers on the GPU or none (CPU only), and the context.
///
/// Without `-c` the server sizes the context from the model (up to 262,144
/// tokens, 13 GB for Kev-4B), and without `-b`/`-ub` it reads 512 tokens at a
/// time, which a decision model refuses for a longer prompt (HTTP 500), so a
/// long command failed closed. One slot: the checker asks one question at a
/// time per call, and four slots would share the one context, each keeping
/// its last state in it.
fn build_args(model: &Path, gpu: bool, port: u16, context: u32) -> Vec<String> {
    let context = context.to_string();
    vec![
        "-m".into(),
        model.to_string_lossy().into_owned(),
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        port.to_string(),
        "-ngl".into(),
        // 999 puts every layer on the GPU; 0 keeps it on the CPU.
        if gpu { "999".into() } else { "0".into() },
        "-c".into(),
        context.clone(),
        "-b".into(),
        context.clone(),
        "-ub".into(),
        context,
        "-np".into(),
        "1".into(),
    ]
}

/// A free loopback port: bind to port 0, read the port, and drop the
/// listener. A short race until llama-server binds it; the center accepts it
/// (docs).
fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

/// Runs the server, restarting it with backoff until the task is aborted. A
/// non-decision model is a reason not to restart. Each process starts with
/// the budget's speeds forgotten.
#[allow(clippy::too_many_arguments)]
async fn supervise(
    program: PathBuf,
    args: Vec<String>,
    port: u16,
    timeout: Duration,
    inner: Arc<Mutex<Inner>>,
    shutdown: Arc<tokio::sync::Notify>,
    exited: Arc<tokio::sync::Notify>,
    budget: Arc<ReadBudget>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        set(&inner, |i| {
            i.phase = Some(Phase::Starting);
            i.url = None;
        });
        budget.restart();
        match run_once(&program, &args, port, timeout, &inner, &shutdown, &budget).await {
            RunEnd::NotDecision => {
                // A clear, final failure: do not restart.
                budget.settled();
                exited.notify_waiters();
                return;
            }
            RunEnd::Stopped => {
                // Asked to stop: the child has exited, its files are free.
                set(&inner, |i| i.phase = Some(Phase::Starting));
                exited.notify_waiters();
                return;
            }
            RunEnd::Exited => {}
            RunEnd::StartFailed(e) => {
                // The restart came to nothing: the model is down, not
                // ended on a call, and allow-and-log applies as it says.
                budget.settled();
                set(&inner, |i| {
                    i.phase = Some(Phase::Failed);
                    i.message = format!("cannot start {}: {e}", program.display());
                });
            }
        }
        // Wait before the next try; a stop during the wait ends it at once.
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.notified() => {
                exited.notify_waiters();
                return;
            }
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

enum RunEnd {
    /// The process could not be started.
    StartFailed(String),
    /// It ran and exited (crash); restart after the backoff.
    Exited,
    /// It was asked to stop and the child has exited; do not restart.
    Stopped,
    /// It loaded a model that is not a decision model; do not restart.
    NotDecision,
}

/// Kills the child and waits for it to exit, so its files are free.
async fn kill_and_wait(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn run_once(
    program: &PathBuf,
    args: &[String],
    port: u16,
    timeout: Duration,
    inner: &Arc<Mutex<Inner>>,
    shutdown: &Arc<tokio::sync::Notify>,
    budget: &ReadBudget,
) -> RunEnd {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return RunEnd::StartFailed(e.to_string()),
    };
    // Follow stderr into the ring buffer, flagging a download.
    if let Some(err) = child.stderr.take() {
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                set(&inner, |i| {
                    if i.phase != Some(Phase::Ready) && is_download(&line) {
                        i.phase = Some(Phase::Downloading);
                    }
                    push_line(&mut i.output, line);
                });
            }
        });
    }
    // Probe until it is ready, it exits, or we are aborted.
    let endpoint = Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None)
        .expect("a loopback URL parses");
    let url = format!("http://127.0.0.1:{port}");
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                kill_and_wait(&mut child).await;
                return RunEnd::Stopped;
            }
            status = child.wait() => {
                let how = status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                // It ended before it was ready: a restart that did not come
                // up (review T3 of #178).
                budget.settled();
                set(inner, |i| {
                    if i.phase != Some(Phase::Failed) {
                        i.phase = Some(Phase::Starting);
                    }
                    i.url = None;
                    push_line(&mut i.output, format!("llama-server ended ({how})"));
                });
                return RunEnd::Exited;
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                match tokio::time::timeout(timeout, model::is_decision_model(&endpoint)).await {
                    Ok(Ok(true)) => {
                        set(inner, |i| {
                            i.phase = Some(Phase::Ready);
                            i.url = Some(url.clone());
                            i.message.clear();
                            // Calls are sent to the server again. Unmarked
                            // with the phase, under its lock.
                            budget.settled();
                        });
                        // Stay here until the child exits or we are stopped.
                        tokio::select! {
                            _ = shutdown.notified() => {
                                kill_and_wait(&mut child).await;
                                return RunEnd::Stopped;
                            }
                            status = child.wait() => {
                                let how = status
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|e| e.to_string());
                                set(inner, |i| {
                                    // Marked with the phase, under its lock,
                                    // if a call was in it.
                                    budget.ended();
                                    i.phase = Some(Phase::Starting);
                                    i.url = None;
                                    push_line(&mut i.output, format!("llama-server ended ({how})"));
                                });
                                return RunEnd::Exited;
                            }
                        }
                    }
                    Ok(Ok(false)) => {
                        set(inner, |i| {
                            i.phase = Some(Phase::Failed);
                            i.message = "the loaded model is not a decision model: /v1/models has no \"decisions\". Use a System One model.".into();
                        });
                        kill_and_wait(&mut child).await;
                        return RunEnd::NotDecision;
                    }
                    // Not up yet, or a transient error: keep probing.
                    _ => {}
                }
            }
        }
    }
}

fn is_download(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("download") || l.contains("fetching") || l.contains("%|")
}

fn push_line(buf: &mut std::collections::VecDeque<String>, line: String) {
    buf.push_back(line);
    while buf.len() > OUTPUT_KEEP {
        buf.pop_front();
    }
}

fn set(inner: &Arc<Mutex<Inner>>, f: impl FnOnce(&mut Inner)) {
    f(&mut inner.lock().unwrap());
}

/// Test helpers the center's own tests share.
#[cfg(all(test, unix))]
pub(crate) mod fake {
    /// A fake `llama-server`: a shell script that ignores the model and serves
    /// `/v1/models` (a decision model) and `/v1/systemone` on the `--port` it
    /// is given, so the supervisor can be tested without a real model. It
    /// writes its process id to `pid` beside it. Unix only (it uses
    /// `/bin/sh` and `nc`-free shell); skipped elsewhere.
    pub(crate) fn fake_llama_server(dir: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("llama-server");
        // A tiny HTTP server in shell + a Python one-liner (Python is present
        // on the test machines). It answers every request by content of the
        // path.
        let script = r#"#!/bin/sh
port=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--port" ]; then port="$a"; fi
  prev="$a"
done
echo $$ > "$(dirname "$0")/pid"
exec python3 - "$port" <<'PY'
import sys, http.server
port = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self._send(b'{"data":[{"architecture":{"output_modalities":["decisions"]}}]}')
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if self.path == "/tokenize":
            self._send(b'{"tokens":[1,2,3]}')
            return
        self._send(b'{"answers":{"danger":{"type":"noul","noul":0.99}}}')
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
"#;
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_and_gpu_args() {
        let model = std::path::Path::new("/s/checker/model/d1-2B-Q4_K_M.gguf");
        let cpu = build_args(model, false, 12345, 4096);
        assert!(cpu.windows(2).any(|w| w == ["-ngl", "0"]));
        assert!(cpu.windows(2).any(|w| w == ["--port", "12345"]));
        assert!(
            cpu.windows(2)
                .any(|w| w == ["-m", "/s/checker/model/d1-2B-Q4_K_M.gguf"])
        );
        let gpu = build_args(model, true, 12345, 4096);
        assert!(gpu.windows(2).any(|w| w == ["-ngl", "999"]));
    }

    /// The server gets the model's context, and reads a prompt of that size
    /// in one batch, on one slot.
    #[test]
    fn the_context_is_bounded_and_read_in_one_batch() {
        let model = std::path::Path::new("/s/checker/model/d1-2B-Q4_K_M.gguf");
        let args = build_args(model, false, 12345, 12_288);
        for flag in ["-c", "-b", "-ub"] {
            assert!(
                args.windows(2).any(|w| w == [flag, "12288"]),
                "{flag}: {args:?}"
            );
        }
        assert!(args.windows(2).any(|w| w == ["-np", "1"]), "{args:?}");
    }

    /// The local server's endpoint carries its budget, built from the pin of
    /// the model it runs: without it every call is sent, however long (review
    /// round 3 of #178).
    #[tokio::test]
    async fn the_local_endpoint_holds_calls_to_its_models_budget() {
        use crate::checker::config::LocalModel;
        let dir = tempfile::tempdir().unwrap();
        // It only has to exist: the budget is set before the server runs.
        let bin = dir.path().join("llama-server");
        std::fs::write(&bin, b"").unwrap();
        for model in [LocalModel::D1_2b, LocalModel::Kev4b] {
            let pin = crate::checker::install::model_pin(model);
            let server =
                LocalServer::start(bin.clone(), dir.path().join("model.gguf"), false, 5000, pin)
                    .expect("start");
            let budget = server.endpoint().budget.expect("a budget");
            assert_eq!(
                budget.built_with(),
                (pin.context as usize, pin.read_ms, pin.read_growth),
                "{model:?}"
            );
        }
    }

    #[test]
    fn a_download_line_is_recognised() {
        assert!(is_download("downloading model.gguf"));
        assert!(is_download("  45%|████      | 200M/440M"));
        assert!(!is_download("llama_server: model loaded"));
    }
    /// The supervisor starts the (fake) server, reports it ready once it
    /// answers `/v1/models` with a decision model, and `stop` ends the child
    /// and returns once it has exited (review r2, findings 1 and 8; r3,
    /// finding 6).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_supervisor_starts_and_stops_a_fake_server() {
        let dir = tempfile::tempdir().unwrap();
        let bin = super::fake::fake_llama_server(dir.path());
        let model = dir.path().join("model.gguf");
        std::fs::write(&model, b"x").unwrap();
        let server = LocalServer::start(
            bin,
            model,
            false,
            5000,
            crate::checker::install::model_pin(crate::checker::config::LocalModel::D1_2b),
        )
        .expect("start");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline && !server.ready() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(server.ready(), "never ready: {:?}", server.status());
        // The endpoint answers.
        let ep = server.endpoint();
        let score = crate::checker::model::ask(
            &ep,
            &crate::checker::config::ModelConfig::default(),
            serde_json::json!({"command": "x"}),
        )
        .await
        .unwrap();
        assert_eq!(score, 0.99);
        // Stop returns well inside its own 10 s cap, because the child has
        // exited (not because the cap ran out), and the port is free: the
        // process is gone (review r3, finding 6).
        let port = server.port;
        tokio::time::timeout(Duration::from_secs(4), server.stop())
            .await
            .expect("stop did not end the child");
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
            "the server still answers after stop"
        );
    }

    /// A restarted server is held to the assumed speed again until it
    /// answered a call: it may run slower than the process before it (one
    /// that lost its GPU runs on the CPU), and a long call admitted at the
    /// old speed would hold its one slot for many timeouts (review T1 of
    /// #178).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_server_forgets_the_speed_it_measured() {
        let dir = tempfile::tempdir().unwrap();
        let bin = super::fake::fake_llama_server(dir.path());
        let model = dir.path().join("model.gguf");
        std::fs::write(&model, b"x").unwrap();
        let pin = crate::checker::install::model_pin(crate::checker::config::LocalModel::D1_2b);
        let server = LocalServer::start(bin, model, false, 5000, pin).expect("start");
        let until = async |what: &str, f: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !f() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{what}: {:?}",
                    server.status()
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        until("ready", &|| server.ready()).await;
        // Far faster than the 20 ms assumed for d1-2B.
        server.budget.learn(1000, 1000.0);
        assert!(server.budget.ms_per_token() < 1.0);
        let pid = std::fs::read_to_string(dir.path().join("pid")).unwrap();
        let killed = std::process::Command::new("kill")
            .args(["-9", pid.trim()])
            .status()
            .unwrap();
        assert!(killed.success());
        // A call was on its way when the server ended.
        server.budget.die_on_call();
        until("ended", &|| !server.ready()).await;
        // Until the new process is up, the center keeps the endpoint so the
        // client refuses calls (review T2 of #178).
        assert!(server.died_on_call());
        until("ready again", &|| server.ready()).await;
        assert!(!server.died_on_call());
        assert_eq!(server.budget.ms_per_token(), pin.read_ms);
        server.stop().await;
    }

    /// Starts the fake server and waits until it is ready.
    #[cfg(unix)]
    async fn ready_fake(dir: &std::path::Path) -> LocalServer {
        let bin = super::fake::fake_llama_server(dir);
        let model = dir.join("model.gguf");
        std::fs::write(&model, b"x").unwrap();
        let pin = crate::checker::install::model_pin(crate::checker::config::LocalModel::D1_2b);
        let server = LocalServer::start(bin, model, false, 5000, pin).expect("start");
        until(&server, "ready", &|| server.ready()).await;
        server
    }

    #[cfg(unix)]
    async fn until(server: &LocalServer, what: &str, f: &dyn Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: {:?}",
                server.status()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(unix)]
    fn kill_fake(dir: &std::path::Path) {
        let pid = std::fs::read_to_string(dir.join("pid")).unwrap();
        let killed = std::process::Command::new("kill")
            .args(["-9", pid.trim()])
            .status()
            .unwrap();
        assert!(killed.success());
    }

    /// A server that ends with a call in it is marked in the same step as it
    /// leaves the ready phase, without waiting for that call's own task to
    /// see its connection end: a call that arrives in between would find it
    /// neither ready nor marked, and be let through by allow-and-log (review
    /// T3 of #178). The mark goes when the restarted process is ready.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_ends_with_a_call_in_it_is_marked_as_it_leaves_ready() {
        let dir = tempfile::tempdir().unwrap();
        let server = ready_fake(dir.path()).await;
        let reading = server.budget.hold_slot();
        kill_fake(dir.path());
        until(&server, "ended", &|| !server.ready()).await;
        assert!(server.died_on_call());
        assert!(server.takes_calls());
        drop(reading);
        until(&server, "ready again", &|| server.ready()).await;
        assert!(!server.died_on_call());
        server.stop().await;
    }

    /// A server that ends with no call in it is down, not marked.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_ends_with_no_call_in_it_is_not_marked() {
        let dir = tempfile::tempdir().unwrap();
        let server = ready_fake(dir.path()).await;
        kill_fake(dir.path());
        until(&server, "ended", &|| !server.ready()).await;
        assert!(!server.died_on_call());
        assert!(!server.takes_calls());
        server.stop().await;
    }

    /// A restart that does not come up leaves the mark: the model is down
    /// then, which is what the docs say allow-and-log applies to, and not
    /// "starting again" for as long as the center runs (review T3 of #178).
    /// Either way the new process does not come up: it ends at once, or it
    /// cannot be started.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restart_that_does_not_come_up_clears_the_mark() {
        use std::os::unix::fs::PermissionsExt;
        for ends_at_once in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let server = ready_fake(dir.path()).await;
            let bin = dir.path().join("llama-server");
            // The running process keeps its file; a restart finds this.
            std::fs::remove_file(&bin).unwrap();
            if ends_at_once {
                std::fs::write(&bin, "#!/bin/sh\nexit 1\n").unwrap();
                std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let reading = server.budget.hold_slot();
            kill_fake(dir.path());
            until(&server, "marked", &|| server.died_on_call()).await;
            drop(reading);
            // The restart follows after the backoff.
            until(&server, "unmarked", &|| !server.died_on_call()).await;
            assert!(!server.takes_calls(), "ends_at_once: {ends_at_once}");
            server.stop().await;
        }
    }

    /// Whether the server takes calls is read with the phase and the mark
    /// together: the reader keeps the phase's lock while it reads the mark,
    /// and the supervisor changes the mark under that lock. Otherwise a call
    /// could read "not ready" just before the restarted server is ready and
    /// "not marked" just after the mark went, and be let through by
    /// allow-and-log (review T3 of #178).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_phase_is_read_together_with_the_mark() {
        let dir = tempfile::tempdir().unwrap();
        let pin = crate::checker::install::model_pin(crate::checker::config::LocalModel::D1_2b);
        // A server that cannot start (the file cannot be run): not ready,
        // not marked.
        let bin = dir.path().join("llama-server");
        std::fs::write(&bin, "x").unwrap();
        let server = Arc::new(
            LocalServer::start(bin, dir.path().join("m"), false, 5000, pin).expect("start"),
        );
        while server.status().phase != Phase::Failed {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mark = server.budget.hold_state();
        let asking = {
            let server = server.clone();
            std::thread::spawn(move || server.takes_calls())
        };
        // The reader waits for the mark, holding the phase's lock.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while server.inner.try_lock().is_ok() {
            assert!(std::time::Instant::now() < deadline, "never waited");
            // Not tokio's sleep: the supervisor blocked on the mark may hold
            // the thread that drives its timers.
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(mark);
        assert!(!asking.join().unwrap());
        server.stop().await;
    }

    /// The supervisor unmarks the server in the step that makes it ready,
    /// under the phase's lock, and sets the phase first (review T3 of
    /// #178).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_mark_goes_in_the_step_that_makes_the_server_ready() {
        let dir = tempfile::tempdir().unwrap();
        let bin = super::fake::fake_llama_server(dir.path());
        let model = dir.path().join("model.gguf");
        std::fs::write(&model, b"x").unwrap();
        let pin = crate::checker::install::model_pin(crate::checker::config::LocalModel::D1_2b);
        let server = LocalServer::start(bin, model, false, 5000, pin).expect("start");
        // The supervisor is past its restart and probing; the first probe is
        // after 500 ms.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mark = server.budget.hold_state();
        // When the server answers, the step waits for the mark with the
        // phase's lock held: nobody reads between the two.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while server.inner.try_lock().is_ok() {
            assert!(std::time::Instant::now() < deadline, "never waited");
            // Not tokio's sleep: the supervisor blocked on the mark may hold
            // the thread that drives its timers.
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(mark);
        until(&server, "ready", &|| server.ready()).await;
        server.stop().await;
    }
}
