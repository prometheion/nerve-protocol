//! Runs `nerve-node` for the app: this same program with arguments, which
//! behaves as `nerve-node` (src/main.rs), with `--json`, and reads its
//! answer (docs/dev/settings-and-config.md). The app never parses text meant for
//! people, and has the CLI's checks because it runs the CLI. On a node
//! installed as a service the CLI of the owner has the running node run the
//! command (nerve_node::owner); a command that needs an administrator, or
//! any for a user who is not the owner, goes through the elevated broker
//! (crate::broker) instead, which runs the same program the same way.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::broker;

/// Starts the CLI: which program, the folders it is given, and whether it
/// goes through the broker.
#[derive(Clone)]
pub struct Runner {
    exe: PathBuf,
    dirs: Vec<String>,
    broker: Option<Arc<broker::Client>>,
}

/// What a run of the program gave back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A command that keeps running and gives a line at a time (`audit
/// --follow`); it ends when this is dropped.
pub struct Follow {
    stop: Option<Box<dyn FnOnce() + Send>>,
}

impl Follow {
    pub fn new(stop: Box<dyn FnOnce() + Send>) -> Follow {
        Follow { stop: Some(stop) }
    }
}

impl Drop for Follow {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
    }
}

impl Runner {
    /// This program. The node's folders come from `NERVE_NODE_CONFIG_DIR`
    /// and `NERVE_NODE_STATE_DIR` when they are set, which the CLI reads too, else
    /// they are the CLI's defaults.
    pub fn this_program() -> Result<Runner, String> {
        let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
        Ok(Runner::new(exe, None, None))
    }

    /// `exe` as the CLI, with `--config-dir` and `--state-dir` when given.
    pub fn new(exe: PathBuf, config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> Runner {
        let mut dirs = Vec::new();
        if let Some(c) = config_dir {
            dirs.push(format!("--config-dir={}", c.display()));
        }
        if let Some(s) = state_dir {
            dirs.push(format!("--state-dir={}", s.display()));
        }
        Runner {
            exe,
            dirs,
            broker: None,
        }
    }

    pub fn exe(&self) -> &PathBuf {
        &self.exe
    }

    /// The same runner, its commands going through `broker`.
    pub fn through(&self, broker: Arc<broker::Client>) -> Runner {
        Runner {
            broker: Some(broker),
            ..self.clone()
        }
    }

    /// The same runner, its commands run directly again.
    pub fn direct(&self) -> Runner {
        Runner {
            broker: None,
            ..self.clone()
        }
    }

    /// Whether the commands go through the broker.
    pub fn elevated(&self) -> bool {
        self.broker.is_some()
    }

    fn args(&self, args: &[&str]) -> Vec<String> {
        let mut all = self.dirs.clone();
        all.push("--json".into());
        all.extend(args.iter().map(|a| a.to_string()));
        all
    }

    /// Runs `nerve-node --json <args>` and returns its answer, or the error
    /// it gave.
    pub fn run(&self, args: &[&str]) -> Result<Value, String> {
        self.run_with(args, None)
    }

    /// [`Runner::run`] with `input` as the first line of stdin, for a
    /// password or a passphrase: never an argument, which every process of
    /// the user could read.
    pub fn run_with(&self, args: &[&str], input: Option<&str>) -> Result<Value, String> {
        let args = self.args(args);
        let out = match &self.broker {
            Some(b) => b.run(args, input)?,
            None => run_process(&self.exe, &args, input)?,
        };
        // On Windows the app is the only way to the node: what the node
        // says, it says in the app's words (crate::in_app).
        crate::in_app::answer(
            answer(out.ok, out.code, &out.stdout, &out.stderr),
            cfg!(windows),
        )
    }

    /// Runs `nerve-node --json <args>` that keeps answering (`--follow`):
    /// `each` gets every entry, or the error that ended it.
    pub fn follow(
        &self,
        args: &[&str],
        each: impl FnMut(Result<Value, String>) + Send + 'static,
    ) -> Result<Follow, String> {
        let args = self.args(args);
        let each = Arc::new(Mutex::new(each));
        let on_line = {
            let each = each.clone();
            move |line: String| {
                if let Some(v) = entry(&line) {
                    (each.lock().unwrap_or_else(|p| p.into_inner()))(v);
                }
            }
        };
        let on_end = move |out: Output| {
            if !out.ok
                && let Err(e) =
                    crate::in_app::answer(answer(out.ok, out.code, b"", &out.stderr), cfg!(windows))
            {
                (each.lock().unwrap_or_else(|p| p.into_inner()))(Err(e));
            }
        };
        match &self.broker {
            Some(b) => b.follow(args, Box::new(on_line), Box::new(on_end)),
            None => follow_process(&self.exe, &args, Box::new(on_line), Box::new(on_end)),
        }
    }
}

/// One line of a command that keeps answering: an entry, or the error it
/// ended with. Anything else is no answer.
fn entry(line: &str) -> Option<Result<Value, String>> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    match v["error"].as_str() {
        Some(e) if v.as_object().is_some_and(|o| o.len() == 1) => Some(Err(e.to_string())),
        _ => Some(Ok(v)),
    }
}

/// Runs `exe` with `args`, `input` as the first line of stdin,
/// and waits.
pub fn run_process(exe: &PathBuf, args: &[String], input: Option<&str>) -> Result<Output, String> {
    let mut c = Command::new(exe);
    c.args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(c, exe)?;
    if let Some(text) = input {
        let mut stdin = child.stdin.take().expect("piped");
        // A command that ends before it reads leaves its own answer.
        let _ = stdin.write_all(format!("{text}\n").as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nerve-node did not end: {e}"))?;
    Ok(Output {
        ok: out.status.success(),
        code: out.status.code(),
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// Starts `exe` with `args`, and gives each line it prints to
/// `on_line`, then how it ended to `on_end`, unless it was ended on purpose.
/// The returned [`Follow`] ends it.
pub fn follow_process(
    exe: &PathBuf,
    args: &[String],
    mut on_line: Box<dyn FnMut(String) + Send>,
    on_end: Box<dyn FnOnce(Output) + Send>,
) -> Result<Follow, String> {
    let mut c = Command::new(exe);
    c.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(c, exe)?;
    let stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let child = Arc::new(Mutex::new(child));
    let stopped = Arc::new(AtomicBool::new(false));
    {
        let (child, stopped) = (child.clone(), stopped.clone());
        std::thread::spawn(move || {
            let err = std::thread::spawn(move || {
                let mut b = Vec::new();
                let _ = std::io::Read::read_to_end(&mut stderr, &mut b);
                b
            });
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                on_line(line);
            }
            // Never waits while it holds the child: a stop takes it to end
            // the child, and a child that keeps running after its output
            // ended (or a stop that came between a line and this) would
            // keep the stop, and the window or the broker's loop that
            // called it, waiting for good.
            let status = loop {
                match child.lock().unwrap_or_else(|p| p.into_inner()).try_wait() {
                    Ok(Some(s)) => break Ok(s),
                    Ok(None) => {}
                    Err(e) => break Err(e),
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            };
            let stderr = err.join().unwrap_or_default();
            if !stopped.load(Ordering::SeqCst) {
                on_end(Output {
                    ok: status.as_ref().is_ok_and(|s| s.success()),
                    code: status.ok().and_then(|s| s.code()),
                    stdout: Vec::new(),
                    stderr,
                });
            }
        });
    }
    Ok(Follow::new(Box::new(move || {
        stopped.store(true, Ordering::SeqCst);
        let _ = child.lock().unwrap_or_else(|p| p.into_inner()).kill();
    })))
}

/// Starts `c`, the program `exe`.
fn spawn(mut c: Command, exe: &std::path::Path) -> Result<std::process::Child, String> {
    c.spawn()
        .map_err(|e| format!("cannot start {}: {e}", exe.display()))
}

/// What a run of the CLI answered: its JSON, or its error. A run that gave
/// no JSON says why with the last line of stderr, which also carries the
/// log's events before it.
pub fn answer(ok: bool, code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Result<Value, String> {
    let text = String::from_utf8_lossy(stdout);
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    let parsed = last.and_then(|l| serde_json::from_str::<Value>(l).ok());
    match parsed {
        Some(v) if ok => Ok(v),
        Some(v) if v["error"].is_string() => Err(v["error"].as_str().unwrap_or_default().into()),
        _ => {
            let err = String::from_utf8_lossy(stderr);
            let why = err
                .lines()
                .rev()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map(|l| l.strip_prefix("nerve-node: ").unwrap_or(l).to_string());
            Err(match (why, code) {
                (Some(why), _) => why,
                (None, Some(c)) => format!("nerve-node ended with exit code {c} and said nothing"),
                (None, None) => "nerve-node was stopped before it answered".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_is_the_json_on_stdout() {
        let v = answer(true, Some(0), b"{\"daemon\":\"running\"}\n", b"").unwrap();
        assert_eq!(v["daemon"], "running");
        // The error on stdout, not the log's events on stderr.
        let e = answer(
            false,
            Some(1),
            b"{\"error\":\"no center named x\"}\n",
            b"2026-10-18 INFO something\nnerve-node: no center named x\n",
        )
        .unwrap_err();
        assert_eq!(e, "no center named x");
    }

    #[test]
    fn a_run_without_json_says_why_from_stderr() {
        let e = answer(false, Some(2), b"", b"error: unexpected argument '--x'\n\n").unwrap_err();
        assert_eq!(e, "error: unexpected argument '--x'");
        let e = answer(false, Some(1), b"", b"nerve-node: cannot read node.toml\n").unwrap_err();
        assert_eq!(e, "cannot read node.toml");
        let e = answer(false, None, b"", b"").unwrap_err();
        assert!(e.contains("stopped"), "{e}");
        // Success without JSON is no answer either.
        assert!(answer(true, Some(0), b"text\n", b"").is_err());
    }

    /// A stop ends a followed command at once, also one that closed its
    /// output and still runs: the reader does not hold the command while it
    /// waits for its end (shared-6).
    #[cfg(unix)]
    #[test]
    fn a_stop_ends_a_command_that_closed_its_output() {
        let (tx, rx) = std::sync::mpsc::channel();
        let f = follow_process(
            &PathBuf::from("/bin/sh"),
            &["-c".into(), "echo up; exec >&- 2>&-; sleep 30".into()],
            Box::new(move |l| {
                let _ = tx.send(l);
            }),
            Box::new(|_| {}),
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap(),
            "up"
        );
        // The reader has seen the output end and waits for the command.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(f);
            let _ = done_tx.send(());
        });
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "the stop waited for the command"
        );
    }

    #[test]
    fn a_followed_line_is_an_entry_or_the_error() {
        assert_eq!(
            entry("{\"ts\":1,\"msg\":\"x\"}").unwrap().unwrap()["msg"],
            "x"
        );
        assert_eq!(entry("{\"error\":\"gone\"}").unwrap().unwrap_err(), "gone");
        // An entry may have a field named error.
        assert!(entry("{\"ts\":1,\"error\":\"e\"}").unwrap().is_ok());
        assert!(entry("not json").is_none());
    }
}
