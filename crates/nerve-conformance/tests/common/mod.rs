//! Running the real `nerve-center` and `nerve-node` binaries for the end-to-end
//! tests.
//!
//! The binaries come from `NERVE_CENTER_BIN` and `NERVE_NODE_BIN` when set (that
//! is how the tests run on another machine), otherwise they are built with
//! the cargo that runs the tests.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The path of a workspace binary, built once per test process.
pub fn bin(name: &str) -> PathBuf {
    let var = format!("{}_BIN", name.to_uppercase().replace('-', "_"));
    if let Some(p) = std::env::var_os(&var) {
        return PathBuf::from(p);
    }
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let ok = Command::new(cargo)
            .args([
                "build",
                "--offline",
                "-p",
                "nerve-center",
                "-p",
                "nerve-node",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("cargo runs")
            .success();
        assert!(ok, "building nerve-center and nerve-node failed");
    });
    // tests run from target/<profile>/deps/<test>; the binaries sit one up.
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(Path::parent).unwrap();
    dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The command of a `nerve-center` with its own state folder, a node
/// listener on a free port (pinned TLS when `tls`, else plain loopback) and
/// the web UI on a free port; the port of the node listener.
fn center_command(state: &Path, tls: bool, extra: &[(&str, &str)]) -> (Command, u16) {
    let node_port = free_port();
    let mut cmd = Command::new(bin("nerve-center"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", state)
        .env("NERVE_STATE_DIR", state)
        .env("NERVE_NAME", "e2e-center")
        .env("NERVE_LISTEN", format!("127.0.0.1:{node_port}"))
        .env("NERVE_UI", "127.0.0.1:0")
        .env("NERVE_LOG", "info")
        .env("NERVE_CALL_WAIT", "20");
    if tls {
        cmd.env("NERVE_PUBLIC_URL", format!("https://127.0.0.1:{node_port}"));
    } else {
        cmd.env("NERVE_PLAIN_LOOPBACK", "true")
            .env("NERVE_PUBLIC_URL", format!("http://127.0.0.1:{node_port}"));
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    (cmd, node_port)
}

/// Passes the center's stderr on to ours and returns the address of its web
/// UI, once it names it.
fn ui_address(child: &mut Child) -> String {
    let (ui_tx, ui_rx) = channel();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut sent = false;
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("[nerve-center] {line}");
            if !sent && let Some(i) = line.find("web UI at http://") {
                let addr = line[i + "web UI at http://".len()..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let _ = ui_tx.send(addr);
                sent = true;
            }
        }
    });
    ui_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("nerve-center names its web UI address")
}

/// A `nerve-center` that serves MCP over HTTP with a harness token and has no
/// harness on stdin.
pub struct HttpCenter {
    child: Child,
    pub ui: Ui,
    pub mcp_addr: String,
    pub token: String,
}

impl HttpCenter {
    pub fn start(state: &Path, token: &str) -> HttpCenter {
        let mcp_addr = format!("127.0.0.1:{}", free_port());
        let (mut cmd, _) = center_command(
            state,
            false,
            &[
                ("NERVE_MCP", "http"),
                ("NERVE_MCP_LISTEN", &mcp_addr),
                ("NERVE_HARNESS_TOKEN", token),
                // The UI is open on loopback for the test to pair through.
                ("NERVE_UI_NO_LOGIN", "true"),
            ],
        );
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("nerve-center starts");
        let ui = ui_address(&mut child);
        HttpCenter {
            child,
            ui: Ui {
                addr: ui,
                cookie: Arc::new(Mutex::new(None)),
            },
            mcp_addr,
            token: token.to_string(),
        }
    }
}

impl Drop for HttpCenter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A `nerve-center` started the way a harness starts it: MCP over stdio.
pub struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Receiver<Value>,
    /// Notifications that arrived while waiting for a reply.
    pub notes: Vec<Value>,
    pub ui: Ui,
    pub node_port: u16,
    next_id: u64,
}

impl Mcp {
    /// Starts a center in `state`. `tls` picks a TLS node listener (pinned
    /// through the link) over plain HTTP on loopback.
    pub fn start(state: &Path, tls: bool, extra: &[(&str, &str)]) -> Mcp {
        let (mut cmd, node_port) = center_command(state, tls, extra);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("nerve-center starts");
        let stdin = child.stdin.take();
        let (tx, out) = channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) => {
                        if tx.send(v).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("nerve-center stdout is not JSON ({e}): {line}"),
                }
            }
        });
        let ui = ui_address(&mut child);
        let mut m = Mcp {
            child,
            stdin,
            out,
            notes: Vec::new(),
            ui: Ui {
                addr: ui,
                cookie: Arc::new(Mutex::new(None)),
            },
            node_port,
            next_id: 1,
        };
        let r = m.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "e2e", "version": "x.y.z"}}),
        );
        assert_eq!(r["result"]["serverInfo"]["name"], "nerve-center", "{r}");
        m.notify("notifications/initialized", json!({}));
        m
    }

    pub fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    /// Sends a request with `id` without waiting for its reply.
    pub fn send(&mut self, id: &str, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    /// Sends a request and waits for its reply, keeping notifications.
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        self.request_wait(method, params, Duration::from_secs(60))
    }

    pub fn request_wait(&mut self, method: &str, params: Value, wait: Duration) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
        let until = Instant::now() + wait;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.out.recv_timeout(left) {
                Ok(v) if v.get("id") == Some(&json!(id)) => return v,
                Ok(v) => self.notes.push(v),
                Err(RecvTimeoutError::Timeout) => panic!("no reply to {method} within {wait:?}"),
                Err(RecvTimeoutError::Disconnected) => panic!("nerve-center closed stdout"),
            }
        }
    }

    /// Waits for the reply to the request sent as `id` with [`Mcp::send`],
    /// keeping notifications.
    pub fn reply(&mut self, id: &str, wait: Duration) -> Value {
        let until = Instant::now() + wait;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.out.recv_timeout(left) {
                Ok(v) if v.get("id") == Some(&json!(id)) => return v,
                Ok(v) => self.notes.push(v),
                Err(RecvTimeoutError::Timeout) => panic!("no reply to {id} within {wait:?}"),
                Err(RecvTimeoutError::Disconnected) => panic!("nerve-center closed stdout"),
            }
        }
    }

    pub fn tools(&mut self) -> Vec<Value> {
        let r = self.request("tools/list", json!({}));
        r["result"]["tools"].as_array().cloned().unwrap_or_default()
    }

    /// Calls a tool and returns its result object.
    pub fn call(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}));
        assert!(r.get("result").is_some(), "tools/call {name}: {r}");
        r["result"].clone()
    }

    /// `list` with `args`: its result object.
    pub fn list(&mut self, args: Value) -> Value {
        self.call("list", args)
    }

    /// The capabilities `list(node)` offers now; none while the node is not
    /// known or not described yet.
    pub fn offered(&mut self, node: &str) -> Vec<String> {
        self.list(json!({"node": node}))["structuredContent"]["result"]["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["name"].as_str().map(str::to_string))
            .collect()
    }

    /// The `tools/call` params that run `unit` (`cap.action`) on `node` with
    /// the arguments `args`, after `list` gave this session the unit's
    /// details, as `execute` asks. The tests name units: this is the one
    /// place that knows how a unit is called.
    pub fn run_params(&mut self, node: &str, unit: &str, args: Value) -> Value {
        let listed = self.list(json!({"node": node, "capability": unit}));
        assert_ne!(
            listed["isError"],
            json!(true),
            "list {unit} on {node}: {listed}"
        );
        json!({"name": "execute",
               "arguments": {"node": node, "capability": unit, "args": args}})
    }

    /// Runs `unit` on `node` as a harness would and returns the result
    /// object.
    pub fn run(&mut self, node: &str, unit: &str, args: Value) -> Value {
        let params = self.run_params(node, unit, args);
        let r = self.request("tools/call", params);
        assert!(r.get("result").is_some(), "{unit} on {node}: {r}");
        r["result"].clone()
    }

    /// A web UI API call; see [`Ui::api`].
    pub fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.ui.api(method, path, body)
    }

    pub fn pair_link(&self) -> String {
        self.ui.pair_link()
    }

    pub fn wait_overview(&self, what: &str, f: impl Fn(&Value) -> bool) -> Value {
        self.ui.wait_overview(what, f)
    }

    /// Ends the harness side (stdin) and waits for the process to exit.
    pub fn finish(mut self) -> bool {
        drop(self.stdin.take());
        wait_exit(&mut self.child, Duration::from_secs(15))
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The center's web UI API, usable from any thread.
#[derive(Clone)]
pub struct Ui {
    pub addr: String,
    cookie: Arc<Mutex<Option<(String, String)>>>,
}

impl Ui {
    /// A web UI API call (the open loopback UI: a session from
    /// `/api/session`, its CSRF token on every change).
    pub fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (cookie, csrf) = {
            let mut c = self.cookie.lock().unwrap();
            if c.is_none() {
                let (status, headers, body) = http(&self.addr, "GET", "/api/session", &[], "");
                assert_eq!(status, 200, "{body}");
                let set = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                    .map(|(_, v)| v.split(';').next().unwrap_or("").to_string())
                    .expect("a session cookie");
                let v: Value = serde_json::from_str(&body).unwrap();
                *c = Some((set, v["csrf"].as_str().unwrap().to_string()));
            }
            c.clone().unwrap()
        };
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        let (status, _, text) = http(
            &self.addr,
            method,
            path,
            &[("Cookie", &cookie), ("x-nerve-csrf", &csrf)],
            &body,
        );
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// A fresh pairing link from the web UI.
    pub fn pair_link(&self) -> String {
        let (status, v) = self.api("POST", "/api/pair", Value::Null);
        assert_eq!(status, 200, "{v}");
        v["link"].as_str().unwrap().to_string()
    }

    /// Waits until `f` holds for the web UI's overview.
    pub fn wait_overview(&self, what: &str, f: impl Fn(&Value) -> bool) -> Value {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let (_, v) = self.api("GET", "/api/overview", Value::Null);
            if f(&v) {
                return v;
            }
            assert!(Instant::now() < until, "{what}: {v}");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn wait_exit(child: &mut Child, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A minimal HTTP/1.1 client: one request, `Connection: close`.
pub fn http(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, Vec<(String, String)>, String) {
    let mut s = TcpStream::connect(addr).expect("the web UI answers");
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, body.to_string())
}

/// A `nerve-node` with its own home, config and state folders under `root`.
pub struct Node {
    pub home: PathBuf,
    pub config: PathBuf,
    pub state: PathBuf,
    daemon: Option<Child>,
}

impl Node {
    pub fn new(root: &Path) -> Node {
        let n = Node {
            home: root.join("home"),
            config: root.join("config"),
            state: root.join("state"),
            daemon: None,
        };
        for d in [&n.home, &n.config, &n.state] {
            std::fs::create_dir_all(d).unwrap();
        }
        n
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(bin("nerve-node"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("NERVE_CONFIG_DIR", &self.config)
            .env("NERVE_STATE_DIR", &self.state)
            .current_dir(&self.home);
        cmd
    }

    /// Runs one CLI command: success, stdout, stderr.
    pub fn cli(&self, args: &[&str]) -> (bool, String, String) {
        let out = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("nerve-node runs");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Runs a CLI command that must succeed; its stdout.
    pub fn ok(&self, args: &[&str]) -> String {
        let (ok, out, err) = self.cli(args);
        assert!(ok, "nerve-node {args:?} failed: {out}{err}");
        out
    }

    /// Starts `nerve-node run` and waits for its control socket.
    pub fn start(&mut self) {
        let mut child = self
            .command()
            .arg("run")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("nerve-node run starts");
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[nerve-node] {line}");
            }
        });
        self.daemon = Some(child);
        let sock = self.state.join("run").join("ctl.sock");
        let until = Instant::now() + Duration::from_secs(30);
        while !sock.exists() {
            assert!(
                Instant::now() < until,
                "nerve-node run made no control socket"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Points `machine.sudo_path` at a script that acts like `sudo -S`
    /// with `right` as the only password, so no test asks this machine's
    /// sudo.
    pub fn use_fake_sudo(&self, right: &str) {
        let script = self.config.parent().unwrap().join("fake-sudo");
        let body = format!(
            "#!/bin/sh\nv=\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; -p) p=\"$2\"; shift 2 ;; \
             -v) v=1; shift ;; *) break ;; esac; done\nprintf %s \"$p\" >&2\nIFS= read -r pw\n\
             [ \"$pw\" = '{right}' ] || {{ echo 'Sorry, try again.' >&2; exit 1; }}\n\
             [ -n \"$v\" ] && exit 0\nexec \"$@\"\n"
        );
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Through the CLI: the node refuses a node.toml it did not sign.
        let path = script.display().to_string();
        self.ok(&["config", "set", "machine.sudo_path", &path]);
    }

    /// Stops the daemon, as a stop of the machine would.
    pub fn stop(&mut self) {
        if let Some(mut c) = self.daemon.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Whether the daemon has exited by itself.
    pub fn daemon_exited(&mut self) -> bool {
        self.daemon
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(c) = self.daemon.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The text of a tool result.
pub fn text_of(result: &Value) -> String {
    result["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}
