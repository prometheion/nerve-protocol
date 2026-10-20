"""Real runs through a local center and node: ordinary agent work, recorded
as the exact `state` the center sends to the decision model.

Starts a `nerve-center` (MCP over HTTP, plain loopback, state in a scratch
folder) and a `nerve-node` (its own home, config and state folders), pairs
them, puts the node in `user` mode (the tool chains live outside the work
folder) with a scratch work folder, and points the
center's decision model at a recorder: a small System One endpoint here that
answers 0 (allow) and writes every `state` it gets to a file. Then it plays
the task scripts from `realruns/*.json` as the agent would, through the MCP
`tools/call` surface. Afterwards it saves the center's audit feed beside the
recorded states.

Nothing here touches the owner's center or node: every folder is under
`--scratch` (default `$TMPDIR/realruns`), and the binaries are the worktree's
`target/release` builds.

    python realruns.py [--scratch DIR] [--out DIR] [task files...]

A task file is a JSON list of steps: `{"tool": "exec_run", "args": {...}}`
(arguments without `node`, which the driver fills in); `{"sleep": s}` waits.
`$WORK` in a string argument becomes the work folder.
"""

import argparse
import http.client
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from common import HERE, REPO, WORK

BIN = REPO / "target" / "release"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Recorder(http.server.BaseHTTPRequestHandler):
    """A System One endpoint that allows everything and keeps each state."""

    out = None
    lock = threading.Lock()

    def log_message(self, *a):
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"object": "list", "data": [
            {"id": "recorder", "architecture": {"output_modalities": ["decisions"]}}]})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n))
        with Recorder.lock, open(Recorder.out, "a", encoding="utf-8") as f:
            f.write(json.dumps(req.get("state"), ensure_ascii=False) + "\n")
        self._send({"answers": {"danger": {"noul": 0.0}}})


class Ui:
    """The center's open loopback web UI (session cookie + CSRF token)."""

    def __init__(self, addr):
        self.addr = addr
        host, port = addr.rsplit(":", 1)
        c = http.client.HTTPConnection(host, int(port), timeout=60)
        c.request("GET", "/api/session")
        r = c.getresponse()
        self.cookie = r.getheader("Set-Cookie").split(";")[0]
        self.csrf = json.loads(r.read())["csrf"]

    def api(self, method, path, body=None):
        host, port = self.addr.rsplit(":", 1)
        c = http.client.HTTPConnection(host, int(port), timeout=60)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Cookie": self.cookie, "x-nerve-csrf": self.csrf}
        if data:
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        text = r.read()
        try:
            return r.status, json.loads(text)
        except ValueError:
            return r.status, text.decode(errors="replace")


class Mcp:
    """An MCP client over the center's HTTP transport."""

    def __init__(self, addr, token):
        self.addr, self.token, self.session, self.next = addr, token, None, 1

    def request(self, method, params=None, timeout=600):
        host, port = self.addr.rsplit(":", 1)
        c = http.client.HTTPConnection(host, int(port), timeout=timeout)
        body = {"jsonrpc": "2.0", "id": self.next, "method": method}
        self.next += 1
        if params is not None:
            body["params"] = params
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        c.request("POST", "/mcp", body=json.dumps(body).encode(), headers=headers)
        r = c.getresponse()
        self.session = r.getheader("Mcp-Session-Id") or self.session
        text = r.read()
        return json.loads(text) if text else None

    def notify(self, method):
        host, port = self.addr.rsplit(":", 1)
        c = http.client.HTTPConnection(host, int(port), timeout=60)
        c.request("POST", "/mcp", body=json.dumps({"jsonrpc": "2.0", "method": method}).encode(),
                  headers={"Authorization": f"Bearer {self.token}",
                           "Content-Type": "application/json", "Mcp-Session-Id": self.session})
        c.getresponse().read()


def wait_for_line(proc, needle, log, limit=60):
    """Copies `proc`'s stderr to `log` and returns the first line with `needle`."""
    found = {}
    ev = threading.Event()

    def pump():
        with open(log, "a", encoding="utf-8") as f:
            for line in iter(proc.stderr.readline, b""):
                s = line.decode(errors="replace")
                f.write(s)
                f.flush()
                if needle in s and not ev.is_set():
                    found["line"] = s
                    ev.set()

    threading.Thread(target=pump, daemon=True).start()
    if not ev.wait(limit):
        raise SystemExit(f"no '{needle}' within {limit} s; see {log}")
    return found["line"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scratch", default=os.path.join(os.environ.get("TMPDIR", "/var/tmp"),
                                                      "realruns"))
    ap.add_argument("--out", default=str(WORK / "data" / "realruns"))
    ap.add_argument("tasks", nargs="*")
    a = ap.parse_args()
    scratch, out = Path(a.scratch), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tasks = [Path(t) for t in a.tasks] or sorted((HERE / "realruns").glob("*.json"))

    center_dir = scratch / "center"
    node = {k: scratch / "node" / k for k in ("home", "config", "state")}
    work = scratch / "work"
    for d in [center_dir, work, *node.values()]:
        d.mkdir(parents=True, exist_ok=True)

    states = out / "states.jsonl"
    Recorder.out = states
    rec_port = free_port()
    rec = http.server.ThreadingHTTPServer(("127.0.0.1", rec_port), Recorder)
    threading.Thread(target=rec.serve_forever, daemon=True).start()

    token = "realruns-harness-token"
    mcp_addr = f"127.0.0.1:{free_port()}"
    node_port = free_port()
    env = {"PATH": os.environ["PATH"], "HOME": str(center_dir), "NERVE_STATE_DIR": str(center_dir),
           "NERVE_NAME": "realruns", "NERVE_LISTEN": f"127.0.0.1:{node_port}",
           "NERVE_PLAIN_LOOPBACK": "true", "NERVE_PUBLIC_URL": f"http://127.0.0.1:{node_port}",
           "NERVE_UI": "127.0.0.1:0", "NERVE_UI_NO_LOGIN": "true", "NERVE_LOG": "info",
           "NERVE_MCP": "http", "NERVE_MCP_LISTEN": mcp_addr, "NERVE_HARNESS_TOKEN": token,
           "NERVE_CALL_WAIT": "600"}
    center = subprocess.Popen([str(BIN / "nerve-center")], env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    procs = [center]
    try:
        line = wait_for_line(center, "web UI at http://", scratch / "center.log")
        ui = Ui(line.split("web UI at http://", 1)[1].split()[0])
        st, v = ui.api("POST", "/api/pair")
        link = v["link"]

        # The node: its own folders; the tool caches of the real home so a
        # build does not download everything again.
        real = Path.home()
        nenv = {"PATH": os.environ["PATH"], "HOME": str(node["home"]),
                "NERVE_CONFIG_DIR": str(node["config"]), "NERVE_STATE_DIR": str(node["state"]),
                "CARGO_HOME": str(real / ".cargo"), "RUSTUP_HOME": str(real / ".rustup"),
                "npm_config_cache": str(real / ".npm"), "UV_CACHE_DIR": str(real / ".cache" / "uv")}

        def cli(*args):
            r = subprocess.run([str(BIN / "nerve-node"), *args], env=nenv, cwd=node["home"],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True)
            if r.returncode:
                raise SystemExit(f"nerve-node {args}: {r.stdout}{r.stderr}")
            return r.stdout

        cli("config", "set", "node.name", "devbox")
        cli("center", "add", link, "--yes")
        # `user` mode: the tool chains live outside the work folder (a
        # `folder` sandbox refuses ~/.cargo/bin/cargo). Every task stays in
        # the work folder by its own commands.
        cli("mode", "set", "user")
        nproc = subprocess.Popen([str(BIN / "nerve-node"), "run"], env=nenv, cwd=node["home"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE)
        procs.append(nproc)
        threading.Thread(target=lambda: [None for _ in iter(nproc.stderr.readline, b"")],
                         daemon=True).start()
        for _ in range(150):
            st, ov = ui.api("GET", "/api/overview")
            if ov["nodes"] and ov["nodes"][0].get("online") and ov["nodes"][0].get("capabilities"):
                break
            time.sleep(0.2)
        else:
            raise SystemExit(f"the node did not come online: {ov}")

        st, ck = ui.api("GET", "/api/checker")
        cfg = ck["config"]
        cfg["model_on"] = True
        cfg["model"].update({"source": "endpoint", "endpoint_url": f"http://127.0.0.1:{rec_port}",
                             "fail_closed": False, "scope": "with-reads"})
        st, v = ui.api("POST", "/api/checker", {"config": cfg})
        if st != 200:
            raise SystemExit(f"checker settings refused: {v}")

        mcp = Mcp(mcp_addr, token)
        mcp.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "realruns", "version": "0"}})
        mcp.notify("notifications/initialized")
        tools = {t["name"]: t for t in mcp.request("tools/list")["result"]["tools"]}
        (out / "tools.json").write_text(json.dumps(tools, indent=1))
        log = open(out / "calls.jsonl", "a", encoding="utf-8")
        for tf in tasks:
            print(f"== {tf.name}", flush=True)
            for step in json.loads(tf.read_text()):
                if "sleep" in step:
                    time.sleep(step["sleep"])
                    continue
                args = json.loads(json.dumps(step["args"]).replace("$WORK", str(work)))
                if "node" in tools[step["tool"]]["inputSchema"].get("properties", {}):
                    args = {"node": "devbox", **args}
                r = mcp.request("tools/call", {"name": step["tool"], "arguments": args})
                res = (r or {}).get("result", {})
                text = "".join(c.get("text", "") for c in res.get("content", []))
                print(("ERR " if res.get("isError") else "ok  ") + step["tool"] + " "
                      + json.dumps(step["args"])[:100] + " -> " + text.replace("\n", " ")[-160:],
                      flush=True)
                log.write(json.dumps({"task": tf.name, "tool": step["tool"], "args": args,
                                      "error": bool(res.get("isError")), "result": text[-2000:]},
                                     ensure_ascii=False) + "\n")
        log.close()
        st, audit = ui.api("GET", "/api/audit")
        (out / "audit.json").write_text(json.dumps(audit, indent=1, ensure_ascii=False))
    finally:
        for p in reversed(procs):
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        rec.shutdown()


if __name__ == "__main__":
    sys.exit(main())
