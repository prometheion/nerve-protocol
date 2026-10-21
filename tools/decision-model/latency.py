"""Latency of a decision model on a small CPU (issue #139): the target is about
2 vCPUs in a container. Starts `llama-server` (the pinned CPU build, with the
center's own arguments plus the options under test) limited to two cores, measures
its cold start (process start to health to first answer) and runs the repo's eval
runner on case files, `--reps` times each. Prints counts and metrics only: the
runner's output (which names failing commands) goes to log files.

    # locally: a systemd scope with two cores and a 200 % quota, no root needed
    python3 latency.py --label laya-q8 --gguf model-Q8_0.gguf --wrap systemd \
        --cpus 2,4 --threads 2 --batch 2048 --state-bytes 320 \
        --runner CHECKER_EVAL_BINARY --cases c214=crates/nerve-center/tests/data/checker-eval.json
    # on a container: taskset (or no wrapper when the container is already limited)
    python3 latency.py --label laya-q8 --gguf model-Q8_0.gguf --wrap taskset --cpus 0,1 ...

d1-3B and Kev-4B: `--state-bytes 2000` and no `--batch`, as the center runs them.

`--runner` is the compiled eval runner (`cargo test -p nerve-center --test
checker_eval --no-run`; a binary built here also runs on another Linux machine),
so no Rust toolchain is needed on the machine under test.
"""

import argparse
import http.client
import json
import os
import re
import shlex
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = Path(os.environ.get("NERVE_TRAINING_DIR", Path.home() / "Services" / "nerve-training"))
LLAMA_BIN = Path(os.environ.get("NERVE_LLAMA_BIN", WORK / "llama" / "bin-b11719" / "llama-b11719"))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def evict(path):
    """Drop the model file from the page cache (clean pages, no root needed)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)


def percentile(values, p):
    """The runner's definition: the value at round((n - 1) * p) of the sorted list."""
    v = sorted(values)
    return v[round((len(v) - 1) * p)]


def wrapper(a):
    if a.wrap == "systemd":
        return ["systemd-run", "--user", "--scope", "-q", "-p", f"AllowedCPUs={a.cpus}",
                "-p", f"CPUQuota={a.quota}%", "-p", f"MemoryMax={a.mem}",
                "-p", "MemorySwapMax=0", "--"]
    if a.wrap == "taskset":
        return ["taskset", "-c", a.cpus]
    return []


def server_args(a, port):
    args = ["-m", str(a.gguf), "--host", "127.0.0.1", "--port", str(port), "-ngl", "0"]
    if a.threads:
        args += ["-t", str(a.threads)]
    if a.threads_batch:
        args += ["-tb", str(a.threads_batch)]
    if a.batch:
        args += ["-b", str(a.batch), "-ub", str(a.batch)]
    if a.no_mmap:
        args.append("--no-mmap")
    if a.mlock:
        args.append("--mlock")
    return args + shlex.split(a.extra)


def post(port, body, timeout=120):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("POST", "/v1/systemone", json.dumps(body), {"Content-Type": "application/json"})
        r = conn.getresponse()
        data = r.read()
        return r.status, data
    finally:
        conn.close()


def start_server(a, log_path):
    """Starts llama-server; returns (proc, port, seconds to health, seconds to the first answer)."""
    port = free_port()
    env = dict(os.environ, LD_LIBRARY_PATH=f"{a.bin}:{os.environ.get('LD_LIBRARY_PATH', '')}",
               CUDA_VISIBLE_DEVICES="")
    cmd = wrapper(a) + [str(a.bin / "llama-server"), *server_args(a, port)]
    log = open(log_path, "w")
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)
    ready = None
    while time.perf_counter() - t0 < 600:
        if proc.poll() is not None:
            raise RuntimeError(f"llama-server exited with {proc.returncode}; see {log_path}")
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/health")
            if c.getresponse().status == 200:
                ready = time.perf_counter() - t0
                break
        except OSError:
            pass
        time.sleep(0.01)
    if ready is None:
        proc.kill()
        raise RuntimeError(f"llama-server did not come up; see {log_path}")
    status, _ = post(port, first_body(a))
    first = time.perf_counter() - t0
    if status != 200:
        raise RuntimeError(f"the first answer was HTTP {status}")
    return proc, port, ready, first


def first_body(a):
    import common
    state = common.model_state("exec", "run", "ls -la", "linux", False, None, a.state_bytes)
    return {"state": state, "questions": common.question()}


def stop(proc):
    proc.terminate()
    try:
        proc.wait(30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def proc_kb(pid, key):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith(key + ":"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def cgroup_stats(pid):
    """CPU throttling and peak memory of the server's cgroup, when readable."""
    out = {}
    try:
        rel = open(f"/proc/{pid}/cgroup").read().strip().split("::")[-1]
        base = Path("/sys/fs/cgroup") / rel.lstrip("/")
        for line in (base / "cpu.stat").read_text().splitlines():
            k, v = line.split()
            if k in ("nr_periods", "nr_throttled", "throttled_usec"):
                out[k] = int(v)
        peak = base / "memory.peak"
        if peak.exists():
            out["memory_peak_mb"] = round(int(peak.read_text()) / 2**20)
    except (OSError, ValueError):
        pass
    return out


def run_runner(a, port, case_file, scores_out, log_file, state_bytes):
    env = dict(os.environ, NERVE_CHECKER_ENDPOINT=f"http://127.0.0.1:{port}",
               NERVE_CHECKER_EVAL_FILE=str(case_file), NERVE_CHECKER_SCORES_OUT=str(scores_out),
               NERVE_CHECKER_TIMEOUT_MS=str(a.timeout_ms),
               NERVE_CHECKER_STATE_BYTES=str(state_bytes))
    pre = ["taskset", "-c", a.runner_cpus] if a.runner_cpus else []
    res = subprocess.run(pre + [str(a.runner), "--ignored", "--nocapture"], env=env,
                         capture_output=True, text=True)
    Path(log_file).write_text(res.stdout + res.stderr, encoding="utf-8")
    m = re.search(r"(\d+) cases scored, (\d+) failed", res.stdout)
    if res.returncode != 0 or not m:
        raise RuntimeError(f"the eval runner failed on {case_file}; see {log_file}")
    return int(m.group(1)), int(m.group(2))


def read_scores(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def summarize(rows, failed):
    ms = [r["ms"] for r in rows]
    return {"n": len(rows), "failed": failed, "p50": round(percentile(ms, 0.5)),
            "p95": round(percentile(ms, 0.95)), "max": round(max(ms)),
            "mean": round(statistics.mean(ms)),
            "over_4000": sum(m > 4000 for m in ms), "over_5000": sum(m > 5000 for m in ms)}


def cmd_run(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cases = dict(c.split("=", 1) for c in a.cases)
    res = {"label": a.label, "gguf": Path(a.gguf).name, "model_mb": round(Path(a.gguf).stat().st_size / 2**20),
           "wrap": a.wrap, "cpus": a.cpus, "quota": a.quota, "threads": a.threads,
           "threads_batch": a.threads_batch, "batch": a.batch, "state_bytes": a.state_bytes,
           "no_mmap": a.no_mmap, "mlock": a.mlock, "extra": a.extra,
           "load_before": [round(x, 2) for x in os.getloadavg()]}
    # Cold start: with the model file evicted from the page cache, then with it cached.
    cold = []
    for kind in ["disk"] * a.cold_reps + ["cached"] * a.cold_reps:
        if kind == "disk":
            evict(a.gguf)
        proc, port, ready, first = start_server(a, out / f"{a.label}.server.log")
        cold.append({"file": kind, "health_s": round(ready, 2), "first_answer_s": round(first, 2)})
        stop(proc)
    res["cold_start"] = cold
    for kind in ("disk", "cached"):
        rows = [c for c in cold if c["file"] == kind]
        if rows:
            res[f"cold_{kind}_median"] = {
                "health_s": round(statistics.median(c["health_s"] for c in rows), 2),
                "first_answer_s": round(statistics.median(c["first_answer_s"] for c in rows), 2)}
    # Steady state: one server, a warm-up call from the start, then the case files.
    evict(a.gguf)
    proc, port, ready, first = start_server(a, out / f"{a.label}.server.log")
    res["first_call_after_evict_s"] = round(first - ready, 2)
    log = open(out / f"{a.label}.server.log").read()
    m = re.search(r"n_threads = (\d+)", log)
    res["server_threads"] = int(m.group(1)) if m else None
    res["steady"] = {}
    try:
        for name, path in cases.items():
            reps = []
            for i in range(a.reps):
                sc = out / f"{a.label}.{name}.rep{i}.scores.jsonl"
                n, failed = run_runner(a, port, path, sc, out / f"{a.label}.{name}.rep{i}.log",
                                       a.state_bytes)
                reps.append(summarize(read_scores(sc), failed))
            res["steady"][name] = {
                "reps": reps,
                "median_p50": round(statistics.median(r["p50"] for r in reps)),
                "median_p95": round(statistics.median(r["p95"] for r in reps)),
                "median_mean": round(statistics.median(r["mean"] for r in reps)),
                "max": max(r["max"] for r in reps)}
        res["rss_mb"] = round((proc_kb(proc.pid, "VmRSS") or 0) / 1024)
        res["rss_peak_mb"] = round((proc_kb(proc.pid, "VmHWM") or 0) / 1024)
        res["cgroup"] = cgroup_stats(proc.pid)
    finally:
        stop(proc)
    res["load_after"] = [round(x, 2) for x in os.getloadavg()]
    (out / f"{a.label}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    c = res.get("cold_disk_median", {})
    print(f"{a.label}: threads {res['server_threads']}, rss {res['rss_mb']} MB (peak {res['rss_peak_mb']}), "
          f"cold start disk {c.get('health_s')}/{c.get('first_answer_s')} s, "
          f"load {res['load_before'][0]} -> {res['load_after'][0]}, cgroup {res['cgroup']}")
    for name, s in res["steady"].items():
        print(f"  {name}: median p50 {s['median_p50']} ms, p95 {s['median_p95']} ms, "
              f"reps p50 {[r['p50'] for r in s['reps']]}, failed {[r['failed'] for r in s['reps']]}, "
              f"over 4 s {[r['over_4000'] for r in s['reps']]}"
              )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--gguf", required=True, type=Path)
    ap.add_argument("--cases", nargs="+", required=True, help="NAME=FILE ...")
    ap.add_argument("--runner", type=Path, required=True)
    ap.add_argument("--bin", type=Path, default=LLAMA_BIN)
    ap.add_argument("--out", default=str(WORK / "runs" / "latency"))
    ap.add_argument("--wrap", choices=["systemd", "taskset", "none"], default="none")
    ap.add_argument("--cpus", default="0,1")
    ap.add_argument("--quota", default="200")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--runner-cpus", default=None, help="cores for the eval runner (taskset)")
    ap.add_argument("--threads", type=int, default=0, help="-t; 0 = the center's default (none)")
    ap.add_argument("--threads-batch", type=int, default=0)
    ap.add_argument("--batch", type=int, default=0, help="-b and -ub; 0 = the default")
    ap.add_argument("--state-bytes", type=int, default=320)
    ap.add_argument("--no-mmap", action="store_true")
    ap.add_argument("--mlock", action="store_true")
    ap.add_argument("--extra", default="", help='more llama-server arguments, e.g. "-c 4096 -np 1"')
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--cold-reps", type=int, default=3)
    ap.add_argument("--timeout-ms", type=int, default=120000)
    a = ap.parse_args()
    sys.path.insert(0, str(HERE))
    cmd_run(a)


if __name__ == "__main__":
    main()
