"""The whole chain in one command: prepare -> train -> export -> evaluate.

    venv/bin/python pipeline.py --name laya-v1            # the owner's files
    venv/bin/python pipeline.py --name laya-dry --dry-run # real runs only

Every step is its own script (see the README) and can be run alone; this
only runs them in order with matching folders:

- data:     data/prepared/        (data/prepared-dry/ with --dry-run; trajectories.py
            first if data/trajectories/ is not there yet)
- model:    runs/<name>/merged/   (train.py)
- GGUF:     runs/<name>/gguf/     (export.py)
- results:  runs/<name>/eval/     (evaluate.py: the 214 cases + each held-out file)

The next round's sweep is one command too (`--sweep`, see "The sweep" below).

`--with-base` also evaluates the untouched model's GGUF (`runs/laya-base/gguf`,
made once by `export.py --checkpoint hf/laya --out runs/laya-base/gguf`) on
the same held-out files, for the base-vs-fine-tuned comparison. Arguments
after `--` go to train.py (e.g. `-- --mode full --epochs 3`).

The sweep (`--sweep`): full fine-tuning of Laya on the round-3 data choice
(2.8 harmless rows per dangerous one, no extra trajectories: `all-t0`) in the
variants of the next round: the decision head's learning rate on (1e-4 beside
the encoder's 2e-5) or off (`--head-lr body`), the top 12 encoder layers or all
of them, and the injection rows repeated 1x, 3x or 5x in train.jsonl
(`--factors`). Every combination (`--grid full`, 12 runs) or the baseline and
one change at a time (`--grid one-at-a-time`, 5 runs) goes through prepare ->
train -> export -> evaluate, two at a time (`--gpus 0,1`, one run per GPU), each
step skipped when its output is there, and `compare.py` writes one table of
all of them next to the round-3 references. Temperature and threshold come from
the dev file (`--dev`, the v3.1 dev for now; the independent dev later), the
benchmark is `--test` (several allowed); the 214 cases are scored but never
used to choose anything. `--plan` only prepares the data and prints the counts
and the list of runs (no GPU, no training). `--smoke` trains a few steps of one
variant and scores it on dev and the 214, but only when every GPU in `--gpus`
is idle; otherwise it says so and does nothing.
"""

import argparse
import concurrent.futures
import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from common import HERE, WORK

# The round-3 data choice (docs/dev/action-checker.md, "Third round"): every
# harmless row of the pool (2.8 per dangerous one), no extra trajectories.
ROUND3_PREPARE = ["--max-harmless-ratio", "99", "--trajectory-ratio", "0"]
HEAD_VARIANTS = {"hlr": [], "nohlr": ["--head-lr", "body"]}
TOP_VARIANTS = {"all": [], "top12": ["--top-layers", "12"]}
FACTORS = (1, 3, 5)
REFERENCES = ["laya-full-all-t0", "d1-3B:eval-v3.1"]
# A GPU counts as idle below these (the desktop and a resident model take some).
IDLE_UTIL, IDLE_MEM_MIB = 5, 1024


def run(script, *args):
    cmd = [sys.executable, str(HERE / script), *map(str, args)]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def variants(grid, factors):
    """The (head, top, factor) combinations of the sweep: all of them, or the
    baseline (head LR on, all layers, the first factor) with one change at a time."""
    if grid == "full":
        return [(h, t, f) for f in factors for t in TOP_VARIANTS for h in HEAD_VARIANTS]
    base = ("hlr", "all", factors[0])
    out = [base, ("nohlr", "all", factors[0]), ("hlr", "top12", factors[0])]
    return out + [("hlr", "all", f) for f in factors[1:]]


def variant_name(prefix, v):
    return f"{prefix}-{v[0]}-{v[1]}-os{v[2]:g}"


def train_flags(v):
    """The train.py flags of a variant (full fine-tuning is the default of the sweep)."""
    return ["--mode", "full", *HEAD_VARIANTS[v[0]], *TOP_VARIANTS[v[1]]]


def gpu_state(gpus):
    """[(index, utilisation %, memory MiB)] of the GPUs from nvidia-smi."""
    res = subprocess.run(["nvidia-smi", "--query-gpu=index,utilization.gpu,memory.used",
                          "--format=csv,noheader,nounits"], capture_output=True, text=True)
    return parse_gpu_state(res.stdout, gpus)


def parse_gpu_state(text, gpus):
    rows = [tuple(int(x) for x in line.split(",")) for line in text.strip().splitlines() if line.strip()]
    return [r for r in rows if r[0] in gpus]


def busy_gpus(state, gpus, max_util=IDLE_UTIL, max_mem=IDLE_MEM_MIB):
    """The wanted GPUs that are not idle (or not there at all), as text."""
    seen = {i: (u, m) for i, u, m in state}
    out = []
    for g in gpus:
        if g not in seen:
            out.append(f"GPU {g}: not found")
        elif seen[g][0] > max_util or seen[g][1] > max_mem:
            out.append(f"GPU {g}: {seen[g][0]} % busy, {seen[g][1]} MiB used")
    return out


def prepared_dir(factor):
    return WORK / "data" / "next" / f"os{factor:g}"


def prepare_all(factors, owner, blocks):
    """prepare.py once per oversampling factor (the held-out files come out the same).
    Its counts go to `<prepared>/stats.json`; the pipeline prints a line of them."""
    for f in factors:
        cmd = [sys.executable, str(HERE / "prepare.py"), "--out", str(prepared_dir(f)),
               "--owner", str(owner), *ROUND3_PREPARE, "--injection-oversample", str(f),
               *(["--block", *map(str, blocks)] if blocks else [])]
        print("+", " ".join(cmd), flush=True)
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def counts_line(folder):
    """One line of counts from a prepared folder's stats.json."""
    st = json.loads((folder / "stats.json").read_text(encoding="utf-8"))
    t, c, o = st["train"], st["calib"], st["oversample"]
    return (f"{folder.name}: train {t['danger']} dangerous / {t['harmless']} harmless, injection "
            f"{t.get('injection_danger', 0)} + {t.get('injection_harmless', 0)} "
            f"({100 * o['injection_share_after']:.1f} % of {o['train_rows_after']} rows; "
            f"{o['injection_rows_before']} injection rows x {o['factor']:g}, "
            f"{o['injection_variants']} distinct), calib {c['danger']} / {c['harmless']} (not oversampled)")


def chain(name, v, gpu, data, dev, tests, extra, log, train_extra=()):
    """train -> export -> evaluate of one variant on one GPU; a step whose
    output is there is skipped, so an interrupted sweep resumes."""
    env = dict(os.environ, CUDA_VISIBLE_DEVICES=str(gpu))
    run_dir = WORK / "runs" / name
    steps = [
        ("train", run_dir / "train.json",
         ["train.py", "--data", data, "--name", name, "--out", run_dir, *train_flags(v),
          "--calib-cases", dev, *train_extra, *extra]),
        ("export", run_dir / "gguf" / "export-summary.json",
         ["export.py", "--checkpoint", run_dir / "merged", "--out", run_dir / "gguf"]),
        ("evaluate", run_dir / "eval" / "results.json",
         ["evaluate.py", "--gguf", run_dir / "gguf" / "model-Q8_0.gguf", "--name", name,
          "--heldout", dev, *tests, "--cpu-check", "0", "--out", run_dir / "eval"]),
    ]
    for step, marker, cmd in steps:
        if marker.exists():
            continue
        cmd = [sys.executable, str(HERE / cmd[0]), *map(str, cmd[1:])]
        log.write("+ " + " ".join(cmd) + "\n")
        log.flush()
        subprocess.run(cmd, check=True, env=env, stdout=log, stderr=subprocess.STDOUT)


def run_sweep(a, extra):
    factors = [5] if a.smoke else a.factors
    plan = variants(a.grid, a.factors)
    gpus = [int(g) for g in a.gpus.split(",")]
    blocks = [p for p in [a.dev, *(a.test or [])] if p]
    if not a.skip_prepare:
        if not a.owner.exists():
            raise SystemExit(f"no owner data at {a.owner}")
        prepare_all(factors, a.owner, blocks)
    for f in factors:
        print(counts_line(prepared_dir(f)), flush=True)
    first = prepared_dir(factors[0])
    dev = a.dev or first / "heldout-v3-dev.json"
    tests = a.test or [first / "heldout-v3-benchmark.json"]
    if a.smoke:
        return smoke(a, gpus, dev, extra)
    names = [variant_name(a.prefix, v) for v in plan]
    print(f"{len(plan)} runs on GPU {', '.join(map(str, gpus))}:", flush=True)
    for n, v in zip(names, plan):
        print(f"  {n}: {' '.join(train_flags(v))} on {prepared_dir(v[2]).name}", flush=True)
    if a.plan:
        print("plan only: nothing trained")
        return 0

    lock, queue, failed = threading.Lock(), list(zip(names, plan)), []

    def worker(gpu):
        while True:
            with lock:
                if not queue:
                    return
                name, v = queue.pop(0)
            log_path = WORK / "logs" / f"{name}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"start {name} on GPU {gpu} (log {log_path})", flush=True)
            try:
                with open(log_path, "a") as log:
                    chain(name, v, gpu, prepared_dir(v[2]), dev, tests, extra, log)
                print(f"done {name}", flush=True)
            except subprocess.CalledProcessError as e:
                print(f"FAILED {name}: step exited with {e.returncode}, see {log_path}", flush=True)
                with lock:
                    failed.append(name)

    with concurrent.futures.ThreadPoolExecutor(len(gpus)) as pool:
        for f in [pool.submit(worker, g) for g in gpus]:
            f.result()
    done = [n for n in names if n not in failed]
    if done:
        report = WORK / "runs" / f"{a.prefix}-compare.md"
        refs = [r for r in a.refs if (WORK / "runs" / r.split(":")[0]).exists()]
        run("compare.py", "--runs", *done, *refs, "--dev", dev, "--test", *tests, "--also", 0.8,
            "--fpr", 1, 3, 5, "--out", report)
        print(f"comparison: {report}")
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


def smoke(a, gpus, dev, extra):
    """A few steps of one variant (head LR off, top 12, 5x) end to end, only on idle GPUs."""
    busy = busy_gpus(gpu_state(gpus), gpus)
    if busy:
        print("smoke run skipped, GPUs not idle: " + "; ".join(busy))
        return 0
    v = ("nohlr", "top12", 5)
    name = f"{a.prefix}-smoke"
    log_path = WORK / "logs" / f"{name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as log:
        chain(name, v, gpus[0], prepared_dir(v[2]), dev, [], extra, log,
              train_extra=["--max-steps", "4", "--epochs", "1"])
    record = json.loads((WORK / "runs" / name / "train.json").read_text())
    print(json.dumps({k: record[k] for k in ("lr", "head_lr", "top_layers", "encoder_params_trainable",
                                             "calib_source", "calib_items", "train_loss", "minutes")}))
    print(f"smoke run ok (log {log_path}); removing runs/{name}")
    shutil.rmtree(WORK / "runs" / name)
    return 0


def main():
    argv = sys.argv[1:]
    extra = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--name", help="the run's name (not needed for --sweep)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--owner", type=Path, default=WORK / "data" / "owner")
    ap.add_argument("--with-base", action="store_true")
    ap.add_argument("--skip-prepare", action="store_true", help="reuse the prepared data")
    sw = ap.add_argument_group("the sweep")
    sw.add_argument("--sweep", action="store_true", help="run the next round's variants")
    sw.add_argument("--plan", action="store_true",
                    help="with --sweep: prepare the data, print counts and the run list, stop")
    sw.add_argument("--smoke", action="store_true",
                    help="with --sweep: a few training steps of one variant, only on idle GPUs")
    sw.add_argument("--prefix", default="laya-nx", help="run names are PREFIX-<head>-<top>-os<N>")
    sw.add_argument("--grid", choices=["full", "one-at-a-time"], default="full")
    sw.add_argument("--factors", type=int, nargs="+", default=list(FACTORS),
                    help="injection oversampling factors (1 = off)")
    sw.add_argument("--gpus", default="0,1", help="one run at a time per listed GPU")
    sw.add_argument("--dev", type=Path, default=None,
                    help="dev case file: temperature, threshold (default: the prepared v3.1 dev)")
    sw.add_argument("--test", type=Path, nargs="*", default=None,
                    help="test case files (default: the prepared v3.1 benchmark)")
    sw.add_argument("--refs", nargs="*", default=REFERENCES,
                    help="runs to put in the table beside the sweep (NAME[:SUBFOLDER])")
    a = ap.parse_args(argv)
    if a.sweep:
        raise SystemExit(run_sweep(a, extra))
    if not a.name:
        ap.error("--name is required (or use --sweep)")

    data = WORK / "data" / ("prepared-dry" if a.dry_run else "prepared")
    run_dir = WORK / "runs" / a.name
    if not a.skip_prepare:
        if not a.dry_run and not (WORK / "data" / "trajectories" / "actions.jsonl").exists():
            run("trajectories.py")
        run("prepare.py", "--out", data, *(["--dry-run"] if a.dry_run else ["--owner", a.owner]))
    run("train.py", "--data", data, "--name", a.name, "--out", run_dir, *extra)
    run("export.py", "--checkpoint", run_dir / "merged", "--out", run_dir / "gguf")
    gguf = next((run_dir / "gguf").glob("*.gguf"))
    run("evaluate.py", "--gguf", gguf, "--name", a.name, "--prepared", data,
        "--out", run_dir / "eval")
    if a.with_base:
        base = WORK / "runs" / "laya-base"
        run("evaluate.py", "--gguf", next((base / "gguf").glob("*.gguf")), "--name",
            f"laya-base-vs-{a.name}", "--prepared", data, "--cpu-check", "0",
            "--out", run_dir / "eval-base")
    print(f"results: {run_dir / 'eval' / 'results.md'}")


if __name__ == "__main__":
    main()
