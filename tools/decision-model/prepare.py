"""Turn the owner's command files and the recorded real runs into training,
calibration and held-out files for the decision model.

The owner builds the labelled command files himself (see the README); this
script only reads them by path, as data. It never prints a command: its output
is counts. Inputs, each optional except as noted:

- `<owner>/shellsafety-train.jsonl`, `<owner>/shellsafety-heldout.jsonl`
  (required unless `--dry-run`), `<owner>/extra-train.jsonl`,
  `<owner>/extra-heldout.jsonl`: one `{"command", "os", "danger", "category",
  "source"}` per line.
- `--realruns` (default `data/realruns/states.jsonl`): states recorded by
  `realruns.py`, all ordinary work, so harmless.

What it does, in order:

1. Each training command becomes a row `{"state", "questions", "gold"}`:
   the state the center sends for `exec.run` (`tainted` for a random 15 %,
   the call's `args` as the center sends them for `--args-share` of the rows,
   since the center always sends them in production but the 214 cases do
   not), the center's question or, for 25 %, one of the paraphrases, and
   `"gold": {"danger": <bool>}`. Real-run states keep their own state.
2. Near-duplicates (same capability and `common.canonical` form) keep one row;
   a group whose rows disagree on the label is dropped whole.
3. Every row whose key matches a held-out row or one of the 214 evaluation
   cases is dropped.
4. Harmless rows are capped at `--max-harmless-ratio` per dangerous row (the
   real runs are kept first, then a random sample of the rest).
5. A stratified `--calib-share` of the rows goes to `calib.jsonl` (fitting the
   temperature after training), the rest to `train.jsonl`.
6. Each held-out file is written in the eval runner's case format
   (`heldout-<name>.json`, see crates/nerve-center/tests/checker_eval.rs).

`--dry-run` uses only the real runs: a part of them becomes the held-out file
`heldout-realruns.json`, and there is no balancing (there is nothing
dangerous). It proves the chain, not the model.

    python prepare.py [--owner DIR] [--out DIR] [--dry-run]
"""

import argparse
import collections
import json
import random
import sys
from pathlib import Path

import common
from common import WORK

# Working folders an agent's command plausibly runs in, for the `args` the
# center sends (`{"command", "cwd"}`). Neutral placeholders, no real setup.
CWDS = {
    "linux": ["/home/user/project", "/home/user/src/app", "/srv/app", "/workspace",
              "/home/dev/code/service", "/opt/build"],
    "windows": ["C:\\Users\\user\\project", "C:\\src\\app", "D:\\work\\service",
                "C:\\Users\\dev\\source\\repos\\tool"],
}


def owner_rows(path):
    """The owner's rows, checked for the fields this script needs (by
    structure only; the commands are not looked at)."""
    rows = common.load_jsonl(path)
    bad = 0
    out = []
    for r in rows:
        if (isinstance(r.get("command"), str) and r["command"].strip()
                and r.get("os") in ("linux", "windows") and isinstance(r.get("danger"), bool)):
            out.append(r)
        else:
            bad += 1
    return out, bad


def key(cap, target):
    return (cap, common.canonical(target))


def command_state(rng, command, os_name, args_share, tainted_share):
    args = None
    if rng.random() < args_share:
        args = {"command": command, "cwd": rng.choice(CWDS[os_name])}
    return common.model_state("exec", "run", command, os_name,
                              tainted=rng.random() < tainted_share, args=args)


def pick_question(rng, paraphrase_share):
    if rng.random() < paraphrase_share:
        return common.question(*rng.choice(common.PARAPHRASES))
    return common.question()


def case_from_command(r):
    """A held-out command in the eval runner's case format."""
    return {"cap": "exec", "action": "run", "target": common.clip(r["command"], 2000),
            "os": r["os"], "danger": r["danger"],
            "kind": "dangerous" if r["danger"] else "benign",
            "category": r.get("category", ""), "source": r.get("source", "")}


def case_from_state(st):
    c = {"cap": st["capability"], "action": st["action"], "target": st["target"],
         "os": st["os"], "danger": False, "kind": "benign", "category": "realrun",
         "source": "realruns"}
    if "args" in st:
        c["args"] = st["args"]
    return c


def split_stratified(rng, rows, share):
    by = collections.defaultdict(list)
    for r in rows:
        by[r["gold"]["danger"]].append(r)
    a, b = [], []
    for label in sorted(by):
        group = by[label][:]
        rng.shuffle(group)
        n = round(len(group) * share)
        if share > 0 and len(group) > 1:
            n = max(n, 1)
        b.extend(group[:n])
        a.extend(group[n:])
    rng.shuffle(a)
    rng.shuffle(b)
    return a, b


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--owner", type=Path, default=WORK / "data" / "owner")
    ap.add_argument("--realruns", type=Path, default=WORK / "data" / "realruns" / "states.jsonl")
    ap.add_argument("--out", type=Path, default=None,
                    help="default data/prepared (data/prepared-dry with --dry-run)")
    ap.add_argument("--dry-run", action="store_true",
                    help="only the real runs, a part of them held out")
    ap.add_argument("--seed", type=int, default=139)
    ap.add_argument("--tainted-share", type=float, default=0.15)
    ap.add_argument("--paraphrase-share", type=float, default=0.25)
    ap.add_argument("--args-share", type=float, default=0.5)
    ap.add_argument("--max-harmless-ratio", type=float, default=1.5)
    ap.add_argument("--calib-share", type=float, default=0.1)
    ap.add_argument("--dry-heldout-share", type=float, default=0.2)
    a = ap.parse_args()
    out = a.out or WORK / "data" / ("prepared-dry" if a.dry_run else "prepared")
    rng = random.Random(a.seed)
    stats = {"inputs": {}, "dropped": collections.Counter()}

    # ---- held-out sources
    heldout = {}  # name -> list of eval cases
    train_cmds = []  # owner command rows for training
    if not a.dry_run:
        for name in ("shellsafety", "extra"):
            tr, ho = a.owner / f"{name}-train.jsonl", a.owner / f"{name}-heldout.jsonl"
            if name == "shellsafety" and not (tr.exists() and ho.exists()):
                sys.exit(f"missing {tr} or {ho} (or use --dry-run)")
            if tr.exists():
                rows, bad = owner_rows(tr)
                stats["inputs"][tr.name] = {"rows": len(rows), "malformed": bad,
                                            "danger": sum(r["danger"] for r in rows)}
                train_cmds.extend(rows)
            if ho.exists():
                rows, bad = owner_rows(ho)
                stats["inputs"][ho.name] = {"rows": len(rows), "malformed": bad,
                                            "danger": sum(r["danger"] for r in rows)}
                heldout[name] = [case_from_command(r) for r in rows]

    states = common.load_jsonl(a.realruns) if a.realruns.exists() else []
    stats["inputs"]["realruns"] = {"rows": len(states), "danger": 0}
    if a.dry_run:
        states = states[:]
        rng.shuffle(states)
        n = round(len(states) * a.dry_heldout_share)
        heldout["realruns"] = [case_from_state(s) for s in states[:n]]
        states = states[n:]

    # ---- training rows
    rows = []
    for r in train_cmds:
        rows.append({"state": command_state(rng, r["command"], r["os"], a.args_share, a.tainted_share),
                     "questions": pick_question(rng, a.paraphrase_share),
                     "gold": {"danger": r["danger"]},
                     "_src": r.get("source", "owner")})
    for st in states:
        rows.append({"state": dict(sorted(st.items())),
                     "questions": pick_question(rng, a.paraphrase_share),
                     "gold": {"danger": False}, "_src": "realruns"})

    # ---- near-duplicates: keep one per key, drop groups with both labels
    groups = collections.OrderedDict()
    for r in rows:
        groups.setdefault(key(r["state"]["capability"], r["state"]["target"]), []).append(r)
    kept = []
    for g in groups.values():
        labels = {r["gold"]["danger"] for r in g}
        if len(labels) > 1:
            stats["dropped"]["conflicting_label_group_rows"] += len(g)
            continue
        stats["dropped"]["near_duplicate"] += len(g) - 1
        # prefer a real-run row: it carries the state exactly as recorded
        g.sort(key=lambda r: r["_src"] != "realruns")
        kept.append(g[0])

    # ---- keep the held-out splits and the 214 cases out of training
    blocked = set()
    for cases in heldout.values():
        blocked.update(key(c["cap"], c["target"]) for c in cases)
    eval214 = json.loads(common.EVAL_214.read_text(encoding="utf-8"))
    blocked_214 = {key(c["cap"], c["target"]) for c in eval214}
    clean = []
    for r in kept:
        k = key(r["state"]["capability"], r["state"]["target"])
        if k in blocked_214:
            stats["dropped"]["matches_214_eval"] += 1
        elif k in blocked:
            stats["dropped"]["matches_heldout"] += 1
        else:
            clean.append(r)

    # ---- balance: at most max_harmless_ratio harmless rows per dangerous one
    danger = [r for r in clean if r["gold"]["danger"]]
    harmless = [r for r in clean if not r["gold"]["danger"]]
    if not a.dry_run:
        cap = int(len(danger) * a.max_harmless_ratio)
        if len(harmless) > cap:
            real = [r for r in harmless if r["_src"] == "realruns"]
            rest = [r for r in harmless if r["_src"] != "realruns"]
            rng.shuffle(rest)
            keep = real[:cap] + rest[:max(0, cap - len(real))]
            stats["dropped"]["balance"] += len(harmless) - len(keep)
            harmless = keep
    final = danger + harmless
    rng.shuffle(final)

    train, calib = split_stratified(rng, final, a.calib_share)
    out.mkdir(parents=True, exist_ok=True)
    srcs = collections.Counter()
    for part in (train, calib):
        for r in part:
            srcs[r.pop("_src")] += 1
    common.write_jsonl(out / "train.jsonl", train)
    common.write_jsonl(out / "calib.jsonl", calib)
    for name, cases in heldout.items():
        (out / f"heldout-{name}.json").write_text(
            json.dumps(cases, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    def counts(part):
        c = collections.Counter()
        for r in part:
            c["danger" if r["gold"]["danger"] else "harmless"] += 1
            c["os_" + r["state"]["os"]] += 1
            c["tainted"] += r["state"]["tainted"]
            c["with_args"] += "args" in r["state"]
            c["paraphrased"] += r["questions"] != common.question()
        return dict(sorted(c.items()))

    stats["dropped"] = dict(stats["dropped"])
    stats["train"] = counts(train)
    stats["calib"] = counts(calib)
    stats["sources"] = dict(srcs)
    stats["heldout"] = {
        name: {"cases": len(cases), "danger": sum(c["danger"] for c in cases)}
        for name, cases in heldout.items()}
    stats["out"] = str(out)
    (out / "stats.json").write_text(json.dumps(stats, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
