"""Turn the owner's command files and the recorded real runs into training,
calibration and held-out files for the decision model.

The owner builds the labelled command files himself (see the README); this
script only reads them by path, as data. It never prints a command: its output
is counts. Inputs, each optional except as noted:

- `<owner>/shellsafety-v2-train.jsonl`, `<owner>/shellsafety-v2-heldout.jsonl`
  (the second build, with shell-safety's `deny` rows split by reason code;
  used when both are there, see `--shellsafety`) or else
  `<owner>/shellsafety-train.jsonl`, `<owner>/shellsafety-heldout.jsonl`
  (required unless `--dry-run`), `<owner>/extra-train.jsonl`,
  `<owner>/extra-heldout.jsonl`: one `{"command", "os", "danger", "category",
  "source"}` per line, v2 rows also with `reason`. `<owner>/reason-classes.json`
  (v2) only feeds the counts per reason class.
- `--realruns` (default `data/realruns/states.jsonl`): states recorded by
  `realruns.py`, all ordinary work, so harmless.
- `--trajectories` (default `data/trajectories/actions.jsonl`): actions of
  public coding-agent trajectories extracted by `trajectories.py`, used as
  harmless rows once every one whose canonical form matches a dangerous row
  of the owner's files is dropped.

What it does, in order:

1. Each training command becomes a row `{"state", "questions", "gold"}`:
   the state the center sends for `exec.run` (`tainted` for a random 15 %,
   the call's `args` as the center sends them for `--args-share` of the rows,
   since the center always sends them in production but the 214 cases do
   not), the center's question or, for 25 %, one of the paraphrases, and
   `"gold": {"danger": <bool>}`. Real-run states keep their own state;
   trajectory file actions (`fs.write`, `fs.read`) carry their `args`.
2. Near-duplicates (same capability and `common.canonical` form) keep one row;
   a group whose rows disagree on the label is dropped whole.
3. Every row whose key matches a held-out row or one of the 214 evaluation
   cases is dropped.
4. Harmless rows are capped at `--max-harmless-ratio` per dangerous row: the
   real runs are kept first, then up to `--trajectory-ratio` trajectory rows
   per dangerous row (no program, e.g. `python` or `grep`, above
   `--trajectory-program-share` of them, so the sample is not all test runs),
   then a random sample of the owner's harmless rows fills the rest.
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
import trajectories
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
            "category": r.get("category", ""), "reason": r.get("reason", ""),
            "source": r.get("source", "")}


def owner_files(owner, which):
    """The owner's (name, train, held-out) files: the v2 shell-safety build when
    `which` is v2, or auto and both v2 files are there, else the first."""
    v2 = (owner / "shellsafety-v2-train.jsonl", owner / "shellsafety-v2-heldout.jsonl")
    if which == "v2" or (which == "auto" and all(p.exists() for p in v2)):
        shell = ("shellsafety-v2", *v2)
    else:
        shell = ("shellsafety", owner / "shellsafety-train.jsonl",
                 owner / "shellsafety-heldout.jsonl")
    return [shell, ("extra", owner / "extra-train.jsonl", owner / "extra-heldout.jsonl")]


def trajectory_row(rng, t, args_share, tainted_share):
    """A trajectory action as the center would send it: a command like the
    owner's rows, a file action with its own `args`."""
    if t["cap"] == "exec":
        return command_state(rng, t["target"], "linux", args_share, tainted_share)
    return common.model_state(t["cap"], t["action"], t["target"], "linux",
                              tainted=rng.random() < tainted_share, args=t.get("args"))


def sample_trajectories(rng, rows, n, program_share):
    """`n` rows at most, at most `program_share` of `n` (and at least one)
    from any one program, at random within that."""
    by = collections.defaultdict(list)
    for r in rows:
        by[r["_program"]].append(r)
    per = max(1, int(n * program_share))
    pool = []
    for prog in sorted(by):
        group = by[prog][:]
        rng.shuffle(group)
        pool.extend(group[:per])
    rng.shuffle(pool)
    return pool[:n]


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
    ap.add_argument("--trajectories", type=Path,
                    default=WORK / "data" / "trajectories" / "actions.jsonl",
                    help="harmless agent actions from trajectories.py (skipped if missing)")
    ap.add_argument("--shellsafety", choices=["auto", "v1", "v2"], default="auto",
                    help="which build of the owner's shell-safety files (auto: v2 if there)")
    ap.add_argument("--trajectory-ratio", type=float, default=0.5,
                    help="at most this many trajectory rows per dangerous row")
    ap.add_argument("--trajectory-program-share", type=float, default=0.15)
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
    danger_keys = set()  # every dangerous owner row, train or held-out
    if not a.dry_run:
        for name, tr, ho in owner_files(a.owner, a.shellsafety):
            if name.startswith("shellsafety") and not (tr.exists() and ho.exists()):
                sys.exit(f"missing {tr} or {ho} (or use --dry-run)")
            for path, part in ((tr, "train"), (ho, "heldout")):
                if not path.exists():
                    continue
                rows, bad = owner_rows(path)
                stats["inputs"][path.name] = {"rows": len(rows), "malformed": bad,
                                              "danger": sum(r["danger"] for r in rows)}
                danger_keys.update(key("exec", r["command"]) for r in rows if r["danger"])
                if part == "train":
                    train_cmds.extend(rows)
                else:
                    heldout[name] = [case_from_command(r) for r in rows]
        classes = a.owner / "reason-classes.json"
        if classes.exists() and any(r.get("reason") for r in train_cmds):
            cls = {c["reason"]: c["class"] for c in
                   json.loads(classes.read_text(encoding="utf-8"))}
            per = collections.Counter(
                ("danger" if r["danger"] else "harmless") + ":" + cls.get(r.get("reason"), "none")
                for r in train_cmds)
            stats["inputs"]["owner_train_by_reason_class"] = dict(sorted(per.items()))

    traj = []
    if not a.dry_run and a.trajectories.exists():
        traj = common.load_jsonl(a.trajectories)
        stats["inputs"]["trajectories"] = {"rows": len(traj), "danger": 0}

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
    for t in traj:
        # Never let an agent's action stand in as harmless when the owner's
        # files call the same command dangerous (also without a leading `cd`).
        if t["cap"] == "exec" and (key("exec", t["target"]) in danger_keys
                                   or trajectories.dedup_key("exec", t["target"]) in danger_keys):
            stats["dropped"]["trajectory_matches_dangerous"] += 1
            continue
        rows.append({"state": trajectory_row(rng, t, a.args_share, a.tainted_share),
                     "questions": pick_question(rng, a.paraphrase_share),
                     "gold": {"danger": False}, "_src": t["source"],
                     "_program": t["program"]})

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
        real = [r for r in harmless if r["_src"] == "realruns"]
        agent = [r for r in harmless if "_program" in r]
        rest = [r for r in harmless if r["_src"] != "realruns" and "_program" not in r]
        keep = real[:cap]
        n_agent = min(int(len(danger) * a.trajectory_ratio), cap - len(keep))
        keep += sample_trajectories(rng, agent, n_agent, a.trajectory_program_share)
        rng.shuffle(rest)
        keep += rest[:max(0, cap - len(keep))]
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
            r.pop("_program", None)
    # A held-out file of an earlier run (e.g. the v1 build) must not be scored again.
    for stale in out.glob("heldout-*.json"):
        stale.unlink()
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
