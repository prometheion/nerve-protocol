"""Compare evaluated runs honestly: the threshold of every run is chosen on
the dev split only, then applied unchanged to the benchmark and the 214 cases.

    python compare.py --runs laya-full-all-t0 laya-lora-all-t0 ... [--budget 3]

Reads `runs/<name>/eval/scores-<file>.jsonl` (evaluate.py) and the case files
in `--cases` (the prepared folder with `heldout-v3-dev.json`,
`heldout-v3-benchmark.json`, and the 214 from the repo). For each run:

1. on the dev split, the lowest threshold (two decimals) at which at most
   `--budget` percent of the benign cases are refused (score >= threshold);
2. at that threshold: the catch rate and the injection catch on dev, and the
   same on the benchmark and the 214 (catch, benign refused, injection catch,
   injection refused), with the ROC-AUC of each file and a 95 % half-width of
   the normal approximation for the rates (rates closer than that are not
   different);
3. a rank on dev: the mean of the catch rate and the injection catch rate,
   averaged over the budgets (`--budget`, then each of `--strict`, default 1 and
   0.5 percent): the dev split is easy and the rates at 3 % are near 100 for
   every run, so the stricter budgets tell the runs apart without looking at
   the benchmark or the 214.

`--calibrate` first fits a temperature on the dev scores (`calibration.py`: the
one number that minimises the log loss there), rescales the scores of every
file with it, and then picks the threshold on the rescaled dev scores; the
table shows the temperature and the same threshold on the unscaled scores
(`raw`), the one to configure if the model itself is not rescaled. The order of
the scores, and so the AUC, does not change.

`--breakdown` also writes, per run and file, the rates by capability, os,
injection and the command's length, chain-operator and nesting buckets at that
threshold. A run folder named like `d1-3B` or `laya-base` works the same.
`--also T ...` adds rows at fixed thresholds for every run, and `--fixed NAME=T`
pins one run's threshold, named as in --runs (e.g. the product's own,
d1-3B 0.8, Kev-4B 0.5). It prints rates only, never a case.
"""

import argparse
import json
import math
from pathlib import Path

import calibration
import common
import evaluate
from common import WORK

# The label of a case set -> the name evaluate.py gives its scores file.
SCORES = {"dev": "heldout-v3-dev", "benchmark": "heldout-v3-benchmark", "214": "214"}
FILES = {"dev": "heldout-v3-dev.json", "benchmark": "heldout-v3-benchmark.json"}


def auc(rows):
    """ROC-AUC of the scores: the chance that a dangerous case scores above a
    benign one (ties count half)."""
    pos = sorted(r["score"] for r in rows if r["danger"])
    neg = sorted(r["score"] for r in rows if not r["danger"])
    if not pos or not neg:
        return None
    import bisect
    total = 0.0
    for p in pos:
        total += bisect.bisect_left(neg, p) + 0.5 * (bisect.bisect_right(neg, p)
                                                      - bisect.bisect_left(neg, p))
    return total / (len(pos) * len(neg))


def pick_threshold(rows, budget):
    """The lowest threshold with at most `budget` percent of the benign rows
    at or above it, rounded up to two decimals."""
    benign = sorted(r["score"] for r in rows if not r["danger"])
    allowed = int(len(benign) * budget / 100)
    # refusing at t means score >= t; allow `allowed` benign rows at or above it
    t = benign[len(benign) - allowed - 1] if len(benign) > allowed else 0.0
    t = math.floor(t * 100 + 1e-9) / 100 + 0.01
    return min(t, 1.0)


def rates(rows, cases, t):
    inj = {i: evaluate.is_injection(c) for i, c in enumerate(cases)}
    d = [r for r in rows if r["danger"]]
    b = [r for r in rows if not r["danger"]]
    i_d = [r for r in d if inj.get(r["index"])]
    i_h = [r for r in b if inj.get(r["index"])]

    def share(part):
        return None if not part else 100.0 * sum(r["score"] >= t for r in part) / len(part)

    def half(part, p):
        return None if not part or p is None else 196.0 * math.sqrt(p / 100 * (1 - p / 100)
                                                                   / len(part))

    out = {"n_danger": len(d), "n_benign": len(b), "n_inj_danger": len(i_d),
           "n_inj_benign": len(i_h), "catch": share(d), "benign_refused": share(b),
           "injection_catch": share(i_d), "injection_refused": share(i_h), "auc": auc(rows)}
    out["catch_pm"] = half(d, out["catch"])
    out["benign_refused_pm"] = half(b, out["benign_refused"])
    out["injection_catch_pm"] = half(i_d, out["injection_catch"])
    return out


def cell(v, pm=None):
    if v is None:
        return "-"
    return f"{v:.1f}" + (f" ±{pm:.1f}" if pm is not None else "")


def load(run, label):
    return common.load_jsonl(WORK / "runs" / run / "eval" / f"scores-{label}.jsonl")


def eval_dir(run, sub):
    return WORK / "runs" / run / sub


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--runs", nargs="+", required=True,
                    help="run names under runs/ (their eval folder is `eval`, or NAME:SUBFOLDER)")
    ap.add_argument("--cases", type=Path, required=True,
                    help="a prepared folder holding heldout-v3-dev.json and heldout-v3-benchmark.json")
    ap.add_argument("--budget", type=float, default=3.0,
                    help="benign refusals allowed on dev, percent")
    ap.add_argument("--fixed", nargs="*", default=[], metavar="NAME=T",
                    help="also report these runs at the given fixed threshold")
    ap.add_argument("--strict", type=float, nargs="*", default=[1.0, 0.5],
                    help="more benign-refusal budgets (percent) for the dev rank")
    ap.add_argument("--also", type=float, nargs="*", default=[],
                    help="also report every run at these fixed thresholds (e.g. 0.8)")
    ap.add_argument("--calibrate", action="store_true",
                    help="temperature-scale every run's scores, fitted on its dev scores")
    ap.add_argument("--breakdown", action="store_true")
    ap.add_argument("--out", type=Path, default=None, help="write the markdown here too")
    a = ap.parse_args()

    cases = {"dev": json.loads((a.cases / FILES["dev"]).read_text(encoding="utf-8")),
             "benchmark": json.loads((a.cases / FILES["benchmark"]).read_text(encoding="utf-8")),
             "214": json.loads(common.EVAL_214.read_text(encoding="utf-8"))}
    fixed = {k: float(v) for k, v in (x.split("=") for x in a.fixed)}
    lines, result = [], {}
    for spec in a.runs:
        run, _, sub = spec.partition(":")
        sub = sub or "eval"
        scores = {}
        for label, name in SCORES.items():
            path = eval_dir(run, sub) / f"scores-{name}.jsonl"
            if path.exists():
                scores[label] = common.load_jsonl(path)
        if "dev" not in scores:
            lines.append(f"{run}: no dev scores, skipped")
            continue
        cal = None
        if a.calibrate:
            temp = calibration.fit_temperature(scores["dev"])
            cal = {"temperature": temp, "dev_nll": calibration.nll(scores["dev"]),
                   "dev_nll_scaled": calibration.nll(scores["dev"], temp),
                   "dev_ece": calibration.ece(scores["dev"]),
                   "dev_ece_scaled": calibration.ece(scores["dev"], temp)}
            scores = {label: calibration.rescored(rows, temp) for label, rows in scores.items()}
        t = pick_threshold(scores["dev"], a.budget)
        thresholds = [("dev-chosen", t)] + [(f"t{x:.2f}", x) for x in a.also]
        if spec in fixed or run in fixed:
            thresholds.append(("fixed", fixed.get(spec, fixed.get(run))))
        for how, th in thresholds:
            entry = {"threshold": th, "how": how}
            if cal:
                entry["calibration"] = cal
                entry["raw_threshold"] = calibration.raw_threshold(th, cal["temperature"])
            for label, rows in scores.items():
                entry[label] = rates(rows, cases[label], th)
                if a.breakdown:
                    entry[label]["breakdown"] = evaluate.breakdown_rows(
                        rows, cases[label], [th])[str(th)]
            # The rank ignores the threshold of this row: dev only, at each budget.
            at = [rates(scores["dev"], cases["dev"], pick_threshold(scores["dev"], b))
                  for b in [a.budget, *a.strict]]
            entry["dev_budgets"] = {b: {"catch": r["catch"], "injection_catch": r["injection_catch"]}
                                    for b, r in zip([a.budget, *a.strict], at)}
            entry["dev_rank"] = sum((r["catch"] + (r["injection_catch"] or 0.0)) / 2
                                    for r in at) / len(at)
            result[f"{run}@{how}"] = entry

    lines += ["| Run | Threshold | Dev catch | Dev inj. catch | Dev benign-refused | "
              "Bench catch | Bench benign-refused | Bench inj. catch | Bench inj. refused | "
              "Bench AUC | 214 catch | 214 benign-refused | 214 inj. catch | 214 AUC | Dev rank |",
              "|" + "---|" * 15]
    for name, e in sorted(result.items(), key=lambda kv: -kv[1]["dev_rank"]):
        d, b, c = e["dev"], e.get("benchmark"), e.get("214")

        def m(x, k, pm=True):
            return "-" if x is None else cell(x[k], x.get(k + "_pm") if pm else None)

        thr = f"{e['threshold']:.2f}"
        if "calibration" in e:
            thr += f" (T {e['calibration']['temperature']:.2f}, raw {e['raw_threshold']:.3f})"
        lines.append(
            f"| {name} | {thr} | {m(d, 'catch')} | {m(d, 'injection_catch')} | "
            f"{m(d, 'benign_refused')} | {m(b, 'catch')} | {m(b, 'benign_refused')} | "
            f"{m(b, 'injection_catch')} | {m(b, 'injection_refused', False)} | "
            f"{'-' if b is None else f'{b['auc']:.3f}'} | {m(c, 'catch')} | "
            f"{m(c, 'benign_refused')} | {m(c, 'injection_catch')} | "
            f"{'-' if c is None else f'{c['auc']:.3f}'} | {e['dev_rank']:.1f} |")
    if a.breakdown:
        for name, e in result.items():
            for label in ("benchmark", "214"):
                if label not in e:
                    continue
                lines += ["", f"### {name} on {label} at {e['threshold']:.2f}", "",
                          "| Group | Value | Dangerous | Catch % | Benign | Benign-refused % |",
                          "|---|---|---|---|---|---|"]
                for axis, values in e[label]["breakdown"].items():
                    for value, mm in values.items():
                        lines.append(f"| {axis} | {value} | {mm['dangerous']} | "
                                     f"{evaluate.show(mm['catch'])} | {mm['benign']} | "
                                     f"{evaluate.show(mm['benign_refused'])} |")
    if a.calibrate:
        lines += ["", "| Run | T | Dev log loss | scaled | Dev ECE | scaled |", "|---|---|---|---|---|---|"]
        for name, e in result.items():
            if "calibration" in e and e["how"] == "dev-chosen":
                c = e["calibration"]
                lines.append(f"| {name} | {c['temperature']:.2f} | {c['dev_nll']:.4f} | "
                             f"{c['dev_nll_scaled']:.4f} | {c['dev_ece']:.4f} | "
                             f"{c['dev_ece_scaled']:.4f} |")
    md = "\n".join(lines)
    print(md)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(md + "\n", encoding="utf-8")
        a.out.with_suffix(".json").write_text(json.dumps(result, indent=1) + "\n")


if __name__ == "__main__":
    main()
