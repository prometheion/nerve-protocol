"""Compare evaluated runs honestly: the threshold of every run is chosen on
the dev split only, then applied unchanged to the benchmark and the 214 cases.

    python compare.py --runs laya-full-all-t0 laya-lora-all-t0 ... [--budget 3]

Reads `runs/<name>/eval/scores-<file>.jsonl` (evaluate.py) and the case files
given by path: `--dev` and `--test` (one or more), or `--cases`, a prepared
folder with `heldout-v3-dev.json` and `heldout-v3-benchmark.json`; the 214 come
from the repo. So the owner's independent dev and test files plug in as they
are (`evaluate.py --heldout` scores them under their file names). For each run:

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

Threshold-free, per axis (harm: cases without an injection; injection: the
injection cases of both labels) and per `tier` where the cases carry one: the
ROC-AUC and the catch rate at fixed benign-refused rates (`--fpr`, default 0.5,
1, 3, 5 percent), see `evaluate.axis_summary`.

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

# The v3.1 files of a prepared folder: the defaults of --dev and --test.
DEV_FILE = "heldout-v3-dev.json"
TEST_FILES = ["heldout-v3-benchmark.json"]

auc = evaluate.auc


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
    ap.add_argument("--cases", type=Path, default=None,
                    help="a prepared folder holding heldout-v3-dev.json and "
                         "heldout-v3-benchmark.json (the defaults of --dev and --test)")
    ap.add_argument("--dev", type=Path, default=None,
                    help="the dev case file (thresholds and the temperature are fitted here)")
    ap.add_argument("--test", type=Path, nargs="*", default=None,
                    help="test case files (the benchmark); each is scored under its file name")
    ap.add_argument("--budget", type=float, default=3.0,
                    help="benign refusals allowed on dev, percent")
    ap.add_argument("--fixed", nargs="*", default=[], metavar="NAME=T",
                    help="also report these runs at the given fixed threshold")
    ap.add_argument("--strict", type=float, nargs="*", default=[1.0, 0.5],
                    help="more benign-refusal budgets (percent) for the dev rank")
    ap.add_argument("--also", type=float, nargs="*", default=[],
                    help="also report every run at these fixed thresholds (e.g. 0.8)")
    ap.add_argument("--fpr", type=float, nargs="*", default=evaluate.FPRS,
                    help="benign-refused budgets (percent) of the per-axis catch rates")
    ap.add_argument("--calibrate", action="store_true",
                    help="temperature-scale every run's scores, fitted on its dev scores")
    ap.add_argument("--breakdown", action="store_true")
    ap.add_argument("--out", type=Path, default=None, help="write the markdown here too")
    a = ap.parse_args()
    if a.cases is None and (a.dev is None or a.test is None):
        ap.error("give --cases, or both --dev and --test")

    dev_path = a.dev or a.cases / DEV_FILE
    test_paths = a.test if a.test is not None else [a.cases / f for f in TEST_FILES]

    def load_cases(path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    # label -> (case file, the name evaluate.py gave its scores file)
    sets = {"dev": (dev_path, dev_path.stem)}
    sets.update({p.stem: (p, p.stem) for p in test_paths})
    sets["214"] = (common.EVAL_214, "214")
    cases = {label: load_cases(path) for label, (path, _) in sets.items()}
    tests = [p.stem for p in test_paths]
    fixed = {k: float(v) for k, v in (x.split("=") for x in a.fixed)}
    lines, result = [], {}
    for spec in a.runs:
        run, _, sub = spec.partition(":")
        sub = sub or "eval"
        scores = {}
        for label, (_, name) in sets.items():
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
                # threshold-free: AUC and catch at fixed benign-refused rates, per axis and tier
                entry[label]["axes"] = evaluate.axis_summary(rows, cases[label], a.fpr)
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

    lines += ["| Run | Test file | Threshold | Dev catch | Dev inj. catch | Dev benign-refused | "
              "Test catch | Test benign-refused | Test inj. catch | Test inj. refused | "
              "Test AUC | 214 catch | 214 benign-refused | 214 inj. catch | 214 AUC | Dev rank |",
              "|" + "---|" * 16]

    def m(x, k, pm=True):
        return "-" if x is None else cell(x[k], x.get(k + "_pm") if pm else None)

    def auc_cell(x):
        return "-" if x is None or x["auc"] is None else f"{x['auc']:.3f}"

    for name, e in sorted(result.items(), key=lambda kv: -kv[1]["dev_rank"]):
        d, c = e["dev"], e.get("214")
        thr = f"{e['threshold']:.2f}"
        if "calibration" in e:
            thr += f" (T {e['calibration']['temperature']:.2f}, raw {e['raw_threshold']:.3f})"
        for test in (tests if any(x in e for x in tests) else [None]):
            b = e.get(test)
            lines.append(
                f"| {name} | {test or '-'} | {thr} | {m(d, 'catch')} | {m(d, 'injection_catch')} | "
                f"{m(d, 'benign_refused')} | {m(b, 'catch')} | {m(b, 'benign_refused')} | "
                f"{m(b, 'injection_catch')} | {m(b, 'injection_refused', False)} | "
                f"{auc_cell(b)} | {m(c, 'catch')} | {m(c, 'benign_refused')} | "
                f"{m(c, 'injection_catch')} | {auc_cell(c)} | {e['dev_rank']:.1f} |")

    # Threshold-free, per axis (the same for every threshold row of a run: show the first).
    shown = {}
    for name, e in result.items():
        shown.setdefault(name.split("@")[0], e)
    for label in ["dev", *tests, "214"]:
        rows = [(run, e[label]["axes"]) for run, e in shown.items() if label in e]
        if not rows:
            continue
        lines += ["", f"### Per axis on {label} (AUC, catch % at a fixed benign-refused %)", ""]
        head = " | ".join(f"{f:g} %" for f in a.fpr)
        lines += [f"| Run | Axis | Dangerous | Benign | AUC | {head} |",
                  "|---|---|---|---|---|" + "---|" * len(a.fpr)]
        for run, axes in rows:
            for axis in ("harm", "injection"):
                x = axes[axis]
                lines.append(f"| {run} | {axis} | {x['dangerous']} | {x['benign']} | "
                             f"{'-' if x['auc'] is None else format(x['auc'], '.3f')} | "
                             + " | ".join(evaluate.show(x["tpr"][str(f)]) for f in a.fpr) + " |")
        tier_rows = [(run, axes["tier"]) for run, axes in rows if axes.get("tier")]
        if tier_rows:
            lines += ["", f"By tier on {label}: AUC / catch % at the injection axis' threshold "
                          "for the budget (benign-refused % in brackets)", "",
                      f"| Run | Tier | Dangerous | Benign | AUC | {head} |",
                      "|---|---|---|---|---|" + "---|" * len(a.fpr)]
            for run, tiers in tier_rows:
                for tier, x in tiers.items():
                    cells = []
                    for f in a.fpr:
                        r = x["at_axis_threshold"][str(f)]
                        cells.append(f"{evaluate.show(r['catch'])} ({evaluate.show(r['benign_refused'])})")
                    lines.append(f"| {run} | {tier} | {x['dangerous']} | {x['benign']} | "
                                 f"{'-' if x['auc'] is None else format(x['auc'], '.3f')} | "
                                 + " | ".join(cells) + " |")
    if a.breakdown:
        for name, e in result.items():
            for label in [*tests, "214"]:
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
        lines += ["", "| Run | T | Dev log loss | scaled | Dev ECE | scaled |",
                  "|---|---|---|---|---|---|"]
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
