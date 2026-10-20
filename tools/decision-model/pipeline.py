"""The whole chain in one command: prepare -> train -> export -> evaluate.

    venv/bin/python pipeline.py --name laya-v1            # the owner's files
    venv/bin/python pipeline.py --name laya-dry --dry-run # real runs only

Every step is its own script (see the README) and can be run alone; this
only runs them in order with matching folders:

- data:     data/prepared/        (data/prepared-dry/ with --dry-run)
- model:    runs/<name>/merged/   (train.py)
- GGUF:     runs/<name>/gguf/     (export.py)
- results:  runs/<name>/eval/     (evaluate.py: the 214 cases + each held-out file)

`--with-base` also evaluates the untouched model's GGUF (`runs/laya-base/gguf`,
made once by `export.py --checkpoint hf/laya --out runs/laya-base/gguf`) on
the same held-out files, for the base-vs-fine-tuned comparison. Arguments
after `--` go to train.py (e.g. `-- --mode full --epochs 3`).
"""

import argparse
import subprocess
import sys
from pathlib import Path

from common import HERE, WORK


def run(script, *args):
    cmd = [sys.executable, str(HERE / script), *map(str, args)]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main():
    argv = sys.argv[1:]
    extra = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--name", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--owner", type=Path, default=WORK / "data" / "owner")
    ap.add_argument("--with-base", action="store_true")
    ap.add_argument("--skip-prepare", action="store_true", help="reuse the prepared data")
    a = ap.parse_args(argv)

    data = WORK / "data" / ("prepared-dry" if a.dry_run else "prepared")
    run_dir = WORK / "runs" / a.name
    if not a.skip_prepare:
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
