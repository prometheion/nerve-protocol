# Decision model for the action checker

Scripts that fine-tune a small decision model for the center's action checker
(issue #139, design in `docs/dev/action-checker.md`), turn it into a GGUF the
pinned llama.cpp build serves on `/v1/systemone`, and evaluate it with the
repo's own eval runner on the CPU. Large files (datasets, checkpoints, GGUFs)
live outside git under `NERVE_TRAINING_DIR` (default
`~/Services/nerve-training`, called `WORK` below).

## Setup

- A Python 3.12 venv with Unsloth and CUDA torch:
  `uv venv --python 3.12 WORK/venv && uv pip install --python WORK/venv/bin/python
  torch==2.11.0 unsloth==2026.10.7 --extra-index-url https://download.pytorch.org/whl/cu128
  --index-strategy unsafe-best-match`. Unsloth needs a visible GPU even to import.
- The llama.cpp build the center pins (`crates/nerve-center/src/checker/install.rs`, b11719):
  its source (for the converter) at `WORK/llama/src-b11719` (`NERVE_LLAMA_SRC`), its
  `ubuntu-x64` CPU binaries at `WORK/llama/bin-b11719/llama-b11719` (`NERVE_LLAMA_BIN`).
- The base model: `convaiinnovations/laya` (Apache-2.0) at `WORK/hf/laya`.
- `cargo test -p nerve-center --test checker_eval --no-run` once (the eval runner).

## Data

The labelled commands are built by the owner, not by these scripts: a
deterministic script from the public dataset
[tomngdev/shell-safety-v1.1](https://huggingface.co/datasets/tomngdev/shell-safety-v1.1)
(MIT, revision `fee89770`), plus optional rows of his own. They go into
`WORK/data/owner/`, one `{"command", "os", "danger", "category", "source"}` per line:
`shellsafety-train.jsonl`, `shellsafety-heldout.jsonl`, and optionally
`extra-train.jsonl`, `extra-heldout.jsonl`. These scripts read them only by
path and print counts, never rows.

The second build (`shellsafety-v2-train.jsonl`, `shellsafety-v2-heldout.jsonl`,
`reason-classes.json`) splits shell-safety's `deny` rows by their reason code:
only the codes the owner classed as serious, irreversible harm are dangerous;
the other `deny` rows are left out, because the first build's `deny` was wider
than the checker's question (the model trained on it refused downloads, `kill`
or `export PATH`). `prepare.py` takes the v2 files when both are there
(`--shellsafety v1` for the first build).

Labelling rules (applied by the owner's script, with the checker's question in
mind: serious, irreversible harm vs. ordinary work): shell-safety's `deny` is
dangerous, `allow` is harmless, `ask` is dropped; `posix` is Linux,
`powershell` and `cmd` are Windows; empty commands and commands over 2000
bytes are dropped; exact duplicates keep one, and are dropped when their labels
disagree; the dataset's `test.jsonl` is the held-out split, `train` and
`validation` are training. Rows of his own are labelled with the same question
and left out when unsure.

The harmless side also takes `WORK/data/realruns/states.jsonl`: ordinary agent
work recorded by `realruns.py` through a local center and node (states exactly
as the center sends them), and the actions of public coding-agent
trajectories: `trajectories.py` reads the first shard of each dataset below
(`WORK/data/raw/swe-agent/data/`, `WORK/data/raw/swe-hero/data/`, Parquet from
the Hugging Face repos), takes the shell commands (SWE-agent's last fenced
block per turn, without its own editor commands; SWE-Hero's `execute_bash`)
and the editor's file creations and views (`fs.write` with path and content,
`fs.read`), keeps one per canonical form (a leading `cd <dir> &&` removed) and
writes `WORK/data/trajectories/actions.jsonl`. `prepare.py` drops every one
whose canonical form matches a dangerous row of the owner's files, and keeps
at most `--trajectory-ratio` (0.5) of them per dangerous row, no program above
15 % of those, inside the 1.5 harmless rows per dangerous one.

| Source | Licence | Use |
|---|---|---|
| tomngdev/shell-safety-v1.1 (rev fee89770) | MIT | dangerous and harmless commands, Linux and Windows; its test split is held out |
| the owner's extra rows (`extra-*.jsonl`) | the owner's | a few more pairs; their held-out file is made separately |
| real runs (`realruns.py`, `realruns/*.json`) | this repo | harmless states as the center sends them |
| [nebius/SWE-agent-trajectories](https://huggingface.co/datasets/nebius/SWE-agent-trajectories) (shard 0 of 12) | CC-BY-4.0 | harmless shell commands of a coding agent |
| [nvidia/SWE-Hero-openhands-trajectories](https://huggingface.co/datasets/nvidia/SWE-Hero-openhands-trajectories) (shard 0 of 14) | CC-BY-4.0 | harmless shell commands, file writes and reads of a coding agent |

## The steps

1. `trajectories.py` (once): the trajectory shards -> `WORK/data/trajectories/actions.jsonl`.
   `prepare.py`: owner files + real runs + trajectories -> `WORK/data/prepared/`:
   `train.jsonl` and `calib.jsonl` (`{"state", "questions", "gold"}` rows,
   the center's state for `exec.run`, `tainted` for 15 %, the call's `args`
   for half of them, a paraphrased question for 25 %), and `heldout-*.json` in
   the eval runner's case format. It drops near-duplicates (`common.canonical`),
   groups with conflicting labels, and every row whose canonical form matches a
   held-out row or one of the 214 evaluation cases; it keeps at most 1.5
   harmless rows per dangerous one. `python3 -m unittest test_prepare` tests it
   on placeholder rows.
2. `train.py`: Unsloth `FastDecisionModel` on Laya, bf16, a normal LoRA (`--mode
   lora`, default r 32) or `--mode full`; the temperature is calibrated on
   `calib.jsonl` (rows never trained on) and the merged 16-bit checkpoint goes
   to `WORK/runs/<name>/merged/`.
3. `export.py`: merged checkpoint -> `WORK/runs/<name>/gguf/model-Q8_0.gguf`
   with b11719's `convert_hf_to_gguf.py` (Unsloth's decision export, which also
   writes the calibrated temperatures into the GGUF).
4. `evaluate.py`: the eval runner against `llama-server` on the 214 cases and
   each held-out file; a table per file in `WORK/runs/<name>/eval/results.md`
   (catch %, benign refused %, injection catch % where a file has injection
   cases, per threshold). Quality is scored on the GPU (a CUDA llama.cpp build
   with `/v1/systemone`, `NERVE_LLAMA_GPU_BIN`, default
   `~/Services/llama.cpp-native/build/bin`); then the 214 cases run once more on
   the shipped CPU build (b11719, 8 threads) for p50/p95 and for the largest
   score difference between the two builds. `--device cpu` scores everything
   on the CPU build.

Laya reads at most 512 tokens, and `llama-server`'s default batch (which the
center uses) refuses a longer input with HTTP 500; such a case counts as
failed in the tables.

## One command

```sh
cd tools/decision-model
WORK=~/Services/nerve-training
$WORK/venv/bin/python pipeline.py --name laya-v1 --with-base   # the owner's files
$WORK/venv/bin/python pipeline.py --name laya-dry --dry-run    # real runs only, proves the chain
```

`--with-base` also scores the untouched Laya GGUF (`runs/laya-base/gguf`,
made once with `export.py --checkpoint $WORK/hf/laya --out
$WORK/runs/laya-base/gguf`) on the held-out files. Arguments after `--` go to
`train.py`, e.g. `-- --mode full --epochs 3`.
