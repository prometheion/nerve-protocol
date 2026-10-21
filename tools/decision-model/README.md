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

The third build (`WORK/data/owner/v3.1/`: `train.jsonl`, `dev.jsonl`,
`benchmark.jsonl`, with its own README and decision log) replaces the
shell-safety files as the main source; `prepare.py` takes it when the three
files are there (`--shellsafety v3`, `--v3-dir`; `v2`/`v1` still work).
Train and dev rows are `{"command", "os", "danger", "category", "source",
"injection"}`; a row whose `category` starts with `fs-write-` is a file write
(its `command` is the path), so it becomes an `fs.write` state (no `args`: the
rows have no content) and every other row an `exec.run` state. The `injection`
flag (an embedded instruction that must not move the label, in both
directions) is carried: as a top-level key of the training rows and in the
held-out cases. `dev.jsonl` becomes a second held-out file
(`heldout-v3-dev.json`); `benchmark.jsonl`, 3,993 cases in the eval runner's
format `{"cap", "action", "target", "os", "danger", "kind", "id",
"injection"}`, is used as given (`heldout-v3-benchmark.json`, the main
held-out file). v3.1 made the benchmark disjoint from train and dev by
`common.canonical`, free of the 214 cases, and stratified by length, chain
operators and nesting (see its README); a v3 benchmark without the flag still
loads, with `injection` false. The harmless cap (`--max-harmless-ratio`, 1.5)
is the pipeline's, not the owner's 3 per dangerous row; to keep the owner's
balance, and not add the trajectories on top of what v3 already took from
them, run `prepare.py --max-harmless-ratio 99 --trajectory-ratio 0` first and
then `pipeline.py --skip-prepare`. The ratio was swept on v3.1 (1.5, 2, 3, all),
and `--bucket-floor` (150) keeps harmless commands in the rare long, chained
and nested buckets; see "Third round" in `docs/dev/action-checker.md`: the
ratio made no measurable difference, `all` (2.8 per dangerous row, no extra
trajectories) was chosen on dev.

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
   harmless rows per dangerous one. It prints counts only: per part the labels,
   os, capability, injection rows per label, and for the commands the buckets
   of `common.buckets` (bytes: <80, 80-300, 300-1000, >1000; chain operators
   `|` `&&` `||` `;`: 0, 1-2, 3-5, 6+; nesting of `$(...)`, backticks and
   `sh -c` / `bash -c` / `powershell -Command` / `cmd /c`: 0, 1, 2+; measured on
   the text, not a shell parser). `python3 -m unittest test_prepare` tests it
   on placeholder rows (and the buckets and `evaluate.py`'s breakdown).
2. `train.py`: Unsloth `FastDecisionModel` on Laya, bf16, a normal LoRA (`--mode
   lora`, default r 32) or `--mode full`; the temperature is calibrated on
   `calib.jsonl` (rows never trained on) and the merged 16-bit checkpoint goes
   to `WORK/runs/<name>/merged/`.
3. `export.py`: merged checkpoint -> `WORK/runs/<name>/gguf/model-Q8_0.gguf`
   with b11719's `convert_hf_to_gguf.py` (Unsloth's decision export, which also
   writes the calibrated temperatures into the GGUF).
4. `evaluate.py`: the eval runner against `llama-server` on the 214 cases and
   each held-out file; a table per file in `WORK/runs/<name>/eval/results.md`
   (catch %, benign refused %, per threshold; injection catch % of the
   dangerous and injection refused % of the harmless injection cases, where a
   file has them: a case is an injection case with `"injection": true` or the
   kind `injection`) and, per file, a breakdown at `--breakdown-threshold`
   (0.8; all thresholds are in `results.json`) by capability (exec / fs), os,
   injection, and for commands by length, chain-operator and nesting bucket. Quality is scored on the GPU (a CUDA llama.cpp build
   with `/v1/systemone`, `NERVE_LLAMA_GPU_BIN`, default
   `~/Services/llama.cpp-native/build/bin`); then the 214 cases run once more on
   the shipped CPU build (b11719, 8 threads) for p50/p95 and for the largest
   score difference between the two builds. `--device cpu` scores everything
   on the CPU build.

Laya reads at most 512 tokens and takes its whole input in one micro-batch;
`llama-server`'s default micro-batch (512) refuses a longer input with HTTP
500. So the target and the args in a state are bounded to 320 bytes each,
keeping their start and end (`common.clip_ends`, the same as the center's
`util::clip_ends`; `prepare.py --state-bytes`, `evaluate.py --state-bytes`),
which kept every state of the training data and the held-out split inside the
367 tokens the default question leaves; and `evaluate.py` starts
`llama-server` with `-b 2048 -ub 2048` (`--batch`), as a Laya pin in the center
must (`ModelPin::state_bytes`, `ModelPin::batch`), so a longer input is still
answered. For d1-3B and Kev-4B use `--state-bytes 2000 --batch 0`.

5. `compare.py`: the sweep's judge. Each run's threshold is chosen on the dev
   split only (the lowest at which at most `--budget` 3 % of the benign cases
   are refused) and applied unchanged to the benchmark and the 214; it prints
   catch, benign refused, injection catch and refused with 95 % half-widths and
   the AUC, ranks the runs on dev, and with `--breakdown` gives the rates by
   capability, os, injection, length, chain operators and nesting. `--also 0.8`
   adds a fixed threshold per run, `NAME:SUBFOLDER` selects an eval folder
   (e.g. `d1-3B:eval-v3.1`).

   ```sh
   # one prepared folder per configuration (data/sweep/<cfg>), then per run:
   $WORK/venv/bin/python prepare.py --out $WORK/data/sweep/all-t0 \
       --max-harmless-ratio 99 --trajectory-ratio 0
   CUDA_VISIBLE_DEVICES=0 $WORK/venv/bin/python train.py --data $WORK/data/sweep/all-t0 \
       --name laya-full-all-t0 --mode full
   $WORK/venv/bin/python export.py --checkpoint $WORK/runs/laya-full-all-t0/merged \
       --out $WORK/runs/laya-full-all-t0/gguf
   $WORK/venv/bin/python evaluate.py --gguf $WORK/runs/laya-full-all-t0/gguf/model-Q8_0.gguf \
       --name laya-full-all-t0 --prepared $WORK/data/sweep/all-t0 --cpu-check 0
   $WORK/venv/bin/python compare.py --runs laya-full-all-t0 d1-3B:eval-v3.1 \
       --cases $WORK/data/sweep/all-t0 --also 0.8 --breakdown
   ```

   d1-3B and Kev-4B run through `evaluate.py --state-bytes 2000 --batch 0` on
   their pinned GGUFs (`WORK/models/`, hashes of `install.rs`).

6. `latency.py`: latency on a small CPU (the target is about 2 vCPUs). Starts the
   pinned `llama-server` limited to two cores (`--wrap systemd`: `AllowedCPUs`,
   `CPUQuota=200%`, `MemoryMax`; or `--wrap taskset`), measures the cold start
   (process start to health to first answer, model file evicted from the page cache
   or cached) and runs the compiled eval runner (`--runner`, the test binary from
   `cargo test -p nerve-center --test checker_eval --no-run`) `--reps` times per case
   file, writing a JSON with the per-run p50/p95, RAM and the machine load before and
   after. Results: "Latency on 2 vCPUs" in `docs/dev/action-checker.md`.

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
