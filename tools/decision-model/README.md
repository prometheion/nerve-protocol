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
   Injection rows (both labels) are then oversampled in `train.jsonl` only
   (`--injection-oversample F`, 1 = off; by default the factor that makes them
   `--injection-share` 27.5 % of the training rows, at most `--injection-max-factor`
   10; `--injection-oversample 1` gives the data of the earlier rounds): each repeat is the same command with a new random draw of taint, call
   arguments and question wording, so no command is new or changed. The split into
   `train.jsonl` and `calib.jsonl` comes first, so `calib.jsonl` keeps the natural
   mix and no repeat can leak into it; the held-out files are not touched either.
   `--block CASES.json ...` keeps more case files (the independent dev and test
   files) out of training, as the held-out files are.
2. `train.py`: Unsloth `FastDecisionModel` on Laya, bf16, a normal LoRA (`--mode
   lora`, default r 32) or `--mode full`; the temperature is calibrated on
   `calib.jsonl` (rows never trained on) and the merged 16-bit checkpoint goes
   to `WORK/runs/<name>/merged/`. Options for the next round: `--head-lr RATE|body`
   gives the decision head its own learning rate (default 1e-4 beside `--lr`; Unsloth's
   trainer has always used 1e-4 for everything outside the encoder, so the full
   fine-tuning runs so far already had "head LR on", and `--head-lr body` is the new
   variant), `--top-layers N` trains only the top N encoder layers and the final norm
   (full: the others are frozen; LoRA: adapters on those layers only; 0 = all, the
   default), and `--calib-cases DEV.json` fits the temperature on a dev
   case file given by path (the eval runner's format, each case as the runner sends it)
   instead of `calib.jsonl`.
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
   (e.g. `d1-3B:eval-v3.1`). The dev and test files are given by path
   (`--dev FILE --test FILE ...`; `--cases DIR` still takes the prepared folder's
   v3.1 files), so the owner's independent files plug in as they are; they must have been
   scored by `evaluate.py --heldout FILE` (the scores file carries the file's name).
   `--calibrate` fits a temperature on the dev scores (`calibration.py`), rescales
   every file with it and picks the threshold on the rescaled dev scores, printing the
   temperature, the log loss and ECE before and after, and the threshold on the unscaled
   score; the order of the scores, and so the AUC, does not change. Beside the rates at a
   threshold, `evaluate.py` and `compare.py` report per axis, without any threshold, the
   ROC-AUC and the share of dangerous cases caught at fixed benign-refused rates
   (`--fpr`, default 0.5, 1, 3, 5 %): the harm axis (cases without an injection) and the
   injection axis (injection cases, both labels), and, where the cases carry an optional
   `tier` (how an injection is disguised), the same per tier plus the tier's catch and
   benign-refused share at the injection axis' threshold for the same budget (a tier
   with few benign cases is still measured against a threshold the whole axis sets), and
   `tier` as one more breakdown group. The 214 cases have no benign injection case, so
   their injection-axis AUC and rates are "-".

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

## The next round: the sweep (prepared, not run)

The independent benchmark is not there yet, so nothing of this has been trained.
`pipeline.py --sweep` is the whole round in one command: full fine-tuning of Laya on the
round-3 data choice (`prepare.py --max-harmless-ratio 99 --trajectory-ratio 0`, 2.8
harmless rows per dangerous one) in the variants

| Axis | Values |
|---|---|
| Decision-head learning rate | on (1e-4 beside the encoder's 2e-5) / off (`--head-lr body`) |
| Trained layers | all 28 / the top 12 (`--top-layers 12`) |
| Injection oversampling | 1x / 3x / 5x (`--factors`) |

All 12 combinations (`--grid full`; `--grid one-at-a-time` runs the baseline and one change
at a time, 5 runs). On v3.1 the injection rows are 4.7 % of the 11,139 training rows, so 3x
gives 12.8 % and 5x 19.7 %; the 25-30 % of the plan needs about 7.7x (`--factors 1 3 5 8`,
or `prepare.py` alone, whose default is that share).

```sh
cd tools/decision-model
WORK=~/Services/nerve-training
# 1. the dry run: prepares data/next/os1, os3, os5 and prints counts and the run list, no GPU
$WORK/venv/bin/python pipeline.py --sweep --plan
# 2. a few training steps of one variant, only if every GPU in --gpus is idle (else it says so)
$WORK/venv/bin/python pipeline.py --sweep --smoke --skip-prepare
# 3. the real run: two runs at a time, one per GPU; each step is skipped when its output is
#    there, so an interrupted sweep resumes by running the same command again
$WORK/venv/bin/python pipeline.py --sweep --prefix laya-nx --gpus 0,1 \
    --dev $WORK/data/owner/independent/dev.json --test $WORK/data/owner/independent/test.json
# without --dev/--test: the prepared v3.1 dev and benchmark
```

Per run it trains (`--calib-cases DEV`: the temperature is fitted on the dev file, and goes
into the GGUF), exports the Q8_0 GGUF, and scores the 214, the dev and the test files on the
GPU (`evaluate.py --heldout DEV TEST...`). At the end `compare.py` writes
`WORK/runs/<prefix>-compare.md` (and `.json`) with all runs beside the round-3 Laya and
d1-3B (`--refs`): threshold chosen on dev only, the same threshold on the test files and the
214, and the per-axis AUC and catch-at-fixed-benign-refused tables and tiers for every file.
`--dev` and `--test` are also given to `prepare.py` as `--block`, so no training row matches
them (the owner's disjointness is checked again by canonical form). The 214 cases are scored
and reported, never used to choose anything. Rough cost, from round 3 (its `all-t0` full fine-tuning took about 25 minutes on one GPU,
and 5x adds 19 % rows): 12 runs on two GPUs take about 3 hours plus export and scoring; each run keeps its merged
checkpoint (0.8 GB) and GGUF (0.45 GB) under `WORK/runs/`, about 15 GB for the sweep.
Arguments after `--` go to `train.py` for every run (e.g. `-- --epochs 3`).

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
