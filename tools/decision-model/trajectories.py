"""Extract the actions of real coding agents from public trajectory datasets,
as more ordinary work for the harmless side of the training data.

Sources (downloaded once into `WORK/data/raw/`, see the README):

- `swe-agent/data/*.parquet`: nebius/SWE-agent-trajectories (CC-BY-4.0). The
  agent's action is the last fenced block of each `ai` turn. SWE-agent's own
  editor and navigation commands (`open`, `edit`, `search_dir`, ...) are not
  shell commands and are skipped.
- `swe-hero/data/*.parquet`: nvidia/SWE-Hero-openhands-trajectories
  (CC-BY-4.0). `execute_bash` calls give shell commands; the editor's
  `create` gives file writes (`fs.write`, path and content) and `view` gives
  file reads (`fs.read`).

Agents in these datasets solve GitHub issues in a sandbox, so their actions
are nearly all ordinary development work. The script does not judge them;
`prepare.py` drops every one whose canonical form matches a dangerous row of
the owner's files, the held-out files or the 214 evaluation cases.

Commands repeat heavily across trajectories (the same `pytest` call in a
thousand repos), so they are deduplicated by `common.canonical` with a
leading `cd <dir> &&` removed; one example per form is kept. Commands over
2000 bytes, interactive input to a running process and empty actions are
skipped. Output: `WORK/data/trajectories/actions.jsonl`, one
`{"cap", "action", "target", "os", "source", "program"}` per line (`args`
for writes and reads, as the center sends them), and `stats.json`. Prints
counts only.

    python trajectories.py [--max-per-source N]
"""

import argparse
import collections
import json
import random
import re
from pathlib import Path

import common
from common import WORK

# SWE-agent's built-in commands: its file viewer and editor, not a shell.
SWE_AGENT_TOOLS = {"open", "goto", "scroll_up", "scroll_down", "create", "edit", "search_dir",
                   "search_file", "find_file", "submit", "end_of_edit", "exit_forfeit",
                   "exit_cost", "exit_context", "exit_error", "exit_format", "skip"}
FENCE = re.compile(r"```[a-z]*\n(.*?)\n?```", re.S)
LEADING_CD = re.compile(r"^\s*cd\s+\S+\s*(?:&&|;)\s*")
MAX_BYTES = 2000


def program(cmd):
    """The first program of a command, for counts and for spreading the
    sample over different tools."""
    c = common.canonical(LEADING_CD.sub("", cmd))
    return (c.split(" ", 1)[0] or "?")[:40]


def dedup_key(cap, target):
    if cap == "exec":
        return (cap, common.canonical(LEADING_CD.sub("", target)))
    return (cap, common.canonical(target))


def parquet_rows(folder, columns):
    import pyarrow.parquet as pq
    for p in sorted(Path(folder).glob("*.parquet")):
        f = pq.ParquetFile(p)
        for batch in f.iter_batches(batch_size=256, columns=columns):
            yield from batch.to_pylist()


def swe_agent(folder, skipped):
    for r in parquet_rows(folder, ["trajectory"]):
        for m in r["trajectory"] or []:
            if m.get("role") != "ai" or not m.get("text"):
                continue
            blocks = FENCE.findall(m["text"])
            if not blocks:
                skipped["swe-agent:no_action"] += 1
                continue
            cmd = blocks[-1].strip()
            first = cmd.split(None, 1)[0] if cmd else ""
            if not cmd:
                skipped["swe-agent:empty"] += 1
            elif first in SWE_AGENT_TOOLS or "end_of_edit" in cmd:
                skipped["swe-agent:editor_command"] += 1
            else:
                yield {"cap": "exec", "action": "run", "target": cmd}


def swe_hero(folder, skipped):
    for r in parquet_rows(folder, ["trajectory"]):
        for m in r["trajectory"] or []:
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                try:
                    a = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    skipped["swe-hero:bad_arguments"] += 1
                    continue
                name = fn.get("name")
                if name == "execute_bash":
                    cmd = (a.get("command") or "").strip()
                    if not cmd or a.get("is_input") in (True, "true"):
                        skipped["swe-hero:empty_or_input"] += 1
                        continue
                    yield {"cap": "exec", "action": "run", "target": cmd}
                elif name == "str_replace_editor" and a.get("command") == "create":
                    if isinstance(a.get("path"), str) and isinstance(a.get("file_text"), str):
                        yield {"cap": "fs", "action": "write", "target": a["path"],
                               "args": {"content": a["file_text"], "path": a["path"]}}
                elif name == "str_replace_editor" and a.get("command") == "view":
                    if isinstance(a.get("path"), str):
                        yield {"cap": "fs", "action": "read", "target": a["path"],
                               "args": {"path": a["path"]}}
                else:
                    skipped[f"swe-hero:other_tool"] += 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--raw", type=Path, default=WORK / "data" / "raw")
    ap.add_argument("--out", type=Path, default=WORK / "data" / "trajectories")
    ap.add_argument("--seed", type=int, default=139)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    skipped = collections.Counter()
    read = collections.Counter()
    seen = {}
    sources = [("swe-agent", swe_agent, a.raw / "swe-agent" / "data"),
               ("swe-hero", swe_hero, a.raw / "swe-hero" / "data")]
    for name, fn, folder in sources:
        for act in fn(folder, skipped):
            read[f"{name}:{act['cap']}.{act['action']}"] += 1
            if len(act["target"].encode("utf-8")) > MAX_BYTES:
                skipped[f"{name}:over_{MAX_BYTES}_bytes"] += 1
                continue
            k = dedup_key(act["cap"], act["target"])
            if k in seen:
                skipped["duplicate_form"] += 1
                continue
            act.update(os="linux", source=name,
                       program=program(act["target"]) if act["cap"] == "exec" else act["cap"])
            seen[k] = act
    rows = list(seen.values())
    rng.shuffle(rows)
    common.write_jsonl(a.out / "actions.jsonl", rows)

    kept = collections.Counter(f"{r['source']}:{r['cap']}.{r['action']}" for r in rows)
    programs = collections.Counter(r["program"] for r in rows if r["cap"] == "exec")
    stats = {"read": dict(sorted(read.items())), "skipped": dict(sorted(skipped.items())),
             "kept": dict(sorted(kept.items())), "kept_total": len(rows),
             "distinct_programs": len(programs), "top_programs": dict(programs.most_common(25))}
    (a.out / "stats.json").write_text(json.dumps(stats, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
