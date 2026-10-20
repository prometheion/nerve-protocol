"""Tests for prepare.py on placeholder rows (no real commands): dedup,
conflicting labels, held-out and 214-case overlap, balance, output format.

    python -m unittest test_prepare
"""

import collections
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import common
import evaluate
import prepare

HERE = Path(__file__).resolve().parent


def word(i):
    """A digit-free token per number (the canonical form folds digits)."""
    return "".join("abcdefghij"[int(c)] for c in str(i))


def row(cmd, danger, os_name="linux"):
    return {"command": cmd, "os": os_name, "danger": danger, "category": "test", "source": "test"}


def v3_row(cmd, danger, category="test", os_name="linux", injection=False):
    return {**row(cmd, danger, os_name), "category": category, "injection": injection}


def bench_row(target, danger, cap="exec", kind="test", os_name="linux", injection=None, id=1):
    r = {"cap": cap, "action": "write" if cap == "fs" else "run", "target": target,
         "os": os_name, "danger": danger, "kind": kind, "id": id}
    if injection is not None:
        r["injection"] = injection
    return r


def traj_row(cmd, program="echo"):
    return {"cap": "exec", "action": "run", "target": cmd, "os": "linux", "source": "swe-agent",
            "program": program}


class PrepareTest(unittest.TestCase):
    def run_prepare(self, train, heldout, realruns, *extra, traj=(), build="shellsafety"):
        d = Path(self.tmp.name)
        owner = d / "owner"
        common.write_jsonl(owner / f"{build}-train.jsonl", train)
        common.write_jsonl(owner / f"{build}-heldout.jsonl", heldout)
        common.write_jsonl(d / "states.jsonl", realruns)
        common.write_jsonl(d / "traj.jsonl", traj)
        out = d / "out"
        res = subprocess.run(
            [sys.executable, str(HERE / "prepare.py"), "--owner", str(owner), "--out", str(out),
             "--realruns", str(d / "states.jsonl"), "--trajectories", str(d / "traj.jsonl"),
             "--calib-share", "0", *extra],
            capture_output=True, text=True, check=True)
        return out, json.loads(res.stdout)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_dedup_conflicts_overlap_and_balance(self):
        # One case of the 214, taken by the script's own key, never shown.
        first = json.loads(common.EVAL_214.read_text(encoding="utf-8"))[0]
        train = [row(f"echo marker-{word(i)}", True) for i in range(4)]
        train += [row("echo marker-a", True), row("ECHO   marker-b", True)]  # near-duplicates
        train += [row("printf both", True), row("printf both", False)]  # conflicting labels
        train += [row(first["target"], first["danger"], first["os"])]  # in the 214
        train += [row("echo held", False)]  # in the held-out file
        train += [row(f"ls dir-{c}", False) for c in "abcdefghij"]  # 10 harmless
        heldout = [row("echo held", False), row("echo other", True, "windows")]
        realruns = [common.model_state("exec", "run", "make docs-preview", "linux", tainted=True,
                                       args={"command": "make docs-preview", "cwd": "/w"})]
        out, stats = self.run_prepare(train, heldout, realruns)

        self.assertEqual(stats["dropped"]["near_duplicate"], 2)
        self.assertEqual(stats["dropped"]["conflicting_label_group_rows"], 2)
        self.assertEqual(stats["dropped"]["matches_214_eval"], 1)
        self.assertEqual(stats["dropped"]["matches_heldout"], 1)
        # 4 dangerous rows allow 6 harmless ones; the real run is kept first.
        self.assertEqual(stats["train"]["danger"], 4)
        self.assertEqual(stats["train"]["harmless"], 6)
        self.assertEqual(stats["dropped"]["balance"], 5)

        rows = common.load_jsonl(out / "train.jsonl")
        self.assertIn(realruns[0], [r["state"] for r in rows])
        for r in rows:
            self.assertEqual(set(r), {"state", "questions", "gold"})
            self.assertEqual(list(r["state"]), sorted(r["state"]))
            self.assertEqual(set(r["gold"]), {"danger"})
            self.assertEqual(list(r["questions"]), ["danger"])
        cases = json.loads((out / "heldout-shellsafety.json").read_text())
        self.assertEqual([(c["cap"], c["action"], c["target"], c["os"], c["danger"], c["kind"])
                          for c in cases],
                         [("exec", "run", "echo held", "linux", False, "benign"),
                          ("exec", "run", "echo other", "windows", True, "dangerous")])

    def test_shares_and_args(self):
        train = [row(f"echo n{word(i)}", i % 2 == 0, "windows" if i % 3 else "linux")
                 for i in range(400)]
        out, stats = self.run_prepare(train, [], [], "--args-share", "1", "--tainted-share", "0")
        rows = common.load_jsonl(out / "train.jsonl")
        self.assertEqual(stats["train"]["tainted"], 0)
        for r in rows:
            args = json.loads(r["state"]["args"])
            self.assertEqual(args["command"], r["state"]["target"])
            self.assertIn(args["cwd"], sum(prepare.CWDS.values(), []))
        # about a quarter of the questions are paraphrased
        self.assertTrue(50 < stats["train"]["paraphrased"] < 150, stats["train"])

    def test_trajectories_filtered_capped_and_spread(self):
        danger = [row(f"echo bad-{word(i)}", True) for i in range(10)]
        harmless = [row(f"ls own-{word(i)}", False) for i in range(20)]
        # Agent actions: two that the owner's files call dangerous (one only
        # without its leading cd), many test runs, a few other programs and a
        # file write.
        traj = [traj_row("echo bad-a"), traj_row("cd /workspace/r && ECHO bad-b")]
        traj += [traj_row(f"python run-{word(i)}.py", "python") for i in range(30)]
        traj += [traj_row(f"grep -n x{word(i)}", "grep") for i in range(3)]
        traj += [{"cap": "fs", "action": "write", "target": "/workspace/r/new.py",
                  "args": {"content": "x = 1\n", "path": "/workspace/r/new.py"},
                  "os": "linux", "source": "swe-hero", "program": "fs"}]
        out, stats = self.run_prepare(danger + harmless, [], [], "--trajectory-ratio", "1",
                                      "--trajectory-program-share", "0.3", traj=traj)
        self.assertEqual(stats["dropped"]["trajectory_matches_dangerous"], 2)
        self.assertEqual(stats["train"], {**stats["train"], "danger": 10, "harmless": 15})
        # 10 trajectory rows at most, no program above 3 of them, owner rows fill up to 15.
        self.assertEqual(stats["sources"]["swe-agent"], 6)
        self.assertEqual(stats["sources"]["swe-hero"], 1)
        self.assertEqual(stats["sources"]["test"], 10 + 8)
        rows = common.load_jsonl(out / "train.jsonl")
        targets = [r["state"]["target"] for r in rows]
        self.assertEqual(sum(t.startswith("python run-") for t in targets), 3)
        self.assertEqual(sum(t.startswith("grep -n") for t in targets), 3)
        write = [r["state"] for r in rows if r["state"]["capability"] == "fs"]
        self.assertEqual(json.loads(write[0]["args"]),
                         {"content": "x = 1\n", "path": "/workspace/r/new.py"})

    def test_bucket_floor_keeps_long_and_nested_harmless_rows(self):
        danger = [row(f"echo bad-{word(i)}", True) for i in range(10)]
        short = [row(f"ls own-{word(i)}", False) for i in range(60)]
        # A few rare commands among many short ones: a random sample of 15 of the
        # 77 would hardly hold two of each kind.
        long = [row(f"echo {'x' * 320} {word(i)}", False) for i in range(4)]
        chained = [row(" && ".join(f"echo s{word(i)}-{c}" for c in "abcdefg"), False)
                   for i in range(4)]
        nested = [row(f"echo $(echo $(echo n-{word(i)}))", False) for i in range(3)]
        train = danger + short + long + chained + nested
        rare = {(0, "300-1000"): 4, (1, "6+"): 4, (2, "2+"): 3}

        def held(extra):
            out, stats = self.run_prepare(train, [], [], *extra)
            seen = collections.Counter()
            for r in common.load_jsonl(out / "train.jsonl"):
                if not r["gold"]["danger"]:
                    b = common.buckets(r["state"]["target"])
                    seen.update(rb for rb in rare if b[rb[0]] == rb[1])
            return seen, stats

        seen, stats = held(["--bucket-floor", "2"])
        # Two of each (the nested ones count as nesting 1 and 2+ alike), inside the
        # cap of 15 harmless rows.
        self.assertTrue(all(seen[rb] >= 2 for rb in rare), seen)
        self.assertEqual(stats["train"]["harmless"], 15)
        self.assertEqual(stats["pool_harmless"]["length"]["300-1000/harmless"], 4)
        self.assertGreater(stats["bucket_floor_rows"], 0)
        # Without the floor the seeded random sample misses a bucket.
        seen, stats = held(["--bucket-floor", "0"])
        self.assertEqual(stats["bucket_floor_rows"], 0)
        self.assertTrue(any(seen[rb] < 2 for rb in rare), seen)
        # A floor the pool cannot meet takes what there is and never exceeds the cap.
        seen, stats = held(["--bucket-floor", "50"])
        self.assertEqual(stats["train"]["harmless"], 15)
        self.assertEqual({rb: seen[rb] for rb in rare}, rare)

    def test_v2_build_is_preferred_and_keeps_reason(self):
        d = Path(self.tmp.name)
        common.write_jsonl(d / "owner" / "shellsafety-train.jsonl", [row("echo old", True)])
        common.write_jsonl(d / "owner" / "shellsafety-heldout.jsonl", [row("echo old2", True)])
        (d / "out").mkdir()
        (d / "out" / "heldout-shellsafety.json").write_text("[]")
        r = {**row("echo held", True), "reason": "code_a"}
        out, stats = self.run_prepare([row("echo new", True), row("ls", False)], [r], [],
                                      build="shellsafety-v2")
        self.assertIn("shellsafety-v2-train.jsonl", stats["inputs"])
        self.assertNotIn("shellsafety-train.jsonl", stats["inputs"])
        self.assertEqual([p.name for p in out.glob("heldout-*.json")],
                         ["heldout-shellsafety-v2.json"])
        cases = json.loads((out / "heldout-shellsafety-v2.json").read_text())
        self.assertEqual(cases[0]["reason"], "code_a")

    def test_long_commands_are_cut_to_the_state_budget_but_matched_whole(self):
        long_cmd = "echo start " + "word " * 200 + "; echo end"
        twin = "echo start " + "word " * 200 + "; echo other-end"  # same start and end cut
        train = [row(long_cmd, True), row(twin, False), row("ls", False)]
        out, stats = self.run_prepare(train, [row(twin, False)], [], "--state-bytes", "100",
                                      "--args-share", "1")
        # The held-out twin only blocks itself, not the row whose cut state looks alike.
        self.assertEqual(stats["dropped"]["matches_heldout"], 1)
        rows = common.load_jsonl(out / "train.jsonl")
        st = [r["state"] for r in rows if r["gold"]["danger"]][0]
        for s in (st["target"], st["args"]):
            self.assertLessEqual(len(s.encode()), 103)
            self.assertIn("…", s)
        self.assertTrue(st["target"].startswith("echo start"))
        self.assertTrue(st["target"].endswith("; echo end"))

    def test_clip_ends_matches_the_center(self):
        # The same cases as util::clip_ends' test in the center.
        self.assertEqual(common.clip_ends("abcdefgh", 8), "abcdefgh")
        self.assertEqual(common.clip_ends("abcdefghij", 5), "ab…hij")
        self.assertEqual(common.clip_ends("äöüß", 5), "ä…ß")
        self.assertEqual(common.clip_ends("äöüß", 4), "ä…ß")

    def run_prepare_v3(self, train, dev, bench, *extra, v2=False):
        d = Path(self.tmp.name)
        owner = d / "owner"
        common.write_jsonl(owner / "v3.1" / "train.jsonl", train)
        common.write_jsonl(owner / "v3.1" / "dev.jsonl", dev)
        common.write_jsonl(owner / "v3.1" / "benchmark.jsonl", bench)
        if v2:
            common.write_jsonl(owner / "shellsafety-v2-train.jsonl", [row("echo v2", True)])
            common.write_jsonl(owner / "shellsafety-v2-heldout.jsonl", [row("echo v2h", True)])
        common.write_jsonl(d / "states.jsonl", [])
        out = d / "out"
        res = subprocess.run(
            [sys.executable, str(HERE / "prepare.py"), "--owner", str(owner), "--out", str(out),
             "--realruns", str(d / "states.jsonl"), "--trajectories", str(d / "none.jsonl"),
             "--calib-share", "0", "--max-harmless-ratio", "10", *extra],
            capture_output=True, text=True, check=True)
        return out, json.loads(res.stdout)

    def test_v3_build_maps_file_writes_and_carries_injection(self):
        first = json.loads(common.EVAL_214.read_text(encoding="utf-8"))[0]
        train = [
            v3_row("echo bad-a", True, "dz-x", injection=True),
            v3_row("echo ok-b", False, "vcs"),
            v3_row("echo ok-note", False, "vcs", injection=True),
            v3_row("/data/x/file-a", True, "fs-write-system", injection=False),
            v3_row("C:\\work\\proj\\file-b", False, "fs-write-project", "windows"),
            v3_row("ECHO   bench-a", False, "vcs"),  # the benchmark has it
            v3_row(first["target"], first["danger"], "vcs", first["os"]),  # in the 214
        ]
        dev = [v3_row("echo dev-a", True, "dz-x", injection=True),
               v3_row("/work/proj/dev-b", False, "fs-write-project", injection=False)]
        bench = [bench_row("echo bench-a", False, id=1),
                 bench_row("/etc/bench-c", True, "fs", "fs-write-system", injection=True, id=2)]
        out, stats = self.run_prepare_v3(train, dev, bench)

        self.assertEqual(stats["inputs"]["build"], "v3")
        self.assertEqual(stats["inputs"]["v3.1/benchmark.jsonl"]["without_injection_flag"], 1)
        self.assertEqual(stats["dropped"]["matches_heldout"], 1)
        self.assertEqual(stats["dropped"]["matches_214_eval"], 1)
        rows = common.load_jsonl(out / "train.jsonl")
        by_target = {r["state"]["target"]: r for r in rows}
        self.assertEqual(len(rows), 5)
        fs = by_target["/data/x/file-a"]["state"]
        self.assertEqual((fs["capability"], fs["action"], fs["os"]), ("fs", "write", "linux"))
        self.assertNotIn("args", fs)
        self.assertEqual(by_target["C:\\work\\proj\\file-b"]["state"]["capability"], "fs")
        self.assertEqual(by_target["echo ok-b"]["state"]["capability"], "exec")
        self.assertEqual(by_target["echo ok-b"]["state"]["action"], "run")
        self.assertEqual({t: r["injection"] for t, r in by_target.items()},
                         {"echo bad-a": True, "echo ok-b": False, "echo ok-note": True,
                          "/data/x/file-a": False, "C:\\work\\proj\\file-b": False})
        self.assertEqual((stats["train"]["injection_danger"], stats["train"]["injection_harmless"],
                          stats["train"]["cap_fs"]), (1, 1, 2))
        # The benchmark is used as given (a row without the flag gets false); the dev file
        # is a second held-out file with the flag and the capability of each row.
        self.assertEqual(sorted(p.name for p in out.glob("heldout-*.json")),
                         ["heldout-v3-benchmark.json", "heldout-v3-dev.json"])
        given = json.loads((out / "heldout-v3-benchmark.json").read_text())
        self.assertEqual(given, [{**bench[0], "injection": False}, bench[1]])
        dev_cases = json.loads((out / "heldout-v3-dev.json").read_text())
        self.assertEqual([(c["cap"], c["action"], c["target"], c["danger"], c["injection"])
                          for c in dev_cases],
                         [("exec", "run", "echo dev-a", True, True),
                          ("fs", "write", "/work/proj/dev-b", False, False)])
        self.assertEqual(stats["heldout"]["v3-benchmark"]["injection_danger"], 1)
        self.assertEqual(stats["heldout"]["v3-dev"]["by_cap_os_label"],
                         {"exec/linux/danger": 1, "fs/linux/harmless": 1})

    def test_v3_build_is_preferred_unless_v2_is_asked_for(self):
        args = ([v3_row("echo new", True, "dz-x")], [], [bench_row("echo b", True)])
        _, stats = self.run_prepare_v3(*args, v2=True)
        self.assertEqual(stats["inputs"]["build"], "v3")
        self.assertNotIn("shellsafety-v2-train.jsonl", stats["inputs"])
        _, stats = self.run_prepare_v3(*args, "--shellsafety", "v2", v2=True)
        self.assertEqual(stats["inputs"]["build"], "v2")
        self.assertIn("shellsafety-v2-train.jsonl", stats["inputs"])

    def test_structure_buckets(self):
        def b(text):
            return common.buckets(text)
        self.assertEqual(b("echo a"), ("<80", "0", "0"))
        self.assertEqual(b("echo " + "w" * 75), ("80-300", "0", "0"))
        self.assertEqual(b("echo " + "w" * 295), ("300-1000", "0", "0"))
        self.assertEqual(b("echo " + "w" * 995), ("300-1000", "0", "0"))
        self.assertEqual(b("echo " + "w" * 996), (">1000", "0", "0"))
        # `|`, `&&`, `||` and `;` count; `\\;` of find and `;;` do not
        self.assertEqual(b("a | b && c || d; e")[1], "3-5")
        self.assertEqual(b("a;b;c;d;e;f;g")[1], "6+")
        self.assertEqual(b("find . -exec x {} \\;")[1], "0")
        self.assertEqual(b("a | b")[1], "1-2")
        # nesting: substitutions, backticks and the shell wrappers
        self.assertEqual(common.structure("echo $(a)")[2], 1)
        self.assertEqual(common.structure("echo $(a $(b $(c)))")[2], 3)
        self.assertEqual(common.structure("echo `a`")[2], 1)
        self.assertEqual(common.structure("echo '$(a)'")[2], 0)  # a literal
        self.assertEqual(common.structure("a (b) c")[2], 0)
        self.assertEqual(common.structure("sh -c 'a b'")[2], 1)
        self.assertEqual(common.structure('bash -c "echo $(a)"')[2], 2)
        self.assertEqual(common.structure('cmd /c "dir && dir"')[2], 1)
        self.assertEqual(common.structure("powershell -Command Get-Item | Out-Null")[2], 1)
        self.assertEqual(common.structure('bash -c "bash -c \\"echo $(a)\\""')[2], 3)
        self.assertEqual(b("sh -c 'a'; echo ok")[2], "1")

    def test_prepare_counts_the_buckets_of_what_it_writes(self):
        cmds = ["echo a", "a | b | c | d", "echo $(a $(b))", "echo " + "w" * 400]
        train = [v3_row(c, i % 2 == 0, "x") for i, c in enumerate(cmds)]
        train.append(v3_row("/data/p/file-a", True, "fs-write-system"))
        bench = [bench_row("echo " + "w" * 1100, False)]
        _, stats = self.run_prepare_v3(train, [], bench)
        st = stats["structure"]["train"]
        self.assertEqual(st["length"], {"300-1000/harmless": 1, "<80/danger": 2,
                                        "<80/harmless": 1})
        self.assertEqual(st["chain_ops"], {"0/danger": 2, "0/harmless": 1, "3-5/harmless": 1})
        self.assertEqual(st["nesting"], {"0/danger": 1, "0/harmless": 2, "2+/danger": 1})
        self.assertEqual(stats["structure"]["heldout"]["v3-benchmark"]["length"],
                         {">1000/harmless": 1})

    def test_evaluate_reports_injection_both_ways_and_the_breakdown(self):
        cases = [
            bench_row("echo a", True, injection=True),                # 0: dangerous injection
            bench_row("echo b", False, injection=True),               # 1: harmless injection
            bench_row("a | b | c | d", True, os_name="windows"),      # 2
            bench_row("/etc/x", False, "fs", "fs-write-system"),      # 3
            {**bench_row("echo c", True), "kind": "injection"},       # 4: the 214's shape
            bench_row("echo " + "w" * 400, False),                    # 5
        ]
        scores = [0.9, 0.7, 0.4, 0.95, 0.85, 0.2]
        path = Path(self.tmp.name) / "scores.jsonl"
        common.write_jsonl(path, [{"index": i, "score": sc, "danger": c["danger"],
                                   "kind": c["kind"]} for i, (c, sc) in enumerate(zip(cases, scores))])
        m = {x["threshold"]: x for x in evaluate.metrics(path, cases)}
        self.assertEqual((m[0.8]["catch"], m[0.8]["benign_refused"]), (66.7, 33.3))
        # dangerous injection: cases 0 and 4 are caught at 0.8; harmless injection: case 1 is not
        self.assertEqual((m[0.8]["injection_catch"], m[0.8]["injection_refused"]), (100.0, 0.0))
        self.assertEqual((m[0.6]["injection_catch"], m[0.6]["injection_refused"]), (100.0, 100.0))
        self.assertEqual((m[0.8]["injection"], m[0.8]["injection_benign"]), (2, 1))
        by = evaluate.breakdown(path, cases)["0.8"]
        self.assertEqual(by["cap"]["fs"], {"dangerous": 0, "catch": None, "benign": 1,
                                           "benign_refused": 100.0})
        self.assertEqual(by["os"]["windows"]["catch"], 0.0)
        self.assertEqual(list(by["chain_ops"]), ["0", "3-5"])
        self.assertEqual(by["chain_ops"]["3-5"]["dangerous"], 1)
        self.assertEqual(list(by["length"]), ["<80", "300-1000"])
        self.assertEqual(by["length"]["300-1000"]["benign_refused"], 0.0)
        self.assertEqual(by["injection"]["yes"]["dangerous"], 2)

    def test_missing_owner_files_fail(self):
        d = Path(self.tmp.name)
        res = subprocess.run([sys.executable, str(HERE / "prepare.py"), "--owner", str(d / "none"),
                              "--out", str(d / "o")], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing", res.stderr)


if __name__ == "__main__":
    unittest.main()
