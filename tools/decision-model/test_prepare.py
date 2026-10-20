"""Tests for prepare.py on placeholder rows (no real commands): dedup,
conflicting labels, held-out and 214-case overlap, balance, output format.

    python -m unittest test_prepare
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import common
import prepare

HERE = Path(__file__).resolve().parent


def word(i):
    """A digit-free token per number (the canonical form folds digits)."""
    return "".join("abcdefghij"[int(c)] for c in str(i))


def row(cmd, danger, os_name="linux"):
    return {"command": cmd, "os": os_name, "danger": danger, "category": "test", "source": "test"}


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

    def test_missing_owner_files_fail(self):
        d = Path(self.tmp.name)
        res = subprocess.run([sys.executable, str(HERE / "prepare.py"), "--owner", str(d / "none"),
                              "--out", str(d / "o")], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing", res.stderr)


if __name__ == "__main__":
    unittest.main()
