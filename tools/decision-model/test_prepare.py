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


class PrepareTest(unittest.TestCase):
    def run_prepare(self, train, heldout, realruns, *extra):
        d = Path(self.tmp.name)
        owner = d / "owner"
        common.write_jsonl(owner / "shellsafety-train.jsonl", train)
        common.write_jsonl(owner / "shellsafety-heldout.jsonl", heldout)
        common.write_jsonl(d / "states.jsonl", realruns)
        out = d / "out"
        res = subprocess.run(
            [sys.executable, str(HERE / "prepare.py"), "--owner", str(owner), "--out", str(out),
             "--realruns", str(d / "states.jsonl"), "--calib-share", "0", *extra],
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

    def test_missing_owner_files_fail(self):
        d = Path(self.tmp.name)
        res = subprocess.run([sys.executable, str(HERE / "prepare.py"), "--owner", str(d / "none"),
                              "--out", str(d / "o")], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing", res.stderr)


if __name__ == "__main__":
    unittest.main()
