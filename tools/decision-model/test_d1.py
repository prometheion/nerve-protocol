"""Tests of d1.py's pure parts (no torch, no model): the prompt llama.cpp's
`systemone` template writes for d1-3B, and the batching. Placeholder rows only.

    python3 -m unittest test_d1
"""

import json
import random
import unittest

import common
import d1


class PromptTest(unittest.TestCase):
    def test_noul_prompt_is_what_the_server_template_writes(self):
        state = {"action": "run", "capability": "exec", "os": "linux", "tainted": False,
                 "target": "ls"}
        q = {"type": "noul", "instructions": "Is it bad?",
             "criteria": {"true": "Bad.", "false": "Fine."}}
        want = ("<|startoftext|><|im_start|>user\n" + json.dumps(state, indent=2) +
                "\n\n\nQUESTION:\nIs it bad?\nYes: Bad.\nNo: Fine.\n\n"
                "Reply with yes or no only.<|im_end|>\n<|im_start|>assistant\n")
        self.assertEqual(d1.prompt_text(state, q), want)

    def test_no_criteria_no_yes_no_lines(self):
        text = d1.prompt_text({"a": 1}, {"type": "noul", "instructions": "Q?"})
        self.assertIn("QUESTION:\nQ?\n\nReply with yes or no only.", text)
        self.assertNotIn("Yes:", text)

    def test_the_centers_question_renders(self):
        text = d1.prompt_text({"target": "x"}, common.question()["danger"])
        self.assertIn(common.INSTRUCTIONS, text)
        self.assertIn(f"\nYes: {common.CRITERIA_TRUE}\nNo: {common.CRITERIA_FALSE}\n", text)

    def test_non_ascii_is_not_escaped(self):
        self.assertIn("ä€", d1.prompt_text({"target": "ä€"}, {"instructions": "Q"}))


class BatchTest(unittest.TestCase):
    ITEMS = [([0] * n, 0) for n in (5, 900, 40, 41, 300, 7, 1500, 12, 260, 80, 3, 640)]

    def test_micro_batches_keep_the_padded_size_and_all_rows(self):
        mbs = d1.micro_batches(list(range(len(self.ITEMS))), self.ITEMS, 1000)
        self.assertEqual(sorted(i for mb in mbs for i in mb), list(range(len(self.ITEMS))))
        for mb in mbs:
            longest = max(len(self.ITEMS[i][0]) for i in mb)
            # a single row longer than the budget is its own batch
            self.assertTrue(len(mb) == 1 or longest * len(mb) <= 1000, mb)

    def test_token_steps_cover_every_row_once_inside_the_budget(self):
        steps = d1.token_steps(self.ITEMS, 1000, random.Random(1))
        self.assertEqual(sorted(i for st in steps for i in st), list(range(len(self.ITEMS))))
        for st in steps:
            longest = max(len(self.ITEMS[i][0]) for i in st)
            self.assertTrue(len(st) == 1 or longest * len(st) <= 1000, st)

    def test_steps_are_reproducible(self):
        a = d1.token_steps(self.ITEMS, 1000, random.Random(7))
        b = d1.token_steps(self.ITEMS, 1000, random.Random(7))
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
