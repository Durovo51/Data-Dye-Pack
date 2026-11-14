"""Proof checks. Run with: python3 -m unittest tests.test_proof -v"""

import argparse
import contextlib
import io
import json
import sqlite3
import statistics
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from dyepack import honey, lab, proof, schema, vocab
from dyepack.profile import build_profile


class ProofTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = lab.make_rows(20_000, seed=9)
        cls.profile = build_profile(cls.table)

    def test_two_thousand_rows_in_under_30_seconds(self):
        start = time.perf_counter()
        result = proof.prove(self.table[:2000], self.profile)
        took = time.perf_counter() - start
        self.assertLess(took, 30, f"took {took:.1f}s")
        self.assertEqual((result["rows"], result["lists"]), (2000, 100))
        self.assertEqual(set(result["rank"]), set(proof.TESTS))
        for rank in result["rank"].values():
            self.assertTrue(1 <= rank <= 100, rank)
        self.assertEqual(result["repeats"], {"real": 0, "fakes": 0})

    def test_real_list_lands_mid_pack_on_average(self):
        # one run can land anywhere, so average a few. with 20 lists the middle is 10.5
        ranks = []
        for _ in range(8):
            ranks += proof.prove(self.table[:1000], self.profile, fakes=19)["rank"].values()
        self.assertTrue(4 < statistics.mean(ranks) < 17, ranks)

    def test_naive_header_gives_the_real_list_away(self):
        # exact counts from the very rows being locked: the real list fits them best every time
        rows = self.table[:1000]
        result = proof.prove(rows, build_profile(rows), fakes=19, naive=True)
        self.assertEqual(result["rank"]["chi_square"], 1)
        self.assertEqual(result["rank"]["g_test"], 1)

    def test_scoring_parts_matches_scoring_rows(self):
        # prove scores decoded parts to save time. that's only fair if rows parse back to the
        # same parts, which needs every name pair to give distinct email and login styles
        for first in vocab.FIRST_NAMES:
            for last in vocab.LAST_NAMES:
                emails = {vocab._email_local(s, first, last) for s in vocab.EMAIL_STYLES}
                logins = {vocab._user_base(s, first, last) for s in vocab.USER_STYLES}
                self.assertEqual((len(emails), len(logins)), (3, 3), (first, last))
        blob = honey.lock(self.table[:500], "correct horse", self.profile, iterations=proof.ROUNDS)
        weights = honey._read(blob)[0]["parts"]
        guesses = ["correct horse", "guess one", "guess two"]
        for guess, parts in zip(guesses, proof._opened(blob, guesses)):
            rows = honey.open_locked(blob, guess)
            self.assertEqual(rows, [vocab.compose(p) for p in parts])
            self.assertEqual(proof.score(parts, weights),
                             proof.score([vocab.decompose(r) for r in rows], weights))

    def test_needs_rows_and_a_wrong_password(self):
        with self.assertRaises(ValueError):
            proof.prove(self.table[:10], self.profile, fakes=0)
        with self.assertRaises(ValueError):
            proof.prove([], self.profile)


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        rows = lab.make_rows(2500, seed=4)
        cls.db, cls.prof = Path(tmp.name) / "lakeview.db", Path(tmp.name) / "profile.json"
        con = sqlite3.connect(cls.db)
        con.execute(f"CREATE TABLE customers ({', '.join(schema.CUSTOMER_FIELDS)})")
        marks = ", ".join("?" * len(schema.CUSTOMER_FIELDS))
        con.executemany(f"INSERT INTO customers VALUES ({marks})",
                        [[r[f] for f in schema.CUSTOMER_FIELDS] for r in rows])
        con.commit()
        con.close()
        cls.prof.write_text(json.dumps(build_profile(rows)))

    def run_prove(self, **args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(schema, "DB_PATH", self.db):
            with mock.patch.object(schema, "PROFILE_PATH", self.prof):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    start = time.perf_counter()
                    code = proof.cmd_prove(argparse.Namespace(**args))
                    took = time.perf_counter() - start
        return code, out.getvalue(), err.getvalue(), took

    def test_prints_a_few_clean_lines(self):
        code, text, _, _ = self.run_prove(rows=300, fakes=19)
        self.assertEqual(code, 0)
        lines = text.splitlines()
        self.assertEqual(lines[0], "locked 300 customers, then opened the file with 19 wrong passwords")
        self.assertEqual(sum("real list ranked" in line and "of 20" in line for line in lines), 3)
        self.assertIn("0 in the real list, 0 across the fakes", text)

    def test_compare_puts_the_naive_header_at_1_in_under_15_seconds(self):
        code, text, _, took = self.run_prove(rows=2000, fakes=99, compare=True)
        self.assertEqual(code, 0)
        self.assertLess(took, 15, f"took {took:.1f}s")
        ranks = {}
        for line in text.splitlines():
            for test, label in proof.LABELS.items():
                if line.startswith(f"  {label} "):
                    ranks[test] = [int(x) for x in line[len(label) + 2:].split()]
        self.assertEqual(set(ranks), set(proof.TESTS))
        self.assertEqual(ranks["chi_square"][0], 1)
        self.assertEqual(ranks["g_test"][0], 1)
        for naive, ours in ranks.values():
            self.assertTrue(1 <= naive <= 100 and 1 <= ours <= 100)

    def test_small_compare_says_why_ours_can_sit_low(self):
        code, text, _, _ = self.run_prove(rows=300, fakes=9, compare=True)
        self.assertEqual(code, 0)
        self.assertIn("note: a table under 2,000 rows", text)
        code, text, _, _ = self.run_prove(rows=300, fakes=9)
        self.assertNotIn("note:", text)

    def test_no_lab_fails_politely(self):
        with mock.patch.object(schema, "DB_PATH", Path("/nonexistent/lakeview.db")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = proof.cmd_prove(argparse.Namespace())
        self.assertEqual(code, 1)
        self.assertIn("dyepack lab", err.getvalue())


if __name__ == "__main__":
    unittest.main()
