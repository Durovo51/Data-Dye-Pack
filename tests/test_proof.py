"""Proof checks. Run with: python3 -m unittest tests.test_proof -v"""

import argparse
import contextlib
import io
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
        result = proof.prove(self.table[:2000], None)
        took = time.perf_counter() - start
        self.assertLess(took, 30, f"took {took:.1f}s")
        self.assertEqual((result["rows"], result["lists"]), (2000, 100))
        self.assertEqual(set(result["rank"]), set(proof.TESTS))
        for rank in result["rank"].values():
            self.assertTrue(1 <= rank <= 100, rank)
        self.assertEqual(result["repeats"], {"real": 0, "fakes": 0})

    def test_lab_lock_lands_mid_pack_on_every_check(self):
        # the lab locks with the recipe's weights (profile None). one run can land anywhere,
        # so average a dozen per check. with 20 lists the middle is 10.5
        ranks = {test: [] for test in proof.TESTS}
        for i in range(12):
            result = proof.prove(self.table[i * 1000:(i + 1) * 1000], None, fakes=19)
            for test, rank in result["rank"].items():
                ranks[test].append(rank)
        for test, got in ranks.items():
            self.assertTrue(4 < statistics.mean(got) < 17, (test, got))

    def test_recipe_fit_catches_a_header_built_from_the_rows(self):
        # jittered counts beat the header checks, but anyone with the repo knows the recipe
        # the lab draws from, and the real list fits it far better than fakes drawn around it
        rows = self.table[:2000]
        result = proof.prove(rows, build_profile(rows), fakes=19)
        self.assertEqual(result["rank"]["recipe_fit"], 1)

    def test_naive_header_gives_the_real_list_away(self):
        # exact counts from the very rows being locked: the real list fits them best every time
        rows = self.table[:1000]
        result = proof.prove(rows, build_profile(rows), fakes=19, naive=True)
        for test in ("chi_square", "g_test", "recipe_fit"):
            self.assertEqual(result["rank"][test], 1, test)

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
        cls.db = Path(tmp.name) / "lakeview.db"
        con = sqlite3.connect(cls.db)
        con.execute(f"CREATE TABLE customers ({', '.join(schema.CUSTOMER_FIELDS)})")
        marks = ", ".join("?" * len(schema.CUSTOMER_FIELDS))
        con.executemany(f"INSERT INTO customers VALUES ({marks})",
                        [[r[f] for f in schema.CUSTOMER_FIELDS] for r in rows])
        con.commit()
        con.close()

    def run_prove(self, **args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(schema, "DB_PATH", self.db):
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
        ranked = [line for line in lines if "real list ranked" in line and "of 20" in line]
        self.assertEqual(len(ranked), len(proof.TESTS))
        self.assertIn("0 in the real list, 0 across the fakes", text)

    def test_compare_shows_both_giveaways_in_under_15_seconds(self):
        code, text, _, took = self.run_prove(rows=2000, fakes=99, compare=True)
        self.assertEqual(code, 0)
        self.assertLess(took, 15, f"took {took:.1f}s")
        ranks = {}
        for line in text.splitlines():
            for test, label in proof.LABELS.items():
                if line.startswith(f"  {label} "):
                    ranks[test] = [int(x) for x in line[len(label) + 2:].split()]
        self.assertEqual(set(ranks), set(proof.TESTS))
        for test in ("chi_square", "g_test", "recipe_fit"):
            self.assertEqual(ranks[test][0], 1, f"exact counts, {test}")
        self.assertEqual(ranks["recipe_fit"][1], 1, "jittered counts, recipe fit")
        for exact, jittered, ours in ranks.values():
            self.assertTrue(all(1 <= r <= 100 for r in (exact, jittered, ours)))

    def test_no_lab_fails_politely(self):
        with mock.patch.object(schema, "DB_PATH", Path("/nonexistent/lakeview.db")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = proof.cmd_prove(argparse.Namespace())
        self.assertEqual(code, 1)
        self.assertIn("dyepack lab", err.getvalue())


if __name__ == "__main__":
    unittest.main()
