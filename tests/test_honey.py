"""Honey lock checks. Run with: python3 -m unittest tests.test_honey -v"""

import argparse
import collections
import contextlib
import hashlib
import io
import json
import math
import random
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from dyepack import honey, lab, schema, vocab
from dyepack.profile import build_profile

FAST = 1000  # pbkdf2 rounds, keeps the tests quick
CATS = [name for name, kind in vocab.PARTS if kind == "cat"]


def edge_rows():
    # both ends of every number range, two word streets and one zip cities
    nums = {name: kind[1:] for name, kind in vocab.PARTS if kind not in ("cat", "zip")}
    low = {name: lo for name, (lo, hi) in nums.items()}
    high = {name: hi for name, (lo, hi) in nums.items()}
    a = dict(low, first_name="Ana", last_name="Henderson", street_name="Mineral Point",
             street_type="Pl", city="Sauk City", zip_idx=0, email_style="firstl",
             email_domain="att.net", plan="DSL 25", addon="Static IP", since_year="2008",
             user_style="first.l")
    b = dict(high, first_name="Raj", last_name="Fisher", street_name="Old Sauk",
             street_type="Way", city="West Bend", zip_idx=1, email_style="first.last",
             email_domain="aol.com", plan="Fiber 2 Gig", addon="TV Basic", since_year="2026",
             user_style="flast")
    return vocab.compose(a), vocab.compose(b)


def fit(rows, weights):
    # two checks a thief could run against the header weights, over every "cat" part:
    # chi square distance of the value counts, and log likelihood of the list
    parts = [vocab.decompose(r) for r in rows]
    chi = likely = 0.0
    for name in CATS:
        w = weights[name]
        total = sum(w.values())
        got = collections.Counter(p[name] for p in parts)
        chi += sum((got[v] - len(rows) * x / total) ** 2 / (len(rows) * x / total) for v, x in w.items())
        likely += sum(n * math.log(w[v] / total) for v, n in got.items())
    return chi, likely


class HoneyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # a lab table and its profile, like dyepack seed makes
        cls.table = lab.make_rows(20_000, seed=7)
        cls.profile = build_profile(cls.table)
        cls.rows = cls.table[:2000]

    def test_right_password_gives_back_the_exact_rows(self):
        first, last = edge_rows()
        keys = {first["account_no"], last["account_no"], first["portal_user"], last["portal_user"]}
        middle = [r for r in self.rows[:500] if not keys & {r["account_no"], r["portal_user"]}]
        rows = [first, *middle, last]
        blob = honey.lock(rows, "correct horse", self.profile, iterations=FAST)
        self.assertEqual(honey.open_locked(blob, "correct horse"), rows)
        self.assertEqual(honey.open_locked(blob, "correct horse", limit=3), rows[:3])

    def test_round_trip_without_a_profile_or_with_a_stale_one(self):
        rows = self.rows[:300]
        stale = json.loads(json.dumps(self.profile))
        del stale["parts"]["first_name"][rows[0]["first_name"]]  # table grew after profiling
        for prof in (None, stale):
            blob = honey.lock(rows, "correct horse", prof, iterations=FAST)
            self.assertEqual(honey.open_locked(blob, "correct horse"), rows)

    def test_every_wrong_password_opens_believable_rows(self):
        rows = self.rows[:200]
        blob = honey.lock(rows, "correct horse", self.profile, iterations=FAST)
        guesses = [f"guess{i}" for i in range(296)]
        guesses += ["", "correct horse ", "Correct Horse", "pässwörd \U0001F511"]
        for guess in guesses:
            fake = honey.open_locked(blob, guess)
            self.assertEqual(len(fake), len(rows))
            self.assertNotEqual(fake, rows)
            for row in fake:
                vocab.decompose(row)  # raises if a row breaks the recipe

    def test_fakes_follow_the_profile(self):
        blob = honey.lock(self.rows, "correct horse", self.profile, iterations=FAST)
        seen = {"city": collections.Counter(), "plan": collections.Counter()}
        for i in range(50):
            for row in honey.open_locked(blob, f"guess{i}"):
                for field, counter in seen.items():
                    counter[row[field]] += 1
        for field, counter in seen.items():
            want = self.profile["parts"][field]
            total = sum(want.values())
            for value, n in want.items():
                self.assertAlmostEqual(counter[value] / 100_000, n / total, delta=0.02,
                                       msg=f"{field} {value}")

    def test_header_holds_nothing_from_the_password(self):
        rows = self.rows[:100]
        pieces = {}
        for pw in ("correct horse", "battery staple"):
            with mock.patch.object(honey, "_rng", random.Random(4)):  # same salt and noise both times
                pieces[pw] = honey.lock(rows, pw, self.profile, iterations=FAST).split(b"\n", 2)
        a, b = pieces["correct horse"], pieces["battery staple"]
        self.assertEqual(a[:2], b[:2])  # magic and header match byte for byte
        self.assertNotEqual(a[2], b[2])  # only the scrambled rows change
        head = json.loads(a[1])
        self.assertEqual(set(head), {"salt", "iterations", "rows", "parts"})
        key = hashlib.pbkdf2_hmac("sha256", b"correct horse", bytes.fromhex(head["salt"]), FAST)
        for secret in (b"correct horse", key, key.hex().encode()):
            self.assertNotIn(secret, a[0] + b"\n" + a[1])

    def test_fifty_thousand_rows_stay_fast(self):
        rows = lab.make_rows(50_000, seed=3)
        prof = build_profile(rows)
        start = time.perf_counter()
        blob = honey.lock(rows, "correct horse", prof, iterations=FAST)
        locked = time.perf_counter() - start
        start = time.perf_counter()
        back = honey.open_locked(blob, "correct horse")
        opened = time.perf_counter() - start
        start = time.perf_counter()
        first = honey.open_locked(blob, "wrong guess", limit=20)
        quick = time.perf_counter() - start
        self.assertEqual(back, rows)
        self.assertLess(locked, 10, f"lock took {locked:.1f}s")
        self.assertLess(opened, 10, f"open took {opened:.1f}s")
        self.assertLess(quick, 0.5, f"limit=20 took {quick:.2f}s")
        fake = honey.open_locked(blob, "wrong guess")
        self.assertEqual(first, fake[:20])
        # a thief's first check: the real table never repeats these, so a fake can't either
        for field in ("account_no", "portal_user"):
            self.assertEqual(len({r[field] for r in fake}), len(fake), field)

    def test_real_list_doesnt_fit_the_header_better_than_fakes(self):
        # exact counts in the header would match the real list almost perfectly and give it away
        prof = build_profile(self.rows)
        blob = honey.lock(self.rows, "correct horse", prof, iterations=FAST)
        weights = json.loads(blob.split(b"\n", 2)[1])["parts"]
        real = fit(self.rows, weights)[0]
        fakes = sorted(fit(honey.open_locked(blob, f"guess{i}"), weights)[0] for i in range(19))
        self.assertGreater(real, fakes[9] / 2)
        self.assertLess(real, fakes[9] * 2)

    def test_real_list_isnt_the_least_likely_either(self):
        # the other side: noisy weights can make the real list the least likely one, so rank it
        # among 9 fakes over a dozen locks. 4.5 means it blends in, a plain 0.5 prior lands near 0.3
        rows = self.rows[:1000]
        prof = build_profile(rows)
        ranks = []
        for t in range(12):
            blob = honey.lock(rows, "correct horse", prof, iterations=FAST)
            weights = json.loads(blob.split(b"\n", 2)[1])["parts"]
            real = fit(rows, weights)[1]
            fakes = [fit(honey.open_locked(blob, f"guess{t}.{i}"), weights)[1] for i in range(9)]
            ranks.append(sum(f < real for f in fakes))
        self.assertTrue(1.5 < sum(ranks) / len(ranks) < 7.5, ranks)

    def test_bad_input_is_refused_clearly(self):
        rows = self.rows[:20]
        twin = dict(rows[1], account_no="LV00000001")  # new account, same login
        for bad in (rows + [dict(rows[0])], rows + [twin]):
            with self.assertRaises(ValueError):
                honey.lock(bad, "correct horse", self.profile, iterations=FAST)
        blob = honey.lock(rows, "correct horse", self.profile, iterations=FAST)
        for broken in (b"", b"hello\nthere\n", blob[:-1], b"DYEPACK2" + blob[8:]):
            with self.assertRaises(ValueError):
                honey.open_locked(broken, "correct horse")


class CliTest(unittest.TestCase):
    def setUp(self):
        self.rows = lab.make_rows(300, seed=5)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        db = self.dir / "lakeview.db"
        con = sqlite3.connect(db)
        con.execute(f"CREATE TABLE customers ({', '.join(schema.CUSTOMER_FIELDS)})")
        con.executemany(f"INSERT INTO customers VALUES ({', '.join('?' * len(schema.CUSTOMER_FIELDS))})",
                        [[r[f] for f in schema.CUSTOMER_FIELDS] for r in self.rows])
        con.commit()
        con.close()
        prof = self.dir / "profile.json"
        prof.write_text(json.dumps(build_profile(self.rows)))
        for name, path in (("DB_PATH", db), ("PROFILE_PATH", prof)):
            patcher = mock.patch.object(schema, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cmd(self, cmd, **args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cmd(argparse.Namespace(**args))
        return code, out.getvalue(), err.getvalue()

    def test_lock_then_open_prints_a_small_table(self):
        out = self.dir / "exports" / "nightly.dye"
        code, text, _ = self.run_cmd(honey.cmd_lock, out=str(out), password="correct horse")
        self.assertEqual(code, 0)
        self.assertIn("300", text)
        accounts = {r["account_no"] for r in self.rows}
        for pw, real in (("correct horse", True), ("wrong guess", False)):
            code, text, _ = self.run_cmd(honey.cmd_open, file=str(out), password=pw, limit=3)
            self.assertEqual(code, 0)
            lines = text.splitlines()
            self.assertEqual(lines[0], "3 of 300 customers")
            shown = [line.split()[0] for line in lines[2:]]
            self.assertEqual(len(shown), 3)
            self.assertEqual(all(a in accounts for a in shown), real)
            self.assertNotIn(pw, text)

    def test_mistyped_confirmation_writes_nothing(self):
        out = self.dir / "typo.dye"
        with mock.patch("getpass.getpass", side_effect=["correct horse", "correct hrose"]):
            with self.assertRaises(SystemExit):
                self.run_cmd(honey.cmd_lock, out=str(out), password=None)
        self.assertFalse(out.exists())

    def test_missing_files_fail_politely(self):
        code, _, err = self.run_cmd(honey.cmd_open, file=str(self.dir / "nope.dye"), password="x", limit=5)
        self.assertEqual(code, 1)
        self.assertIn("can't read", err)
        with mock.patch.object(schema, "DB_PATH", self.dir / "missing.db"):
            code, _, err = self.run_cmd(honey.cmd_lock, out=str(self.dir / "x.dye"), password="x")
        self.assertEqual(code, 1)
        self.assertIn("dyepack lab", err)


if __name__ == "__main__":
    unittest.main()
