import json
import os
import random
import sqlite3
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from dyepack import canary, honey, lab, schema, server, vocab
from dyepack.profile import build_profile
from dyepack.tripwire import Tripwire

ROOT = Path(__file__).resolve().parents[1]


def run(data, *args):
    return subprocess.run(
        [sys.executable, "-m", "dyepack", *args],
        cwd=ROOT, env={**os.environ, "DYEPACK_DATA": str(data)}, capture_output=True, text=True,
    )


class SeedTest(unittest.TestCase):
    """runs the real commands on a small lab in a temp folder"""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.data = Path(tmp.name)
        cls.lab = run(cls.data, "lab", "--customers", "6000", "--seed", "3")
        cls.seed = run(cls.data, "seed", "--every", "30")
        cls.again = run(cls.data, "seed")
        if cls.lab.returncode or cls.seed.returncode:
            raise RuntimeError(cls.lab.stderr + cls.seed.stderr)
        cls.con = sqlite3.connect(cls.data / "lakeview.db")
        cls.addClassCleanup(cls.con.close)
        cls.watch = json.loads((cls.data / "watch_list.json").read_text())["canaries"]
        cls.watched = {c["account_no"] for c in cls.watch}

    def rows(self, table):
        cols = ", ".join(schema.CUSTOMER_FIELDS)
        found = self.con.execute(f"SELECT {cols} FROM {table} ORDER BY rowid")
        return [dict(zip(schema.CUSTOMER_FIELDS, t)) for t in found]

    def test_commands_print_counts(self):
        self.assertEqual(self.lab.returncode, 0, self.lab.stderr)
        self.assertEqual(self.seed.returncode, 0, self.seed.stderr)
        self.assertIn("6,000", self.lab.stdout)
        self.assertIn("planted 200 canaries", self.seed.stdout)
        self.assertIn("customers_clean    6,000 rows  0 canaries", self.seed.stdout)

    def test_canary_counts(self):
        self.assertEqual(len(self.watch), 6000 // 30)
        self.assertEqual(len(self.rows("customers")), 6000 + len(self.watch))
        self.assertEqual(len(self.rows("customers_clean")), 6000)

    def test_clean_table_has_no_canaries(self):
        clean = {r["account_no"] for r in self.rows("customers_clean")}
        everyone = {r["account_no"] for r in self.rows("customers")}
        self.assertFalse(self.watched & clean)
        self.assertEqual(everyone, clean | self.watched)

    def test_accounts_and_logins_unique(self):
        rows = self.rows("customers")
        for field in ("account_no", "portal_user"):
            self.assertEqual(len({r[field] for r in rows}), len(rows), field)
        # every customer, canaries too, has a portal login in the same shuffled order
        portal = [u for (u,) in self.con.execute("SELECT portal_user FROM portal_accounts ORDER BY rowid")]
        self.assertEqual(portal, [r["portal_user"] for r in rows])

    def test_canaries_spread_through_the_table(self):
        rows = self.rows("customers")
        spots = [i for i, r in enumerate(rows) if r["account_no"] in self.watched]
        quarter = len(rows) // 4
        for q in range(4):
            self.assertTrue(any(q * quarter <= s < (q + 1) * quarter for s in spots), q)

    def test_watch_list(self):
        self.assertEqual(len({c["canary_id"] for c in self.watch}), len(self.watch))
        self.assertEqual({c["batch"] for c in self.watch}, {"table"})
        real = [r for r in self.rows("customers") if r["account_no"] not in self.watched]
        contacts = {r["email"] for r in real} | {r["phone"] for r in real}
        for c in self.watch:
            self.assertNotIn(c["email"], contacts)
            self.assertNotIn(c["phone"], contacts)

    def test_secret_files_are_owner_only(self):
        for name in ("lab_logins.json", "watch_list.json", "lakeview.db"):
            self.assertEqual(stat.S_IMODE((self.data / name).stat().st_mode), 0o600, name)

    def test_staff_logins(self):
        logins = json.loads((self.data / "lab_logins.json").read_text())
        self.assertEqual(sorted(logins), sorted(lab.STAFF))
        staff = self.con.execute("SELECT user, password_hash, salt, role FROM staff").fetchall()
        self.assertEqual(len(staff), len(lab.STAFF))
        for user, password_hash, salt, role in staff:
            self.assertEqual(role, lab.STAFF[user])
            self.assertTrue(lab.check_password(logins[user], password_hash, salt))
            self.assertFalse(lab.check_password(logins[user] + "x", password_hash, salt))

    def test_passwords_never_printed(self):
        logins = json.loads((self.data / "lab_logins.json").read_text())
        printed = "".join(r.stdout + r.stderr for r in (self.lab, self.seed, self.again))
        for password in logins.values():
            self.assertNotIn(password, printed)

    def test_profile_counts_real_rows_only(self):
        saved = json.loads((self.data / "profile.json").read_text())
        self.assertEqual(saved, build_profile(self.rows("customers_clean")))

    def test_every_row_fits_the_recipe(self):
        for r in self.rows("customers"):
            vocab.decompose(r)

    def test_second_seed_is_refused(self):
        self.assertEqual(self.again.returncode, 1)
        self.assertIn("already planted", self.again.stderr)
        self.assertEqual(len(self.rows("customers")), 6000 + len(self.watch))


class BlendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = lab.make_rows(20_000, seed=5)
        cls.profile = build_profile(cls.real)

    def canaries(self, seed):
        accounts = [r["account_no"] for r in self.real]
        users = [r["portal_user"] for r in self.real]
        rows, _ = canary.make_canaries(self.profile, 200, accounts, users, "table", rng=random.Random(seed))
        return rows

    def test_canaries_match_real_rows(self):
        # any one batch can land a low p by luck. the middle of ten can't
        results = [canary.blend_test(self.real, self.canaries(s), trials=300) for s in range(10)]
        for field in results[0]:
            self.assertGreater(statistics.median(r[field] for r in results), 0.1, field)

    def test_frequency_test_catches_odd_canaries(self):
        cities = sorted(vocab.CITIES)
        odd = [dict(r, city=random.Random(i).choice(cities)) for i, r in enumerate(self.canaries(0))]
        self.assertLess(canary.blend_test(self.real, odd, fields=("city",))["city"], 0.01)

    def test_lab_repeats_with_the_same_seed(self):
        self.assertEqual(lab.make_rows(300, seed=5), self.real[:300])
        self.assertNotEqual(lab.make_rows(300, seed=6), self.real[:300])




class FileSessionTest(unittest.TestCase):
    def test_a_process_that_comes_back_alarms_again(self):
        events = []

        def emit(kind, who, severity, detail):
            events.append({"type": kind, "session": who["id"], "severity": severity, "detail": detail})
            return events[-1]

        trip = Tripwire(emit, lambda *a: None, [])
        decoy = "/tmp/drive/customers/all_customers_full_export_2026.csv"
        trip.decoys = [{"decoy_id": "d-1", "path": decoy, "kind": "export", "rows": 1, "batch": "drive",
                        "planted_at": 0}]
        # linux events have no pid. both runs come from the same process name
        hit = {"ts": 1000.0, "pid": None, "process": "unknown", "signing_id": None, "path": decoy, "op": "read"}
        trip.file_events([hit, dict(hit, ts=1001.0)])
        trip.file_events([dict(hit, ts=1062.0)])
        opens = [e for e in events if e["type"] == "alarm" and e["detail"]["reason"] == "decoy_open"]
        self.assertEqual(len(opens), 2)
        self.assertNotEqual(opens[0]["detail"]["incident"], opens[1]["detail"]["incident"])
        self.assertEqual([e["session"] for e in opens], ["f-unknown", "f-unknown-2"])

    def test_registered_file_job_never_alarms(self):
        events = []
        jobs = [{"name": "nightly backup", "signing_id": "com.example.backup"},
                {"name": "offsite sync", "exe": "/usr/bin/rsync", "user": "backup"}]
        trip = Tripwire(lambda kind, who, sev, detail: events.append({"type": kind, "detail": detail}) or events[-1],
                        lambda *a: None, [], file_jobs=jobs)
        decoy = "/tmp/drive/customers/all_customers_full_export_2026.csv"
        trip.decoys = [{"decoy_id": "d-1", "path": decoy, "kind": "export", "rows": 1, "batch": "drive",
                        "planted_at": 0}]
        hits = [{"ts": 1.0 + i / 10, "pid": 50, "process": "/usr/local/bin/backup", "signing_id": "com.example.backup",
                 "path": decoy, "op": "read"} for i in range(40)]
        hits.append({"ts": 2.0, "pid": 51, "process": "/usr/bin/rsync", "username": "backup", "server_id": "web-01",
                     "path": decoy, "op": "read"})
        trip.file_events(hits)
        self.assertFalse([e for e in events if e["type"] == "alarm"])
        self.assertEqual({e["detail"]["job"] for e in events if e["type"] == "read"}, {"nightly backup", "offsite sync"})
        trip.file_events([dict(hits[0], pid=52, process="/usr/local/bin/node", signing_id=None)])
        self.assertEqual([e["detail"]["reason"] for e in events if e["type"] == "alarm"], ["decoy_open"])

    def test_writing_a_decoy_is_not_opening_it(self):
        events = []
        trip = Tripwire(lambda kind, who, sev, detail: events.append({"type": kind, "detail": detail}) or events[-1],
                        lambda *a: None, [])
        decoy = "/tmp/drive/backups/all_customers_backup_unencrypted.csv"
        trip.decoys = [{"decoy_id": "d-2", "path": decoy, "kind": "backup", "rows": 1, "batch": "drive",
                        "planted_at": 0}]
        for op in ("write", "rename", "open"):
            trip.file_events([{"ts": 5.0, "pid": 9, "process": "python3", "path": decoy, "op": op}])
        self.assertFalse([e for e in events if e["type"] == "alarm"])
        trip.file_events([{"ts": 6.0, "pid": 9, "process": "python3", "path": decoy, "op": "read"}])
        self.assertEqual([e["detail"]["reason"] for e in events if e["type"] == "alarm"], ["decoy_open"])


class GroupTest(unittest.TestCase):
    def setUp(self):
        self.events, self.now = [], [1000.0]

        def emit(kind, who, severity, detail):
            self.events.append({"type": kind, "session": who["id"], "severity": severity, "detail": detail})
            return self.events[-1]

        self.trip = Tripwire(emit, lambda *a: None, [])
        self.trip.clock = lambda: self.now[0]

    def alarms(self, reason):
        return [e for e in self.events if e["type"] == "alarm" and e["detail"]["reason"] == reason]

    def test_one_user_over_five_sessions_reads_as_one(self):
        sids = [self.trip.staff_login("rep.taylor", "support", f"10.0.1.{i}", True) for i in range(5)]
        rows = [f"LV{n:08d}" for n in range(150)]
        # 100 rows now and 50 more 20 s later is 450 a minute for any one session
        for later, chunk in ((0, rows[:100]), (20, rows[100:])):
            for i, sid in enumerate(sids):
                self.now[0] = 1000.0 + later + 4 * i
                if not self.trip.sessions[sid]["locked"]:
                    self.trip.read(sid, chunk, "/api/customers")
        self.assertEqual(len(self.alarms("speed")), 1)
        self.assertTrue(all(self.trip.sessions[sid]["locked"] for sid in sids))
        incidents = {e["detail"]["incident"] for e in self.events if e["type"] in ("alarm", "lock")}
        self.assertEqual(len(incidents), 1)

    def test_one_address_over_three_users_reads_as_one(self):
        users = ("rep.jordan", "rep.casey", "rep.taylor")
        sids = [self.trip.staff_login(u, "support", "198.51.100.9", True) for u in users]
        for i, sid in enumerate(sids):
            self.now[0] = 1000.0 + 3 * i
            self.trip.read(sid, [f"LV{i}{n:07d}" for n in range(90)], "/api/customers")
        self.assertEqual(len(self.alarms("speed")), 1)
        self.assertTrue(self.trip.sessions[sids[-1]]["locked"])

    def test_human_pace_stays_quiet(self):
        sid = self.trip.staff_login("rep.casey", "support", "10.0.0.12", True)
        for i in range(20):
            self.now[0] = 1000.0 + 3 * i  # one 10 row search every 3 s
            self.trip.read(sid, [f"LV{i}{n:07d}" for n in range(10)], "/api/customers")
        self.assertFalse([e for e in self.events if e["type"] == "alarm"])

    def test_a_session_held_as_a_precaution_stays_out_of_the_breach_count(self):
        oncall = {"id": "dash", "actor": "oncall", "ip": "127.0.0.1"}
        desk = self.trip.staff_login("rep.jordan", "support", "10.0.0.11", True)
        self.trip.read(desk, [f"LV{n:08d}" for n in range(6)], "/api/customers")  # the real rep's own lookups
        self.now[0] += 300
        thief = self.trip.staff_login("rep.jordan", "support", "203.0.113.7", True)
        for page in range(2):
            self.trip.read(thief, [f"LV9{page}{n:06d}" for n in range(100)], "/api/customers")
        iid = self.alarms("speed")[0]["detail"]["incident"]
        self.assertTrue(self.trip.sessions[desk]["locked"] and self.trip.sessions[thief]["locked"])
        self.assertEqual((self.trip.incidents[iid]["sessions"], self.trip.incidents[iid]["held"]), ([thief], [desk]))
        got = self.trip.respond(iid, "notify_customers", oncall)
        # the notice counts what the session that tripped the wire read. the desk session gets its own line
        self.assertEqual((got["plaintext_rows"], got["customers"], got["held_rows"]), (200, 200, 6))
        self.trip.respond(iid, "dismiss", oncall)  # a false alarm lets every session go, the held one too
        self.assertFalse(self.trip.sessions[desk]["locked"] or self.trip.sessions[thief]["locked"])


class WatchLockTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        for patch in point_at(self.data):
            patch.start()
            self.addCleanup(patch.stop)
        lab.update_watch(lambda w: {"canaries": [], "decoys": [{"decoy_id": "d-1"}]})

    def test_threads_never_drop_each_others_entries(self):
        def add(i):
            lab.update_watch(lambda w: w["canaries"].append({"canary_id": f"c-{i}"}))

        threads = [threading.Thread(target=add, args=(i,)) for i in range(30)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        watch = json.loads(schema.WATCH_PATH.read_text())
        self.assertEqual(len(watch["canaries"]), 30)
        self.assertEqual(watch["decoys"], [{"decoy_id": "d-1"}])  # keys nobody touched stay
        self.assertEqual(stat.S_IMODE(schema.WATCH_PATH.stat().st_mode), 0o600)

    def test_two_processes_never_drop_each_others_entries(self):
        code = ("from dyepack import lab\n"
                "for i in range(25):\n"
                "    lab.update_watch(lambda w: w['canaries'].append({'canary_id': 'c'}))\n")
        env = {**os.environ, "DYEPACK_DATA": str(self.data)}
        procs = [subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=env) for _ in range(2)]
        self.assertEqual([p.wait(timeout=60) for p in procs], [0, 0])
        self.assertEqual(len(json.loads(schema.WATCH_PATH.read_text())["canaries"]), 50)

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def point_at(data):
    """patches that point every data path at a temp folder"""
    paths = {"DATA_DIR": data, "DB_PATH": data / "lakeview.db", "WATCH_PATH": data / "watch_list.json",
             "PROFILE_PATH": data / "profile.json", "EXPORTS_DIR": data / "exports",
             "VAULT_DIR": data / "vault", "DRIVE_ROOT": data / "drive"}
    return [mock.patch.object(schema, name, value) for name, value in paths.items()]


class RedrawTest(unittest.TestCase):
    def test_seed_redraws_a_canary_set_that_looks_odd(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patch in point_at(Path(tmp.name)):
            patch.start()
            self.addCleanup(patch.stop)
        lab.build_lab(600, seed=3)
        odd, fine = {"city": 0.001, "plan": 0.5, "first_name": 0.5}, {"city": 0.4, "plan": 0.5, "first_name": 0.6}
        with mock.patch.object(canary, "blend_test", side_effect=[odd, fine]) as blend:
            result = canary.plant(every=30)
        self.assertEqual((blend.call_count, result["draws"], result["blend"]), (2, 2, fine))
        kept = {r["account_no"] for r in blend.call_args_list[1][0][1]}
        self.assertEqual({c["account_no"] for c in canary.load_watch()}, kept)


class ServerTest(unittest.TestCase):
    """the real server on a free port, in front of a small lab in a temp folder"""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        data = Path(tmp.name)
        for patch in point_at(data):
            patch.start()
            cls.addClassCleanup(patch.stop)
        lab.build_lab(3000, seed=3)
        canary.plant(every=250)  # the real density. denser labs make an honest rep trip the 3 canary rule
        cls.httpd, cls.app = server.start(0, quiet=True)
        cls.app.client = cls.app.notify = None  # never reach Databricks or a real phone from a test
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.httpd.server_close)
        cls.addClassCleanup(cls.httpd.shutdown)
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.logins = json.loads(lab.logins_path().read_text())
        cls.data = data

    def setUp(self):
        # each test is its own day: no per user or per address history from the one before
        self.app.trip.groups.clear()
        self.app.trip.by_actor.clear()

    def call(self, method, path, body=None, sid=None, ip=None, raw=False, headers=(), token=True):
        h = {"Content-Type": "application/json", **dict(headers)}
        if token:
            h["X-Dyepack-Token"] = self.app.token
        if sid:
            h["X-Session"] = sid
        if ip:
            h["X-Lab-Ip"] = ip
        req = urllib.request.Request(self.url + path, method=method, headers=h,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            with OPENER.open(req, timeout=30) as r:
                code, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, data = e.code, e.read()
        return code, data if raw else json.loads(data or b"null")

    def login(self, user, ip):
        code, out = self.call("POST", "/api/login", {"user": user, "password": self.logins[user]}, ip=ip)
        self.assertEqual(code, 200, out)
        return out["session"]

    def events(self, kind=None, **match):
        return [e for e in list(self.app.log) if (kind is None or e["type"] == kind)
                and all(e.get(k) == v or e["detail"].get(k) == v for k, v in match.items())]

    def alarms(self, sid):
        return [e for e in self.events("alarm", session=sid) if e["severity"] in ("high", "critical")]

    def test_failed_lock_leaves_no_canaries(self):
        before = len(canary.load_watch())
        broken = mock.Mock(lock=mock.Mock(side_effect=ValueError("a row doesn't fit")))
        with mock.patch.object(self.app, "honey", broken):
            code, out = self.call("POST", "/api/exports", {"password": "x"}, sid=self.login("rep.casey", "10.0.0.12"))
        self.assertEqual(code, 500)
        self.assertIn("export failed", out["error"])
        self.assertEqual(len(canary.load_watch()), before)

    def test_human_lookups_raise_no_alarm(self):
        sid = self.login("rep.casey", "10.0.0.12")
        # support calls come from real customers. lookups go by their account numbers
        with sqlite3.connect(schema.DB_PATH) as con:
            callers = [a for (a,) in con.execute("SELECT account_no FROM customers_clean LIMIT 5")]
        for account in callers:
            self.assertEqual(self.call("GET", f"/api/customers/{account}", sid=sid)[0], 200)
        self.assertEqual(self.call("GET", "/api/customers?q=Smith&limit=10", sid=sid)[0], 200)
        for name in ("Miller", "Olson", "Garcia"):
            self.assertEqual(self.call("GET", f"/api/customers?q={name}&limit=10", sid=sid)[0], 200)
        self.assertEqual(self.alarms(sid), [])
        self.assertEqual(self.call("GET", "/api/customers?q=x", sid="s-nope")[0], 401)

    def test_bulk_read_is_caught_and_locked(self):
        sid, start = self.login("rep.jordan", "198.51.100.23"), time.time()
        self.assertEqual(len(self.call("GET", "/api/customers?page=0&size=1000", sid=sid)[1]["customers"]), 100)
        codes = [self.call("GET", f"/api/customers?page={p}&size=100", sid=sid)[0] for p in range(1, 10)]
        self.assertIn(423, codes)
        self.assertLessEqual(codes.index(423), 3)
        caught = self.alarms(sid)  # speed or a pile of canaries, whichever comes first
        self.assertTrue(caught and caught[0]["ts"] - start < 10)
        self.assertTrue(self.events("lock", session=sid))
        exposed = sum(e["detail"]["rows"] - e["detail"]["canaries"] for e in self.events("read", session=sid))
        self.assertLessEqual(exposed, 300)

    def test_registered_job_and_permits_never_alarm(self):
        job = self.login("backup.nightly", "10.0.0.5")
        watched = {c["account_no"] for c in canary.load_watch()}
        for p in range(4):
            rows = self.call("GET", f"/api/customers?page={p}&size=500", sid=job)[1]["customers"]
            self.assertFalse(watched & {r["account_no"] for r in rows})  # jobs only see the clean table
        self.assertEqual(self.events("alarm", session=job), [])
        boss, digger = self.login("rep.casey", "10.0.0.12"), self.login("rep.taylor", "10.0.0.13")
        self.assertEqual(self.call("POST", "/api/permits", {"who": "rep.casey", "minutes": 5}, sid=boss)[0], 400)
        self.addCleanup(self.app.trip.permits.clear)
        self.assertEqual(self.call("POST", "/api/permits", {"who": "rep.taylor", "minutes": 5}, sid=boss)[0], 200)
        for p in range(4):
            self.assertEqual(self.call("GET", f"/api/customers?page={p}&size=500", sid=digger)[0], 200)
        self.assertEqual(self.events("alarm", session=digger), [])

    def test_slow_reader_is_caught_by_canaries(self):
        sid = self.login("rep.taylor", "10.0.0.13")
        table = [c["account_no"] for c in canary.load_watch() if c["batch"] == "table"][:4]
        codes = [self.call("GET", f"/api/customers/{a}", sid=sid)[0] for a in table]
        self.assertEqual(codes, [200, 200, 200, 423])
        self.assertEqual([e["severity"] for e in self.events("alarm", session=sid)], ["low", "low", "high"])
        self.assertTrue(self.events("lock", session=sid))

    def test_stolen_export_names_itself(self):
        sid = self.login("rep.taylor", "198.51.100.77")
        code, out = self.call("POST", "/api/exports", {"password": "Lakeview2026!"}, sid=sid)
        self.assertEqual(code, 200, out)
        eid = out["export_id"]
        code, blob = self.call("GET", f"/api/exports/{eid}", sid=sid, raw=True)
        self.assertEqual(code, 200)
        self.assertEqual(self.call("GET", "/api/customers?q=a", sid=sid)[0], 423)  # the download tripped the lock
        self.assertTrue(any(e["detail"]["export_id"] == eid for e in self.alarms(sid)))
        touch = next(e["detail"] for e in self.alarms(sid) if e["detail"]["reason"] == "canary_touch")
        self.assertEqual(touch["canary_count"], self.app.trip.exports[eid]["canaries"])
        self.assertLessEqual(len(touch["canary_ids"]), 50)

        mine = {c["account_no"]: c for c in canary.load_watch() if c["batch"] == eid}
        stolen = [r for r in honey.open_locked(blob, "Lakeview2026!") if r["account_no"] in mine]
        self.assertTrue(stolen)
        ip = "203.0.113.50"
        self.assertEqual(self.call("POST", "/portal/login", {"user": stolen[0]["portal_user"], "password": "Password1"},
                                   ip=ip)[0], 401)
        hit = self.events("alarm", reason="canary_login")[-1]
        self.assertEqual((hit["severity"], hit["detail"]["export_id"]), ("critical", eid))
        self.assertEqual(self.call("POST", "/portal/login", {"user": "anyone0001", "password": "x"}, ip=ip)[0], 423)
        self.call("POST", "/lab/contact", {"to": stolen[-1]["email"], "channel": "email"}, ip=ip)
        self.assertEqual(self.events("alarm", reason="canary_contact")[-1]["detail"]["export_id"], eid)

        got = self.call("POST", "/api/respond", {"incident": hit["detail"]["incident"], "action": "notify_customers"})
        self.assertEqual(got[1]["customers"], self.app.trip.exports[eid]["real"])
        self.assertEqual(got[1]["locked_copies"], [eid])
        self.assertEqual(got[1]["plaintext_rows"], 0)  # only logins and a locked copy left the building
        self.assertTrue(got[1]["found_at"] and got[1]["checklist"])
        # nothing beside the locked file. a restart still knows the export
        self.assertEqual(sorted(p.name for p in schema.EXPORTS_DIR.iterdir()), [f"{eid}.dye"])
        self.assertEqual(self.app._load_exports()[eid], self.app.trip.exports[eid])

    def test_unknown_logins_escalate(self):
        ip = "203.0.113.9"
        for user in ("nobody0001", "nobody0002", "nobody0003"):
            self.assertEqual(self.call("POST", "/portal/login", {"user": user, "password": "x"}, ip=ip)[0], 401)
        found = [e["severity"] for e in self.events("alarm", reason="unknown_account_login", ip=ip)]
        self.assertEqual(found, ["low", "low", "high"])

    def test_decoy_file_bursts_its_folder(self):
        decoy = str(self.data / "drive" / "customers" / "all_customers_full_export_2026.csv")
        self.app.trip.decoys.append({"decoy_id": "d-t", "path": decoy, "kind": "export", "rows": 1,
                                     "batch": "drive", "planted_at": 0})
        self.app.drive = mock.Mock(vault_password=lambda: "pw")
        drive = self.data / "drive"
        locked = [str(drive / "customers" / "customers.csv.dye"), str(drive / "billing" / "invoices.json.dye")]
        self.app.burst = mock.Mock(burst_drive=mock.Mock(return_value={
            "folder": str(drive), "folders": [str(drive / "customers"), str(drive / "billing")],
            "files": ["customers/customers.csv", "billing/invoices.json"], "vault": locked, "skipped": []}))
        now = time.time()
        reads = [{"ts": now + i / 10, "pid": 4242, "process": "/usr/local/bin/node", "signing_id": None,
                  "path": str(self.data / "drive" / f"note{i}.md"), "op": "read"} for i in range(12)]
        reads.insert(2, dict(reads[0], path=decoy))
        reads.append(dict(reads[0], pid=os.getpid(), path=str(self.data / "drive" / "mine.md")))
        self.assertEqual(self.call("POST", "/lab/fs-event", reads)[0], 200)
        found = self.events("alarm", session="f-4242")
        self.assertEqual(found[0]["detail"]["reason"], "decoy_open")
        self.assertEqual(found[0]["detail"]["path"], decoy)
        self.assertIn("speed", [e["detail"]["reason"] for e in found])
        self.assertFalse(self.events("read", path=str(self.data / "drive" / "mine.md")))
        self.call("POST", "/lab/fs-event", [dict(reads[0], ts=now + 2, path=decoy.replace("all_", "more_"))])
        time.sleep(0.5)
        bursts = [e["detail"] for e in self.events("burst", incident=found[0]["detail"]["incident"])]
        self.assertEqual([b["files"] for b in bursts], [["customers.csv.dye"], ["invoices.json.dye"]])
        self.assertEqual(self.app.burst.burst_drive.call_count, 1)  # the whole drive, once per incident

    def test_breach_notice_counts_files_read_before_the_lock(self):
        drive = self.data / "drive"
        real = drive / "billing" / "invoices_notice.csv"
        real.parent.mkdir(parents=True, exist_ok=True)
        real.write_text("account_no,amount\nLV1,10\nLV2,20\nLV3,30\n")
        decoy = str(drive / "billing" / "all_accounts_notice_export.csv")
        self.app.trip.decoys.append({"decoy_id": "d-notice", "path": decoy, "kind": "export", "rows": 1,
                                     "batch": "drive", "planted_at": 0})
        old = self.app.drive, self.app.burst
        self.app.drive, self.app.burst = mock.Mock(vault_password=lambda: None), None  # no lock in this test
        try:
            now = time.time()
            proc = {"pid": 51515, "process": "/usr/bin/python3", "signing_id": None, "op": "read"}
            reads = [dict(proc, ts=now, path=str(real)), dict(proc, ts=now + 0.1, path=decoy)]
            self.assertEqual(self.call("POST", "/lab/fs-event", reads)[0], 200)
            hit = self.events("alarm", reason="decoy_open", path=decoy)[-1]
            got = self.call("POST", "/api/respond",
                            {"incident": hit["detail"]["incident"], "action": "notify_customers"})[1]
            self.assertEqual(got["plaintext_files"], ["billing/invoices_notice.csv"])  # shown from the drive root
            self.assertEqual((got["plaintext_rows"], got["customers"]), (3, 3))
            self.assertNotIn("Locked copy only: likely exempt as encrypted data, check with counsel", got["checklist"])
        finally:
            self.app.drive, self.app.burst = old

    def test_banner_never_prints_the_control_token(self):
        text = "\n".join(server.banner(self.app, 8750))
        self.assertNotIn(self.app.token, text)
        self.assertIn("http://127.0.0.1:8750/", text)
        self.assertIn("control_token", text)

    def test_drive_lock_never_waits_behind_slow_reports(self):
        gate, drive = threading.Event(), self.data / "drive"
        old = self.app.drive, self.app.burst
        self.app.drive = mock.Mock(vault_password=lambda: "pw")
        self.app.burst = mock.Mock(burst_drive=mock.Mock(return_value={
            "folder": str(drive), "folders": [str(drive / "customers")], "files": ["customers/customers.csv"],
            "vault": [str(drive / "customers" / "customers.csv.dye")], "skipped": []}))
        try:
            for _ in range(8):  # every slow worker busy, the way model reports and Databricks pushes pile up
                self.app.pool.submit(gate.wait, 10)
            iid, start = f"inc-slow-{time.time()}", time.time()
            self.app._schedule_burst(iid, str(drive / "customers" / "all_customers_full_export_2026.csv"))
            while not self.events("burst", incident=iid) and time.time() - start < 3:
                time.sleep(0.02)
            self.assertTrue(self.events("burst", incident=iid), "the drive lock waited behind the slow pool")
            self.assertLess(time.time() - start, 1.0)
        finally:
            gate.set()
            self.app.drive, self.app.burst = old

    def test_each_incident_level_alerts_once_even_when_alerts_run_late(self):
        sent, gate, ip = [], threading.Event(), "198.51.100.77"

        def send(alert, channels):
            sent.append((alert["id"], alert["severity"], tuple(channels)))
            return [{"channel": c, "status": "sent"} for c in channels]

        old = self.app.notify, self.app.routes
        self.app.notify = mock.Mock(send=send)
        self.app.routes = {"low": [], "high": ["push"], "critical": ["push", "sms"]}
        try:
            for _ in range(2):  # hold the alert workers so every alert runs after the incident is critical
                self.app.urgent.submit(gate.wait, 10)
            for user in ("nobody.ab12", "nobody.cd34", "nobody.ef56"):
                self.call("POST", "/portal/login", {"user": user, "password": "x"}, ip=ip)
            canary_user = next(c["portal_user"] for c in canary.load_watch() if c.get("batch") == "table")
            self.call("POST", "/portal/login", {"user": canary_user, "password": "x"}, ip=ip)
            iid = self.events("alarm", ip=ip)[-1]["detail"]["incident"]
            gate.set()
            deadline = time.time() + 3
            while not any(s[0] == iid and s[1] == "critical" for s in sent) and time.time() < deadline:
                time.sleep(0.05)
            time.sleep(0.5)  # room for a late duplicate to show up
            mine = [s for s in sent if s[0] == iid]
            self.assertEqual([s for s in mine if s[1] == "critical"], [(iid, "critical", ("push", "sms"))])
            self.assertEqual(len(mine), len(set(mine)))
            self.assertTrue(all(s[1] in ("high", "critical") for s in mine))
        finally:
            gate.set()
            self.app.notify, self.app.routes = old

    def test_linux_agent_hits_through_the_bridge(self):
        hit = {"event_id": "ev-1", "server_id": "web-01", "timestamp": time.time(), "file": "/srv/backup/all.csv",
               "process": "/usr/bin/python3", "pid": 77, "access_type": "read", "source": "auditd"}
        self.assertEqual(self.call("POST", "/api/events", hit)[0], 200)
        self.assertEqual(self.call("POST", "/api/events", hit)[0], 200)  # a retry
        found = self.events("alarm", reason="decoy_open", ip="web-01")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["detail"]["path"], "/srv/backup/all.csv")

    def test_alert_routes_and_respond(self):
        self.assertEqual(self.call("GET", "/api/alert-routes")[1], server.DEFAULT_ROUTES)
        quiet = {"critical": ["push"], "high": [], "low": []}
        self.assertEqual(self.call("POST", "/api/alert-routes", quiet)[1], quiet)
        self.assertEqual(json.loads(server.routes_path().read_text()), quiet)
        self.assertEqual(self.call("POST", "/api/alert-routes", {"high": ["pager"]})[0], 400)
        self.assertEqual(self.call("POST", "/api/alert-routes", quiet, ip="198.51.100.1")[0], 403)
        self.call("POST", "/api/alert-routes", server.DEFAULT_ROUTES)

        sid = self.login("rep.casey", "198.51.100.40")
        for p in range(3):
            self.call("GET", f"/api/customers?page={p}&size=200", sid=sid)
        iid = self.alarms(sid)[0]["detail"]["incident"]
        self.assertEqual(self.call("POST", "/api/respond", {"incident": iid, "action": "nope"})[0], 400)
        self.assertEqual(self.call("POST", "/api/respond", {"incident": "inc-999", "action": "lock"})[0], 404)
        self.addCleanup(self.app.trip.revoked.discard, "rep.casey")  # other tests still use casey
        self.assertEqual(self.call("POST", "/api/respond", {"incident": iid, "action": "revoke"})[0], 200)
        self.assertEqual(self.call("POST", "/api/login", {"user": "rep.casey", "password": self.logins["rep.casey"]})[0],
                         403)
        self.assertTrue(self.events("action", incident=iid, action="revoke"))
        time.sleep(2)  # reports wait a moment so a burst of hits makes one report
        report = self.events("report", incident=iid)[-1]["detail"]
        # the triage and the tripwire draw the same line: machine speed means an agent
        reasons = {e["detail"]["reason"] for e in self.events("alarm", incident=iid)}
        self.assertEqual(report["looks_like"], "ai_agent" if "speed" in reasons else "person")
        self.assertTrue(self.events("notify", incident=iid)[0]["detail"]["summary"])

    def test_control_token_guards_the_dashboard_posts(self):
        path = self.data / "control_token"
        self.assertEqual(path.read_text().strip(), self.app.token)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for route, body in (("/api/respond", {"incident": "inc-1", "action": "lock"}),
                            ("/api/alert-routes", server.DEFAULT_ROUTES), ("/lab/fs-event", [])):
            self.assertEqual(self.call("POST", route, body, token=False)[0], 401, route)
            self.assertEqual(self.call("POST", route, body, headers={"X-Dyepack-Token": "guess"}, token=False)[0],
                             401, route)
        self.assertEqual(self.call("POST", "/lab/fs-event", [])[0], 200)
        self.assertEqual(self.call("GET", "/api/alert-routes", token=False)[0], 200)
        self.assertEqual(self.call("POST", "/lab/drill", {"phase": "normal", "status": "start"}, token=False)[0], 200)
        # a remote hit can't turn a file on our own drive into a decoy
        mine = str(self.data / "drive" / "customers" / "customers.csv")
        self.call("POST", "/api/events", {"event_id": "ev-9", "server_id": "web-02", "file": mine, "pid": 5},
                  token=False)
        self.assertFalse([d for d in self.app.trip.decoys if d["path"] == mine])

    def test_late_page_gets_past_events_and_resumes_without_repeats(self):
        who = {"id": "", "actor": "test", "ip": "127.0.0.1"}
        mark, later = f"early-{time.time()}", f"later-{time.time()}"
        self.app.emit("action", who, "info", {"marker": mark})

        def markers(stream, stop):
            """Reads the stream until the stop marker. Returns the markers seen and the stop marker's id."""
            got, last_id = [], None
            for _ in range(100_000):
                line = stream.readline()
                if line.startswith(b"id: "):
                    last_id = int(line[4:])
                elif line.startswith(b"data: "):
                    m = json.loads(line[6:])["detail"].get("marker")
                    if m:
                        got.append(m)
                    if m == stop:
                        return got, last_id
            self.fail(f"{stop} never arrived")

        # a page opened after the event still gets it
        with OPENER.open(self.url + "/events", timeout=10) as stream:
            self.assertEqual(stream.readline(), b"retry: 2000\n")
            got, seen = markers(stream, mark)
        self.assertIsNotNone(seen)
        # a page that reconnects resumes after the last event it had, with no repeats
        req = urllib.request.Request(self.url + "/events", headers={"Last-Event-ID": str(seen)})
        with OPENER.open(req, timeout=10) as stream:
            self.app.emit("action", who, "info", {"marker": later})
            got, _ = markers(stream, later)
        self.assertNotIn(mark, got)

    def test_stream_and_pages(self):
        with OPENER.open(self.url + "/events", timeout=5) as stream:
            self.assertEqual(stream.readline(), b"retry: 2000\n")
            kinds = set()
            for _ in range(100_000):  # past events come first, then the ticks
                line = stream.readline()
                if line.startswith(b"data: "):
                    kinds.add(json.loads(line[6:])["type"])
                if "tick" in kinds:
                    break
            self.assertIn("tick", kinds)
        self.assertEqual(self.call("GET", "/", raw=True)[0], 200)
        self.assertEqual(self.call("GET", "/app.js", raw=True)[0], 200)
        self.assertEqual(self.call("GET", "/../dyepack/schema.py", raw=True)[0], 404)


if __name__ == "__main__":
    unittest.main()
