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
        canary.plant(every=30)
        cls.httpd, cls.app = server.start(0, quiet=True)
        cls.app.client = cls.app.notify = None  # never reach Databricks or a real phone from a test
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.httpd.server_close)
        cls.addClassCleanup(cls.httpd.shutdown)
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.logins = json.loads(lab.logins_path().read_text())
        cls.data = data

    def call(self, method, path, body=None, sid=None, ip=None, raw=False, headers=()):
        h = {"Content-Type": "application/json", **dict(headers)}
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
        rows = self.call("GET", "/api/customers?q=Smith&limit=10", sid=sid)[1]["customers"]
        for r in rows[:5]:
            self.assertEqual(self.call("GET", f"/api/customers/{r['account_no']}", sid=sid)[0], 200)
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
        self.app.burst = mock.Mock(burst=lambda folder, password: {
            "folder": folder, "files": ["customers.csv"], "vault": ["/d/customers.csv.dye"], "skipped": []})
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
        time.sleep(0.5)
        self.assertEqual(self.events("burst")[-1]["detail"]["files"], ["customers.csv.dye"])

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

    def test_stream_and_pages(self):
        with OPENER.open(self.url + "/events", timeout=5) as stream:
            self.assertEqual(stream.readline(), b"retry: 2000\n")
            kinds = set()
            for _ in range(200):
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
