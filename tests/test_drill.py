"""Checks for the drill against a tiny stand in server that runs the real tripwire."""

import contextlib
import io
import json
import queue
import random
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from dyepack import canary, drill, drive, honey, lab, schema
from dyepack.profile import load_profile
from dyepack.tripwire import Tripwire

COLS = ", ".join(schema.CUSTOMER_FIELDS)


class Stub:
    """Just enough of dyepack serve for the drill: same routes, same events, real tripwire."""

    def __init__(self, decoys=()):
        self.clients, self.log, self.drills, self.tokens = [], [], [], []
        self.lock = threading.Lock()
        self.trip = Tripwire(self.emit, self.changed, canary.load_watch(), decoys)
        with contextlib.closing(sqlite3.connect(schema.DB_PATH)) as con:
            self.staff = {u: (h, s, r) for u, h, s, r in con.execute("SELECT * FROM staff")}
        self.exports = {}
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, body, kind="application/json"):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def ip(self):
                return self.headers.get("X-Lab-Ip") or "127.0.0.1"

            def staff(self):
                s = stub.trip.session(self.headers.get("X-Session", ""))
                if s is None:
                    self.send(401, {})
                elif s["locked"]:
                    self.send(423, {})
                else:
                    return s

            def do_GET(self):
                url = urlsplit(self.path)
                q = parse_qs(url.query)
                if url.path == "/events":
                    return self.events()
                if url.path == "/api/alert-routes":
                    return self.send(200, {"critical": [], "high": [], "low": []})
                s = self.staff()
                if s is None:
                    return
                with contextlib.closing(sqlite3.connect(schema.DB_PATH)) as con:
                    con.row_factory = sqlite3.Row
                    if url.path.startswith("/api/exports/"):
                        blob, accounts = stub.exports[url.path.rsplit("/", 1)[1]]
                        stub.trip.read(s["id"], accounts, url.path)
                        return self.send(200, blob, "application/octet-stream")
                    one = url.path[len("/api/customers/"):]
                    if one:
                        rows = con.execute(f"SELECT {COLS} FROM customers WHERE account_no = ?", (one,))
                    elif "q" in q:
                        rows = con.execute(f"SELECT {COLS} FROM customers WHERE phone = ? LIMIT 5", (q["q"][0],))
                    else:
                        page, size = int(q["page"][0]), int(q["size"][0])
                        rows = con.execute(f"SELECT {COLS} FROM customers ORDER BY rowid LIMIT ? OFFSET ?",
                                           (size, page * size))
                    rows = [dict(r) for r in rows]
                stub.trip.read(s["id"], [r["account_no"] for r in rows], "/api/customers")
                self.send(200, {"customer": rows[0]} if one and rows else {"customers": rows})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                path = urlsplit(self.path).path
                if path == "/api/login":
                    found = stub.staff.get(body["user"])
                    ok = bool(found) and lab.check_password(body["password"], found[0], found[1])
                    sid = stub.trip.staff_login(body["user"], found and found[2], self.ip(), ok)
                    return self.send(200 if sid else 401, {"session": sid})
                if path == "/api/exports":
                    s = self.staff()
                    if s is None:
                        return
                    with contextlib.closing(sqlite3.connect(schema.DB_PATH)) as con:
                        con.row_factory = sqlite3.Row
                        rows = [dict(r) for r in con.execute(f"SELECT {COLS} FROM customers")]
                    eid = f"exp-{len(stub.exports) + 1}"
                    # like the server: the export gets its own canaries, added to the watch list
                    watch = json.loads(schema.WATCH_PATH.read_text())
                    known = rows + watch["canaries"]
                    fakes, entries = canary.make_canaries(
                        load_profile(), 10, [r["account_no"] for r in known], [r["portal_user"] for r in known],
                        eid, taken_contacts=[r[f] for r in known for f in ("email", "phone")])
                    for i, e in enumerate(entries, len(watch["canaries"]) + 1):
                        e["canary_id"] = f"c-{i:03d}"
                    watch["canaries"] += entries
                    lab.write_private(schema.WATCH_PATH, watch)
                    stub.trip.watch(entries)
                    rows += fakes
                    random.shuffle(rows)
                    stub.exports[eid] = (honey.lock(rows, body["password"], load_profile(), iterations=2000),
                                         [r["account_no"] for r in rows])
                    return self.send(200, {"export_id": eid})
                if path == "/portal/login":
                    with contextlib.closing(sqlite3.connect(schema.DB_PATH)) as con:
                        found = con.execute("SELECT 1 FROM portal_accounts WHERE portal_user = ?",
                                            (body["user"],)).fetchone()
                    if not stub.trip.portal_login(body["user"], self.ip(), bool(found), False):
                        return self.send(423, {})
                    return self.send(401, {"ok": False})
                if path == "/lab/contact":
                    stub.trip.contact(body["to"], body.get("channel", "email"), self.ip())
                    return self.send(200, {"ok": True})
                if path == "/lab/drill":
                    stub.drills.append(body)
                    return self.send(200, {"ok": True})
                if path == "/lab/fs-event":
                    stub.tokens.append(self.headers.get("X-Dyepack-Token"))
                    stub.trip.file_events(body if isinstance(body, list) else [body])
                    return self.send(200, {"ok": True})
                self.send(404, {})

            def events(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                q = queue.Queue()
                with stub.lock:
                    stub.clients.append(q)
                try:
                    self.wfile.write(b"retry: 2000\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            self.wfile.write(q.get(timeout=1))
                        except queue.Empty:
                            self.wfile.write(b": still here\n\n")
                        self.wfile.flush()
                except OSError:
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def emit(self, kind, who, severity, detail):
        e = {"ts": round(time.time(), 3), "type": kind, "session": who.get("id") or "",
             "actor": who.get("actor") or "", "ip": who.get("ip") or "", "severity": severity, "detail": detail}
        with self.lock:
            self.log.append(e)
            for q in self.clients:
                q.put(f"data: {json.dumps(e)}\n\n".encode())
        return e

    def changed(self, inc, alarm, opened, escalated):
        # stand in for the server's burst
        if alarm["detail"]["reason"] == "decoy_open":
            self.emit("burst", {"actor": "dyepack"}, "critical",
                      {"incident": inc["id"], "folder": str(Path(alarm["detail"]["path"]).parent),
                       "files": ["customers.csv"], "vault": "v"})

    def alarms(self, **match):
        return [e for e in self.log if e["type"] == "alarm" and all(
            e.get(k, e["detail"].get(k)) == v for k, v in match.items())]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class DrillTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        data = cls.tmp / "data"
        cls.patch = mock.patch.multiple(schema, DATA_DIR=data, DB_PATH=data / "lakeview.db",
                                        WATCH_PATH=data / "watch_list.json", PROFILE_PATH=data / "profile.json",
                                        EXPORTS_DIR=data / "exports", VAULT_DIR=data / "vault",
                                        DRIVE_ROOT=cls.tmp / "drive")
        cls.patch.start()
        lab.build_lab(2000, seed=3)
        canary.plant(every=50, rng=random.Random(5))

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.stub = Stub()
        self.addCleanup(self.stub.close)

    def drill(self, **kw):
        base = {"url": self.stub.url, "step": None, "seconds": None, "real": False, "cmd": None,
                "simulate_sentinel": False}
        args = Namespace(**{**base, **kw})
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = drill.cmd_drill(args)
        return code, out.getvalue()

    def final_score(self):
        return self.stub.drills[-1]["score"]

    def test_normal_day_raises_no_alarms(self):
        with mock.patch.object(drill.random.Random, "uniform", return_value=0.3):
            code, out = self.drill(mode="normal", seconds=3)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stub.alarms(), [])
        self.assertEqual(self.final_score(), {"normal_alarms": 0})
        reads = [e for e in self.stub.log if e["type"] == "read"]
        self.assertGreaterEqual(len(reads), 9)
        self.assertEqual({e["actor"] for e in reads}, set(drill.REPS))
        self.assertEqual([d["phase"] for d in self.stub.drills], ["normal", "normal"])

    def test_heist_step_1_is_caught_and_locked(self):
        code, out = self.drill(mode="heist", step=1)
        self.assertEqual(code, 0, out)
        score = self.final_score()
        self.assertLessEqual(score["detect_seconds"], 10)
        alarm = self.stub.alarms(reason="speed")[0]
        self.assertEqual(alarm["actor"], "rep.jordan")
        self.assertTrue(alarm["ip"].startswith("203.0.113."))
        self.assertTrue([e for e in self.stub.log if e["type"] == "lock"])
        # every row before the lock counts, minus the canaries
        read = sum(e["detail"]["rows"] - e["detail"]["canaries"] for e in self.stub.log if e["type"] == "read")
        self.assertEqual(score["rows_exposed"], read)
        self.assertGreater(score["rows_exposed"], 0)
        self.assertNotIn("password", out.lower())

    def test_full_heist_scores_every_key_and_fires_every_try(self):
        with mock.patch.object(drill, "_client", return_value=None):
            code, out = self.drill(mode="heist")
        self.assertEqual(code, 0, out)
        score = self.final_score()
        self.assertEqual(set(score), {"detect_seconds", "rows_exposed", "guesses_cracked", "ai_pick"})
        self.assertEqual(score["guesses_cracked"], len(drill.WORDS))
        self.assertEqual(len(drill.WORDS), 50)
        self.assertEqual(score["ai_pick"]["lists"], 5)
        self.assertIsNone(score["ai_pick"]["pick"])
        self.assertIn(score["ai_pick"]["real"], range(5))
        reasons = [e["detail"]["reason"] for e in self.stub.alarms()]
        for r in ("speed", "canary_touch", "unknown_account_login", "canary_login", "canary_contact"):
            self.assertIn(r, reasons)
        self.assertIn("5 of 5 tries fired", out)
        # the canary tries come from the stolen export and the alarms name it
        self.assertEqual(out.count("taken from exp-1's real list (say the thief guessed the password)"), 2)
        self.assertEqual(out.count("taken from a cracked fake list"), 3)
        for reason in ("canary_login", "canary_contact"):
            self.assertEqual(self.stub.alarms(reason=reason)[0]["detail"]["export_id"], "exp-1")
        self.assertIn("names exp-1", out)
        phases = [(d["phase"], d["status"]) for d in self.stub.drills]
        self.assertEqual(phases, [(p, s) for p in ("heist-1", "heist-2", "heist-3") for s in ("start", "end")])

    def test_step_3_alone_has_nothing_stolen(self):
        code, out = self.drill(mode="heist", step=3)
        self.assertEqual(code, 1)
        self.assertIn("step 3 needs what the thief stole", out)

    def test_ai_pick_asks_the_client(self):
        client = mock.Mock()
        client.chat.return_value = '{"pick": 2, "reason": "looks tidy"}'
        with mock.patch.object(drill, "_client", return_value=client):
            code, out = self.drill(mode="heist", step=2)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.final_score()["ai_pick"]["pick"], 1)
        shown = client.chat.call_args[0][0][1]["content"]
        self.assertEqual(shown.count("List "), 5)

    def test_agent_with_simulated_sentinel_trips_a_decoy_and_a_burst(self):
        root = schema.DRIVE_ROOT
        (root / "customers").mkdir(parents=True, exist_ok=True)
        decoy = root / "customers" / "all_customers_full_export_2026.csv"
        decoy.write_text("account_no\nLV00000001\n")
        (root / "customers" / "customers.csv").write_text("account_no\nLV00000002\n")
        self.stub.trip.decoys = [{"decoy_id": "d-1", "path": str(decoy.resolve()), "kind": "export",
                                  "rows": 1, "batch": "drive", "planted_at": 0}]
        with mock.patch.object(drive, "load_decoys", return_value=self.stub.trip.decoys):
            code, out = self.drill(mode="agent", simulate_sentinel=True)
        self.assertEqual(code, 0, out)
        alarm = self.stub.alarms(reason="decoy_open")[0]
        self.assertEqual(drive.decoy_for(alarm["detail"]["path"], self.stub.trip.decoys)["decoy_id"], "d-1")
        self.assertIsNotNone(self.final_score()["detect_seconds"])
        self.assertIn("burst locked", out)
        self.assertIn("1 of 1 real data files were read before the lock", out)

    def test_simulated_sentinel_sends_the_control_token(self):
        root = schema.DRIVE_ROOT
        (root / "billing").mkdir(parents=True, exist_ok=True)
        (root / "billing" / "invoices.json").write_text("[]")
        self.stub.trip.decoys = [{"decoy_id": "d-1", "path": str((root / "billing" / "invoices.json").resolve()),
                                  "kind": "payments", "rows": 0, "batch": "drive", "planted_at": 0}]
        token = schema.DATA_DIR / "control_token"
        token.write_text("lab-token-123\n")
        self.addCleanup(token.unlink)
        code, out = self.drill(mode="agent", simulate_sentinel=True)
        self.assertEqual(code, 0, out)
        self.assertTrue(self.stub.tokens)
        self.assertEqual(set(self.stub.tokens), {"lab-token-123"})
        self.assertNotIn("lab-token-123", out)

    def test_agent_refuses_real_with_simulation(self):
        schema.DRIVE_ROOT.mkdir(parents=True, exist_ok=True)
        code, out = self.drill(mode="agent", real=True, cmd="true", simulate_sentinel=True)
        self.assertEqual(code, 1)
        self.assertIn("simulate-sentinel", out)

    def test_real_without_cmd_prints_usage(self):
        schema.DRIVE_ROOT.mkdir(parents=True, exist_ok=True)
        code, out = self.drill(mode="agent", real=True)
        self.assertEqual(code, 1)
        self.assertIn("usage: dyepack drill agent --real --cmd", out)

    def test_no_server_is_a_clear_error(self):
        self.stub.close()
        code, out = self.drill(mode="normal")
        self.assertEqual(code, 1)
        self.assertIn("dyepack serve", out)

    def test_only_talks_to_this_machine(self):
        with self.assertRaises(ValueError):
            drill.Lab("http://example.com:8750")


if __name__ == "__main__":
    unittest.main()
