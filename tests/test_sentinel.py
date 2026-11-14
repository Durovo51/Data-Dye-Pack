"""Checks for the company drive, the sentinel and the targeted burst."""

import contextlib
import csv
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from dyepack import burst, drive, honey, lab, schema, sentinel, vocab

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "test vault password"


def wired(cmd):
    """True once cli.py has the command."""
    r = subprocess.run([sys.executable, "-m", "dyepack", cmd, "--help"], cwd=ROOT, capture_output=True)
    return r.returncode == 0


def schema_paths(data, root):
    return {"DATA_DIR": data, "DB_PATH": data / "lakeview.db", "WATCH_PATH": data / "watch_list.json",
            "PROFILE_PATH": data / "profile.json", "EXPORTS_DIR": data / "exports",
            "VAULT_DIR": data / "vault", "DRIVE_ROOT": root}


def table_rows_from(data, suffix):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "t" + suffix)
        p.write_bytes(data)
        return table_rows(p)


def table_rows(path):
    path = Path(path)
    if path.suffix == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    doc = json.loads(path.read_text())
    return doc if isinstance(doc, list) else max((v for v in doc.values() if isinstance(v, list)), key=len)


class Stub:
    """Stands in for the dyepack server and keeps every batch posted to it."""

    def __init__(self):
        self.batches = []
        batches = self.batches

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                batches.append((self.path, json.loads(body)))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def events(self):
        return [e for _, batch in self.batches for e in batch]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def es(kind, path, pid=4242, exe="/opt/homebrew/bin/node", signing="node", platform=False,
       fflag=1, to=None, folder=False):
    """An event shaped like eslogger's JSON, slashes escaped the way Apple's writer does it."""
    def f(p):
        return {"path": p, "path_truncated": False, "stat": {"st_mode": 0o40755 if folder else 0o100644}}
    if kind == "open":
        event = {"open": {"fflag": fflag, "file": f(path)}}
    elif kind == "rename":
        event = {"rename": {"source": f(path), "destination_type": 1, "destination": {
            "new_path": {"dir": f(os.path.dirname(to)), "filename": os.path.basename(to)}}}}
    elif kind == "rename_over":
        event = {"rename": {"source": f(path), "destination_type": 0, "destination": {"existing_file": f(to)}}}
    elif kind == "unlink":
        event = {"unlink": {"target": f(path), "parent_dir": f(os.path.dirname(path))}}
    else:
        event = {kind: {"target": f(path)}}
    process = {"audit_token": {"pid": pid, "euid": 501, "asid": 100007}, "ppid": 1, "signing_id": signing,
               "is_platform_binary": platform, "executable": {"path": exe, "path_truncated": False}}
    msg = {"schema_version": 1, "event_type": 10, "time": "2026-11-14T21:00:00.000000000Z",
           "process": process, "event": event, "seq_num": 1}
    return json.dumps(msg, separators=(",", ":")).replace("/", "\\/")


class DriveTest(unittest.TestCase):
    """builds a small seeded lab in a temp folder, then the drive from it"""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        cls.data, cls.root = base / "data", base / "LakeviewFiber"
        env = {**os.environ, "DYEPACK_DATA": str(cls.data)}
        for args in (["lab", "--customers", "3000", "--seed", "3"], ["seed"]):
            r = subprocess.run([sys.executable, "-m", "dyepack", *args], cwd=ROOT, env=env,
                               capture_output=True, text=True)
            if r.returncode:
                raise RuntimeError(r.stderr)
        patch = mock.patch.multiple(schema, **schema_paths(cls.data, cls.root))
        patch.start()
        cls.addClassCleanup(patch.stop)
        cls.table_watch = json.loads((cls.data / "watch_list.json").read_text())["canaries"]
        cls.out = drive.build_drive(seed=7, password=PASSWORD)
        cls.watch = json.loads((cls.data / "watch_list.json").read_text())

    def test_burst_on_the_drive_round_trips(self):
        # the decoy in each folder stays a decoy, the honey locked backup isn't a table
        want = {"customers": ["customers.csv"], "billing": ["invoices_2026_10.json"], "backups": [], "config": []}
        table = {c["account_no"] for c in self.table_watch}
        for name, files in want.items():
            folder = self.root / name
            before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in folder.iterdir()}
            out = burst.burst(folder, PASSWORD)
            try:
                self.assertEqual(out["files"], files, name)
                self.assertEqual({p.name for p in folder.iterdir()},
                                 set(before) - set(files) | {f"{f}.dye" for f in files}, name)
                for p in folder.iterdir():
                    if p.name in before:
                        self.assertEqual(p.read_bytes(), before[p.name][0], p.name)
                for f in files:  # the table canaries in it are on record, security side
                    rec = next(r for r in burst.locked() if r["dye"] == f"{folder / f}.dye")
                    rows = table_rows_from(before[f][0], Path(f).suffix)
                    self.assertEqual(rec["canaries"], sorted(r["account_no"] for r in rows if r["account_no"] in table))
            finally:
                for dye in out["vault"]:
                    burst.unlock(dye, PASSWORD)
            self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in folder.iterdir()}, before, name)

    @unittest.skipUnless(wired("drive"), "cli.py doesn't have drive yet")
    def test_cli_builds_the_drive(self):
        data, other = self.root.parent / "cli_data", self.root.parent / "cli_drive"
        shutil.copytree(self.data, data)
        env = {**os.environ, "DYEPACK_DATA": str(data), "DYEPACK_DRIVE": str(other),
               "DYEPACK_VAULT_PASSWORD": PASSWORD}
        r = subprocess.run([sys.executable, "-m", "dyepack", "drive"], cwd=ROOT, env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("decoys", r.stdout)
        watch = json.loads((data / "watch_list.json").read_text())
        self.assertEqual(sorted(d["path"] for d in watch["decoys"]), sorted(str(other / rel) for rel in drive.DECOYS))

    def test_decoys_sort_first_in_their_folders(self):
        for rel in drive.DECOYS:
            folder, name = os.path.split(rel)
            self.assertEqual(sorted(os.listdir(self.root / folder))[0], name, folder)

    def test_decoys_look_newest(self):
        newest = max((p for p in self.root.rglob("*") if p.is_file()), key=lambda p: p.stat().st_mtime)
        self.assertIsNotNone(drive.decoy_for(newest))

    def test_decoys_on_the_watch_list(self):
        decoys = self.watch["decoys"]
        self.assertEqual(sorted(d["path"] for d in decoys), sorted(str(self.root / rel) for rel in drive.DECOYS))
        self.assertTrue(all(d["batch"] == "drive" for d in decoys))
        for rel in drive.DECOYS:
            self.assertIsNotNone(drive.decoy_for(self.root / rel), rel)
        self.assertIsNone(drive.decoy_for(self.root / "customers/customers.csv"))

    def test_every_decoy_row_is_a_watched_canary(self):
        mine = {c["account_no"]: c for c in self.watch["canaries"] if c["batch"] == "drive"}
        rows = [r for rel, (_, n) in drive.DECOYS.items() if n for r in table_rows(self.root / rel)]
        self.assertEqual(len(rows), sum(n for _, n in drive.DECOYS.values()))
        self.assertEqual({r["account_no"] for r in rows}, set(mine))
        for r in rows:
            vocab.decompose(r)
            c = mine[r["account_no"]]
            self.assertEqual((c["portal_user"], c["email"], c["phone"]), (r["portal_user"], r["email"], r["phone"]))
        ids = [c["canary_id"] for c in self.watch["canaries"]]
        self.assertEqual(len(ids), len(set(ids)))
        # the table's own canaries are still there, untouched
        self.assertEqual([c for c in self.watch["canaries"] if c["batch"] == "table"], self.table_watch)

    def test_files(self):
        for rel in ("customers/customers.csv", "billing/invoices_2026_10.json", "support/notes.md",
                    "backups/nightly_2026_11_13.dye", *drive.DECOYS):
            self.assertTrue((self.root / rel).is_file(), rel)
        keys = (self.root / "config/.env.production").read_text()
        self.assertIn("BACKUP_ENCRYPTION_KEY=", keys)

    def test_payment_decoy_has_no_card_or_bank_numbers(self):
        text = (self.root / "billing/all_accounts_2026_with_payment_info.json").read_text()
        self.assertIsNone(re.search(r"\d{9,}", text))  # account numbers are 8 digits, nothing longer
        for word in ("card_number", "cvv", "expir", "routing", "iban", "bank_account"):
            self.assertNotIn(word, text.lower())
        self.assertIn("payment_method", text)

    def test_nightly_backup_opens_with_the_password(self):
        blob = (self.root / "backups/nightly_2026_11_13.dye").read_bytes()
        real = {r["account_no"] for r in table_rows(self.root / "customers/customers.csv")}
        self.assertEqual({r["account_no"] for r in honey.open_locked(blob, PASSWORD)}, real)
        guess = honey.open_locked(blob, "a wrong guess")
        self.assertEqual(len(guess), len(real))
        self.assertNotEqual({r["account_no"] for r in guess}, real)

    def test_real_files_come_from_the_table(self):
        con = sqlite3.connect(self.data / "lakeview.db")
        cols = ", ".join(schema.CUSTOMER_FIELDS)
        table = {t[0]: dict(zip(schema.CUSTOMER_FIELDS, t)) for t in con.execute(f"SELECT {cols} FROM customers")}
        con.close()
        real = table_rows(self.root / "customers/customers.csv")
        self.assertEqual(len(real), drive.REAL_ROWS)
        for r in real:
            self.assertEqual(vocab.compose(vocab.decompose(r)), table[r["account_no"]])
        invoices = json.loads((self.root / "billing/invoices_2026_10.json").read_text())["invoices"]
        self.assertEqual(len(invoices), drive.INVOICES)
        self.assertLessEqual({i["account_no"] for i in invoices}, {r["account_no"] for r in real})
        canaries = {c["account_no"] for c in self.table_watch}
        self.assertEqual(self.out["table_canaries"], sum(r["account_no"] in canaries for r in real))

    def test_rebuild_replaces_the_old_drive(self):
        # a decoy from an older layout goes away, a file somebody else put there stays
        watch = json.loads((self.data / "watch_list.json").read_text())
        stale = self.root / "customers/customers_full_export_2026.csv"
        stale.write_text("old decoy\n")
        watch["decoys"].append({"decoy_id": "d-9", "path": str(stale), "kind": "export", "rows": 1,
                                "batch": "drive", "planted_at": 0})
        lab.write_private(self.data / "watch_list.json", watch)
        theirs = self.root / "support/todo.txt"
        theirs.write_text("not ours\n")
        # and a file a burst locked comes back fresh, its .dye gone so the next burst can lock it again
        burst.burst(self.root / "customers", PASSWORD)
        drive.build_drive(seed=7, password=PASSWORD)
        self.assertFalse(stale.exists())
        self.assertTrue(theirs.exists())
        theirs.unlink()
        self.assertTrue((self.root / "customers/customers.csv").exists())
        self.assertFalse((self.root / "customers/customers.csv.dye").exists())
        self.assertEqual(burst.locked(), [])
        after = json.loads((self.data / "watch_list.json").read_text())
        self.assertEqual(len(after["decoys"]), len(drive.DECOYS))
        self.assertEqual(sum(c["batch"] == "drive" for c in after["canaries"]), sum(n for _, n in drive.DECOYS.values()))
        self.assertEqual(len(after["canaries"]), len(self.watch["canaries"]))
        type(self).watch = after

    def test_scan_finds_the_customer_tables(self):
        found = [p.relative_to(self.root).as_posix() for p in burst.scan(self.root)]
        self.assertEqual(found, ["backups/all_customers_backup_unencrypted.csv",
                                 "billing/all_accounts_2026_with_payment_info.json", "billing/invoices_2026_10.json",
                                 "customers/all_customers_full_export_2026.csv", "customers/customers.csv"])


class SentinelTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.root = self.base / "LakeviewFiber"
        (self.root / "customers").mkdir(parents=True)
        self.decoy = str(self.root / "customers/all_customers_full_export_2026.csv")
        self.stub = Stub()
        self.addCleanup(self.stub.close)

    def feed(self, lines):
        src = self.base / "events.jsonl"
        src.write_text("\n".join(lines) + "\n")
        return sentinel.run([self.root], self.stub.url, backend="fake", source=src)

    def test_200_opens_in_20_seconds_reach_the_server_in_order(self):
        t0 = 1763154000.0
        paths = [str(self.root / f"customers/part_{i:03d}.csv") for i in range(200)]
        paths[137] = self.decoy
        want = [{"ts": t0 + i * 0.1, "pid": 4242, "process": "/opt/homebrew/bin/node", "signing_id": "node",
                 "path": p, "op": "read"} for i, p in enumerate(paths)]
        noise = [
            json.dumps({"path": "/etc/hosts", "pid": 4242, "process": "/opt/homebrew/bin/node"}),  # off the drive
            json.dumps({"path": paths[0], "pid": os.getpid(), "process": sys.executable}),  # the sentinel itself
            json.dumps({"path": paths[1], "pid": 88, "signing_id": "com.apple.mdworker_shared",
                        "process": "/System/Library/Frameworks/CoreServices.framework/mdworker_shared"}),
            "not json",
            "",
        ]
        lines = []
        for i, ev in enumerate(want):
            lines.append(json.dumps(ev))
            if i % 40 == 0:
                lines.extend(noise)
        self.assertEqual(self.feed(lines), 200)
        got = self.stub.events()
        self.assertEqual(got, want)  # every field, in order
        self.assertEqual({path for path, _ in self.stub.batches}, {"/lab/fs-event"})
        self.assertTrue(all(1 <= len(batch) <= 50 for _, batch in self.stub.batches))
        self.assertIn(self.decoy, [e["path"] for e in got])
        self.assertAlmostEqual(got[-1]["ts"] - got[0]["ts"], 19.9, places=3)

    def test_eslogger_events(self):
        outside = str(self.base / "elsewhere/notes.txt")
        real = str(self.root / "customers/customers.csv")
        self.feed([
            es("open", self.decoy, pid=501, exe="/bin/cat", signing="com.apple.cat", platform=True),
            es("open", real, fflag=3),  # read and write
            es("open", str(self.root / "customers"), folder=True),  # a folder listing
            es("rename", outside, to=real),  # moved onto the drive
            es("rename_over", self.decoy, to=outside),  # moved off the drive
            es("unlink", self.decoy),
            es("open", self.decoy, exe="/System/Library/Frameworks/mdworker_shared",
               signing="com.apple.mdworker_shared", platform=True),  # Spotlight
            es("open", self.decoy, exe="/tmp/mdworker", signing="mdworker"),  # not Apple's, so it counts
            es("open", outside),
            es("close", self.decoy),  # not watched
            es("open", self.decoy).replace("\\/", "/"),  # plain slashes too
        ])
        got = [(e["op"], e["path"], e["pid"], os.path.basename(e["process"])) for e in self.stub.events()]
        self.assertEqual(got, [
            ("read", self.decoy, 501, "cat"),
            ("write", real, 4242, "node"),
            ("rename", real, 4242, "node"),
            ("rename", self.decoy, 4242, "node"),
            ("delete", self.decoy, 4242, "node"),
            ("read", self.decoy, 4242, "mdworker"),
            ("read", self.decoy, 4242, "node"),
        ])
        first = self.stub.events()[0]
        self.assertEqual((first["process"], first["signing_id"]), ("/bin/cat", "com.apple.cat"))

    def test_eslogger_stream_skips_the_rest_of_the_machine(self):
        lines = [es("open", self.decoy), es("open", self.decoy).replace("\\/", "/"), es("open", "/usr/lib/libz.dylib"),
                 "{broken", es("open", self.decoy, pid=777)]
        stream = io.BytesIO(("\n".join(lines) + "\n").encode())
        got = list(sentinel._from_eslogger(stream, sentinel._roots([self.root]), skip={777}))
        self.assertEqual([e["path"] for e in got], [self.decoy, self.decoy])

    @unittest.skipUnless(sys.platform == "darwin", "macOS path spellings")
    def test_mac_path_spellings(self):
        self.feed([es("open", self.decoy.upper()), es("open", "/System/Volumes/Data" + self.decoy)])
        self.assertEqual(len(self.stub.events()), 2)

    def test_only_talks_to_this_machine(self):
        with self.assertRaises(ValueError):
            sentinel.run([self.root], "http://203.0.113.5:8750", backend="fake", source=io.BytesIO(b""))

    def test_no_server_yet_keeps_watching_and_printing(self):
        self.stub.close()
        src = self.base / "events.jsonl"
        src.write_text("".join(json.dumps({"path": self.decoy, "pid": 9, "process": "/bin/cat"}) + "\n"
                               for _ in range(3)))
        start = time.time()
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()) as out:
            sent = sentinel.run([self.root], self.stub.url, backend="fake", source=src, echo=True)
        self.assertEqual(sent, 0)
        self.assertLess(time.time() - start, 10)
        self.assertEqual(out.getvalue().count("cat (9)"), 3)
        self.assertIn("Still watching", err.getvalue())

    @unittest.skipUnless(wired("sentinel"), "cli.py doesn't have sentinel yet")
    def test_cli_reads_stdin(self):
        lines = "".join(json.dumps({"path": self.decoy, "pid": 9, "process": "/bin/cat", "ts": float(i)}) + "\n"
                        for i in range(3))
        r = subprocess.run([sys.executable, "-m", "dyepack", "sentinel", "--backend", "fake", "--root", str(self.root),
                            "--url", self.stub.url], input=lines, cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([e["ts"] for e in self.stub.events()], [0.0, 1.0, 2.0])


@unittest.skipUnless(sys.platform.startswith("linux"), "inotify is Linux only")
class InotifyTest(unittest.TestCase):
    def test_reads_on_the_drive_reach_the_server(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve() / "LakeviewFiber"
        (root / "customers").mkdir(parents=True)
        first = root / "customers/customers.csv"
        first.write_text("account_no\n")
        stub = Stub()
        self.addCleanup(stub.close)
        threading.Thread(target=sentinel.run, args=([root], stub.url, "inotify"), daemon=True).start()
        time.sleep(0.5)
        first.read_text()
        (root / "later").mkdir()
        time.sleep(0.5)  # a new folder gets its watch a moment after it shows up
        second = root / "later/export.csv"
        second.write_text("x\n")
        second.unlink()
        want = {(str(first), "read"), (str(second), "read"), (str(second), "delete")}
        deadline = time.time() + 5
        while time.time() < deadline and not want <= {(e["path"], e["op"]) for e in stub.events()}:
            time.sleep(0.1)
        got = stub.events()
        self.assertLessEqual(want, {(e["path"], e["op"]) for e in got})
        self.assertTrue(all(e["process"] == "unknown" and e["pid"] is None for e in got))


class BurstTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.data, self.root = base / "data", base / "LakeviewFiber"
        self.data.mkdir()
        patch = mock.patch.multiple(schema, **schema_paths(self.data, self.root))
        patch.start()
        self.addCleanup(patch.stop)
        self.folder = self.root / "customers"
        (self.folder / "archive").mkdir(parents=True)
        rows = lab.make_rows(400, seed=11)
        drive.write_csv(self.folder / "customers.csv", rows[:200])
        # rows one level down, extra keys, compact JSON
        doc = {"company": "Lakeview Fiber", "rows": [{"id": i, **r, "vip": i % 7 == 0} for i, r in enumerate(rows[200:300])]}
        (self.folder / "export.json").write_text(json.dumps(doc))
        # Windows line endings, its own column order, an extra column and a junk row
        cols = ["note", *reversed(schema.CUSTOMER_FIELDS)]
        lines = [",".join(cols)]
        lines += [",".join(["called twice", *(f"{r[k]:.2f}" if k == "monthly_bill" else str(r[k])
                                               for k in reversed(schema.CUSTOMER_FIELDS))]) for r in rows[300:350]]
        lines.append(",".join(["junk"] * len(cols)))
        (self.folder / "windows.csv").write_bytes(("\r\n".join(lines) + "\r\n").encode())
        (self.folder / "notes.txt").write_text("call back on Tuesday\n")
        (self.folder / "plans.csv").write_text("plan,price\nFiber 300,55.00\n")
        drive.write_csv(self.folder / "full_export.csv", rows[350:380])  # a decoy, see the watch list below
        drive.write_csv(self.folder / "archive/old.csv", rows[380:390])  # one folder down, out of reach
        odd = [dict(r, since_year=str(r["since_year"])) for r in rows[390:400]]
        (self.folder / "odd.json").write_text(json.dumps(odd, indent=2))  # years as text, can't come back byte for byte
        self.outside = base / "outside.csv"
        drive.write_csv(self.outside, rows[:10])
        (self.folder / "link.csv").symlink_to(self.outside)
        (self.root / "sneaky").symlink_to(base)
        os.chmod(self.folder / "customers.csv", 0o640)
        self.canaries = [rows[3]["account_no"], rows[150]["account_no"], rows[310]["account_no"]]
        lab.write_private(self.data / "watch_list.json", {
            "canaries": [{"canary_id": f"c-{i:03d}", "account_no": a, "batch": "table"}
                         for i, a in enumerate(self.canaries, 1)],
            "decoys": [{"decoy_id": "d-1", "path": str(self.folder / "full_export.csv"), "kind": "export",
                        "rows": 30, "batch": "drive", "planted_at": 0}]})
        self.before = self.snapshot()

    def snapshot(self):
        files = [p for p in self.root.rglob("*") if p.is_file() and not p.is_symlink()] + [self.outside]
        return {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}

    def original(self, name):
        return self.before[self.folder / name][0]

    def test_burst_locks_customer_files_in_place(self):
        out = burst.burst(self.folder, PASSWORD)
        names = ["customers.csv", "export.json", "windows.csv"]
        self.assertEqual(out["files"], names)
        self.assertEqual(out["vault"], [f"{self.folder / n}.dye" for n in names])
        self.assertEqual([name for name, _ in out["skipped"]], ["odd.json"])
        after = self.snapshot()
        for p, was in self.before.items():
            if p.parent == self.folder and p.name in names:
                self.assertNotIn(p, after)  # gone, so the company's own apps fail loudly
                self.assertIn(p.with_name(p.name + ".dye"), after)
            else:
                self.assertEqual(after[p], was, p.name)  # byte for byte the same
        self.assertEqual(stat.S_IMODE((self.folder / "customers.csv.dye").stat().st_mode), 0o640)
        # canaries go on record on the security side, never into the .dye
        rec = {Path(r["dye"]).name: r for r in burst.locked()}
        self.assertEqual(rec["customers.csv.dye"]["canaries"], sorted(self.canaries[:2]))
        self.assertEqual(rec["windows.csv.dye"]["canaries"], [self.canaries[2]])
        self.assertEqual(rec["export.json.dye"]["canaries"], [])
        for n in names:
            blob = (self.folder / f"{n}.dye").read_bytes()
            for account in self.canaries:
                self.assertNotIn(account.encode(), blob)

    def test_unlock_brings_back_every_byte(self):
        out = burst.burst(self.folder, PASSWORD)
        for dye in out["vault"]:
            self.assertEqual(burst.unlock(dye, PASSWORD), Path(dye[:-len(".dye")]))
        self.assertEqual(self.snapshot(), self.before)  # every .dye gone, every original back
        self.assertEqual(stat.S_IMODE((self.folder / "customers.csv").stat().st_mode), 0o640)
        self.assertEqual(burst.locked(), [])

    def test_wrong_password_fails_clearly_and_the_dye_stays(self):
        out = burst.burst(self.folder, PASSWORD)
        for dye in out["vault"]:  # files with canaries and export.json without any
            with self.assertRaisesRegex(ValueError, "wrong password"):
                burst.unlock(dye, "not the password")
            self.assertTrue(Path(dye).exists())
        self.assertFalse((self.folder / "customers.csv").exists())
        self.assertEqual(len(burst.locked()), 3)

    def test_a_stolen_dye_opens_to_believable_fakes(self):
        blob = Path(burst.burst(self.folder, PASSWORD)["vault"][0]).read_bytes()
        real = {r["account_no"] for r in table_rows_from(self.original("customers.csv"), ".csv")}
        for guess in ("password1", "lakeview2026", "letmein"):
            rows = honey.open_locked(blob, guess)
            self.assertEqual(len(rows), 200)
            for r in rows:
                vocab.decompose(r)
            self.assertNotEqual({r["account_no"] for r in rows}, real)

    def test_bursting_again_leaves_a_locked_file_alone(self):
        burst.burst(self.folder, PASSWORD)
        dye = self.folder / "customers.csv.dye"
        locked = dye.read_bytes()
        (self.folder / "customers.csv").write_bytes(self.original("customers.csv"))  # a copy shows up again
        again = burst.burst(self.folder, PASSWORD)
        self.assertEqual(again["files"], [])
        self.assertIn("customers.csv", [name for name, _ in again["skipped"]])
        self.assertEqual(dye.read_bytes(), locked)

    def test_unlock_wont_overwrite_a_file_that_came_back(self):
        burst.burst(self.folder, PASSWORD)
        (self.folder / "customers.csv").write_text("someone made a new one\n")
        with self.assertRaisesRegex(ValueError, "already exists"):
            burst.unlock(self.folder / "customers.csv.dye", PASSWORD)
        self.assertTrue((self.folder / "customers.csv.dye").exists())
        self.assertEqual((self.folder / "customers.csv").read_text(), "someone made a new one\n")

    def test_unlock_with_no_record_needs_force(self):
        burst.burst(self.folder, PASSWORD)
        watch = json.loads((self.data / "watch_list.json").read_text())
        watch["locked"] = []
        lab.write_private(self.data / "watch_list.json", watch)
        dye = self.folder / "customers.csv.dye"
        with self.assertRaisesRegex(ValueError, "--force"):
            burst.unlock(dye, PASSWORD)
        burst.unlock(dye, PASSWORD, force=True)
        self.assertEqual((self.folder / "customers.csv").read_bytes(), self.original("customers.csv"))
        self.assertTrue(dye.exists())  # kept, nothing confirmed the password

    def test_cmd_unlock_and_the_old_restore_name(self):
        for cmd, args in ((burst.cmd_unlock, Namespace(dye=[], to=None, force=False)),
                          (burst.cmd_restore, Namespace(vault=[], to=None))):
            burst.burst(self.folder, PASSWORD)
            with mock.patch.dict(os.environ, {"DYEPACK_VAULT_PASSWORD": PASSWORD}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd(args), 0)
            self.assertEqual(self.snapshot(), self.before)
            self.assertEqual(burst.locked(), [])

    def test_sorted_files_stay_sorted_and_the_lock_hides_the_order(self):
        folder = self.root / "sorted"
        folder.mkdir()
        rows = lab.make_rows(120, seed=12)
        drive.write_csv(folder / "by_account.csv", sorted(rows[:60], key=lambda r: r["account_no"]))
        by_name = sorted(rows[60:], key=lambda r: (r["last_name"], r["account_no"]), reverse=True)
        (folder / "by_name.json").write_text(json.dumps(by_name, indent=2) + "\n")
        before = {p.name: p.read_bytes() for p in folder.iterdir()}
        out = burst.burst(folder, PASSWORD)
        self.assertEqual(out["files"], ["by_account.csv", "by_name.json"])
        for dye in out["vault"]:
            blob = Path(dye).read_bytes()
            real = [r["account_no"] for r in honey.open_locked(blob, PASSWORD)]
            self.assertNotIn(real, (sorted(real), sorted(real, reverse=True)))  # shuffled inside the lock
            lay = burst._layout_of(blob)
            field, reverse = lay["sort"]
            guess = table_rows_from(burst._render(lay, honey.open_locked(blob, "a guess")), Path(lay["name"]).suffix)
            keys = [(r[field], r["account_no"]) for r in guess]
            self.assertEqual(keys, sorted(keys, reverse=reverse))  # every guess comes out sorted the same way
            burst.unlock(dye, PASSWORD)
        self.assertEqual({p.name: p.read_bytes() for p in folder.iterdir()}, before)

    def test_refuses_anything_off_the_drive(self):
        for where in (self.root.parent, self.root / "sneaky", Path("/")):
            with self.assertRaises(ValueError):
                burst.burst(where, PASSWORD)
        with self.assertRaises(ValueError):
            burst.burst(self.folder, "")
        self.assertEqual(self.snapshot(), self.before)

    def test_scan(self):
        found = [p.relative_to(self.root).as_posix() for p in burst.scan(self.root)]
        self.assertEqual(found, ["customers/archive/old.csv", "customers/customers.csv", "customers/export.json",
                                 "customers/full_export.csv", "customers/odd.json", "customers/windows.csv"])

    @unittest.skipUnless(wired("burst") and wired("restore"), "cli.py doesn't have burst and restore yet")
    def test_cli(self):
        env = {**os.environ, "DYEPACK_DATA": str(self.data), "DYEPACK_DRIVE": str(self.root),
               "DYEPACK_VAULT_PASSWORD": PASSWORD}
        r = subprocess.run([sys.executable, "-m", "dyepack", "burst", str(self.folder)], cwd=ROOT, env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("locked customers.csv", r.stdout)
        back = "unlock" if wired("unlock") else "restore"
        r = subprocess.run([sys.executable, "-m", "dyepack", back], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.snapshot(), self.before)


if __name__ == "__main__":
    unittest.main()
