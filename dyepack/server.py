"""The lab front door: customer API, portal login, file events, alert routes and the live alarm stream."""

import hmac
import importlib
import json
import os
import queue
import random
import secrets
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from . import canary, lab, schema
from .profile import load_profile
from .tripwire import RANK, Tripwire

WEB = Path(__file__).resolve().parent / "web"
FILES = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css",
         "/sample_events.json": "sample_events.json", "/signal.jpg": "signal.jpg"}
KINDS = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".json": "application/json", ".jpg": "image/jpeg"}
COLS = ", ".join(schema.CUSTOMER_FIELDS)
DEFAULT_ROUTES = {"critical": ["push", "sms"], "high": ["push"], "low": []}
ACTIONS = ("lock", "revoke", "notify_customers", "dismiss")
# posts that change what the server does. they need the control token from data/control_token
GUARDED = ("/api/respond", "/api/alert-routes", "/lab/fs-event")
LOOPBACK = ("127.0.0.1", "::1")
SERVER = {"id": "", "actor": "server", "ip": "127.0.0.1"}
DYEPACK = {"id": "", "actor": "dyepack", "ip": "127.0.0.1"}


def _optional(name):
    # parts other windows own. the server still runs without them
    try:
        return importlib.import_module(f"{__package__}.{name}")
    except ImportError:
        return None


def routes_path():
    return schema.DATA_DIR / "alert_routes.json"


def connect():
    return sqlite3.connect(schema.DB_PATH.resolve().as_uri() + "?mode=ro", uri=True)


def rows_of(cursor):
    return [dict(zip(schema.CUSTOMER_FIELDS, t)) for t in cursor]


def _int(query, key, default, top):
    try:
        return max(0, min(top, int(query[key][0])))
    except (KeyError, ValueError):
        return default


class App:
    def __init__(self, quiet=False):
        if not (schema.DB_PATH.exists() and schema.WATCH_PATH.exists()):
            raise RuntimeError("no lab yet, run dyepack lab and dyepack seed first")
        self.quiet = quiet
        self.log, self.clients, self.pending, self.burst_incidents = [], [], set(), set()
        self.lock, self.export_lock = threading.Lock(), threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.assay, self.notify, self.burst, self.drive, self.honey = map(
            _optional, ("assay", "notify", "burst", "drive", "honey"))
        bricks = _optional("databricks")
        self.client = bricks.Client.from_env() if bricks else None
        self.routes = self._load_routes()
        self.profile = load_profile()
        with closing(connect()) as con:
            self.staff = {u: (h, s, role) for u, h, s, role in
                          con.execute("SELECT user, password_hash, salt, role FROM staff")}
        decoys = self.drive.load_decoys() if self.drive else []
        self.trip = Tripwire(self.emit, self.changed, canary.load_watch(), decoys)
        self.trip.exports = self._load_exports()
        self.trip.checklist = getattr(self.assay, "notice_checklist", None)
        # a fresh key every start. drills, the sentinel and the map read it and send it back
        self.token = secrets.token_urlsafe(24)
        path = schema.DATA_DIR / "control_token"
        path.unlink(missing_ok=True)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(self.token + "\n")

    # events

    def emit(self, kind, who, severity, detail):
        event = {"ts": round(time.time(), 3), "type": kind, "session": who.get("id") or "",
                 "actor": who.get("actor") or "", "ip": who.get("ip") or "", "severity": severity, "detail": detail}
        line = f"data: {json.dumps(event)}\n\n".encode()
        with self.lock:
            if kind != "tick":
                self.log.append(event)
            for q in self.clients:
                q.put(line)
        if kind in ("alarm", "lock", "report", "burst", "notify", "action", "export"):
            self._say(event)
        if self.client and kind in ("alarm", "report", "export"):
            self.pool.submit(self._push, event)
        return event

    def _say(self, e):
        if self.quiet:
            return
        d = e["detail"]
        what = d.get("reason") or d.get("what") or d.get("action") or d.get("title") or d.get("export_id") \
            or (f"{d.get('channel')} {d.get('status')}" if e["type"] == "notify" else d.get("folder", ""))
        print(f"{time.strftime('%H:%M:%S')}  {e['type']:<6} {e['severity']:<8} {d.get('incident', '')} "
              f"{what}  {e['actor']} {e['ip']}".rstrip(), flush=True)

    def ticker(self):
        while True:
            time.sleep(1)
            self.emit("tick", SERVER, "info", self.trip.tick())

    # what happens after an alarm

    def changed(self, inc, alarm, opened, escalated):
        # runs inside the tripwire's lock. anything slow goes to the pool
        # a remote agent's hit only alarms. bursting is for decoys this machine's sentinel saw
        if alarm["detail"]["reason"] == "decoy_open" and alarm["ip"] == "127.0.0.1":
            self._schedule_burst(inc["id"], alarm["detail"]["path"])
        if opened or escalated:
            self.pool.submit(self._alert, inc["id"], alarm)
        if RANK[inc["severity"]] >= RANK["high"]:
            self._schedule_report(inc["id"])

    def _summary(self, inc, alarm):
        d, who, ip, sid = alarm["detail"], alarm["actor"], alarm["ip"], alarm["session"]
        reason, locked = d["reason"], " Session locked." if inc["locked"] else ""
        if reason == "decoy_open":
            where = "the company drive" if ip == "127.0.0.1" else ip
            pid = (self.trip.sessions.get(sid) or {}).get("pid")
            by = who if pid is None else f"{who} (pid {pid})"
            return f"Decoy file {Path(d['path']).name} opened by {by} on {where}."
        if reason == "speed" and sid.startswith("f-"):
            return f"{who} is opening files on the company drive at machine speed."
        if reason == "speed" and sid.startswith("p-"):
            return f"Logins tried at machine speed from {ip}."
        if reason == "speed":
            return f"Bulk read at machine speed by {who} from {ip}.{locked}"
        if reason == "canary_touch":
            return f"{who} from {ip} read canary customers.{locked}"
        if reason == "unknown_account_login":
            return f"Logins tried for accounts that don't exist, from {ip}."
        batch = (self.trip.canaries.get(who) or {}).get("batch")
        where = {"table": "the customer table", "drive": "a decoy file on the drive"}.get(batch, f"export {batch}")
        if reason == "canary_login":
            return f"Canary customer {who} tried at the login page. It only exists in {where}."
        return f"Someone outside contacted canary customer {who}. It only exists in {where}."

    def _alert(self, iid, alarm):
        with self.trip.mutex:
            inc = self.trip.incidents[iid]
            severity = inc["severity"]
            # notify trims to 140 characters too. this is exactly the text sent
            summary = " ".join(self._summary(inc, alarm).split())[:140]
        channels = self.routes.get(severity, [])
        if not channels:
            return
        if self.notify:
            results = self.notify.send({"id": iid, "severity": severity, "summary": summary}, channels)
        else:
            results = [{"channel": c, "status": "simulated"} for c in channels]
        for r in results:
            self.emit("notify", DYEPACK, severity,
                      {"incident": iid, "channel": r["channel"], "status": r["status"], "summary": summary})

    def _schedule_report(self, iid):
        # one report per burst of hits, not one per hit
        with self.lock:
            if iid in self.pending:
                return
            self.pending.add(iid)
        timer = threading.Timer(1.5, self.pool.submit, (self._report, iid))
        timer.daemon = True
        timer.start()

    def _report(self, iid):
        with self.lock:
            self.pending.discard(iid)
            events = list(self.log)
        with self.trip.mutex:
            inc = dict(self.trip.incidents[iid])
        try:
            report = self.assay.write_report(inc, events, client=self.client)
        except Exception:
            report = {"title": f"Incident {iid}", "source": "template", "looks_like": "person", "actions": [],
                      "text": f"{inc['actor']} from {inc['ip']} set off {', '.join(inc['reasons'])}."}
        self.emit("report", {"id": inc["session"], "actor": inc["actor"], "ip": inc["ip"]}, inc["severity"],
                  {"incident": iid, **report})

    def _schedule_burst(self, iid, path):
        folder, drive = Path(path).parent.resolve(), Path(schema.DRIVE_ROOT).expanduser().resolve()
        if folder != drive and drive not in folder.parents:
            return  # a decoy somewhere else, nothing here to lock
        with self.lock:
            if iid in self.burst_incidents:
                return  # the whole drive already went for this incident
            self.burst_incidents.add(iid)
        self.pool.submit(self._burst, iid)

    def _burst(self, iid):
        password = self.drive.vault_password() if self.drive else None
        if not (self.burst and password):
            self._note("no burst: put DYEPACK_VAULT_PASSWORD in .env so the drive can be locked")
            return
        try:
            out = self.burst.burst_drive(password)
        except (OSError, ValueError) as e:
            self._note(f"burst of the drive failed: {e}")
            return
        with self.trip.mutex:
            inc = self.trip.incidents.get(iid)
            if inc is not None:
                inc["locked_files"] = inc.get("locked_files", []) + list(out["vault"])
        # files are locked in place. one event per folder, naming the .dye files that now sit there
        for folder in out["folders"]:
            dyes = [v for v in out["vault"] if str(Path(v).parent) == folder]
            self.emit("burst", DYEPACK, "critical", {"incident": iid, "folder": folder,
                                                     "files": [Path(v).name for v in dyes], "vault": ", ".join(dyes)})
        if not out["folders"]:
            self._note("nothing left to lock on the drive")

    def _push(self, event):
        try:
            self.client.push_event(event)
        except Exception as e:
            self._note(f"databricks push failed: {type(e).__name__}")

    def _note(self, text):
        if not self.quiet:
            print(f"{time.strftime('%H:%M:%S')}  {text}", flush=True)

    # exports and routes

    def make_export(self, s, password):
        with self.export_lock, closing(connect()) as con:
            rows = rows_of(con.execute(f"SELECT {COLS} FROM customers ORDER BY rowid"))
            watch = json.loads(schema.WATCH_PATH.read_text())
            done = [c["batch"] for c in watch["canaries"]] + [p.stem for p in schema.EXPORTS_DIR.glob("exp-*")]
            eid = "exp-%d" % (1 + max((int(b[4:]) for b in done if b.startswith("exp-") and b[4:].isdigit()),
                                      default=0))
            known = rows + watch["canaries"]
            fakes, entries = canary.make_canaries(
                self.profile, max(1, len(rows) // 250),
                [r["account_no"] for r in known], [r["portal_user"] for r in known], eid,
                taken_contacts=[r[f] for r in known for f in ("email", "phone")])
            # ids carry on after every canary already on the list, drive ones included
            first = 1 + max((int(c["canary_id"][2:]) for c in watch["canaries"]), default=0)
            for i, e in enumerate(entries):
                e["canary_id"] = f"c-{first + i:03d}"
            mixed = rows + fakes
            random.SystemRandom().shuffle(mixed)  # the lock keeps row order
            # the lab's rows come from the public recipe, so the lock uses it too. a jittered profile in the
            # header would let anyone with the repo rank the real list first. if this fails nothing is written
            blob = self.honey.lock(mixed, password, None)
            # watch first. the worst case is then watched canaries that no file holds
            watch["canaries"] += entries
            lab.write_private(schema.WATCH_PATH, watch)
            self.trip.watch(entries)
            schema.EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
            with open(os.open(schema.EXPORTS_DIR / f"{eid}.dye", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                      "wb") as f:
                f.write(blob)
            inside = sum(r["account_no"] in self.trip.canaries for r in mixed)
            self.trip.exports[eid] = {"export_id": eid, "rows": len(mixed), "canaries": inside,
                                      "real": len(mixed) - inside}
        self.emit("export", s, "info", {"export_id": eid, "rows": len(mixed), "canaries": inside})
        return eid

    def _load_exports(self):
        # rebuilt from each file's header and the watch list. nothing sits beside a locked file,
        # since a list of its canaries would tell a thief which password is right
        out = {}
        for p in schema.EXPORTS_DIR.glob("exp-*.dye"):
            try:
                with open(p, "rb") as f:
                    f.readline()
                    rows = json.loads(f.readline())["rows"]
            except (OSError, ValueError, KeyError):
                continue
            inside = sum(c["batch"] in ("table", p.stem) for c in self.trip.entries)
            out[p.stem] = {"export_id": p.stem, "rows": rows, "canaries": inside, "real": rows - inside}
        return out

    def _check_routes(self, routes):
        channels = set(self.notify.CHANNELS if self.notify else ("push", "sms", "email", "discord"))
        try:
            ok = set(routes) <= set(DEFAULT_ROUTES) and all(
                isinstance(v, list) and set(v) <= channels for v in routes.values())
        except (TypeError, AttributeError):
            ok = False
        if not ok:
            raise ValueError('routes look like {"critical": ["push", "sms"], "high": ["push"], "low": []}')
        return {sev: list(dict.fromkeys(routes.get(sev, []))) for sev in DEFAULT_ROUTES}

    def _load_routes(self):
        try:
            return self._check_routes(json.loads(routes_path().read_text()))
        except (OSError, ValueError):
            return dict(DEFAULT_ROUTES)

    def save_routes(self, routes):
        self.routes = self._check_routes(routes)
        routes_path().write_text(json.dumps(self.routes, indent=2))
        return self.routes


class Handler(BaseHTTPRequestHandler):
    app = None
    server_version = "dyepack"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _ip(self):
        # drills play outside addresses from this laptop. only a local caller may name one
        lab_ip = self.headers.get("X-Lab-Ip")
        return lab_ip if lab_ip and self.client_address[0] in LOOPBACK else self.client_address[0]

    def _send(self, code, body, kind="application/json", extra=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _staff(self):
        s = self.app.trip.session(self.headers.get("X-Session", ""))
        if s is None:
            self._send(401, {"error": "log in first"})
        elif s["locked"]:
            self._send(423, {"error": "locked"})
        else:
            return s
        return None

    def do_GET(self):
        url = urlsplit(self.path)
        path, query = unquote(url.path), parse_qs(url.query)
        if path in FILES and (WEB / FILES[path]).exists():
            f = WEB / FILES[path]
            return self._send(200, f.read_bytes(), KINDS[f.suffix])
        if path == "/events":
            return self._events()
        if path == "/api/alert-routes":
            return self._send(200, self.app.routes)
        if path == "/api/customers" or path.startswith("/api/customers/"):
            return self._customers(path, query)
        if path.startswith("/api/exports/"):
            return self._download(path[len("/api/exports/"):])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        route = {
            "/api/login": self._login, "/api/exports": self._export, "/api/permits": self._permit,
            "/portal/login": self._portal, "/lab/contact": self._contact, "/lab/drill": self._drill,
            "/lab/fs-event": self._fs, "/api/alert-routes": self._routes, "/api/respond": self._respond,
            "/api/events": self._remote,
        }.get(urlsplit(self.path).path)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if 0 <= n <= 2_000_000 else None
        except ValueError:
            body = None
        if route is None:
            return self._send(404, {"error": "not found"})
        if urlsplit(self.path).path in GUARDED and not hmac.compare_digest(
                self.headers.get("X-Dyepack-Token", "").encode(), self.app.token.encode()):
            return self._send(401, {"error": "this needs the control token from data/control_token"})
        if body is None or (route not in (self._fs, self._remote) and not isinstance(body, dict)):
            return self._send(400, {"error": "send a JSON object"})
        route(body)

    def _events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        q = queue.Queue()
        with self.app.lock:
            self.app.clients.append(q)
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while True:
                try:
                    data = q.get(timeout=15)
                except queue.Empty:
                    data = b": still here\n\n"
                self.wfile.write(data)
                self.wfile.flush()
        except OSError:
            pass
        finally:
            with self.app.lock:
                self.app.clients.remove(q)

    def _customers(self, path, query):
        s = self._staff()
        if s is None:
            return
        # registered jobs only ever see the clean table
        table = "customers_clean" if s["role"] == "job" else "customers"
        one = path[len("/api/customers/"):]
        with closing(connect()) as con:
            if one:
                rows = rows_of(con.execute(f"SELECT {COLS} FROM {table} WHERE account_no = ?", (one,)))
                out = {"customer": rows[0]} if rows else None
            elif "q" in query:
                q = query["q"][0].strip()
                like = f"%{q}%"
                rows = rows_of(con.execute(
                    f"SELECT {COLS} FROM {table} WHERE first_name || ' ' || last_name LIKE ? OR email LIKE ? "
                    "OR phone = ? OR account_no = ? OR portal_user = ? ORDER BY rowid LIMIT ?",
                    (like, like, q, q, q, _int(query, "limit", 20, 50))))
                out = {"customers": rows}
            else:
                # support tools never need more than 100 rows a page, which keeps what a thief gets small
                top = 1000 if s["role"] == "job" else 100
                page, size = _int(query, "page", 0, 10 ** 6), _int(query, "size", 50, top)
                rows = rows_of(con.execute(f"SELECT {COLS} FROM {table} ORDER BY rowid LIMIT ? OFFSET ?",
                                           (size, page * size)))
                out = {"customers": rows, "page": page, "size": size}
        self.app.trip.read(s["id"], [r["account_no"] for r in rows], "/api/customers")
        if out is None:
            return self._send(404, {"error": "no such customer"})
        self._send(200, out)

    def _download(self, eid):
        s = self._staff()
        if s is None:
            return
        meta = self.app.trip.exports.get(eid)
        if meta is None or not (schema.EXPORTS_DIR / f"{eid}.dye").exists():
            return self._send(404, {"error": "no such export"})
        if eid in self.app.trip.revoked_exports:
            return self._send(410, {"error": "this export was revoked"})
        blob = (schema.EXPORTS_DIR / f"{eid}.dye").read_bytes()
        # every export holds the table's canaries plus its own batch
        inside = [c["account_no"] for c in self.app.trip.entries if c["batch"] in ("table", eid)]
        accounts = inside + [None] * max(0, meta["rows"] - len(inside))
        self.app.trip.read(s["id"], accounts, f"/api/exports/{eid}", export_id=eid)
        self._send(200, blob, "application/octet-stream",
                   [("Content-Disposition", f'attachment; filename="{eid}.dye"')])

    def _login(self, body):
        user, password = str(body.get("user", "")), str(body.get("password", ""))
        found = self.app.staff.get(user)
        ok = bool(found) and lab.check_password(password, found[0], found[1])
        sid = self.app.trip.staff_login(user, found[2] if found else None, self._ip(), ok)
        if sid:
            return self._send(200, {"session": sid})
        self._send(403 if user in self.app.trip.revoked else 401, {"error": "wrong user or password"})

    def _export(self, body):
        s = self._staff()
        if s is None:
            return
        password = str(body.get("password") or "")
        if not password:
            return self._send(400, {"error": "an export needs a password"})
        if self.app.honey is None:
            return self._send(503, {"error": "the honey lock isn't here yet"})
        try:
            eid = self.app.make_export(s, password)
        except (OSError, ValueError) as e:
            return self._send(500, {"error": f"export failed: {e}"})
        self._send(200, {"export_id": eid})

    def _permit(self, body):
        s = self._staff()
        if s is None:
            return
        try:
            until = self.app.trip.add_permit(s["id"], str(body["who"]), str(body.get("table", "customers")),
                                             float(body.get("minutes", 30)))
        except (KeyError, ValueError, TypeError) as e:
            return self._send(400, {"error": f"bad permit: {e}"})
        self._send(200, {"ok": True, "until": until})

    def _portal(self, body):
        user, password = str(body.get("user", "")), str(body.get("password", ""))
        with closing(connect()) as con:
            found = con.execute("SELECT password_hash, salt FROM portal_accounts WHERE portal_user = ?",
                                (user,)).fetchone()
        if found:
            ok = lab.check_password(password, *found) and user not in self.app.trip.canaries
        else:
            lab.hash_password(password, lab.PORTAL_ROUNDS)  # same work either way. timing can't say who exists
            ok = False
        if not self.app.trip.portal_login(user, self._ip(), bool(found), ok):
            return self._send(423, {"error": "locked"})
        self._send(200 if ok else 401, {"ok": ok})

    def _contact(self, body):
        self.app.trip.contact(str(body.get("to", "")), str(body.get("channel", "email")), self._ip())
        self._send(200, {"ok": True})

    def _drill(self, body):
        score = body.get("score") if isinstance(body.get("score"), dict) else {}
        self.app.emit("drill", {"id": "drill", "actor": "drill", "ip": "127.0.0.1"}, "info",
                      {"phase": str(body.get("phase", "")), "status": str(body.get("status", "")), "score": score})
        self._send(200, {"ok": True})

    def _fs(self, body):
        try:
            self.app.trip.file_events((body if isinstance(body, list) else [body])[:500])
        except (TypeError, ValueError):
            return self._send(400, {"error": "file events look like {ts, pid, process, signing_id, path, op}"})
        self._send(200, {"ok": True})

    def _remote(self, body):
        # hits from a teammate's Linux decoy agent. it only watches decoys. each file it names is one
        bridge = _optional("bridge")
        if bridge is None:
            return self._send(503, {"error": "the bridge isn't here yet"})
        events = bridge.accept(body, self.headers.get("Idempotency-Key"))
        drive = Path(schema.DRIVE_ROOT).expanduser().resolve()
        with self.app.trip.mutex:
            known = {d["path"] for d in self.app.trip.decoys}
            # this route has no token, so it can never make a file on our own drive into a decoy
            self.app.trip.decoys += [bridge.decoy_entry(e) for e in events if e["path"] not in known
                                     and drive not in Path(e["path"]).resolve().parents]
        self._fs(events)

    def _routes(self, body):
        if self.headers.get("X-Lab-Ip"):
            return self._send(403, {"error": "only the dashboard sets routes"})
        try:
            self._send(200, self.app.save_routes(body))
        except ValueError as e:
            self._send(400, {"error": str(e)})

    def _respond(self, body):
        if self.headers.get("X-Lab-Ip"):
            return self._send(403, {"error": "only the dashboard responds"})
        iid, action = str(body.get("incident", "")), str(body.get("action", ""))
        if action not in ACTIONS:
            return self._send(400, {"error": "action is one of " + ", ".join(ACTIONS)})
        try:
            detail = self.app.trip.respond(iid, action, {"id": "dash", "actor": "oncall", "ip": self._ip()})
        except KeyError:
            return self._send(404, {"error": "no such incident"})
        self._send(200, detail)


def start(port=schema.DEFAULT_PORT, quiet=False):
    """Builds the app and binds the port. The caller runs serve_forever."""
    app = App(quiet)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), type("LabHandler", (Handler,), {"app": app}))
    httpd.daemon_threads = True
    threading.Thread(target=app.ticker, daemon=True).start()
    return httpd, app


def cmd_serve(args):
    try:
        httpd, app = start(args.port)
    except (RuntimeError, ValueError, sqlite3.Error) as e:
        print(e, file=sys.stderr)
        return 1
    except OSError:
        print(f"port {args.port} is busy, is dyepack serve already running?", file=sys.stderr)
        return 1
    watched = canary.load_watch()
    batches = {}
    for c in watched:
        key = c["batch"] if c["batch"] in ("table", "drive") else "exports"
        batches[key] = batches.get(key, 0) + 1
    routes = "  ".join(f"{sev}: {', '.join(ch) or 'dashboard only'}" for sev, ch in app.routes.items())
    print(f"Data Dyepack is watching Lakeview Fiber at http://127.0.0.1:{args.port}/")
    print(f"  mine map          http://127.0.0.1:{args.port}/?token={app.token}  (the token also sits in "
          f"{schema.DATA_DIR / 'control_token'})")
    print(f"  canaries watched  {len(watched):,} ({', '.join(f'{n:,} {k}' for k, n in batches.items())})")
    print(f"  decoy files       {len(app.trip.decoys)}")
    print(f"  reports           {'Databricks model' if app.client else 'template (no Databricks .env)'}")
    print(f"  alert routes      {routes}")
    print("press Ctrl+C to stop", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    finally:
        httpd.server_close()
        app.pool.shutdown(wait=False)
    return 0
