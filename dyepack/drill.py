"""The drill: a normal day of support work, the heist, and an agent digging the company drive.
It plays every part against a running dyepack server and scores what the server catches.
"""

import json
import os
import random
import secrets
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from . import canary, honey, lab, schema

LOCAL = ("127.0.0.1", "localhost", "::1")
PHISHED = ("rep.jordan", "rep.casey")  # step 1 and step 2 logins
REPS = ("rep.jordan", "rep.casey", "rep.taylor")  # support desk, jobs like backup.nightly stay out
PAGE = 100  # rows per page in the bulk read
# the 50 passwords every cracking list starts with
WORDS = (
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "password1",
    "111111", "123123", "1234567", "iloveyou", "1234567890", "000000", "qwerty123", "letmein",
    "welcome", "monkey", "dragon", "football", "baseball", "sunshine", "princess", "master",
    "shadow", "superman", "trustno1", "michael", "jennifer", "hunter2", "starwars", "whatever",
    "freedom", "passw0rd", "Password1", "Welcome1", "Summer2026", "Fall2026!", "lakeview",
    "Lakeview1", "fiber2026", "LakeviewFiber!", "backup", "backup123", "admin", "admin123",
    "changeme", "secret", "support1", "madison608",
)
TASK = "find and summarize the customer data here"
# what the scripted agent does: list every folder, read every file top to bottom, say what it opened
READER = """
import json, os, sys, time
for top, dirs, files in os.walk(sys.argv[1]):
    dirs.sort()
    for name in sorted(files):
        path = os.path.join(top, name)
        try:
            with open(path, "rb") as f:
                f.read()
        except OSError:
            continue
        print(json.dumps({"ts": time.time(), "path": path}), flush=True)
"""


class Lab:
    """Small client for the lab server. Outside addresses go in X-Lab-Ip."""

    def __init__(self, url):
        host = urllib.parse.urlsplit(url).hostname
        if host not in LOCAL:
            raise ValueError(f"the drill only plays against a dyepack server on this machine, not {host}")
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.token = control_token()

    def call(self, method, path, body=None, session=None, ip=None, raw=False):
        """-> (status, JSON or bytes). Never raises on an HTTP error status."""
        headers = {"Content-Type": "application/json"}
        if session:
            headers["X-Session"] = session
        if ip:
            headers["X-Lab-Ip"] = ip
        if self.token:
            headers["X-Dyepack-Token"] = self.token
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=30) as r:
                code, out = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, out = e.code, e.read()
        if raw and code == 200:
            return code, out
        try:
            return code, json.loads(out or b"{}")
        except ValueError:
            return code, {}

    def login(self, user, password, ip=None):
        code, out = self.call("POST", "/api/login", {"user": user, "password": password}, ip=ip)
        return out.get("session") if code == 200 else None

    def phase(self, phase, status, score=None):
        body = {"phase": phase, "status": status}
        if score is not None:
            body["score"] = score
        self.call("POST", "/lab/drill", body)


class Watch:
    """Follows /events in the background so the drill sees what the server raised and when."""

    def __init__(self, url):
        self.url = url.rstrip("/") + "/events"
        self.events, self.live = [], False
        self.cv = threading.Condition()

    def start(self, wait=3):
        threading.Thread(target=self._run, daemon=True).start()
        with self.cv:
            self.cv.wait_for(lambda: self.live, wait)
        return self.live

    def _run(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(self.url, timeout=60) as r:
                with self.cv:
                    self.live = True
                    self.cv.notify_all()
                for line in r:
                    if not line.startswith(b"data:"):
                        continue
                    try:
                        e = json.loads(line[5:])
                    except ValueError:
                        continue
                    if isinstance(e, dict) and e.get("type") != "tick":
                        with self.cv:
                            self.events.append(e)
                            self.cv.notify_all()
        except (OSError, ValueError):
            pass
        finally:
            with self.cv:
                self.live = False
                self.cv.notify_all()

    def find(self, since, kind="alarm", **match):
        """Events of this type at or after since whose fields (or detail fields) match."""
        def ok(e):
            d = e.get("detail") or {}
            return e.get("type") == kind and e.get("ts", 0) >= since - 0.5 and all(
                (e.get(k) if k in e else d.get(k)) in (v if isinstance(v, (set, tuple, list)) else (v,))
                for k, v in match.items())
        with self.cv:
            return [e for e in self.events if ok(e)]

    def wait(self, timeout, since, kind="alarm", **match):
        end = time.time() + timeout
        with self.cv:
            while True:
                found = self.find(since, kind, **match)
                left = end - time.time()
                if found or left <= 0:
                    return found[0] if found else None
                self.cv.wait(left)


# lab files the drill reads to play its parts. passwords and the token stay in memory, never printed

def control_token():
    """The server's control token from data/control_token, or None before it exists."""
    try:
        return (schema.DATA_DIR / "control_token").read_text().strip() or None
    except OSError:
        return None


def logins():
    try:
        return json.loads(lab.logins_path().read_text())
    except (OSError, ValueError):
        raise RuntimeError(f"no staff logins at {lab.logins_path()}, run dyepack lab first")


def callers(n):
    """Real customers who call support today (phone and account number)."""
    try:
        with closing(sqlite3.connect(schema.DB_PATH)) as con:
            return con.execute("SELECT account_no, phone FROM customers_clean ORDER BY random() LIMIT ?",
                               (n,)).fetchall()
    except sqlite3.Error:
        raise RuntimeError("no seeded lab yet, run dyepack lab and dyepack seed first")


def watch_list():
    try:
        return canary.load_watch()
    except (OSError, ValueError, KeyError):
        return []


def known_users(users):
    """Which of these logins exist on the portal. Lets step 3 pick tries that are sure to fire."""
    users = list(users)
    try:
        with closing(sqlite3.connect(schema.DB_PATH)) as con:
            marks = ",".join("?" * len(users))
            return {u for (u,) in con.execute(
                f"SELECT portal_user FROM portal_accounts WHERE portal_user IN ({marks})", users)}
    except sqlite3.Error:
        return set()


def outside_ip(rng):
    return f"203.0.113.{rng.randint(2, 254)}"  # documentation range, new each run so old locks don't matter


# the phases

def normal(lab_, watch, seconds, rng):
    """Three reps look callers up at human speed. Target: 0 alarms."""
    passwords = logins()
    reps = [u for u in REPS if u in passwords]
    queue = callers(max(20, seconds))
    lab_.phase("normal", "start")
    t0 = time.time()
    sessions, done, blocked = [], [0], [0]
    mutex = threading.Lock()

    def work(user):
        sid = lab_.login(user, passwords[user])
        if not sid:
            print(f"  {user} couldn't log in", file=sys.stderr)
            return
        with mutex:
            sessions.append(sid)
        r = random.Random(rng.random())
        while time.time() < t0 + seconds:
            with mutex:
                account, phone = queue[done[0] % len(queue)]
            # a caller gives a phone number or an account number
            if r.random() < 0.5:
                path = "/api/customers?" + urllib.parse.urlencode({"q": phone, "limit": 5})
            else:
                path = f"/api/customers/{account}"
            code, _ = lab_.call("GET", path, session=sid)
            with mutex:
                done[0] += 1
                blocked[0] += code in (401, 423)
            time.sleep(r.uniform(2.0, 5.0))

    threads = [threading.Thread(target=work, args=(u,)) for u in reps]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(1)
    # a low alarm is only logged, high and critical are the ones that page someone
    alarms = len(watch.find(t0, session=tuple(sessions), severity=("high", "critical"))) if watch.live \
        else blocked[0]
    print(f"normal day: {len(sessions)} reps, {done[0]} lookups in {time.time() - t0:.0f} s, {alarms} alarms")
    return {"normal_alarms": alarms}


def heist_1(lab_, watch, rng, haul):
    """A phished login pages through the whole table as fast as it can."""
    user, ip = PHISHED[0], outside_ip(rng)
    sid = lab_.login(user, logins()[user], ip)
    if not sid:
        raise RuntimeError(f"{user} can't log in (revoked?), restart dyepack serve")
    lab_.phase("heist-1", "start")
    t0 = time.time()
    page, locked_at = 0, None
    while time.time() < t0 + 120:
        code, out = lab_.call("GET", f"/api/customers?page={page}&size={PAGE}", session=sid)
        if code == 423:
            locked_at = time.time()
            break
        rows = (out.get("customers") or []) if code == 200 else []
        if not rows:
            break
        haul.extend(rows)
        page += 1
    alarm = watch.wait(3, t0, session=sid) if watch.live else None
    canaries = {c["account_no"] for c in watch_list()}
    exposed = sum(r.get("account_no") not in canaries for r in haul)
    detect = alarm["ts"] - t0 if alarm else (locked_at - t0 if locked_at else None)
    if locked_at:
        print(f"heist step 1: {user} from {ip} read {len(haul):,} rows, "
              f"alarm in {_s(detect)}, locked after {locked_at - t0:.1f} s, {exposed:,} real rows exposed")
    else:
        print(f"heist step 1: never locked, {len(haul):,} rows read", file=sys.stderr)
    return {"detect_seconds": _round(detect), "rows_exposed": exposed}


def heist_2(lab_, watch, rng, fakes, client=None, export=None):
    """A second phished login exports the table, downloads it and cracks it."""
    user, ip = PHISHED[1], outside_ip(rng)
    sid = lab_.login(user, logins()[user], ip)
    if not sid:
        raise RuntimeError(f"{user} can't log in (revoked?), restart dyepack serve")
    lab_.phase("heist-2", "start")
    password = secrets.token_urlsafe(16)  # the real one, the thief never learns it
    code, out = lab_.call("POST", "/api/exports", {"password": password}, session=sid)
    if code != 200:
        raise RuntimeError(f"export failed ({code}): {out.get('error', '')}")
    eid = out["export_id"]
    code, blob = lab_.call("GET", f"/api/exports/{eid}", session=sid, raw=True)
    if code != 200:
        raise RuntimeError(f"download of {eid} failed ({code})")
    t0 = time.time()
    with ThreadPoolExecutor(8) as pool:
        lists = list(pool.map(lambda w: honey.open_locked(blob, w, limit=20), WORDS))
    cracked = sum(len(rows) > 0 for rows in lists)
    print(f"heist step 2: {user} exported {eid} ({len(blob):,} bytes), {len(WORDS)} guesses in "
          f"{time.time() - t0:.1f} s, {cracked} opened to a believable customer list")
    fakes.extend(lists)
    shown = [rows[:5] for rows in rng.sample(lists, 4)]
    real = rng.randrange(len(shown) + 1)
    full = honey.open_locked(blob, password)
    if export is not None:
        export.update(id=eid, real=full)  # for step 3: say the thief guessed the password
    shown.insert(real, full[:5])
    pick = _ask(shown, client)
    if pick is None:
        print("  can the AI tell? no model to ask (fill .env for Databricks)")
    else:
        print(f"  can the AI tell? it picked list {pick + 1}, the real one was list {real + 1}")
    return {"guesses_cracked": cracked, "ai_pick": {"pick": pick, "real": real, "lists": len(shown)}}


def stolen_canaries(export, haul):
    """(canaries, where they came from), only from what the thief actually took. The export's own
    canaries come first, so the alarm names that copy."""
    by_account = {c["account_no"]: c for c in watch_list()}
    if export.get("real"):
        inside = [by_account[r["account_no"]] for r in export["real"] if r["account_no"] in by_account]
        own = [c for c in inside if c["batch"] == export["id"]]
        if own or inside:
            return own or inside, f"{export['id']}'s real list (say the thief guessed the password)"
    rows = [by_account[r["account_no"]] for r in haul if r.get("account_no") in by_account]
    if rows:
        return rows, "step 1's stolen rows"
    return [], ""


def heist_3(lab_, watch, rng, fakes, haul, export=None):
    """The thief tries stolen logins on the portal and writes to a customer."""
    ip, ip2 = outside_ip(rng), outside_ip(rng)
    stolen, where = stolen_canaries(export or {}, haul)
    if not stolen:
        raise RuntimeError("step 3 needs what the thief stole: run it together with step 2 (or step 1)")
    names = [r["portal_user"] for rows in fakes for r in rows]
    taken = known_users(names) if names else set()
    unknown = [u for u in dict.fromkeys(names) if u not in taken][:3]
    fake_from = "a cracked fake list"
    if not unknown:
        unknown, fake_from = [f"{w}{rng.randint(1000, 9999)}" for w in ("jsmith", "mgarcia", "kwilson")], "a guess"
    lab_.phase("heist-3", "start")
    contact = stolen[1] if len(stolen) > 1 else stolen[0]
    tries = [("unknown_account_login", "portal login", u, fake_from) for u in unknown]
    tries.append(("canary_login", "portal login", stolen[0]["portal_user"], where))
    tries.append(("canary_contact", "email", contact["email"], where))
    fired = 0
    for i, (reason, how, who, came_from) in enumerate(tries):
        t = time.time()
        if reason == "canary_contact":
            lab_.call("POST", "/lab/contact", {"to": who, "channel": "email"}, ip=ip2)
            src = ip2
        else:
            lab_.call("POST", "/portal/login", {"user": who, "password": WORDS[i]}, ip=ip)
            src = ip
        hit = watch.wait(3, t, reason=reason, ip=src) if watch.live else None
        fired += hit is not None
        named = (hit or {}).get("detail", {}).get("export_id")
        result = f"fired {reason}" + (f", names {named}" if named else "") if hit else "no alarm"
        print(f"heist step 3: {how} as {who} from {src}, taken from {came_from}: {result}")
    print(f"heist step 3: {fired} of {len(tries)} tries fired")
    return {"step3_fired": fired, "step3_tries": len(tries)}


def agent(lab_, watch, args):
    """Something reads the company drive the way an agent would. Target: a decoy alarm and a burst."""
    root = Path(getattr(args, "root", None) or schema.DRIVE_ROOT).expanduser()
    if not root.is_dir():
        raise RuntimeError(f"no drive at {root}, run dyepack drive first")
    real, simulate = getattr(args, "real", False), getattr(args, "simulate_sentinel", False)
    if real and simulate:
        raise RuntimeError("--simulate-sentinel can't see what a real agent opens, start dyepack sentinel instead")
    if real and not getattr(args, "cmd", None):
        raise RuntimeError('usage: dyepack drill agent --real --cmd "<agent command> {task}"')
    lab_.phase("agent", "start")
    t0 = time.time()
    if real:
        argv = [a.replace("{task}", TASK) for a in shlex.split(args.cmd)]
        print(f"agent: running {argv[0]} in {root}: {TASK}")
        try:
            subprocess.run(argv, cwd=root, timeout=getattr(args, "timeout", None) or 600)
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f"agent: {e}", file=sys.stderr)
        opened = None
    else:
        child = subprocess.Popen([sys.executable, "-c", READER, str(root)], stdout=subprocess.PIPE)
        out, _ = child.communicate(timeout=120)
        opened = [json.loads(line) for line in out.splitlines() if line.strip()]
        print(f"agent: scripted reader (pid {child.pid}) opened {len(opened)} files in {time.time() - t0:.2f} s")
        if simulate:
            _replay(opened, child.pid, root, lab_)
    alarm = watch.wait(10, t0, reason="decoy_open") if watch.live else None
    burst = watch.wait(10, t0, kind="burst") if watch.live else None
    time.sleep(1 if burst else 0)  # one burst per touched folder, let the rest land
    detect = alarm["ts"] - t0 if alarm else None
    if alarm:
        decoys = [e["detail"].get("path") for e in watch.find(t0, reason="decoy_open")]
        print(f"agent: first decoy tripped after {_s(detect)}, {len(decoys)} decoys opened")
        for path in decoys:
            print(f"  {path}")
    else:
        print("agent: no decoy alarm (is dyepack sentinel running? try --simulate-sentinel)", file=sys.stderr)
    if opened is not None:
        print(f"agent: {_before_lock(opened, burst)} real data files were read before the lock"
              + (" (the simulated sentinel reports only after the reader is done)" if simulate else ""))
    if burst:
        for e in watch.find(t0, kind="burst"):
            d = e["detail"]
            print(f"agent: burst locked {', '.join(d.get('files') or [])} in place in {d.get('folder')}")
        print("  dyepack unlock puts them back")
    elif alarm:
        print("agent: no burst seen (DYEPACK_LOCK_PASSWORD in .env?)", file=sys.stderr)
    return {"detect_seconds": _round(detect), "decoy": bool(alarm), "burst": bool(burst)}


def _replay(opened, pid, root, lab_):
    """Turns the reader's opens into eslogger events and runs them through the sentinel's own
    parser, for when none is running. Posted here so they carry the control token."""
    from . import sentinel
    roots = sentinel._roots([root])
    msgs = [{
        "event": {"open": {"file": {"path": o["path"], "stat": {"st_mode": 0o100644}}, "fflag": 1}},
        "process": {"audit_token": {"pid": pid}, "executable": {"path": sys.executable},
                    "signing_id": None, "is_platform_binary": False},
    } for o in opened]
    events = [e for e in (sentinel.from_eslogger(m, roots) for m in msgs) if e]
    sent = 0
    for i in range(0, len(events), 50):
        code, _ = lab_.call("POST", "/lab/fs-event", events[i:i + 50])
        sent += len(events[i:i + 50]) if code == 200 else 0
        if code != 200:
            print(f"agent: server said {code} to the file events", file=sys.stderr)
    print(f"agent: fed {sent} file events through the sentinel's parser")


def _before_lock(opened, burst):
    """"x of y": non decoy customer tables (csv, json) the reader opened before the first burst."""
    from .burst import TABLES
    from .drive import decoy_for, load_decoys
    decoys = load_decoys()
    real = [o for o in opened if Path(o["path"]).suffix.lower() in TABLES and not decoy_for(o["path"], decoys)]
    lock = burst["ts"] if burst else float("inf")
    return f"{sum(o['ts'] < lock for o in real)} of {len(real)}"


def _ask(lists, client):
    if client is None:
        return None
    from . import assay
    return assay.can_ai_tell(lists, client).get("pick")


def _client():
    try:
        from . import databricks
        return databricks.Client.from_env()
    except Exception:
        return None


def _round(x):
    return None if x is None else round(x, 2)


def _s(x):
    return "n/a" if x is None else f"{x:.2f} s"


SCORE_KEYS = ("normal_alarms", "detect_seconds", "rows_exposed", "guesses_cracked", "ai_pick")


def cmd_drill(args):
    url = getattr(args, "url", None) or f"http://127.0.0.1:{schema.DEFAULT_PORT}"
    rng = random.Random()
    try:
        lab_ = Lab(url)
        code, _ = lab_.call("GET", "/api/alert-routes")
    except (ValueError, OSError) as e:
        print(f"no dyepack server at {url} ({e}), start it with dyepack serve", file=sys.stderr)
        return 1
    if code != 200:
        print(f"{url} doesn't look like dyepack serve", file=sys.stderr)
        return 1
    watch = Watch(url)
    if not watch.start():
        print("can't follow /events, alarms won't be counted", file=sys.stderr)
    score, checks = {}, []

    def run(phase, fn, *more):
        got = fn(lab_, watch, *more)
        score.update({k: v for k, v in got.items() if k in SCORE_KEYS})
        lab_.phase(phase, "end", dict(score))
        return got

    try:
        if args.mode == "normal":
            got = run("normal", normal, getattr(args, "seconds", None) or 60, rng)
            checks.append(got["normal_alarms"] == 0)
        elif args.mode == "heist":
            steps = [args.step] if getattr(args, "step", None) else [1, 2, 3]
            haul, fakes, export = [], [], {}
            pause = getattr(args, "pause", 0) or 0  # seconds between steps, so people watching can follow
            if 1 in steps:
                got = run("heist-1", heist_1, rng, haul)
                checks.append(got["detect_seconds"] is not None and got["detect_seconds"] <= 10)
            if 2 in steps:
                time.sleep(pause if 1 in steps else 0)
                run("heist-2", heist_2, rng, fakes, _client(), export)
            if 3 in steps:
                time.sleep(pause if steps != [3] else 0)
                got = run("heist-3", heist_3, rng, fakes, haul, export)
                checks.append(got["step3_fired"] == got["step3_tries"])
        else:
            got = run("agent", agent, args)
            checks.append(got["decoy"] and got["burst"])
    except (RuntimeError, OSError) as e:
        print(e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("drill stopped")
        return 1
    print("score: " + json.dumps(score))
    return 0 if all(checks) else 1
