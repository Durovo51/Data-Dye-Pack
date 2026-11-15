"""The tripwire: canary hits, machine speed, incidents, dig permits and lockdown. All in memory."""

import csv
import json
import os
import threading
import time
from collections import deque
from pathlib import Path

from . import schema

RANK = {s: i for i, s in enumerate(schema.SEVERITIES)}
WINDOW = 60  # seconds every speed check looks back
UNKNOWN_HIGH = 3  # unknown logins from one address in a minute before it stops looking like a typo
LOGINS_PER_MIN = 30  # nobody types that fast


def _trim(seen, now):
    while seen and seen[0][0] < now - WINDOW:
        seen.popleft()


def _rate(seen, now):
    # per minute, never from less than 10 s of history so one quick search can't look fast
    span = max(10.0, now - seen[0][0]) if seen else 10.0
    return round(sum(n for _, n in seen) * 60 / span)


def export_of(canary):
    return canary["batch"] if canary["batch"] not in ("table", "drive") else None


def _on_drive(path):
    """A path as the dashboard shows it: from the drive root, so no home folder lands on screen."""
    try:
        return str(Path(path).resolve().relative_to(Path(schema.DRIVE_ROOT).expanduser().resolve()))
    except (ValueError, OSError):
        return str(path)


def _rows_in(path):
    """Customer rows in a data file someone read in plain text. Once it's locked, the .dye header
    keeps the count. Before that, the file itself says."""
    try:
        dye = Path(f"{path}.dye")
        if dye.exists():
            with open(dye, "rb") as f:
                magic, head = f.readline(), f.readline()
            return int(json.loads(head)["rows"]) if magic.strip() == b"DYEPACK1" else 0
        p = Path(path)
        if p.suffix.lower() == ".json":
            data = json.loads(p.read_text())
            if isinstance(data, dict):
                data = max((v for v in data.values() if isinstance(v, list)), key=len, default=[])
            return len(data) if isinstance(data, list) else 0
        with open(p, newline="") as f:
            return max(0, sum(1 for _ in csv.reader(f)) - 1)
    except (OSError, ValueError, KeyError, TypeError):
        return 0


class Tripwire:
    """emit(type, session, severity, detail) sends an event. changed(incident, alarm, opened, escalated)
    hears about every alarm. That lets the server write reports, send alerts or burst a folder."""

    def __init__(self, emit, changed, canaries, decoys=(), file_jobs=()):
        self.emit, self.changed = emit, changed
        self.mutex = threading.RLock()
        self.canaries = {}  # account_no, portal_user, email and phone all point at the watch entry
        self.entries = []
        self.watch(canaries)
        self.decoys = list(decoys)
        self.file_jobs = list(file_jobs)  # registered tools that touch the drive on purpose
        self.sessions, self.incidents = {}, {}
        self.by_session, self.by_export, self.by_actor = {}, {}, {}
        self.groups = {}  # ("actor", name) or ("ip", address) -> the same counters a session keeps
        self.clock = time.time  # tests swap in their own
        self.locked_ips, self.revoked, self.revoked_exports = set(), set(), set()
        self.permits, self.exports, self.files = [], {}, {}
        self.checklist = None  # the server hands in the breach notice checklist when it has one
        self.reads = deque()  # (ts, rows) for everyone, feeds the tick
        self.counts = {}

    def watch(self, canaries):
        with self.mutex:
            self.entries += list(canaries)
            for c in canaries:
                for key in ("account_no", "portal_user", "email", "phone"):
                    self.canaries[c[key]] = c

    def _id(self, prefix):
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]}"

    def _session(self, sid, actor, ip, role):
        s = {"id": sid, "actor": actor, "ip": ip, "role": role, "locked": False,
             "seen": deque(), "tries": deque(), "unknown": deque(), "fast": False,
             "exposed": 0, "decoys": set(), "touched": set(), "last": self.clock()}
        self.sessions[sid] = s
        return s

    def _outside(self, ip, actor):
        # everything from one outside address (portal logins, contact) is one session
        with self.mutex:
            s = next((s for s in self.sessions.values() if s["role"] == "outside" and s["ip"] == ip), None)
            s = s or self._session(self._id("p"), actor, ip, "outside")
            s["actor"], s["last"] = actor, self.clock()
            return s

    # staff and jobs

    def staff_login(self, user, role, ip, ok):
        """Logs the attempt. Returns the new session id (None when it failed)."""
        with self.mutex:
            ok = ok and user not in self.revoked
            s = self._session(self._id("job" if role == "job" else "s"), user, ip, role) if ok \
                else {"id": "", "actor": user, "ip": ip}
            self.emit("login", s, "info", {"user": user, "ok": ok, "where": "staff"})
            return s["id"] if ok else None

    def session(self, sid):
        with self.mutex:
            s = self.sessions.get(sid)
            return s if s and s["role"] in ("support", "job") else None

    def read(self, sid, accounts, path, export_id=None):
        """After the API hands out rows (their account numbers). Logs the read, then decides on alarms."""
        with self.mutex:
            s, now, n = self.sessions[sid], self.clock(), len(accounts)
            hits = [self.canaries[a] for a in accounts if a in self.canaries]
            s["last"] = now
            s["seen"].append((now, n))
            _trim(s["seen"], now)
            self.reads.append((now, n))
            self.emit("read", s, "info", {"rows": n, "canaries": len(hits), "path": path})
            if s["role"] == "job" or self._permitted(s, now):
                return  # registered systems and declared digs get logged, never alarmed
            if not s["locked"] and export_id is None:
                # a download leaves honey locked and a permitted dig is no breach. neither counts as plaintext
                s["exposed"] += n - len(hits)
            # one person or one address spread over many sessions still reads as one
            groups = [self.groups.setdefault(key, {"seen": deque(), "touched": set(), "fast": False})
                      for key in (("actor", s["actor"]), ("ip", s["ip"]))]
            for g in [s, *groups]:
                if g is not s:
                    g["seen"].append((now, n))
                    _trim(g["seen"], now)
                g["touched"] |= {c["canary_id"] for c in hits}
            rate, inc = max(_rate(g["seen"], now) for g in [s, *groups]), None
            fast = rate > schema.SPEED_ROWS_PER_MIN
            # three canaries is no support call, even at a slow pace
            many = max(len(g["touched"]) for g in [s, *groups]) >= 3
            if fast and not any(g["fast"] for g in [s, *groups]):
                inc = self._alarm(s, "speed", "high", rate=rate, export_id=export_id)
                for g in [s, *groups]:
                    g["fast"], g["incident"] = True, inc["id"]
            if hits:
                ids = [c["canary_id"] for c in hits][:50]
                inc = self._alarm(s, "canary_touch", "high" if fast or many else "low", ids,
                                  export_id or next(filter(None, map(export_of, hits)), None), rate,
                                  count=len(hits))
            if (fast or many) and not s["locked"]:
                # whoever keeps a fast user or address going joins the incident that speed opened
                inc = inc or self.incidents.get(self.by_session.get(s["id"]) or self.by_actor.get(s["actor"])
                                                or next((g["incident"] for g in groups if g.get("incident")), None))
                if inc:
                    self._lock_actor(s, inc)

    def add_permit(self, sid, who, table, minutes):
        with self.mutex:
            by = self.sessions[sid]["actor"]
            if by == who:
                raise ValueError("a dig permit needs someone else to sign off")
            until = self.clock() + minutes * 60
            self.permits.append({"who": who, "table": table, "until": until, "by": by})
            return until

    def _permitted(self, s, now):
        return any(p["who"] == s["actor"] and p["table"] == "customers" and now <= p["until"]
                   for p in self.permits)

    # the outside world

    def portal_login(self, user, ip, exists, ok):
        """Customer login page. Returns False when the address is locked."""
        with self.mutex:
            if ip in self.locked_ips:
                return False
            s, now = self._outside(ip, user), self.clock()
            s["tries"].append((now, 1))
            _trim(s["tries"], now)
            self.emit("login", s, "info", {"user": user, "ok": ok, "where": "portal"})
            canary, rate = self.canaries.get(user), _rate(s["tries"], now)
            if rate > LOGINS_PER_MIN and not s["fast"]:
                s["fast"] = True
                self._alarm(s, "speed", "high", rate=rate)
            if canary:
                inc = self._alarm(s, "canary_login", "critical", [canary["canary_id"]], export_of(canary))
                self._lock(s, inc, "ip")
            elif not exists:
                s["unknown"].append((now, 1))
                _trim(s["unknown"], now)
                self._alarm(s, "unknown_account_login", "high" if len(s["unknown"]) >= UNKNOWN_HIGH else "low")
            return True

    def contact(self, to, channel, ip):
        # an email or call to a canary always counts, even from an address that's already locked
        with self.mutex:
            canary = self.canaries.get(to)
            if canary and to in (canary["email"], canary["phone"]):
                s = self._outside(ip, to)
                inc = self._alarm(s, "canary_contact", "critical", [canary["canary_id"]], export_of(canary))
                if not s["locked"]:
                    self._lock(s, inc, "ip")

    def file_events(self, events):
        """Batches from the sentinel. Our own pid is skipped since a burst writes through the drive."""
        from .drive import decoy_for
        me = os.getpid()
        events = [e for e in events if isinstance(e, dict)]
        with self.mutex:
            for e in events:
                pid, host = e.get("pid"), e.get("server_id")
                if pid == me and not host:
                    continue
                path, name = str(e.get("path") or ""), Path(str(e.get("process") or "unknown")).name
                key = "f-" + "-".join(str(x) for x in (host, pid if pid is not None else name) if x)
                job = self._file_job(e)
                if job:
                    # a registered backup or sync job: logged, never counted for speed or decoys
                    self.emit("read", {"id": key, "actor": name, "ip": host or "127.0.0.1"}, "info",
                              {"path": path, "process": name, "pid": pid, "job": job})
                    continue
                now = float(e.get("ts") or self.clock())
                s = self.files.get(key)
                inc = self.incidents.get(self.by_session.get(s["id"])) if s else None
                # a process quiet for a minute or with a closed incident starts fresh. linux events
                # carry no pid. without this a second run on the same box would never alarm
                if s is None or now - s["last"] > WINDOW or (inc and inc["status"] != "open"):
                    n = self.counts[key] = self.counts.get(key, 0) + 1
                    s = self._session(key if n == 1 else f"{key}-{n}", name, host or "127.0.0.1", "process")
                    s["pid"] = pid
                    self.files[key] = s
                s["last"] = now
                s["seen"].append((now, 1))
                _trim(s["seen"], now)
                rate = _rate(s["seen"], now)
                self.emit("read", s, "info", {"path": path, "process": name, "pid": pid, "files_per_min": rate})
                if rate > schema.SPEED_FILES_PER_MIN and not s["fast"]:
                    s["fast"] = True
                    self._alarm(s, "speed", "high", rate=rate)
                # only a read opens a decoy. a write is someone rebuilding the drive
                read = str(e.get("op") or "read") == "read"
                decoy = decoy_for(path, self.decoys) if read else None
                if decoy and decoy["path"] not in s["decoys"]:
                    s["decoys"].add(decoy["path"])
                    self._alarm(s, "decoy_open", "critical", rate=rate, path=decoy["path"])
                # a real data file read in plain text. once the drive locks the original is gone, so a
                # read of one always came before the lock, and a breach notice has to count it
                if read and not decoy and Path(path).suffix.lower() in (".csv", ".json"):
                    s.setdefault("plain_files", set()).add(path)

    def _file_job(self, e):
        # the mac names a program by its signing id, the linux agent by its path and user
        for job in self.file_jobs:
            if job.get("signing_id") and job["signing_id"] == e.get("signing_id"):
                return job.get("name") or job["signing_id"]
            if job.get("exe") and job["exe"] == e.get("process") and job.get("user") == e.get("username"):
                return job.get("name") or job["exe"]
        return None

    # incidents

    def _alarm(self, s, reason, severity, canary_ids=(), export_id=None, rate=None, path=None, count=None):
        person = s["actor"] if s.get("role") == "support" else None
        iid = self.by_session.get(s["id"]) or self.by_actor.get(person) or self.by_export.get(export_id)
        inc = self.incidents.get(iid)
        opened = inc is None or inc["status"] == "dismissed"
        if opened:
            inc = {"id": self._id("inc"), "severity": severity, "status": "open", "opened": self.clock(),
                   "session": s["id"], "actor": s["actor"], "ip": s["ip"], "sessions": [],
                   "export_id": None, "canary_ids": [], "reasons": [], "locked": False}
            self.incidents[inc["id"]] = inc
        escalated = not opened and RANK[severity] > RANK[inc["severity"]]
        if escalated:
            inc["severity"] = severity
        if s["id"] not in inc["sessions"]:
            inc["sessions"].append(s["id"])
        inc["canary_ids"] += [c for c in canary_ids if c not in inc["canary_ids"]]
        if reason not in inc["reasons"]:
            inc["reasons"].append(reason)
        if export_id:
            inc["export_id"] = export_id
            self.by_export[export_id] = inc["id"]
        self.by_session[s["id"]] = inc["id"]
        if person:
            self.by_actor[person] = inc["id"]  # every session of one support login is one incident
        # the id list stays short for the stream. canary_count says how many there really were
        detail = {"reason": reason, "incident": inc["id"], "canary_ids": list(canary_ids),
                  "canary_count": len(canary_ids) if count is None else count,
                  "export_id": export_id, "rate_per_min": rate}
        if path is not None:
            detail["path"] = path
        alarm = self.emit("alarm", s, severity, detail)
        self.changed(inc, alarm, opened, escalated)
        return inc

    def _lock_actor(self, s, inc):
        # every open session of that person goes, not only the one that tripped
        for other in list(self.sessions.values()):
            if other["actor"] == s["actor"] and other["role"] == s["role"] and not other["locked"]:
                if other["id"] not in inc["sessions"]:
                    inc["sessions"].append(other["id"])
                self.by_session[other["id"]] = inc["id"]
                self._lock(other, inc, "session")

    def _lock(self, s, inc, what):
        s["locked"] = inc["locked"] = True
        if what == "ip":
            self.locked_ips.add(s["ip"])
        self.emit("lock", s, inc["severity"], {"incident": inc["id"], "what": what})

    def respond(self, iid, action, by):
        """The dashboard's buttons. by is who pressed it ({"id", "actor", "ip"})."""
        with self.mutex:
            inc = self.incidents[iid]
            detail = {"incident": iid, "action": action}
            sessions = [self.sessions[sid] for sid in inc["sessions"] if sid in self.sessions]
            if action == "lock":
                for s in sessions:
                    if not s["locked"] and s["role"] != "process":
                        self._lock(s, inc, "ip" if s["role"] == "outside" else "session")
            elif action == "revoke":
                users = {s["actor"] for s in sessions if s["role"] in ("support", "job")}
                self.revoked |= users
                for s in self.sessions.values():
                    if s["actor"] in users and not s["locked"]:
                        self._lock(s, inc, "session")
                if inc["export_id"]:
                    self.revoked_exports.add(inc["export_id"])
                detail["revoked"] = sorted(users) + ([inc["export_id"]] if inc["export_id"] else [])
            elif action == "notify_customers":
                exp = self.exports.get(inc["export_id"])
                files = sorted({f for s in sessions for f in s.get("plain_files", ())})
                plain = sum(s.get("exposed", 0) for s in sessions) + sum(_rows_in(f) for f in files)
                detail["customers"] = max(exp["real"] if exp else 0, plain)
                # what a notice needs: rows that left readable, copies that left locked and when we knew
                detail["plaintext_rows"] = plain
                detail["plaintext_files"] = [_on_drive(f) for f in files]
                detail["locked_copies"] = ([inc["export_id"]] if inc["export_id"] else []) + \
                    [_on_drive(f) for f in inc.get("locked_files", [])]
                detail["found_at"] = inc["opened"]
                if self.checklist:
                    try:
                        detail["checklist"] = self.checklist(dict(inc), dict(detail))
                    except Exception:
                        pass  # a drafted notice is nice to have, the action still counts
            elif action == "dismiss":
                inc["status"] = "dismissed"
                for s in sessions:
                    s["locked"], s["fast"], s["touched"] = False, False, set()
                    self.locked_ips.discard(s["ip"])
                    self.groups.pop(("actor", s["actor"]), None)
                    self.groups.pop(("ip", s["ip"]), None)
            self.emit("action", by, "info", detail)
            return detail

    def tick(self):
        with self.mutex:
            now = self.clock()
            while self.reads and self.reads[0][0] < now - 10:
                self.reads.popleft()
            active = sum(1 for s in self.sessions.values() if s["last"] >= now - WINDOW and not s["locked"])
            return {"reads_per_min": sum(n for _, n in self.reads) * 6, "sessions": active}
