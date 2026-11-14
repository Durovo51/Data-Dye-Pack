"""Incident reports, the "can AI tell?" test and the customer notice checklist.

Reports and picks ask the Databricks model when a client is passed in. With no client or on any
error the report comes from a plain template and the pick is None.
"""

import json
import math
import os
import re
from datetime import date, datetime, timedelta

from .schema import CUSTOMER_FIELDS, SPEED_FILES_PER_MIN, SPEED_ROWS_PER_MIN

_RANK = {"info": 0, "low": 1, "high": 2, "critical": 3}
_LOGINS = ("canary_login", "unknown_account_login")
_DRIVE = "file drive"
_HERE = ("", "127.0.0.1", "::1", "localhost")  # anything else is a server name from the Linux agent
_DATA = (".csv", ".json")  # real data files on the drive, same rule as the mine map
MACHINE_PACE = SPEED_ROWS_PER_MIN  # rows a minute, the line the tripwire and the mine map use
FILE_PACE = SPEED_FILES_PER_MIN    # files a minute on the drive
LOGIN_PACE = 30                    # login tries a minute, nobody types that fast
MACHINE = "a script or AI agent"   # all that machine speed can tell us
NOTICE_HEAD = "Lab guidance, not legal advice"

REPORT_PROMPT = (
    "You write incident reports for the security team at Lakeview Fiber, an internet provider. "
    "Use only the facts you are given. Write one paragraph of 4 to 6 plain English sentences that says "
    "what happened, how fast it was caught, whether the pace looks like a person or a script or AI agent, "
    "which canaries or export were involved, how many real customer rows were exposed and the recommended "
    "actions. Machine speed means a script or AI agent. Never claim it was an AI from speed alone. "
    "Give times under a second in ms (like 80 ms) and call the speed the peak, in rows or files a minute. "
    "No lists, no markdown and no dashes."
)

DRIVE_PROMPT = (
    " This one happened on the file drive. Name the decoy path, the process and its peak files a minute, "
    "the customer files that were locked in place as .dye files and any real files it opened before the lock. "
    "End with the next step from the facts."
)

PICK_PROMPT = (
    "Several customer lists were opened from one stolen export, each with a different password guess. "
    "Exactly one of them is the real customer list and the rest are decoys from wrong passwords. "
    'Which list is the real one? Answer with JSON only, like {"pick": 2, "reason": "one short sentence"}.'
)


def _d(e):
    return e.get("detail") if isinstance(e.get("detail"), dict) else {}


def _ts(e):
    t = e.get("ts")
    return float(t) if isinstance(t, (int, float)) and not isinstance(t, bool) else None


def _num(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else 0


def _dur(s):
    """Seconds from one up, milliseconds below, rounded the way the dashboard rounds."""
    s = max(0.0, s)
    if s >= 0.9995:
        return f"{math.floor(s * 10 + 0.5) / 10:.1f} seconds"
    ms = math.floor(s * 1000 + 0.5)
    return f"{ms} ms" if ms else "under 1 ms"


def _later(s):
    return "at the same moment" if s < 0.0005 else _dur(s) + " later"


def _home(path):
    """~ for the home folder. Keeps paths short."""
    home, path = os.path.expanduser("~").rstrip("/"), str(path)
    return "~" + path[len(home):] if home and path.startswith(home + "/") else path


def _spot(path):
    """folder/name, the way the mine map names drive files."""
    folder, name = os.path.split(str(path).rstrip("/"))
    folder = os.path.basename(folder)
    return f"{folder}/{name}" if folder else name


def _plain(name):
    # a burst locks customers.csv in place as customers.csv.dye
    name = str(name)
    return name[:-4] if name.lower().endswith(".dye") else name


def _dyes(burst):
    """Full paths of the .dye files a burst left. The vault field lists them all, the files are a fallback."""
    d = _d(burst)
    vault = d.get("vault")
    found = [str(p).strip() for p in (vault if isinstance(vault, list) else str(vault or "").split(", "))]
    found = [p for p in found if p.lower().endswith(".dye")]
    return found or [os.path.join(str(d.get("folder") or ""), str(n)) for n in d.get("files") or []]


def _on_drive(e):
    # the server gives file watchers an f- session and their reads a pace in files
    return str(e.get("session") or "").startswith("f-") or (e.get("type") == "read" and "files_per_min" in _d(e))


def _facts(incident, events):
    """Boil the incident's events down to the numbers a report needs."""
    inc = incident if isinstance(incident, dict) else {"id": incident}
    iid = inc.get("id") or inc.get("incident")
    events = [e for e in events or [] if isinstance(e, dict)]
    alarms = [e for e in events
              if e.get("type") == "alarm" and (iid is None or _d(e).get("incident") in (None, iid))]
    sessions = {a.get("session") for a in alarms if a.get("session")}
    mine = alarms + [e for e in events if e.get("type") != "alarm" and e.get("session") in sessions]
    first_alarm = min((_ts(a) for a in alarms if _ts(a) is not None), default=None)
    # time to catch runs from each session's first read or file open (else its first event),
    # the same clock as the drill and the dashboard. a staff login doesn't start it
    starts = []
    for sid in sessions:
        evs = [e for e in mine if e.get("session") == sid and _ts(e) is not None]
        reads = [_ts(e) for e in evs if e.get("type") == "read"]
        if evs:
            starts.append(min(reads or [_ts(e) for e in evs]))
    start = min(starts, default=first_alarm)
    first = alarms[0] if alarms else {}
    reasons = list(dict.fromkeys(_d(a)["reason"] for a in alarms if _d(a).get("reason")))
    f = {
        "incident": iid or _d(first).get("incident") or "unknown",
        "alarm_reasons": reasons,
        "worst_severity": max((a.get("severity") for a in alarms), key=lambda s: _RANK.get(s, -1), default=None),
        "seconds_to_first_alarm": None if None in (first_alarm, start) else round(max(0.0, first_alarm - start), 3),
    }
    drive = "decoy_open" in reasons or any(map(_on_drive, mine))
    f.update(_drive_facts(f, alarms, mine, events) if drive else _row_facts(f, inc, alarms, mine, events))
    f["recommended_actions"] = _actions(f)
    if drive:
        f["next_step"] = _next_step(f)
    return f


def _row_facts(f, inc, alarms, mine, events):
    """Customer API reads, portal logins and contact: rows, canaries and exports."""
    first, reasons = alarms[0] if alarms else {}, f["alarm_reasons"]
    lock = min((_ts(e) for e in mine if e.get("type") == "lock" and _ts(e) is not None), default=None)
    reads = [_d(e) for e in mine if e.get("type") == "read" and (lock is None or (_ts(e) or 0) <= lock)]
    rows = sum(_num(r.get("rows")) for r in reads)
    ids = list(dict.fromkeys(str(c) for a in alarms for c in _d(a).get("canary_ids") or []))
    export_id = next((_d(a)["export_id"] for a in alarms if _d(a).get("export_id")), None)
    export = next((_d(e) for e in events
                   if export_id and e.get("type") == "export" and _d(e).get("export_id") == export_id), None)
    peak = max((_num(_d(a).get("rate_per_min")) for a in alarms), default=0)
    tries = sorted(_ts(a) for a in alarms if _d(a).get("reason") in _LOGINS and _ts(a) is not None)
    fast_tries = len(tries) > 2 and (len(tries) - 1) * 60 >= LOGIN_PACE * (tries[-1] - tries[0])
    held = next((_d(e).get("what") for e in mine if e.get("type") == "lock"), None)
    session = first.get("session") or inc.get("session")
    return {
        "actor": first.get("actor") or inc.get("actor"),
        "ip": first.get("ip"),
        "session": session,
        # p- sessions are portal logins and contact from outside. there's no staff login to revoke
        "outside": str(session or "").startswith("p-"),
        "looks_like": "ai_agent" if "speed" in reasons or peak > MACHINE_PACE or fast_tries else "person",
        "session_locked": lock is not None or bool(inc.get("locked")),
        "locked_what": "address" if held == "ip" else "session",
        "rows_read": rows,
        "real_rows_exposed": max(0, rows - sum(_num(r.get("canaries")) for r in reads)),
        "peak_rows_per_minute": peak,
        "canaries_touched": len(ids),
        "canary_ids": ids[:5],
        "export_id": export_id,
        "export_real_rows": None if export is None else max(0, _num(export.get("rows")) - _num(export.get("canaries"))),
        "stolen_login_attempts": sum(_d(a).get("reason") in _LOGINS for a in alarms),
    }


def _drive_facts(f, alarms, mine, events):
    """Sentinel or Linux agent: the decoys, the process and its pace, what got locked and which real files it saw."""
    first = alarms[0] if alarms else {}
    reads = [e for e in mine if e.get("type") == "read"]
    decoys = list(dict.fromkeys(_d(a)["path"] for a in alarms
                                if _d(a).get("reason") == "decoy_open" and _d(a).get("path")))
    skip = {_spot(_d(a)["path"]).lower() for a in events
            if a.get("type") == "alarm" and _d(a).get("reason") == "decoy_open" and _d(a).get("path")}
    # bursts run under the server's own session and get matched on the incident
    bursts = [b for b in events if b.get("type") == "burst"]
    ours = [b for b in bursts if _d(b).get("incident") == f["incident"]]
    locked = {_plain(_spot(p)).lower() for b in bursts for p in _dyes(b)}
    # the plain file only exists until it's locked. opening it means the real data got out
    exposed, got = {}, {}
    for e in reads:
        spot = _spot(_d(e).get("path") or "")
        if spot.lower() in skip:
            continue
        if spot.lower().endswith(".dye") and _plain(spot).lower() in locked:
            got[_plain(spot)] = None
        elif spot.lower().endswith(_DATA):
            exposed[spot] = None
    dyes = list(dict.fromkeys(p for b in ours for p in _dyes(b)))
    lock = min((_ts(b) for b in ours if _ts(b) is not None), default=None)
    first_alarm = min((_ts(a) for a in alarms if _ts(a) is not None), default=None)
    peak = max([_num(_d(a).get("rate_per_min")) for a in alarms] + [_num(_d(e).get("files_per_min")) for e in reads],
               default=0)
    host = first.get("ip") or ""
    return {
        "kind": _DRIVE,
        "process": first.get("actor") or next((str(_d(e)["process"]) for e in reads if _d(e).get("process")), "unknown"),
        "pid": next((_d(e)["pid"] for e in reads if _d(e).get("pid") is not None), None),
        "host": None if host in _HERE else host,
        "looks_like": "ai_agent" if "speed" in f["alarm_reasons"] or peak > FILE_PACE else "person",
        "peak_files_per_minute": peak,
        "decoys_opened": len(decoys),
        "decoy_paths": [_home(p) for p in decoys[:5]],
        "files_opened": max(len({_d(e).get("path") for e in reads if _d(e).get("path")}), len(decoys)),
        "locked_files": [_plain(_spot(p)) for p in dyes],
        "locked_in": list(dict.fromkeys(_home(os.path.dirname(p)) for p in dyes)),
        # from the first alarm, like the dashboard
        "seconds_to_lock": None if None in (lock, first_alarm) else round(max(0.0, lock - first_alarm), 3),
        "real_files_exposed": list(exposed)[:5],
        "locked_copies_opened": [s for s in got if s not in exposed][:5],
    }


def _actions(f):
    """Same names as the respond buttons: lock, revoke, notify_customers or dismiss."""
    if _RANK.get(f["worst_severity"], 0) < _RANK["high"]:
        return ["dismiss"]
    if f.get("kind") == _DRIVE:
        # a file watcher has no login or export to revoke
        return ["lock"] + (["notify_customers"] if f["real_files_exposed"] else [])
    acts = []
    if not f["session_locked"] and (f["session"] or f["stolen_login_attempts"]):
        acts.append("lock")
    if f["export_id"] or (f["session"] and not f["outside"]):
        acts.append("revoke")
    if f["real_rows_exposed"] or f["export_real_rows"]:
        acts.append("notify_customers")
    return acts


def _plural(n, word):
    return f"{n:,} {word}" + ("" if n == 1 else "s")


def _join(items):
    items = [str(i) for i in items]
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else "".join(items)


def _title(f):
    if f.get("kind") == _DRIVE:
        by = ("an unknown process" if f["process"] in ("", "unknown") else f["process"]) + (
            f" on {f['host']}" if f["host"] else "")
        if f["decoys_opened"]:
            return f"Decoy {'file' if f['decoys_opened'] == 1 else 'files'} opened by {by}"
        return f"Files opened {'at machine speed ' if f['looks_like'] == 'ai_agent' else ''}by {by}"
    who, exp, reasons = f["actor"] or "an unknown user", f["export_id"], f["alarm_reasons"]
    if f["stolen_login_attempts"]:
        return f"Stolen logins from export {exp}" if exp else "Logins from a cracked copy"
    if "canary_contact" in reasons:
        return "A canary customer was contacted"
    if "speed" in reasons:
        return f"Bulk read by {who}"
    if "canary_touch" in reasons:
        return f"Canary touched by {who}"
    return f"Incident {f['incident']}"


def _next_step(f):
    if f.get("kind") == _DRIVE:
        proc = "the process" if f["process"] in ("", "unknown") else f["process"]
        say = {
            "lock": f"lock the account that runs {proc}" + (f" on {f['host']}" if f["host"] else ""),
            "notify_customers": f"tell the customers in {_join(f['real_files_exposed'])}",
            "dismiss": "mark it as a false alarm if this was normal work",
        }
        steps = [say[a] for a in f["recommended_actions"] if a in say]
        if f["locked_files"]:
            steps.append("put the locked files back with dyepack unlock once it's stopped")
        return "Next, " + _join(steps) + "."
    exp, who = f["export_id"], f["actor"] or "the account"
    say = {
        "lock": "block where these logins came from" if f["stolen_login_attempts"] else "lock the session",
        "revoke": f"revoke export {exp}" if exp else f"revoke {who}'s login",
        "notify_customers": f"tell the {f['export_real_rows'] or f['real_rows_exposed']:,.0f} affected customers",
        "dismiss": "mark it as a false alarm if this was normal support work",
    }
    steps = [say[a] for a in f["recommended_actions"]]
    if not steps:
        return "Next, find which copy of the customer list held that canary and who had access to it."
    return "Next, " + _join(steps) + "."


def _template(f):
    if f.get("kind") == _DRIVE:
        return _drive_template(f)
    actor, ids, n, exp = f["actor"], f["canary_ids"], f["canaries_touched"], f["export_id"]
    reasons, logins, rows, secs = f["alarm_reasons"], f["stolen_login_attempts"], f["rows_read"], f["seconds_to_first_alarm"]
    agent = f["looks_like"] == "ai_agent"
    who = (actor or "An unknown user") + (f" from {f['ip']}" if f["ip"] else "")
    lock = f" and the {f['locked_what']} was locked" if f["session_locked"] else ""
    s = []

    if logins:
        s.append(f"Someone tried {_plural(logins, 'login')} on the customer portal with usernames that don't "
                 f"belong to real customers, at a pace that looks like {MACHINE if agent else 'a person'}.")
    elif "canary_contact" in reasons:
        s.append("Someone outside the company emailed or called a canary customer, "
                 "which looks like a person working from a leaked list.")
    elif rows:
        rate = f["peak_rows_per_minute"]
        peak = f" (peak {rate:,.0f} rows a minute)" if rate else ""
        s.append(f"{who} read {rows:,.0f} customer rows at {'machine speed' if agent else 'a human pace'}{peak}, "
                 f"which looks like {f'{MACHINE} rather than a person' if agent else f'a person rather than {MACHINE}'}.")
    else:
        s.append(f"{who} set off an alarm.")

    if secs is None:
        s.append(f"The alarm fired{lock}.")
    elif secs < 0.0005:
        s.append(f"The alarm fired on the very first request{lock}.")
    else:
        s.append(f"The first alarm fired {_dur(secs)} after the activity started{lock}.")

    if n:
        more = " and more" if n > len(ids) else ""
        verb = "used the logins of" if logins else "reached" if "canary_contact" in reasons else "touched"
        s.append(f"It {verb} {_plural(n, 'canary customer')} ({', '.join(ids)}{more}).")
    elif "unknown_account_login" in reasons:
        s.append("Those usernames don't exist anywhere, which means they came from a copy opened with a wrong password.")
    elif "speed" in reasons:
        s.append("The read speed alone gave it away, since no canary customers were touched.")
    else:
        s.append("No canary customers were touched.")

    if exp:
        s.append(f"Those canaries were only ever planted in export {exp}, which makes it the copy that leaked." if n
                 else f"The alarm points to export {exp} as the copy that leaked.")

    if exp and f["export_real_rows"] is not None:
        s.append(f"Export {exp} holds {f['export_real_rows']:,.0f} real customer rows "
                 "and all of them should be treated as exposed.")
    elif rows:
        done = "exposed" if f["recommended_actions"] != ["dismiss"] else "read"
        when = "before the lock" if lock else "so far"
        s.append(f"About {f['real_rows_exposed']:,.0f} real customer rows were {done} {when}.")
    elif logins:
        s.append("None of the flagged usernames belong to real customers.")
    else:
        s.append("No customer rows were read in this incident.")

    s.append(_next_step(f))
    return " ".join(s)


def _drive_template(f):
    agent, host, n, peak = f["looks_like"] == "ai_agent", f["host"], f["decoys_opened"], f["peak_files_per_minute"]
    opened, secs, wait = f["files_opened"], f["seconds_to_first_alarm"], f["seconds_to_lock"]
    exposed, got, locked = f["real_files_exposed"], f["locked_copies_opened"], f["locked_files"]
    who = "An unknown process" if f["process"] in ("", "unknown") else f"A process called {f['process']}"
    who += "" if f["pid"] is None else f" (pid {f['pid']})"
    where = f"on {host or 'the company drive'}"
    speed = f"at {'machine speed' if agent else 'a human pace'}" + (f" (peak {peak:,.0f} files a minute)" if peak else "")
    looks = f"{MACHINE} rather than a person" if agent else f"a person rather than {MACHINE}"
    s = []

    if n:
        s.append(f"{who} opened the decoy file {f['decoy_paths'][0]} {where} while reading files {speed}, "
                 f"which looks like {looks}.")
    elif opened:
        s.append(f"{who} opened {_plural(opened, 'file')} {where} {speed}, which looks like {looks}.")
    else:
        s.append(f"{who} set off a file alarm {where} {speed}, which looks like {looks}.")

    if secs is None:
        s.append("The alarm fired.")
    elif secs < 0.0005 and n:
        s.append("The alarm fired the moment it opened the decoy.")
    else:
        s.append(f"The first alarm fired {_dur(secs)} after it started opening files.")

    if locked:
        when = "" if wait is None else " " + _later(wait)
        if len(locked) == 1:
            s.append(f"Dyepack locked {locked[0]} in place{when} and it now sits there as "
                     f"{os.path.basename(locked[0])}.dye.")
        else:
            shown = locked if len(locked) < 5 else locked[:3] + [f"{len(locked) - 3} more files"]
            s.append(f"Dyepack locked {_join(shown)} in place{when} and they now sit there as .dye files.")

    if host:
        s.append(f"Check what else it read on {host} because only the decoys are watched there.")
    elif n == 1 and opened <= 1:
        s.append("The decoy was the only file it opened.")
    else:
        s.append(f"It opened {_plural(opened, 'file')} in all and {n} of them {'was a decoy' if n == 1 else 'were decoys'}."
                 if n else "None of the files were decoys.")
        if exposed:
            s.append(f"Treat {_join(exposed)} as exposed because "
                     f"{'it was' if len(exposed) == 1 else 'they were'} opened while still readable.")
        elif got:
            s.append(f"It only got {_join(got)} as "
                     f"{'a locked .dye file, which gives' if len(got) == 1 else 'locked .dye files, which give'} "
                     "believable fakes for any wrong password.")
        elif locked:
            s.append("None of the real customer files were exposed because they were locked first.")
        else:
            s.append("No real customer file has been exposed so far.")

    s.append(f["next_step"])
    return " ".join(s)


def _tidy(text):
    text = re.sub(r"\s*\N{EM DASH}\s*", ", ", text)
    text = re.sub(r"\s*\N{EN DASH}\s*", " to ", text)
    text = " ".join(text.replace("**", "").split())
    cut = re.match(r".*[.!?]", text, re.S)  # drop a sentence the token limit chopped off
    return cut.group(0) if cut else text


def write_report(incident, events, client=None):
    """Plain English report for one incident.

    Returns {"title", "text", "source", "looks_like", "actions"}. looks_like is "ai_agent" or "person"
    and actions lists the respond buttons worth pressing. Both come from the events, never the model.
    """
    f = _facts(incident, events)
    report = {"title": _title(f), "text": _template(f), "source": "template",
              "looks_like": f["looks_like"], "actions": f["recommended_actions"]}
    if client is None:
        return report
    try:
        text = _tidy(client.chat([
            {"role": "system", "content": REPORT_PROMPT + (DRIVE_PROMPT if f.get("kind") == _DRIVE else "")},
            {"role": "user", "content": "Facts: " + json.dumps(f)},
        ]))
    except Exception:
        return report
    if len(text) < 40:
        return report
    return {**report, "text": text, "source": "databricks"}


def _parse_pick(text, n):
    pick, reason = None, ""
    found = re.search(r"\{.*\}", text, re.S)
    if found:
        try:
            got = json.loads(found.group(0))
            pick, reason = int(got["pick"]), str(got.get("reason") or "")
        except (ValueError, TypeError, KeyError, AttributeError):
            pass
    if pick is None:
        found = re.search(r"\blist\s*#?\s*(\d+)", text, re.I)
        pick = int(found.group(1)) if found else None
    if pick is None or not 1 <= pick <= n:
        raise ValueError("no usable pick")
    return pick - 1, _tidy(reason) or "No reason given."


def can_ai_tell(candidate_lists, client=None):
    """Show the model 5 rows of each list and ask which one is real: {"pick", "reason", "source"}.

    pick is an index into candidate_lists. It's None when there's no usable answer.
    """
    lists = [list(rows or [])[:5] for rows in candidate_lists or []]
    if client is None or len(lists) < 2:
        return {"pick": None, "reason": "No model to ask.", "source": "template"}
    shown = ["Columns: " + " | ".join(CUSTOMER_FIELDS)]
    for i, rows in enumerate(lists, 1):
        shown.append(f"\nList {i}:")
        shown += [" | ".join(str(r.get(k, "")) for k in CUSTOMER_FIELDS) for r in rows]
    try:
        text = client.chat([
            {"role": "system", "content": PICK_PROMPT},
            {"role": "user", "content": "\n".join(shown)},
        ])
        pick, reason = _parse_pick(text, len(lists))
    except Exception:
        return {"pick": None, "reason": "The model didn't give a usable answer.", "source": "template"}
    return {"pick": pick, "reason": reason, "source": "databricks"}


def _workdays(day, n):
    """day plus n business days. Only weekends get skipped. A holiday makes it come out early, never late."""
    while n > 0:
        day += timedelta(days=1)
        if day.weekday() < 5:
            n -= 1
    return day


def _date(d):
    return f"{d:%a %b} {d.day}, {d.year}"


def notice_checklist(incident, detail):
    """Plain lines for telling people about a breach, for the notify_customers step.

    detail can carry customers, plaintext_rows, locked_copies and found_at (epoch seconds, when the
    breach was found). The clocks are the FCC rule for carriers (47 CFR 64.2011) and Wisconsin's
    notice law (Wis. Stat. 134.98). Lab guidance, not legal advice.
    """
    iid = (incident.get("id") or incident.get("incident")) if isinstance(incident, dict) else incident
    d = detail if isinstance(detail, dict) else {}
    found = d.get("found_at")
    if isinstance(found, datetime):
        day = found.date()
    elif isinstance(found, date):
        day = found
    elif _num(found):
        day = datetime.fromtimestamp(found).date()
    else:
        day = date.today()
    plain, copies = d.get("plaintext_rows"), _num(d.get("locked_copies"))
    count = _num(d.get("customers")) or _num(plain)
    parts = [f"{_num(plain):,.0f} rows in plain text"] if plain is not None else []
    if copies:
        parts.append(f"{copies:,.0f} locked {'copy' if copies == 1 else 'copies'}")
    lines = [
        NOTICE_HEAD,
        f"Who is affected{f' by {iid}' if iid else ''}: {_plural(int(count), 'customer')}"
        + (f" ({', '.join(parts)})" if parts else ""),
        f"FCC, FBI and Secret Service: report by {_date(_workdays(day, 7))} (7 business days, 47 CFR 64.2011)",
        f"Customers in Wisconsin: by {_date(day + timedelta(days=45))} (45 days, Wis. Stat. 134.98)",
    ]
    if plain is not None and _num(plain) == 0:
        lines.append("Locked copy only: likely exempt as encrypted data, check with counsel")
    lines.append("A notice must say what happened, what data was involved, what we did, "
                 "what they can do and who to contact")
    return lines
