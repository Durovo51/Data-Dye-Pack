"""Bridge for minefield, the Linux auditd decoy agent. Its hits come in at POST /api/events and
leave here as our fs events, so the server treats them like the sentinel's.

A hit looks like {"event_id", "server_id", "timestamp", "file", "username", "login_username",
"uid", "euid", "auid", "process", "process_name", "pid", "ppid", "access_type", "success",
"source": "auditd", "audit_id", "session_id"}. minefield only watches decoy files, so every
hit is a decoy open.
"""

import threading
import time
from collections import OrderedDict
from datetime import datetime

KEEP = 10_000  # event ids remembered for repeats
OPS = ("read", "write", "rename", "delete")

_ids = OrderedDict()
_mutex = threading.Lock()


def to_fs_event(payload):
    """One minefield hit -> {"ts", "pid", "process", "signing_id", "path", "op", "server_id", "username"}.
    Raises ValueError when it has no file path."""
    if not isinstance(payload, dict):
        raise ValueError("a hit has to be a JSON object")
    path = payload.get("file")
    if not isinstance(path, str) or not path:
        raise ValueError("a hit needs a file path")
    op = str(payload.get("access_type") or "read").lower()
    return {
        "ts": _ts(payload.get("timestamp")),
        "pid": _int(payload.get("pid")),
        "process": str(payload.get("process") or payload.get("process_name") or "unknown"),
        "signing_id": None,
        "path": path,
        "op": op if op in OPS else "read",
        "server_id": str(payload.get("server_id") or "unknown"),
        "username": str(payload.get("login_username") or payload.get("username") or "unknown"),
    }


def seen(event_id):
    """True when this event id already came in. minefield retries with the same Idempotency-Key."""
    if not event_id:
        return False
    key = str(event_id)
    with _mutex:
        if key in _ids:
            _ids.move_to_end(key)
            return True
        _ids[key] = None
        while len(_ids) > KEEP:
            _ids.popitem(last=False)
        return False


def accept(body, idempotency_key=None):
    """A POST body (one hit or a list) -> fs events, repeats and broken hits dropped.
    The header key covers the whole request, each event_id covers one hit."""
    if seen(idempotency_key):
        return []
    hits = body if isinstance(body, list) else [body]
    out = []
    for hit in hits:
        eid = hit.get("event_id") if isinstance(hit, dict) else None
        # the agent often sends its event_id as the key, that one is already marked
        if eid and str(eid) != str(idempotency_key) and seen(eid):
            continue
        try:
            out.append(to_fs_event(hit))
        except ValueError:
            continue
    return out


def decoy_entry(event):
    """Watch list decoy entry for a remote file, so tripwire.decoy_for matches it."""
    return {"decoy_id": f"m-{event['server_id']}", "path": event["path"], "kind": "remote",
            "rows": 0, "batch": "minefield", "planted_at": event["ts"]}


def _ts(value):
    # epoch seconds, epoch millis or ISO 8601, anything else is now
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) / 1000 if value > 1e11 else float(value)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            return _ts(float(text))
        except ValueError:
            pass
        try:
            when = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return time.time()
        return when.timestamp()
    return time.time()


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
