"""Tiny REST client for Databricks: SQL through a warehouse and chat with a served model.

Settings come from .env (see .env.example). The token only ever goes in the Authorization header.
"""

import json
import math
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .schema import CUSTOMER_FIELDS

_TYPES = {"monthly_bill": "DOUBLE", "since_year": "INT"}
CUSTOMER_COLS = ", ".join(f"{f} {_TYPES.get(f, 'STRING')}" for f in CUSTOMER_FIELDS)

TABLES = {
    "customers": CUSTOMER_COLS,
    "customers_clean": CUSTOMER_COLS,
    "alarms": "ts TIMESTAMP, incident STRING, reason STRING, severity STRING, session STRING, actor STRING, "
              "ip STRING, canaries INT, canary_ids STRING, export_id STRING, rate_per_min DOUBLE, detail STRING",
    "reports": "ts TIMESTAMP, incident STRING, title STRING, text STRING, source STRING",
    "exports": "ts TIMESTAMP, export_id STRING, session STRING, actor STRING, ip STRING, row_count INT, canaries INT",
}


class DatabricksError(Exception):
    def __init__(self, message, status=None, code=""):
        super().__init__(message)
        self.status = status  # http status when there is one
        self.code = code      # short type like PERMISSION_DENIED or NETWORK, safe to print


def read_env(path=".env"):
    """KEY=VALUE lines from a .env file. Never print what comes back."""
    out = {}
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip("\"'")
    return out


def _ident(name):
    return "`" + str(name).replace("`", "``") + "`"


def _lit(v):
    """Python value to a SQL literal."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v) if math.isfinite(v) else "NULL"
    if isinstance(v, datetime):
        return f"timestamp_seconds({v.timestamp()!r})"
    if not isinstance(v, str):
        v = json.dumps(v, default=str)
    # backslash escapes are the Databricks SQL default. $ goes in as $ so ${...} never gets substituted
    v = v.replace("\\", "\\\\").replace("'", "\\'").replace("$", "\\u0024")
    return f"'{v}'"


def _when(ts):
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(timezone.utc)


def _state(res):
    return (res.get("status") or {}).get("state")


class Client:
    def __init__(self, host, token, warehouse_id="", model="", catalog="workspace", schema="dyepack", timeout=60):
        url = urllib.parse.urlsplit(host.strip() if "://" in host else "https://" + host.strip())
        self.host = f"{url.scheme}://{url.netloc}"  # drops a pasted path or ?o=
        self._token = token
        self.warehouse_id = warehouse_id.strip().rstrip("/").rsplit("/", 1)[-1]  # the http path works too
        self.model = model.strip()
        self.catalog = catalog
        self.schema = schema
        self.timeout = timeout
        self._ready = False
        self._lock = threading.Lock()

    def __repr__(self):
        return f"Client({self.host!r})"

    @classmethod
    def from_env(cls, path=".env"):
        """None when the host or token is missing. Callers then fall back quietly."""
        env = read_env(path)
        if not env.get("DATABRICKS_HOST") or not env.get("DATABRICKS_TOKEN"):
            return None
        return cls(env["DATABRICKS_HOST"], env["DATABRICKS_TOKEN"],
                   env.get("DATABRICKS_WAREHOUSE_ID", ""), env.get("DATABRICKS_MODEL", ""),
                   env.get("DATABRICKS_CATALOG") or "workspace", env.get("DATABRICKS_SCHEMA") or "dyepack")

    def _scrub(self, text):
        return str(text).replace(self._token, "***")

    def _call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.host + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self._token)
        req.add_header("Content-Type", "application/json")
        # errors get rebuilt from scratch so no header or token can ride along
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read() or b"{}")
            except Exception:
                body = {}
            body = body if isinstance(body, dict) else {}
            code = self._scrub(body.get("error_code") or "")
            why = self._scrub(body.get("message") or e.reason)[:300]
            raise DatabricksError(f"HTTP {e.code} {code} from {path}: {why}", e.code, code) from None
        except OSError as e:
            why = self._scrub(getattr(e, "reason", None) or type(e).__name__)
            raise DatabricksError(f"can't reach {self.host}: {why}", code="NETWORK") from None
        except ValueError:
            raise DatabricksError(f"reply from {path} wasn't JSON", code="BAD_REPLY") from None

    def sql(self, statement, timeout=300):
        """Run one statement on the warehouse and return its rows (lists of strings)."""
        if not self.warehouse_id:
            raise DatabricksError("DATABRICKS_WAREHOUSE_ID isn't set", code="NOT_SET")
        res = self._call("POST", "/api/2.0/sql/statements", {
            "warehouse_id": self.warehouse_id,
            "statement": statement,
            "wait_timeout": "30s",
            "on_wait_timeout": "CONTINUE",
            "disposition": "INLINE",
            "format": "JSON_ARRAY",
        })
        sid, give_up = res.get("statement_id"), time.monotonic() + timeout
        while _state(res) in ("PENDING", "RUNNING"):
            if time.monotonic() >= give_up:
                try:
                    self._call("POST", f"/api/2.0/sql/statements/{sid}/cancel", {})
                except DatabricksError:
                    pass
                raise DatabricksError(f"statement still running after {timeout} s", code="TIMEOUT")
            time.sleep(1)
            res = self._call("GET", f"/api/2.0/sql/statements/{sid}")
        if _state(res) != "SUCCEEDED":
            err = (res.get("status") or {}).get("error") or {}
            code = self._scrub(err.get("error_code") or _state(res) or "")
            why = self._scrub(err.get("message") or "")[:500]
            raise DatabricksError(f"statement {_state(res)}: {code} {why}".strip(), code=code)
        rows, chunk = [], res.get("result") or {}
        while True:
            rows += chunk.get("data_array") or []
            if not chunk.get("next_chunk_internal_link"):
                return rows
            chunk = self._call("GET", chunk["next_chunk_internal_link"])

    def chat(self, messages, max_tokens=400, temperature=0.2):
        """Ask the served chat model and return its text."""
        if not self.model:
            raise DatabricksError("DATABRICKS_MODEL isn't set", code="NOT_SET")
        path = f"/serving-endpoints/{urllib.parse.quote(self.model, safe='')}/invocations"
        res = self._call("POST", path, {"messages": messages, "max_tokens": max_tokens, "temperature": temperature})
        try:
            content = res["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise DatabricksError("chat reply had no message", code="BAD_REPLY") from None
        if isinstance(content, list):  # reasoning models send blocks, keep the text ones
            content = "".join(b.get("text") or "" for b in content if isinstance(b, dict) and b.get("type") == "text")
        return content.strip() if isinstance(content, str) else ""

    def table(self, name):
        return f"{_ident(self.catalog)}.{_ident(self.schema)}.{_ident(name)}"

    def ensure_tables(self):
        self.sql(f"CREATE SCHEMA IF NOT EXISTS {_ident(self.catalog)}.{_ident(self.schema)}")
        for name, cols in TABLES.items():
            self.sql(f"CREATE TABLE IF NOT EXISTS {self.table(name)} ({cols})")
        self._ready = True

    def push_rows(self, table, rows, batch=500):
        """Insert dict rows (all with the same keys) in batches. Makes the tables first if needed."""
        rows = list(rows)
        if not rows:
            return 0
        with self._lock:
            if not self._ready:
                self.ensure_tables()
        cols = list(rows[0])
        head = f"INSERT INTO {self.table(table)} ({', '.join(map(_ident, cols))}) VALUES "
        for i in range(0, len(rows), batch):
            values = ", ".join("(" + ", ".join(_lit(r.get(c)) for c in cols) + ")" for r in rows[i:i + batch])
            self.sql(head + values)
        return len(rows)

    def push_event(self, event):
        """Alarm, report and export events go to their tables. Returns the rows written."""
        kind, d = event.get("type"), event.get("detail") or {}
        who = {k: event.get(k) for k in ("session", "actor", "ip")}
        ts = _when(event.get("ts"))
        if kind == "alarm":
            ids = [str(c) for c in d.get("canary_ids") or []]
            row = {"ts": ts, "incident": d.get("incident"), "reason": d.get("reason"),
                   "severity": event.get("severity"), **who, "canaries": len(ids),
                   "canary_ids": ",".join(ids), "export_id": d.get("export_id"),
                   "rate_per_min": d.get("rate_per_min"), "detail": json.dumps(d, default=str)}
        elif kind == "report":
            row = {"ts": ts, **{k: d.get(k) for k in ("incident", "title", "text", "source")}}
        elif kind == "export":
            row = {"ts": ts, "export_id": d.get("export_id"), **who,
                   "row_count": d.get("rows"), "canaries": d.get("canaries")}
        else:
            return 0
        return self.push_rows(kind + "s", [row])


def check(path=".env"):
    """Live check: one SELECT 1 and one short chat. Prints only ok or the error type."""
    client = Client.from_env(path)
    if client is None:
        print("DATABRICKS_HOST or DATABRICKS_TOKEN is missing from .env")
        return 1
    tests = (
        ("SELECT 1", lambda: client.sql("SELECT 1") == [["1"]]),
        ("chat", lambda: bool(client.chat([{"role": "user", "content": "Reply with the single word ok."}]))),
    )
    failed = 0
    for name, test in tests:
        try:
            result = "ok" if test() else "failed (unexpected reply)"
        except DatabricksError as e:
            kind = [f"HTTP {e.status}" if e.status else "", e.code or "error"]
            result = "failed (" + " ".join(k for k in kind if k) + ")"
        except Exception as e:
            result = f"failed ({type(e).__name__})"
        failed += result != "ok"
        print(f"{name}: {result}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(check())
