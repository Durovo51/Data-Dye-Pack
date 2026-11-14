"""Shared shapes. Every part of dyepack builds against these, so change them only on purpose."""

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("DYEPACK_DATA", "data"))
DB_PATH = DATA_DIR / "lakeview.db"         # lab customer table (sqlite)
WATCH_PATH = DATA_DIR / "watch_list.json"  # canary list, kept apart from the table
PROFILE_PATH = DATA_DIR / "profile.json"   # value counts per part
EXPORTS_DIR = DATA_DIR / "exports"         # honey locked files
VAULT_DIR = DATA_DIR / "vault"             # real files sealed away after a burst
DRIVE_ROOT = Path(os.environ.get("DYEPACK_DRIVE", Path.home() / "LakeviewFiber"))  # lab company drive

# sqlite: table "customers" holds real rows plus canaries,
# view "customers_clean" is the same table minus the watch list
CUSTOMER_FIELDS = (
    "account_no",    # "LV" + 8 digits
    "first_name",
    "last_name",
    "street",        # "4120 Willow Ln"
    "city",
    "zip",
    "phone",         # "608-274-1193"
    "email",
    "plan",
    "monthly_bill",  # dollars, 2 decimals
    "since_year",    # int
    "portal_user",   # customer login name
)

# profile.json looks like {"rows": 50000, "parts": {"city": {"Madison": 12034, ...}, ...}}
# it only counts the "cat" parts from vocab.PARTS, never whole rows

# watch_list.json looks like
# {"canaries": [{"canary_id": "c-001", "account_no": "LV...", "portal_user": "...",
#   "email": "...", "phone": "...", "batch": "table" or an export id, "planted_at": 1763150000.0}]}

# every event on the /events stream is one JSON object:
# {"ts": 1763150000.12, "type": "alarm", "session": "s-3", "actor": "rep.jordan",
#  "ip": "10.0.0.7", "severity": "high", "detail": {...}}
EVENT_TYPES = ("tick", "read", "export", "login", "alarm", "lock", "report", "drill",
               "burst", "notify", "action")
SEVERITIES = ("info", "low", "high", "critical")

# detail shapes by type
#   tick:   {"reads_per_min": 3100, "sessions": 4}               about once a second
#   read:   {"rows": 50, "canaries": 1, "path": "/api/customers"}
#   export: {"export_id": "exp-2", "rows": 50000, "canaries": 200}
#   login:  {"user": "jsmith07", "ok": false, "where": "portal" or "staff"}
#   alarm:  {"reason": one of ALARM_REASONS, "incident": "inc-1", "canary_ids": [...],
#            "export_id": None or "exp-2", "rate_per_min": 3100, "path": "..." for decoy_open}
#   lock:   {"incident": "inc-1", "what": "session"}
#   report: {"incident": "inc-1", "title": "...", "text": "...", "source": "databricks" or "template",
#            "looks_like": "ai_agent" or "person", "actions": ["lock", "revoke", "notify_customers", "dismiss"]}
#   drill:  {"phase": "normal", "heist-1", "heist-2", "heist-3" or "agent", "status": "start" or "end", "score": {...}}
#   read from the file sentinel: {"path": "...", "process": "node", "pid": 4242, "files_per_min": 180}
#   burst:  {"incident": "inc-2", "folder": "...", "files": ["customers.csv"], "vault": "..."}
#   notify: {"incident": "inc-2", "channel": "push", "sms", "email" or "discord",
#            "status": "sent", "simulated" or "failed", "summary": "the exact text sent"}
# drill score keys: normal_alarms, detect_seconds, rows_exposed, guesses_cracked,
#   ai_pick {"pick", "real", "lists"} with pick and real counted from 0
# /events sends plain "data: {json}" lines, no "event:" names
#   action: {"incident": "inc-2", "action": "lock", "revoke", "notify_customers" or "dismiss"}
ALARM_REASONS = (
    "canary_touch",           # a returned row was a canary
    "speed",                  # reading at machine speed (rows from the API or files from the sentinel)
    "canary_login",           # someone tried to log in as a canary
    "unknown_account_login",  # login for a user that doesn't exist (from a cracked fake list)
    "canary_contact",         # email or call to a canary from outside
    "decoy_open",             # a decoy file on the drive was opened
)

# lab HTTP routes (server.py). staff calls send header "X-Session: <id>"
#   POST /api/login                  {"user", "password"} -> {"session"}      support reps
#   GET  /api/customers?q=&limit=    search
#   GET  /api/customers/<account_no> one customer
#   GET  /api/customers?page=&size=  list pages (bulk). size max 100 for staff, 1,000 for registered jobs
#   POST /api/exports                {"password"} -> {"export_id"}   honey locked, own canaries
#   GET  /api/exports/<export_id>    download the locked file
#   POST /api/permits                {"who", "table", "minutes"}
#   POST /portal/login               {"user", "password"}   customer login page
#   POST /lab/contact                {"to", "channel"}       stand in for email or phone
#   POST /lab/drill                  {"phase", "status", "score"}   drill posts its progress
#   POST /lab/fs-event               {"ts", "pid", "process", "signing_id", "path", "op"}   from the sentinel
#   GET  /api/alert-routes           -> {"critical": ["push", "sms"], "high": ["push"], "low": []}
#   POST /api/alert-routes           same shape, saves it
#   POST /api/respond                {"incident", "action"}
#   GET  /events                     server sent events, one JSON event per message
#   GET  /                           mine map (files in dyepack/web)
DEFAULT_PORT = 8750

# machine speed lines, shared by the tripwire, the sentinel and the map
SPEED_ROWS_PER_MIN = 600   # customer rows read by one session
SPEED_FILES_PER_MIN = 30   # files opened under the drive by one process
