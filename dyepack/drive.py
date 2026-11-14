"""Lakeview Fiber's company drive for the demo: real customer files, decoys that no real
workflow opens and a honey locked backup. It lives outside the repo, so it never gets committed.
"""

import csv
import json
import os
import random
import secrets
import sqlite3
import sys
import time
from pathlib import Path

from . import canary, honey, lab, schema
from .profile import load_profile

REAL_ROWS = 2000  # small, so a burst seals it in well under a second
INVOICES = 300
# decoys: path on the drive -> (kind, canary rows). each one sorts first in its folder,
# so whoever lists a folder and reads from the top opens the decoy before the real file
DECOYS = {
    "customers/all_customers_full_export_2026.csv": ("export", 2500),
    "backups/all_customers_backup_unencrypted.csv": ("backup", 800),
    "billing/all_accounts_2026_with_payment_info.json": ("payments", 1000),
    "config/.env.production": ("keys", 0),
}
# file times (local). decoys look newest, so tools that sort by date list them first too
TIMES = {
    "billing/invoices_2026_10.json": (2026, 11, 1, 6, 30),
    "customers/customers.csv": (2026, 11, 9, 8, 12),
    "support/notes.md": (2026, 11, 12, 16, 40),
    "backups/nightly_2026_11_13.dye": (2026, 11, 13, 2, 0),
    "config/.env.production": (2026, 11, 13, 17, 30),
    "backups/all_customers_backup_unencrypted.csv": (2026, 11, 13, 18, 2),
    "billing/all_accounts_2026_with_payment_info.json": (2026, 11, 13, 18, 6),
    "customers/all_customers_full_export_2026.csv": (2026, 11, 13, 18, 10),
}
NOTES = """# Support desk notes

Shared notes for the Lakeview Fiber support desk. Ask in #support before you change anything here.

## Where things live
- Customer list for lookups: customers/customers.csv, refreshed every Monday.
- Full export with every account: customers/all_customers_full_export_2026.csv. Don't email it around.
- October billing: billing/invoices_2026_10.json.
- Payment details for every account: billing/all_accounts_2026_with_payment_info.json (finance only).
- Nightly backups are the .dye files in backups/. IT has the password.
- IT left an unencrypted copy of a backup in backups/ until the storage move is done.
- Production keys live in config/.env.production (ops only).

## Common tickets
- Slow speeds in Verona or Mount Horeb: run a line test first, then book a tech visit.
- Wi-Fi extender returns are free within 30 days, the refund shows on the next bill.
- Static IP requests go to the network team.
- Customers who move keep their account number. Update the address and the plan.
"""


def build_drive(root=None, seed=7, password=None):
    """Writes the drive and puts its decoys and their canaries on the watch list (batch "drive")."""
    root = Path(root or schema.DRIVE_ROOT).expanduser().resolve()
    rows, watch, profile = _lab()
    rng = random.Random(seed)
    real = rng.sample(rows, min(REAL_ROWS, len(rows)))
    password = password or vault_password()

    # fresh canaries for the decoys, numbered after every canary already on the list.
    # a rebuild replaces the old drive's entries
    keep = [c for c in watch.get("canaries", []) if c.get("batch") != "drive"]
    known = rows + keep
    fakes, entries = canary.make_canaries(
        profile, sum(n for _, n in DECOYS.values()),
        [r["account_no"] for r in known], [r["portal_user"] for r in known], "drive",
        taken_contacts=[r[f] for r in known for f in ("email", "phone")],
    )
    first = 1 + max((_number(c["canary_id"]) for c in keep), default=0)
    for i, e in enumerate(entries):
        e["canary_id"] = f"c-{first + i:03d}"

    for folder in ("customers", "billing", "support", "backups", "config"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    write_csv(root / "customers/customers.csv", real)
    invoices = _invoices(rng.sample(real, min(INVOICES, len(real))), rng)
    (root / "billing/invoices_2026_10.json").write_text(json.dumps(invoices, indent=2) + "\n", encoding="utf-8")
    (root / "support/notes.md").write_text(NOTES, encoding="utf-8")
    backup = rng.sample(real, len(real))  # the lock keeps row order, so shuffle first
    (root / "backups/nightly_2026_11_13.dye").write_bytes(
        honey.lock(backup, password or secrets.token_urlsafe(18), profile))

    decoys, at, now = [], 0, time.time()
    for i, (rel, (kind, n)) in enumerate(DECOYS.items(), 1):
        if kind == "keys":
            (root / rel).write_text(_fake_keys(), encoding="utf-8")
        elif rel.endswith(".json"):
            doc = _payments(fakes[at:at + n], rng)
            (root / rel).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        else:
            write_csv(root / rel, fakes[at:at + n])
        at += n
        decoys.append({"decoy_id": f"d-{i}", "path": str(root / rel), "kind": kind, "rows": n,
                       "batch": "drive", "planted_at": now})
    for rel, t in TIMES.items():
        stamp = time.mktime((*t, 0, 0, 0, -1))
        os.utime(root / rel, (stamp, stamp))

    old = {d["path"] for d in watch.get("decoys", [])} - {d["path"] for d in decoys}
    # the real files just came back fresh from the lab, so a burst's .dye of them would only make
    # the next burst skip them. any other locked file keeps its .dye
    fresh = {f"{root / rel}.dye" for rel in ("customers/customers.csv", "billing/invoices_2026_10.json")}
    watch["canaries"] = keep + entries
    watch["decoys"] = decoys
    watch["locked"] = [r for r in watch.get("locked", []) if r["dye"] not in fresh]
    lab.write_private(schema.WATCH_PATH, watch)
    # decoys from an older layout would sit there unwatched, full of canaries nobody checks
    for p in map(Path, (*old, *fresh)):
        if root in p.parents:
            p.unlink(missing_ok=True)
    table = {c["account_no"] for c in keep if c.get("batch") == "table"}
    return {"root": str(root), "rows": len(real), "invoices": len(invoices["invoices"]),
            "table_canaries": sum(r["account_no"] in table for r in real), "decoys": decoys,
            "canaries": len(entries), "own_password": bool(password)}


def write_csv(path, rows):
    """Customer rows to CSV, the way every drive file is written."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(schema.CUSTOMER_FIELDS)
        w.writerows([f"{r[k]:.2f}" if k == "monthly_bill" else r[k] for k in schema.CUSTOMER_FIELDS]
                    for r in rows)


def load_decoys():
    """Decoy entries from the watch list: {"decoy_id", "path", "kind", "rows", "batch", "planted_at"}."""
    try:
        return json.loads(schema.WATCH_PATH.read_text()).get("decoys", [])
    except (OSError, ValueError):
        return []


def decoy_for(path, decoys=None):
    """The decoy entry when path is a decoy, else None. Takes paths straight from the sentinel."""
    key = _key(path)
    return next((d for d in (load_decoys() if decoys is None else decoys) if _key(d["path"]) == key), None)


def vault_password(env_file=".env"):
    """DYEPACK_VAULT_PASSWORD from the environment or .env. Never print it."""
    pw = os.environ.get("DYEPACK_VAULT_PASSWORD")
    if pw:
        return pw
    try:
        lines = Path(env_file).read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        key, _, value = line.strip().partition("=")
        if key.strip() == "DYEPACK_VAULT_PASSWORD":
            return value.strip().strip("\"'") or None
    return None


def cmd_drive(args):
    try:
        out = build_drive(seed=getattr(args, "seed", 7))
    except (RuntimeError, OSError, ValueError, sqlite3.Error) as e:
        print(e, file=sys.stderr)
        return 1
    lock = "the vault password" if out["own_password"] else \
        "a throwaway password (set DYEPACK_VAULT_PASSWORD in .env to use yours)"
    w = max(len(rel) for rel in DECOYS)
    print(f"Lakeview Fiber's drive is ready in {out['root']}")
    print(f"  {'customers/customers.csv':<{w}} {out['rows']:>6,} customers "
          f"({out['table_canaries']} table canaries ride along)")
    print(f"  {'billing/invoices_2026_10.json':<{w}} {out['invoices']:>6,} invoices")
    print("  support/notes.md")
    print(f"  {'backups/nightly_2026_11_13.dye':<{w}} honey locked with {lock}")
    print("decoys (no real workflow opens them, each sorts first in its folder)")
    for d in out["decoys"]:
        what = f"{d['rows']:>6,} canaries" if d["rows"] else "  fake keys"
        print(f"  {os.path.relpath(d['path'], out['root']):<{w}} {what}")
    print(f"watch list: {len(out['decoys'])} decoys and {out['canaries']:,} drive canaries in {schema.WATCH_PATH}")
    return 0


def _lab():
    if not (schema.DB_PATH.exists() and schema.WATCH_PATH.exists() and schema.PROFILE_PATH.exists()):
        raise RuntimeError("no seeded lab yet, run dyepack lab and dyepack seed first")
    con = sqlite3.connect(schema.DB_PATH)
    try:
        cols = ", ".join(schema.CUSTOMER_FIELDS)
        found = con.execute(f"SELECT {cols} FROM customers ORDER BY rowid")
        rows = [dict(zip(schema.CUSTOMER_FIELDS, t)) for t in found]
    finally:
        con.close()
    return rows, json.loads(schema.WATCH_PATH.read_text()), load_profile()


def _number(canary_id):
    try:
        return int(canary_id.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return 0


def _invoices(rows, rng):
    status = ("paid",) * 16 + ("due",) * 3 + ("late",)
    return {"company": "Lakeview Fiber", "period": "2026-10", "invoices": [
        {"invoice_no": f"INV-2610-{i:05d}", **{k: r[k] for k in schema.CUSTOMER_FIELDS},
         "status": rng.choice(status)}
        for i, r in enumerate(rows, 1)
    ]}


def _payments(rows, rng):
    # how each account pays, never a card or bank number
    methods = ("card on file",) * 5 + ("autopay from bank",) * 3 + ("paper check",)
    return {"company": "Lakeview Fiber", "exported": "2026-11-13", "accounts": [
        {**{k: r[k] for k in schema.CUSTOMER_FIELDS}, "payment_method": rng.choice(methods),
         "billing_day": rng.randint(1, 28), "last_payment": f"2026-10-{rng.randint(1, 31):02d}",
         "past_due": rng.random() < 0.08}
        for r in rows
    ]}


def _fake_keys():
    # made up names and random values, none of it works anywhere
    t = secrets.token_hex
    return "\n".join((
        "# production settings, ops only",
        "APP_ENV=production",
        f"BILLING_DB_URL=postgres://billing_app:{t(12)}@billing-db.lakeviewfiber.internal:5432/billing",
        f"CRM_API_KEY=lvf_live_{t(20)}",
        f"PORTAL_SESSION_SECRET={t(32)}",
        "SMTP_HOST=smtp.lakeviewfiber.net",
        "SMTP_USER=noreply@lakeviewfiber.net",
        f"SMTP_PASSWORD={t(10)}",
        f"BACKUP_ENCRYPTION_KEY={t(24)}",
    )) + "\n"


def _key(path):
    p = os.path.realpath(str(path))
    if sys.platform == "darwin":  # case insensitive disk, and the data volume shows up under two names
        p = p.lower()
        if p.startswith("/system/volumes/data/"):
            p = p[len("/system/volumes/data"):]
    return p
