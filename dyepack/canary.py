"""Canary customers: fakes drawn from the table's own value counts and planted among real ones."""

import json
import math
import random
import secrets
import sqlite3
import time
from collections import Counter

from . import lab, schema
from .profile import build_profile, save_profile


def make_canaries(profile, n, taken_accounts, taken_users, batch, taken_contacts=(), rng=None):
    """n fake customers drawn from the profile. Returns (rows, watch list entries) in the same order."""
    rng = random.SystemRandom() if rng is None else rng
    contacts = set(taken_contacts)
    taken = {
        "account_no": set(taken_accounts),
        "portal_user": set(taken_users),
        # a canary never shares an email or phone with a real customer
        "email": contacts,
        "phone": contacts,
    }
    pick = lab.pickers(profile["parts"])
    rows = [lab.unique_row(rng, pick, taken) for _ in range(n)]
    now = time.time()
    watch = [
        {"canary_id": f"c-{i:03d}", "account_no": r["account_no"], "portal_user": r["portal_user"],
         "email": r["email"], "phone": r["phone"], "batch": batch, "planted_at": now}
        for i, r in enumerate(rows, 1)
    ]
    return rows, watch


def plant(every=250, rng=None):
    """Studies the table and shuffles canaries into it. Writes the watch list and customers_clean."""
    rng = random.SystemRandom() if rng is None else rng
    if not schema.DB_PATH.exists():
        raise RuntimeError("no lab yet, run dyepack lab first")
    con = sqlite3.connect(schema.DB_PATH, isolation_level=None)
    try:
        if con.execute("SELECT 1 FROM sqlite_master WHERE name = 'customers_clean'").fetchone():
            raise RuntimeError("canaries are already planted, run dyepack lab for a fresh table")
        cols = ", ".join(schema.CUSTOMER_FIELDS)
        rows = [dict(zip(schema.CUSTOMER_FIELDS, t))
                for t in con.execute(f"SELECT {cols} FROM customers ORDER BY rowid")]
        found = con.execute("SELECT portal_user, password_hash, salt FROM portal_accounts")
        portal = {u: (h, s) for u, h, s in found}

        profile = build_profile(rows)
        best = None
        for draws in range(1, 21):
            fakes, watch = make_canaries(
                profile, max(1, len(rows) // every),
                [r["account_no"] for r in rows], [r["portal_user"] for r in rows], "table",
                taken_contacts=[r[f] for r in rows for f in ("email", "phone")], rng=rng,
            )
            blend = blend_test(rows, fakes)
            if best is None or min(blend.values()) > min(best[2].values()):
                best = (fakes, watch, blend)
            # a fair draw still looks odd now and then. a set that fails our own test never gets planted
            if min(blend.values()) >= 0.05:
                break
        fakes, watch, blend = best
        for r in fakes:
            portal[r["portal_user"]] = lab.hash_password(secrets.token_urlsafe(12), lab.PORTAL_ROUNDS)
        mixed = rows + fakes
        rng.shuffle(mixed)
        fake_accounts = {r["account_no"] for r in fakes}

        save_profile(profile)
        lab.update_watch(lambda w: {"canaries": watch})  # a fresh table starts a fresh list
        con.execute("BEGIN")
        con.execute("DROP TABLE customers")
        con.execute("DROP TABLE portal_accounts")
        lab.write_customers(con, "customers", mixed)
        clean = [r for r in mixed if r["account_no"] not in fake_accounts]
        lab.write_customers(con, "customers_clean", clean)
        # logins follow the same shuffle so canary accounts don't pile up at the end either
        lab.write_portal(con, [(r["portal_user"], *portal[r["portal_user"]]) for r in mixed])
        con.execute("COMMIT")
        # clears leftover pages of the old tables out of the file
        con.execute("VACUUM")
    finally:
        con.close()
    return {"rows": len(rows), "canaries": len(fakes), "blend": blend, "draws": draws}


def load_watch():
    return json.loads(schema.WATCH_PATH.read_text())["canaries"]


def census():
    """Counts read back from disk. What seed prints is measured, not assumed."""
    watched = {c["account_no"] for c in load_watch()}
    con = sqlite3.connect(schema.DB_PATH)
    try:
        out = {"watch_list": len(watched)}
        for table in ("customers", "customers_clean"):
            accounts = [a for (a,) in con.execute(f"SELECT account_no FROM {table}")]
            out[table] = len(accounts)
            out[table + "_canaries"] = sum(a in watched for a in accounts)
        out["portal_accounts"] = con.execute("SELECT COUNT(*) FROM portal_accounts").fetchone()[0]
    finally:
        con.close()
    return out


def _gap(sample, expect):
    # chi square distance from the counts real rows would give
    seen = Counter(sample)
    if not seen.keys() <= expect.keys():
        return math.inf
    return sum((seen[v] - e) ** 2 / e for v, e in expect.items())


def blend_test(real, fakes, fields=("city", "plan", "first_name"), trials=1000):
    """Frequency test. For each field, the share of random same size handfuls of real customers
    that look at least as odd as the canaries. Under 0.01 would mean the canaries stand out."""
    rng = random.Random(0)
    out = {}
    for field in fields:
        values = [r[field] for r in real]
        expect = {v: c * len(fakes) / len(values) for v, c in Counter(values).items()}
        mine = _gap((r[field] for r in fakes), expect)
        odder = sum(_gap(rng.sample(values, len(fakes)), expect) >= mine for _ in range(trials))
        out[field] = (1 + odder) / (1 + trials)
    return out
