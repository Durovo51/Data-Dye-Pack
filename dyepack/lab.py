"""Lakeview Fiber, a made up internet provider full of fake subscribers."""

import fcntl
import hashlib
import hmac
import itertools
import json
import os
import random
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from . import schema, vocab

# who signs in to the customer API. a job is a registered system that only reads customers_clean
STAFF = {"rep.jordan": "support", "rep.casey": "support", "rep.taylor": "support", "backup.nightly": "job"}
# rounds ride along inside each hash. portal ones stay low so 50,000 accounts
# hash in seconds, a real portal would use far more
STAFF_ROUNDS = 200_000
PORTAL_ROUNDS = 2_000

KINDS = dict(vocab.PARTS)
# the parts behind each field that has to stay unique, number last
FEEDS = {
    "account_no": ("account",),
    "portal_user": ("user_style", "user_dd"),
    "email": ("email_style", "email_domain", "email_dd"),
    "phone": ("exchange", "line"),
}
TYPES = {"monthly_bill": "REAL", "since_year": "INTEGER"}


def logins_path():
    return schema.DATA_DIR / "lab_logins.json"


def pickers(weights):
    return {
        name: (list(weights[name]), list(itertools.accumulate(weights[name].values())))
        for name, kind in vocab.PARTS
        if kind == "cat"
    }


def draw(rng, pick, name, parts):
    kind = KINDS[name]
    if kind == "cat":
        values, cum = pick[name]
        return rng.choices(values, cum_weights=cum)[0]
    if kind == "zip":
        return rng.randrange(len(vocab.zips_for(parts["city"])))
    return rng.randint(kind[1], kind[2])


def unique_row(rng, pick, taken):
    """A row whose fields in taken ({field: used values}) are all new. Marks them used."""
    for _ in range(100):
        parts = {}
        for name in KINDS:
            parts[name] = draw(rng, pick, name, parts)
        for tries in range(100):
            row = vocab.compose(parts)
            clash = next((f for f in taken if row[f] in taken[f]), None)
            if clash is None:
                for f in taken:
                    taken[f].add(row[f])
                return row
            # new number first, then the rest of that field. names and styles keep their spread
            for name in (FEEDS[clash][-1:] if tries < 20 else FEEDS[clash]):
                parts[name] = draw(rng, pick, name, parts)
    raise RuntimeError("ran out of unique customers, try a smaller lab")


def make_rows(n, seed=None):
    # no seed means a fresh random lab. a fixed one would let anyone with the code rebuild the rows
    rng = random.Random(seed)
    pick = pickers(vocab.CATEGORIES)
    taken = {"account_no": set(), "portal_user": set()}
    return [unique_row(rng, pick, taken) for _ in range(n)]


def hash_password(password, rounds, salt=None):
    salt = secrets.token_bytes(16) if salt is None else salt
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${digest.hex()}", salt.hex()


def check_password(password, password_hash, salt):
    rounds = int(password_hash.split("$")[1])
    fresh, _ = hash_password(password, rounds, bytes.fromhex(salt))
    return hmac.compare_digest(fresh, password_hash)


def portal_hashes(n):
    # random passwords nobody keeps. pbkdf2 lets go of the GIL so threads help
    with ThreadPoolExecutor() as pool:
        return list(pool.map(lambda _: hash_password(secrets.token_urlsafe(12), PORTAL_ROUNDS), range(n)))


def write_customers(con, table, rows):
    cols = ", ".join(f"{f} {TYPES.get(f, 'TEXT')}" for f in schema.CUSTOMER_FIELDS)
    con.execute(f"CREATE TABLE {table} ({cols}, PRIMARY KEY (account_no), UNIQUE (portal_user))")
    marks = ", ".join("?" * len(schema.CUSTOMER_FIELDS))
    con.executemany(
        f"INSERT INTO {table} VALUES ({marks})",
        ([r[f] for f in schema.CUSTOMER_FIELDS] for r in rows),
    )


def write_portal(con, accounts):
    con.execute("CREATE TABLE portal_accounts (portal_user TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)")
    con.executemany("INSERT INTO portal_accounts VALUES (?, ?, ?)", accounts)


def update_watch(change):
    """Reads, changes and writes the watch list under one lock. The server, a burst and the drive
    never drop each other's entries. change(watch) edits the dict or returns a whole new one."""
    path = schema.WATCH_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # threads and other processes both wait here
        watch = json.loads(path.read_text()) if path.exists() else {}
        watch = change(watch) or watch
        write_private(path, watch)
        return watch
    finally:
        os.close(fd)  # closing lets go of the lock


def write_private(path, data):
    # owner only. swapped in whole so nobody reads half a file
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def build_lab(n, seed=None):
    rows = make_rows(n, seed)
    portal = [(r["portal_user"], *h) for r, h in zip(rows, portal_hashes(n))]
    logins = {user: secrets.token_urlsafe(12) for user in STAFF}
    staff = [(user, *hash_password(pw, STAFF_ROUNDS), STAFF[user]) for user, pw in logins.items()]

    db = schema.DB_PATH
    db.parent.mkdir(parents=True, exist_ok=True)
    # a fresh lab makes the old watch list, profile and exports meaningless
    old = [db, db.with_name(db.name + "-journal"), schema.WATCH_PATH, schema.PROFILE_PATH]
    for path in old + list(schema.EXPORTS_DIR.glob("exp-*")):
        path.unlink(missing_ok=True)
    con = sqlite3.connect(db, isolation_level=None)
    os.chmod(db, 0o600)
    try:
        con.execute("BEGIN")
        write_customers(con, "customers", rows)
        write_portal(con, portal)
        con.execute("CREATE TABLE staff (user TEXT PRIMARY KEY, password_hash TEXT, salt TEXT, role TEXT)")
        con.executemany("INSERT INTO staff VALUES (?, ?, ?, ?)", staff)
        con.execute("COMMIT")
    finally:
        con.close()
    write_private(logins_path(), logins)
    return {"customers": len(rows), "portal_accounts": len(portal), "staff": len(staff)}
