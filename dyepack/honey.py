"""Honey lock for exports: every wrong password opens a believable fake customer list
and only the right password opens the real one. It hides real rows among believable
fakes only as well as the profile matches the real data.
"""

import bisect
import getpass
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import struct
import sys
from pathlib import Path

from . import schema, vocab

MAGIC = b"DYEPACK1"
SPACE = 1 << 32
ROW = struct.Struct(">" + "I" * len(vocab.PARTS))  # 4 bytes per part
SHOW = ("account_no", "first_name", "last_name", "city", "phone", "email", "plan", "monthly_bill")
_rng = secrets.SystemRandom()


def lock(rows, password, profile, iterations=200_000):
    """Customer rows -> locked bytes. Row order is kept, so pass them shuffled.
    profile should describe the population the rows come from, never just these rows: a thief
    who knows the true weights spots the list that fits them best. None uses the recipe's own
    weights, the right header when the rows were drawn from the recipe, like the lab's."""
    for field in ("account_no", "portal_user"):
        if len({r[field] for r in rows}) != len(rows):
            raise ValueError(f"every {field} has to be unique, like in the real table")
    parts = [vocab.decompose(r) for r in rows]
    salt = _rng.randbytes(16)
    head = {"salt": salt.hex(), "iterations": iterations, "rows": len(parts),
            "parts": _weights(profile, parts)}
    codec = _Codec(head["parts"])
    rand = iter(memoryview(_rng.randbytes(8 * len(vocab.PARTS) * len(parts))).cast("Q"))
    plain = b"".join(ROW.pack(*codec.encode(p, rand)) for p in parts)
    return b"\n".join([MAGIC, json.dumps(head).encode(), _xor(plain, _key(password, salt, iterations))])


def open_locked(blob, password, limit=None):
    """Locked bytes + any password -> customer rows. Wrong passwords get believable fakes."""
    head, body = _read(blob)
    n = head["rows"] if limit is None else max(0, min(limit, head["rows"]))
    key = _key(password, bytes.fromhex(head["salt"]), head["iterations"])
    codec = _Codec(head["parts"])
    return [vocab.compose(codec.decode(s)) for s in ROW.iter_unpack(_xor(body[: n * ROW.size], key))]


def cmd_lock(args):
    if not schema.DB_PATH.exists():
        return _fail(f"no lab table at {schema.DB_PATH}, run dyepack lab first")
    try:
        con = sqlite3.connect(schema.DB_PATH)
        try:
            cur = con.execute(f"SELECT {', '.join(schema.CUSTOMER_FIELDS)} FROM customers")
            rows = [dict(zip(schema.CUSTOMER_FIELDS, r)) for r in cur]
        finally:
            con.close()
    except sqlite3.Error as e:
        return _fail(f"can't read the customers table: {e}")
    profile = None
    if schema.PROFILE_PATH.exists():
        try:
            profile = json.loads(schema.PROFILE_PATH.read_text())
        except ValueError:
            return _fail(f"{schema.PROFILE_PATH} is damaged, run dyepack seed on a fresh lab")
    else:
        print("no profile yet, fakes will use the default weights", file=sys.stderr)
    password = _password(args, confirm=True)
    if not password:
        return _fail("the password can't be empty")
    _rng.shuffle(rows)  # leave no order for a thief to read
    try:
        blob = lock(rows, password, profile)
    except ValueError as e:
        return _fail(str(e))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    print(f"locked {len(rows):,} customers into {out}")
    return 0


def cmd_open(args):
    try:
        blob = Path(args.file).read_bytes()
    except OSError as e:
        return _fail(f"can't read {args.file}: {e.strerror}")
    password = _password(args)
    try:
        rows = open_locked(blob, password, getattr(args, "limit", None))
        total = _read(blob)[0]["rows"]
    except ValueError as e:
        return _fail(str(e))
    print(f"{len(rows):,} of {total:,} customers")
    lines = [[f.replace("_", " ") for f in SHOW]]
    lines += [[f"{r[f]:.2f}" if f == "monthly_bill" else str(r[f]) for f in SHOW] for r in rows]
    widths = [max(map(len, col)) for col in zip(*lines)]
    for line in lines:
        print("  ".join(c.ljust(w) for c, w in zip(line, widths)).rstrip())
    return 0


class _Codec:
    """Parts to 4 byte slots and back. Account numbers and logins never repeat inside
    one list, since the real table never repeats them."""

    def __init__(self, weights):
        self.cats = {}
        for name, w in weights.items():
            values, total, run, edges = sorted(w), sum(w.values()), 0, []
            for v in values:
                run += w[v]
                edges.append(run * SPACE // total)
            self.cats[name] = values, {v: i for i, v in enumerate(values)}, edges
        self.accounts = []  # sorted, used so far
        self.logins = {}    # login base -> sorted endings used so far

    def _taken(self, name, p):
        if name == "account":
            return self.accounts
        if name == "user_dd":
            base = vocab._user_base(p["user_style"], p["first_name"], p["last_name"])
            return self.logins.setdefault(base, [])
        return None

    def encode(self, p, rand):
        slots = []
        for name, kind in vocab.PARTS:
            v = p[name]
            if kind == "cat":
                _, index, edges = self.cats[name]
                i = index[v]
                lo, hi = (edges[i - 1] if i else 0), edges[i]
            else:
                if kind == "zip":
                    i, n = v, len(vocab.zips_for(p["city"]))
                else:
                    i, n = v - kind[1], kind[2] - kind[1] + 1
                    taken = self._taken(name, p)
                    if taken is not None:  # rank among the values not used yet
                        k = bisect.bisect_left(taken, v)
                        i, n = i - k, n - len(taken)
                        taken.insert(k, v)
                lo, hi = -(-i * SPACE // n), -(-(i + 1) * SPACE // n)  # slice i of n equal slices
            # random point inside the slot (64 random bits, so the modulo bias is under 2**-32)
            slots.append(lo + next(rand) % (hi - lo))
        return slots

    def decode(self, slots):
        p = {}
        for (name, kind), x in zip(vocab.PARTS, slots):
            if kind == "cat":
                values, _, edges = self.cats[name]
                p[name] = values[bisect.bisect_right(edges, x)]
            elif kind == "zip":
                p[name] = x * len(vocab.zips_for(p["city"])) >> 32
            else:
                lo, hi = kind[1:]
                taken = self._taken(name, p)
                free = hi - lo + 1 - len(taken or ())
                if taken is None or not free:  # nothing left to keep unique, let it repeat
                    p[name] = lo + (x * (hi - lo + 1) >> 32)
                else:
                    p[name] = _unrank(x * free >> 32, lo, taken)
                    bisect.insort(taken, p[name])
        return p


def _weights(profile, parts):
    # interval weights per "cat" part, stored in the header so opening needs nothing else
    counts = (profile or {}).get("parts") or {}
    out = {}
    for name, kind in vocab.PARTS:
        if kind != "cat":
            continue
        seen = {p[name] for p in parts}  # a stale profile can miss a value, give it a sliver
        if counts.get(name):
            out[name] = _jitter({**dict.fromkeys(seen, 0), **counts[name]})
        else:
            out[name] = {**dict.fromkeys(seen, 1), **vocab.CATEGORIES[name]}
    return out


def _jitter(counts):
    # exact counts would fit the real list better than any fake, so draw fresh weights around
    # them (a Dirichlet sample). alpha per part keeps the real list's likelihood level with a fake's
    k, n = len(counts), sum(counts.values()) or 1
    logs = {v: math.log(c + 0.5) for v, c in counts.items()}
    spread = sum(counts[v] * logs[v] for v in counts) / n - sum(logs.values()) / k
    alpha = max(0.5, min(8.0, (k - 1) / (k * spread))) if spread > 0 else 8.0
    g = {v: _rng.gammavariate(counts[v] + alpha, 1) for v in sorted(counts)}
    scale = n / sum(g.values())
    return {v: max(1, round(x * scale)) for v, x in g.items()}


def _unrank(k, lo, taken):
    # the k-th value from lo up that isn't in taken (sorted)
    v = lo + k
    while True:
        nxt = lo + k + bisect.bisect_right(taken, v)
        if nxt == v:
            return v
        v = nxt


def _key(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def _xor(data, key):
    # keystream: HMAC SHA 256 of the key over a block counter
    n = len(data)
    stream = b"".join(hmac.digest(key, i.to_bytes(8, "big"), "sha256") for i in range(-(-n // 32)))
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream[:n], "big")).to_bytes(n, "big")


def _read(blob):
    try:
        magic, head, body = blob.split(b"\n", 2)
        head = json.loads(head)
        weights = [head["parts"][name] for name, kind in vocab.PARTS if kind == "cat"]
        good = (magic == MAGIC and type(head["rows"]) is int and len(body) == head["rows"] * ROW.size
                and bytes.fromhex(head["salt"]) and head["iterations"] > 0
                and all(w and all(type(x) is int and x > 0 for x in w.values()) for w in weights))
    except (AttributeError, KeyError, TypeError, ValueError):
        good = False
    if not good:
        raise ValueError("not a dyepack locked file, or it's damaged")
    return head, body


def _password(args, confirm=False):
    pw = getattr(args, "password", None)
    if pw is None:
        pw = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Same password again: ") != pw:
            raise SystemExit("the passwords don't match")
    return pw


def _fail(msg):
    print(msg, file=sys.stderr)
    return 1
