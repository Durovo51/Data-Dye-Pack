"""Can statistics pick the real list out of cracked copies? Lock real rows, open them with
wrong passwords and score every list the way a careful thief would.
"""

import json
import math
import secrets
import sqlite3
import sys
from collections import Counter

from . import honey, schema, vocab
from .profile import build_profile

ROUNDS = 1_000  # pbkdf2 rounds only slow a thief down, the scores don't depend on them
CATS = [name for name, kind in vocab.PARTS if kind == "cat"]
TESTS = ("chi_square", "g_test", "likelihood", "recipe_fit")
LABELS = {"chi_square": "value counts, chi square", "g_test": "value counts, G test",
          "likelihood": "likelihood", "recipe_fit": "fit to the public recipe"}


def score(parts, weights):
    """Four checks a thief can run on one list: chi square, G test and log likelihood against
    the header weights, plus chi square against the public recipe in vocab, since anyone
    with the repo knows the weights the lab rows were drawn from."""
    chi = g = likely = recipe = 0.0
    for name in CATS:
        got = Counter(p[name] for p in parts)
        w = weights[name]
        total = sum(w.values())
        for v, x in w.items():
            expect, n = len(parts) * x / total, got[v]
            chi += (n - expect) ** 2 / expect
            if n:
                g += 2 * n * math.log(n / expect)
                likely += n * math.log(x / total)
        public = vocab.CATEGORIES[name]
        total = sum(public.values())
        for v, x in public.items():
            expect = len(parts) * x / total
            recipe += (got[v] - expect) ** 2 / expect
    return chi, g, likely, recipe


def repeats(parts):
    # the real table never repeats these, so any repeat would mark a fake
    accounts = {p["account"] for p in parts}
    logins = {(vocab._user_base(p["user_style"], p["first_name"], p["last_name"]), p["user_dd"])
              for p in parts}
    return 2 * len(parts) - len(accounts) - len(logins)


def prove(rows, profile, fakes=99, password=None, naive=False):
    """Lock rows, open them with `fakes` random wrong passwords and score all the lists.
    Returns the real list's rank on each check, 1 being the lowest score of the lot.
    If the real list blends in, every rank is as likely as any other. naive=True locks
    with exact counts in the header instead, for the side by side demo."""
    if fakes < 1:
        raise ValueError("needs at least one wrong password")
    if not rows:
        raise ValueError("needs at least one customer")
    password = password or secrets.token_urlsafe(16)
    if naive:
        blob = _naive_lock(rows, password, profile)
    else:
        blob = honey.lock(rows, password, profile, iterations=ROUNDS)
    if honey.open_locked(blob, password) != rows:
        raise RuntimeError("the right password didn't give the rows back")
    guesses = set()
    while len(guesses) < fakes:
        guess = secrets.token_urlsafe(9)
        if guess != password:
            guesses.add(guess)
    weights = honey._read(blob)[0]["parts"]
    opened = _opened(blob, [password, *guesses])
    real = next(opened)
    mine, theirs, fake_repeats = score(real, weights), [], 0
    for parts in opened:  # score each fake and let it go, 100 lists don't need to sit in memory
        theirs.append(score(parts, weights))
        fake_repeats += repeats(parts)
    return {
        "rows": len(rows),
        "lists": fakes + 1,
        "rank": {t: 1 + sum(s[i] < mine[i] for s in theirs) for i, t in enumerate(TESTS)},
        "repeats": {"real": repeats(real), "fakes": fake_repeats},
    }


def _opened(blob, passwords):
    # what each password opens, as parts. open_locked builds rows from these same parts, and
    # parsing them back gives the same parts (no name pair in the vocab makes a style ambiguous),
    # so scoring parts skips work that cancels out
    head, body = honey._read(blob)
    salt = bytes.fromhex(head["salt"])
    for pw in passwords:
        codec = honey._Codec(head["parts"])
        plain = honey._xor(body, honey._key(pw, salt, head["iterations"]))
        yield [codec.decode(s) for s in honey.ROW.iter_unpack(plain)]


def _naive_lock(rows, password, profile):
    # the obvious design, only for the demo: exact profile counts in the header, the rest of
    # the lock unchanged. never use it for a real export
    parts = [vocab.decompose(r) for r in rows]
    weights = {name: {**dict.fromkeys({p[name] for p in parts}, 1),
                      **{v: max(1, c) for v, c in profile["parts"][name].items()}} for name in CATS}
    salt = secrets.token_bytes(16)
    head = {"salt": salt.hex(), "iterations": ROUNDS, "rows": len(parts), "parts": weights}
    codec = honey._Codec(weights)
    rand = iter(memoryview(secrets.token_bytes(8 * len(vocab.PARTS) * len(parts))).cast("Q"))
    plain = b"".join(honey.ROW.pack(*codec.encode(p, rand)) for p in parts)
    scrambled = honey._xor(plain, honey._key(password, salt, ROUNDS))
    return b"\n".join([honey.MAGIC, json.dumps(head).encode(), scrambled])


def cmd_prove(args):
    want, fakes = getattr(args, "rows", None) or 2000, getattr(args, "fakes", None) or 99
    compare = getattr(args, "compare", False)
    if not schema.DB_PATH.exists():
        print(f"no lab table at {schema.DB_PATH}, run dyepack lab first", file=sys.stderr)
        return 1
    try:
        con = sqlite3.connect(schema.DB_PATH)
        try:
            cur = con.execute(f"SELECT {', '.join(schema.CUSTOMER_FIELDS)} FROM customers")
            table = [dict(zip(schema.CUSTOMER_FIELDS, r)) for r in cur]
        finally:
            con.close()
    except sqlite3.Error as e:
        print(f"can't read the lab: {e}", file=sys.stderr)
        return 1
    rows = secrets.SystemRandom().sample(table, min(max(1, want), len(table)))
    try:
        if compare:
            # three headers for the same rows, locked as if they were the whole table. the
            # first two come from these very rows, ours is the public recipe they were drawn from
            own = build_profile(rows)
            runs = {"exact counts": prove(rows, own, fakes, naive=True),
                    "jittered": prove(rows, own, fakes), "ours": prove(rows, None, fakes)}
        else:
            result = prove(rows, None, fakes)  # the lab locks with the recipe's weights, so this does too
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    if compare:
        print(f"locked the same {len(rows):,} customers three ways, each opened with {fakes} wrong passwords")
        print("header weights: exact counts of these rows, jittered counts, or ours (the public recipe)")
        print(f"where the real list ranks among {fakes + 1} lists (1 = lowest score)")
        print(f"  {'':<26}" + "".join(f"{name:<15}" for name in runs).rstrip())
        for test in TESTS:
            print(f"  {LABELS[test]:<26}" + "".join(f"{r['rank'][test]:<15}" for r in runs.values()).rstrip())
        print("a giveaway sits at 1 every time. ours lands somewhere new every run.")
        return 0
    n = result["lists"]
    print(f"locked {result['rows']:,} customers, then opened the file with {n - 1} wrong passwords")
    print(f"can a thief's statistics find the real list among all {n}? (rank 1 = lowest score)")
    for test, rank in result["rank"].items():
        print(f"  {LABELS[test]:<26}real list ranked {rank} of {n}")
    print(f"  {'repeated accounts, logins':<26}{result['repeats']['real']} in the real list, "
          f"{result['repeats']['fakes']} across the fakes")
    print("a giveaway would rank 1 or last every run. a list that blends in lands anywhere.")
    return 0
