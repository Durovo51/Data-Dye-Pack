"""Study a customer table and keep only how often each value shows up, never rows."""

import json
from collections import Counter

from . import schema, vocab

CAT_PARTS = [name for name, kind in vocab.PARTS if kind == "cat"]


def build_profile(rows):
    counts = {name: Counter() for name in CAT_PARTS}
    n = 0
    for row in rows:
        parts = vocab.decompose(row)
        for name in CAT_PARTS:
            counts[name][parts[name]] += 1
        n += 1
    return {"rows": n, "parts": {name: dict(c.most_common()) for name, c in counts.items()}}


def save_profile(profile, path=None):
    (path or schema.PROFILE_PATH).write_text(json.dumps(profile, indent=1))


def load_profile(path=None):
    return json.loads((path or schema.PROFILE_PATH).read_text())
