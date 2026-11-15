"""Burst. When a decoy fires, the server honey locks the customer data files on the whole drive in
place (burst_drive runs burst on every folder): customers.csv becomes customers.csv.dye right next
to it and the original goes away, so the company's own apps fail loudly instead of quietly reading
made up customers. Only CSV and JSON customer tables get touched, never any other file. dyepack
unlock puts them back with the lock password (DYEPACK_LOCK_PASSWORD).

A stolen .dye opens to believable fakes for every wrong password. The team's own unlock still
tells a wrong password apart: the burst records which canaries each file held, plus a hash of
the file, in the watch list on the security side, never beside the .dye.

Limits. Only the customer fields get the honey lock. Extra columns and rows that don't fit the
recipe sit readable in the .dye header, row by row, so a column that copies a customer field (an
amount due equal to the bill, say) would line up with the real rows only. Files that list a
customer more than once get skipped, since the honey lock needs unique accounts and logins like
the real table has. A file sorted by one field stays sorted for every guess, but one that's only
partly in order (appended over time, grouped by city with no tie rule) keeps that order inside
the lock, so the real list would be the only one that shows it. A value the recipe doesn't have
(a rare first name, say) shows in the header with weight 1, so the real list is the one that
holds it. Lab files never have such values.
"""

import csv
import getpass
import hashlib
import io
import json
import os
import secrets
import stat
import sys
import time
from pathlib import Path

from . import honey, lab, schema, vocab
from .drive import decoy_for, load_decoys, vault_password

TABLES = (".csv", ".json")
MAX_BYTES = 50 << 20  # bigger files don't get scanned


def scan(root, recursive=True):
    """Sensitive files under root: CSV or JSON files where most rows fit the customer recipe."""
    root = Path(root)
    if recursive:
        found = (Path(d, f) for d, _, files in os.walk(root) for f in files)
    else:
        found = root.iterdir()
    return sorted(p for p in found if p.suffix.lower() in TABLES and p.is_file() and not p.is_symlink()
                  and _sensitive(_read(p)))


def burst(folder, password):
    """Honey locks the customer data files right in folder (not the ones below it) into
    <name>.dye next to them and removes the originals. Decoys and every other file stay as they
    are. Returns {"folder", "files": [names], "vault": [.dye files], "skipped": [[name, why]]}."""
    root = Path(schema.DRIVE_ROOT).expanduser().resolve()
    folder = Path(folder).expanduser().resolve()
    if folder != root and root not in folder.parents:
        raise ValueError(f"{folder} isn't on the drive at {root}, a burst never goes there")
    if not folder.is_dir():
        raise ValueError(f"no folder at {folder}")
    if not password:
        raise ValueError("no lock password, set DYEPACK_LOCK_PASSWORD in .env")
    decoys = load_decoys()
    out = {"folder": str(folder), "files": [], "vault": [], "skipped": []}
    for path in scan(folder, recursive=False):
        if decoy_for(path, decoys):
            continue  # decoys keep doing their job
        try:
            dye = _lock(path, password)
        except (OSError, ValueError) as e:
            out["skipped"].append([path.name, str(e)])
            continue
        out["files"].append(path.name)
        out["vault"].append(str(dye))
    return out


def burst_drive(password):
    """burst() on every folder of the drive, for an incident that locks all of it. Same shape as
    burst, with "folder" the drive, files as paths on the drive and "folders" where files got locked."""
    root = Path(schema.DRIVE_ROOT).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"no drive at {root}")
    out = {"folder": str(root), "folders": [], "files": [], "vault": [], "skipped": []}
    for d, dirs, _ in os.walk(root):
        dirs.sort()
        part = burst(d, password)
        rel = Path(d).relative_to(root)
        if part["files"]:
            out["folders"].append(part["folder"])
        out["files"] += [(rel / f).as_posix() for f in part["files"]]
        out["vault"] += part["vault"]
        out["skipped"] += [[(rel / f).as_posix(), why] for f, why in part["skipped"]]
    return out


def unlock(dye_file, password, dest=None, force=False):
    """Puts the exact original back from a .dye a burst made, then removes the .dye. A wrong
    password fails clearly and the .dye stays. force unlocks a file the watch list has no record
    of, with nothing to check against, so the .dye stays then too."""
    dye = Path(dye_file).expanduser().resolve()
    blob = dye.read_bytes()
    lay = _layout_of(blob)
    rows = honey.open_locked(blob, password)
    data = _render(lay, rows)
    rec = _record(dye)
    if rec is None and not force:
        raise ValueError(f"the watch list has no record of {dye.name}, so a wrong password can't be caught "
                         "(--force unlocks it anyway)")
    if rec is not None and not _matches(rec, rows, data):
        raise ValueError(f"wrong password, {dye.name} stays locked")
    home = dye.parent / lay["name"]
    dest = Path(dest) if dest else home
    if dest.exists():
        raise ValueError(f"{dest} already exists, move it away first")
    _write(dest, data, lay["mode"], (lay["mtime_ns"], lay["mtime_ns"]), lay.get("owner"))
    if rec is not None and dest == home:
        dye.unlink()
        _update_locked(rec["dye"])
    return dest


def locked():
    """What bursts locked, from the watch list: {"dye", "file", "canaries", "sha256", "locked_at"}."""
    return _watch().get("locked", [])


def cmd_burst(args):
    password = vault_password()
    if not password:
        return _fail("set DYEPACK_LOCK_PASSWORD in .env first")
    try:
        out = burst(args.folder, password)
    except (OSError, ValueError) as e:
        return _fail(str(e))
    for name, dye in zip(out["files"], out["vault"]):
        print(f"locked {name} into {dye}")
    for name, why in out["skipped"]:
        print(f"skipped {name}: {why}")
    if out["files"]:
        print("dyepack unlock puts them back")
    elif not out["skipped"]:
        print(f"no customer data files right in {out['folder']}")
    return 0


def cmd_unlock(args):
    files = getattr(args, "dye", None) or getattr(args, "vault", None) or [r["dye"] for r in locked()]
    dest, force = getattr(args, "to", None), getattr(args, "force", False)
    if not files:
        print("nothing is locked")
        return 0
    if dest and len(files) > 1:
        return _fail("--to takes one .dye file")
    password = vault_password() or getpass.getpass("Lock password: ")
    bad = 0
    for f in files:
        try:
            print(f"unlocked {unlock(f, password, dest, force)}")
        except (OSError, ValueError) as e:
            print(f"{Path(f).name}: {e}", file=sys.stderr)
            bad += 1
            continue
        if Path(f).exists():
            print(f"  {Path(f).name} stays, delete it once you've checked the file")
    return 1 if bad else 0


cmd_restore = cmd_unlock  # the old name, so wiring made before unlock keeps working


def _lock(path, password):
    dye = path.with_name(path.name + ".dye")
    if dye.exists():
        raise ValueError(f"{dye.name} is already there, so it stays as it is")
    t = _read(path)
    found = t and _layout(t)
    if not found:
        raise ValueError("can't rebuild it byte for byte, left as is")
    lay, rows = found
    st = path.stat()
    lay.update(name=path.name, mode=stat.S_IMODE(st.st_mode), mtime_ns=st.st_mtime_ns, owner=[st.st_uid, st.st_gid])
    # a sorted file gets sorted again on the way out, so the lock can take the rows shuffled
    # and row order can't tell the right password from a wrong one. the drive's rows come from
    # vocab's weights, so the lock uses those (profile None): a header built from counts would
    # let anyone holding the repo rank cracked lists against vocab and pick out the real one
    rows_in = secrets.SystemRandom().sample(rows, len(rows)) if lay["sort"] else rows
    blob = honey.lock(rows_in, password, None)
    _write(dye, _with_layout(blob, lay), lay["mode"], owner=lay["owner"])
    try:
        # the original only goes once the .dye on disk opens back to the very same bytes
        back = dye.read_bytes()
        if _render(_layout_of(back), honey.open_locked(back, password)) != t["raw"]:
            raise ValueError("the .dye didn't open back to the same file, left as is")
        watched = _canaries()
        _update_locked(str(dye), {
            "dye": str(dye), "file": str(path), "sha256": _sha(t["raw"]), "locked_at": time.time(),
            "canaries": sorted(r["account_no"] for r in rows if r["account_no"] in watched)})
    except BaseException:
        dye.unlink(missing_ok=True)
        raise
    path.unlink()  # apps that read it now fail loudly until someone unlocks it
    return dye


def _matches(rec, rows, data):
    # the right password gives back exactly the canaries the file held. the hash covers files
    # that held none, where any wrong password's fake would pass the canary check too
    found = {r["account_no"] for r in rows} & _canaries()
    return found == set(rec["canaries"]) and _sha(data) == rec["sha256"]


def _record(dye):
    for r in locked():
        try:
            if os.path.samefile(r["dye"], dye):
                return r
        except OSError:
            pass
    return None


def _watch():
    # the security side's list. missing is fine, broken isn't, so a list we can't read never gets replaced
    if not schema.WATCH_PATH.exists():
        return {"canaries": []}
    return json.loads(schema.WATCH_PATH.read_text())


def _canaries():
    return {c["account_no"] for c in _watch().get("canaries", [])}


def _update_locked(drop, add=None):
    # change only "locked", under the shared lock, since other parts of dyepack write this file too
    def change(watch):
        watch.setdefault("canaries", [])
        watch["locked"] = [r for r in watch.get("locked", []) if r["dye"] != drop] + ([add] if add else [])

    lab.update_watch(change)


def _with_layout(blob, lay):
    # the layout rides in the lock's own header, so dyepack open still reads a .dye
    magic, head, body = blob.split(b"\n", 2)
    head = json.loads(head)
    head["layout"] = lay
    return b"\n".join([magic, json.dumps(head).encode(), body])


def _layout_of(blob):
    try:
        return json.loads(blob.split(b"\n", 2)[1])["layout"]
    except (IndexError, KeyError, TypeError, ValueError):
        raise ValueError("not a .dye from a burst (dyepack open reads other locked files)") from None


def _read(path):
    """A CSV or JSON file as a table of rows, or None when it isn't one."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        raw = path.read_bytes()
        bom = raw.startswith(b"\xef\xbb\xbf")
        text = raw[3 if bom else 0:].decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    t = {"raw": raw, "text": text, "bom": bom}
    if path.suffix.lower() == ".csv":
        try:
            recs = list(csv.reader(io.StringIO(text, newline="")))
        except csv.Error:
            return None
        if len(recs) < 2:
            return None
        head = recs[0]
        t.update(kind="csv", head=head, rows=[dict(zip(head, r)) if len(r) == len(head) else r for r in recs[1:]])
        return t
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    key = None
    if isinstance(doc, dict):  # rows can sit one level down, like {"invoices": [...]}
        lists = [k for k, v in doc.items() if isinstance(v, list)]
        if not lists:
            return None
        key = max(lists, key=lambda k: len(doc[k]))
    elif not isinstance(doc, list):
        return None
    t.update(kind="json", doc=doc, key=key, rows=doc if key is None else doc[key])
    return t


def _fit(row):
    """The row as the recipe writes it, or None when it doesn't fit."""
    if not isinstance(row, dict):
        return None
    try:
        return vocab.compose(vocab.decompose(row))
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _sensitive(t, sample=200):
    rows = t["rows"][:sample] if t else []
    return sum(_fit(r) is not None for r in rows) * 2 > len(rows) > 0


def _layout(t):
    """Rows to lock plus a layout that rebuilds the file around them. None when the layout
    can't give back the very same bytes, so a file we can't restore never gets locked."""
    rows, entries, keys = [], [], None
    for r in t["rows"]:
        row = _fit(r)
        if row is None:
            entries.append({"raw": r})
            continue
        e, extra = {"i": len(rows)}, {k: v for k, v in r.items() if k not in row}
        if extra:
            e["x"] = extra
        keys = keys or list(r)
        if list(r) != keys:
            e["k"] = list(r)
        entries.append(e)
        rows.append(row)
    text = t["text"]
    base = {"kind": t["kind"], "bom": t["bom"], "keys": keys or [], "rows": entries, "sort": _sorted_by(rows)}
    if t["kind"] == "csv":
        nl = "\r\n" if "\r\n" in text else "\n"
        tries = [dict(base, head=t["head"], nl=nl, end=text.endswith(nl), bill=_bill(t))]
    else:
        body = text.rstrip()
        doc = None if t["key"] is None else {k: None if k == t["key"] else v for k, v in t["doc"].items()}
        indent = _indent(body)
        seps = [(", ", ": "), (",", ":")] if indent is None else [(",", ": "), (", ", ": ")]
        tries = [dict(base, doc=doc, key=t["key"], end=text[len(body):],
                      fmt={"indent": indent, "separators": s, "ensure_ascii": text.isascii()}) for s in seps]
    for lay in tries:
        if _render(lay, rows) == t["raw"]:
            return lay, rows
    return None


def _render(lay, rows):
    """Layout plus customer rows -> file bytes."""
    if lay.get("sort"):
        field, reverse = lay["sort"]
        rows = sorted(rows, key=lambda r: (r[field], r["account_no"]), reverse=reverse)
    out = []
    for e in lay["rows"]:
        if "raw" in e:
            out.append(e["raw"])
            continue
        row, extra = rows[e["i"]], e.get("x", {})
        out.append({k: row[k] if k in row else extra[k] for k in e.get("k", lay["keys"])})
    if lay["kind"] == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator=lay["nl"])
        w.writerow(lay["head"])
        for r in out:
            w.writerow([_cell(k, r[k], lay["bill"]) for k in lay["head"]] if isinstance(r, dict) else r)
        text = buf.getvalue()
        if not lay["end"]:
            text = text[:-len(lay["nl"])]
    else:
        doc = out if lay["key"] is None else {**lay["doc"], lay["key"]: out}
        text = json.dumps(doc, **lay["fmt"]) + lay["end"]
    return (b"\xef\xbb\xbf" if lay["bom"] else b"") + text.encode("utf-8")


def _sorted_by(rows):
    """[field, reverse] when the rows are sorted by a field (account number on ties), else None."""
    for field in schema.CUSTOMER_FIELDS:
        keys = [(r[field], r["account_no"]) for r in rows]
        pairs = list(zip(keys, keys[1:]))
        for reverse in (False, True):
            if pairs and all((b <= a) if reverse else (a <= b) for a, b in pairs):
                return [field, reverse]
    return None


def _cell(k, v, bill):
    return format(v, bill) if k == "monthly_bill" and isinstance(v, float) else v


def _bill(t):
    # "65.00" or "65.0" in the file, going by the first row that fits
    for r in t["rows"]:
        if _fit(r) is not None:
            s = str(r.get("monthly_bill", ""))
            return ".2f" if "." in s and len(s.split(".")[1]) == 2 else ""
    return ""


def _indent(body):
    lines = body.split("\n", 2)
    if len(lines) < 2:
        return None
    lead = lines[1][:len(lines[1]) - len(lines[1].lstrip(" \t"))]
    return lead if "\t" in lead else len(lead)


def _write(path, data, mode, times=None, owner=None):
    # the whole file through a temp file, so nobody reads half of it
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if owner:
            try:
                os.chown(tmp, *owner)
            except OSError:
                pass  # only root can give a file away, keeping your own always works
        os.chmod(tmp, mode)
        if times:
            os.utime(tmp, ns=times)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _fail(msg):
    print(msg, file=sys.stderr)
    return 1
