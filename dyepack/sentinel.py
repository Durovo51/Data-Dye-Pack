"""The sentinel watches file activity and forwards what happens on the protected drive to the
dyepack server. macOS reads the system's own event stream through eslogger (needs root), Linux
uses inotify on the drive folders, and the fake backend replays JSON lines for tests and drills.
Events carry paths and process info only, never file contents.
"""

import http.client
import json
import os
import queue
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import schema

ESLOGGER = "/usr/bin/eslogger"
FOLD = sys.platform == "darwin"  # macOS disks are case insensitive by default
LOCAL = ("127.0.0.1", "localhost", "::1")
# system helpers that read files on their own: Spotlight, fseventsd, Time Machine, Quick Look
NOISE_NAMES = {
    "mds", "mds_stores", "mdworker", "mdworker_shared", "mdimport", "mdsync", "corespotlightd",
    "spotlightknowledged", "fseventsd", "backupd", "backupd-helper", "quicklookd",
    "QuickLookUIService", "QuickLookSatellite", "revisiond",
}
NOISE_IDS = (
    "com.apple.mds", "com.apple.mdworker", "com.apple.metadata", "com.apple.corespotlight",
    "com.apple.spotlight", "com.apple.fseventsd", "com.apple.backupd", "com.apple.TimeMachine",
    "com.apple.quicklook", "com.apple.QuickLook", "com.apple.revisiond",
)
# inotify bits
IN_ACCESS, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO = 0x1, 0x20, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_IGNORED, IN_ISDIR = 0x100, 0x200, 0x8000, 0x40000000
# an inotify open can't say read or write, so it's "open". the read call after it is "read"
OPS = ((IN_OPEN, "open"), (IN_ACCESS, "read"), (IN_MOVED_FROM, "rename"), (IN_DELETE, "delete"))


def run(roots, server_url, backend="auto", source=None, echo=False):
    """Forwards file events under roots to the server until the source ends or Ctrl-C.
    Each event is {"ts", "pid", "process", "signing_id", "path", "op"} with op one of read, write,
    rename, delete or open (Linux, where an open doesn't say which). Returns how many events
    the server took."""
    roots = _roots(roots)
    post = _Poster(server_url)
    backend = pick_backend(backend)
    if backend == "eslogger":
        events = _eslogger(roots)
    elif backend == "inotify":
        events = _inotify(roots)
    elif backend == "fake":
        events = _fake(source, roots)
    else:
        post.close()
        raise ValueError(f"no file watcher for {sys.platform}, try --backend fake")
    me = os.getpid()
    try:
        for ev in events:
            if ev["pid"] == me or not _under(ev["path"], roots):
                continue
            post.put(ev)
            if echo:
                _show(ev)
    except KeyboardInterrupt:
        pass
    finally:
        events.close()
        post.close()
    return post.sent


def pick_backend(backend="auto"):
    if backend != "auto":
        return backend
    return {"darwin": "eslogger", "linux": "inotify"}.get(sys.platform, "none")


def default_root():
    """The drive to watch. Under sudo the home folder is still the user's, not root's."""
    user = os.environ.get("SUDO_USER")
    if user and "DYEPACK_DRIVE" not in os.environ and os.geteuid() == 0:
        import pwd
        try:
            return Path(pwd.getpwnam(user).pw_dir) / "LakeviewFiber"
        except KeyError:
            pass
    return Path(schema.DRIVE_ROOT)


def from_eslogger(msg, roots):
    """One eslogger JSON event -> fs event, or None when it's off the drive, a folder or noise."""
    ev, proc = msg.get("event") or {}, msg.get("process") or {}
    if "open" in ev:
        f = ev["open"].get("file") or {}
        mode = (f.get("stat") or {}).get("st_mode")
        if mode and stat.S_ISDIR(mode):
            return None
        # fflag holds the kernel's FREAD (1) and FWRITE (2) bits
        paths, op = [_path(f)], "write" if (ev["open"].get("fflag") or 0) & 2 else "read"
    elif "rename" in ev:
        r = ev["rename"]
        dest = r.get("destination") or {}
        if "existing_file" in dest:
            to = _path(dest["existing_file"])
        elif "new_path" in dest:
            folder, name = _path(dest["new_path"].get("dir")), dest["new_path"].get("filename")
            to = os.path.join(folder, name) if folder and name else None
        else:
            to = _path(dest)
        paths, op = [_path(r.get("source")), to], "rename"
    elif "unlink" in ev:
        paths, op = [_path(ev["unlink"].get("target"))], "delete"
    else:
        return None
    path = next((p for p in paths if p and _under(p, roots)), None)
    token = proc.get("audit_token") or {}
    exe = _path(proc.get("executable")) or "unknown"
    signing_id = proc.get("signing_id") or None
    if path is None or _noise(exe, signing_id, proc.get("is_platform_binary")):
        return None
    return _event(path, op, token.get("pid", proc.get("pid")), exe, signing_id)


def cmd_sentinel(args):
    roots = [Path(r).expanduser() for r in (getattr(args, "root", None) or [default_root()])]
    url = getattr(args, "url", None) or f"http://127.0.0.1:{schema.DEFAULT_PORT}"
    backend = pick_backend(getattr(args, "backend", None) or "auto")
    missing = [r for r in roots if not r.is_dir()]
    if missing and backend != "fake":
        print(f"no drive at {missing[0]}, run dyepack drive first", file=sys.stderr)
        return 1
    print(f"watching {', '.join(map(str, roots))} with {backend}, sending to {url} (Ctrl-C stops)", flush=True)
    try:
        sent = run(roots, url, backend, getattr(args, "source", None), echo=not getattr(args, "quiet", False))
    except (OSError, RuntimeError, ValueError) as e:
        print(e, file=sys.stderr)
        return 1
    print(f"stopped, {sent:,} events sent")
    return 0


def _eslogger(roots):
    if os.geteuid() != 0:
        raise PermissionError("eslogger needs root: start the sentinel with sudo, "
                              "and give your terminal app Full Disk Access")
    if not os.path.exists(ESLOGGER):
        raise RuntimeError(f"no {ESLOGGER} here, it comes with macOS 13 and newer")
    proc = subprocess.Popen([ESLOGGER, "open", "rename", "unlink"], stdout=subprocess.PIPE)
    try:
        yield from _from_eslogger(proc.stdout, roots, {proc.pid})
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait()
    if proc.returncode:
        raise RuntimeError(f"eslogger stopped (exit {proc.returncode}). It needs sudo, and your terminal app "
                           "needs Full Disk Access (System Settings, Privacy and Security)")


def _from_eslogger(lines, roots, skip=()):
    # the whole machine streams by, so only lines that mention a root get parsed.
    # some JSON writers escape slashes, so look for both spellings
    needles = None
    if all(r.isascii() for r in roots):
        needles = [n for r in roots for n in (r.encode(), r.replace("/", "\\/").encode())]
    for line in lines:
        low = line.lower() if FOLD else line
        if needles and not any(n in low for n in needles):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        ev = from_eslogger(msg, roots) if isinstance(msg, dict) else None
        if ev and ev["pid"] not in skip:
            yield ev


def _inotify(roots):
    import ctypes
    import ctypes.util
    import struct

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    fd = libc.inotify_init()
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init failed")
    dirs, recent = {}, {}
    mask = IN_ACCESS | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE

    def watch(top):
        for d, _, _ in os.walk(top):
            wd = libc.inotify_add_watch(fd, os.fsencode(d), mask)
            if wd >= 0:
                dirs[wd] = d

    try:
        for r in roots:
            watch(r)
        while True:
            buf, pos = os.read(fd, 1 << 16), 0
            while pos < len(buf):
                wd, bits, _, n = struct.unpack_from("iIII", buf, pos)
                name = buf[pos + 16:pos + 16 + n].rstrip(b"\0")
                pos += 16 + n
                if bits & IN_IGNORED:
                    dirs.pop(wd, None)
                if wd not in dirs:
                    continue
                path = os.path.join(dirs[wd], os.fsdecode(name)) if name else dirs[wd]
                if bits & IN_ISDIR:
                    if bits & (IN_CREATE | IN_MOVED_TO):
                        watch(path)  # new folders get watched too
                    continue
                op = next((o for bit, o in OPS if bits & bit), None)
                now = time.time()
                # a read fires once per read call, one event a second per file is plenty
                if op is None or recent.get((path, op), 0) > now - 1:
                    continue
                if len(recent) > 10_000:
                    recent.clear()
                recent[(path, op)] = now
                yield _event(path, op, ts=now)
    finally:
        os.close(fd)


def _fake(source, roots):
    # eslogger lines or plain {"path", "op", "pid", "process", "signing_id", "ts"} lines
    if source in (None, "-"):
        f = sys.stdin.buffer
    elif isinstance(source, (str, Path)):
        f = open(source, "rb")
    else:
        f = source
    try:
        for line in f:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            ev = from_eslogger(msg, roots) if "event" in msg else _plain(msg)
            if ev:
                yield ev
    finally:
        if f is not source and f is not sys.stdin.buffer:
            f.close()


def _plain(msg):
    path, process = msg.get("path"), msg.get("process") or "unknown"
    if not isinstance(path, str) or _noise(process, msg.get("signing_id")):
        return None
    return _event(path, msg.get("op") or "read", msg.get("pid"), process, msg.get("signing_id"), msg.get("ts"))


def _event(path, op, pid=None, process="unknown", signing_id=None, ts=None):
    return {"ts": time.time() if ts is None else ts, "pid": pid, "process": process,
            "signing_id": signing_id, "path": path, "op": op}


def _path(x):
    if isinstance(x, dict):
        x = x.get("path")
    return x if isinstance(x, str) else None


def _noise(exe, signing_id, platform=None):
    # only Apple's own binaries count as noise, so a program named mdworker still gets reported
    if platform is False:
        return False
    return os.path.basename(exe or "") in NOISE_NAMES or (signing_id or "").startswith(NOISE_IDS)


def _fold(path):
    if FOLD:
        path = path.lower()
        if path.startswith("/system/volumes/data/"):  # the data volume shows up under two names
            path = path[len("/system/volumes/data"):]
    return path


def _roots(roots):
    out = set()
    for r in roots:
        r = os.path.expanduser(str(r))
        for p in (os.path.abspath(r), os.path.realpath(r)):
            out.add(_fold(p.rstrip("/")))
    return sorted(out)


def _under(path, roots):
    p = _fold(path)
    return any(p == r or p.startswith(r + "/") for r in roots)


def _token():
    # the server's control token, read fresh each time so a server restart is fine. never printed
    try:
        return (Path(schema.DATA_DIR) / "control_token").read_text().strip() or None
    except OSError:
        return None


def _show(ev):
    who = os.path.basename(ev["process"])
    if ev["pid"] is not None:
        who += f" ({ev['pid']})"
    print(f"{time.strftime('%H:%M:%S', time.localtime(ev['ts']))}  {ev['op']:<6}  {who}  {ev['path']}", flush=True)


class _Poster:
    """Posts events to /lab/fs-event as JSON lists from a background thread, so a slow server
    never holds up the event stream. Keeps their order and holds them while the server is down."""

    def __init__(self, url, batch=50, keep=10_000):
        host = urllib.parse.urlsplit(url).hostname
        if host not in LOCAL:
            raise ValueError(f"the sentinel only talks to a dyepack server on this machine, not {host}")
        self.url = url.rstrip("/") + "/lab/fs-event"
        self.batch, self.keep = batch, keep
        self.sent = self.dropped = 0
        self.down = False
        self.q = queue.Queue()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through a proxy
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def put(self, ev):
        self.q.put(ev)

    def close(self, wait=10):
        self.q.put(None)
        self.thread.join(wait)

    def _loop(self):
        pending, closing = [], False
        while not closing or pending:
            try:
                # wait for events, or a second before trying a down server again
                item = self.q.get(timeout=1 if pending else None)
                while True:
                    if item is None:
                        closing = True
                    else:
                        pending.append(item)
                    item = self.q.get_nowait()
            except queue.Empty:
                pass
            while pending and self._send(pending[:self.batch]):
                del pending[:self.batch]
            if len(pending) > self.keep:
                self.dropped += len(pending) - self.keep
                del pending[:-self.keep]
            if closing and pending and self.down:
                self.dropped += len(pending)
                print(f"{len(pending):,} events never reached the server", file=sys.stderr)
                return

    def _send(self, chunk):
        headers = {"Content-Type": "application/json"}
        token = _token()
        if token:
            headers["X-Dyepack-Token"] = token
        req = urllib.request.Request(self.url, data=json.dumps(chunk).encode(), method="POST", headers=headers)
        try:
            with self.opener.open(req, timeout=5) as r:
                r.read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                # no token yet, or the server made a new one. hold on and try again
                if not self.down:
                    print(f"server said {e.code}, holding events until data/control_token works", file=sys.stderr)
                    self.down = True
                return False
            # the server is up but turned these down, so don't hold up the rest
            print(f"server said {e.code} to {len(chunk)} events, skipped them", file=sys.stderr)
            self.dropped += len(chunk)
            return True
        except (OSError, ValueError, http.client.HTTPException) as e:
            # no server yet is fine: keep watching and printing, and send once it's up
            if not self.down:
                print(f"can't reach the dyepack server at {self.url} ({e}). Still watching and printing "
                      "events, they go out once it's up", file=sys.stderr)
                self.down = True
            return False
        if self.down:
            print("dyepack server is back, sending held events", file=sys.stderr)
            self.down = False
        self.sent += len(chunk)
        return True
