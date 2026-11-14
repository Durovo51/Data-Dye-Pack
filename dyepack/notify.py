"""Alert routes: phone push through ntfy, SMS through Twilio, Discord and email.

A channel that isn't set up in .env is simulated. Messages only carry the incident id, the
severity, a one line summary and lab data, never secrets.
"""

import base64
import json
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .databricks import read_env

CHANNELS = ("push", "sms", "email", "discord")
SMS_KEYS = ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "ALERT_SMS_TO")


class Throttled(Exception):
    pass


class _Bucket:
    """ntfy.sh takes a burst of about 60 and then 1 every 5 s. This stays well under that."""

    def __init__(self, size=20, every=5.0):
        self.size, self.every = size, every
        self.tokens, self.last = float(size), time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.size, self.tokens + (now - self.last) / self.every)
            self.last = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


_pushes = _Bucket()


def _clean(text, limit):
    return " ".join(str(text).split())[:limit]


def _ascii(text):
    return text.encode("ascii", "replace").decode()


def _message(incident):
    inc = incident if isinstance(incident, dict) else {"id": incident}
    iid = _clean(inc.get("id") or inc.get("incident") or "unknown", 40)
    sev = _clean(inc.get("severity") or "high", 10)
    summary = _clean(inc.get("summary") or inc.get("title") or "Alarm in the Lakeview Fiber lab", 140)
    return {"id": iid, "severity": sev, "summary": summary, "title": f"Dyepack {sev} alarm {iid}"}


def _post(url, data, headers):
    req = urllib.request.Request(url, data=data, method="POST", headers={"User-Agent": "dyepack/0.1", **headers})
    with urllib.request.urlopen(req, timeout=10):
        pass


def _push(msg, env):
    topic = env.get("NTFY_TOPIC")
    if not topic:
        return "simulated"
    if not _pushes.take():
        raise Throttled()
    body = f"{msg['summary']}\nIncident {msg['id']}, severity {msg['severity']}, Lakeview Fiber lab data."
    _post("https://ntfy.sh/" + urllib.parse.quote(topic, safe=""), body.encode(), {
        "Title": _ascii(msg["title"]),
        "Priority": "urgent" if msg["severity"] == "critical" else "high",
        "Tags": _ascii(f"dyepack,{msg['severity']},{msg['id']}"),
    })
    return "sent"


def _sms(msg, env):
    if not all(env.get(k) for k in SMS_KEYS):
        return "simulated"
    sid = env["TWILIO_ACCOUNT_SID"]
    auth = base64.b64encode(f"{sid}:{env['TWILIO_AUTH_TOKEN']}".encode()).decode()
    text = f"Dyepack {msg['severity']} alarm {msg['id']}: {msg['summary']}"
    form = urllib.parse.urlencode({"To": env["ALERT_SMS_TO"], "From": env["TWILIO_FROM"], "Body": text})
    _post(f"https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(sid, safe='')}/Messages.json",
          form.encode(), {"Authorization": "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded"})
    return "sent"


def _email(msg, env):
    return "simulated"


def _discord(msg, env):
    url = env.get("DISCORD_WEBHOOK_URL")
    if not url:
        return "simulated"
    # no pings, even if a summary ever holds @everyone
    body = {"content": f"{msg['title']}\n{msg['summary']}", "allowed_mentions": {"parse": []}}
    _post(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    return "sent"


SENDERS = {"push": _push, "sms": _sms, "email": _email, "discord": _discord}


def _try(channel, msg, env):
    """(status, why). why is short and safe to print, like HTTP 401. Never a url, topic or token."""
    sender = SENDERS.get(channel)
    if sender is None:
        return "failed", "unknown channel"
    try:
        return sender(msg, env), ""
    except urllib.error.HTTPError as e:
        return "failed", f"HTTP {e.code}"
    except Exception as e:
        return "failed", type(e).__name__


def send(incident, channels, path=".env"):
    """One alert per channel. incident is {"id", "severity", "summary"} ("title" works as the summary).

    Returns [{"channel", "status"}] where status is sent, simulated or failed.
    """
    env, msg = read_env(path), _message(incident)
    return [{"channel": c, "status": _try(c, msg, env)[0]} for c in channels]


def main(argv=None, path=".env"):
    args = sys.argv[1:] if argv is None else argv
    if args == ["topic"]:
        # anyone who knows the topic can read the alerts, which is why it's long and random
        print("dyepack-" + secrets.token_hex(12))
        return 0
    if args == ["test"]:
        env = read_env(path)
        msg = _message({"id": "inc-test", "severity": "high", "summary": "Test alert from the Lakeview Fiber lab"})
        failed = 0
        for channel in CHANNELS:
            status, why = _try(channel, msg, env)
            failed += status == "failed"
            print(f"{channel}: {status}" + (f" ({why})" if why else ""))
        return 1 if failed else 0
    print("usage: python3 -m dyepack.notify topic|test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
