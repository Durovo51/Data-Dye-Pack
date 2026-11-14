import base64
import contextlib
import io
import json
import re
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

from dyepack import notify

TOPIC = "dyepack-0123456789abcdef01234567"
SID = "ACfakesidfortestsonly0123456789abc"  # not hex. no scanner takes it for a real sid
TWILIO_TOKEN = "twilio-secret-0123456789"
WEBHOOK = "https://discord.com/api/webhooks/123456/hook-secret-abcdef"
SECRETS = (TOPIC, SID, TWILIO_TOKEN, WEBHOOK, "hook-secret")
EVERYTHING = {"NTFY_TOPIC": TOPIC, "DISCORD_WEBHOOK_URL": WEBHOOK, "TWILIO_ACCOUNT_SID": SID,
              "TWILIO_AUTH_TOKEN": TWILIO_TOKEN, "TWILIO_FROM": "+15550001111", "ALERT_SMS_TO": "+15550002222"}
INCIDENT = {"id": "inc-2", "severity": "critical", "summary": "Stolen logins from export exp-2"}
ALL = ["push", "sms", "email", "discord"]


class Net:
    """Stands in for urlopen: keeps every request and answers from a queue."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        answer = self.answers.pop(0) if self.answers else b"{}"
        if isinstance(answer, Exception):
            raise answer
        return io.BytesIO(answer)


class NotifyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        bucket = mock.patch.object(notify, "_pushes", notify._Bucket())
        bucket.start()
        self.addCleanup(bucket.stop)

    def env(self, **settings):
        path = Path(self.dir.name) / ".env"
        path.write_text("".join(f"{k}={v}\n" for k, v in settings.items()))
        return path

    def send(self, net, incident, channels, env):
        with mock.patch("urllib.request.urlopen", net):
            return notify.send(incident, channels, env)

    def test_everything_is_simulated_without_settings(self):
        net = Net()
        self.assertEqual(self.send(net, INCIDENT, ALL, self.env()), [{"channel": c, "status": "simulated"} for c in ALL])
        self.assertEqual(net.requests, [])

    def test_push_goes_to_ntfy(self):
        net = Net()
        self.assertEqual(self.send(net, INCIDENT, ["push"], self.env(NTFY_TOPIC=TOPIC)),
                         [{"channel": "push", "status": "sent"}])
        req = net.requests[0]
        self.assertEqual((req.get_method(), req.full_url), ("POST", "https://ntfy.sh/" + TOPIC))
        self.assertEqual(req.get_header("Title"), "Dyepack critical alarm inc-2")
        self.assertEqual(req.get_header("Priority"), "urgent")
        self.assertEqual(req.get_header("Tags"), "dyepack,critical,inc-2")
        self.assertEqual(req.data.decode().splitlines(),
                         ["Stolen logins from export exp-2", "Incident inc-2, severity critical, Lakeview Fiber lab data."])

    def test_high_alarms_push_at_high_priority_and_messages_stay_tidy(self):
        net = Net()
        odd = {"incident": "inc-" + chr(233), "severity": "high", "title": "Bulk read\nby rep.jordan"}
        self.send(net, odd, ["push"], self.env(NTFY_TOPIC=TOPIC))
        req = net.requests[0]
        self.assertEqual(req.get_header("Priority"), "high")
        self.assertEqual(req.get_header("Title"), "Dyepack high alarm inc-?")
        self.assertEqual(len(req.data.decode().splitlines()), 2)
        self.assertTrue(req.data.decode().startswith("Bulk read by rep.jordan\n"))

    def test_sms_needs_all_four_settings(self):
        partial = {k: v for k, v in EVERYTHING.items() if k != "ALERT_SMS_TO"}
        net = Net()
        self.assertEqual(self.send(net, INCIDENT, ["sms"], self.env(**partial)), [{"channel": "sms", "status": "simulated"}])
        self.assertEqual(net.requests, [])

        self.assertEqual(self.send(net, INCIDENT, ["sms"], self.env(**EVERYTHING)), [{"channel": "sms", "status": "sent"}])
        req = net.requests[0]
        self.assertEqual(req.full_url, f"https://api.twilio.com/2010-04-01/Accounts/{SID}/Messages.json")
        self.assertEqual(req.get_header("Authorization"), "Basic " + base64.b64encode(f"{SID}:{TWILIO_TOKEN}".encode()).decode())
        form = urllib.parse.parse_qs(req.data.decode())
        self.assertEqual((form["To"], form["From"]), (["+15550002222"], ["+15550001111"]))
        self.assertEqual(form["Body"], ["Dyepack critical alarm inc-2: Stolen logins from export exp-2"])

    def test_discord_webhook(self):
        net = Net(b"")
        self.assertEqual(self.send(net, INCIDENT, ["discord"], self.env(DISCORD_WEBHOOK_URL=WEBHOOK)),
                         [{"channel": "discord", "status": "sent"}])
        req = net.requests[0]
        self.assertEqual((req.full_url, req.get_header("Content-type")), (WEBHOOK, "application/json"))
        self.assertEqual(json.loads(req.data), {"content": "Dyepack critical alarm inc-2\nStolen logins from export exp-2",
                                                "allowed_mentions": {"parse": []}})
        self.assertEqual(req.get_header("User-agent"), "dyepack/0.1")

    def test_failures_report_failed_and_never_leak_secrets(self):
        env = self.env(**EVERYTHING)
        for trouble in (urllib.error.HTTPError(WEBHOOK, 401, "Unauthorized", {}, io.BytesIO(TWILIO_TOKEN.encode())),
                        urllib.error.URLError(f"no route to {WEBHOOK}"), TimeoutError("timed out")):
            out = self.send(Net(trouble, trouble, trouble), INCIDENT, ALL, env)
            self.assertEqual([o["status"] for o in out], ["failed", "failed", "simulated", "failed"])
            for secret in SECRETS:
                self.assertNotIn(secret, json.dumps(out))

    def test_unknown_channel_fails(self):
        self.assertEqual(self.send(Net(), INCIDENT, ["pager"], self.env()), [{"channel": "pager", "status": "failed"}])

    def test_pushes_are_throttled(self):
        with mock.patch("time.monotonic", return_value=1000.0):
            with mock.patch.object(notify, "_pushes", notify._Bucket(size=2, every=5.0)):
                net = Net()
                env = self.env(NTFY_TOPIC=TOPIC)
                out = [self.send(net, INCIDENT, ["push"], env)[0]["status"] for _ in range(3)]
        self.assertEqual(out, ["sent", "sent", "failed"])
        self.assertEqual(len(net.requests), 2)

    def test_topic_helper_prints_a_long_random_name(self):
        names = []
        for _ in range(2):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(notify.main(["topic"]), 0)
            names.append(out.getvalue().strip())
        self.assertRegex(names[0], r"^dyepack-[0-9a-f]{24}$")
        self.assertNotEqual(names[0], names[1])

    def test_test_command_prints_only_status_and_safe_reasons(self):
        env = self.env(**EVERYTHING)
        denied = urllib.error.HTTPError(WEBHOOK, 401, "Unauthorized", {}, io.BytesIO(b""))
        out = io.StringIO()
        with mock.patch("urllib.request.urlopen", Net(b"{}", denied, b"")), contextlib.redirect_stdout(out):
            code = notify.main(["test"], path=env)
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), "push: sent\nsms: failed (HTTP 401)\nemail: simulated\ndiscord: sent\n")
        for secret in SECRETS:
            self.assertNotIn(secret, out.getvalue())


if __name__ == "__main__":
    unittest.main()
