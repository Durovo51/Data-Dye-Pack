"""Checks for the minefield bridge."""

import unittest
import uuid
from datetime import datetime, timezone

from dyepack import bridge, drive
from dyepack.tripwire import Tripwire


def hit(**kw):
    base = {"event_id": str(uuid.uuid4()), "server_id": "web-01", "timestamp": "2026-11-14T22:03:05Z",
            "file": "/srv/finance/all_customers_full_export_2026.csv", "username": "www-data",
            "login_username": "miles", "uid": 33, "euid": 33, "auid": 1000, "process": "/usr/bin/cat",
            "process_name": "cat", "pid": "4242", "ppid": 4200, "access_type": "read", "success": True,
            "source": "auditd", "audit_id": "1731621785.123:456", "session_id": 7}
    base.update(kw)
    return base


class BridgeTest(unittest.TestCase):
    def test_hit_becomes_an_fs_event(self):
        ev = bridge.to_fs_event(hit())
        when = datetime(2026, 11, 14, 22, 3, 5, tzinfo=timezone.utc).timestamp()
        self.assertEqual(ev, {"ts": when, "pid": 4242, "process": "/usr/bin/cat", "signing_id": None,
                              "path": "/srv/finance/all_customers_full_export_2026.csv", "op": "read",
                              "server_id": "web-01", "username": "miles"})

    def test_timestamps_in_any_common_shape(self):
        self.assertEqual(bridge.to_fs_event(hit(timestamp=1763150000.5))["ts"], 1763150000.5)
        self.assertEqual(bridge.to_fs_event(hit(timestamp=1763150000500))["ts"], 1763150000.5)
        self.assertEqual(bridge.to_fs_event(hit(timestamp="1763150000"))["ts"], 1763150000.0)
        self.assertAlmostEqual(bridge.to_fs_event(hit(timestamp="soon"))["ts"],
                               datetime.now().timestamp(), delta=5)

    def test_fallbacks(self):
        ev = bridge.to_fs_event(hit(process=None, login_username="", pid=None, access_type="exec"))
        self.assertEqual((ev["process"], ev["username"], ev["pid"], ev["op"]), ("cat", "www-data", None, "read"))
        self.assertEqual(bridge.to_fs_event(hit(access_type="WRITE"))["op"], "write")

    def test_hit_without_a_file_is_refused(self):
        for bad in (hit(file=None), hit(file=""), "nope", None):
            with self.assertRaises(ValueError):
                bridge.to_fs_event(bad)

    def test_seen_drops_repeats(self):
        key = str(uuid.uuid4())
        self.assertFalse(bridge.seen(key))
        self.assertTrue(bridge.seen(key))
        self.assertFalse(bridge.seen(None))
        self.assertFalse(bridge.seen(""))

    def test_seen_forgets_the_oldest(self):
        first = str(uuid.uuid4())
        bridge.seen(first)
        for _ in range(bridge.KEEP):
            bridge.seen(str(uuid.uuid4()))
        self.assertFalse(bridge.seen(first))

    def test_accept_handles_retries_lists_and_junk(self):
        one = hit()
        self.assertEqual(len(bridge.accept(one)), 1)
        self.assertEqual(bridge.accept(one), [])  # agent retried the same hit
        key = str(uuid.uuid4())
        batch = [hit(), hit(file=None), "junk", hit()]
        self.assertEqual(len(bridge.accept(batch, key)), 2)
        self.assertEqual(bridge.accept([hit()], key), [])  # same Idempotency-Key

    def test_key_that_is_the_event_id_still_lets_the_first_one_in(self):
        one = hit()
        self.assertEqual(len(bridge.accept(one, one["event_id"])), 1)
        self.assertEqual(bridge.accept(one, one["event_id"]), [])
        self.assertEqual(bridge.accept(one), [])

    def test_remote_hit_trips_a_decoy_in_the_tripwire(self):
        events = []
        trip = Tripwire(lambda kind, s, sev, d: events.append((kind, s["actor"], d)) or {"detail": d},
                        lambda *a: None, [])
        ev = bridge.accept(hit())[0]
        trip.decoys.append(bridge.decoy_entry(ev))
        self.assertIsNotNone(drive.decoy_for(ev["path"], trip.decoys))
        trip.file_events([ev])
        alarms = [d for kind, _, d in events if kind == "alarm"]
        self.assertEqual([a["reason"] for a in alarms], ["decoy_open"])
        self.assertEqual(alarms[0]["path"], drive.decoy_for(ev["path"], trip.decoys)["path"])


if __name__ == "__main__":
    unittest.main()
