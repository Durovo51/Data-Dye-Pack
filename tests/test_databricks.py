import contextlib
import io
import json
import os
import re
import tempfile
import traceback
import unittest
import urllib.error
from datetime import date, datetime, timezone
from pathlib import Path
from unittest import mock

from dyepack import assay, databricks
from dyepack.databricks import Client, DatabricksError
from dyepack.schema import CUSTOMER_FIELDS

TOKEN = "dapi0123456789abcdef0123456789abcd"
HOST = "https://dbc-1234abcd.cloud.databricks.com"
STATEMENTS = HOST + "/api/2.0/sql/statements"


class Net:
    """Stands in for urlopen: keeps every request and answers from a queue."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return io.BytesIO(answer if isinstance(answer, bytes) else json.dumps(answer).encode())

    def body(self, i):
        return json.loads(self.requests[i].data)

    def statements(self):
        return [json.loads(r.data)["statement"] for r in self.requests if r.full_url == STATEMENTS]


def done(rows=None, **extra):
    res = {"statement_id": "s-1", "status": {"state": "SUCCEEDED"}, **extra}
    if rows is not None:
        res["result"] = {"data_array": rows}
    return res


def answer(content):
    return {"choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}


def http_error(code, body):
    return urllib.error.HTTPError(STATEMENTS, code, "Forbidden", {}, io.BytesIO(json.dumps(body).encode()))


def client(**kw):
    return Client(HOST, TOKEN, kw.pop("warehouse_id", "wh-1"), kw.pop("model", "chat-model"), **kw)


def offline(net):
    return mock.patch("urllib.request.urlopen", net)


def sentences(text):
    return re.split(r"(?<=[.!?])\s+", text.strip())


class EnvTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def env(self, text):
        path = Path(self.dir.name) / ".env"
        path.write_text(text)
        return path

    def test_reads_settings_and_fills_defaults(self):
        c = Client.from_env(self.env(
            "# databricks\n"
            "DATABRICKS_HOST = dbc-1234abcd.cloud.databricks.com/?o=99\n"
            f'DATABRICKS_TOKEN="{TOKEN}"\n'
            "\n"
            "DATABRICKS_WAREHOUSE_ID=/sql/1.0/warehouses/abc123\n"
            "DATABRICKS_MODEL=databricks-meta-llama-3-3-70b-instruct\n"
            "DATABRICKS_CATALOG=\n"
        ))
        self.assertEqual(c.host, HOST)
        self.assertEqual(c.warehouse_id, "abc123")
        self.assertEqual(c.model, "databricks-meta-llama-3-3-70b-instruct")
        self.assertEqual((c.catalog, c.schema), ("workspace", "dyepack"))
        self.assertNotIn(TOKEN, repr(c) + str(c))

    def test_missing_settings_give_none(self):
        self.assertIsNone(Client.from_env(Path(self.dir.name) / "missing.env"))
        self.assertIsNone(Client.from_env(self.env(f"DATABRICKS_HOST={HOST}\nDATABRICKS_TOKEN=\n")))
        example = Path(__file__).resolve().parent.parent / ".env.example"
        self.assertIsNone(Client.from_env(self.env(example.read_text())))


class SqlTests(unittest.TestCase):
    def test_request_shape(self):
        net = Net(done([["1"]]))
        with offline(net):
            self.assertEqual(client().sql("SELECT 1"), [["1"]])
        req = net.requests[0]
        self.assertEqual((req.get_method(), req.full_url), ("POST", STATEMENTS))
        self.assertEqual(req.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(net.body(0), {
            "warehouse_id": "wh-1", "statement": "SELECT 1", "wait_timeout": "30s",
            "on_wait_timeout": "CONTINUE", "disposition": "INLINE", "format": "JSON_ARRAY",
        })

    def test_polls_while_pending_or_running(self):
        net = Net({"statement_id": "s-9", "status": {"state": "PENDING"}},
                  {"statement_id": "s-9", "status": {"state": "RUNNING"}},
                  done([["2"]]))
        with offline(net), mock.patch("time.sleep") as sleep:
            self.assertEqual(client().sql("SELECT 2"), [["2"]])
        self.assertEqual([r.get_method() for r in net.requests], ["POST", "GET", "GET"])
        self.assertEqual({r.full_url for r in net.requests[1:]}, {STATEMENTS + "/s-9"})
        self.assertEqual(sleep.call_count, 2)

    def test_reads_every_chunk(self):
        link = "/api/2.0/sql/statements/s-1/result/chunks/1"
        net = Net(done(result={"data_array": [["a"]], "next_chunk_index": 1, "next_chunk_internal_link": link}),
                  {"chunk_index": 1, "data_array": [["b"], ["c"]]})
        with offline(net):
            self.assertEqual(client().sql("SELECT x"), [["a"], ["b"], ["c"]])
        self.assertEqual((net.requests[1].get_method(), net.requests[1].full_url), ("GET", HOST + link))

    def test_no_result_means_no_rows(self):
        with offline(Net(done())):
            self.assertEqual(client().sql("CREATE SCHEMA IF NOT EXISTS x"), [])

    def test_failed_statement_raises(self):
        net = Net({"statement_id": "s-1", "status": {"state": "FAILED", "error": {
            "error_code": "BAD_REQUEST", "message": "[TABLE_OR_VIEW_NOT_FOUND] alarms"}}})
        with offline(net), self.assertRaises(DatabricksError) as ctx:
            client().sql("SELECT * FROM alarms")
        self.assertEqual(ctx.exception.code, "BAD_REQUEST")
        self.assertIn("TABLE_OR_VIEW_NOT_FOUND", str(ctx.exception))

    def test_gives_up_and_cancels(self):
        net = Net({"statement_id": "s-5", "status": {"state": "RUNNING"}}, {})
        with offline(net), mock.patch("time.sleep"), self.assertRaises(DatabricksError) as ctx:
            client().sql("SELECT slow", timeout=0)
        self.assertEqual(ctx.exception.code, "TIMEOUT")
        last = net.requests[-1]
        self.assertEqual((last.get_method(), last.full_url), ("POST", STATEMENTS + "/s-5/cancel"))

    def test_needs_a_warehouse(self):
        net = Net()
        with offline(net), self.assertRaises(DatabricksError):
            client(warehouse_id="").sql("SELECT 1")
        self.assertEqual(net.requests, [])


class ChatTests(unittest.TestCase):
    def test_request_shape(self):
        net = Net(answer("  Caught it.  "))
        msgs = [{"role": "user", "content": "hi"}]
        with offline(net):
            self.assertEqual(client(model="databricks-meta-llama-3-3-70b-instruct").chat(msgs), "Caught it.")
        req = net.requests[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.full_url, HOST + "/serving-endpoints/databricks-meta-llama-3-3-70b-instruct/invocations")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertEqual(net.body(0), {"messages": msgs, "max_tokens": 400, "temperature": 0.2})

    def test_keeps_only_text_blocks_from_reasoning_models(self):
        blocks = [{"type": "reasoning", "summary": [{"type": "summary_text", "text": "thinking it over"}]},
                  {"type": "text", "text": "The real answer."}]
        with offline(Net(answer(blocks))):
            self.assertEqual(client().chat([{"role": "user", "content": "hi"}]), "The real answer.")

    def test_needs_a_model(self):
        net = Net()
        with offline(net), self.assertRaises(DatabricksError):
            client(model="").chat([{"role": "user", "content": "hi"}])
        self.assertEqual(net.requests, [])

    def test_odd_reply_raises(self):
        with offline(Net({"predictions": [1]})), self.assertRaises(DatabricksError):
            client().chat([{"role": "user", "content": "hi"}])


class TokenTests(unittest.TestCase):
    def assertClean(self, err):
        text = str(err) + repr(err) + "".join(traceback.format_exception(type(err), err, err.__traceback__))
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("Bearer", text)

    def test_http_error(self):
        err = http_error(403, {"error_code": "PERMISSION_DENIED", "message": f"Invalid access token {TOKEN}"})
        with offline(Net(err)), self.assertRaises(DatabricksError) as ctx:
            client().sql("SELECT 1")
        self.assertEqual((ctx.exception.status, ctx.exception.code), (403, "PERMISSION_DENIED"))
        self.assertClean(ctx.exception)

    def test_network_error(self):
        with offline(Net(urllib.error.URLError("nodename nor servname provided"))), \
                self.assertRaises(DatabricksError) as ctx:
            client().chat([{"role": "user", "content": "hi"}])
        self.assertEqual(ctx.exception.code, "NETWORK")
        self.assertClean(ctx.exception)

    def test_timeout_and_bad_json(self):
        for trouble, code in ((TimeoutError("timed out"), "NETWORK"), (b"<html>sign in</html>", "BAD_REPLY")):
            with offline(Net(trouble)), self.assertRaises(DatabricksError) as ctx:
                client().sql("SELECT 1")
            self.assertEqual(ctx.exception.code, code)
            self.assertClean(ctx.exception)

    def test_failed_statement_is_scrubbed(self):
        net = Net({"status": {"state": "FAILED", "error": {"message": f"echo {TOKEN}"}}})
        with offline(net), self.assertRaises(DatabricksError) as ctx:
            client().sql("SELECT 1")
        self.assertClean(ctx.exception)

    def live_check(self, net, text):
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / ".env"
            env.write_text(text)
            out = io.StringIO()
            with offline(net), contextlib.redirect_stdout(out):
                code = databricks.check(env)
        return code, out.getvalue()

    def test_live_check_prints_only_the_result(self):
        env = f"DATABRICKS_HOST={HOST}\nDATABRICKS_TOKEN={TOKEN}\nDATABRICKS_WAREHOUSE_ID=wh-1\nDATABRICKS_MODEL=m\n"
        code, out = self.live_check(Net(done([["1"]]), answer("ok")), env)
        self.assertEqual((code, out), (0, "SELECT 1: ok\nchat: ok\n"))

        denied = {"error_code": "PERMISSION_DENIED", "message": f"bad token {TOKEN}"}
        code, out = self.live_check(Net(http_error(403, denied), http_error(403, denied)), env)
        self.assertEqual(code, 1)
        self.assertEqual(out, "SELECT 1: failed (HTTP 403 PERMISSION_DENIED)\nchat: failed (HTTP 403 PERMISSION_DENIED)\n")

        code, out = self.live_check(Net(), "DATABRICKS_HOST=\n")
        self.assertEqual(code, 1)
        self.assertNotIn(TOKEN, out)


class TableTests(unittest.TestCase):
    def test_ensure_tables(self):
        net = Net(*[done() for _ in range(6)])
        with offline(net):
            client().ensure_tables()
        st = net.statements()
        self.assertEqual(st[0], "CREATE SCHEMA IF NOT EXISTS `workspace`.`dyepack`")
        made = [s.split(" (")[0] for s in st[1:]]
        self.assertEqual(made, [f"CREATE TABLE IF NOT EXISTS `workspace`.`dyepack`.`{t}`"
                                for t in ("customers", "customers_clean", "alarms", "reports", "exports")])
        self.assertIn("monthly_bill DOUBLE, since_year INT, portal_user STRING", st[1])

    def test_literals(self):
        lit = databricks._lit
        self.assertEqual([lit(None), lit(True), lit(False), lit(7), lit(2.5), lit(float("nan"))],
                         ["NULL", "TRUE", "FALSE", "7", "2.5", "NULL"])
        self.assertEqual(lit("O'Brien"), r"'O\'Brien'")
        self.assertEqual(lit("C:\\temp\\'x"), r"'C:\\temp\\\'x'")
        self.assertEqual(lit("${env:HOME}"), r"'\u0024{env:HOME}'")
        self.assertEqual(lit(["c-001"]), "'[\"c-001\"]'")
        self.assertEqual(lit(datetime.fromtimestamp(1763150000.5, timezone.utc)), "timestamp_seconds(1763150000.5)")

    def test_push_rows_batches_and_escapes(self):
        c = client()
        c._ready = True
        rows = [{"plan": "Fiber 1 Gig", "note": "it's"}, {"plan": None, "note": "a\\b"}, {"plan": "DSL 25", "note": ""}]
        net = Net(done(), done())
        with offline(net):
            self.assertEqual(c.push_rows("customers", rows, batch=2), 3)
        head = "INSERT INTO `workspace`.`dyepack`.`customers` (`plan`, `note`) VALUES "
        self.assertEqual(net.statements(), [
            head + r"('Fiber 1 Gig', 'it\'s'), (NULL, 'a\\b')",
            head + "('DSL 25', '')",
        ])

    def test_push_event_routes_and_makes_tables_once(self):
        alarm = {"ts": 1763150000.5, "type": "alarm", "session": "s-3", "actor": "rep.jordan", "ip": "10.0.0.7",
                 "severity": "high", "detail": {"reason": "speed", "incident": "inc-1",
                                                "canary_ids": ["c-001", "c-002"], "export_id": None, "rate_per_min": 3100}}
        report = {"ts": 1763150001, "type": "report", "severity": "info",
                  "detail": {"incident": "inc-1", "title": "Bulk read", "text": "It's caught.", "source": "template"}}
        export = {"ts": 1763150002, "type": "export", "session": "s-4", "actor": "rep.casey", "ip": "10.0.0.8",
                  "severity": "info", "detail": {"export_id": "exp-2", "rows": 50000, "canaries": 200}}
        tick = {"ts": 1763150003, "type": "tick", "detail": {"reads_per_min": 10, "sessions": 1}}
        net = Net(*[done() for _ in range(9)])
        c = client()
        with offline(net):
            self.assertEqual([c.push_event(e) for e in (alarm, report, export, tick)], [1, 1, 1, 0])
        st = net.statements()
        self.assertEqual(len(st), 9)  # 6 to make the tables once, then one insert per event
        self.assertTrue(st[6].startswith("INSERT INTO `workspace`.`dyepack`.`alarms` (`ts`, `incident`, `reason`"))
        self.assertIn("(timestamp_seconds(1763150000.5), 'inc-1', 'speed', 'high', 's-3', 'rep.jordan', "
                      "'10.0.0.7', 2, 'c-001,c-002', NULL, 3100, ", st[6])
        self.assertTrue(st[7].startswith("INSERT INTO `workspace`.`dyepack`.`reports`"))
        self.assertIn(r"'inc-1', 'Bulk read', 'It\'s caught.', 'template'", st[7])
        self.assertTrue(st[8].startswith("INSERT INTO `workspace`.`dyepack`.`exports`"))
        self.assertIn("'exp-2', 's-4', 'rep.casey', '10.0.0.8', 50000, 200)", st[8])


def heist():
    """Heist step 1 as the server would log it, plus noise from other sessions."""
    jordan = {"session": "s-3", "actor": "rep.jordan", "ip": "10.0.0.7"}
    ev = [{"ts": 90.0, "type": "tick", "severity": "info", "detail": {"reads_per_min": 40, "sessions": 2}},
          {"ts": 95.0, "type": "read", "session": "s-1", "actor": "rep.casey", "ip": "10.0.0.5", "severity": "info",
           "detail": {"rows": 1, "canaries": 0, "path": "/api/customers/LV00000001"}}]
    ev += [{"ts": 100.0 + i / 2, "type": "read", **jordan, "severity": "info",
            "detail": {"rows": 500, "canaries": 2, "path": "/api/customers"}} for i in range(8)]
    ev.append({"ts": 104.2, "type": "alarm", **jordan, "severity": "high",
               "detail": {"reason": "speed", "incident": "inc-1", "canary_ids": [f"c-{i:03d}" for i in range(1, 8)],
                          "export_id": None, "rate_per_min": 3100}})
    ev.append({"ts": 104.3, "type": "lock", **jordan, "severity": "high", "detail": {"incident": "inc-1", "what": "session"}})
    ev.append({"ts": 104.9, "type": "read", **jordan, "severity": "info", "detail": {"rows": 500, "canaries": 1}})
    return ev


def stolen_logins():
    """Heist step 3: the export, then logins with usernames from cracked copies."""
    def login(ts, reason, ids, export_id):
        return {"ts": ts, "type": "alarm", "session": None, "actor": "jsmith07", "ip": "203.0.113.9",
                "severity": "critical", "detail": {"reason": reason, "incident": "inc-2", "canary_ids": ids,
                                                   "export_id": export_id, "rate_per_min": 0}}
    return [{"ts": 200.0, "type": "export", "session": "s-4", "actor": "rep.casey", "ip": "10.0.0.8", "severity": "info",
             "detail": {"export_id": "exp-2", "rows": 50000, "canaries": 200}},
            login(300.0, "canary_login", ["c-301"], "exp-2"),
            login(301.0, "unknown_account_login", [], None),
            login(302.5, "canary_login", ["c-302"], "exp-2")]


def human_touch():
    """A rep doing normal lookups lands on one canary."""
    casey = {"session": "s-1", "actor": "rep.casey", "ip": "10.0.0.5", "severity": "info"}
    ev = [{"ts": 50.0 + i * 20, "type": "read", **casey, "detail": {"rows": 10, "canaries": 0}} for i in range(4)]
    ev.append({"ts": 130.0, "type": "read", **casey, "detail": {"rows": 10, "canaries": 1}})
    ev.append({"ts": 130.1, "type": "alarm", **casey, "severity": "low",
               "detail": {"reason": "canary_touch", "incident": "inc-3", "canary_ids": ["c-044"], "rate_per_min": 30}})
    return ev


LAB = "/Users/lab/LakeviewFiber"
NODE = {"session": "f-4242", "actor": "node", "ip": "127.0.0.1"}


def file_read(ts, path, fpm, who=NODE, pid=4242):
    return {"ts": ts, "type": "read", **who, "severity": "info",
            "detail": {"path": path, "process": who["actor"], "pid": pid, "files_per_min": fpm}}


def file_alarm(ts, reason, rate, path=None, who=NODE, incident="inc-4"):
    detail = {"reason": reason, "incident": incident, "canary_ids": [], "export_id": None, "rate_per_min": rate}
    if path:
        detail["path"] = path
    return {"ts": ts, "type": "alarm", **who, "severity": "critical" if path else "high", "detail": detail}


EXPORT_DECOY = f"{LAB}/customers/all_customers_full_export_2026.csv"


def lock_event(ts, folder, dyes, incident="inc-4"):
    """A burst as the server emits it: the .dye names, plus their full paths in vault."""
    return {"ts": ts, "type": "burst", "session": "", "actor": "dyepack", "ip": "127.0.0.1", "severity": "critical",
            "detail": {"incident": incident, "folder": folder, "files": [os.path.basename(p) for p in dyes],
                       "vault": ", ".join(dyes)}}


def drive_dig(real_first=False):
    """The agent from the mine map's replay. With real_first it reaches customers.csv before the lock."""
    backup, keys = f"{LAB}/backups/all_customers_backup_unencrypted.csv", f"{LAB}/config/.env.production"
    first_try = (145.9, f"{LAB}/customers/customers.csv") if real_first else (146.6, f"{LAB}/customers/customers.csv.dye")
    ev = [file_read(143.0, f"{LAB}/support/notes.md", 4),
          file_read(145.6, EXPORT_DECOY, 9), file_alarm(145.8, "decoy_open", 9, EXPORT_DECOY),
          file_read(*first_try, 24), lock_event(146.2, f"{LAB}/customers", [f"{LAB}/customers/customers.csv.dye"]),
          file_read(147.5, f"{LAB}/backups/nightly_2026_11_13.dye", 66), file_alarm(147.65, "speed", 66),
          file_read(147.9, backup, 92), file_alarm(148.05, "decoy_open", 92, backup),
          file_read(148.3, keys, 118), file_alarm(148.45, "decoy_open", 118, keys),
          file_read(149.2, f"{LAB}/customers/customers.csv.dye", 180)]
    return sorted(ev, key=lambda e: e["ts"])


def linux_hit():
    """One hit from the Linux agent on another server, after the bridge."""
    web = {"session": "f-web-01-77", "actor": "python3", "ip": "web-01"}
    return [file_read(400.0, "/srv/backup/all.csv", 6, who=web, pid=77),
            file_alarm(400.0, "decoy_open", 6, "/srv/backup/all.csv", who=web, incident="inc-5")]


class FakeClient:
    def __init__(self, reply):
        self.reply, self.messages = reply, None

    def chat(self, messages, max_tokens=400, temperature=0.2):
        self.messages = messages
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class ReportTests(unittest.TestCase):
    def assertReadable(self, text):
        self.assertTrue(4 <= len(sentences(text)) <= 6, text)
        self.assertNotIn("\u2014", text)
        self.assertNotIn("\u2013", text)

    def test_template_for_a_bulk_read(self):
        r = assay.write_report({"id": "inc-1"}, heist())
        self.assertEqual((r["source"], r["title"]), ("template", "Bulk read by rep.jordan"))
        self.assertEqual((r["looks_like"], r["actions"]), ("ai_agent", ["revoke", "notify_customers"]))
        self.assertReadable(r["text"])
        for bit in ("4,000 customer rows", "3,100 rows a minute", "looks like a script or AI agent rather than a person",
                    "4.2 seconds", "session was locked", "7 canary customers", "c-005 and more",
                    "3,984 real customer rows were exposed before the lock",
                    "Next, revoke rep.jordan's login and tell the 3,984 affected customers."):
            self.assertIn(bit, r["text"])

    def test_template_for_stolen_logins(self):
        r = assay.write_report("inc-2", stolen_logins())
        self.assertEqual((r["source"], r["title"]), ("template", "Stolen logins from export exp-2"))
        self.assertEqual((r["looks_like"], r["actions"]), ("ai_agent", ["lock", "revoke", "notify_customers"]))
        self.assertReadable(r["text"])
        for bit in ("3 logins", "pace that looks like a script or AI agent", "very first request",
                    "used the logins of 2 canary customers",
                    "export exp-2", "49,800 real customer rows",
                    "Next, block where these logins came from, revoke export exp-2 and tell the 49,800 affected customers."):
            self.assertIn(bit, r["text"])

    def test_template_for_a_person_at_human_speed(self):
        r = assay.write_report("inc-3", human_touch())
        self.assertEqual((r["title"], r["looks_like"], r["actions"]), ("Canary touched by rep.casey", "person", ["dismiss"]))
        self.assertReadable(r["text"])
        for bit in ("looks like a person rather than a script or AI agent", "1 canary customer (c-044)",
                    "49 real customer rows were read so far", "false alarm"):
            self.assertIn(bit, r["text"])

    def test_template_survives_odd_input(self):
        for incident, events in (("inc-9", []), (None, None), ({"id": "inc-9"}, [None, "junk", {"type": "alarm"},
                                                                              {"type": "alarm", "ts": "soon", "detail": "x"}])):
            r = assay.write_report(incident, events)
            self.assertEqual((r["source"], r["looks_like"], r["actions"]), ("template", "person", ["dismiss"]))
            self.assertReadable(r["text"])

    def test_template_for_a_decoy_on_the_drive(self):
        with mock.patch.dict(os.environ, {"HOME": "/Users/lab"}):
            r = assay.write_report({"id": "inc-4"}, drive_dig())
        self.assertEqual((r["title"], r["looks_like"], r["actions"]), ("Decoy files opened by node", "ai_agent", ["lock"]))
        self.assertReadable(r["text"])
        for bit in ("A process called node (pid 4242) opened the decoy file "
                    "~/LakeviewFiber/customers/all_customers_full_export_2026.csv on the company drive",
                    "machine speed (peak 180 files a minute), which looks like a script or AI agent rather than a person",
                    "The first alarm fired 2.8 seconds after it started opening files.",
                    "Dyepack locked customers/customers.csv in place 400 ms later and it now sits there as "
                    "customers.csv.dye.",
                    "It opened 6 files in all and 3 of them were decoys.",
                    "It only got customers/customers.csv as a locked .dye file, which gives believable fakes "
                    "for any wrong password.",
                    "Next, lock the account that runs node and put the locked files back with dyepack unlock "
                    "once it's stopped."):
            self.assertIn(bit, r["text"])
        for wrong in ("an AI agent", "login", "revoke", "No customer rows were read"):
            self.assertNotIn(wrong, r["text"])

    def test_real_file_opened_before_the_lock(self):
        with mock.patch.dict(os.environ, {"HOME": "/Users/lab"}):
            r = assay.write_report("inc-4", drive_dig(real_first=True))
        self.assertEqual(r["actions"], ["lock", "notify_customers"])
        self.assertReadable(r["text"])
        for bit in ("It opened 7 files in all",
                    "Treat customers/customers.csv as exposed because it was opened while still readable.",
                    "Next, lock the account that runs node, tell the customers in customers/customers.csv and put "
                    "the locked files back with dyepack unlock once it's stopped."):
            self.assertIn(bit, r["text"])

    def test_every_folder_on_the_drive_gets_locked(self):
        dyes = [f"{LAB}/customers/customers.csv.dye", f"{LAB}/billing/invoices_2026_10.json.dye"]
        events = [file_read(143.0, f"{LAB}/billing/invoices_2026_10.json", 6),
                  file_read(145.6, EXPORT_DECOY, 9), file_alarm(145.8, "decoy_open", 9, EXPORT_DECOY),
                  lock_event(146.2, LAB, dyes), file_read(146.6, dyes[0], 12)]
        r = assay.write_report("inc-4", events)
        self.assertEqual((r["title"], r["looks_like"], r["actions"]),
                         ("Decoy file opened by node", "person", ["lock", "notify_customers"]))
        self.assertReadable(r["text"])
        for bit in ("a human pace (peak 12 files a minute), which looks like a person rather than a script or AI agent",
                    "Dyepack locked customers/customers.csv and billing/invoices_2026_10.json in place 400 ms later "
                    "and they now sit there as .dye files.",
                    "Treat billing/invoices_2026_10.json as exposed because it was opened while still readable.",
                    "tell the customers in billing/invoices_2026_10.json"):
            self.assertIn(bit, r["text"])

    def test_template_for_a_linux_agent_hit(self):
        r = assay.write_report("inc-5", linux_hit())
        self.assertEqual((r["title"], r["looks_like"], r["actions"]),
                         ("Decoy file opened by python3 on web-01", "person", ["lock"]))
        self.assertReadable(r["text"])
        for bit in ("python3 (pid 77) opened the decoy file /srv/backup/all.csv on web-01",
                    "a human pace (peak 6 files a minute)", "fired the moment it opened the decoy",
                    "Check what else it read on web-01", "Next, lock the account that runs python3 on web-01."):
            self.assertIn(bit, r["text"])
        self.assertNotIn("dye", r["text"])

    def test_fast_file_reads_without_a_decoy(self):
        events = [file_read(500.0 + i / 4, f"{LAB}/support/ticket_{i}.md", 6 * (i + 1)) for i in range(12)]
        r = assay.write_report("inc-6", events + [file_alarm(502.75, "speed", 72, incident="inc-6")])
        self.assertEqual((r["title"], r["looks_like"], r["actions"]),
                         ("Files opened at machine speed by node", "ai_agent", ["lock"]))
        self.assertReadable(r["text"])
        for bit in ("opened 12 files on the company drive at machine speed (peak 72 files a minute)",
                    "None of the files were decoys.", "No real customer file has been exposed so far.",
                    "Next, lock the account that runs node."):
            self.assertIn(bit, r["text"])

    def test_times_and_pace_match_the_dashboard(self):
        drew = {"session": "s-9", "actor": "rep.drew", "ip": "10.0.0.9"}
        events = [{"ts": 100.0, "type": "read", **drew, "severity": "info", "detail": {"rows": 200, "canaries": 0}},
                  {"ts": 100.08, "type": "alarm", **drew, "severity": "high",
                   "detail": {"reason": "speed", "incident": "inc-7", "canary_ids": [], "rate_per_min": 12000}}]
        text = assay.write_report("inc-7", events)["text"]
        self.assertIn("at machine speed (peak 12,000 rows a minute)", text)
        self.assertIn("The first alarm fired 80 ms after the activity started.", text)
        self.assertNotIn("reads a minute", text)
        self.assertNotIn("0.08", text)
        self.assertEqual([assay._dur(s) for s in (0, 0.0004, 0.08, 0.9994, 0.9995, 2.25, 4.2)],
                         ["under 1 ms", "under 1 ms", "80 ms", "999 ms", "1.0 seconds", "2.3 seconds", "4.2 seconds"])
        self.assertEqual([assay._later(s) for s in (0.0001, 0.4)], ["at the same moment", "400 ms later"])

    def test_time_to_catch_starts_at_the_first_read(self):
        login = {"ts": 60.0, "type": "login", "session": "s-3", "actor": "rep.jordan", "ip": "10.0.0.7",
                 "severity": "info", "detail": {"user": "rep.jordan", "ok": True, "where": "staff"}}
        r = assay.write_report({"id": "inc-1"}, [login] + heist())
        self.assertIn("The first alarm fired 4.2 seconds after the activity started", r["text"])
        # no reads at all, like portal logins: the clock starts at the session's first event
        outside = {"session": "p-1", "actor": "jsmith07", "ip": "203.0.113.9"}
        tries = [{"ts": 299.0, "type": "login", **outside, "severity": "info",
                  "detail": {"user": "jsmith07", "ok": False, "where": "portal"}},
                 {"ts": 299.5, "type": "alarm", **outside, "severity": "critical",
                  "detail": {"reason": "canary_login", "incident": "inc-8", "canary_ids": ["c-301"], "rate_per_min": 0}}]
        self.assertEqual(assay._facts("inc-8", tries)["seconds_to_first_alarm"], 0.5)

    def test_outside_sessions_never_revoke_a_login(self):
        p = {"session": "p-2", "actor": "richard.cook40@att.net", "ip": "203.0.113.50"}
        events = [{"ts": 600.0, "type": "alarm", **p, "severity": "critical",
                   "detail": {"reason": "canary_contact", "incident": "inc-9", "canary_ids": ["c-001"],
                              "export_id": None, "rate_per_min": None}},
                  {"ts": 600.0, "type": "lock", **p, "severity": "critical", "detail": {"incident": "inc-9", "what": "ip"}}]
        r = assay.write_report("inc-9", events)
        self.assertEqual(r["actions"], [])
        self.assertReadable(r["text"])
        self.assertIn("The alarm fired on the very first request and the address was locked.", r["text"])
        self.assertIn("Next, find which copy of the customer list held that canary", r["text"])
        self.assertNotIn("revoke", r["text"])

    def test_model_gets_the_drive_facts(self):
        fake = FakeClient("A process called node opened a decoy file on the company drive at machine speed and was "
                          "caught in 2.8 seconds. Dyepack locked customers.csv in place 400 ms later. It only got the "
                          "locked copy after that. Next, lock the account that runs node and unlock the files later.")
        with mock.patch.dict(os.environ, {"HOME": "/Users/lab"}):
            r = assay.write_report("inc-4", drive_dig(), client=fake)
        self.assertEqual((r["source"], r["title"], r["looks_like"], r["actions"]),
                         ("databricks", "Decoy files opened by node", "ai_agent", ["lock"]))
        system, user = fake.messages
        self.assertIn("Name the decoy path", system["content"])
        facts = json.loads(user["content"].removeprefix("Facts: "))
        self.assertEqual((facts["kind"], facts["process"], facts["pid"], facts["host"], facts["peak_files_per_minute"]),
                         ("file drive", "node", 4242, None, 180))
        self.assertEqual(facts["decoy_paths"][0], "~/LakeviewFiber/customers/all_customers_full_export_2026.csv")
        self.assertEqual((facts["locked_files"], facts["locked_in"], facts["seconds_to_lock"]),
                         (["customers/customers.csv"], ["~/LakeviewFiber/customers"], 0.4))
        self.assertEqual((facts["real_files_exposed"], facts["locked_copies_opened"]), ([], ["customers/customers.csv"]))
        self.assertTrue(facts["next_step"].startswith("Next, lock the account that runs node"))
        self.assertNotIn("rows_read", facts)

    def test_model_writes_the_report(self):
        fake = FakeClient("rep.jordan pulled 4,000 rows at machine speed \u2014 caught in 4.2 seconds. "
                          "The session was locked. Seven canaries fired. About 3,984 real rows were exposed. "
                          "Reset the password and check the login source.")
        r = assay.write_report({"id": "inc-1"}, heist(), client=fake)
        self.assertEqual(r["source"], "databricks")
        self.assertEqual((r["title"], r["looks_like"], r["actions"]),
                         ("Bulk read by rep.jordan", "ai_agent", ["revoke", "notify_customers"]))
        self.assertTrue(r["text"].startswith("rep.jordan pulled 4,000 rows at machine speed, caught in 4.2 seconds."))
        system, user = fake.messages
        self.assertIn("4 to 6 plain English sentences", system["content"])
        self.assertIn("Machine speed means a script or AI agent. Never claim it was an AI from speed alone.",
                      system["content"])
        self.assertNotIn("file drive", system["content"])
        facts = json.loads(user["content"].removeprefix("Facts: "))
        self.assertEqual((facts["incident"], facts["canaries_touched"], facts["real_rows_exposed"]), ("inc-1", 7, 3984))
        self.assertEqual((facts["looks_like"], facts["recommended_actions"]), ("ai_agent", ["revoke", "notify_customers"]))

    def test_falls_back_on_errors_or_empty_text(self):
        for iid, events in (("inc-1", heist()), ("inc-4", drive_dig())):
            for reply in (DatabricksError("down", code="NETWORK"), RuntimeError("boom"), "", "Ok."):
                r = assay.write_report({"id": iid}, events, client=FakeClient(reply))
                self.assertEqual((r["source"], r["text"]), ("template", assay.write_report(iid, events)["text"]))

    def test_cuts_a_chopped_sentence(self):
        fake = FakeClient("The bulk read was caught in 4.2 seconds and the session was locked. Seven canaries were "
                          "touched. Reset the rep's password. About 3,984 real rows were exposed before the")
        r = assay.write_report({"id": "inc-1"}, heist(), client=fake)
        self.assertTrue(r["text"].endswith("Reset the rep's password."))

    def test_report_goes_through_a_real_client(self):
        net = Net(answer("The heist was caught in 4.2 seconds. The session was locked. Seven canaries fired."))
        with offline(net):
            r = assay.write_report({"id": "inc-1"}, heist(), client=client(model="reports-model"))
        self.assertEqual(r["source"], "databricks")
        self.assertEqual(net.requests[0].full_url, HOST + "/serving-endpoints/reports-model/invocations")


def fake_list(tag, n=20):
    return [{f: f"{tag}{i}" for f in CUSTOMER_FIELDS} for i in range(n)]


class PickTests(unittest.TestCase):
    def test_no_client_means_no_pick(self):
        r = assay.can_ai_tell([fake_list("a"), fake_list("b")])
        self.assertEqual((r["pick"], r["source"]), (None, "template"))

    def test_reads_a_json_pick(self):
        fake = FakeClient('Sure. {"pick": 2, "reason": "List 2 looks consistent \u2014 the bills match the plans"}')
        r = assay.can_ai_tell([fake_list("a"), fake_list("b"), fake_list("x")], client=fake)
        self.assertEqual((r["pick"], r["source"]), (1, "databricks"))
        self.assertNotIn("\u2014", r["reason"])
        shown = fake.messages[1]["content"]
        for tag in "abx":
            self.assertEqual(sum(line.startswith(f"{tag}") for line in shown.splitlines()), 5)
        self.assertIn("List 3:", shown)
        self.assertNotIn("List 4:", shown)

    def test_reads_a_plain_text_pick(self):
        r = assay.can_ai_tell([fake_list("a"), fake_list("b"), fake_list("c")], client=FakeClient("I'd say List 3 is real."))
        self.assertEqual(r["pick"], 2)

    def test_bad_answers_mean_no_pick(self):
        for reply in ('{"pick": 7}', "no idea", DatabricksError("down")):
            r = assay.can_ai_tell([fake_list("a"), fake_list("b"), fake_list("c")], client=FakeClient(reply))
            self.assertEqual((r["pick"], r["source"]), (None, "template"))


class NoticeTests(unittest.TestCase):
    @staticmethod
    def found(y, m, d):
        return datetime(y, m, d, 15, 0).timestamp()  # 3 PM local keeps every timezone on the same day

    def test_lines_and_dates(self):
        lines = assay.notice_checklist({"id": "inc-2"}, {"customers": 49800, "plaintext_rows": 49800,
                                                         "locked_copies": 1, "found_at": self.found(2026, 11, 13)})
        self.assertEqual(lines, [
            "Lab guidance, not legal advice",
            "Who is affected by inc-2: 49,800 customers (49,800 rows in plain text, 1 locked copy)",
            "FCC, FBI and Secret Service: report by Tue Nov 24, 2026 (7 business days, 47 CFR 64.2011)",
            "Customers in Wisconsin: by Mon Dec 28, 2026 (45 days, Wis. Stat. 134.98)",
            "A notice must say what happened, what data was involved, what we did, what they can do and who to contact",
        ])

    def test_business_days_skip_weekends(self):
        def fcc(*ymd):
            return next(x for x in assay.notice_checklist("inc-2", {"found_at": self.found(*ymd)}) if x.startswith("FCC"))
        self.assertIn("by Fri Nov 20, 2026", fcc(2026, 11, 11))  # a Wednesday
        self.assertIn("by Tue Nov 24, 2026", fcc(2026, 11, 13))  # a Friday, the weekend gets skipped
        self.assertIn("by Tue Nov 24, 2026", fcc(2026, 11, 14))  # a Saturday counts from Monday
        self.assertEqual(assay._workdays(date(2026, 11, 13), 1), date(2026, 11, 16))

    def test_locked_copy_only(self):
        lines = assay.notice_checklist("inc-9", {"customers": 49800, "plaintext_rows": 0, "locked_copies": 2,
                                                 "found_at": self.found(2026, 11, 14)})
        self.assertIn("Locked copy only: likely exempt as encrypted data, check with counsel", lines)
        self.assertIn("Who is affected by inc-9: 49,800 customers (0 rows in plain text, 2 locked copies)", lines)
        self.assertIn("Customers in Wisconsin: by Tue Dec 29, 2026 (45 days, Wis. Stat. 134.98)", lines)
        self.assertNotIn("Locked copy only: likely exempt as encrypted data, check with counsel",
                         assay.notice_checklist("inc-9", {"plaintext_rows": 5}))


if __name__ == "__main__":
    unittest.main()
