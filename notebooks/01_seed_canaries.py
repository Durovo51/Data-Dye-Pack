# Databricks notebook source
# MAGIC %md
# MAGIC # Seed canaries
# MAGIC
# MAGIC Installs `dyepack` from a Unity Catalog volume, builds the Lakeview Fiber lab table (or loads real rows from a table you name), plants canary customers and writes three tables:
# MAGIC
# MAGIC * `customers`: real rows plus canaries, for the few accounts allowed to read the raw table
# MAGIC * `customers_clean`: the same rows minus the canaries, for analytics, billing and everyone else
# MAGIC * `watch_list`: the canaries, in a schema of their own with every grant taken away
# MAGIC
# MAGIC Setup, once:
# MAGIC 1. On your laptop, in the repo folder: `python3 -m pip wheel . --no-deps --no-build-isolation -w dist`
# MAGIC 2. In a SQL editor: `CREATE SCHEMA IF NOT EXISTS workspace.dyepack` then `CREATE VOLUME IF NOT EXISTS workspace.dyepack.wheels`
# MAGIC 3. Upload `dist/data_dyepack-0.1.0-py3-none-any.whl` to that volume (Catalog, workspace, dyepack, wheels, Upload to this volume)
# MAGIC
# MAGIC Status: untested. It hasn't run on the workspace yet.

# COMMAND ----------

dbutils.widgets.text("wheel", "/Volumes/workspace/dyepack/wheels/data_dyepack-0.1.0-py3-none-any.whl", "Wheel in a volume")
dbutils.widgets.text("customers", "50000", "Lab customers")
dbutils.widgets.text("every", "250", "One canary per")
dbutils.widgets.text("source", "", "Load real rows from (blank builds the lab)")
dbutils.widgets.text("catalog", "workspace", "Catalog")
dbutils.widgets.text("schema", "dyepack", "Schema")
wheel = dbutils.widgets.get("wheel")

# COMMAND ----------

# MAGIC %pip install $wheel

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

catalog = dbutils.widgets.get("catalog")
db = dbutils.widgets.get("schema")
vault = db + "_vault"
source = dbutils.widgets.get("source").strip()

# the package keeps its lab in DYEPACK_DATA. point that at scratch space before the first import
os.environ["DYEPACK_DATA"] = tempfile.mkdtemp(prefix="dyepack_")
from dyepack import cli, databricks, lab, schema

FIELDS = list(schema.CUSTOMER_FIELDS)
COLS = ", ".join(FIELDS)
MARKS = ", ".join("?" * len(FIELDS))


def name(*parts):
    return ".".join(f"`{p}`" for p in parts)


def dyepack(*args):
    try:
        cli.main([str(a) for a in args])
    except SystemExit as e:
        if e.code not in (None, 0):
            raise RuntimeError(f"dyepack {args[0]} stopped with code {e.code}")


def fix(row):
    r = dict(zip(FIELDS, row))
    r["monthly_bill"], r["since_year"] = float(r["monthly_bill"]), int(r["since_year"])
    return tuple(r[f] for f in FIELDS)

# COMMAND ----------

# build the lab (or load real rows into it), then plant the canaries
if source:
    # use customers_clean from an earlier run here, never customers (it already holds canaries)
    dyepack("lab", "--customers", 1)  # a fresh lab file with every table seed expects
    rows = [fix(r) for r in spark.table(source).select(*FIELDS).collect()]
    users = [r[FIELDS.index("portal_user")] for r in rows]
    con = sqlite3.connect(schema.DB_PATH)
    with con:
        con.execute("DELETE FROM customers")
        con.execute("DELETE FROM portal_accounts")
        con.executemany(f"INSERT INTO customers ({COLS}) VALUES ({MARKS})", rows)
        # seed keeps a portal login for every customer
        con.executemany("INSERT INTO portal_accounts VALUES (?, ?, ?)",
                        [(u, *h) for u, h in zip(users, lab.portal_hashes(len(users)))])
    con.close()
else:
    dyepack("lab", "--customers", dbutils.widgets.get("customers"))
dyepack("seed", "--every", dbutils.widgets.get("every"))

# COMMAND ----------

# copy the seeded lab into Delta, with the watch list in its own schema
con = sqlite3.connect(schema.DB_PATH)
seeded = {t: [fix(r) for r in con.execute(f"SELECT {COLS} FROM {t}")] for t in ("customers", "customers_clean")}
con.close()
watch = json.loads(schema.WATCH_PATH.read_text())["canaries"]

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {name(catalog, db)}")
spark.sql(f"CREATE SCHEMA IF NOT EXISTS {name(catalog, vault)} COMMENT 'canary watch list, two named people only'")
for t, rows in seeded.items():
    (spark.createDataFrame(rows, databricks.TABLES[t]).write.mode("overwrite")
        .option("overwriteSchema", "true").saveAsTable(name(catalog, db, t)))

watch_cols = ("canary_id STRING, account_no STRING, portal_user STRING, email STRING, phone STRING, "
              "batch STRING, planted_at TIMESTAMP")
watch_rows = [(c.get("canary_id"), c.get("account_no"), c.get("portal_user"), c.get("email"), c.get("phone"),
               c.get("batch"), datetime.fromtimestamp(c.get("planted_at") or 0, timezone.utc)) for c in watch]
(spark.createDataFrame(watch_rows, watch_cols).write.mode("overwrite")
    .option("overwriteSchema", "true").saveAsTable(name(catalog, vault, "watch_list")))

# COMMAND ----------

# check: the counts add up and the clean table holds no canaries
raw = spark.table(name(catalog, db, "customers")).count()
clean = spark.table(name(catalog, db, "customers_clean"))
wl = spark.table(name(catalog, vault, "watch_list"))
leaks = clean.join(wl, "account_no").count()
print(f"customers {raw:,}, clean {clean.count():,}, canaries {wl.count():,}, canaries in clean {leaks}")
assert leaks == 0 and raw == clean.count() + wl.count(), "counts don't add up"

# COMMAND ----------

# lock the watch list away, then show who can still see it
spark.sql(f"REVOKE ALL PRIVILEGES ON SCHEMA {name(catalog, vault)} FROM `account users`")
display(spark.sql(f"SHOW GRANTS ON SCHEMA {name(catalog, vault)}"))
