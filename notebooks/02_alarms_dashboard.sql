-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Alarms dashboard
-- MAGIC
-- MAGIC One query per dashboard tile. The tables fill up while `dyepack serve` runs with a filled in `.env`.
-- MAGIC The names assume catalog `workspace` and schema `dyepack`. Change them if your `.env` says otherwise.

-- COMMAND ----------

-- alarms per minute
SELECT date_trunc('MINUTE', ts) AS minute,
       count(*) AS alarms,
       count_if(severity = 'critical') AS critical
FROM workspace.dyepack.alarms
GROUP BY 1
ORDER BY 1

-- COMMAND ----------

-- alarms by reason
SELECT reason,
       count(*) AS alarms,
       count(DISTINCT incident) AS incidents,
       max(ts) AS last_seen
FROM workspace.dyepack.alarms
GROUP BY reason
ORDER BY alarms DESC

-- COMMAND ----------

-- incidents, newest first, with the latest report for each
WITH latest AS (
  SELECT incident,
         max_by(title, ts) AS title,
         max_by(text, ts) AS report,
         max_by(source, ts) AS source
  FROM workspace.dyepack.reports
  GROUP BY incident
)
SELECT a.incident,
       min(a.ts) AS first_alarm,
       count(*) AS alarms,
       max_by(a.severity, CASE a.severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS worst,
       array_join(collect_set(a.reason), ', ') AS reasons,
       min_by(a.actor, a.ts) AS actor,
       size(array_distinct(filter(flatten(collect_list(split(a.canary_ids, ','))), x -> x != ''))) AS canaries,
       max(a.export_id) AS export_id,
       any_value(l.title) AS title,
       any_value(l.report) AS report,
       any_value(l.source) AS source
FROM workspace.dyepack.alarms a
LEFT JOIN latest l ON l.incident = a.incident
GROUP BY a.incident
ORDER BY first_alarm DESC

-- COMMAND ----------

-- exports and the alarms that named each one (a leaked copy shows up here)
SELECT e.export_id,
       e.ts AS exported_at,
       e.actor,
       e.row_count,
       e.canaries,
       count(a.ts) AS alarms_naming_it,
       min(a.ts) AS first_use
FROM workspace.dyepack.exports e
LEFT JOIN workspace.dyepack.alarms a ON a.export_id = e.export_id
GROUP BY e.export_id, e.ts, e.actor, e.row_count, e.canaries
ORDER BY exported_at DESC

-- COMMAND ----------

-- starter questions for a Genie space over these tables:
-- 1. Which export leaked and how many stolen login attempts named it?
-- 2. How many alarms fired each minute during the heist, split by reason?
-- 3. List the critical incidents with their reports, newest first.
SHOW TABLES IN workspace.dyepack
