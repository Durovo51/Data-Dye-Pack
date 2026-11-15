# Data Dyepack

**Let them dig. Everything they take comes out stained.**

When an AI agent breaks into a company, it does not read one table. It reads everything it can
reach and copies it out fast. Data Dyepack plants dye packs in that data. The moment an
agent touches the bait, Dyepack spots it, locks the rest of the drive so the agent leaves with
locked files it cannot read and marks the exact copy that leaked so the team knows who took
what.

Built for the MadHacks 2026 TDS Privacy and Security challenge.

## What it does

- **Canary customers.** Fake customers are mixed into the real table and kept on a separate
  watch list. No real person or app ever touches one, so a touch at machine speed or any use
  of one (a login, an email, a call), is a true alarm. A canary travels with stolen data, so
  it fires even days later, wherever the copy went and the alarm names that copy.
- **A decoy drive.** A company drive holds decoy files among the real ones, like an
  "all customers full export" and an "unencrypted backup". No real workflow opens them, so any
  read is a strong signal.
- **Lock in place.** When a decoy is read, Dyepack honey locks every customer file on the whole
  drive where it sits. `customers.csv` becomes `customers.csv.dye`. The company's own apps fail
  loudly and one command puts every file back byte for byte.
- **Honey encryption.** A stolen `.dye` file opens to a believable fake customer list for every
  wrong password, so a thief can never tell which guess was right. The real list is the only one
  that carries the canaries.
- **A speed alarm.** Anything reading over 600 customers a minute is machine speed. A person
  never reads that fast. The alarm counts per login and per address, so a stolen login cannot
  dodge it by reconnecting.
- **A live dashboard.** Every alarm lands on a console with a plain English report, a read speed
  chart, the time to containment, a phone push and a draft breach notice. The report and triage
  are written by a model served on Databricks.

## The demo in one minute

1. A normal day of support work raises zero alarms.
2. A phished support login reads customers in bulk. Caught and locked after two pages, about
   200 rows out, in under a second.
3. The thief steals an export and cracks it. Every one of fifty wrong passwords opens a
   believable fake list and the served model cannot pick the real one out of five.
4. The thief uses a stolen login. The alarm fires and names the exact export it came from.
5. An AI agent is pointed at the company drive. It trips a decoy in a few hundredths of a
   second, the whole drive locks in place, the phone buzzes and the agent is left with locked
   files and fakes.

## Run it

Needs Python 3.10 or newer. No third party packages.

```bash
pip install -e .
```

```bash
dyepack lab && dyepack seed && dyepack drive
```

Set a lock password in a `.env` file (copy `.env.example`):

```
DYEPACK_LOCK_PASSWORD=pick-any-phrase-you-will-remember
```

Start the server and open the dashboard:

```bash
dyepack serve
```

Run the demo drill:

```bash
dyepack drill heist
```

```bash
dyepack drill agent
```

To watch the whole file system live, run the watcher next to the server. On macOS it reads the
system event stream and needs Full Disk Access for your terminal plus `sudo`. On Linux it uses
inotify and needs no root. The full Linux server walk through is in
[docs/linux-server-demo.md](docs/linux-server-demo.md).

```bash
sudo dyepack sentinel
```

## Databricks

Reports and the triage card are written by a chat model served on Databricks and the alarm
history lands in Delta tables for a dashboard and Genie questions. Copy `.env.example` to `.env`
and fill in the host, warehouse, model and a token. Without them the reports fall back to a
built in template and the rest of the demo is the same.

## Honest limits

- In the lab every customer is made up. In production, canary emails and phone numbers are ones
  the company owns, so a thief who reaches out lands on the company, never on a stranger.
- In the lab the lock password sits in `.env` so the demo runs on one laptop. In production it
  lives in a key manager on a separate system and unlocking takes two people.
- Honey encryption hides the real list only as well as its header matches where the data really
  came from. A real company needs a header from a population model, not from the list being
  locked.
- Lock in place covers customer tables (CSV, JSON, SQLite), not arbitrary files. The sentinel on
  Linux sees the file but not the program, so registered tools are matched on macOS or through
  the auditd agent.
- Dyepack names everything an agent read before the lock. It does not claim to stop the first
  read. It makes everything after it worthless and marks what left.
