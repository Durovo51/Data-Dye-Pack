# Data Dyepack

![tests](https://github.com/Durovo51/Data-Dye-Pack/actions/workflows/ci.yml/badge.svg)

**Contained on contact.**

An AI agent that gets into a company reads everything it can reach and copies it out fast.
Data Dyepack plants dye packs in customer data. When an agent touches the bait, Dyepack catches
it within a second, locks every customer file on the drive in place and marks the exact copy
that leaked.

## How it works

| Piece | What it does |
|---|---|
| Canary customers | Fake customers mixed into the real table and listed on a separate watch list. No real person or app ever touches one, so a read at machine speed or any use of one (a login, an email, a call) is a true alarm. Canaries travel with stolen data and name the copy they came from. |
| Decoy files | Bait files on the company drive, like a "full customer export" or an "unencrypted backup". No real workflow opens them, so any read is a strong signal. |
| Lock in place | When a decoy is read, every customer file on the drive is honey locked where it sits: `customers.csv` becomes `customers.csv.dye`. Your own apps fail loudly instead of quietly reading fakes. `dyepack unlock` restores every byte. |
| Honey encryption | A stolen `.dye` file opens to a believable fake customer list for every wrong password, so a thief can never tell which guess was right. |
| Speed alarm | Reading over 600 customers a minute is machine speed. It counts per session, per staff login and per address, so a stolen login can't pace itself under the limit. |
| Dashboard | A live console with the read speed, time to containment, a plain English report written by a model on Databricks, phone alerts and a draft breach notice. |

## Measured results

- A normal day of support work: 0 alarms.
- A stolen staff login reading in bulk: locked within the first page or two (100 to 200 rows) in under a second.
- An agent opening a decoy: the whole drive locked 515 ms later.
- 50 wrong passwords on a stolen export: 50 believable fake lists. A 70B model asked to find the real one out of five picked wrong.

## Quick start

Needs Python 3.10 or newer. No third party packages.

```bash
git clone https://github.com/Durovo51/Data-Dye-Pack.git && cd Data-Dye-Pack
```

```bash
cp .env.example .env
```

Set `DYEPACK_LOCK_PASSWORD` in `.env` to a password only you know. Then build the lab: a table of
made up customers, the canary customers and the company drive with its decoy files.

```bash
python3 -m dyepack lab && python3 -m dyepack seed && python3 -m dyepack drive
```

Start the server. `--open` opens the dashboard in your browser.

```bash
python3 -m dyepack serve --open
```

Run every command from the repo folder. `pip install -e .` adds a shorter `dyepack` command.

## Watch the drive

The sentinel reports every file opened on the company drive to the server.

On macOS it reads the system event stream, so it needs root and Full Disk Access for your
terminal app (System Settings > Privacy & Security > Full Disk Access):

```bash
sudo python3 -m dyepack sentinel
```

On Linux it uses inotify and needs no root:

```bash
python3 -m dyepack sentinel
```

Full Linux setup, including a server without a desktop: [docs/linux.md](docs/linux.md).

## Try it with a drill

A drill plays an attack against your own setup so you can see what Dyepack catches.

| Command | What it plays |
|---|---|
| `python3 -m dyepack drill normal` | A normal day of support lookups. Expect 0 alarms. |
| `python3 -m dyepack drill heist` | A stolen staff login reads in bulk, steals and cracks an export, then tries the stolen logins. |
| `python3 -m dyepack drill agent` | An agent reads the company drive. Needs the sentinel running or `--simulate-sentinel`. |
| `python3 -m dyepack drill agent --real --cmd '<agent command> "{task}"'` | Runs a real AI coding agent inside the drive with the task "find and summarize the customer data here". |

Put the drive back afterwards:

```bash
python3 -m dyepack unlock
```

## Configuration

Settings live in `.env` (start from `.env.example`). Only the lock password is required.

| Setting | Use |
|---|---|
| `DYEPACK_LOCK_PASSWORD` | Locks and unlocks `.dye` files. Required for the drive lock. |
| `DATABRICKS_HOST`, `DATABRICKS_TOKEN`, `DATABRICKS_WAREHOUSE_ID`, `DATABRICKS_MODEL` | A chat model served on Databricks writes the reports and triage. Alarms land in Delta tables. `DATABRICKS_CATALOG` and `DATABRICKS_SCHEMA` default to `workspace` and `dyepack`. Without these, reports use a built in template. |
| `NTFY_TOPIC` | Phone push through ntfy. Get a private topic with `python3 -m dyepack.notify topic`. |
| `DISCORD_WEBHOOK_URL` | Alerts to a Discord channel. |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`, `ALERT_SMS_TO` | Real SMS. Without them SMS is simulated on the dashboard. |

Two environment variables move things around: `DYEPACK_DRIVE` (the company drive, default
`~/LakeviewFiber`) and `DYEPACK_DATA` (the lab data, default `data/`).

## Commands

| Command | What it does |
|---|---|
| `lab` | Builds the lab table of made up customers (`--customers`, default 50,000). |
| `seed` | Plants canary customers (`--every`, default one per 250). |
| `drive` | Writes the company drive with its decoy files. |
| `serve` | Runs the customer API, the login page and the dashboard on 127.0.0.1:8750 (`--open`, `--port`). |
| `sentinel` | Watches the drive and reports file opens to the server. |
| `drill` | Plays `normal`, `heist` or `agent` against your setup. |
| `lock`, `open` | Honey locks the table into a file or opens one with a password. |
| `prove` | Shows the real list lands in the middle of the fakes (`--compare` shows a naive header giving it away). |
| `burst` | Locks one drive folder's customer files in place by hand. |
| `unlock` | Puts locked files back byte for byte. |

## Databricks

With the Databricks settings filled in, a chat model served on Databricks writes each incident
report and the triage card. Every alarm, report and export lands in Delta tables. The
notebooks in `notebooks/` seed the canary watch list into a locked schema and build the alarms
dashboard.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

CI runs the suite on Python 3.10 and 3.12.

## Security notes and limits

- The server listens on 127.0.0.1 only. The response buttons need a control token that changes on
  every start and is never printed.
- The lab is made up end to end. In production, canary emails and phone numbers should be ones the
  company owns, so a thief who reaches out lands on the company, never on a stranger.
- In the lab the lock password sits in `.env`. In production it belongs in a key manager on a
  separate system, with two people needed to unlock.
- Honey encryption hides the real list only as well as its header matches the real population.
  Build the header from a population model, never from the list being locked.
- Lock in place covers CSV and JSON customer tables, not arbitrary files.
- Dyepack names everything read before the lock. It doesn't stop the first read. It makes
  everything after it worthless and marks what left.

## License

MIT. See [LICENSE](LICENSE).
