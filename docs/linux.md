# Running Data Dyepack on Linux

Data Dyepack runs the same on Linux as on macOS. On Linux the file watcher uses inotify, so
nothing needs root.

## Requirements

- Python 3.10 or newer and git. Ubuntu 22.04 and 24.04 ship both.
- No third party packages.

## Install

```bash
git clone https://github.com/Durovo51/Data-Dye-Pack.git && cd Data-Dye-Pack
```

Run every command from this folder as `python3 -m dyepack ...`. For a shorter `dyepack`
command, install the package with `pip install -e .` (inside a virtual environment if your
system Python blocks it).

## Set the lock password

```bash
cp .env.example .env && chmod 600 .env
```

Open `.env` and set `DYEPACK_LOCK_PASSWORD` to a password only you know. Dyepack uses it to
lock the drive when a decoy is read and to unlock it afterwards. Set it before the next step,
because the drive's nightly backup is locked with it too.

## Set up the lab

```bash
python3 -m dyepack lab && python3 -m dyepack seed && python3 -m dyepack drive
```

`lab` builds a table of 50,000 made up customers, `seed` plants canary customers in it and
`drive` writes a company drive with decoy files at `~/LakeviewFiber`. Set the `DYEPACK_DRIVE`
environment variable to put the drive somewhere else.

## Run it

Terminal 1, the server and dashboard:

```bash
python3 -m dyepack serve
```

Terminal 2, the file watcher:

```bash
python3 -m dyepack sentinel
```

The server listens on 127.0.0.1:8750 only, never on the open network. On a machine with a
desktop, open http://127.0.0.1:8750/ in its browser or start the server with `--open`.

## Open the dashboard from another computer

On a server without a desktop, forward the port over SSH from your laptop:

```bash
ssh -L 8750:127.0.0.1:8750 YOUR_USER@YOUR_SERVER
```

Then open http://localhost:8750/ on your laptop. The response buttons (lock, revoke, draft
breach notice) need the control token, which the server writes on every start. In that SSH
session, from the repo folder:

```bash
cat data/control_token
```

Open http://localhost:8750/?token=THE_TOKEN once and the dashboard keeps it for that tab.

## Check that it works

Run a drill in a third terminal. Each one plays an attack against your setup.

```bash
python3 -m dyepack drill normal
```

A normal day of support lookups. Expect 0 alarms.

```bash
python3 -m dyepack drill heist
```

A stolen staff login reads in bulk, steals and cracks an export, then tries the stolen logins.
Expect every step to be caught.

```bash
python3 -m dyepack drill agent
```

An agent reads the company drive. Expect a decoy alarm and the whole drive locked in place
within about a second.

## Unlock and reset

```bash
python3 -m dyepack unlock
```

```bash
python3 -m dyepack drive
```

`unlock` puts every locked file back byte for byte. `drive` rebuilds the company drive fresh.

## Program names from auditd

inotify reports the file but not the program that opened it. An auditd agent on the same
machine can post the program and user to `POST http://127.0.0.1:8750/api/events`. Those hits
raise alarms but never lock the drive.

## Troubleshooting

- No alarm: make sure `python3 -m dyepack sentinel` is running and watching the drive.
- No lock: set `DYEPACK_LOCK_PASSWORD` in `.env`. The server prints a note when it's missing.
- Dashboard empty: check the SSH tunnel and open http://localhost:8750/.
