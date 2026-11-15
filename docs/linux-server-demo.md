# Running the Data Dyepack demo on a Linux server

This runs the whole demo on one Ubuntu server: the company drive, the dashboard, the file
watcher and an attacker. Everything stays on the server, and you watch the dashboard from
your laptop through an SSH tunnel. No root is needed.

## What you need
- Ubuntu with Python 3.10 or newer and git.
- SSH access from your laptop.
- About 10 minutes.

Check Python:

```bash
python3 --version
```

## 1. Get the code

```bash
git clone https://github.com/Durovo51/Data-Dye-Pack.git
```

```bash
cd Data-Dye-Pack && pip install -e .
```

If `pip install -e .` is blocked on a managed server, skip it and run every `dyepack ...`
command below as `python3 -m dyepack ...` instead. Nothing else changes.

## 2. Build the lab and the decoy drive

```bash
dyepack lab && dyepack seed && dyepack drive
```

This writes a fake customer table with canary customers mixed in, and a company drive at
`~/LakeviewFiber` with decoy files among the real ones. Every customer in it is made up.

## 3. Set the lock password

The drive lock needs a password only you know. Put it in a `.env` file in the repo:

```bash
cp .env.example .env && nano .env
```

Fill in this line, then save (Ctrl+O, Enter, Ctrl+X):

```
DYEPACK_LOCK_PASSWORD=pick-any-phrase-you-will-remember
```

Databricks is optional. Leave the Databricks lines blank and the reports use a built in
template. The rest of the demo is the same.

## 4. Start the three pieces

Open three terminals on the server (or three `tmux` panes).

Terminal 1, the server and dashboard:

```bash
dyepack serve
```

It prints `Data Dyepack is watching Lakeview Fiber at http://127.0.0.1:8750/`. It listens on
127.0.0.1 only, never on the open network, so nobody on the venue wifi can reach it.

Terminal 2, the file watcher:

```bash
dyepack sentinel
```

On Linux this uses inotify and watches `~/LakeviewFiber`. It sees which files get opened and
sends that to the server. It needs no root.

Terminal 3 is for the attacker in step 5.

## 5. Run the attacker

In terminal 3, send an agent that reads the drive the way a thief would:

```bash
dyepack drill agent
```

This walks `~/LakeviewFiber` and reads every file. It opens a decoy within a few
hundredths of a second, which trips the alarm. The server locks every customer file on the
drive in place as a `.dye` file and the dashboard lights up.

To use a real AI coding agent instead of the built in reader, give it the benign task of
reading the folder:

```bash
dyepack drill agent --real --cmd '<your agent command> "find and summarize the customer data in this folder"'
```

The agent runs inside `~/LakeviewFiber`. Point any attacker you like at that folder. The
whole drive is fake data, so nothing real is ever at risk.

## 6. Watch the dashboard from your laptop

The server stays on 127.0.0.1, so tunnel to it from your laptop. In a terminal on your
laptop:

```bash
ssh -L 8750:127.0.0.1:8750 YOUR_USER@YOUR_SERVER
```

Leave that open and visit `http://localhost:8750/` in your laptop browser. To use the
response buttons (lock, revoke, draft breach notice), the page needs the control token. Read
it on the server:

```bash
cat ~/Data-Dye-Pack/data/control_token
```

Then open `http://localhost:8750/?token=PASTE_THE_TOKEN`. For a view only demo you can skip
the token and just watch.

## 7. Reset between runs

Put the locked files back and clear the drive for another run:

```bash
dyepack unlock
```

```bash
dyepack drive
```

`dyepack unlock` restores every file byte for byte with the lock password. `dyepack drive`
rebuilds the decoy drive fresh.

## Optional: real process names with the auditd agent

The inotify watcher sees the file but not which program opened it. A teammate's auditd agent
(`minefield`) adds the process name and user and posts to the server at
`http://127.0.0.1:8750/api/events`. Run it in the same server so its backend stays on
loopback. It is a second detector, not the attacker.

## If something does not fire
- No alarm: make sure `dyepack sentinel` is running and watching `~/LakeviewFiber`, and that
  the attacker read files under that folder.
- No lock: check that `DYEPACK_LOCK_PASSWORD` is set in `.env`. The server prints a note when
  it is missing.
- Dashboard empty: confirm the SSH tunnel is up and you opened `http://localhost:8750/`.
