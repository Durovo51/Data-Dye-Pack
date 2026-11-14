import argparse
import sys

from . import __version__, schema


def count(text):
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("needs to be 1 or more")
    return n


def _lab(args):
    from . import lab
    counts = lab.build_lab(args.customers, args.seed)
    print(f"Lakeview Fiber is ready in {schema.DB_PATH}")
    print(f"  customers        {counts['customers']:>7,}")
    print(f"  portal accounts  {counts['portal_accounts']:>7,}")
    print(f"  staff logins     {counts['staff']:>7,}  (passwords in {lab.logins_path()}, never printed)")
    return 0


def _seed(args):
    from . import canary
    try:
        result = canary.plant(args.every)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 1
    c = canary.census()
    print(f"studied {result['rows']:,} customers, value counts in {schema.PROFILE_PATH}")
    redrawn = ""
    if result["draws"] > 1:
        blends = min(result["blend"].values()) >= 0.05
        redrawn = f" (draw {result['draws']}, the first that blends in)" if blends \
            else f" (best of {result['draws']} draws)"
    print(f"planted {result['canaries']:,} canaries, 1 per {args.every:,} customers{redrawn}")
    print(f"  customers        {c['customers']:>7,} rows  {c['customers_canaries']:,} canaries shuffled in")
    print(f"  customers_clean  {c['customers_clean']:>7,} rows  {c['customers_clean_canaries']:,} canaries")
    print(f"  portal accounts  {c['portal_accounts']:>7,}")
    print(f"  watch list       {c['watch_list']:>7,} canaries in {schema.WATCH_PATH}")
    print("frequency test against real rows (p under 0.01 would mean canaries stand out)")
    print("  " + "   ".join(f"{field} p={p:.3f}" for field, p in result["blend"].items()))
    return 0


def _lock(args):
    from . import honey
    return honey.cmd_lock(args)


def _open(args):
    from . import honey
    return honey.cmd_open(args)


def _prove(args):
    from . import proof
    return proof.cmd_prove(args)


def _serve(args):
    from . import server
    return server.cmd_serve(args)


def _drill(args):
    from . import drill
    return drill.cmd_drill(args)


def _drive(args):
    from . import drive
    return drive.cmd_drive(args)


def _sentinel(args):
    from . import sentinel
    return sentinel.cmd_sentinel(args)


def _burst(args):
    from . import burst
    return burst.cmd_burst(args)


def _unlock(args):
    from . import burst
    return burst.cmd_unlock(args)


def build_parser():
    p = argparse.ArgumentParser(prog="dyepack", description="Dye packs for customer data.")
    p.add_argument("--version", action="version", version=f"dyepack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    lab = sub.add_parser("lab", help="build the Lakeview Fiber lab table")
    lab.add_argument("--customers", type=count, default=50_000)
    lab.add_argument("--seed", type=int, default=7, help="random seed so runs repeat")
    lab.set_defaults(func=_lab)

    seed = sub.add_parser("seed", help="study the table and plant canary customers")
    seed.add_argument("--every", type=count, default=250, help="one canary per this many customers")
    seed.set_defaults(func=_seed)

    lock = sub.add_parser("lock", help="export the table into a honey locked file")
    lock.add_argument("out")
    lock.add_argument("--password", help="asked for if left out")
    lock.set_defaults(func=_lock)

    opn = sub.add_parser("open", help="open a honey locked file with a password")
    opn.add_argument("file")
    opn.add_argument("--password", help="asked for if left out")
    opn.add_argument("--limit", type=int, default=5, help="rows to show")
    opn.set_defaults(func=_open)

    prove = sub.add_parser("prove", help="show the real list hides in the middle of the fakes")
    prove.add_argument("--rows", type=count, default=2000)
    prove.add_argument("--fakes", type=count, default=99)
    prove.add_argument("--compare", action="store_true")
    prove.set_defaults(func=_prove)

    serve = sub.add_parser("serve", help="run the lab customer API, login page and mine map")
    serve.add_argument("--port", type=int, default=schema.DEFAULT_PORT)
    serve.set_defaults(func=_serve)

    drill = sub.add_parser("drill", help="replay a normal day, the heist or an agent on the drive")
    drill.add_argument("mode", choices=["normal", "heist", "agent"])
    drill.add_argument("--url", default=f"http://127.0.0.1:{schema.DEFAULT_PORT}")
    drill.add_argument("--step", type=int, choices=[1, 2, 3], help="heist: run only this step")
    drill.add_argument("--seconds", type=count, default=60, help="normal: how long the day runs")
    drill.add_argument("--real", action="store_true", help="agent: run a real coding agent command")
    drill.add_argument("--cmd", help="agent: the command to run inside the drive")
    drill.add_argument("--simulate-sentinel", action="store_true", help="agent: feed file events without eslogger")
    drill.set_defaults(func=_drill)

    drive = sub.add_parser("drive", help="build the Lakeview Fiber company drive with its decoys")
    drive.add_argument("--seed", type=int, default=7, help="random seed so runs repeat")
    drive.set_defaults(func=_drive)

    sentinel = sub.add_parser("sentinel", help="watch file activity and report what happens on the drive")
    sentinel.add_argument("--root", action="append", help="folder to watch (default: the drive), repeat for more")
    sentinel.add_argument("--url", default=f"http://127.0.0.1:{schema.DEFAULT_PORT}")
    sentinel.add_argument("--backend", choices=["auto", "eslogger", "inotify", "fake"], default="auto")
    sentinel.add_argument("--source", help="fake backend: a file of JSON lines (default: stdin)")
    sentinel.add_argument("--quiet", action="store_true", help="don't print each event")
    sentinel.set_defaults(func=_sentinel)

    burst = sub.add_parser("burst", help="lock a drive folder's customer files in place as .dye files")
    burst.add_argument("folder")
    burst.set_defaults(func=_burst)

    unlock = sub.add_parser("unlock", aliases=["restore"], help="put locked customer files back from their .dye")
    unlock.add_argument("dye", nargs="*", help=".dye files (default: everything still locked)")
    unlock.add_argument("--to", help="write one file somewhere else instead")
    unlock.add_argument("--force", action="store_true", help="unlock a .dye the watch list has no record of")
    unlock.set_defaults(func=_unlock)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    sys.exit(args.func(args))
