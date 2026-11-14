import argparse
import sys

from . import __version__


def _not_built(args):
    print(f"'{args.cmd}' isn't built yet", file=sys.stderr)
    return 2


def build_parser():
    p = argparse.ArgumentParser(prog="dyepack", description="Dye packs for customer data.")
    p.add_argument("--version", action="version", version=f"dyepack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    lab = sub.add_parser("lab", help="build the Lakeview Fiber lab table")
    lab.add_argument("--customers", type=int, default=50_000)
    lab.add_argument("--seed", type=int, default=7, help="random seed so runs repeat")
    lab.set_defaults(func=_not_built)

    seed = sub.add_parser("seed", help="study the table and plant canary customers")
    seed.add_argument("--every", type=int, default=250, help="one canary per this many customers")
    seed.set_defaults(func=_not_built)

    lock = sub.add_parser("lock", help="export the table into a honey locked file")
    lock.add_argument("out")
    lock.add_argument("--password", help="asked for if left out")
    lock.set_defaults(func=_not_built)

    opn = sub.add_parser("open", help="open a honey locked file with a password")
    opn.add_argument("file")
    opn.add_argument("--password", help="asked for if left out")
    opn.add_argument("--limit", type=int, default=5, help="rows to show")
    opn.set_defaults(func=_not_built)

    serve = sub.add_parser("serve", help="run the lab customer API, login page and mine map")
    serve.add_argument("--port", type=int, default=8750)
    serve.set_defaults(func=_not_built)

    drill = sub.add_parser("drill", help="replay a normal day or the heist")
    drill.add_argument("mode", choices=["normal", "heist"])
    drill.add_argument("--url", default="http://127.0.0.1:8750")
    drill.set_defaults(func=_not_built)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    sys.exit(args.func(args))
