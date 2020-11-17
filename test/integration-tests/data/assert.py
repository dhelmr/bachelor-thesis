#!/usr/bin/env python3

import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("arg1")
parser.add_argument("--lt")
parser.add_argument("--gt")
parser.add_argument("--eq")
parser.add_argument("--not-in")
parser.add_argument("--msg")

args = parser.parse_args()


def fail(cond):
    print(
        f"{args.msg + ' -- ' if args.msg is not None else ''} Assertation failed: {cond}"
    )
    sys.exit(1)


if args.lt is not None and not args.arg1 < args.lt:
    fail(f"{args.arg1} < {args.lt}")
if args.gt is not None and not args.arg1 > args.gt:
    fail(f"{args.arg1} > {args.gt}")
if args.eq is not None and not args.arg1 == args.eq:
    fail(f"{args.arg1} == {args.eq}")
if args.not_in is not None and str(args.arg1).lower() in str(args.not_in).lower():
    fail(f"{args.arg1} not in {args.not_in}")
