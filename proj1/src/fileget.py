#!/usr/bin/env python3.8

import sys
import argparse


def error(msg, code):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(code)


aparser = argparse.ArgumentParser(description="Distributed Filesystem Client.")
aparser.add_argument(
    "--nameserver", "-n",
    required = True,
    help="IP address & port of name server")
aparser.add_argument(
    "--file", "-f",
    required = True,
    help="SURL of file to be downloaded; Protocol in URL is always fsp")

args = aparser.parse_args()

# print(args.nameserver + " " + args.file)
