"""Command line entry point.

    py redactor.py [--rules rules.yaml] [input-file]
    py redactor.py --serve [--addr :8080] [--rules rules.yaml]
"""

import argparse
import sys

from pipeline import process_stream
from rules import load_rules


def main(argv=None):
    parser = argparse.ArgumentParser(description="Redact sensitive data from NDJSON API traffic logs.")
    parser.add_argument("--rules", default="rules.yaml", help="path to the rules file (default: rules.yaml)")
    parser.add_argument("input", nargs="?", help="NDJSON file to redact (default: read stdin)")
    parser.add_argument("--serve", action="store_true", help="run as an HTTP service instead")
    parser.add_argument("--addr", default=":8080", help="address for --serve (default: :8080)")
    args = parser.parse_args(argv)
    if args.serve and args.input:
        parser.error("--serve does not take an input file")

    # Load the rules before reading any input or opening a port: without rules, nothing may pass through.
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as e:
        print(f"redactor: cannot load rules from {args.rules}: {e}", file=sys.stderr)
        return 2

    if args.serve:
        from server import parse_addr, serve  # Only service mode needs Flask.

        try:
            parse_addr(args.addr)
        except ValueError as e:
            print(f"redactor: {e}", file=sys.stderr)
            return 2
        serve(rules, args.addr)
        return 0

    try:
        in_stream = open(args.input, "rb") if args.input else sys.stdin.buffer
    except OSError as e:
        print(f"redactor: cannot open {args.input}: {e.strerror}", file=sys.stderr)
        return 2

    with in_stream:
        counts, errors = process_stream(in_stream, sys.stdout.buffer, rules)
    sys.stdout.buffer.flush()

    print_summary(rules, counts, errors)
    return 0


def print_summary(rules, counts, errors):
    """Print redactions per rule and the lines we could not process to stderr. Never any line content."""
    print("redactions per rule:", file=sys.stderr)
    for rule in rules["key_rules"] + rules["value_rules"]:
        print(f"  {rule['name']}: {counts.get(rule['name'], 0)}", file=sys.stderr)

    if errors:
        print(f"lines replaced by an error record: {len(errors)}", file=sys.stderr)
        for line_number, kind in errors:
            print(f"  line {line_number}: {kind}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
