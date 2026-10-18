"""Command line entry point: py redactor.py [--rules rules.yaml] [input-file]"""

import argparse
import sys

from pipeline import process_stream
from rules import load_rules


def main(argv=None):
    parser = argparse.ArgumentParser(description="Redact sensitive data from NDJSON API traffic logs.")
    parser.add_argument("--rules", default="rules.yaml", help="path to the rules file (default: rules.yaml)")
    parser.add_argument("input", nargs="?", help="NDJSON file to redact (default: read stdin)")
    args = parser.parse_args(argv)

    # Load the rules before reading any input: without rules, nothing may pass through.
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as e:
        print(f"redactor: cannot load rules from {args.rules}: {e}", file=sys.stderr)
        return 2

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
