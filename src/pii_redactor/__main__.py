"""Command-line demo: python -m pii_redactor <file> [--mask]"""

import argparse
import json
import sys

from .detector import redact, summarize


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact PII from a text file.")
    parser.add_argument("path", help="text file to scan")
    parser.add_argument("--mask", action="store_true", help="partially mask instead of fully redacting")
    args = parser.parse_args()

    with open(args.path, encoding="utf-8") as f:
        text = f.read()

    cleaned, findings = redact(text, mode="mask" if args.mask else "redact")
    print(cleaned)
    print("--- findings ---", file=sys.stderr)
    print(json.dumps(summarize(findings), indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
