"""Command line interface: phishlens <file.eml> [--json]"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze_file

COLORS = {"PHISHING": "\033[91m", "SUSPICIOUS": "\033[93m", "PROBABLY SAFE": "\033[92m"}
RESET = "\033[0m"


def print_report(path: str, report, color: bool) -> None:
    c = COLORS.get(report.verdict, "") if color else ""
    r = RESET if color else ""
    print(f"\n=== {path} ===")
    print(f"Subject    : {report.subject}")
    print(f"From       : {report.sender}")
    if report.reply_to:
        print(f"Reply-To   : {report.reply_to}")
    print("Auth       : " + "  ".join(f"{k.upper()}={v}" for k, v in report.auth.items()))
    print(f"Links      : {len(report.links)}")
    for link in report.links[:10]:
        print(f"   - {link.url}")
    print(f"Attachments: {len(report.attachments)}")
    for att in report.attachments:
        print(f"   - {att.filename} ({att.content_type}, {att.size} bytes) sha256={att.sha256[:16]}...")
    print("\nFindings:")
    if not report.findings:
        print("   nothing suspicious found")
    for f in sorted(report.findings, key=lambda x: -x.points):
        print(f"   [+{f.points:>2}] {f.category:<10} {f.message}")
    print(f"\nScore: {report.score}/100  ->  {c}{report.verdict}{r}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Analyse .eml files and estimate how likely they are to be phishing.",
    )
    parser.add_argument("files", nargs="+", help="one or more .eml files")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    results = {}
    worst = 0
    for path in args.files:
        try:
            report = analyze_file(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        worst = max(worst, report.score)
        if args.json:
            results[path] = report.to_dict()
        else:
            print_report(path, report, color=not args.no_color and sys.stdout.isatty())

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    # exit code is useful in scripts: 0 safe, 1 suspicious/phishing
    return 1 if worst >= 30 else 0


if __name__ == "__main__":
    sys.exit(main())
