"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .models import Severity
from .report import formats, render
from .rules import RULES
from .scan import DEFAULT_IGNORE_FILE, load_ignore, scan

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2
EXIT_USAGE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillsentry",
        description="Gate agent skills and plugins before install: pin hashes, catch capability drift, inspect payloads.",
    )
    parser.add_argument("--version", action="version", version="skillsentry %s" % __version__)
    subparsers = parser.add_subparsers(dest="command")

    check = subparsers.add_parser("check", help="scan a skill, plugin or repository")
    check.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: .)")
    check.add_argument(
        "--min-severity",
        default="medium",
        help="lowest severity that fails the run (low, medium, high, critical; default: medium)",
    )
    check.add_argument(
        "--format",
        default="text",
        choices=list(formats()),
        help="output format (default: text)",
    )
    check.add_argument("--output", "-o", help="write the report to a file instead of stdout")
    check.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="skip paths matching this glob (repeatable, relative to the scanned root)",
    )
    check.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="ID",
        help="only run these rule ids, e.g. --rules SE001 --rules SE004",
    )
    check.add_argument(
        "--ignore-file",
        default=None,
        help="file with accepted fingerprints (default: .skillsentryignore when present)",
    )
    check.add_argument("--no-ignore", action="store_true", help="ignore any ignore file")

    subparsers.add_parser("rules", help="list every rule with its severity")
    return parser


def _list_rules() -> int:
    width = max(len(rule.id) for rule in RULES)
    print("skillsentry %s — %d rules" % (__version__, len(RULES)))
    for rule in RULES:
        print("  %-*s  %-8s  %-18s  %s" % (width, rule.id, rule.severity.value, rule.title, rule.description))
    return EXIT_OK


def _resolve_ignore(args: argparse.Namespace) -> set:
    if args.no_ignore:
        return set()
    if args.ignore_file:
        path = Path(args.ignore_file).expanduser()
        if not path.exists():
            raise FileNotFoundError("ignore file not found: %s" % path)
        return load_ignore(path)
    default = Path(args.path).expanduser()
    if default.is_file():
        default = default.parent
    candidate = default / DEFAULT_IGNORE_FILE
    if candidate.exists():
        return load_ignore(candidate)
    return set()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    if args.command == "rules":
        return _list_rules()

    try:
        threshold = Severity.parse(args.min_severity)
    except ValueError as exc:
        print("skillsentry: %s" % exc, file=sys.stderr)
        return EXIT_USAGE

    try:
        ignore = _resolve_ignore(args)
        result = scan(args.path, excludes=args.exclude, ignore=ignore, rule_names=args.rules or None)
    except FileNotFoundError as exc:
        print("skillsentry: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print("skillsentry: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - defensive
        print("skillsentry: unexpected error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    body = render(result, args.format)
    if args.output:
        destination = Path(args.output).expanduser()
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(body + "\n", encoding="utf-8")
        except OSError as exc:
            print("skillsentry: cannot write %s: %s" % (destination, exc), file=sys.stderr)
            return EXIT_USAGE
    else:
        print(body)

    failing = [finding for finding in result.findings if finding.severity.rank >= threshold.rank]
    if args.format == "text" and failing:
        print("\nskillsentry: failing on %d finding(s) at or above %s" % (len(failing), threshold.value), file=sys.stderr)
    return EXIT_FINDINGS if failing else EXIT_OK
