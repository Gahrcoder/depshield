"""CLI entry point for depshield."""
from __future__ import annotations

import argparse
import os
import sys

from depshield import __version__
from depshield.core.engine import scan
from depshield.core.models import Severity
from depshield.output import terminal, json_output, sarif

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_RENDERERS = {
    "text": terminal.render,
    "json": json_output.render,
    "sarif": sarif.render,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depshield",
        description="Detect npm supply chain attacks: malicious install scripts, "
                    "typosquatting, obfuscation, dependency confusion, and more.",
    )
    parser.add_argument(
        "--version", action="version", version=f"depshield {__version__}"
    )

    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Scan a project for supply chain risks")
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the project root (default: current directory)",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    scan_parser.add_argument(
        "--exclude", "-e",
        action="append",
        default=[],
        metavar="ANALYZER",
        help="Exclude an analyzer by name (repeatable)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        project_path = os.path.abspath(args.path)
        if not os.path.isdir(project_path):
            print(f"Error: '{project_path}' is not a directory.", file=sys.stderr)
            return 2

        result = scan(
            project_path,
            exclude_analyzers=set(args.exclude),
        )

        min_sev = _SEVERITY_MAP[args.severity]
        renderer = _RENDERERS[args.format]
        renderer(result, min_severity=min_sev)

        return result.exit_code

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
