"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from serpens_scout.configscan import scan_path, write_scan
from serpens_scout.pipeline import hunt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="serpens-scout",
        description="Passive Screening Serpens research and .NET config detection",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    hunt_parser = commands.add_parser("hunt", help="run the passive research pipeline")
    hunt_parser.add_argument("--out", type=Path, required=True, help="output directory")
    hunt_parser.add_argument("--github-limit", type=int, default=20, choices=range(1, 101))
    hunt_parser.add_argument("--skip-dns", action="store_true")
    scan_parser = commands.add_parser("scan", help="scan configs, directories, or archives")
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "hunt":
            result = hunt(args.out, args.github_limit, args.skip_dns)
            delta = result["reports"]["delta"]
            print(
                json.dumps(
                    {
                        "output": str(args.out.resolve()),
                        "delta_domains": len(delta["domains"]),
                        "delta_sha256": len(delta["sha256"]),
                        "github": result["github"]["status"],
                    }
                )
            )
        else:
            results = scan_path(args.path)
            write_scan(results, args.out)
            print(
                json.dumps(
                    {
                        "output": str(args.out.resolve()),
                        "scanned": len(results),
                        "suspicious": sum(
                            item.verdict in {"suspicious", "highly-suspicious"}
                            for item in results
                        ),
                    }
                )
            )
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"serpens-scout: {exc}", file=sys.stderr)
        return 1
