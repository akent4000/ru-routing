"""Command-line surface for the RU routing pipeline."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

COMMANDS = ("fetch", "build", "check", "publish", "rollback")


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level parser without wiring pipeline stages yet."""

    parser = argparse.ArgumentParser(prog="ru-routing")
    subcommands = parser.add_subparsers(dest="command", title="pipeline commands")
    for command in COMMANDS:
        subcommands.add_parser(command, help=f"{command} routing pipeline data")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse a pipeline command and report its current wiring status."""

    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    if arguments.command is None:
        parser.print_help()
        return 0

    print(f"ru-routing: error: {arguments.command} is not wired yet", file=sys.stderr)
    return 2


def run() -> None:
    """Run the command-line application."""

    raise SystemExit(main())


if __name__ == "__main__":
    run()
