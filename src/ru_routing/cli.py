"""Command-line surface for the RU routing pipeline."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .config import ConfigError, load_policy, load_registry, load_thresholds

COMMANDS = ("fetch", "build", "check", "publish", "rollback")


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level parser without wiring pipeline stages yet."""

    parser = argparse.ArgumentParser(prog="ru-routing")
    subcommands = parser.add_subparsers(dest="command", title="pipeline commands")
    for command in COMMANDS:
        command_parser = subcommands.add_parser(
            command, help=f"{command} routing pipeline data"
        )
        if command == "check":
            command_parser.add_argument(
                "--config-only",
                action="store_true",
                help="validate policy configuration",
            )
            command_parser.add_argument(
                "--config",
                type=Path,
                default=Path("config"),
                metavar="CONFIG_ROOT",
                help=(
                    "directory containing sources.yaml, categories.yaml, "
                    "and thresholds.yaml"
                ),
            )
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
    if arguments.command == "check" and arguments.config_only:
        try:
            registry = load_registry(arguments.config / "sources.yaml")
            policy = load_policy(arguments.config / "categories.yaml")
            load_thresholds(arguments.config / "thresholds.yaml")
            if set(policy.source_categories) != registry.declared_category_keys():
                raise ConfigError(
                    "source registry and category policy do not map the same keys"
                )
        except ConfigError as error:
            print(f"ru-routing: invalid configuration: {error}", file=sys.stderr)
            return 2
        print("ru-routing: configuration is valid")
        return 0

    print(f"ru-routing: error: {arguments.command} is not wired yet", file=sys.stderr)
    return 2


def run() -> None:
    """Run the command-line application."""

    raise SystemExit(main())


if __name__ == "__main__":
    run()
