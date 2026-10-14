"""Command-line interface: reads the user's arguments and runs secretscan."""

from __future__ import annotations

import argparse
from importlib.metadata import version


def build_parser() -> argparse.ArgumentParser:
    """Describe the options the `secretscan` command accepts."""
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Find passwords, API keys, and private keys accidentally left in your code.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('secretscan')}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `secretscan` command.

    Returns the exit code: 0 = nothing found, 1 = secrets found.
    """
    parser = build_parser()
    parser.parse_args(argv)
    return 0
