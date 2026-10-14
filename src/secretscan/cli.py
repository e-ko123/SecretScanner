"""Command-line interface: reads the user's arguments and runs secretscan.

This is the file that runs when someone types `secretscan` in a terminal.
The connection is made in pyproject.toml:

    [project.scripts]
    secretscan = "secretscan.cli:main"

which means "the `secretscan` command calls the `main` function in this file".
"""

# Lets us write modern type hints like `list[str] | None` on Python 3.9.
# Without this line, Python 3.9 would crash on that syntax, because the
# `X | Y` style was only added in Python 3.10. With it, Python treats type
# hints as plain text and doesn't try to evaluate them.
from __future__ import annotations

# argparse is Python's built-in tool for reading command-line options
# (like `--help` or `--version`). It also writes the help text for us.
import argparse

# `version()` looks up the version number of an installed package.
# We use it so the version only lives in one place (pyproject.toml),
# instead of being typed out in two files that could get out of sync.
from importlib.metadata import version


def build_parser() -> argparse.ArgumentParser:
    """Describe the options the `secretscan` command accepts.

    A "parser" is the object that knows which options exist and turns
    what the user typed into Python values we can use.
    """
    parser = argparse.ArgumentParser(
        # The program name shown in help and error messages.
        prog="secretscan",
        # The sentence shown at the top of `secretscan --help`.
        description="Find passwords, API keys, and private keys accidentally left in your code.",
    )

    # Add a `--version` option. `action="version"` is a built-in argparse
    # behavior: it prints the text below and then exits the program.
    # `%(prog)s` is filled in by argparse with the program name ("secretscan").
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('secretscan')}",
    )

    # Note: we don't add `--help` ourselves. argparse adds it automatically.
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `secretscan` command.

    `argv` is the list of options the user typed, for example ["--version"].
    - When the real command runs, nothing is passed in, so argv is None and
      argparse reads the options from the actual terminal command instead.
    - In tests, we pass a list directly, e.g. main(["--version"]). This lets
      us test the command without opening a real terminal.

    Returns the exit code: 0 = nothing found, 1 = secrets found.
    (The exit code is how git hooks and CI know whether to block or pass.)
    """
    parser = build_parser()

    # Read and check the options. If the user typed something invalid,
    # argparse prints an error and exits on its own.
    parser.parse_args(argv)

    # Nothing to scan yet, so report "nothing found". Scanning comes next.
    return 0
