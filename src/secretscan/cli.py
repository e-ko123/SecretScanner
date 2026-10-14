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

# `Path` represents a file or folder location (see scanner.py).
from pathlib import Path

# The function that does the actual scanning.
from secretscan.scanner import scan_file


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

    # The file to scan. Because the name has no leading dashes, argparse
    # treats it as a "positional" argument: the user just types it after
    # the command, like `secretscan config.py`.
    # (For now a file is required. Scanning folders, and defaulting to the
    # current folder, comes in the next step.)
    parser.add_argument(
        "path",
        help="the file to scan",
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

    `argv` is the list of options the user typed, for example ["config.py"].
    - When the real command runs, nothing is passed in, so argv is None and
      argparse reads the options from the actual terminal command instead.
    - In tests, we pass a list directly, e.g. main(["config.py"]). This lets
      us test the command without opening a real terminal.

    Returns the exit code: 0 = nothing found, 1 = secrets found.
    (The exit code is how git hooks and CI know whether to block or pass.)
    """
    parser = build_parser()

    # Read and check the options. If the user typed something invalid,
    # argparse prints an error and exits on its own.
    # `args.path` will hold the file name the user typed.
    args = parser.parse_args(argv)
    path = Path(args.path)

    # Check the file exists before trying to open it. `parser.error` prints
    # a short usage message plus our error text, then exits with code 2.
    # Code 2 is the standard argparse code for "you used the command wrong",
    # which keeps it separate from 1 ("secrets found").
    if not path.is_file():
        parser.error(f"file not found: {path}")

    findings = scan_file(path)

    # Print one line per finding, e.g.:  config.py:12  AWS Access Key ID
    # We deliberately do NOT print `finding.secret`: the tool must never
    # show a full secret on screen. A masked preview comes in a later step.
    for finding in findings:
        print(f"{finding.path}:{finding.line_number}  {finding.rule_name}")

    # An empty list counts as False in Python, so this reads as:
    # "if anything was found, exit with 1; otherwise exit with 0".
    if findings:
        return 1
    return 0
