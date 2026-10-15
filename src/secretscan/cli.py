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

# `find_files` works out which files to scan; `scan_file` scans one file.
# `Finding` is the type that holds one result (used in type hints below).
from secretscan.scanner import Finding, find_files, scan_file

# How many characters of a secret we show before hiding the rest with `*`.
# 4 is enough to recognise which key it is (e.g. "AKIA" = AWS), but far too
# little for anyone to actually use it.
VISIBLE_CHARS = 4


def mask(secret: str) -> str:
    """Hide most of a secret so it's safe to print.

    Examples:
        mask("AKIA" + 16 more characters)  ->  "AKIA****************"
        mask("hunter2")                    ->  "*******"

    The result is always the same length as the secret, so you can still
    tell roughly how long it was.
    """
    # Short secrets are hidden completely. If a password is only 6
    # characters long, showing the first 4 would give away most of it.
    # "VISIBLE_CHARS * 2" means: only show the start if at least as many
    # characters stay hidden as are shown.
    if len(secret) <= VISIBLE_CHARS * 2:
        return "*" * len(secret)

    # `secret[:VISIBLE_CHARS]` is a "slice": the first 4 characters.
    # Then add one `*` for every remaining character.
    # (In Python, multiplying a string by a number repeats it: "*" * 3 == "***".)
    hidden_count = len(secret) - VISIBLE_CHARS
    return secret[:VISIBLE_CHARS] + "*" * hidden_count


def print_findings(findings: list[Finding]) -> None:
    """Print one line per finding, lined up in neat columns.

    Example output:
        src/settings.py:3   AWS Access Key ID   AKIA****************
        config/dev.py:12    AWS Access Key ID   AKIA****************
    """
    # Build the "file:line" text for every finding first, so we can
    # measure how wide the first column needs to be.
    locations = [f"{finding.path}:{finding.line_number}" for finding in findings]

    # The widest entry in each column decides that column's width.
    # `max(...)` here goes through every item and keeps the biggest length.
    location_width = max(len(location) for location in locations)
    rule_width = max(len(finding.rule_name) for finding in findings)

    # `zip` walks through two lists side by side, giving us one item from
    # each at a time: (first location, first finding), (second, second)...
    for location, finding in zip(locations, findings):
        # `ljust(width)` pads text with spaces on the right until it's
        # `width` characters long. That's what makes the columns line up.
        # The secret itself is ALWAYS passed through mask() first: the
        # tool must never print a full secret.
        print(
            f"{location.ljust(location_width)}   "
            f"{finding.rule_name.ljust(rule_width)}   "
            f"{mask(finding.secret)}"
        )


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

    # The file or folder to scan. Because the name has no leading dashes,
    # argparse treats it as a "positional" argument: the user just types it
    # after the command, like `secretscan config.py` or `secretscan src/`.
    # - nargs="?" means "this is optional: zero or one value".
    # - default="." means "if the user leaves it out, use the current folder"
    #   ("." is the standard shorthand for "the folder I'm in right now").
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="the file or folder to scan (default: the current folder)",
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
    # `args.path` holds the file or folder the user typed (or "." if none).
    args = parser.parse_args(argv)
    path = Path(args.path)

    # Check the path exists before trying to scan it. `parser.error` prints
    # a short usage message plus our error text, then exits with code 2.
    # Code 2 is the standard argparse code for "you used the command wrong",
    # which keeps it separate from 1 ("secrets found").
    if not path.exists():
        parser.error(f"path not found: {path}")

    # Scan every file and collect all the findings into one list.
    # `extend` adds all items from one list onto the end of another
    # (unlike `append`, which would add the whole list as a single item).
    findings = []
    for file in find_files(path):
        findings.extend(scan_file(file))

    # Print the findings (if there are any). print_findings can't handle an
    # empty list, because there'd be nothing to measure the columns from.
    if findings:
        print_findings(findings)

    # An empty list counts as False in Python, so this reads as:
    # "if anything was found, exit with 1; otherwise exit with 0".
    if findings:
        return 1
    return 0
