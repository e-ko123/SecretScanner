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

# `sys.stderr` is the "error output" stream, where error messages go.
import sys

# `version()` looks up the version number of an installed package.
# We use it so the version only lives in one place (pyproject.toml),
# instead of being typed out in two files that could get out of sync.
from importlib.metadata import version

# `Path` represents a file or folder location (see scanner.py).
from pathlib import Path

# Fingerprints and the .secretscanignore file (see ignores.py).
from secretscan.ignores import (
    IGNORE_FILE_NAME,
    IgnoreFileError,
    finding_id,
    load_ignore_file,
)

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


def print_findings(findings: list[Finding], ids: list[str] | None = None) -> None:
    """Print one line per finding, lined up in neat columns.

    Example output:
        src/settings.py:3   AWS Access Key ID   AKIA****************
        config/dev.py:12    AWS Access Key ID   AKIA****************

    If `ids` is given (with --show-ids), each finding's full ID is added as
    a last column. `ids[0]` belongs to `findings[0]`, and so on.

    A finding is only printed with a placeholder reason when the user asked
    to see placeholders (--include-placeholders). The reason is added at
    the end of its line, so the user can tell why it's normally hidden.
    """
    # Build the "file:line" text for every finding first, so we can
    # measure how wide the first column needs to be.
    locations = [f"{finding.path}:{finding.line_number}" for finding in findings]

    # The widest entry in each column decides that column's width.
    # `max(...)` here goes through every item and keeps the biggest length.
    location_width = max(len(location) for location in locations)
    rule_width = max(len(finding.rule_name) for finding in findings)

    # The secret itself is ALWAYS passed through mask() first: the tool
    # must never print a full secret.
    masked = [mask(finding.secret) for finding in findings]
    masked_width = max(len(text) for text in masked)

    # `enumerate` gives each finding together with its position (0, 1, 2...),
    # which we use to pick the matching item from the other lists.
    for index, finding in enumerate(findings):
        # `ljust(width)` pads text with spaces on the right until it's
        # `width` characters long. That's what makes the columns line up.
        line = (
            f"{locations[index].ljust(location_width)}   "
            f"{finding.rule_name.ljust(rule_width)}   "
        )
        if ids is not None:
            # Pad the masked secret too, so the ID column lines up.
            line += f"{masked[index].ljust(masked_width)}   {ids[index]}"
        else:
            line += masked[index]
        if finding.placeholder_reason:
            line += f"   (recognized placeholder: {finding.placeholder_reason})"
        print(line)


def plural(count: int, word: str) -> str:
    """Return e.g. "1 file" or "3 files", so the summary reads naturally."""
    if count == 1:
        return f"{count} {word}"
    return f"{count} {word}s"


def summary(findings: list[Finding], anything_hidden: bool = False) -> str:
    """Return the one-line summary printed at the end of a scan.

    Examples:
        "No secrets found."
        "No reportable secrets found."   (when some matches were hidden)
        "Found 1 possible secret in 1 file."
        "Found 3 possible secrets in 2 files."

    It says "possible" on purpose: the tool can't be 100% sure, because
    some matches may be fake keys or examples.

    `anything_hidden` is True when some matches were hidden (for example,
    recognized placeholders). Then "No secrets found." would overclaim:
    something WAS found, we just decided not to report it. So the wording
    changes to "No reportable secrets found."
    """
    if not findings and anything_hidden:
        return "No reportable secrets found."
    if not findings:
        return "No secrets found."

    # Count how many DIFFERENT files had findings. One file can have
    # several findings, so we can't just use len(findings).
    # `{... for ...}` (curly braces) builds a set, and a set automatically
    # throws away duplicates. So its size is the number of different files.
    file_count = len({finding.path for finding in findings})

    return (
        f"Found {plural(len(findings), 'possible secret')} "
        f"in {plural(file_count, 'file')}."
    )


def config_error(message: str) -> int:
    """Print a configuration error and return exit code 2.

    Used for problems with the ignore file. Exit code 2 means "something
    is wrong with how secretscan was set up", never "secrets found" (1).
    """
    # `file=sys.stderr` sends the message to the error output, like
    # argparse does with its own errors.
    print(f"secretscan: error: {message}", file=sys.stderr)
    return 2


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

    # `action="store_true"` makes this an on/off switch: if the user types
    # `--include-placeholders`, args.include_placeholders is True;
    # otherwise it's False. (argparse turns the dashes into underscores.)
    parser.add_argument(
        "--include-placeholders",
        action="store_true",
        help="also report recognized placeholder keys (like an all-X key) "
        "instead of hiding them",
    )

    # Show each finding's full ID, so it can be copied into the ignore file.
    parser.add_argument(
        "--show-ids",
        action="store_true",
        help="show each finding's ID (for dismissing it in a "
        f"{IGNORE_FILE_NAME} file)",
    )

    # --ignore-file and --no-ignore contradict each other ("use this ignore
    # file" vs "use no ignore file"). A "mutually exclusive group" tells
    # argparse to reject a command that uses both, with exit code 2.
    ignore_options = parser.add_mutually_exclusive_group()
    ignore_options.add_argument(
        "--ignore-file",
        # `metavar` is the placeholder name shown in --help: "--ignore-file PATH".
        metavar="PATH",
        help=f"use this ignore file instead of {IGNORE_FILE_NAME} in the "
        "scanned folder",
    )
    ignore_options.add_argument(
        "--no-ignore",
        action="store_true",
        help=f"don't use any ignore file (show findings dismissed in "
        f"{IGNORE_FILE_NAME}); placeholders and secretscan:ignore lines "
        "are still skipped",
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

    Returns the exit code: 0 = nothing reportable found, 1 = secrets found,
    2 = the command or the ignore file is wrong. Hidden placeholders and
    findings dismissed in the ignore file don't count as found.
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

    # The "scan root" is the folder that finding IDs are relative to, and
    # where we look for the ignore file. When scanning a folder, it's that
    # folder; when scanning one file, it's the folder the file is in.
    if path.is_dir():
        root = path
    else:
        root = path.parent

    # Work out which ignore file to use, if any.
    # `Path | None` in a type hint means "a Path, or None".
    ignore_path: Path | None
    if args.no_ignore:
        ignore_path = None
    elif args.ignore_file is not None:
        # The user named a file, so it must exist.
        ignore_path = Path(args.ignore_file)
        if not ignore_path.is_file():
            return config_error(f"ignore file not found: {ignore_path}")
    else:
        # Otherwise use .secretscanignore in the scan root, if it's there.
        # A missing default ignore file is normal: most projects won't have one.
        default = root / IGNORE_FILE_NAME
        if default.is_file():
            ignore_path = default
        else:
            ignore_path = None

    # Load the ignore file now, before scanning, so a broken file stops
    # everything with a clear error instead of being treated as empty.
    # `ignored_ids` maps each dismissed ID to the reason the user gave.
    ignored_ids: dict[str, str] = {}
    if ignore_path is not None:
        try:
            ignored_ids = load_ignore_file(ignore_path)
        except IgnoreFileError as error:
            return config_error(f"ignore file {ignore_path}: {error}")

    # The scan happens in clear stages, each with one job.

    # Stage 1: detect candidates. Scan every file and collect every match
    # into one list. `extend` adds all items from one list onto the end of
    # another (unlike `append`, which would add the whole list as one item).
    candidates = []
    for file in find_files(path):
        # Don't scan the ignore file itself: it's settings, not code.
        # `resolve()` turns both into full, absolute paths, so the same
        # file written two different ways still compares as equal.
        if ignore_path is not None and file.resolve() == ignore_path.resolve():
            continue
        candidates.extend(scan_file(file))

    # Stage 2: set aside recognized placeholders, unless the user asked to
    # see them. The scanner has already marked each candidate with a
    # `placeholder_reason` (None means "not a placeholder").
    if args.include_placeholders:
        findings = candidates
        placeholders = []
    else:
        findings = [c for c in candidates if c.placeholder_reason is None]
        placeholders = [c for c in candidates if c.placeholder_reason is not None]

    # Stage 3: give every remaining finding its ID (fingerprint).
    # Stage 4: drop findings whose ID is in the ignore file.
    # `reportable` and `reportable_ids` stay in step: item 0 of one belongs
    # with item 0 of the other.
    reportable = []
    reportable_ids = []
    ignored_count = 0
    for finding in findings:
        this_id = finding_id(finding, root)
        if this_id in ignored_ids:
            ignored_count += 1
        else:
            reportable.append(finding)
            reportable_ids.append(this_id)

    # Stage 5: print the findings (if there are any), then a blank line to
    # separate them from the summary. print_findings can't handle an empty
    # list, because there'd be nothing to measure the columns from.
    if reportable:
        if args.show_ids:
            print_findings(reportable, reportable_ids)
        else:
            print_findings(reportable)
        print()

    # Stage 6: always finish with a summary, so the user knows the scan
    # really ran, even when nothing was found.
    anything_hidden = bool(placeholders) or ignored_count > 0
    print(summary(reportable, anything_hidden=anything_hidden))

    # If anything was hidden, say how much, and how to see it. Hiding
    # things silently would leave the user no way to double-check us.
    if placeholders:
        print(
            f"Suppressed {plural(len(placeholders), 'recognized placeholder')} "
            "(use --include-placeholders to see)."
        )
    if ignored_count:
        print(
            f"Ignored {plural(ignored_count, 'finding')} listed in {ignore_path} "
            "(use --no-ignore to see)."
        )

    # An empty list counts as False in Python, so this reads as:
    # "if anything is left to report, exit with 1; otherwise exit with 0".
    # Hidden placeholders and dismissed findings don't count.
    if reportable:
        return 1
    return 0
