"""Scanner: finds files, reads them, and checks each line against the rules.

This file has two jobs:
1. find_files: work out WHICH files to scan (one file, or a whole folder).
2. scan_file:  turn one file into "a list of findings", where each finding
   says where a possible secret is.

Each finding also records whether it looks like a recognized placeholder
(see placeholders.py). The scanner keeps those findings rather than
dropping them, so the command-line tool can decide whether to show them
and can say how many it hid.
"""

# Lets us use modern type hints on Python 3.9 (see cli.py for details).
from __future__ import annotations

# `os` gives us `os.walk`, which visits every folder inside a folder.
import os
import re

# `dataclass` writes simple data-holding classes for us (see rules.py).
from dataclasses import dataclass

# `Path` represents a file or folder location. It's the modern, readable
# way to work with file paths in Python (instead of plain strings).
from pathlib import Path

# Decides whether a match is a recognized placeholder (see placeholders.py).
from secretscan.placeholders import placeholder_reason

# The list of rules to check, and the Rule type, from rules.py.
from secretscan.rules import RULES, Rule


# Folders we never look inside. They hold tools, downloaded dependencies,
# or generated files rather than code a person wrote, so scanning them would
# be slow (node_modules can contain tens of thousands of files) and noisy
# (other people's code can contain example keys).
#
# This is a `set` (curly braces) rather than a list. Sets are built for
# fast "is this name in here?" checks, which is exactly how we use it.
SKIP_FOLDERS = {
    ".git",          # git's own internal database
    "node_modules",  # JavaScript dependencies
    ".venv",         # Python virtual environments
    "venv",
    "__pycache__",   # Python's cached, compiled files
}

# Files bigger than this are skipped. 1,000,000 bytes is about 1 MB.
# Files that large are almost always generated data (logs, data dumps,
# bundled code), not something a person typed a password into.
# (The underscores in 1_000_000 are just for readability; Python ignores them.)
MAX_FILE_SIZE = 1_000_000

# How many bytes from the start of a file we look at to decide whether it's
# binary. 8,000 is the same amount git checks. It's enough to be accurate
# without reading whole files twice.
BINARY_CHECK_BYTES = 8000

# Inline suppression is limited to a trailing comment and one token match.
# Keeping the marker in one place makes the policy easy to locate.
IGNORE_MARKER = "secretscan:ignore"


@dataclass(frozen=True)
class Finding:
    """One possible secret found in a file."""

    # Which file it was found in, e.g. "config.py".
    path: str

    # Which line it was on. Starts at 1, like line numbers in an editor.
    line_number: int

    # The name of the rule that matched, e.g. "AWS Access Key ID".
    rule_name: str

    # The matched text itself. We keep it so we can show a masked preview
    # later (e.g. "AKIA****"). It must NEVER be printed in full.
    secret: str

    # The stable id of the rule that matched, e.g. "aws-access-key-id".
    # Used to build the finding's fingerprint (see ignores.py).
    # Defaults to "" so findings built by hand (e.g. in tests) still work.
    rule_id: str = ""

    # If this match is a recognized placeholder, a short reason why, e.g.
    # "token body is all 'X' filler". None means "not a placeholder: report
    # it". (`str | None` means "either a string or None".)
    placeholder_reason: str | None = None

    # Kept for audit output; only a single candidate on a marked line qualifies.
    inline_ignored: bool = False


def is_too_large(path: Path) -> bool:
    """Return True if the file is bigger than MAX_FILE_SIZE."""
    # `stat()` asks the operating system for facts about the file without
    # opening it. `st_size` is its size in bytes.
    return path.stat().st_size > MAX_FILE_SIZE


def text_encoding(start: bytes) -> str:
    """Recognize Unicode byte-order marks before checking for binary bytes."""
    # Check UTF-32 first: its little-endian marker starts like UTF-16's.
    if start.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32"
    if start.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    return "utf-8-sig"


def is_binary(path: Path) -> bool:
    with path.open("rb") as file:
        start = file.read(BINARY_CHECK_BYTES)
    return text_encoding(start) == "utf-8-sig" and b"\0" in start


@dataclass(frozen=True)
class ScanIssue:
    """A skipped path, with a safe reason and whether scanning failed."""
    path: str
    reason: str
    error: bool = False


def should_scan(path: Path, issues: list[ScanIssue] | None = None) -> bool:
    reason = ""
    failed = False
    try:
        if not path.is_file():
            reason, failed = "not a regular file", True
        elif is_too_large(path):
            reason = "over size limit"
        elif is_binary(path):
            reason = "binary file"
    except OSError:
        reason, failed = "could not read file", True
    if reason and issues is not None:
        issues.append(ScanIssue(str(path), reason, failed))
    return not reason


def find_files(path: Path, issues: list[ScanIssue] | None = None) -> list[Path]:
    """Find files while recording exclusions and traversal failures."""
    if issues is None:
        issues = []
    if not path.is_dir():
        return [path] if should_scan(path, issues) else []

    def walk_error(error: OSError) -> None:
        issues.append(ScanIssue(str(error.filename), "could not read directory", True))

    files = []
    for folder, subfolders, filenames in os.walk(path, onerror=walk_error):
        kept = []
        for name in sorted(subfolders):
            child = Path(folder) / name
            if name in SKIP_FOLDERS:
                issues.append(ScanIssue(str(child), "excluded directory"))
            elif child.is_symlink():
                # Following links automatically could escape the project or loop.
                issues.append(ScanIssue(str(child), "symlink directory"))
            else:
                kept.append(name)
        subfolders[:] = kept
        for name in sorted(filenames):
            file = Path(folder) / name
            if should_scan(file, issues):
                files.append(file)
    return files


def has_inline_ignore(line: str, matches: list[tuple[Rule, str]]) -> bool:
    """A trailing marker may dismiss one token, never a whole minified file."""
    # A header does not identify the private key below it, so it cannot be
    # safely dismissed by a line marker or a header-based fingerprint.
    return (len(matches) == 1 and matches[0][0].id != "private-key"
            and re.search(rf"(?:#|//)\s*{re.escape(IGNORE_MARKER)}\s*$", line) is not None)


def scan_line(line: str, rules: list[Rule] = RULES, include_inline: bool = False) -> list[tuple[Rule, str]]:
    """Check one line of text against every rule.

    Returns a list of (rule, matched_text) pairs, one for each match.
    An empty list means the line looks clean (or was marked to be ignored).

    `rules` defaults to all the real rules, but tests can pass in their own.
    """
    matches = []

    for rule in rules:
        # `finditer` finds EVERY match of the pattern in the line, not just
        # the first one, in case a single line contains two keys.
        for match in rule.pattern.finditer(line):
            # `match.group(0)` is the exact text the pattern matched.
            matches.append((rule, match.group(0)))

    if not include_inline and has_inline_ignore(line, matches):
        return []
    return matches


def scan_file(path: Path, include_inline: bool = False) -> list[Finding]:
    """Read one file and return every possible secret found in it."""
    findings = []

    # Open the file for reading as text.
    # - encoding="utf-8": the most common text encoding for code.
    # - errors="replace": if some bytes aren't valid text, replace them with
    #   a placeholder character instead of crashing. Binary files are
    #   already filtered out by find_files, but a text file can still have
    #   the odd invalid byte, and one bad byte shouldn't stop the scan.
    # The `with` block automatically closes the file when we're done,
    # even if an error happens partway through.
    with path.open("rb") as raw:
        encoding = text_encoding(raw.read(4))
    with open(path, encoding=encoding, errors="replace") as file:
        # `enumerate(file, start=1)` gives us each line together with its
        # line number, counting from 1 instead of Python's usual 0.
        lines = file.readlines()
        for line_number, line in enumerate(lines, start=1):
            matches = scan_line(line, include_inline=True)
            inline_ignored = has_inline_ignore(line, matches)
            if inline_ignored and not include_inline:
                continue
            for rule, secret in matches:
                findings.append(
                    Finding(
                        path=str(path),
                        line_number=line_number,
                        rule_name=rule.name,
                        secret=secret,
                        # Custom rules may not have an id; fall back to the
                        # name so every finding still has an identifier.
                        # (`a or b` gives `a`, unless `a` is empty, then `b`.)
                        rule_id=rule.id or rule.name,
                        # Each match is checked on its own, so a placeholder
                        # and a real key on the same line are handled
                        # separately.
                        placeholder_reason=placeholder_reason(rule, secret),
                        inline_ignored=inline_ignored,
                    )
                )

    # Recognize two adjacent quoted fragments (Python implicit concatenation,
    # or a +/backslash continuation). Only report matches crossing the join;
    # complete tokens in either fragment were already handled above.
    split_literal = re.compile(
        r"(?P<quote>[\"'])(?P<left>[^\"'\r\n]+)(?P=quote)[ \t]*"
        r"(?:\+|\\)?[ \t]*\r?\n[ \t]*"
        r"(?P=quote)(?P<right>[^\"'\r\n]+)(?P=quote)"
    )
    for number, (first, second) in enumerate(zip(lines, lines[1:]), start=1):
        for parts in split_literal.finditer(first + second):
            left, right = parts.group("left", "right")
            for rule in RULES:
                for match in rule.pattern.finditer(left + right):
                    if match.start() < len(left) < match.end():
                        secret = match.group(0)
                        findings.append(Finding(
                            path=str(path), line_number=number,
                            rule_name=rule.name, secret=secret,
                            rule_id=rule.id or rule.name,
                            placeholder_reason=placeholder_reason(rule, secret),
                        ))

    return findings
