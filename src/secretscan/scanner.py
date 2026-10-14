"""Scanner: reads files and checks each line against the rules.

The main job of this file is to turn "a file on disk" into
"a list of findings", where each finding says where a possible secret is.
"""

# Lets us use modern type hints on Python 3.9 (see cli.py for details).
from __future__ import annotations

# `dataclass` writes simple data-holding classes for us (see rules.py).
from dataclasses import dataclass

# `Path` represents a file or folder location. It's the modern, readable
# way to work with file paths in Python (instead of plain strings).
from pathlib import Path

# The list of rules to check, and the Rule type, from rules.py.
from secretscan.rules import RULES, Rule


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


def scan_line(line: str, rules: list[Rule] = RULES) -> list[tuple[Rule, str]]:
    """Check one line of text against every rule.

    Returns a list of (rule, matched_text) pairs, one for each match.
    An empty list means the line looks clean.

    `rules` defaults to all the real rules, but tests can pass in their own.
    """
    matches = []

    for rule in rules:
        # `finditer` finds EVERY match of the pattern in the line, not just
        # the first one, in case a single line contains two keys.
        for match in rule.pattern.finditer(line):
            # `match.group(0)` is the exact text the pattern matched.
            matches.append((rule, match.group(0)))

    return matches


def scan_file(path: Path) -> list[Finding]:
    """Read one file and return every possible secret found in it."""
    findings = []

    # Open the file for reading as text.
    # - encoding="utf-8": the most common text encoding for code.
    # - errors="replace": if some bytes aren't valid text, replace them with
    #   a placeholder character instead of crashing. (Skipping binary files
    #   properly comes in a later step.)
    # The `with` block automatically closes the file when we're done,
    # even if an error happens partway through.
    with open(path, encoding="utf-8", errors="replace") as file:
        # `enumerate(file, start=1)` gives us each line together with its
        # line number, counting from 1 instead of Python's usual 0.
        for line_number, line in enumerate(file, start=1):
            for rule, secret in scan_line(line):
                findings.append(
                    Finding(
                        path=str(path),
                        line_number=line_number,
                        rule_name=rule.name,
                        secret=secret,
                    )
                )

    return findings
