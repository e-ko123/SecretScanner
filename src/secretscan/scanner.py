"""Scanner: finds files, reads them, and checks each line against the rules.

This file has two jobs:
1. find_files: work out WHICH files to scan (one file, or a whole folder).
2. scan_file:  turn one file into "a list of findings", where each finding
   says where a possible secret is.
"""

# Lets us use modern type hints on Python 3.9 (see cli.py for details).
from __future__ import annotations

# `os` gives us `os.walk`, which visits every folder inside a folder.
import os

# `dataclass` writes simple data-holding classes for us (see rules.py).
from dataclasses import dataclass

# `Path` represents a file or folder location. It's the modern, readable
# way to work with file paths in Python (instead of plain strings).
from pathlib import Path

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
    "dist",          # build output
    "build",
}


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


def find_files(path: Path) -> list[Path]:
    """Work out which files to scan.

    - If `path` is a single file, the answer is just that file.
    - If `path` is a folder, the answer is every file inside it, including
      files inside its subfolders, subfolders of those, and so on,
      except for folders listed in SKIP_FOLDERS.
    """
    # A single file: nothing to search for, just return it in a list.
    if path.is_file():
        return [path]

    files = []

    # `os.walk` visits `path` and then every folder inside it, one at a time.
    # For each folder it visits, it gives us three things:
    #   folder      - the folder it's currently in, e.g. "src/secretscan"
    #   subfolders  - the names of the folders directly inside it
    #   filenames   - the names of the files directly inside it
    for folder, subfolders, filenames in os.walk(path):
        # os.walk uses the `subfolders` list to decide where to go next.
        # So if we change that list, we change where os.walk goes. We
        # replace its contents with only the folders we want to visit,
        # sorted alphabetically:
        #
        # - `[name for name in subfolders if name not in SKIP_FOLDERS]` is a
        #   "list comprehension": a one-line way to build a new list by
        #   filtering another one. It keeps every name NOT in SKIP_FOLDERS.
        # - `sorted(...)` puts them in alphabetical order, so files are
        #   always visited (and reported) in the same order every time.
        # - `subfolders[:] = ...` replaces the contents of the *existing*
        #   list. This detail matters: writing `subfolders = ...` would
        #   only create a new list with the same name, and os.walk (which
        #   still holds the old list) would never see our change.
        subfolders[:] = sorted(
            name for name in subfolders if name not in SKIP_FOLDERS
        )

        # Sort the file names too, for the same reason.
        for filename in sorted(filenames):
            # Join the folder and file name into one path,
            # e.g. "src/secretscan" + "cli.py" -> "src/secretscan/cli.py".
            # (The `/` operator joins paths when used on Path objects.)
            file = Path(folder) / filename

            # Only keep real files. This skips odd things like "broken
            # shortcuts" (symbolic links pointing at a file that's gone).
            if file.is_file():
                files.append(file)

    return files


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
