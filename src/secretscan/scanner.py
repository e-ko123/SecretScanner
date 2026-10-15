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

# Files bigger than this are skipped. 1,000,000 bytes is about 1 MB.
# Files that large are almost always generated data (logs, data dumps,
# bundled code), not something a person typed a password into.
# (The underscores in 1_000_000 are just for readability; Python ignores them.)
MAX_FILE_SIZE = 1_000_000

# How many bytes from the start of a file we look at to decide whether it's
# binary. 8,000 is the same amount git checks. It's enough to be accurate
# without reading whole files twice.
BINARY_CHECK_BYTES = 8000


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


def is_too_large(path: Path) -> bool:
    """Return True if the file is bigger than MAX_FILE_SIZE."""
    # `stat()` asks the operating system for facts about the file without
    # opening it. `st_size` is its size in bytes.
    return path.stat().st_size > MAX_FILE_SIZE


def is_binary(path: Path) -> bool:
    """Return True if the file looks like binary data rather than text.

    Binary files (images, PDFs, compiled programs) almost always contain a
    "null byte": a byte with the value zero. Normal text files basically
    never do. So if one shows up near the start of the file, it's binary.
    """
    # "rb" means "read binary": give us the raw bytes, without trying to
    # turn them into text (which could fail on a binary file).
    with open(path, "rb") as file:
        start = file.read(BINARY_CHECK_BYTES)

    # b"\0" is a bytes value containing a single null byte.
    # (The `b` in front means "bytes", not a normal text string.)
    return b"\0" in start


def should_scan(path: Path) -> bool:
    """Decide whether a single file is worth scanning."""
    try:
        return not is_too_large(path) and not is_binary(path)
    except OSError:
        # OSError is the error Python raises when the operating system
        # can't do something with a file, e.g. we don't have permission to
        # read it, or it was deleted a moment ago. We can't scan a file we
        # can't read, so skip it instead of crashing the whole scan.
        return False


def find_files(path: Path) -> list[Path]:
    """Work out which files to scan.

    - If `path` is a single file, the answer is just that file.
    - If `path` is a folder, the answer is every file inside it, including
      files inside its subfolders, subfolders of those, and so on,
      except for folders listed in SKIP_FOLDERS.

    Either way, binary files and files over MAX_FILE_SIZE are left out.
    """
    # A single file: return it in a list, unless it should be skipped.
    if path.is_file():
        if should_scan(path):
            return [path]
        return []

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

            # Only keep real files that are worth scanning.
            # - `is_file()` skips odd things like "broken shortcuts"
            #   (symbolic links pointing at a file that's gone).
            # - `should_scan()` skips binary and very large files.
            if file.is_file() and should_scan(file):
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
    #   a placeholder character instead of crashing. Binary files are
    #   already filtered out by find_files, but a text file can still have
    #   the odd invalid byte, and one bad byte shouldn't stop the scan.
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
