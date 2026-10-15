"""Ignores: finding fingerprints and the optional .secretscanignore file.

Sometimes a finding is a false alarm that placeholder detection doesn't
catch, like a realistic-looking fake key in a test. Users can dismiss it
WITHOUT editing that file, by listing the finding's ID in a separate JSON
file called .secretscanignore:

    {
      "version": 1,
      "findings": [
        {"id": "<64-character fingerprint>", "reason": "Fake key used in tests"}
      ]
    }

This module does three jobs:
1. fingerprint: give each finding a stable ID.
2. load_ignore_file: read and strictly check the ignore file.
3. save_ignore_file: write it back, after `secretscan --review` adds entries.
"""

# Lets us write type hints like `dict[str, str]` on Python 3.9 (see cli.py).
from __future__ import annotations

# `hashlib` provides SHA-256, a "hash function": it turns any text into a
# fixed-length string of 64 hexadecimal characters (0-9, a-f). The same
# input always gives the same output, but even a one-letter change gives a
# completely different one, and you can't easily work backwards from it.
import hashlib

# `json` reads and writes JSON, a common text format for structured data.
import json

# `os.path.relpath` works out one path relative to another (see below).
import os

# `re` for checking that an ID looks like a real fingerprint.
import re
import tempfile

# `Path` represents a file or folder location (see scanner.py).
from pathlib import Path

# The type that holds one result (see scanner.py).
from secretscan.scanner import Finding, read_regular_file

# The biggest ignore file we'll read: 1 MB, the same limit as source files.
# A real one is a few kilobytes; anything bigger is a mistake or an attack.
MAX_IGNORE_FILE_SIZE = 1_000_000

# The name of the ignore file we look for in the scan root by default.
IGNORE_FILE_NAME = ".secretscanignore"

# Bumped if we ever change how fingerprints are built. It's part of every
# fingerprint, so IDs made the old way and the new way can never collide.
FINGERPRINT_VERSION = 1

# The only ignore-file "version" field value we understand.
IGNORE_FILE_VERSION = 1

# A full SHA-256 fingerprint: exactly 64 characters, each a digit or a
# lowercase letter a-f. Used with `fullmatch`, so the WHOLE ID must fit.
#   [0-9a-f]   one digit, or a lowercase letter from a to f...
#   {64}       ...repeated exactly 64 times.
FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")


class IgnoreFileError(Exception):
    """Raised when the ignore file can't be used (missing fields, bad JSON, ...).

    Making our own error type (a "subclass" of Python's Exception) lets the
    command-line tool catch exactly this problem and report it cleanly,
    without accidentally hiding unrelated bugs.

    Messages must never include the file's contents: if someone pasted a
    real key into the wrong place, an error message shouldn't print it.
    """


# ---------------------------------------------------------------------------
# 1. Fingerprints
# ---------------------------------------------------------------------------

def relative_path(file: str | Path, root: Path) -> str:
    """Return `file`'s path relative to the scan root, always using "/".

    Example: file "/home/me/project/src/app.py" with root "/home/me/project"
    gives "src/app.py". Using the relative path (not the full one) means
    the same project gives the same IDs wherever it's checked out.
    """
    # Use the REAL location of the file's folder (`resolve()` follows any
    # folder shortcuts), and of the root. Otherwise reaching the same project
    # through a shortcut, or through macOS's /var vs /private/var, would give
    # different paths and so different IDs. Only the folder is resolved, not
    # the file name itself, so a file that is a shortcut keeps its own name.
    file = Path(file)
    real_file = file.parent.resolve() / file.name
    # `os.path.relpath` works out the path from `root` to `file`.
    # `as_posix()` writes it with "/" between folders, even on Windows
    # (which uses "\"), so IDs are the same on every operating system.
    return Path(os.path.relpath(real_file, Path(root).resolve())).as_posix()


def fingerprint(rule_id: str, path: str, candidate: str) -> str:
    """Return a finding's ID: a SHA-256 hash of what makes it unique.

    The ID is built from:
    - the fingerprint format version,
    - the rule id (e.g. "aws-access-key-id"),
    - the file's path relative to the scan root (e.g. "src/app.py"),
    - the complete matched text.

    It deliberately leaves out the line number, so adding lines above a
    finding doesn't change its ID. One result: if the same key appears
    several times in the same file, every copy has the same ID, and
    dismissing that ID dismisses all of them.

    A hash is a fingerprint, not encryption. It means the ignore file
    doesn't store keys as plain text, but a short or guessable value could
    still be found by trying candidates until one gives the same hash.
    """
    # Turn the pieces into ONE string in a way that can't be ambiguous.
    # Simply gluing them together with a separator like ":" could be
    # tricked: if a value contained ":" itself, two different findings
    # could produce the same string. A JSON list keeps each piece separate,
    # because JSON marks where each string starts and ends (with quotes,
    # escaping any quotes inside).
    #   separators=(",", ":")  no extra spaces, so the text is always the same.
    #   ensure_ascii=False     keep non-English characters as they are.
    canonical = json.dumps(
        [FINGERPRINT_VERSION, rule_id, path, candidate],
        separators=(",", ":"),
        ensure_ascii=False,
    )

    # SHA-256 works on bytes, not text, so encode the string as UTF-8 first.
    # `hexdigest()` gives the hash as 64 hexadecimal characters.
    return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()


def finding_id(finding: Finding, root: Path) -> str:
    """Return the fingerprint for a Finding, relative to the scan root."""
    return fingerprint(
        finding.rule_id, relative_path(finding.path, root), finding.secret
    )


# ---------------------------------------------------------------------------
# 2. Loading the ignore file
# ---------------------------------------------------------------------------

def load_ignore_file(path: Path) -> dict[str, str]:
    """Read and check an ignore file.

    Returns a dictionary mapping each dismissed ID to the reason given.
    Raises IgnoreFileError if anything about the file is wrong. A broken
    ignore file is never treated as an empty one: that could quietly hide
    (or quietly un-hide) findings the user made decisions about.
    """
    # Read the file safely: one open, normal files only (a named pipe would
    # wait forever, and something like /dev/zero never ends), and at most
    # MAX_IGNORE_FILE_SIZE bytes (see read_regular_file in scanner.py).
    try:
        data = read_regular_file(path, MAX_IGNORE_FILE_SIZE)
    except OSError:
        raise IgnoreFileError("could not be read (it must be a regular file)")
    if len(data) > MAX_IGNORE_FILE_SIZE:
        raise IgnoreFileError("is larger than 1 MB")
    # "utf-8-sig" also accepts the invisible marker Windows Notepad adds.
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise IgnoreFileError("not valid UTF-8 text")

    # Parse the JSON. If it's broken, say where, but not what's there.
    # `json.JSONDecodeError` knows the line and column of the problem.
    try:
        # JSON normally keeps the last duplicate field, hiding mistakes.
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise IgnoreFileError("duplicate JSON field")
                result[key] = value
            return result

        data = json.loads(text, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise IgnoreFileError(
            f"not valid JSON (problem at line {error.lineno}, column {error.colno})"
        )

    # The top level must be a JSON object ({...}), which Python reads as a
    # dictionary, with exactly the fields "version" and "findings".
    # Unknown fields are rejected, so a typo like "findngs" is caught
    # instead of silently doing nothing.
    if not isinstance(data, dict):
        raise IgnoreFileError("the top level must be a JSON object")
    if set(data) != {"version", "findings"}:
        raise IgnoreFileError(
            'the top level must have exactly the fields "version" and "findings"'
        )

    # The version must be exactly the number 1. We check `type(...) is int`
    # rather than just `== 1`, because in Python `True == 1` is also true,
    # and `"version": true` shouldn't be accepted.
    version = data["version"]
    if type(version) is not int or version != IGNORE_FILE_VERSION:
        raise IgnoreFileError(
            f'unsupported "version" (supported: {IGNORE_FILE_VERSION})'
        )

    findings = data["findings"]
    if not isinstance(findings, list):
        raise IgnoreFileError('"findings" must be a list')

    ignored = {}

    # `enumerate` gives each entry together with its position (0, 1, 2...),
    # so error messages can point at the exact entry, e.g. "findings[2]".
    for index, entry in enumerate(findings):
        where = f"findings[{index}]"

        if not isinstance(entry, dict) or set(entry) != {"id", "reason"}:
            raise IgnoreFileError(
                f'{where} must be an object with exactly the fields "id" and "reason"'
            )

        entry_id = entry["id"]
        if not isinstance(entry_id, str) or not FINGERPRINT_PATTERN.fullmatch(entry_id):
            raise IgnoreFileError(
                f"{where}.id must be a full SHA-256 fingerprint "
                "(64 lowercase hexadecimal characters, as shown by --show-ids)"
            )

        # `.strip()` removes spaces from both ends, so a reason of just
        # spaces counts as empty. Every dismissal needs a real explanation.
        reason = entry["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise IgnoreFileError(f"{where}.reason must be a non-empty string")
        # JSON can spell out "half characters" (like \ud800) that aren't valid
        # text. Accepting one would make the next save crash, so reject it
        # now. Encoding to UTF-8 is the test: it fails on such characters.
        try:
            reason.encode("utf-8")
        except UnicodeEncodeError:
            raise IgnoreFileError(f"{where}.reason contains invalid Unicode")

        # The same ID listed twice is almost certainly a copy-paste mistake.
        if entry_id in ignored:
            raise IgnoreFileError(f"{where}.id is listed more than once")

        ignored[entry_id] = reason

    return ignored


# ---------------------------------------------------------------------------
# 3. Saving the ignore file
# ---------------------------------------------------------------------------

def save_ignore_file(path: Path, ignored: dict[str, str]) -> None:
    """Write `ignored` ({id: reason}) to `path` in the ignore-file format.

    Used by `secretscan --review`. Entries are written in the order they
    are in the dictionary (Python dictionaries remember insertion order), so
    entries already in the file stay where they were, and new ones go at
    the end. Any custom spacing in the old file is not kept.
    """
    data = {
        "version": IGNORE_FILE_VERSION,
        # One {"id": ..., "reason": ...} object per entry.
        # `.items()` gives each (key, value) pair of a dictionary.
        "findings": [
            {"id": entry_id, "reason": reason} for entry_id, reason in ignored.items()
        ],
    }

    # `indent=2` spreads the JSON over several lines, indented by 2 spaces,
    # so it's easy for people to read and review in a pull request.
    # The "\n" adds a final newline, which most editors and git expect.
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    # Write to a temporary file first, then swap it into place.
    # `os.replace` swaps in one step: the ignore file is always either the
    # complete old version or the complete new one, never half-written,
    # even if the program is stopped in the middle of saving.
    # If the ignore file is a shortcut (symlink) to a shared file, update
    # the shared file itself. Replacing the shortcut with a normal file would
    # silently split one shared ignore file into separate copies.
    # `os.path.realpath` follows shortcuts to the real location.
    target = Path(os.path.realpath(path))

    # Use a unique name, and remove it even after Ctrl-C or a failed rename.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                         dir=target.parent, prefix=target.name + ".",
                                         suffix=".tmp", delete=False) as file:
            temporary = Path(file.name)
            file.write(text)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
