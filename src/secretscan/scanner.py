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

# `io` lets us treat bytes already in memory like an open text file.
import io

# `os` gives us `os.walk`, which visits every folder inside a folder.
import os
import re

# `stat` explains the "mode" numbers the operating system reports, e.g.
# whether a path is a normal file or a special one like a pipe.
import stat

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

# If a line ends with a comment containing this text, its match is hidden.
# Users can silence a known false alarm this way, e.g. a fake key in docs:
#
#     EXAMPLE_KEY = "..."  # secretscan:ignore
#
# It only works for a comment at the END of a line with exactly ONE match
# (see has_inline_ignore for why).
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

    # True if a `secretscan:ignore` comment on this line hides this finding.
    # Hidden findings are kept (not thrown away), so the tool can count them
    # and show them again with --include-inline-ignored.
    inline_ignored: bool = False


def is_too_large(path: Path) -> bool:
    """Return True if the file is bigger than MAX_FILE_SIZE."""
    # `stat()` asks the operating system for facts about the file without
    # opening it. `st_size` is its size in bytes.
    return path.stat().st_size > MAX_FILE_SIZE


def text_encoding(start: bytes) -> str:
    """Work out how a file's text is stored, from its first few bytes.

    `start` is the beginning of the file as raw bytes.

    Text can be saved in different "encodings" (ways of turning letters
    into bytes). Most code is UTF-8, which needs no special marker. But
    UTF-16 and UTF-32 files (common on Windows) usually begin with a
    "byte-order mark" (BOM): a few invisible bytes that say which encoding
    follows. Those encodings also contain lots of zero bytes, which would
    otherwise make the file look binary, so this check runs first.

    Returns the encoding name Python should use to read the file.
    """
    # `startswith` can take a tuple (several options in round brackets);
    # it's True if the bytes start with ANY of them. The b"..." values are
    # the BOMs, written as hex bytes: \xff is the byte with value 255.
    # There are two of each because the bytes can come in either order
    # ("little-endian" or "big-endian", depending on the computer).
    #
    # Check UTF-32 first: its little-endian marker starts like UTF-16's.
    if start.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32"
    if start.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    # No marker: assume UTF-8. "utf-8-sig" is UTF-8 that also quietly skips
    # the optional UTF-8 marker that some Windows editors add.
    return "utf-8-sig"


def read_regular_file(path: Path, limit: int) -> bytes:
    """Open `path` ONCE, check it's a normal file, and read at most `limit` + 1 bytes.

    Doing all of this on one open file (instead of checking the path and
    then opening it again later) matters because files can change in
    between. Something could swap a small file for a huge one, or for a
    "named pipe" (a special file that waits forever for data), after an
    earlier check said it was fine.

    Reading one byte more than `limit` lets the caller tell "exactly at the
    limit" apart from "too big". Raises OSError if the file can't be used.
    """
    # O_NONBLOCK makes opening a named pipe return immediately instead of
    # waiting for someone to write to it. It has no effect on normal files.
    # `getattr(os, "O_NONBLOCK", 0)` uses 0 (no flag) on Windows, which
    # doesn't have it.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        # `fstat` asks about the file we actually opened, not the path,
        # so the answer can't change between the check and the read.
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"not a regular file: {path}")
        # `fdopen` wraps the low-level descriptor in a normal file object.
        # From here on, the `with` block is responsible for closing it.
        file = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with file:
        return file.read(limit + 1)


def is_binary(path: Path) -> bool:
    """Return True if the file looks like binary data rather than text.

    Binary files (images, PDFs, compiled programs) almost always contain a
    "null byte": a byte with the value zero. Normal UTF-8 text basically
    never does, so a null byte near the start means "binary".
    """
    # Read only the first BINARY_CHECK_BYTES bytes, safely (see
    # read_regular_file). `[:BINARY_CHECK_BYTES]` trims the extra byte that
    # read_regular_file reads past the limit.
    start = read_regular_file(path, BINARY_CHECK_BYTES)[:BINARY_CHECK_BYTES]
    # UTF-16 and UTF-32 text is full of zero bytes, so the null-byte test
    # only applies to files without one of their markers (see text_encoding).
    return text_encoding(start) == "utf-8-sig" and b"\0" in start


@dataclass(frozen=True)
class ScanIssue:
    """One path that wasn't scanned, and why.

    The command-line tool lists these at the end of a scan, so a skipped
    file is never silently treated as "no secrets here".
    """

    # The file or folder that was skipped.
    path: str

    # A short reason that's safe to print, e.g. "binary file". It never
    # contains file contents.
    reason: str

    # True if something went WRONG (e.g. "could not read file"), as opposed
    # to an expected skip (e.g. "excluded directory"). Errors make the
    # scan exit with code 2, because its result can't be trusted.
    error: bool = False


def should_scan(path: Path, issues: list[ScanIssue] | None = None) -> bool:
    """Decide whether a single file is worth scanning.

    If the answer is no and an `issues` list was given, a ScanIssue saying
    why is added to it. Passing a list in like this lets the caller collect
    every reason from every file in one place.
    """
    # `reason` stays "" (empty) unless we find a reason to skip the file.
    reason = ""
    failed = False
    try:
        # Check in order, stopping at the first reason found (`elif` means
        # "otherwise, if"). The cheap checks come first: `is_file` and the
        # size don't open the file at all.
        if not path.is_file():
            # Folders, pipes, devices, broken shortcuts...
            # `a, b = x, y` sets two variables in one line.
            reason, failed = "not a regular file", True
        elif is_too_large(path):
            reason = "over size limit"
        elif is_binary(path):
            reason = "binary file"
    except OSError:
        # OSError is the error Python raises when the operating system
        # can't do something with a file, e.g. no permission to read it.
        reason, failed = "could not read file", True
    if reason and issues is not None:
        issues.append(ScanIssue(str(path), reason, failed))
    # An empty string counts as False, so `not reason` is True ("scan it")
    # exactly when no reason to skip was found.
    return not reason


def find_files(path: Path, issues: list[ScanIssue] | None = None) -> list[Path]:
    """Work out which files to scan.

    - If `path` is a single file, the answer is just that file.
    - If `path` is a folder, the answer is every file inside it, including
      files in subfolders, except the ones skipped below.

    Every skipped path is recorded in `issues` (if given), with the reason.
    """
    # If the caller didn't pass a list, use a throwaway one so the code
    # below can always add to it.
    if issues is None:
        issues = []

    # A single file: return it in a list, unless it should be skipped.
    # `[path] if ... else []` is a one-line if/else that picks a value.
    if not path.is_dir():
        return [path] if should_scan(path, issues) else []

    # os.walk silently ignores folders it can't open unless we give it an
    # `onerror` function. This small function, defined inside find_files,
    # records each such folder as an issue instead. (A function defined
    # inside another one can use the outer function's variables, here
    # `issues`.)
    def walk_error(error: OSError) -> None:
        issues.append(ScanIssue(str(error.filename), "could not read directory", True))

    files = []

    # `os.walk` visits `path` and then every folder inside it, one at a time.
    # For each folder it gives us: the folder's path, the names of the
    # folders directly inside it, and the names of the files directly inside it.
    for folder, subfolders, filenames in os.walk(path, onerror=walk_error):
        # Decide which subfolders to go into, in alphabetical order (so the
        # output is in the same order every run). Skipped ones are recorded.
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
        # os.walk decides where to go next by reading the `subfolders` list,
        # so we replace its CONTENTS with only the folders we kept.
        # `subfolders[:] = ...` changes the existing list that os.walk is
        # holding; `subfolders = ...` would make a new list it never sees.
        subfolders[:] = kept
        for name in sorted(filenames):
            file = Path(folder) / name
            if file.is_symlink():
                # A file shortcut can point anywhere on the computer, outside
                # the folder being scanned. Skip it (and say so) rather than
                # read unrelated files. Naming one directly still scans it.
                issues.append(ScanIssue(str(file), "symlink file"))
            elif should_scan(file, issues):
                files.append(file)
    return files


def has_inline_ignore(line: str, matches: list[tuple[Rule, str]]) -> bool:
    """Return True if this line's `secretscan:ignore` comment should hide its match.

    `matches` is what scan_line found on the line. The comment only counts
    when ALL of these are true:
    - the line has exactly ONE match. Otherwise one comment at the end of
      a minified file (where everything is on one line) could hide every
      key in the file.
    - that match isn't a private key (a key spans many lines, and the
      comment is only on one of them).
    - the marker is a real comment at the very END of the line.
    """
    # A header does not identify the private key below it, so it cannot be
    # safely dismissed by a line marker or a header-based fingerprint.
    # The pattern: start of line or a whitespace character, then # or //,
    # then optional spaces, the marker, optional spaces, and the line end.
    # Requiring whitespace before # or // means text like a URL ending in
    # "...#secretscan:ignore" (where # is part of the data, not a comment)
    # doesn't count. A marker inside a string that has a space before it
    # still can't be told apart from a comment; .secretscanignore is the
    # safer choice for those.
    return (len(matches) == 1 and matches[0][0].id != "private-key"
            and re.search(rf"(?:^|\s)(?:#|//)\s*{re.escape(IGNORE_MARKER)}\s*$", line) is not None)


def scan_line(line: str, rules: list[Rule] = RULES, include_inline: bool = False) -> list[tuple[Rule, str]]:
    """Check one line of text against every rule.

    Returns a list of (rule, matched_text) pairs, one for each match.
    An empty list means the line looks clean (or was marked to be ignored).

    `rules` defaults to all the real rules, but tests can pass in their own.
    `include_inline=True` means "report matches even if the line has a
    secretscan:ignore comment". scan_file uses it so it can count how many
    matches the comments hid, instead of losing track of them.
    """
    matches = []

    for rule in rules:
        # `finditer` finds EVERY match of the pattern in the line, not just
        # the first one, in case a single line contains two keys.
        for match in rule.pattern.finditer(line):
            # `match.group(0)` is the exact text the pattern matched.
            matches.append((rule, match.group(0)))

    # Only after finding the matches can we tell whether the comment
    # applies (it needs exactly one match; see has_inline_ignore).
    if not include_inline and has_inline_ignore(line, matches):
        return []
    return matches


# ---------------------------------------------------------------------------
# Keys split across two quoted strings
# ---------------------------------------------------------------------------
# Long keys are sometimes split over two lines:
#
#     key = ("AKIA1234"            Python: two strings next to each other
#            "5678ABCD...")        inside brackets are joined automatically
#
#     const key = "AKIA1234" +     JavaScript: joined with +
#         "5678ABCD...";
#
# The pattern, piece by piece (it's run on two lines glued together):
#   (?P<q1>["'])(?P<left>[^"'\r\n]+)(?P=q1)
#                       a quoted fragment: an opening quote, the text, and
#                       the SAME quote again ((?P=q1) means "what q1 matched").
#   [ \t]*              spaces or tabs.
#   (?:(?P<op1>[+\\])[ \t]*)?
#                       optionally a + or \ (line continuation), then spaces.
#   (?:(?:\#|//)[^\r\n]*)?
#                       optionally a comment up to the end of the line.
#   \r?\n               the line break.
#   [ \t]*(?:(?P<op2>\+)[ \t]*)?
#                       spaces, optionally a + at the START of line 2.
#   (?P<q2>["'])(?P<right>[^"'\r\n]+)(?P=q2)
#                       the second quoted fragment (its quote may differ).
#
# Each repeated piece ([ \t]*) is followed by something that can never be a
# space (+, \, #, /, a newline, or a quote). That keeps the regex fast: an
# earlier version had two space-runs side by side, so on a line with many
# spaces the engine tried every way of splitting them between the two runs,
# which got slower and slower (quadratically) as lines got longer.
SPLIT_LITERAL = re.compile(
    r"(?P<q1>[\"'])(?P<left>[^\"'\r\n]+)(?P=q1)"
    r"[ \t]*(?:(?P<op1>[+\\])[ \t]*)?(?:(?:\#|//)[^\r\n]*)?\r?\n"
    r"[ \t]*(?:(?P<op2>\+)[ \t]*)?"
    r"(?P<q2>[\"'])(?P<right>[^\"'\r\n]+)(?P=q2)"
)

# Used to roughly track brackets: a quoted string or a comment, whose
# brackets don't count.
STRINGS_AND_COMMENTS = re.compile(r"\"[^\"\r\n]*\"|'[^'\r\n]*'|(?:\#|//)[^\r\n]*")


def bracket_depths(lines: list[str]) -> list[int]:
    """For each line, how many brackets are still open at the END of it.

    Python only joins two strings on separate lines automatically when
    they're inside brackets. At depth 0 they're two separate statements, so
    joining them would invent a key that doesn't exist. This is a rough
    count (it ignores quotes and comments on each line, nothing smarter),
    but it's enough to tell those two situations apart.
    """
    depths = []
    depth = 0
    for line in lines:
        code = STRINGS_AND_COMMENTS.sub("", line)
        depth += sum(code.count(c) for c in "([{") - sum(code.count(c) for c in ")]}")
        # Never go below 0, so one stray ")" can't throw off the rest.
        depth = max(depth, 0)
        depths.append(depth)
    return depths


# ---------------------------------------------------------------------------
# JSON-style \u escapes
# ---------------------------------------------------------------------------
# JSON can write any character as \u plus 4 hex digits: "A" is "A".
# So "AKIA..." is an AWS key once decoded, but the raw text has no
# "AKIA" in it. We decode only the plain-English range (\u0000 to \u007f),
# which is all the characters keys are made of.
#   \\u00       a backslash, "u", and "00".
#   ([0-7][0-9a-fA-F])  the last two hex digits, 00 to 7f.
JSON_ASCII_ESCAPE = re.compile(r"\\u00([0-7][0-9a-fA-F])")


def decode_json_escapes(line: str) -> str:
    # `int(text, 16)` reads hexadecimal; `chr` turns the number into a character.
    return JSON_ASCII_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), line)


# ---------------------------------------------------------------------------
# Private key blocks
# ---------------------------------------------------------------------------
# A header line alone (for example in documentation explaining what a key
# file looks like) isn't a leak. A real key has encoded key data right below
# the header: lines of 64 or more "base64" characters (letters, digits, + and /).
KEY_DATA = re.compile(r"[A-Za-z0-9+/]{60,}")
# Where a key block ends: the PEM end line (PGP keys add " BLOCK" to it,
# hence the optional `(?: BLOCK)?`), or PuTTY's last line.
KEY_END = re.compile(r"-----END[A-Z ]*PRIVATE KEY(?: BLOCK)?-----|Private-MAC: *[0-9a-f]+")
# How many lines after the header we look at for the start of the key data.
# PuTTY files have up to 3 short "Name: value" lines before their data.
KEY_DATA_LINES = 5


def private_key_block(lines: list[str], index: int, start: int) -> str | None:
    """Return the key's text from its header to its end, or None for a header mention.

    `lines[index]` is the header's line and `start` is where the header
    begins in it. The returned text (with spaces, line breaks, and "\n"
    escapes removed) becomes the finding's `secret`, so the finding's ID
    identifies THIS key's data rather than the header every key shares.
    """
    # The header line's rest plus the next few lines: where key data must start.
    nearby = lines[index][start:] + "".join(lines[index + 1:index + 1 + KEY_DATA_LINES])
    if not KEY_DATA.search(nearby):
        return None

    # The whole block: up to the end marker if there is one (searching at
    # most 200 lines ahead), otherwise just the nearby text.
    ahead = lines[index][start:] + "".join(lines[index + 1:index + 200])
    end = KEY_END.search(ahead)
    block = ahead[:end.end()] if end else nearby
    # \s+ is any run of whitespace; \\[nr] is a written-out "\n" or "\r",
    # as in a key stored inside a JSON string.
    return re.sub(r"\s+|\\[nr]", "", block)


def scan_file(path: Path, include_inline: bool = False) -> list[Finding]:
    """Read one file and return every possible secret found in it."""
    findings = []

    # Read the file once, safely (see read_regular_file). If it grew past
    # the size limit since find_files checked it, refuse rather than read
    # an unbounded amount.
    data = read_regular_file(path, MAX_FILE_SIZE)
    if len(data) > MAX_FILE_SIZE:
        raise OSError(f"file grew past the size limit: {path}")

    # Turn the bytes into lines of text, exactly like opening the file as
    # text would. `TextIOWrapper` over `BytesIO` reads from the bytes we
    # already have instead of opening the file again.
    # - errors="replace": a few invalid bytes become a placeholder
    #   character instead of stopping the scan.
    encoding = text_encoding(data[:4])
    lines = io.TextIOWrapper(io.BytesIO(data), encoding=encoding, errors="replace").readlines()

    def add(line_number: int, rule: Rule, secret: str, inline_ignored: bool = False) -> None:
        """Record one finding (a small helper so every place builds it the same way)."""
        findings.append(Finding(
            path=str(path),
            line_number=line_number,
            rule_name=rule.name,
            secret=secret,
            # Custom rules may not have an id; fall back to the name so
            # every finding still has an identifier.
            # (`a or b` gives `a`, unless `a` is empty, then `b`.)
            rule_id=rule.id or rule.name,
            # Each match is checked on its own, so a placeholder and a real
            # key on the same line are handled separately.
            placeholder_reason=placeholder_reason(rule, secret),
            inline_ignored=inline_ignored,
        ))

    # `enumerate(lines, start=1)` gives us each line together with its
    # line number, counting from 1 instead of Python's usual 0.
    for line_number, line in enumerate(lines, start=1):
        matches = scan_line(line, include_inline=True)

        # Also look at the line with JSON \u escapes decoded, keeping only
        # keys the raw line didn't already show.
        decoded = decode_json_escapes(line)
        if decoded != line:
            already = {secret for _, secret in matches}
            matches += [m for m in scan_line(decoded, include_inline=True) if m[1] not in already]

        inline_ignored = has_inline_ignore(line, matches)
        if inline_ignored and not include_inline:
            continue
        for rule, secret in matches:
            if rule.id == "private-key":
                # Replace the shared header with this key's own data; skip
                # headers that have no key data under them.
                block = private_key_block(lines, line_number - 1, max(line.find(secret), 0))
                if block is None:
                    continue
                secret = block
            add(line_number, rule, secret, inline_ignored)

    # Keys split across two quoted fragments on neighboring lines.
    depths = bracket_depths(lines)
    for number, (first, second) in enumerate(zip(lines, lines[1:]), start=1):
        for parts in SPLIT_LITERAL.finditer(first + second):
            # Only join when the language really would: with a + or \, or
            # inside brackets that are still open at the end of line 1.
            joined_by_operator = parts.group("op1") or parts.group("op2")
            if not joined_by_operator and depths[number - 1] == 0:
                continue
            left, right = parts.group("left", "right")
            for rule in RULES:
                # A private-key header split over two strings has no key data
                # to identify it (see private_key_block), so it's not joined.
                if rule.id == "private-key":
                    continue
                for match in rule.pattern.finditer(left + right):
                    # Only matches that cross the join are new; keys entirely
                    # inside one fragment were found line by line above.
                    if match.start() < len(left) < match.end():
                        secret = match.group(0)
                        # The line-by-line pass may have reported the first
                        # half on its own (a long key's first fragment can
                        # be long enough to match). Drop that partial copy.
                        findings[:] = [
                            f for f in findings
                            if not (f.line_number == number and f.rule_id == (rule.id or rule.name)
                                    and secret.startswith(f.secret) and left.endswith(f.secret))
                        ]
                        add(number, rule, secret)

    # Report findings in the order they appear in the file. `sort` keeps
    # findings on the same line in their original order ("stable" sorting).
    findings.sort(key=lambda finding: finding.line_number)
    return findings
