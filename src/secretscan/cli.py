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
import json
import os
import tempfile

# `sys.stderr` is the "error output" stream, where error messages go.
import sys

# `version()` looks up the version number of an installed package.
# We use it so the version only lives in one place (pyproject.toml),
# instead of being typed out in two files that could get out of sync.
from importlib.metadata import version

# `Path` represents a file or folder location (see scanner.py).
from pathlib import Path

# The rules, used to mask key-shaped text in file names and messages.
from secretscan.rules import RULES

# Fingerprints and the .secretscanignore file (see ignores.py).
from secretscan.ignores import (
    IGNORE_FILE_NAME,
    IgnoreFileError,
    finding_id,
    load_ignore_file,
    save_ignore_file,
)

# `find_files` works out which files to scan; `scan_file` scans one file.
# `Finding` is the type that holds one result (used in type hints below).
from secretscan.scanner import Finding, ScanIssue, find_files, scan_file

# How many characters of a secret we show before hiding the rest with `*`.
# 4 is enough to recognise which key it is (e.g. "AKIA" = AWS), but far too
# little for anyone to actually use it.
VISIBLE_CHARS = 4

# The most stars a masked secret shows (see mask), and the widest the
# file:line column is padded to. Both keep the report a sensible size.
MAX_HIDDEN_CHARS = 40
MAX_LOCATION_WIDTH = 250


def display(value: object) -> str:
    """Make text from outside (file names, error messages) safe to print.

    Two steps:
    1. Mask anything that looks like a key, exactly like findings are
       masked. A file can be NAMED after a key, and a mistyped option can
       contain one; printing those as-is would leak the key into logs.
    2. Escape control and non-ASCII characters, so a file name can't forge
       or hide terminal output. ASCII escapes also keep column widths
       predictable without a dependency for measuring emoji or East Asian text.
    """
    text = str(value)
    for rule in RULES:
        # `pattern.sub(function, text)` replaces every match with whatever
        # the function returns for it; here, the masked version.
        text = rule.pattern.sub(lambda match: mask(match.group(0)), text)
    # `ascii()` returns the text as a quoted Python string with escapes;
    # [1:-1] drops the surrounding quotes.
    return ascii(text)[1:-1]


def scan_root(path: Path) -> Path:
    """Use one project root for single-file and directory reviews."""
    directory = (path if path.is_dir() else path.parent).resolve()
    ancestors = (directory, *directory.parents)
    # A git repository's top folder wins: it's the clearest "project root",
    # even if a subfolder happens to have its own ignore file.
    for parent in ancestors:
        if (parent / ".git").exists():
            return parent
    # Otherwise, the nearest folder that already has an ignore file.
    for parent in ancestors:
        if (parent / IGNORE_FILE_NAME).exists():
            return parent
    # Outside a repository, commands run inside the project share the cwd.
    cwd = Path.cwd().resolve()
    if directory == cwd or cwd in directory.parents:
        return cwd
    return directory


def mask(secret: str) -> str:
    """Hide most of a secret so it's safe to print.

    Examples:
        mask("AKIA" + 16 more characters)  ->  "AKIA****************"
        mask("hunter2")                    ->  "*******"

    The result is the same length as the secret, so you can still tell
    roughly how long it was, up to MAX_HIDDEN_CHARS stars. Longer secrets
    get that many stars plus their length, e.g. "sk-p********...(5000 chars)".
    Without a cap, one very long token in a small file could make the report
    (padded to line up with it) gigabytes long.
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
    if hidden_count > MAX_HIDDEN_CHARS:
        return secret[:VISIBLE_CHARS] + "*" * MAX_HIDDEN_CHARS + f"...({len(secret)} chars)"
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
    locations = [f"{display(finding.path)}:{finding.line_number}" for finding in findings]

    # The widest entry in each column decides that column's width.
    # `max(...)` here goes through every item and keeps the biggest length.
    # (`min` caps the padding, so one very long path can't widen every line.)
    location_width = min(max(len(location) for location in locations), MAX_LOCATION_WIDTH)
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


# The reason saved in the ignore file when the user dismisses a finding
# during --review but doesn't type a reason of their own.
DEFAULT_REVIEW_REASON = "Marked as not a secret during secretscan --review"


def is_interactive() -> bool:
    """Return True if a person is typing at a terminal.

    `isatty()` ("is this a terminal?") is False when input comes from a file,
    a pipe, CI, or a git hook, where nobody can answer questions. --review
    refuses to run then, instead of waiting forever for an answer.
    (It's a separate function so tests can pretend to be a terminal.)
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def review_findings(findings: list[Finding], ids: list[str]) -> dict[str, str] | None:
    """Ask the user, one finding at a time, whether to ignore it from now on.

    `ids[0]` is the ID of `findings[0]`, and so on.

    Returns a dictionary {id: reason} of the findings the user chose to
    ignore (possibly empty), or None if they cancelled with Ctrl-C, in
    which case nothing should be saved.

    Answers:
        y        ignore this finding from now on (then asks for a reason)
        Enter    keep reporting it. This is the default, so pressing Enter
                 by accident never hides a possible secret.
        q        stop reviewing; the "y" answers given so far are kept
    """
    dismissed: dict[str, str] = {}
    total = len(findings)

    print(
        f"Reviewing {plural(total, 'finding')}. Open each file at the line "
        "shown to check it."
    )
    print("Answer y to ignore a finding from now on, Enter to keep it, q to stop.")

    # `zip` pairs each finding with its ID; `enumerate(..., start=1)` numbers
    # the pairs 1, 2, 3... for the "[2/5]" counter.
    for number, (finding, this_id) in enumerate(zip(findings, ids), start=1):
        # The same key in the same file shares one ID (see ignores.py), so
        # if the user already said yes to an earlier copy, this one is
        # covered too. Don't ask twice.
        if this_id in dismissed:
            continue

        print()
        # Same details as the normal report. The secret is masked here too.
        print(
            f"[{number}/{total}] {display(finding.path)}:{finding.line_number}   "
            f"{finding.rule_name}   {mask(finding.secret)}"
        )

        # `input(prompt)` prints the prompt and waits for the user to type a
        # line and press Enter. Pressing Ctrl-C raises KeyboardInterrupt,
        # and closing the input (Ctrl-D) raises EOFError. Either way, the
        # user wants out, so cancel without saving anything: they may have
        # pressed it because they just answered "y" by mistake.
        try:
            answer = input("Ignore this finding from now on? [y/N/q] ").strip().lower()
            if answer in ("q", "quit"):
                break
            if answer not in ("y", "yes"):
                # Anything other than yes (including a typo) means "keep".
                continue
            reason = input("Reason (press Enter to use a default): ").strip()
        except (KeyboardInterrupt, EOFError):
            return None

        # `reason or DEFAULT_REVIEW_REASON` uses the typed reason, unless it's
        # empty, in which case it uses the default.
        # A terminal can hand us "half characters" that can't be saved as
        # UTF-8. `errors="replace"` turns any of those into "?".
        reason = reason.encode("utf-8", errors="replace").decode("utf-8")
        dismissed[this_id] = reason or DEFAULT_REVIEW_REASON

        # Tell the user if this answer also covers other copies of the same key.
        # `ids.count(this_id)` counts how many findings share this ID.
        # (plural() would say "copys", so the word is picked by hand here.)
        other_copies = ids.count(this_id) - 1
        if other_copies:
            word = "copy" if other_copies == 1 else "copies"
            print(
                f"  This also covers {other_copies} other {word} of the "
                "same key in this file."
            )

    return dismissed


def config_error(message: str) -> int:
    """Print a configuration error and return exit code 2.

    Used for problems with the ignore file. Exit code 2 means "something
    is wrong with how secretscan was set up", never "secrets found" (1).
    """
    # `file=sys.stderr` sends the message to the error output, like
    # argparse does with its own errors. If even that output is closed,
    # give up on the message but still return 2: the exit code matters most.
    try:
        print(f"secretscan: error: {display(message)}", file=sys.stderr)
        sys.stderr.flush()
    except (OSError, ValueError):
        silence_output()
    return 2


def silence_output() -> None:
    """Point stdout and stderr at "nowhere" after one of them breaks.

    When a program's output is closed (for example `secretscan | head -1`
    after head exits), every later write fails, including the automatic
    flush Python does on exit, which would print a traceback and change the
    exit code. `os.devnull` is a special file that throws away whatever is
    written to it; `os.dup2` makes each stream's descriptor point there.
    We don't know which stream broke, so both are redirected.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            with open(os.devnull, "w") as sink:
                os.dup2(sink.fileno(), stream.fileno())
        except (OSError, ValueError):
            pass


class SafeArgumentParser(argparse.ArgumentParser):
    """An argparse parser whose error messages go through display().

    argparse repeats what the user typed in its errors (e.g. "unrecognized
    arguments: ..."). That text could contain a key or terminal control
    codes, so it gets the same masking and escaping as everything else.
    """

    def error(self, message: str) -> None:
        # `self.exit` prints the message to stderr and exits with code 2,
        # just like the normal argparse error does.
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {display(message)}\n")


def build_parser() -> argparse.ArgumentParser:
    """Describe the options the `secretscan` command accepts.

    A "parser" is the object that knows which options exist and turns
    what the user typed into Python values we can use.
    """
    parser = SafeArgumentParser(
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

    parser.add_argument(
        "--include-inline-ignored", action="store_true",
        help="also report candidates suppressed by trailing inline markers",
    )

    # Show each finding's full ID, so it can be copied into the ignore file.
    parser.add_argument(
        "--show-ids",
        action="store_true",
        help="show each finding's ID (for dismissing it in a "
        f"{IGNORE_FILE_NAME} file)",
    )

    # Go through the findings one by one, asking whether to ignore each one.
    parser.add_argument(
        "--review",
        action="store_true",
        help="go through the findings one by one and choose which to ignore "
        f"from now on (answers are saved to {IGNORE_FILE_NAME})",
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


def file_changed(file: Path, before: tuple[int, int]) -> bool:
    """True if `file`'s modification time or size differ from `before`, or it's gone."""
    try:
        status = file.stat()
    except OSError:
        return True
    return (status.st_mtime_ns, status.st_size) != before


def save_review_elsewhere(dismissed: dict[str, str]) -> int:
    """Keep review answers when the real ignore file couldn't be written.

    First try a new private temporary folder. If even that fails, print the
    entries so the user can paste them in by hand. They're only IDs and the
    user's own reasons, never secrets, so printing them is safe.
    """
    try:
        recovery = Path(tempfile.mkdtemp(prefix="secretscan-review-")) / IGNORE_FILE_NAME
        save_ignore_file(recovery, dismissed)
    except (OSError, UnicodeError):
        entries = [{"id": entry_id, "reason": reason} for entry_id, reason in dismissed.items()]
        try:
            print("Could not save your answers anywhere. Add these entries to the "
                  "\"findings\" list of your ignore file:", file=sys.stderr)
            print(json.dumps(entries, indent=2), file=sys.stderr)
        except (OSError, ValueError):
            silence_output()
        return config_error("could not save review")
    return config_error(f"could not save review; answers preserved in {recovery}")


def run(argv: list[str] | None = None) -> int:
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
        # (parser.error masks and escapes the message itself.)
        parser.error(f"path not found: {path}")

    # --review saves answers to the ignore file, so it can't be combined with
    # "use no ignore file". And it asks questions, so a person must be there
    # to answer them.
    if args.review and args.no_ignore:
        parser.error("--review can't be used with --no-ignore "
                     "(there'd be no ignore file to save your answers to)")
    if args.review and not is_interactive():
        parser.error("--review needs a terminal to ask questions in; "
                     "it can't run with piped input or redirected output")

    # Use the same project root for file and folder scans so review answers
    # remain effective when the next invocation scans a different scope.
    root = scan_root(path)

    # Work out which ignore file to use, if any.
    # `Path | None` in a type hint means "a Path, or None".
    ignore_path: Path | None
    if args.no_ignore:
        ignore_path = None
    elif args.ignore_file is not None:
        # The user named a file, so it must exist.
        ignore_path = Path(args.ignore_file)
        if not ignore_path.exists():
            return config_error(f"ignore file not found: {ignore_path}")
        if not ignore_path.is_file():
            return config_error(f"ignore path is not a regular file: {ignore_path}")
    else:
        # Otherwise use .secretscanignore in the scan root, if it's there.
        # A missing default ignore file is normal: most projects won't have one.
        default = root / IGNORE_FILE_NAME
        # `is_symlink()` catches a broken shortcut, which `exists()` reports
        # as missing. Loading it then fails with a clear error instead of
        # silently scanning without the user's ignore file.
        if default.exists() or default.is_symlink():
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
    issues: list[ScanIssue] = []
    # Size and modification time of each scanned file, so --review can tell
    # if files changed while the user was answering questions.
    snapshot: dict[Path, tuple[int, int]] = {}
    # Other .secretscanignore files found while scanning. Only the one in
    # the project root is used, so the user is told about the rest.
    unused_ignore_files = []
    for file in find_files(path, issues):
        # When scanning a folder, don't scan the active ignore file: it's
        # settings, not code. But if the user names it directly, scan it:
        # skipping it would print "No secrets found." without checking it.
        # `resolve()` turns both into full, absolute paths, so the same
        # file written two different ways still compares as equal.
        if ignore_path is not None and file.resolve() == ignore_path.resolve():
            if path.is_dir():
                continue
        elif file.name == IGNORE_FILE_NAME:
            unused_ignore_files.append(file)
        try:
            candidates.extend(scan_file(file, include_inline=True))
            status = file.stat()
            snapshot[file] = (status.st_mtime_ns, status.st_size)
        except (OSError, UnicodeError):
            issues.append(ScanIssue(str(file), "could not read file", True))

    # Retain suppressed candidates for counts and an explicit audit option.
    inline_count = sum(c.inline_ignored for c in candidates) if not args.include_inline_ignored else 0
    all_ids = {finding_id(c, root) for c in candidates}
    if not args.include_inline_ignored:
        candidates = [c for c in candidates if not c.inline_ignored]

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

    # Stage 4b (only with --review): ask about each remaining finding, save
    # the "ignore it" answers, and treat those findings as ignored from here
    # on, exactly as if they'd been in the ignore file all along.
    if args.review and reportable:
        # Check the destination before collecting answers. Atomic saves need
        # a writable parent directory even when the file already exists.
        destination = ignore_path or root / IGNORE_FILE_NAME
        try:
            with tempfile.TemporaryFile(dir=destination.parent):
                pass
        except OSError:
            return config_error("review destination is not writable; use --ignore-file")
        dismissed = review_findings(reportable, reportable_ids)
        print()

        if dismissed is None:
            # Ctrl-C: save nothing, and report everything as usual below.
            print("Review cancelled. Nothing was saved.")
            print()
        elif dismissed:
            # Save to the ignore file in use, or create .secretscanignore in
            # the scan root if there isn't one yet.
            if ignore_path is None:
                ignore_path = root / IGNORE_FILE_NAME
            # The review may have taken a while, and someone (or another
            # program) may have edited the ignore file meanwhile. So read it
            # again NOW and add this review's answers to that latest version,
            # instead of overwriting it with the copy loaded at the start.
            try:
                latest = {}
                if ignore_path.exists() or ignore_path.is_symlink():
                    latest = load_ignore_file(ignore_path)
                # `update` adds the new entries to the existing ones.
                latest.update(dismissed)
                save_ignore_file(ignore_path, latest)
            except (OSError, UnicodeError, IgnoreFileError):
                return save_review_elsewhere(dismissed)
            ignored_ids.update(dismissed)
            print(f"Added {plural(len(dismissed), 'finding')} to {display(ignore_path)}.")
            print()

            # Rebuild the reportable lists without the dismissed findings.
            kept = []
            kept_ids = []
            for finding, this_id in zip(reportable, reportable_ids):
                if this_id in dismissed:
                    ignored_count += 1
                else:
                    kept.append(finding)
                    kept_ids.append(this_id)
            reportable = kept
            reportable_ids = kept_ids

    # If files changed while the user was answering, the findings above
    # describe the OLD contents. Don't claim a result for the new ones.
    if args.review and any(file_changed(file, before) for file, before in snapshot.items()):
        return config_error("files changed during the review, so these results "
                            "may be out of date; run secretscan again")

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
    anything_hidden = bool(placeholders) or ignored_count > 0 or inline_count > 0 or bool(issues)
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
            f"Ignored {plural(ignored_count, 'finding')} listed in {display(ignore_path)} "
            "(use --no-ignore to see)."
        )

    for extra in unused_ignore_files:
        print(f"Notice: {display(extra)} is not used; only "
              f"{display(Path(root) / IGNORE_FILE_NAME)} applies to this scan.", file=sys.stderr)

    if inline_count:
        print(f"Ignored {plural(inline_count, 'inline finding')} "
              "(use --include-inline-ignored to see).")
    if issues:
        print(f"Skipped {len(issues)} paths; scan coverage is incomplete.", file=sys.stderr)
        for issue in issues:
            print(f"  {display(issue.path)}: {issue.reason}", file=sys.stderr)
    # Only a complete scan of the project root can identify stale entries.
    if (path.is_dir() and path.resolve() == root
            and all(issue.reason == "excluded directory" for issue in issues)):
        unused = set(ignored_ids) - all_ids
        if unused:
            print(f"Notice: {len(unused)} ignore entries did not match this scan "
                  "(review before removing).", file=sys.stderr)
    if any(issue.error for issue in issues) or (issues and not path.is_dir()):
        return 2

    # An empty list counts as False in Python, so this reads as:
    # "if anything is left to report, exit with 1; otherwise exit with 0".
    # Hidden placeholders and dismissed findings don't count.
    if reportable:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """Keep runtime failures distinct from findings, without exposing secrets."""
    try:
        result = run(argv)
        # Flush here so a closed pipe is caught before interpreter shutdown.
        sys.stdout.flush()
        return result
    except BrokenPipeError:
        # Redirect both streams so shutdown does not retry the broken pipe.
        silence_output()
        return 2
    except KeyboardInterrupt:
        return config_error("scan interrupted")
    except Exception as error:
        # Exception messages can contain source content; print only the type.
        return config_error(f"scan failed ({type(error).__name__})")
