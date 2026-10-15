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


def display(value: object) -> str:
    """Escape control/non-ASCII characters so paths cannot forge terminal output.

    ASCII escapes also keep column widths predictable without a dependency
    for measuring emoji, combining characters, or East Asian text.
    """
    return ascii(str(value))[1:-1]


def scan_root(path: Path) -> Path:
    """Use one project root for single-file and directory reviews."""
    directory = (path if path.is_dir() else path.parent).resolve()
    for parent in (directory, *directory.parents):
        if (parent / ".git").exists() or (parent / IGNORE_FILE_NAME).exists():
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
    locations = [f"{display(finding.path)}:{finding.line_number}" for finding in findings]

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
        if finding.rule_id == "private-key":
            print("Private-key headers cannot be dismissed safely; keeping finding.")
            continue
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
    # argparse does with its own errors.
    print(f"secretscan: error: {display(message)}", file=sys.stderr)
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
        parser.error(f"path not found: {display(path)}")

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
        if default.exists():
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
    for file in find_files(path, issues):
        # Don't scan the ignore file itself: it's settings, not code.
        # `resolve()` turns both into full, absolute paths, so the same
        # file written two different ways still compares as equal.
        if ignore_path is not None and file.resolve() == ignore_path.resolve():
            continue
        try:
            candidates.extend(scan_file(file, include_inline=True))
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
        if this_id in ignored_ids and finding.rule_id != "private-key":
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
            # `update` adds the new entries to the existing ones.
            ignored_ids.update(dismissed)
            try:
                save_ignore_file(ignore_path, ignored_ids)
            except OSError:
                # Permissions can change after the preflight. Keep the answers
                # in a private temporary directory instead of losing the review.
                recovery = Path(tempfile.mkdtemp(prefix="secretscan-review-")) / IGNORE_FILE_NAME
                save_ignore_file(recovery, ignored_ids)
                return config_error(f"could not save review; answers preserved in {recovery}")
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
        # Redirect the descriptor so shutdown does not retry the broken pipe.
        try:
            with open(os.devnull, "w") as sink:
                os.dup2(sink.fileno(), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 2
    except KeyboardInterrupt:
        return config_error("scan interrupted")
    except Exception as error:
        # Exception messages can contain source content; print only the type.
        return config_error(f"scan failed ({type(error).__name__})")
