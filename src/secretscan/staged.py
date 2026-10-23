"""Scan an immutable snapshot of Git's index, without reading source files on disk.

The index is Git's name for the files selected by `git add`. We retain object
IDs (content hashes), so later working-tree edits cannot change what we read.
All commands use argument lists: filenames never become shell commands.
"""
from __future__ import annotations

import difflib
import os
import subprocess
import sys
from pathlib import Path

from secretscan.ignores import (
    IGNORE_FILE_NAME, IgnoreFileError, fingerprint, load_ignore_file, parse_ignore_bytes,
)
from secretscan.scanner import (
    BINARY_CHECK_BYTES, MAX_FILE_SIZE, ScanIssue, scan_bytes, text_encoding, text_lines,
)


class GitError(Exception):
    """A Git operation failed; messages deliberately exclude Git's raw output."""


def git(root: Path, *arguments: str, allowed=(0,)) -> subprocess.CompletedProcess:
    """Run Git without a shell, with a timeout and safe, fixed error messages.

    Inherit GIT_INDEX_FILE: Git sets it for some partial commits, and scanning
    the default index instead would check the wrong files. Disable replacement
    objects so the bytes read are the actual contents addressed by their ID.
    """
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *arguments],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GitError("could not run Git (check its installation and repository access)")
    if result.returncode not in allowed:
        raise GitError("Git could not read the repository or its staged contents")
    return result


def repository_root() -> Path:
    """Find the worktree root, including when invoked inside a subdirectory."""
    # Remove only Git's terminating newline; whitespace can belong to a path.
    raw = git(Path.cwd(), "rev-parse", "--show-toplevel").stdout
    return Path(os.fsdecode(raw.removesuffix(b"\n")))


def index_entries(root: Path) -> dict[str, tuple[str, str]]:
    """Map logical paths to (mode, object ID); reject unresolved merges."""
    entries = {}
    # NUL-separated records support tabs, newlines, and unusual filename bytes.
    for record in git(root, "ls-files", "--stage", "-z").stdout.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise GitError("resolve the merge conflicts and stage the files before scanning")
        entries[os.fsdecode(name)] = (mode, oid)
    return entries


def head_entries(root: Path) -> dict[str, tuple[str, str]]:
    """Read the previous commit, or an empty baseline for a new branch."""
    head = git(root, "rev-parse", "--verify", "--quiet", "HEAD", allowed=(0, 1))
    if head.returncode:
        # A missing HEAD is normal only when its branch does not exist yet.
        branch = git(root, "symbolic-ref", "HEAD").stdout.decode().rstrip("\n")
        exists = git(root, "show-ref", "--verify", "--quiet", branch, allowed=(0, 1))
        if exists.returncode == 1:
            return {}
        raise GitError("could not resolve the current commit")
    entries = {}
    for record in git(root, "ls-tree", "-r", "-z", head.stdout.decode().strip()).stdout.split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            mode, _, oid = metadata.decode("ascii").split()
            entries[os.fsdecode(name)] = (mode, oid)
    return entries


def blob(root: Path, oid: str) -> bytes | None:
    """Read at most 1 MB; None means the object exceeds that limit."""
    size = int(git(root, "cat-file", "-s", oid).stdout)
    if size > MAX_FILE_SIZE:
        return None
    return git(root, "cat-file", "blob", oid).stdout


def added_lines(before: bytes, after: bytes) -> set[int]:
    """Compare decoded lines, so UTF-16/32 files work just like UTF-8 files.

    SequenceMatcher groups insertions and replacements. Its default automatic
    shortcut for repeated lines avoids expensive comparisons in generated data.
    Line numbers in a Finding start at 1; sequence positions start at 0.
    """
    changed = set()
    matcher = difflib.SequenceMatcher(None, text_lines(before), text_lines(after))
    for operation, _, _, start, end in matcher.get_opcodes():
        if operation in ("insert", "replace"):
            changed.update(range(start + 1, end + 1))
    return changed


def staged_command(args) -> int:
    """Apply normal filtering and masked output to added staged lines."""
    # Import here to avoid a circular import when cli dispatches this command.
    from secretscan.cli import config_error, display, json_report, print_findings, print_summary

    if args.path != "." or args.review:
        return config_error("--staged scans the whole repository and cannot use a path or --review")
    try:
        root = repository_root()
        staged = index_entries(root)
        previous = head_entries(root)
        ignored = {}
        if not args.no_ignore:
            if args.ignore_file:
                # An explicit override is intentionally a file on disk.
                ignored = load_ignore_file(Path(args.ignore_file))
            elif IGNORE_FILE_NAME in staged:
                mode, oid = staged[IGNORE_FILE_NAME]
                if mode not in ("100644", "100755"):
                    raise IgnoreFileError("staged ignore file must be a regular file")
                data = blob(root, oid)
                if data is None:
                    raise IgnoreFileError("staged ignore file is larger than 1 MB")
                ignored = parse_ignore_bytes(data)

        findings, issues = [], []
        hidden = 0
        for name, (mode, oid) in staged.items():
            old = previous.get(name)
            if old == (mode, oid):
                continue
            if name == IGNORE_FILE_NAME and not args.no_ignore and not args.ignore_file:
                continue
            if mode == "160000":
                issues.append(ScanIssue(name, "submodule contents are not scanned", error=True))
                continue
            data = blob(root, oid)
            if data is None:
                issues.append(ScanIssue(name, "staged file exceeds 1 MB", error=True))
                continue
            start = data[:BINARY_CHECK_BYTES]
            if text_encoding(start) == "utf-8-sig" and b"\0" in start:
                issues.append(ScanIssue(name, "binary staged file (not scanned)"))
                continue
            # A rename is treated as a new path, deliberately checking all its
            # lines. If an old file exceeded the limit, scan all the new text.
            before = blob(root, old[1]) if old and old[0] != "160000" else b""
            changed = added_lines(before or b"", data)
            for finding in scan_bytes(data, Path(name), include_inline=True):
                end = finding.end_line_number or finding.line_number
                if not any(line in changed for line in range(finding.line_number, end + 1)):
                    continue
                # Use the index's logical path, never resolve disk symlinks.
                ident = fingerprint(finding.rule_id, name, finding.secret)
                if (finding.inline_ignored and not args.include_inline_ignored
                        or finding.placeholder_reason and not args.include_placeholders
                        or ident in ignored):
                    hidden += 1
                    continue
                findings.append(finding)
        ids = [fingerprint(f.rule_id, f.path, f.secret) for f in findings]
        # Keep IDs in the same order as the printed findings.
        if args.json:
            # One JSON document on stdout, same layout as a normal --json scan.
            print(json_report(findings, ids, hidden, issues))
        elif findings:
            print_findings(findings, ids if args.show_ids else None)
        if not args.json:
            print_summary(findings, anything_hidden=bool(hidden or issues))
        if hidden and not args.json:
            print(f"Suppressed {hidden} staged finding(s) by placeholders, inline markers, or ignore IDs.")
        for issue in issues:
            print(f"secretscan: {display(issue.path)}: {issue.reason}", file=sys.stderr)
        return 2 if any(issue.error for issue in issues) else (1 if findings else 0)
    except (GitError, IgnoreFileError) as error:
        return config_error(str(error))
