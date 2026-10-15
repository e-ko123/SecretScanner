"""Tests for fingerprints and ignore-file loading (ignores.py).

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

import hashlib
import json

import pytest

from secretscan.ignores import (
    IgnoreFileError,
    finding_id,
    fingerprint,
    load_ignore_file,
    relative_path,
)
from secretscan.scanner import scan_file

FAKE_AWS_KEY = "AKIA" + "Z3K9P2M7W4Q8T6N5"
OTHER_AWS_KEY = "AKIA" + "M4T7Q2W9Z5K3P8N6"

# A well-formed ID to use in ignore files. Any 64 lowercase hex characters
# will do; the loader only checks the format.
VALID_ID = "a" * 64


# --- fingerprint -----------------------------------------------------------

def test_fingerprint_is_deterministic_and_full_length():
    first = fingerprint("aws-access-key-id", "src/app.py", FAKE_AWS_KEY)
    second = fingerprint("aws-access-key-id", "src/app.py", FAKE_AWS_KEY)

    assert first == second
    # A full SHA-256 hex digest is 64 characters long.
    assert len(first) == 64


def test_fingerprint_format_is_exactly_as_documented():
    # This pins the exact recipe: SHA-256 of a compact JSON list
    # [version, rule id, relative path, candidate]. If someone changes the
    # recipe by accident, every user's ignore file would stop working, so
    # this test should fail loudly.
    expected_text = '[1,"aws-access-key-id","src/app.py","' + FAKE_AWS_KEY + '"]'
    expected = hashlib.sha256(expected_text.encode("utf-8")).hexdigest()

    assert fingerprint("aws-access-key-id", "src/app.py", FAKE_AWS_KEY) == expected


def test_fingerprint_changes_when_any_part_changes():
    base = fingerprint("aws-access-key-id", "src/app.py", FAKE_AWS_KEY)

    # A different key, file, or rule each give a different ID.
    assert fingerprint("aws-access-key-id", "src/app.py", OTHER_AWS_KEY) != base
    assert fingerprint("aws-access-key-id", "src/other.py", FAKE_AWS_KEY) != base
    assert fingerprint("github-token", "src/app.py", FAKE_AWS_KEY) != base


def test_fingerprint_pieces_cannot_run_together():
    # If the pieces were just glued together with ":", these two would both
    # become "a:b:c:d" and get the same ID. JSON keeps them apart.
    assert fingerprint("a", "b:c", "d") != fingerprint("a:b", "c", "d")


def test_relative_path_uses_forward_slashes(tmp_path):
    assert relative_path(tmp_path / "src" / "app.py", tmp_path) == "src/app.py"


def test_adding_lines_above_a_finding_keeps_its_id(tmp_path):
    file = tmp_path / "config.py"
    file.write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    before = finding_id(scan_file(file)[0], tmp_path)

    # Add lines above it: the line number changes, but the ID must not.
    file.write_text(f"import os\n\n\nKEY = '{FAKE_AWS_KEY}'\n")
    after = finding_id(scan_file(file)[0], tmp_path)

    assert before == after


def test_moving_the_project_keeps_its_ids(tmp_path):
    # The same project, checked out in two different places.
    first_root = tmp_path / "home" / "alice" / "project"
    second_root = tmp_path / "ci" / "build" / "42" / "project"
    for root in [first_root, second_root]:
        (root / "src").mkdir(parents=True)
        (root / "src" / "config.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")

    first = finding_id(scan_file(first_root / "src" / "config.py")[0], first_root)
    second = finding_id(scan_file(second_root / "src" / "config.py")[0], second_root)

    assert first == second


def test_repeated_key_in_one_file_shares_one_id(tmp_path):
    # Documented behavior: the line number isn't part of the ID, so the
    # same key twice in one file gives the same ID twice.
    file = tmp_path / "config.py"
    file.write_text(f"A = '{FAKE_AWS_KEY}'\nB = '{FAKE_AWS_KEY}'\n")

    first, second = scan_file(file)

    assert finding_id(first, tmp_path) == finding_id(second, tmp_path)


# --- load_ignore_file ------------------------------------------------------

def write_json(path, data):
    """Write `data` to `path` as JSON and return the path."""
    path.write_text(json.dumps(data))
    return path


def test_valid_ignore_file_loads(tmp_path):
    path = write_json(tmp_path / ".secretscanignore", {
        "version": 1,
        "findings": [{"id": VALID_ID, "reason": "Fake key used in tests"}],
    })

    assert load_ignore_file(path) == {VALID_ID: "Fake key used in tests"}


def test_empty_findings_list_is_valid(tmp_path):
    path = write_json(tmp_path / ".secretscanignore", {"version": 1, "findings": []})
    assert load_ignore_file(path) == {}


# `@pytest.mark.parametrize` runs the same test once for each item in the
# list, passing it in as `data`. It's a tidy way to check many bad inputs
# without writing a separate test function for each one.
@pytest.mark.parametrize("data", [
    # The top level isn't an object.
    [],
    # Missing or misspelled top-level fields.
    {"version": 1},
    {"version": 1, "findngs": []},
    {"version": 1, "findings": [], "extra": True},
    # Unsupported versions (true is rejected even though True == 1 in Python).
    {"version": 2, "findings": []},
    {"version": "1", "findings": []},
    {"version": True, "findings": []},
    # "findings" isn't a list.
    {"version": 1, "findings": {}},
    # Entries that aren't objects, or have missing/extra fields.
    {"version": 1, "findings": ["just a string"]},
    {"version": 1, "findings": [{"id": VALID_ID}]},
    {"version": 1, "findings": [{"id": VALID_ID, "reason": "ok", "note": "x"}]},
    # Malformed IDs: too short, uppercase, not hex, not a string.
    {"version": 1, "findings": [{"id": "a" * 63, "reason": "ok"}]},
    {"version": 1, "findings": [{"id": "A" * 64, "reason": "ok"}]},
    {"version": 1, "findings": [{"id": "g" * 64, "reason": "ok"}]},
    {"version": 1, "findings": [{"id": 12345, "reason": "ok"}]},
    # Empty, blank, or non-string reasons.
    {"version": 1, "findings": [{"id": VALID_ID, "reason": ""}]},
    {"version": 1, "findings": [{"id": VALID_ID, "reason": "   "}]},
    {"version": 1, "findings": [{"id": VALID_ID, "reason": None}]},
    # The same ID twice.
    {"version": 1, "findings": [
        {"id": VALID_ID, "reason": "one"},
        {"id": VALID_ID, "reason": "two"},
    ]},
])
def test_invalid_ignore_files_are_rejected(tmp_path, data):
    path = write_json(tmp_path / ".secretscanignore", data)

    with pytest.raises(IgnoreFileError):
        load_ignore_file(path)


def test_invalid_json_is_rejected_without_echoing_contents(tmp_path):
    # Someone pasted a key into the ignore file by mistake, and broke the
    # JSON too. The error must say where the problem is, but not print
    # the file's contents (which would leak the key).
    path = tmp_path / ".secretscanignore"
    path.write_text('{"version": 1, "findings": [' + FAKE_AWS_KEY + "]}")

    with pytest.raises(IgnoreFileError) as error_info:
        load_ignore_file(path)

    message = str(error_info.value)
    assert "not valid JSON" in message
    assert "line 1" in message
    assert FAKE_AWS_KEY not in message
