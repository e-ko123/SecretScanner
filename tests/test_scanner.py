"""Tests for the scanner (scanner.py).

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

from secretscan.scanner import scan_file, scan_line

FAKE_AWS_KEY = "AKIA" + "X" * 16


# --- scan_line -------------------------------------------------------------

def test_scan_line_finds_key():
    matches = scan_line(f"key = {FAKE_AWS_KEY}")

    # Exactly one match, and it's the AWS rule with the right text.
    # Each match is a (rule, matched_text) pair, so we "unpack" it into
    # two variables in one go.
    assert len(matches) == 1
    rule, secret = matches[0]
    assert rule.name == "AWS Access Key ID"
    assert secret == FAKE_AWS_KEY


def test_scan_line_finds_two_keys_on_one_line():
    line = f"{FAKE_AWS_KEY} and {FAKE_AWS_KEY}"
    assert len(scan_line(line)) == 2


def test_scan_line_returns_empty_list_for_clean_line():
    assert scan_line("print('hello world')") == []


# --- scan_file -------------------------------------------------------------
# `tmp_path` is a built-in pytest helper: a brand-new empty folder created
# just for this test and cleaned up afterwards. It lets us write real files
# without touching the project.

def test_scan_file_reports_correct_line_number(tmp_path):
    # Write a small file where the key is on line 3.
    file = tmp_path / "config.py"
    file.write_text(
        "import os\n"
        "\n"
        f"AWS_KEY = '{FAKE_AWS_KEY}'\n"
        "print('done')\n"
    )

    findings = scan_file(file)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].rule_name == "AWS Access Key ID"
    assert findings[0].path == str(file)


def test_scan_file_returns_empty_list_for_clean_file(tmp_path):
    file = tmp_path / "clean.py"
    file.write_text("print('nothing to see here')\n")

    assert scan_file(file) == []
