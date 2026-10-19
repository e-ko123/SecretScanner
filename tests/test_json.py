"""Tests for --json output (cli.json_report and its use in normal and --staged scans).

The key promise: with --json, the normal output (stdout) is ONE valid JSON
document and nothing else, and secret values are always masked.

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

import json
import os
import subprocess

import pytest

from secretscan import cli
from secretscan.ignores import finding_id
from secretscan.scanner import scan_file

AWS = "AKIA" + "Z3K9P2M7W4Q8T6N5"
PLACEHOLDER = "AKIA" + "X" * 16


def run_json(capsys, argv):
    """Run secretscan with --json; return (exit code, parsed JSON, stderr text)."""
    code = cli.main(argv + ["--json"])
    captured = capsys.readouterr()
    # json.loads fails if stdout has ANYTHING besides the JSON document,
    # which is exactly the promise being tested.
    return code, json.loads(captured.out), captured.err


def test_finding_fields_and_masking(tmp_path, capsys):
    path = tmp_path / "config.py"
    path.write_text("import os\n\nKEY = '" + AWS + "'\n")
    code, report, _ = run_json(capsys, [str(tmp_path)])

    assert code == 1
    assert report["version"] == 1
    [finding] = report["findings"]
    assert finding["file"] == str(path)
    assert finding["line"] == 3
    assert finding["end_line"] == 3
    assert finding["rule"] == "AWS Access Key ID"
    assert finding["rule_id"] == "aws-access-key-id"
    assert finding["match"] == "AKIA" + "*" * 16
    assert finding["placeholder"] is None
    # The ID is the same one --show-ids prints and .secretscanignore uses.
    assert finding["id"] == finding_id(scan_file(path)[0], cli.scan_root(tmp_path))
    assert report["summary"] == {"findings": 1, "files": 1, "suppressed": 0, "skipped": 0}


def test_full_key_never_appears_anywhere(tmp_path, capsys):
    # The key is in the file AND in the file's name.
    (tmp_path / (AWS + ".txt")).write_text(AWS + "\n")
    cli.main([str(tmp_path), "--json"])
    captured = capsys.readouterr()
    assert AWS not in captured.out
    assert AWS not in captured.err


def test_clean_scan_has_empty_findings_and_exit_0(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    code, report, _ = run_json(capsys, [str(tmp_path)])
    assert code == 0
    assert report["findings"] == []
    assert report["summary"]["findings"] == 0


def test_suppressed_findings_are_counted(tmp_path, capsys):
    (tmp_path / "docs.md").write_text(PLACEHOLDER + "\n")
    (tmp_path / "a.py").write_text("K = '" + AWS + "'  # secretscan:ignore\n")
    code, report, _ = run_json(capsys, [str(tmp_path)])
    assert code == 0
    assert report["summary"]["suppressed"] == 2


def test_included_placeholders_show_their_reason(tmp_path, capsys):
    (tmp_path / "docs.md").write_text(PLACEHOLDER + "\n")
    code, report, _ = run_json(capsys, [str(tmp_path), "--include-placeholders"])
    assert code == 1
    assert report["findings"][0]["placeholder"] == "token body is all 'X' filler"


def test_skipped_paths_are_listed_in_json(tmp_path, capsys):
    (tmp_path / "logo.png").write_bytes(b"\0binary")
    code, report, err = run_json(capsys, [str(tmp_path)])
    assert code == 0
    assert report["skipped"] == [
        {"path": str(tmp_path / "logo.png"), "reason": "binary file", "error": False}
    ]
    # The human-readable notice still goes to stderr, where it can't break the JSON.
    assert "binary file" in err


@pytest.mark.skipif(os.name == "nt", reason="control characters in file names are Unix-only")
def test_unusual_file_names_stay_valid_json(tmp_path, capsys):
    (tmp_path / "x\n\x1b[8m中.py").write_text(AWS + "\n")
    code, report, _ = run_json(capsys, [str(tmp_path)])
    assert code == 1
    assert report["findings"][0]["file"].endswith("x\n\x1b[8m中.py")


def test_errors_print_nothing_on_stdout(tmp_path, capsys):
    # A broken ignore file is a configuration error: exit code 2, the
    # message on stderr, and stdout left empty (so nobody parses half a report).
    (tmp_path / ".secretscanignore").write_text("{broken")
    assert cli.main([str(tmp_path), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ignore file" in captured.err


def test_json_and_review_cannot_be_combined(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    with pytest.raises(SystemExit) as exit_info:
        cli.main([str(tmp_path), "--json", "--review"])
    assert exit_info.value.code == 2


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_staged_scan_supports_json(tmp_path, monkeypatch, capsys):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Scanner Test")
    git(tmp_path, "config", "user.email", "scanner@example.invalid")
    (tmp_path / "config.py").write_text("KEY = '" + AWS + "'\n")
    git(tmp_path, "add", "config.py")
    monkeypatch.chdir(tmp_path)

    code, report, _ = run_json(capsys, ["--staged"])
    assert code == 1
    [finding] = report["findings"]
    assert finding["file"] == "config.py"
    assert finding["match"] == "AKIA" + "*" * 16
    assert len(finding["id"]) == 64
