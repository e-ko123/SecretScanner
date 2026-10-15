"""Tests for the command-line interface (cli.py).

pytest finds tests automatically: any file named `test_*.py`, and any
function inside it whose name starts with `test_`. Run them all with `pytest`.

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

import json

import pytest

# Import the function we want to test. This works because the project is
# installed (`pip install -e ".[dev]"`), so Python can find the package.
from secretscan.cli import main, mask, summary
from secretscan.ignores import finding_id
from secretscan.scanner import Finding, scan_file

# A fake AWS key in the right shape: "AKIA" + 16 varied capital letters and
# digits. It's deliberately NOT "AKIA" + "X" * 16: an all-X key is a
# recognized placeholder, and these tests need a key that looks real.
FAKE_AWS_KEY = "AKIA" + "Z3K9P2M7W4Q8T6N5"


# --- mask ------------------------------------------------------------------

def test_mask_shows_first_4_characters_of_long_secret():
    # 20 characters in, 4 shown + 16 stars out.
    assert mask(FAKE_AWS_KEY) == "AKIA" + "*" * 16


def test_mask_keeps_the_same_length():
    assert len(mask(FAKE_AWS_KEY)) == len(FAKE_AWS_KEY)


def test_mask_hides_short_secrets_completely():
    # 8 characters or fewer: showing 4 would give away too much.
    assert mask("abcdefgh") == "********"
    assert mask("abc") == "***"


def test_mask_shows_start_just_above_the_short_limit():
    # 9 characters: long enough that 4 shown still leaves 5 hidden.
    assert mask("abcdefghi") == "abcd*****"


# --- summary ---------------------------------------------------------------

def make_finding(path):
    # A small helper so the summary tests don't repeat the same 4 fields.
    # Only the path matters for counting files; the rest is filler.
    return Finding(path=path, line_number=1, rule_name="AWS Access Key ID",
                   secret=FAKE_AWS_KEY)


def test_summary_when_nothing_found():
    assert summary([]) == "No secrets found."


def test_summary_uses_singular_for_one():
    assert summary([make_finding("a.py")]) == "Found 1 possible secret in 1 file."


def test_summary_counts_different_files_not_findings():
    # 3 findings, but two are in the same file, so only 2 files.
    findings = [make_finding("a.py"), make_finding("a.py"), make_finding("b.py")]
    assert summary(findings) == "Found 3 possible secrets in 2 files."


# --- main ------------------------------------------------------------------


def test_version_flag_prints_version(capsys):
    # `capsys` is a built-in pytest helper ("capture system output").
    # pytest gives it to us automatically because we named it as a parameter.
    # It records anything the code prints, so we can check the text.

    # argparse prints the version and then exits the program by raising
    # SystemExit. `pytest.raises` catches that exit so the test doesn't stop,
    # and stores it in `exit_info` so we can inspect it.
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    # Exit code 0 means "finished successfully".
    assert exit_info.value.code == 0

    # Check the printed text contains the program name and version.
    assert "secretscan 0.1.0" in capsys.readouterr().out


def test_file_with_secret_exits_1_and_reports_it(tmp_path, capsys):
    # `tmp_path` is a fresh empty folder for this test (see test_scanner.py).
    file = tmp_path / "config.py"
    file.write_text(f"AWS_KEY = '{FAKE_AWS_KEY}'\n")

    # Exit code 1 means "secrets found".
    assert main([str(file)]) == 1

    output = capsys.readouterr().out
    # The output names the file, the line number, and the type of secret...
    assert f"{file}:1" in output
    assert "AWS Access Key ID" in output
    # ...shows a masked preview...
    assert "AKIA" + "*" * 16 in output
    # ...but must NEVER contain the full secret.
    assert FAKE_AWS_KEY not in output


def test_findings_are_lined_up_in_columns(tmp_path, capsys):
    # Two files with different name lengths, so the columns need padding.
    (tmp_path / "a.py").write_text(f"k = '{FAKE_AWS_KEY}'\n")
    (tmp_path / "much_longer_name.py").write_text(f"k = '{FAKE_AWS_KEY}'\n")

    main([str(tmp_path)])

    # `splitlines()` splits the output into a list of lines.
    lines = capsys.readouterr().out.splitlines()
    # The rule name should start at the same position on both lines.
    # `.index(text)` gives the position where `text` first appears.
    assert lines[0].index("AWS") == lines[1].index("AWS")


def test_clean_file_exits_0_and_says_so(tmp_path, capsys):
    file = tmp_path / "clean.py"
    file.write_text("print('hello')\n")

    # Exit code 0 means "nothing found".
    assert main([str(file)]) == 0
    # The only output is the summary. "\n" is the line break print() adds.
    assert capsys.readouterr().out == "No secrets found.\n"


def test_ignored_secret_exits_0(tmp_path, capsys):
    # A file whose only secret is marked to be ignored counts as clean,
    # so the exit code is 0. (Later, this is what lets a commit through.)
    file = tmp_path / "docs.py"
    file.write_text(f"EXAMPLE = '{FAKE_AWS_KEY}'  # secretscan:ignore\n")

    assert main([str(file)]) == 0
    assert capsys.readouterr().out == "No secrets found.\n"


def test_summary_is_printed_after_findings(tmp_path, capsys):
    file = tmp_path / "config.py"
    file.write_text(f"AWS_KEY = '{FAKE_AWS_KEY}'\n")

    main([str(file)])

    lines = capsys.readouterr().out.splitlines()
    # `lines[-1]` means "the last item" in a list.
    assert lines[-1] == "Found 1 possible secret in 1 file."


def test_folder_with_secret_reports_file_inside_it(tmp_path, capsys):
    # A secret in a subfolder should be found when scanning the top folder.
    (tmp_path / "src").mkdir()
    secret_file = tmp_path / "src" / "settings.py"
    secret_file.write_text(f"AWS_KEY = '{FAKE_AWS_KEY}'\n")
    (tmp_path / "clean.py").write_text("print('hello')\n")

    assert main([str(tmp_path)]) == 1

    output = capsys.readouterr().out
    assert f"{secret_file}:1" in output
    # Only the file with the secret should be reported.
    assert "clean.py" not in output
    assert "Found 1 possible secret in 1 file." in output


def test_no_path_scans_current_folder(tmp_path, monkeypatch, capsys):
    # `monkeypatch` is a pytest helper for temporarily changing things
    # during a test. Here, `chdir` makes tmp_path the "current folder",
    # just like running `cd` in the terminal. It's undone after the test.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.py").write_text(f"AWS_KEY = '{FAKE_AWS_KEY}'\n")

    # An empty list is like typing just `secretscan` with nothing after it.
    assert main([]) == 1
    assert "config.py:1" in capsys.readouterr().out


def test_missing_path_exits_2(tmp_path, capsys):
    missing = tmp_path / "does_not_exist.py"

    # parser.error() exits with code 2 ("you used the command wrong").
    with pytest.raises(SystemExit) as exit_info:
        main([str(missing)])

    assert exit_info.value.code == 2
    # Error messages go to "stderr" (the error output), not normal output.
    assert "path not found" in capsys.readouterr().err


# --- placeholders ----------------------------------------------------------

PLACEHOLDER_AWS_KEY = "AKIA" + "X" * 16


def test_placeholder_only_file_exits_0_and_says_so(tmp_path, capsys):
    file = tmp_path / "docs.py"
    file.write_text(f"KEY = '{PLACEHOLDER_AWS_KEY}'\n")

    assert main([str(file)]) == 0
    assert capsys.readouterr().out == (
        "No reportable secrets found.\n"
        "Suppressed 1 recognized placeholder (use --include-placeholders to see).\n"
    )


def test_include_placeholders_reports_them_as_normal_findings(tmp_path, capsys):
    file = tmp_path / "docs.py"
    file.write_text(f"KEY = '{PLACEHOLDER_AWS_KEY}'\n")

    # With the option, the placeholder counts as a finding: exit code 1.
    assert main([str(file), "--include-placeholders"]) == 1

    output = capsys.readouterr().out
    assert f"{file}:1" in output
    # The reason is shown, so the user knows why it's normally hidden.
    assert "(recognized placeholder: token body is all 'X' filler)" in output
    # Still masked.
    assert PLACEHOLDER_AWS_KEY not in output
    assert "Found 1 possible secret in 1 file." in output
    assert "Suppressed" not in output


def test_placeholders_and_real_findings_are_counted_separately(tmp_path, capsys):
    (tmp_path / "docs.md").write_text(
        f"{PLACEHOLDER_AWS_KEY}\n" f"AKIA{'0' * 16}\n"
    )
    (tmp_path / "config.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")

    assert main([str(tmp_path)]) == 1

    lines = capsys.readouterr().out.splitlines()
    # One real-looking finding is shown; the two placeholders are counted.
    assert lines[0].startswith(f"{tmp_path / 'config.py'}:1")
    assert lines[-2] == "Found 1 possible secret in 1 file."
    assert lines[-1] == (
        "Suppressed 2 recognized placeholders (use --include-placeholders to see)."
    )


def test_inline_ignore_still_applies_with_include_placeholders(tmp_path, capsys):
    # --include-placeholders only turns off placeholder hiding. A line the
    # user marked with secretscan:ignore is still skipped.
    file = tmp_path / "docs.py"
    file.write_text(f"KEY = '{PLACEHOLDER_AWS_KEY}'  # secretscan:ignore\n")

    assert main([str(file), "--include-placeholders"]) == 0
    assert capsys.readouterr().out == "No secrets found.\n"


# --- --show-ids and the .secretscanignore file -----------------------------

OTHER_AWS_KEY = "AKIA" + "M4T7Q2W9Z5K3P8N6"


def write_ignore_file(path, ids):
    """Write an ignore file at `path` dismissing each ID in `ids`."""
    entries = [{"id": one_id, "reason": "Reviewed: fake key for tests"} for one_id in ids]
    path.write_text(json.dumps({"version": 1, "findings": entries}))


def shown_id(capsys, argv):
    """Run secretscan with --show-ids and return the ID from the first finding."""
    main(argv + ["--show-ids"])
    first_line = capsys.readouterr().out.splitlines()[0]
    # The ID is the last column. `split()` splits on runs of spaces.
    return first_line.split()[-1]


def test_show_ids_prints_the_full_fingerprint(tmp_path, capsys):
    file = tmp_path / "config.py"
    file.write_text(f"KEY = '{FAKE_AWS_KEY}'\n")

    assert main([str(tmp_path), "--show-ids"]) == 1

    output = capsys.readouterr().out
    expected = finding_id(scan_file(file)[0], tmp_path)
    assert expected in output
    # Still masked.
    assert FAKE_AWS_KEY not in output


def test_ids_are_not_shown_by_default(tmp_path, capsys):
    file = tmp_path / "config.py"
    file.write_text(f"KEY = '{FAKE_AWS_KEY}'\n")

    main([str(tmp_path)])

    expected = finding_id(scan_file(file)[0], tmp_path)
    assert expected not in capsys.readouterr().out


def test_scanning_a_file_or_its_folder_gives_the_same_id(tmp_path, capsys):
    # A single file's scan root is its folder, so both commands agree.
    file = tmp_path / "config.py"
    file.write_text(f"KEY = '{FAKE_AWS_KEY}'\n")

    assert shown_id(capsys, [str(file)]) == shown_id(capsys, [str(tmp_path)])


def test_full_dismissal_workflow(tmp_path, capsys):
    # 1-2. Scan with --show-ids and copy the ID.
    file = tmp_path / "config.py"
    file.write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    copied_id = shown_id(capsys, [str(tmp_path)])

    # 3-4. Add it to .secretscanignore in the scanned folder.
    write_ignore_file(tmp_path / ".secretscanignore", [copied_id])

    # 5. Scan again: the finding is dismissed and the exit code is 0.
    assert main([str(tmp_path)]) == 0
    assert capsys.readouterr().out == (
        "No reportable secrets found.\n"
        f"Ignored 1 finding listed in {tmp_path / '.secretscanignore'} "
        "(use --no-ignore to see).\n"
    )


def test_changed_key_at_same_spot_is_reported_again(tmp_path, capsys):
    file = tmp_path / "config.py"
    file.write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    write_ignore_file(tmp_path / ".secretscanignore", [shown_id(capsys, [str(tmp_path)])])

    # Same file, same line, different key: the old dismissal doesn't cover it.
    file.write_text(f"KEY = '{OTHER_AWS_KEY}'\n")

    assert main([str(tmp_path)]) == 1


def test_same_key_in_another_file_is_still_reported(tmp_path, capsys):
    (tmp_path / "a.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    write_ignore_file(tmp_path / ".secretscanignore", [shown_id(capsys, [str(tmp_path)])])

    # Copy the same key into a second file.
    (tmp_path / "b.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")

    assert main([str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "b.py:1" in output
    assert "a.py:1" not in output


def test_no_ignore_shows_dismissed_findings_again(tmp_path, capsys):
    (tmp_path / "config.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    write_ignore_file(tmp_path / ".secretscanignore", [shown_id(capsys, [str(tmp_path)])])

    assert main([str(tmp_path), "--no-ignore"]) == 1
    assert "config.py:1" in capsys.readouterr().out


def test_no_ignore_does_not_show_placeholders(tmp_path, capsys):
    # Each option does one job: --no-ignore doesn't turn off placeholders.
    (tmp_path / "docs.md").write_text(f"{PLACEHOLDER_AWS_KEY}\n")

    assert main([str(tmp_path), "--no-ignore"]) == 0


def test_inspect_everything_command(tmp_path, capsys):
    # The documented "show me everything that was hidden" command shows
    # placeholders and dismissed findings, but still honors inline markers.
    (tmp_path / "config.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    (tmp_path / "docs.md").write_text(
        f"{PLACEHOLDER_AWS_KEY}\n"
        f"{OTHER_AWS_KEY}  secretscan:ignore\n"
    )
    write_ignore_file(tmp_path / ".secretscanignore", [shown_id(capsys, [str(tmp_path)])])

    argv = [str(tmp_path), "--include-placeholders", "--no-ignore", "--show-ids"]
    assert main(argv) == 1
    assert "Found 2 possible secrets in 2 files." in capsys.readouterr().out


def test_missing_default_ignore_file_is_fine(tmp_path, capsys):
    (tmp_path / "config.py").write_text("x = 1\n")

    assert main([str(tmp_path)]) == 0
    assert capsys.readouterr().out == "No secrets found.\n"


def test_explicit_ignore_file_is_used(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    elsewhere = tmp_path / "my-ignores.json"
    write_ignore_file(elsewhere, [shown_id(capsys, [str(project)])])

    assert main([str(project), "--ignore-file", str(elsewhere)]) == 0


def test_missing_explicit_ignore_file_exits_2(tmp_path, capsys):
    (tmp_path / "config.py").write_text("x = 1\n")

    assert main([str(tmp_path), "--ignore-file", str(tmp_path / "nope.json")]) == 2
    assert "ignore file not found" in capsys.readouterr().err


@pytest.mark.parametrize("contents", [
    "{not json",
    '{"version": 2, "findings": []}',
    '{"version": 1, "findings": [{"id": "abc", "reason": "x"}]}',
    '{"version": 1, "findings": [{"id": 1, "reason": "x"}]}',
    '{"version": 1, "findings": [{"id": "' + "a" * 64 + '", "reason": ""}]}',
    '{"version": 1, "findings": ['
    '{"id": "' + "a" * 64 + '", "reason": "x"}, '
    '{"id": "' + "a" * 64 + '", "reason": "y"}]}',
])
def test_broken_ignore_file_exits_2(tmp_path, capsys, contents):
    (tmp_path / "config.py").write_text(f"KEY = '{FAKE_AWS_KEY}'\n")
    (tmp_path / ".secretscanignore").write_text(contents)

    # Exit code 2, even though there's also a secret: a broken ignore file
    # must never be quietly treated as an empty one.
    assert main([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert "secretscan: error: ignore file" in captured.err
    assert captured.out == ""


def test_no_ignore_skips_a_broken_ignore_file(tmp_path, capsys):
    # With --no-ignore the ignore file isn't read at all, so a broken one
    # doesn't stop the scan. (It's then scanned like any other file.)
    (tmp_path / ".secretscanignore").write_text("{not json")

    assert main([str(tmp_path), "--no-ignore"]) == 0


def test_ignore_file_and_no_ignore_together_are_rejected(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main([str(tmp_path), "--ignore-file", "x.json", "--no-ignore"])

    assert exit_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_ignore_file_itself_is_not_scanned(tmp_path, capsys):
    # A key written in a reason would be found if the ignore file were
    # scanned like code. It isn't, because it's settings, not code.
    (tmp_path / ".secretscanignore").write_text(json.dumps({
        "version": 1,
        "findings": [{"id": "a" * 64, "reason": f"was {FAKE_AWS_KEY}"}],
    }))

    assert main([str(tmp_path)]) == 0


def test_explicit_ignore_file_inside_the_project_is_not_scanned(tmp_path, capsys):
    ignores = tmp_path / "config" / "ignores.json"
    ignores.parent.mkdir()
    ignores.write_text(json.dumps({
        "version": 1,
        "findings": [{"id": "a" * 64, "reason": f"was {FAKE_AWS_KEY}"}],
    }))

    assert main([str(tmp_path), "--ignore-file", str(ignores)]) == 0
