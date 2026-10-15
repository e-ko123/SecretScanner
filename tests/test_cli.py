"""Tests for the command-line interface (cli.py).

pytest finds tests automatically: any file named `test_*.py`, and any
function inside it whose name starts with `test_`. Run them all with `pytest`.

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

import pytest

# Import the function we want to test. This works because the project is
# installed (`pip install -e ".[dev]"`), so Python can find the package.
from secretscan.cli import main

FAKE_AWS_KEY = "AKIA" + "X" * 16


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
    # ...but must NEVER contain the full secret.
    assert FAKE_AWS_KEY not in output


def test_clean_file_exits_0_and_prints_nothing(tmp_path, capsys):
    file = tmp_path / "clean.py"
    file.write_text("print('hello')\n")

    # Exit code 0 means "nothing found".
    assert main([str(file)]) == 0
    assert capsys.readouterr().out == ""


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
