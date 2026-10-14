"""Tests for the command-line interface (cli.py).

pytest finds tests automatically: any file named `test_*.py`, and any
function inside it whose name starts with `test_`. Run them all with `pytest`.
"""

import pytest

# Import the function we want to test. This works because the project is
# installed (`pip install -e ".[dev]"`), so Python can find the package.
from secretscan.cli import main


def test_runs_with_no_arguments():
    # Calling main with an empty list is like typing just `secretscan`.
    # There's nothing to scan yet, so it should return exit code 0.
    # `assert` means "this must be true, otherwise the test fails".
    assert main([]) == 0


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
