import pytest

from secretscan.cli import main


def test_runs_with_no_arguments():
    assert main([]) == 0


def test_version_flag_prints_version(capsys):
    # argparse prints the version and then exits with code 0.
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert "secretscan 0.1.0" in capsys.readouterr().out
