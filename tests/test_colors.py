"""Keep terminal colors separate from masked content and machine-readable output."""
import json

import pytest

import secretscan.cli as cli

KEY = "AKIA" + "Z3K9P2M7W4Q8T6N5"


@pytest.fixture
def color_terminal(monkeypatch):
    # Enable inside the test call, after pytest has installed its stdout capture.
    # A fixture-time stdout patch would target the setup phase's old stream.
    def enable():
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
    return enable


def test_tty_finding_is_colored_and_still_masked(tmp_path, capsys, color_terminal):
    color_terminal()
    path = tmp_path / "settings.py"
    path.write_text(KEY)
    assert cli.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert "\x1b[31m" in output
    assert "\x1b[0m" in output
    assert KEY not in output


@pytest.mark.parametrize("value", ["", "1", "0"])
def test_no_color_presence_disables_colors(tmp_path, capsys, color_terminal, monkeypatch, value):
    color_terminal()
    monkeypatch.setenv("NO_COLOR", value)
    assert cli.main([str(tmp_path)]) == 0
    assert "\x1b[" not in capsys.readouterr().out


def test_dumb_terminal_is_plain(tmp_path, capsys, color_terminal, monkeypatch):
    color_terminal()
    monkeypatch.setenv("TERM", "dumb")
    assert cli.main([str(tmp_path)]) == 0
    assert "\x1b[" not in capsys.readouterr().out


def test_redirected_output_is_plain(tmp_path, capsys, color_terminal, monkeypatch):
    color_terminal()
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
    (tmp_path / "settings.py").write_text(KEY)
    assert cli.main([str(tmp_path)]) == 1
    assert "\x1b[" not in capsys.readouterr().out


def test_json_remains_parseable_even_on_a_tty(tmp_path, capsys, color_terminal):
    color_terminal()
    (tmp_path / "settings.py").write_text(KEY)
    assert cli.main([str(tmp_path), "--json"]) == 1
    output = capsys.readouterr().out
    assert "\x1b[" not in output
    assert json.loads(output)["summary"]["findings"] == 1
    assert KEY not in output


def test_clean_and_hidden_results_have_different_colors(tmp_path, capsys, color_terminal):
    color_terminal()
    assert cli.main([str(tmp_path)]) == 0
    assert "\x1b[32m" in capsys.readouterr().out
    (tmp_path / "settings.py").write_text("AKIA" + "X" * 16)
    assert cli.main([str(tmp_path)]) == 0
    assert "\x1b[33m" in capsys.readouterr().out
    assert cli.main([str(tmp_path), "--include-placeholders"]) == 1
    output = capsys.readouterr().out
    assert "\x1b[33m" in output
    assert "\x1b[31m" in output
