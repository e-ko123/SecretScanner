"""Regression cases from the security review; all credentials are synthetic."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from secretscan import cli, ignores, scanner
from secretscan.ignores import IgnoreFileError, finding_id, load_ignore_file, save_ignore_file
from secretscan.rules import RULES

# Varied bodies stay reportable, unlike deliberately repeated filler.
AWS = "AKIA" + "Z3K9P2M7W4Q8T6N5"
TOKENS = [
    AWS,
    "ghp_" + "Ab12Cd" * 6,
    "github_pat_" + "Ab12" * 20 + "Z9",
    "xoxb-" + "1234567890-1234567890-Ab12Cd34",
    "sk_live_" + "Ab12Cd" * 4,
    "AIza" + "Ab12Cd3" * 5,
    "sk-ant-" + "Ab12Cd34" * 5,
    "sk-" + "Ab12Cd34" * 6,
]


@pytest.mark.parametrize("token", TOKENS)
@pytest.mark.parametrize("prefix", [r"line1\n", "%22", "AWS_KEY_", r"x\t", "9"])
def test_glued_tokens_remain_visible(token, prefix):
    assert any(value == token for _, value in scanner.scan_line(prefix + token))


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-be", "utf-32"])
def test_unicode_text_is_scanned(tmp_path, encoding):
    path = tmp_path / "config.txt"
    data = AWS.encode(encoding)
    if encoding == "utf-16-be":
        data = b"\xfe\xff" + data
    path.write_bytes(data)
    assert scanner.find_files(path) == [path]
    assert scanner.scan_file(path)[0].secret == AWS


@pytest.mark.parametrize("kind", ["large", "binary", "special"])
def test_direct_skips_are_errors_not_all_clear(tmp_path, capsys, kind):
    path = tmp_path / "input"
    if kind == "large":
        path.write_bytes(b"a" * (scanner.MAX_FILE_SIZE + 1))
    elif kind == "binary":
        path.write_bytes(b"\0binary")
    else:
        path = Path("/dev/null")
    assert cli.main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "Skipped 1 paths" in captured.err
    assert "No secrets found." not in captured.out


def test_directory_skips_explain_reasons(tmp_path, capsys):
    (tmp_path / "binary").write_bytes(b"\0binary")
    (tmp_path / "target").mkdir()
    (tmp_path / "shortcut").symlink_to(tmp_path / "target", target_is_directory=True)
    assert cli.main([str(tmp_path)]) == 0
    output = capsys.readouterr()
    assert "binary file" in output.err
    assert "symlink directory" in output.err
    assert "No secrets found." not in output.out


def test_unreadable_file_and_directory_are_recorded(tmp_path, monkeypatch):
    path = tmp_path / "a"
    path.write_text(AWS)
    # Simulate permission failures; chmod tests can incorrectly pass as root.
    def denied(_):
        raise PermissionError()
    monkeypatch.setattr(scanner, "is_binary", denied)
    issues = []
    assert scanner.find_files(path, issues) == []
    assert issues[0].error

    def failed_walk(path, onerror):
        onerror(PermissionError(13, "denied", str(path)))
        return iter(())
    monkeypatch.setattr(scanner.os, "walk", failed_walk)
    issues = []
    assert scanner.find_files(tmp_path, issues) == []
    assert issues[0].reason == "could not read directory"
    assert issues[0].error


@pytest.mark.parametrize("failure", [FileNotFoundError, KeyboardInterrupt, RuntimeError])
def test_scan_failures_exit_2_without_tracebacks(tmp_path, monkeypatch, capsys, failure):
    (tmp_path / "a").write_text(AWS)
    def fail(*args, **kwargs):
        raise failure()
    monkeypatch.setattr(cli, "scan_file", fail)
    assert cli.main([str(tmp_path)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_filename_cannot_forge_report(tmp_path, capsys):
    path = tmp_path / "x\n\nNo secrets found.\n\x1b[8m中文😀"
    path.write_text(AWS)
    assert cli.main([str(path), "--show-ids"]) == 1
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out
    assert "\nNo secrets found.\n" not in captured.out
    assert r"\x1b" in captured.out
    assert captured.out.isascii()


def test_non_utf8_filename_fingerprint():
    # Linux uses surrogate escapes for filenames containing invalid UTF-8.
    first = ignores.fingerprint("aws", "bad\udcff", AWS)
    assert len(first) == 64
    assert first != ignores.fingerprint("aws", "bad\udcfe", AWS)


def test_private_header_cannot_hide_later_key(tmp_path, capsys, monkeypatch):
    path = tmp_path / "keys.txt"
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    path.write_text(header + "\nfixture\n")
    old_id = finding_id(scanner.scan_file(path)[0], tmp_path)
    save_ignore_file(tmp_path / ".secretscanignore", {old_id: "fixture"})
    path.write_text(header + "\nfixture\n" + header + " # secretscan:ignore\nnew key\n")
    assert cli.main([str(tmp_path)]) == 1
    assert "Found 2 possible secrets" in capsys.readouterr().out
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    def no_questions(*args):
        pytest.fail("Header-only findings must not offer dismissal")
    monkeypatch.setattr("builtins.input", no_questions)
    assert cli.main([str(tmp_path), "--review"]) == 1


def test_single_file_review_uses_project_root(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    path = tmp_path / "src" / "config.py"
    path.parent.mkdir()
    path.write_text(AWS)
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    answers = iter(["y", "fixture"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main([str(path), "--review"]) == 0
    assert (tmp_path / ".secretscanignore").is_file()
    assert not (path.parent / ".secretscanignore").exists()
    assert cli.main([str(tmp_path)]) == 0
    capsys.readouterr()


def test_review_checks_writability_before_questions(tmp_path, monkeypatch, capsys):
    (tmp_path / "a").write_text(AWS)
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    def denied(*args, **kwargs):
        raise PermissionError()
    monkeypatch.setattr(cli.tempfile, "TemporaryFile", denied)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("Must fail before asking"))
    assert cli.main([str(tmp_path), "--review"]) == 2
    assert "not writable" in capsys.readouterr().err


def test_review_preserves_answers_if_save_later_fails(tmp_path, monkeypatch, capsys):
    (tmp_path / "a").write_text(AWS)
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    answers = iter(["y", "fixture"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    recovery_dir = tmp_path / "recovery"
    recovery_dir.mkdir()
    monkeypatch.setattr(cli.tempfile, "mkdtemp", lambda **kwargs: str(recovery_dir))
    original = cli.save_ignore_file
    def fail_destination(path, entries):
        if path.parent == tmp_path:
            raise PermissionError()
        original(path, entries)
    monkeypatch.setattr(cli, "save_ignore_file", fail_destination)
    assert cli.main([str(tmp_path), "--review"]) == 2
    assert len(load_ignore_file(recovery_dir / ".secretscanignore")) == 1
    assert "answers preserved" in capsys.readouterr().err


def test_review_requires_visible_output(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
    assert not cli.is_interactive()


def test_minified_line_and_bare_marker_cannot_hide_keys():
    assert len(scanner.scan_line(AWS + " " + TOKENS[1] + " // secretscan:ignore")) == 2
    assert scanner.scan_line(AWS + " secretscan:ignore")


def test_inline_suppression_is_counted_and_reversible(tmp_path, capsys):
    path = tmp_path / "a"
    path.write_text(AWS + " # secretscan:ignore\n")
    assert cli.main([str(path)]) == 0
    assert "Ignored 1 inline finding" in capsys.readouterr().out
    assert cli.main([str(path), "--include-inline-ignored"]) == 1


@pytest.mark.parametrize("directory", ["dist", "build"])
def test_build_artifacts_are_scanned(tmp_path, directory):
    path = tmp_path / directory / "bundle.js"
    path.parent.mkdir()
    path.write_text(AWS)
    assert path in scanner.find_files(tmp_path)


def test_openai_and_slack_false_positives(tmp_path, capsys):
    path = tmp_path / "docs"
    path.write_text("https://example.org/sk-hynix-semiconductor-quarterly-results-2024\n"
                    + "sk-" + "x" * 48 + "\n" + "xoxb-your-token-goes-here\n")
    assert cli.main([str(path)]) == 0
    assert "Suppressed 2 recognized placeholders" in capsys.readouterr().out
    assert cli.main([str(path), "--include-placeholders"]) == 1
    assert "Found 2 possible secrets" in capsys.readouterr().out


def test_bom_ignore_file(tmp_path):
    path = tmp_path / "ignore"
    path.write_text('{"version":1,"findings":[]}', encoding="utf-8-sig")
    assert load_ignore_file(path) == {}


@pytest.mark.parametrize("contents", [
    '{"version":2,"version":1,"findings":[]}',
    '{"version":1,"findings":[{"id":"a","id":"b","reason":"fixture"}]}',
])
def test_duplicate_json_fields_rejected(tmp_path, contents):
    path = tmp_path / "ignore"
    path.write_text(contents)
    with pytest.raises(IgnoreFileError, match="duplicate JSON field"):
        load_ignore_file(path)


def test_ignore_directory_error_is_accurate(tmp_path, capsys):
    assert cli.main([str(tmp_path), "--ignore-file", str(tmp_path)]) == 2
    assert "not a regular file" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [PermissionError, KeyboardInterrupt])
def test_interrupted_save_cleans_temporary_file(tmp_path, monkeypatch, failure):
    path = tmp_path / ".secretscanignore"
    save_ignore_file(path, {"a" * 64: "original"})
    def fail(*args):
        raise failure()
    monkeypatch.setattr(ignores.os, "replace", fail)
    with pytest.raises(failure):
        save_ignore_file(path, {"b" * 64: "new"})
    assert load_ignore_file(path) == {"a" * 64: "original"}
    assert list(tmp_path.iterdir()) == [path]


def test_stale_ignores_noticed_only_for_complete_project_scan(tmp_path, capsys):
    path = tmp_path / "a"
    path.write_text("clean")
    save_ignore_file(tmp_path / ".secretscanignore", {"a" * 64: "old fixture"})
    assert cli.main([str(path)]) == 0
    assert "did not match" not in capsys.readouterr().err
    assert cli.main([str(tmp_path)]) == 0
    assert "1 ignore entries did not match" in capsys.readouterr().err


@pytest.mark.parametrize("token", [
    "ASIA" + "Z3K9P2M7W4Q8T6N5",
    "rk_live_" + "Ab12Cd" * 4,
    "xapp-" + "1-A123BC-123456-Ab12Cd34",
    "PuTTY-User-Key-File-" + "3: ssh-ed25519",
])
def test_added_key_types(token):
    assert scanner.scan_line(token)


@pytest.mark.parametrize("join", ['"\n    "', '" +\n    "', '" \\\n    "'])
def test_key_split_across_two_quoted_lines(tmp_path, join):
    path = tmp_path / "a.py"
    path.write_text('key = ("' + AWS[:10] + join + AWS[10:] + '")\n')
    findings = scanner.scan_file(path)
    assert len(findings) == 1
    assert findings[0].secret == AWS
    assert findings[0].line_number == 1


def test_module_entrypoint(tmp_path):
    result = subprocess.run([sys.executable, "-m", "secretscan", str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout == "No secrets found.\n"


def test_closed_pipe_exits_2_without_shutdown_traceback(tmp_path):
    (tmp_path / "a").write_text(AWS)
    # Closing the read end before output makes this deterministic; head -1
    # alone may consume the entire small report before the writer notices.
    import os
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        result = subprocess.run([sys.executable, "-m", "secretscan", str(tmp_path)],
                                stdout=write_fd, stderr=subprocess.PIPE, text=True)
    finally:
        os.close(write_fd)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


# --- second audit: rule formats and token endings ----------------------------
# GitHub, Slack and OpenAI shapes below follow the providers' own docs (linked
# in rules.py). Every value is synthetic and built in pieces.

GHP = "ghp_" + "Ab12Cd" * 6
FINE_GRAINED = "github_pat_" + "Ab12" * 20 + "Z9"
OPENAI_LEGACY = "sk-" + "Ab12Cd34" * 6


@pytest.mark.parametrize("token, suffix", [
    (AWS, "_backup"), (AWS, "中"),
    (GHP, "_backup"), (GHP, "中"),
    # "_" is a legal character inside fine-grained tokens, so only the
    # non-ASCII suffix is outside that token's alphabet.
    (FINE_GRAINED, "中"),
])
def test_token_followed_by_underscore_or_non_ascii_is_found(token, suffix):
    # Python's \b counts "_" and letters like "中" as word characters, so a
    # \b at the end of a rule used to hide these keys.
    assert [value for _, value in scanner.scan_line(token + suffix)] == [token]


def test_legacy_openai_key_followed_by_hyphen_is_found():
    # Older OpenAI keys never contain "-", so "-suffix" isn't part of the key.
    assert [value for _, value in scanner.scan_line(OPENAI_LEGACY + "-suffix")] == [OPENAI_LEGACY]


@pytest.mark.parametrize("token", [
    # GitHub refresh token with a 76-character body, like GitHub's own example.
    "ghr_" + "1B4a2e77838347a7" * 4 + "Ab12Cd3456Ef",
    # GitHub's stateless installation token: ghs_<app id>_<JWT>.
    "ghs_123456_" + "eyJhbGciOiJSUzI1NiJ9" + "." + "eyJpc3MiOiIxMjM0NTYifQ" * 10 + "." + "Ab1-_Cd2" * 20,
    # Slack refresh, rotated, workflow, and rotated app-level tokens.
    "xoxe-1-" + "Ab12Cd34Ef" * 3,
    "xoxe.xoxp-1-" + "1234-Ab12Cd34Ef",
    "xwfp-" + "Ab12Cd34Ef" * 2,
    "xoxe.xapp-1-" + "A123BC-123456-Ab12Cd34",
])
def test_current_provider_formats_are_found(token):
    assert [value for _, value in scanner.scan_line(token)] == [token]


def test_slack_rotation_doc_placeholder_is_recognized(tmp_path, capsys):
    path = tmp_path / "docs.md"
    path.write_text("REFRESH=" + "xoxe-1-" + "Your-Refresh-Token" + "\n")
    assert cli.main([str(path)]) == 0
    assert "Suppressed 1 recognized placeholder" in capsys.readouterr().out
