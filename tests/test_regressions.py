"""Regression cases from the security review; all credentials are synthetic."""

import json
import os
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


# Unix-only assumptions are marked so Windows skips them instead of failing:
# /dev/null, control characters in file names, and creating symlinks.
UNIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="relies on Unix-only file system behavior")


@pytest.mark.parametrize("kind", [
    "large", "binary",
    pytest.param("special", marks=UNIX_ONLY),  # uses /dev/null
])
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


@UNIX_ONLY
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


@UNIX_ONLY
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


# A fake private key: the header (built in two pieces so this file never
# contains a whole header), lines of base64-looking data, and the end line.
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_FOOTER = "-----END " + "RSA PRIVATE KEY-----"


def pem_key(seed):
    """A synthetic key block; different seeds give different key data."""
    data = "\n".join(("MIIE" + seed * 15)[:64] for _ in range(3))
    return PEM_HEADER + "\n" + data + "\n" + PEM_FOOTER + "\n"


def test_private_key_header_in_prose_is_not_a_finding(tmp_path):
    path = tmp_path / "README.md"
    path.write_text("A key file starts with " + PEM_HEADER + " and then data.\n"
                    "PuTTY files start with " + "PuTTY-User-Key-File-" + "3: instead.\n")
    assert scanner.scan_file(path) == []


def test_private_key_block_is_found_multiline_and_in_json(tmp_path):
    path = tmp_path / "keys.txt"
    path.write_text(pem_key("Ab12"))
    # The same key stored inside a JSON string, with \n written out.
    json_path = tmp_path / "service.json"
    json_path.write_text('{"private_key": "' + pem_key("Ab12").replace("\n", "\\n") + '"}\n')
    findings = scanner.scan_file(path) + scanner.scan_file(json_path)
    assert [f.rule_id for f in findings] == ["private-key", "private-key"]
    # Both describe the same key data, so their secrets match.
    assert findings[0].secret == findings[1].secret


def test_dismissing_one_private_key_does_not_hide_another(tmp_path, capsys):
    path = tmp_path / "keys.txt"
    path.write_text(pem_key("Ab12"))
    old_id = finding_id(scanner.scan_file(path)[0], cli.scan_root(tmp_path))
    save_ignore_file(tmp_path / ".secretscanignore", {old_id: "test fixture"})
    assert cli.main([str(tmp_path)]) == 0
    # A second, different key in the same file must still be reported.
    path.write_text(pem_key("Ab12") + pem_key("Zz98"))
    assert cli.main([str(tmp_path)]) == 1
    assert "Found 1 possible secret" in capsys.readouterr().out


def test_private_key_block_can_be_dismissed_in_review(tmp_path, monkeypatch, capsys):
    (tmp_path / "keys.txt").write_text(pem_key("Ab12"))
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    answers = iter(["y", "test fixture"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main([str(tmp_path), "--review"]) == 0
    assert cli.main([str(tmp_path)]) == 0


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


# --- second audit: scanning ----------------------------------------------------

import time


def test_many_spaces_do_not_make_scanning_slow(tmp_path):
    # An earlier split-string regex slowed down quadratically on this input:
    # a quote, a long run of spaces, and a character that stops the match.
    path = tmp_path / "a.py"
    path.write_text('"a"' + " " * 200_000 + "!\n'b'\n")
    started = time.perf_counter()
    scanner.scan_file(path)
    # Generous limit: the fixed regex takes well under a tenth of a second.
    assert time.perf_counter() - started < 2


def test_marker_inside_url_is_not_a_comment(tmp_path):
    # Here "#" is part of the URL (data), not a comment, so nothing is hidden.
    path = tmp_path / "a.py"
    path.write_text('DOC = """https://example.com/?k=' + AWS + '#secretscan:ignore"""\n')
    assert [f.secret for f in scanner.scan_file(path)] == [AWS]


def test_independent_statements_are_not_joined(tmp_path):
    # Two separate Python statements (no brackets, no + or \): Python never
    # joins them, so neither should the scanner.
    path = tmp_path / "a.py"
    path.write_text('first = "' + AWS[:10] + '"\n"' + AWS[10:] + '"\n')
    assert scanner.scan_file(path) == []


@pytest.mark.parametrize("source", [
    # Python: mixed quote styles inside brackets.
    'key = ("' + AWS[:10] + "\"\n       '" + AWS[10:] + "')\n",
    # Python: a comment between the two fragments, inside brackets.
    'key = ("' + AWS[:10] + '"  # first half\n       "' + AWS[10:] + '")\n',
    # JavaScript: + at the start of the second line.
    'const key = "' + AWS[:10] + '"\n    + "' + AWS[10:] + '";\n',
])
def test_common_two_fragment_forms_are_joined(tmp_path, source):
    path = tmp_path / "a.src"
    path.write_text(source)
    assert [f.secret for f in scanner.scan_file(path)] == [AWS]


def test_split_key_is_not_also_reported_as_its_first_half(tmp_path):
    # The first fragment alone is long enough to match the OpenAI rule;
    # only the complete key should be reported.
    key = "sk-proj-" + "Ab12Cd34" * 10
    path = tmp_path / "a.py"
    path.write_text('key = ("' + key[:48] + '"\n       "' + key[48:] + '")\n')
    assert [f.secret for f in scanner.scan_file(path)] == [key]


def test_findings_are_in_line_order(tmp_path):
    path = tmp_path / "a.py"
    path.write_text('key = ("' + AWS[:10] + '"\n       "' + AWS[10:] + '")\nother = "' + GHP + '"\n')
    assert [f.line_number for f in scanner.scan_file(path)] == [1, 3]


def test_json_unicode_escape_cannot_hide_a_key(tmp_path):
    # "A" is JSON for "A", so this decodes to the full AWS key.
    path = tmp_path / "config.json"
    path.write_text('{"key": "\\u0041' + AWS[1:] + '"}\n')
    assert [f.secret for f in scanner.scan_file(path)] == [AWS]


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra permissions on Windows")
def test_file_symlink_outside_the_project_is_skipped(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text(AWS)
    project = tmp_path / "project"
    project.mkdir()
    (project / "link.txt").symlink_to(outside)
    issues = []
    assert scanner.find_files(project, issues) == []
    assert issues[0].reason == "symlink file"


def test_file_that_grows_after_listing_is_not_read_in_full(tmp_path, capsys, monkeypatch):
    path = tmp_path / "a.txt"
    path.write_text("small\n")
    real_find = cli.find_files

    def find_then_grow(target, issues):
        files = real_find(target, issues)
        # Simulate another program replacing the file after it was listed.
        path.write_bytes(b"a" * (scanner.MAX_FILE_SIZE + 10))
        return files

    monkeypatch.setattr(cli, "find_files", find_then_grow)
    assert cli.main([str(tmp_path)]) == 2
    assert "could not read file" in capsys.readouterr().err


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are Unix-only")
def test_file_swapped_for_a_pipe_does_not_hang(tmp_path, capsys, monkeypatch):
    path = tmp_path / "a.txt"
    path.write_text("small\n")
    real_find = cli.find_files

    def find_then_swap(target, issues):
        files = real_find(target, issues)
        path.unlink()
        os.mkfifo(path)  # a pipe nobody writes to: reading it would wait forever
        return files

    monkeypatch.setattr(cli, "find_files", find_then_swap)
    assert cli.main([str(tmp_path)]) == 2


# --- second audit: ignore file and command line --------------------------------

def answer(monkeypatch, *answers):
    """Pretend to be a terminal and answer input() with `answers` in order."""
    remaining = iter(answers)
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(remaining))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are Unix-only")
def test_default_ignore_file_that_is_a_pipe_does_not_hang(tmp_path, capsys):
    os.mkfifo(tmp_path / ".secretscanignore")
    assert cli.main([str(tmp_path)]) == 2
    assert "must be a regular file" in capsys.readouterr().err


def test_huge_ignore_file_is_rejected(tmp_path, capsys):
    (tmp_path / ".secretscanignore").write_text(" " * 1_000_001)
    assert cli.main([str(tmp_path)]) == 2
    assert "larger than 1 MB" in capsys.readouterr().err


def test_show_ids_output_stays_small_with_one_huge_token(tmp_path, capsys):
    # One 200,000-character project key plus many normal keys used to make
    # the report about 2 GB, because every line was padded to the huge one.
    path = tmp_path / "a.txt"
    path.write_text("sk-proj-" + "Ab12Cd34" * 25_000 + "\n" + (AWS + "\n") * 2000)
    assert cli.main([str(path), "--show-ids"]) == 1
    assert len(capsys.readouterr().out) < 2_000_000


def test_key_in_a_file_name_is_masked(tmp_path, capsys):
    path = tmp_path / (AWS + ".txt")
    path.write_text(AWS + "\n")
    assert cli.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert AWS not in output
    assert "AKIA****" in output


def test_argument_errors_mask_keys_and_escape_control_codes(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--" + AWS + "\x1b[8m"])
    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert AWS not in err
    assert "\x1b" not in err


def test_git_root_wins_over_a_nested_ignore_file(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    save_ignore_file(tmp_path / "src" / ".secretscanignore", {})
    path = tmp_path / "src" / "config.py"
    path.write_text(AWS)
    answer(monkeypatch, "y", "fixture")
    assert cli.main([str(path), "--review"]) == 0
    # The answer was saved at the repository root, so a full scan honors it...
    assert cli.main([str(tmp_path)]) == 0
    # ...and the unused nested file is pointed out.
    assert "is not used" in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra permissions on Windows")
def test_folder_shortcut_gives_the_same_ids(tmp_path, capsys):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.txt").write_text(AWS)
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    finding = scanner.scan_file(real / "a.txt")[0]
    save_ignore_file(real / ".secretscanignore", {finding_id(finding, real): "fixture"})
    assert cli.main([str(real)]) == 0
    assert cli.main([str(tmp_path / "alias")]) == 0


def test_review_keeps_ignore_file_edits_made_during_the_review(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.txt").write_text(AWS)
    ignore = tmp_path / ".secretscanignore"
    save_ignore_file(ignore, {})
    answers = iter(["y"])

    def fake_input(prompt=""):
        if prompt.startswith("Reason"):
            # Someone else adds an entry while the user is typing a reason.
            save_ignore_file(ignore, {"c" * 64: "added elsewhere"})
            return "fixture"
        return next(answers)

    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", fake_input)
    assert cli.main([str(tmp_path), "--review"]) == 0
    assert set(load_ignore_file(ignore)) >= {"c" * 64}
    assert len(load_ignore_file(ignore)) == 2


def test_reason_with_invalid_unicode_is_rejected_when_loading(tmp_path):
    path = tmp_path / "ignore"
    path.write_text('{"version":1,"findings":[{"id":"' + "a" * 64 + '","reason":"\\ud800"}]}')
    with pytest.raises(IgnoreFileError, match="invalid Unicode"):
        load_ignore_file(path)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra permissions on Windows")
def test_saving_through_a_symlinked_ignore_file_updates_the_shared_file(tmp_path, monkeypatch, capsys):
    shared = tmp_path / "shared.json"
    save_ignore_file(shared, {})
    project = tmp_path / "project"
    project.mkdir()
    (project / ".secretscanignore").symlink_to(shared)
    (project / "a.txt").write_text(AWS)
    answer(monkeypatch, "y", "fixture")
    assert cli.main([str(project), "--review"]) == 0
    assert (project / ".secretscanignore").is_symlink()
    assert len(load_ignore_file(shared)) == 1


def test_files_changed_during_review_are_not_reported_as_clean(tmp_path, monkeypatch, capsys):
    path = tmp_path / "a.txt"
    path.write_text(AWS)

    def fake_input(prompt=""):
        if prompt.startswith("Reason"):
            # The file is edited while the user is answering.
            path.write_text("other = '" + GHP + "'\n")
            return "fixture"
        return "y"

    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", fake_input)
    assert cli.main([str(tmp_path), "--review"]) == 2
    assert "changed during the review" in capsys.readouterr().err


def test_closed_stderr_still_exits_2(tmp_path):
    (tmp_path / ".secretscanignore").write_text("{not json")
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        result = subprocess.run([sys.executable, "-m", "secretscan", str(tmp_path)],
                                stdout=subprocess.PIPE, stderr=write_fd)
    finally:
        os.close(write_fd)
    assert result.returncode == 2


def test_naming_the_ignore_file_directly_scans_it(tmp_path, capsys):
    ignore = tmp_path / ".secretscanignore"
    ignore.write_text(json.dumps({"version": 1, "findings": [
        {"id": "a" * 64, "reason": "was " + AWS}]}))
    assert cli.main([str(ignore)]) == 1


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra permissions on Windows")
def test_broken_default_ignore_symlink_is_an_error(tmp_path, capsys):
    (tmp_path / ".secretscanignore").symlink_to(tmp_path / "missing.json")
    (tmp_path / "a.txt").write_text("clean\n")
    assert cli.main([str(tmp_path / "a.txt")]) == 2


def test_answers_are_printed_if_no_location_can_be_saved(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.txt").write_text(AWS)
    answer(monkeypatch, "y", "fixture")

    def always_fail(*args, **kwargs):
        raise PermissionError()

    monkeypatch.setattr(cli, "save_ignore_file", always_fail)
    assert cli.main([str(tmp_path), "--review"]) == 2
    err = capsys.readouterr().err
    assert "Add these entries" in err
    assert '"reason": "fixture"' in err


# --- audit round 1: bugs introduced by the second-audit fixes -------------------

def test_no_unused_notice_names_the_active_or_missing_file(tmp_path, capsys):
    (tmp_path / ".git").mkdir()
    save_ignore_file(tmp_path / ".secretscanignore", {})
    other = tmp_path.parent / (tmp_path.name + "-other.json")
    save_ignore_file(other, {})
    # --no-ignore uses no ignore file, so there's nothing to point out.
    assert cli.main([str(tmp_path), "--no-ignore"]) == 0
    assert "Notice" not in capsys.readouterr().err
    # With --ignore-file, the root's file IS unused, and the notice names
    # the file that's actually in use.
    assert cli.main([str(tmp_path), "--ignore-file", str(other)]) == 0
    err = capsys.readouterr().err
    assert "is not used by this scan" in err
    assert other.name in err


def test_review_of_the_ignore_file_itself_is_not_a_change_during_review(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    ignore = tmp_path / ".secretscanignore"
    ignore.write_text(json.dumps({"version": 1, "findings": [
        {"id": "a" * 64, "reason": "was " + AWS}]}))
    answer(monkeypatch, "y", "")
    # Saving the answer changes this file on purpose; that's not an outside edit.
    assert cli.main([str(ignore), "--review"]) == 0


def test_backslashes_in_paths_are_not_doubled():
    assert cli.display("C:\\Users\\me\\app.py") == "C:\\Users\\me\\app.py"
    # Control characters are still escaped.
    assert cli.display("a\x1bb") == "a\\x1bb"


def test_private_key_header_split_over_two_strings_is_not_reported(tmp_path):
    path = tmp_path / "doc.py"
    path.write_text('h = ("-----BEGIN RSA PRIV"\n     "ATE KEY-----")\n')
    assert scanner.scan_file(path) == []
