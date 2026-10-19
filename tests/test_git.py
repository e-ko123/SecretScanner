"""Exercise real Git repositories, including the hook Git actually executes.

Each test gets its own temporary repository. None installs a hook in this
project. Fake credentials are assembled so the source contains no full key.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from secretscan.cli import main
from secretscan.ignores import fingerprint
from secretscan.scanner import MAX_FILE_SIZE

KEY = "AKIA" + "Z3K9P2M7W4Q8T6N5"


def git(repo, *args, check=True):
    # Never let Git print a diff containing our synthetic credentials on error.
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if check:
        assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result


@pytest.fixture
def repo(tmp_path, monkeypatch):
    # Ignore the developer's global Git settings and inherited index overrides.
    # This also prevents tests from executing a globally configured hook.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Scanner Test")
    git(tmp_path, "config", "user.email", "scanner@example.invalid")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def stage(repo, contents, name="app.py"):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents.encode() if isinstance(contents, str) else contents)
    git(repo, "add", "--", name)
    return path


def test_initial_commit_uses_index_not_cleaned_disk(repo, capsys):
    path = stage(repo, KEY)
    path.write_text("clean now")
    assert main(["--staged", "--show-ids"]) == 1
    output = capsys.readouterr().out
    assert KEY not in output
    assert fingerprint("aws-access-key-id", "app.py", KEY) in output


def test_unstaged_secret_is_not_scanned(repo):
    path = stage(repo, "clean")
    path.write_text(KEY)
    assert main(["--staged"]) == 0


def test_unchanged_secret_and_deletion_do_not_block(repo):
    stage(repo, KEY + "\nold text\n")
    git(repo, "commit", "-qm", "baseline")
    stage(repo, KEY + "\nnew text\n")
    assert main(["--staged"]) == 0
    git(repo, "rm", "-f", "app.py")
    assert main(["--staged"]) == 0


def test_split_key_second_line_change_is_detected(repo):
    stage(repo, 'key = "AKIA" +\n    "not-a-key"\n')
    git(repo, "commit", "-qm", "baseline")
    stage(repo, 'key = "AKIA" +\n    "' + KEY[4:] + '"\n')
    assert main(["--staged"]) == 1


def test_private_key_body_change_is_detected(repo):
    header = "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    footer = "\n-----END " + "RSA PRIVATE KEY-----\n"
    stage(repo, header + "aB3z" * 16 + footer)
    git(repo, "commit", "-qm", "baseline")
    stage(repo, header + "qD7x" * 16 + footer)
    assert main(["--staged"]) == 1


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_encodings(repo, encoding):
    stage(repo, KEY.encode(encoding))
    assert main(["--staged"]) == 1


@pytest.mark.parametrize("name", ["dist/app.js", "build/app.js", "node_modules/key.js",
                                     "odd\tname\n.py", "-option.py", "nested/hello.py"])
def test_paths_are_not_shell_or_diff_syntax(repo, name, monkeypatch, capsys):
    stage(repo, KEY, name)
    (repo / "subdir").mkdir()
    monkeypatch.chdir(repo / "subdir")
    assert main(["--staged"]) == 1
    assert KEY not in capsys.readouterr().out


def test_rename_is_conservatively_scanned(repo):
    stage(repo, KEY)
    git(repo, "commit", "-qm", "baseline")
    git(repo, "mv", "app.py", "renamed.py")
    assert main(["--staged"]) == 1


def test_ignore_must_be_staged(repo):
    stage(repo, KEY)
    data = {"version": 1, "findings": [{
        "id": fingerprint("aws-access-key-id", "app.py", KEY), "reason": "synthetic test",
    }]}
    path = repo / ".secretscanignore"
    path.write_text(json.dumps(data))
    assert main(["--staged"]) == 1
    git(repo, "add", ".secretscanignore")
    assert main(["--staged"]) == 0
    path.write_text("invalid unstaged contents")
    assert main(["--staged"]) == 0
    assert main(["--staged", "--no-ignore"]) == 1


def test_bad_staged_ignore_fails_even_without_changes(repo):
    stage(repo, "invalid", ".secretscanignore")
    assert main(["--staged"]) == 2


def test_placeholder_and_inline_switches(repo):
    stage(repo, "AKIA" + "X" * 16 + "\n" + KEY + " # secretscan:ignore\n")
    assert main(["--staged"]) == 0
    assert main(["--staged", "--include-placeholders"]) == 1
    assert main(["--staged", "--include-inline-ignored"]) == 1


def test_size_limit_fails_closed(repo):
    stage(repo, b"x" * (MAX_FILE_SIZE + 1))
    assert main(["--staged"]) == 2


def test_binary_skip_is_visible(repo, capsys):
    stage(repo, b"image\0data")
    assert main(["--staged"]) == 0
    assert "binary staged file" in capsys.readouterr().err


def test_no_repo_fails_with_safe_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["--staged"]) == 2
    assert main(["install-hook"]) == 2


def test_staged_rejects_review_and_path(repo):
    assert main(["--staged", "--review"]) == 2
    assert main(["--staged", "somewhere"]) == 2


def test_empty_index(repo):
    assert main(["--staged"]) == 0


def test_alternate_index_is_respected(repo, monkeypatch):
    stage(repo, KEY)
    alternate = repo / ".git" / "alternate-index"
    monkeypatch.setenv("GIT_INDEX_FILE", str(alternate))
    git(repo, "read-tree", "--empty")
    assert main(["--staged"]) == 0


def test_merge_conflict_is_error(repo):
    stage(repo, "baseline\n")
    git(repo, "commit", "-qm", "baseline")
    git(repo, "checkout", "-qb", "other")
    stage(repo, "other branch\n")
    git(repo, "commit", "-qm", "other")
    git(repo, "checkout", "-q", "-")
    stage(repo, "original branch\n")
    git(repo, "commit", "-qm", "original")
    assert git(repo, "merge", "other", check=False).returncode != 0
    assert main(["--staged"]) == 2


def test_hook_blocks_secret_allows_clean_commit(repo):
    assert main(["install-hook"]) == 0
    stage(repo, KEY)
    result = git(repo, "commit", "-m", "blocked", check=False)
    assert result.returncode != 0
    assert b"Commit blocked: secretscan found" in result.stderr
    assert KEY.encode() not in result.stdout + result.stderr
    stage(repo, "clean\n")
    git(repo, "commit", "-qm", "allowed")


def test_existing_hook_preserved_until_force(repo):
    hook = repo / ".git/hooks/pre-commit"
    hook.write_text("existing hook")
    assert main(["install-hook"]) == 2
    assert hook.read_text() == "existing hook"
    assert main(["install-hook", "--force"]) == 0
    assert "-I -m secretscan --staged" in hook.read_text()
    assert hook.stat().st_mode & 0o111


def test_custom_hook_path(repo):
    git(repo, "config", "core.hooksPath", "custom hooks")
    assert main(["install-hook"]) == 0
    assert (repo / "custom hooks/pre-commit").exists()
    stage(repo, KEY)
    assert git(repo, "commit", "-m", "blocked", check=False).returncode != 0


def test_hook_symlink_replaced_without_touching_target(repo):
    target = repo / "keep-me"
    target.write_text("original")
    hook = repo / ".git/hooks/pre-commit"
    hook.symlink_to(target)
    assert main(["install-hook"]) == 2
    assert main(["install-hook", "--force"]) == 0
    assert not hook.is_symlink()
    assert target.read_text() == "original"


def test_hook_fails_closed_on_scan_error(repo):
    assert main(["install-hook"]) == 0
    stage(repo, "invalid", ".secretscanignore")
    result = git(repo, "commit", "-m", "blocked", check=False)
    assert result.returncode != 0
    assert b"could not complete the scan" in result.stderr


def test_linked_worktree_hook_and_scan(repo):
    stage(repo, "clean")
    git(repo, "commit", "-qm", "baseline")
    worktree = repo / "linked-tree"
    git(repo, "worktree", "add", "-qb", "linked", str(worktree))
    # A linked worktree has a .git file, not a .git directory.
    previous = Path.cwd()
    try:
        os.chdir(worktree)
        assert main(["install-hook"]) == 0
        stage(worktree, KEY)
        assert main(["--staged"]) == 1
        result = git(worktree, "commit", "-m", "blocked", check=False)
        assert result.returncode != 0
        assert b"Commit blocked: secretscan found" in result.stderr
    finally:
        os.chdir(previous)


def test_partial_commit_checks_only_selected_files(repo):
    stage(repo, "clean", "a.py")
    stage(repo, "clean", "b.py")
    git(repo, "commit", "-qm", "baseline")
    assert main(["install-hook"]) == 0
    stage(repo, KEY, "a.py")
    (repo / "b.py").write_text("new clean content")
    # git commit --only creates an alternate index for the hook to inspect.
    git(repo, "commit", "-qm", "only b", "--only", "b.py")
    assert main(["--staged"]) == 1


def test_staged_symlink_scans_link_text_not_target(repo):
    (repo / "outside-source").write_text(KEY)
    (repo / "link").symlink_to("outside-source")
    git(repo, "add", "link")
    assert main(["--staged"]) == 0


def test_staged_ignore_symlink_is_rejected(repo):
    (repo / ".secretscanignore").symlink_to("missing")
    git(repo, "add", ".secretscanignore")
    assert main(["--staged"]) == 2


def test_submodule_update_is_not_silently_skipped(repo):
    stage(repo, "clean")
    git(repo, "commit", "-qm", "baseline")
    oid = git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    git(repo, "update-index", "--add", "--cacheinfo", "160000," + oid + ",vendor")
    assert main(["--staged"]) == 2


def test_explicit_ignore_override(repo):
    stage(repo, KEY)
    config = repo / "override.json"
    config.write_text(json.dumps({"version": 1, "findings": [{
        "id": fingerprint("aws-access-key-id", "app.py", KEY), "reason": "test",
    }]}))
    assert main(["--staged", "--ignore-file", str(config)]) == 0


def test_missing_git_is_an_error(repo, monkeypatch):
    monkeypatch.setenv("PATH", str(repo / "no-programs"))
    assert main(["--staged"]) == 2


def test_hook_does_not_import_repository_scanner(repo):
    assert main(["install-hook"]) == 0
    # An accidental module name collision must not replace the installed tool.
    (repo / "secretscan.py").write_text("raise SystemExit(0)\n")
    stage(repo, KEY)
    result = git(repo, "commit", "-m", "blocked", check=False)
    assert result.returncode != 0
    assert b"Commit blocked: secretscan found" in result.stderr


def test_generic_secret_hook_blocks_staged_value_after_disk_cleanup(repo):
    # A password has no provider prefix; its assignment and entropy identify it.
    value = "q8#Lz!" + "v2Wm@9"
    assert main(["install-hook"]) == 0
    path = stage(repo, f'password = "{value}"')
    path.write_text('password = os.getenv("DATABASE_PASSWORD")')
    result = git(repo, "commit", "-m", "blocked", check=False)
    assert result.returncode != 0
    assert b"Hard-coded Password" in result.stdout + result.stderr
    assert b"Commit blocked: secretscan found" in result.stderr
    assert value.encode() not in result.stdout + result.stderr
    # Stage the correction too; the actual commit should now succeed.
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "corrected")


def test_generic_secret_staged_dismissal(repo):
    value = "q8#Lz!" + "v2Wm@9"
    stage(repo, f'password = "{value}"')
    ident = fingerprint("generic-secret", "app.py", value)
    stage(repo, json.dumps({"version": 1, "findings": [
        {"id": ident, "reason": "Synthetic example"},
    ]}), ".secretscanignore")
    assert main(["--staged"]) == 0
    assert main(["--staged", "--no-ignore"]) == 1


def test_old_generic_secret_does_not_block_unrelated_staged_line(repo):
    value = "q8#Lz!" + "v2Wm@9"
    stage(repo, f'password = "{value}"\nold = 1\n')
    git(repo, "commit", "-qm", "baseline")
    stage(repo, f'password = "{value}"\nnew = 2\n')
    assert main(["--staged"]) == 0


@pytest.mark.parametrize("value", ["a", "123", "changeme", "password", "your-password-here"])
def test_weak_password_blocks_real_commit_until_explicitly_dismissed(repo, value):
    # Run Git itself: default placeholder filtering must not let weak password
    # assignments through. A reviewed/staged ignore entry can still dismiss it.
    assert main(["install-hook"]) == 0
    stage(repo, f'password = "{value}"')
    result = git(repo, "commit", "-m", "blocked", check=False)
    assert result.returncode != 0
    assert b"Possible Weak Password or Placeholder" in result.stdout + result.stderr
    ident = fingerprint("generic-secret", "app.py", value)
    stage(repo, json.dumps({"version": 1, "findings": [
        {"id": ident, "reason": "Reviewed test fixture"},
    ]}), ".secretscanignore")
    git(repo, "commit", "-qm", "reviewed")
