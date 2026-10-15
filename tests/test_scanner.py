"""Tests for the scanner (scanner.py).

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

from secretscan.scanner import (
    MAX_FILE_SIZE,
    SKIP_FOLDERS,
    find_files,
    is_binary,
    is_too_large,
    scan_file,
    scan_line,
)

FAKE_AWS_KEY = "AKIA" + "X" * 16


# --- find_files ------------------------------------------------------------
# `tmp_path` is a built-in pytest helper: a brand-new empty folder created
# just for this test and cleaned up afterwards. It lets us build real files
# and folders without touching the project.

def test_find_files_returns_a_single_file_as_is(tmp_path):
    file = tmp_path / "config.py"
    file.write_text("x = 1\n")

    assert find_files(file) == [file]


def test_find_files_includes_files_in_subfolders(tmp_path):
    # Build this folder structure:
    #   tmp_path/
    #   ├── a.py
    #   └── src/
    #       └── deep/
    #           └── b.py
    (tmp_path / "a.py").write_text("x = 1\n")
    # `mkdir(parents=True)` creates the folder AND any missing folders above
    # it, like creating both "src" and "src/deep" in one go.
    (tmp_path / "src" / "deep").mkdir(parents=True)
    (tmp_path / "src" / "deep" / "b.py").write_text("y = 2\n")

    files = find_files(tmp_path)

    assert files == [
        tmp_path / "a.py",
        tmp_path / "src" / "deep" / "b.py",
    ]


def test_find_files_returns_empty_list_for_empty_folder(tmp_path):
    assert find_files(tmp_path) == []


def test_find_files_skips_folders_that_are_not_your_code(tmp_path):
    # Put one file inside each folder that should be skipped...
    for folder in SKIP_FOLDERS:
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "file.py").write_text("x = 1\n")

    # ...plus one normal file that should still be found.
    (tmp_path / "app.py").write_text("x = 1\n")

    assert find_files(tmp_path) == [tmp_path / "app.py"]


def test_find_files_skips_folders_nested_deeper(tmp_path):
    # Skipped folders are skipped wherever they appear, not just at the top,
    # e.g. a node_modules folder inside a frontend/ folder.
    (tmp_path / "frontend" / "node_modules").mkdir(parents=True)
    (tmp_path / "frontend" / "node_modules" / "lib.js").write_text("x\n")
    (tmp_path / "frontend" / "app.js").write_text("x\n")

    assert find_files(tmp_path) == [tmp_path / "frontend" / "app.js"]


def test_find_files_does_not_skip_folders_with_similar_names(tmp_path):
    # Only exact folder names are skipped. "builder" contains the word
    # "build", but it's a different folder and should still be scanned.
    (tmp_path / "builder").mkdir()
    (tmp_path / "builder" / "tool.py").write_text("x = 1\n")

    assert find_files(tmp_path) == [tmp_path / "builder" / "tool.py"]


# --- skipping binary and large files ---------------------------------------

def test_is_binary_true_for_file_with_null_bytes(tmp_path):
    # The first bytes of a real PNG image, which include null bytes (\x00).
    # `write_bytes` writes raw bytes instead of text.
    file = tmp_path / "image.png"
    file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

    assert is_binary(file) is True


def test_is_binary_false_for_text_including_emoji(tmp_path):
    # Non-English characters and emoji are still text, not binary.
    file = tmp_path / "notes.txt"
    file.write_text("héllo wörld 🎉\n", encoding="utf-8")

    assert is_binary(file) is False


def test_is_too_large_only_above_the_limit(tmp_path):
    # Exactly at the limit is fine; one byte over is too large.
    at_limit = tmp_path / "at_limit.txt"
    at_limit.write_text("a" * MAX_FILE_SIZE)
    over_limit = tmp_path / "over_limit.txt"
    over_limit.write_text("a" * (MAX_FILE_SIZE + 1))

    assert is_too_large(at_limit) is False
    assert is_too_large(over_limit) is True


def test_find_files_skips_binary_and_large_files(tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00\x00")
    (tmp_path / "huge.log").write_text("a" * (MAX_FILE_SIZE + 1))
    (tmp_path / "app.py").write_text("x = 1\n")

    assert find_files(tmp_path) == [tmp_path / "app.py"]


def test_find_files_skips_a_single_binary_file(tmp_path):
    # Even when the user names a binary file directly, we don't scan it.
    file = tmp_path / "image.png"
    file.write_bytes(b"\x89PNG\x00\x00")

    assert find_files(file) == []


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
