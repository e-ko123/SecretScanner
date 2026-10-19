"""Tests for four gaps found when testing simple passwords like password123:

1. Unquoted values in config files (env files, shell scripts, YAML, Docker).
2. Passwords inside URLs (database links).
3. The names "pass" and "passphrase".
4. No false alarm on GitHub Actions' ${{ secrets.NAME }} references.

The passwords here are deliberately simple examples, not real credentials.
"""

import time

import pytest

from secretscan import cli
from secretscan.scanner import is_config_file, scan_file, scan_line

GHP = "ghp_" + "Ab12Cd" * 6


def findings(tmp_path, name, text):
    """Write `text` to a file called `name` and return [(rule name, secret), ...]."""
    path = tmp_path / name
    path.write_text(text)
    return [(f.rule_name, f.secret) for f in scan_file(path)]


# --- 1. Unquoted values in config files --------------------------------------

@pytest.mark.parametrize("name, line", [
    (".env", "PASSWORD=password123"),
    (".env.local", "DB_PASSWORD=password123"),
    ("deploy.sh", "export DB_PASSWORD=password123"),
    ("docker-compose.yml", "    password: password123"),
    ("docker-compose.yml", "      - POSTGRES_PASSWORD=password123"),
    ("Dockerfile", "ENV DB_PASSWORD=password123"),
    ("app.properties", "db.password=password123"),
    ("settings.ini", "password = password123"),
])
def test_unquoted_password_in_config_files_is_found(tmp_path, name, line):
    assert findings(tmp_path, name, line + "\n") == [
        ("Possible Weak Password or Placeholder", "password123")
    ]


def test_unquoted_random_api_key_in_config_file_is_found(tmp_path):
    # Not a password name, so it needs a random-looking value, like quoted ones.
    value = "Xk9mP2vL7qR4tZ8w"
    assert findings(tmp_path, ".env", "API_KEY=" + value + "\n") == [
        ("Generic Password or Secret", value)
    ]
    assert findings(tmp_path, "b.env", "API_KEY=short\n") == []


def test_trailing_comment_is_not_part_of_the_value(tmp_path):
    assert findings(tmp_path, ".env", "PASSWORD=hunter2 # dev only\n") == [
        ("Possible Weak Password or Placeholder", "hunter2")
    ]
    # A "#" with no space before it can be part of the value.
    assert findings(tmp_path, "b.env", "PASSWORD=ab#cd12\n") == [
        ("Possible Weak Password or Placeholder", "ab#cd12")
    ]


@pytest.mark.parametrize("line", [
    "PASSWORD=${DB_PASSWORD}",          # a variable reference
    "PASSWORD=$DB_PASSWORD",
    "PASSWORD=$(cat /run/secrets/db)",  # a shell command
    "password: null",                   # YAML "no value"
    "password: ~",
    "password: !vault |",               # YAML tag (an encrypted value follows)
    "password:",                        # no value at all
    "PASSWORD=",
])
def test_config_lines_without_a_stored_password_are_not_findings(tmp_path, line):
    assert findings(tmp_path, ".env", line + "\n") == []


def test_unquoted_rule_does_not_apply_to_code_files(tmp_path):
    # In Python, these are a type hint and a variable assignment, not passwords.
    assert findings(tmp_path, "models.py", "    password: str\npassword = user_input\n") == []


def test_quoted_values_in_config_files_are_reported_once(tmp_path):
    assert findings(tmp_path, ".env", 'PASSWORD="password123"\n') == [
        ("Possible Weak Password or Placeholder", "password123")
    ]


@pytest.mark.parametrize("name, expected", [
    (".env", True), (".env.production", True), ("prod.env", True),
    ("docker-compose.yml", True), ("config.YAML", True), ("Dockerfile", True),
    ("deploy.sh", True), ("app.py", False), ("index.js", False), ("README.md", False),
])
def test_is_config_file(tmp_path, name, expected):
    assert is_config_file(tmp_path / name) is expected


def test_many_spaces_in_a_config_line_stay_fast(tmp_path):
    path = tmp_path / ".env"
    path.write_text("PASSWORD=a" + " " * 200_000 + "b\n")
    started = time.perf_counter()
    scan_file(path)
    assert time.perf_counter() - started < 2


# --- 2. Passwords inside URLs -------------------------------------------------

def test_password_in_a_database_url_is_found():
    line = 'DB_LINK = "mysql://admin:password123@db.example.com/app"'
    assert [(rule.name, secret) for rule, secret in scan_line(line)] == [
        ("Possible Weak Password in URL", "password123")
    ]


def test_random_password_in_a_url_is_not_labeled_weak():
    # (No "#" in it: in a URL, "#" starts the fragment, so a password with a
    # "#" has to be written as %23.)
    line = "https://deploy:Xk9!mP2vL7qR4tZ8w@git.example.com/repo.git"
    [(rule, secret)] = scan_line(line)
    assert rule.name == "Password in URL"
    assert secret == "Xk9!mP2vL7qR4tZ8w"


@pytest.mark.parametrize("line", [
    "ssh://git@github.com/owner/repo.git",          # username only
    "http://localhost:8080/path",                   # port, no login
    "https://user:${DB_PASSWORD}@db.example.com",   # a variable reference
    "mysql://admin:<password>@db.example.com/app",  # a documentation placeholder
    "see https://example.com/a:b/c@d",              # ":" and "@" in the path
])
def test_urls_without_a_stored_password_are_not_findings(line):
    assert scan_line(line) == []


def test_token_used_as_url_password_is_reported_as_the_token():
    # The more specific diagnosis wins; the same value isn't reported twice.
    line = "https://x-access:" + GHP + "@github.com/owner/repo.git"
    assert [(rule.name, secret) for rule, secret in scan_line(line)] == [("GitHub Token", GHP)]


def test_url_password_is_masked_in_the_report(tmp_path, capsys):
    (tmp_path / "config.py").write_text('DB = "mysql://admin:password123@db.example.com/app"\n')
    assert cli.main([str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "password123" not in output
    assert "Possible Weak Password in URL" in output


# --- 3. "pass" and "passphrase" -------------------------------------------------

@pytest.mark.parametrize("line", [
    'db_pass = "password123"',
    'PASS = "password123"',
    'key_passphrase = "password123"',
])
def test_pass_names_are_password_names(line):
    assert [(rule.name, secret) for rule, secret in scan_line(line)] == [
        ("Possible Weak Password or Placeholder", "password123")
    ]


@pytest.mark.parametrize("line", [
    'bypass = "password123"',
    'compass = "password123"',
    'passport = "password123"',
    "    pass",  # Python's "do nothing" statement
])
def test_words_containing_pass_are_not_password_names(line):
    assert scan_line(line) == []


# --- 4. GitHub Actions secret references ------------------------------------------

@pytest.mark.parametrize("line", [
    'password: "${{ secrets.DB_PASSWORD }}"',
    "password: '${{ secrets.DB_PASSWORD }}'",
    'api_key: "${{ vars.API_KEY }}"',
])
def test_github_actions_references_are_not_findings(line):
    assert scan_line(line) == []


def test_angle_bracket_placeholders_are_not_findings():
    # Docs write "put your own value here" as <...>; no real password looks like that.
    assert scan_line('password = "<your-password>"') == []
    # A value that merely CONTAINS angle brackets is still reported.
    assert scan_line('password = "ab<c>d"') != []


def test_github_actions_reference_unquoted_in_a_workflow_file(tmp_path):
    text = "env:\n  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}\n"
    assert findings(tmp_path, "ci.yml", text) == []


def test_real_password_in_a_workflow_file_is_still_found(tmp_path):
    assert findings(tmp_path, "ci.yml", "env:\n  DB_PASSWORD: password123\n") == [
        ("Possible Weak Password or Placeholder", "password123")
    ]
