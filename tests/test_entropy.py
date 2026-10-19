"""Test the math separately from the heuristic and user-facing behavior.

All credential-like examples are assembled at runtime. The samples represent
character distributions, not real accounts or credentials.
"""
import json
from math import log2

import pytest

import secretscan.cli as cli
from secretscan.entropy import MIN_SECRET_ENTROPY, MIN_SECRET_LENGTH, shannon_entropy
from secretscan.ignores import fingerprint, load_ignore_file
from secretscan.rules import GENERIC_SECRET, PASSWORD_ASSIGNMENT, WEAK_PASSWORD_ASSIGNMENT
from secretscan.scanner import scan_file, scan_line

# Twelve different characters score log2(12), slightly more than 3.5.
VALUE = "q8#Lz!" + "v2Wm@9"
AWS = "AKIA" + "Z3K9P2M7W4Q8T6N5"


@pytest.mark.parametrize("value, expected", [
    ("", 0.0), ("a", 0.0), ("aaaaaaaa", 0.0), ("abababab", 1.0),
    ("abcd", 2.0), ("a" * 3 + "b", -(0.75 * log2(0.75) + 0.25 * log2(0.25))),
    ("🙂é🙂é", 1.0),
])
def test_known_entropy_values(value, expected):
    assert shannon_entropy(value) == pytest.approx(expected)


def test_entropy_counts_frequencies_not_order_or_repetition():
    # A sorted sequence and a shuffled sequence have the same character counts.
    assert shannon_entropy("abcd") == shannon_entropy("dcab")
    assert shannon_entropy("abcd") == shannon_entropy("abcd" * 20)


@pytest.mark.parametrize("name", [
    "password", "passwd", "pwd", "secret", "api_key", "apiKey",
    "access_token", "auth-token", "clientSecret", "DATABASE_PASSWORD",
    "MY_SERVICE_API_KEY", "database-password",
])
@pytest.mark.parametrize("operator", ["=", ":"])
def test_supported_assignment_names_extract_only_value(name, operator):
    matches = scan_line(f'{name} {operator} "{VALUE}"')
    password_names = {"password", "passwd", "pwd", "DATABASE_PASSWORD", "database-password"}
    expected_rule = PASSWORD_ASSIGNMENT if name in password_names else GENERIC_SECRET
    assert matches == [(expected_rule, VALUE)]


@pytest.mark.parametrize("key_quote", ['"', "'", ""])
@pytest.mark.parametrize("value_quote", ['"', "'"])
def test_quoted_property_names(key_quote, value_quote):
    line = f'{{{key_quote}password{key_quote}: {value_quote}{VALUE}{value_quote}}}'
    assert scan_line(line) == [(PASSWORD_ASSIGNMENT, VALUE)]


@pytest.mark.parametrize("line", [
    'description = "{value}"', 'notpassword = "{value}"',
    'passwordHash = "{value}"', 'password_hint = "{value}"',
    'password == "{value}"', 'password != "{value}"',
    'password = os.getenv("DATABASE_PASSWORD")',
    'password = process.env.DATABASE_PASSWORD',
    'password = "${{DATABASE_PASSWORD}}"', 'password = "$DATABASE_PASSWORD"',
    'password = "{{{{ secrets.DATABASE_PASSWORD }}}}"',
    'password = "%DATABASE_PASSWORD%"',
    'password = "{value}\'', 'password = "{value}',
    'password =\n"{value}"', 'password = "one\ntwo"',
])
def test_non_literals_unrelated_names_and_references_are_not_findings(line):
    assert scan_line(line.format(value=VALUE)) == []


def test_length_and_entropy_gates():
    assert len(VALUE) == MIN_SECRET_LENGTH
    assert shannon_entropy(VALUE) >= MIN_SECRET_ENTROPY
    assert scan_line(f'secret = "{VALUE}"')
    assert scan_line(f'secret = "{VALUE[:-1]}"') == []
    assert scan_line('secret = "' + "ab" * 50 + '"') == []


def test_placeholder_is_retained_for_optional_display(tmp_path, capsys):
    path = tmp_path / "settings.py"
    # This exact instructional value has enough character variety to pass the
    # entropy gate, so it needs explicit placeholder handling.
    example = "your-" + "password-here"
    path.write_text(f'secret = "{example}"')
    findings = scan_file(path)
    assert len(findings) == 1
    assert findings[0].placeholder_reason == "instructional placeholder"
    assert cli.main([str(path)]) == 0
    assert cli.main([str(path), "--include-placeholders"]) == 1
    assert example not in capsys.readouterr().out


def test_placeholder_word_inside_realistic_value_is_not_hidden():
    candidate = "example-" + VALUE
    assert scan_line(f'password = "{candidate}"') == [(PASSWORD_ASSIGNMENT, candidate)]


def test_escaped_quotes_do_not_end_value_early():
    candidate = VALUE + r'\"more'
    assert scan_line(f'password = "{candidate}"') == [(PASSWORD_ASSIGNMENT, candidate)]


def test_provider_matches_take_precedence_only_where_they_overlap():
    line = f'api_key = "{AWS}"; password = "{VALUE}"'
    matches = scan_line(line)
    assert [(rule.id, secret) for rule, secret in matches] == [
        ("aws-access-key-id", AWS), ("generic-secret", VALUE),
    ]


def test_provider_detection_does_not_depend_on_generic_entropy():
    low_variety_key = "AKIA" + "X" * 16
    matches = scan_line(f'api_key = "{low_variety_key}"')
    assert len(matches) == 1
    assert matches[0][0].id == "aws-access-key-id"
    assert matches[0][1] == low_variety_key


def test_generic_comments_are_scanned_and_inline_marker_still_works():
    line = f'# password = "{VALUE}"'
    assert scan_line(line) == [(PASSWORD_ASSIGNMENT, VALUE)]
    assert scan_line(line + " # secretscan:ignore") == []
    # Two independent secrets cannot both be hidden by a single marker.
    assert len(scan_line(line + f'; api_key = "{AWS}" # secretscan:ignore')) == 2


def test_normal_scan_masks_value_and_has_stable_id(tmp_path, capsys):
    path = tmp_path / "settings.py"
    path.write_text(f'password = "{VALUE}"')
    assert cli.main([str(path), "--show-ids"]) == 1
    output = capsys.readouterr().out
    assert VALUE not in output
    assert VALUE[:4] in output
    assert fingerprint("generic-secret", "settings.py", VALUE) in output


def test_generic_finding_can_be_reviewed(tmp_path, monkeypatch):
    path = tmp_path / "settings.py"
    path.write_text(f'password = "{VALUE}"')
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    answers = iter(["y", "Synthetic credential for a test"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main([str(path), "--review"]) == 0
    saved = load_ignore_file(tmp_path / ".secretscanignore")
    assert fingerprint("generic-secret", "settings.py", VALUE) in saved
    assert cli.main([str(path)]) == 0
    assert cli.main([str(path), "--no-ignore"]) == 1


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_file_decoding_and_line_numbers(tmp_path, encoding):
    path = tmp_path / "settings.txt"
    path.write_bytes((f'# comment\npassword = "{VALUE}"\n').encode(encoding))
    findings = scan_file(path)
    assert len(findings) == 1
    assert findings[0].line_number == 2
    assert findings[0].secret == VALUE


def test_json_unicode_escapes_produce_one_decoded_finding(tmp_path):
    path = tmp_path / "settings.json"
    escaped = "".join("\\u%04x" % ord(character) for character in VALUE)
    path.write_text('{"password": "' + escaped + '"}')
    findings = scan_file(path)
    assert len(findings) == 1
    assert findings[0].secret == VALUE


def test_json_escaped_provider_is_not_also_generic(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"api_key": AWS}).replace("A", r"\u0041"))
    findings = scan_file(path)
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key-id"


@pytest.mark.parametrize("name", ["password", "passwd", "pwd", "DATABASE_PASSWORD", "db-passwd"])
@pytest.mark.parametrize("value", ["a", "123", "summer2024", "changeme", "password", "your-password-here", " " * 3])
def test_password_context_reports_nonempty_weak_values(name, value):
    # Length, repeated characters, and instructional words must not suppress
    # an actual hard-coded password. Even whitespace can be a password.
    assert scan_line(f'{name} = "{value}"') == [(WEAK_PASSWORD_ASSIGNMENT, value)]


@pytest.mark.parametrize("name", ["password", "passwd", "pwd", "secret", "api_key"])
def test_empty_values_are_not_stored_credentials(name):
    assert scan_line(f'{name} = ""') == []


@pytest.mark.parametrize("name", ["secret", "api_key", "access_token", "client_secret"])
def test_broad_names_keep_entropy_gate(name):
    assert scan_line(f'{name} = "abc"') == []
    assert scan_line(f'{name} = "' + "ab" * 20 + '"') == []
    assert scan_line(f'{name} = "{VALUE}"') == [(GENERIC_SECRET, VALUE)]


def test_weak_password_is_visible_masked_and_reviewable(tmp_path, monkeypatch, capsys):
    path = tmp_path / "settings.py"
    value = "change" + "me"
    path.write_text(f'password = "{value}"')
    finding = scan_file(path)[0]
    assert finding.placeholder_reason is None
    assert cli.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert "Possible Weak Password or Placeholder" in output
    assert value not in output
    assert "********" in output
    # Confirm the same ID scheme is retained for earlier generic dismissals.
    assert finding.rule_id == "generic-secret"
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    answers = iter(["y", "Intentionally fake example password"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main([str(path), "--review"]) == 0
    assert cli.main([str(path)]) == 0
    assert cli.main([str(path), "--no-ignore"]) == 1


def test_identical_placeholder_in_password_and_secret_is_classified_per_match(tmp_path):
    path = tmp_path / "settings.py"
    value = "your-" + "password-here"
    path.write_text(f'password = "{value}"; secret = "{value}"')
    findings = scan_file(path)
    assert len(findings) == 2
    assert findings[0].placeholder_reason is None
    assert findings[1].placeholder_reason == "instructional placeholder"


def test_weak_password_inline_ignore_remains_explicitly_reversible(tmp_path):
    path = tmp_path / "settings.py"
    path.write_text('password = "abc" # secretscan:ignore')
    assert cli.main([str(path)]) == 0
    assert cli.main([str(path), "--include-inline-ignored"]) == 1
