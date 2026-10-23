"""Regression coverage for format-specific exclusions and escaped credentials.

Use byte scans as well as the CLI so a missed match cannot be confused with
output filtering. Samples are synthetic and are constructed where practical.
"""
import json
from pathlib import Path

import pytest

from secretscan.cli import main
from secretscan.ignores import fingerprint
from secretscan.scanner import scan_bytes


@pytest.mark.parametrize("filename", [".env", ".env.local", "app.properties", "app.ini", "deploy.sh", "Dockerfile"])
@pytest.mark.parametrize("value", ["false", "true", "null", "none", "nil", "~"])
def test_config_words_are_literal_passwords_outside_yaml(filename, value):
    found = scan_bytes(f'PASSWORD={value}\n'.encode(), Path(filename))
    assert len(found) == 1
    assert found[0].secret == value
    assert found[0].placeholder_reason is None


@pytest.mark.parametrize("value", ["null", "~", "true", "false", "NULL", "False"])
def test_yaml_non_string_scalars_remain_excluded(value):
    assert scan_bytes(f'password: {value}\n'.encode(), Path("app.yaml")) == []
    # Quoting a YAML scalar explicitly turns it into a string password.
    [found] = scan_bytes(f'password: "{value}"\n'.encode(), Path("app.yaml"))
    assert found.secret == value


@pytest.mark.parametrize("value", ["none", "nil"])
def test_yaml_words_that_are_not_null_remain_literal_passwords(value):
    [found] = scan_bytes(f'password: {value}\n'.encode(), Path("app.yml"))
    assert found.secret == value


def test_equals_assignment_in_yaml_does_not_use_yaml_scalar_exclusions():
    [found] = scan_bytes(b'PASSWORD=false\n', Path("app.yml"))
    assert found.secret == "false"


@pytest.mark.parametrize("value", ["<my-password>", "<your-password>", "<abc>"])
def test_angle_bracket_passwords_are_not_automatically_hidden(value):
    [found] = scan_bytes(f'password = "{value}"\n'.encode(), Path("app.py"))
    assert found.secret == value
    assert found.placeholder_reason is None
    url = 'mysql://user:' + value + '@localhost/db'
    [found] = scan_bytes(url.encode(), Path("app.py"))
    assert found.rule_id == "url-password"
    assert found.secret == value


@pytest.mark.parametrize("escape, character", [
    (r'\u000a', '\n'), (r'\u000d', '\r'), (r'\u0022', '"'),
    (r'\u0027', "'"), (r'\u005c', '\\'), (r'\u0000', '\0'),
])
@pytest.mark.parametrize("encoded_name", [False, True])
def test_json_delimiter_escapes_preserve_one_complete_password(escape, character, encoded_name):
    name = r'pass\u0077ord' if encoded_name else 'password'
    source = '{"' + name + '": "ab' + escape + 'cd"}\n'
    [found] = scan_bytes(source.encode(), Path("app.json"))
    assert found.secret == 'ab' + character + 'cd'
    assert found.line_number == found.end_line_number == 1


def test_json_escape_next_to_another_finding_does_not_erase_either():
    source = '{"password": "ab' + r'\u000a' + 'cd", "db_password":"other"}'
    found = scan_bytes(source.encode(), Path("app.json"))
    assert [f.secret for f in found] == ['ab\ncd', 'other']


def test_escaped_password_json_output_is_masked_and_fingerprint_uses_whole_value(tmp_path, capsys):
    path = tmp_path / "app.json"
    path.write_text('{"password":"ab' + r'\u000a' + 'cd"}')
    assert main([str(path), "--json"]) == 1
    output = capsys.readouterr().out
    report = json.loads(output)
    [found] = report['findings']
    assert found['match'] == '*' * 5
    assert found['id'] == fingerprint('generic-secret', 'app.json', 'ab\ncd')


@pytest.mark.parametrize("filename, prefix", [("app.py", 'password = "'), (".env", 'PASSWORD=')])
def test_url_assignment_is_one_specific_finding(filename, prefix):
    value = 'summer' + '2024'
    url = 'mysql://user:' + value + '@localhost/db'
    suffix = '"' if filename.endswith('.py') else ''
    [found] = scan_bytes((prefix + url + suffix).encode(), Path(filename))
    assert found.rule_id == 'url-password'
    assert found.secret == value


def test_url_deduplication_keeps_an_independent_password_on_the_same_line():
    url = 'mysql://user:' + 'summer2024' + '@localhost/db'
    found = scan_bytes(f'password="{url}"; db_password="other"'.encode(), Path('app.py'))
    assert [(f.rule_id, f.secret) for f in found] == [
        ('generic-secret', 'other'), ('url-password', 'summer2024'),
    ]
