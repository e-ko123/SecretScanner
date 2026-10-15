"""Tests for the detection rules (rules.py).

IMPORTANT: GitHub blocks pushes containing real-looking secrets, so we never
write a complete fake key as plain text in this file. We build it in code
instead ("AKIA" + "X" * 16), so the full key string never appears here.
"""

from secretscan.rules import (
    AWS_ACCESS_KEY_ID,
    GITHUB_FINE_GRAINED_TOKEN,
    GITHUB_TOKEN,
)

# A fake AWS key: "AKIA" plus 16 X's = 20 characters, the right shape.
FAKE_AWS_KEY = "AKIA" + "X" * 16


# --- AWS -------------------------------------------------------------------


def test_aws_rule_matches_a_key():
    # `.search` looks for the pattern anywhere in the text.
    # It returns a match object if found, or None if not.
    line = f'aws_key = "{FAKE_AWS_KEY}"'
    match = AWS_ACCESS_KEY_ID.pattern.search(line)

    # The match must exist AND be exactly the key (not the quotes etc.).
    assert match is not None
    assert match.group(0) == FAKE_AWS_KEY


def test_aws_rule_ignores_key_that_is_too_short():
    # Only 15 characters after AKIA instead of 16, so not a real key shape.
    line = "AKIA" + "X" * 15
    assert AWS_ACCESS_KEY_ID.pattern.search(line) is None


def test_aws_rule_ignores_key_that_is_too_long():
    # 17 characters after AKIA: the word boundary (\b) at the end of the
    # pattern stops this from matching just the first 20 characters.
    line = "AKIA" + "X" * 17
    assert AWS_ACCESS_KEY_ID.pattern.search(line) is None


def test_aws_rule_ignores_lowercase():
    # Real AWS key IDs only use capital letters and digits.
    line = "akia" + "x" * 16
    assert AWS_ACCESS_KEY_ID.pattern.search(line) is None


def test_aws_rule_ignores_key_glued_to_other_letters():
    # The word boundary (\b) at the start of the pattern means "AKIA"
    # must not be stuck onto the end of another word.
    line = "NOT" + FAKE_AWS_KEY
    assert AWS_ACCESS_KEY_ID.pattern.search(line) is None


# --- GitHub ----------------------------------------------------------------

# A fake GitHub token: "ghp_" + 36 characters.
FAKE_GITHUB_TOKEN = "ghp_" + "a" * 36


def test_github_rule_matches_a_token():
    line = f'token = "{FAKE_GITHUB_TOKEN}"'
    match = GITHUB_TOKEN.pattern.search(line)
    assert match is not None
    assert match.group(0) == FAKE_GITHUB_TOKEN


def test_github_rule_matches_other_prefixes():
    # Every one of GitHub's five prefixes should match.
    # The `for` loop runs the same check once for each prefix.
    for prefix in ["ghp", "gho", "ghu", "ghs", "ghr"]:
        token = prefix + "_" + "a" * 36
        assert GITHUB_TOKEN.pattern.search(token) is not None


def test_github_rule_allows_mixed_case_and_digits():
    # Real tokens mix lowercase, capitals, and digits.
    token = "ghp_" + "aB3" * 12  # "aB3" repeated 12 times = 36 characters
    assert GITHUB_TOKEN.pattern.search(token) is not None


def test_github_rule_ignores_token_that_is_too_short():
    # Only 35 characters after the prefix instead of 36.
    token = "ghp_" + "a" * 35
    assert GITHUB_TOKEN.pattern.search(token) is None


def test_github_rule_ignores_unknown_prefix():
    # "ghx" isn't a real GitHub prefix.
    token = "ghx_" + "a" * 36
    assert GITHUB_TOKEN.pattern.search(token) is None


def test_github_fine_grained_rule_matches_a_token():
    # Real shape: github_pat_ + 22 characters + "_" + 59 characters = 82.
    token = "github_pat_" + "a" * 22 + "_" + "b" * 59
    match = GITHUB_FINE_GRAINED_TOKEN.pattern.search(f'token = "{token}"')
    assert match is not None
    assert match.group(0) == token


def test_github_fine_grained_rule_ignores_token_that_is_too_short():
    token = "github_pat_" + "a" * 50
    assert GITHUB_FINE_GRAINED_TOKEN.pattern.search(token) is None
