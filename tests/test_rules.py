"""Tests for the detection rules (rules.py).

IMPORTANT: GitHub blocks pushes containing real-looking secrets, so we never
write a complete fake key as plain text in this file. We build it in code
instead ("AKIA" + "X" * 16), so the full key string never appears here.
"""

import re

from secretscan.rules import (
    RULES,
    ANTHROPIC_API_KEY,
    AWS_ACCESS_KEY_ID,
    GITHUB_FINE_GRAINED_TOKEN,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    OPENAI_API_KEY,
    PRIVATE_KEY,
    SLACK_TOKEN,
    STRIPE_LIVE_SECRET_KEY,
    Rule,
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


# --- Slack -----------------------------------------------------------------

# A fake Slack bot token, in the real shape: xoxb-<numbers>-<numbers>-<letters>.
FAKE_SLACK_TOKEN = "xoxb-" + "1" * 12 + "-" + "2" * 12 + "-" + "a" * 24


def test_slack_rule_matches_a_token():
    match = SLACK_TOKEN.pattern.search(f'SLACK = "{FAKE_SLACK_TOKEN}"')
    assert match is not None
    assert match.group(0) == FAKE_SLACK_TOKEN


def test_slack_rule_matches_every_token_kind():
    for kind in ["a", "b", "p", "r", "s"]:
        token = "xox" + kind + "-" + "1" * 20
        assert SLACK_TOKEN.pattern.search(token) is not None


def test_slack_rule_ignores_unknown_kind():
    # "xoxz" isn't a real Slack token kind.
    token = "xoxz-" + "1" * 20
    assert SLACK_TOKEN.pattern.search(token) is None


def test_slack_rule_ignores_token_that_is_too_short():
    # Fewer than 10 characters after the dash.
    token = "xoxb-" + "1" * 9
    assert SLACK_TOKEN.pattern.search(token) is None


# --- Stripe ----------------------------------------------------------------

def test_stripe_rule_matches_a_live_key():
    key = "sk_live_" + "a" * 24
    match = STRIPE_LIVE_SECRET_KEY.pattern.search(f'stripe.api_key = "{key}"')
    assert match is not None
    assert match.group(0) == key


def test_stripe_rule_matches_longer_newer_keys():
    # Newer Stripe keys are longer than 24 characters; the whole key matches.
    key = "sk_live_" + "a" * 99
    assert STRIPE_LIVE_SECRET_KEY.pattern.search(key).group(0) == key


def test_stripe_rule_ignores_test_keys():
    # Test-mode keys can't move real money, so they aren't reported.
    key = "sk_test_" + "a" * 24
    assert STRIPE_LIVE_SECRET_KEY.pattern.search(key) is None


def test_stripe_rule_ignores_key_that_is_too_short():
    key = "sk_live_" + "a" * 23
    assert STRIPE_LIVE_SECRET_KEY.pattern.search(key) is None


# --- Google ----------------------------------------------------------------

def test_google_rule_matches_a_key():
    key = "AIza" + "a" * 35
    match = GOOGLE_API_KEY.pattern.search(f'GOOGLE_KEY = "{key}"')
    assert match is not None
    assert match.group(0) == key


def test_google_rule_matches_key_ending_in_a_dash():
    # This is why the pattern has no \b at the end: a key ending in "-"
    # followed by a quote would otherwise be missed.
    key = "AIza" + "a" * 34 + "-"
    match = GOOGLE_API_KEY.pattern.search(f'"{key}"')
    assert match is not None
    assert match.group(0) == key


def test_google_rule_ignores_key_that_is_too_short():
    key = "AIza" + "a" * 34
    assert GOOGLE_API_KEY.pattern.search(key) is None


def test_google_rule_is_case_sensitive():
    # "AIZA" (capital Z and A) isn't how Google keys start.
    key = "AIZA" + "a" * 35
    assert GOOGLE_API_KEY.pattern.search(key) is None


# --- Anthropic -------------------------------------------------------------

# A fake Anthropic key in the real shape: sk-ant-api03-<long random part>.
FAKE_ANTHROPIC_KEY = "sk-ant-" + "api03-" + "a" * 90


def test_anthropic_rule_matches_a_key():
    match = ANTHROPIC_API_KEY.pattern.search(f'ANTHROPIC_API_KEY="{FAKE_ANTHROPIC_KEY}"')
    assert match is not None
    assert match.group(0) == FAKE_ANTHROPIC_KEY


def test_anthropic_rule_ignores_short_placeholder():
    # Documentation often shows a short placeholder like this.
    assert ANTHROPIC_API_KEY.pattern.search("sk-ant-xxxx") is None


# --- OpenAI ----------------------------------------------------------------

def test_openai_rule_matches_an_older_key():
    key = "sk-" + "a" * 48
    match = OPENAI_API_KEY.pattern.search(f'OPENAI_API_KEY="{key}"')
    assert match is not None
    assert match.group(0) == key


def test_openai_rule_matches_a_project_key():
    key = "sk-" + "proj-" + "a" * 100
    assert OPENAI_API_KEY.pattern.search(key).group(0) == key


def test_openai_rule_ignores_short_placeholder():
    assert OPENAI_API_KEY.pattern.search("sk-xxxx") is None


def test_openai_rule_does_not_match_anthropic_keys():
    # The negative lookahead (?!ant-) stops the OpenAI rule from also
    # reporting Anthropic keys, which would show every one twice.
    assert OPENAI_API_KEY.pattern.search(FAKE_ANTHROPIC_KEY) is None


# --- Private keys ----------------------------------------------------------
# The header is built from two pieces so the full header line never appears
# in this file as plain text.

def make_header(kind):
    # e.g. make_header("RSA ") -> five dashes + "BEGIN RSA PRIVATE KEY" + five dashes
    return "-----BEGIN " + kind + "PRIVATE KEY" + "-----"


def test_private_key_rule_matches_common_key_kinds():
    # "" (nothing) covers the plain kind with no word before PRIVATE KEY.
    for kind in ["RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ", ""]:
        assert PRIVATE_KEY.pattern.search(make_header(kind)) is not None


def test_private_key_rule_matches_pgp_key_block():
    header = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
    assert PRIVATE_KEY.pattern.search(header) is not None


def test_private_key_rule_ignores_public_keys_and_certificates():
    # These are meant to be shared, so they aren't secrets.
    assert PRIVATE_KEY.pattern.search("-----BEGIN PUBLIC KEY-----") is None
    assert PRIVATE_KEY.pattern.search("-----BEGIN CERTIFICATE-----") is None


def test_private_key_rule_ignores_lowercase_mentions():
    # Talking ABOUT private keys in normal text isn't a leak.
    assert PRIVATE_KEY.pattern.search("never commit your private key") is None


# --- Rule metadata: stable ids and token bodies ------------------------------

def test_every_rule_has_a_unique_id():
    # Fingerprints are built from rule ids, so every rule needs its own.
    ids = [rule.id for rule in RULES]
    # No rule is missing an id...
    assert all(ids)
    # ...and no two rules share one. (A set throws away duplicates, so if
    # the set is smaller than the list, something was repeated.)
    assert len(set(ids)) == len(ids)


def test_rule_id_defaults_to_empty_for_custom_rules():
    # Rules made with just a name and a pattern still work.
    rule = Rule(name="Custom", pattern=re.compile("abc"))
    assert rule.id == ""


def test_body_group_is_the_part_after_the_prefix():
    # The match is still the WHOLE key; the body is just the variable part.
    key = "AKIA" + "Z3K9P2M7W4Q8T6N5"
    match = AWS_ACCESS_KEY_ID.pattern.search(f"k = '{key}'")
    assert match.group(0) == key
    assert match.group("body") == "Z3K9P2M7W4Q8T6N5"


def test_only_rules_with_a_simple_body_define_one():
    # `groupindex` is a dictionary of a pattern's NAMED groups. These rules
    # have one clear "variable part", so they define a body...
    for rule in [AWS_ACCESS_KEY_ID, GITHUB_TOKEN, STRIPE_LIVE_SECRET_KEY, GOOGLE_API_KEY]:
        assert "body" in rule.pattern.groupindex
    # ...and these have several parts (or, for private keys, only a
    # header), so they don't.
    for rule in [GITHUB_FINE_GRAINED_TOKEN, SLACK_TOKEN, ANTHROPIC_API_KEY,
                 OPENAI_API_KEY, PRIVATE_KEY]:
        assert "body" not in rule.pattern.groupindex
