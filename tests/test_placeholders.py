"""Tests for placeholder recognition (placeholders.py).

Many of these tests check what must NOT be hidden. Hiding a real key is
much worse than showing a fake one, so the placeholder checks must stay
narrow.

Fake keys are built in code so no complete key appears in this file
(see test_rules.py for why).
"""

import re

from secretscan.placeholders import placeholder_reason
from secretscan.rules import (
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

# A realistic-looking AWS key: varied capital letters and digits.
PLAUSIBLE_AWS_KEY = "AKIA" + "Z3K9P2M7W4Q8T6N5"


# --- Check A: published example values -------------------------------------

def test_aws_documentation_example_is_a_placeholder():
    # AWS's own docs use this exact key ID as their example.
    example = "AKIA" + "IOSFODNN7EXAMPLE"
    assert placeholder_reason(AWS_ACCESS_KEY_ID, example) == "published documentation example"


def test_a_value_one_character_off_the_example_is_reported():
    # Only the EXACT published value counts. Anything else could be real.
    almost = "AKIA" + "IOSFODNN7EXAMPLF"
    assert placeholder_reason(AWS_ACCESS_KEY_ID, almost) is None


# --- Check B: all-filler bodies --------------------------------------------

def test_aws_key_with_all_x_body_is_a_placeholder():
    assert placeholder_reason(AWS_ACCESS_KEY_ID, "AKIA" + "X" * 16) == (
        "token body is all 'X' filler"
    )


def test_aws_key_with_all_zero_body_is_a_placeholder():
    assert placeholder_reason(AWS_ACCESS_KEY_ID, "AKIA" + "0" * 16) is not None


def test_every_supported_rule_recognizes_filler():
    # One example per rule that defines a body group, using different
    # filler characters along the way.
    cases = [
        (GITHUB_TOKEN, "ghp_" + "x" * 36),
        (STRIPE_LIVE_SECRET_KEY, "sk_live_" + "0" * 24),
        (GOOGLE_API_KEY, "AIza" + "X" * 35),
    ]
    for rule, candidate in cases:
        assert placeholder_reason(rule, candidate) is not None, rule.name


def test_plausible_key_is_not_a_placeholder():
    assert placeholder_reason(AWS_ACCESS_KEY_ID, PLAUSIBLE_AWS_KEY) is None


def test_key_containing_a_run_of_filler_is_still_reported():
    # Half X's, half real-looking characters. Only a body that is ENTIRELY
    # filler counts, so this must still be reported.
    key = "AKIA" + "X" * 8 + "Z3K9P2M7"
    assert placeholder_reason(AWS_ACCESS_KEY_ID, key) is None


def test_key_made_of_a_repeated_chunk_is_still_reported():
    # "Q7RZ" repeated four times is repetitive, but not one filler character.
    assert placeholder_reason(AWS_ACCESS_KEY_ID, "AKIA" + "Q7RZ" * 4) is None


def test_repeated_non_filler_character_is_still_reported():
    # Only X, x, and 0 count as filler. "AAAA..." is not on the list.
    assert placeholder_reason(AWS_ACCESS_KEY_ID, "AKIA" + "A" * 16) is None


def test_words_like_example_or_test_inside_a_key_are_not_enough():
    # A key that happens to contain words like these is still reported.
    # Only the exact published example value counts.
    key = "AKIA" + "TESTEXAMPLE" + "DUMMY"
    assert placeholder_reason(AWS_ACCESS_KEY_ID, key) is None


# --- rules that don't support the filler check -----------------------------

def test_rules_without_a_body_never_use_the_filler_check():
    # These rules have several parts, so we don't guess where the body is.
    # Even an all-x value is reported.
    cases = [
        (OPENAI_API_KEY, "sk-" + "x" * 48),
        (SLACK_TOKEN, "xoxb-" + "x" * 20),
        (GITHUB_FINE_GRAINED_TOKEN, "github_pat_" + "x" * 82),
    ]
    for rule, candidate in cases:
        assert placeholder_reason(rule, candidate) is None, rule.name


def test_custom_rule_without_body_gets_no_filler_check():
    # A rule someone adds without a body group is never checked for filler.
    rule = Rule(name="Custom Token", pattern=re.compile(r"tok_[X]{20}"))
    assert placeholder_reason(rule, "tok_" + "X" * 20) is None


def test_private_key_headers_are_never_placeholders():
    header = "-----BEGIN " + "RSA PRIVATE KEY"
    assert placeholder_reason(PRIVATE_KEY, header) is None


# --- the reason is safe to print -------------------------------------------

def test_reason_never_contains_the_candidate():
    candidate = "AKIA" + "X" * 16
    reason = placeholder_reason(AWS_ACCESS_KEY_ID, candidate)
    assert candidate not in reason
