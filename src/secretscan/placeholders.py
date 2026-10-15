"""Placeholders: recognizing a few kinds of obviously fake keys.

Documentation, tutorials, and config templates often contain text that has
the exact SHAPE of a key but clearly isn't one, like "AKIA" followed by 16
X's. Reporting those would make users wade through false alarms, or add
`secretscan:ignore` comments all over their code.

This module answers one question: "is this matched text a placeholder we
recognize?" It deliberately recognizes only a small, explainable set of
cases. It does NOT:

- look at the rest of the line. A comment saying "example" or "fake" next
  to a key is not proof the key is harmless: people comment out real keys
  all the time, and a real key in a comment is still leaked.
- look for words like "test" or "dummy" inside the key. A real key can
  contain those letters by chance, and hiding a real key is far worse than
  showing a fake one.
- measure randomness (entropy). A low-randomness key can still be real.

Anything not recognized here is reported as normal. That's on purpose: an
offline scanner can't tell a realistic-looking fake key from a real one.
"""

# Lets us write type hints like `str | None` on Python 3.9 (see cli.py).
from __future__ import annotations

# The Rule type, so we know which rule matched (see rules.py).
from secretscan.rules import Rule


# ---------------------------------------------------------------------------
# Check A: exact example values published by the provider
# ---------------------------------------------------------------------------
# Some companies publish one specific fake key in their own documentation.
# Those exact values are safe to skip, because the company itself says
# they're examples.
#
# This is a dictionary: the key is a rule id (see rules.py), and the value
# is a set of exact example strings for that rule. A value is only added
# here after checking the provider's own documentation, with the source
# written next to it. Rules with no verified example simply aren't listed.
#
# We compare the WHOLE match exactly (same letters, same capitals). We never
# check whether an example appears INSIDE a longer match, and never ignore
# upper/lowercase differences, because a slightly different string could be
# a real key.
KNOWN_EXAMPLES = {
    "aws-access-key-id": {
        # Source: AWS IAM User Guide, "Programmatic access with AWS security
        # credentials", which gives this as its example access key ID:
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds-programmatic-access.html
        # It's split into two pieces so this file never contains the whole
        # key as plain text (see "fake secrets in tests" in CLAUDE.md).
        "AKIA" + "IOSFODNN7EXAMPLE",
    },
}


# ---------------------------------------------------------------------------
# Check B: a token body made entirely of one filler character
# ---------------------------------------------------------------------------
# People writing docs often fill the variable part of a key with one
# repeated character: "AKIA" + "X" * 16, or a Stripe key ending in 0s.
#
# The rules for this check, all of which must be true:
#   1. The rule defines a "body" group (see rules.py). Only AWS, GitHub
#      classic tokens, Stripe, and Google keys do. Rules with several parts
#      (Slack, OpenAI, Anthropic, GitHub fine-grained) and private-key
#      headers are never checked, because we don't want to guess where their
#      variable part starts.
#   2. The body is at least MIN_FILLER_LENGTH characters long.
#   3. EVERY character of the body is the same character, and it's one of
#      FILLER_CHARACTERS. A real-looking key that merely CONTAINS "XXXX"
#      somewhere is still reported.
#
# This is a guess, not proof: it's possible (though very unlikely) for a
# real key to look like this. Users can turn the check off with
# --include-placeholders.

# The characters people conventionally use as filler: capital X, small x,
# and zero. (A "set" is used because we only ever ask "is it in here?".)
FILLER_CHARACTERS = {"X", "x", "0"}

# The shortest body we treat as filler. All supported rules already have
# bodies at least this long; the limit stops a short body (for example in
# a future rule) from being dismissed too easily.
MIN_FILLER_LENGTH = 16


def token_body(rule: Rule, candidate: str) -> str | None:
    """Return the variable part ("body") of a matched token, if the rule has one.

    Returns None when the rule doesn't define a body group, so callers can
    tell "no body to check" apart from an actual body.
    """
    # `groupindex` is a dictionary of the pattern's named groups.
    # If there's no group called "body", this rule has opted out.
    if "body" not in rule.pattern.groupindex:
        return None

    # Run the rule's pattern again on just the matched text, to find out
    # which part of it is the body. `fullmatch` only succeeds if the pattern
    # matches the WHOLE string, start to end. It always should here, since
    # `candidate` is exactly what this same pattern matched.
    match = rule.pattern.fullmatch(candidate)
    if match is None:
        return None

    return match.group("body")


def is_filler(body: str) -> bool:
    """Return True if `body` is one filler character repeated (Check B)."""
    if len(body) < MIN_FILLER_LENGTH:
        return False

    # `set(body)` is the set of DIFFERENT characters in the body. If it has
    # exactly one member, every character is the same one.
    return len(set(body)) == 1 and body[0] in FILLER_CHARACTERS


def placeholder_reason(rule: Rule, candidate: str) -> str | None:
    """Decide whether a matched candidate is a recognized placeholder.

    `rule` is the rule that matched, and `candidate` is the exact text it
    matched (the whole key, prefix included).

    Returns a short reason (e.g. "token body is all 'X' filler") if the
    candidate is a recognized placeholder, or None if it should be reported.
    The reason never contains the candidate itself, so it's always safe to
    print.
    """
    # Check A: an exact example value published for this rule.
    # `.get(rule.id, set())` returns the rule's examples, or an empty set
    # if the rule has none, so rules without examples never match.
    if candidate in KNOWN_EXAMPLES.get(rule.id, set()):
        return "published documentation example"

    # Check B: the body is entirely one filler character.
    body = token_body(rule, candidate)
    if body is not None and is_filler(body):
        return f"token body is all '{body[0]}' filler"

    # Not a placeholder we recognize: report it.
    return None
