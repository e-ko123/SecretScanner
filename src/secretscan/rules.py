"""Rules: descriptions of what each kind of secret looks like.

Each rule pairs a human-readable name (shown in the output) with a
"regular expression" (regex): a mini-language for describing text patterns.
The scanner checks every line of every file against every rule in RULES.

To add a new kind of secret, add a new Rule to the RULES list at the bottom.
"""

# Lets us use modern type hints on Python 3.9 (see cli.py for details).
from __future__ import annotations

# `re` is Python's built-in regular expression module.
import re

# `dataclass` is a shortcut for writing simple classes that just hold data.
# Instead of writing an __init__ method by hand, we list the fields and
# Python writes the boilerplate for us.
from dataclasses import dataclass


# `frozen=True` makes Rule objects read-only after they're created.
# Rules should never change while the program runs, so this prevents
# accidental edits (trying to change one raises an error).
@dataclass(frozen=True)
class Rule:
    """One kind of secret the scanner knows how to find."""

    # The name shown to the user, e.g. "AWS Access Key ID".
    name: str

    # The compiled regex that matches this kind of secret.
    # "Compiled" means Python has already processed the pattern once,
    # so it's fast to reuse on thousands of lines.
    pattern: re.Pattern


# ---------------------------------------------------------------------------
# AWS Access Key ID
# ---------------------------------------------------------------------------
# Real example shape: AKIA followed by 16 more characters (20 total).
#
# The pattern, piece by piece:
#   \b          a "word boundary": the key must not be glued to other letters
#               or digits on its left. So "xAKIA..." won't match.
#   AKIA        the exact letters A, K, I, A. Every long-term AWS access key
#               ID starts with this.
#   [0-9A-Z]    any one character that is a digit or a CAPITAL letter...
#   {16}        ...repeated exactly 16 times.
#   \b          another word boundary: the key must end here, so a longer
#               string like AKIA + 20 characters doesn't match.
#
# The r"..." in front of the string means "raw string": Python leaves the
# backslashes alone, so \b reaches the regex engine as-is. Without the r,
# Python would turn \b into a "backspace" character and the pattern would break.
AWS_ACCESS_KEY_ID = Rule(
    name="AWS Access Key ID",
    pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


# ---------------------------------------------------------------------------
# GitHub token
# ---------------------------------------------------------------------------
# Real example shape: ghp_ followed by 36 letters or digits (40 total).
# The first three letters tell you what kind of token it is:
#   ghp = personal access token (the most common)
#   gho = OAuth token
#   ghu = user-to-server token
#   ghs = server-to-server token
#   ghr = refresh token
#
# The pattern, piece by piece:
#   \b                     word boundary: nothing glued on the left.
#   (ghp|gho|ghu|ghs|ghr)  ONE of these five prefixes. The | means "or",
#                          and the brackets group the choices together.
#   _                      a literal underscore.
#   [0-9a-zA-Z]            one digit, lowercase letter, or capital letter...
#   {36}                   ...repeated exactly 36 times.
#   \b                     word boundary: the token must end here.
GITHUB_TOKEN = Rule(
    name="GitHub Token",
    pattern=re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b"),
)


# ---------------------------------------------------------------------------
# GitHub fine-grained personal access token
# ---------------------------------------------------------------------------
# GitHub's newer kind of token, which can be limited to specific repos.
# Real example shape: github_pat_ followed by 82 more characters, which are
# letters, digits, and underscores (it has an underscore in the middle).
#
# The pattern, piece by piece:
#   \b              word boundary: nothing glued on the left.
#   github_pat_     the exact text "github_pat_".
#   [0-9a-zA-Z_]    one letter, digit, or underscore...
#   {82}            ...repeated exactly 82 times.
#   \b              word boundary: the token must end here.
GITHUB_FINE_GRAINED_TOKEN = Rule(
    name="GitHub Fine-Grained Token",
    pattern=re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b"),
)


# ---------------------------------------------------------------------------
# Slack token
# ---------------------------------------------------------------------------
# Real example shape: xoxb-<numbers>-<numbers>-<letters and digits>
# (the length varies).
# The letter after "xox" tells you what kind of token it is:
#   b = bot token, p = user token, a / r / s = other kinds of Slack tokens.
#
# The pattern, piece by piece:
#   \b             word boundary: nothing glued on the left.
#   xox            the exact letters "xox". Every Slack token starts this way.
#   [abprs]        ONE of the letters a, b, p, r, or s. A list of letters in
#                  square brackets means "any one of these".
#   -              a literal dash.
#   [0-9A-Za-z-]   one digit, letter, or dash. (A dash at the END of the
#                  square brackets means a real "-" character, not a range
#                  like the one in "0-9".)
#   {10,}          ...repeated 10 OR MORE times. Slack tokens don't have one
#                  fixed length, so we say "at least 10" instead of an exact
#                  number. Nothing after the comma means "no upper limit".
SLACK_TOKEN = Rule(
    name="Slack Token",
    pattern=re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),
)


# ---------------------------------------------------------------------------
# Stripe live secret key
# ---------------------------------------------------------------------------
# Real example shape: sk_live_ followed by 24 or more letters and digits.
#
# We only look for LIVE keys ("sk_live_"), not test keys ("sk_test_").
# Test keys only work in Stripe's practice mode and can't move real money,
# so reporting them would mostly be noise.
#
# The pattern, piece by piece:
#   \b             word boundary: nothing glued on the left.
#   sk_live_       the exact text "sk_live_" ("sk" = secret key).
#   [0-9a-zA-Z]    one digit or letter...
#   {24,}          ...repeated 24 OR MORE times. Older keys have exactly 24;
#                  newer ones are longer, so "at least 24" catches both.
STRIPE_LIVE_SECRET_KEY = Rule(
    name="Stripe Live Secret Key",
    pattern=re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}"),
)


# ---------------------------------------------------------------------------
# Google API key
# ---------------------------------------------------------------------------
# Real example shape: AIza followed by 35 more characters (39 total).
# Used for Google Maps, YouTube, Firebase, and other Google services.
#
# The pattern, piece by piece:
#   \b               word boundary: nothing glued on the left.
#   AIza             the exact text "AIza" (note the lowercase "z" and "a").
#   [0-9A-Za-z_-]    one digit, letter, underscore, or dash...
#   {35}             ...repeated exactly 35 times.
#
# Why no \b at the end, unlike the other rules? A word boundary only exists
# between a "word" character (letter, digit, underscore) and a non-word
# character. Google keys can END with a dash, which is a non-word character,
# so if the key is followed by a quote or a space (also non-word), there's no
# boundary there and \b would wrongly fail. Leaving it off is the simple fix.
GOOGLE_API_KEY = Rule(
    name="Google API Key",
    pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
)


# Every rule the scanner uses. The scanner loops over this list, so adding
# a new rule here is all it takes for it to be checked.
RULES = [
    AWS_ACCESS_KEY_ID,
    GITHUB_TOKEN,
    GITHUB_FINE_GRAINED_TOKEN,
    SLACK_TOKEN,
    STRIPE_LIVE_SECRET_KEY,
    GOOGLE_API_KEY,
]
