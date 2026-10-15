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
    #
    # A pattern MAY contain a "named group" called `body`, written
    # (?P<body>...). It marks the variable part of a token: the part after
    # its fixed prefix. For example, in an AWS key ID the body is the 16
    # characters after "AKIA". Placeholder detection (placeholders.py) only
    # looks at the body, and only for rules that define one. Rules without
    # a body group are never treated as placeholders by those checks.
    pattern: re.Pattern

    # A short, stable identifier, e.g. "aws-access-key-id". It's used to
    # build finding fingerprints (see ignores.py). Unlike `name`, it must
    # never change once released: changing it would change every
    # fingerprint for this rule and undo users' dismissed findings.
    #
    # `= ""` gives it a default value, so code that builds a Rule with only
    # a name and a pattern (like some tests) keeps working. When it's empty,
    # the scanner falls back to using `name` as the identifier.
    id: str = ""


# Token prefixes may follow escaped newlines, URL encodings, or identifiers.
# Do not require a word boundary before them.

# ---------------------------------------------------------------------------
# AWS Access Key ID (long-term AKIA and temporary ASIA)
# https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds-programmatic-access.html
# ---------------------------------------------------------------------------
# Real example shape: AKIA followed by 16 more characters (20 total).
#
# The pattern, piece by piece:
#   (?:AKIA|ASIA)  either the long-term or temporary access-key prefix.
#   (?P<body>   start of a "named group" called body. A group captures the
#               text matched inside the brackets, and naming it lets other
#               code ask for it by name: match.group("body"). It doesn't
#               change WHAT the pattern matches, only labels a part of it.
#               Here the body is everything after "AKIA".
#   [0-9A-Z]    any one character that is a digit or a CAPITAL letter...
#   {16}        ...repeated exactly 16 times.
#   )           end of the body group.
#   \b          a word boundary: the key must end here, so a longer
#               string like AKIA + 20 characters doesn't match.
#
# The r"..." in front of the string means "raw string": Python leaves the
# backslashes alone, so \b reaches the regex engine as-is. Without the r,
# Python would turn \b into a "backspace" character and the pattern would break.
AWS_ACCESS_KEY_ID = Rule(
    name="AWS Access Key ID",
    pattern=re.compile(r"(?:AKIA|ASIA)(?P<body>[0-9A-Z]{16})\b"),
    id="aws-access-key-id",
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
#   (ghp|gho|ghu|ghs|ghr)  ONE of these five prefixes. The | means "or",
#                          and the brackets group the choices together.
#   _                      a literal underscore.
#   (?P<body>...)          the "body" group (see the AWS rule): the 36
#                          characters after the prefix.
#   [0-9a-zA-Z]            one digit, lowercase letter, or capital letter...
#   {36}                   ...repeated exactly 36 times.
#   \b                     word boundary: the token must end here.
GITHUB_TOKEN = Rule(
    name="GitHub Token",
    pattern=re.compile(r"(ghp|gho|ghu|ghs|ghr)_(?P<body>[0-9a-zA-Z]{36})\b"),
    id="github-token",
)


# ---------------------------------------------------------------------------
# GitHub fine-grained personal access token
# ---------------------------------------------------------------------------
# GitHub's newer kind of token, which can be limited to specific repos.
# Real example shape: github_pat_ followed by 82 more characters, which are
# letters, digits, and underscores (it has an underscore in the middle).
#
# The pattern, piece by piece:
#   github_pat_     the exact text "github_pat_".
#   [0-9a-zA-Z_]    one letter, digit, or underscore...
#   {82}            ...repeated exactly 82 times.
#   \b              word boundary: the token must end here.
#
# No body group: the part after the prefix is made of two pieces joined by
# an underscore, so "the body" isn't one simple run of characters. We don't
# guess, so placeholder checks don't apply to this rule.
GITHUB_FINE_GRAINED_TOKEN = Rule(
    name="GitHub Fine-Grained Token",
    pattern=re.compile(r"github_pat_[0-9a-zA-Z_]{82}\b"),
    id="github-fine-grained-token",
)


# ---------------------------------------------------------------------------
# Slack token
# App-level xapp- tokens: https://docs.slack.dev/authentication/tokens/
# ---------------------------------------------------------------------------
# Real example shape: xoxb-<numbers>-<numbers>-<letters and digits>
# (the length varies).
# The letter after "xox" tells you what kind of token it is:
#   b = bot token, p = user token, a / r / s = other kinds of Slack tokens.
#
# The pattern, piece by piece:
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
#
# No body group: a Slack token has several dash-separated parts, so there
# isn't one simple body to check for placeholders.
SLACK_TOKEN = Rule(
    name="Slack Token",
    pattern=re.compile(r"(?:xox[abprs]-[0-9A-Za-z-]{10,}|xapp-[0-9]+-[0-9A-Za-z]+-[0-9]+-[0-9A-Za-z]+)"),
    id="slack-token",
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
#   (?:sk|rk)_live_  live secret keys or restricted keys (rk).
#   (?P<body>...)  the "body" group (see the AWS rule): everything after
#                  the prefix.
#   [0-9a-zA-Z]    one digit or letter...
#   {24,}          ...repeated 24 OR MORE times. Older keys have exactly 24;
#                  newer ones are longer, so "at least 24" catches both.
STRIPE_LIVE_SECRET_KEY = Rule(
    name="Stripe Live Secret Key",
    pattern=re.compile(r"(?:sk|rk)_live_(?P<body>[0-9a-zA-Z]{24,})"),
    id="stripe-live-secret-key",
)


# ---------------------------------------------------------------------------
# Google API key
# ---------------------------------------------------------------------------
# Real example shape: AIza followed by 35 more characters (39 total).
# Used for Google Maps, YouTube, Firebase, and other Google services.
#
# The pattern, piece by piece:
#   AIza             the exact text "AIza" (note the lowercase "z" and "a").
#   (?P<body>...)    the "body" group (see the AWS rule): the 35
#                    characters after the prefix.
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
    pattern=re.compile(r"AIza(?P<body>[0-9A-Za-z_-]{35})"),
    id="google-api-key",
)


# ---------------------------------------------------------------------------
# Anthropic API key
# ---------------------------------------------------------------------------
# Real example shape: sk-ant- followed by a long run of letters, digits,
# dashes, and underscores (e.g. sk-ant-api03-<about 95 more characters>).
#
# The pattern, piece by piece:
#   sk-ant-         the exact text "sk-ant-" ("sk" = secret key, "ant" =
#                   Anthropic).
#   [0-9A-Za-z_-]   one digit, letter, underscore, or dash...
#   {32,}           ...repeated 32 OR MORE times. Real keys are much longer;
#                   "at least 32" is enough to skip short placeholder text
#                   like "sk-ant-xxxx" in documentation.
#
# No body group: real keys contain more parts after "sk-ant-" (such as
# "api03-"), so there isn't one simple body to check for placeholders.
ANTHROPIC_API_KEY = Rule(
    name="Anthropic API Key",
    pattern=re.compile(r"sk-ant-[0-9A-Za-z_-]{32,}"),
    id="anthropic-api-key",
)


# ---------------------------------------------------------------------------
# OpenAI API key
# ---------------------------------------------------------------------------
# Real example shapes:
#   sk-<48 letters and digits>                       (older keys)
#   sk-proj-<long run of letters, digits, _ and ->   (newer project keys)
#
# The first lookahead checks body length without consuming it. This lets
# both alternatives share the named body group for placeholder detection:
# - proj-/svcacct- prefixes allow 32+ letters, digits, dashes, underscores.
# - legacy keys require exactly 48 letters/digits, followed by a delimiter.
# Ordinary hyphenated words and sk-ant- tokens fit neither alternative.
OPENAI_API_KEY = Rule(
    name="OpenAI API Key",
    pattern=re.compile(
        r"sk-(?:(?:proj|svcacct)-(?=[0-9A-Za-z_-]{32,}(?![0-9A-Za-z_-]))"
        r"|(?=[0-9A-Za-z]{48}(?![0-9A-Za-z_-])))(?P<body>[0-9A-Za-z_-]+)"
    ),
    id="openai-api-key",
)


# ---------------------------------------------------------------------------
# Private key block
# ---------------------------------------------------------------------------
# Private keys (used for SSH logins, HTTPS certificates, signing, etc.) are
# stored as a block of text that starts with a header line: five dashes,
# the word BEGIN, the kind of key, the words PRIVATE KEY, and five more
# dashes. The kind of key varies: RSA, EC, DSA, OPENSSH, ENCRYPTED, PGP,
# or nothing at all.
#
# Finding just the header line is enough: if it's in a file, the secret key
# itself is on the lines right below it.
#
# (This comment describes the header in words on purpose. Writing out a
# real-looking header here would make secretscan flag its own source code!)
#
# The pattern, piece by piece:
#   -----        five literal dashes.
#   BEGIN        the exact word "BEGIN".
#   [A-Z ]*      any number of capital letters and spaces, INCLUDING NONE
#                (that's what * means: "zero or more"). This covers the
#                kind of key, like " RSA " or " OPENSSH ", or just " ".
#   PRIVATE KEY  the exact words "PRIVATE KEY".
#
# No \b at the start: the pattern begins with a dash, and \b only works
# next to letters and digits (see the Google rule for why).
# Public keys and certificates ("BEGIN PUBLIC KEY", "BEGIN CERTIFICATE") are
# meant to be shared, so they don't match: they don't contain "PRIVATE KEY".
#
# No body group: the match is only the header line, never the key itself,
# so there's nothing to check for placeholders. PuTTY v2/v3 headers are
# recognized by their file-format prefix too.
PRIVATE_KEY = Rule(
    name="Private Key",
    pattern=re.compile(r"(?:-----BEGIN[A-Z ]*PRIVATE KEY|PuTTY-User-Key-File-[23]:)"),
    id="private-key",
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
    ANTHROPIC_API_KEY,
    OPENAI_API_KEY,
    PRIVATE_KEY,
]
