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
from dataclasses import dataclass, replace


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
    # A separate `secret` group extracts just the value of generic assignments;
    # all existing provider rules keep using their complete match.
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

    # A password assignment is strong context even for a predictable value.
    # Context variants share the generic rule's ID so existing dismissals work.
    password_assignment: bool = False


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
#   (?![0-9A-Z])  a "negative lookahead" (see the OpenAI rule): the next
#               character must NOT be another digit or capital letter, so a
#               longer string like AKIA + 20 characters doesn't match.
#               We deliberately don't use \b here: Python's \b also treats
#               "_" and letters like "中" as part of a word, so a key followed
#               by "_backup" or a Chinese character would be missed.
#
# The r"..." in front of the string means "raw string": Python leaves the
# backslashes alone, so \b reaches the regex engine as-is. Without the r,
# Python would turn \b into a "backspace" character and the pattern would break.
AWS_ACCESS_KEY_ID = Rule(
    name="AWS Access Key ID",
    pattern=re.compile(r"(?:AKIA|ASIA)(?P<body>[0-9A-Z]{16})(?![0-9A-Z])"),
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
# Refresh tokens (ghr_) are longer: GitHub's own revocation example has
# 76 characters after the prefix.
# https://docs.github.com/en/rest/credentials/revoke
#
# The pattern, piece by piece:
#   gh[pous]_            ghp_, gho_, ghu_, or ghs_ (an old-style ghs_ token;
#                        the new long ghs_ format has its own rule below)...
#   (?=[0-9a-zA-Z]{36}   ...then a "lookahead" checks, WITHOUT using up any
#   (?![0-9a-zA-Z]))     text, that exactly 36 letters/digits follow and
#                        that a 37th letter/digit does not.
#   |ghr_(?=[0-9a-zA-Z]{36,})  OR ghr_ followed by 36 or more.
#   (?P<body>[0-9a-zA-Z]+)     then the body itself: the run of letters and
#                        digits that the lookahead just checked.
# Checking the length in a lookahead lets both kinds share ONE body group
# (Python doesn't allow two groups with the same name).
GITHUB_TOKEN = Rule(
    name="GitHub Token",
    pattern=re.compile(
        r"(?:gh[pous]_(?=[0-9a-zA-Z]{36}(?![0-9a-zA-Z]))|ghr_(?=[0-9a-zA-Z]{36,}))"
        r"(?P<body>[0-9a-zA-Z]+)"
    ),
    id="github-token",
)


# ---------------------------------------------------------------------------
# GitHub App installation token (stateless format)
# https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out/
# ---------------------------------------------------------------------------
# Since October 2026 GitHub issues installation tokens shaped like
# ghs_<APP ID>_<JWT>, about 520 characters long. A JWT ("JSON Web Token") is
# three parts made of letters, digits, "_" and "-", joined by dots.
#
# The pattern, piece by piece:
#   ghs_                 the prefix.
#   [0-9]+_              the app's numeric ID, then an underscore.
#   [A-Za-z0-9_-]{10,}   the first JWT part (10 or more characters)...
#   \.                   ...a literal dot (a plain . would mean "any character")...
#   (repeated)           ...and the second and third parts the same way.
# No body group: the token has several parts, so placeholder checks don't apply.
GITHUB_APP_INSTALLATION_TOKEN = Rule(
    name="GitHub App Installation Token",
    pattern=re.compile(
        r"ghs_[0-9]+_[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    ),
    id="github-app-installation-token",
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
#   (?![0-9a-zA-Z_])  the next character must not be another token character
#                   (see the AWS rule for why this isn't \b).
#
# No body group: the part after the prefix is made of two pieces joined by
# an underscore, so "the body" isn't one simple run of characters. We don't
# guess, so placeholder checks don't apply to this rule.
GITHUB_FINE_GRAINED_TOKEN = Rule(
    name="GitHub Fine-Grained Token",
    pattern=re.compile(r"github_pat_[0-9a-zA-Z_]{82}(?![0-9a-zA-Z_])"),
    id="github-fine-grained-token",
)


# ---------------------------------------------------------------------------
# Slack token
# Token catalog (xoxb-, xoxp-, xapp-, xwfp-): https://docs.slack.dev/authentication/tokens/
# Rotating tokens (xoxe- refresh tokens, and access tokens that start with
# "xoxe." like xoxe.xoxb-1-...): https://docs.slack.dev/authentication/using-token-rotation/
# ---------------------------------------------------------------------------
# Real example shape: xoxb-<numbers>-<numbers>-<letters and digits>
# (the length varies).
# The letter after "xox" tells you what kind of token it is:
#   b = bot token, p = user token, e = refresh token,
#   a / r / s = other kinds of Slack tokens. xwfp- is a workflow token.
#
# The pattern, piece by piece:
#   (?:xoxe\.)?    an optional "xoxe." in front, which rotated tokens have.
#                  (? after a group means "zero or one time": optional.)
#   (?:xox[abeprs]|xwfp)  "xox" plus ONE of the letters a, b, e, p, r, s
#                  (a list of letters in square brackets means "any one of
#                  these"), OR "xwfp".
#   ...then a dash and 10 or more letters, digits, or dashes (below).
#   |xapp-...      OR an app-level token: "xapp-", a number, "-", letters and
#                  digits, "-", a number, "-", letters and digits.
#                  [0-9]+ means "one or more digits".
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
    pattern=re.compile(
        r"(?:xoxe\.)?(?:(?:xox[abeprs]|xwfp)-[0-9A-Za-z-]{10,}"
        r"|xapp-[0-9]+-[0-9A-Za-z]+-[0-9]+-[0-9A-Za-z]+)"
    ),
    id="slack-token",
)


# ---------------------------------------------------------------------------
# Stripe live secret key
# ---------------------------------------------------------------------------
# Real example shape: sk_live_ followed by 24 or more letters and digits.
#
# This rule is for LIVE keys, which move real money. Test keys have their
# own rule below, so each kind keeps its own ID and name.
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
# Stripe test secret key
# https://docs.stripe.com/keys
# ---------------------------------------------------------------------------
# Same shape as a live key, but "test" instead of "live". Test keys only work
# in Stripe's practice mode ("sandbox") with fake cards, so they can't move
# real money. They're still secrets: anyone holding one can read and change
# your sandbox data, and Stripe's docs list secret and restricted keys as
# "not safe to expose".
#
# The pattern is the live pattern with "test" in place of "live":
#   (?:sk|rk)_test_  a secret key (sk) or restricted key (rk) in test mode.
#   (?P<body>[0-9a-zA-Z]{24,})  24 or more letters and digits.
# (Publishable keys, pk_test_, are meant to be public, so they don't match.)
STRIPE_TEST_SECRET_KEY = Rule(
    name="Stripe Test Secret Key",
    pattern=re.compile(r"(?:sk|rk)_test_(?P<body>[0-9a-zA-Z]{24,})"),
    id="stripe-test-secret-key",
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
# The pattern, piece by piece:
#   sk-                    the exact text "sk-".
#   (?:proj-|svcacct-)?    an optional "proj-" or "svcacct-" part.
#   (?P<body>              the body group, which is ONE of three choices:
#     (?<=proj-)[...]{32,}     after "proj-": 32+ letters, digits, "_", "-".
#     |(?<=svcacct-)[...]{32,} after "svcacct-": the same.
#     |(?<=sk-)[0-9A-Za-z]{48}(?![0-9A-Za-z])
#                          straight after "sk-": exactly 48 letters/digits
#                          (an older key), not followed by a 49th.
#   )
# `(?<=...)` is a "lookbehind": it checks the text just BEFORE this point
# without using it up. Each choice only applies after the right prefix, so
# all three can share one body group for placeholder detection.
# The older keys never contain "-", so a key followed by "-suffix" still
# matches, while "sk-ant-..." (Anthropic) and ordinary hyphenated words like
# "sk-hynix-..." fit none of the choices.
OPENAI_API_KEY = Rule(
    name="OpenAI API Key",
    pattern=re.compile(
        r"sk-(?:proj-|svcacct-)?(?P<body>(?<=proj-)[0-9A-Za-z_-]{32,}"
        r"|(?<=svcacct-)[0-9A-Za-z_-]{32,}"
        r"|(?<=sk-)[0-9A-Za-z]{48}(?![0-9A-Za-z]))"
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


# Generic assignments have no provider prefix to identify them. Match a
# selected variable/property name and a quoted literal, then let scanner.py
# check the VALUE's context, length, and entropy. The named `secret` group deliberately
# excludes the variable name, assignment operator, and surrounding quotes.
#
# (?<![\w-]) prevents starting halfway through an identifier.
# key_quote and its backreference allow password, "password", or 'password'.
# Prefix segments allow names like database_password or MY_CLIENT_SECRET.
# [ \t] keeps the entire assignment on one physical line.
# =(?![=]) rejects equality comparisons such as password == "...".
# value_quote and its backreference require matching opening/closing quotes.
# Inside the value, a backslash consumes the next character as one pair; the
# other alternative consumes one non-backslash character unless it ends the
# string. This handles escaped quotes without crossing a line boundary.
GENERIC_SECRET = Rule(
    name="Generic Password or Secret",
    pattern=re.compile(
        r"(?<![\w-])(?P<key_quote>[\"']?)"
        r"(?:[a-z0-9]+[_-])*"
        r"(?:(?P<password_name>password|passwd|pwd)|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        r"(?P=key_quote)[ \t]*(?::|=(?!=))[ \t]*"
        r"(?P<value_quote>[\"'])(?P<secret>(?:\\[^\r\n]|(?!(?P=value_quote))[^\\\r\n])*)"
        r"(?P=value_quote)",
        re.IGNORECASE,
    ),
    id="generic-secret",
)


# These are labels for matches of GENERIC_SECRET, not extra regex passes.
# `replace` copies the frozen dataclass while changing selected fields. Keep
# the same ID and pattern so adding weak-password coverage does not invalidate
# previously reviewed generic-password findings.
PASSWORD_ASSIGNMENT = replace(
    GENERIC_SECRET, name="Hard-coded Password", password_assignment=True,
)
WEAK_PASSWORD_ASSIGNMENT = replace(
    PASSWORD_ASSIGNMENT, name="Possible Weak Password or Placeholder",
)


# Every rule the scanner uses. The scanner loops over this list, so adding
# a new rule here is all it takes for it to be checked.
RULES = [
    AWS_ACCESS_KEY_ID,
    GITHUB_TOKEN,
    GITHUB_APP_INSTALLATION_TOKEN,
    GITHUB_FINE_GRAINED_TOKEN,
    SLACK_TOKEN,
    STRIPE_LIVE_SECRET_KEY,
    STRIPE_TEST_SECRET_KEY,
    GOOGLE_API_KEY,
    ANTHROPIC_API_KEY,
    OPENAI_API_KEY,
    PRIVATE_KEY,
    GENERIC_SECRET,
]
