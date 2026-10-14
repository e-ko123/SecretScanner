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


# Every rule the scanner uses. The scanner loops over this list, so adding
# a new rule here is all it takes for it to be checked.
RULES = [
    AWS_ACCESS_KEY_ID,
]
