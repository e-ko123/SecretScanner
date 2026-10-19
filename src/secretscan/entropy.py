"""Measure character variety for the generic secret rule, using only the stdlib.

This is Shannon entropy in bits per character, not a password-strength test.
It counts character frequencies; it does not understand words or their order.
Provider-shaped credentials and explicit password assignments bypass this gate.
"""
from collections import Counter
from math import log2

# Starting cutoffs for broader generic assignments (not password names). Twelve different characters have
# entropy log2(12), about 3.58. Requiring both length and variety reduces noise,
# but weak real passwords can still be missed. These are heuristics, not proof.
MIN_SECRET_LENGTH = 12
MIN_SECRET_ENTROPY = 3.5


def shannon_entropy(value: str) -> float:
    """Return -sum(p * log2(p)) over each distinct character's frequency p."""
    if not value:
        # An empty string has no characters to count; avoid division by zero.
        return 0.0

    # Counter makes a dictionary of character -> number of appearances.
    # Only present characters are counted, so log2 never receives zero.
    score = 0.0
    for count in Counter(value).values():
        probability = count / len(value)
        score -= probability * log2(probability)
    return score
