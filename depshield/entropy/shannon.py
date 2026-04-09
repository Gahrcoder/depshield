"""Shannon entropy calculations."""
from __future__ import annotations

import math
from collections import Counter
from enum import Enum


class EntropyCategory(Enum):
    """Classification of entropy levels."""
    LOW = "low"             # structured / repetitive
    NORMAL = "normal"       # typical source code
    ELEVATED = "elevated"   # minified or dense code
    SUSPICIOUS = "suspicious"  # likely obfuscated
    OBFUSCATED = "obfuscated"  # almost certainly obfuscated / encrypted


# Empirical thresholds derived from analysis of npm packages.
_THRESHOLDS = {
    EntropyCategory.LOW:        (0.0, 3.5),
    EntropyCategory.NORMAL:     (3.5, 5.5),
    EntropyCategory.ELEVATED:   (5.5, 5.8),
    EntropyCategory.SUSPICIOUS: (5.8, 6.2),
    EntropyCategory.OBFUSCATED: (6.2, float("inf")),
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) for a string.

    H = -sum(p_i * log2(p_i)) for each unique character.

    Typical values:
      English prose : 3.5 - 4.5
      Source code   : 4.0 - 5.5
      Minified JS   : 5.0 - 5.5
      Obfuscated    : 5.8 - 6.2
      Random / enc. : 6.2+
    """
    if not data:
        return 0.0

    length = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def entropy_category(data: str) -> EntropyCategory:
    """Classify a string's entropy into a human-readable category."""
    h = shannon_entropy(data)
    for cat, (lo, hi) in _THRESHOLDS.items():
        if lo <= h < hi:
            return cat
    return EntropyCategory.OBFUSCATED  # safety fallback
