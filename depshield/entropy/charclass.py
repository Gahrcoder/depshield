"""Character-class distribution analysis."""
from __future__ import annotations

import math
from typing import Dict


_CLASSES = {
    "lowercase": set("abcdefghijklmnopqrstuvwxyz"),
    "uppercase": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    "digit":     set("0123456789"),
    "hex_alpha": set("abcdefABCDEF"),
    "whitespace": set(" \t\n\r"),
    "punctuation": set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
}


def char_class_distribution(data: str) -> Dict[str, float]:
    """Return the fraction of characters in each class.

    Obfuscated payloads often skew heavily toward hex digits or
    base64 characters, while normal code has a balanced spread.
    """
    if not data:
        return {k: 0.0 for k in _CLASSES}

    length = len(data)
    result: Dict[str, float] = {}

    for name, charset in _CLASSES.items():
        count = sum(1 for ch in data if ch in charset)
        result[name] = count / length

    return result


def char_class_entropy(data: str) -> float:
    """Shannon entropy across character classes (not individual chars).

    Low values indicate the text is dominated by one class
    (e.g., all hex digits).
    """
    dist = char_class_distribution(data)
    non_zero = [v for v in dist.values() if v > 0]
    if not non_zero:
        return 0.0

    total = sum(non_zero)
    entropy = 0.0
    for frac in non_zero:
        p = frac / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
