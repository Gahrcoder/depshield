"""N-gram entropy and uniformity analysis."""
from __future__ import annotations

import math
from collections import Counter


def _ngram_counts(data: str, n: int) -> Counter:
    """Count overlapping n-grams in data."""
    c: Counter = Counter()
    for i in range(len(data) - n + 1):
        c[data[i : i + n]] += 1
    return c


def _ngram_entropy(data: str, n: int) -> float:
    """Shannon entropy over n-gram distribution."""
    if len(data) < n:
        return 0.0

    counts = _ngram_counts(data, n)
    total = sum(counts.values())
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def bigram_entropy(data: str) -> float:
    """Shannon entropy over character bigrams.

    Normal source: 6 - 9 bits
    Obfuscated:    10 - 13 bits
    Random:        13+ bits
    """
    return _ngram_entropy(data, 2)


def trigram_entropy(data: str) -> float:
    """Shannon entropy over character trigrams.

    Higher values indicate more uniform (random) trigram distribution.
    """
    return _ngram_entropy(data, 3)


def ngram_uniformity(data: str, n: int = 2) -> float:
    """How close the n-gram distribution is to uniform.

    Returns a value in [0, 1] where 1.0 = perfectly uniform (random)
    and 0.0 = completely dominated by one n-gram.

    Calculated as actual_entropy / max_possible_entropy.
    """
    if len(data) < n:
        return 0.0

    actual = _ngram_entropy(data, n)
    sum(_ngram_counts(data, n).values())
    unique = len(_ngram_counts(data, n))

    if unique <= 1:
        return 0.0

    max_entropy = math.log2(unique)
    if max_entropy == 0:
        return 0.0

    return min(actual / max_entropy, 1.0)
