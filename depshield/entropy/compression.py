"""Compression-ratio analysis (Kolmogorov complexity approximation)."""
from __future__ import annotations

import zlib


def compression_ratio(data: str | bytes) -> float:
    """Return the zlib compression ratio  len(compressed) / len(original).

    Lower values indicate more redundancy (normal code).
    Values close to 1.0 indicate high randomness (encrypted / obfuscated).

    Thresholds (empirical):
      typical source  : 0.20 u2013 0.45
      minified code   : 0.30 u2013 0.55
      obfuscated      : 0.55 u2013 0.75
      encrypted/random: 0.75 u2013 1.00+

    Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")

    original_len = len(data)
    if original_len == 0:
        return 0.0

    compressed = zlib.compress(data, level=9)
    return len(compressed) / original_len
