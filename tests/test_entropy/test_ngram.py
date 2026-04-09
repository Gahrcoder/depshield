"""Tests for n-gram entropy and uniformity analysis."""
import os
import string

import pytest

from depshield.entropy.ngram import (
    bigram_entropy,
    ngram_uniformity,
    trigram_entropy,
)


class TestBigramEntropy:
    """Bigram (character pair) entropy tests."""

    def test_empty_string(self):
        assert bigram_entropy("") == 0.0

    def test_single_char(self):
        assert bigram_entropy("a") == 0.0

    def test_repeated_bigram_low(self):
        # "ababab" has only one unique bigram pattern
        h = bigram_entropy("ababababab")
        assert h < 2.0

    def test_english_text_moderate(self):
        text = (
            "The quick brown fox jumps over the lazy dog. "
            "Pack my box with five dozen liquor jugs."
        ) * 3
        h = bigram_entropy(text)
        assert 5.0 <= h <= 10.0, f"English bigram entropy {h} outside range"

    def test_random_hex_high(self):
        data = os.urandom(512).hex()
        h = bigram_entropy(data)
        assert h >= 4.0, f"Random hex bigram entropy {h} too low"

    def test_more_unique_bigrams_higher_entropy(self):
        simple = "aaa" * 50
        varied = string.ascii_lowercase * 10
        assert bigram_entropy(simple) < bigram_entropy(varied)

    def test_non_negative(self):
        for s in ["", "a", "ab", "random text here"]:
            assert bigram_entropy(s) >= 0.0


class TestTrigramEntropy:
    """Trigram entropy tests."""

    def test_empty_string(self):
        assert trigram_entropy("") == 0.0

    def test_short_string(self):
        assert trigram_entropy("ab") == 0.0

    def test_trigram_varies_with_data(self):
        # For cyclic data, trigram entropy may be slightly less than bigram
        # due to repeating patterns. Just verify both are reasonable.
        data = string.ascii_lowercase * 20
        assert trigram_entropy(data) > 3.0
        assert bigram_entropy(data) > 3.0


class TestNgramUniformity:
    """Uniformity score tests."""

    def test_empty_returns_zero(self):
        assert ngram_uniformity("") == 0.0

    def test_single_char_returns_zero(self):
        assert ngram_uniformity("a") == 0.0

    def test_repeated_low_uniformity(self):
        u = ngram_uniformity("aaaaaaa")
        assert u == 0.0 or u < 0.2

    def test_varied_text_moderate_uniformity(self):
        text = string.ascii_lowercase * 10
        u = ngram_uniformity(text)
        assert 0.5 <= u <= 1.0

    def test_uniformity_bounded_zero_one(self):
        for s in ["abcdefghij", "aaabbb", string.printable]:
            u = ngram_uniformity(s)
            assert 0.0 <= u <= 1.0

    def test_custom_n(self):
        data = string.ascii_lowercase * 10
        u2 = ngram_uniformity(data, n=2)
        u3 = ngram_uniformity(data, n=3)
        assert u2 > 0 and u3 > 0
