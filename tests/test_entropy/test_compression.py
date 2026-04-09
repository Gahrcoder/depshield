"""Tests for compression ratio analysis."""
import os
import string

import pytest

from depshield.entropy.compression import compression_ratio


class TestCompressionRatio:
    """Kolmogorov complexity approximation tests."""

    def test_empty_string_returns_zero(self):
        assert compression_ratio("") == 0.0

    def test_empty_bytes_returns_zero(self):
        assert compression_ratio(b"") == 0.0

    def test_repetitive_string_low_ratio(self):
        data = "a" * 10000
        ratio = compression_ratio(data)
        assert ratio < 0.05, f"Repetitive string ratio {ratio} should be very low"

    def test_random_string_high_ratio(self):
        data = os.urandom(4096)
        ratio = compression_ratio(data)
        assert ratio > 0.7, f"Random bytes ratio {ratio} should be high"

    def test_normal_code_moderate_ratio(self):
        code = """
        function processItems(items) {
            const results = [];
            for (const item of items) {
                if (item.active) {
                    results.push({
                        id: item.id,
                        name: item.name.trim(),
                        value: item.value * 1.1,
                    });
                }
            }
            return results;
        }
        """ * 10
        ratio = compression_ratio(code)
        assert 0.02 <= ratio <= 0.50, f"Normal code ratio {ratio} unexpected"

    def test_accepts_bytes_input(self):
        data = b"hello world " * 100
        ratio = compression_ratio(data)
        assert 0.0 < ratio < 0.2

    def test_accepts_string_input(self):
        data = "hello world " * 100
        ratio = compression_ratio(data)
        assert 0.0 < ratio < 0.2

    def test_ratio_always_positive_for_nonempty(self):
        for data in ["a", "ab", "test" * 100, os.urandom(128)]:
            assert compression_ratio(data) > 0.0

    def test_more_random_higher_ratio(self):
        repetitive = "abcd" * 1000
        random_data = os.urandom(4000).hex()
        assert compression_ratio(repetitive) < compression_ratio(random_data)

    def test_obfuscated_vs_normal(self):
        normal = "var x = 1; var y = 2; function add(a, b) { return a + b; }" * 20
        obfuscated = ''.join(
            f"\\x{b:02x}" for b in os.urandom(200)
        )
        r_normal = compression_ratio(normal)
        r_obfuscated = compression_ratio(obfuscated)
        assert r_normal < r_obfuscated

    def test_ratio_bounded(self):
        # Compression ratio for real data should be > 0 and typically < 1.1
        data = string.printable * 50
        ratio = compression_ratio(data)
        assert 0.0 < ratio < 1.5
