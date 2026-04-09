"""Tests for character-class distribution analysis."""
import pytest

from depshield.entropy.charclass import char_class_distribution, char_class_entropy


class TestCharClassDistribution:
    """Distribution fraction tests."""

    def test_empty_string_all_zero(self):
        dist = char_class_distribution("")
        assert all(v == 0.0 for v in dist.values())

    def test_all_lowercase(self):
        dist = char_class_distribution("abcdefghij")
        assert dist["lowercase"] == 1.0
        assert dist["uppercase"] == 0.0
        assert dist["digit"] == 0.0

    def test_all_digits(self):
        dist = char_class_distribution("0123456789")
        assert dist["digit"] == 1.0
        assert dist["lowercase"] == 0.0

    def test_all_uppercase(self):
        dist = char_class_distribution("ABCDEFGHIJ")
        assert dist["uppercase"] == 1.0
        assert dist["lowercase"] == 0.0

    def test_mixed_distribution(self):
        # 5 lower + 5 upper = 10 chars
        dist = char_class_distribution("abcdeABCDE")
        assert abs(dist["lowercase"] - 0.5) < 0.01
        assert abs(dist["uppercase"] - 0.5) < 0.01

    def test_hex_heavy_distribution(self):
        # Pure hex chars: 0-9, a-f
        data = "0123456789abcdef" * 10
        dist = char_class_distribution(data)
        assert dist["hex_alpha"] > 0.3
        assert dist["digit"] > 0.3

    def test_normal_js_balanced(self):
        code = "var x = 1; function hello() { return 'world'; }"
        dist = char_class_distribution(code)
        # Should have lowercase, whitespace, punctuation
        assert dist["lowercase"] > 0.3
        assert dist["whitespace"] > 0.1
        assert dist["punctuation"] > 0.05

    def test_fractions_sum_may_exceed_one(self):
        # hex_alpha overlaps with lowercase/uppercase, so sum > 1.0 is expected
        dist = char_class_distribution("abcdef123")
        # Just verify the individual values are in [0, 1]
        for v in dist.values():
            assert 0.0 <= v <= 1.0

    def test_whitespace_detection(self):
        dist = char_class_distribution("   \t\n")
        assert dist["whitespace"] == 1.0

    def test_punctuation_only(self):
        dist = char_class_distribution("!@#$%^&*()")
        assert dist["punctuation"] == 1.0


class TestCharClassEntropy:
    """Entropy across character classes."""

    def test_empty_returns_zero(self):
        assert char_class_entropy("") == 0.0

    def test_single_class_low_entropy(self):
        h = char_class_entropy("aaaaaaa")
        # Only lowercase class represented, but hex_alpha also matches a-f
        # so entropy might not be exactly 0
        assert h < 1.5

    def test_mixed_classes_higher_entropy(self):
        mixed = "abcABC123!@# \t"
        h = char_class_entropy(mixed)
        single = char_class_entropy("aaaaaa")
        assert h > single

    def test_non_negative(self):
        for s in ["", "a", "Test 123!", "0xdeadbeef"]:
            assert char_class_entropy(s) >= 0.0
