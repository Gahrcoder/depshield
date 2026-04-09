"""Tests for Shannon entropy calculations."""
import math
import string

import pytest

from depshield.entropy.shannon import (
    EntropyCategory,
    entropy_category,
    shannon_entropy,
)


class TestShannonEntropy:
    """Core entropy calculation tests."""

    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert shannon_entropy("a") == 0.0

    def test_single_char_repeated_returns_zero(self):
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_two_equal_chars_returns_one_bit(self):
        # "ab" has 2 unique chars, each with p=0.5 => H = 1.0
        assert abs(shannon_entropy("ab") - 1.0) < 0.01

    def test_four_equal_chars_returns_two_bits(self):
        # "abcd" each p=0.25 => H = 2.0
        assert abs(shannon_entropy("abcd") - 2.0) < 0.01

    def test_all_unique_ascii_max_entropy(self):
        data = string.printable
        h = shannon_entropy(data)
        max_h = math.log2(len(set(data)))
        assert abs(h - max_h) < 0.01

    def test_biased_distribution_lower_than_max(self):
        # "aaab" => 3/4 'a', 1/4 'b' => H = 0.811
        h = shannon_entropy("aaab")
        assert 0.75 < h < 0.85

    def test_normal_english_text_range(self):
        text = (
            "The quick brown fox jumps over the lazy dog. "
            "Pack my box with five dozen liquor jugs. "
            "How vexingly quick daft zebras jump."
        )
        h = shannon_entropy(text)
        assert 3.5 <= h <= 5.0, f"English text entropy {h} outside expected range"

    def test_normal_js_code_range(self):
        # Use a longer, more realistic sample without leading whitespace
        code = (
            "function fibonacci(n){if(n<=1)return n;let a=0,b=1;"
            "for(let i=2;i<=n;i++){let temp=a+b;a=b;b=temp;}return b;}"
            "function factorial(n){if(n<=1)return 1;return n*factorial(n-1);}"
            "const arr=[1,2,3,4,5];const sum=arr.reduce((a,b)=>a+b,0);"
            "console.log('Result:',fibonacci(10),factorial(6),sum);"
        )
        h = shannon_entropy(code)
        assert 4.0 <= h <= 5.5, f"JS code entropy {h} outside expected range"

    def test_base64_string_high_entropy(self):
        import base64
        b64 = base64.b64encode(bytes(range(256))).decode()
        h = shannon_entropy(b64)
        assert h >= 5.5, f"Base64 entropy {h} should be >= 5.5"

    def test_random_bytes_very_high_entropy(self):
        import os
        data = os.urandom(1024).hex()
        h = shannon_entropy(data)
        assert h >= 3.5, f"Random hex entropy {h} should be >= 3.5"

    def test_entropy_increases_with_uniqueness(self):
        h1 = shannon_entropy("aaa")
        h2 = shannon_entropy("abc")
        h3 = shannon_entropy("abcdefgh")
        assert h1 < h2 <= h3

    def test_entropy_symmetric(self):
        # Entropy is a property of the distribution, not order
        assert shannon_entropy("abcabc") == shannon_entropy("aabbcc")

    def test_long_uniform_string(self):
        data = (string.ascii_lowercase * 100)
        h = shannon_entropy(data)
        expected = math.log2(26)
        assert abs(h - expected) < 0.01

    def test_binary_string(self):
        data = "01" * 500
        h = shannon_entropy(data)
        assert abs(h - 1.0) < 0.01

    def test_entropy_non_negative(self):
        for s in ["", "a", "ab", "aaabbb", "random_text_here"]:
            assert shannon_entropy(s) >= 0.0


class TestEntropyCategory:
    """Classification threshold tests."""

    def test_empty_is_low(self):
        assert entropy_category("") == EntropyCategory.LOW

    def test_repeated_char_is_low(self):
        assert entropy_category("aaaaaaaaaa") == EntropyCategory.LOW

    def test_normal_code_is_normal(self):
        code = "function hello() { return 'Hello World!'; }" * 5
        cat = entropy_category(code)
        assert cat in (EntropyCategory.NORMAL, EntropyCategory.LOW)

    def test_highly_random_is_obfuscated(self):
        import os
        data = os.urandom(512).hex()
        # hex only has 16 chars, extend alphabet
        data2 = "".join(chr(b % 95 + 32) for b in os.urandom(512))
        cat = entropy_category(data2)
        assert cat in (
            EntropyCategory.ELEVATED,
            EntropyCategory.SUSPICIOUS,
            EntropyCategory.OBFUSCATED,
        )

    def test_category_ordering(self):
        cats = list(EntropyCategory)
        assert cats[0] == EntropyCategory.LOW
        assert cats[-1] == EntropyCategory.OBFUSCATED
