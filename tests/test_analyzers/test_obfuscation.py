"""Tests for obfuscation detection analyzer."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from depshield.analyzers.obfuscation import ObfuscationAnalyzer, _scan_content
from depshield.core.models import FindingCategory, Severity
from tests.conftest import OBFUSCATED_DIR, make_package


@pytest.fixture
def analyzer():
    return ObfuscationAnalyzer()


# ------------------------------------------------------------------ #
# Direct content scanning                                             #
# ------------------------------------------------------------------ #

class TestScanContent:
    """Low-level obfuscation pattern detection."""

    def test_base64_block_detected(self):
        # Threshold is 3: need 3+ base64 blocks of 40+ chars
        block = "A" * 60 + "=="
        content = f"var x='{block}';var y='{block}';var z='{block}';"
        hits = _scan_content(content)
        names = [h[0] for h in hits]
        assert any("Base64" in n for n in names)

    def test_base64_decode_detected(self):
        content = "var x = atob('aGVsbG8='); var y = atob('d29ybGQ='); var z = Buffer.from('test', 'base64');"
        hits = _scan_content(content)
        names = [h[0] for h in hits]
        assert any("Base64" in n for n in names)

    def test_hex_escape_detected(self):
        content = r'var s = "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21";'
        hits = _scan_content(content)
        names = [h[0] for h in hits]
        assert any("Hex" in n or "hex" in n for n in names)

    def test_hex_array_detected(self):
        content = "var a = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72];"
        hits = _scan_content(content)
        names = [h[0] for h in hits]
        assert any("Hex" in n or "hex" in n for n in names)

    def test_unicode_escape_detected(self):
        content = r'var s = "\u0048\u0065\u006c\u006c\u006f\u0020\u0057\u006f\u0072\u006c\u0064";'
        hits = _scan_content(content)
        names = [h[0] for h in hits]
        assert any("Unicode" in n or "unicode" in n for n in names)

    def test_string_concat_detected(self):
        # Threshold is 2: need 2+ occurrences of 6+ concatenated small strings
        content = (
            "var s = 'r' + 'e' + 'q' + 'u' + 'i' + 'r' + 'e';\n"
            "var t = 'c' + 'h' + 'i' + 'l' + 'd' + 'p' + 'r';\n"
        )
        hits = _scan_content(content)
        names = [h[0] for h in hits]
        assert any("concat" in n.lower() for n in names)

    def test_normal_code_not_detected(self):
        content = """
        function add(a, b) {
            return a + b;
        }
        const result = add(1, 2);
        console.log(result);
        """
        hits = _scan_content(content)
        assert len(hits) == 0


# ------------------------------------------------------------------ #
# Fixture file scanning via install scripts                           #
# ------------------------------------------------------------------ #

class TestObfuscationInScripts:
    """Obfuscation in install scripts."""

    def test_base64_in_postinstall(self, analyzer):
        pkg = make_package(
            name="sneaky",
            scripts={"postinstall": (
                "node -e \"var a=Buffer.from('cGF5bG9hZA==','base64').toString();"
                "var b=atob('dGVzdA==');eval(a)\""
            )}
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert all(f.category == FindingCategory.OBFUSCATION for f in findings)

    def test_hex_in_preinstall(self, analyzer):
        pkg = make_package(
            name="hex-pkg",
            scripts={"preinstall": 'node -e "var s=\\"\\x72\\x65\\x71\\x75\\x69\\x72\\x65\\x28\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73\\x29\\""'},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_clean_postinstall_not_flagged(self, analyzer):
        pkg = make_package(
            name="clean",
            scripts={"postinstall": "echo done"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0


# ------------------------------------------------------------------ #
# Source file scanning with fixtures                                  #
# ------------------------------------------------------------------ #

class TestObfuscatedFixtures:
    """Test against fixture JS files."""

    def test_multi_layer_base64_fixture(self):
        content = (OBFUSCATED_DIR / "multi_layer_base64.js").read_text()
        hits = _scan_content(content)
        assert len(hits) >= 1
        techniques = [h[0] for h in hits]
        assert any("Base64" in t for t in techniques)

    def test_hex_shellcode_fixture(self):
        content = (OBFUSCATED_DIR / "hex_shellcode.js").read_text()
        hits = _scan_content(content)
        assert len(hits) >= 1

    def test_string_array_rotation_fixture(self):
        content = (OBFUSCATED_DIR / "string_array_rotation.js").read_text()
        hits = _scan_content(content)
        assert len(hits) >= 1

    def test_normal_minified_not_flagged(self):
        """Legitimate minified code should NOT be flagged."""
        content = (OBFUSCATED_DIR / "normal_minified.js").read_text()
        hits = _scan_content(content)
        # Normal minified code should not trigger obfuscation
        # Allow at most very low severity hits from variable mangling
        high_hits = [h for h in hits if h[1] >= Severity.MEDIUM]
        assert len(high_hits) == 0, f"Minified code should not trigger MEDIUM+ findings: {high_hits}"
