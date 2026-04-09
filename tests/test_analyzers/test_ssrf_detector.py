"""Tests for the SSRF detector."""
from __future__ import annotations

import os

import pytest

from depshield.analyzers.ssrf_detector import SSRFDetector
from depshield.core.models import FindingCategory, Severity


@pytest.fixture
def analyzer():
    return SSRFDetector()


# ------------------------------------------------------------------ #
# Unvalidated fetch detection                                         #
# ------------------------------------------------------------------ #

class TestUnvalidatedFetch:
    """Detect fetch/axios/http.request with unvalidated URLs."""

    def test_fetch_with_variable_url(self, analyzer):
        code = 'const resp = await fetch(userUrl);'
        findings = analyzer.analyze_file(code, "proxy.js")
        assert len(findings) >= 1
        assert any("unvalidated" in f.title.lower() or "fetch" in f.title.lower() for f in findings)

    def test_fetch_with_literal_url_not_flagged(self, analyzer):
        code = 'const resp = await fetch("https://api.example.com/data");'
        findings = analyzer.analyze_file(code, "client.js")
        fetch_findings = [f for f in findings if "unvalidated" in f.title.lower()]
        assert len(fetch_findings) == 0

    def test_http_request_with_variable(self, analyzer):
        code = 'const req = https.request(targetUrl, callback);'
        findings = analyzer.analyze_file(code, "proxy.js")
        assert len(findings) >= 1

    def test_unvalidated_fetch_is_high_severity(self, analyzer):
        code = 'const resp = await fetch(url);'
        findings = analyzer.analyze_file(code, "handler.js")
        high_findings = [f for f in findings if "unvalidated" in f.title.lower()]
        assert all(f.severity == Severity.HIGH for f in high_findings)


# ------------------------------------------------------------------ #
# URL concatenation / proxy patterns                                  #
# ------------------------------------------------------------------ #

class TestUrlConcatenation:
    """Detect URL concatenation with user input."""

    def test_string_concat_with_url(self, analyzer):
        code = 'const target = "http://internal-api/" + req.params.path;'
        findings = analyzer.analyze_file(code, "proxy.js")
        assert any("concatenation" in f.title.lower() for f in findings)

    def test_template_literal_url(self, analyzer):
        code = 'const url = `https://api.internal/${endpoint}`;'
        findings = analyzer.analyze_file(code, "proxy.js")
        assert any("concatenation" in f.title.lower() for f in findings)


# ------------------------------------------------------------------ #
# Missing validation checks                                           #
# ------------------------------------------------------------------ #

class TestIncompleteValidation:
    """Detect incomplete SSRF protection."""

    def test_validation_without_dns_rebinding(self, analyzer):
        code = """const url = new URL(input);
if (url.hostname === 'allowed.com') {
    const resp = await fetch(url);
}"""
        findings = analyzer.analyze_file(code, "proxy.js")
        dns_findings = [f for f in findings if "dns rebinding" in f.title.lower()]
        assert len(dns_findings) >= 1

    def test_incomplete_validation_is_medium(self, analyzer):
        code = """const url = new URL(input);
const resp = await fetch(url);"""
        findings = analyzer.analyze_file(code, "handler.js")
        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) >= 1


# ------------------------------------------------------------------ #
# False positive prevention                                           #
# ------------------------------------------------------------------ #

class TestFalsePositives:
    """Ensure properly validated code is not flagged for unvalidated fetch."""

    def test_validated_fetch_fixture(self, analyzer):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "ssrf", "validated_fetch.js"
        )
        with open(fixture) as f:
            content = f.read()
        findings = analyzer.analyze_file(content, fixture)
        # Should not have unvalidated fetch findings (may have informational ones)
        unvalidated = [f for f in findings if "unvalidated" in f.title.lower()]
        assert len(unvalidated) == 0

    def test_unvalidated_fixture_flagged(self, analyzer):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "ssrf", "unvalidated_fetch.js"
        )
        with open(fixture) as f:
            content = f.read()
        findings = analyzer.analyze_file(content, fixture)
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# Category validation                                                 #
# ------------------------------------------------------------------ #

class TestCategory:
    """Verify finding category."""

    def test_all_findings_have_correct_category(self, analyzer):
        code = 'const resp = await fetch(url);'
        findings = analyzer.analyze_file(code, "proxy.js")
        for f in findings:
            assert f.category == FindingCategory.SSRF
