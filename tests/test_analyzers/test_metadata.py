"""Tests for metadata anomaly analyzer."""
from __future__ import annotations

import pytest

from depshield.analyzers.metadata import MetadataAnalyzer
from depshield.core.models import FindingCategory, Severity
from tests.conftest import LEGITIMATE_DIR, fixture_to_package, make_package


@pytest.fixture
def analyzer():
    return MetadataAnalyzer()


class TestMissingFields:
    """Missing metadata detection."""

    def test_missing_description_flagged(self, analyzer):
        pkg = make_package(name="no-desc", description="")
        findings = analyzer.analyze(pkg)
        assert any("description" in f.title.lower() for f in findings)

    def test_short_description_flagged(self, analyzer):
        pkg = make_package(name="short", description="test")
        findings = analyzer.analyze(pkg)
        assert any("short" in f.title.lower() for f in findings)

    def test_no_repository_flagged(self, analyzer):
        pkg = make_package(name="no-repo", repository=None)
        findings = analyzer.analyze(pkg)
        assert any("repository" in f.title.lower() for f in findings)

    def test_no_author_flagged(self, analyzer):
        pkg = make_package(name="no-author", author=None)
        findings = analyzer.analyze(pkg)
        assert any("author" in f.title.lower() for f in findings)

    def test_no_integrity_flagged(self, analyzer):
        pkg = make_package(name="no-integrity")
        findings = analyzer.analyze(pkg)
        assert any("integrity" in f.title.lower() for f in findings)


class TestEarlyVersionWithHooks:
    """Version 0.0.x with install scripts is suspicious."""

    def test_version_001_with_postinstall_flagged(self, analyzer):
        pkg = make_package(
            name="new-pkg",
            version="0.0.1",
            scripts={"postinstall": "node malicious.js"},
        )
        findings = analyzer.analyze(pkg)
        assert any(
            f.severity == Severity.HIGH and "version" in f.title.lower()
            for f in findings
        )

    def test_version_010_with_install_flagged(self, analyzer):
        pkg = make_package(
            name="new-pkg",
            version="0.1.0",
            scripts={"install": "node setup.js"},
        )
        findings = analyzer.analyze(pkg)
        assert any("version" in f.title.lower() for f in findings)

    def test_stable_version_with_hooks_not_flagged_for_version(self, analyzer):
        pkg = make_package(
            name="stable",
            version="2.1.0",
            scripts={"postinstall": "node setup.js"},
        )
        findings = analyzer.analyze(pkg)
        version_findings = [f for f in findings if "version" in f.title.lower() and "install" in f.title.lower()]
        assert len(version_findings) == 0


class TestResolvedURLs:
    """Suspicious resolved URL detection."""

    def test_http_resolved_flagged(self, analyzer):
        pkg = make_package(
            name="insecure",
            resolved_url="http://registry.example.com/pkg.tgz",
        )
        findings = analyzer.analyze(pkg)
        assert any("HTTP" in f.title or "http" in f.title.lower() for f in findings)

    def test_ip_resolved_flagged(self, analyzer):
        pkg = make_package(
            name="ip-pkg",
            resolved_url="https://10.0.0.1:8080/pkg.tgz",
        )
        findings = analyzer.analyze(pkg)
        assert any("IP" in f.title for f in findings)


class TestNormalPackages:
    """Well-formed packages should not trigger high-severity findings."""

    def test_express_normal(self, analyzer):
        pkg = fixture_to_package(LEGITIMATE_DIR / "express.json")
        findings = analyzer.analyze(pkg)
        high_findings = [f for f in findings if f.severity >= Severity.HIGH]
        assert len(high_findings) == 0

    def test_react_normal(self, analyzer):
        pkg = fixture_to_package(LEGITIMATE_DIR / "react.json")
        findings = analyzer.analyze(pkg)
        high_findings = [f for f in findings if f.severity >= Severity.HIGH]
        assert len(high_findings) == 0
