"""Tests for postMessage security analyzer."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from depshield.analyzers.postmessage import PostMessageAnalyzer
from depshield.core.models import FindingCategory, Severity
from tests.conftest import make_package

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "postmessage"


@pytest.fixture
def analyzer():
    return PostMessageAnalyzer()


def _read_fixture(name: str) -> str:
    """Read a JS fixture file and return its content."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


# ------------------------------------------------------------------ #
# Vulnerable listener (no origin check)                                #
# ------------------------------------------------------------------ #

class TestVulnerableListener:
    """Message handler without origin validation."""

    def test_listener_without_origin_check_is_critical_with_sensitive_data(
        self, analyzer
    ):
        content = _read_fixture("vulnerable_listener.js")
        findings = analyzer.analyze_file("vulnerable_listener.js", content, "test-pkg")
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.category == FindingCategory.NETWORK
        assert "origin" in f.title.lower()
        assert "sensitive" in f.description.lower() or "token" in f.evidence.lower()

    def test_listener_without_origin_check_is_high_without_sensitive_data(
        self, analyzer
    ):
        # A simple listener with no sensitive keywords
        content = '''window.addEventListener('message', function(e) {
            if (e.data.type === 'RESIZE') {
                document.body.style.height = e.data.height + 'px';
            }
        });'''
        findings = analyzer.analyze_file("resize_handler.js", content, "resize-pkg")
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.NETWORK


# ------------------------------------------------------------------ #
# Safe listener (with origin check)                                    #
# ------------------------------------------------------------------ #

class TestSafeListener:
    """Message handler WITH origin validation should produce no findings."""

    def test_listener_with_origin_check_no_finding(self, analyzer):
        content = _read_fixture("safe_listener.js")
        findings = analyzer.analyze_file("safe_listener.js", content, "safe-pkg")
        # Should have zero postMessage-listener findings
        listener_findings = [
            f for f in findings if "origin validation" in f.title.lower()
        ]
        assert len(listener_findings) == 0

    def test_event_origin_check_recognized(self, analyzer):
        content = '''window.addEventListener('message', function(event) {
            if (event.origin !== 'https://trusted.com') return;
            handleData(event.data);
        });'''
        findings = analyzer.analyze_file("origin_check.js", content, "safe-pkg")
        listener_findings = [
            f for f in findings if "origin validation" in f.title.lower()
        ]
        assert len(listener_findings) == 0

    def test_allowed_origins_check_recognized(self, analyzer):
        content = '''var allowedOrigins = ['https://a.com', 'https://b.com'];
        window.addEventListener('message', function(e) {
            if (!allowedOrigins.includes(e.origin)) return;
            process(e.data);
        });'''
        findings = analyzer.analyze_file("allowed.js", content, "safe-pkg")
        listener_findings = [
            f for f in findings if "origin validation" in f.title.lower()
        ]
        assert len(listener_findings) == 0


# ------------------------------------------------------------------ #
# Wildcard targetOrigin                                                #
# ------------------------------------------------------------------ #

class TestWildcardSend:
    """postMessage(data, '*') should be flagged."""

    def test_wildcard_postmessage_detected(self, analyzer):
        content = _read_fixture("wildcard_send.js")
        findings = analyzer.analyze_file("wildcard_send.js", content, "wild-pkg")
        wildcard_findings = [
            f for f in findings if "wildcard" in f.title.lower()
        ]
        assert len(wildcard_findings) >= 1
        f = wildcard_findings[0]
        assert f.severity == Severity.HIGH

    def test_specific_origin_postmessage_no_finding(self, analyzer):
        content = '''targetWindow.postMessage({type: 'ping'}, 'https://app.example.com');'''
        findings = analyzer.analyze_file("specific.js", content, "safe-pkg")
        wildcard_findings = [
            f for f in findings if "wildcard" in f.title.lower()
        ]
        assert len(wildcard_findings) == 0


# ------------------------------------------------------------------ #
# BroadcastChannel                                                     #
# ------------------------------------------------------------------ #

class TestBroadcastChannel:
    """BroadcastChannel without sender validation."""

    def test_broadcast_without_validation_detected(self, analyzer):
        content = _read_fixture("broadcast_no_validation.js")
        findings = analyzer.analyze_file(
            "broadcast_no_validation.js", content, "broadcast-pkg"
        )
        bc_findings = [
            f for f in findings if "broadcastchannel" in f.title.lower()
        ]
        assert len(bc_findings) >= 1
        f = bc_findings[0]
        assert f.severity == Severity.MEDIUM

    def test_broadcast_with_origin_check_no_finding(self, analyzer):
        content = '''var channel = new BroadcastChannel('sync');
        channel.onmessage = function(e) {
            if (e.origin !== expectedOrigin) return;
            update(e.data);
        };'''
        findings = analyzer.analyze_file("bc_safe.js", content, "safe-pkg")
        bc_findings = [
            f for f in findings if "broadcastchannel" in f.title.lower()
        ]
        assert len(bc_findings) == 0


# ------------------------------------------------------------------ #
# Privy-like cross-app pattern                                         #
# ------------------------------------------------------------------ #

class TestPrivyCrossApp:
    """Real-world Privy cross-app connect pattern."""

    def test_privy_cross_app_detected_as_critical(self, analyzer):
        content = _read_fixture("privy_cross_app.js")
        findings = analyzer.analyze_file(
            "privy_cross_app.js", content, "@privy-io/cross-app-connect"
        )
        assert len(findings) >= 1
        # Should be CRITICAL because it handles keys/secrets
        critical_findings = [
            f for f in findings if f.severity == Severity.CRITICAL
        ]
        assert len(critical_findings) >= 1
        f = critical_findings[0]
        assert "origin" in f.title.lower()
        assert f.package_name == "@privy-io/cross-app-connect"

    def test_privy_evidence_contains_listener(self, analyzer):
        content = _read_fixture("privy_cross_app.js")
        findings = analyzer.analyze_file(
            "privy_cross_app.js", content, "@privy-io/cross-app-connect"
        )
        listener_findings = [
            f for f in findings if "origin validation" in f.title.lower()
        ]
        assert len(listener_findings) >= 1
        assert "addEventListener" in listener_findings[0].evidence


# ------------------------------------------------------------------ #
# Metadata-only analyze() returns empty (deep scan handles files)      #
# ------------------------------------------------------------------ #

class TestMetadataOnly:
    """The analyze() method returns no findings (file scanning is separate)."""

    def test_analyze_returns_empty(self, analyzer):
        pkg = make_package(name="any-pkg")
        findings = analyzer.analyze(pkg)
        assert findings == []


# ------------------------------------------------------------------ #
# Edge cases                                                           #
# ------------------------------------------------------------------ #

class TestEdgeCases:
    """Boundary and edge-case coverage."""

    def test_empty_file_no_findings(self, analyzer):
        findings = analyzer.analyze_file("empty.js", "", "empty-pkg")
        assert findings == []

    def test_no_listener_no_finding(self, analyzer):
        content = 'console.log("hello world");'
        findings = analyzer.analyze_file("hello.js", content, "hello-pkg")
        assert findings == []

    def test_multiple_issues_in_one_file(self, analyzer):
        content = '''window.addEventListener('message', function(e) {
            var token = e.data.token;
            save(token);
        });
        parent.postMessage({result: 'done'}, "*");
        var ch = new BroadcastChannel('sync');
        ch.onmessage = function(e) { update(e.data); };
        '''
        findings = analyzer.analyze_file("multi.js", content, "multi-pkg")
        # Should find: listener without origin + wildcard send + broadcast
        assert len(findings) >= 3
        titles = [f.title.lower() for f in findings]
        assert any("origin validation" in t for t in titles)
        assert any("wildcard" in t for t in titles)
        assert any("broadcastchannel" in t for t in titles)
