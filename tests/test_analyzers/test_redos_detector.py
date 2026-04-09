"""Tests for the ReDoS detector."""
from __future__ import annotations

import os

import pytest

from depshield.analyzers.redos_detector import ReDoSDetector
from depshield.core.models import FindingCategory, Severity


@pytest.fixture
def analyzer():
    return ReDoSDetector()


# ------------------------------------------------------------------ #
# Dynamic RegExp detection                                            #
# ------------------------------------------------------------------ #

class TestDynamicRegExp:
    """Detect new RegExp() with user-controlled input."""

    def test_regexp_with_variable(self, analyzer):
        code = 'const re = new RegExp(userInput, "gi");'
        findings = analyzer.analyze_file(code, "search.js")
        assert len(findings) >= 1
        assert any("dynamic" in f.title.lower() or "regexp" in f.title.lower() for f in findings)

    def test_regexp_with_user_input_is_high(self, analyzer):
        code = """app.get('/search', (req, res) => {
    const query = req.query.q;
    const pattern = new RegExp(query, 'gi');
    res.json(results.filter(r => pattern.test(r)));
});"""
        findings = analyzer.analyze_file(code, "routes.js")
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_regexp_with_template_literal(self, analyzer):
        code = 'const re = new RegExp(`^${prefix}.*$`, "i");'
        findings = analyzer.analyze_file(code, "filter.js")
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# Nested quantifier detection                                         #
# ------------------------------------------------------------------ #

class TestNestedQuantifiers:
    """Detect regex patterns with nested quantifiers."""

    def test_nested_plus(self, analyzer):
        code = 'const re = /(a+)+$/;'
        findings = analyzer.analyze_file(code, "validator.js")
        assert len(findings) >= 1
        assert any("nested" in f.title.lower() for f in findings)

    def test_nested_star(self, analyzer):
        code = 'const re = /(a*)*b/;'
        findings = analyzer.analyze_file(code, "parser.js")
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# False positive prevention                                           #
# ------------------------------------------------------------------ #

class TestFalsePositives:
    """Ensure safe regex patterns are not flagged."""

    def test_static_literal_regex(self, analyzer):
        code = 'const re = /^[a-z0-9]+$/;'
        findings = analyzer.analyze_file(code, "utils.js")
        assert len(findings) == 0

    def test_escaped_regexp(self, analyzer):
        code = """const _ = require('lodash');
const escaped = _.escapeRegExp(input);
const re = new RegExp(escaped, 'i');"""
        findings = analyzer.analyze_file(code, "safe.js")
        assert len(findings) == 0

    def test_safe_fixture_not_flagged(self, analyzer):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "redos", "safe_regex.js"
        )
        with open(fixture) as f:
            content = f.read()
        findings = analyzer.analyze_file(content, fixture)
        assert len(findings) == 0

    def test_dynamic_fixture_flagged(self, analyzer):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "redos", "dynamic_regex.js"
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
        code = 'const re = new RegExp(input);'
        findings = analyzer.analyze_file(code, "search.js")
        for f in findings:
            assert f.category == FindingCategory.REDOS
