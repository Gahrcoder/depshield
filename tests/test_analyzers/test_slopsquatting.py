"""Tests for slopsquatting (LLM-hallucinated package name) analyzer."""
from __future__ import annotations

import pytest

from depshield.analyzers.slopsquatting import SlopsquattingAnalyzer
from depshield.core.models import FindingCategory, Severity
from tests.conftest import make_package


@pytest.fixture
def analyzer():
    return SlopsquattingAnalyzer()


class TestHallucinatedNameDetection:
    """Names matching LLM hallucination patterns should be flagged."""

    @pytest.mark.parametrize("name", [
        "react-utils",
        "express-middleware",
        "vue-helpers",
        "angular-service",
        "next-plugin",
        "webpack-adapter",
    ])
    def test_framework_utility_combo_flagged(self, analyzer, name):
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1, f"{name} should be flagged as slopsquat"
        assert findings[0].category == FindingCategory.SLOPSQUATTING

    def test_react_form_utils_flagged(self, analyzer):
        pkg = make_package(name="react-utils")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_express_auth_middleware_flagged(self, analyzer):
        pkg = make_package(name="express-middleware")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_severity_is_medium(self, analyzer):
        pkg = make_package(name="react-helpers")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.parametrize("name", [
        "easy-http",
        "simple-auth",
        "super-logger",
        "auto-deploy",
    ])
    def test_hype_prefix_flagged(self, analyzer, name):
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1, f"{name} should be flagged"


class TestRealPackagesNotFlagged:
    """Real popular packages must NOT be flagged."""

    @pytest.mark.parametrize("name", [
        "react", "express", "lodash", "webpack", "typescript",
        "axios", "moment", "chalk", "debug", "uuid",
    ])
    def test_real_package_not_flagged(self, analyzer, name):
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, f"{name} should NOT be flagged"
