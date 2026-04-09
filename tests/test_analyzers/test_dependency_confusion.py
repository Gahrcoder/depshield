"""Tests for dependency confusion analyzer."""
from __future__ import annotations

import os
import tempfile

import pytest

from depshield.analyzers.dependency_confusion import DependencyConfusionAnalyzer
from depshield.core.models import FindingCategory, Severity
from tests.conftest import make_package


class TestNoNpmrc:
    """Tests without .npmrc configuration."""

    def test_scoped_package_no_registry_flagged(self, tmp_path):
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(name="@internal/utils")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.DEPENDENCY_CONFUSION

    def test_unscoped_package_not_flagged(self, tmp_path):
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(name="lodash")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_multiple_scoped_packages(self, tmp_path):
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        for scope in ["@company/auth", "@company/logger", "@myorg/shared"]:
            pkg = make_package(name=scope)
            findings = analyzer.analyze(pkg)
            assert len(findings) >= 1


class TestWithNpmrc:
    """Tests with .npmrc containing private registry."""

    def test_scoped_with_private_registry_not_flagged(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("@internal:registry=https://npm.internal.example.com\n")
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(name="@internal/utils")
        findings = analyzer.analyze(pkg)
        # Should not flag scope warning since private registry configured
        scope_findings = [
            f for f in findings
            if "no private registry" in f.title
        ]
        assert len(scope_findings) == 0

    def test_scoped_resolved_from_public_despite_private_config(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("@internal:registry=https://npm.internal.example.com\n")
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(
            name="@internal/utils",
            resolved_url="https://registry.npmjs.org/@internal/utils/-/utils-1.0.0.tgz",
        )
        findings = analyzer.analyze(pkg)
        assert any("public registry" in f.title.lower() for f in findings)

    def test_http_registry_url_in_resolved(self, tmp_path):
        """HTTP resolved URLs are flagged by the metadata analyzer, not confusion.
        But we verify confusion doesn't crash on them."""
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(
            name="@corp/shared",
            resolved_url="http://insecure.example.com/shared-1.0.0.tgz",
        )
        findings = analyzer.analyze(pkg)
        # Should still flag the scope issue
        assert any(f.category == FindingCategory.DEPENDENCY_CONFUSION for f in findings)


class TestSeverity:
    """Severity classification tests."""

    def test_scope_no_registry_is_medium(self, tmp_path):
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(name="@internal/auth")
        findings = analyzer.analyze(pkg)
        scope_findings = [f for f in findings if "no private registry" in f.title]
        for f in scope_findings:
            assert f.severity == Severity.MEDIUM

    def test_public_resolution_is_high(self, tmp_path):
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("@corp:registry=https://npm.corp.example.com\n")
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(
            name="@corp/core",
            resolved_url="https://registry.npmjs.org/@corp/core/-/core-1.0.0.tgz",
        )
        findings = analyzer.analyze(pkg)
        public_findings = [f for f in findings if "public registry" in f.title.lower()]
        for f in public_findings:
            assert f.severity == Severity.HIGH
