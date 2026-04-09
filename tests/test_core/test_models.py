"""Tests for core data models."""
from __future__ import annotations

import pytest

from depshield.core.models import (
    Finding,
    FindingCategory,
    PackageInfo,
    ScanResult,
    Severity,
)


class TestSeverity:
    """Severity enum and comparison tests."""

    def test_critical_highest(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.CRITICAL > Severity.MEDIUM
        assert Severity.CRITICAL > Severity.LOW
        assert Severity.CRITICAL > Severity.INFO

    def test_info_lowest(self):
        assert Severity.INFO < Severity.LOW
        assert Severity.INFO < Severity.MEDIUM
        assert Severity.INFO < Severity.HIGH
        assert Severity.INFO < Severity.CRITICAL

    def test_equality_comparison(self):
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.HIGH <= Severity.HIGH

    def test_rank_values(self):
        assert Severity.CRITICAL.rank == 4
        assert Severity.HIGH.rank == 3
        assert Severity.MEDIUM.rank == 2
        assert Severity.LOW.rank == 1
        assert Severity.INFO.rank == 0


class TestFinding:
    """Finding dataclass tests."""

    def test_finding_creation(self):
        f = Finding(
            package_name="test-pkg",
            severity=Severity.HIGH,
            category=FindingCategory.INSTALL_SCRIPT,
            title="Test finding",
            description="Test description",
        )
        assert f.package_name == "test-pkg"
        assert f.severity == Severity.HIGH

    def test_finding_id_unique(self):
        f1 = Finding(
            package_name="pkg-a",
            severity=Severity.HIGH,
            category=FindingCategory.INSTALL_SCRIPT,
            title="Title A",
            description="Desc A",
        )
        f2 = Finding(
            package_name="pkg-b",
            severity=Severity.HIGH,
            category=FindingCategory.INSTALL_SCRIPT,
            title="Title A",
            description="Desc A",
        )
        assert f1.id != f2.id

    def test_finding_id_stable(self):
        f = Finding(
            package_name="test",
            severity=Severity.LOW,
            category=FindingCategory.METADATA,
            title="Missing field",
            description="Something",
        )
        assert f.id == f.id  # deterministic
        assert f.id == "test:metadata:Missing field"

    def test_finding_defaults(self):
        f = Finding(
            package_name="test",
            severity=Severity.INFO,
            category=FindingCategory.METADATA,
            title="t",
            description="d",
        )
        assert f.evidence == ""
        assert f.file_path is None
        assert f.line_number is None


class TestPackageInfo:
    """PackageInfo dataclass tests."""

    def test_creation_minimal(self):
        pkg = PackageInfo(name="test")
        assert pkg.name == "test"
        assert pkg.version == "0.0.0"
        assert pkg.scripts == {}

    def test_creation_full(self):
        pkg = PackageInfo(
            name="express",
            version="4.18.2",
            scripts={"start": "node app.js"},
            dependencies={"debug": "^4.0.0"},
            description="Web framework",
            repository="https://github.com/expressjs/express",
            author="TJ",
        )
        assert pkg.name == "express"
        assert pkg.scripts["start"] == "node app.js"


class TestScanResult:
    """ScanResult tests."""

    def test_empty_result(self):
        r = ScanResult()
        assert r.critical_count == 0
        assert r.high_count == 0
        assert r.exit_code == 0

    def test_exit_code_with_findings(self):
        r = ScanResult(findings=[
            Finding(
                package_name="test",
                severity=Severity.LOW,
                category=FindingCategory.METADATA,
                title="t",
                description="d",
            ),
        ])
        assert r.exit_code == 1

    def test_exit_code_with_critical(self):
        r = ScanResult(findings=[
            Finding(
                package_name="test",
                severity=Severity.CRITICAL,
                category=FindingCategory.INSTALL_SCRIPT,
                title="t",
                description="d",
            ),
        ])
        assert r.exit_code == 2
        assert r.critical_count == 1

    def test_counts(self):
        findings = [
            Finding(package_name="a", severity=Severity.CRITICAL,
                    category=FindingCategory.INSTALL_SCRIPT, title="t1", description="d"),
            Finding(package_name="b", severity=Severity.CRITICAL,
                    category=FindingCategory.INSTALL_SCRIPT, title="t2", description="d"),
            Finding(package_name="c", severity=Severity.HIGH,
                    category=FindingCategory.NETWORK, title="t3", description="d"),
            Finding(package_name="d", severity=Severity.LOW,
                    category=FindingCategory.METADATA, title="t4", description="d"),
        ]
        r = ScanResult(findings=findings)
        assert r.critical_count == 2
        assert r.high_count == 1
