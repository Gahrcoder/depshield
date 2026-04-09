"""Tests for SARIF 2.1.0 output formatter."""
from __future__ import annotations

import io
import json

import pytest

from depshield.core.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)
from depshield.output.sarif import render


def _make_result(*findings: Finding) -> ScanResult:
    return ScanResult(
        findings=list(findings),
        packages_scanned=len(findings),
        scan_duration=0.1,
        analyzers_run=["install_scripts"],
    )


def _render_to_dict(result: ScanResult, min_severity: Severity = Severity.INFO) -> dict:
    buf = io.StringIO()
    render(result, min_severity=min_severity, out=buf)
    return json.loads(buf.getvalue())


class TestSarifStructure:
    """SARIF 2.1.0 schema compliance."""

    def test_version_is_2_1_0(self):
        sarif = _render_to_dict(_make_result())
        assert sarif["version"] == "2.1.0"

    def test_has_schema(self):
        sarif = _render_to_dict(_make_result())
        assert "$schema" in sarif
        assert "sarif" in sarif["$schema"]

    def test_has_runs_array(self):
        sarif = _render_to_dict(_make_result())
        assert "runs" in sarif
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_tool_driver(self):
        sarif = _render_to_dict(_make_result())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "depshield"
        assert "version" in driver

    def test_empty_results_array(self):
        sarif = _render_to_dict(_make_result())
        results = sarif["runs"][0]["results"]
        assert isinstance(results, list)
        assert len(results) == 0


class TestSarifFindings:
    """Finding mapping to SARIF results."""

    def test_finding_mapped_to_result(self):
        finding = Finding(
            package_name="evil-pkg",
            severity=Severity.CRITICAL,
            category=FindingCategory.INSTALL_SCRIPT,
            title="Malicious script",
            description="curl piped to shell",
            evidence="curl | sh",
        )
        sarif = _render_to_dict(_make_result(finding))
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "depshield/install_script"
        assert results[0]["level"] == "error"

    def test_medium_severity_is_warning(self):
        finding = Finding(
            package_name="sus-pkg",
            severity=Severity.MEDIUM,
            category=FindingCategory.TYPOSQUATTING,
            title="Typosquat",
            description="Close to lodash",
        )
        sarif = _render_to_dict(_make_result(finding))
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "warning"

    def test_rules_deduplicated(self):
        f1 = Finding(
            package_name="a", severity=Severity.HIGH,
            category=FindingCategory.INSTALL_SCRIPT,
            title="t1", description="d1",
        )
        f2 = Finding(
            package_name="b", severity=Severity.HIGH,
            category=FindingCategory.INSTALL_SCRIPT,
            title="t2", description="d2",
        )
        sarif = _render_to_dict(_make_result(f1, f2))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # same category => same rule

    def test_severity_filtering(self):
        low = Finding(
            package_name="a", severity=Severity.LOW,
            category=FindingCategory.METADATA,
            title="low", description="d",
        )
        high = Finding(
            package_name="b", severity=Severity.HIGH,
            category=FindingCategory.NETWORK,
            title="high", description="d",
        )
        sarif = _render_to_dict(_make_result(low, high), min_severity=Severity.MEDIUM)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "depshield/network"

    def test_evidence_in_fingerprints(self):
        finding = Finding(
            package_name="test",
            severity=Severity.HIGH,
            category=FindingCategory.OBFUSCATION,
            title="obfuscated",
            description="d",
            evidence="eval(atob(...))",
        )
        sarif = _render_to_dict(_make_result(finding))
        result = sarif["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert result["fingerprints"]["evidence"] == "eval(atob(...))"

    def test_file_path_in_location(self):
        finding = Finding(
            package_name="test",
            severity=Severity.HIGH,
            category=FindingCategory.OBFUSCATION,
            title="t",
            description="d",
            file_path="index.js",
            line_number=42,
        )
        sarif = _render_to_dict(_make_result(finding))
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "index.js"
        assert loc["physicalLocation"]["region"]["startLine"] == 42

    def test_valid_json_output(self):
        finding = Finding(
            package_name="test",
            severity=Severity.CRITICAL,
            category=FindingCategory.INSTALL_SCRIPT,
            title="t",
            description="d",
        )
        buf = io.StringIO()
        render(_make_result(finding), out=buf)
        # Should be valid JSON
        parsed = json.loads(buf.getvalue())
        assert parsed is not None
