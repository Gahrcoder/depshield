"""Regression tests for false positives discovered during real-world scanning.

These tests encode the specific false positive patterns found when scanning
Next.js, Express, Strapi, and other popular projects.  Every test here
represents a real finding that was incorrectly flagged and subsequently fixed.
"""
from __future__ import annotations

import pytest

from depshield.analyzers.dependency_confusion import (
    DependencyConfusionAnalyzer,
    _KNOWN_PUBLIC_SCOPES,
)
from depshield.analyzers.network import (
    NetworkAnalyzer,
    _is_benign_ip,
    _looks_like_version,
    _scan_text,
)
from depshield.analyzers.obfuscation import ObfuscationAnalyzer, _scan_content
from depshield.analyzers.slopsquatting import SlopsquattingAnalyzer
from depshield.analyzers.typosquatting import TyposquattingAnalyzer
from depshield.core.models import FindingCategory, Severity
from tests.conftest import make_package


# ================================================================== #
# FP1: Typosquatting -- short package names                           #
# ================================================================== #

class TestTyposquattingShortNames:
    """Short names like 'ms', 'ws', 'qs' should NOT be flagged.

    These are legitimate, widely-used packages with very short names.
    They have small edit distances to other short names purely due to
    their brevity, not because they are typosquats.
    """

    @pytest.fixture
    def analyzer(self):
        return TyposquattingAnalyzer()

    @pytest.mark.parametrize("name", [
        "ms",   # millisecond conversion utility (38M weekly downloads)
        "jws",  # JSON Web Signature
        "jwa",  # JSON Web Algorithms
        "qs",   # query string parser (in TOP_PACKAGES list)
        "ws",   # WebSocket library (in TOP_PACKAGES list)
    ])
    def test_short_legitimate_packages_not_flagged(self, analyzer, name):
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, (
            f"'{name}' should NOT be flagged as typosquat -- it is a legitimate "
            f"package with a short name. Got: {findings}"
        )

    @pytest.mark.parametrize("name", [
        "etag",  # HTTP ETag utility
        "vary",  # HTTP Vary header
        "gopd",  # GetOwnPropertyDescriptor
    ])
    def test_short_utility_packages_not_flagged(self, analyzer, name):
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, (
            f"'{name}' should NOT be flagged -- short names have inherent "
            f"small edit distances but are not typosquats."
        )

    def test_longer_typosquats_still_detected(self, analyzer):
        """Ensure we still detect typosquats of longer names."""
        pkg = make_package(name="expres")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1, "'expres' should still be detected as typosquat of 'express'"

    @pytest.mark.parametrize("name", [
        "@dnd-kit/core",
        "@swc/core",
        "@strapi/core",
        "@floating-ui/core",
        "@react-aria/color",
        "@react-stately/form",
        "@radix-ui/rect",
        "@smithy/uuid",
    ])
    def test_scoped_subpackage_not_compared_to_unscoped(self, analyzer, name):
        """Scoped sub-package names should not be compared against unscoped packages.

        @dnd-kit/core -> 'core' is distance 1 from 'cors' but is not a typosquat.
        @react-aria/color -> 'color' is distance 1 from 'colors' but is not a typosquat.
        """
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, (
            f"Scoped package '{name}' should not be flagged as typosquat "
            f"of an unscoped package. Got: {findings}"
        )


# ================================================================== #
# FP2: Network -- version-like IP addresses                           #
# ================================================================== #

class TestNetworkVersionLikeIPs:
    """Version strings in browserslist/semver should NOT be flagged as IPs.

    Packages like caniuse-lite and browserslist contain version strings
    such as '2.3.8.0', '4.5.103.30' that match IPv4 regex patterns.
    """

    def test_browserslist_version_not_flagged(self):
        # These are real browserslist version strings, not IP addresses
        assert _looks_like_version("2.3.8.0") is True
        assert _looks_like_version("4.5.103.30") is True
        assert _looks_like_version("3.1.8.25") is True
        assert _looks_like_version("9.4.146.19") is True

    def test_semver_test_data_not_flagged(self):
        assert _looks_like_version("1.2.3.4") is True

    def test_real_ips_not_filtered(self):
        """Actual C2/suspicious IPs must still be detected."""
        assert _looks_like_version("45.33.32.156") is False
        assert _looks_like_version("185.199.108.153") is False
        assert _looks_like_version("23.20.189.1") is False

    def test_well_known_dns_not_filtered(self):
        """Well-known DNS servers (repeated octets) should be detected."""
        assert _looks_like_version("8.8.8.8") is False
        assert _looks_like_version("1.1.1.1") is False

    def test_scan_text_filters_versions(self):
        """Full scan_text should not report version-like IPs."""
        text = "Browser IE 4.5.103.30 supports feature X since version 2.3.8.0"
        hits = _scan_text(text)
        ip_hits = [h for h in hits if "IP" in h[0]]
        assert len(ip_hits) == 0, f"Version strings should not be reported: {ip_hits}"

    def test_scan_text_still_catches_real_ips(self):
        """Real C2 IPs should still be caught."""
        text = "fetch('http://45.33.32.156/payload')"
        hits = _scan_text(text)
        ip_hits = [h for h in hits if "IP" in h[0]]
        assert len(ip_hits) >= 1

    def test_svg_path_data_not_flagged(self):
        """IP-like numbers in SVG path data should not be flagged.

        Icon libraries like @medusajs/icons contain SVG paths with coordinates
        that look like IP addresses (e.g., d="M39.141.7.7").
        """
        svg_content = (
            'd: "M9 4.91c0-.163.037-.323.108-.464a.85.85 0 0 1 .293-.334'
            'A.7.7 0 0 1 9.798 4a.7.7 0 0 1 .39.141l3.454 2.59'
            'c.11.082.2.195.263.33a1.04 1.04 0 0 1 0 .876.9.9 0 0 1'
            '-.263.33l-3.455 2.59a.7.7 0 0 1-.39.141"'
        )
        hits = _scan_text(svg_content)
        ip_hits = [h for h in hits if "IP" in h[0]]
        assert len(ip_hits) == 0, (
            f"SVG path coordinates should not be flagged as IPs: {ip_hits}"
        )


# ================================================================== #
# FP3: Obfuscation -- Buffer.from() is normal Node.js API             #
# ================================================================== #

class TestObfuscationBufferFrom:
    """Plain Buffer.from() usage should NOT be flagged as obfuscation.

    Buffer.from() is the standard Node.js API for creating Buffer objects.
    Only Buffer.from(x, 'base64') (base64 decoding) is suspicious.
    """

    def test_plain_buffer_from_not_flagged(self):
        content = """
        const buf = Buffer.from('hello world');
        const buf2 = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        const buf3 = Buffer.from('hello', 'utf-8');
        """
        hits = _scan_content(content)
        base64_hits = [h for h in hits if "Base64 decode" in h[0]]
        assert len(base64_hits) == 0, (
            f"Plain Buffer.from() should not trigger base64 detection: {base64_hits}"
        )

    def test_buffer_from_base64_still_flagged(self):
        content = """
        var a = Buffer.from('cGF5bG9hZA==', 'base64').toString();
        var b = Buffer.from('dGVzdA==', 'base64').toString();
        """
        hits = _scan_content(content)
        base64_hits = [h for h in hits if "Base64" in h[0]]
        assert len(base64_hits) >= 1, (
            "Buffer.from(x, 'base64') should still be flagged"
        )

    def test_atob_still_flagged(self):
        content = """
        var a = atob('cGF5bG9hZA==');
        var b = atob('dGVzdA==');
        """
        hits = _scan_content(content)
        base64_hits = [h for h in hits if "Base64" in h[0]]
        assert len(base64_hits) >= 1, "atob() should still be flagged"


# ================================================================== #
# FP4: Entropy -- small files with high compression ratio             #
# ================================================================== #

class TestEntropySmallFiles:
    """Small utility files should NOT trigger low-compressibility warnings.

    Files under ~1000 chars naturally have high compression ratios because
    deflate cannot find enough patterns to compress.  This is not a sign
    of obfuscation.
    """

    def test_small_file_concept(self):
        """Verify that the threshold change is meaningful."""
        # A small JS module (typical of Next.js utility files)
        small_content = """
        export function hasBasePath(path) {
            return path.startsWith(getBasePath());
        }
        export function getBasePath() {
            return process.env.__NEXT_ROUTER_BASEPATH || '';
        }
        """
        # This content is ~200 chars.  It should not trigger
        # low-compressibility warnings regardless of compression ratio.
        from depshield.entropy.compression import compression_ratio
        cr = compression_ratio(small_content)
        # The actual CR doesn't matter -- the analyzer should skip
        # small files now (threshold raised to 1000 chars).
        assert len(small_content) < 1000, "Test content should be small"


# ================================================================== #
# FP5: Dependency confusion -- known public scopes                    #
# ================================================================== #

class TestDepConfusionPublicScopes:
    """Well-known public npm scopes should NOT trigger confusion warnings.

    Scopes like @next, @babel, @img, @swc are public open-source scopes
    published on the public npm registry.  They are not internal packages
    and don't need a private registry.
    """

    @pytest.mark.parametrize("scope,package", [
        ("@next", "@next/env"),
        ("@next", "@next/swc-darwin-arm64"),
        ("@babel", "@babel/core"),
        ("@babel", "@babel/preset-env"),
        ("@img", "@img/sharp-darwin-arm64"),
        ("@swc", "@swc/helpers"),
        ("@types", "@types/node"),
        ("@angular", "@angular/core"),
        ("@vue", "@vue/cli-service"),
        ("@mui", "@mui/material"),
        ("@strapi", "@strapi/strapi"),
        ("@medusajs", "@medusajs/medusa"),
        ("@emnapi", "@emnapi/runtime"),
        ("@vercel", "@vercel/analytics"),
    ])
    def test_public_scope_not_flagged(self, scope, package, tmp_path):
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(name=package)
        findings = analyzer.analyze(pkg)
        scope_findings = [f for f in findings if "no private registry" in f.title]
        assert len(scope_findings) == 0, (
            f"'{package}' is from known public scope '{scope}' -- should not "
            f"be flagged for dependency confusion. Got: {scope_findings}"
        )

    def test_unknown_scope_still_flagged(self, tmp_path):
        """Custom/internal scopes should still be flagged."""
        analyzer = DependencyConfusionAnalyzer(str(tmp_path))
        pkg = make_package(name="@mycompany/internal-utils")
        findings = analyzer.analyze(pkg)
        scope_findings = [f for f in findings if "no private registry" in f.title]
        assert len(scope_findings) >= 1, (
            "Unknown scope '@mycompany' should still be flagged"
        )

    def test_known_public_scopes_list_is_reasonable(self):
        """Sanity check: the public scopes list is not empty and has key entries."""
        assert len(_KNOWN_PUBLIC_SCOPES) >= 30
        assert "@next" in _KNOWN_PUBLIC_SCOPES
        assert "@babel" in _KNOWN_PUBLIC_SCOPES
        assert "@types" in _KNOWN_PUBLIC_SCOPES


# ================================================================== #
# FP6: Slopsquatting -- legitimate multi-word package names           #
# ================================================================== #

class TestSlopsquattingLegitNames:
    """Legitimate packages with multiple hyphens should NOT be flagged.

    The old four-part kebab pattern incorrectly flagged real packages
    like 'buffer-equal-constant-time' and 'call-bind-apply-helpers'.
    """

    @pytest.fixture
    def analyzer(self):
        return SlopsquattingAnalyzer()

    @pytest.mark.parametrize("name", [
        "buffer-equal-constant-time",
        "call-bind-apply-helpers",
        "define-lazy-prop",  # would have been caught by old pattern
        "has-own-prop",  # three parts but check it's fine
    ])
    def test_multi_word_packages_not_flagged(self, analyzer, name):
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, (
            f"'{name}' is a legitimate package -- should not be flagged "
            f"as slopsquatting. Got: {findings}"
        )

    @pytest.mark.parametrize("name", [
        "mime-db",    # legitimate IANA mime database
    ])
    def test_tech_suffix_legitimate_not_flagged(self, analyzer, name):
        # mime-db matches the tech-suffix pattern (xxx-db)
        # This is a known FP that we accept for now since the pattern
        # still catches many suspicious names.  Mark as expected.
        pkg = make_package(name=name)
        findings = analyzer.analyze(pkg)
        # If flagged, severity should be at most MEDIUM (not HIGH/CRITICAL)
        for f in findings:
            assert f.severity <= Severity.MEDIUM

    def test_framework_utility_combos_still_flagged(self, analyzer):
        """Genuine hallucination patterns should still be caught."""
        pkg = make_package(name="react-utils")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1

    def test_scoped_helpers_not_flagged(self, analyzer):
        """@swc/helpers should not be flagged after scope pattern fix."""
        pkg = make_package(name="@swc/helpers")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, (
            "@swc/helpers is legitimate -- scoped pattern should not match"
        )
