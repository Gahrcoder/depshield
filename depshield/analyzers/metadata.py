"""Package metadata anomaly detection."""
from __future__ import annotations

import re
from typing import List

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer


@register_analyzer
class MetadataAnalyzer(BaseAnalyzer):
    """Flag suspicious patterns in package metadata."""

    name = "metadata"
    description = "Detect anomalies in package metadata"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        # --- Missing or suspicious description ---------------------------- #
        if not package.description:
            findings.append(Finding(
                package_name=package.name,
                severity=Severity.LOW,
                category=FindingCategory.METADATA,
                title="Missing package description",
                description=(
                    f"'{package.name}' has no description. "
                    f"Legitimate packages typically include a description."
                ),
            ))
        elif len(package.description) < 10:
            findings.append(Finding(
                package_name=package.name,
                severity=Severity.LOW,
                category=FindingCategory.METADATA,
                title="Very short package description",
                description=(
                    f"'{package.name}' has an unusually short description: "
                    f"'{package.description}'"
                ),
                evidence=package.description,
            ))

        # --- No repository link ------------------------------------------ #
        if not package.repository:
            findings.append(Finding(
                package_name=package.name,
                severity=Severity.LOW,
                category=FindingCategory.METADATA,
                title="No repository URL",
                description=(
                    f"'{package.name}' has no repository field. "
                    f"Packages without source repos are harder to audit."
                ),
            ))

        # --- Version 0.0.x / 0.1.0 with install scripts ------------------- #
        if package.version.startswith("0.0.") or package.version == "0.1.0":
            install_hooks = {"preinstall", "install", "postinstall"}
            has_hook = any(k in install_hooks for k in package.scripts)
            if has_hook:
                findings.append(Finding(
                    package_name=package.name,
                    severity=Severity.HIGH,
                    category=FindingCategory.METADATA,
                    title="New package version with install scripts",
                    description=(
                        f"'{package.name}@{package.version}' is a very early "
                        f"version and includes install lifecycle scripts. "
                        f"This combination is a strong signal for malicious "
                        f"packages published to test supply chain attacks."
                    ),
                    evidence=f"version={package.version} hooks={[k for k in package.scripts if k in install_hooks]}",
                ))

        # --- Author is an email-only or missing --------------------------- #
        if not package.author:
            findings.append(Finding(
                package_name=package.name,
                severity=Severity.INFO,
                category=FindingCategory.METADATA,
                title="No author field",
                description=f"'{package.name}' has no author information.",
            ))

        # --- Suspicious resolved URLs ------------------------------------- #
        if package.resolved_url:
            # Non-registry tarball URLs
            if not package.resolved_url.startswith(("https://registry.npmjs.org", "https://registry.yarnpkg.com")):
                if package.resolved_url.startswith("http://"):
                    findings.append(Finding(
                        package_name=package.name,
                        severity=Severity.HIGH,
                        category=FindingCategory.METADATA,
                        title="Package resolved over insecure HTTP",
                        description=(
                            f"'{package.name}' is resolved from an HTTP (not HTTPS) URL. "
                            f"This makes the package vulnerable to MITM attacks."
                        ),
                        evidence=package.resolved_url[:120],
                    ))
                elif re.match(r"https?://\d+\.\d+\.\d+\.\d+", package.resolved_url):
                    findings.append(Finding(
                        package_name=package.name,
                        severity=Severity.HIGH,
                        category=FindingCategory.METADATA,
                        title="Package resolved from IP address",
                        description=(
                            f"'{package.name}' is resolved from a bare IP address "
                            f"rather than a domain. This is unusual and suspicious."
                        ),
                        evidence=package.resolved_url[:120],
                    ))

        # --- Integrity hash missing --------------------------------------- #
        if not package.integrity:
            findings.append(Finding(
                package_name=package.name,
                severity=Severity.LOW,
                category=FindingCategory.METADATA,
                title="No integrity hash",
                description=(
                    f"'{package.name}' has no integrity field. "
                    f"This prevents verification that the downloaded "
                    f"tarball matches what was published."
                ),
            ))

        return findings
