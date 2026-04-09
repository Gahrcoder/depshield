"""Detect dependency confusion attack vectors.

Dependency confusion exploits the way package managers resolve
scoped and unscoped packages across public and private registries.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

_PUBLIC_REGISTRIES = {
    "https://registry.npmjs.org",
    "https://registry.npmjs.org/",
    "https://registry.yarnpkg.com",
    "https://registry.yarnpkg.com/",
}

# Well-known public npm scopes.  These are NOT private/internal scopes,
# so the "no private registry configured" warning is a false positive.
# This list covers the most common scopes from popular open-source projects.
_KNOWN_PUBLIC_SCOPES = {
    "@angular", "@babel", "@biomejs", "@changesets", "@clerk",
    "@cloudflare", "@commitlint", "@discoveryjs", "@emnapi",
    "@emotion", "@eslint", "@floating-ui", "@fontsource",
    "@grpc", "@hapi", "@hookform", "@humanwhocodes",
    "@img", "@isaacs", "@jridgewell",
    "@material-ui", "@mdx-js", "@medusajs", "@mswjs",
    "@mui", "@napi-rs", "@nestjs", "@next", "@nrwl",
    "@octokit", "@opentelemetry",
    "@prisma", "@radix-ui", "@react-native",
    "@rollup", "@rushstack",
    "@sentry", "@shopify", "@sideway", "@sinclair",
    "@smithy", "@strapi", "@sveltejs", "@swc",
    "@tanstack", "@testing-library", "@trpc", "@tsconfig",
    "@types", "@typescript-eslint",
    "@ungap", "@vercel", "@vitejs", "@vue", "@vueuse",
    "@webassemblyjs", "@xtuc",
}


def _parse_npmrc(project_root: str) -> Dict[str, str]:
    """Parse .npmrc files for registry configuration.

    Checks project-level, then user-level .npmrc.
    Returns a mapping of scope -> registry URL.
    """
    registries: Dict[str, str] = {}
    candidates = [
        os.path.join(project_root, ".npmrc"),
        os.path.expanduser("~/.npmrc"),
    ]

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue

                    # @scope:registry=https://...
                    m = re.match(r"(@[^:]+):registry\s*=\s*(\S+)", line)
                    if m:
                        registries[m.group(1)] = m.group(2)
                        continue

                    # registry=https://...
                    m = re.match(r"registry\s*=\s*(\S+)", line)
                    if m:
                        registries["__default__"] = m.group(1)
        except OSError:
            continue

    return registries


@register_analyzer
class DependencyConfusionAnalyzer(BaseAnalyzer):
    """Flag scoped packages that may be vulnerable to dependency confusion."""

    name = "dependency_confusion"
    description = "Detect dependency confusion via registry/scope analysis"

    def __init__(self, project_root: str = ".") -> None:
        self._project_root = project_root
        self._npmrc: Optional[Dict[str, str]] = None

    @property
    def npmrc(self) -> Dict[str, str]:
        if self._npmrc is None:
            self._npmrc = _parse_npmrc(self._project_root)
        return self._npmrc

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        # --- Scoped package with no private registry configured ----------- #
        if package.name.startswith("@"):
            scope = package.name.split("/")[0]

            # Skip well-known public scopes -- these are not internal packages
            if scope in _KNOWN_PUBLIC_SCOPES:
                pass  # fall through to resolved URL check only
            else:
                scope_registry = self.npmrc.get(scope)
                default_registry = self.npmrc.get("__default__", "")

                if scope_registry is None and default_registry in _PUBLIC_REGISTRIES | {""}:
                    findings.append(Finding(
                        package_name=package.name,
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DEPENDENCY_CONFUSION,
                        title=f"Scoped package '{scope}' has no private registry",
                        description=(
                            f"The scope '{scope}' is not mapped to a private registry "
                            f"in .npmrc. If '{package.name}' is an internal package, "
                            f"an attacker could publish a higher-version package with "
                            f"the same name on the public npm registry."
                        ),
                        evidence=f"scope={scope} registry=public",
                    ))

        # --- resolved URL points to unexpected registry ------------------- #
        if package.resolved_url:
            is_public = any(
                package.resolved_url.startswith(r)
                for r in _PUBLIC_REGISTRIES
            )
            has_private = bool(self.npmrc)

            if is_public and has_private and package.name.startswith("@"):
                findings.append(Finding(
                    package_name=package.name,
                    severity=Severity.HIGH,
                    category=FindingCategory.DEPENDENCY_CONFUSION,
                    title="Private-scoped package resolved from public registry",
                    description=(
                        f"'{package.name}' resolved from a public registry "
                        f"({package.resolved_url[:80]}) despite private registry "
                        f"configuration being present. This may indicate a "
                        f"dependency confusion attack."
                    ),
                    evidence=f"resolved={package.resolved_url[:120]}",
                ))

        return findings
