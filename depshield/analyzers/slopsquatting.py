"""Detect slopsquatting: packages that exploit LLM-hallucinated names.

Large language models frequently hallucinate plausible-sounding npm
package names that do not exist.  Attackers register these phantom
names and plant malware.  This analyzer flags packages whose names
match common hallucination patterns.
"""
from __future__ import annotations

import re
from typing import List

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer
from depshield.data.popular_packages import TOP_PACKAGES

# ------------------------------------------------------------------ #
# Frameworks and utilities that LLMs like to combine                  #
# ------------------------------------------------------------------ #
_FRAMEWORKS = {
    "react", "vue", "angular", "svelte", "next", "nuxt", "express",
    "nest", "fastify", "koa", "hapi", "electron", "gatsby", "remix",
    "solid", "astro", "vite", "webpack", "rollup", "esbuild",
    "prisma", "sequelize", "mongoose", "typeorm",
}

_UTILITY_SUFFIXES = [
    "utils", "helpers", "tools", "common", "shared", "core",
    "client", "sdk", "api", "service", "plugin", "adapter",
    "connector", "bridge", "wrapper", "middleware", "handler",
    "manager", "provider", "resolver", "transformer", "serializer",
    "validator", "sanitizer", "formatter", "parser", "builder",
    "factory", "config", "setup", "init", "bootstrap",
]

_SCOPED_PATTERNS = [
    # @scope/plausible-but-fake
    re.compile(r"^@[a-z][a-z0-9-]*/(" + "|".join(_UTILITY_SUFFIXES) + r")$"),
    # @real-scope/hallucinated-subpackage
    re.compile(r"^@(react|vue|angular|svelte|babel|types|testing-library)/[a-z]+-[a-z]+$"),
]

# Pattern: <framework>-<utility>
_COMBO_PATTERN = re.compile(
    r"^(" + "|".join(_FRAMEWORKS) + r")-(" + "|".join(_UTILITY_SUFFIXES) + r")$"
)

# Pattern: names that look auto-generated
_AUTOGEN_PATTERNS = [
    re.compile(r"^[a-z]+-[a-z]+-[a-z]+-[a-z]+$"),  # four-part kebab
    re.compile(r"^(easy|simple|super|mega|ultra|auto|quick)-[a-z]+$"),  # hype prefix
    re.compile(r"^[a-z]+-(js|ts|io|ai|ml|db|fs|ui|fx|rx)$"),  # tech suffix
]

_TOP_SET = set(TOP_PACKAGES)


def _looks_hallucinated(name: str) -> str | None:
    """Return a description if the name matches hallucination patterns, else None."""
    lower = name.lower()

    # Already known? Not a hallucination vector.
    if lower in _TOP_SET:
        return None

    # Check <framework>-<utility> combos
    if _COMBO_PATTERN.match(lower):
        return "framework-utility combination (common LLM hallucination pattern)"

    # Check scoped patterns
    for pat in _SCOPED_PATTERNS:
        if pat.match(lower):
            return "scoped package matching LLM hallucination pattern"

    # Check auto-generated-looking names
    for pat in _AUTOGEN_PATTERNS:
        if pat.match(lower):
            return "name matches common LLM-generated package name pattern"

    return None


@register_analyzer
class SlopsquattingAnalyzer(BaseAnalyzer):
    """Flag packages whose names match LLM hallucination patterns."""

    name = "slopsquatting"
    description = "Detect packages with names matching LLM-hallucinated patterns"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        reason = _looks_hallucinated(package.name)
        if reason is None:
            return []

        return [Finding(
            package_name=package.name,
            severity=Severity.MEDIUM,
            category=FindingCategory.SLOPSQUATTING,
            title="Possible slopsquatting (LLM-hallucinated name)",
            description=(
                f"'{package.name}' matches a {reason}. "
                f"Attackers register phantom package names that LLMs "
                f"frequently hallucinate in code suggestions, then plant "
                f"malware in them. Verify this package is legitimate."
            ),
            evidence=f"pattern={reason}",
        )]
