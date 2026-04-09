"""Detect typosquatting via Levenshtein distance and confusable characters."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer
from depshield.data.popular_packages import TOP_PACKAGES

# ------------------------------------------------------------------ #
# Confusable character substitution map                               #
# ------------------------------------------------------------------ #
_CONFUSABLES: Dict[str, str] = {
    "0": "o", "o": "0",
    "1": "l", "l": "1",
    "rn": "m", "m": "rn",
    "vv": "w", "w": "vv",
    "cl": "d", "d": "cl",
    "nn": "m",
    "ii": "u",
}

# Additional swap patterns (char pairs often exchanged)
_SWAPS: List[Tuple[str, str]] = [
    ("-", "_"), ("_", "-"),
    ("js", ""), ("", "js"),  # lodash vs lodashjs
    (".", "-"),
]


def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein edit distance."""
    if len(a) < len(b):
        return _levenshtein(b, a)

    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,       # insert
                prev[j + 1] + 1,   # delete
                prev[j] + cost,     # replace
            ))
        prev = curr

    return prev[-1]


def _normalize(name: str) -> str:
    """Strip scope and common suffixes for comparison."""
    # Remove npm scope
    if name.startswith("@"):
        parts = name.split("/", 1)
        name = parts[1] if len(parts) > 1 else name
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def _confusable_match(name: str, target: str) -> bool:
    """Check if name matches target after applying confusable substitutions."""
    n = name.lower()
    t = target.lower()
    if n == t:
        return False  # exact match is not confusable

    # Try each confusable substitution on the input name
    for old, new in _CONFUSABLES.items():
        variant = n.replace(old, new)
        if variant == t:
            return True
    return False


# Minimum length for typosquatting comparison.  Very short names (2-3 chars)
# like "ms", "ws", "qs" have tiny edit distances to many unrelated packages,
# producing overwhelming false positives.
_MIN_NAME_LENGTH = 4

# Minimum target length -- don't compare against 2-char targets either.
_MIN_TARGET_LENGTH = 4


def _find_closest(name: str) -> Optional[Tuple[str, int, str]]:
    """Find the closest popular package to *name*.

    Returns (target, distance, method) or None.
    """
    # Strip scope for length check
    bare_name = name.split("/")[-1] if name.startswith("@") else name
    if len(bare_name) < _MIN_NAME_LENGTH:
        return None

    norm = _normalize(name)
    best_target: Optional[str] = None
    best_dist = float("inf")
    best_method = ""

    for target in TOP_PACKAGES:
        # Skip exact match
        if name == target:
            return None

        # Skip very short targets
        bare_target = target.split("/")[-1] if target.startswith("@") else target
        if len(bare_target) < _MIN_TARGET_LENGTH:
            continue

        norm_target = _normalize(target)

        # Levenshtein on normalized forms
        dist = _levenshtein(norm, norm_target)
        if dist < best_dist and dist > 0:
            best_dist = dist
            best_target = target
            best_method = f"edit distance {dist}"

        # Confusable check
        if _confusable_match(name, target):
            return (target, 0, "confusable characters")

    if best_target and best_dist <= 2:
        return (best_target, int(best_dist), best_method)

    return None


@register_analyzer
class TyposquattingAnalyzer(BaseAnalyzer):
    """Flag packages whose names are suspiciously close to popular packages."""

    name = "typosquatting"
    description = "Detect typosquatting via edit distance and confusable characters"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        result = _find_closest(package.name)
        if result is None:
            return []

        target, dist, method = result

        if dist == 0:  # confusable
            severity = Severity.CRITICAL
        elif dist == 1:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        return [Finding(
            package_name=package.name,
            severity=severity,
            category=FindingCategory.TYPOSQUATTING,
            title=f"Possible typosquat of '{target}'",
            description=(
                f"'{package.name}' is very similar to the popular package "
                f"'{target}' ({method}). This could be an intentional "
                f"typosquat designed to intercept mis-typed installs."
            ),
            evidence=f"name='{package.name}' target='{target}' method={method}",
        )]
