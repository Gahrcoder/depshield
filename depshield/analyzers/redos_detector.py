"""Detect Regular Expression Denial of Service (ReDoS) vulnerabilities."""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

_MAX_FILE_SIZE = 512 * 1024

# ------------------------------------------------------------------ #
# ReDoS patterns                                                      #
# ------------------------------------------------------------------ #

# new RegExp() with a variable (user-controlled input)
_REGEXP_DYNAMIC = re.compile(
    r"new\s+RegExp\s*\(\s*"
    r"(?!['\"`/])"  # NOT a string/regex literal
    r"([a-zA-Z_$][a-zA-Z0-9_$.\[\]]*)",
)

# new RegExp() with template literal containing interpolation
_REGEXP_TEMPLATE = re.compile(
    r"new\s+RegExp\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`"
)

# Nested quantifiers in regex literals: (a+)+, (a*)*b, (a{1,}){1,}
# Only match capturing groups — non-capturing (?:...) groups are typically safe
_NESTED_QUANT = re.compile(
    r"/[^/]*"
    r"\((?!\?)"  # capturing group only: ( NOT followed by ?
    r"[^)]*[+*][^)]*\)[+*{]"
    r"[^/]*/[gimsuy]*"
)

# Overlapping alternatives: (a|a)+, (\w|\d)+
_OVERLAPPING_ALT = re.compile(
    r"/[^/]*"
    r"\(([^)]+)\|\1\)[+*]"
    r"[^/]*/[gimsuy]*"
)

# Nested quantifiers in string-form regex patterns
_NESTED_QUANT_STRING = re.compile(
    r"['\"`]\s*[^'\"`]*\([^)]*[+*][^)]*\)[+*{][^'\"`]*['\"`]"
)

# escapeRegExp / escape pattern detection (safe usage)
_ESCAPE_REGEXP = re.compile(
    r"(?:escapeRegExp|escapeRegex|escape_regex|RegExp\.escape|lodash.*escape|_\.escapeRegExp)",
    re.IGNORECASE,
)

# Comment detection
_COMMENT_LINE = re.compile(r"^\s*(?://|\*|/\*)")


def _is_comment(line: str) -> bool:
    return bool(_COMMENT_LINE.match(line.strip()))


def _has_regex_escape_nearby(lines: List[str], line_idx: int, window: int = 5) -> bool:
    """Check if there's a regex escape function nearby."""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    context = "\n".join(lines[start:end])
    return bool(_ESCAPE_REGEXP.search(context))


def _input_comes_from_user(lines: List[str], line_idx: int, var_name: str) -> bool:
    """Heuristic: check if the variable likely comes from user input."""
    user_input_patterns = [
        r"req\.(query|params|body|headers)",
        r"request\.(query|params|body|headers)",
        r"searchParams\.get",
        r"location\.(search|hash)",
        r"document\.getElementById",
        r"event\.target\.value",
        r"\binput\b",
        r"\bquery\b",
        r"\bsearch\b",
        r"\bfilter\b",
        r"\bpattern\b",
    ]
    start = max(0, line_idx - 10)
    context = "\n".join(lines[start:line_idx + 1])
    return any(re.search(pat, context, re.IGNORECASE) for pat in user_input_patterns)


def _scan_js_content(
    content: str, filepath: str
) -> List[Tuple[str, Severity, str, int]]:
    """Scan JS content for ReDoS patterns.

    Returns list of (title, severity, evidence, line_number).
    """
    hits: List[Tuple[str, Severity, str, int]] = []
    lines = content.split("\n")

    for i, line in enumerate(lines):
        if _is_comment(line):
            continue

        # Dynamic RegExp with variable input
        m = _REGEXP_DYNAMIC.search(line)
        if m:
            var_name = m.group(1)
            if not _has_regex_escape_nearby(lines, i):
                is_user = _input_comes_from_user(lines, i, var_name)
                sev = Severity.HIGH if is_user else Severity.MEDIUM
                hits.append((
                    "Dynamic RegExp construction without escaping",
                    sev,
                    line.strip()[:200],
                    i + 1,
                ))

        # RegExp with template literal interpolation
        if _REGEXP_TEMPLATE.search(line):
            if not _has_regex_escape_nearby(lines, i):
                hits.append((
                    "RegExp with interpolated template literal",
                    Severity.MEDIUM,
                    line.strip()[:200],
                    i + 1,
                ))

        # Nested quantifiers in regex literal
        if _NESTED_QUANT.search(line):
            hits.append((
                "Regex with nested quantifiers (ReDoS risk)",
                Severity.MEDIUM,
                line.strip()[:200],
                i + 1,
            ))

        # Overlapping alternatives
        if _OVERLAPPING_ALT.search(line):
            hits.append((
                "Regex with overlapping alternatives (ReDoS risk)",
                Severity.MEDIUM,
                line.strip()[:200],
                i + 1,
            ))

        # Nested quantifiers in string-form regex
        if _NESTED_QUANT_STRING.search(line):
            if re.search(r"new\s+RegExp|RegExp\(", line):
                hits.append((
                    "RegExp string pattern with nested quantifiers",
                    Severity.MEDIUM,
                    line.strip()[:200],
                    i + 1,
                ))

    return hits


def _js_files(directory: str) -> List[str]:
    """List JS files under directory."""
    result: List[str] = []
    try:
        for root, _dirs, files in os.walk(directory):
            for f in files:
                if f.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
                    full = os.path.join(root, f)
                    try:
                        if os.path.getsize(full) <= _MAX_FILE_SIZE:
                            result.append(full)
                    except OSError:
                        continue
    except OSError:
        pass
    return result


@register_analyzer
class ReDoSDetector(BaseAnalyzer):
    """Detect Regular Expression Denial of Service vulnerabilities."""

    name = "redos_detector"
    description = "Detect dynamic RegExp with user input, nested quantifiers, overlapping alternatives"
    deep = True  # requires --deep file-level scanning

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        if package.node_modules_path and os.path.isdir(package.node_modules_path):
            for filepath in _js_files(package.node_modules_path):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue

                for title, severity, evidence, line_no in _scan_js_content(content, filepath):
                    rel_path = os.path.relpath(filepath, package.node_modules_path)
                    findings.append(Finding(
                        package_name=package.name,
                        severity=severity,
                        category=FindingCategory.REDOS,
                        title=title,
                        description=(
                            f"{title} in {rel_path} of "
                            f"{package.name}@{package.version}."
                        ),
                        evidence=evidence,
                        file_path=rel_path,
                        line_number=line_no,
                    ))

        return findings

    def analyze_file(self, content: str, filepath: str, package_name: str = "unknown") -> List[Finding]:
        """Analyze a single file's content directly."""
        findings: List[Finding] = []
        for title, severity, evidence, line_no in _scan_js_content(content, filepath):
            findings.append(Finding(
                package_name=package_name,
                severity=severity,
                category=FindingCategory.REDOS,
                title=title,
                description=f"{title} in {filepath}.",
                evidence=evidence,
                file_path=filepath,
                line_number=line_no,
            ))
        return findings
