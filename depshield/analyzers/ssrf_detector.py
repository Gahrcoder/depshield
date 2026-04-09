"""Detect SSRF vulnerabilities in URL validation and fetch patterns."""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

_MAX_FILE_SIZE = 512 * 1024

# ------------------------------------------------------------------ #
# SSRF patterns                                                       #
# ------------------------------------------------------------------ #

# fetch / http.request / https.request / axios with user-controlled URL
_FETCH_UNVALIDATED = re.compile(
    r"\b(?:fetch|axios\.(?:get|post|put|delete|request))\s*\(\s*"
    r"(?!(['\"`]https?://[^'\"` ]+['\"`]))"  # NOT a string literal URL
    r"([a-zA-Z_$][a-zA-Z0-9_$.\[\]]*)",
)

_HTTP_REQUEST = re.compile(
    r"\b(?:https?)\.(?:request|get)\s*\(\s*"
    r"(?!['\"`])([a-zA-Z_$][a-zA-Z0-9_$.\[\]]*)",
)

# URL concatenation with user input for proxy patterns
_URL_CONCAT = re.compile(
    r"['\"`]https?://[^'\"`]+['\"`]\s*\+\s*[a-zA-Z_$]"
    r"|[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\+\s*['\"`]https?://"
    r"|`[^`]*https?://[^`]*\$\{[^}]+\}[^`]*`"
)

# Missing cloud metadata protection
_CLOUD_METADATA_HOSTS = [
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "100.100.100.200",  # Alibaba Cloud
]

# IP blocklist check patterns (looking for validation code)
_IP_VALIDATION = re.compile(
    r"(?:isPrivate|isInternal|isReserved|blockList|denyList|blacklist|BLOCKED_RANGES)"
    r"|(?:169\.254\.169\.254)"
    r"|(?:metadata\.google\.internal)",
    re.IGNORECASE,
)

# DNS rebinding pattern: validates hostname string but doesn't recheck after DNS resolution
_DNS_REBIND_SAFE = re.compile(
    r"(?:dns\.resolve|dns\.lookup|getaddrinfo|resolved.*ip|checkResolved)"
    r"|(?:net\.isIP.*after)",
    re.IGNORECASE,
)

# Missing ranges in blocklists (CGNAT, broadcast, etc.)
_CGNAT_RANGE = re.compile(r"100\.64\.")
_BROADCAST = re.compile(r"255\.255\.255\.255")

# Comment detection
_COMMENT_LINE = re.compile(r"^\s*(?://|\*|/\*)")


def _is_comment(line: str) -> bool:
    return bool(_COMMENT_LINE.match(line.strip()))


def _has_url_validation_nearby(lines: List[str], line_idx: int, window: int = 10) -> bool:
    """Check if there's URL validation in the surrounding code."""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    context = "\n".join(lines[start:end])
    # Look for URL validation patterns
    validation_patterns = [
        r"new\s+URL\(",
        r"url\.parse\(",
        r"isValidUrl",
        r"validateUrl",
        r"allowedHosts",
        r"allowList",
        r"whitelist",
        r"URL\.canParse",
    ]
    return any(re.search(pat, context, re.IGNORECASE) for pat in validation_patterns)


def _check_metadata_blocking(content: str) -> bool:
    """Check if cloud metadata endpoints are blocked."""
    for host in _CLOUD_METADATA_HOSTS[:2]:  # Check the two most common
        if host in content:
            return True
    return False


def _check_ip_range_completeness(content: str) -> List[str]:
    """Check for missing IP ranges in blocklists."""
    missing: List[str] = []
    # Only check if there IS some IP validation
    if not _IP_VALIDATION.search(content):
        return missing

    if not _CGNAT_RANGE.search(content):
        missing.append("CGNAT range 100.64.0.0/10")
    if not _BROADCAST.search(content):
        missing.append("broadcast 255.255.255.255")
    return missing


def _scan_js_content(
    content: str, filepath: str
) -> List[Tuple[str, Severity, str, int]]:
    """Scan JS content for SSRF patterns.

    Returns list of (title, severity, evidence, line_number).
    """
    hits: List[Tuple[str, Severity, str, int]] = []
    lines = content.split("\n")

    for i, line in enumerate(lines):
        if _is_comment(line):
            continue

        # Unvalidated fetch / axios
        m = _FETCH_UNVALIDATED.search(line)
        if m:
            if not _has_url_validation_nearby(lines, i):
                hits.append((
                    "Unvalidated URL in fetch/axios call",
                    Severity.HIGH,
                    line.strip()[:200],
                    i + 1,
                ))

        # http.request / https.request
        m = _HTTP_REQUEST.search(line)
        if m:
            if not _has_url_validation_nearby(lines, i):
                hits.append((
                    "Unvalidated URL in http/https.request",
                    Severity.HIGH,
                    line.strip()[:200],
                    i + 1,
                ))

        # URL concatenation (proxy pattern)
        if _URL_CONCAT.search(line) and not _is_comment(line):
            hits.append((
                "URL concatenation with dynamic input (proxy SSRF risk)",
                Severity.MEDIUM,
                line.strip()[:200],
                i + 1,
            ))

    # File-level checks: missing metadata blocking
    if any(_FETCH_UNVALIDATED.search(l) or _HTTP_REQUEST.search(l) for l in lines):
        if not _check_metadata_blocking(content):
            has_some_validation = _IP_VALIDATION.search(content)
            if has_some_validation:
                hits.append((
                    "URL validation missing cloud metadata hostname blocking",
                    Severity.MEDIUM,
                    "Missing checks for 169.254.169.254 / metadata.google.internal",
                    0,
                ))

    # Check DNS rebinding protection
    has_url_check = bool(re.search(r"new\s+URL|url\.parse|hostname", content, re.IGNORECASE))
    has_fetch = bool(_FETCH_UNVALIDATED.search(content) or _HTTP_REQUEST.search(content))
    if has_url_check and has_fetch and not _DNS_REBIND_SAFE.search(content):
        hits.append((
            "URL validation without DNS rebinding protection",
            Severity.MEDIUM,
            "Validates hostname string but does not verify resolved IP",
            0,
        ))

    # Check missing IP ranges in blocklist
    missing_ranges = _check_ip_range_completeness(content)
    for missing in missing_ranges:
        hits.append((
            f"Incomplete IP blocklist: missing {missing}",
            Severity.MEDIUM,
            f"IP validation present but does not block {missing}",
            0,
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
class SSRFDetector(BaseAnalyzer):
    """Detect SSRF vulnerabilities in URL validation and fetch patterns."""

    name = "ssrf_detector"
    description = "Detect unvalidated fetch, missing DNS rebinding protection, SSRF"
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
                        category=FindingCategory.SSRF,
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
                category=FindingCategory.SSRF,
                title=title,
                description=f"{title} in {filepath}.",
                evidence=evidence,
                file_path=filepath,
                line_number=line_no,
            ))
        return findings
