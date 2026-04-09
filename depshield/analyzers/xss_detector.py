"""Detect Cross-Site Scripting (XSS) vulnerabilities in server-rendered HTML."""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

_MAX_FILE_SIZE = 512 * 1024

# ------------------------------------------------------------------ #
# XSS patterns                                                        #
# ------------------------------------------------------------------ #

# Template literal interpolation into HTML tags
# Matches: `<tag>${expr}</tag>`, `<tag attr="${expr}">`, etc.
_TEMPLATE_HTML_INTERP = re.compile(
    r"`[^`]*<[a-zA-Z][^`]*\$\{[^}]+\}[^`]*`"
)

# innerHTML assignment with non-sanitized input
_INNER_HTML = re.compile(
    r"\.innerHTML\s*=\s*(?!['\"`]\s*$)(?!['\"`]\s*;)"
)

# document.write with dynamic content
_DOCUMENT_WRITE = re.compile(
    r"document\.write(?:ln)?\s*\(\s*(?!['\"`]<!['\"`])(?!['\"`][^)]*['\"`]\s*\))"
)

# dangerouslySetInnerHTML in React with non-sanitized props
_DANGEROUS_INNER_HTML = re.compile(
    r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"
)

# String concatenation into HTML: '<tag>' + variable + '</tag>'
_HTML_CONCAT = re.compile(
    r"['\"`]\s*<[a-zA-Z][^>]*>\s*['\"`]\s*\+\s*[a-zA-Z_$]"
    r"|[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\+\s*['\"`]\s*</[a-zA-Z]"
)

# Server response with HTML content type and dynamic content
_SERVER_HTML_RESPONSE = re.compile(
    r"(?:res\.(?:send|write|end)|response\.(?:send|write|end))\s*\("
    r"\s*(?:['\"`]\s*<|`[^`]*<)"
)

# Sanitizer detection
_SANITIZER_PATTERNS = re.compile(
    r"(?:DOMPurify|sanitize|escapeHtml|escape|xss|encode)"
    r"|(?:textContent|innerText)\s*=",
    re.IGNORECASE,
)

# Comment detection
_COMMENT_LINE = re.compile(r"^\s*(?://|\*|/\*)")


def _is_comment(line: str) -> bool:
    return bool(_COMMENT_LINE.match(line.strip()))


def _has_sanitizer_nearby(lines: List[str], line_idx: int, window: int = 8) -> bool:
    """Check if there's a sanitizer call in the surrounding code."""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    context = "\n".join(lines[start:end])
    return bool(_SANITIZER_PATTERNS.search(context))


def _is_server_context(content: str) -> bool:
    """Check if the file is a server-side route handler."""
    server_indicators = [
        r"app\.(get|post|put|delete|use)\s*\(",
        r"router\.(get|post|put|delete|use)\s*\(",
        r"express\(",
        r"createServer\(",
        r"req\s*,\s*res",
        r"request\s*,\s*response",
    ]
    return any(re.search(pat, content) for pat in server_indicators)


def _scan_js_content(
    content: str, filepath: str
) -> List[Tuple[str, Severity, str, int]]:
    """Scan JS content for XSS patterns.

    Returns list of (title, severity, evidence, line_number).
    """
    hits: List[Tuple[str, Severity, str, int]] = []
    lines = content.split("\n")
    is_server = _is_server_context(content)

    for i, line in enumerate(lines):
        if _is_comment(line):
            continue

        # Template literal HTML interpolation
        if _TEMPLATE_HTML_INTERP.search(line):
            if not _has_sanitizer_nearby(lines, i):
                sev = Severity.HIGH if is_server else Severity.MEDIUM
                hits.append((
                    "Template literal interpolation into HTML without escaping",
                    sev,
                    line.strip()[:200],
                    i + 1,
                ))

        # innerHTML assignment
        if _INNER_HTML.search(line):
            if not _has_sanitizer_nearby(lines, i):
                hits.append((
                    "innerHTML assignment with potentially unsanitized input",
                    Severity.MEDIUM,
                    line.strip()[:200],
                    i + 1,
                ))

        # document.write
        if _DOCUMENT_WRITE.search(line):
            if not _has_sanitizer_nearby(lines, i):
                hits.append((
                    "document.write() with dynamic content",
                    Severity.MEDIUM,
                    line.strip()[:200],
                    i + 1,
                ))

        # dangerouslySetInnerHTML
        if _DANGEROUS_INNER_HTML.search(line):
            if not _has_sanitizer_nearby(lines, i):
                hits.append((
                    "dangerouslySetInnerHTML with unsanitized content",
                    Severity.HIGH,
                    line.strip()[:200],
                    i + 1,
                ))

        # String concatenation into HTML
        if _HTML_CONCAT.search(line):
            if not _has_sanitizer_nearby(lines, i):
                sev = Severity.HIGH if is_server else Severity.MEDIUM
                hits.append((
                    "String concatenation into HTML",
                    sev,
                    line.strip()[:200],
                    i + 1,
                ))

        # Server HTML response with dynamic content
        if _SERVER_HTML_RESPONSE.search(line):
            if not _has_sanitizer_nearby(lines, i):
                hits.append((
                    "Server response with unsanitized HTML content",
                    Severity.HIGH,
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
class XSSDetector(BaseAnalyzer):
    """Detect Cross-Site Scripting vulnerabilities in server-rendered HTML."""

    name = "xss_detector"
    description = "Detect unescaped HTML interpolation, innerHTML, dangerouslySetInnerHTML"
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
                        category=FindingCategory.XSS,
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
                category=FindingCategory.XSS,
                title=title,
                description=f"{title} in {filepath}.",
                evidence=evidence,
                file_path=filepath,
                line_number=line_no,
            ))
        return findings
