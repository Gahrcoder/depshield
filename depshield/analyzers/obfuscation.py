"""Detect code obfuscation techniques in package source files.

Covers 8 obfuscation techniques commonly used in supply-chain malware.
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

# Maximum file size to analyze (512 KB)
_MAX_FILE_SIZE = 512 * 1024

# ------------------------------------------------------------------ #
# Obfuscation technique patterns                                      #
# ------------------------------------------------------------------ #

# 1. Base64 multi-layer encoding
_BASE64_BLOCK = re.compile(
    r"[A-Za-z0-9+/]{40,}={0,2}",
)
# Buffer.from(x, 'base64') is the suspicious form -- it decodes base64 payloads.
# Plain Buffer.from(x) / Buffer.from(x, 'utf-8') is normal Node.js API usage.
# atob() is a browser API that is suspicious in a Node context.
_BASE64_DECODE = re.compile(
    r"atob\s*\(|Buffer\.from\s*\([^)]*(?:\'|\")(base64)(?:\'|\")",
)

# 2. Hex string sequences
_HEX_LONG = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){8,}",
)
_HEX_ARRAY = re.compile(
    r"\[\s*(?:0x[0-9a-fA-F]{1,4}\s*,\s*){8,}",
)

# 3. Unicode escapes
_UNICODE_LONG = re.compile(
    r"(?:\\u[0-9a-fA-F]{4}){6,}",
)
_UNICODE_BRACE = re.compile(
    r"(?:\\u\{[0-9a-fA-F]+\}){4,}",
)

# 4. String array rotation (javascript-obfuscator pattern)
_STR_ARRAY_ROTATE = re.compile(
    r"var\s+\w+\s*=\s*\[(['\"][^'\"]*['\"]\s*,\s*){10,}\]\s*;\s*"
    r"(\(function\s*\(\w+\s*,\s*\w+\))",
    re.DOTALL,
)
_STR_ARRAY_ACCESS = re.compile(
    r"\w+\[(0x[0-9a-f]+|\d+)\]\s*",  # arr[0x1a] patterns
)

# 5. Control flow flattening
_SWITCH_DISPATCH = re.compile(
    r"while\s*\(!!\[\]\)\s*\{\s*switch",
)
_CFF_PATTERN = re.compile(
    r"case\s+['\"]\d+['\"]\s*:\s*",
)

# 6. Dead code injection
_DEAD_IF_FALSE = re.compile(
    r"if\s*\(\s*false\s*\)",
)
_DEAD_TERNARY = re.compile(
    r"\w+\s*\?\s*void\s+0\s*:\s*",
)

# 7. String concatenation reassembly
_CONCAT_HEAVY = re.compile(
    r"(?:['\"][a-zA-Z0-9]{1,3}['\"]\s*\+\s*){6,}",
)

# 8. Single-character variable mangling
_SINGLE_CHAR_VARS = re.compile(
    r"\b(?:var|let|const)\s+[a-zA-Z_]\s*[=,;]",
)


_TECHNIQUES: List[Tuple[str, re.Pattern, Severity, int]] = [
    ("Base64 multi-layer encoding",   _BASE64_BLOCK,      Severity.MEDIUM,  3),
    ("Base64 decode call",            _BASE64_DECODE,      Severity.MEDIUM,  2),
    ("Hex escape sequences",          _HEX_LONG,           Severity.HIGH,    1),
    ("Hex array",                     _HEX_ARRAY,          Severity.HIGH,    1),
    ("Unicode escape sequences",      _UNICODE_LONG,       Severity.MEDIUM,  1),
    ("Unicode brace escapes",         _UNICODE_BRACE,      Severity.MEDIUM,  1),
    ("String array rotation",         _STR_ARRAY_ROTATE,   Severity.HIGH,    1),
    ("String array index access",     _STR_ARRAY_ACCESS,   Severity.LOW,     10),
    ("Control flow flattening",       _SWITCH_DISPATCH,    Severity.HIGH,    1),
    ("CFF switch/case dispatch",      _CFF_PATTERN,        Severity.MEDIUM,  8),
    ("Dead code (if false)",          _DEAD_IF_FALSE,      Severity.LOW,     3),
    ("Dead code (ternary void)",      _DEAD_TERNARY,       Severity.LOW,     3),
    ("String concatenation assembly", _CONCAT_HEAVY,       Severity.MEDIUM,  2),
    ("Single-char variable mangling", _SINGLE_CHAR_VARS,   Severity.LOW,     15),
]


def _scan_content(content: str) -> List[Tuple[str, Severity, str]]:
    """Scan a string for obfuscation indicators.

    Returns list of (technique_name, severity, evidence_snippet).
    """
    hits: List[Tuple[str, Severity, str]] = []

    for technique, pattern, severity, threshold in _TECHNIQUES:
        matches = pattern.findall(content)
        if len(matches) >= threshold:
            sample = matches[0] if matches else ""
            if isinstance(sample, tuple):
                sample = sample[0]
            hits.append((
                technique,
                severity,
                str(sample)[:120],
            ))

    return hits


def _js_files(directory: str) -> List[str]:
    """Yield paths to .js and .mjs files under directory."""
    result: List[str] = []
    try:
        for root, _dirs, files in os.walk(directory):
            for f in files:
                if f.endswith((".js", ".mjs", ".cjs")):
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
class ObfuscationAnalyzer(BaseAnalyzer):
    """Detect 8 code obfuscation techniques."""

    name = "obfuscation"
    description = "Detect obfuscation: base64, hex, unicode, string rotation, CFF, dead code, concat, mangling"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        # Scan install scripts inline
        for hook, script in package.scripts.items():
            if not script:
                continue
            for technique, severity, evidence in _scan_content(script):
                findings.append(Finding(
                    package_name=package.name,
                    severity=severity,
                    category=FindingCategory.OBFUSCATION,
                    title=f"Obfuscation in '{hook}' script: {technique}",
                    description=(
                        f"The '{hook}' script of {package.name}@{package.version} "
                        f"uses {technique}."
                    ),
                    evidence=evidence,
                ))

        # Scan source files if node_modules path is available
        if package.node_modules_path and os.path.isdir(package.node_modules_path):
            for filepath in _js_files(package.node_modules_path):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue

                for technique, severity, evidence in _scan_content(content):
                    rel_path = os.path.relpath(filepath, package.node_modules_path)
                    findings.append(Finding(
                        package_name=package.name,
                        severity=severity,
                        category=FindingCategory.OBFUSCATION,
                        title=f"Obfuscation in source: {technique}",
                        description=(
                            f"{rel_path} in {package.name}@{package.version} "
                            f"uses {technique}."
                        ),
                        evidence=evidence,
                        file_path=rel_path,
                    ))

        return findings
