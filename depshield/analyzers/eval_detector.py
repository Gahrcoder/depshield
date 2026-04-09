"""Detect dangerous eval(), Function(), and indirect eval usage in JavaScript."""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

_MAX_FILE_SIZE = 512 * 1024

# ------------------------------------------------------------------ #
# Dangerous eval patterns                                             #
# ------------------------------------------------------------------ #

# Indirect eval: (0, eval)(...) — used to force global scope execution
_INDIRECT_EVAL = re.compile(
    r"\(\s*0\s*,\s*eval\s*\)\s*\("
)

# Direct eval with non-literal argument: eval(variable) but NOT eval("string literal")
_EVAL_DYNAMIC = re.compile(
    r"(?<!\w)eval\s*\(\s*(?!['\"`][^)]*['\"`]\s*\))(?![/])"
)

# new Function() with dynamic arguments
_NEW_FUNCTION = re.compile(
    r"new\s+Function\s*\("
)

# setTimeout / setInterval with string first argument (not arrow/function)
_SET_TIMEOUT_STRING = re.compile(
    r"\b(setTimeout|setInterval)\s*\(\s*(?!['\"`]\s*(?:function|\(|=>))(?!['\"`][^)]*['\"`]\s*,)([a-zA-Z_$][a-zA-Z0-9_$.]*)"
)

# vm.runInContext / vm.runInNewContext with any argument
_VM_RUN = re.compile(
    r"\bvm\s*\.\s*(runInContext|runInNewContext|runInThisContext)\s*\("
)

# Comment / string context detection
_COMMENT_LINE = re.compile(r"^\s*(?://|\*|/\*)")
_STRING_CONTEXT = re.compile(r"['\"].*eval.*['\"]")


# Detect eval() occurring inside a string literal on the line
_EVAL_IN_STRING = re.compile(
    r"""['"].*?\beval\s*\(.*?['"]"""  # single/double quoted string containing eval(
)


def _is_comment_or_string(line: str) -> bool:
    """Return True if the line appears to be a comment or the match is inside a string."""
    stripped = line.strip()
    if _COMMENT_LINE.match(stripped):
        return True
    return False


def _eval_only_in_string(line: str) -> bool:
    """Return True if every eval( occurrence on the line is inside a string literal."""
    # Remove all string-quoted content and see if eval( still appears
    without_strings = re.sub(r"(['\"])(?:(?!\1).)*\1", "", line)
    return not re.search(r"\beval\s*\(", without_strings)


def _is_test_file(filepath: str) -> bool:
    """Return True if the file path looks like a test file."""
    base = os.path.basename(filepath).lower()
    parts = filepath.lower().replace("\\", "/")
    return (
        base.startswith("test") or
        base.endswith(".test.js") or
        base.endswith(".spec.js") or
        "__tests__" in parts or
        "/test/" in parts or
        "/tests/" in parts
    )


def _is_deser_or_parsing_context(content: str, line_idx: int, lines: List[str]) -> bool:
    """Check if the eval appears in a deserialization or parsing context."""
    context_window = lines[max(0, line_idx - 5):line_idx + 5]
    context_text = " ".join(context_window).lower()
    keywords = ["deserializ", "parse", "json", "unmarshal", "decode", "template", "compile"]
    return any(kw in context_text for kw in keywords)


def _scan_js_content(
    content: str, filepath: str
) -> List[Tuple[str, Severity, str, int]]:
    """Scan JS content for dangerous eval patterns.

    Returns list of (title, severity, evidence, line_number).
    """
    hits: List[Tuple[str, Severity, str, int]] = []
    lines = content.split("\n")
    is_test = _is_test_file(filepath)

    for i, line in enumerate(lines):
        if _is_comment_or_string(line):
            continue

        # Indirect eval — always dangerous
        if _INDIRECT_EVAL.search(line):
            sev = Severity.CRITICAL if _is_deser_or_parsing_context(content, i, lines) else Severity.HIGH
            hits.append((
                "Indirect eval: (0, eval)() pattern",
                sev,
                line.strip()[:200],
                i + 1,
            ))
            continue

        # Direct dynamic eval
        m = _EVAL_DYNAMIC.search(line)
        if m:
            # Skip if eval() only appears inside a string literal
            if _eval_only_in_string(line):
                continue
            # Skip if this is a test file with a string-literal eval
            if is_test and _STRING_CONTEXT.search(line):
                continue
            sev = Severity.CRITICAL if _is_deser_or_parsing_context(content, i, lines) else Severity.HIGH
            hits.append((
                "Dynamic eval() with non-literal argument",
                sev,
                line.strip()[:200],
                i + 1,
            ))

        # new Function()
        if _NEW_FUNCTION.search(line) and not _is_comment_or_string(line):
            sev = Severity.CRITICAL if _is_deser_or_parsing_context(content, i, lines) else Severity.HIGH
            hits.append((
                "Dynamic Function constructor: new Function()",
                sev,
                line.strip()[:200],
                i + 1,
            ))

        # setTimeout/setInterval with string arg
        if _SET_TIMEOUT_STRING.search(line):
            hits.append((
                "setTimeout/setInterval with string argument",
                Severity.HIGH,
                line.strip()[:200],
                i + 1,
            ))

        # vm.runInContext etc
        if _VM_RUN.search(line):
            hits.append((
                "vm.runInContext/runInNewContext with potentially untrusted input",
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
class EvalDetector(BaseAnalyzer):
    """Detect dangerous eval(), indirect eval, and dynamic Function() usage."""

    name = "eval_detector"
    description = "Detect unsafe eval(), indirect eval, new Function(), vm.run*"
    deep = True  # requires --deep file-level scanning

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        # Scan source files if node_modules_path is available
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
                        category=FindingCategory.DANGEROUS_EVAL,
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
        """Analyze a single file's content directly (for testing/direct use)."""
        findings: List[Finding] = []
        for title, severity, evidence, line_no in _scan_js_content(content, filepath):
            findings.append(Finding(
                package_name=package_name,
                severity=severity,
                category=FindingCategory.DANGEROUS_EVAL,
                title=title,
                description=f"{title} in {filepath}.",
                evidence=evidence,
                file_path=filepath,
                line_number=line_no,
            ))
        return findings
