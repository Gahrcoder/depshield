"""Detect malicious npm install scripts."""
from __future__ import annotations

import re
from typing import List, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

# ------------------------------------------------------------------ #
# Pattern categories: (compiled regex, human label, severity)         #
# ------------------------------------------------------------------ #

_NETWORK_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"\bcurl\b.*\|.*\bsh\b"), "curl piped to shell", Severity.CRITICAL),
    (re.compile(r"\bwget\b.*\|.*\bsh\b"), "wget piped to shell", Severity.CRITICAL),
    (re.compile(r"\bcurl\b.*\b(POST|--data|--upload)\b", re.I), "curl POST / data exfil", Severity.HIGH),
    (re.compile(r"\bwget\b.*--post", re.I), "wget POST / data exfil", Severity.HIGH),
    (re.compile(r"\b(https?://\S+)"), "outbound URL in script", Severity.MEDIUM),
    (re.compile(r"\bnc\b.*-e\b"), "netcat reverse shell", Severity.CRITICAL),
    (re.compile(r"\b/dev/tcp/"), "bash TCP device", Severity.CRITICAL),
]

_EXEC_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"\beval\s*\("), "eval() call", Severity.HIGH),
    (re.compile(r"\bchild_process\b"), "child_process usage", Severity.HIGH),
    (re.compile(r"\bexec(Sync)?\s*\("), "exec / execSync call", Severity.HIGH),
    (re.compile(r"\bspawn(Sync)?\s*\("), "spawn / spawnSync call", Severity.MEDIUM),
    (re.compile(r"\bnew\s+Function\s*\("), "Function constructor", Severity.HIGH),
    (re.compile(r"\brequire\s*\(\s*['\"]child_process['\"]"), "require child_process", Severity.HIGH),
]

_ENCODED_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"Buffer\.from\s*\([^)]+,\s*['\"]base64['\"]"), "Base64 Buffer decode", Severity.HIGH),
    (re.compile(r"atob\s*\("), "atob() base64 decode", Severity.MEDIUM),
    (re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}"), "hex escape sequence", Severity.HIGH),
    (re.compile(r"String\.fromCharCode\s*\("), "String.fromCharCode", Severity.MEDIUM),
    (re.compile(r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}"), "Unicode escape sequence", Severity.MEDIUM),
]

_FS_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"\b(readFileSync|readFile)\b.*(/etc/passwd|/etc/shadow|\.ssh/|id_rsa)"), "reading sensitive files", Severity.CRITICAL),
    (re.compile(r"\b(writeFileSync|appendFileSync)\b.*\.(bashrc|profile|zshrc)"), "writing to shell profile", Severity.CRITICAL),
    (re.compile(r"\bfs\.(chmod|chown)Sync?\s*\("), "changing file permissions", Severity.HIGH),
    (re.compile(r"\b(rmSync|unlinkSync)\b"), "file deletion", Severity.MEDIUM),
    (re.compile(r"\bchmod\b.*\+x\b"), "making file executable", Severity.HIGH),
]

_ENV_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"process\.env\b.*\b(TOKEN|SECRET|KEY|PASSWORD|CRED|AUTH)", re.I), "reading secrets from env", Severity.HIGH),
    (re.compile(r"\$\{?(NPM_TOKEN|NODE_AUTH_TOKEN|GH_TOKEN|GITHUB_TOKEN)\b"), "reading CI/CD tokens", Severity.CRITICAL),
    (re.compile(r"\bos\.environ\b"), "Python os.environ access", Severity.MEDIUM),
    (re.compile(r"\bprocess\.env\b"), "process.env access", Severity.LOW),
]

# ------------------------------------------------------------------ #
# Scripts that are *expected* in install hooks                        #
# ------------------------------------------------------------------ #
SAFE_SCRIPTS: list[str] = [
    "tsc",
    "tsc --build",
    "webpack",
    "webpack --mode production",
    "node-gyp rebuild",
    "node-gyp build",
    "node-gyp configure",
    "node-pre-gyp install --fallback-to-build",
    "prebuild-install || node-gyp rebuild",
    "prebuild-install || cmake-js compile",
    "napi build --release",
    "node install.js",
    "node scripts/install.js",
    "node scripts/build.js",
    "husky install",
    "patch-package",
    "ngcc",
    "opencollective postinstall",
    "node ./scripts/postinstall.js",
    "echo",
    "exit 0",
    "true",
]

_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "preuninstall", "postuninstall")


def _is_safe(script: str) -> bool:
    """Return True if the script matches a known-safe pattern."""
    stripped = script.strip()
    for safe in SAFE_SCRIPTS:
        if stripped == safe or stripped.startswith(safe + " "):
            return True
    return False


def _all_patterns() -> List[Tuple[re.Pattern, str, Severity, str]]:
    out: List[Tuple[re.Pattern, str, Severity, str]] = []
    for pat, label, sev in _NETWORK_PATTERNS:
        out.append((pat, label, sev, "network"))
    for pat, label, sev in _EXEC_PATTERNS:
        out.append((pat, label, sev, "exec"))
    for pat, label, sev in _ENCODED_PATTERNS:
        out.append((pat, label, sev, "encoded"))
    for pat, label, sev in _FS_PATTERNS:
        out.append((pat, label, sev, "filesystem"))
    for pat, label, sev in _ENV_PATTERNS:
        out.append((pat, label, sev, "env"))
    return out


@register_analyzer
class InstallScriptAnalyzer(BaseAnalyzer):
    """Scan npm lifecycle scripts for malicious patterns."""

    name = "install_scripts"
    description = "Detect malicious install/preinstall/postinstall scripts"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        for hook in _INSTALL_HOOKS:
            script = package.scripts.get(hook)
            if not script:
                continue

            if _is_safe(script):
                continue

            for pat, label, severity, category in _all_patterns():
                match = pat.search(script)
                if match:
                    findings.append(Finding(
                        package_name=package.name,
                        severity=severity,
                        category=FindingCategory.INSTALL_SCRIPT,
                        title=f"Suspicious {hook}: {label}",
                        description=(
                            f"The '{hook}' script in {package.name}@{package.version} "
                            f"contains a {category} pattern: {label}"
                        ),
                        evidence=match.group(0)[:200],
                    ))

        return findings
