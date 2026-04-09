"""Detect missing origin validation in postMessage handlers.

This analyzer scans JavaScript/MJS files in node_modules for:
- addEventListener("message") handlers WITHOUT event.origin checks
- window.opener.postMessage with "*" as targetOrigin
- BroadcastChannel usage without sender validation
- postMessage handlers processing sensitive data without origin validation
"""
from __future__ import annotations

import re
from typing import List

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer


@register_analyzer
class PostMessageAnalyzer(BaseAnalyzer):
    """Detect missing origin validation in window.postMessage handlers."""

    name = "postmessage"
    description = "Detect missing origin validation in window.postMessage handlers"

    # Patterns that indicate a message listener
    LISTENER_PATTERNS = [
        re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.IGNORECASE),
        re.compile(r'on(?:message)\s*=', re.IGNORECASE),
    ]

    # Patterns that indicate origin validation
    ORIGIN_CHECK_PATTERNS = [
        re.compile(r'(?:event|e|ev|evt|msg)\.origin'),
        re.compile(r'origin\s*[!=]=='),
        re.compile(r'allowedOrigins?'),
        re.compile(r'trustedOrigins?'),
        re.compile(r'validOrigins?'),
    ]

    # Patterns that indicate sensitive postMessage usage
    SENSITIVE_PATTERNS = [
        re.compile(
            r'(?:key|token|secret|password|credential|private|wallet|'
            r'address|signature|mnemonic)',
            re.IGNORECASE,
        ),
    ]

    # Dangerous postMessage sends
    DANGEROUS_SEND_PATTERNS = [
        re.compile(r'postMessage\s*\([^)]+,\s*["\']\*["\']\s*\)'),
    ]

    # BroadcastChannel without validation
    BROADCAST_PATTERNS = [
        re.compile(r'new\s+BroadcastChannel\s*\('),
    ]

    def analyze(self, package: PackageInfo) -> List[Finding]:
        """Metadata-only analysis (no-op for this analyzer).

        The real work is done by ``analyze_file`` which the engine
        calls during deep scanning.
        """
        return []

    def analyze_file(
        self, filepath: str, content: str, package_name: str
    ) -> List[Finding]:
        """Analyze a JavaScript file for postMessage security issues."""
        findings: List[Finding] = []

        # -- message listeners without origin checks -------------------
        has_listener = any(p.search(content) for p in self.LISTENER_PATTERNS)
        has_origin_check = any(
            p.search(content) for p in self.ORIGIN_CHECK_PATTERNS
        )
        has_sensitive_data = any(
            p.search(content) for p in self.SENSITIVE_PATTERNS
        )

        if has_listener and not has_origin_check:
            severity = (
                Severity.CRITICAL if has_sensitive_data else Severity.HIGH
            )
            findings.append(
                Finding(
                    package_name=package_name,
                    severity=severity,
                    category=FindingCategory.NETWORK,
                    title="Missing origin validation in postMessage handler",
                    description=(
                        'File registers a "message" event listener without '
                        "checking event.origin. Any window/frame can send "
                        "messages that will be processed by this handler."
                        + (
                            " Handler processes sensitive data "
                            "(keys/tokens/secrets)."
                            if has_sensitive_data
                            else ""
                        )
                    ),
                    evidence=self._extract_listener_context(content),
                    file_path=filepath,
                )
            )

        # -- postMessage(data, "*") ------------------------------------
        for pattern in self.DANGEROUS_SEND_PATTERNS:
            matches = pattern.finditer(content)
            for match in matches:
                findings.append(
                    Finding(
                        package_name=package_name,
                        severity=Severity.HIGH,
                        category=FindingCategory.NETWORK,
                        title="postMessage sent with wildcard targetOrigin",
                        description=(
                            'postMessage is called with "*" as targetOrigin, '
                            "allowing any window to receive the message."
                        ),
                        evidence=match.group(0)[:200],
                        file_path=filepath,
                    )
                )

        # -- BroadcastChannel without validation -----------------------
        has_broadcast = any(
            p.search(content) for p in self.BROADCAST_PATTERNS
        )
        if has_broadcast and not has_origin_check:
            findings.append(
                Finding(
                    package_name=package_name,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.NETWORK,
                    title="BroadcastChannel without sender validation",
                    description=(
                        "BroadcastChannel is used without validating message "
                        "sender. Any same-origin context can inject messages."
                    ),
                    evidence=self._extract_broadcast_context(content),
                    file_path=filepath,
                )
            )

        return findings

    def _extract_listener_context(self, content: str) -> str:
        """Extract the addEventListener context for evidence."""
        for pattern in self.LISTENER_PATTERNS:
            match = pattern.search(content)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 200)
                return content[start:end].strip()
        return ""

    def _extract_broadcast_context(self, content: str) -> str:
        """Extract BroadcastChannel context for evidence."""
        for pattern in self.BROADCAST_PATTERNS:
            match = pattern.search(content)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 150)
                return content[start:end].strip()
        return ""
