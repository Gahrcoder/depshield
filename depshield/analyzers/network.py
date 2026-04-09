"""Network indicator extraction and flagging.

Extracts hardcoded IPs, URLs, webhook endpoints, and known C2 patterns
from package source files and install scripts.
"""
from __future__ import annotations

import ipaddress
import os
import re
from typing import List, Set, Tuple

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer

_MAX_FILE_SIZE = 512 * 1024

# ------------------------------------------------------------------ #
# Patterns                                                            #
# ------------------------------------------------------------------ #

_IPV4 = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

_URL = re.compile(
    r"https?://[^\s'\"`,;)}>\]]{4,120}"
)

# Telegram bot API / webhook
_TELEGRAM = re.compile(
    r"https?://api\.telegram\.org/bot[A-Za-z0-9:_-]+",
)

# Discord webhook
_DISCORD_WEBHOOK = re.compile(
    r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+",
)

# Common C2 / exfil patterns
_C2_PATTERNS = [
    re.compile(r"\bngrok\.io\b"),
    re.compile(r"\bpipedream\.net\b"),
    re.compile(r"\brequestbin\.\w+\b"),
    re.compile(r"\bburpcollaborator\.net\b"),
    re.compile(r"\binteract\.sh\b"),
    re.compile(r"\bcanarytokens\.\w+\b"),
    re.compile(r"\boastify\.com\b"),
    re.compile(r"\bdnslog\.(cn|link)\b"),
    re.compile(r"\bpastebin\.com/raw/\b"),
    re.compile(r"\braw\.githubusercontent\.com\b.*\.(sh|ps1|bat|py)\b"),
]

# RFC 1918 / link-local / loopback ranges (safe)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/32"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is RFC1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse => skip
    return any(addr in net for net in _PRIVATE_RANGES)


def _scan_text(text: str) -> List[Tuple[str, Severity, str]]:
    """Scan text for network indicators. Returns (title, severity, evidence)."""
    hits: List[Tuple[str, Severity, str]] = []
    seen: Set[str] = set()

    # Public IPs
    for m in _IPV4.finditer(text):
        ip = m.group(1)
        if ip not in seen and not _is_private_ip(ip):
            seen.add(ip)
            hits.append((
                f"Hardcoded public IP: {ip}",
                Severity.HIGH,
                ip,
            ))

    # Telegram webhooks
    for m in _TELEGRAM.finditer(text):
        url = m.group(0)
        if url not in seen:
            seen.add(url)
            hits.append((
                "Telegram bot API URL",
                Severity.CRITICAL,
                url[:120],
            ))

    # Discord webhooks
    for m in _DISCORD_WEBHOOK.finditer(text):
        url = m.group(0)
        if url not in seen:
            seen.add(url)
            hits.append((
                "Discord webhook URL",
                Severity.CRITICAL,
                url[:120],
            ))

    # Known C2 / exfil domains
    for pat in _C2_PATTERNS:
        for m in pat.finditer(text):
            indicator = m.group(0)
            if indicator not in seen:
                seen.add(indicator)
                hits.append((
                    f"Known C2/exfil indicator: {indicator}",
                    Severity.CRITICAL,
                    indicator,
                ))

    return hits


def _js_files(directory: str) -> List[str]:
    """List .js/.mjs/.cjs files under directory."""
    result: List[str] = []
    try:
        for root, _dirs, files in os.walk(directory):
            for f in files:
                if f.endswith((".js", ".mjs", ".cjs", ".json")):
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
class NetworkAnalyzer(BaseAnalyzer):
    """Extract and flag network indicators in packages."""

    name = "network"
    description = "Detect hardcoded IPs, URLs, webhooks, and C2 patterns"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        # Scan install scripts
        for hook, script in package.scripts.items():
            if not script:
                continue
            for title, severity, evidence in _scan_text(script):
                findings.append(Finding(
                    package_name=package.name,
                    severity=severity,
                    category=FindingCategory.NETWORK,
                    title=f"{title} (in {hook})",
                    description=(
                        f"Network indicator found in '{hook}' script "
                        f"of {package.name}@{package.version}."
                    ),
                    evidence=evidence,
                ))

        # Scan source files
        if package.node_modules_path and os.path.isdir(package.node_modules_path):
            for filepath in _js_files(package.node_modules_path):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue

                for title, severity, evidence in _scan_text(content):
                    rel_path = os.path.relpath(filepath, package.node_modules_path)
                    findings.append(Finding(
                        package_name=package.name,
                        severity=severity,
                        category=FindingCategory.NETWORK,
                        title=title,
                        description=(
                            f"Network indicator in {rel_path} of "
                            f"{package.name}@{package.version}."
                        ),
                        evidence=evidence,
                        file_path=rel_path,
                    ))

        return findings
