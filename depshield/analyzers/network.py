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

# Context patterns that indicate an IP-like match is actually SVG path data,
# CSS values, or other non-network content.
_SVG_CONTEXT = re.compile(
    r'(?:'
    r'\bd:\s*["\']|'         # SVG path d= attribute
    r'viewBox\s*[=:]|'        # SVG viewBox
    r'points\s*[=:]|'         # SVG points
    r'\bM\s*[\d.]+|'         # SVG moveto command
    r'\bL\s*[\d.]+|'         # SVG lineto command
    r'\bC\s*[\d.]+'          # SVG curveto command
    r')',
    re.IGNORECASE,
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

# Files that legitimately contain version-like numbers (browserslist data,
# semver tests, OID tables, etc.).  IPs found inside these are almost always
# version strings, not real addresses.
_VERSION_DATA_FILENAMES = {
    "browserslist", "caniuse-lite", "caniuse", "compat-table",
    "coerce.js",  # semver test data
    "agents.js", "browsers.js",  # browserslist data files
}


def _looks_like_version(ip_str: str) -> bool:
    """Heuristic: does this IP look more like a version string?

    Version strings like 2.3.8.0, 4.5.103.30 are common in browserslist,
    semver test data, and OID tables.  We use a multi-factor heuristic:
    - First octet very small (1-14) and last octet is 0 -> version (e.g., 2.3.8.0)
    - Third octet is very large (>50) -> version (e.g., 4.5.103.30)
    - All octets < 20 -> version (e.g., 1.2.3.4, 9.6.15.14)
    """
    try:
        parts = [int(p) for p in ip_str.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    # Pattern: major.minor.patch.0 with small major
    if parts[0] <= 14 and parts[3] == 0:
        return True
    # Pattern: small major, very large patch (>50) -- like 4.5.103.30
    if parts[0] <= 14 and parts[2] > 50:
        return True
    # Pattern: all octets moderate-sized -- like 1.2.3.4, 9.5.15.14, 3.1.8.25
    # BUT exclude repeated-octet patterns like 8.8.8.8, 1.1.1.1 which are
    # well-known DNS/anycast addresses, not version strings.
    if all(p < 30 for p in parts) and len(set(parts)) > 1:
        return True
    return False


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is RFC1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse => skip
    return any(addr in net for net in _PRIVATE_RANGES)


def _is_benign_ip(ip_str: str, filepath: str = "") -> bool:
    """Return True if the IP should be excluded from findings.

    Covers private ranges and version-like patterns found in data files.
    """
    if _is_private_ip(ip_str):
        return True

    # If file is a known version-data source, apply version heuristic
    basename = os.path.basename(filepath) if filepath else ""
    dirparts = filepath.replace("\\", "/").split("/") if filepath else []
    in_version_context = (
        basename in _VERSION_DATA_FILENAMES
        or any(vf in part for part in dirparts for vf in _VERSION_DATA_FILENAMES)
    )
    if in_version_context and _looks_like_version(ip_str):
        return True

    # Even outside known data files, very-low first octets (1-9) are
    # almost never real C2 addresses and overwhelmingly version numbers
    if _looks_like_version(ip_str):
        return True

    return False


def _scan_text(text: str, filepath: str = "") -> List[Tuple[str, Severity, str]]:
    """Scan text for network indicators. Returns (title, severity, evidence)."""
    hits: List[Tuple[str, Severity, str]] = []
    seen: Set[str] = set()

    # Public IPs
    for m in _IPV4.finditer(text):
        ip = m.group(1)
        if ip in seen or _is_benign_ip(ip, filepath):
            continue
        # Check context: if the IP appears inside SVG path data, skip it.
        # Look at 80 chars before the match for SVG context markers.
        context_start = max(0, m.start() - 80)
        context = text[context_start:m.start()]
        if _SVG_CONTEXT.search(context):
            continue
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

                rel_path = os.path.relpath(filepath, package.node_modules_path)
                for title, severity, evidence in _scan_text(content, filepath):
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
