"""Entropy-based analysis using the information theory engine.

Analyzes install script content and source files for unusually high
entropy that indicates obfuscation, encryption, or encoded payloads.
Also performs multi-layer decoding: if base64 or hex content is found,
it decodes and re-analyzes the inner payload.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
from typing import List

from depshield.analyzers.base import BaseAnalyzer
from depshield.core.models import Finding, FindingCategory, PackageInfo, Severity
from depshield.core.registry import register_analyzer
from depshield.entropy.shannon import EntropyCategory, entropy_category, shannon_entropy
from depshield.entropy.compression import compression_ratio
from depshield.entropy.ngram import bigram_entropy, ngram_uniformity
from depshield.entropy.charclass import char_class_distribution

_MAX_FILE_SIZE = 512 * 1024

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){20,}")


def _try_decode_base64(data: str) -> str | None:
    """Attempt to decode a base64 string. Returns decoded text or None."""
    try:
        decoded = base64.b64decode(data, validate=True)
        text = decoded.decode("utf-8", errors="strict")
        # Only accept if it looks like text
        if all(c == '\n' or c == '\r' or c == '\t' or (32 <= ord(c) < 127) for c in text):
            return text
    except Exception:
        pass
    return None


def _try_decode_hex(data: str) -> str | None:
    """Attempt to decode a hex string. Returns decoded text or None."""
    try:
        decoded = binascii.unhexlify(data)
        text = decoded.decode("utf-8", errors="strict")
        if all(c == '\n' or c == '\r' or c == '\t' or (32 <= ord(c) < 127) for c in text):
            return text
    except Exception:
        pass
    return None


def _analyze_content(content: str, source: str, package_name: str, version: str) -> List[Finding]:
    """Run entropy analysis on a chunk of content."""
    findings: List[Finding] = []

    if len(content) < 50:
        return findings

    h = shannon_entropy(content)
    cat = entropy_category(content)
    cr = compression_ratio(content)
    bi_ent = bigram_entropy(content)
    uniformity = ngram_uniformity(content)
    char_dist = char_class_distribution(content)

    # --- Primary entropy check ---------------------------------------- #
    if cat in (EntropyCategory.SUSPICIOUS, EntropyCategory.OBFUSCATED):
        severity = Severity.HIGH if cat == EntropyCategory.OBFUSCATED else Severity.MEDIUM
        findings.append(Finding(
            package_name=package_name,
            severity=severity,
            category=FindingCategory.ENTROPY,
            title=f"High entropy ({cat.value}) in {source}",
            description=(
                f"{source} of {package_name}@{version} has "
                f"{cat.value} entropy (H={h:.2f}, compression={cr:.2f}). "
                f"This may indicate obfuscated or encrypted content."
            ),
            evidence=f"H={h:.3f} comp={cr:.3f} bigram_H={bi_ent:.2f} uniformity={uniformity:.3f}",
        ))

    # --- Compression ratio anomaly ------------------------------------ #
    if cr > 0.75 and len(content) > 200:
        findings.append(Finding(
            package_name=package_name,
            severity=Severity.MEDIUM,
            category=FindingCategory.ENTROPY,
            title=f"Low compressibility in {source}",
            description=(
                f"{source} of {package_name}@{version} has a "
                f"compression ratio of {cr:.2f}, suggesting "
                f"encrypted or highly random content."
            ),
            evidence=f"compression_ratio={cr:.3f}",
        ))

    # --- Character class skew (e.g., mostly hex digits) --------------- #
    hex_frac = char_dist.get("hex_alpha", 0) + char_dist.get("digit", 0)
    if hex_frac > 0.85 and len(content) > 100:
        findings.append(Finding(
            package_name=package_name,
            severity=Severity.MEDIUM,
            category=FindingCategory.ENTROPY,
            title=f"Hex-dominated content in {source}",
            description=(
                f"{source} of {package_name}@{version} is "
                f"{hex_frac:.0%} hex characters, which may indicate "
                f"an encoded payload."
            ),
            evidence=f"hex_fraction={hex_frac:.3f}",
        ))

    # --- Multi-layer decoding ----------------------------------------- #
    for m in _BASE64_RE.finditer(content):
        decoded = _try_decode_base64(m.group(0))
        if decoded and len(decoded) > 20:
            inner_cat = entropy_category(decoded)
            if inner_cat in (EntropyCategory.SUSPICIOUS, EntropyCategory.OBFUSCATED):
                findings.append(Finding(
                    package_name=package_name,
                    severity=Severity.HIGH,
                    category=FindingCategory.ENTROPY,
                    title=f"Nested obfuscation: base64 in {source}",
                    description=(
                        f"Base64-encoded content in {source} of "
                        f"{package_name}@{version} decodes to "
                        f"{inner_cat.value}-entropy text. Multi-layer "
                        f"encoding is a strong malware signal."
                    ),
                    evidence=decoded[:100],
                ))

    for m in _HEX_RE.finditer(content):
        decoded = _try_decode_hex(m.group(0))
        if decoded and len(decoded) > 20:
            inner_cat = entropy_category(decoded)
            if inner_cat in (EntropyCategory.SUSPICIOUS, EntropyCategory.OBFUSCATED):
                findings.append(Finding(
                    package_name=package_name,
                    severity=Severity.HIGH,
                    category=FindingCategory.ENTROPY,
                    title=f"Nested obfuscation: hex in {source}",
                    description=(
                        f"Hex-encoded content in {source} of "
                        f"{package_name}@{version} decodes to "
                        f"{inner_cat.value}-entropy text."
                    ),
                    evidence=decoded[:100],
                ))

    return findings


@register_analyzer
class EntropyAnalyzer(BaseAnalyzer):
    """Score packages using information-theory metrics."""

    name = "entropy"
    description = "Entropy-based obfuscation/encryption detection"

    def analyze(self, package: PackageInfo) -> List[Finding]:
        findings: List[Finding] = []

        # Analyze install script content
        for hook, script in package.scripts.items():
            if script:
                findings.extend(
                    _analyze_content(script, f"'{hook}' script", package.name, package.version)
                )

        # Analyze source files if node_modules path available
        if package.node_modules_path and os.path.isdir(package.node_modules_path):
            try:
                for root, _dirs, files in os.walk(package.node_modules_path):
                    for fname in files:
                        if not fname.endswith((".js", ".mjs", ".cjs")):
                            continue
                        fpath = os.path.join(root, fname)
                        try:
                            if os.path.getsize(fpath) > _MAX_FILE_SIZE:
                                continue
                            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                                content = fh.read()
                        except OSError:
                            continue

                        rel = os.path.relpath(fpath, package.node_modules_path)
                        file_findings = _analyze_content(
                            content, rel, package.name, package.version
                        )
                        for f in file_findings:
                            f.file_path = rel
                        findings.extend(file_findings)
            except OSError:
                pass

        return findings
