"""SARIF 2.1.0 output for GitHub Security tab integration."""
from __future__ import annotations

import json
import sys
from typing import TextIO

from depshield import __version__
from depshield.core.models import Finding, ScanResult, Severity

_SARIF_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


def _rule_id(finding: Finding) -> str:
    """Generate a stable SARIF rule ID."""
    return f"depshield/{finding.category.value}"


def _make_rules(findings: list[Finding]) -> list[dict]:
    """Deduplicate rules across findings."""
    seen: dict[str, dict] = {}
    for f in findings:
        rid = _rule_id(f)
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": f.category.value.replace("_", " ").title(),
                "shortDescription": {"text": f.category.value},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL[f.severity],
                },
                "properties": {
                    "tags": ["security", "supply-chain"],
                },
            }
    return list(seen.values())


def _make_result(finding: Finding) -> dict:
    """Convert a Finding to a SARIF result."""
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": finding.file_path or f"package:{finding.package_name}",
            },
        },
    }
    if finding.line_number:
        location["physicalLocation"]["region"] = {
            "startLine": finding.line_number,
        }

    result: dict = {
        "ruleId": _rule_id(finding),
        "level": _SARIF_LEVEL[finding.severity],
        "message": {
            "text": finding.description,
        },
        "locations": [location],
    }

    if finding.evidence:
        result["fingerprints"] = {
            "evidence": finding.evidence[:200],
        }

    return result


def render(result: ScanResult, min_severity: Severity = Severity.INFO,
          out: TextIO = sys.stdout) -> None:
    """Render scan results as SARIF 2.1.0."""
    filtered = [f for f in result.findings if f.severity >= min_severity]

    sarif: dict = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depshield",
                        "version": __version__,
                        "informationUri": "https://github.com/OpenClaw/depshield",
                        "rules": _make_rules(filtered),
                    },
                },
                "results": [_make_result(f) for f in filtered],
            },
        ],
    }

    json.dump(sarif, out, indent=2)
    out.write("\n")
