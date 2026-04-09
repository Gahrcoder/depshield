"""JSON output format."""
from __future__ import annotations

import json
import sys
from typing import TextIO

from depshield.core.models import Finding, ScanResult, Severity


def _finding_to_dict(finding: Finding) -> dict:
    """Serialize a Finding to a plain dict."""
    d = {
        "package_name": finding.package_name,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "title": finding.title,
        "description": finding.description,
    }
    if finding.evidence:
        d["evidence"] = finding.evidence
    if finding.file_path:
        d["file_path"] = finding.file_path
    if finding.line_number is not None:
        d["line_number"] = finding.line_number
    return d


def render(result: ScanResult, min_severity: Severity = Severity.INFO,
          out: TextIO = sys.stdout) -> None:
    """Render scan results as JSON."""
    filtered = [f for f in result.findings if f.severity >= min_severity]

    output = {
        "version": "1",
        "packages_scanned": result.packages_scanned,
        "scan_duration": round(result.scan_duration, 3),
        "analyzers_run": result.analyzers_run,
        "findings_count": len(filtered),
        "findings": [_finding_to_dict(f) for f in filtered],
        "summary": {
            "critical": sum(1 for f in filtered if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in filtered if f.severity == Severity.HIGH),
            "medium": sum(1 for f in filtered if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in filtered if f.severity == Severity.LOW),
            "info": sum(1 for f in filtered if f.severity == Severity.INFO),
        },
    }

    json.dump(output, out, indent=2)
    out.write("\n")
