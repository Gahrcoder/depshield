"""Plain-text terminal output (no external dependencies)."""
from __future__ import annotations

import sys
from typing import TextIO

from depshield.core.models import ScanResult, Severity

_SEVERITY_SYMBOL = {
    Severity.CRITICAL: "[!!]",
    Severity.HIGH:     "[! ]",
    Severity.MEDIUM:   "[* ]",
    Severity.LOW:      "[- ]",
    Severity.INFO:     "[i ]",
}

_DIVIDER = "-" * 72


def render(result: ScanResult, min_severity: Severity = Severity.INFO,
          out: TextIO = sys.stdout) -> None:
    """Render scan results to the terminal."""
    filtered = [f for f in result.findings if f.severity >= min_severity]

    out.write(f"\n{'=' * 72}\n")
    out.write("  depshield scan results\n")
    out.write(f"{'=' * 72}\n\n")

    out.write(f"  Packages scanned : {result.packages_scanned}\n")
    out.write(f"  Analyzers run    : {', '.join(result.analyzers_run)}\n")
    out.write(f"  Scan duration    : {result.scan_duration:.2f}s\n")
    out.write(f"  Findings         : {len(filtered)}")
    if len(filtered) != len(result.findings):
        out.write(f" (of {len(result.findings)} total)")
    out.write("\n\n")

    if not filtered:
        out.write("  No findings at or above the selected severity level.\n\n")
        return

    for i, finding in enumerate(filtered, 1):
        sym = _SEVERITY_SYMBOL.get(finding.severity, "[?]")
        out.write(f"{_DIVIDER}\n")
        out.write(f"  {sym} #{i}  {finding.severity.value.upper()}  "
                  f"{finding.category.value}\n")
        out.write(f"  Package : {finding.package_name}\n")
        out.write(f"  {finding.title}\n")
        out.write("\n")
        out.write(f"  {finding.description}\n")
        if finding.evidence:
            out.write(f"\n  Evidence: {finding.evidence}\n")
        if finding.file_path:
            loc = finding.file_path
            if finding.line_number:
                loc += f":{finding.line_number}"
            out.write(f"  Location: {loc}\n")
        out.write("\n")

    out.write(f"{_DIVIDER}\n")

    # Summary by severity
    counts = {}
    for f in filtered:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    parts = [f"{v} {k}" for k, v in counts.items()]
    out.write(f"  Summary: {', '.join(parts)}\n\n")
