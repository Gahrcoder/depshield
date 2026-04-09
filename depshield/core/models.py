"""Core data models for depshield."""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Optional


class Severity(enum.Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


class FindingCategory(enum.Enum):
    """Categories of security findings."""
    INSTALL_SCRIPT = "install_script"
    TYPOSQUATTING = "typosquatting"
    SLOPSQUATTING = "slopsquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    METADATA = "metadata"
    ENTROPY = "entropy"
    OBFUSCATION = "obfuscation"
    NETWORK = "network"


@dataclass
class Finding:
    """A single security finding."""
    package_name: str
    severity: Severity
    category: FindingCategory
    title: str
    description: str
    evidence: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None

    @property
    def id(self) -> str:
        """Unique identifier for deduplication."""
        return f"{self.package_name}:{self.category.value}:{self.title}"


@dataclass
class PackageInfo:
    """Parsed package metadata."""
    name: str
    version: str = "0.0.0"
    scripts: dict[str, str] = field(default_factory=dict)
    dependencies: dict[str, str] = field(default_factory=dict)
    resolved_url: Optional[str] = None
    integrity: Optional[str] = None
    description: str = ""
    repository: Optional[str] = None
    author: Optional[str] = None
    node_modules_path: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregated scan output."""
    findings: list[Finding] = field(default_factory=list)
    packages_scanned: int = 0
    scan_duration: float = 0.0
    analyzers_run: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def exit_code(self) -> int:
        """0=clean, 1=findings, 2=critical findings."""
        if self.critical_count > 0:
            return 2
        if self.findings:
            return 1
        return 0
