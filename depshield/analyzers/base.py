"""Base class for all depshield analyzers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from depshield.core.models import Finding, PackageInfo


class BaseAnalyzer(ABC):
    """Abstract base for security analyzers."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def analyze(self, package: PackageInfo) -> List[Finding]:
        """Analyze a package and return any findings."""
        ...
