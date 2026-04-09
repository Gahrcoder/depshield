"""Plugin registry with decorator-based analyzer registration."""
from __future__ import annotations

from typing import Dict, List, Type

from depshield.analyzers.base import BaseAnalyzer

_registry: Dict[str, Type[BaseAnalyzer]] = {}


def register_analyzer(cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
    """Class decorator that registers an analyzer by its name."""
    _registry[cls.name] = cls
    return cls


def get_analyzers() -> List[Type[BaseAnalyzer]]:
    """Return all registered analyzer classes."""
    return list(_registry.values())


def get_analyzer(name: str) -> Type[BaseAnalyzer] | None:
    """Look up one analyzer by name."""
    return _registry.get(name)
