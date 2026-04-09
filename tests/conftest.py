"""Shared fixtures and helpers for depshield tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from depshield.core.models import PackageInfo

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"
TYPOSQUATS_DIR = FIXTURES_DIR / "typosquats"
LEGITIMATE_DIR = FIXTURES_DIR / "legitimate"
OBFUSCATED_DIR = FIXTURES_DIR / "obfuscated"


def load_fixture_json(path: Path) -> Dict[str, Any]:
    """Load and parse a JSON fixture file."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def fixture_to_package(path: Path) -> PackageInfo:
    """Load a fixture JSON and convert to PackageInfo."""
    data = load_fixture_json(path)
    repo = data.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url", "")
    return PackageInfo(
        name=data.get("name", "unknown"),
        version=data.get("version", "0.0.0"),
        scripts=data.get("scripts", {}),
        dependencies=data.get("dependencies", {}),
        description=data.get("description", ""),
        repository=repo,
        author=data.get("author") if isinstance(data.get("author"), str) else None,
    )


def make_package(
    name: str = "test-package",
    version: str = "1.0.0",
    scripts: Dict[str, str] | None = None,
    description: str = "A test package",
    repository: str | None = "https://github.com/test/test",
    author: str | None = "Test Author",
    **kwargs: Any,
) -> PackageInfo:
    """Convenience factory for PackageInfo in tests."""
    return PackageInfo(
        name=name,
        version=version,
        scripts=scripts or {},
        description=description,
        repository=repository,
        author=author,
        **kwargs,
    )


@pytest.fixture
def malicious_dir():
    return MALICIOUS_DIR


@pytest.fixture
def typosquats_dir():
    return TYPOSQUATS_DIR


@pytest.fixture
def legitimate_dir():
    return LEGITIMATE_DIR


@pytest.fixture
def obfuscated_dir():
    return OBFUSCATED_DIR
