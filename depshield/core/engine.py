"""Scan engine: discovers packages, runs analyzers, collects findings."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from depshield.core.models import Finding, PackageInfo, ScanResult
from depshield.core.registry import get_analyzers


def _read_json(path: str) -> dict:
    """Safely read and parse a JSON file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _packages_from_lockfile(lock_path: str) -> List[PackageInfo]:
    """Extract packages from package-lock.json (v2/v3 format)."""
    data = _read_json(lock_path)
    packages: List[PackageInfo] = []

    # v2/v3: "packages" key with node_modules paths
    if "packages" in data:
        for key, info in data["packages"].items():
            if not key:  # root package
                continue
            # key looks like "node_modules/lodash" or nested
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            pkg = PackageInfo(
                name=name,
                version=info.get("version", "0.0.0"),
                resolved_url=info.get("resolved"),
                integrity=info.get("integrity"),
            )
            packages.append(pkg)

    # v1 fallback: "dependencies" key
    elif "dependencies" in data:
        for name, info in data["dependencies"].items():
            pkg = PackageInfo(
                name=name,
                version=info.get("version", "0.0.0"),
                resolved_url=info.get("resolved"),
                integrity=info.get("integrity"),
            )
            packages.append(pkg)

    return packages


def _packages_from_node_modules(nm_path: str) -> List[PackageInfo]:
    """Discover packages by reading package.json files in node_modules."""
    packages: List[PackageInfo] = []
    nm = Path(nm_path)

    if not nm.is_dir():
        return packages

    for entry in nm.iterdir():
        if entry.name.startswith("."):
            continue

        # Handle scoped packages (@scope/name)
        if entry.name.startswith("@") and entry.is_dir():
            for sub in entry.iterdir():
                pkg = _read_package_json(sub)
                if pkg:
                    packages.append(pkg)
        else:
            pkg = _read_package_json(entry)
            if pkg:
                packages.append(pkg)

    return packages


def _read_package_json(pkg_dir: Path) -> Optional[PackageInfo]:
    """Read a single package.json and return PackageInfo."""
    pj = pkg_dir / "package.json"
    if not pj.is_file():
        return None

    try:
        data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None

    name = data.get("name", pkg_dir.name)
    repo = data.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url", "")

    return PackageInfo(
        name=name,
        version=data.get("version", "0.0.0"),
        scripts=data.get("scripts", {}),
        dependencies=data.get("dependencies", {}),
        description=data.get("description", ""),
        repository=repo,
        author=data.get("author") if isinstance(data.get("author"), str) else
               data.get("author", {}).get("name") if isinstance(data.get("author"), dict) else None,
        node_modules_path=str(pkg_dir),
    )


def _merge_info(lock_pkgs: Dict[str, PackageInfo], nm_pkgs: Dict[str, PackageInfo]) -> List[PackageInfo]:
    """Merge information from lockfile and node_modules."""
    all_names = set(lock_pkgs) | set(nm_pkgs)
    merged: List[PackageInfo] = []

    for name in sorted(all_names):
        lp = lock_pkgs.get(name)
        np = nm_pkgs.get(name)

        if lp and np:
            # Prefer node_modules for scripts/description, lockfile for resolved/integrity
            pkg = PackageInfo(
                name=name,
                version=np.version or lp.version,
                scripts=np.scripts or lp.scripts,
                dependencies=np.dependencies or lp.dependencies,
                resolved_url=lp.resolved_url or np.resolved_url,
                integrity=lp.integrity or np.integrity,
                description=np.description or lp.description,
                repository=np.repository or lp.repository,
                author=np.author or lp.author,
                node_modules_path=np.node_modules_path,
            )
            merged.append(pkg)
        elif np:
            merged.append(np)
        elif lp:
            merged.append(lp)

    return merged


def discover_packages(project_path: str) -> List[PackageInfo]:
    """Discover all packages in a project from lockfile and/or node_modules."""
    lock_pkgs: Dict[str, PackageInfo] = {}
    nm_pkgs: Dict[str, PackageInfo] = {}

    # Try package-lock.json
    lock_path = os.path.join(project_path, "package-lock.json")
    if os.path.isfile(lock_path):
        try:
            for pkg in _packages_from_lockfile(lock_path):
                lock_pkgs[pkg.name] = pkg
        except (json.JSONDecodeError, OSError):
            pass

    # Try node_modules
    nm_path = os.path.join(project_path, "node_modules")
    if os.path.isdir(nm_path):
        for pkg in _packages_from_node_modules(nm_path):
            nm_pkgs[pkg.name] = pkg

    return _merge_info(lock_pkgs, nm_pkgs)


def scan(
    project_path: str,
    exclude_analyzers: Optional[Set[str]] = None,
) -> ScanResult:
    """Run a full scan against the given project path.

    1. Discover packages from lockfile / node_modules.
    2. Instantiate all registered analyzers.
    3. Run each analyzer against each package.
    4. Deduplicate and return findings.
    """
    exclude = exclude_analyzers or set()
    start = time.monotonic()

    packages = discover_packages(project_path)

    # Ensure analyzers are loaded (importing triggers @register_analyzer)
    import depshield.analyzers.dependency_confusion  # noqa: F401
    import depshield.analyzers.entropy_analyzer  # noqa: F401
    import depshield.analyzers.eval_detector  # noqa: F401
    import depshield.analyzers.install_scripts  # noqa: F401
    import depshield.analyzers.metadata  # noqa: F401
    import depshield.analyzers.network  # noqa: F401
    import depshield.analyzers.obfuscation  # noqa: F401
    import depshield.analyzers.redos_detector  # noqa: F401
    import depshield.analyzers.slopsquatting  # noqa: F401
    import depshield.analyzers.ssrf_detector  # noqa: F401
    import depshield.analyzers.typosquatting  # noqa: F401
    import depshield.analyzers.xss_detector  # noqa: F401

    analyzer_classes = [
        cls for cls in get_analyzers()
        if cls.name not in exclude
    ]

    all_findings: List[Finding] = []
    seen_ids: Set[str] = set()
    analyzers_run: List[str] = []

    for cls in analyzer_classes:
        analyzer = cls(project_path) if cls.name == "dependency_confusion" else cls()
        analyzers_run.append(cls.name)

        for pkg in packages:
            try:
                findings = analyzer.analyze(pkg)
            except Exception:
                continue

            for finding in findings:
                if finding.id not in seen_ids:
                    seen_ids.add(finding.id)
                    all_findings.append(finding)

    duration = time.monotonic() - start

    return ScanResult(
        findings=sorted(all_findings, key=lambda f: f.severity.rank, reverse=True),
        packages_scanned=len(packages),
        scan_duration=duration,
        analyzers_run=analyzers_run,
    )
