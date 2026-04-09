<div align="center">

# depshield

**Detect npm supply chain attacks before they hit production.**

[![CI](https://github.com/Gahrcoder/depshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Gahrcoder/depshield/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

</div>

---

**depshield** is an open-source npm supply chain security scanner that detects malicious packages, typosquatting, obfuscated payloads, and dependency confusion attacks using information theory, behavioral analysis, and pattern matching.

In 2025, over **450,000 malicious packages** were published to npm. Tools like `npm audit` and Snyk only check known CVEs -- they miss hijacked packages, zero-day malware, and social engineering attacks entirely. depshield fills that gap.

## Quick Start

```bash
pip install depshield

# Scan a project directory
depshield scan ./my-project

# Output as SARIF for GitHub Security tab
depshield scan ./my-project --format sarif > results.sarif

# Only show HIGH and CRITICAL findings
depshield scan ./my-project --severity high
```

## What It Detects

| Analyzer | What It Catches | How |
|----------|----------------|-----|
| **Install Scripts** | Reverse shells, credential theft, crypto miners in `postinstall`/`preinstall` | Pattern matching, behavioral analysis |
| **Typosquatting** | `l0dash`, `expres`, `chaulk` -- names designed to catch typos | Levenshtein distance, confusable characters |
| **Slopsquatting** | Packages exploiting LLM-hallucinated names like `react-form-utils` | AI pattern detection, framework-utility combinatorics |
| **Dependency Confusion** | Internal scopes resolved from public registry, missing `.npmrc` bindings | Registry analysis, `.npmrc` parsing |
| **Metadata** | Missing repos, suspicious early versions (0.0.x) with install hooks | Heuristic analysis |
| **Entropy** | Obfuscated/encrypted payloads hidden in source files | Shannon entropy, Kolmogorov complexity, n-gram analysis |
| **Obfuscation** | Base64 layers, hex shellcode, string rotation, control flow flattening | Multi-technique pattern matching |
| **Network** | C2 domains, hardcoded IPs, Telegram/Discord exfiltration webhooks | Indicator extraction, IP classification |

## Detection vs. Other Tools

| Capability | npm audit | Snyk | Trivy | Socket.dev | **depshield** |
|-----------|-----------|------|-------|-----------|---------------|
| Known CVEs | Yes | Yes | Yes | Yes | -- |
| Malicious install scripts | No | No | No | Yes | **Yes** |
| Typosquatting | No | No | No | Yes | **Yes** |
| Slopsquatting (AI) | No | No | No | No | **Yes** |
| Obfuscation detection | No | No | No | Yes | **Yes** |
| Dependency confusion | No | No | No | Yes | **Yes** |
| Entropy analysis | No | No | No | No | **Yes** |
| SARIF output | No | Yes | Yes | No | **Yes** |
| Open source | Yes | No | Yes | No | **Yes** |
| Free | Yes | Freemium | Yes | Freemium | **Yes** |

## GitHub Action

Add depshield to your CI pipeline:

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  depshield:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Gahrcoder/depshield@v1
        with:
          severity: medium
          fail-on: high
```

Findings appear in the GitHub Security tab via SARIF upload.

## Docker

```bash
docker build -t depshield .
docker run --rm -v $(pwd):/scan depshield
```

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Gahrcoder/depshield
    rev: v0.1.0
    hooks:
      - id: depshield
        args: ['--severity', 'high']
```

## How Entropy Analysis Works

depshield uses information theory to detect obfuscated payloads without signatures:

**Shannon Entropy** -- Measures bits per character. Normal source code sits around 4.0-5.5 bits. Obfuscated payloads push toward 6.0+ because encoding increases character diversity:

```
Normal JS:     function add(a, b) { return a + b; }     -> 4.2 bits
Minified:      function add(a,b){return a+b}              -> 4.5 bits
Base64 payload: cmVxdWlyZSgiY2hpbGRfcHJvY2Vzcyi...      -> 5.9 bits
Encrypted:     \x68\x65\x6c\x6c\x6f\x20\x77\x6f...    -> 6.4 bits
```

**Compression Ratio** -- Approximates Kolmogorov complexity via zlib. Normal code compresses well (ratio ~0.25). Encrypted/obfuscated data is nearly incompressible (ratio ~0.90+).

**N-gram Analysis** -- Character bigram distributions differ between natural code and obfuscated payloads. Normal code has predictable character pair frequencies; obfuscated code has a uniform distribution.

**Character Class Distribution** -- Normal code uses a balanced mix of character types. Hex-encoded payloads skew heavily toward digits and hex alpha characters.

## Output Formats

### Terminal (default)
```bash
depshield scan ./my-project
```
Human-readable output with severity indicators.

### JSON
```bash
depshield scan ./my-project --format json
```
Machine-parseable findings for CI/CD pipelines.

### SARIF
```bash
depshield scan ./my-project --format sarif > results.sarif
```
SARIF 2.1.0 for GitHub Security tab integration. Upload with:
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Architecture

```
depshield/
  analyzers/         # Plugin-based analyzer system
    base.py          # BaseAnalyzer ABC
    install_scripts.py
    typosquatting.py
    slopsquatting.py
    dependency_confusion.py
    metadata.py
    obfuscation.py
    network.py
    entropy_analyzer.py
  core/
    engine.py        # Scan orchestrator: discover + analyze + dedupe
    models.py        # Finding, PackageInfo, ScanResult, Severity
    registry.py      # @register_analyzer decorator, plugin discovery
  entropy/
    shannon.py       # Shannon entropy + classification
    compression.py   # zlib compression ratio
    ngram.py         # Bigram/trigram entropy, uniformity
    charclass.py     # Character class distribution
  output/
    terminal.py      # Terminal output
    json_output.py   # JSON formatter
    sarif.py         # SARIF 2.1.0
  data/
    popular_packages.py  # Top 200 npm packages (typosquat reference)
```

### Plugin Registry

Analyzers register via `@register_analyzer`. The engine discovers all registered analyzers and runs each against every package. Adding a new analyzer = creating one file:

```python
from depshield.analyzers.base import BaseAnalyzer
from depshield.core.registry import register_analyzer
from depshield.core.models import Finding, PackageInfo

@register_analyzer
class MyAnalyzer(BaseAnalyzer):
    name = "my_analyzer"
    description = "Detect something new"

    def analyze(self, package: PackageInfo) -> list[Finding]:
        findings = []
        # Detection logic here
        return findings
```

## Test Suite

238 tests covering:

- **Entropy calculations**: Shannon entropy, compression ratio, n-gram analysis, character class distribution
- **Attack detection**: 8 malicious fixture packages (reverse shell, credential stealer, crypto miner, data exfiltration, base64 eval, env stealer, worm propagation, C2 beacon)
- **Typosquatting**: 12 typosquat fixtures, edit distance, confusable characters
- **False positive prevention**: 23 legitimate packages verified to produce zero findings
- **SARIF output**: Schema compliance, severity mapping, deduplication
- **Integration**: Full scan engine, package discovery, analyzer pipeline

All malicious fixtures use RFC 2606 reserved domains for safety.

```bash
python -m pytest tests/ -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, how to add new analyzers, code style guidelines, and the PR process.

## References

- [Socket.dev 2025 Software Supply Chain Security Report](https://socket.dev/blog/2025-supply-chain-report)
- [OpenSSF Malicious Packages Database](https://github.com/ossf/malicious-packages)
- [Dependency Confusion (Alex Birsan)](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [Shannon, C.E. (1948). A Mathematical Theory of Communication](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)

## License

[MIT](LICENSE)
