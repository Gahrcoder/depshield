<div align="center">

```
    u2588u2588u2588u2588u2588u2588u2557 u2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2588u2588u2588u2588u2557 u2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2557  u2588u2588u2557u2588u2588u2557u2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2557     u2588u2588u2588u2588u2588u2588u2557 
    u2588u2588u2554u2550u2550u2588u2588u2557u2588u2588u2554u2550u2550u2550u2550u255du2588u2588u2554u2550u2550u2588u2588u2557u2588u2588u2554u2550u2550u2550u2550u255du2588u2588u2551  u2588u2588u2551u2588u2588u2551u2588u2588u2554u2550u2550u2550u2550u255du2588u2588u2551     u2588u2588u2554u2550u2550u2588u2588u2557
    u2588u2588u2551  u2588u2588u2551u2588u2588u2588u2588u2588u2557  u2588u2588u2588u2588u2588u2588u2554u255du2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2588u2588u2588u2588u2588u2551u2588u2588u2551u2588u2588u2588u2588u2588u2557  u2588u2588u2551     u2588u2588u2551  u2588u2588u2551
    u2588u2588u2551  u2588u2588u2551u2588u2588u2554u2550u2550u255d  u2588u2588u2554u2550u2550u2550u255d u255au2550u2550u2550u2550u2588u2588u2551u2588u2588u2554u2550u2550u2588u2588u2551u2588u2588u2551u2588u2588u2554u2550u2550u255d  u2588u2588u2551     u2588u2588u2551  u2588u2588u2551
    u2588u2588u2588u2588u2588u2588u2554u255du2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2551     u2588u2588u2588u2588u2588u2588u2588u2551u2588u2588u2551  u2588u2588u2551u2588u2588u2551u2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2588u2588u2588u2588u2588u2557u2588u2588u2588u2588u2588u2588u2554u255d
    u255au2550u2550u2550u2550u2550u255d u255au2550u2550u2550u2550u2550u2550u255du255au2550u255d     u255au2550u2550u2550u2550u2550u2550u255du255au2550u255d  u255au2550u255du255au2550u255du255au2550u2550u2550u2550u2550u2550u255du255au2550u2550u2550u2550u2550u2550u255du255au2550u2550u2550u2550u2550u255d 
```

**Detect npm supply chain attacks before they hit production.**

[![Tests](https://img.shields.io/badge/tests-238%20passed-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.9%2B-blue)]() [![License](https://img.shields.io/badge/license-MIT-green)]() [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

---

**depshield** is an open-source npm supply chain security scanner that detects malicious packages, typosquatting, obfuscated payloads, and dependency confusion attacks using information theory, behavioral analysis, and pattern matching.

In 2025, **454,648 malicious packages** were published to npm ([Socket.dev Supply Chain Report](https://socket.dev/blog/2025-supply-chain-report)). Tools like `npm audit` and Snyk only check known CVEs -- they miss hijacked packages, zero-day malware, and social engineering attacks entirely. depshield fills that gap.

## Quick Start

```bash
pip install depshield

# Scan a project directory
depshield scan ./my-project

# Output as SARIF for GitHub Security tab
depshield scan ./my-project --format sarif > results.sarif

# Only show HIGH and CRITICAL findings
depshield scan ./my-project --min-severity high
```

## What It Detects

| Analyzer | What It Detects | Techniques |
|----------|----------------|------------|
| Install Scripts | Malicious `postinstall`/`preinstall` hooks: reverse shells, credential theft, crypto miners | Pattern matching, behavioral analysis |
| Typosquatting | `l0dash`, `expres`, `chaulk` -- names designed to catch typos | Levenshtein distance, confusable character detection |
| Slopsquatting | Packages exploiting LLM-hallucinated names like `react-form-utils` | LLM pattern detection, framework-utility combinatorics |
| Dependency Confusion | Internal scopes resolved from public registry, missing `.npmrc` config | Registry analysis, `.npmrc` parsing |
| Metadata | Missing repos, suspicious early versions (0.0.x) with install hooks | Heuristic analysis |
| Entropy | Obfuscated/encrypted payloads hidden in source files | Shannon entropy, Kolmogorov complexity, n-gram analysis |
| Obfuscation | 8 techniques: base64 layers, hex shellcode, string rotation, CFF | Pattern matching, threshold analysis |
| Network | C2 domains, hardcoded IPs, Telegram/Discord webhooks | Indicator extraction, IP classification |

## Detection vs. Other Tools

| Capability | npm audit | Snyk | Trivy | Socket.dev | **depshield** |
|-----------|-----------|------|-------|-----------|---------------|
| Known CVEs | Yes | Yes | Yes | Yes | -- |
| Malicious install scripts | No | No | No | Yes | **Yes** |
| Typosquatting | No | No | No | Yes | **Yes** |
| Slopsquatting | No | No | No | No | **Yes** |
| Obfuscation detection | No | No | No | Yes | **Yes** |
| Dependency confusion | No | No | No | Yes | **Yes** |
| Entropy analysis | No | No | No | No | **Yes** |
| SARIF output | No | Yes | Yes | No | **Yes** |
| Open source | Yes | No | Yes | No | **Yes** |
| Free | Yes | Freemium | Yes | Freemium | **Yes** |

## How Entropy Analysis Works

depshield uses information theory to detect obfuscated payloads without signatures:

### Shannon Entropy

Measures bits per character. Normal source code sits around 4.0-5.5 bits. Obfuscated payloads push toward 6.0+ because encoding increases character diversity:

```
Normal JS:     function add(a, b) { return a + b; }     -> 4.2 bits
Minified:      function add(a,b){return a+b}              -> 4.5 bits
Base64 payload: cmVxdWlyZSgiY2hpbGRfcHJvY2Vzcyi...      -> 5.9 bits
Encrypted:     \x68\x65\x6c\x6c\x6f\x20\x77\x6f...    -> 6.4 bits
```

### Compression Ratio (Kolmogorov Complexity Approximation)

Measures how compressible the data is. Normal code has repetitive patterns (keywords, indentation) that compress well. Encrypted/obfuscated data is nearly incompressible:

```
Normal code:    ratio ~0.25  (compresses to 25% of original)
Minified code:  ratio ~0.40
Obfuscated:     ratio ~0.65
Encrypted:      ratio ~0.90+ (almost incompressible)
```

### N-gram Analysis

Character bigram and trigram distributions differ between natural code and obfuscated payloads. Normal code has predictable character pair frequencies (`th`, `he`, `in` in identifiers); obfuscated code has a more uniform distribution.

### Character Class Distribution

Normal code uses a balanced mix of lowercase, uppercase, digits, punctuation, and whitespace. Hex-encoded payloads skew heavily toward digits and hex alpha characters.

## Output Formats

### Terminal (default)
```
depshield scan ./my-project
```
Human-readable colored output with severity indicators.

### JSON
```
depshield scan ./my-project --format json
```
Machine-parseable findings for CI/CD integration.

### SARIF
```
depshield scan ./my-project --format sarif > results.sarif
```
SARIF 2.1.0 output for GitHub Security tab integration. Upload with:
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
    terminal.py      # Colored terminal output
    json_output.py   # JSON formatter
    sarif.py         # SARIF 2.1.0
  data/
    popular_packages.py  # Top 200 npm packages (typosquat reference)
```

### Plugin Registry

Analyzers register themselves via the `@register_analyzer` decorator. The scan engine discovers all registered analyzers and runs each against every package. This makes it trivial to add new analyzers:

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
        # Your detection logic here
        return findings
```

## Test Suite

238 tests covering:

- **Entropy calculations**: Shannon entropy, compression ratio, n-gram analysis, character class distribution
- **Attack detection**: 8 malicious fixture packages (reverse shell, credential stealer, crypto miner, data exfiltration, base64 eval, env stealer, worm propagation, C2 beacon)
- **Typosquatting**: 12 typosquat fixtures, edit distance, confusable characters
- **False positive prevention**: 23 legitimate packages verified to NOT trigger alerts
- **SARIF output**: Schema compliance, severity mapping, deduplication
- **Integration**: Full scan engine, package discovery, analyzer pipeline

All malicious fixtures use RFC 2606 reserved domains (`*.test.invalid`) for safety.

```bash
python -m pytest tests/ -v
```

## Contributing

### Adding a New Analyzer

1. Create `depshield/analyzers/my_analyzer.py`
2. Subclass `BaseAnalyzer` and implement `analyze()`
3. Decorate with `@register_analyzer`
4. Add tests in `tests/test_analyzers/test_my_analyzer.py`
5. Add fixtures in `tests/fixtures/` if needed

### Adding Attack Fixtures

Fixtures go in `tests/fixtures/malicious/`. Requirements:
- Use RFC 2606 reserved domains only (`*.test.invalid`, `*.example.com`)
- Never use real C2 infrastructure domains
- Include realistic but sanitized payloads

### Running Tests

```bash
git clone https://github.com/Gahrcoder/depshield.git
cd depshield
pip install -e '.[dev]'
python -m pytest tests/ -v
```

## References

- [Socket.dev 2025 Software Supply Chain Security Report](https://socket.dev/blog/2025-supply-chain-report)
- [OpenSSF Malicious Packages Database](https://github.com/ossf/malicious-packages)
- [Slopsquatting: How AI Hallucinations Became an Attack Vector (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25)
- [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [Shannon, C.E. (1948). A Mathematical Theory of Communication](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)

## License

MIT
