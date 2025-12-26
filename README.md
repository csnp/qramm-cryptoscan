<h1 align="center">CryptoScan</h1>

<h3 align="center">Cryptographic Discovery for the Post-Quantum Era</h3>

<p align="center">
  <strong>Find every cryptographic algorithm in your codebase. Know your quantum risk. Plan your migration.</strong>
</p>

<p align="center">
  <a href="https://github.com/csnp/qramm-cryptoscan/actions/workflows/ci.yml"><img src="https://github.com/csnp/qramm-cryptoscan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/csnp/qramm-cryptoscan"><img src="https://goreportcard.com/badge/github.com/csnp/qramm-cryptoscan?v=2" alt="Go Report Card"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
</p>

<p align="center">
  <a href="#why-cryptoscan">Why CryptoScan</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## The Quantum Computing Challenge

**Quantum computers will break RSA, ECDSA, and Diffie-Hellman within the next decade.** This isn't speculation—the NSA, NIST, and major technology companies are already migrating to post-quantum cryptography (PQC).

The challenge? **You can't migrate what you can't find.**

Most organizations have no visibility into which cryptographic algorithms are used across their codebases, configurations, and dependencies. CryptoScan solves this by providing a complete cryptographic inventory in seconds—with full source code context so you know exactly what needs to change and where.

## Why CryptoScan

CryptoScan is purpose-built for quantum readiness assessment:

| Capability | CryptoScan | grep/ripgrep | Commercial Tools |
|------------|:----------:|:------------:|:----------------:|
| Remote Git URL scanning | **Yes** | No | Some |
| Source code context (see surrounding lines) | **Yes** | No | Rarely |
| Quantum risk classification per finding | **Yes** | No | Some |
| Context-aware confidence scoring | **Yes** | No | Varies |
| CBOM (Cryptographic Bill of Materials) | **Yes** | No | Rarely |
| SARIF output for GitHub Security | **Yes** | No | Yes |
| Inline ignore comments | **Yes** | No | Some |
| Migration guidance per finding | **Yes** | No | Varies |
| Dependency scanning (20+ package managers) | **Yes** | No | Some |
| Open source | **Yes** | Yes | No |
| Price | **Free** | Free | $$$$ |

## Quick Start

### Installation

```bash
# Install with Go (recommended)
go install github.com/csnp/qramm-cryptoscan/cmd/cryptoscan@latest

# Or build from source
git clone https://github.com/csnp/qramm-cryptoscan.git
cd qramm-cryptoscan
go build -o cryptoscan ./cmd/cryptoscan
```

### Basic Usage

```bash
# Scan a local directory
cryptoscan scan .

# Scan a remote Git repository
cryptoscan scan https://github.com/your-org/your-repo.git

# Output to JSON for automation
cryptoscan scan . --format json --output findings.json

# Generate SARIF for GitHub Security integration
cryptoscan scan . --format sarif --output results.sarif
```

### Try It Out

This repository includes sample cryptographic code for testing:

```bash
# Clone and build
git clone https://github.com/csnp/qramm-cryptoscan.git
cd qramm-cryptoscan
go build -o cryptoscan ./cmd/cryptoscan

# Scan the sample files (Go, Python, Java)
./cryptoscan scan ./crypto-samples

# Expected: ~35 findings showing various crypto patterns
# - Quantum vulnerable: RSA, ECDSA, Ed25519
# - Broken/weak: MD5, SHA-1, DES, 3DES
# - With source context and remediation guidance
```

## Features

### Comprehensive Detection

CryptoScan identifies cryptographic usage across your entire technology stack:

| Category | What We Detect |
|----------|----------------|
| **Asymmetric Encryption** | RSA (all key sizes), ECDSA, DSA, DH, ECDH, Ed25519, X25519 |
| **Symmetric Encryption** | AES (CBC, GCM, ECB, CTR), DES, 3DES, RC4, Blowfish, ChaCha20 |
| **Hash Functions** | MD5, SHA-1, SHA-2 (256/384/512), SHA-3, BLAKE2, RIPEMD |
| **TLS/SSL** | Protocol versions, cipher suites, weak configurations |
| **Key Material** | Private keys (RSA, EC, SSH, PGP, PKCS#8), JWT secrets, HMAC keys |
| **Cloud KMS** | AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault |
| **Dependencies** | Crypto libraries across 20+ package managers |
| **Configurations** | Hardcoded key sizes, algorithm selections, TLS settings |

**50+ detection patterns** with context-aware confidence scoring to minimize false positives.

### Quantum Risk Classification

Every finding is classified by quantum computing threat level:

| Risk Level | Meaning | Threat | Recommended Action |
|------------|---------|--------|-------------------|
| **VULNERABLE** | Broken by quantum computers | Shor's algorithm | Migrate to PQC now |
| **PARTIAL** | Security reduced by quantum | Grover's algorithm | Increase key sizes |
| **SAFE** | Quantum-resistant | N/A | No action needed |
| **UNKNOWN** | Cannot determine | Unknown | Manual review required |

### Context-Aware Analysis

CryptoScan goes beyond simple pattern matching:

- **Source code context**: See 3 lines before and after each finding
- **Confidence scoring**: Findings in comments, logs, or docs are marked low confidence
- **File type awareness**: Different severity for code vs. test vs. documentation
- **Language detection**: 15+ programming languages recognized
- **Noise reduction**: Automatically filters minified files, lock files, and build artifacts

### Multiple Output Formats

```bash
# Human-readable text (default)
cryptoscan scan .

# JSON for automation and integration
cryptoscan scan . --format json --output findings.json

# CSV for spreadsheet analysis
cryptoscan scan . --format csv --output findings.csv

# SARIF for GitHub Code Scanning
cryptoscan scan . --format sarif --output results.sarif

# CBOM (Cryptographic Bill of Materials) for compliance
cryptoscan scan . --format cbom --output crypto-bom.json
```

## Documentation

### CLI Reference

```
cryptoscan scan [path] [flags]

Arguments:
  path    Local directory, file, or Git URL to scan (default: current directory)

Flags:
  -f, --format string       Output format: text, json, csv, sarif, cbom (default "text")
  -o, --output string       Output file path (default: stdout)
  -i, --include string      File patterns to include (comma-separated globs)
  -e, --exclude string      File patterns to exclude (comma-separated globs)
  -d, --max-depth int       Maximum directory depth (0 = unlimited)
  -g, --group-by string     Group output by: file, severity, category, quantum
  -c, --context int         Lines of source context to show (default 3)
  -p, --progress            Show scan progress indicator
      --min-severity string Minimum severity to report: info, low, medium, high, critical
      --no-color            Disable colored output
      --pretty              Pretty print JSON output
  -h, --help                Show help
```

### Common Workflows

```bash
# Focus on high-priority issues only
cryptoscan scan . --min-severity high

# Scan and group findings by file for review
cryptoscan scan . --group-by file

# Scan only specific file types
cryptoscan scan . --include "*.go,*.py,*.java,*.js,*.ts"

# Exclude vendor and test directories
cryptoscan scan . --exclude "vendor/*,node_modules/*,*_test.go"

# CI/CD: Fail if critical issues found
cryptoscan scan . --min-severity critical --format json | jq '.findings | length'
```

### Suppressing False Positives

Use inline comments to suppress findings that are intentional or not applicable:

```go
// Suppress a specific line
key := rsa.GenerateKey(rand.Reader, 2048) // cryptoscan:ignore

// Suppress the next line
// cryptoscan:ignore-next-line
legacyKey := oldCrypto.NewKey()
```

Supported directives:
- `cryptoscan:ignore` — Ignore finding on this line
- `cryptoscan:ignore-next-line` — Ignore finding on the following line
- `crypto-scan:ignore` — Alternative format
- `noscan` — Quick ignore

### CI/CD Integration

#### GitHub Actions with SARIF

```yaml
# .github/workflows/crypto-scan.yml
name: Cryptographic Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  crypto-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install CryptoScan
        run: go install github.com/csnp/qramm-cryptoscan/cmd/cryptoscan@latest

      - name: Run Scan
        run: cryptoscan scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
crypto-scan:
  stage: security
  image: golang:1.21
  script:
    - go install github.com/csnp/qramm-cryptoscan/cmd/cryptoscan@latest
    - cryptoscan scan . --format json --output crypto-findings.json
  artifacts:
    reports:
      sast: crypto-findings.json
    paths:
      - crypto-findings.json
```

#### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if command -v cryptoscan &> /dev/null; then
    cryptoscan scan . --min-severity critical --format text
    if [ $? -ne 0 ]; then
        echo "Critical cryptographic issues found. Commit blocked."
        exit 1
    fi
fi
```

### Output Formats Explained

#### SARIF (Static Analysis Results Interchange Format)

SARIF output integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CryptoScan",
        "informationUri": "https://github.com/csnp/qramm-cryptoscan"
      }
    },
    "results": [...]
  }]
}
```

#### CBOM (Cryptographic Bill of Materials)

CBOM provides a compliance-ready inventory of all cryptographic assets:

```json
{
  "bomFormat": "CryptoBOM",
  "specVersion": "1.0",
  "components": [
    {
      "type": "crypto-algorithm",
      "name": "RSA-2048",
      "quantumSafe": false,
      "locations": [...]
    }
  ]
}
```

### Architecture

```
qramm-cryptoscan/
├── cmd/cryptoscan/      # CLI entry point
├── internal/cli/        # Command implementations
├── pkg/
│   ├── analyzer/        # File context and line analysis
│   ├── patterns/        # Cryptographic pattern definitions (50+)
│   ├── reporter/        # Output formatters (text, json, csv, sarif, cbom)
│   ├── scanner/         # Core scanning engine with parallel processing
│   └── types/           # Shared type definitions
└── crypto-samples/      # Sample files for testing
```

## Roadmap

### v1.0 (Current Release)
- [x] Local and remote repository scanning
- [x] 50+ cryptographic patterns
- [x] Multiple output formats (text, JSON, CSV, SARIF, CBOM)
- [x] Context-aware analysis with confidence scoring
- [x] Dependency scanning for 20+ package managers
- [x] Parallel scanning with worker pools
- [x] Inline ignore comments

### v1.1 (Next)
- [ ] Git history scanning (find crypto in past commits)
- [ ] Enhanced dependency version analysis
- [ ] Configuration file templates

### v2.0 (Future)
- [ ] AWS resource scanning (KMS, ACM, Secrets Manager)
- [ ] Azure resource scanning (Key Vault, App Configuration)
- [ ] GCP resource scanning (Cloud KMS, Secret Manager)
- [ ] Infrastructure-as-Code analysis (Terraform, CloudFormation, Pulumi)
- [ ] Certificate chain analysis

## Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/csnp/qramm-cryptoscan.git
cd qramm-cryptoscan

# Install dependencies
go mod download

# Run tests
go test -race ./...

# Build
go build -o cryptoscan ./cmd/cryptoscan

# Run linter
golangci-lint run
```

### Adding New Patterns

New detection patterns are added in `pkg/patterns/matcher.go`. Each pattern includes:

- Unique ID and descriptive name
- Category classification
- Compiled regex
- Severity and quantum risk levels
- Description and remediation guidance
- References to standards or documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed instructions.

## About CSNP

CryptoScan is developed by the **Cyber Security Non-Profit (CSNP)**, a 501(c)(3) organization dedicated to making cybersecurity knowledge accessible to everyone through education, community, and practical resources.

### Our Mission

We believe that:

- **Accessibility**: Cybersecurity knowledge should be available to everyone, regardless of background or resources
- **Community**: Supportive communities help people learn, share knowledge, and grow together
- **Education**: Practical, actionable learning resources empower people to implement better security
- **Integrity**: The highest ethical standards in all operations and educational content

### QRAMM Toolkit

CryptoScan is part of the **Quantum Readiness Assurance Maturity Model (QRAMM)** toolkit—a suite of open-source tools designed to help organizations prepare for the post-quantum era:

- **CryptoScan** — Cryptographic discovery scanner (this project)
- **QRAMM Assessment** — Quantum readiness maturity assessment
- **TLS Analyzer** — TLS/SSL configuration analysis (coming soon)
- **CryptoCBOM** — Cryptographic Bill of Materials generator (coming soon)

Learn more at [qramm.org](https://qramm.org) and [csnp.org](https://csnp.org).

## References

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)](https://csrc.nist.gov/pubs/fips/203/final) — Replaces RSA/ECDH for key exchange
- [FIPS 204 - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/204/final) — Replaces RSA/ECDSA for signatures
- [FIPS 205 - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/205/final) — Alternative signature scheme
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) — Transitioning cryptographic algorithms and key lengths

### Additional Resources

- [NSA Cybersecurity Advisory on Post-Quantum Cryptography](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2025 Cyber Security Non-Profit (CSNP)

---

<p align="center">
  <sub>Built with purpose by <a href="https://csnp.org">CSNP</a> — Advancing cybersecurity for everyone</sub>
</p>

<p align="center">
  <a href="https://qramm.org">QRAMM</a> •
  <a href="https://csnp.org">CSNP</a> •
  <a href="https://github.com/csnp/qramm-cryptoscan/issues">Issues</a> •
  <a href="https://twitter.com/csnp_org">Twitter</a>
</p>
