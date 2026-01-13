# Sentry

**Container Security Auditing for Dagger Pipelines**

Sentry is a Dagger module that audits container images for security vulnerabilities and misconfigurations. It integrates multiple vulnerability scanners (Trivy, Grype, Snyk, Wiz, Black Duck), performs security best practice checks, and generates compliance-ready reports for CI/CD pipelines.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![Dagger](https://img.shields.io/badge/Dagger-0.19+-131313?style=flat&logo=dagger&logoColor=white)](https://dagger.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- 🔍 **Multi-Scanner Support** - Trivy, Grype, Snyk, Wiz, Black Duck, or custom scanners
- ✅ **Security Checks** - Non-root user, secret detection, healthcheck validation
- 📊 **Multiple Report Formats** - Markdown reports with executive summary, JSON for automation
- 🎯 **Security Scoring** - 0-100 score based on findings
- 🚦 **CI/CD Integration** - Pass/fail exit codes for pipeline gates
- ⚙️ **Configurable Thresholds** - Fail on CRITICAL, HIGH, MEDIUM, or LOW severity

## Quick Start

### Basic Audit

```bash
# Audit a container with default Trivy scanner
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=nginx:latest \
  report
```

### With Different Scanner

```bash
# Use Grype instead of Trivy
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-grype \
  report
```

### Get JSON Output

```bash
# Get machine-readable JSON for automation
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  json
```

### CI/CD Integration

```bash
# Get exit code (0=pass, 1=fail) for pipeline gates
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  exit-code
```

## Available Functions

### Entry Points

| Function | Description | Returns |
|----------|-------------|---------|
| `scan --container=<image>` | Initialize security audit for a container | `AuditConfig` |
| `test` | Run module unit tests (43 test cases) | Test report |

### Scanner Selection

| Function | Description | Authentication |
|----------|-------------|----------------|
| `with-trivy` | Use Trivy scanner (default) | None |
| `with-grype` | Use Grype (Anchore) scanner | None |
| `with-snyk --token=<secret>` | Use Snyk scanner | SNYK_TOKEN |
| `with-wiz --client-id=<secret> --client-secret=<secret>` | Use Wiz scanner | WIZ credentials |
| `with-black-duck --url=<url> --token=<secret>` | Use Black Duck scanner | URL + token |
| `with-custom-scanner --image=<img> --args=<args>` | Use custom scanner | Varies |
| `without-scanner` | Disable scanning (checks only) | None |

### Configuration

| Function | Description | Default |
|----------|-------------|---------|
| `fail-on --severity=<level>` | Set minimum severity to fail audit | HIGH |
| `with-secret-check --enable=<bool>` | Enable/disable secret detection | true |
| `with-non-root-check --enable=<bool>` | Enable/disable non-root check | true |
| `with-health-check --enable=<bool>` | Enable/disable healthcheck validation | true |

### Output

| Function | Description | Format |
|----------|-------------|--------|
| `audit` | Get complete audit result object | `AuditResult` |
| `report` | Generate Markdown report | Markdown |
| `json` | Generate JSON report | JSON |
| `passed` | Check if audit passed | boolean |
| `exit-code` | Get CI/CD exit code | 0 or 1 |

## Usage Examples

### Production (Strict)

```bash
# Fail on HIGH or CRITICAL vulnerabilities
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  fail-on --severity=HIGH \
  report
```

### Development (Lenient)

```bash
# Only fail on CRITICAL vulnerabilities
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  fail-on --severity=CRITICAL \
  report
```

### With Authentication (Snyk)

```bash
# Use Snyk with authentication
export SNYK_TOKEN=your-token
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-snyk --token=env:SNYK_TOKEN \
  report
```

### Configuration Checks Only

```bash
# Skip vulnerability scanning, run only security checks
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  without-scanner \
  report
```

### Disable Specific Checks

```bash
# Skip non-root check for containers that must run as root
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-non-root-check --enable=false \
  report
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Dagger
        uses: dagger/dagger-for-github@v5

      - name: Security Audit
        run: |
          dagger call -m github.com/sylvester-francis/Sentry \
            scan --container=myapp:${{ github.sha }} \
            exit-code
```

### GitLab CI

```yaml
security_audit:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - curl -fsSL https://dl.dagger.io/dagger/install.sh | sh
  script:
    - dagger call -m github.com/sylvester-francis/Sentry \
        scan --container=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        exit-code
```

### Use in Your Dagger Module

```go
package main

import (
    "context"
    "dagger/mymodule/internal/dagger"
)

type MyModule struct{}

func (m *MyModule) SecurityAudit(ctx context.Context, container *dagger.Container) (string, error) {
    return dag.Sentry().
        Scan(container).
        WithGrype().
        FailOn("CRITICAL").
        Report(ctx)
}
```

## Security Checks

### Non-Root User Check (HIGH)
Verifies the container runs as a non-root user (UID > 0). Running as root increases the impact of container escape vulnerabilities.

### Secret Detection (HIGH)
Scans environment variables for exposed credentials:
- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_`, `gho_`, `ghs_`, `ghr_`)
- JWT Tokens (`eyJ...`)
- Private Keys (`-----BEGIN...`)
- Database URLs (with credentials)
- API Keys

### Health Check Capability (INFO)
Verifies `curl` or `wget` is available for implementing container health checks.

## Vulnerability Scanners

| Scanner | Image | Best For | Auth Required |
|---------|-------|----------|---------------|
| **Trivy** | `aquasec/trivy:latest` | General purpose, fast | ❌ |
| **Grype** | `anchore/grype:latest` | SBOM-based analysis | ❌ |
| **Snyk** | `snyk/snyk:docker` | Enterprise, dev-friendly | ✅ Token |
| **Wiz** | `wizsecurity/wiz-cli:latest` | Cloud-native, CSPM | ✅ Credentials |
| **Black Duck** | `blackducksoftware/detect:latest` | License compliance | ✅ URL + Token |

## Report Formats

### Markdown Report

```
# Security Audit Report

## Executive Summary

┌─────────────────────────────────────────────────────────────┐
│  STATUS: PASSED                                             │
├─────────────────────────────────────────────────────────────┤
│  Score: 85/100                                              │
│  Checks: 2 passed, 1 failed                                 │
│  Vulnerabilities: 3 total (0 critical)                      │
└─────────────────────────────────────────────────────────────┘

## Vulnerability Summary

Critical:      0
High:          1  █████
Medium:        2  ██████████
Low:           0
```

### JSON Report

```json
{
  "timestamp": "2026-01-13T12:00:00Z",
  "imageRef": "myapp:latest",
  "scannerUsed": "trivy",
  "passed": true,
  "score": 85,
  "checks": [...],
  "vulnerabilities": [...],
  "vulnSummary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "total": 3
  }
}
```

## Security Scoring

Score starts at 100 and deducts points for findings:

**Check Failures:**
- CRITICAL: -25 points
- HIGH: -15 points
- MEDIUM: -10 points
- LOW: -5 points
- WARN: -3 points

**Vulnerabilities:**
- CRITICAL: -10 points each
- HIGH: -5 points each
- MEDIUM: -2 points each
- LOW: -1 point each

**Score Interpretation:**
- 90-100: Excellent (safe to deploy)
- 70-89: Good (review findings)
- 50-69: Fair (address high-severity issues)
- 0-49: Poor (do not deploy)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Sentry Module                        │
├─────────────────────────────────────────────────────────┤
│  1. Security Checks                                     │
│     • Non-root user verification                        │
│     • Secret detection in environment variables         │
│     • Health check capability validation                │
│                                                          │
│  2. Vulnerability Scanner (configurable)                │
│     • Trivy (default)                                   │
│     • Grype, Snyk, Wiz, Black Duck                     │
│     • Custom scanner support                            │
│                                                          │
│  3. Report Generator                                    │
│     • Markdown with executive summary                   │
│     • JSON for automation                               │
│     • Security score calculation (0-100)                │
│                                                          │
│  4. CI/CD Integration                                   │
│     • Exit codes for pipeline gates                     │
│     • Pass/fail status                                  │
└─────────────────────────────────────────────────────────┘
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Scanner returned empty results | Minimal image (e.g., `scratch`) | Normal behavior |
| Container running as root | No USER directive | Add `USER nobody` to Dockerfile |
| No curl/wget found | Minimal base image | Add health check tools or disable check |
| 401 Unauthorized | Invalid/expired token | Refresh authentication credentials |

## Development

### Run Tests

```bash
dagger call -m github.com/sylvester-francis/Sentry test
```

### Local Development

```bash
git clone https://github.com/sylvester-francis/Sentry.git
cd Sentry
dagger develop
dagger functions
dagger call scan --container=alpine:latest report
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `dagger call test`
5. Open a Pull Request

## License

MIT License - see [LICENSE](https://github.com/sylvester-francis/Sentry/blob/main/LICENSE) for details.

## Links

- **GitHub Repository:** https://github.com/sylvester-francis/Sentry
- **Daggerverse:** https://daggerverse.dev/mod/github.com/sylvester-francis/Sentry
- **Issues & Feature Requests:** https://github.com/sylvester-francis/Sentry/issues
- **Dagger Documentation:** https://docs.dagger.io/

---

<div align="center">

**Built with [Dagger](https://dagger.io)** 🚀

</div>
