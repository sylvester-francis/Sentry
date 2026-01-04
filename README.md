<div align="center">

# Sentry

**Container Security Auditing for Dagger Pipelines**

[![Dagger](https://img.shields.io/badge/Dagger-Module-blue)](https://dagger.io)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

*Automated security checks, vulnerability scanning, and compliance reporting for containers*

</div>

---

## Overview

Sentry is a [Dagger](https://dagger.io) module that audits containers for security compliance. It performs automated security checks, integrates with multiple vulnerability scanners, and generates compliance-ready reports.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Scanner Support** | Trivy, Grype, Snyk, Wiz, Black Duck, or custom |
| **Security Checks** | Non-root user, secret detection, health check capability |
| **Compliance Reports** | Professional Markdown and JSON output |
| **CI/CD Integration** | Pass/fail exit codes for pipeline gates |
| **Security Scoring** | 0-100 score based on findings |

---

## Quick Start

```bash
# Basic security audit (uses Trivy by default)
dagger call scan --container=nginx:latest report

# Use Grype scanner instead
dagger call scan --container=nginx:latest with-grype report

# Get JSON output
dagger call scan --container=nginx:latest json

# CI integration (exit code 0=pass, 1=fail)
dagger call scan --container=nginx:latest exit-code
```

---

## Supported Scanners

| Scanner | Method | Auth Required |
|---------|--------|---------------|
| **Trivy** (default) | `with-trivy` | None |
| **Grype** (Anchore) | `with-grype` | None |
| **Snyk** | `with-snyk --token=env:SNYK_TOKEN` | SNYK_TOKEN |
| **Wiz** | `with-wiz --client-id=... --client-secret=...` | WIZ credentials |
| **Black Duck** | `with-black-duck --url=... --token=...` | BlackDuck credentials |
| **Custom** | `with-custom-scanner --image=... --args=...` | Varies |
| **Disabled** | `without-scanner` | N/A |

### Scanner Examples

```bash
# Grype (open source, no auth)
dagger call scan --container=myapp:latest with-grype report

# Snyk (requires token)
dagger call scan --container=myapp:latest \
  with-snyk --token=env:SNYK_TOKEN \
  report

# Disable vulnerability scanning
dagger call scan --container=myapp:latest without-scanner report

# Custom scanner
dagger call scan --container=myapp:latest \
  with-custom-scanner \
    --image="my-scanner:latest" \
    --args='["scan", "-o", "json"]' \
    --output-format="trivy" \
  report
```

---

## Configuration

```bash
# Set severity threshold to CRITICAL only
dagger call scan --container=alpine:latest \
  fail-on --severity=CRITICAL \
  report

# Disable specific security checks
dagger call scan --container=alpine:latest \
  with-non-root-check --enable=false \
  with-secret-check --enable=false \
  report
```

---

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
      - name: Install Dagger
        uses: dagger/dagger-for-github@v5
      - name: Run Security Audit
        run: |
          dagger call -m github.com/sylvester-francis/Sentry \
            scan --container=${{ env.IMAGE }} \
            exit-code
```

### GitLab CI

```yaml
security_audit:
  image: docker:latest
  services:
    - docker:dind
  script:
    - curl -fsSL https://dl.dagger.io/dagger/install.sh | sh
    - dagger call -m github.com/sylvester-francis/Sentry \
        scan --container=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        exit-code
```

---

## API Reference

### Scanner Selection

| Method | Description |
|--------|-------------|
| `with-trivy` | Use Trivy scanner (default) |
| `with-grype` | Use Grype (Anchore) scanner |
| `with-snyk --token` | Use Snyk scanner |
| `with-wiz --client-id --client-secret` | Use Wiz scanner |
| `with-black-duck --url --token` | Use Black Duck scanner |
| `with-custom-scanner --image --args` | Use custom scanner |
| `without-scanner` | Disable vulnerability scanning |

### Configuration

| Method | Description |
|--------|-------------|
| `fail-on --severity` | Set minimum severity to fail (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `with-secret-check --enable` | Enable/disable secret detection |
| `with-non-root-check --enable` | Enable/disable non-root check |
| `with-health-check --enable` | Enable/disable health check verification |

### Output

| Method | Returns | Description |
|--------|---------|-------------|
| `report` | `string` | Markdown formatted report |
| `json` | `string` | JSON formatted report |
| `passed` | `bool` | Pass/fail status |
| `exit-code` | `int` | 0 (pass) or 1 (fail) |

---

## Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Non-Root User | HIGH | Verifies container runs as non-root |
| Secret Detection | HIGH | Scans env vars for AWS keys, GitHub tokens, JWTs, etc. |
| Health Check | INFO | Verifies curl/wget available for health checks |

---

## Sample Output

```
# Security Audit Report

## Executive Summary

┌─────────────────────────────────────────────────────────────┐
│  STATUS: PASSED                                             │
├─────────────────────────────────────────────────────────────┤
│  Score: 100/100                                             │
│  Checks: 3 passed, 0 failed                                 │
│  Vulnerabilities: 0 total (0 critical)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Development

```bash
# Run tests
dagger call test

# View available functions
dagger functions
dagger functions scan
```

---

## Requirements

- Dagger CLI v0.19.8+
- Docker daemon running

---

## License

MIT

---

<div align="center">

**Built with [Dagger](https://dagger.io)**

</div>