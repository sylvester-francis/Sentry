# Sentry

<div align="center">

<pre>
███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
</pre>

**Container Security Auditing for CI/CD Pipelines**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![Dagger](https://img.shields.io/badge/Dagger-0.19+-131313?style=flat&logo=dagger&logoColor=white)](https://dagger.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Daggerverse](https://img.shields.io/badge/Daggerverse-Sentry-6366F1?style=flat&logo=dagger&logoColor=white)](https://daggerverse.dev/mod/github.com/sylvester-francis/Sentry)

[![Trivy](https://img.shields.io/badge/Trivy-Scanner-1904DA?style=flat&logo=aqua&logoColor=white)](https://trivy.dev/)
[![Grype](https://img.shields.io/badge/Grype-Scanner-E31C3D?style=flat&logo=anchore&logoColor=white)](https://github.com/anchore/grype)
[![Snyk](https://img.shields.io/badge/Snyk-Scanner-4C4A73?style=flat&logo=snyk&logoColor=white)](https://snyk.io/)
[![Wiz](https://img.shields.io/badge/Wiz-Scanner-00D1B2?style=flat)](https://wiz.io/)
[![Black Duck](https://img.shields.io/badge/Black%20Duck-Scanner-000000?style=flat)](https://www.synopsys.com/software-integrity/security-testing/software-composition-analysis.html)

[Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#usage-guide) • [CI/CD Integration](#cicd-integration)

</div>

---

## What is Sentry?

Sentry is a security auditing tool that scans your container images for vulnerabilities and misconfigurations. It integrates with your CI/CD pipeline to automatically check containers before deployment.

**Key Features:**
- **Multi-Scanner Support** — Trivy, Grype, Snyk, Wiz, or Black Duck
- **Security Checks** — Non-root user, secret detection, healthcheck validation
- **Reports** — Markdown summaries, JSON for automation, 0-100 security scores
- **CI/CD Gates** — Pass/fail exit codes to block vulnerable deployments

---

## What is Dagger?

[Dagger](https://dagger.io) is a programmable CI/CD engine that runs your pipelines in containers. Instead of writing YAML, you write code in Go, Python, or TypeScript.

**Why Dagger?**
- **Portable** — Same pipeline runs locally and in any CI (GitHub Actions, GitLab, Jenkins)
- **Fast** — Intelligent caching speeds up builds
- **Reproducible** — Containers ensure consistent environments

Sentry is a **Dagger Module** — a reusable component you can call from any Dagger pipeline.

---

## Installation

### Prerequisites

1. **Docker** — [Install Docker](https://docs.docker.com/get-docker/)
2. **Dagger CLI** — Install with one command:

```bash
# macOS / Linux
curl -fsSL https://dl.dagger.io/dagger/install.sh | sh

# Windows (PowerShell)
Invoke-WebRequest -Uri https://dl.dagger.io/dagger/install.ps1 -OutFile install.ps1; .\install.ps1
```

Verify installation:
```bash
dagger version
```

### No Additional Setup Required

Sentry runs directly from the Daggerverse — no cloning or installing needed.

---

## Quick Start

### Your First Scan

Scan any container image with a single command:

```bash
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=nginx:latest \
  report
```

**Output:**
```
# Security Audit Report

## Executive Summary

┌─────────────────────────────────────────────────────────────┐
│  STATUS: PASSED                                             │
├─────────────────────────────────────────────────────────────┤
│  Score: 85/100                                              │
│  Checks: 2 passed, 1 warning                                │
│  Vulnerabilities: 12 total (0 critical, 2 high)             │
└─────────────────────────────────────────────────────────────┘
```

### Common Use Cases

**Get a pass/fail result for CI pipelines:**
```bash
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  exit-code
# Returns 0 (pass) or 1 (fail)
```

**Get JSON output for automation:**
```bash
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  json
```

**Get just the security score:**
```bash
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  score
# Returns: 85
```

---

## Usage Guide

### Choosing a Scanner

Sentry supports multiple vulnerability scanners. Default is **Trivy**.

| Scanner | Command | Auth Required |
|---------|---------|---------------|
| Trivy (default) | `with-trivy` | No |
| Grype | `with-grype` | No |
| Snyk | `with-snyk --token=env:SNYK_TOKEN` | Yes |
| Wiz | `with-wiz --client-id=... --client-secret=...` | Yes |
| Black Duck | `with-black-duck --url=... --token=...` | Yes |

**Example: Use Grype instead of Trivy**
```bash
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-grype \
  report
```

**Example: Use Snyk with authentication**
```bash
export SNYK_TOKEN=your-token-here
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-snyk --token=env:SNYK_TOKEN \
  report
```

### Setting Failure Thresholds

Control when the audit fails based on vulnerability severity:

```bash
# Fail only on CRITICAL vulnerabilities (lenient)
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  fail-on --severity=CRITICAL \
  exit-code

# Fail on HIGH or above (default)
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  fail-on --severity=HIGH \
  exit-code

# Fail on MEDIUM or above (strict)
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  fail-on --severity=MEDIUM \
  exit-code
```

### Ignoring Known CVEs

Suppress specific CVEs (for accepted risks or false positives):

```bash
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  ignore-cves --cve-ids=CVE-2024-1234,CVE-2024-5678 \
  report
```

### Disabling Specific Checks

```bash
# Skip non-root check (for containers that must run as root)
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-non-root-check --enable=false \
  report

# Skip secret detection
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  with-secret-check --enable=false \
  report

# Run security checks only (no vulnerability scanning)
dagger call -m github.com/sylvester-francis/Sentry \
  scan --container=myapp:latest \
  without-scanner \
  report
```

---

## Security Checks

Sentry performs these automated security checks:

| Check | Severity | Description |
|-------|----------|-------------|
| **Non-Root User** | HIGH | Verifies container doesn't run as root (UID 0) |
| **Secret Detection** | HIGH | Scans environment variables for exposed credentials |
| **Health Check** | INFO | Verifies `curl` or `wget` is available for health probes |

### Secret Detection Patterns

Sentry detects these credential patterns in environment variables:
- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_`, `gho_`, `ghs_`, `ghr_`)
- JWT Tokens (`eyJ...`)
- Private Keys (`-----BEGIN...`)
- Database URLs with credentials
- Slack Tokens, API Keys

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
        run: curl -fsSL https://dl.dagger.io/dagger/install.sh | sh

      - name: Run Security Audit
        run: |
          ./bin/dagger call -m github.com/sylvester-francis/Sentry \
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
    - ./bin/dagger call -m github.com/sylvester-francis/Sentry \
        scan --container=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        exit-code
```

### Using in Your Dagger Module

Call Sentry from your own Dagger pipeline code:

```go
package main

import (
    "context"
    "dagger/mymodule/internal/dagger"
)

type MyModule struct{}

func (m *MyModule) Build(ctx context.Context) (*dagger.Container, error) {
    container := dag.Container().
        From("golang:1.21").
        // ... build steps ...

    // Run security audit before deploying
    result, err := dag.Sentry().
        Scan(container).
        FailOn("HIGH").
        Report(ctx)
    
    if err != nil {
        return nil, err
    }
    
    return container, nil
}
```

---

## Output Formats

### Markdown Report (`report`)

Human-readable report with executive summary, vulnerability breakdown, and check results.

### JSON Report (`json`)

Machine-readable format for automation and integration:

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
    "high": 2,
    "medium": 5,
    "low": 5,
    "total": 12
  }
}
```

### Security Score (`score`)

0-100 score based on findings. Deductions:
- CRITICAL vulnerability: -10 points
- HIGH vulnerability: -5 points  
- MEDIUM vulnerability: -2 points
- Failed security check: -15 to -25 points

---

## Command Reference

| Command | Description |
|---------|-------------|
| `scan --container=<image>` | Start audit for a container |
| `scan-image --image-ref=<ref>` | Start audit from image reference string |
| `with-trivy` / `with-grype` / `with-snyk` | Select vulnerability scanner |
| `fail-on --severity=<level>` | Set failure threshold (CRITICAL/HIGH/MEDIUM/LOW) |
| `ignore-cves --cve-ids=<list>` | Suppress specific CVE IDs |
| `with-secret-check --enable=<bool>` | Enable/disable secret detection |
| `with-non-root-check --enable=<bool>` | Enable/disable non-root check |
| `report` | Generate Markdown report |
| `json` | Generate JSON report |
| `score` | Get numeric security score (0-100) |
| `summary` | Get one-line status summary |
| `passed` | Get boolean pass/fail |
| `exit-code` | Get CI exit code (0=pass, 1=fail) |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Scanner returns empty results | Normal for minimal images (e.g., `scratch`, `distroless`) |
| "Container running as root" | Add `USER nobody` to your Dockerfile |
| "No curl/wget found" | Add health check tools or disable check with `--with-health-check=false` |
| 401 Unauthorized | Refresh your scanner authentication token |

---

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

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `dagger call test`
5. Open a Pull Request

---

## Links

- [GitHub Repository](https://github.com/sylvester-francis/Sentry)
- [Daggerverse](https://daggerverse.dev/mod/github.com/sylvester-francis/Sentry)
- [Dagger Documentation](https://docs.dagger.io/)
- [Report Issues](https://github.com/sylvester-francis/Sentry/issues)

---

<div align="center">

**Built with [Dagger](https://dagger.io)**

</div>
