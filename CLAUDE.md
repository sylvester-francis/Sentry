# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sentry is a Dagger module written in Go that audits containers for security compliance. It fills a gap in the Daggerverse by aggregating security scan results into compliance-ready reports.

**Core Features:**
- Security checks (non-root user, secret detection in env vars, healthcheck verification)
- Trivy vulnerability scanning integration
- Markdown/JSON compliance report generation
- Pass/fail exit codes for CI integration

## Build Commands

```bash
# Initialize the Dagger module (first-time setup)
dagger init --sdk=go --name=Sentry

# Generate Dagger types after code changes
dagger develop

# List available functions
dagger functions

# Run security audit on a container
dagger call scan --container=<image> report      # Markdown report
dagger call scan --container=<image> json        # JSON report
dagger call scan --container=<image> passed      # Boolean pass/fail

# Run Go tests
go test -v ./...
go test -cover ./...
```

## Architecture

**Builder Pattern API:**
- `Scan(container)` → returns `AuditConfig`
- `WithTrivy(bool)` → enables/disables Trivy scanning
- `FailOn(severity)` → sets failure threshold (CRITICAL, HIGH, MEDIUM, LOW)
- `WithSecretCheck(bool)`, `WithNonRootCheck(bool)`, `WithHealthCheck(bool)` → toggle individual checks

**Data Types:**
- `Severity` enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `CheckStatus` enum: PASS, FAIL, WARN, SKIP
- `SecurityCheck`: individual check result with name, description, status, details, severity
- `Vulnerability`: package name, CVE ID, severity, installed/fixed versions
- `AuditResult`: aggregated results with timestamp, checks, vulnerabilities, pass status, score

**Trivy Integration:**
- Container is exported via `container.AsTarball()`
- Trivy runs in `aquasec/trivy:latest` container with mounted tarball
- JSON output parsed and aggregated into vulnerability summary

**Scoring:**
- Starts at 100, deducts for failed checks and vulnerabilities by severity
- Floor at 0

## Project Structure

```
Sentry/
├── dagger.json       # Dagger module config
├── main.go           # All module code
├── main_test.go      # Unit tests
├── go.mod
├── go.sum
└── README.md
```

## Key Implementation Notes

- Execute commands inside containers with fallbacks (e.g., `printenv` → `sh -c env`)
- Handle containers without shell or standard tools gracefully
- Secret detection uses regex patterns for AWS keys (AKIA...), GitHub tokens (ghp_...), JWTs, etc.
- Check both variable names AND values for sensitive patterns
- Healthcheck is heuristic-based (cannot directly access HEALTHCHECK instruction)
