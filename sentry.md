# 🔒 Sentry v0.0.1 - Build Guide

> **Time Budget:** 6 hours  
> **Goal:** A Dagger module that audits containers for security compliance  
> **Output:** Published module on Daggerverse

---

## What You're Building

**Sentry** fills a gap in the Daggerverse: scanners exist (Trivy, Grype), but nothing aggregates results into compliance-ready reports.

### Core Features
- Security checks (non-root user, secret detection, healthcheck)
- Trivy vulnerability scanning integration
- Markdown/JSON compliance reports
- Pass/fail exit codes for CI integration

### Interview Talking Points
- "I identified a gap in the ecosystem and filled it"
- "Security teams need audit trails, not just scan outputs"
- "Combines multiple security signals into one actionable report"

---

## Hour-by-Hour Roadmap

| Hour | Focus | Milestone |
|------|-------|-----------|
| **1** | Setup & Types | Module scaffold, data structures defined |
| **2** | Container Inspection | Extract env vars, detect user, get metadata |
| **3** | Security Checks | Secret patterns, non-root check, healthcheck |
| **4** | Trivy Integration | Run scanner, parse JSON, aggregate results |
| **5** | Report Generation | Markdown output, JSON export, scoring |
| **6** | Tests & Polish | Unit tests, README, publish prep |

---

## Pre-Flight Checklist

Before starting:
- [ ] Dagger CLI installed (v0.9.0+)
- [ ] Go 1.21+ installed
- [ ] Docker running
- [ ] GitHub repo created for the module

---

# Hour 1: Setup & Foundation

## Tasks

1. **Initialize the Dagger module**
   - Run `dagger init --sdk=go --name=Sentry`
   - This creates `dagger.json`, `main.go`, `go.mod`

2. **Define your data structures**
   - `Severity` enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
   - `CheckStatus` enum: PASS, FAIL, WARN, SKIP
   - `SecurityCheck` struct: name, description, status, details, severity
   - `Vulnerability` struct: package, CVE ID, severity, versions
   - `VulnerabilitySummary` struct: counts by severity
   - `AuditResult` struct: timestamp, checks, vulns, passed, score
   - `AuditConfig` struct: container ref + all config options

3. **Create the builder pattern API**
   - `Scan(container)` → returns AuditConfig
   - `WithTrivy(bool)` → enables/disables Trivy
   - `FailOn(severity)` → sets failure threshold
   - `WithSecretCheck(bool)` → enables/disables secret scanning
   - `WithNonRootCheck(bool)` → enables/disables root check
   - `WithHealthCheck(bool)` → enables/disables healthcheck

4. **Verify setup**
   - Run `dagger develop` to generate types
   - Run `dagger functions` to see your API

## Hour 1 Checkpoint
- [ ] Module initializes without errors
- [ ] All types compile
- [ ] `dagger functions` shows `scan` function

## If Stuck - AI Prompts
- "Explain the builder pattern in Go with a simple example"
- "What's the difference between *Container and Container in Dagger?"
- "How do I define string enums in Go?"

---

# Hour 2: Container Inspection

## Tasks

1. **Extract environment variables**
   - Execute `printenv` inside the container
   - Fallback to `sh -c env` if printenv missing
   - Parse KEY=VALUE format into a map
   - Handle containers without shell gracefully

2. **Detect running user**
   - Execute `id` command inside container
   - Fallback to `whoami` if id missing
   - Parse output to determine if root (uid=0)
   - Handle missing commands gracefully

3. **Extract image metadata**
   - Repository name, tag
   - Image size (if accessible)
   - Layer count (informational)

## Hour 2 Checkpoint
- [ ] Can extract env vars from alpine container
- [ ] Can detect user from alpine container
- [ ] Gracefully handles containers without standard tools

## If Stuck - AI Prompts
- "How do I execute a command inside a Dagger container and get stdout?"
- "What's the idiomatic way to handle errors in Go when a command might not exist?"
- "How do I parse environment variables from a string in Go?"

---

# Hour 3: Security Checks

## Tasks

1. **Secret detection in environment variables**
   - Define regex patterns for common secrets:
     - AWS access keys (AKIA...)
     - GitHub tokens (ghp_...)
     - Generic API keys, passwords, tokens
     - Database connection strings
     - JWTs
     - Private key headers
   - Check both variable names AND values
   - Flag sensitive variable names (PASSWORD, SECRET, KEY, TOKEN)
   - Return list of findings with pattern matched

2. **Non-root user check**
   - Use the user detection from Hour 2
   - Check for uid=0 or "root" in output
   - PASS if non-root, FAIL if root

3. **Healthcheck verification**
   - Note: Actual HEALTHCHECK instruction isn't directly accessible
   - Use heuristic: check for common health endpoints
   - Mark as WARN if not detected (informational)

4. **Additional informational checks**
   - Read-only filesystem recommendation
   - No-new-privileges recommendation
   - These are STATUS=INFO, not pass/fail

5. **Create orchestrator function**
   - `runSecurityChecks()` that runs all enabled checks
   - Returns slice of SecurityCheck results
   - Respects config flags (CheckSecrets, CheckNonRoot, etc.)

## Hour 3 Checkpoint
- [ ] Secret detection catches AWS keys, GitHub tokens
- [ ] Non-root check correctly identifies root vs non-root
- [ ] All checks return proper SecurityCheck structs

## If Stuck - AI Prompts
- "How do I compile regex patterns at package level in Go?"
- "What regex pattern matches AWS access keys?"
- "How do I check if a string contains any of multiple substrings in Go?"

---

# Hour 4: Trivy Integration

## Tasks

1. **Export container for scanning**
   - Use `container.AsTarball()` to get exportable format
   - This creates a tar archive Trivy can scan

2. **Run Trivy in a container**
   - Pull `aquasec/trivy:latest`
   - Mount the tarball at `/image.tar`
   - Execute: `trivy image --input /image.tar --format json --quiet`
   - Capture stdout

3. **Parse Trivy JSON output**
   - Define structs matching Trivy's JSON schema
   - Handle empty results gracefully
   - Handle malformed JSON gracefully
   - Extract: package name, CVE ID, severity, installed/fixed versions

4. **Aggregate vulnerabilities**
   - Convert Trivy results to your Vulnerability structs
   - Count by severity into VulnerabilitySummary
   - Store full list for detailed reporting

5. **Threshold checking**
   - Implement `exceedsThreshold()` function
   - If FailOn=CRITICAL, only fail on critical vulns
   - If FailOn=HIGH, fail on critical OR high
   - And so on for MEDIUM, LOW

## Hour 4 Checkpoint
- [ ] Trivy runs successfully against alpine:latest
- [ ] JSON parsing extracts vulnerabilities correctly
- [ ] Threshold logic works as expected

## If Stuck - AI Prompts
- "How do I mount a Dagger File into another Container?"
- "How do I unmarshal JSON with optional fields in Go?"
- "Trivy returns empty JSON for some images - how do I handle this?"

---

# Hour 5: Report Generation

## Tasks

1. **Main Audit() function**
   - Orchestrate: metadata → security checks → Trivy scan
   - Aggregate all results into AuditResult
   - Determine overall pass/fail status
   - Calculate security score

2. **Scoring algorithm**
   - Start at 100 points
   - Deduct for failed checks (by severity)
   - Deduct for vulnerabilities (by severity)
   - Floor at 0

3. **Markdown report generator**
   - Header with status (PASSED/FAILED), score, timestamp
   - Image information table
   - Security checks table with status icons
   - Vulnerability summary table
   - Top 10 critical/high findings
   - Recommendations section
   - Footer with version

4. **JSON export**
   - Simply marshal AuditResult to JSON
   - Use indented format for readability

5. **CI-friendly outputs**
   - `Passed()` → returns bool
   - `ExitCode()` → returns 0 (pass) or 1 (fail)

## Hour 5 Checkpoint
- [ ] Full audit runs end-to-end
- [ ] Markdown report looks professional
- [ ] JSON export is valid and complete
- [ ] Exit codes work correctly

## If Stuck - AI Prompts
- "How do I build a string efficiently in Go for large outputs?"
- "How do I format a Go time.Time as RFC3339?"
- "What's a good security scoring algorithm for container audits?"

---

# Hour 6: Tests & Polish

## Tasks

1. **Unit tests**
   - Test `parseSeverity()` with various inputs
   - Test `calculateScore()` with different scenarios
   - Test secret regex patterns (true positives AND negatives)
   - Test `truncate()` helper
   - Test `getStatusIcon()` helper
   - Test `exceedsThreshold()` logic

2. **Run tests**
   - `go test -v ./...`
   - `go test -cover ./...` for coverage
   - Aim for >70% coverage on core logic

3. **Create README.md**
   - Project description and value prop
   - Installation instructions
   - Usage examples (basic and advanced)
   - Configuration options table
   - Output format examples
   - License

4. **Manual testing**
   - Test against `alpine:latest` (minimal, likely clean)
   - Test against `python:3.8-slim` (has some vulns)
   - Test against `nginx:latest` (different base)
   - Verify reports look correct

5. **Prepare for publishing**
   - Ensure all functions are documented
   - Run `dagger develop` one final time
   - Create git tag: `git tag v0.0.1`

## Hour 6 Checkpoint
- [ ] All unit tests pass
- [ ] README is complete and professional
- [ ] Tested against 3+ different images
- [ ] Ready to publish

## If Stuck - AI Prompts
- "How do I write table-driven tests in Go?"
- "What should I include in a README for a Dagger module?"
- "How do I publish a module to Daggerverse?"

---

# Quick Reference

## Dagger Commands
```
dagger init --sdk=go --name=Sentry
dagger develop
dagger functions
dagger call scan --container=alpine:latest report
dagger call scan --container=IMAGE json
dagger call scan --container=IMAGE passed
```

## Go Commands
```
go test -v ./...
go test -cover ./...
go fmt ./...
```

## Project Structure
```
Sentry/
├── dagger.json       # Module config
├── main.go           # All module code
├── main_test.go      # Unit tests
├── go.mod
├── go.sum
└── README.md
```

---

# Publishing to Daggerverse

When ready:

1. Push code to GitHub
2. Tag release: `git tag v0.0.1 && git push origin v0.0.1`
3. Module becomes available at: `github.com/YOUR_USERNAME/Sentry`

Users can then install with:
```
dagger install github.com/YOUR_USERNAME/Sentry
```

---

# Troubleshooting

| Problem | Solution |
|---------|----------|
| `dagger develop` fails | Check Dagger version, update if needed |
| Trivy returns empty | Normal for minimal images, handle gracefully |
| Context deadline exceeded | Increase timeout with `--timeout=600s` |
| Container has no shell | Handle error, skip checks that require exec |
| JSON parse error | Check for empty response, handle edge cases |

---

# Success Criteria

Before calling it done:

- [ ] `dagger functions` shows all expected functions
- [ ] `dagger call scan --container=alpine:latest report` produces markdown
- [ ] `dagger call scan --container=alpine:latest json` produces valid JSON
- [ ] `dagger call scan --container=alpine:latest passed` returns true/false
- [ ] Unit tests pass with >70% coverage
- [ ] README explains usage clearly
- [ ] Code is committed and tagged

---

# What You've Built

A production-ready Dagger module that:

1. **Inspects containers** for security best practices
2. **Scans for vulnerabilities** via Trivy integration
3. **Generates reports** in Markdown and JSON
4. **Integrates with CI** via exit codes
5. **Is configurable** with severity thresholds

**Portfolio value:** Demonstrates security awareness, Go proficiency, and ecosystem contribution.

---

**Now go build it! 🚀**
