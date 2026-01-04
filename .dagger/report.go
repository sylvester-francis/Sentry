// Package main contains report generation for the Sentry security audit module
package main

import (
	"context"
	"encoding/json"
	"time"
)

// ============================================================================
// SCORING ALGORITHM
// ============================================================================

// calculateScore computes a security score from 0-100 based on checks and vulnerabilities
func calculateScore(checks []SecurityCheck, vulnSummary VulnerabilitySummary) int {
	score := 100

	// Deduct for failed security checks
	for _, check := range checks {
		if check.Status == StatusFail {
			switch check.Severity {
			case SeverityCritical:
				score -= 25
			case SeverityHigh:
				score -= 15
			case SeverityMedium:
				score -= 10
			case SeverityLow:
				score -= 5
			}
		} else if check.Status == StatusWarn {
			score -= 3
		}
	}

	// Deduct for vulnerabilities
	score -= vulnSummary.Critical * 10
	score -= vulnSummary.High * 5
	score -= vulnSummary.Medium * 2
	score -= vulnSummary.Low * 1

	// Floor at 0
	if score < 0 {
		score = 0
	}

	return score
}

// ============================================================================
// MAIN AUDIT FUNCTION
// ============================================================================

// Audit runs the complete security audit and returns the result
func (c *AuditConfig) Audit(ctx context.Context) (*AuditResult, error) {
	result := &AuditResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ImageRef:  "container", // Default, could extract from container metadata
	}

	// Run security checks
	result.Checks = runSecurityChecks(ctx, c.Container, c)

	// Run Trivy vulnerability scan if enabled
	if c.EnableTrivy {
		vulns, summary, err := runTrivy(ctx, c.Container)
		if err == nil {
			result.Vulnerabilities = vulns
			result.VulnSummary = summary
		}
	}

	// Calculate score
	result.Score = calculateScore(result.Checks, result.VulnSummary)

	// Determine pass/fail status
	result.Passed = true
	for _, check := range result.Checks {
		if check.Status == StatusFail {
			result.Passed = false
			break
		}
	}
	if c.EnableTrivy && exceedsThreshold(result.Vulnerabilities, c.FailOnSeverity) {
		result.Passed = false
	}

	return result, nil
}

// ============================================================================
// REPORT OUTPUTS
// ============================================================================

// Report generates a Markdown security audit report
func (c *AuditConfig) Report(ctx context.Context) (string, error) {
	result, err := c.Audit(ctx)
	if err != nil {
		return "", err
	}

	return generateMarkdownReport(result), nil
}

// Json generates a JSON security audit report
func (c *AuditConfig) Json(ctx context.Context) (string, error) {
	result, err := c.Audit(ctx)
	if err != nil {
		return "", err
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// Passed returns true if the audit passed all checks
func (c *AuditConfig) Passed(ctx context.Context) (bool, error) {
	result, err := c.Audit(ctx)
	if err != nil {
		return false, err
	}
	return result.Passed, nil
}

// ExitCode returns 0 if passed, 1 if failed (for CI integration)
func (c *AuditConfig) ExitCode(ctx context.Context) (int, error) {
	passed, err := c.Passed(ctx)
	if err != nil {
		return 1, err
	}
	if passed {
		return 0, nil
	}
	return 1, nil
}

// ============================================================================
// MARKDOWN REPORT GENERATION
// ============================================================================

// generateMarkdownReport creates a formatted Markdown audit report
func generateMarkdownReport(result *AuditResult) string {
	var sb stringBuilder

	// Header
	sb.write("# Security Audit Report\n\n")

	// Executive Summary Card
	sb.write("## Executive Summary\n\n")
	sb.write("```\n")
	if result.Passed {
		sb.write("┌─────────────────────────────────────────────────────────────┐\n")
		sb.write("│  STATUS: PASSED                                             │\n")
	} else {
		sb.write("┌─────────────────────────────────────────────────────────────┐\n")
		sb.write("│  STATUS: FAILED                                             │\n")
	}
	sb.write("├─────────────────────────────────────────────────────────────┤\n")
	sb.write("│  Score: " + padRight(intToStr(result.Score)+"/100", 52) + "│\n")
	sb.write("│  Timestamp: " + padRight(result.Timestamp, 48) + "│\n")
	sb.write("│  Image: " + padRight(truncate(result.ImageRef, 50), 52) + "│\n")
	sb.write("├─────────────────────────────────────────────────────────────┤\n")
	sb.write("│  Checks: " + padRight(intToStr(countByStatus(result.Checks, StatusPass))+" passed, "+intToStr(countByStatus(result.Checks, StatusFail))+" failed", 51) + "│\n")
	sb.write("│  Vulnerabilities: " + padRight(intToStr(result.VulnSummary.Total)+" total ("+intToStr(result.VulnSummary.Critical)+" critical)", 42) + "│\n")
	sb.write("└─────────────────────────────────────────────────────────────┘\n")
	sb.write("```\n\n")

	// Security Checks Card
	sb.write("---\n\n")
	sb.write("## Security Checks\n\n")
	for _, check := range result.Checks {
		sb.write("> **" + check.Name + "**\n")
		sb.write("> \n")
		sb.write("> - Status: `" + string(check.Status) + "`\n")
		sb.write("> - Severity: " + string(check.Severity) + "\n")
		sb.write("> - Details: " + check.Details + "\n")
		sb.write("\n")
	}

	// Vulnerability Summary Card
	sb.write("---\n\n")
	sb.write("## Vulnerability Summary\n\n")
	sb.write("```\n")
	sb.write("Critical:  " + padLeft(intToStr(result.VulnSummary.Critical), 5) + "  " + barGraph(result.VulnSummary.Critical, result.VulnSummary.Total) + "\n")
	sb.write("High:      " + padLeft(intToStr(result.VulnSummary.High), 5) + "  " + barGraph(result.VulnSummary.High, result.VulnSummary.Total) + "\n")
	sb.write("Medium:    " + padLeft(intToStr(result.VulnSummary.Medium), 5) + "  " + barGraph(result.VulnSummary.Medium, result.VulnSummary.Total) + "\n")
	sb.write("Low:       " + padLeft(intToStr(result.VulnSummary.Low), 5) + "  " + barGraph(result.VulnSummary.Low, result.VulnSummary.Total) + "\n")
	sb.write("─────────────────────\n")
	sb.write("Total:     " + padLeft(intToStr(result.VulnSummary.Total), 5) + "\n")
	sb.write("```\n\n")

	// Top Vulnerabilities Card (if any)
	if len(result.Vulnerabilities) > 0 {
		sb.write("---\n\n")
		sb.write("## Top Vulnerabilities\n\n")
		count := 0
		for _, v := range result.Vulnerabilities {
			if count >= 5 {
				break
			}
			fixedVer := v.FixedVersion
			if fixedVer == "" {
				fixedVer = "No fix available"
			}
			sb.write("> **" + v.CVEID + "**\n")
			sb.write("> \n")
			sb.write("> - Package: `" + v.PackageName + "`\n")
			sb.write("> - Severity: " + string(v.Severity) + "\n")
			sb.write("> - Installed: " + v.InstalledVersion + "\n")
			sb.write("> - Fixed: " + fixedVer + "\n")
			sb.write("\n")
			count++
		}
		if len(result.Vulnerabilities) > 5 {
			sb.write("*... and " + intToStr(len(result.Vulnerabilities)-5) + " more vulnerabilities*\n\n")
		}
	}

	// Recommendations Card
	sb.write("---\n\n")
	sb.write("## Recommendations\n\n")
	hasRecs := false
	for _, check := range result.Checks {
		if check.Status == StatusFail {
			sb.write("1. **" + check.Name + "**: " + check.Details + "\n")
			hasRecs = true
		}
	}
	for _, check := range result.Checks {
		if check.Status == StatusWarn {
			sb.write("2. **" + check.Name + "** (Warning): " + check.Details + "\n")
			hasRecs = true
		}
	}
	if result.VulnSummary.Critical > 0 {
		sb.write("1. **Critical Vulnerabilities**: Address " + intToStr(result.VulnSummary.Critical) + " critical vulnerabilities immediately\n")
		hasRecs = true
	}
	if result.VulnSummary.High > 0 {
		sb.write("2. **High Vulnerabilities**: Review and patch " + intToStr(result.VulnSummary.High) + " high-severity vulnerabilities\n")
		hasRecs = true
	}
	if !hasRecs {
		sb.write("No immediate actions required. All checks passed.\n")
	}
	sb.write("\n")

	// Footer
	sb.write("---\n\n")
	sb.write("*Report generated by Sentry v0.0.1*\n")

	return sb.String()
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// stringBuilder is a simple string builder to avoid importing strings
type stringBuilder struct {
	data string
}

func (sb *stringBuilder) write(s string) {
	sb.data += s
}

func (sb *stringBuilder) String() string {
	return sb.data
}

// statusBadge returns a badge for pass/fail status
func statusBadge(passed bool) string {
	if passed {
		return "PASSED"
	}
	return "FAILED"
}

// statusIcon returns an icon for check status
func statusIcon(status CheckStatus) string {
	switch status {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusWarn:
		return "WARN"
	case StatusSkip:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

// truncate shortens a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// intToStr converts an int to a string
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n = n / 10
	}
	if negative {
		digits = "-" + digits
	}
	return digits
}

// padRight pads a string to the right with spaces to reach width
func padRight(s string, width int) string {
	for len(s) < width {
		s = s + " "
	}
	return s
}

// padLeft pads a string to the left with spaces to reach width
func padLeft(s string, width int) string {
	for len(s) < width {
		s = " " + s
	}
	return s
}

// countByStatus counts checks with a specific status
func countByStatus(checks []SecurityCheck, status CheckStatus) int {
	count := 0
	for _, c := range checks {
		if c.Status == status {
			count++
		}
	}
	return count
}

// barGraph generates a simple ASCII bar graph
func barGraph(value, total int) string {
	if total == 0 || value == 0 {
		return ""
	}
	maxBars := 20
	bars := (value * maxBars) / total
	if bars == 0 && value > 0 {
		bars = 1
	}
	result := ""
	for i := 0; i < bars; i++ {
		result += "█"
	}
	return result
}
