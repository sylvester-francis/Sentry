// Sentry - Dagger module for container security auditing
// https://github.com/sylvester-francis/Sentry
// Licensed under MIT - see LICENSE file

// Package main provides type definitions for the Sentry container security
// audit module. It defines severity levels, check statuses, scanner types,
// and core data structures used throughout the module.
package main

// Severity represents the severity level of a security finding.
// It is used to classify both security check results and vulnerabilities.
type Severity string

// Severity constants define the classification levels for security findings.
// These follow industry-standard severity naming conventions.
const (
	// SeverityCritical indicates a critical security issue that requires
	// immediate attention and should block deployment.
	SeverityCritical Severity = "CRITICAL"

	// SeverityHigh indicates a high-priority security issue that should be
	// addressed before production deployment.
	SeverityHigh Severity = "HIGH"

	// SeverityMedium indicates a moderate security issue that should be
	// addressed in a timely manner.
	SeverityMedium Severity = "MEDIUM"

	// SeverityLow indicates a low-priority security issue that should be
	// tracked and addressed when convenient.
	SeverityLow Severity = "LOW"

	// SeverityInfo indicates an informational finding that does not represent
	// a security risk but may be worth noting.
	SeverityInfo Severity = "INFO"
)

// CheckStatus represents the result status of a security check.
// It indicates whether a check passed, failed, produced a warning, or was skipped.
type CheckStatus string

// CheckStatus constants define the possible outcomes of a security check.
const (
	// StatusPass indicates the security check passed successfully.
	StatusPass CheckStatus = "PASS"

	// StatusFail indicates the security check failed and requires attention.
	StatusFail CheckStatus = "FAIL"

	// StatusWarn indicates the security check produced a warning that should
	// be reviewed but may not require immediate action.
	StatusWarn CheckStatus = "WARN"

	// StatusSkip indicates the security check was skipped, typically due to
	// an error or missing prerequisites.
	StatusSkip CheckStatus = "SKIP"
)

// ScannerType represents supported vulnerability scanners
type ScannerType string

const (
	ScannerTrivy     ScannerType = "trivy"
	ScannerGrype     ScannerType = "grype"
	ScannerSnyk      ScannerType = "snyk"
	ScannerWiz       ScannerType = "wiz"
	ScannerBlackDuck ScannerType = "blackduck"
	ScannerCustom    ScannerType = "custom"
	ScannerNone      ScannerType = "none"
)

// ============================================================================
// SCANNER CONFIGURATION
// ============================================================================

// ScannerConfig holds configuration for a vulnerability scanner
type ScannerConfig struct {
	Type         ScannerType // Which scanner to use
	Image        string      // Container image for the scanner
	Args         []string    // Command arguments to run
	OutputFormat string      // Output format type for parsing
}

// ============================================================================
// DATA STRUCTURES - Core types for audit results
// ============================================================================

// SecurityCheck represents the result of a single security check
type SecurityCheck struct {
	Name        string      // e.g., "Non-Root User Check"
	Description string      // e.g., "Verifies container runs as non-root"
	Status      CheckStatus // PASS, FAIL, WARN, SKIP
	Details     string      // Additional context or findings
	Severity    Severity    // How critical is this check
}

// Vulnerability represents a single CVE finding from a scanner
type Vulnerability struct {
	PackageName      string   // e.g., "openssl"
	CVEID            string   // e.g., "CVE-2023-12345"
	Severity         Severity // CRITICAL, HIGH, etc.
	InstalledVersion string   // Currently installed version
	FixedVersion     string   // Version with the fix (if available)
}

// VulnerabilitySummary aggregates vulnerability counts by severity
type VulnerabilitySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
}

// AuditResult contains the complete security audit output
type AuditResult struct {
	Timestamp       string               // RFC3339 formatted timestamp
	ImageRef        string               // Container image reference
	ScannerUsed     string               // Which scanner was used
	Checks          []SecurityCheck      // Results of security checks
	Vulnerabilities []Vulnerability      // List of CVEs found
	VulnSummary     VulnerabilitySummary // Aggregated vuln counts
	Passed          bool                 // Overall pass/fail status
	Score           int                  // Security score (0-100)
}
