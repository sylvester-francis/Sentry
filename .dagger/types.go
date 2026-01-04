// Package main contains the type definitions for the Sentry security audit module
package main

// ============================================================================
// ENUMS - String-based enums for type safety
// ============================================================================

// Severity represents the severity level of a security finding
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// CheckStatus represents the result status of a security check
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusFail CheckStatus = "FAIL"
	StatusWarn CheckStatus = "WARN"
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
