// Sentry - Container Security Auditing for Dagger Pipelines
//
// Sentry audits container images for security vulnerabilities and misconfigurations.
// It integrates multiple vulnerability scanners (Trivy, Grype, Snyk, Wiz, Black Duck),
// performs security best practice checks, and generates compliance-ready reports.
//
// Features:
//   - Multi-Scanner Support: Trivy (default), Grype, Snyk, Wiz, Black Duck, or custom scanners
//   - Security Checks: Non-root user verification, secret detection, healthcheck validation
//   - Multiple Report Formats: Markdown reports with executive summary, JSON for automation
//   - Security Scoring: 0-100 score based on findings
//   - CI/CD Integration: Pass/fail exit codes for pipeline gates
//   - Configurable Thresholds: Fail on CRITICAL, HIGH, MEDIUM, or LOW severity
//
// Quick Start:
//
//	# Basic audit with Trivy (default)
//	dagger call scan --container=nginx:latest report
//
//	# Use Grype scanner
//	dagger call scan --container=myapp:latest with-grype report
//
//	# Get JSON output
//	dagger call scan --container=myapp:latest json
//
//	# CI/CD exit code (0=pass, 1=fail)
//	dagger call scan --container=myapp:latest exit-code
//
//	# Configure failure threshold
//	dagger call scan --container=myapp:latest fail-on --severity=CRITICAL report
//
// GitHub: https://github.com/sylvester-francis/Sentry
// License: MIT
package main

import (
	"dagger/sentry/internal/dagger"
)

// ============================================================================
// BUILDER PATTERN - Fluent API for configuring audits
// ============================================================================

// AuditConfig holds the configuration for a security audit
type AuditConfig struct {
	Container      *dagger.Container // The container to audit
	Scanner        ScannerConfig     // Vulnerability scanner configuration
	FailOnSeverity Severity          // Fail if vulns >= this severity
	CheckSecrets   bool              // Check for secrets in env vars
	CheckNonRoot   bool              // Check for non-root user
	CheckHealth    bool              // Check for healthcheck
}

// ============================================================================
// MODULE ENTRY POINT
// ============================================================================

// Sentry is the main module struct for container security auditing
type Sentry struct{}

// Scan initializes a security audit for the given container
// Returns an AuditConfig that can be further configured with chain methods
// Default scanner is Trivy
func (m *Sentry) Scan(
	// +required
	container *dagger.Container, // Container image to audit for security vulnerabilities
) *AuditConfig {
	return &AuditConfig{
		Container:      container,
		Scanner:        getTrivyConfig(), // Trivy is default
		FailOnSeverity: SeverityHigh,
		CheckSecrets:   true,
		CheckNonRoot:   true,
		CheckHealth:    true,
	}
}

// ============================================================================
// SCANNER SELECTION METHODS
// ============================================================================

// WithTrivy uses Trivy as the vulnerability scanner (default)
func (c *AuditConfig) WithTrivy() *AuditConfig {
	c.Scanner = getTrivyConfig()
	return c
}

// WithGrype uses Grype (Anchore) as the vulnerability scanner
func (c *AuditConfig) WithGrype() *AuditConfig {
	c.Scanner = getGrypeConfig()
	return c
}

// WithSnyk uses Snyk as the vulnerability scanner
// Requires SNYK_TOKEN environment variable
func (c *AuditConfig) WithSnyk(
	// +required
	token *dagger.Secret, // Snyk authentication token (env:SNYK_TOKEN)
) *AuditConfig {
	c.Scanner = getSnykConfig(token)
	return c
}

// WithWiz uses Wiz as the vulnerability scanner
// Requires WIZ_CLIENT_ID and WIZ_CLIENT_SECRET
func (c *AuditConfig) WithWiz(
	// +required
	clientId *dagger.Secret, // Wiz client ID credential
	// +required
	clientSecret *dagger.Secret, // Wiz client secret credential
) *AuditConfig {
	c.Scanner = getWizConfig(clientId, clientSecret)
	return c
}

// WithBlackDuck uses Black Duck as the vulnerability scanner
// Requires BLACKDUCK_URL and BLACKDUCK_API_TOKEN
func (c *AuditConfig) WithBlackDuck(
	// +required
	url string, // Black Duck server URL
	// +required
	token *dagger.Secret, // Black Duck API token
) *AuditConfig {
	c.Scanner = getBlackDuckConfig(url, token)
	return c
}

// WithCustomScanner uses a custom scanner container
// You provide the container image, command args, and output format for parsing
func (c *AuditConfig) WithCustomScanner(
	// +required
	image string, // Scanner container image (e.g., "aquasec/trivy:latest")
	// +required
	args []string, // Command arguments to pass to the scanner
	// +optional
	// +default="trivy"
	outputFormat string, // Output format for parsing (trivy, grype, snyk, etc.)
) *AuditConfig {
	c.Scanner = ScannerConfig{
		Type:         ScannerCustom,
		Image:        image,
		Args:         args,
		OutputFormat: outputFormat,
	}
	return c
}

// WithoutScanner disables vulnerability scanning entirely
func (c *AuditConfig) WithoutScanner() *AuditConfig {
	c.Scanner = ScannerConfig{Type: ScannerNone}
	return c
}

// ============================================================================
// CONFIGURATION METHODS
// ============================================================================

// FailOn sets the minimum severity that causes the audit to fail
func (c *AuditConfig) FailOn(
	// +required
	severity Severity, // Minimum severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
) *AuditConfig {
	c.FailOnSeverity = severity
	return c
}

// WithSecretCheck enables or disables secret detection in environment variables
func (c *AuditConfig) WithSecretCheck(
	// +required
	enable bool, // Enable or disable secret detection (true to enable, false to disable)
) *AuditConfig {
	c.CheckSecrets = enable
	return c
}

// WithNonRootCheck enables or disables the non-root user check
func (c *AuditConfig) WithNonRootCheck(
	// +required
	enable bool, // Enable or disable non-root user check (true to enable, false to disable)
) *AuditConfig {
	c.CheckNonRoot = enable
	return c
}

// WithHealthCheck enables or disables the healthcheck verification
func (c *AuditConfig) WithHealthCheck(
	// +required
	enable bool, // Enable or disable healthcheck verification (true to enable, false to disable)
) *AuditConfig {
	c.CheckHealth = enable
	return c
}
