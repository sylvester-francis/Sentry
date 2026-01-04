// Sentry - A Dagger module for container security auditing
//
// Sentry audits containers for security compliance by performing checks for
// common security best practices (non-root user, secret detection, healthcheck)
// and integrating with Trivy for vulnerability scanning. It generates
// compliance-ready reports in Markdown and JSON formats.

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
	EnableTrivy    bool              // Run Trivy vulnerability scan
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
func (m *Sentry) Scan(container *dagger.Container) *AuditConfig {
	return &AuditConfig{
		Container:      container,
		EnableTrivy:    true, // Enabled by default
		FailOnSeverity: SeverityHigh,
		CheckSecrets:   true, // Enabled by default
		CheckNonRoot:   true, // Enabled by default
		CheckHealth:    true, // Enabled by default
	}
}

// ============================================================================
// CHAIN METHODS - Configure the audit before running
// ============================================================================

// WithTrivy enables or disables Trivy vulnerability scanning
func (c *AuditConfig) WithTrivy(enable bool) *AuditConfig {
	c.EnableTrivy = enable
	return c
}

// FailOn sets the minimum severity that causes the audit to fail
func (c *AuditConfig) FailOn(severity Severity) *AuditConfig {
	c.FailOnSeverity = severity
	return c
}

// WithSecretCheck enables or disables secret detection in environment variables
func (c *AuditConfig) WithSecretCheck(enable bool) *AuditConfig {
	c.CheckSecrets = enable
	return c
}

// WithNonRootCheck enables or disables the non-root user check
func (c *AuditConfig) WithNonRootCheck(enable bool) *AuditConfig {
	c.CheckNonRoot = enable
	return c
}

// WithHealthCheck enables or disables the healthcheck verification
func (c *AuditConfig) WithHealthCheck(enable bool) *AuditConfig {
	c.CheckHealth = enable
	return c
}
