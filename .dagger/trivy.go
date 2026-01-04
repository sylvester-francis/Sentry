// Sentry - Dagger module for container security auditing
// https://github.com/sylvester-francis/Sentry
// Licensed under MIT - see LICENSE file

// Package main provides Trivy vulnerability scanner integration for Sentry.
// It handles container export, Trivy execution, and JSON output parsing
// to extract vulnerability information.
package main

import (
	"context"
	"encoding/json"
	"strings"

	"dagger/sentry/internal/dagger"
)

// ============================================================================
// TRIVY JSON OUTPUT STRUCTURES
// ============================================================================

// TrivyOutput represents the top-level structure of Trivy JSON output
type TrivyOutput struct {
	Results []TrivyResult `json:"Results"`
}

// TrivyResult represents a single result from Trivy (one per target)
type TrivyResult struct {
	Target          string      `json:"Target"`
	Vulnerabilities []TrivyVuln `json:"Vulnerabilities"`
}

// TrivyVuln represents a single vulnerability from Trivy
type TrivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

// ============================================================================
// TRIVY SCANNING FUNCTIONS
// ============================================================================

// runTrivy exports the container and scans it with Trivy
func runTrivy(ctx context.Context, container *dagger.Container) ([]Vulnerability, VulnerabilitySummary, error) {
	// Export container as tarball
	tarball := container.AsTarball()

	// Create Trivy container and mount the tarball
	trivyContainer := dag.Container().
		From("aquasec/trivy:latest").
		WithMountedFile("/image.tar", tarball).
		WithExec([]string{
			"image",
			"--input", "/image.tar",
			"--format", "json",
			"--quiet",
			"--no-progress",
		})

	// Get the scan output
	output, err := trivyContainer.Stdout(ctx)
	if err != nil {
		// Trivy might fail for minimal images - return empty results
		return nil, VulnerabilitySummary{}, nil
	}

	// Parse the JSON output
	vulns, summary := parseTrivyOutput(output)
	return vulns, summary, nil
}

// parseTrivyOutput parses Trivy JSON output into our Vulnerability structs
func parseTrivyOutput(jsonOutput string) ([]Vulnerability, VulnerabilitySummary) {
	var vulns []Vulnerability
	var summary VulnerabilitySummary

	// Handle empty output
	jsonOutput = strings.TrimSpace(jsonOutput)
	if jsonOutput == "" || jsonOutput == "{}" || jsonOutput == "null" {
		return vulns, summary
	}

	// Parse JSON
	var trivyOutput TrivyOutput
	if err := json.Unmarshal([]byte(jsonOutput), &trivyOutput); err != nil {
		// Try parsing as array of results (older Trivy format)
		var results []TrivyResult
		if err := json.Unmarshal([]byte(jsonOutput), &results); err != nil {
			return vulns, summary
		}
		trivyOutput.Results = results
	}

	// Convert Trivy vulnerabilities to our format
	for _, result := range trivyOutput.Results {
		for _, tv := range result.Vulnerabilities {
			severity := parseSeverity(tv.Severity)
			vulns = append(vulns, Vulnerability{
				PackageName:      tv.PkgName,
				CVEID:            tv.VulnerabilityID,
				Severity:         severity,
				InstalledVersion: tv.InstalledVersion,
				FixedVersion:     tv.FixedVersion,
			})

			// Update summary counts
			summary.Total++
			switch severity {
			case SeverityCritical:
				summary.Critical++
			case SeverityHigh:
				summary.High++
			case SeverityMedium:
				summary.Medium++
			case SeverityLow:
				summary.Low++
			}
		}
	}

	return vulns, summary
}

// parseSeverity converts a Trivy severity string to our Severity type
func parseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// exceedsThreshold checks if vulnerabilities exceed the given severity threshold
func exceedsThreshold(vulns []Vulnerability, threshold Severity) bool {
	for _, v := range vulns {
		if severityExceeds(v.Severity, threshold) {
			return true
		}
	}
	return false
}

// severityExceeds returns true if severity a is >= threshold
func severityExceeds(a, threshold Severity) bool {
	severityOrder := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	return severityOrder[a] >= severityOrder[threshold]
}
