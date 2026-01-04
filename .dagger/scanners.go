// Package main contains scanner configurations and execution for the Sentry module
package main

import (
	"context"
	"encoding/json"
	"strings"

	"dagger/sentry/internal/dagger"
)

// ============================================================================
// SCANNER CONFIGURATIONS - Built-in scanner presets
// ============================================================================

// getTrivyConfig returns the default Trivy scanner configuration
func getTrivyConfig() ScannerConfig {
	return ScannerConfig{
		Type:         ScannerTrivy,
		Image:        "aquasec/trivy:latest",
		Args:         []string{"image", "--input", "/image.tar", "--format", "json", "--quiet", "--no-progress"},
		OutputFormat: "trivy",
	}
}

// getGrypeConfig returns the Grype (Anchore) scanner configuration
func getGrypeConfig() ScannerConfig {
	return ScannerConfig{
		Type:         ScannerGrype,
		Image:        "anchore/grype:latest",
		Args:         []string{"/image.tar", "-o", "json", "--quiet"},
		OutputFormat: "grype",
	}
}

// getSnykConfig returns the Snyk scanner configuration
// Note: Requires SNYK_TOKEN to be set in the environment
func getSnykConfig(token *dagger.Secret) ScannerConfig {
	return ScannerConfig{
		Type:         ScannerSnyk,
		Image:        "snyk/snyk:docker",
		Args:         []string{"container", "test", "--json", "docker-archive:/image.tar"},
		OutputFormat: "snyk",
	}
}

// getWizConfig returns the Wiz scanner configuration
// Note: Requires WIZ_CLIENT_ID and WIZ_CLIENT_SECRET in the environment
func getWizConfig(clientId *dagger.Secret, clientSecret *dagger.Secret) ScannerConfig {
	return ScannerConfig{
		Type:         ScannerWiz,
		Image:        "wizsecurity/wiz-cli:latest",
		Args:         []string{"docker", "scan", "--image", "/image.tar", "--format", "json"},
		OutputFormat: "wiz",
	}
}

// getBlackDuckConfig returns the Black Duck scanner configuration
// Note: Requires BLACKDUCK_API_TOKEN in the environment
func getBlackDuckConfig(url string, token *dagger.Secret) ScannerConfig {
	return ScannerConfig{
		Type:         ScannerBlackDuck,
		Image:        "blackducksoftware/detect:latest",
		Args:         []string{"--blackduck.url=" + url, "--detect.docker.tar=/image.tar", "--detect.output.path=/output"},
		OutputFormat: "blackduck",
	}
}

// ============================================================================
// SCANNER EXECUTION
// ============================================================================

// runScanner executes the configured vulnerability scanner
func runScanner(ctx context.Context, container *dagger.Container, config ScannerConfig) ([]Vulnerability, VulnerabilitySummary, error) {
	// Handle disabled scanner
	if config.Type == ScannerNone {
		return nil, VulnerabilitySummary{}, nil
	}

	// Export container as tarball
	tarball := container.AsTarball()

	// Create scanner container and mount the tarball
	scannerContainer := dag.Container().
		From(config.Image).
		WithMountedFile("/image.tar", tarball).
		WithExec(config.Args)

	// Get the scan output
	output, err := scannerContainer.Stdout(ctx)
	if err != nil {
		// Scanner might fail for minimal images - return empty results
		return nil, VulnerabilitySummary{}, nil
	}

	// Parse output based on scanner type
	return parseScannerOutput(output, config)
}

// parseScannerOutput parses scanner output based on the scanner type
func parseScannerOutput(output string, config ScannerConfig) ([]Vulnerability, VulnerabilitySummary, error) {
	format := config.OutputFormat
	if format == "" {
		format = string(config.Type)
	}

	switch format {
	case "trivy":
		vulns, summary := parseTrivyOutput(output)
		return vulns, summary, nil
	case "grype":
		vulns, summary := parseGrypeOutput(output)
		return vulns, summary, nil
	case "snyk":
		vulns, summary := parseSnykOutput(output)
		return vulns, summary, nil
	case "wiz":
		vulns, summary := parseWizOutput(output)
		return vulns, summary, nil
	case "blackduck":
		vulns, summary := parseBlackDuckOutput(output)
		return vulns, summary, nil
	default:
		// Try Trivy format as fallback
		vulns, summary := parseTrivyOutput(output)
		return vulns, summary, nil
	}
}

// ============================================================================
// GRYPE OUTPUT PARSING
// ============================================================================

// GrypeOutput represents the top-level structure of Grype JSON output
type GrypeOutput struct {
	Matches []GrypeMatch `json:"matches"`
}

// GrypeMatch represents a single vulnerability match from Grype
type GrypeMatch struct {
	Vulnerability GrypeVuln     `json:"vulnerability"`
	Artifact      GrypeArtifact `json:"artifact"`
}

// GrypeVuln represents vulnerability details from Grype
type GrypeVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Fix      struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

// GrypeArtifact represents the affected package
type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseGrypeOutput parses Grype JSON output into Vulnerability structs
func parseGrypeOutput(jsonOutput string) ([]Vulnerability, VulnerabilitySummary) {
	var vulns []Vulnerability
	var summary VulnerabilitySummary

	jsonOutput = strings.TrimSpace(jsonOutput)
	if jsonOutput == "" || jsonOutput == "{}" || jsonOutput == "null" {
		return vulns, summary
	}

	var grypeOutput GrypeOutput
	if err := json.Unmarshal([]byte(jsonOutput), &grypeOutput); err != nil {
		return vulns, summary
	}

	for _, match := range grypeOutput.Matches {
		severity := parseSeverity(match.Vulnerability.Severity)
		fixedVersion := ""
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = match.Vulnerability.Fix.Versions[0]
		}

		vulns = append(vulns, Vulnerability{
			PackageName:      match.Artifact.Name,
			CVEID:            match.Vulnerability.ID,
			Severity:         severity,
			InstalledVersion: match.Artifact.Version,
			FixedVersion:     fixedVersion,
		})

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

	return vulns, summary
}

// ============================================================================
// SNYK OUTPUT PARSING
// ============================================================================

// SnykOutput represents Snyk JSON output
type SnykOutput struct {
	Vulnerabilities []SnykVuln `json:"vulnerabilities"`
}

// SnykVuln represents a single Snyk vulnerability
type SnykVuln struct {
	ID          string   `json:"id"`
	PackageName string   `json:"packageName"`
	Version     string   `json:"version"`
	Severity    string   `json:"severity"`
	FixedIn     []string `json:"fixedIn"`
}

// parseSnykOutput parses Snyk JSON output
func parseSnykOutput(jsonOutput string) ([]Vulnerability, VulnerabilitySummary) {
	var vulns []Vulnerability
	var summary VulnerabilitySummary

	jsonOutput = strings.TrimSpace(jsonOutput)
	if jsonOutput == "" || jsonOutput == "{}" || jsonOutput == "null" {
		return vulns, summary
	}

	var snykOutput SnykOutput
	if err := json.Unmarshal([]byte(jsonOutput), &snykOutput); err != nil {
		return vulns, summary
	}

	for _, sv := range snykOutput.Vulnerabilities {
		severity := parseSeverity(sv.Severity)
		fixedVersion := ""
		if len(sv.FixedIn) > 0 {
			fixedVersion = sv.FixedIn[0]
		}

		vulns = append(vulns, Vulnerability{
			PackageName:      sv.PackageName,
			CVEID:            sv.ID,
			Severity:         severity,
			InstalledVersion: sv.Version,
			FixedVersion:     fixedVersion,
		})

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

	return vulns, summary
}

// ============================================================================
// WIZ OUTPUT PARSING
// ============================================================================

// WizOutput represents Wiz scanner output
type WizOutput struct {
	Result struct {
		Vulnerabilities []WizVuln `json:"vulnerabilities"`
	} `json:"result"`
}

// WizVuln represents a Wiz vulnerability
type WizVuln struct {
	Name           string `json:"name"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	Severity       string `json:"severity"`
	FixedVersion   string `json:"fixedVersion"`
}

// parseWizOutput parses Wiz JSON output
func parseWizOutput(jsonOutput string) ([]Vulnerability, VulnerabilitySummary) {
	var vulns []Vulnerability
	var summary VulnerabilitySummary

	jsonOutput = strings.TrimSpace(jsonOutput)
	if jsonOutput == "" || jsonOutput == "{}" || jsonOutput == "null" {
		return vulns, summary
	}

	var wizOutput WizOutput
	if err := json.Unmarshal([]byte(jsonOutput), &wizOutput); err != nil {
		return vulns, summary
	}

	for _, wv := range wizOutput.Result.Vulnerabilities {
		severity := parseSeverity(wv.Severity)

		vulns = append(vulns, Vulnerability{
			PackageName:      wv.PackageName,
			CVEID:            wv.Name,
			Severity:         severity,
			InstalledVersion: wv.PackageVersion,
			FixedVersion:     wv.FixedVersion,
		})

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

	return vulns, summary
}

// ============================================================================
// BLACK DUCK OUTPUT PARSING
// ============================================================================

// BlackDuckOutput represents Black Duck scanner output
type BlackDuckOutput struct {
	Items []BlackDuckVuln `json:"items"`
}

// BlackDuckVuln represents a Black Duck vulnerability
type BlackDuckVuln struct {
	VulnerabilityID  string `json:"vulnerabilityId"`
	ComponentName    string `json:"componentName"`
	ComponentVersion string `json:"componentVersionName"`
	Severity         string `json:"severity"`
	Solution         string `json:"solution"`
}

// parseBlackDuckOutput parses Black Duck JSON output
func parseBlackDuckOutput(jsonOutput string) ([]Vulnerability, VulnerabilitySummary) {
	var vulns []Vulnerability
	var summary VulnerabilitySummary

	jsonOutput = strings.TrimSpace(jsonOutput)
	if jsonOutput == "" || jsonOutput == "{}" || jsonOutput == "null" {
		return vulns, summary
	}

	var bdOutput BlackDuckOutput
	if err := json.Unmarshal([]byte(jsonOutput), &bdOutput); err != nil {
		return vulns, summary
	}

	for _, bv := range bdOutput.Items {
		severity := parseSeverity(bv.Severity)

		vulns = append(vulns, Vulnerability{
			PackageName:      bv.ComponentName,
			CVEID:            bv.VulnerabilityID,
			Severity:         severity,
			InstalledVersion: bv.ComponentVersion,
			FixedVersion:     bv.Solution,
		})

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

	return vulns, summary
}
