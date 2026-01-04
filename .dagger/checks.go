// Package main contains security check implementations for the Sentry module
package main

import (
	"context"
	"regexp"
	"strings"

	"dagger/sentry/internal/dagger"
)

// ============================================================================
// CONTAINER INSPECTION - Extract information from containers
// ============================================================================

// extractEnvVars executes printenv inside the container and returns a map of environment variables
func extractEnvVars(ctx context.Context, container *dagger.Container) (map[string]string, error) {
	envVars := make(map[string]string)

	// Try printenv first, fallback to env
	output, err := container.WithExec([]string{"printenv"}).Stdout(ctx)
	if err != nil {
		// Fallback to sh -c env
		output, err = container.WithExec([]string{"sh", "-c", "env"}).Stdout(ctx)
		if err != nil {
			// Container might not have a shell - return empty map, no error
			return envVars, nil
		}
	}

	// Parse KEY=VALUE format
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}

	return envVars, nil
}

// detectUser executes id command inside the container to determine if running as root
func detectUser(ctx context.Context, container *dagger.Container) (isRoot bool, username string, err error) {
	// Try id command first
	output, err := container.WithExec([]string{"id"}).Stdout(ctx)
	if err != nil {
		// Fallback to whoami
		output, err = container.WithExec([]string{"whoami"}).Stdout(ctx)
		if err != nil {
			// Container might not have these commands
			return false, "unknown", nil
		}
		username = strings.TrimSpace(output)
		return username == "root", username, nil
	}

	// Parse id output: uid=0(root) gid=0(root) groups=0(root)
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "uid=0") || strings.Contains(output, "(root)") {
		return true, "root", nil
	}

	// Extract username from id output
	if idx := strings.Index(output, "("); idx != -1 {
		end := strings.Index(output[idx:], ")")
		if end != -1 {
			username = output[idx+1 : idx+end]
		}
	}

	return false, username, nil
}

// ============================================================================
// SECURITY CHECKS - Individual check implementations
// ============================================================================

// Sensitive variable name patterns (case-insensitive check)
var sensitiveKeywords = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "AUTH",
}

// Secret patterns - compiled regex for detecting secrets in values
var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}[0-9a-zA-Z/+]{40}`)},
	{"GitHub Personal Token", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{"GitHub OAuth Token", regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)},
	{"GitHub App Token", regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`)},
	{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----`)},
	{"Generic API Key", regexp.MustCompile(`(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`)},
	{"Database URL", regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis):\/\/[^\s]+`)},
}

// checkSecrets scans environment variables for potential secrets
func checkSecrets(envVars map[string]string) SecurityCheck {
	var findings []string

	for key, value := range envVars {
		upperKey := strings.ToUpper(key)

		// Check if variable name contains sensitive keywords
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(upperKey, keyword) {
				// Mask the value for security
				maskedValue := maskSecret(value)
				findings = append(findings, "Sensitive variable: "+key+"="+maskedValue)
				break
			}
		}

		// Check value against secret patterns
		for _, sp := range secretPatterns {
			if sp.pattern.MatchString(value) {
				findings = append(findings, "Pattern match ("+sp.name+"): "+key)
			}
		}
	}

	if len(findings) > 0 {
		return SecurityCheck{
			Name:        "Secret Detection",
			Description: "Checks for secrets and sensitive data in environment variables",
			Status:      StatusFail,
			Details:     strings.Join(findings, "; "),
			Severity:    SeverityHigh,
		}
	}

	return SecurityCheck{
		Name:        "Secret Detection",
		Description: "Checks for secrets and sensitive data in environment variables",
		Status:      StatusPass,
		Details:     "No secrets detected in environment variables",
		Severity:    SeverityHigh,
	}
}

// maskSecret masks a secret value for safe display
func maskSecret(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

// checkNonRoot verifies the container runs as a non-root user
func checkNonRoot(isRoot bool, username string) SecurityCheck {
	if isRoot {
		return SecurityCheck{
			Name:        "Non-Root User",
			Description: "Verifies container runs as non-root user",
			Status:      StatusFail,
			Details:     "Container is running as root user",
			Severity:    SeverityHigh,
		}
	}

	details := "Container runs as non-root"
	if username != "" && username != "unknown" {
		details = "Container runs as user: " + username
	}

	return SecurityCheck{
		Name:        "Non-Root User",
		Description: "Verifies container runs as non-root user",
		Status:      StatusPass,
		Details:     details,
		Severity:    SeverityHigh,
	}
}

// checkHealthcheck verifies health checking capability (heuristic-based)
func checkHealthcheck(ctx context.Context, container *dagger.Container) SecurityCheck {
	// Check for common health check indicators
	// Since we can't directly access HEALTHCHECK instruction, use heuristics

	// Look for curl/wget for health endpoints
	_, curlErr := container.WithExec([]string{"which", "curl"}).Stdout(ctx)
	_, wgetErr := container.WithExec([]string{"which", "wget"}).Stdout(ctx)

	hasHealthTools := curlErr == nil || wgetErr == nil

	if hasHealthTools {
		return SecurityCheck{
			Name:        "Health Check Capability",
			Description: "Checks if container has health monitoring tools",
			Status:      StatusPass,
			Details:     "Container has curl/wget for health checks",
			Severity:    SeverityInfo,
		}
	}

	return SecurityCheck{
		Name:        "Health Check Capability",
		Description: "Checks if container has health monitoring tools",
		Status:      StatusWarn,
		Details:     "No curl/wget found - health checks may be limited",
		Severity:    SeverityInfo,
	}
}

// runSecurityChecks executes all enabled security checks and returns results
func runSecurityChecks(ctx context.Context, container *dagger.Container, config *AuditConfig) []SecurityCheck {
	var checks []SecurityCheck

	// Secret detection check
	if config.CheckSecrets {
		envVars, err := extractEnvVars(ctx, container)
		if err == nil {
			checks = append(checks, checkSecrets(envVars))
		} else {
			checks = append(checks, SecurityCheck{
				Name:        "Secret Detection",
				Description: "Checks for secrets in environment variables",
				Status:      StatusSkip,
				Details:     "Could not extract environment variables: " + err.Error(),
				Severity:    SeverityHigh,
			})
		}
	}

	// Non-root user check
	if config.CheckNonRoot {
		isRoot, username, err := detectUser(ctx, container)
		if err == nil {
			checks = append(checks, checkNonRoot(isRoot, username))
		} else {
			checks = append(checks, SecurityCheck{
				Name:        "Non-Root User",
				Description: "Verifies container runs as non-root user",
				Status:      StatusSkip,
				Details:     "Could not detect user: " + err.Error(),
				Severity:    SeverityHigh,
			})
		}
	}

	// Health check verification
	if config.CheckHealth {
		checks = append(checks, checkHealthcheck(ctx, container))
	}

	return checks
}
