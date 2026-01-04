// Package main contains testing functions for the Sentry security audit module
// Run tests with: dagger call test
package main

// ============================================================================
// TESTING SUPPORT - Run unit tests via Dagger
// ============================================================================

// Test runs unit tests for the Sentry module and returns a test report
func (m *Sentry) Test() (string, error) {
	var results []string
	var failed bool

	// Test maskSecret function
	maskTests := []struct {
		input, expected string
	}{
		{"", "****"},
		{"abc", "****"},
		{"abcd", "****"},
		{"abcde", "ab****de"},
		{"mypassword123", "my****23"},
	}

	for _, tt := range maskTests {
		result := maskSecret(tt.input)
		if result != tt.expected {
			results = append(results, "FAIL: maskSecret("+tt.input+") = "+result+", want "+tt.expected)
			failed = true
		}
	}
	if !failed {
		results = append(results, "PASS: maskSecret (5 cases)")
	}

	// Test checkNonRoot function
	failed = false
	rootCheck := checkNonRoot(true, "root")
	if rootCheck.Status != StatusFail {
		results = append(results, "FAIL: checkNonRoot(true, root) should be FAIL")
		failed = true
	}
	nonRootCheck := checkNonRoot(false, "appuser")
	if nonRootCheck.Status != StatusPass {
		results = append(results, "FAIL: checkNonRoot(false, appuser) should be PASS")
		failed = true
	}
	if !failed {
		results = append(results, "PASS: checkNonRoot (2 cases)")
	}

	// Test checkSecrets function
	failed = false
	cleanEnv := checkSecrets(map[string]string{"HOME": "/home/user"})
	if cleanEnv.Status != StatusPass {
		results = append(results, "FAIL: checkSecrets(clean) should be PASS")
		failed = true
	}
	secretEnv := checkSecrets(map[string]string{"DB_PASSWORD": "secret123"})
	if secretEnv.Status != StatusFail {
		results = append(results, "FAIL: checkSecrets(PASSWORD) should be FAIL")
		failed = true
	}
	awsEnv := checkSecrets(map[string]string{"KEY": "AKIAIOSFODNN7EXAMPLE"})
	if awsEnv.Status != StatusFail {
		results = append(results, "FAIL: checkSecrets(AWS) should be FAIL")
		failed = true
	}
	if !failed {
		results = append(results, "PASS: checkSecrets (3 cases)")
	}

	// =========================================================================
	// PHASE 4 TESTS: Trivy Integration
	// =========================================================================

	// Test parseSeverity function
	failed = false
	severityTests := []struct {
		input    string
		expected Severity
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"high", SeverityHigh},
		{"MEDIUM", SeverityMedium},
		{"LOW", SeverityLow},
		{"UNKNOWN", SeverityInfo},
		{"", SeverityInfo},
	}

	for _, tt := range severityTests {
		result := parseSeverity(tt.input)
		if result != tt.expected {
			results = append(results, "FAIL: parseSeverity("+tt.input+") = "+string(result)+", want "+string(tt.expected))
			failed = true
		}
	}
	if !failed {
		results = append(results, "PASS: parseSeverity (8 cases)")
	}

	// Test parseTrivyOutput with empty/null input
	failed = false
	emptyVulns, emptySummary := parseTrivyOutput("")
	if len(emptyVulns) != 0 || emptySummary.Total != 0 {
		results = append(results, "FAIL: parseTrivyOutput('') should return empty")
		failed = true
	}

	nullVulns, nullSummary := parseTrivyOutput("null")
	if len(nullVulns) != 0 || nullSummary.Total != 0 {
		results = append(results, "FAIL: parseTrivyOutput('null') should return empty")
		failed = true
	}

	// Test parseTrivyOutput with valid JSON
	sampleJSON := `{
		"Results": [{
			"Target": "test",
			"Vulnerabilities": [
				{"VulnerabilityID": "CVE-2023-0001", "PkgName": "openssl", "Severity": "CRITICAL", "InstalledVersion": "1.0", "FixedVersion": "1.1"},
				{"VulnerabilityID": "CVE-2023-0002", "PkgName": "curl", "Severity": "HIGH", "InstalledVersion": "7.0", "FixedVersion": "7.1"}
			]
		}]
	}`
	vulns, summary := parseTrivyOutput(sampleJSON)
	if len(vulns) != 2 {
		results = append(results, "FAIL: parseTrivyOutput(sample) should return 2 vulns, got "+itoa(len(vulns)))
		failed = true
	}
	if summary.Critical != 1 || summary.High != 1 || summary.Total != 2 {
		results = append(results, "FAIL: parseTrivyOutput(sample) summary counts wrong")
		failed = true
	}
	if len(vulns) > 0 && vulns[0].CVEID != "CVE-2023-0001" {
		results = append(results, "FAIL: parseTrivyOutput(sample) first CVE ID wrong")
		failed = true
	}

	if !failed {
		results = append(results, "PASS: parseTrivyOutput (4 cases)")
	}

	// Test exceedsThreshold function
	failed = false
	testVulns := []Vulnerability{
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
	}

	// Should exceed MEDIUM threshold (has HIGH)
	if !exceedsThreshold(testVulns, SeverityMedium) {
		results = append(results, "FAIL: exceedsThreshold with HIGH vuln should exceed MEDIUM")
		failed = true
	}
	// Should exceed HIGH threshold (has HIGH)
	if !exceedsThreshold(testVulns, SeverityHigh) {
		results = append(results, "FAIL: exceedsThreshold with HIGH vuln should exceed HIGH")
		failed = true
	}
	// Should NOT exceed CRITICAL threshold (no CRITICAL)
	if exceedsThreshold(testVulns, SeverityCritical) {
		results = append(results, "FAIL: exceedsThreshold without CRITICAL should not exceed CRITICAL")
		failed = true
	}
	// Empty vulns should not exceed any threshold
	if exceedsThreshold([]Vulnerability{}, SeverityLow) {
		results = append(results, "FAIL: exceedsThreshold with empty vulns should not exceed")
		failed = true
	}

	if !failed {
		results = append(results, "PASS: exceedsThreshold (4 cases)")
	}

	// Test severityExceeds helper
	failed = false
	if !severityExceeds(SeverityCritical, SeverityHigh) {
		results = append(results, "FAIL: CRITICAL should exceed HIGH")
		failed = true
	}
	if !severityExceeds(SeverityHigh, SeverityHigh) {
		results = append(results, "FAIL: HIGH should equal HIGH")
		failed = true
	}
	if severityExceeds(SeverityLow, SeverityHigh) {
		results = append(results, "FAIL: LOW should not exceed HIGH")
		failed = true
	}
	if !failed {
		results = append(results, "PASS: severityExceeds (3 cases)")
	}

	// =========================================================================
	// PHASE 5 TESTS: Report Generation
	// =========================================================================

	// Test calculateScore function
	failed = false

	// Perfect score - no issues
	perfectChecks := []SecurityCheck{
		{Status: StatusPass, Severity: SeverityHigh},
		{Status: StatusPass, Severity: SeverityHigh},
	}
	perfectScore := calculateScore(perfectChecks, VulnerabilitySummary{})
	if perfectScore != 100 {
		results = append(results, "FAIL: calculateScore(all pass) = "+itoa(perfectScore)+", want 100")
		failed = true
	}

	// Score with failed HIGH check (-15)
	failedChecks := []SecurityCheck{
		{Status: StatusFail, Severity: SeverityHigh},
		{Status: StatusPass, Severity: SeverityHigh},
	}
	failedScore := calculateScore(failedChecks, VulnerabilitySummary{})
	if failedScore != 85 {
		results = append(results, "FAIL: calculateScore(1 HIGH fail) = "+itoa(failedScore)+", want 85")
		failed = true
	}

	// Score with vulnerabilities
	vulnScore := calculateScore([]SecurityCheck{}, VulnerabilitySummary{Critical: 1, High: 2, Total: 3})
	// 100 - 10 (1 critical) - 10 (2 high * 5) = 80
	if vulnScore != 80 {
		results = append(results, "FAIL: calculateScore with vulns = "+itoa(vulnScore)+", want 80")
		failed = true
	}

	// Floor at 0
	extremeVulns := VulnerabilitySummary{Critical: 20, High: 20, Medium: 20, Low: 20, Total: 80}
	floorScore := calculateScore([]SecurityCheck{}, extremeVulns)
	if floorScore != 0 {
		results = append(results, "FAIL: calculateScore should floor at 0, got "+itoa(floorScore))
		failed = true
	}

	if !failed {
		results = append(results, "PASS: calculateScore (4 cases)")
	}

	// Test truncate function
	failed = false
	if truncate("short", 10) != "short" {
		results = append(results, "FAIL: truncate(short, 10) should not truncate")
		failed = true
	}
	if truncate("this is a very long string", 10) != "this is..." {
		results = append(results, "FAIL: truncate(long, 10) should truncate: "+truncate("this is a very long string", 10))
		failed = true
	}
	if !failed {
		results = append(results, "PASS: truncate (2 cases)")
	}

	// Test statusIcon function
	failed = false
	if statusIcon(StatusPass) != "PASS" {
		results = append(results, "FAIL: statusIcon(PASS) wrong")
		failed = true
	}
	if statusIcon(StatusFail) != "FAIL" {
		results = append(results, "FAIL: statusIcon(FAIL) wrong")
		failed = true
	}
	if statusIcon(StatusWarn) != "WARN" {
		results = append(results, "FAIL: statusIcon(WARN) wrong")
		failed = true
	}
	if !failed {
		results = append(results, "PASS: statusIcon (3 cases)")
	}

	// Test statusBadge function
	failed = false
	if statusBadge(true) != "PASSED" {
		results = append(results, "FAIL: statusBadge(true) wrong")
		failed = true
	}
	if statusBadge(false) != "FAILED" {
		results = append(results, "FAIL: statusBadge(false) wrong")
		failed = true
	}
	if !failed {
		results = append(results, "PASS: statusBadge (2 cases)")
	}

	// Test intToStr function
	failed = false
	if intToStr(0) != "0" {
		results = append(results, "FAIL: intToStr(0) = "+intToStr(0))
		failed = true
	}
	if intToStr(42) != "42" {
		results = append(results, "FAIL: intToStr(42) = "+intToStr(42))
		failed = true
	}
	if intToStr(100) != "100" {
		results = append(results, "FAIL: intToStr(100) = "+intToStr(100))
		failed = true
	}
	if !failed {
		results = append(results, "PASS: intToStr (3 cases)")
	}

	// Summary
	results = append(results, "")
	results = append(results, "Test run complete.")

	return joinStrings(results, "\n"), nil
}

// joinStrings joins strings with a separator
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// itoa converts an int to a string (simple implementation)
func itoa(n int) string {
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
