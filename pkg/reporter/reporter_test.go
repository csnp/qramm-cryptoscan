// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
)

func createTestResults() *scanner.Results {
	return &scanner.Results{
		ScanTarget:   "/test/path",
		ScanTime:     time.Now(),
		ScanDuration: time.Second * 5,
		FilesScanned: 10,
		LinesScanned: 1000,
		Findings: []scanner.Finding{
			{
				ID:          "RSA-001",
				Type:        "RSA Key Generation",
				Severity:    scanner.SeverityHigh,
				Category:    "Asymmetric Cryptography",
				Algorithm:   "RSA",
				KeySize:     2048,
				Quantum:     scanner.QuantumVulnerable,
				Confidence:  "HIGH",
				File:        "/test/crypto.go",
				Line:        42,
				Match:       "rsa.GenerateKey(rand.Reader, 2048)",
				Description: "RSA key generation detected",
				Remediation: "Consider migrating to ML-KEM for key exchange",
			},
			{
				ID:          "AES-001",
				Type:        "AES Cipher",
				Severity:    scanner.SeverityInfo,
				Category:    "Symmetric Cryptography",
				Algorithm:   "AES",
				KeySize:     256,
				Quantum:     scanner.QuantumPartial,
				Confidence:  "HIGH",
				File:        "/test/encrypt.go",
				Line:        15,
				Match:       "aes.NewCipher(key)",
				Description: "AES cipher usage",
				Remediation: "AES-256 provides adequate post-quantum security",
			},
		},
		Summary: scanner.Summary{
			TotalFindings: 2,
			BySeverity:    map[string]int{"HIGH": 1, "INFO": 1},
			ByCategory:    map[string]int{"Asymmetric Cryptography": 1, "Symmetric Cryptography": 1},
			ByQuantumRisk: map[string]int{"VULNERABLE": 1, "PARTIAL": 1},
		},
	}
}

func TestTextReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewTextReporter(false)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check for key elements
	checks := []string{
		"CRYPTOGRAPHIC SCAN RESULTS",
		"RSA Key Generation",
		"AES Cipher",
		"QUANTUM VULNERABLE",
		"QRAMM",
		"CSNP",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output missing expected text: %s", check)
		}
	}
}

func TestTextReporterWithColors(t *testing.T) {
	results := createTestResults()
	reporter := NewTextReporter(true)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should contain ANSI color codes
	if !strings.Contains(output, "\033[") {
		t.Error("Expected ANSI color codes in output")
	}
}

func TestJSONReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewJSONReporter(false)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Check structure
	if _, ok := parsed["findings"]; !ok {
		t.Error("JSON missing 'findings' key")
	}
	if _, ok := parsed["summary"]; !ok {
		t.Error("JSON missing 'summary' key")
	}
}

func TestJSONReporterPretty(t *testing.T) {
	results := createTestResults()
	reporter := NewJSONReporter(true)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Pretty printed JSON should have newlines
	if !strings.Contains(output, "\n") {
		t.Error("Expected pretty printed JSON with newlines")
	}
}

func TestCSVReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewCSVReporter()

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		t.Error("Expected at least header and one data row")
	}

	// Check header
	header := lines[0]
	expectedCols := []string{"ID", "Severity", "Type", "Category", "Algorithm", "Quantum Risk"}
	for _, col := range expectedCols {
		if !strings.Contains(header, col) {
			t.Errorf("Header missing column: %s", col)
		}
	}

	// Should have 3 lines total (header + 2 findings)
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}
}

func TestSARIFReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewSARIFReporter()

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(output), &sarif); err != nil {
		t.Fatalf("Invalid SARIF JSON: %v", err)
	}

	// Check SARIF schema
	if sarif["$schema"] == nil {
		t.Error("SARIF missing $schema")
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	runs := sarif["runs"].([]interface{})
	if len(runs) == 0 {
		t.Error("SARIF missing runs")
	}
}

func TestCBOMReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewCBOMReporter()

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var cbom map[string]interface{}
	if err := json.Unmarshal([]byte(output), &cbom); err != nil {
		t.Fatalf("Invalid CBOM JSON: %v", err)
	}

	// Check CycloneDX structure
	if cbom["bomFormat"] != "CycloneDX" {
		t.Error("Expected bomFormat CycloneDX")
	}
	if cbom["specVersion"] == nil {
		t.Error("CBOM missing specVersion")
	}
}

func TestEmptyResults(t *testing.T) {
	results := &scanner.Results{
		ScanTarget:   "/empty",
		ScanTime:     time.Now(),
		ScanDuration: time.Millisecond * 100,
		FilesScanned: 5,
		LinesScanned: 100,
		Findings:     []scanner.Finding{},
		Summary: scanner.Summary{
			TotalFindings: 0,
			BySeverity:    map[string]int{},
			ByCategory:    map[string]int{},
			ByQuantumRisk: map[string]int{},
		},
	}

	reporters := []struct {
		name string
		r    Reporter
	}{
		{"text", NewTextReporter(false)},
		{"json", NewJSONReporter(false)},
		{"csv", NewCSVReporter()},
		{"sarif", NewSARIFReporter()},
		{"cbom", NewCBOMReporter()},
	}

	for _, tc := range reporters {
		t.Run(tc.name, func(t *testing.T) {
			output, err := tc.r.Generate(results)
			if err != nil {
				t.Errorf("%s reporter failed on empty results: %v", tc.name, err)
			}
			if output == "" {
				t.Errorf("%s reporter returned empty output", tc.name)
			}
		})
	}
}
