// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  scanner.Severity
	}{
		{"critical", scanner.SeverityCritical},
		{"CRITICAL", scanner.SeverityCritical},
		{"Critical", scanner.SeverityCritical},
		{"high", scanner.SeverityHigh},
		{"HIGH", scanner.SeverityHigh},
		{"medium", scanner.SeverityMedium},
		{"MEDIUM", scanner.SeverityMedium},
		{"low", scanner.SeverityLow},
		{"LOW", scanner.SeverityLow},
		{"info", scanner.SeverityInfo},
		{"INFO", scanner.SeverityInfo},
		{"", scanner.SeverityInfo},
		{"invalid", scanner.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSeverity(tt.input)
			if got != tt.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/org/repo", true},
		{"http://github.com/org/repo", true},
		{"git@github.com:org/repo.git", true},
		{"/path/to/local/dir", false},
		{"./relative/path", false},
		{".", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isURL(tt.input)
			if got != tt.want {
				t.Errorf("isURL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestScanCmdExists(t *testing.T) {
	if scanCmd == nil {
		t.Error("scanCmd should not be nil")
	}
	if scanCmd.Use != "scan [path or URL]" {
		t.Errorf("scanCmd.Use = %q, want %q", scanCmd.Use, "scan [path or URL]")
	}
}

func TestRootCmdExists(t *testing.T) {
	if rootCmd == nil {
		t.Error("rootCmd should not be nil")
	}
	if rootCmd.Use != "cryptoscan" {
		t.Errorf("rootCmd.Use = %q, want %q", rootCmd.Use, "cryptoscan")
	}
}

func TestSetVersionInfo(t *testing.T) {
	SetVersionInfo("1.0.0", "abc123", "2025-01-01")
	if version != "1.0.0" {
		t.Errorf("version = %q, want %q", version, "1.0.0")
	}
	if commit != "abc123" {
		t.Errorf("commit = %q, want %q", commit, "abc123")
	}
	if buildDate != "2025-01-01" {
		t.Errorf("buildDate = %q, want %q", buildDate, "2025-01-01")
	}
}
