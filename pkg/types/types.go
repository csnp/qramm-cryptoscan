// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package types contains shared type definitions
package types

// Severity levels for findings
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// QuantumRisk indicates quantum vulnerability status
type QuantumRisk string

const (
	QuantumVulnerable QuantumRisk = "VULNERABLE" // Broken by quantum computers
	QuantumPartial    QuantumRisk = "PARTIAL"    // Weakened but not fully broken
	QuantumSafe       QuantumRisk = "SAFE"       // Quantum-resistant
	QuantumUnknown    QuantumRisk = "UNKNOWN"    // Cannot determine
)

// Confidence indicates how confident we are in the finding
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// FindingType categorizes the type of finding
type FindingType string

const (
	FindingTypeAlgorithm  FindingType = "algorithm"   // Direct algorithm usage
	FindingTypeDependency FindingType = "dependency"  // Crypto library in dependencies
	FindingTypeConfig     FindingType = "config"      // Configuration setting
	FindingTypeSecret     FindingType = "secret"      // Exposed key/secret
	FindingTypeProtocol   FindingType = "protocol"    // Protocol configuration (TLS, etc.)
)

// Finding represents a single cryptographic finding
type Finding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	FindingType FindingType       `json:"findingType"`
	Category    string            `json:"category"`
	Algorithm   string            `json:"algorithm,omitempty"`
	KeySize     int               `json:"keySize,omitempty"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Column      int               `json:"column,omitempty"`
	Match       string            `json:"match"`
	Context     string            `json:"context,omitempty"`
	Severity    Severity          `json:"severity"`
	Quantum     QuantumRisk       `json:"quantumRisk"`
	Confidence  Confidence        `json:"confidence"`
	Purpose     string            `json:"purpose,omitempty"`     // What the crypto is used for
	Language    string            `json:"language,omitempty"`    // Programming language
	FileType    string            `json:"fileType,omitempty"`    // code, config, docs, etc.
	Description string            `json:"description"`
	Remediation string            `json:"remediation,omitempty"`
	Impact      string            `json:"impact,omitempty"`      // Business impact description
	Effort      string            `json:"effort,omitempty"`      // Migration effort estimate
	References  []string          `json:"references,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Priority calculates a priority score for sorting (higher = more urgent)
func (f *Finding) Priority() int {
	score := 0

	// Severity weight
	switch f.Severity {
	case SeverityCritical:
		score += 100
	case SeverityHigh:
		score += 75
	case SeverityMedium:
		score += 50
	case SeverityLow:
		score += 25
	}

	// Quantum risk weight
	switch f.Quantum {
	case QuantumVulnerable:
		score += 50
	case QuantumPartial:
		score += 20
	}

	// Confidence weight
	switch f.Confidence {
	case ConfidenceHigh:
		score += 30
	case ConfidenceMedium:
		score += 15
	}

	// Finding type weight (actual code > dependencies > configs > docs)
	switch f.FindingType {
	case FindingTypeSecret:
		score += 40
	case FindingTypeAlgorithm:
		score += 25
	case FindingTypeDependency:
		score += 20
	case FindingTypeConfig:
		score += 15
	}

	// File type weight
	switch f.FileType {
	case "code":
		score += 20
	case "config":
		score += 15
	case "test":
		score -= 10 // Deprioritize test files
	case "documentation":
		score -= 20 // Deprioritize docs
	}

	return score
}
