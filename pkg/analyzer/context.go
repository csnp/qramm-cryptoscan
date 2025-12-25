// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptoscan/pkg/types"
)

// LineContext provides context about a specific line of code
type LineContext struct {
	Line       string
	LineNumber int
	IsComment  bool
	IsString   bool
	IsImport   bool
	IsFunction bool
	IsVariable bool
	Confidence types.Confidence
	Purpose    string // What this crypto is being used for
}

// AnalyzeLine analyzes a line of code for context
func AnalyzeLine(line string, lang Language, prevLines []string) *LineContext {
	ctx := &LineContext{
		Line:       line,
		Confidence: types.ConfidenceHigh,
	}

	trimmed := strings.TrimSpace(line)

	// Detect if line is a comment
	ctx.IsComment = isCommentLine(trimmed, lang)

	// Detect if in a string literal (basic heuristic)
	ctx.IsString = isStringContext(trimmed)

	// Detect if this is an import statement
	ctx.IsImport = isImportLine(trimmed, lang)

	// Detect function definitions
	ctx.IsFunction = isFunctionDef(trimmed, lang)

	// Detect variable assignments
	ctx.IsVariable = isVariableAssignment(trimmed, lang)

	// Determine confidence based on context
	ctx.Confidence = determineConfidence(ctx, lang)

	// Try to determine purpose
	ctx.Purpose = determinePurpose(line, prevLines, lang)

	return ctx
}

func isCommentLine(line string, lang Language) bool {
	switch lang {
	case LangPython, LangRuby, LangShell, LangYAML:
		return strings.HasPrefix(line, "#")
	case LangGo, LangJava, LangJavaScript, LangTypeScript, LangC, LangCPP, LangCSharp, LangSwift, LangKotlin, LangRust, LangPHP:
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*")
	case LangMarkdown:
		return strings.HasPrefix(line, "<!--")
	}
	return false
}

func isStringContext(line string) bool {
	// Simple heuristic: check if the line is likely documentation
	docPatterns := []string{
		"@param", "@return", "@deprecated", "@see", "@link",
		"TODO", "FIXME", "NOTE", "XXX",
		"Example:", "Usage:", "e.g.", "i.e.",
	}
	for _, pattern := range docPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func isImportLine(line string, lang Language) bool {
	switch lang {
	case LangPython:
		return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ")
	case LangGo:
		return strings.HasPrefix(line, "import ") || strings.Contains(line, `"`) && !strings.Contains(line, "=")
	case LangJava:
		return strings.HasPrefix(line, "import ")
	case LangJavaScript, LangTypeScript:
		return strings.HasPrefix(line, "import ") || strings.Contains(line, "require(")
	case LangRust:
		return strings.HasPrefix(line, "use ")
	case LangRuby:
		return strings.HasPrefix(line, "require ")
	case LangCSharp:
		return strings.HasPrefix(line, "using ")
	case LangC, LangCPP:
		return strings.HasPrefix(line, "#include")
	}
	return false
}

func isFunctionDef(line string, lang Language) bool {
	switch lang {
	case LangPython:
		return strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "async def ")
	case LangGo:
		return strings.HasPrefix(line, "func ")
	case LangJava, LangCSharp:
		return (strings.Contains(line, "public ") || strings.Contains(line, "private ") ||
			strings.Contains(line, "protected ")) && strings.Contains(line, "(")
	case LangJavaScript, LangTypeScript:
		return strings.HasPrefix(line, "function ") || strings.Contains(line, "=>") ||
			strings.Contains(line, ": function")
	case LangRust:
		return strings.HasPrefix(line, "fn ") || strings.HasPrefix(line, "pub fn ")
	case LangRuby:
		return strings.HasPrefix(line, "def ")
	}
	return false
}

func isVariableAssignment(line string, lang Language) bool {
	switch lang {
	case LangGo:
		return strings.Contains(line, ":=") || (strings.Contains(line, "=") && strings.Contains(line, "var "))
	case LangPython, LangRuby:
		return strings.Contains(line, " = ") && !strings.Contains(line, "==")
	case LangJavaScript, LangTypeScript:
		return strings.Contains(line, "const ") || strings.Contains(line, "let ") || strings.Contains(line, "var ")
	case LangJava, LangCSharp:
		return strings.Contains(line, " = ") && !strings.Contains(line, "==") && !strings.Contains(line, "!=")
	case LangRust:
		return strings.HasPrefix(line, "let ") || strings.HasPrefix(line, "const ")
	}
	return false
}

func determineConfidence(ctx *LineContext, lang Language) types.Confidence {
	// Comments and strings are low confidence
	if ctx.IsComment || ctx.IsString {
		return types.ConfidenceLow
	}

	// Imports are high confidence for library detection
	if ctx.IsImport {
		return types.ConfidenceHigh
	}

	// Function definitions with crypto names are high confidence
	if ctx.IsFunction {
		return types.ConfidenceHigh
	}

	// Variable assignments are medium-high confidence
	if ctx.IsVariable {
		return types.ConfidenceMedium
	}

	return types.ConfidenceMedium
}

func determinePurpose(line string, prevLines []string, lang Language) string {
	lineLower := strings.ToLower(line)
	context := strings.ToLower(strings.Join(prevLines, " "))

	// Check for authentication patterns
	authPatterns := []string{"auth", "login", "session", "token", "jwt", "oauth", "credential", "password"}
	for _, p := range authPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "authentication"
		}
	}

	// Check for encryption patterns
	encryptPatterns := []string{"encrypt", "decrypt", "cipher", "plaintext", "ciphertext"}
	for _, p := range encryptPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "encryption"
		}
	}

	// Check for signing patterns
	signPatterns := []string{"sign", "verify", "signature", "certificate", "cert"}
	for _, p := range signPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "signing"
		}
	}

	// Check for hashing patterns
	hashPatterns := []string{"hash", "digest", "checksum", "integrity"}
	for _, p := range hashPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "hashing"
		}
	}

	// Check for key exchange patterns
	kexPatterns := []string{"key exchange", "key agreement", "handshake", "negotiate"}
	for _, p := range kexPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "key-exchange"
		}
	}

	// Check for TLS/SSL patterns
	tlsPatterns := []string{"tls", "ssl", "https", "certificate"}
	for _, p := range tlsPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "tls-configuration"
		}
	}

	return "general"
}

// ContextPatterns contains patterns that indicate specific crypto contexts
var ContextPatterns = map[string]*regexp.Regexp{
	"key_generation":  regexp.MustCompile(`(?i)(generate|create|new).*key`),
	"encryption":      regexp.MustCompile(`(?i)(encrypt|cipher|encode)`),
	"decryption":      regexp.MustCompile(`(?i)(decrypt|decipher|decode)`),
	"signing":         regexp.MustCompile(`(?i)(sign|signature)`),
	"verification":    regexp.MustCompile(`(?i)(verify|validate)`),
	"hashing":         regexp.MustCompile(`(?i)(hash|digest|checksum)`),
	"key_exchange":    regexp.MustCompile(`(?i)(exchange|agree|handshake|negotiate)`),
	"password":        regexp.MustCompile(`(?i)(password|passphrase|secret)`),
	"certificate":     regexp.MustCompile(`(?i)(cert|x509|pem|der)`),
	"random":          regexp.MustCompile(`(?i)(random|entropy|seed)`),
}

// DetectCryptoContext detects what cryptographic operation is happening
func DetectCryptoContext(line string) []string {
	var contexts []string
	for name, pattern := range ContextPatterns {
		if pattern.MatchString(line) {
			contexts = append(contexts, name)
		}
	}
	return contexts
}
