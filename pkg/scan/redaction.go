package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// redactionEngine implements the RedactionEngine interface
type redactionEngine struct {
	maskChar    rune
	hashPrefix  string
	tokenFormat string
}

// NewRedactionEngine creates a new redaction engine
func NewRedactionEngine() RedactionEngine {
	return &redactionEngine{
		maskChar:    '*',
		hashPrefix:  "HASH:",
		tokenFormat: "[%s_TOKEN_%s]",
	}
}

// NewRedactionEngineWithConfig creates a redaction engine with custom configuration
func NewRedactionEngineWithConfig(maskChar rune, hashPrefix, tokenFormat string) RedactionEngine {
	return &redactionEngine{
		maskChar:    maskChar,
		hashPrefix:  hashPrefix,
		tokenFormat: tokenFormat,
	}
}

// Redact redacts content based on scan findings
func (e *redactionEngine) Redact(content string, findings []Finding, strategy RedactionStrategy) (string, error) {
	if len(findings) == 0 {
		return content, nil
	}

	// Sort findings by position (reverse order for replacement)
	sortedFindings := make([]Finding, len(findings))
	copy(sortedFindings, findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		return sortedFindings[i].Location.Offset > sortedFindings[j].Location.Offset
	})

	result := content
	for _, finding := range sortedFindings {
		if finding.Location.Offset < 0 || finding.Location.EndOffset > len(content) {
			continue
		}

		original := content[finding.Location.Offset:finding.Location.EndOffset]
		replacement := e.generateReplacement(original, finding.PIIType, strategy)
		result = result[:finding.Location.Offset] + replacement + result[finding.Location.EndOffset:]
	}

	return result, nil
}

// RedactBytes redacts byte content based on scan findings
func (e *redactionEngine) RedactBytes(content []byte, findings []Finding, strategy RedactionStrategy) ([]byte, error) {
	redacted, err := e.Redact(string(content), findings, strategy)
	if err != nil {
		return nil, err
	}
	return []byte(redacted), nil
}

// GeneratePreview generates a masked preview of a value (for logging)
func (e *redactionEngine) GeneratePreview(value string, piiType PIIType) string {
	if len(value) == 0 {
		return ""
	}

	// Type-specific preview generation
	switch piiType {
	case PIITypeEmail:
		return e.maskEmail(value)
	case PIITypeCreditCard:
		return e.maskCreditCard(value)
	case PIITypeSSN:
		return e.maskSSN(value)
	case PIITypePhoneNumber:
		return e.maskPhone(value)
	case PIITypeIPAddress:
		return e.maskIP(value)
	default:
		return e.maskGeneric(value)
	}
}

// GenerateRedactionMap creates a mapping of original to redacted values
func (e *redactionEngine) GenerateRedactionMap(findings []Finding, strategy RedactionStrategy) map[string]string {
	redactionMap := make(map[string]string)

	for _, finding := range findings {
		if finding.Value == "" {
			continue
		}
		redactionMap[finding.Value] = e.generateReplacement(finding.Value, finding.PIIType, strategy)
	}

	return redactionMap
}

// generateReplacement generates a replacement string based on strategy
func (e *redactionEngine) generateReplacement(original string, piiType PIIType, strategy RedactionStrategy) string {
	switch strategy {
	case RedactionNone:
		return original

	case RedactionMask:
		return e.generateMask(original, piiType)

	case RedactionReplace:
		return e.generatePlaceholder(piiType)

	case RedactionHash:
		return e.generateHash(original)

	case RedactionRemove:
		return ""

	case RedactionTokenize:
		return e.generateToken(original, piiType)

	default:
		return e.generateMask(original, piiType)
	}
}

// generateMask creates a masked version of the value
func (e *redactionEngine) generateMask(value string, piiType PIIType) string {
	switch piiType {
	case PIITypeEmail:
		return e.maskEmail(value)
	case PIITypeCreditCard:
		return e.maskCreditCard(value)
	case PIITypeSSN:
		return e.maskSSN(value)
	case PIITypePhoneNumber:
		return e.maskPhone(value)
	case PIITypeIPAddress:
		return e.maskIP(value)
	default:
		return e.maskGeneric(value)
	}
}

// maskEmail masks email addresses (shows first char and domain)
func (e *redactionEngine) maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return e.maskGeneric(email)
	}

	local := parts[0]
	domain := parts[1]

	if len(local) <= 1 {
		return string(e.maskChar) + "@" + domain
	}

	masked := string(local[0]) + strings.Repeat(string(e.maskChar), len(local)-1)
	return masked + "@" + domain
}

// maskCreditCard shows only last 4 digits
func (e *redactionEngine) maskCreditCard(cc string) string {
	// Remove separators for processing
	clean := strings.ReplaceAll(cc, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")

	if len(clean) < 4 {
		return strings.Repeat(string(e.maskChar), len(cc))
	}

	last4 := clean[len(clean)-4:]
	maskedLen := len(clean) - 4

	// Reconstruct with original formatting if possible
	if strings.Contains(cc, "-") {
		return strings.Repeat(string(e.maskChar), 4) + "-" +
			strings.Repeat(string(e.maskChar), 4) + "-" +
			strings.Repeat(string(e.maskChar), 4) + "-" + last4
	}
	if strings.Contains(cc, " ") {
		return strings.Repeat(string(e.maskChar), 4) + " " +
			strings.Repeat(string(e.maskChar), 4) + " " +
			strings.Repeat(string(e.maskChar), 4) + " " + last4
	}

	return strings.Repeat(string(e.maskChar), maskedLen) + last4
}

// maskSSN shows only last 4 digits
func (e *redactionEngine) maskSSN(ssn string) string {
	clean := strings.ReplaceAll(ssn, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")

	if len(clean) < 4 {
		return strings.Repeat(string(e.maskChar), len(ssn))
	}

	last4 := clean[len(clean)-4:]

	// Reconstruct with dashes
	if strings.Contains(ssn, "-") {
		return strings.Repeat(string(e.maskChar), 3) + "-" +
			strings.Repeat(string(e.maskChar), 2) + "-" + last4
	}

	return strings.Repeat(string(e.maskChar), len(clean)-4) + last4
}

// maskPhone shows only last 4 digits
func (e *redactionEngine) maskPhone(phone string) string {
	// Count digits
	digits := make([]rune, 0, len(phone))
	for _, c := range phone {
		if c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}

	if len(digits) < 4 {
		return strings.Repeat(string(e.maskChar), len(phone))
	}

	last4 := string(digits[len(digits)-4:])
	return strings.Repeat(string(e.maskChar), len(phone)-4) + last4
}

// maskIP masks the first three octets
func (e *redactionEngine) maskIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return e.maskGeneric(ip)
	}

	return strings.Repeat(string(e.maskChar), len(parts[0])) + "." +
		strings.Repeat(string(e.maskChar), len(parts[1])) + "." +
		strings.Repeat(string(e.maskChar), len(parts[2])) + "." +
		parts[3]
}

// maskGeneric masks a value, showing first and last characters
func (e *redactionEngine) maskGeneric(value string) string {
	if len(value) <= 2 {
		return strings.Repeat(string(e.maskChar), len(value))
	}

	runes := []rune(value)
	masked := make([]rune, len(runes))
	masked[0] = runes[0]
	masked[len(runes)-1] = runes[len(runes)-1]
	for i := 1; i < len(runes)-1; i++ {
		masked[i] = e.maskChar
	}

	return string(masked)
}

// generatePlaceholder creates a type-specific placeholder
func (e *redactionEngine) generatePlaceholder(piiType PIIType) string {
	placeholders := map[PIIType]string{
		PIITypeSSN:            "[SSN_REDACTED]",
		PIITypeCreditCard:     "[CC_REDACTED]",
		PIITypeEmail:          "[EMAIL_REDACTED]",
		PIITypePhoneNumber:    "[PHONE_REDACTED]",
		PIITypeIPAddress:      "[IP_REDACTED]",
		PIITypeBankAccount:    "[BANK_REDACTED]",
		PIITypeDateOfBirth:    "[DOB_REDACTED]",
		PIITypeDriversLicense: "[DL_REDACTED]",
		PIITypePassport:       "[PASSPORT_REDACTED]",
		PIITypeAddress:        "[ADDRESS_REDACTED]",
		PIITypeName:           "[NAME_REDACTED]",
		PIITypeMedicalRecordNumber: "[MRN_REDACTED]",
		PIITypeAWSAccessKey:   "[AWS_KEY_REDACTED]",
		PIITypeAWSSecretKey:   "[AWS_SECRET_REDACTED]",
		PIITypeAPIKey:         "[API_KEY_REDACTED]",
	}

	if placeholder, ok := placeholders[piiType]; ok {
		return placeholder
	}

	return "[REDACTED]"
}

// generateHash creates a hash of the value
func (e *redactionEngine) generateHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	// Return first 8 chars of hex hash for readability
	return e.hashPrefix + hex.EncodeToString(hash[:])[:8]
}

// generateToken creates a tokenized placeholder
func (e *redactionEngine) generateToken(value string, piiType PIIType) string {
	// Create a short hash for the token ID
	hash := sha256.Sum256([]byte(value))
	tokenID := hex.EncodeToString(hash[:])[:8]

	typeStr := string(piiType)
	if typeStr == "" {
		typeStr = "PII"
	}

	return fmt.Sprintf(e.tokenFormat, strings.ToUpper(typeStr), tokenID)
}

// RedactByMap redacts content using a pre-computed redaction map
func RedactByMap(content string, redactionMap map[string]string) string {
	result := content
	for original, replacement := range redactionMap {
		result = strings.ReplaceAll(result, original, replacement)
	}
	return result
}

// RedactionStats provides statistics about redaction operations
type RedactionStats struct {
	TotalFindings    int
	RedactedCount    int
	ByType           map[PIIType]int
	ByStrategy       map[RedactionStrategy]int
	CharactersHidden int
}

// ComputeRedactionStats computes statistics for redaction
func ComputeRedactionStats(findings []Finding, strategy RedactionStrategy) *RedactionStats {
	stats := &RedactionStats{
		TotalFindings: len(findings),
		ByType:        make(map[PIIType]int),
		ByStrategy:    make(map[RedactionStrategy]int),
	}

	for _, finding := range findings {
		stats.RedactedCount++
		stats.ByType[finding.PIIType]++
		stats.ByStrategy[strategy]++
		stats.CharactersHidden += len(finding.Value)
	}

	return stats
}
