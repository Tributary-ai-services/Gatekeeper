package scan

import (
	"regexp"
	"strconv"
	"strings"
)

// SSNMatcher detects Social Security Numbers
type SSNMatcher struct {
	baseMatcher
}

// NewSSNMatcher creates a new SSN matcher
func NewSSNMatcher() *SSNMatcher {
	return &SSNMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-ssn",
			name:        "Social Security Number",
			patternType: PatternTypePII,
			piiType:     PIITypeSSN,
			severity:    SeverityCritical,
			riskBase:    0.9,
			pattern:     regexp.MustCompile(`\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b`),
			description: "Detects US Social Security Numbers in various formats",
		},
	}
}

// Match finds all SSN matches in content
func (m *SSNMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Filter out invalid SSNs
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		if m.isValidSSN(match.Value) {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// isValidSSN validates SSN format and rules
func (m *SSNMatcher) isValidSSN(ssn string) bool {
	// Remove separators
	clean := strings.ReplaceAll(ssn, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")

	if len(clean) != 9 {
		return false
	}

	// Check if all digits
	for _, c := range clean {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Area number (first 3 digits) cannot be 000, 666, or 900-999
	area, _ := strconv.Atoi(clean[0:3])
	if area == 0 || area == 666 || area >= 900 {
		return false
	}

	// Group number (middle 2 digits) cannot be 00
	group, _ := strconv.Atoi(clean[3:5])
	if group == 0 {
		return false
	}

	// Serial number (last 4 digits) cannot be 0000
	serial, _ := strconv.Atoi(clean[5:9])
	if serial == 0 {
		return false
	}

	return true
}

// GetConfidenceScore returns confidence based on format
func (m *SSNMatcher) GetConfidenceScore(match string) float64 {
	// Higher confidence for properly formatted SSNs
	if strings.Contains(match, "-") {
		return 0.95
	}
	return 0.85
}

// CreditCardMatcher detects credit card numbers
type CreditCardMatcher struct {
	baseMatcher
}

// NewCreditCardMatcher creates a new credit card matcher
func NewCreditCardMatcher() *CreditCardMatcher {
	return &CreditCardMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-credit-card",
			name:        "Credit Card Number",
			patternType: PatternTypePII,
			piiType:     PIITypeCreditCard,
			severity:    SeverityCritical,
			riskBase:    0.9,
			pattern:     regexp.MustCompile(`\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{15,16})\b`),
			description: "Detects credit card numbers with Luhn validation",
		},
	}
}

// Match finds all credit card matches in content
func (m *CreditCardMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Filter using Luhn algorithm
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		if m.isValidLuhn(match.Value) {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// isValidLuhn validates credit card using Luhn algorithm
func (m *CreditCardMatcher) isValidLuhn(cc string) bool {
	// Remove separators
	clean := strings.ReplaceAll(cc, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")

	if len(clean) < 13 || len(clean) > 19 {
		return false
	}

	// Luhn algorithm
	sum := 0
	alternate := false

	for i := len(clean) - 1; i >= 0; i-- {
		n := int(clean[i] - '0')
		if n < 0 || n > 9 {
			return false
		}

		if alternate {
			n *= 2
			if n > 9 {
				n = (n % 10) + 1
			}
		}

		sum += n
		alternate = !alternate
	}

	return sum%10 == 0
}

// GetConfidenceScore returns confidence based on card type
func (m *CreditCardMatcher) GetConfidenceScore(match string) float64 {
	clean := strings.ReplaceAll(match, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")

	// Known card prefixes increase confidence
	if strings.HasPrefix(clean, "4") { // Visa
		return 0.95
	}
	if strings.HasPrefix(clean, "5") { // Mastercard
		return 0.95
	}
	if strings.HasPrefix(clean, "3") { // Amex
		return 0.95
	}
	if strings.HasPrefix(clean, "6") { // Discover
		return 0.95
	}

	return 0.85
}

// EmailMatcher detects email addresses
type EmailMatcher struct {
	baseMatcher
}

// NewEmailMatcher creates a new email matcher
func NewEmailMatcher() *EmailMatcher {
	return &EmailMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-email",
			name:        "Email Address",
			patternType: PatternTypePII,
			piiType:     PIITypeEmail,
			severity:    SeverityMedium,
			riskBase:    0.4,
			pattern:     regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
			description: "Detects email addresses",
		},
	}
}

// Match finds all email matches in content
func (m *EmailMatcher) Match(content string) []Match {
	return m.findAllMatches(content, 50)
}

// GetConfidenceScore returns confidence based on email format
func (m *EmailMatcher) GetConfidenceScore(match string) float64 {
	// Common domains increase confidence
	lowerMatch := strings.ToLower(match)
	commonDomains := []string{".com", ".org", ".net", ".edu", ".gov"}
	for _, domain := range commonDomains {
		if strings.HasSuffix(lowerMatch, domain) {
			return 0.95
		}
	}
	return 0.85
}

// PhoneNumberMatcher detects phone numbers
type PhoneNumberMatcher struct {
	baseMatcher
}

// NewPhoneNumberMatcher creates a new phone number matcher
func NewPhoneNumberMatcher() *PhoneNumberMatcher {
	return &PhoneNumberMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-phone",
			name:        "Phone Number",
			patternType: PatternTypePII,
			piiType:     PIITypePhoneNumber,
			severity:    SeverityMedium,
			riskBase:    0.5,
			pattern: regexp.MustCompile(
				`\b(?:` +
					`\+?1?[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}|` + // US format
					`\+?[1-9]\d{1,14}` + // International E.164
					`)\b`,
			),
			description: "Detects phone numbers in various formats",
		},
	}
}

// Match finds all phone number matches in content
func (m *PhoneNumberMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Filter out sequences that are too short
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		digits := countDigits(match.Value)
		if digits >= 10 && digits <= 15 {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// GetConfidenceScore returns confidence based on phone format
func (m *PhoneNumberMatcher) GetConfidenceScore(match string) float64 {
	// Properly formatted numbers get higher confidence
	if strings.Contains(match, "(") || strings.HasPrefix(match, "+") {
		return 0.90
	}
	return 0.75
}

// IPAddressMatcher detects IP addresses
type IPAddressMatcher struct {
	baseMatcher
}

// NewIPAddressMatcher creates a new IP address matcher
func NewIPAddressMatcher() *IPAddressMatcher {
	return &IPAddressMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-ip-address",
			name:        "IP Address",
			patternType: PatternTypePII,
			piiType:     PIITypeIPAddress,
			severity:    SeverityLow,
			riskBase:    0.3,
			pattern: regexp.MustCompile(
				`\b(?:` +
					`(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.` +
					`(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.` +
					`(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.` +
					`(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)` +
					`)\b`,
			),
			description: "Detects IPv4 addresses",
		},
	}
}

// Match finds all IP address matches in content
func (m *IPAddressMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Filter out common non-PII IPs (localhost, private ranges in some contexts)
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		if !m.isExcludedIP(match.Value) {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// isExcludedIP checks if IP should be excluded
func (m *IPAddressMatcher) isExcludedIP(ip string) bool {
	excludedPrefixes := []string{
		"127.",    // Localhost
		"0.",      // Invalid
		"255.",    // Broadcast
		"224.",    // Multicast
		"169.254.", // Link-local
	}

	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// GetConfidenceScore returns confidence for IP addresses
func (m *IPAddressMatcher) GetConfidenceScore(match string) float64 {
	// Public IPs have higher PII risk
	if strings.HasPrefix(match, "10.") ||
		strings.HasPrefix(match, "172.") ||
		strings.HasPrefix(match, "192.168.") {
		return 0.6 // Private ranges, lower risk
	}
	return 0.8
}

// BankAccountMatcher detects bank account numbers
type BankAccountMatcher struct {
	baseMatcher
}

// NewBankAccountMatcher creates a new bank account matcher
func NewBankAccountMatcher() *BankAccountMatcher {
	return &BankAccountMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-bank-account",
			name:        "Bank Account Number",
			patternType: PatternTypePII,
			piiType:     PIITypeBankAccount,
			severity:    SeverityHigh,
			riskBase:    0.8,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`(?:account|acct|a/c)[\s#:]*(\d{8,17})|` + // Account with label
					`(?:routing|aba|rtn)[\s#:]*(\d{9})|` + // Routing number
					`\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16})\b` + // IBAN
					`)`,
			),
			description: "Detects bank account numbers and IBANs",
		},
	}
}

// Match finds all bank account matches in content
func (m *BankAccountMatcher) Match(content string) []Match {
	return m.findAllMatches(content, 50)
}

// GetConfidenceScore returns confidence based on context
func (m *BankAccountMatcher) GetConfidenceScore(match string) float64 {
	matchUpper := strings.ToUpper(match)

	// IBAN format has high confidence
	if len(match) > 15 && regexp.MustCompile(`^[A-Z]{2}\d{2}`).MatchString(matchUpper) {
		return 0.95
	}

	// Labeled accounts have high confidence
	if strings.Contains(strings.ToLower(match), "account") ||
		strings.Contains(strings.ToLower(match), "routing") {
		return 0.90
	}

	return 0.70
}

// DateOfBirthMatcher detects dates of birth
type DateOfBirthMatcher struct {
	baseMatcher
}

// NewDateOfBirthMatcher creates a new date of birth matcher
func NewDateOfBirthMatcher() *DateOfBirthMatcher {
	return &DateOfBirthMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-dob",
			name:        "Date of Birth",
			patternType: PatternTypePII,
			piiType:     PIITypeDateOfBirth,
			severity:    SeverityMedium,
			riskBase:    0.7,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`(?:dob|birth(?:day|date)?|born)[\s:]*` +
					`(\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})` +
					`)`,
			),
			description: "Detects dates of birth with contextual labels",
		},
	}
}

// Match finds all date of birth matches in content
func (m *DateOfBirthMatcher) Match(content string) []Match {
	return m.findAllMatches(content, 50)
}

// GetConfidenceScore returns confidence based on format
func (m *DateOfBirthMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)

	// Explicit DOB labels have high confidence
	if strings.Contains(lowerMatch, "dob") ||
		strings.Contains(lowerMatch, "birth") {
		return 0.95
	}

	return 0.75
}

// Helper function to count digits in a string
func countDigits(s string) int {
	count := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			count++
		}
	}
	return count
}
