package scan

import (
	"regexp"
	"strings"
)

// AWSAccessKeyMatcher detects AWS access key IDs
type AWSAccessKeyMatcher struct {
	baseMatcher
}

// NewAWSAccessKeyMatcher creates a new AWS access key matcher
func NewAWSAccessKeyMatcher() *AWSAccessKeyMatcher {
	return &AWSAccessKeyMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-aws-access-key",
			name:        "AWS Access Key ID",
			patternType: PatternTypeCredential,
			piiType:     PIITypeAWSAccessKey,
			severity:    SeverityCritical,
			riskBase:    0.95,
			// AWS Access Key IDs start with AKIA, ABIA, ACCA, or ASIA
			pattern:     regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b`),
			description: "Detects AWS Access Key IDs",
		},
	}
}

// Match finds all AWS access key matches in content
func (m *AWSAccessKeyMatcher) Match(content string) []Match {
	return m.findAllMatches(content, 50)
}

// GetConfidenceScore returns confidence for AWS access keys
func (m *AWSAccessKeyMatcher) GetConfidenceScore(match string) float64 {
	// AKIA prefix is most common for user access keys
	if strings.HasPrefix(match, "AKIA") {
		return 0.98
	}
	// ASIA prefix is for temporary credentials (STS)
	if strings.HasPrefix(match, "ASIA") {
		return 0.95
	}
	return 0.90
}

// AWSSecretKeyMatcher detects AWS secret access keys
type AWSSecretKeyMatcher struct {
	baseMatcher
}

// NewAWSSecretKeyMatcher creates a new AWS secret key matcher
func NewAWSSecretKeyMatcher() *AWSSecretKeyMatcher {
	return &AWSSecretKeyMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-aws-secret-key",
			name:        "AWS Secret Access Key",
			patternType: PatternTypeCredential,
			piiType:     PIITypeAWSSecretKey,
			severity:    SeverityCritical,
			riskBase:    0.98,
			// AWS Secret Keys are 40 characters, base64-like
			pattern:     regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?key)[\s:='"]*([A-Za-z0-9/+=]{40})\b`),
			description: "Detects AWS Secret Access Keys",
		},
	}
}

// Match finds all AWS secret key matches in content
func (m *AWSSecretKeyMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Validate base64-like format
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		if m.isValidSecretKey(match.Value) {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// isValidSecretKey validates secret key format
func (m *AWSSecretKeyMatcher) isValidSecretKey(key string) bool {
	// Extract just the key part if it includes label
	parts := regexp.MustCompile(`[A-Za-z0-9/+=]{40}`).FindString(key)
	if parts == "" {
		return false
	}

	// Should contain mix of characters
	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, c := range parts {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}

	return hasUpper && hasLower && hasDigit
}

// GetConfidenceScore returns confidence for AWS secret keys
func (m *AWSSecretKeyMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)

	// Explicit AWS labels increase confidence
	if strings.Contains(lowerMatch, "aws") {
		return 0.98
	}
	if strings.Contains(lowerMatch, "secret") {
		return 0.95
	}

	return 0.85
}

// APIKeyMatcher detects generic API keys
type APIKeyMatcher struct {
	baseMatcher
}

// NewAPIKeyMatcher creates a new API key matcher
func NewAPIKeyMatcher() *APIKeyMatcher {
	return &APIKeyMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-api-key",
			name:        "API Key",
			patternType: PatternTypeCredential,
			piiType:     PIITypeAPIKey,
			severity:    SeverityHigh,
			riskBase:    0.85,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					// Common API key patterns with labels
					`(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer|secret[_-]?key|private[_-]?key)` +
					`[\s:='"]+([A-Za-z0-9_\-]{20,64})` +
					`|` +
					// Known service prefixes
					`\b(sk-[A-Za-z0-9]{32,})` + // OpenAI
					`|` +
					`\b(ghp_[A-Za-z0-9]{36})` + // GitHub PAT
					`|` +
					`\b(gho_[A-Za-z0-9]{36})` + // GitHub OAuth
					`|` +
					`\b(glpat-[A-Za-z0-9\-_]{20,})` + // GitLab PAT
					`|` +
					`\b(xox[baprs]-[A-Za-z0-9\-]+)` + // Slack tokens
					`)`,
			),
			description: "Detects various API keys and tokens",
		},
	}
}

// Match finds all API key matches in content
func (m *APIKeyMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Filter out obvious false positives
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		if !m.isFalsePositive(match.Value) {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// isFalsePositive checks for common false positives
func (m *APIKeyMatcher) isFalsePositive(value string) bool {
	// Common placeholder values
	placeholders := []string{
		"your_api_key",
		"your-api-key",
		"api_key_here",
		"xxxxxxxx",
		"example",
		"sample",
		"test_key",
		"placeholder",
	}

	lowerValue := strings.ToLower(value)
	for _, ph := range placeholders {
		if strings.Contains(lowerValue, ph) {
			return true
		}
	}

	// All same character
	if len(value) > 0 {
		first := value[0]
		allSame := true
		for _, c := range value {
			if byte(c) != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}

// GetConfidenceScore returns confidence based on key type
func (m *APIKeyMatcher) GetConfidenceScore(match string) float64 {
	// Known service prefixes have high confidence
	if strings.HasPrefix(match, "sk-") { // OpenAI
		return 0.98
	}
	if strings.HasPrefix(match, "ghp_") || strings.HasPrefix(match, "gho_") { // GitHub
		return 0.98
	}
	if strings.HasPrefix(match, "glpat-") { // GitLab
		return 0.98
	}
	if strings.HasPrefix(match, "xox") { // Slack
		return 0.95
	}

	// Generic API key patterns
	lowerMatch := strings.ToLower(match)
	if strings.Contains(lowerMatch, "api") || strings.Contains(lowerMatch, "token") {
		return 0.85
	}

	return 0.70
}

// PrivateKeyMatcher detects private keys (RSA, DSA, etc.)
type PrivateKeyMatcher struct {
	baseMatcher
}

// NewPrivateKeyMatcher creates a new private key matcher
func NewPrivateKeyMatcher() *PrivateKeyMatcher {
	return &PrivateKeyMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-private-key",
			name:        "Private Key",
			patternType: PatternTypeCredential,
			piiType:     PIITypeAPIKey, // Reusing type
			severity:    SeverityCritical,
			riskBase:    0.99,
			pattern: regexp.MustCompile(
				`(?s)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----` +
					`.*?` +
					`-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`,
			),
			description: "Detects PEM-encoded private keys",
		},
	}
}

// Match finds all private key matches in content
func (m *PrivateKeyMatcher) Match(content string) []Match {
	return m.findAllMatches(content, 100)
}

// GetConfidenceScore returns very high confidence for private keys
func (m *PrivateKeyMatcher) GetConfidenceScore(match string) float64 {
	return 0.99 // Private key markers are very reliable
}
