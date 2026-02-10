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
					`|` +
					`\b(sk_(?:live|test)_[A-Za-z0-9]{24,})` + // Stripe secret
					`|` +
					`\b(pk_(?:live|test)_[A-Za-z0-9]{24,})` + // Stripe publishable
					`|` +
					`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})` + // SendGrid
					`|` +
					`\b(sk-ant-[A-Za-z0-9_\-]{32,})` + // Anthropic
					`|` +
					`\b(AC[a-z0-9]{32})` + // Twilio Account SID
					`|` +
					`\b(dop_v1_[a-f0-9]{64})` + // DigitalOcean
					`|` +
					`\b(hf_[A-Za-z0-9]{34})` + // HuggingFace
					`|` +
					`\b(npm_[A-Za-z0-9]{36})` + // NPM token
					`|` +
					`\b(pypi-[A-Za-z0-9_\-]{16,})` + // PyPI token
					`|` +
					`\b(nuget[A-Za-z0-9]{46})` + // NuGet API key
					`)`,
			),
			description: "Detects various API keys and tokens",
		},
	}
}

// apiKeyKeywords are cheap pre-screen terms — if none are present, skip regex.
var apiKeyKeywords = []string{
	"api_key", "api-key", "apikey", "access_token", "access-token",
	"auth_token", "auth-token", "bearer", "secret_key", "secret-key",
	"private_key", "private-key",
	"sk-", "ghp_", "gho_", "glpat-", "xox", "sk_live", "sk_test",
	"pk_live", "pk_test", "sg.", "sk-ant-", "dop_v1_", "hf_", "npm_",
	"pypi-", "nuget",
}

// Match finds all API key matches in content
func (m *APIKeyMatcher) Match(content string) []Match {
	// Fast pre-screen: skip regex if no API key indicators found
	lower := strings.ToLower(content)
	found := false
	for _, kw := range apiKeyKeywords {
		if strings.Contains(lower, kw) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

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
	if strings.HasPrefix(match, "sk-ant-") { // Anthropic (check before generic sk-)
		return 0.98
	}
	if strings.HasPrefix(match, "sk-") { // OpenAI
		return 0.98
	}
	if strings.HasPrefix(match, "sk_live_") || strings.HasPrefix(match, "sk_test_") { // Stripe secret
		return 0.98
	}
	if strings.HasPrefix(match, "pk_live_") || strings.HasPrefix(match, "pk_test_") { // Stripe publishable
		return 0.95
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
	if strings.HasPrefix(match, "SG.") { // SendGrid
		return 0.98
	}
	if strings.HasPrefix(match, "AC") && len(match) == 34 { // Twilio
		return 0.95
	}
	if strings.HasPrefix(match, "dop_v1_") { // DigitalOcean
		return 0.98
	}
	if strings.HasPrefix(match, "hf_") { // HuggingFace
		return 0.95
	}
	if strings.HasPrefix(match, "npm_") { // NPM
		return 0.95
	}
	if strings.HasPrefix(match, "pypi-") { // PyPI
		return 0.95
	}
	if strings.HasPrefix(match, "nuget") && len(match) > 50 { // NuGet
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
			piiType:     PIITypePrivateKey,
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

// ============================================================================
// Azure Credential Matcher
// ============================================================================

// AzureCredentialMatcher detects Azure-specific credentials
type AzureCredentialMatcher struct {
	baseMatcher
	connStringPattern *regexp.Regexp
	sasTokenPattern   *regexp.Regexp
}

// NewAzureCredentialMatcher creates a new Azure credential matcher
func NewAzureCredentialMatcher() *AzureCredentialMatcher {
	return &AzureCredentialMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-azure-key",
			name:        "Azure Credential",
			patternType: PatternTypeCredential,
			piiType:     PIITypeAzureKey,
			severity:    SeverityCritical,
			riskBase:    0.95,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					// Azure Storage Account Key with label
					`(?:AccountKey|azure[_-]?(?:storage[_-]?)?(?:key|secret|connection))[\s:='"]*([A-Za-z0-9+/=]{44,88})` +
					`|` +
					// Azure AD Client Secret with label
					`(?:client[_-]?secret|azure[_-]?(?:ad|active[_-]?directory)[_-]?(?:secret|key))[\s:='"]*([A-Za-z0-9~._\-]{34,})` +
					`)`,
			),
			description: "Detects Azure credentials including storage keys and AD client secrets",
		},
		connStringPattern: regexp.MustCompile(
			`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,88}`,
		),
		sasTokenPattern: regexp.MustCompile(
			`(?i)\?sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*?&sig=[A-Za-z0-9%+/=]+`,
		),
	}
}

// Match finds all Azure credential matches in content
func (m *AzureCredentialMatcher) Match(content string) []Match {
	var allMatches []Match

	// Standard label-based matches
	allMatches = append(allMatches, m.findAllMatches(content, 50)...)

	// Azure Connection Strings
	for _, idx := range m.connStringPattern.FindAllStringIndex(content, -1) {
		start, end := idx[0], idx[1]
		allMatches = append(allMatches, Match{
			Value:    content[start:end],
			StartPos: start,
			EndPos:   end,
			Context:  extractContext(content, start, end, 50),
		})
	}

	// Azure SAS Tokens
	for _, idx := range m.sasTokenPattern.FindAllStringIndex(content, -1) {
		start, end := idx[0], idx[1]
		allMatches = append(allMatches, Match{
			Value:    content[start:end],
			StartPos: start,
			EndPos:   end,
			Context:  extractContext(content, start, end, 50),
		})
	}

	return deduplicateMatches(allMatches)
}

// GetConfidenceScore returns confidence for Azure credentials
func (m *AzureCredentialMatcher) GetConfidenceScore(match string) float64 {
	if strings.Contains(match, "DefaultEndpointsProtocol") {
		return 0.98
	}
	if strings.Contains(match, "AccountKey") {
		return 0.95
	}
	lowerMatch := strings.ToLower(match)
	if strings.Contains(lowerMatch, "azure") || strings.Contains(lowerMatch, "?sv=") {
		return 0.90
	}
	return 0.85
}

// ============================================================================
// GCP Key Matcher
// ============================================================================

// GCPKeyMatcher detects Google Cloud Platform credentials
type GCPKeyMatcher struct {
	baseMatcher
	serviceAccountPattern *regexp.Regexp
}

// NewGCPKeyMatcher creates a new GCP key matcher
func NewGCPKeyMatcher() *GCPKeyMatcher {
	return &GCPKeyMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-gcp-key",
			name:        "GCP Credential",
			patternType: PatternTypeCredential,
			piiType:     PIITypeGCPKey,
			severity:    SeverityCritical,
			riskBase:    0.95,
			pattern: regexp.MustCompile(
				`(?:` +
					// GCP API Key (AIza prefix is distinctive)
					`\bAIza[0-9A-Za-z_\-]{35}\b` +
					`|` +
					// GCP key with label
					`(?i)(?:google[_-]?(?:api[_-]?)?key|gcp[_-]?(?:api[_-]?)?key)[\s:='"]+([A-Za-z0-9_\-]{20,})` +
					`)`,
			),
			description: "Detects GCP API keys and service account patterns",
		},
		serviceAccountPattern: regexp.MustCompile(
			`(?s)"type"\s*:\s*"service_account".*?"private_key"\s*:\s*"-----BEGIN`,
		),
	}
}

// Match finds all GCP key matches in content
func (m *GCPKeyMatcher) Match(content string) []Match {
	allMatches := m.findAllMatches(content, 50)

	// Check for service account JSON
	for _, idx := range m.serviceAccountPattern.FindAllStringIndex(content, -1) {
		start, end := idx[0], idx[1]
		allMatches = append(allMatches, Match{
			Value:    content[start:end],
			StartPos: start,
			EndPos:   end,
			Context:  extractContext(content, start, end, 50),
		})
	}

	return allMatches
}

// GetConfidenceScore returns confidence for GCP keys
func (m *GCPKeyMatcher) GetConfidenceScore(match string) float64 {
	if strings.HasPrefix(match, "AIza") {
		return 0.98
	}
	if strings.Contains(match, "service_account") {
		return 0.99
	}
	return 0.85
}

// ============================================================================
// JWT Token Matcher
// ============================================================================

// JWTTokenMatcher detects JWT tokens (critical for Keycloak)
type JWTTokenMatcher struct {
	baseMatcher
}

// NewJWTTokenMatcher creates a new JWT token matcher
func NewJWTTokenMatcher() *JWTTokenMatcher {
	return &JWTTokenMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-jwt-token",
			name:        "JWT Token",
			patternType: PatternTypeCredential,
			piiType:     PIITypeJWTToken,
			severity:    SeverityHigh,
			riskBase:    0.85,
			// JWT format: header.payload.signature (each base64url-encoded)
			pattern: regexp.MustCompile(
				`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
			),
			description: "Detects JWT tokens including Keycloak/OIDC tokens",
		},
	}
}

// Match finds all JWT token matches in content
func (m *JWTTokenMatcher) Match(content string) []Match {
	return m.findAllMatches(content, 50)
}

// GetConfidenceScore returns confidence for JWT tokens
func (m *JWTTokenMatcher) GetConfidenceScore(match string) float64 {
	// All JWT tokens with proper 3-part structure are high confidence
	parts := strings.Split(match, ".")
	if len(parts) == 3 && strings.HasPrefix(parts[0], "eyJ") && strings.HasPrefix(parts[1], "eyJ") {
		return 0.95
	}
	return 0.85
}

// ============================================================================
// OAuth Credential Matcher
// ============================================================================

// OAuthCredentialMatcher detects OAuth/OIDC secrets and Personal Access Tokens
type OAuthCredentialMatcher struct {
	baseMatcher
}

// NewOAuthCredentialMatcher creates a new OAuth credential matcher
func NewOAuthCredentialMatcher() *OAuthCredentialMatcher {
	return &OAuthCredentialMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-oauth-token",
			name:        "OAuth/PAT Credential",
			patternType: PatternTypeCredential,
			piiType:     PIITypeOAuthToken,
			severity:    SeverityHigh,
			riskBase:    0.85,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					// OAuth/OIDC client secrets
					`(?:client[_-]?secret|oauth[_-]?secret|oidc[_-]?secret|keycloak[_-]?secret)[\s:='"]+([A-Za-z0-9_\-]{16,})` +
					`|` +
					// Azure DevOps PAT
					`(?:azure[_-]?devops|ado)[_-]?(?:pat|token)[\s:='"]+([A-Za-z0-9]{52})` +
					`|` +
					// Atlassian/Jira API tokens
					`(?:atlassian|jira|confluence)[_-]?(?:api[_-]?)?(?:key|token)[\s:='"]+([A-Za-z0-9]{24,})` +
					`|` +
					// Bitbucket App Passwords
					`(?:bitbucket)[_-]?(?:app[_-]?)?(?:password|token)[\s:='"]+([A-Za-z0-9]{18,})` +
					`|` +
					// Generic OAuth tokens with labels
					`(?:oauth[_-]?(?:access[_-]?)?token|refresh[_-]?token|bearer[_-]?token)[\s:='"]+([A-Za-z0-9_\-\.]{20,})` +
					`)`,
			),
			description: "Detects OAuth client secrets, OIDC secrets, and platform PATs",
		},
	}
}

// oauthKeywords are cheap pre-screen terms for OAuth/PAT detection.
var oauthKeywords = []string{
	"client_secret", "client-secret", "oauth_secret", "oauth-secret",
	"oidc_secret", "oidc-secret", "keycloak_secret", "keycloak-secret",
	"azure_devops", "azure-devops", "ado_pat", "ado_token", "ado-pat", "ado-token",
	"atlassian", "jira", "confluence", "bitbucket",
	"oauth_token", "oauth-token", "oauth_access", "oauth-access",
	"refresh_token", "refresh-token", "bearer_token", "bearer-token",
}

// Match finds all OAuth credential matches in content
func (m *OAuthCredentialMatcher) Match(content string) []Match {
	// Fast pre-screen: skip regex if no OAuth indicators found
	lower := strings.ToLower(content)
	found := false
	for _, kw := range oauthKeywords {
		if strings.Contains(lower, kw) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

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
func (m *OAuthCredentialMatcher) isFalsePositive(value string) bool {
	placeholders := []string{
		"your_secret", "your-secret", "secret_here", "placeholder",
		"xxxxxxxx", "example", "sample", "test_secret",
	}
	lowerValue := strings.ToLower(value)
	for _, ph := range placeholders {
		if strings.Contains(lowerValue, ph) {
			return true
		}
	}
	return false
}

// GetConfidenceScore returns confidence for OAuth credentials
func (m *OAuthCredentialMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)
	if strings.Contains(lowerMatch, "client_secret") || strings.Contains(lowerMatch, "client-secret") {
		return 0.95
	}
	if strings.Contains(lowerMatch, "keycloak") || strings.Contains(lowerMatch, "oidc") {
		return 0.95
	}
	if strings.Contains(lowerMatch, "azure_devops") || strings.Contains(lowerMatch, "ado") {
		return 0.90
	}
	if strings.Contains(lowerMatch, "atlassian") || strings.Contains(lowerMatch, "jira") {
		return 0.90
	}
	if strings.Contains(lowerMatch, "bitbucket") {
		return 0.90
	}
	return 0.80
}

// ============================================================================
// Connection String Matcher
// ============================================================================

// ConnectionStringMatcher detects database connection URIs with embedded passwords
type ConnectionStringMatcher struct {
	baseMatcher
	jdbcPattern *regexp.Regexp
}

// NewConnectionStringMatcher creates a new connection string matcher
func NewConnectionStringMatcher() *ConnectionStringMatcher {
	return &ConnectionStringMatcher{
		baseMatcher: baseMatcher{
			id:          "cred-connection-string",
			name:        "Database Connection String",
			patternType: PatternTypeCredential,
			piiType:     PIITypeConnectionString,
			severity:    SeverityCritical,
			riskBase:    0.92,
			// Matches URI-style connection strings with embedded credentials
			pattern: regexp.MustCompile(
				`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:]+:[^\s@]+@[^\s]+`,
			),
			description: "Detects database connection strings with embedded passwords",
		},
		jdbcPattern: regexp.MustCompile(
			`(?i)jdbc:[a-z]+://[^\s]+(?:password|pwd)\s*=\s*[^\s;&]+`,
		),
	}
}

// Match finds all connection string matches in content
func (m *ConnectionStringMatcher) Match(content string) []Match {
	allMatches := m.findAllMatches(content, 50)

	// JDBC connection strings
	for _, idx := range m.jdbcPattern.FindAllStringIndex(content, -1) {
		start, end := idx[0], idx[1]
		allMatches = append(allMatches, Match{
			Value:    content[start:end],
			StartPos: start,
			EndPos:   end,
			Context:  extractContext(content, start, end, 50),
		})
	}

	return allMatches
}

// GetConfidenceScore returns confidence for connection strings
func (m *ConnectionStringMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)
	if strings.Contains(lowerMatch, "postgresql://") || strings.Contains(lowerMatch, "postgres://") {
		return 0.95
	}
	if strings.Contains(lowerMatch, "mongodb") {
		return 0.95
	}
	if strings.Contains(lowerMatch, "mysql://") {
		return 0.95
	}
	if strings.Contains(lowerMatch, "redis://") {
		return 0.90
	}
	if strings.Contains(lowerMatch, "jdbc:") {
		return 0.90
	}
	return 0.85
}

// ============================================================================
// Helper functions
// ============================================================================

// deduplicateMatches removes overlapping matches, keeping the longer one
func deduplicateMatches(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}

	result := make([]Match, 0, len(matches))
	for i, m := range matches {
		overlaps := false
		for j, other := range matches {
			if i == j {
				continue
			}
			// If m is contained within other and other is longer, skip m
			if m.StartPos >= other.StartPos && m.EndPos <= other.EndPos && len(other.Value) > len(m.Value) {
				overlaps = true
				break
			}
		}
		if !overlaps {
			result = append(result, m)
		}
	}
	return result
}
