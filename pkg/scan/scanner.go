package scan

import (
	"context"
)

// Scanner is the main interface for content scanning
type Scanner interface {
	// Scan scans content for PII, compliance violations, and injection attacks
	Scan(ctx context.Context, content []byte, config *ScanConfig) (*ScanResult, error)

	// ScanString is a convenience method for scanning string content
	ScanString(ctx context.Context, content string, config *ScanConfig) (*ScanResult, error)

	// GetSupportedPatterns returns all patterns this scanner can detect
	GetSupportedPatterns() []PatternInfo

	// ValidateConfig validates a scan configuration
	ValidateConfig(config *ScanConfig) error
}

// PatternMatcher defines an interface for detecting specific patterns
type PatternMatcher interface {
	// GetID returns the pattern identifier
	GetID() string

	// GetName returns the human-readable pattern name
	GetName() string

	// GetType returns the pattern type (pii, credential, injection)
	GetType() PatternType

	// GetPIIType returns the PII type if applicable
	GetPIIType() PIIType

	// Match finds all instances of this pattern in content
	Match(content string) []Match

	// GetConfidenceScore returns confidence score for a specific match
	GetConfidenceScore(match string) float64

	// GetRiskBase returns the base risk score for this pattern
	GetRiskBase() float64

	// GetSeverity returns the default severity for this pattern
	GetSeverity() Severity

	// IsEnabled checks if this matcher should be used given the config
	IsEnabled(config *ScanConfig) bool
}

// RedactionEngine handles redaction and tokenization of detected PII
type RedactionEngine interface {
	// Redact redacts content based on scan findings
	Redact(content string, findings []Finding, strategy RedactionStrategy) (string, error)

	// RedactBytes redacts byte content based on scan findings
	RedactBytes(content []byte, findings []Finding, strategy RedactionStrategy) ([]byte, error)

	// GeneratePreview generates a masked preview of a value (for logging)
	GeneratePreview(value string, piiType PIIType) string

	// GenerateRedactionMap creates a mapping of original to redacted values
	GenerateRedactionMap(findings []Finding, strategy RedactionStrategy) map[string]string
}

// Classifier classifies findings into compliance frameworks
type Classifier interface {
	// Classify determines which frameworks a finding violates
	Classify(finding *Finding, context ClassificationContext) []FrameworkMatch

	// GetFrameworkRules returns rules for a specific framework
	GetFrameworkRules(framework Framework) []FrameworkRule
}

// ClassificationContext provides context for classification decisions
type ClassificationContext struct {
	TenantID      string
	Source        string
	ContentType   string
	Hints         []string // Context hints like "healthcare", "financial", "EU"
	IsEUData      bool
	IsHealthcare  bool
	IsFinancial   bool
}

// FrameworkRule defines how a pattern maps to a compliance framework
type FrameworkRule struct {
	Framework   Framework
	RuleID      string
	Severity    Severity
	Description string
	Condition   func(ctx ClassificationContext) bool
}

// ComplianceChecker validates scan results against compliance requirements
type ComplianceChecker interface {
	// Check validates findings against compliance rules
	Check(ctx context.Context, result *ScanResult, rules []ComplianceRule) ([]Violation, error)

	// GetSupportedFrameworks returns supported compliance frameworks
	GetSupportedFrameworks() []Framework
}

// PatternRegistry manages pattern matchers
type PatternRegistry interface {
	// Register adds a pattern matcher to the registry
	Register(matcher PatternMatcher)

	// Get returns a matcher by ID
	Get(id string) (PatternMatcher, bool)

	// GetByType returns all matchers of a given type
	GetByType(patternType PatternType) []PatternMatcher

	// GetByPIIType returns the matcher for a specific PII type
	GetByPIIType(piiType PIIType) (PatternMatcher, bool)

	// GetAll returns all registered matchers
	GetAll() []PatternMatcher

	// GetEnabled returns matchers enabled for the given config
	GetEnabled(config *ScanConfig) []PatternMatcher
}
