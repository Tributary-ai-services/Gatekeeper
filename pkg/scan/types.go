// Package scan provides content scanning capabilities for PII detection,
// compliance checking, and injection detection.
package scan

import (
	"time"
)

// PIIType represents different types of personally identifiable information
type PIIType string

const (
	PIITypeSSN                 PIIType = "ssn"
	PIITypeCreditCard          PIIType = "credit_card"
	PIITypeEmail               PIIType = "email"
	PIITypePhoneNumber         PIIType = "phone_number"
	PIITypeIPAddress           PIIType = "ip_address"
	PIITypeBankAccount         PIIType = "bank_account"
	PIITypePassport            PIIType = "passport"
	PIITypeDriversLicense      PIIType = "drivers_license"
	PIITypeDateOfBirth         PIIType = "date_of_birth"
	PIITypeAddress             PIIType = "address"
	PIITypeName                PIIType = "name"
	PIITypeMedicalRecordNumber PIIType = "medical_record_number"
	PIITypeAWSAccessKey        PIIType = "aws_access_key"
	PIITypeAWSSecretKey        PIIType = "aws_secret_key"
	PIITypeAPIKey              PIIType = "api_key"
	PIITypeAzureKey            PIIType = "azure_key"
	PIITypeGCPKey              PIIType = "gcp_key"
	PIITypeJWTToken            PIIType = "jwt_token"
	PIITypeOAuthToken          PIIType = "oauth_token"
	PIITypePrivateKey          PIIType = "private_key"
	PIITypeConnectionString    PIIType = "connection_string"
	PIITypeCustom              PIIType = "custom"
)

// PatternType categorizes detection patterns
type PatternType string

const (
	PatternTypePII        PatternType = "pii"
	PatternTypeCredential PatternType = "credential"
	PatternTypeInjection  PatternType = "injection"
	PatternTypeCustom     PatternType = "custom"
)

// InjectionType represents different types of injection attacks
type InjectionType string

const (
	InjectionTypeSQL         InjectionType = "sql_injection"
	InjectionTypeXSS         InjectionType = "xss"
	InjectionTypeHTML        InjectionType = "html_injection"
	InjectionTypePrompt      InjectionType = "prompt_injection"
	InjectionTypeControlChar InjectionType = "control_chars"
)

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityValue returns numeric value for severity comparison
func (s Severity) Value() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// RedactionStrategy defines how sensitive content should be redacted
type RedactionStrategy string

const (
	RedactionNone     RedactionStrategy = "none"
	RedactionMask     RedactionStrategy = "mask"     // j***@***.com
	RedactionReplace  RedactionStrategy = "replace"  // [EMAIL]
	RedactionHash     RedactionStrategy = "hash"     // [HASH:abc123]
	RedactionRemove   RedactionStrategy = "remove"   // (empty)
	RedactionTokenize RedactionStrategy = "tokenize" // [email:abc12345]
)

// Framework represents a compliance framework
type Framework string

const (
	FrameworkPII     Framework = "PII"
	FrameworkHIPAA   Framework = "HIPAA"
	FrameworkGDPR    Framework = "GDPR"
	FrameworkPCIDSS  Framework = "PCI_DSS"
	FrameworkSOX     Framework = "SOX"
	FrameworkCCPA    Framework = "CCPA"
	FrameworkSecurity  Framework = "SECURITY"
	FrameworkNISTCSF   Framework = "NIST_CSF"
	FrameworkNISTAIRMF Framework = "NIST_AI_RMF"
	FrameworkSOC2      Framework = "SOC2"
	FrameworkEUAIAct   Framework = "EU_AI_ACT"
	FrameworkISO27001  Framework = "ISO_27001"
)

// TrustTier represents the trust level of content source
type TrustTier int

const (
	TierInternal TrustTier = iota // Your own services, system prompts
	TierPartner                   // Known third-party MCP servers
	TierExternal                  // Untrusted user input, unknown MCP servers
)

// String returns string representation of TrustTier
func (t TrustTier) String() string {
	switch t {
	case TierInternal:
		return "internal"
	case TierPartner:
		return "partner"
	case TierExternal:
		return "external"
	default:
		return "unknown"
	}
}

// TrustTierFromString converts string to TrustTier
func TrustTierFromString(s string) TrustTier {
	switch s {
	case "internal":
		return TierInternal
	case "partner":
		return TierPartner
	case "external":
		return TierExternal
	default:
		return TierExternal // Default to most restrictive
	}
}

// ScanProfile defines which scans to perform
type ScanProfile string

const (
	ProfileFull          ScanProfile = "full"
	ProfileCompliance    ScanProfile = "compliance"
	ProfilePIIOnly       ScanProfile = "pii_only"
	ProfileInjectionOnly ScanProfile = "injection_only"
)

// Finding represents a detected sensitive data instance
type Finding struct {
	ID            string            `json:"id"`
	PatternID     string            `json:"pattern_id"`     // "email", "ssn", "sql_injection"
	PatternType   PatternType       `json:"pattern_type"`   // "pii", "credential", "injection"
	PIIType       PIIType           `json:"pii_type,omitempty"`
	InjectionType InjectionType     `json:"injection_type,omitempty"`

	// Match details
	Value         string            `json:"value"`
	Confidence    float64           `json:"confidence"`
	Location      Location          `json:"location"`
	Context       string            `json:"context"`

	// Classification
	Frameworks    []FrameworkMatch  `json:"frameworks"`
	Severity      Severity          `json:"severity"`

	// Value handling (never log actual PII)
	ValueHash     string            `json:"value_hash"`
	ValuePreview  string            `json:"value_preview"` // "j***@***.com"

	// Outcome
	Redacted      bool              `json:"redacted"`
	RedactedWith  string            `json:"redacted_with,omitempty"`
	Tokenized     bool              `json:"tokenized"`
	TokenID       string            `json:"token_id,omitempty"`

	// Metadata
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Location represents where a finding was detected
type Location struct {
	Offset    int    `json:"offset"`
	Length    int    `json:"length"`
	EndOffset int    `json:"end_offset"`
	FieldPath string `json:"field_path,omitempty"` // "messages[2].content"
}

// FrameworkMatch represents a compliance framework that a finding violates
type FrameworkMatch struct {
	Framework   Framework `json:"framework"`
	RuleID      string    `json:"rule_id"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description,omitempty"`
}

// ScanResult contains the results of a content scan
type ScanResult struct {
	// Identifiers
	ID            string        `json:"id"`
	RequestID     string        `json:"request_id"`
	TenantID      string        `json:"tenant_id"`

	// Scan details
	ScannedAt     time.Time     `json:"scanned_at"`
	ScanProfile   ScanProfile   `json:"scan_profile"`
	TrustTier     TrustTier     `json:"trust_tier"`

	// Results
	Findings      []Finding     `json:"findings"`
	TotalFindings int           `json:"total_findings"`

	// Risk assessment
	RiskScore     float64       `json:"risk_score"`
	MaxSeverity   Severity      `json:"max_severity"`
	HighRiskCount int           `json:"high_risk_count"`

	// Compliance status
	IsCompliant   bool          `json:"is_compliant"`
	Violations    []Violation   `json:"violations,omitempty"`

	// Performance metrics
	Metadata      ScanMetadata  `json:"metadata"`
}

// ScanMetadata contains scan performance and configuration info
type ScanMetadata struct {
	ScanDuration    time.Duration `json:"scan_duration"`
	ContentLength   int           `json:"content_length"`
	PatternsScanned int           `json:"patterns_scanned"`
	ProcessingTime  time.Duration `json:"processing_time"`
	ScannerVersion  string        `json:"scanner_version"`
	ExtractedLength int           `json:"extracted_length,omitempty"`
}

// Violation represents a compliance rule violation
type Violation struct {
	Framework   Framework `json:"framework"`
	RuleID      string    `json:"rule_id"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	FindingIDs  []string  `json:"finding_ids"`
	Actions     []string  `json:"actions,omitempty"`
}

// Match represents a raw pattern match before classification
type Match struct {
	Value      string  `json:"value"`
	StartPos   int     `json:"start_pos"`
	EndPos     int     `json:"end_pos"`
	Context    string  `json:"context"`
	Confidence float64 `json:"confidence"`
}

// PatternInfo describes a detection pattern
type PatternInfo struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        PatternType `json:"type"`
	PIIType     PIIType     `json:"pii_type,omitempty"`
	Description string      `json:"description"`
	Regex       string      `json:"regex"`
	Severity    Severity    `json:"severity"`
	Examples    []string    `json:"examples,omitempty"`
	RiskBase    float64     `json:"risk_base"`
}

// ScanConfig contains configuration for a scan operation
type ScanConfig struct {
	// Profile settings
	Profile          ScanProfile       `json:"profile"`
	TrustTier        TrustTier         `json:"trust_tier"`

	// Pattern settings
	EnabledPatterns  []PIIType         `json:"enabled_patterns,omitempty"`
	DisabledPatterns []PIIType         `json:"disabled_patterns,omitempty"`
	CustomPatterns   []CustomPattern   `json:"custom_patterns,omitempty"`

	// Thresholds
	MinConfidence    float64           `json:"min_confidence"`
	ContextWindow    int               `json:"context_window"`

	// Limits
	Timeout          time.Duration     `json:"timeout"`
	MaxContentSize   int               `json:"max_content_size"`

	// Redaction
	RedactionMode    RedactionStrategy `json:"redaction_mode"`
	TokenizeTypes    []PIIType         `json:"tokenize_types,omitempty"`
	MaskTypes        []PIIType         `json:"mask_types,omitempty"`

	// Compliance
	ComplianceRules      []ComplianceRule       `json:"compliance_rules,omitempty"`
	ScanMetadata         bool                   `json:"scan_metadata"`
	ClassificationHints  ClassificationContext  `json:"classification_hints,omitempty"`
}

// CustomPattern allows defining custom detection patterns
type CustomPattern struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        PatternType `json:"type"`
	PIIType     PIIType     `json:"pii_type,omitempty"`
	Regex       string      `json:"regex"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	RiskBase    float64     `json:"risk_base"`
	Enabled     bool        `json:"enabled"`
}

// ComplianceRule represents a compliance requirement to check
type ComplianceRule struct {
	Framework  Framework         `json:"framework"`
	RuleID     string            `json:"rule_id"`
	PIITypes   []PIIType         `json:"pii_types"`
	Required   bool              `json:"required"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// DefaultScanConfig returns a default scan configuration
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Profile:         ProfileFull,
		TrustTier:       TierExternal,
		MinConfidence:   0.7,
		ContextWindow:   20,
		Timeout:         30 * time.Second,
		MaxContentSize:  10 * 1024 * 1024, // 10MB
		RedactionMode:   RedactionTokenize,
		ScanMetadata:    true,
	}
}
