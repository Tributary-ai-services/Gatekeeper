// Package pipeline orchestrates the content scanning workflow.
package pipeline

import (
	"context"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// Processor is the main entry point for content processing
type Processor interface {
	// Process performs the full content intelligence pipeline:
	// extract -> scan -> classify -> attest -> stream
	Process(ctx context.Context, req ProcessRequest) (*ProcessResult, error)

	// ScanOnly performs scanning without extraction or attestation
	ScanOnly(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error)

	// Verify verifies an attestation is valid
	Verify(attestation Attestation) (bool, error)

	// Close releases resources
	Close() error
}

// ProcessRequest contains all inputs for content processing
type ProcessRequest struct {
	// Content to process
	Content       []byte `json:"content"`
	ContentType   string `json:"content_type"` // "chat", "document", "tool_response"

	// Query context for relevance extraction
	QueryContext  string `json:"query_context,omitempty"`

	// Trust and scanning settings
	TrustTier     scan.TrustTier   `json:"trust_tier"`
	ScanProfile   scan.ScanProfile `json:"scan_profile"`

	// Identifiers
	TenantID      string `json:"tenant_id"`
	RequestID     string `json:"request_id"`
	UserID        string `json:"user_id,omitempty"`
	Source        string `json:"source"` // "llm_input", "mcp_response", "upload"
	MCPServerID   string `json:"mcp_server_id,omitempty"`

	// Existing attestation (from upstream service)
	Attestation   *Attestation `json:"attestation,omitempty"`

	// Options
	SkipExtraction bool `json:"skip_extraction,omitempty"`
	SkipStreaming  bool `json:"skip_streaming,omitempty"`
}

// ProcessResult contains the output of content processing
type ProcessResult struct {
	// Skip information
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skip_reason,omitempty"` // "valid_attestation", "cache_hit"

	// Scan results
	ScanResult *scan.ScanResult `json:"scan_result,omitempty"`

	// Modified content
	ExtractedContent []byte `json:"extracted_content,omitempty"` // Relevance-filtered
	RedactedContent  []byte `json:"redacted_content,omitempty"`  // With PII redacted/tokenized

	// Attestation for downstream services
	Attestation *Attestation `json:"attestation,omitempty"`

	// Action results
	ActionResult *ActionResult `json:"action_result,omitempty"`

	// Performance metrics
	Metrics ProcessMetrics `json:"metrics"`
}

// Attestation represents a signed scan attestation
type Attestation struct {
	ID             string    `json:"id"`
	ContentHash    string    `json:"content_hash"` // SHA-256 of scanned content

	// Scan summary
	ScanProfile    string    `json:"scan_profile"`
	RuleSetsUsed   []string  `json:"rule_sets"`
	Clean          bool      `json:"clean"`          // No violations found
	ViolationCount int       `json:"violation_count"`
	MaxSeverity    string    `json:"max_severity"`
	Redacted       bool      `json:"redacted"`
	Tokenized      bool      `json:"tokenized"`
	TokenCount     int       `json:"token_count"`

	// Context
	ScannedAt      time.Time `json:"scanned_at"`
	ScannedBy      string    `json:"scanned_by"`  // Service ID
	TenantID       string    `json:"tenant_id"`
	RequestID      string    `json:"request_id"`
	TrustTier      string    `json:"trust_tier"`
	ExpiresAt      time.Time `json:"expires_at"`

	// Signature
	Signature      string    `json:"signature"` // HMAC-SHA256
}

// ActionResult contains results of automated actions
type ActionResult struct {
	Blocked      bool              `json:"blocked"`
	BlockReason  string            `json:"block_reason,omitempty"`
	RulesMatched []string          `json:"rules_matched"`
	Actions      []ActionTaken     `json:"actions"`
	Alerts       []AlertSent       `json:"alerts,omitempty"`
}

// ActionTaken describes an action that was executed
type ActionTaken struct {
	RuleID     string `json:"rule_id"`
	ActionType string `json:"action_type"` // "block", "redact", "alert", etc.
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

// AlertSent describes an alert that was sent
type AlertSent struct {
	Channel   string    `json:"channel"` // "slack", "pagerduty"
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// ProcessMetrics contains performance information
type ProcessMetrics struct {
	TotalDuration      time.Duration `json:"total_duration"`
	ExtractionDuration time.Duration `json:"extraction_duration,omitempty"`
	ScanDuration       time.Duration `json:"scan_duration"`
	AttestDuration     time.Duration `json:"attest_duration,omitempty"`
	ActionDuration     time.Duration `json:"action_duration,omitempty"`
	StreamDuration     time.Duration `json:"stream_duration,omitempty"`

	ContentSize        int  `json:"content_size"`
	ExtractedSize      int  `json:"extracted_size,omitempty"`
	ExtractionRatio    float64 `json:"extraction_ratio,omitempty"`
	FindingsCount      int  `json:"findings_count"`
	AttestationSkipped bool `json:"attestation_skipped"`
}

// ProcessorConfig configures the processor
type ProcessorConfig struct {
	// Service identification
	ServiceID string `json:"service_id"`

	// Feature toggles
	EnableExtraction    bool `json:"enable_extraction"`
	EnableAttestation   bool `json:"enable_attestation"`
	EnableStreaming     bool `json:"enable_streaming"`
	EnableActions       bool `json:"enable_actions"`
	HonorAttestations   bool `json:"honor_attestations"`

	// Extraction settings
	ExtractionThreshold int     `json:"extraction_threshold"` // Min content size to extract
	RelevanceThreshold  float64 `json:"relevance_threshold"`

	// Attestation settings
	AttestationTTL      time.Duration `json:"attestation_ttl"`
	SigningKeyName      string        `json:"signing_key_name"`

	// Timeouts
	ScanTimeout         time.Duration `json:"scan_timeout"`
	ExtractionTimeout   time.Duration `json:"extraction_timeout"`
	ActionTimeout       time.Duration `json:"action_timeout"`
}

// DefaultProcessorConfig returns default processor configuration
func DefaultProcessorConfig() *ProcessorConfig {
	return &ProcessorConfig{
		ServiceID:           "gatekeeper",
		EnableExtraction:    true,
		EnableAttestation:   true,
		EnableStreaming:     true,
		EnableActions:       true,
		HonorAttestations:   true,
		ExtractionThreshold: 32 * 1024, // 32KB
		RelevanceThreshold:  0.3,
		AttestationTTL:      5 * time.Minute,
		SigningKeyName:      "tas-scan-signing-key",
		ScanTimeout:         30 * time.Second,
		ExtractionTimeout:   30 * time.Second,
		ActionTimeout:       10 * time.Second,
	}
}
