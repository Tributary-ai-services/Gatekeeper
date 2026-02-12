// Package pipeline orchestrates the content scanning workflow.
package pipeline

import (
	"context"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// Type aliases for backward compatibility - types now live in pkg/types
type Attestation = types.Attestation
type ActionResult = types.ActionResult
type ActionTaken = types.ActionTaken
type AlertSent = types.AlertSent
type ProcessMetrics = types.ProcessMetrics

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
