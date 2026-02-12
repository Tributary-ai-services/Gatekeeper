// Package types provides shared types used across Gatekeeper packages.
// This package breaks circular dependencies between pipeline, action, and attest packages.
package types

import (
	"time"
)

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
