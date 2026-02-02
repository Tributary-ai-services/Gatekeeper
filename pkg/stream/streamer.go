// Package stream provides Kafka streaming for compliance findings.
package stream

import (
	"context"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// Streamer publishes findings to Kafka
type Streamer interface {
	// Stream publishes findings to Kafka
	Stream(ctx context.Context, findings []Finding) error

	// StreamBatch publishes a batch of findings
	StreamBatch(ctx context.Context, batch []Finding) error

	// Close flushes pending messages and closes the connection
	Close() error
}

// Finding represents a streaming finding event
type Finding struct {
	// Identifiers
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	Timestamp     time.Time `json:"timestamp"`

	// Pattern info
	PatternID     string         `json:"pattern_id"`
	PatternType   scan.PatternType `json:"pattern_type"`

	// Location
	Source        string `json:"source"` // "llm_input", "mcp_response", "upload"
	Location      scan.Location `json:"location"`

	// Classification
	Frameworks    []string      `json:"frameworks"`
	Severity      scan.Severity `json:"severity"`

	// Context
	TenantID      string `json:"tenant_id"`
	UserID        string `json:"user_id,omitempty"`
	MCPServerID   string `json:"mcp_server_id,omitempty"`
	ContentType   string `json:"content_type"`

	// Value (safely handled)
	ValueHash     string `json:"value_hash"`
	ValuePreview  string `json:"value_preview"`

	// Outcome
	ActionTaken   string `json:"action_taken"`
	Redacted      bool   `json:"redacted"`
	Tokenized     bool   `json:"tokenized"`
}

// ActionEvent represents an action taken event
type ActionEvent struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	RequestID   string    `json:"request_id"`
	Timestamp   time.Time `json:"timestamp"`
	TenantID    string    `json:"tenant_id"`
	RuleID      string    `json:"rule_id"`
	ActionType  string    `json:"action_type"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
}

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id,omitempty"`
	RequestID   string    `json:"request_id"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// StreamerConfig configures the streamer
type StreamerConfig struct {
	// Kafka settings
	Brokers        []string `json:"brokers"`
	Topics         Topics   `json:"topics"`

	// Producer settings
	BatchSize      int           `json:"batch_size"`
	FlushInterval  time.Duration `json:"flush_interval"`
	Compression    string        `json:"compression"` // "none", "gzip", "snappy", "lz4"
	RequiredAcks   string        `json:"required_acks"` // "none", "leader", "all"

	// Retry settings
	MaxRetries     int           `json:"max_retries"`
	RetryBackoff   time.Duration `json:"retry_backoff"`
}

// Topics defines Kafka topics for different event types
type Topics struct {
	Findings string `json:"findings"`  // All findings
	Critical string `json:"critical"`  // Critical severity only
	HIPAA    string `json:"hipaa"`     // HIPAA-specific
	PCI      string `json:"pci"`       // PCI-DSS specific
	Actions  string `json:"actions"`   // Action events
	Audit    string `json:"audit"`     // Audit log
}

// DefaultStreamerConfig returns default streamer configuration
func DefaultStreamerConfig() *StreamerConfig {
	return &StreamerConfig{
		Brokers: []string{"localhost:9092"},
		Topics: Topics{
			Findings: "tas.compliance.findings",
			Critical: "tas.compliance.findings.critical",
			HIPAA:    "tas.compliance.findings.hipaa",
			PCI:      "tas.compliance.findings.pci",
			Actions:  "tas.compliance.actions",
			Audit:    "tas.compliance.audit",
		},
		BatchSize:     100,
		FlushInterval: time.Second,
		Compression:   "snappy",
		RequiredAcks:  "all",
		MaxRetries:    3,
		RetryBackoff:  100 * time.Millisecond,
	}
}

// ConvertFinding converts a scan.Finding to a stream.Finding
func ConvertFinding(f *scan.Finding, requestID, tenantID, userID, source, mcpServerID, contentType string) Finding {
	frameworks := make([]string, len(f.Frameworks))
	for i, fm := range f.Frameworks {
		frameworks[i] = string(fm.Framework)
	}

	return Finding{
		ID:           f.ID,
		RequestID:    requestID,
		Timestamp:    time.Now(),
		PatternID:    f.PatternID,
		PatternType:  f.PatternType,
		Source:       source,
		Location:     f.Location,
		Frameworks:   frameworks,
		Severity:     f.Severity,
		TenantID:     tenantID,
		UserID:       userID,
		MCPServerID:  mcpServerID,
		ContentType:  contentType,
		ValueHash:    f.ValueHash,
		ValuePreview: f.ValuePreview,
		Redacted:     f.Redacted,
		Tokenized:    f.Tokenized,
	}
}
