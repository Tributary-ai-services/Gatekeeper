// Package tokenize provides PII tokenization via Databunker.
package tokenize

import (
	"context"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// Tokenizer stores PII in Databunker and returns opaque tokens
type Tokenizer interface {
	// Tokenize stores PII and returns a token
	Tokenize(ctx context.Context, req TokenizeRequest) (*TokenizeResponse, error)

	// TokenizeBatch tokenizes multiple values
	TokenizeBatch(ctx context.Context, reqs []TokenizeRequest) ([]TokenizeResponse, error)

	// Detokenize retrieves original value (requires authorization)
	Detokenize(ctx context.Context, req DetokenizeRequest) (*DetokenizeResponse, error)

	// GetSecret retrieves a secret (e.g., signing key)
	GetSecret(ctx context.Context, secretName string) ([]byte, error)

	// LogAudit logs an audit event
	LogAudit(ctx context.Context, event AuditEvent) error

	// Close releases resources
	Close() error
}

// TokenizeRequest contains inputs for tokenization
type TokenizeRequest struct {
	TenantID  string       `json:"tenant_id"`
	PIIType   scan.PIIType `json:"pii_type"`
	Value     string       `json:"value"`
	RequestID string       `json:"request_id"`
	UserID    string       `json:"user_id,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// TokenizeResponse contains tokenization result
type TokenizeResponse struct {
	Token     string       `json:"token"`      // Opaque token like "abc12345"
	RecordKey string       `json:"record_key"` // Databunker record key
	PIIType   scan.PIIType `json:"pii_type"`
	Created   time.Time    `json:"created"`
}

// DetokenizeRequest contains inputs for detokenization
type DetokenizeRequest struct {
	TenantID  string `json:"tenant_id"`
	Token     string `json:"token"`
	RequestID string `json:"request_id"`
	UserID    string `json:"user_id"`
	Reason    string `json:"reason"` // Audit reason for access
}

// DetokenizeResponse contains detokenization result
type DetokenizeResponse struct {
	Value     string       `json:"value"`
	PIIType   scan.PIIType `json:"pii_type"`
	Retrieved time.Time    `json:"retrieved"`
}

// AuditEvent represents an audit log entry for Databunker
type AuditEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	TenantID  string            `json:"tenant_id"`
	UserID    string            `json:"user_id,omitempty"`
	RequestID string            `json:"request_id"`
	Action    string            `json:"action"` // "tokenize", "detokenize", "delete"
	PIIType   scan.PIIType      `json:"pii_type"`
	Token     string            `json:"token,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// TokenizerConfig configures the tokenizer
type TokenizerConfig struct {
	DatabunkerURL string        `json:"databunker_url"`
	APIKey        string        `json:"api_key"`
	Timeout       time.Duration `json:"timeout"`
	MaxRetries    int           `json:"max_retries"`
	RetryBackoff  time.Duration `json:"retry_backoff"`
	EnableAudit   bool          `json:"enable_audit"`
}

// DefaultTokenizerConfig returns default tokenizer configuration
func DefaultTokenizerConfig() *TokenizerConfig {
	return &TokenizerConfig{
		DatabunkerURL: "http://databunker:3000",
		Timeout:       5 * time.Second,
		MaxRetries:    3,
		RetryBackoff:  100 * time.Millisecond,
		EnableAudit:   true,
	}
}

// TokenFormat returns the formatted token string for embedding in content
func TokenFormat(piiType scan.PIIType, token string) string {
	return "[" + string(piiType) + ":" + token + "]"
}

// Common token patterns for parsing
const (
	TokenPattern = `\[([a-z_]+):([a-zA-Z0-9]+)\]` // [pii_type:token_id]
)
