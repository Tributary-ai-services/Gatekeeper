// Package middleware provides HTTP and gRPC middleware for integrating Gatekeeper.
package middleware

import (
	"github.com/Tributary-ai-services/Gatekeeper/pkg/pipeline"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// HTTPConfig configures the HTTP scanning middleware
type HTTPConfig struct {
	// Scanning settings
	ScanProfile scan.ScanProfile `json:"scan_profile"`
	TrustTier   scan.TrustTier   `json:"trust_tier"`

	// Header extraction
	TenantIDHeader  string `json:"tenant_id_header"`
	UserIDHeader    string `json:"user_id_header"`
	RequestIDHeader string `json:"request_id_header"`

	// Behavior
	BlockOnViolation bool `json:"block_on_violation"`
	InjectAttestation bool `json:"inject_attestation"`
	RedactResponse   bool `json:"redact_response"`

	// Exemptions
	ExemptPaths   []string `json:"exempt_paths"`
	ExemptMethods []string `json:"exempt_methods"`
}

// DefaultHTTPConfig returns default HTTP middleware configuration
func DefaultHTTPConfig() *HTTPConfig {
	return &HTTPConfig{
		ScanProfile:       scan.ProfileFull,
		TrustTier:         scan.TierExternal,
		TenantIDHeader:    "X-Tenant-ID",
		UserIDHeader:      "X-User-ID",
		RequestIDHeader:   "X-Request-ID",
		BlockOnViolation:  true,
		InjectAttestation: true,
		RedactResponse:    false,
		ExemptPaths:       []string{"/health", "/metrics"},
		ExemptMethods:     []string{"OPTIONS"},
	}
}

// GinMiddleware returns a Gin middleware function for content scanning
// TODO: Implement after gin dependency is resolved
// func GinMiddleware(processor pipeline.Processor, config *HTTPConfig) gin.HandlerFunc

// MiddlewareResult contains the result of middleware processing
type MiddlewareResult struct {
	Blocked     bool
	BlockReason string
	Attestation *pipeline.Attestation
	ScanResult  *scan.ScanResult
}
