// Package attest provides scan attestation for deduplication across services.
package attest

import (
	"context"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// Attestor creates and verifies scan attestations
type Attestor interface {
	// Create creates a new attestation for a completed scan
	Create(ctx context.Context, req CreateRequest) (*types.Attestation, error)

	// Verify verifies an attestation signature and validity
	Verify(ctx context.Context, attestation *types.Attestation) error

	// CanSkip determines if scanning can be skipped based on existing attestation
	CanSkip(ctx context.Context, req SkipCheckRequest) (canSkip bool, reason string)
}

// CreateRequest contains inputs for creating an attestation
type CreateRequest struct {
	Content      []byte
	ScanResult   *scan.ScanResult
	TenantID     string
	RequestID    string
	ServiceID    string
	TrustTier    scan.TrustTier
	ScanProfile  scan.ScanProfile
	RuleSetsUsed []string
	Redacted     bool
	Tokenized    bool
	TokenCount   int
	TTL          time.Duration
}

// SkipCheckRequest contains inputs for determining if scan can be skipped
type SkipCheckRequest struct {
	Attestation *types.Attestation
	Content     []byte
	TenantID    string
	TrustTier   scan.TrustTier
	ScanProfile scan.ScanProfile
}

// Signer signs attestations using HMAC
type Signer interface {
	// Sign creates HMAC signature for attestation
	Sign(attestation *types.Attestation) (string, error)

	// Verify verifies attestation signature
	Verify(attestation *types.Attestation) error
}

// Cache caches attestations for quick lookup
type Cache interface {
	// Get retrieves an attestation by content hash
	Get(ctx context.Context, contentHash string) (*types.Attestation, error)

	// Set stores an attestation
	Set(ctx context.Context, attestation *types.Attestation) error

	// Delete removes an attestation
	Delete(ctx context.Context, contentHash string) error
}

// AttestorConfig configures the attestor
type AttestorConfig struct {
	ServiceID        string        `json:"service_id"`
	SigningKeyName   string        `json:"signing_key_name"`
	DefaultTTL       time.Duration `json:"default_ttl"`
	EnableCaching    bool          `json:"enable_caching"`
	CacheTTL         time.Duration `json:"cache_ttl"`
	HonorDowngrades  bool          `json:"honor_downgrades"`  // Allow higher trust tier to skip
}

// DefaultAttestorConfig returns default attestor configuration
func DefaultAttestorConfig() *AttestorConfig {
	return &AttestorConfig{
		ServiceID:       "gatekeeper",
		SigningKeyName:  "tas-scan-signing-key",
		DefaultTTL:      5 * time.Minute,
		EnableCaching:   true,
		CacheTTL:        5 * time.Minute,
		HonorDowngrades: false,
	}
}

// AttestationHeader constants for HTTP header propagation
const (
	HeaderAttestation = "X-TAS-Scan-Attestation"
	HeaderScanStatus  = "X-TAS-Scan-Status"
	HeaderRequestID   = "X-TAS-Scan-Request-ID"
)

// ScanStatus values for header
const (
	StatusClean      = "clean"
	StatusViolations = "violations"
	StatusTokenized  = "tokenized"
	StatusSkipped    = "skipped"
)
