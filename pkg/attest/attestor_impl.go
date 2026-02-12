package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
	"github.com/google/uuid"
)

// defaultAttestor implements the Attestor interface combining signer and cache.
type defaultAttestor struct {
	signer Signer
	cache  Cache
	config *AttestorConfig
}

// NewAttestor creates a new Attestor with an HMAC signer and memory cache.
func NewAttestor(signingKey []byte, config *AttestorConfig) Attestor {
	if config == nil {
		config = DefaultAttestorConfig()
	}
	return &defaultAttestor{
		signer: NewHMACSigner(signingKey),
		cache:  NewMemoryCache(),
		config: config,
	}
}

// NewAttestorWithComponents creates a new Attestor with provided signer and cache.
func NewAttestorWithComponents(signer Signer, cache Cache, config *AttestorConfig) Attestor {
	if config == nil {
		config = DefaultAttestorConfig()
	}
	return &defaultAttestor{
		signer: signer,
		cache:  cache,
		config: config,
	}
}

// Create creates a new attestation for a completed scan.
func (a *defaultAttestor) Create(ctx context.Context, req CreateRequest) (*types.Attestation, error) {
	// Compute SHA-256 hash of content
	contentHash := computeContentHash(req.Content)

	// Determine TTL
	ttl := req.TTL
	if ttl == 0 {
		ttl = a.config.DefaultTTL
	}

	now := time.Now()

	// Determine max severity
	maxSeverity := ""
	if req.ScanResult != nil {
		maxSeverity = string(req.ScanResult.MaxSeverity)
	}

	// Build attestation
	attestation := &types.Attestation{
		ID:             uuid.New().String(),
		ContentHash:    contentHash,
		ScanProfile:    string(req.ScanProfile),
		RuleSetsUsed:   req.RuleSetsUsed,
		Clean:          req.ScanResult != nil && len(req.ScanResult.Findings) == 0,
		ViolationCount: 0,
		MaxSeverity:    maxSeverity,
		Redacted:       req.Redacted,
		Tokenized:      req.Tokenized,
		TokenCount:     req.TokenCount,
		ScannedAt:      now,
		ScannedBy:      a.config.ServiceID,
		TenantID:       req.TenantID,
		RequestID:      req.RequestID,
		TrustTier:      req.TrustTier.String(),
		ExpiresAt:      now.Add(ttl),
	}

	if req.ScanResult != nil {
		attestation.ViolationCount = len(req.ScanResult.Findings)
	}

	// Sign the attestation
	sig, err := a.signer.Sign(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %w", err)
	}
	attestation.Signature = sig

	// Cache the attestation
	if a.config.EnableCaching {
		if err := a.cache.Set(ctx, attestation); err != nil {
			// Cache failure is non-fatal; log and continue
			_ = err
		}
	}

	return attestation, nil
}

// Verify verifies an attestation signature and checks that it has not expired.
func (a *defaultAttestor) Verify(_ context.Context, attestation *types.Attestation) error {
	if attestation == nil {
		return fmt.Errorf("attestation is nil")
	}

	// Check expiry
	if time.Now().After(attestation.ExpiresAt) {
		return fmt.Errorf("attestation has expired at %s", attestation.ExpiresAt.Format(time.RFC3339))
	}

	// Verify signature
	if err := a.signer.Verify(attestation); err != nil {
		return fmt.Errorf("attestation signature invalid: %w", err)
	}

	return nil
}

// CanSkip determines if scanning can be skipped based on an existing attestation.
// Returns (true, reason) if scanning can be skipped, or (false, "") if it cannot.
func (a *defaultAttestor) CanSkip(ctx context.Context, req SkipCheckRequest) (bool, string) {
	// No attestation means we must scan
	if req.Attestation == nil {
		return false, ""
	}

	// Verify attestation signature
	if err := a.signer.Verify(req.Attestation); err != nil {
		return false, ""
	}

	// Check content hash matches
	contentHash := computeContentHash(req.Content)
	if req.Attestation.ContentHash != contentHash {
		return false, ""
	}

	// Check tenant matches
	if req.Attestation.TenantID != req.TenantID {
		return false, ""
	}

	// Check scan profile is adequate
	if !isProfileAdequate(scan.ScanProfile(req.Attestation.ScanProfile), req.ScanProfile) {
		return false, ""
	}

	// Check trust tier is adequate
	attestedTier := scan.TrustTierFromString(req.Attestation.TrustTier)
	if !isTierAdequate(attestedTier, req.TrustTier) {
		return false, ""
	}

	// Check expiry
	if time.Now().After(req.Attestation.ExpiresAt) {
		return false, ""
	}

	// Also check cache for a matching entry (if caching enabled)
	if a.config.EnableCaching {
		cached, err := a.cache.Get(ctx, contentHash)
		if err == nil && cached != nil {
			return true, fmt.Sprintf("valid attestation from %s (cached, profile=%s, tier=%s)",
				req.Attestation.ScannedBy, req.Attestation.ScanProfile, req.Attestation.TrustTier)
		}
	}

	return true, fmt.Sprintf("valid attestation from %s (profile=%s, tier=%s)",
		req.Attestation.ScannedBy, req.Attestation.ScanProfile, req.Attestation.TrustTier)
}

// computeContentHash returns the hex-encoded SHA-256 hash of content.
func computeContentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// isProfileAdequate checks if the attested scan profile covers the requested profile.
// "full" covers everything. "compliance" covers pii_only but not injection_only.
// A profile always covers itself.
func isProfileAdequate(attested, requested scan.ScanProfile) bool {
	if attested == requested {
		return true
	}

	// Full profile covers everything
	if attested == scan.ProfileFull {
		return true
	}

	// Compliance covers PII (compliance includes PII checks)
	if attested == scan.ProfileCompliance && requested == scan.ProfilePIIOnly {
		return true
	}

	return false
}

// isTierAdequate checks if the attested trust tier is adequate for the requested tier.
// A scan performed at a higher trust tier (more restrictive = higher numeric value)
// covers lower trust tiers.
// External (2) covers Partner (1) and Internal (0).
// Partner (1) covers Internal (0).
// Internal (0) only covers Internal (0).
func isTierAdequate(attested, requested scan.TrustTier) bool {
	// If the attested tier is >= the requested tier, the scan was at least
	// as thorough as what's being requested.
	return attested >= requested
}
