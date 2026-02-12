package attest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// hmacSigner implements the Signer interface using HMAC-SHA256.
type hmacSigner struct {
	key []byte
}

// NewHMACSigner creates a new HMAC-SHA256 signer with the given key.
func NewHMACSigner(key []byte) Signer {
	return &hmacSigner{key: key}
}

// Sign creates an HMAC-SHA256 signature for the attestation.
// It builds a canonical string from the attestation fields and computes the HMAC.
func (s *hmacSigner) Sign(attestation *types.Attestation) (string, error) {
	if attestation == nil {
		return "", fmt.Errorf("attestation is nil")
	}

	canonical := buildCanonicalString(attestation)

	mac := hmac.New(sha256.New, s.key)
	_, err := mac.Write([]byte(canonical))
	if err != nil {
		return "", fmt.Errorf("failed to compute HMAC: %w", err)
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify verifies the attestation signature using constant-time comparison.
func (s *hmacSigner) Verify(attestation *types.Attestation) error {
	if attestation == nil {
		return fmt.Errorf("attestation is nil")
	}

	expected, err := s.Sign(attestation)
	if err != nil {
		return fmt.Errorf("failed to compute expected signature: %w", err)
	}

	// Decode both signatures to bytes for constant-time comparison
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("failed to decode expected signature: %w", err)
	}

	actualBytes, err := hex.DecodeString(attestation.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode attestation signature: %w", err)
	}

	if !hmac.Equal(expectedBytes, actualBytes) {
		return fmt.Errorf("attestation signature verification failed")
	}

	return nil
}

// buildCanonicalString creates a deterministic string from attestation fields
// for HMAC computation. Format:
// id|content_hash|scan_profile|tenant_id|scanned_at_unix|expires_at_unix|clean|violation_count
func buildCanonicalString(a *types.Attestation) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d|%t|%d",
		a.ID,
		a.ContentHash,
		a.ScanProfile,
		a.TenantID,
		a.ScannedAt.Unix(),
		a.ExpiresAt.Unix(),
		a.Clean,
		a.ViolationCount,
	)
}
