package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
	"github.com/google/uuid"
)

// --- Helper functions ---

func newTestAttestation() *types.Attestation {
	now := time.Now()
	return &types.Attestation{
		ID:             uuid.New().String(),
		ContentHash:    "abc123hash",
		ScanProfile:    string(scan.ProfileFull),
		RuleSetsUsed:   []string{"pii", "injection"},
		Clean:          true,
		ViolationCount: 0,
		MaxSeverity:    "",
		Redacted:       false,
		Tokenized:      false,
		TokenCount:     0,
		ScannedAt:      now,
		ScannedBy:      "test-service",
		TenantID:       "tenant-1",
		RequestID:      uuid.New().String(),
		TrustTier:      "external",
		ExpiresAt:      now.Add(5 * time.Minute),
	}
}

func testSigningKey() []byte {
	return []byte("test-signing-key-for-hmac-256-operations")
}

// --- Signer Tests ---

func TestHMACSigner_SignVerify(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())
	att := newTestAttestation()

	// Sign the attestation
	sig, err := signer.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}
	if sig == "" {
		t.Fatal("Sign() returned empty signature")
	}

	// Set signature on attestation and verify
	att.Signature = sig
	if err := signer.Verify(att); err != nil {
		t.Fatalf("Verify() returned error for valid signature: %v", err)
	}
}

func TestHMACSigner_SignDeterministic(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())
	att := newTestAttestation()

	sig1, err := signer.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	sig2, err := signer.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	if sig1 != sig2 {
		t.Fatalf("Sign() is not deterministic: %q != %q", sig1, sig2)
	}
}

func TestHMACSigner_SignNil(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())

	_, err := signer.Sign(nil)
	if err == nil {
		t.Fatal("Sign(nil) should return error")
	}
}

func TestHMACSigner_VerifyNil(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())

	err := signer.Verify(nil)
	if err == nil {
		t.Fatal("Verify(nil) should return error")
	}
}

func TestHMACSigner_TamperedAttestation(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())
	att := newTestAttestation()

	// Sign the attestation
	sig, err := signer.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}
	att.Signature = sig

	// Tamper with the attestation
	att.TenantID = "different-tenant"

	// Verify should fail
	if err := signer.Verify(att); err == nil {
		t.Fatal("Verify() should fail for tampered attestation")
	}
}

func TestHMACSigner_TamperedViolationCount(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())
	att := newTestAttestation()

	sig, err := signer.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}
	att.Signature = sig

	// Tamper with violation count
	att.ViolationCount = 5

	if err := signer.Verify(att); err == nil {
		t.Fatal("Verify() should fail when violation count is tampered")
	}
}

func TestHMACSigner_TamperedCleanFlag(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())
	att := newTestAttestation()

	sig, err := signer.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}
	att.Signature = sig

	// Tamper with clean flag
	att.Clean = false

	if err := signer.Verify(att); err == nil {
		t.Fatal("Verify() should fail when clean flag is tampered")
	}
}

func TestHMACSigner_WrongKey(t *testing.T) {
	signer1 := NewHMACSigner([]byte("key-one"))
	signer2 := NewHMACSigner([]byte("key-two"))

	att := newTestAttestation()

	// Sign with key 1
	sig, err := signer1.Sign(att)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}
	att.Signature = sig

	// Verify with key 2 should fail
	if err := signer2.Verify(att); err == nil {
		t.Fatal("Verify() should fail with different signing key")
	}
}

func TestHMACSigner_InvalidSignatureHex(t *testing.T) {
	signer := NewHMACSigner(testSigningKey())
	att := newTestAttestation()
	att.Signature = "not-valid-hex-!!!!"

	if err := signer.Verify(att); err == nil {
		t.Fatal("Verify() should fail with invalid hex signature")
	}
}

// --- Cache Tests ---

func TestMemoryCache_SetGet(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()
	att := newTestAttestation()
	att.ContentHash = "test-hash-1"

	// Set
	if err := cache.Set(ctx, att); err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	// Get
	got, err := cache.Get(ctx, "test-hash-1")
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if got == nil {
		t.Fatal("Get() returned nil for existing entry")
	}
	if got.ID != att.ID {
		t.Fatalf("Get() returned wrong attestation: got ID %q, want %q", got.ID, att.ID)
	}
}

func TestMemoryCache_GetNotFound(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()

	got, err := cache.Get(ctx, "nonexistent-hash")
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if got != nil {
		t.Fatal("Get() should return nil for nonexistent entry")
	}
}

func TestMemoryCache_SetNil(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()

	err := cache.Set(ctx, nil)
	if err == nil {
		t.Fatal("Set(nil) should return error")
	}
}

func TestMemoryCache_Expiry(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()

	att := newTestAttestation()
	att.ContentHash = "expiring-hash"
	att.ExpiresAt = time.Now().Add(-1 * time.Second) // Already expired

	if err := cache.Set(ctx, att); err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	// Should return nil because it's expired
	got, err := cache.Get(ctx, "expiring-hash")
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if got != nil {
		t.Fatal("Get() should return nil for expired entry")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()

	att := newTestAttestation()
	att.ContentHash = "delete-me-hash"

	if err := cache.Set(ctx, att); err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	// Verify it exists
	got, _ := cache.Get(ctx, "delete-me-hash")
	if got == nil {
		t.Fatal("Expected entry to exist before deletion")
	}

	// Delete
	if err := cache.Delete(ctx, "delete-me-hash"); err != nil {
		t.Fatalf("Delete() returned error: %v", err)
	}

	// Verify it's gone
	got, err := cache.Get(ctx, "delete-me-hash")
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if got != nil {
		t.Fatal("Get() should return nil after deletion")
	}
}

func TestMemoryCache_DeleteNonexistent(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()

	// Deleting a nonexistent key should not error
	if err := cache.Delete(ctx, "no-such-hash"); err != nil {
		t.Fatalf("Delete() returned error for nonexistent key: %v", err)
	}
}

func TestMemoryCache_Overwrite(t *testing.T) {
	cache := NewMemoryCache()
	ctx := context.Background()

	att1 := newTestAttestation()
	att1.ContentHash = "overwrite-hash"
	att1.TenantID = "tenant-a"

	att2 := newTestAttestation()
	att2.ContentHash = "overwrite-hash"
	att2.TenantID = "tenant-b"

	cache.Set(ctx, att1)
	cache.Set(ctx, att2)

	got, _ := cache.Get(ctx, "overwrite-hash")
	if got == nil {
		t.Fatal("Expected entry after overwrite")
	}
	if got.TenantID != "tenant-b" {
		t.Fatalf("Expected overwritten entry, got tenant %q", got.TenantID)
	}
}

// --- Attestor Tests ---

func TestAttestor_Create(t *testing.T) {
	key := testSigningKey()
	config := DefaultAttestorConfig()
	attestor := NewAttestor(key, config)
	ctx := context.Background()

	content := []byte("some test content to scan")
	scanResult := &scan.ScanResult{
		ID:          uuid.New().String(),
		RequestID:   uuid.New().String(),
		TenantID:    "tenant-1",
		ScanProfile: scan.ProfileFull,
		TrustTier:   scan.TierExternal,
		Findings:    []scan.Finding{},
		MaxSeverity: "",
	}

	att, err := attestor.Create(ctx, CreateRequest{
		Content:     content,
		ScanResult:  scanResult,
		TenantID:    "tenant-1",
		RequestID:   scanResult.RequestID,
		ServiceID:   "test-service",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		RuleSetsUsed: []string{"pii", "injection"},
	})
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	if att == nil {
		t.Fatal("Create() returned nil attestation")
	}
	if att.ID == "" {
		t.Fatal("Attestation ID should not be empty")
	}
	if att.Signature == "" {
		t.Fatal("Attestation Signature should not be empty")
	}
	if att.ContentHash == "" {
		t.Fatal("Attestation ContentHash should not be empty")
	}
	if !att.Clean {
		t.Fatal("Attestation should be clean (no findings)")
	}
	if att.ViolationCount != 0 {
		t.Fatalf("Expected 0 violations, got %d", att.ViolationCount)
	}
	if att.TenantID != "tenant-1" {
		t.Fatalf("Expected tenant-1, got %s", att.TenantID)
	}
	if att.ScanProfile != string(scan.ProfileFull) {
		t.Fatalf("Expected full profile, got %s", att.ScanProfile)
	}

	// Verify the content hash is correct
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])
	if att.ContentHash != expectedHash {
		t.Fatalf("ContentHash mismatch: got %q, want %q", att.ContentHash, expectedHash)
	}

	// ExpiresAt should be in the future
	if att.ExpiresAt.Before(time.Now()) {
		t.Fatal("ExpiresAt should be in the future")
	}
}

func TestAttestor_CreateWithFindings(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	scanResult := &scan.ScanResult{
		Findings: []scan.Finding{
			{ID: "f1", PatternID: "email", Severity: scan.SeverityMedium},
			{ID: "f2", PatternID: "ssn", Severity: scan.SeverityHigh},
		},
		MaxSeverity: scan.SeverityHigh,
	}

	att, err := attestor.Create(ctx, CreateRequest{
		Content:     []byte("content with PII"),
		ScanResult:  scanResult,
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	if att.Clean {
		t.Fatal("Attestation should not be clean (has findings)")
	}
	if att.ViolationCount != 2 {
		t.Fatalf("Expected 2 violations, got %d", att.ViolationCount)
	}
	if att.MaxSeverity != string(scan.SeverityHigh) {
		t.Fatalf("Expected max severity high, got %s", att.MaxSeverity)
	}
}

func TestAttestor_CreateWithCustomTTL(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	customTTL := 10 * time.Minute
	before := time.Now()

	att, err := attestor.Create(ctx, CreateRequest{
		Content:     []byte("test"),
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TTL:         customTTL,
	})
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	expectedExpiry := before.Add(customTTL)
	// Allow 1 second tolerance
	if att.ExpiresAt.Before(expectedExpiry.Add(-1 * time.Second)) {
		t.Fatalf("ExpiresAt too early: got %s, expected near %s", att.ExpiresAt, expectedExpiry)
	}
}

func TestAttestor_Verify(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	att, err := attestor.Create(ctx, CreateRequest{
		Content:     []byte("valid content"),
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	// Should verify successfully
	if err := attestor.Verify(ctx, att); err != nil {
		t.Fatalf("Verify() returned error for valid attestation: %v", err)
	}
}

func TestAttestor_VerifyNil(t *testing.T) {
	attestor := NewAttestor(testSigningKey(), nil)
	ctx := context.Background()

	if err := attestor.Verify(ctx, nil); err == nil {
		t.Fatal("Verify(nil) should return error")
	}
}

func TestAttestor_VerifyExpired(t *testing.T) {
	key := testSigningKey()
	signer := NewHMACSigner(key)
	cache := NewMemoryCache()
	attestor := NewAttestorWithComponents(signer, cache, nil)
	ctx := context.Background()

	// Create an attestation that's already expired
	att := newTestAttestation()
	att.ExpiresAt = time.Now().Add(-1 * time.Minute)
	sig, _ := signer.Sign(att)
	att.Signature = sig

	err := attestor.Verify(ctx, att)
	if err == nil {
		t.Fatal("Verify() should fail for expired attestation")
	}
}

func TestAttestor_VerifyTamperedSignature(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	att, err := attestor.Create(ctx, CreateRequest{
		Content:     []byte("content"),
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	// Tamper with signature
	att.Signature = "0000000000000000000000000000000000000000000000000000000000000000"

	if err := attestor.Verify(ctx, att); err == nil {
		t.Fatal("Verify() should fail for tampered signature")
	}
}

// --- CanSkip Tests ---

func TestAttestor_CanSkip_Valid(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	content := []byte("content to scan once")

	// Create attestation
	att, err := attestor.Create(ctx, CreateRequest{
		Content:      content,
		ScanResult:   &scan.ScanResult{},
		TenantID:     "tenant-1",
		TrustTier:    scan.TierExternal,
		ScanProfile:  scan.ProfileFull,
		RuleSetsUsed: []string{"pii"},
	})
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	// Check if we can skip
	canSkip, reason := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: att,
		Content:     content,
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	if !canSkip {
		t.Fatal("CanSkip() should return true for valid attestation")
	}
	if reason == "" {
		t.Fatal("CanSkip() should return a reason when skipping")
	}
}

func TestAttestor_CanSkip_NilAttestation(t *testing.T) {
	attestor := NewAttestor(testSigningKey(), nil)
	ctx := context.Background()

	canSkip, reason := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: nil,
		Content:     []byte("test"),
		TenantID:    "tenant-1",
	})

	if canSkip {
		t.Fatal("CanSkip() should return false for nil attestation")
	}
	if reason != "" {
		t.Fatalf("CanSkip() should return empty reason when not skipping, got %q", reason)
	}
}

func TestAttestor_CanSkip_WrongTenant(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	content := []byte("content")
	att, _ := attestor.Create(ctx, CreateRequest{
		Content:     content,
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: att,
		Content:     content,
		TenantID:    "tenant-2", // Different tenant
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	if canSkip {
		t.Fatal("CanSkip() should return false for wrong tenant")
	}
}

func TestAttestor_CanSkip_WrongProfile(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	content := []byte("content")
	att, _ := attestor.Create(ctx, CreateRequest{
		Content:     content,
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfilePIIOnly, // Only PII
	})

	canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: att,
		Content:     content,
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileInjectionOnly, // Needs injection
	})

	if canSkip {
		t.Fatal("CanSkip() should return false when pii_only doesn't cover injection_only")
	}
}

func TestAttestor_CanSkip_FullCoversAll(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	content := []byte("content")
	att, _ := attestor.Create(ctx, CreateRequest{
		Content:     content,
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	profiles := []scan.ScanProfile{
		scan.ProfilePIIOnly,
		scan.ProfileInjectionOnly,
		scan.ProfileCompliance,
		scan.ProfileFull,
	}

	for _, profile := range profiles {
		canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
			Attestation: att,
			Content:     content,
			TenantID:    "tenant-1",
			TrustTier:   scan.TierExternal,
			ScanProfile: profile,
		})
		if !canSkip {
			t.Fatalf("CanSkip() should return true: full profile should cover %s", profile)
		}
	}
}

func TestAttestor_CanSkip_Expired(t *testing.T) {
	key := testSigningKey()
	signer := NewHMACSigner(key)
	cache := NewMemoryCache()
	attestor := NewAttestorWithComponents(signer, cache, nil)
	ctx := context.Background()

	content := []byte("expired content")
	h := sha256.Sum256(content)
	contentHash := hex.EncodeToString(h[:])

	att := &types.Attestation{
		ID:             uuid.New().String(),
		ContentHash:    contentHash,
		ScanProfile:    string(scan.ProfileFull),
		Clean:          true,
		ViolationCount: 0,
		ScannedAt:      time.Now().Add(-10 * time.Minute),
		ScannedBy:      "test-service",
		TenantID:       "tenant-1",
		RequestID:      uuid.New().String(),
		TrustTier:      "external",
		ExpiresAt:      time.Now().Add(-1 * time.Minute), // Expired
	}

	sig, _ := signer.Sign(att)
	att.Signature = sig

	canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: att,
		Content:     content,
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	if canSkip {
		t.Fatal("CanSkip() should return false for expired attestation")
	}
}

func TestAttestor_CanSkip_DifferentContent(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	att, _ := attestor.Create(ctx, CreateRequest{
		Content:     []byte("original content"),
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: att,
		Content:     []byte("different content"), // Different
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	if canSkip {
		t.Fatal("CanSkip() should return false when content has changed")
	}
}

func TestAttestor_CanSkip_TrustTierAdequacy(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	tests := []struct {
		name           string
		attestedTier   scan.TrustTier
		requestedTier  scan.TrustTier
		expectCanSkip  bool
	}{
		{
			name:          "external covers external",
			attestedTier:  scan.TierExternal,
			requestedTier: scan.TierExternal,
			expectCanSkip: true,
		},
		{
			name:          "external covers partner",
			attestedTier:  scan.TierExternal,
			requestedTier: scan.TierPartner,
			expectCanSkip: true,
		},
		{
			name:          "external covers internal",
			attestedTier:  scan.TierExternal,
			requestedTier: scan.TierInternal,
			expectCanSkip: true,
		},
		{
			name:          "partner covers partner",
			attestedTier:  scan.TierPartner,
			requestedTier: scan.TierPartner,
			expectCanSkip: true,
		},
		{
			name:          "partner covers internal",
			attestedTier:  scan.TierPartner,
			requestedTier: scan.TierInternal,
			expectCanSkip: true,
		},
		{
			name:          "internal covers internal",
			attestedTier:  scan.TierInternal,
			requestedTier: scan.TierInternal,
			expectCanSkip: true,
		},
		{
			name:          "internal does not cover partner",
			attestedTier:  scan.TierInternal,
			requestedTier: scan.TierPartner,
			expectCanSkip: false,
		},
		{
			name:          "internal does not cover external",
			attestedTier:  scan.TierInternal,
			requestedTier: scan.TierExternal,
			expectCanSkip: false,
		},
		{
			name:          "partner does not cover external",
			attestedTier:  scan.TierPartner,
			requestedTier: scan.TierExternal,
			expectCanSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := []byte("trust tier test content")
			att, err := attestor.Create(ctx, CreateRequest{
				Content:     content,
				ScanResult:  &scan.ScanResult{},
				TenantID:    "tenant-1",
				TrustTier:   tt.attestedTier,
				ScanProfile: scan.ProfileFull,
			})
			if err != nil {
				t.Fatalf("Create() returned error: %v", err)
			}

			canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
				Attestation: att,
				Content:     content,
				TenantID:    "tenant-1",
				TrustTier:   tt.requestedTier,
				ScanProfile: scan.ProfileFull,
			})

			if canSkip != tt.expectCanSkip {
				t.Fatalf("CanSkip() = %v, want %v", canSkip, tt.expectCanSkip)
			}
		})
	}
}

func TestAttestor_CanSkip_InvalidSignature(t *testing.T) {
	key := testSigningKey()
	attestor := NewAttestor(key, nil)
	ctx := context.Background()

	content := []byte("content")
	att, _ := attestor.Create(ctx, CreateRequest{
		Content:     content,
		ScanResult:  &scan.ScanResult{},
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	// Corrupt signature
	att.Signature = "0000000000000000000000000000000000000000000000000000000000000000"

	canSkip, _ := attestor.CanSkip(ctx, SkipCheckRequest{
		Attestation: att,
		Content:     content,
		TenantID:    "tenant-1",
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
	})

	if canSkip {
		t.Fatal("CanSkip() should return false for invalid signature")
	}
}

// --- Profile Adequacy Tests ---

func TestIsProfileAdequate(t *testing.T) {
	tests := []struct {
		name     string
		attested scan.ScanProfile
		requested scan.ScanProfile
		expected bool
	}{
		{"same profile", scan.ProfileFull, scan.ProfileFull, true},
		{"full covers pii_only", scan.ProfileFull, scan.ProfilePIIOnly, true},
		{"full covers injection_only", scan.ProfileFull, scan.ProfileInjectionOnly, true},
		{"full covers compliance", scan.ProfileFull, scan.ProfileCompliance, true},
		{"compliance covers pii_only", scan.ProfileCompliance, scan.ProfilePIIOnly, true},
		{"compliance does not cover injection_only", scan.ProfileCompliance, scan.ProfileInjectionOnly, false},
		{"pii_only does not cover injection_only", scan.ProfilePIIOnly, scan.ProfileInjectionOnly, false},
		{"injection_only does not cover pii_only", scan.ProfileInjectionOnly, scan.ProfilePIIOnly, false},
		{"pii_only does not cover full", scan.ProfilePIIOnly, scan.ProfileFull, false},
		{"injection_only does not cover full", scan.ProfileInjectionOnly, scan.ProfileFull, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProfileAdequate(tt.attested, tt.requested)
			if got != tt.expected {
				t.Fatalf("isProfileAdequate(%s, %s) = %v, want %v",
					tt.attested, tt.requested, got, tt.expected)
			}
		})
	}
}

// --- Encoding Tests ---

func TestEncoding_Roundtrip(t *testing.T) {
	original := newTestAttestation()
	original.Signature = "abc123deadbeef"
	original.RuleSetsUsed = []string{"pii", "injection", "compliance"}

	encoded, err := EncodeAttestation(original)
	if err != nil {
		t.Fatalf("EncodeAttestation() returned error: %v", err)
	}
	if encoded == "" {
		t.Fatal("EncodeAttestation() returned empty string")
	}

	decoded, err := DecodeAttestation(encoded)
	if err != nil {
		t.Fatalf("DecodeAttestation() returned error: %v", err)
	}

	// Verify all fields match
	if decoded.ID != original.ID {
		t.Fatalf("ID mismatch: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.ContentHash != original.ContentHash {
		t.Fatalf("ContentHash mismatch: got %q, want %q", decoded.ContentHash, original.ContentHash)
	}
	if decoded.ScanProfile != original.ScanProfile {
		t.Fatalf("ScanProfile mismatch: got %q, want %q", decoded.ScanProfile, original.ScanProfile)
	}
	if decoded.Clean != original.Clean {
		t.Fatalf("Clean mismatch: got %v, want %v", decoded.Clean, original.Clean)
	}
	if decoded.ViolationCount != original.ViolationCount {
		t.Fatalf("ViolationCount mismatch: got %d, want %d", decoded.ViolationCount, original.ViolationCount)
	}
	if decoded.TenantID != original.TenantID {
		t.Fatalf("TenantID mismatch: got %q, want %q", decoded.TenantID, original.TenantID)
	}
	if decoded.Signature != original.Signature {
		t.Fatalf("Signature mismatch: got %q, want %q", decoded.Signature, original.Signature)
	}
	if decoded.TrustTier != original.TrustTier {
		t.Fatalf("TrustTier mismatch: got %q, want %q", decoded.TrustTier, original.TrustTier)
	}
	if len(decoded.RuleSetsUsed) != len(original.RuleSetsUsed) {
		t.Fatalf("RuleSetsUsed length mismatch: got %d, want %d",
			len(decoded.RuleSetsUsed), len(original.RuleSetsUsed))
	}
	for i, rs := range decoded.RuleSetsUsed {
		if rs != original.RuleSetsUsed[i] {
			t.Fatalf("RuleSetsUsed[%d] mismatch: got %q, want %q", i, rs, original.RuleSetsUsed[i])
		}
	}
}

func TestEncoding_NilAttestation(t *testing.T) {
	_, err := EncodeAttestation(nil)
	if err == nil {
		t.Fatal("EncodeAttestation(nil) should return error")
	}
}

func TestEncoding_EmptyString(t *testing.T) {
	_, err := DecodeAttestation("")
	if err == nil {
		t.Fatal("DecodeAttestation(\"\") should return error")
	}
}

func TestEncoding_InvalidBase64(t *testing.T) {
	_, err := DecodeAttestation("not-valid-base64!!!")
	if err == nil {
		t.Fatal("DecodeAttestation() should fail for invalid base64")
	}
}

func TestEncoding_InvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := DecodeAttestation(encoded)
	if err == nil {
		t.Fatal("DecodeAttestation() should fail for invalid JSON")
	}
}
