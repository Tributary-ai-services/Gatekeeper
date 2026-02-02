package middleware

import (
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// GRPCConfig configures the gRPC scanning interceptor
type GRPCConfig struct {
	// Scanning settings
	ScanProfile scan.ScanProfile `json:"scan_profile"`
	TrustTier   scan.TrustTier   `json:"trust_tier"`

	// Metadata extraction
	TenantIDMetadata  string `json:"tenant_id_metadata"`
	UserIDMetadata    string `json:"user_id_metadata"`
	RequestIDMetadata string `json:"request_id_metadata"`

	// Behavior
	BlockOnViolation  bool `json:"block_on_violation"`
	InjectAttestation bool `json:"inject_attestation"`

	// Exemptions
	ExemptMethods []string `json:"exempt_methods"`
}

// DefaultGRPCConfig returns default gRPC middleware configuration
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		ScanProfile:       scan.ProfileFull,
		TrustTier:         scan.TierExternal,
		TenantIDMetadata:  "x-tenant-id",
		UserIDMetadata:    "x-user-id",
		RequestIDMetadata: "x-request-id",
		BlockOnViolation:  true,
		InjectAttestation: true,
		ExemptMethods: []string{
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		},
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor for content scanning
// TODO: Implement after grpc dependency is resolved
// func UnaryServerInterceptor(processor pipeline.Processor, config *GRPCConfig) grpc.UnaryServerInterceptor

// StreamServerInterceptor returns a gRPC stream interceptor for content scanning
// TODO: Implement after grpc dependency is resolved
// func StreamServerInterceptor(processor pipeline.Processor, config *GRPCConfig) grpc.StreamServerInterceptor
