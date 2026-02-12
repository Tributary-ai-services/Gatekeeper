package middleware

import (
	"context"
	"strings"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/attest"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/pipeline"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

// grpcContextKey is the context key type for gRPC middleware results.
type grpcContextKey string

const grpcMiddlewareResultKey grpcContextKey = "gatekeeper_grpc_result"

// GetGRPCMiddlewareResult retrieves the scan result from a gRPC context.
// Returns nil if no result is present.
func GetGRPCMiddlewareResult(ctx context.Context) *MiddlewareResult {
	val := ctx.Value(grpcMiddlewareResultKey)
	if val == nil {
		return nil
	}
	result, ok := val.(*MiddlewareResult)
	if !ok {
		return nil
	}
	return result
}

// UnaryServerInterceptor returns a gRPC unary interceptor that scans
// request payloads using the given processor. It reads the serialized
// request bytes from the gRPC info, scans them, and either blocks or
// passes through.
func UnaryServerInterceptor(processor pipeline.Processor, config *GRPCConfig) grpc.UnaryServerInterceptor {
	if config == nil {
		config = DefaultGRPCConfig()
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if the method is exempt
		if isExemptGRPCMethod(info.FullMethod, config.ExemptMethods) {
			return handler(ctx, req)
		}

		// Extract metadata
		md, _ := metadata.FromIncomingContext(ctx)
		tenantID := getMetadataValue(md, config.TenantIDMetadata)
		userID := getMetadataValue(md, config.UserIDMetadata)
		requestID := getMetadataValue(md, config.RequestIDMetadata)

		// Serialize the request for scanning
		content := serializeRequest(req)
		if len(content) == 0 {
			return handler(ctx, req)
		}

		// Build process request
		processReq := pipeline.ProcessRequest{
			Content:     content,
			ContentType: "grpc_request",
			TrustTier:   config.TrustTier,
			ScanProfile: config.ScanProfile,
			TenantID:    tenantID,
			UserID:      userID,
			RequestID:   requestID,
			Source:      "grpc_request",
		}

		// Extract existing attestation from metadata
		if attestVal := getMetadataValue(md, strings.ToLower(attest.HeaderAttestation)); attestVal != "" {
			if a, err := attest.DecodeAttestation(attestVal); err == nil {
				processReq.Attestation = a
			}
		}

		// Process content
		result, err := processor.Process(ctx, processReq)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "content scanning failed: %v", err)
		}

		// Build middleware result
		mwResult := &MiddlewareResult{
			ScanResult: result.ScanResult,
		}
		if result.Attestation != nil {
			mwResult.Attestation = result.Attestation
		}

		// Check if content should be blocked
		if result.ActionResult != nil && result.ActionResult.Blocked {
			mwResult.Blocked = true
			mwResult.BlockReason = result.ActionResult.BlockReason
		}

		if mwResult.Blocked && config.BlockOnViolation {
			return nil, status.Errorf(codes.PermissionDenied, "content blocked: %s", mwResult.BlockReason)
		}

		// Inject attestation into outgoing metadata
		if config.InjectAttestation && mwResult.Attestation != nil {
			if encoded, encErr := attest.EncodeAttestation(mwResult.Attestation); encErr == nil {
				header := metadata.Pairs(strings.ToLower(attest.HeaderAttestation), encoded)
				if sendErr := grpc.SetHeader(ctx, header); sendErr != nil {
					// Non-fatal: attestation header injection failed
					_ = sendErr
				}
			}
		}

		// Store result in context for downstream handlers
		ctx = context.WithValue(ctx, grpcMiddlewareResultKey, mwResult)

		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor that scans
// the initial request metadata. For streaming RPCs, only the connection
// metadata is scanned (not individual stream messages).
func StreamServerInterceptor(processor pipeline.Processor, config *GRPCConfig) grpc.StreamServerInterceptor {
	if config == nil {
		config = DefaultGRPCConfig()
	}

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if the method is exempt
		if isExemptGRPCMethod(info.FullMethod, config.ExemptMethods) {
			return handler(srv, ss)
		}

		// For streaming, we scan based on metadata only (no request body to read upfront)
		ctx := ss.Context()
		md, _ := metadata.FromIncomingContext(ctx)
		tenantID := getMetadataValue(md, config.TenantIDMetadata)

		// If there's an attestation in metadata, verify it
		if attestVal := getMetadataValue(md, strings.ToLower(attest.HeaderAttestation)); attestVal != "" {
			if a, err := attest.DecodeAttestation(attestVal); err == nil {
				if _, verifyErr := processor.Verify(*a); verifyErr != nil {
					if config.BlockOnViolation {
						return status.Errorf(codes.PermissionDenied, "invalid attestation from tenant %s: %v", tenantID, verifyErr)
					}
				}
			}
		}

		return handler(srv, ss)
	}
}

// isExemptGRPCMethod checks if a gRPC method is in the exempt list.
func isExemptGRPCMethod(method string, exemptMethods []string) bool {
	for _, exempt := range exemptMethods {
		if method == exempt {
			return true
		}
	}
	return false
}

// getMetadataValue extracts the first value for a key from gRPC metadata.
func getMetadataValue(md metadata.MD, key string) string {
	if md == nil {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// serializeRequest attempts to serialize a gRPC request to bytes for scanning.
// It uses the encoding.BinaryMarshaler interface if available, otherwise
// falls back to a simple string conversion for basic types.
func serializeRequest(req interface{}) []byte {
	if req == nil {
		return nil
	}

	// Try proto.Marshal via the encoding.BinaryMarshaler interface
	type binaryMarshaler interface {
		Marshal() ([]byte, error)
	}
	if m, ok := req.(binaryMarshaler); ok {
		data, err := m.Marshal()
		if err == nil {
			return data
		}
	}

	// Try proto.Message's MarshalVT or similar
	type vtMarshaler interface {
		MarshalVT() ([]byte, error)
	}
	if m, ok := req.(vtMarshaler); ok {
		data, err := m.MarshalVT()
		if err == nil {
			return data
		}
	}

	// Fallback: try fmt.Stringer
	type stringer interface {
		String() string
	}
	if s, ok := req.(stringer); ok {
		str := s.String()
		if len(str) > 0 {
			return []byte(str)
		}
	}

	return nil
}
