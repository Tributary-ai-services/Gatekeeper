// Package middleware provides HTTP and gRPC middleware for integrating Gatekeeper.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/attest"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/pipeline"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
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
	BlockOnViolation  bool `json:"block_on_violation"`
	InjectAttestation bool `json:"inject_attestation"`
	RedactResponse    bool `json:"redact_response"`

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

// MiddlewareResult contains the result of middleware processing
type MiddlewareResult struct {
	Blocked     bool
	BlockReason string
	Attestation *types.Attestation
	ScanResult  *scan.ScanResult
}

// contextKey type for request context
type contextKey string

const middlewareResultKey contextKey = "gatekeeper_result"

// GetMiddlewareResult retrieves the scan result from request context.
// Returns nil if no middleware result is present.
func GetMiddlewareResult(r *http.Request) *MiddlewareResult {
	val := r.Context().Value(middlewareResultKey)
	if val == nil {
		return nil
	}
	result, ok := val.(*MiddlewareResult)
	if !ok {
		return nil
	}
	return result
}

// ScanMiddleware returns an HTTP middleware that scans request bodies using the processor.
// It works as a stdlib net/http handler wrapper, compatible with any Go HTTP framework.
func ScanMiddleware(processor pipeline.Processor, config *HTTPConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultHTTPConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the path is exempt
			if isExemptPath(r.URL.Path, config.ExemptPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the method is exempt
			if isExemptMethod(r.Method, config.ExemptMethods) {
				next.ServeHTTP(w, r)
				return
			}

			// Read the request body
			var body []byte
			if r.Body != nil {
				var err error
				body, err = io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, `{"error":"failed to read request body"}`, http.StatusInternalServerError)
					return
				}
				r.Body.Close()
			}

			// Build the process request
			processReq := pipeline.ProcessRequest{
				Content:     body,
				ContentType: "document",
				TrustTier:   config.TrustTier,
				ScanProfile: config.ScanProfile,
				TenantID:    r.Header.Get(config.TenantIDHeader),
				UserID:      r.Header.Get(config.UserIDHeader),
				RequestID:   r.Header.Get(config.RequestIDHeader),
				Source:      "http_request",
			}

			// Extract existing attestation from header
			if attestHeader := r.Header.Get(attest.HeaderAttestation); attestHeader != "" {
				if a, err := attest.DecodeAttestation(attestHeader); err == nil {
					processReq.Attestation = a
				}
			}

			// Process the content
			result, err := processor.Process(r.Context(), processReq)
			if err != nil {
				http.Error(w, `{"error":"content scanning failed"}`, http.StatusInternalServerError)
				return
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
				// Store result in context even for blocked requests
				ctx := context.WithValue(r.Context(), middlewareResultKey, mwResult)
				r = r.WithContext(ctx)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				resp := map[string]string{
					"error":  "content blocked",
					"reason": mwResult.BlockReason,
				}
				if processReq.RequestID != "" {
					resp["request_id"] = processReq.RequestID
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			// Inject attestation header if enabled
			if config.InjectAttestation && mwResult.Attestation != nil {
				if encoded, err := attest.EncodeAttestation(mwResult.Attestation); err == nil {
					r.Header.Set(attest.HeaderAttestation, encoded)
				}
			}

			// Restore the body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Store result in request context for downstream handlers
			ctx := context.WithValue(r.Context(), middlewareResultKey, mwResult)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// isExemptPath checks if a path is in the exempt list
func isExemptPath(path string, exemptPaths []string) bool {
	for _, exempt := range exemptPaths {
		if strings.EqualFold(path, exempt) {
			return true
		}
	}
	return false
}

// isExemptMethod checks if a method is in the exempt list
func isExemptMethod(method string, exemptMethods []string) bool {
	for _, exempt := range exemptMethods {
		if strings.EqualFold(method, exempt) {
			return true
		}
	}
	return false
}
