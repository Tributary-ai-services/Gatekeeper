package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/attest"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/pipeline"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// mockProcessor implements pipeline.Processor for testing
type mockProcessor struct {
	processFunc  func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error)
	scanOnlyFunc func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error)
	verifyFunc   func(attestation types.Attestation) (bool, error)
}

func (m *mockProcessor) Process(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
	if m.processFunc != nil {
		return m.processFunc(ctx, req)
	}
	return &pipeline.ProcessResult{}, nil
}

func (m *mockProcessor) ScanOnly(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
	if m.scanOnlyFunc != nil {
		return m.scanOnlyFunc(ctx, content, config)
	}
	return &scan.ScanResult{}, nil
}

func (m *mockProcessor) Verify(attestation types.Attestation) (bool, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(attestation)
	}
	return true, nil
}

func (m *mockProcessor) Close() error {
	return nil
}

// cleanProcessor returns a mock that always reports clean results
func cleanProcessor() *mockProcessor {
	return &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			return &pipeline.ProcessResult{
				ScanResult: &scan.ScanResult{
					IsCompliant:   true,
					TotalFindings: 0,
				},
				Attestation: &types.Attestation{
					ID:    "test-attestation-id",
					Clean: true,
				},
			}, nil
		},
	}
}

// blockingProcessor returns a mock that always blocks content
func blockingProcessor(reason string) *mockProcessor {
	return &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			return &pipeline.ProcessResult{
				ScanResult: &scan.ScanResult{
					IsCompliant:   false,
					TotalFindings: 1,
					Findings: []scan.Finding{
						{
							PatternID:   "ssn",
							PatternType: scan.PatternTypePII,
							Severity:    scan.SeverityCritical,
						},
					},
				},
				ActionResult: &types.ActionResult{
					Blocked:     true,
					BlockReason: reason,
				},
			}, nil
		},
	}
}

// successHandler is a simple handler that returns 200 OK
func successHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
}

func TestScanMiddleware_ExemptPath(t *testing.T) {
	// The processor should NOT be called for exempt paths
	proc := &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			t.Error("processor should not be called for exempt paths")
			return &pipeline.ProcessResult{}, nil
		},
	}

	config := DefaultHTTPConfig()
	// /health is already in the default exempt paths

	handler := ScanMiddleware(proc, config)(successHandler())

	req := httptest.NewRequest(http.MethodPost, "/health", bytes.NewReader([]byte(`test body`)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for exempt path, got %d", rr.Code)
	}
}

func TestScanMiddleware_ExemptMethod(t *testing.T) {
	// The processor should NOT be called for exempt methods
	proc := &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			t.Error("processor should not be called for exempt methods")
			return &pipeline.ProcessResult{}, nil
		},
	}

	config := DefaultHTTPConfig()
	// OPTIONS is already in the default exempt methods

	handler := ScanMiddleware(proc, config)(successHandler())

	req := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for exempt method, got %d", rr.Code)
	}
}

func TestScanMiddleware_CleanContent(t *testing.T) {
	proc := cleanProcessor()
	config := DefaultHTTPConfig()

	handler := ScanMiddleware(proc, config)(successHandler())

	body := []byte(`{"message": "hello world"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for clean content, got %d", rr.Code)
	}

	// Verify the response body came from the success handler
	respBody := rr.Body.String()
	if respBody != `{"status":"ok"}` {
		t.Errorf("unexpected response body: %s", respBody)
	}
}

func TestScanMiddleware_BlockedContent(t *testing.T) {
	reason := "PII detected: SSN found in content"
	proc := blockingProcessor(reason)
	config := DefaultHTTPConfig()

	handler := ScanMiddleware(proc, config)(successHandler())

	body := []byte(`{"ssn": "123-45-6789"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	req.Header.Set("X-Request-ID", "req-123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for blocked content, got %d", rr.Code)
	}

	// Parse the response body
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["error"] != "content blocked" {
		t.Errorf("expected error 'content blocked', got %q", resp["error"])
	}
	if resp["reason"] != reason {
		t.Errorf("expected reason %q, got %q", reason, resp["reason"])
	}
	if resp["request_id"] != "req-123" {
		t.Errorf("expected request_id 'req-123', got %q", resp["request_id"])
	}
}

func TestScanMiddleware_AttestationInjection(t *testing.T) {
	proc := cleanProcessor()
	config := DefaultHTTPConfig()
	config.InjectAttestation = true

	// Track the attestation header that's injected into the request
	var injectedHeader string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injectedHeader = r.Header.Get(attest.HeaderAttestation)
		w.WriteHeader(http.StatusOK)
	})

	handler := ScanMiddleware(proc, config)(inner)

	body := []byte(`{"message": "clean content"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if injectedHeader == "" {
		t.Error("expected attestation header to be injected, but it was empty")
	}

	// Verify the injected header can be decoded
	decoded, err := attest.DecodeAttestation(injectedHeader)
	if err != nil {
		t.Fatalf("failed to decode injected attestation: %v", err)
	}
	if decoded.ID != "test-attestation-id" {
		t.Errorf("expected attestation ID 'test-attestation-id', got %q", decoded.ID)
	}
}

func TestScanMiddleware_HeaderExtraction(t *testing.T) {
	var capturedReq pipeline.ProcessRequest

	proc := &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			capturedReq = req
			return &pipeline.ProcessResult{
				ScanResult: &scan.ScanResult{
					IsCompliant: true,
				},
			}, nil
		},
	}

	config := DefaultHTTPConfig()
	config.TenantIDHeader = "X-Tenant-ID"
	config.UserIDHeader = "X-User-ID"
	config.RequestIDHeader = "X-Request-ID"

	handler := ScanMiddleware(proc, config)(successHandler())

	body := []byte(`test body`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-abc")
	req.Header.Set("X-User-ID", "user-xyz")
	req.Header.Set("X-Request-ID", "req-456")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if capturedReq.TenantID != "tenant-abc" {
		t.Errorf("expected TenantID 'tenant-abc', got %q", capturedReq.TenantID)
	}
	if capturedReq.UserID != "user-xyz" {
		t.Errorf("expected UserID 'user-xyz', got %q", capturedReq.UserID)
	}
	if capturedReq.RequestID != "req-456" {
		t.Errorf("expected RequestID 'req-456', got %q", capturedReq.RequestID)
	}
	if capturedReq.Source != "http_request" {
		t.Errorf("expected Source 'http_request', got %q", capturedReq.Source)
	}
	if capturedReq.ContentType != "document" {
		t.Errorf("expected ContentType 'document', got %q", capturedReq.ContentType)
	}
	if string(capturedReq.Content) != "test body" {
		t.Errorf("expected Content 'test body', got %q", string(capturedReq.Content))
	}
}

func TestScanMiddleware_EmptyBody(t *testing.T) {
	proc := cleanProcessor()
	config := DefaultHTTPConfig()

	handler := ScanMiddleware(proc, config)(successHandler())

	// Request with nil body
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for empty body, got %d", rr.Code)
	}
}

func TestScanMiddleware_ContextResult(t *testing.T) {
	proc := cleanProcessor()
	config := DefaultHTTPConfig()

	var capturedResult *MiddlewareResult
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedResult = GetMiddlewareResult(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := ScanMiddleware(proc, config)(inner)

	body := []byte(`{"message": "test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if capturedResult == nil {
		t.Fatal("expected MiddlewareResult in context, got nil")
	}
	if capturedResult.Blocked {
		t.Error("expected Blocked to be false for clean content")
	}
	if capturedResult.ScanResult == nil {
		t.Error("expected ScanResult to be non-nil")
	}
	if capturedResult.Attestation == nil {
		t.Error("expected Attestation to be non-nil")
	}
}

func TestGetMiddlewareResult(t *testing.T) {
	t.Run("nil when not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		result := GetMiddlewareResult(req)
		if result != nil {
			t.Errorf("expected nil result when not set, got %+v", result)
		}
	})

	t.Run("returns result when set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		expected := &MiddlewareResult{
			Blocked:     true,
			BlockReason: "test reason",
		}
		ctx := context.WithValue(req.Context(), middlewareResultKey, expected)
		req = req.WithContext(ctx)

		result := GetMiddlewareResult(req)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Blocked != expected.Blocked {
			t.Errorf("expected Blocked=%v, got %v", expected.Blocked, result.Blocked)
		}
		if result.BlockReason != expected.BlockReason {
			t.Errorf("expected BlockReason=%q, got %q", expected.BlockReason, result.BlockReason)
		}
	})

	t.Run("nil when wrong type in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), middlewareResultKey, "not a MiddlewareResult")
		req = req.WithContext(ctx)

		result := GetMiddlewareResult(req)
		if result != nil {
			t.Errorf("expected nil for wrong type, got %+v", result)
		}
	})
}

func TestScanMiddleware_NilConfig(t *testing.T) {
	proc := cleanProcessor()

	// Passing nil config should use defaults
	handler := ScanMiddleware(proc, nil)(successHandler())

	// /health should be exempt with default config
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for exempt path with nil config, got %d", rr.Code)
	}
}

func TestScanMiddleware_ProcessorError(t *testing.T) {
	proc := &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			return nil, fmt.Errorf("processor internal error")
		},
	}
	config := DefaultHTTPConfig()

	handler := ScanMiddleware(proc, config)(successHandler())

	body := []byte(`test`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 for processor error, got %d", rr.Code)
	}
}

func TestScanMiddleware_BodyPreserved(t *testing.T) {
	proc := cleanProcessor()
	config := DefaultHTTPConfig()

	originalBody := `{"key": "value", "data": "important"}`
	var downstreamBody string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body in downstream handler: %v", err)
		}
		downstreamBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	})

	handler := ScanMiddleware(proc, config)(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader([]byte(originalBody)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if downstreamBody != originalBody {
		t.Errorf("body not preserved for downstream handler.\nexpected: %s\ngot: %s", originalBody, downstreamBody)
	}
}

func TestScanMiddleware_BlockOnViolationDisabled(t *testing.T) {
	// Even with violations, if BlockOnViolation is false, should pass through
	reason := "PII detected"
	proc := blockingProcessor(reason)
	config := DefaultHTTPConfig()
	config.BlockOnViolation = false

	var capturedResult *MiddlewareResult
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedResult = GetMiddlewareResult(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := ScanMiddleware(proc, config)(inner)

	body := []byte(`{"ssn": "123-45-6789"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 when BlockOnViolation is false, got %d", rr.Code)
	}

	if capturedResult == nil {
		t.Fatal("expected MiddlewareResult in context")
	}
	if !capturedResult.Blocked {
		t.Error("expected Blocked to be true in result even when not blocking")
	}
	if capturedResult.BlockReason != reason {
		t.Errorf("expected BlockReason %q, got %q", reason, capturedResult.BlockReason)
	}
}

func TestScanMiddleware_ExistingAttestation(t *testing.T) {
	var capturedReq pipeline.ProcessRequest

	proc := &mockProcessor{
		processFunc: func(ctx context.Context, req pipeline.ProcessRequest) (*pipeline.ProcessResult, error) {
			capturedReq = req
			return &pipeline.ProcessResult{
				ScanResult: &scan.ScanResult{
					IsCompliant: true,
				},
			}, nil
		},
	}

	config := DefaultHTTPConfig()
	handler := ScanMiddleware(proc, config)(successHandler())

	// Create an attestation and encode it
	original := &types.Attestation{
		ID:    "upstream-attest-id",
		Clean: true,
	}
	encoded, err := attest.EncodeAttestation(original)
	if err != nil {
		t.Fatalf("failed to encode attestation: %v", err)
	}

	body := []byte(`test`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(body))
	req.Header.Set(attest.HeaderAttestation, encoded)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if capturedReq.Attestation == nil {
		t.Fatal("expected existing attestation to be passed to processor")
	}
	if capturedReq.Attestation.ID != "upstream-attest-id" {
		t.Errorf("expected attestation ID 'upstream-attest-id', got %q", capturedReq.Attestation.ID)
	}
}

func TestIsExemptPath(t *testing.T) {
	exemptPaths := []string{"/health", "/metrics", "/ready"}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/ready", true},
		{"/Health", true},  // case-insensitive
		{"/api/data", false},
		{"/healthz", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			result := isExemptPath(tc.path, exemptPaths)
			if result != tc.expected {
				t.Errorf("isExemptPath(%q) = %v, want %v", tc.path, result, tc.expected)
			}
		})
	}
}

func TestIsExemptMethod(t *testing.T) {
	exemptMethods := []string{"OPTIONS", "HEAD"}

	tests := []struct {
		method   string
		expected bool
	}{
		{"OPTIONS", true},
		{"HEAD", true},
		{"options", true}, // case-insensitive
		{"GET", false},
		{"POST", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			result := isExemptMethod(tc.method, exemptMethods)
			if result != tc.expected {
				t.Errorf("isExemptMethod(%q) = %v, want %v", tc.method, result, tc.expected)
			}
		})
	}
}
