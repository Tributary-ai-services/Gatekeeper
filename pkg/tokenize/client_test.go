package tokenize

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

func newTestServer(handler http.HandlerFunc) (*httptest.Server, *TokenizerConfig) {
	server := httptest.NewServer(handler)
	return server, &TokenizerConfig{
		DatabunkerURL: server.URL,
		APIKey:        "test-api-key",
		Timeout:       5 * time.Second,
		MaxRetries:    2,
		RetryBackoff:  10 * time.Millisecond,
		EnableAudit:   true,
	}
}

func TestNewTokenizer_Validation(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := NewTokenizer(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("missing URL", func(t *testing.T) {
		_, err := NewTokenizer(&TokenizerConfig{
			APIKey: "test-key",
		})
		if err == nil {
			t.Fatal("expected error for missing URL")
		}
	})

	t.Run("missing API key", func(t *testing.T) {
		_, err := NewTokenizer(&TokenizerConfig{
			DatabunkerURL: "http://localhost:3000",
		})
		if err == nil {
			t.Fatal("expected error for missing API key")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		tok, err := NewTokenizer(&TokenizerConfig{
			DatabunkerURL: "http://localhost:3000",
			APIKey:        "test-key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tok == nil {
			t.Fatal("expected non-nil tokenizer")
		}
	})
}

func TestTokenize_Success(t *testing.T) {
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/user" {
			t.Errorf("expected /v1/user, got %s", r.URL.Path)
		}
		if r.Header.Get("X-Bunker-Token") != "test-api-key" {
			t.Errorf("expected API key header, got %q", r.Header.Get("X-Bunker-Token"))
		}
		if r.Header.Get("X-Bunker-Tenant") != "tenant-1" {
			t.Errorf("expected tenant header, got %q", r.Header.Get("X-Bunker-Tenant"))
		}

		var profile databunkerProfile
		if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if profile.PIIType != "email" {
			t.Errorf("expected pii_type 'email', got %q", profile.PIIType)
		}
		if profile.Value != "test@example.com" {
			t.Errorf("expected value 'test@example.com', got %q", profile.Value)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(databunkerCreateResponse{
			Status: "ok",
			Token:  "uuid-token-123",
		})
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, err := tok.Tokenize(context.Background(), TokenizeRequest{
		TenantID:  "tenant-1",
		PIIType:   scan.PIITypeEmail,
		Value:     "test@example.com",
		RequestID: "req-1",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Token != "uuid-token-123" {
		t.Errorf("expected token 'uuid-token-123', got %q", resp.Token)
	}
	if resp.PIIType != scan.PIITypeEmail {
		t.Errorf("expected pii_type 'email', got %q", resp.PIIType)
	}
	if resp.Created.IsZero() {
		t.Error("expected created time to be set")
	}
}

func TestTokenize_ServerError(t *testing.T) {
	var attempts int32
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = tok.Tokenize(context.Background(), TokenizeRequest{
		TenantID: "tenant-1",
		PIIType:  scan.PIITypeSSN,
		Value:    "123-45-6789",
	})

	if err == nil {
		t.Fatal("expected error from server error")
	}
	// Should have retried: 1 initial + 2 retries = 3
	got := atomic.LoadInt32(&attempts)
	if got != 3 {
		t.Errorf("expected 3 attempts (1 + 2 retries), got %d", got)
	}
}

func TestTokenize_Timeout(t *testing.T) {
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		json.NewEncoder(w).Encode(databunkerCreateResponse{Status: "ok", Token: "late"})
	})
	defer server.Close()

	cfg.MaxRetries = 0 // no retries
	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = tok.Tokenize(ctx, TokenizeRequest{
		TenantID: "tenant-1",
		PIIType:  scan.PIITypeEmail,
		Value:    "test@example.com",
	})

	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestTokenizeBatch_Multiple(t *testing.T) {
	var count int32
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(databunkerCreateResponse{
			Status: "ok",
			Token:  fmt.Sprintf("token-%d", n),
		})
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reqs := []TokenizeRequest{
		{TenantID: "t1", PIIType: scan.PIITypeEmail, Value: "a@b.com"},
		{TenantID: "t1", PIIType: scan.PIITypeSSN, Value: "123-45-6789"},
		{TenantID: "t1", PIIType: scan.PIITypePhoneNumber, Value: "555-0100"},
	}

	results, err := tok.TokenizeBatch(context.Background(), reqs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Token != "token-1" {
		t.Errorf("expected token-1, got %q", results[0].Token)
	}
	if results[2].Token != "token-3" {
		t.Errorf("expected token-3, got %q", results[2].Token)
	}
}

func TestTokenizeBatch_Empty(t *testing.T) {
	tok, err := NewTokenizer(&TokenizerConfig{
		DatabunkerURL: "http://localhost:9999",
		APIKey:        "key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	results, err := tok.TokenizeBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty batch, got %d", len(results))
	}
}

func TestTokenizeBatch_FailFast(t *testing.T) {
	var count int32
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		if n == 2 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
			return
		}
		json.NewEncoder(w).Encode(databunkerCreateResponse{Status: "ok", Token: fmt.Sprintf("t-%d", n)})
	})
	defer server.Close()

	cfg.MaxRetries = 0 // no retries on client errors
	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reqs := []TokenizeRequest{
		{TenantID: "t1", PIIType: scan.PIITypeEmail, Value: "a@b.com"},
		{TenantID: "t1", PIIType: scan.PIITypeSSN, Value: "123-45-6789"},
		{TenantID: "t1", PIIType: scan.PIITypePhoneNumber, Value: "555-0100"},
	}

	_, err = tok.TokenizeBatch(context.Background(), reqs)
	if err == nil {
		t.Fatal("expected error from batch fail-fast")
	}
	// Should have stopped at 2nd request
	got := atomic.LoadInt32(&count)
	if got != 2 {
		t.Errorf("expected 2 requests before fail, got %d", got)
	}
}

func TestDetokenize_Success(t *testing.T) {
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/user/token/uuid-123" {
			t.Errorf("expected /v1/user/token/uuid-123, got %s", r.URL.Path)
		}

		json.NewEncoder(w).Encode(databunkerGetResponse{
			Status: "ok",
			Data: map[string]interface{}{
				"pii_type": "email",
				"value":    "test@example.com",
			},
		})
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, err := tok.Detokenize(context.Background(), DetokenizeRequest{
		TenantID: "tenant-1",
		Token:    "uuid-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Value != "test@example.com" {
		t.Errorf("expected 'test@example.com', got %q", resp.Value)
	}
	if resp.PIIType != scan.PIITypeEmail {
		t.Errorf("expected pii_type 'email', got %q", resp.PIIType)
	}
}

func TestDetokenize_NotFound(t *testing.T) {
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	cfg.MaxRetries = 0
	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = tok.Detokenize(context.Background(), DetokenizeRequest{
		TenantID: "tenant-1",
		Token:    "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for not found token")
	}
}

func TestGetSecret_Success(t *testing.T) {
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/user/token/signing-key" {
			t.Errorf("expected /v1/user/token/signing-key, got %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(databunkerGetResponse{
			Status: "ok",
			Data: map[string]interface{}{
				"value": "my-secret-key-bytes",
			},
		})
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secret, err := tok.GetSecret(context.Background(), "signing-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(secret) != "my-secret-key-bytes" {
		t.Errorf("expected 'my-secret-key-bytes', got %q", string(secret))
	}
}

func TestLogAudit_Success(t *testing.T) {
	called := false
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(databunkerCreateResponse{Status: "ok", Token: "audit-1"})
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = tok.LogAudit(context.Background(), AuditEvent{
		Timestamp: time.Now(),
		TenantID:  "tenant-1",
		RequestID: "req-1",
		Action:    "tokenize",
		PIIType:   scan.PIITypeEmail,
		Token:     "token-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected audit endpoint to be called")
	}
}

func TestLogAudit_Disabled(t *testing.T) {
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called when audit is disabled")
	})
	defer server.Close()

	cfg.EnableAudit = false
	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = tok.LogAudit(context.Background(), AuditEvent{
		Action: "tokenize",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRetry_TransientThenSuccess(t *testing.T) {
	var attempts int32
	server, cfg := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(databunkerCreateResponse{Status: "ok", Token: "recovered"})
	})
	defer server.Close()

	tok, err := NewTokenizer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, err := tok.Tokenize(context.Background(), TokenizeRequest{
		TenantID: "tenant-1",
		PIIType:  scan.PIITypeEmail,
		Value:    "test@example.com",
	})
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if resp.Token != "recovered" {
		t.Errorf("expected token 'recovered', got %q", resp.Token)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestTokenFormat(t *testing.T) {
	result := TokenFormat(scan.PIITypeEmail, "abc123")
	expected := "[email:abc123]"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}

	result = TokenFormat(scan.PIITypeSSN, "xyz789")
	expected = "[ssn:xyz789]"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestClose_Noop(t *testing.T) {
	tok, err := NewTokenizer(&TokenizerConfig{
		DatabunkerURL: "http://localhost:3000",
		APIKey:        "key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := tok.Close(); err != nil {
		t.Errorf("expected no error from Close, got %v", err)
	}
}
