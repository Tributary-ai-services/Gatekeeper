package tokenize

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// databunkerClient implements the Tokenizer interface using Databunker's HTTP API.
type databunkerClient struct {
	client       *http.Client
	baseURL      string
	apiKey       string
	maxRetries   int
	retryBackoff time.Duration
	enableAudit  bool
}

// databunkerCreateResponse is the response from POST /v1/user.
type databunkerCreateResponse struct {
	Status string `json:"status"`
	Token  string `json:"token"`
}

// databunkerGetResponse is the response from GET /v1/user/token/{token}.
type databunkerGetResponse struct {
	Status string                 `json:"status"`
	Data   map[string]interface{} `json:"data"`
}

// databunkerProfile is the profile data stored in Databunker for a PII value.
type databunkerProfile struct {
	PIIType   string `json:"pii_type"`
	Value     string `json:"value"`
	TenantID  string `json:"tenant_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// NewTokenizer creates a new Databunker-backed Tokenizer.
// Returns an error if the URL or API key is missing.
func NewTokenizer(config *TokenizerConfig) (Tokenizer, error) {
	if config == nil {
		return nil, fmt.Errorf("tokenizer config is required")
	}
	if config.DatabunkerURL == "" {
		return nil, fmt.Errorf("databunker URL is required")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("databunker API key is required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	maxRetries := config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}
	retryBackoff := config.RetryBackoff
	if retryBackoff == 0 {
		retryBackoff = 100 * time.Millisecond
	}

	return &databunkerClient{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:      config.DatabunkerURL,
		apiKey:       config.APIKey,
		maxRetries:   maxRetries,
		retryBackoff: retryBackoff,
		enableAudit:  config.EnableAudit,
	}, nil
}

// Tokenize stores a PII value in Databunker and returns an opaque token.
func (c *databunkerClient) Tokenize(ctx context.Context, req TokenizeRequest) (*TokenizeResponse, error) {
	profile := databunkerProfile{
		PIIType:   string(req.PIIType),
		Value:     req.Value,
		TenantID:  req.TenantID,
		RequestID: req.RequestID,
	}

	body, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("marshal profile: %w", err)
	}

	respBody, err := c.doRequest(ctx, http.MethodPost, "/v1/user", body, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("tokenize request: %w", err)
	}

	var resp databunkerCreateResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Status != "ok" {
		return nil, fmt.Errorf("databunker returned status: %s", resp.Status)
	}

	return &TokenizeResponse{
		Token:     resp.Token,
		RecordKey: resp.Token,
		PIIType:   req.PIIType,
		Created:   time.Now(),
	}, nil
}

// TokenizeBatch tokenizes multiple values sequentially.
// Fails fast on the first error.
func (c *databunkerClient) TokenizeBatch(ctx context.Context, reqs []TokenizeRequest) ([]TokenizeResponse, error) {
	if len(reqs) == 0 {
		return []TokenizeResponse{}, nil
	}

	results := make([]TokenizeResponse, 0, len(reqs))
	for _, req := range reqs {
		resp, err := c.Tokenize(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("batch tokenize failed at pii_type=%s: %w", req.PIIType, err)
		}
		results = append(results, *resp)
	}
	return results, nil
}

// Detokenize retrieves the original PII value from Databunker by token.
func (c *databunkerClient) Detokenize(ctx context.Context, req DetokenizeRequest) (*DetokenizeResponse, error) {
	path := "/v1/user/token/" + req.Token

	respBody, err := c.doRequest(ctx, http.MethodGet, path, nil, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("detokenize request: %w", err)
	}

	var resp databunkerGetResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Status != "ok" {
		return nil, fmt.Errorf("databunker returned status: %s", resp.Status)
	}

	value, _ := resp.Data["value"].(string)
	piiType, _ := resp.Data["pii_type"].(string)

	return &DetokenizeResponse{
		Value:     value,
		PIIType:   scan.PIIType(piiType),
		Retrieved: time.Now(),
	}, nil
}

// GetSecret retrieves a secret from Databunker by name.
func (c *databunkerClient) GetSecret(ctx context.Context, secretName string) ([]byte, error) {
	path := "/v1/user/token/" + secretName

	respBody, err := c.doRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}

	var resp databunkerGetResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Status != "ok" {
		return nil, fmt.Errorf("databunker returned status: %s", resp.Status)
	}

	value, _ := resp.Data["value"].(string)
	return []byte(value), nil
}

// LogAudit creates an audit record in Databunker.
// No-op when enableAudit is false.
func (c *databunkerClient) LogAudit(ctx context.Context, event AuditEvent) error {
	if !c.enableAudit {
		return nil
	}

	body, err := json.Marshal(map[string]interface{}{
		"pii_type":   string(event.PIIType),
		"action":     event.Action,
		"tenant_id":  event.TenantID,
		"request_id": event.RequestID,
		"user_id":    event.UserID,
		"token":      event.Token,
		"reason":     event.Reason,
		"timestamp":  event.Timestamp.Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	_, err = c.doRequest(ctx, http.MethodPost, "/v1/user", body, event.TenantID)
	if err != nil {
		return fmt.Errorf("log audit: %w", err)
	}
	return nil
}

// Close is a no-op for the HTTP client.
func (c *databunkerClient) Close() error {
	return nil
}

// doRequest performs an HTTP request with retry logic for transient errors.
func (c *databunkerClient) doRequest(ctx context.Context, method, path string, body []byte, tenantID string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.retryBackoff * time.Duration(attempt)):
			}
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("X-Bunker-Token", c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		if tenantID != "" {
			req.Header.Set("X-Bunker-Tenant", tenantID)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response body: %w", err)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: status %d", resp.StatusCode)
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("not found: %s %s", method, path)
		}

		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("client error: status %d, body: %s", resp.StatusCode, string(respBody))
		}

		return respBody, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, lastErr)
}

