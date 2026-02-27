package extract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ollamaSLMClient implements the SLMClient interface using Ollama's /api/generate endpoint.
type ollamaSLMClient struct {
	client    *http.Client
	url       string
	model     string
	maxTokens int
}

// NewSLMClient creates a new Ollama-based SLM client.
func NewSLMClient(config SLMConfig) SLMClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ollamaSLMClient{
		client: &http.Client{
			Timeout: timeout,
		},
		url:       config.URL,
		model:     config.Model,
		maxTokens: config.MaxTokens,
	}
}

// ollamaGenerateRequest is the request body for Ollama's /api/generate endpoint.
type ollamaGenerateRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// ollamaGenerateResponse is the response from Ollama's /api/generate endpoint.
type ollamaGenerateResponse struct {
	Response      string `json:"response"`
	EvalCount     int    `json:"eval_count"`
	TotalDuration int64  `json:"total_duration"` // nanoseconds
}

// Extract uses the SLM to extract relevant information from chunks.
func (s *ollamaSLMClient) Extract(ctx context.Context, req SLMRequest) (*SLMResponse, error) {
	start := time.Now()

	// Build the content from chunks
	var contentParts []string
	for _, chunk := range req.Chunks {
		contentParts = append(contentParts, chunk.Content)
	}
	content := strings.Join(contentParts, "\n\n")

	// Use custom prompt or default extraction prompt
	prompt := req.Prompt
	if prompt == "" {
		prompt = strings.ReplaceAll(ExtractionPrompt, "{{.Query}}", req.Query)
		prompt = strings.ReplaceAll(prompt, "{{.Content}}", content)
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = s.maxTokens
	}

	response, evalCount, err := s.generate(ctx, prompt, maxTokens)
	if err != nil {
		return nil, fmt.Errorf("SLM extract failed: %w", err)
	}

	return &SLMResponse{
		Content:        response,
		TokensUsed:     evalCount,
		ProcessingTime: time.Since(start),
	}, nil
}

// Summarize uses the SLM to summarize content to the given max length.
func (s *ollamaSLMClient) Summarize(ctx context.Context, content string, maxLength int) (string, error) {
	prompt := fmt.Sprintf(
		"Summarize the following content concisely in no more than %d characters.\n\nContent:\n%s\n\nSummary:",
		maxLength, content,
	)

	response, _, err := s.generate(ctx, prompt, s.maxTokens)
	if err != nil {
		return "", fmt.Errorf("SLM summarize failed: %w", err)
	}

	return response, nil
}

// Close releases resources. No-op for HTTP client.
func (s *ollamaSLMClient) Close() error {
	return nil
}

// generate calls Ollama's /api/generate endpoint with stream: false.
func (s *ollamaSLMClient) generate(ctx context.Context, prompt string, maxTokens int) (string, int, error) {
	reqBody := ollamaGenerateRequest{
		Model:  s.model,
		Prompt: prompt,
		Stream: false,
	}
	if maxTokens > 0 {
		reqBody.Options = map[string]interface{}{
			"num_predict": maxTokens,
		}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal generate request: %w", err)
	}

	endpoint := s.url + "/api/generate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create generate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to call generate API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read generate response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("generate API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var genResp ollamaGenerateResponse
	if err := json.Unmarshal(respBody, &genResp); err != nil {
		return "", 0, fmt.Errorf("failed to parse generate response: %w", err)
	}

	return genResp.Response, genResp.EvalCount, nil
}
