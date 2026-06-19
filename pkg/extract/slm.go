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

// slmClient implements SLMClient against Ollama (/api/generate), OpenAI (or any
// OpenAI-compatible /v1/chat/completions), or Anthropic (/v1/messages). All the
// higher-level methods funnel through generate(); only the transport differs.
type slmClient struct {
	client    *http.Client
	provider  string
	url       string
	model     string
	apiKey    string
	maxTokens int
}

// NewSLMClient creates an SLM client for the configured provider. Defaults to
// Ollama when Provider is empty (back-compat).
func NewSLMClient(config SLMConfig) SLMClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	provider := config.Provider
	if provider == "" {
		provider = SLMProviderOllama
	}
	url := config.URL
	if url == "" {
		switch provider {
		case SLMProviderOpenAI:
			url = "https://api.openai.com"
		case SLMProviderAnthropic:
			url = "https://api.anthropic.com"
		}
	}
	url = strings.TrimRight(url, "/")
	return &slmClient{
		client:    &http.Client{Timeout: timeout},
		provider:  provider,
		url:       url,
		model:     config.Model,
		apiKey:    config.APIKey,
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
func (s *slmClient) Extract(ctx context.Context, req SLMRequest) (*SLMResponse, error) {
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
func (s *slmClient) Summarize(ctx context.Context, content string, maxLength int) (string, error) {
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

// SummarizeMerge merges multiple chunk summaries into a single coherent summary.
func (s *slmClient) SummarizeMerge(ctx context.Context, summaries []string, query string, maxLength int) (string, error) {
	queryClause := ""
	if query != "" {
		queryClause = fmt.Sprintf(" Focus on information relevant to: %s.", query)
	}

	combined := strings.Join(summaries, "\n\n---\n\n")
	prompt := fmt.Sprintf(MergePrompt, maxLength, queryClause, combined)

	response, _, err := s.generate(ctx, prompt, s.maxTokens)
	if err != nil {
		return "", fmt.Errorf("SLM merge failed: %w", err)
	}

	return response, nil
}

// Close releases resources. No-op for HTTP client.
func (s *slmClient) Close() error {
	return nil
}

// generate dispatches to the configured provider's transport. Returns the
// generated text + token count used.
func (s *slmClient) generate(ctx context.Context, prompt string, maxTokens int) (string, int, error) {
	switch s.provider {
	case SLMProviderOpenAI:
		return s.generateOpenAI(ctx, prompt, maxTokens)
	case SLMProviderAnthropic:
		return s.generateAnthropic(ctx, prompt, maxTokens)
	default:
		return s.generateOllama(ctx, prompt, maxTokens)
	}
}

// postJSON is a small helper: marshal body, POST to endpoint with headers,
// return the response bytes (erroring on non-2xx).
func (s *slmClient) postJSON(ctx context.Context, endpoint string, body any, headers map[string]string) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call API: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// --- OpenAI (and OpenAI-compatible) chat completions ---

type openAIChatRequest struct {
	Model     string          `json:"model"`
	Messages  []openAIMessage `json:"messages"`
	MaxTokens int             `json:"max_tokens,omitempty"`
}
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type openAIChatResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (s *slmClient) generateOpenAI(ctx context.Context, prompt string, maxTokens int) (string, int, error) {
	respBody, err := s.postJSON(ctx, s.url+"/v1/chat/completions",
		openAIChatRequest{
			Model:     s.model,
			Messages:  []openAIMessage{{Role: "user", Content: prompt}},
			MaxTokens: maxTokens,
		},
		map[string]string{"Authorization": "Bearer " + s.apiKey},
	)
	if err != nil {
		return "", 0, err
	}
	var r openAIChatResponse
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", 0, fmt.Errorf("parse openai response: %w", err)
	}
	if len(r.Choices) == 0 {
		return "", 0, fmt.Errorf("openai response had no choices")
	}
	return r.Choices[0].Message.Content, r.Usage.CompletionTokens, nil
}

// --- Anthropic messages ---

type anthropicRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []openAIMessage `json:"messages"`
}
type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (s *slmClient) generateAnthropic(ctx context.Context, prompt string, maxTokens int) (string, int, error) {
	if maxTokens <= 0 {
		maxTokens = 1024 // Anthropic requires max_tokens
	}
	respBody, err := s.postJSON(ctx, s.url+"/v1/messages",
		anthropicRequest{
			Model:     s.model,
			MaxTokens: maxTokens,
			Messages:  []openAIMessage{{Role: "user", Content: prompt}},
		},
		map[string]string{"x-api-key": s.apiKey, "anthropic-version": "2023-06-01"},
	)
	if err != nil {
		return "", 0, err
	}
	var r anthropicResponse
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", 0, fmt.Errorf("parse anthropic response: %w", err)
	}
	var sb strings.Builder
	for _, c := range r.Content {
		sb.WriteString(c.Text)
	}
	return sb.String(), r.Usage.OutputTokens, nil
}

// generateOllama calls Ollama's /api/generate endpoint with stream: false.
func (s *slmClient) generateOllama(ctx context.Context, prompt string, maxTokens int) (string, int, error) {
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
