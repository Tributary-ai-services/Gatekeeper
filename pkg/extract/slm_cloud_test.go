package extract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSLMClient_OpenAIProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("auth header = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "compressed"}}},
			"usage":   map[string]int{"completion_tokens": 7},
		})
	}))
	defer srv.Close()

	c := NewSLMClient(SLMConfig{Provider: SLMProviderOpenAI, URL: srv.URL, Model: "gpt-4o-mini", APIKey: "test-key"})
	out, err := c.Summarize(context.Background(), "long text", 100)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if out != "compressed" {
		t.Errorf("got %q, want compressed", out)
	}
}

func TestSLMClient_AnthropicProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "ak" {
			t.Errorf("x-api-key = %q", got)
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Error("missing anthropic-version header")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]string{{"type": "text", "text": "tight"}},
			"usage":   map[string]int{"output_tokens": 3},
		})
	}))
	defer srv.Close()

	c := NewSLMClient(SLMConfig{Provider: SLMProviderAnthropic, URL: srv.URL, Model: "claude-haiku-4-5-20251001", APIKey: "ak"})
	out, err := c.Summarize(context.Background(), "long text", 100)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if out != "tight" {
		t.Errorf("got %q, want tight", out)
	}
}

func TestSLMClient_DefaultsToOllama(t *testing.T) {
	c := NewSLMClient(SLMConfig{Model: "phi3.5", URL: "http://ollama:11434"}).(*slmClient)
	if c.provider != SLMProviderOllama {
		t.Errorf("provider = %q, want ollama", c.provider)
	}
}
