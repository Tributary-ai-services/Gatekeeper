package extract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// ollamaEmbedder implements the Embedder interface using Ollama's /api/embed endpoint.
type ollamaEmbedder struct {
	client     *http.Client
	url        string
	model      string
	dimensions int
}

// NewEmbedder creates a new Ollama-based embedder.
func NewEmbedder(config EmbeddingConfig, ollamaURL string) Embedder {
	return &ollamaEmbedder{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		url:        ollamaURL,
		model:      config.Model,
		dimensions: config.Dimensions,
	}
}

// ollamaEmbedRequest is the request body for Ollama's /api/embed endpoint.
type ollamaEmbedRequest struct {
	Model string      `json:"model"`
	Input interface{} `json:"input"` // string or []string
}

// ollamaEmbedResponse is the response from Ollama's /api/embed endpoint.
type ollamaEmbedResponse struct {
	Embeddings [][]float64 `json:"embeddings"`
}

// Embed generates an embedding for a single text string.
func (e *ollamaEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	embeddings, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(embeddings) == 0 {
		return nil, fmt.Errorf("no embeddings returned")
	}
	return embeddings[0], nil
}

// EmbedBatch generates embeddings for multiple texts in a single request.
func (e *ollamaEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	reqBody := ollamaEmbedRequest{
		Model: e.model,
		Input: texts,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal embed request: %w", err)
	}

	endpoint := e.url + "/api/embed"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create embed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call embed API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read embed response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("embed API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var embedResp ollamaEmbedResponse
	if err := json.Unmarshal(respBody, &embedResp); err != nil {
		return nil, fmt.Errorf("failed to parse embed response: %w", err)
	}

	return embedResp.Embeddings, nil
}

// Similarity calculates the cosine similarity between two embedding vectors.
// Returns 0 if either vector has zero magnitude.
func (e *ollamaEmbedder) Similarity(a, b []float64) float64 {
	return cosineSimilarity(a, b)
}

// GetDimensions returns the configured embedding dimensions.
func (e *ollamaEmbedder) GetDimensions() int {
	return e.dimensions
}

// cosineSimilarity computes dot(a,b) / (norm(a) * norm(b)).
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	magProduct := math.Sqrt(normA) * math.Sqrt(normB)
	if magProduct == 0 {
		return 0
	}

	return dot / magProduct
}
