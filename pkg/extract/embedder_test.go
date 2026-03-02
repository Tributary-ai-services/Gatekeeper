package extract

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer creates an httptest server that handles /api/embed requests.
// embedFunc receives the parsed request and returns embeddings to send back.
func newTestServer(t *testing.T, embedFunc func(req ollamaEmbedRequest) ([][]float64, int)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embed" {
			http.NotFound(w, r)
			return
		}

		var req ollamaEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		embeddings, statusCode := embedFunc(req)
		if statusCode != 0 && statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			w.Write([]byte("server error"))
			return
		}

		resp := ollamaEmbedResponse{Embeddings: embeddings}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestEmbed_SingleText(t *testing.T) {
	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		return [][]float64{{1.0, 2.0, 3.0}}, 0
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  32,
	}, server.URL)

	embedding, err := embedder.Embed(context.Background(), "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(embedding) != 3 {
		t.Fatalf("expected 3 dimensions, got %d", len(embedding))
	}
	if embedding[0] != 1.0 || embedding[1] != 2.0 || embedding[2] != 3.0 {
		t.Errorf("unexpected embedding values: %v", embedding)
	}
}

func TestEmbedBatch_MultipleTexts(t *testing.T) {
	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		texts := req.Input.([]interface{})
		result := make([][]float64, len(texts))
		for i := range texts {
			result[i] = []float64{float64(i), 0, 0}
		}
		return result, 0
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  32,
	}, server.URL)

	embeddings, err := embedder.EmbedBatch(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(embeddings) != 3 {
		t.Fatalf("expected 3 embeddings, got %d", len(embeddings))
	}
	for i, emb := range embeddings {
		if emb[0] != float64(i) {
			t.Errorf("embedding %d: expected first element %f, got %f", i, float64(i), emb[0])
		}
	}
}

func TestEmbedBatch_EmptyInput(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  32,
	}, "http://unused")

	embeddings, err := embedder.EmbedBatch(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if embeddings != nil {
		t.Errorf("expected nil for empty input, got %v", embeddings)
	}
}

func TestEmbedBatch_BatchSizeChunking(t *testing.T) {
	var requestCount int32

	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		atomic.AddInt32(&requestCount, 1)
		texts := req.Input.([]interface{})
		result := make([][]float64, len(texts))
		for i := range texts {
			result[i] = []float64{1, 0, 0}
		}
		return result, 0
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  2, // Small batch size
	}, server.URL)

	// 5 texts with batchSize=2 should produce 3 requests (2+2+1)
	texts := []string{"a", "b", "c", "d", "e"}
	embeddings, err := embedder.EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(embeddings) != 5 {
		t.Fatalf("expected 5 embeddings, got %d", len(embeddings))
	}

	count := atomic.LoadInt32(&requestCount)
	if count != 3 {
		t.Errorf("expected 3 HTTP requests (batchSize=2, 5 texts), got %d", count)
	}
}

func TestEmbedBatch_Normalization(t *testing.T) {
	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		// Return non-unit vectors
		return [][]float64{
			{3.0, 4.0},
			{1.0, 1.0, 1.0, 1.0},
		}, 0
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 2,
		BatchSize:  32,
		Normalize:  true,
	}, server.URL)

	embeddings, err := embedder.EmbedBatch(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, emb := range embeddings {
		norm := l2Norm(emb)
		if math.Abs(norm-1.0) > 1e-9 {
			t.Errorf("embedding %d: expected unit norm, got %f (vector: %v)", i, norm, emb)
		}
	}

	// Verify specific values for [3,4] -> [0.6, 0.8]
	if math.Abs(embeddings[0][0]-0.6) > 1e-9 || math.Abs(embeddings[0][1]-0.8) > 1e-9 {
		t.Errorf("expected [0.6, 0.8], got %v", embeddings[0])
	}
}

func TestEmbedBatch_NormalizationDisabled(t *testing.T) {
	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		return [][]float64{{3.0, 4.0}}, 0
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 2,
		BatchSize:  32,
		Normalize:  false,
	}, server.URL)

	embeddings, err := embedder.EmbedBatch(context.Background(), []string{"a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Raw values should be unchanged
	if embeddings[0][0] != 3.0 || embeddings[0][1] != 4.0 {
		t.Errorf("expected raw [3.0, 4.0], got %v", embeddings[0])
	}
}

func TestEmbedBatch_HTTPError(t *testing.T) {
	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		return nil, http.StatusInternalServerError
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  32,
	}, server.URL)

	_, err := embedder.EmbedBatch(context.Background(), []string{"hello"})
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestEmbedBatch_MalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  32,
	}, server.URL)

	_, err := embedder.EmbedBatch(context.Background(), []string{"hello"})
	if err == nil {
		t.Fatal("expected error for malformed JSON response")
	}
}

func TestEmbedBatch_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 3,
		BatchSize:  32,
	}, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := embedder.EmbedBatch(ctx, []string{"hello"})
	if err == nil {
		t.Fatal("expected error for timeout")
	}
}

func TestSimilarity_IdenticalVectors(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{Dimensions: 3}, "http://unused")
	sim := embedder.Similarity([]float64{1, 2, 3}, []float64{1, 2, 3})
	if math.Abs(sim-1.0) > 1e-9 {
		t.Errorf("expected similarity 1.0 for identical vectors, got %f", sim)
	}
}

func TestSimilarity_OrthogonalVectors(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{Dimensions: 3}, "http://unused")
	sim := embedder.Similarity([]float64{1, 0, 0}, []float64{0, 1, 0})
	if math.Abs(sim) > 1e-9 {
		t.Errorf("expected similarity 0.0 for orthogonal vectors, got %f", sim)
	}
}

func TestSimilarity_DifferentLengths(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{Dimensions: 3}, "http://unused")
	sim := embedder.Similarity([]float64{1, 0}, []float64{1, 0, 0})
	if sim != 0.0 {
		t.Errorf("expected similarity 0.0 for mismatched lengths, got %f", sim)
	}
}

func TestSimilarity_EmptyVectors(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{Dimensions: 3}, "http://unused")
	sim := embedder.Similarity([]float64{}, []float64{})
	if sim != 0.0 {
		t.Errorf("expected similarity 0.0 for empty vectors, got %f", sim)
	}
}

func TestSimilarity_ZeroVector(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{Dimensions: 3}, "http://unused")
	sim := embedder.Similarity([]float64{0, 0, 0}, []float64{1, 2, 3})
	if sim != 0.0 {
		t.Errorf("expected similarity 0.0 for zero vector, got %f", sim)
	}
}

func TestGetDimensions(t *testing.T) {
	embedder := NewEmbedder(EmbeddingConfig{Dimensions: 384}, "http://unused")
	if embedder.GetDimensions() != 384 {
		t.Errorf("expected 384 dimensions, got %d", embedder.GetDimensions())
	}
}

func TestCosineSimilarity_KnownValues(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []float64
		expected float64
	}{
		{"identical unit", []float64{1, 0, 0}, []float64{1, 0, 0}, 1.0},
		{"orthogonal", []float64{1, 0, 0}, []float64{0, 1, 0}, 0.0},
		{"opposite", []float64{1, 0, 0}, []float64{-1, 0, 0}, -1.0},
		{"45 degrees", []float64{1, 1}, []float64{1, 0}, 1.0 / math.Sqrt(2)},
		{"scaled identical", []float64{2, 0, 0}, []float64{5, 0, 0}, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim := cosineSimilarity(tt.a, tt.b)
			if math.Abs(sim-tt.expected) > 1e-9 {
				t.Errorf("expected %f, got %f", tt.expected, sim)
			}
		})
	}
}

func TestNormalizeVector(t *testing.T) {
	v := normalizeVector([]float64{3, 4})
	norm := l2Norm(v)
	if math.Abs(norm-1.0) > 1e-9 {
		t.Errorf("expected unit norm, got %f", norm)
	}
	if math.Abs(v[0]-0.6) > 1e-9 || math.Abs(v[1]-0.8) > 1e-9 {
		t.Errorf("expected [0.6, 0.8], got %v", v)
	}
}

func TestNormalizeVector_ZeroVector(t *testing.T) {
	v := normalizeVector([]float64{0, 0, 0})
	for i, val := range v {
		if val != 0 {
			t.Errorf("element %d: expected 0, got %f", i, val)
		}
	}
}

func TestEmbedBatch_BatchSizeDefault(t *testing.T) {
	// BatchSize=0 should default to 32
	server := newTestServer(t, func(req ollamaEmbedRequest) ([][]float64, int) {
		texts := req.Input.([]interface{})
		result := make([][]float64, len(texts))
		for i := range texts {
			result[i] = []float64{1}
		}
		return result, 0
	})
	defer server.Close()

	embedder := NewEmbedder(EmbeddingConfig{
		Model:      "test-model",
		Dimensions: 1,
		BatchSize:  0, // Should default to 32
	}, server.URL).(*ollamaEmbedder)

	if embedder.batchSize != 32 {
		t.Errorf("expected default batchSize 32, got %d", embedder.batchSize)
	}
}

// l2Norm computes the L2 norm of a vector.
func l2Norm(v []float64) float64 {
	var sum float64
	for _, val := range v {
		sum += val * val
	}
	return math.Sqrt(sum)
}
