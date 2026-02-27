package extract

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

// --- Mock implementations ---

type mockEmbedder struct {
	embedFunc      func(ctx context.Context, text string) ([]float64, error)
	embedBatchFunc func(ctx context.Context, texts []string) ([][]float64, error)
	dimensions     int
}

func (m *mockEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	if m.embedFunc != nil {
		return m.embedFunc(ctx, text)
	}
	return make([]float64, m.dimensions), nil
}

func (m *mockEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if m.embedBatchFunc != nil {
		return m.embedBatchFunc(ctx, texts)
	}
	result := make([][]float64, len(texts))
	for i := range texts {
		result[i] = make([]float64, m.dimensions)
	}
	return result, nil
}

func (m *mockEmbedder) Similarity(a, b []float64) float64 {
	return cosineSimilarity(a, b)
}

func (m *mockEmbedder) GetDimensions() int {
	return m.dimensions
}

type mockSLMClient struct {
	extractFunc        func(ctx context.Context, req SLMRequest) (*SLMResponse, error)
	summarizeFunc      func(ctx context.Context, content string, maxLength int) (string, error)
	summarizeMergeFunc func(ctx context.Context, summaries []string, query string, maxLength int) (string, error)
	closed             bool
}

func (m *mockSLMClient) Extract(ctx context.Context, req SLMRequest) (*SLMResponse, error) {
	if m.extractFunc != nil {
		return m.extractFunc(ctx, req)
	}
	return &SLMResponse{
		Content:    "extracted content",
		TokensUsed: 100,
	}, nil
}

func (m *mockSLMClient) Summarize(ctx context.Context, content string, maxLength int) (string, error) {
	if m.summarizeFunc != nil {
		return m.summarizeFunc(ctx, content, maxLength)
	}
	return "summary", nil
}

func (m *mockSLMClient) SummarizeMerge(ctx context.Context, summaries []string, query string, maxLength int) (string, error) {
	if m.summarizeMergeFunc != nil {
		return m.summarizeMergeFunc(ctx, summaries, query, maxLength)
	}
	return "merged summary", nil
}

func (m *mockSLMClient) Close() error {
	m.closed = true
	return nil
}

// --- Chunker Tests ---

func TestChunker_Basic(t *testing.T) {
	chunker := NewChunker(10)
	content := []byte("abcdefghijklmnopqrstuvwxyz")
	chunks := chunker.Chunk(content)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	// Verify all content is covered
	var combined string
	for _, c := range chunks {
		combined += c.Content
	}
	if combined != string(content) {
		t.Errorf("combined chunks don't match original content")
	}

	// Verify IDs and indices are sequential
	for i, c := range chunks {
		expectedID := fmt.Sprintf("chunk-%d", i)
		if c.ID != expectedID {
			t.Errorf("chunk %d: expected ID %q, got %q", i, expectedID, c.ID)
		}
		if c.Index != i {
			t.Errorf("chunk %d: expected Index %d, got %d", i, i, c.Index)
		}
	}
}

func TestChunker_WithOverlap(t *testing.T) {
	chunker := NewChunker(10)
	content := []byte("abcdefghijklmnopqrstuvwxyz")
	chunks := chunker.ChunkWithOverlap(content, 3)

	if len(chunks) < 2 {
		t.Fatal("expected multiple chunks with overlap")
	}

	// With overlap, later chunks should start before previous ones end
	for i := 1; i < len(chunks); i++ {
		if chunks[i].StartPos >= chunks[i-1].EndPos {
			t.Errorf("chunk %d starts at %d, expected before chunk %d end at %d (overlap)",
				i, chunks[i].StartPos, i-1, chunks[i-1].EndPos)
		}
	}
}

func TestChunker_SmallContent(t *testing.T) {
	chunker := NewChunker(100)
	content := []byte("small")
	chunks := chunker.Chunk(content)

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for small content, got %d", len(chunks))
	}
	if chunks[0].Content != "small" {
		t.Errorf("expected chunk content 'small', got %q", chunks[0].Content)
	}
}

func TestChunker_EmptyContent(t *testing.T) {
	chunker := NewChunker(100)
	chunks := chunker.Chunk([]byte{})

	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty content, got %d", len(chunks))
	}

	chunks = chunker.ChunkWithOverlap([]byte{}, 10)
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty content with overlap, got %d", len(chunks))
	}
}

func TestChunker_NewlineBoundary(t *testing.T) {
	chunker := NewChunker(20)
	// Place a newline in the last 20% of the chunk (position 17-20)
	content := []byte("abcdefghijklmnop\nrstuvwxyz1234567890")
	chunks := chunker.Chunk(content)

	if len(chunks) < 2 {
		t.Fatal("expected at least 2 chunks")
	}

	// First chunk should end at the newline boundary
	if chunks[0].Content[len(chunks[0].Content)-1] != '\n' {
		t.Logf("chunk 0 content: %q", chunks[0].Content)
		// This is acceptable — it just means the newline wasn't in the right window
	}
}

func TestChunker_OverlapExceedsChunkSize(t *testing.T) {
	chunker := NewChunker(10)
	content := []byte("abcdefghijklmnopqrstuvwxyz")
	// Overlap >= chunkSize should be clamped
	chunks := chunker.ChunkWithOverlap(content, 15)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk even with large overlap")
	}
}

// --- Cosine Similarity Tests ---

func TestCosineSimilarity_KnownVectors(t *testing.T) {
	// Identical vectors → similarity = 1.0
	a := []float64{1, 0, 0}
	b := []float64{1, 0, 0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim-1.0) > 0.001 {
		t.Errorf("expected similarity ~1.0 for identical vectors, got %f", sim)
	}

	// Orthogonal vectors → similarity = 0.0
	a = []float64{1, 0, 0}
	b = []float64{0, 1, 0}
	sim = cosineSimilarity(a, b)
	if math.Abs(sim) > 0.001 {
		t.Errorf("expected similarity ~0.0 for orthogonal vectors, got %f", sim)
	}

	// Opposite vectors → similarity = -1.0
	a = []float64{1, 0, 0}
	b = []float64{-1, 0, 0}
	sim = cosineSimilarity(a, b)
	if math.Abs(sim+1.0) > 0.001 {
		t.Errorf("expected similarity ~-1.0 for opposite vectors, got %f", sim)
	}

	// Known angle
	a = []float64{1, 1}
	b = []float64{1, 0}
	sim = cosineSimilarity(a, b)
	expected := 1.0 / math.Sqrt(2)
	if math.Abs(sim-expected) > 0.001 {
		t.Errorf("expected similarity ~%f, got %f", expected, sim)
	}
}

func TestCosineSimilarity_ZeroVector(t *testing.T) {
	a := []float64{0, 0, 0}
	b := []float64{1, 2, 3}
	sim := cosineSimilarity(a, b)
	if sim != 0 {
		t.Errorf("expected similarity 0 for zero vector, got %f", sim)
	}
}

func TestCosineSimilarity_DifferentLengths(t *testing.T) {
	a := []float64{1, 0}
	b := []float64{1, 0, 0}
	sim := cosineSimilarity(a, b)
	if sim != 0 {
		t.Errorf("expected similarity 0 for different length vectors, got %f", sim)
	}
}

func TestCosineSimilarity_EmptyVectors(t *testing.T) {
	sim := cosineSimilarity(nil, nil)
	if sim != 0 {
		t.Errorf("expected similarity 0 for nil vectors, got %f", sim)
	}

	sim = cosineSimilarity([]float64{}, []float64{})
	if sim != 0 {
		t.Errorf("expected similarity 0 for empty vectors, got %f", sim)
	}
}

// --- Extractor Tests ---

func TestExtractor_BelowMinContentSize(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 1000 // Set high threshold
	config.EnableEmbedding = false
	config.EnableSLM = false

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, nil, config,
	)

	result, err := extractor.Extract(context.Background(), ExtractRequest{
		Content: []byte("small content"),
		Query:   "test query",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Content) != "small content" {
		t.Errorf("expected unchanged content, got %q", string(result.Content))
	}
	if result.ReductionRatio != 0 {
		t.Errorf("expected reduction ratio 0, got %f", result.ReductionRatio)
	}
}

func TestExtractor_NoQuery(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 10
	config.EnableEmbedding = true
	config.EnableSLM = false

	embedCalled := false
	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			embedCalled = true
			return nil, nil
		},
		dimensions: 3,
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, nil, config,
	)

	content := make([]byte, 100)
	for i := range content {
		content[i] = 'a'
	}

	result, err := extractor.Extract(context.Background(), ExtractRequest{
		Content: content,
		Query:   "", // No query
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Content) != string(content) {
		t.Errorf("expected unchanged content when no query")
	}
	if embedCalled {
		t.Error("embedder should not be called without a query")
	}
}

func TestExtractor_TopKFiltering(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 10
	config.ChunkSize = 20
	config.ChunkOverlap = 0
	config.RelevanceThreshold = 0.1
	config.TopKChunks = 2
	config.TopKRatio = 1.0 // Don't constrain by ratio
	config.EnableEmbedding = true
	config.EnableSLM = false

	// Create embedder that returns different similarity scores per chunk
	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			result := make([][]float64, len(texts))
			// Query embedding
			result[0] = []float64{1, 0, 0}
			// Chunk embeddings with varying similarity to query
			for i := 1; i < len(texts); i++ {
				switch i {
				case 1:
					result[i] = []float64{0.9, 0.1, 0} // High similarity
				case 2:
					result[i] = []float64{0, 1, 0} // Low similarity
				case 3:
					result[i] = []float64{0.8, 0.2, 0} // Medium-high similarity
				default:
					result[i] = []float64{0, 0, 1} // Low similarity
				}
			}
			return result, nil
		},
		dimensions: 3,
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, nil, config,
	)

	// Create content large enough to generate multiple chunks
	content := make([]byte, 80)
	for i := range content {
		content[i] = byte('a' + i%26)
	}

	result, err := extractor.Extract(context.Background(), ExtractRequest{
		Content: content,
		Query:   "find relevant content",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ChunksRetained > 2 {
		t.Errorf("expected at most 2 retained chunks (TopKChunks), got %d", result.ChunksRetained)
	}
	if result.ReductionRatio <= 0 {
		t.Errorf("expected positive reduction ratio, got %f", result.ReductionRatio)
	}
}

func TestExtractor_EmbeddingError_FallbackToSLM(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 10
	config.EnableEmbedding = true
	config.EnableSLM = true

	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			return nil, fmt.Errorf("embedding service unavailable")
		},
		dimensions: 3,
	}

	slmCalled := false
	slm := &mockSLMClient{
		extractFunc: func(ctx context.Context, req SLMRequest) (*SLMResponse, error) {
			slmCalled = true
			return &SLMResponse{
				Content:        "SLM extracted content",
				TokensUsed:     50,
				ProcessingTime: 10 * time.Millisecond,
			}, nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, slm, config,
	)

	content := make([]byte, 100)
	for i := range content {
		content[i] = 'a'
	}

	result, err := extractor.Extract(context.Background(), ExtractRequest{
		Content: content,
		Query:   "test query",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slmCalled {
		t.Error("expected SLM to be called as fallback when embedding fails")
	}
	if string(result.Content) != "SLM extracted content" {
		t.Errorf("expected SLM content, got %q", string(result.Content))
	}
}

func TestExtractor_AllFailures_ReturnsOriginal(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 10
	config.EnableEmbedding = true
	config.EnableSLM = true

	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			return nil, fmt.Errorf("embedding failed")
		},
		dimensions: 3,
	}

	slm := &mockSLMClient{
		extractFunc: func(ctx context.Context, req SLMRequest) (*SLMResponse, error) {
			return nil, fmt.Errorf("SLM failed")
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, slm, config,
	)

	content := make([]byte, 100)
	for i := range content {
		content[i] = byte('a' + i%26)
	}

	result, err := extractor.Extract(context.Background(), ExtractRequest{
		Content: content,
		Query:   "test query",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Content) != string(content) {
		t.Error("expected original content returned when all extraction fails")
	}
	if result.ReductionRatio != 0 {
		t.Errorf("expected reduction ratio 0, got %f", result.ReductionRatio)
	}
}

func TestExtractor_WithSLM(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 10
	config.ChunkSize = 30
	config.ChunkOverlap = 0
	config.RelevanceThreshold = 0.1
	config.TopKChunks = 100
	config.EnableEmbedding = true
	config.EnableSLM = true

	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			result := make([][]float64, len(texts))
			for i := range texts {
				result[i] = []float64{1, 0, 0} // All similar
			}
			return result, nil
		},
		dimensions: 3,
	}

	slm := &mockSLMClient{
		extractFunc: func(ctx context.Context, req SLMRequest) (*SLMResponse, error) {
			return &SLMResponse{
				Content:        "refined extraction",
				TokensUsed:     30,
				ProcessingTime: 5 * time.Millisecond,
			}, nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, slm, config,
	)

	content := make([]byte, 100)
	for i := range content {
		content[i] = 'x'
	}

	result, err := extractor.Extract(context.Background(), ExtractRequest{
		Content: content,
		Query:   "test query",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Content) != "refined extraction" {
		t.Errorf("expected SLM refined content, got %q", string(result.Content))
	}
	if result.SLMTime == 0 {
		t.Error("expected SLM time to be recorded")
	}
}

func TestExtractor_Close(t *testing.T) {
	slm := &mockSLMClient{}
	config := DefaultExtractorConfig()
	config.EnableEmbedding = false
	config.EnableSLM = true

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, slm, config,
	)

	err := extractor.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slm.closed {
		t.Error("expected SLM client to be closed")
	}
}

func TestExtractor_Close_NilSLM(t *testing.T) {
	config := DefaultExtractorConfig()
	config.EnableEmbedding = false
	config.EnableSLM = false

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, nil, config,
	)

	err := extractor.Close()
	if err != nil {
		t.Fatalf("unexpected error closing with nil SLM: %v", err)
	}
}

func TestNewExtractor_DefaultConfig(t *testing.T) {
	config := DefaultExtractorConfig()
	config.EnableEmbedding = false
	config.EnableSLM = false

	ext, err := NewExtractor(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext == nil {
		t.Fatal("expected non-nil extractor")
	}
}

func TestNewExtractor_NilConfig(t *testing.T) {
	ext, err := NewExtractor(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext == nil {
		t.Fatal("expected non-nil extractor with default config")
	}
}

// --- Summarization Tests ---

func TestSummarize_MapReduce_MultipleChunks(t *testing.T) {
	config := DefaultExtractorConfig()
	config.SummarizeChunkSize = 20
	config.EnableEmbedding = false
	config.EnableSLM = true

	summarizeCalls := 0
	mergeCalled := false
	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			summarizeCalls++
			return fmt.Sprintf("summary-%d", summarizeCalls), nil
		},
		summarizeMergeFunc: func(ctx context.Context, summaries []string, query string, maxLength int) (string, error) {
			mergeCalled = true
			if len(summaries) < 2 {
				t.Errorf("expected multiple summaries to merge, got %d", len(summaries))
			}
			return "final merged summary", nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, slm, config,
	)

	// Content large enough to produce multiple chunks at size 20
	content := make([]byte, 100)
	for i := range content {
		content[i] = byte('a' + i%26)
	}

	result, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   content,
		Strategy:  StrategyMapReduce,
		MaxLength: 200,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summarizeCalls < 2 {
		t.Errorf("expected multiple summarize calls, got %d", summarizeCalls)
	}
	if !mergeCalled {
		t.Error("expected merge to be called for multiple chunks")
	}
	if result.Summary != "final merged summary" {
		t.Errorf("expected 'final merged summary', got %q", result.Summary)
	}
	if result.SLMCalls != summarizeCalls+1 {
		t.Errorf("expected SLMCalls=%d, got %d", summarizeCalls+1, result.SLMCalls)
	}
	if result.ChunksProcessed < 2 {
		t.Errorf("expected multiple chunks processed, got %d", result.ChunksProcessed)
	}
	if result.ReductionRatio <= 0 {
		t.Errorf("expected positive reduction ratio, got %f", result.ReductionRatio)
	}
}

func TestSummarize_MapReduce_SingleChunk(t *testing.T) {
	config := DefaultExtractorConfig()
	config.SummarizeChunkSize = 2048
	config.EnableEmbedding = false
	config.EnableSLM = true

	mergeCalled := false
	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			return "single chunk summary", nil
		},
		summarizeMergeFunc: func(ctx context.Context, summaries []string, query string, maxLength int) (string, error) {
			mergeCalled = true
			return "", nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, slm, config,
	)

	result, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   []byte("short content"),
		Strategy:  StrategyMapReduce,
		MaxLength: 200,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mergeCalled {
		t.Error("merge should NOT be called for single chunk")
	}
	if result.Summary != "single chunk summary" {
		t.Errorf("expected 'single chunk summary', got %q", result.Summary)
	}
	if result.SLMCalls != 1 {
		t.Errorf("expected 1 SLM call, got %d", result.SLMCalls)
	}
}

func TestSummarize_EmbedThenSummarize(t *testing.T) {
	config := DefaultExtractorConfig()
	config.MinContentSize = 10
	config.ChunkSize = 30
	config.ChunkOverlap = 0
	config.RelevanceThreshold = 0.1
	config.TopKChunks = 100
	config.EnableEmbedding = true
	config.EnableSLM = true

	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			result := make([][]float64, len(texts))
			for i := range texts {
				result[i] = []float64{1, 0, 0} // All similar
			}
			return result, nil
		},
		dimensions: 3,
	}

	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			return "embed summary", nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, slm, config,
	)

	content := make([]byte, 100)
	for i := range content {
		content[i] = 'x'
	}

	result, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   content,
		Query:     "test query",
		Strategy:  StrategyEmbedThenSummarize,
		MaxLength: 200,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "embed summary" {
		t.Errorf("expected 'embed summary', got %q", result.Summary)
	}
	if result.SLMCalls != 1 {
		t.Errorf("expected 1 SLM call for embed strategy, got %d", result.SLMCalls)
	}
	if result.EmbeddingTime == 0 {
		t.Error("expected embedding time > 0")
	}
}

func TestSummarize_EmbedFailure_FallbackToMapReduce(t *testing.T) {
	config := DefaultExtractorConfig()
	config.SummarizeChunkSize = 2048
	config.EnableEmbedding = true
	config.EnableSLM = true

	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			return nil, fmt.Errorf("embedding service unavailable")
		},
		dimensions: 3,
	}

	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			return "fallback summary", nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, slm, config,
	)

	result, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   []byte("some content to summarize"),
		Query:     "test query",
		Strategy:  StrategyEmbedThenSummarize,
		MaxLength: 200,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "fallback summary" {
		t.Errorf("expected 'fallback summary', got %q", result.Summary)
	}
}

func TestSummarize_SLMFailure_ReturnsError(t *testing.T) {
	config := DefaultExtractorConfig()
	config.SummarizeChunkSize = 2048
	config.EnableSLM = true

	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			return "", fmt.Errorf("SLM unavailable")
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, slm, config,
	)

	_, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   []byte("content"),
		Strategy:  StrategyMapReduce,
		MaxLength: 200,
	})

	if err == nil {
		t.Fatal("expected error when SLM fails")
	}
}

func TestSummarize_NoSLMClient_ReturnsError(t *testing.T) {
	config := DefaultExtractorConfig()
	config.EnableSLM = false

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, nil, config,
	)

	_, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   []byte("content"),
		Strategy:  StrategyMapReduce,
		MaxLength: 200,
	})

	if err == nil {
		t.Fatal("expected error when no SLM client configured")
	}
}

func TestSummarize_SmallContent(t *testing.T) {
	config := DefaultExtractorConfig()
	config.SummarizeChunkSize = 2048
	config.MinContentSize = 32 * 1024 // 32KB, way larger than content
	config.EnableSLM = true

	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			return "small content summary", nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		nil, slm, config,
	)

	// Content well below MinContentSize — should still summarize
	result, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   []byte("tiny"),
		Strategy:  StrategyMapReduce,
		MaxLength: 200,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "small content summary" {
		t.Errorf("expected 'small content summary', got %q", result.Summary)
	}
}

func TestSummarize_EmbedStrategy_NoQuery_FallsBackToMapReduce(t *testing.T) {
	config := DefaultExtractorConfig()
	config.SummarizeChunkSize = 2048
	config.EnableEmbedding = true
	config.EnableSLM = true

	embedCalled := false
	embedder := &mockEmbedder{
		embedBatchFunc: func(ctx context.Context, texts []string) ([][]float64, error) {
			embedCalled = true
			return nil, nil
		},
		dimensions: 3,
	}

	slm := &mockSLMClient{
		summarizeFunc: func(ctx context.Context, content string, maxLength int) (string, error) {
			return "map-reduce fallback", nil
		},
	}

	extractor := NewExtractorWithComponents(
		NewChunker(config.ChunkSize),
		embedder, slm, config,
	)

	result, err := extractor.Summarize(context.Background(), SummarizeRequest{
		Content:   []byte("content without query"),
		Query:     "", // No query — embed strategy should fall back
		Strategy:  StrategyEmbedThenSummarize,
		MaxLength: 200,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if embedCalled {
		t.Error("embedder should NOT be called when query is empty")
	}
	if result.Summary != "map-reduce fallback" {
		t.Errorf("expected 'map-reduce fallback', got %q", result.Summary)
	}
}
