package extract

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// defaultExtractor implements the Extractor interface, orchestrating
// chunking → embedding → scoring → optional SLM extraction.
type defaultExtractor struct {
	chunker   Chunker
	embedder  Embedder
	slmClient SLMClient
	config    *ExtractorConfig
}

// NewExtractor creates a new extractor with all sub-components based on config.
func NewExtractor(config *ExtractorConfig) (Extractor, error) {
	if config == nil {
		config = DefaultExtractorConfig()
	}

	chunker := NewChunker(config.ChunkSize)

	var embedder Embedder
	if config.EnableEmbedding {
		embedder = NewEmbedder(config.Embedding, config.SLM.URL)
	}

	var slmClient SLMClient
	if config.EnableSLM {
		slmClient = NewSLMClient(config.SLM)
	}

	return &defaultExtractor{
		chunker:   chunker,
		embedder:  embedder,
		slmClient: slmClient,
		config:    config,
	}, nil
}

// NewExtractorWithComponents creates an extractor with explicitly provided sub-components.
// Useful for testing with mocks.
func NewExtractorWithComponents(chunker Chunker, embedder Embedder, slmClient SLMClient, config *ExtractorConfig) Extractor {
	if config == nil {
		config = DefaultExtractorConfig()
	}
	return &defaultExtractor{
		chunker:   chunker,
		embedder:  embedder,
		slmClient: slmClient,
		config:    config,
	}
}

// scoredChunk pairs a chunk with its similarity score for ranking.
type scoredChunk struct {
	chunk      Chunk
	similarity float64
}

// Extract reduces content to portions relevant to the query.
func (e *defaultExtractor) Extract(ctx context.Context, req ExtractRequest) (*ExtractResult, error) {
	start := time.Now()
	originalSize := len(req.Content)

	result := &ExtractResult{
		OriginalSize: originalSize,
	}

	// If content is below minimum size, return unchanged
	if originalSize < e.config.MinContentSize {
		result.Content = req.Content
		result.ExtractedSize = originalSize
		result.ReductionRatio = 0
		result.ProcessingTime = time.Since(start)
		return result, nil
	}

	// If no query is provided, we can't do embedding-based extraction
	if req.Query == "" {
		result.Content = req.Content
		result.ExtractedSize = originalSize
		result.ReductionRatio = 0
		result.ProcessingTime = time.Since(start)
		return result, nil
	}

	// Chunk content with overlap
	overlap := e.config.ChunkOverlap
	chunks := e.chunker.ChunkWithOverlap(req.Content, overlap)
	result.ChunksProcessed = len(chunks)

	if len(chunks) == 0 {
		result.Content = req.Content
		result.ExtractedSize = originalSize
		result.ReductionRatio = 0
		result.ProcessingTime = time.Since(start)
		return result, nil
	}

	// Try embedding-based scoring
	retainedChunks, embeddingTime, err := e.scoreAndFilterChunks(ctx, req.Query, chunks)
	result.EmbeddingTime = embeddingTime

	if err != nil {
		// Embedding failed — try SLM-only fallback
		if e.slmClient != nil {
			slmResult, slmErr := e.extractWithSLM(ctx, req.Query, chunks, req.MaxOutput)
			if slmErr == nil {
				result.Content = []byte(slmResult.Content)
				result.ExtractedSize = len(result.Content)
				result.ReductionRatio = 1 - float64(result.ExtractedSize)/float64(originalSize)
				result.ChunksRetained = len(chunks)
				result.SLMTime = slmResult.ProcessingTime
				result.ProcessingTime = time.Since(start)
				return result, nil
			}
		}
		// All extraction failed — return original content (graceful degradation)
		result.Content = req.Content
		result.ExtractedSize = originalSize
		result.ReductionRatio = 0
		result.ProcessingTime = time.Since(start)
		return result, nil
	}

	result.ChunksRetained = len(retainedChunks)

	// If SLM is enabled, feed retained chunks through SLM for further extraction
	if e.slmClient != nil && e.config.EnableSLM {
		slmResult, slmErr := e.extractWithSLM(ctx, req.Query, retainedChunks, req.MaxOutput)
		if slmErr == nil {
			result.Content = []byte(slmResult.Content)
			result.ExtractedSize = len(result.Content)
			result.ReductionRatio = 1 - float64(result.ExtractedSize)/float64(originalSize)
			result.SLMTime = slmResult.ProcessingTime
			result.ProcessingTime = time.Since(start)
			return result, nil
		}
		// SLM failed — fall through to concatenation
	}

	// Concatenate retained chunks (no SLM or SLM failed)
	concatenated := concatenateChunks(retainedChunks)
	result.Content = []byte(concatenated)
	result.ExtractedSize = len(result.Content)
	result.ReductionRatio = 1 - float64(result.ExtractedSize)/float64(originalSize)
	result.ProcessingTime = time.Since(start)

	return result, nil
}

// Close releases resources held by sub-components.
func (e *defaultExtractor) Close() error {
	if e.slmClient != nil {
		return e.slmClient.Close()
	}
	return nil
}

// scoreAndFilterChunks embeds the query and all chunks, scores by cosine similarity,
// and returns the top-K chunks above the relevance threshold.
func (e *defaultExtractor) scoreAndFilterChunks(ctx context.Context, query string, chunks []Chunk) ([]Chunk, time.Duration, error) {
	if e.embedder == nil {
		return nil, 0, fmt.Errorf("no embedder configured")
	}

	embStart := time.Now()

	// Build texts: query first, then all chunks
	texts := make([]string, 0, len(chunks)+1)
	texts = append(texts, query)
	for _, c := range chunks {
		texts = append(texts, c.Content)
	}

	embeddings, err := e.embedder.EmbedBatch(ctx, texts)
	if err != nil {
		return nil, time.Since(embStart), fmt.Errorf("embedding failed: %w", err)
	}

	if len(embeddings) < len(chunks)+1 {
		return nil, time.Since(embStart), fmt.Errorf("expected %d embeddings, got %d", len(chunks)+1, len(embeddings))
	}

	embeddingTime := time.Since(embStart)
	queryEmbedding := embeddings[0]

	// Score each chunk
	scored := make([]scoredChunk, 0, len(chunks))
	for i, chunk := range chunks {
		sim := e.embedder.Similarity(queryEmbedding, embeddings[i+1])
		if sim >= e.config.RelevanceThreshold {
			scored = append(scored, scoredChunk{chunk: chunk, similarity: sim})
		}
	}

	// Sort by similarity descending
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].similarity > scored[j].similarity
	})

	// Determine how many to keep
	maxChunks := e.config.TopKChunks
	if e.config.TopKRatio > 0 {
		ratioMax := int(float64(len(chunks)) * e.config.TopKRatio)
		if ratioMax < maxChunks {
			maxChunks = ratioMax
		}
	}
	if maxChunks <= 0 {
		maxChunks = 1
	}
	if len(scored) > maxChunks {
		scored = scored[:maxChunks]
	}

	// Sort retained chunks by original position to maintain order
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].chunk.Index < scored[j].chunk.Index
	})

	retained := make([]Chunk, len(scored))
	for i, sc := range scored {
		retained[i] = sc.chunk
	}

	return retained, embeddingTime, nil
}

// extractWithSLM sends chunks to the SLM for extraction.
func (e *defaultExtractor) extractWithSLM(ctx context.Context, query string, chunks []Chunk, maxOutput int) (*SLMResponse, error) {
	maxTokens := e.config.SLM.MaxTokens
	if maxOutput > 0 {
		// Rough estimate: 4 chars per token
		tokenEstimate := maxOutput / 4
		if tokenEstimate < maxTokens {
			maxTokens = tokenEstimate
		}
	}

	return e.slmClient.Extract(ctx, SLMRequest{
		Chunks:    chunks,
		Query:     query,
		MaxTokens: maxTokens,
	})
}

// concatenateChunks joins chunks in order, separated by double newlines.
func concatenateChunks(chunks []Chunk) string {
	parts := make([]string, len(chunks))
	for i, c := range chunks {
		parts[i] = c.Content
	}
	return strings.Join(parts, "\n\n")
}
