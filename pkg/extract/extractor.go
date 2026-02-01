// Package extract provides content extraction using embeddings and SLM.
package extract

import (
	"context"
	"time"
)

// Extractor reduces content to relevant portions before scanning
type Extractor interface {
	// Extract reduces content to portions relevant to the query
	Extract(ctx context.Context, req ExtractRequest) (*ExtractResult, error)

	// Close releases resources
	Close() error
}

// ExtractRequest contains inputs for extraction
type ExtractRequest struct {
	Content     []byte `json:"content"`
	Query       string `json:"query"`        // What the user asked (for relevance)
	ContentType string `json:"content_type"` // "text", "json", "markdown"
	MaxOutput   int    `json:"max_output"`   // Max output size in bytes
}

// ExtractResult contains extraction output
type ExtractResult struct {
	Content           []byte    `json:"content"`
	OriginalSize      int       `json:"original_size"`
	ExtractedSize     int       `json:"extracted_size"`
	ReductionRatio    float64   `json:"reduction_ratio"`
	ChunksProcessed   int       `json:"chunks_processed"`
	ChunksRetained    int       `json:"chunks_retained"`
	ProcessingTime    time.Duration `json:"processing_time"`
	EmbeddingTime     time.Duration `json:"embedding_time"`
	SLMTime           time.Duration `json:"slm_time,omitempty"`
}

// Chunker splits content into chunks for processing
type Chunker interface {
	// Chunk splits content into chunks
	Chunk(content []byte) []Chunk

	// ChunkWithOverlap splits content with overlap between chunks
	ChunkWithOverlap(content []byte, overlapSize int) []Chunk
}

// Chunk represents a content chunk
type Chunk struct {
	ID        string `json:"id"`
	Content   string `json:"content"`
	StartPos  int    `json:"start_pos"`
	EndPos    int    `json:"end_pos"`
	Index     int    `json:"index"`
}

// Embedder generates vector embeddings for text
type Embedder interface {
	// Embed generates an embedding for text
	Embed(ctx context.Context, text string) ([]float64, error)

	// EmbedBatch generates embeddings for multiple texts
	EmbedBatch(ctx context.Context, texts []string) ([][]float64, error)

	// Similarity calculates cosine similarity between two embeddings
	Similarity(a, b []float64) float64

	// GetDimensions returns the embedding dimensions
	GetDimensions() int
}

// SLMClient interfaces with the Small Language Model for extraction
type SLMClient interface {
	// Extract uses the SLM to extract relevant information
	Extract(ctx context.Context, req SLMRequest) (*SLMResponse, error)

	// Summarize uses the SLM to summarize content
	Summarize(ctx context.Context, content string, maxLength int) (string, error)

	// Close releases resources
	Close() error
}

// SLMRequest contains inputs for SLM extraction
type SLMRequest struct {
	Chunks    []Chunk `json:"chunks"`
	Query     string  `json:"query"`
	MaxTokens int     `json:"max_tokens"`
	Prompt    string  `json:"prompt,omitempty"` // Custom prompt template
}

// SLMResponse contains SLM extraction output
type SLMResponse struct {
	Content        string        `json:"content"`
	TokensUsed     int           `json:"tokens_used"`
	ProcessingTime time.Duration `json:"processing_time"`
}

// ExtractorConfig configures the extractor
type ExtractorConfig struct {
	// Feature toggles
	EnableEmbedding bool `json:"enable_embedding"`
	EnableSLM       bool `json:"enable_slm"`

	// Chunking settings
	ChunkSize    int `json:"chunk_size"`    // Target chunk size in chars
	ChunkOverlap int `json:"chunk_overlap"` // Overlap between chunks

	// Embedding settings
	Embedding EmbeddingConfig `json:"embedding"`

	// SLM settings
	SLM SLMConfig `json:"slm"`

	// Thresholds
	MinContentSize     int     `json:"min_content_size"`     // Min size to trigger extraction
	RelevanceThreshold float64 `json:"relevance_threshold"`  // Min similarity to keep chunk
	TopKChunks         int     `json:"top_k_chunks"`         // Max chunks to keep
	TopKRatio          float64 `json:"top_k_ratio"`          // Ratio of chunks to keep

	// Timeouts
	Timeout time.Duration `json:"timeout"`
}

// EmbeddingConfig configures the embedding model
type EmbeddingConfig struct {
	Model      string `json:"model"`      // e.g., "all-MiniLM-L6-v2"
	Dimensions int    `json:"dimensions"` // e.g., 384
	BatchSize  int    `json:"batch_size"`
	Normalize  bool   `json:"normalize"`
}

// SLMConfig configures the Small Language Model
type SLMConfig struct {
	URL       string        `json:"url"`       // Ollama URL
	Model     string        `json:"model"`     // e.g., "phi3.5"
	Timeout   time.Duration `json:"timeout"`
	MaxTokens int           `json:"max_tokens"`
}

// DefaultExtractorConfig returns default extractor configuration
func DefaultExtractorConfig() *ExtractorConfig {
	return &ExtractorConfig{
		EnableEmbedding: true,
		EnableSLM:       true,
		ChunkSize:       512,
		ChunkOverlap:    50,
		Embedding: EmbeddingConfig{
			Model:      "all-MiniLM-L6-v2",
			Dimensions: 384,
			BatchSize:  32,
			Normalize:  true,
		},
		SLM: SLMConfig{
			URL:       "http://ollama:11434",
			Model:     "phi3.5",
			Timeout:   30 * time.Second,
			MaxTokens: 4096,
		},
		MinContentSize:     32 * 1024, // 32KB
		RelevanceThreshold: 0.3,
		TopKChunks:         100,
		TopKRatio:          0.3,
		Timeout:            30 * time.Second,
	}
}

// ExtractionPrompt is the default prompt for SLM extraction
const ExtractionPrompt = `Extract only information relevant to the following query from the provided content.
Be concise and include only directly relevant information.

Query: {{.Query}}

Content:
{{.Content}}

Relevant information:`
