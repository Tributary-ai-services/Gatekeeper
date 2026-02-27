package extract

import (
	"fmt"
)

// textChunker implements the Chunker interface by splitting content into
// fixed-size chunks, optionally with overlap between adjacent chunks.
type textChunker struct {
	chunkSize int
}

// NewChunker creates a new text chunker with the given chunk size in bytes.
func NewChunker(chunkSize int) Chunker {
	if chunkSize <= 0 {
		chunkSize = 512
	}
	return &textChunker{chunkSize: chunkSize}
}

// Chunk splits content into sequential chunks of the configured size.
// It tries to break at newline boundaries within the last 20% of each chunk.
func (c *textChunker) Chunk(content []byte) []Chunk {
	if len(content) == 0 {
		return nil
	}

	text := string(content)
	var chunks []Chunk
	pos := 0
	index := 0

	for pos < len(text) {
		end := pos + c.chunkSize
		if end > len(text) {
			end = len(text)
		}

		// Try to find a newline boundary in the last 20% of the chunk
		if end < len(text) {
			end = findNewlineBoundary(text, pos, end, c.chunkSize)
		}

		chunks = append(chunks, Chunk{
			ID:       fmt.Sprintf("chunk-%d", index),
			Content:  text[pos:end],
			StartPos: pos,
			EndPos:   end,
			Index:    index,
		})

		pos = end
		index++
	}

	return chunks
}

// ChunkWithOverlap splits content with overlap between adjacent chunks.
// The step size is chunkSize - overlapSize.
func (c *textChunker) ChunkWithOverlap(content []byte, overlapSize int) []Chunk {
	if len(content) == 0 {
		return nil
	}
	if overlapSize < 0 {
		overlapSize = 0
	}
	if overlapSize >= c.chunkSize {
		overlapSize = c.chunkSize / 2
	}

	text := string(content)
	step := c.chunkSize - overlapSize
	if step <= 0 {
		step = 1
	}

	var chunks []Chunk
	pos := 0
	index := 0

	for pos < len(text) {
		end := pos + c.chunkSize
		if end > len(text) {
			end = len(text)
		}

		// Try to find a newline boundary in the last 20% of the chunk
		if end < len(text) {
			end = findNewlineBoundary(text, pos, end, c.chunkSize)
		}

		chunks = append(chunks, Chunk{
			ID:       fmt.Sprintf("chunk-%d", index),
			Content:  text[pos:end],
			StartPos: pos,
			EndPos:   end,
			Index:    index,
		})

		pos += step
		index++
	}

	return chunks
}

// findNewlineBoundary searches for the nearest newline within the last 20% of
// the chunk [pos, end). If found, returns the position just after the newline.
// Otherwise returns end unchanged.
func findNewlineBoundary(text string, pos, end, chunkSize int) int {
	searchStart := end - chunkSize/5
	if searchStart < pos {
		searchStart = pos
	}

	bestBreak := -1
	for i := end - 1; i >= searchStart; i-- {
		if text[i] == '\n' {
			bestBreak = i + 1 // include the newline in the current chunk
			break
		}
	}

	if bestBreak > pos {
		return bestBreak
	}
	return end
}
