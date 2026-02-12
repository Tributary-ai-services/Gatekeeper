package attest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// cacheEntry holds a cached attestation with its expiry time.
type cacheEntry struct {
	attestation *types.Attestation
	expiresAt   time.Time
}

// memoryCache implements the Cache interface using an in-memory map with TTL.
type memoryCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

// NewMemoryCache creates a new in-memory attestation cache.
func NewMemoryCache() Cache {
	return &memoryCache{
		entries: make(map[string]cacheEntry),
	}
}

// Get retrieves a cached attestation by content hash.
// Returns nil if the entry is not found or has expired.
func (c *memoryCache) Get(_ context.Context, contentHash string) (*types.Attestation, error) {
	c.mu.RLock()
	entry, ok := c.entries[contentHash]
	c.mu.RUnlock()

	if !ok {
		return nil, nil
	}

	if time.Now().After(entry.expiresAt) {
		// Entry has expired; clean it up
		c.mu.Lock()
		delete(c.entries, contentHash)
		c.mu.Unlock()
		return nil, nil
	}

	return entry.attestation, nil
}

// Set stores an attestation in the cache, using the attestation's ExpiresAt as the TTL.
func (c *memoryCache) Set(_ context.Context, attestation *types.Attestation) error {
	if attestation == nil {
		return fmt.Errorf("attestation is nil")
	}

	c.mu.Lock()
	c.entries[attestation.ContentHash] = cacheEntry{
		attestation: attestation,
		expiresAt:   attestation.ExpiresAt,
	}
	c.mu.Unlock()

	return nil
}

// Delete removes a cached attestation by content hash.
func (c *memoryCache) Delete(_ context.Context, contentHash string) error {
	c.mu.Lock()
	delete(c.entries, contentHash)
	c.mu.Unlock()

	return nil
}
