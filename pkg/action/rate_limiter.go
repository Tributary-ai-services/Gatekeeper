package action

import (
	"sync"
	"time"
)

// rateLimiter implements a sliding window rate limiter using in-memory storage.
type rateLimiter struct {
	mu              sync.Mutex
	windows         map[string][]time.Time
	cleanupInterval time.Duration
	stopCh          chan struct{}
}

// newRateLimiter creates a new in-memory sliding window rate limiter.
// It starts a background goroutine to periodically clean up expired entries.
func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		windows:         make(map[string][]time.Time),
		cleanupInterval: time.Minute,
		stopCh:          make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks whether a request identified by key is within the rate limit.
// It returns true if the request is allowed (count within limit for the given window),
// false if the rate limit has been exceeded. Each allowed call records the current time.
func (r *rateLimiter) Allow(key string, limit int, window time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Filter out expired timestamps
	existing := r.windows[key]
	active := make([]time.Time, 0, len(existing))
	for _, t := range existing {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}

	if len(active) >= limit {
		r.windows[key] = active
		return false
	}

	r.windows[key] = append(active, now)
	return true
}

// cleanupLoop runs periodically to remove expired entries from the windows map.
func (r *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(r.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanup()
		case <-r.stopCh:
			return
		}
	}
}

// cleanup removes entries that are older than a reasonable maximum window (10 minutes).
func (r *rateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	maxAge := 10 * time.Minute
	cutoff := time.Now().Add(-maxAge)

	for key, timestamps := range r.windows {
		active := make([]time.Time, 0, len(timestamps))
		for _, t := range timestamps {
			if t.After(cutoff) {
				active = append(active, t)
			}
		}
		if len(active) == 0 {
			delete(r.windows, key)
		} else {
			r.windows[key] = active
		}
	}
}

// stop terminates the background cleanup goroutine.
func (r *rateLimiter) stop() {
	close(r.stopCh)
}
