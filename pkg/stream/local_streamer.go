package stream

import (
	"context"
	"errors"
	"sync"
)

// ErrStreamerClosed is returned when attempting to stream to a closed streamer.
var ErrStreamerClosed = errors.New("streamer is closed")

// StreamCallback is called for each finding published to a topic.
type StreamCallback func(topic string, finding Finding)

// LocalStreamer is an in-memory implementation of Streamer for library mode.
// It routes findings to topics and invokes callbacks for each published message.
// This avoids requiring a real Kafka dependency for library consumers.
type LocalStreamer struct {
	router    *TopicRouter
	config    *StreamerConfig
	callbacks []StreamCallback
	mu        sync.RWMutex
	closed    bool
}

// Ensure LocalStreamer implements the Streamer interface.
var _ Streamer = (*LocalStreamer)(nil)

// NewLocalStreamer creates a new local streamer with the given configuration.
// If config is nil, DefaultStreamerConfig() is used.
func NewLocalStreamer(config *StreamerConfig) *LocalStreamer {
	if config == nil {
		config = DefaultStreamerConfig()
	}
	return &LocalStreamer{
		router:    NewTopicRouter(config.Topics),
		config:    config,
		callbacks: make([]StreamCallback, 0),
	}
}

// OnPublish registers a callback that will be invoked for each finding
// published to a topic. Multiple callbacks can be registered and all
// will be invoked in registration order.
func (s *LocalStreamer) OnPublish(cb StreamCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callbacks = append(s.callbacks, cb)
}

// Stream publishes findings to the appropriate topics based on routing rules.
// For each finding, the TopicRouter determines which topics it should be
// published to, and all registered callbacks are invoked for each (topic, finding) pair.
func (s *LocalStreamer) Stream(ctx context.Context, findings []Finding) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrStreamerClosed
	}

	for _, finding := range findings {
		if err := ctx.Err(); err != nil {
			return err
		}
		topics := s.router.Route(finding)
		for _, topic := range topics {
			for _, cb := range s.callbacks {
				cb(topic, finding)
			}
		}
	}

	return nil
}

// StreamBatch publishes a batch of findings. In the local implementation,
// this behaves identically to Stream since there is no network batching concern.
func (s *LocalStreamer) StreamBatch(ctx context.Context, batch []Finding) error {
	return s.Stream(ctx, batch)
}

// Close marks the streamer as closed. Subsequent calls to Stream or StreamBatch
// will return ErrStreamerClosed.
func (s *LocalStreamer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
