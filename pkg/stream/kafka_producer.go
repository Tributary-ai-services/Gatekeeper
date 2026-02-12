package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/IBM/sarama"
)

// KafkaStreamer is a Kafka-backed implementation of Streamer.
// It uses sarama's AsyncProducer for high-throughput, non-blocking publishing.
type KafkaStreamer struct {
	producer sarama.AsyncProducer
	router   *TopicRouter
	config   *StreamerConfig
	mu       sync.RWMutex
	closed   bool
	errCh    chan error
	wg       sync.WaitGroup
}

// Ensure KafkaStreamer implements the Streamer interface.
var _ Streamer = (*KafkaStreamer)(nil)

// NewKafkaStreamer creates a new Kafka streamer with the given configuration.
// It connects to the configured brokers and starts an async producer.
func NewKafkaStreamer(config *StreamerConfig) (*KafkaStreamer, error) {
	if config == nil {
		config = DefaultStreamerConfig()
	}

	if len(config.Brokers) == 0 {
		return nil, errors.New("at least one Kafka broker is required")
	}

	saramaConfig := buildSaramaConfig(config)

	producer, err := sarama.NewAsyncProducer(config.Brokers, saramaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	ks := &KafkaStreamer{
		producer: producer,
		router:   NewTopicRouter(config.Topics),
		config:   config,
		errCh:    make(chan error, 100),
	}

	// Start background goroutines to handle successes and errors
	ks.wg.Add(2)
	go ks.handleSuccesses()
	go ks.handleErrors()

	return ks, nil
}

// NewKafkaStreamerWithProducer creates a KafkaStreamer with an injected producer.
// This is primarily useful for testing with sarama/mocks.
func NewKafkaStreamerWithProducer(producer sarama.AsyncProducer, config *StreamerConfig) *KafkaStreamer {
	if config == nil {
		config = DefaultStreamerConfig()
	}

	ks := &KafkaStreamer{
		producer: producer,
		router:   NewTopicRouter(config.Topics),
		config:   config,
		errCh:    make(chan error, 100),
	}

	ks.wg.Add(2)
	go ks.handleSuccesses()
	go ks.handleErrors()

	return ks
}

// Stream publishes findings to Kafka topics based on routing rules.
func (ks *KafkaStreamer) Stream(ctx context.Context, findings []Finding) error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return ErrStreamerClosed
	}

	for _, finding := range findings {
		if err := ctx.Err(); err != nil {
			return err
		}

		data, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("failed to marshal finding %s: %w", finding.ID, err)
		}

		// Route to appropriate topics
		topics := ks.router.Route(finding)
		for _, topic := range topics {
			msg := &sarama.ProducerMessage{
				Topic: topic,
				Key:   sarama.StringEncoder(finding.TenantID + ":" + finding.RequestID),
				Value: sarama.ByteEncoder(data),
			}

			select {
			case ks.producer.Input() <- msg:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// StreamBatch publishes a batch of findings. Uses the same implementation
// as Stream since sarama's async producer handles batching internally.
func (ks *KafkaStreamer) StreamBatch(ctx context.Context, batch []Finding) error {
	return ks.Stream(ctx, batch)
}

// Close flushes pending messages and closes the Kafka producer.
func (ks *KafkaStreamer) Close() error {
	ks.mu.Lock()
	if ks.closed {
		ks.mu.Unlock()
		return nil
	}
	ks.closed = true
	ks.mu.Unlock()

	// AsyncClose triggers the producer to flush and close
	ks.producer.AsyncClose()

	// Wait for background handlers to finish
	ks.wg.Wait()

	return nil
}

// Errors returns a channel of non-fatal errors encountered during publishing.
func (ks *KafkaStreamer) Errors() <-chan error {
	return ks.errCh
}

// handleSuccesses drains the producer's success channel.
func (ks *KafkaStreamer) handleSuccesses() {
	defer ks.wg.Done()
	for range ks.producer.Successes() {
		// Success messages are acknowledged; no action needed.
	}
}

// handleErrors drains the producer's error channel and forwards errors.
func (ks *KafkaStreamer) handleErrors() {
	defer ks.wg.Done()
	for err := range ks.producer.Errors() {
		if err != nil {
			select {
			case ks.errCh <- fmt.Errorf("kafka produce error on topic %s: %w", err.Msg.Topic, err.Err):
			default:
				// Error channel full; drop to avoid blocking the producer
			}
		}
	}
}

// buildSaramaConfig creates a sarama configuration from our StreamerConfig.
func buildSaramaConfig(config *StreamerConfig) *sarama.Config {
	sc := sarama.NewConfig()

	// Producer settings
	sc.Producer.Return.Successes = true
	sc.Producer.Return.Errors = true

	// Batch settings
	if config.FlushInterval > 0 {
		sc.Producer.Flush.Frequency = config.FlushInterval
	}
	if config.BatchSize > 0 {
		sc.Producer.Flush.Messages = config.BatchSize
	}

	// Compression
	switch config.Compression {
	case "gzip":
		sc.Producer.Compression = sarama.CompressionGZIP
	case "snappy":
		sc.Producer.Compression = sarama.CompressionSnappy
	case "lz4":
		sc.Producer.Compression = sarama.CompressionLZ4
	default:
		sc.Producer.Compression = sarama.CompressionNone
	}

	// Required acks
	switch config.RequiredAcks {
	case "none":
		sc.Producer.RequiredAcks = sarama.NoResponse
	case "leader":
		sc.Producer.RequiredAcks = sarama.WaitForLocal
	case "all":
		sc.Producer.RequiredAcks = sarama.WaitForAll
	default:
		sc.Producer.RequiredAcks = sarama.WaitForAll
	}

	// Retry settings
	if config.MaxRetries > 0 {
		sc.Producer.Retry.Max = config.MaxRetries
	}
	if config.RetryBackoff > 0 {
		sc.Producer.Retry.Backoff = config.RetryBackoff
	}

	return sc
}
