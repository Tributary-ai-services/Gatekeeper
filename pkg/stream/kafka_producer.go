package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/IBM/sarama"
	"github.com/google/uuid"
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
//
// Each finding is dual-published to every routed topic during the migration
// window:
//  1. Legacy Envelope v1 (existing consumers continue to work)
//  2. CloudEvents 1.0 structured-mode (new aether-be + Spark consumers)
//
// Both messages share the same EventID (UUID) so a CE-aware consumer
// receiving both can deduplicate; consumers that understand only one
// envelope format silently ignore the other via the content-type header.
//
// When SourceService is empty (configuration error) we still produce a
// stable CE source URN ("urn:tas:service:gatekeeper") so consumers can
// always attribute events.
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

		eventID := uuid.NewString()

		// Legacy envelope (Envelope v1, snake_case fields)
		envelope := WrapFindingWithID(eventID, finding, ks.config.SourceService)
		legacyValue, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("failed to marshal envelope for finding %s: %w", finding.ID, err)
		}

		// CloudEvents 1.0 structured-mode (with content-type header)
		ce := BuildFindingCE(eventID, finding, ks.config.SourceService)
		ceValue, ceHeaders, err := EncodeCEForSarama(ce)
		if err != nil {
			// CE encode failure must NOT block legacy delivery. Log via
			// the producer errors channel and continue with legacy only.
			ceValue = nil
			select {
			case ks.errCh <- fmt.Errorf("ce encode failed for finding %s: %w", finding.ID, err):
			default:
			}
		}

		key := sarama.StringEncoder(finding.TenantID + ":" + finding.RequestID)
		topics := ks.router.Route(finding)
		for _, topic := range topics {
			// Legacy message
			if err := ks.send(ctx, &sarama.ProducerMessage{
				Topic: topic,
				Key:   key,
				Value: sarama.ByteEncoder(legacyValue),
			}); err != nil {
				return err
			}

			// CloudEvents mirror (skipped if encode failed)
			if ceValue == nil {
				continue
			}
			if err := ks.send(ctx, &sarama.ProducerMessage{
				Topic:   topic,
				Key:     key,
				Value:   sarama.ByteEncoder(ceValue),
				Headers: ceHeaders,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// send enqueues a message on the sarama AsyncProducer input channel,
// respecting ctx cancellation.
func (ks *KafkaStreamer) send(ctx context.Context, msg *sarama.ProducerMessage) error {
	select {
	case ks.producer.Input() <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
