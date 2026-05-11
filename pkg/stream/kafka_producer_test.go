package stream

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// TestKafkaStreamer_PublishesEnvelope verifies that Stream wraps each finding
// in an Envelope v1 before handing it to the producer, and that the partition
// key is tenant:request_id.
func TestKafkaStreamer_PublishesEnvelope(t *testing.T) {
	cfg := DefaultStreamerConfig()
	cfg.SourceService = "gatekeeper"

	mockProducer := mocks.NewAsyncProducer(t, mocks.NewTestConfig())

	// Single finding → 1 topic (findings) → 1 expected produce
	mockProducer.ExpectInputWithMessageCheckerFunctionAndSucceed(func(msg *sarama.ProducerMessage) error {
		key, err := msg.Key.Encode()
		if err != nil {
			t.Fatalf("encode key: %v", err)
		}
		if got, want := string(key), "tenant-1:req-1"; got != want {
			t.Errorf("partition key = %q, want %q", got, want)
		}

		val, err := msg.Value.Encode()
		if err != nil {
			t.Fatalf("encode value: %v", err)
		}
		var env Envelope
		if err := json.Unmarshal(val, &env); err != nil {
			t.Fatalf("value is not a valid envelope: %v", err)
		}
		if env.SchemaVersion != SchemaVersion {
			t.Errorf("envelope SchemaVersion = %q, want %q", env.SchemaVersion, SchemaVersion)
		}
		if env.EventType != EventTypeFinding {
			t.Errorf("envelope EventType = %q, want %q", env.EventType, EventTypeFinding)
		}
		if env.SourceService != "gatekeeper" {
			t.Errorf("envelope SourceService = %q, want gatekeeper", env.SourceService)
		}
		if env.EventID == "" {
			t.Error("envelope EventID is empty")
		}
		return nil
	})

	ks := NewKafkaStreamerWithProducer(mockProducer, cfg)
	t.Cleanup(func() { _ = ks.Close() })

	err := ks.Stream(context.Background(), []Finding{{
		ID:        "f-1",
		TenantID:  "tenant-1",
		RequestID: "req-1",
		Severity:  scan.SeverityLow,
	}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
}

// TestKafkaStreamer_FanOutTopics verifies that a critical+HIPAA finding is
// published to 3 topics (findings, critical, hipaa), producing 3 messages.
func TestKafkaStreamer_FanOutTopics(t *testing.T) {
	cfg := DefaultStreamerConfig()
	cfg.SourceService = "gatekeeper"

	mockProducer := mocks.NewAsyncProducer(t, mocks.NewTestConfig())

	seenTopics := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		mockProducer.ExpectInputWithMessageCheckerFunctionAndSucceed(func(msg *sarama.ProducerMessage) error {
			seenTopics = append(seenTopics, msg.Topic)
			return nil
		})
	}

	ks := NewKafkaStreamerWithProducer(mockProducer, cfg)
	t.Cleanup(func() { _ = ks.Close() })

	err := ks.Stream(context.Background(), []Finding{{
		ID:         "f-fanout",
		TenantID:   "tenant-1",
		RequestID:  "req-1",
		Severity:   scan.SeverityCritical,
		Frameworks: []string{"HIPAA"},
	}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Close flushes the mock producer so all expectations run before we assert.
	// Close is idempotent, so the t.Cleanup below is safe.
	if err := ks.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	expected := map[string]bool{
		cfg.Topics.Findings: false,
		cfg.Topics.Critical: false,
		cfg.Topics.HIPAA:    false,
	}
	for _, topic := range seenTopics {
		if _, ok := expected[topic]; !ok {
			t.Errorf("unexpected topic %q", topic)
		}
		expected[topic] = true
	}
	for topic, seen := range expected {
		if !seen {
			t.Errorf("topic %q was not published to", topic)
		}
	}
}

// TestKafkaStreamer_ClosedErrors verifies Stream returns ErrStreamerClosed
// after Close.
func TestKafkaStreamer_ClosedErrors(t *testing.T) {
	cfg := DefaultStreamerConfig()
	mockProducer := mocks.NewAsyncProducer(t, mocks.NewTestConfig())
	ks := NewKafkaStreamerWithProducer(mockProducer, cfg)

	if err := ks.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := ks.Stream(context.Background(), []Finding{{ID: "f-1", Severity: scan.SeverityLow}})
	if err != ErrStreamerClosed {
		t.Errorf("Stream after close: got %v, want ErrStreamerClosed", err)
	}
}

// TestKafkaStreamer_NoBrokers verifies constructor validation.
func TestKafkaStreamer_NoBrokers(t *testing.T) {
	cfg := &StreamerConfig{Brokers: nil}
	if _, err := NewKafkaStreamer(cfg); err == nil {
		t.Error("expected error for empty brokers, got nil")
	}
}
