package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// findHeader returns the value of the named header in a sarama message, or
// the empty string if absent.
func findHeader(msg *sarama.ProducerMessage, name string) string {
	for _, h := range msg.Headers {
		if bytes.EqualFold(h.Key, []byte(name)) {
			return string(h.Value)
		}
	}
	return ""
}

// TestKafkaStreamer_DualPublishesLegacyAndCloudEvent verifies that Stream
// emits both a legacy Envelope v1 message AND a CloudEvents 1.0 mirror to
// the same topic, with a shared EventID/id so consumers can dedupe.
func TestKafkaStreamer_DualPublishesLegacyAndCloudEvent(t *testing.T) {
	cfg := DefaultStreamerConfig()
	cfg.SourceService = "gatekeeper"

	mockProducer := mocks.NewAsyncProducer(t, mocks.NewTestConfig())

	type capturedMsg struct {
		topic   string
		key     string
		value   []byte
		headers map[string]string
	}
	captured := make([]capturedMsg, 0, 2)
	check := func(msg *sarama.ProducerMessage) error {
		key, err := msg.Key.Encode()
		if err != nil {
			t.Fatalf("encode key: %v", err)
		}
		val, err := msg.Value.Encode()
		if err != nil {
			t.Fatalf("encode value: %v", err)
		}
		hdrs := map[string]string{}
		for _, h := range msg.Headers {
			hdrs[string(h.Key)] = string(h.Value)
		}
		captured = append(captured, capturedMsg{
			topic:   msg.Topic,
			key:     string(key),
			value:   append([]byte(nil), val...),
			headers: hdrs,
		})
		return nil
	}
	// Single finding → 1 topic (findings) → 2 expected messages (legacy + CE)
	mockProducer.ExpectInputWithMessageCheckerFunctionAndSucceed(check)
	mockProducer.ExpectInputWithMessageCheckerFunctionAndSucceed(check)

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
	if err := ks.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got, want := len(captured), 2; got != want {
		t.Fatalf("captured %d messages, want %d", got, want)
	}

	// Both messages must share the partition key.
	for _, m := range captured {
		if got, want := m.key, "tenant-1:req-1"; got != want {
			t.Errorf("partition key = %q, want %q", got, want)
		}
		if got, want := m.topic, cfg.Topics.Findings; got != want {
			t.Errorf("topic = %q, want %q", got, want)
		}
	}

	// Distinguish legacy vs CE by content-type header.
	var legacy, ce *capturedMsg
	for i := range captured {
		switch captured[i].headers["content-type"] {
		case ceContentType:
			ce = &captured[i]
		case "":
			legacy = &captured[i]
		}
	}
	if legacy == nil {
		t.Fatal("no legacy message produced")
	}
	if ce == nil {
		t.Fatal("no CloudEvents message produced")
	}

	// Parse legacy envelope.
	var env Envelope
	if err := json.Unmarshal(legacy.value, &env); err != nil {
		t.Fatalf("legacy value is not a valid envelope: %v", err)
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

	// Parse CE envelope.
	var ceEnv map[string]any
	if err := json.Unmarshal(ce.value, &ceEnv); err != nil {
		t.Fatalf("CE value is not valid JSON: %v", err)
	}
	if got, want := ceEnv["specversion"], "1.0"; got != want {
		t.Errorf("CE specversion = %v, want %v", got, want)
	}
	if got, want := ceEnv["type"], "com.tas.compliance.finding.detected"; got != want {
		t.Errorf("CE type = %v, want %v", got, want)
	}
	if got, want := ceEnv["source"], "urn:tas:service:gatekeeper"; got != want {
		t.Errorf("CE source = %v, want %v", got, want)
	}
	// Dedup invariant: same UUID in both envelopes.
	if env.EventID != ceEnv["id"] {
		t.Errorf("EventID mismatch — legacy=%q CE=%v", env.EventID, ceEnv["id"])
	}
	// CE extension attribute names must be lowercase, no underscores.
	if got, want := ceEnv["tenantid"], "tenant-1"; got != want {
		t.Errorf("CE tenantid = %v, want %v", got, want)
	}
	if got, want := ce.headers["ce_type"], "com.tas.compliance.finding.detected"; got != want {
		t.Errorf("CE ce_type header = %q, want %q", got, want)
	}
}

// TestKafkaStreamer_FanOutTopics verifies that a critical+HIPAA finding is
// published to 3 topics (findings, critical, hipaa). With dual-publish each
// topic receives 2 messages (legacy + CE), so 6 sends total.
func TestKafkaStreamer_FanOutTopics(t *testing.T) {
	cfg := DefaultStreamerConfig()
	cfg.SourceService = "gatekeeper"

	mockProducer := mocks.NewAsyncProducer(t, mocks.NewTestConfig())

	// 3 topics × 2 envelopes each = 6 sends.
	seenTopics := make([]string, 0, 6)
	seenContentTypes := make(map[string]int, 6)
	for i := 0; i < 6; i++ {
		mockProducer.ExpectInputWithMessageCheckerFunctionAndSucceed(func(msg *sarama.ProducerMessage) error {
			seenTopics = append(seenTopics, msg.Topic)
			seenContentTypes[findHeader(msg, "content-type")]++
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

	if err := ks.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Each routed topic should appear twice (legacy + CE).
	expected := map[string]int{
		cfg.Topics.Findings: 0,
		cfg.Topics.Critical: 0,
		cfg.Topics.HIPAA:    0,
	}
	for _, topic := range seenTopics {
		if _, ok := expected[topic]; !ok {
			t.Errorf("unexpected topic %q", topic)
			continue
		}
		expected[topic]++
	}
	for topic, count := range expected {
		if count != 2 {
			t.Errorf("topic %q seen %d times, want 2 (legacy + CE)", topic, count)
		}
	}

	// Half of the messages should carry the CE content-type header,
	// the other half should have no content-type (legacy).
	if got, want := seenContentTypes[ceContentType], 3; got != want {
		t.Errorf("messages with content-type=%q = %d, want %d", ceContentType, got, want)
	}
	if got, want := seenContentTypes[""], 3; got != want {
		t.Errorf("messages without content-type (legacy) = %d, want %d", got, want)
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
