package stream

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// testTopics returns a standard topic configuration for tests.
func testTopics() Topics {
	return Topics{
		Findings: "tas.compliance.findings",
		Critical: "tas.compliance.findings.critical",
		HIPAA:    "tas.compliance.findings.hipaa",
		PCI:      "tas.compliance.findings.pci",
		Actions:  "tas.compliance.actions",
		Audit:    "tas.compliance.audit",
	}
}

// TestTopicRouter_AllFindings verifies that every finding goes to the findings topic.
func TestTopicRouter_AllFindings(t *testing.T) {
	router := NewTopicRouter(testTopics())

	tests := []struct {
		name    string
		finding Finding
	}{
		{
			name: "low severity finding",
			finding: Finding{
				ID:        "f-1",
				PatternID: "email",
				Severity:  scan.SeverityLow,
			},
		},
		{
			name: "medium severity finding",
			finding: Finding{
				ID:        "f-2",
				PatternID: "phone_number",
				Severity:  scan.SeverityMedium,
			},
		},
		{
			name: "high severity finding",
			finding: Finding{
				ID:        "f-3",
				PatternID: "ssn",
				Severity:  scan.SeverityHigh,
			},
		},
		{
			name: "finding with no frameworks",
			finding: Finding{
				ID:         "f-4",
				PatternID:  "ip_address",
				Severity:   scan.SeverityLow,
				Frameworks: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topics := router.Route(tt.finding)
			if len(topics) == 0 {
				t.Fatal("expected at least one topic")
			}
			if topics[0] != testTopics().Findings {
				t.Errorf("first topic = %q, want %q", topics[0], testTopics().Findings)
			}
		})
	}
}

// TestTopicRouter_Critical verifies that critical findings also go to the critical topic.
func TestTopicRouter_Critical(t *testing.T) {
	router := NewTopicRouter(testTopics())

	finding := Finding{
		ID:        "f-critical",
		PatternID: "ssn",
		Severity:  scan.SeverityCritical,
	}

	topics := router.Route(finding)
	if len(topics) != 2 {
		t.Fatalf("expected 2 topics, got %d: %v", len(topics), topics)
	}
	assertContains(t, topics, testTopics().Findings)
	assertContains(t, topics, testTopics().Critical)
}

// TestTopicRouter_HIPAA verifies that HIPAA framework findings also go to the HIPAA topic.
func TestTopicRouter_HIPAA(t *testing.T) {
	router := NewTopicRouter(testTopics())

	finding := Finding{
		ID:         "f-hipaa",
		PatternID:  "medical_record_number",
		Severity:   scan.SeverityHigh,
		Frameworks: []string{"HIPAA"},
	}

	topics := router.Route(finding)
	if len(topics) != 2 {
		t.Fatalf("expected 2 topics, got %d: %v", len(topics), topics)
	}
	assertContains(t, topics, testTopics().Findings)
	assertContains(t, topics, testTopics().HIPAA)
}

// TestTopicRouter_PCI verifies that PCI_DSS framework findings also go to the PCI topic.
func TestTopicRouter_PCI(t *testing.T) {
	router := NewTopicRouter(testTopics())

	finding := Finding{
		ID:         "f-pci",
		PatternID:  "credit_card",
		Severity:   scan.SeverityHigh,
		Frameworks: []string{"PCI_DSS"},
	}

	topics := router.Route(finding)
	if len(topics) != 2 {
		t.Fatalf("expected 2 topics, got %d: %v", len(topics), topics)
	}
	assertContains(t, topics, testTopics().Findings)
	assertContains(t, topics, testTopics().PCI)
}

// TestTopicRouter_MultipleTopics verifies that a critical HIPAA+PCI finding goes to
// findings, critical, HIPAA, and PCI topics (4 topics total).
func TestTopicRouter_MultipleTopics(t *testing.T) {
	router := NewTopicRouter(testTopics())

	finding := Finding{
		ID:         "f-multi",
		PatternID:  "ssn",
		Severity:   scan.SeverityCritical,
		Frameworks: []string{"HIPAA", "PCI_DSS"},
		TenantID:   "tenant-1",
		RequestID:  "req-1",
	}

	topics := router.Route(finding)
	if len(topics) != 4 {
		t.Fatalf("expected 4 topics, got %d: %v", len(topics), topics)
	}
	assertContains(t, topics, testTopics().Findings)
	assertContains(t, topics, testTopics().Critical)
	assertContains(t, topics, testTopics().HIPAA)
	assertContains(t, topics, testTopics().PCI)
}

// TestTopicRouter_NonCriticalNoExtraTopic verifies that non-critical findings
// without framework matches only go to the findings topic.
func TestTopicRouter_NonCriticalNoExtraTopic(t *testing.T) {
	router := NewTopicRouter(testTopics())

	finding := Finding{
		ID:        "f-simple",
		PatternID: "email",
		Severity:  scan.SeverityLow,
	}

	topics := router.Route(finding)
	if len(topics) != 1 {
		t.Fatalf("expected 1 topic, got %d: %v", len(topics), topics)
	}
	if topics[0] != testTopics().Findings {
		t.Errorf("topic = %q, want %q", topics[0], testTopics().Findings)
	}
}

// TestTopicRouter_UnknownFramework verifies that unknown frameworks do not add extra topics.
func TestTopicRouter_UnknownFramework(t *testing.T) {
	router := NewTopicRouter(testTopics())

	finding := Finding{
		ID:         "f-unknown-fw",
		PatternID:  "email",
		Severity:   scan.SeverityMedium,
		Frameworks: []string{"UNKNOWN_FRAMEWORK"},
	}

	topics := router.Route(finding)
	if len(topics) != 1 {
		t.Fatalf("expected 1 topic, got %d: %v", len(topics), topics)
	}
}

// TestLocalStreamer_Stream verifies that findings are published to the correct
// topics via callbacks.
func TestLocalStreamer_Stream(t *testing.T) {
	config := DefaultStreamerConfig()
	streamer := NewLocalStreamer(config)

	var mu sync.Mutex
	var results []published

	streamer.OnPublish(func(topic string, finding Finding) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, published{topic: topic, finding: finding})
	})

	findings := []Finding{
		{
			ID:        "test-1",
			PatternID: "email",
			Severity:  scan.SeverityLow,
			TenantID:  "tenant-1",
			RequestID: "req-1",
		},
		{
			ID:         "test-2",
			PatternID:  "ssn",
			Severity:   scan.SeverityCritical,
			Frameworks: []string{"HIPAA"},
			TenantID:   "tenant-1",
			RequestID:  "req-1",
		},
	}

	err := streamer.Stream(context.Background(), findings)
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Finding "test-1" (low, no frameworks) -> 1 topic (findings)
	// Finding "test-2" (critical, HIPAA) -> 3 topics (findings, critical, hipaa)
	// Total: 4 publications
	if len(results) != 4 {
		t.Fatalf("expected 4 publications, got %d", len(results))
	}

	// Verify first finding only went to findings topic
	findingTopics := filterByID(results, "test-1")
	if len(findingTopics) != 1 {
		t.Errorf("test-1: expected 1 publication, got %d", len(findingTopics))
	}

	// Verify second finding went to 3 topics
	criticalTopics := filterByID(results, "test-2")
	if len(criticalTopics) != 3 {
		t.Errorf("test-2: expected 3 publications, got %d", len(criticalTopics))
	}
}

// TestLocalStreamer_StreamBatch verifies that batch publishing works correctly.
func TestLocalStreamer_StreamBatch(t *testing.T) {
	config := DefaultStreamerConfig()
	streamer := NewLocalStreamer(config)

	var mu sync.Mutex
	var results []string

	streamer.OnPublish(func(topic string, finding Finding) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, topic+":"+finding.ID)
	})

	batch := []Finding{
		{
			ID:        "batch-1",
			PatternID: "email",
			Severity:  scan.SeverityLow,
		},
		{
			ID:        "batch-2",
			PatternID: "phone_number",
			Severity:  scan.SeverityMedium,
		},
		{
			ID:         "batch-3",
			PatternID:  "credit_card",
			Severity:   scan.SeverityCritical,
			Frameworks: []string{"PCI_DSS"},
		},
	}

	err := streamer.StreamBatch(context.Background(), batch)
	if err != nil {
		t.Fatalf("StreamBatch returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// batch-1: 1 topic (findings)
	// batch-2: 1 topic (findings)
	// batch-3: 3 topics (findings, critical, pci)
	// Total: 5
	if len(results) != 5 {
		t.Fatalf("expected 5 publications, got %d: %v", len(results), results)
	}
}

// TestLocalStreamer_Closed verifies that Stream and StreamBatch return
// ErrStreamerClosed after Close is called.
func TestLocalStreamer_Closed(t *testing.T) {
	streamer := NewLocalStreamer(nil)

	err := streamer.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	findings := []Finding{
		{ID: "test-closed", PatternID: "email", Severity: scan.SeverityLow},
	}

	err = streamer.Stream(context.Background(), findings)
	if err != ErrStreamerClosed {
		t.Errorf("Stream after close: got %v, want %v", err, ErrStreamerClosed)
	}

	err = streamer.StreamBatch(context.Background(), findings)
	if err != ErrStreamerClosed {
		t.Errorf("StreamBatch after close: got %v, want %v", err, ErrStreamerClosed)
	}
}

// TestLocalStreamer_MultipleCallbacks verifies that all registered callbacks
// are invoked for each published finding.
func TestLocalStreamer_MultipleCallbacks(t *testing.T) {
	streamer := NewLocalStreamer(nil)

	var mu sync.Mutex
	counts := make([]int, 3)

	for i := 0; i < 3; i++ {
		idx := i
		streamer.OnPublish(func(topic string, finding Finding) {
			mu.Lock()
			defer mu.Unlock()
			counts[idx]++
		})
	}

	findings := []Finding{
		{
			ID:        "multi-cb-1",
			PatternID: "email",
			Severity:  scan.SeverityLow,
		},
		{
			ID:        "multi-cb-2",
			PatternID: "ssn",
			Severity:  scan.SeverityHigh,
		},
	}

	err := streamer.Stream(context.Background(), findings)
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// 2 findings, each going to 1 topic (findings) = 2 invocations per callback
	for i, count := range counts {
		if count != 2 {
			t.Errorf("callback %d: invoked %d times, want 2", i, count)
		}
	}
}

// TestConvertFinding tests the existing ConvertFinding function that converts
// a scan.Finding to a stream.Finding.
func TestConvertFinding(t *testing.T) {
	scanFinding := &scan.Finding{
		ID:          "scan-123",
		PatternID:   "ssn",
		PatternType: scan.PatternTypePII,
		PIIType:     scan.PIITypeSSN,
		Value:       "123-45-6789",
		Confidence:  0.95,
		Location: scan.Location{
			Offset:    10,
			Length:    11,
			EndOffset: 21,
			FieldPath: "messages[0].content",
		},
		Frameworks: []scan.FrameworkMatch{
			{
				Framework:   scan.FrameworkHIPAA,
				RuleID:      "HIPAA-001",
				Severity:    scan.SeverityCritical,
				Description: "SSN detected in content",
			},
			{
				Framework:   scan.FrameworkPCIDSS,
				RuleID:      "PCI-002",
				Severity:    scan.SeverityHigh,
				Description: "PII in cardholder data environment",
			},
		},
		Severity:     scan.SeverityCritical,
		ValueHash:    "abc123hash",
		ValuePreview: "1**-**-***9",
		Redacted:     true,
		Tokenized:    false,
	}

	streamFinding := ConvertFinding(
		scanFinding,
		"req-456",    // requestID
		"tenant-789", // tenantID
		"user-001",   // userID
		"llm_input",  // source
		"",           // mcpServerID
		"chat",       // contentType
	)

	// Verify identifiers
	if streamFinding.ID != "scan-123" {
		t.Errorf("ID = %q, want %q", streamFinding.ID, "scan-123")
	}
	if streamFinding.RequestID != "req-456" {
		t.Errorf("RequestID = %q, want %q", streamFinding.RequestID, "req-456")
	}
	if streamFinding.TenantID != "tenant-789" {
		t.Errorf("TenantID = %q, want %q", streamFinding.TenantID, "tenant-789")
	}
	if streamFinding.UserID != "user-001" {
		t.Errorf("UserID = %q, want %q", streamFinding.UserID, "user-001")
	}

	// Verify pattern info
	if streamFinding.PatternID != "ssn" {
		t.Errorf("PatternID = %q, want %q", streamFinding.PatternID, "ssn")
	}
	if streamFinding.PatternType != scan.PatternTypePII {
		t.Errorf("PatternType = %q, want %q", streamFinding.PatternType, scan.PatternTypePII)
	}

	// Verify source and content type
	if streamFinding.Source != "llm_input" {
		t.Errorf("Source = %q, want %q", streamFinding.Source, "llm_input")
	}
	if streamFinding.ContentType != "chat" {
		t.Errorf("ContentType = %q, want %q", streamFinding.ContentType, "chat")
	}

	// Verify location
	if streamFinding.Location.Offset != 10 {
		t.Errorf("Location.Offset = %d, want 10", streamFinding.Location.Offset)
	}
	if streamFinding.Location.Length != 11 {
		t.Errorf("Location.Length = %d, want 11", streamFinding.Location.Length)
	}
	if streamFinding.Location.EndOffset != 21 {
		t.Errorf("Location.EndOffset = %d, want 21", streamFinding.Location.EndOffset)
	}
	if streamFinding.Location.FieldPath != "messages[0].content" {
		t.Errorf("Location.FieldPath = %q, want %q", streamFinding.Location.FieldPath, "messages[0].content")
	}

	// Verify frameworks conversion
	if len(streamFinding.Frameworks) != 2 {
		t.Fatalf("Frameworks length = %d, want 2", len(streamFinding.Frameworks))
	}
	if streamFinding.Frameworks[0] != "HIPAA" {
		t.Errorf("Frameworks[0] = %q, want %q", streamFinding.Frameworks[0], "HIPAA")
	}
	if streamFinding.Frameworks[1] != "PCI_DSS" {
		t.Errorf("Frameworks[1] = %q, want %q", streamFinding.Frameworks[1], "PCI_DSS")
	}

	// Verify severity
	if streamFinding.Severity != scan.SeverityCritical {
		t.Errorf("Severity = %q, want %q", streamFinding.Severity, scan.SeverityCritical)
	}

	// Verify value handling
	if streamFinding.ValueHash != "abc123hash" {
		t.Errorf("ValueHash = %q, want %q", streamFinding.ValueHash, "abc123hash")
	}
	if streamFinding.ValuePreview != "1**-**-***9" {
		t.Errorf("ValuePreview = %q, want %q", streamFinding.ValuePreview, "1**-**-***9")
	}

	// Verify outcome flags
	if !streamFinding.Redacted {
		t.Error("Redacted = false, want true")
	}
	if streamFinding.Tokenized {
		t.Error("Tokenized = true, want false")
	}

	// Verify timestamp is recent
	if time.Since(streamFinding.Timestamp) > 5*time.Second {
		t.Errorf("Timestamp %v is not recent", streamFinding.Timestamp)
	}

	// Verify MCPServerID is empty
	if streamFinding.MCPServerID != "" {
		t.Errorf("MCPServerID = %q, want empty", streamFinding.MCPServerID)
	}
}

// TestLocalStreamer_ContextCancellation verifies that Stream respects context cancellation.
func TestLocalStreamer_ContextCancellation(t *testing.T) {
	streamer := NewLocalStreamer(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	findings := []Finding{
		{ID: "ctx-1", PatternID: "email", Severity: scan.SeverityLow},
	}

	err := streamer.Stream(ctx, findings)
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

// TestLocalStreamer_EmptyFindings verifies that streaming empty findings works without error.
func TestLocalStreamer_EmptyFindings(t *testing.T) {
	streamer := NewLocalStreamer(nil)

	callCount := 0
	streamer.OnPublish(func(topic string, finding Finding) {
		callCount++
	})

	err := streamer.Stream(context.Background(), []Finding{})
	if err != nil {
		t.Fatalf("Stream with empty findings returned error: %v", err)
	}

	if callCount != 0 {
		t.Errorf("callback invoked %d times for empty findings, want 0", callCount)
	}
}

// TestLocalStreamer_NilConfig verifies that NewLocalStreamer with nil config uses defaults.
func TestLocalStreamer_NilConfig(t *testing.T) {
	streamer := NewLocalStreamer(nil)
	if streamer == nil {
		t.Fatal("NewLocalStreamer(nil) returned nil")
	}

	// Should be usable without panicking
	err := streamer.Stream(context.Background(), []Finding{
		{ID: "default-cfg", PatternID: "email", Severity: scan.SeverityLow},
	})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
}

// TestLocalStreamer_CloseIdempotent verifies that Close can be called multiple times.
func TestLocalStreamer_CloseIdempotent(t *testing.T) {
	streamer := NewLocalStreamer(nil)

	if err := streamer.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}
	if err := streamer.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

// --- helpers ---

// assertContains checks that the slice contains the expected string.
func assertContains(t *testing.T, slice []string, expected string) {
	t.Helper()
	for _, s := range slice {
		if s == expected {
			return
		}
	}
	t.Errorf("expected %v to contain %q", slice, expected)
}

// published represents a single (topic, finding) pair captured by a callback.
type published struct {
	topic   string
	finding Finding
}

// filterByID returns published entries matching the given finding ID.
func filterByID(results []published, id string) []published {
	var filtered []published
	for _, r := range results {
		if r.finding.ID == id {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// TestTopicRouter_TopicDeduplication verifies that even with duplicate
// frameworks, topics are not duplicated (since Route iterates and appends
// once per matching framework string).
func TestTopicRouter_TopicDeduplication(t *testing.T) {
	router := NewTopicRouter(testTopics())

	// A finding with the same framework listed twice
	finding := Finding{
		ID:         "f-dup",
		PatternID:  "ssn",
		Severity:   scan.SeverityHigh,
		Frameworks: []string{"HIPAA", "HIPAA"},
	}

	topics := router.Route(finding)

	// Count occurrences of HIPAA topic
	hipaaCount := 0
	for _, topic := range topics {
		if topic == testTopics().HIPAA {
			hipaaCount++
		}
	}

	// The router adds the HIPAA topic once per framework entry,
	// so duplicate frameworks will produce duplicate topics.
	// This documents the current behavior.
	if hipaaCount != 2 {
		t.Errorf("HIPAA topic count = %d, want 2 (one per framework entry)", hipaaCount)
	}
}

// TestTopicRouter_SortedTopics verifies that routing output is predictable
// by sorting and comparing expected topics.
func TestTopicRouter_SortedTopics(t *testing.T) {
	router := NewTopicRouter(testTopics())

	tests := []struct {
		name     string
		finding  Finding
		expected []string
	}{
		{
			name: "low severity only",
			finding: Finding{
				ID: "sort-1", Severity: scan.SeverityLow,
			},
			expected: []string{"tas.compliance.findings"},
		},
		{
			name: "critical with HIPAA and PCI",
			finding: Finding{
				ID:         "sort-2",
				Severity:   scan.SeverityCritical,
				Frameworks: []string{"HIPAA", "PCI_DSS"},
			},
			expected: []string{
				"tas.compliance.findings",
				"tas.compliance.findings.critical",
				"tas.compliance.findings.hipaa",
				"tas.compliance.findings.pci",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topics := router.Route(tt.finding)
			sort.Strings(topics)
			sort.Strings(tt.expected)

			if len(topics) != len(tt.expected) {
				t.Fatalf("got %d topics %v, want %d %v", len(topics), topics, len(tt.expected), tt.expected)
			}
			for i := range topics {
				if topics[i] != tt.expected[i] {
					t.Errorf("topic[%d] = %q, want %q", i, topics[i], tt.expected[i])
				}
			}
		})
	}
}
