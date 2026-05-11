package stream

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// TestWrapFinding_RequiredFields verifies every envelope carries the fields
// downstream consumers rely on: schema_version, event_id, event_type,
// timestamp, source_service, payload.
func TestWrapFinding_RequiredFields(t *testing.T) {
	f := Finding{
		ID:         "f-1",
		RequestID:  "req-1",
		TenantID:   "tenant-1",
		UserID:     "user-1",
		Severity:   scan.SeverityHigh,
		Frameworks: []string{"HIPAA"},
	}

	env := WrapFinding(f, "gatekeeper")

	if env.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", env.SchemaVersion, SchemaVersion)
	}
	if env.EventID == "" {
		t.Error("EventID is empty")
	}
	if env.EventType != EventTypeFinding {
		t.Errorf("EventType = %q, want %q", env.EventType, EventTypeFinding)
	}
	if env.SourceService != "gatekeeper" {
		t.Errorf("SourceService = %q, want %q", env.SourceService, "gatekeeper")
	}
	if env.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
	if env.TenantID != "tenant-1" || env.RequestID != "req-1" || env.UserID != "user-1" {
		t.Errorf("tenant/request/user mismatch: %+v", env)
	}
	if env.Severity != scan.SeverityHigh {
		t.Errorf("Severity = %q, want %q", env.Severity, scan.SeverityHigh)
	}
	if len(env.Frameworks) != 1 || env.Frameworks[0] != "HIPAA" {
		t.Errorf("Frameworks = %v, want [HIPAA]", env.Frameworks)
	}
	if env.Payload == nil {
		t.Error("Payload is nil")
	}
}

// TestWrapFinding_UniqueEventIDs verifies every wrap call mints a fresh EventID
// so replayed findings dedupe on ingest.
func TestWrapFinding_UniqueEventIDs(t *testing.T) {
	f := Finding{ID: "f-same", Severity: scan.SeverityLow}

	e1 := WrapFinding(f, "gatekeeper")
	e2 := WrapFinding(f, "gatekeeper")

	if e1.EventID == e2.EventID {
		t.Errorf("expected unique event IDs, both were %q", e1.EventID)
	}
}

// TestWrapFinding_PreservesTimestamp verifies WrapFinding uses Finding.Timestamp
// when set (so replayed findings keep their original event time) but falls back
// to now() when zero.
func TestWrapFinding_PreservesTimestamp(t *testing.T) {
	original := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	f := Finding{ID: "f-ts", Timestamp: original, Severity: scan.SeverityLow}

	env := WrapFinding(f, "gatekeeper")
	if !env.Timestamp.Equal(original) {
		t.Errorf("Timestamp = %v, want %v", env.Timestamp, original)
	}

	fZero := Finding{ID: "f-ts-zero", Severity: scan.SeverityLow}
	envZero := WrapFinding(fZero, "gatekeeper")
	if envZero.Timestamp.IsZero() {
		t.Error("zero-timestamp finding did not fall back to now()")
	}
}

// TestEnvelope_JSONContract verifies the on-wire JSON shape stays stable.
// Consumers depend on these exact keys.
func TestEnvelope_JSONContract(t *testing.T) {
	env := WrapFinding(Finding{
		ID:         "f-json",
		RequestID:  "req-json",
		TenantID:   "tenant-json",
		Severity:   scan.SeverityCritical,
		Frameworks: []string{"HIPAA"},
	}, "gatekeeper")

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"schema_version", "event_id", "event_type", "timestamp", "source_service", "payload"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("envelope JSON missing required key %q", key)
		}
	}
	if decoded["schema_version"] != "1" {
		t.Errorf("schema_version = %v, want \"1\"", decoded["schema_version"])
	}
	if decoded["event_type"] != "finding" {
		t.Errorf("event_type = %v, want \"finding\"", decoded["event_type"])
	}
}

// TestWrapAction_WrapAudit verifies the non-finding helpers build correctly
// typed envelopes.
func TestWrapAction_WrapAudit(t *testing.T) {
	action := ActionEvent{
		ID:         "a-1",
		FindingID:  "f-1",
		RequestID:  "req-1",
		TenantID:   "tenant-1",
		RuleID:     "critical-block",
		ActionType: "block",
		Success:    true,
	}
	envA := WrapAction(action, "gatekeeper")
	if envA.EventType != EventTypeAction {
		t.Errorf("action EventType = %q, want %q", envA.EventType, EventTypeAction)
	}
	if envA.TenantID != "tenant-1" || envA.RequestID != "req-1" {
		t.Errorf("action metadata not propagated: %+v", envA)
	}

	audit := AuditEvent{
		ID:        "ae-1",
		TenantID:  "tenant-1",
		UserID:    "user-1",
		RequestID: "req-1",
		Action:    "attestation.verify",
		Resource:  "content-hash-abc",
	}
	envU := WrapAudit(audit, "gatekeeper")
	if envU.EventType != EventTypeAudit {
		t.Errorf("audit EventType = %q, want %q", envU.EventType, EventTypeAudit)
	}
	if envU.UserID != "user-1" {
		t.Errorf("audit UserID = %q, want user-1", envU.UserID)
	}
}
