package stream

import (
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/google/uuid"
)

// SchemaVersion is the current envelope schema. Consumers MUST reject envelopes
// with a version they do not understand.
const SchemaVersion = "1"

// EventType identifies the payload shape carried by an Envelope.
type EventType string

const (
	EventTypeFinding EventType = "finding"
	EventTypeAction  EventType = "action"
	EventTypeAudit   EventType = "audit"
)

// Envelope is the versioned wrapper published to every TAS compliance /
// activity topic. It carries routing + attribution metadata around a
// type-specific payload so consumers can share one schema across topics.
type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	EventID       string    `json:"event_id"`
	EventType     EventType `json:"event_type"`
	Timestamp     time.Time `json:"timestamp"`

	// Tenancy + correlation
	TenantID  string `json:"tenant_id,omitempty"`
	SpaceID   string `json:"space_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`

	// Producer identity — set from StreamerConfig.SourceService
	SourceService string `json:"source_service"`

	// Compliance-only fields (finding / action events); omitted for plain activity
	Severity   scan.Severity `json:"severity,omitempty"`
	Frameworks []string      `json:"frameworks,omitempty"`

	// Payload carries the concrete event struct (Finding, ActionEvent, AuditEvent,
	// or an activity payload from a non-Gatekeeper producer).
	Payload any `json:"payload"`
}

// WrapFinding builds an Envelope v1 around a stream.Finding with a freshly
// generated EventID. Equivalent to WrapFindingWithID(uuid.NewString(), …).
func WrapFinding(f Finding, sourceService string) Envelope {
	return WrapFindingWithID(uuid.NewString(), f, sourceService)
}

// WrapFindingWithID builds an Envelope v1 around a stream.Finding using a
// caller-supplied EventID. Use this when the same event is dual-published
// in another envelope format (e.g. CloudEvents) so consumers can dedupe
// on a stable ID across formats.
//
// Timestamp defaults to Finding.Timestamp when non-zero so a replayed
// finding keeps its original event time.
func WrapFindingWithID(eventID string, f Finding, sourceService string) Envelope {
	ts := f.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		EventType:     EventTypeFinding,
		Timestamp:     ts,
		TenantID:      f.TenantID,
		UserID:        f.UserID,
		RequestID:     f.RequestID,
		SourceService: sourceService,
		Severity:      f.Severity,
		Frameworks:    f.Frameworks,
		Payload:       f,
	}
}

// WrapAction builds an Envelope v1 around an ActionEvent.
func WrapAction(a ActionEvent, sourceService string) Envelope {
	return WrapActionWithID(uuid.NewString(), a, sourceService)
}

// WrapActionWithID builds an Envelope v1 around an ActionEvent with a
// caller-supplied EventID (see WrapFindingWithID for dual-publish rationale).
func WrapActionWithID(eventID string, a ActionEvent, sourceService string) Envelope {
	ts := a.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		EventType:     EventTypeAction,
		Timestamp:     ts,
		TenantID:      a.TenantID,
		RequestID:     a.RequestID,
		SourceService: sourceService,
		Payload:       a,
	}
}

// WrapAudit builds an Envelope v1 around an AuditEvent.
func WrapAudit(a AuditEvent, sourceService string) Envelope {
	return WrapAuditWithID(uuid.NewString(), a, sourceService)
}

// WrapAuditWithID builds an Envelope v1 around an AuditEvent with a
// caller-supplied EventID (see WrapFindingWithID for dual-publish rationale).
func WrapAuditWithID(eventID string, a AuditEvent, sourceService string) Envelope {
	ts := a.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		EventType:     EventTypeAudit,
		Timestamp:     ts,
		TenantID:      a.TenantID,
		UserID:        a.UserID,
		RequestID:     a.RequestID,
		SourceService: sourceService,
		Payload:       a,
	}
}
