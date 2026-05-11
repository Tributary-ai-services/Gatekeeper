package stream

import (
	"encoding/json"
	"fmt"

	"github.com/IBM/sarama"

	tasevents "github.com/Tributary-ai-services/aether-shared/go-events"
	"github.com/Tributary-ai-services/aether-shared/go-events/payloads"
)

// ceContentType is the structured-mode content type per CloudEvents 1.0
// Kafka Protocol Binding §3.4.
const ceContentType = "application/cloudevents+json"

// ceSource builds the URN identifying Gatekeeper as the producer.
// SourceService is normalized into the urn:tas:service:<name> form so
// every TAS service shares one URI scheme.
func ceSource(sourceService string) string {
	if sourceService == "" {
		sourceService = "gatekeeper"
	}
	return "urn:tas:service:" + sourceService
}

// ceSeverity maps Gatekeeper's scan.Severity to the CloudEvents extension
// severity attribute.
func ceSeverity(sev string) tasevents.Severity {
	switch sev {
	case "critical":
		return tasevents.SeverityCritical
	case "high":
		return tasevents.SeverityHigh
	case "medium":
		return tasevents.SeverityMedium
	case "low":
		return tasevents.SeverityLow
	case "info":
		return tasevents.SeverityInfo
	default:
		return ""
	}
}

// BuildFindingCE wraps a stream.Finding in a CloudEvents 1.0 envelope.
// eventID MUST match the legacy envelope's EventID when dual-publishing so
// consumers can dedupe across formats during the migration window.
func BuildFindingCE(eventID string, f Finding, sourceService string) tasevents.Event {
	data := payloads.ComplianceFinding{
		FindingID:    f.ID,
		PatternID:    f.PatternID,
		PatternType:  string(f.PatternType),
		Source:       f.Source,
		ValueHash:    f.ValueHash,
		ValuePreview: f.ValuePreview,
		ActionTaken:  f.ActionTaken,
		Redacted:     f.Redacted,
		Tokenized:    f.Tokenized,
	}
	return tasevents.NewWithID(eventID, payloads.TypeComplianceFindingDetected, ceSource(sourceService),
		tasevents.WithTime(f.Timestamp),
		tasevents.WithSubject(f.ID),
		tasevents.WithTenant(f.TenantID, ""),
		tasevents.WithUser(f.UserID),
		tasevents.WithRequest(f.RequestID),
		tasevents.WithSeverity(ceSeverity(string(f.Severity))),
		tasevents.WithFrameworks(f.Frameworks...),
		tasevents.WithData(data),
	)
}

// BuildActionCE wraps an ActionEvent in a CloudEvents 1.0 envelope.
func BuildActionCE(eventID string, a ActionEvent, sourceService string) tasevents.Event {
	data := payloads.ComplianceAction{
		ActionID:   a.ID,
		FindingID:  a.FindingID,
		RuleID:     a.RuleID,
		ActionType: a.ActionType,
		Success:    a.Success,
		Error:      a.Error,
	}
	return tasevents.NewWithID(eventID, payloads.TypeComplianceActionExecuted, ceSource(sourceService),
		tasevents.WithTime(a.Timestamp),
		tasevents.WithSubject(a.FindingID),
		tasevents.WithTenant(a.TenantID, ""),
		tasevents.WithRequest(a.RequestID),
		tasevents.WithSeverity(tasevents.SeverityInfo),
		tasevents.WithData(data),
	)
}

// BuildAuditCE wraps an AuditEvent in a CloudEvents 1.0 envelope.
func BuildAuditCE(eventID string, a AuditEvent, sourceService string) tasevents.Event {
	data := payloads.ComplianceAudit{
		AuditID:  a.ID,
		Action:   a.Action,
		Resource: a.Resource,
		Details:  a.Details,
	}
	return tasevents.NewWithID(eventID, payloads.TypeComplianceAuditRecorded, ceSource(sourceService),
		tasevents.WithTime(a.Timestamp),
		tasevents.WithSubject(a.Resource),
		tasevents.WithTenant(a.TenantID, ""),
		tasevents.WithUser(a.UserID),
		tasevents.WithRequest(a.RequestID),
		tasevents.WithSeverity(tasevents.SeverityInfo),
		tasevents.WithData(data),
	)
}

// EncodeCEForSarama serializes a CloudEvents envelope into structured-mode
// JSON suitable for a sarama.ProducerMessage. Returns the message value
// bytes and the headers that flag the message as a CloudEvent.
//
// Headers set:
//   - content-type: application/cloudevents+json (CE Kafka §3.4)
//   - ce_type: <event type> (redundant; enables DLQ routing without body parse)
func EncodeCEForSarama(e tasevents.Event) ([]byte, []sarama.RecordHeader, error) {
	if err := e.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid CloudEvent: %w", err)
	}
	value, err := json.Marshal(e)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CloudEvent: %w", err)
	}
	headers := []sarama.RecordHeader{
		{Key: []byte("content-type"), Value: []byte(ceContentType)},
		{Key: []byte("ce_type"), Value: []byte(e.Type)},
	}
	return value, headers, nil
}
