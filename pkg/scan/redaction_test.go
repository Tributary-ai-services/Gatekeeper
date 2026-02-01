package scan

import (
	"strings"
	"testing"
)

func TestRedactionEngine_GeneratePreview(t *testing.T) {
	engine := NewRedactionEngine()

	tests := []struct {
		name     string
		value    string
		piiType  PIIType
		expected string
	}{
		{
			name:     "Email masking",
			value:    "john.doe@example.com",
			piiType:  PIITypeEmail,
			expected: "j*******@example.com",
		},
		{
			name:     "SSN masking",
			value:    "123-45-6789",
			piiType:  PIITypeSSN,
			expected: "***-**-6789",
		},
		{
			name:     "Credit card masking",
			value:    "4111-1111-1111-1111",
			piiType:  PIITypeCreditCard,
			expected: "****-****-****-1111",
		},
		{
			name:     "Phone masking",
			value:    "(555) 123-4567",
			piiType:  PIITypePhoneNumber,
			expected: "**********4567",
		},
		{
			name:     "IP masking",
			value:    "192.168.1.100",
			piiType:  PIITypeIPAddress,
			expected: "***.***.*.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.GeneratePreview(tt.value, tt.piiType)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestRedactionEngine_Redact_Mask(t *testing.T) {
	engine := NewRedactionEngine()

	findings := []Finding{
		{
			Value:   "john@example.com",
			PIIType: PIITypeEmail,
			Location: Location{
				Offset:    15,
				Length:    16,
				EndOffset: 31,
			},
		},
	}

	content := "Contact me at: john@example.com please"
	expected := "Contact me at: j***@example.com please"

	result, err := engine.Redact(content, findings, RedactionMask)
	if err != nil {
		t.Fatalf("Redact returned error: %v", err)
	}

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestRedactionEngine_Redact_Replace(t *testing.T) {
	engine := NewRedactionEngine()

	findings := []Finding{
		{
			Value:   "123-45-6789",
			PIIType: PIITypeSSN,
			Location: Location{
				Offset:    8,
				Length:    11,
				EndOffset: 19,
			},
		},
	}

	content := "My SSN: 123-45-6789"

	result, err := engine.Redact(content, findings, RedactionReplace)
	if err != nil {
		t.Fatalf("Redact returned error: %v", err)
	}

	if !strings.Contains(result, "[SSN_REDACTED]") {
		t.Errorf("Expected SSN to be replaced with placeholder, got %q", result)
	}
}

func TestRedactionEngine_Redact_Hash(t *testing.T) {
	engine := NewRedactionEngine()

	findings := []Finding{
		{
			Value:   "test@example.com",
			PIIType: PIITypeEmail,
			Location: Location{
				Offset:    7,
				Length:    16,
				EndOffset: 23,
			},
		},
	}

	content := "Email: test@example.com"

	result, err := engine.Redact(content, findings, RedactionHash)
	if err != nil {
		t.Fatalf("Redact returned error: %v", err)
	}

	if !strings.Contains(result, "HASH:") {
		t.Errorf("Expected email to be replaced with hash, got %q", result)
	}
}

func TestRedactionEngine_Redact_Remove(t *testing.T) {
	engine := NewRedactionEngine()

	findings := []Finding{
		{
			Value:   "secret",
			PIIType: PIITypeAPIKey,
			Location: Location{
				Offset:    9,
				Length:    6,
				EndOffset: 15,
			},
		},
	}

	content := "API key: secret here"
	expected := "API key:  here"

	result, err := engine.Redact(content, findings, RedactionRemove)
	if err != nil {
		t.Fatalf("Redact returned error: %v", err)
	}

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestRedactionEngine_Redact_Tokenize(t *testing.T) {
	engine := NewRedactionEngine()

	findings := []Finding{
		{
			Value:   "4111-1111-1111-1111",
			PIIType: PIITypeCreditCard,
			Location: Location{
				Offset:    6,
				Length:    19,
				EndOffset: 25,
			},
		},
	}

	content := "Card: 4111-1111-1111-1111"

	result, err := engine.Redact(content, findings, RedactionTokenize)
	if err != nil {
		t.Fatalf("Redact returned error: %v", err)
	}

	if !strings.Contains(result, "[CREDIT_CARD_TOKEN_") {
		t.Errorf("Expected credit card to be tokenized, got %q", result)
	}
}

func TestRedactionEngine_Redact_MultipleFindings(t *testing.T) {
	engine := NewRedactionEngine()

	content := "SSN: 123-45-6789, Email: john@example.com"
	findings := []Finding{
		{
			Value:   "123-45-6789",
			PIIType: PIITypeSSN,
			Location: Location{
				Offset:    5,
				Length:    11,
				EndOffset: 16,
			},
		},
		{
			Value:   "john@example.com",
			PIIType: PIITypeEmail,
			Location: Location{
				Offset:    25,
				Length:    16,
				EndOffset: 41,
			},
		},
	}

	result, err := engine.Redact(content, findings, RedactionReplace)
	if err != nil {
		t.Fatalf("Redact returned error: %v", err)
	}

	if !strings.Contains(result, "[SSN_REDACTED]") {
		t.Errorf("Expected SSN placeholder, got %q", result)
	}
	if !strings.Contains(result, "[EMAIL_REDACTED]") {
		t.Errorf("Expected Email placeholder, got %q", result)
	}
}

func TestRedactionEngine_GenerateRedactionMap(t *testing.T) {
	engine := NewRedactionEngine()

	findings := []Finding{
		{
			Value:   "john@example.com",
			PIIType: PIITypeEmail,
		},
		{
			Value:   "123-45-6789",
			PIIType: PIITypeSSN,
		},
	}

	redactionMap := engine.GenerateRedactionMap(findings, RedactionReplace)

	if len(redactionMap) != 2 {
		t.Errorf("Expected 2 entries in redaction map, got %d", len(redactionMap))
	}

	if redactionMap["john@example.com"] != "[EMAIL_REDACTED]" {
		t.Errorf("Expected email to map to [EMAIL_REDACTED], got %q", redactionMap["john@example.com"])
	}

	if redactionMap["123-45-6789"] != "[SSN_REDACTED]" {
		t.Errorf("Expected SSN to map to [SSN_REDACTED], got %q", redactionMap["123-45-6789"])
	}
}

func TestRedactByMap(t *testing.T) {
	content := "Contact john@example.com or call 555-123-4567"
	redactionMap := map[string]string{
		"john@example.com": "[EMAIL]",
		"555-123-4567":     "[PHONE]",
	}

	result := RedactByMap(content, redactionMap)

	if !strings.Contains(result, "[EMAIL]") {
		t.Error("Expected [EMAIL] in result")
	}
	if !strings.Contains(result, "[PHONE]") {
		t.Error("Expected [PHONE] in result")
	}
}

func TestComputeRedactionStats(t *testing.T) {
	findings := []Finding{
		{Value: "john@example.com", PIIType: PIITypeEmail},
		{Value: "jane@example.com", PIIType: PIITypeEmail},
		{Value: "123-45-6789", PIIType: PIITypeSSN},
	}

	stats := ComputeRedactionStats(findings, RedactionMask)

	if stats.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", stats.TotalFindings)
	}

	if stats.ByType[PIITypeEmail] != 2 {
		t.Errorf("Expected 2 email findings, got %d", stats.ByType[PIITypeEmail])
	}

	if stats.ByType[PIITypeSSN] != 1 {
		t.Errorf("Expected 1 SSN finding, got %d", stats.ByType[PIITypeSSN])
	}
}
