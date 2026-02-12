package scan

import (
	"context"
	"testing"
)

// ============================================================================
// Passport Matcher Tests
// ============================================================================

func TestPassportMatcher(t *testing.T) {
	m := NewPassportMatcher()

	tests := []struct {
		name           string
		content        string
		expectMatch    bool
		minConfidence  float64
	}{
		{
			name:          "US passport with context",
			content:       "My passport number is A12345678 and it expires next year",
			expectMatch:   true,
			minConfidence: 0.90,
		},
		{
			name:          "UK passport with context",
			content:       "Passport: AB123456789 issued in London",
			expectMatch:   true,
			minConfidence: 0.90,
		},
		{
			name:          "Passport number without context keyword",
			content:       "The reference code is A12345678 for the order",
			expectMatch:   true,
			minConfidence: 0.60,
		},
		{
			name:        "Too short to be passport",
			content:     "passport A12 is invalid",
			expectMatch: false,
		},
		{
			name:        "No passport number present",
			content:     "This is a regular text with no passport info",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content)

			if tt.expectMatch {
				if len(matches) == 0 {
					t.Fatalf("Expected match in %q, got none", tt.content)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %.2f, got %.2f", tt.minConfidence, matches[0].Confidence)
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("Expected no match in %q, got %d matches", tt.content, len(matches))
				}
			}
		})
	}
}

func TestPassportMatcher_Properties(t *testing.T) {
	m := NewPassportMatcher()

	if m.GetID() != "pii-passport" {
		t.Errorf("Expected ID 'pii-passport', got %q", m.GetID())
	}
	if m.GetType() != PatternTypePII {
		t.Errorf("Expected type PII, got %v", m.GetType())
	}
	if m.GetPIIType() != PIITypePassport {
		t.Errorf("Expected PII type passport, got %v", m.GetPIIType())
	}
	if m.GetSeverity() != SeverityHigh {
		t.Errorf("Expected severity High, got %v", m.GetSeverity())
	}
}

// ============================================================================
// Driver's License Matcher Tests
// ============================================================================

func TestDriversLicenseMatcher(t *testing.T) {
	m := NewDriversLicenseMatcher()

	tests := []struct {
		name          string
		content       string
		expectMatch   bool
		minConfidence float64
	}{
		{
			name:          "California format with context",
			content:       "Driver's License: A1234567 issued in California",
			expectMatch:   true,
			minConfidence: 0.70,
		},
		{
			name:          "NY format with DL keyword",
			content:       "DL: 123456789 from New York",
			expectMatch:   true,
			minConfidence: 0.70,
		},
		{
			name:          "With license keyword",
			content:       "license number D12345678 on file",
			expectMatch:   true,
			minConfidence: 0.70,
		},
		{
			name:        "No context keyword - should not match",
			content:     "The code is A1234567 for your reference",
			expectMatch: false,
		},
		{
			name:        "No license number present",
			content:     "No driver information here",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content)

			if tt.expectMatch {
				if len(matches) == 0 {
					t.Fatalf("Expected match in %q, got none", tt.content)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %.2f, got %.2f", tt.minConfidence, matches[0].Confidence)
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("Expected no match in %q, got %d matches", tt.content, len(matches))
				}
			}
		})
	}
}

func TestDriversLicenseMatcher_Properties(t *testing.T) {
	m := NewDriversLicenseMatcher()

	if m.GetID() != "pii-drivers-license" {
		t.Errorf("Expected ID 'pii-drivers-license', got %q", m.GetID())
	}
	if m.GetPIIType() != PIITypeDriversLicense {
		t.Errorf("Expected PII type drivers_license, got %v", m.GetPIIType())
	}
	if m.GetSeverity() != SeverityHigh {
		t.Errorf("Expected severity High, got %v", m.GetSeverity())
	}
}

// ============================================================================
// Address Matcher Tests
// ============================================================================

func TestAddressMatcher(t *testing.T) {
	m := NewAddressMatcher()

	tests := []struct {
		name          string
		content       string
		expectMatch   bool
		minConfidence float64
	}{
		{
			name:          "Standard US address with Street",
			content:       "Please ship to 123 Main Street in our city",
			expectMatch:   true,
			minConfidence: 0.60,
		},
		{
			name:          "Address with Avenue",
			content:       "Our office is at 456 Oak Avenue downtown",
			expectMatch:   true,
			minConfidence: 0.60,
		},
		{
			name:          "Address with Boulevard",
			content:       "Located at 789 Sunset Boulevard near the mall",
			expectMatch:   true,
			minConfidence: 0.60,
		},
		{
			name:          "Address with Drive",
			content:       "My home is 42 Elm Drive in the suburbs",
			expectMatch:   true,
			minConfidence: 0.60,
		},
		{
			name:        "Number only - no street suffix",
			content:     "The count is 123 items",
			expectMatch: false,
		},
		{
			name:        "No address present",
			content:     "This is just regular text without any address",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content)

			if tt.expectMatch {
				if len(matches) == 0 {
					t.Fatalf("Expected match in %q, got none", tt.content)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %.2f, got %.2f", tt.minConfidence, matches[0].Confidence)
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("Expected no match in %q, got %d matches", tt.content, len(matches))
				}
			}
		})
	}
}

func TestAddressMatcher_ConfidenceByLength(t *testing.T) {
	m := NewAddressMatcher()

	// Shorter address should have lower confidence than longer one
	shortAddr := "10 Elm St"
	longAddr := "1234 North Main Street Suite 100"

	shortScore := m.GetConfidenceScore(shortAddr)
	longScore := m.GetConfidenceScore(longAddr)

	if longScore <= shortScore {
		t.Errorf("Expected longer address to have higher confidence (%.2f) than shorter (%.2f)",
			longScore, shortScore)
	}
}

// ============================================================================
// Name Matcher Tests
// ============================================================================

func TestNameMatcher(t *testing.T) {
	m := NewNameMatcher()

	tests := []struct {
		name          string
		content       string
		expectMatch   bool
		minConfidence float64
	}{
		{
			name:          "With Name label",
			content:       "Name: John Smith is the applicant",
			expectMatch:   true,
			minConfidence: 0.65,
		},
		{
			name:          "With Patient label",
			content:       "Patient: Jane Doe was admitted yesterday",
			expectMatch:   true,
			minConfidence: 0.75,
		},
		{
			name:          "With Customer label",
			content:       "Customer: Alice Johnson placed an order",
			expectMatch:   true,
			minConfidence: 0.75,
		},
		{
			name:          "With Employee label",
			content:       "Employee: Bob Wilson started today",
			expectMatch:   true,
			minConfidence: 0.75,
		},
		{
			name:        "No label - should not match",
			content:     "John Smith walked into the office",
			expectMatch: false,
		},
		{
			name:          "Label with equals sign",
			content:       "user=Alice Johnson submitted a form",
			expectMatch:   true,
			minConfidence: 0.65,
		},
		{
			name:        "No name present",
			content:     "This is plain text without any personal names",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content)

			if tt.expectMatch {
				if len(matches) == 0 {
					t.Fatalf("Expected match in %q, got none", tt.content)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %.2f, got %.2f", tt.minConfidence, matches[0].Confidence)
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("Expected no match in %q, got %d matches", tt.content, len(matches))
				}
			}
		})
	}
}

func TestNameMatcher_Properties(t *testing.T) {
	m := NewNameMatcher()

	if m.GetID() != "pii-name" {
		t.Errorf("Expected ID 'pii-name', got %q", m.GetID())
	}
	if m.GetPIIType() != PIITypeName {
		t.Errorf("Expected PII type name, got %v", m.GetPIIType())
	}
	if m.GetSeverity() != SeverityLow {
		t.Errorf("Expected severity Low, got %v", m.GetSeverity())
	}
}

// ============================================================================
// Medical Record Matcher Tests
// ============================================================================

func TestMedicalRecordMatcher(t *testing.T) {
	m := NewMedicalRecordMatcher()

	tests := []struct {
		name          string
		content       string
		expectMatch   bool
		minConfidence float64
	}{
		{
			name:          "MRN format",
			content:       "MRN: 12345678 in the patient chart",
			expectMatch:   true,
			minConfidence: 0.95,
		},
		{
			name:          "Medical Record format",
			content:       "Medical Record Number: ABC12345 on file",
			expectMatch:   true,
			minConfidence: 0.90,
		},
		{
			name:          "MR# format",
			content:       "MR# 987654AB is the identifier",
			expectMatch:   true,
			minConfidence: 0.95,
		},
		{
			name:          "Med Rec format",
			content:       "Med Rec: XY123456 entered into system",
			expectMatch:   true,
			minConfidence: 0.90,
		},
		{
			name:        "No MRN label - should not match",
			content:     "The ID 12345678 is not a medical record",
			expectMatch: false,
		},
		{
			name:        "No medical record present",
			content:     "Regular text with no medical information",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content)

			if tt.expectMatch {
				if len(matches) == 0 {
					t.Fatalf("Expected match in %q, got none", tt.content)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %.2f, got %.2f", tt.minConfidence, matches[0].Confidence)
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("Expected no match in %q, got %d matches", tt.content, len(matches))
				}
			}
		})
	}
}

func TestMedicalRecordMatcher_Properties(t *testing.T) {
	m := NewMedicalRecordMatcher()

	if m.GetID() != "pii-mrn" {
		t.Errorf("Expected ID 'pii-mrn', got %q", m.GetID())
	}
	if m.GetPIIType() != PIITypeMedicalRecordNumber {
		t.Errorf("Expected PII type medical_record_number, got %v", m.GetPIIType())
	}
	if m.GetSeverity() != SeverityCritical {
		t.Errorf("Expected severity Critical, got %v", m.GetSeverity())
	}
}

// ============================================================================
// Framework Classification Integration Tests
// ============================================================================

func TestExtendedMatchers_FrameworkClassification(t *testing.T) {
	scanner := NewScanner()

	t.Run("Medical record triggers HIPAA", func(t *testing.T) {
		content := "Patient has MRN: 12345678 in the healthcare system"
		config := DefaultScanConfig()
		config.ClassificationHints = ClassificationContext{
			IsHealthcare: true,
		}

		result, err := scanner.ScanString(context.TODO(), content, config)
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}

		foundMRN := false
		foundHIPAA := false
		for _, f := range result.Findings {
			if f.PIIType == PIITypeMedicalRecordNumber {
				foundMRN = true
				for _, fw := range f.Frameworks {
					if fw.Framework == FrameworkHIPAA {
						foundHIPAA = true
					}
				}
			}
		}

		if !foundMRN {
			t.Error("Expected to find medical record number")
		}
		if !foundHIPAA {
			t.Error("Expected medical record to trigger HIPAA framework")
		}
	})

	t.Run("Passport triggers GDPR in EU context", func(t *testing.T) {
		// Use passport keyword to ensure high confidence match
		content := "Passport number AB123456789 for the EU traveler"
		config := DefaultScanConfig()
		config.ClassificationHints = ClassificationContext{
			IsEUData: true,
			Hints:    []string{"european"},
		}

		result, err := scanner.ScanString(context.TODO(), content, config)
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}

		foundPassport := false
		foundGDPR := false
		for _, f := range result.Findings {
			if f.PIIType == PIITypePassport {
				foundPassport = true
				for _, fw := range f.Frameworks {
					if fw.Framework == FrameworkGDPR {
						foundGDPR = true
					}
				}
			}
		}

		if !foundPassport {
			t.Error("Expected to find passport number")
		}
		if !foundGDPR {
			t.Error("Expected passport in EU context to trigger GDPR framework")
		}
	})

	t.Run("Name triggers HIPAA in healthcare context", func(t *testing.T) {
		content := "Patient: Jane Doe is scheduled for appointment"
		config := DefaultScanConfig()
		config.ClassificationHints = ClassificationContext{
			IsHealthcare: true,
		}

		result, err := scanner.ScanString(context.TODO(), content, config)
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}

		foundName := false
		foundHIPAA := false
		for _, f := range result.Findings {
			if f.PIIType == PIITypeName {
				foundName = true
				for _, fw := range f.Frameworks {
					if fw.Framework == FrameworkHIPAA {
						foundHIPAA = true
					}
				}
			}
		}

		if !foundName {
			t.Error("Expected to find name")
		}
		if !foundHIPAA {
			t.Error("Expected name in healthcare context to trigger HIPAA framework")
		}
	})
}

// ============================================================================
// Extended Matchers in Registry
// ============================================================================

func TestExtendedMatchers_InRegistry(t *testing.T) {
	registry := NewDefaultRegistry()

	matchers := []struct {
		id      string
		piiType PIIType
	}{
		{"pii-passport", PIITypePassport},
		{"pii-drivers-license", PIITypeDriversLicense},
		{"pii-address", PIITypeAddress},
		{"pii-name", PIITypeName},
		{"pii-mrn", PIITypeMedicalRecordNumber},
	}

	for _, m := range matchers {
		t.Run(m.id, func(t *testing.T) {
			matcher, found := registry.Get(m.id)
			if !found {
				t.Fatalf("Matcher %q not found in registry", m.id)
			}
			if matcher.GetPIIType() != m.piiType {
				t.Errorf("Expected PII type %v, got %v", m.piiType, matcher.GetPIIType())
			}
		})
	}
}
