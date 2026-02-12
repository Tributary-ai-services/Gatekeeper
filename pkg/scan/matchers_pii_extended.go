package scan

import (
	"regexp"
	"strings"
)

// PassportMatcher detects passport numbers
type PassportMatcher struct {
	baseMatcher
	contextPattern *regexp.Regexp
}

// NewPassportMatcher creates a new passport matcher
func NewPassportMatcher() *PassportMatcher {
	return &PassportMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-passport",
			name:        "Passport Number",
			patternType: PatternTypePII,
			piiType:     PIITypePassport,
			severity:    SeverityHigh,
			riskBase:    0.8,
			pattern:     regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`),
			description: "Detects passport numbers in common formats",
		},
		contextPattern: regexp.MustCompile(`(?i)passport`),
	}
}

// Match finds all passport number matches in content
func (m *PassportMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Enhance matches with context-aware confidence
	enhancedMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		// Check for "passport" keyword nearby (within the context window)
		if m.contextPattern.MatchString(match.Context) {
			match.Confidence = 0.95
		} else {
			match.Confidence = 0.70
		}
		enhancedMatches = append(enhancedMatches, match)
	}

	return enhancedMatches
}

// GetConfidenceScore returns confidence based on context
func (m *PassportMatcher) GetConfidenceScore(match string) float64 {
	// When called with just the match value, check if the match itself
	// contains a passport keyword hint
	if m.contextPattern.MatchString(match) {
		return 0.95
	}
	return 0.70
}

// DriversLicenseMatcher detects driver's license numbers
type DriversLicenseMatcher struct {
	baseMatcher
	statePatterns  []*regexp.Regexp
	contextPattern *regexp.Regexp
}

// NewDriversLicenseMatcher creates a new driver's license matcher
func NewDriversLicenseMatcher() *DriversLicenseMatcher {
	return &DriversLicenseMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-drivers-license",
			name:        "Driver's License Number",
			patternType: PatternTypePII,
			piiType:     PIITypeDriversLicense,
			severity:    SeverityHigh,
			riskBase:    0.8,
			// Generic pattern: letter followed by digits (covers most states)
			pattern:     regexp.MustCompile(`\b(?:[A-Z][0-9]{7}|[0-9]{9}|[0-9]{8}|[A-Z][0-9]{12}|[A-Z][0-9]{5,14})\b`),
			description: "Detects driver's license numbers in various state formats",
		},
		statePatterns: []*regexp.Regexp{
			regexp.MustCompile(`\b[A-Z][0-9]{7}\b`),  // CA format
			regexp.MustCompile(`\b[0-9]{9}\b`),        // NY format
			regexp.MustCompile(`\b[0-9]{8}\b`),        // TX format
			regexp.MustCompile(`\b[A-Z][0-9]{12}\b`),  // FL format
		},
		contextPattern: regexp.MustCompile(`(?i)(?:license|licence|dl\b|driver)`),
	}
}

// Match finds all driver's license matches in content
func (m *DriversLicenseMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Only return matches where a context keyword is found nearby
	// to avoid massive false positives from generic alphanumeric sequences
	validMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		if m.contextPattern.MatchString(match.Context) {
			match.Confidence = m.computeConfidence(match.Value, match.Context)
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// computeConfidence determines confidence based on pattern specificity and context
func (m *DriversLicenseMatcher) computeConfidence(value, context string) float64 {
	// Check for state-specific pattern matches (higher confidence)
	for _, sp := range m.statePatterns {
		if sp.MatchString(value) {
			return 0.90
		}
	}
	return 0.70
}

// GetConfidenceScore returns confidence based on format
func (m *DriversLicenseMatcher) GetConfidenceScore(match string) float64 {
	// Check state-specific formats
	for _, sp := range m.statePatterns {
		if sp.MatchString(match) {
			return 0.90
		}
	}
	return 0.70
}

// AddressMatcher detects US street addresses
type AddressMatcher struct {
	baseMatcher
}

// NewAddressMatcher creates a new address matcher
func NewAddressMatcher() *AddressMatcher {
	return &AddressMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-address",
			name:        "Street Address",
			patternType: PatternTypePII,
			piiType:     PIITypeAddress,
			severity:    SeverityMedium,
			riskBase:    0.5,
			pattern: regexp.MustCompile(
				`(?i)\b\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+` +
					`(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Rd|Road|Ln|Lane|Way|Ct|Court|Pl|Place|Cir|Circle)\b`,
			),
			description: "Detects US street addresses",
		},
	}
}

// Match finds all address matches in content
func (m *AddressMatcher) Match(content string) []Match {
	matches := m.findAllMatches(content, 50)

	// Assign confidence based on address completeness
	enhancedMatches := make([]Match, 0, len(matches))
	for _, match := range matches {
		match.Confidence = m.computeAddressConfidence(match.Value)
		enhancedMatches = append(enhancedMatches, match)
	}

	return enhancedMatches
}

// computeAddressConfidence scores based on address completeness
func (m *AddressMatcher) computeAddressConfidence(value string) float64 {
	// Count word parts to estimate completeness
	parts := strings.Fields(value)
	if len(parts) >= 5 {
		return 0.85
	}
	if len(parts) >= 4 {
		return 0.75
	}
	return 0.60
}

// GetConfidenceScore returns confidence based on address format
func (m *AddressMatcher) GetConfidenceScore(match string) float64 {
	return m.computeAddressConfidence(match)
}

// NameMatcher detects personal names preceded by contextual labels
type NameMatcher struct {
	baseMatcher
}

// NewNameMatcher creates a new name matcher
func NewNameMatcher() *NameMatcher {
	return &NameMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-name",
			name:        "Personal Name",
			patternType: PatternTypePII,
			piiType:     PIITypeName,
			severity:    SeverityLow,
			riskBase:    0.3,
			pattern: regexp.MustCompile(
				`(?i)(?:name|patient|customer|employee|user|contact|person|client)\s*[:=]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)`,
			),
			description: "Detects personal names preceded by contextual labels",
		},
	}
}

// Match finds all name matches in content
func (m *NameMatcher) Match(content string) []Match {
	if m.pattern == nil {
		return nil
	}

	var matches []Match
	// Use FindAllStringSubmatchIndex to extract the name portion (capture group 1)
	indices := m.pattern.FindAllStringSubmatchIndex(content, -1)

	for _, idx := range indices {
		// idx[0], idx[1] = full match
		// idx[2], idx[3] = first capture group (the name)
		fullStart, fullEnd := idx[0], idx[1]
		fullValue := content[fullStart:fullEnd]
		context := extractContext(content, fullStart, fullEnd, 50)

		confidence := m.computeNameConfidence(fullValue)

		matches = append(matches, Match{
			Value:      fullValue,
			StartPos:   fullStart,
			EndPos:     fullEnd,
			Context:    context,
			Confidence: confidence,
		})
	}

	return matches
}

// computeNameConfidence scores based on the label and name structure
func (m *NameMatcher) computeNameConfidence(value string) float64 {
	lower := strings.ToLower(value)

	// Stronger labels indicate higher confidence
	highConfLabels := []string{"patient", "customer", "employee"}
	for _, label := range highConfLabels {
		if strings.HasPrefix(lower, label) {
			return 0.80
		}
	}

	// Standard labels
	if strings.HasPrefix(lower, "name") ||
		strings.HasPrefix(lower, "user") ||
		strings.HasPrefix(lower, "contact") ||
		strings.HasPrefix(lower, "person") ||
		strings.HasPrefix(lower, "client") {
		return 0.75
	}

	return 0.65
}

// GetConfidenceScore returns confidence based on name format
func (m *NameMatcher) GetConfidenceScore(match string) float64 {
	return m.computeNameConfidence(match)
}

// MedicalRecordMatcher detects medical record numbers
type MedicalRecordMatcher struct {
	baseMatcher
}

// NewMedicalRecordMatcher creates a new medical record number matcher
func NewMedicalRecordMatcher() *MedicalRecordMatcher {
	return &MedicalRecordMatcher{
		baseMatcher: baseMatcher{
			id:          "pii-mrn",
			name:        "Medical Record Number",
			patternType: PatternTypePII,
			piiType:     PIITypeMedicalRecordNumber,
			severity:    SeverityCritical,
			riskBase:    0.95,
			pattern: regexp.MustCompile(
				`(?i)(?:MRN|MR#|Medical\s*Record|Med\s*Rec)[\s#:]*([A-Z0-9]{6,12})`,
			),
			description: "Detects medical record numbers with explicit labels",
		},
	}
}

// Match finds all medical record number matches in content
func (m *MedicalRecordMatcher) Match(content string) []Match {
	if m.pattern == nil {
		return nil
	}

	var matches []Match
	indices := m.pattern.FindAllStringSubmatchIndex(content, -1)

	for _, idx := range indices {
		// idx[0], idx[1] = full match
		fullStart, fullEnd := idx[0], idx[1]
		fullValue := content[fullStart:fullEnd]
		context := extractContext(content, fullStart, fullEnd, 50)

		confidence := m.computeMRNConfidence(fullValue)

		matches = append(matches, Match{
			Value:      fullValue,
			StartPos:   fullStart,
			EndPos:     fullEnd,
			Context:    context,
			Confidence: confidence,
		})
	}

	return matches
}

// computeMRNConfidence scores based on the label specificity
func (m *MedicalRecordMatcher) computeMRNConfidence(value string) float64 {
	lower := strings.ToLower(value)

	// Explicit MRN prefix is strongest signal
	if strings.HasPrefix(lower, "mrn") || strings.HasPrefix(lower, "mr#") {
		return 0.98
	}

	// Full "medical record" label
	if strings.HasPrefix(lower, "medical") || strings.HasPrefix(lower, "med rec") {
		return 0.95
	}

	return 0.90
}

// GetConfidenceScore returns confidence based on MRN format
func (m *MedicalRecordMatcher) GetConfidenceScore(match string) float64 {
	return m.computeMRNConfidence(match)
}
