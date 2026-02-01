package scan

import (
	"regexp"
)

// baseMatcher provides common functionality for pattern matchers
type baseMatcher struct {
	id          string
	name        string
	patternType PatternType
	piiType     PIIType
	severity    Severity
	riskBase    float64
	pattern     *regexp.Regexp
	description string
}

// GetID returns the pattern identifier
func (m *baseMatcher) GetID() string {
	return m.id
}

// GetName returns the human-readable pattern name
func (m *baseMatcher) GetName() string {
	return m.name
}

// GetType returns the pattern type
func (m *baseMatcher) GetType() PatternType {
	return m.patternType
}

// GetPIIType returns the PII type if applicable
func (m *baseMatcher) GetPIIType() PIIType {
	return m.piiType
}

// GetRiskBase returns the base risk score
func (m *baseMatcher) GetRiskBase() float64 {
	return m.riskBase
}

// GetSeverity returns the default severity
func (m *baseMatcher) GetSeverity() Severity {
	return m.severity
}

// IsEnabled checks if this matcher should be used given the config
func (m *baseMatcher) IsEnabled(config *ScanConfig) bool {
	if config == nil {
		return true
	}

	// Check profile restrictions
	switch config.Profile {
	case ProfilePIIOnly:
		if m.patternType != PatternTypePII && m.patternType != PatternTypeCredential {
			return false
		}
	case ProfileInjectionOnly:
		if m.patternType != PatternTypeInjection {
			return false
		}
	case ProfileCompliance:
		// All patterns relevant to compliance
	case ProfileFull:
		// All patterns enabled
	}

	// Check if explicitly disabled
	for _, disabled := range config.DisabledPatterns {
		if disabled == m.piiType {
			return false
		}
	}

	// If enabled patterns is specified, check if included
	if len(config.EnabledPatterns) > 0 {
		for _, enabled := range config.EnabledPatterns {
			if enabled == m.piiType {
				return true
			}
		}
		// PII type not in enabled list, but might be injection
		if m.patternType == PatternTypeInjection {
			return true // Injection patterns always enabled unless profile restricts
		}
		return false
	}

	return true
}

// findAllMatches finds all regex matches and returns Match structs
func (m *baseMatcher) findAllMatches(content string, contextWindow int) []Match {
	if m.pattern == nil {
		return nil
	}

	var matches []Match
	indices := m.pattern.FindAllStringIndex(content, -1)

	for _, idx := range indices {
		start, end := idx[0], idx[1]
		value := content[start:end]
		context := extractContext(content, start, end, contextWindow)

		matches = append(matches, Match{
			Value:    value,
			StartPos: start,
			EndPos:   end,
			Context:  context,
		})
	}

	return matches
}

// extractContext extracts surrounding context for a match
func extractContext(content string, start, end, windowSize int) string {
	contextStart := start - windowSize
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := end + windowSize
	if contextEnd > len(content) {
		contextEnd = len(content)
	}

	return content[contextStart:contextEnd]
}
