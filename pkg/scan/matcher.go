package scan

import (
	"regexp"
	"strings"
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

// GetPatternDescriptors returns a single descriptor from the baseMatcher's pattern.
func (m *baseMatcher) GetPatternDescriptors() []PatternDescriptor {
	if m.pattern == nil {
		return nil
	}
	expr := m.pattern.String()
	caseSensitive := true
	dotAll := false
	// Detect and strip inline flags for engine use
	if strings.HasPrefix(expr, "(?") {
		end := strings.Index(expr, ")")
		if end != -1 {
			flags := expr[2:end]
			for _, c := range flags {
				switch c {
				case 'i':
					caseSensitive = false
				case 's':
					dotAll = true
				}
			}
		}
	}
	return []PatternDescriptor{{
		MatcherID:     m.id,
		PatternIndex:  0,
		Expression:    expr,
		CaseSensitive: caseSensitive,
		DotAll:        dotAll,
	}}
}

// ValidateMatches provides a default implementation that converts raw hits to matches.
func (m *baseMatcher) ValidateMatches(content string, rawHits []RawMatch, contextWindow int) []Match {
	return rawHitsToMatches(content, rawHits, contextWindow)
}

// rawHitsToMatches converts RawMatch slices into Match slices with context extraction.
func rawHitsToMatches(content string, rawHits []RawMatch, contextWindow int) []Match {
	if contextWindow <= 0 {
		contextWindow = 50
	}
	matches := make([]Match, 0, len(rawHits))
	for _, hit := range rawHits {
		if hit.Start < 0 || hit.End > len(content) || hit.Start >= hit.End {
			continue
		}
		value := content[hit.Start:hit.End]
		ctx := extractContext(content, hit.Start, hit.End, contextWindow)
		matches = append(matches, Match{
			Value:    value,
			StartPos: hit.Start,
			EndPos:   hit.End,
			Context:  ctx,
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
