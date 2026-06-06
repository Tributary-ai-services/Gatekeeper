// AIQG-specific quality matchers. These don't classify PII or
// detect classical injection attacks — they flag patterns that
// matter for the AI Quality Gateway's CLEAR Assurance dimension:
//
//   * Bloated RAG-style context that wastes input tokens
//   * Subtle role-claim injection that softer than the existing
//     prompt-injection matcher catches
//   * Model refusal / hedging in outbound responses
//
// All three are Custom-type matchers (not Injection) so they share
// shelf space with future AIQG-specific signals without overloading
// the security-focused Injection category. Severity caps at Medium
// because none of these are policy violations per se — they degrade
// quality scores but shouldn't auto-block traffic.
package scan

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------
// Bloated context
// ---------------------------------------------------------------------

// AIQGBloatedContextMatcher flags inbound payloads that look like
// over-injected RAG context — many "Document N:" / "Context:" /
// "Source:" separators plus a length over the threshold. The
// composite signal is more reliable than either heuristic alone:
// long prompts are fine for code-gen, many separators are fine
// for tool catalogs, but both together is the cost-burning RAG
// anti-pattern AIQG wants to call out.
type AIQGBloatedContextMatcher struct {
	baseMatcher
	separatorPattern *regexp.Regexp
}

// NewAIQGBloatedContextMatcher constructs the bloated-context matcher.
func NewAIQGBloatedContextMatcher() *AIQGBloatedContextMatcher {
	m := &AIQGBloatedContextMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-bloated-context",
			name:        "AIQG Bloated Context",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.40,
			description: "Long prompt with multiple context-block separators — typical RAG context bloat",
		},
		// Recognized separators: "Document 1:", "Context:", "Source:",
		// "Chunk 3:", "Passage 2:", "Reference:". Case-insensitive.
		separatorPattern: regexp.MustCompile(`(?i)\b(document|context|source|chunk|passage|reference)(\s*#?\s*\d+)?\s*:`),
	}
	m.pattern = m.separatorPattern
	return m
}

// Bloated-context thresholds. Conservative — production RAG with
// reasonable retrieval still passes when context is under 6k chars
// or has fewer than 3 separators.
const (
	bloatedContextMinChars      = 6000
	bloatedContextMinSeparators = 3
)

func (m *AIQGBloatedContextMatcher) Match(content string) []Match {
	if len(content) < bloatedContextMinChars {
		return nil
	}
	hits := m.separatorPattern.FindAllStringIndex(content, -1)
	if len(hits) < bloatedContextMinSeparators {
		return nil
	}
	// Single finding per request — the whole content IS the violation,
	// not each individual separator. Cap the value preview at 120 chars
	// so logs don't carry the full prompt.
	preview := content[:120]
	return []Match{{
		Value:    preview,
		StartPos: 0,
		EndPos:   len(content),
		Context:  preview,
	}}
}

// GetConfidenceScore reflects how strongly the pattern indicates
// bloat. Sliding scale: more separators = higher confidence.
func (m *AIQGBloatedContextMatcher) GetConfidenceScore(match string) float64 {
	seps := len(m.separatorPattern.FindAllString(match, -1))
	switch {
	case seps >= 10:
		return 0.95
	case seps >= 6:
		return 0.85
	case seps >= 4:
		return 0.75
	default:
		return 0.65
	}
}

// ---------------------------------------------------------------------
// Role claim — softer prompt injection
// ---------------------------------------------------------------------

// AIQGRoleClaimMatcher catches subtle role-manipulation phrases the
// existing PromptInjection matcher's tighter regex doesn't pick up
// (e.g. "from now on", "consider yourself", "treat this as"). These
// don't always indicate malicious intent — sometimes they're a
// legitimate system-prompt rewrite — but they're worth flagging for
// CLEAR Assurance because the model's behavior may diverge from its
// trained role.
type AIQGRoleClaimMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGRoleClaimMatcher constructs the role-claim matcher.
func NewAIQGRoleClaimMatcher() *AIQGRoleClaimMatcher {
	return &AIQGRoleClaimMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-role-claim",
			name:        "AIQG Role Claim",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityMedium,
			riskBase:    0.55,
			description: "Soft role-manipulation phrasing (subset of prompt injection that the security matcher misses)",
		},
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bfrom\s+now\s+on\b`),
			regexp.MustCompile(`(?i)\bconsider\s+yourself\b`),
			regexp.MustCompile(`(?i)\btreat\s+this\s+as\b`),
			regexp.MustCompile(`(?i)\byour\s+new\s+(?:role|persona|character|task)\b`),
			regexp.MustCompile(`(?i)\bfor\s+this\s+(?:conversation|task|request),?\s+(?:assume|pretend|imagine)\b`),
		},
	}
}

func (m *AIQGRoleClaimMatcher) Match(content string) []Match {
	var out []Match
	for _, p := range m.patterns {
		for _, idx := range p.FindAllStringIndex(content, -1) {
			out = append(out, Match{
				Value:    content[idx[0]:idx[1]],
				StartPos: idx[0],
				EndPos:   idx[1],
				Context:  extractContext(content, idx[0], idx[1], 80),
			})
		}
	}
	return out
}

func (m *AIQGRoleClaimMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	// "your new role" is unambiguous; "from now on" can be benign
	// (recipe instructions, etc.) so confidence is lower.
	if strings.Contains(lower, "new role") || strings.Contains(lower, "new persona") {
		return 0.85
	}
	return 0.65
}

// ---------------------------------------------------------------------
// Outbound refusal / hedging
// ---------------------------------------------------------------------

// AIQGRefusalMatcher detects model refusal phrasing in outbound
// responses. A refusal isn't always a quality failure — some refusals
// are correct safety responses — but the refusal rate is a number
// AIQG users want to track. Drives the Efficacy + Assurance signal
// on outbound scans.
type AIQGRefusalMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGRefusalMatcher constructs the refusal matcher.
func NewAIQGRefusalMatcher() *AIQGRefusalMatcher {
	return &AIQGRefusalMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-refusal",
			name:        "AIQG Refusal / Hedging",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.35,
			description: "Model refused or hedged — useful to track refusal rate; not a hard failure",
		},
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bI\s+cannot\s+(?:help|assist|provide|answer|comply|do\s+that)\b`),
			regexp.MustCompile(`(?i)\bI('?m| am)\s+(?:unable|not\s+able)\s+to\b`),
			regexp.MustCompile(`(?i)\bI\s+don'?t\s+have\s+(?:the\s+)?(?:ability|permission|access)\s+to\b`),
			regexp.MustCompile(`(?i)\bI('?m| am)\s+(?:just\s+)?an?\s+AI\b`),
			regexp.MustCompile(`(?i)\bas\s+an?\s+(?:AI|language\s+model|assistant)\b`),
			regexp.MustCompile(`(?i)\bagainst\s+my\s+(?:guidelines|principles|training)\b`),
		},
	}
}

func (m *AIQGRefusalMatcher) Match(content string) []Match {
	var out []Match
	for _, p := range m.patterns {
		for _, idx := range p.FindAllStringIndex(content, -1) {
			out = append(out, Match{
				Value:    content[idx[0]:idx[1]],
				StartPos: idx[0],
				EndPos:   idx[1],
				Context:  extractContext(content, idx[0], idx[1], 80),
			})
		}
	}
	return out
}

func (m *AIQGRefusalMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	// "against my guidelines" is high signal; "as an AI" can be a
	// benign self-reference.
	if strings.Contains(lower, "against my") {
		return 0.90
	}
	if strings.Contains(lower, "cannot") || strings.Contains(lower, "unable") {
		return 0.80
	}
	return 0.55
}
