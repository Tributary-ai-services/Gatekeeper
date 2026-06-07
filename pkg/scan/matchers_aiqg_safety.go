// Safety / policy matchers — populate the NIST AI RMF "Safe"
// characteristic on the AIQG Trustworthiness panel. All three are
// inbound-focused (catch user prompts requesting unsafe outputs)
// and tuned for HIGH PRECISION over recall. False positives on
// benign queries would erode trust in the Safe metric, so each
// regex is anchored to specific phrasings rather than broad
// keyword matching.
//
// Severity tiers reflect product policy, not technical danger:
//   - Low:    advisory ("this looks like a soft attempt")
//   - Medium: review-worthy ("flag for analyst")
//   - High:   policy violation ("explicit attack signal")
//
// None of these matchers BLOCK requests — they only contribute
// scoring signal. Hard blocking is a separate, higher-stakes
// decision left to the Gatekeeper actions engine.
package scan

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------
// Harm request
// ---------------------------------------------------------------------

// AIQGHarmRequestMatcher catches explicit requests for harm or
// weapons instructions. Patterns are deliberately narrow — e.g.
// "how to make a bomb" (specific) rather than just "bomb" (way too
// broad, fires on benign discussion of historical events).
type AIQGHarmRequestMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGHarmRequestMatcher constructs the harm-request matcher.
func NewAIQGHarmRequestMatcher() *AIQGHarmRequestMatcher {
	return &AIQGHarmRequestMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-harm-request",
			name:        "AIQG Harm Request",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityMedium,
			riskBase:    0.70,
			description: "Explicit request for harm or weapons-construction instructions",
		},
		patterns: []*regexp.Regexp{
			// Weapons construction — anchored to "how to/instructions"
			// + verb + indefinite article + weapon noun. Avoids firing
			// on historical/factual discussion ("the bomb dropped on…").
			regexp.MustCompile(`(?i)\bhow\s+(?:to|do\s+I|can\s+I)\s+(?:make|build|create|construct|assemble|synthesi[sz]e)\s+(?:a\s+|an\s+)?(?:bomb|explosive|nerve\s+agent|chemical\s+weapon|biological\s+weapon|firearm|silencer)\b`),
			regexp.MustCompile(`(?i)\b(?:instructions|recipe|steps)\s+(?:for|to)\s+(?:making|building|creating|synthesi[sz]ing)\s+(?:a\s+|an\s+)?(?:bomb|explosive|nerve\s+agent|chemical\s+weapon|biological\s+weapon)\b`),

			// Self-harm / suicide instruction asks. Note: legitimate
			// crisis-support conversations should be handled by the
			// model + safety layer; this matcher flags the prompt for
			// analyst review, not blocking.
			regexp.MustCompile(`(?i)\bhow\s+(?:to|do\s+I|can\s+I)\s+(?:kill|harm|hurt)\s+(?:myself|my\s*self)\b`),
			regexp.MustCompile(`(?i)\b(?:methods|ways|steps)\s+(?:to|for)\s+(?:suicide|self[\s-]?harm)\b`),

			// Targeted harm against named entities — "how to kill X"
			// where X is a person/entity (rough heuristic via verb +
			// object). False-positive risk on fiction; mitigated by
			// Medium severity, not High.
			regexp.MustCompile(`(?i)\bhow\s+(?:to|do\s+I|can\s+I)\s+(?:kill|murder|poison|stab|shoot)\s+(?:a\s+|an\s+|the\s+)?(?:person|child|teacher|coworker)\b`),
		},
	}
}

func (m *AIQGHarmRequestMatcher) Match(content string) []Match {
	return aiqgRunPatterns(m.patterns, content)
}

func (m *AIQGHarmRequestMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	if strings.Contains(lower, "bomb") || strings.Contains(lower, "weapon") ||
		strings.Contains(lower, "agent") || strings.Contains(lower, "explosive") {
		return 0.90
	}
	if strings.Contains(lower, "suicide") || strings.Contains(lower, "self") {
		return 0.85
	}
	return 0.75
}

// ---------------------------------------------------------------------
// Credential / system-prompt solicitation
// ---------------------------------------------------------------------

// AIQGCredentialSolicitationMatcher catches softer prompt-injection
// patterns the existing injection-prompt matcher doesn't always hit:
// requests to leak secrets, expose the system prompt, or reveal
// internal configuration. Distinct from `aiqg-role-claim` (which is
// about overriding behavior) — this is about exfiltration.
type AIQGCredentialSolicitationMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGCredentialSolicitationMatcher constructs the solicitation matcher.
func NewAIQGCredentialSolicitationMatcher() *AIQGCredentialSolicitationMatcher {
	return &AIQGCredentialSolicitationMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-credential-solicitation",
			name:        "AIQG Credential / Secret Solicitation",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityMedium,
			riskBase:    0.60,
			description: "Prompt asks the model to expose secrets, credentials, or its own system prompt",
		},
		patterns: []*regexp.Regexp{
			// Direct credential requests
			regexp.MustCompile(`(?i)\b(?:tell|show|give|reveal|share)\s+me\s+(?:the\s+|your\s+)?(?:api\s+key|password|secret|credentials|access\s+token|auth\s+token|private\s+key)\b`),
			regexp.MustCompile(`(?i)\bwhat(?:'s|\s+is)\s+(?:the\s+|your\s+)?(?:api\s+key|password|secret|credentials|access\s+token)\b`),

			// System-prompt extraction — beyond what injection-prompt
			// catches. Includes softer phrasings.
			regexp.MustCompile(`(?i)\b(?:show|reveal|share|repeat|print)\s+(?:me\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+prompt|developer\s+message)\b`),
			regexp.MustCompile(`(?i)\bwhat(?:'s|\s+is)\s+(?:in\s+)?your\s+(?:system\s+prompt|initial\s+instructions|developer\s+message|hidden\s+prompt)\b`),
			regexp.MustCompile(`(?i)\bcan\s+you\s+(?:show|tell|reveal|share)\s+(?:me\s+)?(?:your\s+)?(?:system\s+prompt|instructions|guidelines|rules)\b`),
		},
	}
}

func (m *AIQGCredentialSolicitationMatcher) Match(content string) []Match {
	return aiqgRunPatterns(m.patterns, content)
}

func (m *AIQGCredentialSolicitationMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	if strings.Contains(lower, "api key") || strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "credentials") ||
		strings.Contains(lower, "private key") {
		return 0.90
	}
	return 0.75
}

// ---------------------------------------------------------------------
// Explicit jailbreak
// ---------------------------------------------------------------------

// AIQGExplicitJailbreakMatcher catches well-known jailbreak markers
// the existing injection-prompt matcher misses. High severity
// because these are unambiguous attack signals — no legitimate use
// case for asking a model to enter "DAN mode" or disable safety.
type AIQGExplicitJailbreakMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGExplicitJailbreakMatcher constructs the jailbreak matcher.
func NewAIQGExplicitJailbreakMatcher() *AIQGExplicitJailbreakMatcher {
	return &AIQGExplicitJailbreakMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-explicit-jailbreak",
			name:        "AIQG Explicit Jailbreak",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityHigh,
			riskBase:    0.85,
			description: "Known jailbreak phrasing (DAN/Sydney/developer mode, disable safety)",
		},
		patterns: []*regexp.Regexp{
			// Named jailbreak personas
			regexp.MustCompile(`(?i)\b(?:enter|activate|switch\s+to|enable)\s+(?:DAN|Sydney|developer|god|admin|unrestricted)\s+mode\b`),
			regexp.MustCompile(`(?i)\bDAN\s+(?:mode|persona|prompt)\b`),

			// Explicit safety / guideline disablement
			regexp.MustCompile(`(?i)\b(?:disable|bypass|ignore|turn\s+off|override)\s+(?:your\s+|all\s+|the\s+)?(?:safety|safeguards?|safety\s+(?:filters?|protocols?|guidelines?|measures?)|content\s+(?:filter|policy)|ethical\s+guidelines?)\b`),
			regexp.MustCompile(`(?i)\bpretend\s+(?:that\s+)?(?:safety|guidelines?|restrictions?|filters?|rules?)\s+(?:are|don'?t)\s+(?:disabled|removed|exist|apply)\b`),
			regexp.MustCompile(`(?i)\bact\s+as\s+(?:if\s+)?(?:you\s+have\s+no|without)\s+(?:safety|restrictions?|guidelines?|content\s+policy|ethics?)\b`),

			// "Do anything now" family
			regexp.MustCompile(`(?i)\byou\s+can\s+(?:now\s+)?do\s+anything\s+now\b`),
			regexp.MustCompile(`(?i)\bdo\s+anything\s+now\s+(?:mode|persona|prompt)?\b`),
		},
	}
}

func (m *AIQGExplicitJailbreakMatcher) Match(content string) []Match {
	return aiqgRunPatterns(m.patterns, content)
}

func (m *AIQGExplicitJailbreakMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	if strings.Contains(lower, "dan") || strings.Contains(lower, "sydney") ||
		strings.Contains(lower, "developer mode") || strings.Contains(lower, "god mode") ||
		strings.Contains(lower, "admin mode") {
		return 0.95
	}
	if strings.Contains(lower, "disable") || strings.Contains(lower, "bypass") ||
		strings.Contains(lower, "ignore") {
		return 0.85
	}
	return 0.75
}

// ---------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------

// aiqgRunPatterns is the common Match() body — run every regex,
// collect every hit, attach 80-char context. Reduces duplication
// across the three safety matchers above.
func aiqgRunPatterns(patterns []*regexp.Regexp, content string) []Match {
	var out []Match
	for _, p := range patterns {
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
