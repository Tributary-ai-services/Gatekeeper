// Additional inbound AIQG matchers — input-quality antipatterns
// that degrade output reliability. Complement the existing
// bloated-context (RAG) and role-claim (soft injection) matchers
// in matchers_aiqg.go.
//
// All three map to NIST AI RMF "Valid & Reliable" in the
// tas-llm-router classifier: vague / overloaded / unbounded prompts
// produce unreliable or unverifiable outputs, regardless of intent.
package scan

import (
	"regexp"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------
// Vague prompt
// ---------------------------------------------------------------------

// AIQGVaguePromptMatcher flags ultra-short fragmented prompts that
// can't possibly yield a useful response without prior context.
// Examples: "do it", "more please", "continue", "again", "fix this".
//
// False-positive risk: these phrases ARE valid in multi-turn
// conversations where prior context establishes intent. The matcher
// only sees one message at a time, so it'll fire on legitimate
// follow-ups too. Severity is Low because the cost of a false
// flag is small (just an extra finding in the report), and the
// signal is genuinely useful for spotting bot-traffic or broken
// integrations that emit naked fragments.
type AIQGVaguePromptMatcher struct {
	baseMatcher
}

// NewAIQGVaguePromptMatcher constructs the vague-prompt matcher.
func NewAIQGVaguePromptMatcher() *AIQGVaguePromptMatcher {
	return &AIQGVaguePromptMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-vague-prompt",
			name:        "AIQG Vague Prompt",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.35,
			description: "Ultra-short fragment that lacks the context to yield a useful response",
		},
	}
}

// vagueFragments are exact normalized phrases that, when they're
// the WHOLE user message, signal a fragment. Each is short enough
// that it can't carry standalone intent.
var vagueFragments = map[string]struct{}{
	"do it":           {},
	"do that":         {},
	"more":            {},
	"more please":     {},
	"continue":        {},
	"continue please": {},
	"keep going":      {},
	"again":           {},
	"again please":    {},
	"fix it":          {},
	"fix this":        {},
	"help":            {},
	"help me":         {},
	"go":              {},
	"go on":           {},
	"next":            {},
	"redo":            {},
	"retry":           {},
}

func (m *AIQGVaguePromptMatcher) Match(content string) []Match {
	// Normalize: strip leading/trailing whitespace + trailing punctuation,
	// lowercase, collapse internal whitespace.
	norm := normalizeVaguePrompt(content)
	if _, ok := vagueFragments[norm]; !ok {
		return nil
	}
	// Single finding spanning the whole input — the value IS the
	// violation, not a substring within it.
	return []Match{{
		Value:    content,
		StartPos: 0,
		EndPos:   len(content),
		Context:  content,
	}}
}

// GetConfidenceScore: confidence is uniform — if the prompt
// normalizes exactly into our stoplist, we're confident it's
// fragment-like. The legitimacy question (was prior context
// established?) lives at the conversation layer, not here.
func (m *AIQGVaguePromptMatcher) GetConfidenceScore(_ string) float64 { return 0.70 }

func normalizeVaguePrompt(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ".!?,;: ")
	s = strings.ToLower(s)
	// Collapse internal whitespace runs to single space.
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		b.WriteRune(r)
		lastSpace = false
	}
	return strings.TrimRight(b.String(), " ")
}

// ---------------------------------------------------------------------
// Instruction stuffing
// ---------------------------------------------------------------------

// AIQGInstructionStuffingMatcher flags prompts with many compound
// instructions piled together. Symptoms — 5+ "and also" / "also" /
// "additionally" / "furthermore" / "make sure to" connectors, or a
// numbered list with 10+ items. Cognitive overload degrades model
// fidelity to any single instruction.
type AIQGInstructionStuffingMatcher struct {
	baseMatcher
	connectorPattern *regexp.Regexp
	numListPattern   *regexp.Regexp
}

// NewAIQGInstructionStuffingMatcher constructs the matcher.
func NewAIQGInstructionStuffingMatcher() *AIQGInstructionStuffingMatcher {
	return &AIQGInstructionStuffingMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-instruction-stuffing",
			name:        "AIQG Instruction Stuffing",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.50,
			description: "Many piled-on instructions in a single prompt — model fidelity drops",
		},
		// Connectors that typically chain additional instructions.
		// Word boundaries + comma-or-newline ahead make these unlikely
		// to fire on natural prose use of "also" or "furthermore".
		connectorPattern: regexp.MustCompile(`(?i)(?:^|\n|[.,;])\s*(?:and\s+also|also,|additionally|furthermore|moreover|in\s+addition,|make\s+sure\s+to|make\s+sure\s+you|don'?t\s+forget\s+to|remember\s+to|be\s+sure\s+to)\b`),
		// Numbered list items at line start: "1.", "2)", "(3)".
		numListPattern: regexp.MustCompile(`(?m)^\s*(?:\d+[.)]|\(\d+\))\s+`),
	}
}

const (
	instructionStuffingMinConnectors = 5
	instructionStuffingMinListItems  = 10
)

func (m *AIQGInstructionStuffingMatcher) Match(content string) []Match {
	connectors := m.connectorPattern.FindAllStringIndex(content, -1)
	listItems := m.numListPattern.FindAllStringIndex(content, -1)
	if len(connectors) < instructionStuffingMinConnectors && len(listItems) < instructionStuffingMinListItems {
		return nil
	}
	// One finding per prompt. Anchor at the first triggering hit so
	// downstream UIs can highlight where the pile-on starts.
	var start, end int
	switch {
	case len(connectors) >= instructionStuffingMinConnectors && len(listItems) >= instructionStuffingMinListItems:
		// Both trigger — pick the earlier one.
		first := connectors[0][0]
		if listItems[0][0] < first {
			first = listItems[0][0]
		}
		start = first
	case len(connectors) >= instructionStuffingMinConnectors:
		start = connectors[0][0]
	default:
		start = listItems[0][0]
	}
	end = start + 1
	preview := content
	if len(preview) > 160 {
		preview = preview[:160] + "…"
	}
	return []Match{{
		Value:    preview,
		StartPos: start,
		EndPos:   end,
		Context:  extractContext(content, start, end, 80),
	}}
}

// GetConfidenceScore scales mildly with how much stuffing occurred.
// (Cheap recount inside the method — we don't know which signal
// fired, but we do know the prompt is stuffed.)
func (m *AIQGInstructionStuffingMatcher) GetConfidenceScore(_ string) float64 {
	return 0.75
}

// ---------------------------------------------------------------------
// Unbounded loop request
// ---------------------------------------------------------------------

// AIQGUnboundedLoopMatcher catches explicit "don't stop" / "keep
// going forever" patterns that try to make the model emit until
// max_tokens. Cost-burning at best, abuse signal at worst. Medium
// severity because the intent is unambiguous (no legitimate use case
// for "infinite generation" against an LLM you're paying per-token
// for).
type AIQGUnboundedLoopMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGUnboundedLoopMatcher constructs the matcher.
func NewAIQGUnboundedLoopMatcher() *AIQGUnboundedLoopMatcher {
	return &AIQGUnboundedLoopMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-unbounded-loop",
			name:        "AIQG Unbounded Loop Request",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityMedium,
			riskBase:    0.65,
			description: "Prompt asks model to generate without stopping — cost burner / abuse signal",
		},
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(?:don'?t|do\s+not|never)\s+stop\s+(?:generating|writing|until|when|even)\b`),
			regexp.MustCompile(`(?i)\bkeep\s+(?:going|generating|writing)\s+(?:forever|indefinitely|until\s+(?:you\s+(?:run\s+out|hit\s+the\s+limit)|the\s+context\s+(?:fills|runs\s+out)))\b`),
			regexp.MustCompile(`(?i)\bcontinue\s+(?:forever|indefinitely|without\s+stopping|until\s+max\s*[\s_]?tokens)\b`),
			regexp.MustCompile(`(?i)\bgenerate\s+(?:as\s+much\s+as\s+possible|until\s+(?:you\s+run\s+out|the\s+token\s+limit|max\s*[\s_]?tokens))\b`),
			regexp.MustCompile(`(?i)\b(?:write|output|produce)\s+(?:a\s+)?(?:1000|10000|100000|million)\s+(?:words?|tokens?|lines?|paragraphs?)\b`),
		},
	}
}

func (m *AIQGUnboundedLoopMatcher) Match(content string) []Match {
	return aiqgRunPatterns(m.patterns, content)
}

func (m *AIQGUnboundedLoopMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	if strings.Contains(lower, "forever") || strings.Contains(lower, "indefinitely") ||
		strings.Contains(lower, "max tokens") || strings.Contains(lower, "max_tokens") {
		return 0.90
	}
	return 0.75
}
