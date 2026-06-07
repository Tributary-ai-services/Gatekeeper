// Outbound-focused AIQG quality matchers. These complement the
// inbound matchers in matchers_aiqg.go by scoring the model's
// response side. All three are PatternTypeCustom + low severity —
// none auto-block; they only contribute Assurance scoring signal.
//
// Direction caveat: Gatekeeper matchers don't know whether they're
// scanning inbound or outbound content. Each of these is named for
// the side that's USUALLY interesting (e.g. repetition in user
// prompts is harmless, in responses it indicates broken generation),
// but a hit on the unexpected side is still a true positive and
// surfaces as a finding — just be aware when reviewing dashboards.
package scan

import (
	"regexp"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------
// Repetition loop
// ---------------------------------------------------------------------

// AIQGRepetitionMatcher detects a broken-generation pattern where the
// model emits the same sentence 3+ times. Classic symptom of:
//   - temperature=0 with too-tight a prompt (model gets stuck)
//   - a hallucinated stop sequence the model can't escape
//   - decoding bugs in streaming
//
// Heuristic: split content into sentences (by . ! ? followed by
// whitespace), normalize each, and flag any normalized sentence
// that appears >= 3 times. Single-word "sentences" (e.g. "OK." or
// "Yes.") are skipped to avoid false positives on natural assent.
type AIQGRepetitionMatcher struct {
	baseMatcher
}

// NewAIQGRepetitionMatcher constructs the repetition matcher.
func NewAIQGRepetitionMatcher() *AIQGRepetitionMatcher {
	return &AIQGRepetitionMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-repetition",
			name:        "AIQG Repetition Loop",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.50,
			description: "Same sentence repeated 3+ times — typical broken-generation symptom",
		},
	}
}

const (
	repetitionMinOccurrences = 3
	repetitionMinWords       = 3 // skip "Yes.", "OK.", "Sure!"
	repetitionMaxScanLen     = 200_000
)

var sentenceSplitRe = regexp.MustCompile(`[.!?]+\s+`)

func (m *AIQGRepetitionMatcher) Match(content string) []Match {
	if len(content) == 0 {
		return nil
	}
	if len(content) > repetitionMaxScanLen {
		content = content[:repetitionMaxScanLen]
	}
	parts := sentenceSplitRe.Split(content, -1)
	counts := make(map[string]int, len(parts))
	first := make(map[string]int)
	for _, raw := range parts {
		norm := normalizeSentence(raw)
		if len(strings.Fields(norm)) < repetitionMinWords {
			continue
		}
		if _, seen := first[norm]; !seen {
			// Capture the earliest character offset so the Match has
			// a stable position field.
			if idx := strings.Index(content, raw); idx >= 0 {
				first[norm] = idx
			} else {
				first[norm] = 0
			}
		}
		counts[norm]++
	}
	var out []Match
	for norm, n := range counts {
		if n < repetitionMinOccurrences {
			continue
		}
		start := first[norm]
		end := start + len(norm)
		if end > len(content) {
			end = len(content)
		}
		val := norm
		if len(val) > 80 {
			val = val[:80] + "…"
		}
		out = append(out, Match{
			Value:    val,
			StartPos: start,
			EndPos:   end,
			Context:  extractContext(content, start, end, 60),
		})
	}
	return out
}

// GetConfidenceScore scales with how heavily the model repeated.
func (m *AIQGRepetitionMatcher) GetConfidenceScore(match string) float64 {
	// Without knowing the original count here, default to a single
	// "yes this looks like broken generation" score. The Match() loop
	// could embed the count in the Value, but truncation makes that
	// fragile; a single confidence is fine for v0.1.
	return 0.80
}

// normalizeSentence lowercases + collapses whitespace + strips
// trailing punctuation so "Hello world." and "hello   world!" hash
// the same.
func normalizeSentence(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
		case unicode.IsSpace(r):
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
		default:
			b.WriteRune(unicode.ToLower(r))
			lastSpace = false
		}
	}
	out := strings.TrimSpace(b.String())
	out = strings.TrimRight(out, ".!?,;:- ")
	return out
}

// ---------------------------------------------------------------------
// Hallucination hedge
// ---------------------------------------------------------------------

// AIQGHallucinationHedgeMatcher catches epistemic-hedging phrases
// the standalone Refusal matcher misses: not outright refusals, but
// uncertainty markers that often precede fabricated content. Things
// like "I believe", "as far as I know", "based on my training",
// "to my recollection".
//
// Not every hedge is a hallucination — a model saying "I think 2+2=4"
// is hedging but correct. The signal here is volume: a response with
// many hedge phrases is one to review.
type AIQGHallucinationHedgeMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewAIQGHallucinationHedgeMatcher constructs the hedge matcher.
func NewAIQGHallucinationHedgeMatcher() *AIQGHallucinationHedgeMatcher {
	return &AIQGHallucinationHedgeMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-hallucination-hedge",
			name:        "AIQG Hallucination Hedge",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.35,
			description: "Epistemic hedging phrasing that often precedes fabricated claims",
		},
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bI\s+(?:believe|think|recall|remember|recollect)\s+(?:that\s+)?\w`),
			regexp.MustCompile(`(?i)\bas\s+far\s+as\s+I\s+(?:know|remember|recall)\b`),
			regexp.MustCompile(`(?i)\bto\s+(?:my|the\s+best\s+of\s+my)\s+(?:knowledge|recollection|understanding)\b`),
			regexp.MustCompile(`(?i)\bbased\s+on\s+my\s+(?:training|knowledge|understanding|data)\b`),
			regexp.MustCompile(`(?i)\bif\s+I\s+(?:remember|recall)\s+correctly\b`),
			regexp.MustCompile(`(?i)\bI\s+(?:may|might)\s+be\s+(?:wrong|mistaken|incorrect)\b`),
		},
	}
}

func (m *AIQGHallucinationHedgeMatcher) Match(content string) []Match {
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

func (m *AIQGHallucinationHedgeMatcher) GetConfidenceScore(match string) float64 {
	lower := strings.ToLower(match)
	// "based on my training" is a near-certain LLM hallucination cue.
	if strings.Contains(lower, "based on my training") {
		return 0.85
	}
	return 0.55
}

// ---------------------------------------------------------------------
// Malformed structured output
// ---------------------------------------------------------------------

// AIQGMalformedOutputMatcher catches two common output-quality
// failures: (1) the model started a code fence with ``` but never
// closed it, and (2) the response begins with `{` or `[` looking
// like JSON but doesn't actually parse.
//
// Both indicate the response is unusable for downstream automation
// even though no error was returned by the vendor.
type AIQGMalformedOutputMatcher struct {
	baseMatcher
}

// NewAIQGMalformedOutputMatcher constructs the matcher.
func NewAIQGMalformedOutputMatcher() *AIQGMalformedOutputMatcher {
	return &AIQGMalformedOutputMatcher{
		baseMatcher: baseMatcher{
			id:          "aiqg-malformed-output",
			name:        "AIQG Malformed Structured Output",
			patternType: PatternTypeCustom,
			piiType:     "",
			severity:    SeverityLow,
			riskBase:    0.60,
			description: "Unclosed code fence or attempted-but-invalid JSON response",
		},
	}
}

// Track an even-vs-odd count of ``` fences. Odd = unclosed.
var codeFenceRe = regexp.MustCompile("(?m)^```")

func (m *AIQGMalformedOutputMatcher) Match(content string) []Match {
	var out []Match

	// 1. Unclosed code fence.
	if hits := codeFenceRe.FindAllStringIndex(content, -1); len(hits)%2 == 1 {
		first := hits[0][0]
		out = append(out, Match{
			Value:    "```",
			StartPos: first,
			EndPos:   first + 3,
			Context:  extractContext(content, first, first+3, 80),
		})
	}

	// 2. Looks-like-JSON-but-isn't. Cheap pre-screen: trimmed
	// content starts with { or [. Then attempt to validate by
	// counting brace/bracket balance — full json.Unmarshal would
	// be heavier and would also reject extra prose after the
	// structured block, which is annoyingly common.
	trimmed := strings.TrimLeftFunc(content, unicode.IsSpace)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		if !bracesBalanced(trimmed) {
			start := strings.Index(content, string(trimmed[0]))
			if start < 0 {
				start = 0
			}
			out = append(out, Match{
				Value:    string(trimmed[0]),
				StartPos: start,
				EndPos:   start + 1,
				Context:  extractContext(content, start, start+1, 80),
			})
		}
	}

	return out
}

func (m *AIQGMalformedOutputMatcher) GetConfidenceScore(match string) float64 {
	if match == "```" {
		return 0.90 // unclosed fence is nearly always a bug
	}
	return 0.75
}

// bracesBalanced checks whether { } and [ ] are balanced in s,
// ignoring content inside string literals. Doesn't validate full
// JSON grammar — just structural balance, which is good enough to
// flag obviously truncated output without rejecting JSON-with-
// trailing-prose.
func bracesBalanced(s string) bool {
	var stack []byte
	inString := false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if inString {
			switch c {
			case '\\':
				escape = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			stack = append(stack, c)
		case '}':
			if len(stack) == 0 || stack[len(stack)-1] != '{' {
				return false
			}
			stack = stack[:len(stack)-1]
		case ']':
			if len(stack) == 0 || stack[len(stack)-1] != '[' {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}
	return len(stack) == 0
}
