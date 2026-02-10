package scan

import (
	"regexp"
	"strings"
)

// SQLInjectionMatcher detects SQL injection attempts
type SQLInjectionMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewSQLInjectionMatcher creates a new SQL injection matcher
func NewSQLInjectionMatcher() *SQLInjectionMatcher {
	m := &SQLInjectionMatcher{
		baseMatcher: baseMatcher{
			id:          "injection-sql",
			name:        "SQL Injection",
			patternType: PatternTypeInjection,
			piiType:     "", // Not PII
			severity:    SeverityCritical,
			riskBase:    0.95,
			description: "Detects SQL injection attack patterns",
		},
		patterns: []*regexp.Regexp{
			// Classic SQL injection
			regexp.MustCompile(`(?i)(?:--|#|/\*)\s*$`),
			regexp.MustCompile(`(?i)'\s*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`),
			regexp.MustCompile(`(?i)'\s*(?:OR|AND)\s+['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+`),
			regexp.MustCompile(`(?i)(?:UNION\s+(?:ALL\s+)?SELECT)`),
			regexp.MustCompile(`(?i)(?:SELECT\s+[^\n]{0,200}\s+FROM\s+[^\n]{0,200}\s+WHERE)`),
			regexp.MustCompile(`(?i)(?:INSERT\s+INTO\s+[^\n]{0,200}\s+VALUES)`),
			regexp.MustCompile(`(?i)(?:UPDATE\s+[^\n]{0,200}\s+SET\s+[^\n]{0,200}\s+WHERE)`),
			regexp.MustCompile(`(?i)(?:DELETE\s+FROM\s+[^\n]{0,200}\s+WHERE)`),
			regexp.MustCompile(`(?i)(?:DROP\s+(?:TABLE|DATABASE|INDEX))`),
			regexp.MustCompile(`(?i)(?:TRUNCATE\s+TABLE)`),
			regexp.MustCompile(`(?i)(?:ALTER\s+TABLE)`),
			regexp.MustCompile(`(?i)(?:EXEC(?:UTE)?\s*\()`),
			regexp.MustCompile(`(?i)(?:xp_cmdshell)`),
			regexp.MustCompile(`(?i)(?:WAITFOR\s+DELAY)`),
			regexp.MustCompile(`(?i)(?:BENCHMARK\s*\()`),
			regexp.MustCompile(`(?i)(?:SLEEP\s*\()`),
			regexp.MustCompile(`(?i)(?:LOAD_FILE\s*\()`),
			regexp.MustCompile(`(?i)(?:INTO\s+(?:OUT|DUMP)FILE)`),
			regexp.MustCompile(`(?i)(?:INFORMATION_SCHEMA)`),
			regexp.MustCompile(`(?i)(?:sys\.(?:tables|columns|objects))`),
			regexp.MustCompile(`(?i)(?:1\s*=\s*1|'1'\s*=\s*'1')`),
			regexp.MustCompile(`(?i)(?:'\s*;\s*--)`),
			regexp.MustCompile(`(?i)(?:HAVING\s+\d+\s*=\s*\d+)`),
			regexp.MustCompile(`(?i)(?:ORDER\s+BY\s+\d+)`),
			regexp.MustCompile(`(?i)(?:GROUP\s+BY\s+\d+)`),
		},
	}

	// Set the primary pattern for baseMatcher
	m.pattern = m.patterns[0]

	return m
}

// sqlKeywords are cheap pre-screen terms — if none are present, skip all regex.
var sqlKeywords = []string{
	"--", "/*", "union", "select", "insert", "update", "delete",
	"drop", "truncate", "alter", "exec", "xp_cmdshell", "waitfor",
	"benchmark", "sleep", "load_file", "outfile", "dumpfile",
	"information_schema", "sys.", "1=1", "'='", "having", "order by",
	"group by", "'1'='1'", ";--",
}

// Match finds all SQL injection matches in content
func (m *SQLInjectionMatcher) Match(content string) []Match {
	// Fast pre-screen: skip all regex work if no SQL keywords found
	lower := strings.ToLower(content)
	found := false
	for _, kw := range sqlKeywords {
		if strings.Contains(lower, kw) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	var allMatches []Match

	for _, pattern := range m.patterns {
		indices := pattern.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			start, end := idx[0], idx[1]
			value := content[start:end]
			context := extractContext(content, start, end, 100)

			allMatches = append(allMatches, Match{
				Value:    value,
				StartPos: start,
				EndPos:   end,
				Context:  context,
			})
		}
	}

	// Deduplicate overlapping matches
	return m.deduplicateMatches(allMatches)
}

// deduplicateMatches removes overlapping matches, keeping the longer one
func (m *SQLInjectionMatcher) deduplicateMatches(matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}

	result := make([]Match, 0, len(matches))
	for _, match := range matches {
		overlaps := false
		for i, existing := range result {
			// Check for overlap
			if match.StartPos < existing.EndPos && match.EndPos > existing.StartPos {
				overlaps = true
				// Keep the longer match
				if len(match.Value) > len(existing.Value) {
					result[i] = match
				}
				break
			}
		}
		if !overlaps {
			result = append(result, match)
		}
	}

	return result
}

// GetConfidenceScore returns confidence based on pattern severity
func (m *SQLInjectionMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)

	// High confidence patterns
	highConfidence := []string{
		"union select",
		"drop table",
		"drop database",
		"xp_cmdshell",
		"information_schema",
		"1=1",
		"'='",
	}

	for _, pattern := range highConfidence {
		if strings.Contains(lowerMatch, pattern) {
			return 0.95
		}
	}

	// Medium confidence
	if strings.Contains(lowerMatch, "select") ||
		strings.Contains(lowerMatch, "insert") ||
		strings.Contains(lowerMatch, "update") ||
		strings.Contains(lowerMatch, "delete") {
		return 0.80
	}

	return 0.70
}

// XSSMatcher detects Cross-Site Scripting attempts
type XSSMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewXSSMatcher creates a new XSS matcher
func NewXSSMatcher() *XSSMatcher {
	m := &XSSMatcher{
		baseMatcher: baseMatcher{
			id:          "injection-xss",
			name:        "Cross-Site Scripting (XSS)",
			patternType: PatternTypeInjection,
			piiType:     "", // Not PII
			severity:    SeverityHigh,
			riskBase:    0.90,
			description: "Detects XSS attack patterns",
		},
		patterns: []*regexp.Regexp{
			// Script tags
			regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
			regexp.MustCompile(`(?i)<script[^>]*>`),

			// Event handlers
			regexp.MustCompile(`(?i)\bon\w+\s*=\s*["']?[^"'>\s]+`),

			// JavaScript URLs
			regexp.MustCompile(`(?i)javascript\s*:`),
			regexp.MustCompile(`(?i)vbscript\s*:`),
			regexp.MustCompile(`(?i)data\s*:\s*text/html`),

			// Dangerous tags
			regexp.MustCompile(`(?i)<iframe[^>]*>`),
			regexp.MustCompile(`(?i)<embed[^>]*>`),
			regexp.MustCompile(`(?i)<object[^>]*>`),
			regexp.MustCompile(`(?i)<applet[^>]*>`),
			regexp.MustCompile(`(?i)<meta[^>]*http-equiv[^>]*>`),
			regexp.MustCompile(`(?i)<link[^>]*>`),
			regexp.MustCompile(`(?i)<base[^>]*>`),

			// SVG-based XSS
			regexp.MustCompile(`(?i)<svg[^>]*onload[^>]*>`),
			regexp.MustCompile(`(?i)<svg[^>]*>.*?<script`),

			// Expression/eval patterns
			regexp.MustCompile(`(?i)expression\s*\(`),
			regexp.MustCompile(`(?i)eval\s*\(`),
			regexp.MustCompile(`(?i)document\.(?:cookie|write|location)`),
			regexp.MustCompile(`(?i)window\.(?:location|open)`),
			regexp.MustCompile(`(?i)\.innerHTML\s*=`),

			// Encoded patterns
			regexp.MustCompile(`(?i)&#x?[0-9a-f]+;`),
			regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`),
			regexp.MustCompile(`(?i)\\u[0-9a-f]{4}`),
		},
	}

	m.pattern = m.patterns[0]

	return m
}

// xssKeywords are cheap pre-screen terms for XSS detection.
var xssKeywords = []string{
	"<script", "<iframe", "<embed", "<object", "<applet", "<meta",
	"<link", "<base", "<svg", "javascript:", "vbscript:", "data:",
	"expression(", "eval(", "document.", "window.", ".innerhtml",
	"&#", "\\x", "\\u", "onclick", "onerror", "onload", "onmouse",
}

// Match finds all XSS matches in content
func (m *XSSMatcher) Match(content string) []Match {
	// Fast pre-screen: skip all regex work if no XSS keywords found
	lower := strings.ToLower(content)
	found := false
	for _, kw := range xssKeywords {
		if strings.Contains(lower, kw) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	var allMatches []Match

	for _, pattern := range m.patterns {
		indices := pattern.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			start, end := idx[0], idx[1]
			value := content[start:end]
			context := extractContext(content, start, end, 100)

			allMatches = append(allMatches, Match{
				Value:    value,
				StartPos: start,
				EndPos:   end,
				Context:  context,
			})
		}
	}

	return m.deduplicateMatches(allMatches)
}

// deduplicateMatches removes overlapping matches
func (m *XSSMatcher) deduplicateMatches(matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}

	result := make([]Match, 0, len(matches))
	for _, match := range matches {
		overlaps := false
		for i, existing := range result {
			if match.StartPos < existing.EndPos && match.EndPos > existing.StartPos {
				overlaps = true
				if len(match.Value) > len(existing.Value) {
					result[i] = match
				}
				break
			}
		}
		if !overlaps {
			result = append(result, match)
		}
	}

	return result
}

// GetConfidenceScore returns confidence based on pattern type
func (m *XSSMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)

	// Very high confidence patterns
	if strings.Contains(lowerMatch, "<script") {
		return 0.98
	}
	if strings.Contains(lowerMatch, "javascript:") {
		return 0.95
	}

	// High confidence patterns
	highConfidence := []string{
		"onerror=",
		"onload=",
		"onclick=",
		"onmouseover=",
		"eval(",
		"document.cookie",
	}

	for _, pattern := range highConfidence {
		if strings.Contains(lowerMatch, pattern) {
			return 0.90
		}
	}

	return 0.75
}

// PromptInjectionMatcher detects LLM prompt injection attempts
type PromptInjectionMatcher struct {
	baseMatcher
	patterns []*regexp.Regexp
}

// NewPromptInjectionMatcher creates a new prompt injection matcher
func NewPromptInjectionMatcher() *PromptInjectionMatcher {
	m := &PromptInjectionMatcher{
		baseMatcher: baseMatcher{
			id:          "injection-prompt",
			name:        "Prompt Injection",
			patternType: PatternTypeInjection,
			piiType:     "", // Not PII
			severity:    SeverityHigh,
			riskBase:    0.85,
			description: "Detects LLM prompt injection attempts",
		},
		patterns: []*regexp.Regexp{
			// Direct instruction override
			regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)`),
			regexp.MustCompile(`(?i)disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)`),
			regexp.MustCompile(`(?i)forget\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)`),
			regexp.MustCompile(`(?i)override\s+(?:your\s+)?(?:instructions?|programming|rules?)`),

			// Role manipulation
			regexp.MustCompile(`(?i)you\s+are\s+(?:now\s+)?(?:a\s+)?(?:new|different)\s+(?:ai|assistant|bot)`),
			regexp.MustCompile(`(?i)pretend\s+(?:to\s+be|you\s+are)\s+(?:a\s+)?`),
			regexp.MustCompile(`(?i)act\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?`),
			regexp.MustCompile(`(?i)roleplay\s+as\s+`),
			regexp.MustCompile(`(?i)switch\s+(?:to\s+)?(?:a\s+)?(?:new\s+)?(?:mode|persona|character)`),

			// System prompt extraction
			regexp.MustCompile(`(?i)(?:show|reveal|display|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)`),
			regexp.MustCompile(`(?i)what\s+(?:are|is)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)`),
			regexp.MustCompile(`(?i)repeat\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`),

			// Jailbreak attempts
			regexp.MustCompile(`(?i)(?:dan|jailbreak|bypass)\s+(?:mode|prompt)`),
			regexp.MustCompile(`(?i)do\s+anything\s+now`),
			regexp.MustCompile(`(?i)(?:unlock|enable)\s+(?:developer|admin|god)\s+mode`),

			// Boundary manipulation
			regexp.MustCompile(`(?i)\[system\]`),
			regexp.MustCompile(`(?i)\[assistant\]`),
			regexp.MustCompile(`(?i)\[user\]`),
			regexp.MustCompile(`(?i)<\|(?:im_start|im_end|system|user|assistant)\|>`),
			regexp.MustCompile("(?i)`{3}(?:system|instructions?|rules?)`{3}?"),

			// Instruction injection markers
			regexp.MustCompile(`(?i)(?:new\s+)?(?:instructions?|task|objective)\s*:`),
			regexp.MustCompile(`(?i)(?:begin|start)\s+(?:new\s+)?(?:instructions?|session)`),
			regexp.MustCompile(`(?i)(?:end|stop)\s+(?:of\s+)?(?:previous\s+)?(?:instructions?|session)`),

			// Encoded/obfuscated attempts
			regexp.MustCompile(`(?i)(?:base64|rot13|hex)\s*:\s*`),
			regexp.MustCompile(`(?i)decode\s+(?:the\s+)?following`),
		},
	}

	m.pattern = m.patterns[0]

	return m
}

// promptKeywords are cheap pre-screen terms for prompt injection detection.
var promptKeywords = []string{
	"ignore", "disregard", "forget", "override",
	"pretend", "act as", "roleplay", "you are now",
	"show your", "reveal", "system prompt", "repeat your",
	"jailbreak", "dan mode", "bypass", "do anything now",
	"[system]", "[assistant]", "[user]", "<|im_start|>", "<|im_end|>",
	"instruction", "new task", "objective:", "begin new", "end of",
	"base64:", "rot13:", "hex:", "decode",
}

// Match finds all prompt injection matches in content
func (m *PromptInjectionMatcher) Match(content string) []Match {
	// Fast pre-screen: skip all regex work if no prompt injection keywords found
	lower := strings.ToLower(content)
	found := false
	for _, kw := range promptKeywords {
		if strings.Contains(lower, kw) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	var allMatches []Match

	for _, pattern := range m.patterns {
		indices := pattern.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			start, end := idx[0], idx[1]
			value := content[start:end]
			context := extractContext(content, start, end, 100)

			allMatches = append(allMatches, Match{
				Value:    value,
				StartPos: start,
				EndPos:   end,
				Context:  context,
			})
		}
	}

	return m.deduplicateMatches(allMatches)
}

// deduplicateMatches removes overlapping matches
func (m *PromptInjectionMatcher) deduplicateMatches(matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}

	result := make([]Match, 0, len(matches))
	for _, match := range matches {
		overlaps := false
		for i, existing := range result {
			if match.StartPos < existing.EndPos && match.EndPos > existing.StartPos {
				overlaps = true
				if len(match.Value) > len(existing.Value) {
					result[i] = match
				}
				break
			}
		}
		if !overlaps {
			result = append(result, match)
		}
	}

	return result
}

// GetConfidenceScore returns confidence based on injection type
func (m *PromptInjectionMatcher) GetConfidenceScore(match string) float64 {
	lowerMatch := strings.ToLower(match)

	// Very high confidence - explicit attacks
	veryHigh := []string{
		"ignore previous instructions",
		"ignore all instructions",
		"disregard previous",
		"jailbreak",
		"dan mode",
		"do anything now",
	}

	for _, pattern := range veryHigh {
		if strings.Contains(lowerMatch, pattern) {
			return 0.95
		}
	}

	// High confidence - system prompt extraction
	high := []string{
		"system prompt",
		"show your instructions",
		"reveal your rules",
		"[system]",
		"<|im_start|>",
	}

	for _, pattern := range high {
		if strings.Contains(lowerMatch, pattern) {
			return 0.90
		}
	}

	// Medium confidence - role manipulation
	medium := []string{
		"pretend to be",
		"act as if",
		"roleplay as",
		"you are now",
	}

	for _, pattern := range medium {
		if strings.Contains(lowerMatch, pattern) {
			return 0.75
		}
	}

	return 0.65
}
