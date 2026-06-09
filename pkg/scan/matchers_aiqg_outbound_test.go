package scan

import (
	"strings"
	"testing"
)

// ---------------- Repetition ----------------

func TestAIQGRepetition_FiresOnLoop(t *testing.T) {
	m := NewAIQGRepetitionMatcher()
	body := "The quick brown fox jumps. The quick brown fox jumps. The quick brown fox jumps. Done."
	if got := m.Match(body); len(got) == 0 {
		t.Errorf("expected repetition finding, got none")
	}
}

func TestAIQGRepetition_IgnoresShortAffirmations(t *testing.T) {
	// Two-word "Yes." and "OK." don't count — too short, would
	// false-positive on normal assent.
	m := NewAIQGRepetitionMatcher()
	body := "OK. OK. OK. Yes. Yes. Yes."
	if got := m.Match(body); len(got) > 0 {
		t.Errorf("short affirmations shouldn't trigger: %v", got)
	}
}

func TestAIQGRepetition_NoFalsePositives(t *testing.T) {
	m := NewAIQGRepetitionMatcher()
	body := "First sentence here. A completely different second one. And a third unique sentence."
	if got := m.Match(body); len(got) > 0 {
		t.Errorf("varied sentences shouldn't trigger: %v", got)
	}
}

// ---------------- Hallucination hedge ----------------

func TestAIQGHedge_Matches(t *testing.T) {
	m := NewAIQGHallucinationHedgeMatcher()
	cases := []string{
		"I believe the answer is 42.",
		"As far as I know, water boils at 100 C.",
		"To my knowledge there are seven continents.",
		"Based on my training data, this happened in 2023.",
		"If I recall correctly, the function is recursive.",
		"I may be wrong but I think it's blue.",
	}
	for _, c := range cases {
		t.Run(c[:20], func(t *testing.T) {
			if got := m.Match(c); len(got) == 0 {
				t.Errorf("expected hedge match in %q", c)
			}
		})
	}
}

func TestAIQGHedge_NoFalsePositives(t *testing.T) {
	m := NewAIQGHallucinationHedgeMatcher()
	for _, c := range []string{
		"The capital of France is Paris.",
		"Photosynthesis converts CO2 into glucose.",
		"sort([3,1,2]) returns [1,2,3].",
	} {
		if got := m.Match(c); len(got) != 0 {
			t.Errorf("false positive in %q: %v", c, got)
		}
	}
}

// ---------------- Malformed output ----------------

func TestAIQGMalformed_UnclosedFence(t *testing.T) {
	m := NewAIQGMalformedOutputMatcher()
	body := "Here is the code:\n```python\nprint('hello')\n"
	if got := m.Match(body); len(got) == 0 {
		t.Errorf("unclosed code fence should match")
	}
}

func TestAIQGMalformed_BalancedFenceIsClean(t *testing.T) {
	m := NewAIQGMalformedOutputMatcher()
	body := "Here is the code:\n```python\nprint('hello')\n```"
	if got := m.Match(body); len(got) > 0 {
		t.Errorf("balanced fences shouldn't trigger: %v", got)
	}
}

func TestAIQGMalformed_InvalidJSONShape(t *testing.T) {
	m := NewAIQGMalformedOutputMatcher()
	// Opens with {, doesn't close
	body := `{"name": "alice", "items": [1, 2`
	if got := m.Match(body); len(got) == 0 {
		t.Errorf("invalid JSON shape should match")
	}
}

func TestAIQGMalformed_ValidJSONIsClean(t *testing.T) {
	m := NewAIQGMalformedOutputMatcher()
	body := `{"name": "alice", "items": [1, 2, 3]}`
	if got := m.Match(body); len(got) > 0 {
		t.Errorf("valid JSON shouldn't trigger: %v", got)
	}
}

// JSON with trailing prose: a model often emits `{...} <explanation>`.
// We accept this — balanced JSON, just extra text. Strict json.Unmarshal
// would reject it, our balance-checker accepts it.
func TestAIQGMalformed_JSONWithTrailingProse(t *testing.T) {
	m := NewAIQGMalformedOutputMatcher()
	body := `{"name": "alice"} The above represents the user record.`
	if got := m.Match(body); len(got) > 0 {
		t.Errorf("JSON + trailing prose shouldn't trigger: %v", got)
	}
}

func TestAIQGMalformed_NonJSONIsIgnored(t *testing.T) {
	m := NewAIQGMalformedOutputMatcher()
	body := "Hello, this response is just prose."
	if got := m.Match(body); len(got) > 0 {
		t.Errorf("plain text shouldn't trigger: %v", got)
	}
}

// ---------------- Citation marker ----------------

func TestAIQGCitationMarker_NumberedFootnotes(t *testing.T) {
	m := NewAIQGCitationMarkerMatcher()
	body := `According to recent research [1], the protocol supports retries [2]. ` +
		`See also [42] for the deprecation notice.`
	got := m.Match(body)
	if len(got) != 3 {
		t.Fatalf("expected 3 citation matches, got %d (%v)", len(got), got)
	}
	wantValues := []string{"[1]", "[2]", "[42]"}
	for i, want := range wantValues {
		if got[i].Value != want {
			t.Errorf("match[%d].Value = %q, want %q", i, got[i].Value, want)
		}
	}
}

func TestAIQGCitationMarker_NamedSources(t *testing.T) {
	m := NewAIQGCitationMarkerMatcher()
	body := `Per [Source: RFC 9110], retries are allowed. ` +
		`The vendor docs [Ref: vendor-api-v2] confirm this. ` +
		`[CITATION: Smith et al. 2023] supports the claim.`
	got := m.Match(body)
	if len(got) != 3 {
		t.Fatalf("expected 3 named-source matches, got %d (%v)", len(got), got)
	}
}

func TestAIQGCitationMarker_MixedPatterns(t *testing.T) {
	m := NewAIQGCitationMarkerMatcher()
	body := `Per [Source: RFC 9110] retries work [1]; see [2] for details.`
	got := m.Match(body)
	if len(got) != 3 {
		t.Fatalf("expected 3 mixed matches (1 named + 2 numbered), got %d", len(got))
	}
}

func TestAIQGCitationMarker_NoFalsePositives(t *testing.T) {
	m := NewAIQGCitationMarkerMatcher()
	cases := []string{
		// Inline parenthetical with year — explicitly NOT matched
		`As Smith (2023) demonstrated, this is fine.`,
		// Enumerated list items
		`1. first item\n2. second item\n3. third item`,
		// Markdown link without source: prefix
		`See [the docs](https://example.com) for more.`,
		// Year ranges in brackets (4 digits — out of range)
		`The period [2020-2024] saw major changes.`,
		// Plain prose
		`There are no citations in this sentence.`,
	}
	for _, body := range cases {
		if got := m.Match(body); len(got) > 0 {
			t.Errorf("false positive on %q: %v", body, got)
		}
	}
}

func TestAIQGCitationMarker_EmptyContent(t *testing.T) {
	m := NewAIQGCitationMarkerMatcher()
	if got := m.Match(""); len(got) > 0 {
		t.Errorf("empty content should match nothing: %v", got)
	}
}

// ---------------- Registry ----------------

func TestAIQGOutbound_RegisteredByDefault(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, id := range []string{"aiqg-repetition", "aiqg-hallucination-hedge", "aiqg-malformed-output", "aiqg-citation-marker"} {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("matcher %q not registered in default registry", id)
		}
	}
}

// Sanity: bracesBalanced edge cases.
func TestBracesBalanced(t *testing.T) {
	cases := map[string]bool{
		`{}`:                  true,
		`[1, 2]`:              true,
		`{"a": [1, 2]}`:       true,
		`{"a": [1, 2}`:        false, // mismatched
		`{"a": "}"}`:          true,  // closing brace inside string OK
		`{"a": "\""}`:         true,  // escaped quote inside string OK
		`{`:                   false,
		`}`:                   false,
		`{[}]`:                false, // crossed
		``:                    true,
	}
	for in, want := range cases {
		if got := bracesBalanced(in); got != want {
			t.Errorf("bracesBalanced(%q) = %v, want %v", strings.ReplaceAll(in, "\n", `\n`), got, want)
		}
	}
}
