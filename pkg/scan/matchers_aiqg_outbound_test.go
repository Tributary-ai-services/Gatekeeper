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

// ---------------- Registry ----------------

func TestAIQGOutbound_RegisteredByDefault(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, id := range []string{"aiqg-repetition", "aiqg-hallucination-hedge", "aiqg-malformed-output"} {
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
