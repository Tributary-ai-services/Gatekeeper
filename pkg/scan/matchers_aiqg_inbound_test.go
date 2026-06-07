package scan

import (
	"strings"
	"testing"
)

// ---------------- Vague prompt ----------------

func TestAIQGVague_Matches(t *testing.T) {
	m := NewAIQGVaguePromptMatcher()
	for _, prompt := range []string{
		"do it",
		"do it.",
		"  More please  ",
		"Continue.",
		"keep going",
		"Fix this.",
		"Again, please!",
		"redo",
	} {
		t.Run(prompt[:min(len(prompt), 20)], func(t *testing.T) {
			if got := m.Match(prompt); len(got) == 0 {
				t.Errorf("expected match for %q", prompt)
			}
		})
	}
}

func TestAIQGVague_NoFalsePositives(t *testing.T) {
	m := NewAIQGVaguePromptMatcher()
	for _, prompt := range []string{
		"Continue writing the function that handles errors gracefully.",
		"Please fix this code so it handles the null case.",
		"Help me debug why my tests are failing.",
		"Do it tomorrow, not today.",
	} {
		if got := m.Match(prompt); len(got) > 0 {
			t.Errorf("false positive on %q: %v", prompt, got)
		}
	}
}

// ---------------- Instruction stuffing ----------------

func TestAIQGStuffing_FiresOnManyConnectors(t *testing.T) {
	m := NewAIQGInstructionStuffingMatcher()
	prompt := "Please write a function. Also, make sure to handle errors. " +
		"And also include logging. Additionally, add unit tests. " +
		"Furthermore, write documentation. Make sure to handle edge cases. " +
		"Don't forget to add type hints."
	if got := m.Match(prompt); len(got) == 0 {
		t.Errorf("expected stuffing finding, got none")
	}
}

func TestAIQGStuffing_FiresOnLongNumberedList(t *testing.T) {
	m := NewAIQGInstructionStuffingMatcher()
	var sb strings.Builder
	sb.WriteString("Do all of the following:\n")
	for i := 1; i <= 12; i++ {
		sb.WriteString("\n")
		sb.WriteString("  ")
		sb.WriteString(intToString(i))
		sb.WriteString(". Step ")
		sb.WriteString(intToString(i))
	}
	if got := m.Match(sb.String()); len(got) == 0 {
		t.Errorf("expected stuffing finding on long numbered list")
	}
}

func TestAIQGStuffing_NoFalsePositiveOnNormalProse(t *testing.T) {
	m := NewAIQGInstructionStuffingMatcher()
	// Three connectors — below the threshold of 5.
	prompt := "Write a function. Also, handle errors. Additionally, log results."
	if got := m.Match(prompt); len(got) > 0 {
		t.Errorf("false positive on %q: %v", prompt, got)
	}
}

// ---------------- Unbounded loop ----------------

func TestAIQGUnbounded_Matches(t *testing.T) {
	m := NewAIQGUnboundedLoopMatcher()
	for _, prompt := range []string{
		"Keep generating forever.",
		"Continue indefinitely until you run out.",
		"Don't stop writing until you hit the limit.",
		"Generate until max tokens.",
		"Write 10000 words on this topic.",
		"Produce 1000 paragraphs.",
	} {
		t.Run(prompt[:min(len(prompt), 25)], func(t *testing.T) {
			if got := m.Match(prompt); len(got) == 0 {
				t.Errorf("expected match for %q", prompt)
			}
		})
	}
}

func TestAIQGUnbounded_NoFalsePositives(t *testing.T) {
	m := NewAIQGUnboundedLoopMatcher()
	for _, prompt := range []string{
		"Don't stop believin'.",
		"Continue writing the chapter to its natural conclusion.",
		"Generate a summary of these 10 documents.",
		"Write a 500-word essay.",
	} {
		if got := m.Match(prompt); len(got) > 0 {
			t.Errorf("false positive on %q: %v", prompt, got)
		}
	}
}

// ---------------- Registry ----------------

func TestAIQGInbound_RegisteredByDefault(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, id := range []string{
		"aiqg-vague-prompt",
		"aiqg-instruction-stuffing",
		"aiqg-unbounded-loop",
	} {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("matcher %q not registered in default registry", id)
		}
	}
}

// ---- helpers ----

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
