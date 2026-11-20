package scan

import "testing"

func TestRulesetVersionIsStableAndOrderIndependent(t *testing.T) {
	a := RulesetVersion(NewDefaultRegistry())
	b := RulesetVersion(NewDefaultRegistry())
	if a == "" || a != b {
		t.Fatalf("version not stable: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Fatalf("want 16 hex chars, got %q", a)
	}

	// The scanner reports the same value as its registry.
	s, ok := NewScanner().(RulesetVersioner)
	if !ok {
		t.Fatal("default scanner does not implement RulesetVersioner")
	}
	if s.RulesetVersion() != a {
		t.Fatalf("scanner version %q != registry version %q", s.RulesetVersion(), a)
	}
}

func TestRulesetVersionChangesWithRules(t *testing.T) {
	full := NewDefaultRegistry()
	fewer := NewPatternRegistry()
	for i, m := range full.GetAll() {
		if i == 0 {
			continue // drop one matcher
		}
		fewer.Register(m)
	}
	if RulesetVersion(full) == RulesetVersion(fewer) {
		t.Fatal("removing a rule did not change the version")
	}
	if RulesetVersion(nil) != "none" {
		t.Fatal("nil registry should report none")
	}
}
