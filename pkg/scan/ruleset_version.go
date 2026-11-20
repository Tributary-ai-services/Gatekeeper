package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// RulesetVersioner is implemented by scanners that can name the exact rule
// set they apply. Callers that cache "this content was already scanned"
// (the gateway's scan-once store, Plan #22 GK-5a) put it in the cache key, so
// any rule change makes every earlier answer unusable and content is scanned
// again rather than trusted under rules that no longer apply.
type RulesetVersioner interface {
	RulesetVersion() string
}

// RulesetVersion returns a short, stable digest of every registered matcher:
// its id, type, PII type, severity, risk base and each regex with its flags.
// The order of registration does not matter.
//
// It covers what the registry can describe. A change made only in a matcher's
// Go code (a new validator, say) does not move it, so callers should also key
// on their own build identity; the gateway does.
func RulesetVersion(reg PatternRegistry) string {
	if reg == nil {
		return "none"
	}
	matchers := reg.GetAll()
	lines := make([]string, 0, len(matchers)*2)
	for _, m := range matchers {
		lines = append(lines, fmt.Sprintf("m|%s|%s|%s|%s|%g",
			m.GetID(), m.GetType(), m.GetPIIType(), m.GetSeverity(), m.GetRiskBase()))
		for _, d := range m.GetPatternDescriptors() {
			lines = append(lines, fmt.Sprintf("p|%s|%d|%t|%t|%s",
				d.MatcherID, d.PatternIndex, d.CaseSensitive, d.DotAll, d.Expression))
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// RulesetVersion implements RulesetVersioner. It is computed once per call;
// the registry is fixed after construction, so callers may cache the value.
func (s *defaultScanner) RulesetVersion() string {
	return RulesetVersion(s.registry)
}
