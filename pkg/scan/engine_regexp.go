//go:build nohs

package scan

import (
	"regexp"
)

// useEngineForScanning returns whether the scanner should use the MatchEngine
// for its scan loop. For Go regexp, the legacy per-matcher Match() path with
// keyword pre-screening is faster. For Hyperscan, the engine single-pass is faster.
func useEngineForScanning() bool {
	return false
}

// regexpEngine implements MatchEngine using Go's standard regexp package.
type regexpEngine struct {
	patterns    []*regexp.Regexp
	descriptors []PatternDescriptor
}

// NewMatchEngine creates a MatchEngine backed by Go regexp.
func NewMatchEngine(descriptors []PatternDescriptor) (MatchEngine, error) {
	patterns := make([]*regexp.Regexp, len(descriptors))
	for i, desc := range descriptors {
		expr := desc.Expression
		// Apply flags as inline prefixes for Go regexp
		prefix := ""
		if !desc.CaseSensitive {
			prefix += "(?i)"
		}
		if desc.DotAll {
			prefix += "(?s)"
		}
		// Only add prefix if the expression doesn't already start with those flags
		if prefix != "" && !hasInlineFlags(expr, !desc.CaseSensitive, desc.DotAll) {
			expr = prefix + expr
		}
		compiled, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		patterns[i] = compiled
	}
	return &regexpEngine{
		patterns:    patterns,
		descriptors: descriptors,
	}, nil
}

// hasInlineFlags checks if expression already starts with the needed flags.
func hasInlineFlags(expr string, needCaseInsensitive, needDotAll bool) bool {
	if len(expr) < 4 {
		return false
	}
	if expr[0] != '(' || expr[1] != '?' {
		return false
	}
	// Find the closing paren
	end := -1
	for i := 2; i < len(expr); i++ {
		if expr[i] == ')' {
			end = i
			break
		}
	}
	if end == -1 {
		return false
	}
	flags := expr[2:end]
	hasI := false
	hasS := false
	for _, c := range flags {
		if c == 'i' {
			hasI = true
		}
		if c == 's' {
			hasS = true
		}
	}
	if needCaseInsensitive && !hasI {
		return false
	}
	if needDotAll && !hasS {
		return false
	}
	return true
}

// ScanAll iterates all compiled patterns and collects matches.
func (e *regexpEngine) ScanAll(content string) map[string][]RawMatch {
	results := make(map[string][]RawMatch)
	for i, pattern := range e.patterns {
		desc := e.descriptors[i]
		indices := pattern.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			results[desc.MatcherID] = append(results[desc.MatcherID], RawMatch{
				PatternIndex: desc.PatternIndex,
				MatcherID:    desc.MatcherID,
				Start:        idx[0],
				End:          idx[1],
			})
		}
	}
	return results
}

// ScanMatchers only scans patterns belonging to the given matcher IDs.
// This is the key optimization for Go regexp — skips patterns for disabled matchers.
func (e *regexpEngine) ScanMatchers(content string, matcherIDs map[string]bool) map[string][]RawMatch {
	results := make(map[string][]RawMatch)
	for i, pattern := range e.patterns {
		desc := e.descriptors[i]
		if !matcherIDs[desc.MatcherID] {
			continue
		}
		indices := pattern.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			results[desc.MatcherID] = append(results[desc.MatcherID], RawMatch{
				PatternIndex: desc.PatternIndex,
				MatcherID:    desc.MatcherID,
				Start:        idx[0],
				End:          idx[1],
			})
		}
	}
	return results
}

// PatternCount returns the total number of compiled patterns.
func (e *regexpEngine) PatternCount() int {
	return len(e.patterns)
}

// Close is a no-op for the regexp engine.
func (e *regexpEngine) Close() error {
	return nil
}
