//go:build !nohs

package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// useEngineForScanning returns whether the scanner should use the MatchEngine
// for its scan loop. Hyperscan benefits from the engine single-pass approach.
func useEngineForScanning() bool {
	return true
}

// hyperscanEngine implements MatchEngine using Intel Hyperscan for single-pass scanning.
type hyperscanEngine struct {
	db          hyperscan.BlockDatabase
	scratchPool sync.Pool
	descriptors []PatternDescriptor
	patternMap  []patternMapping // index → descriptor mapping

	// Fallback patterns that couldn't be compiled into Hyperscan
	fallbackPatterns []fallbackPattern
}

// patternMapping maps a Hyperscan pattern ID to its descriptor.
type patternMapping struct {
	matcherID    string
	patternIndex int
}

// fallbackPattern holds a pattern that was incompatible with Hyperscan.
type fallbackPattern struct {
	descriptor PatternDescriptor
	compiled   *regexp.Regexp
}

// hsCandidate pairs a Hyperscan pattern with the descriptor it came from, so a
// pattern that Hyperscan ultimately rejects can be routed to the Go regexp
// fallback.
type hsCandidate struct {
	pattern *hyperscan.Pattern
	desc    PatternDescriptor
}

// NewMatchEngine creates a MatchEngine backed by Hyperscan.
func NewMatchEngine(descriptors []PatternDescriptor) (MatchEngine, error) {
	if len(descriptors) == 0 {
		return &hyperscanEngine{}, nil
	}

	var candidates []hsCandidate
	var fallbacks []fallbackPattern

	// addFallback compiles a descriptor with Go regexp and records it for the
	// fallback scan pass. Used for patterns Hyperscan can't handle.
	addFallback := func(desc PatternDescriptor) error {
		compiled, err := regexp.Compile(desc.Expression)
		if err != nil {
			return fmt.Errorf("pattern %s/%d: neither Hyperscan nor Go regexp compatible: %w",
				desc.MatcherID, desc.PatternIndex, err)
		}
		fallbacks = append(fallbacks, fallbackPattern{descriptor: desc, compiled: compiled})
		return nil
	}

	for _, desc := range descriptors {
		expr, flags := sanitizeForHyperscan(desc)

		// Statically-detectable incompatibilities (e.g. backreferences) go
		// straight to the Go regexp fallback.
		if !isHyperscanCompatible(expr) {
			if err := addFallback(desc); err != nil {
				return nil, err
			}
			continue
		}

		p := hyperscan.NewPattern(expr, flags|hyperscan.SomLeftMost)
		candidates = append(candidates, hsCandidate{pattern: p, desc: desc})
	}

	engine := &hyperscanEngine{descriptors: descriptors}

	db, mappings, err := compileBlockDatabase(candidates)
	if err != nil {
		// The combined compile failed — most commonly "Pattern is too large",
		// where a single pattern's NFA exceeds Hyperscan's limits (e.g. bounded
		// repeats like [^\n]{0,200}). Isolate the offenders by compiling each
		// candidate alone, route those to the Go regexp fallback, and recompile
		// the remainder so Hyperscan still handles every pattern it can.
		var good []hsCandidate
		for _, c := range candidates {
			single := *c.pattern
			single.Id = 0
			if _, e := hyperscan.NewBlockDatabase(&single); e != nil {
				if ferr := addFallback(c.desc); ferr != nil {
					return nil, ferr
				}
				continue
			}
			good = append(good, c)
		}
		db, mappings, err = compileBlockDatabase(good)
		if err != nil {
			return nil, fmt.Errorf("failed to compile Hyperscan database after isolating oversized patterns: %w", err)
		}
	}

	engine.patternMap = mappings
	engine.fallbackPatterns = fallbacks

	if db != nil {
		engine.db = db
		// Create scratch pool
		engine.scratchPool = sync.Pool{
			New: func() interface{} {
				s, err := hyperscan.NewScratch(db)
				if err != nil {
					return nil
				}
				return s
			},
		}
	}

	return engine, nil
}

// compileBlockDatabase assigns contiguous pattern IDs to the given candidates
// and compiles them into a single Hyperscan block database. It returns the
// database and a patternMap aligned with the assigned IDs (so a scan callback's
// pattern id indexes directly into the returned slice). A nil database is
// returned, with no error, when there are no candidates.
func compileBlockDatabase(candidates []hsCandidate) (hyperscan.BlockDatabase, []patternMapping, error) {
	if len(candidates) == 0 {
		return nil, nil, nil
	}

	patterns := make([]*hyperscan.Pattern, len(candidates))
	mappings := make([]patternMapping, len(candidates))
	for i, c := range candidates {
		c.pattern.Id = i
		patterns[i] = c.pattern
		mappings[i] = patternMapping{
			matcherID:    c.desc.MatcherID,
			patternIndex: c.desc.PatternIndex,
		}
	}

	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return nil, nil, err
	}
	return db, mappings, nil
}

// sanitizeForHyperscan converts a Go regexp expression and descriptor flags
// into a Hyperscan-compatible expression string and flag set.
func sanitizeForHyperscan(desc PatternDescriptor) (string, hyperscan.CompileFlag) {
	expr := desc.Expression
	flags := hyperscan.CompileFlag(0)

	// Strip inline flag groups at the start of the expression
	for {
		if strings.HasPrefix(expr, "(?") {
			end := strings.Index(expr[2:], ")")
			if end == -1 {
				break
			}
			flagStr := expr[2 : 2+end]
			// Only strip pure flag groups (no alternation chars)
			isFlags := true
			for _, c := range flagStr {
				switch c {
				case 'i', 's', 'm', 'U':
					// valid flags
				default:
					isFlags = false
				}
			}
			if !isFlags {
				break
			}
			for _, c := range flagStr {
				switch c {
				case 'i':
					flags |= hyperscan.Caseless
				case 's':
					flags |= hyperscan.DotAll
				case 'm':
					flags |= hyperscan.MultiLine
				}
			}
			expr = expr[2+end+1:]
		} else {
			break
		}
	}

	// Apply descriptor-level flags
	if !desc.CaseSensitive {
		flags |= hyperscan.Caseless
	}
	if desc.DotAll {
		flags |= hyperscan.DotAll
	}

	return expr, flags
}

// isHyperscanCompatible checks if a pattern can be compiled by Hyperscan.
func isHyperscanCompatible(expr string) bool {
	// Hyperscan doesn't support backreferences
	if strings.Contains(expr, `\1`) || strings.Contains(expr, `\2`) ||
		strings.Contains(expr, `\3`) || strings.Contains(expr, `\4`) {
		return false
	}
	// Hyperscan doesn't support lookaheads/lookbehinds in all contexts,
	// but we'll let the compiler decide — return true here and catch
	// compilation errors at NewMatchEngine time.
	return true
}

// ScanAll runs Hyperscan block scan once, then runs fallback patterns.
func (e *hyperscanEngine) ScanAll(content string) map[string][]RawMatch {
	results := make(map[string][]RawMatch)

	// Phase 1: Hyperscan single-pass scan
	if e.db != nil {
		scratch := e.scratchPool.Get()
		if scratch != nil {
			s := scratch.(*hyperscan.Scratch)
			data := []byte(content)

			_ = e.db.Scan(data, s, func(id uint, from, to uint64, flags uint, _ interface{}) error {
				if int(id) < len(e.patternMap) {
					mapping := e.patternMap[id]
					results[mapping.matcherID] = append(results[mapping.matcherID], RawMatch{
						PatternIndex: mapping.patternIndex,
						MatcherID:    mapping.matcherID,
						Start:        int(from),
						End:          int(to),
					})
				}
				return nil
			}, nil)

			e.scratchPool.Put(s)
		}
	}

	// Phase 2: Fallback patterns via Go regexp
	for _, fb := range e.fallbackPatterns {
		indices := fb.compiled.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			results[fb.descriptor.MatcherID] = append(results[fb.descriptor.MatcherID], RawMatch{
				PatternIndex: fb.descriptor.PatternIndex,
				MatcherID:    fb.descriptor.MatcherID,
				Start:        idx[0],
				End:          idx[1],
			})
		}
	}

	// Hyperscan reports a hit at every end position a pattern accepts (e.g.
	// [A-Za-z]{2,} fires at ".co" and again at ".com"), so a single logical
	// match surfaces as several overlapping RawMatches. Collapse each matcher's
	// hits to non-overlapping, leftmost-longest matches to mirror Go regexp's
	// FindAll semantics (and keep parity with the fallback path above).
	for id, matches := range results {
		results[id] = leftmostLongest(matches)
	}

	return results
}

// leftmostLongest reduces a set of (possibly overlapping) raw matches to the
// non-overlapping, leftmost-longest subset, scanning left to right the same way
// regexp.FindAll does. Input order is not assumed.
func leftmostLongest(matches []RawMatch) []RawMatch {
	if len(matches) <= 1 {
		return matches
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		// Prefer the longer match at the same start.
		return matches[i].End > matches[j].End
	})

	out := matches[:0]
	lastEnd := -1
	for _, m := range matches {
		if m.Start >= lastEnd {
			out = append(out, m)
			lastEnd = m.End
		}
	}
	return out
}

// ScanMatchers scans all patterns (Hyperscan does a single pass regardless)
// but only keeps results for the specified matcher IDs.
func (e *hyperscanEngine) ScanMatchers(content string, matcherIDs map[string]bool) map[string][]RawMatch {
	all := e.ScanAll(content)
	// Filter to only requested matchers
	for id := range all {
		if !matcherIDs[id] {
			delete(all, id)
		}
	}
	return all
}

// PatternCount returns the total number of patterns (Hyperscan + fallback).
func (e *hyperscanEngine) PatternCount() int {
	return len(e.patternMap) + len(e.fallbackPatterns)
}

// Close releases the Hyperscan database.
func (e *hyperscanEngine) Close() error {
	if e.db != nil {
		return e.db.Close()
	}
	return nil
}
