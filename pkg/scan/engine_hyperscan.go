//go:build !nohs

package scan

import (
	"fmt"
	"regexp"
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

// NewMatchEngine creates a MatchEngine backed by Hyperscan.
func NewMatchEngine(descriptors []PatternDescriptor) (MatchEngine, error) {
	if len(descriptors) == 0 {
		return &hyperscanEngine{}, nil
	}

	var hsPatterns []*hyperscan.Pattern
	var mappings []patternMapping
	var fallbacks []fallbackPattern

	for _, desc := range descriptors {
		expr, flags := sanitizeForHyperscan(desc)

		// Validate compatibility
		if !isHyperscanCompatible(expr) {
			// Fall back to Go regexp for this pattern
			compiled, err := regexp.Compile(desc.Expression)
			if err != nil {
				return nil, fmt.Errorf("pattern %s/%d: neither Hyperscan nor Go regexp compatible: %w",
					desc.MatcherID, desc.PatternIndex, err)
			}
			fallbacks = append(fallbacks, fallbackPattern{
				descriptor: desc,
				compiled:   compiled,
			})
			continue
		}

		id := len(hsPatterns)
		p := hyperscan.NewPattern(expr, flags|hyperscan.SomLeftMost)
		p.Id = id
		hsPatterns = append(hsPatterns, p)
		mappings = append(mappings, patternMapping{
			matcherID:    desc.MatcherID,
			patternIndex: desc.PatternIndex,
		})
	}

	engine := &hyperscanEngine{
		descriptors:      descriptors,
		patternMap:       mappings,
		fallbackPatterns: fallbacks,
	}

	if len(hsPatterns) > 0 {
		db, err := hyperscan.NewBlockDatabase(hsPatterns...)
		if err != nil {
			return nil, fmt.Errorf("failed to compile Hyperscan database: %w", err)
		}
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

	return results
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
