//go:build !nohs

package scan

import (
	"fmt"
	"strings"

	"github.com/flier/gohs/hyperscan"
)

// ValidateHyperscanCompatibility tests all descriptors against Hyperscan compilation.
// Returns a list of incompatible patterns with error details.
func ValidateHyperscanCompatibility(descriptors []PatternDescriptor) []PatternCompatError {
	var errors []PatternCompatError
	for _, desc := range descriptors {
		expr, flags := sanitizeForHyperscan(desc)
		if !isHyperscanCompatible(expr) {
			errors = append(errors, PatternCompatError{
				MatcherID:    desc.MatcherID,
				PatternIndex: desc.PatternIndex,
				Expression:   desc.Expression,
				Reason:       "contains backreferences",
			})
			continue
		}
		// Try to compile individually
		p := hyperscan.NewPattern(expr, flags|hyperscan.SomLeftMost)
		p.Id = 0
		_, err := hyperscan.NewBlockDatabase(p)
		if err != nil {
			errors = append(errors, PatternCompatError{
				MatcherID:    desc.MatcherID,
				PatternIndex: desc.PatternIndex,
				Expression:   desc.Expression,
				Reason:       err.Error(),
			})
		}
	}
	return errors
}

// PatternCompatError describes a pattern that is incompatible with Hyperscan.
type PatternCompatError struct {
	MatcherID    string
	PatternIndex int
	Expression   string
	Reason       string
}

// String returns a human-readable description of the compatibility error.
func (e PatternCompatError) String() string {
	return fmt.Sprintf("pattern %s/%d: %s (expr: %s)",
		e.MatcherID, e.PatternIndex, e.Reason, truncate(e.Expression, 60))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// StripInlineFlags removes Go-style inline flag prefixes from a regex.
// For example, "(?i)(?s)foo" becomes "foo".
func StripInlineFlags(expr string) string {
	for {
		if strings.HasPrefix(expr, "(?") {
			end := strings.Index(expr[2:], ")")
			if end == -1 {
				break
			}
			flagStr := expr[2 : 2+end]
			isFlags := true
			for _, c := range flagStr {
				switch c {
				case 'i', 's', 'm', 'U':
				default:
					isFlags = false
				}
			}
			if !isFlags {
				break
			}
			expr = expr[2+end+1:]
		} else {
			break
		}
	}
	return expr
}
