package scan

// RawMatch represents a raw match from the engine before post-validation.
type RawMatch struct {
	PatternIndex int    // Sub-pattern index within matcher
	MatcherID    string // Owning matcher ID
	Start        int    // Byte offset start
	End          int    // Byte offset end
}

// PatternDescriptor describes a single regex pattern to be compiled into the engine.
type PatternDescriptor struct {
	MatcherID     string
	PatternIndex  int
	Expression    string
	CaseSensitive bool
	DotAll        bool
}

// MatchEngine abstracts the regex backend for scanning content.
type MatchEngine interface {
	// ScanAll scans content in one pass, returning raw matches grouped by matcher ID.
	ScanAll(content string) map[string][]RawMatch

	// ScanMatchers scans content only for patterns belonging to the given matcher IDs.
	// For Hyperscan this still does a single pass (all patterns compiled together)
	// but filters results. For Go regexp this skips patterns not in the set.
	ScanMatchers(content string, matcherIDs map[string]bool) map[string][]RawMatch

	// PatternCount returns the number of compiled patterns.
	PatternCount() int

	// Close releases engine resources.
	Close() error
}
