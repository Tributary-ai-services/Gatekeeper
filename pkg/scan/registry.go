package scan

import (
	"sync"
)

// patternRegistry manages all pattern matchers
type patternRegistry struct {
	mu       sync.RWMutex
	matchers map[string]PatternMatcher
	byType   map[PatternType][]PatternMatcher
	byPII    map[PIIType]PatternMatcher
}

// NewPatternRegistry creates a new pattern registry
func NewPatternRegistry() PatternRegistry {
	return &patternRegistry{
		matchers: make(map[string]PatternMatcher),
		byType:   make(map[PatternType][]PatternMatcher),
		byPII:    make(map[PIIType]PatternMatcher),
	}
}

// NewDefaultRegistry creates a registry with all built-in matchers
func NewDefaultRegistry() PatternRegistry {
	registry := NewPatternRegistry()

	// Register PII matchers
	registry.Register(NewSSNMatcher())
	registry.Register(NewCreditCardMatcher())
	registry.Register(NewEmailMatcher())
	registry.Register(NewPhoneNumberMatcher())
	registry.Register(NewIPAddressMatcher())
	registry.Register(NewBankAccountMatcher())
	registry.Register(NewDateOfBirthMatcher())

	// Register credential matchers
	registry.Register(NewAWSAccessKeyMatcher())
	registry.Register(NewAWSSecretKeyMatcher())
	registry.Register(NewAPIKeyMatcher())

	// Register injection matchers
	registry.Register(NewSQLInjectionMatcher())
	registry.Register(NewXSSMatcher())
	registry.Register(NewPromptInjectionMatcher())

	return registry
}

// Register adds a pattern matcher to the registry
func (r *patternRegistry) Register(matcher PatternMatcher) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := matcher.GetID()
	r.matchers[id] = matcher

	// Index by type
	patternType := matcher.GetType()
	r.byType[patternType] = append(r.byType[patternType], matcher)

	// Index by PII type if applicable
	if piiType := matcher.GetPIIType(); piiType != "" {
		r.byPII[piiType] = matcher
	}
}

// Get returns a matcher by ID
func (r *patternRegistry) Get(id string) (PatternMatcher, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	matcher, ok := r.matchers[id]
	return matcher, ok
}

// GetByType returns all matchers of a given type
func (r *patternRegistry) GetByType(patternType PatternType) []PatternMatcher {
	r.mu.RLock()
	defer r.mu.RUnlock()

	matchers := r.byType[patternType]
	result := make([]PatternMatcher, len(matchers))
	copy(result, matchers)
	return result
}

// GetByPIIType returns the matcher for a specific PII type
func (r *patternRegistry) GetByPIIType(piiType PIIType) (PatternMatcher, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	matcher, ok := r.byPII[piiType]
	return matcher, ok
}

// GetAll returns all registered matchers
func (r *patternRegistry) GetAll() []PatternMatcher {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PatternMatcher, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		result = append(result, matcher)
	}
	return result
}

// GetEnabled returns matchers enabled for the given config
func (r *patternRegistry) GetEnabled(config *ScanConfig) []PatternMatcher {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PatternMatcher, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		if matcher.IsEnabled(config) {
			result = append(result, matcher)
		}
	}
	return result
}
