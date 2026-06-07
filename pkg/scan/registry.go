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
	registry.Register(NewPassportMatcher())
	registry.Register(NewDriversLicenseMatcher())
	registry.Register(NewAddressMatcher())
	registry.Register(NewNameMatcher())
	registry.Register(NewMedicalRecordMatcher())

	// Register credential matchers
	registry.Register(NewAWSAccessKeyMatcher())
	registry.Register(NewAWSSecretKeyMatcher())
	registry.Register(NewAPIKeyMatcher())
	registry.Register(NewPrivateKeyMatcher())
	registry.Register(NewAzureCredentialMatcher())
	registry.Register(NewGCPKeyMatcher())
	registry.Register(NewJWTTokenMatcher())
	registry.Register(NewOAuthCredentialMatcher())
	registry.Register(NewConnectionStringMatcher())

	// Register injection matchers
	registry.Register(NewSQLInjectionMatcher())
	registry.Register(NewXSSMatcher())
	registry.Register(NewPromptInjectionMatcher())

	// AIQG quality matchers (Custom-type). Fire as low/medium-severity
	// findings on the AIQG Assurance dimension. Safe to enable for all
	// callers — none auto-block; they only contribute scoring signal.
	registry.Register(NewAIQGBloatedContextMatcher())
	registry.Register(NewAIQGRoleClaimMatcher())
	registry.Register(NewAIQGRefusalMatcher())

	// AIQG outbound-focused quality matchers (matchers_aiqg_outbound.go).
	// Repetition + hedging + malformed output. Direction-agnostic at
	// the matcher level — they fire on either side; the scoring
	// surface is the same.
	registry.Register(NewAIQGRepetitionMatcher())
	registry.Register(NewAIQGHallucinationHedgeMatcher())
	registry.Register(NewAIQGMalformedOutputMatcher())

	// AIQG safety / policy matchers (matchers_aiqg_safety.go). Populate
	// the NIST AI RMF "Safe" characteristic on the dashboard. All
	// inbound-focused (catch user prompts requesting unsafe outputs).
	// Tuned for high precision to avoid eroding trust in the Safe
	// metric.
	registry.Register(NewAIQGHarmRequestMatcher())
	registry.Register(NewAIQGCredentialSolicitationMatcher())
	registry.Register(NewAIQGExplicitJailbreakMatcher())

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

// CollectDescriptors gathers PatternDescriptors from all registered matchers.
func (r *patternRegistry) CollectDescriptors() []PatternDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var all []PatternDescriptor
	for _, matcher := range r.matchers {
		all = append(all, matcher.GetPatternDescriptors()...)
	}
	return all
}
