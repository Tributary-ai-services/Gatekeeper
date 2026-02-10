package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// defaultScanner implements the Scanner interface
type defaultScanner struct {
	mu               sync.RWMutex
	registry         PatternRegistry
	classifier       Classifier
	redactionEngine  RedactionEngine
	version          string
	defaultConfig    *ScanConfig
}

// NewScanner creates a new scanner with default configuration
func NewScanner() Scanner {
	return NewScannerWithRegistry(NewDefaultRegistry())
}

// NewScannerWithRegistry creates a scanner with a custom registry
func NewScannerWithRegistry(registry PatternRegistry) Scanner {
	return &defaultScanner{
		registry:        registry,
		classifier:      NewClassifier(),
		redactionEngine: NewRedactionEngine(),
		version:         "1.0.0",
		defaultConfig:   DefaultScanConfig(),
	}
}

// NewScannerWithConfig creates a scanner with custom configuration
func NewScannerWithConfig(config *ScanConfig) Scanner {
	s := &defaultScanner{
		registry:        NewDefaultRegistry(),
		classifier:      NewClassifier(),
		redactionEngine: NewRedactionEngine(),
		version:         "1.0.0",
		defaultConfig:   config,
	}
	return s
}

// Scan scans byte content for PII, compliance violations, and injection attacks
func (s *defaultScanner) Scan(ctx context.Context, content []byte, config *ScanConfig) (*ScanResult, error) {
	return s.ScanString(ctx, string(content), config)
}

// ScanString scans string content
func (s *defaultScanner) ScanString(ctx context.Context, content string, config *ScanConfig) (*ScanResult, error) {
	startTime := time.Now()

	// Use default config if none provided
	if config == nil {
		config = s.defaultConfig
	}

	// Create result structure
	result := &ScanResult{
		ID:          uuid.New().String(),
		ScannedAt:   startTime,
		ScanProfile: config.Profile,
		TrustTier:   config.TrustTier,
		IsCompliant: true,
		Metadata: ScanMetadata{
			ContentLength:  len(content),
			ScannerVersion: s.version,
		},
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Check content size limit
	if config.MaxContentSize > 0 && len(content) > config.MaxContentSize {
		return nil, fmt.Errorf("content size %d exceeds maximum %d", len(content), config.MaxContentSize)
	}

	// Get enabled matchers
	matchers := s.registry.GetEnabled(config)
	result.Metadata.PatternsScanned = len(matchers)

	// Scan for patterns
	var findings []Finding
	var maxSeverity Severity = SeverityLow
	highRiskCount := 0
	totalRisk := 0.0

	for _, matcher := range matchers {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		matches := matcher.Match(content)
		for _, match := range matches {
			// Calculate confidence
			confidence := matcher.GetConfidenceScore(match.Value)
			if confidence < config.MinConfidence {
				continue
			}

			// Create finding
			finding := s.createFinding(match, matcher, confidence, content, config)

			// Classify into frameworks
			classCtx := s.buildClassificationContext(config)
			if matcher.GetType() == PatternTypeInjection {
				finding.Frameworks = ClassifyInjection(&finding)
			} else {
				finding.Frameworks = s.classifier.Classify(&finding, classCtx)
			}

			// Update severity based on framework matches
			for _, fw := range finding.Frameworks {
				if fw.Severity.Value() > finding.Severity.Value() {
					finding.Severity = fw.Severity
				}
			}

			findings = append(findings, finding)

			// Track risk metrics
			totalRisk += finding.Confidence * matcher.GetRiskBase()
			if finding.Severity.Value() >= SeverityHigh.Value() {
				highRiskCount++
			}
			if finding.Severity.Value() > maxSeverity.Value() {
				maxSeverity = finding.Severity
			}
		}
	}

	// Sort findings by position
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Location.Offset < findings[j].Location.Offset
	})

	// Calculate risk score (0-100)
	riskScore := 0.0
	if len(findings) > 0 {
		riskScore = (totalRisk / float64(len(findings))) * 100
		if riskScore > 100 {
			riskScore = 100
		}
	}

	// Set compliance status
	result.IsCompliant = len(findings) == 0

	// Build violations from findings
	result.Violations = s.buildViolations(findings)

	// Update result
	result.Findings = findings
	result.TotalFindings = len(findings)
	result.RiskScore = riskScore
	result.MaxSeverity = maxSeverity
	result.HighRiskCount = highRiskCount
	result.Metadata.ScanDuration = time.Since(startTime)
	result.Metadata.ProcessingTime = time.Since(startTime)

	return result, nil
}

// createFinding creates a Finding from a Match
func (s *defaultScanner) createFinding(match Match, matcher PatternMatcher, confidence float64, content string, config *ScanConfig) Finding {
	// Generate value hash (never log actual PII)
	hash := sha256.Sum256([]byte(match.Value))
	valueHash := hex.EncodeToString(hash[:])

	// Generate preview
	preview := s.redactionEngine.GeneratePreview(match.Value, matcher.GetPIIType())

	// Determine context window
	contextWindow := config.ContextWindow
	if contextWindow <= 0 {
		contextWindow = 20
	}

	// Get context
	matchContext := extractContext(content, match.StartPos, match.EndPos, contextWindow)

	finding := Finding{
		ID:           uuid.New().String(),
		PatternID:    matcher.GetID(),
		PatternType:  matcher.GetType(),
		PIIType:      matcher.GetPIIType(),
		Value:        match.Value,
		Confidence:   confidence,
		Location: Location{
			Offset:    match.StartPos,
			Length:    match.EndPos - match.StartPos,
			EndOffset: match.EndPos,
		},
		Context:      matchContext,
		Severity:     matcher.GetSeverity(),
		ValueHash:    valueHash,
		ValuePreview: preview,
	}

	// Set injection type if applicable
	if matcher.GetType() == PatternTypeInjection {
		finding.InjectionType = s.getInjectionType(matcher.GetID())
	}

	return finding
}

// getInjectionType determines injection type from matcher ID
func (s *defaultScanner) getInjectionType(matcherID string) InjectionType {
	switch matcherID {
	case "injection-sql":
		return InjectionTypeSQL
	case "injection-xss":
		return InjectionTypeXSS
	case "injection-prompt":
		return InjectionTypePrompt
	default:
		return InjectionTypeControlChar
	}
}

// buildClassificationContext builds context for classification
func (s *defaultScanner) buildClassificationContext(config *ScanConfig) ClassificationContext {
	hints := config.ClassificationHints
	if hints.Hints == nil {
		hints.Hints = []string{}
	}
	return hints
}

// buildViolations groups findings into compliance violations
func (s *defaultScanner) buildViolations(findings []Finding) []Violation {
	// Group findings by framework and rule
	violationMap := make(map[string]*Violation)

	for _, finding := range findings {
		for _, fw := range finding.Frameworks {
			key := fmt.Sprintf("%s:%s", fw.Framework, fw.RuleID)

			if v, ok := violationMap[key]; ok {
				v.FindingIDs = append(v.FindingIDs, finding.ID)
				if fw.Severity.Value() > v.Severity.Value() {
					v.Severity = fw.Severity
				}
			} else {
				violationMap[key] = &Violation{
					Framework:   fw.Framework,
					RuleID:      fw.RuleID,
					Severity:    fw.Severity,
					Description: fw.Description,
					FindingIDs:  []string{finding.ID},
				}
			}
		}
	}

	// Convert map to slice
	violations := make([]Violation, 0, len(violationMap))
	for _, v := range violationMap {
		violations = append(violations, *v)
	}

	// Sort by severity (highest first)
	sort.Slice(violations, func(i, j int) bool {
		return violations[i].Severity.Value() > violations[j].Severity.Value()
	})

	return violations
}

// GetSupportedPatterns returns all patterns this scanner can detect
func (s *defaultScanner) GetSupportedPatterns() []PatternInfo {
	matchers := s.registry.GetAll()
	patterns := make([]PatternInfo, 0, len(matchers))

	for _, matcher := range matchers {
		patterns = append(patterns, PatternInfo{
			ID:          matcher.GetID(),
			Name:        matcher.GetName(),
			Type:        matcher.GetType(),
			PIIType:     matcher.GetPIIType(),
			Severity:    matcher.GetSeverity(),
			RiskBase:    matcher.GetRiskBase(),
		})
	}

	return patterns
}

// ValidateConfig validates a scan configuration
func (s *defaultScanner) ValidateConfig(config *ScanConfig) error {
	if config == nil {
		return nil // Will use defaults
	}

	if config.MinConfidence < 0 || config.MinConfidence > 1 {
		return fmt.Errorf("min_confidence must be between 0 and 1, got %f", config.MinConfidence)
	}

	if config.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}

	if config.MaxContentSize < 0 {
		return fmt.Errorf("max_content_size cannot be negative")
	}

	if config.ContextWindow < 0 {
		return fmt.Errorf("context_window cannot be negative")
	}

	return nil
}

// ScanWithRedaction scans content and returns both result and redacted content
func (s *defaultScanner) ScanWithRedaction(ctx context.Context, content string, config *ScanConfig) (*ScanResult, string, error) {
	result, err := s.ScanString(ctx, content, config)
	if err != nil {
		return nil, "", err
	}

	if len(result.Findings) == 0 {
		return result, content, nil
	}

	// Apply redaction
	strategy := config.RedactionMode
	if strategy == "" {
		strategy = RedactionMask
	}

	redacted, err := s.redactionEngine.Redact(content, result.Findings, strategy)
	if err != nil {
		return result, "", err
	}

	// Mark findings as redacted
	for i := range result.Findings {
		result.Findings[i].Redacted = true
		result.Findings[i].RedactedWith = string(strategy)
	}

	return result, redacted, nil
}

// ScanJSON scans JSON content, tracking field paths
func (s *defaultScanner) ScanJSON(ctx context.Context, jsonContent []byte, config *ScanConfig) (*ScanResult, error) {
	// For now, scan as string
	// TODO: Implement JSON-aware scanning with field path tracking
	return s.Scan(ctx, jsonContent, config)
}

// QuickScan performs a fast scan with minimal configuration
func QuickScan(content string) (*ScanResult, error) {
	scanner := NewScanner()
	return scanner.ScanString(context.Background(), content, nil)
}

// QuickScanBytes performs a fast scan on byte content
func QuickScanBytes(content []byte) (*ScanResult, error) {
	scanner := NewScanner()
	return scanner.Scan(context.Background(), content, nil)
}
