package pipeline

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/action"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/attest"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/stream"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// --- Mock implementations ---

// mockScanner implements scan.Scanner for testing.
type mockScanner struct {
	scanFunc             func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error)
	scanStringFunc       func(ctx context.Context, content string, config *scan.ScanConfig) (*scan.ScanResult, error)
	supportedPatterns    []scan.PatternInfo
	validateConfigError  error
}

func (m *mockScanner) Scan(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
	if m.scanFunc != nil {
		return m.scanFunc(ctx, content, config)
	}
	return &scan.ScanResult{
		Findings:      []scan.Finding{},
		TotalFindings: 0,
		IsCompliant:   true,
	}, nil
}

func (m *mockScanner) ScanString(ctx context.Context, content string, config *scan.ScanConfig) (*scan.ScanResult, error) {
	if m.scanStringFunc != nil {
		return m.scanStringFunc(ctx, content, config)
	}
	return m.Scan(ctx, []byte(content), config)
}

func (m *mockScanner) GetSupportedPatterns() []scan.PatternInfo {
	return m.supportedPatterns
}

func (m *mockScanner) ValidateConfig(config *scan.ScanConfig) error {
	return m.validateConfigError
}

// mockAttestor implements attest.Attestor for testing.
type mockAttestor struct {
	createFunc func(ctx context.Context, req attest.CreateRequest) (*types.Attestation, error)
	verifyFunc func(ctx context.Context, attestation *types.Attestation) error
	canSkipFunc func(ctx context.Context, req attest.SkipCheckRequest) (bool, string)
}

func (m *mockAttestor) Create(ctx context.Context, req attest.CreateRequest) (*types.Attestation, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, req)
	}
	return &types.Attestation{
		ID:          "test-attest-id",
		ContentHash: "abc123",
		ScannedBy:   "test",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}, nil
}

func (m *mockAttestor) Verify(ctx context.Context, attestation *types.Attestation) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, attestation)
	}
	return nil
}

func (m *mockAttestor) CanSkip(ctx context.Context, req attest.SkipCheckRequest) (bool, string) {
	if m.canSkipFunc != nil {
		return m.canSkipFunc(ctx, req)
	}
	return false, ""
}

// mockEngine implements action.Engine for testing.
type mockEngine struct {
	evaluateFunc func(ctx context.Context, req action.EvaluateRequest) (*action.EvaluateResult, error)
	executeFunc  func(ctx context.Context, result *action.EvaluateResult) (*types.ActionResult, error)
	loadRulesErr error
	closed       bool
	mu           sync.Mutex
}

func (m *mockEngine) Evaluate(ctx context.Context, req action.EvaluateRequest) (*action.EvaluateResult, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, req)
	}
	return &action.EvaluateResult{
		ShouldBlock:  false,
		MatchedRules: []action.MatchedRule{},
		Actions:      []action.ActionToTake{},
	}, nil
}

func (m *mockEngine) Execute(ctx context.Context, result *action.EvaluateResult) (*types.ActionResult, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, result)
	}
	return &types.ActionResult{
		Blocked:      result.ShouldBlock,
		BlockReason:  result.BlockReason,
		RulesMatched: []string{},
		Actions:      []types.ActionTaken{},
	}, nil
}

func (m *mockEngine) LoadRules(rules []action.Rule) error {
	return m.loadRulesErr
}

func (m *mockEngine) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockEngine) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// mockStreamer implements stream.Streamer for testing.
type mockStreamer struct {
	streamFunc      func(ctx context.Context, findings []stream.Finding) error
	streamBatchFunc func(ctx context.Context, batch []stream.Finding) error
	closed          bool
	mu              sync.Mutex
	streamedCount   int
}

func (m *mockStreamer) Stream(ctx context.Context, findings []stream.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamedCount += len(findings)
	if m.streamFunc != nil {
		return m.streamFunc(ctx, findings)
	}
	return nil
}

func (m *mockStreamer) StreamBatch(ctx context.Context, batch []stream.Finding) error {
	if m.streamBatchFunc != nil {
		return m.streamBatchFunc(ctx, batch)
	}
	return nil
}

func (m *mockStreamer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockStreamer) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *mockStreamer) getStreamedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamedCount
}

// --- Helper functions ---

func makeFinding(id, patternID string, severity scan.Severity) scan.Finding {
	return scan.Finding{
		ID:          id,
		PatternID:   patternID,
		PatternType: scan.PatternTypePII,
		PIIType:     scan.PIITypeSSN,
		Value:       "123-45-6789",
		Confidence:  0.95,
		Severity:    severity,
		ValueHash:   "hash123",
		ValuePreview: "1**-**-**89",
	}
}

func makeScanResultWithFindings(findings []scan.Finding) *scan.ScanResult {
	maxSev := scan.SeverityLow
	for _, f := range findings {
		if f.Severity.Value() > maxSev.Value() {
			maxSev = f.Severity
		}
	}
	return &scan.ScanResult{
		ID:            "scan-123",
		RequestID:     "req-123",
		TenantID:      "tenant-1",
		ScannedAt:     time.Now(),
		ScanProfile:   scan.ProfileFull,
		TrustTier:     scan.TierExternal,
		Findings:      findings,
		TotalFindings: len(findings),
		MaxSeverity:   maxSev,
		IsCompliant:   len(findings) == 0,
	}
}

// --- Tests ---

func TestNewProcessor(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		scanner := &mockScanner{}
		p := NewProcessor(scanner)

		if p.scanner == nil {
			t.Fatal("expected scanner to be set")
		}
		if p.config == nil {
			t.Fatal("expected config to be set")
		}
		if p.config.ServiceID != "gatekeeper" {
			t.Errorf("expected default ServiceID 'gatekeeper', got %q", p.config.ServiceID)
		}
		if p.attestor != nil {
			t.Error("expected attestor to be nil by default")
		}
		if p.engine != nil {
			t.Error("expected engine to be nil by default")
		}
		if p.streamer != nil {
			t.Error("expected streamer to be nil by default")
		}
	})

	t.Run("custom config with all options", func(t *testing.T) {
		scanner := &mockScanner{}
		attestor := &mockAttestor{}
		engine := &mockEngine{}
		streamer := &mockStreamer{}
		cfg := &ProcessorConfig{
			ServiceID:         "test-service",
			EnableAttestation: true,
			EnableStreaming:   true,
			EnableActions:     true,
			HonorAttestations: true,
			AttestationTTL:    10 * time.Minute,
			ScanTimeout:       5 * time.Second,
			ActionTimeout:     3 * time.Second,
		}

		p := NewProcessor(scanner,
			WithAttestor(attestor),
			WithActionEngine(engine),
			WithStreamer(streamer),
			WithConfig(cfg),
		)

		if p.scanner == nil {
			t.Fatal("expected scanner to be set")
		}
		if p.attestor == nil {
			t.Fatal("expected attestor to be set")
		}
		if p.engine == nil {
			t.Fatal("expected engine to be set")
		}
		if p.streamer == nil {
			t.Fatal("expected streamer to be set")
		}
		if p.config.ServiceID != "test-service" {
			t.Errorf("expected ServiceID 'test-service', got %q", p.config.ServiceID)
		}
		if p.config.AttestationTTL != 10*time.Minute {
			t.Errorf("expected AttestationTTL 10m, got %v", p.config.AttestationTTL)
		}
	})

	t.Run("nil config option does not overwrite default", func(t *testing.T) {
		scanner := &mockScanner{}
		p := NewProcessor(scanner, WithConfig(nil))
		if p.config == nil {
			t.Fatal("expected default config to be preserved")
		}
		if p.config.ServiceID != "gatekeeper" {
			t.Errorf("expected default ServiceID, got %q", p.config.ServiceID)
		}
	})
}

func TestProcess_FullFlow(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "ssn", scan.SeverityHigh),
		makeFinding("f-2", "email", scan.SeverityMedium),
	}
	scanResult := makeScanResultWithFindings(findings)

	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return scanResult, nil
		},
	}

	attestorCalled := false
	attestor := &mockAttestor{
		createFunc: func(ctx context.Context, req attest.CreateRequest) (*types.Attestation, error) {
			attestorCalled = true
			return &types.Attestation{
				ID:          "attest-1",
				ContentHash: "hash",
				ScannedBy:   req.ServiceID,
				ExpiresAt:   time.Now().Add(5 * time.Minute),
			}, nil
		},
	}

	engineEvalCalled := false
	engine := &mockEngine{
		evaluateFunc: func(ctx context.Context, req action.EvaluateRequest) (*action.EvaluateResult, error) {
			engineEvalCalled = true
			if len(req.Findings) != 2 {
				t.Errorf("expected 2 findings in evaluate request, got %d", len(req.Findings))
			}
			return &action.EvaluateResult{
				ShouldBlock:  false,
				MatchedRules: []action.MatchedRule{},
				Actions:      []action.ActionToTake{},
			}, nil
		},
	}

	streamer := &mockStreamer{}

	p := NewProcessor(scanner,
		WithAttestor(attestor),
		WithActionEngine(engine),
		WithStreamer(streamer),
		WithConfig(&ProcessorConfig{
			ServiceID:         "test-svc",
			EnableAttestation: true,
			EnableStreaming:   true,
			EnableActions:     true,
			HonorAttestations: true,
			ScanTimeout:       5 * time.Second,
			ActionTimeout:     3 * time.Second,
			AttestationTTL:    5 * time.Minute,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content with SSN 123-45-6789"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-1",
		UserID:      "user-1",
		Source:      "llm_input",
		ContentType: "chat",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped {
		t.Error("expected result to not be skipped")
	}
	if result.ScanResult == nil {
		t.Fatal("expected scan result to be set")
	}
	if result.ScanResult.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", result.ScanResult.TotalFindings)
	}
	if !attestorCalled {
		t.Error("expected attestor.Create to be called")
	}
	if result.Attestation == nil {
		t.Error("expected attestation to be set")
	}
	if !engineEvalCalled {
		t.Error("expected engine.Evaluate to be called")
	}
	if result.Metrics.ScanDuration == 0 {
		t.Error("expected scan duration to be > 0")
	}
	if result.Metrics.ContentSize != len("test content with SSN 123-45-6789") {
		t.Errorf("expected content size %d, got %d",
			len("test content with SSN 123-45-6789"), result.Metrics.ContentSize)
	}
	if result.Metrics.FindingsCount != 2 {
		t.Errorf("expected findings count 2, got %d", result.Metrics.FindingsCount)
	}

	// Give the goroutine time to run
	time.Sleep(50 * time.Millisecond)
	if streamer.getStreamedCount() != 2 {
		t.Errorf("expected 2 findings streamed, got %d", streamer.getStreamedCount())
	}
}

func TestProcess_CleanContent(t *testing.T) {
	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return makeScanResultWithFindings(nil), nil
		},
	}

	attestorCalled := false
	attestor := &mockAttestor{
		createFunc: func(ctx context.Context, req attest.CreateRequest) (*types.Attestation, error) {
			attestorCalled = true
			return &types.Attestation{
				ID:          "attest-clean",
				ContentHash: "hash",
				Clean:       true,
			}, nil
		},
	}

	engineCalled := false
	engine := &mockEngine{
		evaluateFunc: func(ctx context.Context, req action.EvaluateRequest) (*action.EvaluateResult, error) {
			engineCalled = true
			return nil, nil
		},
	}

	streamer := &mockStreamer{}

	p := NewProcessor(scanner,
		WithAttestor(attestor),
		WithActionEngine(engine),
		WithStreamer(streamer),
		WithConfig(&ProcessorConfig{
			ServiceID:         "test-svc",
			EnableAttestation: true,
			EnableStreaming:   true,
			EnableActions:     true,
			HonorAttestations: true,
			AttestationTTL:    5 * time.Minute,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("clean content with no PII"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-2",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped {
		t.Error("expected result to not be skipped")
	}
	if result.ScanResult == nil {
		t.Fatal("expected scan result to be set")
	}
	if result.ScanResult.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", result.ScanResult.TotalFindings)
	}
	if !attestorCalled {
		t.Error("expected attestor.Create to be called for clean content")
	}
	if result.Attestation == nil {
		t.Error("expected attestation to be set for clean content")
	}
	if engineCalled {
		t.Error("expected engine.Evaluate to NOT be called with 0 findings")
	}

	// Streamer should not be called with 0 findings
	time.Sleep(50 * time.Millisecond)
	if streamer.getStreamedCount() != 0 {
		t.Errorf("expected 0 findings streamed for clean content, got %d", streamer.getStreamedCount())
	}
}

func TestProcess_AttestationSkip(t *testing.T) {
	scanCalled := false
	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			scanCalled = true
			return nil, nil
		},
	}

	existingAttestation := &types.Attestation{
		ID:          "existing-attest",
		ContentHash: "hash",
		ScannedBy:   "upstream-svc",
		ScanProfile: "full",
		TrustTier:   "external",
		TenantID:    "tenant-1",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	attestor := &mockAttestor{
		canSkipFunc: func(ctx context.Context, req attest.SkipCheckRequest) (bool, string) {
			if req.Attestation == existingAttestation {
				return true, "valid attestation from upstream-svc"
			}
			return false, ""
		},
	}

	p := NewProcessor(scanner,
		WithAttestor(attestor),
		WithConfig(&ProcessorConfig{
			ServiceID:         "test-svc",
			EnableAttestation: true,
			HonorAttestations: true,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-3",
		Attestation: existingAttestation,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Skipped {
		t.Error("expected result to be skipped")
	}
	if result.SkipReason == "" {
		t.Error("expected skip reason to be set")
	}
	if result.Attestation != existingAttestation {
		t.Error("expected existing attestation to be returned")
	}
	if result.Metrics.AttestationSkipped != true {
		t.Error("expected metrics.AttestationSkipped to be true")
	}
	if scanCalled {
		t.Error("expected scanner.Scan to NOT be called when attestation skip succeeds")
	}
}

func TestProcess_ScannerOnly(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "email", scan.SeverityMedium),
	}
	scanResult := makeScanResultWithFindings(findings)

	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return scanResult, nil
		},
	}

	// No attestor, no engine, no streamer
	p := NewProcessor(scanner)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content with email test@example.com"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-4",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped {
		t.Error("expected result to not be skipped")
	}
	if result.ScanResult == nil {
		t.Fatal("expected scan result to be set")
	}
	if result.ScanResult.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", result.ScanResult.TotalFindings)
	}
	if result.Attestation != nil {
		t.Error("expected no attestation when attestor is nil")
	}
	if result.ActionResult != nil {
		t.Error("expected no action result when engine is nil")
	}
}

func TestProcess_ActionBlock(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "ssn", scan.SeverityCritical),
	}
	scanResult := makeScanResultWithFindings(findings)

	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return scanResult, nil
		},
	}

	engine := &mockEngine{
		evaluateFunc: func(ctx context.Context, req action.EvaluateRequest) (*action.EvaluateResult, error) {
			return &action.EvaluateResult{
				ShouldBlock: true,
				BlockReason: "Critical SSN detected",
				MatchedRules: []action.MatchedRule{
					{
						Rule:       &action.Rule{ID: "critical-block"},
						FindingIDs: []string{"f-1"},
					},
				},
				Actions: []action.ActionToTake{
					{
						RuleID:     "critical-block",
						Type:       action.ActionBlock,
						FindingIDs: []string{"f-1"},
					},
				},
			}, nil
		},
		executeFunc: func(ctx context.Context, result *action.EvaluateResult) (*types.ActionResult, error) {
			return &types.ActionResult{
				Blocked:      true,
				BlockReason:  result.BlockReason,
				RulesMatched: []string{"critical-block"},
				Actions: []types.ActionTaken{
					{
						RuleID:     "critical-block",
						ActionType: "block",
						Success:    true,
					},
				},
			}, nil
		},
	}

	p := NewProcessor(scanner,
		WithActionEngine(engine),
		WithConfig(&ProcessorConfig{
			ServiceID:     "test-svc",
			EnableActions: true,
			ActionTimeout: 3 * time.Second,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("critical content"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-5",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ActionResult == nil {
		t.Fatal("expected action result to be set")
	}
	if !result.ActionResult.Blocked {
		t.Error("expected action result to indicate blocked")
	}
	if result.ActionResult.BlockReason != "Critical SSN detected" {
		t.Errorf("expected block reason 'Critical SSN detected', got %q", result.ActionResult.BlockReason)
	}
	if len(result.ActionResult.RulesMatched) != 1 {
		t.Errorf("expected 1 matched rule, got %d", len(result.ActionResult.RulesMatched))
	}
}

func TestProcess_StreamerError(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "email", scan.SeverityMedium),
	}
	scanResult := makeScanResultWithFindings(findings)

	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return scanResult, nil
		},
	}

	streamerErrorCalled := make(chan struct{}, 1)
	streamer := &mockStreamer{
		streamFunc: func(ctx context.Context, findings []stream.Finding) error {
			streamerErrorCalled <- struct{}{}
			return fmt.Errorf("kafka connection failed")
		},
	}

	p := NewProcessor(scanner,
		WithStreamer(streamer),
		WithConfig(&ProcessorConfig{
			ServiceID:      "test-svc",
			EnableStreaming: true,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-6",
	})

	// Streamer error should not cause Process to fail
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScanResult == nil {
		t.Fatal("expected scan result to be set")
	}
	if result.ScanResult.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", result.ScanResult.TotalFindings)
	}

	// Wait for the async goroutine to run
	select {
	case <-streamerErrorCalled:
		// Streamer was called and returned error, but Process succeeded
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for streamer to be called")
	}
}

func TestProcess_ScannerError(t *testing.T) {
	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return nil, fmt.Errorf("scanner internal error")
		},
	}

	p := NewProcessor(scanner)

	_, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-7",
	})

	if err == nil {
		t.Fatal("expected error from scanner failure")
	}
	if err.Error() != "scan failed: scanner internal error" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestProcess_HonorAttestationsDisabled(t *testing.T) {
	scanCalled := false
	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			scanCalled = true
			return makeScanResultWithFindings(nil), nil
		},
	}

	canSkipCalled := false
	attestor := &mockAttestor{
		canSkipFunc: func(ctx context.Context, req attest.SkipCheckRequest) (bool, string) {
			canSkipCalled = true
			return true, "should be ignored"
		},
	}

	p := NewProcessor(scanner,
		WithAttestor(attestor),
		WithConfig(&ProcessorConfig{
			ServiceID:         "test-svc",
			HonorAttestations: false, // Disabled
			EnableAttestation: false,
		}),
	)

	existingAttestation := &types.Attestation{
		ID: "existing",
	}

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-8",
		Attestation: existingAttestation,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped {
		t.Error("expected result to not be skipped when HonorAttestations is false")
	}
	if canSkipCalled {
		t.Error("expected CanSkip to NOT be called when HonorAttestations is false")
	}
	if !scanCalled {
		t.Error("expected scanner to be called")
	}
}

func TestProcess_SkipStreaming(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "email", scan.SeverityMedium),
	}
	scanResult := makeScanResultWithFindings(findings)

	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return scanResult, nil
		},
	}

	streamer := &mockStreamer{}

	p := NewProcessor(scanner,
		WithStreamer(streamer),
		WithConfig(&ProcessorConfig{
			ServiceID:      "test-svc",
			EnableStreaming: true,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:       []byte("test content"),
		TrustTier:     scan.TierExternal,
		ScanProfile:   scan.ProfileFull,
		TenantID:      "tenant-1",
		RequestID:     "req-9",
		SkipStreaming:  true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScanResult == nil {
		t.Fatal("expected scan result to be set")
	}

	// Give time for any async operations
	time.Sleep(50 * time.Millisecond)
	if streamer.getStreamedCount() != 0 {
		t.Errorf("expected 0 findings streamed when SkipStreaming is true, got %d", streamer.getStreamedCount())
	}
}

func TestScanOnly(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "ssn", scan.SeverityHigh),
	}
	scanResult := makeScanResultWithFindings(findings)

	var receivedConfig *scan.ScanConfig
	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			receivedConfig = config
			return scanResult, nil
		},
	}

	p := NewProcessor(scanner)

	config := &scan.ScanConfig{
		Profile:   scan.ProfilePIIOnly,
		TrustTier: scan.TierPartner,
	}

	result, err := p.ScanOnly(context.Background(), []byte("test content"), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected scan result to be set")
	}
	if result.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", result.TotalFindings)
	}
	if receivedConfig != config {
		t.Error("expected scan config to be passed through to scanner")
	}
}

func TestVerify(t *testing.T) {
	t.Run("with attestor - valid", func(t *testing.T) {
		attestor := &mockAttestor{
			verifyFunc: func(ctx context.Context, attestation *types.Attestation) error {
				return nil
			},
		}

		p := NewProcessor(&mockScanner{}, WithAttestor(attestor))

		valid, err := p.Verify(types.Attestation{
			ID:        "test-attest",
			Signature: "valid-sig",
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Error("expected attestation to be valid")
		}
	})

	t.Run("with attestor - invalid", func(t *testing.T) {
		attestor := &mockAttestor{
			verifyFunc: func(ctx context.Context, attestation *types.Attestation) error {
				return fmt.Errorf("signature mismatch")
			},
		}

		p := NewProcessor(&mockScanner{}, WithAttestor(attestor))

		valid, err := p.Verify(types.Attestation{
			ID:        "test-attest",
			Signature: "invalid-sig",
		})

		if err == nil {
			t.Fatal("expected error for invalid attestation")
		}
		if valid {
			t.Error("expected attestation to be invalid")
		}
	})

	t.Run("without attestor", func(t *testing.T) {
		p := NewProcessor(&mockScanner{})

		valid, err := p.Verify(types.Attestation{
			ID: "test-attest",
		})

		if err == nil {
			t.Fatal("expected error when no attestor configured")
		}
		if valid {
			t.Error("expected invalid when no attestor configured")
		}
	})
}

func TestClose(t *testing.T) {
	t.Run("closes engine and streamer", func(t *testing.T) {
		engine := &mockEngine{}
		streamer := &mockStreamer{}

		p := NewProcessor(&mockScanner{},
			WithActionEngine(engine),
			WithStreamer(streamer),
		)

		err := p.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !engine.isClosed() {
			t.Error("expected engine to be closed")
		}
		if !streamer.isClosed() {
			t.Error("expected streamer to be closed")
		}
	})

	t.Run("handles nil components", func(t *testing.T) {
		p := NewProcessor(&mockScanner{})

		err := p.Close()
		if err != nil {
			t.Fatalf("unexpected error when closing with nil components: %v", err)
		}
	})

	t.Run("only engine set", func(t *testing.T) {
		engine := &mockEngine{}

		p := NewProcessor(&mockScanner{}, WithActionEngine(engine))

		err := p.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !engine.isClosed() {
			t.Error("expected engine to be closed")
		}
	})

	t.Run("only streamer set", func(t *testing.T) {
		streamer := &mockStreamer{}

		p := NewProcessor(&mockScanner{}, WithStreamer(streamer))

		err := p.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !streamer.isClosed() {
			t.Error("expected streamer to be closed")
		}
	})
}

func TestProcess_ActionEvaluateError(t *testing.T) {
	findings := []scan.Finding{
		makeFinding("f-1", "ssn", scan.SeverityHigh),
	}
	scanResult := makeScanResultWithFindings(findings)

	scanner := &mockScanner{
		scanFunc: func(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
			return scanResult, nil
		},
	}

	engine := &mockEngine{
		evaluateFunc: func(ctx context.Context, req action.EvaluateRequest) (*action.EvaluateResult, error) {
			return nil, fmt.Errorf("rule evaluation error")
		},
	}

	p := NewProcessor(scanner,
		WithActionEngine(engine),
		WithConfig(&ProcessorConfig{
			ServiceID:     "test-svc",
			EnableActions: true,
		}),
	)

	result, err := p.Process(context.Background(), ProcessRequest{
		Content:     []byte("test content"),
		TrustTier:   scan.TierExternal,
		ScanProfile: scan.ProfileFull,
		TenantID:    "tenant-1",
		RequestID:   "req-10",
	})

	// Action evaluation errors are non-fatal
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScanResult == nil {
		t.Fatal("expected scan result to be set despite action error")
	}
	if result.ActionResult != nil {
		t.Error("expected no action result when evaluation fails")
	}
}

func TestProcess_InterfaceCompliance(t *testing.T) {
	// Verify that defaultProcessor implements Processor interface
	var _ Processor = (*defaultProcessor)(nil)
}
