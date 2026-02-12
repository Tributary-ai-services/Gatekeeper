package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/action"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/attest"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/stream"
)

// defaultProcessor implements the Processor interface, orchestrating
// the scan -> attest -> action -> stream pipeline.
type defaultProcessor struct {
	scanner  scan.Scanner
	attestor attest.Attestor
	engine   action.Engine
	streamer stream.Streamer
	config   *ProcessorConfig
}

// ProcessorOption is a functional option for configuring a defaultProcessor.
type ProcessorOption func(*defaultProcessor)

// WithAttestor sets the attestor on the processor.
func WithAttestor(a attest.Attestor) ProcessorOption {
	return func(p *defaultProcessor) {
		p.attestor = a
	}
}

// WithActionEngine sets the action engine on the processor.
func WithActionEngine(e action.Engine) ProcessorOption {
	return func(p *defaultProcessor) {
		p.engine = e
	}
}

// WithStreamer sets the streamer on the processor.
func WithStreamer(s stream.Streamer) ProcessorOption {
	return func(p *defaultProcessor) {
		p.streamer = s
	}
}

// WithConfig sets the processor configuration.
func WithConfig(cfg *ProcessorConfig) ProcessorOption {
	return func(p *defaultProcessor) {
		if cfg != nil {
			p.config = cfg
		}
	}
}

// NewProcessor creates a new defaultProcessor with the given scanner and options.
// The scanner is required; all other components are optional.
func NewProcessor(scanner scan.Scanner, opts ...ProcessorOption) *defaultProcessor {
	p := &defaultProcessor{
		scanner: scanner,
		config:  DefaultProcessorConfig(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Process performs the full content intelligence pipeline:
// check attestation -> scan -> evaluate actions -> create attestation -> stream findings.
func (p *defaultProcessor) Process(ctx context.Context, req ProcessRequest) (*ProcessResult, error) {
	startTime := time.Now()

	result := &ProcessResult{
		Metrics: ProcessMetrics{
			ContentSize: len(req.Content),
		},
	}

	// Step 1: Check existing attestation for skip
	if p.config.HonorAttestations && p.attestor != nil && req.Attestation != nil {
		canSkip, reason := p.attestor.CanSkip(ctx, attest.SkipCheckRequest{
			Attestation: req.Attestation,
			Content:     req.Content,
			TenantID:    req.TenantID,
			TrustTier:   req.TrustTier,
			ScanProfile: req.ScanProfile,
		})
		if canSkip {
			result.Skipped = true
			result.SkipReason = reason
			result.Attestation = req.Attestation
			result.Metrics.AttestationSkipped = true
			result.Metrics.TotalDuration = time.Since(startTime)
			return result, nil
		}
	}

	// Step 2: Build ScanConfig from request
	scanConfig := &scan.ScanConfig{
		Profile:   req.ScanProfile,
		TrustTier: req.TrustTier,
	}
	if p.config.ScanTimeout > 0 {
		scanConfig.Timeout = p.config.ScanTimeout
	}

	// Step 3: Scan content
	scanStart := time.Now()

	var scanCtx context.Context
	var scanCancel context.CancelFunc
	if p.config.ScanTimeout > 0 {
		scanCtx, scanCancel = context.WithTimeout(ctx, p.config.ScanTimeout)
	} else {
		scanCtx, scanCancel = context.WithCancel(ctx)
	}
	defer scanCancel()

	scanResult, err := p.scanner.Scan(scanCtx, req.Content, scanConfig)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	result.ScanResult = scanResult
	result.Metrics.ScanDuration = time.Since(scanStart)
	result.Metrics.FindingsCount = len(scanResult.Findings)

	// Step 4: Evaluate and execute actions if findings exist and actions are enabled
	if p.config.EnableActions && p.engine != nil && len(scanResult.Findings) > 0 {
		actionStart := time.Now()

		var actionCtx context.Context
		var actionCancel context.CancelFunc
		if p.config.ActionTimeout > 0 {
			actionCtx, actionCancel = context.WithTimeout(ctx, p.config.ActionTimeout)
		} else {
			actionCtx, actionCancel = context.WithCancel(ctx)
		}

		evalResult, err := p.engine.Evaluate(actionCtx, action.EvaluateRequest{
			Findings:    scanResult.Findings,
			ScanResult:  scanResult,
			RequestID:   req.RequestID,
			TenantID:    req.TenantID,
			UserID:      req.UserID,
			Source:      req.Source,
			MCPServerID: req.MCPServerID,
		})
		if err != nil {
			actionCancel()
			// Action evaluation failure is non-fatal; continue without actions
		} else {
			execResult, execErr := p.engine.Execute(actionCtx, evalResult)
			if execErr == nil {
				result.ActionResult = execResult
			}
		}

		actionCancel()
		result.Metrics.ActionDuration = time.Since(actionStart)
	}

	// Step 5: Create attestation if enabled
	if p.config.EnableAttestation && p.attestor != nil {
		attestStart := time.Now()

		attestation, err := p.attestor.Create(ctx, attest.CreateRequest{
			Content:     req.Content,
			ScanResult:  scanResult,
			TenantID:    req.TenantID,
			RequestID:   req.RequestID,
			ServiceID:   p.config.ServiceID,
			TrustTier:   req.TrustTier,
			ScanProfile: req.ScanProfile,
			TTL:         p.config.AttestationTTL,
		})
		if err == nil {
			result.Attestation = attestation
		}

		result.Metrics.AttestDuration = time.Since(attestStart)
	}

	// Step 6: Stream findings asynchronously if enabled and not skipped
	if p.config.EnableStreaming && p.streamer != nil && !req.SkipStreaming && len(scanResult.Findings) > 0 {
		streamFindings := make([]stream.Finding, len(scanResult.Findings))
		for i := range scanResult.Findings {
			streamFindings[i] = stream.ConvertFinding(
				&scanResult.Findings[i],
				req.RequestID,
				req.TenantID,
				req.UserID,
				req.Source,
				req.MCPServerID,
				req.ContentType,
			)
		}

		// Stream asynchronously to avoid blocking the response
		go func() {
			_ = p.streamer.Stream(context.Background(), streamFindings)
		}()
	}

	// Step 7: Set total duration
	result.Metrics.TotalDuration = time.Since(startTime)

	return result, nil
}

// ScanOnly performs scanning without attestation or actions.
func (p *defaultProcessor) ScanOnly(ctx context.Context, content []byte, config *scan.ScanConfig) (*scan.ScanResult, error) {
	return p.scanner.Scan(ctx, content, config)
}

// Verify verifies an attestation is valid.
func (p *defaultProcessor) Verify(attestation Attestation) (bool, error) {
	if p.attestor == nil {
		return false, fmt.Errorf("no attestor configured")
	}
	err := p.attestor.Verify(context.Background(), &attestation)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Close releases resources held by the processor's sub-components.
func (p *defaultProcessor) Close() error {
	var errs []error
	if p.engine != nil {
		if err := p.engine.Close(); err != nil {
			errs = append(errs, fmt.Errorf("engine close: %w", err))
		}
	}
	if p.streamer != nil {
		if err := p.streamer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("streamer close: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}
