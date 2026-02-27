package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/action"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/attest"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/extract"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/stream"
)

// defaultProcessor implements the Processor interface, orchestrating
// the scan -> attest -> action -> stream pipeline.
type defaultProcessor struct {
	scanner   scan.Scanner
	attestor  attest.Attestor
	engine    action.Engine
	streamer  stream.Streamer
	extractor extract.Extractor
	config    *ProcessorConfig
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

// WithExtractor sets the extractor on the processor.
func WithExtractor(e extract.Extractor) ProcessorOption {
	return func(p *defaultProcessor) {
		p.extractor = e
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

	// Step 2: Extract relevant content if enabled and content is large enough
	contentToScan := req.Content
	if p.config.EnableExtraction && p.extractor != nil && !req.SkipExtraction &&
		len(req.Content) > p.config.ExtractionThreshold {
		extractStart := time.Now()

		var extractCtx context.Context
		var extractCancel context.CancelFunc
		if p.config.ExtractionTimeout > 0 {
			extractCtx, extractCancel = context.WithTimeout(ctx, p.config.ExtractionTimeout)
		} else {
			extractCtx, extractCancel = context.WithCancel(ctx)
		}

		extractResult, extractErr := p.extractor.Extract(extractCtx, extract.ExtractRequest{
			Content:     req.Content,
			Query:       req.QueryContext,
			ContentType: req.ContentType,
		})
		extractCancel()

		if extractErr == nil && extractResult != nil && len(extractResult.Content) > 0 {
			contentToScan = extractResult.Content
			result.ExtractedContent = extractResult.Content
			result.Metrics.ExtractedSize = extractResult.ExtractedSize
			result.Metrics.ExtractionRatio = extractResult.ReductionRatio
		}
		// On extraction error, we scan original content (graceful degradation)
		result.Metrics.ExtractionDuration = time.Since(extractStart)
	}

	// Step 3: Build ScanConfig from request
	scanConfig := &scan.ScanConfig{
		Profile:   req.ScanProfile,
		TrustTier: req.TrustTier,
	}
	if p.config.ScanTimeout > 0 {
		scanConfig.Timeout = p.config.ScanTimeout
	}

	// Step 4: Scan content
	scanStart := time.Now()

	var scanCtx context.Context
	var scanCancel context.CancelFunc
	if p.config.ScanTimeout > 0 {
		scanCtx, scanCancel = context.WithTimeout(ctx, p.config.ScanTimeout)
	} else {
		scanCtx, scanCancel = context.WithCancel(ctx)
	}
	defer scanCancel()

	scanResult, err := p.scanner.Scan(scanCtx, contentToScan, scanConfig)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	result.ScanResult = scanResult
	result.Metrics.ScanDuration = time.Since(scanStart)
	result.Metrics.FindingsCount = len(scanResult.Findings)

	// Step 5: Evaluate and execute actions if findings exist and actions are enabled
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

	// Step 6: Create attestation if enabled
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

	// Step 7: Stream findings asynchronously if enabled and not skipped
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

	// Step 8: Set total duration
	result.Metrics.TotalDuration = time.Since(startTime)

	return result, nil
}

// Summarize produces a summary of content using the configured extractor.
func (p *defaultProcessor) Summarize(ctx context.Context, req SummarizeRequest) (*SummarizeResult, error) {
	if p.extractor == nil {
		return nil, fmt.Errorf("no extractor configured for summarization")
	}

	var summarizeCtx context.Context
	var summarizeCancel context.CancelFunc
	if p.config.ExtractionTimeout > 0 {
		summarizeCtx, summarizeCancel = context.WithTimeout(ctx, p.config.ExtractionTimeout)
	} else {
		summarizeCtx, summarizeCancel = context.WithCancel(ctx)
	}
	defer summarizeCancel()

	return p.extractor.Summarize(summarizeCtx, extract.SummarizeRequest{
		Content:     req.Content,
		Query:       req.Query,
		Strategy:    req.Strategy,
		MaxLength:   req.MaxLength,
		ContentType: req.ContentType,
	})
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
	if p.extractor != nil {
		if err := p.extractor.Close(); err != nil {
			errs = append(errs, fmt.Errorf("extractor close: %w", err))
		}
	}
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
