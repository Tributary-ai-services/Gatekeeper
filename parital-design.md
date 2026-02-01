# TAS Content Intelligence Library - Design Specification

## Executive Summary

This document captures the complete design for a unified content scanning, extraction, and compliance library (`tas-contentintel`) that will be shared across TAS services (LLM Router, MCP Proxy, Audimodal, Aether-BE). The goal is to consolidate existing scattered scanning code into a high-performance, reusable Go library with support for PII detection, compliance frameworks (HIPAA, GDPR, SOX, PCI-DSS), injection detection, and real-time streaming to Kafka for reporting and automated actions.

---

## Problem Statement

### Current State
- Scanning logic is spread across multiple repos:
  - `audimodal`: DLP pipelines, PII detection (15+ types), compliance scanning
  - `aether-be`: Compliance middleware
  - `tas-llm-router`: Request validation, WAF design
  - `tas-mcp`: Event forwarding rules, but no content scanning
- Previously achieved 98% headroom on RTOS for scanning workloads
- Now deployed in K8s, losing deterministic performance guarantees
- Context windows growing (8K → 128K → 200K+ tokens), making scan time a bottleneck

### Requirements
1. **Performance**: Scan large contexts without blocking LLM invocation
2. **Efficiency**: Content should only be scanned once, even if it flows through multiple services
3. **Deduplication**: Single pattern match should tag all applicable compliance frameworks
4. **Streaming**: Real-time findings to Kafka for dashboards, alerts, and actions
5. **Tokenization**: PII should be tokenized via Databunker, not just redacted
6. **Extraction**: Reduce content size before scanning using embedding + SLM

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Content Intelligence Library                        │
│                   (tas-contentintel)                                │
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  Extractor  │  │   Scanner   │  │  Attestor   │  │  Streamer  │ │
│  │ (embed+SLM) │  │ (Hyperscan) │  │ (sign+cache)│  │  (Kafka)   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
   ┌───────────┐    ┌───────────┐    ┌───────────────┐
   │ LLM Router│    │ MCP Proxy │    │ Standalone    │
   │ (linked)  │    │ (linked)  │    │ Service (API) │
   └───────────┘    └───────────┘    └───────────────┘
```

---

## Component Design

### 1. Repository Structure

```
github.com/Tributary-ai-services/tas-contentintel/
├── pkg/
│   ├── scan/
│   │   ├── hyperscan.go      # High-perf pattern matching
│   │   ├── pii.go            # PII detection patterns
│   │   ├── compliance.go     # SOX, HIPAA, GDPR, PCI-DSS rules
│   │   ├── injection.go      # SQL injection, prompt injection
│   │   ├── classifier.go     # Pattern → framework mapping
│   │   └── rules/            # Compiled rule sets (YAML)
│   ├── extract/
│   │   ├── chunker.go        # Text segmentation
│   │   ├── embedder.go       # Relevance scoring (vector similarity)
│   │   └── slm.go            # Ollama sidecar client for extraction
│   ├── attest/
│   │   ├── signer.go         # HMAC signing with Databunker key
│   │   ├── verifier.go       # Attestation verification
│   │   └── cache.go          # Redis-backed attestation cache
│   ├── tokenize/
│   │   ├── databunker.go     # Databunker client
│   │   └── detokenize.go     # Authorized detokenization service
│   ├── stream/
│   │   ├── kafka.go          # Async finding streaming
│   │   └── finding.go        # Finding data model
│   ├── action/
│   │   ├── engine.go         # Rule-based action engine
│   │   ├── rules.go          # Action rule definitions
│   │   └── alerter.go        # PagerDuty, Slack integration
│   └── pipeline/
│       └── processor.go      # Orchestrates extract → scan → attest
├── middleware/
│   ├── http.go               # Gin middleware for HTTP APIs
│   └── grpc.go               # gRPC interceptor for MCP
├── service/                   # Optional standalone service wrapper
│   ├── grpc.go
│   └── http.go
├── configs/
│   ├── rules/                # Compliance rule definitions
│   │   ├── pii.yaml
│   │   ├── hipaa.yaml
│   │   ├── gdpr.yaml
│   │   ├── sox.yaml
│   │   ├── pci_dss.yaml
│   │   └── injection.yaml
│   └── contentintel.yaml     # Main configuration
└── cmd/
    └── contentintel-server/   # Standalone service binary
```

### 2. Core Interfaces

```go
// pkg/contentintel/interfaces.go

package contentintel

import "context"

// Processor is the main entry point
type Processor interface {
    Process(ctx context.Context, req ProcessRequest) (*ProcessResult, error)
    ScanOnly(ctx context.Context, content []byte, tier TrustTier) (*ScanResult, error)
    Verify(attestation Attestation) (bool, error)
}

type ProcessRequest struct {
    Content       []byte
    QueryContext  string      // For relevance extraction (what user asked)
    TrustTier     TrustTier
    ScanProfile   string      // "full", "pii_only", "injection_only"
    TenantID      string
    RequestID     string
    UserID        string
    Source        string      // "llm_input", "mcp_response", "upload"
    MCPServerID   string      // If from MCP
    ContentType   string      // "chat", "document", "tool_response"
    
    // Existing attestation (from header)
    Attestation   *Attestation
}

type ProcessResult struct {
    Skipped         bool
    SkipReason      string      // "valid_attestation", "cache_hit"
    
    // Scan results
    ScanResult      *ScanResult
    
    // Modified content
    ExtractedContent []byte     // Relevance-filtered (if extraction enabled)
    RedactedContent  []byte     // With PII redacted/tokenized
    
    // Attestation for downstream
    Attestation     *Attestation
    
    // Action results (if violations found)
    ActionResult    *ActionResult
    
    // Metrics
    Metrics         ProcessMetrics
}

type TrustTier int

const (
    TierInternal TrustTier = iota  // Your own services, system prompts
    TierPartner                     // Known third-party MCP servers
    TierExternal                    // Untrusted user input, unknown MCP servers
)

type ScanProfile string

const (
    ProfileFull          ScanProfile = "full"
    ProfileCompliance    ScanProfile = "compliance"
    ProfilePIIOnly       ScanProfile = "pii_only"
    ProfileInjectionOnly ScanProfile = "injection_only"
)
```

### 3. Scanner with Hyperscan

```go
// pkg/scan/scanner.go

type Scanner struct {
    patterns    *hyperscan.BlockDatabase
    classifier  *Classifier
    databunker  *databunker.Client
    config      ScanConfig
}

type ScanConfig struct {
    RedactMode      RedactMode   // "mask", "tokenize", "remove"
    TokenizeTypes   []string     // PII types to store in Databunker
    MaskTypes       []string     // PII types to just mask
}

type RedactMode string

const (
    RedactMask     RedactMode = "mask"     // j***@***.com
    RedactTokenize RedactMode = "tokenize" // [email:abc12345]
    RedactRemove   RedactMode = "remove"   // [REDACTED]
)

func (s *Scanner) Scan(ctx context.Context, content []byte, opts ScanOptions) (*ScanResult, error)
```

### 4. Finding Data Model (Match Once, Tag Many)

```go
// pkg/stream/finding.go

// Finding represents a single deduplicated match tagged with all applicable frameworks
type Finding struct {
    ID            string            `json:"id"`
    RequestID     string            `json:"request_id"`
    Timestamp     time.Time         `json:"timestamp"`
    
    // Pattern info (what matched)
    PatternID     string            `json:"pattern_id"`    // "email", "ssn", "credit_card"
    PatternType   string            `json:"pattern_type"`  // "pii", "credential", "injection"
    
    // Location (where it matched)
    Source        string            `json:"source"`        // "llm_input", "mcp_response", "upload"
    Location      Location          `json:"location"`
    
    // Classification (all applicable frameworks)
    Frameworks    []Framework       `json:"frameworks"`    // ["PII", "HIPAA", "GDPR"]
    Severity      Severity          `json:"severity"`      // Aggregate (highest)
    
    // Context
    TenantID      string            `json:"tenant_id"`
    UserID        string            `json:"user_id,omitempty"`
    MCPServerID   string            `json:"mcp_server_id,omitempty"`
    ContentType   string            `json:"content_type"`
    
    // Value (safely handled - never log actual PII)
    ValueHash     string            `json:"value_hash"`
    ValuePreview  string            `json:"value_preview"` // "j***@***.com"
    
    // Outcome
    ActionTaken   string            `json:"action_taken"`  // "blocked", "redacted", "tokenized"
    Redacted      bool              `json:"redacted"`
    Tokenized     bool              `json:"tokenized"`
}

type Framework struct {
    ID          string   `json:"id"`          // "HIPAA", "GDPR", "SOX", "PCI_DSS"
    RuleID      string   `json:"rule_id"`     // "HIPAA-164.514"
    Severity    Severity `json:"severity"`
    Description string   `json:"description"`
}

type Location struct {
    Offset    int    `json:"offset"`
    Length    int    `json:"length"`
    FieldPath string `json:"field_path,omitempty"` // "messages[2].content"
}

type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)
```

### 5. Pattern → Framework Mapping

```go
// pkg/scan/classifier.go

// PatternFrameworks maps a pattern to all frameworks it can violate
var PatternFrameworks = map[string][]FrameworkRule{
    "email": {
        {Framework: "PII", RuleID: "PII-EMAIL", Severity: SeverityMedium},
        {Framework: "GDPR", RuleID: "GDPR-6.1", Severity: SeverityHigh,
         Condition: func(ctx Context) bool { return ctx.IsEUData() }},
        {Framework: "HIPAA", RuleID: "HIPAA-164.514", Severity: SeverityHigh,
         Condition: func(ctx Context) bool { return ctx.IsHealthcareContext() }},
    },
    "ssn": {
        {Framework: "PII", RuleID: "PII-SSN", Severity: SeverityCritical},
        {Framework: "GDPR", RuleID: "GDPR-9", Severity: SeverityCritical},
        {Framework: "SOX", RuleID: "SOX-302", Severity: SeverityHigh},
    },
    "credit_card": {
        {Framework: "PII", RuleID: "PII-FINANCIAL", Severity: SeverityCritical},
        {Framework: "PCI_DSS", RuleID: "PCI-3.4", Severity: SeverityCritical},
    },
    "sql_injection": {
        {Framework: "SECURITY", RuleID: "SEC-SQLI", Severity: SeverityCritical},
        {Framework: "SOX", RuleID: "SOX-404", Severity: SeverityHigh},
    },
    "prompt_injection": {
        {Framework: "SECURITY", RuleID: "SEC-PROMPT-INJ", Severity: SeverityHigh},
    },
}
```

### 6. Scan Attestation (Skip Re-scanning)

Content that has been scanned should not be re-scanned when it flows through multiple services.

```go
// pkg/attest/attestation.go

type Attestation struct {
    ID            string    `json:"id"`
    ContentHash   string    `json:"content_hash"`   // SHA-256 of scanned content
    
    ScanProfile   string    `json:"scan_profile"`
    RuleSetsUsed  []string  `json:"rule_sets"`
    
    Clean         bool      `json:"clean"`          // No violations found
    ViolationCount int      `json:"violation_count"`
    MaxSeverity   string    `json:"max_severity"`
    Redacted      bool      `json:"redacted"`
    Tokenized     bool      `json:"tokenized"`
    TokenCount    int       `json:"token_count"`
    
    ScannedAt     time.Time `json:"scanned_at"`
    ScannedBy     string    `json:"scanned_by"`     // Service ID
    TenantID      string    `json:"tenant_id"`
    RequestID     string    `json:"request_id"`
    TrustTier     string    `json:"trust_tier"`
    ExpiresAt     time.Time `json:"expires_at"`
    
    Signature     string    `json:"signature"`      // HMAC-SHA256
}
```

**HTTP Headers:**

```
X-TAS-Scan-Attestation: <base64-encoded signed attestation>
X-TAS-Scan-Status: clean | violations | tokenized | skipped
X-TAS-Scan-Request-ID: <correlation ID>
```

**Skip Logic:**

```go
func (p *Processor) canSkipScan(req ProcessRequest) (reason string, canSkip bool) {
    att := req.Attestation
    
    // 1. Verify signature
    if err := p.verifier.Verify(att); err != nil {
        return "", false
    }
    
    // 2. Verify content hash matches
    if sha256Hex(req.Content) != att.ContentHash {
        return "", false  // Content changed
    }
    
    // 3. Check tenant matches
    if att.TenantID != req.TenantID {
        return "", false
    }
    
    // 4. Check scan profile is sufficient
    if !p.profileSufficient(att.ScanProfile, req.ScanProfile) {
        return "upgrade_required", false
    }
    
    // 5. Check trust tier - if current is LESS trusted, must rescan
    if TrustTierFromString(att.TrustTier) > req.TrustTier {
        return "trust_escalation", false
    }
    
    return "valid_attestation", true
}
```

### 7. Databunker Integration

Databunker is used for:
1. **Signing key storage** - HMAC key for attestation signing
2. **PII tokenization** - Store actual PII, return opaque token
3. **Audit trail** - All access logged
4. **Consent management** - GDPR compliance

```go
// pkg/tokenize/databunker.go

type Client struct {
    baseURL    string
    apiKey     string
    httpClient *http.Client
}

// Tokenize stores PII in Databunker and returns a token
func (c *Client) Tokenize(ctx context.Context, req TokenizeRequest) (*TokenizeResponse, error)

// Detokenize retrieves PII for authorized users
func (c *Client) Detokenize(ctx context.Context, tenantID, piiType, recordKey string) (string, error)

// GetSecret retrieves signing key
func (c *Client) GetSecret(ctx context.Context, secretName string) ([]byte, error)

// LogAudit writes to Databunker's audit log
func (c *Client) LogAudit(ctx context.Context, event AuditEvent) error
```

**Tokenization flow:**

```
Original: "Contact john@acme.com for details"
                    ↓
Scan finds email at offset 8
                    ↓
Store in Databunker: {pii_type: "email", value: "john@acme.com", tenant_id: "..."}
                    ↓
Get back record_key: "abc12345"
                    ↓
Replace: "Contact [email:abc12345] for details"
```

### 8. Content Extraction (Reduce Scan Surface)

For large MCP tool responses, extract only relevant content before scanning.

```go
// pkg/extract/extractor.go

type Extractor struct {
    chunker   *Chunker
    embedder  *Embedder      // Vector similarity
    slm       *SLMClient     // Ollama sidecar
}

// Extract reduces content to relevant portions
func (e *Extractor) Extract(ctx context.Context, content []byte, query string) ([]byte, error) {
    // 1. Chunk content into paragraphs/sections
    chunks := e.chunker.Chunk(content)
    
    // 2. Embed query and chunks
    queryVec := e.embedder.Embed(query)
    chunkVecs := e.embedder.EmbedBatch(chunks)
    
    // 3. Keep top 30% by similarity
    topChunks := e.topBySimilarity(chunks, chunkVecs, queryVec, 0.3)
    
    // 4. Use SLM for intelligent extraction on survivors
    extracted, err := e.slm.Extract(ctx, topChunks, query)
    
    return extracted, err
}
```

**SLM sidecar (Ollama):**
- Model: Phi-3.5-mini (3.8B) or Qwen2.5-3B
- Runs as K8s sidecar or separate deployment
- ~100-500ms to summarize large response
- Prompt: "Extract only information relevant to: {query}"

### 9. Action Engine

```go
// pkg/action/engine.go

type Engine struct {
    rules       []Rule
    alerter     *Alerter
    redis       *redis.Client
    mcpBlocker  *MCPBlocker
    producer    sarama.AsyncProducer
}

type Rule struct {
    ID          string
    Name        string
    Priority    int           // Lower = higher priority
    Enabled     bool
    Conditions  []Condition
    Actions     []Action
    RateLimit   *RateLimit
    Cooldown    time.Duration
}

type ActionType string

const (
    ActionBlock       ActionType = "block"
    ActionRedact      ActionType = "redact"
    ActionAlert       ActionType = "alert"
    ActionQuarantine  ActionType = "quarantine"
    ActionLog         ActionType = "log"
    ActionWebhook     ActionType = "webhook"
    ActionIncident    ActionType = "create_incident"
    ActionMCPBlock    ActionType = "block_mcp_server"
)
```

**Default Rules (from config):**

| Rule | Conditions | Actions |
|------|------------|---------|
| critical-block | severity == CRITICAL | block, alert(pagerduty, slack), create_incident |
| pci-redact | pattern_id == credit_card | redact, log |
| hipaa-phi-block | frameworks contains HIPAA, severity in [CRITICAL, HIGH] | block, alert(slack), webhook |
| sqli-block | pattern_id == sql_injection | block, alert(security team) |
| mcp-anomaly | source == mcp_response, rate > 50/min | block_mcp_server(5m), alert |

---

## Kafka Streaming Architecture

### Topics

```
tas.compliance.findings          # All findings (high volume)
tas.compliance.findings.critical # Critical only (alerts)
tas.compliance.findings.hipaa    # HIPAA-specific
tas.compliance.findings.pci      # PCI-DSS specific
tas.compliance.actions           # Action results
tas.compliance.audit             # Audit log (immutable)
```

### Avro Schema

```json
{
  "type": "record",
  "name": "ComplianceFinding",
  "namespace": "com.tas.compliance",
  "fields": [
    {"name": "id", "type": "string"},
    {"name": "event_time", "type": {"type": "long", "logicalType": "timestamp-millis"}},
    {"name": "processing_time", "type": {"type": "long", "logicalType": "timestamp-millis"}},
    {"name": "tenant_id", "type": "string"},
    {"name": "request_id", "type": "string"},
    {"name": "pattern_id", "type": "string"},
    {"name": "pattern_type", "type": "string"},
    {"name": "source", "type": "string"},
    {"name": "mcp_server_id", "type": ["null", "string"], "default": null},
    {"name": "frameworks", "type": {"type": "array", "items": "string"}},
    {"name": "severity", "type": {"type": "enum", "name": "Severity", "symbols": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}},
    {"name": "action_taken", "type": ["null", "string"], "default": null},
    {"name": "redacted", "type": "boolean"},
    {"name": "tokenized", "type": "boolean"},
    {"name": "user_id", "type": ["null", "string"], "default": null},
    {"name": "content_type", "type": "string"},
    {"name": "value_hash", "type": "string"}
  ]
}
```

---

## Real-time Metrics & Reporting (Spark + Argo)

### Architecture

```
Kafka (tas.compliance.findings)
              │
    ┌─────────┴─────────┐
    │                   │
    ▼                   ▼
Spark Streaming     Spark Batch
(Speed Layer)       (True-up)
    │                   │
    ▼                   ▼
TimescaleDB         TimescaleDB
(realtime.*)        (batch.*)
    │                   │
    └─────────┬─────────┘
              │
              ▼
       Serving Layer
       (Merged Views)
```

### Spark Streaming Job

- **Trigger**: 30-second micro-batches
- **Watermark**: 2 minutes (late data tolerance)
- **Aggregations**:
  - Tenant summary (1-minute windows)
  - Pattern breakdown
  - Framework breakdown
  - MCP server health
- **Output**: TimescaleDB `realtime.*` tables
- **Retention**: 7 days

### Spark Batch True-up Job

- **Schedule**: 15 minutes past each hour (via Argo CronWorkflow)
- **Input**: Re-read Kafka for the previous hour
- **Output**: Exact counts to `batch.*` tables
- **Late arrival handling**: Separate job every 4 hours reprocesses hours with >100 late arrivals
- **Retention**: 90 days hourly, 2 years daily rollups

### Argo Workflows

```yaml
CronWorkflows:
  - compliance-hourly-trueup:     "15 * * * *"   # Hourly batch reconciliation
  - compliance-daily-rollup:      "0 2 * * *"    # Daily aggregation
  - compliance-late-reprocess:    "0 */4 * * *"  # Late arrival handling
  - compliance-data-cleanup:      "0 4 * * *"    # Retention enforcement

Event-Driven Workflows (via Argo Events):
  - Critical finding → PagerDuty alert
  - MCP anomaly → Block server + Slack alert
  - Manual reprocess webhook
```

### TimescaleDB Schema

**Realtime tables** (streaming layer):
- `realtime.tenant_summary_1m`
- `realtime.pattern_breakdown_1m`
- `realtime.framework_breakdown_1m`
- `realtime.mcp_health_1m`

**Batch tables** (true-up layer):
- `batch.tenant_summary_hourly`
- `batch.pattern_breakdown_hourly`
- `batch.framework_breakdown_hourly`
- `batch.tenant_summary_daily`

**Serving views** (merged):
- `serving.tenant_summary` - Current hour from streaming, previous from batch
- `serving.framework_summary`
- `serving.mcp_server_health` - With anomaly scores

### Monitoring

- `monitoring.streaming_batch_deltas` - Track accuracy of streaming vs batch
- `monitoring.late_arrivals` - Track reprocessing needs
- Alert if delta > 5%

---

## Integration Points

### LLM Router Integration

```go
// In tas-llm-router request handling
func (r *Router) handleChatCompletion(ctx context.Context, req *ChatRequest) {
    result, err := r.contentIntel.Process(ctx, contentintel.ProcessRequest{
        Content:      marshalMessages(req.Messages),
        TrustTier:    contentintel.TierExternal,  // User input
        ScanProfile:  "full",
        TenantID:     getTenantID(ctx),
        RequestID:    getRequestID(ctx),
        Source:       "llm_input",
        Attestation:  getAttestationFromHeader(ctx),
    })
    
    if result.ActionResult != nil && result.ActionResult.Blocked {
        return nil, &ComplianceError{Violations: result.ScanResult.Violations}
    }
    
    // Add attestation header for downstream
    ctx = setAttestationHeader(ctx, result.Attestation)
    
    // Use redacted content if applicable
    if result.RedactedContent != nil {
        req.Messages = unmarshalMessages(result.RedactedContent)
    }
    
    // Continue to LLM...
}
```

### MCP Proxy Integration

```go
// In tas-mcp tool response handling
func (p *MCPProxy) handleToolResponse(ctx context.Context, resp *ToolResponse) (*ToolResponse, error) {
    result, err := p.contentIntel.Process(ctx, contentintel.ProcessRequest{
        Content:      resp.Body,
        QueryContext: p.currentQuery,  // For extraction
        TrustTier:    p.getTrustTier(resp.ServerID),
        ScanProfile:  "full",
        TenantID:     getTenantID(ctx),
        RequestID:    getRequestID(ctx),
        Source:       "mcp_response",
        MCPServerID:  resp.ServerID,
        Attestation:  getAttestationFromHeader(ctx),
    })
    
    if result.ActionResult != nil && result.ActionResult.Blocked {
        return nil, &ComplianceError{...}
    }
    
    // Use extracted + scanned content
    resp.Body = result.ExtractedContent
    if resp.Body == nil {
        resp.Body = result.RedactedContent
    }
    resp.Attestation = result.Attestation
    
    return resp, nil
}
```

### HTTP Middleware

```go
// pkg/middleware/http.go

func ScanMiddleware(processor *Processor, config MiddlewareConfig) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract existing attestation
        var existingAtt *Attestation
        if header := c.GetHeader("X-TAS-Scan-Attestation"); header != "" {
            existingAtt, _ = DecodeHeader(header)
        }
        
        // Read body
        body, _ := io.ReadAll(c.Request.Body)
        c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
        
        // Process
        result, _ := processor.Process(c.Request.Context(), ProcessRequest{
            Content:     body,
            Attestation: existingAtt,
            // ... other fields from context
        })
        
        // Block if needed
        if result.ActionResult != nil && result.ActionResult.Blocked {
            c.AbortWithStatusJSON(403, gin.H{"error": "blocked", "request_id": result.Attestation.RequestID})
            return
        }
        
        // Inject attestation header
        c.Header("X-TAS-Scan-Attestation", EncodeHeader(result.Attestation))
        c.Header("X-TAS-Scan-Status", result.Attestation.Status())
        
        // Replace body if redacted
        if result.RedactedContent != nil {
            c.Request.Body = io.NopCloser(bytes.NewBuffer(result.RedactedContent))
        }
        
        c.Next()
    }
}
```

---

## Configuration

```yaml
# configs/contentintel.yaml

databunker:
  url: "http://databunker:3000"
  api_key: "${DATABUNKER_API_KEY}"
  timeout: 5s

attestation:
  signing_key_name: "tas-scan-signing-key"  # Key stored in Databunker
  ttl: 5m
  service_id: "tas-llm-router"  # Or "tas-mcp-proxy"

scanning:
  default_profile: "full"
  honor_attestations: true
  
  # Hyperscan settings
  hyperscan:
    block_size: 65536
    scratch_pool_size: 4
  
  redaction:
    mode: "tokenize"  # "mask", "tokenize", "remove"
    tokenize_types:   # Store in Databunker
      - email
      - ssn
      - credit_card
      - phone
      - medical_record_number
    mask_types:       # Just mask, don't store
      - ip_address
      - date_of_birth

extraction:
  enabled: true
  embedding_model: "all-MiniLM-L6-v2"
  slm:
    url: "http://ollama:11434"
    model: "phi3.5"
    timeout: 30s
  relevance_threshold: 0.3  # Keep top 30%

streaming:
  kafka:
    brokers:
      - "kafka:9092"
    topics:
      findings: "tas.compliance.findings"
      critical: "tas.compliance.findings.critical"
      actions: "tas.compliance.actions"
    batch_size: 100
    flush_interval: 1s

actions:
  enabled: true
  rules_file: "/configs/action_rules.yaml"
  alerting:
    slack_webhook: "${SLACK_WEBHOOK_URL}"
    pagerduty_key: "${PAGERDUTY_KEY}"

cache:
  redis:
    addr: "redis:6379"
    db: 0
  attestation_ttl: 5m
```

---

## Migration Path

### Phase 1: Extract from Audimodal (Week 1)
1. Create `tas-contentintel` repo
2. Extract PII detection patterns from audimodal `internal/dlp/` or `pkg/compliance/`
3. Extract compliance rules (HIPAA, SOX, etc.)
4. Set up Hyperscan integration
5. Basic scan interface working

### Phase 2: Add Attestation & Caching (Week 2)
1. Implement attestation signing with Databunker
2. Add Redis caching for attestations
3. HTTP header encoding/decoding
4. Skip logic for already-scanned content

### Phase 3: Tokenization & Extraction (Week 3)
1. Databunker tokenization integration
2. Embedding-based relevance filtering
3. Ollama SLM extraction client
4. Hybrid extraction pipeline

### Phase 4: Integration & Streaming (Week 4)
1. Integrate into tas-llm-router
2. Integrate into tas-mcp
3. Update audimodal to use shared library
4. Kafka streaming for findings
5. Action engine rules

### Phase 5: Reporting (Week 5)
1. Spark Structured Streaming job
2. Spark batch true-up job
3. Argo CronWorkflows
4. TimescaleDB schema
5. Dashboard API

---

## Existing Code to Review

When implementing, examine these files in the existing repos:

### audimodal
- `internal/dlp/` or `pkg/dlp/` - DLP pipeline implementation
- `pkg/compliance/` - Compliance scanning
- PII patterns for 15+ types (SSN, credit card, email, phone, etc.)

### aether-be
- `internal/middleware/` - Compliance middleware
- Request/response scanning integration

### tas-llm-router
- `llm-router-waf-design.md` - WAF design document
- `internal/server/` - Request validation

### tas-mcp
- `internal/forwarding/` - Event forwarding rules engine
- Can be extended for content scanning

---

## Go Dependencies

```go
// go.mod additions

require (
    github.com/flier/gohs v1.2.0           // Hyperscan bindings
    github.com/Shopify/sarama v1.40.0      // Kafka client
    github.com/redis/go-redis/v9 v9.3.0    // Redis client
    github.com/jackc/pgx/v5 v5.5.0         // PostgreSQL (TimescaleDB)
    github.com/gin-gonic/gin v1.9.1        // HTTP middleware
    google.golang.org/grpc v1.60.0         // gRPC middleware
)
```

---

## Success Metrics

1. **Scan performance**: <5ms for 200KB context on dedicated nodes
2. **Skip rate**: >80% of content skipped due to valid attestation
3. **Streaming/batch delta**: <5% difference between real-time and true-up counts
4. **Late arrival rate**: <1% of findings arrive >2 minutes late
5. **False positive rate**: <0.1% for PII detection
6. **Action latency**: <100ms from finding to action (block/alert)

---

## Open Questions for Implementation

1. What's the exact interface for compliance scanning in audimodal today?
2. What patterns are currently implemented vs. need to be added?
3. Is there existing Redis infrastructure we can use for attestation caching?
4. What's the current Kafka topic structure in tas-mcp?
5. Are there existing Argo WorkflowTemplates we should follow as patterns?
6. What's the authentication model for Databunker?

