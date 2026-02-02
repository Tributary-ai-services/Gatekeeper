# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is **Gatekeeper** (also known as `tas-contentintel`) - a unified content scanning, extraction, and compliance library for the TAS platform. This library provides high-performance content analysis capabilities shared across TAS services including TAS LLM Router, TAS MCP Proxy, Audimodal, and Aether-BE.

**Design Document**: See `parital-design.md` for the complete architecture specification.

**Core Capabilities**:
- PII detection (15+ types: SSN, credit cards, emails, phone numbers, medical records, etc.)
- Compliance framework scanning (HIPAA, GDPR, SOX, PCI-DSS)
- Injection detection (SQL injection, prompt injection)
- Content extraction using embedding + SLM for large context optimization
- PII tokenization via Databunker integration
- Scan attestation to prevent duplicate scanning across services
- Real-time findings streaming to Kafka
- Rule-based action engine (block, redact, alert, quarantine)

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

## Technology Stack

### Core Technologies
- **Language**: Go 1.21+
- **Pattern Matching**: Hyperscan (Intel high-performance regex library)
- **Caching**: Redis (attestation caching)
- **Streaming**: Apache Kafka (findings and audit events)
- **PII Tokenization**: Databunker
- **Embedding/Extraction**: Ollama (Phi-3.5-mini or Qwen2.5-3B)
- **HTTP Framework**: Gin (for middleware)
- **gRPC**: For MCP integration

### Key Dependencies
```go
require (
    github.com/flier/gohs           // Hyperscan bindings
    github.com/Shopify/sarama       // Kafka client
    github.com/redis/go-redis/v9    // Redis client
    github.com/jackc/pgx/v5         // PostgreSQL (TimescaleDB)
    github.com/gin-gonic/gin        // HTTP middleware
    google.golang.org/grpc          // gRPC middleware
)
```

## Repository Structure

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

## Common Commands

### Build & Development

```bash
# Build the library
make build

# Run unit tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Run security scan
make security

# Full CI pipeline
make ci

# Build standalone service binary
make build-server

# Build Docker image
make docker-build

# Run development dependencies (Redis, Kafka, Ollama)
make dev-services
```

### Code Generation

```bash
# Generate Hyperscan pattern database
make generate-patterns

# Generate protobuf files (if using gRPC service)
make proto

# Generate mocks for testing
make generate-mocks
```

### Testing

```bash
# Unit tests
go test ./...

# Integration tests (requires running services)
make test-integration

# Benchmark tests
make benchmark

# Test specific package
go test -v ./pkg/scan/...

# Test with race detection
go test -race ./...
```

## Core Interfaces

### Main Processor Interface

```go
type Processor interface {
    Process(ctx context.Context, req ProcessRequest) (*ProcessResult, error)
    ScanOnly(ctx context.Context, content []byte, tier TrustTier) (*ScanResult, error)
    Verify(attestation Attestation) (bool, error)
}

type ProcessRequest struct {
    Content       []byte
    QueryContext  string      // For relevance extraction
    TrustTier     TrustTier   // Internal, Partner, External
    ScanProfile   string      // "full", "pii_only", "injection_only"
    TenantID      string
    RequestID     string
    UserID        string
    Source        string      // "llm_input", "mcp_response", "upload"
    MCPServerID   string      // If from MCP
    ContentType   string      // "chat", "document", "tool_response"
    Attestation   *Attestation
}
```

### Trust Tiers

```go
type TrustTier int

const (
    TierInternal TrustTier = iota  // Your own services, system prompts
    TierPartner                     // Known third-party MCP servers
    TierExternal                    // Untrusted user input, unknown MCP servers
)
```

### Scan Profiles

```go
type ScanProfile string

const (
    ProfileFull          ScanProfile = "full"
    ProfileCompliance    ScanProfile = "compliance"
    ProfilePIIOnly       ScanProfile = "pii_only"
    ProfileInjectionOnly ScanProfile = "injection_only"
)
```

## Configuration

Main configuration file: `configs/contentintel.yaml`

```yaml
databunker:
  url: "http://databunker:3000"
  api_key: "${DATABUNKER_API_KEY}"
  timeout: 5s

attestation:
  signing_key_name: "tas-scan-signing-key"
  ttl: 5m
  service_id: "tas-llm-router"

scanning:
  default_profile: "full"
  honor_attestations: true
  hyperscan:
    block_size: 65536
    scratch_pool_size: 4
  redaction:
    mode: "tokenize"  # "mask", "tokenize", "remove"
    tokenize_types:
      - email
      - ssn
      - credit_card
      - phone
      - medical_record_number
    mask_types:
      - ip_address
      - date_of_birth

extraction:
  enabled: true
  embedding_model: "all-MiniLM-L6-v2"
  slm:
    url: "http://ollama:11434"
    model: "phi3.5"
    timeout: 30s
  relevance_threshold: 0.3

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

## Kafka Topics

```
tas.compliance.findings          # All findings (high volume)
tas.compliance.findings.critical # Critical only (alerts)
tas.compliance.findings.hipaa    # HIPAA-specific
tas.compliance.findings.pci      # PCI-DSS specific
tas.compliance.actions           # Action results
tas.compliance.audit             # Audit log (immutable)
```

## HTTP Headers

The library uses standard HTTP headers for attestation propagation:

```
X-TAS-Scan-Attestation: <base64-encoded signed attestation>
X-TAS-Scan-Status: clean | violations | tokenized | skipped
X-TAS-Scan-Request-ID: <correlation ID>
```

## Integration with TAS Services

### LLM Router Integration

```go
result, err := r.contentIntel.Process(ctx, contentintel.ProcessRequest{
    Content:      marshalMessages(req.Messages),
    TrustTier:    contentintel.TierExternal,  // User input
    ScanProfile:  "full",
    TenantID:     getTenantID(ctx),
    RequestID:    getRequestID(ctx),
    Source:       "llm_input",
    Attestation:  getAttestationFromHeader(ctx),
})
```

### MCP Proxy Integration

```go
result, err := p.contentIntel.Process(ctx, contentintel.ProcessRequest{
    Content:      resp.Body,
    QueryContext: p.currentQuery,  // For extraction
    TrustTier:    p.getTrustTier(resp.ServerID),
    ScanProfile:  "full",
    Source:       "mcp_response",
    MCPServerID:  resp.ServerID,
})
```

### HTTP Middleware (Gin)

```go
router.Use(contentintel.ScanMiddleware(processor, contentintel.MiddlewareConfig{
    ScanProfile: "full",
    TrustTier:   contentintel.TierExternal,
}))
```

## Action Rules

Default rules for automated responses:

| Rule | Conditions | Actions |
|------|------------|---------|
| critical-block | severity == CRITICAL | block, alert(pagerduty, slack), create_incident |
| pci-redact | pattern_id == credit_card | redact, log |
| hipaa-phi-block | frameworks contains HIPAA, severity in [CRITICAL, HIGH] | block, alert(slack), webhook |
| sqli-block | pattern_id == sql_injection | block, alert(security team) |
| mcp-anomaly | source == mcp_response, rate > 50/min | block_mcp_server(5m), alert |

## Performance Targets

- **Scan performance**: <5ms for 200KB context on dedicated nodes
- **Skip rate**: >80% of content skipped due to valid attestation
- **False positive rate**: <0.1% for PII detection
- **Action latency**: <100ms from finding to action (block/alert)

## Development Workflow

### Setting Up Development Environment

1. **Install Hyperscan** (required for scanning):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libhyperscan-dev

   # macOS
   brew install hyperscan
   ```

2. **Start development services**:
   ```bash
   make dev-services
   ```

3. **Run tests**:
   ```bash
   make test
   ```

### Testing Strategy

- **Unit tests**: Mock Hyperscan, Redis, Kafka for fast isolated tests
- **Integration tests**: Use testcontainers for real service dependencies
- **Benchmark tests**: Measure scan latency for various content sizes
- **Contract tests**: Verify attestation format compatibility

## Data Models & Documentation

### TAS Platform Data Models

The TAS platform maintains comprehensive data model documentation at:

**Main Documentation Hub**: `../aether-shared/data-models/`

Key references:
- **README**: [`../aether-shared/data-models/README.md`](../aether-shared/data-models/README.md) - Navigation hub
- **Index**: [`../aether-shared/data-models/INDEX.md`](../aether-shared/data-models/INDEX.md) - Complete model reference
- **Quick Start**: [`../aether-shared/data-models/overview/QUICK-START.md`](../aether-shared/data-models/overview/QUICK-START.md)
- **Cross-Service Integration**: [`../aether-shared/data-models/cross-service/`](../aether-shared/data-models/cross-service/)

### Related Service Data Models

- **AudiModal** (source of PII patterns): `../aether-shared/data-models/audimodal/`
- **TAS LLM Router** (integration point): `../aether-shared/data-models/tas-llm-router/`
- **TAS-MCP** (integration point): `../aether-shared/data-models/tas-mcp/`
- **DeepLake API** (vector operations): `../aether-shared/data-models/deeplake-api/`

### OpenAPI Documentation

When implementing the standalone service, maintain OpenAPI specs at:
- `api/openapi.yaml` - REST API specification
- Interactive docs at `/swagger` endpoint

## Monitoring & Observability

### Prometheus Metrics

The library exposes metrics at `/metrics`:

```
# Scan metrics
contentintel_scan_duration_seconds{profile,trust_tier}
contentintel_scan_findings_total{pattern_type,severity,framework}
contentintel_scan_skip_total{reason}

# Extraction metrics
contentintel_extract_duration_seconds
contentintel_extract_reduction_ratio

# Action metrics
contentintel_action_total{action_type,rule_id}
contentintel_action_latency_seconds{action_type}

# Attestation metrics
contentintel_attestation_created_total
contentintel_attestation_verified_total{valid}
contentintel_attestation_cache_hit_total
```

### Logging

Use structured JSON logging:

```go
log.Info("Scan completed",
    zap.String("request_id", requestID),
    zap.String("tenant_id", tenantID),
    zap.Int("findings_count", len(findings)),
    zap.Duration("duration", elapsed),
)
```

## Shared Infrastructure

This service uses the TAS shared infrastructure:

```yaml
REDIS_URL: "redis://tas-redis-shared:6379/0"
KAFKA_BROKERS: "tas-kafka-shared:9092"
DATABUNKER_URL: "http://tas-databunker-shared:3000"
OLLAMA_URL: "http://tas-ollama-shared:11434"
```

See `../aether-shared/services-and-ports.md` for complete port allocation.

## Migration from Existing Code

When implementing, extract patterns from:

### audimodal
- `internal/dlp/` or `pkg/dlp/` - DLP pipeline implementation
- `pkg/compliance/` - Compliance scanning
- PII patterns for 15+ types

### aether-be
- `internal/middleware/` - Compliance middleware

### tas-llm-router
- `llm-router-waf-design.md` - WAF design document
- `internal/server/` - Request validation

### tas-mcp
- `internal/forwarding/` - Event forwarding rules engine

## Important Files

- `parital-design.md` - Complete design specification
- `configs/contentintel.yaml` - Main configuration
- `configs/rules/` - Compliance rule definitions
- `.env` - Environment variables (never commit)

## Code Quality Standards

### Go Best Practices
- Use `context.Context` for all operations
- Proper error wrapping with `fmt.Errorf("...: %w", err)`
- Structured logging with zap
- Comprehensive test coverage (>80%)

### Security Considerations
- Never log actual PII values (use hashes or previews)
- Validate all inputs at service boundaries
- Use constant-time comparison for attestation signatures
- Rotate signing keys regularly

## Memories & Important Notes

- Always use Redux for managing state in frontend applications (when building dashboards)
- Keycloak authentication realm is `aether`
- Remember how to talk with Neo4j (for Aether-BE integration)
- Tests are not completed if there are failures - create a new agent to determine the reason and resolve the failure, then rerun the test
- The TAS platform uses a space-based multi-tenancy model (see `SPACE_BASED_IMPLEMENTATION_PLAN.md`)
- All services communicate via `tas-shared-network` Docker bridge network
- Use container names for service discovery (e.g., `tas-redis-shared`, `tas-kafka-shared`)

## Related Documentation

- TAS Platform Overview: `../README.md`
- Shared Infrastructure: `../README-SHARED-INFRASTRUCTURE.md`
- Services & Ports: `../aether-shared/services-and-ports.md`
- Data Models: `../aether-shared/data-models/README.md`
- Space-Based Architecture: `../SPACE_BASED_IMPLEMENTATION_PLAN.md`
