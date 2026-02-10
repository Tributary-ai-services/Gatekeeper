# Gatekeeper

TAS Gatekeeper is a unified content scanning, extraction, and compliance library for the TAS platform. It provides high-performance content analysis capabilities shared across TAS services including TAS LLM Router, TAS MCP Proxy, Audimodal, and Aether-BE.

## Features

- **PII Detection**: 21+ PII types including SSN, credit cards, emails, phone numbers, medical records
- **Credential Detection**: Multi-cloud coverage for AWS, Azure, GCP, JWT/OAuth, database connection strings, and 10+ SaaS providers (Stripe, SendGrid, Anthropic, HuggingFace, NPM, PyPI, etc.)
- **Compliance Scanning**: 12 frameworks — HIPAA, GDPR, SOX, PCI-DSS, CCPA, NIST CSF, NIST AI RMF, SOC 2, EU AI Act, ISO 27001, plus PII and SECURITY categories
- **Injection Detection**: SQL injection, XSS, prompt injection with keyword pre-screening optimization
- **Content Extraction**: Embedding + SLM for large context optimization
- **PII Tokenization**: Databunker integration for secure PII storage
- **Scan Attestation**: Prevent duplicate scanning across services
- **Real-time Streaming**: Kafka-based findings streaming for dashboards and alerts
- **Action Engine**: Rule-based automated responses (block, redact, alert, quarantine)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Gatekeeper                                   │
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  Extractor  │  │   Scanner   │  │  Attestor   │  │  Streamer  │ │
│  │ (embed+SLM) │  │ (patterns)  │  │ (sign+cache)│  │  (Kafka)   │ │
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

## Quick Start

### Prerequisites

- Go 1.21+
- Docker & Docker Compose (for development dependencies)

### Development Setup

```bash
# Start development dependencies (Redis, Kafka)
make dev-services

# Build the library
make build

# Run tests
make test

# Run linter
make lint

# Full CI pipeline
make ci
```

### Build Standalone Server

```bash
# Build server binary
make build-server

# Run server
./bin/contentintel-server --config configs/gatekeeper.yaml
```

### Docker

```bash
# Build Docker image
make docker-build

# Run with Docker
docker run -p 8087:8087 -p 8088:8088 registry.tas.scharber.com/gatekeeper:latest
```

## Usage

### As a Library

```go
import (
    "github.com/Tributary-ai-services/Gatekeeper/pkg/pipeline"
    "github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// Create processor
processor := pipeline.NewProcessor(config)

// Process content
result, err := processor.Process(ctx, pipeline.ProcessRequest{
    Content:     []byte(content),
    TrustTier:   scan.TierExternal,
    ScanProfile: scan.ProfileFull,
    TenantID:    tenantID,
    RequestID:   requestID,
    Source:      "llm_input",
})

if result.ActionResult != nil && result.ActionResult.Blocked {
    // Content was blocked due to violations
}

// Use redacted content
safeContent := result.RedactedContent
```

### HTTP Middleware (Gin)

```go
import "github.com/Tributary-ai-services/Gatekeeper/middleware"

router.Use(middleware.GinMiddleware(processor, &middleware.HTTPConfig{
    ScanProfile:      scan.ProfileFull,
    TrustTier:        scan.TierExternal,
    BlockOnViolation: true,
}))
```

### gRPC Interceptor

```go
import "github.com/Tributary-ai-services/Gatekeeper/middleware"

grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(middleware.UnaryServerInterceptor(processor, config)),
)
```

## Configuration

See `configs/gatekeeper.yaml` for full configuration options.

### Key Settings

```yaml
scanning:
  default_profile: "full"    # full, pii_only, injection_only
  honor_attestations: true   # Skip re-scanning with valid attestation

attestation:
  ttl: 5m                    # Attestation validity period

streaming:
  kafka:
    brokers: ["kafka:9092"]
    topics:
      findings: "tas.compliance.findings"
```

## Compliance Frameworks

| Framework | Key Rules | Conditional Context |
|-----------|-----------|-------------------|
| HIPAA | PHI protection, breach notification | `IsHealthcare` |
| GDPR | Data protection, right to erasure | `IsEUData` |
| PCI-DSS | Cardholder data protection | Always-on for credit cards |
| SOX | Financial data controls | `IsFinancial` |
| CCPA | Consumer data rights | Always-on for PII |
| NIST CSF | PR.DS-1, ID.AM-5, DE.CM-1 | `IsGovernment`, `IsCriticalInfra` |
| NIST AI RMF | MAP-1.5, MEASURE-2.6, MANAGE-2.2 | `IsAIContext` |
| SOC 2 | CC6.1, CC6.6, CC7.2, C1.1 | `IsCloudService` |
| EU AI Act | ART10, ART15 (robustness) | `IsEUData` + `IsAIContext` |
| ISO 27001 | A.8.2, A.9.4, A.14.2, A.18.1.4 | Always-on for credentials |

Credential and injection rules for SOC 2, ISO 27001, and NIST CSF are unconditional — credential exposure is always a violation. Prompt injection maps to EU AI Act ART15 and NIST AI RMF MEASURE-2.6 unconditionally.

## Credential Detection

| Provider | Patterns |
|----------|----------|
| AWS | Access keys (`AKIA*`), secret keys (context-based) |
| Azure | Storage keys, connection strings, AD client secrets, SAS tokens |
| GCP | API keys (`AIza*`), service account JSON |
| JWT/OAuth | JWT tokens (`eyJ*`), OAuth client secrets, OIDC/Keycloak secrets |
| PATs | GitHub, GitLab, Azure DevOps, Atlassian/Jira, Bitbucket |
| Database | PostgreSQL, MySQL, MongoDB, Redis connection URIs with passwords |
| SaaS | Stripe, SendGrid, Anthropic, Twilio, DigitalOcean, HuggingFace, NPM, PyPI, NuGet |
| Keys | PEM-encoded private keys (RSA, DSA, EC, OPENSSH, PGP) |

## Trust Tiers

| Tier | Description | Default Scan Profile |
|------|-------------|---------------------|
| `internal` | Your own services, system prompts | `injection_only` |
| `partner` | Known third-party MCP servers | `full` |
| `external` | Untrusted user input | `full` |

## HTTP Headers

Attestations are propagated via HTTP headers:

```
X-TAS-Scan-Attestation: <base64-encoded signed attestation>
X-TAS-Scan-Status: clean | violations | tokenized | skipped
X-TAS-Scan-Request-ID: <correlation ID>
```

## Performance

Scan throughput at 100KB content on Intel i7-1185G7:

| Content | Latency | Throughput | Allocs |
|---------|---------|------------|--------|
| Clean (no findings) | ~88ms | 1.2 MB/s | 19 |
| Mixed (PII + credentials + injections) | ~364ms | 0.29 MB/s | 5,149 |

Key optimizations:
- **Keyword pre-screening**: Injection and credential matchers skip expensive regex when no relevant keywords present (5x speedup on clean content)
- **Bounded regex quantifiers**: SQL injection patterns use `[^\n]{0,200}` instead of `.*` to prevent backtracking

See [BENCHMARKS.md](BENCHMARKS.md) for full results including per-matcher breakdowns, CPU/memory profiles, and optimization details.

## Development

```bash
# Install development tools
make install-tools

# Run pre-commit checks
make pre-commit

# Generate mocks for testing
make generate-mocks

# Run benchmarks
make benchmark

# Run benchmarks with profiling
go test ./pkg/scan/ -bench=BenchmarkScanScaling -benchtime=5s -cpuprofile=cpu.prof -benchmem

# Per-matcher benchmark breakdown
go test ./pkg/scan/ -bench=BenchmarkIndividualMatchers -benchtime=3s -benchmem
```

## Documentation

- [Design Specification](parital-design.md)
- [Benchmarks](BENCHMARKS.md) - Performance results and profiling
- [CLAUDE.md](CLAUDE.md) - Development guidance

## License

See [LICENSE](LICENSE) file.
