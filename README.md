# Gatekeeper

TAS Gatekeeper is a unified content scanning, extraction, and compliance library for the TAS platform. It provides high-performance content analysis capabilities shared across TAS services including TAS LLM Router, TAS MCP Proxy, Audimodal, and Aether-BE.

## Features

- **PII Detection**: 15+ PII types including SSN, credit cards, emails, phone numbers, medical records
- **Compliance Scanning**: HIPAA, GDPR, SOX, PCI-DSS, CCPA framework rules
- **Injection Detection**: SQL injection, XSS, prompt injection, HTML injection
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
```

## Documentation

- [Design Specification](parital-design.md)
- [CLAUDE.md](CLAUDE.md) - Development guidance

## License

See [LICENSE](LICENSE) file.
