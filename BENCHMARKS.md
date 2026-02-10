# Gatekeeper Benchmarks

Benchmark results for the Gatekeeper content scanning library.

**Hardware**: Intel i7-1185G7 @ 3.00GHz, Linux (WSL2)
**Go Version**: 1.21+
**Date**: 2026-02-10

## Full Scan Throughput (Scaling)

Content scanned using `DefaultScanConfig()` (all matchers enabled, 19 matchers total).

### Clean Content (no PII, credentials, or injections)

| Size | Latency (avg) | Throughput | Allocs/op |
|------|---------------|------------|-----------|
| 2KB | 1.6ms | 1.30 MB/s | 10 |
| 10KB | 9.8ms | 1.05 MB/s | 11 |
| 25KB | 25ms | 0.96 MB/s | 13 |
| 100KB | 88ms | 1.20 MB/s | 19 |

### Mixed Content (~2 sensitive items per KB: PII + credentials + injections)

| Size | Latency (avg) | Throughput | Allocs/op |
|------|---------------|------------|-----------|
| 2KB | 4.0ms | 0.52 MB/s | 146 |
| 10KB | 35ms | 0.29 MB/s | 612 |
| 25KB | 91ms | 0.28 MB/s | 1,425 |
| 100KB | 364ms | 0.29 MB/s | 5,149 |

## Scan Profiles

Tested at 100KB mixed content:

| Profile | Description | Matchers | Latency |
|---------|-------------|----------|---------|
| Full | All matchers | 19 | ~364ms |
| PII Only | PII matchers only | 8 | ~45ms |
| Injection Only | Injection matchers only | 3 | ~35ms |

## Scan with Redaction

Tested at 100KB mixed content with `ScanWithRedaction()`:

| Size | Latency (avg) | Allocs/op |
|------|---------------|-----------|
| 2KB | ~5ms | ~180 |
| 10KB | ~40ms | ~700 |
| 25KB | ~100ms | ~1,600 |
| 100KB | ~400ms | ~5,500 |

## Individual Matcher Performance (100KB)

### Clean Content (pre-screening effectiveness)

Matchers with keyword pre-screening skip all regex work on clean content:

| Matcher | Latency | Throughput | Pre-screened? |
|---------|---------|------------|---------------|
| cred-private-key | 0.004ms | 25,968 MB/s | literal search |
| cred-jwt-token | 0.11ms | 911 MB/s | literal prefix |
| injection-xss | 0.86ms | 119 MB/s | Yes |
| cred-api-key | 1.3ms | 78 MB/s | Yes |
| cred-oauth-token | 1.4ms | 73 MB/s | Yes |
| injection-prompt | 1.4ms | 73 MB/s | Yes |
| injection-sql | 1.5ms | 70 MB/s | Yes |
| pii-ssn | 2.5ms | 40 MB/s | No (regex) |
| cred-aws-access-key | 2.8ms | 37 MB/s | No (regex) |
| pii-credit-card | 2.9ms | 34 MB/s | No (regex) |
| pii-ip-address | 3.3ms | 31 MB/s | No (regex) |
| cred-gcp-key | 4.7ms | 21 MB/s | No (regex) |
| pii-dob | 5.4ms | 19 MB/s | No (regex) |
| pii-email | 5.6ms | 18 MB/s | No (regex) |
| pii-phone | 5.5ms | 18 MB/s | No (regex) |
| cred-aws-secret-key | 6.3ms | 16 MB/s | No (regex) |
| cred-azure-key | 8.0ms | 12 MB/s | No (regex) |
| pii-bank-account | 13.3ms | 7.7 MB/s | No (regex) |
| cred-connection-string | 15.1ms | 6.8 MB/s | No (regex) |

### By Category (100KB mixed content)

| Category | Matchers | Latency |
|----------|----------|---------|
| Credentials | 9 | ~30ms |
| PII | 7 | ~40ms |
| Injection | 3 | ~25ms |

## Optimizations Applied

### Keyword Pre-screening (5x speedup on clean content)

The top 5 CPU-consuming matchers use cheap `strings.Contains` checks before invoking regex:

| Matcher | Before (clean 100KB) | After (clean 100KB) | Speedup |
|---------|---------------------|---------------------|---------|
| PromptInjection (25 regexes) | ~120ms | ~1.4ms | 86x |
| SQLInjection (25 regexes) | ~85ms | ~1.5ms | 57x |
| APIKey (16-way alternation) | ~65ms | ~1.3ms | 50x |
| OAuth (5-way alternation) | ~45ms | ~1.4ms | 32x |
| XSS (21 regexes) | ~30ms | ~0.9ms | 33x |
| **Full scan total** | **~444ms** | **~88ms** | **5x** |

### Bounded Regex Quantifiers

SQL injection patterns replaced `.*` with `[^\n]{0,200}` to prevent catastrophic backtracking:

```
Before: (?i)(?:SELECT\s+.*\s+FROM\s+.*\s+WHERE)
After:  (?i)(?:SELECT\s+[^\n]{0,200}\s+FROM\s+[^\n]{0,200}\s+WHERE)
```

## CPU Profile Breakdown (100KB mixed content)

| Component | CPU % | Description |
|-----------|-------|-------------|
| `regexp.(*machine).add` | 35.6% | NFA state management |
| `regexp.(*machine).step` | 16.9% | NFA execution |
| `unicode.SimpleFold` | 9.5% | Case-insensitive matching |
| `runtime.memmove` | 9.7% | Memory operations |
| `regexp.(*machine).match` | 7.9% | Match orchestration |
| `regexp/syntax.MatchRunePos` | 7.1% | Character matching |

97.8% of CPU time is spent in Go's `regexp` package. Future optimization would benefit from Hyperscan (Intel's high-performance regex library) for production workloads.

## Memory Profile (100KB mixed content)

| Component | Alloc % | Description |
|-----------|---------|-------------|
| `regexp/syntax.compiler.inst` | 29% | Regex NFA instruction cache |
| `regexp/syntax.parser.newRegexp` | 16% | Regex AST nodes |
| `ScanString` | 8% | Finding struct allocation |
| `baseMatcher.findAllMatches` | 8% | Match result slices |
| `buildViolations` | 4% | Violation struct allocation |

## Running Benchmarks

```bash
# Full scaling benchmark (all sizes, clean + mixed)
go test ./pkg/scan/ -bench=BenchmarkScanScaling -benchtime=5s -count=3 -benchmem

# Individual matcher breakdown
go test ./pkg/scan/ -bench=BenchmarkIndividualMatchers -benchtime=3s -benchmem

# Category-level benchmarks
go test ./pkg/scan/ -bench='BenchmarkMatcher(Credentials|PII|Injection)' -benchtime=3s -benchmem

# With CPU profiling
go test ./pkg/scan/ -bench=BenchmarkScanMixed100KB -benchtime=5s -cpuprofile=cpu.prof -memprofile=mem.prof -benchmem

# Analyze profile
go tool pprof -top cpu.prof
go tool pprof -top -cum cpu.prof
```
