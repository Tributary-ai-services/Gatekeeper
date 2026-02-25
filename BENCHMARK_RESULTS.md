# Gatekeeper Benchmark Results

**Date**: 2026-02-25
**CPU**: 11th Gen Intel Core i7-1185G7 @ 3.00GHz
**OS**: Linux 6.6.87.2 (WSL2)
**Go**: 1.24
**GOMAXPROCS**: 8

## Full Scan — Clean Content (no findings)

| Size | ns/op | ms/op | MB/s | B/op | allocs/op |
|------|------:|------:|-----:|-----:|----------:|
| 2 KB | 2,674,699 | 2.67 | 0.77 | 11,199 | 10 |
| 10 KB | 15,838,041 | 15.84 | 0.65 | 55,606 | 12 |
| 25 KB | 37,483,468 | 37.48 | 0.68 | 137,190 | 10 |
| 100 KB | 162,196,231 | 162.20 | 0.63 | 548,706 | 31 |

## Full Scan — Mixed Content (PII + credentials + injections, ~2 items/KB)

| Size | ns/op | ms/op | MB/s | B/op | allocs/op |
|------|------:|------:|-----:|-----:|----------:|
| 2 KB | 6,280,168 | 6.28 | 0.33 | 24,705 | 146 |
| 10 KB | 55,836,974 | 55.84 | 0.18 | 129,758 | 618 |
| 25 KB | 143,672,565 | 143.67 | 0.18 | 365,872 | 1,446 |
| 100 KB | 498,482,367 | 498.48 | 0.21 | 1,291,053 | 5,193 |

## PII-Only Profile — Mixed Content

| Size | ns/op | ms/op | MB/s | B/op | allocs/op |
|------|------:|------:|-----:|-----:|----------:|
| 2 KB | 2,826,570 | 2.83 | 0.72 | 12,438 | 89 |
| 10 KB | 23,212,393 | 23.21 | 0.44 | 73,781 | 408 |
| 25 KB | 59,242,235 | 59.24 | 0.43 | 209,229 | 1,093 |
| 100 KB | 228,408,088 | 228.41 | 0.45 | 812,651 | 3,939 |

## Injection-Only Profile — Mixed Content

| Size | ns/op | ms/op | MB/s | B/op | allocs/op |
|------|------:|------:|-----:|-----:|----------:|
| 2 KB | 2,583,865 | 2.58 | 0.79 | 11,694 | 63 |
| 10 KB | 22,693,553 | 22.69 | 0.45 | 60,025 | 221 |
| 25 KB | 67,629,970 | 67.63 | 0.38 | 130,238 | 349 |
| 100 KB | 480,493,325 | 480.49 | 0.21 | 503,757 | 1,269 |

## Full Scan + Redaction — Mixed Content

| Size | ns/op | ms/op | MB/s | B/op | allocs/op |
|------|------:|------:|-----:|-----:|----------:|
| 2 KB | 8,351,198 | 8.35 | 0.25 | 33,898 | 172 |
| 10 KB | 60,076,167 | 60.08 | 0.17 | 354,962 | 781 |
| 25 KB | 213,632,113 | 213.63 | 0.12 | 1,606,632 | 1,818 |
| 100 KB | 632,295,956 | 632.30 | 0.16 | 19,422,832 | 6,555 |

## Matcher Category Breakdown (100 KB mixed content)

| Category | ns/op | ms/op | MB/s | B/op | allocs/op |
|----------|------:|------:|-----:|-----:|----------:|
| Credentials | 138,613,347 | 138.61 | 0.74 | 358,913 | 375 |
| PII | 104,046,513 | 104.05 | 0.98 | 87,769 | 405 |
| Injection | 326,215,658 | 326.22 | 0.31 | 391,168 | 112 |

## Key Observations

1. **Scaling**: Scan latency scales roughly linearly with content size. Full scan of 100 KB mixed content takes ~498 ms — well above the 5 ms design target. This confirms the extraction pipeline (chunking + embedding relevance filtering) is essential for meeting latency targets on large payloads.

2. **Mixed vs Clean**: Mixed content with findings is ~2.5-3x slower than clean content at the same size, due to match validation, confidence scoring, and allocation overhead from building `Finding` structs.

3. **Profile comparison** (100 KB mixed):
   - PII-only: 228 ms (46% of full scan)
   - Injection-only: 480 ms (96% of full scan) — injection regex patterns are the most expensive
   - Full scan: 498 ms

4. **Redaction overhead**: Adding redaction to the scan adds ~27% latency at 100 KB but dramatically increases memory (19 MB B/op vs 1.3 MB), likely from string rebuilding during PII masking.

5. **Injection matchers are the bottleneck**: At 326 ms for 100 KB, injection detection alone accounts for ~65% of full scan time. The complex regex patterns (SQL injection, prompt injection, XSS) are the primary performance cost.

6. **Memory efficiency**: Clean scans are very lean (10-31 allocs regardless of size). Allocations scale linearly with finding density, not content size.

## Reproducing

```bash
# All benchmarks (may take several minutes)
go test -bench=. -benchmem -count=1 -timeout=600s ./pkg/scan/

# Quick — just the scan profiles
go test -bench='Benchmark(ScanClean|ScanMixed)' -benchmem ./pkg/scan/

# Individual matchers at 100KB
go test -bench='BenchmarkMatcher' -benchmem ./pkg/scan/

# Per-matcher breakdown (slow, ~5+ min)
go test -bench='BenchmarkIndividualMatchers' -benchmem -timeout=600s ./pkg/scan/
```
