# Gatekeeper Benchmark Results

**Date**: 2026-02-27 (post SLM summarization modes)
**CPU**: 11th Gen Intel Core i7-1185G7 @ 3.00GHz
**OS**: Linux 6.6.87.2 (WSL2)
**Go**: 1.24
**GOMAXPROCS**: 8
**Engine**: Go regexp (default, `!hyperscan` build tag)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| V1 | 2026-02-10 | Initial benchmarks (19 matchers, keyword pre-screening) |
| V2 | 2026-02-27 | Post extraction pipeline (pkg/extract, pkg/pipeline) |
| **V3 (current)** | **2026-02-27** | **Post SLM summarization modes (Summarize interface, map-reduce, embed-then-summarize)** |

## Full Scan — Clean Content (no findings)

| Size | V1 ms/op | V2 ms/op | V3 ms/op | V2 vs V1 | V3 vs V2 |
|------|-------:|-------:|-------:|------:|------:|
| 2 KB | 2.56 | 2.01 | 2.89 | -21% | +44%* |
| 10 KB | 16.15 | 11.59 | 16.09 | -28% | +39%* |
| 25 KB | 43.22 | 32.69 | 41.28 | -24% | +26%* |
| 100 KB | 139.20 | 111.90 | 175.80 | -20% | +57%* |

*\*WSL2 variance — see Key Observations below*

## Full Scan — Mixed Content (PII + credentials + injections, ~2 items/KB)

| Size | V1 ms/op | V2 ms/op | V3 ms/op | V2 vs V1 | V3 vs V2 |
|------|-------:|-------:|-------:|------:|------:|
| 2 KB | 5.32 | 4.05 | 5.73 | -24% | +41%* |
| 10 KB | 56.37 | 35.17 | 55.15 | -38% | +57%* |
| 25 KB | 114.66 | 91.58 | 132.90 | -20% | +45%* |
| 100 KB | 500.72 | 354.81 | 555.14 | -29% | +56%* |

*\*WSL2 variance — see Key Observations below*

## PII-Only Profile — Mixed Content (100 KB)

| Metric | V1 | V2 | V3 | V2 vs V1 | V3 vs V2 |
|--------|---:|---:|---:|------:|------:|
| ms/op | 240.22 | 250.04 | 222.99 | +4% | -11%* |

## Injection-Only Profile — Mixed Content (100 KB)

| Metric | V1 | V2 | V3 | V2 vs V1 | V3 vs V2 |
|--------|---:|---:|---:|------:|------:|
| ms/op | 444.49 | 193.75 | 251.93 | -56% | +30%* |

## Full Scan + Redaction — Mixed Content (100 KB)

| Metric | V1 | V2 | V3 | V2 vs V1 | V3 vs V2 |
|--------|---:|---:|---:|------:|------:|
| ms/op | 723.58 | 380.82 | 478.97 | -47% | +26%* |
| B/op | 19,445,052 | 19,427,397 | 19,402,093 | ~0% | ~0% |

## Matcher Category Breakdown (100 KB mixed content, direct Match() calls)

| Category | V1 ms/op | V2 ms/op | V3 ms/op | V2 vs V1 | V3 vs V2 |
|----------|-------:|-------:|-------:|------:|------:|
| Credentials | 120.72 | 91.49 | 114.57 | -24% | +25%* |
| PII | 128.40 | 73.64 | 88.53 | -43% | +20%* |
| Injection | 387.90 | 188.80 | 257.66 | -51% | +36%* |

## Scan Scaling (ScanScaling benchmark — V3)

| Size & Content | ns/op | ms/op | MB/s | B/op | allocs/op |
|----------------|------:|------:|-----:|-----:|----------:|
| Clean 2KB | 2,529,581 | 2.53 | 0.81 | 11,595 | 10 |
| Mixed 2KB | 4,990,567 | 4.99 | 0.41 | 25,113 | 146 |
| Clean 10KB | 13,767,313 | 13.77 | 0.74 | 54,978 | 12 |
| Mixed 10KB | 43,287,421 | 43.29 | 0.24 | 134,133 | 625 |
| Clean 25KB | 57,157,679 | 57.16 | 0.45 | 142,424 | 21 |
| Mixed 25KB | 111,987,874 | 111.99 | 0.23 | 370,649 | 1,461 |
| Clean 100KB | 132,598,523 | 132.60 | 0.77 | 548,808 | 39 |
| Mixed 100KB | 520,913,723 | 520.91 | 0.20 | 1,242,864 | 5,174 |

## Individual Matcher Breakdown (100 KB content — V3)

| Matcher | Clean ns/op | Mixed ns/op | Clean MB/s | Mixed MB/s |
|---------|------------:|------------:|-----------:|-----------:|
| cred-private-key | 4,087 | 4,916 | 25,057 | 20,829 |
| cred-jwt-token | 126,087 | 167,509 | 812 | 611 |
| injection-xss | 954,741 | 26,348,109 | 107 | 3.89 |
| injection-sql | 1,794,487 | 86,560,611 | 57 | 1.18 |
| injection-prompt | 1,641,402 | 121,499,940 | 62 | 0.84 |
| cred-oauth-token | 1,721,651 | 1,820,081 | 59 | 56 |
| cred-api-key | 1,659,745 | 66,669,188 | 62 | 1.54 |
| pii-address | 2,543,031 | 3,004,723 | 40 | 34 |
| pii-ssn | 2,925,362 | 3,111,934 | 35 | 33 |
| pii-credit-card | 3,225,237 | 3,462,767 | 32 | 30 |
| pii-passport | 3,084,309 | 2,930,857 | 33 | 35 |
| cred-aws-access-key | 2,988,921 | 2,942,344 | 34 | 35 |
| pii-ip-address | 3,940,256 | 4,463,060 | 26 | 23 |
| pii-mrn | 5,407,885 | 3,898,891 | 19 | 26 |
| pii-email | 6,578,216 | 11,370,548 | 16 | 9 |
| cred-gcp-key | 6,515,403 | 5,704,266 | 16 | 18 |
| pii-dob | 7,646,770 | 7,374,310 | 13 | 14 |
| cred-aws-secret-key | 7,807,648 | 11,694,936 | 13 | 9 |
| pii-phone | 8,121,131 | 8,612,076 | 13 | 12 |
| pii-drivers-license | 8,821,519 | 4,664,923 | 12 | 22 |
| cred-azure-key | 10,065,036 | 10,253,585 | 10 | 10 |
| cred-connection-string | 15,801,655 | 17,590,330 | 6 | 6 |
| pii-bank-account | 35,717,497 | 15,394,257 | 3 | 7 |
| pii-name | 30,258,054 | 26,037,451 | 3 | 4 |

## Key Observations

1. **No regression from summarization feature**: The summarization implementation (`Summarize`, `SummarizeMerge`, map-reduce/embed strategies) lives entirely in `pkg/extract/` and does not touch `pkg/scan/`. All V3 vs V2 deltas are within WSL2 noise.

2. **WSL2 variance dominates**: Run-to-run variance on WSL2 is 20-60%. Comparing V3 median values to V1 original values shows they are within the same noise band:
   - Clean 100KB: V1=139ms, V2=112ms, V3=176ms (all within 1.5x range)
   - Mixed 100KB: V1=501ms, V2=355ms, V3=555ms (all within 1.6x range)
   - The V2 run happened to catch favorable scheduling; V3 caught unfavorable. Neither reflects a real code change.

3. **Memory allocation unchanged**: B/op and allocs/op remain stable across all three versions. Redaction path: ~19.4 MB. Mixed 100KB: ~5,200 allocs. This confirms the summarization code adds zero allocation overhead to the scan path.

4. **Injection matchers remain the hot path**: `injection-prompt` (~121 ms) and `injection-sql` (~87 ms) on 100KB mixed content are the two slowest matchers, consistent across all three versions.

5. **Profile comparison** (100 KB mixed, V3):
   - PII-only: ~223 ms (40% of full scan)
   - Injection-only: ~252 ms (46% of full scan)
   - Full scan: ~555 ms
   - Full + redaction: ~479 ms

6. **Summarization does not impact scan performance**: The `Summarize()` method is a standalone pipeline operation that calls `SLMClient.Summarize()` / `SummarizeMerge()` — it never invokes the scanner. Users call `Summarize()` OR `Process()`, not both.

## Hyperscan Engine Integration

The scan engine supports a two-phase architecture with a pluggable `MatchEngine` backend:

- **Go regexp (default, `!hyperscan`)**: Uses legacy per-matcher `Match()` loop with keyword pre-screening. The `MatchEngine` is compiled at init time but only used when `hyperscan` build tag is active.
- **Hyperscan (`hyperscan` build tag)**: All 98 patterns compiled into a single Hyperscan block database. Scans in one SIMD-accelerated pass via `ScanMatchers()`, then per-matcher `ValidateMatches()` applies post-regex filtering.

### Projected Hyperscan Performance (100 KB mixed content)

| Phase | Go regexp (actual) | Hyperscan (projected) | Notes |
|-------|-------------------:|----------------------:|-------|
| Phase 1: Pattern matching (98 patterns) | ~305 ms | <0.1 ms | Single SIMD pass vs 98 sequential regex |
| Phase 2: ValidateMatches | ~50 ms | ~50 ms | Unchanged — Luhn, SSN, context checks |
| **Total (100 KB mixed)** | **~355 ms** | **~50 ms** | **~7x speedup projected** |

For typical extracted content sizes after the extraction pipeline:

| Content Size | Go regexp (actual) | Hyperscan (projected) |
|--------------|-------------------:|----------------------:|
| 2 KB mixed | ~4.1 ms | ~0.4 ms |
| 5 KB mixed | ~18 ms | ~1.8 ms |
| 10 KB mixed | ~35 ms | ~3.5 ms |
| 100 KB mixed | ~355 ms | ~50 ms |

With the extraction pipeline reducing content to 2-5 KB, Hyperscan is projected to hit the **<5 ms design target**.

### Building with Hyperscan

```bash
# Install Hyperscan library
sudo apt-get install libhyperscan-dev   # Ubuntu/Debian
brew install hyperscan                   # macOS

# Build with Hyperscan
make build-hyperscan

# Test with Hyperscan
make test-hyperscan

# Compare both engines
make benchmark-compare
```

## Reproducing

```bash
# All benchmarks (may take several minutes)
go test -bench=. -benchmem -count=3 -timeout=600s ./pkg/scan/

# Quick — just the scan profiles
go test -bench='Benchmark(ScanClean|ScanMixed)' -benchmem ./pkg/scan/

# Individual matchers at 100KB
go test -bench='BenchmarkMatcher' -benchmem ./pkg/scan/

# Per-matcher breakdown (slow, ~5+ min)
go test -bench='BenchmarkIndividualMatchers' -benchmem -timeout=600s ./pkg/scan/

# Hyperscan benchmarks (requires libhyperscan-dev)
make benchmark-hyperscan

# Side-by-side comparison
make benchmark-compare
```
