# TriageMate Stress Test Report — `verify-test`

**Generated:** 2026-07-08T20:45:11.123305

## 1. Summary

| Metric | Value |
|--------|-------|
| Duration | 0s |
| Total Requests | 5 |
| Successful | 5 (100.0%) |
| Failed | 0 (0.0%) |
| Error Rate | 0.0% |
| Throughput | 156.4 req/s |

## 2. Tier Routing

| Decision | Count | % |
|----------|-------|---|
| Tier 0 auto-resolved | 5 | 100.0% |
| Tier 0 escalated | 0 | 0.0% |
| Tier 1 auto-resolved | 5 | 100.0% |
| Tier 1 escalated | 0 | 0.0% |
| Tier 2 called | 5 | 100.0% |
| Tier 2 skipped | 0 | 0.0% |
| Tier 3 flagged | 0 | 0.0% |

## 3. Accuracy

| Metric | Value |
|--------|-------|
| KEV recall | 0.0% |
| KEV in test set | 0 |
| KEV auto-resolved at Tier 0 | 0 |
| Mean score (KEV) | 0.0 |
| Mean score (non-KEV) | 80.0 |
| Score separation | -80.0 pts |

## 4. Latency (ms)

| Metric | p50 | p95 | p99 |
|--------|-----|-----|-----|
| Total ingest | 420.0 | 420.0 | 420.0 |
| Pre-Tier | 2.0 | 2.0 | 2.0 |
| Tier 0 | 5.0 | 5.0 | 5.0 |
| Tier 1 | 50.0 | 50.0 | 50.0 |
| Tier 2 | 0 | 0 | 0 |

## 5. LLM Cost

| Metric | Value |
|--------|-------|
| Total calls | 5 |
| Total tokens in | 0 |
| Total tokens out | 0 |
| Total cost (USD) | $0.001500 |
| Avg cost/call (USD) | $0.000300 |

## 6. Risk Distribution

| Band | Count | % |
|------|-------|---|
| Very Critical | 0 | 0.0% |
| Critical | 5 | 100.0% |
| Medium | 0 | 0.0% |
| Low | 0 | 0.0% |

### Score Histogram

| Bucket | Count | % |
|--------|-------|---|
| 0-25 | 0 | 0.0% |
| 26-50 | 0 | 0.0% |
| 51-75 | 0 | 0.0% |
| 76-100 | 5 | 100.0% |

## 7. Failures

| Metric | Value |
|--------|-------|
| Error count | 0 |
| Error rate | 0.0% |

