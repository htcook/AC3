# Caldera Passive Discovery Pipeline — Speed & Efficiency Optimization Report

**Author:** Harrison Cook / AceofCloud  
**Date:** March 9, 2026  
**Engagement Reference:** Master Test Range (ID: 1590026) — 20 domains, 21 targets

---

## Executive Summary

The Caldera passive discovery pipeline runs **34 OSINT connectors** and **8 LLM-powered analysis stages** per domain, orchestrated in batches of 2 concurrent domains. A production scan of the Master Test Range engagement confirmed that the recent connector timeout fix (Promise.race + semaphore pattern) reduced connector execution from **20+ minutes to ~3 minutes per batch**. However, the post-connector LLM pipeline stages now represent the dominant bottleneck, with the scan stalling after connectors complete. This report identifies **12 concrete optimizations** across three tiers — connector layer, LLM pipeline, and orchestration architecture — that can reduce total scan time from the current ~30–60 minutes to under 10 minutes for a 20-domain engagement without sacrificing analytical accuracy.

---

## 1. Current Architecture Overview

The pipeline processes each domain through a sequential chain of stages. Understanding where time is spent is critical to identifying optimization opportunities.

### 1.1 Pipeline Stages Per Domain

| Stage | Description | LLM Calls | Estimated Time | Blocking? |
|-------|-------------|-----------|----------------|-----------|
| **Passive Recon** | 34 OSINT connectors via semaphore pool | 0 | 30–90s | No (parallel) |
| **Stage 1: Discovery** | LLM infers assets from recon data | 1 | 5–15s | Yes |
| **Stage 2: Analysis** | LLM scores each asset (CARVER/Shock/CVSS) | 1 | 10–30s | Yes |
| **Stage 3.1: KEV Enrichment** | Match technologies against CISA KEV catalog | 0 | <1s | No |
| **Stage 3.2: Exploit Matching** | Match findings against exploit DB | 0 | <1s | No |
| **Stage 3.5: Vuln Feed Enrichment** | Cross-reference CVE databases | 0 | 1–3s | No |
| **Stage 3.7: Port Risk Scoring** | Score open ports from Shodan data | 0 | <1s | No |
| **Stage 3.9: Email Security** | DNS-based SPF/DKIM/DMARC analysis | 0 | 2–5s | No |
| **Stage 3.95: Cross-Module Enrichment** | Bug bounty, threat intel, OpSec correlation | 0 | 2–5s | No |
| **Stage 3.97: OEM Credential Matching** | Match technologies to default credentials | 0 | <1s | No |
| **Stage 3.98: Credential Testing** | Test matched credentials against services | 0 | 5–15s | No |
| **Stage 3.991: SCAP Compliance** | External SCAP/STIG compliance scan | 0 | 5–15s | No |
| **Stage 3.992: Container Exposure** | Docker/K8s infrastructure discovery | 0 | 3–10s | No |
| **Stage 3.99: Post-Enrichment LLM** | Attack paths, blind spots, recommendations | 1 | 10–20s | Yes |
| **Stage 4: Campaign Design** | LLM generates campaign recommendations | 1 | 10–20s | Yes |
| **Stage 5: Summaries** | LLM generates executive/threat summaries | 1–2 | 5–15s | Yes |
| **Stage 6: FP Auto-Flagging** | Match findings against known FP hashes | 0 | <1s | No |
| **CARVER Risk Card** | Auto-generate industry risk card | 0 | <1s | No |
| **Scan Delta** | Cross-session comparison | 0 | <1s | No |

**Total LLM calls per domain:** 5–6 (each taking 5–30 seconds)  
**Total estimated time per domain:** 90–180 seconds (after connector fix)  
**Total for 20 domains at concurrency 2:** 10 batches × 3 min = ~30 minutes theoretical minimum

### 1.2 Connector Layer (34 Connectors)

The connector layer runs 34 OSINT sources through a semaphore-limited pool (max 5 concurrent per domain). After the timeout fix, connector execution is no longer the primary bottleneck.

| Connector Category | Count | Typical Duration | Notes |
|-------------------|-------|-----------------|-------|
| Free/No-Key (crt.sh, RDAP, DNS, HTTP headers) | 6 | 0.1–2s | Always fast |
| Shodan InternetDB (free tier) | 1 | 0.1s | Instant CVE/port data |
| API-keyed (Shodan, Censys, SecurityTrails, etc.) | 18 | 2–30s | Rate-limited, key-dependent |
| GitHub (leaks + recon) | 2 | 30s (hard timeout) | Consistently hits timeout |
| Cloud/Container discovery | 3 | 2–10s | Probe-based |
| Email/Social | 2 | 1–5s | DNS + API lookups |
| Skipped (no API key) | ~10 | 0s | Pre-filtered |

**Production observation:** Of the 34 registered connectors, typically only 12–18 actually execute (the rest are skipped due to missing API keys). The effective connector phase completes in 30–90 seconds per domain.

---

## 2. Confirmed Bottlenecks (Production Data)

### 2.1 Bottleneck #1: Sequential LLM Calls (Primary)

Each domain makes 5–6 sequential LLM calls that cannot overlap. At 5–30 seconds each, this adds 30–90 seconds of pure LLM wait time per domain. With 20 domains at concurrency 2, that is **10–15 minutes of LLM wait time alone**.

The LLM calls are sequential because each stage depends on the output of the previous stage (discovery feeds analysis, analysis feeds scoring, scoring feeds campaign design). However, not all dependencies are strict — some stages can be parallelized.

### 2.2 Bottleneck #2: LLM Pipeline Hangs (Critical Bug)

The production scan demonstrated that the LLM pipeline stages hang silently after connectors complete. The scan processed Batch 1 successfully but stalled during Batch 2 with no new log entries for 10+ minutes. This suggests either LLM API timeouts without error handling, or promise chains that never resolve.

### 2.3 Bottleneck #3: Domain Concurrency Ceiling

The current concurrency of 2 domains means 10 sequential batches for 20 domains. Even if each batch takes only 3 minutes, that is 30 minutes minimum. Increasing concurrency to 3–4 would reduce this proportionally, but risks LLM API rate limits and event loop pressure.

### 2.4 Bottleneck #4: GitHub Connectors (Always Timeout)

Both `github_leaks` and `github_recon` consistently hit the 30-second hard timeout. They are effectively wasting 30 seconds of a concurrency slot every time. Either they need optimization or should be moved to a background/async queue.

---

## 3. Optimization Recommendations

### Tier 1: High Impact, Low Risk (Implement First)

#### 3.1 Add Timeout Protection to LLM Calls

**Impact:** Prevents pipeline hangs (the #1 production failure mode)  
**Effort:** 2 hours  
**Risk:** None — graceful degradation on timeout

Every `invokeLLM()` call in `domainIntel.ts` should be wrapped in a `Promise.race` with a 60-second timeout. If the LLM doesn't respond within 60 seconds, the stage should use a fallback (empty results or cached previous results) and continue to the next stage.

```typescript
async function invokeLLMWithTimeout(params: any, timeoutMs = 60000): Promise<any> {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('LLM timeout')), timeoutMs)
  );
  return Promise.race([invokeLLM(params), timeout]);
}
```

#### 3.2 Parallelize Independent LLM Stages

**Impact:** Reduces LLM wait time by 40–50%  
**Effort:** 4 hours  
**Risk:** Low — stages are already independent

The following stages have no data dependency on each other and can run concurrently:

- **Stage 3.99 (Post-Enrichment LLM)** and **Stage 4 (Campaign Design)** can run in parallel — both consume the same `analyses` array but produce independent outputs.
- **Executive Summary** and **Threat Model Summary** (Stage 5) can run in parallel — they are two separate LLM calls that produce independent text.

This would reduce the sequential LLM chain from 5–6 calls to 3–4 calls, saving 10–30 seconds per domain.

```typescript
// Before: sequential
const postEnrichment = await runPostEnrichmentAnalysis(analyses, org);
const campaigns = await generateCampaignRecommendations(analyses, org);
const summaries = await generateSummaries(analyses, campaigns, org);

// After: parallel where possible
const [postEnrichment, campaigns] = await Promise.all([
  runPostEnrichmentAnalysis(analyses, org),
  generateCampaignRecommendations(analyses, org),
]);
const summaries = await generateSummaries(analyses, campaigns, org);
```

#### 3.3 Move GitHub Connectors to Background Queue

**Impact:** Saves 30s per domain (they always timeout)  
**Effort:** 2 hours  
**Risk:** None — results are supplementary

Since `github_leaks` and `github_recon` consistently hit the 30-second timeout, they should be moved out of the main connector pool and run as a background task that enriches results after the main pipeline completes. This frees up 2 concurrency slots per domain.

#### 3.4 Cache KEV Catalog and Exploit DB

**Impact:** Saves 2–5s per domain on repeated scans  
**Effort:** 1 hour  
**Risk:** None — data changes infrequently

The KEV catalog and exploit database are fetched fresh for every domain. These should be cached in memory with a 1-hour TTL since they change at most daily. For a 20-domain scan, this eliminates 19 redundant fetches.

```typescript
let kevCache: { data: any; fetchedAt: number } | null = null;
const KEV_CACHE_TTL = 60 * 60 * 1000; // 1 hour

async function getCachedKev() {
  if (kevCache && Date.now() - kevCache.fetchedAt < KEV_CACHE_TTL) {
    return kevCache.data;
  }
  kevCache = { data: await fetchKevCatalog(), fetchedAt: Date.now() };
  return kevCache.data;
}
```

### Tier 2: Medium Impact, Medium Risk

#### 3.5 Increase Domain Concurrency to 3 (with LLM Rate Limiting)

**Impact:** Reduces total scan time by ~33%  
**Effort:** 1 hour (config change) + 2 hours (rate limiter)  
**Risk:** Medium — may hit LLM API rate limits

Increasing `PARALLEL_CONCURRENCY` from 2 to 3 would reduce 20-domain scans from 10 batches to 7 batches. However, this means 3 domains × 5 LLM calls = 15 concurrent LLM requests, which may exceed API rate limits. The solution is to add a shared LLM semaphore that limits concurrent LLM calls to 4–6 across all domains.

```typescript
// Shared LLM semaphore across all concurrent domains
const llmSemaphore = new Semaphore(4); // max 4 concurrent LLM calls

async function invokeLLMThrottled(params: any): Promise<any> {
  return llmSemaphore.acquire(() => invokeLLMWithTimeout(params));
}
```

#### 3.6 Implement Connector Result Caching (Cross-Domain)

**Impact:** Saves 10–20s per domain for shared infrastructure  
**Effort:** 4 hours  
**Risk:** Low — cache invalidation is simple (per-scan session)

Many domains in an engagement share the same IP ranges, nameservers, and cloud infrastructure. Connector results for shared resources (Shodan IP lookups, DNS nameserver queries, cloud bucket scans) can be cached within a scan session and reused across domains.

For example, if `159.223.152.190` is resolved by both `domain-a.com` and `domain-b.com`, the Shodan lookup for that IP should only happen once.

#### 3.7 Reduce LLM Prompt Size with Structured Summaries

**Impact:** Reduces LLM response time by 20–40%  
**Effort:** 6 hours  
**Risk:** Low — requires careful prompt engineering

The current LLM prompts include full passive recon data dumps, which can be 5,000–10,000 tokens. Replacing raw data with pre-computed structured summaries (e.g., "12 subdomains found, 3 with expired certs, 2 with open admin panels") would reduce prompt size by 60–80% and proportionally reduce LLM response time.

This is particularly impactful for the **Stage 2 Analysis** prompt, which currently includes the full asset list with all technologies, versions, and observations.

#### 3.8 Implement Progressive Result Delivery

**Impact:** Perceived speed improvement (results appear faster)  
**Effort:** 8 hours  
**Risk:** Low — UI change only

Instead of waiting for all 20 domains to complete before showing results, deliver results progressively as each domain completes. The UI already supports WebSocket updates via `broadcastOpsUpdate` — extend this to push completed domain results to the frontend immediately.

This doesn't reduce total scan time but dramatically improves the user experience. An operator can start reviewing Domain 1's results while Domain 20 is still scanning.

### Tier 3: High Impact, Higher Effort

#### 3.9 Implement Scan Tiering (Quick Scan vs. Deep Scan)

**Impact:** 5x faster for routine scans  
**Effort:** 16 hours  
**Risk:** Medium — requires UI changes and user education

Introduce two scan modes:

| Mode | Connectors | LLM Stages | Est. Time (20 domains) |
|------|-----------|------------|----------------------|
| **Quick Scan** | Top 8 (free + Shodan + crt.sh + DNS) | Discovery + Scoring only | 3–5 minutes |
| **Deep Scan** | All 34 | Full pipeline (all 8 LLM stages) | 15–25 minutes |

Quick Scan would skip campaign design, post-enrichment analysis, credential testing, SCAP compliance, and container discovery — stages that are valuable but not essential for a routine posture check. Deep Scan remains the default for formal engagements.

#### 3.10 Pre-compute Shared Intelligence Before Domain Loop

**Impact:** Eliminates redundant work across domains  
**Effort:** 8 hours  
**Risk:** Low — architectural refactor

Several operations are currently performed per-domain but produce engagement-wide results:

- **KEV catalog fetch** — same for all domains
- **Org profile inference** — same customer for all domains
- **FP hash loading** — same engagement for all domains
- **Historical context fetch** — same engagement for all domains

Moving these to a pre-computation phase before the domain loop would save 5–10 seconds per domain (100–200 seconds for 20 domains).

#### 3.11 Implement Differential Scanning

**Impact:** 80% faster for repeat scans  
**Effort:** 24 hours  
**Risk:** Medium — requires scan history tracking

For engagements that have been scanned before, only re-scan domains where the previous scan found changes or where the scan is older than a configurable threshold (e.g., 24 hours). Unchanged domains reuse cached results with a "last verified" timestamp.

The `scanDelta` infrastructure already exists (Stage 3.992) — extend it to skip domains that haven't changed since the last scan.

#### 3.12 Worker Thread Isolation for CPU-Intensive Stages

**Impact:** Prevents event loop blocking  
**Effort:** 16 hours  
**Risk:** Medium — requires careful data serialization

The scoring engine (CARVER/Shock computation, hybrid risk calculation) and corroboration engine are CPU-intensive and block the Node.js event loop. Moving these to `worker_threads` would keep the main thread responsive and allow connector I/O to proceed unblocked.

---

## 4. Projected Impact

The table below estimates the cumulative effect of implementing optimizations in order.

| Optimization | Est. Time Saved (20 domains) | Cumulative Total Time |
|-------------|-----------------------------|-----------------------|
| **Baseline (current)** | — | ~30–60 min |
| + LLM timeout protection (#3.1) | Prevents hangs | ~30 min (reliable) |
| + Parallel LLM stages (#3.2) | -5 min | ~25 min |
| + Background GitHub (#3.3) | -3 min | ~22 min |
| + Cache KEV/exploit DB (#3.4) | -2 min | ~20 min |
| + Concurrency 3 + LLM throttle (#3.5) | -7 min | ~13 min |
| + Cross-domain caching (#3.6) | -3 min | ~10 min |
| + Reduced prompt size (#3.7) | -2 min | ~8 min |
| + Quick Scan mode (#3.9) | -5 min (quick mode) | ~3–5 min (quick) |
| + Differential scanning (#3.11) | -6 min (repeat scans) | ~2–4 min (repeat) |

**Realistic target:** Implementing Tier 1 + Tier 2 optimizations would bring a 20-domain scan from ~30 minutes to **8–13 minutes** — a 2.5–4x improvement with no accuracy loss.

---

## 5. Accuracy Safeguards

Every optimization above preserves analytical accuracy through these principles:

1. **No data is dropped** — timeouts and caching produce graceful degradation, not data loss. If an LLM call times out, the pipeline continues with available data and logs the gap.

2. **No connectors are removed** — background queuing and caching still execute all connectors; they just don't block the critical path.

3. **LLM prompts are not simplified** — prompt size reduction uses pre-computed summaries of the same data, not less data. The LLM receives the same information in a more efficient format.

4. **Scoring integrity is maintained** — CARVER, Shock, and hybrid risk calculations use the same algorithms regardless of execution order or parallelism.

5. **Quick Scan mode is opt-in** — operators explicitly choose reduced coverage when speed is the priority. Deep Scan remains the default.

---

## 6. Recommended Implementation Order

**Week 1 (Tier 1 — immediate wins):**
1. LLM timeout protection (2 hours)
2. Cache KEV catalog and exploit DB (1 hour)
3. Move GitHub connectors to background queue (2 hours)
4. Parallelize independent LLM stages (4 hours)

**Week 2 (Tier 2 — measured improvements):**
5. Increase domain concurrency to 3 with LLM rate limiter (3 hours)
6. Implement cross-domain connector caching (4 hours)
7. Reduce LLM prompt size (6 hours)

**Week 3+ (Tier 3 — strategic enhancements):**
8. Quick Scan vs. Deep Scan modes (16 hours)
9. Pre-compute shared intelligence (8 hours)
10. Differential scanning (24 hours)

---

## Appendix A: Production Scan Timing Data

From the Master Test Range scan (March 9, 2026):

| Connector | Before Fix | After Fix | Improvement |
|-----------|-----------|-----------|-------------|
| cloud_assets | 405s | 2.5s | **162x faster** |
| shodan | 449s | 19.4s | **23x faster** |
| github_leaks | 157s+ | 30s (hard cap) | **5x faster** |
| github_recon | 157s+ | 30s (hard cap) | **5x faster** |
| shodan_internetdb | 0.1s | 0.1s | No change |
| crt.sh | 1.2s | 1.2s | No change |

**Batch 1 total:** ~3 minutes (was 20+ minutes)  
**Projected 20-domain total:** ~30 minutes (was 3+ hours)
