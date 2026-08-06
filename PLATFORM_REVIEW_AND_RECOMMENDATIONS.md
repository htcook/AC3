# AC3 Platform — Comprehensive Review & Improvement Recommendations

**Date:** May 5, 2026  
**Reviewer:** Claude (AI Engineering Assistant)  
**Platform:** Ace of Cloud C3 (Caldera Dashboard)  
**Scale:** ~1M LOC | 307 pages | 234 routers | 566 server modules | 88 passive connectors | 378 test files

---

## Executive Summary

The AC3 platform is an extraordinarily comprehensive offensive security and threat intelligence platform. It combines attack surface management, penetration testing automation, threat intelligence, compliance mapping, and reporting into a single unified system. The codebase demonstrates deep domain expertise in cybersecurity operations.

After a thorough audit, I've identified **high-impact improvements** organized by priority and effort level. These focus on areas where I can provide the most value: architecture hardening, intelligence pipeline enhancement, UX refinement, and operational reliability.

---

## 1. HIGH PRIORITY — Immediate Impact

### 1.1 Polymarket OSINT Feed Integration (Missing Requirement)

**Status:** Not implemented (0 references in codebase)  
**Impact:** Geopolitical threat intelligence enrichment for regional dashboards

The platform has no Polymarket integration despite it being a documented requirement. Prediction markets provide leading indicators for geopolitical events that correlate with cyber threat activity (state-sponsored attacks often follow geopolitical tensions).

**What I can build:**
- A `polymarket-feed.ts` connector that polls Polymarket's API for contracts related to cyber events, geopolitical conflicts, and sanctions
- Keyword extraction pipeline that routes relevant signals to Iran/Russia/China/Cyber dashboards
- Confidence-weighted scoring based on market liquidity and resolution probability

---

### 1.2 Automatic Keyword Addition for Threat Actors (Missing Requirement)

**Status:** Not implemented (0 references for auto-keyword)  
**Impact:** Ensures new threat actors are automatically tracked across all feeds

When new threat actor names are identified (from CISA advisories, dark web crawls, or threat intel feeds), they should automatically be added to the keyword watchlist that filters data feeds.

**What I can build:**
- Hook into the existing `threat-actor-discovery.ts` and `threat-actor-crawler.ts` modules
- Auto-extract actor names/aliases and add them to the keyword list
- Deduplication and alias resolution (e.g., "Volt Typhoon" = "VANGUARD PANDA" = "BRONZE SILHOUETTE")

---

### 1.3 E2E Test Suite (Critical Gap)

**Status:** 0 E2E tests exist  
**Impact:** Prevents regressions in critical user flows (report generation, scan execution, engagement lifecycle)

With 307 pages and complex multi-step workflows, the platform has zero end-to-end tests. Unit tests (378 files) cover individual modules, but no tests verify the full user journey.

**What I can build:**
- Playwright E2E test suite covering the top 10 critical flows:
  1. DI scan initiation → completion → report download
  2. Engagement creation → scan execution → findings → report generation
  3. Customer portal login → view reports → download
  4. Threat intel feed ingestion → alert generation
  5. Compliance scan → evidence collection → export

---

### 1.4 Large Page Decomposition (Performance)

**Status:** Several pages exceed 5000+ lines (EngagementOps: 8573, DomainIntelResults: 7088)  
**Impact:** Faster initial load, better code maintainability, reduced bundle size per route

**What I can build:**
- Decompose `EngagementOps.tsx` (8573 lines) into sub-route components with proper code splitting
- Split `DomainIntelResults.tsx` (7088 lines) into tab-level lazy-loaded components
- Implement route-level prefetching for predictable navigation patterns

---

## 2. MEDIUM PRIORITY — Strategic Improvements

### 2.1 Diplomatic/Geopolitical Intelligence Feed Enhancement

**Status:** 29 references exist (basic implementation)  
**Impact:** Better context for state-sponsored threat attribution

The platform has some geopolitical awareness but could be significantly enhanced with structured feeds from:
- US State Department press releases (RSS)
- UN Security Council resolutions
- OFAC sanctions list updates (auto-parsed)
- EU/UK sanctions updates

**What I can build:**
- Structured ingestion pipeline for diplomatic sources
- Auto-correlation between sanctions announcements and threat actor activity spikes
- Timeline visualization showing geopolitical events alongside cyber incidents

---

### 2.2 Customer Portal Enhancement

**Status:** Basic implementation (18 references)  
**Impact:** Client self-service reduces operational overhead

The customer portal exists but could be significantly improved for MSSP operations:

**What I can build:**
- Real-time scan progress dashboard for customers (SSE-based)
- Self-service report download with watermarking
- Remediation tracking interface (customers mark findings as fixed, triggering re-verification)
- SLA compliance dashboard showing response times and resolution rates
- Customizable alert preferences (email/webhook/Slack)

---

### 2.3 STIX/TAXII 2.1 Server (Intelligence Sharing)

**Status:** STIX export exists, but no TAXII server for bidirectional sharing  
**Impact:** Enables automated threat intel sharing with ISACs, partners, and government agencies

**What I can build:**
- TAXII 2.1 compliant server endpoint
- Collection management (per-customer, per-sector feeds)
- Automatic STIX bundle generation from DI scan findings
- Subscriber management with access controls

---

### 2.4 Attack Surface Change Detection & Alerting

**Status:** Delta comparison exists (`delta-comparison.ts`) but no continuous monitoring loop  
**Impact:** Proactive alerting when new assets appear or configurations change

**What I can build:**
- Scheduled ASM scans (daily/weekly) with diff-based alerting
- New subdomain detection alerts
- Certificate expiry monitoring
- DNS record change notifications
- Port/service change detection with risk scoring

---

### 2.5 Report Template Customization Engine

**Status:** Reports use hardcoded Ace of Cloud branding  
**Impact:** White-label capability for MSSP customers

**What I can build:**
- Template engine with customer-specific branding (logo, colors, fonts)
- Custom section ordering and inclusion/exclusion rules
- Executive summary tone adjustment (technical vs. business audience)
- Multi-format output (PDF, DOCX, HTML, PPTX for board presentations)

---

## 3. LOWER PRIORITY — Quality of Life

### 3.1 Structured Logging Migration

**Status:** 28 references to structured logging (mostly `console.log`)  
**Impact:** Better debugging, alerting, and audit trail in production

The platform uses `console.log` extensively (~1000+ instances). Migrating to structured JSON logging with correlation IDs would dramatically improve production debugging.

**What I can build:**
- Pino-based structured logger with request correlation IDs
- Log level management per module
- Sensitive data redaction (API keys, credentials, PII)
- Integration with CloudWatch/Datadog/ELK

---

### 3.2 API Documentation Generation

**Status:** 79 references to API docs, no auto-generated docs  
**Impact:** Developer onboarding, customer API integration

With 234 routers and thousands of tRPC procedures, there's no auto-generated API documentation.

**What I can build:**
- Auto-generated OpenAPI spec from tRPC router definitions
- Interactive API explorer (Swagger UI equivalent)
- Customer-facing API docs for the customer portal endpoints
- Webhook payload documentation with examples

---

### 3.3 Performance Profiling Dashboard

**Status:** Performance monitoring exists (968 references) but no unified view  
**Impact:** Identify slow queries, LLM bottlenecks, and API latency issues

**What I can build:**
- Real-time performance dashboard showing:
  - tRPC procedure latency percentiles (p50, p95, p99)
  - LLM call duration and token usage
  - Database query performance (slow query log)
  - External API call success rates and latency
- Automated alerting on performance degradation

---

### 3.4 Accessibility Audit & Remediation

**Status:** 87 ARIA references (minimal for 307 pages)  
**Impact:** Section 508 compliance, broader usability

For a platform serving government/FedRAMP customers, accessibility is important:

**What I can build:**
- Full WCAG 2.1 AA audit of critical flows
- Keyboard navigation improvements
- Screen reader optimization for data tables and charts
- Color contrast fixes for the dark theme
- Focus management for modal dialogs and slide-over panels

---

### 3.5 Intelligent Scan Scheduling & Resource Optimization

**Status:** Scan scheduler exists but no intelligent resource allocation  
**Impact:** Prevent scan server overload, optimize scan completion times

**What I can build:**
- Priority queue with resource-aware scheduling
- Scan duration estimation based on historical data
- Auto-scaling recommendations based on queue depth
- Conflict detection (don't scan same target from multiple engagements simultaneously)
- SLA-aware scheduling (prioritize scans approaching deadline)

---

## 4. Architecture Observations

### Strengths
- **Comprehensive coverage:** 80+ OSINT connectors, 37 scan templates, 27 protocol scanners
- **LLM integration:** 418 invokeLLM calls demonstrate deep AI-augmented analysis
- **Resilience:** Circuit breakers, rate limiting, retry logic throughout
- **Security:** Zod validation (8950 references), parameterized queries (7700), RBAC
- **Real-time:** SSE/WebSocket support (17585 references) for live scan updates
- **Multi-tenancy:** 1299 tenant-aware references

### Areas of Concern
- **Memory pressure:** 768MB heap limit with 1M LOC codebase — consider more aggressive code splitting on the server side
- **Schema size:** 8396 lines in a single schema file — consider splitting by domain
- **Page size:** Top pages exceed 7000+ lines — decomposition needed
- **No E2E tests:** High risk of regression in complex multi-step workflows
- **Console logging:** Production debugging relies on unstructured console.log

---

## 5. Quick Wins (< 1 hour each)

| # | Improvement | Impact |
|---|---|---|
| 1 | Add `robots.txt` and `security.txt` to customer portal | Professionalism |
| 2 | Implement request timeout middleware (30s default) | Prevent hung requests |
| 3 | Add `Cache-Control` headers to static API responses | Performance |
| 4 | Create a `/api/health` endpoint for load balancer health checks | Reliability |
| 5 | Add CSP headers to prevent XSS in report rendering | Security |
| 6 | Implement graceful shutdown handler for in-flight scans | Data integrity |
| 7 | Add retry logic to the DI report PDF export (the fix we just did) | UX |
| 8 | Create index on `report_findings.risk_owner` column | Query performance |

---

## Recommended Next Steps

1. **Immediate:** Let me implement the Polymarket feed + auto-keyword system (addresses two documented requirements)
2. **This week:** Let me build the E2E test suite for the top 5 critical flows
3. **This sprint:** Let me decompose the large pages and add the attack surface change detection system
4. **Strategic:** Customer portal enhancement + STIX/TAXII server for intelligence sharing

---

*Which of these would you like me to start on? I can tackle multiple items in parallel.*
