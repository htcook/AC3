# Roadmap Audit: Existing Capabilities vs. Gaps

## 1. SOC/SIEM Integration (HIGH PRIORITY)
**Existing:**
- `server/lib/siem-connectors.ts` — Wazuh + Elastic connectors, alert normalization, detection correlation
- `server/lib/siem-feedback.ts` — Splunk, Elastic, Sentinel, QRadar query functions + connection testing
- `server/lib/siem-mutation-engine.ts` — SIEM rule mutation/evasion testing (1300+ lines)
- `server/routers/siem-connectors.ts` — tRPC router for SIEM connectors
- `server/routers/siem-feedback.ts` — tRPC router for SIEM feedback loop
- `client/src/pages/SiemConnectors.tsx` — Frontend for SIEM connector management
- `client/src/pages/SiemFeedback.tsx` — Frontend for SIEM detection feedback

**Gaps to fill:**
- No unified SOC Integration Hub page that ties all SIEM features together
- No auto-export of engagement findings to SIEM as structured alerts
- No real-time detection gap analysis (attack executed → was it detected?)
- No SIEM health dashboard showing connector status, alert volume, detection rates

## 2. Cloud Workload Testing (HIGH PRIORITY)
**Existing:**
- `server/lib/cloud-security-validation.ts` — CIS benchmark checks for AWS/Azure/GCP (IAM, networking, storage, compute, logging)
- `server/lib/cloud-attack-chain-designer.ts` — LLM-powered cloud attack chain generation
- `server/lib/cloud-iam-enumerator.ts` — AWS/Azure/GCP IAM enumeration
- `server/lib/cloud-storage-scanner.ts` — Cloud storage misconfiguration scanning
- `server/lib/cloud-attack-paths.ts` — Cloud attack path catalog (AWS/Azure/GCP)
- `client/src/pages/CloudAttackPaths.tsx`, `CloudCredentials.tsx`, `CloudSecurityValidation.tsx`

**Gaps to fill:**
- No unified Cloud Workload Testing dashboard
- No container/Kubernetes scanning
- No serverless function security testing
- No cloud-to-on-prem lateral movement simulation
- No multi-cloud comparison view

## 3. LLM Reliability Hardening (HIGH PRIORITY)
**Existing:**
- `server/_core/llm.ts` — Already has retry (3 attempts), exponential backoff (2s→4s→8s), retryable status codes (403, 429, 500, 502, 503, 504), 90s timeout, network error retry
- LLM telemetry recording with caller, engagement ID, status, error tracking

**Gaps to fill:**
- No circuit breaker pattern (if LLM is down, keep hammering it)
- No prompt caching/deduplication (same scan data → same prompt → redundant calls)
- No fallback prompt simplification (if complex prompt fails, try simpler version)
- No LLM health dashboard showing success rates, latency percentiles, error patterns
- No cost tracking/budgeting per engagement

## 4. Agent-Based Deployment (MEDIUM PRIORITY)
**Existing:**
- `server/lib/agent-heartbeat.ts` — Full heartbeat processing, watchdog sweep, scheduler
- `server/routers/agent-manager.ts` — Agent deployment, approval, pause/resume, audit chain
- `client/src/pages/AgentManager.tsx`, `AgentDeploy.tsx`, `Agents.tsx`

**Gaps to fill:**
- No agent installer generator (one-liner for target OS)
- No agent auto-update mechanism
- No agent capability negotiation (what tools are available on the agent)
- No agent-to-agent lateral movement coordination

## 5. MSSP Multi-Tenant Mode (MEDIUM PRIORITY)
**Existing:**
- `server/routers/tenants.ts` — Basic tenant router
- `server/routers/tenant-management.ts` — Tenant management router
- `server/routers/tenant-onboarding.ts` — Tenant onboarding router
- `client/src/pages/Tenants.tsx`, `TenantOnboarding.tsx`

**Gaps to fill:**
- No tenant-scoped data isolation (engagements, scans, findings per tenant)
- No MSSP dashboard with cross-tenant analytics
- No tenant billing/usage tracking
- No white-label report generation per tenant
- No tenant-specific LLM learning isolation

## 6. Data Exfiltration Simulation (MEDIUM PRIORITY)
**Existing:**
- `data_exfiltration` as a campaign archetype category
- Exfiltration mentioned in domain intel port scanning context

**Gaps to fill:**
- No dedicated exfiltration simulation engine
- No DLP bypass testing (DNS tunneling, steganography, encrypted channels)
- No data classification simulation
- No exfiltration detection validation against SIEM
- No exfiltration path visualization
