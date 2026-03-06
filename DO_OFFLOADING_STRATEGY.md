# DigitalOcean Infrastructure Offloading Strategy
## Reducing Manus Backend Load for the Caldera Dashboard Platform

**Author:** Harrison Cook / AceofCloud  
**Date:** March 6, 2026  
**Platform:** Caldera Dashboard v2.x (~248K lines, 438 modules)

---

## Executive Summary

The Caldera Dashboard currently runs all workloads on the Manus-hosted backend, including compute-intensive scanning, high-volume OSINT collection, feed ingestion, and LLM inference. This report identifies workloads that can be offloaded to DigitalOcean (DO) infrastructure to reduce Manus backend CPU/memory pressure by an estimated **95%** per engagement, while keeping the user-facing API, authentication, database, and real-time UI on Manus where they belong.

The strategy is organized into four priority tiers with a 6-week implementation roadmap and estimated monthly costs.

---

## Current Architecture & Bottlenecks

The Manus backend currently handles every workload in a single Node.js process:

```
┌────────────────────────────────────────────────────┐
│  Manus Backend (Single Node.js Process)            │
│                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ tRPC API │ │ WebSocket│ │ OAuth/   │  ← Keep   │
│  │ Layer    │ │ Hub      │ │ Sessions │           │
│  └──────────┘ └──────────┘ └──────────┘           │
│                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ 37 OSINT │ │ Feed     │ │ Scoring  │  ← Move   │
│  │ Connectors│ │ Ingest  │ │ Engine   │           │
│  └──────────┘ └──────────┘ └──────────┘           │
│                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Nmap/    │ │ ZAP      │ │ Nuclei   │  ← Move   │
│  │ Scanning │ │ Proxy    │ │ Engine   │           │
│  └──────────┘ └──────────┘ └──────────┘           │
│                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ C2 Bridge│ │ LLM      │ │ Report   │  ← Move   │
│  │          │ │ Inference│ │ Gen      │           │
│  └──────────┘ └──────────┘ └──────────┘           │
└────────────────────────────────────────────────────┘
```

The primary bottlenecks during an engagement are:

| Bottleneck | CPU Impact | Duration | Frequency |
|-----------|-----------|----------|-----------|
| Passive recon (37 connectors) | ~30s burst | 2-5 min | Per engagement |
| Active scanning (nmap/nuclei/ZAP) | ~5 min sustained | 10-30 min | Per engagement |
| Threat intel feed sync | ~15s burst | 30s | Hourly |
| NVD/CVE feed sync | ~45s burst | 2 min | Daily |
| LLM inference (scoring, planning) | ~2s per call | Variable | Per finding |
| Report generation | ~10s burst | 30s | Per engagement |

---

## What MUST Stay on Manus

These components depend on Manus platform services (auth, database, storage, LLM API) and cannot be moved:

| Component | Lines | Reason |
|-----------|-------|--------|
| tRPC API layer (147 routers) | 61,198 | User-facing, requires Manus OAuth |
| WebSocket event hub (`ws-event-hub.ts`) | 889 | Real-time UI updates via Manus proxy |
| Database access (Drizzle ORM) | N/A | TiDB managed by Manus platform |
| S3 storage (`storagePut`/`storageGet`) | N/A | Managed by Manus platform |
| OAuth/session management | N/A | Manus auth integration |
| LLM invocation (`invokeLLM`) | N/A | Uses Manus Forge API (BUILT_IN_FORGE_API_URL) |
| Engagement orchestrator (coordination) | 4,175 | Orchestration logic stays; execution moves |

---

## Priority 1: Scan Infrastructure (Week 1-2)

### Current State

The scan infrastructure already partially uses DigitalOcean. The `scan-server-executor.ts` (701 lines) SSHs into a DO droplet to execute nmap, nuclei, and other tools. However, the orchestration, result parsing, and SSH connection management all run on Manus.

### Target State

Move the entire scan execution loop to a DO worker that receives scan jobs from a Redis queue and pushes results back.

### Components to Move

| Component | Lines | Current | Target | Savings |
|-----------|-------|---------|--------|---------|
| `scan-server-executor.ts` | 701 | Manus (SSH to DO) | DO Worker (local exec) | Eliminates SSH overhead |
| `nmap-orchestrator.ts` | 704 | Manus | DO Worker | Local nmap execution |
| `nuclei-engine.ts` | 306 | Manus | DO Worker | Local nuclei execution |
| `zap-scanner.ts` | 1,714 | Manus | DO Worker | Local ZAP execution |
| `zap-proxy-orchestrator.ts` | 1,212 | Manus | DO Worker | Local ZAP proxy |
| `zap-attack-playbooks.ts` | 1,351 | Manus | DO Worker | Local playbook exec |
| `web-crawler.ts` | 907 | Manus | DO Worker | Bandwidth-intensive |
| `projectdiscovery.ts` | 738 | Manus | DO Worker | subfinder/httpx/etc. |
| `amass-engine.ts` | 880 | Manus | DO Worker | Amass enumeration |

### Architecture

```
┌─────────────────────┐          ┌──────────────────────────┐
│  Manus Backend      │          │  DO Scan Droplet         │
│                     │          │  (s-2vcpu-4gb, $24/mo)   │
│  Orchestrator ──────┼── Redis ─┼──→ Scan Worker           │
│  (job dispatch)     │  Queue   │     ├── nmap             │
│                     │          │     ├── nuclei            │
│  Result Handler ◀───┼── Redis ─┼──── ├── ZAP              │
│  (DB write)         │  Result  │     ├── subfinder/httpx   │
│                     │          │     └── amass             │
└─────────────────────┘          └──────────────────────────┘
```

### DO Resource Estimate

| Resource | Spec | Monthly Cost |
|----------|------|-------------|
| Scan Droplet | s-2vcpu-4gb (2 vCPU, 4GB RAM) | $24 |
| Managed Redis | db-s-1vcpu-1gb | $15 |
| **Subtotal** | | **$39/mo** |

### Implementation Steps

1. Create DO Droplet with nmap, nuclei, ZAP, subfinder, httpx, amass pre-installed
2. Deploy Redis instance on DO Managed Databases
3. Create scan worker service that polls Redis for jobs
4. Modify `engagement-orchestrator.ts` to dispatch scan jobs to Redis instead of SSH
5. Worker pushes results to Redis result queue; Manus handler writes to DB
6. Add health check endpoint on worker for monitoring

---

## Priority 2: Passive Recon Workers (Week 2-3)

### Current State

All 37 passive connectors run in the Manus Node.js process, making concurrent API calls to Shodan, Censys, crt.sh, AbuseIPDB, GitHub, etc. This creates CPU bursts and risks IP-based rate limiting from the Manus IP.

### Target State

Move all passive connectors to a DO App Platform Worker that processes recon jobs from the Redis queue. This gives a different source IP for API calls and eliminates CPU pressure on Manus.

### Components to Move

| Component | Lines | Current | Target |
|-----------|-------|---------|--------|
| `domainIntel.ts` | 3,068 | Manus | DO Worker |
| `domain-intel-advanced.ts` | 1,500 | Manus | DO Worker |
| All 37 `passive/*.ts` connectors | 10,826 | Manus | DO Worker |
| `org-domain-discovery.ts` | 932 | Manus | DO Worker |
| `org-enrichment.ts` | 1,049 | Manus | DO Worker |

### Architecture

```
┌─────────────────────┐          ┌──────────────────────────┐
│  Manus Backend      │          │  DO App Platform Worker  │
│                     │          │  (basic-xxs, $5/mo)      │
│  startPassiveScan() │          │                          │
│  ──→ Redis Queue ───┼──────────┼──→ OSINT Worker          │
│                     │          │     ├── Shodan            │
│  Result Handler ◀───┼──────────┼──── ├── Censys            │
│  (observation       │          │     ├── crt.sh            │
│   ingestor)         │          │     ├── GitHub            │
│                     │          │     ├── AbuseIPDB         │
│                     │          │     └── 32 more...        │
└─────────────────────┘          └──────────────────────────┘
```

### DO Resource Estimate

| Resource | Spec | Monthly Cost |
|----------|------|-------------|
| App Platform Worker | basic-xxs (1 vCPU, 512MB) | $5 |
| Shared Redis (from P1) | Already provisioned | $0 |
| **Subtotal** | | **$5/mo** |

---

## Priority 3: Threat Intel & Feed Processing (Week 3-4)

### Current State

Feed ingestion runs on Manus with scheduled jobs (hourly RSS, daily NVD/CVE sync, periodic MITRE ATT&CK crawl). These are CPU-intensive JSON/XML parsing operations that spike the Manus process.

### Target State

Move all feed processing to DO App Platform Workers running on cron schedules. Results are written directly to the shared database (TiDB supports external connections with SSL).

### Components to Move

| Component | Lines | Schedule | Target |
|-----------|-------|----------|--------|
| `threat-intel-ingest.ts` | 758 | On-demand | DO Worker |
| `threat-intel-rss.ts` | 775 | Every 15 min | DO Cron Worker |
| `threat-intel-connectors.ts` | 858 | On-demand | DO Worker |
| `threat-actor-crawler.ts` | 1,341 | Daily | DO Cron Worker |
| `vuln-feeds.ts` | 1,073 | Daily | DO Cron Worker |
| `vuln-feed-sync.ts` | 159 | Hourly | DO Cron Worker |
| `darkweb-feeds.ts` | 864 | Every 6 hours | DO Cron Worker |
| `darkweb-feed-scheduler.ts` | 351 | Scheduler | DO Cron Worker |
| `dailydarkweb-feed.ts` | 550 | Daily | DO Cron Worker |
| `dailydarkweb-rss.ts` | 408 | Every 4 hours | DO Cron Worker |
| `ransomware-intel.ts` | 451 | Every 6 hours | DO Cron Worker |
| `ioc-sync.ts` | 252 | Hourly | DO Cron Worker |

### Architecture

```
┌─────────────────────┐          ┌──────────────────────────┐
│  Manus Backend      │          │  DO App Platform         │
│                     │          │                          │
│  TiDB Database ◀────┼── SSL ───┼──── Feed Workers         │
│  (shared access)    │          │     ├── NVD/CVE Sync     │
│                     │          │     ├── RSS Aggregator    │
│                     │          │     ├── MITRE Crawler     │
│                     │          │     ├── Darkweb Feeds     │
│                     │          │     └── IOC Sync          │
│                     │          │                          │
│                     │          │  Cron Schedules:          │
│                     │          │  - */15 * * * * RSS      │
│                     │          │  - 0 * * * * IOC/Vuln    │
│                     │          │  - 0 */6 * * * Darkweb   │
│                     │          │  - 0 2 * * * NVD/MITRE   │
└─────────────────────┘          └──────────────────────────┘
```

### DO Resource Estimate

| Resource | Spec | Monthly Cost |
|----------|------|-------------|
| App Platform Worker (feeds) | basic-xs (1 vCPU, 1GB) | $10 |
| Shared Redis (from P1) | Already provisioned | $0 |
| **Subtotal** | | **$10/mo** |

### Database Access Note

The feed workers need direct database access to write ingested data. The Manus TiDB instance supports external SSL connections. The `DATABASE_URL` connection string with `?ssl=true` parameter should be configured as an environment variable in the DO App Platform.

---

## Priority 4: C2 & Exploitation Infrastructure (Week 5-6)

### Current State

C2 bridge operations (`c2-abstraction.ts`, 2,115 lines) route through the Manus backend, which is inappropriate for several reasons: C2 traffic should not traverse the Manus proxy, the Manus IP should not be associated with C2 operations, and C2 requires persistent connections that conflict with Manus's serverless-like architecture.

### Target State

Deploy a dedicated DO Droplet for C2 operations with Caldera, Cobalt Strike adapter, and Metasploit client. This droplet has its own IP address and persistent processes.

### Components to Move

| Component | Lines | Current | Target |
|-----------|-------|---------|--------|
| `c2-abstraction.ts` | 2,115 | Manus | DO C2 Droplet |
| `c2-orchestrator.ts` | 1,284 | Manus | DO C2 Droplet |
| `c2-actor-orchestration.ts` | 977 | Manus | DO C2 Droplet |
| `c2-module-builder.ts` | 1,057 | Manus | DO C2 Droplet |
| `c2-traffic-profiles.ts` | 665 | Manus | DO C2 Droplet |
| `c2-health.ts` | 381 | Manus | DO C2 Droplet |
| `cobalt-strike-adapter.ts` | 734 | Manus | DO C2 Droplet |
| `msf-client.ts` | 776 | Manus | DO C2 Droplet |
| `msf-provisioner.ts` | 338 | Manus | DO C2 Droplet |
| `payload-transform-pipeline.ts` | 966 | Manus | DO C2 Droplet |
| `redirector-manager.ts` | 747 | Manus | DO C2 Droplet |

### Architecture

```
┌─────────────────────┐          ┌──────────────────────────┐
│  Manus Backend      │          │  DO C2 Droplet           │
│  (Operator Console) │          │  (s-4vcpu-8gb, $48/mo)   │
│                     │          │                          │
│  Operator UI ───────┼── API ───┼──→ C2 API Server         │
│  (approve/reject)   │          │     ├── Caldera Agent    │
│                     │          │     ├── CS Adapter       │
│  Exploit Approval ──┼── API ───┼──→  ├── MSF Client       │
│  Gate               │          │     ├── Payload Builder  │
│                     │          │     └── Redirector Mgr   │
│                     │          │                          │
│                     │          │  Separate IP address     │
│                     │          │  Persistent processes    │
│                     │          │  Firewall: operator-only │
└─────────────────────┘          └──────────────────────────┘
```

### DO Resource Estimate

| Resource | Spec | Monthly Cost |
|----------|------|-------------|
| C2 Droplet | s-4vcpu-8gb (4 vCPU, 8GB RAM) | $48 |
| Reserved IP | Static IP for C2 | $5 |
| DO Firewall | Operator-only access rules | $0 |
| **Subtotal** | | **$53/mo** |

### Security Considerations

The C2 droplet requires strict security controls:

1. **Firewall rules**: Only allow SSH from operator IPs and API access from Manus backend IP
2. **Separate SSH key**: Dedicated ed25519 key for C2 droplet (already configured as `SCAN_SERVER_SSH_KEY`)
3. **No direct internet exposure**: C2 traffic routes through redirectors, not the droplet's public IP
4. **Audit logging**: All C2 commands logged with operator identity and timestamp
5. **Ephemeral storage**: Engagement data wiped after completion

---

## Total Cost Summary

| Priority | Component | Monthly Cost |
|----------|-----------|-------------|
| P1 | Scan Droplet + Redis | $39 |
| P2 | OSINT Worker | $5 |
| P3 | Feed Processing Worker | $10 |
| P4 | C2 Droplet + Reserved IP | $53 |
| **Total** | | **$107/mo** |

This is approximately **$1,284/year** for a **95% reduction** in Manus backend compute load per engagement.

---

## Performance Impact Estimates

| Workload | Before (Manus CPU) | After (Manus CPU) | Reduction |
|----------|--------------------|--------------------|-----------|
| Passive recon (per engagement) | ~30s burst | ~0.5s (dispatch only) | 98% |
| Active scanning (per engagement) | ~5 min sustained | ~5s (dispatch + result write) | 98% |
| Threat intel sync (hourly) | ~15s burst | 0s (runs on DO) | 100% |
| NVD/CVE feed sync (daily) | ~45s burst | 0s (runs on DO) | 100% |
| C2 operations | ~2 min per session | ~1s (API proxy only) | 99% |
| Report generation | ~10s burst | ~10s (stays on Manus) | 0% |
| **Total per-engagement** | **~6 min CPU** | **~30s CPU** | **~95%** |

---

## Implementation Roadmap

### Week 1: Foundation

- Provision DO Managed Redis (db-s-1vcpu-1gb)
- Create scan droplet with nmap, nuclei, ZAP, subfinder, httpx, amass
- Build generic job queue library (`@caldera/job-queue`) with Redis pub/sub
- Define job schemas: `ScanJob`, `ReconJob`, `FeedJob`, `C2Job`

### Week 2: Scan Worker Migration

- Deploy scan worker service on DO droplet
- Modify `engagement-orchestrator.ts` to dispatch scan jobs to Redis
- Build result handler on Manus to process scan results from Redis
- Test with Vianova engagement (3 RoE-scoped assets)
- Verify RoE scope guard still enforced (dispatch-side validation)

### Week 3: OSINT Worker Migration

- Deploy OSINT worker on DO App Platform
- Move all 37 passive connectors to worker
- Configure API keys as DO App Platform environment variables
- Modify `domainIntel.ts` to dispatch recon jobs to Redis
- Test with Vianova passive scan

### Week 4: Feed Worker Migration

- Deploy feed worker on DO App Platform with cron schedules
- Configure TiDB SSL connection for direct database writes
- Move NVD/CVE, RSS, MITRE, darkweb feed jobs to DO cron
- Verify feed data appears in Manus database
- Remove feed schedulers from Manus backend

### Week 5: C2 Infrastructure

- Provision dedicated C2 droplet with firewall rules
- Deploy C2 API server with Caldera, CS adapter, MSF client
- Configure operator-only SSH access
- Build C2 API proxy on Manus (thin wrapper for operator UI)
- Test C2 operations through approval gate

### Week 6: Integration Testing & Monitoring

- End-to-end test: full engagement lifecycle through DO infrastructure
- Set up DO Monitoring alerts for CPU, memory, disk on all droplets
- Configure Redis queue depth alerts
- Load test with concurrent engagements
- Document operational runbook

---

## Communication Protocol

### Manus to DO (Job Dispatch)

```typescript
interface JobMessage {
  id: string;           // UUID
  type: 'scan' | 'recon' | 'feed' | 'c2';
  engagementId: number;
  payload: {
    targets: string[];
    tools: string[];
    options: Record<string, unknown>;
  };
  metadata: {
    dispatchedAt: number;  // Unix timestamp
    dispatchedBy: string;  // Operator ID
    roeScope: string[];    // Authorized targets only
  };
}
```

### DO to Manus (Result Push)

```typescript
interface ResultMessage {
  jobId: string;
  status: 'completed' | 'failed' | 'partial';
  results: {
    tool: string;
    target: string;
    findings: Finding[];
    duration_ms: number;
    severity_summary: Record<string, number>;
  }[];
  metadata: {
    completedAt: number;
    workerHost: string;
  };
}
```

### Health Check

Each DO worker exposes a `/health` endpoint that the Manus backend polls every 30 seconds. If a worker is unhealthy for 3 consecutive checks, the Manus backend falls back to local execution.

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Redis queue failure | Manus falls back to local execution |
| DO droplet unavailable | Auto-restart via DO monitoring; Manus fallback |
| Network latency | Redis pub/sub adds ~5ms; negligible vs. scan duration |
| Database connection from DO | TiDB supports external SSL; connection pooling |
| API key exposure on DO | DO App Platform encrypted env vars |
| C2 droplet compromise | Firewall rules, separate SSH key, ephemeral storage |
| Cost overrun | DO billing alerts at $100, $150, $200 thresholds |

---

## Existing Infrastructure

The platform already has partial DO integration:

- **`SCAN_SERVER_HOST`**: DO droplet IP for scan execution
- **`SCAN_SERVER_USER`**: SSH user (root)
- **`SCAN_SERVER_SSH_KEY`**: ed25519 SSH key for DO access
- **`DIGITALOCEAN_ACCESS_TOKEN`**: DO API token for infrastructure management
- **`digitalocean-infra.ts`** (285 lines): Existing DO infrastructure management module

This means Priority 1 (scan infrastructure) is partially implemented. The main change is replacing SSH-based execution with Redis queue-based job dispatch.

---

## Decision Matrix: Move vs. Keep

For any module not explicitly listed above, use this decision matrix:

| Question | Yes → Move | No → Keep |
|----------|-----------|-----------|
| Does it make external API calls? | Move to DO (different IP) | Keep on Manus |
| Does it run on a schedule? | Move to DO cron | Keep on Manus |
| Does it process >1MB of data? | Move to DO worker | Keep on Manus |
| Does it need Manus auth? | Keep on Manus | Move to DO |
| Does it need `invokeLLM`? | Keep on Manus* | Move to DO |
| Does it write to the database? | Either (TiDB supports external) | N/A |

> *LLM inference could be moved to DO if a self-hosted LLM is deployed, but the Manus Forge API is currently the most cost-effective option.

---

*Generated: March 6, 2026 | Caldera Dashboard v2.x*
