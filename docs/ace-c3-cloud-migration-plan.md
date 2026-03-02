# Ace C3 Platform — Cloud Migration & Project Size Reduction Plan

**Prepared for:** AceofCloud  
**Date:** March 2, 2026  
**Author:** Manus AI

---

## 1. Current State Assessment

The Ace C3 platform has grown into a substantial full-stack application. Before discussing what to offload to DigitalOcean, it is important to understand exactly where the weight sits.

### 1.1 Project Size Breakdown

| Component | Size | Lines of Code | Files |
|---|---|---|---|
| **Server source code** (excl. tests) | 13 MB | 232,821 | 418 |
| **Server test code** | — | 73,904 | 221 |
| **Client source code** | 7.4 MB | 144,132 | 314 (199 pages, 80 components) |
| **Drizzle schema** | — | 6,249 | 1 file, 220 tables |
| **Drizzle migrations** | 33 MB | 4,846 | 73 SQL files |
| **Built dist (frontend + server)** | 35 MB | — | — |
| **node_modules** | 793 MB | — | — |
| **Total project (excl. node_modules)** | **92 MB** | **~451,000** | **~950** |

### 1.2 The Core Problem

The entire platform — web dashboard, background data pipelines, scan orchestration, C2 integration, OSINT connectors, LLM analysis, and WebSocket real-time feeds — runs as a **single Node.js process**. This monolith creates three critical issues:

1. **Memory pressure.** TypeScript compilation alone causes OOM errors. The runtime process holds all 220 database table schemas, 94 npm dependencies, and every background scheduler in a single heap.

2. **Deployment coupling.** A change to the phishing template UI requires redeploying the entire scan orchestrator, C2 bridge, and threat intel crawlers.

3. **No horizontal scaling.** Long-running scan pipelines (nmap, ZAP, domain intel) block the same event loop that serves the dashboard UI and WebSocket connections.

### 1.3 Heaviest Modules

The server-side code breaks down into distinct workload categories:

| Workload Category | Lines | Key Files | Nature |
|---|---|---|---|
| **Scan & Exploit Engine** | 38,270 | c2-abstraction, zap-scanner, credential-attack-engine, nmap-orchestrator, evasion-orchestrator | Long-running, CPU/network-heavy |
| **Data Pipelines** | 14,054 | vuln-feeds, threat-actor-crawler, darkweb-feeds, exploit-ingestion, org-enrichment | Scheduled, I/O-bound |
| **OSINT Connectors** | ~8,000 | 30+ files in server/lib/passive/ (Shodan, Censys, crt.sh, VirusTotal, etc.) | Burst I/O, API-rate-limited |
| **Core Router (routers.ts)** | 9,271 | Single file with all tRPC procedures | Should be split |
| **Engagement Orchestrator** | 2,443 | engagement-orchestrator.ts | Stateful, WebSocket-dependent |
| **Frontend Bundle** | 25 MB JS | mermaid (1.5 MB), cytoscape (632 KB), KaTeX (292 KB + 59 fonts), code highlight langs (~3 MB) | Bloated, needs tree-shaking |

---

## 2. DigitalOcean Architecture Recommendation

The goal is to decompose the monolith into **three tiers** that map cleanly to DigitalOcean services, allowing independent scaling, deployment, and failure isolation.

### 2.1 Target Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DigitalOcean App Platform                     │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │  Web Service  │  │  API Service  │  │  Worker Service    │   │
│  │  (Static SPA) │  │  (tRPC + WS)  │  │  (Scans/Pipelines)│   │
│  │  $0/mo (CDN)  │  │  $12-24/mo    │  │  $12-42/mo        │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬───────────┘   │
│         │                  │                    │               │
└─────────┼──────────────────┼────────────────────┼───────────────┘
          │                  │                    │
          │         ┌───────┴────────┐           │
          │         │  DO Managed    │           │
          │         │  MySQL $15/mo  │◄──────────┘
          │         └───────┬────────┘
          │                 │
          │         ┌───────┴────────┐
          └────────►│  DO Spaces     │
                    │  (S3) $5/mo    │
                    └────────────────┘
```

### 2.2 Service Mapping

| Current Component | DigitalOcean Service | Monthly Cost | Why |
|---|---|---|---|
| **Frontend SPA** | App Platform — Static Site | **$0** (free tier) | Vite build output served from CDN. No server needed. |
| **API Server** (tRPC, auth, WebSocket) | App Platform — Web Service (Basic, 1 GB) | **$12** | Handles dashboard requests, auth, real-time WS. Lightweight once scan logic is extracted. |
| **Scan Workers** (nmap, ZAP, domain intel, C2) | App Platform — Worker Service (CPU-Optimized, 2 vCPU) or Dedicated Droplet | **$12–42** | Long-running scans need dedicated CPU. No HTTP listener. Communicates via DB + Redis/queue. |
| **Data Pipelines** (vuln feeds, threat crawlers, darkweb) | DO Functions (Serverless) | **~$2–5** | Scheduled cron jobs. Run for 30–120 seconds, then sleep. Perfect for serverless. |
| **MySQL Database** | DO Managed MySQL (1 GB, single node) | **$15** | Automated backups, failover-ready. 220 tables fit easily in 1 GB for current scale. |
| **File Storage** (reports, scan artifacts) | DO Spaces | **$5** | S3-compatible. Already using S3 helpers in the codebase. |
| **Redis** (job queue, pub/sub for WS) | DO Managed Redis (1 GB) | **$15** | Replaces in-memory state. Enables API ↔ Worker communication. |

**Estimated total: $49–94/month** depending on worker sizing.

---

## 3. Project Size Reduction — What to Do Now

These changes can be made in the current Manus-hosted codebase and will immediately reduce build times, memory usage, and deployment size.

### 3.1 Split `routers.ts` (9,271 lines → ~30 files)

The single `routers.ts` file is the biggest maintainability bottleneck. It should be split into domain-specific router files that are already partially started in `server/routers/` (124 files exist there already, but `routers.ts` still holds the core procedures).

**Action:** Extract the remaining procedures from `routers.ts` into `server/routers/` by domain:
- `server/routers/engagement-ops.ts` — startPassiveScan, startActiveScan, stop, resetOps, getState
- `server/routers/domain-intel.ts` — runDomainIntel, getDomainIntelResults
- `server/routers/dashboard.ts` — stats, recent activity, overview queries
- `server/routers/reports.ts` — report generation procedures

This does not change functionality but makes the codebase navigable and reduces per-file TypeScript memory usage.

### 3.2 Trim Frontend Bundle (25 MB → ~8 MB)

The Vite build includes several large libraries that can be lazy-loaded or removed:

| Library | Current Size | Action |
|---|---|---|
| **Mermaid** | 1.5 MB | Lazy-load via `React.lazy()` — only DomainIntelResults uses it |
| **Cytoscape** | 632 KB | Lazy-load — only AbilityGraph page uses it |
| **KaTeX** | 292 KB JS + 1 MB fonts (59 files) | Lazy-load — only used in markdown rendering |
| **Code highlight languages** (emacs-lisp, cpp, wasm, wolfram, vue, angular) | ~3 MB | Configure highlight.js to only include languages you actually use (bash, json, yaml, python, javascript) |
| **html2canvas** | 200 KB | Lazy-load — only used for report export |

**Action:** Add dynamic imports in the Vite config and component-level `React.lazy()`:

```typescript
// Instead of: import Mermaid from 'mermaid'
// Use: const Mermaid = React.lazy(() => import('mermaid'))
```

Configure Vite's `build.rollupOptions.output.manualChunks` to split these into separate async chunks that only load when the user navigates to the relevant page.

### 3.3 Squash Drizzle Migrations (33 MB → ~1 MB)

You have 73 migration files totaling 33 MB. Since the database schema is fully captured in `schema.ts`, you can:

1. Export the current production database schema as a baseline
2. Delete all 73 migration files
3. Create a single `0000_baseline.sql` from the current schema
4. Future migrations start from `0001_*`

This is safe because the production database already has all migrations applied. The migration history is only needed for fresh database setup.

### 3.4 Extract Background Schedulers into Standalone Workers

The following modules run on `setInterval`/`setTimeout` inside the main API process and should be extracted:

| Scheduler | Current Location | Interval | Extraction Target |
|---|---|---|---|
| Vuln Feed Sync | vuln-feed-sync.ts | Periodic | DO Function (cron) |
| Threat Actor Crawler | threat-actor-crawler.ts | Periodic | DO Function (cron) |
| Darkweb Feed Scheduler | darkweb-feed-scheduler.ts | Periodic | DO Function (cron) |
| Scan Scheduler | scan-scheduler.ts | Periodic | Worker Service |
| Enrichment Scheduler | enrichment-scheduler.ts | Periodic | DO Function (cron) |
| FIPS Audit Scheduler | fips-audit-scheduler.ts | Periodic | DO Function (cron) |
| Crawler Scheduler | crawler-scheduler.ts | Periodic | DO Function (cron) |
| IOC Sync | ioc-sync.ts | Periodic | DO Function (cron) |

**Action:** Create a `worker/` directory at the project root. Move scheduler logic there. Each scheduler becomes a standalone script that:
- Connects to the same MySQL database
- Runs its pipeline
- Exits (for serverless) or sleeps (for worker service)

### 3.5 Introduce a Job Queue (BullMQ + Redis)

The current architecture uses in-memory state (`opsStates` Map) for scan progress. This is why:
- Scan state is lost on server restart
- The Stop button can fail if the reference breaks
- You cannot scale to multiple API instances

**Action:** Add BullMQ (backed by Redis) as a job queue:

```
API Server                    Redis (BullMQ)              Worker
────────────                  ──────────────              ──────
startPassiveScan() ──────►    queue.add('passive-scan')
                              ◄──────────────────────     worker.process()
getState() ◄─────────────    job.progress / job.data     updates job.progress
WebSocket broadcast ◄────    pub/sub channel             publishes events
```

This decouples the scan execution from the API server entirely. The API server becomes a thin layer that enqueues jobs and reads progress from Redis.

---

## 4. DigitalOcean Migration — Step-by-Step

### Phase 1: Database Migration (Week 1)

1. Provision a **DO Managed MySQL** instance (1 GB, $15/mo)
2. Squash migrations to a single baseline
3. Run `pnpm db:push` against the new DO MySQL instance
4. Update `DATABASE_URL` to point to DO MySQL
5. Verify all 220 tables are created and data migrates correctly

### Phase 2: Storage Migration (Week 1)

1. Create a **DO Spaces** bucket (S3-compatible)
2. Update the `storagePut`/`storageGet` helpers to use DO Spaces endpoint
3. Migrate existing S3 assets to DO Spaces (use `rclone` or `aws s3 sync`)

### Phase 3: Split Frontend from Backend (Week 2)

1. Build the Vite SPA as a standalone static site
2. Deploy frontend to **DO App Platform — Static Site** (free)
3. Configure API proxy rules so `/api/*` routes to the API service
4. Deploy API server to **DO App Platform — Web Service** ($12/mo)

### Phase 4: Extract Workers (Week 3)

1. Create `worker/` package with shared database access
2. Move scan orchestration (nmap, ZAP, domain intel, C2) into worker
3. Add BullMQ for job queuing between API and Worker
4. Deploy worker to **DO App Platform — Worker Service** ($12–42/mo)
5. Move scheduled pipelines to **DO Functions** with cron triggers

### Phase 5: Optimize & Harden (Week 4)

1. Add DO Managed Redis ($15/mo) for BullMQ + WebSocket pub/sub
2. Implement health checks and auto-restart policies
3. Set up DO monitoring alerts for CPU, memory, and disk
4. Configure DO firewall rules for the scan server
5. Enable DO database backups (automated daily)

---

## 5. DigitalOcean vs. AWS Comparison

Since you mentioned AWS as an alternative, here is a direct comparison for this workload:

| Capability | DigitalOcean | AWS | Verdict |
|---|---|---|---|
| **Managed MySQL** | $15/mo (1 GB) | $25–50/mo (RDS db.t3.micro) | DO is cheaper for small scale |
| **App Hosting** | $12/mo (App Platform) | $5–20/mo (Lightsail) or complex ECS/EKS | DO is simpler |
| **Static Site CDN** | Free (App Platform) | $0.50–5/mo (CloudFront + S3) | Comparable |
| **Object Storage** | $5/mo (250 GB + 1 TB transfer) | $5–10/mo (S3 + transfer fees) | DO is more predictable |
| **Serverless Functions** | $0–5/mo (90K GiB-sec free) | $0–5/mo (Lambda free tier) | Comparable |
| **Redis** | $15/mo (Managed) | $15–25/mo (ElastiCache) | Comparable |
| **Kubernetes** | $0 control plane + $12/node | $73/mo control plane + nodes | DO is much cheaper |
| **Complexity** | Low — flat pricing, simple UI | High — IAM, VPC, security groups | DO wins for small teams |
| **Compliance (FedRAMP, etc.)** | Limited | Full GovCloud | AWS wins for gov contracts |

**Recommendation:** Start with DigitalOcean for cost and simplicity. If you need FedRAMP compliance for government clients, plan a future migration path to AWS GovCloud for the production environment only.

---

## 6. Estimated Monthly Costs

### Starter Tier (Current Scale)

| Service | Spec | Cost |
|---|---|---|
| Static Site (Frontend) | App Platform free tier | $0 |
| API Service | 1 GB RAM, 1 vCPU | $12 |
| Worker Service | 2 GB RAM, 1 vCPU | $12 |
| Managed MySQL | 1 GB RAM, single node | $15 |
| Managed Redis | 1 GB RAM | $15 |
| Spaces (S3) | 250 GB storage | $5 |
| DO Functions | Scheduled pipelines | ~$2 |
| **Total** | | **~$61/mo** |

### Production Tier (Multi-client)

| Service | Spec | Cost |
|---|---|---|
| Static Site (Frontend) | App Platform free tier + CDN | $0 |
| API Service | 2 GB RAM, 1 vCPU (2 instances) | $24 |
| Worker Service | 4 GB RAM, 2 vCPU (dedicated) | $42 |
| Managed MySQL | 2 GB RAM, HA (2 nodes) | $60 |
| Managed Redis | 1 GB RAM | $15 |
| Spaces (S3) | 250 GB storage | $5 |
| DO Functions | Scheduled pipelines | ~$5 |
| Load Balancer | Standard | $12 |
| **Total** | | **~$163/mo** |

---

## 7. What We Can Build Right Now in the Codebase

The following changes can be implemented immediately within the Manus environment to prepare for cloud deployment:

1. **Split `routers.ts`** — Extract the remaining ~9,000 lines into domain-specific router files. This is pure refactoring with no behavior change.

2. **Add Vite chunk splitting config** — Configure `manualChunks` to lazy-load mermaid, cytoscape, KaTeX, and code highlight languages. Cuts frontend bundle from 25 MB to ~8 MB.

3. **Create a `worker/` entry point** — A separate `worker/index.ts` that imports scan orchestration modules and connects to BullMQ. This prepares the codebase for the API/Worker split without changing the current single-process deployment.

4. **Add a `Dockerfile`** — Multi-stage Docker build that produces a lean production image (~150 MB instead of 793 MB node_modules). This is required for DO App Platform deployment.

5. **Add `docker-compose.yml`** — Local development setup with MySQL + Redis + API + Worker, mirroring the production DO architecture.

6. **Squash migrations** — Consolidate 73 SQL files into a single baseline.

---

## 8. Summary

The Ace C3 platform at ~450,000 lines of code is a serious application that has outgrown the single-process deployment model. The path forward is:

1. **Immediate wins** (no architecture change): Split routers.ts, trim frontend bundle, squash migrations. This reduces cognitive load and build times today.

2. **Near-term** (1–2 weeks): Dockerize the application and deploy to DigitalOcean App Platform with separate API and Worker services. Add managed MySQL and Redis.

3. **Medium-term** (3–4 weeks): Extract scheduled pipelines to DO Functions. Implement BullMQ job queue for scan orchestration. This enables true horizontal scaling.

4. **Long-term**: If government compliance becomes a requirement, migrate the production environment to AWS GovCloud while keeping DO for development and staging.

The DigitalOcean architecture keeps costs at **$61–163/month** while giving you independent scaling, failure isolation, and a clear path to multi-tenant SaaS deployment.

---

## References

[1]: https://www.digitalocean.com/pricing/app-platform "DigitalOcean App Platform Pricing"
[2]: https://www.digitalocean.com/pricing/managed-databases "DigitalOcean Managed Database Pricing"
[3]: https://www.digitalocean.com/pricing/spaces-object-storage "DigitalOcean Spaces Pricing"
[4]: https://www.digitalocean.com/pricing/droplets "DigitalOcean Droplet Pricing"
[5]: https://www.digitalocean.com/pricing/functions "DigitalOcean Functions Pricing"
[6]: https://www.digitalocean.com/pricing/kubernetes "DigitalOcean Kubernetes Pricing"
