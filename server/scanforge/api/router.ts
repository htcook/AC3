/**
 * ScanForge API Router
 *
 * Unified RESTful API for scan lifecycle management.
 * Replaces the per-tool SSH invocation pattern with a clean API:
 *
 *   POST   /api/v1/scans           — Create and enqueue a new scan
 *   GET    /api/v1/scans           — List all scans
 *   GET    /api/v1/scans/:id       — Get scan status and results
 *   POST   /api/v1/scans/:id/pause — Pause a running scan
 *   POST   /api/v1/scans/:id/resume — Resume a paused scan
 *   DELETE /api/v1/scans/:id       — Cancel a scan
 *   GET    /api/v1/templates       — List available templates
 *   GET    /api/v1/protocols       — List available protocol scanners
 *   GET    /api/v1/intelligence    — Get TI enrichment for a target
 *   GET    /api/v1/health          — Health check
 *   WS     /api/v1/scans/:id/ws    — Real-time scan events
 *
 * This router is mounted on the existing Express server under /api/v1.
 */

import { Router, Request, Response } from "express";
import { randomUUID } from "crypto";
import { getScanQueue } from "../queue/scan-queue";
import { getTemplateEngine } from "../engine/template-engine";
import { getProtocolRegistry } from "../protocols/registry";
import { getIntelligenceEngine } from "../intelligence/ti-engine";
import { ScanOrchestrator } from "../engine/scan-orchestrator";
import type {
  ScanRequest,
  ScanTarget,
  ScanType,
  ScanPriority,
  ScanConfig,
} from "../types";

const router = Router();

// ─── Middleware ─────────────────────────────────────────────────────────────

// API key validation (uses the same CALDERA_API_KEY or a dedicated SCANFORGE_API_KEY)
router.use((req: Request, res: Response, next) => {
  const apiKey = req.headers["x-api-key"] || req.headers.authorization?.replace("Bearer ", "");
  const validKey = process.env.SCANFORGE_API_KEY || process.env.CALDERA_API_KEY;

  if (!validKey || apiKey === validKey) {
    next();
  } else {
    res.status(401).json({ error: "Invalid API key" });
  }
});

// ─── Health ────────────────────────────────────────────────────────────────

router.get("/health", (_req: Request, res: Response) => {
  const queue = getScanQueue();
  const templates = getTemplateEngine();
  const protocols = getProtocolRegistry();

  res.json({
    status: "healthy",
    version: "1.0.0",
    uptime: process.uptime(),
    queue: queue.getStatus(),
    templates: templates.count,
    protocols: protocols.count,
    protocolList: protocols.listProtocols(),
  });
});

// ─── Scans ─────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/scans — Create a new scan
 *
 * Body:
 *   targets: Array<{ type, value, ports?, services? }>
 *   type: "quick" | "web" | "network" | "full" | "recon" | "compliance"
 *   priority?: "critical" | "high" | "medium" | "low"
 *   config?: { maxConcurrency, scannerTimeoutSeconds, ... }
 *   templateIds?: string[]  — Specific templates to run
 *   engagementId?: number   — Link to AC3 engagement
 *   callbackUrl?: string    — Webhook for completion notification
 *   intelligence?: { targetIndustry, threatActors, ... }
 */
router.post("/scans", async (req: Request, res: Response) => {
  try {
    const {
      targets,
      type = "full",
      priority = "medium",
      config,
      templateIds,
      engagementId,
      callbackUrl,
      intelligence,
    } = req.body;

    // Validate targets
    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: "At least one target is required" });
    }

    const validTypes: ScanType[] = ["quick", "web", "network", "full", "recon", "compliance"];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `Invalid scan type. Must be one of: ${validTypes.join(", ")}` });
    }

    // Build scan request
    const scanRequest: ScanRequest = {
      id: randomUUID(),
      targets: targets.map((t: any) => ({
        type: t.type || "domain",
        value: t.value,
        ports: t.ports,
        services: t.services,
      })),
      type: type as ScanType,
      priority: (priority || "medium") as ScanPriority,
      config: config || {},
      templateIds,
      engagementId,
      callbackUrl,
      intelligence,
      createdAt: Date.now(),
    };

    // Enqueue the scan
    const queue = getScanQueue();
    const job = queue.enqueue(scanRequest);

    res.status(201).json({
      id: scanRequest.id,
      status: job.status,
      position: queue.getStatus().queued,
      message: "Scan queued successfully",
      links: {
        status: `/api/v1/scans/${scanRequest.id}`,
        events: `/api/v1/scans/${scanRequest.id}/ws`,
        cancel: `/api/v1/scans/${scanRequest.id}`,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/v1/scans — List all scans
 */
router.get("/scans", (_req: Request, res: Response) => {
  const queue = getScanQueue();
  const jobs = queue.getAllJobs();

  res.json({
    total: jobs.length,
    queue: queue.getStatus(),
    scans: jobs.map(j => ({
      id: j.request.id,
      type: j.request.type,
      targets: j.request.targets.map(t => t.value),
      status: j.status,
      progress: j.progress,
      phase: j.phase,
      currentScanner: j.currentScanner,
      findingCount: j.findings.length,
      scannerCount: j.scannerResults.length,
      startedAt: j.startedAt,
      completedAt: j.completedAt,
      error: j.error,
      engagementId: j.request.engagementId,
    })),
  });
});

/**
 * GET /api/v1/scans/:id — Get scan details
 */
router.get("/scans/:id", (req: Request, res: Response) => {
  const queue = getScanQueue();
  const job = queue.getJob(req.params.id);

  if (!job) {
    return res.status(404).json({ error: "Scan not found" });
  }

  res.json({
    id: job.request.id,
    type: job.request.type,
    targets: job.request.targets,
    status: job.status,
    progress: job.progress,
    phase: job.phase,
    currentScanner: job.currentScanner,
    findings: job.findings,
    scannerResults: job.scannerResults,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
    error: job.error,
    config: job.request.config,
    engagementId: job.request.engagementId,
  });
});

/**
 * POST /api/v1/scans/:id/pause — Pause a running scan
 */
router.post("/scans/:id/pause", (req: Request, res: Response) => {
  const queue = getScanQueue();
  const success = queue.pause(req.params.id);

  if (success) {
    res.json({ message: "Scan paused", id: req.params.id });
  } else {
    res.status(400).json({ error: "Cannot pause scan (not running)" });
  }
});

/**
 * POST /api/v1/scans/:id/resume — Resume a paused scan
 */
router.post("/scans/:id/resume", (req: Request, res: Response) => {
  const queue = getScanQueue();
  const success = queue.resume(req.params.id);

  if (success) {
    res.json({ message: "Scan resumed", id: req.params.id });
  } else {
    res.status(400).json({ error: "Cannot resume scan (not paused)" });
  }
});

/**
 * DELETE /api/v1/scans/:id — Cancel a scan
 */
router.delete("/scans/:id", (req: Request, res: Response) => {
  const queue = getScanQueue();
  const success = queue.cancel(req.params.id);

  if (success) {
    res.json({ message: "Scan cancelled", id: req.params.id });
  } else {
    res.status(404).json({ error: "Scan not found or already completed" });
  }
});

// ─── Templates ─────────────────────────────────────────────────────────────

/**
 * GET /api/v1/templates — List available scan templates
 */
router.get("/templates", (req: Request, res: Response) => {
  const engine = getTemplateEngine();
  const { protocol, tags, severity } = req.query;

  const templates = engine.query({
    protocol: protocol as string,
    tags: tags ? (tags as string).split(",") : undefined,
    severity: severity ? (severity as string).split(",") as any : undefined,
  });

  res.json({
    total: templates.length,
    templates: templates.map(t => ({
      id: t.id,
      name: t.name,
      description: t.description,
      protocol: t.protocol,
      severity: t.severity,
      tags: t.tags,
      author: t.author,
      references: t.references,
    })),
  });
});

// ─── Protocols ─────────────────────────────────────────────────────────────

/**
 * GET /api/v1/protocols — List available protocol scanners
 */
router.get("/protocols", (_req: Request, res: Response) => {
  const registry = getProtocolRegistry();
  const scanners = registry.getAll();

  res.json({
    total: scanners.length,
    protocols: scanners.map(s => ({
      name: s.name,
      protocol: s.protocol,
      defaultPorts: s.defaultPorts,
    })),
  });
});

// ─── Intelligence ──────────────────────────────────────────────────────────

/**
 * GET /api/v1/intelligence — Get TI enrichment for a target
 */
router.get("/intelligence", async (req: Request, res: Response) => {
  const { target, industry } = req.query;

  if (!target) {
    return res.status(400).json({ error: "Target parameter is required" });
  }

  const engine = getIntelligenceEngine();
  await engine.initialize();

  const scanTarget: ScanTarget = {
    type: "domain",
    value: target as string,
  };

  const dfirChecks = engine.getDFIRInformedChecks(scanTarget);

  res.json({
    target: target,
    dfirRecommendedChecks: dfirChecks,
    enrichmentAvailable: true,
  });
});

// ─── Export ────────────────────────────────────────────────────────────────

export { router as scanforgeRouter };

// ─── Initialize ScanForge ──────────────────────────────────────────────────

let _initialized = false;

export async function initializeScanForge(): Promise<void> {
  if (_initialized) return;

  console.log("[ScanForge] Initializing...");

  const queue = getScanQueue({
    maxConcurrency: parseInt(process.env.SCANFORGE_MAX_CONCURRENCY || "3", 10),
    maxQueueDepth: parseInt(process.env.SCANFORGE_MAX_QUEUE_DEPTH || "50", 10),
    jobTimeoutMs: parseInt(process.env.SCANFORGE_JOB_TIMEOUT_MS || "1800000", 10),
  });

  const orchestrator = new ScanOrchestrator(queue);
  await orchestrator.initialize();

  _initialized = true;
  console.log("[ScanForge] Ready");
}
