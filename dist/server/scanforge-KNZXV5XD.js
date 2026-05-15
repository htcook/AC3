import {
  ATTACK_MAPPING_PROMPT,
  ATTACK_MAPPING_SCHEMA,
  EXECUTIVE_SUMMARY_PROMPT,
  EXECUTIVE_SUMMARY_SCHEMA,
  FALSE_POSITIVE_REVIEWER_PROMPT,
  FALSE_POSITIVE_REVIEWER_SCHEMA,
  FEDRAMP_ALIGNMENT_PROMPT,
  FEDRAMP_ALIGNMENT_SCHEMA,
  FINDING_ENRICHMENT_PROMPT,
  FINDING_ENRICHMENT_SCHEMA,
  PROMPT_REGISTRY,
  REMEDIATION_PLANNER_PROMPT,
  REMEDIATION_PLANNER_SCHEMA,
  REPORT_WRITER_PROMPT,
  REPORT_WRITER_SCHEMA,
  SCANFORGE_WORKFLOW_STAGES,
  STRICT_PASSIVE_MODE_POLICY,
  TRIAGE_RESPONSE_SCHEMA,
  TRIAGE_SYSTEM_PROMPT,
  batchScore,
  buildPromptMessages,
  computeAttackPathModifier,
  computeExploitabilityConfidence,
  computeExposureModifier,
  computeHybridScore,
  computeMissionImpact,
  computeTechnicalSeverity,
  getPromptsForStage,
  getResponseFormat,
  init_hybrid_scoring,
  init_llm_prompts,
  quickSeverityFromCvss
} from "./chunk-IECUZIQV.js";
import {
  CoverageGapDetector,
  DeduplicationEngine,
  NormalizationEngine,
  getCoverageGapDetector,
  getDeduplicationEngine,
  getNormalizationEngine,
  init_dedup_coverage
} from "./chunk-5L2O5ONH.js";
import {
  ContextEngine,
  FPFNPreventionEngine,
  IntelligenceEngine,
  ProtocolRegistry,
  ScanOrchestrator,
  ScanQueue,
  getContextEngine,
  getFPFNEngine,
  getIntelligenceEngine,
  getProtocolRegistry,
  getScanQueue
} from "./chunk-CZULG27S.js";
import {
  TemplateEngine,
  getTemplateEngine,
  init_template_engine
} from "./chunk-R4LF5PWF.js";
import "./chunk-KFQGP6VL.js";

// server/scanforge/api/router.ts
import { Router } from "express";
import { randomUUID } from "crypto";
init_template_engine();
var router = Router();
router.use((req, res, next) => {
  const apiKey = req.headers["x-api-key"] || req.headers.authorization?.replace("Bearer ", "");
  const validKey = process.env.SCANFORGE_API_KEY || process.env.CALDERA_API_KEY;
  if (!validKey || apiKey === validKey) {
    next();
  } else {
    res.status(401).json({ error: "Invalid API key" });
  }
});
router.get("/health", (_req, res) => {
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
    protocolList: protocols.listProtocols()
  });
});
router.post("/scans", async (req, res) => {
  try {
    const {
      targets,
      type = "full",
      priority = "medium",
      config,
      templateIds,
      engagementId,
      callbackUrl,
      intelligence
    } = req.body;
    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: "At least one target is required" });
    }
    const validTypes = ["quick", "web", "network", "full", "recon", "compliance", "cloud", "iot", "ics_ot", "container", "hybrid"];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `Invalid scan type. Must be one of: ${validTypes.join(", ")}` });
    }
    const scanRequest = {
      id: randomUUID(),
      targets: targets.map((t) => ({
        type: t.type || "domain",
        value: t.value,
        ports: t.ports,
        services: t.services
      })),
      type,
      priority: priority || "medium",
      config: config || {},
      templateIds,
      engagementId,
      callbackUrl,
      intelligence,
      createdAt: Date.now()
    };
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
        cancel: `/api/v1/scans/${scanRequest.id}`
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.get("/scans", (_req, res) => {
  const queue = getScanQueue();
  const jobs = queue.getAllJobs();
  res.json({
    total: jobs.length,
    queue: queue.getStatus(),
    scans: jobs.map((j) => ({
      id: j.request.id,
      type: j.request.type,
      targets: j.request.targets.map((t) => t.value),
      status: j.status,
      progress: j.progress,
      phase: j.phase,
      currentScanner: j.currentScanner,
      findingCount: j.findings.length,
      scannerCount: j.scannerResults.length,
      startedAt: j.startedAt,
      completedAt: j.completedAt,
      error: j.error,
      engagementId: j.request.engagementId
    }))
  });
});
router.get("/scans/:id", (req, res) => {
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
    engagementId: job.request.engagementId
  });
});
router.post("/scans/:id/pause", (req, res) => {
  const queue = getScanQueue();
  const success = queue.pause(req.params.id);
  if (success) {
    res.json({ message: "Scan paused", id: req.params.id });
  } else {
    res.status(400).json({ error: "Cannot pause scan (not running)" });
  }
});
router.post("/scans/:id/resume", (req, res) => {
  const queue = getScanQueue();
  const success = queue.resume(req.params.id);
  if (success) {
    res.json({ message: "Scan resumed", id: req.params.id });
  } else {
    res.status(400).json({ error: "Cannot resume scan (not paused)" });
  }
});
router.delete("/scans/:id", (req, res) => {
  const queue = getScanQueue();
  const success = queue.cancel(req.params.id);
  if (success) {
    res.json({ message: "Scan cancelled", id: req.params.id });
  } else {
    res.status(404).json({ error: "Scan not found or already completed" });
  }
});
router.get("/templates", (req, res) => {
  const engine = getTemplateEngine();
  const { protocol, tags, severity } = req.query;
  const templates = engine.query({
    protocol,
    tags: tags ? tags.split(",") : void 0,
    severity: severity ? severity.split(",") : void 0
  });
  res.json({
    total: templates.length,
    templates: templates.map((t) => ({
      id: t.id,
      name: t.name,
      description: t.description,
      protocol: t.protocol,
      severity: t.severity,
      tags: t.tags,
      author: t.author,
      references: t.references
    }))
  });
});
router.get("/protocols", (_req, res) => {
  const registry = getProtocolRegistry();
  const scanners = registry.getAll();
  res.json({
    total: scanners.length,
    protocols: scanners.map((s) => ({
      name: s.name,
      protocol: s.protocol,
      defaultPorts: s.defaultPorts,
      environments: s.environments || ["traditional"]
    }))
  });
});
router.get("/intelligence", async (req, res) => {
  const { target, industry } = req.query;
  if (!target) {
    return res.status(400).json({ error: "Target parameter is required" });
  }
  const engine = getIntelligenceEngine();
  await engine.initialize();
  const scanTarget = {
    type: "domain",
    value: target
  };
  const dfirChecks = engine.getDFIRInformedChecks(scanTarget);
  res.json({
    target,
    dfirRecommendedChecks: dfirChecks,
    enrichmentAvailable: true
  });
});
router.post("/context/classify", async (req, res) => {
  try {
    const { target, reconData } = req.body;
    if (!target?.value) {
      return res.status(400).json({ error: "Target with value is required" });
    }
    const engine = getContextEngine();
    await engine.initialize();
    const classification = await engine.classifyTarget(
      { type: target.type || "domain", value: target.value, ports: target.ports, services: target.services },
      reconData
    );
    res.json({ classification });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post("/context/correlate", async (req, res) => {
  try {
    const { findings, target, classification } = req.body;
    if (!findings?.length || !target?.value) {
      return res.status(400).json({ error: "Findings array and target are required" });
    }
    const engine = getContextEngine();
    await engine.initialize();
    const result = await engine.correlateFindings(
      findings,
      { type: target.type || "domain", value: target.value },
      classification || { environment: "traditional", confidence: 50 }
    );
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post("/context/enrich", async (req, res) => {
  try {
    const { finding, classification } = req.body;
    if (!finding?.id) {
      return res.status(400).json({ error: "Finding with id is required" });
    }
    const engine = getContextEngine();
    await engine.initialize();
    const narrative = await engine.enrichFinding(finding, classification);
    res.json(narrative);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post("/context/compliance", async (req, res) => {
  try {
    const { finding, frameworks } = req.body;
    if (!finding?.id || !frameworks?.length) {
      return res.status(400).json({ error: "Finding and frameworks array are required" });
    }
    const engine = getContextEngine();
    await engine.initialize();
    const mappings = await engine.mapToCompliance(finding, frameworks);
    res.json({ mappings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
var _initialized = false;
async function initializeScanForge() {
  if (_initialized) return;
  console.log("[ScanForge] Initializing...");
  const queue = getScanQueue({
    maxConcurrency: parseInt(process.env.SCANFORGE_MAX_CONCURRENCY || "3", 10),
    maxQueueDepth: parseInt(process.env.SCANFORGE_MAX_QUEUE_DEPTH || "50", 10),
    jobTimeoutMs: parseInt(process.env.SCANFORGE_JOB_TIMEOUT_MS || "1800000", 10)
  });
  const orchestrator = new ScanOrchestrator(queue);
  await orchestrator.initialize();
  _initialized = true;
  console.log("[ScanForge] Ready");
}

// server/scanforge/index.ts
init_template_engine();
init_dedup_coverage();
init_hybrid_scoring();
init_llm_prompts();

// server/scanforge/engine/detection-plugins.ts
var BUILTIN_PLUGINS = [
  // Apache Path Traversal (CVE-2021-41773)
  {
    id: "apache_path_traversal_cve_2021_41773",
    metadata: {
      title: "Apache HTTP Server Path Traversal Check",
      category: "web_server",
      safe_by_default: true,
      references: ["CVE-2021-41773"]
    },
    targeting: {
      service: ["http", "https"],
      ports: [80, 443, 8080, 8443],
      products: ["Apache httpd"]
    },
    preconditions: ["target responds to HTTP"],
    detection: {
      type: "http_request",
      method: "GET",
      path_candidates: ["/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"],
      success_indicators: ["root:x:"]
    },
    verification: { type: "bounded_content_check", confirm_only: true, max_bytes: 200 },
    output: {
      default_state: "probable",
      severity: "critical",
      tags: ["cve", "web", "path_traversal", "safe_validation"]
    }
  },
  // Azure Storage Public Blob Access
  {
    id: "azure_storage_public_access",
    metadata: {
      title: "Azure Storage Public Blob Access Exposure",
      category: "cloud_storage",
      safe_by_default: true,
      references: []
    },
    targeting: {
      service: ["https"],
      ports: [443],
      products: ["Azure Blob Storage"]
    },
    preconditions: ["hostname matches blob.core.windows.net or provider metadata suggests Azure storage"],
    detection: {
      type: "anonymous_http_probe",
      method: "GET",
      path_candidates: ["/"],
      success_indicators: ["BlobServiceProperties", "ContainerNotFound"]
    },
    verification: { type: "anonymous_listing_guarded", confirm_only: true },
    output: {
      default_state: "probable",
      severity: "high",
      tags: ["cloud", "storage", "exposure", "azure"]
    }
  },
  // NGINX Version Disclosure
  {
    id: "nginx_version_exposure",
    metadata: {
      title: "NGINX Version Disclosure",
      category: "web_server",
      safe_by_default: true,
      references: []
    },
    targeting: {
      service: ["http", "https"],
      ports: [80, 443, 8080, 8443],
      products: ["nginx"]
    },
    preconditions: ["server header is present or fingerprint confidence >= 0.6"],
    detection: {
      type: "response_header",
      header: "Server",
      regex: "nginx\\/([0-9.]+)"
    },
    verification: { type: "banner_confirmation" },
    output: {
      default_state: "informational",
      severity: "low",
      tags: ["disclosure", "fingerprinting", "web"]
    }
  },
  // Weak TLS Cipher / Protocol Support
  {
    id: "tls_weak_cipher_policy",
    metadata: {
      title: "Weak TLS Cipher / Protocol Support",
      category: "tls",
      safe_by_default: true,
      references: []
    },
    targeting: {
      service: ["https", "tls", "imaps", "smtps", "rdp"],
      ports: [443, 993, 465, 3389],
      products: []
    },
    preconditions: ["target negotiates TLS"],
    detection: {
      type: "tls_handshake_matrix",
      reject_if_supported: {
        protocols: ["SSLv3", "TLS1.0", "TLS1.1"],
        cipher_patterns: ["RC4", "3DES"]
      }
    },
    verification: { type: "repeat_handshake" },
    output: {
      default_state: "verified",
      severity: "medium",
      tags: ["tls", "crypto", "configuration"]
    }
  },
  // SSH Weak Ciphers
  {
    id: "ssh_weak_ciphers",
    metadata: {
      title: "SSH Weak Cipher Support",
      category: "network",
      safe_by_default: true,
      references: []
    },
    targeting: {
      service: ["ssh"],
      ports: [22, 2222],
      products: ["OpenSSH"]
    },
    preconditions: ["target accepts SSH connections"],
    detection: {
      type: "banner_grab",
      port: 22,
      protocol: "tcp",
      regex: "SSH-2\\.0-(.+)"
    },
    verification: { type: "banner_confirmation" },
    output: {
      default_state: "probable",
      severity: "medium",
      tags: ["ssh", "crypto", "configuration"]
    }
  },
  // DNS Zone Transfer
  {
    id: "dns_zone_transfer",
    metadata: {
      title: "DNS Zone Transfer Allowed",
      category: "dns",
      safe_by_default: true,
      references: []
    },
    targeting: {
      service: ["dns"],
      ports: [53],
      products: []
    },
    preconditions: ["target is an authoritative DNS server"],
    detection: {
      type: "dns_query",
      record_type: "AXFR",
      success_indicators: ["SOA", "NS"]
    },
    verification: { type: "dns_recheck", delay_ms: 5e3 },
    output: {
      default_state: "verified",
      severity: "high",
      tags: ["dns", "zone_transfer", "information_disclosure"]
    }
  }
];
function matchPlugins(services, options) {
  const allPlugins = [...BUILTIN_PLUGINS, ...options?.customPlugins ?? []];
  const results = [];
  for (const plugin of allPlugins) {
    if (options?.safeOnly && !plugin.metadata.safe_by_default) continue;
    if (options?.categories && !options.categories.includes(plugin.metadata.category)) continue;
    for (const svc of services) {
      const reasons = [];
      if (plugin.targeting.ports.length > 0 && plugin.targeting.ports.includes(svc.port)) {
        reasons.push(`port ${svc.port}`);
      }
      if (plugin.targeting.service.length > 0 && svc.service_name) {
        const svcLower = svc.service_name.toLowerCase();
        if (plugin.targeting.service.some((s) => svcLower.includes(s.toLowerCase()))) {
          reasons.push(`service ${svc.service_name}`);
        }
      }
      if (plugin.targeting.products.length > 0 && svc.product) {
        const prodLower = svc.product.toLowerCase();
        if (plugin.targeting.products.some((p) => prodLower.includes(p.toLowerCase()))) {
          reasons.push(`product ${svc.product}`);
        }
      }
      if (reasons.length > 0) {
        results.push({
          plugin,
          matchedService: svc,
          matchReason: reasons.join(", ")
        });
      }
    }
  }
  return results;
}
function getPluginSummary(customPlugins) {
  const allPlugins = [...BUILTIN_PLUGINS, ...customPlugins ?? []];
  const summary = {};
  for (const p of allPlugins) {
    if (!summary[p.metadata.category]) {
      summary[p.metadata.category] = { count: 0, ids: [] };
    }
    summary[p.metadata.category].count++;
    summary[p.metadata.category].ids.push(p.id);
  }
  return summary;
}
function buildPluginExecutionPlan(services, options) {
  const matches = matchPlugins(services, options);
  const categoryPriority = {
    tls: 1,
    web_server: 2,
    authentication: 3,
    cloud_storage: 4,
    dns: 5,
    network: 6,
    database: 7,
    api: 8,
    container: 9,
    configuration: 10,
    disclosure: 11,
    iot: 12,
    ics: 13
  };
  matches.sort((a, b) => {
    if (a.plugin.metadata.safe_by_default !== b.plugin.metadata.safe_by_default) {
      return a.plugin.metadata.safe_by_default ? -1 : 1;
    }
    const aPrio = categoryPriority[a.plugin.metadata.category] ?? 50;
    const bPrio = categoryPriority[b.plugin.metadata.category] ?? 50;
    return aPrio - bPrio;
  });
  if (options?.maxPlugins) {
    return matches.slice(0, options.maxPlugins);
  }
  return matches;
}
function pluginToLlmContext(plugin) {
  const lines = [
    `Plugin: ${plugin.id}`,
    `Title: ${plugin.metadata.title}`,
    `Category: ${plugin.metadata.category}`,
    `Safe: ${plugin.metadata.safe_by_default}`,
    `Targets: services=${plugin.targeting.service.join(",")}, ports=${plugin.targeting.ports.join(",")}, products=${plugin.targeting.products.join(",")}`,
    `Detection: ${plugin.detection.type}`,
    `Default output: state=${plugin.output.default_state}, severity=${plugin.output.severity}`,
    `Tags: ${plugin.output.tags.join(", ")}`
  ];
  if (plugin.metadata.references.length > 0) {
    lines.push(`References: ${plugin.metadata.references.join(", ")}`);
  }
  return lines.join("\n");
}
export {
  ATTACK_MAPPING_PROMPT,
  ATTACK_MAPPING_SCHEMA,
  BUILTIN_PLUGINS,
  ContextEngine,
  CoverageGapDetector,
  DeduplicationEngine,
  EXECUTIVE_SUMMARY_PROMPT,
  EXECUTIVE_SUMMARY_SCHEMA,
  FALSE_POSITIVE_REVIEWER_PROMPT,
  FALSE_POSITIVE_REVIEWER_SCHEMA,
  FEDRAMP_ALIGNMENT_PROMPT,
  FEDRAMP_ALIGNMENT_SCHEMA,
  FINDING_ENRICHMENT_PROMPT,
  FINDING_ENRICHMENT_SCHEMA,
  FPFNPreventionEngine,
  IntelligenceEngine,
  NormalizationEngine,
  PROMPT_REGISTRY,
  ProtocolRegistry,
  REMEDIATION_PLANNER_PROMPT,
  REMEDIATION_PLANNER_SCHEMA,
  REPORT_WRITER_PROMPT,
  REPORT_WRITER_SCHEMA,
  SCANFORGE_WORKFLOW_STAGES,
  STRICT_PASSIVE_MODE_POLICY,
  ScanOrchestrator,
  ScanQueue,
  TRIAGE_RESPONSE_SCHEMA,
  TRIAGE_SYSTEM_PROMPT,
  TemplateEngine,
  batchScore,
  buildPluginExecutionPlan,
  buildPromptMessages,
  computeAttackPathModifier,
  computeExploitabilityConfidence,
  computeExposureModifier,
  computeHybridScore,
  computeMissionImpact,
  computeTechnicalSeverity,
  getContextEngine,
  getCoverageGapDetector,
  getDeduplicationEngine,
  getFPFNEngine,
  getIntelligenceEngine,
  getNormalizationEngine,
  getPluginSummary,
  getPromptsForStage,
  getProtocolRegistry,
  getResponseFormat,
  getScanQueue,
  getTemplateEngine,
  initializeScanForge,
  matchPlugins,
  pluginToLlmContext,
  quickSeverityFromCvss,
  router as scanforgeRouter
};
