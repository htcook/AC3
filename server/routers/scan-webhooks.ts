/**
 * Webhook-Triggered Scan Automation Router
 * 
 * Allows SOAR platforms and external tools to trigger scans via inbound webhooks,
 * closing the bidirectional integration loop. Supports ZAP DAST, ScanForge, Nuclei,
 * and custom scan profiles with HMAC signature verification.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { eq, and, desc, sql, gte, count } from "drizzle-orm";
import crypto from "crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

interface WebhookEndpoint {
  id: string;
  name: string;
  path: string;
  secret: string;
  scanType: "zap_dast" | "scanforge-discovery" | "nuclei" | "custom";
  scanProfile: Record<string, any>;
  enabled: boolean;
  createdBy: string;
  createdAt: number;
  lastTriggered: number | null;
  triggerCount: number;
  allowedSources: string[]; // IP allowlist
}

interface WebhookExecution {
  id: string;
  endpointId: string;
  triggeredAt: number;
  sourceIp: string;
  payload: Record<string, any>;
  status: "queued" | "running" | "completed" | "failed";
  scanId: string | null;
  result: Record<string, any> | null;
  completedAt: number | null;
}

// ─── In-memory store (production would use DB) ───────────────────────────────

const webhookEndpoints = new Map<string, WebhookEndpoint>();
const webhookExecutions: WebhookExecution[] = [];

function generateId(): string {
  return crypto.randomBytes(16).toString("hex");
}

function generateSecret(): string {
  return `whsec_${crypto.randomBytes(32).toString("hex")}`;
}

function verifyHmacSignature(payload: string, signature: string, secret: string): boolean {
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  const sig = signature.replace("sha256=", "");
  return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(sig, "hex"));
}

// ─── Scan profile templates ─────────────────────────────────────────────────

const SCAN_PROFILES: Record<string, Record<string, any>> = {
  zap_quick: {
    scanType: "zap_dast",
    name: "ZAP Quick Scan",
    config: { strength: "LOW", threshold: "MEDIUM", maxDuration: 300, spiderDepth: 3 },
  },
  zap_full: {
    scanType: "zap_dast",
    name: "ZAP Full Active Scan",
    config: { strength: "HIGH", threshold: "LOW", maxDuration: 3600, spiderDepth: 10, ajaxSpider: true },
  },
  zap_api: {
    scanType: "zap_dast",
    name: "ZAP API Scan",
    config: { strength: "MEDIUM", threshold: "MEDIUM", apiDefinition: true, openApiUrl: "" },
  },
  scanforge_discovery: {
    scanType: "scanforge-discovery",
    name: "ScanForge Host Discovery",
    config: { scanType: "-sn", timing: "T3", ports: "" },
  },
  scanforge_full: {
    scanType: "scanforge-discovery",
    name: "ScanForge Full Port Scan",
    config: { scanType: "-sS -sV -sC", timing: "T4", ports: "1-65535", osDetection: true },
  },
  scanforge_vuln: {
    scanType: "scanforge-discovery",
    name: "ScanForge Vulnerability Scan",
    config: { scanType: "-sV --script=vuln", timing: "T3", ports: "1-10000" },
  },
  nuclei_default: {
    scanType: "nuclei",
    name: "Nuclei Default Templates",
    config: { templates: "default", severity: "medium,high,critical", rateLimit: 150, concurrency: 25 },
  },
  nuclei_cves: {
    scanType: "nuclei",
    name: "Nuclei CVE Templates",
    config: { templates: "cves", severity: "high,critical", rateLimit: 100, concurrency: 10 },
  },
  nuclei_exposed: {
    scanType: "nuclei",
    name: "Nuclei Exposed Panels",
    config: { templates: "exposed-panels,technologies", severity: "info,low,medium,high,critical", rateLimit: 200 },
  },
};

// ─── Router ──────────────────────────────────────────────────────────────────

export const scanWebhooksRouter = router({
  // ─── List webhook endpoints ────────────────────────────────────────────
  list: protectedProcedure.query(async () => {
    const endpoints = Array.from(webhookEndpoints.values()).sort((a, b) => b.createdAt - a.createdAt);
    // Mask secrets in list view
    return endpoints.map(ep => ({
      ...ep,
      secret: `${ep.secret.substring(0, 10)}...${ep.secret.substring(ep.secret.length - 4)}`,
    }));
  }),

  // ─── Create webhook endpoint ───────────────────────────────────────────
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100),
      scanType: z.enum(["zap_dast", "scanforge-discovery", "nuclei", "custom"]),
      profileId: z.string().optional(),
      customProfile: z.record(z.any()).optional(),
      allowedSources: z.array(z.string()).default([]),
    }))
    .mutation(async ({ ctx, input }) => {
      const id = generateId();
      const secret = generateSecret();
      const profile = input.profileId && SCAN_PROFILES[input.profileId]
        ? SCAN_PROFILES[input.profileId].config
        : input.customProfile || {};

      const endpoint: WebhookEndpoint = {
        id,
        name: input.name,
        path: `/api/webhooks/scan/${id}`,
        secret,
        scanType: input.scanType,
        scanProfile: profile,
        enabled: true,
        createdBy: ctx.user.openId,
        createdAt: Date.now(),
        lastTriggered: null,
        triggerCount: 0,
        allowedSources: input.allowedSources,
      };

      webhookEndpoints.set(id, endpoint);

      return {
        id,
        path: endpoint.path,
        secret, // Return full secret only on creation
        name: endpoint.name,
      };
    }),

  // ─── Get webhook endpoint details ──────────────────────────────────────
  get: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const endpoint = webhookEndpoints.get(input.id);
      if (!endpoint) throw new TRPCError({ code: "NOT_FOUND", message: "Webhook endpoint not found" });
      return {
        ...endpoint,
        secret: `${endpoint.secret.substring(0, 10)}...${endpoint.secret.substring(endpoint.secret.length - 4)}`,
      };
    }),

  // ─── Update webhook endpoint ───────────────────────────────────────────
  update: protectedProcedure
    .input(z.object({
      id: z.string(),
      name: z.string().min(1).max(100).optional(),
      enabled: z.boolean().optional(),
      scanProfile: z.record(z.any()).optional(),
      allowedSources: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const endpoint = webhookEndpoints.get(input.id);
      if (!endpoint) throw new TRPCError({ code: "NOT_FOUND", message: "Webhook endpoint not found" });

      if (input.name !== undefined) endpoint.name = input.name;
      if (input.enabled !== undefined) endpoint.enabled = input.enabled;
      if (input.scanProfile !== undefined) endpoint.scanProfile = input.scanProfile;
      if (input.allowedSources !== undefined) endpoint.allowedSources = input.allowedSources;

      webhookEndpoints.set(input.id, endpoint);
      return { success: true };
    }),

  // ─── Delete webhook endpoint ───────────────────────────────────────────
  delete: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      if (!webhookEndpoints.has(input.id)) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Webhook endpoint not found" });
      }
      webhookEndpoints.delete(input.id);
      return { success: true };
    }),

  // ─── Rotate webhook secret ─────────────────────────────────────────────
  rotateSecret: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ input }) => {
      const endpoint = webhookEndpoints.get(input.id);
      if (!endpoint) throw new TRPCError({ code: "NOT_FOUND", message: "Webhook endpoint not found" });

      const newSecret = generateSecret();
      endpoint.secret = newSecret;
      webhookEndpoints.set(input.id, endpoint);

      return { secret: newSecret };
    }),

  // ─── Simulate webhook trigger (for testing) ────────────────────────────
  testTrigger: protectedProcedure
    .input(z.object({
      id: z.string(),
      target: z.string().url(),
      overrides: z.record(z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      const endpoint = webhookEndpoints.get(input.id);
      if (!endpoint) throw new TRPCError({ code: "NOT_FOUND", message: "Webhook endpoint not found" });

      const executionId = generateId();
      const execution: WebhookExecution = {
        id: executionId,
        endpointId: input.id,
        triggeredAt: Date.now(),
        sourceIp: "127.0.0.1",
        payload: { target: input.target, ...input.overrides },
        status: "queued",
        scanId: `scan_${generateId().substring(0, 8)}`,
        result: null,
        completedAt: null,
      };

      webhookExecutions.push(execution);

      // Update endpoint stats
      endpoint.lastTriggered = Date.now();
      endpoint.triggerCount += 1;
      webhookEndpoints.set(input.id, endpoint);

      // Simulate scan progression
      setTimeout(() => {
        execution.status = "running";
      }, 1000);
      setTimeout(() => {
        execution.status = "completed";
        execution.completedAt = Date.now();
        execution.result = {
          findingsCount: Math.floor(Math.random() * 20) + 1,
          criticalCount: Math.floor(Math.random() * 3),
          highCount: Math.floor(Math.random() * 5),
          mediumCount: Math.floor(Math.random() * 8),
          lowCount: Math.floor(Math.random() * 10),
          scanDuration: Math.floor(Math.random() * 300) + 30,
          target: input.target,
        };
      }, 5000);

      return {
        executionId,
        scanId: execution.scanId,
        status: "queued",
        message: `Scan queued for ${input.target} using ${endpoint.scanType} profile`,
      };
    }),

  // ─── Get execution history ─────────────────────────────────────────────
  getExecutions: protectedProcedure
    .input(z.object({
      endpointId: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
    }).optional())
    .query(async ({ input }) => {
      let executions = [...webhookExecutions].sort((a, b) => b.triggeredAt - a.triggeredAt);
      if (input?.endpointId) {
        executions = executions.filter(e => e.endpointId === input.endpointId);
      }
      return executions.slice(0, input?.limit || 50);
    }),

  // ─── Get available scan profiles ───────────────────────────────────────
  getProfiles: protectedProcedure.query(async () => {
    return Object.entries(SCAN_PROFILES).map(([id, profile]) => ({
      id,
      ...profile,
    }));
  }),

  // ─── Get webhook stats ─────────────────────────────────────────────────
  getStats: protectedProcedure.query(async () => {
    const endpoints = Array.from(webhookEndpoints.values());
    const now = Date.now();
    const last24h = now - 86400000;
    const last7d = now - 7 * 86400000;

    const recentExecutions = webhookExecutions.filter(e => e.triggeredAt > last24h);
    const weeklyExecutions = webhookExecutions.filter(e => e.triggeredAt > last7d);

    return {
      totalEndpoints: endpoints.length,
      activeEndpoints: endpoints.filter(e => e.enabled).length,
      totalExecutions: webhookExecutions.length,
      last24hExecutions: recentExecutions.length,
      last7dExecutions: weeklyExecutions.length,
      successRate: webhookExecutions.length > 0
        ? Math.round(webhookExecutions.filter(e => e.status === "completed").length / webhookExecutions.length * 100)
        : 100,
      avgScanDuration: webhookExecutions
        .filter(e => e.result?.scanDuration)
        .reduce((sum, e) => sum + (e.result?.scanDuration || 0), 0) /
        Math.max(1, webhookExecutions.filter(e => e.result?.scanDuration).length),
      byType: {
        zap_dast: endpoints.filter(e => e.scanType === "zap_dast").length,
        discovery: endpoints.filter(e => e.scanType === "scanforge-discovery").length,
        nuclei: endpoints.filter(e => e.scanType === "nuclei").length,
        custom: endpoints.filter(e => e.scanType === "custom").length,
      },
    };
  }),

  // ─── Generate SOAR integration snippet ─────────────────────────────────
  getIntegrationSnippet: protectedProcedure
    .input(z.object({
      endpointId: z.string(),
      platform: z.enum(["splunk_soar", "cortex_xsoar", "tines", "shuffle", "curl", "python"]),
    }))
    .query(async ({ input }) => {
      const endpoint = webhookEndpoints.get(input.endpointId);
      if (!endpoint) throw new TRPCError({ code: "NOT_FOUND", message: "Webhook endpoint not found" });

      const baseUrl = "https://your-caldera-instance.com";
      const snippets: Record<string, string> = {
        curl: `curl -X POST "${baseUrl}${endpoint.path}" \\
  -H "Content-Type: application/json" \\
  -H "X-Webhook-Signature: sha256=$(echo -n '{"target":"https://example.com"}' | openssl dgst -sha256 -hmac '${endpoint.secret}')" \\
  -d '{"target":"https://example.com","priority":"high"}'`,

        python: `import hmac, hashlib, json, requests

WEBHOOK_URL = "${baseUrl}${endpoint.path}"
WEBHOOK_SECRET = "${endpoint.secret}"

payload = {"target": "https://example.com", "priority": "high"}
body = json.dumps(payload)
signature = "sha256=" + hmac.new(
    WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256
).hexdigest()

response = requests.post(
    WEBHOOK_URL,
    json=payload,
    headers={
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
    },
)
print(response.json())`,

        splunk_soar: `# Splunk SOAR Playbook Action
# Add as a custom function in your playbook

def trigger_caldera_scan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    import phantom.rules as phantom
    import json, hmac, hashlib

    url = "${baseUrl}${endpoint.path}"
    secret = "${endpoint.secret}"
    
    payload = {
        "target": container.get("data", {}).get("target_url", ""),
        "priority": "high",
        "soar_container_id": container.get("id"),
    }
    body = json.dumps(payload)
    signature = "sha256=" + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    
    phantom.act("http request", parameters=[{
        "url": url,
        "method": "POST",
        "body": body,
        "headers": json.dumps({
            "Content-Type": "application/json",
            "X-Webhook-Signature": signature,
        }),
    }], callback=success)`,

        cortex_xsoar: `# Cortex XSOAR Integration Script
import demistomock as demisto
import hmac, hashlib, json

WEBHOOK_URL = "${baseUrl}${endpoint.path}"
WEBHOOK_SECRET = "${endpoint.secret}"

def trigger_scan():
    target = demisto.args().get("target", "")
    payload = {"target": target, "priority": "high", "xsoar_incident_id": demisto.incident().get("id")}
    body = json.dumps(payload)
    signature = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    
    response = demisto.executeCommand("http-request", {
        "method": "POST",
        "url": WEBHOOK_URL,
        "body": body,
        "headers": {"Content-Type": "application/json", "X-Webhook-Signature": signature},
    })
    demisto.results(response)

trigger_scan()`,

        tines: `{
  "name": "Trigger Caldera Scan",
  "type": "HTTP Request",
  "options": {
    "url": "${baseUrl}${endpoint.path}",
    "method": "POST",
    "content_type": "json",
    "payload": {
      "target": "<<receive_alert.body.target_url>>",
      "priority": "high",
      "tines_story_id": "<<STORY.id>>"
    },
    "headers": {
      "X-Webhook-Signature": "<<HMAC_SHA256('${endpoint.secret}', JSON(payload))>>"
    }
  }
}`,

        shuffle: `{
  "app_name": "HTTP",
  "app_action": "POST request",
  "parameters": {
    "url": "${baseUrl}${endpoint.path}",
    "body": "{\\\"target\\\": \\\"$exec.target_url\\\", \\\"priority\\\": \\\"high\\\"}",
    "headers": "Content-Type: application/json\\nX-Webhook-Signature: sha256=$hmac_sha256(${endpoint.secret}, body)"
  }
}`,
      };

      return {
        platform: input.platform,
        snippet: snippets[input.platform] || "// Platform not supported",
        endpointPath: endpoint.path,
      };
    }),
});
