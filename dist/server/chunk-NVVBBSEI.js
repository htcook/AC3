import {
  getDb,
  init_db
} from "./chunk-YEW6KKPA.js";
import {
  init_schema,
  webhookEndpoints,
  webhookEvents
} from "./chunk-EMIPCWBF.js";

// server/lib/integration-registry/webhook-receiver.ts
init_db();
init_schema();
import crypto from "crypto";
import { eq, and, sql, desc, gte } from "drizzle-orm";
var rateLimitWindows = /* @__PURE__ */ new Map();
function checkRateLimit(endpointId, perMinute, perHour) {
  const now = Date.now();
  let window = rateLimitWindows.get(endpointId);
  if (!window) {
    window = {
      minuteCount: 0,
      minuteResetAt: now + 6e4,
      hourCount: 0,
      hourResetAt: now + 36e5
    };
    rateLimitWindows.set(endpointId, window);
  }
  if (now >= window.minuteResetAt) {
    window.minuteCount = 0;
    window.minuteResetAt = now + 6e4;
  }
  if (now >= window.hourResetAt) {
    window.hourCount = 0;
    window.hourResetAt = now + 36e5;
  }
  if (window.minuteCount >= perMinute) {
    return { allowed: false, retryAfterMs: window.minuteResetAt - now };
  }
  if (window.hourCount >= perHour) {
    return { allowed: false, retryAfterMs: window.hourResetAt - now };
  }
  window.minuteCount++;
  window.hourCount++;
  return { allowed: true };
}
function validateSignature(payload, secret, signatureHeader, algorithm, headers) {
  if (algorithm === "none") return true;
  const receivedSig = headers[signatureHeader.toLowerCase()];
  if (!receivedSig) return false;
  const algoMap = {
    hmac_sha256: "sha256",
    hmac_sha1: "sha1",
    hmac_sha512: "sha512"
  };
  const hmac = crypto.createHmac(algoMap[algorithm], secret);
  hmac.update(payload, "utf8");
  const expectedSig = hmac.digest("hex");
  const cleanReceived = receivedSig.replace(/^(sha256|sha1|sha512)=/, "");
  try {
    return crypto.timingSafeEqual(
      Buffer.from(cleanReceived, "hex"),
      Buffer.from(expectedSig, "hex")
    );
  } catch {
    return cleanReceived === expectedSig;
  }
}
function normalizePayload(rawPayload, payloadFormat, transformTemplate, endpointName, category, endpointId, integrationId) {
  let parsed;
  switch (payloadFormat) {
    case "json":
      try {
        parsed = JSON.parse(rawPayload);
      } catch {
        parsed = { raw: rawPayload };
      }
      break;
    case "form":
      parsed = Object.fromEntries(new URLSearchParams(rawPayload));
      break;
    case "xml":
      parsed = { raw: rawPayload, format: "xml" };
      break;
    default:
      parsed = { raw: rawPayload };
  }
  let transformedData = parsed;
  let transformApplied = false;
  if (transformTemplate) {
    try {
      transformedData = applyTransformTemplate(parsed, transformTemplate);
      transformApplied = true;
    } catch (err) {
      console.warn(`[Webhook] Transform failed for ${endpointId}:`, err);
      transformedData = parsed;
    }
  }
  const eventType = detectEventType(parsed);
  return {
    source: endpointName,
    category,
    eventType,
    timestamp: Date.now(),
    data: transformedData,
    metadata: {
      endpointId,
      integrationId: integrationId || void 0,
      rawPayloadSize: rawPayload.length,
      transformApplied
    }
  };
}
function detectEventType(payload) {
  if (!payload || typeof payload !== "object") return "unknown";
  const typeFields = ["event", "event_type", "eventType", "type", "action", "alert_type", "notification_type"];
  for (const field of typeFields) {
    if (payload[field] && typeof payload[field] === "string") {
      return payload[field];
    }
  }
  if (payload.cve || payload.CVE || payload.vulnerability) return "vulnerability_alert";
  if (payload.indicator || payload.ioc || payload.IoC) return "ioc_update";
  if (payload.scan_result || payload.findings) return "scan_complete";
  if (payload.alert || payload.alarm) return "security_alert";
  if (payload.breach || payload.leak) return "breach_notification";
  if (payload.malware || payload.sample) return "malware_sample";
  if (payload.domain || payload.subdomain) return "domain_discovery";
  if (payload.exploit || payload.poc) return "exploit_published";
  return "generic";
}
function applyTransformTemplate(data, template) {
  try {
    const mapping = JSON.parse(template);
    return resolveMapping(data, mapping);
  } catch {
    return data;
  }
}
function resolveMapping(data, mapping) {
  if (typeof mapping === "string") {
    if (mapping.startsWith("$.")) {
      const path = mapping.slice(2).split(".");
      let current = data;
      for (const key of path) {
        if (current == null) return null;
        current = current[key];
      }
      return current;
    }
    return mapping;
  }
  if (Array.isArray(mapping)) {
    return mapping.map((item) => resolveMapping(data, item));
  }
  if (typeof mapping === "object" && mapping !== null) {
    const result = {};
    for (const [key, value] of Object.entries(mapping)) {
      result[key] = resolveMapping(data, value);
    }
    return result;
  }
  return mapping;
}
async function routeToPipeline(normalizedData, targetStages) {
  const results = [];
  for (const stage of targetStages) {
    try {
      const result = await injectIntoPipelineStage(stage, normalizedData);
      results.push(result);
    } catch (err) {
      results.push({
        stage,
        dataInjected: false,
        summary: { error: err.message }
      });
    }
  }
  return results;
}
async function injectIntoPipelineStage(stage, data) {
  const stageHandlers = {
    recon: async (d) => ({
      stage: "recon",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["domains", "ips", "organizations", "targets"])
      }
    }),
    passive_discovery: async (d) => ({
      stage: "passive_discovery",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["subdomains", "dns_records", "certificates", "whois"])
      }
    }),
    enumeration: async (d) => ({
      stage: "enumeration",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["services", "ports", "technologies", "banners"])
      }
    }),
    vuln_detection: async (d) => ({
      stage: "vuln_detection",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["cves", "vulnerabilities", "findings", "advisories"])
      }
    }),
    exploitation: async (d) => ({
      stage: "exploitation",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["exploits", "pocs", "payloads"])
      }
    }),
    threat_intel: async (d) => ({
      stage: "threat_intel",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["iocs", "indicators", "threat_actors", "ttps", "campaigns"])
      }
    }),
    monitoring: async (d) => ({
      stage: "monitoring",
      dataInjected: true,
      summary: {
        type: "webhook_alert",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["alerts", "anomalies", "status_changes"])
      }
    }),
    reporting: async (d) => ({
      stage: "reporting",
      dataInjected: true,
      summary: {
        type: "webhook_enrichment",
        source: d.source,
        dataPoints: extractDataPoints(d.data, ["findings", "compliance", "summaries"])
      }
    })
  };
  const handler = stageHandlers[stage];
  if (!handler) {
    return {
      stage,
      dataInjected: false,
      summary: { error: `Unknown pipeline stage: ${stage}` }
    };
  }
  return handler(data);
}
function extractDataPoints(data, keys) {
  const counts = {};
  if (!data || typeof data !== "object") return counts;
  for (const key of keys) {
    if (data[key]) {
      if (Array.isArray(data[key])) {
        counts[key] = data[key].length;
      } else if (typeof data[key] === "object") {
        counts[key] = Object.keys(data[key]).length;
      } else {
        counts[key] = 1;
      }
    }
  }
  return counts;
}
var recentEventHashes = /* @__PURE__ */ new Map();
var DEDUP_WINDOW_MS = 5 * 60 * 1e3;
function isDuplicate(endpointId, payload) {
  const hash = crypto.createHash("sha256").update(`${endpointId}:${payload}`).digest("hex").slice(0, 16);
  const now = Date.now();
  for (const [key, ts] of recentEventHashes) {
    if (now - ts > DEDUP_WINDOW_MS) {
      recentEventHashes.delete(key);
    }
  }
  if (recentEventHashes.has(hash)) {
    return true;
  }
  recentEventHashes.set(hash, now);
  return false;
}
async function receiveWebhook(ctx) {
  const eventId = ctx.eventId || crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  const startTime = Date.now();
  try {
    const db = await getDb();
    const [endpoint] = await db.select().from(webhookEndpoints).where(eq(webhookEndpoints.endpointId, ctx.endpointId)).limit(1);
    if (!endpoint) {
      return {
        success: false,
        eventId,
        status: "rejected",
        message: `Unknown endpoint: ${ctx.endpointId}`
      };
    }
    const endpointStatus = endpoint.status || "active";
    if (endpointStatus !== "active") {
      return {
        success: false,
        eventId,
        status: "endpoint_disabled",
        message: `Endpoint is ${endpointStatus}`
      };
    }
    const sigAlgorithm = endpoint.signatureAlgorithm || "hmac_sha256";
    const sigHeader = endpoint.signatureHeader || "x-webhook-signature";
    if (sigAlgorithm !== "none" && endpoint.secret) {
      const valid = validateSignature(
        ctx.rawPayload,
        endpoint.secret,
        sigHeader,
        sigAlgorithm,
        ctx.headers
      );
      if (!valid) {
        await db.insert(webhookEvents).values({
          endpointId: ctx.endpointId,
          eventId,
          eventType: ctx.eventType,
          rawPayload: ctx.rawPayload.slice(0, 1e4),
          headers: ctx.headers,
          sourceIp: ctx.sourceIp,
          status: "failed",
          error: "Invalid signature",
          receivedAt: ctx.receivedAt,
          createdAt: Date.now()
        });
        return {
          success: false,
          eventId,
          status: "invalid_signature",
          message: "Signature validation failed"
        };
      }
    }
    const perMinute = endpoint.rateLimitPerMinute || 60;
    const perHour = endpoint.rateLimitPerHour || 1e3;
    const rateCheck = checkRateLimit(ctx.endpointId, perMinute, perHour);
    if (!rateCheck.allowed) {
      await db.insert(webhookEvents).values({
        endpointId: ctx.endpointId,
        eventId,
        eventType: ctx.eventType,
        rawPayload: ctx.rawPayload.slice(0, 1e4),
        headers: ctx.headers,
        sourceIp: ctx.sourceIp,
        status: "skipped",
        error: `Rate limited. Retry after ${Math.ceil((rateCheck.retryAfterMs || 0) / 1e3)}s`,
        receivedAt: ctx.receivedAt,
        createdAt: Date.now()
      });
      return {
        success: false,
        eventId,
        status: "rate_limited",
        message: `Rate limit exceeded. Retry after ${Math.ceil((rateCheck.retryAfterMs || 0) / 1e3)}s`
      };
    }
    if (isDuplicate(ctx.endpointId, ctx.rawPayload)) {
      await db.insert(webhookEvents).values({
        endpointId: ctx.endpointId,
        eventId,
        eventType: ctx.eventType,
        rawPayload: ctx.rawPayload.slice(0, 500),
        headers: ctx.headers,
        sourceIp: ctx.sourceIp,
        status: "skipped",
        error: "Duplicate event within dedup window",
        receivedAt: ctx.receivedAt,
        createdAt: Date.now()
      });
      return {
        success: true,
        eventId,
        status: "processed",
        message: "Duplicate event skipped"
      };
    }
    const category = endpoint.dataCategory || "custom";
    const payloadFormat = endpoint.payloadFormat || "json";
    const transformTemplate = endpoint.transformTemplate || null;
    const integrationId = endpoint.integrationId || null;
    const normalizedData = normalizePayload(
      ctx.rawPayload,
      payloadFormat,
      transformTemplate,
      endpoint.name,
      category,
      ctx.endpointId,
      integrationId
    );
    const targetStages = endpoint.targetPipelineStages || [];
    let routeResults = [];
    if (targetStages.length > 0) {
      routeResults = await routeToPipeline(normalizedData, targetStages);
    }
    const processingDuration = Date.now() - startTime;
    const successfulRoutes = routeResults.filter((r) => r.dataInjected);
    await db.insert(webhookEvents).values({
      endpointId: ctx.endpointId,
      eventId,
      eventType: normalizedData.eventType,
      rawPayload: ctx.rawPayload.slice(0, 1e4),
      normalizedPayload: normalizedData,
      headers: ctx.headers,
      sourceIp: ctx.sourceIp,
      status: "processed",
      processingStartedAt: startTime,
      processingCompletedAt: Date.now(),
      processingDurationMs: processingDuration,
      routedToStage: successfulRoutes.map((r) => r.stage).join(",") || null,
      resultSummary: {
        routeResults,
        normalizedEventType: normalizedData.eventType,
        dataPointsExtracted: normalizedData.data ? Object.keys(normalizedData.data).length : 0
      },
      receivedAt: ctx.receivedAt,
      createdAt: Date.now()
    });
    await db.update(webhookEndpoints).set({
      totalEventsReceived: sql`total_events_received + 1`,
      totalEventsProcessed: sql`total_events_processed + 1`,
      lastEventAt: Date.now()
    }).where(eq(webhookEndpoints.endpointId, ctx.endpointId));
    return {
      success: true,
      eventId,
      status: "processed",
      message: `Event processed. Routed to ${successfulRoutes.length}/${targetStages.length} pipeline stages.`,
      processingDurationMs: processingDuration
    };
  } catch (err) {
    const processingDuration = Date.now() - startTime;
    try {
      const db = await getDb();
      await db.insert(webhookEvents).values({
        endpointId: ctx.endpointId,
        eventId,
        eventType: ctx.eventType,
        rawPayload: ctx.rawPayload?.slice(0, 5e3),
        headers: ctx.headers,
        sourceIp: ctx.sourceIp,
        status: "failed",
        error: err.message,
        processingStartedAt: startTime,
        processingCompletedAt: Date.now(),
        processingDurationMs: processingDuration,
        receivedAt: ctx.receivedAt,
        createdAt: Date.now()
      });
      await db.update(webhookEndpoints).set({
        totalEventsReceived: sql`total_events_received + 1`,
        totalEventsFailed: sql`total_events_failed + 1`,
        lastErrorAt: Date.now(),
        lastError: err.message?.slice(0, 500)
      }).where(eq(webhookEndpoints.endpointId, ctx.endpointId));
    } catch (dbErr) {
      console.error("[Webhook] Failed to record error event:", dbErr);
    }
    return {
      success: false,
      eventId,
      status: "rejected",
      message: `Processing failed: ${err.message}`,
      processingDurationMs: processingDuration
    };
  }
}
async function retryFailedEvents(endpointId) {
  const db = await getDb();
  const now = Date.now();
  const conditions = [
    eq(webhookEvents.status, "failed"),
    sql`${webhookEvents.retryCount} < ${webhookEvents.maxRetries}`,
    sql`(${webhookEvents.nextRetryAt} IS NULL OR ${webhookEvents.nextRetryAt} <= ${now})`
  ];
  if (endpointId) {
    conditions.push(eq(webhookEvents.endpointId, endpointId));
  }
  const failedEvents = await db.select().from(webhookEvents).where(and(...conditions)).limit(50);
  let retried = 0, succeeded = 0, failed = 0;
  for (const event of failedEvents) {
    retried++;
    try {
      const result = await receiveWebhook({
        endpointId: event.endpointId,
        eventId: event.eventId + "_retry",
        eventType: event.eventType || void 0,
        rawPayload: event.rawPayload || "{}",
        headers: event.headers || {},
        sourceIp: event.sourceIp || "retry",
        receivedAt: Date.now()
      });
      if (result.success) {
        succeeded++;
        await db.update(webhookEvents).set({ status: "processed", retryCount: sql`retry_count + 1` }).where(eq(webhookEvents.eventId, event.eventId));
      } else {
        failed++;
        const nextRetry = now + Math.pow(2, (event.retryCount || 0) + 1) * 6e4;
        await db.update(webhookEvents).set({
          retryCount: sql`retry_count + 1`,
          nextRetryAt: nextRetry,
          error: result.message
        }).where(eq(webhookEvents.eventId, event.eventId));
      }
    } catch {
      failed++;
    }
  }
  return { retried, succeeded, failed };
}
async function replayEvent(eventId) {
  const db = await getDb();
  const [event] = await db.select().from(webhookEvents).where(eq(webhookEvents.eventId, eventId)).limit(1);
  if (!event) {
    return {
      success: false,
      eventId,
      status: "rejected",
      message: "Event not found"
    };
  }
  await db.update(webhookEvents).set({ status: "replayed" }).where(eq(webhookEvents.eventId, eventId));
  return receiveWebhook({
    endpointId: event.endpointId,
    eventId: `${eventId}_replay_${Date.now()}`,
    eventType: event.eventType || void 0,
    rawPayload: event.rawPayload || "{}",
    headers: event.headers || {},
    sourceIp: event.sourceIp || "replay",
    receivedAt: Date.now()
  });
}
function registerWebhookRoutes(app) {
  app.post("/api/webhooks/:endpointId", async (req, res) => {
    const { endpointId } = req.params;
    const sourceIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "unknown";
    let rawPayload;
    if (typeof req.body === "string") {
      rawPayload = req.body;
    } else if (Buffer.isBuffer(req.body)) {
      rawPayload = req.body.toString("utf8");
    } else {
      rawPayload = JSON.stringify(req.body);
    }
    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === "string") {
        headers[key.toLowerCase()] = value;
      }
    }
    try {
      const result = await receiveWebhook({
        endpointId,
        eventId: crypto.randomUUID().replace(/-/g, "").slice(0, 16),
        eventType: headers["x-event-type"] || headers["x-webhook-event"] || void 0,
        rawPayload,
        headers,
        sourceIp,
        receivedAt: Date.now()
      });
      const statusCode = result.success ? 200 : result.status === "rate_limited" ? 429 : result.status === "invalid_signature" ? 401 : result.status === "endpoint_disabled" ? 503 : 400;
      res.status(statusCode).json(result);
    } catch (err) {
      console.error("[Webhook] Unhandled error:", err);
      res.status(500).json({
        success: false,
        eventId: "error",
        status: "rejected",
        message: "Internal server error"
      });
    }
  });
  app.get("/api/webhooks/:endpointId", async (req, res) => {
    const { endpointId } = req.params;
    try {
      const db = await getDb();
      const [endpoint] = await db.select({ endpointId: webhookEndpoints.endpointId, name: webhookEndpoints.name }).from(webhookEndpoints).where(eq(webhookEndpoints.endpointId, endpointId)).limit(1);
      if (!endpoint) {
        res.status(404).json({ error: "Endpoint not found" });
        return;
      }
      const challenge = req.query.challenge || req.query["hub.challenge"] || req.query.verify_token;
      if (challenge) {
        res.status(200).send(challenge);
        return;
      }
      res.status(200).json({
        status: "active",
        endpoint: endpoint.name,
        message: "Webhook endpoint is active and ready to receive events"
      });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  });
  console.log("[Webhooks] Receiver routes mounted at /api/webhooks/:endpointId");
}
async function getWebhookStats(endpointId, hoursBack = 24) {
  const db = await getDb();
  const since = Date.now() - hoursBack * 36e5;
  const conditions = [gte(webhookEvents.receivedAt, since)];
  if (endpointId) {
    conditions.push(eq(webhookEvents.endpointId, endpointId));
  }
  const events = await db.select({
    status: webhookEvents.status,
    count: sql`COUNT(*)`,
    avgDuration: sql`AVG(${webhookEvents.processingDurationMs})`
  }).from(webhookEvents).where(and(...conditions)).groupBy(webhookEvents.status);
  const recentEvents = await db.select().from(webhookEvents).where(and(...conditions)).orderBy(desc(webhookEvents.receivedAt)).limit(20);
  return {
    period: `${hoursBack}h`,
    statusBreakdown: events,
    totalEvents: events.reduce((sum, e) => sum + Number(e.count), 0),
    recentEvents: recentEvents.map((e) => ({
      eventId: e.eventId,
      endpointId: e.endpointId,
      eventType: e.eventType,
      status: e.status,
      processingDurationMs: e.processingDurationMs,
      routedToStage: e.routedToStage,
      receivedAt: e.receivedAt
    }))
  };
}

export {
  receiveWebhook,
  retryFailedEvents,
  replayEvent,
  registerWebhookRoutes,
  getWebhookStats
};
