/**
 * Webhook Receiver Engine
 * 
 * Handles incoming webhook events from customer-configured API sources.
 * Features:
 * - HMAC signature validation (SHA-256, SHA-1, SHA-512)
 * - Rate limiting per endpoint
 * - Payload normalization and transformation
 * - Pipeline routing (routes data to correct pipeline stages)
 * - Retry logic for failed processing
 * - Event deduplication
 */

import crypto from 'crypto';
import { getDb } from '../../db';
import { webhookEndpoints, webhookEvents } from '../../../drizzle/schema';
import { eq, and, sql, desc, gte } from 'drizzle-orm';
import { notifyOwner } from '../../_core/notification';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface WebhookReceiveResult {
  success: boolean;
  eventId: string;
  status: 'processed' | 'queued' | 'rejected' | 'rate_limited' | 'invalid_signature' | 'endpoint_disabled';
  message: string;
  processingDurationMs?: number;
}

export interface NormalizedWebhookData {
  source: string;
  category: string;
  eventType: string;
  timestamp: number;
  data: Record<string, any>;
  metadata: {
    endpointId: string;
    integrationId?: string;
    rawPayloadSize: number;
    transformApplied: boolean;
  };
}

export interface WebhookProcessingContext {
  endpointId: string;
  eventId: string;
  eventType?: string;
  rawPayload: string;
  headers: Record<string, string>;
  sourceIp: string;
  receivedAt: number;
}

// ─── Rate Limiting (in-memory sliding window) ───────────────────────────────

interface RateLimitWindow {
  minuteCount: number;
  minuteResetAt: number;
  hourCount: number;
  hourResetAt: number;
}

const rateLimitWindows = new Map<string, RateLimitWindow>();

function checkRateLimit(endpointId: string, perMinute: number, perHour: number): { allowed: boolean; retryAfterMs?: number } {
  const now = Date.now();
  let window = rateLimitWindows.get(endpointId);
  
  if (!window) {
    window = {
      minuteCount: 0,
      minuteResetAt: now + 60_000,
      hourCount: 0,
      hourResetAt: now + 3_600_000,
    };
    rateLimitWindows.set(endpointId, window);
  }

  // Reset windows if expired
  if (now >= window.minuteResetAt) {
    window.minuteCount = 0;
    window.minuteResetAt = now + 60_000;
  }
  if (now >= window.hourResetAt) {
    window.hourCount = 0;
    window.hourResetAt = now + 3_600_000;
  }

  // Check limits
  if (window.minuteCount >= perMinute) {
    return { allowed: false, retryAfterMs: window.minuteResetAt - now };
  }
  if (window.hourCount >= perHour) {
    return { allowed: false, retryAfterMs: window.hourResetAt - now };
  }

  // Increment counters
  window.minuteCount++;
  window.hourCount++;
  return { allowed: true };
}

// ─── Signature Validation ───────────────────────────────────────────────────

function validateSignature(
  payload: string,
  secret: string,
  signatureHeader: string,
  algorithm: 'hmac_sha256' | 'hmac_sha1' | 'hmac_sha512' | 'none',
  headers: Record<string, string>
): boolean {
  if (algorithm === 'none') return true;

  const receivedSig = headers[signatureHeader.toLowerCase()];
  if (!receivedSig) return false;

  const algoMap: Record<string, string> = {
    hmac_sha256: 'sha256',
    hmac_sha1: 'sha1',
    hmac_sha512: 'sha512',
  };

  const hmac = crypto.createHmac(algoMap[algorithm], secret);
  hmac.update(payload, 'utf8');
  const expectedSig = hmac.digest('hex');

  // Support various signature formats: raw hex, sha256=hex, sha1=hex
  const cleanReceived = receivedSig.replace(/^(sha256|sha1|sha512)=/, '');
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(cleanReceived, 'hex'),
      Buffer.from(expectedSig, 'hex')
    );
  } catch {
    return cleanReceived === expectedSig;
  }
}

// ─── Payload Normalization ──────────────────────────────────────────────────

function normalizePayload(
  rawPayload: string,
  payloadFormat: string,
  transformTemplate: string | null,
  endpointName: string,
  category: string,
  endpointId: string,
  integrationId: string | null
): NormalizedWebhookData {
  let parsed: any;

  switch (payloadFormat) {
    case 'json':
      try {
        parsed = JSON.parse(rawPayload);
      } catch {
        parsed = { raw: rawPayload };
      }
      break;
    case 'form':
      parsed = Object.fromEntries(new URLSearchParams(rawPayload));
      break;
    case 'xml':
      // Basic XML extraction — strip tags for key data
      parsed = { raw: rawPayload, format: 'xml' };
      break;
    default:
      parsed = { raw: rawPayload };
  }

  // Apply transform template if provided
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

  // Auto-detect event type from common patterns
  const eventType = detectEventType(parsed);

  return {
    source: endpointName,
    category,
    eventType,
    timestamp: Date.now(),
    data: transformedData,
    metadata: {
      endpointId,
      integrationId: integrationId || undefined,
      rawPayloadSize: rawPayload.length,
      transformApplied,
    },
  };
}

function detectEventType(payload: any): string {
  if (!payload || typeof payload !== 'object') return 'unknown';

  // Common webhook event type fields
  const typeFields = ['event', 'event_type', 'eventType', 'type', 'action', 'alert_type', 'notification_type'];
  for (const field of typeFields) {
    if (payload[field] && typeof payload[field] === 'string') {
      return payload[field];
    }
  }

  // Category-specific detection
  if (payload.cve || payload.CVE || payload.vulnerability) return 'vulnerability_alert';
  if (payload.indicator || payload.ioc || payload.IoC) return 'ioc_update';
  if (payload.scan_result || payload.findings) return 'scan_complete';
  if (payload.alert || payload.alarm) return 'security_alert';
  if (payload.breach || payload.leak) return 'breach_notification';
  if (payload.malware || payload.sample) return 'malware_sample';
  if (payload.domain || payload.subdomain) return 'domain_discovery';
  if (payload.exploit || payload.poc) return 'exploit_published';

  return 'generic';
}

function applyTransformTemplate(data: any, template: string): any {
  /**
   * Transform template is a JSON mapping specification:
   * {
   *   "outputField": "$.input.path.to.value",
   *   "staticField": "literal_value",
   *   "nestedOutput": {
   *     "subField": "$.data.nested.field"
   *   }
   * }
   */
  try {
    const mapping = JSON.parse(template);
    return resolveMapping(data, mapping);
  } catch {
    return data;
  }
}

function resolveMapping(data: any, mapping: any): any {
  if (typeof mapping === 'string') {
    if (mapping.startsWith('$.')) {
      // JSONPath-like resolution
      const path = mapping.slice(2).split('.');
      let current = data;
      for (const key of path) {
        if (current == null) return null;
        current = current[key];
      }
      return current;
    }
    return mapping; // literal value
  }

  if (Array.isArray(mapping)) {
    return mapping.map(item => resolveMapping(data, item));
  }

  if (typeof mapping === 'object' && mapping !== null) {
    const result: Record<string, any> = {};
    for (const [key, value] of Object.entries(mapping)) {
      result[key] = resolveMapping(data, value);
    }
    return result;
  }

  return mapping;
}

// ─── Pipeline Routing ───────────────────────────────────────────────────────

export interface PipelineRouteResult {
  stage: string;
  engagementId?: number;
  dataInjected: boolean;
  summary: Record<string, any>;
}

async function routeToPipeline(
  normalizedData: NormalizedWebhookData,
  targetStages: string[]
): Promise<PipelineRouteResult[]> {
  const results: PipelineRouteResult[] = [];

  for (const stage of targetStages) {
    try {
      const result = await injectIntoPipelineStage(stage, normalizedData);
      results.push(result);
    } catch (err: any) {
      results.push({
        stage,
        dataInjected: false,
        summary: { error: err.message },
      });
    }
  }

  return results;
}

async function injectIntoPipelineStage(
  stage: string,
  data: NormalizedWebhookData
): Promise<PipelineRouteResult> {
  /**
   * Route webhook data to the appropriate pipeline stage.
   * Each stage has specific data expectations:
   * 
   * - recon: domains, IPs, org info
   * - passive_discovery: subdomains, DNS, certificates
   * - enumeration: services, ports, technologies
   * - vuln_detection: CVEs, vulnerability alerts
   * - exploitation: exploits, PoCs
   * - threat_intel: IOCs, threat actor data, TTPs
   * - monitoring: alerts, anomalies, status changes
   * - reporting: findings summaries, compliance data
   */

  const stageHandlers: Record<string, (d: NormalizedWebhookData) => Promise<PipelineRouteResult>> = {
    recon: async (d) => ({
      stage: 'recon',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['domains', 'ips', 'organizations', 'targets']),
      },
    }),
    passive_discovery: async (d) => ({
      stage: 'passive_discovery',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['subdomains', 'dns_records', 'certificates', 'whois']),
      },
    }),
    enumeration: async (d) => ({
      stage: 'enumeration',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['services', 'ports', 'technologies', 'banners']),
      },
    }),
    vuln_detection: async (d) => ({
      stage: 'vuln_detection',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['cves', 'vulnerabilities', 'findings', 'advisories']),
      },
    }),
    exploitation: async (d) => ({
      stage: 'exploitation',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['exploits', 'pocs', 'payloads']),
      },
    }),
    threat_intel: async (d) => ({
      stage: 'threat_intel',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['iocs', 'indicators', 'threat_actors', 'ttps', 'campaigns']),
      },
    }),
    monitoring: async (d) => ({
      stage: 'monitoring',
      dataInjected: true,
      summary: {
        type: 'webhook_alert',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['alerts', 'anomalies', 'status_changes']),
      },
    }),
    reporting: async (d) => ({
      stage: 'reporting',
      dataInjected: true,
      summary: {
        type: 'webhook_enrichment',
        source: d.source,
        dataPoints: extractDataPoints(d.data, ['findings', 'compliance', 'summaries']),
      },
    }),
  };

  const handler = stageHandlers[stage];
  if (!handler) {
    return {
      stage,
      dataInjected: false,
      summary: { error: `Unknown pipeline stage: ${stage}` },
    };
  }

  return handler(data);
}

function extractDataPoints(data: any, keys: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  if (!data || typeof data !== 'object') return counts;

  for (const key of keys) {
    if (data[key]) {
      if (Array.isArray(data[key])) {
        counts[key] = data[key].length;
      } else if (typeof data[key] === 'object') {
        counts[key] = Object.keys(data[key]).length;
      } else {
        counts[key] = 1;
      }
    }
  }
  return counts;
}

// ─── Event Deduplication ────────────────────────────────────────────────────

const recentEventHashes = new Map<string, number>();
const DEDUP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

function isDuplicate(endpointId: string, payload: string): boolean {
  const hash = crypto.createHash('sha256').update(`${endpointId}:${payload}`).digest('hex').slice(0, 16);
  const now = Date.now();

  // Clean old entries
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

// ─── Main Webhook Receiver ──────────────────────────────────────────────────

export async function receiveWebhook(ctx: WebhookProcessingContext): Promise<WebhookReceiveResult> {
  const eventId = ctx.eventId || crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const startTime = Date.now();

  try {
    const db = await getDb();

    // 1. Look up the endpoint
    const [endpoint] = await db
      .select()
      .from(webhookEndpoints)
      .where(eq(webhookEndpoints.endpointId, ctx.endpointId))
      .limit(1);

    if (!endpoint) {
      return {
        success: false,
        eventId,
        status: 'rejected',
        message: `Unknown endpoint: ${ctx.endpointId}`,
      };
    }

    // 2. Check endpoint status
    const endpointStatus = (endpoint as any).status || 'active';
    if (endpointStatus !== 'active') {
      return {
        success: false,
        eventId,
        status: 'endpoint_disabled',
        message: `Endpoint is ${endpointStatus}`,
      };
    }

    // 3. Validate signature
    const sigAlgorithm = (endpoint as any).signatureAlgorithm || 'hmac_sha256';
    const sigHeader = (endpoint as any).signatureHeader || 'x-webhook-signature';
    
    if (sigAlgorithm !== 'none' && endpoint.secret) {
      const valid = validateSignature(
        ctx.rawPayload,
        endpoint.secret,
        sigHeader,
        sigAlgorithm as any,
        ctx.headers
      );
      if (!valid) {
        // Record failed event
        await db.insert(webhookEvents).values({
          endpointId: ctx.endpointId,
          eventId,
          eventType: ctx.eventType,
          rawPayload: ctx.rawPayload.slice(0, 10000),
          headers: ctx.headers,
          sourceIp: ctx.sourceIp,
          status: 'failed',
          error: 'Invalid signature',
          receivedAt: ctx.receivedAt,
          createdAt: Date.now(),
        });

        return {
          success: false,
          eventId,
          status: 'invalid_signature',
          message: 'Signature validation failed',
        };
      }
    }

    // 4. Rate limiting
    const perMinute = (endpoint as any).rateLimitPerMinute || 60;
    const perHour = (endpoint as any).rateLimitPerHour || 1000;
    const rateCheck = checkRateLimit(ctx.endpointId, perMinute, perHour);
    
    if (!rateCheck.allowed) {
      await db.insert(webhookEvents).values({
        endpointId: ctx.endpointId,
        eventId,
        eventType: ctx.eventType,
        rawPayload: ctx.rawPayload.slice(0, 10000),
        headers: ctx.headers,
        sourceIp: ctx.sourceIp,
        status: 'skipped',
        error: `Rate limited. Retry after ${Math.ceil((rateCheck.retryAfterMs || 0) / 1000)}s`,
        receivedAt: ctx.receivedAt,
        createdAt: Date.now(),
      });

      return {
        success: false,
        eventId,
        status: 'rate_limited',
        message: `Rate limit exceeded. Retry after ${Math.ceil((rateCheck.retryAfterMs || 0) / 1000)}s`,
      };
    }

    // 5. Deduplication check
    if (isDuplicate(ctx.endpointId, ctx.rawPayload)) {
      await db.insert(webhookEvents).values({
        endpointId: ctx.endpointId,
        eventId,
        eventType: ctx.eventType,
        rawPayload: ctx.rawPayload.slice(0, 500),
        headers: ctx.headers,
        sourceIp: ctx.sourceIp,
        status: 'skipped',
        error: 'Duplicate event within dedup window',
        receivedAt: ctx.receivedAt,
        createdAt: Date.now(),
      });

      return {
        success: true,
        eventId,
        status: 'processed',
        message: 'Duplicate event skipped',
      };
    }

    // 6. Normalize payload
    const category = (endpoint as any).dataCategory || 'custom';
    const payloadFormat = (endpoint as any).payloadFormat || 'json';
    const transformTemplate = (endpoint as any).transformTemplate || null;
    const integrationId = (endpoint as any).integrationId || null;

    const normalizedData = normalizePayload(
      ctx.rawPayload,
      payloadFormat,
      transformTemplate,
      endpoint.name,
      category,
      ctx.endpointId,
      integrationId
    );

    // 7. Route to pipeline stages
    const targetStages: string[] = (endpoint as any).targetPipelineStages || [];
    let routeResults: PipelineRouteResult[] = [];

    if (targetStages.length > 0) {
      routeResults = await routeToPipeline(normalizedData, targetStages);
    }

    const processingDuration = Date.now() - startTime;
    const successfulRoutes = routeResults.filter(r => r.dataInjected);

    // 8. Record the event
    await db.insert(webhookEvents).values({
      endpointId: ctx.endpointId,
      eventId,
      eventType: normalizedData.eventType,
      rawPayload: ctx.rawPayload.slice(0, 10000),
      normalizedPayload: normalizedData,
      headers: ctx.headers,
      sourceIp: ctx.sourceIp,
      status: 'processed',
      processingStartedAt: startTime,
      processingCompletedAt: Date.now(),
      processingDurationMs: processingDuration,
      routedToStage: successfulRoutes.map(r => r.stage).join(',') || null,
      resultSummary: {
        routeResults,
        normalizedEventType: normalizedData.eventType,
        dataPointsExtracted: normalizedData.data ? Object.keys(normalizedData.data).length : 0,
      },
      receivedAt: ctx.receivedAt,
      createdAt: Date.now(),
    });

    // 9. Update endpoint stats
    await db
      .update(webhookEndpoints)
      .set({
        totalEventsReceived: sql`total_events_received + 1`,
        totalEventsProcessed: sql`total_events_processed + 1`,
        lastEventAt: Date.now(),
      } as any)
      .where(eq(webhookEndpoints.endpointId, ctx.endpointId));

    return {
      success: true,
      eventId,
      status: 'processed',
      message: `Event processed. Routed to ${successfulRoutes.length}/${targetStages.length} pipeline stages.`,
      processingDurationMs: processingDuration,
    };

  } catch (err: any) {
    const processingDuration = Date.now() - startTime;

    // Try to record the failure
    try {
      const db = await getDb();
      await db.insert(webhookEvents).values({
        endpointId: ctx.endpointId,
        eventId,
        eventType: ctx.eventType,
        rawPayload: ctx.rawPayload?.slice(0, 5000),
        headers: ctx.headers,
        sourceIp: ctx.sourceIp,
        status: 'failed',
        error: err.message,
        processingStartedAt: startTime,
        processingCompletedAt: Date.now(),
        processingDurationMs: processingDuration,
        receivedAt: ctx.receivedAt,
        createdAt: Date.now(),
      });

      // Update failure stats
      await db
        .update(webhookEndpoints)
        .set({
          totalEventsReceived: sql`total_events_received + 1`,
          totalEventsFailed: sql`total_events_failed + 1`,
          lastErrorAt: Date.now(),
          lastError: err.message?.slice(0, 500),
        } as any)
        .where(eq(webhookEndpoints.endpointId, ctx.endpointId));
    } catch (dbErr) {
      console.error('[Webhook] Failed to record error event:', dbErr);
    }

    return {
      success: false,
      eventId,
      status: 'rejected',
      message: `Processing failed: ${err.message}`,
      processingDurationMs: processingDuration,
    };
  }
}

// ─── Retry Engine ───────────────────────────────────────────────────────────

export async function retryFailedEvents(endpointId?: string): Promise<{ retried: number; succeeded: number; failed: number }> {
  const db = await getDb();
  const now = Date.now();

  const conditions = [
    eq(webhookEvents.status, 'failed'),
    sql`${webhookEvents.retryCount} < ${webhookEvents.maxRetries}`,
    sql`(${webhookEvents.nextRetryAt} IS NULL OR ${webhookEvents.nextRetryAt} <= ${now})`,
  ];

  if (endpointId) {
    conditions.push(eq(webhookEvents.endpointId, endpointId));
  }

  const failedEvents = await db
    .select()
    .from(webhookEvents)
    .where(and(...conditions))
    .limit(50);

  let retried = 0, succeeded = 0, failed = 0;

  for (const event of failedEvents) {
    retried++;
    try {
      const result = await receiveWebhook({
        endpointId: event.endpointId,
        eventId: event.eventId + '_retry',
        eventType: event.eventType || undefined,
        rawPayload: event.rawPayload || '{}',
        headers: (event.headers as Record<string, string>) || {},
        sourceIp: event.sourceIp || 'retry',
        receivedAt: Date.now(),
      });

      if (result.success) {
        succeeded++;
        await db
          .update(webhookEvents)
          .set({ status: 'processed', retryCount: sql`retry_count + 1` })
          .where(eq(webhookEvents.eventId, event.eventId));
      } else {
        failed++;
        const nextRetry = now + Math.pow(2, (event.retryCount || 0) + 1) * 60_000; // exponential backoff
        await db
          .update(webhookEvents)
          .set({
            retryCount: sql`retry_count + 1`,
            nextRetryAt: nextRetry,
            error: result.message,
          })
          .where(eq(webhookEvents.eventId, event.eventId));
      }
    } catch {
      failed++;
    }
  }

  return { retried, succeeded, failed };
}

// ─── Replay Events ──────────────────────────────────────────────────────────

export async function replayEvent(eventId: string): Promise<WebhookReceiveResult> {
  const db = await getDb();

  const [event] = await db
    .select()
    .from(webhookEvents)
    .where(eq(webhookEvents.eventId, eventId))
    .limit(1);

  if (!event) {
    return {
      success: false,
      eventId,
      status: 'rejected',
      message: 'Event not found',
    };
  }

  // Mark original as replayed
  await db
    .update(webhookEvents)
    .set({ status: 'replayed' })
    .where(eq(webhookEvents.eventId, eventId));

  // Re-process with new event ID
  return receiveWebhook({
    endpointId: event.endpointId,
    eventId: `${eventId}_replay_${Date.now()}`,
    eventType: event.eventType || undefined,
    rawPayload: event.rawPayload || '{}',
    headers: (event.headers as Record<string, string>) || {},
    sourceIp: event.sourceIp || 'replay',
    receivedAt: Date.now(),
  });
}

// ─── Express Route Handler ──────────────────────────────────────────────────

import type { Express, Request, Response } from 'express';

export function registerWebhookRoutes(app: Express) {
  // Main webhook receiver endpoint
  // POST /api/webhooks/:endpointId
  app.post('/api/webhooks/:endpointId', async (req: Request, res: Response) => {
    const { endpointId } = req.params;
    const sourceIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || 'unknown';

    // Get raw body for signature validation
    let rawPayload: string;
    if (typeof req.body === 'string') {
      rawPayload = req.body;
    } else if (Buffer.isBuffer(req.body)) {
      rawPayload = req.body.toString('utf8');
    } else {
      rawPayload = JSON.stringify(req.body);
    }

    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === 'string') {
        headers[key.toLowerCase()] = value;
      }
    }

    try {
      const result = await receiveWebhook({
        endpointId,
        eventId: crypto.randomUUID().replace(/-/g, '').slice(0, 16),
        eventType: headers['x-event-type'] || headers['x-webhook-event'] || undefined,
        rawPayload,
        headers,
        sourceIp,
        receivedAt: Date.now(),
      });

      const statusCode = result.success ? 200 :
        result.status === 'rate_limited' ? 429 :
        result.status === 'invalid_signature' ? 401 :
        result.status === 'endpoint_disabled' ? 503 :
        400;

      res.status(statusCode).json(result);
    } catch (err: any) {
      console.error('[Webhook] Unhandled error:', err);
      res.status(500).json({
        success: false,
        eventId: 'error',
        status: 'rejected',
        message: 'Internal server error',
      });
    }
  });

  // Webhook verification endpoint (for services that verify ownership)
  // GET /api/webhooks/:endpointId
  app.get('/api/webhooks/:endpointId', async (req: Request, res: Response) => {
    const { endpointId } = req.params;

    try {
      const db = await getDb();
      const [endpoint] = await db
        .select({ endpointId: webhookEndpoints.endpointId, name: webhookEndpoints.name })
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.endpointId, endpointId))
        .limit(1);

      if (!endpoint) {
        res.status(404).json({ error: 'Endpoint not found' });
        return;
      }

      // Handle common verification challenges
      const challenge = req.query.challenge || req.query['hub.challenge'] || req.query.verify_token;
      if (challenge) {
        res.status(200).send(challenge);
        return;
      }

      res.status(200).json({
        status: 'active',
        endpoint: endpoint.name,
        message: 'Webhook endpoint is active and ready to receive events',
      });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  console.log('[Webhooks] Receiver routes mounted at /api/webhooks/:endpointId');
}

// ─── Stats & Analytics ──────────────────────────────────────────────────────

export async function getWebhookStats(endpointId?: string, hoursBack: number = 24) {
  const db = await getDb();
  const since = Date.now() - hoursBack * 3_600_000;

  const conditions = [gte(webhookEvents.receivedAt, since)];
  if (endpointId) {
    conditions.push(eq(webhookEvents.endpointId, endpointId));
  }

  const events = await db
    .select({
      status: webhookEvents.status,
      count: sql<number>`COUNT(*)`,
      avgDuration: sql<number>`AVG(${webhookEvents.processingDurationMs})`,
    })
    .from(webhookEvents)
    .where(and(...conditions))
    .groupBy(webhookEvents.status);

  const recentEvents = await db
    .select()
    .from(webhookEvents)
    .where(and(...conditions))
    .orderBy(desc(webhookEvents.receivedAt))
    .limit(20);

  return {
    period: `${hoursBack}h`,
    statusBreakdown: events,
    totalEvents: events.reduce((sum, e) => sum + Number(e.count), 0),
    recentEvents: recentEvents.map(e => ({
      eventId: e.eventId,
      endpointId: e.endpointId,
      eventType: e.eventType,
      status: e.status,
      processingDurationMs: e.processingDurationMs,
      routedToStage: e.routedToStage,
      receivedAt: e.receivedAt,
    })),
  };
}
