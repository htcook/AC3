/**
 * CI/CD Webhook Delivery Manager
 * 
 * Handles webhook delivery with retry logic, exponential backoff,
 * and delivery logging for CI/CD pipeline notifications.
 */

import { sql } from "drizzle-orm";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface WebhookDeliveryPayload {
  pipelineId: number;
  runId?: number;
  eventType: string;
  webhookUrl: string;
  payload: Record<string, any>;
  maxRetries?: number;
}

export interface DeliveryRecord {
  id: number;
  pipelineId: number;
  runId: number | null;
  eventType: string;
  webhookUrl: string | null;
  payloadSummary: string | null;
  responseStatus: number | null;
  responseBody: string | null;
  deliveryStatus: "pending" | "delivered" | "failed" | "retrying";
  attemptCount: number;
  maxRetries: number;
  nextRetryAt: string | null;
  lastAttemptAt: string | null;
  deliveredAt: string | null;
  createdAt: string;
  errorMessage: string | null;
  durationMs: number | null;
}

// ─── Backoff Calculator ──────────────────────────────────────────────────────

/**
 * Calculate exponential backoff delay in milliseconds.
 * Base: 30s, multiplied by 2^attempt, capped at 30 minutes.
 */
export function calculateBackoff(attempt: number): number {
  const baseMs = 30_000; // 30 seconds
  const maxMs = 30 * 60_000; // 30 minutes
  const delay = baseMs * Math.pow(2, attempt);
  return Math.min(delay, maxMs);
}

/**
 * Get human-readable backoff description
 */
export function describeBackoff(attempt: number): string {
  const ms = calculateBackoff(attempt);
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  return `${Math.round(ms / 60_000)}m`;
}

// ─── Delivery Functions ──────────────────────────────────────────────────────

/**
 * Create a delivery record and attempt first delivery
 */
export async function createAndDeliver(opts: WebhookDeliveryPayload): Promise<{ deliveryId: number; success: boolean }> {
  const { getDb } = await import("../db");
  const { cicdWebhookDeliveries } = await import("../../drizzle/schema");
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const maxRetries = opts.maxRetries ?? 3;
  const payloadSummary = JSON.stringify(opts.payload).substring(0, 2000);

  // Insert delivery record
  const result = await db.insert(cicdWebhookDeliveries).values({
    pipelineId: opts.pipelineId,
    runId: opts.runId || null,
    eventType: opts.eventType,
    webhookUrl: opts.webhookUrl,
    payloadSummary,
    deliveryStatus: "pending",
    attemptCount: 0,
    maxRetries,
  } as any);

  const deliveryId = (result as any)[0]?.insertId;
  if (!deliveryId) throw new Error("Failed to create delivery record");

  // Attempt delivery
  const success = await attemptDelivery(deliveryId, opts.webhookUrl, opts.payload);
  return { deliveryId, success };
}

/**
 * Attempt to deliver a webhook payload to the target URL
 */
async function attemptDelivery(deliveryId: number, webhookUrl: string, payload: Record<string, any>): Promise<boolean> {
  const { getDb } = await import("../db");
  const { cicdWebhookDeliveries } = await import("../../drizzle/schema");
  const { eq } = await import("drizzle-orm");
  const db = await getDb();
  if (!db) return false;

  const startTime = Date.now();
  const now = new Date().toISOString().slice(0, 19).replace("T", " ");

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Caldera-CICD-Webhook/1.0",
        "X-Delivery-ID": String(deliveryId),
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30_000), // 30s timeout
    });

    const durationMs = Date.now() - startTime;
    const responseBody = await response.text().catch(() => "");

    if (response.ok) {
      // Success
      await db.execute(sql.raw(
        `UPDATE cicd_webhook_deliveries SET
          delivery_status = 'delivered',
          response_status = ${response.status},
          response_body = ${escSql(responseBody.substring(0, 2000))},
          attempt_count = attempt_count + 1,
          last_attempt_at = '${now}',
          delivered_at = '${now}',
          duration_ms = ${durationMs},
          error_message = NULL,
          next_retry_at = NULL
        WHERE id = ${deliveryId}`
      ));
      return true;
    } else {
      // HTTP error — schedule retry
      await handleFailedAttempt(deliveryId, `HTTP ${response.status}: ${responseBody.substring(0, 500)}`, response.status, responseBody.substring(0, 2000), durationMs);
      return false;
    }
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    await handleFailedAttempt(deliveryId, err.message || "Network error", null, null, durationMs);
    return false;
  }
}

/**
 * Handle a failed delivery attempt — increment counter and schedule retry or mark failed
 */
async function handleFailedAttempt(
  deliveryId: number,
  errorMessage: string,
  responseStatus: number | null,
  responseBody: string | null,
  durationMs: number
): Promise<void> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return;

  const now = new Date().toISOString().slice(0, 19).replace("T", " ");

  // Get current attempt count and max retries
  const rows = await db.execute(sql.raw(
    `SELECT attempt_count, max_retries FROM cicd_webhook_deliveries WHERE id = ${deliveryId}`
  ));
  const record = ((rows as any).rows || rows)?.[0] as any;
  if (!record) return;

  const newAttemptCount = (record.attempt_count || 0) + 1;
  const maxRetries = record.max_retries || 3;

  if (newAttemptCount >= maxRetries) {
    // Max retries reached — mark as failed
    await db.execute(sql.raw(
      `UPDATE cicd_webhook_deliveries SET
        delivery_status = 'failed',
        ${responseStatus !== null ? `response_status = ${responseStatus},` : ""}
        ${responseBody !== null ? `response_body = ${escSql(responseBody)},` : ""}
        attempt_count = ${newAttemptCount},
        last_attempt_at = '${now}',
        duration_ms = ${durationMs},
        error_message = ${escSql(errorMessage)},
        next_retry_at = NULL
      WHERE id = ${deliveryId}`
    ));
  } else {
    // Schedule retry with exponential backoff
    const backoffMs = calculateBackoff(newAttemptCount);
    const nextRetry = new Date(Date.now() + backoffMs);
    const nextRetryStr = nextRetry.toISOString().slice(0, 19).replace("T", " ");

    await db.execute(sql.raw(
      `UPDATE cicd_webhook_deliveries SET
        delivery_status = 'retrying',
        ${responseStatus !== null ? `response_status = ${responseStatus},` : ""}
        ${responseBody !== null ? `response_body = ${escSql(responseBody)},` : ""}
        attempt_count = ${newAttemptCount},
        last_attempt_at = '${now}',
        duration_ms = ${durationMs},
        error_message = ${escSql(errorMessage)},
        next_retry_at = '${nextRetryStr}'
      WHERE id = ${deliveryId}`
    ));
  }
}

/**
 * Process pending retries — called by the cron scheduler
 */
export async function processRetryQueue(): Promise<{ processed: number; succeeded: number; failed: number }> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return { processed: 0, succeeded: 0, failed: 0 };

  const now = new Date().toISOString().slice(0, 19).replace("T", " ");

  // Find deliveries due for retry
  const rows = await db.execute(sql.raw(
    `SELECT id, webhook_url, payload_summary FROM cicd_webhook_deliveries
     WHERE delivery_status = 'retrying'
       AND next_retry_at IS NOT NULL
       AND next_retry_at <= '${now}'
     ORDER BY next_retry_at ASC
     LIMIT 20`
  ));

  const deliveries = ((rows as any).rows || rows) as any[];
  if (!deliveries?.length) return { processed: 0, succeeded: 0, failed: 0 };

  let succeeded = 0;
  let failed = 0;

  for (const delivery of deliveries) {
    try {
      const payload = delivery.payload_summary ? JSON.parse(delivery.payload_summary) : {};
      const success = await attemptDelivery(delivery.id, delivery.webhook_url, payload);
      if (success) succeeded++;
      else failed++;
    } catch {
      failed++;
    }
  }

  return { processed: deliveries.length, succeeded, failed };
}

/**
 * Manually retry a specific failed delivery
 */
export async function manualRetry(deliveryId: number): Promise<boolean> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return false;

  const rows = await db.execute(sql.raw(
    `SELECT id, webhook_url, payload_summary, delivery_status FROM cicd_webhook_deliveries WHERE id = ${deliveryId}`
  ));
  const record = ((rows as any).rows || rows)?.[0] as any;
  if (!record) return false;
  if (record.delivery_status === "delivered") return true; // Already delivered

  // Reset max retries to allow one more attempt
  await db.execute(sql.raw(
    `UPDATE cicd_webhook_deliveries SET max_retries = attempt_count + 1 WHERE id = ${deliveryId}`
  ));

  const payload = record.payload_summary ? JSON.parse(record.payload_summary) : {};
  return attemptDelivery(deliveryId, record.webhook_url, payload);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function escSql(s: string | null): string {
  if (s === null) return "NULL";
  return `'${s.replace(/'/g, "''")}'`;
}
