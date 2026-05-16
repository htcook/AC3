import "./chunk-KFQGP6VL.js";

// server/lib/cicd-webhook-delivery.ts
import { sql } from "drizzle-orm";
function calculateBackoff(attempt) {
  const baseMs = 3e4;
  const maxMs = 30 * 6e4;
  const delay = baseMs * Math.pow(2, attempt);
  return Math.min(delay, maxMs);
}
function describeBackoff(attempt) {
  const ms = calculateBackoff(attempt);
  if (ms < 6e4) return `${Math.round(ms / 1e3)}s`;
  return `${Math.round(ms / 6e4)}m`;
}
async function createAndDeliver(opts) {
  const { getDb } = await import("./db-GNA5CL3K.js");
  const { cicdWebhookDeliveries } = await import("./schema-RLVX4V4P.js");
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const maxRetries = opts.maxRetries ?? 3;
  const payloadSummary = JSON.stringify(opts.payload).substring(0, 2e3);
  const result = await db.insert(cicdWebhookDeliveries).values({
    pipelineId: opts.pipelineId,
    runId: opts.runId || null,
    eventType: opts.eventType,
    webhookUrl: opts.webhookUrl,
    payloadSummary,
    deliveryStatus: "pending",
    attemptCount: 0,
    maxRetries
  });
  const deliveryId = result[0]?.insertId;
  if (!deliveryId) throw new Error("Failed to create delivery record");
  const success = await attemptDelivery(deliveryId, opts.webhookUrl, opts.payload);
  return { deliveryId, success };
}
async function attemptDelivery(deliveryId, webhookUrl, payload) {
  const { getDb } = await import("./db-GNA5CL3K.js");
  const { cicdWebhookDeliveries } = await import("./schema-RLVX4V4P.js");
  const { eq } = await import("drizzle-orm");
  const db = await getDb();
  if (!db) return false;
  const startTime = Date.now();
  const now = (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace("T", " ");
  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Caldera-CICD-Webhook/1.0",
        "X-Delivery-ID": String(deliveryId)
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3e4)
      // 30s timeout
    });
    const durationMs = Date.now() - startTime;
    const responseBody = await response.text().catch(() => "");
    if (response.ok) {
      await db.execute(sql.raw(
        `UPDATE cicd_webhook_deliveries SET
          delivery_status = 'delivered',
          response_status = ${response.status},
          response_body = ${escSql(responseBody.substring(0, 2e3))},
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
      await handleFailedAttempt(deliveryId, `HTTP ${response.status}: ${responseBody.substring(0, 500)}`, response.status, responseBody.substring(0, 2e3), durationMs);
      return false;
    }
  } catch (err) {
    const durationMs = Date.now() - startTime;
    await handleFailedAttempt(deliveryId, err.message || "Network error", null, null, durationMs);
    return false;
  }
}
async function handleFailedAttempt(deliveryId, errorMessage, responseStatus, responseBody, durationMs) {
  const { getDb } = await import("./db-GNA5CL3K.js");
  const db = await getDb();
  if (!db) return;
  const now = (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace("T", " ");
  const rows = await db.execute(sql.raw(
    `SELECT attempt_count, max_retries FROM cicd_webhook_deliveries WHERE id = ${deliveryId}`
  ));
  const record = (rows.rows || rows)?.[0];
  if (!record) return;
  const newAttemptCount = (record.attempt_count || 0) + 1;
  const maxRetries = record.max_retries || 3;
  if (newAttemptCount >= maxRetries) {
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
async function processRetryQueue() {
  const { getDb } = await import("./db-GNA5CL3K.js");
  const db = await getDb();
  if (!db) return { processed: 0, succeeded: 0, failed: 0 };
  const now = (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace("T", " ");
  const rows = await db.execute(sql.raw(
    `SELECT id, webhook_url, payload_summary FROM cicd_webhook_deliveries
     WHERE delivery_status = 'retrying'
       AND next_retry_at IS NOT NULL
       AND next_retry_at <= '${now}'
     ORDER BY next_retry_at ASC
     LIMIT 20`
  ));
  const deliveries = rows.rows || rows;
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
async function manualRetry(deliveryId) {
  const { getDb } = await import("./db-GNA5CL3K.js");
  const db = await getDb();
  if (!db) return false;
  const rows = await db.execute(sql.raw(
    `SELECT id, webhook_url, payload_summary, delivery_status FROM cicd_webhook_deliveries WHERE id = ${deliveryId}`
  ));
  const record = (rows.rows || rows)?.[0];
  if (!record) return false;
  if (record.delivery_status === "delivered") return true;
  await db.execute(sql.raw(
    `UPDATE cicd_webhook_deliveries SET max_retries = attempt_count + 1 WHERE id = ${deliveryId}`
  ));
  const payload = record.payload_summary ? JSON.parse(record.payload_summary) : {};
  return attemptDelivery(deliveryId, record.webhook_url, payload);
}
function escSql(s) {
  if (s === null) return "NULL";
  return `'${s.replace(/'/g, "''")}'`;
}
export {
  calculateBackoff,
  createAndDeliver,
  describeBackoff,
  manualRetry,
  processRetryQueue
};
