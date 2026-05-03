// ─────────────────────────────────────────────────────────────────────────────
// Correlation ID Middleware
// ─────────────────────────────────────────────────────────────────────────────
// Assigns a unique correlation ID to every incoming request for distributed
// tracing. Accepts an existing ID from X-Request-ID or X-Correlation-ID
// headers (e.g., from an upstream load balancer), or generates a new UUIDv4.
//
// The correlation ID is:
// 1. Stored on req.correlationId for use in downstream handlers
// 2. Echoed back in the X-Correlation-ID response header
// 3. Available for structured logging via createRequestLogger()
//
// Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
// ─────────────────────────────────────────────────────────────────────────────

import type { Request, Response, NextFunction } from "express";
import { v4 as uuidv4 } from "uuid";

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      correlationId: string;
      requestStartTime: number;
    }
  }
}

// ── UUID validation ─────────────────────────────────────────────────────────
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidCorrelationId(id: string): boolean {
  // Accept UUIDs or alphanumeric strings up to 128 chars (for ALB/CloudFront trace IDs)
  if (UUID_REGEX.test(id)) return true;
  if (/^[\w\-.:]{1,128}$/.test(id)) return true;
  return false;
}

// ── Correlation ID Middleware ────────────────────────────────────────────────
export function correlationIdMiddleware(req: Request, res: Response, next: NextFunction) {
  // Check for existing correlation ID from upstream (ALB, CloudFront, API Gateway)
  const existingId =
    (req.headers["x-correlation-id"] as string) ||
    (req.headers["x-request-id"] as string) ||
    (req.headers["x-amzn-trace-id"] as string);

  const correlationId =
    existingId && isValidCorrelationId(existingId) ? existingId : uuidv4();

  // Store on request object
  req.correlationId = correlationId;
  req.requestStartTime = Date.now();

  // Echo back in response headers
  res.setHeader("X-Correlation-ID", correlationId);
  res.setHeader("X-Request-ID", correlationId);

  next();
}

// ── Request Logging Middleware ───────────────────────────────────────────────
// Logs request start and completion with timing, status, and correlation ID.
// Uses structured logger when available, falls back to console.
export function requestLoggingMiddleware(req: Request, res: Response, next: NextFunction) {
  // Skip logging for health checks and static assets
  if (
    req.path === "/healthz" ||
    req.path === "/api/health" ||
    req.path === "/api/memory-profile" ||
    req.path.startsWith("/assets/") ||
    req.path.startsWith("/node_modules/") ||
    req.path.endsWith(".js") ||
    req.path.endsWith(".css") ||
    req.path.endsWith(".map") ||
    req.path.endsWith(".ico")
  ) {
    return next();
  }

  const startTime = req.requestStartTime || Date.now();

  // Log on response finish
  res.on("finish", () => {
    const duration = Date.now() - startTime;
    const logData = {
      correlationId: req.correlationId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: duration,
      ip: req.ip,
      userAgent: req.headers["user-agent"]?.substring(0, 100),
      contentLength: res.getHeader("content-length"),
    };

    // Use structured logger if available, otherwise console
    try {
      const { serverLogger } = require("./structured-logger");
      if (res.statusCode >= 500) {
        serverLogger.error(logData, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      } else if (res.statusCode >= 400) {
        serverLogger.warn(logData, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      } else if (duration > 5000) {
        serverLogger.warn({ ...logData, slow: true }, `SLOW ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      } else {
        serverLogger.info(logData, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      }
    } catch {
      // Fallback to console if structured logger not available
      const level = res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "log";
      console[level](
        `[${req.correlationId?.substring(0, 8)}] ${req.method} ${req.path} → ${res.statusCode} (${duration}ms)`
      );
    }
  });

  next();
}
