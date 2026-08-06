// ─────────────────────────────────────────────────────────────────────────────
// Structured Logger — Production-grade logging with pino
// ─────────────────────────────────────────────────────────────────────────────
// Replaces console.log/error with structured JSON logging for production
// environments. Supports correlation IDs, child loggers per module, and
// automatic redaction of sensitive fields.
//
// Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
// ─────────────────────────────────────────────────────────────────────────────

import pino from "pino";

const isDev = process.env.NODE_ENV === "development";

// ── Sensitive field redaction paths ─────────────────────────────────────────
const REDACT_PATHS = [
  "password",
  "secret",
  "token",
  "authorization",
  "cookie",
  "apiKey",
  "api_key",
  "accessToken",
  "refreshToken",
  "sessionToken",
  "req.headers.authorization",
  "req.headers.cookie",
  "req.headers['x-api-key']",
];

// ── Base logger configuration ───────────────────────────────────────────────
export const logger = pino({
  level: process.env.LOG_LEVEL || (isDev ? "debug" : "info"),
  redact: {
    paths: REDACT_PATHS,
    censor: "[REDACTED]",
  },
  serializers: {
    err: pino.stdSerializers.err,
    req: (req: any) => ({
      method: req.method,
      url: req.url,
      path: req.path,
      remoteAddress: req.ip || req.remoteAddress,
      userAgent: req.headers?.["user-agent"],
      correlationId: req.correlationId,
    }),
    res: (res: any) => ({
      statusCode: res.statusCode,
      contentLength: res.getHeader?.("content-length"),
    }),
  },
  // In development, use pino-pretty for human-readable output
  // In production, output raw JSON for log aggregation (CloudWatch, ELK, etc.)
  ...(isDev
    ? {
        transport: {
          target: "pino-pretty",
          options: {
            colorize: true,
            translateTime: "HH:MM:ss",
            ignore: "pid,hostname",
            singleLine: false,
          },
        },
      }
    : {
        // Production: raw JSON, no transport overhead
        timestamp: pino.stdTimeFunctions.isoTime,
        formatters: {
          level: (label: string) => ({ level: label }),
          bindings: (bindings: Record<string, any>) => ({
            pid: bindings.pid,
            host: bindings.hostname,
            service: "caldera-dashboard",
            version: process.env.APP_VERSION || "unknown",
          }),
        },
      }),
});

// ── Module-scoped child loggers ─────────────────────────────────────────────
// Create child loggers with module context for easier filtering
export function createModuleLogger(module: string) {
  return logger.child({ module });
}

// ── Request-scoped child logger ─────────────────────────────────────────────
// Create a child logger bound to a specific request's correlation ID
export function createRequestLogger(correlationId: string, userId?: string) {
  return logger.child({
    correlationId,
    ...(userId ? { userId } : {}),
  });
}

// ── Pre-built module loggers ────────────────────────────────────────────────
export const serverLogger = createModuleLogger("server");
export const authLogger = createModuleLogger("auth");
export const trpcLogger = createModuleLogger("trpc");
export const dbLogger = createModuleLogger("database");
export const engagementLogger = createModuleLogger("engagement");
export const scanLogger = createModuleLogger("scan");
export const bountyLogger = createModuleLogger("bounty");
export const securityLogger = createModuleLogger("security");

// ── Audit log helper ────────────────────────────────────────────────────────
// For security-sensitive operations that need an audit trail
export function auditLog(event: {
  action: string;
  userId?: string;
  resource?: string;
  resourceId?: string | number;
  outcome: "success" | "failure" | "denied";
  details?: Record<string, any>;
  correlationId?: string;
}) {
  securityLogger.info(
    {
      audit: true,
      ...event,
    },
    `AUDIT: ${event.action} ${event.outcome} ${event.resource ? `on ${event.resource}` : ""}`.trim()
  );
}
