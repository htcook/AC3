import {
  __esm,
  __export,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/structured-logger.ts
var structured_logger_exports = {};
__export(structured_logger_exports, {
  auditLog: () => auditLog,
  authLogger: () => authLogger,
  bountyLogger: () => bountyLogger,
  createModuleLogger: () => createModuleLogger,
  createRequestLogger: () => createRequestLogger,
  dbLogger: () => dbLogger,
  engagementLogger: () => engagementLogger,
  logger: () => logger,
  scanLogger: () => scanLogger,
  securityLogger: () => securityLogger,
  serverLogger: () => serverLogger,
  trpcLogger: () => trpcLogger
});
import pino from "pino";
function createModuleLogger(module) {
  return logger.child({ module });
}
function createRequestLogger(correlationId, userId) {
  return logger.child({
    correlationId,
    ...userId ? { userId } : {}
  });
}
function auditLog(event) {
  securityLogger.info(
    {
      audit: true,
      ...event
    },
    `AUDIT: ${event.action} ${event.outcome} ${event.resource ? `on ${event.resource}` : ""}`.trim()
  );
}
var isDev, REDACT_PATHS, logger, serverLogger, authLogger, trpcLogger, dbLogger, engagementLogger, scanLogger, bountyLogger, securityLogger;
var init_structured_logger = __esm({
  "server/lib/structured-logger.ts"() {
    "use strict";
    isDev = process.env.NODE_ENV === "development";
    REDACT_PATHS = [
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
      "req.headers['x-api-key']"
    ];
    logger = pino({
      level: process.env.LOG_LEVEL || (isDev ? "debug" : "info"),
      redact: {
        paths: REDACT_PATHS,
        censor: "[REDACTED]"
      },
      serializers: {
        err: pino.stdSerializers.err,
        req: (req) => ({
          method: req.method,
          url: req.url,
          path: req.path,
          remoteAddress: req.ip || req.remoteAddress,
          userAgent: req.headers?.["user-agent"],
          correlationId: req.correlationId
        }),
        res: (res) => ({
          statusCode: res.statusCode,
          contentLength: res.getHeader?.("content-length")
        })
      },
      // In development, use pino-pretty for human-readable output
      // In production, output raw JSON for log aggregation (CloudWatch, ELK, etc.)
      ...isDev ? {
        transport: {
          target: "pino-pretty",
          options: {
            colorize: true,
            translateTime: "HH:MM:ss",
            ignore: "pid,hostname",
            singleLine: false
          }
        }
      } : {
        // Production: raw JSON, no transport overhead
        timestamp: pino.stdTimeFunctions.isoTime,
        formatters: {
          level: (label) => ({ level: label }),
          bindings: (bindings) => ({
            pid: bindings.pid,
            host: bindings.hostname,
            service: "caldera-dashboard",
            version: process.env.APP_VERSION || "unknown"
          })
        }
      }
    });
    serverLogger = createModuleLogger("server");
    authLogger = createModuleLogger("auth");
    trpcLogger = createModuleLogger("trpc");
    dbLogger = createModuleLogger("database");
    engagementLogger = createModuleLogger("engagement");
    scanLogger = createModuleLogger("scan");
    bountyLogger = createModuleLogger("bounty");
    securityLogger = createModuleLogger("security");
  }
});

// server/lib/correlation-id.ts
import { v4 as uuidv4 } from "uuid";
var UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidCorrelationId(id) {
  if (UUID_REGEX.test(id)) return true;
  if (/^[\w\-.:]{1,128}$/.test(id)) return true;
  return false;
}
function correlationIdMiddleware(req, res, next) {
  const existingId = req.headers["x-correlation-id"] || req.headers["x-request-id"] || req.headers["x-amzn-trace-id"];
  const correlationId = existingId && isValidCorrelationId(existingId) ? existingId : uuidv4();
  req.correlationId = correlationId;
  req.requestStartTime = Date.now();
  res.setHeader("X-Correlation-ID", correlationId);
  res.setHeader("X-Request-ID", correlationId);
  next();
}
function requestLoggingMiddleware(req, res, next) {
  if (req.path === "/healthz" || req.path === "/api/health" || req.path === "/api/memory-profile" || req.path.startsWith("/assets/") || req.path.startsWith("/node_modules/") || req.path.endsWith(".js") || req.path.endsWith(".css") || req.path.endsWith(".map") || req.path.endsWith(".ico")) {
    return next();
  }
  const startTime = req.requestStartTime || Date.now();
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
      contentLength: res.getHeader("content-length")
    };
    try {
      const { serverLogger: serverLogger2 } = (init_structured_logger(), __toCommonJS(structured_logger_exports));
      if (res.statusCode >= 500) {
        serverLogger2.error(logData, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      } else if (res.statusCode >= 400) {
        serverLogger2.warn(logData, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      } else if (duration > 5e3) {
        serverLogger2.warn({ ...logData, slow: true }, `SLOW ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      } else {
        serverLogger2.info(logData, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      }
    } catch {
      const level = res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "log";
      console[level](
        `[${req.correlationId?.substring(0, 8)}] ${req.method} ${req.path} \u2192 ${res.statusCode} (${duration}ms)`
      );
    }
  });
  next();
}
export {
  correlationIdMiddleware,
  requestLoggingMiddleware
};
