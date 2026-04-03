/**
 * Rate Limiting Middleware
 * 
 * Provides tiered rate limiting for different endpoint categories:
 * - Auth endpoints (login/register): strict limits to prevent brute force
 * - tRPC API endpoints: moderate limits for normal usage
 * 
 * Uses express-rate-limit with in-memory store (suitable for single-instance DO deployment).
 * For multi-instance deployments, swap to a Redis-backed store.
 * 
 * Note: The Express app has `trust proxy` set to 1, so req.ip already resolves
 * to the correct client IP from X-Forwarded-For. We use the default keyGenerator
 * which handles IPv6 normalization properly.
 */
import rateLimit from "express-rate-limit";
import type { Request, Response } from "express";

// ─── Helpers ────────────────────────────────────────────────────────────────

function rateLimitResponse(_req: Request, res: Response) {
  res.status(429).json({
    error: {
      json: {
        message: "Too many requests. Please try again later.",
        code: -32029,
        data: { code: "TOO_MANY_REQUESTS", httpStatus: 429 },
      },
    },
  });
}

function isLocalRequest(req: Request): boolean {
  const host = req.hostname || req.headers.host || "";
  return host.includes("localhost") || host.includes("127.0.0.1");
}

// ─── Auth Rate Limiter ──────────────────────────────────────────────────────
// Strict: 10 requests per 15 minutes per IP for login/register endpoints
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  // Use default keyGenerator (req.ip with IPv6 normalization)
  handler: rateLimitResponse,
  skip: isLocalRequest,
  message: "Too many authentication attempts. Please try again in 15 minutes.",
});

// ─── tRPC API Rate Limiter ──────────────────────────────────────────────────
// Moderate: 500 requests per minute per IP for tRPC endpoints
export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitResponse,
  skip: (req) => {
    if (isLocalRequest(req)) return true;
    // SSE event stream is a long-lived connection, not burst traffic
    if (req.path === "/api/events/stream") return true;
    return false;
  },
  message: "Too many API requests. Please slow down.",
});

// ─── General Rate Limiter ───────────────────────────────────────────────
// Lenient: 500 requests per minute per IP for all other endpoints
export const generalRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitResponse,
  skip: (req) => {
    if (isLocalRequest(req)) return true;
    // Skip for health check endpoints
    if (req.path === "/healthz" || req.path === "/api/health") return true;
    // Skip for SSE event stream — long-lived connections, not burst traffic
    if (req.path === "/api/events/stream") return true;
    return false;
  },
  message: "Too many requests. Please try again later.",
});

// ─── Auth-specific tRPC path matcher ────────────────────────────────────────
// Matches tRPC batch calls that include auth mutations (login, register, etc.)
const AUTH_TRPC_PATHS = [
  "accountAuth.emailLogin",
  "accountAuth.verifyMfa",
  "accountAuth.resetPassword",
  "accountAuth.completeInvite",
  "calderaAuth.login",
];

/**
 * Middleware that applies auth rate limiting to tRPC auth mutations.
 * tRPC batches multiple calls into a single HTTP request, so we inspect
 * the URL path to detect auth-related procedure calls.
 */
export function trpcAuthRateLimiter(req: Request, res: Response, next: () => void) {
  // tRPC encodes procedure names in the URL path after /api/trpc/
  const trpcPath = req.path.replace(/^\//, "");
  const procedures = trpcPath.split(",");
  const isAuthCall = procedures.some((p) =>
    AUTH_TRPC_PATHS.some((authPath) => p.includes(authPath))
  );

  if (isAuthCall) {
    return authRateLimiter(req, res, next);
  }
  next();
}
