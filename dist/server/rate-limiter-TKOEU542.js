import "./chunk-KFQGP6VL.js";

// server/lib/rate-limiter.ts
import rateLimit from "express-rate-limit";
function rateLimitResponse(_req, res) {
  res.status(429).json({
    error: {
      json: {
        message: "Too many requests. Please try again later.",
        code: -32029,
        data: { code: "TOO_MANY_REQUESTS", httpStatus: 429 }
      }
    }
  });
}
function isLocalRequest(req) {
  const host = req.hostname || req.headers.host || "";
  return host.includes("localhost") || host.includes("127.0.0.1");
}
var authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  // Use default keyGenerator (req.ip with IPv6 normalization)
  handler: rateLimitResponse,
  skip: isLocalRequest,
  message: "Too many authentication attempts. Please try again in 15 minutes."
});
var apiRateLimiter = rateLimit({
  windowMs: 60 * 1e3,
  // 1 minute
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitResponse,
  skip: (req) => {
    if (isLocalRequest(req)) return true;
    if (req.path === "/api/events/stream") return true;
    return false;
  },
  message: "Too many API requests. Please slow down."
});
var generalRateLimiter = rateLimit({
  windowMs: 60 * 1e3,
  // 1 minute
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitResponse,
  skip: (req) => {
    if (isLocalRequest(req)) return true;
    if (req.path === "/healthz" || req.path === "/api/health") return true;
    if (req.path === "/api/events/stream") return true;
    return false;
  },
  message: "Too many requests. Please try again later."
});
var AUTH_TRPC_PATHS = [
  "accountAuth.emailLogin",
  "accountAuth.verifyMfa",
  "accountAuth.resetPassword",
  "accountAuth.completeInvite",
  "calderaAuth.login"
];
function trpcAuthRateLimiter(req, res, next) {
  const trpcPath = req.path.replace(/^\//, "");
  const procedures = trpcPath.split(",");
  const isAuthCall = procedures.some(
    (p) => AUTH_TRPC_PATHS.some((authPath) => p.includes(authPath))
  );
  if (isAuthCall) {
    return authRateLimiter(req, res, next);
  }
  next();
}
export {
  apiRateLimiter,
  authRateLimiter,
  generalRateLimiter,
  trpcAuthRateLimiter
};
