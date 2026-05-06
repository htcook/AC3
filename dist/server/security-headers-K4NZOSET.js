import "./chunk-KFQGP6VL.js";

// server/lib/security-headers.ts
import crypto from "crypto";
function generateNonce() {
  return crypto.randomBytes(16).toString("base64");
}
function cspMiddleware(req, res, next) {
  const nonce = generateNonce();
  req.cspNonce = nonce;
  const isDev = process.env.NODE_ENV === "development";
  const scriptSrc = isDev ? `'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com` : `'self' 'nonce-${nonce}' https://fonts.googleapis.com`;
  const styleSrc = isDev ? `'self' 'unsafe-inline' https://fonts.googleapis.com` : `'self' 'unsafe-inline' https://fonts.googleapis.com`;
  const directives = [
    `default-src 'self'`,
    `script-src ${scriptSrc}`,
    `style-src ${styleSrc}`,
    `font-src 'self' https://fonts.gstatic.com data:`,
    `img-src 'self' data: blob: https:`,
    `connect-src 'self' wss: ws: https://api.manus.im https://fonts.googleapis.com https://fonts.gstatic.com ${isDev ? "http://localhost:* ws://localhost:*" : ""}`,
    `frame-src 'none'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `upgrade-insecure-requests`
  ];
  const headerName = isDev ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
  res.setHeader(headerName, directives.join("; "));
  next();
}
function securityHeadersMiddleware(_req, res, next) {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
  );
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  if (_req.path.startsWith("/api/")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
  }
  next();
}
function corsMiddleware(req, res, next) {
  const isDev = process.env.NODE_ENV === "development";
  const origin = req.headers.origin;
  const allowedOrigins = isDev ? ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"] : [
    process.env.APP_URL,
    process.env.VITE_APP_URL
    // Add your production domains here
  ].filter(Boolean);
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else if (isDev && origin) {
    if (origin.includes("localhost") || origin.includes("127.0.0.1")) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Request-ID, X-Correlation-ID"
  );
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Max-Age", "86400");
  res.setHeader("Vary", "Origin");
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  next();
}
export {
  corsMiddleware,
  cspMiddleware,
  securityHeadersMiddleware
};
