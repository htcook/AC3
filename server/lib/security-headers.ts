// ─────────────────────────────────────────────────────────────────────────────
// Security Headers Middleware
// ─────────────────────────────────────────────────────────────────────────────
// Production-grade security headers for FedRAMP/SOC2 compliance:
// - Content Security Policy (CSP) with nonce support
// - X-Frame-Options, X-Content-Type-Options, Referrer-Policy
// - Permissions-Policy (camera, microphone, geolocation)
// - CORS configuration for API endpoints
//
// Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
// ─────────────────────────────────────────────────────────────────────────────

import type { Request, Response, NextFunction } from "express";
import crypto from "crypto";

// ── CSP Nonce Generator ─────────────────────────────────────────────────────
function generateNonce(): string {
  return crypto.randomBytes(16).toString("base64");
}

// ── Content Security Policy ─────────────────────────────────────────────────
// Strict CSP that allows inline scripts only via nonce, blocks mixed content,
// and restricts resource origins to known-good domains.
export function cspMiddleware(req: Request, res: Response, next: NextFunction) {
  const nonce = generateNonce();
  // Store nonce on request for use in HTML templates
  (req as any).cspNonce = nonce;

  const isDev = process.env.NODE_ENV === "development";

  // In development, allow unsafe-eval for HMR and Vite
  const scriptSrc = isDev
    ? `'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com`
    : `'self' 'nonce-${nonce}' https://fonts.googleapis.com`;

  const styleSrc = isDev
    ? `'self' 'unsafe-inline' https://fonts.googleapis.com`
    : `'self' 'unsafe-inline' https://fonts.googleapis.com`;

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
    `upgrade-insecure-requests`,
  ];

  // Use Report-Only in development to avoid breaking HMR
  const headerName = isDev
    ? "Content-Security-Policy-Report-Only"
    : "Content-Security-Policy";

  res.setHeader(headerName, directives.join("; "));
  next();
}

// ── Standard Security Headers ───────────────────────────────────────────────
export function securityHeadersMiddleware(_req: Request, res: Response, next: NextFunction) {
  // Prevent clickjacking — DENY means no framing at all
  res.setHeader("X-Frame-Options", "DENY");

  // Prevent MIME-type sniffing attacks
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Control referrer information leakage
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Restrict browser features — deny camera, mic, geolocation by default
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
  );

  // Prevent XSS reflection attacks (legacy browsers)
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Prevent DNS prefetching to avoid leaking visited domains
  res.setHeader("X-DNS-Prefetch-Control", "off");

  // Disable client-side caching for API responses
  if (_req.path.startsWith("/api/")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
  }

  next();
}

// ── CORS Configuration ──────────────────────────────────────────────────────
// Configurable CORS for API endpoints. In production, restrict to known origins.
export function corsMiddleware(req: Request, res: Response, next: NextFunction) {
  const isDev = process.env.NODE_ENV === "development";
  const origin = req.headers.origin;

  // Allowed origins — in production, restrict to the app's own domain
  const allowedOrigins = isDev
    ? ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"]
    : [
        process.env.APP_URL,
        process.env.VITE_APP_URL,
        // Add your production domains here
      ].filter(Boolean) as string[];

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else if (isDev && origin) {
    // In dev, be permissive for localhost variants
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
  res.setHeader("Access-Control-Max-Age", "86400"); // 24 hours preflight cache
  res.setHeader("Vary", "Origin");

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
}
