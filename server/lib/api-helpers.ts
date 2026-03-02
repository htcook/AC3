/**
 * Shared API helpers for Caldera and GoPhish proxy routers.
 * Extracted from routers.ts during the router split refactoring.
 */
import { ENV } from "../_core/env";

// ─── Caldera Session ────────────────────────────────────────────────────

export const CALDERA_SESSION_COOKIE = 'caldera_session';

export function getCalderaCookieOptions(req: any, rememberMe = false) {
  const host = req.hostname || req.headers?.host || '';
  const isLocalhost = host.includes('localhost');
  const isManusPreview = host.includes('manus.space') || host.includes('manus.computer') || host.includes('manusvm.computer');
  
  const sameSite = isManusPreview ? 'none' as const : 'lax' as const;
  
  const opts = {
    path: '/',
    httpOnly: true,
    secure: !isLocalhost,
    sameSite,
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
  };
  console.log(`[Auth Cookie] host=${host}, sameSite=${sameSite}, secure=${opts.secure}, maxAge=${opts.maxAge}`);
  return opts;
}

export const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

// ─── GoPhish & Caldera API Config ───────────────────────────────────────

export const GOPHISH_URL = ENV.gophishBaseUrl;
export const GOPHISH_API_KEY = ENV.gophishApiKey;
export const CALDERA_BASE_URL = ENV.calderaBaseUrl;
export const CALDERA_API_KEY = ENV.calderaApiKey;

// ─── GoPhish API Helper ─────────────────────────────────────────────────

export async function fetchGophishAPI(endpoint: string, method: string = 'GET', data?: any) {
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const url = `${GOPHISH_URL}${endpoint}`;
    const options: RequestInit = {
      method,
      headers: {
        'Authorization': GOPHISH_API_KEY,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(15000),
    };
    if (data) options.body = JSON.stringify(data);
    
    const response = await fetch(url, options);
    if (!response.ok) {
      const errText = await response.text();
      console.error(`GoPhish API error (${endpoint}):`, response.status, errText);
      return null;
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  } catch (error) {
    console.error(`GoPhish API error (${endpoint}):`, error);
    return null;
  }
}

// ─── Caldera API Helper ─────────────────────────────────────────────────

export async function fetchCalderaAPI(url: string, apiKey: string, endpoint: string) {
  try {
    const response = await fetch(`${url}${endpoint}`, {
      headers: { 'KEY': apiKey },
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Caldera API error (${endpoint}):`, error);
    return null;
  }
}
