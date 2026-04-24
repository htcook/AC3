/**
 * Unified OSINT Rate Limiter
 * 
 * Provides per-connector and global rate limiting for all OSINT API calls.
 * Prevents hitting API quotas, avoids IP bans, and ensures fair usage
 * across concurrent scans.
 * 
 * Features:
 * - Per-connector rate limits (requests per window)
 * - Global rate limit across all connectors
 * - Token bucket algorithm with burst allowance
 * - Automatic backoff on 429 responses
 * - Queue-based request scheduling
 * - Rate limit status reporting for diagnostics
 */

export interface RateLimitConfig {
  /** Max requests per window */
  maxRequests: number;
  /** Window duration in milliseconds */
  windowMs: number;
  /** Max burst above steady rate (default: maxRequests * 0.2) */
  burstAllowance?: number;
  /** Backoff multiplier on 429 (default: 2.0) */
  backoffMultiplier?: number;
  /** Max backoff duration in ms (default: 60000) */
  maxBackoffMs?: number;
}

interface BucketState {
  tokens: number;
  lastRefill: number;
  backoffUntil: number;
  backoffLevel: number;
  totalRequests: number;
  totalThrottled: number;
  total429s: number;
}

/**
 * Per-connector rate limit configurations.
 * Based on documented API limits and fair-use policies.
 */
export const CONNECTOR_RATE_LIMITS: Record<string, RateLimitConfig> = {
  // === Free APIs (conservative limits) ===
  urlhaus:          { maxRequests: 10, windowMs: 60_000 },      // abuse.ch: undocumented, be conservative
  malwarebazaar:    { maxRequests: 10, windowMs: 60_000 },      // abuse.ch: undocumented, be conservative
  threatfox:        { maxRequests: 10, windowMs: 60_000 },      // abuse.ch: undocumented, be conservative
  cisa_advisories:  { maxRequests: 5,  windowMs: 60_000 },      // Static JSON, rarely changes — cache-friendly
  osv_dev:          { maxRequests: 20, windowMs: 60_000 },      // Google-backed, generous but undocumented
  team_cymru:       { maxRequests: 30, windowMs: 60_000 },      // DNS-based, generous but respect fair use
  sec_edgar:        { maxRequests: 10, windowMs: 60_000 },      // SEC: 10 req/sec documented, we go slower
  crtsh:            { maxRequests: 5,  windowMs: 60_000 },      // crt.sh: shared resource, be gentle
  phishtank:        { maxRequests: 10, windowMs: 60_000 },      // PhishTank: undocumented
  alienvault_otx:   { maxRequests: 20, windowMs: 60_000 },      // OTX: documented 10k/day ≈ 7/min
  ransomware_live:  { maxRequests: 5,  windowMs: 60_000 },      // Small project, be gentle
  hackertarget:     { maxRequests: 5,  windowMs: 60_000 },      // Free tier: 100/day
  rapiddns:         { maxRequests: 5,  windowMs: 60_000 },      // Web scraping, be gentle
  bgpview:          { maxRequests: 10, windowMs: 60_000 },      // Undocumented
  ip_api:           { maxRequests: 45, windowMs: 60_000 },      // Documented: 45/min
  anubis:           { maxRequests: 10, windowMs: 60_000 },      // Undocumented
  dnsrepo:          { maxRequests: 5,  windowMs: 60_000 },      // Undocumented
  sitedossier:      { maxRequests: 5,  windowMs: 60_000 },      // Web scraping, be gentle
  commoncrawl:      { maxRequests: 5,  windowMs: 60_000 },      // Shared resource
  threatminer:      { maxRequests: 10, windowMs: 60_000 },      // Documented: 10/min
  circl_pdns:       { maxRequests: 10, windowMs: 60_000 },      // Undocumented

  // === API Key Required (respect documented limits) ===
  shodan:           { maxRequests: 1,  windowMs: 1_000 },       // Documented: 1 req/sec
  shodan_internetdb:{ maxRequests: 30, windowMs: 60_000 },      // Free, no auth, generous
  censys:           { maxRequests: 5,  windowMs: 60_000 },      // Documented: 120/5min = 24/min, we go slower
  virustotal:       { maxRequests: 4,  windowMs: 60_000 },      // Free: 4/min, Premium: 500/min
  securitytrails:   { maxRequests: 10, windowMs: 60_000 },      // Documented: 50/day free
  urlscan:          { maxRequests: 5,  windowMs: 60_000 },      // Documented: varies by plan
  abuseipdb:        { maxRequests: 10, windowMs: 60_000 },      // Documented: 1000/day ≈ 0.7/min
  greynoise:        { maxRequests: 10, windowMs: 60_000 },      // Community: 500/day
  dehashed:         { maxRequests: 5,  windowMs: 60_000 },      // Commercial API
  dehashed_whois:   { maxRequests: 5,  windowMs: 60_000 },      // Commercial API
  hunter:           { maxRequests: 10, windowMs: 60_000 },      // Documented: 500/month free
  whoisxml:         { maxRequests: 10, windowMs: 60_000 },      // Documented: 500/month free
  passivetotal:     { maxRequests: 10, windowMs: 60_000 },      // Commercial API
  fullhunt:         { maxRequests: 5,  windowMs: 60_000 },      // Free tier limited
  netlas:           { maxRequests: 5,  windowMs: 60_000 },      // Free tier limited
  intelx_search:    { maxRequests: 3,  windowMs: 60_000 },      // Free: 3/day
  leakix:           { maxRequests: 5,  windowMs: 60_000 },      // Free tier limited
  coalition_control:{ maxRequests: 10, windowMs: 60_000 },      // Commercial API
  google_safebrowsing: { maxRequests: 10, windowMs: 60_000 },   // Documented: 10k/day

  // === DNS-based (no API, but respect DNS infrastructure) ===
  dns_deep:         { maxRequests: 30, windowMs: 60_000 },      // Direct DNS queries
  email_security:   { maxRequests: 20, windowMs: 60_000 },      // Direct DNS queries
  dns_zone_transfer:{ maxRequests: 5,  windowMs: 60_000 },      // AXFR — be very conservative
  domain_health:    { maxRequests: 10, windowMs: 60_000 },      // DNSBL lookups

  // === Web scraping (conservative) ===
  builtwith:        { maxRequests: 3,  windowMs: 60_000 },      // Web scraping
  github_leaks:     { maxRequests: 10, windowMs: 60_000 },      // GitHub API: 30/min unauthenticated
  github_recon:     { maxRequests: 10, windowMs: 60_000 },      // GitHub API
  social_media:     { maxRequests: 5,  windowMs: 60_000 },      // Web scraping
  company_intel:    { maxRequests: 3,  windowMs: 60_000 },      // Web scraping + LLM
  wayback:          { maxRequests: 5,  windowMs: 60_000 },      // Wayback CDX API
  wayback_diff:     { maxRequests: 3,  windowMs: 60_000 },      // Wayback content fetch
  http_security:    { maxRequests: 10, windowMs: 60_000 },      // Direct HTTP requests
  reverse_whois:    { maxRequests: 5,  windowMs: 60_000 },      // crt.sh based
  favicon_hash:     { maxRequests: 5,  windowMs: 60_000 },      // HTTP + Shodan
  jarm_fingerprint: { maxRequests: 5,  windowMs: 60_000 },      // Direct TLS probing
  typosquat:        { maxRequests: 10, windowMs: 60_000 },      // DNS resolution
  cloud_assets:     { maxRequests: 10, windowMs: 60_000 },      // DNS/HTTP probing
  cloud_bucket_recon:{ maxRequests: 5, windowMs: 60_000 },      // HTTP probing
  container_discovery:{ maxRequests: 5, windowMs: 60_000 },     // HTTP probing

  // === Credential sources ===
  hibp:             { maxRequests: 10, windowMs: 60_000 },      // Documented: 10/min
  hudson_rock:      { maxRequests: 5,  windowMs: 60_000 },      // Free API
  leakcheck:        { maxRequests: 5,  windowMs: 60_000 },      // Commercial API
  darkweb_crossref: { maxRequests: 20, windowMs: 60_000 },      // Local DB, generous
};

/** Global rate limit across all connectors */
const GLOBAL_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 100,
  windowMs: 60_000,
  burstAllowance: 20,
};

class TokenBucket {
  private state: BucketState;
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig) {
    this.config = config;
    this.state = {
      tokens: config.maxRequests + (config.burstAllowance ?? Math.floor(config.maxRequests * 0.2)),
      lastRefill: Date.now(),
      backoffUntil: 0,
      backoffLevel: 0,
      totalRequests: 0,
      totalThrottled: 0,
      total429s: 0,
    };
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.state.lastRefill;
    const maxTokens = this.config.maxRequests + (this.config.burstAllowance ?? Math.floor(this.config.maxRequests * 0.2));
    const tokensToAdd = Math.floor((elapsed / this.config.windowMs) * this.config.maxRequests);
    
    if (tokensToAdd > 0) {
      this.state.tokens = Math.min(maxTokens, this.state.tokens + tokensToAdd);
      this.state.lastRefill = now;
    }
  }

  /**
   * Try to consume a token. Returns true if allowed, false if throttled.
   */
  tryConsume(): boolean {
    const now = Date.now();

    // Check backoff
    if (now < this.state.backoffUntil) {
      this.state.totalThrottled++;
      return false;
    }

    this.refill();

    if (this.state.tokens >= 1) {
      this.state.tokens -= 1;
      this.state.totalRequests++;
      // Decay backoff on successful request
      if (this.state.backoffLevel > 0) {
        this.state.backoffLevel = Math.max(0, this.state.backoffLevel - 1);
      }
      return true;
    }

    this.state.totalThrottled++;
    return false;
  }

  /**
   * Report a 429 response to trigger exponential backoff
   */
  report429(): void {
    this.state.total429s++;
    this.state.backoffLevel++;
    const multiplier = this.config.backoffMultiplier ?? 2.0;
    const maxBackoff = this.config.maxBackoffMs ?? 60_000;
    const backoffMs = Math.min(maxBackoff, 1000 * Math.pow(multiplier, this.state.backoffLevel));
    this.state.backoffUntil = Date.now() + backoffMs;
  }

  /**
   * Get time until next available token (ms), 0 if available now
   */
  getWaitTime(): number {
    const now = Date.now();
    if (now < this.state.backoffUntil) {
      return this.state.backoffUntil - now;
    }
    this.refill();
    if (this.state.tokens >= 1) return 0;
    // Calculate time until next refill
    return Math.ceil(this.config.windowMs / this.config.maxRequests);
  }

  getStats(): { totalRequests: number; totalThrottled: number; total429s: number; tokensRemaining: number; backoffLevel: number } {
    this.refill();
    return {
      totalRequests: this.state.totalRequests,
      totalThrottled: this.state.totalThrottled,
      total429s: this.state.total429s,
      tokensRemaining: Math.floor(this.state.tokens),
      backoffLevel: this.state.backoffLevel,
    };
  }
}

/**
 * Unified OSINT Rate Limiter
 * 
 * Singleton that manages per-connector and global rate limits.
 */
class OsintRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  private globalBucket: TokenBucket;

  constructor() {
    this.globalBucket = new TokenBucket(GLOBAL_RATE_LIMIT);
  }

  private getBucket(connector: string): TokenBucket {
    if (!this.buckets.has(connector)) {
      const config = CONNECTOR_RATE_LIMITS[connector] || { maxRequests: 10, windowMs: 60_000 };
      this.buckets.set(connector, new TokenBucket(config));
    }
    return this.buckets.get(connector)!;
  }

  /**
   * Check if a request is allowed for the given connector.
   * Checks both per-connector and global limits.
   */
  tryAcquire(connector: string): boolean {
    const bucket = this.getBucket(connector);
    if (!bucket.tryConsume()) return false;
    if (!this.globalBucket.tryConsume()) return false;
    return true;
  }

  /**
   * Wait until a request is allowed, then return.
   * Use this for queue-based scheduling.
   */
  async waitAndAcquire(connector: string, maxWaitMs: number = 30_000): Promise<boolean> {
    const deadline = Date.now() + maxWaitMs;
    
    while (Date.now() < deadline) {
      if (this.tryAcquire(connector)) return true;
      
      const bucket = this.getBucket(connector);
      const waitTime = Math.min(bucket.getWaitTime(), this.globalBucket.getWaitTime(), 1000);
      await new Promise(resolve => setTimeout(resolve, Math.max(100, waitTime)));
    }

    return false; // Timed out
  }

  /**
   * Report a 429 response for a connector
   */
  report429(connector: string): void {
    this.getBucket(connector).report429();
  }

  /**
   * Get rate limit status for all active connectors
   */
  getStatus(): Record<string, ReturnType<TokenBucket["getStats"]>> {
    const status: Record<string, ReturnType<TokenBucket["getStats"]>> = {};
    status["__global__"] = this.globalBucket.getStats();
    for (const [name, bucket] of this.buckets) {
      status[name] = bucket.getStats();
    }
    return status;
  }

  /**
   * Get rate limit status for a specific connector
   */
  getConnectorStatus(connector: string): ReturnType<TokenBucket["getStats"]> | null {
    const bucket = this.buckets.get(connector);
    return bucket?.getStats() ?? null;
  }

  /**
   * Reset all rate limit state (useful for testing)
   */
  reset(): void {
    this.buckets.clear();
    this.globalBucket = new TokenBucket(GLOBAL_RATE_LIMIT);
  }
}

// Singleton instance
export const osintRateLimiter = new OsintRateLimiter();

/**
 * Rate-limited fetch wrapper for OSINT connectors.
 * 
 * Usage:
 * ```ts
 * const resp = await rateLimitedFetch("shodan", "https://api.shodan.io/...", { ... });
 * ```
 */
export async function rateLimitedFetch(
  connector: string,
  url: string,
  init?: RequestInit,
  options?: { maxWaitMs?: number }
): Promise<Response> {
  const acquired = await osintRateLimiter.waitAndAcquire(connector, options?.maxWaitMs ?? 30_000);
  if (!acquired) {
    throw new Error(`Rate limit exceeded for ${connector} — could not acquire token within timeout`);
  }

  const resp = await fetch(url, init);

  if (resp.status === 429) {
    osintRateLimiter.report429(connector);
    throw new Error(`429 Too Many Requests from ${connector} — backoff activated`);
  }

  return resp;
}
