/**
 * Rate Limiting & Stealth Controls (Gap 7)
 * ══════════════════════════════════════════
 * Controls the timing, fingerprint, and traffic profile of exploit execution
 * to avoid detection by IDS/IPS, WAF, and SOC monitoring.
 *
 * Capabilities:
 *   - Timing profiles (aggressive, normal, stealth, paranoid)
 *   - User-Agent rotation from realistic browser pools
 *   - Header randomization (Accept, Accept-Language, Accept-Encoding)
 *   - Request jitter (random delays between requests)
 *   - TLS fingerprint variation
 *   - Proxy chain support (SOCKS5, HTTP, Tor)
 *   - Source IP rotation
 *   - Request rate limiting per target
 *   - Traffic pattern obfuscation (mix exploit traffic with benign)
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export type TimingProfile = 'aggressive' | 'normal' | 'stealth' | 'paranoid';

export interface StealthConfig {
  /** Timing profile */
  profile: TimingProfile;
  /** Enable User-Agent rotation */
  rotateUserAgent: boolean;
  /** Enable header randomization */
  randomizeHeaders: boolean;
  /** Enable request jitter */
  enableJitter: boolean;
  /** Jitter range in ms [min, max] */
  jitterRangeMs: [number, number];
  /** Max requests per second to a single target */
  maxRps: number;
  /** Enable proxy chain */
  enableProxy: boolean;
  /** Proxy list (SOCKS5/HTTP URLs) */
  proxies: string[];
  /** Rotate proxy after N requests */
  proxyRotateAfter: number;
  /** Enable traffic mixing (benign requests between exploit requests) */
  enableTrafficMixing: boolean;
  /** Ratio of benign to exploit requests (e.g., 3 = 3 benign per 1 exploit) */
  benignRatio: number;
  /** Custom headers to always include */
  customHeaders: Record<string, string>;
  /** Enable TLS fingerprint randomization */
  randomizeTls: boolean;
}

export interface StealthRequestOptions {
  /** Target URL */
  url: string;
  /** HTTP method */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  /** Request headers (will be merged with stealth headers) */
  headers?: Record<string, string>;
  /** Request body */
  body?: string;
  /** Content type */
  contentType?: string;
  /** Timeout in ms */
  timeoutMs?: number;
}

export interface StealthRequestResult {
  /** HTTP status code */
  statusCode: number;
  /** Response headers */
  headers: Record<string, string>;
  /** Response body */
  body: string;
  /** Actual delay applied before this request */
  delayMs: number;
  /** User-Agent used */
  userAgent: string;
  /** Proxy used (if any) */
  proxy?: string;
  /** Request duration in ms */
  durationMs: number;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — TIMING PROFILES
// ═══════════════════════════════════════════════════════════════════════

const TIMING_PROFILES: Record<TimingProfile, {
  maxRps: number;
  jitterRangeMs: [number, number];
  benignRatio: number;
  description: string;
}> = {
  aggressive: {
    maxRps: 50,
    jitterRangeMs: [10, 100],
    benignRatio: 0,
    description: 'Maximum speed, no stealth. Use only in authorized lab environments.',
  },
  normal: {
    maxRps: 10,
    jitterRangeMs: [100, 500],
    benignRatio: 1,
    description: 'Balanced speed and stealth. Suitable for most engagements.',
  },
  stealth: {
    maxRps: 2,
    jitterRangeMs: [500, 3000],
    benignRatio: 3,
    description: 'Low and slow. Mimics human browsing patterns.',
  },
  paranoid: {
    maxRps: 0.2,
    jitterRangeMs: [3000, 15000],
    benignRatio: 5,
    description: 'Extremely slow. Designed to evade advanced SOC monitoring.',
  },
};

export function getTimingProfile(profile: TimingProfile) {
  return TIMING_PROFILES[profile];
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — USER-AGENT POOLS
// ═══════════════════════════════════════════════════════════════════════

const USER_AGENTS = {
  chrome_windows: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  ],
  chrome_mac: [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  ],
  firefox_windows: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
  ],
  firefox_linux: [
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
  ],
  safari_mac: [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
  ],
  edge_windows: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
  ],
  // Pentest tool UAs (for when stealth isn't needed)
  tools: [
    'sqlmap/1.7.12#stable (https://sqlmap.org)',
    'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
    'Mozilla/5.0 (compatible; Naabu Scanner; https://github.com/projectdiscovery/naabu)',
    'Wfuzz/3.1.0',
  ],
};

const ALL_BROWSER_UAS = [
  ...USER_AGENTS.chrome_windows,
  ...USER_AGENTS.chrome_mac,
  ...USER_AGENTS.firefox_windows,
  ...USER_AGENTS.firefox_linux,
  ...USER_AGENTS.safari_mac,
  ...USER_AGENTS.edge_windows,
];

function getRandomUserAgent(): string {
  return ALL_BROWSER_UAS[Math.floor(Math.random() * ALL_BROWSER_UAS.length)];
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — HEADER RANDOMIZATION
// ═══════════════════════════════════════════════════════════════════════

const ACCEPT_HEADERS = [
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'application/json, text/plain, */*',
];

const ACCEPT_LANGUAGE_HEADERS = [
  'en-US,en;q=0.9',
  'en-US,en;q=0.5',
  'en-GB,en;q=0.9,en-US;q=0.8',
  'en-US,en;q=0.9,es;q=0.8',
  'en,en-US;q=0.9',
];

const ACCEPT_ENCODING_HEADERS = [
  'gzip, deflate, br',
  'gzip, deflate',
  'gzip, deflate, br, zstd',
];

const SEC_FETCH_MODES = ['navigate', 'cors', 'no-cors', 'same-origin'];
const SEC_FETCH_SITES = ['none', 'same-origin', 'same-site', 'cross-site'];
const SEC_FETCH_DESTS = ['document', 'empty', 'script', 'style', 'image'];

function randomElement<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateStealthHeaders(ua: string): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': ua,
    'Accept': randomElement(ACCEPT_HEADERS),
    'Accept-Language': randomElement(ACCEPT_LANGUAGE_HEADERS),
    'Accept-Encoding': randomElement(ACCEPT_ENCODING_HEADERS),
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
  };

  // Add Sec-Fetch-* headers (modern browsers)
  if (ua.includes('Chrome') || ua.includes('Firefox') || ua.includes('Edg')) {
    headers['Sec-Fetch-Mode'] = randomElement(SEC_FETCH_MODES);
    headers['Sec-Fetch-Site'] = randomElement(SEC_FETCH_SITES);
    headers['Sec-Fetch-Dest'] = randomElement(SEC_FETCH_DESTS);
    headers['Sec-Ch-Ua-Platform'] = ua.includes('Windows') ? '"Windows"' : ua.includes('Mac') ? '"macOS"' : '"Linux"';
  }

  // Randomly add cache headers
  if (Math.random() > 0.5) {
    headers['Cache-Control'] = randomElement(['no-cache', 'max-age=0']);
  }

  // Randomly add DNT
  if (Math.random() > 0.7) {
    headers['DNT'] = '1';
  }

  return headers;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — RATE LIMITER
// ═══════════════════════════════════════════════════════════════════════

class RateLimiter {
  private timestamps: Map<string, number[]> = new Map();

  async waitForSlot(target: string, maxRps: number): Promise<number> {
    if (maxRps <= 0) return 0;

    const now = Date.now();
    const windowMs = 1000;
    const key = new URL(target).hostname;

    let times = this.timestamps.get(key) || [];
    // Remove timestamps outside the window
    times = times.filter(t => now - t < windowMs);

    if (times.length >= maxRps) {
      const oldestInWindow = times[0];
      const waitMs = windowMs - (now - oldestInWindow) + 10;
      if (waitMs > 0) {
        await new Promise(r => setTimeout(r, waitMs));
      }
      // Clean again after waiting
      const afterWait = Date.now();
      times = times.filter(t => afterWait - t < windowMs);
    }

    times.push(Date.now());
    this.timestamps.set(key, times);
    return Date.now() - now;
  }

  reset(target?: string) {
    if (target) {
      const key = new URL(target).hostname;
      this.timestamps.delete(key);
    } else {
      this.timestamps.clear();
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — PROXY MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

class ProxyRotator {
  private proxies: string[];
  private currentIndex: number = 0;
  private requestCount: number = 0;
  private rotateAfter: number;

  constructor(proxies: string[], rotateAfter: number = 10) {
    this.proxies = proxies;
    this.rotateAfter = rotateAfter;
  }

  getProxy(): string | undefined {
    if (this.proxies.length === 0) return undefined;

    this.requestCount++;
    if (this.requestCount >= this.rotateAfter) {
      this.requestCount = 0;
      this.currentIndex = (this.currentIndex + 1) % this.proxies.length;
    }

    return this.proxies[this.currentIndex];
  }

  addProxy(proxy: string) {
    if (!this.proxies.includes(proxy)) {
      this.proxies.push(proxy);
    }
  }

  removeProxy(proxy: string) {
    this.proxies = this.proxies.filter(p => p !== proxy);
  }

  getProxyCount(): number {
    return this.proxies.length;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — BENIGN TRAFFIC GENERATOR
// ═══════════════════════════════════════════════════════════════════════

const BENIGN_PATHS = [
  '/', '/about', '/contact', '/robots.txt', '/sitemap.xml',
  '/favicon.ico', '/css/style.css', '/js/main.js',
  '/images/logo.png', '/api/health', '/login', '/register',
  '/terms', '/privacy', '/help', '/faq',
];

function generateBenignUrl(baseUrl: string): string {
  const path = randomElement(BENIGN_PATHS);
  try {
    const url = new URL(baseUrl);
    url.pathname = path;
    return url.toString();
  } catch {
    return `${baseUrl}${path}`;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — STEALTH REQUEST EXECUTOR
// ═══════════════════════════════════════════════════════════════════════

const DEFAULT_STEALTH_CONFIG: StealthConfig = {
  profile: 'normal',
  rotateUserAgent: true,
  randomizeHeaders: true,
  enableJitter: true,
  jitterRangeMs: [100, 500],
  maxRps: 10,
  enableProxy: false,
  proxies: [],
  proxyRotateAfter: 10,
  enableTrafficMixing: false,
  benignRatio: 1,
  customHeaders: {},
  randomizeTls: false,
};

/**
 * Create a stealth-aware request executor.
 */
export function createStealthExecutor(config: Partial<StealthConfig> = {}) {
  const cfg = { ...DEFAULT_STEALTH_CONFIG, ...config };

  // Apply timing profile defaults
  const profileDefaults = TIMING_PROFILES[cfg.profile];
  if (!config.maxRps) cfg.maxRps = profileDefaults.maxRps;
  if (!config.jitterRangeMs) cfg.jitterRangeMs = profileDefaults.jitterRangeMs;
  if (!config.benignRatio) cfg.benignRatio = profileDefaults.benignRatio;

  const rateLimiter = new RateLimiter();
  const proxyRotator = new ProxyRotator(cfg.proxies, cfg.proxyRotateAfter);

  /**
   * Execute a single request with stealth controls applied.
   */
  async function execute(options: StealthRequestOptions): Promise<StealthRequestResult> {
    const startTime = Date.now();
    let totalDelay = 0;

    // Apply jitter
    if (cfg.enableJitter) {
      const [min, max] = cfg.jitterRangeMs;
      const jitter = min + Math.random() * (max - min);
      await new Promise(r => setTimeout(r, jitter));
      totalDelay += jitter;
    }

    // Rate limiting
    const rateDelay = await rateLimiter.waitForSlot(options.url, cfg.maxRps);
    totalDelay += rateDelay;

    // Send benign traffic if mixing enabled
    if (cfg.enableTrafficMixing && cfg.benignRatio > 0) {
      for (let i = 0; i < cfg.benignRatio; i++) {
        const benignUrl = generateBenignUrl(options.url);
        const ua = cfg.rotateUserAgent ? getRandomUserAgent() : ALL_BROWSER_UAS[0];
        const benignHeaders = cfg.randomizeHeaders ? generateStealthHeaders(ua) : { 'User-Agent': ua };

        try {
          await makeCurlRequest({
            url: benignUrl,
            method: 'GET',
            headers: benignHeaders,
            timeoutMs: 5000,
          }, proxyRotator.getProxy());
        } catch { /* benign requests can fail silently */ }

        // Small delay between benign requests
        const benignDelay = 50 + Math.random() * 200;
        await new Promise(r => setTimeout(r, benignDelay));
        totalDelay += benignDelay;
      }
    }

    // Build stealth headers
    const ua = cfg.rotateUserAgent ? getRandomUserAgent() : ALL_BROWSER_UAS[0];
    const stealthHeaders = cfg.randomizeHeaders ? generateStealthHeaders(ua) : { 'User-Agent': ua };
    const finalHeaders = {
      ...stealthHeaders,
      ...cfg.customHeaders,
      ...options.headers,
    };

    if (options.contentType) {
      finalHeaders['Content-Type'] = options.contentType;
    }

    // Execute the actual request
    const proxy = cfg.enableProxy ? proxyRotator.getProxy() : undefined;
    const result = await makeCurlRequest({
      ...options,
      headers: finalHeaders,
      timeoutMs: options.timeoutMs || 30000,
    }, proxy);

    return {
      ...result,
      delayMs: totalDelay,
      userAgent: ua,
      proxy,
    };
  }

  /**
   * Execute multiple requests with stealth controls.
   */
  async function executeBatch(
    requests: StealthRequestOptions[],
  ): Promise<StealthRequestResult[]> {
    const results: StealthRequestResult[] = [];
    for (const req of requests) {
      results.push(await execute(req));
    }
    return results;
  }

  return {
    execute,
    executeBatch,
    config: cfg,
    addProxy: (proxy: string) => proxyRotator.addProxy(proxy),
    removeProxy: (proxy: string) => proxyRotator.removeProxy(proxy),
    resetRateLimit: (target?: string) => rateLimiter.reset(target),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — CURL-BASED HTTP CLIENT
// ═══════════════════════════════════════════════════════════════════════

import { executeRawCommand } from './scan-server-executor';

async function makeCurlRequest(
  options: StealthRequestOptions & { headers: Record<string, string> },
  proxy?: string,
): Promise<Omit<StealthRequestResult, 'delayMs' | 'userAgent' | 'proxy'>> {
  const startTime = Date.now();

  // Build curl command
  const parts: string[] = ['curl', '-s', '-S', '-i'];

  // Method
  parts.push('-X', options.method);

  // Headers
  for (const [key, value] of Object.entries(options.headers)) {
    parts.push('-H', `"${key}: ${value}"`);
  }

  // Body
  if (options.body) {
    parts.push('-d', `'${options.body.replace(/'/g, "'\\''")}'`);
  }

  // Timeout
  const timeoutSec = Math.ceil((options.timeoutMs || 30000) / 1000);
  parts.push('--connect-timeout', '10', '--max-time', String(timeoutSec));

  // Proxy
  if (proxy) {
    parts.push('--proxy', proxy);
  }

  // Follow redirects (limited)
  parts.push('-L', '--max-redirs', '3');

  // URL (must be last)
  parts.push(`"${options.url}"`);

  const cmd = parts.join(' ');

  try {
    const result = await executeRawCommand(cmd, timeoutSec + 5);
    const durationMs = Date.now() - startTime;

    // Parse response
    const { statusCode, headers, body } = parseCurlResponse(result.stdout);

    return { statusCode, headers, body, durationMs };
  } catch (err: any) {
    return {
      statusCode: 0,
      headers: {},
      body: `Error: ${err.message}`,
      durationMs: Date.now() - startTime,
    };
  }
}

function parseCurlResponse(raw: string): {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
} {
  // Split headers and body at the double newline
  const headerEnd = raw.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    // Try Unix-style newlines
    const unixEnd = raw.indexOf('\n\n');
    if (unixEnd === -1) {
      return { statusCode: 0, headers: {}, body: raw };
    }
    return parseHeadersAndBody(raw, unixEnd, '\n\n');
  }
  return parseHeadersAndBody(raw, headerEnd, '\r\n\r\n');
}

function parseHeadersAndBody(raw: string, splitIndex: number, separator: string) {
  const headerSection = raw.slice(0, splitIndex);
  const body = raw.slice(splitIndex + separator.length);

  const headerLines = headerSection.split(/\r?\n/);
  let statusCode = 0;
  const headers: Record<string, string> = {};

  for (const line of headerLines) {
    if (line.startsWith('HTTP/')) {
      const match = line.match(/HTTP\/[\d.]+ (\d+)/);
      if (match) statusCode = parseInt(match[1]);
    } else {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.slice(0, colonIndex).trim().toLowerCase();
        const value = line.slice(colonIndex + 1).trim();
        headers[key] = value;
      }
    }
  }

  return { statusCode, headers, body };
}

// ═══════════════════════════════════════════════════════════════════════
// §10 — GENERATE CURL COMMAND FOR LLM PROMPTS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate stealth-aware curl command strings for injection into LLM exploit prompts.
 * This allows LLM-generated exploits to inherit stealth settings.
 */
export function generateStealthCurlTemplate(
  config: Partial<StealthConfig> = {},
): string {
  const cfg = { ...DEFAULT_STEALTH_CONFIG, ...config };
  const ua = getRandomUserAgent();
  const headers = generateStealthHeaders(ua);

  const headerFlags = Object.entries(headers)
    .map(([k, v]) => `-H "${k}: ${v}"`)
    .join(' \\\n  ');

  const proxyFlag = cfg.enableProxy && cfg.proxies.length > 0
    ? `--proxy "${cfg.proxies[0]}" `
    : '';

  return `# Stealth curl template (profile: ${cfg.profile})
# Apply these flags to all HTTP requests in the exploit:
STEALTH_CURL="curl -s -S ${proxyFlag}\\
  ${headerFlags} \\
  --connect-timeout 10 --max-time 30 -L --max-redirs 3"

# Usage: $STEALTH_CURL -X GET "http://target/path"
# Usage: $STEALTH_CURL -X POST -d 'payload' "http://target/path"
`;
}

/**
 * Generate Python requests session setup for LLM exploit prompts.
 */
export function generateStealthPythonTemplate(
  config: Partial<StealthConfig> = {},
): string {
  const cfg = { ...DEFAULT_STEALTH_CONFIG, ...config };
  const ua = getRandomUserAgent();
  const headers = generateStealthHeaders(ua);

  const proxyDict = cfg.enableProxy && cfg.proxies.length > 0
    ? `proxies = {"http": "${cfg.proxies[0]}", "https": "${cfg.proxies[0]}"}`
    : 'proxies = None';

  const [minJitter, maxJitter] = cfg.jitterRangeMs;

  return `# Stealth requests session (profile: ${cfg.profile})
import requests, time, random

session = requests.Session()
session.headers.update(${JSON.stringify(headers, null, 2)})
${proxyDict}
if proxies:
    session.proxies.update(proxies)
session.verify = True
session.max_redirects = 3

def stealth_request(method, url, **kwargs):
    """Make a request with jitter delay"""
    time.sleep(random.uniform(${minJitter / 1000}, ${maxJitter / 1000}))
    kwargs.setdefault('timeout', 30)
    return session.request(method, url, **kwargs)

# Usage: resp = stealth_request("GET", "http://target/path")
# Usage: resp = stealth_request("POST", "http://target/path", data="payload")
`;
}


// ── Factory wrapper used by scanforge-enhanced-pipeline ──────────────

export interface StealthDecision {
  shouldDelay: boolean;
  delayMs: number;
  profile: TimingProfile;
  reason: string;
}

export interface StealthController {
  evaluate(targetHost: string, vulnClass: string): StealthDecision;
  config: StealthConfig;
}

/**
 * Create a StealthController instance with the given config.
 */
export function createStealthController(config: Partial<StealthConfig> = {}): StealthController {
  const profile = config.profile || 'normal';
  const timing = getTimingProfile(profile);
  const fullConfig: StealthConfig = {
    profile,
    maxRps: config.maxRps || timing.maxRps,
    jitterRangeMs: config.jitterRangeMs || timing.jitterRangeMs,
    rotateUserAgent: config.rotateUserAgent ?? true,
    benignRatio: config.benignRatio || timing.benignRatio,
    proxies: config.proxies || [],
    proxyRotateAfter: config.proxyRotateAfter || 5,
    respectRobotsTxt: config.respectRobotsTxt ?? false,
    maxConcurrent: config.maxConcurrent || 1,
  };

  return {
    config: fullConfig,
    evaluate(targetHost: string, vulnClass: string): StealthDecision {
      const [minJitter, maxJitter] = fullConfig.jitterRangeMs;
      const delayMs = Math.floor(Math.random() * (maxJitter - minJitter) + minJitter);

      const shouldDelay = profile !== 'aggressive';

      return {
        shouldDelay,
        delayMs: shouldDelay ? delayMs : 0,
        profile,
        reason: shouldDelay
          ? `Stealth profile '${profile}': applying ${delayMs}ms jitter for ${vulnClass} against ${targetHost}`
          : `Aggressive profile: no delay for ${vulnClass}`,
      };
    },
  };
}
