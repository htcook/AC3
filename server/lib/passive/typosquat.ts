/**
 * Typosquat Domain Generator — Free, No API Key
 * 
 * Generates potential typosquatting/lookalike domains for a target domain
 * and checks which ones are actually registered (via DNS resolution).
 * Useful for phishing campaign planning when phishing is in-scope.
 * 
 * Techniques: character swap, missing char, double char, homoglyph,
 * wrong TLD, hyphenation, subdomain prefix, bitsquatting.
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// ── Typosquat Generation Algorithms ──────────────────────────────────

const HOMOGLYPHS: Record<string, string[]> = {
  a: ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а'],  // last is Cyrillic а
  c: ['ç', 'ć', 'с'],  // last is Cyrillic с
  d: ['ɗ', 'đ'],
  e: ['è', 'é', 'ê', 'ë', 'ē', 'е'],  // last is Cyrillic е
  g: ['ğ', 'ġ'],
  h: ['һ'],  // Cyrillic
  i: ['ì', 'í', 'î', 'ï', 'ı', 'і'],  // last is Cyrillic і
  k: ['κ', 'к'],  // Greek kappa, Cyrillic к
  l: ['ĺ', 'ļ', 'ℓ', '1'],
  m: ['м'],
  n: ['ñ', 'ń', 'ŋ'],
  o: ['ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'о', '0'],  // Cyrillic о, zero
  p: ['р'],  // Cyrillic р
  r: ['ŕ', 'ř'],
  s: ['ś', 'ş', 'ș', 'ѕ'],  // last is Cyrillic ѕ
  t: ['ţ', 'ț'],
  u: ['ù', 'ú', 'û', 'ü', 'ū'],
  w: ['ẃ', 'ẁ', 'ŵ'],
  x: ['х'],  // Cyrillic х
  y: ['ý', 'ÿ', 'у'],  // last is Cyrillic у
  z: ['ź', 'ż', 'ž'],
};

const COMMON_TLDS = ['com', 'net', 'org', 'io', 'co', 'info', 'biz', 'us', 'xyz', 'app', 'dev', 'tech', 'online', 'site', 'cloud'];

const QWERTY_NEIGHBORS: Record<string, string[]> = {
  q: ['w', 'a'], w: ['q', 'e', 's', 'a'], e: ['w', 'r', 'd', 's'],
  r: ['e', 't', 'f', 'd'], t: ['r', 'y', 'g', 'f'], y: ['t', 'u', 'h', 'g'],
  u: ['y', 'i', 'j', 'h'], i: ['u', 'o', 'k', 'j'], o: ['i', 'p', 'l', 'k'],
  p: ['o', 'l'], a: ['q', 'w', 's', 'z'], s: ['a', 'w', 'e', 'd', 'z', 'x'],
  d: ['s', 'e', 'r', 'f', 'x', 'c'], f: ['d', 'r', 't', 'g', 'c', 'v'],
  g: ['f', 't', 'y', 'h', 'v', 'b'], h: ['g', 'y', 'u', 'j', 'b', 'n'],
  j: ['h', 'u', 'i', 'k', 'n', 'm'], k: ['j', 'i', 'o', 'l', 'm'],
  l: ['k', 'o', 'p'], z: ['a', 's', 'x'], x: ['z', 's', 'd', 'c'],
  c: ['x', 'd', 'f', 'v'], v: ['c', 'f', 'g', 'b'], b: ['v', 'g', 'h', 'n'],
  n: ['b', 'h', 'j', 'm'], m: ['n', 'j', 'k'],
};

function generateTyposquats(domain: string): string[] {
  const parts = domain.split('.');
  if (parts.length < 2) return [];
  const name = parts.slice(0, -1).join('.');
  const tld = parts[parts.length - 1];
  const candidates = new Set<string>();

  // 1. Character omission: remove one char at a time
  for (let i = 0; i < name.length; i++) {
    if (name[i] === '.') continue;
    const variant = name.slice(0, i) + name.slice(i + 1);
    if (variant.length > 0) candidates.add(`${variant}.${tld}`);
  }

  // 2. Character swap (adjacent transposition)
  for (let i = 0; i < name.length - 1; i++) {
    if (name[i] === '.' || name[i + 1] === '.') continue;
    const arr = name.split('');
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    candidates.add(`${arr.join('')}.${tld}`);
  }

  // 3. Character duplication
  for (let i = 0; i < name.length; i++) {
    if (name[i] === '.' || name[i] === '-') continue;
    const variant = name.slice(0, i) + name[i] + name.slice(i);
    candidates.add(`${variant}.${tld}`);
  }

  // 4. QWERTY neighbor replacement (fat-finger typos)
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase();
    const neighbors = QWERTY_NEIGHBORS[ch];
    if (!neighbors) continue;
    for (const n of neighbors.slice(0, 2)) { // limit to 2 neighbors per char
      const variant = name.slice(0, i) + n + name.slice(i + 1);
      candidates.add(`${variant}.${tld}`);
    }
  }

  // 5. Homoglyph substitution (IDN-like)
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase();
    const glyphs = HOMOGLYPHS[ch];
    if (!glyphs) continue;
    for (const g of glyphs.slice(0, 2)) { // limit to 2 glyphs per char
      const variant = name.slice(0, i) + g + name.slice(i + 1);
      candidates.add(`${variant}.${tld}`);
    }
  }

  // 6. Wrong TLD
  for (const altTld of COMMON_TLDS) {
    if (altTld !== tld) {
      candidates.add(`${name}.${altTld}`);
    }
  }

  // 7. Hyphenation variants
  for (let i = 1; i < name.length; i++) {
    if (name[i] === '.' || name[i] === '-' || name[i - 1] === '-') continue;
    const variant = name.slice(0, i) + '-' + name.slice(i);
    candidates.add(`${variant}.${tld}`);
  }

  // 8. Subdomain prefix tricks
  const prefixes = ['www', 'login', 'secure', 'mail', 'portal', 'account', 'auth'];
  for (const prefix of prefixes) {
    candidates.add(`${prefix}-${name}.${tld}`);
    candidates.add(`${prefix}${name}.${tld}`);
  }

  // 9. Character insertion (vowel addition)
  const vowels = ['a', 'e', 'i', 'o', 'u'];
  for (let i = 0; i <= name.length && candidates.size < 500; i++) {
    if (i > 0 && (name[i - 1] === '.' || name[i - 1] === '-')) continue;
    for (const v of vowels) {
      const variant = name.slice(0, i) + v + name.slice(i);
      candidates.add(`${variant}.${tld}`);
      if (candidates.size >= 500) break;
    }
  }

  // Remove the original domain and any empty/invalid entries
  candidates.delete(domain);
  candidates.delete(`.${tld}`);

  return Array.from(candidates).slice(0, 300); // cap at 300 candidates
}

// ── DNS Resolution Check (batch with concurrency limit) ──────────────

async function checkDomainRegistered(domain: string): Promise<{ registered: boolean; ip?: string }> {
  try {
    const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!resp.ok) return { registered: false };
    const data = await resp.json();
    if (data.Answer && data.Answer.length > 0) {
      return { registered: true, ip: data.Answer[0].data };
    }
    return { registered: false };
  } catch {
    return { registered: false };
  }
}

async function batchCheckDomains(
  domains: string[],
  concurrency: number = 20
): Promise<Map<string, { registered: boolean; ip?: string }>> {
  const results = new Map<string, { registered: boolean; ip?: string }>();
  const queue = [...domains];

  async function worker() {
    while (queue.length > 0) {
      const domain = queue.shift()!;
      const result = await checkDomainRegistered(domain);
      results.set(domain, result);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, () => worker());
  await Promise.allSettled(workers);
  return results;
}

// ── Connector Export ─────────────────────────────────────────────────

export const typosquatConnector: PassiveConnector = {
  name: "typosquat",
  description: "Typosquat Domain Generator — identifies registered lookalike domains for phishing assessment",
  requiresApiKey: false,
  freeUrl: "https://dns.google",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const start = Date.now();
    const now = new Date();
    let rateLimited = false;

    try {
      // Generate all typosquat candidates
      const candidates = generateTyposquats(domain);

      // Batch DNS check to find which ones are actually registered
      const dnsResults = await batchCheckDomains(candidates, 15);

      const registeredDomains: { domain: string; ip?: string; technique: string }[] = [];

      for (const [candidate, result] of dnsResults) {
        if (!result.registered) continue;

        // Classify the technique used
        let technique = 'unknown';
        const namePart = candidate.split('.').slice(0, -1).join('.');
        const origName = domain.split('.').slice(0, -1).join('.');
        const origTld = domain.split('.').pop()!;
        const candTld = candidate.split('.').pop()!;

        if (candTld !== origTld) technique = 'wrong-tld';
        else if (namePart.includes('-') && !origName.includes('-')) technique = 'hyphenation';
        else if (namePart.length < origName.length) technique = 'char-omission';
        else if (namePart.length > origName.length) technique = 'char-insertion';
        else technique = 'char-substitution';

        registeredDomains.push({ domain: candidate, ip: result.ip, technique });

        observations.push({
          assetId: makeAssetId(domain, `typosquat:${candidate}`, "typosquat"),
          domain,
          assetType: "subdomain",
          name: `Typosquat: ${candidate}`,
          source: "typosquat",
          observedAt: now,
          tags: ['typosquat', 'phishing', technique],
          evidence: {
            typosquatDomain: candidate,
            resolvedIp: result.ip,
            technique,
            originalDomain: domain,
            severity: 7,
            confidence: 90,
            description: `Registered lookalike domain: ${candidate} (${technique}) resolves to ${result.ip}`,
          },
          attribution: {
            provider: "Typosquat Generator",
            url: "https://dns.google",
            method: `DNS resolution check via Google DNS — ${technique} variant`,
          },
        });
      }

      // Summary observation
      if (registeredDomains.length > 0) {
        const byTechnique: Record<string, number> = {};
        for (const d of registeredDomains) {
          byTechnique[d.technique] = (byTechnique[d.technique] || 0) + 1;
        }

        observations.push({
          assetId: makeAssetId(domain, "typosquat-summary", "typosquat"),
          domain,
          assetType: "breach",
          name: `Typosquat Summary: ${registeredDomains.length} lookalike domains found`,
          source: "typosquat",
          observedAt: now,
          tags: ['typosquat', 'phishing', 'summary'],
          evidence: {
            totalCandidatesGenerated: candidates.length,
            registeredCount: registeredDomains.length,
            byTechnique,
            registeredDomains: registeredDomains.slice(0, 50),
            severity: registeredDomains.length > 10 ? 8 : registeredDomains.length > 3 ? 6 : 4,
            confidence: 95,
            description: `Found ${registeredDomains.length} registered typosquat domains out of ${candidates.length} candidates`,
          },
          attribution: {
            provider: "Typosquat Generator",
            url: "https://dns.google",
            method: `Generated ${candidates.length} candidates, ${registeredDomains.length} registered`,
          },
        });
      }
    } catch (err: any) {
      errors.push(`Typosquat generator error: ${err.message}`);
    }

    return {
      connector: "typosquat",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
