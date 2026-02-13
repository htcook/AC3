/**
 * OSINT Reconnaissance Engine
 * - DNS/MX/SPF/DKIM/DMARC analysis
 * - Subdomain enumeration via crt.sh
 * - Typosquat domain generation (dnstwist-style algorithms)
 * - Email spoofability scoring
 */
import dns from "dns";
import { promisify } from "util";

const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveNs = promisify(dns.resolveNs);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveCname = promisify(dns.resolveCname);

// ==================== DNS ANALYSIS ====================

export interface DnsAnalysis {
  mxRecords: Array<{ exchange: string; priority: number }>;
  spfRecord: string | null;
  dmarcRecord: string | null;
  dmarcPolicy: string | null;
  dkimFound: boolean;
  nsRecords: string[];
  aRecords: string[];
  aaaaRecords: string[];
}

async function safeDnsResolve<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

export async function analyzeDns(domain: string): Promise<DnsAnalysis> {
  const [mx, ns, a, aaaa] = await Promise.all([
    safeDnsResolve(() => resolveMx(domain), []),
    safeDnsResolve(() => resolveNs(domain), []),
    safeDnsResolve(() => resolve4(domain), []),
    safeDnsResolve(() => resolve6(domain), []),
  ]);

  // Get TXT records for SPF
  const txtRecords = await safeDnsResolve(() => resolveTxt(domain), []);
  const spfRecord = txtRecords
    .map((r) => r.join(""))
    .find((r) => r.startsWith("v=spf1")) || null;

  // Get DMARC record
  const dmarcRecords = await safeDnsResolve(() => resolveTxt(`_dmarc.${domain}`), []);
  const dmarcRecord = dmarcRecords
    .map((r) => r.join(""))
    .find((r) => r.startsWith("v=DMARC1")) || null;

  // Extract DMARC policy
  let dmarcPolicy: string | null = null;
  if (dmarcRecord) {
    const policyMatch = dmarcRecord.match(/;\s*p=(\w+)/);
    if (policyMatch) dmarcPolicy = policyMatch[1];
  }

  // Check for DKIM (common selectors)
  const dkimSelectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2"];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    const dkimTxt = await safeDnsResolve(() => resolveTxt(`${sel}._domainkey.${domain}`), []);
    if (dkimTxt.length > 0) {
      dkimFound = true;
      break;
    }
  }

  return {
    mxRecords: mx.map((r) => ({ exchange: r.exchange, priority: r.priority })),
    spfRecord,
    dmarcRecord,
    dmarcPolicy,
    dkimFound,
    nsRecords: ns,
    aRecords: a,
    aaaaRecords: aaaa,
  };
}

// ==================== SPOOFABILITY SCORING ====================

export interface SpoofabilityResult {
  score: number; // 0-100, higher = easier to spoof
  spoofable: boolean;
  factors: Array<{ factor: string; impact: string; detail: string }>;
  recommendation: string; // "spoof" | "buy_lookalike" | "both"
}

export function analyzeSpoofability(dnsData: DnsAnalysis): SpoofabilityResult {
  let score = 0;
  const factors: Array<{ factor: string; impact: string; detail: string }> = [];

  // No SPF record → highly spoofable
  if (!dnsData.spfRecord) {
    score += 35;
    factors.push({
      factor: "No SPF Record",
      impact: "critical",
      detail: "Domain has no SPF record. Any server can send email claiming to be from this domain.",
    });
  } else if (dnsData.spfRecord.includes("~all")) {
    score += 20;
    factors.push({
      factor: "SPF Soft Fail (~all)",
      impact: "high",
      detail: "SPF uses soft fail (~all). Spoofed emails may still be delivered to inbox.",
    });
  } else if (dnsData.spfRecord.includes("?all")) {
    score += 25;
    factors.push({
      factor: "SPF Neutral (?all)",
      impact: "high",
      detail: "SPF uses neutral policy (?all). No enforcement — spoofed emails pass SPF checks.",
    });
  } else if (dnsData.spfRecord.includes("-all")) {
    score += 5;
    factors.push({
      factor: "SPF Hard Fail (-all)",
      impact: "low",
      detail: "SPF uses hard fail (-all). Spoofed emails should be rejected, but not all servers enforce.",
    });
  }

  // No DMARC → spoofable
  if (!dnsData.dmarcRecord) {
    score += 30;
    factors.push({
      factor: "No DMARC Record",
      impact: "critical",
      detail: "No DMARC policy. Receiving servers have no guidance on handling spoofed emails.",
    });
  } else if (dnsData.dmarcPolicy === "none") {
    score += 25;
    factors.push({
      factor: "DMARC Policy: none",
      impact: "high",
      detail: "DMARC policy is set to 'none' — monitoring only, no enforcement. Spoofed emails are delivered.",
    });
  } else if (dnsData.dmarcPolicy === "quarantine") {
    score += 10;
    factors.push({
      factor: "DMARC Policy: quarantine",
      impact: "medium",
      detail: "DMARC quarantines failed emails. Some may still reach spam folder.",
    });
  } else if (dnsData.dmarcPolicy === "reject") {
    score += 0;
    factors.push({
      factor: "DMARC Policy: reject",
      impact: "low",
      detail: "DMARC rejects failed emails. Spoofing this domain is difficult.",
    });
  }

  // No DKIM
  if (!dnsData.dkimFound) {
    score += 15;
    factors.push({
      factor: "No DKIM Detected",
      impact: "medium",
      detail: "No DKIM signing detected on common selectors. Email authenticity cannot be verified.",
    });
  } else {
    score += 0;
    factors.push({
      factor: "DKIM Present",
      impact: "low",
      detail: "DKIM signing detected. Adds a layer of email authentication.",
    });
  }

  // No MX records → domain doesn't receive email, easier to impersonate
  if (dnsData.mxRecords.length === 0) {
    score += 10;
    factors.push({
      factor: "No MX Records",
      impact: "medium",
      detail: "Domain has no MX records. May not actively monitor email, making spoofing less likely to be detected.",
    });
  }

  // Cap at 100
  score = Math.min(score, 100);

  const spoofable = score >= 40;
  let recommendation: string;
  if (score >= 60) {
    recommendation = "spoof";
  } else if (score >= 30) {
    recommendation = "both";
  } else {
    recommendation = "buy_lookalike";
  }

  return { score, spoofable, factors, recommendation };
}

// ==================== SUBDOMAIN ENUMERATION (crt.sh) ====================

export async function enumerateSubdomains(domain: string): Promise<string[]> {
  try {
    const response = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(15000) }
    );
    if (!response.ok) return [];
    const data = await response.json() as Array<{ name_value: string }>;

    const subdomains = new Set<string>();
    for (const entry of data) {
      const names = entry.name_value.split("\n");
      for (const name of names) {
        const cleaned = name.trim().toLowerCase();
        if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
          subdomains.add(cleaned);
        }
      }
    }
    return Array.from(subdomains).sort();
  } catch {
    return [];
  }
}

// ==================== TYPOSQUAT DOMAIN GENERATION ====================

const KEYBOARD_NEIGHBORS: Record<string, string> = {
  q: "wa", w: "qeas", e: "wrds", r: "etfs", t: "rygs",
  y: "tuhs", u: "yijs", i: "uoks", o: "ipls", p: "o",
  a: "qwsz", s: "weadxz", d: "ersfxc", f: "rtdgcv",
  g: "tyfhvb", h: "uygjbn", j: "iohknm", k: "opjlm",
  l: "pk", z: "asx", x: "zsdc", c: "xdfv", v: "cfgb",
  b: "vghn", n: "bhjm", m: "njk",
};

const HOMOGLYPHS: Record<string, string[]> = {
  a: ["à", "á", "â", "ã", "ä", "å", "ɑ", "а", "ạ", "ą"],
  b: ["d", "ḃ", "ɓ", "ь", "ƀ"],
  c: ["ç", "ć", "ĉ", "ċ", "с"],
  d: ["b", "ḋ", "ɗ", "ď", "đ"],
  e: ["è", "é", "ê", "ë", "ē", "ĕ", "ė", "ę", "е"],
  f: ["ƒ"],
  g: ["ğ", "ġ", "ģ", "ɡ"],
  h: ["ĥ", "ħ", "ḥ"],
  i: ["ì", "í", "î", "ï", "ı", "ĩ", "ī", "ĭ", "і", "1", "l"],
  j: ["ĵ"],
  k: ["ķ", "ĸ", "κ"],
  l: ["ĺ", "ļ", "ľ", "ŀ", "ł", "1", "i"],
  m: ["ṁ", "ɱ", "rn"],
  n: ["ñ", "ń", "ņ", "ň", "ŋ", "п"],
  o: ["ò", "ó", "ô", "õ", "ö", "ø", "ō", "ŏ", "ő", "о", "0"],
  p: ["ṗ", "р"],
  q: ["ɋ"],
  r: ["ŕ", "ŗ", "ř", "ɍ", "г"],
  s: ["ś", "ŝ", "ş", "š", "ṡ", "ș", "ʂ"],
  t: ["ţ", "ť", "ŧ", "ṫ", "ț"],
  u: ["ù", "ú", "û", "ü", "ũ", "ū", "ŭ", "ů", "ű", "ų"],
  v: ["ṿ", "ν"],
  w: ["ŵ", "ẁ", "ẃ", "ẅ", "ω"],
  x: ["ẋ", "х"],
  y: ["ý", "ÿ", "ŷ", "ẏ", "у"],
  z: ["ź", "ż", "ž", "ẑ"],
};

const VOWELS = "aeiou";

export interface TyposquatCandidate {
  domain: string;
  type: string;
}

function splitDomain(domain: string): { name: string; tld: string } {
  const parts = domain.split(".");
  if (parts.length < 2) return { name: domain, tld: "" };
  // Handle multi-part TLDs like co.uk
  if (parts.length > 2 && parts[parts.length - 2].length <= 3) {
    return {
      name: parts.slice(0, -2).join("."),
      tld: parts.slice(-2).join("."),
    };
  }
  return { name: parts.slice(0, -1).join("."), tld: parts[parts.length - 1] };
}

export function generateTyposquats(domain: string, maxPerType: number = 20): TyposquatCandidate[] {
  const { name, tld } = splitDomain(domain);
  const results: TyposquatCandidate[] = [];
  const seen = new Set<string>();

  function add(d: string, type: string) {
    const full = `${d}.${tld}`;
    if (full !== domain && !seen.has(full)) {
      seen.add(full);
      results.push({ domain: full, type });
    }
  }

  // 1. Character omission (missing-dot for subdomains handled separately)
  for (let i = 0; i < name.length && results.filter(r => r.type === "omission").length < maxPerType; i++) {
    add(name.slice(0, i) + name.slice(i + 1), "omission");
  }

  // 2. Character repetition
  for (let i = 0; i < name.length && results.filter(r => r.type === "repetition").length < maxPerType; i++) {
    if (name[i].match(/[a-z]/)) {
      add(name.slice(0, i) + name[i] + name.slice(i), "repetition");
    }
  }

  // 3. Adjacent character swap (transposition)
  for (let i = 0; i < name.length - 1 && results.filter(r => r.type === "transposition").length < maxPerType; i++) {
    const arr = name.split("");
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    add(arr.join(""), "transposition");
  }

  // 4. Character replacement (keyboard neighbors)
  for (let i = 0; i < name.length; i++) {
    const neighbors = KEYBOARD_NEIGHBORS[name[i]];
    if (neighbors && results.filter(r => r.type === "replacement").length < maxPerType) {
      for (const n of neighbors) {
        add(name.slice(0, i) + n + name.slice(i + 1), "replacement");
      }
    }
  }

  // 5. Character insertion
  for (let i = 0; i <= name.length && results.filter(r => r.type === "insertion").length < maxPerType; i++) {
    for (const c of "abcdefghijklmnopqrstuvwxyz") {
      if (results.filter(r => r.type === "insertion").length >= maxPerType) break;
      add(name.slice(0, i) + c + name.slice(i), "insertion");
    }
  }

  // 6. Bitsquatting (flip single bit in each character)
  for (let i = 0; i < name.length && results.filter(r => r.type === "bitsquatting").length < maxPerType; i++) {
    const code = name.charCodeAt(i);
    for (let bit = 0; bit < 8; bit++) {
      const flipped = code ^ (1 << bit);
      if (flipped >= 48 && flipped <= 122) {
        const c = String.fromCharCode(flipped);
        if (c.match(/[a-z0-9-]/)) {
          add(name.slice(0, i) + c + name.slice(i + 1), "bitsquatting");
        }
      }
    }
  }

  // 7. Homoglyph substitution
  for (let i = 0; i < name.length && results.filter(r => r.type === "homoglyph").length < maxPerType; i++) {
    const glyphs = HOMOGLYPHS[name[i]];
    if (glyphs) {
      for (const g of glyphs.slice(0, 3)) {
        add(name.slice(0, i) + g + name.slice(i + 1), "homoglyph");
      }
    }
  }

  // 8. Vowel swap
  for (let i = 0; i < name.length && results.filter(r => r.type === "vowel_swap").length < maxPerType; i++) {
    if (VOWELS.includes(name[i])) {
      for (const v of VOWELS) {
        if (v !== name[i]) {
          add(name.slice(0, i) + v + name.slice(i + 1), "vowel_swap");
        }
      }
    }
  }

  // 9. Addition (append character)
  for (const c of "abcdefghijklmnopqrstuvwxyz0123456789") {
    if (results.filter(r => r.type === "addition").length >= maxPerType) break;
    add(name + c, "addition");
  }

  // 10. Hyphenation
  for (let i = 1; i < name.length && results.filter(r => r.type === "hyphenation").length < maxPerType; i++) {
    add(name.slice(0, i) + "-" + name.slice(i), "hyphenation");
  }

  // 11. TLD swap
  const commonTlds = ["com", "net", "org", "io", "co", "biz", "info", "xyz", "app", "dev", "us", "me"];
  for (const t of commonTlds) {
    if (t !== tld) {
      const full = `${name}.${t}`;
      if (!seen.has(full)) {
        seen.add(full);
        results.push({ domain: full, type: "tld_swap" });
      }
    }
  }

  // 12. Subdomain insertion (www prefix tricks)
  add(`www${name}`, "subdomain_trick");
  add(`${name}login`, "subdomain_trick");
  add(`${name}secure`, "subdomain_trick");
  add(`${name}mail`, "subdomain_trick");

  return results;
}

// ==================== DNS RESOLUTION CHECK FOR TYPOSQUATS ====================

export async function checkDomainRegistration(domain: string): Promise<{
  resolved: boolean;
  ip: string | null;
  mx: Array<{ exchange: string; priority: number }>;
}> {
  try {
    const ips = await resolve4(domain);
    const mx = await safeDnsResolve(() => resolveMx(domain), []);
    return {
      resolved: true,
      ip: ips[0] || null,
      mx: mx.map((r) => ({ exchange: r.exchange, priority: r.priority })),
    };
  } catch {
    return { resolved: false, ip: null, mx: [] };
  }
}

// ==================== FULL RECON PIPELINE ====================

export interface FullReconResult {
  domain: string;
  dns: DnsAnalysis;
  spoofability: SpoofabilityResult;
  subdomains: string[];
  typosquats: TyposquatCandidate[];
}

export async function runFullRecon(domain: string): Promise<FullReconResult> {
  // Run DNS analysis and subdomain enum in parallel
  const [dnsResult, subdomains] = await Promise.all([
    analyzeDns(domain),
    enumerateSubdomains(domain),
  ]);

  const spoofability = analyzeSpoofability(dnsResult);
  const typosquats = generateTyposquats(domain);

  return {
    domain,
    dns: dnsResult,
    spoofability,
    subdomains,
    typosquats,
  };
}
