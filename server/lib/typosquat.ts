/**
 * Typosquat Domain Service
 * 
 * Generates effective typosquat domain variants for phishing campaigns,
 * checks availability, manages DNS configuration via DigitalOcean,
 * and auto-integrates with GoPhish sending profiles.
 * 
 * Typosquat techniques ranked by effectiveness (based on research):
 * 1. Homoglyph substitution (rn→m, l→1, O→0)
 * 2. Character swap (adjacent key substitution)
 * 3. Missing dot (wwwexample.com)
 * 4. Subdomain insertion (exam.ple.com)
 * 5. TLD swap (.com→.co, .net, .org)
 * 6. Character omission (exmple.com)
 * 7. Character doubling (exxample.com)
 * 8. Bit-flip / vowel swap
 * 9. Hyphenation (ex-ample.com)
 * 10. Combosquat (example-login.com, example-secure.com)
 */

import { ENV } from "../_core/env";
import dns from "dns";
import { promisify } from "util";

const resolveDns = promisify(dns.resolve);

// ─── Types ─────────────────────────────────────────────────────────────────

export interface TyposquatVariant {
  domain: string;
  technique: string;
  effectiveness: number;  // 1-10 scale
  description: string;
  available?: boolean;
  tld: string;
}

export interface TyposquatResult {
  targetDomain: string;
  canSpoof: boolean;
  spoofabilityScore: number;
  spoofabilityReason: string;
  variants: TyposquatVariant[];
  recommendedVariants: TyposquatVariant[];
  generatedAt: string;
}

export interface DomainDnsConfig {
  domain: string;
  mxRecords: Array<{ exchange: string; priority: number }>;
  spfRecord: string;
  dkimSelector?: string;
  dmarcRecord: string;
}

// ─── Homoglyph Map ─────────────────────────────────────────────────────────

const HOMOGLYPHS: Record<string, string[]> = {
  a: ["à", "á", "â", "ã", "ä", "å", "ɑ", "а"],
  b: ["d", "lb"],
  c: ["ç", "ć", "ĉ", "ċ"],
  d: ["b", "cl", "ɗ"],
  e: ["è", "é", "ê", "ë", "ē", "ĕ", "ė"],
  f: ["ƒ"],
  g: ["q", "ɡ"],
  h: ["lh"],
  i: ["1", "l", "ì", "í", "î", "ï"],
  j: ["ĵ"],
  k: ["lk", "ĸ"],
  l: ["1", "i", "ĺ"],
  m: ["rn", "ṁ"],
  n: ["ñ", "ń", "ŋ"],
  o: ["0", "ò", "ó", "ô", "õ", "ö", "ø"],
  p: ["ρ"],
  q: ["g"],
  r: ["ŕ"],
  s: ["5", "ś", "ŝ", "ş"],
  t: ["ţ", "ť"],
  u: ["ù", "ú", "û", "ü", "ũ"],
  v: ["ν"],
  w: ["vv", "ŵ"],
  x: ["×"],
  y: ["ý", "ÿ", "ŷ"],
  z: ["ź", "ż", "ž"],
};

// Adjacent keyboard keys for typo simulation
const ADJACENT_KEYS: Record<string, string[]> = {
  a: ["q", "w", "s", "z"],
  b: ["v", "g", "h", "n"],
  c: ["x", "d", "f", "v"],
  d: ["s", "e", "r", "f", "c", "x"],
  e: ["w", "s", "d", "r"],
  f: ["d", "r", "t", "g", "v", "c"],
  g: ["f", "t", "y", "h", "b", "v"],
  h: ["g", "y", "u", "j", "n", "b"],
  i: ["u", "j", "k", "o"],
  j: ["h", "u", "i", "k", "n", "m"],
  k: ["j", "i", "o", "l", "m"],
  l: ["k", "o", "p"],
  m: ["n", "j", "k"],
  n: ["b", "h", "j", "m"],
  o: ["i", "k", "l", "p"],
  p: ["o", "l"],
  q: ["w", "a"],
  r: ["e", "d", "f", "t"],
  s: ["a", "w", "e", "d", "x", "z"],
  t: ["r", "f", "g", "y"],
  u: ["y", "h", "j", "i"],
  v: ["c", "f", "g", "b"],
  w: ["q", "a", "s", "e"],
  x: ["z", "s", "d", "c"],
  y: ["t", "g", "h", "u"],
  z: ["a", "s", "x"],
};

// Phishing-effective TLDs
const PHISHING_TLDS = [".co", ".net", ".org", ".io", ".info", ".biz", ".us", ".cc", ".xyz"];

// Combosquat prefixes/suffixes
const COMBO_PREFIXES = ["login-", "secure-", "auth-", "mail-", "portal-", "my-", "account-", "verify-"];
const COMBO_SUFFIXES = ["-login", "-secure", "-auth", "-portal", "-verify", "-support", "-help", "-account"];

// ─── Generation Functions ──────────────────────────────────────────────────

function splitDomain(domain: string): { name: string; tld: string } {
  const parts = domain.split(".");
  if (parts.length < 2) return { name: domain, tld: "" };
  const tld = "." + parts.slice(-1).join(".");
  const name = parts.slice(0, -1).join(".");
  return { name, tld };
}

/**
 * Generate homoglyph substitution variants
 * Effectiveness: 9/10 — very hard for humans to spot
 */
function generateHomoglyphs(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (let i = 0; i < name.length; i++) {
    const char = name[i].toLowerCase();
    const glyphs = HOMOGLYPHS[char];
    if (glyphs) {
      // Only use ASCII-safe homoglyphs for domain registration
      const asciiGlyphs = glyphs.filter(g => /^[a-z0-9]+$/.test(g));
      for (const glyph of asciiGlyphs) {
        const variant = name.slice(0, i) + glyph + name.slice(i + 1);
        if (variant !== name && variant.length <= 63) {
          variants.push({
            domain: variant + tld,
            technique: "homoglyph",
            effectiveness: 9,
            description: `Replaced '${char}' with '${glyph}' at position ${i + 1}`,
            tld,
          });
        }
      }
    }
  }
  return variants;
}

/**
 * Generate adjacent key swap variants
 * Effectiveness: 7/10 — mimics real typos
 */
function generateAdjacentSwaps(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (let i = 0; i < name.length; i++) {
    const char = name[i].toLowerCase();
    const adjacent = ADJACENT_KEYS[char];
    if (adjacent) {
      for (const adj of adjacent.slice(0, 2)) { // Limit to 2 per position
        const variant = name.slice(0, i) + adj + name.slice(i + 1);
        if (variant !== name) {
          variants.push({
            domain: variant + tld,
            technique: "adjacent_swap",
            effectiveness: 7,
            description: `Swapped '${char}' with adjacent key '${adj}' at position ${i + 1}`,
            tld,
          });
        }
      }
    }
  }
  return variants;
}

/**
 * Generate character omission variants
 * Effectiveness: 6/10 — common typo pattern
 */
function generateOmissions(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (let i = 0; i < name.length; i++) {
    const variant = name.slice(0, i) + name.slice(i + 1);
    if (variant.length >= 2) {
      variants.push({
        domain: variant + tld,
        technique: "omission",
        effectiveness: 6,
        description: `Omitted '${name[i]}' at position ${i + 1}`,
        tld,
      });
    }
  }
  return variants;
}

/**
 * Generate character doubling variants
 * Effectiveness: 6/10 — common typo pattern
 */
function generateDoublings(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (let i = 0; i < name.length; i++) {
    const variant = name.slice(0, i) + name[i] + name.slice(i);
    if (variant.length <= 63) {
      variants.push({
        domain: variant + tld,
        technique: "doubling",
        effectiveness: 6,
        description: `Doubled '${name[i]}' at position ${i + 1}`,
        tld,
      });
    }
  }
  return variants;
}

/**
 * Generate TLD swap variants
 * Effectiveness: 8/10 — users often don't check TLD
 */
function generateTldSwaps(name: string, originalTld: string): TyposquatVariant[] {
  return PHISHING_TLDS
    .filter(tld => tld !== originalTld)
    .map(tld => ({
      domain: name + tld,
      technique: "tld_swap",
      effectiveness: 8,
      description: `Changed TLD from '${originalTld}' to '${tld}'`,
      tld,
    }));
}

/**
 * Generate missing dot variants (wwwexample.com)
 * Effectiveness: 7/10 — exploits URL bar reading habits
 */
function generateMissingDot(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  // www prefix
  variants.push({
    domain: "www" + name + tld,
    technique: "missing_dot",
    effectiveness: 7,
    description: `Missing dot: www${name}${tld} (looks like www.${name}${tld})`,
    tld,
  });
  return variants;
}

/**
 * Generate hyphenation variants
 * Effectiveness: 5/10 — less convincing but cheap
 */
function generateHyphenation(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (let i = 1; i < name.length; i++) {
    const variant = name.slice(0, i) + "-" + name.slice(i);
    if (variant.length <= 63) {
      variants.push({
        domain: variant + tld,
        technique: "hyphenation",
        effectiveness: 5,
        description: `Inserted hyphen at position ${i + 1}: ${variant}`,
        tld,
      });
    }
  }
  return variants.slice(0, 3); // Limit
}

/**
 * Generate combosquat variants
 * Effectiveness: 8/10 — very convincing for phishing
 */
function generateCombosquats(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (const prefix of COMBO_PREFIXES) {
    const domain = prefix + name + tld;
    if (domain.length <= 63 + tld.length) {
      variants.push({
        domain,
        technique: "combosquat",
        effectiveness: 8,
        description: `Added prefix '${prefix}' for phishing context`,
        tld,
      });
    }
  }
  for (const suffix of COMBO_SUFFIXES) {
    const domain = name + suffix + tld;
    if (domain.length <= 63 + tld.length) {
      variants.push({
        domain,
        technique: "combosquat",
        effectiveness: 8,
        description: `Added suffix '${suffix}' for phishing context`,
        tld,
      });
    }
  }
  return variants;
}

/**
 * Generate character transposition variants
 * Effectiveness: 7/10 — common typo
 */
function generateTranspositions(name: string, tld: string): TyposquatVariant[] {
  const variants: TyposquatVariant[] = [];
  for (let i = 0; i < name.length - 1; i++) {
    const variant = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
    if (variant !== name) {
      variants.push({
        domain: variant + tld,
        technique: "transposition",
        effectiveness: 7,
        description: `Swapped '${name[i]}' and '${name[i + 1]}' at positions ${i + 1}-${i + 2}`,
        tld,
      });
    }
  }
  return variants;
}

// ─── Domain Availability Check ─────────────────────────────────────────────

/**
 * Check if a domain is likely available by attempting DNS resolution.
 * Not 100% accurate (some registered domains have no DNS) but fast.
 */
async function checkDomainAvailability(domain: string): Promise<boolean> {
  try {
    await resolveDns(domain, "A");
    return false; // Domain resolves → likely registered
  } catch (err: any) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      // No DNS records — might be available
      // Double-check with NS records
      try {
        await resolveDns(domain, "NS");
        return false; // Has NS records → registered
      } catch {
        return true; // No A or NS records → likely available
      }
    }
    return true; // DNS error → assume available for now
  }
}

// ─── Main Generation Function ──────────────────────────────────────────────

/**
 * Generate top typosquat domain variants for a target domain.
 * Returns the top 10 most effective variants with availability status.
 */
export async function generateTyposquatVariants(
  targetDomain: string,
  options?: {
    checkAvailability?: boolean;
    maxVariants?: number;
    includeAllTechniques?: boolean;
  }
): Promise<TyposquatResult> {
  const { name, tld } = splitDomain(targetDomain);
  const maxVariants = options?.maxVariants || 10;
  const checkAvail = options?.checkAvailability !== false;

  // Generate all variants
  const allVariants: TyposquatVariant[] = [
    ...generateHomoglyphs(name, tld),
    ...generateAdjacentSwaps(name, tld),
    ...generateTldSwaps(name, tld),
    ...generateCombosquats(name, tld),
    ...generateMissingDot(name, tld),
    ...generateTranspositions(name, tld),
    ...generateOmissions(name, tld),
    ...generateDoublings(name, tld),
    ...generateHyphenation(name, tld),
  ];

  // Deduplicate
  const seen = new Set<string>();
  const unique = allVariants.filter(v => {
    if (seen.has(v.domain)) return false;
    seen.add(v.domain);
    return true;
  });

  // Sort by effectiveness (highest first)
  unique.sort((a, b) => b.effectiveness - a.effectiveness);

  // Take top candidates
  const topCandidates = unique.slice(0, maxVariants * 3); // Check more than needed

  // Check availability in parallel (batched)
  if (checkAvail) {
    const BATCH_SIZE = 10;
    for (let i = 0; i < topCandidates.length; i += BATCH_SIZE) {
      const batch = topCandidates.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map(v => checkDomainAvailability(v.domain))
      );
      results.forEach((result, idx) => {
        batch[idx].available = result.status === "fulfilled" ? result.value : undefined;
      });
    }
  }

  // Prioritize available domains, then by effectiveness
  const recommended = topCandidates
    .filter(v => v.available === true || v.available === undefined)
    .slice(0, maxVariants);

  // Check spoofability of target domain
  let canSpoof = false;
  let spoofabilityScore = 0;
  let spoofabilityReason = "";
  try {
    const { analyzeDns, analyzeSpoofability } = await import("../osint");
    const dnsData = await analyzeDns(targetDomain);
    const spoofResult = analyzeSpoofability(dnsData);
    spoofabilityScore = spoofResult.score;
    canSpoof = spoofResult.score >= 50;
    spoofabilityReason = canSpoof
      ? `Target domain has weak email security (score: ${spoofResult.score}/100). Direct spoofing may be possible, but typosquat domains provide better deliverability.`
      : `Target domain has strong email security (score: ${spoofResult.score}/100). SPF/DKIM/DMARC prevent direct spoofing — typosquat domains are recommended.`;
  } catch {
    spoofabilityReason = "Could not check target domain email security. Typosquat domains recommended as a safe approach.";
  }

  return {
    targetDomain,
    canSpoof,
    spoofabilityScore,
    spoofabilityReason,
    variants: options?.includeAllTechniques ? unique : topCandidates,
    recommendedVariants: recommended,
    generatedAt: new Date().toISOString(),
  };
}

// ─── DigitalOcean DNS Management ───────────────────────────────────────────

const DO_API = "https://api.digitalocean.com/v2";

async function doFetch(endpoint: string, method: string = "GET", body?: any) {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN not configured");

  const resp = await fetch(`${DO_API}${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => "");
    throw new Error(`DigitalOcean API error ${resp.status}: ${errText}`);
  }

  if (resp.status === 204) return null;
  return resp.json();
}

/**
 * Add a domain to DigitalOcean DNS management.
 * The domain must already be registered at a registrar.
 * After adding, update nameservers at registrar to:
 *   ns1.digitalocean.com, ns2.digitalocean.com, ns3.digitalocean.com
 */
export async function addDomainToDO(domain: string, ipAddress?: string): Promise<any> {
  return doFetch("/domains", "POST", {
    name: domain,
    ip_address: ipAddress || "127.0.0.1", // Placeholder IP
  });
}

/**
 * Create a DNS record for a domain managed by DigitalOcean.
 */
export async function createDnsRecord(
  domain: string,
  record: {
    type: "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "NS" | "SRV";
    name: string;
    data: string;
    priority?: number;
    ttl?: number;
  }
): Promise<any> {
  return doFetch(`/domains/${domain}/records`, "POST", {
    ...record,
    ttl: record.ttl || 1800,
  });
}

/**
 * Configure a domain for email sending (MX, SPF, DKIM, DMARC).
 * This sets up the minimum DNS records needed for phishing email delivery.
 */
export async function configureDomainForEmail(
  domain: string,
  mailServerIp: string = "137.184.7.224" // Default: our mail server
): Promise<DomainDnsConfig> {
  // Add domain to DO
  await addDomainToDO(domain, mailServerIp);

  // Create MX record pointing to the domain itself (or mail server)
  await createDnsRecord(domain, {
    type: "MX",
    name: "@",
    data: `mail.${domain}.`,
    priority: 10,
  });

  // Create A record for mail subdomain
  await createDnsRecord(domain, {
    type: "A",
    name: "mail",
    data: mailServerIp,
  });

  // Create SPF record
  const spfRecord = `v=spf1 ip4:${mailServerIp} -all`;
  await createDnsRecord(domain, {
    type: "TXT",
    name: "@",
    data: spfRecord,
  });

  // Create DMARC record (permissive for phishing)
  const dmarcRecord = `v=DMARC1; p=none; sp=none`;
  await createDnsRecord(domain, {
    type: "TXT",
    name: "_dmarc",
    data: dmarcRecord,
  });

  return {
    domain,
    mxRecords: [{ exchange: `mail.${domain}`, priority: 10 }],
    spfRecord,
    dmarcRecord,
  };
}

/**
 * List all domains managed in DigitalOcean.
 */
export async function listDODomains(): Promise<any[]> {
  const result = await doFetch("/domains");
  return result?.domains || [];
}

/**
 * Get DNS records for a domain.
 */
export async function getDomainRecords(domain: string): Promise<any[]> {
  const result = await doFetch(`/domains/${domain}/records`);
  return result?.domain_records || [];
}

/**
 * Delete a domain from DigitalOcean DNS management.
 */
export async function deleteDODomain(domain: string): Promise<void> {
  await doFetch(`/domains/${domain}`, "DELETE");
}
