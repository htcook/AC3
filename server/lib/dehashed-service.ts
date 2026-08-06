/**
 * Dehashed API Service (v4)
 * Provides breach data lookups and subdomain discovery for domain intelligence scans.
 *
 * API: POST https://api.dehashed.com/v2/search
 * Auth: Dehashed-Api-Key header (v4 — old Basic Auth is deprecated)
 */

// ── Types ──────────────────────────────────────────────────────────────────────

/** v4 API returns arrays for most fields */
export interface DehashedEntry {
  id: string;
  email: string[];
  ip_address: string[];
  username: string[];
  password: string[];
  hashed_password: string[];
  name: string[];
  phone: string[];
  address: string[];
  company: string[];
  url: string[];
  social: string[];
  database_name: string;
  raw_record?: { le_only?: boolean; unstructured?: boolean };
}

export interface DehashedSearchResult {
  balance: number;
  entries: DehashedEntry[] | null;
  total: number;
  took?: string;
  error?: string;
}

export interface BreachSummary {
  domain: string;
  totalExposures: number;
  uniqueEmails: number;
  uniqueBreachSources: number;
  breachSources: string[];
  passwordsExposed: number;
  hashedPasswordsExposed: number;
  credentialPairs: number; // entries with both email + password/hash
  sampleEmails: string[]; // first 20 unique emails (redacted)
  entries: BreachEntry[];
  queriedAt: string;
}

export interface BreachEntry {
  email: string;
  username: string;
  hasPassword: boolean;
  hasHashedPassword: boolean;
  breachSource: string;
  ipAddress: string;
}

export interface DehashedSubdomain {
  subdomain: string;
  source: "dehashed_email" | "dehashed_ip";
  associatedEmails: number;
  associatedIps: number;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Get first value from a v4 array field */
function first(arr?: string[]): string {
  return arr && arr.length > 0 ? arr[0] : "";
}

/** Check if any element in array is non-empty */
function hasValue(arr?: string[]): boolean {
  return !!arr && arr.some(v => v && v.trim().length > 0);
}

async function dehashedFetch(query: string, size = 10000, page = 1): Promise<DehashedSearchResult | null> {
  const apiKey = process.env.DEHASHED_API_KEY;
  if (!apiKey) {
    console.warn("[Dehashed] Missing DEHASHED_API_KEY");
    return null;
  }

  const res = await fetch("https://api.dehashed.com/v2/search", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Dehashed-Api-Key": apiKey,
    },
    body: JSON.stringify({
      query,
      page,
      size,
      de_dupe: true,
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    console.error(`[Dehashed] API error ${res.status}: ${text}`);
    if (res.status === 401) throw new Error("Dehashed API authentication failed — check DEHASHED_API_KEY (v4 key from app.dehashed.com/documentation/api)");
    if (res.status === 402) throw new Error("Dehashed API credits exhausted — purchase more at dehashed.com");
    if (res.status === 403) throw new Error("Dehashed API insufficient credits");
    throw new Error(`Dehashed API error: ${res.status}`);
  }

  const data = (await res.json()) as DehashedSearchResult;
  if (data.error) {
    throw new Error(`Dehashed API error: ${data.error}`);
  }
  return data;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Search Dehashed for all breached records associated with a domain.
 * Returns a summary with breach sources, credential exposure stats, and sample entries.
 */
export async function searchBreachesByDomain(domain: string): Promise<BreachSummary | null> {
  try {
    const result = await dehashedFetch(`domain:${domain}`, 10000);
    if (!result) return null;

    const entries = result.entries || [];
    const uniqueEmails = new Set<string>();
    const breachSources = new Set<string>();
    let passwordsExposed = 0;
    let hashedPasswordsExposed = 0;
    let credentialPairs = 0;

    const breachEntries: BreachEntry[] = [];

    for (const entry of entries) {
      // v4: email is an array
      for (const email of (entry.email || [])) {
        if (email) uniqueEmails.add(email.toLowerCase());
      }
      if (entry.database_name) breachSources.add(entry.database_name);

      const hasPass = hasValue(entry.password);
      const hasHash = hasValue(entry.hashed_password);

      if (hasPass) passwordsExposed++;
      if (hasHash) hashedPasswordsExposed++;
      if (hasValue(entry.email) && (hasPass || hasHash)) credentialPairs++;

      breachEntries.push({
        email: first(entry.email),
        username: first(entry.username),
        hasPassword: hasPass,
        hasHashedPassword: hasHash,
        breachSource: entry.database_name || "Unknown",
        ipAddress: first(entry.ip_address),
      });
    }

    // Redact emails for the sample list (show first 2 chars + domain)
    const sampleEmails = Array.from(uniqueEmails)
      .slice(0, 20)
      .map((e) => {
        const [local, dom] = e.split("@");
        if (!local || !dom) return e;
        return `${local.slice(0, 2)}***@${dom}`;
      });

    return {
      domain,
      totalExposures: result.total,
      uniqueEmails: uniqueEmails.size,
      uniqueBreachSources: breachSources.size,
      breachSources: Array.from(breachSources).sort(),
      passwordsExposed,
      hashedPasswordsExposed,
      credentialPairs,
      sampleEmails,
      entries: breachEntries,
      queriedAt: new Date().toISOString(),
    };
  } catch (err: any) {
    console.error(`[Dehashed] Breach search failed for ${domain}:`, err.message);
    return null;
  }
}

/**
 * Search Dehashed for email records matching a domain to discover subdomains.
 * Extracts unique subdomains from email addresses (e.g., user@mail.example.com → mail.example.com).
 */
export async function discoverSubdomains(domain: string): Promise<DehashedSubdomain[]> {
  try {
    const result = await dehashedFetch(`domain:${domain}`, 10000);
    if (!result || !result.entries) return [];

    const subdomainMap = new Map<string, { emails: Set<string>; ips: Set<string> }>();

    for (const entry of result.entries) {
      // v4: email and ip_address are arrays
      const emails = entry.email || [];
      const ips = entry.ip_address || [];

      for (const email of emails) {
        if (!email) continue;
        const emailDomain = email.split("@")[1]?.toLowerCase();
        if (emailDomain && emailDomain !== domain.toLowerCase() && emailDomain.endsWith(`.${domain.toLowerCase()}`)) {
          if (!subdomainMap.has(emailDomain)) {
            subdomainMap.set(emailDomain, { emails: new Set(), ips: new Set() });
          }
          subdomainMap.get(emailDomain)!.emails.add(email.toLowerCase());
          for (const ip of ips) {
            if (ip) subdomainMap.get(emailDomain)!.ips.add(ip);
          }
        }
      }
    }

    return Array.from(subdomainMap.entries()).map(([subdomain, data]) => ({
      subdomain,
      source: "dehashed_email" as const,
      associatedEmails: data.emails.size,
      associatedIps: data.ips.size,
    }));
  } catch (err: any) {
    console.error(`[Dehashed] Subdomain discovery failed for ${domain}:`, err.message);
    return [];
  }
}

/**
 * Search Dehashed for breached records by email address.
 * Useful for targeted lookups on specific accounts found during OSINT.
 */
export async function searchBreachesByEmail(email: string): Promise<DehashedEntry[]> {
  try {
    const result = await dehashedFetch(`email:${email}`, 100);
    if (!result) return [];
    return result.entries || [];
  } catch (err: any) {
    console.error(`[Dehashed] Email search failed for ${email}:`, err.message);
    return [];
  }
}

/**
 * Check if Dehashed API credentials are configured.
 * v4 only requires DEHASHED_API_KEY (no email needed).
 */
export function isDehashedConfigured(): boolean {
  return !!process.env.DEHASHED_API_KEY;
}

/**
 * Get remaining API credit balance.
 */
export async function getDehashedBalance(): Promise<number | null> {
  try {
    // A minimal query to check balance (1 result)
    const result = await dehashedFetch("domain:example.com", 1);
    return result?.balance ?? null;
  } catch {
    return null;
  }
}
