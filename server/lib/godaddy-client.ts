/**
 * GoDaddy API Client — Automated Domain Purchasing for Phishing Infrastructure
 *
 * Enables domain purchasing and DNS management via GoDaddy's REST API.
 * Used alongside Namecheap as an alternative registrar for typosquat domains.
 *
 * API Docs: https://developer.godaddy.com/doc
 * Production: https://api.godaddy.com
 * OTE (sandbox): https://api.ote-godaddy.com
 */

import { ENV } from "../_core/env";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface GoDaddyConfig {
  apiKey: string;
  apiSecret: string;
  useSandbox: boolean;
  shopperId?: string;
}

export interface GoDaddyDomainCheck {
  domain: string;
  available: boolean;
  price: number;         // In micros (divide by 1,000,000 for USD)
  currency: string;
  period: number;        // Registration period in years
  definitive: boolean;
}

export interface GoDaddyPurchaseResult {
  success: boolean;
  domain: string;
  orderId?: string;
  itemCount?: number;
  total?: number;
  currency?: string;
  error?: string;
}

export interface GoDaddyDnsRecord {
  type: "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "NS" | "SRV";
  name: string;
  data: string;
  ttl?: number;
  priority?: number;
}

export interface GoDaddyDnsResult {
  success: boolean;
  domain: string;
  recordsSet: number;
  error?: string;
}

export interface GoDaddyContact {
  nameFirst: string;
  nameLast: string;
  email: string;
  phone: string;
  addressMailing: {
    address1: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
  };
  organization?: string;
}

// ─── Client ──────────────────────────────────────────────────────────────────

function getConfig(): GoDaddyConfig {
  return {
    apiKey: ENV.GODADDY_API_KEY || "",
    apiSecret: ENV.GODADDY_API_SECRET || "",
    useSandbox: ENV.GODADDY_SANDBOX === "true",
    shopperId: ENV.GODADDY_SHOPPER_ID,
  };
}

function getBaseUrl(config: GoDaddyConfig): string {
  return config.useSandbox
    ? "https://api.ote-godaddy.com"
    : "https://api.godaddy.com";
}

function getHeaders(config: GoDaddyConfig): Record<string, string> {
  return {
    "Authorization": `sso-key ${config.apiKey}:${config.apiSecret}`,
    "Content-Type": "application/json",
    "Accept": "application/json",
  };
}

async function callApi(
  config: GoDaddyConfig,
  method: string,
  path: string,
  body?: any
): Promise<any> {
  const url = `${getBaseUrl(config)}${path}`;
  const opts: RequestInit = {
    method,
    headers: getHeaders(config),
    signal: AbortSignal.timeout(15000),
  };
  if (body) {
    opts.body = JSON.stringify(body);
  }

  const response = await fetch(url, opts);

  if (!response.ok) {
    const errorBody = await response.text();
    let errorMsg: string;
    try {
      const parsed = JSON.parse(errorBody);
      errorMsg = parsed.message || parsed.code || errorBody;
    } catch {
      errorMsg = errorBody;
    }
    throw new Error(`GoDaddy API ${response.status}: ${errorMsg}`);
  }

  // Some endpoints return 204 No Content
  if (response.status === 204) return null;

  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Check domain availability and get pricing.
 */
export async function checkDomainAvailability(domains: string[]): Promise<GoDaddyDomainCheck[]> {
  const config = getConfig();
  if (!config.apiKey) throw new Error("GODADDY_API_KEY not configured");

  const results: GoDaddyDomainCheck[] = [];

  // GoDaddy checks one domain at a time via the suggest/available endpoint
  for (const domain of domains) {
    try {
      const data = await callApi(config, "GET", `/v1/domains/available?domain=${encodeURIComponent(domain)}`);
      results.push({
        domain: data.domain || domain,
        available: data.available === true,
        price: data.price || 0,
        currency: data.currency || "USD",
        period: data.period || 1,
        definitive: data.definitive !== false,
      });
    } catch (err: any) {
      // If 404 or error, mark as unavailable
      results.push({
        domain,
        available: false,
        price: 0,
        currency: "USD",
        period: 1,
        definitive: false,
      });
    }
  }

  return results;
}

/**
 * Get pricing for a specific TLD.
 */
export async function getTldPricing(tld: string = "com"): Promise<{ registerPrice: number; renewPrice: number }> {
  const config = getConfig();

  try {
    const data = await callApi(config, "GET", `/v1/pricing/domains/${tld}`);
    return {
      registerPrice: (data?.registration?.price || 1199) / 100, // Convert cents to dollars
      renewPrice: (data?.renewal?.price || 1799) / 100,
    };
  } catch {
    // Fallback pricing
    return { registerPrice: 11.99, renewPrice: 17.99 };
  }
}

/**
 * Purchase a domain.
 */
export async function purchaseDomain(
  domain: string,
  contact: GoDaddyContact,
  years: number = 1,
  privacy: boolean = true
): Promise<GoDaddyPurchaseResult> {
  const config = getConfig();
  if (!config.apiKey) throw new Error("GODADDY_API_KEY not configured");

  const purchaseBody = {
    domain,
    consent: {
      agreedAt: new Date().toISOString(),
      agreedBy: contact.addressMailing.address1,
      agreementKeys: ["DNRA"],
    },
    contactAdmin: contact,
    contactBilling: contact,
    contactRegistrant: contact,
    contactTech: contact,
    period: years,
    privacy,
    renewAuto: false,
    nameServers: undefined as string[] | undefined,
  };

  try {
    const data = await callApi(config, "POST", "/v1/domains/purchase", purchaseBody);
    return {
      success: true,
      domain,
      orderId: data?.orderId?.toString(),
      itemCount: data?.itemCount,
      total: data?.total,
      currency: data?.currency || "USD",
    };
  } catch (err: any) {
    return { success: false, domain, error: err.message };
  }
}

/**
 * Set DNS records for a domain (replaces records of the specified type).
 */
export async function setDnsRecords(domain: string, records: GoDaddyDnsRecord[]): Promise<GoDaddyDnsResult> {
  const config = getConfig();

  // GoDaddy API requires records grouped by type
  // Use PUT /v1/domains/{domain}/records to replace all records
  const apiRecords = records.map((r) => ({
    type: r.type,
    name: r.name === "@" ? "@" : r.name,
    data: r.data,
    ttl: r.ttl || 600,
    ...(r.priority !== undefined ? { priority: r.priority } : {}),
  }));

  try {
    await callApi(config, "PUT", `/v1/domains/${domain}/records`, apiRecords);
    return { success: true, domain, recordsSet: records.length };
  } catch (err: any) {
    return { success: false, domain, recordsSet: 0, error: err.message };
  }
}

/**
 * Add DNS records (append, don't replace).
 */
export async function addDnsRecords(domain: string, records: GoDaddyDnsRecord[]): Promise<GoDaddyDnsResult> {
  const config = getConfig();

  const apiRecords = records.map((r) => ({
    type: r.type,
    name: r.name === "@" ? "@" : r.name,
    data: r.data,
    ttl: r.ttl || 600,
    ...(r.priority !== undefined ? { priority: r.priority } : {}),
  }));

  try {
    await callApi(config, "PATCH", `/v1/domains/${domain}/records`, apiRecords);
    return { success: true, domain, recordsSet: records.length };
  } catch (err: any) {
    return { success: false, domain, recordsSet: 0, error: err.message };
  }
}

/**
 * Configure a domain for phishing: MX, SPF, DMARC, DKIM, and A record.
 */
export async function configureForPhishing(
  domain: string,
  mailServerIp: string,
  dkimSelector: string = "default",
  dkimPublicKey?: string
): Promise<GoDaddyDnsResult> {
  const records: GoDaddyDnsRecord[] = [
    { type: "A", name: "@", data: mailServerIp, ttl: 600 },
    { type: "A", name: "mail", data: mailServerIp, ttl: 600 },
    { type: "MX", name: "@", data: `mail.${domain}`, ttl: 600, priority: 10 },
    { type: "TXT", name: "@", data: `v=spf1 ip4:${mailServerIp} -all`, ttl: 600 },
    { type: "TXT", name: "_dmarc", data: "v=DMARC1; p=none; sp=none", ttl: 600 },
  ];

  if (dkimPublicKey) {
    records.push({
      type: "TXT",
      name: `${dkimSelector}._domainkey`,
      data: `v=DKIM1; k=rsa; p=${dkimPublicKey}`,
      ttl: 600,
    });
  }

  return setDnsRecords(domain, records);
}

/**
 * Full auto-integration: purchase domain → configure DNS → ready for phishing.
 */
export async function purchaseAndConfigure(
  domain: string,
  contact: GoDaddyContact,
  mailServerIp: string,
  dkimPublicKey?: string
): Promise<{
  purchase: GoDaddyPurchaseResult;
  dns?: GoDaddyDnsResult;
}> {
  // Step 1: Purchase
  const purchase = await purchaseDomain(domain, contact);
  if (!purchase.success) {
    return { purchase };
  }

  // Step 2: Wait for DNS to become manageable
  await new Promise((resolve) => setTimeout(resolve, 10000));

  // Step 3: Configure DNS for phishing
  const dns = await configureForPhishing(domain, mailServerIp, "default", dkimPublicKey);

  return { purchase, dns };
}

/**
 * Get list of domains owned by the account.
 */
export async function listOwnedDomains(): Promise<Array<{ domain: string; status: string; expires: string }>> {
  const config = getConfig();

  try {
    const data = await callApi(config, "GET", "/v1/domains?limit=100&statuses=ACTIVE");
    return (data || []).map((d: any) => ({
      domain: d.domain,
      status: d.status,
      expires: d.expires,
    }));
  } catch {
    return [];
  }
}
