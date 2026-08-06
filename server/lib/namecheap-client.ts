/**
 * Namecheap API Client — Automated Domain Purchasing for Phishing Infrastructure
 *
 * Enables customers to purchase typosquat domains directly from AC3 and have them
 * auto-configured for phishing campaigns (DNS + GoPhish sending profile).
 *
 * API Docs: https://www.namecheap.com/support/api/methods/
 * Sandbox: https://api.sandbox.namecheap.com/xml.response
 * Production: https://api.namecheap.com/xml.response
 */

import { ENV } from "../_core/env";
import crypto from "crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface NamecheapConfig {
  apiUser: string;
  apiKey: string;
  clientIp: string;
  useSandbox: boolean;
}

export interface DomainCheckResult {
  domain: string;
  available: boolean;
  premium: boolean;
  price?: number;
  currency?: string;
  icannFee?: number;
}

export interface DomainPurchaseResult {
  success: boolean;
  domain: string;
  orderId?: string;
  transactionId?: string;
  chargedAmount?: number;
  error?: string;
}

export interface DnsRecord {
  type: "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "NS" | "SRV";
  name: string;
  value: string;
  ttl?: number;
  priority?: number;
}

export interface DnsSetResult {
  success: boolean;
  domain: string;
  recordsSet: number;
  error?: string;
}

export interface RegistrantContact {
  firstName: string;
  lastName: string;
  address1: string;
  city: string;
  stateProvince: string;
  postalCode: string;
  country: string;
  phone: string;
  email: string;
  organizationName?: string;
}

// ─── Client ──────────────────────────────────────────────────────────────────

function getConfig(): NamecheapConfig {
  return {
    apiUser: ENV.NAMECHEAP_API_USER || "",
    apiKey: ENV.NAMECHEAP_API_KEY || "",
    clientIp: ENV.NAMECHEAP_CLIENT_IP || ENV.MAIL_SERVER_IP || "0.0.0.0",
    useSandbox: ENV.NAMECHEAP_SANDBOX === "true",
  };
}

function getBaseUrl(config: NamecheapConfig): string {
  return config.useSandbox
    ? "https://api.sandbox.namecheap.com/xml.response"
    : "https://api.namecheap.com/xml.response";
}

function buildParams(config: NamecheapConfig, command: string): URLSearchParams {
  return new URLSearchParams({
    ApiUser: config.apiUser,
    ApiKey: config.apiKey,
    UserName: config.apiUser,
    ClientIp: config.clientIp,
    Command: command,
  });
}

async function callApi(params: URLSearchParams, config: NamecheapConfig): Promise<string> {
  const url = `${getBaseUrl(config)}?${params.toString()}`;
  const response = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Namecheap API HTTP ${response.status}`);
  return response.text();
}

function parseXmlValue(xml: string, tag: string): string | undefined {
  const match = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, "i"));
  return match?.[1];
}

function parseXmlAttr(xml: string, tag: string, attr: string): string | undefined {
  const match = xml.match(new RegExp(`<${tag}[^>]*${attr}="([^"]*)"`, "i"));
  return match?.[1];
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Check domain availability and pricing.
 */
export async function checkDomainAvailability(domains: string[]): Promise<DomainCheckResult[]> {
  const config = getConfig();
  if (!config.apiKey) throw new Error("NAMECHEAP_API_KEY not configured");

  const params = buildParams(config, "namecheap.domains.check");
  params.set("DomainList", domains.join(","));

  const xml = await callApi(params, config);
  const results: DomainCheckResult[] = [];

  // Parse each DomainCheckResult from XML
  const domainMatches = xml.matchAll(
    /<DomainCheckResult\s+Domain="([^"]+)"\s+Available="([^"]+)"[^>]*(?:IsPremiumName="([^"]+)")?[^>]*(?:PremiumRegistrationPrice="([^"]+)")?/gi
  );

  for (const match of domainMatches) {
    results.push({
      domain: match[1],
      available: match[2].toLowerCase() === "true",
      premium: match[3]?.toLowerCase() === "true" || false,
      price: match[4] ? parseFloat(match[4]) : undefined,
    });
  }

  // If no results parsed, try simpler parsing
  if (results.length === 0) {
    for (const domain of domains) {
      const available = xml.includes(`Domain="${domain}" Available="true"`);
      results.push({ domain, available, premium: false });
    }
  }

  return results;
}

/**
 * Get domain pricing for registration.
 */
export async function getDomainPricing(tld: string = "com"): Promise<{ registerPrice: number; renewPrice: number }> {
  const config = getConfig();
  const params = buildParams(config, "namecheap.users.getPricing");
  params.set("ProductType", "DOMAIN");
  params.set("ProductCategory", "REGISTER");
  params.set("ProductName", tld);

  const xml = await callApi(params, config);
  const price = parseXmlAttr(xml, "Price", "Price") || "12.98";
  const renewPrice = parseXmlAttr(xml, "Price", "AdditionalCost") || price;

  return {
    registerPrice: parseFloat(price),
    renewPrice: parseFloat(renewPrice as string),
  };
}

/**
 * Purchase a domain. Requires registrant contact info.
 */
export async function purchaseDomain(
  domain: string,
  contact: RegistrantContact,
  years: number = 1,
  enableWhoisGuard: boolean = true
): Promise<DomainPurchaseResult> {
  const config = getConfig();
  if (!config.apiKey) throw new Error("NAMECHEAP_API_KEY not configured");

  const [sld, tld] = splitDomain(domain);
  const params = buildParams(config, "namecheap.domains.create");

  // Domain details
  params.set("DomainName", domain);
  params.set("Years", years.toString());
  params.set("AddFreeWhoisguard", enableWhoisGuard ? "yes" : "no");
  params.set("WGEnabled", enableWhoisGuard ? "yes" : "no");

  // Registrant contact (same for all contact types)
  const contactTypes = ["Registrant", "Tech", "Admin", "AuxBilling"];
  for (const type of contactTypes) {
    params.set(`${type}FirstName`, contact.firstName);
    params.set(`${type}LastName`, contact.lastName);
    params.set(`${type}Address1`, contact.address1);
    params.set(`${type}City`, contact.city);
    params.set(`${type}StateProvince`, contact.stateProvince);
    params.set(`${type}PostalCode`, contact.postalCode);
    params.set(`${type}Country`, contact.country);
    params.set(`${type}Phone`, contact.phone);
    params.set(`${type}EmailAddress`, contact.email);
    if (contact.organizationName) {
      params.set(`${type}OrganizationName`, contact.organizationName);
    }
  }

  try {
    const xml = await callApi(params, config);

    if (xml.includes('Status="ERROR"')) {
      const errorMsg = parseXmlValue(xml, "Err") || "Unknown error";
      return { success: false, domain, error: errorMsg };
    }

    const orderId = parseXmlAttr(xml, "DomainCreateResult", "OrderId");
    const transactionId = parseXmlAttr(xml, "DomainCreateResult", "TransactionId");
    const charged = parseXmlAttr(xml, "DomainCreateResult", "ChargedAmount");

    return {
      success: true,
      domain,
      orderId: orderId || undefined,
      transactionId: transactionId || undefined,
      chargedAmount: charged ? parseFloat(charged) : undefined,
    };
  } catch (err: any) {
    return { success: false, domain, error: err.message };
  }
}

/**
 * Set DNS records for a domain (replaces all existing host records).
 */
export async function setDnsRecords(domain: string, records: DnsRecord[]): Promise<DnsSetResult> {
  const config = getConfig();
  const [sld, tld] = splitDomain(domain);
  const params = buildParams(config, "namecheap.domains.dns.setHosts");

  params.set("SLD", sld);
  params.set("TLD", tld);

  records.forEach((record, i) => {
    const idx = i + 1;
    params.set(`HostName${idx}`, record.name);
    params.set(`RecordType${idx}`, record.type);
    params.set(`Address${idx}`, record.value);
    params.set(`TTL${idx}`, (record.ttl || 1800).toString());
    if (record.priority !== undefined) {
      params.set(`MXPref${idx}`, record.priority.toString());
    }
  });

  try {
    const xml = await callApi(params, config);

    if (xml.includes('Status="ERROR"')) {
      const errorMsg = parseXmlValue(xml, "Err") || "DNS update failed";
      return { success: false, domain, recordsSet: 0, error: errorMsg };
    }

    return { success: true, domain, recordsSet: records.length };
  } catch (err: any) {
    return { success: false, domain, recordsSet: 0, error: err.message };
  }
}

/**
 * Configure a domain for phishing: MX, SPF, DMARC, and A record.
 */
export async function configureForPhishing(
  domain: string,
  mailServerIp: string,
  dkimSelector: string = "default",
  dkimPublicKey?: string
): Promise<DnsSetResult> {
  const records: DnsRecord[] = [
    // A record for landing page
    { type: "A", name: "@", value: mailServerIp, ttl: 300 },
    // MX record for receiving bounces
    { type: "MX", name: "@", value: `mail.${domain}`, ttl: 300, priority: 10 },
    // A record for mail subdomain
    { type: "A", name: "mail", value: mailServerIp, ttl: 300 },
    // SPF record
    { type: "TXT", name: "@", value: `v=spf1 ip4:${mailServerIp} -all`, ttl: 300 },
    // DMARC record (relaxed for phishing — don't reject)
    { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none; sp=none", ttl: 300 },
  ];

  // Add DKIM if public key provided
  if (dkimPublicKey) {
    records.push({
      type: "TXT",
      name: `${dkimSelector}._domainkey`,
      value: `v=DKIM1; k=rsa; p=${dkimPublicKey}`,
      ttl: 300,
    });
  }

  return setDnsRecords(domain, records);
}

/**
 * Full auto-integration: purchase domain → configure DNS → ready for phishing.
 */
export async function purchaseAndConfigure(
  domain: string,
  contact: RegistrantContact,
  mailServerIp: string,
  dkimPublicKey?: string
): Promise<{
  purchase: DomainPurchaseResult;
  dns?: DnsSetResult;
}> {
  // Step 1: Purchase
  const purchase = await purchaseDomain(domain, contact);
  if (!purchase.success) {
    return { purchase };
  }

  // Step 2: Wait for propagation (Namecheap needs a moment)
  await new Promise((resolve) => setTimeout(resolve, 5000));

  // Step 3: Configure DNS for phishing
  const dns = await configureForPhishing(domain, mailServerIp, "default", dkimPublicKey);

  return { purchase, dns };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function splitDomain(domain: string): [string, string] {
  const parts = domain.split(".");
  const tld = parts.pop()!;
  const sld = parts.join(".");
  return [sld, tld];
}
