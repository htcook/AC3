/**
 * Unified Domain Registrar Interface
 *
 * Abstracts Namecheap and GoDaddy behind a common API so the typosquat
 * router and UI can work with either registrar transparently.
 *
 * Features:
 * - Check availability across both registrars simultaneously
 * - Compare pricing between registrars
 * - Purchase from the cheapest (or user-selected) registrar
 * - Configure DNS for phishing (MX, SPF, DMARC, DKIM) regardless of registrar
 * - Auto-generate DKIM keys during domain setup
 */

import { ENV } from "../_core/env";
import * as namecheap from "./namecheap-client";
import * as godaddy from "./godaddy-client";
import { generateDkimKeypair, type DkimKeypair } from "./dkim-generator";

// ─── Types ───────────────────────────────────────────────────────────────────

export type RegistrarId = "namecheap" | "godaddy";

export interface RegistrarStatus {
  id: RegistrarId;
  name: string;
  configured: boolean;
  sandbox: boolean;
}

export interface DomainAvailability {
  domain: string;
  registrar: RegistrarId;
  available: boolean;
  price: number;       // USD
  currency: string;
  premium: boolean;
}

export interface PriceComparison {
  domain: string;
  cheapest: RegistrarId;
  prices: Record<RegistrarId, number | null>;
  savings: number;     // Difference between cheapest and most expensive
}

export interface RegistrantInfo {
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  organization?: string;
}

export interface PurchaseRequest {
  domain: string;
  registrar: RegistrarId;
  contact: RegistrantInfo;
  years?: number;
  privacy?: boolean;
  autoConfigurePhishing?: boolean;
  mailServerIp?: string;
}

export interface PurchaseResult {
  success: boolean;
  domain: string;
  registrar: RegistrarId;
  orderId?: string;
  chargedAmount?: number;
  currency?: string;
  dnsConfigured?: boolean;
  dkim?: DkimKeypair;
  error?: string;
}

export interface DnsConfigResult {
  success: boolean;
  domain: string;
  registrar: RegistrarId;
  recordsSet: number;
  dkim?: DkimKeypair;
  error?: string;
}

// ─── Registrar Status ────────────────────────────────────────────────────────

/**
 * Get the configuration status of all supported registrars.
 */
export function getRegistrarStatus(): RegistrarStatus[] {
  return [
    {
      id: "namecheap",
      name: "Namecheap",
      configured: !!(ENV.NAMECHEAP_API_KEY && ENV.NAMECHEAP_API_USER),
      sandbox: ENV.NAMECHEAP_SANDBOX === "true",
    },
    {
      id: "godaddy",
      name: "GoDaddy",
      configured: !!(ENV.GODADDY_API_KEY && ENV.GODADDY_API_SECRET),
      sandbox: ENV.GODADDY_SANDBOX === "true",
    },
  ];
}

/**
 * Get list of configured (usable) registrars.
 */
export function getConfiguredRegistrars(): RegistrarId[] {
  const statuses = getRegistrarStatus();
  return statuses.filter((s) => s.configured).map((s) => s.id);
}

// ─── Domain Availability ─────────────────────────────────────────────────────

/**
 * Check domain availability across all configured registrars.
 */
export async function checkAvailability(domains: string[]): Promise<DomainAvailability[]> {
  const configured = getConfiguredRegistrars();
  const results: DomainAvailability[] = [];

  const promises: Promise<void>[] = [];

  if (configured.includes("namecheap")) {
    promises.push(
      namecheap.checkDomainAvailability(domains).then((ncResults) => {
        for (const r of ncResults) {
          results.push({
            domain: r.domain,
            registrar: "namecheap",
            available: r.available,
            price: r.price || 12.98,
            currency: r.currency || "USD",
            premium: r.premium,
          });
        }
      }).catch((err) => {
        // Namecheap failed — skip silently
        console.warn("[registrar] Namecheap check failed:", err.message);
      })
    );
  }

  if (configured.includes("godaddy")) {
    promises.push(
      godaddy.checkDomainAvailability(domains).then((gdResults) => {
        for (const r of gdResults) {
          results.push({
            domain: r.domain,
            registrar: "godaddy",
            available: r.available,
            price: r.price > 1000 ? r.price / 1000000 : r.price, // Handle micros
            currency: r.currency,
            premium: false,
          });
        }
      }).catch((err) => {
        console.warn("[registrar] GoDaddy check failed:", err.message);
      })
    );
  }

  await Promise.allSettled(promises);
  return results;
}

/**
 * Compare pricing across registrars for a list of domains.
 */
export async function comparePricing(domains: string[]): Promise<PriceComparison[]> {
  const availability = await checkAvailability(domains);

  // Group by domain
  const byDomain: Record<string, DomainAvailability[]> = {};
  for (const a of availability) {
    if (!byDomain[a.domain]) byDomain[a.domain] = [];
    byDomain[a.domain].push(a);
  }

  const comparisons: PriceComparison[] = [];
  for (const [domain, options] of Object.entries(byDomain)) {
    const available = options.filter((o) => o.available);
    if (available.length === 0) {
      comparisons.push({
        domain,
        cheapest: "namecheap",
        prices: { namecheap: null, godaddy: null },
        savings: 0,
      });
      continue;
    }

    const prices: Record<RegistrarId, number | null> = { namecheap: null, godaddy: null };
    for (const opt of available) {
      prices[opt.registrar] = opt.price;
    }

    const cheapest = available.sort((a, b) => a.price - b.price)[0];
    const mostExpensive = available.sort((a, b) => b.price - a.price)[0];

    comparisons.push({
      domain,
      cheapest: cheapest.registrar,
      prices,
      savings: available.length > 1 ? mostExpensive.price - cheapest.price : 0,
    });
  }

  return comparisons;
}

// ─── Domain Purchase ─────────────────────────────────────────────────────────

/**
 * Purchase a domain from the specified registrar and optionally configure for phishing.
 */
export async function purchaseDomain(request: PurchaseRequest): Promise<PurchaseResult> {
  const { domain, registrar, contact, years = 1, privacy = true } = request;

  // Generate DKIM keys upfront (needed for DNS config)
  let dkim: DkimKeypair | undefined;
  if (request.autoConfigurePhishing) {
    dkim = generateDkimKeypair(domain);
  }

  let purchaseResult: PurchaseResult;

  if (registrar === "namecheap") {
    const ncContact: namecheap.RegistrantContact = {
      firstName: contact.firstName,
      lastName: contact.lastName,
      address1: contact.address,
      city: contact.city,
      stateProvince: contact.state,
      postalCode: contact.postalCode,
      country: contact.country,
      phone: contact.phone,
      email: contact.email,
      organizationName: contact.organization,
    };

    const result = await namecheap.purchaseDomain(domain, ncContact, years, privacy);
    purchaseResult = {
      success: result.success,
      domain,
      registrar: "namecheap",
      orderId: result.orderId,
      chargedAmount: result.chargedAmount,
      error: result.error,
    };
  } else if (registrar === "godaddy") {
    const gdContact: godaddy.GoDaddyContact = {
      nameFirst: contact.firstName,
      nameLast: contact.lastName,
      email: contact.email,
      phone: contact.phone,
      addressMailing: {
        address1: contact.address,
        city: contact.city,
        state: contact.state,
        postalCode: contact.postalCode,
        country: contact.country,
      },
      organization: contact.organization,
    };

    const result = await godaddy.purchaseDomain(domain, gdContact, years, privacy);
    purchaseResult = {
      success: result.success,
      domain,
      registrar: "godaddy",
      orderId: result.orderId,
      chargedAmount: result.total,
      currency: result.currency,
      error: result.error,
    };
  } else {
    return { success: false, domain, registrar, error: `Unknown registrar: ${registrar}` };
  }

  // Auto-configure phishing DNS if requested and purchase succeeded
  if (purchaseResult.success && request.autoConfigurePhishing && request.mailServerIp) {
    await new Promise((resolve) => setTimeout(resolve, 8000)); // Wait for DNS propagation

    const dnsResult = await configureDns({
      domain,
      registrar,
      mailServerIp: request.mailServerIp,
      dkimPublicKey: dkim?.publicKey,
    });

    purchaseResult.dnsConfigured = dnsResult.success;
    purchaseResult.dkim = dkim;
  }

  return purchaseResult;
}

/**
 * Purchase from the cheapest available registrar.
 */
export async function purchaseCheapest(
  domain: string,
  contact: RegistrantInfo,
  options?: { autoConfigurePhishing?: boolean; mailServerIp?: string }
): Promise<PurchaseResult> {
  const comparisons = await comparePricing([domain]);
  const comparison = comparisons[0];

  if (!comparison || comparison.prices[comparison.cheapest] === null) {
    return { success: false, domain, registrar: "namecheap", error: "Domain not available at any registrar" };
  }

  return purchaseDomain({
    domain,
    registrar: comparison.cheapest,
    contact,
    autoConfigurePhishing: options?.autoConfigurePhishing,
    mailServerIp: options?.mailServerIp,
  });
}

// ─── DNS Configuration ───────────────────────────────────────────────────────

/**
 * Configure DNS for phishing on a domain (works with either registrar).
 */
export async function configureDns(params: {
  domain: string;
  registrar: RegistrarId;
  mailServerIp: string;
  dkimSelector?: string;
  dkimPublicKey?: string;
}): Promise<DnsConfigResult> {
  const { domain, registrar, mailServerIp, dkimSelector = "default", dkimPublicKey } = params;

  let dkim: DkimKeypair | undefined;
  let pubKey = dkimPublicKey;

  // Generate DKIM if not provided
  if (!pubKey) {
    dkim = generateDkimKeypair(domain, dkimSelector);
    pubKey = dkim.publicKey;
  }

  if (registrar === "namecheap") {
    const result = await namecheap.configureForPhishing(domain, mailServerIp, dkimSelector, pubKey);
    return {
      success: result.success,
      domain,
      registrar: "namecheap",
      recordsSet: result.recordsSet,
      dkim,
      error: result.error,
    };
  } else if (registrar === "godaddy") {
    const result = await godaddy.configureForPhishing(domain, mailServerIp, dkimSelector, pubKey);
    return {
      success: result.success,
      domain,
      registrar: "godaddy",
      recordsSet: result.recordsSet,
      dkim,
      error: result.error,
    };
  }

  return { success: false, domain, registrar, recordsSet: 0, error: `Unknown registrar: ${registrar}` };
}
