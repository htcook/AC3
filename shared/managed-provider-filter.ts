/**
 * Asset Ownership Filter — Enhanced with Comprehensive Vendor Infrastructure Taxonomy
 *
 * Determines whether a discovered asset belongs to the client's attack surface
 * or is managed by a third-party vendor (ISP, web host, IaaS, PaaS, SaaS, CDN, etc.).
 *
 * Now includes:
 * - Full vendor infrastructure taxonomy (100+ vendors across 15 categories)
 * - Three-tier risk responsibility model (vendor / shared / customer)
 * - CNAME-based vendor detection
 * - Supply chain concentration risk scoring
 *
 * Consumed by:
 *   - server/domainIntel.ts (pipeline risk score calc)
 *   - server/lib/llm-post-enrichment-analysis.ts
 *   - client/src/lib/export-di-report.ts
 *   - client/src/pages/domain-intel-tabs/VendorRiskTab.tsx
 *
 * Usage (server-side):
 *   import { createAssetOwnershipFilter } from '../../shared/managed-provider-filter';
 *   const filter = createAssetOwnershipFilter({ managedProviderName, primaryDomain });
 *   filter.isClientOwned({ hostname, tags }); // backward compatible
 *   filter.classifyEnhanced({ hostname, tags, cnames }); // new enhanced classification
 *
 * Usage (client-side):
 *   import { createAssetOwnershipFilter, MANAGED_HOST_PATTERNS } from '../../../shared/managed-provider-filter';
 */

import {
  classifyVendor,
  partitionByResponsibility,
  computeVendorConcentrationRisk,
  getRiskResponsibilityLabel,
  getCategoryLabel,
  VENDOR_REGISTRY,
  type VendorClassification,
  type VendorCategory,
  type RiskResponsibility,
  type VendorDefinition,
} from './vendor-infrastructure-taxonomy';

// Re-export taxonomy types for consumers
export type { VendorClassification, VendorCategory, RiskResponsibility, VendorDefinition };
export {
  classifyVendor,
  partitionByResponsibility,
  computeVendorConcentrationRisk,
  getRiskResponsibilityLabel,
  getCategoryLabel,
  VENDOR_REGISTRY,
};

// ─── Legacy Managed Provider Host Patterns (backward compat) ────────────────
// These are now derived from the taxonomy but kept for API compatibility.
export const MANAGED_HOST_PATTERNS: Record<string, RegExp[]> = {
  'Microsoft 365': [
    /outlook\.com$/i,
    /microsoft\.com$/i,
    /office365/i,
    /protection\.outlook/i,
    /microsoftonline\.com$/i,
    /onmicrosoft\.com$/i,
  ],
  'Google Workspace': [
    /google\.com$/i,
    /gmail\.com$/i,
    /googlemail/i,
    /aspmx\.l\.google\.com$/i,
    /googlehosted\.com$/i,
  ],
  'Proofpoint': [/proofpoint/i, /pphosted\.com$/i],
  'Mimecast': [/mimecast/i],
  'Zoho Mail': [/zoho/i, /zohomail\.com$/i],
  'Barracuda': [/barracuda/i, /barracudanetworks/i],
  'Cisco Email Security': [/iphmx\.com$/i, /ironport/i],
  'SendGrid': [/sendgrid/i],
  'Mailchimp': [/mailchimp/i, /mandrillapp/i],
  'Amazon SES': [/amazonses/i, /ses\.amazonaws/i],
  'SpamExperts': [/spamexperts/i, /antispamcloud/i, /mailassure/i],
};

// ─── Types ──────────────────────────────────────────────────────────────────

/** Minimal asset shape required for ownership classification. */
export interface AssetForOwnershipCheck {
  hostname: string;
  tags?: string[];
  cnames?: string[];
  asn?: number;
}

/** Options for creating the ownership filter. */
export interface OwnershipFilterOptions {
  /** Name of the detected managed mail provider (e.g. 'Microsoft 365'). */
  managedProviderName?: string | null;
  /** The client's primary domain (e.g. 'aceofcloud.com'). */
  primaryDomain: string;
  /** Additional domains owned by the client (for multi-domain orgs). */
  additionalDomains?: string[];
}

/** Result of the ownership classification for a single asset (legacy). */
export interface OwnershipResult {
  isClientOwned: boolean;
  exclusionReason?: 'managed_provider' | 'reverse_whois_third_party' | 'vendor_infrastructure';
}

/** Enhanced classification result with full vendor details. */
export interface EnhancedOwnershipResult extends OwnershipResult {
  vendorClassification: VendorClassification;
  riskResponsibility: RiskResponsibility;
  /** What the customer is still responsible for on this vendor's infra */
  customerResponsibilities?: string[];
  /** Risk multiplier: 1.0 = full risk, 0.5 = shared, 0.0 = vendor-managed */
  riskMultiplier: number;
}

/** The filter object returned by createAssetOwnershipFilter. */
export interface AssetOwnershipFilter {
  /** Returns true if the asset belongs to the client's attack surface (backward compat). */
  isClientOwned: (asset: AssetForOwnershipCheck) => boolean;
  /** Returns the full classification with exclusion reason (backward compat). */
  classify: (asset: AssetForOwnershipCheck) => OwnershipResult;
  /** Enhanced classification with vendor details and risk responsibility. */
  classifyEnhanced: (asset: AssetForOwnershipCheck) => EnhancedOwnershipResult;
  /** The managed provider name, if detected. */
  managedProviderName: string | null;
  /** The regex patterns used for managed provider host matching. */
  managedPatterns: RegExp[];
}

// ─── Factory ────────────────────────────────────────────────────────────────

/**
 * Creates a reusable filter for classifying assets as client-owned vs
 * managed-provider / third-party infrastructure.
 *
 * Enhanced Classification rules (in priority order):
 * 1. If the hostname matches a managed email provider pattern → managed_provider (vendor_responsibility)
 * 2. If the hostname/CNAME matches vendor infrastructure taxonomy → vendor_infrastructure
 *    - vendor_responsibility: fully excluded from customer risk
 *    - shared_responsibility: partial risk (config issues attributed to customer)
 * 3. If the asset has both 'reverse_whois' and 'related_domain' tags AND
 *    the hostname does NOT contain the client's primary domain base → reverse_whois_third_party
 * 4. Otherwise → client-owned (customer_responsibility)
 */
export function createAssetOwnershipFilter(
  opts: OwnershipFilterOptions
): AssetOwnershipFilter {
  const mpName = opts.managedProviderName || null;
  const managedPatterns =
    mpName && MANAGED_HOST_PATTERNS[mpName]
      ? MANAGED_HOST_PATTERNS[mpName]
      : [];

  // Extract the base domain name without TLD for substring matching.
  // e.g. 'aceofcloud.com' → 'aceofcloud'
  const primaryBase = opts.primaryDomain
    .toLowerCase()
    .replace(/\.[^.]+$/, '');

  // Build set of all client domain bases for multi-domain orgs
  const clientDomainBases = new Set<string>([primaryBase]);
  if (opts.additionalDomains) {
    for (const d of opts.additionalDomains) {
      clientDomainBases.add(d.toLowerCase().replace(/\.[^.]+$/, ''));
    }
  }

  // Check if hostname belongs to client's domain family
  function isClientDomain(hostname: string): boolean {
    const h = hostname.toLowerCase();
    for (const base of clientDomainBases) {
      if (h.includes(base)) return true;
    }
    return false;
  }

  function classifyEnhanced(asset: AssetForOwnershipCheck): EnhancedOwnershipResult {
    const h = (asset.hostname || '').toLowerCase();
    const tags: string[] = asset.tags || [];

    // Rule 1: Managed email provider hostname match (highest priority)
    if (managedPatterns.some((p) => p.test(h))) {
      const vendorClass = classifyVendor({ hostname: h, cnames: asset.cnames, tags, asn: asset.asn });
      return {
        isClientOwned: false,
        exclusionReason: 'managed_provider',
        vendorClassification: vendorClass,
        riskResponsibility: 'vendor_responsibility',
        customerResponsibilities: vendorClass.vendor?.customerResponsibilities,
        riskMultiplier: 0,
      };
    }

    // Rule 2: Vendor infrastructure taxonomy match
    const vendorClass = classifyVendor({
      hostname: h,
      cnames: asset.cnames,
      tags,
      asn: asset.asn,
    });

    if (vendorClass.vendor && vendorClass.riskResponsibility !== 'customer_responsibility') {
      // Check if this is the customer's own domain hosted on vendor infra
      // e.g., "app.aceofcloud.com" CNAMEd to Cloudflare is still customer's asset
      if (isClientDomain(h)) {
        // Customer's domain on vendor infrastructure = shared responsibility
        // The asset IS in the customer's attack surface, but some risk is vendor's
        return {
          isClientOwned: true, // Still in customer's scope
          vendorClassification: vendorClass,
          riskResponsibility: 'shared_responsibility',
          customerResponsibilities: vendorClass.vendor?.customerResponsibilities,
          riskMultiplier: 0.6, // 60% risk attribution to customer (config issues)
        };
      }

      // Pure vendor hostname (e.g., "mail.protection.outlook.com")
      const isVendorManaged = vendorClass.riskResponsibility === 'vendor_responsibility';
      return {
        isClientOwned: false,
        exclusionReason: 'vendor_infrastructure',
        vendorClassification: vendorClass,
        riskResponsibility: vendorClass.riskResponsibility,
        customerResponsibilities: vendorClass.vendor?.customerResponsibilities,
        riskMultiplier: isVendorManaged ? 0 : 0.4, // shared = 40% to customer
      };
    }

    // Rule 3: Reverse WHOIS third-party (not related to client domain)
    const isReverseWhoisThirdParty =
      tags.includes('reverse_whois') &&
      tags.includes('related_domain') &&
      !isClientDomain(h);

    if (isReverseWhoisThirdParty) {
      return {
        isClientOwned: false,
        exclusionReason: 'reverse_whois_third_party',
        vendorClassification: vendorClass,
        riskResponsibility: 'customer_responsibility', // Unknown third party — flag for review
        riskMultiplier: 0,
      };
    }

    // Rule 4: Client-owned (full risk attribution)
    return {
      isClientOwned: true,
      vendorClassification: vendorClass,
      riskResponsibility: 'customer_responsibility',
      riskMultiplier: 1.0,
    };
  }

  function classify(asset: AssetForOwnershipCheck): OwnershipResult {
    const result = classifyEnhanced(asset);
    return {
      isClientOwned: result.isClientOwned,
      exclusionReason: result.exclusionReason,
    };
  }

  function isClientOwned(asset: AssetForOwnershipCheck): boolean {
    return classify(asset).isClientOwned;
  }

  return {
    isClientOwned,
    classify,
    classifyEnhanced,
    managedProviderName: mpName,
    managedPatterns,
  };
}

/**
 * Convenience: given a list of items that each wrap an asset, partition them
 * into client-owned and excluded arrays. (Backward compatible)
 */
export function partitionByOwnership<T>(
  items: T[],
  getAsset: (item: T) => AssetForOwnershipCheck,
  filter: AssetOwnershipFilter
): { clientOwned: T[]; excluded: T[] } {
  const clientOwned: T[] = [];
  const excluded: T[] = [];
  for (const item of items) {
    if (filter.isClientOwned(getAsset(item))) {
      clientOwned.push(item);
    } else {
      excluded.push(item);
    }
  }
  return { clientOwned, excluded };
}

/**
 * Enhanced partition: separates into three buckets with full classification details.
 */
export function partitionByOwnershipEnhanced<T>(
  items: T[],
  getAsset: (item: T) => AssetForOwnershipCheck,
  filter: AssetOwnershipFilter
): {
  customerOwned: T[];
  vendorManaged: T[];
  sharedResponsibility: T[];
  classifications: Map<T, EnhancedOwnershipResult>;
} {
  const customerOwned: T[] = [];
  const vendorManaged: T[] = [];
  const sharedResponsibility: T[] = [];
  const classifications = new Map<T, EnhancedOwnershipResult>();

  for (const item of items) {
    const asset = getAsset(item);
    const result = filter.classifyEnhanced(asset);
    classifications.set(item, result);

    if (result.riskResponsibility === 'vendor_responsibility' || result.exclusionReason === 'reverse_whois_third_party') {
      vendorManaged.push(item);
    } else if (result.riskResponsibility === 'shared_responsibility') {
      sharedResponsibility.push(item);
    } else {
      customerOwned.push(item);
    }
  }

  return { customerOwned, vendorManaged, sharedResponsibility, classifications };
}

/**
 * Compute risk-adjusted score based on vendor responsibility.
 * Used in the DI pipeline to properly attribute risk.
 */
export function computeAdjustedRiskScore(
  rawScore: number,
  classification: EnhancedOwnershipResult
): number {
  return Math.round(rawScore * classification.riskMultiplier);
}

/**
 * Generate a vendor risk summary for reports.
 */
export function generateVendorRiskSummary(
  classifications: Map<any, EnhancedOwnershipResult>
): {
  totalAssets: number;
  customerOwnedCount: number;
  vendorManagedCount: number;
  sharedCount: number;
  vendorBreakdown: { vendor: string; category: string; count: number; responsibility: string }[];
  concentrationRisk: { score: number; band: string; topVendors: { name: string; count: number; percentage: number }[] };
} {
  let customerOwnedCount = 0;
  let vendorManagedCount = 0;
  let sharedCount = 0;
  const vendorCounts = new Map<string, { category: string; count: number; responsibility: string }>();
  const allClassifications: VendorClassification[] = [];

  for (const [, result] of classifications) {
    allClassifications.push(result.vendorClassification);

    if (result.riskResponsibility === 'customer_responsibility' && result.isClientOwned) {
      customerOwnedCount++;
    } else if (result.riskResponsibility === 'vendor_responsibility') {
      vendorManagedCount++;
    } else {
      sharedCount++;
    }

    if (result.vendorClassification.vendor) {
      const vName = result.vendorClassification.vendor.name;
      const existing = vendorCounts.get(vName);
      if (existing) {
        existing.count++;
      } else {
        vendorCounts.set(vName, {
          category: getCategoryLabel(result.vendorClassification.category!),
          count: 1,
          responsibility: getRiskResponsibilityLabel(result.riskResponsibility),
        });
      }
    }
  }

  const vendorBreakdown = Array.from(vendorCounts.entries())
    .map(([vendor, data]) => ({ vendor, ...data }))
    .sort((a, b) => b.count - a.count);

  const concentrationRisk = computeVendorConcentrationRisk(allClassifications);

  return {
    totalAssets: classifications.size,
    customerOwnedCount,
    vendorManagedCount,
    sharedCount,
    vendorBreakdown,
    concentrationRisk,
  };
}
