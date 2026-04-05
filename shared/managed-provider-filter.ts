/**
 * Shared utility for identifying managed provider and third-party assets.
 *
 * Centralises the host-pattern matching that was previously duplicated across:
 *   - server/domainIntel.ts  (generateScanOnlySummary, generateSummaries, risk score calc)
 *   - server/lib/llm-post-enrichment-analysis.ts
 *   - client/src/lib/export-di-report.ts
 *
 * Usage (server-side):
 *   import { createAssetOwnershipFilter } from '../../shared/managed-provider-filter';
 *   const { isClientOwned } = createAssetOwnershipFilter({ managedProviderName, primaryDomain });
 *
 * Usage (client-side):
 *   import { createAssetOwnershipFilter, MANAGED_HOST_PATTERNS } from '../../../shared/managed-provider-filter';
 */

// ─── Managed Provider Host Patterns ─────────────────────────────────────────
// Maps a managed provider name to an array of hostname regex patterns.
// When a discovered asset's hostname matches any pattern for the detected
// managed provider, it is classified as provider-managed infrastructure.

export const MANAGED_HOST_PATTERNS: Record<string, RegExp[]> = {
  'Microsoft 365': [
    /outlook\.com$/i,
    /microsoft\.com$/i,
    /office365/i,
    /protection\.outlook/i,
  ],
  'Google Workspace': [
    /google\.com$/i,
    /gmail\.com$/i,
    /googlemail/i,
  ],
  'Proofpoint': [/proofpoint/i],
  'Mimecast': [/mimecast/i],
  'Zoho Mail': [/zoho/i],
};

// ─── Types ──────────────────────────────────────────────────────────────────

/** Minimal asset shape required for ownership classification. */
export interface AssetForOwnershipCheck {
  hostname: string;
  tags?: string[];
}

/** Options for creating the ownership filter. */
export interface OwnershipFilterOptions {
  /** Name of the detected managed mail provider (e.g. 'Microsoft 365'). */
  managedProviderName?: string | null;
  /** The client's primary domain (e.g. 'aceofcloud.com'). */
  primaryDomain: string;
}

/** Result of the ownership classification for a single asset. */
export interface OwnershipResult {
  isClientOwned: boolean;
  exclusionReason?: 'managed_provider' | 'reverse_whois_third_party';
}

/** The filter object returned by createAssetOwnershipFilter. */
export interface AssetOwnershipFilter {
  /** Returns true if the asset belongs to the client's attack surface. */
  isClientOwned: (asset: AssetForOwnershipCheck) => boolean;
  /** Returns the full classification with exclusion reason. */
  classify: (asset: AssetForOwnershipCheck) => OwnershipResult;
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
 * Classification rules:
 * 1. If the hostname matches a managed provider pattern → managed_provider
 * 2. If the asset has both 'reverse_whois' and 'related_domain' tags AND
 *    the hostname does NOT contain the client's primary domain base → reverse_whois_third_party
 * 3. Otherwise → client-owned
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

  function classify(asset: AssetForOwnershipCheck): OwnershipResult {
    const h = (asset.hostname || '').toLowerCase();
    const tags: string[] = asset.tags || [];

    // Rule 1: Managed provider hostname match
    if (managedPatterns.some((p) => p.test(h))) {
      return { isClientOwned: false, exclusionReason: 'managed_provider' };
    }

    // Rule 2: Reverse WHOIS third-party (not related to client domain)
    const isReverseWhoisThirdParty =
      tags.includes('reverse_whois') &&
      tags.includes('related_domain') &&
      !h.includes(primaryBase);
    if (isReverseWhoisThirdParty) {
      return {
        isClientOwned: false,
        exclusionReason: 'reverse_whois_third_party',
      };
    }

    // Rule 3: Client-owned
    return { isClientOwned: true };
  }

  function isClientOwned(asset: AssetForOwnershipCheck): boolean {
    return classify(asset).isClientOwned;
  }

  return {
    isClientOwned,
    classify,
    managedProviderName: mpName,
    managedPatterns,
  };
}

/**
 * Convenience: given a list of items that each wrap an asset, partition them
 * into client-owned and excluded arrays.
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
