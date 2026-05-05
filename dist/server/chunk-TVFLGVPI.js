import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/managed-provider-filter.ts
function createAssetOwnershipFilter(opts) {
  const mpName = opts.managedProviderName || null;
  const managedPatterns = mpName && MANAGED_HOST_PATTERNS[mpName] ? MANAGED_HOST_PATTERNS[mpName] : [];
  const primaryBase = opts.primaryDomain.toLowerCase().replace(/\.[^.]+$/, "");
  function classify(asset) {
    const h = (asset.hostname || "").toLowerCase();
    const tags = asset.tags || [];
    if (managedPatterns.some((p) => p.test(h))) {
      return { isClientOwned: false, exclusionReason: "managed_provider" };
    }
    const isReverseWhoisThirdParty = tags.includes("reverse_whois") && tags.includes("related_domain") && !h.includes(primaryBase);
    if (isReverseWhoisThirdParty) {
      return {
        isClientOwned: false,
        exclusionReason: "reverse_whois_third_party"
      };
    }
    return { isClientOwned: true };
  }
  function isClientOwned(asset) {
    return classify(asset).isClientOwned;
  }
  return {
    isClientOwned,
    classify,
    managedProviderName: mpName,
    managedPatterns
  };
}
function partitionByOwnership(items, getAsset, filter) {
  const clientOwned = [];
  const excluded = [];
  for (const item of items) {
    if (filter.isClientOwned(getAsset(item))) {
      clientOwned.push(item);
    } else {
      excluded.push(item);
    }
  }
  return { clientOwned, excluded };
}
var MANAGED_HOST_PATTERNS;
var init_managed_provider_filter = __esm({
  "shared/managed-provider-filter.ts"() {
    MANAGED_HOST_PATTERNS = {
      "Microsoft 365": [
        /outlook\.com$/i,
        /microsoft\.com$/i,
        /office365/i,
        /protection\.outlook/i
      ],
      "Google Workspace": [
        /google\.com$/i,
        /gmail\.com$/i,
        /googlemail/i
      ],
      "Proofpoint": [/proofpoint/i],
      "Mimecast": [/mimecast/i],
      "Zoho Mail": [/zoho/i]
    };
  }
});

export {
  MANAGED_HOST_PATTERNS,
  createAssetOwnershipFilter,
  partitionByOwnership,
  init_managed_provider_filter
};
