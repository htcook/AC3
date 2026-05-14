import {
  classifyVendor,
  computeVendorConcentrationRisk,
  getCategoryLabel,
  getRiskResponsibilityLabel,
  init_vendor_infrastructure_taxonomy
} from "./chunk-E64FO4YW.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/managed-provider-filter.ts
function createAssetOwnershipFilter(opts) {
  const mpName = opts.managedProviderName || null;
  const managedPatterns = mpName && MANAGED_HOST_PATTERNS[mpName] ? MANAGED_HOST_PATTERNS[mpName] : [];
  const primaryBase = opts.primaryDomain.toLowerCase().replace(/\.[^.]+$/, "");
  const clientDomainBases = /* @__PURE__ */ new Set([primaryBase]);
  if (opts.additionalDomains) {
    for (const d of opts.additionalDomains) {
      clientDomainBases.add(d.toLowerCase().replace(/\.[^.]+$/, ""));
    }
  }
  function isClientDomain(hostname) {
    const h = hostname.toLowerCase();
    for (const base of clientDomainBases) {
      if (h.includes(base)) return true;
    }
    return false;
  }
  function classifyEnhanced(asset) {
    const h = (asset.hostname || "").toLowerCase();
    const tags = asset.tags || [];
    if (managedPatterns.some((p) => p.test(h))) {
      const vendorClass2 = classifyVendor({ hostname: h, cnames: asset.cnames, tags, asn: asset.asn });
      return {
        isClientOwned: false,
        exclusionReason: "managed_provider",
        vendorClassification: vendorClass2,
        riskResponsibility: "vendor_responsibility",
        customerResponsibilities: vendorClass2.vendor?.customerResponsibilities,
        riskMultiplier: 0
      };
    }
    const vendorClass = classifyVendor({
      hostname: h,
      cnames: asset.cnames,
      tags,
      asn: asset.asn
    });
    if (vendorClass.vendor && vendorClass.riskResponsibility !== "customer_responsibility") {
      if (isClientDomain(h)) {
        return {
          isClientOwned: true,
          // Still in customer's scope
          vendorClassification: vendorClass,
          riskResponsibility: "shared_responsibility",
          customerResponsibilities: vendorClass.vendor?.customerResponsibilities,
          riskMultiplier: 0.6
          // 60% risk attribution to customer (config issues)
        };
      }
      const isVendorManaged = vendorClass.riskResponsibility === "vendor_responsibility";
      return {
        isClientOwned: false,
        exclusionReason: "vendor_infrastructure",
        vendorClassification: vendorClass,
        riskResponsibility: vendorClass.riskResponsibility,
        customerResponsibilities: vendorClass.vendor?.customerResponsibilities,
        riskMultiplier: isVendorManaged ? 0 : 0.4
        // shared = 40% to customer
      };
    }
    const isReverseWhoisThirdParty = tags.includes("reverse_whois") && tags.includes("related_domain") && !isClientDomain(h);
    if (isReverseWhoisThirdParty) {
      return {
        isClientOwned: false,
        exclusionReason: "reverse_whois_third_party",
        vendorClassification: vendorClass,
        riskResponsibility: "customer_responsibility",
        // Unknown third party — flag for review
        riskMultiplier: 0
      };
    }
    return {
      isClientOwned: true,
      vendorClassification: vendorClass,
      riskResponsibility: "customer_responsibility",
      riskMultiplier: 1
    };
  }
  function classify(asset) {
    const result = classifyEnhanced(asset);
    return {
      isClientOwned: result.isClientOwned,
      exclusionReason: result.exclusionReason
    };
  }
  function isClientOwned(asset) {
    return classify(asset).isClientOwned;
  }
  return {
    isClientOwned,
    classify,
    classifyEnhanced,
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
function partitionByOwnershipEnhanced(items, getAsset, filter) {
  const customerOwned = [];
  const vendorManaged = [];
  const sharedResponsibility = [];
  const classifications = /* @__PURE__ */ new Map();
  for (const item of items) {
    const asset = getAsset(item);
    const result = filter.classifyEnhanced(asset);
    classifications.set(item, result);
    if (result.riskResponsibility === "vendor_responsibility" || result.exclusionReason === "reverse_whois_third_party") {
      vendorManaged.push(item);
    } else if (result.riskResponsibility === "shared_responsibility") {
      sharedResponsibility.push(item);
    } else {
      customerOwned.push(item);
    }
  }
  return { customerOwned, vendorManaged, sharedResponsibility, classifications };
}
function computeAdjustedRiskScore(rawScore, classification) {
  return Math.round(rawScore * classification.riskMultiplier);
}
function generateVendorRiskSummary(classifications) {
  let customerOwnedCount = 0;
  let vendorManagedCount = 0;
  let sharedCount = 0;
  const vendorCounts = /* @__PURE__ */ new Map();
  const allClassifications = [];
  for (const [, result] of classifications) {
    allClassifications.push(result.vendorClassification);
    if (result.riskResponsibility === "customer_responsibility" && result.isClientOwned) {
      customerOwnedCount++;
    } else if (result.riskResponsibility === "vendor_responsibility") {
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
          category: getCategoryLabel(result.vendorClassification.category),
          count: 1,
          responsibility: getRiskResponsibilityLabel(result.riskResponsibility)
        });
      }
    }
  }
  const vendorBreakdown = Array.from(vendorCounts.entries()).map(([vendor, data]) => ({ vendor, ...data })).sort((a, b) => b.count - a.count);
  const concentrationRisk = computeVendorConcentrationRisk(allClassifications);
  return {
    totalAssets: classifications.size,
    customerOwnedCount,
    vendorManagedCount,
    sharedCount,
    vendorBreakdown,
    concentrationRisk
  };
}
var MANAGED_HOST_PATTERNS;
var init_managed_provider_filter = __esm({
  "shared/managed-provider-filter.ts"() {
    init_vendor_infrastructure_taxonomy();
    MANAGED_HOST_PATTERNS = {
      "Microsoft 365": [
        /outlook\.com$/i,
        /microsoft\.com$/i,
        /office365/i,
        /protection\.outlook/i,
        /microsoftonline\.com$/i,
        /onmicrosoft\.com$/i
      ],
      "Google Workspace": [
        /google\.com$/i,
        /gmail\.com$/i,
        /googlemail/i,
        /aspmx\.l\.google\.com$/i,
        /googlehosted\.com$/i
      ],
      "Proofpoint": [/proofpoint/i, /pphosted\.com$/i],
      "Mimecast": [/mimecast/i],
      "Zoho Mail": [/zoho/i, /zohomail\.com$/i],
      "Barracuda": [/barracuda/i, /barracudanetworks/i],
      "Cisco Email Security": [/iphmx\.com$/i, /ironport/i],
      "SendGrid": [/sendgrid/i],
      "Mailchimp": [/mailchimp/i, /mandrillapp/i],
      "Amazon SES": [/amazonses/i, /ses\.amazonaws/i],
      "SpamExperts": [/spamexperts/i, /antispamcloud/i, /mailassure/i]
    };
  }
});

export {
  MANAGED_HOST_PATTERNS,
  createAssetOwnershipFilter,
  partitionByOwnership,
  partitionByOwnershipEnhanced,
  computeAdjustedRiskScore,
  generateVendorRiskSummary,
  init_managed_provider_filter
};
