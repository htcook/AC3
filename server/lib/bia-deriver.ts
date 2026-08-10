/**
 * BIA Deriver — turn DI discovery evidence into an evidence-grounded Business
 * Impact Analysis record (FIPS 199 CIA categorization + business-impact level +
 * data classification + availability tier).
 *
 * WHY: the hybrid scoring engine already consumes `fips199` and
 * `businessImpactLevel` (scoring-engine.ts §4 / Layer 4) and bia-report-generator
 * already renders FIPS 199 system categorization — but today those inputs are
 * re-inferred by the scorer's own LLM from thin context, NOT grounded in the
 * rich signals the DI scan already collects (regulatory exposure, revenue path,
 * asset role, dependency edges, data-handling signals, HA topology).
 *
 * This module consolidates that DI evidence into ONE provisional BIA record that
 * feeds both consumers via the adapters at the bottom:
 *   - biaToScoringInputs()  → { fips199Category, businessImpactLevel }  (Layer 4)
 *   - biaToReportInputs()   → subset for bia-report-generator's BiaAssetInput
 *
 * DESIGN: deterministic + explainable baseline (this file). It mirrors the
 * engine's "deterministic baseline, optional bounded-LLM delta" pattern — an LLM
 * refinement can wrap `deriveAssetBia()` later and nudge within bounds; the
 * baseline always stands on its own and every field carries a rationale.
 *
 * GOVERNANCE: a DI-derived categorization is a PROVISIONAL, evidence-cited DRAFT
 * for the ISSO/AO to confirm — never an authoritative FIPS 199 categorization.
 * `confidence` is capped below 1.0 to reflect that, and `rationale` exists so the
 * draft can be cited (and overridden) downstream.
 *
 * Pure (no I/O) → unit-testable in isolation.
 */

export type ImpactLevel = "low" | "moderate" | "high";

export interface Fips199 {
  confidentiality: ImpactLevel;
  integrity: ImpactLevel;
  availability: ImpactLevel;
}

// Matches scoring-engine.ts BUSINESS_IMPACT_LEVELS.
export type BusinessImpactLevel =
  | "mission_critical"
  | "business_essential"
  | "operational"
  | "administrative";

export type DataClass =
  | "PHI"
  | "PCI"
  | "CUI"
  | "FTI"
  | "PII"
  | "financial"
  | "credentials"
  | "public";

/** DI evidence bundle. All fields optional — derivation degrades gracefully. */
export interface BiaEvidence {
  /** Regulatory frameworks from the business-context specialist (e.g. "HIPAA", "PCI-DSS", "CMMC"). */
  regulatoryFrameworks?: string[];
  /** Revenue path from the business-context specialist. */
  revenuePath?: "direct" | "supporting" | "internal" | "unknown";
  /** Free-text asset function/role (business-context `function`). */
  assetFunction?: string;
  /** Normalized asset role hint if known (e.g. "identity_provider", "payment", "marketing"). */
  assetRole?: string;
  /** How many other assets depend on this one (dependency in-degree). */
  dependencyInDegree?: number;
  /** Concatenated tech/URL/service/header signal string from discovery-context. */
  signals?: string;
  /** Availability / HA topology signals. */
  aRecordCount?: number;
  hasCdn?: boolean;
  multiRegion?: boolean;
  loadBalanced?: boolean;
  internetExposed?: boolean;
}

export interface AssetBiaRecord {
  fips199: Fips199;
  /** High-water mark across the CIA triad (FIPS 200 system categorization input). */
  overall: ImpactLevel;
  businessImpactLevel: BusinessImpactLevel;
  dataClassification: DataClass[];
  /** 1 (highest availability need / shortest RTO) … 4 (lowest). Feeds bia-report-generator.deriveRtoRpo. */
  availabilityTier: 1 | 2 | 3 | 4;
  /** 0–1; capped below 1 — this is a provisional, evidence-derived draft. */
  confidence: number;
  mode: "deterministic" | "refined";
  rationale: {
    confidentiality: string;
    integrity: string;
    availability: string;
    businessImpact: string;
  };
  provenance: { signalsUsed: string[] };
}

const RANK: Record<ImpactLevel, number> = { low: 0, moderate: 1, high: 2 };
const LEVELS: ImpactLevel[] = ["low", "moderate", "high"];
const maxLevel = (a: ImpactLevel, b: ImpactLevel): ImpactLevel => (RANK[a] >= RANK[b] ? a : b);
const highWaterMark = (levels: ImpactLevel[]): ImpactLevel =>
  levels.reduce((acc, l) => maxLevel(acc, l), "low" as ImpactLevel);

function haystack(e: BiaEvidence): string {
  return [
    (e.regulatoryFrameworks || []).join(" "),
    e.assetFunction || "",
    e.assetRole || "",
    e.signals || "",
  ]
    .join(" ")
    .toLowerCase();
}

/** Detect data classes from regulatory + signal evidence. */
function classifyData(h: string): DataClass[] {
  const out = new Set<DataClass>();
  if (/hipaa|\bphi\b|health|patient|clinical|ehr|hl7/.test(h)) out.add("PHI");
  if (/pci|payment|card|checkout|stripe|braintree|adyen|cardholder/.test(h)) out.add("PCI");
  if (/cmmc|dfars|itar|\bcui\b|controlled unclassified/.test(h)) out.add("CUI");
  if (/\bfti\b|irs|1075|tax return/.test(h)) out.add("FTI");
  if (/\bsox\b|ledger|general.?ledger|financial.?report|10-?k|earnings/.test(h)) out.add("financial");
  if (/auth|login|identity|\bsso\b|oauth|saml|ldap|active.?directory|entra|credential/.test(h))
    out.add("credentials");
  if (/gdpr|ccpa|\bpii\b|personal.?data|customer.?data|\bemail\b|\bssn\b|user.?account/.test(h))
    out.add("PII");
  if (out.size === 0 && /marketing|brochure|landing|public|cdn|static/.test(h)) out.add("public");
  return [...out];
}

/**
 * Derive a provisional, evidence-grounded BIA record from DI discovery evidence.
 * Deterministic and explainable; every dimension carries a rationale.
 */
export function deriveAssetBia(e: BiaEvidence): AssetBiaRecord {
  const h = haystack(e);
  const dataClassification = classifyData(h);
  const dc = new Set(dataClassification);
  const signalsUsed: string[] = [];
  if (e.regulatoryFrameworks?.length) signalsUsed.push("regulatory_exposure");
  if (e.revenuePath && e.revenuePath !== "unknown") signalsUsed.push("revenue_path");
  if (e.assetRole || e.assetFunction) signalsUsed.push("asset_role");
  if (typeof e.dependencyInDegree === "number") signalsUsed.push("dependency_in_degree");
  if (e.signals) signalsUsed.push("service_signals");
  if (e.aRecordCount || e.hasCdn || e.multiRegion || e.loadBalanced) signalsUsed.push("ha_topology");

  // ── Confidentiality ──
  let confidentiality: ImpactLevel = "low";
  let cReason = "No sensitive-data signals detected; treated as public/low.";
  if (dc.has("PHI") || dc.has("PCI") || dc.has("CUI") || dc.has("FTI")) {
    confidentiality = "high";
    cReason = `Handles regulated sensitive data (${[...dc].filter((d) => ["PHI", "PCI", "CUI", "FTI"].includes(d)).join(", ")}).`;
  } else if (dc.has("credentials") || /identity/.test(e.assetRole || "")) {
    confidentiality = "high";
    cReason = "Identity/authentication surface — credential exposure has broad downstream impact.";
  } else if (dc.has("PII") || dc.has("financial")) {
    confidentiality = "moderate";
    cReason = `Handles ${dc.has("PII") ? "PII" : "financial"} data.`;
  }

  // ── Integrity ──
  let integrity: ImpactLevel = "low";
  let iReason = "Static/informational surface; unauthorized modification has limited impact.";
  if (/payment|transaction|identity|ci.?cd|pipeline|config|iac|deploy|ledger|financial.?report/.test(h) ||
      dc.has("PCI") || dc.has("financial") || dc.has("credentials")) {
    integrity = "high";
    iReason = "Transaction/identity/config-plane surface — unauthorized modification has severe integrity impact.";
  } else if (/api|app|form|upload|database|record/.test(h) || [...dc].some((d) => d !== "public")) {
    integrity = "moderate";
    iReason = "Processes or stores data; modification has moderate impact.";
  }

  // ── Availability ──
  const haPresent = Boolean(e.hasCdn || e.multiRegion || e.loadBalanced || (e.aRecordCount ?? 0) > 1);
  let availability: ImpactLevel = "low";
  let aReason = "Internal/non-revenue surface; short outages tolerable.";
  if (e.revenuePath === "direct" || haPresent) {
    availability = "high";
    aReason = e.revenuePath === "direct"
      ? "Directly on the revenue path — outage causes direct business loss."
      : "Operated with high-availability topology (CDN/multi-region/LB), indicating the org treats loss as high-impact.";
  } else if (e.revenuePath === "supporting" || e.internetExposed) {
    availability = "moderate";
    aReason = "Supporting/customer-facing surface; outage has moderate impact.";
  }

  const fips199: Fips199 = { confidentiality, integrity, availability };
  const overall = highWaterMark([confidentiality, integrity, availability]);

  // ── Business impact level ──
  const role = (e.assetRole || "").toLowerCase();
  const isKeystone =
    /identity|idp|active.?directory|entra|sso|payment|auth/.test(role + " " + h) ||
    (e.dependencyInDegree ?? 0) >= 5;
  let businessImpactLevel: BusinessImpactLevel;
  let bReason: string;
  if (isKeystone || (overall === "high" && e.revenuePath === "direct")) {
    businessImpactLevel = "mission_critical";
    bReason = isKeystone
      ? "Keystone asset (identity/payment or high dependency in-degree) — cascading failure risk."
      : "High categorization on the direct revenue path.";
  } else if (e.revenuePath === "direct" || e.revenuePath === "supporting" || overall === "high") {
    businessImpactLevel = "business_essential";
    bReason = "Revenue-adjacent or high-impact but not a single point of cascade.";
  } else if (RANK[overall] >= RANK["moderate"] || e.internetExposed) {
    businessImpactLevel = "operational";
    bReason = "Internet-exposed or moderate-impact operational asset.";
  } else {
    businessImpactLevel = "administrative";
    bReason = "Low-impact administrative/informational asset.";
  }

  // ── Availability tier (1 highest → 4 lowest) for RTO/RPO ──
  let availabilityTier: 1 | 2 | 3 | 4 = 4;
  if (businessImpactLevel === "mission_critical" || availability === "high") availabilityTier = 1;
  else if (businessImpactLevel === "business_essential" || availability === "moderate") availabilityTier = 2;
  else if (businessImpactLevel === "operational") availabilityTier = 3;

  // ── Confidence: more independent signal categories → higher (capped, provisional) ──
  const confidence = Math.min(0.9, 0.35 + 0.09 * signalsUsed.length);

  return {
    fips199,
    overall,
    businessImpactLevel,
    dataClassification,
    availabilityTier,
    confidence,
    mode: "deterministic",
    rationale: { confidentiality: cReason, integrity: iReason, availability: aReason, businessImpact: bReason },
    provenance: { signalsUsed },
  };
}

// ─── Adapters — plug into existing consumers without editing them ─────────────

/** Layer 4 (scoring.ts reads asset.fips199Category + asset.businessImpactLevel). */
export function biaToScoringInputs(bia: AssetBiaRecord): {
  fips199Category: Fips199;
  businessImpactLevel: BusinessImpactLevel;
} {
  return { fips199Category: bia.fips199, businessImpactLevel: bia.businessImpactLevel };
}

/** Subset for bia-report-generator's BiaAssetInput. */
export function biaToReportInputs(bia: AssetBiaRecord): {
  fips199Category: Fips199;
  businessImpactLevel: string;
} {
  return { fips199Category: bia.fips199, businessImpactLevel: bia.businessImpactLevel };
}

export { highWaterMark };
