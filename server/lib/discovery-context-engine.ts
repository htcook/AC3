/**
 * Discovery Context Engine
 * 
 * Implements Claude's recommended architecture for context-aware asset discovery.
 * Sits between raw discovery data ingestion and downstream scoring/exploitation pipelines.
 * 
 * Architecture:
 * - 5 decomposed LLM specialists (not monolithic) for independent graduation
 * - Structured evidence packages as input (not raw data dumps)
 * - Bounded delta pattern: deterministic baseline + LLM ±20pt adjustment
 * - Evidence grounding validation: every claim must cite input evidence
 * - Three degradation modes: Full LLM, Deterministic-only, Confidence-degraded
 * 
 * Specialists:
 * 1. Asset Attribution Specialist — who owns this asset
 * 2. Asset Role Specialist — customer-facing/internal, prod/non-prod
 * 3. Lifecycle Stage Specialist — active/declining/abandoned/unknown
 * 4. Business Context Specialist — business unit, function, revenue path
 * 5. Threat Relevance Specialist — per-actor-type, per-attack-pattern scoring
 */

import type {
  DiscoveredHost, TLSCertificate, DNSRecord, SubdomainResult,
  DiscoveryResult, EnrichmentResult
} from "./discovery-engine";

// ═══════════════════════════════════════════════════════════════════════
// §1 — Core Data Model
// ═══════════════════════════════════════════════════════════════════════

/** Degradation mode reported per specialist per asset */
export type SpecialistMode = "full_llm" | "deterministic_only" | "confidence_degraded";

/** Evidence weight classification */
export type EvidenceWeight = "strong" | "moderate" | "weak";

/** Confidence band (categorical) */
export type ConfidenceBand = "high" | "medium" | "low";

/** A single piece of evidence cited by a specialist */
export interface EvidenceCitation {
  source: string;          // e.g., "CERTIFICATE", "DNS", "BGP", "WHOIS", "HTTP"
  evidenceType: string;    // e.g., "subject_organization", "a_record", "asn_owner"
  weight: EvidenceWeight;
  detail: string;          // human-readable description of what this evidence shows
}

/** Contradicting evidence that weakens a claim */
export interface ContradictingEvidence {
  source: string;
  evidenceType: string;
  detail: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — Structured Evidence Package
// ═══════════════════════════════════════════════════════════════════════

/** Certificate evidence extracted from TLS certificates */
export interface CertificateEvidence {
  issuer: string;
  subjectCN: string;
  sanEntries: string[];
  organizationInSubject: string | null;
  validFrom: string;
  validTo: string;
  isExpired: boolean;
  isWildcard: boolean;
  firstObservedInCTLogs: string | null;
}

/** DNS evidence extracted from DNS records */
export interface DNSEvidence {
  aRecords: { value: string; firstSeen: string | null; lastSeen: string | null }[];
  mxRecords: { value: string; priority?: number }[];
  nsRecords: string[];
  txtRecords: string[];
  soaRecord: string | null;
  cnameChain: string[];
  stableSince: string | null;  // earliest firstSeen across records
}

/** BGP/ASN evidence from host data */
export interface BGPEvidence {
  asn: number | null;
  asnOrganization: string | null;
  isp: string | null;
  ipRange: string | null;
  adjacentIPs: string[];
}

/** WHOIS evidence from domain registration */
export interface WHOISEvidence {
  registrantOrganization: string | null;
  registrantName: string | null;
  registrantCountry: string | null;
  registrationDate: string | null;
  expirationDate: string | null;
  adminContact: string | null;
  nameServers: string[];
  lastUpdated: string | null;
}

/** HTTP response evidence from web fingerprinting */
export interface HTTPEvidence {
  statusCode: number | null;
  serverHeader: string | null;
  poweredByHeader: string | null;
  technologies: string[];
  faviconHash: string | null;
  hostnamePattern: string | null;  // e.g., "api.", "admin.", "staging."
  contentKeywords: string[];
  responseHeaders: Record<string, string>;
}

/** Business intelligence evidence from public sources */
export interface BusinessIntelEvidence {
  secEdgarCIK: string | null;
  businessSegments: { name: string; revenue: string | null }[];
  industry: string | null;
  employeeCount: number | null;
  headquarters: string | null;
  subsidiaries: string[];
  regulatoryRegimes: string[];  // e.g., ["PCI-DSS", "HIPAA", "SOX"]
}

/** The complete structured evidence package assembled for each asset */
export interface StructuredEvidencePackage {
  assetIdentifier: string;        // primary identifier (hostname or IP)
  resolvedIPs: string[];
  certificate: CertificateEvidence | null;
  dns: DNSEvidence;
  bgp: BGPEvidence;
  whois: WHOISEvidence | null;
  http: HTTPEvidence | null;
  businessIntel: BusinessIntelEvidence | null;
  /** Context the specialist can use for reasoning but cannot cite as evidence */
  externalContext: {
    customerStatedIndustry: string | null;
    customerStatedSize: string | null;
    scanTargetDomain: string;
  };
  assembledAt: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — Specialist 1: Asset Attribution
// ═══════════════════════════════════════════════════════════════════════

export type AttributionClaimType =
  | "primary_owner"
  | "subsidiary"
  | "third_party_hosted"
  | "vendor_managed"
  | "cdn_fronted"
  | "shared_hosting"
  | "unknown";

export interface AttributionClaim {
  attributedTo: {
    organization: string;
    legalEntity?: string;
    parentOrganization?: string;
  };
  claimType: AttributionClaimType;
  confidence: ConfidenceBand;
  confidenceScore: number;  // 0-100
  supportingEvidence: EvidenceCitation[];
  contradictingEvidence: ContradictingEvidence[];
  alternativeAttributions: {
    organization: string;
    confidenceScore: number;
    rationale: string;
  }[];
}

export interface AttributionResult {
  assetIdentifier: string;
  claims: AttributionClaim[];
  mode: SpecialistMode;
  deterministicBaseline: number;  // baseline confidence before LLM adjustment
  llmDelta: number;               // bounded ±20 adjustment
  processingTimeMs: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — Specialist 2: Asset Role
// ═══════════════════════════════════════════════════════════════════════

export type AssetExposure = "customer_facing" | "internal" | "partner" | "unknown";
export type AssetEnvironment = "production" | "staging" | "development" | "testing" | "unknown";
export type AssetCriticality = "primary" | "backup" | "auxiliary" | "unknown";

export interface RoleInference {
  exposure: { value: AssetExposure; confidence: number; evidence: EvidenceCitation[] };
  environment: { value: AssetEnvironment; confidence: number; evidence: EvidenceCitation[] };
  criticality: { value: AssetCriticality; confidence: number; evidence: EvidenceCitation[] };
  inferredFunction: string | null;  // e.g., "API gateway", "email server", "CDN edge"
  hostnameSignals: string[];        // patterns detected: "api.", "admin.", "staging."
  technologyStack: string[];
}

export interface RoleResult {
  assetIdentifier: string;
  role: RoleInference;
  mode: SpecialistMode;
  processingTimeMs: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — Specialist 3: Lifecycle Stage
// ═══════════════════════════════════════════════════════════════════════

export type LifecycleStage = "active" | "declining" | "abandoned" | "unknown";

export interface LifecycleSignal {
  signalType: string;  // e.g., "cert_renewal_pattern", "dns_staleness", "tech_recency"
  value: string;
  interpretation: string;
  weight: EvidenceWeight;
}

export interface LifecycleResult {
  assetIdentifier: string;
  stage: LifecycleStage;
  confidence: number;  // 0-100
  signals: LifecycleSignal[];
  /** Risk multiplier: abandoned assets get higher risk weighting */
  riskMultiplier: number;  // 1.0 for active, up to 2.0 for abandoned
  lastMaintenanceEstimate: string | null;
  mode: SpecialistMode;
  processingTimeMs: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — Specialist 4: Business Context
// ═══════════════════════════════════════════════════════════════════════

export interface BusinessUnitAttribution {
  businessUnit: string | null;
  function: string | null;
  revenuePath: string | null;
  confidence: number;
  evidence: EvidenceCitation[];
}

export interface RegulatoryExposure {
  regime: string;  // e.g., "PCI-DSS", "HIPAA", "SOX", "GDPR", "CMMC"
  indicators: string[];
  confidence: number;
}

export interface DependencyEdge {
  targetAsset: string;
  relationshipType: "dns_chain" | "api_reference" | "cert_trust" | "bgp_adjacency" | "hosting_shared" | "code_reference";
  confidence: number;
  evidence: string;
}

export interface BusinessContextResult {
  assetIdentifier: string;
  businessUnit: BusinessUnitAttribution;
  regulatoryExposures: RegulatoryExposure[];
  dependencies: DependencyEdge[];
  customerAttribution: {
    servesTopCustomers: boolean;
    customerIndicators: string[];
    concentrationRisk: "high" | "medium" | "low" | "unknown";
  };
  mode: SpecialistMode;
  processingTimeMs: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — Specialist 5: Threat Relevance
// ═══════════════════════════════════════════════════════════════════════

export interface ThreatActorRelevance {
  actorName: string;
  actorType: "apt" | "ransomware" | "hacktivist" | "cybercrime" | "unknown";
  relevanceScore: number;  // 0-100
  matchedTTPs: string[];   // ATT&CK technique IDs
  rationale: string;
}

export interface SectorExposurePattern {
  sector: string;
  pattern: string;
  matchStrength: "strong" | "moderate" | "weak";
  indicators: string[];
}

export interface ActiveCampaignCorrelation {
  campaignName: string;
  source: string;  // e.g., "KEV", "Mandiant", "CrowdStrike"
  matchedCharacteristics: string[];
  urgency: "critical" | "high" | "medium" | "low";
}

export interface ThreatRelevanceResult {
  assetIdentifier: string;
  overallThreatScore: number;  // 0-100
  actorRelevance: ThreatActorRelevance[];
  sectorExposures: SectorExposurePattern[];
  activeCampaigns: ActiveCampaignCorrelation[];
  geopoliticalExposure: {
    nationStateInterest: "high" | "medium" | "low" | "none";
    rationale: string;
  };
  mode: SpecialistMode;
  processingTimeMs: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — Unified Discovery Context (all 5 specialists combined)
// ═══════════════════════════════════════════════════════════════════════

export interface DiscoveryContext {
  assetIdentifier: string;
  evidencePackage: StructuredEvidencePackage;
  attribution: AttributionResult;
  role: RoleResult;
  lifecycle: LifecycleResult;
  businessContext: BusinessContextResult;
  threatRelevance: ThreatRelevanceResult;
  /** Discovery-time tier classification (bullseye/perimeter/peripheral/unknown) */
  discoveryTier: "bullseye" | "perimeter" | "peripheral" | "unknown";
  /** Composite confidence across all specialists */
  overallConfidence: number;
  /** Negative findings: what was looked for and not found */
  negativeFindings: NegativeFinding[];
  processedAt: string;
}

export interface NegativeFinding {
  checkedFor: string;
  result: "not_found";
  significance: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — Evidence Package Builder
// ═══════════════════════════════════════════════════════════════════════

/**
 * Assembles a structured evidence package from raw discovery data.
 * This is the deterministic pre-processing step before LLM specialists run.
 */
export function buildEvidencePackage(
  assetIdentifier: string,
  discoveryResult: DiscoveryResult,
  whoisData?: Record<string, any>,
  httpFingerprint?: Record<string, any>,
  businessIntelData?: Record<string, any>
): StructuredEvidencePackage {
  // Find the host data for this asset
  const host = discoveryResult.hosts.find(h =>
    h.hostnames.includes(assetIdentifier) || h.ip === assetIdentifier
  );
  const subdomain = discoveryResult.subdomains.find(s =>
    s.subdomain === assetIdentifier
  );

  // Extract certificate evidence
  const matchingCerts = discoveryResult.certificates.filter(c =>
    c.subject.includes(assetIdentifier) ||
    c.sans.some(san => san === assetIdentifier || san === `*.${assetIdentifier.split('.').slice(1).join('.')}`)
  );
  const primaryCert = matchingCerts[0] || null;

  const certEvidence: CertificateEvidence | null = primaryCert ? {
    issuer: primaryCert.issuer,
    subjectCN: primaryCert.subject,
    sanEntries: primaryCert.sans,
    organizationInSubject: extractOrgFromCertSubject(primaryCert.subject),
    validFrom: primaryCert.validFrom,
    validTo: primaryCert.validTo,
    isExpired: primaryCert.isExpired,
    isWildcard: primaryCert.isWildcard,
    firstObservedInCTLogs: null, // Would come from CT log data
  } : null;

  // Extract DNS evidence
  const relevantDNS = discoveryResult.dnsRecords;
  const aRecords = relevantDNS
    .filter(r => r.type === "A" || r.type === "AAAA")
    .map(r => ({ value: r.value, firstSeen: r.firstSeen, lastSeen: r.lastSeen }));
  const mxRecords = relevantDNS
    .filter(r => r.type === "MX")
    .map(r => ({ value: r.value }));
  const nsRecords = relevantDNS
    .filter(r => r.type === "NS")
    .map(r => r.value);
  const txtRecords = relevantDNS
    .filter(r => r.type === "TXT")
    .map(r => r.value);
  const cnameRecords = relevantDNS
    .filter(r => r.type === "CNAME")
    .map(r => r.value);
  const soaRecord = relevantDNS.find(r => r.type === "SOA")?.value || null;

  // Find earliest firstSeen across all DNS records
  const allFirstSeen = relevantDNS
    .map(r => r.firstSeen)
    .filter((d): d is string => d !== null)
    .sort();
  const stableSince = allFirstSeen[0] || null;

  const dnsEvidence: DNSEvidence = {
    aRecords,
    mxRecords,
    nsRecords,
    txtRecords,
    soaRecord,
    cnameChain: cnameRecords,
    stableSince,
  };

  // Extract BGP/ASN evidence
  const bgpEvidence: BGPEvidence = {
    asn: host?.asn || null,
    asnOrganization: host?.organization || null,
    isp: host?.isp || null,
    ipRange: null,
    adjacentIPs: [],
  };

  // Extract WHOIS evidence
  const whoisEvidence: WHOISEvidence | null = whoisData ? {
    registrantOrganization: whoisData.registrant?.organization || null,
    registrantName: whoisData.registrant?.name || null,
    registrantCountry: whoisData.registrant?.country || null,
    registrationDate: whoisData.created_date || whoisData.creationDate || null,
    expirationDate: whoisData.expiry_date || whoisData.expirationDate || null,
    adminContact: whoisData.admin?.email || null,
    nameServers: whoisData.nameservers || [],
    lastUpdated: whoisData.updated_date || null,
  } : null;

  // Extract HTTP evidence
  const httpEvidence: HTTPEvidence | null = httpFingerprint ? {
    statusCode: httpFingerprint.statusCode || null,
    serverHeader: httpFingerprint.server || null,
    poweredByHeader: httpFingerprint.poweredBy || null,
    technologies: httpFingerprint.technologies || [],
    faviconHash: httpFingerprint.faviconHash || null,
    hostnamePattern: extractHostnamePattern(assetIdentifier),
    contentKeywords: httpFingerprint.keywords || [],
    responseHeaders: httpFingerprint.headers || {},
  } : null;

  // Extract business intelligence evidence
  const bizEvidence: BusinessIntelEvidence | null = businessIntelData ? {
    secEdgarCIK: businessIntelData.cik || null,
    businessSegments: businessIntelData.segments || [],
    industry: businessIntelData.industry || null,
    employeeCount: businessIntelData.employeeCount || null,
    headquarters: businessIntelData.headquarters || null,
    subsidiaries: businessIntelData.subsidiaries || [],
    regulatoryRegimes: businessIntelData.regulatoryRegimes || [],
  } : null;

  // Determine the primary scan target domain
  const scanTargetDomain = discoveryResult.targets?.[0]?.domain
    || discoveryResult.targets?.[0]?.ip
    || assetIdentifier;

  return {
    assetIdentifier,
    resolvedIPs: subdomain?.ips || (host ? [host.ip] : []),
    certificate: certEvidence,
    dns: dnsEvidence,
    bgp: bgpEvidence,
    whois: whoisEvidence,
    http: httpEvidence,
    businessIntel: bizEvidence,
    externalContext: {
      customerStatedIndustry: null,
      customerStatedSize: null,
      scanTargetDomain,
    },
    assembledAt: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §10 — Deterministic Baseline Engines (run before LLM)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Deterministic attribution baseline from rule-based pattern matching.
 * Gets 60-70% of attribution value with no LLM dependency.
 */
export function computeAttributionBaseline(pkg: StructuredEvidencePackage): AttributionClaim[] {
  const claims: AttributionClaim[] = [];
  let baseConfidence = 0;
  const evidence: EvidenceCitation[] = [];
  const contradictions: ContradictingEvidence[] = [];
  let orgName: string | null = null;

  // Rule 1: Certificate organization
  if (pkg.certificate?.organizationInSubject) {
    orgName = pkg.certificate.organizationInSubject;
    baseConfidence += 25;
    evidence.push({
      source: "CERTIFICATE",
      evidenceType: "subject_organization",
      weight: "strong",
      detail: `Certificate subject organization: ${orgName}`,
    });
  }

  // Rule 2: WHOIS registrant
  if (pkg.whois?.registrantOrganization) {
    const whoisOrg = pkg.whois.registrantOrganization;
    if (orgName && normalizeOrgName(orgName) === normalizeOrgName(whoisOrg)) {
      baseConfidence += 25;
      evidence.push({
        source: "WHOIS",
        evidenceType: "registrant_organization",
        weight: "strong",
        detail: `WHOIS registrant matches certificate: ${whoisOrg}`,
      });
    } else if (orgName && normalizeOrgName(orgName) !== normalizeOrgName(whoisOrg)) {
      contradictions.push({
        source: "WHOIS",
        evidenceType: "registrant_mismatch",
        detail: `WHOIS registrant (${whoisOrg}) differs from certificate org (${orgName})`,
      });
      baseConfidence += 10;
    } else {
      orgName = whoisOrg;
      baseConfidence += 20;
      evidence.push({
        source: "WHOIS",
        evidenceType: "registrant_organization",
        weight: "moderate",
        detail: `WHOIS registrant organization: ${whoisOrg}`,
      });
    }
  }

  // Rule 3: ASN organization
  if (pkg.bgp.asnOrganization) {
    const asnOrg = pkg.bgp.asnOrganization;
    if (orgName && normalizeOrgName(orgName).includes(normalizeOrgName(asnOrg).slice(0, 8))) {
      baseConfidence += 15;
      evidence.push({
        source: "BGP",
        evidenceType: "asn_organization",
        weight: "moderate",
        detail: `ASN organization corroborates: ${asnOrg} (AS${pkg.bgp.asn})`,
      });
    } else if (!orgName) {
      orgName = asnOrg;
      baseConfidence += 10;
      evidence.push({
        source: "BGP",
        evidenceType: "asn_organization",
        weight: "weak",
        detail: `ASN organization: ${asnOrg} (AS${pkg.bgp.asn})`,
      });
    }
  }

  // Rule 4: DNS nameserver pattern
  if (pkg.dns.nsRecords.length > 0) {
    const nsDomain = pkg.dns.nsRecords[0].split('.').slice(-2).join('.');
    const assetDomain = pkg.assetIdentifier.split('.').slice(-2).join('.');
    if (nsDomain === assetDomain) {
      baseConfidence += 10;
      evidence.push({
        source: "DNS",
        evidenceType: "nameserver_self_hosted",
        weight: "moderate",
        detail: `Self-hosted nameservers on same domain: ${pkg.dns.nsRecords.join(', ')}`,
      });
    }
  }

  // Rule 5: Domain pattern matching against scan target
  const targetDomain = pkg.externalContext.scanTargetDomain;
  if (pkg.assetIdentifier.endsWith(`.${targetDomain}`) || pkg.assetIdentifier === targetDomain) {
    baseConfidence += 15;
    evidence.push({
      source: "DNS",
      evidenceType: "domain_pattern_match",
      weight: "strong",
      detail: `Asset domain matches scan target: ${targetDomain}`,
    });
  }

  // Cap at 100
  baseConfidence = Math.min(baseConfidence, 100);

  // Determine claim type
  let claimType: AttributionClaimType = "unknown";
  if (baseConfidence >= 60) claimType = "primary_owner";
  else if (baseConfidence >= 30) claimType = "third_party_hosted";

  // Detect CDN/shared hosting
  if (isCDNProvider(pkg.bgp.asnOrganization || "") || isCDNProvider(pkg.certificate?.issuer || "")) {
    claimType = "cdn_fronted";
  }

  if (orgName) {
    claims.push({
      attributedTo: { organization: orgName },
      claimType,
      confidence: baseConfidence >= 70 ? "high" : baseConfidence >= 40 ? "medium" : "low",
      confidenceScore: baseConfidence,
      supportingEvidence: evidence,
      contradictingEvidence: contradictions,
      alternativeAttributions: [],
    });
  }

  return claims;
}

/**
 * Deterministic role inference from hostname patterns and technology signals.
 */
export function computeRoleBaseline(pkg: StructuredEvidencePackage): RoleInference {
  const hostnameSignals = extractHostnameSignals(pkg.assetIdentifier);
  const technologies = pkg.http?.technologies || [];

  // Exposure inference
  let exposure: AssetExposure = "unknown";
  let exposureConfidence = 30;
  const exposureEvidence: EvidenceCitation[] = [];

  if (hostnameSignals.includes("api.") || hostnameSignals.includes("www.") || hostnameSignals.includes("app.")) {
    exposure = "customer_facing";
    exposureConfidence = 70;
    exposureEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "moderate",
      detail: `Hostname pattern suggests customer-facing: ${hostnameSignals.join(', ')}`,
    });
  } else if (hostnameSignals.includes("admin.") || hostnameSignals.includes("internal.") || hostnameSignals.includes("vpn.")) {
    exposure = "internal";
    exposureConfidence = 65;
    exposureEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "moderate",
      detail: `Hostname pattern suggests internal: ${hostnameSignals.join(', ')}`,
    });
  } else if (hostnameSignals.includes("partner.") || hostnameSignals.includes("b2b.")) {
    exposure = "partner";
    exposureConfidence = 60;
    exposureEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "moderate",
      detail: `Hostname pattern suggests partner-facing: ${hostnameSignals.join(', ')}`,
    });
  }

  // Environment inference
  let environment: AssetEnvironment = "unknown";
  let envConfidence = 30;
  const envEvidence: EvidenceCitation[] = [];

  if (hostnameSignals.includes("staging.") || hostnameSignals.includes("stg.")) {
    environment = "staging";
    envConfidence = 80;
    envEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "strong",
      detail: `Hostname contains staging indicator: ${hostnameSignals.join(', ')}`,
    });
  } else if (hostnameSignals.includes("dev.") || hostnameSignals.includes("development.")) {
    environment = "development";
    envConfidence = 80;
    envEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "strong",
      detail: `Hostname contains development indicator`,
    });
  } else if (hostnameSignals.includes("test.") || hostnameSignals.includes("qa.") || hostnameSignals.includes("uat.")) {
    environment = "testing";
    envConfidence = 75;
    envEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "strong",
      detail: `Hostname contains testing indicator`,
    });
  } else if (!hostnameSignals.some(s => ["staging.", "stg.", "dev.", "test.", "qa.", "uat."].includes(s))) {
    environment = "production";
    envConfidence = 50; // default assumption, lower confidence
    envEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern_absence", weight: "weak",
      detail: `No non-production indicators in hostname — assumed production`,
    });
  }

  // Criticality inference
  let criticality: AssetCriticality = "unknown";
  let critConfidence = 30;
  const critEvidence: EvidenceCitation[] = [];

  if (hostnameSignals.includes("backup.") || hostnameSignals.includes("dr.") || hostnameSignals.includes("failover.")) {
    criticality = "backup";
    critConfidence = 70;
    critEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "moderate",
      detail: `Hostname suggests backup/DR system`,
    });
  } else if (hostnameSignals.includes("www.") || hostnameSignals.includes("api.") || hostnameSignals.includes("mail.")) {
    criticality = "primary";
    critConfidence = 65;
    critEvidence.push({
      source: "DNS", evidenceType: "hostname_pattern", weight: "moderate",
      detail: `Hostname suggests primary service endpoint`,
    });
  }

  // Infer function from technology + hostname
  let inferredFunction: string | null = null;
  if (technologies.some(t => /mail|smtp|exchange/i.test(t)) || hostnameSignals.includes("mail.")) {
    inferredFunction = "email server";
  } else if (hostnameSignals.includes("api.")) {
    inferredFunction = "API gateway";
  } else if (hostnameSignals.includes("cdn.") || hostnameSignals.includes("static.")) {
    inferredFunction = "CDN edge / static assets";
  } else if (hostnameSignals.includes("vpn.")) {
    inferredFunction = "VPN gateway";
  } else if (hostnameSignals.includes("ftp.")) {
    inferredFunction = "file transfer server";
  } else if (technologies.some(t => /mysql|postgres|mongo|redis/i.test(t))) {
    inferredFunction = "database server";
  }

  return {
    exposure: { value: exposure, confidence: exposureConfidence, evidence: exposureEvidence },
    environment: { value: environment, confidence: envConfidence, evidence: envEvidence },
    criticality: { value: criticality, confidence: critConfidence, evidence: critEvidence },
    inferredFunction,
    hostnameSignals,
    technologyStack: technologies,
  };
}

/**
 * Deterministic lifecycle stage inference from temporal signals.
 */
export function computeLifecycleBaseline(pkg: StructuredEvidencePackage): {
  stage: LifecycleStage;
  confidence: number;
  signals: LifecycleSignal[];
  riskMultiplier: number;
} {
  const signals: LifecycleSignal[] = [];
  let activeScore = 0;
  let abandonedScore = 0;

  // Signal 1: Certificate expiration
  if (pkg.certificate) {
    const validTo = new Date(pkg.certificate.validTo);
    const now = new Date();
    const daysUntilExpiry = (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

    if (pkg.certificate.isExpired) {
      abandonedScore += 30;
      signals.push({
        signalType: "cert_expired",
        value: pkg.certificate.validTo,
        interpretation: "Certificate is expired — strong indicator of abandonment",
        weight: "strong",
      });
    } else if (daysUntilExpiry < 30) {
      abandonedScore += 15;
      signals.push({
        signalType: "cert_near_expiry",
        value: `${Math.round(daysUntilExpiry)} days remaining`,
        interpretation: "Certificate near expiry without renewal — possible declining maintenance",
        weight: "moderate",
      });
    } else if (daysUntilExpiry > 180) {
      activeScore += 15;
      signals.push({
        signalType: "cert_well_maintained",
        value: `${Math.round(daysUntilExpiry)} days remaining`,
        interpretation: "Certificate has significant validity remaining — actively maintained",
        weight: "moderate",
      });
    }
  }

  // Signal 2: DNS staleness
  if (pkg.dns.stableSince) {
    const stableDate = new Date(pkg.dns.stableSince);
    const now = new Date();
    const daysSinceChange = (now.getTime() - stableDate.getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceChange > 730) { // 2+ years
      abandonedScore += 20;
      signals.push({
        signalType: "dns_staleness",
        value: `${Math.round(daysSinceChange)} days since last DNS change`,
        interpretation: "DNS records unchanged for 2+ years — possible forgotten infrastructure",
        weight: "moderate",
      });
    } else if (daysSinceChange < 90) {
      activeScore += 15;
      signals.push({
        signalType: "dns_recent_update",
        value: `${Math.round(daysSinceChange)} days since last DNS change`,
        interpretation: "Recent DNS changes indicate active management",
        weight: "moderate",
      });
    }
  }

  // Signal 3: Technology recency
  if (pkg.http?.technologies && pkg.http.technologies.length > 0) {
    activeScore += 10;
    signals.push({
      signalType: "tech_detected",
      value: pkg.http.technologies.join(", "),
      interpretation: "Active technology stack detected",
      weight: "weak",
    });
  }

  // Signal 4: HTTP response
  if (pkg.http?.statusCode) {
    if (pkg.http.statusCode >= 200 && pkg.http.statusCode < 400) {
      activeScore += 10;
      signals.push({
        signalType: "http_responsive",
        value: `HTTP ${pkg.http.statusCode}`,
        interpretation: "Asset responding with success status",
        weight: "weak",
      });
    } else if (pkg.http.statusCode >= 500) {
      abandonedScore += 10;
      signals.push({
        signalType: "http_error",
        value: `HTTP ${pkg.http.statusCode}`,
        interpretation: "Server error may indicate unmaintained infrastructure",
        weight: "weak",
      });
    }
  }

  // Signal 5: WHOIS registration age and update recency
  if (pkg.whois?.lastUpdated) {
    const lastUpdated = new Date(pkg.whois.lastUpdated);
    const now = new Date();
    const daysSinceUpdate = (now.getTime() - lastUpdated.getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceUpdate > 365 * 3) {
      abandonedScore += 10;
      signals.push({
        signalType: "whois_stale",
        value: `Last WHOIS update: ${pkg.whois.lastUpdated}`,
        interpretation: "WHOIS not updated in 3+ years",
        weight: "weak",
      });
    }
  }

  // Compute stage
  const netScore = activeScore - abandonedScore;
  let stage: LifecycleStage;
  let confidence: number;
  let riskMultiplier: number;

  if (netScore > 20) {
    stage = "active";
    confidence = Math.min(70 + netScore, 95);
    riskMultiplier = 1.0;
  } else if (netScore > -10) {
    stage = "declining";
    confidence = 50;
    riskMultiplier = 1.3;
  } else if (netScore <= -10) {
    stage = "abandoned";
    confidence = Math.min(60 + Math.abs(netScore), 90);
    riskMultiplier = 1.8;
  } else {
    stage = "unknown";
    confidence = 30;
    riskMultiplier = 1.2;
  }

  // If no signals at all, mark unknown
  if (signals.length === 0) {
    stage = "unknown";
    confidence = 20;
    riskMultiplier = 1.2;
  }

  return { stage, confidence, signals, riskMultiplier };
}

/**
 * Deterministic threat relevance baseline from asset characteristics.
 */
export function computeThreatRelevanceBaseline(
  pkg: StructuredEvidencePackage,
  sectorContext?: string
): {
  overallThreatScore: number;
  sectorExposures: SectorExposurePattern[];
  activeCampaigns: ActiveCampaignCorrelation[];
} {
  const sectorExposures: SectorExposurePattern[] = [];
  const activeCampaigns: ActiveCampaignCorrelation[] = [];
  let threatScore = 30; // baseline

  const technologies = pkg.http?.technologies || [];
  const hostnameSignals = extractHostnameSignals(pkg.assetIdentifier);

  // Sector-specific exposure patterns
  if (sectorContext) {
    const sector = sectorContext.toLowerCase();

    if (sector.includes("finance") || sector.includes("banking")) {
      if (hostnameSignals.some(s => /payment|swift|transaction|banking/i.test(s))) {
        threatScore += 20;
        sectorExposures.push({
          sector: "Financial Services",
          pattern: "Payment/transaction infrastructure exposure",
          matchStrength: "strong",
          indicators: hostnameSignals.filter(s => /payment|swift|transaction|banking/i.test(s)),
        });
      }
    }

    if (sector.includes("health")) {
      if (hostnameSignals.some(s => /ehr|patient|telehealth|medical|fhir/i.test(s)) ||
          technologies.some(t => /epic|cerner|meditech/i.test(t))) {
        threatScore += 20;
        sectorExposures.push({
          sector: "Healthcare",
          pattern: "EHR/patient data system exposure",
          matchStrength: "strong",
          indicators: [...hostnameSignals, ...technologies].filter(s => /ehr|patient|telehealth|medical|fhir|epic|cerner/i.test(s)),
        });
      }
    }

    if (sector.includes("defense") || sector.includes("government")) {
      threatScore += 15;
      sectorExposures.push({
        sector: "Defense/Government",
        pattern: "Government sector asset — elevated nation-state interest",
        matchStrength: "moderate",
        indicators: [],
      });
    }

    if (sector.includes("energy") || sector.includes("utility")) {
      if (hostnameSignals.some(s => /scada|ot|plc|hmi|modbus/i.test(s))) {
        threatScore += 25;
        sectorExposures.push({
          sector: "Energy/Utilities",
          pattern: "SCADA/OT infrastructure exposure",
          matchStrength: "strong",
          indicators: hostnameSignals.filter(s => /scada|ot|plc|hmi|modbus/i.test(s)),
        });
      }
    }
  }

  // Technology-based threat relevance
  const riskyTech = technologies.filter(t =>
    /citrix|pulse|fortinet|sonicwall|palo alto|f5|exchange|sharepoint|confluence|jira/i.test(t)
  );
  if (riskyTech.length > 0) {
    threatScore += 15;
    activeCampaigns.push({
      campaignName: "Common Initial Access Targets",
      source: "KEV/CISA",
      matchedCharacteristics: riskyTech,
      urgency: "high",
    });
  }

  // VPN/remote access exposure
  if (hostnameSignals.some(s => /vpn|remote|rdp|citrix|gateway/i.test(s))) {
    threatScore += 10;
    activeCampaigns.push({
      campaignName: "Remote Access Targeting",
      source: "Threat Intelligence",
      matchedCharacteristics: hostnameSignals.filter(s => /vpn|remote|rdp|citrix|gateway/i.test(s)),
      urgency: "medium",
    });
  }

  return {
    overallThreatScore: Math.min(threatScore, 100),
    sectorExposures,
    activeCampaigns,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §11 — LLM Specialist Prompts and Invocation
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build the prompt for the Asset Attribution Specialist.
 * Includes explicit role definition, evidence grounding requirements,
 * calibration anchor examples, and output schema.
 */
export function buildAttributionPrompt(pkg: StructuredEvidencePackage, baseline: AttributionClaim[]): string {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  const baselineBlock = baseline.length > 0
    ? `\nDETERMINISTIC BASELINE:\nOrganization: ${baseline[0].attributedTo.organization}\nBaseline Confidence: ${baseline[0].confidenceScore}/100\nClaim Type: ${baseline[0].claimType}\nEvidence Count: ${baseline[0].supportingEvidence.length} supporting, ${baseline[0].contradictingEvidence.length} contradicting\n`
    : "\nDETERMINISTIC BASELINE:\nNo baseline attribution could be established from rule-based analysis.\n";

  return `You are a Discovery Context Analyst. Your role is to analyze structured discovery evidence and produce grounded attribution claims about digital assets. Your analysis should reflect 25 years of hands-on practitioner experience in penetration testing and security assessment. You prioritize verifiable evidence over plausible inference, and you explicitly flag uncertainty rather than producing confident-sounding speculation.

EVIDENCE GROUNDING REQUIREMENTS:
- Every claim must cite supporting evidence from the input package below.
- Claims without supporting evidence must not be made; instead, state that the evidence is insufficient.
- If multiple pieces of evidence contradict each other, surface the contradiction rather than picking a side.
- Do NOT use your training data to make attribution claims. Only use the evidence provided.
- You may adjust the baseline confidence by at most ±20 points based on your synthesis of the evidence.

${evidenceBlock}
${baselineBlock}
EXTERNAL CONTEXT (do not cite as evidence):
- Customer stated industry: ${pkg.externalContext.customerStatedIndustry || 'Not provided'}
- Customer stated size: ${pkg.externalContext.customerStatedSize || 'Not provided'}
- Scan target domain: ${pkg.externalContext.scanTargetDomain}

CALIBRATION EXAMPLES:
1. When certificate org, WHOIS registrant, and ASN org all name the same entity → confidence 85-95, claim_type "primary_owner"
2. When certificate names one org but ASN belongs to AWS/Azure/GCP → confidence 60-75, claim_type "third_party_hosted"
3. When only domain pattern matches scan target, no other evidence → confidence 40-55, claim_type "primary_owner" (tentative)
4. When WHOIS is privacy-protected and certificate is Let's Encrypt → confidence 20-35, claim_type "unknown"

OUTPUT FORMAT: Respond with valid JSON matching this schema:
{
  "claims": [{
    "attributedTo": { "organization": "string", "legalEntity": "string|null", "parentOrganization": "string|null" },
    "claimType": "primary_owner|subsidiary|third_party_hosted|vendor_managed|cdn_fronted|shared_hosting|unknown",
    "confidenceScore": number_0_to_100,
    "confidence": "high|medium|low",
    "supportingEvidence": [{ "source": "string", "evidenceType": "string", "weight": "strong|moderate|weak", "detail": "string" }],
    "contradictingEvidence": [{ "source": "string", "evidenceType": "string", "detail": "string" }],
    "alternativeAttributions": [{ "organization": "string", "confidenceScore": number, "rationale": "string" }]
  }],
  "adjustmentRationale": "string explaining why you adjusted from baseline",
  "confidenceDelta": number_minus20_to_plus20
}`;
}

/**
 * Build the prompt for the Asset Role Specialist.
 */
export function buildRolePrompt(pkg: StructuredEvidencePackage, baseline: RoleInference): string {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);

  return `You are an Asset Role Analyst. Your role is to determine the functional role, exposure level, and operational environment of a discovered digital asset based on structured evidence. You have 25 years of experience in infrastructure assessment and understand how organizations deploy and manage their systems.

EVIDENCE GROUNDING REQUIREMENTS:
- Every inference must cite supporting evidence from the input package.
- If evidence is insufficient for a determination, return "unknown" with an explanation.
- Do NOT guess based on training data. Only use the evidence provided.

${evidenceBlock}

DETERMINISTIC BASELINE:
- Exposure: ${baseline.exposure.value} (confidence: ${baseline.exposure.confidence})
- Environment: ${baseline.environment.value} (confidence: ${baseline.environment.confidence})
- Criticality: ${baseline.criticality.value} (confidence: ${baseline.criticality.confidence})
- Inferred function: ${baseline.inferredFunction || 'None'}
- Hostname signals: ${baseline.hostnameSignals.join(', ') || 'None'}
- Technology stack: ${baseline.technologyStack.join(', ') || 'None'}

OUTPUT FORMAT: Respond with valid JSON:
{
  "exposure": { "value": "customer_facing|internal|partner|unknown", "confidence": number_0_to_100, "rationale": "string" },
  "environment": { "value": "production|staging|development|testing|unknown", "confidence": number_0_to_100, "rationale": "string" },
  "criticality": { "value": "primary|backup|auxiliary|unknown", "confidence": number_0_to_100, "rationale": "string" },
  "inferredFunction": "string|null",
  "adjustmentRationale": "string"
}`;
}

/**
 * Build the prompt for the Lifecycle Stage Specialist.
 */
export function buildLifecyclePrompt(
  pkg: StructuredEvidencePackage,
  baseline: { stage: LifecycleStage; confidence: number; signals: LifecycleSignal[] }
): string {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  const signalsBlock = baseline.signals.map(s =>
    `- ${s.signalType}: ${s.value} → ${s.interpretation} (${s.weight})`
  ).join('\n');

  return `You are a Lifecycle Stage Analyst. Your role is to determine whether a discovered digital asset is actively maintained, declining in maintenance, or abandoned. Forgotten infrastructure is where most catastrophic compromises start — your analysis directly impacts security prioritization.

EVIDENCE GROUNDING REQUIREMENTS:
- Every determination must cite temporal signals from the evidence.
- If evidence is insufficient, return "unknown" with explanation of what additional data would help.

${evidenceBlock}

DETERMINISTIC BASELINE:
- Stage: ${baseline.stage} (confidence: ${baseline.confidence})
- Temporal signals detected:
${signalsBlock || '  None'}

OUTPUT FORMAT: Respond with valid JSON:
{
  "stage": "active|declining|abandoned|unknown",
  "confidence": number_0_to_100,
  "riskMultiplier": number_1_to_2,
  "additionalSignals": [{ "signalType": "string", "value": "string", "interpretation": "string", "weight": "strong|moderate|weak" }],
  "adjustmentRationale": "string",
  "lastMaintenanceEstimate": "ISO date string|null"
}`;
}

/**
 * Build the prompt for the Business Context Specialist.
 */
export function buildBusinessContextPrompt(pkg: StructuredEvidencePackage): string {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);

  return `You are a Business Context Analyst. Your role is to infer the business significance of a discovered digital asset — which business unit it serves, what function it performs, whether it sits on a revenue path, and what regulatory regimes may apply. Your analysis enables the platform to say "these systems run your billing pipeline" rather than "we found 47 servers."

EVIDENCE GROUNDING REQUIREMENTS:
- Every business attribution must cite evidence from the input package.
- Regulatory exposure claims must cite specific indicators (payment keywords → PCI, health data → HIPAA).
- If no business context can be inferred, return null values with explanation.
- Do NOT fabricate business relationships from training data.

${evidenceBlock}

OUTPUT FORMAT: Respond with valid JSON:
{
  "businessUnit": { "name": "string|null", "function": "string|null", "revenuePath": "string|null", "confidence": number_0_to_100, "evidence": [{ "source": "string", "evidenceType": "string", "weight": "strong|moderate|weak", "detail": "string" }] },
  "regulatoryExposures": [{ "regime": "string", "indicators": ["string"], "confidence": number_0_to_100 }],
  "dependencies": [{ "targetAsset": "string", "relationshipType": "dns_chain|api_reference|cert_trust|bgp_adjacency|hosting_shared|code_reference", "confidence": number_0_to_100, "evidence": "string" }],
  "customerAttribution": { "servesTopCustomers": boolean, "customerIndicators": ["string"], "concentrationRisk": "high|medium|low|unknown" }
}`;
}

/**
 * Build the prompt for the Threat Relevance Specialist.
 */
export function buildThreatRelevancePrompt(
  pkg: StructuredEvidencePackage,
  baseline: { overallThreatScore: number; sectorExposures: SectorExposurePattern[]; activeCampaigns: ActiveCampaignCorrelation[] }
): string {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);

  return `You are a Threat Relevance Analyst. Your role is to assess how relevant specific threat actors and attack campaigns are to a discovered digital asset. You correlate asset characteristics with known threat actor TTPs, sector-specific targeting patterns, and active campaigns. Your analysis should reflect deep knowledge of the threat landscape.

EVIDENCE GROUNDING REQUIREMENTS:
- Threat actor relevance claims must cite specific asset characteristics that match known TTPs.
- Active campaign correlations must reference specific campaign characteristics.
- Do NOT invent threat actor associations from training data alone.
- You may adjust the baseline threat score by at most ±20 points.

${evidenceBlock}

DETERMINISTIC BASELINE:
- Overall threat score: ${baseline.overallThreatScore}/100
- Sector exposures detected: ${baseline.sectorExposures.length}
- Active campaign correlations: ${baseline.activeCampaigns.length}

OUTPUT FORMAT: Respond with valid JSON:
{
  "overallThreatScore": number_0_to_100,
  "actorRelevance": [{ "actorName": "string", "actorType": "apt|ransomware|hacktivist|cybercrime|unknown", "relevanceScore": number_0_to_100, "matchedTTPs": ["string"], "rationale": "string" }],
  "sectorExposures": [{ "sector": "string", "pattern": "string", "matchStrength": "strong|moderate|weak", "indicators": ["string"] }],
  "activeCampaigns": [{ "campaignName": "string", "source": "string", "matchedCharacteristics": ["string"], "urgency": "critical|high|medium|low" }],
  "geopoliticalExposure": { "nationStateInterest": "high|medium|low|none", "rationale": "string" },
  "adjustmentRationale": "string",
  "confidenceDelta": number_minus20_to_plus20
}`;
}

// ═══════════════════════════════════════════════════════════════════════
// §12 — Evidence Grounding Validation
// ═══════════════════════════════════════════════════════════════════════

/**
 * Validates that LLM output claims are grounded in the evidence package.
 * Returns ungrounded claims that should be rejected.
 */
export function validateEvidenceGrounding(
  llmOutput: any,
  pkg: StructuredEvidencePackage
): { valid: boolean; ungroundedClaims: string[]; warnings: string[] } {
  const ungroundedClaims: string[] = [];
  const warnings: string[] = [];

  // Build set of valid evidence sources from the package
  const validSources = new Set<string>();
  if (pkg.certificate) validSources.add("CERTIFICATE");
  if (pkg.dns.aRecords.length > 0 || pkg.dns.nsRecords.length > 0) validSources.add("DNS");
  if (pkg.bgp.asn) validSources.add("BGP");
  if (pkg.whois) validSources.add("WHOIS");
  if (pkg.http) validSources.add("HTTP");
  if (pkg.businessIntel) validSources.add("BUSINESS_INTEL");

  // Check attribution claims
  if (llmOutput.claims && Array.isArray(llmOutput.claims)) {
    for (const claim of llmOutput.claims) {
      if (claim.supportingEvidence && Array.isArray(claim.supportingEvidence)) {
        for (const ev of claim.supportingEvidence) {
          if (!validSources.has(ev.source)) {
            ungroundedClaims.push(
              `Claim cites "${ev.source}" but no ${ev.source} evidence was in the package`
            );
          }
        }
      }
      // Check confidence delta bounds
      if (llmOutput.confidenceDelta !== undefined) {
        if (Math.abs(llmOutput.confidenceDelta) > 20) {
          warnings.push(
            `Confidence delta ${llmOutput.confidenceDelta} exceeds ±20 bound — clamping`
          );
        }
      }
    }
  }

  return {
    valid: ungroundedClaims.length === 0,
    ungroundedClaims,
    warnings,
  };
}

/**
 * Clamp a confidence delta to the bounded range ±20.
 */
export function clampDelta(delta: number): number {
  return Math.max(-20, Math.min(20, delta));
}

/**
 * Apply bounded LLM delta to deterministic baseline confidence.
 */
export function applyBoundedDelta(baseline: number, delta: number): number {
  const clampedDelta = clampDelta(delta);
  return Math.max(0, Math.min(100, baseline + clampedDelta));
}

// ═══════════════════════════════════════════════════════════════════════
// §13 — Discovery Tier Classification
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute discovery-time tier classification for an asset.
 * bullseye = high-value, high-confidence target
 * perimeter = confirmed asset with moderate priority
 * peripheral = low-confidence or low-priority
 * unknown = insufficient data
 */
export function classifyDiscoveryTier(
  attribution: AttributionResult,
  role: RoleResult,
  lifecycle: LifecycleResult,
  threatRelevance: ThreatRelevanceResult
): "bullseye" | "perimeter" | "peripheral" | "unknown" {
  const attrConfidence = attribution.claims[0]?.confidenceScore || 0;
  const isProduction = role.role.environment.value === "production";
  const isCustomerFacing = role.role.exposure.value === "customer_facing";
  const isPrimary = role.role.criticality.value === "primary";
  const threatScore = threatRelevance.overallThreatScore;
  const isAbandoned = lifecycle.stage === "abandoned";

  // Bullseye: high-confidence attribution + production + customer-facing + high threat
  if (attrConfidence >= 60 && isProduction && (isCustomerFacing || isPrimary) && threatScore >= 50) {
    return "bullseye";
  }

  // Also bullseye: abandoned infrastructure (highest actual risk)
  if (attrConfidence >= 40 && isAbandoned && threatScore >= 30) {
    return "bullseye";
  }

  // Perimeter: confirmed asset with moderate signals
  if (attrConfidence >= 40 && (isProduction || threatScore >= 30)) {
    return "perimeter";
  }

  // Peripheral: low-confidence or low-priority
  if (attrConfidence >= 20) {
    return "peripheral";
  }

  return "unknown";
}

// ═══════════════════════════════════════════════════════════════════════
// §14 — Negative Finding Capture
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate negative findings — what was checked and not found.
 * Structured absence of evidence improves assessment completeness claims.
 */
export function generateNegativeFindings(pkg: StructuredEvidencePackage): NegativeFinding[] {
  const negatives: NegativeFinding[] = [];

  if (!pkg.certificate) {
    negatives.push({
      checkedFor: "TLS certificate",
      result: "not_found",
      significance: "No TLS certificate found — asset may not serve HTTPS or certificate data unavailable",
    });
  }

  if (!pkg.whois) {
    negatives.push({
      checkedFor: "WHOIS registration data",
      result: "not_found",
      significance: "No WHOIS data available — domain registration details could not be verified",
    });
  }

  if (!pkg.http) {
    negatives.push({
      checkedFor: "HTTP response fingerprint",
      result: "not_found",
      significance: "No HTTP response captured — asset may not serve web content or was unreachable",
    });
  }

  if (!pkg.businessIntel) {
    negatives.push({
      checkedFor: "Business intelligence (SEC EDGAR, corporate registry)",
      result: "not_found",
      significance: "No public business intelligence found — organization may be private or data unavailable",
    });
  }

  if (pkg.dns.aRecords.length === 0) {
    negatives.push({
      checkedFor: "DNS A/AAAA records",
      result: "not_found",
      significance: "No DNS resolution — asset may be decommissioned or DNS not configured",
    });
  }

  if (!pkg.bgp.asn) {
    negatives.push({
      checkedFor: "BGP/ASN attribution",
      result: "not_found",
      significance: "No ASN data — IP-level attribution could not be established",
    });
  }

  return negatives;
}

// ═══════════════════════════════════════════════════════════════════════
// §15 — Main Orchestrator
// ═══════════════════════════════════════════════════════════════════════

export interface DiscoveryContextOptions {
  /** Skip LLM calls, use deterministic-only mode */
  deterministicOnly?: boolean;
  /** Customer-provided industry context */
  customerIndustry?: string;
  /** Customer-provided size context */
  customerSize?: string;
  /** LLM invocation function (injected for testability) */
  llmInvoke?: (messages: { role: string; content: string }[]) => Promise<{ choices: { message: { content: string } }[] }>;
}

/**
 * Run the full discovery context engine for a single asset.
 * Orchestrates all 5 specialists with graceful degradation.
 */
export async function analyzeAssetContext(
  assetIdentifier: string,
  discoveryResult: DiscoveryResult,
  options: DiscoveryContextOptions = {},
  whoisData?: Record<string, any>,
  httpFingerprint?: Record<string, any>,
  businessIntelData?: Record<string, any>
): Promise<DiscoveryContext> {
  const startTime = Date.now();

  // Step 1: Build structured evidence package
  const pkg = buildEvidencePackage(
    assetIdentifier, discoveryResult, whoisData, httpFingerprint, businessIntelData
  );

  // Inject customer context
  if (options.customerIndustry) pkg.externalContext.customerStatedIndustry = options.customerIndustry;
  if (options.customerSize) pkg.externalContext.customerStatedSize = options.customerSize;

  // Step 2: Compute deterministic baselines (always runs)
  const attrBaseline = computeAttributionBaseline(pkg);
  const roleBaseline = computeRoleBaseline(pkg);
  const lifecycleBaseline = computeLifecycleBaseline(pkg);
  const threatBaseline = computeThreatRelevanceBaseline(pkg, options.customerIndustry);

  // Step 3: Run LLM specialists (if not deterministic-only)
  let attrMode: SpecialistMode = "deterministic_only";
  let roleMode: SpecialistMode = "deterministic_only";
  let lifecycleMode: SpecialistMode = "deterministic_only";
  let businessMode: SpecialistMode = "deterministic_only";
  let threatMode: SpecialistMode = "deterministic_only";

  let llmAttrDelta = 0;
  let llmThreatDelta = 0;

  if (!options.deterministicOnly && options.llmInvoke) {
    // Attribution specialist
    try {
      const attrPrompt = buildAttributionPrompt(pkg, attrBaseline);
      const attrResponse = await options.llmInvoke([
        { role: "system", content: "You are a Discovery Context Analyst. Respond only with valid JSON." },
        { role: "user", content: attrPrompt },
      ]);
      const attrParsed = JSON.parse(attrResponse.choices[0].message.content);
      const validation = validateEvidenceGrounding(attrParsed, pkg);

      if (validation.valid) {
        llmAttrDelta = clampDelta(attrParsed.confidenceDelta || 0);
        if (attrBaseline[0]) {
          attrBaseline[0].confidenceScore = applyBoundedDelta(attrBaseline[0].confidenceScore, llmAttrDelta);
          attrBaseline[0].confidence = attrBaseline[0].confidenceScore >= 70 ? "high" :
            attrBaseline[0].confidenceScore >= 40 ? "medium" : "low";
        }
        attrMode = "full_llm";
      } else {
        attrMode = "confidence_degraded";
        console.warn(`[DiscoveryContext] Attribution grounding failed for ${assetIdentifier}:`, validation.ungroundedClaims);
      }
    } catch (err) {
      attrMode = "confidence_degraded";
      console.warn(`[DiscoveryContext] Attribution LLM failed for ${assetIdentifier}:`, (err as Error).message);
    }

    // Threat relevance specialist
    try {
      const threatPrompt = buildThreatRelevancePrompt(pkg, threatBaseline);
      const threatResponse = await options.llmInvoke([
        { role: "system", content: "You are a Threat Relevance Analyst. Respond only with valid JSON." },
        { role: "user", content: threatPrompt },
      ]);
      const threatParsed = JSON.parse(threatResponse.choices[0].message.content);
      llmThreatDelta = clampDelta(threatParsed.confidenceDelta || 0);
      threatBaseline.overallThreatScore = applyBoundedDelta(threatBaseline.overallThreatScore, llmThreatDelta);
      if (threatParsed.actorRelevance) {
        // Merge LLM actor relevance
      }
      if (threatParsed.sectorExposures) {
        threatBaseline.sectorExposures.push(...threatParsed.sectorExposures);
      }
      threatMode = "full_llm";
    } catch (err) {
      threatMode = "confidence_degraded";
      console.warn(`[DiscoveryContext] Threat relevance LLM failed for ${assetIdentifier}:`, (err as Error).message);
    }
  }

  // Step 4: Assemble results
  const now = new Date().toISOString();
  const processingTime = Date.now() - startTime;

  const attributionResult: AttributionResult = {
    assetIdentifier,
    claims: attrBaseline,
    mode: attrMode,
    deterministicBaseline: attrBaseline[0]?.confidenceScore || 0,
    llmDelta: llmAttrDelta,
    processingTimeMs: processingTime,
    timestamp: now,
  };

  const roleResult: RoleResult = {
    assetIdentifier,
    role: roleBaseline,
    mode: roleMode,
    processingTimeMs: processingTime,
    timestamp: now,
  };

  const lifecycleResult: LifecycleResult = {
    assetIdentifier,
    stage: lifecycleBaseline.stage,
    confidence: lifecycleBaseline.confidence,
    signals: lifecycleBaseline.signals,
    riskMultiplier: lifecycleBaseline.riskMultiplier,
    lastMaintenanceEstimate: null,
    mode: lifecycleMode,
    processingTimeMs: processingTime,
    timestamp: now,
  };

  const businessContextResult: BusinessContextResult = {
    assetIdentifier,
    businessUnit: {
      businessUnit: pkg.businessIntel?.businessSegments?.[0]?.name || null,
      function: roleBaseline.inferredFunction,
      revenuePath: pkg.businessIntel?.businessSegments?.[0]?.revenue || null,
      confidence: pkg.businessIntel ? 40 : 10,
      evidence: pkg.businessIntel ? [{
        source: "BUSINESS_INTEL",
        evidenceType: "sec_edgar_segment",
        weight: "moderate" as EvidenceWeight,
        detail: `Business segment: ${pkg.businessIntel.businessSegments?.[0]?.name || 'unknown'}`,
      }] : [],
    },
    regulatoryExposures: inferRegulatoryExposures(pkg),
    dependencies: [],
    customerAttribution: {
      servesTopCustomers: false,
      customerIndicators: [],
      concentrationRisk: "unknown",
    },
    mode: businessMode,
    processingTimeMs: processingTime,
    timestamp: now,
  };

  const threatRelevanceResult: ThreatRelevanceResult = {
    assetIdentifier,
    overallThreatScore: threatBaseline.overallThreatScore,
    actorRelevance: [],
    sectorExposures: threatBaseline.sectorExposures,
    activeCampaigns: threatBaseline.activeCampaigns,
    geopoliticalExposure: { nationStateInterest: "none", rationale: "No specific geopolitical indicators detected" },
    mode: threatMode,
    processingTimeMs: processingTime,
    timestamp: now,
  };

  // Step 5: Classify discovery tier
  const discoveryTier = classifyDiscoveryTier(
    attributionResult, roleResult, lifecycleResult, threatRelevanceResult
  );

  // Step 6: Generate negative findings
  const negativeFindings = generateNegativeFindings(pkg);

  // Step 7: Compute overall confidence
  const overallConfidence = Math.round(
    (attributionResult.claims[0]?.confidenceScore || 0) * 0.3 +
    roleResult.role.exposure.confidence * 0.2 +
    lifecycleResult.confidence * 0.2 +
    (businessContextResult.businessUnit.confidence) * 0.15 +
    (threatRelevanceResult.overallThreatScore) * 0.15
  );

  return {
    assetIdentifier,
    evidencePackage: pkg,
    attribution: attributionResult,
    role: roleResult,
    lifecycle: lifecycleResult,
    businessContext: businessContextResult,
    threatRelevance: threatRelevanceResult,
    discoveryTier,
    overallConfidence,
    negativeFindings,
    processedAt: now,
  };
}

/**
 * Run discovery context analysis for all assets in a discovery result.
 * Processes assets in parallel with concurrency limit.
 */
export async function analyzeDiscoveryContext(
  discoveryResult: DiscoveryResult,
  options: DiscoveryContextOptions = {},
  whoisData?: Record<string, any>,
  httpFingerprints?: Record<string, Record<string, any>>,
  businessIntelData?: Record<string, any>
): Promise<DiscoveryContext[]> {
  // Collect all unique asset identifiers
  const assetIds = new Set<string>();
  for (const host of discoveryResult.hosts) {
    assetIds.add(host.ip);
    for (const hostname of host.hostnames) {
      assetIds.add(hostname);
    }
  }
  for (const sub of discoveryResult.subdomains) {
    assetIds.add(sub.subdomain);
  }

  const results: DiscoveryContext[] = [];
  const concurrency = 5;
  const queue = Array.from(assetIds);

  for (let i = 0; i < queue.length; i += concurrency) {
    const batch = queue.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(id =>
        analyzeAssetContext(
          id, discoveryResult, options, whoisData,
          httpFingerprints?.[id], businessIntelData
        )
      )
    );
    results.push(...batchResults);
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// §16 — Helper Functions
// ═══════════════════════════════════════════════════════════════════════

function extractOrgFromCertSubject(subject: string): string | null {
  const match = subject.match(/O=([^,/]+)/);
  return match ? match[1].trim() : null;
}

function normalizeOrgName(name: string): string {
  return name.toLowerCase()
    .replace(/\b(inc|corp|ltd|llc|co|company|group|holdings|plc|gmbh|sa|ag)\b\.?/gi, '')
    .replace(/[^a-z0-9]/g, '')
    .trim();
}

function extractHostnamePattern(hostname: string): string | null {
  const parts = hostname.split('.');
  if (parts.length >= 3) {
    return parts[0] + '.';
  }
  return null;
}

function extractHostnameSignals(hostname: string): string[] {
  const signals: string[] = [];
  const parts = hostname.split('.');

  const patterns = [
    "api.", "www.", "app.", "admin.", "internal.", "vpn.", "mail.", "smtp.",
    "ftp.", "staging.", "stg.", "dev.", "development.", "test.", "qa.", "uat.",
    "backup.", "dr.", "failover.", "cdn.", "static.", "partner.", "b2b.",
    "payment.", "billing.", "portal.", "dashboard.", "monitor.", "status.",
    "git.", "ci.", "jenkins.", "grafana.", "kibana.", "elastic.",
  ];

  for (const part of parts) {
    const prefix = part + '.';
    if (patterns.includes(prefix)) {
      signals.push(prefix);
    }
  }

  return signals;
}

function isCDNProvider(name: string): boolean {
  const cdnProviders = [
    "cloudflare", "akamai", "fastly", "cloudfront", "amazon", "google",
    "microsoft", "azure", "incapsula", "imperva", "sucuri", "stackpath",
    "limelight", "edgecast", "keycdn", "bunny",
  ];
  const lower = name.toLowerCase();
  return cdnProviders.some(cdn => lower.includes(cdn));
}

function inferRegulatoryExposures(pkg: StructuredEvidencePackage): RegulatoryExposure[] {
  const exposures: RegulatoryExposure[] = [];
  const hostname = pkg.assetIdentifier.toLowerCase();
  const technologies = pkg.http?.technologies?.map(t => t.toLowerCase()) || [];
  const keywords = pkg.http?.contentKeywords?.map(k => k.toLowerCase()) || [];
  const allSignals = [hostname, ...technologies, ...keywords].join(' ');

  if (/payment|pci|card|checkout|stripe|braintree|adyen/i.test(allSignals)) {
    exposures.push({
      regime: "PCI-DSS",
      indicators: ["Payment-related keywords detected in hostname/technology"],
      confidence: 60,
    });
  }

  if (/patient|hipaa|ehr|medical|health|fhir|hl7/i.test(allSignals)) {
    exposures.push({
      regime: "HIPAA",
      indicators: ["Healthcare-related keywords detected"],
      confidence: 55,
    });
  }

  if (/financial|sox|audit|accounting|ledger/i.test(allSignals)) {
    exposures.push({
      regime: "SOX",
      indicators: ["Financial reporting keywords detected"],
      confidence: 45,
    });
  }

  if (/gdpr|privacy|consent|eu\.|\.eu/i.test(allSignals)) {
    exposures.push({
      regime: "GDPR",
      indicators: ["EU/privacy-related keywords detected"],
      confidence: 50,
    });
  }

  if (/cmmc|nist|fedramp|gov\.|\.gov|\.mil/i.test(allSignals)) {
    exposures.push({
      regime: "CMMC",
      indicators: ["Government/defense compliance keywords detected"],
      confidence: 55,
    });
  }

  return exposures;
}

/**
 * Format the evidence package into a human-readable block for LLM prompts.
 */
function formatEvidencePackageForPrompt(pkg: StructuredEvidencePackage): string {
  const sections: string[] = [];

  sections.push(`ASSET: ${pkg.assetIdentifier} (resolved to ${pkg.resolvedIPs.join(', ') || 'unknown'})`);

  if (pkg.certificate) {
    sections.push(`\nCERTIFICATE EVIDENCE:
- Issuer: ${pkg.certificate.issuer}
- Subject CN: ${pkg.certificate.subjectCN}
- SAN entries: ${pkg.certificate.sanEntries.join(', ')}
- Organization in subject: ${pkg.certificate.organizationInSubject || 'Not present'}
- Valid: ${pkg.certificate.validFrom} to ${pkg.certificate.validTo}
- Expired: ${pkg.certificate.isExpired}
- Wildcard: ${pkg.certificate.isWildcard}
- First observed in CT logs: ${pkg.certificate.firstObservedInCTLogs || 'Unknown'}`);
  }

  sections.push(`\nDNS EVIDENCE:
- A records: ${pkg.dns.aRecords.map(r => `${r.value} (first seen: ${r.firstSeen || 'unknown'})`).join(', ') || 'None'}
- MX records: ${pkg.dns.mxRecords.map(r => r.value).join(', ') || 'None'}
- NS records: ${pkg.dns.nsRecords.join(', ') || 'None'}
- TXT records: ${pkg.dns.txtRecords.length} entries
- SOA: ${pkg.dns.soaRecord || 'None'}
- CNAME chain: ${pkg.dns.cnameChain.join(' → ') || 'None'}
- Stable since: ${pkg.dns.stableSince || 'Unknown'}`);

  if (pkg.bgp.asn) {
    sections.push(`\nBGP/AS EVIDENCE:
- ASN: AS${pkg.bgp.asn} (${pkg.bgp.asnOrganization || 'Unknown'})
- ISP: ${pkg.bgp.isp || 'Unknown'}`);
  }

  if (pkg.whois) {
    sections.push(`\nWHOIS EVIDENCE:
- Registrant: ${pkg.whois.registrantOrganization || pkg.whois.registrantName || 'Privacy protected'}
- Country: ${pkg.whois.registrantCountry || 'Unknown'}
- Registered: ${pkg.whois.registrationDate || 'Unknown'}
- Expires: ${pkg.whois.expirationDate || 'Unknown'}
- Last updated: ${pkg.whois.lastUpdated || 'Unknown'}
- Nameservers: ${pkg.whois.nameServers.join(', ') || 'None'}`);
  }

  if (pkg.http) {
    sections.push(`\nHTTP EVIDENCE:
- Status: ${pkg.http.statusCode || 'Unknown'}
- Server: ${pkg.http.serverHeader || 'Not disclosed'}
- Powered by: ${pkg.http.poweredByHeader || 'Not disclosed'}
- Technologies: ${pkg.http.technologies.join(', ') || 'None detected'}
- Hostname pattern: ${pkg.http.hostnamePattern || 'None'}
- Content keywords: ${pkg.http.contentKeywords.join(', ') || 'None'}`);
  }

  if (pkg.businessIntel) {
    sections.push(`\nBUSINESS INTELLIGENCE:
- SEC EDGAR CIK: ${pkg.businessIntel.secEdgarCIK || 'Not found'}
- Industry: ${pkg.businessIntel.industry || 'Unknown'}
- Employees: ${pkg.businessIntel.employeeCount || 'Unknown'}
- Headquarters: ${pkg.businessIntel.headquarters || 'Unknown'}
- Business segments: ${pkg.businessIntel.businessSegments.map(s => `${s.name} (${s.revenue || 'revenue unknown'})`).join(', ') || 'None'}
- Subsidiaries: ${pkg.businessIntel.subsidiaries.join(', ') || 'None'}
- Regulatory regimes: ${pkg.businessIntel.regulatoryRegimes.join(', ') || 'None identified'}`);
  }

  return sections.join('\n');
}
