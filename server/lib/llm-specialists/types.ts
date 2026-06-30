/**
 * LLM Specialists — Shared Type Definitions
 * 
 * All specialist modules share these core interfaces for evidence handling,
 * validation, invocation metadata, and scoring integration.
 * 
 * Architecture: Each specialist follows the pattern:
 *   evidence package → deterministic baseline → LLM augmentation → validation → output
 */

// ─── Specialist Modes ─────────────────────────────────────────────
export type SpecialistMode = "full_llm" | "deterministic_only" | "confidence_degraded";

// ─── Evidence Primitives ──────────────────────────────────────────
export type EvidenceWeight = "strong" | "moderate" | "weak";
export type ConfidenceBand = "high" | "medium" | "low";

export interface EvidenceReference {
  source: string;         // e.g., "certificate.subject_o", "rdap.registrant"
  evidenceType: string;   // e.g., "direct_identity", "corroborating_business"
  weight: EvidenceWeight;
  detail: string;         // verbatim from input package — MUST be a direct quote
}

export interface ContradictingEvidence {
  source: string;
  detail: string;
  contradicts: string;    // which claim or field this contradicts
  severity: "major" | "minor";
}

export interface AlternativeAttribution {
  organization: string;
  confidenceScore: number;
  rationale: string;
  ruledOutBy?: string;
}

// ─── Evidence Package Components ──────────────────────────────────
export interface CertificateEvidence {
  subjectO?: string;
  subjectCN?: string;
  issuerO?: string;
  issuerCN?: string;
  san?: string[];
  validFrom?: string;
  validTo?: string;
  serialNumber?: string;
  signatureAlgorithm?: string;
  isExpired?: boolean;
  isSelfSigned?: boolean;
  isWildcard?: boolean;
}

export interface DNSEvidence {
  aRecords?: string[];
  aaaaRecords?: string[];
  cnameChain?: string[];
  mxRecords?: string[];
  nsRecords?: string[];
  txtRecords?: string[];
  soaRecord?: { mname?: string; rname?: string; serial?: number };
  reversePtr?: string;
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
}

export interface BGPEvidence {
  asn?: number;
  asHolder?: string;
  prefix?: string;
  rir?: string;
  country?: string;
  peerCount?: number;
}

export interface WHOISEvidence {
  registrant?: string;
  registrantOrg?: string;
  registrantCountry?: string;
  adminContact?: string;
  techContact?: string;
  nameServers?: string[];
  creationDate?: string;
  updatedDate?: string;
  expirationDate?: string;
  privacyProtected?: boolean;
  registrar?: string;
}

export interface HTTPEvidence {
  serverHeader?: string;
  poweredBy?: string;
  technologies?: string[];
  title?: string;
  metaGenerator?: string;
  securityHeaders?: Record<string, string>;
  statusCode?: number;
  redirectChain?: string[];
  responseTimeMs?: number;
  contentLength?: number;
}

export interface BusinessIntelEvidence {
  secEdgarMatch?: {
    companyName: string;
    cik: string;
    sic?: string;
    sicDescription?: string;
    stateOfIncorporation?: string;
    revenue?: string;
  };
  publicReferences?: string[];
  linkedinMatch?: string;
  crunchbaseMatch?: string;
  sector?: string;
  industry?: string;
  employeeCount?: string;
}

export interface StructuredEvidencePackage {
  assetId: string;
  assetIdentifier: string;  // domain, IP, or hostname
  observedIPs?: string[];
  firstSeen?: string;
  lastSeen?: string;
  certificate?: CertificateEvidence;
  dns?: DNSEvidence;
  bgp?: BGPEvidence;
  whois?: WHOISEvidence;
  http?: HTTPEvidence;
  businessIntel?: BusinessIntelEvidence;
  crossReferenceConvergence?: {
    sourcesChecked: string[];
    convergingOn?: string;
    divergences?: string[];
  };
  negativeEvidence?: {
    checkedButNotFound: string[];
  };
}

// ─── Attribution Specialist Types ─────────────────────────────────
export type AttributionClaimType =
  | "primary_owner"
  | "subsidiary"
  | "third_party_hosted"
  | "vendor_managed"
  | "partner_integration"
  | "unknown";

export type OrganizationType =
  | "public_company"
  | "private_company"
  | "subsidiary"
  | "government"
  | "nonprofit"
  | "unknown";

export interface AttributionClaim {
  attributedTo: {
    organization: string;
    legalEntity?: string;
    parentOrganization?: string;
    organizationType?: OrganizationType;
  };
  claimType: AttributionClaimType;
  confidence: ConfidenceBand;
  confidenceScore: number;  // 0-100
  supportingEvidence: EvidenceReference[];
  contradictingEvidence?: ContradictingEvidence[];
  alternativeAttributions?: AlternativeAttribution[];
  reasoning: string;
}

export interface AttributionSpecialistInput {
  assetId: string;
  evidencePackage: StructuredEvidencePackage;
  engagementContext?: EngagementContext;
  configurationHints?: SpecialistConfigHints;
}

export interface AttributionSpecialistOutput {
  asset: { id: string; identifier: string };
  claims: AttributionClaim[];
  primaryClaim?: AttributionClaim;
  evidenceSufficiency: "sufficient" | "partial" | "insufficient";
  insufficiencyReason?: string;
  validationResult: ValidationResult;
  metadata: SpecialistInvocationMetadata;
}

// ─── Role Specialist Types ────────────────────────────────────────
export type AssetExposure = "customer_facing" | "internal" | "partner" | "unknown";
export type AssetEnvironment = "production" | "staging" | "development" | "testing" | "unknown";
export type AssetCriticality = "primary" | "backup" | "auxiliary" | "unknown";

export interface RoleInference {
  exposure: AssetExposure;
  environment: AssetEnvironment;
  criticality: AssetCriticality;
  confidenceScore: number;
  supportingEvidence: EvidenceReference[];
  reasoning: string;
}

export interface RoleSpecialistInput {
  assetId: string;
  evidencePackage: StructuredEvidencePackage;
  engagementContext?: EngagementContext;
}

export interface RoleSpecialistOutput {
  asset: { id: string; identifier: string };
  role: RoleInference;
  alternativeRoles?: RoleInference[];
  validationResult: ValidationResult;
  metadata: SpecialistInvocationMetadata;
}

// ─── Lifecycle Specialist Types ───────────────────────────────────
export type LifecycleStage = "active" | "declining" | "abandoned" | "unknown";

export interface LifecycleSignal {
  signal: string;
  direction: "active" | "declining" | "abandoned";
  weight: EvidenceWeight;
  detail: string;
}

export interface LifecycleSpecialistInput {
  assetId: string;
  evidencePackage: StructuredEvidencePackage;
  engagementContext?: EngagementContext;
}

export interface LifecycleSpecialistOutput {
  asset: { id: string; identifier: string };
  stage: LifecycleStage;
  confidenceScore: number;
  signals: LifecycleSignal[];
  estimatedAge?: string;
  lastActivityIndicator?: string;
  validationResult: ValidationResult;
  metadata: SpecialistInvocationMetadata;
}

// ─── Business Context Specialist Types ────────────────────────────
export interface BusinessUnitAttribution {
  unit: string;
  confidence: ConfidenceBand;
  supportingEvidence: EvidenceReference[];
}

export interface RegulatoryExposure {
  framework: string;
  applicability: "definite" | "probable" | "possible";
  reasoning: string;
}

export interface DependencyEdge {
  dependsOn: string;
  relationship: "hosts" | "serves" | "authenticates" | "proxies" | "unknown";
  confidence: ConfidenceBand;
}

export interface BusinessContextSpecialistInput {
  assetId: string;
  evidencePackage: StructuredEvidencePackage;
  engagementContext?: EngagementContext;
  customerIndustry?: string;
  customerSize?: string;
}

export interface BusinessContextSpecialistOutput {
  asset: { id: string; identifier: string };
  businessUnit?: BusinessUnitAttribution;
  function?: string;
  revenuePath?: "direct" | "supporting" | "internal" | "unknown";
  regulatoryExposure: RegulatoryExposure[];
  dependencies: DependencyEdge[];
  validationResult: ValidationResult;
  metadata: SpecialistInvocationMetadata;
}

// ─── Threat Relevance Specialist Types ────────────────────────────
export interface ThreatActorRelevance {
  actorType: string;
  relevanceScore: number;
  attackPatterns: string[];
  reasoning: string;
  supportingEvidence: EvidenceReference[];
}

export interface SectorExposurePattern {
  sector: string;
  exposureLevel: "high" | "medium" | "low";
  knownCampaigns?: string[];
  reasoning: string;
}

export interface ActiveCampaignCorrelation {
  campaignId?: string;
  campaignName: string;
  correlationStrength: ConfidenceBand;
  matchingIndicators: string[];
}

export interface ThreatRelevanceSpecialistInput {
  assetId: string;
  evidencePackage: StructuredEvidencePackage;
  engagementContext?: EngagementContext;
  customerIndustry?: string;
}

export interface ThreatRelevanceSpecialistOutput {
  asset: { id: string; identifier: string };
  actorRelevance: ThreatActorRelevance[];
  sectorExposure: SectorExposurePattern[];
  activeCampaigns: ActiveCampaignCorrelation[];
  overallThreatScore: number;
  validationResult: ValidationResult;
  metadata: SpecialistInvocationMetadata;
}

// ─── Validation Types ─────────────────────────────────────────────
export interface ValidationResult {
  passed: boolean;
  groundingChecks: {
    allEvidenceReferencesExistInInput: boolean;
    noTrainingDataCitations: boolean;
    confidenceWithinEvidenceBounds: boolean;
  };
  failures: string[];
  fallbackApplied?: boolean;
}

// ─── Invocation Metadata ──────────────────────────────────────────
export interface SpecialistInvocationMetadata {
  invocationId: string;
  specialistName: string;
  specialistVersion: string;
  promptVersion: string;
  modelVersion: string;
  durationMs: number;
  fallbackApplied: boolean;
  mode: SpecialistMode;
  inputPackageHash: string;
  timestamp: string;
}

// ─── Engagement Context ───────────────────────────────────────────
export interface EngagementContext {
  customerName?: string;
  customerIndustry?: string;
  customerSize?: string;
  engagementType?: string;
  scopeDescription?: string;
  // Explicitly marked "do not cite" — background only
}

export interface SpecialistConfigHints {
  preferDeterministic?: boolean;
  maxLLMLatencyMs?: number;
  cacheTTLDays?: number;
}

// ─── Discovery Tier Classification ────────────────────────────────
export type DiscoveryTier = "bullseye" | "perimeter" | "peripheral" | "unknown";

// ─── Negative Finding ─────────────────────────────────────────────
export interface NegativeFinding {
  checked: string;
  result: "not_found" | "inconclusive" | "error";
  implication: string;
  checkedAt: string;
}

// ─── Composite Discovery Context ──────────────────────────────────
export interface DiscoveryContext {
  assetId: string;
  assetIdentifier: string;
  tier: DiscoveryTier;
  attribution: AttributionSpecialistOutput;
  role: RoleSpecialistOutput;
  lifecycle: LifecycleSpecialistOutput;
  businessContext: BusinessContextSpecialistOutput;
  threatRelevance: ThreatRelevanceSpecialistOutput;
  negativeFindings: NegativeFinding[];
  overallConfidence: number;
  mode: SpecialistMode;
  timestamp: string;
}

// ─── Scoring Integration Types ────────────────────────────────────
export interface AttributionScoringOutput {
  attributionConfidenceMultiplier: number;
  attributionStatus: "attributed" | "partial" | "insufficient";
  attributedOrganization: string | null;
  attributionLegalEntity?: string | null;
  attributionParent?: string | null;
  attributionClaimType?: AttributionClaimType;
  attributionEvidenceCount: number;
}

export interface CarverScores {
  criticality: number;
  accessibility: number;
  recuperability: number;
  vulnerability: number;
  effect: number;
  recognizability: number;
}

// ─── LLM Invoke Signature ─────────────────────────────────────────
export type LLMInvokeFunction = (messages: Array<{ role: string; content: string }>) => Promise<any>;
