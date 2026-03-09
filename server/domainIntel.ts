/**
 * Domain Intel Engine
 * 
 * Multi-stage pipeline inspired by SpicyTip:
 * 1. Passive Discovery (LLM-powered subdomain, tech stack, email pattern inference)
 * 2. Asset Signal Extraction & Classification
 * 3. Auto-BIA Inference (CARVER+SHOCK factor scoring)
 * 4. Hybrid Risk Scoring (CVSS + Mission Impact + Context)
 * 5. Campaign Recommendation (Caldera abilities + GoPhish templates)
 */

import { invokeLLM } from "./_core/llm";
import { fetchKevCatalog, matchTechnologiesAgainstKev, calculateKevRiskBoost, getKevChainSteps, type KevMatch } from "./lib/kev-service";
import { runPassiveRecon, type PassiveReconResult, type ScanMode } from "./lib/passive/index";
import { enrichAssetsWithShodanData, verifyCvesWithShodanData, createShodanPostureFindings } from "./lib/shodan-verifier";
import { matchExploitsToFindings, type ExploitMatch } from "./lib/exploit-matcher";
import { ENV } from "./_core/env";
import { runCrossModuleEnrichment, type CrossModuleEnrichmentResult } from "./lib/cross-module-enrichment";
import { discoverOrgDomains, type OrgDiscoveryResult } from "./lib/org-domain-discovery";
import { runPostEnrichmentAnalysis, type PostEnrichmentAnalysis } from "./lib/llm-post-enrichment-analysis";
import { runWafNgfwAssessment, buildNmapCommand, buildNucleiCommand, type WafNgfwAssessment } from "./lib/waf-ngfw-detection";

// ─── Types ───────────────────────────────────────────────────────────

export interface OrgProfile {
  customerName: string;
  primaryDomain: string;
  additionalDomains?: string[];
  sector: string;
  clientType: string;
  criticalFunctions: string[];
  complianceFlags: string[];
  notes?: string;
}

export interface DiscoveredAssetRaw {
  assetId: string;
  hostname: string;
  url?: string;
  assetType: string;
  dnsRecords?: Record<string, any>;
  dnsStatus?: string;
  headers?: string;
  technologies?: string[];
  technologyVersions?: Record<string, string>; // e.g. { "nginx": "1.18.0", "OpenSSL": "1.1.1" }
  assetClasses: string[];
  tags: string[];
  description?: string;
  discoveryMethod?: "inferred" | "dns_verified" | "cert_transparency" | "header_detected";
  discoveryEvidence?: string; // What data supports this asset's existence
}

export interface CarverScores {
  criticality: number;
  accessibility: number;
  recuperability: number;
  vulnerability: number;
  effect: number;
  recognizability: number;
}

export interface ShockScores {
  scope: number;
  handling: number;
  operationalImpact: number;
  cascadingEffects: number;
  knowledge: number;
}

/**
 * Corroboration tiers for findings:
 * - confirmed: Version detected AND matched to specific CVE affected version range. Severity uncapped.
 * - probable: Product/brand detected but version unknown; CVE exists for this product family. Severity capped at 6.
 * - potential: LLM-inferred risk with no CVE backing. Severity capped at 4. Shown as advisory.
 */
export type CorroborationTier = "confirmed" | "probable" | "potential";

export interface PostureFinding {
  id: string;
  assetRef: string;
  assetHostname?: string; // Human-readable hostname
  category: string;
  title: string;
  severity: number; // 0-10
  likelihood: number; // 0-10
  confidence: number; // 0-1
  recommendedControls: string[];
  cveIds?: string[]; // Associated CVE IDs
  kevListed?: boolean; // On CISA KEV list
  exploitAvailable?: boolean; // Public exploit exists
  cvssScore?: number; // Actual CVSS score from NVD
  affectedAssets?: string[]; // Hostnames of affected assets
  evidenceBasis?: "confirmed_cve" | "kev_match" | "vuln_feed" | "llm_inference" | "technology_match";
  evidenceDetail?: string; // How this finding was determined
  // Corroboration fields
  corroborationTier: CorroborationTier;
  detectedVersion?: string; // The actual version detected (if any)
  affectedVersions?: string; // The CVE's affected version range (e.g. "< 1.21.0")
  versionMatchConfirmed?: boolean; // True if detected version falls within affected range
  evidenceChain?: string[]; // Step-by-step evidence trail
}

export interface TestVector {
  id: string;
  assetRef: string;
  vectorType: string;
  hypothesis: string;
  prerequisites: string[];
  suggestedEmulation: {
    technique?: string;
    tactic?: string;
    calderaAbilityHint?: string;
  };
  expectedTelemetry: string[];
  riskSignal: { severity: number; likelihood: number };
}

export interface CampaignRecommendation {
  id: string;
  name: string;
  type: "red_team" | "phishing" | "purple_team" | "pentest";
  priority: "critical" | "high" | "medium" | "low";
  description: string;
  targetAssets: string[];
  // Caldera mapping
  calderaAbilities: Array<{
    abilityId?: string;
    name: string;
    tactic: string;
    technique: string;
    rationale: string;
  }>;
  // GoPhish mapping
  gophishTemplates: Array<{
    name: string;
    subject: string;
    theme: string;
    targetPersona: string;
    rationale: string;
  }>;
  // Attack chain
  attackChain: Array<{
    step: number;
    phase: string;
    action: string;
    technique: string;
    tool: string;
  }>;
  estimatedRisk: number;
  mitreTactics: string[];
}

export interface AssetAnalysis {
  asset: DiscoveredAssetRaw;
  carverScores: CarverScores;
  shockScores: ShockScores;
  missionImpactScore: number;
  suggestedTier: string;
  hybridRiskScore: number;
  riskBand: string;
  cvssEstimate: number;
  contextIndicators: { exposure: number; recognizability: number; confidence: number };
  postureFindings: PostureFinding[];
  testVectors: TestVector[];
  confidence: number;
  // Separated scores: asset criticality vs vulnerability risk
  assetCriticalityScore: number; // 0-100, derived from CARVER+SHOCK (how important the asset is)
  assetCriticalityBand: string;  // "critical" | "high" | "medium" | "low" — asset importance only
  vulnRiskScore: number;         // 0-100, derived from confirmed/probable scan findings only
  vulnRiskBand: string;          // "critical" | "high" | "medium" | "low" — scan-confirmed weakness only
  // Impact × Likelihood decomposition (for analyst transparency)
  impactScore: number;           // 0-100, normalized from CARVER/SHOCK mission impact
  likelihoodScore: number;       // 0-100, derived from CVSS + exposure + recognizability, dampened by confidence
  // Mission Function Classification
  missionFunction: string;       // e.g., 'authentication_and_access', 'revenue_generation'
  essentialService: string;      // e.g., 'sso_idp', 'payment_processing'
  businessImpactLevel: string;   // 'catastrophic' | 'severe' | 'significant' | 'moderate' | 'minimal'
  deviceType: string;            // e.g., 'server', 'cloud_service', 'network_appliance'
  platformType: string;          // e.g., 'linux_server', 'cloud_saas', 'web_application'
  missionJustification: string;  // Brief explanation of why this asset is critical
}

export interface KevEnrichment {
  matches: KevMatch[];
  riskBoost: number;
  ransomwareExposure: boolean;
  criticalKevCount: number;
  summary: string;
  chainSteps: Array<{ techniqueId: string; priority: number; source: "kev"; context: string }>;
}

export interface RescoringTimelineEntry {
  assetId: string;
  hostname: string;
  phase: string;
  triggerType: string;
  previousScore: number;
  newScore: number;
  delta: number;
  previousBand: string;
  newBand: string;
  changeDescription: string;
  factorChanges: Array<{ factor: string; previousValue: number; newValue: number; reason: string }>;
  timestamp: number;
}

export interface PipelineResult {
  orgProfile: OrgProfile;
  assets: AssetAnalysis[];
  campaignRecommendations: CampaignRecommendation[];
  overallRiskScore: number;
  overallRiskBand: string;
  executiveSummary: string;
  threatModelSummary: string;
  totalAssets: number;
  totalFindings: number;
  confirmedFindingsCount: number;
  probableFindingsCount: number;
  potentialFindingsCount: number;
  kevEnrichment?: KevEnrichment;
  passiveRecon?: PassiveReconResult;
  breachData?: BreachDataSummary;
  exploitMatches?: {
    matches: ExploitMatch[];
    totalMetasploit: number;
    totalExploitDb: number;
    totalCalderaAbilities: number;
    remoteAccessCount: number;
  };
  rescoringTimeline?: RescoringTimelineEntry[];
  emailSecurity?: {
    domain: string;
    analyzedAt: string;
    overallScore: number;
    overallGrade: string;
    totalWeaknesses: number;
    criticalWeaknesses: number;
    phishingDifficultyRating: string;
    phishingSummary: string;
    recommendations: string[];
    spf: { exists: boolean; record: string | null; score: number; weaknesses: Array<{ id: string; severity: string; title: string; description: string; phishingRelevance: string }> };
    dkim: { selectorsFound: string[]; score: number; weaknesses: Array<{ id: string; severity: string; title: string; description: string; phishingRelevance: string }> };
    dmarc: { exists: boolean; record: string | null; policy: string | null; score: number; weaknesses: Array<{ id: string; severity: string; title: string; description: string; phishingRelevance: string }> };
    mx: { records: Array<{ priority: number; exchange: string }>; provider: string | null; weaknesses: Array<{ id: string; severity: string; title: string; description: string; phishingRelevance: string }> };
  };
  discoveryCoverage?: {
    coverageScore: number;
    prioritiesCovered: number;
    totalPriorities: number;
    coverageBand: string;
    assessment: string;
    structuralGaps: string[];
    actionableGaps: string[];
    priorities: Array<{
      id: number;
      name: string;
      shortName: string;
      weight: number;
      covered: boolean;
      observationCount: number;
      contributingConnectors: string[];
      quality: string;
      hasConnectors: boolean;
      attackTechniques: string[];
    }>;
  };
  crossModuleEnrichment?: CrossModuleEnrichmentResult;
  postEnrichmentAnalysis?: PostEnrichmentAnalysis;
  orgDiscovery?: OrgDiscoveryResult;
  oemCredentials?: Array<{
    vendor: string;
    product: string;
    protocol: string;
    port: number | null;
    username: string;
    password: string;
    accessLevel: string;
    tags: string[];
    matchedTechnology: string;
    matchedAsset: string;
  }>;
  /** External SCAP/STIG compliance scan results */
  complianceScan?: {
    target: string;
    complianceScore: number;
    totalChecks: number;
    passed: number;
    failed: number;
    notApplicable: number;
    manualReview: number;
    errors: number;
    benchmarkProfile: string;
    scanType: string;
    durationMs: number;
    checks: Array<{
      checkId: string;
      title: string;
      category: string;
      severity: string;
      status: string;
      evidence: string;
      remediation: string;
      benchmarkRef: string;
      stigId?: string;
      nistControls: string[];
    }>;
  };
  /** Container infrastructure exposure findings */
  containerExposure?: {
    totalProbes: number;
    totalHits: number;
    criticalFindings: number;
    highFindings: number;
    findings: Array<{
      service: string;
      category: string;
      port: number;
      path: string;
      severity: string;
      authenticated: boolean;
      version?: string;
      matchedSignatures: string[];
      riskDescription: string;
      cveRefs: string[];
      mitreTechniques: string[];
    }>;
    subdomainsProbed: string[];
    durationMs: number;
  };
  /** WAF/NGFW detection and scan tuning profile */
  wafNgfwAssessment?: WafNgfwAssessment;
  /** Summary of automated credential testing against discovered services */
  credentialTestSummary?: {
    totalTargets: number;
    totalCredentialsTested: number;
    successfulLogins: number;
    failedAttempts: number;
    timeouts: number;
    errors: number;
    confirmedCredentials: Array<{
      host: string;
      port: number;
      protocol: string;
      vendor: string;
      product: string;
      username: string;
      accessLevel: string;
    }>;
  };
  /** Cross-session scan delta — comparison against previous scan of the same domain */
  scanDelta?: {
    previousScanId: number;
    previousScanDate: string;
    scanNumber: number;
    riskDelta: number | null; // positive = risk increased, negative = improved
    previousRiskScore: number | null;
    assetDelta: number | null; // positive = more assets discovered
    previousTotalAssets: number | null;
    findingsDelta: number | null;
    previousTotalFindings: number | null;
    newAssets: string[]; // hostnames not seen in previous scan
    removedAssets: string[]; // hostnames in previous scan but not in current
    persistentAssets: string[]; // hostnames in both scans
  };
}

export interface BreachDataSummary {
  totalExposures: number;
  uniqueEmails: number;
  uniqueBreachSources: number;
  breachSources: string[];
  passwordsExposed: number;
  hashedPasswordsExposed: number;
  credentialPairs: number;
  subdomainsDiscovered: number;
  ipsDiscovered: number;
  queriedAt: string;
}

// ─── Utility ─────────────────────────────────────────────────────────

function clamp(x: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, x));
}

/** Sanitize LLM output: strip markdown fences, fix common JSON issues */
function sanitizeJsonResponse(raw: string): string {
  let s = raw.trim();
  // Strip markdown code fences
  if (s.startsWith('```')) {
    s = s.replace(/^```(?:json)?\s*\n?/, '').replace(/\n?```\s*$/, '');
  }
  // Strip leading/trailing whitespace
  s = s.trim();
  // If it doesn't start with { or [, try to find the first { or [
  if (!s.startsWith('{') && !s.startsWith('[')) {
    const objIdx = s.indexOf('{');
    const arrIdx = s.indexOf('[');
    if (objIdx >= 0 && (arrIdx < 0 || objIdx < arrIdx)) {
      s = s.substring(objIdx);
    } else if (arrIdx >= 0) {
      s = s.substring(arrIdx);
    }
  }
  return s;
}

/** Safely parse JSON from LLM response with fallback */
function safeParseLLMJson(content: unknown, fallback: any = {}): any {
  const raw = String(content || '{}');
  try {
    return JSON.parse(sanitizeJsonResponse(raw));
  } catch {
    console.error('[DomainIntel] JSON parse failed, raw content:', raw.substring(0, 500));
    return fallback;
  }
}

// ─── Stage 1: LLM-Powered Passive Discovery ─────────────────────────

export async function discoverAssets(org: OrgProfile, fpContext?: { patterns: { title: string; type: string | null; reason: string; occurrences: number }[] }, passiveContext?: string): Promise<DiscoveredAssetRaw[]> {
  const allDomains = [org.primaryDomain, ...(org.additionalDomains || [])];
  
  // Build FP learning context for the LLM
  let fpLearningBlock = '';
  if (fpContext && fpContext.patterns.length > 0) {
    const fpLines = fpContext.patterns.slice(0, 20).map(p =>
      `  - "${p.title}" (type: ${p.type || 'unknown'}, marked ${p.occurrences}x) — Analyst reason: ${p.reason}`
    ).join('\n');
    fpLearningBlock = `\n\nANALYST FEEDBACK (False Positive History):\nThe following finding patterns have been previously marked as false positives by security analysts. Use these insights to calibrate your asset discovery — avoid inferring assets that consistently produce these false positive patterns unless you have strong evidence they exist:\n${fpLines}\n`;
  }
  
  const prompt = `You are a passive OSINT reconnaissance analyst. Given the following organization profile, infer and enumerate likely digital assets that would exist for this organization. This is PASSIVE analysis only - no active scanning.

Organization:
- Name: ${org.customerName}
- Primary Domain: ${org.primaryDomain}
- Additional Domains: ${(org.additionalDomains || []).join(", ") || "none"}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${(org.criticalFunctions || []).join(", ") || "none specified"}
- Compliance: ${(org.complianceFlags || []).join(", ") || "none specified"}
- Notes: ${org.notes || "none"}${fpLearningBlock}${passiveContext || ''}

For each domain (${allDomains.join(", ")}), ${passiveContext ? 'use the PASSIVE RECONNAISSANCE DATA above as your PRIMARY AND AUTHORITATIVE source. ONLY include assets that appear in the passive recon data (confirmed subdomains, IPs, services from crt.sh, Shodan, Censys, SecurityTrails, etc.). You may add a SMALL number (max 3-5) of high-confidence inferences' : 'infer likely subdomains, services, and assets'} based on:
1. Common subdomain patterns for this sector and client type
2. Expected technology stack based on sector
3. Likely email infrastructure (MX, SPF, DMARC patterns)
4. Common SaaS/cloud services for this sector
5. Authentication endpoints (SSO, VPN, OWA)
6. Developer/API endpoints
7. Customer-facing portals
8. Internal tools likely exposed

For each asset, classify it and assess its exposure level.

Return a JSON array of discovered assets. Each asset must have:
{
  "assetId": "a-001",
  "hostname": "subdomain.domain.com",
  "url": "https://subdomain.domain.com",
  "assetType": "sso|mail_gateway|api|payment|cdn|vpn|owa|crm|erp|dev|ci_cd|storage|database|monitoring|customer_portal|admin_panel|other",
  "technologies": ["nginx", "Microsoft 365", etc],
  "technologyVersions": {"nginx": "1.18.0", "OpenSSL": "1.1.1", etc},  // Include version numbers when they can be reasonably inferred from sector/client type patterns. Use null for unknown versions.
  "assetClasses": ["identity_provider", "email_infrastructure", etc],
  "tags": ["internet_exposed", "authentication", "critical_data", etc],
  "description": "Brief description of what this asset likely does",
  "dnsRecords": {"A": [], "CNAME": [], "MX": [], "TXT": [], "NS": []},
  "headers": "likely server headers"
}

IMPORTANT: For the "technologyVersions" field, only include version numbers you have HIGH confidence about based on:
- Common default versions for this sector/client type
- Versions implied by other technology choices (e.g., if using Ubuntu 22.04, OpenSSL is likely 3.0.x)
- DO NOT guess random version numbers. If you cannot reasonably infer the version, omit that technology from technologyVersions.

CRITICAL DATA INTEGRITY RULES:
- Assets from passive recon data are CONFIRMED — mark discoveryMethod as "cert_transparency" or "dns_verified"
- Assets you infer (not in passive recon) are HYPOTHESES — mark discoveryMethod as "inferred"
- NEVER invent fake version numbers, CVE IDs, or service details
- If passive recon found 50 subdomains, include ALL of them — do not truncate
- If no passive recon data is available, generate max 10 conservative guesses (root domain + common patterns only)

ASSET DEDUPLICATION & SCOPING RULES:
- ONE ASSET PER UNIQUE HOSTNAME — do NOT create separate assets for different URL paths, query strings, or static files on the same host. For example, if rapidtalentgroup.com serves /_next/static/*, /_next/image, /api/*, etc., these are ALL part of the single "rapidtalentgroup.com" asset.
- The "url" field should be the root URL of the hostname (e.g., https://subdomain.domain.com), NOT a specific path or resource URL.
- Do NOT create assets for individual JavaScript files, CSS files, images, API endpoints, or static resources — these are resources served by a host, not separate assets.
- Do NOT create assets for third-party SaaS provider hostnames that the organization does not own or operate. Examples: outlook.office365.com, login.microsoftonline.com, mail.google.com, accounts.google.com, *.salesforce.com, *.zendesk.com, *.cloudflare.com. Instead, note the SaaS dependency as a tag on the root domain asset (e.g., tags: ["uses_o365", "uses_cloudflare"]).
- Do NOT create assets for DNS infrastructure (nameservers, SOA records). NS records like dns1.p02.nsone.net are third-party DNS providers, not target assets. Record DNS provider info as metadata on the root domain.
- Do NOT create assets for MX record hostnames that point to third-party email providers (e.g., *.mail.protection.outlook.com, aspmx.l.google.com). Note the email provider as a tag on the root domain.

Generate assets based on passive recon data. Be specific to the sector and client type. For ${org.clientType} clients, emphasize:
${org.clientType === "msp" ? "- Multi-tenant management portals, RMM tools, PSA platforms, client VPN endpoints, backup systems" : ""}
${org.clientType === "enterprise" ? "- Corporate SSO, Active Directory, Exchange/O365, ERP systems, internal wikis, VPN concentrators" : ""}
${org.clientType === "saas" ? "- API endpoints, customer dashboards, billing portals, CI/CD pipelines, staging environments" : ""}
${org.clientType === "paas" ? "- Container registries, orchestration dashboards, developer portals, build systems" : ""}
${org.clientType === "iaas" ? "- Cloud consoles, hypervisor management, storage APIs, network management, tenant isolation" : ""}
${org.clientType === "mixed_hosting" ? "- Shared hosting panels, dedicated server management, DNS management, billing, support portals" : ""}

Return ONLY the JSON array, no markdown fences.`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a cybersecurity OSINT analyst. Return only valid JSON arrays." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const content = response.choices?.[0]?.message?.content;
    const parsed = safeParseLLMJson(content, { assets: [] });
    // Handle both { assets: [...] } and direct array format
    const rawAssets = Array.isArray(parsed) ? parsed : (parsed.assets || []);
    // Tag provenance: LLM-discovered assets default to "inferred" unless they claim a real source
    const validRealMethods = new Set(['cert_transparency', 'dns_verified', 'header_detected']);
    return rawAssets.map((a: any) => {
      const claimedMethod = a.discoveryMethod || 'inferred';
      // Only trust real discovery methods if the LLM explicitly set them AND passive recon data was provided
      const isRealMethod = validRealMethods.has(claimedMethod) && !!passiveContext;
      return {
        ...a,
        discoveryMethod: isRealMethod ? claimedMethod : 'inferred',
        discoveryEvidence: a.discoveryEvidence || `Inferred from ${org.sector} ${org.clientType} patterns for ${org.primaryDomain}`,
        _provenance: isRealMethod ? 'passive_recon_confirmed' : 'llm_inferred',
      };
    });
  } catch (err) {
    console.error("[DomainIntel] Discovery failed:", err);
    return generateFallbackAssets(org);
  }
}

function generateFallbackAssets(org: OrgProfile): DiscoveredAssetRaw[] {
  // NO FAKE ASSETS — only return the root domain which we know exists.
  // All other assets must come from real passive recon connectors or DNS-verified discovery.
  console.warn(`[DomainIntel] LLM asset discovery failed for ${org.primaryDomain}. Returning only root domain — all other assets must come from passive recon connectors.`);
  return [
    {
      assetId: `root-${org.primaryDomain.replace(/\./g, '-')}`,
      hostname: org.primaryDomain,
      url: `https://${org.primaryDomain}`,
      assetType: "other",
      assetClasses: ["dns_root"],
      tags: ["internet_exposed"],
      description: "Root domain (LLM discovery failed — only passive recon data available)",
      discoveryMethod: "inferred" as const,
      discoveryEvidence: "Primary domain root — LLM discovery fallback",
    },
  ];
}

// ─── Stage 2: Asset Classification & BIA Scoring (LLM) ──────────────

export async function analyzeAssets(
  assets: DiscoveredAssetRaw[],
  org: OrgProfile,
  fpContext?: { patterns: { title: string; type: string | null; severity: string | null; reason: string; occurrences: number }[]; categorySummary: { type: string; count: number }[] },
  historicalContext?: string
): Promise<AssetAnalysis[]> {
  // Build FP learning context for severity calibration
  let fpCalibrationBlock = '';
  if (fpContext && fpContext.patterns.length > 0) {
    const fpLines = fpContext.patterns.slice(0, 30).map(p =>
      `  - "${p.title}" (type: ${p.type || 'unknown'}, severity: ${p.severity || '?'}, marked FP ${p.occurrences}x) — Analyst reason: ${p.reason}`
    ).join('\n');
    const catLines = fpContext.categorySummary.slice(0, 10).map(c =>
      `  - ${c.type}: ${c.count} false positives`
    ).join('\n');
    fpCalibrationBlock = `\n\nANALYST FALSE POSITIVE FEEDBACK:\nSecurity analysts have reviewed previous scan results and marked the following findings as false positives. Use this feedback to CALIBRATE your severity and likelihood scores — reduce confidence for finding patterns that analysts consistently reject, and avoid generating findings that match these known FP patterns unless you have strong new evidence:\n\nKnown FP Patterns:\n${fpLines}\n\nFP Rates by Category:\n${catLines}\n\nIMPORTANT: This feedback represents real analyst expertise. Findings matching these patterns should have LOWER severity and confidence scores unless new evidence contradicts the analyst's assessment.\n`;
  }

  const prompt = `You are a cybersecurity risk analyst performing Business Impact Analysis using the CARVER+SHOCK methodology combined with hybrid risk scoring.

Organization Profile:
- Name: ${org.customerName}
- Domain: ${org.primaryDomain}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${(org.criticalFunctions || []).join(", ") || "none specified"}
- Compliance: ${(org.complianceFlags || []).join(", ") || "none"}

Discovered Assets (${assets.length} total):
${JSON.stringify(assets.map(a => ({ id: a.assetId, hostname: a.hostname, type: a.assetType, classes: a.assetClasses, tags: a.tags, desc: a.description })), null, 2)}

For EACH asset, provide:

1. CARVER Scores (each 0-10):
   - Criticality: How critical is this asset to the organization's mission?
   - Accessibility: How accessible is this asset to an attacker?
   - Recuperability: How quickly can the org recover if this asset is compromised?
   - Vulnerability: How vulnerable is this asset based on its type and exposure?
   - Effect: What is the cascading effect of compromising this asset?
   - Recognizability: How easily can an attacker identify this as a valuable target?

2. SHOCK Scores (each 0-10):
   - Scope: How many people/systems are affected?
   - Handling: How difficult is incident response for this asset?
   - OperationalImpact: Direct impact on business operations?
   - CascadingEffects: Downstream failures from compromise?
   - Knowledge: Attacker knowledge required (inverse - low knowledge = high score)?

3. CVSS Estimate (0-10): Based on likely vulnerabilities for this asset type

4. Context Indicators (each 0-1):
   - exposure: Internet exposure level
   - recognizability: How easily identified as belonging to this org
   - confidence: Confidence in the assessment

5. Suggested Tier: tier0_critical, tier1_high, tier2_medium, tier3_low

6. Posture Findings: Security weaknesses identified (array of objects with id, category, title, severity 0-10, likelihood 0-10, confidence 0-1, recommendedControls[], cveIds[] (known CVE IDs if applicable - MUST be real CVE IDs like CVE-2024-XXXXX, do NOT invent fake CVE IDs))

DATA INTEGRITY RULES:
- For assets with discoveryMethod "inferred": set confidence to 0.3 or lower and add tag "unverified_hypothesis"
- For assets with discoveryMethod "cert_transparency" or "dns_verified": these are REAL and can have higher confidence
- NEVER invent CVE IDs. Only reference CVEs you are certain exist (e.g., CVE-2021-44228 for Log4Shell)
- CVSS estimates should be conservative (lower) for inferred assets and more precise for verified assets
- Posture findings for inferred assets should be marked with lower confidence (0.1-0.3)
   
   CRITICAL EVIDENCE RULES FOR POSTURE FINDINGS:
   - CONFIRMED findings: You have specific version info AND a matching real CVE. Severity can be 7-10. Likelihood can be 7-10.
   - PROBABLE findings: You know the technology family but NOT the version. Severity capped at 6. Likelihood capped at 6.
   - POTENTIAL findings: No version, no CVE — purely inferred from asset type. Severity capped at 5. Likelihood capped at 5.
   - ONLY confirmed findings with version-matched CVEs will drive the final risk rating. Potential findings are recorded as weaknesses but DO NOT affect the risk score.
   - Generic or theoretical risks (e.g., "web server might have XSS") are POTENTIAL — severity 3-5 max.
   - Do NOT inflate findings. If you cannot confirm a specific vulnerability, mark it as potential.
   - NEVER generate email security findings (missing DMARC, SPF, DKIM, email spoofing, email authentication) for ANY asset that is not a mail server (assetType 'mail_gateway'). This includes web servers, API endpoints, SSO portals, VPNs, admin panels, CDNs, load balancers, databases, CI/CD pipelines, monitoring tools, and all other non-mail assets. Email security analysis is handled separately by the dedicated email security analyzer and will only be assigned to mail-related assets. If an asset's assetType is not 'mail_gateway', do NOT create any findings with 'DMARC', 'SPF', 'DKIM', 'email security', 'email spoofing', or 'mail' in the title or category.

7. Test Vectors: Suggested attack vectors (array of objects with id, vectorType, hypothesis, suggestedEmulation {technique, tactic}, expectedTelemetry[], riskSignal {severity, likelihood})

8. Mission Function Classification (REQUIRED for each asset):
   Classify each asset's role in the organization's mission-essential functions:
   - missionFunction: One of: command_and_control, revenue_generation, customer_data_processing, intellectual_property_storage, authentication_and_access, communication_infrastructure, regulatory_compliance, business_continuity, supply_chain_integration, public_facing_services
   - essentialService: Specific service type, one of: sso_idp, active_directory, payment_processing, email_gateway, vpn_concentrator, dns_infrastructure, database_primary, database_replica, load_balancer, web_application_firewall, api_gateway, ci_cd_pipeline, monitoring_alerting, backup_recovery, file_storage, certificate_authority, secrets_management, container_orchestration, message_queue, cdn_edge, erp_system, crm_system, scada_hmi, medical_device, pos_terminal, voip_pbx, print_server, general_server
   - businessImpactLevel: One of: catastrophic, severe, significant, moderate, minimal
     * catastrophic: Complete mission failure, existential threat to organization
     * severe: Major mission degradation, significant financial/operational impact
     * significant: Noticeable mission impact, requires immediate attention
     * moderate: Limited impact, workarounds available
     * minimal: Negligible operational impact
   - deviceType: One of: server, workstation, network_appliance, iot_device, mobile_device, virtual_machine, container, cloud_service, embedded_system, unknown
   - platformType: One of: windows_server, linux_server, cloud_saas, cloud_iaas, cloud_paas, network_os, firmware, web_application, mobile_app, database_engine, unknown
   - missionJustification: Brief explanation of WHY this asset is critical to the identified mission function (1-2 sentences)

Return JSON with this exact structure:
{
  "analyses": [
    {
      "assetId": "a-001",
      "carverScores": { "criticality": 8, "accessibility": 7, ... },
      "shockScores": { "scope": 6, "handling": 7, ... },
      "cvssEstimate": 7.5,
      "contextIndicators": { "exposure": 0.6, "recognizability": 0.5, "confidence": 0.4 },
      "suggestedTier": "tier2_medium",
      "postureFindings": [...],
      "testVectors": [...],
      "missionFunction": "authentication_and_access",
      "essentialService": "sso_idp",
      "businessImpactLevel": "severe",
      "deviceType": "cloud_service",
      "platformType": "cloud_saas",
      "missionJustification": "SSO portal is the single authentication gateway for all employees; compromise grants lateral access to every connected system."
    }
  ]
}

SCORING CALIBRATION (CRITICAL):
- CARVER/SHOCK scores drive IMPACT (how bad if compromised), NOT the final risk rating. Score 3-6 for most assets. Only mission-critical assets (primary auth, payment, core DB) warrant 7+.
- CVSS estimate is a PLACEHOLDER only — it will be overridden by confirmed vulnerability data from KEV/NVD feeds. Set it conservatively: 2-3 for assets with no known vulns, 4-5 for assets with probable vulns, 7+ ONLY if you can cite a specific real CVE with version evidence.
- Confidence should be LOW (0.2-0.4) when you have no version info or confirmed vulnerabilities. Only use 0.6+ with specific version evidence. Only use 0.8+ with confirmed CVE + version match.
- The final risk score = sqrt(Impact × Likelihood). Likelihood is driven ONLY by confirmed/probable vulnerabilities. An asset with high CARVER scores but no confirmed vulns will correctly score LOW risk.
- A typical scan should produce: ~5-10% critical (confirmed CVEs on critical assets), ~15-25% high, ~40-50% medium, ~20-30% low. If most assets are critical/high, your scores are inflated.
- CDNs, static sites, and informational pages are LOW risk (tier3). APIs and SSO are MEDIUM unless specific vulns are confirmed.

Be thorough and realistic. Score based on the specific sector (${org.sector}) and client type (${org.clientType}).${fpCalibrationBlock}${historicalContext ? `\n\n${historicalContext}\n\nWhen analyzing assets, compare against the historical data above. For assets that appeared in the previous scan:\n- Note whether their risk profile has changed\n- Flag any NEW findings not present before\n- Indicate if previously identified vulnerabilities appear to be remediated\n- Adjust confidence scores upward for findings that persist across scans (confirmed by repeated observation)` : ''}`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a cybersecurity risk analyst. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const content = response.choices?.[0]?.message?.content;
    const parsed = safeParseLLMJson(content, { analyses: [] });
    const analysesMap = new Map<string, any>();
    for (const a of (parsed.analyses || [])) {
      analysesMap.set(a.assetId, a);
    }

    return assets.map((asset) => {
      const analysis = analysesMap.get(asset.assetId) || {};
      const carver = normalizeCarver(analysis.carverScores || {});
      const shock = normalizeShock(analysis.shockScores || {});
      // Lower defaults for missing data to prevent inflated scores
      const hasAnalysis = !!analysesMap.get(asset.assetId);
      const cvss = clamp(analysis.cvssEstimate || (hasAnalysis ? 4 : 3), 0, 10);
      const ctx = {
        exposure: clamp(analysis.contextIndicators?.exposure || (hasAnalysis ? 0.5 : 0.3), 0, 1),
        recognizability: clamp(analysis.contextIndicators?.recognizability || (hasAnalysis ? 0.5 : 0.3), 0, 1),
        confidence: clamp(analysis.contextIndicators?.confidence || (hasAnalysis ? 0.5 : 0.3), 0, 1),
      };

      const missionImpact = computeMissionImpact(carver, shock);
      const hybrid = computeHybridRisk(cvss, missionImpact, ctx);

      return {
        asset,
        carverScores: carver,
        shockScores: shock,
        missionImpactScore: Math.round(missionImpact * 10) / 10,
        suggestedTier: analysis.suggestedTier || inferTier(hybrid.score),
        hybridRiskScore: Math.round(hybrid.score),
        riskBand: hybrid.band,
        cvssEstimate: Math.round(cvss * 10) / 10,
        contextIndicators: ctx,
        postureFindings: (analysis.postureFindings || []).map((f: any, i: number) => {
          // Determine corroboration tier based on evidence
          const hasCveIds = f.cveIds && f.cveIds.length > 0;
          const tier: CorroborationTier = hasCveIds ? "probable" : "potential";
          // Cap severity based on tier: potential=4, probable=6, confirmed=uncapped
          const severityCap = tier === "potential" ? 4 : tier === "probable" ? 6 : 10;
          const rawSeverity = clamp(f.severity || 4, 0, 10);
          const cappedSeverity = Math.min(rawSeverity, severityCap);
          // Build evidence chain
          const evidenceChain: string[] = [
            `Asset "${asset.hostname}" identified as ${asset.assetType} (discovery: ${asset.discoveryMethod || "inferred"})`,
          ];
          if (hasCveIds) {
            evidenceChain.push(`CVE(s) ${f.cveIds.join(", ")} associated with ${asset.assetType} product family`);
            evidenceChain.push(`No specific version detected — product-family match only (severity capped at ${severityCap}/10)`);
          } else {
            evidenceChain.push(`Risk inferred by LLM analysis — no specific CVE or version evidence`);
            evidenceChain.push(`Advisory only — severity capped at ${severityCap}/10 pending corroboration`);
          }
          return {
            id: f.id || `pf-${asset.assetId}-${i}`,
            assetRef: asset.assetId,
            assetHostname: asset.hostname,
            category: f.category || "general",
            title: f.title || "Finding",
            severity: cappedSeverity,
            likelihood: clamp(f.likelihood || 3, 0, tier === "potential" ? 5 : 10),
            confidence: clamp(f.confidence || 0.4, 0, 1),
            recommendedControls: f.recommendedControls || [],
            cveIds: f.cveIds || [],
            kevListed: false,
            exploitAvailable: false,
            affectedAssets: [asset.hostname],
            evidenceBasis: hasCveIds ? "technology_match" as const : "llm_inference" as const,
            evidenceDetail: hasCveIds
              ? `Product-family match: CVE(s) ${f.cveIds.join(", ")} affect ${asset.assetType} products. Version not confirmed — finding is PROBABLE, not confirmed.`
              : `Inferred by LLM analysis of ${asset.assetType} asset (${asset.hostname}). No CVE or version evidence — finding is POTENTIAL only.`,
            corroborationTier: tier,
            evidenceChain,
          };
        }),
        testVectors: (analysis.testVectors || []).map((v: any, i: number) => ({
          id: v.id || `tv-${asset.assetId}-${i}`,
          assetRef: asset.hostname,
          vectorType: v.vectorType || "unknown",
          hypothesis: v.hypothesis || "",
          prerequisites: v.prerequisites || ["Authorized environment"],
          suggestedEmulation: v.suggestedEmulation || {},
          expectedTelemetry: v.expectedTelemetry || [],
          riskSignal: { severity: v.riskSignal?.severity || 5, likelihood: v.riskSignal?.likelihood || 5 },
        })),
        confidence: Math.round(ctx.confidence * 100),
        // Separated scores — computed after postureFindings are built
        assetCriticalityScore: computeAssetCriticality(missionImpact).score,
        assetCriticalityBand: computeAssetCriticality(missionImpact).band,
        // vulnRiskScore will be 0 at this stage — recalculated after vuln feed enrichment
        vulnRiskScore: 0,
        vulnRiskBand: "low",
        // Impact × Likelihood decomposition
        impactScore: hybrid.impactScore,
        likelihoodScore: hybrid.likelihoodScore,
        // Mission Function Classification (from LLM)
        missionFunction: analysis.missionFunction || 'public_facing_services',
        essentialService: analysis.essentialService || 'general_server',
        businessImpactLevel: analysis.businessImpactLevel || 'moderate',
        deviceType: analysis.deviceType || 'unknown',
        platformType: analysis.platformType || 'unknown',
        missionJustification: analysis.missionJustification || '',
      };
    });
  } catch (err) {
    console.error("[DomainIntel] Analysis failed:", err);
    return assets.map((asset) => createDefaultAnalysis(asset));
  }
}

// ─── Stage 3: Hybrid Risk Computation ────────────────────────────────

function normalizeCarver(raw: any): CarverScores {
  return {
    criticality: clamp(raw.criticality || 3, 0, 10),
    accessibility: clamp(raw.accessibility || 3, 0, 10),
    recuperability: clamp(raw.recuperability || 3, 0, 10),
    vulnerability: clamp(raw.vulnerability || 3, 0, 10),
    effect: clamp(raw.effect || 3, 0, 10),
    recognizability: clamp(raw.recognizability || 3, 0, 10),
  };
}

function normalizeShock(raw: any): ShockScores {
  return {
    scope: clamp(raw.scope || 3, 0, 10),
    handling: clamp(raw.handling || 3, 0, 10),
    operationalImpact: clamp(raw.operationalImpact || 3, 0, 10),
    cascadingEffects: clamp(raw.cascadingEffects || 3, 0, 10),
    knowledge: clamp(raw.knowledge || 3, 0, 10),
  };
}

function computeMissionImpact(carver: CarverScores, shock: ShockScores): number {
  const carverWeights = { criticality: 2, accessibility: 1.5, recuperability: 1, vulnerability: 1.5, effect: 1.5, recognizability: 0.5 };
  const shockWeights = { scope: 1.5, handling: 1, operationalImpact: 2, cascadingEffects: 1.5, knowledge: 1 };

  let carverSum = 0, carverW = 0;
  for (const [k, w] of Object.entries(carverWeights)) {
    carverSum += (carver as any)[k] * w;
    carverW += w;
  }
  const carverScore = carverSum / carverW;

  let shockSum = 0, shockW = 0;
  for (const [k, w] of Object.entries(shockWeights)) {
    shockSum += (shock as any)[k] * w;
    shockW += w;
  }
  const shockScore = shockSum / shockW;

  return (carverScore + shockScore) / 2;
}

/**
 * Compute hybrid risk using Impact × Likelihood model.
 *
 * IMPACT (0-1): Derived from CARVER/SHOCK mission impact.
 *   - Represents "how bad would it be if this asset were compromised?"
 *   - A critical asset with no vulnerabilities has HIGH impact but LOW risk.
 *
 * LIKELIHOOD (0-1): Driven by CONFIRMED vulnerability evidence.
 *   - If confirmedVulnScore is provided (0-100 from computeVulnRisk), it becomes the primary driver.
 *   - If no confirmed vulns (confirmedVulnScore = 0 or not provided), Likelihood falls to a
 *     baseline from exposure + recognizability only (~5-15%), ensuring unconfirmed assets stay low-risk.
 *   - Exposure and recognizability are minor modifiers (±10%).
 *   - Confidence dampens likelihood: low-confidence assessments reduce likelihood.
 *
 * RISK = sqrt(Impact × Likelihood) × 100
 *   - Geometric mean ensures both dimensions must be elevated for high risk.
 *   - A critical asset with no confirmed vulns (impact=0.9, likelihood=0.1) → score ≈ 30 (low).
 *   - A low-importance asset with confirmed CVEs (impact=0.3, likelihood=0.9) → score ≈ 52 (medium).
 *   - A critical asset with confirmed CVEs (impact=0.9, likelihood=0.9) → score ≈ 90 (critical).
 */
function computeHybridRisk(
  cvss: number,
  missionImpact: number,
  ctx: { exposure: number; recognizability: number; confidence: number },
  confirmedVulnScore?: number, // 0-100 from computeVulnRisk; undefined = use LLM CVSS (initial pass)
  portLikelihoodBoost?: number // 0-0.3 from computePortRisk; boosts likelihood for high-risk exposed ports
): { score: number; band: string; impactScore: number; likelihoodScore: number } {
  // IMPACT: normalized mission impact from CARVER+SHOCK (0-1)
  const impact = clamp(missionImpact / 10, 0, 1);

  // LIKELIHOOD: driven by confirmed vulnerability evidence
  let likelihoodBase: number;

  if (confirmedVulnScore !== undefined) {
    // POST-ENRICHMENT: Use actual confirmed vuln score as the primary Likelihood driver.
    // confirmedVulnScore is 0-100; normalize to 0-1.
    // If 0 (no confirmed vulns), Likelihood falls to baseline from exposure/recognizability only.
    const vulnNorm = clamp(confirmedVulnScore / 100, 0, 1);
    if (vulnNorm === 0) {
      // No confirmed vulns — baseline Likelihood from exposure + recognizability only (very low)
      likelihoodBase = clamp((ctx.exposure * 0.1) + (ctx.recognizability * 0.05), 0, 0.15);
    } else {
      // Confirmed vulns drive Likelihood
      likelihoodBase = vulnNorm;
      // Exposure and recognizability shift likelihood by up to ±10%
      likelihoodBase += (ctx.exposure - 0.5) * 0.2;
      likelihoodBase += (ctx.recognizability - 0.5) * 0.1;
    }
  } else {
    // INITIAL PASS (pre-enrichment): "Innocent until proven guilty" approach.
    // LLM CVSS estimates are unconfirmed — treat as advisory only.
    // Use the same low-baseline formula as no-confirmed-vulns to keep assets GREEN
    // until enrichment provides corroborated evidence.
    // The LLM CVSS is stored for reference but does NOT inflate the displayed score.
    likelihoodBase = clamp((ctx.exposure * 0.1) + (ctx.recognizability * 0.05), 0, 0.15);
  }
  likelihoodBase = clamp(likelihoodBase, 0, 1);

  // Port exposure boost: high-risk exposed ports increase attack surface likelihood
  if (portLikelihoodBoost && portLikelihoodBoost > 0) {
    likelihoodBase = clamp(likelihoodBase + portLikelihoodBoost, 0, 1);
  }

  // Confidence dampening: low-confidence assessments reduce likelihood
  // At confidence 1.0: no dampening. At confidence 0.3: ~47% reduction
  const confidenceDampening = 0.55 + (ctx.confidence * 0.45);
  const likelihood = clamp(likelihoodBase * confidenceDampening, 0, 1);

  // RISK = geometric mean of impact and likelihood, scaled to 0-100
  const score = clamp(Math.round(Math.sqrt(impact * likelihood) * 100), 0, 100);
  const band = riskBand(score);

  return { score, band, impactScore: Math.round(impact * 100), likelihoodScore: Math.round(likelihood * 100) };
}

// ─── Port-Based Risk Scoring ─────────────────────────────────────────

/** High-risk ports that significantly increase attack surface when exposed to the internet */
const HIGH_RISK_PORTS: Record<number, { service: string; severity: number; category: string; rationale: string }> = {
  21:   { service: 'FTP', severity: 8, category: 'remote_access', rationale: 'FTP transmits credentials in cleartext and is frequently targeted by automated scanners' },
  23:   { service: 'Telnet', severity: 9, category: 'remote_access', rationale: 'Telnet transmits all data including credentials in cleartext — critical exposure' },
  25:   { service: 'SMTP', severity: 5, category: 'mail', rationale: 'Open SMTP relay can be abused for spam/phishing if misconfigured' },
  135:  { service: 'MS-RPC', severity: 7, category: 'windows', rationale: 'MS-RPC endpoint mapper is commonly exploited in Windows attacks' },
  139:  { service: 'NetBIOS', severity: 7, category: 'windows', rationale: 'NetBIOS session service exposes Windows file sharing and is frequently targeted' },
  445:  { service: 'SMB', severity: 8, category: 'windows', rationale: 'SMB is the primary vector for ransomware propagation (WannaCry, EternalBlue)' },
  1433: { service: 'MSSQL', severity: 8, category: 'database', rationale: 'Exposed MSSQL server allows direct database attack attempts' },
  1521: { service: 'Oracle DB', severity: 8, category: 'database', rationale: 'Exposed Oracle database listener allows direct database attack attempts' },
  3306: { service: 'MySQL', severity: 8, category: 'database', rationale: 'Exposed MySQL server allows direct database attack and credential brute-force' },
  3389: { service: 'RDP', severity: 9, category: 'remote_access', rationale: 'RDP is the #1 initial access vector for ransomware — BlueKeep, brute-force, credential stuffing' },
  5432: { service: 'PostgreSQL', severity: 7, category: 'database', rationale: 'Exposed PostgreSQL allows direct database attack attempts' },
  5900: { service: 'VNC', severity: 9, category: 'remote_access', rationale: 'VNC often lacks strong authentication and transmits screen data — critical exposure' },
  5901: { service: 'VNC', severity: 9, category: 'remote_access', rationale: 'VNC display :1 — same critical exposure as port 5900' },
  6379: { service: 'Redis', severity: 8, category: 'database', rationale: 'Redis often runs without authentication — allows arbitrary command execution' },
  8080: { service: 'HTTP-Alt', severity: 4, category: 'web', rationale: 'Alternative HTTP port may expose admin panels or development servers' },
  8443: { service: 'HTTPS-Alt', severity: 3, category: 'web', rationale: 'Alternative HTTPS port — lower risk but may expose management interfaces' },
  9200: { service: 'Elasticsearch', severity: 8, category: 'database', rationale: 'Exposed Elasticsearch allows data exfiltration and cluster manipulation' },
  11211: { service: 'Memcached', severity: 7, category: 'database', rationale: 'Exposed Memcached can be used for DDoS amplification and data leakage' },
  27017: { service: 'MongoDB', severity: 8, category: 'database', rationale: 'MongoDB often runs without auth — #1 target for database ransomware' },
};

/** Medium-risk ports that moderately increase attack surface */
const MEDIUM_RISK_PORTS: Record<number, { service: string; severity: number; category: string; rationale: string }> = {
  22:   { service: 'SSH', severity: 3, category: 'remote_access', rationale: 'SSH is generally secure but exposed to brute-force attempts' },
  53:   { service: 'DNS', severity: 4, category: 'infrastructure', rationale: 'Open DNS resolver can be used for DDoS amplification' },
  110:  { service: 'POP3', severity: 5, category: 'mail', rationale: 'POP3 transmits credentials in cleartext' },
  143:  { service: 'IMAP', severity: 5, category: 'mail', rationale: 'IMAP transmits credentials in cleartext' },
  161:  { service: 'SNMP', severity: 6, category: 'management', rationale: 'SNMP v1/v2c uses community strings — information disclosure risk' },
  389:  { service: 'LDAP', severity: 6, category: 'directory', rationale: 'Exposed LDAP can leak directory information and user accounts' },
  636:  { service: 'LDAPS', severity: 4, category: 'directory', rationale: 'LDAPS is encrypted but still exposes directory services' },
  993:  { service: 'IMAPS', severity: 3, category: 'mail', rationale: 'Encrypted IMAP — lower risk but still exposes mail service' },
  995:  { service: 'POP3S', severity: 3, category: 'mail', rationale: 'Encrypted POP3 — lower risk but still exposes mail service' },
  2049: { service: 'NFS', severity: 7, category: 'file_sharing', rationale: 'NFS can expose file systems if misconfigured' },
  5060: { service: 'SIP', severity: 5, category: 'voip', rationale: 'SIP can be exploited for toll fraud and eavesdropping' },
  8888: { service: 'HTTP-Alt', severity: 4, category: 'web', rationale: 'Alternative HTTP port may expose development or admin interfaces' },
};

export interface PortRiskResult {
  /** Overall port exposure score 0-100 */
  portExposureScore: number;
  /** Risk band for port exposure */
  portExposureBand: string;
  /** Number of high-risk ports found */
  highRiskPortCount: number;
  /** Number of medium-risk ports found */
  mediumRiskPortCount: number;
  /** Total open ports found */
  totalOpenPorts: number;
  /** Detailed port findings for posture report */
  portFindings: Array<{
    port: number;
    service: string;
    severity: number;
    category: string;
    rationale: string;
    ip?: string;
    riskLevel: 'high' | 'medium' | 'low';
  }>;
  /** CARVER accessibility boost (0-3 points) */
  accessibilityBoost: number;
  /** Likelihood boost (0-0.3) for computeHybridRisk */
  likelihoodBoost: number;
}

/**
 * Compute port-based risk scoring for an asset by matching its hostname/IP
 * against passive recon observations that contain port data.
 * 
 * High-risk ports (RDP, Telnet, FTP, VNC, SMB, exposed databases) significantly
 * elevate risk because they represent direct attack vectors.
 */
export function computePortRisk(
  asset: DiscoveredAssetRaw,
  passiveObservations: Array<{ name?: string; ip?: string; tags: string[]; evidence: Record<string, any> }>
): PortRiskResult {
  // Collect all open ports for this asset from passive recon data
  const assetPorts = new Map<number, { ip?: string; service?: string; source?: string }>();
  
  const assetHostname = asset.hostname?.toLowerCase() || '';
  const assetIps = new Set<string>();
  
  // Extract IPs from DNS records if available
  if (asset.dnsRecords) {
    for (const [type, records] of Object.entries(asset.dnsRecords)) {
      if (type === 'A' || type === 'AAAA') {
        const arr = Array.isArray(records) ? records : [records];
        for (const r of arr) {
          if (typeof r === 'string') assetIps.add(r);
          else if (r?.address) assetIps.add(r.address);
        }
      }
    }
  }
  
  for (const obs of passiveObservations) {
    // Match observation to asset by hostname or IP
    const obsName = (obs.name || '').toLowerCase();
    const obsIp = obs.ip || '';
    const isMatch = (
      (assetHostname && (obsName.includes(assetHostname) || assetHostname.includes(obsName.split(' ')[0]))) ||
      (obsIp && assetIps.has(obsIp)) ||
      (obsIp && assetHostname.includes(obsIp))
    );
    
    if (!isMatch) continue;
    
    // Extract ports from evidence
    if (obs.evidence?.ports && Array.isArray(obs.evidence.ports)) {
      for (const p of obs.evidence.ports) {
        if (typeof p === 'number' && !assetPorts.has(p)) {
          assetPorts.set(p, { ip: obsIp || undefined });
        }
      }
    }
    if (obs.evidence?.all_ports && Array.isArray(obs.evidence.all_ports)) {
      for (const p of obs.evidence.all_ports) {
        if (typeof p === 'number' && !assetPorts.has(p)) {
          assetPorts.set(p, { ip: obsIp || undefined });
        }
      }
    }
    // Single port from Shodan host detail
    if (obs.evidence?.port && typeof obs.evidence.port === 'number') {
      const p = obs.evidence.port;
      if (!assetPorts.has(p)) {
        assetPorts.set(p, {
          ip: obsIp || undefined,
          service: obs.evidence.product || undefined,
        });
      }
    }
    // Extract ports from tags (port:80, port:443, etc.)
    for (const tag of obs.tags) {
      const portMatch = tag.match(/^port:(\d+)$/);
      if (portMatch) {
        const p = parseInt(portMatch[1], 10);
        if (!assetPorts.has(p)) {
          assetPorts.set(p, { ip: obsIp || undefined });
        }
      }
    }
  }
  
  if (assetPorts.size === 0) {
    return {
      portExposureScore: 0,
      portExposureBand: 'low',
      highRiskPortCount: 0,
      mediumRiskPortCount: 0,
      totalOpenPorts: 0,
      portFindings: [],
      accessibilityBoost: 0,
      likelihoodBoost: 0,
    };
  }
  
  // Classify each port
  const portFindings: PortRiskResult['portFindings'] = [];
  let highRiskCount = 0;
  let mediumRiskCount = 0;
  let maxSeverity = 0;
  let severitySum = 0;
  
  for (const [port, info] of Array.from(assetPorts.entries())) {
    const highRisk = HIGH_RISK_PORTS[port];
    const medRisk = MEDIUM_RISK_PORTS[port];
    
    if (highRisk) {
      highRiskCount++;
      portFindings.push({ port, ...highRisk, ip: info.ip, riskLevel: 'high' });
      maxSeverity = Math.max(maxSeverity, highRisk.severity);
      severitySum += highRisk.severity;
    } else if (medRisk) {
      mediumRiskCount++;
      portFindings.push({ port, ...medRisk, ip: info.ip, riskLevel: 'medium' });
      maxSeverity = Math.max(maxSeverity, medRisk.severity);
      severitySum += medRisk.severity;
    } else {
      // Unknown port — low risk but still counts as exposure
      portFindings.push({
        port,
        service: info.service || `Port ${port}`,
        severity: 2,
        category: 'unknown',
        rationale: `Open port ${port} detected — service unknown`,
        ip: info.ip,
        riskLevel: 'low',
      });
      severitySum += 2;
    }
  }
  
  // Sort findings by severity descending
  portFindings.sort((a, b) => b.severity - a.severity);
  
  // Compute port exposure score (0-100)
  // Weighted: max severity (60%) + average severity (20%) + port count factor (20%)
  const avgSeverity = portFindings.length > 0 ? severitySum / portFindings.length : 0;
  const portCountFactor = Math.min(assetPorts.size / 10, 1) * 10; // 0-10, caps at 10 ports
  const portExposureScore = clamp(
    Math.round((maxSeverity / 10) * 60 + (avgSeverity / 10) * 20 + portCountFactor * 2),
    0, 100
  );
  
  // CARVER accessibility boost: high-risk ports make the asset more accessible to attackers
  // 0 = no boost, up to 3 points for multiple high-risk ports
  const accessibilityBoost = clamp(
    highRiskCount >= 3 ? 3 :
    highRiskCount >= 2 ? 2 :
    highRiskCount >= 1 ? 1.5 :
    mediumRiskCount >= 3 ? 1 :
    mediumRiskCount >= 1 ? 0.5 : 0,
    0, 3
  );
  
  // Likelihood boost: high-risk ports increase attack surface exposure
  // This is added to the exposure component in computeHybridRisk
  // Max 0.3 for critical port exposure (RDP + SMB + DB exposed)
  const likelihoodBoost = clamp(
    highRiskCount >= 3 ? 0.3 :
    highRiskCount >= 2 ? 0.2 :
    highRiskCount >= 1 ? 0.15 :
    mediumRiskCount >= 3 ? 0.1 :
    mediumRiskCount >= 1 ? 0.05 : 0,
    0, 0.3
  );
  
  return {
    portExposureScore,
    portExposureBand: riskBand(portExposureScore),
    highRiskPortCount: highRiskCount,
    mediumRiskPortCount: mediumRiskCount,
    totalOpenPorts: assetPorts.size,
    portFindings,
    accessibilityBoost,
    likelihoodBoost,
  };
}

/**
 * Generate posture findings from high-risk exposed ports.
 * These are "confirmed" findings because port exposure is directly observed
 * from passive reconnaissance data (Shodan, InternetDB, Censys).
 */
export function generatePortPostureFindings(
  asset: DiscoveredAssetRaw,
  portRisk: PortRiskResult
): PostureFinding[] {
  const findings: PostureFinding[] = [];
  
  // Only generate findings for high-risk and significant medium-risk ports
  const significantPorts = portRisk.portFindings.filter(
    f => f.riskLevel === 'high' || (f.riskLevel === 'medium' && f.severity >= 5)
  );
  
  for (const pf of significantPorts) {
    const findingId = `port-${asset.assetId}-${pf.port}`;
    const isHighRisk = pf.riskLevel === 'high';
    
    findings.push({
      id: findingId,
      assetRef: asset.assetId,
      assetHostname: asset.hostname,
      category: 'network_exposure',
      title: `${pf.service} (port ${pf.port}) exposed to internet`,
      severity: pf.severity,
      likelihood: isHighRisk ? 8 : 5,
      confidence: 1.0, // Directly observed from passive recon
      recommendedControls: [
        `Restrict ${pf.service} access via firewall rules or security groups`,
        isHighRisk ? `Move ${pf.service} behind VPN or bastion host` : `Review necessity of ${pf.service} exposure`,
        `Implement network segmentation to isolate ${pf.service}`,
        ...(pf.category === 'database' ? ['Ensure strong authentication is configured', 'Enable encryption in transit'] : []),
        ...(pf.category === 'remote_access' ? ['Enable multi-factor authentication', 'Implement account lockout policies'] : []),
      ],
      cveIds: [],
      kevListed: false,
      exploitAvailable: isHighRisk, // High-risk ports have well-known exploit tooling
      affectedAssets: [asset.hostname],
      evidenceBasis: 'passive_recon' as any,
      evidenceDetail: `Port ${pf.port}/${pf.service} detected open via passive reconnaissance (Shodan/InternetDB/Censys). ${pf.rationale}`,
      corroborationTier: 'confirmed' as CorroborationTier, // Directly observed = confirmed
      evidenceChain: [
        `Passive reconnaissance detected port ${pf.port} (${pf.service}) open on ${asset.hostname}${pf.ip ? ` (${pf.ip})` : ''}`,
        `Service identified as ${pf.service} in category: ${pf.category}`,
        pf.rationale,
        `Finding corroboration: CONFIRMED — directly observed from internet-wide scan data`,
      ],
    });
  }
  
  // If multiple high-risk ports are exposed, add a compound finding
  const highRiskPorts = portRisk.portFindings.filter(f => f.riskLevel === 'high');
  if (highRiskPorts.length >= 2) {
    findings.push({
      id: `port-compound-${asset.assetId}`,
      assetRef: asset.assetId,
      assetHostname: asset.hostname,
      category: 'network_exposure',
      title: `Multiple high-risk services exposed (${highRiskPorts.map(p => p.service).join(', ')})`,
      severity: Math.min(10, Math.max(...highRiskPorts.map(p => p.severity)) + 1),
      likelihood: 9,
      confidence: 1.0,
      recommendedControls: [
        'Conduct immediate network exposure audit',
        'Implement defense-in-depth with network segmentation',
        'Deploy host-based firewall rules on all exposed assets',
        'Move all management services behind VPN',
        'Enable comprehensive logging and monitoring on all exposed ports',
      ],
      cveIds: [],
      kevListed: false,
      exploitAvailable: true,
      affectedAssets: [asset.hostname],
      evidenceBasis: 'passive_recon' as any,
      evidenceDetail: `${highRiskPorts.length} high-risk ports exposed simultaneously: ${highRiskPorts.map(p => `${p.port}/${p.service}`).join(', ')}. Combined exposure dramatically increases attack surface.`,
      corroborationTier: 'confirmed' as CorroborationTier,
      evidenceChain: [
        `${highRiskPorts.length} high-risk services detected exposed on ${asset.hostname}`,
        ...highRiskPorts.map(p => `Port ${p.port} (${p.service}): ${p.rationale}`),
        'Combined exposure creates compound risk — attackers can pivot between services',
        'Finding corroboration: CONFIRMED — all ports directly observed from passive reconnaissance',
      ],
    });
  }
  
  return findings;
}

/** Centralized band thresholds — Critical raised to 90 to prevent over-classification */
function riskBand(score: number): string {
  if (score >= 90) return "critical";  // was 85 — only truly severe findings
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

/** Centralized tier thresholds — aligned with riskBand */
function riskTier(score: number): string {
  if (score >= 90) return "tier0_critical";
  if (score >= 70) return "tier1_high";
  if (score >= 40) return "tier2_medium";
  return "tier3_low";
}

function inferTier(riskScore: number): string {
  return riskTier(riskScore);
}

/**
 * Compute asset criticality score from CARVER+SHOCK only (no vulnerability data).
 * This represents how IMPORTANT the asset is to the mission, not how vulnerable it is.
 */
function computeAssetCriticality(missionImpact: number): { score: number; band: string } {
  // missionImpact is 0-10, normalize to 0-100
  const score = clamp(Math.round(missionImpact * 10), 0, 100);
  return { score, band: riskBand(score) };
}

/**
 * Compute vulnerability risk score from CONFIRMED scan findings only.
 * Only confirmed and probable posture findings contribute. Potential (LLM-inferred) do NOT.
 * An asset with high criticality but no confirmed vulns gets vulnRiskScore = 0.
 */
function computeVulnRisk(findings: PostureFinding[]): { score: number; band: string } {
  // Only count confirmed and probable findings
  const actionable = findings.filter(f => f.corroborationTier === "confirmed" || f.corroborationTier === "probable");
  if (actionable.length === 0) return { score: 0, band: "low" };

  // Weight: confirmed findings count more than probable
  let maxSeverity = 0;
  let weightedSum = 0;
  for (const f of actionable) {
    const weight = f.corroborationTier === "confirmed" ? 1.0 : 0.6;
    const findingScore = (f.severity / 10) * 100 * weight;
    weightedSum += findingScore;
    if (f.severity > maxSeverity) maxSeverity = f.severity;
  }

  // Score: blend of max severity and average weighted severity
  const avgWeighted = weightedSum / actionable.length;
  const maxNorm = (maxSeverity / 10) * 100;
  const score = clamp(Math.round(maxNorm * 0.6 + avgWeighted * 0.4), 0, 100);
  return { score, band: riskBand(score) };
}

function createDefaultAnalysis(asset: DiscoveredAssetRaw): AssetAnalysis {
  const carver = normalizeCarver({});
  const shock = normalizeShock({});
  const mission = computeMissionImpact(carver, shock);
  const hybrid = computeHybridRisk(3, mission, { exposure: 0.3, recognizability: 0.3, confidence: 0.2 });
  const criticality = computeAssetCriticality(mission);
  return {
    asset,
    carverScores: carver,
    shockScores: shock,
    missionImpactScore: Math.round(mission * 10) / 10,
    suggestedTier: inferTier(hybrid.score),
    hybridRiskScore: Math.round(hybrid.score),
    riskBand: hybrid.band,
    cvssEstimate: 3,
    contextIndicators: { exposure: 0.3, recognizability: 0.3, confidence: 0.2 },
    postureFindings: [],
    testVectors: [],
    confidence: 40,
    assetCriticalityScore: criticality.score,
    assetCriticalityBand: criticality.band,
    vulnRiskScore: 0,
    vulnRiskBand: "low",
    impactScore: hybrid.impactScore,
    likelihoodScore: hybrid.likelihoodScore,
    // Mission Function Classification defaults
    missionFunction: 'public_facing_services',
    essentialService: 'general_server',
    businessImpactLevel: 'moderate',
    deviceType: 'unknown',
    platformType: 'unknown',
    missionJustification: '',
  };
}

// ─── Stage 4: Campaign Recommendation Engine ─────────────────────────

export async function generateCampaignRecommendations(
  analyses: AssetAnalysis[],
  org: OrgProfile,
  kevEnrichment?: KevEnrichment
): Promise<CampaignRecommendation[]> {
  // Sort by risk score descending
  const sorted = [...analyses].sort((a, b) => b.hybridRiskScore - a.hybridRiskScore);
  const topAssets = sorted.slice(0, 15);

  const prompt = `You are a red team campaign designer. Based on the following asset analysis and risk scoring, design tailored offensive security campaigns.

Organization: ${org.customerName} (${org.sector}, ${org.clientType})
Critical Functions: ${(org.criticalFunctions || []).join(", ") || "none specified"}
Compliance: ${(org.complianceFlags || []).join(", ") || "none"}

Top Risk Assets (sorted by hybrid risk score):
${JSON.stringify(topAssets.map(a => {
  // Only include confirmed and probable findings for campaign design — exclude potential-only (LLM-inferred without CVE evidence)
  const actionableFindings = a.postureFindings.filter(f => f.corroborationTier === "confirmed" || f.corroborationTier === "probable");
  return {
    id: a.asset.assetId,
    hostname: a.asset.hostname,
    type: a.asset.assetType,
    riskScore: a.hybridRiskScore,
    riskBand: a.riskBand,
    tier: a.suggestedTier,
    classes: a.asset.assetClasses,
    tags: a.asset.tags,
    confirmedFindings: actionableFindings.filter(f => f.corroborationTier === "confirmed").map(f => ({ title: f.title, cves: f.cveIds, severity: f.severity, version: f.detectedVersion })),
    probableFindings: actionableFindings.filter(f => f.corroborationTier === "probable").map(f => ({ title: f.title, cves: f.cveIds, severity: f.severity, note: "version not confirmed" })),
    vectors: a.testVectors.map(v => ({ type: v.vectorType, hypothesis: v.hypothesis })),
  };
}), null, 2)}

IMPORTANT CORROBORATION RULES:
- Only design campaigns targeting CONFIRMED or PROBABLE findings. Do NOT target POTENTIAL-only findings.
- CONFIRMED findings have a detected version that matches a known vulnerable version range — these are highest priority.
- PROBABLE findings have a real CVE but the specific version on the target is unconfirmed — include these but note the version uncertainty.
- Do NOT invent vulnerabilities or assume versions that have not been detected.

Design 4-8 campaigns that:
1. Target the highest-risk assets first
2. Map to specific MITRE ATT&CK techniques
3. Include specific Caldera adversary emulation abilities (reference real ATT&CK technique IDs like T1566.001, T1078, T1021.001, etc.)
4. Include GoPhish phishing template designs tailored to this organization
5. Define complete attack chains with step-by-step phases
6. Consider the client type (${org.clientType}) for realistic scenarios

Campaign types to consider:
- Phishing campaigns targeting discovered email infrastructure
- Credential harvesting via SSO/VPN portals
- Lateral movement chains based on discovered internal assets
- Supply chain attack simulations for ${org.clientType} environments
- Purple team validation of specific posture findings
${kevEnrichment && kevEnrichment.matches.length > 0 ? `
CISA KEV ALERT: The following actively exploited vulnerabilities were found in the target's technology stack:
${kevEnrichment.matches.slice(0, 20).map(m => `- ${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [KNOWN RANSOMWARE]" : ""}`).join("\n")}

You MUST incorporate these KEV vulnerabilities into your campaign designs. Prioritize campaigns that exploit these known-exploited CVEs. Include specific exploitation steps for KEV-listed vulnerabilities in attack chains.
${kevEnrichment.ransomwareExposure ? "WARNING: Some KEV entries are linked to known ransomware campaigns. Design campaigns that simulate ransomware attack paths." : ""}
` : ""}
For each campaign, provide:
{
  "id": "camp-001",
  "name": "Campaign Name",
  "type": "red_team|phishing|purple_team|pentest",
  "priority": "critical|high|medium|low",
  "description": "Detailed campaign description",
  "targetAssets": ["a-001", "a-002"],
  "calderaAbilities": [
    { "name": "Ability name", "tactic": "initial-access", "technique": "T1566.001", "rationale": "Why this ability" }
  ],
  "gophishTemplates": [
    { "name": "Template name", "subject": "Email subject", "theme": "password_reset|invoice|it_support|etc", "targetPersona": "Who receives this", "rationale": "Why this template" }
  ],
  "attackChain": [
    { "step": 1, "phase": "Initial Access", "action": "Send phishing email", "technique": "T1566.001", "tool": "GoPhish" },
    { "step": 2, "phase": "Execution", "action": "Execute payload", "technique": "T1059.001", "tool": "Caldera" }
  ],
  "estimatedRisk": 85,
  "mitreTactics": ["initial-access", "execution", "persistence"]
}

Return JSON: { "campaigns": [...] }`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a red team campaign designer. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const content = response.choices?.[0]?.message?.content;
    const parsed = safeParseLLMJson(content, { campaigns: [] });
    return (parsed.campaigns || []).map((c: any) => ({
      id: c.id || `camp-${Date.now()}`,
      name: c.name || "Unnamed Campaign",
      type: c.type || "red_team",
      priority: c.priority || "medium",
      description: c.description || "",
      targetAssets: c.targetAssets || [],
      calderaAbilities: c.calderaAbilities || [],
      gophishTemplates: c.gophishTemplates || [],
      attackChain: c.attackChain || [],
      estimatedRisk: c.estimatedRisk || 50,
      mitreTactics: c.mitreTactics || [],
    }));
  } catch (err) {
    console.error("[DomainIntel] Campaign recommendation failed:", err);
    return [];
  }
}

// ─── Scan-Only Summary (no campaigns) ───────────────────────────────

export async function generateScanOnlySummary(
  analyses: AssetAnalysis[],
  org: OrgProfile
): Promise<{ executiveSummary: string; threatModelSummary: string }> {
  const criticalAssets = analyses.filter(a => a.riskBand === 'critical' || a.riskBand === 'high');
  const allFindings = analyses.flatMap(a => a.postureFindings);
  const kevFindings = allFindings.filter(f => (f as any).kevListed);

  const prompt = `Generate a scan summary for a domain intelligence reconnaissance:

Organization: ${org.customerName} (${org.sector}, ${org.clientType})
Total Assets Discovered: ${analyses.length}
Critical/High Risk Assets: ${criticalAssets.length}
Total Posture Findings: ${allFindings.length}
KEV-listed Findings: ${kevFindings.length}

Top Risk Assets:
${criticalAssets.slice(0, 5).map(a => `- ${a.asset.hostname} (${a.asset.assetType}): Risk ${a.hybridRiskScore}/100 [${a.riskBand}]`).join('\n')}

Key Findings:
${allFindings.slice(0, 10).map(f => `- ${f.title} (severity: ${f.severity}/10)`).join('\n')}

Provide:
1. "executiveSummary": A 2-3 paragraph reconnaissance summary describing the attack surface discovered, key risk areas, and a recommendation on whether to proceed with a full engagement (campaign design + threat actor profiling). Written for Ace C3 by AceofCloud.
2. "threatModelSummary": A brief technical summary of the attack surface and risk posture. Note that campaign design and threat actor matching have not yet been performed — this is a pre-engagement scan.

Return JSON: { "executiveSummary": "...", "threatModelSummary": "..." }`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: 'system', content: 'You are a cybersecurity report writer. Return only valid JSON.' },
        { role: 'user', content: prompt },
      ],
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'scan_summaries',
          strict: true,
          schema: {
            type: 'object',
            properties: {
              executiveSummary: { type: 'string' },
              threatModelSummary: { type: 'string' },
            },
            required: ['executiveSummary', 'threatModelSummary'],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    return safeParseLLMJson(content, {
      executiveSummary: `Reconnaissance scan of ${org.primaryDomain} identified ${analyses.length} assets with ${criticalAssets.length} classified as critical or high risk. Review the findings below to decide whether to proceed with a full engagement.`,
      threatModelSummary: `Attack surface scan for ${org.customerName} reveals ${analyses.length} discoverable assets across the ${org.primaryDomain} domain. Campaign design and threat actor profiling are available upon engagement start.`,
    });
  } catch (err) {
    console.error('[DomainIntel] Scan-only summary generation failed:', err);
    return {
      executiveSummary: `Reconnaissance scan of ${org.primaryDomain} identified ${analyses.length} assets with ${criticalAssets.length} classified as critical or high risk and ${allFindings.length} posture findings. Review the results to decide whether to proceed with a full engagement.`,
      threatModelSummary: `Attack surface scan for ${org.customerName} reveals ${analyses.length} discoverable assets across the ${org.primaryDomain} domain infrastructure. Campaign design and threat actor profiling have not yet been performed.`,
    };
  }
}

// ─── Stage 5: Executive Summary & Threat Model ───────────────────────

export async function generateSummaries(
  analyses: AssetAnalysis[],
  campaigns: CampaignRecommendation[],
  org: OrgProfile,
  historicalContext?: string
): Promise<{ executiveSummary: string; threatModelSummary: string }> {
  const criticalAssets = analyses.filter(a => a.riskBand === "critical" || a.riskBand === "high");
  const allFindings = analyses.flatMap(a => a.postureFindings);

  const prompt = `Generate two summaries for a security assessment:

Organization: ${org.customerName} (${org.sector}, ${org.clientType})
Total Assets Discovered: ${analyses.length}
Critical/High Risk Assets: ${criticalAssets.length}
Total Posture Findings: ${allFindings.length}
Recommended Campaigns: ${campaigns.length}

Top Risk Assets:
${criticalAssets.slice(0, 5).map(a => `- ${a.asset.hostname} (${a.asset.assetType}): Risk ${a.hybridRiskScore}/100 [${a.riskBand}]`).join("\n")}

Key Findings:
${allFindings.slice(0, 10).map(f => `- ${f.title} (severity: ${f.severity}/10)`).join("\n")}

Campaigns Designed:
${campaigns.map(c => `- ${c.name} [${c.type}] - Priority: ${c.priority}`).join("\n")}${historicalContext ? `\n\n${historicalContext}` : ''}

Provide:
1. "executiveSummary": A 2-3 paragraph executive summary suitable for C-level presentation. Include overall risk posture, key findings, and recommended actions. Written for Ace C3 by AceofCloud.
2. "threatModelSummary": A technical threat model summary covering attack surface analysis, likely threat actors for this sector, and prioritized attack paths.

Return JSON: { "executiveSummary": "...", "threatModelSummary": "..." }`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a cybersecurity report writer. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "summaries",
          strict: true,
          schema: {
            type: "object",
            properties: {
              executiveSummary: { type: "string" },
              threatModelSummary: { type: "string" },
            },
            required: ["executiveSummary", "threatModelSummary"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    return safeParseLLMJson(content, {
      executiveSummary: `Domain intelligence analysis of ${org.primaryDomain} identified ${analyses.length} assets.`,
      threatModelSummary: `Attack surface analysis for ${org.customerName} reveals ${analyses.length} discoverable assets.`,
    });
  } catch (err) {
    console.error("[DomainIntel] Summary generation failed:", err);
    return {
      executiveSummary: `Domain intelligence analysis of ${org.primaryDomain} identified ${analyses.length} assets with ${criticalAssets.length} classified as critical or high risk. ${campaigns.length} tailored campaigns have been recommended.`,
      threatModelSummary: `Attack surface analysis for ${org.customerName} reveals ${analyses.length} discoverable assets across the ${org.primaryDomain} domain infrastructure.`,
    };
  }
}

// ─── Full Pipeline ───────────────────────────────────────────────────

export async function runDomainIntelPipeline(
  org: OrgProfile,
  onProgress?: (stage: 'passive_recon' | 'discovering' | 'analyzing' | 'scoring' | 'recommending') => void | Promise<void>,
  options?: { scanMode?: ScanMode; skipEngagement?: boolean; scopedAssets?: string[]; onConnectorProgress?: (event: { connector: string; status: 'started' | 'completed' | 'failed' | 'skipped'; observations?: number; durationMs?: number; error?: string }) => void | Promise<void> }
): Promise<PipelineResult> {
  // ── Event loop yield helper: prevents blocking the server during long pipelines ──
  const yieldEventLoop = () => new Promise<void>(resolve => setImmediate(resolve));
  // Defensive defaults for optional arrays to prevent undefined access
  org.criticalFunctions = org.criticalFunctions || [];
  org.complianceFlags = org.complianceFlags || [];
  org.additionalDomains = org.additionalDomains || [];
  const scanMode: ScanMode = options?.scanMode || 'standard';
  const isScopedScan = options?.scopedAssets && options.scopedAssets.length > 0;
  // Stage 0: Load FP learning context from analyst feedback
  let fpContext: { totalFPs: number; patterns: { title: string; type: string | null; severity: string | null; reason: string; occurrences: number }[]; categorySummary: { type: string; count: number; fpRate: string }[] } | undefined;
  let fpHashes: Set<string> | undefined;
  try {
    const db = await import('./db');
    fpContext = await db.getFPContextForLLM();
    if (fpContext.totalFPs > 0) {
      const activeFPs = await db.getActiveFPHashes();
      fpHashes = new Set(activeFPs.map(fp => fp.hash));
      console.log(`[DomainIntel] FP Learning: Loaded ${fpContext.totalFPs} false positive patterns across ${fpContext.categorySummary.length} categories`);
    }
  } catch (err: any) {
    console.error(`[DomainIntel] FP context load failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();

  // Stage 0.1: Load Cross-Session Historical Context
  let historicalContext = '';
  try {
    const db = await import('./db');
    const histCtx = await db.getHistoricalScanContext(org.primaryDomain);
    if (histCtx) {
      historicalContext = db.buildHistoricalContextString(histCtx);
      console.log(`[DomainIntel] Historical Context: Loaded scan #${histCtx.scanCount} context from ${histCtx.previousScanDate} (prev risk: ${histCtx.previousRiskScore}, assets: ${histCtx.previousTotalAssets}, findings: ${histCtx.previousTotalFindings})`);
    } else {
      console.log(`[DomainIntel] Historical Context: No previous scans found for ${org.primaryDomain} — this is the first scan`);
    }
  } catch (err: any) {
    console.error(`[DomainIntel] Historical context load failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 0.5: Passive Reconnaissance (run all connectors)
  await onProgress?.('passive_recon');
  let passiveRecon: PassiveReconResult | undefined;
  let passiveContext = '';
  try {
    passiveRecon = await runPassiveRecon(org.primaryDomain, {
      scanMode,
      apiKeys: {
        shodan: ENV.SHODAN_API_KEY || undefined,
        censys_id: ENV.CENSYS_API_ID || undefined,
        censys_secret: ENV.CENSYS_API_SECRET || undefined,
        urlscan: ENV.URLSCAN_API_KEY || undefined,
        securitytrails: ENV.SECURITYTRAILS_API_KEY || undefined,
        dehashed: ENV.DEHASHED_API_KEY || undefined,
        binaryedge: ENV.BINARYEDGE_API_KEY || undefined,
        greynoise: ENV.GREYNOISE_API_KEY || undefined,
        abuseipdb: ENV.ABUSEIPDB_API_KEY || undefined,
        github: ENV.GITHUB_PAT || undefined,
      },
      timeout: 15000,
      maxConcurrent: 5,
      onConnectorProgress: options?.onConnectorProgress,
    });
    console.log(`[DomainIntel] Passive Recon: ${passiveRecon.summary.totalObservations} observations from ${passiveRecon.connectorResults.filter(r => r.observations.length > 0).length} connectors, ${passiveRecon.summary.totalSignals} risk signals detected`);

    // Build context string for LLM discovery stage
    if (passiveRecon.allObservations.length > 0) {
      const subdomains = passiveRecon.allObservations.filter(o => o.assetType === 'subdomain').map(o => o.name);
      const ips = passiveRecon.allObservations.filter(o => o.assetType === 'ip').map(o => `${o.name} (${o.tags.filter(t => t.startsWith('port:') || t.startsWith('service:')).join(', ')})`);
      const urls = passiveRecon.allObservations.filter(o => o.assetType === 'url').map(o => o.name).slice(0, 30);
      const certs = passiveRecon.allObservations.filter(o => o.assetType === 'certificate').map(o => o.name);
      const nsRecords = passiveRecon.allObservations.filter(o => o.assetType === 'ns').map(o => o.name);
      const mxRecords = passiveRecon.allObservations.filter(o => o.assetType === 'mx').map(o => o.name);

      const parts: string[] = ['\n--- PASSIVE RECONNAISSANCE DATA (verified from external sources) ---'];
      if (subdomains.length > 0) parts.push(`Confirmed subdomains (${subdomains.length}): ${subdomains.slice(0, 50).join(', ')}${subdomains.length > 50 ? ` ... and ${subdomains.length - 50} more` : ''}`);
      if (ips.length > 0) parts.push(`Discovered IPs/services (${ips.length}): ${ips.slice(0, 20).join('; ')}`);
      if (urls.length > 0) parts.push(`Historical URLs from Wayback (${urls.length}): ${urls.join(', ')}`);
      if (certs.length > 0) parts.push(`Certificate subjects (${certs.length}): ${certs.slice(0, 20).join(', ')}`);
      if (nsRecords.length > 0) parts.push(`Nameservers: ${nsRecords.join(', ')}`);
      if (mxRecords.length > 0) parts.push(`Mail servers: ${mxRecords.join(', ')}`);

      // Add Shodan-specific service/version/CVE data for LLM context
      const shodanObs = passiveRecon.allObservations.filter(o => o.source === 'shodan' && o.assetType === 'ip');
      if (shodanObs.length > 0) {
        const shodanServices = shodanObs
          .filter(o => o.evidence?.product)
          .map(o => `${o.name || o.ip} — ${o.evidence?.product}${o.evidence?.version ? '/' + o.evidence.version : ''} on port ${o.evidence?.port}/${o.evidence?.transport || 'tcp'}${o.evidence?.vulns?.length > 0 ? ` [CVEs: ${o.evidence.vulns.slice(0, 3).join(', ')}]` : ''}`)
          .slice(0, 20);
        if (shodanServices.length > 0) {
          parts.push(`Shodan service banners (${shodanServices.length}): ${shodanServices.join('; ')}`);
        }
      }

      // Add risk signals
      if (passiveRecon.riskSignals.length > 0) {
        parts.push(`\nRisk signals detected (${passiveRecon.riskSignals.length}):`);
        for (const sig of passiveRecon.riskSignals.slice(0, 15)) {
          parts.push(`  - [${sig.severity.toUpperCase()}] ${sig.rationale.substring(0, 150)}`);
        }
      }
      parts.push('--- END PASSIVE RECON DATA ---\n');
      passiveContext = parts.join('\n');
    }
  } catch (err: any) {
    console.error(`[DomainIntel] Passive recon failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 0.75: Org Domain Discovery (find related domains owned by same org)
  let orgDiscoveryResult: OrgDiscoveryResult | undefined;
  try {
    const orgEmail = passiveRecon?.allObservations?.find(o => o.evidence?.registrant?.organization || o.evidence?.contactEmail)?.evidence?.contactEmail || null;
    orgDiscoveryResult = await discoverOrgDomains(
      org.primaryDomain,
      org.customerName,
      orgEmail || null,
      {
        minConfidenceThreshold: 40,
        maxCandidates: 50,
        enableWebVerification: false,
        enableSpfPivoting: true,
        lookupTimeoutMs: 10000,
      }
    );
    console.log(`[DomainIntel] Org Discovery: ${orgDiscoveryResult.verifiedDomains.length} verified, ${orgDiscoveryResult.unverifiedDomains.length} unverified related domains found`);
  } catch (err: any) {
    console.error(`[DomainIntel] Org domain discovery failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 1: Discover assets (with FP learning context + passive recon data)
  await onProgress?.('discovering');
  // Combine passive recon data with historical context for richer LLM prompts
  const combinedContext = [passiveContext, historicalContext].filter(Boolean).join('\n');
  const rawAssets = await discoverAssets(org, fpContext ? { patterns: fpContext.patterns } : undefined, combinedContext);

  await yieldEventLoop();
  // Stage 1.1: Post-LLM Deduplication & Filtering
  // Fix: LLM sometimes creates multiple assets for the same hostname (e.g., different URL paths)
  // and includes third-party SaaS/infrastructure hostnames that aren't target-owned.
  {
    const beforeCount = rawAssets.length;

    // --- 1. Hostname-based deduplication ---
    // Normalize hostnames and merge assets sharing the same host, keeping the richest metadata.
    const byHostname = new Map<string, typeof rawAssets[0]>();
    const duplicateIds: Set<number> = new Set();
    for (let i = 0; i < rawAssets.length; i++) {
      const a = rawAssets[i];
      // Normalize: extract hostname from URL if hostname field is missing, strip paths/queries
      let hostname = (a.hostname || '').toLowerCase().replace(/\.$/, '');
      if (!hostname && a.url) {
        try {
          hostname = new URL(a.url).hostname.toLowerCase();
        } catch { /* skip */ }
      }
      // Normalize URL to root (strip paths, query strings, fragments)
      if (a.url) {
        try {
          const u = new URL(a.url);
          a.url = `${u.protocol}//${u.hostname}`;
        } catch { /* keep original */ }
      }
      a.hostname = hostname;
      if (!hostname) continue;

      if (byHostname.has(hostname)) {
        // Merge: keep the existing entry but enrich it with data from the duplicate
        const existing = byHostname.get(hostname)!;
        // Merge technologies
        const existingTechs = new Set((existing.technologies || []).map((t: string) => t.toLowerCase()));
        for (const tech of (a.technologies || [])) {
          if (!existingTechs.has(tech.toLowerCase())) {
            (existing.technologies as string[]).push(tech);
          }
        }
        // Merge tags
        const existingTags = new Set((existing.tags || []).map((t: string) => t.toLowerCase()));
        for (const tag of (a.tags || [])) {
          if (!existingTags.has(tag.toLowerCase())) {
            (existing.tags as string[]).push(tag);
          }
        }
        // Merge technologyVersions
        if (a.technologyVersions) {
          existing.technologyVersions = { ...(existing.technologyVersions || {}), ...a.technologyVersions };
        }
        // Prefer more specific assetType over 'other'
        if (existing.assetType === 'other' && a.assetType !== 'other') {
          existing.assetType = a.assetType;
        }
        // Prefer confirmed discovery method over inferred
        if (existing.discoveryMethod === 'inferred' && a.discoveryMethod !== 'inferred') {
          existing.discoveryMethod = a.discoveryMethod;
          existing.discoveryEvidence = a.discoveryEvidence;
        }
        duplicateIds.add(i);
      } else {
        byHostname.set(hostname, a);
      }
    }
    // Remove duplicates (iterate in reverse to preserve indices)
    for (let i = rawAssets.length - 1; i >= 0; i--) {
      if (duplicateIds.has(i)) rawAssets.splice(i, 1);
    }

    // --- 2. Third-party SaaS provider exclusion ---
    const THIRD_PARTY_HOSTNAME_PATTERNS = [
      // Microsoft
      /\.office365\.com$/i, /\.outlook\.com$/i, /\.microsoftonline\.com$/i,
      /\.microsoft\.com$/i, /\.live\.com$/i, /\.sharepoint\.com$/i,
      /\.office\.com$/i, /\.onmicrosoft\.com$/i,
      // Google
      /\.google\.com$/i, /\.googleapis\.com$/i, /\.gstatic\.com$/i,
      /\.gmail\.com$/i, /\.googlemail\.com$/i,
      // Salesforce
      /\.salesforce\.com$/i, /\.force\.com$/i,
      // Cloudflare
      /\.cloudflare\.com$/i, /\.cloudflare-dns\.com$/i,
      // AWS infrastructure (not customer-owned)
      /\.amazonaws\.com$/i, /\.cloudfront\.net$/i,
      // Zendesk, Atlassian, etc.
      /\.zendesk\.com$/i, /\.atlassian\.net$/i, /\.atlassian\.com$/i,
      // DNS providers
      /\.nsone\.net$/i, /\.cloudns\.net$/i, /\.awsdns-\d+/i,
      /\.ultradns\.com$/i, /\.dynect\.net$/i, /\.domaincontrol\.com$/i,
      /\.registrar-servers\.com$/i,
      // CDN/hosting infra
      /\.akamai\.net$/i, /\.akamaiedge\.net$/i, /\.fastly\.net$/i,
      /\.edgekey\.net$/i,
    ];

    const thirdPartyRemoved: string[] = [];
    for (let i = rawAssets.length - 1; i >= 0; i--) {
      const hostname = (rawAssets[i].hostname || '').toLowerCase();
      if (THIRD_PARTY_HOSTNAME_PATTERNS.some(pattern => pattern.test(hostname))) {
        thirdPartyRemoved.push(hostname);
        // Tag the root domain with the SaaS dependency before removing
        const rootAsset = rawAssets.find(a =>
          (a.hostname || '').toLowerCase() === org.primaryDomain.toLowerCase() ||
          (a.assetClasses || []).includes('dns_root')
        );
        if (rootAsset) {
          const depTag = `saas_dep:${hostname}`;
          if (!(rootAsset.tags || []).includes(depTag)) {
            (rootAsset.tags as string[]) = [...(rootAsset.tags || []), depTag];
          }
        }
        rawAssets.splice(i, 1);
      }
    }

    // --- 3. Filter NS/SOA/MX infrastructure records ---
    // These are DNS metadata, not target-owned assets
    const infraRemoved: string[] = [];
    for (let i = rawAssets.length - 1; i >= 0; i--) {
      const a = rawAssets[i];
      const hostname = (a.hostname || '').toLowerCase();
      const assetId = (a.assetId || '').toLowerCase();
      // Detect malformed NS/SOA assets (hostname starts with "ns:" or "soa:")
      const isMalformedDnsRecord = hostname.startsWith('ns:') || hostname.startsWith('soa:') ||
        hostname.startsWith('mx:') || assetId.startsWith('passive-ns:') ||
        assetId.startsWith('passive-soa:') || assetId.startsWith('passive-mx:');
      // Detect DNS nameserver hostnames (e.g., dns1.p02.nsone.net)
      const isDnsNameserver = /^(ns\d*|dns\d*)\./.test(hostname) &&
        THIRD_PARTY_HOSTNAME_PATTERNS.some(p => p.test(hostname));
      if (isMalformedDnsRecord || isDnsNameserver) {
        infraRemoved.push(hostname);
        rawAssets.splice(i, 1);
      }
    }

    const totalRemoved = beforeCount - rawAssets.length;
    if (totalRemoved > 0) {
      console.log(`[DomainIntel] Stage 1.1 Dedup & Filter: Removed ${totalRemoved} assets (${duplicateIds.size} duplicates, ${thirdPartyRemoved.length} third-party SaaS, ${infraRemoved.length} DNS infrastructure). ${rawAssets.length} assets remain.`);
      if (thirdPartyRemoved.length > 0) console.log(`[DomainIntel]   Third-party removed: ${thirdPartyRemoved.join(', ')}`);
      if (infraRemoved.length > 0) console.log(`[DomainIntel]   Infrastructure removed: ${infraRemoved.join(', ')}`);
    }
  }

  await yieldEventLoop();
  // Stage 1.25: Merge passive recon subdomains into rawAssets
  // The LLM discovery stage only generates 15-30 assets. Passive recon may discover
  // many more subdomains (from crt.sh, SecurityTrails, Shodan, Censys, etc.) that the
  // LLM didn't include. Convert these into proper DiscoveredAssetRaw objects so they
  // flow through DNS verification → analysis → storage with full details.
  if (passiveRecon?.allObservations) {
    const existingHostnames = new Set(rawAssets.map(a => (a.hostname || '').toLowerCase()));
    const seenSubdomains = new Set<string>();
    const passiveSubdomainAssets: DiscoveredAssetRaw[] = [];
    // Re-use the same third-party patterns from Stage 1.1
    const THIRD_PARTY_PATTERNS_PASSIVE = [
      /\.office365\.com$/i, /\.outlook\.com$/i, /\.microsoftonline\.com$/i,
      /\.microsoft\.com$/i, /\.live\.com$/i, /\.sharepoint\.com$/i,
      /\.office\.com$/i, /\.onmicrosoft\.com$/i,
      /\.google\.com$/i, /\.googleapis\.com$/i, /\.gstatic\.com$/i,
      /\.gmail\.com$/i, /\.salesforce\.com$/i, /\.force\.com$/i,
      /\.cloudflare\.com$/i, /\.amazonaws\.com$/i, /\.cloudfront\.net$/i,
      /\.zendesk\.com$/i, /\.atlassian\.net$/i, /\.nsone\.net$/i,
      /\.cloudns\.net$/i, /\.ultradns\.com$/i, /\.domaincontrol\.com$/i,
      /\.akamai\.net$/i, /\.fastly\.net$/i,
    ];
    for (const obs of passiveRecon.allObservations) {
      if (obs.assetType !== 'subdomain' || !obs.name) continue;
      const hostname = obs.name.toLowerCase().replace(/\.$/, '');
      if (existingHostnames.has(hostname) || seenSubdomains.has(hostname)) continue;
      // Skip third-party SaaS/infrastructure hostnames
      if (THIRD_PARTY_PATTERNS_PASSIVE.some(p => p.test(hostname))) continue;
      // Skip malformed NS/SOA/MX record hostnames
      if (hostname.startsWith('ns:') || hostname.startsWith('soa:') || hostname.startsWith('mx:')) continue;
      seenSubdomains.add(hostname);
      // Build tags from observation evidence
      const tags: string[] = [...(obs.tags || [])];
      if (obs.source) tags.push(`source:${obs.source}`);
      // Extract technology hints from evidence if available (e.g., Shodan data)
      const technologies: string[] = [];
      const technologyVersions: Record<string, string> = {};
      if (obs.evidence?.product) {
        technologies.push(obs.evidence.product);
        if (obs.evidence.version) technologyVersions[obs.evidence.product] = obs.evidence.version;
      }
      if (obs.evidence?.technologies) {
        for (const t of obs.evidence.technologies) {
          if (typeof t === 'string') technologies.push(t);
          else if (t?.name) {
            technologies.push(t.name);
            if (t.version) technologyVersions[t.name] = t.version;
          }
        }
      }
      passiveSubdomainAssets.push({
        assetId: `passive-${hostname.replace(/\./g, '-')}-${Date.now().toString(36)}`,
        hostname,
        url: `https://${hostname}`,
        assetType: obs.evidence?.port ? 'service' : 'web_application',
        assetClasses: ['subdomain', 'passive_recon'],
        tags,
        technologies,
        technologyVersions,
        description: `Subdomain discovered via passive recon (${obs.source}): ${obs.attribution?.method || hostname}`,
        discoveryMethod: 'cert_transparency' as const,
        discoveryEvidence: `Passive recon source: ${obs.source}. ${obs.attribution?.method || ''} ${obs.attribution?.url ? `Verify: ${obs.attribution.url}` : ''}`.trim(),
      });
    }
    if (passiveSubdomainAssets.length > 0) {
      rawAssets.push(...passiveSubdomainAssets);
      console.log(`[DomainIntel] Merged ${passiveSubdomainAssets.length} passive recon subdomains into asset pipeline (${rawAssets.length} total assets now)`);
    }
  }

  await yieldEventLoop();
  // Stage 1.4: Scoped Scan Filter — restrict to user-specified assets only (RoE mode)
  // This is the critical scope enforcement gate: only assets explicitly listed by the user
  // should survive into the analysis pipeline. Matches on hostname, URL, resolved IPs,
  // and DNS records to handle both domain-based and IP-based scoped entries.
  if (isScopedScan && options?.scopedAssets) {
    const scopedSet = new Set(options.scopedAssets.map(a => a.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '')));
    const beforeCount = rawAssets.length;
    const filtered = rawAssets.filter(a => {
      const hostname = (a.hostname || '').toLowerCase();
      const url = (a.url || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      // Direct hostname or URL match
      if (scopedSet.has(hostname) || scopedSet.has(url)) return true;
      // Check if any resolved IP from DNS records matches a scoped IP
      if (a.dnsRecords) {
        const aRecords: string[] = Array.isArray(a.dnsRecords.A) ? a.dnsRecords.A : [];
        const aaaaRecords: string[] = Array.isArray(a.dnsRecords.AAAA) ? a.dnsRecords.AAAA : [];
        for (const ip of [...aRecords, ...aaaaRecords]) {
          if (scopedSet.has(ip.toLowerCase())) return true;
        }
      }
      return false;
    });
    // If no discovered assets match the scoped list, create stub assets from the scoped list
    if (filtered.length === 0) {
      for (const scopedHost of options.scopedAssets) {
        const clean = scopedHost.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
        filtered.push({
          assetId: `scoped-${clean.replace(/[^a-z0-9]/g, '-')}-${Date.now().toString(36)}`,
          hostname: clean,
          url: `https://${clean}`,
          assetType: 'web_application',
          assetClasses: ['scoped_asset'],
          tags: ['scoped_scan', 'roe_restricted'],
          technologies: [],
          technologyVersions: {},
          description: `Asset specified in scoped scan (RoE restricted)`,
          discoveryMethod: 'manual' as const,
          discoveryEvidence: 'User-specified asset for scoped/RoE-restricted scan',
        });
      }
    }
    rawAssets.length = 0;
    rawAssets.push(...filtered);
    console.log(`[DomainIntel] Scoped Scan: Filtered ${beforeCount} discovered assets down to ${rawAssets.length} matching RoE scope (${options.scopedAssets.join(', ')})`);
  }

  await yieldEventLoop();
  // Stage 1.5: Active DNS & Banner Verification
  let verifiedAssets: typeof rawAssets;
  let unresolvedHypotheses: typeof rawAssets = [];
  try {
    const { verifyAllAssets } = await import("./lib/dns-banner-verify");
    const verification = await verifyAllAssets(rawAssets, 5);
    // Gate: Only keep assets that passed DNS verification or came from passive recon sources.
    // LLM-inferred subdomains that failed DNS resolution are moved to unresolvedHypotheses
    // and excluded from analysis/results to prevent phantom assets from appearing in findings.
    const passiveReconSources = new Set(['shodan', 'censys', 'crtsh', 'securitytrails', 'dehashed', 'urlscan', 'abuseipdb']);
    verifiedAssets = [];
    for (const asset of verification.assets) {
      const isLlmInferred = asset.discoveryMethod === 'inferred';
      const isUnresolved = asset.dnsStatus === 'unresolved';
      const hasPassiveReconEvidence = passiveReconSources.has((asset as any).source || '');
      if (isLlmInferred && isUnresolved && !hasPassiveReconEvidence) {
        // LLM suggested this subdomain but DNS says it doesn't exist — exclude it
        unresolvedHypotheses.push(asset);
      } else {
        verifiedAssets.push(asset);
      }
    }
    const filteredCount = unresolvedHypotheses.length;
    console.log(`[DomainIntel] Verification: ${verification.summary.dnsVerified} DNS verified, ${verification.summary.bannerDetected} banner detected, ${verification.summary.unresolved} unresolved. ${verification.summary.versionsFound} versions found.`);
    if (filteredCount > 0) {
      console.log(`[DomainIntel] DNS Gate: Filtered out ${filteredCount} LLM-inferred subdomains that failed DNS resolution. Only verified assets proceed to analysis.`);
    }
  } catch (err: any) {
    console.error(`[DomainIntel] DNS/banner verification failed (non-fatal): ${err.message}`);
    verifiedAssets = rawAssets;
  }

  await yieldEventLoop();
  // Stage 1.7: Shodan Banner Enrichment — populate technologyVersions from Shodan data
  // This runs BEFORE analysis so that KEV/CVE matching has real version data to work with
  if (passiveRecon) {
    try {
      const shodanObs = passiveRecon.allObservations.filter(o => o.source === 'shodan');
      if (shodanObs.length > 0) {
        const shodanEnrichment = enrichAssetsWithShodanData(verifiedAssets, shodanObs);
        console.log(`[DomainIntel] ${shodanEnrichment.summary}`);
      }
    } catch (err: any) {
      console.error(`[DomainIntel] Shodan enrichment failed (non-fatal): ${err.message}`);
    }
  }

  await yieldEventLoop();
  // Stage 1.8: WAF/NGFW Detection & Scan Tuning Profile
  let wafNgfwAssessment: WafNgfwAssessment | undefined;
  try {
    console.log(`[DomainIntel] Stage 1.8: Running WAF/NGFW detection for ${org.primaryDomain}`);
    const shodanBanners: string[] = [];
    const certOrgs: string[] = [];
    const dnsChain: string[] = [];
    
    // Extract Shodan banners and cert orgs from passive recon
    if (passiveRecon) {
      for (const obs of passiveRecon.allObservations) {
        if (obs.source === 'shodan' && obs.evidence?.banner) {
          shodanBanners.push(String(obs.evidence.banner));
        }
        if (obs.source === 'shodan' && obs.evidence?.ssl?.cert?.subject?.O) {
          certOrgs.push(String(obs.evidence.ssl.cert.subject.O));
        }
        if (obs.source === 'dns' && obs.evidence?.cname) {
          if (Array.isArray(obs.evidence.cname)) dnsChain.push(...obs.evidence.cname.map(String));
          else dnsChain.push(String(obs.evidence.cname));
        }
      }
    }
    
    wafNgfwAssessment = await runWafNgfwAssessment(org.primaryDomain, {
      timeout: 8000,
      shodanBanners,
      certOrgs,
      dnsChain,
    });
    
    const wafNames = wafNgfwAssessment.wafDetections.map(w => `${w.productName} (${w.confidence})`).join(', ');
    const ngfwNames = wafNgfwAssessment.ngfwDetections.map(n => `${n.productName} (${n.confidence})`).join(', ');
    console.log(`[DomainIntel] Stage 1.8 complete — WAF: ${wafNames || 'none detected'}, NGFW: ${ngfwNames || 'none detected'}`);
    console.log(`[DomainIntel]   Scan tuning: ${wafNgfwAssessment.scanTuningProfile.aggressiveness} mode, defensive posture: ${wafNgfwAssessment.defensivePostureScore}/100`);
    
    // Log generated Nmap command for operator reference
    const nmapCmd = buildNmapCommand(wafNgfwAssessment.scanTuningProfile, [org.primaryDomain]);
    console.log(`[DomainIntel]   Suggested Nmap: ${nmapCmd.substring(0, 200)}...`);
    const nucleiCmd = buildNucleiCommand(wafNgfwAssessment.scanTuningProfile, [`https://${org.primaryDomain}`]);
    console.log(`[DomainIntel]   Suggested Nuclei: ${nucleiCmd.substring(0, 200)}...`);
  } catch (err: any) {
    console.error(`[DomainIntel] Stage 1.8 WAF/NGFW detection failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 2 & 3: Analyze assets (classification, BIA, hybrid risk) — with FP calibration
  await onProgress?.('analyzing');
  const analyses = await analyzeAssets(verifiedAssets, org, fpContext ? {
    patterns: fpContext.patterns,
    categorySummary: fpContext.categorySummary.map(c => ({ type: c.type, count: c.count })),
  } : undefined, historicalContext || undefined);

  // ─── Dynamic Re-Scoring Timeline ────────────────────────────────
  // Capture score snapshots before each enrichment phase so we can record
  // exactly how each phase changes asset scores. This feeds the Scoring
  // Timeline UI and the scoring_audit_log table.
  const rescoringTimeline: RescoringTimelineEntry[] = [];

  // Helper: snapshot current scores for all analyses
  function snapshotScores(): Map<string, { score: number; band: string; carver: CarverScores; shock: ShockScores; impact: number; likelihood: number }> {
    const snap = new Map<string, { score: number; band: string; carver: CarverScores; shock: ShockScores; impact: number; likelihood: number }>();
    for (const a of analyses) {
      snap.set(a.asset.assetId, {
        score: a.hybridRiskScore,
        band: a.riskBand,
        carver: { ...a.carverScores },
        shock: { ...a.shockScores },
        impact: a.impactScore,
        likelihood: a.likelihoodScore,
      });
    }
    return snap;
  }

  // Helper: diff snapshots and record timeline entries
  function recordPhaseDeltas(
    phase: string,
    triggerType: string,
    before: Map<string, { score: number; band: string; carver: CarverScores; shock: ShockScores; impact: number; likelihood: number }>,
    description: string
  ): void {
    for (const a of analyses) {
      const prev = before.get(a.asset.assetId);
      if (!prev) continue;
      const delta = a.hybridRiskScore - prev.score;
      // Only record if score actually changed
      if (delta === 0 && a.riskBand === prev.band) continue;
      const factorChanges: RescoringTimelineEntry['factorChanges'] = [];
      // Detect CARVER changes
      for (const k of Object.keys(prev.carver) as (keyof CarverScores)[]) {
        if (a.carverScores[k] !== prev.carver[k]) {
          factorChanges.push({ factor: `CARVER.${k}`, previousValue: prev.carver[k], newValue: a.carverScores[k], reason: description });
        }
      }
      // Detect SHOCK changes
      for (const k of Object.keys(prev.shock) as (keyof ShockScores)[]) {
        if (a.shockScores[k] !== prev.shock[k]) {
          factorChanges.push({ factor: `SHOCK.${k}`, previousValue: prev.shock[k], newValue: a.shockScores[k], reason: description });
        }
      }
      // Detect impact/likelihood changes
      if (a.impactScore !== prev.impact) {
        factorChanges.push({ factor: 'impactScore', previousValue: prev.impact, newValue: a.impactScore, reason: description });
      }
      if (a.likelihoodScore !== prev.likelihood) {
        factorChanges.push({ factor: 'likelihoodScore', previousValue: prev.likelihood, newValue: a.likelihoodScore, reason: description });
      }
      rescoringTimeline.push({
        assetId: a.asset.assetId,
        hostname: a.asset.hostname,
        phase,
        triggerType,
        previousScore: prev.score,
        newScore: a.hybridRiskScore,
        delta,
        previousBand: prev.band,
        newBand: a.riskBand,
        changeDescription: `${description}: ${a.asset.hostname} ${delta > 0 ? '+' : ''}${delta} (${prev.band} → ${a.riskBand})`,
        factorChanges,
        timestamp: Date.now(),
      });
    }
  }

  // Record initial_scan baseline (the LLM-generated scores before any enrichment)
  for (const a of analyses) {
    rescoringTimeline.push({
      assetId: a.asset.assetId,
      hostname: a.asset.hostname,
      phase: 'initial_scan',
      triggerType: 'initial_scan',
      previousScore: 0,
      newScore: a.hybridRiskScore,
      delta: a.hybridRiskScore,
      previousBand: 'low',
      newBand: a.riskBand,
      changeDescription: `Initial BIA assessment: ${a.asset.hostname} scored ${a.hybridRiskScore} (${a.riskBand})`,
      factorChanges: [],
      timestamp: Date.now(),
    });
  }

  await yieldEventLoop();
  // Stage 3.5: CISA KEV Enrichment
  const preKevSnapshot = snapshotScores();
  await onProgress?.('scoring');
  let kevEnrichment: KevEnrichment | undefined;
  try {
    const allTechnologies = analyses.flatMap(a => a.asset.technologies || []);
    const uniqueTechs = Array.from(new Set(allTechnologies.filter(Boolean)));
    if (uniqueTechs.length > 0) {
      const kevCatalog = await fetchKevCatalog();
      const kevMatches = matchTechnologiesAgainstKev(uniqueTechs, kevCatalog);
      if (kevMatches.length > 0) {
        const boost = calculateKevRiskBoost(kevMatches);
        const chainSteps = getKevChainSteps(kevMatches);
        kevEnrichment = {
          matches: kevMatches,
          riskBoost: boost.riskBoost,
          ransomwareExposure: boost.ransomwareExposure,
          criticalKevCount: boost.criticalKevCount,
          summary: boost.summary,
          chainSteps,
        };
        // KEV findings are added to postureFindings below. The hybridRiskScore boost is
        // ONLY applied for version-confirmed KEV matches. Without version confirmation,
        // the KEV finding is "probable" and contributes to vulnRiskScore (which drives
        // Likelihood in the post-enrichment recalculation) but does NOT get an extra boost.
        //
        // FIX: Per-asset KEV matching. We run matchTechnologiesAgainstKev per-asset
        // using only THAT asset's technologies, so findings are never cross-contaminated.
        // We also build a per-asset seen set to avoid duplicate CVEs on the same asset.
        let kevIdx = 0;
        for (const a of analyses) {
          kevIdx++;
          if (kevIdx % 10 === 0) await yieldEventLoop();
          const assetTechs = (a.asset.technologies || []).filter(Boolean);
          if (assetTechs.length === 0) continue;
          // Run KEV matching using ONLY this asset's own technologies
          const assetKevMatches = matchTechnologiesAgainstKev(assetTechs, kevCatalog);
          // Deduplicate: skip CVEs already present as posture findings on this asset
          const existingCves = new Set(a.postureFindings.flatMap(f => f.cveIds || []));
          const uniqueAssetKevMatches = assetKevMatches.filter(m => !existingCves.has(m.cveID));
          if (assetKevMatches.length > 0) {
            // Only boost for version-confirmed KEV matches
            const versions = a.asset.technologyVersions || {};
            // FIX: Require the KEV product name to match the detected technology name,
            // not just the matchedOn field (which could be a generic vendor name like "Microsoft").
            // This prevents "Microsoft IIS v10.0" from confirming a SharePoint KEV entry.
            const confirmedKevMatches = assetKevMatches.filter(m => {
              const kevProductLower = (m.product || '').toLowerCase();
              return Object.entries(versions).some(([tech]) => {
                const techLower = tech.toLowerCase();
                // Check if the detected technology name matches the KEV product name
                // (not just the matchedOn field which could be a broad pattern like "iis")
                return techLower.includes(kevProductLower) || kevProductLower.includes(techLower);
              });
            });
            if (confirmedKevMatches.length > 0) {
              // Cap per-asset KEV boost at 15 — only for version-confirmed matches
              const assetBoost = Math.min(confirmedKevMatches.reduce((s, m) => s + Math.min(m.severityBoost, 8), 0), 15);
              a.hybridRiskScore = Math.min(100, a.hybridRiskScore + assetBoost);
              a.riskBand = riskBand(a.hybridRiskScore);
              a.suggestedTier = riskTier(a.hybridRiskScore);
            }
            // Add KEV posture findings with full evidence and corroboration
            // Use uniqueAssetKevMatches to skip CVEs already present on this asset
            uniqueAssetKevMatches.forEach(m => {
              // Check if we have a detected version for this technology
              // FIX: Match against the KEV PRODUCT name, not the matchedOn pattern.
              // Previously, matchedOn="Microsoft" would match "Microsoft IIS" version,
              // falsely confirming a SharePoint or Windows CLFS KEV entry.
              const versions = a.asset.technologyVersions || {};
              const kevProductLower = (m.product || '').toLowerCase();
              const detectedVersion = Object.entries(versions).find(
                ([tech]) => {
                  const techLower = tech.toLowerCase();
                  return techLower.includes(kevProductLower) || kevProductLower.includes(techLower);
                }
              )?.[1] || undefined;
              // KEV entries are product-family matches unless we have a version
              // KEV is always at least "probable" because it's a confirmed CVE on a confirmed product family
              const tier: CorroborationTier = detectedVersion ? "confirmed" : "probable";
              const severityCap = tier === "confirmed" ? 10 : 6;
              const rawSeverity = m.knownRansomware ? 10 : 9;
              const cappedSeverity = Math.min(rawSeverity, severityCap);
              const evidenceChain: string[] = [
                `Technology "${m.matchedOn}" detected on asset "${a.asset.hostname}"`,
                `Matched against CISA KEV entry ${m.cveID} (${m.vendorProject} ${m.product})`,
              ];
              if (detectedVersion) {
                evidenceChain.push(`Detected version: ${detectedVersion} — version-specific match CONFIRMED`);
              } else {
                evidenceChain.push(`No specific version detected — product-family match only (severity capped at ${severityCap}/10)`);
              }
              evidenceChain.push(`KEV status: actively exploited in the wild. Due date: ${m.dueDate}`);
              if (m.knownRansomware) evidenceChain.push(`Ransomware association confirmed`);

              a.postureFindings.push({
                id: `kev-${m.cveID}-${a.asset.assetId}`,
                assetRef: a.asset.assetId,
                assetHostname: a.asset.hostname,
                category: "CISA KEV",
                title: `${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [RANSOMWARE]" : ""}`,
                severity: cappedSeverity,
                likelihood: detectedVersion ? 9 : 6, // Lower likelihood without version confirmation
                confidence: detectedVersion ? 0.95 : 0.7,
                recommendedControls: [m.requiredAction, `Patch ${m.product} immediately`, "Monitor for exploitation indicators"],
                cveIds: [m.cveID],
                kevListed: true,
                exploitAvailable: true,
                cvssScore: m.knownRansomware ? 9.8 : 9.0,
                affectedAssets: [a.asset.hostname],
                evidenceBasis: "kev_match" as const,
                evidenceDetail: detectedVersion
                  ? `CONFIRMED: Technology "${m.matchedOn}" v${detectedVersion} on ${a.asset.hostname} matches CISA KEV entry ${m.cveID}. Due date: ${m.dueDate}.`
                  : `PROBABLE: Technology "${m.matchedOn}" on ${a.asset.hostname} matches CISA KEV product family ${m.vendorProject} ${m.product}. Version not confirmed — severity capped. Due date: ${m.dueDate}.`,
                corroborationTier: tier,
                detectedVersion,
                versionMatchConfirmed: !!detectedVersion,
                evidenceChain,
              });
            });
          }
        }
        console.log(`[DomainIntel] KEV enrichment: ${kevMatches.length} matches, ${chainSteps.length} chain steps, boost=${boost.riskBoost}`);
      }
    }
    // Record KEV enrichment deltas
    recordPhaseDeltas('kev_enrichment', 'kev_match', preKevSnapshot, 'CISA KEV catalog match');
  } catch (err: any) {
    console.error(`[DomainIntel] KEV enrichment failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 3.6: Vuln Feed Enrichment — add real CVE IDs from all feeds
  // FIX: Per-asset vuln feed matching. We run matchTechnologiesAgainstAllFeeds per-asset
  // using only THAT asset's technologies, so findings are never cross-contaminated.
  // Previously, a global tech pool caused the same CVEs to appear on every asset.
  try {
    const { matchTechnologiesAgainstAllFeeds } = await import("./lib/vuln-feeds");
    // Cache vuln feed results per technology to avoid redundant API calls
    const vulnFeedCache = new Map<string, Awaited<ReturnType<typeof matchTechnologiesAgainstAllFeeds>>>();
    let totalVulnsFound = 0;
    let totalTechsMatched = 0;

    // Enrich each asset's posture findings with real CVE data — PER ASSET
    let vfIdx = 0;
    for (const a of analyses) {
      vfIdx++;
      if (vfIdx % 10 === 0) await yieldEventLoop();
      const assetTechs = (a.asset.technologies || []).filter(Boolean);
      if (assetTechs.length === 0) continue;

      // Get unique techs for this asset only
      const uniqueAssetTechs = Array.from(new Set(assetTechs));
      // Include version info in cache key since version-aware filtering produces different results
      const versionSuffix = Object.entries(a.asset.technologyVersions || {}).sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => `${k}=${v}`).join('&');
      const cacheKey = uniqueAssetTechs.sort().join('|').toLowerCase() + (versionSuffix ? `#${versionSuffix}` : '');

      // Check cache first — if another asset has the exact same tech set, reuse results
      let vulnResult = vulnFeedCache.get(cacheKey);
      if (!vulnResult) {
        vulnResult = await matchTechnologiesAgainstAllFeeds(uniqueAssetTechs, a.asset.technologyVersions || {});
        vulnFeedCache.set(cacheKey, vulnResult);
      }

      // Build a tech->vuln map for THIS asset's results
      const techVulnMap = new Map<string, typeof vulnResult.matches[0]>();
      for (const match of vulnResult.matches) {
        techVulnMap.set(match.technology.toLowerCase(), match);
      }

      const assetTechsLower = assetTechs.map(t => t.toLowerCase());
      for (const techLower of assetTechsLower) {
        const vulnMatch = techVulnMap.get(techLower);
        if (!vulnMatch) continue;

        // Add vuln-feed-backed findings for the top CVEs
        const topVulns = vulnMatch.vulns.slice(0, 5); // Top 5 by CVSS
        for (const vuln of topVulns) {
          // Skip if we already have a KEV finding for this CVE
          if (a.postureFindings.some(f => f.cveIds?.includes(vuln.cveId))) continue;

          // Determine corroboration tier based on version evidence
          const versions = a.asset.technologyVersions || {};
          const detectedVersion = Object.entries(versions).find(
            ([tech]) => tech.toLowerCase().includes(techLower) || techLower.includes(tech.toLowerCase())
          )?.[1] || undefined;

          // VERSION-AWARE FILTERING: If we have a detected version AND the CVE has
          // version range data, verify the detected version is actually affected.
          // This prevents listing all CVEs for a product when only specific versions are vulnerable.
          if (detectedVersion && vuln.affectedVersionRange) {
            const { isVersionAffected } = await import("./lib/dynamic-cpe-matcher");
            if (!isVersionAffected(detectedVersion, vuln.affectedVersionRange)) {
              continue; // Detected version is NOT in the affected range — skip this CVE
            }
          }

          // With version: confirmed. Without: probable (we have a real CVE, just no version confirmation)
          const tier: CorroborationTier = detectedVersion ? "confirmed" : "probable";
          const severityCap = tier === "confirmed" ? 10 : 6;
          const rawSeverity = vuln.cvssScore ? Math.round(vuln.cvssScore) : 5;
          const cappedSeverity = Math.min(rawSeverity, severityCap);
          const evidenceChain: string[] = [
            `Technology "${vulnMatch.technology}" detected on asset "${a.asset.hostname}"`,
            `${vuln.cveId} affects ${vuln.vendor} ${vuln.product} (CVSS: ${vuln.cvssScore || "N/A"})`,
            `Sources: ${vuln.sources.join(", ")}`,
          ];
          if (detectedVersion) {
            if (vuln.affectedVersionRange) {
              evidenceChain.push(`Detected version: ${detectedVersion} — CONFIRMED within affected range (${vuln.affectedVersionRange})`);
            } else {
              evidenceChain.push(`Detected version: ${detectedVersion} — version-specific match CONFIRMED (no version range data to verify against)`);
            }
          } else {
            evidenceChain.push(`No specific version detected — product-family match only (severity capped at ${severityCap}/10)`);
          }
          if (vuln.kevListed) evidenceChain.push(`Listed on CISA KEV — actively exploited in the wild`);
          if (vuln.exploitAvailable) evidenceChain.push(`Public exploit available`);
          if (vuln.inTheWild) evidenceChain.push(`Confirmed 0-day exploitation in the wild`);

          a.postureFindings.push({
            id: `vf-${vuln.cveId}-${a.asset.assetId}`,
            assetRef: a.asset.assetId,
            assetHostname: a.asset.hostname,
            category: vuln.kevListed ? "CISA KEV" : vuln.inTheWild ? "0-Day" : vuln.exploitAvailable ? "Exploitable CVE" : "Known CVE",
            title: `${vuln.cveId}: ${vuln.title || vuln.description?.substring(0, 100) || "Vulnerability"} (${vuln.vendor} ${vuln.product})`,
            severity: cappedSeverity,
            likelihood: detectedVersion
              ? (vuln.kevListed ? 9 : vuln.inTheWild ? 8 : vuln.exploitAvailable ? 7 : 5)
              : Math.min(vuln.kevListed ? 6 : vuln.inTheWild ? 5 : vuln.exploitAvailable ? 4 : 3, 6),
            confidence: detectedVersion ? (vuln.cvssScore ? 0.9 : 0.75) : (vuln.cvssScore ? 0.6 : 0.4),
            recommendedControls: [
              vuln.patchAvailable ? `Apply patch for ${vuln.cveId}` : `Mitigate ${vuln.cveId} — no patch available`,
              `Monitor for exploitation of ${vuln.cveId}`,
              ...(!detectedVersion ? [`Verify ${vuln.vendor} ${vuln.product} version on ${a.asset.hostname} to confirm vulnerability`] : []),
            ],
            cveIds: [vuln.cveId],
            kevListed: vuln.kevListed,
            exploitAvailable: vuln.exploitAvailable,
            cvssScore: vuln.cvssScore || undefined,
            affectedAssets: [a.asset.hostname],
            evidenceBasis: vuln.kevListed ? "kev_match" as const : vuln.exploitAvailable ? "confirmed_cve" as const : "vuln_feed" as const,
            evidenceDetail: detectedVersion
              ? `CONFIRMED: ${vuln.cveId} affects ${vuln.vendor} ${vuln.product}${vuln.affectedVersionRange ? ` (affected: ${vuln.affectedVersionRange})` : ''}. Detected version ${detectedVersion} on ${a.asset.hostname}. CVSS: ${vuln.cvssScore || "N/A"}. Sources: ${vuln.sources.join(", ")}.`
              : `PROBABLE: ${vuln.cveId} affects ${vuln.vendor} ${vuln.product} product family. Technology "${vulnMatch.technology}" detected on ${a.asset.hostname} but version not confirmed. Severity capped at ${severityCap}/10. CVSS: ${vuln.cvssScore || "N/A"}. Sources: ${vuln.sources.join(", ")}.`,
            corroborationTier: tier,
            detectedVersion,
            versionMatchConfirmed: !!detectedVersion,
            evidenceChain,
          });
        }
      }
      totalVulnsFound += vulnResult.totalVulns;
      totalTechsMatched += vulnResult.matches.length;
    }
    console.log(`[DomainIntel] Vuln feed enrichment: ${totalVulnsFound} vulns across ${totalTechsMatched} technologies (per-asset matching)`);
  } catch (err: any) {
    console.error(`[DomainIntel] Vuln feed enrichment failed (non-fatal): ${err.message}`);
  }
  // Note: vuln feed findings don't change hybridRiskScore directly — they add postureFindings
  // that are picked up in the post-enrichment recalculation below.

  await yieldEventLoop();
  // Stage 3.7: Shodan CVE Verification — upgrade probable findings to confirmed using Shodan banner data
  if (passiveRecon) {
    try {
      const shodanObs = passiveRecon.allObservations.filter(o => o.source === 'shodan');
      if (shodanObs.length > 0) {
        // First: add Shodan-detected CVEs as new confirmed posture findings
        const shodanFindings = createShodanPostureFindings(analyses, shodanObs);
        if (shodanFindings.findingsAdded > 0) {
          console.log(`[DomainIntel] ${shodanFindings.summary}`);
        }

        // Second: verify existing KEV/vuln feed findings against Shodan data
        const shodanVerification = verifyCvesWithShodanData(analyses, shodanObs);
        if (shodanVerification.upgraded > 0) {
          console.log(`[DomainIntel] ${shodanVerification.summary}`);
        }
      }
    } catch (err: any) {
      console.error(`[DomainIntel] Shodan CVE verification failed (non-fatal): ${err.message}`);
    }
  }

  await yieldEventLoop();
  // Stage 3.8: Exploit Matching — match confirmed CVEs against Metasploit/ExploitDB
  let exploitMatchResult: PipelineResult['exploitMatches'] | undefined;
  try {
    // Collect all confirmed/probable posture findings with CVE IDs
    const allFindings = analyses.flatMap(a => a.postureFindings.map(f => ({
      title: f.title,
      cveIds: f.cveIds,
      corroborationTier: f.corroborationTier,
      severity: f.severity,
      description: f.evidenceDetail,
    })));
    const findingsWithCves = allFindings.filter(f => f.cveIds && f.cveIds.length > 0);
    if (findingsWithCves.length > 0) {
      exploitMatchResult = await matchExploitsToFindings(findingsWithCves);
      console.log(`[DomainIntel] Exploit matching: ${exploitMatchResult.matches.length} CVEs matched → ${exploitMatchResult.totalMetasploit} MSF modules, ${exploitMatchResult.totalExploitDb} EDB entries, ${exploitMatchResult.totalCalderaAbilities} Caldera abilities, ${exploitMatchResult.remoteAccessCount} remote access`);
    }
  } catch (err: any) {
    console.error(`[DomainIntel] Exploit matching failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 3.81: Cross-link exploit matches back to KEV posture findings
  // The exploit matcher finds Metasploit/ExploitDB/Caldera matches for CVEs, but stores
  // them in a separate exploitMatches object. This stage annotates each KEV posture finding
  // with its matched exploits so the UI can show exploit details directly on KEV findings
  // and validation testing can use the linked exploits for PoC verification.
  if (exploitMatchResult && exploitMatchResult.matches.length > 0) {
    // Build a CVE → exploit match lookup
    const cveToExploit = new Map<string, typeof exploitMatchResult.matches[0]>();
    for (const match of exploitMatchResult.matches) {
      cveToExploit.set(match.cveId, match);
    }
    let linkedCount = 0;
    let linkIdx = 0;
    for (const a of analyses) {
      linkIdx++;
      if (linkIdx % 10 === 0) await yieldEventLoop();
      for (const finding of a.postureFindings) {
        if (!finding.cveIds || finding.cveIds.length === 0) continue;
        const matchedExploits: Array<{
          cveId: string;
          metasploitCount: number;
          exploitDbCount: number;
          bestExploit: any;
          calderaAbility: any;
          isRemoteAccess: boolean;
        }> = [];
        for (const cveId of finding.cveIds) {
          const exploit = cveToExploit.get(cveId);
          if (exploit) {
            matchedExploits.push({
              cveId: exploit.cveId,
              metasploitCount: exploit.metasploitModules.length,
              exploitDbCount: exploit.exploitDbEntries.length,
              bestExploit: exploit.bestExploit,
              calderaAbility: exploit.calderaAbility,
              isRemoteAccess: exploit.isRemoteAccess,
            });
          }
        }
        if (matchedExploits.length > 0) {
          // Annotate the finding with linked exploits for validation testing
          (finding as any).linkedExploits = matchedExploits;
          (finding as any).exploitCount = matchedExploits.reduce(
            (sum, e) => sum + e.metasploitCount + e.exploitDbCount, 0
          );
          (finding as any).hasRemoteExploit = matchedExploits.some(e => e.isRemoteAccess);
          (finding as any).hasCalderaAbility = matchedExploits.some(e => e.calderaAbility != null);
          // If this is a KEV finding, upgrade evidence to include exploit availability
          if (finding.kevListed) {
            finding.evidenceChain = [
              ...(finding.evidenceChain || []),
              `Exploit validation: ${matchedExploits.reduce((s, e) => s + e.metasploitCount, 0)} Metasploit modules, ${matchedExploits.reduce((s, e) => s + e.exploitDbCount, 0)} ExploitDB entries available`,
              matchedExploits.some(e => e.isRemoteAccess) ? 'Remote access exploit available — HIGH PRIORITY for validation testing' : 'Local/DoS exploits only',
              matchedExploits.some(e => e.calderaAbility) ? 'Caldera ability auto-generated for automated validation' : '',
            ].filter(Boolean);
          }
          linkedCount++;
        }
      }
    }
    if (linkedCount > 0) {
      console.log(`[DomainIntel] Cross-linked exploits to ${linkedCount} posture findings (${exploitMatchResult.matches.length} CVEs with exploits)`);
    }
  }

  await yieldEventLoop();
  // Stage 3.85: Port-Based Risk Scoring — analyze exposed ports and generate findings
  const prePortSnapshot = snapshotScores();
  let portRiskStats = { totalAssetsWithPorts: 0, totalHighRiskPorts: 0, totalPortFindings: 0 };
  if (passiveRecon) {
    try {
      const allObs = passiveRecon.allObservations;
      let portIdx = 0;
      for (const a of analyses) {
        portIdx++;
        if (portIdx % 10 === 0) await yieldEventLoop();
        const portRisk = computePortRisk(a.asset, allObs);
        if (portRisk.totalOpenPorts > 0) {
          portRiskStats.totalAssetsWithPorts++;
          portRiskStats.totalHighRiskPorts += portRisk.highRiskPortCount;
          
          // Boost CARVER accessibility score based on exposed ports
          if (portRisk.accessibilityBoost > 0) {
            a.carverScores = {
              ...a.carverScores,
              accessibility: clamp(a.carverScores.accessibility + portRisk.accessibilityBoost, 0, 10),
            };
          }
          
          // Generate confirmed posture findings for high-risk ports
          const portFindings = generatePortPostureFindings(a.asset, portRisk);
          if (portFindings.length > 0) {
            a.postureFindings.push(...portFindings);
            portRiskStats.totalPortFindings += portFindings.length;
          }
          
          // Store port risk data on the analysis for use in hybrid risk recalculation
          (a as any)._portLikelihoodBoost = portRisk.likelihoodBoost;
          (a as any)._portExposureScore = portRisk.portExposureScore;
        }
      }
      console.log(`[DomainIntel] Port risk scoring: ${portRiskStats.totalAssetsWithPorts} assets with open ports, ${portRiskStats.totalHighRiskPorts} high-risk ports, ${portRiskStats.totalPortFindings} port findings generated`);
      // Record port risk deltas (CARVER accessibility boosts)
      recordPhaseDeltas('port_risk', 'new_port_service', prePortSnapshot, 'Port-based risk scoring');
    } catch (err: any) {
      console.error(`[DomainIntel] Port risk scoring failed (non-fatal): ${err.message}`);
    }
  }

  await yieldEventLoop();
  // Stage 3.9: Email Security Analysis — check SPF/DKIM/DMARC for phishing weaknesses
  let emailSecurityReport: any = undefined;
  let hasMx = false;
  try {
    const { analyzeEmailSecurity, generateEmailPostureFindings } = await import('./lib/email-security-analyzer');
    emailSecurityReport = await analyzeEmailSecurity(org.primaryDomain);
    hasMx = emailSecurityReport.mx?.records?.length > 0;
    console.log(`[DomainIntel] Email security: grade=${emailSecurityReport.overallGrade}, score=${emailSecurityReport.overallScore}, weaknesses=${emailSecurityReport.totalWeaknesses}, phishing=${emailSecurityReport.phishingDifficultyRating}, hasMX=${hasMx}`);
    if (!hasMx) {
      console.log(`[DomainIntel] No MX records for ${org.primaryDomain} — SPF/DKIM findings suppressed (not a mail server)`);
    }

    // Generate posture findings from email security weaknesses
    const emailFindings = generateEmailPostureFindings(org.primaryDomain, emailSecurityReport);
    if (emailFindings.length > 0) {
      // Only assign email security findings to mail-related assets.
      // Non-mail assets (web servers, APIs, CDNs, VPNs, admin panels, etc.)
      // should NEVER receive DMARC/SPF/DKIM findings.
      const { isMailAsset } = await import('./lib/email-security-analyzer');
      const mailAsset = analyses.find(a => isMailAsset({
        hostname: a.asset.hostname,
        assetType: a.asset.assetType,
        essentialService: a.essentialService,
        missionFunction: a.missionFunction,
        tags: a.asset.tags,
      }));

      // Fallback: only use the root domain asset (hostname === primaryDomain) if it exists
      // AND the domain actually has MX records (i.e., operates mail infrastructure).
      // If there are no MX records, the in-scope assets are not mail infra and email
      // findings should NOT be assigned to any asset — they are false positives.
      const rootDomainAsset = (!mailAsset && hasMx) ? analyses.find(a =>
        a.asset.hostname === org.primaryDomain &&
        (a.asset.assetType === 'other' || a.asset.assetClasses?.includes('dns_root'))
      ) : null;

      const targetAsset = mailAsset || rootDomainAsset;
      if (targetAsset) {
        for (const ef of emailFindings) {
          targetAsset.postureFindings.push({
            id: ef.id,
            assetRef: ef.assetRef,
            assetHostname: org.primaryDomain,
            category: ef.category,
            title: ef.title,
            severity: ef.severity,
            confidence: ef.confidence,
            evidenceDetail: ef.evidenceDetail,
            corroborationTier: ef.corroborationTier,
            evidenceChain: [`DNS lookup verified: ${ef.evidenceDetail}`, `Phishing relevance: ${ef.phishingRelevance}`],
            remediation: ef.remediation,
          } as any);
        }
        console.log(`[DomainIntel] Added ${emailFindings.length} email security findings to mail asset ${targetAsset.asset.hostname}`);
      } else {
        console.log(`[DomainIntel] Suppressed ${emailFindings.length} email security findings — no mail-related asset found to assign them to`);
      }
    }
  } catch (err: any) {
    console.error(`[DomainIntel] Email security analysis failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 3.10: Strip email security findings from ALL non-mail assets.
  // Only assets positively identified as mail infrastructure should retain
  // DMARC/SPF/DKIM/email security findings. Web servers, APIs, SSO portals,
  // CDN edges, VPNs, admin panels, cloud compute, and all other non-mail
  // assets should NEVER be flagged for missing email authentication.
  try {
    const { isMailAsset } = await import('./lib/email-security-analyzer');
    let emailIdx = 0;
    for (const a of analyses) {
      emailIdx++;
      if (emailIdx % 10 === 0) await yieldEventLoop();
      const hostname = a.asset.hostname || '';
      // Check if this asset is a mail asset — if NOT, strip all email findings
      const assetIsMailRelated = isMailAsset({
        hostname: a.asset.hostname,
        assetType: a.asset.assetType,
        essentialService: a.essentialService,
        missionFunction: a.missionFunction,
        tags: a.asset.tags,
      });

      // Only allow root domain assets (dns_root) to keep email findings if the
      // domain actually has MX records. If there are no MX records, the domain
      // does not operate mail infrastructure and email findings are false positives.
      const isRootDomainWithMail = (
        a.asset.assetClasses?.includes('dns_root') ||
        (a.asset.assetType === 'other' && a.asset.hostname === org.primaryDomain)
      ) && emailSecurityReport?.mx?.records?.length > 0;

      if (!assetIsMailRelated && !isRootDomainWithMail) {
        const before = a.postureFindings.length;
        a.postureFindings = a.postureFindings.filter((f: any) => {
          const cat = (f.category || '').toLowerCase();
          const title = (f.title || '').toLowerCase();
          // Remove findings about email authentication on non-mail assets
          if (cat.includes('email security')) return false;
          if (title.includes('no dmarc') || title.includes('no spf') || title.includes('no dkim')) return false;
          if (title.includes('missing dmarc') || title.includes('missing spf') || title.includes('missing dkim')) return false;
          if (title.includes('dmarc missing') || title.includes('spf missing') || title.includes('dkim missing')) return false;
          if (title.includes('dmarc policy') || title.includes('dmarc record')) return false;
          if (title.includes('email spoofing') || title.includes('email impersonation')) return false;
          if (title.includes('spf record') || title.includes('dkim selector') || title.includes('dkim key')) return false;
          if (title.includes('mail') && (title.includes('security') || title.includes('authentication') || title.includes('record'))) return false;
          return true;
        });
        const removed = before - a.postureFindings.length;
        if (removed > 0) {
          console.log(`[DomainIntel] Suppressed ${removed} email security finding(s) from non-mail asset ${hostname}`);
        }
      }
    }
  } catch (err: any) {
    console.warn(`[DomainIntel] Non-mail asset filter failed (non-fatal): ${err.message}`);
  }

  // Recalculate vulnRiskScore for each asset now that all findings (LLM + vuln feed + KEV + Shodan + PORT + EMAIL) are in place
  await yieldEventLoop();
  for (const a of analyses) {
    const vulnRisk = computeVulnRisk(a.postureFindings);
    a.vulnRiskScore = vulnRisk.score;
    a.vulnRiskBand = vulnRisk.band;
  }
  console.log(`[DomainIntel] Separated scores computed: criticality (CARVER+SHOCK) vs vulnRisk (confirmed/probable findings only)`);

  // Snapshot before the final recalculation
  const preRecalcSnapshot = snapshotScores();

  // POST-ENRICHMENT: Recalculate hybridRiskScore using CONFIRMED vuln data + port exposure boost.
  // This is the critical step: unconfirmed/potential vulns no longer inflate the risk score.
  // Only confirmed (version-matched CVEs, KEV with version overlap, zero-days) and probable (CVE product-family match) drive Likelihood.
  // Port exposure boost adds to likelihood for assets with high-risk exposed ports (RDP, Telnet, FTP, VNC, SMB, databases).
  // Assets with zero confirmed/probable vulns get a baseline low Likelihood (~5-15%).
  //
  // ENHANCED: Apply mission function baselines from the scoring engine.
  // Assets classified with critical mission functions (C2, auth, revenue) get floor scores
  // that ensure they are never under-scored regardless of vuln data.
  // Essential service baselines provide granular CARVER/Shock adjustments.
  try {
    const { applyMissionBaselines } = await import('./lib/scoring-engine');
    let missionIdx = 0;
    for (const a of analyses) {
      missionIdx++;
      if (missionIdx % 10 === 0) await yieldEventLoop();
      // Apply mission function + essential service baselines in one call
      // This ensures critical assets are never under-scored regardless of vuln data
      const baselines = applyMissionBaselines(
        a.carverScores,
        a.shockScores,
        a.missionFunction || 'public_facing_services',
        a.essentialService || 'general_server'
      );
      // Use the baseline-adjusted scores for mission impact calculation
      const missionImpact = computeMissionImpact(baselines.carver, baselines.shock);
      const portBoost = (a as any)._portLikelihoodBoost || 0;
      const hybrid = computeHybridRisk(
        a.cvssEstimate,
        missionImpact,
        a.contextIndicators,
        a.vulnRiskScore, // Pass the CONFIRMED vuln score — this overrides the LLM CVSS for Likelihood
        portBoost // Port exposure boost — high-risk ports increase likelihood
      );
      // Update CARVER/Shock scores with baseline-adjusted values
      a.carverScores = baselines.carver;
      a.shockScores = baselines.shock;
      a.missionImpactScore = Math.round(missionImpact * 10) / 10;
      a.hybridRiskScore = hybrid.score;
      a.riskBand = hybrid.band;
      a.suggestedTier = riskTier(hybrid.score);
      a.impactScore = hybrid.impactScore;
      a.likelihoodScore = hybrid.likelihoodScore;
      a.assetCriticalityScore = computeAssetCriticality(missionImpact).score;
      a.assetCriticalityBand = computeAssetCriticality(missionImpact).band;
      // Clean up temporary port data
      delete (a as any)._portLikelihoodBoost;
      delete (a as any)._portExposureScore;
    }
    console.log(`[DomainIntel] Hybrid risk recalculated with mission function baselines + confirmed vuln data + port exposure`);
    // Record post-enrichment recalculation deltas
    recordPhaseDeltas('post_enrichment_recalc', 'vuln_scan_complete', preRecalcSnapshot, 'Post-enrichment recalculation with confirmed vuln data + mission baselines');
  } catch (err: any) {
    console.error(`[DomainIntel] Post-enrichment recalculation failed (non-fatal, using pre-enrichment scores): ${err.message}`);
    // Clean up temporary port data even on failure
    for (const a of analyses) {
      delete (a as any)._portLikelihoodBoost;
      delete (a as any)._portExposureScore;
    }
  }
  console.log(`[DomainIntel] Re-scoring timeline: ${rescoringTimeline.length} events recorded across ${analyses.length} assets`);

  await yieldEventLoop();
  // Stage 3.95: Cross-Module Enrichment — Bug Bounty, Threat Intel, OpSec, Discovery Deep Dive
  // This feeds data from other modules back into the pipeline for two-way enrichment
  let crossModuleEnrichment: CrossModuleEnrichmentResult | undefined;
  try {
    console.log(`[DomainIntel] Stage 3.95: Running cross-module enrichment (Bug Bounty, Threat Intel, OpSec, Discovery)`);
    crossModuleEnrichment = await runCrossModuleEnrichment(analyses, org.primaryDomain, passiveRecon);
    console.log(
      `[DomainIntel] Cross-module enrichment complete: ` +
      `${crossModuleEnrichment.summary.modulesSucceeded}/${crossModuleEnrichment.summary.modulesRun} modules, ` +
      `${crossModuleEnrichment.summary.totalCorrelations} correlations, ` +
      `${crossModuleEnrichment.summary.totalNewFindings} new findings, ` +
      `${crossModuleEnrichment.summary.totalRiskAdjustments} risk adjustments`
    );

    // Apply threat intel risk boosts to hybrid scores
    for (const a of analyses) {
      const boost = (a as any)._threatIntelBoost;
      if (boost && boost > 0) {
        a.hybridRiskScore = Math.min(100, a.hybridRiskScore + boost);
        a.riskBand = riskBand(a.hybridRiskScore);
        console.log(`[DomainIntel] Threat intel boost: ${a.asset.hostname} +${boost} → ${a.hybridRiskScore} (${a.riskBand})`);
      }
      delete (a as any)._threatIntelBoost;
    }
  } catch (err: any) {
    console.error(`[DomainIntel] Cross-module enrichment failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 3.99: LLM Post-Enrichment Analysis — attack paths, blind spots, recommendations
  let postEnrichmentAnalysis: PostEnrichmentAnalysis | undefined;
  try {
    console.log(`[DomainIntel] Stage 3.99: Running LLM post-enrichment analysis`);
    postEnrichmentAnalysis = await runPostEnrichmentAnalysis(analyses, org, crossModuleEnrichment);
    console.log(
      `[DomainIntel] Post-enrichment analysis complete: ` +
      `${postEnrichmentAnalysis.attackPaths.length} attack paths, ` +
      `${postEnrichmentAnalysis.blindSpots.length} blind spots, ` +
      `${postEnrichmentAnalysis.prioritizedRecommendations.length} recommendations`
    );
  } catch (err: any) {
    console.error(`[DomainIntel] Post-enrichment analysis failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 4: Generate campaign recommendations (now KEV-enriched)
  // If skipEngagement is true, skip campaign design and generate scan-only summaries
  let campaigns: CampaignRecommendation[] = [];
  let summaries: { executiveSummary: string; threatModelSummary: string };

  if (options?.skipEngagement) {
    // Scan-only mode: generate a scan summary without campaign design
    summaries = await generateScanOnlySummary(analyses, org);
    console.log(`[DomainIntel] Scan-only mode: skipped campaign design and threat modeling`);
  } else {
    await onProgress?.('recommending');
    campaigns = await generateCampaignRecommendations(analyses, org, kevEnrichment);
    summaries = await generateSummaries(analyses, campaigns, org, historicalContext || undefined);
  }

  // Compute overall risk — KEV boost is already baked into per-asset hybridRiskScores,
  // so we no longer add an additional overall KEV boost (was double-counting)
  const riskScores = analyses.map(a => a.hybridRiskScore);
  const overallRisk = riskScores.length > 0
    ? Math.round(riskScores.reduce((s, v) => s + v, 0) / riskScores.length)
    : 0;
  const overallBand = riskBand(overallRisk);

  await yieldEventLoop();
  // Stage 6: Post-scan FP auto-flagging — mark findings that match known FP hashes
  if (fpHashes && fpHashes.size > 0) {
    const { createHash } = await import('crypto');
    let autoFlagged = 0;
    let fpIdx = 0;
    for (const a of analyses) {
      fpIdx++;
      if (fpIdx % 10 === 0) await yieldEventLoop();
      for (const f of a.postureFindings) {
        const hash = createHash('sha256')
          .update(`${f.title}|${a.asset.assetId}|${f.category || ''}`)
          .digest('hex').slice(0, 64);
        // Also check title-only hash for cross-asset matching
        const titleHash = createHash('sha256')
          .update(`${f.title}||${f.category || ''}`)
          .digest('hex').slice(0, 64);
        if (fpHashes.has(hash) || fpHashes.has(titleHash)) {
          (f as any).previouslyMarkedFP = true;
          (f as any).fpAutoFlagged = true;
          f.confidence = Math.max(0, f.confidence - 0.3); // Reduce confidence
          if (!f.evidenceChain) f.evidenceChain = [];
          f.evidenceChain.push('⚠ Previously marked as false positive by analyst — confidence reduced');
          autoFlagged++;
        }
      }
    }
    if (autoFlagged > 0) {
      console.log(`[DomainIntel] FP Auto-flag: ${autoFlagged} findings matched known FP patterns`);
    }
  }

  const totalFindings = analyses.reduce((s, a) => s + a.postureFindings.length, 0);
  const confirmedFindingsCount = analyses.reduce((s, a) => s + a.postureFindings.filter((f: any) => f.corroborationTier === 'confirmed').length, 0);
  const probableFindingsCount = analyses.reduce((s, a) => s + a.postureFindings.filter((f: any) => f.corroborationTier === 'probable').length, 0);
  const potentialFindingsCount = analyses.reduce((s, a) => s + a.postureFindings.filter((f: any) => f.corroborationTier === 'potential' || !f.corroborationTier).length, 0);

  // Extract breach data summary from Dehashed passive recon observations
  let breachData: BreachDataSummary | undefined;
  if (passiveRecon) {
    const dehashedResult = passiveRecon.connectorResults.find(r => r.connector === 'dehashed');
    if (dehashedResult && dehashedResult.observations.length > 0) {
      const summaryObs = dehashedResult.observations.find(o => o.tags.includes('breach_summary'));
      const breachObs = dehashedResult.observations.filter(o => o.tags.includes('breach_database'));
      const subdomainObs = dehashedResult.observations.filter(o => o.assetType === 'subdomain');
      const ipObs = dehashedResult.observations.filter(o => o.assetType === 'ip');

      if (summaryObs?.evidence) {
        breachData = {
          totalExposures: summaryObs.evidence.total_records || 0,
          uniqueEmails: breachObs.reduce((s, o) => s + (o.evidence?.total_records || 0), 0),
          uniqueBreachSources: summaryObs.evidence.unique_breaches || breachObs.length,
          breachSources: summaryObs.evidence.breach_databases || breachObs.map(o => o.name || 'unknown'),
          passwordsExposed: summaryObs.evidence.credentials_exposed || 0,
          hashedPasswordsExposed: breachObs.reduce((s, o) => o.evidence?.has_hashed_passwords ? s + 1 : s, 0),
          credentialPairs: summaryObs.evidence.credentials_exposed || 0,
          subdomainsDiscovered: summaryObs.evidence.unique_subdomains_found || subdomainObs.length,
          ipsDiscovered: summaryObs.evidence.unique_ips_found || ipObs.length,
          queriedAt: new Date().toISOString(),
        };
        console.log(`[DomainIntel] Breach data: ${breachData.totalExposures} exposures across ${breachData.uniqueBreachSources} breach sources, ${breachData.credentialPairs} credentials exposed`);
      }
    }
  }

  // Count unique subdomains from passive recon not already in analyzed assets
  let subdomainAssetCount = 0;
  if (passiveRecon?.allObservations) {
    const analyzedHostnames = new Set(analyses.map(a => (a.asset.hostname || '').toLowerCase()));
    const seen = new Set<string>();
    for (const o of passiveRecon.allObservations) {
      if (o.assetType !== 'subdomain' || !o.name) continue;
      const key = o.name.toLowerCase();
      if (seen.has(key) || analyzedHostnames.has(key)) continue;
      seen.add(key);
      subdomainAssetCount++;
    }
  }
  console.log(`[DomainIntel] Asset totals: ${analyses.length} analyzed + ${subdomainAssetCount} passive recon subdomains = ${analyses.length + subdomainAssetCount} total`);

  await yieldEventLoop();
  // Stage 3.97: OEM Default Credential Auto-Collection
  // Match discovered technologies against known default credentials for use in active testing
  let oemCredentials: PipelineResult['oemCredentials'] = [];
  try {
    const { matchCredentialsForAssets, persistMatchedCredentials } = await import('./lib/oem-default-creds');
    const allTechAssets = analyses.map(a => ({
      hostname: a.asset.hostname,
      technologies: a.asset.technologies || [],
      technologyVersions: a.asset.technologyVersions || {},
      openPorts: (a.asset as any).openPorts || [],
    }));
    oemCredentials = matchCredentialsForAssets(allTechAssets);
    if (oemCredentials.length > 0) {
      console.log(`[DomainIntel] OEM credential matching: ${oemCredentials.length} default credentials matched across ${new Set(oemCredentials.map(c => c.matchedAsset)).size} assets`);
      // Persist to DB for reference by operators, AI chat, and automated tools
      try {
        await persistMatchedCredentials(org.primaryDomain, oemCredentials);
      } catch (persistErr: any) {
        console.error(`[DomainIntel] Failed to persist OEM credentials (non-fatal): ${persistErr.message}`);
      }
    } else {
      console.log(`[DomainIntel] OEM credential matching: no default credentials matched`);
    }
  } catch (err: any) {
    console.error(`[DomainIntel] OEM credential matching failed (non-fatal): ${err.message}`);
  }

  await yieldEventLoop();
  // Stage 3.98: Automated Credential Testing
  // Test matched OEM credentials against discovered services with open ports
  let credentialTestSummary: PipelineResult['credentialTestSummary'];
  if (oemCredentials.length > 0) {
    try {
      const { runCredentialTests, getCredentialsForService } = await import('./lib/credential-tester');
      // Build targets from assets that have open ports and matched credentials
      const credTestTargets: Array<{ host: string; port: number; protocol: string; product?: string; technologies?: Array<{ name?: string; vendor?: string; version?: string; cpe?: string }> }> = [];
      for (const analysis of analyses) {
        const asset = analysis.asset;
        const openPorts = (asset as any).openPorts || [];
        for (const portInfo of openPorts) {
          const port = typeof portInfo === 'number' ? portInfo : portInfo?.port;
          if (!port) continue;
          // Determine protocol from port
          const protocol = port === 22 ? 'ssh' : port === 21 ? 'ftp' : port === 23 ? 'telnet'
            : port === 3306 ? 'mysql' : port === 5432 ? 'postgresql' : port === 6379 ? 'redis'
            : port === 27017 ? 'mongodb' : port === 5900 ? 'vnc'
            : (port === 80 || port === 443 || port === 8080 || port === 8443) ? 'http' : 'tcp';
          credTestTargets.push({
            host: asset.hostname,
            port,
            protocol,
            product: portInfo?.service || undefined,
            technologies: (asset.technologies || []).map((t: string) => ({ name: t })),
          });
        }
      }
      if (credTestTargets.length > 0) {
        console.log(`[DomainIntel] Stage 3.98: Running credential tests against ${credTestTargets.length} services`);
        const testResult = await runCredentialTests(credTestTargets, {
          concurrency: 3,
          timeoutMs: 8000,
          maxCredsPerTarget: 5,
        });
        const confirmedCreds = testResult.results.filter(r => r.status === 'success').map(r => ({
          host: r.target.host,
          port: r.target.port,
          protocol: r.credential.protocol,
          vendor: r.credential.vendor,
          product: r.credential.product,
          username: r.credential.username,
          accessLevel: r.confirmedAccess || r.credential.accessLevel,
        }));
        credentialTestSummary = {
          totalTargets: testResult.totalTargets,
          totalCredentialsTested: testResult.totalCredentialsTested,
          successfulLogins: testResult.successfulLogins,
          failedAttempts: testResult.failedAttempts,
          timeouts: testResult.timeouts,
          errors: testResult.errors,
          confirmedCredentials: confirmedCreds,
        };
        if (testResult.successfulLogins > 0) {
          console.log(`[DomainIntel] Stage 3.98: ${testResult.successfulLogins} default credential(s) CONFIRMED across ${new Set(confirmedCreds.map(c => c.host)).size} hosts`);
        } else {
          console.log(`[DomainIntel] Stage 3.98: No default credentials confirmed (${testResult.totalCredentialsTested} tested)`);
        }
      }
    } catch (credTestErr: any) {
      console.error(`[DomainIntel] Stage 3.98 credential testing failed (non-fatal): ${credTestErr.message}`);
    }
  }

  await yieldEventLoop();
  // Stage 3.991: External SCAP/STIG Compliance Scan
  let complianceScan: PipelineResult['complianceScan'];
  try {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    console.log(`[DomainIntel] Stage 3.991: Running external SCAP/STIG compliance scan against ${org.primaryDomain}`);
    complianceScan = await runExternalComplianceScan(org.primaryDomain, { timeout: 15000 });
    console.log(`[DomainIntel] SCAP compliance: ${complianceScan.complianceScore}% (${complianceScan.passed}/${complianceScan.totalChecks - complianceScan.notApplicable} passed, ${complianceScan.failed} failed)`);
  } catch (scapErr: any) {
    console.error(`[DomainIntel] Stage 3.991 SCAP compliance scan failed (non-fatal): ${scapErr.message}`);
  }

  await yieldEventLoop();
  // Stage 3.992: Container Infrastructure Exposure Scan
  let containerExposure: PipelineResult['containerExposure'];
  try {
    const { analyzeContainerExposure } = await import('./lib/passive/container-discovery');
    const additionalHosts = analyses.map(a => a.asset.hostname).filter(h => h !== org.primaryDomain);
    console.log(`[DomainIntel] Stage 3.992: Running container exposure scan (${additionalHosts.length + 1} hosts)`);
    containerExposure = await analyzeContainerExposure(org.primaryDomain, additionalHosts, 3000, 45000);
    if (containerExposure.totalHits > 0) {
      console.log(`[DomainIntel] Container exposure: ${containerExposure.totalHits} exposed services found (${containerExposure.criticalFindings} critical, ${containerExposure.highFindings} high)`);
    } else {
      console.log(`[DomainIntel] Container exposure: No exposed container infrastructure detected (${containerExposure.totalProbes} probes)`);
    }
  } catch (containerErr: any) {
    console.error(`[DomainIntel] Stage 3.992 container exposure scan failed (non-fatal): ${containerErr.message}`);
  }

  // ─── Auto-generate CARVER Risk Card for this domain ────────────────────
  let carverRiskCard: any = null;
  try {
    const { buildExplainableRiskCard } = await import('./lib/auto-industry-carver');
    const { createCarverRiskCard } = await import('./db');

    // Build asset signals from passive recon
    const assetSignals: string[] = [];
    if (passiveRecon) {
      const obs = passiveRecon.allObservations || [];
      if (obs.some(o => o.assetType === 'mx')) assetSignals.push('MX Record');
      if (obs.some(o => o.name?.includes('sso') || o.name?.includes('auth') || o.name?.includes('login'))) assetSignals.push('SSO');
      if (obs.some(o => o.name?.includes('vpn'))) assetSignals.push('VPN Gateway');
      if (obs.some(o => o.name?.includes('api'))) assetSignals.push('API Gateway');
      if (obs.some(o => o.name?.includes('ehr') || o.name?.includes('epic') || o.name?.includes('cerner'))) assetSignals.push('EHR System');
      if (obs.some(o => o.name?.includes('scada') || o.name?.includes('ics') || o.name?.includes('ot'))) assetSignals.push('SCADA/ICS');
    }

    // Build keywords from findings
    const keywords: string[] = [];
    for (const a of analyses.slice(0, 20)) {
      if (a.technology) keywords.push(...a.technology.split(',').map((t: string) => t.trim()));
    }

    const riskCard = buildExplainableRiskCard({
      assetId: org.primaryDomain,
      assetLabel: `${org.primaryDomain} (${org.name || 'Domain Intel'})`,
      domain: org.primaryDomain,
      keywords: [...new Set(keywords)].slice(0, 20),
      assetSignals: [...new Set(assetSignals)],
    });

    carverRiskCard = riskCard;

    await createCarverRiskCard({
      domain: org.primaryDomain,
      scanTitle: `${org.primaryDomain} — Domain Intel Pipeline`,
      inferredSector: riskCard.sector,
      sectorConfidence: riskCard.confidence >= 0.78 ? 'high' : riskCard.confidence >= 0.55 ? 'medium' : riskCard.confidence >= 0.35 ? 'low' : 'insufficient',
      naicsCode: riskCard.naics || null,
      naicsLabel: null,
      industry: null,
      regulatoryTags: riskCard.regulatoryProfile || [],
      country: 'US',
      carverScores: { criticality: riskCard.scores?.carverShock || 0 },
      shockScores: null,
      hybridScore: riskCard.scores?.hybrid || 0,
      priorityTier: riskCard.scores?.priorityTier || 'P3',
      confidenceBand: riskCard.confidence >= 0.78 ? 'high' : riskCard.confidence >= 0.55 ? 'medium' : 'low',
      topDrivers: riskCard.topDrivers || [],
      recommendedActions: riskCard.recommendedActions || [],
      calderaOps: riskCard.calderaPriority || null,
      threatLikelihood: riskCard.threatLikelihood || null,
      fullRiskCard: riskCard,
      source: 'domain_intel_pipeline' as any,
      batchId: null,
    } as any);
    console.log(`[DomainIntel] CARVER risk card generated for ${org.primaryDomain}: ${riskCard.scores?.priorityTier} (hybrid=${riskCard.scores?.hybrid})`);
  } catch (carverErr: any) {
    console.error(`[DomainIntel] CARVER risk card generation failed (non-fatal): ${carverErr.message}`);
  }

  // ─── Compute Scan Delta (cross-session comparison) ──────────────────
  let scanDelta: PipelineResult['scanDelta'] | undefined;
  try {
    const db = await import('./db');
    const histCtx = await db.getHistoricalScanContext(org.primaryDomain);
    if (histCtx) {
      const currentHostnames = new Set(analyses.map(a => a.asset.hostname.toLowerCase()));
      const previousHostnames = new Set(histCtx.previousAssets.map(a => a.hostname.toLowerCase()));
      const newAssets = [...currentHostnames].filter(h => !previousHostnames.has(h));
      const removedAssets = [...previousHostnames].filter(h => !currentHostnames.has(h));
      const persistentAssets = [...currentHostnames].filter(h => previousHostnames.has(h));

      scanDelta = {
        previousScanId: histCtx.previousScanId,
        previousScanDate: histCtx.previousScanDate,
        scanNumber: histCtx.scanCount + 1,
        riskDelta: histCtx.previousRiskScore != null ? overallRisk - histCtx.previousRiskScore : null,
        previousRiskScore: histCtx.previousRiskScore,
        assetDelta: histCtx.previousTotalAssets != null ? (analyses.length + subdomainAssetCount) - histCtx.previousTotalAssets : null,
        previousTotalAssets: histCtx.previousTotalAssets,
        findingsDelta: histCtx.previousTotalFindings != null ? totalFindings - histCtx.previousTotalFindings : null,
        previousTotalFindings: histCtx.previousTotalFindings,
        newAssets,
        removedAssets,
        persistentAssets,
      };
      console.log(`[DomainIntel] Scan Delta: risk ${scanDelta.riskDelta! >= 0 ? '+' : ''}${scanDelta.riskDelta}, assets ${scanDelta.assetDelta! >= 0 ? '+' : ''}${scanDelta.assetDelta}, findings ${scanDelta.findingsDelta! >= 0 ? '+' : ''}${scanDelta.findingsDelta}, new=${newAssets.length}, removed=${removedAssets.length}, persistent=${persistentAssets.length}`);
    }
  } catch (err: any) {
    console.error(`[DomainIntel] Scan delta computation failed (non-fatal): ${err.message}`);
  }

  return {
    orgProfile: org,
    assets: analyses,
    campaignRecommendations: campaigns,
    carverRiskCard,
    overallRiskScore: overallRisk,
    overallRiskBand: overallBand,
    executiveSummary: summaries.executiveSummary,
    threatModelSummary: summaries.threatModelSummary,
    // @ts-ignore
      totalAnalyzedAssets: analyses.length,
    totalSubdomainAssets: subdomainAssetCount,
    totalAssets: analyses.length + subdomainAssetCount,
    totalFindings,
    confirmedFindingsCount,
    probableFindingsCount,
    potentialFindingsCount,
    kevEnrichment,
    passiveRecon,
    breachData,
    exploitMatches: exploitMatchResult,
    rescoringTimeline,
    discoveryCoverage: passiveRecon?.discoveryCoverage || undefined,
    emailSecurity: emailSecurityReport || undefined,
    crossModuleEnrichment,
    postEnrichmentAnalysis,
    orgDiscovery: orgDiscoveryResult || undefined,
    oemCredentials,
    credentialTestSummary,
    complianceScan,
    containerExposure,
    wafNgfwAssessment,
    scanDelta,
  };
}
