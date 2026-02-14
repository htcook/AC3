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
  assetClasses: string[];
  tags: string[];
  description?: string;
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

export interface PostureFinding {
  id: string;
  assetRef: string;
  category: string;
  title: string;
  severity: number; // 0-10
  likelihood: number; // 0-10
  confidence: number; // 0-1
  recommendedControls: string[];
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
}

export interface KevEnrichment {
  matches: KevMatch[];
  riskBoost: number;
  ransomwareExposure: boolean;
  criticalKevCount: number;
  summary: string;
  chainSteps: Array<{ techniqueId: string; priority: number; source: "kev"; context: string }>;
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
  kevEnrichment?: KevEnrichment;
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

export async function discoverAssets(org: OrgProfile): Promise<DiscoveredAssetRaw[]> {
  const allDomains = [org.primaryDomain, ...(org.additionalDomains || [])];
  
  const prompt = `You are a passive OSINT reconnaissance analyst. Given the following organization profile, infer and enumerate likely digital assets that would exist for this organization. This is PASSIVE analysis only - no active scanning.

Organization:
- Name: ${org.customerName}
- Primary Domain: ${org.primaryDomain}
- Additional Domains: ${(org.additionalDomains || []).join(", ") || "none"}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${org.criticalFunctions.join(", ")}
- Compliance: ${org.complianceFlags.join(", ") || "none specified"}
- Notes: ${org.notes || "none"}

For each domain (${allDomains.join(", ")}), infer likely subdomains, services, and assets based on:
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
  "assetClasses": ["identity_provider", "email_infrastructure", etc],
  "tags": ["internet_exposed", "authentication", "critical_data", etc],
  "description": "Brief description of what this asset likely does",
  "dnsRecords": {"A": [], "CNAME": [], "MX": [], "TXT": [], "NS": []},
  "headers": "likely server headers"
}

Generate 15-30 realistic assets. Be specific to the sector and client type. For ${org.clientType} clients, emphasize:
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
    return Array.isArray(parsed) ? parsed : (parsed.assets || []);
  } catch (err) {
    console.error("[DomainIntel] Discovery failed:", err);
    return generateFallbackAssets(org);
  }
}

function generateFallbackAssets(org: OrgProfile): DiscoveredAssetRaw[] {
  const domain = org.primaryDomain;
  const base: DiscoveredAssetRaw[] = [
    { assetId: "a-001", hostname: `mail.${domain}`, assetType: "mail_gateway", assetClasses: ["email_infrastructure"], tags: ["internet_exposed", "email"], description: "Mail gateway" },
    { assetId: "a-002", hostname: `sso.${domain}`, assetType: "sso", assetClasses: ["identity_provider"], tags: ["internet_exposed", "authentication", "critical_data"], description: "Single sign-on portal" },
    { assetId: "a-003", hostname: `vpn.${domain}`, assetType: "vpn", assetClasses: ["network_access"], tags: ["internet_exposed", "authentication"], description: "VPN concentrator" },
    { assetId: "a-004", hostname: `www.${domain}`, assetType: "customer_portal", assetClasses: ["web_application"], tags: ["internet_exposed", "public"], description: "Main website" },
    { assetId: "a-005", hostname: `api.${domain}`, assetType: "api", assetClasses: ["api_endpoint"], tags: ["internet_exposed", "developer"], description: "API endpoint" },
    { assetId: "a-006", hostname: `admin.${domain}`, assetType: "admin_panel", assetClasses: ["management_interface"], tags: ["internet_exposed", "authentication", "privileged"], description: "Admin panel" },
    { assetId: "a-007", hostname: domain, url: `https://${domain}`, assetType: "other", assetClasses: ["dns_root"], tags: ["internet_exposed"], description: "Root domain - DNS records", dnsRecords: { MX: [], TXT: [], NS: [] } },
  ];
  return base;
}

// ─── Stage 2: Asset Classification & BIA Scoring (LLM) ──────────────

export async function analyzeAssets(
  assets: DiscoveredAssetRaw[],
  org: OrgProfile
): Promise<AssetAnalysis[]> {
  const prompt = `You are a cybersecurity risk analyst performing Business Impact Analysis using the CARVER+SHOCK methodology combined with hybrid risk scoring.

Organization Profile:
- Name: ${org.customerName}
- Domain: ${org.primaryDomain}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${org.criticalFunctions.join(", ")}
- Compliance: ${org.complianceFlags.join(", ") || "none"}

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

6. Posture Findings: Security weaknesses identified (array of objects with id, category, title, severity 0-10, likelihood 0-10, recommendedControls[])

7. Test Vectors: Suggested attack vectors (array of objects with id, vectorType, hypothesis, suggestedEmulation {technique, tactic}, expectedTelemetry[], riskSignal {severity, likelihood})

Return JSON with this exact structure:
{
  "analyses": [
    {
      "assetId": "a-001",
      "carverScores": { "criticality": 8, "accessibility": 7, ... },
      "shockScores": { "scope": 6, "handling": 7, ... },
      "cvssEstimate": 7.5,
      "contextIndicators": { "exposure": 0.8, "recognizability": 0.7, "confidence": 0.75 },
      "suggestedTier": "tier1_high",
      "postureFindings": [...],
      "testVectors": [...]
    }
  ]
}

Be thorough and realistic. Score based on the specific sector (${org.sector}) and client type (${org.clientType}).`;

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
      const cvss = clamp(analysis.cvssEstimate || 5, 0, 10);
      const ctx = {
        exposure: clamp(analysis.contextIndicators?.exposure || 0.5, 0, 1),
        recognizability: clamp(analysis.contextIndicators?.recognizability || 0.5, 0, 1),
        confidence: clamp(analysis.contextIndicators?.confidence || 0.5, 0, 1),
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
        postureFindings: (analysis.postureFindings || []).map((f: any, i: number) => ({
          id: f.id || `pf-${asset.assetId}-${i}`,
          assetRef: asset.hostname,
          category: f.category || "general",
          title: f.title || "Finding",
          severity: clamp(f.severity || 5, 0, 10),
          likelihood: clamp(f.likelihood || 5, 0, 10),
          confidence: clamp(f.confidence || 0.7, 0, 1),
          recommendedControls: f.recommendedControls || [],
        })),
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
    criticality: clamp(raw.criticality || 5, 0, 10),
    accessibility: clamp(raw.accessibility || 5, 0, 10),
    recuperability: clamp(raw.recuperability || 5, 0, 10),
    vulnerability: clamp(raw.vulnerability || 5, 0, 10),
    effect: clamp(raw.effect || 5, 0, 10),
    recognizability: clamp(raw.recognizability || 5, 0, 10),
  };
}

function normalizeShock(raw: any): ShockScores {
  return {
    scope: clamp(raw.scope || 5, 0, 10),
    handling: clamp(raw.handling || 5, 0, 10),
    operationalImpact: clamp(raw.operationalImpact || 5, 0, 10),
    cascadingEffects: clamp(raw.cascadingEffects || 5, 0, 10),
    knowledge: clamp(raw.knowledge || 5, 0, 10),
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

function computeHybridRisk(
  cvss: number,
  missionImpact: number,
  ctx: { exposure: number; recognizability: number; confidence: number }
): { score: number; band: string } {
  const alpha = 0.4; // 40% CVSS, 60% mission impact
  const cvssNorm = cvss / 10;
  const missionNorm = missionImpact / 10;
  const blended = alpha * cvssNorm + (1 - alpha) * missionNorm;

  // Context multiplier
  let multiplier = 1.0;
  multiplier += (ctx.exposure - 0.5) * 0.3;
  multiplier += (ctx.recognizability - 0.5) * 0.15;
  multiplier = clamp(multiplier, 0.7, 1.4);

  const score = clamp(100 * blended * multiplier, 0, 100);
  const band = score >= 85 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : "low";

  return { score, band };
}

function inferTier(riskScore: number): string {
  if (riskScore >= 85) return "tier0_critical";
  if (riskScore >= 70) return "tier1_high";
  if (riskScore >= 40) return "tier2_medium";
  return "tier3_low";
}

function createDefaultAnalysis(asset: DiscoveredAssetRaw): AssetAnalysis {
  const carver = normalizeCarver({});
  const shock = normalizeShock({});
  const mission = computeMissionImpact(carver, shock);
  const hybrid = computeHybridRisk(5, mission, { exposure: 0.5, recognizability: 0.5, confidence: 0.4 });
  return {
    asset,
    carverScores: carver,
    shockScores: shock,
    missionImpactScore: Math.round(mission * 10) / 10,
    suggestedTier: inferTier(hybrid.score),
    hybridRiskScore: Math.round(hybrid.score),
    riskBand: hybrid.band,
    cvssEstimate: 5,
    contextIndicators: { exposure: 0.5, recognizability: 0.5, confidence: 0.4 },
    postureFindings: [],
    testVectors: [],
    confidence: 40,
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
Critical Functions: ${org.criticalFunctions.join(", ")}
Compliance: ${org.complianceFlags.join(", ") || "none"}

Top Risk Assets (sorted by hybrid risk score):
${JSON.stringify(topAssets.map(a => ({
  id: a.asset.assetId,
  hostname: a.asset.hostname,
  type: a.asset.assetType,
  riskScore: a.hybridRiskScore,
  riskBand: a.riskBand,
  tier: a.suggestedTier,
  classes: a.asset.assetClasses,
  tags: a.asset.tags,
  findings: a.postureFindings.map(f => f.title),
  vectors: a.testVectors.map(v => ({ type: v.vectorType, hypothesis: v.hypothesis })),
})), null, 2)}

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

// ─── Stage 5: Executive Summary & Threat Model ───────────────────────

export async function generateSummaries(
  analyses: AssetAnalysis[],
  campaigns: CampaignRecommendation[],
  org: OrgProfile
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
${campaigns.map(c => `- ${c.name} [${c.type}] - Priority: ${c.priority}`).join("\n")}

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
  onProgress?: (stage: 'discovering' | 'analyzing' | 'scoring' | 'recommending') => void | Promise<void>
): Promise<PipelineResult> {
  // Stage 1: Discover assets
  await onProgress?.('discovering');
  const rawAssets = await discoverAssets(org);

  // Stage 2 & 3: Analyze assets (classification, BIA, hybrid risk)
  await onProgress?.('analyzing');
  const analyses = await analyzeAssets(rawAssets, org);

  // Stage 3.5: CISA KEV Enrichment
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
        // Boost risk scores for assets with KEV-matched technologies
        analyses.forEach(a => {
          const assetTechs = (a.asset.technologies || []).map(t => t.toLowerCase());
          const assetKevMatches = kevMatches.filter(m =>
            assetTechs.some(t => t.toLowerCase().includes(m.matchedOn.toLowerCase()) || m.matchedOn.toLowerCase().includes(t.toLowerCase()))
          );
          if (assetKevMatches.length > 0) {
            const assetBoost = Math.min(assetKevMatches.reduce((s, m) => s + m.severityBoost, 0), 30);
            a.hybridRiskScore = Math.min(100, a.hybridRiskScore + assetBoost);
            a.riskBand = a.hybridRiskScore >= 85 ? "critical" : a.hybridRiskScore >= 70 ? "high" : a.hybridRiskScore >= 40 ? "medium" : "low";
            a.suggestedTier = a.hybridRiskScore >= 85 ? "tier0_critical" : a.hybridRiskScore >= 70 ? "tier1_high" : a.hybridRiskScore >= 40 ? "tier2_medium" : "tier3_low";
            // Add KEV posture findings
            assetKevMatches.forEach(m => {
              a.postureFindings.push({
                id: `kev-${m.cveID}`,
                assetRef: a.asset.assetId,
                category: "CISA KEV",
                title: `${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [RANSOMWARE]" : ""}`,
                severity: m.knownRansomware ? 10 : 9,
                likelihood: 9, // KEV = actively exploited = very high likelihood
                confidence: 0.95,
                recommendedControls: [m.requiredAction, `Patch ${m.product} immediately`, "Monitor for exploitation indicators"],
              });
            });
          }
        });
        console.log(`[DomainIntel] KEV enrichment: ${kevMatches.length} matches, ${chainSteps.length} chain steps, boost=${boost.riskBoost}`);
      }
    }
  } catch (err: any) {
    console.error(`[DomainIntel] KEV enrichment failed (non-fatal): ${err.message}`);
  }

  // Stage 4: Generate campaign recommendations (now KEV-enriched)
  await onProgress?.('recommending');
  const campaigns = await generateCampaignRecommendations(analyses, org, kevEnrichment);

  // Stage 5: Generate summaries
  const summaries = await generateSummaries(analyses, campaigns, org);

  // Compute overall risk (with KEV boost)
  const riskScores = analyses.map(a => a.hybridRiskScore);
  let overallRisk = riskScores.length > 0
    ? Math.round(riskScores.reduce((s, v) => s + v, 0) / riskScores.length)
    : 0;
  if (kevEnrichment) {
    overallRisk = Math.min(100, overallRisk + Math.round(kevEnrichment.riskBoost / 3));
  }
  const overallBand = overallRisk >= 85 ? "critical" : overallRisk >= 70 ? "high" : overallRisk >= 40 ? "medium" : "low";
  const totalFindings = analyses.reduce((s, a) => s + a.postureFindings.length, 0);

  return {
    orgProfile: org,
    assets: analyses,
    campaignRecommendations: campaigns,
    overallRiskScore: overallRisk,
    overallRiskBand: overallBand,
    executiveSummary: summaries.executiveSummary,
    threatModelSummary: summaries.threatModelSummary,
    totalAssets: analyses.length,
    totalFindings,
    kevEnrichment,
  };
}
