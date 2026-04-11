/**
 * Post-Pipeline Graduation & Training Module
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Shared module that runs graduation scoring, results persistence, and
 * training data collection at the end of ANY pipeline — engagement orchestrator,
 * DI scanner, scheduled scans, or ad-hoc scans.
 *
 * This ensures every scan/engagement contributes to the platform's learning
 * loop regardless of how it was triggered.
 *
 * Specialist Models Scored:
 *   - recon_analyst:      Asset discovery, subdomain enumeration, port coverage
 *   - exploit_selector:   Exploit success rate, evidence quality, vuln verification
 *   - evasion_optimizer:  WAF/IDS bypass, scan completion without blocking
 *   - cognitive_core:     Overall quality, OWASP coverage, accuracy, false positive rate
 *   - cloud_assessor:     Cloud/SaaS/PaaS asset identification and risk scoring
 *   - supply_chain_analyst: Dependency, repo, and third-party risk detection
 *
 * Enterprise Asset Categories:
 *   - Web Applications (traditional web apps, SPAs, APIs)
 *   - Cloud Infrastructure (AWS, Azure, GCP, DO services)
 *   - Code Repositories (GitHub, GitLab, Bitbucket exposure)
 *   - Platforms & SaaS (Jira, Confluence, Slack, etc.)
 *   - Network Infrastructure (routers, switches, VPNs, firewalls)
 *   - Container/Orchestration (Docker, K8s, ECS)
 *   - Storage (S3 buckets, blob storage, NFS)
 *   - Identity/Auth (SSO, LDAP, AD, OAuth providers)
 */

import type { SpecialistModel, TrainingExample } from "./llm-training-pipeline";

// ─── Types ──────────────────────────────────────────────────────────────────

export type PipelineType = "engagement" | "di_scan" | "scheduled_scan" | "ad_hoc";

export interface PipelineMetrics {
  pipelineType: PipelineType;
  pipelineId: string | number;
  domain?: string;

  // Recon metrics
  assetsDiscovered: number;
  subdomainsFound: number;
  portsFound: number;
  servicesIdentified: number;
  technologiesDetected: number;

  // Vulnerability metrics
  totalVulns: number;
  confirmedVulns: number;
  potentialVulns: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  infoVulns: number;
  uniqueCVEs: number;
  kevMatches: number;

  // Exploit metrics (engagement-only, default 0 for DI scans)
  exploitsAttempted: number;
  exploitsSucceeded: number;
  verifiedVulns: number;
  /** Count of exploits independently confirmed by Nuclei (direct execution or re-verification) */
  nucleiVerifiedExploits: number;

  // Evasion metrics
  wafDetected: boolean;
  wafBypassed: boolean;
  evasionEscalations: number;
  scanBlocked: boolean;
  scanRecovered: boolean;

  // Coverage metrics
  owaspCategoriesTested: number;
  owaspCategoriesTotal: number;
  ptesPhasesCovered: number;
  ptesPhasesTotal: number;

  // Enterprise asset category metrics
  cloudAssetsFound: number;
  repoExposuresFound: number;
  platformAssetsFound: number;
  containerAssetsFound: number;
  storageAssetsFound: number;
  identityAssetsFound: number;
  networkInfraFound: number;

  // Quality metrics
  falsePositiveRate: number;
  connectorSuccessRate: number;
  scanDurationMs: number;

  // Raw data for training examples
  successfulExploits: Array<{
    id?: string;
    target?: string;
    vulnTitle?: string;
    technique?: string;
    tool?: string;
    command?: string;
    rawEvidence?: string;
  }>;
  reconObservations: Array<{
    source: string;
    assetType: string;
    name?: string;
    ip?: string;
    findings?: number;
  }>;
}

export interface GraduationResult {
  scores: {
    recon_analyst: number;
    exploit_selector: number;
    evasion_optimizer: number;
    cognitive_core: number;
    cloud_assessor: number;
    supply_chain_analyst: number;
  };
  passed: {
    recon_analyst: boolean;
    exploit_selector: boolean;
    evasion_optimizer: boolean;
    cognitive_core: boolean;
    cloud_assessor: boolean;
    supply_chain_analyst: boolean;
  };
  trainingExamplesCollected: number;
  modelsScored: number;
  summary: string;
}

// ─── Enterprise Asset Classification ────────────────────────────────────────

const CLOUD_INDICATORS = [
  "aws", "amazon", "s3", "ec2", "lambda", "cloudfront", "elasticbeanstalk",
  "azure", "microsoft", "blob.core", "azurewebsites",
  "gcp", "google", "googleapis", "appspot", "firebase",
  "digitalocean", "linode", "vultr", "heroku", "netlify", "vercel",
  "cloudflare", "fastly", "akamai",
];

const REPO_INDICATORS = [
  "github", "gitlab", "bitbucket", "codecommit", "gitea", "gogs",
  ".git", "repository", "repo",
];

const PLATFORM_INDICATORS = [
  "jira", "confluence", "atlassian", "slack", "teams", "zoom",
  "salesforce", "hubspot", "zendesk", "freshdesk", "servicenow",
  "okta", "auth0", "onelogin", "ping",
];

const CONTAINER_INDICATORS = [
  "docker", "kubernetes", "k8s", "ecs", "fargate", "rancher",
  "openshift", "portainer", "registry",
];

const STORAGE_INDICATORS = [
  "s3", "blob", "storage", "minio", "nfs", "ceph", "gluster",
  "backblaze", "wasabi",
];

const IDENTITY_INDICATORS = [
  "sso", "ldap", "active-directory", "adfs", "oauth", "saml",
  "keycloak", "okta", "auth0", "cognito",
];

function classifyAssetCategory(hostname: string, technologies: string[]): string[] {
  const categories: string[] = [];
  const lower = hostname.toLowerCase();
  const techLower = technologies.map(t => t.toLowerCase());
  const all = [lower, ...techLower].join(" ");

  if (CLOUD_INDICATORS.some(i => all.includes(i))) categories.push("cloud");
  if (REPO_INDICATORS.some(i => all.includes(i))) categories.push("repository");
  if (PLATFORM_INDICATORS.some(i => all.includes(i))) categories.push("platform");
  if (CONTAINER_INDICATORS.some(i => all.includes(i))) categories.push("container");
  if (STORAGE_INDICATORS.some(i => all.includes(i))) categories.push("storage");
  if (IDENTITY_INDICATORS.some(i => all.includes(i))) categories.push("identity");
  if (categories.length === 0) categories.push("web_application");

  return categories;
}

// ─── Scoring Functions ──────────────────────────────────────────────────────

function scoreReconAnalyst(m: PipelineMetrics): number {
  // Asset discovery: 5 pts per asset, 2 pts per subdomain (max 30)
  const assetScore = Math.min(30, m.assetsDiscovered * 5 + m.subdomainsFound * 2);
  // Port coverage: 3 pts per port (max 25)
  const portScore = Math.min(25, m.portsFound * 3);
  // Service identification: 4 pts per identified service (max 15)
  const serviceScore = Math.min(15, m.servicesIdentified * 4);
  // Technology detection: 2 pts per tech (max 10)
  const techScore = Math.min(10, m.technologiesDetected * 2);
  // Intelligence enrichment bonus: credit KEV matches, CVE correlation, and vuln discovery
  // This rewards the recon phase for producing actionable intelligence, not just asset counts
  const kevBonus = Math.min(10, m.kevMatches * 5);
  const cveBonus = Math.min(5, m.uniqueCVEs > 0 ? 5 : 0);
  const vulnDiscoveryBonus = Math.min(5, m.totalVulns > 0 ? Math.min(5, Math.ceil(m.totalVulns / 4)) : 0);
  return Math.min(100, assetScore + portScore + serviceScore + techScore + kevBonus + cveBonus + vulnDiscoveryBonus);
}

function scoreExploitSelector(m: PipelineMetrics): number {
  if (m.pipelineType === "di_scan" || m.pipelineType === "scheduled_scan") {
    // DI scans don't exploit — score on vuln identification accuracy
    const vulnAccuracy = m.totalVulns > 0
      ? (m.confirmedVulns / m.totalVulns) * 50
      : 0;
    const severityDepth = Math.min(30, (m.criticalVulns * 10) + (m.highVulns * 5) + (m.mediumVulns * 2));
    const kevScore = Math.min(20, m.kevMatches * 10);
    return Math.min(100, Math.round(vulnAccuracy + severityDepth + kevScore));
  }

  // Engagement scoring — balanced across exploit success, vuln discovery, and attempt effort
  // Success rate: up to 35 pts (reduced from 50 to avoid penalizing training lab attempts)
  const successRate = m.exploitsAttempted > 0
    ? (m.exploitsSucceeded / m.exploitsAttempted) * 35
    : 0;
  // Attempt credit: up to 15 pts for making exploit attempts (shows exploit selection capability)
  const attemptCredit = Math.min(15, m.exploitsAttempted * 5);
  // Evidence quality: up to 20 pts for verified vulns
  const evidenceRate = m.totalVulns > 0
    ? (m.verifiedVulns / m.totalVulns) * 20
    : 0;
  // Vuln volume: up to 15 pts for finding vulns (shows target selection)
  const volumeBonus = Math.min(15, m.totalVulns > 10 ? 15 : Math.ceil(m.totalVulns * 1.5));
  // Severity depth: up to 15 pts for finding critical/high vulns
  const severityBonus = Math.min(15, (m.criticalVulns * 5) + (m.highVulns * 3) + (m.mediumVulns * 1));
  // Nuclei verification bonus: up to 10 pts for Nuclei-confirmed exploits
  // Nuclei-confirmed exploits are independently verified by a second tool, so they deserve a scoring bonus
  const nucleiBonus = Math.min(10, (m.nucleiVerifiedExploits || 0) * 5);
  return Math.min(100, Math.round(successRate + attemptCredit + evidenceRate + volumeBonus + severityBonus + nucleiBonus));
}

function scoreEvasionOptimizer(m: PipelineMetrics): number {
  if (!m.wafDetected) return 90; // No WAF = easy mode, still decent score
  if (m.scanBlocked && !m.scanRecovered) return 30; // Blocked and couldn't recover
  if (m.scanBlocked && m.scanRecovered) return 70; // Blocked but recovered
  if (m.wafBypassed) return 95; // Detected and bypassed
  return 80; // WAF present but not blocking
}

function scoreCognitiveCore(m: PipelineMetrics): number {
  const coverageScore = m.owaspCategoriesTotal > 0
    ? Math.round((m.owaspCategoriesTested / m.owaspCategoriesTotal) * 35)
    : 20;
  const evidenceRate = m.totalVulns > 0
    ? Math.round((m.confirmedVulns / m.totalVulns) * 25)
    : 0;
  const fpPenalty = Math.round(m.falsePositiveRate * 20);
  // Vuln discovery baseline: finding vulns shows cognitive capability
  const vulnBaseline = m.totalVulns > 0 ? 15 : 0;
  // PTES phase coverage bonus: credit for covering more phases
  const ptesBonus = m.ptesPhasesTotal > 0
    ? Math.min(15, Math.round((m.ptesPhasesCovered / m.ptesPhasesTotal) * 15))
    : 0;
  // Multi-tool corroboration bonus: having both confirmed and total vulns shows quality
  const corroborationBonus = m.confirmedVulns > 0 && m.totalVulns > m.confirmedVulns ? 5 : 0;
  const baseScore = coverageScore + evidenceRate + vulnBaseline + ptesBonus + corroborationBonus;
  return Math.min(100, Math.max(0, baseScore - fpPenalty));
}

function scoreCloudAssessor(m: PipelineMetrics): number {
  const cloudScore = Math.min(40, m.cloudAssetsFound * 10);
  const storageScore = Math.min(20, m.storageAssetsFound * 10);
  const containerScore = Math.min(20, m.containerAssetsFound * 10);
  const identityScore = Math.min(20, m.identityAssetsFound * 10);
  return Math.min(100, cloudScore + storageScore + containerScore + identityScore);
}

function scoreSupplyChainAnalyst(m: PipelineMetrics): number {
  const repoScore = Math.min(40, m.repoExposuresFound * 15);
  const platformScore = Math.min(30, m.platformAssetsFound * 10);
  const techDepthScore = Math.min(30, m.technologiesDetected * 3);
  return Math.min(100, repoScore + platformScore + techDepthScore);
}

// ─── Main Graduation Function ───────────────────────────────────────────────

/**
 * Run graduation scoring for any pipeline type.
 * Returns structured scores and records them via the graduation-lab-bridge.
 */
export async function runPostPipelineGraduation(
  metrics: PipelineMetrics,
): Promise<GraduationResult> {
  const { recordScenarioResult, recordTrainingData } = await import("./graduation-lab-bridge");

  const scores = {
    recon_analyst: scoreReconAnalyst(metrics),
    exploit_selector: scoreExploitSelector(metrics),
    evasion_optimizer: scoreEvasionOptimizer(metrics),
    cognitive_core: scoreCognitiveCore(metrics),
    cloud_assessor: scoreCloudAssessor(metrics),
    supply_chain_analyst: scoreSupplyChainAnalyst(metrics),
  };

  const passed = {
    recon_analyst: scores.recon_analyst >= 30,
    exploit_selector: scores.exploit_selector >= 20,
    evasion_optimizer: scores.evasion_optimizer >= 50,
    cognitive_core: scores.cognitive_core >= 40,
    cloud_assessor: scores.cloud_assessor >= 10,
    supply_chain_analyst: scores.supply_chain_analyst >= 10,
  };

  const pipelineId = String(metrics.pipelineId);
  const prefix = metrics.pipelineType === "engagement" ? "eng" : "di";

  // Record each specialist model score via graduation-lab-bridge
  const models: Array<{ key: keyof typeof scores; model: SpecialistModel }> = [
    { key: "recon_analyst", model: "recon_analyst" },
    { key: "exploit_selector", model: "exploit_selector" },
    { key: "evasion_optimizer", model: "evasion_optimizer" },
    { key: "cognitive_core", model: "cognitive_core" },
  ];

  for (const { key, model } of models) {
    recordScenarioResult({
      model,
      scenarioId: `${prefix}-${pipelineId}-${key}`,
      passed: passed[key],
      score: scores[key],
      maxScore: 100,
    });
  }

  // Collect training examples from successful exploits
  let trainingExamplesCollected = 0;

  if (metrics.successfulExploits.length > 0) {
    const exploitExamples: TrainingExample[] = metrics.successfulExploits.map((exp) => ({
      id: `te-${prefix}-${pipelineId}-exploit-${exp.id || Date.now()}`,
      model: "exploit_selector" as SpecialistModel,
      timestamp: Date.now(),
      source: "live_engagement" as const,
      sourceId: pipelineId,
      quality: "high" as const,
      qualityScore: 0.9,
      messages: [
        { role: "system" as const, content: "You are an exploit selection specialist. Given a vulnerability, select the optimal exploitation technique." },
        { role: "user" as const, content: `Target: ${exp.target}\nVulnerability: ${exp.vulnTitle}\nTool: ${exp.tool}` },
        { role: "assistant" as const, content: `Technique: ${exp.technique}\nCommand: ${exp.command}\nResult: ${exp.rawEvidence || "successful exploitation"}` },
      ],
      metadata: {
        engagementId: pipelineId,
        objectiveCompleted: true,
        decisionOutcome: "success" as const,
        mitreAttackTechniques: exp.technique ? [exp.technique] : [],
      },
    }));
    recordTrainingData("exploit_selector", exploitExamples);
    trainingExamplesCollected += exploitExamples.length;
  }

  // Collect training examples from recon observations
  if (metrics.reconObservations.length > 0) {
    const reconExamples: TrainingExample[] = metrics.reconObservations.map((obs) => ({
      id: `te-${prefix}-${pipelineId}-recon-${obs.source}-${Date.now()}`,
      model: "recon_analyst" as SpecialistModel,
      timestamp: Date.now(),
      source: "live_engagement" as const,
      sourceId: pipelineId,
      quality: "medium" as const,
      qualityScore: 0.7,
      messages: [
        { role: "system" as const, content: "You are a reconnaissance analyst. Analyze target infrastructure and identify assets." },
        { role: "user" as const, content: `Domain: ${metrics.domain}\nSource: ${obs.source}\nAsset Type: ${obs.assetType}` },
        { role: "assistant" as const, content: `Found ${obs.findings || 0} findings via ${obs.source} for ${obs.name || metrics.domain}` },
      ],
      metadata: {
        engagementId: pipelineId,
        objectiveCompleted: true,
        decisionOutcome: "success" as const,
      },
    }));
    recordTrainingData("recon_analyst", reconExamples);
    trainingExamplesCollected += reconExamples.length;
  }

  // Calculate average score, excluding N/A categories (cloud/supply_chain with 0 assets)
  // This prevents training lab targets (which have no cloud/supply chain assets) from being
  // penalized by irrelevant 0-score categories
  const applicableScores = Object.entries(scores).filter(([key, _value]) => {
    // Cloud and supply chain are N/A if no relevant assets were found
    if (key === 'cloud_assessor' && metrics.cloudAssetsFound === 0 && metrics.storageAssetsFound === 0 && metrics.containerAssetsFound === 0 && metrics.identityAssetsFound === 0) return false;
    if (key === 'supply_chain_analyst' && metrics.repoExposuresFound === 0 && metrics.platformAssetsFound === 0 && metrics.technologiesDetected === 0) return false;
    return true;
  });
  const scoreEntries = Object.entries(scores);
  const avgScore = applicableScores.length > 0
    ? Math.round(applicableScores.reduce((s, [, v]) => s + v, 0) / applicableScores.length)
    : Math.round(scoreEntries.reduce((s, [, v]) => s + v, 0) / scoreEntries.length);
  const passedCount = Object.values(passed).filter(Boolean).length;

  const summary = `${scoreEntries.length} specialist models scored (avg ${avgScore}/100, ${passedCount} passed). Training examples: ${trainingExamplesCollected}`;

  return {
    scores,
    passed,
    trainingExamplesCollected,
    modelsScored: scoreEntries.length,
    summary,
  };
}

// ─── Metric Extractors ─────────────────────────────────────────────────────

/**
 * Extract PipelineMetrics from an engagement orchestrator state object.
 */
export function extractEngagementMetrics(
  engagementId: number,
  state: any,
): PipelineMetrics {
  const assets = state.assets || [];
  const stats = state.stats || {};
  const evasionState = (state as any).evasionState;
  const owaspCoverage = (state as any).owaspCoverage;

  // Classify assets into enterprise categories
  let cloudCount = 0, repoCount = 0, platformCount = 0, containerCount = 0;
  let storageCount = 0, identityCount = 0, networkCount = 0;

  for (const asset of assets) {
    const techs = asset.technologies || asset.techStack || [];
    const hostname = asset.hostname || asset.ip || "";
    const categories = classifyAssetCategory(hostname, techs);
    if (categories.includes("cloud")) cloudCount++;
    if (categories.includes("repository")) repoCount++;
    if (categories.includes("platform")) platformCount++;
    if (categories.includes("container")) containerCount++;
    if (categories.includes("storage")) storageCount++;
    if (categories.includes("identity")) identityCount++;
  }

  // Count ports with identified (non-unknown) services
  const servicesIdentified = assets.reduce((count: number, a: any) => {
    return count + (a.ports || []).filter((p: any) => p.service && p.service !== "unknown").length;
  }, 0);

  return {
    pipelineType: "engagement",
    pipelineId: engagementId,
    domain: state.targetDomain || state.target,
    assetsDiscovered: assets.length,
    subdomainsFound: stats.subdomainsFound || 0,
    portsFound: stats.portsFound || 0,
    servicesIdentified,
    technologiesDetected: new Set(assets.flatMap((a: any) => a.technologies || [])).size,
    totalVulns: stats.vulnsFound || 0,
    confirmedVulns: (stats as any).verifiedVulns || 0,
    potentialVulns: (stats.vulnsFound || 0) - ((stats as any).verifiedVulns || 0),
    criticalVulns: (stats as any).criticalVulns || 0,
    highVulns: (stats as any).highVulns || 0,
    mediumVulns: (stats as any).mediumVulns || 0,
    lowVulns: (stats as any).lowVulns || 0,
    infoVulns: (stats as any).infoVulns || 0,
    uniqueCVEs: (stats as any).uniqueCVEs || 0,
    kevMatches: (stats as any).kevMatches || 0,
    exploitsAttempted: stats.exploitsAttempted || 0,
    exploitsSucceeded: stats.exploitsSucceeded || 0,
    verifiedVulns: (stats as any).verifiedVulns || 0,
    nucleiVerifiedExploits: (stats as any).nucleiVerifiedExploits || 0,
    wafDetected: !!(stats as any).wafDetected,
    wafBypassed: !!(stats as any).wafBypassed,
    evasionEscalations: evasionState?.escalationHistory?.length || 0,
    scanBlocked: evasionState?.currentLevel > 1,
    scanRecovered: (evasionState?.escalationHistory?.length || 0) > 0,
    owaspCategoriesTested: owaspCoverage?.tested || 0,
    owaspCategoriesTotal: owaspCoverage?.total || 25,
    ptesPhasesCovered: state.log?.filter((l: any) => l.type === "phase_complete").length || 0,
    ptesPhasesTotal: 7,
    cloudAssetsFound: cloudCount,
    repoExposuresFound: repoCount,
    platformAssetsFound: platformCount,
    containerAssetsFound: containerCount,
    storageAssetsFound: storageCount,
    identityAssetsFound: identityCount,
    networkInfraFound: networkCount,
    falsePositiveRate: 0,
    connectorSuccessRate: 1,
    scanDurationMs: Date.now() - (state.startedAt || Date.now()),
    successfulExploits: assets.flatMap((a: any) =>
      (a.exploitAttempts || []).filter((e: any) => e.succeeded)
    ),
    reconObservations: [],
  };
}

/**
 * Extract PipelineMetrics from a DI scanner pipeline result.
 */
export function extractDIScanMetrics(
  scanId: number,
  domain: string,
  result: any,
  durationMs: number,
): PipelineMetrics {
  const assets = result.assets || [];
  const passiveRecon = result.passiveRecon;

  // Classify assets into enterprise categories
  let cloudCount = 0, repoCount = 0, platformCount = 0, containerCount = 0;
  let storageCount = 0, identityCount = 0, networkCount = 0;

  for (const analysis of assets) {
    const asset = analysis.asset || analysis;
    const techs = asset.technologies || [];
    const hostname = asset.hostname || "";
    const categories = classifyAssetCategory(hostname, techs);
    if (categories.includes("cloud")) cloudCount++;
    if (categories.includes("repository")) repoCount++;
    if (categories.includes("platform")) platformCount++;
    if (categories.includes("container")) containerCount++;
    if (categories.includes("storage")) storageCount++;
    if (categories.includes("identity")) identityCount++;
  }

  // Count findings by severity
  let criticalVulns = 0, highVulns = 0, mediumVulns = 0, lowVulns = 0, infoVulns = 0;
  let confirmedVulns = 0;
  const allFindings: any[] = [];

  for (const analysis of assets) {
    const findings = analysis.findings || [];
    for (const f of findings) {
      allFindings.push(f);
      const sev = (f.severity || "info").toLowerCase();
      if (sev === "critical") criticalVulns++;
      else if (sev === "high") highVulns++;
      else if (sev === "medium") mediumVulns++;
      else if (sev === "low") lowVulns++;
      else infoVulns++;
      if (f.confidence === "confirmed" || f.verified) confirmedVulns++;
    }
  }

  // Count unique CVEs
  const cveSet = new Set<string>();
  for (const f of allFindings) {
    if (f.cve) cveSet.add(f.cve);
    if (f.cves) for (const c of f.cves) cveSet.add(c);
  }

  // Count ports from passive recon
  let portsFound = 0;
  let servicesIdentified = 0;
  if (passiveRecon?.allObservations) {
    const portSet = new Set<string>();
    for (const obs of passiveRecon.allObservations) {
      const evidence = obs.evidence as any;
      if (evidence?.port && obs.ip) {
        portSet.add(`${obs.ip}:${evidence.port}`);
        if (evidence.product || evidence.service) servicesIdentified++;
      }
    }
    portsFound = portSet.size;
  }

  // Count subdomains
  const subdomains = passiveRecon?.allObservations?.filter(
    (o: any) => o.assetType === "subdomain"
  ) || [];

  // Count technologies
  const techSet = new Set<string>();
  for (const analysis of assets) {
    const techs = (analysis.asset || analysis).technologies || [];
    for (const t of techs) techSet.add(t);
  }

  // Connector success rate
  const connectorResults = passiveRecon?.connectorResults || [];
  const connectorSuccess = connectorResults.filter(
    (r: any) => r.observations?.length > 0
  ).length;
  const connectorTotal = connectorResults.length || 1;

  // KEV matches
  const kevMatches = result.kevEnrichment?.kevMatchCount || 0;

  // Build recon observations for training data
  const reconObservations = connectorResults
    .filter((r: any) => r.observations?.length > 0)
    .map((r: any) => ({
      source: r.connector || r.source || "unknown",
      assetType: "mixed",
      name: domain,
      findings: r.observations?.length || 0,
    }));

  return {
    pipelineType: "di_scan",
    pipelineId: scanId,
    domain,
    assetsDiscovered: result.totalAssets || assets.length,
    subdomainsFound: subdomains.length,
    portsFound,
    servicesIdentified,
    technologiesDetected: techSet.size,
    totalVulns: result.totalFindings || allFindings.length,
    confirmedVulns,
    potentialVulns: allFindings.length - confirmedVulns,
    criticalVulns,
    highVulns,
    mediumVulns,
    lowVulns,
    infoVulns,
    uniqueCVEs: cveSet.size,
    kevMatches,
    exploitsAttempted: 0,
    exploitsSucceeded: 0,
    verifiedVulns: confirmedVulns,
    nucleiVerifiedExploits: 0, // DI scans don't run exploits
    wafDetected: !!(result.wafNgfwAssessment?.wafDetected),
    wafBypassed: false,
    evasionEscalations: 0,
    scanBlocked: false,
    scanRecovered: false,
    owaspCategoriesTested: 0,
    owaspCategoriesTotal: 25,
    ptesPhasesCovered: 3, // DI scans cover: recon, scanning, analysis
    ptesPhasesTotal: 7,
    cloudAssetsFound: cloudCount,
    repoExposuresFound: repoCount,
    platformAssetsFound: platformCount,
    containerAssetsFound: containerCount,
    storageAssetsFound: storageCount,
    identityAssetsFound: identityCount,
    networkInfraFound: networkCount,
    falsePositiveRate: 0,
    connectorSuccessRate: connectorSuccess / connectorTotal,
    scanDurationMs: durationMs,
    successfulExploits: [],
    reconObservations,
  };
}
