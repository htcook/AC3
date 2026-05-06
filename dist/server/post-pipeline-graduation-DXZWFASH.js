import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-pipeline-graduation.ts
function classifyAssetCategory(hostname, technologies) {
  const categories = [];
  const lower = hostname.toLowerCase();
  const techLower = technologies.map((t) => t.toLowerCase());
  const all = [lower, ...techLower].join(" ");
  if (CLOUD_INDICATORS.some((i) => all.includes(i))) categories.push("cloud");
  if (REPO_INDICATORS.some((i) => all.includes(i))) categories.push("repository");
  if (PLATFORM_INDICATORS.some((i) => all.includes(i))) categories.push("platform");
  if (CONTAINER_INDICATORS.some((i) => all.includes(i))) categories.push("container");
  if (STORAGE_INDICATORS.some((i) => all.includes(i))) categories.push("storage");
  if (IDENTITY_INDICATORS.some((i) => all.includes(i))) categories.push("identity");
  if (categories.length === 0) categories.push("web_application");
  return categories;
}
function scoreReconAnalyst(m) {
  const assetScore = Math.min(30, m.assetsDiscovered * 5 + m.subdomainsFound * 2);
  const portScore = Math.min(25, m.portsFound * 3);
  const serviceScore = Math.min(15, m.servicesIdentified * 4);
  const techScore = Math.min(10, m.technologiesDetected * 2);
  const kevBonus = Math.min(10, m.kevMatches * 5);
  const cveBonus = Math.min(5, m.uniqueCVEs > 0 ? 5 : 0);
  const vulnDiscoveryBonus = Math.min(5, m.totalVulns > 0 ? Math.min(5, Math.ceil(m.totalVulns / 4)) : 0);
  return Math.min(100, assetScore + portScore + serviceScore + techScore + kevBonus + cveBonus + vulnDiscoveryBonus);
}
function scoreExploitSelector(m) {
  if (m.pipelineType === "di_scan" || m.pipelineType === "scheduled_scan") {
    const vulnAccuracy = m.totalVulns > 0 ? m.confirmedVulns / m.totalVulns * 50 : 0;
    const severityDepth = Math.min(30, m.criticalVulns * 10 + m.highVulns * 5 + m.mediumVulns * 2);
    const kevScore = Math.min(20, m.kevMatches * 10);
    return Math.min(100, Math.round(vulnAccuracy + severityDepth + kevScore));
  }
  const successRate = m.exploitsAttempted > 0 ? m.exploitsSucceeded / m.exploitsAttempted * 35 : 0;
  const attemptCredit = Math.min(15, m.exploitsAttempted * 5);
  const evidenceRate = m.totalVulns > 0 ? m.verifiedVulns / m.totalVulns * 20 : 0;
  const volumeBonus = Math.min(15, m.totalVulns > 10 ? 15 : Math.ceil(m.totalVulns * 1.5));
  const severityBonus = Math.min(15, m.criticalVulns * 5 + m.highVulns * 3 + m.mediumVulns * 1);
  const nucleiBonus = Math.min(10, (m.nucleiVerifiedExploits || 0) * 5);
  return Math.min(100, Math.round(successRate + attemptCredit + evidenceRate + volumeBonus + severityBonus + nucleiBonus));
}
function scoreEvasionOptimizer(m) {
  if (!m.wafDetected) return 90;
  if (m.scanBlocked && !m.scanRecovered) return 30;
  if (m.scanBlocked && m.scanRecovered) return 70;
  if (m.wafBypassed) return 95;
  return 80;
}
function scoreCognitiveCore(m) {
  const coverageScore = m.owaspCategoriesTotal > 0 ? Math.round(m.owaspCategoriesTested / m.owaspCategoriesTotal * 35) : 20;
  const evidenceRate = m.totalVulns > 0 ? Math.round(m.confirmedVulns / m.totalVulns * 25) : 0;
  const fpPenalty = Math.round(m.falsePositiveRate * 20);
  const vulnBaseline = m.totalVulns > 0 ? 15 : 0;
  const ptesBonus = m.ptesPhasesTotal > 0 ? Math.min(15, Math.round(m.ptesPhasesCovered / m.ptesPhasesTotal * 15)) : 0;
  const corroborationBonus = m.confirmedVulns > 0 && m.totalVulns > m.confirmedVulns ? 5 : 0;
  const baseScore = coverageScore + evidenceRate + vulnBaseline + ptesBonus + corroborationBonus;
  return Math.min(100, Math.max(0, baseScore - fpPenalty));
}
function scoreCloudAssessor(m) {
  const cloudScore = Math.min(40, m.cloudAssetsFound * 10);
  const storageScore = Math.min(20, m.storageAssetsFound * 10);
  const containerScore = Math.min(20, m.containerAssetsFound * 10);
  const identityScore = Math.min(20, m.identityAssetsFound * 10);
  return Math.min(100, cloudScore + storageScore + containerScore + identityScore);
}
function scoreSupplyChainAnalyst(m) {
  const repoScore = Math.min(40, m.repoExposuresFound * 15);
  const platformScore = Math.min(30, m.platformAssetsFound * 10);
  const techDepthScore = Math.min(30, m.technologiesDetected * 3);
  return Math.min(100, repoScore + platformScore + techDepthScore);
}
async function runPostPipelineGraduation(metrics) {
  const { recordScenarioResult, recordTrainingData } = await import("./graduation-lab-bridge-WEKEGIOD.js");
  let methodologyBonus = 0;
  let methodologyRationale = "";
  try {
    const { computeMethodologyGraduationBonus } = await import("./methodology-db-persistence-5EHY4WIH.js");
    const engagementId = metrics.pipelineType === "engagement" ? Number(metrics.pipelineId) : void 0;
    const bonusResult = await computeMethodologyGraduationBonus(engagementId);
    methodologyBonus = bonusResult.bonus;
    methodologyRationale = bonusResult.rationale;
  } catch {
  }
  const baseExploitScore = scoreExploitSelector(metrics);
  const scores = {
    recon_analyst: scoreReconAnalyst(metrics),
    exploit_selector: Math.min(100, baseExploitScore + methodologyBonus),
    evasion_optimizer: scoreEvasionOptimizer(metrics),
    cognitive_core: scoreCognitiveCore(metrics),
    cloud_assessor: scoreCloudAssessor(metrics),
    supply_chain_analyst: scoreSupplyChainAnalyst(metrics)
  };
  const passed = {
    recon_analyst: scores.recon_analyst >= 30,
    exploit_selector: scores.exploit_selector >= 20,
    evasion_optimizer: scores.evasion_optimizer >= 50,
    cognitive_core: scores.cognitive_core >= 40,
    cloud_assessor: scores.cloud_assessor >= 10,
    supply_chain_analyst: scores.supply_chain_analyst >= 10
  };
  const pipelineId = String(metrics.pipelineId);
  const prefix = metrics.pipelineType === "engagement" ? "eng" : "di";
  const models = [
    { key: "recon_analyst", model: "recon_analyst" },
    { key: "exploit_selector", model: "exploit_selector" },
    { key: "evasion_optimizer", model: "evasion_optimizer" },
    { key: "cognitive_core", model: "cognitive_core" }
  ];
  for (const { key, model } of models) {
    recordScenarioResult({
      model,
      scenarioId: `${prefix}-${pipelineId}-${key}`,
      passed: passed[key],
      score: scores[key],
      maxScore: 100
    });
  }
  let trainingExamplesCollected = 0;
  if (metrics.successfulExploits.length > 0) {
    const exploitExamples = metrics.successfulExploits.map((exp) => ({
      id: `te-${prefix}-${pipelineId}-exploit-${exp.id || Date.now()}`,
      model: "exploit_selector",
      timestamp: Date.now(),
      source: "live_engagement",
      sourceId: pipelineId,
      quality: "high",
      qualityScore: 0.9,
      messages: [
        { role: "system", content: "You are an exploit selection specialist. Given a vulnerability, select the optimal exploitation technique." },
        { role: "user", content: `Target: ${exp.target}
Vulnerability: ${exp.vulnTitle}
Tool: ${exp.tool}` },
        { role: "assistant", content: `Technique: ${exp.technique}
Command: ${exp.command}
Result: ${exp.rawEvidence || "successful exploitation"}` }
      ],
      metadata: {
        engagementId: pipelineId,
        objectiveCompleted: true,
        decisionOutcome: "success",
        mitreAttackTechniques: exp.technique ? [exp.technique] : []
      }
    }));
    recordTrainingData("exploit_selector", exploitExamples);
    trainingExamplesCollected += exploitExamples.length;
  }
  if (metrics.reconObservations.length > 0) {
    const reconExamples = metrics.reconObservations.map((obs) => ({
      id: `te-${prefix}-${pipelineId}-recon-${obs.source}-${Date.now()}`,
      model: "recon_analyst",
      timestamp: Date.now(),
      source: "live_engagement",
      sourceId: pipelineId,
      quality: "medium",
      qualityScore: 0.7,
      messages: [
        { role: "system", content: "You are a reconnaissance analyst. Analyze target infrastructure and identify assets." },
        { role: "user", content: `Domain: ${metrics.domain}
Source: ${obs.source}
Asset Type: ${obs.assetType}` },
        { role: "assistant", content: `Found ${obs.findings || 0} findings via ${obs.source} for ${obs.name || metrics.domain}` }
      ],
      metadata: {
        engagementId: pipelineId,
        objectiveCompleted: true,
        decisionOutcome: "success"
      }
    }));
    recordTrainingData("recon_analyst", reconExamples);
    trainingExamplesCollected += reconExamples.length;
  }
  const applicableScores = Object.entries(scores).filter(([key, _value]) => {
    if (key === "cloud_assessor" && metrics.cloudAssetsFound === 0 && metrics.storageAssetsFound === 0 && metrics.containerAssetsFound === 0 && metrics.identityAssetsFound === 0) return false;
    if (key === "supply_chain_analyst" && metrics.repoExposuresFound === 0 && metrics.platformAssetsFound === 0 && metrics.technologiesDetected === 0) return false;
    return true;
  });
  const scoreEntries = Object.entries(scores);
  const avgScore = applicableScores.length > 0 ? Math.round(applicableScores.reduce((s, [, v]) => s + v, 0) / applicableScores.length) : Math.round(scoreEntries.reduce((s, [, v]) => s + v, 0) / scoreEntries.length);
  const passedCount = Object.values(passed).filter(Boolean).length;
  const methodologyNote = methodologyRationale ? ` | ${methodologyRationale}` : "";
  const summary = `${scoreEntries.length} specialist models scored (avg ${avgScore}/100, ${passedCount} passed). Training examples: ${trainingExamplesCollected}${methodologyNote}`;
  return {
    scores,
    passed,
    trainingExamplesCollected,
    modelsScored: scoreEntries.length,
    summary
  };
}
function extractEngagementMetrics(engagementId, state) {
  const assets = state.assets || [];
  const stats = state.stats || {};
  const evasionState = state.evasionState;
  const owaspCoverage = state.owaspCoverage;
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
  const servicesIdentified = assets.reduce((count, a) => {
    return count + (a.ports || []).filter((p) => p.service && p.service !== "unknown").length;
  }, 0);
  return {
    pipelineType: "engagement",
    pipelineId: engagementId,
    domain: state.targetDomain || state.target,
    assetsDiscovered: assets.length,
    subdomainsFound: stats.subdomainsFound || 0,
    portsFound: stats.portsFound || 0,
    servicesIdentified,
    technologiesDetected: new Set(assets.flatMap((a) => a.technologies || [])).size,
    totalVulns: stats.vulnsFound || 0,
    confirmedVulns: stats.verifiedVulns || 0,
    potentialVulns: (stats.vulnsFound || 0) - (stats.verifiedVulns || 0),
    criticalVulns: stats.criticalVulns || 0,
    highVulns: stats.highVulns || 0,
    mediumVulns: stats.mediumVulns || 0,
    lowVulns: stats.lowVulns || 0,
    infoVulns: stats.infoVulns || 0,
    uniqueCVEs: stats.uniqueCVEs || 0,
    kevMatches: stats.kevMatches || 0,
    exploitsAttempted: stats.exploitsAttempted || 0,
    exploitsSucceeded: stats.exploitsSucceeded || 0,
    verifiedVulns: stats.verifiedVulns || 0,
    nucleiVerifiedExploits: stats.nucleiVerifiedExploits || 0,
    wafDetected: !!stats.wafDetected,
    wafBypassed: !!stats.wafBypassed,
    evasionEscalations: evasionState?.escalationHistory?.length || 0,
    scanBlocked: evasionState?.currentLevel > 1,
    scanRecovered: (evasionState?.escalationHistory?.length || 0) > 0,
    owaspCategoriesTested: owaspCoverage?.tested || 0,
    owaspCategoriesTotal: owaspCoverage?.total || 25,
    ptesPhasesCovered: state.log?.filter((l) => l.type === "phase_complete").length || 0,
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
    successfulExploits: assets.flatMap(
      (a) => (a.exploitAttempts || []).filter((e) => e.succeeded)
    ),
    reconObservations: []
  };
}
function extractDIScanMetrics(scanId, domain, result, durationMs) {
  const assets = result.assets || [];
  const passiveRecon = result.passiveRecon;
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
  let criticalVulns = 0, highVulns = 0, mediumVulns = 0, lowVulns = 0, infoVulns = 0;
  let confirmedVulns = 0;
  const allFindings = [];
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
  const cveSet = /* @__PURE__ */ new Set();
  for (const f of allFindings) {
    if (f.cve) cveSet.add(f.cve);
    if (f.cves) for (const c of f.cves) cveSet.add(c);
  }
  let portsFound = 0;
  let servicesIdentified = 0;
  if (passiveRecon?.allObservations) {
    const portSet = /* @__PURE__ */ new Set();
    for (const obs of passiveRecon.allObservations) {
      const evidence = obs.evidence;
      if (evidence?.port && obs.ip) {
        portSet.add(`${obs.ip}:${evidence.port}`);
        if (evidence.product || evidence.service) servicesIdentified++;
      }
    }
    portsFound = portSet.size;
  }
  const subdomains = passiveRecon?.allObservations?.filter(
    (o) => o.assetType === "subdomain"
  ) || [];
  const techSet = /* @__PURE__ */ new Set();
  for (const analysis of assets) {
    const techs = (analysis.asset || analysis).technologies || [];
    for (const t of techs) techSet.add(t);
  }
  const connectorResults = passiveRecon?.connectorResults || [];
  const connectorSuccess = connectorResults.filter(
    (r) => r.observations?.length > 0
  ).length;
  const connectorTotal = connectorResults.length || 1;
  const kevMatches = result.kevEnrichment?.kevMatchCount || 0;
  const reconObservations = connectorResults.filter((r) => r.observations?.length > 0).map((r) => ({
    source: r.connector || r.source || "unknown",
    assetType: "mixed",
    name: domain,
    findings: r.observations?.length || 0
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
    nucleiVerifiedExploits: 0,
    // DI scans don't run exploits
    wafDetected: !!result.wafNgfwAssessment?.wafDetected,
    wafBypassed: false,
    evasionEscalations: 0,
    scanBlocked: false,
    scanRecovered: false,
    owaspCategoriesTested: 0,
    owaspCategoriesTotal: 25,
    ptesPhasesCovered: 3,
    // DI scans cover: recon, scanning, analysis
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
    reconObservations
  };
}
var CLOUD_INDICATORS, REPO_INDICATORS, PLATFORM_INDICATORS, CONTAINER_INDICATORS, STORAGE_INDICATORS, IDENTITY_INDICATORS;
var init_post_pipeline_graduation = __esm({
  "server/lib/post-pipeline-graduation.ts"() {
    CLOUD_INDICATORS = [
      "aws",
      "amazon",
      "s3",
      "ec2",
      "lambda",
      "cloudfront",
      "elasticbeanstalk",
      "azure",
      "microsoft",
      "blob.core",
      "azurewebsites",
      "gcp",
      "google",
      "googleapis",
      "appspot",
      "firebase",
      "digitalocean",
      "linode",
      "vultr",
      "heroku",
      "netlify",
      "vercel",
      "cloudflare",
      "fastly",
      "akamai"
    ];
    REPO_INDICATORS = [
      "github",
      "gitlab",
      "bitbucket",
      "codecommit",
      "gitea",
      "gogs",
      ".git",
      "repository",
      "repo"
    ];
    PLATFORM_INDICATORS = [
      "jira",
      "confluence",
      "atlassian",
      "slack",
      "teams",
      "zoom",
      "salesforce",
      "hubspot",
      "zendesk",
      "freshdesk",
      "servicenow",
      "okta",
      "auth0",
      "onelogin",
      "ping"
    ];
    CONTAINER_INDICATORS = [
      "docker",
      "kubernetes",
      "k8s",
      "ecs",
      "fargate",
      "rancher",
      "openshift",
      "portainer",
      "registry"
    ];
    STORAGE_INDICATORS = [
      "s3",
      "blob",
      "storage",
      "minio",
      "nfs",
      "ceph",
      "gluster",
      "backblaze",
      "wasabi"
    ];
    IDENTITY_INDICATORS = [
      "sso",
      "ldap",
      "active-directory",
      "adfs",
      "oauth",
      "saml",
      "keycloak",
      "okta",
      "auth0",
      "cognito"
    ];
  }
});
init_post_pipeline_graduation();
export {
  extractDIScanMetrics,
  extractEngagementMetrics,
  runPostPipelineGraduation
};
