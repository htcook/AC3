import "./chunk-KFQGP6VL.js";

// server/lib/dast-carver-integration.ts
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}
var SEVERITY_VULN_BOOST = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0.3,
  info: 0.1
};
var SEVERITY_LIKELIHOOD_BOOST = {
  critical: 0.4,
  high: 0.25,
  medium: 0.1,
  low: 0.03,
  info: 0
};
var CATEGORY_CARVER_MAP = {
  // SSH audit categories
  "weak_algorithms": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 0.8 }
  ],
  "cve": [
    { dimension: "vulnerability", boost: 2.5 },
    { dimension: "accessibility", boost: 1 },
    { dimension: "recognizability", boost: 0.5 }
  ],
  "auth_methods": [
    { dimension: "accessibility", boost: 1.5 },
    { dimension: "criticality", boost: 0.5 }
  ],
  "key_exchange": [
    { dimension: "vulnerability", boost: 1 },
    { dimension: "recuperability", boost: 0.5 }
  ],
  "protocol": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recognizability", boost: 0.8 }
  ],
  // FTP audit categories
  "anonymous_access": [
    { dimension: "accessibility", boost: 3 },
    { dimension: "effect", boost: 2 },
    { dimension: "criticality", boost: 1 }
  ],
  "authentication": [
    { dimension: "accessibility", boost: 2 },
    { dimension: "vulnerability", boost: 1.5 }
  ],
  "encryption": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 1 }
  ],
  "bounce_attack": [
    { dimension: "effect", boost: 2 },
    { dimension: "accessibility", boost: 1.5 }
  ],
  "directory_traversal": [
    { dimension: "effect", boost: 2.5 },
    { dimension: "accessibility", boost: 1.5 }
  ],
  // SMTP audit categories
  "open_relay": [
    { dimension: "accessibility", boost: 3 },
    { dimension: "effect", boost: 2.5 },
    { dimension: "criticality", boost: 1.5 }
  ],
  "spf_dkim_dmarc": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "effect", boost: 1 }
  ],
  "tls_security": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 0.8 }
  ],
  "user_enumeration": [
    { dimension: "accessibility", boost: 2 },
    { dimension: "recognizability", boost: 1.5 }
  ],
  "banner_disclosure": [
    { dimension: "recognizability", boost: 2 },
    { dimension: "vulnerability", boost: 0.5 }
  ],
  // SNMP audit categories
  "default_community": [
    { dimension: "accessibility", boost: 3 },
    { dimension: "criticality", boost: 1.5 },
    { dimension: "effect", boost: 2 }
  ],
  "snmp_version": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 0.8 }
  ],
  "information_disclosure": [
    { dimension: "recognizability", boost: 2 },
    { dimension: "effect", boost: 1 }
  ],
  "write_access": [
    { dimension: "criticality", boost: 2.5 },
    { dimension: "effect", boost: 2.5 },
    { dimension: "accessibility", boost: 2 }
  ],
  // RDP audit categories
  "nla_disabled": [
    { dimension: "accessibility", boost: 2 },
    { dimension: "vulnerability", boost: 1.5 }
  ],
  "bluekeep": [
    { dimension: "vulnerability", boost: 3 },
    { dimension: "accessibility", boost: 2.5 },
    { dimension: "effect", boost: 2 },
    { dimension: "criticality", boost: 1.5 }
  ],
  "rdp_encryption": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 1 }
  ],
  "session_security": [
    { dimension: "vulnerability", boost: 1 },
    { dimension: "effect", boost: 0.8 }
  ],
  // DAST web scanner categories
  "xss": [
    { dimension: "vulnerability", boost: 2 },
    { dimension: "effect", boost: 1.5 }
  ],
  "sql_injection": [
    { dimension: "vulnerability", boost: 3 },
    { dimension: "effect", boost: 2.5 },
    { dimension: "criticality", boost: 1.5 }
  ],
  "command_injection": [
    { dimension: "vulnerability", boost: 3 },
    { dimension: "effect", boost: 3 },
    { dimension: "criticality", boost: 2 }
  ],
  "file_inclusion": [
    { dimension: "vulnerability", boost: 2.5 },
    { dimension: "effect", boost: 2 }
  ],
  "server_misconfiguration": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recognizability", boost: 1 }
  ],
  "outdated_software": [
    { dimension: "vulnerability", boost: 2 },
    { dimension: "recognizability", boost: 1.5 }
  ]
};
var SERVICE_SHOCK_MAP = {
  ssh: [
    { dimension: "cascadingEffects", boost: 2 },
    // lateral movement
    { dimension: "operationalImpact", boost: 1.5 },
    // remote access disruption
    { dimension: "knowledge", boost: 1 }
    // well-known attack surface
  ],
  ftp: [
    { dimension: "scope", boost: 1.5 },
    // data exfiltration
    { dimension: "operationalImpact", boost: 1 },
    // file transfer disruption
    { dimension: "handling", boost: 0.8 }
    // often poorly monitored
  ],
  smtp: [
    { dimension: "scope", boost: 2.5 },
    // spam/phishing blast radius
    { dimension: "handling", boost: 1.5 },
    // reputation damage hard to fix
    { dimension: "cascadingEffects", boost: 1 }
    // phishing → credential theft
  ],
  snmp: [
    { dimension: "scope", boost: 2 },
    // network-wide recon
    { dimension: "cascadingEffects", boost: 2 },
    // config changes cascade
    { dimension: "handling", boost: 1.5 },
    // often unmonitored
    { dimension: "knowledge", boost: 1 }
    // well-documented attacks
  ],
  rdp: [
    { dimension: "cascadingEffects", boost: 2.5 },
    // lateral movement + persistence
    { dimension: "operationalImpact", boost: 2 },
    // full desktop access
    { dimension: "scope", boost: 1.5 },
    // often internet-facing
    { dimension: "knowledge", boost: 1.5 }
    // BlueKeep, etc.
  ],
  http: [
    { dimension: "scope", boost: 1.5 },
    // public-facing
    { dimension: "operationalImpact", boost: 1 },
    // web service disruption
    { dimension: "knowledge", boost: 0.5 }
    // many known web vulns
  ],
  https: [
    { dimension: "scope", boost: 1.5 },
    { dimension: "operationalImpact", boost: 1 },
    { dimension: "knowledge", boost: 0.5 }
  ]
};
function scoreServiceAudit(result) {
  const carverBoosts = {
    criticality: 0,
    accessibility: 0,
    recuperability: 0,
    vulnerability: 0,
    effect: 0,
    recognizability: 0
  };
  const shockBoosts = {
    scope: 0,
    handling: 0,
    operationalImpact: 0,
    cascadingEffects: 0,
    knowledge: 0
  };
  let likelihoodBoost = 0;
  const postureFindings = [];
  if (!result.findings || result.findings.length === 0) {
    return { carverBoosts, shockBoosts, likelihoodBoost, postureFindings };
  }
  const serviceShock = SERVICE_SHOCK_MAP[result.service] || SERVICE_SHOCK_MAP["http"] || [];
  for (const mapping of serviceShock) {
    shockBoosts[mapping.dimension] = Math.max(
      shockBoosts[mapping.dimension] || 0,
      mapping.boost * 0.5
      // Base service exposure boost (half weight)
    );
  }
  for (const finding of result.findings) {
    const severity = (finding.severity || "info").toLowerCase();
    const category = (finding.category || "").toLowerCase().replace(/[^a-z_]/g, "_");
    const vulnBoost = SEVERITY_VULN_BOOST[severity] || 0.1;
    carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, vulnBoost);
    likelihoodBoost += SEVERITY_LIKELIHOOD_BOOST[severity] || 0;
    const categoryMappings = CATEGORY_CARVER_MAP[category];
    if (categoryMappings) {
      for (const mapping of categoryMappings) {
        const severityMultiplier = severity === "critical" ? 1 : severity === "high" ? 0.8 : severity === "medium" ? 0.5 : severity === "low" ? 0.25 : 0.1;
        const boost = mapping.boost * severityMultiplier;
        carverBoosts[mapping.dimension] = Math.max(
          carverBoosts[mapping.dimension] || 0,
          boost
        );
      }
    }
    if (finding.cve) {
      carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, 2);
      carverBoosts.recognizability = Math.max(carverBoosts.recognizability, 1.5);
      shockBoosts.knowledge = Math.max(shockBoosts.knowledge, 1.5);
    }
    if (result.findings.length > 0) {
      const serviceShockFindings = SERVICE_SHOCK_MAP[result.service] || [];
      for (const mapping of serviceShockFindings) {
        const findingSeverityMult = severity === "critical" ? 1 : severity === "high" ? 0.7 : severity === "medium" ? 0.4 : 0.15;
        shockBoosts[mapping.dimension] = Math.max(
          shockBoosts[mapping.dimension] || 0,
          mapping.boost * findingSeverityMult
        );
      }
    }
    const severityNum = severity === "critical" ? 9 : severity === "high" ? 7 : severity === "medium" ? 5 : severity === "low" ? 3 : 1;
    postureFindings.push({
      id: `dast-${result.service}-${result.port}-${postureFindings.length}`,
      category: `${result.service}_audit`,
      title: finding.title || `${result.service.toUpperCase()} Finding`,
      severity: severityNum,
      confidence: finding.cve ? 0.95 : 0.8,
      description: finding.description || "",
      evidenceDetail: `${result.host}:${result.port} (${result.service}) \u2014 ${finding.evidence || finding.description || ""}`,
      corroborationTier: finding.cve ? "confirmed" : "probable",
      remediation: finding.recommendation || "",
      source: `${result.service}_audit`
    });
  }
  return { carverBoosts, shockBoosts, likelihoodBoost: clamp(likelihoodBoost, 0, 1), postureFindings };
}
function scoreDastScanner(scannerName, results) {
  const carverBoosts = {
    criticality: 0,
    accessibility: 0,
    recuperability: 0,
    vulnerability: 0,
    effect: 0,
    recognizability: 0
  };
  const shockBoosts = {
    scope: 0,
    handling: 0,
    operationalImpact: 0,
    cascadingEffects: 0,
    knowledge: 0
  };
  let likelihoodBoost = 0;
  const postureFindings = [];
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  for (const result of results) {
    if (!result.findings) continue;
    for (const finding of result.findings) {
      const severity = (finding.severity || "info").toLowerCase();
      if (severity === "critical") criticalCount++;
      else if (severity === "high") highCount++;
      else if (severity === "medium") mediumCount++;
      else if (severity === "low") lowCount++;
      const vulnBoost = SEVERITY_VULN_BOOST[severity] || 0.1;
      carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, vulnBoost);
      likelihoodBoost += SEVERITY_LIKELIHOOD_BOOST[severity] || 0;
      const category = (finding.category || "").toLowerCase().replace(/[^a-z_]/g, "_");
      const categoryMappings = CATEGORY_CARVER_MAP[category];
      if (categoryMappings) {
        const severityMult = severity === "critical" ? 1 : severity === "high" ? 0.8 : severity === "medium" ? 0.5 : 0.25;
        for (const mapping of categoryMappings) {
          carverBoosts[mapping.dimension] = Math.max(
            carverBoosts[mapping.dimension] || 0,
            mapping.boost * severityMult
          );
        }
      }
      if (finding.cve) {
        carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, 2);
        shockBoosts.knowledge = Math.max(shockBoosts.knowledge, 1.5);
      }
      shockBoosts.scope = Math.max(shockBoosts.scope, 1.5);
      if (severity === "critical" || severity === "high") {
        shockBoosts.operationalImpact = Math.max(shockBoosts.operationalImpact, 1.5);
      }
      postureFindings.push({
        id: `dast-${scannerName}-${postureFindings.length}`,
        category: `dast_${scannerName}`,
        title: finding.title || `${scannerName} Finding`,
        severity: severity === "critical" ? 9 : severity === "high" ? 7 : severity === "medium" ? 5 : severity === "low" ? 3 : 1,
        confidence: finding.cve ? 0.9 : 0.75,
        description: finding.description || "",
        evidenceDetail: `${result.host || result.target || "unknown"} \u2014 ${finding.evidence || finding.description || ""}`,
        corroborationTier: finding.cve ? "confirmed" : "possible",
        remediation: finding.recommendation || "",
        source: `dast_${scannerName}`
      });
    }
  }
  const totalFindings = criticalCount + highCount + mediumCount + lowCount;
  const carverImpact = Object.values(carverBoosts).reduce((a, b) => a + b, 0);
  const shockImpact = Object.values(shockBoosts).reduce((a, b) => a + b, 0);
  return {
    carverBoosts,
    shockBoosts,
    likelihoodBoost: clamp(likelihoodBoost, 0, 1),
    postureFindings,
    scannerScore: {
      scanner: scannerName,
      findingCount: totalFindings,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      carverImpact: Math.round(carverImpact * 100) / 100,
      shockImpact: Math.round(shockImpact * 100) / 100
    }
  };
}
function computeDastCarverAdjustment(pipelineResults, hostname = "unknown") {
  const allCarverBoosts = {
    criticality: 0,
    accessibility: 0,
    recuperability: 0,
    vulnerability: 0,
    effect: 0,
    recognizability: 0
  };
  const allShockBoosts = {
    scope: 0,
    handling: 0,
    operationalImpact: 0,
    cascadingEffects: 0,
    knowledge: 0
  };
  let totalLikelihoodBoost = 0;
  const allPostureFindings = [];
  const scannerScores = [];
  const serviceScores = [];
  const serviceAuditTypes = ["ssh", "ftp", "smtp", "snmp", "rdp"];
  for (const sType of serviceAuditTypes) {
    const results = pipelineResults[sType];
    if (!Array.isArray(results) || results.length === 0) continue;
    let scannerCritical = 0, scannerHigh = 0, scannerMedium = 0, scannerLow = 0;
    let scannerCarverTotal = 0, scannerShockTotal = 0;
    for (const result of results) {
      const scored = scoreServiceAudit(result);
      for (const [dim, val] of Object.entries(scored.carverBoosts)) {
        allCarverBoosts[dim] = Math.max(allCarverBoosts[dim] || 0, val);
        scannerCarverTotal += val;
      }
      for (const [dim, val] of Object.entries(scored.shockBoosts)) {
        allShockBoosts[dim] = Math.max(allShockBoosts[dim] || 0, val);
        scannerShockTotal += val;
      }
      totalLikelihoodBoost = Math.max(totalLikelihoodBoost, scored.likelihoodBoost);
      allPostureFindings.push(...scored.postureFindings);
      for (const f of result.findings || []) {
        const sev = (f.severity || "info").toLowerCase();
        if (sev === "critical") scannerCritical++;
        else if (sev === "high") scannerHigh++;
        else if (sev === "medium") scannerMedium++;
        else if (sev === "low") scannerLow++;
      }
      serviceScores.push({
        service: result.service || sType,
        port: result.port || 0,
        host: result.host || hostname,
        vulnerabilityScore: scored.carverBoosts.vulnerability || 0,
        accessibilityScore: scored.carverBoosts.accessibility || 0,
        findings: (result.findings || []).map((f) => f.title || "Unknown")
      });
    }
    scannerScores.push({
      scanner: `${sType}_audit`,
      findingCount: scannerCritical + scannerHigh + scannerMedium + scannerLow,
      criticalCount: scannerCritical,
      highCount: scannerHigh,
      mediumCount: scannerMedium,
      lowCount: scannerLow,
      carverImpact: Math.round(scannerCarverTotal * 100) / 100,
      shockImpact: Math.round(scannerShockTotal * 100) / 100
    });
  }
  const dastTypes = ["nikto", "wapiti", "arachni"];
  for (const dType of dastTypes) {
    const results = pipelineResults[dType];
    if (!Array.isArray(results) || results.length === 0) continue;
    const scored = scoreDastScanner(dType, results);
    for (const [dim, val] of Object.entries(scored.carverBoosts)) {
      allCarverBoosts[dim] = Math.max(allCarverBoosts[dim] || 0, val);
    }
    for (const [dim, val] of Object.entries(scored.shockBoosts)) {
      allShockBoosts[dim] = Math.max(allShockBoosts[dim] || 0, val);
    }
    totalLikelihoodBoost = Math.max(totalLikelihoodBoost, scored.likelihoodBoost);
    allPostureFindings.push(...scored.postureFindings);
    scannerScores.push(scored.scannerScore);
  }
  const totalCarverBoost = Object.values(allCarverBoosts).reduce((a, b) => a + b, 0);
  const totalShockBoost = Object.values(allShockBoosts).reduce((a, b) => a + b, 0);
  const overallScore = clamp(Math.round((totalCarverBoost + totalShockBoost) / 40 * 100), 0, 100);
  const scannersWithResults = scannerScores.filter((s) => s.findingCount > 0).length;
  const confidence = clamp(0.5 + scannersWithResults * 0.1, 0.5, 0.95);
  return {
    carver: {
      criticality: clamp(Math.round(allCarverBoosts.criticality * 100) / 100, 0, 5),
      accessibility: clamp(Math.round(allCarverBoosts.accessibility * 100) / 100, 0, 5),
      recuperability: clamp(Math.round(allCarverBoosts.recuperability * 100) / 100, 0, 5),
      vulnerability: clamp(Math.round(allCarverBoosts.vulnerability * 100) / 100, 0, 5),
      effect: clamp(Math.round(allCarverBoosts.effect * 100) / 100, 0, 5),
      recognizability: clamp(Math.round(allCarverBoosts.recognizability * 100) / 100, 0, 5)
    },
    shock: {
      scope: clamp(Math.round(allShockBoosts.scope * 100) / 100, 0, 5),
      handling: clamp(Math.round(allShockBoosts.handling * 100) / 100, 0, 5),
      operationalImpact: clamp(Math.round(allShockBoosts.operationalImpact * 100) / 100, 0, 5),
      cascadingEffects: clamp(Math.round(allShockBoosts.cascadingEffects * 100) / 100, 0, 5),
      knowledge: clamp(Math.round(allShockBoosts.knowledge * 100) / 100, 0, 5)
    },
    likelihoodBoost: clamp(Math.round(totalLikelihoodBoost * 100) / 100, 0, 1),
    contextAdjustment: {
      exposureBoost: clamp(allCarverBoosts.accessibility * 0.3, 0, 1),
      recognizabilityBoost: clamp(allCarverBoosts.recognizability * 0.3, 0, 1),
      confidenceBoost: clamp((scannersWithResults - 1) * 0.05, 0, 0.3)
    },
    breakdown: {
      scannerScores,
      serviceScores,
      overallDastVulnScore: overallScore,
      assessmentConfidence: confidence
    },
    postureFindings: allPostureFindings
  };
}
function applyDastAdjustments(existingCarver, existingShock, adjustment) {
  return {
    carver: {
      criticality: clamp(existingCarver.criticality + adjustment.carver.criticality, 0, 10),
      accessibility: clamp(existingCarver.accessibility + adjustment.carver.accessibility, 0, 10),
      recuperability: clamp(existingCarver.recuperability + adjustment.carver.recuperability, 0, 10),
      vulnerability: clamp(existingCarver.vulnerability + adjustment.carver.vulnerability, 0, 10),
      effect: clamp(existingCarver.effect + adjustment.carver.effect, 0, 10),
      recognizability: clamp(existingCarver.recognizability + adjustment.carver.recognizability, 0, 10)
    },
    shock: {
      scope: clamp(existingShock.scope + adjustment.shock.scope, 0, 10),
      handling: clamp(existingShock.handling + adjustment.shock.handling, 0, 10),
      operationalImpact: clamp(existingShock.operationalImpact + adjustment.shock.operationalImpact, 0, 10),
      cascadingEffects: clamp(existingShock.cascadingEffects + adjustment.shock.cascadingEffects, 0, 10),
      knowledge: clamp(existingShock.knowledge + adjustment.shock.knowledge, 0, 10)
    }
  };
}
function aggregateDastAdjustments(adjustments) {
  if (adjustments.length === 0) return null;
  if (adjustments.length === 1) return adjustments[0];
  const allFindings = [];
  const seenFindingIds = /* @__PURE__ */ new Set();
  const allScannerScores = [];
  const allServiceScores = [];
  const result = {
    carver: { criticality: 0, accessibility: 0, recuperability: 0, vulnerability: 0, effect: 0, recognizability: 0 },
    shock: { scope: 0, handling: 0, operationalImpact: 0, cascadingEffects: 0, knowledge: 0 },
    likelihoodBoost: 0,
    contextAdjustment: { exposureBoost: 0, recognizabilityBoost: 0, confidenceBoost: 0 },
    breakdown: {
      scannerScores: [],
      serviceScores: [],
      overallDastVulnScore: 0,
      assessmentConfidence: 0
    },
    postureFindings: []
  };
  for (const adj of adjustments) {
    for (const key of Object.keys(result.carver)) {
      result.carver[key] = Math.max(result.carver[key], adj.carver[key]);
    }
    for (const key of Object.keys(result.shock)) {
      result.shock[key] = Math.max(result.shock[key], adj.shock[key]);
    }
    result.likelihoodBoost = Math.max(result.likelihoodBoost, adj.likelihoodBoost);
    result.contextAdjustment.exposureBoost = Math.max(result.contextAdjustment.exposureBoost, adj.contextAdjustment.exposureBoost);
    result.contextAdjustment.recognizabilityBoost = Math.max(result.contextAdjustment.recognizabilityBoost, adj.contextAdjustment.recognizabilityBoost);
    result.contextAdjustment.confidenceBoost = Math.max(result.contextAdjustment.confidenceBoost, adj.contextAdjustment.confidenceBoost);
    allScannerScores.push(...adj.breakdown.scannerScores);
    allServiceScores.push(...adj.breakdown.serviceScores);
    for (const f of adj.postureFindings) {
      const key = `${f.category}:${f.title.substring(0, 50)}`;
      if (!seenFindingIds.has(key)) {
        seenFindingIds.add(key);
        allFindings.push(f);
      }
    }
  }
  const totalCarverBoost = Object.values(result.carver).reduce((a, b) => a + b, 0);
  const totalShockBoost = Object.values(result.shock).reduce((a, b) => a + b, 0);
  result.breakdown.scannerScores = allScannerScores;
  result.breakdown.serviceScores = allServiceScores;
  result.breakdown.overallDastVulnScore = clamp(Math.round((totalCarverBoost + totalShockBoost) / 40 * 100), 0, 100);
  result.breakdown.assessmentConfidence = Math.max(...adjustments.map((a) => a.breakdown.assessmentConfidence));
  result.postureFindings = allFindings;
  return result;
}
export {
  aggregateDastAdjustments,
  applyDastAdjustments,
  computeDastCarverAdjustment
};
