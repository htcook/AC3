/**
 * DAST & Service Audit → Hybrid Risk Scoring Integration
 * ──────────────────────────────────────────────────────────
 * Maps DAST scanner findings (Nikto, Wapiti, Arachni) and service audit
 * findings (SSH, FTP, SMTP, SNMP, RDP) to CARVER + Shock scoring dimensions
 * so that protocol-level and web-layer vulnerabilities automatically feed
 * into the hybrid risk scoring pipeline for target prioritization.
 *
 * CARVER Mapping:
 *   Criticality    — critical services (SSH root, SMTP relay, RDP) → higher criticality
 *   Accessibility  — anonymous FTP, open relay, default creds → higher accessibility
 *   Recuperability — weak encryption, no TLS, protocol downgrade → harder to recover
 *   Vulnerability  — CVEs, weak algorithms, misconfigurations → more vulnerable
 *   Effect         — data exfil paths, relay abuse, lateral movement → broader effect
 *   Recognizability — banner disclosure, version fingerprinting → easier to target
 *
 * SHOCK Mapping:
 *   Scope             — services exposed to internet, multi-protocol → wider blast radius
 *   Handling          — weak logging, no monitoring indicators → harder incident response
 *   OperationalImpact — service disruption potential, auth bypass → operational disruption
 *   CascadingEffects  — lateral movement (RDP/SSH), relay chains → cascade potential
 *   Knowledge         — known CVEs, public exploits, default creds → exploit knowledge
 *
 * Patent-pending: Hybrid Risk/CVSS Hybrid Risk Scoring Pipeline
 * Created by Harrison Cook
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface DastCarverAdjustment {
  carver: {
    criticality: number;
    accessibility: number;
    recuperability: number;
    vulnerability: number;
    effect: number;
    recognizability: number;
  };
  shock: {
    scope: number;
    handling: number;
    operationalImpact: number;
    cascadingEffects: number;
    knowledge: number;
  };
  likelihoodBoost: number;
  contextAdjustment: {
    exposureBoost: number;
    recognizabilityBoost: number;
    confidenceBoost: number;
  };
  breakdown: DastScoreBreakdown;
  postureFindings: DastPostureFinding[];
}

export interface DastScoreBreakdown {
  /** Per-scanner breakdown */
  scannerScores: {
    scanner: string;
    findingCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    carverImpact: number;
    shockImpact: number;
  }[];
  /** Service-level breakdown */
  serviceScores: {
    service: string;
    port: number;
    host: string;
    vulnerabilityScore: number;
    accessibilityScore: number;
    findings: string[];
  }[];
  overallDastVulnScore: number;
  assessmentConfidence: number;
}

export interface DastPostureFinding {
  id: string;
  category: string;
  title: string;
  severity: number;
  confidence: number;
  description: string;
  evidenceDetail: string;
  corroborationTier: "confirmed" | "probable" | "possible";
  remediation: string;
  source: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — SEVERITY CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

const SEVERITY_VULN_BOOST: Record<string, number> = {
  critical: 3.0, high: 2.0, medium: 1.0, low: 0.3, info: 0.1,
};

const SEVERITY_LIKELIHOOD_BOOST: Record<string, number> = {
  critical: 0.4, high: 0.25, medium: 0.1, low: 0.03, info: 0.0,
};

/** Category-specific CARVER dimension mappings */
const CATEGORY_CARVER_MAP: Record<string, { dimension: string; boost: number }[]> = {
  // SSH audit categories
  "weak_algorithms": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 0.8 },
  ],
  "cve": [
    { dimension: "vulnerability", boost: 2.5 },
    { dimension: "accessibility", boost: 1.0 },
    { dimension: "recognizability", boost: 0.5 },
  ],
  "auth_methods": [
    { dimension: "accessibility", boost: 1.5 },
    { dimension: "criticality", boost: 0.5 },
  ],
  "key_exchange": [
    { dimension: "vulnerability", boost: 1.0 },
    { dimension: "recuperability", boost: 0.5 },
  ],
  "protocol": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recognizability", boost: 0.8 },
  ],
  // FTP audit categories
  "anonymous_access": [
    { dimension: "accessibility", boost: 3.0 },
    { dimension: "effect", boost: 2.0 },
    { dimension: "criticality", boost: 1.0 },
  ],
  "authentication": [
    { dimension: "accessibility", boost: 2.0 },
    { dimension: "vulnerability", boost: 1.5 },
  ],
  "encryption": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 1.0 },
  ],
  "bounce_attack": [
    { dimension: "effect", boost: 2.0 },
    { dimension: "accessibility", boost: 1.5 },
  ],
  "directory_traversal": [
    { dimension: "effect", boost: 2.5 },
    { dimension: "accessibility", boost: 1.5 },
  ],
  // SMTP audit categories
  "open_relay": [
    { dimension: "accessibility", boost: 3.0 },
    { dimension: "effect", boost: 2.5 },
    { dimension: "criticality", boost: 1.5 },
  ],
  "spf_dkim_dmarc": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "effect", boost: 1.0 },
  ],
  "tls_security": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 0.8 },
  ],
  "user_enumeration": [
    { dimension: "accessibility", boost: 2.0 },
    { dimension: "recognizability", boost: 1.5 },
  ],
  "banner_disclosure": [
    { dimension: "recognizability", boost: 2.0 },
    { dimension: "vulnerability", boost: 0.5 },
  ],
  // SNMP audit categories
  "default_community": [
    { dimension: "accessibility", boost: 3.0 },
    { dimension: "criticality", boost: 1.5 },
    { dimension: "effect", boost: 2.0 },
  ],
  "snmp_version": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 0.8 },
  ],
  "information_disclosure": [
    { dimension: "recognizability", boost: 2.0 },
    { dimension: "effect", boost: 1.0 },
  ],
  "write_access": [
    { dimension: "criticality", boost: 2.5 },
    { dimension: "effect", boost: 2.5 },
    { dimension: "accessibility", boost: 2.0 },
  ],
  // RDP audit categories
  "nla_disabled": [
    { dimension: "accessibility", boost: 2.0 },
    { dimension: "vulnerability", boost: 1.5 },
  ],
  "bluekeep": [
    { dimension: "vulnerability", boost: 3.0 },
    { dimension: "accessibility", boost: 2.5 },
    { dimension: "effect", boost: 2.0 },
    { dimension: "criticality", boost: 1.5 },
  ],
  "rdp_encryption": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recuperability", boost: 1.0 },
  ],
  "session_security": [
    { dimension: "vulnerability", boost: 1.0 },
    { dimension: "effect", boost: 0.8 },
  ],
  // DAST web scanner categories
  "xss": [
    { dimension: "vulnerability", boost: 2.0 },
    { dimension: "effect", boost: 1.5 },
  ],
  "sql_injection": [
    { dimension: "vulnerability", boost: 3.0 },
    { dimension: "effect", boost: 2.5 },
    { dimension: "criticality", boost: 1.5 },
  ],
  "command_injection": [
    { dimension: "vulnerability", boost: 3.0 },
    { dimension: "effect", boost: 3.0 },
    { dimension: "criticality", boost: 2.0 },
  ],
  "file_inclusion": [
    { dimension: "vulnerability", boost: 2.5 },
    { dimension: "effect", boost: 2.0 },
  ],
  "server_misconfiguration": [
    { dimension: "vulnerability", boost: 1.5 },
    { dimension: "recognizability", boost: 1.0 },
  ],
  "outdated_software": [
    { dimension: "vulnerability", boost: 2.0 },
    { dimension: "recognizability", boost: 1.5 },
  ],
};

/** Service-type to SHOCK dimension mappings */
const SERVICE_SHOCK_MAP: Record<string, { dimension: string; boost: number }[]> = {
  ssh: [
    { dimension: "cascadingEffects", boost: 2.0 },   // lateral movement
    { dimension: "operationalImpact", boost: 1.5 },   // remote access disruption
    { dimension: "knowledge", boost: 1.0 },            // well-known attack surface
  ],
  ftp: [
    { dimension: "scope", boost: 1.5 },               // data exfiltration
    { dimension: "operationalImpact", boost: 1.0 },   // file transfer disruption
    { dimension: "handling", boost: 0.8 },             // often poorly monitored
  ],
  smtp: [
    { dimension: "scope", boost: 2.5 },               // spam/phishing blast radius
    { dimension: "handling", boost: 1.5 },             // reputation damage hard to fix
    { dimension: "cascadingEffects", boost: 1.0 },     // phishing → credential theft
  ],
  snmp: [
    { dimension: "scope", boost: 2.0 },               // network-wide recon
    { dimension: "cascadingEffects", boost: 2.0 },     // config changes cascade
    { dimension: "handling", boost: 1.5 },             // often unmonitored
    { dimension: "knowledge", boost: 1.0 },            // well-documented attacks
  ],
  rdp: [
    { dimension: "cascadingEffects", boost: 2.5 },    // lateral movement + persistence
    { dimension: "operationalImpact", boost: 2.0 },   // full desktop access
    { dimension: "scope", boost: 1.5 },                // often internet-facing
    { dimension: "knowledge", boost: 1.5 },            // BlueKeep, etc.
  ],
  http: [
    { dimension: "scope", boost: 1.5 },               // public-facing
    { dimension: "operationalImpact", boost: 1.0 },   // web service disruption
    { dimension: "knowledge", boost: 0.5 },            // many known web vulns
  ],
  https: [
    { dimension: "scope", boost: 1.5 },
    { dimension: "operationalImpact", boost: 1.0 },
    { dimension: "knowledge", boost: 0.5 },
  ],
};

// ═══════════════════════════════════════════════════════════════════════
// §3 — CORE SCORING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

interface ServiceAuditFinding {
  title?: string;
  description?: string;
  severity?: string;
  category?: string;
  cve?: string;
  cwe?: string;
  recommendation?: string;
  evidence?: string;
}

interface ServiceAuditResult {
  host: string;
  port: number;
  service: string;
  banner?: string;
  findings: ServiceAuditFinding[];
  error?: string;
}

interface DastScannerResult {
  host?: string;
  port?: number;
  target?: string;
  findings: ServiceAuditFinding[];
  error?: string;
}

/**
 * Score a single service audit result against CARVER dimensions.
 */
function scoreServiceAudit(result: ServiceAuditResult): {
  carverBoosts: Record<string, number>;
  shockBoosts: Record<string, number>;
  likelihoodBoost: number;
  postureFindings: DastPostureFinding[];
} {
  const carverBoosts: Record<string, number> = {
    criticality: 0, accessibility: 0, recuperability: 0,
    vulnerability: 0, effect: 0, recognizability: 0,
  };
  const shockBoosts: Record<string, number> = {
    scope: 0, handling: 0, operationalImpact: 0,
    cascadingEffects: 0, knowledge: 0,
  };
  let likelihoodBoost = 0;
  const postureFindings: DastPostureFinding[] = [];

  if (!result.findings || result.findings.length === 0) {
    return { carverBoosts, shockBoosts, likelihoodBoost, postureFindings };
  }

  // Apply service-level SHOCK boosts
  const serviceShock = SERVICE_SHOCK_MAP[result.service] || SERVICE_SHOCK_MAP["http"] || [];
  for (const mapping of serviceShock) {
    shockBoosts[mapping.dimension] = Math.max(
      shockBoosts[mapping.dimension] || 0,
      mapping.boost * 0.5, // Base service exposure boost (half weight)
    );
  }

  for (const finding of result.findings) {
    const severity = (finding.severity || "info").toLowerCase();
    const category = (finding.category || "").toLowerCase().replace(/[^a-z_]/g, "_");

    // 1. Severity-based vulnerability boost
    const vulnBoost = SEVERITY_VULN_BOOST[severity] || 0.1;
    carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, vulnBoost);

    // 2. Likelihood boost from severity
    likelihoodBoost += SEVERITY_LIKELIHOOD_BOOST[severity] || 0;

    // 3. Category-specific CARVER mappings
    const categoryMappings = CATEGORY_CARVER_MAP[category];
    if (categoryMappings) {
      for (const mapping of categoryMappings) {
        const severityMultiplier = severity === "critical" ? 1.0 :
          severity === "high" ? 0.8 :
          severity === "medium" ? 0.5 :
          severity === "low" ? 0.25 : 0.1;
        const boost = mapping.boost * severityMultiplier;
        carverBoosts[mapping.dimension] = Math.max(
          carverBoosts[mapping.dimension] || 0,
          boost,
        );
      }
    }

    // 4. CVE-specific boosts
    if (finding.cve) {
      carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, 2.0);
      carverBoosts.recognizability = Math.max(carverBoosts.recognizability, 1.5);
      shockBoosts.knowledge = Math.max(shockBoosts.knowledge, 1.5);
    }

    // 5. Service-specific SHOCK amplification based on findings
    if (result.findings.length > 0) {
      const serviceShockFindings = SERVICE_SHOCK_MAP[result.service] || [];
      for (const mapping of serviceShockFindings) {
        const findingSeverityMult = severity === "critical" ? 1.0 :
          severity === "high" ? 0.7 : severity === "medium" ? 0.4 : 0.15;
        shockBoosts[mapping.dimension] = Math.max(
          shockBoosts[mapping.dimension] || 0,
          mapping.boost * findingSeverityMult,
        );
      }
    }

    // 6. Generate posture finding
    const severityNum = severity === "critical" ? 9 :
      severity === "high" ? 7 : severity === "medium" ? 5 :
      severity === "low" ? 3 : 1;

    postureFindings.push({
      id: `dast-${result.service}-${result.port}-${postureFindings.length}`,
      category: `${result.service}_audit`,
      title: finding.title || `${result.service.toUpperCase()} Finding`,
      severity: severityNum,
      confidence: finding.cve ? 0.95 : 0.8,
      description: finding.description || "",
      evidenceDetail: `${result.host}:${result.port} (${result.service}) — ${finding.evidence || finding.description || ""}`,
      corroborationTier: finding.cve ? "confirmed" : "probable",
      remediation: finding.recommendation || "",
      source: `${result.service}_audit`,
    });
  }

  return { carverBoosts, shockBoosts, likelihoodBoost: clamp(likelihoodBoost, 0, 1), postureFindings };
}

/**
 * Score DAST web scanner results (Nikto, Wapiti, Arachni).
 */
function scoreDastScanner(scannerName: string, results: DastScannerResult[]): {
  carverBoosts: Record<string, number>;
  shockBoosts: Record<string, number>;
  likelihoodBoost: number;
  postureFindings: DastPostureFinding[];
  scannerScore: DastScoreBreakdown["scannerScores"][0];
} {
  const carverBoosts: Record<string, number> = {
    criticality: 0, accessibility: 0, recuperability: 0,
    vulnerability: 0, effect: 0, recognizability: 0,
  };
  const shockBoosts: Record<string, number> = {
    scope: 0, handling: 0, operationalImpact: 0,
    cascadingEffects: 0, knowledge: 0,
  };
  let likelihoodBoost = 0;
  const postureFindings: DastPostureFinding[] = [];
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;

  for (const result of results) {
    if (!result.findings) continue;

    for (const finding of result.findings) {
      const severity = (finding.severity || "info").toLowerCase();

      if (severity === "critical") criticalCount++;
      else if (severity === "high") highCount++;
      else if (severity === "medium") mediumCount++;
      else if (severity === "low") lowCount++;

      // Vulnerability boost from severity
      const vulnBoost = SEVERITY_VULN_BOOST[severity] || 0.1;
      carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, vulnBoost);

      // Likelihood
      likelihoodBoost += SEVERITY_LIKELIHOOD_BOOST[severity] || 0;

      // Category-specific mapping
      const category = (finding.category || "").toLowerCase().replace(/[^a-z_]/g, "_");
      const categoryMappings = CATEGORY_CARVER_MAP[category];
      if (categoryMappings) {
        const severityMult = severity === "critical" ? 1.0 :
          severity === "high" ? 0.8 : severity === "medium" ? 0.5 : 0.25;
        for (const mapping of categoryMappings) {
          carverBoosts[mapping.dimension] = Math.max(
            carverBoosts[mapping.dimension] || 0,
            mapping.boost * severityMult,
          );
        }
      }

      // CVE boost
      if (finding.cve) {
        carverBoosts.vulnerability = Math.max(carverBoosts.vulnerability, 2.0);
        shockBoosts.knowledge = Math.max(shockBoosts.knowledge, 1.5);
      }

      // Web-specific SHOCK boosts
      shockBoosts.scope = Math.max(shockBoosts.scope, 1.5); // public-facing
      if (severity === "critical" || severity === "high") {
        shockBoosts.operationalImpact = Math.max(shockBoosts.operationalImpact, 1.5);
      }

      postureFindings.push({
        id: `dast-${scannerName}-${postureFindings.length}`,
        category: `dast_${scannerName}`,
        title: finding.title || `${scannerName} Finding`,
        severity: severity === "critical" ? 9 : severity === "high" ? 7 :
          severity === "medium" ? 5 : severity === "low" ? 3 : 1,
        confidence: finding.cve ? 0.9 : 0.75,
        description: finding.description || "",
        evidenceDetail: `${result.host || result.target || "unknown"} — ${finding.evidence || finding.description || ""}`,
        corroborationTier: finding.cve ? "confirmed" : "possible",
        remediation: finding.recommendation || "",
        source: `dast_${scannerName}`,
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
      shockImpact: Math.round(shockImpact * 100) / 100,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — MAIN INTEGRATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute CARVER+Shock adjustments from service audit pipeline results.
 * Accepts the raw output from runServiceAuditPipeline().
 */
export function computeDastCarverAdjustment(
  pipelineResults: Record<string, any[]>,
  hostname: string = "unknown",
): DastCarverAdjustment {
  const allCarverBoosts: Record<string, number> = {
    criticality: 0, accessibility: 0, recuperability: 0,
    vulnerability: 0, effect: 0, recognizability: 0,
  };
  const allShockBoosts: Record<string, number> = {
    scope: 0, handling: 0, operationalImpact: 0,
    cascadingEffects: 0, knowledge: 0,
  };
  let totalLikelihoodBoost = 0;
  const allPostureFindings: DastPostureFinding[] = [];
  const scannerScores: DastScoreBreakdown["scannerScores"] = [];
  const serviceScores: DastScoreBreakdown["serviceScores"] = [];

  // Service audit scanners
  const serviceAuditTypes = ["ssh", "ftp", "smtp", "snmp", "rdp"];
  for (const sType of serviceAuditTypes) {
    const results = pipelineResults[sType];
    if (!Array.isArray(results) || results.length === 0) continue;

    let scannerCritical = 0, scannerHigh = 0, scannerMedium = 0, scannerLow = 0;
    let scannerCarverTotal = 0, scannerShockTotal = 0;

    for (const result of results) {
      const scored = scoreServiceAudit(result);

      // Merge boosts (take max per dimension)
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

      // Count severities
      for (const f of (result.findings || [])) {
        const sev = (f.severity || "info").toLowerCase();
        if (sev === "critical") scannerCritical++;
        else if (sev === "high") scannerHigh++;
        else if (sev === "medium") scannerMedium++;
        else if (sev === "low") scannerLow++;
      }

      // Service score
      serviceScores.push({
        service: result.service || sType,
        port: result.port || 0,
        host: result.host || hostname,
        vulnerabilityScore: scored.carverBoosts.vulnerability || 0,
        accessibilityScore: scored.carverBoosts.accessibility || 0,
        findings: (result.findings || []).map((f: any) => f.title || "Unknown"),
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
      shockImpact: Math.round(scannerShockTotal * 100) / 100,
    });
  }

  // DAST web scanners
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

  // Compute overall score
  const totalCarverBoost = Object.values(allCarverBoosts).reduce((a, b) => a + b, 0);
  const totalShockBoost = Object.values(allShockBoosts).reduce((a, b) => a + b, 0);
  const overallScore = clamp(Math.round(((totalCarverBoost + totalShockBoost) / 40) * 100), 0, 100);

  // Confidence based on number of scanners that produced results
  const scannersWithResults = scannerScores.filter(s => s.findingCount > 0).length;
  const confidence = clamp(0.5 + (scannersWithResults * 0.1), 0.5, 0.95);

  return {
    carver: {
      criticality: clamp(Math.round(allCarverBoosts.criticality * 100) / 100, 0, 5),
      accessibility: clamp(Math.round(allCarverBoosts.accessibility * 100) / 100, 0, 5),
      recuperability: clamp(Math.round(allCarverBoosts.recuperability * 100) / 100, 0, 5),
      vulnerability: clamp(Math.round(allCarverBoosts.vulnerability * 100) / 100, 0, 5),
      effect: clamp(Math.round(allCarverBoosts.effect * 100) / 100, 0, 5),
      recognizability: clamp(Math.round(allCarverBoosts.recognizability * 100) / 100, 0, 5),
    },
    shock: {
      scope: clamp(Math.round(allShockBoosts.scope * 100) / 100, 0, 5),
      handling: clamp(Math.round(allShockBoosts.handling * 100) / 100, 0, 5),
      operationalImpact: clamp(Math.round(allShockBoosts.operationalImpact * 100) / 100, 0, 5),
      cascadingEffects: clamp(Math.round(allShockBoosts.cascadingEffects * 100) / 100, 0, 5),
      knowledge: clamp(Math.round(allShockBoosts.knowledge * 100) / 100, 0, 5),
    },
    likelihoodBoost: clamp(Math.round(totalLikelihoodBoost * 100) / 100, 0, 1),
    contextAdjustment: {
      exposureBoost: clamp(allCarverBoosts.accessibility * 0.3, 0, 1),
      recognizabilityBoost: clamp(allCarverBoosts.recognizability * 0.3, 0, 1),
      confidenceBoost: clamp((scannersWithResults - 1) * 0.05, 0, 0.3),
    },
    breakdown: {
      scannerScores,
      serviceScores,
      overallDastVulnScore: overallScore,
      assessmentConfidence: confidence,
    },
    postureFindings: allPostureFindings,
  };
}

/**
 * Apply DAST/service audit adjustments to existing CARVER+Shock scores.
 * Same pattern as applyCrawlAdjustments.
 */
export function applyDastAdjustments(
  existingCarver: { criticality: number; accessibility: number; recuperability: number; vulnerability: number; effect: number; recognizability: number },
  existingShock: { scope: number; handling: number; operationalImpact: number; cascadingEffects: number; knowledge: number },
  adjustment: DastCarverAdjustment,
): { carver: typeof existingCarver; shock: typeof existingShock } {
  return {
    carver: {
      criticality: clamp(existingCarver.criticality + adjustment.carver.criticality, 0, 10),
      accessibility: clamp(existingCarver.accessibility + adjustment.carver.accessibility, 0, 10),
      recuperability: clamp(existingCarver.recuperability + adjustment.carver.recuperability, 0, 10),
      vulnerability: clamp(existingCarver.vulnerability + adjustment.carver.vulnerability, 0, 10),
      effect: clamp(existingCarver.effect + adjustment.carver.effect, 0, 10),
      recognizability: clamp(existingCarver.recognizability + adjustment.carver.recognizability, 0, 10),
    },
    shock: {
      scope: clamp(existingShock.scope + adjustment.shock.scope, 0, 10),
      handling: clamp(existingShock.handling + adjustment.shock.handling, 0, 10),
      operationalImpact: clamp(existingShock.operationalImpact + adjustment.shock.operationalImpact, 0, 10),
      cascadingEffects: clamp(existingShock.cascadingEffects + adjustment.shock.cascadingEffects, 0, 10),
      knowledge: clamp(existingShock.knowledge + adjustment.shock.knowledge, 0, 10),
    },
  };
}

/**
 * Aggregate multiple DAST adjustments (e.g., from multiple hosts).
 * Takes the maximum adjustment across all results for each dimension.
 */
export function aggregateDastAdjustments(adjustments: DastCarverAdjustment[]): DastCarverAdjustment | null {
  if (adjustments.length === 0) return null;
  if (adjustments.length === 1) return adjustments[0];

  const allFindings: DastPostureFinding[] = [];
  const seenFindingIds = new Set<string>();
  const allScannerScores: DastScoreBreakdown["scannerScores"] = [];
  const allServiceScores: DastScoreBreakdown["serviceScores"] = [];

  const result: DastCarverAdjustment = {
    carver: { criticality: 0, accessibility: 0, recuperability: 0, vulnerability: 0, effect: 0, recognizability: 0 },
    shock: { scope: 0, handling: 0, operationalImpact: 0, cascadingEffects: 0, knowledge: 0 },
    likelihoodBoost: 0,
    contextAdjustment: { exposureBoost: 0, recognizabilityBoost: 0, confidenceBoost: 0 },
    breakdown: {
      scannerScores: [],
      serviceScores: [],
      overallDastVulnScore: 0,
      assessmentConfidence: 0,
    },
    postureFindings: [],
  };

  for (const adj of adjustments) {
    for (const key of Object.keys(result.carver) as Array<keyof typeof result.carver>) {
      result.carver[key] = Math.max(result.carver[key], adj.carver[key]);
    }
    for (const key of Object.keys(result.shock) as Array<keyof typeof result.shock>) {
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
  result.breakdown.overallDastVulnScore = clamp(Math.round(((totalCarverBoost + totalShockBoost) / 40) * 100), 0, 100);
  result.breakdown.assessmentConfidence = Math.max(...adjustments.map(a => a.breakdown.assessmentConfidence));
  result.postureFindings = allFindings;

  return result;
}
