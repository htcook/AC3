import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/crawl-carver-integration.ts
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}
function scoreHeaders(crawl) {
  const grade = crawl.securityHeaderGrade || "F";
  const headers = crawl.securityHeaders;
  const missingCritical = headers?.missing?.filter((h) => h.severity === "high")?.map((h) => h.name) || [];
  const missingMedium = headers?.missing?.filter((h) => h.severity === "medium")?.map((h) => h.name) || [];
  const misconfigured = headers?.misconfigured?.map((h) => h.name) || [];
  const vulnerabilityBoost = clamp((GRADE_VULNERABILITY_MAP[grade] ?? 2) + misconfigured.length * 0.3, 0, 4);
  const handlingBoost = clamp(GRADE_HANDLING_MAP[grade] ?? 1.5, 0, 3);
  const recuperabilityBoost = clamp(!crawl.securityTxt ? 0.5 : 0, 0, 1);
  return {
    vulnerabilityBoost,
    handlingBoost,
    recuperabilityBoost,
    breakdown: { grade, missingCritical, missingMedium, misconfigured, vulnerabilityImpact: vulnerabilityBoost, handlingImpact: handlingBoost }
  };
}
function scoreExposedPaths(paths) {
  if (!paths || paths.length === 0) {
    return { accessibilityBoost: 0, effectBoost: 0, breakdown: { criticalPaths: [], highPaths: [], mediumPaths: [], accessibilityImpact: 0, effectImpact: 0 } };
  }
  let accessibilityBoost = 0, effectBoost = 0;
  const criticalPaths = [], highPaths = [], mediumPaths = [];
  for (const p of paths) {
    const sev = p.severity || "info";
    accessibilityBoost += PATH_SEVERITY_BOOST[sev] || 0;
    effectBoost += PATH_EFFECT_BOOST[sev] || 0;
    if (sev === "critical") criticalPaths.push(p.path);
    else if (sev === "high") highPaths.push(p.path);
    else if (sev === "medium") mediumPaths.push(p.path);
  }
  return {
    accessibilityBoost: clamp(accessibilityBoost, 0, 4),
    effectBoost: clamp(effectBoost, 0, 3),
    breakdown: { criticalPaths, highPaths, mediumPaths, accessibilityImpact: accessibilityBoost, effectImpact: effectBoost }
  };
}
function scoreCookies(cookies) {
  if (!cookies || cookies.length === 0) {
    return { vulnerabilityBoost: 0, breakdown: { insecureCookies: [], totalCookies: 0, vulnerabilityImpact: 0 } };
  }
  const insecureCookies = [];
  let boost = 0;
  for (const c of cookies) {
    const issues = [];
    if (!c.secure) issues.push("no-secure");
    if (!c.httpOnly) issues.push("no-httponly");
    if (!c.sameSite || c.sameSite === "None") issues.push("no-samesite");
    if (issues.length > 0) {
      insecureCookies.push(`${c.name} (${issues.join(", ")})`);
      const isSession = /session|sid|token|auth|jwt/i.test(c.name);
      boost += isSession ? 0.8 : 0.3;
    }
  }
  return { vulnerabilityBoost: clamp(boost, 0, 3), breakdown: { insecureCookies, totalCookies: cookies.length, vulnerabilityImpact: boost } };
}
function scoreTechnologies(techs) {
  if (!techs || techs.length === 0) {
    return { recognizabilityBoost: 0, knowledgeBoost: 0, outdatedVersions: [], breakdown: { detectedTech: [], outdatedVersions: [], recognizabilityImpact: 0, knowledgeImpact: 0 } };
  }
  const detectedTech = techs.map((t) => `${t.name}${t.version ? ` v${t.version}` : ""}`);
  const outdatedVersions = [];
  let recognizabilityBoost = clamp(techs.length * 0.2, 0, 2);
  const withVersions = techs.filter((t) => t.version);
  recognizabilityBoost += clamp(withVersions.length * 0.3, 0, 1.5);
  let knowledgeBoost = 0;
  for (const tech of techs) {
    if (!tech.version) continue;
    for (const pattern of OUTDATED_TECH_PATTERNS) {
      if (pattern.name.test(tech.name)) {
        const current = parseVersion(tech.version);
        const safe = parseVersion(pattern.maxSafe);
        if (current && safe && isOlderThan(current, safe)) {
          outdatedVersions.push(`${tech.name} v${tech.version} (safe: ${pattern.maxSafe}+)`);
          knowledgeBoost += 0.5;
        }
      }
    }
  }
  const categories = new Set(techs.map((t) => t.category));
  knowledgeBoost += clamp(categories.size * 0.15, 0, 1);
  return {
    recognizabilityBoost: clamp(recognizabilityBoost, 0, 3.5),
    knowledgeBoost: clamp(knowledgeBoost, 0, 3),
    outdatedVersions,
    breakdown: { detectedTech, outdatedVersions, recognizabilityImpact: recognizabilityBoost, knowledgeImpact: knowledgeBoost }
  };
}
function scoreTls(tlsInfo) {
  if (!tlsInfo) {
    return { vulnerabilityBoost: 1.5, breakdown: { issues: ["No TLS/SSL detected"], vulnerabilityImpact: 1.5 } };
  }
  const issues = [];
  let boost = 0;
  const protocol = tlsInfo.protocol || "";
  if (protocol.includes("1.0") || protocol.includes("1.1")) {
    issues.push(`Outdated TLS protocol: ${protocol}`);
    boost += 1;
  }
  const validTo = tlsInfo.validTo;
  if (validTo) {
    const expiry = new Date(validTo);
    if (expiry < /* @__PURE__ */ new Date()) {
      issues.push("Certificate expired");
      boost += 1.5;
    } else {
      const daysLeft = (expiry.getTime() - Date.now()) / 864e5;
      if (daysLeft < 30) {
        issues.push(`Certificate expires in ${Math.round(daysLeft)} days`);
        boost += 0.5;
      }
    }
  }
  const issuer = tlsInfo.issuer || "";
  if (issuer.toLowerCase().includes("self-signed") || issuer === "") {
    issues.push("Self-signed or untrusted certificate");
    boost += 1;
  }
  return { vulnerabilityBoost: clamp(boost, 0, 3), breakdown: { issues, vulnerabilityImpact: boost } };
}
function scoreForms(forms) {
  if (!forms || forms.length === 0) {
    return { criticalityBoost: 0, operationalImpactBoost: 0, breakdown: { loginForms: 0, fileUploadForms: 0, criticalityImpact: 0, operationalImpact: 0 } };
  }
  let loginForms = 0, fileUploadForms = 0;
  for (const f of forms) {
    if (f.hasPasswordField) loginForms++;
    if (f.hasFileUpload) fileUploadForms++;
  }
  const criticalityBoost = clamp(loginForms * 1, 0, 2);
  const operationalImpactBoost = clamp(fileUploadForms * 0.8 + loginForms * 0.5, 0, 2);
  return { criticalityBoost, operationalImpactBoost, breakdown: { loginForms, fileUploadForms, criticalityImpact: criticalityBoost, operationalImpact: operationalImpactBoost } };
}
function scoreSurface(crawl) {
  const internalLinks = crawl.internalLinks?.length || 0;
  const externalLinks = crawl.externalLinks?.length || 0;
  const scopeBoost = clamp(externalLinks * 0.05, 0, 1.5);
  const cascadingBoost = clamp(internalLinks * 0.02, 0, 1);
  return { scopeBoost, cascadingBoost, breakdown: { internalLinks, externalLinks, scopeImpact: scopeBoost, cascadingImpact: cascadingBoost } };
}
function generateCrawlPostureFindings(crawl, hostname) {
  const findings = [];
  const now = Date.now();
  for (const p of crawl.exposedPaths || []) {
    if (p.severity === "critical" || p.severity === "high") {
      findings.push({
        id: `crawl-path-${hostname}-${p.path.replace(/[^a-z0-9]/gi, "_")}-${now}`,
        category: "Web Exposure",
        title: `Exposed ${(p.type || "path").replace(/_/g, " ")}: ${p.path}`,
        severity: p.severity === "critical" ? 9 : 7,
        confidence: 1,
        description: p.description,
        evidenceDetail: `HTTP ${p.status} response at ${p.path} \u2014 confirmed accessible`,
        corroborationTier: "confirmed",
        remediation: `Restrict access to ${p.path} via web server configuration or remove the file`,
        source: "web_crawler"
      });
    }
  }
  const missingCritical = crawl.securityHeaders?.missing?.filter((h) => h.severity === "high") || [];
  if (missingCritical.length > 0) {
    findings.push({
      id: `crawl-headers-${hostname}-${now}`,
      category: "Web Security Headers",
      title: `Missing critical security headers: ${missingCritical.map((h) => h.name).join(", ")}`,
      severity: 6,
      confidence: 1,
      description: `${missingCritical.length} critical security headers missing, leaving the application vulnerable to XSS, clickjacking, and protocol downgrade attacks`,
      evidenceDetail: `Confirmed via HTTP response header analysis: ${missingCritical.map((h) => h.name).join(", ")}`,
      corroborationTier: "confirmed",
      remediation: `Add the following headers: ${missingCritical.map((h) => h.name).join(", ")}`,
      source: "web_crawler"
    });
  }
  const sessionCookies = (crawl.cookies || []).filter(
    (c) => /session|sid|token|auth|jwt/i.test(c.name) && (!c.secure || !c.httpOnly)
  );
  if (sessionCookies.length > 0) {
    findings.push({
      id: `crawl-cookies-${hostname}-${now}`,
      category: "Web Session Security",
      title: `Insecure session cookies: ${sessionCookies.map((c) => c.name).join(", ")}`,
      severity: 7,
      confidence: 1,
      description: `Session cookies lack Secure and/or HttpOnly flags, enabling session hijacking`,
      evidenceDetail: `Confirmed via Set-Cookie header analysis: ${sessionCookies.map((c) => `${c.name} (Secure=${c.secure}, HttpOnly=${c.httpOnly})`).join("; ")}`,
      corroborationTier: "confirmed",
      remediation: `Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies`,
      source: "web_crawler"
    });
  }
  if (!crawl.tlsInfo) {
    findings.push({
      id: `crawl-tls-${hostname}-${now}`,
      category: "Transport Security",
      title: "No TLS/SSL encryption detected",
      severity: 8,
      confidence: 1,
      description: "The web application does not use TLS/SSL encryption, transmitting all data in plaintext",
      evidenceDetail: "No TLS certificate information returned during crawl",
      corroborationTier: "confirmed",
      remediation: "Enable TLS/SSL with a valid certificate from a trusted CA",
      source: "web_crawler"
    });
  } else {
    const validTo = crawl.tlsInfo.validTo;
    if (validTo && new Date(validTo) < /* @__PURE__ */ new Date()) {
      findings.push({
        id: `crawl-tls-expired-${hostname}-${now}`,
        category: "Transport Security",
        title: "Expired TLS certificate",
        severity: 7,
        confidence: 1,
        description: `TLS certificate expired on ${validTo}`,
        evidenceDetail: `Certificate validTo: ${validTo}`,
        corroborationTier: "confirmed",
        remediation: "Renew the TLS certificate immediately",
        source: "web_crawler"
      });
    }
  }
  if (crawl.serverHeader) {
    const versionMatch = crawl.serverHeader.match(/[\d]+\.[\d]+/);
    if (versionMatch) {
      findings.push({
        id: `crawl-version-${hostname}-${now}`,
        category: "Information Disclosure",
        title: `Server version disclosed: ${crawl.serverHeader}`,
        severity: 4,
        confidence: 0.9,
        description: `The server header reveals version information (${crawl.serverHeader}), enabling targeted exploit selection`,
        evidenceDetail: `Server header: ${crawl.serverHeader}`,
        corroborationTier: "probable",
        remediation: "Remove or obfuscate the Server header in web server configuration",
        source: "web_crawler"
      });
    }
  }
  return findings;
}
function computeCrawlCarverAdjustment(crawl, hostname) {
  const headerResult = scoreHeaders(crawl);
  const pathResult = scoreExposedPaths(crawl.exposedPaths);
  const cookieResult = scoreCookies(crawl.cookies);
  const techResult = scoreTechnologies(crawl.detectedTechnologies);
  const tlsResult = scoreTls(crawl.tlsInfo);
  const formResult = scoreForms(crawl.forms);
  const surfaceResult = scoreSurface(crawl);
  const carver = {
    criticality: clamp(formResult.criticalityBoost, 0, 3),
    accessibility: clamp(pathResult.accessibilityBoost, 0, 4),
    recuperability: clamp(headerResult.recuperabilityBoost, 0, 2),
    vulnerability: clamp(headerResult.vulnerabilityBoost + cookieResult.vulnerabilityBoost + tlsResult.vulnerabilityBoost, 0, 5),
    effect: clamp(pathResult.effectBoost, 0, 3),
    recognizability: clamp(techResult.recognizabilityBoost, 0, 3.5)
  };
  const shock = {
    scope: clamp(surfaceResult.scopeBoost, 0, 2),
    handling: clamp(headerResult.handlingBoost, 0, 3),
    operationalImpact: clamp(formResult.operationalImpactBoost, 0, 2),
    cascadingEffects: clamp(surfaceResult.cascadingBoost, 0, 1.5),
    knowledge: clamp(techResult.knowledgeBoost, 0, 3)
  };
  const criticalFindings = (crawl.findings || []).filter((f) => f.severity === "critical").length;
  const highFindings = (crawl.findings || []).filter((f) => f.severity === "high").length;
  const likelihoodBoost = clamp(criticalFindings * 0.08 + highFindings * 0.04, 0, 0.25);
  const contextAdjustment = {
    exposureBoost: clamp((pathResult.accessibilityBoost > 1 ? 0.15 : 0) + (cookieResult.vulnerabilityBoost > 1 ? 0.05 : 0), 0, 0.2),
    recognizabilityBoost: clamp(techResult.recognizabilityBoost > 1 ? 0.1 : 0, 0, 0.15),
    confidenceBoost: clamp(crawl.httpStatus === 200 ? 0.15 : 0.05, 0, 0.2)
  };
  const totalCarverBoost = Object.values(carver).reduce((a, b) => a + b, 0);
  const totalShockBoost = Object.values(shock).reduce((a, b) => a + b, 0);
  const maxPossibleBoost = 34;
  const overallWebVulnScore = clamp(Math.round((totalCarverBoost + totalShockBoost) / maxPossibleBoost * 100), 0, 100);
  const assessmentConfidence = crawl.httpStatus === 200 ? 0.85 : crawl.httpStatus && crawl.httpStatus < 400 ? 0.7 : crawl.httpStatus && crawl.httpStatus < 500 ? 0.4 : 0.2;
  const breakdown = {
    headerScore: headerResult.breakdown,
    exposedPathScore: pathResult.breakdown,
    cookieScore: cookieResult.breakdown,
    technologyScore: techResult.breakdown,
    tlsScore: tlsResult.breakdown,
    formScore: formResult.breakdown,
    surfaceScore: surfaceResult.breakdown,
    overallWebVulnScore,
    assessmentConfidence
  };
  const postureFindings = generateCrawlPostureFindings(crawl, hostname);
  return { carver, shock, likelihoodBoost, contextAdjustment, breakdown, postureFindings };
}
function applyCrawlAdjustments(existingCarver, existingShock, adjustment) {
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
function aggregateCrawlAdjustments(adjustments) {
  if (adjustments.length === 0) return null;
  if (adjustments.length === 1) return adjustments[0];
  const allFindings = [];
  const seenFindingIds = /* @__PURE__ */ new Set();
  const result = {
    carver: { criticality: 0, accessibility: 0, recuperability: 0, vulnerability: 0, effect: 0, recognizability: 0 },
    shock: { scope: 0, handling: 0, operationalImpact: 0, cascadingEffects: 0, knowledge: 0 },
    likelihoodBoost: 0,
    contextAdjustment: { exposureBoost: 0, recognizabilityBoost: 0, confidenceBoost: 0 },
    breakdown: adjustments[0].breakdown,
    // Use first breakdown as representative
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
  result.breakdown.overallWebVulnScore = clamp(Math.round((totalCarverBoost + totalShockBoost) / 34 * 100), 0, 100);
  result.breakdown.assessmentConfidence = Math.max(...adjustments.map((a) => a.breakdown.assessmentConfidence));
  result.postureFindings = allFindings;
  return result;
}
function parseVersion(v) {
  const parts = v.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!parts) return null;
  return [parseInt(parts[1], 10), parseInt(parts[2], 10), parseInt(parts[3] || "0", 10)];
}
function isOlderThan(current, safe) {
  for (let i = 0; i < 3; i++) {
    if (current[i] < safe[i]) return true;
    if (current[i] > safe[i]) return false;
  }
  return false;
}
var GRADE_VULNERABILITY_MAP, GRADE_HANDLING_MAP, PATH_SEVERITY_BOOST, PATH_EFFECT_BOOST, OUTDATED_TECH_PATTERNS;
var init_crawl_carver_integration = __esm({
  "server/lib/crawl-carver-integration.ts"() {
    GRADE_VULNERABILITY_MAP = {
      "F": 3,
      "D": 2,
      "C": 1,
      "B": 0.5,
      "A": 0,
      "A+": 0
    };
    GRADE_HANDLING_MAP = {
      "F": 2,
      "D": 1.5,
      "C": 1,
      "B": 0.5,
      "A": 0,
      "A+": 0
    };
    PATH_SEVERITY_BOOST = {
      critical: 2.5,
      high: 1.5,
      medium: 0.8,
      low: 0.3,
      info: 0.1
    };
    PATH_EFFECT_BOOST = {
      critical: 2,
      high: 1,
      medium: 0.5,
      low: 0.2,
      info: 0
    };
    OUTDATED_TECH_PATTERNS = [
      { name: /^Apache$/i, maxSafe: "2.4.58", severity: 6 },
      { name: /^Nginx$/i, maxSafe: "1.25.0", severity: 5 },
      { name: /^PHP$/i, maxSafe: "8.2.0", severity: 7 },
      { name: /^jQuery$/i, maxSafe: "3.6.0", severity: 4 },
      { name: /^WordPress$/i, maxSafe: "6.4.0", severity: 7 },
      { name: /^OpenSSL$/i, maxSafe: "3.0.0", severity: 8 },
      { name: /^Node\.js$/i, maxSafe: "20.0.0", severity: 5 },
      { name: /^React$/i, maxSafe: "18.0.0", severity: 3 },
      { name: /^Angular$/i, maxSafe: "16.0.0", severity: 4 },
      { name: /^Express$/i, maxSafe: "4.18.0", severity: 5 }
    ];
  }
});

export {
  computeCrawlCarverAdjustment,
  applyCrawlAdjustments,
  aggregateCrawlAdjustments,
  init_crawl_carver_integration
};
