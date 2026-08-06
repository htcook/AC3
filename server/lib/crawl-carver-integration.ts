/**
 * Crawl → Hybrid Risk Scoring Integration
 * ──────────────────────────────────────────
 * Maps web crawler findings to Hybrid Risk scoring dimensions so that
 * web-layer vulnerabilities (missing headers, exposed paths, insecure cookies,
 * outdated technologies, TLS issues) automatically feed into the hybrid
 * risk scoring pipeline for target prioritization.
 *
 * CARVER Mapping:
 *   Criticality    — login forms, payment forms, auth endpoints → higher criticality
 *   Accessibility  — exposed paths (.env, .git, admin panels) → higher accessibility
 *   Recuperability — no security.txt, no CSP report-uri → harder to recover
 *   Vulnerability  — missing security headers, insecure cookies, outdated tech → more vulnerable
 *   Effect         — data exposure paths, directory listings → broader effect
 *   Recognizability — server version disclosure, tech fingerprinting → easier to target
 *
 * SHOCK Mapping:
 *   Scope             — external links count, cookie domains → wider blast radius
 *   Handling          — no security.txt, missing HSTS → harder incident response
 *   OperationalImpact — forms with file upload, password fields → operational disruption
 *   CascadingEffects  — internal links count, resource dependencies → cascade potential
 *   Knowledge         — technology stack complexity, version disclosure → exploit knowledge
 *
 * Patent-pending: Hybrid Risk/CVSS Hybrid Risk Scoring Pipeline
 * Created by Harrison Cook
 */

import type { CrawlPageResult, ExposedPath, CookieAnalysis, DetectedTechnology } from "./web-crawler";

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface CrawlCarverAdjustment {
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
  breakdown: CrawlScoreBreakdown;
  postureFindings: CrawlPostureFinding[];
}

export interface CrawlScoreBreakdown {
  headerScore: {
    grade: string;
    missingCritical: string[];
    missingMedium: string[];
    misconfigured: string[];
    vulnerabilityImpact: number;
    handlingImpact: number;
  };
  exposedPathScore: {
    criticalPaths: string[];
    highPaths: string[];
    mediumPaths: string[];
    accessibilityImpact: number;
    effectImpact: number;
  };
  cookieScore: {
    insecureCookies: string[];
    totalCookies: number;
    vulnerabilityImpact: number;
  };
  technologyScore: {
    detectedTech: string[];
    outdatedVersions: string[];
    recognizabilityImpact: number;
    knowledgeImpact: number;
  };
  tlsScore: {
    issues: string[];
    vulnerabilityImpact: number;
  };
  formScore: {
    loginForms: number;
    fileUploadForms: number;
    criticalityImpact: number;
    operationalImpact: number;
  };
  surfaceScore: {
    internalLinks: number;
    externalLinks: number;
    scopeImpact: number;
    cascadingImpact: number;
  };
  overallWebVulnScore: number;
  assessmentConfidence: number;
}

export interface CrawlPostureFinding {
  id: string;
  category: string;
  title: string;
  severity: number;
  confidence: number;
  description: string;
  evidenceDetail: string;
  corroborationTier: "confirmed" | "probable";
  remediation: string;
  source: "web_crawler";
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — SCORING CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const GRADE_VULNERABILITY_MAP: Record<string, number> = {
  "F": 3.0, "D": 2.0, "C": 1.0, "B": 0.5, "A": 0.0, "A+": 0.0,
};

const GRADE_HANDLING_MAP: Record<string, number> = {
  "F": 2.0, "D": 1.5, "C": 1.0, "B": 0.5, "A": 0.0, "A+": 0.0,
};

const PATH_SEVERITY_BOOST: Record<string, number> = {
  critical: 2.5, high: 1.5, medium: 0.8, low: 0.3, info: 0.1,
};

const PATH_EFFECT_BOOST: Record<string, number> = {
  critical: 2.0, high: 1.0, medium: 0.5, low: 0.2, info: 0.0,
};

const OUTDATED_TECH_PATTERNS: Array<{ name: RegExp; maxSafe: string; severity: number }> = [
  { name: /^Apache$/i, maxSafe: "2.4.58", severity: 6 },
  { name: /^Nginx$/i, maxSafe: "1.25.0", severity: 5 },
  { name: /^PHP$/i, maxSafe: "8.2.0", severity: 7 },
  { name: /^jQuery$/i, maxSafe: "3.6.0", severity: 4 },
  { name: /^WordPress$/i, maxSafe: "6.4.0", severity: 7 },
  { name: /^OpenSSL$/i, maxSafe: "3.0.0", severity: 8 },
  { name: /^Node\.js$/i, maxSafe: "20.0.0", severity: 5 },
  { name: /^React$/i, maxSafe: "18.0.0", severity: 3 },
  { name: /^Angular$/i, maxSafe: "16.0.0", severity: 4 },
  { name: /^Express$/i, maxSafe: "4.18.0", severity: 5 },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — CORE SCORING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

function scoreHeaders(crawl: CrawlPageResult) {
  const grade = crawl.securityHeaderGrade || "F";
  const headers = crawl.securityHeaders;
  const missingCritical = headers?.missing?.filter(h => h.severity === "high")?.map(h => h.name) || [];
  const missingMedium = headers?.missing?.filter(h => h.severity === "medium")?.map(h => h.name) || [];
  const misconfigured = headers?.misconfigured?.map(h => h.name) || [];

  const vulnerabilityBoost = clamp((GRADE_VULNERABILITY_MAP[grade] ?? 2.0) + misconfigured.length * 0.3, 0, 4);
  const handlingBoost = clamp(GRADE_HANDLING_MAP[grade] ?? 1.5, 0, 3);
  const recuperabilityBoost = clamp(!crawl.securityTxt ? 0.5 : 0, 0, 1);

  return {
    vulnerabilityBoost, handlingBoost, recuperabilityBoost,
    breakdown: { grade, missingCritical, missingMedium, misconfigured, vulnerabilityImpact: vulnerabilityBoost, handlingImpact: handlingBoost },
  };
}

function scoreExposedPaths(paths: ExposedPath[]) {
  if (!paths || paths.length === 0) {
    return { accessibilityBoost: 0, effectBoost: 0, breakdown: { criticalPaths: [] as string[], highPaths: [] as string[], mediumPaths: [] as string[], accessibilityImpact: 0, effectImpact: 0 } };
  }
  let accessibilityBoost = 0, effectBoost = 0;
  const criticalPaths: string[] = [], highPaths: string[] = [], mediumPaths: string[] = [];
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
    breakdown: { criticalPaths, highPaths, mediumPaths, accessibilityImpact: accessibilityBoost, effectImpact: effectBoost },
  };
}

function scoreCookies(cookies: CookieAnalysis[]) {
  if (!cookies || cookies.length === 0) {
    return { vulnerabilityBoost: 0, breakdown: { insecureCookies: [] as string[], totalCookies: 0, vulnerabilityImpact: 0 } };
  }
  const insecureCookies: string[] = [];
  let boost = 0;
  for (const c of cookies) {
    const issues: string[] = [];
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

function scoreTechnologies(techs: DetectedTechnology[]) {
  if (!techs || techs.length === 0) {
    return { recognizabilityBoost: 0, knowledgeBoost: 0, outdatedVersions: [] as string[], breakdown: { detectedTech: [] as string[], outdatedVersions: [] as string[], recognizabilityImpact: 0, knowledgeImpact: 0 } };
  }
  const detectedTech = techs.map(t => `${t.name}${t.version ? ` v${t.version}` : ""}`);
  const outdatedVersions: string[] = [];
  let recognizabilityBoost = clamp(techs.length * 0.2, 0, 2);
  const withVersions = techs.filter(t => t.version);
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
  const categories = new Set(techs.map(t => t.category));
  knowledgeBoost += clamp(categories.size * 0.15, 0, 1);

  return {
    recognizabilityBoost: clamp(recognizabilityBoost, 0, 3.5),
    knowledgeBoost: clamp(knowledgeBoost, 0, 3),
    outdatedVersions,
    breakdown: { detectedTech, outdatedVersions, recognizabilityImpact: recognizabilityBoost, knowledgeImpact: knowledgeBoost },
  };
}

function scoreTls(tlsInfo: Record<string, unknown> | null) {
  if (!tlsInfo) {
    return { vulnerabilityBoost: 1.5, breakdown: { issues: ["No TLS/SSL detected"], vulnerabilityImpact: 1.5 } };
  }
  const issues: string[] = [];
  let boost = 0;
  const protocol = (tlsInfo.protocol as string) || "";
  if (protocol.includes("1.0") || protocol.includes("1.1")) { issues.push(`Outdated TLS protocol: ${protocol}`); boost += 1.0; }
  const validTo = tlsInfo.validTo as string;
  if (validTo) {
    const expiry = new Date(validTo);
    if (expiry < new Date()) { issues.push("Certificate expired"); boost += 1.5; }
    else { const daysLeft = (expiry.getTime() - Date.now()) / 86400000; if (daysLeft < 30) { issues.push(`Certificate expires in ${Math.round(daysLeft)} days`); boost += 0.5; } }
  }
  const issuer = (tlsInfo.issuer as string) || "";
  if (issuer.toLowerCase().includes("self-signed") || issuer === "") { issues.push("Self-signed or untrusted certificate"); boost += 1.0; }
  return { vulnerabilityBoost: clamp(boost, 0, 3), breakdown: { issues, vulnerabilityImpact: boost } };
}

function scoreForms(forms: CrawlPageResult["forms"]) {
  if (!forms || forms.length === 0) {
    return { criticalityBoost: 0, operationalImpactBoost: 0, breakdown: { loginForms: 0, fileUploadForms: 0, criticalityImpact: 0, operationalImpact: 0 } };
  }
  let loginForms = 0, fileUploadForms = 0;
  for (const f of forms) { if (f.hasPasswordField) loginForms++; if (f.hasFileUpload) fileUploadForms++; }
  const criticalityBoost = clamp(loginForms * 1.0, 0, 2);
  const operationalImpactBoost = clamp(fileUploadForms * 0.8 + loginForms * 0.5, 0, 2);
  return { criticalityBoost, operationalImpactBoost, breakdown: { loginForms, fileUploadForms, criticalityImpact: criticalityBoost, operationalImpact: operationalImpactBoost } };
}

function scoreSurface(crawl: CrawlPageResult) {
  const internalLinks = crawl.internalLinks?.length || 0;
  const externalLinks = crawl.externalLinks?.length || 0;
  const scopeBoost = clamp(externalLinks * 0.05, 0, 1.5);
  const cascadingBoost = clamp(internalLinks * 0.02, 0, 1);
  return { scopeBoost, cascadingBoost, breakdown: { internalLinks, externalLinks, scopeImpact: scopeBoost, cascadingImpact: cascadingBoost } };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — POSTURE FINDING GENERATION
// ═══════════════════════════════════════════════════════════════════════

function generateCrawlPostureFindings(crawl: CrawlPageResult, hostname: string): CrawlPostureFinding[] {
  const findings: CrawlPostureFinding[] = [];
  const now = Date.now();

  // Critical/high exposed paths → confirmed findings
  for (const p of (crawl.exposedPaths || [])) {
    if (p.severity === "critical" || p.severity === "high") {
      findings.push({
        id: `crawl-path-${hostname}-${p.path.replace(/[^a-z0-9]/gi, "_")}-${now}`,
        category: "Web Exposure",
        title: `Exposed ${(p.type || "path").replace(/_/g, " ")}: ${p.path}`,
        severity: p.severity === "critical" ? 9 : 7,
        confidence: 1.0,
        description: p.description,
        evidenceDetail: `HTTP ${p.status} response at ${p.path} — confirmed accessible`,
        corroborationTier: "confirmed",
        remediation: `Restrict access to ${p.path} via web server configuration or remove the file`,
        source: "web_crawler",
      });
    }
  }

  // Missing critical security headers → confirmed
  const missingCritical = crawl.securityHeaders?.missing?.filter(h => h.severity === "high") || [];
  if (missingCritical.length > 0) {
    findings.push({
      id: `crawl-headers-${hostname}-${now}`,
      category: "Web Security Headers",
      title: `Missing critical security headers: ${missingCritical.map(h => h.name).join(", ")}`,
      severity: 6,
      confidence: 1.0,
      description: `${missingCritical.length} critical security headers missing, leaving the application vulnerable to XSS, clickjacking, and protocol downgrade attacks`,
      evidenceDetail: `Confirmed via HTTP response header analysis: ${missingCritical.map(h => h.name).join(", ")}`,
      corroborationTier: "confirmed",
      remediation: `Add the following headers: ${missingCritical.map(h => h.name).join(", ")}`,
      source: "web_crawler",
    });
  }

  // Insecure session cookies → confirmed
  const sessionCookies = (crawl.cookies || []).filter(c =>
    /session|sid|token|auth|jwt/i.test(c.name) && (!c.secure || !c.httpOnly)
  );
  if (sessionCookies.length > 0) {
    findings.push({
      id: `crawl-cookies-${hostname}-${now}`,
      category: "Web Session Security",
      title: `Insecure session cookies: ${sessionCookies.map(c => c.name).join(", ")}`,
      severity: 7,
      confidence: 1.0,
      description: `Session cookies lack Secure and/or HttpOnly flags, enabling session hijacking`,
      evidenceDetail: `Confirmed via Set-Cookie header analysis: ${sessionCookies.map(c => `${c.name} (Secure=${c.secure}, HttpOnly=${c.httpOnly})`).join("; ")}`,
      corroborationTier: "confirmed",
      remediation: `Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies`,
      source: "web_crawler",
    });
  }

  // TLS issues → confirmed
  if (!crawl.tlsInfo) {
    findings.push({
      id: `crawl-tls-${hostname}-${now}`,
      category: "Transport Security",
      title: "No TLS/SSL encryption detected",
      severity: 8,
      confidence: 1.0,
      description: "The web application does not use TLS/SSL encryption, transmitting all data in plaintext",
      evidenceDetail: "No TLS certificate information returned during crawl",
      corroborationTier: "confirmed",
      remediation: "Enable TLS/SSL with a valid certificate from a trusted CA",
      source: "web_crawler",
    });
  } else {
    const validTo = crawl.tlsInfo.validTo as string;
    if (validTo && new Date(validTo) < new Date()) {
      findings.push({
        id: `crawl-tls-expired-${hostname}-${now}`,
        category: "Transport Security",
        title: "Expired TLS certificate",
        severity: 7,
        confidence: 1.0,
        description: `TLS certificate expired on ${validTo}`,
        evidenceDetail: `Certificate validTo: ${validTo}`,
        corroborationTier: "confirmed",
        remediation: "Renew the TLS certificate immediately",
        source: "web_crawler",
      });
    }
  }

  // Server version disclosure → probable
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
        source: "web_crawler",
      });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — MAIN INTEGRATION FUNCTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute Hybrid Risk adjustments from web crawler results.
 * Returns additive adjustments to apply on top of existing scores.
 */
export function computeCrawlCarverAdjustment(crawl: CrawlPageResult, hostname: string): CrawlCarverAdjustment {
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
    recognizability: clamp(techResult.recognizabilityBoost, 0, 3.5),
  };

  const shock = {
    scope: clamp(surfaceResult.scopeBoost, 0, 2),
    handling: clamp(headerResult.handlingBoost, 0, 3),
    operationalImpact: clamp(formResult.operationalImpactBoost, 0, 2),
    cascadingEffects: clamp(surfaceResult.cascadingBoost, 0, 1.5),
    knowledge: clamp(techResult.knowledgeBoost, 0, 3),
  };

  const criticalFindings = (crawl.findings || []).filter(f => f.severity === "critical").length;
  const highFindings = (crawl.findings || []).filter(f => f.severity === "high").length;
  const likelihoodBoost = clamp(criticalFindings * 0.08 + highFindings * 0.04, 0, 0.25);

  const contextAdjustment = {
    exposureBoost: clamp((pathResult.accessibilityBoost > 1 ? 0.15 : 0) + (cookieResult.vulnerabilityBoost > 1 ? 0.05 : 0), 0, 0.2),
    recognizabilityBoost: clamp(techResult.recognizabilityBoost > 1 ? 0.1 : 0, 0, 0.15),
    confidenceBoost: clamp(crawl.httpStatus === 200 ? 0.15 : 0.05, 0, 0.2),
  };

  const totalCarverBoost = Object.values(carver).reduce((a, b) => a + b, 0);
  const totalShockBoost = Object.values(shock).reduce((a, b) => a + b, 0);
  const maxPossibleBoost = 34;
  const overallWebVulnScore = clamp(Math.round(((totalCarverBoost + totalShockBoost) / maxPossibleBoost) * 100), 0, 100);
  const assessmentConfidence = crawl.httpStatus === 200 ? 0.85 : crawl.httpStatus && crawl.httpStatus < 400 ? 0.7 : crawl.httpStatus && crawl.httpStatus < 500 ? 0.4 : 0.2;

  const breakdown: CrawlScoreBreakdown = {
    headerScore: headerResult.breakdown,
    exposedPathScore: pathResult.breakdown,
    cookieScore: cookieResult.breakdown,
    technologyScore: techResult.breakdown,
    tlsScore: tlsResult.breakdown,
    formScore: formResult.breakdown,
    surfaceScore: surfaceResult.breakdown,
    overallWebVulnScore,
    assessmentConfidence,
  };

  const postureFindings = generateCrawlPostureFindings(crawl, hostname);

  return { carver, shock, likelihoodBoost, contextAdjustment, breakdown, postureFindings };
}

/**
 * Apply crawl-derived Hybrid Risk adjustments to existing scores.
 */
export function applyCrawlAdjustments(
  existingCarver: { criticality: number; accessibility: number; recuperability: number; vulnerability: number; effect: number; recognizability: number },
  existingShock: { scope: number; handling: number; operationalImpact: number; cascadingEffects: number; knowledge: number },
  adjustment: CrawlCarverAdjustment,
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
 * Aggregate multiple crawl results for a single asset (e.g., multiple pages).
 * Takes the maximum adjustment across all crawled pages for each dimension.
 */
export function aggregateCrawlAdjustments(adjustments: CrawlCarverAdjustment[]): CrawlCarverAdjustment | null {
  if (adjustments.length === 0) return null;
  if (adjustments.length === 1) return adjustments[0];

  const allFindings: CrawlPostureFinding[] = [];
  const seenFindingIds = new Set<string>();

  // Take max across all adjustments for each dimension
  const result: CrawlCarverAdjustment = {
    carver: { criticality: 0, accessibility: 0, recuperability: 0, vulnerability: 0, effect: 0, recognizability: 0 },
    shock: { scope: 0, handling: 0, operationalImpact: 0, cascadingEffects: 0, knowledge: 0 },
    likelihoodBoost: 0,
    contextAdjustment: { exposureBoost: 0, recognizabilityBoost: 0, confidenceBoost: 0 },
    breakdown: adjustments[0].breakdown, // Use first breakdown as representative
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

    // Deduplicate posture findings by category+title pattern
    for (const f of adj.postureFindings) {
      const key = `${f.category}:${f.title.substring(0, 50)}`;
      if (!seenFindingIds.has(key)) {
        seenFindingIds.add(key);
        allFindings.push(f);
      }
    }
  }

  // Update overall score from aggregated values
  const totalCarverBoost = Object.values(result.carver).reduce((a, b) => a + b, 0);
  const totalShockBoost = Object.values(result.shock).reduce((a, b) => a + b, 0);
  result.breakdown.overallWebVulnScore = clamp(Math.round(((totalCarverBoost + totalShockBoost) / 34) * 100), 0, 100);
  result.breakdown.assessmentConfidence = Math.max(...adjustments.map(a => a.breakdown.assessmentConfidence));
  result.postureFindings = allFindings;

  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — HELPERS
// ═══════════════════════════════════════════════════════════════════════

function parseVersion(v: string): number[] | null {
  const parts = v.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!parts) return null;
  return [parseInt(parts[1], 10), parseInt(parts[2], 10), parseInt(parts[3] || "0", 10)];
}

function isOlderThan(current: number[], safe: number[]): boolean {
  for (let i = 0; i < 3; i++) {
    if (current[i] < safe[i]) return true;
    if (current[i] > safe[i]) return false;
  }
  return false;
}
