/**
 * Compensating Control Awareness
 * 
 * Detects compensating controls (WAF, IPS, EDR, network segmentation, etc.)
 * from OSINT signals and adjusts finding severity accordingly. A critical RCE
 * behind a WAF + network segmentation is less exploitable than one on a
 * directly exposed host.
 * 
 * Matches Picus Security's contextual severity re-scoring capability.
 * 
 * @module compensating-controls
 */

// ─── Types ─────────────────────────────────────────────────────────

export type ControlCategory =
  | "waf"               // Web Application Firewall (Cloudflare, Akamai, AWS WAF, etc.)
  | "cdn"               // CDN with DDoS protection (Cloudflare, Fastly, etc.)
  | "ips"               // Intrusion Prevention System
  | "edr"               // Endpoint Detection & Response
  | "network_segmentation" // Evidence of network segmentation
  | "mfa"               // Multi-Factor Authentication detected
  | "rate_limiting"     // Rate limiting detected
  | "hsts"              // HTTP Strict Transport Security
  | "csp"               // Content Security Policy
  | "cors_strict"       // Strict CORS policy
  | "certificate_pinning" // Certificate pinning detected
  | "api_gateway"       // API gateway (Kong, Apigee, etc.)
  | "bot_protection"    // Bot protection (reCAPTCHA, hCaptcha, etc.)
  | "geo_blocking"      // Geographic IP blocking detected
  | "vpn_required";     // VPN/zero-trust access required

export interface DetectedControl {
  category: ControlCategory;
  name: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  mitigationFactor: number; // 0.0 - 1.0, how much this control reduces exploitability
  affectedAttackVectors: string[]; // Which attack vectors this control mitigates
}

export interface ControlAssessment {
  controls: DetectedControl[];
  overallMitigationScore: number; // 0-100, higher = more protected
  severityAdjustment: number;     // Negative number to subtract from severity score
  adjustedSeverityLabel: string;  // "critical" → "high" if controls present
  rationale: string;
  controlCategories: ControlCategory[];
}

export interface ControlDetectionConfig {
  enableWafDetection: boolean;
  enableHeaderAnalysis: boolean;
  enableCdnDetection: boolean;
  enableSecurityHeaderScoring: boolean;
  minimumConfidence: "high" | "medium" | "low";
}

export const DEFAULT_CONTROL_CONFIG: ControlDetectionConfig = {
  enableWafDetection: true,
  enableHeaderAnalysis: true,
  enableCdnDetection: true,
  enableSecurityHeaderScoring: true,
  minimumConfidence: "low",
};

// ─── WAF / CDN Detection Signatures ───────────────────────────────

interface WafSignature {
  name: string;
  category: ControlCategory;
  headerPatterns: Array<{ header: string; pattern: RegExp }>;
  bodyPatterns?: RegExp[];
  mitigationFactor: number;
  affectedVectors: string[];
}

const WAF_SIGNATURES: WafSignature[] = [
  {
    name: "Cloudflare",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /cloudflare/i },
      { header: "cf-ray", pattern: /.+/ },
      { header: "cf-cache-status", pattern: /.+/ },
    ],
    mitigationFactor: 0.35,
    affectedVectors: ["T1190", "T1189", "T1059", "T1203"],
  },
  {
    name: "Akamai",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /akamai/i },
      { header: "x-akamai-transformed", pattern: /.+/ },
      { header: "x-akamai-request-id", pattern: /.+/ },
    ],
    mitigationFactor: 0.35,
    affectedVectors: ["T1190", "T1189", "T1059"],
  },
  {
    name: "AWS WAF / CloudFront",
    category: "waf",
    headerPatterns: [
      { header: "x-amz-cf-id", pattern: /.+/ },
      { header: "x-amzn-waf-action", pattern: /.+/ },
      { header: "server", pattern: /cloudfront/i },
    ],
    mitigationFactor: 0.30,
    affectedVectors: ["T1190", "T1189"],
  },
  {
    name: "Imperva / Incapsula",
    category: "waf",
    headerPatterns: [
      { header: "x-iinfo", pattern: /.+/ },
      { header: "x-cdn", pattern: /incapsula/i },
    ],
    mitigationFactor: 0.35,
    affectedVectors: ["T1190", "T1189", "T1059"],
  },
  {
    name: "F5 BIG-IP ASM",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /big-?ip/i },
      { header: "x-wa-info", pattern: /.+/ },
    ],
    mitigationFactor: 0.30,
    affectedVectors: ["T1190", "T1059"],
  },
  {
    name: "Sucuri",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /sucuri/i },
      { header: "x-sucuri-id", pattern: /.+/ },
    ],
    mitigationFactor: 0.25,
    affectedVectors: ["T1190"],
  },
  {
    name: "Fastly",
    category: "cdn",
    headerPatterns: [
      { header: "server", pattern: /fastly/i },
      { header: "x-served-by", pattern: /cache-/i },
      { header: "via", pattern: /varnish/i },
    ],
    mitigationFactor: 0.15,
    affectedVectors: ["T1499"],
  },
  {
    name: "ModSecurity",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /mod_security/i },
    ],
    mitigationFactor: 0.20,
    affectedVectors: ["T1190", "T1059"],
  },
];

// ─── Security Header Analysis ──────────────────────────────────────

interface SecurityHeaderCheck {
  header: string;
  category: ControlCategory;
  name: string;
  validator: (value: string) => boolean;
  mitigationFactor: number;
  affectedVectors: string[];
}

const SECURITY_HEADER_CHECKS: SecurityHeaderCheck[] = [
  {
    header: "strict-transport-security",
    category: "hsts",
    name: "HSTS",
    validator: (v) => v.includes("max-age=") && parseInt(v.match(/max-age=(\d+)/)?.[1] || "0") >= 31536000,
    mitigationFactor: 0.10,
    affectedVectors: ["T1557"],
  },
  {
    header: "content-security-policy",
    category: "csp",
    name: "Content Security Policy",
    validator: (v) => !v.includes("unsafe-inline") || v.includes("nonce-"),
    mitigationFactor: 0.15,
    affectedVectors: ["T1189", "T1059.007"],
  },
  {
    header: "x-frame-options",
    category: "csp",
    name: "X-Frame-Options",
    validator: (v) => v.toLowerCase() === "deny" || v.toLowerCase() === "sameorigin",
    mitigationFactor: 0.05,
    affectedVectors: ["T1189"],
  },
  {
    header: "x-content-type-options",
    category: "csp",
    name: "X-Content-Type-Options",
    validator: (v) => v.toLowerCase() === "nosniff",
    mitigationFactor: 0.05,
    affectedVectors: ["T1189"],
  },
  {
    header: "x-xss-protection",
    category: "csp",
    name: "XSS Protection",
    validator: (v) => v.startsWith("1"),
    mitigationFactor: 0.05,
    affectedVectors: ["T1189"],
  },
];

// ─── Core Detection Functions ──────────────────────────────────────

/**
 * Detect compensating controls from HTTP response headers.
 */
export function detectControlsFromHeaders(
  headers: Record<string, string>,
  config: ControlDetectionConfig = DEFAULT_CONTROL_CONFIG
): DetectedControl[] {
  const controls: DetectedControl[] = [];
  const normalizedHeaders: Record<string, string> = {};
  
  // Normalize header names to lowercase
  for (const [key, value] of Object.entries(headers)) {
    normalizedHeaders[key.toLowerCase()] = value;
  }
  
  // WAF / CDN detection
  if (config.enableWafDetection) {
    for (const sig of WAF_SIGNATURES) {
      let matchCount = 0;
      let evidence = "";
      
      for (const { header, pattern } of sig.headerPatterns) {
        const value = normalizedHeaders[header.toLowerCase()];
        if (value && pattern.test(value)) {
          matchCount++;
          evidence += `${header}: ${value}; `;
        }
      }
      
      if (matchCount > 0) {
        const confidence: DetectedControl["confidence"] =
          matchCount >= 2 ? "high" : matchCount === 1 ? "medium" : "low";
        
        controls.push({
          category: sig.category,
          name: sig.name,
          confidence,
          evidence: evidence.trim(),
          mitigationFactor: sig.mitigationFactor,
          affectedAttackVectors: sig.affectedVectors,
        });
      }
    }
  }
  
  // Security header analysis
  if (config.enableHeaderAnalysis) {
    for (const check of SECURITY_HEADER_CHECKS) {
      const value = normalizedHeaders[check.header.toLowerCase()];
      if (value && check.validator(value)) {
        controls.push({
          category: check.category,
          name: check.name,
          confidence: "high",
          evidence: `${check.header}: ${value}`,
          mitigationFactor: check.mitigationFactor,
          affectedAttackVectors: check.affectedVectors,
        });
      }
    }
  }
  
  return controls;
}

/**
 * Detect controls from OSINT observations (technologies, DNS records, etc.)
 */
export function detectControlsFromObservations(
  observations: Array<{
    assetType: string;
    value: string;
    source: string;
    metadata?: Record<string, any>;
  }>
): DetectedControl[] {
  const controls: DetectedControl[] = [];
  const seen = new Set<string>();
  
  for (const obs of observations) {
    const valueLower = (obs.value || "").toLowerCase();
    const metaStr = JSON.stringify(obs.metadata || {}).toLowerCase();
    const combined = `${valueLower} ${metaStr}`;
    
    // CDN / WAF detection from DNS/technology observations
    if (obs.assetType === "technology" || obs.assetType === "dns_record") {
      // Cloudflare
      if (combined.includes("cloudflare") && !seen.has("cloudflare")) {
        seen.add("cloudflare");
        controls.push({
          category: "waf",
          name: "Cloudflare WAF",
          confidence: "high",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.35,
          affectedAttackVectors: ["T1190", "T1189", "T1059", "T1499"],
        });
      }
      
      // Akamai
      if (combined.includes("akamai") && !seen.has("akamai")) {
        seen.add("akamai");
        controls.push({
          category: "waf",
          name: "Akamai WAF",
          confidence: "high",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.35,
          affectedAttackVectors: ["T1190", "T1189"],
        });
      }
      
      // CrowdStrike / EDR
      if ((combined.includes("crowdstrike") || combined.includes("falcon")) && !seen.has("edr")) {
        seen.add("edr");
        controls.push({
          category: "edr",
          name: "CrowdStrike Falcon EDR",
          confidence: "medium",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.25,
          affectedAttackVectors: ["T1059", "T1203", "T1068", "T1105"],
        });
      }
      
      // SentinelOne EDR
      if (combined.includes("sentinelone") && !seen.has("edr")) {
        seen.add("edr");
        controls.push({
          category: "edr",
          name: "SentinelOne EDR",
          confidence: "medium",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.25,
          affectedAttackVectors: ["T1059", "T1203", "T1068"],
        });
      }
    }
    
    // MFA detection
    if (obs.assetType === "technology") {
      if ((combined.includes("okta") || combined.includes("duo") || combined.includes("auth0")) && !seen.has("mfa")) {
        seen.add("mfa");
        controls.push({
          category: "mfa",
          name: combined.includes("okta") ? "Okta MFA" : combined.includes("duo") ? "Cisco Duo MFA" : "Auth0 MFA",
          confidence: "medium",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.30,
          affectedAttackVectors: ["T1078", "T1110", "T1133"],
        });
      }
    }
    
    // Bot protection
    if (combined.includes("recaptcha") || combined.includes("hcaptcha") || combined.includes("turnstile")) {
      if (!seen.has("bot_protection")) {
        seen.add("bot_protection");
        controls.push({
          category: "bot_protection",
          name: combined.includes("recaptcha") ? "Google reCAPTCHA" : combined.includes("hcaptcha") ? "hCaptcha" : "Cloudflare Turnstile",
          confidence: "high",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.10,
          affectedAttackVectors: ["T1110", "T1499"],
        });
      }
    }
  }
  
  return controls;
}

// ─── Severity Adjustment ───────────────────────────────────────────

/**
 * Assess the overall compensating control posture and calculate severity adjustment.
 */
export function assessControls(
  controls: DetectedControl[],
  findingSeverity: "critical" | "high" | "medium" | "low",
  findingAttackVector?: string
): ControlAssessment {
  if (controls.length === 0) {
    return {
      controls: [],
      overallMitigationScore: 0,
      severityAdjustment: 0,
      adjustedSeverityLabel: findingSeverity,
      rationale: "No compensating controls detected. Finding severity unchanged.",
      controlCategories: [],
    };
  }
  
  // Calculate overall mitigation score
  // Use diminishing returns: each additional control adds less
  let cumulativeMitigation = 0;
  const sortedControls = [...controls].sort((a, b) => b.mitigationFactor - a.mitigationFactor);
  
  for (const control of sortedControls) {
    // If the finding has a specific attack vector, only count controls that mitigate it
    if (findingAttackVector && !control.affectedAttackVectors.includes(findingAttackVector)) {
      continue;
    }
    
    // Diminishing returns formula: each control adds (1 - current) * factor
    const effectiveFactor = (1 - cumulativeMitigation) * control.mitigationFactor;
    cumulativeMitigation += effectiveFactor;
  }
  
  const overallMitigationScore = Math.round(cumulativeMitigation * 100);
  
  // Calculate severity adjustment (0 to -2 levels)
  const severityLevels = ["low", "medium", "high", "critical"];
  const currentLevel = severityLevels.indexOf(findingSeverity);
  
  let levelReduction = 0;
  if (overallMitigationScore >= 60) levelReduction = 2;
  else if (overallMitigationScore >= 35) levelReduction = 1;
  
  const adjustedLevel = Math.max(0, currentLevel - levelReduction);
  const adjustedSeverityLabel = severityLevels[adjustedLevel] as ControlAssessment["adjustedSeverityLabel"];
  
  // Build rationale
  const controlNames = controls.map(c => c.name).join(", ");
  const categories = Array.from(new Set(controls.map(c => c.category)));
  
  let rationale: string;
  if (levelReduction > 0) {
    rationale = `${controls.length} compensating control(s) detected (${controlNames}). Overall mitigation score: ${overallMitigationScore}%. Severity adjusted from ${findingSeverity} to ${adjustedSeverityLabel} (${levelReduction} level${levelReduction > 1 ? "s" : ""} reduced). Note: controls reduce exploitability but do not eliminate the underlying vulnerability.`;
  } else {
    rationale = `${controls.length} compensating control(s) detected (${controlNames}). Overall mitigation score: ${overallMitigationScore}%. Insufficient to warrant severity reduction. Finding remains ${findingSeverity}.`;
  }
  
  return {
    controls,
    overallMitigationScore,
    severityAdjustment: -levelReduction,
    adjustedSeverityLabel,
    rationale,
    controlCategories: categories,
  };
}

/**
 * Batch assess controls for multiple findings.
 */
export function batchAssessControls(
  controls: DetectedControl[],
  findings: Array<{
    id: string;
    severity: "critical" | "high" | "medium" | "low";
    attackVector?: string;
  }>
): Map<string, ControlAssessment> {
  const results = new Map<string, ControlAssessment>();
  
  for (const finding of findings) {
    results.set(finding.id, assessControls(controls, finding.severity, finding.attackVector));
  }
  
  return results;
}


// ─── Router-facing wrapper functions ──────────────────────────────

/**
 * Evaluate compensating controls for a given vulnerability context.
 * Used by the compensating-controls router.
 */
export async function evaluateCompensatingControls(params: {
  cveId?: string;
  techniqueId?: string;
  targetService?: string;
  targetPort?: number;
  existingControls: string[];
}): Promise<{
  controls: DetectedControl[];
  assessment: ControlAssessment;
  recommendations: string[];
}> {
  // Build simulated controls from the existingControls list
  const controls: DetectedControl[] = [];
  
  for (const controlName of params.existingControls) {
    const lower = controlName.toLowerCase();
    let category: ControlCategory = "waf";
    let mitigationFactor = 0.15;
    const affectedVectors: string[] = [];
    
    if (lower.includes("waf")) { category = "waf"; mitigationFactor = 0.35; affectedVectors.push("T1190", "T1189"); }
    else if (lower.includes("edr")) { category = "edr"; mitigationFactor = 0.25; affectedVectors.push("T1059", "T1203"); }
    else if (lower.includes("ips")) { category = "ips"; mitigationFactor = 0.20; affectedVectors.push("T1190"); }
    else if (lower.includes("mfa")) { category = "mfa"; mitigationFactor = 0.30; affectedVectors.push("T1078", "T1110"); }
    else if (lower.includes("hsts")) { category = "hsts"; mitigationFactor = 0.10; affectedVectors.push("T1557"); }
    else if (lower.includes("csp")) { category = "csp"; mitigationFactor = 0.15; affectedVectors.push("T1189"); }
    else if (lower.includes("segment")) { category = "network_segmentation"; mitigationFactor = 0.25; affectedVectors.push("T1021"); }
    else if (lower.includes("cdn")) { category = "cdn"; mitigationFactor = 0.15; affectedVectors.push("T1499"); }
    else if (lower.includes("rate")) { category = "rate_limiting"; mitigationFactor = 0.10; affectedVectors.push("T1110", "T1499"); }
    
    controls.push({
      category,
      name: controlName,
      confidence: "medium",
      evidence: `User-declared control: ${controlName}`,
      mitigationFactor,
      affectedAttackVectors: affectedVectors,
    });
  }
  
  const assessment = assessControls(controls, "high", params.techniqueId);
  
  const recommendations: string[] = [];
  if (!controls.some(c => c.category === "waf")) recommendations.push("Consider deploying a WAF to protect web-facing assets.");
  if (!controls.some(c => c.category === "edr")) recommendations.push("Consider deploying EDR for endpoint protection.");
  if (!controls.some(c => c.category === "mfa")) recommendations.push("Enable MFA for all privileged accounts.");
  if (!controls.some(c => c.category === "hsts")) recommendations.push("Enable HSTS to prevent protocol downgrade attacks.");
  
  return { controls, assessment, recommendations };
}

/**
 * Get the full catalog of recognized compensating controls.
 * Used by the compensating-controls router.
 */
export function getControlCatalog(): Array<{
  category: ControlCategory;
  name: string;
  description: string;
  typicalMitigationFactor: number;
  affectedAttackVectors: string[];
}> {
  return [
    { category: "waf", name: "Web Application Firewall", description: "Filters malicious HTTP traffic (SQL injection, XSS, etc.)", typicalMitigationFactor: 0.35, affectedAttackVectors: ["T1190", "T1189", "T1059"] },
    { category: "cdn", name: "CDN with DDoS Protection", description: "Content delivery with DDoS mitigation", typicalMitigationFactor: 0.15, affectedAttackVectors: ["T1499"] },
    { category: "ips", name: "Intrusion Prevention System", description: "Network-based attack detection and prevention", typicalMitigationFactor: 0.20, affectedAttackVectors: ["T1190", "T1059"] },
    { category: "edr", name: "Endpoint Detection & Response", description: "Endpoint monitoring, detection, and response", typicalMitigationFactor: 0.25, affectedAttackVectors: ["T1059", "T1203", "T1068", "T1105"] },
    { category: "network_segmentation", name: "Network Segmentation", description: "Isolates critical assets from general network", typicalMitigationFactor: 0.25, affectedAttackVectors: ["T1021", "T1570"] },
    { category: "mfa", name: "Multi-Factor Authentication", description: "Requires multiple authentication factors", typicalMitigationFactor: 0.30, affectedAttackVectors: ["T1078", "T1110", "T1133"] },
    { category: "rate_limiting", name: "Rate Limiting", description: "Limits request frequency to prevent brute force", typicalMitigationFactor: 0.10, affectedAttackVectors: ["T1110", "T1499"] },
    { category: "hsts", name: "HTTP Strict Transport Security", description: "Enforces HTTPS connections", typicalMitigationFactor: 0.10, affectedAttackVectors: ["T1557"] },
    { category: "csp", name: "Content Security Policy", description: "Restricts content sources to prevent XSS", typicalMitigationFactor: 0.15, affectedAttackVectors: ["T1189", "T1059.007"] },
    { category: "cors_strict", name: "Strict CORS Policy", description: "Restricts cross-origin requests", typicalMitigationFactor: 0.10, affectedAttackVectors: ["T1189"] },
    { category: "api_gateway", name: "API Gateway", description: "Centralized API management with auth and rate limiting", typicalMitigationFactor: 0.20, affectedAttackVectors: ["T1190", "T1110"] },
    { category: "bot_protection", name: "Bot Protection", description: "CAPTCHA and bot detection mechanisms", typicalMitigationFactor: 0.10, affectedAttackVectors: ["T1110", "T1499"] },
    { category: "geo_blocking", name: "Geographic IP Blocking", description: "Blocks traffic from specific regions", typicalMitigationFactor: 0.10, affectedAttackVectors: ["T1190"] },
    { category: "vpn_required", name: "VPN / Zero Trust Access", description: "Requires VPN or zero-trust network access", typicalMitigationFactor: 0.35, affectedAttackVectors: ["T1190", "T1133", "T1078"] },
  ];
}

/**
 * Calculate risk adjustment based on active control IDs.
 * Used by the compensating-controls router.
 */
export function calculateRiskAdjustment(
  baseRiskScore: number,
  activeControlIds: string[]
): {
  baseRiskScore: number;
  adjustedRiskScore: number;
  reduction: number;
  reductionPercent: number;
  activeControls: string[];
  rationale: string;
} {
  const catalog = getControlCatalog();
  let cumulativeMitigation = 0;
  
  for (const controlId of activeControlIds) {
    const control = catalog.find(c => c.category === controlId || c.name.toLowerCase().includes(controlId.toLowerCase()));
    if (control) {
      const effectiveFactor = (1 - cumulativeMitigation) * control.typicalMitigationFactor;
      cumulativeMitigation += effectiveFactor;
    }
  }
  
  const reduction = baseRiskScore * cumulativeMitigation;
  const adjustedRiskScore = Math.max(0, Math.round((baseRiskScore - reduction) * 10) / 10);
  
  return {
    baseRiskScore,
    adjustedRiskScore,
    reduction: Math.round(reduction * 10) / 10,
    reductionPercent: Math.round(cumulativeMitigation * 100),
    activeControls: activeControlIds,
    rationale: `${activeControlIds.length} control(s) applied. Cumulative mitigation: ${Math.round(cumulativeMitigation * 100)}%. Risk reduced from ${baseRiskScore} to ${adjustedRiskScore}.`,
  };
}
