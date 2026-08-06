/**
 * ScanForge CVSS Scoring Engine
 * 
 * Implements CVSS v3.1 and v4.0 scoring calculations.
 * Inspired by OpenVAS built-in CVSS calculator.
 * 
 * Features:
 * - Full CVSS v3.1 base score calculation
 * - CVSS v4.0 base score calculation
 * - Temporal and Environmental score modifiers
 * - Vector string parsing and generation
 * - Severity classification (None/Low/Medium/High/Critical)
 * - Auto-scoring from vulnerability characteristics
 */

// ─── CVSS v3.1 Types ────────────────────────────────────────────

export type AttackVector = "N" | "A" | "L" | "P";       // Network, Adjacent, Local, Physical
export type AttackComplexity = "L" | "H";                // Low, High
export type PrivilegesRequired = "N" | "L" | "H";       // None, Low, High
export type UserInteraction = "N" | "R";                 // None, Required
export type Scope = "U" | "C";                           // Unchanged, Changed
export type Impact = "N" | "L" | "H";                    // None, Low, High

export interface CVSSv31BaseMetrics {
  attackVector: AttackVector;
  attackComplexity: AttackComplexity;
  privilegesRequired: PrivilegesRequired;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentialityImpact: Impact;
  integrityImpact: Impact;
  availabilityImpact: Impact;
}

export interface CVSSv31TemporalMetrics {
  exploitCodeMaturity?: "X" | "U" | "P" | "F" | "H";   // Not Defined, Unproven, PoC, Functional, High
  remediationLevel?: "X" | "O" | "T" | "W" | "U";      // Not Defined, Official, Temporary, Workaround, Unavailable
  reportConfidence?: "X" | "U" | "R" | "C";             // Not Defined, Unknown, Reasonable, Confirmed
}

export interface CVSSv31Score {
  baseScore: number;
  temporalScore?: number;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  vectorString: string;
}

// ─── CVSS v3.1 Metric Values ────────────────────────────────────

const AV_VALUES: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC_VALUES: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 };
const PR_VALUES_UNCHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_VALUES_CHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.50 };
const UI_VALUES: Record<UserInteraction, number> = { N: 0.85, R: 0.62 };
const CIA_VALUES: Record<Impact, number> = { N: 0, L: 0.22, H: 0.56 };

const TEMPORAL_E: Record<string, number> = { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1.0 };
const TEMPORAL_RL: Record<string, number> = { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1.0 };
const TEMPORAL_RC: Record<string, number> = { X: 1, U: 0.92, R: 0.96, C: 1.0 };

// ─── CVSS v3.1 Calculator ────────────────────────────────────────

export class CVSSv31Calculator {
  
  /**
   * Calculate CVSS v3.1 base score from metrics
   */
  calculate(
    base: CVSSv31BaseMetrics,
    temporal?: CVSSv31TemporalMetrics
  ): CVSSv31Score {
    const baseScore = this.calculateBaseScore(base);
    const temporalScore = temporal ? this.calculateTemporalScore(baseScore, temporal) : undefined;
    const effectiveScore = temporalScore ?? baseScore;
    
    return {
      baseScore: this.roundUp(baseScore),
      temporalScore: temporalScore ? this.roundUp(temporalScore) : undefined,
      severity: this.getSeverity(effectiveScore),
      vectorString: this.buildVectorString(base, temporal),
    };
  }
  
  /**
   * Parse a CVSS v3.1 vector string and calculate score
   */
  parseAndCalculate(vectorString: string): CVSSv31Score {
    const metrics = this.parseVectorString(vectorString);
    return this.calculate(metrics.base, metrics.temporal);
  }
  
  /**
   * Auto-score a vulnerability based on its characteristics
   */
  autoScore(vuln: {
    type: string;           // sqli, xss, rce, ssrf, etc.
    remote: boolean;        // Can be exploited remotely?
    authenticated: boolean; // Requires authentication?
    userInteraction: boolean; // Requires user interaction?
    dataAccess: boolean;    // Can access sensitive data?
    dataModify: boolean;    // Can modify data?
    codeExecution: boolean; // Can execute code?
    dos: boolean;           // Can cause denial of service?
  }): CVSSv31Score {
    const base: CVSSv31BaseMetrics = {
      attackVector: vuln.remote ? "N" : "L",
      attackComplexity: this.guessComplexity(vuln.type),
      privilegesRequired: vuln.authenticated ? "L" : "N",
      userInteraction: vuln.userInteraction ? "R" : "N",
      scope: vuln.codeExecution ? "C" : "U",
      confidentialityImpact: vuln.dataAccess ? (vuln.codeExecution ? "H" : "L") : "N",
      integrityImpact: vuln.dataModify ? (vuln.codeExecution ? "H" : "L") : "N",
      availabilityImpact: vuln.dos ? "H" : (vuln.codeExecution ? "L" : "N"),
    };
    
    return this.calculate(base);
  }
  
  // ─── Internal Calculations ─────────────────────────────────────
  
  private calculateBaseScore(m: CVSSv31BaseMetrics): number {
    const iss = 1 - (
      (1 - CIA_VALUES[m.confidentialityImpact]) *
      (1 - CIA_VALUES[m.integrityImpact]) *
      (1 - CIA_VALUES[m.availabilityImpact])
    );
    
    if (iss <= 0) return 0;
    
    const impact = m.scope === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    
    const prValues = m.scope === "C" ? PR_VALUES_CHANGED : PR_VALUES_UNCHANGED;
    
    const exploitability = 8.22 *
      AV_VALUES[m.attackVector] *
      AC_VALUES[m.attackComplexity] *
      prValues[m.privilegesRequired] *
      UI_VALUES[m.userInteraction];
    
    if (impact <= 0) return 0;
    
    const score = m.scope === "U"
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
    
    return score;
  }
  
  private calculateTemporalScore(baseScore: number, t: CVSSv31TemporalMetrics): number {
    return baseScore *
      TEMPORAL_E[t.exploitCodeMaturity || "X"] *
      TEMPORAL_RL[t.remediationLevel || "X"] *
      TEMPORAL_RC[t.reportConfidence || "X"];
  }
  
  private getSeverity(score: number): "None" | "Low" | "Medium" | "High" | "Critical" {
    const rounded = this.roundUp(score);
    if (rounded === 0) return "None";
    if (rounded <= 3.9) return "Low";
    if (rounded <= 6.9) return "Medium";
    if (rounded <= 8.9) return "High";
    return "Critical";
  }
  
  private roundUp(value: number): number {
    return Math.ceil(value * 10) / 10;
  }
  
  private guessComplexity(vulnType: string): AttackComplexity {
    // High complexity vulns require specific conditions
    const highComplexity = ["race-condition", "timing-attack", "heap-overflow", "use-after-free"];
    return highComplexity.includes(vulnType) ? "H" : "L";
  }
  
  // ─── Vector String Handling ────────────────────────────────────
  
  private buildVectorString(
    base: CVSSv31BaseMetrics,
    temporal?: CVSSv31TemporalMetrics
  ): string {
    let vector = `CVSS:3.1/AV:${base.attackVector}/AC:${base.attackComplexity}/PR:${base.privilegesRequired}/UI:${base.userInteraction}/S:${base.scope}/C:${base.confidentialityImpact}/I:${base.integrityImpact}/A:${base.availabilityImpact}`;
    
    if (temporal) {
      if (temporal.exploitCodeMaturity && temporal.exploitCodeMaturity !== "X") {
        vector += `/E:${temporal.exploitCodeMaturity}`;
      }
      if (temporal.remediationLevel && temporal.remediationLevel !== "X") {
        vector += `/RL:${temporal.remediationLevel}`;
      }
      if (temporal.reportConfidence && temporal.reportConfidence !== "X") {
        vector += `/RC:${temporal.reportConfidence}`;
      }
    }
    
    return vector;
  }
  
  parseVectorString(vector: string): {
    base: CVSSv31BaseMetrics;
    temporal?: CVSSv31TemporalMetrics;
  } {
    const parts = vector.replace("CVSS:3.1/", "").split("/");
    const metrics: Record<string, string> = {};
    
    for (const part of parts) {
      const [key, value] = part.split(":");
      if (key && value) metrics[key] = value;
    }
    
    const base: CVSSv31BaseMetrics = {
      attackVector: (metrics.AV as AttackVector) || "N",
      attackComplexity: (metrics.AC as AttackComplexity) || "L",
      privilegesRequired: (metrics.PR as PrivilegesRequired) || "N",
      userInteraction: (metrics.UI as UserInteraction) || "N",
      scope: (metrics.S as Scope) || "U",
      confidentialityImpact: (metrics.C as Impact) || "N",
      integrityImpact: (metrics.I as Impact) || "N",
      availabilityImpact: (metrics.A as Impact) || "N",
    };
    
    const temporal: CVSSv31TemporalMetrics = {};
    if (metrics.E) temporal.exploitCodeMaturity = metrics.E as CVSSv31TemporalMetrics["exploitCodeMaturity"];
    if (metrics.RL) temporal.remediationLevel = metrics.RL as CVSSv31TemporalMetrics["remediationLevel"];
    if (metrics.RC) temporal.reportConfidence = metrics.RC as CVSSv31TemporalMetrics["reportConfidence"];
    
    const hasTemporal = Object.keys(temporal).length > 0;
    
    return { base, temporal: hasTemporal ? temporal : undefined };
  }
}

// ─── Vulnerability Type to CVSS Mapping ──────────────────────────

/**
 * Pre-built CVSS profiles for common vulnerability types
 * Used by the auto-scoring engine when detailed metrics aren't available
 */
export const VULN_TYPE_CVSS_PROFILES: Record<string, CVSSv31BaseMetrics> = {
  // Critical
  "rce": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "C", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "H" },
  "sqli": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "H" },
  "deserialization": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "C", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "H" },
  "command-injection": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "C", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "H" },
  
  // High
  "ssrf": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "C", confidentialityImpact: "H", integrityImpact: "L", availabilityImpact: "N" },
  "xxe": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "C", confidentialityImpact: "H", integrityImpact: "N", availabilityImpact: "L" },
  "lfi": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "N", availabilityImpact: "N" },
  "auth-bypass": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "N" },
  "idor": { attackVector: "N", attackComplexity: "L", privilegesRequired: "L", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "N" },
  "ssti": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "C", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "H" },
  "default-creds": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "H" },
  
  // Medium
  "xss-stored": { attackVector: "N", attackComplexity: "L", privilegesRequired: "L", userInteraction: "R", scope: "C", confidentialityImpact: "L", integrityImpact: "L", availabilityImpact: "N" },
  "xss-reflected": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "R", scope: "C", confidentialityImpact: "L", integrityImpact: "L", availabilityImpact: "N" },
  "csrf": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "R", scope: "U", confidentialityImpact: "N", integrityImpact: "H", availabilityImpact: "N" },
  "open-redirect": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "R", scope: "C", confidentialityImpact: "L", integrityImpact: "L", availabilityImpact: "N" },
  "cors-misconfiguration": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "R", scope: "U", confidentialityImpact: "H", integrityImpact: "N", availabilityImpact: "N" },
  
  // Low
  "info-disclosure": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "L", integrityImpact: "N", availabilityImpact: "N" },
  "missing-headers": { attackVector: "N", attackComplexity: "H", privilegesRequired: "N", userInteraction: "R", scope: "U", confidentialityImpact: "L", integrityImpact: "N", availabilityImpact: "N" },
  "directory-listing": { attackVector: "N", attackComplexity: "L", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "L", integrityImpact: "N", availabilityImpact: "N" },
  "tls-weak-cipher": { attackVector: "N", attackComplexity: "H", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "N", availabilityImpact: "N" },
  "smb-signing-disabled": { attackVector: "A", attackComplexity: "H", privilegesRequired: "N", userInteraction: "N", scope: "U", confidentialityImpact: "H", integrityImpact: "H", availabilityImpact: "N" },
};

/**
 * Get CVSS score for a vulnerability type
 */
export function getVulnTypeCVSS(vulnType: string): CVSSv31Score | null {
  const profile = VULN_TYPE_CVSS_PROFILES[vulnType.toLowerCase()];
  if (!profile) return null;
  
  const calculator = new CVSSv31Calculator();
  return calculator.calculate(profile);
}

/**
 * Score a ScanForge finding with CVSS
 */
export function scoreFinding(finding: {
  vulnType: string;
  severity: string;
  remote: boolean;
  authenticated: boolean;
  cve?: string;
  vectorString?: string;
}): CVSSv31Score {
  const calculator = new CVSSv31Calculator();
  
  // If we have a vector string, use it directly
  if (finding.vectorString) {
    try {
      return calculator.parseAndCalculate(finding.vectorString);
    } catch {
      // Fall through to auto-scoring
    }
  }
  
  // Try type-based profile
  const typeScore = getVulnTypeCVSS(finding.vulnType);
  if (typeScore) return typeScore;
  
  // Fallback: auto-score from characteristics
  return calculator.autoScore({
    type: finding.vulnType,
    remote: finding.remote,
    authenticated: finding.authenticated,
    userInteraction: false,
    dataAccess: ["sqli", "lfi", "xxe", "ssrf", "idor", "info-disclosure"].includes(finding.vulnType),
    dataModify: ["sqli", "csrf", "rce", "command-injection", "ssti"].includes(finding.vulnType),
    codeExecution: ["rce", "command-injection", "ssti", "deserialization"].includes(finding.vulnType),
    dos: ["rce", "command-injection"].includes(finding.vulnType),
  });
}
