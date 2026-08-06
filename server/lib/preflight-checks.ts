/**
 * Exploit Confidence Pre-Flight Checks
 * 
 * Before executing an exploit or BAS test, run a series of pre-flight checks
 * to assess the likelihood of success. This reduces wasted test cycles and
 * improves the signal-to-noise ratio of validation results.
 * 
 * Checks include: service reachability, version fingerprinting, prerequisite
 * validation, environmental compatibility, and exploit maturity assessment.
 */

export interface PreFlightCheckInput {
  targetHost: string;
  targetPort?: number;
  service?: string;
  serviceVersion?: string;
  cveId?: string;
  exploitModule?: string;
  techniqueId?: string;
  requiresAuth?: boolean;
  authCredentials?: { username: string; password: string };
  protocol?: "tcp" | "udp" | "http" | "https";
}

export interface PreFlightResult {
  overallConfidence: number; // 0-100
  recommendation: "proceed" | "proceed_with_caution" | "skip" | "manual_review";
  checks: CheckResult[];
  estimatedSuccessRate: number; // 0-100
  reasoning: string;
  blockers: string[];
  warnings: string[];
}

export interface CheckResult {
  checkName: string;
  category: "reachability" | "version" | "prerequisite" | "environment" | "exploit_maturity";
  status: "pass" | "fail" | "warn" | "skip";
  confidence: number; // 0-100
  detail: string;
  durationMs: number;
}

// ─── Exploit Maturity Database ─────────────────────────────────────

interface ExploitMaturity {
  hasPublicExploit: boolean;
  exploitDbCount: number;
  metasploitModule: boolean;
  nucleiTemplate: boolean;
  weaponized: boolean;
  maturityScore: number; // 0-100
}

// Well-known CVEs with high exploit maturity
const KNOWN_EXPLOIT_MATURITY: Record<string, ExploitMaturity> = {
  "CVE-2021-44228": { hasPublicExploit: true, exploitDbCount: 50, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 100 },
  "CVE-2021-34527": { hasPublicExploit: true, exploitDbCount: 20, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 95 },
  "CVE-2023-44487": { hasPublicExploit: true, exploitDbCount: 10, metasploitModule: false, nucleiTemplate: true, weaponized: true, maturityScore: 85 },
  "CVE-2024-3400":  { hasPublicExploit: true, exploitDbCount: 8, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 90 },
  "CVE-2023-27997": { hasPublicExploit: true, exploitDbCount: 5, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 88 },
  "CVE-2021-26855": { hasPublicExploit: true, exploitDbCount: 30, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 98 },
  "CVE-2020-1472":  { hasPublicExploit: true, exploitDbCount: 15, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 95 },
  "CVE-2019-19781": { hasPublicExploit: true, exploitDbCount: 12, metasploitModule: true, nucleiTemplate: true, weaponized: true, maturityScore: 92 },
};

// ─── Service Fingerprint Patterns ──────────────────────────────────

const SERVICE_PATTERNS: Record<string, RegExp[]> = {
  apache: [/apache/i, /httpd/i],
  nginx: [/nginx/i],
  iis: [/microsoft-iis/i, /iis/i],
  openssh: [/openssh/i],
  openssl: [/openssl/i],
  tomcat: [/tomcat/i, /coyote/i],
  exchange: [/exchange/i, /owa/i],
  wordpress: [/wordpress/i, /wp-/i],
  jboss: [/jboss/i, /wildfly/i],
  weblogic: [/weblogic/i],
  jenkins: [/jenkins/i],
  elasticsearch: [/elasticsearch/i],
  redis: [/redis/i],
  mongodb: [/mongodb/i, /mongod/i],
  mysql: [/mysql/i, /mariadb/i],
  postgresql: [/postgresql/i, /postgres/i],
  mssql: [/microsoft sql/i, /mssql/i],
};

// ─── Check Functions ───────────────────────────────────────────────

/**
 * Check 1: Service reachability — can we reach the target?
 */
async function checkReachability(input: PreFlightCheckInput): Promise<CheckResult> {
  const start = Date.now();
  const port = input.targetPort || (input.protocol === "https" ? 443 : 80);
  
  try {
    const protocol = input.protocol || "https";
    const url = `${protocol}://${input.targetHost}:${port}`;
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    
    try {
      const response = await fetch(url, {
        method: "HEAD",
        signal: controller.signal,
        redirect: "manual",
      });
      clearTimeout(timeout);
      
      return {
        checkName: "Service Reachability",
        category: "reachability",
        status: "pass",
        confidence: 95,
        detail: `Target ${input.targetHost}:${port} is reachable (HTTP ${response.status}).`,
        durationMs: Date.now() - start,
      };
    } catch (fetchErr: any) {
      clearTimeout(timeout);
      if (fetchErr.name === "AbortError") {
        return {
          checkName: "Service Reachability",
          category: "reachability",
          status: "fail",
          confidence: 10,
          detail: `Target ${input.targetHost}:${port} timed out after 5s.`,
          durationMs: Date.now() - start,
        };
      }
      // Connection refused or DNS failure
      return {
        checkName: "Service Reachability",
        category: "reachability",
        status: "fail",
        confidence: 5,
        detail: `Target ${input.targetHost}:${port} unreachable: ${fetchErr.message}`,
        durationMs: Date.now() - start,
      };
    }
  } catch (err: any) {
    return {
      checkName: "Service Reachability",
      category: "reachability",
      status: "fail",
      confidence: 0,
      detail: `Reachability check failed: ${err.message}`,
      durationMs: Date.now() - start,
    };
  }
}

/**
 * Check 2: Version fingerprinting — does the service version match what the exploit targets?
 */
function checkVersionMatch(input: PreFlightCheckInput): CheckResult {
  const start = Date.now();
  
  if (!input.serviceVersion) {
    return {
      checkName: "Version Fingerprint",
      category: "version",
      status: "skip",
      confidence: 50,
      detail: "No service version provided. Cannot verify exploit applicability.",
      durationMs: Date.now() - start,
    };
  }
  
  if (!input.service) {
    return {
      checkName: "Version Fingerprint",
      category: "version",
      status: "skip",
      confidence: 40,
      detail: "No service name provided. Version check skipped.",
      durationMs: Date.now() - start,
    };
  }
  
  // Check if the service matches known patterns
  const serviceLower = input.service.toLowerCase();
  let matchedService: string | null = null;
  
  for (const [svcName, patterns] of Object.entries(SERVICE_PATTERNS)) {
    if (patterns.some(p => p.test(serviceLower))) {
      matchedService = svcName;
      break;
    }
  }
  
  if (matchedService) {
    return {
      checkName: "Version Fingerprint",
      category: "version",
      status: "pass",
      confidence: 80,
      detail: `Service identified as ${matchedService} version ${input.serviceVersion}. Exploit targeting is plausible.`,
      durationMs: Date.now() - start,
    };
  }
  
  return {
    checkName: "Version Fingerprint",
    category: "version",
    status: "warn",
    confidence: 50,
    detail: `Service "${input.service}" version "${input.serviceVersion}" not in known fingerprint database. Proceed with caution.`,
    durationMs: Date.now() - start,
  };
}

/**
 * Check 3: Exploit maturity — how reliable is the exploit?
 */
function checkExploitMaturity(input: PreFlightCheckInput): CheckResult {
  const start = Date.now();
  
  if (!input.cveId) {
    return {
      checkName: "Exploit Maturity",
      category: "exploit_maturity",
      status: "skip",
      confidence: 40,
      detail: "No CVE ID provided. Cannot assess exploit maturity.",
      durationMs: Date.now() - start,
    };
  }
  
  const maturity = KNOWN_EXPLOIT_MATURITY[input.cveId.toUpperCase()];
  
  if (maturity) {
    const details: string[] = [];
    if (maturity.metasploitModule) details.push("Metasploit module available");
    if (maturity.nucleiTemplate) details.push("Nuclei template available");
    if (maturity.weaponized) details.push("Known weaponized in the wild");
    details.push(`${maturity.exploitDbCount} public exploits on ExploitDB`);
    
    return {
      checkName: "Exploit Maturity",
      category: "exploit_maturity",
      status: maturity.maturityScore >= 70 ? "pass" : "warn",
      confidence: maturity.maturityScore,
      detail: `${input.cveId}: Maturity score ${maturity.maturityScore}/100. ${details.join(". ")}.`,
      durationMs: Date.now() - start,
    };
  }
  
  // Unknown CVE — lower confidence
  return {
    checkName: "Exploit Maturity",
    category: "exploit_maturity",
    status: "warn",
    confidence: 30,
    detail: `${input.cveId} not in known exploit maturity database. Public exploit availability unknown.`,
    durationMs: Date.now() - start,
  };
}

/**
 * Check 4: Prerequisite validation — are required conditions met?
 */
function checkPrerequisites(input: PreFlightCheckInput): CheckResult {
  const start = Date.now();
  const issues: string[] = [];
  
  // Auth check
  if (input.requiresAuth && !input.authCredentials) {
    issues.push("Exploit requires authentication but no credentials provided");
  }
  
  // Port check
  if (!input.targetPort && !input.protocol) {
    issues.push("No target port or protocol specified — may target wrong service");
  }
  
  // Technique check
  if (input.techniqueId && !input.exploitModule && !input.cveId) {
    issues.push("ATT&CK technique specified but no exploit module or CVE — may need manual selection");
  }
  
  if (issues.length === 0) {
    return {
      checkName: "Prerequisite Validation",
      category: "prerequisite",
      status: "pass",
      confidence: 90,
      detail: "All prerequisites met. Target, credentials, and exploit parameters are configured.",
      durationMs: Date.now() - start,
    };
  }
  
  return {
    checkName: "Prerequisite Validation",
    category: "prerequisite",
    status: issues.some(i => i.includes("authentication")) ? "fail" : "warn",
    confidence: Math.max(10, 90 - issues.length * 25),
    detail: `Issues found: ${issues.join("; ")}.`,
    durationMs: Date.now() - start,
  };
}

/**
 * Check 5: Environmental compatibility — is the test safe to run?
 */
function checkEnvironment(input: PreFlightCheckInput): CheckResult {
  const start = Date.now();
  const warnings: string[] = [];
  
  // Check for production indicators
  const host = input.targetHost.toLowerCase();
  if (host.includes("prod") || host.includes("live") || host.includes("www.")) {
    warnings.push("Target appears to be a production system — ensure authorization");
  }
  
  // Check for critical infrastructure ports
  const criticalPorts = [53, 88, 389, 636, 445, 3389];
  if (input.targetPort && criticalPorts.includes(input.targetPort)) {
    warnings.push(`Port ${input.targetPort} is associated with critical infrastructure services`);
  }
  
  // Check for destructive CVEs
  const destructiveCves = ["CVE-2017-0144", "CVE-2017-0145"]; // EternalBlue etc.
  if (input.cveId && destructiveCves.includes(input.cveId.toUpperCase())) {
    warnings.push("This exploit is known to cause service disruption or data corruption");
  }
  
  if (warnings.length === 0) {
    return {
      checkName: "Environmental Safety",
      category: "environment",
      status: "pass",
      confidence: 85,
      detail: "No environmental concerns detected. Test appears safe to execute.",
      durationMs: Date.now() - start,
    };
  }
  
  return {
    checkName: "Environmental Safety",
    category: "environment",
    status: "warn",
    confidence: Math.max(30, 85 - warnings.length * 20),
    detail: `Warnings: ${warnings.join("; ")}.`,
    durationMs: Date.now() - start,
  };
}

// ─── Main Pre-Flight Runner ────────────────────────────────────────

/**
 * Run all pre-flight checks for a given exploit/test configuration.
 */
export async function runPreFlightChecks(input: PreFlightCheckInput): Promise<PreFlightResult> {
  const checks: CheckResult[] = [];
  const blockers: string[] = [];
  const warnings: string[] = [];
  
  // Run all checks
  const reachability = await checkReachability(input);
  checks.push(reachability);
  
  const version = checkVersionMatch(input);
  checks.push(version);
  
  const maturity = checkExploitMaturity(input);
  checks.push(maturity);
  
  const prereqs = checkPrerequisites(input);
  checks.push(prereqs);
  
  const environment = checkEnvironment(input);
  checks.push(environment);
  
  // Collect blockers and warnings
  for (const check of checks) {
    if (check.status === "fail") blockers.push(`[${check.checkName}] ${check.detail}`);
    if (check.status === "warn") warnings.push(`[${check.checkName}] ${check.detail}`);
  }
  
  // Calculate overall confidence (weighted average)
  const weights: Record<string, number> = {
    reachability: 0.30,
    version: 0.20,
    exploit_maturity: 0.20,
    prerequisite: 0.20,
    environment: 0.10,
  };
  
  let totalWeight = 0;
  let weightedSum = 0;
  for (const check of checks) {
    if (check.status !== "skip") {
      const w = weights[check.category] || 0.1;
      weightedSum += check.confidence * w;
      totalWeight += w;
    }
  }
  
  const overallConfidence = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
  const estimatedSuccessRate = Math.round(overallConfidence * 0.85); // Conservative estimate
  
  // Determine recommendation
  let recommendation: PreFlightResult["recommendation"];
  if (blockers.length > 0) {
    recommendation = "skip";
  } else if (overallConfidence >= 70 && warnings.length === 0) {
    recommendation = "proceed";
  } else if (overallConfidence >= 40) {
    recommendation = "proceed_with_caution";
  } else {
    recommendation = "manual_review";
  }
  
  // Build reasoning
  const passCount = checks.filter(c => c.status === "pass").length;
  const failCount = checks.filter(c => c.status === "fail").length;
  const warnCount = checks.filter(c => c.status === "warn").length;
  
  const reasoning = `Pre-flight completed: ${passCount} passed, ${failCount} failed, ${warnCount} warnings. ` +
    `Overall confidence: ${overallConfidence}%. Estimated success rate: ${estimatedSuccessRate}%. ` +
    `Recommendation: ${recommendation.replace(/_/g, " ")}.`;
  
  return {
    overallConfidence,
    recommendation,
    checks,
    estimatedSuccessRate,
    reasoning,
    blockers,
    warnings,
  };
}

/**
 * Quick check: is this exploit worth running? (lightweight version)
 */
export function quickConfidenceEstimate(input: PreFlightCheckInput): number {
  let score = 50; // Base
  
  if (input.cveId) {
    const maturity = KNOWN_EXPLOIT_MATURITY[input.cveId.toUpperCase()];
    if (maturity) score += maturity.maturityScore * 0.3;
    else score -= 10;
  }
  
  if (input.serviceVersion) score += 15;
  if (input.targetPort) score += 5;
  if (input.requiresAuth && !input.authCredentials) score -= 30;
  
  return Math.max(0, Math.min(100, Math.round(score)));
}
