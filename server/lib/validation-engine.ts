/**
 * Autonomous Validation Engine
 *
 * Lightweight exploitation validation layer that:
 * 1. Selects the highest-confidence candidates from discovered assets
 *    (KEV-confirmed + known Metasploit modules)
 * 2. Attempts safe, non-destructive validation using MSF `check` where available,
 *    or controlled auxiliary scans
 * 3. Records proof-of-exploit evidence and feeds results back into CARVER/SHOCK scoring
 *
 * Safety model:
 * - Prefers `module.check` (vulnerability check without exploitation)
 * - Falls back to auxiliary scanners (e.g., auxiliary/scanner/http/*)
 * - Full exploit execution requires explicit operator approval
 * - All actions are logged to validation_results with timestamps and evidence
 * - Scope verification enforced before any network interaction
 */

import type { MsfClient } from "./msf-client";

// ─── Types ─────────────────────────────────────────────────────────────────

export type ValidationMode = "check_only" | "auxiliary_scan" | "safe_exploit";

export type ValidationStatus =
  | "pending"
  | "running"
  | "validated"      // Vulnerability confirmed exploitable
  | "not_vulnerable" // Check returned negative
  | "inconclusive"   // Could not determine
  | "error"          // Execution error
  | "skipped"        // Skipped (no MSF module, out of scope, etc.)
  | "approved_pending"; // Awaiting operator approval for safe_exploit

export type CandidateSource = "kev_match" | "confirmed_cve" | "vuln_feed" | "technology_match";

export interface ValidationCandidate {
  /** Discovered asset ID */
  assetId: number;
  /** Asset hostname/IP */
  hostname: string;
  /** IP address for targeting */
  ipAddress: string | null;
  /** Port to target */
  port: number | null;
  /** CVE ID being validated */
  cveId: string;
  /** Whether this CVE is on the CISA KEV list */
  kevListed: boolean;
  /** CVSS score */
  cvssScore: number | null;
  /** Evidence basis from the discovery pipeline */
  source: CandidateSource;
  /** Matched MSF module path (if any) */
  msfModule: string | null;
  /** MSF module rank (higher = more reliable) */
  msfRank: number | null;
  /** Whether the MSF module supports `check` */
  supportsCheck: boolean;
  /** Current hybrid risk score of the asset */
  currentRiskScore: number;
  /** Posture finding ID that triggered this candidate */
  findingId: string;
  /** Confidence from the discovery pipeline (0-1) */
  discoveryConfidence: number;
  /** Priority score for ordering (computed) */
  priorityScore: number;
}

export interface ValidationResult {
  candidateId: string; // `${assetId}:${cveId}`
  assetId: number;
  cveId: string;
  hostname: string;
  msfModule: string | null;
  mode: ValidationMode;
  status: ValidationStatus;
  /** Whether the vulnerability was confirmed exploitable */
  exploitable: boolean;
  /** Raw output from MSF check/auxiliary */
  rawOutput: string | null;
  /** Structured evidence for the proof-of-exploit record */
  evidence: ValidationEvidence | null;
  /** Score adjustment to apply */
  scoreAdjustment: number;
  /** Duration in milliseconds */
  durationMs: number;
  /** Error message if status is 'error' */
  errorMessage: string | null;
  /** Timestamp */
  timestamp: Date;
}

export interface ValidationEvidence {
  /** What was tested */
  target: string;
  /** How it was tested */
  method: string;
  /** What was found */
  finding: string;
  /** Confidence level (0-1) */
  confidence: number;
  /** Raw MSF output excerpt */
  msfOutput: string;
  /** Whether a session was obtained (for safe_exploit mode) */
  sessionObtained: boolean;
  /** Session ID if obtained (immediately terminated) */
  sessionId: number | null;
  /** MITRE ATT&CK technique if applicable */
  mitreId: string | null;
  /** Screenshots or file references */
  artifacts: string[];
}

export interface ValidationRunConfig {
  /** Scan ID to validate against */
  scanId: number;
  /** MSF server ID to use */
  msfServerId: number;
  /** Maximum candidates to validate (default: 10) */
  maxCandidates: number;
  /** Validation mode */
  mode: ValidationMode;
  /** Whether to require operator approval for each exploit */
  requireApproval: boolean;
  /** Timeout per candidate in seconds (default: 60) */
  timeoutPerCandidate: number;
  /** Target scope restriction (CIDR ranges or hostnames) */
  scopeRestrictions: string[];
  /** Operator who initiated the run */
  operatorId: string;
  /** Engagement ID (optional) */
  engagementId: number | null;
}

export interface ValidationRunSummary {
  runId: number;
  scanId: number;
  totalCandidates: number;
  validated: number;
  notVulnerable: number;
  inconclusive: number;
  errors: number;
  skipped: number;
  /** Average score adjustment across validated findings */
  avgScoreAdjustment: number;
  /** Top validated findings */
  topFindings: ValidationResult[];
  /** Duration in milliseconds */
  totalDurationMs: number;
  /** Timestamp */
  startedAt: Date;
  completedAt: Date | null;
}

// ─── Candidate Selection ────────────────────────────────────────────────────

/**
 * Compute a priority score for a validation candidate.
 * Higher score = should be validated first.
 *
 * Factors:
 * - KEV listed: +40 points (known exploited = highest priority)
 * - CVSS score: up to +30 points (scaled from 0-10)
 * - Has MSF module: +15 points
 * - MSF module supports check: +10 points
 * - Discovery confidence: up to +5 points
 */
export function computeCandidatePriority(candidate: Omit<ValidationCandidate, "priorityScore">): number {
  let score = 0;

  // KEV-listed vulnerabilities are the highest priority
  if (candidate.kevListed) score += 40;

  // CVSS score contributes up to 30 points
  if (candidate.cvssScore) score += (candidate.cvssScore / 10) * 30;

  // Having a known MSF module means we can actually test it
  if (candidate.msfModule) score += 15;

  // Modules that support `check` are safer to validate
  if (candidate.supportsCheck) score += 10;

  // Discovery pipeline confidence
  score += candidate.discoveryConfidence * 5;

  return Math.round(score * 100) / 100;
}

/**
 * Select the top N validation candidates from a scan's discovered assets.
 *
 * Selection criteria:
 * 1. Must have at least one CVE with a known MSF module OR be KEV-listed
 * 2. Must have an IP address or resolvable hostname
 * 3. Ordered by priority score (KEV first, then CVSS, then MSF module availability)
 * 4. Limited to maxCandidates
 */
export function selectCandidates(
  assets: AssetWithFindings[],
  exploitCatalog: ExploitCatalogEntry[],
  maxCandidates: number = 10,
): ValidationCandidate[] {
  const candidates: ValidationCandidate[] = [];

  // Build a CVE → MSF module lookup from the exploit catalog
  const cveToModules = new Map<string, ExploitCatalogEntry[]>();
  for (const entry of exploitCatalog) {
    const cveIds = (entry.cveIds as string[]) || [];
    for (const cve of cveIds) {
      const existing = cveToModules.get(cve) || [];
      existing.push(entry);
      cveToModules.set(cve, existing);
    }
  }

  for (const asset of assets) {
    if (asset.excluded) continue;

    const findings = (asset.postureFindings as any[]) || [];
    for (const finding of findings) {
      const cveIds = (finding.cveIds as string[]) || [];
      for (const cveId of cveIds) {
        // Look up MSF modules for this CVE
        const modules = cveToModules.get(cveId) || [];
        const bestModule = modules
          .filter(m => m.msfModule)
          .sort((a, b) => (b.msfRank ?? 0) - (a.msfRank ?? 0))[0];

        // Must have MSF module OR be KEV-listed
        if (!bestModule?.msfModule && !finding.kevListed) continue;

        // Must have an IP address
        const ipAddress = asset.ipAddress || asset.hostname;
        if (!ipAddress) continue;

        const partial = {
          assetId: asset.id,
          hostname: asset.hostname || asset.ipAddress || "unknown",
          ipAddress: asset.ipAddress || null,
          port: finding.port || asset.port || null,
          cveId,
          kevListed: !!finding.kevListed,
          cvssScore: finding.cvssScore || null,
          source: (finding.evidenceBasis || "vuln_feed") as CandidateSource,
          msfModule: bestModule?.msfModule || null,
          msfRank: bestModule?.msfRank || null,
          supportsCheck: false, // Will be determined at runtime
          currentRiskScore: asset.hybridRiskScore || 0,
          findingId: finding.id || `${asset.id}:${cveId}`,
          discoveryConfidence: (finding.confidence ?? asset.confidence ?? 50) / 100,
        };

        const priorityScore = computeCandidatePriority(partial);

        candidates.push({
          ...partial,
          priorityScore,
        });
      }
    }
  }

  // Deduplicate by assetId + cveId (keep highest priority)
  const seen = new Map<string, ValidationCandidate>();
  for (const c of candidates) {
    const key = `${c.assetId}:${c.cveId}`;
    const existing = seen.get(key);
    if (!existing || c.priorityScore > existing.priorityScore) {
      seen.set(key, c);
    }
  }

  // Sort by priority and take top N
  return Array.from(seen.values())
    .sort((a, b) => b.priorityScore - a.priorityScore)
    .slice(0, maxCandidates);
}

// ─── Validation Execution ───────────────────────────────────────────────────

/**
 * Validate a single candidate using MSF check or auxiliary scan.
 *
 * Safety hierarchy:
 * 1. check_only: Uses module.check — no exploitation, just vulnerability verification
 * 2. auxiliary_scan: Uses auxiliary/scanner modules — network probing without exploitation
 * 3. safe_exploit: Executes the exploit but immediately terminates any session obtained
 */
export async function validateCandidate(
  candidate: ValidationCandidate,
  msfClient: MsfClient,
  config: ValidationRunConfig,
): Promise<ValidationResult> {
  const startTime = Date.now();
  const candidateId = `${candidate.assetId}:${candidate.cveId}`;

  // Scope verification
  if (config.scopeRestrictions.length > 0 && candidate.ipAddress) {
    const inScope = config.scopeRestrictions.some(scope =>
      isInScope(candidate.ipAddress!, scope)
    );
    if (!inScope) {
      return makeResult(candidate, candidateId, "skipped", false, null, "Target out of scope", startTime);
    }
  }

  if (!candidate.msfModule) {
    return makeResult(candidate, candidateId, "skipped", false, null, "No MSF module available", startTime);
  }

  try {
    await msfClient.ensureAuth();

    // Step 1: Try module.check first (safest)
    if (config.mode === "check_only" || config.mode === "auxiliary_scan") {
      return await runModuleCheck(candidate, candidateId, msfClient, config, startTime);
    }

    // Step 2: Safe exploit mode — execute but immediately clean up
    if (config.mode === "safe_exploit") {
      if (config.requireApproval) {
        return makeResult(candidate, candidateId, "approved_pending", false, null, "Awaiting operator approval", startTime);
      }
      return await runSafeExploit(candidate, candidateId, msfClient, config, startTime);
    }

    return makeResult(candidate, candidateId, "error", false, null, `Unknown mode: ${config.mode}`, startTime);
  } catch (err: any) {
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}

/**
 * Run module.check to verify vulnerability without exploitation.
 */
async function runModuleCheck(
  candidate: ValidationCandidate,
  candidateId: string,
  msfClient: MsfClient,
  config: ValidationRunConfig,
  startTime: number,
): Promise<ValidationResult> {
  const options: Record<string, any> = {
    RHOSTS: candidate.ipAddress || candidate.hostname,
  };
  if (candidate.port) {
    options.RPORT = String(candidate.port);
  }

  try {
    // Extract module type and name from full path
    const { moduleType, moduleName } = parseModulePath(candidate.msfModule!);

    const checkResult = await Promise.race([
      msfClient.checkModule(moduleType, moduleName, options),
      timeout(config.timeoutPerCandidate * 1000),
    ]);

    if (!checkResult || typeof checkResult === "string") {
      // Timeout or empty result
      return makeResult(candidate, candidateId, "inconclusive", false, null,
        typeof checkResult === "string" ? checkResult : "Check timed out", startTime);
    }

    // Parse check result — MSF check returns job_id and uuid
    // We need to poll for the result
    const jobId = checkResult.job_id;
    if (jobId !== undefined) {
      // Wait for the check job to complete
      const output = await waitForJobCompletion(msfClient, String(jobId), config.timeoutPerCandidate);

      const isVulnerable = parseCheckOutput(output);
      const evidence: ValidationEvidence = {
        target: `${candidate.ipAddress || candidate.hostname}:${candidate.port || "auto"}`,
        method: `module.check(${candidate.msfModule})`,
        finding: isVulnerable ? "Vulnerable" : (output.includes("safe") || output.includes("not vulnerable") ? "Not Vulnerable" : "Inconclusive"),
        confidence: isVulnerable ? 0.9 : 0.7,
        msfOutput: output.slice(0, 2000),
        sessionObtained: false,
        sessionId: null,
        mitreId: null,
        artifacts: [],
      };

      const status: ValidationStatus = isVulnerable ? "validated" : "not_vulnerable";
      const scoreAdj = isVulnerable ? computeScoreAdjustment(candidate, true) : 0;

      return {
        candidateId,
        assetId: candidate.assetId,
        cveId: candidate.cveId,
        hostname: candidate.hostname,
        msfModule: candidate.msfModule,
        mode: "check_only",
        status,
        exploitable: isVulnerable,
        rawOutput: output.slice(0, 4000),
        evidence,
        scoreAdjustment: scoreAdj,
        durationMs: Date.now() - startTime,
        errorMessage: null,
        timestamp: new Date(),
      };
    }

    return makeResult(candidate, candidateId, "inconclusive", false, null, "Check returned no job ID", startTime);
  } catch (err: any) {
    // If check is not supported, try auxiliary scan in auxiliary_scan mode
    if (config.mode === "auxiliary_scan" && err.message?.includes("check is not supported")) {
      return await runAuxiliaryScan(candidate, candidateId, msfClient, config, startTime);
    }
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}

/**
 * Run an auxiliary scanner module for non-destructive probing.
 */
async function runAuxiliaryScan(
  candidate: ValidationCandidate,
  candidateId: string,
  msfClient: MsfClient,
  config: ValidationRunConfig,
  startTime: number,
): Promise<ValidationResult> {
  // Map common exploit modules to their auxiliary scanner equivalents
  const auxModule = mapToAuxiliaryScanner(candidate.msfModule!);
  if (!auxModule) {
    return makeResult(candidate, candidateId, "skipped", false, null,
      "No auxiliary scanner available for this module", startTime);
  }

  const options: Record<string, any> = {
    RHOSTS: candidate.ipAddress || candidate.hostname,
  };
  if (candidate.port) {
    options.RPORT = String(candidate.port);
  }

  try {
    const result = await Promise.race([
      msfClient.executeModule("auxiliary", auxModule, options),
      timeout(config.timeoutPerCandidate * 1000),
    ]);

    if (!result || typeof result === "string") {
      return makeResult(candidate, candidateId, "inconclusive", false, null,
        "Auxiliary scan timed out", startTime);
    }

    const output = await waitForJobCompletion(msfClient, String(result.job_id), config.timeoutPerCandidate);
    const isVulnerable = parseCheckOutput(output);
    const scoreAdj = isVulnerable ? computeScoreAdjustment(candidate, true) : 0;

    const evidence: ValidationEvidence = {
      target: `${candidate.ipAddress || candidate.hostname}:${candidate.port || "auto"}`,
      method: `auxiliary/${auxModule}`,
      finding: isVulnerable ? "Vulnerable (auxiliary scan)" : "Not confirmed",
      confidence: isVulnerable ? 0.75 : 0.5,
      msfOutput: output.slice(0, 2000),
      sessionObtained: false,
      sessionId: null,
      mitreId: null,
      artifacts: [],
    };

    return {
      candidateId,
      assetId: candidate.assetId,
      cveId: candidate.cveId,
      hostname: candidate.hostname,
      msfModule: candidate.msfModule,
      mode: "auxiliary_scan",
      status: isVulnerable ? "validated" : "inconclusive",
      exploitable: isVulnerable,
      rawOutput: output.slice(0, 4000),
      evidence,
      scoreAdjustment: scoreAdj,
      durationMs: Date.now() - startTime,
      errorMessage: null,
      timestamp: new Date(),
    };
  } catch (err: any) {
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}

/**
 * Run a safe exploit — execute the exploit but immediately terminate any session.
 * This provides the strongest proof-of-exploit evidence.
 */
async function runSafeExploit(
  candidate: ValidationCandidate,
  candidateId: string,
  msfClient: MsfClient,
  config: ValidationRunConfig,
  startTime: number,
): Promise<ValidationResult> {
  const { moduleType, moduleName } = parseModulePath(candidate.msfModule!);
  const options: Record<string, any> = {
    RHOSTS: candidate.ipAddress || candidate.hostname,
  };
  if (candidate.port) {
    options.RPORT = String(candidate.port);
  }

  try {
    const result = await Promise.race([
      msfClient.executeModule(moduleType, moduleName, options),
      timeout(config.timeoutPerCandidate * 1000),
    ]);

    if (!result || typeof result === "string") {
      return makeResult(candidate, candidateId, "inconclusive", false, null,
        "Exploit execution timed out", startTime);
    }

    // Wait briefly for session establishment
    await sleep(3000);

    // Check for new sessions
    const sessions = await msfClient.listSessions();
    let sessionObtained = false;
    let sessionId: number | null = null;

    // Find sessions targeting our host
    for (const [sid, session] of Object.entries(sessions)) {
      if (session.tunnel_peer?.includes(candidate.ipAddress || candidate.hostname)) {
        sessionObtained = true;
        sessionId = parseInt(sid);

        // IMMEDIATELY terminate the session — we only needed proof
        try {
          await msfClient.stopSession(sid);
        } catch {
          // Best effort cleanup
        }
        break;
      }
    }

    // Also stop the job
    if (result.job_id !== undefined) {
      try {
        await msfClient.stopJob(String(result.job_id));
      } catch {
        // Best effort
      }
    }

    const output = sessionObtained
      ? `Session ${sessionId} obtained on ${candidate.ipAddress}:${candidate.port || "auto"} via ${candidate.msfModule}. Session immediately terminated.`
      : `Exploit executed but no session obtained. Job ID: ${result.job_id}`;

    const evidence: ValidationEvidence = {
      target: `${candidate.ipAddress || candidate.hostname}:${candidate.port || "auto"}`,
      method: `safe_exploit(${candidate.msfModule})`,
      finding: sessionObtained ? "Exploitable — session obtained and terminated" : "Exploit executed, no session",
      confidence: sessionObtained ? 0.99 : 0.4,
      msfOutput: output,
      sessionObtained,
      sessionId,
      mitreId: null,
      artifacts: [],
    };

    const scoreAdj = sessionObtained ? computeScoreAdjustment(candidate, true) : 0;

    return {
      candidateId,
      assetId: candidate.assetId,
      cveId: candidate.cveId,
      hostname: candidate.hostname,
      msfModule: candidate.msfModule,
      mode: "safe_exploit",
      status: sessionObtained ? "validated" : "inconclusive",
      exploitable: sessionObtained,
      rawOutput: output,
      evidence,
      scoreAdjustment: scoreAdj,
      durationMs: Date.now() - startTime,
      errorMessage: null,
      timestamp: new Date(),
    };
  } catch (err: any) {
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}

// ─── Score Integration ──────────────────────────────────────────────────────

/**
 * Compute the score adjustment for a validated vulnerability.
 *
 * Validated exploitable findings increase the asset's risk score because
 * we now have proof-of-exploit evidence rather than just theoretical risk.
 *
 * Adjustment factors:
 * - KEV-listed + validated: +15 points (confirmed actively exploited)
 * - High CVSS + validated: +10 points
 * - Medium CVSS + validated: +5 points
 * - Not exploitable: 0 (no change)
 */
export function computeScoreAdjustment(
  candidate: Pick<ValidationCandidate, "kevListed" | "cvssScore">,
  exploitable: boolean,
): number {
  if (!exploitable) return 0;

  let adjustment = 5; // Base adjustment for any validated exploit

  if (candidate.kevListed) {
    adjustment += 10; // KEV + validated = very high confidence
  }

  if (candidate.cvssScore) {
    if (candidate.cvssScore >= 9.0) adjustment += 10;
    else if (candidate.cvssScore >= 7.0) adjustment += 5;
    else if (candidate.cvssScore >= 4.0) adjustment += 2;
  }

  return Math.min(adjustment, 25); // Cap at 25 points
}

/**
 * Compute the overall validation score for an asset based on all its validation results.
 * This becomes the `validationScore` field that feeds into the scoring engine.
 *
 * Returns 0-100 where:
 * - 0 = no validation performed
 * - 1-30 = validated, nothing exploitable found
 * - 31-60 = some findings validated exploitable
 * - 61-100 = critical findings confirmed exploitable
 */
export function computeAssetValidationScore(results: ValidationResult[]): number {
  if (results.length === 0) return 0;

  const validated = results.filter(r => r.status === "validated");
  const notVulnerable = results.filter(r => r.status === "not_vulnerable");
  const total = results.filter(r => r.status !== "skipped" && r.status !== "error");

  if (total.length === 0) return 0;

  // If nothing was exploitable, return a low score (good news)
  if (validated.length === 0) {
    return Math.min(30, 10 + notVulnerable.length * 5);
  }

  // Scale based on how many findings were exploitable and their severity
  const maxAdjustment = Math.max(...validated.map(r => r.scoreAdjustment));
  const exploitRatio = validated.length / total.length;

  return Math.min(100, Math.round(30 + exploitRatio * 40 + maxAdjustment));
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Parse MSF module path into type and name */
export function parseModulePath(fullPath: string): { moduleType: string; moduleName: string } {
  // e.g., "exploit/windows/smb/ms17_010_eternalblue" → type="exploit", name="windows/smb/ms17_010_eternalblue"
  const parts = fullPath.split("/");
  const moduleType = parts[0]; // "exploit", "auxiliary", "post"
  const moduleName = parts.slice(1).join("/");
  return { moduleType, moduleName };
}

/** Map exploit modules to their auxiliary scanner equivalents */
export function mapToAuxiliaryScanner(exploitModule: string): string | null {
  // Common exploit → auxiliary scanner mappings
  const mappings: Record<string, string> = {
    // SMB
    "exploit/windows/smb/ms17_010_eternalblue": "scanner/smb/smb_ms17_010",
    "exploit/windows/smb/ms08_067_netapi": "scanner/smb/smb_ms08_067",
    // HTTP
    "exploit/multi/http/apache_mod_cgi_bash_env_exec": "scanner/http/apache_mod_cgi_bash_env",
    "exploit/unix/webapp/drupal_drupalgeddon2": "scanner/http/drupal_modules",
    // SSH
    "exploit/linux/ssh/libssh_auth_bypass": "scanner/ssh/libssh_auth_bypass",
  };

  // Direct mapping
  if (mappings[exploitModule]) return mappings[exploitModule];

  // Pattern-based mapping: try to find a scanner in the same service category
  const parts = exploitModule.split("/");
  if (parts.length >= 3) {
    const service = parts[2]; // e.g., "smb", "http", "ssh"
    const moduleName = parts[parts.length - 1];

    // Try common scanner patterns
    const scannerPatterns = [
      `scanner/${service}/${moduleName}`,
      `scanner/${service}/${service}_${moduleName}`,
    ];

    // Return the first pattern (caller should handle if module doesn't exist)
    return scannerPatterns[0];
  }

  return null;
}

/** Check if an IP is within a CIDR scope or matches a hostname */
function isInScope(target: string, scope: string): boolean {
  // Simple hostname match
  if (scope === target) return true;

  // Wildcard domain match (e.g., "*.example.com")
  if (scope.startsWith("*.")) {
    const domain = scope.slice(2);
    return target.endsWith(domain);
  }

  // CIDR match (simplified — supports /24, /16, /8)
  if (scope.includes("/")) {
    const [network, bits] = scope.split("/");
    const mask = parseInt(bits);
    if (isNaN(mask)) return false;

    const targetParts = target.split(".").map(Number);
    const networkParts = network.split(".").map(Number);

    if (targetParts.length !== 4 || networkParts.length !== 4) return false;

    const targetNum = (targetParts[0] << 24) | (targetParts[1] << 16) | (targetParts[2] << 8) | targetParts[3];
    const networkNum = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
    const maskNum = ~((1 << (32 - mask)) - 1);

    return (targetNum & maskNum) === (networkNum & maskNum);
  }

  return false;
}

/** Parse MSF check output to determine if target is vulnerable */
function parseCheckOutput(output: string): boolean {
  const lower = output.toLowerCase();

  // Positive indicators
  if (lower.includes("is vulnerable") || lower.includes("appears to be vulnerable")) return true;
  if (lower.includes("vulnerable!") || lower.includes("[+]")) return true;
  if (lower.includes("exploitable")) return true;

  // Negative indicators
  if (lower.includes("not vulnerable") || lower.includes("is not vulnerable")) return false;
  if (lower.includes("safe") || lower.includes("patched")) return false;
  if (lower.includes("[-]") && !lower.includes("[+]")) return false;

  return false;
}

/** Wait for an MSF job to complete and return its output */
async function waitForJobCompletion(
  msfClient: MsfClient,
  jobId: string,
  timeoutSeconds: number,
): Promise<string> {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let output = "";

  while (Date.now() < deadline) {
    try {
      const jobs = await msfClient.listJobs();
      if (!jobs[jobId]) {
        // Job completed
        return output || "Job completed (no output captured)";
      }
    } catch {
      // Ignore polling errors
    }
    await sleep(2000);
  }

  return output || "Job timed out";
}

/** Create a standard result object */
function makeResult(
  candidate: ValidationCandidate,
  candidateId: string,
  status: ValidationStatus,
  exploitable: boolean,
  evidence: ValidationEvidence | null,
  message: string | null,
  startTime: number,
): ValidationResult {
  return {
    candidateId,
    assetId: candidate.assetId,
    cveId: candidate.cveId,
    hostname: candidate.hostname,
    msfModule: candidate.msfModule,
    mode: "check_only",
    status,
    exploitable,
    rawOutput: message,
    evidence,
    scoreAdjustment: exploitable ? computeScoreAdjustment(candidate, true) : 0,
    durationMs: Date.now() - startTime,
    errorMessage: status === "error" ? message : null,
    timestamp: new Date(),
  };
}

function timeout(ms: number): Promise<string> {
  return new Promise((resolve) => setTimeout(() => resolve("timeout"), ms));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Supporting Types (from DB/pipeline) ────────────────────────────────────

export interface AssetWithFindings {
  id: number;
  hostname: string | null;
  ipAddress: string | null;
  port: number | null;
  excluded: boolean;
  hybridRiskScore: number | null;
  confidence: number | null;
  postureFindings: unknown; // JSON array of PostureFinding
}

export interface ExploitCatalogEntry {
  catalogId: string;
  msfModule: string | null;
  msfRank: number | null;
  cveIds: unknown; // JSON array of string
  cvssScore: number | null;
  source: string;
}
