/**
 * Nuclei Verification Engine
 * ══════════════════════════
 * Uses Nuclei as a fast re-verification step after LLM-generated exploits.
 * When an LLM exploit claims success, this module runs a targeted Nuclei scan
 * to independently confirm or deny the finding, then adjusts the confidence score.
 *
 * Integration points:
 *   - Called after LLM exploit execution in enhanced-exploit-orchestration.ts
 *   - Uses buildNucleiCommand() from exploit-selection-intelligence.ts
 *   - Feeds results through nuclei-output-parser.ts for structured analysis
 *   - Adjusts VerificationResult confidence from exploit-verification-engine.ts
 */

import type { AccessLevel, VerificationResult, VerificationStatus } from './exploit-verification-engine';
import { parseNucleiJsonOutput, assessNucleiAccessLevel, addJsonFlag, type NucleiParseResult } from './nuclei-output-parser';

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface NucleiVerificationParams {
  /** Target host */
  target: string;
  /** Target port */
  port: number;
  /** CVE being exploited (if known) */
  cve?: string;
  /** Vulnerability class (sqli, xss, lfi, etc.) */
  vulnClass: string;
  /** Service name (http, ssh, etc.) */
  service: string;
  /** Session cookie for authenticated scanning */
  sessionCookie?: string;
  /** Scan server host for remote execution */
  scanServerHost: string;
  /** Timeout in seconds for the Nuclei scan */
  timeoutSec?: number;
}

export interface NucleiVerificationResult {
  /** Whether Nuclei independently confirmed the vulnerability */
  confirmed: boolean;
  /** Confidence adjustment: positive = boost, negative = reduce */
  confidenceAdjustment: number;
  /** Nuclei's own assessment of access level */
  nucleiAccessLevel: AccessLevel;
  /** Parsed Nuclei findings */
  parseResult: NucleiParseResult;
  /** Human-readable summary */
  summary: string;
  /** Duration of the verification scan in ms */
  durationMs: number;
  /** The Nuclei command that was executed */
  command: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — VERIFICATION ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run Nuclei as a fast re-verification step after an LLM-generated exploit.
 * Returns a verification result with confidence adjustment.
 */
export async function runNucleiVerification(
  params: NucleiVerificationParams,
): Promise<NucleiVerificationResult> {
  const startTime = Date.now();
  const { target, port, cve, vulnClass, service, sessionCookie, scanServerHost, timeoutSec = 300 } = params;

  try {
    // Build the Nuclei command using the existing intelligence framework
    const { buildNucleiCommand } = await import('./exploit-selection-intelligence');
    const nucleiCmd = buildNucleiCommand({
      target,
      port,
      cve,
      vulnClass,
      cookie: sessionCookie,
    });

    if (!nucleiCmd) {
      return {
        confirmed: false,
        confidenceAdjustment: 0,
        nucleiAccessLevel: 'none',
        parseResult: { findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false, highestSeverity: 'unknown', allExtractedData: [], curlCommands: [], parseErrors: [] },
        summary: `No Nuclei template available for vulnClass=${vulnClass}, CVE=${cve || 'none'}. Verification skipped.`,
        durationMs: Date.now() - startTime,
        command: '',
      };
    }

    // Add -json flag for structured output parsing
    const jsonCommand = addJsonFlag(nucleiCmd.command);

    // Execute the Nuclei scan
    const { executeRawCommand } = await import('./scan-server-executor');
    const result = await executeRawCommand(jsonCommand, scanServerHost, timeoutSec);
    const rawOutput = result.stdout || '';

    // Parse the JSON output
    const parseResult = parseNucleiJsonOutput(rawOutput);

    // Assess access level from findings
    const accessAssessment = assessNucleiAccessLevel(parseResult);

    // Determine confirmation and confidence adjustment
    let confirmed = false;
    let confidenceAdjustment = 0;

    if (parseResult.hasExploitableFindings) {
      // Nuclei independently confirmed an exploitable vulnerability
      confirmed = true;
      confidenceAdjustment = +20; // Significant confidence boost
    } else if (parseResult.stats.total > 0 && (parseResult.stats.critical > 0 || parseResult.stats.high > 0)) {
      // Nuclei found critical/high findings but no extracted data
      confirmed = true;
      confidenceAdjustment = +15;
    } else if (parseResult.stats.total > 0) {
      // Nuclei found some findings (medium/low/info)
      confirmed = false;
      confidenceAdjustment = +5; // Small boost — related findings exist
    } else {
      // Nuclei found nothing — this reduces confidence in the LLM exploit
      confirmed = false;
      confidenceAdjustment = -10; // Confidence reduction
    }

    // Build summary
    const summary = confirmed
      ? `Nuclei CONFIRMED: ${parseResult.stats.total} findings (${parseResult.stats.critical} critical, ${parseResult.stats.high} high). ` +
        `Templates: ${parseResult.matchedTemplates.join(', ')}. ` +
        `Access: ${accessAssessment.accessLevel} (${accessAssessment.confidence}% confidence).`
      : parseResult.stats.total > 0
        ? `Nuclei found ${parseResult.stats.total} findings but none exploitable. Confidence adjustment: ${confidenceAdjustment}.`
        : `Nuclei found NO matching vulnerabilities. LLM exploit may be a false positive. Confidence reduced by ${Math.abs(confidenceAdjustment)}.`;

    return {
      confirmed,
      confidenceAdjustment,
      nucleiAccessLevel: accessAssessment.accessLevel as AccessLevel,
      parseResult,
      summary,
      durationMs: Date.now() - startTime,
      command: jsonCommand,
    };
  } catch (err: any) {
    return {
      confirmed: false,
      confidenceAdjustment: 0,
      nucleiAccessLevel: 'none',
      parseResult: { findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false, highestSeverity: 'unknown', allExtractedData: [], curlCommands: [], parseErrors: [`Execution error: ${err.message}`] },
      summary: `Nuclei verification failed: ${err.message}`,
      durationMs: Date.now() - startTime,
      command: '',
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — VERIFICATION RESULT ADJUSTMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Adjust an existing VerificationResult based on Nuclei verification.
 * This is called after the standard verification engine has run,
 * adding Nuclei's independent confirmation as an additional signal.
 */
export function adjustVerificationWithNuclei(
  existing: VerificationResult,
  nucleiResult: NucleiVerificationResult,
): VerificationResult {
  const adjusted = { ...existing };

  // Adjust confidence
  adjusted.confidence = Math.min(100, Math.max(0, adjusted.confidence + nucleiResult.confidenceAdjustment));

  // If Nuclei confirmed and existing was unverified/probable, upgrade
  if (nucleiResult.confirmed) {
    if (adjusted.status === 'unverified' || adjusted.status === 'probable_success') {
      adjusted.status = 'confirmed_success';
    }
    // If Nuclei found a higher access level, upgrade
    const nucleiAccessNum = ACCESS_LEVEL_RANK[nucleiResult.nucleiAccessLevel] || 0;
    const existingAccessNum = ACCESS_LEVEL_RANK[adjusted.accessLevel] || 0;
    if (nucleiAccessNum > existingAccessNum) {
      adjusted.accessLevel = nucleiResult.nucleiAccessLevel;
    }
  } else if (!nucleiResult.confirmed && nucleiResult.confidenceAdjustment < 0) {
    // Nuclei found nothing — if existing was only probable, downgrade
    if (adjusted.status === 'probable_success' && adjusted.confidence < 40) {
      adjusted.status = 'unverified';
    }
  }

  // Append Nuclei verification to explanation
  adjusted.explanation = `${adjusted.explanation} | Nuclei: ${nucleiResult.summary.slice(0, 200)}`;

  return adjusted;
}

const ACCESS_LEVEL_RANK: Record<string, number> = {
  'none': 0,
  'info_disclosure': 1,
  'file_read': 2,
  'file_write': 3,
  'credential_access': 4,
  'database_access': 5,
  'command_execution': 6,
  'service_account': 7,
  'user_shell': 8,
  'root_shell': 9,
};

// ═══════════════════════════════════════════════════════════════════════
// §4 — COOKIE EXTRACTION HELPERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extract the best session cookie from asset credentials and training lab creds.
 * Checks confirmedCredentials for sessionCookie field, then trainingLabCreds.
 * Returns a cookie string suitable for Nuclei's -H "Cookie: ..." flag.
 */
export function extractSessionCookie(asset?: {
  confirmedCredentials?: Array<{
    username: string;
    password?: string;
    service?: string;
    sessionCookie?: string;
    [key: string]: any;
  }>;
  trainingLabCreds?: {
    username?: string;
    password?: string;
    sessionCookie?: string;
    loginPath?: string;
    [key: string]: any;
  };
  [key: string]: any;
}): string | undefined {
  if (!asset) return undefined;

  // Priority 1: Session cookie from confirmed credentials
  if (asset.confirmedCredentials) {
    for (const cred of asset.confirmedCredentials) {
      if ((cred as any).sessionCookie) {
        return (cred as any).sessionCookie;
      }
    }
  }

  // Priority 2: Session cookie from training lab creds
  if ((asset as any).trainingLabCreds?.sessionCookie) {
    return (asset as any).trainingLabCreds.sessionCookie;
  }

  // Priority 3: Build a basic auth cookie from username:password (for HTTP form auth)
  // This is a fallback — the actual session cookie should be obtained from the auth flow
  if (asset.confirmedCredentials?.length) {
    const httpCred = asset.confirmedCredentials.find(c =>
      c.service === 'http' || c.service === 'https' || c.service === 'http-form'
    );
    if (httpCred && httpCred.password) {
      // Return undefined — we can't synthesize a session cookie from username/password
      // The caller should use the credential-based auth flow instead
      return undefined;
    }
  }

  return undefined;
}

/**
 * Build a cookie header string from multiple cookie name=value pairs.
 * Handles both raw cookie strings and structured cookie objects.
 */
export function buildCookieHeader(cookies: Array<{ name: string; value: string }> | string): string {
  if (typeof cookies === 'string') return cookies;
  return cookies.map(c => `${c.name}=${c.value}`).join('; ');
}
