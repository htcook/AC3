/**
 * Credential Verification Gates — Negative Control & Four-State Classification
 * 
 * Implements the AC3 ZAP Scan Reliability Specification addendum items:
 *   - Negative-control canary: Test a known-invalid credential before/during/after
 *     the batch. If its response changes, the endpoint stopped giving truthful answers.
 *   - Four-state credential classification:
 *     VALID          — Login succeeded, session obtained
 *     INVALID        — Login failed with expected failure response
 *     VALID_MFA_BLOCKED — Password accepted but MFA gate prevents session
 *     INDETERMINATE  — Response doesn't match ACCEPT or REJECT signatures
 * 
 * @module credential-verification-gates
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type CredentialState = "VALID" | "INVALID" | "VALID_MFA_BLOCKED" | "INDETERMINATE";

export interface NegativeControlResult {
  /** Whether the negative control canary passed (endpoint is giving truthful responses) */
  passed: boolean;
  /** The canary credential used */
  canaryUsername: string;
  canaryPassword: string;
  /** Response from the canary test */
  canaryResponse: {
    success: boolean;
    responseCode?: number;
    responseSnippet?: string;
  };
  /** If the canary started succeeding, the endpoint is lying */
  reason?: string;
}

export interface CredentialClassification {
  username: string;
  password: string;
  state: CredentialState;
  evidence: {
    responseCode?: number;
    responseSnippet?: string;
    mfaIndicators?: string[];
    sessionObtained?: boolean;
    redirectUrl?: string;
  };
  source?: string;
}

export interface VerificationBatchResult {
  /** Negative control status */
  negativeControl: NegativeControlResult;
  /** Classified credentials */
  credentials: CredentialClassification[];
  /** Whether the batch results are trustworthy */
  trustworthy: boolean;
  /** If not trustworthy, why */
  quarantineReason?: string;
}

// ─── MFA Detection Patterns ─────────────────────────────────────────────────

const MFA_INDICATORS = [
  /two.?factor/i,
  /2fa/i,
  /mfa/i,
  /verification.?code/i,
  /authenticator/i,
  /one.?time.?password/i,
  /otp/i,
  /sms.?code/i,
  /security.?code/i,
  /enter.?code/i,
  /verify.?identity/i,
  /additional.?verification/i,
  /second.?step/i,
  /confirm.?device/i,
  /push.?notification/i,
  /approve.?login/i,
  /duo/i,
  /okta.?verify/i,
  /google.?authenticator/i,
  /microsoft.?authenticator/i,
];

// ─── Negative Control Canary ────────────────────────────────────────────────

/**
 * Generate a canary credential that should ALWAYS fail.
 * Uses a UUID-based username and random password to ensure no collision with real accounts.
 */
function generateCanaryCredential(): { username: string; password: string } {
  const canaryId = `canary-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return {
    username: `__CANARY_INVALID_${canaryId}@nonexistent.invalid`,
    password: `CANARY_${Math.random().toString(36).slice(2, 20)}_INVALID`,
  };
}

/**
 * Run the negative-control canary test.
 * 
 * Strategy: Send a known-invalid credential. If it succeeds, the endpoint
 * is not giving truthful responses (e.g., lockout page returning 200 for all,
 * or WAF blocking everything with a generic page).
 */
export async function runNegativeControl(
  testFn: (username: string, password: string) => Promise<{ success: boolean; responseCode?: number; responseSnippet?: string }>,
): Promise<NegativeControlResult> {
  const canary = generateCanaryCredential();

  const response = await testFn(canary.username, canary.password);

  if (response.success) {
    // The canary "succeeded" — this means the endpoint is lying
    return {
      passed: false,
      canaryUsername: canary.username,
      canaryPassword: canary.password,
      canaryResponse: response,
      reason: `NEGATIVE_CONTROL_FAILED: Known-invalid credential (${canary.username}) was accepted. Endpoint is returning false positives — likely a lockout page, WAF block, or misconfigured success detection.`,
    };
  }

  return {
    passed: true,
    canaryUsername: canary.username,
    canaryPassword: canary.password,
    canaryResponse: response,
  };
}

// ─── Four-State Credential Classification ───────────────────────────────────

/**
 * Classify a credential test result into one of four states.
 * 
 * VALID:             Login succeeded, session obtained
 * INVALID:           Login failed with expected failure response
 * VALID_MFA_BLOCKED: Password accepted but MFA gate prevents full session
 * INDETERMINATE:     Response doesn't match expected patterns
 */
export function classifyCredentialResult(
  username: string,
  password: string,
  response: { success: boolean; responseCode?: number; responseSnippet?: string; error?: string },
  source?: string,
): CredentialClassification {
  const snippet = response.responseSnippet || "";
  const code = response.responseCode;

  // Check for MFA indicators in the response
  const mfaMatches = MFA_INDICATORS.filter(pattern => pattern.test(snippet));

  // Case 1: Explicit success
  if (response.success && mfaMatches.length === 0) {
    return {
      username,
      password,
      state: "VALID",
      evidence: {
        responseCode: code,
        responseSnippet: snippet.slice(0, 500),
        sessionObtained: true,
      },
      source,
    };
  }

  // Case 2: MFA blocked — password was correct but MFA prevents session
  // Indicators: 200/302 response with MFA keywords, or success=true with MFA in body
  if (mfaMatches.length > 0) {
    // If we got a 200/302 AND MFA indicators, the password is likely correct
    const likelyValidPassword = (code === 200 || code === 302 || response.success);
    if (likelyValidPassword) {
      return {
        username,
        password,
        state: "VALID_MFA_BLOCKED",
        evidence: {
          responseCode: code,
          responseSnippet: snippet.slice(0, 500),
          mfaIndicators: mfaMatches.map(m => m.source),
          sessionObtained: false,
        },
        source,
      };
    }
  }

  // Case 3: Clear failure — expected rejection patterns
  const isExpectedFailure = (
    code === 401 ||
    code === 403 ||
    /invalid|incorrect|wrong|failed|denied|unauthorized/i.test(snippet)
  );

  if (!response.success && isExpectedFailure) {
    return {
      username,
      password,
      state: "INVALID",
      evidence: {
        responseCode: code,
        responseSnippet: snippet.slice(0, 500),
        sessionObtained: false,
      },
      source,
    };
  }

  // Case 4: Indeterminate — response doesn't match expected patterns
  // This could be: WAF blocking, generic error page, timeout, unexpected redirect
  return {
    username,
    password,
    state: "INDETERMINATE",
    evidence: {
      responseCode: code,
      responseSnippet: snippet.slice(0, 500),
      sessionObtained: false,
    },
    source,
  };
}

// ─── Verified Credential Batch Testing ──────────────────────────────────────

/**
 * Run a verified credential testing batch with negative-control gates.
 * 
 * Flow:
 * 1. Run negative-control canary (pre-batch)
 * 2. Test each credential pair and classify
 * 3. Run negative-control canary again (post-batch)
 * 4. If post-batch canary fails, quarantine all results
 * 
 * This catches the case where lockout/rate-limiting kicked in mid-batch
 * and the endpoint started returning false responses.
 */
export async function runVerifiedCredentialBatch(
  testFn: (username: string, password: string) => Promise<{ success: boolean; responseCode?: number; responseSnippet?: string; error?: string }>,
  credentials: Array<{ username: string; password: string; source?: string }>,
  options?: {
    delayBetweenMs?: number;
    midBatchCanaryInterval?: number; // Run canary every N attempts
  },
): Promise<VerificationBatchResult> {
  const delayMs = options?.delayBetweenMs || 500;
  const canaryInterval = options?.midBatchCanaryInterval || 10;

  // 1. Pre-batch negative control
  const preCanary = await runNegativeControl(testFn);
  if (!preCanary.passed) {
    return {
      negativeControl: preCanary,
      credentials: credentials.map(c => ({
        username: c.username,
        password: c.password,
        state: "INDETERMINATE" as CredentialState,
        evidence: {},
        source: c.source,
      })),
      trustworthy: false,
      quarantineReason: preCanary.reason,
    };
  }

  // 2. Test each credential with classification
  const results: CredentialClassification[] = [];
  let batchQuarantined = false;
  let quarantineReason: string | undefined;

  for (let i = 0; i < credentials.length; i++) {
    const cred = credentials[i];

    // Mid-batch canary check
    if (i > 0 && i % canaryInterval === 0) {
      const midCanary = await runNegativeControl(testFn);
      if (!midCanary.passed) {
        batchQuarantined = true;
        quarantineReason = `Mid-batch canary failed at attempt ${i}: ${midCanary.reason}`;
        // Mark remaining credentials as indeterminate
        for (let j = i; j < credentials.length; j++) {
          results.push({
            username: credentials[j].username,
            password: credentials[j].password,
            state: "INDETERMINATE",
            evidence: {},
            source: credentials[j].source,
          });
        }
        break;
      }
    }

    // Test the credential
    try {
      const response = await testFn(cred.username, cred.password);
      results.push(classifyCredentialResult(cred.username, cred.password, response, cred.source));
    } catch (err: any) {
      results.push({
        username: cred.username,
        password: cred.password,
        state: "INDETERMINATE",
        evidence: { responseSnippet: err.message },
        source: cred.source,
      });
    }

    // Delay between attempts
    if (i < credentials.length - 1) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  // 3. Post-batch negative control (only if not already quarantined)
  let postCanary: NegativeControlResult | undefined;
  if (!batchQuarantined) {
    postCanary = await runNegativeControl(testFn);
    if (!postCanary.passed) {
      batchQuarantined = true;
      quarantineReason = `Post-batch canary failed: ${postCanary.reason}. Results from this batch may include false positives.`;
    }
  }

  return {
    negativeControl: postCanary || preCanary,
    credentials: results,
    trustworthy: !batchQuarantined,
    quarantineReason,
  };
}

// ─── Credential State Summary ───────────────────────────────────────────────

/**
 * Summarize credential classification results for reporting.
 */
export function summarizeCredentialResults(results: CredentialClassification[]): {
  valid: CredentialClassification[];
  mfaBlocked: CredentialClassification[];
  invalid: CredentialClassification[];
  indeterminate: CredentialClassification[];
  summary: string;
} {
  const valid = results.filter(r => r.state === "VALID");
  const mfaBlocked = results.filter(r => r.state === "VALID_MFA_BLOCKED");
  const invalid = results.filter(r => r.state === "INVALID");
  const indeterminate = results.filter(r => r.state === "INDETERMINATE");

  const parts: string[] = [];
  if (valid.length > 0) parts.push(`${valid.length} VALID (full access)`);
  if (mfaBlocked.length > 0) parts.push(`${mfaBlocked.length} VALID_MFA_BLOCKED (password reuse confirmed, MFA only remaining control)`);
  if (invalid.length > 0) parts.push(`${invalid.length} INVALID`);
  if (indeterminate.length > 0) parts.push(`${indeterminate.length} INDETERMINATE (endpoint may be unreliable)`);

  return {
    valid,
    mfaBlocked,
    invalid,
    indeterminate,
    summary: parts.join(", ") || "No credentials tested",
  };
}
