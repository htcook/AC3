import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/auth-testing-knowledge.ts
function calculateAuthCarverScore(conditions) {
  const weights = { ...AUTH_CARVER_OVERLAY.defaultWeights };
  for (const adj of AUTH_CARVER_OVERLAY.adjustments) {
    if (conditions.includes(adj.conditionKey)) {
      for (const [factor, delta] of Object.entries(adj.changes)) {
        if (factor in weights) {
          weights[factor] = Math.max(0, Math.min(10, weights[factor] + delta));
        }
      }
    }
  }
  const totalScore = Object.values(weights).reduce((sum, w) => sum + w, 0);
  const maxScore = 60;
  return {
    weights,
    totalScore,
    maxScore,
    percentage: Math.round(totalScore / maxScore * 100)
  };
}
function buildAuthKnowledgeContext() {
  const sections = [];
  sections.push("## Authentication Testing Knowledge Base");
  sections.push(`${AUTH_TESTING_PHASES.length} testing phases | ${AUTH_ATTACK_TAXONOMY.length} attack classes | ${SSO_ASSESSMENT_CHECKS.length} SSO checks | ${AUTH_MITRE_MAPPINGS.length} MITRE mappings`);
  const phaseSummary = AUTH_TESTING_PHASES.map(
    (p) => `**Phase ${p.order}: ${p.phase}** \u2014 ${p.objectives[0]}. Tools: ${p.tools.join(", ")}.`
  ).join("\n");
  sections.push(`### Auth Testing Phases
${phaseSummary}`);
  const attackSummary = AUTH_ATTACK_TAXONOMY.map(
    (a) => `**${a.name}** [${a.mitreTechniques.join(",")}] \u2014 ${a.subtypes.length} subtypes. Signals: ${a.signals.slice(0, 2).join("; ")}.`
  ).join("\n");
  sections.push(`### Attack Classes
${attackSummary}`);
  const oauthChecks = SSO_ASSESSMENT_CHECKS.filter((c) => c.protocol === "oauth_oidc");
  const samlChecks = SSO_ASSESSMENT_CHECKS.filter((c) => c.protocol === "saml");
  sections.push(`### SSO Assessment
${oauthChecks.length} OAuth/OIDC checks | ${samlChecks.length} SAML checks`);
  return sections.join("\n\n");
}
function validateAgainstGuardrails(action, guardrails) {
  const violations = [];
  if (action.rps !== void 0 && action.rps > guardrails.maxRps) {
    violations.push(`Rate ${action.rps} RPS exceeds limit of ${guardrails.maxRps} RPS`);
  }
  if (action.attemptsPerAccount !== void 0 && action.attemptsPerAccount > guardrails.maxAttemptsPerAccount) {
    violations.push(`${action.attemptsPerAccount} attempts/account exceeds limit of ${guardrails.maxAttemptsPerAccount}`);
  }
  if (guardrails.requireScopeAllowlist && guardrails.scopeAllowlist && action.target) {
    const inScope = guardrails.scopeAllowlist.some(
      (s) => action.target.includes(s)
    );
    if (!inScope) {
      violations.push(`Target ${action.target} not in scope allowlist`);
    }
  }
  if (guardrails.requireEvidenceCapture && action.hasEvidence === false) {
    violations.push("Evidence capture required but not enabled");
  }
  return { valid: violations.length === 0, violations };
}
var AUTH_TESTING_PHASES, AUTH_ATTACK_TAXONOMY, AUTH_MITRE_MAPPINGS, SSO_ASSESSMENT_CHECKS, AUTH_CARVER_OVERLAY, FEDERAL_AUTH_CONTROLS, AUTH_REASONING_SYSTEM_PROMPT, AUTH_TOOLING_STACK, STRICT_MODE_GUARDRAILS, STANDARD_MODE_GUARDRAILS;
var init_auth_testing_knowledge = __esm({
  "server/lib/auth-testing-knowledge.ts"() {
    AUTH_TESTING_PHASES = [
      {
        phase: "Recon & Identification",
        order: 1,
        objectives: [
          "Identify login endpoints and auth entrypoints",
          "Detect auth framework (cookies, headers, redirects)",
          "Identify SSO provider (OIDC/OAuth/SAML)",
          "Identify MFA mechanisms and recovery flows",
          "Map all authentication-related endpoints (login, register, reset, verify, callback)"
        ],
        artifacts: [
          "HTTP headers",
          "Cookies",
          "Redirect chains",
          "Response codes",
          "Login form parameters",
          "SSO metadata documents",
          "MFA configuration indicators"
        ],
        tools: ["ffuf", "scanforge-discovery", "zap", "burp_suite", "mitmproxy"],
        guardrails: [
          "Passive observation only \u2014 no active probing in this phase",
          "Record all redirect chains for evidence",
          "Do not attempt authentication yet"
        ]
      },
      {
        phase: "Enumeration Testing",
        order: 2,
        objectives: [
          "Detect username/email enumeration via response differences",
          "Detect timing side-channels in authentication responses",
          "Validate rate limits and lockout behavior safely",
          "Identify error message information leakage"
        ],
        artifacts: [
          "Response length/time deltas",
          "Error message variants",
          "Header differences between valid/invalid usernames",
          "Rate limit trigger thresholds"
        ],
        tools: ["custom_http_probe", "zap", "burp_suite", "ffuf"],
        guardrails: [
          "Use controlled, low-rate probes (max 0.1 RPS in strict mode)",
          "Avoid lockout thresholds \u2014 max 2 attempts per account",
          "Use non-existing accounts and a single known-valid account when authorized",
          "Stop immediately on lockout signal (429/403)"
        ]
      },
      {
        phase: "Credential Surface Analysis",
        order: 3,
        objectives: [
          "Assess lockout thresholds and throttling mechanisms",
          "Assess CAPTCHA effectiveness and bypass conditions",
          "Assess password policy strength and enforcement",
          "Assess password reset design and token security",
          "Evaluate account recovery flow robustness"
        ],
        artifacts: [
          "Lockout behavior documentation",
          "CAPTCHA trigger conditions",
          "Password policy requirements",
          "Reset token characteristics (length, entropy, expiry)"
        ],
        tools: ["zap", "burp_suite", "hydra"],
        guardrails: [
          "Credential guessing requires explicit written authorization",
          "Use strict rate limits even when authorized",
          "Document all lockout events for evidence",
          "Coordinate with target monitoring team before testing"
        ]
      },
      {
        phase: "Flow Manipulation",
        order: 4,
        objectives: [
          "Model the auth state machine and transitions",
          "Test for step skipping and direct resource access",
          "Test parameter tampering and state desynchronization",
          "Assess MFA and recovery flow weaknesses (logic-based)",
          "Test for race conditions in auth flows"
        ],
        artifacts: [
          "State machine diagram",
          "Step-skip test results",
          "Parameter tampering evidence",
          "MFA bypass attempt logs"
        ],
        tools: ["burp_suite", "mitmproxy", "zap"],
        guardrails: [
          "Focus on logic analysis over brute forcing",
          "Document all state transitions tested",
          "Do not attempt to bypass MFA without authorization",
          "Record full request/response pairs for all manipulation attempts"
        ]
      },
      {
        phase: "Session & Token Security",
        order: 5,
        objectives: [
          "Validate cookie flags (Secure/HttpOnly/SameSite)",
          "Test session fixation and logout invalidation",
          "Inspect token lifetimes, rotation, replay protection",
          "Assess JWT/OAuth token handling and audience/issuer checks",
          "Evaluate refresh token controls and revocation"
        ],
        artifacts: [
          "Cookie audit results",
          "Session fixation test evidence",
          "JWT claim analysis",
          "Token lifecycle documentation",
          "Refresh token rotation evidence"
        ],
        tools: ["zap", "jwt_tool", "testssl", "burp_suite", "mitmproxy"],
        guardrails: [
          "Use only authorized test accounts for session testing",
          "Do not attempt to hijack real user sessions",
          "Document all token values observed (redact sensitive data in reports)"
        ]
      },
      {
        phase: "Post-Authentication Abuse",
        order: 6,
        objectives: [
          "Test authorization boundaries (IDOR/horizontal/vertical)",
          "Assess API token scoping and refresh token controls",
          "Identify escalation paths from authenticated context",
          "Test cross-tenant isolation in multi-tenant applications",
          "Assess data exposure through authenticated API endpoints"
        ],
        artifacts: [
          "IDOR proof-of-concept evidence",
          "Privilege escalation paths",
          "API scope analysis",
          "Cross-tenant access test results"
        ],
        tools: ["burp_suite", "zap", "impacket", "bloodhound"],
        guardrails: [
          "Stay within authorized scope \u2014 do not access other users' data",
          "Report IDOR findings immediately to engagement lead",
          "Document all privilege escalation attempts with timestamps"
        ]
      }
    ];
    AUTH_ATTACK_TAXONOMY = [
      {
        id: "AUTH-ATTACK-001",
        name: "Username Enumeration",
        description: "Detection of valid usernames through observable differences in application responses to valid vs. invalid credentials. Enumeration enables targeted credential attacks and social engineering.",
        signals: [
          "HTTP status variance across invalid/valid usernames",
          "Response length differences beyond baseline noise (>50 bytes)",
          "Timing delta beyond jitter threshold (>100ms consistent)",
          "Redirect chain differences between valid and invalid accounts",
          "Different error messages for valid vs. invalid usernames"
        ],
        subtypes: [
          {
            name: "Response-Based Enumeration",
            description: "Different HTTP status codes or response bodies for valid vs. invalid usernames",
            signals: ["HTTP 200 vs 401 for different usernames", "Different error text in response body"]
          },
          {
            name: "Timing-Based Enumeration",
            description: "Measurable timing differences due to password hash computation for valid accounts",
            signals: ["Consistent >100ms delta between valid and invalid username responses"]
          },
          {
            name: "Side-Channel Enumeration",
            description: "Information leakage through headers, redirects, or secondary channels",
            signals: ["Different Set-Cookie headers", "Different redirect targets", "Different response headers"]
          }
        ],
        safeTestNotes: [
          "Use controlled, low-rate probes",
          "Avoid lockout thresholds",
          "Use non-existing accounts and a single known-valid account when authorized"
        ],
        mitreTechniques: ["T1110"],
        relatedPhases: ["Enumeration Testing"]
      },
      {
        id: "AUTH-ATTACK-002",
        name: "Credential Defense Analysis",
        description: "Assessment of lockouts, throttling, MFA gating, and monitoring without high-volume guessing. Focus on understanding the defensive posture rather than attempting to bypass it.",
        signals: [
          "429/403 response patterns indicating rate limiting",
          "CAPTCHA triggers and challenge presentation",
          "Account lock messages and lockout duration",
          "Backoff behavior (progressive delays)",
          "MFA challenge presentation timing"
        ],
        subtypes: [
          {
            name: "Lockout Threshold Analysis",
            description: "Determine the number of failed attempts before account lockout",
            signals: ["Account locked message", "403 after N attempts", "Lockout duration indicators"]
          },
          {
            name: "Rate Limit Assessment",
            description: "Evaluate rate limiting mechanisms and their bypass potential",
            signals: ["429 responses", "Retry-After headers", "IP-based vs. account-based limiting"]
          },
          {
            name: "CAPTCHA Effectiveness",
            description: "Assess CAPTCHA implementation and potential bypass conditions",
            signals: ["CAPTCHA trigger threshold", "CAPTCHA type and difficulty", "Bypass via API endpoints"]
          }
        ],
        safeTestNotes: [
          "Do not trigger actual account lockouts in production",
          "Coordinate with target monitoring team",
          "Document all rate limit encounters"
        ],
        mitreTechniques: ["T1110.001", "T1110.003"],
        relatedPhases: ["Credential Surface Analysis"]
      },
      {
        id: "AUTH-ATTACK-003",
        name: "MFA Bypass Logic",
        description: "Assessment of multi-factor authentication implementation for logic-level weaknesses. Focuses on state management, token binding, and flow integrity rather than brute-force approaches.",
        signals: [
          "Missing state checks between MFA steps",
          "OTP not bound to session",
          "Replayable recovery tokens",
          "Device trust persisted without proper validation",
          "Race conditions in OTP verification"
        ],
        subtypes: [
          {
            name: "Step Skipping",
            description: "Bypassing MFA by directly accessing post-MFA resources without completing the MFA challenge",
            signals: ["Direct URL access to authenticated resources", "Missing server-side MFA completion check"]
          },
          {
            name: "OTP Reuse",
            description: "Reusing a previously valid OTP code after it should have expired",
            signals: ["OTP accepted after expiry window", "Same OTP valid across multiple sessions"]
          },
          {
            name: "Race Condition",
            description: "Exploiting timing windows in MFA verification to bypass or reuse codes",
            signals: ["Concurrent requests accepted with same OTP", "TOCTOU vulnerability in verification"]
          },
          {
            name: "Recovery Flow Abuse",
            description: "Exploiting account recovery mechanisms to bypass MFA entirely",
            signals: ["Recovery flow skips MFA re-enrollment", "Weak recovery token generation"]
          },
          {
            name: "Device Trust Abuse",
            description: "Manipulating device trust mechanisms to avoid MFA challenges",
            signals: ["Device trust cookie transferable", "No device fingerprint validation"]
          }
        ],
        safeTestNotes: [
          "Only test with authorized test accounts",
          "Do not attempt to bypass MFA on production accounts",
          "Document all bypass attempts with full evidence"
        ],
        mitreTechniques: ["T1556", "T1111"],
        relatedPhases: ["Flow Manipulation"]
      },
      {
        id: "AUTH-ATTACK-004",
        name: "Token & Session Attacks",
        description: "Assessment of session management and token security including cookies, JWTs, OAuth tokens, and session lifecycle management.",
        signals: [
          "Static session ID across login (session fixation)",
          "Missing SameSite cookie attribute",
          "No token rotation on privilege change",
          "Weak logout invalidation (session persists after logout)",
          "CSRF on login endpoint"
        ],
        subtypes: [
          {
            name: "Session Fixation",
            description: "Forcing a known session ID onto a victim before they authenticate",
            signals: ["Session ID unchanged after authentication", "Session ID accepted from URL parameter"]
          },
          {
            name: "Weak Cookie Flags",
            description: "Missing or misconfigured cookie security attributes",
            signals: ["Missing Secure flag", "Missing HttpOnly flag", "Missing or lax SameSite"]
          },
          {
            name: "JWT Misuse",
            description: "Vulnerabilities in JWT implementation including algorithm confusion and weak signing",
            signals: ["Algorithm none accepted", "Weak HMAC secret", "Missing audience/issuer validation"]
          },
          {
            name: "Token Replay",
            description: "Reusing captured tokens to gain unauthorized access",
            signals: ["No token expiry enforcement", "No replay detection", "Tokens valid across sessions"]
          },
          {
            name: "CSRF on Login",
            description: "Cross-site request forgery on the login endpoint enabling login CSRF attacks",
            signals: ["No CSRF token on login form", "Login accepts cross-origin requests"]
          }
        ],
        safeTestNotes: [
          "Use only test accounts for session manipulation",
          "Do not intercept real user sessions",
          "Document all token values (redact in final reports)"
        ],
        mitreTechniques: ["T1550", "T1539"],
        relatedPhases: ["Session & Token Security"]
      },
      {
        id: "AUTH-ATTACK-005",
        name: "Password Reset Abuse",
        description: "Assessment of password reset and account recovery mechanisms for security weaknesses in token generation, delivery, and validation.",
        signals: [
          "Predictable reset tokens",
          "Reset link bound to user ID in URL (IDOR)",
          "Weak link domain validation",
          "Token reuse after password change",
          "Host header poisoning in reset emails"
        ],
        subtypes: [
          {
            name: "Token Reuse",
            description: "Reset token remains valid after being used to change password",
            signals: ["Token accepted after password change", "No single-use enforcement"]
          },
          {
            name: "IDOR Reset Link",
            description: "Reset link contains predictable user identifier enabling cross-account reset",
            signals: ["Sequential user IDs in reset URL", "User ID modifiable in reset request"]
          },
          {
            name: "Host Header Poisoning",
            description: "Manipulating the Host header to redirect reset links to attacker-controlled domain",
            signals: ["Reset email contains Host header value", "No fixed domain in reset URL generation"]
          },
          {
            name: "Rate Limit Bypass on Reset",
            description: "Bypassing rate limits on password reset to enable token brute-force",
            signals: ["No rate limit on reset endpoint", "Rate limit bypassable via IP rotation"]
          }
        ],
        safeTestNotes: [
          "Only test with authorized test accounts",
          "Do not send reset emails to real users",
          "Coordinate with email team if testing email delivery"
        ],
        mitreTechniques: ["T1556", "T1078"],
        relatedPhases: ["Credential Surface Analysis", "Flow Manipulation"]
      }
    ];
    AUTH_MITRE_MAPPINGS = [
      {
        findingType: "username_enumeration",
        tactic: "Credential Access",
        techniqueId: "T1110",
        techniqueName: "Brute Force",
        notes: "Enumeration supports password spraying/stuffing risk by identifying valid accounts."
      },
      {
        findingType: "credential_stuffing_risk",
        tactic: "Credential Access",
        techniqueId: "T1110.004",
        techniqueName: "Credential Stuffing",
        notes: "Weak rate limiting or lockout enables credential stuffing attacks with breached credential databases."
      },
      {
        findingType: "valid_account_abuse",
        tactic: "Defense Evasion",
        techniqueId: "T1078",
        techniqueName: "Valid Accounts",
        notes: "Compromised credentials enable defense evasion by using legitimate access."
      },
      {
        findingType: "exploit_public_facing_app",
        tactic: "Initial Access",
        techniqueId: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        notes: "Auth bypass vulnerabilities in public-facing login portals enable initial access."
      },
      {
        findingType: "modify_auth_process",
        tactic: "Credential Access",
        techniqueId: "T1556",
        techniqueName: "Modify Authentication Process",
        notes: "MFA bypass and auth flow manipulation modify the intended authentication process."
      },
      {
        findingType: "steal_web_session_cookie",
        tactic: "Credential Access",
        techniqueId: "T1539",
        techniqueName: "Steal Web Session Cookie",
        notes: "Weak cookie flags and session management enable session theft."
      },
      {
        findingType: "use_alternate_auth_material",
        tactic: "Defense Evasion",
        techniqueId: "T1550",
        techniqueName: "Use Alternate Authentication Material",
        notes: "Token replay and JWT misuse enable access via alternate authentication material."
      },
      {
        findingType: "input_capture",
        tactic: "Collection",
        techniqueId: "T1056",
        techniqueName: "Input Capture",
        notes: "Credential capture via phishing landing pages or keyloggers on login forms."
      }
    ];
    SSO_ASSESSMENT_CHECKS = [
      {
        id: "SSO-OAUTH-001",
        protocol: "oauth_oidc",
        name: "Redirect URI Validation",
        whatToVerify: [
          "Exact match enforcement (no substring matching)",
          "No open redirect chaining via redirect_uri parameter",
          "No wildcard or overly-broad URI patterns",
          "Reject unregistered redirect URIs"
        ],
        commonFindings: [
          "Open redirect enabling OAuth code/token leakage",
          "Subdomain takeover enabling redirect URI hijack",
          "Path traversal in redirect URI validation"
        ],
        severity: "critical",
        fedrampControls: ["AC-2", "IA-2"]
      },
      {
        id: "SSO-OAUTH-002",
        protocol: "oauth_oidc",
        name: "State Parameter Integrity",
        whatToVerify: [
          "State parameter required on authorization requests",
          "State bound to user session (not just present)",
          "Reject missing or mismatched state on callback",
          "State has sufficient entropy (\u2265128 bits)"
        ],
        commonFindings: [
          "Missing state parameter enabling CSRF on OAuth flow",
          "State not bound to session enabling cross-user attacks"
        ],
        severity: "high",
        fedrampControls: ["IA-2", "SC-23"]
      },
      {
        id: "SSO-OAUTH-003",
        protocol: "oauth_oidc",
        name: "PKCE Enforcement",
        whatToVerify: [
          "code_challenge required for public clients",
          "Reject missing code_verifier on token exchange",
          "S256 method preferred over plain",
          "Reject reused code_challenge values"
        ],
        commonFindings: [
          "PKCE not enforced for public clients (SPAs, mobile apps)",
          "Plain method accepted instead of S256"
        ],
        severity: "high",
        fedrampControls: ["IA-2", "IA-5"]
      },
      {
        id: "SSO-OAUTH-004",
        protocol: "oauth_oidc",
        name: "Nonce Validation (OIDC)",
        whatToVerify: [
          "Nonce present in ID token",
          "Nonce bound to session",
          "Reject replay of ID tokens with same nonce",
          "Nonce has sufficient entropy"
        ],
        commonFindings: [
          "Missing nonce enabling ID token replay",
          "Nonce not validated on client side"
        ],
        severity: "medium",
        fedrampControls: ["IA-2", "SC-23"]
      },
      {
        id: "SSO-OAUTH-005",
        protocol: "oauth_oidc",
        name: "Token Audience/Issuer Checks",
        whatToVerify: [
          "aud claim matches expected client ID",
          "iss claim matches expected provider",
          "Reject tokens from other tenants/providers",
          "Validate token signature with correct key"
        ],
        commonFindings: [
          "Tokens from other tenants accepted (cross-tenant attack)",
          "Issuer not validated enabling token substitution"
        ],
        severity: "critical",
        fedrampControls: ["AC-2", "IA-2", "IA-5"]
      },
      {
        id: "SSO-OAUTH-006",
        protocol: "oauth_oidc",
        name: "Refresh Token Controls",
        whatToVerify: [
          "Refresh token rotation on use",
          "Revocation on reuse detection (replay)",
          "Scoped permissions (not broader than access token)",
          "Short lifetimes appropriate to risk level",
          "Revocation endpoint functional"
        ],
        commonFindings: [
          "Refresh tokens not rotated enabling persistent access",
          "Reuse detection missing enabling token theft exploitation"
        ],
        severity: "high",
        fedrampControls: ["IA-5", "IA-5(1)", "SC-23"]
      },
      {
        id: "SSO-SAML-001",
        protocol: "saml",
        name: "Signature Validation",
        whatToVerify: [
          "Signed assertions/responses as required by SP policy",
          "Validate certificate chain/pinning policy",
          "Reject unsigned assertions when signing is required",
          "Reject assertions signed with untrusted certificates"
        ],
        commonFindings: [
          "SAML signature wrapping / insufficient validation",
          "Unsigned assertions accepted",
          "Self-signed certificates accepted without pinning"
        ],
        severity: "critical",
        fedrampControls: ["IA-2", "IA-2(1)", "SC-12(3)"]
      },
      {
        id: "SSO-SAML-002",
        protocol: "saml",
        name: "InResponseTo Validation",
        whatToVerify: [
          "InResponseTo matches original AuthnRequest ID",
          "Reject missing InResponseTo when expected",
          "Reject reused InResponseTo values (replay)"
        ],
        commonFindings: [
          "InResponseTo not validated enabling response injection",
          "Replay of SAML responses accepted"
        ],
        severity: "high",
        fedrampControls: ["IA-2", "SC-23"]
      },
      {
        id: "SSO-SAML-003",
        protocol: "saml",
        name: "Audience Restriction",
        whatToVerify: [
          "Audience matches SP entity ID exactly",
          "Reject assertions with broad or missing audience",
          "Reject assertions intended for other SPs"
        ],
        commonFindings: [
          "Audience restriction not enforced enabling cross-SP attacks",
          "Wildcard audience accepted"
        ],
        severity: "high",
        fedrampControls: ["AC-2", "IA-2"]
      },
      {
        id: "SSO-SAML-004",
        protocol: "saml",
        name: "Recipient/Destination Checks",
        whatToVerify: [
          "Destination matches ACS endpoint URL",
          "Reject mismatched destinations",
          "Validate scheme and host (not just path)"
        ],
        commonFindings: [
          "Destination not validated enabling assertion redirection",
          "Partial URL matching enabling subdomain attacks"
        ],
        severity: "high",
        fedrampControls: ["IA-2", "SC-23"]
      },
      {
        id: "SSO-SAML-005",
        protocol: "saml",
        name: "Clock Skew and Replay",
        whatToVerify: [
          "NotBefore/NotOnOrAfter conditions enforced",
          "Reasonable clock skew tolerance (\u22645 minutes)",
          "Replay cache prevents assertion reuse",
          "Expired assertions rejected"
        ],
        commonFindings: [
          "Excessive clock skew tolerance enabling old assertion replay",
          "No replay cache enabling assertion reuse"
        ],
        severity: "medium",
        fedrampControls: ["IA-2", "AU-2"]
      }
    ];
    AUTH_CARVER_OVERLAY = {
      defaultWeights: {
        criticality: 9,
        accessibility: 8,
        recuperability: 6,
        vulnerability: 7,
        effect: 9,
        recognizability: 8
      },
      adjustments: [
        {
          condition: "MFA bypass confirmed",
          conditionKey: "mfa_bypass_confirmed",
          changes: { effect: 2, criticality: 1 }
        },
        {
          condition: "Username enumeration only (no credential access)",
          conditionKey: "username_enumeration_only",
          changes: { effect: -2 }
        },
        {
          condition: "Refresh token replay possible",
          conditionKey: "refresh_token_replay_possible",
          changes: { effect: 2, accessibility: 1 }
        },
        {
          condition: "Weak session management",
          conditionKey: "weak_session_management",
          changes: { vulnerability: 1, effect: 1 }
        },
        {
          condition: "SAML signature bypass",
          conditionKey: "saml_signature_bypass",
          changes: { criticality: 2, effect: 2, vulnerability: 2 }
        },
        {
          condition: "OAuth redirect URI hijack",
          conditionKey: "oauth_redirect_hijack",
          changes: { criticality: 1, effect: 2, accessibility: 1 }
        }
      ]
    };
    FEDERAL_AUTH_CONTROLS = [
      // Moderate baseline
      { controlId: "AC-2", title: "Account Management", baseline: "moderate", authRelevance: "Account provisioning, deprovisioning, and access review processes", testingNotes: "Verify account lifecycle management and orphaned account detection" },
      { controlId: "AC-7", title: "Unsuccessful Logon Attempts", baseline: "moderate", authRelevance: "Lockout/throttling evaluation must not cause user impact", testingNotes: "Verify configuration and monitoring without triggering production lockouts" },
      { controlId: "IA-2", title: "Identification and Authentication", baseline: "moderate", authRelevance: "MFA/SSO enforcement validated by flow state modeling", testingNotes: "Deterministic checks on auth flow integrity and MFA enforcement" },
      { controlId: "IA-5", title: "Authenticator Management", baseline: "moderate", authRelevance: "Authenticator lifecycle assessed via password reset and recovery flow logic", testingNotes: "Test password policy, reset flows, and token management" },
      { controlId: "IA-5(1)", title: "Password-Based Authentication", baseline: "moderate", authRelevance: "Password complexity, history, and age requirements", testingNotes: "Verify password policy enforcement and history checks" },
      { controlId: "SC-23", title: "Session Authenticity", baseline: "moderate", authRelevance: "Session binding, cookie security, and anti-replay mechanisms", testingNotes: "Validate session management, cookie flags, and token binding" },
      { controlId: "AU-2", title: "Audit Events", baseline: "moderate", authRelevance: "Authentication events must be logged and auditable", testingNotes: "Verify auth event logging completeness and integrity" },
      { controlId: "AU-12", title: "Audit Generation", baseline: "moderate", authRelevance: "Audit records generated for all auth-related events", testingNotes: "Verify audit trail for login, logout, MFA, and password changes" },
      // High baseline additions
      { controlId: "IA-2(1)", title: "Multi-Factor Authentication to Privileged Accounts", baseline: "high", authRelevance: "MFA required for all privileged account access", testingNotes: "Verify MFA enforcement on admin and privileged accounts" },
      { controlId: "IA-2(11)", title: "Remote Access \u2013 Separate Device", baseline: "high", authRelevance: "MFA via separate device for remote access", testingNotes: "Verify MFA device separation for remote authentication" },
      { controlId: "IA-5(13)", title: "Expiration of Cached Authenticators", baseline: "high", authRelevance: "Cached credentials must expire within defined timeframes", testingNotes: "Verify token expiry and cached session timeout enforcement" },
      { controlId: "AU-6(3)", title: "Correlate Audit Repositories", baseline: "high", authRelevance: "Auth audit logs correlated across systems", testingNotes: "Verify cross-system auth event correlation capability" },
      { controlId: "SC-12(3)", title: "Asymmetric Keys", baseline: "high", authRelevance: "Asymmetric key management for SAML/OAuth signing", testingNotes: "Verify certificate management and key rotation for SSO" }
    ];
    AUTH_REASONING_SYSTEM_PROMPT = `
## Authentication Testing Reasoning Framework

When the engagement involves authentication portal testing, follow this structured reasoning chain:

### Step 1: Evidence Ingestion
Ingest all available evidence: HAR files, ZAP/Burp reports, HTTP headers, timing data, screenshots.
Classify the evidence by auth phase (recon, enumeration, credential surface, flow manipulation, session/token, post-auth).

### Step 2: Auth Type Classification
Identify and classify the authentication mechanism:
- **Local auth**: Username/password with server-side session
- **OAuth/OIDC**: Authorization code flow, implicit flow, client credentials
- **SAML**: SP-initiated or IdP-initiated SSO
- **Hybrid**: Multiple auth mechanisms (e.g., local + SSO fallback)

### Step 3: Flow State Machine Modeling
Model the authentication flow as a state machine:
- Map all states (unauthenticated \u2192 credentials submitted \u2192 MFA challenge \u2192 authenticated)
- Identify state transitions and their guards
- Look for missing guards (step skipping, state desynchronization)

### Step 4: Safe Signal Detection
Run safe, low-impact checks:
- Enumeration signals (response length/time deltas)
- Cookie flag audit (Secure, HttpOnly, SameSite)
- Token claim inspection (JWT aud, iss, exp, nbf)
- Redirect URI integrity (exact match, no open redirect)
- Session fixation indicators (session ID change on login)

### Step 5: Hypothesis Generation
Based on evidence, generate ranked hypotheses:
- What vulnerabilities are likely present?
- What is the recommended next safe step to confirm/deny each hypothesis?
- What is the OPSEC risk of each next step?

### Step 6: Finding Production
For confirmed findings, produce:
- **Vulnerability summary** with root cause analysis
- **Evidence references** (request/response pairs, screenshots, timing data)
- **MITRE ATT&CK mapping** (tactic + technique ID)
- **CARVER+Shock risk score** with auth-specific adjustments
- **Compliance control alignment** (which NIST 800-53 / federal controls are impacted)
- **Remediation recommendations** prioritized by effectiveness

### Human-in-the-Loop Gates
The following actions REQUIRE explicit operator approval:
- Any credential testing (even with authorization)
- Any active scanning beyond passive observation
- Any rate increase above strict mode threshold (0.1 RPS)
- Any action that may affect target availability
`;
    AUTH_TOOLING_STACK = [
      {
        name: "OWASP ZAP",
        category: "web_proxy_scanner",
        license: "Apache-2.0",
        useCases: ["Context-based auth scanning", "Passive analysis", "Automation framework", "Session/cookie checks"],
        integration: ["zap-baseline.py", "zap-full-scan.py", "ZAP Automation Framework plans"]
      },
      {
        name: "Burp Suite Community",
        category: "manual_proxy",
        license: "Free (not open-source)",
        useCases: ["Manual flow analysis", "Replay", "Macro-like capture via exports"],
        integration: ["Burp project/export parsing", "HTTP history and site map exports"]
      },
      {
        name: "ScanForge",
        category: "network_enum",
        license: "ScanForge license",
        useCases: ["http-auth discovery", "TLS/cipher inventory", "Service fingerprinting"],
        integration: ["http-auth", "http-methods", "http-enum", "ssl-cert", "ssl-enum-ciphers"]
      },
      {
        name: "ffuf",
        category: "content_discovery",
        license: "MIT",
        useCases: ["Endpoint discovery", "Parameter discovery", "Safe fuzzing (low rate)"],
        integration: ["Custom wordlists", "Response filtering"]
      },
      {
        name: "Hydra",
        category: "credential_testing",
        license: "GPL",
        useCases: ["Authorized credential testing with strict rate/lockout guards"],
        integration: ["Protocol modules", "Custom wordlists"],
        guardrails: ["max_attempts_per_account", "global_rps_limit", "stop_on_lockout_signal"]
      },
      {
        name: "jwt_tool",
        category: "token_analysis",
        license: "Open-source",
        useCases: ["JWT decode", "Claim inspection", "Algorithm checks", "Weak secret testing (authorized)"],
        integration: ["CLI output parsing", "JSON report export"]
      },
      {
        name: "testssl.sh",
        category: "tls_analysis",
        license: "GPL",
        useCases: ["TLS config assessment", "Weak cipher detection", "Protocol downgrade checks"],
        integration: ["JSON output parsing", "CSV export"]
      },
      {
        name: "mitmproxy",
        category: "intercept_and_script",
        license: "MIT",
        useCases: ["Flow capture", "Controlled response/request manipulation", "State transition testing"],
        integration: ["Python scripting API", "HAR export"]
      },
      {
        name: "Impacket",
        category: "enterprise_identity",
        license: "Apache-2.0",
        useCases: ["Protocol inspection in authorized environments", "Kerberos/NTLM negotiation observations"],
        integration: ["Python library", "CLI tools"]
      },
      {
        name: "BloodHound CE",
        category: "enterprise_identity",
        license: "Open-source",
        useCases: ["Post-auth path modeling for AD-connected portals"],
        integration: ["Neo4j queries", "JSON ingest"]
      }
    ];
    STRICT_MODE_GUARDRAILS = {
      maxRps: 0.1,
      maxAttemptsPerAccount: 1,
      stopOnLockoutSignal: true,
      requireScopeAllowlist: true,
      requireChangeWindow: true,
      requireEvidenceCapture: true
    };
    STANDARD_MODE_GUARDRAILS = {
      maxRps: 0.5,
      maxAttemptsPerAccount: 3,
      stopOnLockoutSignal: true,
      requireScopeAllowlist: true,
      requireChangeWindow: false,
      requireEvidenceCapture: false
    };
  }
});

export {
  AUTH_TESTING_PHASES,
  AUTH_ATTACK_TAXONOMY,
  AUTH_MITRE_MAPPINGS,
  SSO_ASSESSMENT_CHECKS,
  AUTH_CARVER_OVERLAY,
  calculateAuthCarverScore,
  FEDERAL_AUTH_CONTROLS,
  AUTH_REASONING_SYSTEM_PROMPT,
  buildAuthKnowledgeContext,
  AUTH_TOOLING_STACK,
  STRICT_MODE_GUARDRAILS,
  STANDARD_MODE_GUARDRAILS,
  validateAgainstGuardrails,
  init_auth_testing_knowledge
};
