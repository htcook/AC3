import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/bb-roe-enforcement.ts
function getProgramRoE(programHandle) {
  return PROGRAM_ROE_REGISTRY[programHandle.toLowerCase()];
}
function getAllProgramRoEs() {
  return Object.values(PROGRAM_ROE_REGISTRY);
}
function registerProgramRoE(config) {
  PROGRAM_ROE_REGISTRY[config.programHandle.toLowerCase()] = config;
}
function enforceScanAction(programHandle, action, operatorUsername) {
  const roe = getProgramRoE(programHandle);
  if (!roe) {
    return {
      allowed: false,
      enforcement: "hard",
      reason: `No RoE config found for program "${programHandle}". Cannot proceed without understanding program rules.`
    };
  }
  const targetLower = action.target.toLowerCase();
  for (const excluded of roe.testingRestrictions.excludedTargets) {
    const pattern = excluded.replace(/\*/g, ".*").toLowerCase();
    if (new RegExp(`^${pattern}$`).test(targetLower) || targetLower.includes(excluded.replace(/\*/g, "").toLowerCase())) {
      return {
        allowed: false,
        enforcement: "hard",
        blockedBy: "excluded_target",
        reason: `Target "${action.target}" is explicitly excluded from scope: ${excluded}`
      };
    }
  }
  if (action.endpoint) {
    const endpointLower = action.endpoint.toLowerCase();
    for (const ep of roe.testingRestrictions.excludedEndpoints) {
      let matches = false;
      const patternLower = ep.pattern.toLowerCase();
      switch (ep.matchType) {
        case "exact":
          matches = endpointLower === patternLower;
          break;
        case "prefix":
          matches = endpointLower.startsWith(patternLower);
          break;
        case "contains":
          matches = endpointLower.includes(patternLower);
          break;
        case "regex":
          matches = new RegExp(ep.pattern, "i").test(action.endpoint);
          break;
      }
      if (matches && action.type === "fuzz") {
        return {
          allowed: false,
          enforcement: "hard",
          blockedBy: "excluded_endpoint",
          reason: `Endpoint "${action.endpoint}" must not be fuzzed: ${ep.reason}`
        };
      }
    }
  }
  if (action.isAutomated && !roe.testingRestrictions.automatedScannersAllowed) {
    if (action.type === "fuzz" || action.type === "brute_force") {
      return {
        allowed: false,
        enforcement: "hard",
        blockedBy: "automated_scanner_prohibited",
        reason: `Program "${programHandle}" does not accept automated scanner output. ${roe.testingRestrictions.scannerRestrictions || "Manual testing with detailed PoC required."}`
      };
    }
  }
  for (const prohibited of roe.testingRestrictions.prohibitedActions) {
    let matches = false;
    switch (prohibited.category) {
      case "dos":
      case "availability_impact":
        matches = action.type === "brute_force" && action.context?.highVolume === true;
        break;
      case "fuzzing":
        if (action.type === "fuzz" && prohibited.targets) {
          for (const t of prohibited.targets) {
            const pattern = t.replace(/\*/g, ".*");
            if (new RegExp(pattern, "i").test(action.endpoint || action.target)) {
              matches = true;
              break;
            }
          }
        }
        break;
      case "automated_scanning":
        matches = action.isAutomated && (action.type === "scan" || action.type === "fuzz");
        break;
      case "inventory_manipulation":
        matches = action.context?.involvesReservation === true || action.context?.involvesBooking === true;
        break;
      case "data_access":
        matches = action.context?.accessesOtherUserData === true;
        break;
      case "account_manipulation":
        matches = action.context?.modifiesOtherAccounts === true;
        break;
    }
    if (matches) {
      return {
        allowed: false,
        enforcement: prohibited.enforcement,
        blockedBy: `prohibited_action:${prohibited.category}`,
        reason: prohibited.action
      };
    }
  }
  const modifications = {};
  if (Object.keys(roe.identification.customHeaders).length > 0) {
    modifications.headers = { ...roe.identification.customHeaders };
    if (operatorUsername) {
      for (const [key, val] of Object.entries(modifications.headers)) {
        if (val === "") {
          modifications.headers[key] = operatorUsername;
        }
      }
    }
  }
  if (roe.testingRestrictions.rateLimiting?.maxRequestsPerSecond) {
    modifications.rateLimit = {
      maxRps: roe.testingRestrictions.rateLimiting.maxRequestsPerSecond
    };
  }
  return {
    allowed: true,
    modifications: Object.keys(modifications).length > 0 ? modifications : void 0
  };
}
function filterFindingsForProgram(programHandle, findings) {
  const roe = getProgramRoE(programHandle);
  if (!roe) {
    const eligible2 = findings.map((f) => ({ ...f, eligible: true, warnings: ["No program RoE config \u2014 cannot validate eligibility"] }));
    return {
      eligible: eligible2,
      ineligible: [],
      summary: { total: findings.length, eligible: findings.length, ineligible: 0, noRoEConfig: true }
    };
  }
  const eligible = [];
  const ineligible = [];
  for (const finding of findings) {
    const result = checkFindingEligibility(roe, finding);
    if (result.eligible) {
      eligible.push(result);
    } else {
      ineligible.push(result);
    }
  }
  return {
    eligible,
    ineligible,
    summary: {
      total: findings.length,
      eligible: eligible.length,
      ineligible: ineligible.length,
      noRoEConfig: false
    }
  };
}
function checkFindingEligibility(roe, finding) {
  const titleLower = (finding.title || "").toLowerCase();
  const descLower = (finding.description || "").toLowerCase();
  const combined = `${titleLower} ${descLower}`;
  const warnings = [];
  if (roe.ineligibleFindings.h1CoreIneligible) {
    for (const pattern of H1_CORE_INELIGIBLE_PATTERNS) {
      if (matchesIneligiblePattern(pattern, combined, finding)) {
        return {
          ...finding,
          eligible: false,
          ineligibleReason: pattern.reason
        };
      }
    }
  }
  for (const pattern of roe.ineligibleFindings.programSpecificIneligible) {
    if (matchesIneligiblePattern(pattern, combined, finding)) {
      return {
        ...finding,
        eligible: false,
        ineligibleReason: pattern.reason
      };
    }
  }
  const assetLower = (finding.asset || "").toLowerCase();
  for (const excluded of roe.testingRestrictions.excludedTargets) {
    const pattern = excluded.replace(/\*/g, ".*").toLowerCase();
    if (new RegExp(pattern).test(assetLower)) {
      return {
        ...finding,
        eligible: false,
        ineligibleReason: `Finding on excluded target: ${excluded}`
      };
    }
  }
  if (roe.submissionRequirements.requiresDetailedPoC && !finding.hasDetailedPoC) {
    warnings.push("Program requires detailed working PoC \u2014 ensure manual verification before submission");
  }
  if (!roe.submissionRequirements.acceptsAutomatedScannerOutput && finding.source) {
    const automatedSources = ["nuclei", "zap", "burp_scanner", "nikto", "nessus", "qualys", "acunetix"];
    if (automatedSources.includes(finding.source.toLowerCase())) {
      warnings.push(`Finding from automated scanner (${finding.source}) \u2014 program requires manual PoC, not raw scanner output`);
    }
  }
  return {
    ...finding,
    eligible: true,
    warnings: warnings.length > 0 ? warnings : void 0
  };
}
function matchesIneligiblePattern(pattern, combinedText, finding) {
  switch (pattern.matchType) {
    case "regex":
      return new RegExp(pattern.pattern, "i").test(combinedText);
    case "title_contains":
      return (finding.title || "").toLowerCase().includes(pattern.pattern.toLowerCase());
    case "category_equals":
      return (finding.cwe || "").toLowerCase() === pattern.pattern.toLowerCase();
    case "cwe_equals":
      return (finding.cwe || "") === pattern.pattern;
    case "severity_below": {
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const findingSeverityIdx = severityOrder.indexOf((finding.severity || "").toLowerCase());
      const thresholdIdx = severityOrder.indexOf(pattern.pattern.toLowerCase());
      return findingSeverityIdx > thresholdIdx;
    }
    default:
      return false;
  }
}
function generateOperatorBriefing(programHandle) {
  const roe = getProgramRoE(programHandle);
  if (!roe) return null;
  return {
    programName: programHandle,
    platform: roe.platform,
    policyUrl: roe.policyUrl,
    criticalRules: roe.testingRestrictions.prohibitedActions.filter((a) => a.enforcement === "hard").map((a) => `\u274C ${a.action}`),
    identificationSetup: [
      ...Object.entries(roe.identification.customHeaders).map(
        ([k, v]) => `Add header: ${k}: ${v || "<your-username>"}`
      ),
      ...roe.identification.emailAlias ? [`Use email alias: <username>${roe.identification.emailAlias}`] : [],
      ...roe.identification.includeIpInReport ? ["Include your IP address in all reports"] : []
    ],
    targetFindings: roe.acceptableFindings.eligibleCategories.map(
      (c) => `\u2705 ${c.description}${c.examples ? ` (e.g., ${c.examples.join(", ")})` : ""}`
    ),
    doNotSubmit: [
      ...roe.ineligibleFindings.h1CoreIneligible ? ["All H1 Core Ineligible findings (version disclosure, missing headers, self-XSS, etc.)"] : [],
      ...roe.ineligibleFindings.programSpecificIneligible.map((p) => p.reason),
      ...!roe.submissionRequirements.acceptsAutomatedScannerOutput ? ["Raw automated scanner output without manual PoC"] : []
    ],
    cleanupActions: roe.submissionRequirements.cleanupRequired.map((c) => c.action),
    excludedTargets: roe.testingRestrictions.excludedTargets
  };
}
function buildScanHeaders(programHandle, operatorUsername) {
  const roe = getProgramRoE(programHandle);
  if (!roe) return {};
  const headers = {};
  for (const [key, val] of Object.entries(roe.identification.customHeaders)) {
    headers[key] = val || operatorUsername;
  }
  return headers;
}
var H1_CORE_INELIGIBLE_PATTERNS, PRICELINE_ROE, NEXTCLOUD_ROE, WORDPRESS_ROE, NODEJS_ROE, PROGRAM_ROE_REGISTRY;
var init_bb_roe_enforcement = __esm({
  "server/lib/bb-roe-enforcement.ts"() {
    H1_CORE_INELIGIBLE_PATTERNS = [
      // Category 1: Theoretical vulnerabilities requiring unlikely user interaction
      { pattern: "unsupported.*browser|end.of.life.*browser|EOL.*browser", matchType: "regex", reason: "H1 Ineligible: Only affects unsupported/EOL browsers" },
      { pattern: "broken.link.hijack", matchType: "regex", reason: "H1 Ineligible: Broken link hijacking" },
      { pattern: "tabnab", matchType: "regex", reason: "H1 Ineligible: Tabnabbing" },
      { pattern: "content.spoof|text.injection", matchType: "regex", reason: "H1 Ineligible: Content spoofing / text injection" },
      { pattern: "physical.access", matchType: "regex", reason: "H1 Ineligible: Requires physical access" },
      { pattern: "self.xss|self.dos", matchType: "regex", reason: "H1 Ineligible: Self-exploitation (self-XSS/self-DoS)" },
      // Category 2: Theoretical vulnerabilities without real-world security impact
      { pattern: "clickjack.*no.sensitive|clickjack.*logout|clickjack.*static", matchType: "regex", reason: "H1 Ineligible: Clickjacking on pages with no sensitive actions" },
      { pattern: "csrf.*logout|csrf.*no.sensitive|csrf.*non.sensitive", matchType: "regex", reason: "H1 Ineligible: CSRF on forms with no sensitive actions" },
      { pattern: "permissive.cors.*no.*impact|cors.*misconfigur.*no.*impact", matchType: "regex", reason: "H1 Ineligible: Permissive CORS without demonstrated impact" },
      { pattern: "version.disclos|banner.grab|server.header|stack.trace|verbose.error", matchType: "regex", reason: "H1 Ineligible: Software version disclosure / banner identification" },
      { pattern: "csv.injection|formula.injection", matchType: "regex", reason: "H1 Ineligible: CSV injection" },
      { pattern: "open.redirect(?!.*additional)", matchType: "regex", reason: "H1 Ineligible: Open redirect without additional security impact" },
      // Category 3: Optional security hardening / Missing best practices
      { pattern: "ssl.*config|tls.*config|weak.cipher|ssl.*grade", matchType: "regex", reason: "H1 Ineligible: SSL/TLS configuration opinions" },
      { pattern: "ssl.pin|certificate.pin|hpkp", matchType: "regex", reason: "H1 Ineligible: Lack of SSL Pinning" },
      { pattern: "jailbreak.detect|root.detect", matchType: "regex", reason: "H1 Ineligible: Lack of jailbreak detection" },
      { pattern: "missing.*httponly|missing.*secure.*flag|cookie.*flag", matchType: "regex", reason: "H1 Ineligible: Cookie handling (missing flags)" },
      { pattern: "content.security.policy|csp.*missing|csp.*bypass(?!.*xss)", matchType: "regex", reason: "H1 Ineligible: CSP configuration opinions" },
      { pattern: "spf.*missing|dkim.*missing|dmarc.*missing|email.*security.*missing", matchType: "regex", reason: "H1 Ineligible: Optional email security features" },
      { pattern: "rate.limit.*missing|no.rate.limit|rate.limit.*bypass(?!.*brute)", matchType: "regex", reason: "H1 Ineligible: Rate limiting issues (most)" },
      // Category 4: Vulnerabilities requiring hazardous testing
      { pattern: "denial.of.service|ddos|dos.attack", matchType: "regex", reason: "H1 Ineligible: DoS/DDoS (hazardous testing)" },
      { pattern: "social.engineer|phishing.*employee", matchType: "regex", reason: "H1 Ineligible: Social engineering attacks" }
    ];
    PRICELINE_ROE = {
      programHandle: "priceline",
      platform: "hackerone",
      policyUrl: "https://hackerone.com/priceline?type=team",
      lastParsedAt: Date.now(),
      identification: {
        customHeaders: {
          "X-Bug-Bounty": ""
          // Will be filled with operator's H1 username at runtime
        },
        emailAlias: "@wearehackerone.com",
        // Use HackerOne email alias for account creation
        includeIpInReport: true,
        platformUsername: ""
        // Set per-operator
      },
      testingRestrictions: {
        prohibitedActions: [
          { action: "Access private customer information", category: "data_access", enforcement: "hard" },
          { action: "View, modify, or damage information belonging to other customers", category: "data_access", enforcement: "hard" },
          { action: "Affect service availability (DoS, spam)", category: "dos", enforcement: "hard" },
          { action: "Affect product availability (hotel/flight/rental car reservations blocking inventory)", category: "inventory_manipulation", enforcement: "hard" },
          { action: "Make multiple reservations without canceling", category: "inventory_manipulation", enforcement: "hard" },
          { action: "Send automated scanner report exports (require detailed working PoC)", category: "automated_scanning", enforcement: "hard" },
          { action: "Fuzz Contact forms", category: "fuzzing", targets: ["*/contact*", "*/support*"], enforcement: "hard" },
          { action: 'Fuzz "Request Account Activation" & "Request Product Activation" requests', category: "fuzzing", targets: ["*/account-activation*", "*/product-activation*"], enforcement: "hard" },
          { action: 'Fuzz "Change Request under Sites" requests', category: "fuzzing", targets: ["*/change-request*", "*/sites*"], enforcement: "hard" },
          { action: "Modify other hacker_* user accounts under HackerOne test account", category: "account_manipulation", enforcement: "hard" }
        ],
        excludedTargets: [
          "*.roomvaluesteam.com",
          "*.testaroom.com",
          "*.testaroom.cloud",
          "airportrentalcars.com"
        ],
        excludedEndpoints: [
          { pattern: "/contact", reason: "Contact forms must not be fuzzed", matchType: "contains" },
          { pattern: "/support", reason: "Support forms must not be fuzzed", matchType: "contains" },
          { pattern: "account-activation", reason: "Account activation requests must not be fuzzed", matchType: "contains" },
          { pattern: "product-activation", reason: "Product activation requests must not be fuzzed", matchType: "contains" },
          { pattern: "change-request", reason: "Change requests under Sites must not be fuzzed", matchType: "contains" }
        ],
        rateLimiting: {
          maxRequestsPerSecond: 10,
          maxConcurrentScans: 2
        },
        automatedScannersAllowed: false,
        // "Do not send reports exported from automated scanners"
        scannerRestrictions: "Automated scanners may be used for discovery only. All reported findings MUST have a detailed working PoC \u2014 no raw scanner output.",
        dataHandling: [
          { dataType: "customer_pii", rule: "Do not access. If accessed accidentally to support a finding, do not misuse \u2014 report immediately.", enforcement: "hard" },
          { dataType: "reservations", rule: "If you submit a reservation, you MUST cancel it. Do not block inventory.", enforcement: "hard" }
        ]
      },
      acceptableFindings: {
        eligibleCategories: [
          { category: "xss", description: "Cross-Site Scripting", examples: ["Stored XSS in search", "Reflected XSS in booking flow"] },
          { category: "sqli", description: "SQL Injection" },
          { category: "ssrf", description: "Server-Side Request Forgery" },
          { category: "idor", description: "Insecure Direct Object References" },
          { category: "broken_access_control", description: "Broken Access Control" },
          { category: "rce", description: "Remote Code Execution" },
          { category: "auth_bypass", description: "Authentication Bypass" },
          { category: "business_logic", description: "Business Logic Flaws", examples: ["Pricing manipulation", "Booking flow bypass"] },
          { category: "information_disclosure", description: "Sensitive Information Disclosure (with real impact)" },
          { category: "subdomain_takeover", description: "Subdomain Takeover" }
        ],
        subTargetRules: [
          {
            targetName: "Penny",
            assets: ["penny", "priceline.com/penny", "ai.priceline.com"],
            acceptableCategories: [
              { category: "business_logic", description: "Business logic bypass flaws", examples: ["View/modify bookings of other customers", "Authentication bypass", "Pricing manipulation", "Bypassing critical service restrictions"] },
              { category: "pii_access", description: "Access to Personally Identifiable Information (PII) of other customers" },
              { category: "prompt_injection", description: "Prompt Injection specifically leading to disclosure of sensitive internal information (proprietary data, backend raw responses, system prompts, internal API keys)" }
            ]
          }
        ]
      },
      ineligibleFindings: {
        h1CoreIneligible: true,
        programSpecificIneligible: [
          { pattern: "open.redirect", matchType: "regex", reason: "Priceline: Open redirects without demonstrated additional security impact" },
          { pattern: "clickjack", matchType: "regex", reason: "Priceline: Clickjacking on non-sensitive pages" },
          { pattern: "missing.*header|security.*header", matchType: "regex", reason: "Priceline: Missing security headers without demonstrated impact" },
          { pattern: "version.disclosure|server.banner", matchType: "regex", reason: "Priceline: Version/banner disclosure" }
        ]
      },
      submissionRequirements: {
        acceptsAutomatedScannerOutput: false,
        requiresDetailedPoC: true,
        cleanupRequired: [
          { action: "Cancel any test reservations (hotel, flight, rental car)", timing: "immediate" },
          { action: "Do not retain any accessed customer data", timing: "immediate" }
        ],
        reportFormat: "Detailed working PoC with steps to reproduce. No automated scanner exports."
      }
    };
    NEXTCLOUD_ROE = {
      programHandle: "nextcloud",
      platform: "hackerone",
      policyUrl: "https://hackerone.com/nextcloud",
      lastParsedAt: Date.now(),
      identification: {
        customHeaders: {},
        includeIpInReport: false
      },
      testingRestrictions: {
        prohibitedActions: [
          { action: "DoS attacks against Nextcloud infrastructure", category: "dos", enforcement: "hard" },
          { action: "Automated scanning against Nextcloud-operated servers", category: "automated_scanning", enforcement: "hard" },
          { action: "User data extraction from Nextcloud infrastructure", category: "data_exfiltration", enforcement: "hard" },
          { action: "Leaking report contents to SaaS, AI, search engines, or translation tools", category: "data_exfiltration", enforcement: "hard" },
          { action: "Testing third-party AppStore apps (only Nextcloud GmbH-supported apps)", category: "target_exclusion", enforcement: "hard" },
          { action: "Using cloud-based AI/LLM services (only locally-running LLMs allowed)", category: "ai_service_usage", enforcement: "hard" }
        ],
        excludedTargets: [],
        excludedEndpoints: [],
        automatedScannersAllowed: false,
        scannerRestrictions: "No automated scanning against Nextcloud-operated servers. Local testing against self-hosted instances is permitted.",
        dataHandling: [
          { dataType: "report_contents", rule: "Do NOT leak to SaaS, AI services, search engines, or translation tools", enforcement: "hard" },
          { dataType: "user_data", rule: "Do NOT extract user data from Nextcloud infrastructure", enforcement: "hard" }
        ]
      },
      acceptableFindings: {
        eligibleCategories: [
          { category: "access_control_bypass", description: "Access control bypass in sharing (IDOR, permission escalation)" },
          { category: "ssrf", description: "SSRF via external storage, mail, avatar URLs, link previews" },
          { category: "stored_xss", description: "Stored XSS with CSP bypass in file names, comments, chat, calendar" },
          { category: "path_traversal", description: "Path traversal in file operations, WebDAV, or API" },
          { category: "sqli", description: "SQL Injection in custom queries or database interactions" },
          { category: "rce", description: "Remote Code Execution" },
          { category: "auth_bypass", description: "Authentication bypass or session management flaws" },
          { category: "encryption_flaw", description: "End-to-end encryption weaknesses" }
        ],
        subTargetRules: []
      },
      ineligibleFindings: {
        h1CoreIneligible: true,
        programSpecificIneligible: [
          { pattern: "third.party.*app", matchType: "regex", reason: "Nextcloud: Third-party AppStore apps are out of scope" }
        ]
      },
      submissionRequirements: {
        acceptsAutomatedScannerOutput: false,
        requiresDetailedPoC: true,
        cleanupRequired: [],
        reportFormat: "Detailed PoC. Do NOT use cloud AI/LLM services to draft reports."
      }
    };
    WORDPRESS_ROE = {
      programHandle: "wordpress",
      platform: "hackerone",
      policyUrl: "https://hackerone.com/wordpress?type=team",
      lastParsedAt: Date.now(),
      identification: {
        customHeaders: {},
        includeIpInReport: false
      },
      testingRestrictions: {
        prohibitedActions: [
          { action: "Denial of Service (DoS) attacks", category: "dos", enforcement: "hard" },
          { action: "Physical attacks against WordPress infrastructure", category: "physical", enforcement: "hard" },
          { action: "Social engineering against WordPress employees or users", category: "social_engineering", enforcement: "hard" },
          { action: "Automated scanning that causes significant traffic or disruption", category: "automated_scanning", enforcement: "hard" },
          { action: "Testing on production WordPress.com sites without explicit permission", category: "target_exclusion", enforcement: "hard" },
          { action: "Any actions that could lead to data loss or corruption", category: "data_exfiltration", enforcement: "hard" }
        ],
        excludedTargets: [
          "*.wordpress.com"
          // Production WordPress.com — NOT in scope unless explicitly permitted
        ],
        excludedEndpoints: [],
        automatedScannersAllowed: true,
        // Allowed if not causing significant traffic
        scannerRestrictions: "Automated scanning permitted but must not cause significant traffic or disruption.",
        dataHandling: [
          { dataType: "user_data", rule: "No actions that could lead to data loss or corruption", enforcement: "hard" }
        ]
      },
      acceptableFindings: {
        eligibleCategories: [
          { category: "xss", description: "Cross-Site Scripting in themes, plugins, or core" },
          { category: "sqli", description: "SQL Injection in custom queries or database interactions" },
          { category: "rce", description: "Remote Code Execution via file uploads, theme/plugin editors, or deserialization" },
          { category: "auth_bypass", description: "Authentication bypass or privilege escalation" },
          { category: "ssrf", description: "Server-Side Request Forgery" },
          { category: "path_traversal", description: "Path traversal or local file inclusion" },
          { category: "csrf", description: "CSRF on sensitive state-changing actions" }
        ],
        subTargetRules: []
      },
      ineligibleFindings: {
        h1CoreIneligible: true,
        programSpecificIneligible: [
          { pattern: "wordpress\\.com", matchType: "regex", reason: "WordPress: Findings on WordPress.com production are out of scope unless explicitly permitted" }
        ]
      },
      submissionRequirements: {
        acceptsAutomatedScannerOutput: false,
        requiresDetailedPoC: true,
        cleanupRequired: []
      }
    };
    NODEJS_ROE = {
      programHandle: "nodejs",
      platform: "hackerone",
      policyUrl: "https://hackerone.com/nodejs",
      lastParsedAt: Date.now(),
      identification: {
        customHeaders: {},
        includeIpInReport: false
      },
      testingRestrictions: {
        prohibitedActions: [
          { action: "Denial of Service (DoS) attacks", category: "dos", enforcement: "hard" },
          { action: "Social engineering against Node.js maintainers", category: "social_engineering", enforcement: "hard" }
        ],
        excludedTargets: [],
        excludedEndpoints: [],
        automatedScannersAllowed: true,
        dataHandling: []
      },
      acceptableFindings: {
        eligibleCategories: [
          { category: "rce", description: "Remote Code Execution in Node.js runtime" },
          { category: "memory_corruption", description: "Buffer overflow, use-after-free, heap corruption" },
          { category: "crypto_flaw", description: "Cryptographic implementation flaws" },
          { category: "dns_rebinding", description: "DNS rebinding attacks" },
          { category: "http_smuggling", description: "HTTP request smuggling" },
          { category: "path_traversal", description: "Path traversal in core modules" },
          { category: "prototype_pollution", description: "Prototype pollution with security impact" }
        ],
        subTargetRules: []
      },
      ineligibleFindings: {
        h1CoreIneligible: true,
        programSpecificIneligible: []
      },
      submissionRequirements: {
        acceptsAutomatedScannerOutput: false,
        requiresDetailedPoC: true,
        cleanupRequired: []
      }
    };
    PROGRAM_ROE_REGISTRY = {
      priceline: PRICELINE_ROE,
      nextcloud: NEXTCLOUD_ROE,
      wordpress: WORDPRESS_ROE,
      nodejs: NODEJS_ROE
    };
  }
});
init_bb_roe_enforcement();
export {
  H1_CORE_INELIGIBLE_PATTERNS,
  NEXTCLOUD_ROE,
  NODEJS_ROE,
  PRICELINE_ROE,
  WORDPRESS_ROE,
  buildScanHeaders,
  enforceScanAction,
  filterFindingsForProgram,
  generateOperatorBriefing,
  getAllProgramRoEs,
  getProgramRoE,
  registerProgramRoE
};
