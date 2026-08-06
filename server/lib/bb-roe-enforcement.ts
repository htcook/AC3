/**
 * Bug Bounty RoE Enforcement Module
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Per-program Rules of Engagement enforcement for bug bounty engagements.
 * Every BB engagement targeting LIVE production assets MUST have its program's
 * specific rules parsed, stored, and enforced at both scan-time and report-time.
 * 
 * Enforcement layers:
 *   1. SCAN-TIME: Block prohibited actions before they execute
 *   2. HEADER INJECTION: Add required identification headers to all requests
 *   3. TARGET FILTERING: Exclude out-of-scope assets and prohibited test targets
 *   4. REPORT-TIME: Filter ineligible findings from submission output
 *   5. SUBMISSION GUARD: Ensure PoC quality and format requirements are met
 * 
 * Each program gets its OWN tailored config — Priceline rules are for Priceline,
 * Nextcloud rules are for Nextcloud, etc. No shared/generic rules applied across programs.
 */

// ─── Types ─────────────────────────────────────────────────────────────────

export interface BugBountyProgramRoE {
  /** Program identifier (e.g., "priceline", "nextcloud") */
  programHandle: string;
  /** Platform (hackerone, bugcrowd, etc.) */
  platform: string;
  /** Program policy URL */
  policyUrl: string;
  /** Last time the RoE was parsed/updated from the program page */
  lastParsedAt: number;

  // ─── Identification Requirements ───
  identification: {
    /** Custom HTTP header to include in all requests (e.g., "X-Bug-Bounty: username") */
    customHeaders: Record<string, string>;
    /** Email alias to use for account creation (e.g., "user@wearehackerone.com") */
    emailAlias?: string;
    /** Whether to include IP address in reports */
    includeIpInReport: boolean;
    /** Username/handle on the platform */
    platformUsername?: string;
  };

  // ─── Testing Restrictions ───
  testingRestrictions: {
    /** Actions that are explicitly PROHIBITED */
    prohibitedActions: ProhibitedAction[];
    /** Domains/patterns that must NOT be tested */
    excludedTargets: string[];
    /** Specific endpoints/forms that must NOT be fuzzed */
    excludedEndpoints: ExcludedEndpoint[];
    /** Rate limiting requirements */
    rateLimiting?: {
      maxRequestsPerSecond?: number;
      maxConcurrentScans?: number;
      cooldownBetweenScansMs?: number;
    };
    /** Whether automated scanners are allowed */
    automatedScannersAllowed: boolean;
    /** Scanner-specific restrictions */
    scannerRestrictions?: string;
    /** Special data handling rules */
    dataHandling: DataHandlingRule[];
  };

  // ─── Acceptable Findings ───
  acceptableFindings: {
    /** Finding categories that ARE eligible for this program */
    eligibleCategories: AcceptableFindingCategory[];
    /** Program-specific sub-targets with their own acceptable findings (e.g., Penny for Priceline) */
    subTargetRules: SubTargetRule[];
  };

  // ─── Ineligible Findings ───
  ineligibleFindings: {
    /** H1 Core Ineligible Findings (universal for HackerOne programs) */
    h1CoreIneligible: boolean;
    /** Program-specific ineligible findings beyond H1 core */
    programSpecificIneligible: IneligibleFinding[];
  };

  // ─── Submission Requirements ───
  submissionRequirements: {
    /** Whether automated scanner output alone is accepted (usually NO) */
    acceptsAutomatedScannerOutput: boolean;
    /** Minimum PoC requirements */
    requiresDetailedPoC: boolean;
    /** Whether to cancel test accounts/reservations after testing */
    cleanupRequired: CleanupRequirement[];
    /** Report format requirements */
    reportFormat?: string;
  };
}

export interface ProhibitedAction {
  /** What is prohibited */
  action: string;
  /** Category for matching against scan actions */
  category: ProhibitedActionCategory;
  /** Specific targets this prohibition applies to (empty = all targets) */
  targets?: string[];
  /** Severity of violation (hard = block scan, soft = warn operator) */
  enforcement: 'hard' | 'soft';
}

export type ProhibitedActionCategory =
  | 'dos'                    // Denial of Service
  | 'availability_impact'   // Anything affecting service availability
  | 'inventory_manipulation' // Booking/reservation manipulation
  | 'data_access'           // Accessing other users' data
  | 'social_engineering'    // Phishing, pretexting
  | 'physical'              // Physical access attacks
  | 'automated_scanning'    // Automated scanner usage
  | 'fuzzing'               // Fuzzing specific endpoints
  | 'account_manipulation'  // Modifying other accounts
  | 'target_exclusion'      // Testing excluded targets
  | 'data_exfiltration'     // Extracting/leaking data
  | 'ai_service_usage'      // Using cloud AI/LLM services
  | 'noise'                 // Spamming notifications/forms
  | 'other';

export interface ExcludedEndpoint {
  /** URL pattern or description */
  pattern: string;
  /** Why it's excluded */
  reason: string;
  /** Match type */
  matchType: 'exact' | 'prefix' | 'contains' | 'regex';
}

export interface DataHandlingRule {
  /** What data type */
  dataType: string;
  /** Rule description */
  rule: string;
  /** Enforcement level */
  enforcement: 'hard' | 'soft';
}

export interface AcceptableFindingCategory {
  /** CWE or category name */
  category: string;
  /** Description of what's acceptable */
  description: string;
  /** Examples */
  examples?: string[];
}

export interface SubTargetRule {
  /** Sub-target name (e.g., "Penny" for Priceline's AI assistant) */
  targetName: string;
  /** Assets that belong to this sub-target */
  assets: string[];
  /** Acceptable finding categories for this sub-target */
  acceptableCategories: AcceptableFindingCategory[];
}

export interface IneligibleFinding {
  /** Pattern to match against finding titles/descriptions */
  pattern: string;
  /** Match type */
  matchType: 'title_contains' | 'category_equals' | 'cwe_equals' | 'severity_below' | 'regex';
  /** Why it's ineligible */
  reason: string;
}

export interface CleanupRequirement {
  /** What needs to be cleaned up */
  action: string;
  /** When (after each test, after engagement, etc.) */
  timing: 'immediate' | 'after_test' | 'after_engagement';
}

// ─── H1 Core Ineligible Findings ─────────────────────────────────────────

/**
 * HackerOne Core Ineligible Findings (as of May 2025)
 * These apply to ALL HackerOne programs unless explicitly overridden.
 * Source: https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings
 */
export const H1_CORE_INELIGIBLE_PATTERNS: IneligibleFinding[] = [
  // Category 1: Theoretical vulnerabilities requiring unlikely user interaction
  { pattern: 'unsupported.*browser|end.of.life.*browser|EOL.*browser', matchType: 'regex', reason: 'H1 Ineligible: Only affects unsupported/EOL browsers' },
  { pattern: 'broken.link.hijack', matchType: 'regex', reason: 'H1 Ineligible: Broken link hijacking' },
  { pattern: 'tabnab', matchType: 'regex', reason: 'H1 Ineligible: Tabnabbing' },
  { pattern: 'content.spoof|text.injection', matchType: 'regex', reason: 'H1 Ineligible: Content spoofing / text injection' },
  { pattern: 'physical.access', matchType: 'regex', reason: 'H1 Ineligible: Requires physical access' },
  { pattern: 'self.xss|self.dos', matchType: 'regex', reason: 'H1 Ineligible: Self-exploitation (self-XSS/self-DoS)' },

  // Category 2: Theoretical vulnerabilities without real-world security impact
  { pattern: 'clickjack.*no.sensitive|clickjack.*logout|clickjack.*static', matchType: 'regex', reason: 'H1 Ineligible: Clickjacking on pages with no sensitive actions' },
  { pattern: 'csrf.*logout|csrf.*no.sensitive|csrf.*non.sensitive', matchType: 'regex', reason: 'H1 Ineligible: CSRF on forms with no sensitive actions' },
  { pattern: 'permissive.cors.*no.*impact|cors.*misconfigur.*no.*impact', matchType: 'regex', reason: 'H1 Ineligible: Permissive CORS without demonstrated impact' },
  { pattern: 'version.disclos|banner.grab|server.header|stack.trace|verbose.error', matchType: 'regex', reason: 'H1 Ineligible: Software version disclosure / banner identification' },
  { pattern: 'csv.injection|formula.injection', matchType: 'regex', reason: 'H1 Ineligible: CSV injection' },
  { pattern: 'open.redirect(?!.*additional)', matchType: 'regex', reason: 'H1 Ineligible: Open redirect without additional security impact' },

  // Category 3: Optional security hardening / Missing best practices
  { pattern: 'ssl.*config|tls.*config|weak.cipher|ssl.*grade', matchType: 'regex', reason: 'H1 Ineligible: SSL/TLS configuration opinions' },
  { pattern: 'ssl.pin|certificate.pin|hpkp', matchType: 'regex', reason: 'H1 Ineligible: Lack of SSL Pinning' },
  { pattern: 'jailbreak.detect|root.detect', matchType: 'regex', reason: 'H1 Ineligible: Lack of jailbreak detection' },
  { pattern: 'missing.*httponly|missing.*secure.*flag|cookie.*flag', matchType: 'regex', reason: 'H1 Ineligible: Cookie handling (missing flags)' },
  { pattern: 'content.security.policy|csp.*missing|csp.*bypass(?!.*xss)', matchType: 'regex', reason: 'H1 Ineligible: CSP configuration opinions' },
  { pattern: 'spf.*missing|dkim.*missing|dmarc.*missing|email.*security.*missing', matchType: 'regex', reason: 'H1 Ineligible: Optional email security features' },
  { pattern: 'rate.limit.*missing|no.rate.limit|rate.limit.*bypass(?!.*brute)', matchType: 'regex', reason: 'H1 Ineligible: Rate limiting issues (most)' },

  // Category 4: Vulnerabilities requiring hazardous testing
  { pattern: 'denial.of.service|ddos|dos.attack', matchType: 'regex', reason: 'H1 Ineligible: DoS/DDoS (hazardous testing)' },
  { pattern: 'social.engineer|phishing.*employee', matchType: 'regex', reason: 'H1 Ineligible: Social engineering attacks' },
];

// ─── Program-Specific RoE Configs ─────────────────────────────────────────

/**
 * Priceline Bug Bounty Program RoE
 * Source: https://hackerone.com/priceline (Testing Rules + Guidelines for Penny)
 */
export const PRICELINE_ROE: BugBountyProgramRoE = {
  programHandle: 'priceline',
  platform: 'hackerone',
  policyUrl: 'https://hackerone.com/priceline?type=team',
  lastParsedAt: Date.now(),

  identification: {
    customHeaders: {
      'X-Bug-Bounty': '', // Will be filled with operator's H1 username at runtime
    },
    emailAlias: '@wearehackerone.com', // Use HackerOne email alias for account creation
    includeIpInReport: true,
    platformUsername: '', // Set per-operator
  },

  testingRestrictions: {
    prohibitedActions: [
      { action: 'Access private customer information', category: 'data_access', enforcement: 'hard' },
      { action: 'View, modify, or damage information belonging to other customers', category: 'data_access', enforcement: 'hard' },
      { action: 'Affect service availability (DoS, spam)', category: 'dos', enforcement: 'hard' },
      { action: 'Affect product availability (hotel/flight/rental car reservations blocking inventory)', category: 'inventory_manipulation', enforcement: 'hard' },
      { action: 'Make multiple reservations without canceling', category: 'inventory_manipulation', enforcement: 'hard' },
      { action: 'Send automated scanner report exports (require detailed working PoC)', category: 'automated_scanning', enforcement: 'hard' },
      { action: 'Fuzz Contact forms', category: 'fuzzing', targets: ['*/contact*', '*/support*'], enforcement: 'hard' },
      { action: 'Fuzz "Request Account Activation" & "Request Product Activation" requests', category: 'fuzzing', targets: ['*/account-activation*', '*/product-activation*'], enforcement: 'hard' },
      { action: 'Fuzz "Change Request under Sites" requests', category: 'fuzzing', targets: ['*/change-request*', '*/sites*'], enforcement: 'hard' },
      { action: 'Modify other hacker_* user accounts under HackerOne test account', category: 'account_manipulation', enforcement: 'hard' },
    ],
    excludedTargets: [
      '*.roomvaluesteam.com',
      '*.testaroom.com',
      '*.testaroom.cloud',
      'airportrentalcars.com',
    ],
    excludedEndpoints: [
      { pattern: '/contact', reason: 'Contact forms must not be fuzzed', matchType: 'contains' },
      { pattern: '/support', reason: 'Support forms must not be fuzzed', matchType: 'contains' },
      { pattern: 'account-activation', reason: 'Account activation requests must not be fuzzed', matchType: 'contains' },
      { pattern: 'product-activation', reason: 'Product activation requests must not be fuzzed', matchType: 'contains' },
      { pattern: 'change-request', reason: 'Change requests under Sites must not be fuzzed', matchType: 'contains' },
    ],
    rateLimiting: {
      maxRequestsPerSecond: 10,
      maxConcurrentScans: 2,
    },
    automatedScannersAllowed: false, // "Do not send reports exported from automated scanners"
    scannerRestrictions: 'Automated scanners may be used for discovery only. All reported findings MUST have a detailed working PoC — no raw scanner output.',
    dataHandling: [
      { dataType: 'customer_pii', rule: 'Do not access. If accessed accidentally to support a finding, do not misuse — report immediately.', enforcement: 'hard' },
      { dataType: 'reservations', rule: 'If you submit a reservation, you MUST cancel it. Do not block inventory.', enforcement: 'hard' },
    ],
  },

  acceptableFindings: {
    eligibleCategories: [
      { category: 'xss', description: 'Cross-Site Scripting', examples: ['Stored XSS in search', 'Reflected XSS in booking flow'] },
      { category: 'sqli', description: 'SQL Injection' },
      { category: 'ssrf', description: 'Server-Side Request Forgery' },
      { category: 'idor', description: 'Insecure Direct Object References' },
      { category: 'broken_access_control', description: 'Broken Access Control' },
      { category: 'rce', description: 'Remote Code Execution' },
      { category: 'auth_bypass', description: 'Authentication Bypass' },
      { category: 'business_logic', description: 'Business Logic Flaws', examples: ['Pricing manipulation', 'Booking flow bypass'] },
      { category: 'information_disclosure', description: 'Sensitive Information Disclosure (with real impact)' },
      { category: 'subdomain_takeover', description: 'Subdomain Takeover' },
    ],
    subTargetRules: [
      {
        targetName: 'Penny',
        assets: ['penny', 'priceline.com/penny', 'ai.priceline.com'],
        acceptableCategories: [
          { category: 'business_logic', description: 'Business logic bypass flaws', examples: ['View/modify bookings of other customers', 'Authentication bypass', 'Pricing manipulation', 'Bypassing critical service restrictions'] },
          { category: 'pii_access', description: 'Access to Personally Identifiable Information (PII) of other customers' },
          { category: 'prompt_injection', description: 'Prompt Injection specifically leading to disclosure of sensitive internal information (proprietary data, backend raw responses, system prompts, internal API keys)' },
        ],
      },
    ],
  },

  ineligibleFindings: {
    h1CoreIneligible: true,
    programSpecificIneligible: [
      { pattern: 'open.redirect', matchType: 'regex', reason: 'Priceline: Open redirects without demonstrated additional security impact' },
      { pattern: 'clickjack', matchType: 'regex', reason: 'Priceline: Clickjacking on non-sensitive pages' },
      { pattern: 'missing.*header|security.*header', matchType: 'regex', reason: 'Priceline: Missing security headers without demonstrated impact' },
      { pattern: 'version.disclosure|server.banner', matchType: 'regex', reason: 'Priceline: Version/banner disclosure' },
    ],
  },

  submissionRequirements: {
    acceptsAutomatedScannerOutput: false,
    requiresDetailedPoC: true,
    cleanupRequired: [
      { action: 'Cancel any test reservations (hotel, flight, rental car)', timing: 'immediate' },
      { action: 'Do not retain any accessed customer data', timing: 'immediate' },
    ],
    reportFormat: 'Detailed working PoC with steps to reproduce. No automated scanner exports.',
  },
};

/**
 * Nextcloud Bug Bounty Program RoE
 * Source: https://hackerone.com/nextcloud
 */
export const NEXTCLOUD_ROE: BugBountyProgramRoE = {
  programHandle: 'nextcloud',
  platform: 'hackerone',
  policyUrl: 'https://hackerone.com/nextcloud',
  lastParsedAt: Date.now(),

  identification: {
    customHeaders: {},
    includeIpInReport: false,
  },

  testingRestrictions: {
    prohibitedActions: [
      { action: 'DoS attacks against Nextcloud infrastructure', category: 'dos', enforcement: 'hard' },
      { action: 'Automated scanning against Nextcloud-operated servers', category: 'automated_scanning', enforcement: 'hard' },
      { action: 'User data extraction from Nextcloud infrastructure', category: 'data_exfiltration', enforcement: 'hard' },
      { action: 'Leaking report contents to SaaS, AI, search engines, or translation tools', category: 'data_exfiltration', enforcement: 'hard' },
      { action: 'Testing third-party AppStore apps (only Nextcloud GmbH-supported apps)', category: 'target_exclusion', enforcement: 'hard' },
      { action: 'Using cloud-based AI/LLM services (only locally-running LLMs allowed)', category: 'ai_service_usage', enforcement: 'hard' },
    ],
    excludedTargets: [],
    excludedEndpoints: [],
    automatedScannersAllowed: false,
    scannerRestrictions: 'No automated scanning against Nextcloud-operated servers. Local testing against self-hosted instances is permitted.',
    dataHandling: [
      { dataType: 'report_contents', rule: 'Do NOT leak to SaaS, AI services, search engines, or translation tools', enforcement: 'hard' },
      { dataType: 'user_data', rule: 'Do NOT extract user data from Nextcloud infrastructure', enforcement: 'hard' },
    ],
  },

  acceptableFindings: {
    eligibleCategories: [
      { category: 'access_control_bypass', description: 'Access control bypass in sharing (IDOR, permission escalation)' },
      { category: 'ssrf', description: 'SSRF via external storage, mail, avatar URLs, link previews' },
      { category: 'stored_xss', description: 'Stored XSS with CSP bypass in file names, comments, chat, calendar' },
      { category: 'path_traversal', description: 'Path traversal in file operations, WebDAV, or API' },
      { category: 'sqli', description: 'SQL Injection in custom queries or database interactions' },
      { category: 'rce', description: 'Remote Code Execution' },
      { category: 'auth_bypass', description: 'Authentication bypass or session management flaws' },
      { category: 'encryption_flaw', description: 'End-to-end encryption weaknesses' },
    ],
    subTargetRules: [],
  },

  ineligibleFindings: {
    h1CoreIneligible: true,
    programSpecificIneligible: [
      { pattern: 'third.party.*app', matchType: 'regex', reason: 'Nextcloud: Third-party AppStore apps are out of scope' },
    ],
  },

  submissionRequirements: {
    acceptsAutomatedScannerOutput: false,
    requiresDetailedPoC: true,
    cleanupRequired: [],
    reportFormat: 'Detailed PoC. Do NOT use cloud AI/LLM services to draft reports.',
  },
};

/**
 * WordPress Bug Bounty Program RoE
 * Source: https://hackerone.com/wordpress
 */
export const WORDPRESS_ROE: BugBountyProgramRoE = {
  programHandle: 'wordpress',
  platform: 'hackerone',
  policyUrl: 'https://hackerone.com/wordpress?type=team',
  lastParsedAt: Date.now(),

  identification: {
    customHeaders: {},
    includeIpInReport: false,
  },

  testingRestrictions: {
    prohibitedActions: [
      { action: 'Denial of Service (DoS) attacks', category: 'dos', enforcement: 'hard' },
      { action: 'Physical attacks against WordPress infrastructure', category: 'physical', enforcement: 'hard' },
      { action: 'Social engineering against WordPress employees or users', category: 'social_engineering', enforcement: 'hard' },
      { action: 'Automated scanning that causes significant traffic or disruption', category: 'automated_scanning', enforcement: 'hard' },
      { action: 'Testing on production WordPress.com sites without explicit permission', category: 'target_exclusion', enforcement: 'hard' },
      { action: 'Any actions that could lead to data loss or corruption', category: 'data_exfiltration', enforcement: 'hard' },
    ],
    excludedTargets: [
      '*.wordpress.com', // Production WordPress.com — NOT in scope unless explicitly permitted
    ],
    excludedEndpoints: [],
    automatedScannersAllowed: true, // Allowed if not causing significant traffic
    scannerRestrictions: 'Automated scanning permitted but must not cause significant traffic or disruption.',
    dataHandling: [
      { dataType: 'user_data', rule: 'No actions that could lead to data loss or corruption', enforcement: 'hard' },
    ],
  },

  acceptableFindings: {
    eligibleCategories: [
      { category: 'xss', description: 'Cross-Site Scripting in themes, plugins, or core' },
      { category: 'sqli', description: 'SQL Injection in custom queries or database interactions' },
      { category: 'rce', description: 'Remote Code Execution via file uploads, theme/plugin editors, or deserialization' },
      { category: 'auth_bypass', description: 'Authentication bypass or privilege escalation' },
      { category: 'ssrf', description: 'Server-Side Request Forgery' },
      { category: 'path_traversal', description: 'Path traversal or local file inclusion' },
      { category: 'csrf', description: 'CSRF on sensitive state-changing actions' },
    ],
    subTargetRules: [],
  },

  ineligibleFindings: {
    h1CoreIneligible: true,
    programSpecificIneligible: [
      { pattern: 'wordpress\\.com', matchType: 'regex', reason: 'WordPress: Findings on WordPress.com production are out of scope unless explicitly permitted' },
    ],
  },

  submissionRequirements: {
    acceptsAutomatedScannerOutput: false,
    requiresDetailedPoC: true,
    cleanupRequired: [],
  },
};

/**
 * Node.js Bug Bounty Program RoE
 * Source: https://hackerone.com/nodejs (minimal public policy)
 */
export const NODEJS_ROE: BugBountyProgramRoE = {
  programHandle: 'nodejs',
  platform: 'hackerone',
  policyUrl: 'https://hackerone.com/nodejs',
  lastParsedAt: Date.now(),

  identification: {
    customHeaders: {},
    includeIpInReport: false,
  },

  testingRestrictions: {
    prohibitedActions: [
      { action: 'Denial of Service (DoS) attacks', category: 'dos', enforcement: 'hard' },
      { action: 'Social engineering against Node.js maintainers', category: 'social_engineering', enforcement: 'hard' },
    ],
    excludedTargets: [],
    excludedEndpoints: [],
    automatedScannersAllowed: true,
    dataHandling: [],
  },

  acceptableFindings: {
    eligibleCategories: [
      { category: 'rce', description: 'Remote Code Execution in Node.js runtime' },
      { category: 'memory_corruption', description: 'Buffer overflow, use-after-free, heap corruption' },
      { category: 'crypto_flaw', description: 'Cryptographic implementation flaws' },
      { category: 'dns_rebinding', description: 'DNS rebinding attacks' },
      { category: 'http_smuggling', description: 'HTTP request smuggling' },
      { category: 'path_traversal', description: 'Path traversal in core modules' },
      { category: 'prototype_pollution', description: 'Prototype pollution with security impact' },
    ],
    subTargetRules: [],
  },

  ineligibleFindings: {
    h1CoreIneligible: true,
    programSpecificIneligible: [],
  },

  submissionRequirements: {
    acceptsAutomatedScannerOutput: false,
    requiresDetailedPoC: true,
    cleanupRequired: [],
  },
};

// ─── Program Registry ─────────────────────────────────────────────────────

/** Registry of all known program RoE configs */
const PROGRAM_ROE_REGISTRY: Record<string, BugBountyProgramRoE> = {
  priceline: PRICELINE_ROE,
  nextcloud: NEXTCLOUD_ROE,
  wordpress: WORDPRESS_ROE,
  nodejs: NODEJS_ROE,
};

/**
 * Get the RoE config for a specific program.
 * Returns undefined if no config exists (program needs RoE import).
 */
export function getProgramRoE(programHandle: string): BugBountyProgramRoE | undefined {
  return PROGRAM_ROE_REGISTRY[programHandle.toLowerCase()];
}

/**
 * Get all registered program RoE configs.
 */
export function getAllProgramRoEs(): BugBountyProgramRoE[] {
  return Object.values(PROGRAM_ROE_REGISTRY);
}

/**
 * Register a new program RoE config (e.g., parsed from a program URL).
 */
export function registerProgramRoE(config: BugBountyProgramRoE): void {
  PROGRAM_ROE_REGISTRY[config.programHandle.toLowerCase()] = config;
}

// ─── Scan-Time Enforcement ────────────────────────────────────────────────

export interface ScanAction {
  /** Type of scan action being attempted */
  type: 'fuzz' | 'scan' | 'exploit' | 'enumerate' | 'crawl' | 'brute_force' | 'request';
  /** Target URL or hostname */
  target: string;
  /** Specific endpoint being targeted */
  endpoint?: string;
  /** Tool being used */
  tool?: string;
  /** Whether this is automated scanning */
  isAutomated: boolean;
  /** Additional context */
  context?: Record<string, any>;
}

export interface EnforcementResult {
  /** Whether the action is allowed */
  allowed: boolean;
  /** If blocked, which rule blocked it */
  blockedBy?: string;
  /** Enforcement level */
  enforcement?: 'hard' | 'soft';
  /** Human-readable reason */
  reason?: string;
  /** Required modifications to the action (e.g., add headers) */
  modifications?: {
    headers?: Record<string, string>;
    rateLimit?: { maxRps: number };
  };
}

/**
 * Check whether a scan action is permitted under the program's RoE.
 * This MUST be called before every active scan action in a BB engagement.
 */
export function enforceScanAction(
  programHandle: string,
  action: ScanAction,
  operatorUsername?: string
): EnforcementResult {
  const roe = getProgramRoE(programHandle);
  if (!roe) {
    return {
      allowed: false,
      enforcement: 'hard',
      reason: `No RoE config found for program "${programHandle}". Cannot proceed without understanding program rules.`,
    };
  }

  // ─── Check excluded targets ───
  const targetLower = action.target.toLowerCase();
  for (const excluded of roe.testingRestrictions.excludedTargets) {
    const pattern = excluded.replace(/\*/g, '.*').toLowerCase();
    if (new RegExp(`^${pattern}$`).test(targetLower) || targetLower.includes(excluded.replace(/\*/g, '').toLowerCase())) {
      return {
        allowed: false,
        enforcement: 'hard',
        blockedBy: 'excluded_target',
        reason: `Target "${action.target}" is explicitly excluded from scope: ${excluded}`,
      };
    }
  }

  // ─── Check excluded endpoints ───
  if (action.endpoint) {
    const endpointLower = action.endpoint.toLowerCase();
    for (const ep of roe.testingRestrictions.excludedEndpoints) {
      let matches = false;
      const patternLower = ep.pattern.toLowerCase();
      switch (ep.matchType) {
        case 'exact': matches = endpointLower === patternLower; break;
        case 'prefix': matches = endpointLower.startsWith(patternLower); break;
        case 'contains': matches = endpointLower.includes(patternLower); break;
        case 'regex': matches = new RegExp(ep.pattern, 'i').test(action.endpoint); break;
      }
      if (matches && action.type === 'fuzz') {
        return {
          allowed: false,
          enforcement: 'hard',
          blockedBy: 'excluded_endpoint',
          reason: `Endpoint "${action.endpoint}" must not be fuzzed: ${ep.reason}`,
        };
      }
    }
  }

  // ─── Check automated scanner restrictions ───
  if (action.isAutomated && !roe.testingRestrictions.automatedScannersAllowed) {
    // For programs that don't allow automated scanners, block automated actions
    // but allow manual-triggered scans with proper PoC follow-up
    if (action.type === 'fuzz' || action.type === 'brute_force') {
      return {
        allowed: false,
        enforcement: 'hard',
        blockedBy: 'automated_scanner_prohibited',
        reason: `Program "${programHandle}" does not accept automated scanner output. ${roe.testingRestrictions.scannerRestrictions || 'Manual testing with detailed PoC required.'}`,
      };
    }
  }

  // ─── Check prohibited action categories ───
  for (const prohibited of roe.testingRestrictions.prohibitedActions) {
    let matches = false;

    switch (prohibited.category) {
      case 'dos':
      case 'availability_impact':
        matches = action.type === 'brute_force' && (action.context?.highVolume === true);
        break;
      case 'fuzzing':
        if (action.type === 'fuzz' && prohibited.targets) {
          for (const t of prohibited.targets) {
            const pattern = t.replace(/\*/g, '.*');
            if (new RegExp(pattern, 'i').test(action.endpoint || action.target)) {
              matches = true;
              break;
            }
          }
        }
        break;
      case 'automated_scanning':
        matches = action.isAutomated && (action.type === 'scan' || action.type === 'fuzz');
        break;
      case 'inventory_manipulation':
        matches = action.context?.involvesReservation === true || action.context?.involvesBooking === true;
        break;
      case 'data_access':
        matches = action.context?.accessesOtherUserData === true;
        break;
      case 'account_manipulation':
        matches = action.context?.modifiesOtherAccounts === true;
        break;
    }

    if (matches) {
      return {
        allowed: false,
        enforcement: prohibited.enforcement,
        blockedBy: `prohibited_action:${prohibited.category}`,
        reason: prohibited.action,
      };
    }
  }

  // ─── Build modifications (headers, rate limiting) ───
  const modifications: EnforcementResult['modifications'] = {};

  // Add custom identification headers
  if (Object.keys(roe.identification.customHeaders).length > 0) {
    modifications.headers = { ...roe.identification.customHeaders };
    // Replace empty username placeholder with operator's username
    if (operatorUsername) {
      for (const [key, val] of Object.entries(modifications.headers)) {
        if (val === '') {
          modifications.headers[key] = operatorUsername;
        }
      }
    }
  }

  // Apply rate limiting
  if (roe.testingRestrictions.rateLimiting?.maxRequestsPerSecond) {
    modifications.rateLimit = {
      maxRps: roe.testingRestrictions.rateLimiting.maxRequestsPerSecond,
    };
  }

  return {
    allowed: true,
    modifications: Object.keys(modifications).length > 0 ? modifications : undefined,
  };
}

// ─── Report-Time Filtering ────────────────────────────────────────────────

export interface ReportFinding {
  /** Finding title */
  title: string;
  /** Finding description */
  description?: string;
  /** Severity (critical, high, medium, low, info) */
  severity: string;
  /** CWE ID if available */
  cwe?: string;
  /** Asset/target where found */
  asset: string;
  /** Source tool */
  source?: string;
  /** Whether finding has a detailed PoC */
  hasDetailedPoC?: boolean;
  /** CVE if available */
  cve?: string;
}

export interface FilteredFinding extends ReportFinding {
  /** Whether this finding is eligible for submission */
  eligible: boolean;
  /** If ineligible, why */
  ineligibleReason?: string;
  /** If eligible, any warnings */
  warnings?: string[];
}

/**
 * Filter findings against a program's RoE for report generation.
 * Returns findings annotated with eligibility status.
 */
export function filterFindingsForProgram(
  programHandle: string,
  findings: ReportFinding[]
): { eligible: FilteredFinding[]; ineligible: FilteredFinding[]; summary: FilterSummary } {
  const roe = getProgramRoE(programHandle);
  if (!roe) {
    // No RoE config — pass all through with warning
    const eligible = findings.map(f => ({ ...f, eligible: true, warnings: ['No program RoE config — cannot validate eligibility'] }));
    return {
      eligible,
      ineligible: [],
      summary: { total: findings.length, eligible: findings.length, ineligible: 0, noRoEConfig: true },
    };
  }

  const eligible: FilteredFinding[] = [];
  const ineligible: FilteredFinding[] = [];

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
      noRoEConfig: false,
    },
  };
}

export interface FilterSummary {
  total: number;
  eligible: number;
  ineligible: number;
  noRoEConfig: boolean;
}

/**
 * Check a single finding's eligibility against program RoE.
 */
function checkFindingEligibility(roe: BugBountyProgramRoE, finding: ReportFinding): FilteredFinding {
  const titleLower = (finding.title || '').toLowerCase();
  const descLower = (finding.description || '').toLowerCase();
  const combined = `${titleLower} ${descLower}`;
  const warnings: string[] = [];

  // ─── Check H1 Core Ineligible (if applicable) ───
  if (roe.ineligibleFindings.h1CoreIneligible) {
    for (const pattern of H1_CORE_INELIGIBLE_PATTERNS) {
      if (matchesIneligiblePattern(pattern, combined, finding)) {
        return {
          ...finding,
          eligible: false,
          ineligibleReason: pattern.reason,
        };
      }
    }
  }

  // ─── Check program-specific ineligible findings ───
  for (const pattern of roe.ineligibleFindings.programSpecificIneligible) {
    if (matchesIneligiblePattern(pattern, combined, finding)) {
      return {
        ...finding,
        eligible: false,
        ineligibleReason: pattern.reason,
      };
    }
  }

  // ─── Check excluded targets ───
  const assetLower = (finding.asset || '').toLowerCase();
  for (const excluded of roe.testingRestrictions.excludedTargets) {
    const pattern = excluded.replace(/\*/g, '.*').toLowerCase();
    if (new RegExp(pattern).test(assetLower)) {
      return {
        ...finding,
        eligible: false,
        ineligibleReason: `Finding on excluded target: ${excluded}`,
      };
    }
  }

  // ─── Check submission requirements ───
  if (roe.submissionRequirements.requiresDetailedPoC && !finding.hasDetailedPoC) {
    warnings.push('Program requires detailed working PoC — ensure manual verification before submission');
  }

  if (!roe.submissionRequirements.acceptsAutomatedScannerOutput && finding.source) {
    const automatedSources = ['nuclei', 'zap', 'burp_scanner', 'nikto', 'nessus', 'qualys', 'acunetix'];
    if (automatedSources.includes(finding.source.toLowerCase())) {
      warnings.push(`Finding from automated scanner (${finding.source}) — program requires manual PoC, not raw scanner output`);
    }
  }

  return {
    ...finding,
    eligible: true,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
}

/**
 * Match a finding against an ineligible pattern.
 */
function matchesIneligiblePattern(
  pattern: IneligibleFinding,
  combinedText: string,
  finding: ReportFinding
): boolean {
  switch (pattern.matchType) {
    case 'regex':
      return new RegExp(pattern.pattern, 'i').test(combinedText);
    case 'title_contains':
      return (finding.title || '').toLowerCase().includes(pattern.pattern.toLowerCase());
    case 'category_equals':
      return (finding.cwe || '').toLowerCase() === pattern.pattern.toLowerCase();
    case 'cwe_equals':
      return (finding.cwe || '') === pattern.pattern;
    case 'severity_below': {
      const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const findingSeverityIdx = severityOrder.indexOf((finding.severity || '').toLowerCase());
      const thresholdIdx = severityOrder.indexOf(pattern.pattern.toLowerCase());
      return findingSeverityIdx > thresholdIdx; // Higher index = lower severity
    }
    default:
      return false;
  }
}

// ─── Engagement RoE Summary (for UI display) ──────────────────────────────

export interface RoESummaryForOperator {
  programName: string;
  platform: string;
  policyUrl: string;
  /** Critical rules the operator MUST follow */
  criticalRules: string[];
  /** Required identification setup */
  identificationSetup: string[];
  /** What to look for (acceptable findings) */
  targetFindings: string[];
  /** What NOT to submit */
  doNotSubmit: string[];
  /** Cleanup actions required */
  cleanupActions: string[];
  /** Excluded targets */
  excludedTargets: string[];
}

/**
 * Generate a human-readable RoE summary for operator briefing.
 */
export function generateOperatorBriefing(programHandle: string): RoESummaryForOperator | null {
  const roe = getProgramRoE(programHandle);
  if (!roe) return null;

  return {
    programName: programHandle,
    platform: roe.platform,
    policyUrl: roe.policyUrl,
    criticalRules: roe.testingRestrictions.prohibitedActions
      .filter(a => a.enforcement === 'hard')
      .map(a => `❌ ${a.action}`),
    identificationSetup: [
      ...Object.entries(roe.identification.customHeaders).map(([k, v]) =>
        `Add header: ${k}: ${v || '<your-username>'}`
      ),
      ...(roe.identification.emailAlias ? [`Use email alias: <username>${roe.identification.emailAlias}`] : []),
      ...(roe.identification.includeIpInReport ? ['Include your IP address in all reports'] : []),
    ],
    targetFindings: roe.acceptableFindings.eligibleCategories.map(c =>
      `✅ ${c.description}${c.examples ? ` (e.g., ${c.examples.join(', ')})` : ''}`
    ),
    doNotSubmit: [
      ...(roe.ineligibleFindings.h1CoreIneligible ? ['All H1 Core Ineligible findings (version disclosure, missing headers, self-XSS, etc.)'] : []),
      ...roe.ineligibleFindings.programSpecificIneligible.map(p => p.reason),
      ...(!roe.submissionRequirements.acceptsAutomatedScannerOutput ? ['Raw automated scanner output without manual PoC'] : []),
    ],
    cleanupActions: roe.submissionRequirements.cleanupRequired.map(c => c.action),
    excludedTargets: roe.testingRestrictions.excludedTargets,
  };
}

// ─── HTTP Header Builder ──────────────────────────────────────────────────

/**
 * Build the custom HTTP headers required for a BB engagement.
 * These MUST be injected into all HTTP requests made during scanning.
 */
export function buildScanHeaders(
  programHandle: string,
  operatorUsername: string
): Record<string, string> {
  const roe = getProgramRoE(programHandle);
  if (!roe) return {};

  const headers: Record<string, string> = {};
  for (const [key, val] of Object.entries(roe.identification.customHeaders)) {
    headers[key] = val || operatorUsername;
  }

  return headers;
}
