/**
 * ZAP Source Code & Secrets Analysis Knowledge Module
 *
 * Teaches the LLM to use ZAP passive scanning for:
 * 1. JavaScript source code review (inline scripts, external JS files)
 * 2. Secret/credential detection in responses (API keys, tokens, passwords)
 * 3. Browser storage analysis (localStorage, sessionStorage secrets)
 * 4. Source code disclosure detection (Git, SVN, backup files, WEB-INF)
 * 5. Cloud metadata and infrastructure secret exposure
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SecretPattern {
  id: string;
  name: string;
  category: "api_key" | "token" | "credential" | "cloud" | "database" | "encryption" | "internal";
  regex: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  falsePositiveRate: "low" | "medium" | "high";
  remediation: string;
  examples: string[];
}

export interface JSAnalysisTechnique {
  id: string;
  name: string;
  description: string;
  zapRuleIds: number[];
  manualSteps: string[];
  whatToLookFor: string[];
  attackVectors: string[];
  tools: string[];
}

export interface SourceCodeDisclosureVector {
  id: string;
  name: string;
  zapRuleIds: number[];
  paths: string[];
  indicators: string[];
  exploitability: string;
  postExploitation: string[];
}

export interface BrowserStorageCheck {
  storageType: "localStorage" | "sessionStorage" | "cookies" | "indexedDB";
  zapRuleIds: number[];
  sensitiveKeys: string[];
  description: string;
  extractionMethod: string;
}

// ─── ZAP Passive Rules for Source/Secret Analysis ───────────────────────────

export const ZAP_SOURCE_SECRET_RULES = {
  // Source Code Disclosure
  sourceCodeDisclosure: [
    { ruleId: 41, name: "Source Code Disclosure - SVN", risk: "Medium", type: "active" as const },
    { ruleId: 42, name: "Source Code Disclosure - Git", risk: "Medium", type: "active" as const },
    { ruleId: 43, name: "Source Code Disclosure - File Inclusion", risk: "High", type: "active" as const },
    { ruleId: 10045, name: "Source Code Disclosure - /WEB-INF", risk: "High", type: "active" as const },
    { ruleId: 10099, name: "Source Code Disclosure - PHP", risk: "Medium", type: "active" as const },
    { ruleId: 20017, name: "Source Code Disclosure - CVE-2012-1823", risk: "High", type: "active" as const },
  ],

  // JavaScript & Script Analysis
  scriptAnalysis: [
    { ruleId: 10055, name: "CSP: script-src unsafe-inline", risk: "Medium", type: "passive" as const },
    { ruleId: 10115, name: "Script Served From Malicious Domain", risk: "High", type: "passive" as const },
    { ruleId: 40026, name: "Cross Site Scripting (DOM Based)", risk: "High", type: "active" as const },
    { ruleId: 90003, name: "Sub Resource Integrity Missing", risk: "Medium", type: "passive" as const },
    { ruleId: 10025, name: "Suspicious Comments in Source", risk: "Informational", type: "passive" as const },
  ],

  // Secrets & Credential Disclosure
  secretsDisclosure: [
    { ruleId: 10105, name: "Authentication Credentials Captured", risk: "High", type: "passive" as const },
    { ruleId: 10057, name: "Username Hash Found", risk: "Informational", type: "passive" as const },
    { ruleId: 10097, name: "Hash Disclosure - MD4/MD5", risk: "Medium", type: "passive" as const },
    { ruleId: 10094, name: "Base64 Disclosure", risk: "Informational", type: "passive" as const },
    { ruleId: 10062, name: "PII Disclosure", risk: "High", type: "passive" as const },
    { ruleId: 100034, name: "Google API Key Disclosure", risk: "Medium", type: "passive" as const },
    { ruleId: 100043, name: "Swagger UI Secret Detector", risk: "High", type: "passive" as const },
  ],

  // File & Backup Disclosure
  fileDisclosure: [
    { ruleId: 40034, name: ".env Information Leak", risk: "High", type: "active" as const },
    { ruleId: 40032, name: ".htaccess Information Leak", risk: "Medium", type: "active" as const },
    { ruleId: 40035, name: "Hidden File Found", risk: "Medium", type: "active" as const },
    { ruleId: 10095, name: "Backup File Disclosure", risk: "Medium", type: "active" as const },
    { ruleId: 40028, name: "ELMAH Information Leak", risk: "Medium", type: "active" as const },
    { ruleId: 40029, name: "Trace.axd Information Leak", risk: "Medium", type: "active" as const },
    { ruleId: 40042, name: "Spring Actuator Information Leak", risk: "High", type: "active" as const },
  ],

  // Cloud & Infrastructure
  cloudSecrets: [
    { ruleId: 90034, name: "Cloud Metadata Exposed", risk: "High", type: "active" as const },
    { ruleId: 100036, name: "Amazon S3 Bucket URL Disclosure", risk: "Medium", type: "passive" as const },
  ],

  // Browser Storage Analysis
  browserStorage: [
    { ruleId: 120000, name: "Information in Browser Storage", risk: "Medium", type: "passive" as const },
    { ruleId: 120001, name: "Sensitive Information in Browser Storage", risk: "High", type: "passive" as const },
    { ruleId: 120002, name: "JWT in Browser Storage", risk: "High", type: "passive" as const },
  ],

  // Debug & Error Disclosure
  debugDisclosure: [
    { ruleId: 10042, name: "Debug Error Messages", risk: "Medium", type: "passive" as const },
    { ruleId: 10056, name: "X-Debug-Token Information Leak", risk: "Low", type: "passive" as const },
    { ruleId: 10052, name: "X-ChromeLogger-Data Header Leak", risk: "Medium", type: "passive" as const },
    { ruleId: 90022, name: "Application Error Disclosure", risk: "Medium", type: "passive" as const },
  ],
};

// ─── Secret Patterns for JS/HTML Source Analysis ────────────────────────────

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    category: "cloud",
    regex: "AKIA[0-9A-Z]{16}",
    description: "AWS IAM access key that grants programmatic access to AWS services",
    severity: "critical",
    falsePositiveRate: "low",
    remediation: "Rotate the key immediately via AWS IAM console, check CloudTrail for unauthorized usage",
    examples: ["AKIAIOSFODNN7EXAMPLE"],
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    category: "cloud",
    regex: "['\"][0-9a-zA-Z/+]{40}['\"]",
    description: "AWS secret key paired with access key ID for authentication",
    severity: "critical",
    falsePositiveRate: "medium",
    remediation: "Rotate both access key and secret key, audit CloudTrail logs",
    examples: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
  },
  {
    id: "gcp-api-key",
    name: "Google Cloud API Key",
    category: "cloud",
    regex: "AIza[0-9A-Za-z_-]{35}",
    description: "Google Cloud Platform API key for service authentication",
    severity: "high",
    falsePositiveRate: "low",
    remediation: "Restrict API key scope, rotate via GCP console, add HTTP referrer restrictions",
    examples: ["AIzaSyA1234567890abcdefghijklmnopqrstuvw"],
  },
  {
    id: "github-token",
    name: "GitHub Personal Access Token",
    category: "token",
    regex: "gh[pousr]_[A-Za-z0-9_]{36,255}",
    description: "GitHub PAT granting repository and organization access",
    severity: "critical",
    falsePositiveRate: "low",
    remediation: "Revoke token at github.com/settings/tokens, audit repository access logs",
    examples: ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"],
  },
  {
    id: "slack-token",
    name: "Slack Bot/User Token",
    category: "token",
    regex: "xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
    description: "Slack API token for bot or user workspace access",
    severity: "high",
    falsePositiveRate: "low",
    remediation: "Revoke token in Slack admin, rotate bot credentials",
    examples: ["xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx"],
  },
  {
    id: "stripe-secret",
    name: "Stripe Secret Key",
    category: "api_key",
    regex: "sk_(live|test)_[0-9a-zA-Z]{24,99}",
    description: "Stripe payment processing secret key — allows charges and refunds",
    severity: "critical",
    falsePositiveRate: "low",
    remediation: "Roll the key in Stripe Dashboard immediately, audit recent transactions",
    examples: ["sk_live_4eC39HqLyjWDarjtT1zdp7dc"],
  },
  {
    id: "stripe-publishable",
    name: "Stripe Publishable Key",
    category: "api_key",
    regex: "pk_(live|test)_[0-9a-zA-Z]{24,99}",
    description: "Stripe publishable key — lower risk but reveals account info",
    severity: "low",
    falsePositiveRate: "low",
    remediation: "Verify it's only used client-side; roll if paired with exposed secret key",
    examples: ["pk_live_4eC39HqLyjWDarjtT1zdp7dc"],
  },
  {
    id: "jwt-secret",
    name: "JWT Secret / Signing Key",
    category: "encryption",
    regex: "(?:jwt[_-]?secret|JWT_SECRET|jwt[_-]?key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
    description: "JWT signing secret allows forging authentication tokens",
    severity: "critical",
    falsePositiveRate: "medium",
    remediation: "Rotate the JWT secret, invalidate all existing sessions, move to env vars",
    examples: ["JWT_SECRET='my-super-secret-key-2024'"],
  },
  {
    id: "database-url",
    name: "Database Connection String",
    category: "database",
    regex: "(?:mysql|postgres|mongodb|redis|mssql)://[^\\s'\"]+:[^\\s'\"]+@[^\\s'\"]+",
    description: "Database connection URI with embedded credentials",
    severity: "critical",
    falsePositiveRate: "low",
    remediation: "Rotate database password, restrict network access, move to env vars",
    examples: ["postgres://admin:password123@db.example.com:5432/production"],
  },
  {
    id: "private-key",
    name: "Private Key (RSA/EC/SSH)",
    category: "encryption",
    regex: "-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    description: "Cryptographic private key for TLS, SSH, or code signing",
    severity: "critical",
    falsePositiveRate: "low",
    remediation: "Revoke and regenerate the key pair, update all services using it",
    examples: ["-----BEGIN RSA PRIVATE KEY-----"],
  },
  {
    id: "sendgrid-key",
    name: "SendGrid API Key",
    category: "api_key",
    regex: "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}",
    description: "SendGrid email service API key",
    severity: "high",
    falsePositiveRate: "low",
    remediation: "Revoke in SendGrid dashboard, create new restricted key",
    examples: ["SG.abcdefghijklmnopqrstuv.wxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"],
  },
  {
    id: "twilio-key",
    name: "Twilio API Key",
    category: "api_key",
    regex: "SK[0-9a-fA-F]{32}",
    description: "Twilio API key for SMS/voice services",
    severity: "high",
    falsePositiveRate: "medium",
    remediation: "Delete the API key in Twilio console, create new one",
    examples: ["SK1234567890abcdef1234567890abcdef"],
  },
  {
    id: "firebase-config",
    name: "Firebase Configuration",
    category: "cloud",
    regex: "(?:apiKey|authDomain|databaseURL|storageBucket)\\s*:\\s*['\"][^'\"]+['\"]",
    description: "Firebase project configuration — may expose project details and enable abuse",
    severity: "medium",
    falsePositiveRate: "high",
    remediation: "Restrict Firebase security rules, add domain restrictions to API key",
    examples: ["apiKey: 'AIzaSyA1234567890'"],
  },
  {
    id: "hardcoded-password",
    name: "Hardcoded Password",
    category: "credential",
    regex: "(?:password|passwd|pwd|secret)\\s*[:=]\\s*['\"][^'\"]{4,}['\"]",
    description: "Hardcoded password in source code or configuration",
    severity: "high",
    falsePositiveRate: "high",
    remediation: "Remove hardcoded password, use environment variables or secret manager",
    examples: ["password = 'admin123'", "const pwd = 'supersecret'"],
  },
  {
    id: "bearer-token",
    name: "Bearer/Authorization Token",
    category: "token",
    regex: "(?:Bearer|Authorization)\\s+[A-Za-z0-9_-]{20,}",
    description: "Authorization bearer token in source code or response headers",
    severity: "high",
    falsePositiveRate: "medium",
    remediation: "Revoke the token, implement token rotation, use short-lived tokens",
    examples: ["Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."],
  },
  {
    id: "mailgun-key",
    name: "Mailgun API Key",
    category: "api_key",
    regex: "key-[0-9a-zA-Z]{32}",
    description: "Mailgun email service API key",
    severity: "high",
    falsePositiveRate: "low",
    remediation: "Rotate key in Mailgun dashboard",
    examples: ["key-1234567890abcdef1234567890abcdef"],
  },
  {
    id: "azure-connection",
    name: "Azure Connection String",
    category: "cloud",
    regex: "DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
    description: "Azure Storage account connection string with embedded key",
    severity: "critical",
    falsePositiveRate: "low",
    remediation: "Rotate storage account keys in Azure portal, use managed identity instead",
    examples: ["DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123..."],
  },
  {
    id: "openai-key",
    name: "OpenAI API Key",
    category: "api_key",
    regex: "sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",
    description: "OpenAI API key for GPT/DALL-E/Whisper services",
    severity: "high",
    falsePositiveRate: "low",
    remediation: "Revoke at platform.openai.com, create new key with usage limits",
    examples: ["sk-abc123...T3BlbkFJ...xyz789"],
  },
  {
    id: "internal-ip",
    name: "Internal/Private IP Address",
    category: "internal",
    regex: "(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})",
    description: "Internal network IP address leaked in response — reveals network topology",
    severity: "low",
    falsePositiveRate: "medium",
    remediation: "Configure server to strip internal IPs from responses and error messages",
    examples: ["10.0.1.42", "192.168.1.100"],
  },
];

// ─── JavaScript Analysis Techniques ─────────────────────────────────────────

export const JS_ANALYSIS_TECHNIQUES: JSAnalysisTechnique[] = [
  {
    id: "inline-secrets",
    name: "Inline Secret Detection in JavaScript",
    description: "Scan JavaScript files and inline <script> blocks for hardcoded API keys, tokens, passwords, and connection strings. Modern SPAs often bundle configuration objects containing secrets that should be server-side only.",
    zapRuleIds: [10025, 10094, 100034, 100043],
    manualSteps: [
      "Spider the target with parseComments=true and parseGit=true to discover all JS files",
      "Use ZAP's Search feature to grep all responses for secret patterns (AKIA, sk_, ghp_, etc.)",
      "Check inline <script> tags in HTML responses for config objects with API keys",
      "Inspect webpack/vite chunk files — secrets often end up in vendor bundles",
      "Check source maps (.map files) which may contain original source with comments and secrets",
      "Review window.__CONFIG__ or similar global config injections",
    ],
    whatToLookFor: [
      "API keys: AWS (AKIA...), GCP (AIza...), Stripe (sk_live/pk_live), SendGrid (SG.)",
      "OAuth secrets: client_secret, client_id paired with secret values",
      "Database URLs: mongodb://, postgres://, mysql:// with credentials",
      "JWT secrets: jwt_secret, JWT_KEY, signing_key assignments",
      "Firebase config objects with apiKey, authDomain, databaseURL",
      "Environment variable leaks: process.env references that got bundled",
      "Hardcoded Bearer tokens in fetch/axios interceptors",
      "Base64-encoded credentials in Authorization headers",
    ],
    attackVectors: [
      "Use discovered API keys to access cloud services (S3, GCP Storage, etc.)",
      "Use database connection strings for direct database access",
      "Forge JWT tokens using discovered signing secrets",
      "Access internal APIs using discovered bearer tokens",
      "Enumerate cloud resources using leaked account identifiers",
    ],
    tools: ["ZAP Spider", "ZAP Ajax Spider", "ZAP Search", "ZAP Passive Scanner", "JS Beautifier"],
  },
  {
    id: "source-map-analysis",
    name: "Source Map Exploitation",
    description: "Modern JavaScript bundlers (webpack, vite, rollup) generate .map files that contain the original source code. If these are accessible in production, attackers can reconstruct the entire frontend codebase including comments, variable names, and potentially secrets.",
    zapRuleIds: [10025, 10094],
    manualSteps: [
      "Check for sourceMappingURL comments in JS files: //# sourceMappingURL=...",
      "Try appending .map to discovered JS file URLs",
      "Check common paths: /static/js/*.map, /assets/*.map, /_next/static/*.map",
      "Parse source maps to extract original file tree and source code",
      "Search extracted source for secrets, internal URLs, and API endpoints",
      "Look for development comments (TODO, FIXME, HACK, XXX) with sensitive context",
    ],
    whatToLookFor: [
      "Original TypeScript/JSX source with developer comments",
      "Internal API endpoint URLs and service architecture",
      "Environment variable references that reveal configuration",
      "Authentication logic and token handling patterns",
      "Admin routes and hidden functionality",
      "Database query patterns and ORM model definitions",
    ],
    attackVectors: [
      "Reconstruct full application logic to find business logic flaws",
      "Discover hidden admin endpoints and API routes",
      "Find authentication bypass patterns in original source",
      "Map internal microservice architecture from import paths",
    ],
    tools: ["ZAP Spider", "source-map-explorer", "unwebpack-sourcemap"],
  },
  {
    id: "dom-based-analysis",
    name: "DOM-Based Vulnerability Analysis",
    description: "Analyze JavaScript for DOM-based vulnerabilities where user input flows from sources (location.hash, document.referrer, postMessage) to sinks (innerHTML, eval, document.write) without sanitization.",
    zapRuleIds: [40026, 10055],
    manualSteps: [
      "Use ZAP Ajax Spider with browser-based crawling to execute JavaScript",
      "Enable DOM XSS passive scan rule (40026) for automated detection",
      "Check for unsafe CSP directives: unsafe-inline, unsafe-eval",
      "Review JavaScript for dangerous sink functions: eval(), innerHTML, document.write()",
      "Trace data flow from URL parameters/fragments to DOM manipulation",
      "Check postMessage handlers for missing origin validation",
    ],
    whatToLookFor: [
      "document.location.hash used directly in DOM operations",
      "URL parameters reflected into innerHTML or outerHTML",
      "eval() or Function() called with user-controllable input",
      "jQuery .html() or .append() with unsanitized data",
      "postMessage event handlers without origin checks",
      "Angular/React dangerouslySetInnerHTML with dynamic content",
      "Template literal injection in framework templates",
    ],
    attackVectors: [
      "DOM XSS via URL fragment injection",
      "Prototype pollution via __proto__ or constructor.prototype",
      "Client-side template injection in Angular/Vue",
      "postMessage-based XSS from cross-origin frames",
      "Open redirect via client-side routing manipulation",
    ],
    tools: ["ZAP Ajax Spider", "ZAP DOM XSS Scanner", "Browser DevTools"],
  },
  {
    id: "browser-storage-audit",
    name: "Browser Storage Secret Audit",
    description: "Analyze localStorage, sessionStorage, cookies, and IndexedDB for sensitive data that should not be stored client-side. Many SPAs store JWTs, API keys, or PII in browser storage where they're vulnerable to XSS extraction.",
    zapRuleIds: [120000, 120001, 120002],
    manualSteps: [
      "Use ZAP Ajax Spider (browser-based) to trigger JavaScript that populates storage",
      "Enable Browser Storage passive scan rules (120000-120002)",
      "Check localStorage for JWT tokens, API keys, and session data",
      "Check sessionStorage for temporary credentials and auth state",
      "Review cookies for sensitive data without HttpOnly/Secure flags",
      "Check IndexedDB for cached API responses containing PII",
    ],
    whatToLookFor: [
      "JWT tokens in localStorage (vulnerable to XSS theft)",
      "API keys or access tokens stored client-side",
      "User PII (email, phone, SSN) in browser storage",
      "OAuth refresh tokens in localStorage",
      "Session identifiers without HttpOnly flag",
      "Cached API responses with sensitive business data",
    ],
    attackVectors: [
      "XSS + localStorage theft = full account takeover",
      "Stolen JWT from storage allows session hijacking",
      "Cached PII extraction for identity theft",
      "Refresh token theft for persistent access",
    ],
    tools: ["ZAP Ajax Spider", "Browser DevTools", "ZAP Passive Scanner"],
  },
  {
    id: "js-library-audit",
    name: "JavaScript Library Vulnerability Audit",
    description: "Identify outdated or vulnerable JavaScript libraries loaded by the application. Known CVEs in client-side libraries (jQuery, Angular, lodash, etc.) can enable XSS, prototype pollution, and other attacks.",
    zapRuleIds: [10003, 90003, 10115],
    manualSteps: [
      "Spider the target to discover all loaded JavaScript files",
      "Check for version strings in JS file headers/comments",
      "Cross-reference discovered libraries with known CVE databases",
      "Check for Sub-Resource Integrity (SRI) on CDN-loaded scripts",
      "Verify scripts are not loaded from compromised CDNs (polyfill.io)",
      "Check for outdated jQuery, Angular 1.x, lodash with prototype pollution",
    ],
    whatToLookFor: [
      "jQuery < 3.5.0 (XSS via htmlPrefilter)",
      "Angular 1.x (template injection, sandbox escape)",
      "lodash < 4.17.21 (prototype pollution)",
      "moment.js (ReDoS vulnerabilities)",
      "Scripts from polyfill.io or other compromised CDNs",
      "Missing SRI hashes on third-party scripts",
    ],
    attackVectors: [
      "Exploit known CVEs in outdated libraries",
      "Supply chain attack via compromised CDN scripts",
      "Prototype pollution leading to XSS or auth bypass",
      "ReDoS for denial of service",
    ],
    tools: ["ZAP Spider", "Retire.js", "npm audit", "Snyk"],
  },
];

// ─── Source Code Disclosure Vectors ──────────────────────────────────────────

export const SOURCE_CODE_DISCLOSURE_VECTORS: SourceCodeDisclosureVector[] = [
  {
    id: "git-exposure",
    name: "Git Repository Exposure",
    zapRuleIds: [42, 40035],
    paths: ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/refs/heads/main", "/.gitignore"],
    indicators: ["ref: refs/heads/", "[core]", "[remote", "DIRC"],
    exploitability: "Full source code reconstruction using git-dumper or manual object download",
    postExploitation: [
      "Reconstruct full source code history with git checkout",
      "Extract secrets from git log (committed then removed)",
      "Find internal URLs, database schemas, API documentation",
      "Discover deployment scripts and infrastructure details",
    ],
  },
  {
    id: "svn-exposure",
    name: "SVN Repository Exposure",
    zapRuleIds: [41, 40035],
    paths: ["/.svn/entries", "/.svn/wc.db", "/.svn/pristine/"],
    indicators: ["svn:entry", "SQLite format 3"],
    exploitability: "Source code extraction via SVN metadata files",
    postExploitation: [
      "Download wc.db for full file listing and metadata",
      "Extract pristine copies of source files",
      "Find credentials in SVN properties",
    ],
  },
  {
    id: "env-file-exposure",
    name: "Environment File Exposure",
    zapRuleIds: [40034, 40035, 10095],
    paths: ["/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup", "/env.js", "/config.js"],
    indicators: ["DB_PASSWORD=", "API_KEY=", "SECRET_KEY=", "DATABASE_URL=", "AWS_"],
    exploitability: "Direct credential extraction — often contains all service credentials",
    postExploitation: [
      "Use database credentials for direct DB access",
      "Use API keys for cloud service access (AWS, GCP, Azure)",
      "Use JWT secrets to forge authentication tokens",
      "Use SMTP credentials for email spoofing",
      "Use payment gateway keys (Stripe, PayPal) for financial fraud",
    ],
  },
  {
    id: "backup-file-exposure",
    name: "Backup & Config File Exposure",
    zapRuleIds: [10095, 40035],
    paths: [
      "/web.config.bak", "/web.config.old", "/wp-config.php.bak", "/config.php.bak",
      "/database.yml.bak", "/settings.py.bak", "/.DS_Store", "/Thumbs.db",
      "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
    ],
    indicators: ["<?php", "connectionString", "password:", "secret_key"],
    exploitability: "Configuration files often contain database credentials and API keys",
    postExploitation: [
      "Extract database credentials from config backups",
      "Map application dependencies for known CVE exploitation",
      "Find internal service URLs and architecture details",
    ],
  },
  {
    id: "webinf-exposure",
    name: "Java WEB-INF Exposure",
    zapRuleIds: [10045],
    paths: ["/WEB-INF/web.xml", "/WEB-INF/classes/", "/WEB-INF/lib/", "/META-INF/MANIFEST.MF"],
    indicators: ["<web-app", "<servlet", "Main-Class:"],
    exploitability: "Full Java application source and configuration exposure",
    postExploitation: [
      "Extract servlet mappings and URL patterns",
      "Download compiled .class files for decompilation",
      "Find database JNDI configurations",
      "Discover internal API endpoints from web.xml",
    ],
  },
  {
    id: "cloud-metadata",
    name: "Cloud Metadata Service Exposure",
    zapRuleIds: [90034],
    paths: [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    indicators: ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey"],
    exploitability: "SSRF to cloud metadata can yield temporary IAM credentials with broad access",
    postExploitation: [
      "Use temporary AWS credentials for S3 bucket access",
      "Enumerate EC2 instances and security groups",
      "Access other cloud services using instance role",
      "Pivot to internal network via cloud VPC",
    ],
  },
];

// ─── Browser Storage Checks ─────────────────────────────────────────────────

export const BROWSER_STORAGE_CHECKS: BrowserStorageCheck[] = [
  {
    storageType: "localStorage",
    zapRuleIds: [120000, 120001, 120002],
    sensitiveKeys: [
      "token", "jwt", "access_token", "refresh_token", "id_token",
      "api_key", "apiKey", "auth", "session", "user", "credentials",
      "password", "secret", "private_key", "bearer",
    ],
    description: "localStorage persists across browser sessions and is accessible to any JavaScript on the same origin. XSS can steal all stored data.",
    extractionMethod: "Object.keys(localStorage).forEach(k => console.log(k, localStorage.getItem(k)))",
  },
  {
    storageType: "sessionStorage",
    zapRuleIds: [120000, 120001, 120002],
    sensitiveKeys: [
      "token", "jwt", "access_token", "auth_state", "csrf_token",
      "session_id", "user_data", "temp_credentials",
    ],
    description: "sessionStorage is cleared when the tab closes but is still vulnerable to XSS during the session.",
    extractionMethod: "Object.keys(sessionStorage).forEach(k => console.log(k, sessionStorage.getItem(k)))",
  },
  {
    storageType: "cookies",
    zapRuleIds: [10010, 10011, 10054, 10029],
    sensitiveKeys: [
      "session", "JSESSIONID", "PHPSESSID", "connect.sid", "auth",
      "token", "remember_me", "csrf",
    ],
    description: "Cookies without HttpOnly flag are accessible to JavaScript. Missing Secure flag allows interception over HTTP.",
    extractionMethod: "document.cookie",
  },
  {
    storageType: "indexedDB",
    zapRuleIds: [120000],
    sensitiveKeys: [
      "user_profile", "cached_responses", "offline_data", "encryption_keys",
    ],
    description: "IndexedDB can store large amounts of structured data including cached API responses with PII.",
    extractionMethod: "indexedDB.databases().then(dbs => console.log(dbs))",
  },
];

// ─── Context Builder Functions ──────────────────────────────────────────────

/**
 * Build the full ZAP source code & secrets analysis context for LLM injection
 */
export function buildSourceSecretsContext(params: {
  phase: string;
  includeSecretPatterns?: boolean;
  includeJSAnalysis?: boolean;
  includeSourceDisclosure?: boolean;
  includeBrowserStorage?: boolean;
  technology?: string;
}): string {
  const sections: string[] = [];

  // Always include the ZAP rule catalog for source/secret scanning
  sections.push(buildRuleCatalogSection());

  // Secret patterns for vuln_detection and exploitation phases
  if (params.includeSecretPatterns !== false &&
      (params.phase === "vuln_detection" || params.phase === "exploitation" || params.phase === "enumeration")) {
    sections.push(buildSecretPatternsSection(params.technology));
  }

  // JS analysis techniques for vuln_detection and exploitation
  if (params.includeJSAnalysis !== false &&
      (params.phase === "vuln_detection" || params.phase === "exploitation")) {
    sections.push(buildJSAnalysisSection());
  }

  // Source code disclosure vectors for enumeration and vuln_detection
  if (params.includeSourceDisclosure !== false &&
      (params.phase === "enumeration" || params.phase === "vuln_detection" || params.phase === "exploitation")) {
    sections.push(buildSourceDisclosureSection());
  }

  // Browser storage checks for vuln_detection with Ajax Spider
  if (params.includeBrowserStorage !== false &&
      (params.phase === "vuln_detection" || params.phase === "exploitation")) {
    sections.push(buildBrowserStorageSection());
  }

  if (sections.length === 0) return "";

  return `# ZAP Source Code & Secrets Analysis Knowledge\n\n${sections.join("\n\n---\n\n")}`;
}

function buildRuleCatalogSection(): string {
  const allRules = [
    ...ZAP_SOURCE_SECRET_RULES.sourceCodeDisclosure,
    ...ZAP_SOURCE_SECRET_RULES.scriptAnalysis,
    ...ZAP_SOURCE_SECRET_RULES.secretsDisclosure,
    ...ZAP_SOURCE_SECRET_RULES.fileDisclosure,
    ...ZAP_SOURCE_SECRET_RULES.cloudSecrets,
    ...ZAP_SOURCE_SECRET_RULES.browserStorage,
    ...ZAP_SOURCE_SECRET_RULES.debugDisclosure,
  ];

  const passive = allRules.filter(r => r.type === "passive");
  const active = allRules.filter(r => r.type === "active");

  return `## ZAP Rules for Source Code & Secret Detection

### Passive Rules (run automatically during spidering)
${passive.map(r => `- **${r.ruleId}**: ${r.name} [${r.risk}]`).join("\n")}

### Active Rules (require active scan)
${active.map(r => `- **${r.ruleId}**: ${r.name} [${r.risk}]`).join("\n")}

**Configuration**: Enable ALL passive rules at LOW threshold for maximum coverage. For active rules, set source code disclosure rules (41, 42, 43, 10045) to HIGH strength and file disclosure rules (40034, 40035, 10095) to MEDIUM strength.`;
}

function buildSecretPatternsSection(technology?: string): string {
  let patterns = SECRET_PATTERNS;

  // Prioritize patterns relevant to the technology
  if (technology) {
    const techLower = technology.toLowerCase();
    const prioritized = patterns.filter(p => {
      if (techLower.includes("aws") || techLower.includes("amazon")) return p.category === "cloud";
      if (techLower.includes("node") || techLower.includes("react")) return ["api_key", "token", "database"].includes(p.category);
      if (techLower.includes("java") || techLower.includes("spring")) return ["database", "cloud", "encryption"].includes(p.category);
      return true;
    });
    if (prioritized.length > 0) patterns = [...prioritized, ...patterns.filter(p => !prioritized.includes(p))];
  }

  return `## Secret Detection Patterns

When analyzing JavaScript files, HTML source, and API responses, search for these patterns:

${patterns.map(p => `### ${p.name} [${p.severity.toUpperCase()}]
- **Pattern**: \`${p.regex}\`
- **Category**: ${p.category}
- **FP Rate**: ${p.falsePositiveRate}
- **What it means**: ${p.description}
- **Remediation**: ${p.remediation}
- **Example**: \`${p.examples[0]}\``).join("\n\n")}

**Search Strategy**: After spidering, use ZAP's Search tab to grep ALL responses for each pattern. Focus on JavaScript files, JSON responses, and HTML inline scripts.`;
}

function buildJSAnalysisSection(): string {
  return `## JavaScript Source Code Analysis Techniques

${JS_ANALYSIS_TECHNIQUES.map(t => `### ${t.name}
${t.description}

**ZAP Rules**: ${t.zapRuleIds.join(", ")}

**Steps**:
${t.manualSteps.map((s, i) => `${i + 1}. ${s}`).join("\n")}

**What to look for**:
${t.whatToLookFor.map(w => `- ${w}`).join("\n")}

**Attack vectors**:
${t.attackVectors.map(a => `- ${a}`).join("\n")}`).join("\n\n---\n\n")}`;
}

function buildSourceDisclosureSection(): string {
  return `## Source Code Disclosure Vectors

${SOURCE_CODE_DISCLOSURE_VECTORS.map(v => `### ${v.name}
**ZAP Rules**: ${v.zapRuleIds.join(", ")}
**Probe Paths**: ${v.paths.slice(0, 4).join(", ")}
**Indicators**: ${v.indicators.join(", ")}
**Exploitability**: ${v.exploitability}
**Post-Exploitation**:
${v.postExploitation.map(p => `- ${p}`).join("\n")}`).join("\n\n")}`;
}

function buildBrowserStorageSection(): string {
  return `## Browser Storage Security Audit

Use ZAP Ajax Spider (browser-based crawling) to trigger JavaScript that populates browser storage, then analyze:

${BROWSER_STORAGE_CHECKS.map(c => `### ${c.storageType}
**ZAP Rules**: ${c.zapRuleIds.join(", ")}
**Risk**: ${c.description}
**Sensitive Keys to Check**: ${c.sensitiveKeys.join(", ")}
**Extraction**: \`${c.extractionMethod}\``).join("\n\n")}

**IMPORTANT**: Browser storage analysis requires the Ajax Spider (browser-based crawling) to be enabled. Standard spider does not execute JavaScript and will miss storage-based secrets.`;
}

// ─── Compact Context for Token-Limited Scenarios ────────────────────────────

/**
 * Build a compact version of the source/secrets context for token-limited LLM calls
 */
export function buildCompactSourceSecretsContext(): string {
  const criticalPatterns = SECRET_PATTERNS.filter(p => p.severity === "critical");
  const highPatterns = SECRET_PATTERNS.filter(p => p.severity === "high").slice(0, 5);

  return `## Source Code & Secrets Quick Reference

### Critical Secret Patterns to Search For:
${[...criticalPatterns, ...highPatterns].map(p => `- ${p.name}: \`${p.regex}\` [${p.severity}]`).join("\n")}

### ZAP Configuration for Secret Detection:
1. Enable passive rules: 10025 (Suspicious Comments), 10094 (Base64), 100034 (Google API Key), 120001 (Browser Storage Secrets)
2. Enable active rules: 40034 (.env), 40035 (Hidden Files), 42 (Git), 10045 (WEB-INF), 10095 (Backup Files)
3. Spider config: parseComments=true, parseGit=true, parseSVNEntries=true
4. Use Ajax Spider for browser storage analysis
5. After spidering: Search all responses for secret patterns listed above

### Key JS Analysis Points:
- Check source maps (.map files) for original source code
- Search webpack/vite bundles for hardcoded secrets
- Analyze localStorage/sessionStorage for JWT tokens and API keys
- Check inline <script> blocks for config objects with credentials
- Review postMessage handlers for missing origin validation`;
}

// ─── Metadata ───────────────────────────────────────────────────────────────

export function getSourceSecretsMetadata() {
  return {
    name: "ZAP Source Code & Secrets Analysis",
    description: "Knowledge module for using ZAP to analyze JavaScript source code, detect hardcoded secrets, audit browser storage, and find source code disclosure vulnerabilities",
    itemCount: SECRET_PATTERNS.length + JS_ANALYSIS_TECHNIQUES.length + SOURCE_CODE_DISCLOSURE_VECTORS.length + BROWSER_STORAGE_CHECKS.length,
    categories: ["source_code_disclosure", "secret_detection", "javascript_analysis", "browser_storage"],
    phases: ["enumeration", "vuln_detection", "exploitation"],
    mitreTechniques: [
      "T1552.001", // Credentials In Files
      "T1552.004", // Private Keys
      "T1552.005", // Cloud Instance Metadata
      "T1190",     // Exploit Public-Facing Application
      "T1059.007", // JavaScript
      "T1539",     // Steal Web Session Cookie
      "T1528",     // Steal Application Access Token
    ],
  };
}
