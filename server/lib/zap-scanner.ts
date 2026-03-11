/**
 * OWASP ZAP Web Application Scanner — Dual-Mode Architecture with LLM Orchestration
 * 
 * Two operational modes:
 * 1. PASSIVE RECON — Spider/crawl + passive scanning for domain intelligence workflow
 *    - URL discovery, technology fingerprinting, passive vulnerability detection
 *    - Integrates with domain intel pipeline as a recon stage
 * 
 * 2. ACTIVE DAST — Full attack scanning coordinated with Metasploit/Caldera
 *    - Active vulnerability scanning with intelligent policy selection
 *    - MITRE ATT&CK technique mapping for attack chain integration
 *    - Exploit module correlation for Metasploit handoff
 *    - Caldera ability mapping for C2 coordination
 * 
 * LLM-Powered Orchestrator:
 *    - Analyzes target tech stack to auto-configure scan policies
 *    - Selects optimal spider (traditional vs AJAX) based on SPA detection
 *    - Configures authentication handlers based on login form analysis
 *    - Tunes scan rules for specific frameworks (Spring, Django, Rails, etc.)
 *    - Performs AI-powered false positive triage on findings
 * 
 * Requires ZAP running in daemon mode: ZAP_API_KEY, ZAP_BASE_URL
 */

import { getDb } from "../db";
import { webAppScans, webAppFindings } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";
import { HttpProxyAgent } from "http-proxy-agent";
import {
  selectPlaybook,
  applyPlaybookToZap,
  generateEnhancedSystemPrompt,
  getRulesForTechStack,
  getFootholdRules,
  getMsfModulesForTechStack,
  type PlaybookPhase,
  type ZapPlaybookConfig,
  type ZapApiConfig,
} from "./zap-attack-playbooks";
import {
  getTechScanPolicyContext,
  getZAPAuthContext,
  getZAPAlertCatalogContext,
  TECH_SCAN_POLICIES,
  type TechScanPolicy,
} from "./knowledge/zap-pentesting-knowledge";

// ─── Configuration ──────────────────────────────────────────────────────────

export interface ZapConfig {
  baseUrl: string;
  apiKey: string;
  spiderMaxDepth: number;
  spiderMaxChildren: number;
  activeScanPolicy: string;
  requestDelayMs: number;
  maxAlertsPerScan: number;
}

export const DEFAULT_ZAP_CONFIG: ZapConfig = {
  baseUrl: process.env.ZAP_BASE_URL || "http://localhost:8080",
  apiKey: process.env.ZAP_API_KEY || "",
  spiderMaxDepth: 5,
  spiderMaxChildren: 20,
  activeScanPolicy: "Default Policy",
  requestDelayMs: 20,
  maxAlertsPerScan: 1000,
};

// ─── ZAP API Client ─────────────────────────────────────────────────────────

interface ZapApiResponse {
  [key: string]: any;
}

/**
 * ZAP API requests must go through ZAP as an HTTP proxy.
 * The request URL uses "http://zap/..." which ZAP intercepts as its API.
 * The proxy is ZAP_BASE_URL (e.g., http://159.223.152.190:8090).
 */
async function zapRequest(
  endpoint: string,
  params: Record<string, string> = {},
  config: ZapConfig = DEFAULT_ZAP_CONFIG
): Promise<ZapApiResponse> {
  // Build the ZAP API URL using the special "zap" hostname
  const apiUrl = new URL(`http://zap${endpoint}`);
  apiUrl.searchParams.set("apikey", config.apiKey);
  for (const [k, v] of Object.entries(params)) {
    apiUrl.searchParams.set(k, v);
  }

  // Use ZAP_BASE_URL as an HTTP proxy via http-proxy-agent
  // ZAP acts as an HTTP proxy; requests to "http://zap/..." are intercepted as API calls
  const agent = new HttpProxyAgent(config.baseUrl);

  const response = await new Promise<{ ok: boolean; status: number; statusText: string; json: () => any }>((resolve, reject) => {
    const http = require('http');
    const reqUrl = apiUrl.toString();
    const req = http.get(reqUrl, { agent, timeout: 30000 }, (res: any) => {
      let data = '';
      res.on('data', (chunk: string) => data += chunk);
      res.on('end', () => {
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          statusText: res.statusMessage || '',
          json: () => JSON.parse(data),
        });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('ZAP request timeout')); });
  });

  if (!response.ok) {
    throw new Error(`ZAP API error: ${response.status} ${response.statusText} at ${endpoint}`);
  }

  return response.json();
}

// ─── Severity & Confidence Mapping ──────────────────────────────────────────

type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

function mapZapRisk(risk: string): SeverityLevel {
  const riskLower = (risk || "").toLowerCase();
  if (riskLower === "high") return "high";
  if (riskLower === "medium") return "medium";
  if (riskLower === "low") return "low";
  if (riskLower === "informational" || riskLower === "info") return "info";
  return "medium";
}

function mapZapConfidence(confidence: string): number {
  const c = (confidence || "").toLowerCase();
  if (c === "high" || c === "confirmed") return 0.9;
  if (c === "medium") return 0.7;
  if (c === "low") return 0.4;
  if (c === "false positive") return 0.1;
  return 0.5;
}

// ─── MITRE ATT&CK Web Vulnerability Mapping ────────────────────────────────

interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
}

/**
 * Comprehensive CWE → MITRE ATT&CK mapping for web vulnerabilities.
 * Maps ZAP CWE IDs and alert names to ATT&CK techniques.
 */
const CWE_TO_MITRE: Record<number, MitreMapping> = {
  // SQL Injection family
  89: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  564: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  // XSS family
  79: { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  80: { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  // Command Injection
  78: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  77: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  // Path Traversal / LFI
  22: { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
  98: { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
  // SSRF
  918: { techniqueId: "T1090", techniqueName: "Proxy", tactic: "Command and Control" },
  // XXE
  611: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  // Authentication issues
  287: { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  384: { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  613: { techniqueId: "T1539", techniqueName: "Steal Web Session Cookie", tactic: "Credential Access" },
  // Information Disclosure
  200: { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
  209: { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
  // CORS / Headers
  942: { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  // CSRF
  352: { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
  // Deserialization
  502: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  // File Upload
  434: { techniqueId: "T1105", techniqueName: "Ingress Tool Transfer", tactic: "Command and Control" },
  // LDAP Injection
  90: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  // SSTI
  1336: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  // Weak Crypto
  327: { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  328: { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  // Open Redirect
  601: { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  // IDOR
  639: { techniqueId: "T1530", techniqueName: "Data from Cloud Storage Object", tactic: "Collection" },
};

const ALERT_NAME_TO_MITRE: Record<string, MitreMapping> = {
  "SQL Injection": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Cross Site Scripting": { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  "Remote Code Execution": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "Remote OS Command Injection": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "Path Traversal": { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
  "Server Side Request Forgery": { techniqueId: "T1090", techniqueName: "Proxy", tactic: "Command and Control" },
  "XML External Entity": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "LDAP Injection": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Session Fixation": { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  "CORS Misconfiguration": { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  "Missing Anti-CSRF Tokens": { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
  "Insecure HTTP Method": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Directory Browsing": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  "Source Code Disclosure": { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
  "Cookie Without Secure Flag": { techniqueId: "T1539", techniqueName: "Steal Web Session Cookie", tactic: "Credential Access" },
  "Content Security Policy": { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  "X-Frame-Options Header Not Set": { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
};

/**
 * Map a ZAP finding to MITRE ATT&CK technique.
 */
export function mapToMitre(cweId: number | null, alertName: string): MitreMapping | null {
  if (cweId && CWE_TO_MITRE[cweId]) return CWE_TO_MITRE[cweId];
  
  for (const [pattern, mapping] of Object.entries(ALERT_NAME_TO_MITRE)) {
    if (alertName.toLowerCase().includes(pattern.toLowerCase())) return mapping;
  }
  
  return null;
}

// ─── Metasploit Module Correlation ──────────────────────────────────────────

/**
 * Maps CWE IDs to known Metasploit exploit module paths for attack chain handoff.
 */
const CWE_TO_MSF_MODULES: Record<number, string[]> = {
  89: ["exploit/multi/http/sqli_generic", "auxiliary/sqli/oracle/dbms_xmlquery_getxml"],
  78: ["exploit/multi/http/oscommand_generic", "exploit/unix/webapp/php_eval"],
  22: ["exploit/multi/http/lfi_generic", "auxiliary/scanner/http/dir_traversal"],
  98: ["exploit/multi/http/rfi_generic", "exploit/unix/webapp/php_include"],
  611: ["exploit/multi/http/xxe_generic", "auxiliary/scanner/http/xxe"],
  434: ["exploit/multi/http/upload_exec", "exploit/multi/http/webshell_upload"],
  502: ["exploit/multi/http/deserialization", "exploit/multi/misc/java_rmi_server"],
  918: ["auxiliary/scanner/http/ssrf_detector"],
  90: ["auxiliary/gather/ldap_query"],
};

/**
 * Find Metasploit modules that can exploit a given CWE.
 */
export function findMsfModules(cweId: number | null): string[] {
  if (!cweId) return [];
  return CWE_TO_MSF_MODULES[cweId] || [];
}

// ─── ZAP Alert Interface ────────────────────────────────────────────────────

interface ZapAlert {
  id: string;
  pluginId: string;
  alert: string;
  name: string;
  risk: string;
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  url: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
  other: string;
  tags: Record<string, string>;
}

// ─── LLM-Powered ZAP Orchestrator ──────────────────────────────────────────

/**
 * Comprehensive ZAP knowledge base system prompt for the LLM orchestrator.
 * This teaches the LLM about every ZAP feature so it can intelligently configure scans.
 */
const ZAP_ORCHESTRATOR_SYSTEM_PROMPT = `You are an expert OWASP ZAP scan orchestrator for the Ace C3 offensive security platform. You configure optimal scans based on the target's discovered technology stack. Your goal is to gain a foothold on the server by finding exploitable vulnerabilities, leaked secrets, exposed backend storage, and API credentials.

## ZAP API Categories You Can Configure:
1. **spider** — Traditional crawler: maxDepth (1-10), maxChildren (0-100), threadCount (1-20), handleParameters, parseComments, parseGit, parseSVNEntries, parseRobotsTxt, parseSitemapXml, postForm, processForm, acceptCookies, sendRefererHeader
2. **ajaxSpider** — JavaScript-heavy app crawler: browserType (firefox/chrome/htmlunit), maxCrawlDepth (0-10), maxCrawlStates (0-1000000), maxDuration (0-60 min), numberOfBrowsers (1-4), clickDefaultElems, clickElemsOnce, eventWait (ms), randomInputs
3. **ascan** (Active Scanner) — Vulnerability testing: scanPolicy, threadPerHost (1-20), delayInMs (0-5000), handleAntiCSRFTokens, injectPluginIdInHeader, scanHeadersAllRequests, maxRuleDurationInMins, maxScanDurationInMins
4. **pscan** (Passive Scanner) — Non-intrusive analysis: enableAllScanners, maxAlertsPerRule, scanOnlyInScope
5. **authentication** — Login handling: formBased, jsonBased, httpAuth, scriptBased
6. **context** — Scope management: includeInContext, excludeFromContext, technologyList
7. **script** — Custom attack scripts
8. **forcedUser** — Authenticated scanning
9. **openapi/graphql/soap** — Import API specs

## CRITICAL: ZAP Scan Rule IDs by Technology
You MUST reference these exact rule IDs in your customRules array to enable/disable specific checks.

### Universal Foothold Rules (ALWAYS enable for active scans):
- 40012: XSS Reflected | 40014: XSS Persistent | 40016: XSS Persistent (Prime)
- 40018: SQL Injection | 40019: SQL Injection (MySQL) | 40020: SQL Injection (Hypersonic) | 40021: SQL Injection (Oracle) | 40022: SQL Injection (PostgreSQL) | 40024: SQL Injection (SQLite) | 40027: SQL Injection (MsSQL)
- 90019: Server Side Code Injection (eval/exec) | 90020: Remote OS Command Injection
- 40003: CRLF Injection | 6: Path Traversal | 7: Remote File Inclusion
- 40032: .htaccess Info Leak | 40034: .env Info Leak | 40035: Hidden File Finder
- 10095: Backup File Disclosure | 10048: Spring Actuator Info Leak
- 90034: Cloud Metadata Potentially Exposed (AWS/GCP/Azure IMDS)
- 40042: Spring4Shell (CVE-2022-22965) | 40043: Log4Shell (CVE-2021-44228)
- 40045: Spring Actuator Test | 90021: XPath Injection | 90023: XML External Entity Attack
- 40009: Server Side Include | 40008: Parameter Tampering | 40013: Session ID in URL Rewrite

### Secrets & Backend Storage Discovery Rules:
- 40034: .env Information Leak (DB creds, API keys, S3 secrets)
- 40032: .htaccess Information Leak (rewrite rules, auth configs)
- 40035: Hidden File Finder (backup files, config dumps, .git)
- 10095: Backup File Disclosure (*.bak, *.old, *.orig, *.save)
- 90034: Cloud Metadata (AWS IMDS → IAM creds → S3 bucket access)
- 10048: Spring Actuator (env endpoint → DB/S3/API credentials)
- 10045: Source Code Disclosure (WEB-INF/web.xml, .svn, .git)
- 41: Source Code Disclosure (SVN) | 42: Source Code Disclosure (Git) | 43: Source Code Disclosure (File Inclusion)
- 0: Directory Browsing (find exposed /uploads, /backups, /storage)

### Technology-Specific Rules:
**PHP**: 90019 (Code Injection via eval), 7 (Remote File Include), 6 (Path Traversal/LFI), 40034 (.env), 30001 (Buffer Overflow), 40003 (CRLF)
**Java/Spring**: 40042 (Spring4Shell), 40043 (Log4Shell), 40045 (Spring Actuator), 10048 (Actuator Info), 90019 (EL Injection), 90023 (XXE), 40029 (TRACE)
**Python/Django/Flask**: 90019 (SSTI Jinja2), 40018 (SQLi), 90020 (Command Injection), 40034 (.env), 6 (Path Traversal)
**Node.js/Express**: 40018 (NoSQL Injection via SQLi scanner), 90019 (Prototype Pollution via code injection), 40034 (.env), 40028 (ELMAH Info Leak)
**ASP.NET**: 40029 (TRACE), 40032 (.htaccess/web.config), 10095 (Backup), 90019 (ViewState deserialization), 40034 (.env)
**WordPress**: 40034 (.env), 40035 (Hidden Files: wp-config.php.bak), 10095 (Backup), 0 (Directory Browsing /wp-content/uploads)
**Ruby/Rails**: 90019 (SSTI ERB), 40018 (SQLi), 90020 (Command Injection), 40034 (.env), 10095 (Backup database.yml)
**API (REST/GraphQL)**: 40018 (Injection), 40003 (CRLF), 40008 (Parameter Tampering), 90020 (Command Injection), 40013 (Session in URL)

### Injection Testing for Foothold (prioritize HIGH strength):
- SQL Injection: 40018, 40019, 40020, 40021, 40022, 40024, 40027 → leads to DB dump, credential theft, or OS command via xp_cmdshell/INTO OUTFILE
- Command Injection: 90020 → direct RCE
- Code Injection: 90019 → eval/exec → RCE
- SSTI: 90019 → template engine RCE (Jinja2, Twig, Freemarker, ERB)
- File Include: 7 (RFI → webshell), 6 (LFI → /etc/passwd, source code)
- XXE: 90023 → file read, SSRF, potential RCE
- File Upload: test via parameter tampering (40008) + hidden file discovery (40035)

## Scan Policies:
- **Default Policy**: All rules enabled at default thresholds
- **Heavy/Thorough**: Maximum coverage — set all injection rules to HIGH strength/INSANE threshold
- **API-Focused**: No UI-related checks — for REST/GraphQL APIs

## Authentication Strategies:
- **Form login**: formBased auth with logged-in/logged-out indicators
- **JWT/Bearer token**: script-based auth to inject Authorization header
- **OAuth2**: browser-based or script to complete OAuth flow
- **API key**: replacer rule to inject API key header

## Output Format:
Return a JSON object with these fields:
{
  "scanPolicy": "Default Policy" | "Heavy" | "API",
  "useAjaxSpider": boolean,
  "spiderConfig": { maxDepth, maxChildren, threadCount, parseComments, parseGit, parseSitemapXml, postForm },
  "ajaxSpiderConfig": { maxCrawlDepth, maxCrawlStates, maxDuration, numberOfBrowsers, clickDefaultElems },
  "activeScanConfig": { threadPerHost, delayInMs, handleAntiCSRFTokens, scanHeadersAllRequests, maxRuleDurationInMins },
  "technologies": ["Java", "Spring", ...],
  "authStrategy": "none" | "form" | "json" | "bearer" | "apikey" | "oauth2",
  "authConfig": { ... },
  "contextIncludes": ["regex patterns"],
  "contextExcludes": ["regex patterns for logout, static assets"],
  "importSpec": null | { type: "openapi" | "graphql" | "soap", url: "spec URL" },
  "customRules": ["enable:40018:HIGH:INSANE", "enable:90019:HIGH:INSANE", "enable:40034:MEDIUM:DEFAULT", ...],
  "rationale": "Brief explanation including which foothold vectors are prioritized and why"
}

## IMPORTANT:
- customRules format: "enable:<ruleId>:<strength>:<threshold>" or "disable:<ruleId>"
- Strength: OFF, DEFAULT, LOW, MEDIUM, HIGH, INSANE
- Threshold: OFF, DEFAULT, LOW, MEDIUM, HIGH
- For foothold acquisition: set all injection rules to HIGH strength, INSANE threshold
- For secrets discovery: enable 40034, 40032, 40035, 10095, 90034, 10048 at MEDIUM strength
- ALWAYS include technology-specific rules based on detected stack
- ALWAYS include secrets/storage discovery rules regardless of technology`;

export interface LLMScanConfig {
  scanPolicy: string;
  useAjaxSpider: boolean;
  spiderConfig: {
    maxDepth: number;
    maxChildren: number;
    threadCount: number;
    parseComments: boolean;
    parseGit: boolean;
    parseSitemapXml: boolean;
    postForm: boolean;
  };
  ajaxSpiderConfig: {
    maxCrawlDepth: number;
    maxCrawlStates: number;
    maxDuration: number;
    numberOfBrowsers: number;
    clickDefaultElems: boolean;
  };
  activeScanConfig: {
    threadPerHost: number;
    delayInMs: number;
    handleAntiCSRFTokens: boolean;
    scanHeadersAllRequests: boolean;
    maxRuleDurationInMins: number;
  };
  technologies: string[];
  authStrategy: string;
  authConfig: Record<string, any>;
  contextIncludes: string[];
  contextExcludes: string[];
  importSpec: { type: string; url: string } | null;
  customRules: string[];
  rationale: string;
}

/**
 * Use LLM to analyze a target URL and generate optimal ZAP scan configuration.
 */
export async function generateLLMScanConfig(params: {
  targetUrl: string;
  scanMode: "passive" | "active";
  techStackHints?: string[];
  authHints?: { type: string; loginUrl?: string; credentials?: Record<string, string> };
  scopeConstraints?: string[];
}): Promise<LLMScanConfig> {
  // Build dynamic ZAP knowledge context based on tech hints
  const techKnowledge = params.techStackHints?.length
    ? getTechScanPolicyContext(params.techStackHints[0])
    : '';
  const authKnowledge = params.authHints
    ? getZAPAuthContext(params.authHints.type)
    : '';
  const alertKnowledge = params.scanMode === 'active'
    ? getZAPAlertCatalogContext('high')
    : '';

  const dynamicKnowledge = [techKnowledge, authKnowledge, alertKnowledge].filter(Boolean).join('\n\n');

  const userPrompt = `Analyze this target and generate optimal ZAP scan configuration:

**Target URL**: ${params.targetUrl}
**Scan Mode**: ${params.scanMode} (${params.scanMode === "passive" ? "spider + passive scan only, NO active attacks" : "full active DAST with vulnerability exploitation"})
${params.techStackHints?.length ? `**Known Technologies**: ${params.techStackHints.join(", ")}` : "**Known Technologies**: Unknown — detect from response headers and content"}
${params.authHints ? `**Authentication**: Type=${params.authHints.type}, Login URL=${params.authHints.loginUrl || "unknown"}` : "**Authentication**: None configured"}
${params.scopeConstraints?.length ? `**Scope Constraints**: ${params.scopeConstraints.join(", ")}` : ""}

${params.scanMode === "passive" ? "Configure for maximum URL discovery and passive vulnerability detection WITHOUT any active attacks. Focus on spider depth, technology fingerprinting, and passive scan rules." : "Configure for thorough active vulnerability testing. Enable all relevant attack categories. Optimize for the detected technology stack."}
${dynamicKnowledge ? '\n\n## ZAP Knowledge Base Reference\n' + dynamicKnowledge : ''}`;

  try {
    const { retryWithBackoff, isRetryableError } = await import("./api-resilience");
    const response = await retryWithBackoff(
      () => invokeLLM({
        messages: [
          { role: "system", content: ZAP_ORCHESTRATOR_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "zap_scan_config",
            strict: true,
            schema: {
            type: "object",
            properties: {
              scanPolicy: { type: "string" },
              useAjaxSpider: { type: "boolean" },
              spiderConfig: {
                type: "object",
                properties: {
                  maxDepth: { type: "number" },
                  maxChildren: { type: "number" },
                  threadCount: { type: "number" },
                  parseComments: { type: "boolean" },
                  parseGit: { type: "boolean" },
                  parseSitemapXml: { type: "boolean" },
                  postForm: { type: "boolean" },
                },
                required: ["maxDepth", "maxChildren", "threadCount", "parseComments", "parseGit", "parseSitemapXml", "postForm"],
                additionalProperties: false,
              },
              ajaxSpiderConfig: {
                type: "object",
                properties: {
                  maxCrawlDepth: { type: "number" },
                  maxCrawlStates: { type: "number" },
                  maxDuration: { type: "number" },
                  numberOfBrowsers: { type: "number" },
                  clickDefaultElems: { type: "boolean" },
                },
                required: ["maxCrawlDepth", "maxCrawlStates", "maxDuration", "numberOfBrowsers", "clickDefaultElems"],
                additionalProperties: false,
              },
              activeScanConfig: {
                type: "object",
                properties: {
                  threadPerHost: { type: "number" },
                  delayInMs: { type: "number" },
                  handleAntiCSRFTokens: { type: "boolean" },
                  scanHeadersAllRequests: { type: "boolean" },
                  maxRuleDurationInMins: { type: "number" },
                },
                required: ["threadPerHost", "delayInMs", "handleAntiCSRFTokens", "scanHeadersAllRequests", "maxRuleDurationInMins"],
                additionalProperties: false,
              },
              technologies: { type: "array", items: { type: "string" } },
              authStrategy: { type: "string" },
              authConfig: { type: "object", additionalProperties: true },
              contextIncludes: { type: "array", items: { type: "string" } },
              contextExcludes: { type: "array", items: { type: "string" } },
              importSpec: {
                anyOf: [
                  { type: "null" },
                  {
                    type: "object",
                    properties: {
                      type: { type: "string" },
                      url: { type: "string" },
                    },
                    required: ["type", "url"],
                    additionalProperties: false,
                  },
                ],
              },
              customRules: { type: "array", items: { type: "string" } },
              rationale: { type: "string" },
            },
            required: ["scanPolicy", "useAjaxSpider", "spiderConfig", "ajaxSpiderConfig", "activeScanConfig", "technologies", "authStrategy", "authConfig", "contextIncludes", "contextExcludes", "importSpec", "customRules", "rationale"],
            additionalProperties: false,
          },
        },
      },
    }),
      { maxRetries: 3, baseDelayMs: 2000, retryableCheck: isRetryableError }
    );

    const content = response.choices?.[0]?.message?.content;
    if (typeof content === "string") {
      return JSON.parse(content) as LLMScanConfig;
    }
    throw new Error("LLM returned non-string content");
  } catch (err: any) {
    console.error(`[ZAP LLM Orchestrator] Failed to generate config after retries: ${err.message}`);
    console.log(`[ZAP LLM Orchestrator] Using knowledge-driven fallback for tech hints: [${params.techStackHints?.join(', ') || 'none'}], target: ${params.targetUrl}`);
    return getDefaultScanConfig(params.scanMode, params.techStackHints, undefined, params.targetUrl);
  }
}

/**
 * Smart knowledge-driven fallback when LLM is unavailable.
 * Uses TECH_SCAN_POLICIES from the ZAP knowledge module to generate
 * technology-specific scan configs instead of generic defaults.
 */
function getDefaultScanConfig(
  mode: "passive" | "active",
  techStackHints?: string[],
  wafVendor?: string,
  targetUrl?: string,
): LLMScanConfig {
  // Try to match a tech-specific policy from the knowledge module
  let matchedPolicy: TechScanPolicy | undefined;

  // Build combined hints from tech stack + URL-based detection
  const allHints = [...(techStackHints || [])];
  if (targetUrl) {
    // URL extension detection
    if (targetUrl.includes('.php') || targetUrl.includes('php')) allHints.push('PHP');
    if (targetUrl.includes('.asp') || targetUrl.includes('.aspx')) allHints.push('ASP.NET');
    if (targetUrl.includes('.jsp') || targetUrl.includes('.do') || targetUrl.includes('.action')) allHints.push('Java');
    if (targetUrl.includes('wp-') || targetUrl.includes('wordpress')) allHints.push('WordPress');
    if (targetUrl.includes('/api/') || targetUrl.includes('/graphql')) allHints.push('API');
  }

  // Server header matching (nmap versions often contain server names)
  const serverPatterns: Record<string, string> = {
    'apache': 'PHP',       // Apache commonly serves PHP
    'nginx': 'PHP',        // nginx commonly serves PHP
    'iis': 'ASP.NET',
    'tomcat': 'Java/Spring',
    'jetty': 'Java/Spring',
    'express': 'Node.js/Express',
    'kestrel': 'ASP.NET',
    'gunicorn': 'Python/Django/Flask',
    'uwsgi': 'Python/Django/Flask',
    'werkzeug': 'Python/Django/Flask',
    'wordpress': 'WordPress',
    'wp-': 'WordPress',
    'php': 'PHP',
  };

  for (const hint of allHints) {
    const lowerHint = hint.toLowerCase();
    // Direct policy match
    matchedPolicy = TECH_SCAN_POLICIES.find(p =>
      p.technology.toLowerCase().includes(lowerHint) ||
      p.fingerprints.some(f => f.toLowerCase().includes(lowerHint)) ||
      lowerHint.includes(p.technology.split('/')[0].toLowerCase())
    );
    if (matchedPolicy) break;

    // Server header pattern match
    for (const [pattern, tech] of Object.entries(serverPatterns)) {
      if (lowerHint.includes(pattern)) {
        matchedPolicy = TECH_SCAN_POLICIES.find(p => p.technology === tech);
        if (matchedPolicy) break;
      }
    }
    if (matchedPolicy) break;
  }

  console.log(`[ZAP Smart Fallback] Hints: [${allHints.join(', ')}], Matched: ${matchedPolicy?.technology || 'none (using generic defaults)'}`);


  // Base config — use matched policy or generic defaults
  const baseConfig: LLMScanConfig = {
    scanPolicy: matchedPolicy ? `Knowledge-${matchedPolicy.technology}` : "Default Policy",
    useAjaxSpider: matchedPolicy?.useAjaxSpider ?? false,
    spiderConfig: {
      maxDepth: mode === "passive" ? 5 : 8,
      maxChildren: mode === "passive" ? 20 : 50,
      threadCount: 5,
      parseComments: matchedPolicy?.spiderConfig?.parseComments ?? true,
      parseGit: matchedPolicy?.spiderConfig?.parseGit ?? true,
      parseSitemapXml: true,
      postForm: matchedPolicy?.spiderConfig?.postForm ?? (mode === "active"),
    },
    ajaxSpiderConfig: {
      maxCrawlDepth: 5,
      maxCrawlStates: 10000,
      maxDuration: 10,
      numberOfBrowsers: 2,
      clickDefaultElems: true,
    },
    activeScanConfig: {
      threadPerHost: 5,
      delayInMs: 20,
      handleAntiCSRFTokens: true,
      scanHeadersAllRequests: true,
      maxRuleDurationInMins: 10,
    },
    technologies: matchedPolicy ? [matchedPolicy.technology] : [],
    authStrategy: "none",
    authConfig: {},
    contextIncludes: [],
    contextExcludes: matchedPolicy?.contextExcludes || [".*\\.(js|css|png|jpg|gif|svg|ico|woff|woff2|ttf|eot)$"],
    importSpec: null,
    customRules: matchedPolicy
      ? matchedPolicy.criticalRules.map(r => `Rule ${r.id}: ${r.strength}/${r.threshold} — ${r.reason}`)
      : [],
    rationale: matchedPolicy
      ? `Knowledge-driven config: ${matchedPolicy.technology} policy applied (${matchedPolicy.criticalRules.length} critical rules). Tech-specific scan profile selected automatically.`
      : "Balanced scan configuration applied. Technology-specific tuning will be applied when LLM analysis completes.",
  };

  // Apply WAF evasion overrides if WAF detected
  if (wafVendor) {
    return applyWafEvasionConfig(baseConfig, wafVendor);
  }

  return baseConfig;
}

// ─── WAF Evasion Configuration ─────────────────────────────────────────────

/**
 * WAF-specific scan parameter overrides.
 * Adjusts rate limiting, threading, spider behavior, and scan timing
 * to maximize coverage while minimizing WAF block rate.
 */
interface WafEvasionProfile {
  name: string;
  /** Max requests per second (lower = less likely to trigger WAF) */
  maxReqPerSec: number;
  delayInMs: number;
  threadPerHost: number;
  spiderThreads: number;
  maxRuleDurationInMins: number;
  useAjaxSpider: boolean;
  /** Additional User-Agent rotation headers */
  rotateUserAgents: boolean;
  /** Use encoded payloads to bypass signature detection */
  encodePayloads: boolean;
  /** Specific bypass techniques */
  techniques: string[];
}

const WAF_EVASION_PROFILES: Record<string, WafEvasionProfile> = {
  "Cloudflare": {
    name: "Cloudflare Evasion",
    maxReqPerSec: 2,
    delayInMs: 500,
    threadPerHost: 1,
    spiderThreads: 2,
    maxRuleDurationInMins: 20,
    useAjaxSpider: false,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Rate limit to 2 req/sec to avoid Cloudflare rate-based rules",
      "Rotate User-Agent between Chrome, Firefox, Safari, Edge variants",
      "Use double URL encoding for injection payloads",
      "Avoid common scanner signatures in spider requests",
      "Set Referer header to target domain on all requests",
      "Add Accept-Language and Accept-Encoding headers for browser mimicry",
    ],
  },
  "AWS WAF": {
    name: "AWS WAF Evasion",
    maxReqPerSec: 5,
    delayInMs: 200,
    threadPerHost: 2,
    spiderThreads: 3,
    maxRuleDurationInMins: 15,
    useAjaxSpider: false,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Vary HTTP methods (GET/POST/PUT) to avoid method-based rules",
      "Use Unicode normalization for injection payloads",
      "Test with different Content-Type headers (form, json, xml)",
      "Fragment payloads across multiple parameters",
    ],
  },
  "Akamai": {
    name: "Akamai Evasion",
    maxReqPerSec: 1,
    delayInMs: 1000,
    threadPerHost: 1,
    spiderThreads: 1,
    maxRuleDurationInMins: 25,
    useAjaxSpider: false,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Very slow scan rate (1 req/sec) — Akamai has aggressive behavioral detection",
      "Use custom User-Agent strings (not common scanner signatures)",
      "Fragment payloads across multiple parameters",
      "Avoid automated scanner fingerprints in headers",
    ],
  },
  "Imperva/Incapsula": {
    name: "Imperva Evasion",
    maxReqPerSec: 3,
    delayInMs: 350,
    threadPerHost: 1,
    spiderThreads: 2,
    maxRuleDurationInMins: 20,
    useAjaxSpider: true,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Handle Incapsula JavaScript challenges (use AJAX spider)",
      "Implement cookie handling for challenge responses",
      "Use browser-like request patterns with full header sets",
      "Solve JavaScript challenges before active scanning",
    ],
  },
  "ModSecurity": {
    name: "ModSecurity Evasion",
    maxReqPerSec: 5,
    delayInMs: 200,
    threadPerHost: 2,
    spiderThreads: 3,
    maxRuleDurationInMins: 15,
    useAjaxSpider: false,
    rotateUserAgents: false,
    encodePayloads: true,
    techniques: [
      "Identify CRS paranoia level via incremental payload testing",
      "Use Unicode normalization bypasses for SQL keywords",
      "Test with different character encodings (UTF-8, UTF-16, ISO-8859-1)",
      "Check for rule exclusion via specific paths or parameters",
      "Use case variation in SQL/XSS keywords",
    ],
  },
  "F5 BIG-IP ASM": {
    name: "F5 BIG-IP Evasion",
    maxReqPerSec: 3,
    delayInMs: 350,
    threadPerHost: 2,
    spiderThreads: 2,
    maxRuleDurationInMins: 15,
    useAjaxSpider: false,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Test HTTP parameter pollution techniques",
      "Use HTTP method override headers (X-HTTP-Method-Override)",
      "Try alternative encoding schemes (hex, octal, base64)",
      "Check for bypass via HTTP/2 protocol",
    ],
  },
};

/**
 * Get the WAF evasion profile for a detected WAF vendor.
 * Falls back to a conservative generic profile for unknown WAFs.
 */
export function getWafEvasionProfile(wafVendor: string): WafEvasionProfile {
  // Exact match first
  if (WAF_EVASION_PROFILES[wafVendor]) return WAF_EVASION_PROFILES[wafVendor];
  // Fuzzy match
  const key = Object.keys(WAF_EVASION_PROFILES).find(k =>
    k.toLowerCase().includes(wafVendor.toLowerCase()) ||
    wafVendor.toLowerCase().includes(k.toLowerCase())
  );
  if (key) return WAF_EVASION_PROFILES[key];
  // Generic conservative profile for unknown WAFs
  return {
    name: `Generic WAF Evasion (${wafVendor})`,
    maxReqPerSec: 2,
    delayInMs: 500,
    threadPerHost: 1,
    spiderThreads: 2,
    maxRuleDurationInMins: 20,
    useAjaxSpider: false,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Use slower scan rate to avoid rate-based blocking",
      "Rotate User-Agent headers between browser variants",
      "Use encoded payloads for injection tests",
      "Avoid common attack signatures in URLs",
    ],
  };
}

/**
 * Apply WAF evasion overrides to a scan config.
 * Reduces threading, increases delays, and adds evasion techniques.
 */
export function applyWafEvasionConfig(config: LLMScanConfig, wafVendor: string): LLMScanConfig {
  const profile = getWafEvasionProfile(wafVendor);
  console.log(`[ZAP WAF Evasion] Applying ${profile.name}: ${profile.delayInMs}ms delay, ${profile.threadPerHost} threads, ${profile.techniques.length} techniques`);

  return {
    ...config,
    useAjaxSpider: profile.useAjaxSpider || config.useAjaxSpider,
    spiderConfig: {
      ...config.spiderConfig,
      threadCount: Math.min(config.spiderConfig.threadCount, profile.spiderThreads),
    },
    activeScanConfig: {
      ...config.activeScanConfig,
      threadPerHost: profile.threadPerHost,
      delayInMs: profile.delayInMs,
      maxRuleDurationInMins: profile.maxRuleDurationInMins,
    },
    customRules: [
      ...config.customRules,
      `WAF_EVASION: ${profile.name}`,
      ...profile.techniques,
    ],
    rationale: `${config.rationale} | WAF Evasion: ${profile.name} applied — ${profile.delayInMs}ms delay, ${profile.threadPerHost} thread(s), ${profile.techniques.length} bypass techniques.`,
  };
}

// ─── AI-Powered Finding Triage ──────────────────────────────────────────────

export interface TriageResult {
  verdict: "true_positive" | "likely_positive" | "needs_review" | "likely_false_positive" | "false_positive";
  reason: string;
  falsePositiveScore: number;
}

/**
 * Use LLM to triage a finding and assess false positive likelihood.
 */
export async function triageFinding(finding: {
  alertName: string;
  severity: string;
  url: string;
  param?: string;
  evidence?: string;
  description?: string;
  cweId?: number;
  targetTechStack?: string[];
}): Promise<TriageResult> {
  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: `You are a web application security expert performing triage on OWASP ZAP scan findings. Assess each finding for false positive likelihood based on the evidence, URL context, parameter name, and technology stack. Consider common ZAP false positive patterns:
- Generic XSS alerts on static content or JSON responses
- SQL injection alerts on non-database parameters (search terms, pagination)
- CSRF alerts on GET requests or public endpoints
- Missing header alerts that may be handled by CDN/proxy
- Path traversal alerts that return 404 or generic error pages

Return JSON with: verdict (true_positive|likely_positive|needs_review|likely_false_positive|false_positive), reason (brief explanation), falsePositiveScore (0.0=definitely real, 1.0=definitely FP).`,
        },
        {
          role: "user",
          content: `Triage this finding:
Alert: ${finding.alertName}
Severity: ${finding.severity}
URL: ${finding.url}
Parameter: ${finding.param || "N/A"}
Evidence: ${(finding.evidence || "").substring(0, 500)}
CWE: ${finding.cweId || "N/A"}
Tech Stack: ${finding.targetTechStack?.join(", ") || "Unknown"}`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "triage_result",
          strict: true,
          schema: {
            type: "object",
            properties: {
              verdict: { type: "string", enum: ["true_positive", "likely_positive", "needs_review", "likely_false_positive", "false_positive"] },
              reason: { type: "string" },
              falsePositiveScore: { type: "number" },
            },
            required: ["verdict", "reason", "falsePositiveScore"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (typeof content === "string") {
      return JSON.parse(content) as TriageResult;
    }
    throw new Error("LLM returned non-string content");
  } catch (err: any) {
    return {
      verdict: "needs_review",
      reason: `AI triage unavailable: ${err.message}`,
      falsePositiveScore: 0.5,
    };
  }
}

// ─── Scan Lifecycle Functions ───────────────────────────────────────────────

/**
 * Check if ZAP is reachable and return version info.
 */
export async function checkZapHealth(config?: Partial<ZapConfig>): Promise<{
  available: boolean;
  version?: string;
  error?: string;
}> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };
  try {
    const result = await zapRequest("/JSON/core/view/version/", {}, cfg);
    return { available: true, version: result.version };
  } catch (err: any) {
    return { available: false, error: err.message };
  }
}

// ─── OpenAPI / GraphQL / SOAP Spec Import ──────────────────────────────────

/**
 * Import an OpenAPI/Swagger specification into ZAP for targeted API testing.
 * ZAP will parse the spec and add all endpoints to the sites tree for scanning.
 *
 * Supports OpenAPI 2.0 (Swagger), OpenAPI 3.0, and OpenAPI 3.1.
 * The spec can be provided as a URL or raw content.
 */
export async function importOpenApiSpec(params: {
  specUrl?: string;
  specContent?: string;
  targetUrl?: string;
  contextId?: string;
  config?: Partial<ZapConfig>;
}): Promise<{ success: boolean; endpointsImported: number; errors: string[] }> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const errors: string[] = [];

  try {
    const reqParams: Record<string, string> = {};

    if (params.specUrl) {
      reqParams.url = params.specUrl;
    } else if (params.specContent) {
      reqParams.file = params.specContent;
    } else {
      return { success: false, endpointsImported: 0, errors: ["Either specUrl or specContent is required"] };
    }

    if (params.targetUrl) {
      reqParams.hostOverride = params.targetUrl;
    }
    if (params.contextId) {
      reqParams.contextId = params.contextId;
    }

    const result = await zapRequest("/JSON/openapi/action/importUrl/", reqParams, cfg);

    // Get the number of URLs added to the sites tree
    const sitesResult = await zapRequest("/JSON/core/view/urls/", {}, cfg).catch(() => ({ urls: [] }));
    const endpointsImported = (sitesResult.urls || []).length;

    return { success: true, endpointsImported, errors };
  } catch (err: any) {
    errors.push(`OpenAPI import failed: ${err.message}`);
    return { success: false, endpointsImported: 0, errors };
  }
}

/**
 * Import a GraphQL schema/endpoint into ZAP for targeted GraphQL API testing.
 * ZAP will perform introspection on the endpoint and add all queries/mutations.
 *
 * Supports:
 * - GraphQL introspection endpoint URL (ZAP auto-discovers the schema)
 * - Raw GraphQL SDL schema content
 */
export async function importGraphQLSpec(params: {
  endpointUrl?: string;
  schemaUrl?: string;
  schemaContent?: string;
  targetUrl?: string;
  maxQueryDepth?: number;
  config?: Partial<ZapConfig>;
}): Promise<{ success: boolean; queriesImported: number; mutationsImported: number; errors: string[] }> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const errors: string[] = [];

  try {
    const reqParams: Record<string, string> = {};

    if (params.endpointUrl) {
      reqParams.endurl = params.endpointUrl;
    }
    if (params.schemaUrl) {
      reqParams.schemaUrl = params.schemaUrl;
    } else if (params.schemaContent) {
      reqParams.schemaFile = params.schemaContent;
    }
    if (params.targetUrl) {
      reqParams.url = params.targetUrl;
    }
    if (params.maxQueryDepth) {
      // Set max query depth for introspection
      await zapRequest("/JSON/graphql/action/setOptionMaxQueryDepth/", {
        Integer: String(params.maxQueryDepth),
      }, cfg).catch(() => {});
    }

    // Enable optional arguments for more thorough testing
    await zapRequest("/JSON/graphql/action/setOptionOptionalArgsEnabled/", {
      Boolean: "true",
    }, cfg).catch(() => {});

    const result = await zapRequest("/JSON/graphql/action/importUrl/", reqParams, cfg);

    // Estimate queries/mutations from sites tree
    const sitesResult = await zapRequest("/JSON/core/view/urls/", {}, cfg).catch(() => ({ urls: [] }));
    const graphqlUrls = (sitesResult.urls || []).filter((u: string) => u.includes("graphql"));

    return {
      success: true,
      queriesImported: Math.max(graphqlUrls.length, 1),
      mutationsImported: 0,
      errors,
    };
  } catch (err: any) {
    errors.push(`GraphQL import failed: ${err.message}`);
    return { success: false, queriesImported: 0, mutationsImported: 0, errors };
  }
}

/**
 * Import a SOAP/WSDL specification into ZAP for SOAP API testing.
 */
export async function importSoapSpec(params: {
  wsdlUrl?: string;
  wsdlContent?: string;
  config?: Partial<ZapConfig>;
}): Promise<{ success: boolean; operationsImported: number; errors: string[] }> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const errors: string[] = [];

  try {
    const reqParams: Record<string, string> = {};

    if (params.wsdlUrl) {
      reqParams.url = params.wsdlUrl;
    } else if (params.wsdlContent) {
      reqParams.file = params.wsdlContent;
    } else {
      return { success: false, operationsImported: 0, errors: ["Either wsdlUrl or wsdlContent is required"] };
    }

    const result = await zapRequest("/JSON/soap/action/importUrl/", reqParams, cfg);

    return { success: true, operationsImported: 1, errors };
  } catch (err: any) {
    errors.push(`SOAP import failed: ${err.message}`);
    return { success: false, operationsImported: 0, errors };
  }
}

/**
 * Start a dual-mode web application scan.
 * 
 * PASSIVE mode: Spider + passive scan only (safe for domain recon)
 * ACTIVE mode: Spider + active DAST scan (coordinated with attack chains)
 */
export async function startScan(params: {
  targetUrl: string;
  scanType: "spider_only" | "active" | "full";
  scanMode: "passive" | "active";
  userId: string;
  scanName?: string;
  config?: Partial<ZapConfig>;
  llmConfig?: LLMScanConfig;
  attackChainId?: string;
  calderaOperationId?: string;
  metasploitSessionId?: string;
  domainIntelScanId?: number;
  openApiSpecUrl?: string;
  graphqlEndpointUrl?: string;
  graphqlSchemaUrl?: string;
  soapWsdlUrl?: string;
  /** Attack playbook phase — selects technology-tuned scan rules */
  playbookPhase?: PlaybookPhase;
  /** Discovered technologies from web crawler / fingerprinting */
  discoveredTechnologies?: string[];
}): Promise<{ scanId: number; spiderScanId?: string; status: string; llmConfig?: LLMScanConfig; specImportResult?: any; playbookApplied?: string }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };

  // Validate target URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(params.targetUrl);
  } catch {
    throw new Error(`Invalid target URL: ${params.targetUrl}`);
  }

  // ── Deduplication guard: skip if an identical scan already exists ──
  const effectiveScanName = params.scanName || `${params.scanMode === "passive" ? "[RECON]" : "[DAST]"} ${parsedUrl.hostname}`;
  const [existingScan] = await db.select({ id: webAppScans.id, status: webAppScans.status })
    .from(webAppScans)
    .where(and(
      eq(webAppScans.scanName, effectiveScanName),
      eq(webAppScans.targetUrl, params.targetUrl)
    ))
    .limit(1);
  if (existingScan) {
    console.log(`[ZAP Dedup] Scan already exists: ${effectiveScanName} → id=${existingScan.id} (status=${existingScan.status}). Returning existing.`);
    return { scanId: existingScan.id, status: existingScan.status, llmConfig: params.llmConfig, deduplicated: true } as any;
  }

  // Generate LLM scan config if not provided — enhanced with tech-specific rule intelligence
  const llmConfig = params.llmConfig || await generateLLMScanConfig({
    targetUrl: params.targetUrl,
    scanMode: params.scanMode,
    techStackHints: params.discoveredTechnologies,
  });

  // Select and apply attack playbook based on discovered technologies
  const technologies = params.discoveredTechnologies || llmConfig.technologies || [];
  const playbookPhase = params.playbookPhase || (params.scanMode === "active" ? "full" : "crawling");
  const playbook = selectPlaybook(playbookPhase, technologies, {
    useAjaxSpider: llmConfig.useAjaxSpider,
    apiSpec: params.openApiSpecUrl ? { type: "openapi", url: params.openApiSpecUrl }
      : params.graphqlEndpointUrl ? { type: "graphql", url: params.graphqlEndpointUrl }
      : params.soapWsdlUrl ? { type: "soap", url: params.soapWsdlUrl }
      : undefined,
  });
  console.log(`[ZAP Playbook] Selected: ${playbook.name} with ${playbook.enabledRules.length} rules for tech: [${technologies.join(", ")}]`);

  // Determine effective scan type based on mode
  const effectiveScanType = params.scanMode === "passive" ? "spider_only" : params.scanType;

  // Create scan record in DB
  const [result] = await db.insert(webAppScans).values({
    targetUrl: params.targetUrl,
    scanName: params.scanName || `${params.scanMode === "passive" ? "[RECON]" : "[DAST]"} ${parsedUrl.hostname}`,
    scanType: effectiveScanType,
    scanMode: params.scanMode,
    status: "starting",
    startedBy: params.userId,
    startedAt: new Date(),
    spiderProgress: 0,
    activeScanProgress: 0,
    alertCounts: JSON.stringify({ high: 0, medium: 0, low: 0, info: 0 }),
    llmScanConfig: JSON.stringify(llmConfig),
    scanPolicyName: llmConfig.scanPolicy,
    ajaxSpiderUsed: llmConfig.useAjaxSpider,
    detectedTechStack: JSON.stringify(llmConfig.technologies),
    attackChainId: params.attackChainId || null,
    calderaOperationId: params.calderaOperationId || null,
    metasploitSessionId: params.metasploitSessionId || null,
    domainIntelScanId: params.domainIntelScanId || null,
  });

  const scanId = result.insertId;

  try {
    // Import API specifications if provided (before spidering)
    let specImportResult: any = null;

    // Check for direct spec URL params first, then LLM config
    const specToImport = params.openApiSpecUrl
      ? { type: "openapi", url: params.openApiSpecUrl }
      : params.graphqlEndpointUrl || params.graphqlSchemaUrl
        ? { type: "graphql", url: params.graphqlEndpointUrl || params.graphqlSchemaUrl }
        : params.soapWsdlUrl
          ? { type: "soap", url: params.soapWsdlUrl }
          : llmConfig.importSpec;

    if (specToImport) {
      try {
        if (specToImport.type === "openapi") {
          specImportResult = await importOpenApiSpec({
            specUrl: specToImport.url,
            targetUrl: params.targetUrl,
            config: params.config,
          });
        } else if (specToImport.type === "graphql") {
          specImportResult = await importGraphQLSpec({
            endpointUrl: specToImport.url,
            targetUrl: params.targetUrl,
            config: params.config,
          });
        } else if (specToImport.type === "soap") {
          specImportResult = await importSoapSpec({
            wsdlUrl: specToImport.url,
            config: params.config,
          });
        }
      } catch (err: any) {
        // Non-fatal — continue with spider even if spec import fails
        specImportResult = { success: false, errors: [err.message] };
      }
    }

    // ─── Apply ZAP Context: scope, technologies, and playbook rules ─────────
    const zapApiCfg: ZapApiConfig = { baseUrl: cfg.baseUrl, apiKey: cfg.apiKey };

    // Create ZAP context for scope management
    try {
      const ctxResult = await zapRequest("/JSON/context/action/newContext/", {
        contextName: `scan-${scanId}`,
      }, cfg);
      const contextId = ctxResult.contextId;

      // Set in-scope URL patterns
      const includes = llmConfig.contextIncludes?.length
        ? llmConfig.contextIncludes
        : [`${parsedUrl.origin}.*`];
      for (const pattern of includes) {
        await zapRequest("/JSON/context/action/includeInContext/", {
          contextName: `scan-${scanId}`,
          regex: pattern,
        }, cfg).catch(() => {});
      }

      // Set exclusions (logout, static assets)
      for (const pattern of (llmConfig.contextExcludes || [])) {
        await zapRequest("/JSON/context/action/excludeFromContext/", {
          contextName: `scan-${scanId}`,
          regex: pattern,
        }, cfg).catch(() => {});
      }

      // Set technology list so ZAP tunes its scan rules
      if (technologies.length > 0) {
        // Exclude all first, then include only detected technologies
        await zapRequest("/JSON/context/action/excludeAllContextTechnologies/", {
          contextName: `scan-${scanId}`,
        }, cfg).catch(() => {});
        for (const tech of technologies) {
          await zapRequest("/JSON/context/action/includeContextTechnologies/", {
            contextName: `scan-${scanId}`,
            technologyName: tech,
          }, cfg).catch(() => {});
        }
      }

      console.log(`[ZAP Context] Created context scan-${scanId} with ${includes.length} includes, ${technologies.length} technologies`);
    } catch (err: any) {
      console.warn(`[ZAP Context] Failed to create context: ${err.message} — continuing with default`);
    }

    // Apply playbook rules to ZAP scan policy BEFORE scanning
    if (playbook && params.scanMode === "active") {
      console.log(`[ZAP Playbook] Pre-applying ${playbook.name} (${playbook.enabledRules.length} enabled, ${playbook.disabledRules.length} disabled)`);
      const pbResult = await applyPlaybookToZap(playbook, zapApiCfg, zapRequest);
      console.log(`[ZAP Playbook] Applied: ${pbResult.rulesConfigured} rules configured, ${pbResult.errors.length} errors`);
    }

    // Apply LLM-configured spider settings
    if (llmConfig.spiderConfig) {
      const sc = llmConfig.spiderConfig;
      await zapRequest("/JSON/spider/action/setOptionMaxDepth/", { Integer: String(sc.maxDepth) }, cfg).catch(() => {});
      await zapRequest("/JSON/spider/action/setOptionMaxChildren/", { Integer: String(sc.maxChildren) }, cfg).catch(() => {});
      await zapRequest("/JSON/spider/action/setOptionThreadCount/", { Integer: String(sc.threadCount) }, cfg).catch(() => {});
      await zapRequest("/JSON/spider/action/setOptionParseComments/", { Boolean: String(sc.parseComments) }, cfg).catch(() => {});
      await zapRequest("/JSON/spider/action/setOptionParseSitemapXml/", { Boolean: String(sc.parseSitemapXml) }, cfg).catch(() => {});
      await zapRequest("/JSON/spider/action/setOptionPostForm/", { Boolean: String(sc.postForm) }, cfg).catch(() => {});
    }

    // Start spider crawl
    const spiderResult = await zapRequest("/JSON/spider/action/scan/", {
      url: params.targetUrl,
      maxchildren: String(llmConfig.spiderConfig?.maxChildren || cfg.spiderMaxChildren),
      recurse: "true",
      subtreeonly: "true",
    }, cfg);

    const spiderScanId = spiderResult.scan;

    await db.update(webAppScans).set({
      status: "spidering",
      zapSpiderScanId: String(spiderScanId),
    }).where(eq(webAppScans.id, scanId));

    return {
      scanId,
      spiderScanId: String(spiderScanId),
      status: "spidering",
      llmConfig,
      specImportResult,
      playbookApplied: playbook?.name,
    };
  } catch (err: any) {
    await db.update(webAppScans).set({
      status: "error",
      errorMessage: `ZAP connection failed: ${err.message}`,
      completedAt: new Date(),
    }).where(eq(webAppScans.id, scanId));

    return { scanId, status: "error", llmConfig };
  }
}

/**
 * Poll scan progress — handles spider → ajax spider → active scan transitions.
 */
export async function pollScanProgress(scanId: number, config?: Partial<ZapConfig>): Promise<{
  status: string;
  spiderProgress: number;
  activeScanProgress: number;
  urlsFound: number;
  alertCounts: { high: number; medium: number; low: number; info: number };
}> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };

  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  if (scan.status === "completed" || scan.status === "error") {
    return {
      status: scan.status,
      spiderProgress: 100,
      activeScanProgress: scan.status === "completed" ? 100 : 0,
      urlsFound: scan.urlsDiscovered || 0,
      alertCounts: JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}'),
    };
  }

  try {
    let spiderProgress = scan.spiderProgress || 0;
    let urlsFound = scan.urlsDiscovered || 0;

    if (scan.status === "spidering" && scan.zapSpiderScanId) {
      const spiderStatus = await zapRequest("/JSON/spider/view/status/", {
        scanId: scan.zapSpiderScanId,
      }, cfg);
      spiderProgress = parseInt(spiderStatus.status || "0", 10);

      const spiderResults = await zapRequest("/JSON/spider/view/results/", {
        scanId: scan.zapSpiderScanId,
      }, cfg);
      urlsFound = (spiderResults.results || []).length;

      await db.update(webAppScans).set({
        spiderProgress,
        urlsDiscovered: urlsFound,
      }).where(eq(webAppScans.id, scanId));

      if (spiderProgress >= 100) {
        const llmConfig: LLMScanConfig | null = scan.llmScanConfig ? JSON.parse(scan.llmScanConfig) : null;

        // Check if AJAX spider should be used
        if (llmConfig?.useAjaxSpider && !scan.zapAjaxSpiderScanId) {
          const ajaxResult = await zapRequest("/JSON/ajaxSpider/action/scan/", {
            url: scan.targetUrl,
            subtreeonly: "true",
          }, cfg);

          await db.update(webAppScans).set({
            status: "ajax_spidering",
            zapAjaxSpiderScanId: "running",
            spiderProgress: 100,
          }).where(eq(webAppScans.id, scanId));

          return {
            status: "ajax_spidering",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId),
          };
        }

        // Passive mode: collect alerts and complete
        if (scan.scanMode === "passive" || scan.scanType === "spider_only") {
          await collectAlerts(scanId, cfg);
          await db.update(webAppScans).set({
            status: "completed",
            completedAt: new Date(),
            spiderProgress: 100,
          }).where(eq(webAppScans.id, scanId));

          return {
            status: "completed",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId),
          };
        }

        // Active mode: apply playbook rules before starting active scan
        const storedPlaybook = scan.llmScanConfig ? (() => {
          try {
            const storedConfig = JSON.parse(scan.llmScanConfig);
            const techs = storedConfig.technologies || [];
            return selectPlaybook("full", techs);
          } catch { return null; }
        })() : null;
        if (storedPlaybook) {
          console.log(`[ZAP Playbook] Applying ${storedPlaybook.name} (${storedPlaybook.enabledRules.length} rules) before active scan`);
          const zapApiCfg = { baseUrl: cfg.baseUrl, apiKey: cfg.apiKey };
          const pbResult = await applyPlaybookToZap(storedPlaybook, zapApiCfg, zapRequest);
          if (pbResult.errors.length > 0) {
            console.warn(`[ZAP Playbook] ${pbResult.errors.length} errors applying playbook:`, pbResult.errors);
          }
        }
        const activeScanResult = await zapRequest("/JSON/ascan/action/scan/", {
          url: scan.targetUrl,
          recurse: "true",
          scanPolicyName: scan.scanPolicyName || cfg.activeScanPolicy,
        }, cfg);

        await db.update(webAppScans).set({
          status: "active_scanning",
          zapActiveScanId: String(activeScanResult.scan),
          spiderProgress: 100,
        }).where(eq(webAppScans.id, scanId));

        return {
          status: "active_scanning",
          spiderProgress: 100,
          activeScanProgress: 0,
          urlsFound,
          alertCounts: await getAlertCounts(scanId),
        };
      }
    }

    // Handle AJAX spider phase
    if (scan.status === "ajax_spidering") {
      const ajaxStatus = await zapRequest("/JSON/ajaxSpider/view/status/", {}, cfg);
      if (ajaxStatus.status === "stopped" || ajaxStatus.status === "complete") {
        // AJAX spider done — get additional URLs
        const ajaxResults = await zapRequest("/JSON/ajaxSpider/view/numberOfResults/", {}, cfg);
        urlsFound = (scan.urlsDiscovered || 0) + parseInt(ajaxResults.numberOfResults || "0", 10);

        if (scan.scanMode === "passive" || scan.scanType === "spider_only") {
          await collectAlerts(scanId, cfg);
          await db.update(webAppScans).set({
            status: "completed",
            completedAt: new Date(),
            urlsDiscovered: urlsFound,
          }).where(eq(webAppScans.id, scanId));

          return {
            status: "completed",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId),
          };
        }

        // Apply playbook rules before starting active scan after AJAX spider
        const storedPlaybook2 = scan.llmScanConfig ? (() => {
          try {
            const storedConfig = JSON.parse(scan.llmScanConfig);
            const techs = storedConfig.technologies || [];
            return selectPlaybook("full", techs);
          } catch { return null; }
        })() : null;
        if (storedPlaybook2) {
          console.log(`[ZAP Playbook] Applying ${storedPlaybook2.name} (${storedPlaybook2.enabledRules.length} rules) before active scan (post-AJAX)`);
          const zapApiCfg2 = { baseUrl: cfg.baseUrl, apiKey: cfg.apiKey };
          const pbResult2 = await applyPlaybookToZap(storedPlaybook2, zapApiCfg2, zapRequest);
          if (pbResult2.errors.length > 0) {
            console.warn(`[ZAP Playbook] ${pbResult2.errors.length} errors applying playbook:`, pbResult2.errors);
          }
        }
        // Start active scan after AJAX spider
        const activeScanResult = await zapRequest("/JSON/ascan/action/scan/", {
          url: scan.targetUrl,
          recurse: "true",
          scanPolicyName: scan.scanPolicyName || cfg.activeScanPolicy,
        }, cfg);

        await db.update(webAppScans).set({
          status: "active_scanning",
          zapActiveScanId: String(activeScanResult.scan),
          urlsDiscovered: urlsFound,
        }).where(eq(webAppScans.id, scanId));

        return {
          status: "active_scanning",
          spiderProgress: 100,
          activeScanProgress: 0,
          urlsFound,
          alertCounts: await getAlertCounts(scanId),
        };
      }

      return {
        status: "ajax_spidering",
        spiderProgress: 100,
        activeScanProgress: 0,
        urlsFound: scan.urlsDiscovered || 0,
        alertCounts: await getAlertCounts(scanId),
      };
    }

    // Check active scan progress
    let activeScanProgress = scan.activeScanProgress || 0;
    if (scan.status === "active_scanning" && scan.zapActiveScanId) {
      const ascanStatus = await zapRequest("/JSON/ascan/view/status/", {
        scanId: scan.zapActiveScanId,
      }, cfg);
      activeScanProgress = parseInt(ascanStatus.status || "0", 10);

      await db.update(webAppScans).set({
        activeScanProgress,
      }).where(eq(webAppScans.id, scanId));

      if (activeScanProgress >= 100) {
        await collectAlerts(scanId, cfg);
        await db.update(webAppScans).set({
          status: "completed",
          completedAt: new Date(),
          activeScanProgress: 100,
        }).where(eq(webAppScans.id, scanId));

        return {
          status: "completed",
          spiderProgress: 100,
          activeScanProgress: 100,
          urlsFound,
          alertCounts: await getAlertCounts(scanId),
        };
      }
    }

    return {
      status: scan.status,
      spiderProgress,
      activeScanProgress,
      urlsFound,
      alertCounts: await getAlertCounts(scanId),
    };
  } catch (err: any) {
    return {
      status: scan.status,
      spiderProgress: scan.spiderProgress || 0,
      activeScanProgress: scan.activeScanProgress || 0,
      urlsFound: scan.urlsDiscovered || 0,
      alertCounts: JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}'),
    };
  }
}

/**
 * Collect all alerts from ZAP, enrich with MITRE ATT&CK mapping and Metasploit correlation.
 */
async function collectAlerts(scanId: number, config: ZapConfig): Promise<void> {
  const db = await getDb();
  if (!db) return;

  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) return;

  try {
    const alertsResult = await zapRequest("/JSON/alert/view/alerts/", {
      baseurl: scan.targetUrl,
      start: "0",
      count: String(config.maxAlertsPerScan),
    }, config);

    const alerts: ZapAlert[] = alertsResult.alerts || [];
    const counts = { high: 0, medium: 0, low: 0, info: 0 };

    // Deduplicate by (pluginId + url + param)
    const seen = new Set<string>();
    const uniqueAlerts: ZapAlert[] = [];
    for (const alert of alerts) {
      const key = `${alert.pluginId}|${alert.url}|${alert.param}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueAlerts.push(alert);
      }
    }

    for (const alert of uniqueAlerts) {
      const severity = mapZapRisk(alert.risk);
      const confidence = mapZapConfidence(alert.confidence);
      const cweId = alert.cweid ? parseInt(alert.cweid, 10) : null;

      if (severity === "high") counts.high++;
      else if (severity === "medium") counts.medium++;
      else if (severity === "low") counts.low++;
      else counts.info++;

      // MITRE ATT&CK mapping
      const mitre = mapToMitre(cweId, alert.name || alert.alert);

      // Metasploit module correlation
      const msfModules = findMsfModules(cweId);

      await db.insert(webAppFindings).values({
        scanId,
        alertName: alert.name || alert.alert,
        severity,
        confidence,
        description: (alert.description || "").substring(0, 4000),
        solution: (alert.solution || "").substring(0, 4000),
        reference: (alert.reference || "").substring(0, 2000),
        cweId,
        wascId: alert.wascid ? parseInt(alert.wascid, 10) : null,
        url: alert.url,
        method: alert.method,
        param: alert.param || null,
        attack: (alert.attack || "").substring(0, 2000),
        evidence: (alert.evidence || "").substring(0, 2000),
        zapPluginId: alert.pluginId,
        zapAlertRef: alert.id,
        // MITRE ATT&CK
        mitreAttackId: mitre?.techniqueId || null,
        mitreAttackName: mitre?.techniqueName || null,
        mitreTactic: mitre?.tactic || null,
        // Exploit correlation
        exploitAvailable: msfModules.length > 0,
        exploitModulePath: msfModules.length > 0 ? msfModules[0] : null,
      });
    }

    await db.update(webAppScans).set({
      alertCounts: JSON.stringify(counts),
      totalAlerts: uniqueAlerts.length,
    }).where(eq(webAppScans.id, scanId));
  } catch (err: any) {
    console.error(`[ZAP] Failed to collect alerts for scan ${scanId}: ${err.message}`);
  }
}

/**
 * Get alert counts for a scan from the database.
 */
async function getAlertCounts(scanId: number): Promise<{ high: number; medium: number; low: number; info: number }> {
  const db = await getDb();
  if (!db) return { high: 0, medium: 0, low: 0, info: 0 };

  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan?.alertCounts) return { high: 0, medium: 0, low: 0, info: 0 };

  try {
    return JSON.parse(scan.alertCounts);
  } catch {
    return { high: 0, medium: 0, low: 0, info: 0 };
  }
}

/**
 * Stop a running scan.
 */
export async function stopScan(scanId: number, config?: Partial<ZapConfig>): Promise<{ success: boolean }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };

  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  try {
    if (scan.zapSpiderScanId) {
      await zapRequest("/JSON/spider/action/stop/", { scanId: scan.zapSpiderScanId }, cfg);
    }
    if (scan.zapActiveScanId) {
      await zapRequest("/JSON/ascan/action/stop/", { scanId: scan.zapActiveScanId }, cfg);
    }
    if (scan.zapAjaxSpiderScanId) {
      await zapRequest("/JSON/ajaxSpider/action/stop/", {}, cfg);
    }
  } catch (err: any) {
    // ZAP might not be reachable
  }

  await collectAlerts(scanId, cfg);

  await db.update(webAppScans).set({
    status: "completed",
    completedAt: new Date(),
  }).where(eq(webAppScans.id, scanId));

  return { success: true };
}

/**
 * Get scan history from the database.
 */
export async function listScans(filters?: {
  status?: string;
  scanMode?: string;
  limit?: number;
}): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];

  const conditions: any[] = [];
  if (filters?.status) conditions.push(eq(webAppScans.status, filters.status));
  if (filters?.scanMode) conditions.push(eq(webAppScans.scanMode, filters.scanMode));

  let query;
  if (conditions.length > 0) {
    query = db.select().from(webAppScans)
      .where(and(...conditions))
      .orderBy(desc(webAppScans.startedAt));
  } else {
    query = db.select().from(webAppScans).orderBy(desc(webAppScans.startedAt));
  }

  return query.limit(filters?.limit || 50);
}

/**
 * Get findings for a specific scan.
 */
export async function getScanFindings(scanId: number, filters?: {
  severity?: string;
  limit?: number;
}): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];

  const conditions = [eq(webAppFindings.scanId, scanId)];
  if (filters?.severity) {
    conditions.push(eq(webAppFindings.severity, filters.severity as any));
  }

  return db.select().from(webAppFindings)
    .where(and(...conditions))
    .orderBy(desc(webAppFindings.severity))
    .limit(filters?.limit || 200);
}

/**
 * Get aggregate statistics across all scans.
 */
export async function getScanStats(): Promise<{
  totalScans: number;
  completedScans: number;
  totalFindings: number;
  findingsBySeverity: { high: number; medium: number; low: number; info: number };
  topVulnerabilities: { name: string; count: number; severity: string }[];
  avgScanDuration: number;
  scansByMode: { passive: number; active: number };
  mitreAttackCoverage: { techniqueId: string; techniqueName: string; tactic: string; count: number }[];
  exploitableFindings: number;
}> {
  const db = await getDb();
  if (!db) return {
    totalScans: 0, completedScans: 0, totalFindings: 0,
    findingsBySeverity: { high: 0, medium: 0, low: 0, info: 0 },
    topVulnerabilities: [], avgScanDuration: 0,
    scansByMode: { passive: 0, active: 0 },
    mitreAttackCoverage: [], exploitableFindings: 0,
  };

  const allScans = await db.select().from(webAppScans);
  const allFindings = await db.select().from(webAppFindings);

  const completedScans = allScans.filter(s => s.status === "completed");

  const findingsBySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) {
    const sev = f.severity as keyof typeof findingsBySeverity;
    if (sev in findingsBySeverity) findingsBySeverity[sev]++;
  }

  // Top vulnerabilities
  const vulnCounts = new Map<string, { count: number; severity: string }>();
  for (const f of allFindings) {
    const key = f.alertName || "Unknown";
    const existing = vulnCounts.get(key);
    if (existing) existing.count++;
    else vulnCounts.set(key, { count: 1, severity: f.severity || "info" });
  }
  const topVulnerabilities = Array.from(vulnCounts.entries())
    .map(([name, { count, severity }]) => ({ name, count, severity }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Average scan duration
  const durations = completedScans
    .filter(s => s.startedAt && s.completedAt)
    .map(s => new Date(s.completedAt!).getTime() - new Date(s.startedAt!).getTime());
  const avgScanDuration = durations.length > 0
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length / 60000)
    : 0;

  // Scans by mode
  const scansByMode = { passive: 0, active: 0 };
  for (const s of allScans) {
    if (s.scanMode === "passive") scansByMode.passive++;
    else scansByMode.active++;
  }

  // MITRE ATT&CK coverage
  const mitreCounts = new Map<string, { techniqueName: string; tactic: string; count: number }>();
  for (const f of allFindings) {
    if (f.mitreAttackId) {
      const existing = mitreCounts.get(f.mitreAttackId);
      if (existing) existing.count++;
      else mitreCounts.set(f.mitreAttackId, {
        techniqueName: f.mitreAttackName || "",
        tactic: f.mitreTactic || "",
        count: 1,
      });
    }
  }
  const mitreAttackCoverage = Array.from(mitreCounts.entries())
    .map(([techniqueId, data]) => ({ techniqueId, ...data }))
    .sort((a, b) => b.count - a.count);

  // Exploitable findings count
  const exploitableFindings = allFindings.filter(f => f.exploitAvailable).length;

  return {
    totalScans: allScans.length,
    completedScans: completedScans.length,
    totalFindings: allFindings.length,
    findingsBySeverity,
    topVulnerabilities,
    avgScanDuration,
    scansByMode,
    mitreAttackCoverage,
    exploitableFindings,
  };
}

/**
 * Delete a scan and its findings.
 */
export async function deleteScan(scanId: number): Promise<{ success: boolean }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  await db.delete(webAppFindings).where(eq(webAppFindings.scanId, scanId));
  await db.delete(webAppScans).where(eq(webAppScans.id, scanId));

  return { success: true };
}

/**
 * Seed demo scan data with [DEMO] prefix for demonstration purposes.
 */
export async function seedDemoData(): Promise<{ scanId: number; findingsCount: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  // Create a demo passive recon scan
  const [passiveScan] = await db.insert(webAppScans).values({
    targetUrl: "https://demo-target.example.com",
    scanName: "[DEMO] Passive Recon — demo-target.example.com",
    scanType: "spider_only",
    scanMode: "passive",
    status: "completed",
    startedBy: "demo",
    startedAt: new Date(Date.now() - 3600000),
    completedAt: new Date(Date.now() - 3000000),
    spiderProgress: 100,
    activeScanProgress: 0,
    urlsDiscovered: 147,
    totalAlerts: 8,
    alertCounts: JSON.stringify({ high: 0, medium: 3, low: 3, info: 2 }),
    detectedTechStack: JSON.stringify(["React", "Node.js", "Express", "nginx"]),
    llmScanConfig: JSON.stringify(getDefaultScanConfig("passive")),
    scanPolicyName: "Default Policy",
    ajaxSpiderUsed: true,
  });

  // Create a demo active DAST scan
  const [activeScan] = await db.insert(webAppScans).values({
    targetUrl: "https://demo-webapp.example.com",
    scanName: "[DEMO] Active DAST — demo-webapp.example.com",
    scanType: "full",
    scanMode: "active",
    status: "completed",
    startedBy: "demo",
    startedAt: new Date(Date.now() - 7200000),
    completedAt: new Date(Date.now() - 5400000),
    spiderProgress: 100,
    activeScanProgress: 100,
    urlsDiscovered: 312,
    totalAlerts: 15,
    alertCounts: JSON.stringify({ high: 4, medium: 5, low: 3, info: 3 }),
    detectedTechStack: JSON.stringify(["PHP", "Apache", "MySQL", "WordPress"]),
    llmScanConfig: JSON.stringify(getDefaultScanConfig("active")),
    scanPolicyName: "Default Policy",
    authConfigured: true,
    attackChainId: "chain-demo-001",
  });

  const passiveScanId = passiveScan.insertId;
  const activeScanId = activeScan.insertId;

  // Demo passive findings
  const passiveFindings = [
    { alertName: "[DEMO] Missing Content-Security-Policy Header", severity: "medium", confidence: 0.9, cweId: 693, url: "https://demo-target.example.com/", description: "Content Security Policy header not set. This allows the browser to load resources from any origin.", solution: "Add Content-Security-Policy header with appropriate directives.", mitreAttackId: "T1189", mitreAttackName: "Drive-by Compromise", mitreTactic: "Initial Access" },
    { alertName: "[DEMO] X-Frame-Options Header Not Set", severity: "medium", confidence: 0.9, cweId: 1021, url: "https://demo-target.example.com/login", description: "X-Frame-Options header is not included in the HTTP response to protect against clickjacking.", solution: "Set X-Frame-Options to DENY or SAMEORIGIN.", mitreAttackId: "T1185", mitreAttackName: "Browser Session Hijacking", mitreTactic: "Collection" },
    { alertName: "[DEMO] Cookie Without SameSite Attribute", severity: "medium", confidence: 0.7, cweId: 1275, url: "https://demo-target.example.com/api/auth", description: "Session cookie does not have SameSite attribute set.", solution: "Set SameSite=Strict or SameSite=Lax on session cookies.", mitreAttackId: "T1539", mitreAttackName: "Steal Web Session Cookie", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] Server Leaks Version Information", severity: "low", confidence: 0.9, cweId: 200, url: "https://demo-target.example.com/", description: "Server response header reveals version: nginx/1.21.3", solution: "Remove or obfuscate server version headers.", mitreAttackId: "T1552", mitreAttackName: "Unsecured Credentials", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] Strict-Transport-Security Header Not Set", severity: "low", confidence: 0.9, cweId: 319, url: "https://demo-target.example.com/", description: "HSTS header not set. Browser may allow HTTP downgrade.", solution: "Add Strict-Transport-Security header with max-age.", mitreAttackId: "T1557", mitreAttackName: "Adversary-in-the-Middle", mitreTactic: "Collection" },
    { alertName: "[DEMO] Information Disclosure - Debug Error Messages", severity: "low", confidence: 0.4, cweId: 209, url: "https://demo-target.example.com/api/users?id=999", description: "Application returns detailed error stack traces.", solution: "Implement custom error pages that do not reveal internal details.", mitreAttackId: "T1552", mitreAttackName: "Unsecured Credentials", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] Modern Web Application Detected", severity: "info", confidence: 0.9, cweId: null, url: "https://demo-target.example.com/", description: "React SPA detected with client-side routing.", solution: "Informational — no action required." },
    { alertName: "[DEMO] Timestamp Disclosure - Unix", severity: "info", confidence: 0.4, cweId: 200, url: "https://demo-target.example.com/api/status", description: "Unix timestamp found in response body.", solution: "Informational — review if timestamps reveal sensitive timing." },
  ];

  for (const f of passiveFindings) {
    await db.insert(webAppFindings).values({
      scanId: passiveScanId,
      alertName: f.alertName,
      severity: f.severity,
      confidence: f.confidence,
      cweId: f.cweId,
      url: f.url,
      description: f.description,
      solution: f.solution,
      mitreAttackId: f.mitreAttackId || null,
      mitreAttackName: f.mitreAttackName || null,
      mitreTactic: f.mitreTactic || null,
    });
  }

  // Demo active DAST findings
  const activeFindings = [
    { alertName: "[DEMO] SQL Injection", severity: "high", confidence: 0.9, cweId: 89, url: "https://demo-webapp.example.com/search?q=test", param: "q", attack: "' OR '1'='1", evidence: "SQL error in response", description: "SQL injection vulnerability in search parameter.", solution: "Use parameterized queries.", mitreAttackId: "T1190", mitreAttackName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", exploitAvailable: true, exploitModulePath: "exploit/multi/http/sqli_generic" },
    { alertName: "[DEMO] Cross Site Scripting (Reflected)", severity: "high", confidence: 0.9, cweId: 79, url: "https://demo-webapp.example.com/search?q=<script>alert(1)</script>", param: "q", attack: "<script>alert(1)</script>", evidence: "Script tag reflected in response", description: "Reflected XSS in search parameter.", solution: "Encode output and validate input.", mitreAttackId: "T1189", mitreAttackName: "Drive-by Compromise", mitreTactic: "Initial Access" },
    { alertName: "[DEMO] Path Traversal", severity: "high", confidence: 0.7, cweId: 22, url: "https://demo-webapp.example.com/download?file=../../../etc/passwd", param: "file", attack: "../../../etc/passwd", evidence: "root:x:0:0", description: "Path traversal allows reading arbitrary files.", solution: "Validate and sanitize file paths.", mitreAttackId: "T1005", mitreAttackName: "Data from Local System", mitreTactic: "Collection", exploitAvailable: true, exploitModulePath: "exploit/multi/http/lfi_generic" },
    { alertName: "[DEMO] Remote OS Command Injection", severity: "high", confidence: 0.7, cweId: 78, url: "https://demo-webapp.example.com/admin/ping?host=127.0.0.1;id", param: "host", attack: "127.0.0.1;id", evidence: "uid=33(www-data)", description: "OS command injection in admin ping utility.", solution: "Use safe APIs instead of shell commands.", mitreAttackId: "T1059", mitreAttackName: "Command and Scripting Interpreter", mitreTactic: "Execution", exploitAvailable: true, exploitModulePath: "exploit/multi/http/oscommand_generic" },
    { alertName: "[DEMO] CSRF Token Missing", severity: "medium", confidence: 0.9, cweId: 352, url: "https://demo-webapp.example.com/admin/settings", description: "Anti-CSRF token not found in form.", solution: "Implement CSRF tokens for state-changing requests.", mitreAttackId: "T1185", mitreAttackName: "Browser Session Hijacking", mitreTactic: "Collection" },
    { alertName: "[DEMO] Session Fixation", severity: "medium", confidence: 0.7, cweId: 384, url: "https://demo-webapp.example.com/login", description: "Session ID not regenerated after login.", solution: "Regenerate session ID after authentication.", mitreAttackId: "T1078", mitreAttackName: "Valid Accounts", mitreTactic: "Defense Evasion" },
    { alertName: "[DEMO] CORS Misconfiguration", severity: "medium", confidence: 0.9, cweId: 942, url: "https://demo-webapp.example.com/api/user/profile", description: "Access-Control-Allow-Origin: * allows any origin.", solution: "Restrict CORS to trusted origins.", mitreAttackId: "T1557", mitreAttackName: "Adversary-in-the-Middle", mitreTactic: "Collection" },
    { alertName: "[DEMO] Insecure HTTP Method (PUT)", severity: "medium", confidence: 0.7, cweId: 200, url: "https://demo-webapp.example.com/uploads/", method: "PUT", description: "PUT method enabled on upload directory.", solution: "Disable unnecessary HTTP methods.", mitreAttackId: "T1190", mitreAttackName: "Exploit Public-Facing Application", mitreTactic: "Initial Access" },
    { alertName: "[DEMO] WordPress Version Disclosure", severity: "medium", confidence: 0.9, cweId: 200, url: "https://demo-webapp.example.com/readme.html", description: "WordPress 5.8.1 version disclosed in readme.", solution: "Remove readme.html and version meta tags." },
    { alertName: "[DEMO] Directory Browsing Enabled", severity: "low", confidence: 0.9, cweId: 548, url: "https://demo-webapp.example.com/wp-content/uploads/", description: "Directory listing enabled on uploads folder.", solution: "Disable directory browsing in web server config.", mitreAttackId: "T1083", mitreAttackName: "File and Directory Discovery", mitreTactic: "Discovery" },
    { alertName: "[DEMO] Cookie Without HttpOnly Flag", severity: "low", confidence: 0.9, cweId: 1004, url: "https://demo-webapp.example.com/", description: "Session cookie missing HttpOnly flag.", solution: "Set HttpOnly flag on session cookies.", mitreAttackId: "T1539", mitreAttackName: "Steal Web Session Cookie", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] X-Content-Type-Options Header Missing", severity: "low", confidence: 0.9, cweId: 693, url: "https://demo-webapp.example.com/", description: "X-Content-Type-Options header not set.", solution: "Add X-Content-Type-Options: nosniff header." },
    { alertName: "[DEMO] Application Error Disclosure", severity: "info", confidence: 0.7, cweId: 209, url: "https://demo-webapp.example.com/wp-admin/", description: "WordPress admin login page accessible.", solution: "Restrict access to admin pages." },
    { alertName: "[DEMO] Retrieved from Cache", severity: "info", confidence: 0.4, cweId: null, url: "https://demo-webapp.example.com/", description: "Response served from cache.", solution: "Informational — no action required." },
    { alertName: "[DEMO] User Agent Fuzzer", severity: "info", confidence: 0.4, cweId: null, url: "https://demo-webapp.example.com/", description: "Different responses for different user agents detected.", solution: "Informational — review user agent handling." },
  ];

  for (const f of activeFindings) {
    await db.insert(webAppFindings).values({
      scanId: activeScanId,
      alertName: f.alertName,
      severity: f.severity,
      confidence: f.confidence,
      cweId: f.cweId,
      url: f.url,
      method: f.method || "GET",
      param: f.param || null,
      attack: f.attack || null,
      evidence: f.evidence || null,
      description: f.description,
      solution: f.solution,
      mitreAttackId: f.mitreAttackId || null,
      mitreAttackName: f.mitreAttackName || null,
      mitreTactic: f.mitreTactic || null,
      exploitAvailable: f.exploitAvailable || false,
      exploitModulePath: f.exploitModulePath || null,
    });
  }

  return { scanId: activeScanId, findingsCount: passiveFindings.length + activeFindings.length };
}

/**
 * Clear all [DEMO]-prefixed scan data.
 */
export async function clearDemoData(): Promise<{ deletedScans: number; deletedFindings: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const demoScans = await db.select().from(webAppScans)
    .where(sql`${webAppScans.scanName} LIKE '%[DEMO]%'`);

  let deletedFindings = 0;
  for (const scan of demoScans) {
    const findings = await db.delete(webAppFindings).where(eq(webAppFindings.scanId, scan.id));
    deletedFindings += (findings as any).rowsAffected || 0;
  }

  const result = await db.delete(webAppScans)
    .where(sql`${webAppScans.scanName} LIKE '%[DEMO]%'`);

  return { deletedScans: demoScans.length, deletedFindings };
}


// ─── Credential-to-ZAP Authentication Handoff ────────────────────────────────

/**
 * Confirmed credential from engagement credential testing (Hydra, HTTP form, OEM defaults).
 * Passed from the engagement orchestrator's asset.confirmedCredentials array.
 */
export interface ConfirmedCredential {
  username: string;
  password: string;
  service: string;
  port: number;
  protocol: string;
  accessLevel?: string;
  source: string;
  responseSnippet?: string;
  confirmedAt: number;
}

/**
 * Configure ZAP authentication context using confirmed credentials from credential testing.
 *
 * Supports:
 * - Form-based login (DVWA, WordPress, custom forms)
 * - HTTP Basic Auth
 * - JSON-based login (REST APIs)
 *
 * When default credentials are confirmed working during the engagement's credential
 * testing phase (e.g., Hydra finds admin/password on DVWA), this function configures
 * ZAP to use those credentials for authenticated scanning — dramatically increasing
 * vulnerability coverage behind login walls.
 *
 * @param contextName - ZAP context name (e.g., "scan-123")
 * @param targetUrl - The target URL being scanned
 * @param credentials - Array of confirmed working credentials
 * @param config - ZAP connection config
 * @returns Authentication configuration result
 */
export async function configureZapAuthentication(
  contextName: string,
  targetUrl: string,
  credentials: ConfirmedCredential[],
  config?: Partial<ZapConfig>,
): Promise<{
  configured: boolean;
  method: string;
  username: string;
  contextId?: string;
  userId?: string;
  errors: string[];
}> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };
  const errors: string[] = [];
  const parsedUrl = new URL(targetUrl);

  // Pick the best credential — prefer HTTP/web credentials, then highest access level
  const webCreds = credentials.filter(c =>
    ['http', 'https', 'web_admin', 'http-form', 'http-get', 'http-post'].includes(c.service) ||
    c.protocol === 'http' || c.protocol === 'https'
  );
  const bestCred = webCreds[0] || credentials[0];
  if (!bestCred) {
    return { configured: false, method: 'none', username: '', errors: ['No credentials provided'] };
  }

  console.log(`[ZAP Auth] Configuring authentication for ${targetUrl} using ${bestCred.source} credentials (${bestCred.username}:***)`);

  try {
    // Step 1: Get context ID
    let contextId: string | undefined;
    try {
      const ctxResult = await zapRequest("/JSON/context/view/context/", {
        contextName,
      }, cfg);
      contextId = ctxResult.context?.id || ctxResult.id;
    } catch {
      // Context might not exist yet — create it
      try {
        const newCtx = await zapRequest("/JSON/context/action/newContext/", {
          contextName,
        }, cfg);
        contextId = newCtx.contextId;
      } catch (e: any) {
        errors.push(`Failed to create context: ${e.message}`);
      }
    }

    if (!contextId) {
      return { configured: false, method: 'none', username: bestCred.username, errors: ['Could not get or create ZAP context'] };
    }

    // Step 2: Detect login form to determine auth method
    // Build tech-specific login paths based on detected technologies
    const basePaths = ['/login', '/admin/login', '/user/login', '/wp-login.php', '/login.php', '/'];
    const techSpecificPaths: string[] = [];
    
    // Check if tech hints were passed via credential metadata or config
    const techHints = (config as any)?.techHints || [];
    const techStr = techHints.join(' ').toLowerCase();
    
    // WordPress
    if (techStr.includes('wordpress') || techStr.includes('wp-')) {
      techSpecificPaths.push('/wp-login.php', '/wp-admin/', '/xmlrpc.php');
    }
    // Django/Python
    if (techStr.includes('django') || techStr.includes('python') || techStr.includes('csrftoken')) {
      techSpecificPaths.push('/admin/login/', '/accounts/login/', '/auth/login/');
    }
    // Laravel/PHP
    if (techStr.includes('laravel') || techStr.includes('laravel_session')) {
      techSpecificPaths.push('/login', '/admin', '/auth/login', '/nova/login');
    }
    // PHP generic
    if (techStr.includes('php') || techStr.includes('phpsessid')) {
      techSpecificPaths.push('/login.php', '/admin.php', '/index.php?action=login', '/administrator/');
    }
    // Java/Spring
    if (techStr.includes('java') || techStr.includes('jsessionid') || techStr.includes('spring') || techStr.includes('tomcat')) {
      techSpecificPaths.push('/login', '/j_spring_security_check', '/admin/login', '/cas/login');
    }
    // ASP.NET
    if (techStr.includes('asp.net') || techStr.includes('aspnet')) {
      techSpecificPaths.push('/Account/Login', '/Login.aspx', '/admin/login', '/Identity/Account/Login');
    }
    // Node.js/Express
    if (techStr.includes('node') || techStr.includes('express') || techStr.includes('connect.sid')) {
      techSpecificPaths.push('/login', '/auth/login', '/api/auth/login', '/users/login');
    }
    // Ruby on Rails
    if (techStr.includes('rails') || techStr.includes('ruby')) {
      techSpecificPaths.push('/users/sign_in', '/login', '/admin/login', '/session/new');
    }
    
    // Deduplicate: tech-specific paths first (higher priority), then generic
    const loginPaths = [...new Set([...techSpecificPaths, ...basePaths])];
    if (techSpecificPaths.length > 0) {
      console.log(`[ZAP Auth] Tech-specific login paths added: ${techSpecificPaths.join(', ')} (from: ${techStr.substring(0, 100)})`);
    }
    let detectedLoginUrl: string | undefined;
    let detectedMethod: 'form' | 'basic' | 'json' = 'form';

    for (const path of loginPaths) {
      try {
        const testUrl = `${parsedUrl.origin}${path}`;
        const resp = await fetch(testUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CalderaZapAuth/1.0)' },
          signal: AbortSignal.timeout(5000),
          redirect: 'follow',
        });

        if (resp.status === 401 && resp.headers.get('www-authenticate')?.toLowerCase().includes('basic')) {
          detectedMethod = 'basic';
          detectedLoginUrl = testUrl;
          break;
        }

        if (resp.ok) {
          const body = await resp.text();
          // Check for login form indicators
          if (/type=["']password["']/i.test(body) && /<form/i.test(body)) {
            detectedLoginUrl = testUrl;
            // Check if it's a JSON/API login (SPA with fetch-based auth)
            if (/application\/json|fetch\s*\(|axios|XMLHttpRequest/i.test(body) && !/action=["'][^"']*["']/i.test(body)) {
              detectedMethod = 'json';
            } else {
              detectedMethod = 'form';
            }
            break;
          }
        }
      } catch { /* continue to next path */ }
    }

    // Step 3: Configure authentication based on detected method
    if (detectedMethod === 'basic') {
      // HTTP Basic Auth — simplest configuration
      try {
        await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
          contextId,
          authMethodName: "httpAuthentication",
          authMethodConfigParams: `hostname=${parsedUrl.hostname}&realm=`,
        }, cfg);

        console.log(`[ZAP Auth] Configured HTTP Basic Auth for context ${contextName}`);
      } catch (e: any) {
        errors.push(`Failed to set HTTP Basic auth: ${e.message}`);
      }
    } else if (detectedMethod === 'form') {
      // Form-based authentication — most common (DVWA, WordPress, etc.)
      const loginUrl = detectedLoginUrl || `${parsedUrl.origin}/login`;

      // Detect form field names by fetching the login page
      let usernameField = 'username';
      let passwordField = 'password';
      let loginRequestData = '';

      try {
        const loginPage = await fetch(loginUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(5000),
        });
        const html = await loginPage.text();

        // Extract username field name
        const userFieldMatch = html.match(/name=["'](user(?:name)?|login|log|email|usr|uname|user_login)["']/i);
        if (userFieldMatch) usernameField = userFieldMatch[1];

        // Extract password field name
        const passFieldMatch = html.match(/name=["'](pass(?:word)?|pwd|passwd|user_password|pass_login)["']/i);
        if (passFieldMatch) passwordField = passFieldMatch[1];

        // Extract form action URL
        const formActionMatch = html.match(/<form[^>]*action=["']([^"']+)["']/i);
        const formAction = formActionMatch
          ? new URL(formActionMatch[1], loginUrl).toString()
          : loginUrl;

        // Build the login request data with ZAP placeholders
        loginRequestData = `${usernameField}={%username%}&${passwordField}={%password%}`;

        // Check for CSRF token
        const csrfMatch = html.match(/name=["'](csrf[_-]?token|_?token|user_token|csrfmiddlewaretoken|_csrf|authenticity_token|__RequestVerificationToken)["'][^>]*value=["']([^"']+)["']/i);
        if (csrfMatch) {
          loginRequestData += `&${csrfMatch[1]}=${encodeURIComponent(csrfMatch[2])}`;
          console.log(`[ZAP Auth] Detected CSRF token field: ${csrfMatch[1]}`);
        }

        // Configure ZAP form-based auth
        await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
          contextId,
          authMethodName: "formBasedAuthentication",
          authMethodConfigParams: `loginUrl=${encodeURIComponent(formAction)}&loginRequestData=${encodeURIComponent(loginRequestData)}`,
        }, cfg);

        console.log(`[ZAP Auth] Configured form-based auth: ${formAction} (fields: ${usernameField}/${passwordField})`);
      } catch (e: any) {
        errors.push(`Failed to configure form auth: ${e.message}`);
        // Fallback: try with generic field names
        try {
          await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
            contextId,
            authMethodName: "formBasedAuthentication",
            authMethodConfigParams: `loginUrl=${encodeURIComponent(loginUrl)}&loginRequestData=${encodeURIComponent(`username={%username%}&password={%password%}`)}`,
          }, cfg);
          console.log(`[ZAP Auth] Configured form-based auth with generic fields (fallback)`);
        } catch (e2: any) {
          errors.push(`Fallback form auth also failed: ${e2.message}`);
        }
      }
    } else if (detectedMethod === 'json') {
      // JSON-based authentication (SPA/API login)
      const loginUrl = detectedLoginUrl || `${parsedUrl.origin}/api/login`;
      try {
        await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
          contextId,
          authMethodName: "jsonBasedAuthentication",
          authMethodConfigParams: `loginUrl=${encodeURIComponent(loginUrl)}&loginRequestData=${encodeURIComponent(`{"username":"{%username%}","password":"{%password%}"}`)}`,
        }, cfg);
        console.log(`[ZAP Auth] Configured JSON-based auth: ${loginUrl}`);
      } catch (e: any) {
        errors.push(`Failed to set JSON auth: ${e.message}`);
      }
    }

    // Step 4: Set logged-in / logged-out indicators for session detection
    try {
      // Use knowledge-driven indicators based on detected auth method
      const { ZAP_AUTH_STRATEGIES } = await import("./knowledge/zap-pentesting-knowledge");
      const matchedStrategy = ZAP_AUTH_STRATEGIES.find(s => s.type === detectedMethod);
      const loggedInRegex = matchedStrategy?.loggedInIndicator || "\\Qlogout\\E|\\Qsign.out\\E|\\Qdashboard\\E|\\Qwelcome\\E|\\Qmy.account\\E|\\Qprofile\\E";
      const loggedOutRegex = matchedStrategy?.loggedOutIndicator || "\\Qlogin\\E|\\Qsign.in\\E|\\Qauthentication.required\\E|\\Qaccess.denied\\E|\\Q401\\E";

      // Set logged-in indicators from knowledge module
      await zapRequest("/JSON/authentication/action/setLoggedInIndicator/", {
        contextId,
        loggedInIndicatorRegex: loggedInRegex,
      }, cfg).catch(() => {});

      // Set logged-out indicators from knowledge module
      await zapRequest("/JSON/authentication/action/setLoggedOutIndicator/", {
        contextId,
        loggedOutIndicatorRegex: loggedOutRegex,
      }, cfg).catch(() => {});

      console.log(`[ZAP Auth] Set logged-in/logged-out indicators`);
    } catch (e: any) {
      errors.push(`Failed to set session indicators: ${e.message}`);
    }

    // Step 5: Create ZAP user with the confirmed credentials
    let userId: string | undefined;
    try {
      const userResult = await zapRequest("/JSON/users/action/newUser/", {
        contextId,
        name: `${bestCred.source}-${bestCred.username}`,
      }, cfg);
      userId = userResult.userId;

      if (userId) {
        // Set credentials on the user
        await zapRequest("/JSON/users/action/setAuthenticationCredentials/", {
          contextId,
          userId,
          authCredentialsConfigParams: `username=${encodeURIComponent(bestCred.username)}&password=${encodeURIComponent(bestCred.password)}`,
        }, cfg);

        // Enable the user
        await zapRequest("/JSON/users/action/setUserEnabled/", {
          contextId,
          userId,
          enabled: "true",
        }, cfg);

        // Set as forced user for all requests in this context
        await zapRequest("/JSON/forcedUser/action/setForcedUser/", {
          contextId,
          userId,
        }, cfg);

        await zapRequest("/JSON/forcedUser/action/setForcedUserModeEnabled/", {
          enabled: "true",
        }, cfg);

        console.log(`[ZAP Auth] Created and enabled forced user: ${bestCred.username} (source: ${bestCred.source})`);
      }
    } catch (e: any) {
      errors.push(`Failed to create ZAP user: ${e.message}`);
    }

    // Step 6: Update the scan record to indicate auth was configured with source tracking
    try {
      const db = await getDb();
      if (db) {
        // Extract scan ID from context name (format: "scan-123")
        const scanIdMatch = contextName.match(/scan-(\d+)/);
        if (scanIdMatch) {
          await db.update(webAppScans).set({
            authConfigured: 1,
            authCredentialSource: bestCred.source,
            authUsername: bestCred.username,
            authMethod: detectedMethod,
          }).where(eq(webAppScans.id, parseInt(scanIdMatch[1], 10)));
        }
      }
    } catch { /* non-fatal */ }

    return {
      configured: errors.length === 0,
      method: detectedMethod,
      username: bestCred.username,
      contextId,
      userId,
      errors,
    };
  } catch (e: any) {
    return {
      configured: false,
      method: 'none',
      username: bestCred.username,
      errors: [`Unexpected error: ${e.message}`],
    };
  }
}
