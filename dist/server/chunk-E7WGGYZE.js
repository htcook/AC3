import {
  init_knowledge_loader,
  loadKnowledgeData
} from "./chunk-PIYDKQBM.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/knowledge/zap-pentesting-knowledge.ts
async function initZapKnowledge() {
  if (_loaded) return;
  const data = await loadKnowledgeData("zap_pentesting_knowledge.json", FALLBACK);
  WSTG_METHODOLOGY = data.wstgMethodology || [];
  ZAP_ALERT_CATALOG = data.zapAlertCatalog || [];
  TECH_SCAN_POLICIES = data.techScanPolicies || [];
  ZAP_AUTH_STRATEGIES = data.zapAuthStrategies || [];
  LLM_REASONING_PROMPTS = data.llmReasoningPrompts || [];
  ZAP_PENTEST_WORKFLOW = data.zapPentestWorkflow || [];
  VULN_PAYLOADS = data.vulnPayloads || [];
  ZAP_FALSE_POSITIVE_PATTERNS = data.zapFalsePositivePatterns || [];
  _loaded = true;
  console.log(`[ZapKnowledge] Loaded ${WSTG_METHODOLOGY.length} WSTG categories, ${ZAP_ALERT_CATALOG.length} alerts, ${ZAP_FALSE_POSITIVE_PATTERNS.length} FP patterns`);
}
function getWSTGMethodologyContext(categoryId) {
  let categories = WSTG_METHODOLOGY;
  if (categoryId) {
    categories = WSTG_METHODOLOGY.filter((c) => c.id === categoryId);
    if (categories.length === 0) categories = WSTG_METHODOLOGY;
  }
  const sections = categories.map((cat) => {
    const tests = cat.tests.filter((t) => t.automatable).map((t) => `  - **${t.id}** ${t.name}: ${t.zapApproach} [Rules: ${t.zapRuleIds.length > 0 ? t.zapRuleIds.join(", ") : "manual"}]`).join("\n");
    return `### ${cat.id}: ${cat.name}
${cat.description}

**Automatable Tests:**
${tests}`;
  }).join("\n\n");
  return `## OWASP WSTG v4.2 Testing Methodology (ZAP-Mapped)
Follow this methodology systematically. Each test maps to specific ZAP scan rules.

${sections}

**Methodology Strategy:**
1. Start with Information Gathering (WSTG-INFO) during spider phase
2. Configuration Testing (WSTG-CONF) runs automatically via passive scan
3. Input Validation (WSTG-INPV) is the core of active scanning
4. Session/Auth testing requires configured authentication
5. Business Logic (WSTG-BUSL) requires manual testing with ZAP proxy`;
}
function getZAPAlertCatalogContext(minFoothold) {
  const footholdOrder = ["none", "low", "medium", "high", "critical"];
  const minIdx = minFoothold ? footholdOrder.indexOf(minFoothold) : 2;
  const filtered = ZAP_ALERT_CATALOG.filter(
    (a) => footholdOrder.indexOf(a.footholdPotential) >= minIdx
  );
  const byCategory = {};
  for (const alert of filtered) {
    if (!byCategory[alert.category]) byCategory[alert.category] = [];
    byCategory[alert.category].push(alert);
  }
  const sections = Object.entries(byCategory).map(([cat, alerts]) => {
    const rows = alerts.sort((a, b) => footholdOrder.indexOf(b.footholdPotential) - footholdOrder.indexOf(a.footholdPotential)).map((a) => `  - **${a.id}** ${a.name} [${a.risk}/${a.footholdPotential}]: ${a.description}`).join("\n");
    return `### ${cat}
${rows}`;
  }).join("\n\n");
  return `## ZAP Alert Catalog (Foothold-Prioritized)
${filtered.length} alerts with ${minFoothold || "medium"}+ foothold potential:

${sections}

**Alert Interpretation:**
- CRITICAL foothold: Direct RCE or credential theft \u2014 exploit immediately
- HIGH foothold: Significant access gain \u2014 prioritize verification
- MEDIUM foothold: Useful for chaining \u2014 combine with other findings`;
}
function getTechScanPolicyContext(technology) {
  let policies = TECH_SCAN_POLICIES;
  if (technology) {
    policies = TECH_SCAN_POLICIES.filter(
      (p) => p.technology.toLowerCase().includes(technology.toLowerCase()) || p.fingerprints.some((f) => f.toLowerCase().includes(technology.toLowerCase()))
    );
    if (policies.length === 0) policies = TECH_SCAN_POLICIES;
  }
  const sections = policies.map((p) => {
    const rules = p.criticalRules.map((r) => `  - Rule ${r.id}: ${r.strength}/${r.threshold} \u2014 ${r.reason}`).join("\n");
    const secrets = p.secretsRules.map((id) => {
      const alert = ZAP_ALERT_CATALOG.find((a) => a.id === id);
      return alert ? `  - ${id}: ${alert.name}` : `  - ${id}`;
    }).join("\n");
    return `### ${p.technology}
${p.description}
**Fingerprints:** ${p.fingerprints.join(", ")}
**AJAX Spider:** ${p.useAjaxSpider ? "Required" : "Optional"}

**Critical Rules:**
${rules}

**Secrets Discovery:**
${secrets}`;
  }).join("\n\n");
  return `## Technology-Specific ZAP Scan Policies
Configure scan rules based on detected technology stack:

${sections}

**Policy Selection Strategy:**
1. Fingerprint the technology from passive scan results
2. Enable all critical rules for detected technology at HIGH strength
3. Always enable secrets discovery rules regardless of technology
4. Use AJAX Spider for JavaScript-heavy frameworks
5. Configure context excludes to avoid scanning external domains`;
}
function getZAPAuthContext(authType) {
  let strategies = ZAP_AUTH_STRATEGIES;
  if (authType) {
    strategies = ZAP_AUTH_STRATEGIES.filter((s) => s.type === authType);
    if (strategies.length === 0) strategies = ZAP_AUTH_STRATEGIES;
  }
  const sections = strategies.map((s) => {
    const steps = s.setupSteps.join("\n");
    return `### ${s.name} (${s.type})
${s.description}
**Detection Indicators:** ${s.indicators.join(", ")}
**Logged-In Pattern:** \`${s.loggedInIndicator}\`
**Logged-Out Pattern:** \`${s.loggedOutIndicator}\`

**Setup Steps:**
${steps}`;
  }).join("\n\n");
  return `## ZAP Authentication Strategies
Configure authentication for deeper vulnerability coverage:

${sections}

**Authentication Priority:**
1. Use confirmed credentials from hydra/credential dictionary
2. Prefer form-based auth for traditional web apps
3. Use JSON auth for SPAs and API-first applications
4. Fall back to script-based for OAuth2/SAML/MFA
5. Browser-based as last resort for CAPTCHA-protected logins`;
}
function getZAPReasoningPrompt(phase) {
  const phaseMap = {
    vuln_detection: "zap-scan-interpret",
    exploitation: "zap-attack-path",
    triage: "zap-finding-triage",
    scan_config: "zap-scan-config",
    rescan: "zap-rescan-decision"
  };
  const promptId = phaseMap[phase];
  if (!promptId) return null;
  return LLM_REASONING_PROMPTS.find((p) => p.id === promptId) || null;
}
function getZAPWorkflowContext() {
  const steps = ZAP_PENTEST_WORKFLOW.map((s) => {
    const decisions = s.decisionPoints.map((d) => `    - ${d}`).join("\n");
    return `### Step ${s.order}: ${s.name}
${s.description}
**ZAP API Calls:** ${s.zapApiCalls.join(", ")}
**Decision Points:**
${decisions}
**Success:** ${s.successCriteria}
**On Failure:** ${s.failureHandling}`;
  }).join("\n\n");
  return `## ZAP Pentest Workflow
Standard 8-step workflow for comprehensive web application testing:

${steps}`;
}
function getVulnPayloadContext(vulnType) {
  let payloadSets = VULN_PAYLOADS;
  if (vulnType) {
    payloadSets = VULN_PAYLOADS.filter(
      (p) => p.vulnerability.toLowerCase().includes(vulnType.toLowerCase())
    );
    if (payloadSets.length === 0) payloadSets = VULN_PAYLOADS;
  }
  const sections = payloadSets.map((ps) => {
    const payloads = ps.payloads.map((p) => `  - \`${p.payload}\` \u2014 ${p.context} \u2192 ${p.expectedResult}`).join("\n");
    return `### ${ps.vulnerability} [Rules: ${ps.zapRuleIds.join(", ")}]
${payloads}`;
  }).join("\n\n");
  return `## Vulnerability Test Payloads
Reference payloads for manual verification of ZAP findings:

${sections}

**Payload Usage:**
1. Use these to manually verify ZAP findings before reporting
2. Adapt payloads based on detected WAF/filtering
3. Chain payloads with technology-specific variations
4. Document successful payloads as evidence in the report`;
}
function buildZAPKnowledgeContext(params) {
  const sections = [];
  if (params.phase === "vuln_detection" || params.phase === "exploitation") {
    if (params.phase === "vuln_detection") {
      sections.push(getWSTGMethodologyContext("WSTG-INPV"));
    }
    sections.push(getZAPAlertCatalogContext(params.footholdMinimum || "medium"));
  }
  if (params.phase === "enumeration" || params.phase === "vuln_detection") {
    sections.push(getTechScanPolicyContext(params.technology));
  }
  if (params.phase === "vuln_detection" || params.phase === "exploitation") {
    if (params.authType) {
      sections.push(getZAPAuthContext(params.authType));
    }
  }
  if (params.includeWorkflow) {
    sections.push(getZAPWorkflowContext());
  }
  if (params.phase === "exploitation" && params.includePayloads !== false) {
    sections.push(getVulnPayloadContext());
  }
  if (params.phase === "vuln_detection" || params.phase === "exploitation" || params.phase === "reporting") {
    sections.push(getFalsePositiveTriageContext(params.alertIds));
  }
  if (sections.length === 0) return "";
  return `# ZAP Pentesting Knowledge Base

${sections.join("\n\n---\n\n")}`;
}
function getFalsePositiveTriageContext(alertIds) {
  let patterns = ZAP_FALSE_POSITIVE_PATTERNS;
  if (alertIds && alertIds.length > 0) {
    patterns = ZAP_FALSE_POSITIVE_PATTERNS.filter((p) => alertIds.includes(p.alertId));
    if (patterns.length === 0) patterns = ZAP_FALSE_POSITIVE_PATTERNS;
  }
  const sections = patterns.map((p) => {
    const fpIndicators = p.fpIndicators.map((i) => `  - ${i}`).join("\n");
    const tpIndicators = p.tpIndicators.map((i) => `  - ${i}`).join("\n");
    const verification = p.verificationSteps.map((s) => `  ${s}`).join("\n");
    return `### Alert ${p.alertId}: ${p.alertName} [FP Rate: ${p.fpRate.toUpperCase()}]
**Category:** ${p.category}
**FP-Prone Technologies:** ${p.fpProneTechnologies.join(", ") || "None specific"}

**False Positive Indicators:**
${fpIndicators}

**True Positive Indicators:**
${tpIndicators || "  - (No specific TP indicators \u2014 verify manually)"}

**Verification Steps:**
${verification}

**Triage Guidance:** ${p.triageGuidance}`;
  }).join("\n\n");
  return `## ZAP False Positive Triage Guide
Use this guide to classify ZAP findings as True Positive (TP) or False Positive (FP).

**Triage Decision Matrix:**
1. Check FP Rate \u2014 very_high/high alerts need extra scrutiny
2. Match FP Indicators \u2014 if 2+ match, likely FP
3. Match TP Indicators \u2014 if any match, likely TP
4. Run Verification Steps \u2014 manual confirmation required for medium/low FP rate alerts
5. Consider technology context \u2014 some alerts are always FP for certain tech stacks

${sections}`;
}
function getCompactFPTriage(alertId) {
  const pattern = ZAP_FALSE_POSITIVE_PATTERNS.find((p) => p.alertId === alertId);
  if (!pattern) return null;
  return {
    fpRate: pattern.fpRate,
    guidance: pattern.triageGuidance
  };
}
function getZapKnowledgeMetadata() {
  return {
    version: "1.1.0",
    wstgCategories: WSTG_METHODOLOGY.length,
    wstgTests: WSTG_METHODOLOGY.reduce((sum, c) => sum + c.tests.length, 0),
    automatableTests: WSTG_METHODOLOGY.reduce((sum, c) => sum + c.tests.filter((t) => t.automatable).length, 0),
    alertCatalogSize: ZAP_ALERT_CATALOG.length,
    activeAlerts: ZAP_ALERT_CATALOG.filter((a) => a.type === "active").length,
    passiveAlerts: ZAP_ALERT_CATALOG.filter((a) => a.type === "passive").length,
    techPolicies: TECH_SCAN_POLICIES.length,
    authStrategies: ZAP_AUTH_STRATEGIES.length,
    reasoningPrompts: LLM_REASONING_PROMPTS.length,
    workflowSteps: ZAP_PENTEST_WORKFLOW.length,
    payloadSets: VULN_PAYLOADS.length,
    totalPayloads: VULN_PAYLOADS.reduce((sum, p) => sum + p.payloads.length, 0),
    falsePositivePatterns: ZAP_FALSE_POSITIVE_PATTERNS.length,
    veryHighFPAlerts: ZAP_FALSE_POSITIVE_PATTERNS.filter((p) => p.fpRate === "very_high").length,
    highFPAlerts: ZAP_FALSE_POSITIVE_PATTERNS.filter((p) => p.fpRate === "high").length
  };
}
var FALLBACK, WSTG_METHODOLOGY, ZAP_ALERT_CATALOG, TECH_SCAN_POLICIES, ZAP_AUTH_STRATEGIES, LLM_REASONING_PROMPTS, ZAP_PENTEST_WORKFLOW, VULN_PAYLOADS, ZAP_FALSE_POSITIVE_PATTERNS, _loaded, ZAP_KNOWLEDGE_METADATA;
var init_zap_pentesting_knowledge = __esm({
  "server/lib/knowledge/zap-pentesting-knowledge.ts"() {
    init_knowledge_loader();
    FALLBACK = {
      wstgMethodology: [],
      zapAlertCatalog: [],
      techScanPolicies: [],
      zapAuthStrategies: [],
      llmReasoningPrompts: [],
      zapPentestWorkflow: [],
      vulnPayloads: [],
      zapFalsePositivePatterns: []
    };
    WSTG_METHODOLOGY = [];
    ZAP_ALERT_CATALOG = [];
    TECH_SCAN_POLICIES = [];
    ZAP_AUTH_STRATEGIES = [];
    LLM_REASONING_PROMPTS = [];
    ZAP_PENTEST_WORKFLOW = [];
    VULN_PAYLOADS = [];
    ZAP_FALSE_POSITIVE_PATTERNS = [];
    _loaded = false;
    initZapKnowledge().catch((e) => console.warn("[ZapKnowledge] Auto-init failed:", e.message));
    ZAP_KNOWLEDGE_METADATA = new Proxy({}, {
      get(_, prop) {
        return getZapKnowledgeMetadata()[prop];
      },
      ownKeys() {
        return Object.keys(getZapKnowledgeMetadata());
      },
      getOwnPropertyDescriptor(_, prop) {
        const meta = getZapKnowledgeMetadata();
        if (prop in meta) return { configurable: true, enumerable: true, value: meta[prop] };
      }
    });
  }
});

export {
  WSTG_METHODOLOGY,
  ZAP_ALERT_CATALOG,
  TECH_SCAN_POLICIES,
  ZAP_AUTH_STRATEGIES,
  LLM_REASONING_PROMPTS,
  ZAP_PENTEST_WORKFLOW,
  VULN_PAYLOADS,
  ZAP_FALSE_POSITIVE_PATTERNS,
  initZapKnowledge,
  getWSTGMethodologyContext,
  getZAPAlertCatalogContext,
  getTechScanPolicyContext,
  getZAPAuthContext,
  getZAPReasoningPrompt,
  getZAPWorkflowContext,
  getVulnPayloadContext,
  buildZAPKnowledgeContext,
  getFalsePositiveTriageContext,
  getCompactFPTriage,
  getZapKnowledgeMetadata,
  ZAP_KNOWLEDGE_METADATA,
  init_zap_pentesting_knowledge
};
