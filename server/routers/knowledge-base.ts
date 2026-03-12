/**
 * Knowledge Base Router
 *
 * Provides tRPC procedures for the Knowledge Base admin page:
 *   - List all knowledge modules with metadata
 *   - Preview context output for each module with configurable params
 *   - View engagement phase mapping (which modules inject into which phases)
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getLOTLContext,
  getFileUploadBypassContext,
  getFirewallEvasionContext,
  getSocialEngineeringContext,
  getShodanReconContext,
  getSubdomainEnumContext,
  buildOffensiveTechniquesContext,
} from "../lib/knowledge/offensive-techniques-knowledge";
import {
  getGoPhishTemplatesContext,
  getPretextScriptsContext,
  getLandingPagePatternsContext,
  buildPhishingKnowledgeContext,
  GOPHISH_TEMPLATES,
  PRETEXT_SCRIPTS,
  LANDING_PAGE_PATTERNS,
  SOCIAL_ENGINEERING_TEMPLATES_METADATA,
} from "../lib/knowledge/social-engineering-templates";
import {
  buildZAPKnowledgeContext,
  getWSTGMethodologyContext,
  getZAPAlertCatalogContext,
  getTechScanPolicyContext,
  getZAPAuthContext,
  getZAPWorkflowContext,
  getVulnPayloadContext,
  getFalsePositiveTriageContext,
  ZAP_KNOWLEDGE_METADATA,
} from "../lib/knowledge/zap-pentesting-knowledge";
import {
  getPayloadCategories,
  getPayloadsByCategory,
  searchPayloads,
  getWafBypasses,
  getTechniques,
  getTools as getPayloadTools,
  getTrainingLabMapping,
  getPayloadsForLab,
  buildPayloadContext,
  buildMultiCategoryContext,
  getPayloadsMetadata,
} from "../lib/knowledge/payloads-knowledge";
import {
  OFFENSIVE_TOOLS,
  getToolsForLab,
  getToolsByCategory,
  searchTools,
  getToolStats,
  buildToolRecommendationContext,
  buildAttackPlannerToolContext,
} from "../lib/knowledge/offensive-tools-knowledge";
import {
  getAllBugBountyTools,
  getAllMethodologies,
  getWorkflow,
  buildMethodologyContext,
  buildPhaseToolContext,
  buildVulnTestingContext,
  buildScanPlanningContext,
  getToolsByPhase,
  getMethodologiesByCategory,
  getBugBountyStats,
} from "../lib/knowledge/bugbounty-methodology-knowledge";

// ─── Module Registry ────────────────────────────────────────────────────────

export interface KnowledgeModule {
  id: string;
  name: string;
  category: "offensive" | "social_engineering" | "recon" | "evasion" | "web_app_testing" | "payloads";
  description: string;
  version: string;
  itemCount: number;
  mitreTechniques: string[];
  injectedInto: string[];
  phases: string[];
  platforms?: string[];
  status: "active" | "beta" | "deprecated";
}

function getModuleRegistry(): KnowledgeModule[] {
  return [
    {
      id: "lotl-resources",
      name: "Living Off the Land (LOTL)",
      category: "offensive",
      description: "Curated list of legitimate binaries, drivers, and APIs that can be abused for LOTL techniques across Windows, Linux, and macOS. Includes GTFOBins, LOLBAS, LOOBins, LOLDrivers, MalAPI, HijackLibs, WADComs, LOTS Project, FileSec, and LoFP.",
      version: "1.0.0",
      itemCount: 10,
      mitreTechniques: ["T1059.004", "T1548.001", "T1218", "T1216", "T1068", "T1014", "T1055", "T1574.001", "T1087", "T1102", "T1204.002"],
      injectedInto: ["engagement-orchestrator.ts", "ai-attack-planner.ts", "chain-builder.ts"],
      phases: ["exploitation", "post_exploitation"],
      platforms: ["windows", "linux", "macos", "cross-platform"],
      status: "active",
    },
    {
      id: "file-upload-bypass",
      name: "File Upload Extension Filter Bypass",
      category: "evasion",
      description: "Extension splitting, null byte injection, Unicode overlong encoding, and other techniques to bypass file upload validation. Covers 7 bypass categories with specific payloads for each.",
      version: "1.0.0",
      itemCount: 7,
      mitreTechniques: ["T1027", "T1036", "T1204.002"],
      injectedInto: ["engagement-orchestrator.ts", "llm-scan-feedback.ts"],
      phases: ["enumeration", "vuln_detection", "exploitation"],
      status: "active",
    },
    {
      id: "firewall-evasion",
      name: "Firewall Testing & Evasion",
      category: "evasion",
      description: "25 tools mapped to firewall testing and evasion techniques including port scanning, fragmentation, tunneling (ICMP, DNS, HTTP, SSH), SSL/TLS interception, WAF testing, and protocol-specific evasion.",
      version: "1.0.0",
      itemCount: 25,
      mitreTechniques: ["T1572", "T1090", "T1095", "T1071", "T1048"],
      injectedInto: ["engagement-orchestrator.ts", "llm-scan-feedback.ts"],
      phases: ["enumeration", "vuln_detection", "post_exploitation"],
      status: "active",
    },
    {
      id: "social-engineering-taxonomy",
      name: "Social Engineering Attack Taxonomy",
      category: "social_engineering",
      description: "Comprehensive taxonomy of social engineering attacks: Phishing (7 sub-techniques), Pretexting (7), Baiting (7), Quid Pro Quo (7), and Tailgating (7). Each with MITRE ATT&CK mappings and behavioral indicators.",
      version: "1.0.0",
      itemCount: 35,
      mitreTechniques: ["T1566", "T1598", "T1091", "T1598.003", "T1200"],
      injectedInto: ["engagement-orchestrator.ts", "phishing-ops.ts"],
      phases: ["recon", "exploitation"],
      status: "active",
    },
    {
      id: "shodan-recon",
      name: "Shodan Filters & Queries",
      category: "recon",
      description: "Pre-built Shodan search queries for discovering exposed databases, web servers, remote access services, IoT/ICS systems, and more. Includes CLI commands, common filters, and recon strategy.",
      version: "1.0.0",
      itemCount: 20,
      mitreTechniques: ["T1595", "T1596"],
      injectedInto: ["engagement-orchestrator.ts"],
      phases: ["recon", "enumeration"],
      status: "active",
    },
    {
      id: "subdomain-enumeration",
      name: "Subdomain Enumeration Tools",
      category: "recon",
      description: "40+ subdomain enumeration tools categorized by tier (primary, secondary, specialized) and method (passive, active, both). Includes Subfinder, Amass, Sublist3r, dnsenum, and many more.",
      version: "1.0.0",
      itemCount: 40,
      mitreTechniques: ["T1595.002", "T1596.001"],
      injectedInto: ["engagement-orchestrator.ts"],
      phases: ["recon", "enumeration"],
      status: "active",
    },
    {
      id: "gophish-templates",
      name: "GoPhish Email Templates",
      category: "social_engineering",
      description: `${SOCIAL_ENGINEERING_TEMPLATES_METADATA.templateCount} proven phishing email templates covering BEC, credential harvest, IT support, invoice lure, compliance, shared doc, MFA reset, and delivery notification. Each with GoPhish placeholders, MITRE mappings, and success metrics.`,
      version: "1.0.0",
      itemCount: SOCIAL_ENGINEERING_TEMPLATES_METADATA.templateCount,
      mitreTechniques: SOCIAL_ENGINEERING_TEMPLATES_METADATA.mitreTechniques,
      injectedInto: ["phishing-ops.ts"],
      phases: ["exploitation"],
      status: "active",
    },
    {
      id: "pretext-scripts",
      name: "Pretext Scripts & Playbooks",
      category: "social_engineering",
      description: `${SOCIAL_ENGINEERING_TEMPLATES_METADATA.pretextScriptCount} pretext scripts covering phishing, pretexting, baiting, quid pro quo, and tailgating. Each with opening lines, key talking points, escalation triggers, exit strategies, and target profiles.`,
      version: "1.0.0",
      itemCount: SOCIAL_ENGINEERING_TEMPLATES_METADATA.pretextScriptCount,
      mitreTechniques: SOCIAL_ENGINEERING_TEMPLATES_METADATA.mitreTechniques,
      injectedInto: ["phishing-ops.ts"],
      phases: ["exploitation"],
      status: "active",
    },
    {
      id: "landing-page-patterns",
      name: "Landing Page Patterns",
      category: "social_engineering",
      description: `${SOCIAL_ENGINEERING_TEMPLATES_METADATA.landingPagePatternCount} landing page patterns for credential harvesting: login clone, document viewer, MFA prompt, and form submission. Each with capture fields and best practices.`,
      version: "1.0.0",
      itemCount: SOCIAL_ENGINEERING_TEMPLATES_METADATA.landingPagePatternCount,
      mitreTechniques: ["T1566.002", "T1556.006"],
      injectedInto: ["phishing-ops.ts"],
      phases: ["exploitation"],
      status: "active",
    },
    {
      id: "zap-wstg-methodology",
      name: "OWASP WSTG v4.2 Methodology (ZAP-Mapped)",
      category: "web_app_testing",
      description: `${ZAP_KNOWLEDGE_METADATA.wstgCategories} WSTG testing categories with ${ZAP_KNOWLEDGE_METADATA.wstgTests} individual tests (${ZAP_KNOWLEDGE_METADATA.automatableTests} automatable). Each test mapped to specific ZAP scan rule IDs with approach guidance.`,
      version: ZAP_KNOWLEDGE_METADATA.version,
      itemCount: ZAP_KNOWLEDGE_METADATA.wstgTests,
      mitreTechniques: ["T1190", "T1133", "T1059.007", "T1505.003", "T1071.001"],
      injectedInto: ["engagement-orchestrator.ts", "zap-scanner.ts"],
      phases: ["vuln_detection", "exploitation"],
      status: "active",
    },
    {
      id: "zap-alert-catalog",
      name: "ZAP Alert Catalog (Foothold-Prioritized)",
      category: "web_app_testing",
      description: `${ZAP_KNOWLEDGE_METADATA.alertCatalogSize} ZAP alerts (${ZAP_KNOWLEDGE_METADATA.activeAlerts} active, ${ZAP_KNOWLEDGE_METADATA.passiveAlerts} passive) with severity, CWE, OWASP Top 10 mappings, and foothold potential ratings.`,
      version: ZAP_KNOWLEDGE_METADATA.version,
      itemCount: ZAP_KNOWLEDGE_METADATA.alertCatalogSize,
      mitreTechniques: ["T1190", "T1059", "T1505.003", "T1552", "T1552.001"],
      injectedInto: ["engagement-orchestrator.ts", "zap-scanner.ts"],
      phases: ["vuln_detection", "exploitation"],
      status: "active",
    },
    {
      id: "zap-tech-scan-policies",
      name: "Technology-Specific ZAP Scan Policies",
      category: "web_app_testing",
      description: `${ZAP_KNOWLEDGE_METADATA.techPolicies} technology-specific scan policies (PHP, Java/Spring, Python, Node.js, ASP.NET, WordPress, API) with critical rule configurations, fingerprints, and secrets discovery rules.`,
      version: ZAP_KNOWLEDGE_METADATA.version,
      itemCount: ZAP_KNOWLEDGE_METADATA.techPolicies,
      mitreTechniques: ["T1190", "T1592.002"],
      injectedInto: ["engagement-orchestrator.ts", "zap-scanner.ts"],
      phases: ["enumeration", "vuln_detection"],
      status: "active",
    },
    {
      id: "zap-auth-strategies",
      name: "ZAP Authentication Strategies",
      category: "web_app_testing",
      description: `${ZAP_KNOWLEDGE_METADATA.authStrategies} authentication strategies (form, JSON, HTTP Basic, script, browser) with ZAP API configuration, logged-in/out indicators, and setup steps.`,
      version: ZAP_KNOWLEDGE_METADATA.version,
      itemCount: ZAP_KNOWLEDGE_METADATA.authStrategies,
      mitreTechniques: ["T1078", "T1110"],
      injectedInto: ["engagement-orchestrator.ts", "zap-scanner.ts"],
      phases: ["vuln_detection"],
      status: "active",
    },
    {
      id: "zap-vuln-payloads",
      name: "Vulnerability Test Payloads",
      category: "web_app_testing",
      description: `${ZAP_KNOWLEDGE_METADATA.payloadSets} payload sets with ${ZAP_KNOWLEDGE_METADATA.totalPayloads} total payloads for SQLi, XSS, command injection, SSTI, path traversal, and XXE. Each with context and expected results.`,
      version: ZAP_KNOWLEDGE_METADATA.version,
      itemCount: ZAP_KNOWLEDGE_METADATA.totalPayloads,
      mitreTechniques: ["T1190", "T1059", "T1505.003"],
      injectedInto: ["engagement-orchestrator.ts"],
      phases: ["exploitation"],
      status: "active",
    },
    {
      id: "zap-fp-triage",
      name: "ZAP False Positive Triage Guide",
      category: "web_app_testing",
      description: `${ZAP_KNOWLEDGE_METADATA.falsePositivePatterns} false positive patterns covering high-FP-rate ZAP alerts with FP/TP indicators, verification steps, and triage guidance. Reduces noise in scan results.`,
      version: ZAP_KNOWLEDGE_METADATA.version,
      itemCount: ZAP_KNOWLEDGE_METADATA.falsePositivePatterns,
      mitreTechniques: [],
      injectedInto: ["engagement-orchestrator.ts", "llm-scan-feedback.ts"],
      phases: ["vuln_detection", "exploitation", "reporting"],
      status: "active",
    },
    {
      id: "payloads-all-the-things",
      name: "PayloadsAllTheThings",
      category: "payloads",
      description: `${getPayloadsMetadata().total_payloads} payloads across ${getPayloadsMetadata().total_categories} vulnerability categories from swisskyrepo/PayloadsAllTheThings. Includes WAF bypass techniques, detection patterns, MITRE ATT&CK mappings, and training lab correlations.`,
      version: getPayloadsMetadata().version,
      itemCount: getPayloadsMetadata().total_payloads,
      mitreTechniques: ["T1190", "T1059", "T1505.003", "T1027", "T1036"],
      injectedInto: ["engagement-orchestrator.ts", "llm-scan-feedback.ts", "training-lab.ts"],
      phases: ["enumeration", "vuln_detection", "exploitation"],
      status: "active",
    },
    {
      id: "offensive-tools-taxonomy",
      name: "Offensive Security Tools",
      category: "offensive",
      description: `${getToolStats().totalTools} offensive security tools across ${Object.keys(getToolStats().categories).length} categories (Reconnaissance, Exploitation, Post-Exploitation, WebApp Pentesting, API Testing, Cloud Security, etc.). Includes CLI patterns, lab applicability, and MITRE ATT&CK tactic mappings.`,
      version: "1.0.0",
      itemCount: getToolStats().totalTools,
      mitreTechniques: ["T1595", "T1190", "T1059", "T1046", "T1110", "T1071"],
      injectedInto: ["engagement-orchestrator.ts", "ai-attack-planner.ts"],
      phases: ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"],
      status: "active",
    },
    {
      id: "bugbounty-methodology",
      name: "Bug Bounty Methodology & Tools",
      category: "offensive",
      description: `${getBugBountyStats().totalTools} bug bounty tools, ${getBugBountyStats().totalMethodologies} attack methodologies, and ${getBugBountyStats().workflowSteps}-step workflow covering the full bug bounty lifecycle. Includes vulnerability testing patterns (SQLi, XSS, SSRF, IDOR, etc.), phase-specific tool recommendations, and scan planning context.`,
      version: "1.0.0",
      itemCount: getBugBountyStats().totalTools + getBugBountyStats().totalMethodologies,
      mitreTechniques: ["T1190", "T1059", "T1046", "T1595", "T1071", "T1110", "T1557"],
      injectedInto: ["engagement-orchestrator.ts", "ai-attack-planner.ts", "llm-scan-feedback.ts", "engagement-ops-core.ts"],
      phases: ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"],
      status: "active",
    },
  ];
}

// ─── Phase Mapping ──────────────────────────────────────────────────────────

interface PhaseMapping {
  phase: string;
  description: string;
  modules: string[];
  conditions: string[];
}

function getPhaseMapping(): PhaseMapping[] {
  return [
    {
      phase: "recon",
      description: "Initial reconnaissance and target discovery",
      modules: ["subdomain-enumeration", "shodan-recon", "social-engineering-taxonomy", "bugbounty-methodology"],
      conditions: ["Always injected for recon", "Shodan injected by default", "Social engineering when includePhishing=true", "Bug bounty methodology always injected"],
    },
    {
      phase: "enumeration",
      description: "Active enumeration and service discovery",
      modules: ["subdomain-enumeration", "shodan-recon", "firewall-evasion", "file-upload-bypass", "bugbounty-methodology"],
      conditions: ["Always injected for enumeration", "Firewall evasion when hasFirewall=true or hasWAF=true", "File upload bypass when hasFileUpload=true", "Bug bounty methodology always injected"],
    },
    {
      phase: "vuln_detection",
      description: "Vulnerability scanning and detection",
      modules: ["firewall-evasion", "file-upload-bypass", "zap-wstg-methodology", "zap-alert-catalog", "zap-tech-scan-policies", "zap-auth-strategies", "zap-fp-triage", "bugbounty-methodology"],
      conditions: ["Firewall evasion when hasFirewall=true or hasWAF=true", "File upload bypass when hasFileUpload=true", "ZAP WSTG/alerts always injected for web app targets", "Tech scan policies based on detected technology", "Auth strategies when credentials available", "FP triage always injected for scan result classification"],
    },
    {
      phase: "exploitation",
      description: "Vulnerability exploitation and initial access",
      modules: ["lotl-resources", "file-upload-bypass", "gophish-templates", "pretext-scripts", "landing-page-patterns", "zap-alert-catalog", "zap-vuln-payloads", "zap-fp-triage", "bugbounty-methodology"],
      conditions: ["LOTL always injected (platform-filtered)", "File upload bypass when hasFileUpload=true", "Phishing templates when includePhishing=true", "ZAP alert catalog and payloads for web app exploitation", "FP triage for finding classification"],
    },
    {
      phase: "post_exploitation",
      description: "Post-exploitation, lateral movement, and persistence",
      modules: ["lotl-resources", "firewall-evasion"],
      conditions: ["LOTL always injected (platform-filtered)", "Firewall evasion when hasFirewall=true or hasWAF=true"],
    },
    {
      phase: "reporting",
      description: "Final reporting and documentation",
      modules: ["zap-fp-triage"],
      conditions: ["FP triage injected for final finding classification and noise reduction"],
    },
  ];
}

// ─── Router ─────────────────────────────────────────────────────────────────

export const knowledgeBaseRouter = router({
  /** List all knowledge modules with metadata */
  listModules: protectedProcedure.query(() => {
    return getModuleRegistry();
  }),

  /** Get a single module's details */
  getModule: protectedProcedure
    .input(z.object({ moduleId: z.string() }))
    .query(({ input }) => {
      const modules = getModuleRegistry();
      const mod = modules.find(m => m.id === input.moduleId);
      if (!mod) return null;
      return mod;
    }),

  /** Preview the context output for a specific module with configurable params */
  previewContext: protectedProcedure
    .input(z.object({
      moduleId: z.string(),
      platform: z.enum(["windows", "linux", "macos"]).optional(),
      category: z.string().optional(),
      hasFirewall: z.boolean().optional(),
      hasWAF: z.boolean().optional(),
    }))
    .query(({ input }) => {
      let context = "";
      let charCount = 0;
      let estimatedTokens = 0;

      switch (input.moduleId) {
        case "lotl-resources":
          context = getLOTLContext(input.platform);
          break;
        case "file-upload-bypass":
          context = getFileUploadBypassContext();
          break;
        case "firewall-evasion":
          context = getFirewallEvasionContext(input.hasFirewall ?? true, input.hasWAF ?? false);
          break;
        case "social-engineering-taxonomy":
          context = getSocialEngineeringContext(input.category);
          break;
        case "shodan-recon":
          context = getShodanReconContext(input.category);
          break;
        case "subdomain-enumeration":
          context = getSubdomainEnumContext();
          break;
        case "gophish-templates":
          context = getGoPhishTemplatesContext(input.category as any);
          break;
        case "pretext-scripts":
          context = getPretextScriptsContext(input.category as any);
          break;
        case "landing-page-patterns":
          context = getLandingPagePatternsContext();
          break;
        case "zap-wstg-methodology":
          context = getWSTGMethodologyContext();
          break;
        case "zap-alert-catalog":
          context = getZAPAlertCatalogContext("medium");
          break;
        case "zap-tech-scan-policies":
          context = getTechScanPolicyContext(input.platform || undefined);
          break;
        case "zap-auth-strategies":
          context = getZAPAuthContext();
          break;
        case "zap-vuln-payloads":
          context = getVulnPayloadContext();
          break;
        case "zap-fp-triage":
          context = getFalsePositiveTriageContext();
          break;
        case "payloads-all-the-things":
          context = buildPayloadContext(input.category || "SQL Injection");
          break;
        case "offensive-tools-taxonomy":
          context = buildAttackPlannerToolContext(input.category || undefined);
          break;
        case "bugbounty-methodology":
          context = [
            buildMethodologyContext(),
            buildVulnTestingContext('sql_injection'),
            buildPhaseToolContext(input.category as any || 'recon'),
          ].filter(Boolean).join('\n\n');
          break;
        default:
          context = "Module not found";
      }

      charCount = context.length;
      estimatedTokens = Math.ceil(charCount / 4); // rough estimate

      return { context, charCount, estimatedTokens };
    }),

  /** Preview the composite context for a specific engagement phase */
  previewPhaseContext: protectedProcedure
    .input(z.object({
      phase: z.enum(["recon", "enumeration", "vuln_detection", "exploitation", "post_exploitation", "reporting"]),
      platform: z.enum(["windows", "linux", "macos"]).optional(),
      hasFirewall: z.boolean().optional(),
      hasWAF: z.boolean().optional(),
      hasFileUpload: z.boolean().optional(),
      includePhishing: z.boolean().optional(),
      includeShodan: z.boolean().optional(),
    }))
    .query(({ input }) => {
      const offensiveCtx = buildOffensiveTechniquesContext(input);
      const phishingCtx = input.includePhishing ? buildPhishingKnowledgeContext() : "";
      const zapCtx = buildZAPKnowledgeContext({
        phase: input.phase as any,
        technology: input.platform || undefined,
        footholdMinimum: 'medium',
      });
      const toolsCtx = buildToolRecommendationContext({
        phase: input.phase,
        hasWebApp: true,
        hasAPI: false,
      });
      const methodologyCtx = buildMethodologyContext();
      const phaseToolCtx = buildPhaseToolContext(input.phase as any);
      const combined = [offensiveCtx, phishingCtx, zapCtx, toolsCtx, methodologyCtx, phaseToolCtx].filter(Boolean).join("\n\n---\n\n");

      return {
        context: combined,
        charCount: combined.length,
        estimatedTokens: Math.ceil(combined.length / 4),
        modulesIncluded: getPhaseMapping().find(p => p.phase === input.phase)?.modules || [],
      };
    }),

  /** Get the phase mapping visualization data */
  getPhaseMapping: protectedProcedure.query(() => {
    return getPhaseMapping();
  }),

  /** Get summary statistics */
  getStats: protectedProcedure.query(() => {
    const modules = getModuleRegistry();
    const totalItems = modules.reduce((sum, m) => sum + m.itemCount, 0);
    const totalMitre = new Set(modules.flatMap(m => m.mitreTechniques)).size;
    const totalInjectionPoints = new Set(modules.flatMap(m => m.injectedInto)).size;

    return {
      totalModules: modules.length,
      totalItems,
      totalMitreTechniques: totalMitre,
      totalInjectionPoints,
      categoryCounts: {
        offensive: modules.filter(m => m.category === "offensive").length,
        social_engineering: modules.filter(m => m.category === "social_engineering").length,
        recon: modules.filter(m => m.category === "recon").length,
        evasion: modules.filter(m => m.category === "evasion").length,
        web_app_testing: modules.filter(m => m.category === "web_app_testing").length,
        payloads: modules.filter(m => m.category === "payloads").length,
      },
      statusCounts: {
        active: modules.filter(m => m.status === "active").length,
        beta: modules.filter(m => m.status === "beta").length,
        deprecated: modules.filter(m => m.status === "deprecated").length,
      },
    };
  }),
});
