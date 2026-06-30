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
import {
  CREDENTIAL_DUMP_TECHNIQUES,
  LATERAL_MOVE_TECHNIQUES,
  DOMAIN_ESCALATION_TECHNIQUES,
  SERVICE_EXPLOIT_TECHNIQUES,
  buildFullPostExploitKnowledgeContext,
  buildCredentialDumpContext,
  buildLateralMoveContext,
} from "../lib/knowledge/post-exploit-credential-knowledge";
import { VNC_EXPLOIT_TEMPLATES, buildVncExploitContext } from "../lib/vnc-exploit-module";
import { MSSQL_EXPLOIT_TEMPLATES, buildMssqlExploitContext } from "../lib/mssql-exploit-module";
import { getDb } from "../db";
import { knowledgeEntries } from "../../drizzle/schema";
import { eq, like, and, or, sql, desc } from "drizzle-orm";
import { randomUUID } from "crypto";

// ─── Module Registry ────────────────────────────────────────────────────────

export interface KnowledgeModule {
  id: string;
  name: string;
  category: "offensive" | "social_engineering" | "recon" | "evasion" | "web_app_testing" | "payloads" | "post_exploitation" | "exploit_template";
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
      id: "post-exploit-credentials",
      name: "Post-Exploit Credential & Lateral Movement Knowledge",
      category: "post_exploitation" as any,
      description: `${CREDENTIAL_DUMP_TECHNIQUES.length} credential dumping techniques, ${LATERAL_MOVE_TECHNIQUES.length} lateral movement techniques, ${DOMAIN_ESCALATION_TECHNIQUES.length} domain escalation techniques, and ${SERVICE_EXPLOIT_TECHNIQUES.length} service exploitation techniques. Extracted from Hacking Articles with full tool commands, MITRE mappings, and detection indicators.`,
      version: "1.0.0",
      itemCount: CREDENTIAL_DUMP_TECHNIQUES.length + LATERAL_MOVE_TECHNIQUES.length + DOMAIN_ESCALATION_TECHNIQUES.length + SERVICE_EXPLOIT_TECHNIQUES.length,
      mitreTechniques: ["T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1550.002", "T1021.002", "T1021.003", "T1021.006", "T1187"],
      injectedInto: ["functional-exploit-generator.ts", "pentest-report-pipeline.ts", "engagement-ops-core.ts"],
      phases: ["exploitation", "post_exploitation"],
      platforms: ["windows", "linux"],
      status: "active",
    },
    {
      id: "vnc-exploit-templates",
      name: "VNC Exploitation Module",
      category: "exploit_template" as any,
      description: `${VNC_EXPLOIT_TEMPLATES.length} pre-built VNC exploit templates covering RFB auth bypass, clipboard hijacking, framebuffer screenshot, keystroke injection, VNC tunneling, and session hijacking. Auto-injected when VNC ports (5900-5903) detected.`,
      version: "1.0.0",
      itemCount: VNC_EXPLOIT_TEMPLATES.length,
      mitreTechniques: ["T1021.005", "T1056.001", "T1113", "T1115", "T1572"],
      injectedInto: ["functional-exploit-generator.ts", "engagement-ops-core.ts"],
      phases: ["exploitation", "post_exploitation"],
      platforms: ["windows", "linux"],
      status: "active",
    },
    {
      id: "mssql-exploit-templates",
      name: "MSSQL Exploitation Module",
      category: "exploit_template" as any,
      description: `${MSSQL_EXPLOIT_TEMPLATES.length} pre-built MSSQL exploit templates covering xp_cmdshell, linked server abuse, CLR assembly injection, OLE automation, credential extraction, and Impacket-based attacks. Auto-injected when MSSQL ports (1433-1434) detected.`,
      version: "1.0.0",
      itemCount: MSSQL_EXPLOIT_TEMPLATES.length,
      mitreTechniques: ["T1059.001", "T1059.003", "T1505.001", "T1210", "T1557"],
      injectedInto: ["functional-exploit-generator.ts", "engagement-ops-core.ts"],
      phases: ["exploitation", "post_exploitation"],
      platforms: ["windows", "linux"],
      status: "active",
    },
    {
      id: "bugbounty-methodology",
      name: "Bug Bounty Methodology & Tools",
      category: "offensive",
      description: `${getBugBountyStats().total_tools} bug bounty tools, ${getBugBountyStats().total_methodologies} attack methodologies, and ${getBugBountyStats().total_workflow_steps}-step workflow covering the full bug bounty lifecycle. Includes vulnerability testing patterns (SQLi, XSS, SSRF, IDOR, etc.), phase-specific tool recommendations, and scan planning context.`,
      version: "1.0.0",
      itemCount: getBugBountyStats().total_tools + getBugBountyStats().total_methodologies,
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
      modules: ["lotl-resources", "firewall-evasion", "post-exploit-credentials", "vnc-exploit-templates", "mssql-exploit-templates"],
      conditions: ["LOTL always injected (platform-filtered)", "Firewall evasion when hasFirewall=true or hasWAF=true", "Post-exploit credentials always injected", "VNC templates when VNC ports detected", "MSSQL templates when MSSQL ports detected"],
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
        case "post-exploit-credentials":
          context = buildFullPostExploitKnowledgeContext({ platform: input.platform || 'windows' });
          break;
        case "vnc-exploit-templates":
          context = buildVncExploitContext({});
          break;
        case "mssql-exploit-templates":
          context = buildMssqlExploitContext({});
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

  // ─── User-Added Knowledge CRUD ───────────────────────────────────────────

  /** List user-added knowledge entries with search/filter */
  listUserEntries: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      category: z.string().optional(),
      phase: z.string().optional(),
      limit: z.number().min(1).max(200).default(100),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const conditions: any[] = [eq(knowledgeEntries.isActive, 1)];
      if (input.category) conditions.push(eq(knowledgeEntries.category, input.category));
      if (input.phase) conditions.push(eq(knowledgeEntries.phase, input.phase));
      if (input.search) {
        conditions.push(or(
          like(knowledgeEntries.name, `%${input.search}%`),
          like(knowledgeEntries.description, `%${input.search}%`)
        )!);
      }
      const db = await getDb();
      const rows = await db.select().from(knowledgeEntries)
        .where(and(...conditions))
        .orderBy(desc(knowledgeEntries.createdAt))
        .limit(input.limit)
        .offset(input.offset);
      const countResult = await db.select({ count: sql<number>`COUNT(*)` })
        .from(knowledgeEntries).where(and(...conditions));
      return { entries: rows, total: countResult[0]?.count || 0 };
    }),

  /** Create a new user-added knowledge entry */
  createEntry: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      category: z.string().min(1).max(64),
      subcategory: z.string().max(64).optional(),
      description: z.string().min(1),
      mitreTechniqueIds: z.array(z.string()).optional(),
      phase: z.string().min(1).max(64),
      targetPlatform: z.string().max(32).optional(),
      requiredPrivilege: z.string().max(32).optional(),
      tools: z.array(z.object({ name: z.string(), command: z.string(), description: z.string() })).optional(),
      code: z.string().optional(),
      language: z.string().max(32).optional(),
      prerequisites: z.array(z.string()).optional(),
      detectionIndicators: z.array(z.string()).optional(),
      postExploitActions: z.array(z.string()).optional(),
      verificationSteps: z.array(z.string()).optional(),
      opsecRisk: z.number().min(1).max(10).optional(),
      confidence: z.number().min(0).max(100).optional(),
      source: z.string().max(255).optional(),
      sourceUrl: z.string().max(512).optional(),
      tags: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const entryId = `USER-${randomUUID().slice(0, 8).toUpperCase()}`;
      const db = await getDb();
      await db.insert(knowledgeEntries).values({
        entryId,
        name: input.name,
        category: input.category,
        subcategory: input.subcategory || null,
        description: input.description,
        mitreTechniqueIds: input.mitreTechniqueIds || null,
        phase: input.phase,
        targetPlatform: input.targetPlatform || 'both',
        requiredPrivilege: input.requiredPrivilege || null,
        tools: input.tools || null,
        code: input.code || null,
        language: input.language || null,
        prerequisites: input.prerequisites || null,
        detectionIndicators: input.detectionIndicators || null,
        postExploitActions: input.postExploitActions || null,
        verificationSteps: input.verificationSteps || null,
        opsecRisk: input.opsecRisk || null,
        confidence: input.confidence || null,
        source: input.source || 'user',
        sourceUrl: input.sourceUrl || null,
        tags: input.tags || null,
        createdBy: ctx.user.name || ctx.user.openId,
      });
      return { entryId, success: true };
    }),

  /** Update a user-added entry */
  updateEntry: protectedProcedure
    .input(z.object({
      entryId: z.string(),
      name: z.string().min(1).max(255).optional(),
      description: z.string().optional(),
      mitreTechniqueIds: z.array(z.string()).optional(),
      tools: z.array(z.object({ name: z.string(), command: z.string(), description: z.string() })).optional(),
      code: z.string().optional(),
      language: z.string().max(32).optional(),
      prerequisites: z.array(z.string()).optional(),
      detectionIndicators: z.array(z.string()).optional(),
      postExploitActions: z.array(z.string()).optional(),
      verificationSteps: z.array(z.string()).optional(),
      opsecRisk: z.number().min(1).max(10).optional(),
      confidence: z.number().min(0).max(100).optional(),
      tags: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const updates: any = {};
      if (input.name) updates.name = input.name;
      if (input.description) updates.description = input.description;
      if (input.mitreTechniqueIds) updates.mitreTechniqueIds = input.mitreTechniqueIds;
      if (input.tools) updates.tools = input.tools;
      if (input.code !== undefined) updates.code = input.code;
      if (input.language !== undefined) updates.language = input.language;
      if (input.prerequisites) updates.prerequisites = input.prerequisites;
      if (input.detectionIndicators) updates.detectionIndicators = input.detectionIndicators;
      if (input.postExploitActions) updates.postExploitActions = input.postExploitActions;
      if (input.verificationSteps) updates.verificationSteps = input.verificationSteps;
      if (input.opsecRisk !== undefined) updates.opsecRisk = input.opsecRisk;
      if (input.confidence !== undefined) updates.confidence = input.confidence;
      if (input.tags) updates.tags = input.tags;
      const db = await getDb();
      await db.update(knowledgeEntries).set(updates).where(eq(knowledgeEntries.entryId, input.entryId));
      return { success: true };
    }),

  /** Soft-delete a user-added entry */
  deleteEntry: protectedProcedure
    .input(z.object({ entryId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.update(knowledgeEntries).set({ isActive: 0 }).where(eq(knowledgeEntries.entryId, input.entryId));
      return { success: true };
    }),

  /** Get all categories with counts (built-in + user-added) */
  getCategories: protectedProcedure.query(async () => {
    const modules = getModuleRegistry();
    const catMap = new Map<string, number>();
    for (const m of modules) catMap.set(m.category, (catMap.get(m.category) || 0) + 1);
    const db = await getDb();
    const dbCats = await db.select({ category: knowledgeEntries.category, count: sql<number>`COUNT(*)` })
      .from(knowledgeEntries).where(eq(knowledgeEntries.isActive, 1)).groupBy(knowledgeEntries.category);
    for (const row of dbCats) catMap.set(row.category, (catMap.get(row.category) || 0) + row.count);
    return Array.from(catMap.entries()).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  }),

  /** Get summary statistics */
   getStats: protectedProcedure.query(async () => {
    const modules = getModuleRegistry();
    const totalItems = modules.reduce((sum, m) => sum + (Number.isFinite(m.itemCount) ? m.itemCount : 0), 0);
    const totalMitre = new Set(modules.flatMap(m => m.mitreTechniques)).size;
    const totalInjectionPoints = new Set(modules.flatMap(m => m.injectedInto)).size;
    const db = await getDb();
    const dbCount = await db.select({ count: sql<number>`COUNT(*)` }).from(knowledgeEntries).where(eq(knowledgeEntries.isActive, 1));
    const userAddedCount = dbCount[0]?.count || 0;

    return {
      totalModules: modules.length,
      totalItems: totalItems + userAddedCount,
      totalUserAdded: userAddedCount,
      totalMitreTechniques: totalMitre,
      totalInjectionPoints,
      categoryCounts: {
        offensive: modules.filter(m => m.category === "offensive").length,
        social_engineering: modules.filter(m => m.category === "social_engineering").length,
        recon: modules.filter(m => m.category === "recon").length,
        evasion: modules.filter(m => m.category === "evasion").length,
        web_app_testing: modules.filter(m => m.category === "web_app_testing").length,
        payloads: modules.filter(m => m.category === "payloads").length,
        post_exploitation: modules.filter(m => m.category === ("post_exploitation" as any)).length,
        exploit_template: modules.filter(m => m.category === ("exploit_template" as any)).length,
      },
      statusCounts: {
        active: modules.filter(m => m.status === "active").length,
        beta: modules.filter(m => m.status === "beta").length,
        deprecated: modules.filter(m => m.status === "deprecated").length,
      },
    };
  }),
});
