/**
 * ScanForge Deep Research Agent
 * 
 * Continuously monitors all 30+ threat intelligence feeds and uses LLM analysis
 * to auto-generate new detection templates. This is the proactive improvement engine
 * that keeps ScanForge ahead of emerging threats.
 * 
 * Feed Categories:
 *   1. CVE/Exploit Feeds — NVD, CISA KEV, ExploitDB → detect newly weaponized vulns
 *   2. Reconnaissance Feeds — Shodan, Censys, SecurityTrails → detect exposed services
 *   3. Threat Actor Feeds — Spicy TIP, OTX, MalwareBazaar → detect actor-specific TTPs
 *   4. Breach/Darkweb Feeds — DeHashed, HIBP, Daily Dark Web → detect credential exposure
 *   5. Bug Bounty Feeds — HackerOne hacktivity → detect real-world exploit patterns
 *   6. Abuse Feeds — AbuseIPDB, abuse.ch, Tor, Blocklist.de → detect malicious infra
 *   7. Knowledge Base — OWASP, MITRE ATT&CK → map findings to frameworks
 * 
 * Architecture:
 *   - Each feed adapter normalizes data into ResearchInput
 *   - LLM analyzes ResearchInput and decides if a new template is warranted
 *   - Generated templates go to scanforge_generated_templates as "draft"
 *   - The reassessment agent can promote drafts to production after validation
 */

import { invokeLLM } from "../../_core/llm";
import { getDbRequired } from "../../db";
import { eq, desc, sql } from "drizzle-orm";
import {
  scanforgeResearchLog,
  scanforgeGeneratedTemplates,
  scanforgeTemplateMetrics,
} from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export type FeedSource =
  | "nvd" | "cisa_kev" | "exploitdb"
  | "shodan" | "censys" | "securitytrails" | "urlscan"
  | "abuseipdb" | "dehashed" | "hackerone"
  | "spicy_tip" | "abuse_ch" | "otx" | "malwarebazaar"
  | "ransomware_live" | "openphish" | "tor_exit" | "blocklist_de" | "spamhaus"
  | "hibp" | "daily_dark_web" | "intelx" | "hudson_rock" | "leak_check"
  | "knowledge_base" | "bug_bounty" | "exploit_matcher"
  | "corroboration_engine" | "vuln_feed_sync" | "discovery_engine";

export type ResearchType =
  | "cve_analysis" | "exploit_research" | "trend_analysis"
  | "gap_analysis" | "ttp_mapping" | "zero_day_monitoring"
  | "bug_bounty_pattern" | "credential_exposure" | "malware_analysis"
  | "threat_actor_ttp" | "service_exposure";

export interface ResearchInput {
  feedSource: FeedSource;
  researchType: ResearchType;
  subject: string; // CVE ID, domain, IP, threat actor, CWE, etc.
  data: Record<string, any>;
  urgency: "critical" | "high" | "medium" | "low";
}

export interface GeneratedTemplate {
  templateId: string;
  name: string;
  description: string;
  severity: string;
  category: string;
  detectionMethod: string;
  requests: Array<{
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: string;
  }>;
  matchers: Array<{
    type: string;
    condition: string;
    values: string[];
  }>;
  metadata: {
    cve?: string;
    cwe?: string;
    cvss?: number;
    references: string[];
    feedSource: FeedSource;
  };
}

export interface ResearchResult {
  actionable: boolean;
  generatedTemplates: GeneratedTemplate[];
  analysisResult: Record<string, any>;
}

// ─── Feed Adapters ──────────────────────────────────────────────────────────

/**
 * Adapter registry — maps feed sources to their data fetching functions.
 * Each adapter returns normalized ResearchInput items for LLM analysis.
 */
const feedAdapters: Record<string, () => Promise<ResearchInput[]>> = {};

/**
 * Register a feed adapter. Called during initialization.
 */
export function registerFeedAdapter(source: FeedSource, adapter: () => Promise<ResearchInput[]>): void {
  feedAdapters[source] = adapter;
}

// ─── CVE/Exploit Feed Adapters ──────────────────────────────────────────────

/**
 * Initialize all feed adapters with the actual service functions.
 * Called once at server startup.
 */
export async function initializeFeedAdapters(): Promise<void> {
  // CVE/Exploit Feeds
  registerFeedAdapter("nvd", async () => {
    try {
      const { getRecentZeroDays, getWeaponizedCves } = await import("../../lib/vuln-feed-sync");
      const zeroDays = await getRecentZeroDays(7); // last 7 days
      const weaponized = await getWeaponizedCves(7);
      
      const inputs: ResearchInput[] = [];
      for (const zd of (zeroDays || []).slice(0, 20)) {
        inputs.push({
          feedSource: "nvd",
          researchType: "zero_day_monitoring",
          subject: zd.cveId || zd.id || "unknown",
          data: zd,
          urgency: (zd.cvss || 0) >= 9 ? "critical" : (zd.cvss || 0) >= 7 ? "high" : "medium",
        });
      }
      for (const wc of (weaponized || []).slice(0, 20)) {
        inputs.push({
          feedSource: "nvd",
          researchType: "exploit_research",
          subject: wc.cveId || wc.id || "unknown",
          data: wc,
          urgency: "high",
        });
      }
      return inputs;
    } catch { return []; }
  });

  registerFeedAdapter("cisa_kev", async () => {
    try {
      const { getCISAKEV } = await import("../../lib/spicy-tip-bridge");
      const kev = await getCISAKEV();
      return (kev?.vulnerabilities || []).slice(0, 20).map((v: any) => ({
        feedSource: "cisa_kev" as FeedSource,
        researchType: "cve_analysis" as ResearchType,
        subject: v.cveID || v.cve || "unknown",
        data: v,
        urgency: "critical" as const,
      }));
    } catch { return []; }
  });

  // Reconnaissance Feeds
  registerFeedAdapter("shodan", async () => {
    try {
      const { queryShodan } = await import("../../lib/darkweb-osint-service");
      // Shodan is query-based, so we generate inputs from recent engagement targets
      return []; // Populated per-engagement via runTargetedResearch()
    } catch { return []; }
  });

  registerFeedAdapter("censys", async () => {
    try {
      const { queryCensys } = await import("../../lib/darkweb-osint-service");
      return []; // Populated per-engagement via runTargetedResearch()
    } catch { return []; }
  });

  registerFeedAdapter("securitytrails", async () => {
    try {
      const { querySecurityTrails } = await import("../../lib/darkweb-osint-service");
      return []; // Populated per-engagement via runTargetedResearch()
    } catch { return []; }
  });

  // Threat Actor Feeds
  registerFeedAdapter("spicy_tip", async () => {
    try {
      const { getRansomwareVictimStats, getThreatFoxIOCs, getActivityRatings } = await import("../../lib/spicy-tip-bridge");
      const inputs: ResearchInput[] = [];
      
      const iocs = await getThreatFoxIOCs?.();
      for (const ioc of (iocs || []).slice(0, 15)) {
        inputs.push({
          feedSource: "spicy_tip",
          researchType: "threat_actor_ttp",
          subject: ioc.threat_type || ioc.malware || "unknown",
          data: ioc,
          urgency: "high",
        });
      }
      return inputs;
    } catch { return []; }
  });

  registerFeedAdapter("abuse_ch", async () => {
    try {
      const { fetchFeodoTracker, fetchMalwareBazaar, fetchSSLBlacklist } = await import("../../lib/abuse-ch-feeds");
      const inputs: ResearchInput[] = [];
      
      const feodo = await fetchFeodoTracker?.();
      for (const entry of (feodo || []).slice(0, 10)) {
        inputs.push({
          feedSource: "abuse_ch",
          researchType: "malware_analysis",
          subject: entry.malware || entry.ip || "unknown",
          data: entry,
          urgency: "high",
        });
      }
      
      const bazaar = await fetchMalwareBazaar?.();
      for (const entry of (bazaar || []).slice(0, 10)) {
        inputs.push({
          feedSource: "abuse_ch",
          researchType: "malware_analysis",
          subject: entry.signature || entry.sha256 || "unknown",
          data: entry,
          urgency: "medium",
        });
      }
      return inputs;
    } catch { return []; }
  });

  registerFeedAdapter("otx", async () => {
    try {
      const { getOTXPulses } = await import("../../lib/spicy-tip-bridge");
      const pulses = await getOTXPulses?.();
      return (pulses || []).slice(0, 15).map((p: any) => ({
        feedSource: "otx" as FeedSource,
        researchType: "threat_actor_ttp" as ResearchType,
        subject: p.name || p.id || "unknown",
        data: p,
        urgency: "medium" as const,
      }));
    } catch { return []; }
  });

  // Bug Bounty Feeds
  registerFeedAdapter("hackerone", async () => {
    try {
      const { enrichAttackVectors, enrichThreatIntelligence } = await import("../../lib/bug-bounty-intelligence");
      const inputs: ResearchInput[] = [];
      
      // Get recent hacktivity patterns
      const attackVectors = await enrichAttackVectors?.("web_app");
      if (attackVectors?.patterns) {
        for (const pattern of attackVectors.patterns.slice(0, 10)) {
          inputs.push({
            feedSource: "hackerone",
            researchType: "bug_bounty_pattern",
            subject: pattern.name || pattern.cwe || "unknown",
            data: pattern,
            urgency: pattern.severity === "critical" ? "critical" : "medium",
          });
        }
      }
      return inputs;
    } catch { return []; }
  });

  registerFeedAdapter("bug_bounty", async () => {
    try {
      const { enrichDomainIntel } = await import("../../lib/bug-bounty-intelligence");
      return []; // Populated per-engagement via runTargetedResearch()
    } catch { return []; }
  });

  // Breach/Darkweb Feeds
  registerFeedAdapter("daily_dark_web", async () => {
    try {
      const { syncDailyDarkWebFeed } = await import("../../lib/darkweb-feeds");
      return []; // Darkweb sync runs separately, we analyze its output
    } catch { return []; }
  });

  registerFeedAdapter("ransomware_live", async () => {
    try {
      const { fetchRansomwareLiveVictims } = await import("../../lib/darkweb-feeds");
      const victims = await fetchRansomwareLiveVictims?.();
      return (victims || []).slice(0, 10).map((v: any) => ({
        feedSource: "ransomware_live" as FeedSource,
        researchType: "trend_analysis" as ResearchType,
        subject: v.group || v.actor || "unknown",
        data: v,
        urgency: "medium" as const,
      }));
    } catch { return []; }
  });

  // Abuse Feeds
  registerFeedAdapter("abuseipdb", async () => {
    try {
      const { queryAbuseIpdb } = await import("../../lib/darkweb-osint-service");
      return []; // Query-based, populated per-engagement
    } catch { return []; }
  });

  registerFeedAdapter("dehashed", async () => {
    try {
      const { queryDehashed } = await import("../../lib/darkweb-osint-service");
      return []; // Query-based, populated per-engagement
    } catch { return []; }
  });

  // Exploit Matcher
  registerFeedAdapter("exploit_matcher", async () => {
    try {
      const { matchExploitsToFindings } = await import("../../lib/exploit-matcher");
      return []; // Populated per-engagement after findings
    } catch { return []; }
  });

  // Knowledge Base
  registerFeedAdapter("knowledge_base", async () => {
    try {
      const { getKnowledgeModule } = await import("../../lib/knowledge-base");
      // Knowledge base is reference material, not a live feed
      return [];
    } catch { return []; }
  });

  console.log(`[ScanForge Deep Research] Initialized ${Object.keys(feedAdapters).length} feed adapters`);
}

// ─── Research Execution ─────────────────────────────────────────────────────

/**
 * Run a full research cycle across all active feeds.
 * Called on a schedule (e.g., every 6 hours) to discover new threats.
 */
export async function runResearchCycle(): Promise<{
  feedsQueried: number;
  inputsAnalyzed: number;
  templatesGenerated: number;
}> {
  console.log("[ScanForge Deep Research] Starting research cycle...");
  
  let totalInputs = 0;
  let totalTemplates = 0;
  let feedsQueried = 0;

  // Collect inputs from all feeds
  const allInputs: ResearchInput[] = [];
  
  for (const [source, adapter] of Object.entries(feedAdapters)) {
    try {
      const inputs = await adapter();
      if (inputs.length > 0) {
        allInputs.push(...inputs);
        feedsQueried++;
        console.log(`[ScanForge Deep Research] ${source}: ${inputs.length} research inputs`);
      }
    } catch (err) {
      console.warn(`[ScanForge Deep Research] ${source} adapter failed:`, (err as Error).message);
    }
  }

  totalInputs = allInputs.length;
  console.log(`[ScanForge Deep Research] Collected ${totalInputs} inputs from ${feedsQueried} feeds`);

  // Prioritize: critical first, then high, then medium
  const prioritized = allInputs.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.urgency] - order[b.urgency];
  });

  // Process in batches to avoid LLM rate limits
  const batchSize = 5;
  for (let i = 0; i < Math.min(prioritized.length, 50); i += batchSize) {
    const batch = prioritized.slice(i, i + batchSize);
    const results = await analyzeBatch(batch);
    
    for (const result of results) {
      if (result.actionable) {
        for (const template of result.generatedTemplates) {
          await storeGeneratedTemplate(template, batch[0].feedSource);
          totalTemplates++;
        }
      }
    }
  }

  console.log(`[ScanForge Deep Research] Cycle complete: ${totalTemplates} templates generated`);
  return { feedsQueried, inputsAnalyzed: totalInputs, templatesGenerated: totalTemplates };
}

/**
 * Run targeted research for a specific engagement's targets.
 * Uses recon feeds (Shodan, Censys, SecurityTrails) + bug bounty intel.
 */
export async function runTargetedResearch(
  engagementId: string,
  targets: string[], // IPs, domains, URLs
  targetType: string
): Promise<ResearchInput[]> {
  console.log(`[ScanForge Deep Research] Targeted research for ${engagementId}: ${targets.length} targets`);
  
  const inputs: ResearchInput[] = [];

  for (const target of targets.slice(0, 10)) {
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target);
    const domain = isIP ? null : target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];

    // Shodan lookup
    if (isIP) {
      try {
        const { shodanHostLookup } = await import("../../lib/darkweb-osint-service");
        const result = await shodanHostLookup?.(target);
        if (result) {
          inputs.push({
            feedSource: "shodan",
            researchType: "service_exposure",
            subject: target,
            data: result,
            urgency: "high",
          });
        }
      } catch {}
    }

    // Censys lookup
    if (isIP) {
      try {
        const { censysHostSearch } = await import("../../lib/darkweb-osint-service");
        const result = await censysHostSearch?.(target);
        if (result) {
          inputs.push({
            feedSource: "censys",
            researchType: "service_exposure",
            subject: target,
            data: result,
            urgency: "medium",
          });
        }
      } catch {}
    }

    // SecurityTrails for domains
    if (domain) {
      try {
        const { securityTrailsDomainInfo } = await import("../../lib/darkweb-osint-service");
        const result = await securityTrailsDomainInfo?.(domain);
        if (result) {
          inputs.push({
            feedSource: "securitytrails",
            researchType: "service_exposure",
            subject: domain,
            data: result,
            urgency: "medium",
          });
        }
      } catch {}
    }

    // Bug bounty intel for domains
    if (domain) {
      try {
        const { enrichDomainIntel } = await import("../../lib/bug-bounty-intelligence");
        const result = await enrichDomainIntel?.(domain);
        if (result) {
          inputs.push({
            feedSource: "bug_bounty",
            researchType: "bug_bounty_pattern",
            subject: domain,
            data: result,
            urgency: "medium",
          });
        }
      } catch {}
    }

    // AbuseIPDB reputation check
    if (isIP) {
      try {
        const { queryAbuseIpdb } = await import("../../lib/darkweb-osint-service");
        const result = await queryAbuseIpdb?.(target);
        if (result) {
          inputs.push({
            feedSource: "abuseipdb",
            researchType: "trend_analysis",
            subject: target,
            data: result,
            urgency: (result as any).abuseConfidenceScore > 80 ? "high" : "low",
          });
        }
      } catch {}
    }

    // Credential exposure check
    if (domain) {
      try {
        const { queryDehashed } = await import("../../lib/darkweb-osint-service");
        const result = await queryDehashed?.(domain);
        if (result) {
          inputs.push({
            feedSource: "dehashed",
            researchType: "credential_exposure",
            subject: domain,
            data: { resultCount: Array.isArray(result) ? result.length : 0, sample: Array.isArray(result) ? result.slice(0, 3) : [] },
            urgency: Array.isArray(result) && result.length > 100 ? "high" : "medium",
          });
        }
      } catch {}
    }

    // URLScan for web targets
    if (domain || target.startsWith("http")) {
      try {
        const { queryUrlscan } = await import("../../lib/darkweb-osint-service");
        const result = await queryUrlscan?.(domain || target);
        if (result) {
          inputs.push({
            feedSource: "urlscan",
            researchType: "service_exposure",
            subject: domain || target,
            data: result,
            urgency: "low",
          });
        }
      } catch {}
    }
  }

  // Log all research inputs
  for (const input of inputs) {
    const _db1 = await getDbRequired();
    await _db1.insert(scanforgeResearchLog).values({
      feedSource: input.feedSource,
      researchSubject: input.subject,
      researchType: input.researchType,
      analysisResult: input.data,
      actionable: false, // Will be updated after LLM analysis
    });
  }

  console.log(`[ScanForge Deep Research] Targeted research produced ${inputs.length} inputs`);
  return inputs;
}

// ─── LLM Analysis ───────────────────────────────────────────────────────────

/**
 * Analyze a batch of research inputs and generate detection templates.
 */
async function analyzeBatch(inputs: ResearchInput[]): Promise<ResearchResult[]> {
  const results: ResearchResult[] = [];

  for (const input of inputs) {
    try {
      const result = await analyzeResearchInput(input);
      results.push(result);

      // Update research log with actionability
      if (result.actionable) {
        const _db2 = await getDbRequired();
        await _db2.update(scanforgeResearchLog)
          .set({
            actionable: true,
            generatedTemplateIds: result.generatedTemplates.map(t => t.templateId),
          })
          .where(eq(scanforgeResearchLog.researchSubject, input.subject));
      }
    } catch (err) {
      console.warn(`[ScanForge Deep Research] Analysis failed for ${input.subject}:`, (err as Error).message);
      results.push({ actionable: false, generatedTemplates: [], analysisResult: {} });
    }
  }

  return results;
}

/**
 * Use LLM to analyze a single research input and decide if a template should be generated.
 */
async function analyzeResearchInput(input: ResearchInput): Promise<ResearchResult> {
  const prompt = buildAnalysisPrompt(input);

  try {
    const response = await invokeLLM({
      _caller: "deep-research-agent.analyzeIntelligence",
      messages: [
        {
          role: "system",
          content: `You are the ScanForge Deep Research Agent — an expert vulnerability researcher and detection engineer.
Your job is to analyze threat intelligence data and determine if new detection templates should be created for ScanForge.

ScanForge templates detect vulnerabilities by sending HTTP/TCP requests and matching responses.
Only generate templates for vulnerabilities that can be reliably detected via network scanning.

Template JSON schema:
{
  "actionable": boolean,
  "reason": "why this is/isn't actionable",
  "templates": [{
    "templateId": "unique-id",
    "name": "Human-readable name",
    "description": "What this detects",
    "severity": "critical|high|medium|low|info",
    "category": "sqli|xss|rce|ssrf|lfi|auth|misconfig|exposure|cve",
    "detectionMethod": "How the template detects this",
    "requests": [{ "method": "GET|POST", "path": "/path", "headers": {}, "body": "" }],
    "matchers": [{ "type": "status|body|header|regex", "condition": "and|or", "values": ["match1"] }],
    "metadata": { "cve": "CVE-XXXX-XXXXX", "cwe": "CWE-XX", "cvss": 9.8, "references": ["url"] }
  }]
}`
        },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "research_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              actionable: { type: "boolean" },
              reason: { type: "string" },
              templates: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    templateId: { type: "string" },
                    name: { type: "string" },
                    description: { type: "string" },
                    severity: { type: "string" },
                    category: { type: "string" },
                    detectionMethod: { type: "string" },
                    requests: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          method: { type: "string" },
                          path: { type: "string" },
                          headers: { type: "object", additionalProperties: true },
                          body: { type: "string" },
                        },
                        required: ["method", "path"],
                        additionalProperties: false,
                      },
                    },
                    matchers: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          type: { type: "string" },
                          condition: { type: "string" },
                          values: { type: "array", items: { type: "string" } },
                        },
                        required: ["type", "condition", "values"],
                        additionalProperties: false,
                      },
                    },
                    metadata: {
                      type: "object",
                      properties: {
                        cve: { type: "string" },
                        cwe: { type: "string" },
                        cvss: { type: "number" },
                        references: { type: "array", items: { type: "string" } },
                      },
                      required: ["references"],
                      additionalProperties: false,
                    },
                  },
                  required: ["templateId", "name", "description", "severity", "category", "detectionMethod", "requests", "matchers", "metadata"],
                  additionalProperties: false,
                },
              },
            },
            required: ["actionable", "reason", "templates"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) return { actionable: false, generatedTemplates: [], analysisResult: {} };

    const parsed = JSON.parse(content);
    return {
      actionable: parsed.actionable,
      generatedTemplates: parsed.templates || [],
      analysisResult: parsed,
    };
  } catch (err) {
    console.warn(`[ScanForge Deep Research] LLM analysis error:`, (err as Error).message);
    return { actionable: false, generatedTemplates: [], analysisResult: {} };
  }
}

function buildAnalysisPrompt(input: ResearchInput): string {
  const dataStr = JSON.stringify(input.data, null, 2).slice(0, 3000);
  
  switch (input.researchType) {
    case "zero_day_monitoring":
      return `Analyze this zero-day vulnerability and determine if a network-detectable template can be created:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Consider: Is this vulnerability detectable via HTTP/TCP scanning? What specific requests and response patterns would indicate this vulnerability?`;

    case "cve_analysis":
      return `Analyze this CVE from CISA's Known Exploited Vulnerabilities catalog:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

This CVE is actively exploited in the wild. Generate a detection template if the vulnerability is network-detectable.`;

    case "exploit_research":
      return `Analyze this weaponized exploit:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Generate a detection template that can identify systems vulnerable to this exploit via network scanning.`;

    case "bug_bounty_pattern":
      return `Analyze this bug bounty finding pattern from HackerOne:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Real-world bug bounty findings often reveal novel attack patterns. Generate a detection template if this pattern is generalizable.`;

    case "threat_actor_ttp":
      return `Analyze this threat actor TTP/IOC:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

If this threat actor uses specific web exploitation techniques, generate detection templates for their known attack patterns.`;

    case "service_exposure":
      return `Analyze this exposed service/asset:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Identify if the exposed services have known vulnerabilities or misconfigurations that can be detected via scanning.`;

    case "credential_exposure":
      return `Analyze this credential exposure data:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Generate templates to detect if exposed credentials are still valid on common services (SSH, FTP, web login forms, etc.).`;

    case "malware_analysis":
      return `Analyze this malware/C2 intelligence:

Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Generate templates to detect C2 infrastructure indicators or malware delivery mechanisms via network scanning.`;

    default:
      return `Analyze this threat intelligence data:

Source: ${input.feedSource}
Type: ${input.researchType}
Subject: ${input.subject}
Urgency: ${input.urgency}
Data:
${dataStr}

Determine if a new ScanForge detection template should be created based on this intelligence.`;
  }
}

// ─── Template Storage ───────────────────────────────────────────────────────

async function storeGeneratedTemplate(template: GeneratedTemplate, feedSource: FeedSource): Promise<void> {
  const _db = await getDbRequired();
  await _db.insert(scanforgeGeneratedTemplates).values({
    templateId: template.templateId,
    name: template.name,
    generationSource: feedSource,
    sourceReference: template.metadata?.cve || template.metadata?.cwe || template.name,
    templateData: template,
    status: "draft",
    generationConfidence: template.metadata?.cvss ? Math.min(0.95, template.metadata.cvss / 10) : 0.5,
  });
}

// ─── Template Promotion ─────────────────────────────────────────────────────

/**
 * Promote a draft template to production after validation.
 * Writes the template JSON to the definitions directory.
 */
export async function promoteTemplate(templateId: string): Promise<boolean> {
  const _db = await getDbRequired();
  const rows = await _db.select()
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.templateId, templateId))
    .limit(1);

  if (!rows[0] || rows[0].status !== "review") return false;

  await _db.update(scanforgeGeneratedTemplates)
    .set({ status: "promoted", promotedToTemplateId: templateId })
    .where(eq(scanforgeGeneratedTemplates.templateId, templateId));

  return true;
}

/**
 * Get all draft templates pending review.
 */
export async function getDraftTemplates(limit: number = 50) {
  const _db = await getDbRequired();
  return _db.select()
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.status, "draft"))
    .orderBy(desc(scanforgeGeneratedTemplates.createdAt))
    .limit(limit);
}

/**
 * Get research activity log for dashboard display.
 */
export async function getResearchLog(limit: number = 100) {
  const _db = await getDbRequired();
  return _db.select()
    .from(scanforgeResearchLog)
    .orderBy(desc(scanforgeResearchLog.createdAt))
    .limit(limit);
}
