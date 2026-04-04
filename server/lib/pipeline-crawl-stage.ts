/**
 * Pipeline Crawl Stage (Stage 3.993)
 * ────────────────────────────────────
 * Runs the web crawler INLINE within the DI pipeline (before CARVER feedback loop)
 * so that crawl-derived CARVER adjustments and business intelligence feed directly
 * into hybrid risk scoring.
 *
 * Previously, auto-crawl ran as fire-and-forget AFTER the pipeline completed,
 * meaning its CARVER adjustments never influenced the final risk scores.
 *
 * This stage:
 * 1. Crawls discovered web assets (same logic as auto-crawl, but inline)
 * 2. Computes per-asset CARVER/SHOCK adjustments from crawl findings
 * 3. Applies adjustments directly to analyses[].carverScores/shockScores
 * 4. Extracts business intelligence via LLM (services, products, revenue context)
 * 5. Enriches org profile with crawl-derived business context
 *
 * Patent-pending: Hybrid Risk/CVSS Hybrid Risk Scoring Pipeline
 * Created by Harrison Cook
 */

import type { CrawlPageResult } from "./web-crawler";
import { computeCrawlCarverAdjustment, aggregateCrawlAdjustments, type CrawlCarverAdjustment } from "./crawl-carver-integration";
import type { AssetAnalysis, CarverScores, ShockScores, OrgProfile } from "../domainIntel";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PipelineCrawlResult {
  /** Total assets attempted */
  totalAssets: number;
  /** Successfully crawled */
  totalCrawled: number;
  /** Failed to crawl */
  totalFailed: number;
  /** Total security findings from crawl */
  totalFindings: number;
  /** Worst security header grade across all crawled pages */
  worstGrade: string;
  /** Duration of the crawl stage in ms */
  durationMs: number;
  /** Number of CARVER adjustments applied to asset analyses */
  carverAdjustmentsApplied: number;
  /** Aggregated CARVER adjustment summary */
  aggregatedCarver: CrawlCarverAdjustment | null;
  /** Business intelligence extracted from crawled pages */
  businessIntelligence: BusinessIntelligence | null;
  /** Per-asset crawl summaries */
  assetCrawls: AssetCrawlSummary[];
}

export interface AssetCrawlSummary {
  hostname: string;
  url: string;
  httpStatus: number | null;
  securityGrade: string | null;
  findingCount: number;
  technologies: string[];
  carverAdjusted: boolean;
}

export interface BusinessIntelligence {
  /** Company services identified from website content */
  services: string[];
  /** Products or solutions offered */
  products: string[];
  /** Industry/vertical indicators */
  industryIndicators: string[];
  /** Key partnerships or integrations mentioned */
  partnerships: string[];
  /** Client types or target market */
  targetMarket: string[];
  /** Compliance/certification mentions (SOC2, HIPAA, ISO, etc.) */
  complianceMentions: string[];
  /** Career/hiring signals (indicates company size/growth) */
  hiringSignals: string[];
  /** Technology stack mentioned on website (beyond what crawler detects) */
  statedTechStack: string[];
  /** Revenue/pricing model indicators */
  pricingModel: string | null;
  /** Geographic presence indicators */
  geographicPresence: string[];
  /** Raw page titles and descriptions for context */
  pageContext: Array<{ url: string; title: string; description: string }>;
  /** LLM-generated business summary */
  businessSummary: string;
  /** Confidence in the extraction (0-1) */
  confidence: number;
}

// ─── Main Stage Function ─────────────────────────────────────────────────────

/**
 * Run the inline pipeline crawl stage.
 * 
 * @param analyses - Current asset analyses (will be mutated with CARVER adjustments)
 * @param org - Organization profile
 * @param domain - Primary domain being scanned
 * @returns PipelineCrawlResult with crawl data, CARVER adjustments, and business intel
 */
export async function runPipelineCrawlStage(
  analyses: AssetAnalysis[],
  org: OrgProfile,
  domain: string,
): Promise<PipelineCrawlResult> {
  const startedAt = Date.now();
  console.log(`[PipelineCrawl] Stage 3.993: Starting inline web crawl for ${domain} (${analyses.length} assets)`);

  const { quickScan } = await import("./web-crawler");

  // ── Step 1: Identify crawlable assets ──────────────────────────────────
  const crawlableAssets = analyses.filter(a => {
    const hostname = a.asset.hostname;
    if (!hostname) return false;
    // Include web-facing assets
    const assetType = (a.asset.assetType || "").toLowerCase();
    if (["web_application", "api_endpoint", "cdn", "web_server", "load_balancer"].includes(assetType)) return true;
    // Include anything with web-related tags
    const tags = a.asset.tags || [];
    if (tags.some(t => ["web", "http", "https", "api", "cdn"].includes(t.toLowerCase()))) return true;
    // Default: try to crawl any hostname
    return true;
  });

  // Cap at 20 assets to keep pipeline responsive (auto-crawl handles the rest post-pipeline)
  const assetsToScan = crawlableAssets.slice(0, 20);
  console.log(`[PipelineCrawl] Found ${crawlableAssets.length} crawlable assets, scanning top ${assetsToScan.length}`);

  if (assetsToScan.length === 0) {
    console.log(`[PipelineCrawl] No crawlable assets — skipping`);
    return {
      totalAssets: 0,
      totalCrawled: 0,
      totalFailed: 0,
      totalFindings: 0,
      worstGrade: "N/A",
      durationMs: Date.now() - startedAt,
      carverAdjustmentsApplied: 0,
      aggregatedCarver: null,
      businessIntelligence: null,
      assetCrawls: [],
    };
  }

  // ── Step 2: Crawl assets (3 concurrent) ────────────────────────────────
  const assetCrawls: AssetCrawlSummary[] = [];
  const allCarverAdjustments: CrawlCarverAdjustment[] = [];
  const crawlPages: CrawlPageResult[] = [];
  let totalCrawled = 0;
  let totalFailed = 0;
  let totalFindings = 0;
  const gradeOrder = ["F", "D", "C", "B", "A", "A+"];
  let worstGradeIdx = gradeOrder.length - 1;

  // Process in batches of 3 for concurrency control
  for (let i = 0; i < assetsToScan.length; i += 3) {
    const batch = assetsToScan.slice(i, i + 3);
    const results = await Promise.allSettled(
      batch.map(async (analysis) => {
        const hostname = analysis.asset.hostname;
        const url = analysis.asset.url || `https://${hostname}`;
        try {
          const page = await quickScan(url);
          if (!page) return { analysis, hostname, url, page: null };
          return { analysis, hostname, url, page };
        } catch (err: any) {
          console.error(`[PipelineCrawl] Failed to crawl ${url}: ${err.message}`);
          return { analysis, hostname, url, page: null };
        }
      })
    );

    for (const result of results) {
      if (result.status === "rejected") {
        totalFailed++;
        continue;
      }
      const { analysis, hostname, url, page } = result.value;
      if (!page) {
        totalFailed++;
        assetCrawls.push({
          hostname,
          url,
          httpStatus: null,
          securityGrade: null,
          findingCount: 0,
          technologies: [],
          carverAdjusted: false,
        });
        continue;
      }

      totalCrawled++;
      totalFindings += page.findings.length;
      crawlPages.push(page);

      // Track worst grade
      const gradeIdx = gradeOrder.indexOf(page.securityHeaderGrade);
      if (gradeIdx >= 0 && gradeIdx < worstGradeIdx) worstGradeIdx = gradeIdx;

      // ── Step 3: Compute CARVER adjustment for this asset ──────────
      let carverAdjusted = false;
      try {
        const adj = computeCrawlCarverAdjustment(page, hostname);
        if (adj) {
          allCarverAdjustments.push(adj);

          // Apply CARVER adjustments directly to the analysis
          const carverKeys: (keyof CarverScores)[] = ["criticality", "accessibility", "recuperability", "vulnerability", "effect", "recognizability"];
          for (const key of carverKeys) {
            if (adj.carver[key] !== 0) {
              const prev = analysis.carverScores[key];
              analysis.carverScores[key] = Math.min(10, Math.max(0, prev + adj.carver[key]));
              carverAdjusted = true;
            }
          }

          const shockKeys: (keyof ShockScores)[] = ["scope", "handling", "operationalImpact", "cascadingEffects", "knowledge"];
          for (const key of shockKeys) {
            if (adj.shock[key] !== 0) {
              const prev = analysis.shockScores[key];
              analysis.shockScores[key] = Math.min(10, Math.max(0, prev + adj.shock[key]));
              carverAdjusted = true;
            }
          }

          // Apply context adjustments to the analysis
          if (adj.contextAdjustment.exposureBoost) {
            analysis.contextIndicators.exposure = Math.min(1, analysis.contextIndicators.exposure + adj.contextAdjustment.exposureBoost * 0.1);
          }
          if (adj.contextAdjustment.recognizabilityBoost) {
            analysis.contextIndicators.recognizability = Math.min(1, analysis.contextIndicators.recognizability + adj.contextAdjustment.recognizabilityBoost * 0.1);
          }

          // Add crawl posture findings to the asset's posture findings
          if (adj.postureFindings?.length > 0) {
            for (const pf of adj.postureFindings) {
              analysis.postureFindings.push({
                title: pf.title,
                severity: pf.severity as any,
                category: pf.category || "web_security",
                description: pf.description,
                evidenceDetail: pf.evidenceDetail || "",
                corroborationTier: pf.corroborationTier || "confirmed",
                corroborationSources: ["web_crawler"],
                affectedVersions: null,
                cveId: null,
                cvssScore: null,
                remediation: pf.remediation || null,
              });
            }
          }
        }
      } catch (err: any) {
        console.error(`[PipelineCrawl] CARVER scoring failed for ${hostname}: ${err.message}`);
      }

      assetCrawls.push({
        hostname,
        url,
        httpStatus: page.httpStatus,
        securityGrade: page.securityHeaderGrade,
        findingCount: page.findings.length,
        technologies: page.detectedTechnologies.map(t => t.version ? `${t.name} ${t.version}` : t.name),
        carverAdjusted,
      });
    }
  }

  // ── Step 4: Aggregate CARVER adjustments ───────────────────────────────
  const aggregatedCarver = aggregateCrawlAdjustments(allCarverAdjustments);
  const carverAdjustmentsApplied = assetCrawls.filter(a => a.carverAdjusted).length;

  console.log(
    `[PipelineCrawl] Crawled ${totalCrawled}/${assetsToScan.length} assets, ` +
    `${totalFindings} findings, grade=${gradeOrder[worstGradeIdx] || "F"}, ` +
    `${carverAdjustmentsApplied} CARVER adjustments applied`
  );

  // ── Step 5: Extract business intelligence via LLM ──────────────────────
  let businessIntelligence: BusinessIntelligence | null = null;
  try {
    businessIntelligence = await extractBusinessIntelligence(crawlPages, domain, org);
    if (businessIntelligence) {
      console.log(
        `[PipelineCrawl] Business intel extracted: ${businessIntelligence.services.length} services, ` +
        `${businessIntelligence.products.length} products, ` +
        `${businessIntelligence.complianceMentions.length} compliance refs, ` +
        `confidence=${businessIntelligence.confidence}`
      );
    }
  } catch (err: any) {
    console.error(`[PipelineCrawl] Business intelligence extraction failed (non-fatal): ${err.message}`);
  }

  const durationMs = Date.now() - startedAt;
  console.log(`[PipelineCrawl] Stage 3.993 complete in ${durationMs}ms`);

  return {
    totalAssets: assetsToScan.length,
    totalCrawled,
    totalFailed,
    totalFindings,
    worstGrade: gradeOrder[worstGradeIdx] || "F",
    durationMs,
    carverAdjustmentsApplied,
    aggregatedCarver,
    businessIntelligence,
    assetCrawls,
  };
}

// ─── Business Intelligence Extraction ────────────────────────────────────────

/**
 * Use LLM to extract structured business intelligence from crawled web pages.
 * This provides context for CARVER scoring (criticality based on business function)
 * and enriches the org profile for better executive summaries.
 */
async function extractBusinessIntelligence(
  pages: CrawlPageResult[],
  domain: string,
  org: OrgProfile,
): Promise<BusinessIntelligence | null> {
  if (pages.length === 0) return null;

  const { invokeLLM } = await import("../_core/llm");

  // Build page context for the LLM
  const pageContext: BusinessIntelligence["pageContext"] = [];
  const pageTexts: string[] = [];

  for (const page of pages.slice(0, 10)) { // Limit to 10 pages for token efficiency
    const title = page.pageTitle || "";
    const desc = page.metaDescription || "";
    pageContext.push({ url: page.url, title, description: desc });

    // Build a text summary of what we found on this page
    const parts: string[] = [];
    if (title) parts.push(`Title: ${title}`);
    if (desc) parts.push(`Description: ${desc}`);
    if (page.detectedTechnologies.length > 0) {
      parts.push(`Technologies: ${page.detectedTechnologies.map(t => t.version ? `${t.name} ${t.version}` : t.name).join(", ")}`);
    }
    if (page.forms.length > 0) {
      parts.push(`Forms: ${page.forms.map(f => `${f.method} ${f.action} (${f.inputTypes.join(", ")})`).join("; ")}`);
    }
    if (page.externalLinks.length > 0) {
      // External links can reveal partnerships, integrations, social profiles
      const relevantLinks = page.externalLinks
        .filter(l => !l.includes("google") && !l.includes("facebook.com/tr") && !l.includes("analytics"))
        .slice(0, 15);
      if (relevantLinks.length > 0) {
        parts.push(`External links: ${relevantLinks.join(", ")}`);
      }
    }
    pageTexts.push(`[${page.url}]\n${parts.join("\n")}`);
  }

  const prompt = `You are a business intelligence analyst. Analyze the following crawled web pages from ${domain} (${org.customerName || "unknown org"}) and extract structured business intelligence.

CRAWLED PAGES:
${pageTexts.join("\n\n")}

Extract the following information. Be specific and factual — only include what you can directly observe or reasonably infer from the page content. Do not hallucinate.

Return a JSON object with these fields:
{
  "services": ["list of services the company offers"],
  "products": ["list of products or solutions"],
  "industryIndicators": ["industry verticals they serve or operate in"],
  "partnerships": ["technology partners, integrations, or vendor relationships mentioned"],
  "targetMarket": ["who their customers are — enterprise, SMB, government, etc."],
  "complianceMentions": ["SOC2, HIPAA, ISO 27001, FedRAMP, PCI-DSS, etc."],
  "hiringSignals": ["any career/hiring indicators — job titles, team growth, etc."],
  "statedTechStack": ["technologies explicitly mentioned on the site beyond what the crawler detected"],
  "pricingModel": "subscription/freemium/enterprise/per-seat/null if not visible",
  "geographicPresence": ["countries, regions, or offices mentioned"],
  "businessSummary": "2-3 sentence summary of what this company does, who they serve, and their market position",
  "confidence": 0.0-1.0
}`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a business intelligence analyst. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "business_intelligence",
          strict: true,
          schema: {
            type: "object",
            properties: {
              services: { type: "array", items: { type: "string" } },
              products: { type: "array", items: { type: "string" } },
              industryIndicators: { type: "array", items: { type: "string" } },
              partnerships: { type: "array", items: { type: "string" } },
              targetMarket: { type: "array", items: { type: "string" } },
              complianceMentions: { type: "array", items: { type: "string" } },
              hiringSignals: { type: "array", items: { type: "string" } },
              statedTechStack: { type: "array", items: { type: "string" } },
              pricingModel: { type: ["string", "null"] },
              geographicPresence: { type: "array", items: { type: "string" } },
              businessSummary: { type: "string" },
              confidence: { type: "number" },
            },
            required: [
              "services", "products", "industryIndicators", "partnerships",
              "targetMarket", "complianceMentions", "hiringSignals", "statedTechStack",
              "pricingModel", "geographicPresence", "businessSummary", "confidence"
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response?.choices?.[0]?.message?.content;
    if (!content) return null;

    const parsed = JSON.parse(content);
    return {
      ...parsed,
      pageContext,
    };
  } catch (err: any) {
    console.error(`[PipelineCrawl] LLM business intelligence extraction failed: ${err.message}`);
    return null;
  }
}

/**
 * Enrich the org profile with crawl-derived business intelligence.
 * This mutates the org object to add business context that improves
 * the executive summary and campaign recommendations.
 */
export function enrichOrgWithBusinessIntel(
  org: OrgProfile,
  bizIntel: BusinessIntelligence,
): void {
  // Add services and products to org profile if not already present
  if (bizIntel.services.length > 0) {
    (org as any).keyProducts = bizIntel.services.concat(bizIntel.products).slice(0, 10);
  }

  // Add industry indicators
  if (bizIntel.industryIndicators.length > 0) {
    (org as any).industry = bizIntel.industryIndicators[0];
    (org as any).industryIndicators = bizIntel.industryIndicators;
  }

  // Add compliance context (useful for CARVER criticality assessment)
  if (bizIntel.complianceMentions.length > 0) {
    (org as any).complianceFrameworks = bizIntel.complianceMentions;
    // Also merge into complianceFlags for report and scoring consumption
    const existing = new Set((org.complianceFlags || []).map(f => f.toLowerCase()));
    for (const mention of bizIntel.complianceMentions) {
      if (!existing.has(mention.toLowerCase())) {
        org.complianceFlags.push(mention);
        existing.add(mention.toLowerCase());
      }
    }
  }

  // Add business summary for exec summary generation
  if (bizIntel.businessSummary) {
    (org as any).businessSummary = bizIntel.businessSummary;
  }

  // Add geographic presence
  if (bizIntel.geographicPresence.length > 0) {
    (org as any).geographicPresence = bizIntel.geographicPresence;
  }

  // Add target market for campaign design
  if (bizIntel.targetMarket.length > 0) {
    (org as any).targetMarket = bizIntel.targetMarket;
  }

  // Add partnerships (useful for supply chain risk assessment)
  if (bizIntel.partnerships.length > 0) {
    (org as any).partnerships = bizIntel.partnerships;
  }

  // Add stated tech stack (supplements crawler detection)
  if (bizIntel.statedTechStack?.length > 0) {
    (org as any).statedTechStack = bizIntel.statedTechStack;
  }
}

/**
 * Apply CARVER boosts based on business intelligence.
 * Companies with compliance requirements, critical services, or large customer bases
 * should have higher CARVER criticality scores.
 */
export function applyBusinessIntelCarverBoosts(
  analyses: AssetAnalysis[],
  bizIntel: BusinessIntelligence,
): number {
  let boostsApplied = 0;

  // Compliance-driven criticality boost
  const hasHighCompliance = bizIntel.complianceMentions.some(c =>
    /hipaa|pci.?dss|fedramp|sox|itar|cjis/i.test(c)
  );
  const hasMedCompliance = bizIntel.complianceMentions.some(c =>
    /soc.?2|iso.?27001|gdpr|ccpa|nist/i.test(c)
  );

  // Service-driven criticality boost
  const hasCriticalServices = bizIntel.services.some(s =>
    /payment|banking|health|medical|government|defense|infrastructure/i.test(s)
  );

  // Market-driven effect boost
  const servesEnterprise = bizIntel.targetMarket.some(m =>
    /enterprise|government|fortune|large/i.test(m)
  );

  for (const analysis of analyses) {
    let adjusted = false;

    // Boost criticality for compliance-heavy orgs
    if (hasHighCompliance && analysis.carverScores.criticality < 8) {
      analysis.carverScores.criticality = Math.min(10, analysis.carverScores.criticality + 1.5);
      adjusted = true;
    } else if (hasMedCompliance && analysis.carverScores.criticality < 7) {
      analysis.carverScores.criticality = Math.min(10, analysis.carverScores.criticality + 0.75);
      adjusted = true;
    }

    // Boost criticality for critical service providers
    if (hasCriticalServices && analysis.carverScores.criticality < 8) {
      analysis.carverScores.criticality = Math.min(10, analysis.carverScores.criticality + 1.0);
      adjusted = true;
    }

    // Boost effect for enterprise-serving orgs (broader blast radius)
    if (servesEnterprise && analysis.carverScores.effect < 7) {
      analysis.carverScores.effect = Math.min(10, analysis.carverScores.effect + 0.5);
      adjusted = true;
    }

    // Boost recuperability (harder to recover) for orgs with many partnerships (supply chain)
    if (bizIntel.partnerships.length >= 3 && analysis.carverScores.recuperability < 7) {
      analysis.carverScores.recuperability = Math.min(10, analysis.carverScores.recuperability + 0.5);
      adjusted = true;
    }

    if (adjusted) boostsApplied++;
  }

  if (boostsApplied > 0) {
    console.log(
      `[PipelineCrawl] Business intel CARVER boosts applied to ${boostsApplied}/${analyses.length} assets ` +
      `(compliance=${hasHighCompliance ? 'high' : hasMedCompliance ? 'med' : 'none'}, ` +
      `criticalServices=${hasCriticalServices}, enterprise=${servesEnterprise})`
    );
  }

  return boostsApplied;
}
