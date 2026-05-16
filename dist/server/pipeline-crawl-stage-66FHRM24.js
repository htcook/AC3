import {
  aggregateCrawlAdjustments,
  computeCrawlCarverAdjustment,
  init_crawl_carver_integration
} from "./chunk-NTJIMC3H.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/pipeline-crawl-stage.ts
async function runPipelineCrawlStage(analyses, org, domain) {
  const startedAt = Date.now();
  console.log(`[PipelineCrawl] Stage 3.993: Starting inline web crawl for ${domain} (${analyses.length} assets)`);
  const { quickScan } = await import("./web-crawler-UHM7AOL2.js");
  const crawlableAssets = analyses.filter((a) => {
    const hostname = a.asset.hostname;
    if (!hostname) return false;
    const assetType = (a.asset.assetType || "").toLowerCase();
    if (["web_application", "api_endpoint", "cdn", "web_server", "load_balancer"].includes(assetType)) return true;
    const tags = a.asset.tags || [];
    if (tags.some((t) => ["web", "http", "https", "api", "cdn"].includes(t.toLowerCase()))) return true;
    return true;
  });
  const assetsToScan = crawlableAssets.slice(0, 20);
  console.log(`[PipelineCrawl] Found ${crawlableAssets.length} crawlable assets, scanning top ${assetsToScan.length}`);
  if (assetsToScan.length === 0) {
    console.log(`[PipelineCrawl] No crawlable assets \u2014 skipping`);
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
      assetCrawls: []
    };
  }
  const assetCrawls = [];
  const allCarverAdjustments = [];
  const crawlPages = [];
  let totalCrawled = 0;
  let totalFailed = 0;
  let totalFindings = 0;
  const gradeOrder = ["F", "D", "C", "B", "A", "A+"];
  let worstGradeIdx = gradeOrder.length - 1;
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
        } catch (err) {
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
          carverAdjusted: false
        });
        continue;
      }
      totalCrawled++;
      totalFindings += page.findings.length;
      crawlPages.push(page);
      const gradeIdx = gradeOrder.indexOf(page.securityHeaderGrade);
      if (gradeIdx >= 0 && gradeIdx < worstGradeIdx) worstGradeIdx = gradeIdx;
      let carverAdjusted = false;
      try {
        const adj = computeCrawlCarverAdjustment(page, hostname);
        if (adj) {
          allCarverAdjustments.push(adj);
          const carverKeys = ["criticality", "accessibility", "recuperability", "vulnerability", "effect", "recognizability"];
          for (const key of carverKeys) {
            if (adj.carver[key] !== 0) {
              const prev = analysis.carverScores[key];
              analysis.carverScores[key] = Math.min(10, Math.max(0, prev + adj.carver[key]));
              carverAdjusted = true;
            }
          }
          const shockKeys = ["scope", "handling", "operationalImpact", "cascadingEffects", "knowledge"];
          for (const key of shockKeys) {
            if (adj.shock[key] !== 0) {
              const prev = analysis.shockScores[key];
              analysis.shockScores[key] = Math.min(10, Math.max(0, prev + adj.shock[key]));
              carverAdjusted = true;
            }
          }
          if (adj.contextAdjustment.exposureBoost) {
            analysis.contextIndicators.exposure = Math.min(1, analysis.contextIndicators.exposure + adj.contextAdjustment.exposureBoost * 0.1);
          }
          if (adj.contextAdjustment.recognizabilityBoost) {
            analysis.contextIndicators.recognizability = Math.min(1, analysis.contextIndicators.recognizability + adj.contextAdjustment.recognizabilityBoost * 0.1);
          }
          if (adj.postureFindings?.length > 0) {
            for (const pf of adj.postureFindings) {
              analysis.postureFindings.push({
                title: pf.title,
                severity: pf.severity,
                category: pf.category || "web_security",
                description: pf.description,
                evidenceDetail: pf.evidenceDetail || "",
                corroborationTier: pf.corroborationTier || "confirmed",
                corroborationSources: ["web_crawler"],
                affectedVersions: null,
                cveId: null,
                cvssScore: null,
                remediation: pf.remediation || null
              });
            }
          }
        }
      } catch (err) {
        console.error(`[PipelineCrawl] CARVER scoring failed for ${hostname}: ${err.message}`);
      }
      if (page.detectedTechnologies.length > 0) {
        if (!analysis.asset.technologyVersions) {
          analysis.asset.technologyVersions = {};
        }
        if (!analysis.asset.technologies) {
          analysis.asset.technologies = [];
        }
        const techSet = new Set((analysis.asset.technologies || []).map((t) => t.toLowerCase()));
        for (const dt of page.detectedTechnologies) {
          if (!techSet.has(dt.name.toLowerCase())) {
            analysis.asset.technologies.push(dt.name);
            techSet.add(dt.name.toLowerCase());
          }
          if (dt.version) {
            const existing = analysis.asset.technologyVersions[dt.name];
            if (!existing) {
              analysis.asset.technologyVersions[dt.name] = dt.version;
            }
          }
        }
      }
      assetCrawls.push({
        hostname,
        url,
        httpStatus: page.httpStatus,
        securityGrade: page.securityHeaderGrade,
        findingCount: page.findings.length,
        technologies: page.detectedTechnologies.map((t) => t.version ? `${t.name} ${t.version}` : t.name),
        carverAdjusted
      });
    }
  }
  const aggregatedCarver = aggregateCrawlAdjustments(allCarverAdjustments);
  const carverAdjustmentsApplied = assetCrawls.filter((a) => a.carverAdjusted).length;
  console.log(
    `[PipelineCrawl] Crawled ${totalCrawled}/${assetsToScan.length} assets, ${totalFindings} findings, grade=${gradeOrder[worstGradeIdx] || "F"}, ${carverAdjustmentsApplied} CARVER adjustments applied`
  );
  let businessIntelligence = null;
  try {
    businessIntelligence = await extractBusinessIntelligence(crawlPages, domain, org);
    if (businessIntelligence) {
      console.log(
        `[PipelineCrawl] Business intel extracted: ${businessIntelligence.services.length} services, ${businessIntelligence.products.length} products, ${businessIntelligence.complianceMentions.length} compliance refs, confidence=${businessIntelligence.confidence}`
      );
    }
  } catch (err) {
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
    assetCrawls
  };
}
async function extractBusinessIntelligence(pages, domain, org) {
  if (pages.length === 0) return null;
  const { invokeLLM } = await import("./llm-ZHBF7TZ4.js");
  const pageContext = [];
  const pageTexts = [];
  for (const page of pages.slice(0, 10)) {
    const title = page.pageTitle || "";
    const desc = page.metaDescription || "";
    pageContext.push({ url: page.url, title, description: desc });
    const parts = [];
    if (title) parts.push(`Title: ${title}`);
    if (desc) parts.push(`Description: ${desc}`);
    if (page.detectedTechnologies.length > 0) {
      parts.push(`Technologies: ${page.detectedTechnologies.map((t) => t.version ? `${t.name} ${t.version}` : t.name).join(", ")}`);
    }
    if (page.forms.length > 0) {
      parts.push(`Forms: ${page.forms.map((f) => `${f.method} ${f.action} (${f.inputTypes.join(", ")})`).join("; ")}`);
    }
    if (page.externalLinks.length > 0) {
      const relevantLinks = page.externalLinks.filter((l) => !l.includes("google") && !l.includes("facebook.com/tr") && !l.includes("analytics")).slice(0, 15);
      if (relevantLinks.length > 0) {
        parts.push(`External links: ${relevantLinks.join(", ")}`);
      }
    }
    pageTexts.push(`[${page.url}]
${parts.join("\n")}`);
  }
  const prompt = `You are a business intelligence analyst. Analyze the following crawled web pages from ${domain} (${org.customerName || "unknown org"}) and extract structured business intelligence.

CRAWLED PAGES:
${pageTexts.join("\n\n")}

Extract the following information. Be specific and factual \u2014 only include what you can directly observe or reasonably infer from the page content. Do not hallucinate.

Return a JSON object with these fields:
{
  "services": ["list of services the company offers"],
  "products": ["list of products or solutions"],
  "industryIndicators": ["industry verticals they serve or operate in"],
  "partnerships": ["technology partners, integrations, or vendor relationships mentioned"],
  "targetMarket": ["who their customers are \u2014 enterprise, SMB, government, etc."],
  "complianceMentions": ["SOC2, HIPAA, ISO 27001, FedRAMP, PCI-DSS, etc."],
  "hiringSignals": ["any career/hiring indicators \u2014 job titles, team growth, etc."],
  "statedTechStack": ["technologies explicitly mentioned on the site beyond what the crawler detected"],
  "pricingModel": "subscription/freemium/enterprise/per-seat/null if not visible",
  "geographicPresence": ["countries, regions, or offices mentioned"],
  "businessSummary": "2-3 sentence summary of what this company does, who they serve, and their market position",
  "confidence": 0.0-1.0
}`;
  try {
    const response = await invokeLLM({
      _caller: "pipeline-crawl-stage:analyzeCompanyIntel",
      messages: [
        { role: "system", content: "You are a business intelligence analyst. Return only valid JSON." },
        { role: "user", content: prompt }
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
              confidence: { type: "number" }
            },
            required: [
              "services",
              "products",
              "industryIndicators",
              "partnerships",
              "targetMarket",
              "complianceMentions",
              "hiringSignals",
              "statedTechStack",
              "pricingModel",
              "geographicPresence",
              "businessSummary",
              "confidence"
            ],
            additionalProperties: false
          }
        }
      }
    });
    const content = response?.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = JSON.parse(content);
    return {
      ...parsed,
      pageContext
    };
  } catch (err) {
    console.error(`[PipelineCrawl] LLM business intelligence extraction failed: ${err.message}`);
    return null;
  }
}
function enrichOrgWithBusinessIntel(org, bizIntel) {
  if (bizIntel.services.length > 0) {
    org.keyProducts = bizIntel.services.concat(bizIntel.products).slice(0, 10);
  }
  if (bizIntel.industryIndicators.length > 0) {
    org.industry = bizIntel.industryIndicators[0];
    org.industryIndicators = bizIntel.industryIndicators;
  }
  if (bizIntel.complianceMentions.length > 0) {
    org.complianceFrameworks = bizIntel.complianceMentions;
    const existing = new Set((org.complianceFlags || []).map((f) => f.toLowerCase()));
    for (const mention of bizIntel.complianceMentions) {
      if (!existing.has(mention.toLowerCase())) {
        org.complianceFlags.push(mention);
        existing.add(mention.toLowerCase());
      }
    }
  }
  if (bizIntel.businessSummary) {
    org.businessSummary = bizIntel.businessSummary;
  }
  if (bizIntel.geographicPresence.length > 0) {
    org.geographicPresence = bizIntel.geographicPresence;
  }
  if (bizIntel.targetMarket.length > 0) {
    org.targetMarket = bizIntel.targetMarket;
  }
  if (bizIntel.partnerships.length > 0) {
    org.partnerships = bizIntel.partnerships;
  }
  if (bizIntel.statedTechStack?.length > 0) {
    org.statedTechStack = bizIntel.statedTechStack;
  }
}
function applyBusinessIntelCarverBoosts(analyses, bizIntel) {
  let boostsApplied = 0;
  const hasHighCompliance = bizIntel.complianceMentions.some(
    (c) => /hipaa|pci.?dss|fedramp|sox|itar|cjis/i.test(c)
  );
  const hasMedCompliance = bizIntel.complianceMentions.some(
    (c) => /soc.?2|iso.?27001|gdpr|ccpa|nist/i.test(c)
  );
  const hasCriticalServices = bizIntel.services.some(
    (s) => /payment|banking|health|medical|government|defense|infrastructure/i.test(s)
  );
  const servesEnterprise = bizIntel.targetMarket.some(
    (m) => /enterprise|government|fortune|large/i.test(m)
  );
  for (const analysis of analyses) {
    let adjusted = false;
    if (hasHighCompliance && analysis.carverScores.criticality < 8) {
      analysis.carverScores.criticality = Math.min(10, analysis.carverScores.criticality + 1.5);
      adjusted = true;
    } else if (hasMedCompliance && analysis.carverScores.criticality < 7) {
      analysis.carverScores.criticality = Math.min(10, analysis.carverScores.criticality + 0.75);
      adjusted = true;
    }
    if (hasCriticalServices && analysis.carverScores.criticality < 8) {
      analysis.carverScores.criticality = Math.min(10, analysis.carverScores.criticality + 1);
      adjusted = true;
    }
    if (servesEnterprise && analysis.carverScores.effect < 7) {
      analysis.carverScores.effect = Math.min(10, analysis.carverScores.effect + 0.5);
      adjusted = true;
    }
    if (bizIntel.partnerships.length >= 3 && analysis.carverScores.recuperability < 7) {
      analysis.carverScores.recuperability = Math.min(10, analysis.carverScores.recuperability + 0.5);
      adjusted = true;
    }
    if (adjusted) boostsApplied++;
  }
  if (boostsApplied > 0) {
    console.log(
      `[PipelineCrawl] Business intel CARVER boosts applied to ${boostsApplied}/${analyses.length} assets (compliance=${hasHighCompliance ? "high" : hasMedCompliance ? "med" : "none"}, criticalServices=${hasCriticalServices}, enterprise=${servesEnterprise})`
    );
  }
  return boostsApplied;
}
var init_pipeline_crawl_stage = __esm({
  "server/lib/pipeline-crawl-stage.ts"() {
    init_crawl_carver_integration();
  }
});
init_pipeline_crawl_stage();
export {
  applyBusinessIntelCarverBoosts,
  enrichOrgWithBusinessIntel,
  runPipelineCrawlStage
};
