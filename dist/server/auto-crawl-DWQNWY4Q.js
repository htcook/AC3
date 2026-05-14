import {
  aggregateCrawlAdjustments,
  computeCrawlCarverAdjustment,
  init_crawl_carver_integration
} from "./chunk-NTJIMC3H.js";
import "./chunk-KFQGP6VL.js";

// server/lib/auto-crawl.ts
init_crawl_carver_integration();
async function triggerAutoCrawl(scanId, domain) {
  const startedAt = Date.now();
  console.log(`[AutoCrawl] Starting auto-crawl for scan ${scanId} (${domain})`);
  try {
    const { getDb } = await import("./db-LCEQKGBV.js");
    const { discoveredAssets, webCrawlResults, webCrawlJobs, domainIntelScans } = await import("./schema-5UXBHZJS.js");
    const { eq } = await import("drizzle-orm");
    const { quickScan } = await import("./web-crawler-UHM7AOL2.js");
    const db = await getDb();
    if (!db) {
      console.error("[AutoCrawl] Database not available");
      return null;
    }
    const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));
    const webAssets = assets.filter((a) => {
      if (a.url && (a.url.startsWith("http://") || a.url.startsWith("https://"))) return true;
      if (a.hostname) {
        const assetType = (a.assetType || "").toLowerCase();
        if (["web_application", "api_endpoint", "cdn", "web_server", "load_balancer"].includes(assetType)) return true;
        const tags = a.tags || [];
        if (tags.some((t) => ["web", "http", "https", "api", "cdn"].includes(t.toLowerCase()))) return true;
        return true;
      }
      return false;
    });
    if (webAssets.length === 0) {
      console.log(`[AutoCrawl] No web-accessible assets found for scan ${scanId}`);
      return null;
    }
    console.log(`[AutoCrawl] Found ${webAssets.length} crawlable assets out of ${assets.length} total for scan ${scanId}`);
    const assetsToScan = webAssets.slice(0, 30);
    const results = [];
    let totalFindings = 0;
    const gradeOrder = ["F", "D", "C", "B", "A", "A+"];
    let worstGradeIdx = gradeOrder.length - 1;
    const allCarverAdjustments = [];
    const jobId = `auto_crawl_${scanId}_${Date.now()}`;
    try {
      await db.insert(webCrawlJobs).values({
        jobId,
        scanId,
        targetDomain: domain,
        seedUrls: assetsToScan.map((a) => a.url || `https://${a.hostname}`),
        maxDepth: 0,
        maxPages: assetsToScan.length,
        timeoutMs: 15e3,
        respectRobotsTxt: true,
        status: "running",
        totalUrlsQueued: assetsToScan.length,
        totalUrlsCrawled: 0,
        totalUrlsFailed: 0,
        totalFindings: 0,
        findingSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        technologiesSummary: [],
        securityGrade: "N/A",
        startedBy: "auto-crawl",
        startedAt,
        completedAt: null
      });
    } catch (err) {
      console.error(`[AutoCrawl] Failed to create job record: ${err.message}`);
    }
    for (let i = 0; i < assetsToScan.length; i += 3) {
      const batch = assetsToScan.slice(i, i + 3);
      const batchResults = await Promise.all(
        batch.map(async (asset) => {
          const url = asset.url || `https://${asset.hostname}`;
          try {
            const result = await quickScan(url);
            return { asset, url, result };
          } catch (err) {
            console.error(`[AutoCrawl] Failed to crawl ${url}: ${err.message}`);
            return { asset, url, result: null };
          }
        })
      );
      for (const { asset, url, result } of batchResults) {
        let assetCarverAdj = null;
        if (result) {
          try {
            assetCarverAdj = computeCrawlCarverAdjustment(result, asset.hostname);
            allCarverAdjustments.push(assetCarverAdj);
          } catch (err) {
            console.error(`[AutoCrawl] CARVER scoring failed for ${asset.hostname}: ${err.message}`);
          }
        }
        const summary2 = {
          assetId: asset.id,
          hostname: asset.hostname,
          url,
          httpStatus: result?.httpStatus || null,
          securityGrade: result?.securityHeaderGrade || null,
          findingCount: result?.findings.length || 0,
          technologies: result?.detectedTechnologies.map((t) => t.name) || [],
          carverAdjustment: assetCarverAdj
        };
        results.push(summary2);
        if (result) {
          totalFindings += result.findings.length;
          const gradeIdx = gradeOrder.indexOf(result.securityHeaderGrade);
          if (gradeIdx >= 0 && gradeIdx < worstGradeIdx) worstGradeIdx = gradeIdx;
          try {
            await db.insert(webCrawlResults).values({
              scanId,
              assetId: asset.id,
              targetUrl: url,
              finalUrl: result.finalUrl,
              domain: asset.hostname,
              status: "completed",
              httpStatus: result.httpStatus,
              responseTimeMs: result.responseTimeMs,
              contentType: result.contentType,
              contentLength: result.contentLength,
              depth: 0,
              securityHeaders: result.securityHeaders,
              securityHeaderGrade: result.securityHeaderGrade,
              detectedTechnologies: result.detectedTechnologies,
              serverHeader: result.serverHeader,
              poweredBy: result.poweredBy,
              pageTitle: result.pageTitle,
              metaDescription: result.metaDescription,
              internalLinks: result.internalLinks,
              externalLinks: result.externalLinks,
              resourceUrls: result.resourceUrls,
              forms: result.forms,
              exposedPaths: result.exposedPaths,
              robotsTxt: result.robotsTxt,
              securityTxt: result.securityTxt,
              sitemapUrls: result.sitemapUrls,
              cookies: result.cookies,
              tlsInfo: result.tlsInfo,
              findings: result.findings,
              findingCounts: result.findingCounts,
              totalFindings: result.findings.length,
              rawHeaders: result.rawHeaders,
              crawledBy: "auto-crawl",
              startedAt,
              completedAt: Date.now()
            });
          } catch (err) {
            console.error(`[AutoCrawl] Failed to persist result for ${asset.hostname}: ${err.message}`);
          }
        }
      }
    }
    const completedAt = Date.now();
    const totalCrawled = results.filter((r) => r.httpStatus !== null).length;
    const totalFailed = results.filter((r) => r.httpStatus === null).length;
    try {
      const { eq: eqOp } = await import("drizzle-orm");
      await db.update(webCrawlJobs).set({
        status: "completed",
        totalUrlsCrawled: totalCrawled,
        totalUrlsFailed: totalFailed,
        totalFindings,
        findingSummary: results.reduce(
          (acc, r) => acc,
          { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        ),
        securityGrade: gradeOrder[worstGradeIdx] || "F",
        completedAt
      }).where(eqOp(webCrawlJobs.jobId, jobId));
    } catch (err) {
      console.error(`[AutoCrawl] Failed to update job record: ${err.message}`);
    }
    const aggregatedCarver = aggregateCrawlAdjustments(allCarverAdjustments);
    try {
      const [scan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, scanId)).limit(1);
      if (scan) {
        const existingOutput = scan.pipelineOutput || {};
        await db.update(domainIntelScans).set({
          pipelineOutput: {
            ...existingOutput,
            autoCrawlSummary: {
              totalAssets: assetsToScan.length,
              totalCrawled,
              totalFailed,
              totalFindings,
              worstGrade: gradeOrder[worstGradeIdx] || "F",
              completedAt: new Date(completedAt).toISOString()
            },
            crawlCarverAdjustment: aggregatedCarver ? {
              carver: aggregatedCarver.carver,
              shock: aggregatedCarver.shock,
              likelihoodBoost: aggregatedCarver.likelihoodBoost,
              contextAdjustment: aggregatedCarver.contextAdjustment,
              overallWebVulnScore: aggregatedCarver.breakdown.overallWebVulnScore,
              assessmentConfidence: aggregatedCarver.breakdown.assessmentConfidence,
              postureFindings: aggregatedCarver.postureFindings
            } : null
          }
        }).where(eq(domainIntelScans.id, scanId));
      }
    } catch (err) {
      console.error(`[AutoCrawl] Failed to update scan with auto-crawl summary: ${err.message}`);
    }
    const summary = {
      scanId,
      domain,
      totalAssets: assetsToScan.length,
      totalCrawled,
      totalFailed,
      totalFindings,
      worstGrade: gradeOrder[worstGradeIdx] || "F",
      startedAt,
      completedAt,
      carverAdjustment: aggregatedCarver,
      results
    };
    const carverSummary = aggregatedCarver ? `, webVulnScore=${aggregatedCarver.breakdown.overallWebVulnScore}, postureFindings=${aggregatedCarver.postureFindings.length}` : ", no CARVER adjustments";
    console.log(`[AutoCrawl] Completed for scan ${scanId}: ${totalCrawled}/${assetsToScan.length} assets crawled, ${totalFindings} findings, grade=${summary.worstGrade}${carverSummary} in ${completedAt - startedAt}ms`);
    try {
      console.log(`[EntityResolver] Starting entity resolution for scan ${scanId} (${domain})`);
      const { resolveAndEnrichEntity, calculateFinancialImpact } = await import("./entity-resolver-TT23CRGV.js");
      const primaryCrawlResult = await db.select().from(webCrawlResults).where(eq(webCrawlResults.scanId, scanId)).limit(1);
      const crawlData = primaryCrawlResult[0];
      if (crawlData) {
        const [currentScanForWhois] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, scanId)).limit(1);
        const existingPipeline = currentScanForWhois?.pipelineOutput || {};
        const whoisOrg = existingPipeline?.passiveRecon?.domainRegistration?.registrantOrg || existingPipeline?.passiveRecon?.connectorResults?.find((c) => c.connector === "dehashed_whois")?.result?.registrantOrg || existingPipeline?.passiveRecon?.connectorResults?.find((c) => c.connector === "whoisxml")?.result?.registrant?.organization || null;
        const thirdPartyTitles = ["outlook", "sign in", "login", "microsoft", "google", "yahoo", "office 365", "webmail", "roundcube", "cpanel", "plesk", "wordpress"];
        const rawTitle = crawlData.pageTitle || "";
        const isThirdPartyTitle = thirdPartyTitles.some((t) => rawTitle.toLowerCase().includes(t));
        const filteredPageTitle = isThirdPartyTitle ? null : crawlData.pageTitle;
        const entityProfile = await resolveAndEnrichEntity({
          domain,
          pageTitle: filteredPageTitle,
          metaDescription: crawlData.metaDescription,
          html: null,
          // We don't store full HTML, rely on other signals
          externalLinks: crawlData.externalLinks,
          tlsInfo: crawlData.tlsInfo,
          whoisOrg,
          technologies: crawlData.detectedTechnologies?.map((t) => t.name) || null,
          rawHeaders: crawlData.rawHeaders
        });
        const financialImpact = calculateFinancialImpact(entityProfile);
        const [currentScan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, scanId)).limit(1);
        if (currentScan) {
          const existingOutput2 = currentScan.pipelineOutput || {};
          await db.update(domainIntelScans).set({
            pipelineOutput: {
              ...existingOutput2,
              entityProfile: {
                orgName: entityProfile.orgName,
                confidence: entityProfile.confidence,
                identificationMethod: entityProfile.identificationMethod,
                evidence: entityProfile.evidence,
                industry: entityProfile.industry,
                subSector: entityProfile.subSector,
                companySize: entityProfile.companySize,
                estimatedRevenue: entityProfile.estimatedRevenue,
                revenueConfidence: entityProfile.revenueConfidence,
                revenueSource: entityProfile.revenueSource,
                estimatedValuation: entityProfile.estimatedValuation,
                valuationConfidence: entityProfile.valuationConfidence,
                valuationSource: entityProfile.valuationSource,
                estimatedEmployees: entityProfile.estimatedEmployees,
                isPublicCompany: entityProfile.isPublicCompany,
                stockTicker: entityProfile.stockTicker,
                headquarters: entityProfile.headquarters,
                foundedYear: entityProfile.foundedYear,
                keyProducts: entityProfile.keyProducts,
                socialProfiles: entityProfile.socialProfiles,
                whoisOrg: entityProfile.whoisOrg,
                sslCertOrg: entityProfile.sslCertOrg,
                whoisIsHostingProvider: entityProfile.whoisIsHostingProvider
              },
              financialImpact: {
                maxSingleIncidentLoss: financialImpact.maxSingleIncidentLoss,
                estimatedDailyRevenueLoss: financialImpact.estimatedDailyRevenueLoss,
                regulatoryFineExposure: financialImpact.regulatoryFineExposure,
                reputationalDamageEstimate: financialImpact.reputationalDamageEstimate,
                totalMaxExposure: financialImpact.totalMaxExposure,
                impactTier: financialImpact.impactTier,
                rationale: financialImpact.rationale
              }
            }
          }).where(eq(domainIntelScans.id, scanId));
          console.log(`[EntityResolver] Identified entity for scan ${scanId}: ${entityProfile.orgName} (confidence: ${entityProfile.confidence}%, method: ${entityProfile.identificationMethod})`);
          console.log(`[EntityResolver] Financial impact tier: ${financialImpact.impactTier}, max exposure: $${(financialImpact.totalMaxExposure / 1e6).toFixed(1)}M`);
        }
      } else {
        console.log(`[EntityResolver] No crawl data available for entity resolution on scan ${scanId}`);
      }
    } catch (entityErr) {
      console.error(`[EntityResolver] Entity resolution failed for scan ${scanId} (non-fatal): ${entityErr.message}`);
    }
    try {
      const { listIntegrations, getClientForIntegration, cacheVendorData } = await import("./vendors-AX37I5C2.js");
      const integrations = await listIntegrations();
      const enabledIntegrations = integrations.filter((i) => i.enabled);
      if (enabledIntegrations.length > 0) {
        console.log(`[VendorCorrelation] Running alert correlation against ${enabledIntegrations.length} vendor(s) for scan ${scanId}`);
        const correlationResults = [];
        for (const integration of enabledIntegrations) {
          try {
            const client = await getClientForIntegration(integration.id);
            const now = Date.now();
            const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1e3;
            let alerts = [];
            let incidents = [];
            try {
              if ("listAlerts" in client && typeof client.listAlerts === "function") {
                alerts = await client.listAlerts({
                  limit: 25,
                  timeRange: { start: thirtyDaysAgo, end: now }
                });
              }
            } catch {
            }
            try {
              if ("listIncidents" in client && typeof client.listIncidents === "function") {
                incidents = await client.listIncidents({
                  limit: 25,
                  timeRange: { start: thirtyDaysAgo, end: now }
                });
              }
            } catch {
            }
            const domainAlerts = alerts.filter(
              (a) => a.hostname?.includes(domain) || a.domain?.includes(domain) || a.title?.toLowerCase().includes(domain.toLowerCase())
            );
            const domainIncidents = incidents.filter(
              (i) => i.title?.toLowerCase().includes(domain.toLowerCase()) || JSON.stringify(i.raw || {}).toLowerCase().includes(domain.toLowerCase())
            );
            const allCorrelated = [...domainAlerts, ...domainIncidents];
            if (allCorrelated.length > 0) {
              await cacheVendorData(integration.id, allCorrelated);
            }
            const { VENDOR_METADATA } = await import("./vendors-AX37I5C2.js");
            const meta = VENDOR_METADATA[integration.vendor];
            correlationResults.push({
              vendor: integration.vendor,
              displayName: meta?.displayName || integration.displayName,
              category: meta?.category || "Unknown",
              alertCount: domainAlerts.length,
              incidentCount: domainIncidents.length,
              matchedIOCs: 0,
              // Future: cross-reference IOCs from scan findings
              topAlerts: domainAlerts.slice(0, 5).map((a) => ({
                id: a.id,
                title: a.title,
                severity: a.severity
              }))
            });
            console.log(`[VendorCorrelation] ${meta?.displayName}: ${domainAlerts.length} alerts, ${domainIncidents.length} incidents for ${domain}`);
          } catch (vendorErr) {
            console.warn(`[VendorCorrelation] ${integration.vendor} correlation failed (non-fatal): ${vendorErr.message}`);
            correlationResults.push({
              vendor: integration.vendor,
              displayName: integration.displayName,
              category: "Unknown",
              alertCount: 0,
              incidentCount: 0,
              matchedIOCs: 0,
              topAlerts: []
            });
          }
        }
        const [currentScan3] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, scanId)).limit(1);
        if (currentScan3) {
          const existingOutput3 = currentScan3.pipelineOutput || {};
          await db.update(domainIntelScans).set({
            pipelineOutput: {
              ...existingOutput3,
              vendorCorrelation: {
                correlatedAt: Date.now(),
                vendorCount: enabledIntegrations.length,
                totalAlerts: correlationResults.reduce((s, r) => s + r.alertCount, 0),
                totalIncidents: correlationResults.reduce((s, r) => s + r.incidentCount, 0),
                results: correlationResults
              }
            }
          }).where(eq(domainIntelScans.id, scanId));
        }
        console.log(`[VendorCorrelation] Completed: ${correlationResults.reduce((s, r) => s + r.alertCount, 0)} total correlated alerts across ${enabledIntegrations.length} vendor(s)`);
      } else {
        console.log(`[VendorCorrelation] No enabled vendor integrations \u2014 skipping alert correlation for scan ${scanId}`);
      }
    } catch (vendorCorrelationErr) {
      console.error(`[VendorCorrelation] Vendor correlation failed for scan ${scanId} (non-fatal): ${vendorCorrelationErr.message}`);
    }
    return summary;
  } catch (err) {
    console.error(`[AutoCrawl] Fatal error for scan ${scanId}: ${err.message}`);
    return null;
  }
}
export {
  triggerAutoCrawl
};
