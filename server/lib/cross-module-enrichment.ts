/**
 * Cross-Module Enrichment Bridge
 *
 * This module integrates Bug Bounty Intelligence, Threat Enrichment, OpSec,
 * and Discovery Engine data back into the main domain intel pipeline.
 *
 * It runs as Stage 3.95 in the pipeline — AFTER all vuln/KEV/exploit/port/email
 * enrichment stages, but BEFORE the final hybrid risk recalculation.
 *
 * Two-way enrichment flow:
 * 1. Pipeline → Modules: Sends discovered assets, technologies, and findings
 *    to Bug Bounty, Threat Intel, and OpSec modules for context-aware analysis
 * 2. Modules → Pipeline: Receives correlations, risk adjustments, and new
 *    findings that get injected back into the asset analyses
 *
 * This ensures that:
 * - Bug bounty program scope and historical vulns inform asset risk scoring
 * - Trending threat actor TTPs boost scores for matching attack surfaces
 * - OpSec defensive gaps create new posture findings on affected assets
 * - Discovery Engine deep-dive data (DNS history, cert analysis) enriches assets
 */

import type { AssetAnalysis, PostureFinding, CorroborationTier, CarverScores, ShockScores } from "../domainIntel";
import type { PassiveReconResult } from "./passive/index";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CrossModuleEnrichmentResult {
  bugBounty: BugBountyEnrichmentResult;
  threatIntel: ThreatIntelEnrichmentResult;
  opsec: OpSecEnrichmentResult;
  discoveryDeepDive: DiscoveryDeepDiveResult;
  summary: {
    totalCorrelations: number;
    totalNewFindings: number;
    totalRiskAdjustments: number;
    modulesRun: number;
    modulesSucceeded: number;
    modulesFailed: number;
    durationMs: number;
  };
}

export interface BugBountyEnrichmentResult {
  status: "success" | "failed" | "skipped";
  hasBugBountyProgram: boolean;
  programName: string | null;
  inScopeAssets: string[];
  historicalVulnPatterns: Array<{ cwe: string; count: number; avgBounty: number }>;
  correlations: EnrichmentCorrelation[];
  newFindings: PostureFinding[];
  error?: string;
}

export interface ThreatIntelEnrichmentResult {
  status: "success" | "failed" | "skipped";
  matchingThreatActors: Array<{ name: string; relevance: string; techniques: string[] }>;
  trendingWeaknesses: Array<{ cwe: string; trend: string; recentCount: number }>;
  correlations: EnrichmentCorrelation[];
  riskAdjustments: Array<{ assetId: string; adjustment: number; reason: string }>;
  error?: string;
}

export interface OpSecEnrichmentResult {
  status: "success" | "failed" | "skipped";
  defensiveGaps: Array<{ category: string; severity: string; description: string; affectedAssets: string[] }>;
  correlations: EnrichmentCorrelation[];
  newFindings: PostureFinding[];
  error?: string;
}

export interface DiscoveryDeepDiveResult {
  status: "success" | "failed" | "skipped";
  dnsHistoryChanges: Array<{ domain: string; oldIp: string; newIp: string; changedAt: string }>;
  certificateFindings: Array<{ subject: string; issue: string; severity: string }>;
  infrastructureInsights: Array<{ type: string; detail: string; confidence: number }>;
  correlations: EnrichmentCorrelation[];
  error?: string;
}

export interface EnrichmentCorrelation {
  sourceModule: string;
  targetModule: string;
  correlationType: "confirms" | "extends" | "contradicts" | "new_finding";
  description: string;
  confidence: number;
  relatedAssets: string[];
  riskImpact: number; // -10 to +10
}

// ─── Bug Bounty Enrichment ──────────────────────────────────────────────────

async function enrichFromBugBounty(
  analyses: AssetAnalysis[],
  domain: string,
): Promise<BugBountyEnrichmentResult> {
  try {
    const { enrichDomainIntel } = await import("./bug-bounty-intelligence");
    const bbData = await enrichDomainIntel(domain);

    const correlations: EnrichmentCorrelation[] = [];
    const newFindings: PostureFinding[] = [];
    const inScopeAssets: string[] = [];

    // Check if any discovered assets fall within bug bounty scope
    if (bbData.hasBugBountyProgram) {
      for (const a of analyses) {
        const hostname = a.asset.hostname?.toLowerCase() || "";
        // Check if asset is in scope (simplified scope matching)
        if (hostname.endsWith(`.${domain}`) || hostname === domain) {
          inScopeAssets.push(a.asset.assetId);
        }
      }

      if (inScopeAssets.length > 0) {
        correlations.push({
          sourceModule: "bug_bounty",
          targetModule: "domain_intel",
          correlationType: "extends",
          description: `${inScopeAssets.length} discovered assets fall within active bug bounty program scope (${bbData.programName}). Historical vulnerability patterns available for risk calibration.`,
          confidence: 0.85,
          relatedAssets: inScopeAssets,
          riskImpact: 2, // Slight risk increase — active bounty means attackers are looking
        });
      }
    }

    // Cross-reference historical CWE patterns with discovered technologies
    if (bbData.topCWEs && bbData.topCWEs.length > 0) {
      const cweToTech: Record<string, string[]> = {
        "CWE-79": ["JavaScript", "React", "Angular", "Vue", "jQuery"],
        "CWE-89": ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "MariaDB"],
        "CWE-22": ["Apache", "Nginx", "IIS", "Tomcat"],
        "CWE-352": ["PHP", "Django", "Rails", "Express"],
        "CWE-502": ["Java", "Python", ".NET", "PHP"],
        "CWE-918": ["Node.js", "Python", "Java", "Go"],
        "CWE-287": ["OAuth", "SAML", "JWT", "LDAP"],
        "CWE-200": ["Apache", "Nginx", "IIS", "Express"],
      };

      for (const cwe of bbData.topCWEs.slice(0, 5)) {
        const matchingTechs = cweToTech[cwe.cwe] || [];
        for (const a of analyses) {
          const assetTechs = (a.asset.technologies || []).map(t => t.toLowerCase());
          const matched = matchingTechs.filter(t =>
            assetTechs.some(at => at.includes(t.toLowerCase()))
          );
          if (matched.length > 0) {
            correlations.push({
              sourceModule: "bug_bounty",
              targetModule: "domain_intel",
              correlationType: "extends",
              description: `Asset ${a.asset.hostname} uses ${matched.join(", ")} — historically associated with ${cwe.cwe} (${cwe.count} bounty reports). Consider targeted testing.`,
              confidence: 0.7,
              relatedAssets: [a.asset.assetId],
              riskImpact: 1,
            });
          }
        }
      }
    }

    // Generate advisory findings for assets with matching historical vuln patterns
    if (bbData.disclosedVulnerabilities && bbData.disclosedVulnerabilities.total > 0) {
      const primaryAsset = analyses.find(a =>
        a.asset.hostname === domain || a.asset.hostname?.endsWith(`.${domain}`)
      );
      if (primaryAsset) {
        newFindings.push({
          id: `bb-history-${domain}-${Date.now().toString(36)}`,
          assetRef: primaryAsset.asset.assetId,
          assetHostname: primaryAsset.asset.hostname,
          category: "Bug Bounty Intelligence",
          title: `Active bug bounty program with ${bbData.disclosedVulnerabilities.total} disclosed vulnerabilities`,
          severity: 3,
          likelihood: 5,
          confidence: 0.8,
          recommendedControls: [
            "Review historical bounty reports for recurring vulnerability patterns",
            "Prioritize testing for top CWEs from bounty history",
            "Monitor bug bounty program for new disclosures",
          ],
          corroborationTier: "probable" as CorroborationTier,
          evidenceChain: [
            `Bug bounty program "${bbData.programName}" is active for ${domain}`,
            `${bbData.disclosedVulnerabilities.total} vulnerabilities previously disclosed through the program`,
            `Top weakness categories: ${bbData.topCWEs?.slice(0, 3).map(c => c.cwe).join(", ") || "N/A"}`,
            "Historical patterns suggest continued attacker interest in this target",
          ],
        });
      }
    }

    return {
      status: "success",
      hasBugBountyProgram: bbData.hasBugBountyProgram,
      programName: bbData.programName || null,
      inScopeAssets,
      historicalVulnPatterns: bbData.topCWEs?.map(c => ({
        cwe: c.cwe,
        count: c.count,
        avgBounty: bbData.avgBountyAmount || 0,
      })) || [],
      correlations,
      newFindings,
    };
  } catch (err: any) {
    console.error(`[CrossModuleEnrichment] Bug bounty enrichment failed: ${err.message}`);
    return {
      status: "failed",
      hasBugBountyProgram: false,
      programName: null,
      inScopeAssets: [],
      historicalVulnPatterns: [],
      correlations: [],
      newFindings: [],
      error: err.message,
    };
  }
}

// ─── Threat Intelligence Enrichment ─────────────────────────────────────────

async function enrichFromThreatIntel(
  analyses: AssetAnalysis[],
): Promise<ThreatIntelEnrichmentResult> {
  try {
    const { enrichThreatIntelligence } = await import("./bug-bounty-intelligence");
    const threatData = await enrichThreatIntelligence(30);

    const correlations: EnrichmentCorrelation[] = [];
    const riskAdjustments: Array<{ assetId: string; adjustment: number; reason: string }> = [];

    // Cross-reference discovered services with trending weaknesses
    if (threatData.trendingWeaknesses) {
      const risingWeaknesses = threatData.trendingWeaknesses.filter(w => w.trend === "rising");
      if (risingWeaknesses.length > 0) {
        correlations.push({
          sourceModule: "threat_enrichment",
          targetModule: "domain_intel",
          correlationType: "extends",
          description: `${risingWeaknesses.length} rising weakness trends detected in the threat landscape. Cross-referencing with discovered attack surface.`,
          confidence: 0.75,
          relatedAssets: analyses.map(a => a.asset.assetId),
          riskImpact: 1,
        });
      }
    }

    // Cross-reference exploit patterns with discovered technologies
    if (threatData.exploitPatterns) {
      for (const pattern of threatData.exploitPatterns) {
        for (const a of analyses) {
          const techs = (a.asset.technologies || []).map(t => t.toLowerCase());
          // Check if any technology matches the exploit pattern's target
          const patternTarget = (pattern.pattern || pattern.description || "").toLowerCase();
          if (patternTarget && techs.some(t => patternTarget.includes(t.toLowerCase()))) {
            riskAdjustments.push({
              assetId: a.asset.assetId,
              adjustment: 3,
              reason: `Trending exploit pattern "${pattern.pattern}" targets technology found on ${a.asset.hostname}`,
            });
            correlations.push({
              sourceModule: "threat_enrichment",
              targetModule: "domain_intel",
              correlationType: "confirms",
              description: `Exploit pattern "${pattern.pattern}" matches technology on ${a.asset.hostname}. Active exploitation in the wild increases risk.`,
              confidence: 0.8,
              relatedAssets: [a.asset.assetId],
              riskImpact: 3,
            });
          }
        }
      }
    }

    // Map trending weaknesses as threat actor indicators
    const matchingActors: Array<{ name: string; relevance: string; techniques: string[] }> = [];
    // Derive actor relevance from trending weakness patterns
    if (threatData.trendingWeaknesses) {
      const risingCWEs = threatData.trendingWeaknesses.filter(w => w.trend === "rising");
      if (risingCWEs.length > 0) {
        matchingActors.push({
          name: "Active Exploit Campaigns",
          relevance: "high",
          techniques: risingCWEs.map(w => w.cwe).slice(0, 5),
        });
      }
    }

    return {
      status: "success",
      matchingThreatActors: matchingActors.slice(0, 10),
      trendingWeaknesses: threatData.trendingWeaknesses?.map(w => ({
        cwe: w.cwe,
        trend: w.trend,
        recentCount: w.recentCount,
      })) || [],
      correlations,
      riskAdjustments,
    };
  } catch (err: any) {
    console.error(`[CrossModuleEnrichment] Threat intel enrichment failed: ${err.message}`);
    return {
      status: "failed",
      matchingThreatActors: [],
      trendingWeaknesses: [],
      correlations: [],
      riskAdjustments: [],
      error: err.message,
    };
  }
}

// ─── OpSec Enrichment ───────────────────────────────────────────────────────

async function enrichFromOpSec(
  analyses: AssetAnalysis[],
  passiveRecon?: PassiveReconResult,
): Promise<OpSecEnrichmentResult> {
  try {
    const { enrichOpSec } = await import("./bug-bounty-intelligence");
    const opsecData = await enrichOpSec();

    const correlations: EnrichmentCorrelation[] = [];
    const newFindings: PostureFinding[] = [];
    const defensiveGaps: OpSecEnrichmentResult["defensiveGaps"] = [];

    // Map discovered ports to defensive gap categories
    const remoteAccessAssets = analyses.filter(a =>
      a.postureFindings.some(f =>
        f.category === "Exposed Port" &&
        (f.title.includes("RDP") || f.title.includes("SSH") || f.title.includes("VNC") || f.title.includes("Telnet"))
      )
    );

    if (remoteAccessAssets.length > 0) {
      defensiveGaps.push({
        category: "Remote Access Exposure",
        severity: "high",
        description: `${remoteAccessAssets.length} assets expose remote access services (RDP, SSH, VNC, Telnet) directly to the internet`,
        affectedAssets: remoteAccessAssets.map(a => a.asset.hostname),
      });

      correlations.push({
        sourceModule: "discovery_engine",
        targetModule: "opsec",
        correlationType: "new_finding",
        description: `${remoteAccessAssets.length} assets with exposed remote access ports identified. These represent high-priority defensive gaps.`,
        confidence: 0.95,
        relatedAssets: remoteAccessAssets.map(a => a.asset.assetId),
        riskImpact: 5,
      });
    }

    // Check for database exposure
    const dbAssets = analyses.filter(a =>
      a.postureFindings.some(f =>
        f.category === "Exposed Port" &&
        (f.title.includes("MySQL") || f.title.includes("PostgreSQL") || f.title.includes("MongoDB") ||
         f.title.includes("Redis") || f.title.includes("Elasticsearch"))
      )
    );

    if (dbAssets.length > 0) {
      defensiveGaps.push({
        category: "Database Exposure",
        severity: "critical",
        description: `${dbAssets.length} assets expose database services directly to the internet`,
        affectedAssets: dbAssets.map(a => a.asset.hostname),
      });

      for (const a of dbAssets) {
        newFindings.push({
          id: `opsec-db-${a.asset.assetId}-${Date.now().toString(36)}`,
          assetRef: a.asset.assetId,
          assetHostname: a.asset.hostname,
          category: "OpSec Defensive Gap",
          title: `Internet-exposed database service on ${a.asset.hostname}`,
          severity: 8,
          likelihood: 7,
          confidence: 0.9,
          recommendedControls: [
            "Restrict database access to internal networks only",
            "Implement network segmentation and firewall rules",
            "Enable authentication and encryption for database connections",
            "Monitor for unauthorized access attempts",
          ],
          corroborationTier: "confirmed" as CorroborationTier,
          evidenceChain: [
            `Database service detected on ${a.asset.hostname} via passive scanning`,
            "Service is reachable from the public internet",
            "Cross-module enrichment: OpSec module flagged as critical defensive gap",
          ],
        });
      }
    }

    // Check for missing security headers (from HTTP security connector data)
    if (passiveRecon) {
      const httpSecResults = passiveRecon.connectorResults.find(r => r.connector === "http-security");
      if (httpSecResults && httpSecResults.observations.length > 0) {
        const missingHeaders = httpSecResults.observations.filter(o =>
          o.tags.includes("missing_security_header")
        );
        if (missingHeaders.length > 0) {
          defensiveGaps.push({
            category: "Missing Security Headers",
            severity: "medium",
            description: `${missingHeaders.length} security header deficiencies detected across web assets`,
            affectedAssets: missingHeaders.map(o => o.name || o.domain),
          });
        }
      }
    }

    // Check for weak OpSec categories from the enrichment module
    if (opsecData.weaknessCategories) {
      for (const weakness of opsecData.weaknessCategories) {
        defensiveGaps.push({
          category: weakness.category || "General",
          severity: weakness.defensivePriority || "medium",
          description: weakness.mitigationFocus || "Defensive weakness identified",
          affectedAssets: [],
        });
      }
    }

    return {
      status: "success",
      defensiveGaps,
      correlations,
      newFindings,
    };
  } catch (err: any) {
    console.error(`[CrossModuleEnrichment] OpSec enrichment failed: ${err.message}`);
    return {
      status: "failed",
      defensiveGaps: [],
      correlations: [],
      newFindings: [],
      error: err.message,
    };
  }
}

// ─── Discovery Engine Deep Dive ─────────────────────────────────────────────

async function enrichFromDiscoveryDeepDive(
  analyses: AssetAnalysis[],
  domain: string,
  passiveRecon?: PassiveReconResult,
): Promise<DiscoveryDeepDiveResult> {
  try {
    const { securityTrailsDNSHistory, censysCertSearch } = await import("./discovery-engine");

    const dnsHistoryChanges: DiscoveryDeepDiveResult["dnsHistoryChanges"] = [];
    const certificateFindings: DiscoveryDeepDiveResult["certificateFindings"] = [];
    const infrastructureInsights: DiscoveryDeepDiveResult["infrastructureInsights"] = [];
    const correlations: EnrichmentCorrelation[] = [];

    // 1. DNS History Analysis — detect infrastructure changes
    try {
      const dnsHistory = await securityTrailsDNSHistory(domain);
      if (dnsHistory.length > 1) {
        // Sort by lastSeen to detect changes
        const sorted = dnsHistory
          .filter(r => r.lastSeen)
          .sort((a, b) => new Date(b.lastSeen!).getTime() - new Date(a.lastSeen!).getTime());

        const currentIPs = new Set(sorted.filter(r => {
          const lastSeen = new Date(r.lastSeen!);
          const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          return lastSeen > thirtyDaysAgo;
        }).map(r => r.value));

        const historicalIPs = sorted.filter(r => !currentIPs.has(r.value));

        if (historicalIPs.length > 0) {
          infrastructureInsights.push({
            type: "dns_migration",
            detail: `${domain} has changed IP addresses ${historicalIPs.length} times. Current: ${Array.from(currentIPs).join(", ")}. Previous: ${historicalIPs.slice(0, 3).map(r => r.value).join(", ")}`,
            confidence: 0.85,
          });

          for (const hist of historicalIPs.slice(0, 5)) {
            dnsHistoryChanges.push({
              domain,
              oldIp: hist.value,
              newIp: Array.from(currentIPs)[0] || "unknown",
              changedAt: hist.lastSeen || "unknown",
            });
          }
        }

        // Detect hosting provider changes
        const uniqueASNs = new Set<string>();
        for (const obs of passiveRecon?.allObservations || []) {
          if (obs.evidence?.asn) uniqueASNs.add(String(obs.evidence.asn));
        }
        if (uniqueASNs.size > 1) {
          infrastructureInsights.push({
            type: "multi_provider",
            detail: `Infrastructure spans ${uniqueASNs.size} different ASNs/providers, suggesting distributed hosting or CDN usage`,
            confidence: 0.8,
          });
        }
      }
    } catch (err: any) {
      console.error(`[CrossModuleEnrichment] DNS history analysis failed: ${err.message}`);
    }

    // 2. Certificate Analysis — find expired, weak, or misconfigured certs
    try {
      const certs = await censysCertSearch(domain);
      for (const cert of certs) {
        if (cert.isExpired) {
          certificateFindings.push({
            subject: cert.subject,
            issue: `Expired certificate (valid until ${cert.validTo})`,
            severity: "high",
          });
        }
        if (cert.isWildcard) {
          certificateFindings.push({
            subject: cert.subject,
            issue: `Wildcard certificate detected — covers all subdomains`,
            severity: "info",
          });
        }
        // Check for SANs that reveal additional infrastructure
        const newDomains = cert.sans.filter(san =>
          san.endsWith(`.${domain}`) &&
          !san.startsWith("*.") &&
          !analyses.some(a => a.asset.hostname === san)
        );
        if (newDomains.length > 0) {
          infrastructureInsights.push({
            type: "cert_san_discovery",
            detail: `Certificate for ${cert.subject} reveals ${newDomains.length} additional subdomains not yet in asset inventory: ${newDomains.slice(0, 5).join(", ")}`,
            confidence: 0.9,
          });
          correlations.push({
            sourceModule: "discovery_engine",
            targetModule: "domain_intel",
            correlationType: "new_finding",
            description: `Certificate SAN analysis revealed ${newDomains.length} additional subdomains for ${domain}`,
            confidence: 0.9,
            relatedAssets: [],
            riskImpact: 1,
          });
        }
      }

      if (certificateFindings.filter(f => f.severity === "high").length > 0) {
        correlations.push({
          sourceModule: "discovery_engine",
          targetModule: "domain_intel",
          correlationType: "new_finding",
          description: `${certificateFindings.filter(f => f.severity === "high").length} certificate issues found (expired, weak, or misconfigured)`,
          confidence: 0.85,
          relatedAssets: analyses.map(a => a.asset.assetId),
          riskImpact: 2,
        });
      }
    } catch (err: any) {
      console.error(`[CrossModuleEnrichment] Certificate analysis failed: ${err.message}`);
    }

    // 3. Infrastructure pattern analysis from passive recon
    if (passiveRecon) {
      // Detect cloud provider usage
      const cloudObs = passiveRecon.allObservations.filter(o =>
        o.tags.some(t => t.includes("aws") || t.includes("azure") || t.includes("gcp") || t.includes("cloudflare"))
      );
      if (cloudObs.length > 0) {
        const providers = new Set(cloudObs.flatMap(o =>
          o.tags.filter(t => t.includes("aws") || t.includes("azure") || t.includes("gcp") || t.includes("cloudflare"))
        ));
        infrastructureInsights.push({
          type: "cloud_infrastructure",
          detail: `Cloud infrastructure detected: ${Array.from(providers).join(", ")}. ${cloudObs.length} cloud-hosted assets identified.`,
          confidence: 0.85,
        });
      }

      // Detect WAF/CDN usage
      const wafObs = passiveRecon.allObservations.filter(o =>
        o.tags.some(t => t.includes("waf") || t.includes("cdn"))
      );
      if (wafObs.length > 0) {
        infrastructureInsights.push({
          type: "waf_cdn_detection",
          detail: `WAF/CDN protection detected on ${wafObs.length} assets. This affects scan accuracy and attack surface visibility.`,
          confidence: 0.8,
        });
      }
    }

    return {
      status: "success",
      dnsHistoryChanges,
      certificateFindings,
      infrastructureInsights,
      correlations,
    };
  } catch (err: any) {
    console.error(`[CrossModuleEnrichment] Discovery deep dive failed: ${err.message}`);
    return {
      status: "failed",
      dnsHistoryChanges: [],
      certificateFindings: [],
      infrastructureInsights: [],
      correlations: [],
      error: err.message,
    };
  }
}

// ─── Main Orchestrator ──────────────────────────────────────────────────────

/**
 * Run cross-module enrichment on analyzed assets.
 * Call this as Stage 3.95 in the domain intel pipeline.
 *
 * @param analyses - The asset analyses from Stage 2-3 (with posture findings)
 * @param domain - The primary domain being scanned
 * @param passiveRecon - The passive recon results from Stage 0.5
 * @returns CrossModuleEnrichmentResult with correlations, new findings, and risk adjustments
 */
export async function runCrossModuleEnrichment(
  analyses: AssetAnalysis[],
  domain: string,
  passiveRecon?: PassiveReconResult,
): Promise<CrossModuleEnrichmentResult> {
  const start = Date.now();

  // Run all enrichment modules in parallel
  const [bugBounty, threatIntel, opsec, discoveryDeepDive] = await Promise.allSettled([
    enrichFromBugBounty(analyses, domain),
    enrichFromThreatIntel(analyses),
    enrichFromOpSec(analyses, passiveRecon),
    enrichFromDiscoveryDeepDive(analyses, domain, passiveRecon),
  ]);

  const bbResult = bugBounty.status === "fulfilled" ? bugBounty.value : {
    status: "failed" as const, hasBugBountyProgram: false, programName: null,
    inScopeAssets: [], historicalVulnPatterns: [], correlations: [], newFindings: [],
    error: bugBounty.status === "rejected" ? String(bugBounty.reason) : "Unknown error",
  };

  const tiResult = threatIntel.status === "fulfilled" ? threatIntel.value : {
    status: "failed" as const, matchingThreatActors: [], trendingWeaknesses: [],
    correlations: [], riskAdjustments: [],
    error: threatIntel.status === "rejected" ? String(threatIntel.reason) : "Unknown error",
  };

  const osResult = opsec.status === "fulfilled" ? opsec.value : {
    status: "failed" as const, defensiveGaps: [], correlations: [], newFindings: [],
    error: opsec.status === "rejected" ? String(opsec.reason) : "Unknown error",
  };

  const ddResult = discoveryDeepDive.status === "fulfilled" ? discoveryDeepDive.value : {
    status: "failed" as const, dnsHistoryChanges: [], certificateFindings: [],
    infrastructureInsights: [], correlations: [],
    error: discoveryDeepDive.status === "rejected" ? String(discoveryDeepDive.reason) : "Unknown error",
  };

  // ─── Apply enrichment results back to analyses ─────────────────────

  // 1. Inject new findings from Bug Bounty and OpSec
  const allNewFindings = [...bbResult.newFindings, ...osResult.newFindings];
  for (const finding of allNewFindings) {
    const targetAnalysis = analyses.find(a => a.asset.assetId === finding.assetRef);
    if (targetAnalysis) {
      // Avoid duplicates
      if (!targetAnalysis.postureFindings.some(f => f.id === finding.id)) {
        targetAnalysis.postureFindings.push(finding);
      }
    }
  }

  // 2. Apply threat intel risk adjustments
  for (const adj of tiResult.riskAdjustments) {
    const targetAnalysis = analyses.find(a => a.asset.assetId === adj.assetId);
    if (targetAnalysis) {
      // Store adjustment for the post-enrichment recalculation
      (targetAnalysis as any)._threatIntelBoost = (
        ((targetAnalysis as any)._threatIntelBoost || 0) + adj.adjustment
      );
    }
  }

  // Aggregate stats
  const allCorrelations = [
    ...bbResult.correlations,
    ...tiResult.correlations,
    ...osResult.correlations,
    ...ddResult.correlations,
  ];

  const modules = [bbResult, tiResult, osResult, ddResult];
  const modulesSucceeded = modules.filter(m => m.status === "success").length;
  const modulesFailed = modules.filter(m => m.status === "failed").length;

  const result: CrossModuleEnrichmentResult = {
    bugBounty: bbResult,
    threatIntel: tiResult,
    opsec: osResult,
    discoveryDeepDive: ddResult,
    summary: {
      totalCorrelations: allCorrelations.length,
      totalNewFindings: allNewFindings.length,
      totalRiskAdjustments: tiResult.riskAdjustments.length,
      modulesRun: 4,
      modulesSucceeded,
      modulesFailed,
      durationMs: Date.now() - start,
    },
  };

  console.log(
    `[CrossModuleEnrichment] Complete: ${modulesSucceeded}/4 modules succeeded, ` +
    `${allCorrelations.length} correlations, ${allNewFindings.length} new findings, ` +
    `${tiResult.riskAdjustments.length} risk adjustments (${Date.now() - start}ms)`
  );

  return result;
}
