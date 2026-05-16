import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cross-module-enrichment.ts
async function enrichFromBugBounty(analyses, domain) {
  try {
    const { enrichDomainIntel } = await import("./bug-bounty-intelligence-Z6HACD4O.js");
    const bbData = await enrichDomainIntel(domain);
    const correlations = [];
    const newFindings = [];
    const inScopeAssets = [];
    if (bbData.hasBugBountyProgram) {
      for (const a of analyses) {
        const hostname = a.asset.hostname?.toLowerCase() || "";
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
          riskImpact: 2
          // Slight risk increase — active bounty means attackers are looking
        });
      }
    }
    if (bbData.topCWEs && bbData.topCWEs.length > 0) {
      const cweToTech = {
        "CWE-79": ["JavaScript", "React", "Angular", "Vue", "jQuery"],
        "CWE-89": ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "MariaDB"],
        "CWE-22": ["Apache", "Nginx", "IIS", "Tomcat"],
        "CWE-352": ["PHP", "Django", "Rails", "Express"],
        "CWE-502": ["Java", "Python", ".NET", "PHP"],
        "CWE-918": ["Node.js", "Python", "Java", "Go"],
        "CWE-287": ["OAuth", "SAML", "JWT", "LDAP"],
        "CWE-200": ["Apache", "Nginx", "IIS", "Express"]
      };
      for (const cwe of bbData.topCWEs.slice(0, 5)) {
        const matchingTechs = cweToTech[cwe.cwe] || [];
        for (const a of analyses) {
          const assetTechs = (a.asset.technologies || []).map((t) => t.toLowerCase());
          const matched = matchingTechs.filter(
            (t) => assetTechs.some((at) => at.includes(t.toLowerCase()))
          );
          if (matched.length > 0) {
            correlations.push({
              sourceModule: "bug_bounty",
              targetModule: "domain_intel",
              correlationType: "extends",
              description: `Asset ${a.asset.hostname} uses ${matched.join(", ")} \u2014 historically associated with ${cwe.cwe} (${cwe.count} bounty reports). Consider targeted testing.`,
              confidence: 0.7,
              relatedAssets: [a.asset.assetId],
              riskImpact: 1
            });
          }
        }
      }
    }
    if (bbData.disclosedVulnerabilities && bbData.disclosedVulnerabilities.total > 0) {
      const primaryAsset = analyses.find(
        (a) => a.asset.hostname === domain || a.asset.hostname?.endsWith(`.${domain}`)
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
            "Monitor bug bounty program for new disclosures"
          ],
          corroborationTier: "probable",
          evidenceChain: [
            `Bug bounty program "${bbData.programName}" is active for ${domain}`,
            `${bbData.disclosedVulnerabilities.total} vulnerabilities previously disclosed through the program`,
            `Top weakness categories: ${bbData.topCWEs?.slice(0, 3).map((c) => c.cwe).join(", ") || "N/A"}`,
            "Historical patterns suggest continued attacker interest in this target"
          ]
        });
      }
    }
    return {
      status: "success",
      hasBugBountyProgram: bbData.hasBugBountyProgram,
      programName: bbData.programName || null,
      inScopeAssets,
      historicalVulnPatterns: bbData.topCWEs?.map((c) => ({
        cwe: c.cwe,
        count: c.count,
        avgBounty: bbData.avgBountyAmount || 0
      })) || [],
      correlations,
      newFindings
    };
  } catch (err) {
    console.error(`[CrossModuleEnrichment] Bug bounty enrichment failed: ${err.message}`);
    return {
      status: "failed",
      hasBugBountyProgram: false,
      programName: null,
      inScopeAssets: [],
      historicalVulnPatterns: [],
      correlations: [],
      newFindings: [],
      error: err.message
    };
  }
}
async function enrichFromThreatIntel(analyses) {
  try {
    const { enrichThreatIntelligence } = await import("./bug-bounty-intelligence-Z6HACD4O.js");
    const threatData = await enrichThreatIntelligence(30);
    const correlations = [];
    const riskAdjustments = [];
    if (threatData.trendingWeaknesses) {
      const risingWeaknesses = threatData.trendingWeaknesses.filter((w) => w.trend === "rising");
      if (risingWeaknesses.length > 0) {
        correlations.push({
          sourceModule: "threat_enrichment",
          targetModule: "domain_intel",
          correlationType: "extends",
          description: `${risingWeaknesses.length} rising weakness trends detected in the threat landscape. Cross-referencing with discovered attack surface.`,
          confidence: 0.75,
          relatedAssets: analyses.map((a) => a.asset.assetId),
          riskImpact: 1
        });
      }
    }
    if (threatData.exploitPatterns) {
      for (const pattern of threatData.exploitPatterns) {
        for (const a of analyses) {
          const techs = (a.asset.technologies || []).map((t) => t.toLowerCase());
          const patternTarget = (pattern.pattern || pattern.description || "").toLowerCase();
          if (patternTarget && techs.some((t) => patternTarget.includes(t.toLowerCase()))) {
            riskAdjustments.push({
              assetId: a.asset.assetId,
              adjustment: 3,
              reason: `Trending exploit pattern "${pattern.pattern}" targets technology found on ${a.asset.hostname}`
            });
            correlations.push({
              sourceModule: "threat_enrichment",
              targetModule: "domain_intel",
              correlationType: "confirms",
              description: `Exploit pattern "${pattern.pattern}" matches technology on ${a.asset.hostname}. Active exploitation in the wild increases risk.`,
              confidence: 0.8,
              relatedAssets: [a.asset.assetId],
              riskImpact: 3
            });
          }
        }
      }
    }
    const matchingActors = [];
    if (threatData.trendingWeaknesses) {
      const risingCWEs = threatData.trendingWeaknesses.filter((w) => w.trend === "rising");
      if (risingCWEs.length > 0) {
        matchingActors.push({
          name: "Active Exploit Campaigns",
          relevance: "high",
          techniques: risingCWEs.map((w) => w.cwe).slice(0, 5)
        });
      }
    }
    return {
      status: "success",
      matchingThreatActors: matchingActors.slice(0, 10),
      trendingWeaknesses: threatData.trendingWeaknesses?.map((w) => ({
        cwe: w.cwe,
        trend: w.trend,
        recentCount: w.recentCount
      })) || [],
      correlations,
      riskAdjustments
    };
  } catch (err) {
    console.error(`[CrossModuleEnrichment] Threat intel enrichment failed: ${err.message}`);
    return {
      status: "failed",
      matchingThreatActors: [],
      trendingWeaknesses: [],
      correlations: [],
      riskAdjustments: [],
      error: err.message
    };
  }
}
async function enrichFromOpSec(analyses, passiveRecon) {
  try {
    const { enrichOpSec } = await import("./bug-bounty-intelligence-Z6HACD4O.js");
    const opsecData = await enrichOpSec();
    const correlations = [];
    const newFindings = [];
    const defensiveGaps = [];
    const remoteAccessAssets = analyses.filter(
      (a) => a.postureFindings.some(
        (f) => f.category === "Exposed Port" && (f.title.includes("RDP") || f.title.includes("SSH") || f.title.includes("VNC") || f.title.includes("Telnet"))
      )
    );
    if (remoteAccessAssets.length > 0) {
      defensiveGaps.push({
        category: "Remote Access Exposure",
        severity: "high",
        description: `${remoteAccessAssets.length} assets expose remote access services (RDP, SSH, VNC, Telnet) directly to the internet`,
        affectedAssets: remoteAccessAssets.map((a) => a.asset.hostname)
      });
      correlations.push({
        sourceModule: "discovery_engine",
        targetModule: "opsec",
        correlationType: "new_finding",
        description: `${remoteAccessAssets.length} assets with exposed remote access ports identified. These represent high-priority defensive gaps.`,
        confidence: 0.95,
        relatedAssets: remoteAccessAssets.map((a) => a.asset.assetId),
        riskImpact: 5
      });
    }
    const dbAssets = analyses.filter(
      (a) => a.postureFindings.some(
        (f) => f.category === "Exposed Port" && (f.title.includes("MySQL") || f.title.includes("PostgreSQL") || f.title.includes("MongoDB") || f.title.includes("Redis") || f.title.includes("Elasticsearch"))
      )
    );
    if (dbAssets.length > 0) {
      defensiveGaps.push({
        category: "Database Exposure",
        severity: "critical",
        description: `${dbAssets.length} assets expose database services directly to the internet`,
        affectedAssets: dbAssets.map((a) => a.asset.hostname)
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
            "Monitor for unauthorized access attempts"
          ],
          corroborationTier: "confirmed",
          evidenceChain: [
            `Database service detected on ${a.asset.hostname} via passive scanning`,
            "Service is reachable from the public internet",
            "Cross-module enrichment: OpSec module flagged as critical defensive gap"
          ]
        });
      }
    }
    if (passiveRecon) {
      const httpSecResults = passiveRecon.connectorResults.find((r) => r.connector === "http-security");
      if (httpSecResults && httpSecResults.observations.length > 0) {
        const missingHeaders = httpSecResults.observations.filter(
          (o) => o.tags.includes("missing_security_header")
        );
        if (missingHeaders.length > 0) {
          defensiveGaps.push({
            category: "Missing Security Headers",
            severity: "medium",
            description: `${missingHeaders.length} security header deficiencies detected across web assets`,
            affectedAssets: missingHeaders.map((o) => o.name || o.domain)
          });
        }
      }
    }
    if (opsecData.weaknessCategories) {
      for (const weakness of opsecData.weaknessCategories) {
        defensiveGaps.push({
          category: weakness.category || "General",
          severity: weakness.defensivePriority || "medium",
          description: weakness.mitigationFocus || "Defensive weakness identified",
          affectedAssets: []
        });
      }
    }
    return {
      status: "success",
      defensiveGaps,
      correlations,
      newFindings
    };
  } catch (err) {
    console.error(`[CrossModuleEnrichment] OpSec enrichment failed: ${err.message}`);
    return {
      status: "failed",
      defensiveGaps: [],
      correlations: [],
      newFindings: [],
      error: err.message
    };
  }
}
async function enrichFromDiscoveryDeepDive(analyses, domain, passiveRecon) {
  try {
    const { securityTrailsDNSHistory, censysCertSearch } = await import("./discovery-engine-D4PZ4WS4.js");
    const dnsHistoryChanges = [];
    const certificateFindings = [];
    const infrastructureInsights = [];
    const correlations = [];
    try {
      const dnsHistory = await securityTrailsDNSHistory(domain);
      if (dnsHistory.length > 1) {
        const sorted = dnsHistory.filter((r) => r.lastSeen).sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
        const currentIPs = new Set(sorted.filter((r) => {
          const lastSeen = new Date(r.lastSeen);
          const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3);
          return lastSeen > thirtyDaysAgo;
        }).map((r) => r.value));
        const historicalIPs = sorted.filter((r) => !currentIPs.has(r.value));
        if (historicalIPs.length > 0) {
          infrastructureInsights.push({
            type: "dns_migration",
            detail: `${domain} has changed IP addresses ${historicalIPs.length} times. Current: ${Array.from(currentIPs).join(", ")}. Previous: ${historicalIPs.slice(0, 3).map((r) => r.value).join(", ")}`,
            confidence: 0.85
          });
          for (const hist of historicalIPs.slice(0, 5)) {
            dnsHistoryChanges.push({
              domain,
              oldIp: hist.value,
              newIp: Array.from(currentIPs)[0] || "unknown",
              changedAt: hist.lastSeen || "unknown"
            });
          }
        }
        const uniqueASNs = /* @__PURE__ */ new Set();
        for (const obs of passiveRecon?.allObservations || []) {
          if (obs.evidence?.asn) uniqueASNs.add(String(obs.evidence.asn));
        }
        if (uniqueASNs.size > 1) {
          infrastructureInsights.push({
            type: "multi_provider",
            detail: `Infrastructure spans ${uniqueASNs.size} different ASNs/providers, suggesting distributed hosting or CDN usage`,
            confidence: 0.8
          });
        }
      }
    } catch (err) {
      console.error(`[CrossModuleEnrichment] DNS history analysis failed: ${err.message}`);
    }
    try {
      const certs = await censysCertSearch(domain);
      for (const cert of certs) {
        if (cert.isExpired) {
          certificateFindings.push({
            subject: cert.subject,
            issue: `Expired certificate (valid until ${cert.validTo})`,
            severity: "high"
          });
        }
        if (cert.isWildcard) {
          certificateFindings.push({
            subject: cert.subject,
            issue: `Wildcard certificate detected \u2014 covers all subdomains`,
            severity: "info"
          });
        }
        const newDomains = cert.sans.filter(
          (san) => san.endsWith(`.${domain}`) && !san.startsWith("*.") && !analyses.some((a) => a.asset.hostname === san)
        );
        if (newDomains.length > 0) {
          infrastructureInsights.push({
            type: "cert_san_discovery",
            detail: `Certificate for ${cert.subject} reveals ${newDomains.length} additional subdomains not yet in asset inventory: ${newDomains.slice(0, 5).join(", ")}`,
            confidence: 0.9
          });
          correlations.push({
            sourceModule: "discovery_engine",
            targetModule: "domain_intel",
            correlationType: "new_finding",
            description: `Certificate SAN analysis revealed ${newDomains.length} additional subdomains for ${domain}`,
            confidence: 0.9,
            relatedAssets: [],
            riskImpact: 1
          });
        }
      }
      if (certificateFindings.filter((f) => f.severity === "high").length > 0) {
        correlations.push({
          sourceModule: "discovery_engine",
          targetModule: "domain_intel",
          correlationType: "new_finding",
          description: `${certificateFindings.filter((f) => f.severity === "high").length} certificate issues found (expired, weak, or misconfigured)`,
          confidence: 0.85,
          relatedAssets: analyses.map((a) => a.asset.assetId),
          riskImpact: 2
        });
      }
    } catch (err) {
      console.error(`[CrossModuleEnrichment] Certificate analysis failed: ${err.message}`);
    }
    if (passiveRecon) {
      const cloudObs = passiveRecon.allObservations.filter(
        (o) => o.tags.some((t) => t.includes("aws") || t.includes("azure") || t.includes("gcp") || t.includes("cloudflare"))
      );
      if (cloudObs.length > 0) {
        const providers = new Set(cloudObs.flatMap(
          (o) => o.tags.filter((t) => t.includes("aws") || t.includes("azure") || t.includes("gcp") || t.includes("cloudflare"))
        ));
        infrastructureInsights.push({
          type: "cloud_infrastructure",
          detail: `Cloud infrastructure detected: ${Array.from(providers).join(", ")}. ${cloudObs.length} cloud-hosted assets identified.`,
          confidence: 0.85
        });
      }
      const wafObs = passiveRecon.allObservations.filter(
        (o) => o.tags.some((t) => t.includes("waf") || t.includes("cdn"))
      );
      if (wafObs.length > 0) {
        infrastructureInsights.push({
          type: "waf_cdn_detection",
          detail: `WAF/CDN protection detected on ${wafObs.length} assets. This affects scan accuracy and attack surface visibility.`,
          confidence: 0.8
        });
      }
    }
    return {
      status: "success",
      dnsHistoryChanges,
      certificateFindings,
      infrastructureInsights,
      correlations
    };
  } catch (err) {
    console.error(`[CrossModuleEnrichment] Discovery deep dive failed: ${err.message}`);
    return {
      status: "failed",
      dnsHistoryChanges: [],
      certificateFindings: [],
      infrastructureInsights: [],
      correlations: [],
      error: err.message
    };
  }
}
async function runCrossModuleEnrichment(analyses, domain, passiveRecon) {
  const start = Date.now();
  const [bugBounty, threatIntel, opsec, discoveryDeepDive] = await Promise.allSettled([
    enrichFromBugBounty(analyses, domain),
    enrichFromThreatIntel(analyses),
    enrichFromOpSec(analyses, passiveRecon),
    enrichFromDiscoveryDeepDive(analyses, domain, passiveRecon)
  ]);
  const bbResult = bugBounty.status === "fulfilled" ? bugBounty.value : {
    status: "failed",
    hasBugBountyProgram: false,
    programName: null,
    inScopeAssets: [],
    historicalVulnPatterns: [],
    correlations: [],
    newFindings: [],
    error: bugBounty.status === "rejected" ? String(bugBounty.reason) : "Unknown error"
  };
  const tiResult = threatIntel.status === "fulfilled" ? threatIntel.value : {
    status: "failed",
    matchingThreatActors: [],
    trendingWeaknesses: [],
    correlations: [],
    riskAdjustments: [],
    error: threatIntel.status === "rejected" ? String(threatIntel.reason) : "Unknown error"
  };
  const osResult = opsec.status === "fulfilled" ? opsec.value : {
    status: "failed",
    defensiveGaps: [],
    correlations: [],
    newFindings: [],
    error: opsec.status === "rejected" ? String(opsec.reason) : "Unknown error"
  };
  const ddResult = discoveryDeepDive.status === "fulfilled" ? discoveryDeepDive.value : {
    status: "failed",
    dnsHistoryChanges: [],
    certificateFindings: [],
    infrastructureInsights: [],
    correlations: [],
    error: discoveryDeepDive.status === "rejected" ? String(discoveryDeepDive.reason) : "Unknown error"
  };
  const allNewFindings = [...bbResult.newFindings, ...osResult.newFindings];
  for (const finding of allNewFindings) {
    const targetAnalysis = analyses.find((a) => a.asset.assetId === finding.assetRef);
    if (targetAnalysis) {
      if (!targetAnalysis.postureFindings.some((f) => f.id === finding.id)) {
        targetAnalysis.postureFindings.push(finding);
      }
    }
  }
  for (const adj of tiResult.riskAdjustments) {
    const targetAnalysis = analyses.find((a) => a.asset.assetId === adj.assetId);
    if (targetAnalysis) {
      targetAnalysis._threatIntelBoost = (targetAnalysis._threatIntelBoost || 0) + adj.adjustment;
    }
  }
  const allCorrelations = [
    ...bbResult.correlations,
    ...tiResult.correlations,
    ...osResult.correlations,
    ...ddResult.correlations
  ];
  const modules = [bbResult, tiResult, osResult, ddResult];
  const modulesSucceeded = modules.filter((m) => m.status === "success").length;
  const modulesFailed = modules.filter((m) => m.status === "failed").length;
  const result = {
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
      durationMs: Date.now() - start
    }
  };
  console.log(
    `[CrossModuleEnrichment] Complete: ${modulesSucceeded}/4 modules succeeded, ${allCorrelations.length} correlations, ${allNewFindings.length} new findings, ${tiResult.riskAdjustments.length} risk adjustments (${Date.now() - start}ms)`
  );
  return result;
}
var init_cross_module_enrichment = __esm({
  "server/lib/cross-module-enrichment.ts"() {
  }
});

export {
  runCrossModuleEnrichment,
  init_cross_module_enrichment
};
