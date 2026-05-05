import {
  getCoverageGapDetector,
  getDeduplicationEngine,
  getNormalizationEngine,
  init_dedup_coverage
} from "./chunk-5L2O5ONH.js";
import {
  enrichFinding,
  generateNistGapSummary,
  getImpactedNistFamilies,
  init_nist_mitre_cwe_mapper
} from "./chunk-BXFHH4GF.js";
import {
  init_nvd_cve_lookup,
  resolveCvesToCwes
} from "./chunk-LJKHMLJF.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/dedup-coverage-bridge.ts
function vulnToScanFinding(vuln, asset) {
  const sourceMatch = vuln.title.match(/^\[([^\]]+)\]/);
  const scanner = sourceMatch ? sourceMatch[1].toLowerCase() : "unknown";
  const cleanTitle = sourceMatch ? vuln.title.slice(sourceMatch[0].length).trim() : vuln.title;
  const severityMap = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "info"
  };
  const severity = severityMap[vuln.severity?.toLowerCase()] || "info";
  const cweMatch = vuln.title.match(/CWE-(\d+)/i);
  const cwes = cweMatch ? [`CWE-${cweMatch[1]}`] : [];
  return {
    id: vuln.id,
    source: `orchestrator-${scanner}`,
    title: cleanTitle || vuln.title,
    description: vuln.evidenceDetail || `Finding from ${scanner}: ${cleanTitle || vuln.title}`,
    severity,
    confidence: vuln.corroborationTier === "confirmed" ? 95 : vuln.corroborationTier === "corroborated" ? 80 : 60,
    target: asset.hostname,
    port: 0,
    protocol: "tcp",
    evidence: {
      data: { raw: vuln.evidenceDetail || vuln.title },
      matchedPattern: vuln.title
    },
    cves: vuln.cve ? [vuln.cve] : [],
    cwes,
    references: [],
    remediation: "",
    foundAt: Date.now()
  };
}
function zapFindingToScanFinding(zap, asset) {
  const severityMap = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info"
  };
  return {
    id: `zap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    source: "orchestrator-zap",
    title: zap.alert,
    description: `ZAP finding: ${zap.alert} at ${zap.url}`,
    severity: severityMap[zap.risk] || "info",
    confidence: 85,
    target: asset.hostname,
    port: 0,
    protocol: "tcp",
    evidence: {
      data: { alert: zap.alert, risk: zap.risk, url: zap.url }
    },
    cves: [],
    cwes: zap.cweId ? [`CWE-${zap.cweId}`] : [],
    references: [],
    remediation: "",
    foundAt: Date.now()
  };
}
function scanFindingToVuln(finding) {
  const sourceStr = finding.source || "unknown";
  const scanner = sourceStr.replace(/^orchestrator-/, "") || "unknown";
  const title = `[${scanner}] ${finding.title}`;
  const cwe = finding.cwes?.[0] || void 0;
  const description = finding.description || void 0;
  const evidence = finding.evidence?.data ? JSON.stringify(finding.evidence.data) : void 0;
  return {
    id: finding.id,
    severity: finding.severity,
    title,
    cve: finding.cves?.[0],
    cwe,
    description,
    evidence,
    source: scanner,
    corroborationTier: finding.confidence >= 90 ? "confirmed" : finding.confidence >= 70 ? "corroborated" : "tentative",
    evidenceDetail: finding.evidence?.data?.raw || finding.description
  };
}
function inferAssetEnvironment(asset) {
  const services = asset.ports.map((p) => p.service?.toLowerCase() || "");
  const toolNames = (asset.toolResults || []).map((t) => t.tool?.toLowerCase() || "");
  const allText = [
    ...services,
    ...toolNames,
    ...asset.vulns.map((v) => v.title.toLowerCase()),
    asset.hostname.toLowerCase()
  ].join(" ");
  if (allText.includes("aws") || allText.includes("azure") || allText.includes("gcp") || allText.includes("cloud") || allText.includes("s3") || allText.includes("lambda") || asset.hostname.includes("amazonaws.com") || asset.hostname.includes("azure") || asset.hostname.includes("cloudfront") || asset.hostname.includes("appspot")) {
    return "cloud";
  }
  if (allText.includes("mqtt") || allText.includes("coap") || allText.includes("upnp") || allText.includes("zigbee") || allText.includes("ble") || allText.includes("iot") || services.includes("mqtt") || services.includes("coap")) {
    return "iot";
  }
  if (allText.includes("modbus") || allText.includes("dnp3") || allText.includes("bacnet") || allText.includes("scada") || allText.includes("plc") || allText.includes("ics") || allText.includes("opc") || allText.includes("ethernetip") || services.includes("modbus") || services.includes("dnp3") || services.includes("bacnet")) {
    return "ics_ot";
  }
  if (allText.includes("docker") || allText.includes("kubernetes") || allText.includes("k8s") || allText.includes("container") || allText.includes("etcd") || allText.includes("kubelet") || services.includes("docker") || services.includes("etcd")) {
    return "container";
  }
  return "traditional";
}
async function runEngagementDedup(assets) {
  const dedup = getDeduplicationEngine();
  const normalizer = getNormalizationEngine();
  let totalBefore = 0;
  let totalAfter = 0;
  let totalDuplicates = 0;
  let totalSeverityChanges = 0;
  const duplicatesByAsset = {};
  const allMergeLog = [];
  for (const asset of assets) {
    const allFindings = [];
    for (const vuln of asset.vulns) {
      allFindings.push(vulnToScanFinding(vuln, asset));
    }
    if (asset.zapFindings) {
      for (const zap of asset.zapFindings) {
        allFindings.push(zapFindingToScanFinding(zap, asset));
      }
    }
    if (asset.toolResults) {
      for (const tr of asset.toolResults) {
        if (tr.findings) {
          for (const f of tr.findings) {
            allFindings.push({
              id: `tr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              source: `orchestrator-${tr.tool}`,
              title: f.title,
              description: `Finding from ${tr.tool}: ${f.title}`,
              severity: f.severity || "info",
              confidence: 70,
              target: asset.hostname,
              port: 0,
              protocol: "tcp",
              evidence: {
                data: { raw: tr.outputPreview?.slice(0, 500) || f.title }
              },
              cves: f.cve ? [f.cve] : [],
              cwes: [],
              references: [],
              remediation: "",
              foundAt: tr.executedAt || Date.now()
            });
          }
        }
      }
    }
    totalBefore += allFindings.length;
    if (allFindings.length === 0) continue;
    const dedupResult = dedup.deduplicate(allFindings);
    const dupsRemoved = dedupResult.duplicatesRemoved;
    duplicatesByAsset[asset.hostname] = dupsRemoved;
    totalDuplicates += dupsRemoved;
    const normResult = normalizer.normalize(dedupResult.findings);
    totalSeverityChanges += normResult.log.filter((e) => e.field === "severity").length;
    const dedupedVulns = normResult.findings.map(scanFindingToVuln);
    asset.vulns = dedupedVulns;
    totalAfter += dedupedVulns.length;
    for (const entry of dedupResult.mergeLog) {
      const canonicalFinding = dedupResult.findings.find((f) => f.id === entry.canonicalId);
      const canonicalTitle = canonicalFinding?.title || entry.canonicalId;
      allMergeLog.push({
        canonicalTitle,
        mergedCount: entry.mergedIds.length + 1,
        sources: [entry.canonicalId, ...entry.mergedIds].map((id) => {
          const f = allFindings.find((af) => af.id === id);
          return f?.source?.replace(/^orchestrator-/, "") || "unknown";
        }).filter((v, i, a) => a.indexOf(v) === i)
        // unique sources
      });
    }
  }
  const cveIdsToResolve = [];
  const vulnCveMap = [];
  for (const asset of assets) {
    for (const vuln of asset.vulns) {
      if (vuln.cve) {
        const cweMatch = vuln.title.match(/CWE-(\d+)/gi);
        if (!cweMatch || cweMatch.length === 0) {
          cveIdsToResolve.push(vuln.cve);
          vulnCveMap.push({ vulnId: vuln.id, cve: vuln.cve });
        }
      }
    }
  }
  let cveToCweMap = /* @__PURE__ */ new Map();
  if (cveIdsToResolve.length > 0) {
    try {
      cveToCweMap = await resolveCvesToCwes(cveIdsToResolve);
    } catch (err) {
      console.warn("[DedupBridge] NVD CVE-to-CWE resolution failed:", err);
    }
  }
  const allDedupedFindings = [];
  const findingEnrichments = {};
  for (const asset of assets) {
    for (const vuln of asset.vulns) {
      const cweMatch = vuln.title.match(/CWE-(\d+)/gi);
      const cwes = cweMatch ? cweMatch.map((m) => m.toUpperCase()) : [];
      if (vuln.cve && cwes.length === 0) {
        const nvdCwes = cveToCweMap.get(vuln.cve.toUpperCase());
        if (nvdCwes) {
          cwes.push(...nvdCwes);
        }
      }
      const findingInput = {
        cwes,
        techniqueIds: [],
        severity: vuln.severity,
        title: vuln.title,
        category: void 0
      };
      allDedupedFindings.push({ id: vuln.id, ...findingInput });
      const enrichment = enrichFinding(findingInput);
      findingEnrichments[vuln.id] = enrichment;
    }
  }
  const nistGapSummary = generateNistGapSummary(allDedupedFindings);
  const impactedFamilies = getImpactedNistFamilies(allDedupedFindings);
  const mitreTechniquesByTactic = {};
  const allMitreSet = /* @__PURE__ */ new Map();
  const allCweSet = /* @__PURE__ */ new Map();
  for (const enrichment of Object.values(findingEnrichments)) {
    for (const tech of enrichment.mitreTechniques) {
      allMitreSet.set(tech.techniqueId, tech);
      if (!mitreTechniquesByTactic[tech.tactic]) {
        mitreTechniquesByTactic[tech.tactic] = [];
      }
      if (!mitreTechniquesByTactic[tech.tactic].some((t) => t.techniqueId === tech.techniqueId)) {
        mitreTechniquesByTactic[tech.tactic].push({ techniqueId: tech.techniqueId, techniqueName: tech.techniqueName });
      }
    }
    for (const cwe of enrichment.cwes) {
      allCweSet.set(cwe.cweId, cwe);
    }
  }
  const cwesByCategory = {};
  for (const cwe of allCweSet.values()) {
    if (!cwesByCategory[cwe.category]) {
      cwesByCategory[cwe.category] = [];
    }
    cwesByCategory[cwe.category].push(cwe);
  }
  const complianceEnrichment = {
    totalNistControlsImpacted: nistGapSummary.totalControlsImpacted,
    impactedNistFamilies: impactedFamilies,
    totalMitreTechniques: allMitreSet.size,
    mitreTechniquesByTactic,
    totalCwes: allCweSet.size,
    cwesByCategory,
    nistGapSummary,
    findingEnrichments
  };
  return {
    totalFindingsBeforeDedup: totalBefore,
    totalFindingsAfterDedup: totalAfter,
    duplicatesRemoved: totalDuplicates,
    duplicatesByAsset,
    mergeLog: allMergeLog,
    normalizedSeverityChanges: totalSeverityChanges,
    processedAt: Date.now(),
    complianceEnrichment
  };
}
function runEngagementCoverageAnalysis(assets) {
  const detector = getCoverageGapDetector();
  const assetReports = [];
  let totalGaps = 0;
  let criticalGaps = 0;
  const allRecommendations = [];
  for (const asset of assets) {
    const target = {
      value: asset.hostname,
      type: asset.hostname.match(/^\d+\.\d+\.\d+\.\d+$/) ? "ip" : "domain",
      ports: asset.ports.map((p) => p.port),
      services: Object.fromEntries(asset.ports.map((p) => [p.port, p.service]))
    };
    const config = {
      maxConcurrency: 5,
      timeoutSeconds: 300
    };
    const TOOL_TO_PROTOCOLS = {
      httpx: ["http", "https"],
      nuclei: ["http", "https"],
      naabu: [],
      // port scanner — protocols inferred from discovered services
      masscan: [],
      rustscan: [],
      nerva: ["http", "https", "ssh", "dns", "smtp", "ftp"],
      zap: ["http", "https"],
      nikto: ["http", "https"],
      sqlmap: ["http", "https"],
      hydra: ["ssh", "ftp", "http", "https"],
      dig: ["dns"],
      dnsrecon: ["dns"],
      subfinder: ["dns"],
      amass: ["dns"],
      curl: ["http", "https"],
      wpscan: ["http", "https"],
      gobuster: ["http", "https"],
      dirb: ["http", "https"],
      ffuf: ["http", "https"],
      testssl: ["https"],
      sslscan: ["https"],
      msfconsole: ["http", "https", "ssh", "ftp", "smtp"]
    };
    const TOOL_TO_TAGS = {
      nuclei: ["cve", "exposure", "misconfig", "owasp-top10"],
      zap: ["owasp-top10", "exposure", "misconfig"],
      nikto: ["exposure", "misconfig"],
      httpx: ["exposure"],
      hydra: ["credentials"],
      sqlmap: ["owasp-top10"],
      wpscan: ["cve", "exposure", "credentials"],
      dig: ["dns", "zone-transfer"],
      dnsrecon: ["dns", "dnssec", "zone-transfer"],
      naabu: ["exposure"],
      nerva: ["exposure"],
      testssl: ["misconfig"],
      sslscan: ["misconfig"],
      gobuster: ["exposure"],
      dirb: ["exposure"],
      ffuf: ["exposure"],
      msfconsole: ["cve", "owasp-top10"]
    };
    const protocolsFromTools = /* @__PURE__ */ new Set();
    const tagsFromTools = /* @__PURE__ */ new Set();
    const completedTools = (asset.toolResults || []).filter((tr) => tr.exitCode === 0 && !tr.timedOut);
    for (const tr of completedTools) {
      const toolName = tr.tool.toLowerCase();
      const protocols = TOOL_TO_PROTOCOLS[toolName];
      if (protocols) protocols.forEach((p) => protocolsFromTools.add(p));
      const tags = TOOL_TO_TAGS[toolName];
      if (tags) tags.forEach((t) => tagsFromTools.add(t));
    }
    for (const p of asset.ports) {
      const svc = (p.service || "").toLowerCase();
      if (svc === "http" || svc === "https" || svc === "ssh" || svc === "dns" || svc === "smtp" || svc === "ftp" || svc === "smb" || svc === "mysql" || svc === "postgresql" || svc === "redis" || svc === "mongodb") {
        protocolsFromTools.add(svc);
      }
    }
    const scannersRun = [];
    for (const proto of protocolsFromTools) {
      scannersRun.push({
        scanner: proto,
        status: "completed",
        durationMs: 0,
        findingCount: 0
      });
    }
    for (const tr of asset.toolResults || []) {
      scannersRun.push({
        scanner: tr.tool,
        status: tr.timedOut ? "timeout" : tr.exitCode === 0 ? "completed" : "failed",
        durationMs: tr.durationMs,
        findingCount: tr.findingCount,
        error: tr.exitCode !== 0 && !tr.timedOut ? `Exit code ${tr.exitCode}` : void 0
      });
    }
    const templatesExecuted = [
      ...(asset.toolResults || []).map((tr) => tr.tool),
      ...Array.from(tagsFromTools)
    ];
    const environment = inferAssetEnvironment(asset);
    const classification = {
      environment,
      assetType: asset.type || "server",
      protocols: [...protocolsFromTools],
      technologies: [],
      complianceScope: []
    };
    const syntheticTemplates = Array.from(tagsFromTools).map((tag) => ({
      id: tag,
      name: `Inferred: ${tag}`,
      description: `Synthetic template for coverage tracking \u2014 inferred from tool execution`,
      author: "bridge",
      severity: "info",
      tags: [tag],
      protocol: "http",
      matchers: []
    }));
    const report = detector.analyze(
      target,
      config,
      scannersRun,
      templatesExecuted,
      syntheticTemplates,
      // synthetic templates so tag matching works
      classification
    );
    const assetGaps = report.gaps.map((g) => {
      const gapEnrichment = enrichFinding({
        title: `${g.category}: ${g.description}`,
        category: g.category,
        severity: g.severity
      });
      return {
        category: g.category,
        description: g.description,
        severity: g.severity,
        recommendation: g.recommendation,
        missingChecks: [
          ...g.recommendedTemplateIds,
          ...g.recommendedProtocols
        ],
        relatedNistControls: gapEnrichment.nistControls.map((c) => c.controlId),
        relatedMitreTechniques: gapEnrichment.mitreTechniques.map((t) => t.techniqueId)
      };
    });
    const assetCritical = assetGaps.filter((g) => g.severity === "critical" || g.severity === "high").length;
    assetReports.push({
      hostname: asset.hostname,
      score: report.coveragePercent,
      // CoverageReport uses coveragePercent, not score
      gaps: assetGaps,
      totalGaps: assetGaps.length,
      criticalGaps: assetCritical
    });
    totalGaps += assetGaps.length;
    criticalGaps += assetCritical;
    for (const g of assetGaps) {
      if (g.recommendation && !allRecommendations.includes(g.recommendation)) {
        allRecommendations.push(g.recommendation);
      }
    }
  }
  const totalScore = assetReports.length > 0 ? Math.round(assetReports.reduce((sum, r) => sum + r.score, 0) / assetReports.length) : 100;
  return {
    overallScore: totalScore,
    assetReports,
    totalGaps,
    criticalGaps,
    recommendations: allRecommendations.slice(0, 20),
    // Top 20 recommendations
    processedAt: Date.now()
  };
}
var init_dedup_coverage_bridge = __esm({
  "server/lib/dedup-coverage-bridge.ts"() {
    init_dedup_coverage();
    init_nist_mitre_cwe_mapper();
    init_nvd_cve_lookup();
  }
});
init_dedup_coverage_bridge();
export {
  runEngagementCoverageAnalysis,
  runEngagementDedup
};
