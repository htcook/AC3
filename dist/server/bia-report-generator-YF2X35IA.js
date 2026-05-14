import {
  CRITICALITY_TIERS,
  MISSION_FUNCTION_BASELINES,
  init_scoring_engine
} from "./chunk-M4P542MO.js";
import "./chunk-NQKLH74H.js";
import "./chunk-J6EMIQSU.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-L5VXSJ4F.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-GN2OC6SU.js";
import "./chunk-KFQGP6VL.js";

// server/lib/bia-report-generator.ts
init_scoring_engine();
var FIPS_LEVEL_ORDER = { low: 1, moderate: 2, high: 3 };
var FIPS_LEVEL_NAMES = { 1: "LOW", 2: "MODERATE", 3: "HIGH" };
function highWaterMark(levels) {
  const max = Math.max(...levels.map((l) => FIPS_LEVEL_ORDER[l] || 1));
  return FIPS_LEVEL_NAMES[max] || "LOW";
}
function inferFips199(asset) {
  if (asset.fips199Category) return asset.fips199Category;
  const mf = asset.missionFunction;
  const bil = asset.businessImpactLevel;
  let conf = "low";
  let integ = "low";
  let avail = "low";
  if (["customer_data", "intellectual_property", "authentication"].includes(mf)) {
    conf = "high";
    integ = "high";
  } else if (["revenue_generation", "compliance", "supply_chain"].includes(mf)) {
    conf = "moderate";
    integ = "high";
  } else if (["command_control", "operational_continuity"].includes(mf)) {
    integ = "high";
    avail = "high";
  } else if (["data_processing", "external_communication"].includes(mf)) {
    conf = "moderate";
    integ = "moderate";
  }
  if (bil === "mission_critical") {
    avail = "high";
    if (conf === "low") conf = "moderate";
    if (integ === "low") integ = "moderate";
  } else if (bil === "business_essential") {
    if (avail === "low") avail = "moderate";
    if (conf === "low") conf = "moderate";
  } else if (bil === "operational") {
    if (avail === "low") avail = "moderate";
  }
  return { confidentiality: conf, integrity: integ, availability: avail };
}
function fips199LevelLabel(level) {
  return (level || "low").toUpperCase();
}
function inferRecoveryObjectives(asset) {
  const tier = asset.criticalityTier || inferCriticalityTier(asset);
  const tierInfo = CRITICALITY_TIERS[tier] || CRITICALITY_TIERS[3];
  const rtoMap = {
    1: "< 1 hour",
    2: "1\u20134 hours",
    3: "4\u201324 hours",
    4: "24\u201372 hours",
    5: "72+ hours"
  };
  const rpoMap = {
    1: "< 15 minutes",
    2: "1 hour",
    3: "4 hours",
    4: "24 hours",
    5: "72 hours"
  };
  const mtpdMap = {
    1: "4 hours",
    2: "24 hours",
    3: "72 hours",
    4: "1 week",
    5: "2 weeks"
  };
  return {
    rto: rtoMap[tier] || "24\u201372 hours",
    rpo: rpoMap[tier] || "24 hours",
    mtpd: mtpdMap[tier] || "72 hours",
    tier
  };
}
function inferCriticalityTier(asset) {
  if (asset.businessImpactLevel === "mission_critical") return 1;
  if (asset.businessImpactLevel === "business_essential") return 2;
  if (asset.hybridRiskScore >= 85) return 1;
  if (asset.hybridRiskScore >= 65) return 2;
  if (asset.hybridRiskScore >= 40) return 3;
  if (asset.businessImpactLevel === "operational") return 3;
  return 4;
}
function generateBiaReport(org, assets, overallRiskScore, overallRiskBand) {
  const sorted = [...assets].sort((a, b) => b.hybridRiskScore - a.hybridRiskScore);
  const allFips = sorted.map((a) => inferFips199(a));
  const systemCat = {
    confidentiality: highWaterMark(allFips.map((f) => f.confidentiality)),
    integrity: highWaterMark(allFips.map((f) => f.integrity)),
    availability: highWaterMark(allFips.map((f) => f.availability)),
    overall: highWaterMark(allFips.flatMap((f) => [f.confidentiality, f.integrity, f.availability]))
  };
  const criticalAssets = sorted.filter((a) => a.riskBand === "critical");
  const highAssets = sorted.filter((a) => a.riskBand === "high");
  const mediumAssets = sorted.filter((a) => a.riskBand === "medium");
  const lowAssets = sorted.filter((a) => a.riskBand === "low");
  const sections = [];
  sections.push(buildExecutiveOverview(org, sorted, systemCat, overallRiskScore, overallRiskBand));
  sections.push(buildFips199Section(org, sorted, allFips, systemCat));
  sections.push(buildMissionFunctionSection(sorted));
  sections.push(buildCriticalitySection(sorted));
  sections.push(buildRecoveryObjectivesSection(sorted));
  sections.push(buildDependencySection(sorted));
  sections.push(buildRiskDistributionSection(sorted, criticalAssets, highAssets, mediumAssets, lowAssets));
  sections.push(buildRecommendationsSection(sorted, criticalAssets, highAssets));
  return {
    title: `Business Impact Analysis \u2014 ${org.customerName}`,
    generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    organization: org,
    overallRiskScore,
    overallRiskBand,
    systemSecurityCategorization: systemCat,
    sections,
    assetCount: sorted.length,
    criticalAssetCount: criticalAssets.length,
    highAssetCount: highAssets.length
  };
}
function buildExecutiveOverview(org, assets, systemCat, overallRiskScore, overallRiskBand) {
  const critCount = assets.filter((a) => a.riskBand === "critical").length;
  const highCount = assets.filter((a) => a.riskBand === "high").length;
  const totalFindings = assets.reduce((s, a) => s + (a.postureFindings?.length || 0), 0);
  const kevFindings = assets.reduce((s, a) => s + (a.postureFindings?.filter((f) => f.kevListed)?.length || 0), 0);
  const content = [
    `This Business Impact Analysis (BIA) was conducted for **${org.customerName}** (${org.primaryDomain}) in the **${org.sector}** sector. `,
    `The analysis covers **${assets.length}** discovered information systems and services, evaluated using the CARVER+SHOCK hybrid methodology `,
    `aligned with NIST IR 8286D guidance for using BIA to inform risk prioritization.

`,
    `**System Security Categorization:** The overall system is categorized as **${systemCat.overall}** impact under FIPS 199, `,
    `with Confidentiality: ${systemCat.confidentiality}, Integrity: ${systemCat.integrity}, Availability: ${systemCat.availability}.

`,
    `**Overall Risk Posture:** The organization's aggregate risk score is **${overallRiskScore}/100 (${overallRiskBand.toUpperCase()})**, `,
    `with **${critCount}** critical-risk and **${highCount}** high-risk assets identified. `,
    `A total of **${totalFindings}** security findings were documented`,
    kevFindings > 0 ? `, including **${kevFindings}** CISA KEV-listed vulnerabilities requiring immediate remediation.` : ".",
    `

**Compliance Context:** ${org.complianceFlags.length > 0 ? org.complianceFlags.join(", ") : "No specific compliance frameworks identified"}.`,
    `

**Critical Business Functions:** ${org.criticalFunctions.length > 0 ? org.criticalFunctions.join(", ") : "Not specified"}.`
  ].join("");
  return {
    id: "executive-overview",
    title: "1. Executive Overview",
    content,
    tables: [{
      caption: "Risk Distribution Summary",
      headers: ["Risk Band", "Asset Count", "Percentage", "Immediate Action Required"],
      rows: [
        ["CRITICAL", String(critCount), `${(critCount / assets.length * 100).toFixed(1)}%`, "Yes \u2014 Remediate within 24-48 hours"],
        ["HIGH", String(highCount), `${(highCount / assets.length * 100).toFixed(1)}%`, "Yes \u2014 Remediate within 1-2 weeks"],
        ["MEDIUM", String(assets.filter((a) => a.riskBand === "medium").length), `${(assets.filter((a) => a.riskBand === "medium").length / assets.length * 100).toFixed(1)}%`, "Monitor \u2014 Schedule remediation"],
        ["LOW", String(assets.filter((a) => a.riskBand === "low").length), `${(assets.filter((a) => a.riskBand === "low").length / assets.length * 100).toFixed(1)}%`, "Accept or defer"]
      ]
    }]
  };
}
function buildFips199Section(org, assets, allFips, systemCat) {
  const content = [
    `Per FIPS 199 (Standards for Security Categorization of Federal Information and Information Systems), `,
    `each information system is categorized based on the potential impact of a loss of confidentiality, integrity, or availability. `,
    `The security categorization follows the high-water mark principle: the overall system categorization is determined by the highest `,
    `impact level across all three security objectives.

`,
    `**System Categorization:** SC ${org.primaryDomain} = {(confidentiality, ${systemCat.confidentiality}), `,
    `(integrity, ${systemCat.integrity}), (availability, ${systemCat.availability})}

`,
    `The overall impact level is **${systemCat.overall}**, which determines the minimum security control baseline `,
    `per NIST SP 800-53 and drives the recovery priority tiering in Section 5.`
  ].join("");
  const rows = assets.slice(0, 30).map((a, i) => {
    const fips = allFips[i];
    const overall = highWaterMark([fips.confidentiality, fips.integrity, fips.availability]);
    return [
      a.hostname,
      fips199LevelLabel(fips.confidentiality),
      fips199LevelLabel(fips.integrity),
      fips199LevelLabel(fips.availability),
      overall
    ];
  });
  return {
    id: "fips199",
    title: "2. FIPS 199 Security Categorization",
    content,
    tables: [{
      caption: "Per-Asset Security Categorization",
      headers: ["Asset", "Confidentiality", "Integrity", "Availability", "Overall"],
      rows
    }]
  };
}
function buildMissionFunctionSection(assets) {
  const byFunction = /* @__PURE__ */ new Map();
  for (const a of assets) {
    const mf = a.missionFunction || "unclassified";
    if (!byFunction.has(mf)) byFunction.set(mf, []);
    byFunction.get(mf).push(a);
  }
  const functionRows = Array.from(byFunction.entries()).sort((a, b) => {
    const aMax = Math.max(...a[1].map((x) => x.hybridRiskScore));
    const bMax = Math.max(...b[1].map((x) => x.hybridRiskScore));
    return bMax - aMax;
  }).map(([fn, fnAssets]) => {
    const baseline = MISSION_FUNCTION_BASELINES[fn];
    const avgRisk = Math.round(fnAssets.reduce((s, a) => s + a.hybridRiskScore, 0) / fnAssets.length);
    return [
      fn.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      String(fnAssets.length),
      String(avgRisk),
      baseline?.missionMultiplier ? `${baseline.missionMultiplier}x` : "1.0x",
      baseline?.description?.substring(0, 80) || "Standard baseline"
    ];
  });
  const content = [
    `Mission function mapping classifies each asset by its role in supporting organizational objectives. `,
    `This classification drives the CARVER+SHOCK baseline scores and mission multipliers that ensure `,
    `critical assets are never under-scored regardless of vulnerability data.

`,
    `The following table shows how assets are distributed across mission functions, `,
    `with the mission multiplier indicating the risk amplification factor applied to assets in that category.`
  ].join("");
  return {
    id: "mission-functions",
    title: "3. Mission Function Mapping",
    content,
    tables: [{
      caption: "Mission Function Distribution",
      headers: ["Mission Function", "Assets", "Avg Risk", "Multiplier", "Impact Description"],
      rows: functionRows
    }]
  };
}
function buildCriticalitySection(assets) {
  const rows = assets.slice(0, 40).map((a) => {
    const tier = a.criticalityTier || inferCriticalityTier(a);
    const tierInfo = CRITICALITY_TIERS[tier] || CRITICALITY_TIERS[3];
    return [
      a.hostname,
      `Tier ${tier}: ${tierInfo.name}`,
      String(a.hybridRiskScore),
      a.riskBand.toUpperCase(),
      String(a.assetCriticalityScore),
      a.businessImpactLevel?.replace(/_/g, " ") || "N/A",
      tierInfo.rto
    ];
  });
  const content = [
    `Asset criticality is determined by combining the CARVER+SHOCK mission impact assessment `,
    `with the business impact level classification. Assets are assigned to criticality tiers `,
    `aligned with NIST SP 800-34 recovery priorities:

`,
    `- **Tier 1 (Mission Critical):** RTO < 1 hour. Loss causes complete mission failure.
`,
    `- **Tier 2 (Business Critical):** RTO 1\u201324 hours. Core functions degraded.
`,
    `- **Tier 3 (Operational):** RTO 1\u20133 days. Business processes impacted.
`,
    `- **Tier 4 (Administrative):** RTO 3\u20137 days. Support functions affected.
`,
    `- **Tier 5 (Non-Essential):** RTO 7+ days. Minimal operational impact.

`,
    `The criticality tier directly informs recovery prioritization and resource allocation during incident response.`
  ].join("");
  return {
    id: "criticality",
    title: "4. Asset Criticality Analysis",
    content,
    tables: [{
      caption: "Asset Criticality Tiering",
      headers: ["Asset", "Criticality Tier", "Risk Score", "Band", "Criticality Score", "Impact Level", "RTO"],
      rows
    }]
  };
}
function buildRecoveryObjectivesSection(assets) {
  const rows = assets.slice(0, 30).map((a) => {
    const ro = inferRecoveryObjectives(a);
    return [
      a.hostname,
      `Tier ${ro.tier}`,
      ro.rto,
      ro.rpo,
      ro.mtpd,
      a.essentialService?.replace(/_/g, " ") || "General"
    ];
  });
  const content = [
    `Recovery objectives define the maximum acceptable downtime and data loss for each system. `,
    `These objectives are derived from the asset's criticality tier and mission function:

`,
    `- **RTO (Recovery Time Objective):** Maximum acceptable time to restore service after disruption.
`,
    `- **RPO (Recovery Point Objective):** Maximum acceptable data loss measured in time.
`,
    `- **MTPD (Maximum Tolerable Period of Disruption):** Absolute limit before irreversible damage occurs.

`,
    `These values should be validated with business stakeholders and incorporated into the organization's `,
    `Business Continuity Plan (BCP) and Disaster Recovery Plan (DRP).`
  ].join("");
  return {
    id: "recovery-objectives",
    title: "5. Recovery Time & Point Objectives",
    content,
    tables: [{
      caption: "Recovery Objectives by Asset",
      headers: ["Asset", "Tier", "RTO", "RPO", "MTPD", "Service Type"],
      rows
    }]
  };
}
function buildDependencySection(assets) {
  const assetsWithDeps = assets.filter((a) => a.missionDependencies && (a.missionDependencies.upstreamAssets.length > 0 || a.missionDependencies.downstreamAssets.length > 0 || a.missionDependencies.sharedServices.length > 0));
  const rows = assetsWithDeps.slice(0, 25).map((a) => {
    const deps = a.missionDependencies;
    return [
      a.hostname,
      deps.upstreamAssets.slice(0, 3).join(", ") || "None identified",
      deps.downstreamAssets.slice(0, 3).join(", ") || "None identified",
      deps.sharedServices.slice(0, 3).join(", ") || "None identified",
      a.riskBand.toUpperCase()
    ];
  });
  const content = [
    `Dependency analysis identifies upstream and downstream relationships between assets `,
    `to understand cascading failure risks. A compromise of an upstream asset can propagate `,
    `to all dependent downstream systems, amplifying the effective blast radius.

`,
    `**${assetsWithDeps.length}** of **${assets.length}** assets have identified inter-system dependencies. `,
    `Assets with many downstream dependents should receive priority in patching and monitoring.`
  ].join("");
  return {
    id: "dependencies",
    title: "6. Dependency & Cascading Failure Analysis",
    content,
    tables: rows.length > 0 ? [{
      caption: "Asset Dependency Map",
      headers: ["Asset", "Upstream Dependencies", "Downstream Dependents", "Shared Services", "Risk Band"],
      rows
    }] : void 0
  };
}
function buildRiskDistributionSection(assets, critical, high, medium, low) {
  const allFindings = assets.flatMap((a) => (a.postureFindings || []).map((f) => ({ ...f, parentAsset: a.hostname })));
  const topFindings = allFindings.sort((a, b) => (b.severity || 0) - (a.severity || 0)).slice(0, 20);
  const findingRows = topFindings.map((f) => [
    f.parentAsset || "",
    f.category || "",
    (f.title || "").substring(0, 70),
    String(f.severity || 0),
    f.corroborationTier || "potential",
    f.kevListed ? "YES" : "",
    (f.cveIds || []).join(", ") || ""
  ]);
  const content = [
    `This section provides a detailed breakdown of the risk distribution across all assessed assets `,
    `and highlights the top security findings by severity.

`,
    `**Risk Distribution:**
`,
    `- Critical: ${critical.length} assets (${(critical.length / assets.length * 100).toFixed(1)}%)
`,
    `- High: ${high.length} assets (${(high.length / assets.length * 100).toFixed(1)}%)
`,
    `- Medium: ${medium.length} assets (${(medium.length / assets.length * 100).toFixed(1)}%)
`,
    `- Low: ${low.length} assets (${(low.length / assets.length * 100).toFixed(1)}%)

`,
    `**Total Findings:** ${allFindings.length}
`,
    `**KEV-Listed:** ${allFindings.filter((f) => f.kevListed).length}
`,
    `**Confirmed Findings:** ${allFindings.filter((f) => f.corroborationTier === "confirmed").length}
`,
    `**Probable Findings:** ${allFindings.filter((f) => f.corroborationTier === "probable").length}`
  ].join("");
  return {
    id: "risk-distribution",
    title: "7. Risk Distribution & Findings Summary",
    content,
    tables: findingRows.length > 0 ? [{
      caption: "Top Security Findings by Severity",
      headers: ["Asset", "Category", "Finding", "Severity", "Corroboration", "KEV", "CVEs"],
      rows: findingRows
    }] : void 0
  };
}
function buildRecommendationsSection(assets, critical, high) {
  const recommendations = [];
  const kevAssets = assets.filter((a) => a.postureFindings?.some((f) => f.kevListed));
  if (kevAssets.length > 0) {
    recommendations.push(
      `**1. CISA KEV Remediation (IMMEDIATE):** ${kevAssets.length} assets have CISA Known Exploited Vulnerabilities. Per BOD 22-01, these must be remediated within the specified due dates. Priority assets: ` + kevAssets.slice(0, 5).map((a) => a.hostname).join(", ") + "."
    );
  }
  if (critical.length > 0) {
    recommendations.push(
      `**2. Critical Asset Hardening (24-48 HOURS):** ${critical.length} assets scored in the critical risk band. Implement compensating controls immediately: network segmentation, enhanced monitoring, and emergency patching. Priority: ` + critical.slice(0, 5).map((a) => `${a.hostname} (${a.hybridRiskScore})`).join(", ") + "."
    );
  }
  const authAssets = assets.filter((a) => ["authentication", "command_control"].includes(a.missionFunction));
  if (authAssets.length > 0) {
    recommendations.push(
      `**3. Authentication & C2 Infrastructure (HIGH PRIORITY):** ${authAssets.length} assets serve authentication or command-and-control functions. Compromise of these assets enables lateral movement across the entire environment. Ensure MFA enforcement, privileged access management, and continuous monitoring.`
    );
  }
  const tier1Assets = assets.filter((a) => (a.criticalityTier || inferCriticalityTier(a)) <= 2);
  if (tier1Assets.length > 0) {
    recommendations.push(
      `**4. Recovery Planning (ONGOING):** ${tier1Assets.length} assets are classified as Tier 1-2 (Mission/Business Critical) with RTOs under 24 hours. Validate that current backup and disaster recovery capabilities can meet these objectives. Conduct tabletop exercises to test recovery procedures.`
    );
  }
  const highDependencyAssets = assets.filter(
    (a) => a.missionDependencies && a.missionDependencies.downstreamAssets.length >= 3
  );
  if (highDependencyAssets.length > 0) {
    recommendations.push(
      `**5. Dependency Risk Mitigation:** ${highDependencyAssets.length} assets have 3+ downstream dependents, creating single points of failure. Implement redundancy, failover mechanisms, and circuit breakers to limit cascading failure propagation.`
    );
  }
  recommendations.push(
    `**6. Continuous Monitoring:** Implement automated vulnerability scanning on a weekly cadence for critical assets and monthly for all others. Integrate CISA KEV feed monitoring to detect newly listed vulnerabilities affecting your environment.`
  );
  recommendations.push(
    `**7. Compliance Alignment:** ${org_compliance_note(assets[0])} Review control implementations against the ${assets[0]?.fips199Category ? "FIPS 199 categorization" : "identified risk levels"} and update the System Security Plan (SSP) accordingly.`
  );
  const content = [
    `Based on the analysis above, the following remediation priorities are recommended, `,
    `ordered by urgency and potential impact reduction:

`,
    recommendations.join("\n\n")
  ].join("");
  return {
    id: "recommendations",
    title: "8. Recommendations & Remediation Priorities",
    content
  };
}
function org_compliance_note(_asset) {
  return "Ensure all identified findings are tracked in the Plan of Action & Milestones (POA&M).";
}
export {
  generateBiaReport
};
