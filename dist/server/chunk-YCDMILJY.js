import {
  formatOntologyForPrompt,
  init_asset_ontology
} from "./chunk-EIBYJ3NZ.js";
import {
  getOwaspAssetClassificationContext,
  init_owasp_knowledge
} from "./chunk-J6EMIQSU.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-AOUQ6RTC.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scoring-engine.ts
function getFormatOntologyForPrompt() {
  return formatOntologyForPrompt;
}
function detectAndDampCorrelatedInputs(baseCarver, enrichmentSources) {
  const report = [];
  const dampedCarver = { ...baseCarver };
  const factors = [
    "criticality",
    "accessibility",
    "recuperability",
    "vulnerability",
    "effect",
    "recognizability"
  ];
  for (const factor of factors) {
    const sources = [];
    for (const src of enrichmentSources) {
      const floor = src.carverFloors[factor];
      if (floor !== void 0 && floor > baseCarver[factor]) {
        sources.push({ name: src.name, proposedFloor: floor });
      }
    }
    if (sources.length === 0) {
      report.push({
        factor,
        sourceCount: 0,
        sources: [],
        rawMax: baseCarver[factor],
        dampedValue: baseCarver[factor],
        wasDamped: false
      });
      continue;
    }
    const rawMax = Math.max(baseCarver[factor], ...sources.map((s) => s.proposedFloor));
    if (sources.length >= 3) {
      const totalPush = sources.reduce((sum, s) => sum + (s.proposedFloor - baseCarver[factor]), 0);
      const dampedPush = Math.log1p(totalPush) * 2;
      const dampedValue = Math.min(10, Math.round((baseCarver[factor] + dampedPush) * 100) / 100);
      dampedCarver[factor] = Math.max(dampedCarver[factor], dampedValue);
      report.push({
        factor,
        sourceCount: sources.length,
        sources,
        rawMax,
        dampedValue,
        wasDamped: true
      });
    } else {
      dampedCarver[factor] = rawMax;
      report.push({
        factor,
        sourceCount: sources.length,
        sources,
        rawMax,
        dampedValue: rawMax,
        wasDamped: false
      });
    }
  }
  return { dampedCarver, report };
}
function parseCvssV4Vector(vector) {
  if (!vector || !vector.startsWith("CVSS:4.0/")) return null;
  const parts = vector.replace("CVSS:4.0/", "").split("/");
  const metrics = {};
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key] = value;
  }
  const requiredBase = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
  for (const key of requiredBase) {
    if (!metrics[key]) return null;
  }
  const hasThreat = !!metrics.E && metrics.E !== "X";
  const hasEnvironmental = !!(metrics.CR && metrics.CR !== "X" || metrics.IR && metrics.IR !== "X" || metrics.AR && metrics.AR !== "X" || metrics.MAV || metrics.MAC || metrics.MAT || metrics.MPR || metrics.MUI || metrics.MVC || metrics.MVI || metrics.MVA || metrics.MSC || metrics.MSI || metrics.MSA);
  const hasSupplemental = !!(metrics.S && metrics.S !== "X" || metrics.AU && metrics.AU !== "X" || metrics.U && metrics.U !== "X" || metrics.R && metrics.R !== "X" || metrics.V && metrics.V !== "X" || metrics.RE && metrics.RE !== "X");
  let nomenclature = "CVSS-B";
  if (hasThreat && hasEnvironmental) nomenclature = "CVSS-BTE";
  else if (hasThreat) nomenclature = "CVSS-BT";
  else if (hasEnvironmental) nomenclature = "CVSS-BE";
  const estimatedScore = estimateCvssV4Score(metrics);
  const severity = cvssScoreToSeverity(estimatedScore);
  return {
    metrics,
    nomenclature,
    estimatedScore,
    severity,
    hasThreat,
    hasEnvironmental,
    hasSupplemental
  };
}
function estimateCvssV4Score(m) {
  const avWeight = { N: 1, A: 0.75, L: 0.55, P: 0.2 };
  const acWeight = { L: 1, H: 0.44 };
  const atWeight = { N: 1, P: 0.6 };
  const prWeight = { N: 1, L: 0.68, H: 0.27 };
  const uiWeight = { N: 1, P: 0.62, A: 0.38 };
  const exploitability = (avWeight[m.AV] ?? 0.5) * (acWeight[m.AC] ?? 0.5) * (atWeight[m.AT] ?? 0.5) * (prWeight[m.PR] ?? 0.5) * (uiWeight[m.UI] ?? 0.5);
  const impactWeight = { N: 0, L: 0.22, H: 0.56 };
  const vulnImpact = 1 - (1 - (impactWeight[m.VC] ?? 0)) * (1 - (impactWeight[m.VI] ?? 0)) * (1 - (impactWeight[m.VA] ?? 0));
  const subImpact = 1 - (1 - (impactWeight[m.SC] ?? 0)) * (1 - (impactWeight[m.SI] ?? 0)) * (1 - (impactWeight[m.SA] ?? 0));
  const totalImpact = Math.min(1, vulnImpact + subImpact * 0.5);
  if (totalImpact <= 0) return 0;
  let score = Math.min(10, 10 * (0.6 * totalImpact + 0.4 * exploitability));
  if (m.E && m.E !== "X") {
    const threatMult = { A: 1, P: 0.94, U: 0.91 };
    score *= threatMult[m.E] ?? 1;
  }
  if (m.CR && m.CR !== "X") {
    const reqMult = { H: 1.1, M: 1, L: 0.9 };
    score *= reqMult[m.CR] ?? 1;
  }
  return Math.round(clamp(score, 0, 10) * 10) / 10;
}
function cvssScoreToSeverity(score) {
  if (score === 0) return "None";
  if (score <= 3.9) return "Low";
  if (score <= 6.9) return "Medium";
  if (score <= 8.9) return "High";
  return "Critical";
}
function buildCvssV4Vector(metrics) {
  const parts = ["CVSS:4.0"];
  const order = [
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
    "E",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
    "S",
    "AU",
    "U",
    "R",
    "V",
    "RE"
  ];
  for (const key of order) {
    const val = metrics[key];
    if (val && val !== "X") parts.push(`${key}:${val}`);
  }
  return parts.join("/");
}
function cvssV4ToCarverAdjustments(parsed) {
  const m = parsed.metrics;
  const carver = {};
  const shock = {};
  const avMap = { N: 9, A: 7, L: 4, P: 2 };
  carver.accessibility = avMap[m.AV] ?? 5;
  const acBase = { L: 8, H: 4 };
  const atMod = { N: 1, P: 0.7 };
  carver.vulnerability = Math.round(
    (acBase[m.AC] ?? 5) * (atMod[m.AT] ?? 0.85)
  );
  const prMod = { N: 0, L: -1, H: -3 };
  const uiMod = { N: 0, P: -1, A: -2 };
  carver.accessibility = clamp(
    carver.accessibility + (prMod[m.PR] ?? 0) + (uiMod[m.UI] ?? 0),
    1,
    10
  );
  const impMap = { N: 0, L: 3, H: 8 };
  const vulnEffect = Math.max(
    impMap[m.VC] ?? 0,
    impMap[m.VI] ?? 0,
    impMap[m.VA] ?? 0
  );
  carver.effect = clamp(vulnEffect, 1, 10);
  const subEffect = Math.max(
    impMap[m.SC] ?? 0,
    impMap[m.SI] ?? 0,
    impMap[m.SA] ?? 0
  );
  if (subEffect > 0) {
    shock.cascadingEffects = clamp(subEffect + 1, 1, 10);
    shock.scope = clamp(Math.round(subEffect * 0.8), 1, 10);
  }
  if (m.E && m.E !== "X") {
    const eMod = { A: 2, P: 1, U: 0 };
    carver.vulnerability = clamp(
      (carver.vulnerability ?? 5) + (eMod[m.E] ?? 0),
      1,
      10
    );
    if (m.E === "A") carver.recognizability = 8;
    else if (m.E === "P") carver.recognizability = 6;
  }
  if (m.CR || m.IR || m.AR) {
    const reqMap = { H: 9, M: 6, L: 3 };
    const maxReq = Math.max(
      reqMap[m.CR ?? "X"] ?? 0,
      reqMap[m.IR ?? "X"] ?? 0,
      reqMap[m.AR ?? "X"] ?? 0
    );
    if (maxReq > 0) carver.criticality = maxReq;
  }
  if (m.R && m.R !== "X") {
    const recMap = { I: 10, U: 7, A: 3 };
    carver.recuperability = recMap[m.R] ?? 5;
  }
  if (m.S === "P") {
    shock.operationalImpact = 9;
  }
  if (m.AU === "Y") {
    carver.accessibility = clamp((carver.accessibility ?? 5) + 1, 1, 10);
    carver.recognizability = clamp((carver.recognizability ?? 5) + 1, 1, 10);
  }
  if (m.V === "C") {
    shock.scope = clamp((shock.scope ?? 5) + 2, 1, 10);
  }
  return { carverAdjustments: carver, shockAdjustments: shock };
}
function fips199ToCarverAdjustments(category) {
  const levelMap = { low: 2, moderate: 5, high: 9 };
  const confScore = levelMap[category.confidentiality] ?? 5;
  const intScore = levelMap[category.integrity] ?? 5;
  const availScore = levelMap[category.availability] ?? 5;
  const maxLevel = Math.max(confScore, intScore, availScore);
  const carver = {
    criticality: maxLevel,
    effect: Math.round((confScore + intScore) / 2),
    recuperability: availScore >= 7 ? 8 : availScore >= 4 ? 5 : 3
  };
  const shock = {
    scope: confScore >= 7 ? 8 : confScore >= 4 ? 5 : 2,
    operationalImpact: availScore >= 7 ? 8 : availScore >= 4 ? 5 : 2,
    handling: intScore >= 7 ? 7 : intScore >= 4 ? 5 : 3
  };
  let missionMultiplier = 1;
  if (maxLevel >= 9) missionMultiplier = 1.8;
  else if (maxLevel >= 5) missionMultiplier = 1.3;
  else missionMultiplier = 0.9;
  return { carverAdjustments: carver, shockAdjustments: shock, missionMultiplier };
}
function applyCriticalityTierFloors(carver, shock, tier) {
  const tierDef = CRITICALITY_TIERS[tier];
  const adjustedCarver = { ...carver };
  const adjustedShock = { ...shock };
  for (const [key, val] of Object.entries(tierDef.carverFloor)) {
    const k = key;
    adjustedCarver[k] = Math.max(adjustedCarver[k], val);
  }
  for (const [key, val] of Object.entries(tierDef.shockFloor)) {
    const k = key;
    adjustedShock[k] = Math.max(adjustedShock[k], val);
  }
  return { carver: adjustedCarver, shock: adjustedShock, missionMultiplier: tierDef.missionMultiplier };
}
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}
function computeCarverComposite(scores, weights) {
  let sum = 0, totalWeight = 0;
  const entries = [
    ["criticality", weights.criticality],
    ["accessibility", weights.accessibility],
    ["recuperability", weights.recuperability],
    ["vulnerability", weights.vulnerability],
    ["effect", weights.effect],
    ["recognizability", weights.recognizability]
  ];
  for (const [key, w] of entries) {
    sum += clamp(scores[key], 0, 10) * w;
    totalWeight += w;
  }
  return totalWeight > 0 ? sum / totalWeight : 0;
}
function computeShockComposite(scores, weights) {
  let sum = 0, totalWeight = 0;
  const entries = [
    ["scope", weights.scope],
    ["handling", weights.handling],
    ["operationalImpact", weights.operationalImpact],
    ["cascadingEffects", weights.cascadingEffects],
    ["knowledge", weights.knowledge]
  ];
  for (const [key, w] of entries) {
    sum += clamp(scores[key], 0, 10) * w;
    totalWeight += w;
  }
  return totalWeight > 0 ? sum / totalWeight : 0;
}
function computeMissionImpact(carverComposite, shockComposite, profile, missionMultiplier = 1) {
  const carverNorm = profile.carverWeight / (profile.carverWeight + profile.shockWeight);
  const shockNorm = profile.shockWeight / (profile.carverWeight + profile.shockWeight);
  const baseMissionImpact = carverComposite * carverNorm + shockComposite * shockNorm;
  return clamp(baseMissionImpact * missionMultiplier, 0, 10);
}
function applyMissionBaselines(carver, shock, missionFunction, essentialService) {
  const missionBaseline = MISSION_FUNCTION_BASELINES[missionFunction];
  const serviceBaseline = essentialService ? ESSENTIAL_SERVICE_BASELINES[essentialService] : void 0;
  let adjustedCarver = { ...carver };
  let adjustedShock = { ...shock };
  let missionMultiplier = 1;
  if (missionBaseline) {
    missionMultiplier = missionBaseline.missionMultiplier;
    for (const [key, val] of Object.entries(missionBaseline.carver)) {
      const k = key;
      adjustedCarver[k] = Math.max(adjustedCarver[k], val);
    }
    for (const [key, val] of Object.entries(missionBaseline.shock)) {
      const k = key;
      adjustedShock[k] = Math.max(adjustedShock[k], val);
    }
  }
  if (serviceBaseline) {
    for (const [key, val] of Object.entries(serviceBaseline.carver)) {
      const k = key;
      adjustedCarver[k] = Math.max(adjustedCarver[k], val);
    }
    for (const [key, val] of Object.entries(serviceBaseline.shock)) {
      const k = key;
      adjustedShock[k] = Math.max(adjustedShock[k], val);
    }
  }
  return { carver: adjustedCarver, shock: adjustedShock, missionMultiplier };
}
function businessImpactToMultiplier(level) {
  switch (level) {
    case "mission_critical":
      return 1.8;
    case "business_essential":
      return 1.4;
    case "operational":
      return 1.1;
    case "administrative":
      return 0.8;
    default:
      return 1;
  }
}
function computeHybridRisk(input, profile) {
  let missionMult = input.missionMultiplier ?? 1;
  if (!input.missionMultiplier && input.businessImpactLevel) {
    missionMult = businessImpactToMultiplier(input.businessImpactLevel);
  }
  let carver = { ...input.carver };
  let shock = { ...input.shock };
  let cvssV4Parsed;
  let cvssCarverAdjustments;
  let fips199Applied;
  let criticalityTierApplied;
  const enrichmentSources = [];
  if (input.cvssV4Vector) {
    cvssV4Parsed = parseCvssV4Vector(input.cvssV4Vector) ?? void 0;
    if (cvssV4Parsed) {
      const { carverAdjustments, shockAdjustments } = cvssV4ToCarverAdjustments(cvssV4Parsed);
      cvssCarverAdjustments = carverAdjustments;
      enrichmentSources.push({ name: "CVSS_v4_Environmental", carverFloors: carverAdjustments });
      for (const [key, val] of Object.entries(shockAdjustments)) {
        const k = key;
        shock[k] = Math.max(shock[k], val);
      }
    }
  }
  if (input.fips199) {
    fips199Applied = input.fips199;
    const fipsResult = fips199ToCarverAdjustments(input.fips199);
    enrichmentSources.push({ name: "FIPS_199", carverFloors: fipsResult.carverAdjustments });
    for (const [key, val] of Object.entries(fipsResult.shockAdjustments)) {
      const k = key;
      shock[k] = Math.max(shock[k], val);
    }
    missionMult = Math.max(missionMult, fipsResult.missionMultiplier);
  }
  if (input.criticalityTier) {
    criticalityTierApplied = input.criticalityTier;
    const tierResult = applyCriticalityTierFloors(carver, shock, input.criticalityTier);
    const tierCarverFloors = {};
    for (const [key] of Object.entries(tierResult.carver)) {
      const k = key;
      if (tierResult.carver[k] > carver[k]) {
        tierCarverFloors[k] = tierResult.carver[k];
      }
    }
    enrichmentSources.push({ name: "Criticality_Tier", carverFloors: tierCarverFloors });
    shock = tierResult.shock;
    missionMult = Math.max(missionMult, tierResult.missionMultiplier);
  }
  const { dampedCarver, report: correlatedInputReport } = detectAndDampCorrelatedInputs(carver, enrichmentSources);
  carver = dampedCarver;
  const carverComposite = computeCarverComposite(carver, profile.carverWeights);
  const shockComposite = computeShockComposite(shock, profile.shockWeights);
  const missionImpact = computeMissionImpact(carverComposite, shockComposite, profile, missionMult);
  const impact = clamp(missionImpact / 10, 0, 1);
  let likelihoodBase;
  if (input.confirmedVulnScore !== void 0 && input.confirmedVulnScore > 0) {
    const vulnNorm = clamp(input.confirmedVulnScore / 100, 0, 1);
    likelihoodBase = vulnNorm;
    likelihoodBase += (input.exposure - 0.5) * 0.2;
    likelihoodBase += (clamp(carver.recognizability / 10, 0, 1) - 0.5) * 0.1;
  } else if (input.confirmedVulnScore === 0) {
    likelihoodBase = clamp(input.exposure * 0.1 + clamp(carver.recognizability / 10, 0, 1) * 0.05, 0, 0.15);
  } else {
    likelihoodBase = clamp(input.exposure * 0.1 + clamp(carver.recognizability / 10, 0, 1) * 0.05, 0, 0.15);
  }
  likelihoodBase = clamp(likelihoodBase, 0, 1);
  if (input.portLikelihoodBoost && input.portLikelihoodBoost > 0) {
    likelihoodBase = clamp(likelihoodBase + input.portLikelihoodBoost, 0, 1);
  }
  const confidenceDampening = 0.55 + input.confidence * 0.45;
  const likelihood = clamp(likelihoodBase * confidenceDampening, 0, 1);
  const hybridRiskScore = Math.round(Math.sqrt(impact * likelihood) * 100);
  let riskBand;
  if (hybridRiskScore >= profile.criticalThreshold) riskBand = "critical";
  else if (hybridRiskScore >= profile.highThreshold) riskBand = "high";
  else if (hybridRiskScore >= profile.mediumThreshold) riskBand = "medium";
  else riskBand = "low";
  const factorContributions = [
    ...Object.entries(profile.carverWeights).map(([key, weight]) => ({
      factor: key.charAt(0).toUpperCase() + key.slice(1),
      category: "CARVER",
      rawScore: carver[key],
      weight,
      weightedScore: carver[key] * weight
    })),
    ...Object.entries(profile.shockWeights).map(([key, weight]) => ({
      factor: key.charAt(0).toUpperCase() + key.slice(1),
      category: "Shock",
      rawScore: shock[key],
      weight,
      weightedScore: shock[key] * weight
    }))
  ];
  return {
    carverComposite: Math.round(carverComposite * 100) / 100,
    shockComposite: Math.round(shockComposite * 100) / 100,
    missionImpactScore: Math.round(missionImpact * 100) / 100,
    impactScore: Math.round(impact * 100),
    likelihoodScore: Math.round(likelihood * 100),
    hybridRiskScore,
    riskBand,
    factorContributions,
    cvssV4Parsed,
    cvssCarverAdjustments,
    fips199Applied,
    criticalityTierApplied,
    correlatedInputReport
  };
}
async function classifyAssets(assets, orgContext) {
  if (assets.length === 0) return /* @__PURE__ */ new Map();
  const prompt = `You are an IT asset classification specialist trained on NIST SP 800-60, FIPS 199, and organizational mission function mapping. Classify each discovered asset using a three-step inference chain:

STEP 1: Identify DEVICE TYPE from hostname, services, and technology fingerprints
STEP 2: Infer PLATFORM TYPE from device type and detected technologies
STEP 3: Map to MISSION FUNCTION based on platform type and organizational context

ORGANIZATION CONTEXT:
- Name: ${orgContext.name}
- Sector: ${orgContext.sector}
- Critical Functions: ${orgContext.criticalFunctions.join(", ")}
- Compliance Requirements: ${orgContext.complianceFlags.join(", ") || "none specified"}

CLASSIFICATION TAXONOMY:

Device Types: ${ASSET_DEVICE_TYPES.filter((t) => t !== "unknown").join(", ")}
Platform Types: ${ASSET_PLATFORM_TYPES.filter((t) => t !== "unknown").join(", ")}
Mission Functions: ${MISSION_FUNCTIONS.join(", ")}
Essential Services: ${ESSENTIAL_SERVICES.join(", ")}
Business Impact Levels: ${BUSINESS_IMPACT_LEVELS.join(", ")}

FIPS 199 Security Categories (for each of Confidentiality, Integrity, Availability):
- high: Loss would have severe/catastrophic adverse effect
- moderate: Loss would have serious adverse effect
- low: Loss would have limited adverse effect

Criticality Tiers:
- 1 (Mission Critical): < 1 hour RTO, immediate operational impact
- 2 (Business Critical): 1-24 hour RTO, significant impact within hours
- 3 (Business Important): 1-7 day RTO, moderate impact within days
- 4 (Administrative): > 7 day RTO, minimal impact
- 5 (Non-Essential): No operational impact

ASSETS TO CLASSIFY (${assets.length}):
${JSON.stringify(assets.map((a) => ({
    id: a.assetId,
    hostname: a.hostname,
    type: a.assetType,
    classes: a.assetClasses,
    tags: a.tags,
    tech: a.technologies?.slice(0, 5),
    desc: a.description?.slice(0, 200),
    url: a.url
  })), null, 2)}

${(() => {
    const allTech = assets.flatMap((a) => [
      a.assetType,
      ...(a.technologies || []).map((t) => typeof t === "string" ? t : t.name || "")
    ].filter(Boolean));
    const ontologyCtx = allTech.length > 0 ? getFormatOntologyForPrompt()([...new Set(allTech)]) : "";
    const owaspCtx = getOwaspAssetClassificationContext();
    return (ontologyCtx ? "ASSET ARCHITECTURE KNOWLEDGE BASE:\n" + ontologyCtx + "\n\n" : "") + owaspCtx;
  })()}

For EACH asset, return:
1. deviceType, platformType, missionFunction, essentialService
2. assetPurpose: 1-2 sentence description of what this asset does for the organization
3. businessImpactLevel: mission_critical | business_essential | operational | administrative
4. fips199Category: { confidentiality: "low"|"moderate"|"high", integrity: "low"|"moderate"|"high", availability: "low"|"moderate"|"high" }
5. criticalityTier: 1-5 based on RTO analysis
6. missionDependencies: { upstreamAssets: [], downstreamAssets: [], sharedServices: [] }
7. carverAdjustments: Specific CARVER factor scores (0-10) based on your classification
8. shockAdjustments: Specific Shock factor scores (0-10) based on your classification
9. classificationConfidence: 0-1
10. reasoning: Brief explanation including your inference chain (device \u2192 platform \u2192 mission)

CALIBRATION RULES:
- Only 5-10% of assets should be mission_critical / Tier 1
- Consider the organization's sector when assessing impact
- CDNs, static sites, and marketing pages are almost always administrative / Tier 4-5
- Domain controllers, SSO, and payment gateways are almost always Tier 1
- APIs and databases are typically Tier 2 unless storing critical data

Return JSON: { "classifications": [ { "assetId": "...", ... } ] }`;
  try {
    const response = await invokeLLM({
      _caller: "scoring-engine",
      _priority: "essential",
      messages: [
        { role: "system", content: "You are an IT asset classification specialist. Return only valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" }
    });
    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) return /* @__PURE__ */ new Map();
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch {
      const match = content.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (match) parsed = JSON.parse(match[1]);
      else return /* @__PURE__ */ new Map();
    }
    const result = /* @__PURE__ */ new Map();
    for (const c of parsed.classifications || []) {
      result.set(c.assetId, {
        deviceType: c.deviceType || "unknown",
        platformType: c.platformType || "unknown",
        missionFunction: c.missionFunction || "operational_continuity",
        essentialService: c.essentialService || "unknown",
        assetPurpose: c.assetPurpose || "",
        businessImpactLevel: c.businessImpactLevel || "operational",
        fips199Category: c.fips199Category || void 0,
        criticalityTier: c.criticalityTier ? clamp(c.criticalityTier, 1, 5) : void 0,
        missionDependencies: c.missionDependencies || { upstreamAssets: [], downstreamAssets: [], sharedServices: [] },
        carverAdjustments: c.carverAdjustments || {},
        shockAdjustments: c.shockAdjustments || {},
        classificationConfidence: clamp(c.classificationConfidence || 0.5, 0, 1),
        reasoning: c.reasoning || ""
      });
    }
    return result;
  } catch (err) {
    console.error(`[ScoringEngine] Asset classification failed: ${err.message}`);
    return /* @__PURE__ */ new Map();
  }
}
function applyDiscoveryTrigger(triggerType, triggerData, currentCarver, currentShock) {
  const trigger = DISCOVERY_PHASE_TRIGGERS[triggerType];
  if (!trigger) return { carver: currentCarver, shock: currentShock, likelihoodBoost: 0 };
  const carverAdj = trigger.carverAdjustments(triggerData);
  const shockAdj = trigger.shockAdjustments(triggerData);
  const likelihoodBoost = trigger.likelihoodBoost(triggerData);
  const adjustedCarver = { ...currentCarver };
  const adjustedShock = { ...currentShock };
  for (const [key, val] of Object.entries(carverAdj)) {
    const k = key;
    adjustedCarver[k] = Math.max(adjustedCarver[k], val);
  }
  for (const [key, val] of Object.entries(shockAdj)) {
    const k = key;
    adjustedShock[k] = Math.max(adjustedShock[k], val);
  }
  return { carver: adjustedCarver, shock: adjustedShock, likelihoodBoost };
}
function generateRescoringEvent(trigger, assetId, previousResult, newResult, changeDescription, factorChanges) {
  return {
    trigger,
    assetId,
    previousScore: previousResult.hybridRiskScore,
    newScore: newResult.hybridRiskScore,
    previousBand: previousResult.riskBand,
    newBand: newResult.riskBand,
    delta: newResult.hybridRiskScore - previousResult.hybridRiskScore,
    changeDescription,
    factorChanges,
    timestamp: Date.now()
  };
}
function isSignificantChange(event) {
  if (event.previousBand !== event.newBand) return true;
  if (Math.abs(event.delta) >= 15) return true;
  if (event.newBand === "critical" && event.previousBand !== "critical") return true;
  return false;
}
function dbProfileToScoringProfile(row) {
  return {
    carverWeights: {
      criticality: row.wCriticality ?? 2,
      accessibility: row.wAccessibility ?? 1.5,
      recuperability: row.wRecuperability ?? 1,
      vulnerability: row.wVulnerability ?? 1.5,
      effect: row.wEffect ?? 1.5,
      recognizability: row.wRecognizability ?? 0.5
    },
    shockWeights: {
      scope: row.wScope ?? 1.5,
      handling: row.wHandling ?? 1,
      operationalImpact: row.wOperationalImpact ?? 2,
      cascadingEffects: row.wCascadingEffects ?? 1.5,
      knowledge: row.wKnowledge ?? 1
    },
    carverWeight: row.carverWeight ?? 0.4,
    shockWeight: row.shockWeight ?? 0.3,
    cvssWeight: row.cvssWeight ?? 0.3,
    criticalThreshold: row.criticalThreshold ?? 85,
    highThreshold: row.highThreshold ?? 65,
    mediumThreshold: row.mediumThreshold ?? 40
  };
}
function riskScoreToHeatColor(score) {
  const clamped = clamp(score, 0, 100);
  const hue = Math.round(120 * (1 - clamped / 100));
  const saturation = 70 + Math.round(30 * (clamped / 100));
  const lightness = 50 - Math.round(10 * (clamped / 100));
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
}
function generateHeatMapData(assets) {
  return assets.map((a) => ({
    assetId: a.assetId,
    hostname: a.hostname,
    score: a.hybridRiskScore,
    band: a.riskBand,
    color: riskScoreToHeatColor(a.hybridRiskScore),
    missionFunction: a.missionFunction || "unknown",
    businessImpactLevel: a.businessImpactLevel || "operational",
    intensity: clamp(a.hybridRiskScore / 100, 0, 1)
  }));
}
var CRITICALITY_TIERS, CARVER_DIGITAL_TRANSLATION, SHOCK_DIGITAL_TRANSLATION, ASSET_DEVICE_TYPES, ASSET_PLATFORM_TYPES, MISSION_FUNCTIONS, ESSENTIAL_SERVICES, BUSINESS_IMPACT_LEVELS, MISSION_FUNCTION_BASELINES, ESSENTIAL_SERVICE_BASELINES, DEFAULT_PROFILE, PRESET_PROFILES, DISCOVERY_PHASE_TRIGGERS;
var init_scoring_engine = __esm({
  "server/lib/scoring-engine.ts"() {
    init_llm();
    init_asset_ontology();
    init_owasp_knowledge();
    CRITICALITY_TIERS = {
      1: {
        name: "Mission Critical",
        rto: "< 1 hour",
        description: "Immediate operational impact. Loss causes complete mission failure. No acceptable workaround exists.",
        missionMultiplier: 2,
        carverFloor: { criticality: 9, effect: 8, recuperability: 9 },
        shockFloor: { operationalImpact: 9, cascadingEffects: 8, scope: 8 }
      },
      2: {
        name: "Business Critical",
        rto: "1\u201324 hours",
        description: "Significant impact within hours. Core business functions degraded. Manual workarounds possible but costly.",
        missionMultiplier: 1.6,
        carverFloor: { criticality: 7, effect: 7, recuperability: 7 },
        shockFloor: { operationalImpact: 7, cascadingEffects: 6, scope: 6 }
      },
      3: {
        name: "Business Important",
        rto: "1\u20137 days",
        description: "Moderate impact within days. Supporting functions affected. Workarounds available.",
        missionMultiplier: 1.3,
        carverFloor: { criticality: 5, effect: 5, recuperability: 5 },
        shockFloor: { operationalImpact: 5, cascadingEffects: 4, scope: 4 }
      },
      4: {
        name: "Administrative",
        rto: "> 7 days",
        description: "Minimal operational impact. Administrative or convenience functions. Extended outage tolerable.",
        missionMultiplier: 0.9,
        carverFloor: { criticality: 3, effect: 3 },
        shockFloor: { operationalImpact: 3 }
      },
      5: {
        name: "Non-Essential",
        rto: "N/A",
        description: "No operational impact. Test environments, deprecated systems, or non-production assets.",
        missionMultiplier: 0.6,
        carverFloor: { criticality: 1, effect: 1 },
        shockFloor: { operationalImpact: 1 }
      }
    };
    CARVER_DIGITAL_TRANSLATION = {
      criticality: {
        name: "Criticality (Mission Value)",
        contextQuestion: "How important is the target to the overall system/mission?",
        digital: "How critical is this digital asset to the organization's essential missions and supporting functions?",
        scale: [
          { range: [9, 10], original: "Immediate halt in output/production/service", digital: "Domain controller, primary DB, payment gateway \u2014 immediate halt to all dependent services" },
          { range: [7, 8], original: "Halt within 1 day, or 66% curtailment", digital: "Email server, VPN concentrator, ERP \u2014 major business disruption within hours" },
          { range: [5, 6], original: "Halt within 1 week, or 33% curtailment", digital: "CI/CD pipeline, monitoring stack, secondary DNS \u2014 degraded operations within days" },
          { range: [3, 4], original: "Halt within 10 days, or 10% curtailment", digital: "Development server, staging environment, internal wiki \u2014 minor productivity loss" },
          { range: [1, 2], original: "No significant effect on output", digital: "Test environment, deprecated system, static marketing page \u2014 no operational impact" }
        ],
        subFactors: ["Time to impact", "Percentage of function curtailment", "Availability of surrogates", "Position in dependency chain"]
      },
      accessibility: {
        name: "Accessibility (Attack Surface)",
        contextQuestion: "Can the attacker reach the target?",
        digital: "How reachable is the asset from an attacker's perspective, considering network position and authentication barriers?",
        scale: [
          { range: [9, 10], original: "Easily accessible, standoff weapons can be employed", digital: "Internet-facing, no auth required, known service with public exploits" },
          { range: [7, 8], original: "Inside perimeter fence but outdoors", digital: "Internet-facing with basic auth, or DMZ with known attack surface" },
          { range: [5, 6], original: "Inside building, ground floor", digital: "DMZ with WAF/IDS, requires credential theft or social engineering" },
          { range: [3, 4], original: "Inside building, 2nd floor/basement", digital: "Internal network, segmented VLAN, requires lateral movement" },
          { range: [1, 2], original: "Not accessible or extreme difficulty", digital: "Air-gapped, hardware security module, or zero-trust microsegmented" }
        ],
        subFactors: ["Network exposure", "Authentication barriers", "Firewall/WAF protection", "Physical access requirements"]
      },
      recuperability: {
        name: "Recuperability (Recovery Difficulty)",
        contextQuestion: "How long to replace, repair, or bypass?",
        digital: "How long to restore the asset to full operational capability after compromise or destruction?",
        scale: [
          { range: [9, 10], original: "Replacement/repair requires 1 month+", digital: "Custom-built system, no backups, no documentation \u2014 months to rebuild" },
          { range: [7, 8], original: "Replacement/repair requires 1 week to 1 month", digital: "Complex system, weekly backups, specialized knowledge required" },
          { range: [5, 6], original: "Replacement/repair requires 72 hours to 1 week", digital: "Standard system, daily backups, documented recovery procedures" },
          { range: [3, 4], original: "Replacement/repair requires 24 to 72 hours", digital: "Redundant system, hot standby, automated failover with manual intervention" },
          { range: [1, 2], original: "Same day replacement/repair", digital: "Auto-scaling, instant failover, immutable infrastructure, containerized" }
        ],
        subFactors: ["Backup frequency", "Recovery documentation", "Redundancy level", "Specialized knowledge required"]
      },
      vulnerability: {
        name: "Vulnerability (Exploitability)",
        contextQuestion: "Does the attacker have means to exploit?",
        digital: "Does the attacker have viable means to exploit this asset, considering known CVEs, misconfigurations, and available tooling?",
        scale: [
          { range: [9, 10], original: "Vulnerable to small arms or charges \u22645 lbs", digital: "Known RCE with public exploit, actively exploited in the wild (KEV)" },
          { range: [7, 8], original: "Vulnerable to light antiarmor or 5-10 lb charges", digital: "Known vulnerability with proof-of-concept, exploit kit available" },
          { range: [5, 6], original: "Vulnerable to medium antiarmor or 10-30 lb charges", digital: "Known vulnerability, complex exploit chain required" },
          { range: [3, 4], original: "Vulnerable to heavy antiarmor or 30-50 lb charges", digital: "Theoretical vulnerability, no public exploit, requires custom tooling" },
          { range: [1, 2], original: "Invulnerable to all but extreme measures", digital: "No known vulnerabilities, hardened configuration, defense in depth" }
        ],
        subFactors: ["CVE count and severity", "Exploit availability", "Patch status", "Configuration hardening"]
      },
      effect: {
        name: "Effect (Organizational Impact)",
        contextQuestion: "Financial, regulatory, reputational, operational impacts",
        digital: "What are the broader organizational impacts of successful compromise \u2014 financial, regulatory, reputational, operational?",
        scale: [
          { range: [9, 10], original: "Overwhelmingly positive effects for attacker", digital: "Data breach + regulatory fines + reputational damage + operational shutdown" },
          { range: [7, 8], original: "Moderately positive effects for attacker", digital: "Service disruption + financial loss + customer impact" },
          { range: [5, 6], original: "No significant effects; neutral", digital: "Limited operational impact, contained to single business unit" },
          { range: [3, 4], original: "Moderately negative effects for attacker", digital: "Minimal impact, quickly contained, no data exposure" },
          { range: [1, 2], original: "Overwhelmingly negative effects for attacker", digital: "No meaningful impact, honeypot/deception, attacker exposure risk" }
        ],
        subFactors: ["Financial impact", "Regulatory consequences", "Reputational damage", "Operational disruption"]
      },
      recognizability: {
        name: "Recognizability (Discoverability)",
        contextQuestion: "Degree to which target can be identified",
        digital: "How easily can an attacker identify, fingerprint, and target this specific asset?",
        scale: [
          { range: [9, 10], original: "Clearly recognizable under all conditions from distance", digital: "Banner grabbing reveals exact version, indexed by search engines, public documentation" },
          { range: [7, 8], original: "Easily recognizable at small-arms range", digital: "Service type identifiable, version guessable from behavior patterns" },
          { range: [5, 6], original: "Difficult in bad weather, might be confused", digital: "Service type identifiable but version hidden, generic error pages" },
          { range: [3, 4], original: "Difficult even at close range, easily confused", digital: "Behind CDN/WAF, minimal fingerprint, custom headers stripped" },
          { range: [1, 2], original: "Cannot be recognized except by experts", digital: "Completely obscured, no signatures, deception/honeypot deployed" }
        ],
        subFactors: ["Banner exposure", "Search engine indexing", "DNS/certificate transparency", "Error page information leakage"]
      }
    };
    SHOCK_DIGITAL_TRANSLATION = {
      scope: {
        name: "Scope (Blast Radius)",
        original: "Health, psychological, and collateral economic impacts \u2014 scope of affected population",
        digital: "How many users, customers, or systems are affected by compromise of this asset?",
        scale: [
          { range: [9, 10], digital: "All customers/users affected, global service outage, supply chain cascade" },
          { range: [7, 8], digital: "Major customer segment affected, regional outage, partner impact" },
          { range: [5, 6], digital: "Department-level impact, subset of users affected" },
          { range: [3, 4], digital: "Team-level impact, limited user base affected" },
          { range: [1, 2], digital: "Single user or system affected, no external impact" }
        ]
      },
      handling: {
        name: "Handling (Response Complexity)",
        original: "Difficulty of incident response and containment",
        digital: "How complex is the incident response, forensics, and remediation process?",
        scale: [
          { range: [9, 10], digital: "Requires external forensics, legal counsel, regulatory notification, board-level response" },
          { range: [7, 8], digital: "Cross-team IR, evidence preservation, customer notification required" },
          { range: [5, 6], digital: "Standard IR playbook, contained within security team" },
          { range: [3, 4], digital: "Simple remediation, automated response available" },
          { range: [1, 2], digital: "Self-healing, auto-rollback, no manual intervention needed" }
        ]
      },
      operationalImpact: {
        name: "Operational Impact (Business Disruption)",
        original: "Disruption to normal operations and essential services",
        digital: "How severely does compromise disrupt day-to-day business operations and revenue generation?",
        scale: [
          { range: [9, 10], digital: "Complete business halt, revenue stops, SLA violations, contractual penalties" },
          { range: [7, 8], digital: "Major business disruption, significant revenue impact, degraded SLAs" },
          { range: [5, 6], digital: "Moderate disruption, some revenue impact, workarounds available" },
          { range: [3, 4], digital: "Minor disruption, negligible revenue impact, easy workarounds" },
          { range: [1, 2], digital: "No operational disruption, business continues normally" }
        ]
      },
      cascadingEffects: {
        name: "Cascading Effects (Dependency Chain)",
        original: "Collateral national economic impact and downstream effects",
        digital: "Does compromise of this asset enable attacks on dependent systems, partners, or supply chain?",
        scale: [
          { range: [9, 10], digital: "Compromise enables full domain takeover, supply chain poisoning, island-hopping to partners" },
          { range: [7, 8], digital: "Compromise of auth/SSO cascades to all downstream applications" },
          { range: [5, 6], digital: "Compromise affects 2-3 dependent systems or services" },
          { range: [3, 4], digital: "Limited cascade, 1 dependent system affected" },
          { range: [1, 2], digital: "Isolated system, no downstream dependencies" }
        ]
      },
      knowledge: {
        name: "Knowledge (Exploitation Expertise)",
        original: "Specialized knowledge required for attack",
        digital: "What level of specialized knowledge or tooling does an attacker need to exploit this asset?",
        scale: [
          { range: [9, 10], digital: "Script kiddie level \u2014 automated tools, public exploits, no expertise needed" },
          { range: [7, 8], digital: "Intermediate \u2014 requires understanding of the technology stack" },
          { range: [5, 6], digital: "Advanced \u2014 requires custom tooling or exploit development" },
          { range: [3, 4], digital: "Expert \u2014 requires deep domain knowledge and specialized equipment" },
          { range: [1, 2], digital: "Nation-state level \u2014 requires zero-day research and significant resources" }
        ]
      }
    };
    ASSET_DEVICE_TYPES = [
      "network_infrastructure",
      "server",
      "endpoint",
      "security_appliance",
      "storage",
      "cloud_service",
      "iot_ot",
      "unknown"
    ];
    ASSET_PLATFORM_TYPES = [
      "identity_access",
      "business_critical",
      "communication",
      "development",
      "data_store",
      "web_application",
      "monitoring",
      "content_delivery",
      "unknown"
    ];
    MISSION_FUNCTIONS = [
      "command_control",
      "revenue_generation",
      "customer_data",
      "intellectual_property",
      "operational_continuity",
      "compliance",
      "external_communication",
      "authentication",
      "data_processing",
      "supply_chain"
    ];
    ESSENTIAL_SERVICES = [
      "email",
      "sso",
      "vpn",
      "dns",
      "dhcp",
      "active_directory",
      "payment_processing",
      "customer_portal",
      "api_gateway",
      "database",
      "file_storage",
      "backup",
      "monitoring",
      "ci_cd",
      "source_control",
      "container_orchestration",
      "erp",
      "crm",
      "hrm",
      "voip",
      "video_conferencing",
      "web_server",
      "load_balancer",
      "firewall",
      "waf",
      "siem",
      "edr",
      "dlp",
      "encryption_key_management"
    ];
    BUSINESS_IMPACT_LEVELS = [
      "mission_critical",
      "business_essential",
      "operational",
      "administrative"
    ];
    MISSION_FUNCTION_BASELINES = {
      command_control: {
        carver: { criticality: 9, effect: 8, recuperability: 7 },
        shock: { operationalImpact: 9, cascadingEffects: 8, scope: 7 },
        missionMultiplier: 1.8,
        description: "C2 assets are the nerve center \u2014 compromise enables adversary control of the entire operational environment"
      },
      revenue_generation: {
        carver: { criticality: 8, effect: 8, recognizability: 7 },
        shock: { operationalImpact: 8, scope: 7, handling: 6 },
        missionMultiplier: 1.6,
        description: "Revenue assets directly impact financial viability \u2014 downtime or breach has immediate P&L consequences"
      },
      customer_data: {
        carver: { criticality: 8, effect: 7, recuperability: 8 },
        shock: { scope: 9, handling: 8, operationalImpact: 7 },
        missionMultiplier: 1.7,
        description: "Customer data assets carry regulatory and reputational risk \u2014 breach triggers mandatory disclosure and potential class action"
      },
      intellectual_property: {
        carver: { criticality: 7, effect: 9, recuperability: 9 },
        shock: { cascadingEffects: 8, scope: 6, knowledge: 7 },
        missionMultiplier: 1.5,
        description: "IP assets represent irreplaceable competitive advantage \u2014 exfiltration causes permanent strategic damage"
      },
      operational_continuity: {
        carver: { criticality: 7, effect: 7, recuperability: 6 },
        shock: { operationalImpact: 8, cascadingEffects: 7, handling: 6 },
        missionMultiplier: 1.4,
        description: "Operational assets keep the lights on \u2014 disruption cascades through dependent business processes"
      },
      compliance: {
        carver: { criticality: 6, effect: 7, recognizability: 5 },
        shock: { scope: 7, handling: 7, operationalImpact: 5 },
        missionMultiplier: 1.3,
        description: "Compliance assets carry regulatory risk \u2014 failure triggers audit findings, fines, and potential license revocation"
      },
      external_communication: {
        carver: { criticality: 6, accessibility: 8, recognizability: 8 },
        shock: { scope: 6, handling: 5, operationalImpact: 5 },
        missionMultiplier: 1.2,
        description: "External-facing communication assets are highly accessible and recognizable \u2014 prime targets for impersonation and phishing"
      },
      authentication: {
        carver: { criticality: 9, accessibility: 7, effect: 9, recuperability: 8 },
        shock: { cascadingEffects: 9, operationalImpact: 8, scope: 8 },
        missionMultiplier: 1.9,
        description: "Authentication is the master key \u2014 compromise grants adversary access to all downstream systems and data"
      },
      data_processing: {
        carver: { criticality: 6, effect: 6, vulnerability: 5 },
        shock: { operationalImpact: 6, cascadingEffects: 5, handling: 5 },
        missionMultiplier: 1.2,
        description: "Data processing assets transform raw data into actionable intelligence \u2014 disruption delays decision-making"
      },
      supply_chain: {
        carver: { criticality: 7, accessibility: 6, vulnerability: 7 },
        shock: { cascadingEffects: 8, scope: 7, handling: 7 },
        missionMultiplier: 1.5,
        description: "Supply chain assets bridge trust boundaries \u2014 compromise enables island-hopping attacks to partners and vendors"
      }
    };
    ESSENTIAL_SERVICE_BASELINES = {
      sso: { carver: { criticality: 9, effect: 9, recuperability: 8 }, shock: { cascadingEffects: 9, scope: 8 } },
      active_directory: { carver: { criticality: 9, effect: 9, recuperability: 9 }, shock: { cascadingEffects: 9, scope: 9, operationalImpact: 9 } },
      payment_processing: { carver: { criticality: 8, effect: 8, recognizability: 7 }, shock: { scope: 8, handling: 8 } },
      email: { carver: { criticality: 7, accessibility: 8, recognizability: 8 }, shock: { scope: 7, operationalImpact: 7 } },
      vpn: { carver: { criticality: 7, accessibility: 9, vulnerability: 7 }, shock: { cascadingEffects: 7, operationalImpact: 7 } },
      dns: { carver: { criticality: 8, effect: 8, recuperability: 6 }, shock: { cascadingEffects: 8, scope: 8 } },
      database: { carver: { criticality: 8, effect: 7, recuperability: 7 }, shock: { scope: 7, handling: 7 } },
      api_gateway: { carver: { criticality: 7, accessibility: 8, recognizability: 7 }, shock: { cascadingEffects: 7, scope: 6 } },
      firewall: { carver: { criticality: 8, effect: 8, vulnerability: 5 }, shock: { cascadingEffects: 8, scope: 7 } },
      backup: { carver: { criticality: 7, recuperability: 9, recognizability: 3 }, shock: { handling: 8, operationalImpact: 6 } },
      siem: { carver: { criticality: 6, effect: 5, recognizability: 4 }, shock: { handling: 7, knowledge: 7 } },
      encryption_key_management: { carver: { criticality: 9, effect: 9, recuperability: 10 }, shock: { cascadingEffects: 9, scope: 8, handling: 9 } },
      ci_cd: { carver: { criticality: 7, vulnerability: 7, effect: 7 }, shock: { cascadingEffects: 7, knowledge: 6 } },
      source_control: { carver: { criticality: 7, effect: 8, recuperability: 7 }, shock: { scope: 6, knowledge: 7 } },
      customer_portal: { carver: { criticality: 7, accessibility: 9, recognizability: 8 }, shock: { scope: 7, handling: 6 } },
      erp: { carver: { criticality: 8, effect: 8, recuperability: 7 }, shock: { operationalImpact: 9, cascadingEffects: 7, scope: 7 } },
      load_balancer: { carver: { criticality: 7, effect: 7, recognizability: 5 }, shock: { cascadingEffects: 7, operationalImpact: 6 } },
      waf: { carver: { criticality: 6, effect: 6, vulnerability: 4 }, shock: { scope: 5, handling: 5 } }
    };
    DEFAULT_PROFILE = {
      carverWeights: {
        criticality: 2,
        accessibility: 1.5,
        recuperability: 1,
        vulnerability: 1.5,
        effect: 1.5,
        recognizability: 0.5
      },
      shockWeights: {
        scope: 1.5,
        handling: 1,
        operationalImpact: 2,
        cascadingEffects: 1.5,
        knowledge: 1
      },
      carverWeight: 0.4,
      shockWeight: 0.3,
      cvssWeight: 0.3,
      criticalThreshold: 85,
      highThreshold: 65,
      mediumThreshold: 40
    };
    PRESET_PROFILES = {
      critical_infrastructure: {
        name: "Critical Infrastructure",
        description: "Emphasizes Shock factors (cascading effects, operational impact) for SCADA/ICS/OT environments. Designed for assessments of power grids, water treatment, and transportation systems.",
        profile: {
          ...DEFAULT_PROFILE,
          carverWeights: { criticality: 2.5, accessibility: 1, recuperability: 2, vulnerability: 1.5, effect: 2, recognizability: 0.5 },
          shockWeights: { scope: 2.5, handling: 1.5, operationalImpact: 3, cascadingEffects: 2.5, knowledge: 1 },
          carverWeight: 0.3,
          shockWeight: 0.5,
          cvssWeight: 0.2
        }
      },
      financial_services: {
        name: "Financial Services",
        description: "Prioritizes accessibility and data exposure for banking, payment processing, and financial infrastructure. Aligns with PCI-DSS and SOX requirements.",
        profile: {
          ...DEFAULT_PROFILE,
          carverWeights: { criticality: 2, accessibility: 2.5, recuperability: 1.5, vulnerability: 2, effect: 1.5, recognizability: 1 },
          shockWeights: { scope: 2, handling: 1.5, operationalImpact: 1.5, cascadingEffects: 1, knowledge: 0.5 },
          carverWeight: 0.45,
          shockWeight: 0.2,
          cvssWeight: 0.35
        }
      },
      healthcare: {
        name: "Healthcare / HIPAA",
        description: "Emphasizes recuperability and operational impact for patient care systems. Aligns with HIPAA security requirements and patient safety priorities.",
        profile: {
          ...DEFAULT_PROFILE,
          carverWeights: { criticality: 2, accessibility: 1.5, recuperability: 2.5, vulnerability: 1.5, effect: 2, recognizability: 0.5 },
          shockWeights: { scope: 1.5, handling: 2, operationalImpact: 2.5, cascadingEffects: 2, knowledge: 1 },
          carverWeight: 0.35,
          shockWeight: 0.4,
          cvssWeight: 0.25
        }
      },
      government_dod: {
        name: "Government / DoD",
        description: "Balanced CARVER emphasis for military and government assessments. Aligns with NIST 800-53, CMMC, and traditional CARVER targeting methodology.",
        profile: {
          ...DEFAULT_PROFILE,
          carverWeights: { criticality: 2.5, accessibility: 2, recuperability: 1.5, vulnerability: 1.5, effect: 2, recognizability: 1 },
          shockWeights: { scope: 1.5, handling: 1, operationalImpact: 1.5, cascadingEffects: 1.5, knowledge: 1.5 },
          carverWeight: 0.5,
          shockWeight: 0.25,
          cvssWeight: 0.25
        }
      },
      red_team_offensive: {
        name: "Red Team / Offensive",
        description: "Maximizes accessibility and vulnerability weights to prioritize the easiest attack paths. Designed for penetration testing and adversary emulation engagements.",
        profile: {
          ...DEFAULT_PROFILE,
          carverWeights: { criticality: 1.5, accessibility: 3, recuperability: 0.5, vulnerability: 2.5, effect: 1, recognizability: 1.5 },
          shockWeights: { scope: 1, handling: 0.5, operationalImpact: 1, cascadingEffects: 0.5, knowledge: 1.5 },
          carverWeight: 0.5,
          shockWeight: 0.15,
          cvssWeight: 0.35
        }
      },
      mssp_managed: {
        name: "MSSP / Managed Services",
        description: "Balanced profile for managed security service providers managing multiple client environments. Emphasizes scope and cascading effects across client boundaries.",
        profile: {
          ...DEFAULT_PROFILE,
          carverWeights: { criticality: 2, accessibility: 2, recuperability: 1.5, vulnerability: 1.5, effect: 1.5, recognizability: 1 },
          shockWeights: { scope: 2.5, handling: 1.5, operationalImpact: 1.5, cascadingEffects: 2, knowledge: 1 },
          carverWeight: 0.35,
          shockWeight: 0.35,
          cvssWeight: 0.3
        }
      }
    };
    DISCOVERY_PHASE_TRIGGERS = {
      new_cve_discovered: {
        description: "New CVE discovered during vulnerability scanning",
        carverAdjustments: (data) => ({
          vulnerability: data.kevListed ? 10 : data.exploitAvailable ? 8 : Math.min(10, Math.round((data.cvssScore ?? 5) * 1.2))
        }),
        shockAdjustments: () => ({}),
        likelihoodBoost: (data) => data.exploitAvailable ? 0.25 : (data.cvssScore ?? 5) > 7 ? 0.15 : 0.05
      },
      new_port_service: {
        description: "New port/service discovered during enumeration",
        carverAdjustments: (data) => ({
          accessibility: data.isHighRiskPort ? 8 : 6,
          recognizability: data.serviceVersion ? 7 : 5
        }),
        shockAdjustments: () => ({}),
        likelihoodBoost: (data) => data.isHighRiskPort ? 0.1 : 0.03
      },
      kev_match: {
        description: "Asset vulnerability matches CISA Known Exploited Vulnerabilities catalog",
        carverAdjustments: (data) => ({
          vulnerability: 10,
          recognizability: 8,
          ...data.ransomware ? { criticality: 9, effect: 9 } : {},
          ...data.overdueAction ? { accessibility: 9 } : {}
        }),
        shockAdjustments: (data) => ({
          scope: data.ransomware ? 9 : 7,
          handling: data.ransomware ? 9 : 7,
          ...data.ransomware ? { cascadingEffects: 9, operationalImpact: 9 } : {}
        }),
        likelihoodBoost: (data) => data.ransomware ? 0.45 : 0.3
      },
      darkweb_exposure: {
        description: "Asset credentials or data found on dark web marketplaces",
        carverAdjustments: (data) => ({
          accessibility: 9,
          vulnerability: 8,
          recognizability: 9
        }),
        shockAdjustments: (data) => ({
          scope: data.dataType === "credentials" ? 8 : 6,
          handling: 8
        }),
        likelihoodBoost: () => 0.25
      },
      threat_actor_ttp_match: {
        description: "Asset matches known threat actor TTP targeting patterns",
        carverAdjustments: (data) => ({
          vulnerability: data.sophistication === "apt" ? 7 : 5
        }),
        shockAdjustments: (data) => ({
          knowledge: data.sophistication === "apt" ? 3 : 6
        }),
        likelihoodBoost: (data) => data.sophistication === "apt" ? 0.2 : 0.1
      },
      attack_chain_match: {
        description: "Asset vulnerabilities match a known multi-step attack chain from the training corpus",
        carverAdjustments: (data) => ({
          vulnerability: data.feasibility === "high" ? 9 : data.feasibility === "medium" ? 7 : 5,
          effect: (data.chainLength ?? 1) >= 3 ? 8 : 6
        }),
        shockAdjustments: (data) => ({
          cascadingEffects: (data.chainLength ?? 1) >= 3 ? 8 : 5,
          scope: (data.chainLength ?? 1) >= 4 ? 7 : 5
        }),
        likelihoodBoost: (data) => data.feasibility === "high" ? 0.25 : data.feasibility === "medium" ? 0.15 : 0.05
      },
      bug_bounty_correlation: {
        description: "Vulnerability pattern matches known bug bounty findings from training corpus",
        carverAdjustments: (data) => ({
          vulnerability: data.bountyTier === "critical" ? 9 : data.bountyTier === "high" ? 7 : 5,
          accessibility: 7
        }),
        shockAdjustments: (data) => ({
          handling: data.bountyTier === "critical" ? 8 : 6
        }),
        likelihoodBoost: (data) => data.bountyTier === "critical" ? 0.3 : data.bountyTier === "high" ? 0.2 : 0.1
      }
    };
  }
});

export {
  detectAndDampCorrelatedInputs,
  parseCvssV4Vector,
  buildCvssV4Vector,
  cvssV4ToCarverAdjustments,
  fips199ToCarverAdjustments,
  CRITICALITY_TIERS,
  applyCriticalityTierFloors,
  CARVER_DIGITAL_TRANSLATION,
  SHOCK_DIGITAL_TRANSLATION,
  ASSET_DEVICE_TYPES,
  ASSET_PLATFORM_TYPES,
  MISSION_FUNCTIONS,
  ESSENTIAL_SERVICES,
  BUSINESS_IMPACT_LEVELS,
  MISSION_FUNCTION_BASELINES,
  ESSENTIAL_SERVICE_BASELINES,
  DEFAULT_PROFILE,
  PRESET_PROFILES,
  computeCarverComposite,
  computeShockComposite,
  computeMissionImpact,
  applyMissionBaselines,
  businessImpactToMultiplier,
  computeHybridRisk,
  classifyAssets,
  DISCOVERY_PHASE_TRIGGERS,
  applyDiscoveryTrigger,
  generateRescoringEvent,
  isSignificantChange,
  dbProfileToScoringProfile,
  riskScoreToHeatColor,
  generateHeatMapData,
  init_scoring_engine
};
