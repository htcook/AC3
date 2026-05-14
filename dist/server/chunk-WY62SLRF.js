import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/passive/corroboration-engine.ts
function generateFingerprint(obs) {
  const type = obs.assetType;
  switch (type) {
    case "subdomain": {
      const host = (obs.name || obs.assetId).toLowerCase().replace(/\.$/, "");
      return `sub:${host}`;
    }
    case "ip": {
      const ip = obs.ip || obs.name || obs.assetId;
      const port = obs.evidence?.port || obs.evidence?.ports?.[0] || "";
      return port ? `ip:${ip}:${port}` : `ip:${ip}`;
    }
    case "certificate": {
      const cn = obs.evidence?.subject_cn || obs.evidence?.common_name || obs.name || "";
      const serial = obs.evidence?.serial || "";
      return serial ? `cert:${serial}` : `cert:${cn.toLowerCase()}`;
    }
    case "url": {
      const url = (obs.name || obs.evidence?.url || obs.assetId).toLowerCase();
      const normalized = url.replace(/^https?:\/\//, "").replace(/\/$/, "");
      return `url:${normalized}`;
    }
    case "breach": {
      const source = obs.evidence?.breach_source || obs.evidence?.database_name || "";
      const target = obs.evidence?.email || obs.domain;
      return `breach:${source.toLowerCase()}:${target.toLowerCase()}`;
    }
    case "mx":
    case "ns":
    case "cname":
    case "txt": {
      const value = (obs.name || obs.evidence?.value || obs.assetId).toLowerCase();
      return `${type}:${value}`;
    }
    case "asn": {
      const asnNum = obs.asn || obs.evidence?.asn || obs.assetId;
      return `asn:${asnNum}`;
    }
    default:
      return `${type}:${obs.assetId}`;
  }
}
function corroborateFindings(connectorResults, riskSignals, config = DEFAULT_CORROBORATION_CONFIG) {
  const fingerprintMap = /* @__PURE__ */ new Map();
  for (const result of connectorResults) {
    for (const obs of result.observations) {
      const fp = generateFingerprint(obs);
      if (!fingerprintMap.has(fp)) {
        fingerprintMap.set(fp, { sources: /* @__PURE__ */ new Set(), observations: [] });
      }
      const group = fingerprintMap.get(fp);
      group.sources.add(obs.source);
      group.observations.push(obs);
    }
  }
  const corroboratedObservations = [];
  const sourceAgreement = {};
  let unverifiedCount = 0;
  let corroboratedCount = 0;
  let highConfidenceCount = 0;
  let totalSourceCount = 0;
  for (const fp of Array.from(fingerprintMap.keys())) {
    const group = fingerprintMap.get(fp);
    const sourceCount = group.sources.size;
    const confirmingSources = Array.from(group.sources).sort();
    totalSourceCount += sourceCount;
    let tier;
    let confidenceMultiplier;
    if (sourceCount >= 3) {
      tier = "high-confidence";
      confidenceMultiplier = config.multiSourceMultiplier;
      highConfidenceCount += group.observations.length;
    } else if (sourceCount === 2) {
      tier = "corroborated";
      confidenceMultiplier = config.dualSourceMultiplier;
      corroboratedCount += group.observations.length;
    } else {
      tier = "unverified";
      confidenceMultiplier = config.singleSourceMultiplier;
      unverifiedCount += group.observations.length;
    }
    if (sourceCount >= 2) {
      for (let i = 0; i < confirmingSources.length; i++) {
        for (let j = i + 1; j < confirmingSources.length; j++) {
          const a = confirmingSources[i];
          const b = confirmingSources[j];
          if (!sourceAgreement[a]) sourceAgreement[a] = {};
          if (!sourceAgreement[b]) sourceAgreement[b] = {};
          sourceAgreement[a][b] = (sourceAgreement[a][b] || 0) + 1;
          sourceAgreement[b][a] = (sourceAgreement[b][a] || 0) + 1;
        }
      }
    }
    for (const obs of group.observations) {
      const corroborated = {
        ...obs,
        corroboration: {
          sourceCount,
          confirmingSources,
          confidenceMultiplier,
          tier,
          fingerprint: fp
        }
      };
      corroboratedObservations.push(corroborated);
    }
  }
  const assetCorroboration = /* @__PURE__ */ new Map();
  for (const obs of corroboratedObservations) {
    const existing = assetCorroboration.get(obs.assetId);
    if (!existing || obs.corroboration.confidenceMultiplier > existing.multiplier) {
      assetCorroboration.set(obs.assetId, {
        multiplier: obs.corroboration.confidenceMultiplier,
        tier: obs.corroboration.tier
      });
    }
  }
  const adjustedSignals = riskSignals.map((signal) => {
    const corr = assetCorroboration.get(signal.assetId);
    if (!corr) return signal;
    return {
      ...signal,
      confidence: Math.min(1, signal.confidence * corr.multiplier),
      evidenceRefs: [
        ...signal.evidenceRefs,
        `corroboration:${corr.tier}`
      ]
    };
  });
  const totalObs = corroboratedObservations.length;
  const corroborationRate = totalObs > 0 ? (corroboratedCount + highConfidenceCount) / totalObs * 100 : 0;
  const averageSourceCount = fingerprintMap.size > 0 ? totalSourceCount / fingerprintMap.size : 0;
  return {
    totalObservations: totalObs,
    uniqueFindings: fingerprintMap.size,
    corroboratedObservations,
    adjustedSignals,
    stats: {
      unverifiedCount,
      corroboratedCount,
      highConfidenceCount,
      corroborationRate: Math.round(corroborationRate * 10) / 10,
      averageSourceCount: Math.round(averageSourceCount * 100) / 100,
      sourceAgreement
    }
  };
}
function deduplicateWithCorroboration(corroboratedObservations) {
  const byFingerprint = /* @__PURE__ */ new Map();
  for (const obs of corroboratedObservations) {
    const fp = obs.corroboration.fingerprint;
    if (!byFingerprint.has(fp)) {
      byFingerprint.set(fp, []);
    }
    byFingerprint.get(fp).push(obs);
  }
  const deduplicated = [];
  for (const fp of Array.from(byFingerprint.keys())) {
    const group = byFingerprint.get(fp);
    const best = group.reduce((a, b) => {
      const aEvidence = Object.keys(a.evidence).length;
      const bEvidence = Object.keys(b.evidence).length;
      if (bEvidence > aEvidence) return b;
      if (bEvidence === aEvidence && b.observedAt > a.observedAt) return b;
      return a;
    });
    const allSources = /* @__PURE__ */ new Set();
    for (const obs of group) {
      for (const src of obs.corroboration.confirmingSources) {
        allSources.add(src);
      }
    }
    deduplicated.push({
      ...best,
      corroboration: {
        ...best.corroboration,
        confirmingSources: Array.from(allSources).sort(),
        sourceCount: allSources.size
      }
    });
  }
  return deduplicated;
}
function getSourceReliability(source) {
  return SOURCE_RELIABILITY[source] ?? 0.5;
}
var DEFAULT_CORROBORATION_CONFIG, SOURCE_RELIABILITY;
var init_corroboration_engine = __esm({
  "server/lib/passive/corroboration-engine.ts"() {
    DEFAULT_CORROBORATION_CONFIG = {
      singleSourceMultiplier: 0.6,
      dualSourceMultiplier: 0.85,
      multiSourceMultiplier: 1,
      annotateObservations: true
    };
    SOURCE_RELIABILITY = {
      "shodan": 0.9,
      // Active scanning, fresh data
      "shodan-internetdb": 0.85,
      // Cached but frequently updated
      "censys": 0.9,
      // Active scanning, fresh data
      "binaryedge": 0.85,
      // Active scanning
      "crtsh": 0.95,
      // Certificate transparency — authoritative
      "securitytrails": 0.8,
      // DNS history — good but can be stale
      "urlscan": 0.75,
      // Community submissions — variable freshness
      "rdap": 0.95,
      // Registry data — authoritative
      "ripestat": 0.9,
      // RIR data — authoritative
      "dehashed": 0.7,
      // Breach data — variable age
      "greynoise": 0.85,
      // Active threat intel — fresh
      "wayback": 0.5
      // Historical archives — often stale
    };
  }
});

export {
  DEFAULT_CORROBORATION_CONFIG,
  generateFingerprint,
  corroborateFindings,
  deduplicateWithCorroboration,
  SOURCE_RELIABILITY,
  getSourceReliability,
  init_corroboration_engine
};
