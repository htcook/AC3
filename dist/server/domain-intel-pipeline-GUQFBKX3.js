import "./chunk-KFQGP6VL.js";

// server/lib/domain-intel-pipeline.ts
async function runDomainIntelPipeline(domain) {
  const { runPassiveRecon } = await import("./passive-5NB6YR5H.js");
  const { ENV } = await import("./env-ERXRTOPW.js");
  const passiveRecon = await runPassiveRecon(domain, {
    scanMode: "standard",
    apiKeys: {
      shodan: ENV.SHODAN_API_KEY || void 0,
      censys_id: ENV.CENSYS_API_ID || void 0,
      censys_secret: ENV.CENSYS_API_SECRET || void 0,
      urlscan: ENV.URLSCAN_API_KEY || void 0,
      securitytrails: ENV.SECURITYTRAILS_API_KEY || void 0,
      dehashed: ENV.DEHASHED_API_KEY || void 0,
      abuseipdb: ENV.ABUSEIPDB_API_KEY || void 0,
      github: ENV.GITHUB_PAT || void 0
    },
    timeout: 3e4,
    maxConcurrent: 5
  });
  const technologies = [];
  const services = [];
  const subdomains = [];
  const certificates = [];
  const aRecords = [];
  for (const obs of passiveRecon.allObservations) {
    if (obs.ip && !aRecords.includes(obs.ip)) aRecords.push(obs.ip);
    if (obs.assetType === "subdomain" && obs.name && !subdomains.includes(obs.name)) {
      subdomains.push(obs.name);
    }
    const ev = obs.evidence || {};
    if (ev.port) {
      services.push({
        port: Number(ev.port),
        protocol: ev.transport || "tcp",
        service: ev.service || ev.product || "unknown",
        product: ev.product,
        version: ev.version
      });
    }
    if (ev.product && !technologies.includes(ev.product)) technologies.push(ev.product);
    if (ev.technologies && Array.isArray(ev.technologies)) {
      for (const t of ev.technologies) {
        if (typeof t === "string" && !technologies.includes(t)) technologies.push(t);
      }
    }
    if (obs.assetType === "certificate" && obs.name) {
      certificates.push({ subject: obs.name, issuer: obs.evidence?.issuer });
    }
  }
  return {
    dns: { aRecords },
    technologies,
    riskSignals: passiveRecon.riskSignals?.map((r) => ({
      severity: r.severity || "info",
      type: r.signalType || r.type || "unknown",
      rationale: r.rationale || r.description || r.title || ""
    })) || [],
    services,
    subdomains,
    certificates,
    allObservations: passiveRecon.allObservations,
    summary: passiveRecon.summary
  };
}
export {
  runDomainIntelPipeline
};
