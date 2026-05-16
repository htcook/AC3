import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/fingerprint-cve-enrichment.ts
var fingerprint_cve_enrichment_exports = {};
__export(fingerprint_cve_enrichment_exports, {
  buildFingerprintExploitContext: () => buildFingerprintExploitContext,
  enrichFingerprintsWithVulnFeeds: () => enrichFingerprintsWithVulnFeeds
});
function expandProductNames(product) {
  const lower = product.toLowerCase().replace(/[^a-z0-9.-]/g, "");
  const variants = /* @__PURE__ */ new Set();
  variants.add(product);
  for (const [key, aliases] of Object.entries(PRODUCT_NORMALIZATION)) {
    if (lower === key || lower.includes(key) || key.includes(lower)) {
      for (const alias of aliases) variants.add(alias);
    }
  }
  return Array.from(variants);
}
async function enrichFingerprintsWithVulnFeeds(fpResults) {
  const { matchTechnologiesAgainstAllFeeds } = await import("./vuln-feeds-3ZYWGLNW.js");
  const productVersionMap = {};
  const allTechnologies = [];
  for (const fp of fpResults) {
    if (fp.error || !fp.product) continue;
    const variants = expandProductNames(fp.product);
    for (const variant of variants) {
      allTechnologies.push(variant);
      if (fp.version) {
        productVersionMap[variant] = fp.version;
      }
    }
    if (fp.metadata?.techPhp) {
      allTechnologies.push("PHP");
    }
    if (fp.metadata?.techWordPress) {
      allTechnologies.push("WordPress");
    }
    if (fp.metadata?.techDrupal) {
      allTechnologies.push("Drupal");
    }
    if (fp.metadata?.techJoomla) {
      allTechnologies.push("Joomla");
    }
    if (fp.metadata?.techAspNet) {
      allTechnologies.push("ASP.NET");
    }
    if (fp.metadata?.techExpress) {
      allTechnologies.push("Express");
    }
    if (fp.metadata?.techNextJs) {
      allTechnologies.push("Next.js");
    }
    if (fp.metadata?.techVarnish) {
      allTechnologies.push("Varnish");
    }
    if (fp.metadata?.poweredBy) {
      const pbParts = fp.metadata.poweredBy.match(/^([\w.-]+)(?:\/([\d.]+))?/);
      if (pbParts) {
        allTechnologies.push(pbParts[1]);
        if (pbParts[2]) productVersionMap[pbParts[1]] = pbParts[2];
      }
    }
  }
  const uniqueTech = [...new Set(allTechnologies)];
  if (uniqueTech.length === 0) {
    return {
      results: fpResults,
      summary: buildEmptySummary(fpResults)
    };
  }
  let feedResult;
  try {
    feedResult = await matchTechnologiesAgainstAllFeeds(uniqueTech, productVersionMap);
  } catch (err) {
    console.error("[FP-CVE-Enrich] Vuln feed query failed:", err.message);
    return {
      results: fpResults,
      summary: buildEmptySummary(fpResults)
    };
  }
  const { matchMultipleTechnologies, buildCpeUri, filterCvesByVersion } = await import("./dynamic-cpe-matcher-HNVLLGIO.js");
  const { registerUnmappedTechnology } = await import("./cpe-dictionary-updater-HXAJWKYS.js");
  const cpeTechEntries = [];
  const cpeTechToFpMap = /* @__PURE__ */ new Map();
  for (const fp of fpResults) {
    if (fp.error || !fp.product) continue;
    const key = `${fp.product.toLowerCase()}|${fp.version || ""}`;
    if (!cpeTechToFpMap.has(key)) {
      cpeTechToFpMap.set(key, []);
      cpeTechEntries.push({ name: fp.product, version: fp.version || void 0 });
    }
    cpeTechToFpMap.get(key).push(fp);
  }
  let cpeResults = [];
  let cpeStats = { totalResolved: 0, exactMatches: 0, partialMatches: 0, fuzzyMatches: 0, totalCpeCves: 0, uniqueCpeCves: 0 };
  if (cpeTechEntries.length > 0) {
    try {
      cpeResults = await matchMultipleTechnologies(cpeTechEntries);
      const cpeCveIds = /* @__PURE__ */ new Set();
      for (const r of cpeResults) {
        if (r.cpeUri && r.cpeUri !== "cpe:2.3:*:*:*:*:*:*:*:*") {
          cpeStats.totalResolved++;
          if (r.matchConfidence === "exact") cpeStats.exactMatches++;
          else if (r.matchConfidence === "partial") cpeStats.partialMatches++;
          else cpeStats.fuzzyMatches++;
        }
        cpeStats.totalCpeCves += r.cves.length;
        for (const cve of r.cves) cpeCveIds.add(cve.cveId);
      }
      cpeStats.uniqueCpeCves = cpeCveIds.size;
      for (const r of cpeResults) {
        if (!r.cpeUri || r.cpeUri.startsWith("keyword:") || r.matchConfidence === "fuzzy") {
          registerUnmappedTechnology(r.technology);
        }
      }
      console.log(`[FP-CVE-Enrich] CPE matching: ${cpeStats.totalResolved} resolved, ${cpeStats.uniqueCpeCves} unique CVEs from ${cpeStats.totalCpeCves} total`);
    } catch (err) {
      console.error("[FP-CVE-Enrich] CPE matching failed (non-fatal):", err.message);
    }
  }
  const cpeResultMap = /* @__PURE__ */ new Map();
  for (const r of cpeResults) {
    const key = `${r.technology.toLowerCase()}|${r.version || ""}`;
    cpeResultMap.set(key, r);
  }
  const techMatchMap = /* @__PURE__ */ new Map();
  for (const match of feedResult.matches) {
    techMatchMap.set(match.technology.toLowerCase(), match);
  }
  const perService = [];
  let totalCvesMatched = 0;
  let exploitableCveCount = 0;
  let kevCveCount = 0;
  let zeroDayCveCount = 0;
  let enrichedCount = 0;
  let maxSeverityOrder = 0;
  const severityOrderMap = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  for (const fp of fpResults) {
    if (fp.error) continue;
    let bestMatch;
    if (fp.product) {
      const variants = expandProductNames(fp.product);
      for (const variant of variants) {
        const match = techMatchMap.get(variant.toLowerCase());
        if (match && (!bestMatch || match.riskScore > bestMatch.riskScore)) {
          bestMatch = match;
        }
      }
    }
    let cpeMatch;
    if (fp.product) {
      const cpeKey = `${fp.product.toLowerCase()}|${fp.version || ""}`;
      cpeMatch = cpeResultMap.get(cpeKey);
    }
    const metaTechs = [];
    if (fp.metadata?.techPhp) metaTechs.push("php");
    if (fp.metadata?.techWordPress) metaTechs.push("wordpress");
    if (fp.metadata?.techDrupal) metaTechs.push("drupal");
    if (fp.metadata?.techJoomla) metaTechs.push("joomla");
    if (fp.metadata?.techAspNet) metaTechs.push("asp.net");
    const metaMatches = [];
    for (const mt of metaTechs) {
      const match = techMatchMap.get(mt);
      if (match) metaMatches.push(match);
    }
    const allMatches = bestMatch ? [bestMatch, ...metaMatches] : metaMatches;
    const seenCves = /* @__PURE__ */ new Set();
    const mergedCves = [];
    for (const match of allMatches) {
      for (const vuln of match.vulns) {
        if (!seenCves.has(vuln.cveId)) {
          seenCves.add(vuln.cveId);
          mergedCves.push(vuln);
        }
      }
    }
    if (cpeMatch && cpeMatch.cves.length > 0) {
      const versionFilteredCves = fp.version ? filterCvesByVersion(cpeMatch.cves, fp.version) : cpeMatch.cves;
      for (const cpeCve of versionFilteredCves) {
        if (!seenCves.has(cpeCve.cveId)) {
          seenCves.add(cpeCve.cveId);
          mergedCves.push({
            cveId: cpeCve.cveId,
            title: cpeCve.description?.slice(0, 200) || cpeCve.cveId,
            severity: cpeCve.severity,
            cvssScore: cpeCve.cvssV3Score,
            exploitAvailable: (cpeCve.exploitabilityScore ?? 0) > 3.5,
            kevListed: false,
            // KEV status comes from vuln feeds, not NVD directly
            inTheWild: false,
            source: "nvd-cpe",
            publishedDate: cpeCve.published
          });
        }
      }
    }
    if (mergedCves.length > 0) {
      enrichedCount++;
      const existingCves = new Set(fp.potentialCves || []);
      for (const vuln of mergedCves) {
        if (!existingCves.has(vuln.cveId)) {
          fp.potentialCves.push(vuln.cveId);
        }
      }
      for (const vuln of mergedCves) {
        if (vuln.severity === "critical" || vuln.severity === "high") {
          const existingTitles = new Set(fp.riskIndicators.map((r) => r.title));
          const title = vuln.kevListed ? `KEV-Listed: ${vuln.cveId}` : vuln.inTheWild ? `Active Exploitation: ${vuln.cveId}` : vuln.exploitAvailable ? `Public Exploit: ${vuln.cveId}` : `Known Vuln: ${vuln.cveId}`;
          if (!existingTitles.has(title)) {
            fp.riskIndicators.push({
              severity: vuln.severity,
              title,
              description: `${vuln.title} (CVSS: ${vuln.cvssScore ?? "N/A"})${vuln.exploitAvailable ? " \u2014 Exploit available" : ""}${vuln.kevListed ? " \u2014 CISA KEV" : ""}`,
              cweId: void 0,
              cveId: vuln.cveId,
              exploitAvailable: vuln.exploitAvailable,
              kevListed: vuln.kevListed
            });
          }
        }
      }
      fp.metadata.vulnFeedMatches = {
        totalCves: mergedCves.length,
        exploitableCves: mergedCves.filter((v) => v.exploitAvailable).length,
        kevCves: mergedCves.filter((v) => v.kevListed).length,
        zeroDayCves: mergedCves.filter((v) => v.inTheWild).length,
        maxCvss: Math.max(...mergedCves.map((v) => v.cvssScore || 0)),
        corroborationTier: bestMatch?.corroborationTier || "potential",
        riskScore: bestMatch?.riskScore || 0,
        topCves: mergedCves.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0)).slice(0, 10).map((v) => ({
          cveId: v.cveId,
          title: v.title,
          severity: v.severity,
          cvssScore: v.cvssScore,
          exploitAvailable: v.exploitAvailable,
          kevListed: v.kevListed,
          inTheWild: v.inTheWild
        }))
      };
      if (mergedCves.some((v) => v.exploitAvailable)) {
        if (!fp.mitreRelevance.includes("T1190")) fp.mitreRelevance.push("T1190");
      }
      if (mergedCves.some((v) => v.kevListed)) {
        if (!fp.mitreRelevance.includes("T1203")) fp.mitreRelevance.push("T1203");
      }
      const fpExploitable = mergedCves.filter((v) => v.exploitAvailable).length;
      const fpKev = mergedCves.filter((v) => v.kevListed).length;
      const fpZeroDay = mergedCves.filter((v) => v.inTheWild).length;
      totalCvesMatched += mergedCves.length;
      exploitableCveCount += fpExploitable;
      kevCveCount += fpKev;
      zeroDayCveCount += fpZeroDay;
      const fpMaxSev = Math.max(...mergedCves.map((v) => severityOrderMap[v.severity] || 0));
      if (fpMaxSev > maxSeverityOrder) maxSeverityOrder = fpMaxSev;
    }
    perService.push({
      host: fp.host,
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product,
      version: fp.version,
      matchedCves: mergedCves.slice(0, 15).map((v) => ({
        cveId: v.cveId,
        severity: v.severity,
        cvssScore: v.cvssScore,
        exploitAvailable: v.exploitAvailable,
        kevListed: v.kevListed,
        inTheWild: v.inTheWild,
        title: v.title
      })),
      corroborationTier: cpeMatch && cpeMatch.matchConfidence === "exact" ? "confirmed" : bestMatch?.corroborationTier || (mergedCves.length > 0 ? "potential" : "none"),
      riskScore: cpeMatch && cpeMatch.cves.length > 0 ? Math.max(bestMatch?.riskScore || 0, 60 + Math.min(cpeMatch.cves.length * 5, 40)) : bestMatch?.riskScore || 0,
      exploitPriority: 0,
      // Calculated below
      cpeUri: cpeMatch?.cpeUri,
      cpeMatchConfidence: cpeMatch?.matchConfidence || "none"
    });
  }
  perService.sort((a, b) => {
    const aKev = a.matchedCves.filter((c) => c.kevListed).length;
    const bKev = b.matchedCves.filter((c) => c.kevListed).length;
    if (aKev !== bKev) return bKev - aKev;
    const aExploit = a.matchedCves.filter((c) => c.exploitAvailable).length;
    const bExploit = b.matchedCves.filter((c) => c.exploitAvailable).length;
    if (aExploit !== bExploit) return bExploit - aExploit;
    return b.riskScore - a.riskScore;
  });
  perService.forEach((s, i) => {
    s.exploitPriority = i + 1;
  });
  const severityNames = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: "unknown"
  };
  const summary = {
    totalFingerprints: fpResults.length,
    identifiedProducts: fpResults.filter((f) => f.product && !f.error).length,
    enrichedCount,
    totalCvesMatched,
    exploitableCveCount,
    kevCveCount,
    zeroDayCveCount,
    perService,
    overallRiskScore: Math.min(100, Math.round(
      (feedResult.overallRiskBoost || 0) + (kevCveCount > 0 ? 30 : 0) + (exploitableCveCount > 0 ? 20 : 0) + (totalCvesMatched > 10 ? 15 : totalCvesMatched > 5 ? 10 : totalCvesMatched > 0 ? 5 : 0) + (maxSeverityOrder >= 4 ? 25 : maxSeverityOrder >= 3 ? 15 : 5) + (cpeStats.exactMatches > 0 ? 10 : 0)
      // Bonus for CPE-confirmed matches
    )),
    maxSeverity: severityNames[maxSeverityOrder] || "unknown",
    cpeStats: cpeStats.totalResolved > 0 ? cpeStats : void 0
  };
  return { results: fpResults, summary };
}
function buildFingerprintExploitContext(summary) {
  if (summary.enrichedCount === 0) return "";
  const lines = [
    "## Fingerprint-Based Vulnerability Intelligence",
    "",
    `**${summary.totalCvesMatched} CVEs matched** across ${summary.enrichedCount} services (${summary.exploitableCveCount} with public exploits, ${summary.kevCveCount} CISA KEV, ${summary.zeroDayCveCount} active 0-day)`,
    `**Overall Risk Score: ${summary.overallRiskScore}/100** | Max Severity: ${summary.maxSeverity.toUpperCase()}`,
    "",
    "### Priority Targets (ordered by exploit likelihood):",
    ""
  ];
  for (const svc of summary.perService) {
    if (svc.matchedCves.length === 0) continue;
    const kevCves = svc.matchedCves.filter((c) => c.kevListed);
    const exploitCves = svc.matchedCves.filter((c) => c.exploitAvailable && !c.kevListed);
    const otherCves = svc.matchedCves.filter((c) => !c.exploitAvailable && !c.kevListed);
    lines.push(
      `**#${svc.exploitPriority} ${svc.host}:${svc.port}** (${svc.protocol}) \u2014 ${svc.product || "unknown"}${svc.version ? "/" + svc.version : ""} [${svc.corroborationTier.toUpperCase()}] Risk: ${svc.riskScore}/100`
    );
    if (kevCves.length > 0) {
      lines.push(`  \u{1F534} CISA KEV (MUST exploit first): ${kevCves.map((c) => `${c.cveId} (CVSS ${c.cvssScore ?? "?"})`).join(", ")}`);
    }
    if (exploitCves.length > 0) {
      lines.push(`  \u{1F7E0} Public Exploits: ${exploitCves.slice(0, 5).map((c) => `${c.cveId} (CVSS ${c.cvssScore ?? "?"})`).join(", ")}${exploitCves.length > 5 ? ` (+${exploitCves.length - 5} more)` : ""}`);
    }
    if (otherCves.length > 0) {
      lines.push(`  \u{1F7E1} Known CVEs: ${otherCves.slice(0, 5).map((c) => `${c.cveId}`).join(", ")}${otherCves.length > 5 ? ` (+${otherCves.length - 5} more)` : ""}`);
    }
    lines.push("");
  }
  lines.push(
    "### Exploitation Priority Rules:",
    "1. ALWAYS attempt CISA KEV-listed CVEs first \u2014 these have confirmed in-the-wild exploitation",
    "2. Prioritize services with public exploits (ExploitDB/MSF modules available)",
    "3. Target version-confirmed CVEs over potential matches",
    "4. For services with multiple CVEs, chain exploits for maximum impact",
    ""
  );
  return lines.join("\n");
}
function buildEmptySummary(fpResults) {
  return {
    totalFingerprints: fpResults.length,
    identifiedProducts: fpResults.filter((f) => f.product && !f.error).length,
    enrichedCount: 0,
    totalCvesMatched: 0,
    exploitableCveCount: 0,
    kevCveCount: 0,
    zeroDayCveCount: 0,
    perService: [],
    overallRiskScore: 0,
    maxSeverity: "unknown"
  };
}
var PRODUCT_NORMALIZATION;
var init_fingerprint_cve_enrichment = __esm({
  "server/lib/fingerprint-cve-enrichment.ts"() {
    PRODUCT_NORMALIZATION = {
      "apache": ["Apache", "Apache HTTP Server", "httpd", "Apache2"],
      "nginx": ["nginx", "Nginx"],
      "microsoft-iis": ["Microsoft IIS", "IIS", "Internet Information Services"],
      "iis": ["Microsoft IIS", "IIS", "Internet Information Services"],
      "openssl": ["OpenSSL"],
      "openssh": ["OpenSSH"],
      "php": ["PHP"],
      "wordpress": ["WordPress"],
      "drupal": ["Drupal"],
      "joomla": ["Joomla"],
      "tomcat": ["Apache Tomcat", "Tomcat"],
      "jenkins": ["Jenkins"],
      "grafana": ["Grafana"],
      "gitlab": ["GitLab"],
      "redis": ["Redis"],
      "mysql": ["MySQL"],
      "mariadb": ["MariaDB"],
      "postgresql": ["PostgreSQL"],
      "mongodb": ["MongoDB"],
      "elasticsearch": ["Elasticsearch"],
      "rabbitmq": ["RabbitMQ"],
      "proftpd": ["ProFTPD"],
      "vsftpd": ["vsftpd"],
      "exim": ["Exim"],
      "postfix": ["Postfix"],
      "dovecot": ["Dovecot"],
      "samba": ["Samba"],
      "lighttpd": ["lighttpd"],
      "caddy": ["Caddy"],
      "haproxy": ["HAProxy"],
      "varnish": ["Varnish"],
      "express": ["Express", "Express.js"],
      "next.js": ["Next.js"],
      "flask": ["Flask"],
      "django": ["Django"],
      "spring": ["Spring", "Spring Framework", "Spring Boot"],
      "laravel": ["Laravel"]
    };
  }
});

export {
  enrichFingerprintsWithVulnFeeds,
  buildFingerprintExploitContext,
  fingerprint_cve_enrichment_exports,
  init_fingerprint_cve_enrichment
};
