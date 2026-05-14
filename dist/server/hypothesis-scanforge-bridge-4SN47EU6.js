import "./chunk-KFQGP6VL.js";

// server/lib/hypothesis-scanforge-bridge.ts
var VULN_CLASS_TO_NUCLEI_TAGS = {
  "xss": ["xss", "dom-xss", "reflected-xss", "stored-xss"],
  "sqli": ["sqli", "sql-injection", "blind-sqli", "error-based-sqli"],
  "ssrf": ["ssrf", "server-side-request-forgery"],
  "idor": ["idor", "insecure-direct-object-reference", "broken-access-control"],
  "rce": ["rce", "remote-code-execution", "command-injection", "code-injection"],
  "lfi": ["lfi", "local-file-inclusion", "path-traversal", "directory-traversal"],
  "rfi": ["rfi", "remote-file-inclusion"],
  "xxe": ["xxe", "xml-external-entity"],
  "ssti": ["ssti", "server-side-template-injection", "template-injection"],
  "auth-bypass": ["auth-bypass", "authentication-bypass", "broken-authentication"],
  "csrf": ["csrf", "cross-site-request-forgery"],
  "open-redirect": ["open-redirect", "redirect"],
  "file-upload": ["file-upload", "unrestricted-upload"],
  "deserialization": ["deserialization", "insecure-deserialization"],
  "jwt": ["jwt", "json-web-token"],
  "cors": ["cors", "misconfiguration"],
  "information-disclosure": ["exposure", "disclosure", "information-disclosure"],
  "privilege-escalation": ["privilege-escalation", "broken-access-control"],
  "race-condition": ["race-condition", "toctou"],
  "business-logic": ["business-logic", "logic-flaw"],
  "api-abuse": ["api", "graphql", "rest-api"],
  "subdomain-takeover": ["takeover", "subdomain-takeover"],
  "cache-poisoning": ["cache-poisoning", "web-cache"],
  "prototype-pollution": ["prototype-pollution"],
  "crlf-injection": ["crlf", "header-injection"]
};
var VULN_CLASS_TO_SCANFORGE_SCRIPTS = {
  "xss": ["--script=http-stored-xss,http-dombased-xss,http-phpself-xss"],
  "sqli": ["--script=http-sql-injection"],
  "rce": ["--script=http-shellshock,http-vuln-cve*"],
  "lfi": ["--script=http-passwd"],
  "xxe": ["--script=http-xml-external-entity"],
  "auth-bypass": ["--script=http-auth-finder,http-default-accounts,http-brute"],
  "information-disclosure": ["--script=http-headers,http-methods,http-trace,http-config-backup"],
  "subdomain-takeover": ["--script=dns-nsid,dns-zone-transfer"]
};
var PRIORITY_BOOST = {
  critical: 25,
  high: 15,
  medium: 8
};
function enrichScanPlanWithHypotheses(plan, adjustments) {
  if (!adjustments.length || !plan.targets.length) {
    return {
      targetsEnriched: 0,
      nucleiTagsInjected: 0,
      scanforgeConfigsAugmented: 0,
      provenanceRecordsAdded: 0,
      enrichments: []
    };
  }
  const enrichments = [];
  let nucleiTagsInjected = 0;
  let scanforgeConfigsAugmented = 0;
  let provenanceRecordsAdded = 0;
  const enrichedTargets = /* @__PURE__ */ new Set();
  const adjustmentsByTarget = /* @__PURE__ */ new Map();
  for (const adj of adjustments) {
    const hostname = extractHostname(adj.endpoint);
    if (!hostname) continue;
    if (!adjustmentsByTarget.has(hostname)) {
      adjustmentsByTarget.set(hostname, []);
    }
    adjustmentsByTarget.get(hostname).push(adj);
  }
  for (const target of plan.targets) {
    const targetAdjs = findMatchingAdjustments(target.hostname, adjustmentsByTarget);
    if (!targetAdjs.length) continue;
    enrichedTargets.add(target.hostname);
    const originalPriority = target.priority;
    const maxBoost = Math.max(...targetAdjs.map((a) => PRIORITY_BOOST[a.priority] || 0));
    target.priority = Math.min(100, target.priority + maxBoost);
    for (const adj of targetAdjs) {
      target.triggeringSignals.push(`[HYPOTHESIS] ${adj.vulnClass}: ${adj.reason}`);
    }
    target.rationale += ` | Hypothesis boost: +${maxBoost} (${targetAdjs.length} hypotheses)`;
    enrichments.push({
      target: target.hostname,
      action: "priority_boost",
      detail: `Priority ${originalPriority} \u2192 ${target.priority} (+${maxBoost}) from ${targetAdjs.length} hypothesis(es)`
    });
  }
  for (const nucleiCfg of plan.nucleiConfigs) {
    const targetAdjs = findMatchingAdjustments(nucleiCfg.target, adjustmentsByTarget);
    if (!targetAdjs.length) continue;
    const existingTags = new Set(nucleiCfg.tags);
    const newTags = [];
    for (const adj of targetAdjs) {
      const vulnKey = normalizeVulnClass(adj.vulnClass);
      const mappedTags = VULN_CLASS_TO_NUCLEI_TAGS[vulnKey] || [];
      for (const tag of mappedTags) {
        if (!existingTags.has(tag)) {
          newTags.push(tag);
          existingTags.add(tag);
        }
      }
    }
    if (newTags.length > 0) {
      nucleiCfg.tags.push(...newTags);
      nucleiTagsInjected += newTags.length;
      const hasCritical = targetAdjs.some((a) => a.priority === "critical");
      if (hasCritical && nucleiCfg.severityFilter !== "info,low,medium,high,critical") {
        nucleiCfg.severityFilter = "info,low,medium,high,critical";
      }
      nucleiCfg.rationale += ` | Hypothesis-injected tags: ${newTags.join(", ")}`;
      enrichments.push({
        target: nucleiCfg.target,
        action: "nuclei_tag_injection",
        detail: `Added ${newTags.length} hypothesis-derived template tags: ${newTags.slice(0, 5).join(", ")}${newTags.length > 5 ? "..." : ""}`
      });
    }
  }
  for (const scanCfg of plan.scanConfigs) {
    const targetAdjs = findMatchingAdjustments(scanCfg.target, adjustmentsByTarget);
    if (!targetAdjs.length) continue;
    const additionalFlags = [];
    for (const adj of targetAdjs) {
      const vulnKey = normalizeVulnClass(adj.vulnClass);
      const scripts = VULN_CLASS_TO_SCANFORGE_SCRIPTS[vulnKey];
      if (scripts) {
        for (const flag of scripts) {
          if (!scanCfg.flags.includes(flag)) {
            additionalFlags.push(flag);
          }
        }
      }
    }
    if (additionalFlags.length > 0) {
      scanCfg.flags += " " + additionalFlags.join(" ");
      scanCfg.rationale += ` | Hypothesis-targeted scripts: ${additionalFlags.join(", ")}`;
      scanforgeConfigsAugmented++;
      enrichments.push({
        target: scanCfg.target,
        action: "scanforge_augmentation",
        detail: `Added ${additionalFlags.length} hypothesis-targeted script flags`
      });
    }
  }
  for (const adj of adjustments) {
    const hostname = extractHostname(adj.endpoint);
    if (!hostname) continue;
    const targetExists = plan.targets.some((t) => t.hostname === hostname || hostname.includes(t.hostname) || t.hostname.includes(hostname));
    if (!targetExists) continue;
    plan.provenance.push({
      passiveObservationId: `hypothesis-${hostname}-${normalizeVulnClass(adj.vulnClass)}`,
      passiveSignal: `Hypothesis: ${adj.vulnClass} vulnerability predicted at ${adj.endpoint}`,
      activeTool: mapVulnClassToTool(adj.vulnClass),
      target: hostname,
      rationale: adj.reason
    });
    provenanceRecordsAdded++;
  }
  plan.targets.sort((a, b) => b.priority - a.priority);
  return {
    targetsEnriched: enrichedTargets.size,
    nucleiTagsInjected,
    scanforgeConfigsAugmented,
    provenanceRecordsAdded,
    enrichments
  };
}
function extractHostname(endpoint) {
  try {
    if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
      return new URL(endpoint).hostname;
    }
    return endpoint.split("/")[0].split(":")[0];
  } catch {
    return endpoint.split("/")[0].split(":")[0];
  }
}
function normalizeVulnClass(vulnClass) {
  const normalized = vulnClass.toLowerCase().replace(/[_\s]+/g, "-").replace(/cross-site-scripting/g, "xss").replace(/sql-injection/g, "sqli").replace(/server-side-request-forgery/g, "ssrf").replace(/insecure-direct-object-reference/g, "idor").replace(/remote-code-execution/g, "rce").replace(/local-file-inclusion/g, "lfi").replace(/remote-file-inclusion/g, "rfi").replace(/xml-external-entity/g, "xxe").replace(/server-side-template-injection/g, "ssti").replace(/cross-site-request-forgery/g, "csrf");
  return normalized;
}
function findMatchingAdjustments(hostname, adjustmentsByTarget) {
  const direct = adjustmentsByTarget.get(hostname);
  if (direct) return direct;
  const matches = [];
  for (const [adjHostname, adjs] of adjustmentsByTarget) {
    if (hostname.includes(adjHostname) || adjHostname.includes(hostname)) {
      matches.push(...adjs);
    }
  }
  return matches;
}
function mapVulnClassToTool(vulnClass) {
  const normalized = normalizeVulnClass(vulnClass);
  const nucleiVulns = ["xss", "sqli", "ssrf", "lfi", "rfi", "xxe", "ssti", "cors", "information-disclosure", "subdomain-takeover", "crlf-injection", "prototype-pollution", "cache-poisoning"];
  const zapVulns = ["xss", "csrf", "auth-bypass", "business-logic", "api-abuse"];
  const scanforgeVulns = ["rce", "deserialization"];
  if (scanforgeVulns.includes(normalized)) return "scanforge-discovery";
  if (zapVulns.includes(normalized)) return "zap";
  if (nucleiVulns.includes(normalized)) return "nuclei";
  return "nuclei";
}
function formatHypothesisEnrichmentSummary(enrichment) {
  if (enrichment.targetsEnriched === 0) {
    return "No hypothesis-based enrichments applied (no matching targets in scan plan).";
  }
  const lines = [
    `Hypothesis-driven scan enrichment: ${enrichment.targetsEnriched} targets boosted`,
    `  Nuclei tags injected: ${enrichment.nucleiTagsInjected}`,
    `  ScanForge configs augmented: ${enrichment.scanforgeConfigsAugmented}`,
    `  Provenance records added: ${enrichment.provenanceRecordsAdded}`
  ];
  if (enrichment.enrichments.length > 0) {
    lines.push("  Details:");
    for (const e of enrichment.enrichments.slice(0, 10)) {
      lines.push(`    [${e.action}] ${e.target}: ${e.detail}`);
    }
    if (enrichment.enrichments.length > 10) {
      lines.push(`    ... and ${enrichment.enrichments.length - 10} more`);
    }
  }
  return lines.join("\n");
}
export {
  enrichScanPlanWithHypotheses,
  formatHypothesisEnrichmentSummary
};
