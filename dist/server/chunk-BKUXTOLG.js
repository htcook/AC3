import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/bounty-hypothesis-generator.ts
var bounty_hypothesis_generator_exports = {};
__export(bounty_hypothesis_generator_exports, {
  generateHypotheses: () => generateHypotheses,
  generateProgramAwareHypotheses: () => generateProgramAwareHypotheses
});
function generateHypothesisId() {
  return `HYP-${Date.now().toString(36)}-${(++hypothesisCounter).toString(36).padStart(4, "0")}`;
}
function assessReconQuality(recon) {
  const missing = [];
  const recommendations = [];
  let score = 0;
  if (recon.techStack.length > 0) score += 25;
  else {
    missing.push("technology stack fingerprinting");
    recommendations.push("Run Wappalyzer or similar tech detection");
  }
  if (recon.openPorts.length > 0) score += 15;
  else {
    missing.push("port scan results");
    recommendations.push("Run Nmap service detection scan");
  }
  if (recon.endpoints.length > 0) score += 20;
  else {
    missing.push("endpoint enumeration");
    recommendations.push("Run Gobuster/ffuf directory enumeration");
  }
  if (recon.subdomains.length > 0) score += 10;
  else {
    missing.push("subdomain enumeration");
    recommendations.push("Run subfinder/amass for subdomain discovery");
  }
  if (recon.headers && Object.keys(recon.headers).length > 0) score += 10;
  else {
    missing.push("HTTP response headers");
    recommendations.push("Collect response headers from main endpoints");
  }
  if (recon.certificates) score += 5;
  else {
    missing.push("TLS certificate analysis");
    recommendations.push("Analyze TLS certificates for alt names and issuer");
  }
  if (recon.historicalArtifacts && recon.historicalArtifacts.length > 0) score += 10;
  else {
    missing.push("historical reconnaissance (Wayback)");
    recommendations.push("Check Wayback Machine for historical endpoints");
  }
  if (recon.configAnomalies && recon.configAnomalies.length > 0) score += 5;
  else {
    missing.push("configuration analysis");
    recommendations.push("Analyze CORS, CSP, and security headers");
  }
  return { overallScore: score, missingData: missing, recommendations };
}
function generateTechStackHypotheses(recon) {
  const hypotheses = [];
  for (const tech of recon.techStack) {
    for (const mapping of TECH_VULN_MAPPINGS) {
      if (!mapping.techPattern.test(tech.technology)) continue;
      for (const vulnMapping of mapping.vulnClasses) {
        if (vulnMapping.versionCondition && tech.version && !vulnMapping.versionCondition(tech.version)) {
          continue;
        }
        let confidenceScore = vulnMapping.baseConfidence * tech.confidence;
        const corroboratingEndpoints = recon.endpoints.filter((e) => {
          if (vulnMapping.vulnClass.includes("sqli") && e.parameters && e.parameters.length > 0) return true;
          if (vulnMapping.vulnClass.includes("xss") && e.parameters && e.parameters.length > 0) return true;
          if (vulnMapping.vulnClass === "ssrf" && e.parameters?.some((p) => /url|uri|link|redirect|callback|webhook/i.test(p))) return true;
          if (vulnMapping.vulnClass === "path_traversal" && e.parameters?.some((p) => /file|path|dir|doc|template/i.test(p))) return true;
          if (vulnMapping.vulnClass === "open_redirect" && e.parameters?.some((p) => /redirect|next|return|url|goto|continue/i.test(p))) return true;
          return false;
        });
        if (corroboratingEndpoints.length > 0) {
          confidenceScore = Math.min(confidenceScore + 0.15, 0.95);
        }
        const severity = VULN_SEVERITY_MAP[vulnMapping.vulnClass] || "medium";
        const bountyRange = SEVERITY_BOUNTY_RANGES[severity] || SEVERITY_BOUNTY_RANGES.medium;
        const affectedEndpoint = corroboratingEndpoints.length > 0 ? corroboratingEndpoints[0].path : recon.targetDomain;
        hypotheses.push({
          id: generateHypothesisId(),
          vulnClass: vulnMapping.vulnClass,
          title: `${vulnMapping.vulnClass.replace(/_/g, " ").toUpperCase()} in ${tech.technology}${tech.version ? ` ${tech.version}` : ""}`,
          description: vulnMapping.reasoning,
          affectedEndpoint,
          confidence: scoreToLevel(confidenceScore),
          confidenceScore,
          reasoning: [
            `Detected ${tech.technology}${tech.version ? ` version ${tech.version}` : ""} (confidence: ${(tech.confidence * 100).toFixed(0)}%, source: ${tech.source})`,
            vulnMapping.reasoning,
            ...corroboratingEndpoints.length > 0 ? [`Found ${corroboratingEndpoints.length} endpoint(s) with relevant parameters`] : []
          ],
          supportingEvidence: [
            { type: "tech_fingerprint", description: `${tech.technology} detected via ${tech.source}`, strength: tech.confidence > 0.8 ? "strong" : tech.confidence > 0.5 ? "moderate" : "weak", source: tech.source },
            ...corroboratingEndpoints.map((e) => ({
              type: "endpoint_pattern",
              description: `Endpoint ${e.path} has parameters: ${e.parameters?.join(", ")}`,
              strength: "moderate",
              source: "endpoint_enumeration"
            }))
          ],
          disconfirmingEvidence: [
            ...recon.wafDetected ? [{ type: "behavioral", description: `WAF detected (${recon.wafDetected}) may block exploitation`, strength: "moderate", source: "waf_detection" }] : []
          ],
          evidenceThatWouldChangeConfidence: [
            `Successful exploitation of ${vulnMapping.vulnClass} at ${affectedEndpoint} would confirm`,
            `WAF blocking all payloads would reduce confidence`,
            `Finding the specific vulnerable code path would increase confidence`
          ],
          verificationSteps: [
            { order: 1, action: vulnMapping.verificationHint, tool: getToolForVulnClass(vulnMapping.vulnClass), expectedOutcome: "Identify specific vulnerable endpoint", riskLevel: "low" },
            { order: 2, action: `Test with safe payload for ${vulnMapping.vulnClass}`, expectedOutcome: "Confirm vulnerability without exploitation", riskLevel: "medium" }
          ],
          estimatedEffort: confidenceScore > 0.6 ? "minutes" : confidenceScore > 0.3 ? "hours" : "days",
          potentialSeverity: severity,
          potentialBountyRange: { ...bountyRange, currency: "USD" },
          chainPotential: findChainOpportunities(vulnMapping.vulnClass),
          duplicateLikelihood: estimateDuplicateLikelihood(vulnMapping.vulnClass, tech.technology),
          tags: [tech.technology.toLowerCase(), vulnMapping.vulnClass, severity],
          generatedAt: Date.now()
        });
      }
    }
  }
  return hypotheses;
}
function generateConfigAnomalyHypotheses(recon) {
  const hypotheses = [];
  if (!recon.configAnomalies) return hypotheses;
  for (const anomaly of recon.configAnomalies) {
    for (const mapping of CONFIG_VULN_MAPPINGS) {
      if (mapping.category !== anomaly.category) continue;
      if (!mapping.pattern.test(anomaly.description) && !mapping.pattern.test(anomaly.evidence)) continue;
      const confidenceScore = Math.min(0.3 + mapping.confidenceBoost, 0.9);
      const severity = VULN_SEVERITY_MAP[mapping.vulnClass] || "medium";
      const bountyRange = SEVERITY_BOUNTY_RANGES[severity] || SEVERITY_BOUNTY_RANGES.medium;
      hypotheses.push({
        id: generateHypothesisId(),
        vulnClass: mapping.vulnClass,
        title: `${mapping.vulnClass.replace(/_/g, " ").toUpperCase()} via ${anomaly.category} misconfiguration`,
        description: mapping.reasoning,
        affectedEndpoint: recon.targetDomain,
        confidence: scoreToLevel(confidenceScore),
        confidenceScore,
        reasoning: [
          `Configuration anomaly detected: ${anomaly.description}`,
          mapping.reasoning,
          `Evidence: ${anomaly.evidence}`
        ],
        supportingEvidence: [
          { type: "config_anomaly", description: anomaly.description, strength: anomaly.severity === "high" ? "strong" : "moderate", source: "config_analysis" }
        ],
        disconfirmingEvidence: [],
        evidenceThatWouldChangeConfidence: [
          `Successful exploitation would confirm the misconfiguration is exploitable`,
          `Finding the configuration is intentional (documented security decision) would reduce confidence`
        ],
        verificationSteps: [
          { order: 1, action: `Verify ${anomaly.category} misconfiguration`, expectedOutcome: "Confirm the anomaly is exploitable", riskLevel: "safe" },
          { order: 2, action: `Attempt exploitation of ${mapping.vulnClass}`, expectedOutcome: "Demonstrate impact", riskLevel: "low" }
        ],
        estimatedEffort: "minutes",
        potentialSeverity: severity,
        potentialBountyRange: { ...bountyRange, currency: "USD" },
        chainPotential: findChainOpportunities(mapping.vulnClass),
        duplicateLikelihood: "medium",
        tags: [anomaly.category, mapping.vulnClass, severity],
        generatedAt: Date.now()
      });
    }
  }
  return hypotheses;
}
function generateHistoricalHypotheses(recon) {
  const hypotheses = [];
  if (!recon.historicalArtifacts) return hypotheses;
  for (const artifact of recon.historicalArtifacts) {
    if (!artifact.stillAccessible) continue;
    let vulnClass;
    let reasoning;
    let confidenceScore;
    switch (artifact.type) {
      case "admin":
        vulnClass = "auth_bypass";
        reasoning = "Historical admin endpoint still accessible \u2014 may lack proper authentication";
        confidenceScore = 0.5;
        break;
      case "debug":
        vulnClass = "info_disclosure";
        reasoning = "Historical debug endpoint still accessible \u2014 likely leaks sensitive information";
        confidenceScore = 0.6;
        break;
      case "config":
        vulnClass = "sensitive_data_exposure";
        reasoning = "Historical config file still accessible \u2014 may contain credentials or secrets";
        confidenceScore = 0.65;
        break;
      case "backup":
        vulnClass = "sensitive_data_exposure";
        reasoning = "Historical backup file still accessible \u2014 may contain source code or data";
        confidenceScore = 0.55;
        break;
      case "api":
        vulnClass = "auth_bypass";
        reasoning = "Historical API endpoint still accessible \u2014 may lack current auth controls";
        confidenceScore = 0.45;
        break;
      default:
        vulnClass = "info_disclosure";
        reasoning = "Historical endpoint still accessible \u2014 may expose outdated but sensitive content";
        confidenceScore = 0.3;
    }
    const severity = VULN_SEVERITY_MAP[vulnClass] || "medium";
    const bountyRange = SEVERITY_BOUNTY_RANGES[severity] || SEVERITY_BOUNTY_RANGES.medium;
    hypotheses.push({
      id: generateHypothesisId(),
      vulnClass,
      title: `${vulnClass.replace(/_/g, " ").toUpperCase()} via historical ${artifact.type} endpoint`,
      description: reasoning,
      affectedEndpoint: artifact.url,
      confidence: scoreToLevel(confidenceScore),
      confidenceScore,
      reasoning: [
        `Historical ${artifact.type} endpoint discovered: ${artifact.url}`,
        `First seen: ${artifact.discoveredAt}`,
        reasoning
      ],
      supportingEvidence: [
        { type: "historical", description: `${artifact.type} endpoint from ${artifact.discoveredAt} still accessible`, strength: "strong", source: "wayback_machine" }
      ],
      disconfirmingEvidence: [],
      evidenceThatWouldChangeConfidence: [
        `Endpoint returning 403/401 would indicate auth is in place`,
        `Endpoint returning sensitive data would confirm the hypothesis`
      ],
      verificationSteps: [
        { order: 1, action: `Access ${artifact.url} and analyze response`, expectedOutcome: "Determine if sensitive content is exposed", riskLevel: "safe" },
        { order: 2, action: `Check authentication requirements on the endpoint`, expectedOutcome: "Verify if auth is required", riskLevel: "safe" }
      ],
      estimatedEffort: "minutes",
      potentialSeverity: severity,
      potentialBountyRange: { ...bountyRange, currency: "USD" },
      chainPotential: findChainOpportunities(vulnClass),
      duplicateLikelihood: "low",
      tags: ["historical", artifact.type, vulnClass, severity],
      generatedAt: Date.now()
    });
  }
  return hypotheses;
}
function generateSubdomainHypotheses(recon) {
  const hypotheses = [];
  const takoverPatterns = [
    /\.s3\.amazonaws\.com$/i,
    /\.cloudfront\.net$/i,
    /\.herokuapp\.com$/i,
    /\.azurewebsites\.net$/i,
    /\.ghost\.io$/i,
    /\.surge\.sh$/i,
    /\.bitbucket\.io$/i,
    /\.github\.io$/i,
    /\.shopify\.com$/i,
    /\.fastly\.net$/i,
    /\.pantheon\.io$/i,
    /\.zendesk\.com$/i,
    /\.readme\.io$/i
  ];
  const certSubdomains = recon.certificates?.altNames || [];
  const allSubdomains = [.../* @__PURE__ */ new Set([...recon.subdomains, ...certSubdomains])];
  if (allSubdomains.length > 20) {
    hypotheses.push({
      id: generateHypothesisId(),
      vulnClass: "subdomain_takeover",
      title: "Potential subdomain takeover across large subdomain surface",
      description: `${allSubdomains.length} subdomains detected \u2014 large surface increases takeover probability`,
      affectedEndpoint: recon.targetDomain,
      confidence: "low",
      confidenceScore: 0.25,
      reasoning: [
        `${allSubdomains.length} subdomains enumerated for ${recon.targetDomain}`,
        "Large subdomain surfaces statistically have higher rates of dangling DNS records",
        "Each subdomain should be checked for CNAME records pointing to unclaimed services"
      ],
      supportingEvidence: [
        { type: "endpoint_pattern", description: `${allSubdomains.length} subdomains detected`, strength: "weak", source: "subdomain_enumeration" }
      ],
      disconfirmingEvidence: [],
      evidenceThatWouldChangeConfidence: [
        "Finding a CNAME pointing to an unclaimed service would significantly increase confidence",
        "All subdomains resolving to active services would decrease confidence"
      ],
      verificationSteps: [
        { order: 1, action: "Check DNS CNAME records for all subdomains", tool: "dig/nslookup", expectedOutcome: "Identify dangling CNAMEs", riskLevel: "safe" },
        { order: 2, action: "Verify unclaimed service endpoints", expectedOutcome: "Confirm takeover possibility", riskLevel: "safe" }
      ],
      estimatedEffort: "hours",
      potentialSeverity: "medium",
      potentialBountyRange: { min: 250, max: 3e3, currency: "USD" },
      chainPotential: findChainOpportunities("subdomain_takeover"),
      duplicateLikelihood: "medium",
      tags: ["subdomain", "takeover", "dns"],
      generatedAt: Date.now()
    });
  }
  return hypotheses;
}
function scoreToLevel(score) {
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  if (score >= 0.2) return "low";
  return "speculative";
}
function getToolForVulnClass(vulnClass) {
  const toolMap = {
    xss_reflected: "Burp Suite / XSS Hunter",
    xss_stored: "Burp Suite / XSS Hunter",
    xss_dom: "Browser DevTools / DOM Invader",
    sqli_classic: "SQLMap",
    sqli_blind: "SQLMap",
    sqli_time_based: "SQLMap",
    ssrf: "Burp Collaborator",
    ssrf_blind: "Burp Collaborator",
    idor: "Burp Suite Autorize",
    path_traversal: "Burp Suite / ffuf",
    lfi: "Burp Suite / ffuf",
    open_redirect: "Manual testing",
    cors_misconfiguration: "curl / Burp Suite",
    jwt_weakness: "jwt_tool / Burp JWT plugin",
    graphql_introspection: "GraphQL Voyager / InQL",
    subdomain_takeover: "subjack / nuclei",
    http_request_smuggling: "Burp HTTP Request Smuggler",
    ssti: "tplmap"
  };
  return toolMap[vulnClass] || "Manual testing / Burp Suite";
}
function findChainOpportunities(vulnClass) {
  return CHAIN_PATTERNS.filter((c) => c.fromVulnClass === vulnClass || c.toVulnClass === vulnClass);
}
function estimateDuplicateLikelihood(vulnClass, technology) {
  const highDuplicatePatterns = [
    { tech: /wordpress/i, vulns: ["sqli_classic", "xss_stored", "auth_bypass"] },
    { tech: /spring/i, vulns: ["info_disclosure", "ssrf"] },
    { tech: /graphql/i, vulns: ["graphql_introspection"] },
    { tech: /aws|s3/i, vulns: ["sensitive_data_exposure"] }
  ];
  for (const pattern of highDuplicatePatterns) {
    if (pattern.tech.test(technology) && pattern.vulns.includes(vulnClass)) {
      return "high";
    }
  }
  if (["info_disclosure", "open_redirect", "cors_misconfiguration"].includes(vulnClass)) {
    return "medium";
  }
  return "low";
}
function deduplicateHypotheses(hypotheses) {
  const seen = /* @__PURE__ */ new Map();
  for (const h of hypotheses) {
    const key = `${h.vulnClass}:${h.affectedEndpoint}`;
    const existing = seen.get(key);
    if (!existing || h.confidenceScore > existing.confidenceScore) {
      seen.set(key, h);
    }
  }
  return Array.from(seen.values());
}
function rankHypotheses(hypotheses) {
  return hypotheses.sort((a, b) => {
    const confDiff = b.confidenceScore - a.confidenceScore;
    if (Math.abs(confDiff) > 0.1) return confDiff;
    const sevOrder = { critical: 5, high: 4, medium: 3, low: 2, none: 1 };
    const sevDiff = (sevOrder[b.potentialSeverity] || 0) - (sevOrder[a.potentialSeverity] || 0);
    if (sevDiff !== 0) return sevDiff;
    const dupOrder = { low: 3, medium: 2, high: 1 };
    const dupDiff = (dupOrder[b.duplicateLikelihood] || 0) - (dupOrder[a.duplicateLikelihood] || 0);
    if (dupDiff !== 0) return dupDiff;
    const effortOrder = { minutes: 3, hours: 2, days: 1 };
    return (effortOrder[b.estimatedEffort] || 0) - (effortOrder[a.estimatedEffort] || 0);
  });
}
function generateHypotheses(recon) {
  const reconQuality = assessReconQuality(recon);
  const techHypotheses = generateTechStackHypotheses(recon);
  const configHypotheses = generateConfigAnomalyHypotheses(recon);
  const historicalHypotheses = generateHistoricalHypotheses(recon);
  const subdomainHypotheses = generateSubdomainHypotheses(recon);
  const allHypotheses = [
    ...techHypotheses,
    ...configHypotheses,
    ...historicalHypotheses,
    ...subdomainHypotheses
  ];
  const deduped = deduplicateHypotheses(allHypotheses);
  const ranked = rankHypotheses(deduped);
  const byConfidence = { high: 0, medium: 0, low: 0, speculative: 0 };
  const bySeverity = {};
  const byVulnClass = {};
  for (const h of ranked) {
    byConfidence[h.confidence]++;
    bySeverity[h.potentialSeverity] = (bySeverity[h.potentialSeverity] || 0) + 1;
    byVulnClass[h.vulnClass] = (byVulnClass[h.vulnClass] || 0) + 1;
  }
  const allChains = ranked.flatMap((h) => h.chainPotential);
  const uniqueChains = allChains.filter(
    (c, i) => allChains.findIndex((x) => x.fromVulnClass === c.fromVulnClass && x.toVulnClass === c.toVulnClass) === i
  );
  const topChains = uniqueChains.sort((a, b) => b.impactMultiplier - a.impactMultiplier).slice(0, 5);
  const effortMap = { minutes: 0.25, hours: 2, days: 8 };
  const estimatedResearchHours = ranked.reduce((sum, h) => sum + (effortMap[h.estimatedEffort] || 2), 0);
  const endpointCounts = /* @__PURE__ */ new Map();
  for (const h of ranked) {
    endpointCounts.set(h.affectedEndpoint, (endpointCounts.get(h.affectedEndpoint) || 0) + 1);
  }
  const highValueTargets = Array.from(endpointCounts.entries()).filter(([, count]) => count >= 2).sort((a, b) => b[1] - a[1]).map(([endpoint]) => endpoint).slice(0, 10);
  return {
    targetDomain: recon.targetDomain,
    programHandle: recon.programHandle,
    hypotheses: ranked,
    summary: {
      totalHypotheses: ranked.length,
      byConfidence,
      bySeverity,
      byVulnClass,
      topChainOpportunities: topChains,
      estimatedResearchHours,
      highValueTargets
    },
    reconQuality,
    generatedAt: Date.now()
  };
}
function generateProgramAwareHypotheses(recon, programContext) {
  const result = generateHypotheses(recon);
  if (programContext.avgBounty || programContext.maxBounty) {
    for (const h of result.hypotheses) {
      if (h.potentialBountyRange && programContext.maxBounty) {
        const severityMultiplier = { critical: 0.8, high: 0.5, medium: 0.2, low: 0.05 };
        const mult = severityMultiplier[h.potentialSeverity] || 0.2;
        h.potentialBountyRange.max = Math.round(programContext.maxBounty * mult);
        h.potentialBountyRange.min = Math.round(h.potentialBountyRange.max * 0.1);
      }
    }
  }
  if (programContext.commonCWEs && programContext.commonCWEs.length > 0) {
    for (const h of result.hypotheses) {
      const cweForVuln = vulnClassToCWE(h.vulnClass);
      if (cweForVuln && programContext.commonCWEs.includes(cweForVuln)) {
        h.confidenceScore = Math.min(h.confidenceScore + 0.1, 0.95);
        h.confidence = scoreToLevel(h.confidenceScore);
        h.reasoning.push(`Program has history of accepting ${cweForVuln} findings \u2014 confidence boosted`);
      }
    }
  }
  return result;
}
function vulnClassToCWE(vulnClass) {
  const mapping = {
    xss_reflected: "CWE-79",
    xss_stored: "CWE-79",
    xss_dom: "CWE-79",
    sqli_classic: "CWE-89",
    sqli_blind: "CWE-89",
    sqli_time_based: "CWE-89",
    ssrf: "CWE-918",
    ssrf_blind: "CWE-918",
    idor: "CWE-639",
    bola: "CWE-639",
    auth_bypass: "CWE-287",
    broken_auth: "CWE-287",
    rce: "CWE-94",
    command_injection: "CWE-78",
    code_injection: "CWE-94",
    path_traversal: "CWE-22",
    lfi: "CWE-98",
    rfi: "CWE-98",
    open_redirect: "CWE-601",
    csrf: "CWE-352",
    info_disclosure: "CWE-200",
    sensitive_data_exposure: "CWE-200",
    xxe: "CWE-611",
    ssti: "CWE-1336",
    deserialization: "CWE-502",
    subdomain_takeover: "CWE-284",
    cors_misconfiguration: "CWE-942",
    jwt_weakness: "CWE-347",
    privilege_escalation: "CWE-269"
  };
  return mapping[vulnClass] || null;
}
var TECH_VULN_MAPPINGS, CONFIG_VULN_MAPPINGS, CHAIN_PATTERNS, VULN_SEVERITY_MAP, SEVERITY_BOUNTY_RANGES, hypothesisCounter;
var init_bounty_hypothesis_generator = __esm({
  "server/lib/bounty-hypothesis-generator.ts"() {
    TECH_VULN_MAPPINGS = [
      {
        techPattern: /spring\s*boot/i,
        vulnClasses: [
          { vulnClass: "ssrf", baseConfidence: 0.6, reasoning: "Spring Boot actuator endpoints often expose SSRF via /actuator/gateway/routes or /actuator/env", verificationHint: "Check /actuator/* endpoints for exposure" },
          { vulnClass: "rce", baseConfidence: 0.4, versionCondition: (v) => v.startsWith("2.") || v.startsWith("1."), reasoning: "Spring4Shell (CVE-2022-22965) affects Spring Framework \u22645.3.17", verificationHint: "Test class.module.classLoader parameter manipulation" },
          { vulnClass: "info_disclosure", baseConfidence: 0.7, reasoning: "Spring Boot actuator /env, /health, /mappings often leak sensitive config", verificationHint: "Enumerate /actuator/* endpoints" },
          { vulnClass: "deserialization", baseConfidence: 0.35, reasoning: "Spring uses Java serialization in various components", verificationHint: "Check for Java serialization markers in responses" }
        ]
      },
      {
        techPattern: /django/i,
        vulnClasses: [
          { vulnClass: "ssti", baseConfidence: 0.3, reasoning: "Django template injection possible if user input reaches template rendering", verificationHint: "Test {{7*7}} in user-controlled fields" },
          { vulnClass: "sqli_classic", baseConfidence: 0.25, reasoning: "Django ORM is safe by default but raw() queries and extra() are vulnerable", verificationHint: "Look for endpoints with complex filtering/sorting parameters" },
          { vulnClass: "csrf", baseConfidence: 0.4, reasoning: "Django CSRF protection can be misconfigured with @csrf_exempt decorators", verificationHint: "Test state-changing endpoints without CSRF token" },
          { vulnClass: "open_redirect", baseConfidence: 0.5, reasoning: "Django login redirect via ?next= parameter is commonly exploitable", verificationHint: "Test /login?next=//evil.com and /login?next=https://evil.com" }
        ]
      },
      {
        techPattern: /express|node\.?js/i,
        vulnClasses: [
          { vulnClass: "xss_reflected", baseConfidence: 0.5, reasoning: "Express apps often reflect user input without sanitization", verificationHint: "Test query parameters and path segments for reflection" },
          { vulnClass: "ssrf", baseConfidence: 0.4, reasoning: "Node.js HTTP client libraries often follow redirects and resolve internal IPs", verificationHint: "Test URL parameters with internal IP addresses" },
          { vulnClass: "path_traversal", baseConfidence: 0.35, reasoning: "Express static file serving and path.join can be bypassed", verificationHint: "Test ../ sequences in file download/upload endpoints" },
          { vulnClass: "deserialization", baseConfidence: 0.3, reasoning: "node-serialize and similar libraries have known RCE via deserialization", verificationHint: "Check for serialized object handling in cookies or parameters" },
          { vulnClass: "api_mass_assignment", baseConfidence: 0.5, reasoning: "Express/Node APIs commonly accept full JSON bodies without field filtering", verificationHint: "Add extra fields (role, isAdmin, balance) to POST/PUT requests" }
        ]
      },
      {
        techPattern: /wordpress/i,
        vulnClasses: [
          { vulnClass: "sqli_classic", baseConfidence: 0.5, reasoning: "WordPress plugins frequently have SQL injection in custom queries", verificationHint: "Enumerate plugins via /wp-content/plugins/ and check for known vulns" },
          { vulnClass: "xss_stored", baseConfidence: 0.5, reasoning: "WordPress comment forms and plugin inputs often lack proper sanitization", verificationHint: "Test comment forms, custom fields, and plugin-specific inputs" },
          { vulnClass: "auth_bypass", baseConfidence: 0.35, reasoning: "WordPress REST API and XML-RPC can expose auth bypass vectors", verificationHint: "Test /wp-json/wp/v2/users and xmlrpc.php" },
          { vulnClass: "rfi", baseConfidence: 0.3, reasoning: "WordPress themes and plugins may include remote files", verificationHint: "Check for file inclusion parameters in plugin URLs" },
          { vulnClass: "privilege_escalation", baseConfidence: 0.4, reasoning: "WordPress role management plugins often have privilege escalation bugs", verificationHint: "Test user registration with elevated role parameters" }
        ]
      },
      {
        techPattern: /laravel|php/i,
        vulnClasses: [
          { vulnClass: "sqli_classic", baseConfidence: 0.35, reasoning: "Laravel Eloquent is safe by default but raw queries and whereRaw are vulnerable", verificationHint: "Test complex filter/sort parameters for SQL injection" },
          { vulnClass: "rce", baseConfidence: 0.3, reasoning: "PHP deserialization and eval-based template engines can lead to RCE", verificationHint: "Check for PHP object injection in cookies and parameters" },
          { vulnClass: "lfi", baseConfidence: 0.45, reasoning: "PHP include/require with user-controlled paths is a classic vulnerability", verificationHint: "Test file parameters with php://filter and ../ sequences" },
          { vulnClass: "info_disclosure", baseConfidence: 0.6, reasoning: "Laravel debug mode (APP_DEBUG=true) leaks environment variables and stack traces", verificationHint: "Trigger errors and check for Whoops/Ignition debug pages" },
          { vulnClass: "ssti", baseConfidence: 0.3, reasoning: "Blade templates can be exploited if user input reaches template compilation", verificationHint: "Test {{}} and {!! !!} injection in user-controlled fields" }
        ]
      },
      {
        techPattern: /react|angular|vue/i,
        vulnClasses: [
          { vulnClass: "xss_dom", baseConfidence: 0.45, reasoning: "SPA frameworks can have DOM XSS via dangerouslySetInnerHTML, v-html, or [innerHTML]", verificationHint: "Check for innerHTML usage in client-side JavaScript" },
          { vulnClass: "open_redirect", baseConfidence: 0.4, reasoning: "Client-side routing can be manipulated for open redirects", verificationHint: "Test redirect parameters and hash-based routing" },
          { vulnClass: "sensitive_data_exposure", baseConfidence: 0.5, reasoning: "SPAs often embed API keys, tokens, or internal URLs in JavaScript bundles", verificationHint: "Analyze JavaScript bundles for hardcoded secrets" },
          { vulnClass: "cors_misconfiguration", baseConfidence: 0.4, reasoning: "SPA backends often have overly permissive CORS to support the frontend", verificationHint: "Test Origin header reflection in CORS responses" }
        ]
      },
      {
        techPattern: /graphql/i,
        vulnClasses: [
          { vulnClass: "graphql_introspection", baseConfidence: 0.7, reasoning: "GraphQL introspection is often left enabled in production", verificationHint: "Send introspection query to /graphql endpoint" },
          { vulnClass: "graphql_injection", baseConfidence: 0.4, reasoning: "GraphQL resolvers may have injection vulnerabilities in arguments", verificationHint: "Test query arguments with injection payloads" },
          { vulnClass: "idor", baseConfidence: 0.5, reasoning: "GraphQL queries often expose direct object references via node(id:) patterns", verificationHint: "Enumerate IDs in GraphQL queries across user boundaries" },
          { vulnClass: "info_disclosure", baseConfidence: 0.6, reasoning: "GraphQL error messages often leak schema and resolver details", verificationHint: "Send malformed queries and analyze error responses" }
        ]
      },
      {
        techPattern: /nginx/i,
        vulnClasses: [
          { vulnClass: "path_traversal", baseConfidence: 0.4, reasoning: "Nginx alias misconfiguration allows path traversal when location lacks trailing slash", verificationHint: "Test /location../etc/passwd on alias-configured paths" },
          { vulnClass: "http_request_smuggling", baseConfidence: 0.3, reasoning: "Nginx + backend server combinations can have request smuggling", verificationHint: "Test CL.TE and TE.CL smuggling with Transfer-Encoding variations" },
          { vulnClass: "info_disclosure", baseConfidence: 0.35, reasoning: "Nginx status pages and server tokens leak version information", verificationHint: "Check /nginx_status, /server-status, and Server header" }
        ]
      },
      {
        techPattern: /apache/i,
        vulnClasses: [
          { vulnClass: "path_traversal", baseConfidence: 0.35, reasoning: "Apache path traversal via CVE-2021-41773 and CVE-2021-42013", verificationHint: "Test /cgi-bin/.%2e/.%2e/etc/passwd for Apache 2.4.49-2.4.50" },
          { vulnClass: "ssrf", baseConfidence: 0.3, reasoning: "Apache mod_proxy can be exploited for SSRF", verificationHint: "Test proxy-related headers and URL parameters" },
          { vulnClass: "info_disclosure", baseConfidence: 0.4, reasoning: "Apache server-status and server-info pages leak internal details", verificationHint: "Check /server-status and /server-info endpoints" }
        ]
      },
      {
        techPattern: /jwt|json\s*web\s*token/i,
        vulnClasses: [
          { vulnClass: "jwt_weakness", baseConfidence: 0.6, reasoning: "JWT implementations often have algorithm confusion, weak secrets, or missing validation", verificationHint: "Test alg:none, RS256\u2192HS256 confusion, and brute-force weak secrets" },
          { vulnClass: "auth_bypass", baseConfidence: 0.4, reasoning: "JWT claim manipulation can bypass authorization checks", verificationHint: "Modify JWT claims (role, sub, exp) and test authorization" }
        ]
      },
      {
        techPattern: /aws|s3|cloudfront|lambda/i,
        vulnClasses: [
          { vulnClass: "ssrf", baseConfidence: 0.5, reasoning: "AWS metadata endpoint (169.254.169.254) accessible via SSRF on EC2/Lambda", verificationHint: "Test URL parameters with http://169.254.169.254/latest/meta-data/" },
          { vulnClass: "sensitive_data_exposure", baseConfidence: 0.5, reasoning: "S3 bucket misconfigurations are extremely common", verificationHint: "Check for public S3 buckets and list permissions" },
          { vulnClass: "subdomain_takeover", baseConfidence: 0.35, reasoning: "Dangling CloudFront/S3 CNAMEs enable subdomain takeover", verificationHint: "Check DNS CNAME records for unclaimed S3/CloudFront distributions" }
        ]
      }
    ];
    CONFIG_VULN_MAPPINGS = [
      { category: "cors", pattern: /reflect|wildcard|\*/i, vulnClass: "cors_misconfiguration", confidenceBoost: 0.3, reasoning: "CORS origin reflection or wildcard allows cross-origin attacks" },
      { category: "cors", pattern: /credentials.*true/i, vulnClass: "cors_misconfiguration", confidenceBoost: 0.2, reasoning: "CORS with credentials enabled increases impact of origin misconfiguration" },
      { category: "csp", pattern: /unsafe-inline|unsafe-eval|data:|blob:/i, vulnClass: "csp_bypass", confidenceBoost: 0.25, reasoning: "Weak CSP directives enable XSS bypass" },
      { category: "csp", pattern: /missing|none/i, vulnClass: "xss_reflected", confidenceBoost: 0.2, reasoning: "Missing CSP makes XSS exploitation easier" },
      { category: "headers", pattern: /x-frame-options.*missing/i, vulnClass: "csrf", confidenceBoost: 0.15, reasoning: "Missing X-Frame-Options enables clickjacking" },
      { category: "headers", pattern: /server.*version/i, vulnClass: "info_disclosure", confidenceBoost: 0.1, reasoning: "Server version disclosure aids targeted exploitation" },
      { category: "tls", pattern: /tls\s*1\.[01]|ssl\s*3/i, vulnClass: "sensitive_data_exposure", confidenceBoost: 0.2, reasoning: "Weak TLS versions enable MITM attacks" },
      { category: "auth", pattern: /basic\s*auth|no.*auth/i, vulnClass: "broken_auth", confidenceBoost: 0.25, reasoning: "Basic auth or missing auth on sensitive endpoints" },
      { category: "cache", pattern: /cache.*sensitive|no-store.*missing/i, vulnClass: "sensitive_data_exposure", confidenceBoost: 0.15, reasoning: "Caching sensitive responses enables data leakage" },
      { category: "api_gateway", pattern: /rate.*limit.*missing|throttl.*disabled/i, vulnClass: "business_logic", confidenceBoost: 0.2, reasoning: "Missing rate limiting enables brute force and abuse" }
    ];
    CHAIN_PATTERNS = [
      { fromVulnClass: "info_disclosure", toVulnClass: "ssrf", chainDescription: "Information disclosure reveals internal endpoints \u2192 SSRF to access them", impactMultiplier: 2.5 },
      { fromVulnClass: "info_disclosure", toVulnClass: "auth_bypass", chainDescription: "Leaked credentials or tokens \u2192 authentication bypass", impactMultiplier: 3 },
      { fromVulnClass: "ssrf", toVulnClass: "rce", chainDescription: "SSRF to internal service \u2192 remote code execution via internal API", impactMultiplier: 4 },
      { fromVulnClass: "xss_stored", toVulnClass: "privilege_escalation", chainDescription: "Stored XSS targeting admin \u2192 session hijacking \u2192 privilege escalation", impactMultiplier: 3.5 },
      { fromVulnClass: "idor", toVulnClass: "sensitive_data_exposure", chainDescription: "IDOR on user objects \u2192 mass data exfiltration", impactMultiplier: 2 },
      { fromVulnClass: "sqli_classic", toVulnClass: "rce", chainDescription: "SQL injection \u2192 file write \u2192 web shell \u2192 RCE", impactMultiplier: 4 },
      { fromVulnClass: "open_redirect", toVulnClass: "auth_bypass", chainDescription: "Open redirect in OAuth flow \u2192 token theft \u2192 account takeover", impactMultiplier: 3 },
      { fromVulnClass: "cors_misconfiguration", toVulnClass: "sensitive_data_exposure", chainDescription: "CORS misconfiguration \u2192 cross-origin data theft via authenticated requests", impactMultiplier: 2.5 },
      { fromVulnClass: "jwt_weakness", toVulnClass: "privilege_escalation", chainDescription: "JWT algorithm confusion \u2192 forge admin token \u2192 full privilege escalation", impactMultiplier: 3.5 },
      { fromVulnClass: "path_traversal", toVulnClass: "sensitive_data_exposure", chainDescription: "Path traversal \u2192 read config files \u2192 extract database credentials", impactMultiplier: 2.5 },
      { fromVulnClass: "graphql_introspection", toVulnClass: "idor", chainDescription: "GraphQL schema leak \u2192 discover hidden mutations \u2192 IDOR on sensitive objects", impactMultiplier: 2 },
      { fromVulnClass: "subdomain_takeover", toVulnClass: "xss_stored", chainDescription: "Subdomain takeover \u2192 serve malicious content on trusted domain \u2192 stored XSS equivalent", impactMultiplier: 2.5 },
      { fromVulnClass: "race_condition", toVulnClass: "business_logic", chainDescription: "Race condition on payment/transfer \u2192 double-spend or balance manipulation", impactMultiplier: 3 },
      { fromVulnClass: "csrf", toVulnClass: "privilege_escalation", chainDescription: "CSRF on admin action \u2192 force admin to elevate attacker privileges", impactMultiplier: 2.5 }
    ];
    VULN_SEVERITY_MAP = {
      xss_reflected: "medium",
      xss_stored: "high",
      xss_dom: "medium",
      sqli_classic: "critical",
      sqli_blind: "high",
      sqli_time_based: "high",
      ssrf: "high",
      ssrf_blind: "medium",
      idor: "high",
      bola: "high",
      auth_bypass: "critical",
      broken_auth: "high",
      session_fixation: "medium",
      rce: "critical",
      command_injection: "critical",
      code_injection: "critical",
      path_traversal: "high",
      lfi: "high",
      rfi: "critical",
      open_redirect: "low",
      csrf: "medium",
      info_disclosure: "low",
      sensitive_data_exposure: "high",
      xxe: "high",
      ssti: "high",
      deserialization: "critical",
      race_condition: "medium",
      subdomain_takeover: "medium",
      cors_misconfiguration: "medium",
      csp_bypass: "low",
      jwt_weakness: "high",
      graphql_introspection: "low",
      graphql_injection: "high",
      api_mass_assignment: "high",
      business_logic: "medium",
      privilege_escalation: "critical",
      cache_poisoning: "high",
      http_request_smuggling: "high",
      websocket_hijacking: "medium"
    };
    SEVERITY_BOUNTY_RANGES = {
      critical: { min: 5e3, max: 5e4 },
      high: { min: 1e3, max: 15e3 },
      medium: { min: 250, max: 3e3 },
      low: { min: 50, max: 500 },
      none: { min: 0, max: 0 }
    };
    hypothesisCounter = 0;
  }
});

export {
  generateHypotheses,
  generateProgramAwareHypotheses,
  bounty_hypothesis_generator_exports,
  init_bounty_hypothesis_generator
};
