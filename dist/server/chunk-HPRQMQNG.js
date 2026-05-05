import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/context-aware-scanner.ts
var context_aware_scanner_exports = {};
__export(context_aware_scanner_exports, {
  buildTargetProfileContext: () => buildTargetProfileContext,
  classifyAssetRole: () => classifyAssetRole,
  detectCDN: () => detectCDN,
  detectWAF: () => detectWAF,
  generateScanStrategy: () => generateScanStrategy,
  getDefaultScopeConstraints: () => getDefaultScopeConstraints,
  selectEvasionProfile: () => selectEvasionProfile
});
function detectWAF(responseHeaders, cookies, responseBody, statusCode) {
  const headersLower = Object.fromEntries(
    Object.entries(responseHeaders).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );
  const cookiesLower = cookies.map((c) => c.toLowerCase());
  const bodyLower = responseBody.toLowerCase();
  let bestMatch = null;
  for (const [vendor, sig] of Object.entries(WAF_SIGNATURES)) {
    let score = 0;
    for (const h of sig.headers) {
      const [key, val] = h.includes(":") ? h.split(": ") : [h, null];
      if (val) {
        if (headersLower[key]?.includes(val)) score += 30;
      } else {
        if (key in headersLower) score += 25;
      }
    }
    for (const c of sig.cookies) {
      if (cookiesLower.some((ck) => ck.includes(c.toLowerCase()))) score += 20;
    }
    for (const p of sig.bodyPatterns) {
      if (bodyLower.includes(p.toLowerCase())) score += 15;
    }
    if (statusCode === 403 || statusCode === 406 || statusCode === 429) {
      score += 10;
    }
    if (!bestMatch || score > bestMatch.score) {
      bestMatch = { vendor, score };
    }
  }
  if (bestMatch && bestMatch.score >= 25) {
    const sig = WAF_SIGNATURES[bestMatch.vendor];
    return {
      detected: true,
      vendor: bestMatch.vendor,
      type: ["cloudflare", "akamai", "aws_waf", "sucuri", "incapsula"].includes(bestMatch.vendor) ? "cloud_waf" : ["f5_bigip", "fortinet"].includes(bestMatch.vendor) ? "appliance_waf" : bestMatch.vendor === "modsecurity" ? "host_waf" : "unknown",
      confidence: Math.min(bestMatch.score, 100),
      detectionMethod: "header_cookie_body_analysis",
      bypassTechniques: sig.bypassTechniques,
      evasionProfile: { ...EVASION_PROFILES.waf_bypass, wafBypassPayloads: sig.bypassTechniques },
      inScope: false,
      // Must be explicitly set by engagement scope
      detectedRules: []
    };
  }
  return {
    detected: false,
    vendor: null,
    type: "unknown",
    confidence: 0,
    detectionMethod: "none",
    bypassTechniques: [],
    evasionProfile: EVASION_PROFILES.moderate,
    inScope: false,
    detectedRules: []
  };
}
function detectCDN(responseHeaders, cnames) {
  const headersLower = Object.fromEntries(
    Object.entries(responseHeaders).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );
  const cnamesLower = cnames.map((c) => c.toLowerCase());
  for (const [provider, sig] of Object.entries(CDN_SIGNATURES)) {
    let headerMatch = false;
    let cnameMatch = false;
    for (const h of sig.headers) {
      const [key, val] = h.includes(":") ? h.split(": ") : [h, null];
      if (val) {
        if (headersLower[key]?.includes(val)) headerMatch = true;
      } else {
        if (key.includes("*")) {
          const prefix = key.replace("*", "");
          if (Object.keys(headersLower).some((k) => k.startsWith(prefix))) headerMatch = true;
        } else {
          if (key in headersLower) headerMatch = true;
        }
      }
    }
    for (const c of sig.cnames) {
      if (cnamesLower.some((cn) => cn.includes(c))) cnameMatch = true;
    }
    if (headerMatch || cnameMatch) {
      const evidence = [];
      if (headerMatch) evidence.push("HTTP response headers match CDN signature");
      if (cnameMatch) evidence.push("DNS CNAME chain points to CDN infrastructure");
      const cdnHeaders = {};
      for (const h of sig.headers) {
        const key = h.includes(":") ? h.split(": ")[0] : h;
        if (!key.includes("*") && headersLower[key]) {
          cdnHeaders[key] = headersLower[key];
        }
      }
      return {
        detected: true,
        provider,
        evidence,
        originIp: null,
        originDiscoveryMethod: null,
        originInScope: false,
        cdnHeaders,
        hasBuiltInWAF: sig.hasBuiltInWAF
      };
    }
  }
  return {
    detected: false,
    provider: null,
    evidence: [],
    originIp: null,
    originDiscoveryMethod: null,
    originInScope: false,
    cdnHeaders: {},
    hasBuiltInWAF: false
  };
}
function classifyAssetRole(fingerprint, openPorts, responseHeaders) {
  const scores = [];
  for (const [role, indicators] of Object.entries(SERVER_ROLE_INDICATORS)) {
    let score = 0;
    const reasons = [];
    if (fingerprint.serverHeader) {
      const serverLower = fingerprint.serverHeader.toLowerCase();
      for (const sh of indicators.serverHeaders) {
        if (serverLower.includes(sh)) {
          score += 30;
          reasons.push(`Server header contains "${sh}"`);
        }
      }
    }
    const portOverlap = openPorts.filter((p) => indicators.ports.includes(p));
    if (portOverlap.length > 0) {
      score += Math.min(portOverlap.length * 5, 20);
      reasons.push(`Open ports match: ${portOverlap.join(", ")}`);
    }
    const headersLower = Object.fromEntries(
      Object.entries(responseHeaders).map(([k, v]) => [k.toLowerCase(), v])
    );
    for (const h of indicators.headers) {
      if (h in headersLower) {
        score += 15;
        reasons.push(`Response header "${h}" present`);
      }
    }
    if (role === "reverse_proxy") {
      const hasForwardHeaders = ["x-forwarded-for", "x-real-ip", "via"].some((h) => h in headersLower);
      const hasProxyServer = fingerprint.serverHeader && /nginx|haproxy|traefik|envoy|caddy/i.test(fingerprint.serverHeader);
      if (hasForwardHeaders && hasProxyServer) {
        score += 25;
        reasons.push("Forwarding headers + proxy server detected");
      }
    }
    if (role === "web_application") {
      if (fingerprint.appFramework) {
        score += 25;
        reasons.push(`Application framework detected: ${fingerprint.appFramework.name}`);
      }
      if (fingerprint.cms) {
        score += 30;
        reasons.push(`CMS detected: ${fingerprint.cms.name}`);
      }
    }
    scores.push({ role, score, reasons });
  }
  scores.sort((a, b) => b.score - a.score);
  const best = scores[0];
  if (best.score >= 20) {
    return {
      role: best.role,
      confidence: Math.min(best.score, 100),
      rationale: best.reasons.join("; ")
    };
  }
  return { role: "unknown", confidence: 0, rationale: "No strong indicators matched" };
}
function selectEvasionProfile(waf, cdn, firewall, scopeConstraints) {
  let profile;
  if (waf.detected && scopeConstraints.wafBypassAuthorized) {
    profile = { ...waf.evasionProfile };
  } else if (waf.detected) {
    profile = { ...EVASION_PROFILES.stealth };
  } else if (cdn.detected) {
    profile = { ...EVASION_PROFILES.moderate, rateLimit: 3, delayMs: 800 };
  } else if (firewall.rateLimiting.detected) {
    const maxRate = firewall.rateLimiting.requestsPerSecond || 5;
    profile = { ...EVASION_PROFILES.moderate, rateLimit: Math.max(1, maxRate - 2) };
  } else {
    profile = { ...EVASION_PROFILES.moderate };
  }
  if (scopeConstraints.maxScanRate > 0) {
    profile.rateLimit = Math.min(profile.rateLimit, scopeConstraints.maxScanRate);
  }
  if (scopeConstraints.sharedInfrastructure) {
    profile.rateLimit = Math.min(profile.rateLimit, 2);
    profile.delayMs = Math.max(profile.delayMs, 1500);
    profile.randomizeOrder = true;
  }
  return profile;
}
function generateScanStrategy(profile) {
  const phases = [];
  const { fingerprint, waf, cdn, firewall, topology, scopeConstraints } = profile;
  phases.push({
    name: "port_discovery",
    tools: [
      { tool: "naabu", flags: `-top-ports 1000 -rate ${Math.min(100, scopeConstraints.maxScanRate * 10 || 100)}`, purpose: "Fast TCP port discovery" }
    ],
    dependsOn: [],
    outputType: "ports",
    requiresApproval: false
  });
  phases.push({
    name: "service_fingerprinting",
    tools: [
      { tool: "nerva", flags: "--target HOST --port DISCOVERED_PORTS", purpose: "Deep service fingerprinting (120+ protocols)" },
      { tool: "httpx", flags: "-td -sc -title -server -ct -cdn -fr -favicon", purpose: "HTTP service probing with tech detection" }
    ],
    dependsOn: ["port_discovery"],
    outputType: "fingerprints",
    requiresApproval: false
  });
  if (topology.services.some((s) => [80, 443, 8080, 8443].includes(s.port))) {
    phases.push({
      name: "boundary_detection",
      tools: [
        { tool: "wafw00f", flags: "-a TARGET_URL", purpose: "WAF fingerprinting and classification" },
        ...waf.detected && scopeConstraints.wafBypassAuthorized ? [{ tool: "nuclei", flags: "-t waf-detect/ -t technologies/", purpose: "WAF rule detection and technology profiling" }] : []
      ],
      dependsOn: ["service_fingerprinting"],
      outputType: "fingerprints",
      requiresApproval: false
    });
  }
  if (topology.services.some((s) => [443, 8443, 993, 995, 465].includes(s.port))) {
    phases.push({
      name: "tls_audit",
      tools: [
        { tool: "testssl", flags: "--quiet --color 0 --jsonfile - TARGET:PORT", purpose: "Comprehensive TLS/SSL configuration audit" }
      ],
      dependsOn: ["service_fingerprinting"],
      outputType: "vulns",
      requiresApproval: false
    });
  }
  const serviceAuditTools = [];
  if (topology.services.some((s) => s.service === "ssh" || s.port === 22)) {
    serviceAuditTools.push({ tool: "ssh-audit", flags: "TARGET:22", purpose: "SSH algorithm strength and CVE detection" });
  }
  if (topology.services.some((s) => s.service === "ftp" || s.port === 21)) {
    serviceAuditTools.push({ tool: "hydra", flags: "-L users.txt -P pass.txt ftp://TARGET", purpose: "FTP credential testing" });
  }
  if (topology.services.some((s) => s.service === "rdp" || s.port === 3389)) {
    serviceAuditTools.push({ tool: "nuclei", flags: "-t network/rdp/ TARGET", purpose: "RDP vulnerability scanning (BlueKeep, DejaBlue)" });
  }
  if (topology.services.some((s) => s.service === "smb" || [139, 445].includes(s.port))) {
    serviceAuditTools.push({ tool: "netexec", flags: "smb TARGET --shares", purpose: "SMB share enumeration and access testing" });
  }
  if (serviceAuditTools.length > 0) {
    phases.push({
      name: "service_audit",
      tools: serviceAuditTools,
      dependsOn: ["service_fingerprinting"],
      outputType: "vulns",
      requiresApproval: false
    });
  }
  const vulnTools = [
    { tool: "nuclei", flags: "-severity critical,high,medium -rate-limit RATE", purpose: "Template-based vulnerability scanning" }
  ];
  if (topology.services.some((s) => [80, 443, 8080, 8443].includes(s.port))) {
    vulnTools.push({ tool: "zap", flags: "active-scan TARGET_URL", purpose: "DAST scanning with full request/response evidence" });
    vulnTools.push({ tool: "katana", flags: "-u TARGET_URL -d 3 -jc", purpose: "JavaScript-aware web crawling for endpoint discovery" });
  }
  phases.push({
    name: "vulnerability_scanning",
    tools: vulnTools,
    dependsOn: ["service_fingerprinting", ...phases.some((p) => p.name === "boundary_detection") ? ["boundary_detection"] : []],
    outputType: "vulns",
    requiresApproval: false
  });
  if (scopeConstraints.bruteForceAuthorized) {
    const credTools = [];
    if (topology.services.some((s) => s.service === "ssh" || s.port === 22)) {
      credTools.push({ tool: "hydra", flags: "-L users.txt -P pass.txt ssh://TARGET -t 4", purpose: "SSH credential testing" });
    }
    if (topology.services.some((s) => [80, 443].includes(s.port))) {
      credTools.push({ tool: "hydra", flags: "-L users.txt -P pass.txt http-post-form://TARGET", purpose: "Web login credential testing" });
    }
    if (credTools.length > 0) {
      phases.push({
        name: "credential_testing",
        tools: credTools,
        dependsOn: ["vulnerability_scanning"],
        outputType: "credentials",
        requiresApproval: true
      });
    }
  }
  const estimatedTimeMinutes = phases.reduce((total, phase) => {
    return total + phase.tools.length * 5;
  }, 0);
  const evasionProfile = selectEvasionProfile(waf, cdn, firewall, scopeConstraints);
  return {
    name: `${profile.environment}_${waf.detected ? "waf_aware" : "standard"}_scan`,
    phases,
    evasionProfile,
    estimatedTimeMinutes,
    riskLevel: scopeConstraints.bruteForceAuthorized ? "high" : waf.detected ? "medium" : "low",
    rationale: buildStrategyRationale(profile)
  };
}
function buildStrategyRationale(profile) {
  const parts = [];
  parts.push(`Target classified as ${profile.topology.role} in ${profile.environment} environment.`);
  if (profile.waf.detected) {
    parts.push(`WAF detected: ${profile.waf.vendor} (${profile.waf.type}, ${profile.waf.confidence}% confidence). ${profile.scopeConstraints.wafBypassAuthorized ? "WAF bypass testing authorized." : "WAF bypass NOT authorized \u2014 using stealth approach."}`);
  }
  if (profile.cdn.detected) {
    parts.push(`CDN detected: ${profile.cdn.provider}. ${profile.cdn.originIp ? `Origin IP discovered: ${profile.cdn.originIp}` : "Origin IP not yet discovered."} ${profile.cdn.hasBuiltInWAF ? "CDN includes built-in WAF." : ""}`);
  }
  if (profile.firewall.rateLimiting.detected) {
    parts.push(`Rate limiting detected: ~${profile.firewall.rateLimiting.requestsPerSecond} req/s. Scan rate adjusted accordingly.`);
  }
  if (profile.scopeConstraints.sharedInfrastructure) {
    parts.push("CAUTION: Shared infrastructure detected \u2014 using conservative scan rates to avoid impacting other tenants.");
  }
  if (profile.fingerprint.appFramework) {
    parts.push(`Application framework: ${profile.fingerprint.appFramework.name} (${profile.fingerprint.appFramework.language}).`);
  }
  if (profile.fingerprint.cms) {
    parts.push(`CMS: ${profile.fingerprint.cms.name}${profile.fingerprint.cms.version ? ` v${profile.fingerprint.cms.version}` : ""}.`);
  }
  return parts.join(" ");
}
function buildTargetProfileContext(profile) {
  const lines = [];
  lines.push("## Target Profile");
  lines.push(`- **Host:** ${profile.hostname} (${profile.ips.join(", ")})`);
  lines.push(`- **Role:** ${profile.topology.role} (${profile.topology.confidence}% confidence)`);
  lines.push(`- **Environment:** ${profile.environment}`);
  lines.push(`- **Risk Profile:** ${profile.riskProfile}`);
  if (profile.fingerprint.webServer) {
    const ws = profile.fingerprint.webServer;
    lines.push(`- **Web Server:** ${ws.name}${ws.version ? ` v${ws.version}` : ""} (role: ${ws.role})`);
  }
  if (profile.fingerprint.appFramework) {
    const af = profile.fingerprint.appFramework;
    lines.push(`- **App Framework:** ${af.name}${af.version ? ` v${af.version}` : ""} (${af.language})`);
  }
  if (profile.fingerprint.cms) {
    lines.push(`- **CMS:** ${profile.fingerprint.cms.name}${profile.fingerprint.cms.version ? ` v${profile.fingerprint.cms.version}` : ""}`);
  }
  if (profile.fingerprint.techTags.length > 0) {
    lines.push(`- **Technologies:** ${profile.fingerprint.techTags.join(", ")}`);
  }
  if (Object.keys(profile.fingerprint.serviceBanners).length > 0) {
    lines.push("\n### Discovered Services");
    for (const [port, svc] of Object.entries(profile.fingerprint.serviceBanners)) {
      lines.push(`- Port ${port}: ${svc.service}${svc.version ? ` v${svc.version}` : ""}${svc.banner ? ` \u2014 "${svc.banner}"` : ""}`);
    }
  }
  if (profile.waf.detected) {
    lines.push("\n### WAF Detection");
    lines.push(`- **Vendor:** ${profile.waf.vendor} (${profile.waf.type})`);
    lines.push(`- **Confidence:** ${profile.waf.confidence}%`);
    lines.push(`- **In Scope:** ${profile.waf.inScope ? "YES" : "NO"}`);
    if (profile.waf.bypassTechniques.length > 0) {
      lines.push("- **Known Bypass Techniques:**");
      for (const t of profile.waf.bypassTechniques.slice(0, 5)) {
        lines.push(`  - ${t}`);
      }
    }
  }
  if (profile.cdn.detected) {
    lines.push("\n### CDN Detection");
    lines.push(`- **Provider:** ${profile.cdn.provider}`);
    lines.push(`- **Origin IP:** ${profile.cdn.originIp || "Not discovered"}`);
    lines.push(`- **Built-in WAF:** ${profile.cdn.hasBuiltInWAF ? "Yes" : "No"}`);
    lines.push(`- **Origin In Scope:** ${profile.cdn.originInScope ? "YES" : "NO"}`);
  }
  lines.push("\n### Scope Constraints");
  lines.push(`- WAF Bypass: ${profile.scopeConstraints.wafBypassAuthorized ? "Authorized" : "NOT Authorized"}`);
  lines.push(`- Brute Force: ${profile.scopeConstraints.bruteForceAuthorized ? "Authorized" : "NOT Authorized"}`);
  lines.push(`- Max Scan Rate: ${profile.scopeConstraints.maxScanRate} req/s`);
  lines.push(`- Engagement Type: ${profile.scopeConstraints.engagementType}`);
  if (profile.scopeConstraints.sharedInfrastructure) {
    lines.push("- \u26A0\uFE0F SHARED INFRASTRUCTURE \u2014 use conservative scan rates");
  }
  lines.push("\n### Recommended Strategy");
  lines.push(`- **Name:** ${profile.recommendedStrategy.name}`);
  lines.push(`- **Risk Level:** ${profile.recommendedStrategy.riskLevel}`);
  lines.push(`- **Estimated Time:** ${profile.recommendedStrategy.estimatedTimeMinutes} minutes`);
  lines.push(`- **Evasion Profile:** ${profile.recommendedStrategy.evasionProfile.name} (${profile.recommendedStrategy.evasionProfile.rateLimit} req/s)`);
  lines.push(`- **Rationale:** ${profile.recommendedStrategy.rationale}`);
  lines.push("\n### Scan Phases");
  for (const phase of profile.recommendedStrategy.phases) {
    lines.push(`
**${phase.name}**${phase.requiresApproval ? " \u26A0\uFE0F REQUIRES APPROVAL" : ""}`);
    for (const tool of phase.tools) {
      lines.push(`- \`${tool.tool} ${tool.flags}\` \u2014 ${tool.purpose}`);
    }
  }
  return lines.join("\n");
}
function getDefaultScopeConstraints(engagementType) {
  switch (engagementType) {
    case "pentest":
      return {
        wafBypassAuthorized: true,
        cdnOriginAuthorized: true,
        bruteForceAuthorized: true,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 10,
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "pentest"
      };
    case "red_team":
      return {
        wafBypassAuthorized: true,
        cdnOriginAuthorized: true,
        bruteForceAuthorized: true,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: true,
        maxScanRate: 5,
        // Lower rate for stealth
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "red_team"
      };
    case "vuln_assessment":
      return {
        wafBypassAuthorized: false,
        cdnOriginAuthorized: false,
        bruteForceAuthorized: false,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 20,
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "vuln_assessment"
      };
    case "bug_bounty":
      return {
        wafBypassAuthorized: false,
        cdnOriginAuthorized: false,
        bruteForceAuthorized: false,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 3,
        // Very conservative
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: true,
        // Assume shared by default
        engagementType: "bug_bounty"
      };
  }
}
var WAF_SIGNATURES, CDN_SIGNATURES, SERVER_ROLE_INDICATORS, EVASION_PROFILES;
var init_context_aware_scanner = __esm({
  "server/lib/context-aware-scanner.ts"() {
    WAF_SIGNATURES = {
      cloudflare: {
        headers: ["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
        cookies: ["__cfduid", "__cf_bm", "cf_clearance"],
        bodyPatterns: ["Attention Required! | Cloudflare", "cf-error-details", "cloudflare-nginx"],
        bypassTechniques: [
          "Use origin IP directly (find via DNS history, cert transparency, email headers)",
          "Unicode normalization bypass: replace / with \u2044 (U+2044)",
          "Chunked transfer encoding with comment injection",
          "HTTP/2 CONTINUATION frame abuse",
          "Case variation in SQL keywords (SeLeCt, UnIoN)",
          "Double URL encoding for path traversal",
          "JSON content-type with SQL in values",
          "Multipart/form-data boundary manipulation"
        ]
      },
      akamai: {
        headers: ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id", "x-akamai-session-info"],
        cookies: ["akamai_generated_", "AkaSid", "bm_sz", "ak_bmsc", "_abck"],
        bodyPatterns: ["Access Denied", "Reference #", "akamaiedge"],
        bypassTechniques: [
          "Parameter pollution (duplicate params with different values)",
          "HTTP method override headers (X-HTTP-Method-Override)",
          "Null byte injection in parameters",
          "Tab character injection between SQL keywords",
          "Overlong UTF-8 encoding",
          "Request smuggling via CL.TE or TE.CL"
        ]
      },
      aws_waf: {
        headers: ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
        cookies: ["AWSALB", "AWSALBCORS", "aws-waf-token"],
        bodyPatterns: ["403 Forbidden", "Request blocked"],
        bypassTechniques: [
          "Unicode normalization (AWS WAF v1 doesn't normalize)",
          "JSON body with nested objects to bypass regex rules",
          "Multiline payloads in headers",
          "HTTP/2 pseudo-headers manipulation",
          "Alternate IP representation (decimal, hex, octal)"
        ]
      },
      modsecurity: {
        headers: ["server: apache", "server: nginx"],
        cookies: [],
        bodyPatterns: ["ModSecurity", "OWASP_CRS", "SecRule", "mod_security", "Not Acceptable"],
        bypassTechniques: [
          "Identify CRS version (v3.x vs v4.x have different bypass surfaces)",
          "Paranoia level detection (PL1-PL4 have different rule sets)",
          "Comment injection in SQL (/*!50000 SELECT*/)",
          "HPP (HTTP Parameter Pollution) for PHP backends",
          "Alternate function names (CHAR() instead of CHR())",
          "Scientific notation for numeric injection",
          "Case mixing with inline comments"
        ]
      },
      imperva: {
        headers: ["x-iinfo", "x-cdn"],
        cookies: ["incap_ses_", "visid_incap_", "nlbi_"],
        bodyPatterns: ["Incapsula", "incident", "_Incapsula_Resource"],
        bypassTechniques: [
          "Slow-rate attacks (below detection threshold)",
          "Fragment payloads across multiple parameters",
          "Use CNAME uncloaking to find origin",
          "HTTP desync / request smuggling",
          "Alternate encodings (base64 in headers)"
        ]
      },
      f5_bigip: {
        headers: ["server: bigip", "x-cnection"],
        cookies: ["BIGipServer", "TS", "f5_cspm"],
        bodyPatterns: ["The requested URL was rejected", "BIG-IP"],
        bypassTechniques: [
          "HTTP desync via Content-Length / Transfer-Encoding mismatch",
          "Cookie manipulation (BIGipServer cookie reveals backend pool info)",
          "Path normalization differences between F5 and backend",
          "Websocket upgrade bypass"
        ]
      },
      fortinet: {
        headers: ["server: fortiweb"],
        cookies: ["FORTIWAFSID", "cookiesession1"],
        bodyPatterns: ["FortiWeb", "FortiGuard", "fgd_icon"],
        bypassTechniques: [
          "Unicode normalization bypass",
          "Chunked transfer with small chunks",
          "HTTP/2 multiplexing to bypass rate limits",
          "Path traversal via backslash on Windows backends"
        ]
      },
      sucuri: {
        headers: ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        cookies: ["sucuri_cloudproxy_uuid"],
        bodyPatterns: ["Sucuri WebSite Firewall", "Access Denied - Sucuri", "sucuri.net"],
        bypassTechniques: [
          "Find origin via DNS history (SecurityTrails, ViewDNS)",
          "Email header analysis for origin IP",
          "Subdomain enumeration for unprotected subdomains",
          "HTTP method switching (POST instead of GET)"
        ]
      }
    };
    CDN_SIGNATURES = {
      cloudflare: {
        headers: ["cf-ray", "cf-cache-status"],
        cnames: ["cdn.cloudflare.net", "cloudflare.com"],
        hasBuiltInWAF: true
      },
      akamai: {
        headers: ["x-akamai-transformed", "akamai-grn"],
        cnames: ["akamaiedge.net", "akamai.net", "edgesuite.net", "edgekey.net"],
        hasBuiltInWAF: true
      },
      cloudfront: {
        headers: ["x-amz-cf-id", "x-amz-cf-pop", "via: CloudFront"],
        cnames: ["cloudfront.net", "d1.awsstatic.com"],
        hasBuiltInWAF: false
        // AWS WAF is separate
      },
      fastly: {
        headers: ["x-served-by", "x-cache", "x-timer", "fastly-restarts"],
        cnames: ["fastly.net", "fastlylb.net"],
        hasBuiltInWAF: true
      },
      azure_cdn: {
        headers: ["x-msedge-ref", "x-azure-ref"],
        cnames: ["azureedge.net", "trafficmanager.net", "azure.com"],
        hasBuiltInWAF: false
      },
      google_cloud_cdn: {
        headers: ["via: google", "x-goog-*"],
        cnames: ["googleapis.com", "googleusercontent.com", "1e100.net"],
        hasBuiltInWAF: false
      },
      incapsula: {
        headers: ["x-iinfo", "x-cdn: Incapsula"],
        cnames: ["incapdns.net"],
        hasBuiltInWAF: true
      }
    };
    SERVER_ROLE_INDICATORS = {
      reverse_proxy: {
        serverHeaders: ["nginx", "haproxy", "traefik", "envoy", "caddy", "varnish"],
        ports: [80, 443, 8080, 8443],
        paths: [],
        headers: ["x-forwarded-for", "x-real-ip", "x-forwarded-proto", "via"]
      },
      api_gateway: {
        serverHeaders: ["kong", "tyk", "apigee", "aws-apigateway"],
        ports: [80, 443, 8e3, 8443, 9080],
        paths: ["/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi"],
        headers: ["x-ratelimit-limit", "x-ratelimit-remaining", "x-api-key"]
      },
      load_balancer: {
        serverHeaders: ["awselb", "haproxy", "f5", "citrix", "a10"],
        ports: [80, 443],
        paths: [],
        headers: ["x-forwarded-for", "x-forwarded-port"]
      },
      mail_server: {
        serverHeaders: ["postfix", "exim", "sendmail", "exchange", "dovecot"],
        ports: [25, 110, 143, 465, 587, 993, 995],
        paths: [],
        headers: []
      },
      dns_server: {
        serverHeaders: ["bind", "unbound", "powerdns", "knot"],
        ports: [53],
        paths: [],
        headers: []
      },
      vpn_gateway: {
        serverHeaders: ["openvpn", "strongswan", "wireguard"],
        ports: [500, 1194, 4500, 51820, 1723],
        paths: [],
        headers: []
      },
      bastion_host: {
        serverHeaders: ["openssh"],
        ports: [22, 2222, 3389],
        paths: [],
        headers: []
      },
      database_server: {
        serverHeaders: ["mysql", "postgresql", "mongodb", "redis", "mssql"],
        ports: [3306, 5432, 27017, 6379, 1433, 1521],
        paths: [],
        headers: []
      },
      file_server: {
        serverHeaders: ["samba", "proftpd", "vsftpd", "pure-ftpd"],
        ports: [21, 22, 139, 445, 2049],
        paths: [],
        headers: []
      },
      web_application: {
        serverHeaders: [],
        ports: [80, 443, 8080, 8443, 3e3, 5e3, 8e3],
        paths: ["/login", "/register", "/dashboard", "/admin"],
        headers: ["set-cookie", "x-powered-by"]
      },
      cdn_edge: {
        serverHeaders: ["cloudflare", "akamai", "fastly", "cloudfront"],
        ports: [80, 443],
        paths: [],
        headers: ["cf-ray", "x-cache", "x-amz-cf-id"]
      },
      iot_device: {
        serverHeaders: ["lighttpd", "boa", "goahead", "mini_httpd", "uhttpd"],
        ports: [80, 443, 8080, 23, 8443],
        paths: ["/cgi-bin/", "/HNAP1/"],
        headers: []
      },
      embedded_system: {
        serverHeaders: ["thttpd", "micro_httpd", "busybox"],
        ports: [80, 23, 8080],
        paths: [],
        headers: []
      },
      container_host: {
        serverHeaders: [],
        ports: [2375, 2376, 6443, 10250],
        paths: ["/v2/", "/_catalog"],
        headers: ["docker-distribution-api-version"]
      },
      cloud_service: {
        serverHeaders: [],
        ports: [80, 443],
        paths: [],
        headers: ["x-amzn-requestid", "x-goog-*", "x-ms-request-id"]
      },
      unknown: {
        serverHeaders: [],
        ports: [],
        paths: [],
        headers: []
      }
    };
    EVASION_PROFILES = {
      stealth: {
        name: "Stealth",
        rateLimit: 1,
        delayMs: 2e3,
        randomizeOrder: true,
        userAgentStrategy: "browser_mimic",
        httpMethodPreferences: ["GET", "HEAD"],
        encodingTricks: ["double_url_encode", "unicode_normalize"],
        headerManipulation: {
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Accept-Encoding": "gzip, deflate, br",
          "Connection": "keep-alive",
          "Upgrade-Insecure-Requests": "1"
        },
        chunkedTransfer: false,
        useHttp2: true,
        ipRotation: "none",
        wafBypassPayloads: []
      },
      moderate: {
        name: "Moderate",
        rateLimit: 5,
        delayMs: 500,
        randomizeOrder: true,
        userAgentStrategy: "rotate",
        httpMethodPreferences: ["GET", "POST", "HEAD"],
        encodingTricks: ["url_encode"],
        headerManipulation: {},
        chunkedTransfer: false,
        useHttp2: false,
        ipRotation: "none",
        wafBypassPayloads: []
      },
      aggressive: {
        name: "Aggressive",
        rateLimit: 50,
        delayMs: 50,
        randomizeOrder: false,
        userAgentStrategy: "bot",
        httpMethodPreferences: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        encodingTricks: [],
        headerManipulation: {},
        chunkedTransfer: false,
        useHttp2: false,
        ipRotation: "none",
        wafBypassPayloads: []
      },
      waf_bypass: {
        name: "WAF Bypass",
        rateLimit: 2,
        delayMs: 1500,
        randomizeOrder: true,
        userAgentStrategy: "browser_mimic",
        httpMethodPreferences: ["GET", "POST"],
        encodingTricks: [
          "double_url_encode",
          "unicode_normalize",
          "overlong_utf8",
          "null_byte_inject",
          "case_variation",
          "comment_injection",
          "chunked_split"
        ],
        headerManipulation: {
          "X-Forwarded-For": "127.0.0.1",
          "X-Originating-IP": "127.0.0.1",
          "X-Remote-IP": "127.0.0.1",
          "X-Remote-Addr": "127.0.0.1",
          "X-Custom-IP-Authorization": "127.0.0.1"
        },
        chunkedTransfer: true,
        useHttp2: true,
        ipRotation: "proxy_chain",
        wafBypassPayloads: []
      }
    };
  }
});

export {
  detectWAF,
  detectCDN,
  classifyAssetRole,
  selectEvasionProfile,
  generateScanStrategy,
  buildTargetProfileContext,
  getDefaultScopeConstraints,
  context_aware_scanner_exports,
  init_context_aware_scanner
};
