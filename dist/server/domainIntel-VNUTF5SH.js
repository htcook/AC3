import {
  init_llm_post_enrichment_analysis,
  runPostEnrichmentAnalysis
} from "./chunk-7TUE6QZF.js";
import {
  computeAdjustedRiskScore,
  createAssetOwnershipFilter,
  generateVendorRiskSummary,
  init_managed_provider_filter,
  partitionByOwnership,
  partitionByOwnershipEnhanced
} from "./chunk-T6LEVQYF.js";
import "./chunk-E64FO4YW.js";
import {
  init_passive,
  runPassiveRecon
} from "./chunk-L37LWH3T.js";
import "./chunk-B5ZZBP3X.js";
import "./chunk-NBT7IJMY.js";
import "./chunk-WY62SLRF.js";
import {
  createShodanPostureFindings,
  enrichAssetsWithShodanData,
  init_shodan_verifier,
  isProtocolVersion,
  verifyCvesWithShodanData
} from "./chunk-XM7PLEGG.js";
import {
  discoverOrgDomains,
  init_org_domain_discovery
} from "./chunk-WELUX4DK.js";
import {
  init_cross_module_enrichment,
  runCrossModuleEnrichment
} from "./chunk-54W3LWMR.js";
import {
  init_llm_json_parser,
  safeParseLLMJson
} from "./chunk-UQ7CH3JX.js";
import "./chunk-VCQC5R24.js";
import "./chunk-YWKNEYVH.js";
import {
  init_exploit_matcher,
  matchExploitsToFindings
} from "./chunk-EPISD6GV.js";
import "./chunk-FLABQZEG.js";
import "./chunk-Z4F6I6ND.js";
import {
  init_version_threshold_service,
  version_threshold_service_exports
} from "./chunk-H7YCSXZY.js";
import {
  getAllGroups,
  init_threat_group_knowledge
} from "./chunk-RXZBKY45.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import {
  calculateKevRiskBoost,
  fetchKevCatalog,
  getKevChainSteps,
  init_kev_service,
  matchTechnologiesAgainstKev
} from "./chunk-PFTNS476.js";
import "./chunk-NIB6SN7A.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-2CCDF2QL.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-AX6SVAQZ.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import "./chunk-DQZ564DJ.js";
import {
  __esm,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/waf-ngfw-detection.ts
function detectWafFromResponse(headers, body = "", cookies = "") {
  const detections = [];
  for (const fp of WAF_FINGERPRINTS) {
    let totalWeight = 0;
    const evidence = [];
    for (const sig of fp.headerSignatures) {
      const value = headers[sig.header] || headers[sig.header.toLowerCase()] || "";
      if (sig.pattern.test(value)) {
        totalWeight += sig.weight;
        evidence.push({
          method: "header",
          detail: `Header '${sig.header}' matches ${fp.productName} signature`,
          raw: `${sig.header}: ${value}`
        });
      }
    }
    for (const sig of fp.cookieSignatures) {
      const cookieStr = cookies || headers["set-cookie"] || headers["cookie"] || "";
      if (sig.pattern.test(cookieStr)) {
        totalWeight += sig.weight;
        evidence.push({
          method: "cookie",
          detail: `Cookie matches ${fp.productName} signature`,
          raw: cookieStr.substring(0, 200)
        });
      }
    }
    if (body) {
      for (const sig of fp.bodySignatures) {
        if (sig.pattern.test(body)) {
          totalWeight += sig.weight;
          evidence.push({
            method: "challenge_page",
            detail: `Response body matches ${fp.productName} signature`
          });
        }
      }
    }
    if (totalWeight >= 3) {
      let confidence = "low";
      if (totalWeight >= 10) confidence = "confirmed";
      else if (totalWeight >= 7) confidence = "high";
      else if (totalWeight >= 5) confidence = "medium";
      detections.push({
        vendor: fp.vendor,
        productName: fp.productName,
        confidence,
        evidence,
        capabilities: fp.capabilities,
        bypassDifficulty: fp.bypassDifficulty
      });
    }
  }
  const confOrder = { confirmed: 4, high: 3, medium: 2, low: 1 };
  detections.sort((a, b) => confOrder[b.confidence] - confOrder[a.confidence]);
  return detections;
}
function detectWafFromDns(cnameChain) {
  const detections = [];
  for (const fp of WAF_FINGERPRINTS) {
    for (const cname of cnameChain) {
      for (const pattern of fp.dnsPatterns) {
        if (pattern.test(cname)) {
          detections.push({
            vendor: fp.vendor,
            productName: fp.productName,
            confidence: "high",
            evidence: [{
              method: "dns_cname",
              detail: `DNS CNAME chain includes ${fp.productName} domain`,
              raw: cname
            }],
            capabilities: fp.capabilities,
            bypassDifficulty: fp.bypassDifficulty
          });
        }
      }
    }
  }
  return detections;
}
function detectNgfwFromBanners(banners, certOrgs = [], observedPaths = []) {
  const detections = [];
  for (const fp of NGFW_FINGERPRINTS) {
    const evidence = [];
    let matched = false;
    for (const banner of banners) {
      for (const pattern of fp.bannerPatterns) {
        if (pattern.test(banner)) {
          evidence.push(`Banner match: "${banner.substring(0, 100)}"`);
          matched = true;
        }
      }
    }
    for (const org of certOrgs) {
      for (const pattern of fp.certOrgPatterns) {
        if (pattern.test(org)) {
          evidence.push(`Certificate org match: "${org}"`);
          matched = true;
        }
      }
    }
    for (const path of observedPaths) {
      if (fp.managementPaths.some((mp) => path.includes(mp))) {
        evidence.push(`Management interface detected: "${path}"`);
        matched = true;
      }
    }
    if (matched) {
      detections.push({
        vendor: fp.vendor,
        productName: fp.productName,
        confidence: evidence.length >= 2 ? "high" : "medium",
        evidence,
        capabilities: fp.capabilities
      });
    }
  }
  return detections;
}
function generateScanTuningProfile(wafDetections, ngfwDetections, rateLimitProfile) {
  const primaryWaf = wafDetections[0] || null;
  const primaryNgfw = ngfwDetections[0] || null;
  const hasWaf = wafDetections.length > 0;
  const hasNgfw = ngfwDetections.length > 0;
  const hasRateLimit = rateLimitProfile.detected;
  let aggressiveness = "normal";
  if (hasWaf && primaryWaf?.bypassDifficulty === "very_hard") aggressiveness = "stealth";
  else if (hasWaf && hasNgfw) aggressiveness = "stealth";
  else if (hasWaf || hasNgfw) aggressiveness = "cautious";
  else if (hasRateLimit) aggressiveness = "cautious";
  const scanConfig = generateScanForgeDiscoveryConfig(aggressiveness, primaryWaf, primaryNgfw, rateLimitProfile);
  const nucleiConfig = generateNucleiConfig(aggressiveness, primaryWaf, rateLimitProfile);
  const evasion = generateEvasionTechniques(aggressiveness, primaryWaf, primaryNgfw);
  const wafBypasses = [];
  for (const waf of wafDetections) {
    const vendorBypasses = WAF_BYPASS_DB[waf.vendor] || WAF_BYPASS_DB.unknown_waf;
    wafBypasses.push(...vendorBypasses);
  }
  const warnings = [];
  if (hasWaf && primaryWaf?.capabilities.rateLimiting) {
    warnings.push(`${primaryWaf.productName} has rate limiting \u2014 aggressive scanning will trigger blocks.`);
  }
  if (hasWaf && primaryWaf?.capabilities.ipReputation) {
    warnings.push(`${primaryWaf.productName} uses IP reputation \u2014 scanning from known scanner IPs may be blocked immediately.`);
  }
  if (hasNgfw && primaryNgfw?.capabilities.deepPacketInspection) {
    warnings.push(`${primaryNgfw.productName} performs DPI \u2014 encrypted payloads may be inspected if SSL decryption is enabled.`);
  }
  if (hasNgfw && primaryNgfw?.capabilities.ipsIdsIntegrated) {
    warnings.push(`${primaryNgfw.productName} has integrated IPS \u2014 ScanForge Discovery scripts and aggressive probes may trigger alerts.`);
  }
  const wafNames = wafDetections.map((w) => w.productName).join(", ");
  const ngfwNames = ngfwDetections.map((n) => n.productName).join(", ");
  let summary = `Scan tuning profile: ${aggressiveness.toUpperCase()} mode.`;
  if (hasWaf) summary += ` WAF detected: ${wafNames}.`;
  if (hasNgfw) summary += ` NGFW detected: ${ngfwNames}.`;
  if (hasRateLimit) summary += ` Rate limiting active (${rateLimitProfile.requestsPerSecond || "unknown"} req/s).`;
  if (!hasWaf && !hasNgfw) summary += " No WAF or NGFW detected \u2014 standard scanning parameters apply.";
  return {
    aggressiveness,
    discovery: scanConfig,
    nuclei: nucleiConfig,
    evasion,
    wafBypasses,
    summary,
    warnings
  };
}
function generateScanForgeDiscoveryConfig(aggressiveness, primaryWaf, primaryNgfw, rateLimit) {
  const base = {
    flags: ["-sV", "--version-intensity 5", "-O"],
    scripts: ["default", "vuln", "http-headers"],
    evasionFlags: [],
    maxRetries: 3,
    hostTimeout: "300s",
    scanDelay: "0ms",
    maxRate: 1e3,
    portScanOrder: "sequential",
    fragmentPackets: false,
    decoyScans: false,
    sourcePortRandomize: false,
    rationale: ""
  };
  switch (aggressiveness) {
    case "stealth":
      return {
        ...base,
        timing: "-T1",
        flags: ["-sS", "-sV", "--version-intensity 2", "-Pn"],
        scripts: ["default"],
        evasionFlags: [
          "-f",
          // Fragment packets
          "--mtu 24",
          // Custom MTU for fragmentation
          "--data-length 50",
          // Append random data to packets
          "--randomize-hosts",
          // Randomize target order
          "--spoof-mac 0",
          // Random MAC address
          "-D RND:5",
          // 5 random decoys
          "--source-port 53",
          // Spoof DNS source port
          "--badsum"
          // Send bad checksums (some firewalls pass these)
        ],
        maxRetries: 1,
        hostTimeout: "600s",
        scanDelay: "2000ms",
        maxRate: 10,
        portScanOrder: "random",
        fragmentPackets: true,
        decoyScans: true,
        sourcePortRandomize: true,
        rationale: `Stealth mode: ${primaryWaf?.productName || "WAF"} and/or ${primaryNgfw?.productName || "NGFW"} detected. Using SYN scan with fragmentation, decoys, and slow timing to minimize detection. ScanForge Discovery scripts limited to 'default' only.`
      };
    case "cautious":
      return {
        ...base,
        timing: "-T2",
        flags: ["-sS", "-sV", "--version-intensity 3", "-Pn"],
        scripts: ["default", "http-headers", "ssl-enum-ciphers"],
        evasionFlags: [
          "-f",
          // Fragment packets
          "--randomize-hosts",
          "--data-length 25"
        ],
        maxRetries: 2,
        hostTimeout: "450s",
        scanDelay: rateLimit.detected ? `${Math.max(500, Math.floor(1e3 / (rateLimit.requestsPerSecond || 5)))}ms` : "500ms",
        maxRate: rateLimit.detected ? Math.min(50, (rateLimit.requestsPerSecond || 10) * 2) : 100,
        portScanOrder: "random",
        fragmentPackets: true,
        decoyScans: false,
        sourcePortRandomize: true,
        rationale: `Cautious mode: ${primaryWaf?.productName || primaryNgfw?.productName || "security controls"} detected. Using SYN scan with moderate timing and fragmentation. Rate limited to ${rateLimit.requestsPerSecond || "estimated"} req/s based on detected rate limiting.`
      };
    case "aggressive":
      return {
        ...base,
        timing: "-T4",
        flags: ["-sS", "-sV", "--version-intensity 7", "-O", "--osscan-guess", "-A"],
        scripts: ["default", "vuln", "exploit", "http-headers", "ssl-enum-ciphers", "http-enum"],
        evasionFlags: [],
        maxRetries: 6,
        hostTimeout: "180s",
        scanDelay: "0ms",
        maxRate: 5e3,
        portScanOrder: "sequential",
        fragmentPackets: false,
        decoyScans: false,
        sourcePortRandomize: false,
        rationale: "Aggressive mode: No WAF/NGFW detected. Full-speed scanning with comprehensive version detection, OS fingerprinting, and vulnerability scripts enabled."
      };
    default:
      return {
        ...base,
        timing: "-T3",
        flags: ["-sS", "-sV", "--version-intensity 5", "-O"],
        scripts: ["default", "vuln", "http-headers", "ssl-enum-ciphers"],
        evasionFlags: ["--randomize-hosts"],
        maxRetries: 3,
        hostTimeout: "300s",
        scanDelay: "100ms",
        maxRate: 500,
        portScanOrder: "random",
        fragmentPackets: false,
        decoyScans: false,
        sourcePortRandomize: false,
        rationale: "Normal mode: No significant defensive controls detected. Standard scanning parameters with randomized host order."
      };
  }
}
function generateNucleiConfig(aggressiveness, primaryWaf, rateLimit) {
  const base = {
    templateExclusions: [],
    interactshDisabled: false,
    headless: false,
    customHeaders: {},
    rationale: ""
  };
  switch (aggressiveness) {
    case "stealth":
      return {
        ...base,
        rateLimit: 5,
        bulkSize: 5,
        concurrency: 2,
        timeout: 30,
        retries: 1,
        templateExclusions: [
          "dos",
          "fuzzing",
          "brute-force",
          "sqli-error-based",
          "headless",
          "file-upload",
          "ssrf-detection"
        ],
        interactshDisabled: true,
        headless: false,
        customHeaders: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5"
        },
        rationale: `Stealth mode for ${primaryWaf?.productName || "WAF"}: Very low rate (5 req/s), minimal concurrency, OOB interactions disabled, fuzzing/DoS templates excluded. Using realistic browser User-Agent.`
      };
    case "cautious":
      return {
        ...base,
        rateLimit: rateLimit.detected ? Math.max(10, (rateLimit.requestsPerSecond || 20) / 2) : 25,
        bulkSize: 15,
        concurrency: 5,
        timeout: 20,
        retries: 2,
        templateExclusions: ["dos", "fuzzing", "brute-force"],
        interactshDisabled: false,
        headless: false,
        customHeaders: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
        rationale: `Cautious mode: Rate limited to ${rateLimit.requestsPerSecond ? Math.floor(rateLimit.requestsPerSecond / 2) : 25} req/s. DoS and fuzzing templates excluded. OOB interactions enabled for blind vulnerability detection.`
      };
    case "aggressive":
      return {
        ...base,
        rateLimit: 150,
        bulkSize: 50,
        concurrency: 25,
        timeout: 10,
        retries: 3,
        templateExclusions: [],
        interactshDisabled: false,
        headless: true,
        customHeaders: {},
        rationale: "Aggressive mode: Full-speed scanning with all templates enabled including headless browser checks."
      };
    default:
      return {
        ...base,
        rateLimit: 50,
        bulkSize: 25,
        concurrency: 10,
        timeout: 15,
        retries: 2,
        templateExclusions: ["dos"],
        interactshDisabled: false,
        headless: false,
        customHeaders: {},
        rationale: "Normal mode: Standard scanning parameters. DoS templates excluded as a safety measure."
      };
  }
}
function generateEvasionTechniques(aggressiveness, primaryWaf, primaryNgfw) {
  const techniques = [];
  if (aggressiveness === "stealth" || aggressiveness === "cautious") {
    techniques.push(
      {
        id: "ip_fragmentation",
        name: "IP Fragmentation",
        description: "Split packets into smaller fragments to bypass signature-based detection. Many IDS/IPS struggle to reassemble fragmented packets correctly.",
        applicableTo: ["scanforge-discovery"],
        effectiveness: primaryNgfw?.capabilities.deepPacketInspection ? "low" : "high",
        implementationNote: "Use ScanForge discovery -f or --mtu flags. Note: modern NGFWs with DPI can reassemble fragments."
      },
      {
        id: "timing_evasion",
        name: "Slow Scan Timing",
        description: "Spread scan probes over extended time periods to stay below IDS/IPS detection thresholds.",
        applicableTo: ["scanforge-discovery", "nuclei", "custom"],
        effectiveness: "high",
        implementationNote: "Use masscan --rate0/-T1 or nuclei rate-limit. Add random jitter between requests."
      },
      {
        id: "user_agent_rotation",
        name: "User-Agent Rotation",
        description: "Rotate User-Agent strings to appear as different browsers/devices, avoiding bot detection.",
        applicableTo: ["nuclei", "custom", "burp"],
        effectiveness: primaryWaf?.capabilities.botProtection ? "medium" : "high",
        implementationNote: "Maintain a pool of 50+ real browser User-Agent strings. Rotate per request or per target."
      },
      {
        id: "encoding_bypass",
        name: "Payload Encoding",
        description: "Use URL encoding, double encoding, Unicode normalization, or hex encoding to bypass WAF pattern matching.",
        applicableTo: ["nuclei", "custom", "burp", "sqlmap"],
        effectiveness: "medium",
        implementationNote: "Chain encodings: URL \u2192 double URL \u2192 Unicode. Test each encoding layer independently."
      }
    );
  }
  if (aggressiveness === "stealth") {
    techniques.push(
      {
        id: "decoy_scanning",
        name: "Decoy Scanning",
        description: "Generate traffic from spoofed source IPs alongside real scan traffic to obscure the true scanner.",
        applicableTo: ["scanforge-discovery"],
        effectiveness: primaryNgfw?.capabilities.statefulInspection ? "low" : "medium",
        implementationNote: "Use ScanForge discovery -D RND:5 for 5 random decoys. Requires raw socket access."
      },
      {
        id: "source_port_spoofing",
        name: "Source Port Spoofing",
        description: "Use well-known source ports (53/DNS, 80/HTTP, 443/HTTPS) to bypass firewall rules that allow return traffic from these services.",
        applicableTo: ["scanforge-discovery"],
        effectiveness: "medium",
        implementationNote: "Use ScanForge discovery --source-port 53. Works against poorly configured firewalls."
      },
      {
        id: "ssl_tls_wrapping",
        name: "TLS-Wrapped Scanning",
        description: "Wrap scan traffic in TLS to prevent DPI from inspecting payloads. Effective against NGFWs without SSL decryption.",
        applicableTo: ["custom", "burp"],
        effectiveness: primaryNgfw?.capabilities.sslDecryption ? "low" : "high",
        implementationNote: "Use stunnel or custom TLS wrappers. Check if NGFW performs SSL interception first."
      }
    );
  }
  return {
    techniques,
    encodingStrategies: aggressiveness === "stealth" ? ["url_encode", "double_url_encode", "unicode_normalize", "hex_encode", "base64", "html_entities"] : aggressiveness === "cautious" ? ["url_encode", "double_url_encode", "unicode_normalize"] : ["url_encode"],
    timingStrategies: aggressiveness === "stealth" ? ["random_delay_2s_10s", "exponential_backoff", "time_of_day_variation", "burst_then_pause"] : aggressiveness === "cautious" ? ["random_delay_500ms_2s", "linear_backoff"] : ["no_delay"],
    userAgentRotation: aggressiveness === "stealth" || aggressiveness === "cautious",
    ipRotation: aggressiveness === "stealth",
    headerRandomization: aggressiveness === "stealth"
  };
}
function analyzeRateLimiting(responses) {
  const result = {
    detected: false,
    blockType: "none"
  };
  const rateLimitResponses = responses.filter((r) => r.statusCode === 429);
  if (rateLimitResponses.length > 0) {
    result.detected = true;
    result.blockType = "429_response";
    const rlHeaders = rateLimitResponses[0].headers;
    const limit = parseInt(rlHeaders["x-ratelimit-limit"] || rlHeaders["ratelimit-limit"] || "0");
    const remaining = parseInt(rlHeaders["x-ratelimit-remaining"] || rlHeaders["ratelimit-remaining"] || "0");
    const reset = parseInt(rlHeaders["x-ratelimit-reset"] || rlHeaders["ratelimit-reset"] || "0");
    const retryAfter = parseInt(rlHeaders["retry-after"] || "0");
    if (limit > 0) result.burstLimit = limit;
    if (retryAfter > 0) result.blockDurationSeconds = retryAfter;
    if (reset > 0) {
      const windowMs = reset * 1e3 - Date.now();
      if (windowMs > 0) result.windowSeconds = Math.ceil(windowMs / 1e3);
    }
    if (limit > 0 && result.windowSeconds) {
      result.requestsPerSecond = Math.floor(limit / result.windowSeconds);
    }
  }
  const challengeResponses = responses.filter(
    (r) => r.statusCode === 403 && (r.headers["cf-ray"] || r.headers["server"]?.includes("cloudflare"))
  );
  if (challengeResponses.length > 0 && !result.detected) {
    result.detected = true;
    result.blockType = "captcha";
  }
  const dropResponses = responses.filter((r) => r.statusCode === 0);
  if (dropResponses.length > responses.length * 0.3 && !result.detected) {
    result.detected = true;
    result.blockType = "connection_drop";
  }
  return result;
}
async function runWafNgfwAssessment(domain, options = {}) {
  const start = Date.now();
  const timeout = options.timeout ?? 1e4;
  let headers = {};
  let body = "";
  let cookies = "";
  let challengeDetected = false;
  let blockPageDetected = false;
  const errorSignatures = [];
  try {
    const probeUrls = [
      `https://${domain}/`,
      `https://${domain}/?test=<script>alert(1)</script>`,
      // Trigger WAF block page
      `https://${domain}/wp-admin/`
      // Common admin path
    ];
    for (const url of probeUrls) {
      try {
        const res = await fetch(url, {
          method: "GET",
          signal: AbortSignal.timeout(timeout),
          redirect: "follow",
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/2.0)",
            "Accept": "text/html"
          }
        });
        res.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });
        const setCookie = res.headers.get("set-cookie") || "";
        if (setCookie) cookies += setCookie + "; ";
        const bodyText = await res.text().catch(() => "");
        if (url.includes("<script>") && (res.status === 403 || res.status === 406)) {
          blockPageDetected = true;
          body = bodyText.substring(0, 5e3);
          errorSignatures.push(`WAF block on XSS probe: HTTP ${res.status}`);
        }
        if (res.status === 503 && bodyText.includes("challenge")) {
          challengeDetected = true;
          body = bodyText.substring(0, 5e3);
        }
        if (!body && bodyText) body = bodyText.substring(0, 5e3);
      } catch {
      }
    }
  } catch {
  }
  const wafDetections = detectWafFromResponse(headers, body, cookies);
  if (options.dnsChain && options.dnsChain.length > 0) {
    const dnsWafs = detectWafFromDns(options.dnsChain);
    for (const dnsWaf of dnsWafs) {
      if (!wafDetections.some((w) => w.vendor === dnsWaf.vendor)) {
        wafDetections.push(dnsWaf);
      }
    }
  }
  const ngfwDetections = detectNgfwFromBanners(
    options.shodanBanners || [],
    options.certOrgs || [],
    options.observedPaths || []
  );
  const rateLimitProfile = options.previousResponses ? analyzeRateLimiting(options.previousResponses) : { detected: false, blockType: "none" };
  const scanTuningProfile = generateScanTuningProfile(wafDetections, ngfwDetections, rateLimitProfile);
  let defensivePostureScore = 0;
  if (wafDetections.length > 0) {
    const primaryWaf = wafDetections[0];
    const capCount = Object.values(primaryWaf.capabilities).filter(Boolean).length;
    defensivePostureScore += Math.min(50, capCount * 4);
    if (primaryWaf.bypassDifficulty === "very_hard") defensivePostureScore += 15;
    else if (primaryWaf.bypassDifficulty === "hard") defensivePostureScore += 10;
    else if (primaryWaf.bypassDifficulty === "medium") defensivePostureScore += 5;
  }
  if (ngfwDetections.length > 0) {
    const primaryNgfw = ngfwDetections[0];
    const capCount = Object.values(primaryNgfw.capabilities).filter(Boolean).length;
    defensivePostureScore += Math.min(30, capCount * 4);
  }
  if (rateLimitProfile.detected) defensivePostureScore += 10;
  if (challengeDetected) defensivePostureScore += 5;
  defensivePostureScore = Math.min(100, defensivePostureScore);
  return {
    domain,
    scanTimestamp: Date.now(),
    durationMs: Date.now() - start,
    wafDetections,
    ngfwDetections,
    rateLimitProfile,
    primaryWaf: wafDetections[0] || null,
    primaryNgfw: ngfwDetections[0] || null,
    scanTuningProfile,
    defensivePostureScore,
    rawEvidence: {
      headers,
      dnsChain: options.dnsChain || [],
      challengeDetected,
      blockPageDetected,
      errorSignatures
    }
  };
}
function buildScanForgeDiscoveryCommand(profile, targets, ports = "1-1000") {
  const parts = ["scanforge-discovery"];
  parts.push(profile.discovery.timing);
  parts.push(...profile.discovery.flags);
  parts.push(...profile.discovery.evasionFlags);
  if (profile.discovery.maxRate < 1e3) {
    parts.push(`--max-rate ${profile.discovery.maxRate}`);
  }
  if (profile.discovery.scanDelay !== "0ms") {
    parts.push(`--scan-delay ${profile.discovery.scanDelay}`);
  }
  parts.push(`--host-timeout ${profile.discovery.hostTimeout}`);
  parts.push(`--max-retries ${profile.discovery.maxRetries}`);
  if (profile.discovery.scripts.length > 0) {
    parts.push(`--script=${profile.discovery.scripts.join(",")}`);
  }
  parts.push(`-p ${ports}`);
  parts.push("-oJ discovery_results.json");
  parts.push(...targets);
  return parts.join(" ");
}
function buildNucleiCommand(profile, targets) {
  const parts = ["nuclei"];
  parts.push(`-rl ${profile.nuclei.rateLimit}`);
  parts.push(`-bs ${profile.nuclei.bulkSize}`);
  parts.push(`-c ${profile.nuclei.concurrency}`);
  parts.push(`-timeout ${profile.nuclei.timeout}`);
  parts.push(`-retries ${profile.nuclei.retries}`);
  if (profile.nuclei.templateExclusions.length > 0) {
    parts.push(`-etags ${profile.nuclei.templateExclusions.join(",")}`);
  }
  if (profile.nuclei.interactshDisabled) {
    parts.push("-ni");
  }
  if (profile.nuclei.headless) {
    parts.push("-headless");
  }
  for (const [key, value] of Object.entries(profile.nuclei.customHeaders)) {
    parts.push(`-H "${key}: ${value}"`);
  }
  if (targets.length === 1) {
    parts.push(`-u ${targets[0]}`);
  } else {
    parts.push("-l targets.txt");
  }
  parts.push("-o nuclei_results.json -json");
  return parts.join(" ");
}
var WAF_FINGERPRINTS, NGFW_FINGERPRINTS, WAF_BYPASS_DB;
var init_waf_ngfw_detection = __esm({
  "server/lib/waf-ngfw-detection.ts"() {
    "use strict";
    WAF_FINGERPRINTS = [
      {
        vendor: "cloudflare",
        productName: "Cloudflare WAF",
        headerSignatures: [
          { header: "server", pattern: /cloudflare/i, weight: 3 },
          { header: "cf-ray", pattern: /.+/, weight: 5 },
          { header: "cf-cache-status", pattern: /.+/, weight: 3 },
          { header: "cf-connecting-ip", pattern: /.+/, weight: 2 },
          { header: "cf-request-id", pattern: /.+/, weight: 2 },
          { header: "expect-ct", pattern: /cloudflare/i, weight: 2 }
        ],
        cookieSignatures: [
          { pattern: /__cfduid/i, weight: 3 },
          { pattern: /cf_clearance/i, weight: 4 },
          { pattern: /__cf_bm/i, weight: 3 }
        ],
        bodySignatures: [
          { pattern: /cloudflare/i, weight: 2 },
          { pattern: /cf-browser-verification/i, weight: 4 },
          { pattern: /Attention Required.*Cloudflare/i, weight: 5 },
          { pattern: /ray\s*ID/i, weight: 3 }
        ],
        dnsPatterns: [/\.cloudflare\.com$/i, /\.cloudflare-dns\.com$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: true
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "akamai",
        productName: "Akamai Kona Site Defender",
        headerSignatures: [
          { header: "server", pattern: /akamai/i, weight: 4 },
          { header: "x-akamai-transformed", pattern: /.+/, weight: 5 },
          { header: "x-akamai-request-id", pattern: /.+/, weight: 4 },
          { header: "x-akamai-session-info", pattern: /.+/, weight: 3 },
          { header: "akamai-grn", pattern: /.+/, weight: 3 }
        ],
        cookieSignatures: [
          { pattern: /AkaSid/i, weight: 4 },
          { pattern: /akamai/i, weight: 3 },
          { pattern: /bm_sv/i, weight: 3 }
        ],
        bodySignatures: [
          { pattern: /akamai/i, weight: 2 },
          { pattern: /Access Denied.*akamai/i, weight: 5 },
          { pattern: /Reference #\d+\.\w+/i, weight: 3 }
        ],
        dnsPatterns: [/\.akamai\.net$/i, /\.akamaiedge\.net$/i, /\.akamaized\.net$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: true
        },
        bypassDifficulty: "very_hard"
      },
      {
        vendor: "aws_waf",
        productName: "AWS WAF + CloudFront",
        headerSignatures: [
          { header: "x-amz-cf-id", pattern: /.+/, weight: 4 },
          { header: "x-amz-cf-pop", pattern: /.+/, weight: 3 },
          { header: "x-amzn-waf-action", pattern: /.+/, weight: 5 },
          { header: "server", pattern: /cloudfront/i, weight: 3 },
          { header: "x-amzn-requestid", pattern: /.+/, weight: 2 },
          { header: "x-cache", pattern: /cloudfront/i, weight: 3 }
        ],
        cookieSignatures: [
          { pattern: /AWSALB/i, weight: 3 },
          { pattern: /AWSALBCORS/i, weight: 3 }
        ],
        bodySignatures: [
          { pattern: /Request blocked/i, weight: 2 },
          { pattern: /aws.*waf/i, weight: 4 }
        ],
        dnsPatterns: [/\.cloudfront\.net$/i, /\.amazonaws\.com$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "imperva",
        productName: "Imperva Cloud WAF (Incapsula)",
        headerSignatures: [
          { header: "x-iinfo", pattern: /.+/, weight: 5 },
          { header: "x-cdn", pattern: /incapsula|imperva/i, weight: 5 },
          { header: "x-iinfo", pattern: /\d+-\d+-\d+/i, weight: 3 }
        ],
        cookieSignatures: [
          { pattern: /incap_ses/i, weight: 5 },
          { pattern: /visid_incap/i, weight: 5 },
          { pattern: /nlbi_/i, weight: 3 }
        ],
        bodySignatures: [
          { pattern: /incapsula/i, weight: 4 },
          { pattern: /imperva/i, weight: 3 },
          { pattern: /Request unsuccessful.*Incapsula/i, weight: 5 }
        ],
        dnsPatterns: [/\.incapdns\.net$/i, /\.impervadns\.net$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: true
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "f5_bigip",
        productName: "F5 BIG-IP ASM",
        headerSignatures: [
          { header: "server", pattern: /big-?ip/i, weight: 5 },
          { header: "x-wa-info", pattern: /.+/, weight: 4 },
          { header: "x-cnection", pattern: /close/i, weight: 2 }
        ],
        cookieSignatures: [
          { pattern: /BIGipServer/i, weight: 5 },
          { pattern: /TS[0-9a-f]{8}/i, weight: 3 },
          { pattern: /f5_cspm/i, weight: 4 }
        ],
        bodySignatures: [
          { pattern: /The requested URL was rejected/i, weight: 4 },
          { pattern: /support ID/i, weight: 3 }
        ],
        dnsPatterns: [],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: false,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: false,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "medium"
      },
      {
        vendor: "azure_front_door",
        productName: "Azure Front Door + WAF",
        headerSignatures: [
          { header: "x-azure-ref", pattern: /.+/, weight: 5 },
          { header: "x-fd-healthprobe", pattern: /.+/, weight: 3 },
          { header: "x-ms-ref", pattern: /.+/, weight: 3 },
          { header: "x-azure-requestid", pattern: /.+/, weight: 2 }
        ],
        cookieSignatures: [],
        bodySignatures: [
          { pattern: /azure.*front.*door/i, weight: 4 },
          { pattern: /This request has been blocked/i, weight: 2 }
        ],
        dnsPatterns: [/\.azurefd\.net$/i, /\.azureedge\.net$/i, /\.trafficmanager\.net$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "gcp_cloud_armor",
        productName: "Google Cloud Armor",
        headerSignatures: [
          { header: "via", pattern: /google/i, weight: 2 },
          { header: "server", pattern: /gws|google/i, weight: 2 },
          { header: "x-goog-component", pattern: /.+/, weight: 3 }
        ],
        cookieSignatures: [],
        bodySignatures: [
          { pattern: /cloud armor/i, weight: 5 },
          { pattern: /google cloud/i, weight: 2 }
        ],
        dnsPatterns: [/\.googleusercontent\.com$/i, /\.googleapis\.com$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "sucuri",
        productName: "Sucuri WAF",
        headerSignatures: [
          { header: "server", pattern: /sucuri/i, weight: 5 },
          { header: "x-sucuri-id", pattern: /.+/, weight: 5 },
          { header: "x-sucuri-cache", pattern: /.+/, weight: 3 }
        ],
        cookieSignatures: [
          { pattern: /sucuri/i, weight: 4 }
        ],
        bodySignatures: [
          { pattern: /sucuri/i, weight: 3 },
          { pattern: /Access Denied.*Sucuri/i, weight: 5 }
        ],
        dnsPatterns: [/\.sucuri\.net$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: false,
          customRules: true,
          apiProtection: false,
          challengePages: false
        },
        bypassDifficulty: "medium"
      },
      {
        vendor: "fortiweb",
        productName: "Fortinet FortiWeb",
        headerSignatures: [
          { header: "server", pattern: /fortiweb/i, weight: 5 },
          { header: "x-powered-by", pattern: /fortiweb/i, weight: 4 }
        ],
        cookieSignatures: [
          { pattern: /FORTIWAFSID/i, weight: 5 },
          { pattern: /cookiesession1/i, weight: 2 }
        ],
        bodySignatures: [
          { pattern: /fortinet/i, weight: 3 },
          { pattern: /FortiWeb/i, weight: 5 },
          { pattern: /block.*page.*fortinet/i, weight: 4 }
        ],
        dnsPatterns: [],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: false,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "medium"
      },
      {
        vendor: "barracuda",
        productName: "Barracuda WAF",
        headerSignatures: [
          { header: "server", pattern: /barracuda/i, weight: 5 },
          { header: "barra_counter_session", pattern: /.+/, weight: 4 }
        ],
        cookieSignatures: [
          { pattern: /barra_counter_session/i, weight: 5 },
          { pattern: /BNI__BARRACUDA_LB_COOKIE/i, weight: 5 }
        ],
        bodySignatures: [
          { pattern: /barracuda/i, weight: 3 },
          { pattern: /You are being blocked/i, weight: 2 }
        ],
        dnsPatterns: [],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: false,
          ddosProtection: false,
          rateLimiting: true,
          geoBlocking: false,
          ipReputation: false,
          customRules: true,
          apiProtection: false,
          challengePages: false
        },
        bypassDifficulty: "easy"
      },
      {
        vendor: "modsecurity",
        productName: "ModSecurity (OWASP CRS)",
        headerSignatures: [
          { header: "server", pattern: /mod_security|modsecurity/i, weight: 5 }
        ],
        cookieSignatures: [],
        bodySignatures: [
          { pattern: /ModSecurity/i, weight: 5 },
          { pattern: /OWASP.*CRS/i, weight: 4 },
          { pattern: /Not Acceptable!.*406/i, weight: 3 }
        ],
        dnsPatterns: [],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: false,
          ddosProtection: false,
          rateLimiting: false,
          geoBlocking: false,
          ipReputation: false,
          customRules: true,
          apiProtection: false,
          challengePages: false
        },
        bypassDifficulty: "easy"
      },
      {
        vendor: "wallarm",
        productName: "Wallarm WAAP",
        headerSignatures: [
          { header: "server", pattern: /wallarm/i, weight: 5 },
          { header: "x-wallarm-instance", pattern: /.+/, weight: 5 }
        ],
        cookieSignatures: [],
        bodySignatures: [
          { pattern: /wallarm/i, weight: 4 }
        ],
        dnsPatterns: [/\.wallarm\.com$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: false,
          rateLimiting: true,
          geoBlocking: false,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "fastly",
        productName: "Fastly Next-Gen WAF (Signal Sciences)",
        headerSignatures: [
          { header: "server", pattern: /fastly/i, weight: 3 },
          { header: "x-served-by", pattern: /cache-/i, weight: 3 },
          { header: "x-fastly-request-id", pattern: /.+/, weight: 4 },
          { header: "fastly-debug-digest", pattern: /.+/, weight: 4 },
          { header: "via", pattern: /varnish/i, weight: 2 }
        ],
        cookieSignatures: [],
        bodySignatures: [
          { pattern: /fastly/i, weight: 2 }
        ],
        dnsPatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: true,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: true,
          ipReputation: true,
          customRules: true,
          apiProtection: true,
          challengePages: false
        },
        bypassDifficulty: "hard"
      },
      {
        vendor: "citrix_adc",
        productName: "Citrix ADC (NetScaler) AppFirewall",
        headerSignatures: [
          { header: "via", pattern: /NS-CACHE/i, weight: 4 },
          { header: "cneonction", pattern: /close/i, weight: 3 },
          { header: "x-ns-cache", pattern: /.+/, weight: 4 }
        ],
        cookieSignatures: [
          { pattern: /NSC_/i, weight: 5 },
          { pattern: /citrix_ns_id/i, weight: 5 }
        ],
        bodySignatures: [
          { pattern: /citrix|netscaler/i, weight: 4 },
          { pattern: /ns_af/i, weight: 4 }
        ],
        dnsPatterns: [],
        capabilities: {
          sqlInjectionProtection: true,
          xssProtection: true,
          rfiLfiProtection: true,
          commandInjectionProtection: true,
          botProtection: false,
          ddosProtection: true,
          rateLimiting: true,
          geoBlocking: false,
          ipReputation: false,
          customRules: true,
          apiProtection: false,
          challengePages: false
        },
        bypassDifficulty: "medium"
      }
    ];
    NGFW_FINGERPRINTS = [
      {
        vendor: "palo_alto",
        productName: "Palo Alto Networks NGFW",
        bannerPatterns: [/palo\s*alto/i, /PAN-OS/i, /GlobalProtect/i],
        certOrgPatterns: [/Palo Alto Networks/i],
        managementPaths: ["/php/login.php", "/global-protect/login.esp", "/ssl-vpn/login.esp"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: true,
          urlFiltering: true
        }
      },
      {
        vendor: "fortinet",
        productName: "Fortinet FortiGate NGFW",
        bannerPatterns: [/fortigate/i, /fortinet/i, /FortiOS/i],
        certOrgPatterns: [/Fortinet/i],
        managementPaths: ["/login", "/remote/login", "/remote/logincheck"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: true,
          urlFiltering: true
        }
      },
      {
        vendor: "checkpoint",
        productName: "Check Point NGFW",
        bannerPatterns: [/check\s*point/i, /CPMI/i, /FW-1/i, /FireWall-1/i],
        certOrgPatterns: [/Check Point/i],
        managementPaths: ["/sslvpn/Login/Login", "/cgi-bin/home.tcl"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: true,
          urlFiltering: true
        }
      },
      {
        vendor: "cisco_firepower",
        productName: "Cisco Firepower NGFW",
        bannerPatterns: [/firepower/i, /cisco.*ftd/i, /Sourcefire/i],
        certOrgPatterns: [/Cisco/i],
        managementPaths: ["/ui/login", "/login.cgi"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: true,
          urlFiltering: true
        }
      },
      {
        vendor: "cisco_asa",
        productName: "Cisco ASA",
        bannerPatterns: [/cisco.*asa/i, /Adaptive Security Appliance/i],
        certOrgPatterns: [/Cisco/i],
        managementPaths: ["/+CSCOE+/logon.html", "/CSCOSSLC/tunnel"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: false,
          ipsIdsIntegrated: false,
          applicationAwareness: false,
          sslDecryption: false,
          threatIntelFeed: false,
          sandboxing: false,
          urlFiltering: false
        }
      },
      {
        vendor: "juniper_srx",
        productName: "Juniper SRX Series",
        bannerPatterns: [/juniper/i, /JUNOS/i, /SRX/i],
        certOrgPatterns: [/Juniper Networks/i],
        managementPaths: ["/login", "/dana-na/auth/url_default/welcome.cgi"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: false,
          urlFiltering: true
        }
      },
      {
        vendor: "sophos_xg",
        productName: "Sophos XG Firewall",
        bannerPatterns: [/sophos/i, /cyberoam/i],
        certOrgPatterns: [/Sophos/i],
        managementPaths: ["/webconsole/webpages/login.jsp", "/userportal/webpages/myaccount/login.jsp"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: true,
          urlFiltering: true
        }
      },
      {
        vendor: "sonicwall",
        productName: "SonicWall NGFW",
        bannerPatterns: [/sonicwall/i, /SonicOS/i],
        certOrgPatterns: [/SonicWall/i, /SonicWALL/i],
        managementPaths: ["/auth.html", "/auth1.html"],
        capabilities: {
          statefulInspection: true,
          deepPacketInspection: true,
          ipsIdsIntegrated: true,
          applicationAwareness: true,
          sslDecryption: true,
          threatIntelFeed: true,
          sandboxing: true,
          urlFiltering: true
        }
      }
    ];
    WAF_BYPASS_DB = {
      cloudflare: [
        { wafVendor: "cloudflare", technique: "Origin IP Discovery", description: "Find the origin IP behind Cloudflare using historical DNS records, certificate transparency logs, or Shodan. Bypass WAF by connecting directly to origin.", risk: "low", references: ["https://github.com/m0rtem/CloudFail"] },
        { wafVendor: "cloudflare", technique: "HTTP/2 Smuggling", description: "Exploit HTTP/2 to HTTP/1.1 translation differences at the Cloudflare edge to smuggle requests past WAF rules.", risk: "medium", references: ["CL.0 / H2.CL smuggling research"] },
        { wafVendor: "cloudflare", technique: "Unicode Normalization", description: "Use Unicode characters that normalize differently at the WAF vs. application layer to bypass SQL injection and XSS filters.", risk: "low", references: ["Unicode WAF bypass techniques"] }
      ],
      akamai: [
        { wafVendor: "akamai", technique: "Parameter Pollution", description: "Use HTTP Parameter Pollution to split payloads across duplicate parameters. Akamai may only inspect the first occurrence.", risk: "low", references: ["HPP research papers"] },
        { wafVendor: "akamai", technique: "Chunked Transfer Encoding", description: "Use chunked transfer encoding to split malicious payloads across chunks, bypassing pattern matching.", risk: "medium", references: ["Chunked encoding WAF bypass"] }
      ],
      aws_waf: [
        { wafVendor: "aws_waf", technique: "Case Variation", description: "AWS WAF managed rules may be case-sensitive. Try mixed-case SQL keywords (SeLeCt, UnIoN) or HTML tags.", risk: "low", references: ["AWS WAF managed rules documentation"] },
        { wafVendor: "aws_waf", technique: "JSON Content-Type", description: "Send payloads in JSON body with Content-Type: application/json. Some AWS WAF rules only inspect form-encoded data.", risk: "low", references: ["AWS WAF content type handling"] }
      ],
      imperva: [
        { wafVendor: "imperva", technique: "Multipart Form Bypass", description: "Wrap payloads in multipart/form-data boundaries. Imperva may not fully parse nested multipart content.", risk: "medium", references: ["Imperva WAF bypass research"] }
      ],
      f5_bigip: [
        { wafVendor: "f5_bigip", technique: "Cookie Decoding", description: "F5 BIG-IP encodes backend server info in cookies (BIGipServer*). Decode to discover internal IPs and pool members.", risk: "low", references: ["F5 cookie decoding tools"] },
        { wafVendor: "f5_bigip", technique: "HTTP Desync", description: "Exploit request smuggling via CL/TE or TE/CL discrepancies between F5 and backend servers.", risk: "high", references: ["HTTP request smuggling research"] }
      ],
      modsecurity: [
        { wafVendor: "modsecurity", technique: "Paranoia Level Exploitation", description: "ModSecurity CRS has paranoia levels 1-4. Most deployments use PL1-2, leaving advanced evasion techniques effective.", risk: "low", references: ["OWASP CRS documentation"] },
        { wafVendor: "modsecurity", technique: "Comment Injection", description: "Use SQL comments (/**/) and inline comments to break up keywords: SEL/**/ECT, UN/**/ION.", risk: "low", references: ["SQL injection WAF bypass cheatsheets"] }
      ],
      fortiweb: [
        { wafVendor: "fortiweb", technique: "Encoding Chains", description: "Chain multiple encoding layers (URL encode \u2192 double URL encode \u2192 Unicode) to bypass FortiWeb pattern matching.", risk: "low", references: ["FortiWeb WAF bypass research"] }
      ],
      // Defaults for vendors without specific bypasses
      aws_cloudfront: [],
      azure_front_door: [],
      azure_waf: [],
      gcp_cloud_armor: [],
      f5_silverline: [],
      barracuda: [],
      citrix_adc: [],
      radware: [],
      cloudfront_shield: [],
      stackpath: [],
      edgecast: [],
      wallarm: [],
      reblaze: [],
      signal_sciences: [],
      sucuri: [],
      fastly: [],
      unknown_waf: [
        { wafVendor: "unknown_waf", technique: "Generic Encoding Bypass", description: "Try URL encoding, double encoding, Unicode normalization, and mixed case to bypass unknown WAF rules.", risk: "low", references: ["OWASP WAF bypass techniques"] }
      ]
    };
  }
});

// server/lib/carver-feedback-loop.ts
function createState() {
  return {
    adjustments: [],
    attackChainAssets: /* @__PURE__ */ new Map(),
    discoverySignals: [],
    threatIntelFactorBoosts: [],
    cumulativeBoosts: /* @__PURE__ */ new Map()
  };
}
function getCumulative(state, assetId, factor) {
  return state.cumulativeBoosts.get(assetId)?.get(factor) || 0;
}
function addCumulative(state, assetId, factor, boost) {
  if (!state.cumulativeBoosts.has(assetId)) state.cumulativeBoosts.set(assetId, /* @__PURE__ */ new Map());
  const current = getCumulative(state, assetId, factor);
  const capped = Math.min(boost, MAX_CUMULATIVE_BOOST - current);
  if (capped <= 0) return 0;
  state.cumulativeBoosts.get(assetId).set(factor, current + capped);
  return capped;
}
function applyFactorBoostInternal(state, analysis, factor, rawBoost, source, reason, confidence) {
  const cappedBoost = Math.min(rawBoost, MAX_FACTOR_BOOST);
  const effectiveBoost = addCumulative(state, analysis.asset.assetId, factor, cappedBoost);
  if (effectiveBoost <= 0) return null;
  const prev = analysis.carverScores[factor];
  const newVal = Math.min(10, prev + effectiveBoost);
  analysis.carverScores[factor] = newVal;
  const adj = {
    assetId: analysis.asset.assetId,
    hostname: analysis.asset.hostname,
    source,
    factor,
    previousValue: prev,
    newValue: newVal,
    delta: newVal - prev,
    reason,
    confidence
  };
  state.adjustments.push(adj);
  return adj;
}
function buildResult(state) {
  const affectedAssets = new Set(state.adjustments.map((a) => a.assetId));
  const avgDelta = state.adjustments.length > 0 ? state.adjustments.reduce((sum, a) => sum + a.delta, 0) / state.adjustments.length : 0;
  return {
    adjustments: state.adjustments,
    attackChainAssets: state.attackChainAssets,
    discoverySignals: state.discoverySignals,
    threatIntelFactorBoosts: state.threatIntelFactorBoosts,
    summary: {
      totalAdjustments: state.adjustments.length,
      assetsAffected: affectedAssets.size,
      avgScoreChange: Math.round(avgDelta * 100) / 100,
      attackChainAssetsCount: state.attackChainAssets.size,
      discoverySignalsCount: state.discoverySignals.length,
      threatIntelBoostsCount: state.threatIntelFactorBoosts.length
    }
  };
}
function applyCarverFeedbackEarly(analyses, crossModuleData, passiveRecon) {
  const state = createState();
  applyThreatIntelBoosts(state, analyses, crossModuleData);
  applyDiscoveryContext(state, analyses, passiveRecon);
  const result = buildResult(state);
  if (result.summary.totalAdjustments > 0) {
    console.log(
      `[CarverFeedback/Early] ${result.summary.totalAdjustments} adjustments across ${result.summary.assetsAffected} assets (avg delta: ${result.summary.avgScoreChange}). Discovery signals: ${result.summary.discoverySignalsCount}, Threat intel boosts: ${result.summary.threatIntelBoostsCount}`
    );
  }
  return result;
}
function applyCarverFeedbackLate(analyses, postEnrichment, priorState) {
  const state = createState();
  if (priorState) {
    for (const adj of priorState.adjustments) {
      if (!state.cumulativeBoosts.has(adj.assetId)) state.cumulativeBoosts.set(adj.assetId, /* @__PURE__ */ new Map());
      const factorMap = state.cumulativeBoosts.get(adj.assetId);
      factorMap.set(String(adj.factor), (factorMap.get(String(adj.factor)) || 0) + adj.delta);
    }
  }
  applyAttackChainBoosts(state, analyses, postEnrichment);
  applyBlindSpotBoosts(state, analyses, postEnrichment);
  const result = buildResult(state);
  if (result.summary.totalAdjustments > 0) {
    console.log(
      `[CarverFeedback/Late] ${result.summary.totalAdjustments} adjustments across ${result.summary.assetsAffected} assets (avg delta: ${result.summary.avgScoreChange}). Attack chains: ${result.summary.attackChainAssetsCount}`
    );
  }
  return result;
}
function applyAttackChainBoosts(state, analyses, postEnrichment) {
  if (postEnrichment?.attackPaths?.length) {
    for (const chain of postEnrichment.attackPaths) {
      if (!chain.steps?.length) continue;
      for (const step of chain.steps) {
        const targetAsset = step.targetAsset?.toLowerCase() || "";
        const matchedAnalysis = analyses.find(
          (a) => a.asset.hostname.toLowerCase().includes(targetAsset) || targetAsset.includes(a.asset.hostname.toLowerCase()) || a.asset.assetId === targetAsset
        );
        if (!matchedAnalysis) continue;
        const assetId = matchedAnalysis.asset.assetId;
        const isFirst = step.order === 1 || step.order === Math.min(...chain.steps.map((s) => s.order));
        const isLast = step.order === Math.max(...chain.steps.map((s) => s.order));
        const role = isFirst ? "entry_point" : isLast ? "objective" : "pivot";
        const positionWeight = CHAIN_POSITION_WEIGHTS[role] || 0.5;
        if (!state.attackChainAssets.has(assetId)) {
          state.attackChainAssets.set(assetId, {
            chainIds: [],
            chainNames: [],
            positionInChains: [],
            aggregateRisk: 0,
            techniques: []
          });
        }
        const ctx = state.attackChainAssets.get(assetId);
        if (!ctx.chainIds.includes(chain.id)) {
          ctx.chainIds.push(chain.id);
          ctx.chainNames.push(chain.name);
        }
        ctx.positionInChains.push({ chainId: chain.id, stepOrder: step.order, role });
        ctx.aggregateRisk = Math.max(ctx.aggregateRisk, chain.overallRisk);
        if (step.technique && !ctx.techniques.includes(step.technique)) {
          ctx.techniques.push(step.technique);
        }
        const chainRiskFactor = Math.min(chain.overallRisk / 100, 1);
        const difficultyBoost = DIFFICULTY_ACCESSIBILITY_MAP[step.difficulty] || 0;
        if (role === "entry_point") {
          applyFactorBoostInternal(
            state,
            matchedAnalysis,
            "accessibility",
            (1 + difficultyBoost * 0.5) * positionWeight * chainRiskFactor,
            "attack_chain",
            `Entry point in attack chain "${chain.name}" (difficulty: ${step.difficulty}, chain risk: ${chain.overallRisk}/100)`,
            0.8
          );
          if (difficultyBoost >= 1) {
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "vulnerability",
              difficultyBoost * 0.5 * chainRiskFactor,
              "attack_chain",
              `Low-difficulty entry point in chain "${chain.name}" \u2014 ${step.technique}`,
              0.7
            );
          }
        }
        if (role === "pivot") {
          applyFactorBoostInternal(
            state,
            matchedAnalysis,
            "vulnerability",
            (0.8 + difficultyBoost * 0.3) * positionWeight * chainRiskFactor,
            "attack_chain",
            `Pivot point in attack chain "${chain.name}" \u2014 enables lateral movement via ${step.technique}`,
            0.7
          );
        }
        if (role === "objective") {
          applyFactorBoostInternal(
            state,
            matchedAnalysis,
            "effect",
            1.5 * positionWeight * chainRiskFactor,
            "attack_chain",
            `Objective of attack chain "${chain.name}" \u2014 compromise would achieve attacker goal`,
            0.8
          );
        }
        applyFactorBoostInternal(
          state,
          matchedAnalysis,
          "recognizability",
          0.5 * chainRiskFactor,
          "attack_chain",
          `Asset appears in ${ctx.chainIds.length} attack chain(s) \u2014 increased attacker awareness`,
          0.6
        );
      }
    }
    console.log(
      `[CarverFeedback] Attack chain analysis: ${state.attackChainAssets.size} assets in ${postEnrichment.attackPaths.length} chains, ${state.adjustments.length} CARVER adjustments`
    );
  }
}
function applyThreatIntelBoosts(state, analyses, crossModuleData) {
  if (crossModuleData?.threatIntel?.status === "success") {
    const ti = crossModuleData.threatIntel;
    for (const adj of ti.riskAdjustments) {
      const targetAnalysis = analyses.find((a) => a.asset.assetId === adj.assetId);
      if (!targetAnalysis) continue;
      const factorBoosts = [];
      const reason = adj.reason.toLowerCase();
      if (reason.includes("exploit") || reason.includes("vulnerability") || reason.includes("cve")) {
        const boost = applyFactorBoostInternal(
          state,
          targetAnalysis,
          "vulnerability",
          Math.min(adj.adjustment * 0.6, MAX_FACTOR_BOOST),
          "threat_intel",
          `Trending exploit targeting this asset's technology stack: ${adj.reason}`,
          0.8
        );
        if (boost) factorBoosts.push({ factor: "vulnerability", boost: boost.delta, reason: adj.reason });
      }
      if (reason.includes("threat actor") || reason.includes("apt") || reason.includes("campaign")) {
        const boost = applyFactorBoostInternal(
          state,
          targetAnalysis,
          "recognizability",
          Math.min(adj.adjustment * 0.5, MAX_FACTOR_BOOST),
          "threat_intel",
          `Active threat actor campaign targeting this technology: ${adj.reason}`,
          0.7
        );
        if (boost) factorBoosts.push({ factor: "recognizability", boost: boost.delta, reason: adj.reason });
      }
      if (reason.includes("exposed") || reason.includes("internet-facing") || reason.includes("public")) {
        const boost = applyFactorBoostInternal(
          state,
          targetAnalysis,
          "accessibility",
          Math.min(adj.adjustment * 0.4, MAX_FACTOR_BOOST),
          "threat_intel",
          `Internet-exposed service in active threat landscape: ${adj.reason}`,
          0.7
        );
        if (boost) factorBoosts.push({ factor: "accessibility", boost: boost.delta, reason: adj.reason });
      }
      if (factorBoosts.length === 0) {
        const vulnBoost = applyFactorBoostInternal(
          state,
          targetAnalysis,
          "vulnerability",
          Math.min(adj.adjustment * 0.4, MAX_FACTOR_BOOST),
          "threat_intel",
          `Threat intel risk adjustment: ${adj.reason}`,
          0.6
        );
        if (vulnBoost) factorBoosts.push({ factor: "vulnerability", boost: vulnBoost.delta, reason: adj.reason });
        const recogBoost = applyFactorBoostInternal(
          state,
          targetAnalysis,
          "recognizability",
          Math.min(adj.adjustment * 0.3, MAX_FACTOR_BOOST),
          "threat_intel",
          `Threat intel risk adjustment: ${adj.reason}`,
          0.6
        );
        if (recogBoost) factorBoosts.push({ factor: "recognizability", boost: recogBoost.delta, reason: adj.reason });
      }
      if (factorBoosts.length > 0) {
        state.threatIntelFactorBoosts.push({
          assetId: adj.assetId,
          hostname: targetAnalysis.asset.hostname,
          originalAdjustment: adj.adjustment,
          factorBoosts
        });
      }
    }
    if (ti.matchingThreatActors?.length > 0) {
      const highRelevanceActors = ti.matchingThreatActors.filter((a) => a.relevance === "high");
      if (highRelevanceActors.length > 0) {
        for (const analysis of analyses) {
          const techs = (analysis.asset.technologies || []).map((t) => t.toLowerCase());
          for (const actor of highRelevanceActors) {
            const actorTechniques = actor.techniques.map((t) => t.toLowerCase());
            const hasMatch = techs.some(
              (tech) => actorTechniques.some((at) => at.includes(tech) || tech.includes(at))
            );
            if (hasMatch) {
              applyFactorBoostInternal(
                state,
                analysis,
                "recognizability",
                0.5,
                "threat_intel",
                `High-relevance threat actor "${actor.name}" actively targets technology on this asset`,
                0.7
              );
            }
          }
        }
      }
    }
    console.log(
      `[CarverFeedback] Threat intel factor boosts: ${state.threatIntelFactorBoosts.length} assets received CARVER-specific adjustments (replacing flat +3 boosts)`
    );
  }
}
function applyDiscoveryContext(state, analyses, passiveRecon) {
  if (passiveRecon) {
    for (const cr of passiveRecon.connectorResults) {
      for (const obs of cr.observations) {
        const tags = obs.tags || [];
        const evidence = obs.evidence || {};
        if (tags.includes("recently_registered") || evidence.recently_registered) {
          const matchedAnalysis = analyses.find(
            (a) => a.asset.hostname.includes(obs.domain || "") || obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "recently_registered",
              description: `Domain registered within the last year \u2014 may indicate shadow IT, phishing infrastructure, or rapid expansion`,
              carverFactor: "recognizability",
              boost: 1,
              evidence: { registrationDate: evidence.registration_date, domainAge: evidence.domain_age }
            };
            state.discoverySignals.push(signal);
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "recognizability",
              1,
              "discovery_context",
              signal.description,
              0.8
            );
          }
        }
        if (tags.includes("dns_change") || tags.includes("new_subdomain") || evidence.dns_changed) {
          const matchedAnalysis = analyses.find(
            (a) => a.asset.hostname.includes(obs.domain || "") || obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "dns_change",
              description: `Recent DNS changes detected \u2014 may indicate infrastructure migration, misconfiguration, or takeover risk`,
              carverFactor: "effect",
              boost: 0.5,
              evidence: { changeType: evidence.change_type, previousValue: evidence.previous_value }
            };
            state.discoverySignals.push(signal);
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "effect",
              0.5,
              "discovery_context",
              signal.description,
              0.6
            );
          }
        }
        if (tags.includes("shadow_it") || tags.includes("unmanaged") || evidence.shadow_it) {
          const matchedAnalysis = analyses.find(
            (a) => a.asset.hostname.includes(obs.domain || "") || obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "shadow_it",
              description: `Asset appears to be unmanaged or shadow IT \u2014 may lack security controls and patching`,
              carverFactor: "vulnerability",
              boost: 1.5,
              evidence: { indicators: evidence.shadow_it_indicators }
            };
            state.discoverySignals.push(signal);
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "vulnerability",
              1.5,
              "discovery_context",
              signal.description,
              0.7
            );
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "accessibility",
              1,
              "discovery_context",
              `Unmanaged asset likely has weaker access controls`,
              0.6
            );
          }
        }
        if (tags.includes("whois_privacy") || tags.includes("privacy_protected") || evidence.privacy_protected) {
          const matchedAnalysis = analyses.find(
            (a) => a.asset.hostname.includes(obs.domain || "") || obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "privacy_protected",
              description: `WHOIS privacy protection enabled \u2014 may indicate desire to hide ownership or infrastructure details`,
              carverFactor: "recognizability",
              boost: 0.3,
              evidence: { registrar: evidence.registrar }
            };
            state.discoverySignals.push(signal);
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "recognizability",
              0.3,
              "discovery_context",
              signal.description,
              0.4
            );
          }
        }
        if (tags.includes("certificate_change") || tags.includes("cert_expiring") || evidence.cert_expiring_soon) {
          const matchedAnalysis = analyses.find(
            (a) => a.asset.hostname.includes(obs.domain || "") || obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "certificate_change",
              description: `Certificate change or expiration detected \u2014 may indicate infrastructure changes or security gaps`,
              carverFactor: "vulnerability",
              boost: 0.5,
              evidence: { certExpiry: evidence.cert_expiry, certIssuer: evidence.cert_issuer }
            };
            state.discoverySignals.push(signal);
            applyFactorBoostInternal(
              state,
              matchedAnalysis,
              "vulnerability",
              0.5,
              "discovery_context",
              signal.description,
              0.5
            );
          }
        }
      }
    }
    console.log(
      `[CarverFeedback] Discovery context: ${state.discoverySignals.length} signals from passive recon applied to CARVER factors`
    );
  }
}
function applyBlindSpotBoosts(state, analyses, postEnrichment) {
  if (postEnrichment?.blindSpots?.length) {
    for (const blindSpot of postEnrichment.blindSpots) {
      if (blindSpot.severity !== "critical" && blindSpot.severity !== "high") continue;
      const areaLower = blindSpot.area.toLowerCase();
      for (const analysis of analyses) {
        const hostname = analysis.asset.hostname.toLowerCase();
        const techs = (analysis.asset.technologies || []).map((t) => t.toLowerCase());
        const tags = (analysis.asset.tags || []).map((t) => t.toLowerCase());
        const isRelevant = areaLower.includes(hostname) || hostname.includes(areaLower) || techs.some((t) => areaLower.includes(t)) || tags.some((t) => areaLower.includes(t));
        if (isRelevant) {
          applyFactorBoostInternal(
            state,
            analysis,
            "vulnerability",
            blindSpot.severity === "critical" ? 1 : 0.5,
            "blind_spot",
            `Blind spot in "${blindSpot.area}": ${blindSpot.description}`,
            blindSpot.severity === "critical" ? 0.7 : 0.5
          );
        }
      }
    }
    console.log(
      `[CarverFeedback] Blind spot adjustments: ${postEnrichment.blindSpots.filter((b) => b.severity === "critical" || b.severity === "high").length} critical/high blind spots processed`
    );
  }
}
var MAX_FACTOR_BOOST, MAX_CUMULATIVE_BOOST, CHAIN_POSITION_WEIGHTS, DIFFICULTY_ACCESSIBILITY_MAP;
var init_carver_feedback_loop = __esm({
  "server/lib/carver-feedback-loop.ts"() {
    "use strict";
    MAX_FACTOR_BOOST = 2;
    MAX_CUMULATIVE_BOOST = 3;
    CHAIN_POSITION_WEIGHTS = {
      entry_point: 1,
      // Entry points get full boost
      pivot: 0.7,
      // Pivot points get 70%
      objective: 0.5
      // Objectives already have high criticality
    };
    DIFFICULTY_ACCESSIBILITY_MAP = {
      trivial: 2,
      easy: 1.5,
      moderate: 1,
      hard: 0.5,
      expert: 0
    };
  }
});

// server/lib/di-threat-matching.ts
function extractScanFingerprint(analyses, org, kevEnrichment, crossModuleEnrichment) {
  const cves = /* @__PURE__ */ new Set();
  const technologies = /* @__PURE__ */ new Set();
  const services = /* @__PURE__ */ new Set();
  const ports = /* @__PURE__ */ new Set();
  const techniques = /* @__PURE__ */ new Set();
  const findings = /* @__PURE__ */ new Map();
  for (const analysis of analyses) {
    if (analysis.asset.technologies) {
      for (const tech of analysis.asset.technologies) {
        technologies.add(tech.toLowerCase());
      }
    }
    if (analysis.asset.tags) {
      for (const tag of analysis.asset.tags) {
        services.add(tag.toLowerCase());
      }
    }
    if (analysis.asset.assetType) {
      services.add(analysis.asset.assetType.toLowerCase());
    }
    for (const finding of analysis.postureFindings || []) {
      if (finding.cveIds) {
        for (const cve of finding.cveIds) {
          cves.add(cve);
          findings.set(cve, {
            hostname: analysis.asset.hostname,
            title: finding.title,
            severity: finding.severity
          });
        }
      }
      const titleCves = finding.title?.match(/CVE-\d{4}-\d+/g) || [];
      for (const cve of titleCves) {
        cves.add(cve);
        if (!findings.has(cve)) {
          findings.set(cve, {
            hostname: analysis.asset.hostname,
            title: finding.title,
            severity: finding.severity
          });
        }
      }
    }
    for (const tv of analysis.testVectors || []) {
      if (tv.suggestedEmulation?.technique) {
        techniques.add(tv.suggestedEmulation.technique);
      }
    }
  }
  if (kevEnrichment?.matches) {
    for (const m of kevEnrichment.matches) {
      cves.add(m.cveId);
    }
  }
  if (crossModuleEnrichment?.threatIntel?.matchingThreatActors) {
    for (const actor of crossModuleEnrichment.threatIntel.matchingThreatActors) {
      for (const tech of actor.techniques || []) {
        techniques.add(tech);
      }
    }
  }
  const techServiceMap = {
    "apache": ["http", "web"],
    "nginx": ["http", "web"],
    "iis": ["http", "web"],
    "tomcat": ["http", "web", "java"],
    "wordpress": ["http", "web", "php"],
    "drupal": ["http", "web", "php"],
    "joomla": ["http", "web", "php"],
    "exchange": ["smtp", "email"],
    "postfix": ["smtp", "email"],
    "openssh": ["ssh"],
    "proftpd": ["ftp"],
    "vsftpd": ["ftp"],
    "mysql": ["mysql", "database"],
    "postgres": ["postgres", "database"],
    "mongodb": ["mongodb", "database"],
    "redis": ["redis", "database"],
    "docker": ["docker", "container"],
    "kubernetes": ["kubernetes", "container"],
    "jenkins": ["jenkins", "ci"],
    "gitlab": ["gitlab", "ci"],
    "microsoft 365": ["email", "cloud"],
    "google workspace": ["email", "cloud"]
  };
  for (const tech of technologies) {
    const mapped = Object.entries(techServiceMap).find(([k]) => tech.includes(k));
    if (mapped) {
      for (const svc of mapped[1]) services.add(svc);
    }
  }
  return {
    cves,
    technologies,
    services,
    ports,
    sectors: [org.sector, ...org.complianceFlags || []].filter(Boolean),
    techniques,
    findings
  };
}
function scoreGroup(group, fingerprint) {
  const matchedCVEs = [];
  const matchedTechniques = [];
  const matchedTools = [];
  const matchedInitialAccess = [];
  for (const cve of group.exploitedCVEs) {
    if (fingerprint.cves.has(cve)) {
      matchedCVEs.push(cve);
    }
  }
  const cveScore = group.exploitedCVEs.length > 0 ? Math.min(100, matchedCVEs.length / Math.min(group.exploitedCVEs.length, 5) * 100) : 0;
  const allServices = [...fingerprint.services, ...fingerprint.technologies];
  for (const ttp of group.ttps) {
    if (fingerprint.techniques.has(ttp.techniqueId)) {
      matchedTechniques.push({ id: ttp.techniqueId, name: ttp.techniqueName, tactic: ttp.tactic });
      continue;
    }
    const relevantServices = TECHNIQUE_SERVICE_MAP[ttp.techniqueId] || [];
    const hasRelevantService = relevantServices.some(
      (svc) => allServices.some((s) => s.includes(svc))
    );
    if (hasRelevantService) {
      matchedTechniques.push({ id: ttp.techniqueId, name: ttp.techniqueName, tactic: ttp.tactic });
    }
  }
  const techniqueScore = group.ttps.length > 0 ? Math.min(100, matchedTechniques.length / Math.min(group.ttps.length, 8) * 100) : 0;
  for (const tool of group.tools) {
    const toolLower = tool.name.toLowerCase();
    if (fingerprint.technologies.has(toolLower) || [...fingerprint.technologies].some((t) => t.includes(toolLower) || toolLower.includes(t))) {
      matchedTools.push(tool.name);
    }
  }
  const toolScore = group.tools.length > 0 ? Math.min(100, matchedTools.length / Math.min(group.tools.length, 5) * 100) : 0;
  const sectorLower = fingerprint.sectors.map((s) => s.toLowerCase());
  const sectorMatches = group.targetSectors.filter(
    (gs) => sectorLower.some((s) => s.includes(gs.toLowerCase()) || gs.toLowerCase().includes(s))
  );
  const sectorScore = group.targetSectors.length > 0 ? Math.min(100, sectorMatches.length / Math.min(group.targetSectors.length, 3) * 100) : 0;
  for (const method of group.initialAccessMethods) {
    const methodLower = method.toLowerCase();
    const relevantServices = Object.entries(IA_METHOD_SERVICE_MAP).find(
      ([k]) => methodLower.includes(k)
    );
    if (relevantServices) {
      const hasService = relevantServices[1].some(
        (svc) => allServices.some((s) => s.includes(svc))
      );
      if (hasService) {
        matchedInitialAccess.push(method);
      }
    }
  }
  const iaScore = group.initialAccessMethods.length > 0 ? Math.min(100, matchedInitialAccess.length / Math.min(group.initialAccessMethods.length, 3) * 100) : 0;
  const matchScore = Math.round(
    cveScore * 0.3 + techniqueScore * 0.25 + toolScore * 0.2 + sectorScore * 0.15 + iaScore * 0.1
  );
  if (matchScore < 15 && matchedCVEs.length === 0) return null;
  const riskLevel = matchScore >= 70 ? "critical" : matchScore >= 50 ? "high" : matchScore >= 30 ? "medium" : "low";
  const rationaleParts = [];
  if (matchedCVEs.length > 0) {
    const cveDetails = matchedCVEs.slice(0, 3).map((cve) => {
      const f = fingerprint.findings.get(cve);
      return f ? `${cve} (found on ${f.hostname}, severity ${f.severity}/10)` : cve;
    });
    rationaleParts.push(`${group.name} is known to exploit ${matchedCVEs.length} CVE(s) that were discovered on the target's attack surface: ${cveDetails.join(", ")}. This indicates the group has demonstrated capability and intent to leverage these specific vulnerabilities.`);
  }
  if (matchedTechniques.length > 0) {
    const tacticSet = [...new Set(matchedTechniques.map((t) => t.tactic))];
    rationaleParts.push(`${matchedTechniques.length} of the group's preferred MITRE ATT&CK techniques align with services discovered on the target, spanning ${tacticSet.length} tactic(s): ${tacticSet.join(", ")}. Key techniques include ${matchedTechniques.slice(0, 3).map((t) => `${t.id} (${t.name})`).join(", ")}.`);
  }
  if (matchedTools.length > 0) {
    rationaleParts.push(`The group's known toolset includes ${matchedTools.join(", ")}, which correlate with technologies detected on the target infrastructure.`);
  }
  if (sectorMatches.length > 0) {
    rationaleParts.push(`${group.name} actively targets the ${sectorMatches.join(", ")} sector(s), which aligns with the target organization's profile.`);
  }
  if (matchedInitialAccess.length > 0) {
    rationaleParts.push(`The group's initial access methods (${matchedInitialAccess.join(", ")}) are viable against the discovered attack surface.`);
  }
  const hedgingPrefix = matchScore >= 80 ? `The observed attack surface exhibits patterns strongly consistent with ${group.name}'s known operational profile. ` : matchScore >= 60 ? `The target's infrastructure shows characteristics moderately consistent with ${group.name}'s documented TTPs. ` : `Some indicators suggest possible \u2014 but unconfirmed \u2014 alignment with ${group.name}'s operational patterns. `;
  const hedgingSuffix = ` Note: This is a behavioral pattern match, not a definitive attribution. Multiple threat actors may exhibit similar TTPs.`;
  const matchRationale = rationaleParts.length > 0 ? hedgingPrefix + rationaleParts.join(" ") + hedgingSuffix : `${group.name} shows general profile overlap based on sector targeting and technique applicability. This represents pattern similarity, not confirmed attribution.`;
  return {
    groupId: group.id,
    groupName: group.name,
    aliases: group.aliases,
    groupType: group.type,
    origin: group.origin,
    threatLevel: group.threatLevel,
    active: group.active,
    motivation: group.motivation,
    targetSectors: group.targetSectors,
    matchScore,
    riskLevel,
    matchRationale,
    matchedCVEs,
    matchedTechniques,
    matchedTools,
    matchedInitialAccess,
    sectorRelevance: sectorScore,
    primaryTTPs: group.ttps.filter((t) => t.frequency === "primary").slice(0, 10).map((t) => ({ id: t.techniqueId, name: t.techniqueName, tactic: t.tactic })),
    defenseRecommendations: group.defenseRecommendations.filter((r) => r.priority === "critical" || r.priority === "high").slice(0, 5).map((r) => r.recommendation),
    scoreBreakdown: {
      cveScore: Math.round(cveScore),
      techniqueScore: Math.round(techniqueScore),
      toolScore: Math.round(toolScore),
      sectorScore: Math.round(sectorScore),
      initialAccessScore: Math.round(iaScore)
    }
  };
}
function synthesizeAttackPaths(analyses, matchedGroups, fingerprint) {
  const paths = [];
  let pathId = 0;
  const confirmedFindings = [];
  for (const analysis of analyses) {
    for (const f of analysis.postureFindings || []) {
      if (f.corroborationTier === "confirmed" || f.corroborationTier === "probable") {
        const cves = f.cveIds || [];
        const titleCves = f.title?.match(/CVE-\d{4}-\d+/g) || [];
        confirmedFindings.push({
          hostname: analysis.asset.hostname,
          finding: f.title,
          severity: f.severity,
          cves: [.../* @__PURE__ */ new Set([...cves, ...titleCves])],
          tier: f.corroborationTier,
          technologies: analysis.asset.technologies || []
        });
      }
    }
  }
  confirmedFindings.sort((a, b) => b.severity - a.severity);
  const webFindings = confirmedFindings.filter(
    (f) => f.technologies.some((t) => ["http", "https", "web", "apache", "nginx", "iis", "tomcat", "php", "java", "node"].some((s) => t.toLowerCase().includes(s))) || f.finding.toLowerCase().includes("rce") || f.finding.toLowerCase().includes("injection") || f.finding.toLowerCase().includes("xss")
  );
  if (webFindings.length > 0) {
    const topWebFinding = webFindings[0];
    const steps = [
      {
        order: 1,
        phase: "Reconnaissance",
        mitreTechnique: "T1595",
        techniqueName: "Active Scanning",
        targetAsset: topWebFinding.hostname,
        evidence: `Discovered ${webFindings.length} web-facing asset(s) with confirmed vulnerabilities via passive scanning`,
        difficulty: "trivial"
      },
      {
        order: 2,
        phase: "Initial Access",
        mitreTechnique: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        targetAsset: topWebFinding.hostname,
        evidence: `${topWebFinding.finding} (severity: ${topWebFinding.severity}/10, ${topWebFinding.tier})`,
        difficulty: topWebFinding.severity >= 8 ? "easy" : "moderate"
      }
    ];
    const hasBreachData = fingerprint.findings.size > 0;
    if (hasBreachData) {
      steps.push({
        order: 3,
        phase: "Credential Access",
        mitreTechnique: "T1078",
        techniqueName: "Valid Accounts",
        targetAsset: topWebFinding.hostname,
        evidence: `${fingerprint.cves.size} CVE(s) discovered across attack surface; credential exposure likely via breach data or default credentials`,
        difficulty: "moderate"
      });
    }
    if (analyses.length > 1) {
      const otherAssets = analyses.filter((a) => a.asset.hostname !== topWebFinding.hostname);
      if (otherAssets.length > 0) {
        steps.push({
          order: steps.length + 1,
          phase: "Lateral Movement",
          mitreTechnique: "T1021",
          techniqueName: "Remote Services",
          targetAsset: otherAssets[0].asset.hostname,
          evidence: `${otherAssets.length} additional asset(s) in the same infrastructure could be reached via pivoting`,
          difficulty: "moderate"
        });
      }
    }
    const relevantGroups = matchedGroups.filter((g) => g.matchedTechniques.some((t) => t.id === "T1190" || t.id === "T1595")).slice(0, 3).map((g) => g.groupName);
    const overallRisk = Math.min(100, Math.round(topWebFinding.severity * 10 + steps.length * 5));
    paths.push({
      id: `AP-${++pathId}`,
      name: "External Web Application Exploitation Chain",
      description: `An adversary exploits a confirmed vulnerability on ${topWebFinding.hostname} to gain initial access, then leverages the compromised position to access credentials and move laterally across ${analyses.length} discovered asset(s). This path is grounded in ${topWebFinding.finding}.`,
      steps,
      overallRisk,
      likelihood: topWebFinding.severity >= 8 ? 4 : 3,
      impact: 4,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map((s) => s.phase))]
    });
  }
  const sshFindings = confirmedFindings.filter(
    (f) => f.technologies.some((t) => t.toLowerCase().includes("ssh") || t.toLowerCase().includes("openssh")) || f.finding.toLowerCase().includes("ssh")
  );
  const emailFindings = confirmedFindings.filter(
    (f) => f.technologies.some((t) => ["smtp", "email", "exchange", "mail"].some((s) => t.toLowerCase().includes(s)))
  );
  if (sshFindings.length > 0 || emailFindings.length > 0) {
    const targetFinding = sshFindings[0] || emailFindings[0];
    const steps = [
      {
        order: 1,
        phase: "Reconnaissance",
        mitreTechnique: "T1589",
        techniqueName: "Gather Victim Identity Information",
        targetAsset: targetFinding.hostname,
        evidence: `Employee email patterns and organizational structure discoverable via OSINT`,
        difficulty: "trivial"
      },
      {
        order: 2,
        phase: "Initial Access",
        mitreTechnique: "T1078",
        techniqueName: "Valid Accounts",
        targetAsset: targetFinding.hostname,
        evidence: `${targetFinding.finding} \u2014 credentials potentially available from breach databases`,
        difficulty: "easy"
      },
      {
        order: 3,
        phase: "Persistence",
        mitreTechnique: "T1098",
        techniqueName: "Account Manipulation",
        targetAsset: targetFinding.hostname,
        evidence: `Once authenticated, adversary can establish persistence via account modification`,
        difficulty: "moderate"
      }
    ];
    const relevantGroups = matchedGroups.filter((g) => g.matchedInitialAccess.some((ia) => ia.toLowerCase().includes("credential") || ia.toLowerCase().includes("brute") || ia.toLowerCase().includes("valid"))).slice(0, 3).map((g) => g.groupName);
    paths.push({
      id: `AP-${++pathId}`,
      name: "Credential-Based Initial Access",
      description: `An adversary leverages compromised credentials from breach databases or credential stuffing to authenticate to ${targetFinding.hostname}. The ${targetFinding.finding} finding indicates potential exposure. Once authenticated, the adversary establishes persistence.`,
      steps,
      overallRisk: Math.min(100, Math.round(targetFinding.severity * 8 + 20)),
      likelihood: 3,
      impact: 4,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map((s) => s.phase))]
    });
  }
  const hasEmailService = [...fingerprint.services].some(
    (s) => ["smtp", "email", "exchange", "mail", "microsoft 365", "google workspace"].some((e) => s.includes(e))
  );
  if (hasEmailService) {
    const emailAsset = analyses.find(
      (a) => (a.asset.technologies || []).some(
        (t) => ["smtp", "email", "exchange", "mail"].some((e) => t.toLowerCase().includes(e))
      )
    );
    const targetHost = emailAsset?.asset.hostname || analyses[0]?.asset.hostname || "target";
    const steps = [
      {
        order: 1,
        phase: "Reconnaissance",
        mitreTechnique: "T1592",
        techniqueName: "Gather Victim Host Information",
        targetAsset: targetHost,
        evidence: `Email infrastructure detected; employee email patterns discoverable via OSINT`,
        difficulty: "trivial"
      },
      {
        order: 2,
        phase: "Initial Access",
        mitreTechnique: "T1566",
        techniqueName: "Phishing",
        targetAsset: targetHost,
        evidence: `Email services present \u2014 spear phishing viable as initial access vector`,
        difficulty: "moderate"
      },
      {
        order: 3,
        phase: "Execution",
        mitreTechnique: "T1059",
        techniqueName: "Command and Scripting Interpreter",
        targetAsset: targetHost,
        evidence: `Post-phishing payload execution via scripting interpreter`,
        difficulty: "moderate"
      },
      {
        order: 4,
        phase: "Command and Control",
        mitreTechnique: "T1071",
        techniqueName: "Application Layer Protocol",
        targetAsset: targetHost,
        evidence: `C2 communication over standard HTTP/HTTPS to blend with legitimate traffic`,
        difficulty: "moderate"
      }
    ];
    const relevantGroups = matchedGroups.filter((g) => g.matchedInitialAccess.some((ia) => ia.toLowerCase().includes("phish"))).slice(0, 3).map((g) => g.groupName);
    paths.push({
      id: `AP-${++pathId}`,
      name: "Spear Phishing to Command & Control",
      description: `An adversary crafts targeted phishing emails leveraging discovered email infrastructure on ${targetHost}. After successful payload delivery, a C2 channel is established over standard protocols to evade detection.`,
      steps,
      overallRisk: 55,
      likelihood: 3,
      impact: 4,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map((s) => s.phase))]
    });
  }
  const kevCves = [...fingerprint.cves].filter((cve) => {
    const f = fingerprint.findings.get(cve);
    return f && f.severity >= 7;
  });
  if (kevCves.length > 0) {
    const topKevCve = kevCves[0];
    const topFinding = fingerprint.findings.get(topKevCve);
    const steps = [
      {
        order: 1,
        phase: "Initial Access",
        mitreTechnique: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        targetAsset: topFinding.hostname,
        evidence: `${topKevCve}: ${topFinding.title} (severity: ${topFinding.severity}/10) \u2014 known exploited vulnerability`,
        difficulty: "easy"
      },
      {
        order: 2,
        phase: "Execution",
        mitreTechnique: "T1059",
        techniqueName: "Command and Scripting Interpreter",
        targetAsset: topFinding.hostname,
        evidence: `Post-exploitation command execution via ${topKevCve}`,
        difficulty: "easy"
      },
      {
        order: 3,
        phase: "Impact",
        mitreTechnique: "T1486",
        techniqueName: "Data Encrypted for Impact",
        targetAsset: topFinding.hostname,
        evidence: `Ransomware deployment possible after gaining execution capability`,
        difficulty: "moderate"
      }
    ];
    const relevantGroups = matchedGroups.filter((g) => g.matchedCVEs.includes(topKevCve)).slice(0, 3).map((g) => g.groupName);
    paths.push({
      id: `AP-${++pathId}`,
      name: "Known Exploited Vulnerability to Ransomware",
      description: `An adversary exploits ${topKevCve} on ${topFinding.hostname}, a known exploited vulnerability with active exploitation in the wild. After gaining code execution, ransomware is deployed for maximum impact. This path represents the highest-confidence threat given the confirmed vulnerability.`,
      steps,
      overallRisk: Math.min(100, Math.round(topFinding.severity * 10 + 15)),
      likelihood: 4,
      impact: 5,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map((s) => s.phase))]
    });
  }
  paths.sort((a, b) => b.overallRisk - a.overallRisk);
  return paths.slice(0, 6);
}
function buildTechniqueHeatmap(matchedGroups, fingerprint) {
  const techniqueMap = /* @__PURE__ */ new Map();
  const allServices = [...fingerprint.services, ...fingerprint.technologies];
  for (const group of matchedGroups) {
    for (const ttp of group.primaryTTPs) {
      const existing = techniqueMap.get(ttp.id);
      if (existing) {
        existing.groups.add(group.groupName);
      } else {
        const relevantServices = TECHNIQUE_SERVICE_MAP[ttp.id] || [];
        const surfaceRelevant = relevantServices.some(
          (svc) => allServices.some((s) => s.includes(svc))
        );
        let relatedFinding = null;
        if (surfaceRelevant) {
          for (const [cve, f] of fingerprint.findings) {
            if (f.severity >= 5) {
              relatedFinding = `${cve} on ${f.hostname}`;
              break;
            }
          }
        }
        techniqueMap.set(ttp.id, {
          name: ttp.name,
          tactic: ttp.tactic,
          groups: /* @__PURE__ */ new Set([group.groupName]),
          surfaceRelevant,
          relatedFinding
        });
      }
    }
    for (const mt of group.matchedTechniques) {
      if (!techniqueMap.has(mt.id)) {
        techniqueMap.set(mt.id, {
          name: mt.name,
          tactic: mt.tactic,
          groups: /* @__PURE__ */ new Set([group.groupName]),
          surfaceRelevant: true,
          relatedFinding: null
        });
      } else {
        techniqueMap.get(mt.id).groups.add(group.groupName);
        techniqueMap.get(mt.id).surfaceRelevant = true;
      }
    }
  }
  return [...techniqueMap.entries()].map(([id, data]) => ({
    techniqueId: id,
    techniqueName: data.name,
    tactic: data.tactic,
    groups: [...data.groups],
    surfaceRelevant: data.surfaceRelevant,
    relatedFinding: data.relatedFinding
  })).sort((a, b) => {
    if (a.surfaceRelevant !== b.surfaceRelevant) return a.surfaceRelevant ? -1 : 1;
    return b.groups.length - a.groups.length;
  });
}
function runDIThreatMatching(analyses, org, kevEnrichment, crossModuleEnrichment) {
  const allGroups = getAllGroups();
  const fingerprint = extractScanFingerprint(analyses, org, kevEnrichment, crossModuleEnrichment);
  const scored = [];
  for (const group of allGroups) {
    const match = scoreGroup(group, fingerprint);
    if (match) scored.push(match);
  }
  scored.sort((a, b) => b.matchScore - a.matchScore);
  const matchedGroups = scored.slice(0, 15);
  const attackPaths = synthesizeAttackPaths(analyses, matchedGroups, fingerprint);
  const techniqueHeatmap = buildTechniqueHeatmap(matchedGroups, fingerprint);
  const allTechniques = /* @__PURE__ */ new Set();
  const allTactics = /* @__PURE__ */ new Set();
  for (const g of matchedGroups) {
    for (const t of g.matchedTechniques) {
      allTechniques.add(t.id);
      allTactics.add(t.tactic);
    }
    for (const t of g.primaryTTPs) {
      allTechniques.add(t.id);
      allTactics.add(t.tactic);
    }
  }
  return {
    matchedGroups,
    attackPaths,
    techniqueHeatmap,
    summary: {
      totalGroupsAnalyzed: allGroups.length,
      totalMatched: matchedGroups.length,
      topGroupName: matchedGroups[0]?.groupName || null,
      topGroupScore: matchedGroups[0]?.matchScore || 0,
      totalAttackPaths: attackPaths.length,
      uniqueTechniques: allTechniques.size,
      uniqueTactics: allTactics.size
    }
  };
}
var TECHNIQUE_SERVICE_MAP, IA_METHOD_SERVICE_MAP;
var init_di_threat_matching = __esm({
  "server/lib/di-threat-matching.ts"() {
    "use strict";
    init_threat_group_knowledge();
    TECHNIQUE_SERVICE_MAP = {
      "T1190": ["http", "https", "web", "apache", "nginx", "iis", "tomcat", "wordpress", "drupal", "joomla", "php", "java", "node", "express", "next.js", "react", "vue"],
      "T1133": ["vpn", "rdp", "ssh", "citrix", "pulse", "fortinet", "paloalto", "sonicwall"],
      "T1078": ["ssh", "rdp", "ftp", "smtp", "imap", "pop3", "ldap", "active directory", "microsoft 365", "google workspace"],
      "T1566": ["smtp", "email", "exchange", "microsoft 365", "google workspace", "mail"],
      "T1059": ["powershell", "cmd", "bash", "python", "javascript", "node"],
      "T1021": ["smb", "rdp", "ssh", "winrm", "wmi", "psexec"],
      "T1110": ["ssh", "rdp", "ftp", "smtp", "http", "https", "ldap", "mysql", "postgres", "mssql"],
      "T1505": ["http", "https", "apache", "nginx", "iis", "tomcat", "php", "asp", "jsp"],
      "T1071": ["http", "https", "dns", "smtp"],
      "T1048": ["ftp", "http", "https", "dns", "smtp", "cloud"],
      "T1053": ["cron", "at", "scheduled task", "systemd"],
      "T1098": ["active directory", "azure ad", "ldap", "iam"],
      "T1136": ["active directory", "ldap", "iam", "cloud"],
      "T1003": ["active directory", "lsass", "sam", "ntds"],
      "T1486": ["smb", "cifs", "nfs", "file server"],
      "T1499": ["http", "https", "dns", "web"],
      "T1595": ["http", "https", "dns", "web", "shodan"],
      "T1592": ["http", "https", "web", "dns"],
      "T1589": ["email", "linkedin", "social media"],
      "T1583": ["dns", "domain", "hosting"],
      "T1588": ["exploit", "malware", "c2"],
      "T1203": ["pdf", "office", "browser", "flash", "java"],
      "T1210": ["smb", "rdp", "ssh", "rpc", "ms17-010", "eternalblue"],
      "T1046": ["nmap", "port scan", "network"],
      "T1018": ["active directory", "dns", "ldap", "network"],
      "T1082": ["system", "os", "kernel"],
      "T1083": ["file system", "smb", "nfs"],
      "T1105": ["http", "https", "ftp", "smb", "dns"],
      "T1027": ["malware", "obfuscation"],
      "T1070": ["log", "syslog", "event log"],
      "T1562": ["edr", "antivirus", "firewall", "waf"],
      "T1219": ["rdp", "vnc", "teamviewer", "anydesk"],
      "T1572": ["ssh", "dns", "http", "https"],
      "T1573": ["ssl", "tls", "https", "c2"],
      "T1041": ["http", "https", "ftp", "dns", "c2"],
      "T1567": ["cloud", "google drive", "dropbox", "onedrive", "s3"],
      "T1557": ["arp", "dns", "llmnr", "nbns", "network"],
      "T1040": ["network", "wireshark", "tcpdump"],
      "T1560": ["archive", "zip", "rar", "7z"],
      "T1114": ["email", "exchange", "microsoft 365", "gmail", "imap"],
      "T1213": ["sharepoint", "confluence", "wiki", "intranet"],
      "T1530": ["s3", "azure blob", "gcs", "cloud storage"],
      "T1552": ["git", "github", "config", "env", "credentials"],
      "T1087": ["active directory", "ldap", "net user"],
      "T1069": ["active directory", "ldap", "group policy"],
      "T1016": ["network", "ipconfig", "ifconfig"],
      "T1049": ["network", "netstat", "ss"],
      "T1518": ["software", "installed programs"],
      "T1047": ["wmi", "wmic", "windows"],
      "T1543": ["systemd", "service", "daemon", "windows service"],
      "T1547": ["registry", "startup", "autorun", "cron"],
      "T1053.005": ["cron", "crontab", "scheduled task"],
      "T1059.001": ["powershell"],
      "T1059.003": ["cmd", "command prompt", "windows"],
      "T1059.004": ["bash", "sh", "linux", "unix"]
    };
    IA_METHOD_SERVICE_MAP = {
      "spear phishing": ["smtp", "email", "exchange", "mail"],
      "phishing": ["smtp", "email", "exchange", "mail"],
      "exploit public-facing application": ["http", "https", "web", "apache", "nginx", "iis", "tomcat"],
      "valid accounts": ["ssh", "rdp", "vpn", "ftp", "smtp"],
      "external remote services": ["vpn", "rdp", "ssh", "citrix"],
      "drive-by compromise": ["http", "https", "web"],
      "supply chain compromise": ["npm", "pypi", "maven", "docker", "github"],
      "trusted relationship": ["vpn", "api", "oauth"],
      "hardware additions": ["usb", "physical"],
      "replication through removable media": ["usb", "physical"],
      "brute force": ["ssh", "rdp", "ftp", "http", "smtp", "mysql", "postgres"],
      "default credentials": ["ssh", "ftp", "telnet", "http", "snmp"],
      "sql injection": ["http", "https", "mysql", "postgres", "mssql", "web"],
      "remote code execution": ["http", "https", "web", "rpc", "smb"],
      "watering hole": ["http", "https", "web", "dns"]
    };
  }
});

// server/lib/tech-stack-grouping.ts
function generateStackFingerprint(technologies, technologyVersions) {
  if (!technologies || technologies.length === 0) return "__no_tech__";
  const normalized = technologies.map((t) => t.trim()).filter(Boolean).map((t) => {
    const version = technologyVersions?.[t] || null;
    const normName = t.toLowerCase();
    const normVersion = version ? normalizeMajorMinor(version) : "unknown";
    return `${normName}@${normVersion}`;
  }).sort().join("|");
  return normalized || "__no_tech__";
}
function normalizeMajorMinor(version) {
  const match = version.match(/^(\d+\.\d+)/);
  return match ? match[1] : version;
}
function createStackLabel(technologies) {
  const sorted = [...technologies].sort((a, b) => a.name.localeCompare(b.name));
  const shown = sorted.slice(0, 4);
  const label = shown.map((t) => t.version ? `${t.name} ${t.version}` : t.name).join(" + ");
  if (sorted.length > 4) {
    return `${label} +${sorted.length - 4} more`;
  }
  return label;
}
function riskBand(score) {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}
function computeTechStackGrouping(analyses) {
  if (!analyses || analyses.length === 0) {
    return {
      groups: [],
      mostWidespreadVulns: [],
      summary: {
        totalGroups: 0,
        totalAssets: 0,
        largestGroupSize: 0,
        largestGroupLabel: "N/A",
        averageGroupSize: 0,
        stackOverlapPercentage: 0,
        uniqueStacks: 0
      }
    };
  }
  const groupMap = /* @__PURE__ */ new Map();
  for (const a of analyses) {
    const techs = a.asset.technologies || [];
    const versions = a.asset.technologyVersions || {};
    const fp = generateStackFingerprint(techs, versions);
    if (!groupMap.has(fp)) {
      groupMap.set(fp, {
        fingerprint: fp,
        technologies: techs.map((t) => ({
          name: t,
          version: versions[t] || null
        })),
        assets: []
      });
    }
    groupMap.get(fp).assets.push(a);
  }
  const cveToAssets = /* @__PURE__ */ new Map();
  for (const a of analyses) {
    const fp = generateStackFingerprint(
      a.asset.technologies || [],
      a.asset.technologyVersions || {}
    );
    for (const f of a.postureFindings) {
      if (f.cveIds) {
        for (const cve of f.cveIds) {
          if (!cveToAssets.has(cve)) {
            cveToAssets.set(cve, {
              cveId: cve,
              title: f.title || cve,
              severity: f.severity,
              cvssScore: f.cvssScore ?? null,
              kevListed: !!f.kevListed,
              exploitAvailable: !!f.exploitAvailable,
              corroborationTier: f.corroborationTier || "potential",
              assetHostnames: /* @__PURE__ */ new Set(),
              stackFingerprints: /* @__PURE__ */ new Set()
            });
          }
          const entry = cveToAssets.get(cve);
          entry.assetHostnames.add(a.asset.hostname);
          entry.stackFingerprints.add(fp);
          if (f.corroborationTier === "confirmed") entry.corroborationTier = "confirmed";
          else if (f.corroborationTier === "probable" && entry.corroborationTier !== "confirmed") entry.corroborationTier = "probable";
          if (f.severity > entry.severity) entry.severity = f.severity;
          if (f.cvssScore && (!entry.cvssScore || f.cvssScore > entry.cvssScore)) entry.cvssScore = f.cvssScore;
          if (f.kevListed) entry.kevListed = true;
          if (f.exploitAvailable) entry.exploitAvailable = true;
        }
      }
    }
  }
  const groups = [];
  for (const [fp, group] of groupMap) {
    const assetHostnames = group.assets.map((a) => a.asset.hostname);
    const assetSet = new Set(assetHostnames);
    const sharedCves = [];
    const groupUniqueCves = /* @__PURE__ */ new Set();
    for (const [cve, cveData] of cveToAssets) {
      const affectedInGroup = [...cveData.assetHostnames].filter((h) => assetSet.has(h));
      if (affectedInGroup.length > 0) {
        groupUniqueCves.add(cve);
        if (affectedInGroup.length === group.assets.length && group.assets.length > 1) {
          sharedCves.push({
            cveId: cve,
            title: cveData.title,
            severity: cveData.severity,
            cvssScore: cveData.cvssScore,
            kevListed: cveData.kevListed,
            corroborationTier: cveData.corroborationTier,
            affectedAssetCount: affectedInGroup.length,
            exploitAvailable: cveData.exploitAvailable
          });
        }
      }
    }
    sharedCves.sort((a, b) => b.severity - a.severity || (b.cvssScore || 0) - (a.cvssScore || 0));
    const riskScores = group.assets.map((a) => a.hybridRiskScore || 0);
    const avgRisk = riskScores.length > 0 ? Math.round(riskScores.reduce((s, v) => s + v, 0) / riskScores.length) : 0;
    const maxRisk = riskScores.length > 0 ? Math.max(...riskScores) : 0;
    const tierCounts = /* @__PURE__ */ new Map();
    for (const a of group.assets) {
      const tier = a.suggestedTier || "unknown";
      tierCounts.set(tier, (tierCounts.get(tier) || 0) + 1);
    }
    const primaryTier = [...tierCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown";
    groups.push({
      fingerprint: fp,
      stackLabel: createStackLabel(group.technologies),
      technologies: group.technologies,
      assetHostnames,
      assetCount: group.assets.length,
      sharedCves: sharedCves.slice(0, 20),
      // Top 20 shared CVEs
      totalUniqueCves: groupUniqueCves.size,
      avgRiskScore: avgRisk,
      maxRiskScore: maxRisk,
      riskBand: riskBand(avgRisk),
      primaryTier
    });
  }
  groups.sort((a, b) => b.assetCount - a.assetCount);
  const totalAssets = analyses.length;
  const mostWidespreadVulns = Array.from(cveToAssets.values()).filter((c) => c.assetHostnames.size > 1).sort((a, b) => b.assetHostnames.size - a.assetHostnames.size).slice(0, 20).map((c) => ({
    cveId: c.cveId,
    title: c.title,
    severity: c.severity,
    cvssScore: c.cvssScore,
    kevListed: c.kevListed,
    exploitAvailable: c.exploitAvailable,
    affectedAssetCount: c.assetHostnames.size,
    affectedPercentage: Math.round(c.assetHostnames.size / totalAssets * 100),
    stackGroups: [...c.stackFingerprints],
    corroborationTier: c.corroborationTier
  }));
  const multiAssetGroups = groups.filter((g) => g.assetCount > 1);
  const assetsInMultiGroups = multiAssetGroups.reduce((s, g) => s + g.assetCount, 0);
  const largestGroup = groups[0];
  return {
    groups,
    mostWidespreadVulns,
    summary: {
      totalGroups: groups.length,
      totalAssets,
      largestGroupSize: largestGroup?.assetCount || 0,
      largestGroupLabel: largestGroup?.stackLabel || "N/A",
      averageGroupSize: groups.length > 0 ? Math.round(totalAssets / groups.length * 10) / 10 : 0,
      stackOverlapPercentage: totalAssets > 0 ? Math.round(assetsInMultiGroups / totalAssets * 100) : 0,
      uniqueStacks: groups.length
    }
  };
}
var init_tech_stack_grouping = __esm({
  "server/lib/tech-stack-grouping.ts"() {
    "use strict";
  }
});

// server/domainIntel.ts
async function invokeLLMWithTimeout(params, timeoutMs = LLM_TIMEOUT_MS) {
  const paramsWithTimeout = { ...params, _timeoutMs: timeoutMs };
  const timeoutPromise = new Promise(
    (_, reject) => setTimeout(() => reject(new Error(`LLM timeout after ${timeoutMs}ms`)), timeoutMs + 5e3)
    // 5s grace over fetch timeout
  );
  return Promise.race([invokeLLM({ _caller: "domainIntel", ...paramsWithTimeout }), timeoutPromise]);
}
function clamp(x, lo, hi) {
  return Math.max(lo, Math.min(hi, x));
}
async function discoverAssets(org, fpContext, passiveContext) {
  const allDomains = [org.primaryDomain, ...org.additionalDomains || []];
  let fpLearningBlock = "";
  if (fpContext && fpContext.patterns.length > 0) {
    const fpLines = fpContext.patterns.slice(0, 20).map(
      (p) => `  - "${p.title}" (type: ${p.type || "unknown"}, marked ${p.occurrences}x) \u2014 Analyst reason: ${p.reason}`
    ).join("\n");
    fpLearningBlock = `

ANALYST FEEDBACK (False Positive History):
The following finding patterns have been previously marked as false positives by security analysts. Use these insights to calibrate your asset discovery \u2014 avoid inferring assets that consistently produce these false positive patterns unless you have strong evidence they exist:
${fpLines}
`;
  }
  const prompt = `You are a passive OSINT reconnaissance analyst. Given the following organization profile, infer and enumerate likely digital assets that would exist for this organization. This is PASSIVE analysis only - no active scanning.

Organization:
- Name: ${org.customerName}
- Primary Domain: ${org.primaryDomain}
- Additional Domains: ${(org.additionalDomains || []).join(", ") || "none"}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${(org.criticalFunctions || []).join(", ") || "none specified"}
- Compliance: ${(org.complianceFlags || []).join(", ") || "none specified"}
- Notes: ${org.notes || "none"}${fpLearningBlock}${passiveContext || ""}

For each domain (${allDomains.join(", ")}), ${passiveContext ? "use the PASSIVE RECONNAISSANCE DATA above as your PRIMARY AND AUTHORITATIVE source. ONLY include assets that appear in the passive recon data (confirmed subdomains, IPs, services from crt.sh, Shodan, Censys, SecurityTrails, etc.). You may add a SMALL number (max 3-5) of high-confidence inferences" : "infer likely subdomains, services, and assets"} based on:
1. Common subdomain patterns for this sector and client type
2. Expected technology stack based on sector
3. Likely email infrastructure (MX, SPF, DMARC patterns)
4. Common SaaS/cloud services for this sector
5. Authentication endpoints (SSO, VPN, OWA)
6. Developer/API endpoints
7. Customer-facing portals
8. Internal tools likely exposed

For each asset, classify it and assess its exposure level.

Return a JSON array of discovered assets. Each asset must have:
{
  "assetId": "a-001",
  "hostname": "subdomain.domain.com",
  "url": "https://subdomain.domain.com",
  "assetType": "sso|mail_gateway|api|payment|cdn|vpn|owa|crm|erp|dev|ci_cd|storage|database|monitoring|customer_portal|admin_panel|other",
  "technologies": ["nginx", "Microsoft 365", etc],
  "technologyVersions": {"nginx": "1.18.0", "OpenSSL": "1.1.1", etc},  // Include version numbers when they can be reasonably inferred from sector/client type patterns. Use null for unknown versions.
  "assetClasses": ["identity_provider", "email_infrastructure", etc],
  "tags": ["internet_exposed", "authentication", "critical_data", etc],
  "description": "Brief description of what this asset likely does",
  "dnsRecords": {"A": [], "CNAME": [], "MX": [], "TXT": [], "NS": []},
  "headers": "likely server headers"
}

IMPORTANT: For the "technologyVersions" field, only include version numbers you have HIGH confidence about based on:
- Common default versions for this sector/client type
- Versions implied by other technology choices (e.g., if using Ubuntu 22.04, OpenSSL is likely 3.0.x)
- DO NOT guess random version numbers. If you cannot reasonably infer the version, omit that technology from technologyVersions.

CRITICAL DATA INTEGRITY RULES:
- Assets from passive recon data are CONFIRMED \u2014 mark discoveryMethod as "cert_transparency" or "dns_verified"
- Assets you infer (not in passive recon) are HYPOTHESES \u2014 mark discoveryMethod as "inferred"
- NEVER invent fake version numbers, CVE IDs, or service details
- If passive recon found 50 subdomains, include ALL of them \u2014 do not truncate
- If no passive recon data is available, generate max 10 conservative guesses (root domain + common patterns only)

ASSET DEDUPLICATION & SCOPING RULES:
- ONE ASSET PER UNIQUE HOSTNAME \u2014 do NOT create separate assets for different URL paths, query strings, or static files on the same host. For example, if rapidtalentgroup.com serves /_next/static/*, /_next/image, /api/*, etc., these are ALL part of the single "rapidtalentgroup.com" asset.
- The "url" field should be the root URL of the hostname (e.g., https://subdomain.domain.com), NOT a specific path or resource URL.
- Do NOT create assets for individual JavaScript files, CSS files, images, API endpoints, or static resources \u2014 these are resources served by a host, not separate assets.
- Do NOT create assets for third-party SaaS provider hostnames that the organization does not own or operate. Examples: outlook.office365.com, login.microsoftonline.com, mail.google.com, accounts.google.com, *.salesforce.com, *.zendesk.com, *.cloudflare.com. Instead, note the SaaS dependency as a tag on the root domain asset (e.g., tags: ["uses_o365", "uses_cloudflare"]).
- Do NOT create assets for DNS infrastructure (nameservers, SOA records). NS records like dns1.p02.nsone.net are third-party DNS providers, not target assets. Record DNS provider info as metadata on the root domain.
- Do NOT create assets for MX record hostnames that point to third-party email providers (e.g., *.mail.protection.outlook.com, aspmx.l.google.com). Note the email provider as a tag on the root domain.
- TECHNOLOGY LIST ACCURACY: Do NOT list server-side products managed by a third-party provider as technologies on the client's assets. For example, if MX records point to Microsoft 365 (*.mail.protection.outlook.com), list "Microsoft 365" as the technology \u2014 NOT "Microsoft Exchange" or "Exchange Server". The client uses M365 as a SaaS service; they do NOT run Exchange Server on-premise. Similarly, if email is Google Workspace, do NOT list "Gmail Server" \u2014 list "Google Workspace". Only list server products (Exchange, Postfix, Sendmail, etc.) when there is evidence the client operates their own mail server.

Generate assets based on passive recon data. Be specific to the sector and client type. For ${org.clientType} clients, emphasize:
${org.clientType === "msp" ? "- Multi-tenant management portals, RMM tools, PSA platforms, client VPN endpoints, backup systems" : ""}
${org.clientType === "enterprise" ? "- Corporate SSO, Active Directory, Exchange/O365, ERP systems, internal wikis, VPN concentrators" : ""}
${org.clientType === "saas" ? "- API endpoints, customer dashboards, billing portals, CI/CD pipelines, staging environments" : ""}
${org.clientType === "paas" ? "- Container registries, orchestration dashboards, developer portals, build systems" : ""}
${org.clientType === "iaas" ? "- Cloud consoles, hypervisor management, storage APIs, network management, tenant isolation" : ""}
${org.clientType === "mixed_hosting" ? "- Shared hosting panels, dedicated server management, DNS management, billing, support portals" : ""}

Return ONLY the JSON array, no markdown fences.`;
  try {
    const response = await invokeLLMWithTimeout({
      _priority: "standard",
      messages: [
        { role: "system", content: "You are a cybersecurity OSINT analyst. Return only valid JSON arrays." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" }
    });
    const content = response.choices?.[0]?.message?.content;
    const parsed = safeParseLLMJson(content, { assets: [] });
    const rawAssets = Array.isArray(parsed) ? parsed : parsed.assets || [];
    const validRealMethods = /* @__PURE__ */ new Set(["cert_transparency", "dns_verified", "header_detected"]);
    return rawAssets.map((a) => {
      const claimedMethod = a.discoveryMethod || "inferred";
      const isRealMethod = validRealMethods.has(claimedMethod) && !!passiveContext;
      return {
        ...a,
        discoveryMethod: isRealMethod ? claimedMethod : "inferred",
        discoveryEvidence: a.discoveryEvidence || `Inferred from ${org.sector} ${org.clientType} patterns for ${org.primaryDomain}`,
        _provenance: isRealMethod ? "passive_recon_confirmed" : "llm_inferred"
      };
    });
  } catch (err) {
    console.error("[DomainIntel] Discovery failed:", err);
    return generateFallbackAssets(org);
  }
}
function generateFallbackAssets(org) {
  console.warn(`[DomainIntel] LLM asset discovery failed for ${org.primaryDomain}. Returning only root domain \u2014 all other assets must come from passive recon connectors.`);
  return [
    {
      assetId: `root-${org.primaryDomain.replace(/\./g, "-")}`,
      hostname: org.primaryDomain,
      url: `https://${org.primaryDomain}`,
      assetType: "other",
      assetClasses: ["dns_root"],
      tags: ["internet_exposed"],
      description: "Root domain (LLM discovery failed \u2014 only passive recon data available)",
      discoveryMethod: "inferred",
      discoveryEvidence: "Primary domain root \u2014 LLM discovery fallback"
    }
  ];
}
async function analyzeAssets(assets, org, fpContext, historicalContext) {
  let fpCalibrationBlock = "";
  if (fpContext && fpContext.patterns.length > 0) {
    const fpLines = fpContext.patterns.slice(0, 30).map(
      (p) => `  - "${p.title}" (type: ${p.type || "unknown"}, severity: ${p.severity || "?"}, marked FP ${p.occurrences}x) \u2014 Analyst reason: ${p.reason}`
    ).join("\n");
    const catLines = fpContext.categorySummary.slice(0, 10).map(
      (c) => `  - ${c.type}: ${c.count} false positives`
    ).join("\n");
    fpCalibrationBlock = `

ANALYST FALSE POSITIVE FEEDBACK:
Security analysts have reviewed previous scan results and marked the following findings as false positives. Use this feedback to CALIBRATE your severity and likelihood scores \u2014 reduce confidence for finding patterns that analysts consistently reject, and avoid generating findings that match these known FP patterns unless you have strong new evidence:

Known FP Patterns:
${fpLines}

FP Rates by Category:
${catLines}

IMPORTANT: This feedback represents real analyst expertise. Findings matching these patterns should have LOWER severity and confidence scores unless new evidence contradicts the analyst's assessment.
`;
  }
  const prompt = `You are a cybersecurity risk analyst performing Business Impact Analysis using the CARVER+SHOCK methodology combined with hybrid risk scoring.

Organization Profile:
- Name: ${org.customerName}
- Domain: ${org.primaryDomain}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${(org.criticalFunctions || []).join(", ") || "none specified"}
- Compliance: ${(org.complianceFlags || []).join(", ") || "none"}

Discovered Assets (${assets.length} total):
${JSON.stringify(assets.map((a) => ({ id: a.assetId, hostname: a.hostname, type: a.assetType, classes: a.assetClasses, tags: a.tags, desc: a.description })), null, 2)}

For EACH asset, provide:

1. CARVER Scores (each 0-10):
   - Criticality: How critical is this asset to the organization's mission?
   - Accessibility: How accessible is this asset to an attacker?
   - Recuperability: How quickly can the org recover if this asset is compromised?
   - Vulnerability: How vulnerable is this asset based on its type and exposure?
   - Effect: What is the cascading effect of compromising this asset?
   - Recognizability: How easily can an attacker identify this as a valuable target?

2. SHOCK Scores (each 0-10):
   - Scope: How many people/systems are affected?
   - Handling: How difficult is incident response for this asset?
   - OperationalImpact: Direct impact on business operations?
   - CascadingEffects: Downstream failures from compromise?
   - Knowledge: Attacker knowledge required (inverse - low knowledge = high score)?

3. CVSS Estimate (0-10): Based on likely vulnerabilities for this asset type

4. Context Indicators (each 0-1):
   - exposure: Internet exposure level
   - recognizability: How easily identified as belonging to this org
   - confidence: Confidence in the assessment

5. Suggested Tier: tier0_critical, tier1_high, tier2_medium, tier3_low

6. Posture Findings: Security weaknesses identified (array of objects with id, category, title, severity 0-10, likelihood 0-10, confidence 0-1, recommendedControls[], cveIds[] (known CVE IDs if applicable - MUST be real CVE IDs like CVE-2024-XXXXX, do NOT invent fake CVE IDs))

DATA INTEGRITY RULES:
- For assets with discoveryMethod "inferred": set confidence to 0.3 or lower and add tag "unverified_hypothesis"
- For assets with discoveryMethod "cert_transparency" or "dns_verified": these are REAL and can have higher confidence
- NEVER invent CVE IDs. Only reference CVEs you are certain exist (e.g., CVE-2021-44228 for Log4Shell)
- CVSS estimates should be conservative (lower) for inferred assets and more precise for verified assets
- Posture findings for inferred assets should be marked with lower confidence (0.1-0.3)
   
   CRITICAL EVIDENCE RULES FOR POSTURE FINDINGS:
   - CONFIRMED findings: You have specific version info AND a matching real CVE. Severity can be 7-10. Likelihood can be 7-10.
   - PROBABLE findings: You know the technology family but NOT the version. Severity capped at 6. Likelihood capped at 6.
   - POTENTIAL findings: No version, no CVE \u2014 purely inferred from asset type. Severity capped at 5. Likelihood capped at 5.
   - ONLY confirmed findings with version-matched CVEs will drive the final risk rating. Potential findings are recorded as weaknesses but DO NOT affect the risk score.
   - Generic or theoretical risks (e.g., "web server might have XSS") are POTENTIAL \u2014 severity 3-5 max.
   - Do NOT inflate findings. If you cannot confirm a specific vulnerability, mark it as potential.
   - NEVER generate email security findings (missing DMARC, SPF, DKIM, email spoofing, email authentication) for ANY asset that is not a mail server (assetType 'mail_gateway'). This includes web servers, API endpoints, SSO portals, VPNs, admin panels, CDNs, load balancers, databases, CI/CD pipelines, monitoring tools, and all other non-mail assets. Email security analysis is handled separately by the dedicated email security analyzer and will only be assigned to mail-related assets. If an asset's assetType is not 'mail_gateway', do NOT create any findings with 'DMARC', 'SPF', 'DKIM', 'email security', 'email spoofing', or 'mail' in the title or category.

7. Test Vectors: Suggested attack vectors (array of objects with id, vectorType, hypothesis, suggestedEmulation {technique, tactic}, expectedTelemetry[], riskSignal {severity, likelihood})

8. Mission Function Classification (REQUIRED for each asset):
   Classify each asset's role in the organization's mission-essential functions:
   - missionFunction: One of: command_and_control, revenue_generation, customer_data_processing, intellectual_property_storage, authentication_and_access, communication_infrastructure, regulatory_compliance, business_continuity, supply_chain_integration, public_facing_services
   - essentialService: Specific service type, one of: sso_idp, active_directory, payment_processing, email_gateway, vpn_concentrator, dns_infrastructure, database_primary, database_replica, load_balancer, web_application_firewall, api_gateway, ci_cd_pipeline, monitoring_alerting, backup_recovery, file_storage, certificate_authority, secrets_management, container_orchestration, message_queue, cdn_edge, erp_system, crm_system, scada_hmi, medical_device, pos_terminal, voip_pbx, print_server, general_server
   - businessImpactLevel: One of: catastrophic, severe, significant, moderate, minimal
     * catastrophic: Complete mission failure, existential threat to organization
     * severe: Major mission degradation, significant financial/operational impact
     * significant: Noticeable mission impact, requires immediate attention
     * moderate: Limited impact, workarounds available
     * minimal: Negligible operational impact
   - deviceType: One of: server, workstation, network_appliance, iot_device, mobile_device, virtual_machine, container, cloud_service, embedded_system, unknown
   - platformType: One of: windows_server, linux_server, cloud_saas, cloud_iaas, cloud_paas, network_os, firmware, web_application, mobile_app, database_engine, unknown
   - missionJustification: Brief explanation of WHY this asset is critical to the identified mission function (1-2 sentences)

Return JSON with this exact structure:
{
  "analyses": [
    {
      "assetId": "a-001",
      "carverScores": { "criticality": 8, "accessibility": 7, ... },
      "shockScores": { "scope": 6, "handling": 7, ... },
      "cvssEstimate": 7.5,
      "contextIndicators": { "exposure": 0.6, "recognizability": 0.5, "confidence": 0.4 },
      "suggestedTier": "tier2_medium",
      "postureFindings": [...],
      "testVectors": [...],
      "missionFunction": "authentication_and_access",
      "essentialService": "sso_idp",
      "businessImpactLevel": "severe",
      "deviceType": "cloud_service",
      "platformType": "cloud_saas",
      "missionJustification": "SSO portal is the single authentication gateway for all employees; compromise grants lateral access to every connected system."
    }
  ]
}

SCORING CALIBRATION (CRITICAL):
- CARVER/SHOCK scores drive IMPACT (how bad if compromised), NOT the final risk rating. Score 3-6 for most assets. Only mission-critical assets (primary auth, payment, core DB) warrant 7+.
- CVSS estimate is a PLACEHOLDER only \u2014 it will be overridden by confirmed vulnerability data from KEV/NVD feeds. Set it conservatively: 2-3 for assets with no known vulns, 4-5 for assets with probable vulns, 7+ ONLY if you can cite a specific real CVE with version evidence.
- Confidence should be LOW (0.2-0.4) when you have no version info or confirmed vulnerabilities. Only use 0.6+ with specific version evidence. Only use 0.8+ with confirmed CVE + version match.
- The final risk score = sqrt(Impact \xD7 Likelihood). Likelihood is driven ONLY by confirmed/probable vulnerabilities. An asset with high CARVER scores but no confirmed vulns will correctly score LOW risk.
- A typical scan should produce: ~5-10% critical (confirmed CVEs on critical assets), ~15-25% high, ~40-50% medium, ~20-30% low. If most assets are critical/high, your scores are inflated.
- CDNs, static sites, and informational pages are LOW risk (tier3). APIs and SSO are MEDIUM unless specific vulns are confirmed.

Be thorough and realistic. Score based on the specific sector (${org.sector}) and client type (${org.clientType}).${fpCalibrationBlock}${historicalContext ? `

${historicalContext}

When analyzing assets, compare against the historical data above. For assets that appeared in the previous scan:
- Note whether their risk profile has changed
- Flag any NEW findings not present before
- Indicate if previously identified vulnerabilities appear to be remediated
- Adjust confidence scores upward for findings that persist across scans (confirmed by repeated observation)` : ""}`;
  try {
    const response = await invokeLLMWithTimeout({
      _priority: "essential",
      messages: [
        { role: "system", content: "You are a cybersecurity risk analyst. Return only valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" }
    });
    const content = response.choices?.[0]?.message?.content;
    const parsed = safeParseLLMJson(content, { analyses: [] });
    const analysesMap = /* @__PURE__ */ new Map();
    for (const a of parsed.analyses || []) {
      analysesMap.set(a.assetId, a);
    }
    return assets.map((asset) => {
      const analysis = analysesMap.get(asset.assetId) || {};
      const carver = normalizeCarver(analysis.carverScores || {});
      const shock = normalizeShock(analysis.shockScores || {});
      const hasAnalysis = !!analysesMap.get(asset.assetId);
      const cvss = clamp(analysis.cvssEstimate || (hasAnalysis ? 4 : 3), 0, 10);
      const ctx = {
        exposure: clamp(analysis.contextIndicators?.exposure || (hasAnalysis ? 0.5 : 0.3), 0, 1),
        recognizability: clamp(analysis.contextIndicators?.recognizability || (hasAnalysis ? 0.5 : 0.3), 0, 1),
        confidence: clamp(analysis.contextIndicators?.confidence || (hasAnalysis ? 0.5 : 0.3), 0, 1)
      };
      const missionImpact = computeMissionImpact(carver, shock);
      const hybrid = computeHybridRisk(cvss, missionImpact, ctx);
      return {
        asset,
        carverScores: carver,
        shockScores: shock,
        missionImpactScore: Math.round(missionImpact * 10) / 10,
        suggestedTier: analysis.suggestedTier || inferTier(hybrid.score),
        hybridRiskScore: Math.round(hybrid.score),
        riskBand: hybrid.band,
        cvssEstimate: Math.round(cvss * 10) / 10,
        contextIndicators: ctx,
        postureFindings: (analysis.postureFindings || []).map((f, i) => {
          const hasCveIds = f.cveIds && f.cveIds.length > 0;
          const tier = hasCveIds ? "probable" : "potential";
          const severityCap = tier === "potential" ? 4 : tier === "probable" ? 6 : 10;
          const rawSeverity = clamp(f.severity || 4, 0, 10);
          const cappedSeverity = Math.min(rawSeverity, severityCap);
          const evidenceChain = [
            `Asset "${asset.hostname}" identified as ${asset.assetType} (discovery: ${asset.discoveryMethod || "inferred"})`
          ];
          if (hasCveIds) {
            evidenceChain.push(`CVE(s) ${f.cveIds.join(", ")} associated with ${asset.assetType} product family`);
            evidenceChain.push(`No specific version detected \u2014 product-family match only (severity capped at ${severityCap}/10)`);
          } else {
            evidenceChain.push(`Risk inferred by LLM analysis \u2014 no specific CVE or version evidence`);
            evidenceChain.push(`Advisory only \u2014 severity capped at ${severityCap}/10 pending corroboration`);
          }
          return {
            id: f.id || `pf-${asset.assetId}-${i}`,
            assetRef: asset.assetId,
            assetHostname: asset.hostname,
            category: f.category || "general",
            title: f.title || "Finding",
            severity: cappedSeverity,
            likelihood: clamp(f.likelihood || 3, 0, tier === "potential" ? 5 : 10),
            confidence: clamp(f.confidence || 0.4, 0, 1),
            recommendedControls: f.recommendedControls || [],
            cveIds: f.cveIds || [],
            kevListed: false,
            exploitAvailable: false,
            affectedAssets: [asset.hostname],
            evidenceBasis: hasCveIds ? "technology_match" : "llm_inference",
            evidenceDetail: hasCveIds ? `Product-family match: CVE(s) ${f.cveIds.join(", ")} affect ${asset.assetType} products. Version not confirmed \u2014 finding is PROBABLE, not confirmed.` : `Inferred by LLM analysis of ${asset.assetType} asset (${asset.hostname}). No CVE or version evidence \u2014 finding is POTENTIAL only.`,
            corroborationTier: tier,
            evidenceChain
          };
        }),
        testVectors: (analysis.testVectors || []).map((v, i) => ({
          id: v.id || `tv-${asset.assetId}-${i}`,
          assetRef: asset.hostname,
          vectorType: v.vectorType || "unknown",
          hypothesis: v.hypothesis || "",
          prerequisites: v.prerequisites || ["Authorized environment"],
          suggestedEmulation: v.suggestedEmulation || {},
          expectedTelemetry: v.expectedTelemetry || [],
          riskSignal: { severity: v.riskSignal?.severity || 5, likelihood: v.riskSignal?.likelihood || 5 }
        })),
        confidence: Math.round(ctx.confidence * 100),
        // Separated scores — computed after postureFindings are built
        assetCriticalityScore: computeAssetCriticality(missionImpact).score,
        assetCriticalityBand: computeAssetCriticality(missionImpact).band,
        // vulnRiskScore will be 0 at this stage — recalculated after vuln feed enrichment
        vulnRiskScore: 0,
        vulnRiskBand: "low",
        // Impact × Likelihood decomposition
        impactScore: hybrid.impactScore,
        likelihoodScore: hybrid.likelihoodScore,
        // Mission Function Classification (from LLM)
        missionFunction: analysis.missionFunction || "public_facing_services",
        essentialService: analysis.essentialService || "general_server",
        businessImpactLevel: analysis.businessImpactLevel || "moderate",
        deviceType: analysis.deviceType || "unknown",
        platformType: analysis.platformType || "unknown",
        missionJustification: analysis.missionJustification || ""
      };
    });
  } catch (err) {
    console.error("[DomainIntel] Analysis failed:", err);
    return assets.map((asset) => createDefaultAnalysis(asset));
  }
}
function normalizeMissionFunction(llmValue) {
  const MISSION_FUNCTION_MAP = {
    "command_and_control": "command_control",
    "command_control": "command_control",
    "revenue_generation": "revenue_generation",
    "customer_data_processing": "customer_data",
    "customer_data": "customer_data",
    "intellectual_property_storage": "intellectual_property",
    "intellectual_property": "intellectual_property",
    "authentication_and_access": "authentication",
    "authentication": "authentication",
    "communication_infrastructure": "external_communication",
    "external_communication": "external_communication",
    "regulatory_compliance": "compliance",
    "compliance": "compliance",
    "business_continuity": "operational_continuity",
    "operational_continuity": "operational_continuity",
    "supply_chain_integration": "supply_chain",
    "supply_chain": "supply_chain",
    "public_facing_services": "external_communication",
    "data_processing": "data_processing"
  };
  const mapped = MISSION_FUNCTION_MAP[llmValue];
  if (!mapped) {
    console.warn(`[DomainIntel] Unknown missionFunction '${llmValue}' \u2014 no baseline will be applied`);
  }
  return mapped || llmValue;
}
function normalizeEssentialService(llmValue) {
  const SERVICE_MAP = {
    "sso_idp": "sso",
    "active_directory": "active_directory",
    "payment_processing": "payment_processing",
    "email_gateway": "email",
    "vpn_concentrator": "vpn",
    "dns_infrastructure": "dns",
    "database_primary": "database",
    "database_replica": "database",
    "load_balancer": "load_balancer",
    "web_application_firewall": "waf",
    "api_gateway": "api_gateway",
    "ci_cd_pipeline": "ci_cd",
    "monitoring_alerting": "siem",
    "backup_recovery": "backup",
    "file_storage": "backup",
    "certificate_authority": "encryption_key_management",
    "secrets_management": "encryption_key_management",
    "container_orchestration": "ci_cd",
    "message_queue": "api_gateway",
    "cdn_edge": "load_balancer",
    "erp_system": "erp",
    "crm_system": "customer_portal",
    "scada_hmi": "critical_infrastructure",
    "medical_device": "critical_infrastructure",
    "pos_terminal": "payment_processing",
    "voip_pbx": "email",
    "print_server": "general_server",
    "general_server": "general_server",
    "source_control": "source_control",
    "firewall": "firewall"
  };
  return SERVICE_MAP[llmValue] || llmValue;
}
function normalizeCarver(raw) {
  return {
    criticality: clamp(raw.criticality || 3, 0, 10),
    accessibility: clamp(raw.accessibility || 3, 0, 10),
    recuperability: clamp(raw.recuperability || 3, 0, 10),
    vulnerability: clamp(raw.vulnerability || 3, 0, 10),
    effect: clamp(raw.effect || 3, 0, 10),
    recognizability: clamp(raw.recognizability || 3, 0, 10)
  };
}
function normalizeShock(raw) {
  return {
    scope: clamp(raw.scope || 3, 0, 10),
    handling: clamp(raw.handling || 3, 0, 10),
    operationalImpact: clamp(raw.operationalImpact || 3, 0, 10),
    cascadingEffects: clamp(raw.cascadingEffects || 3, 0, 10),
    knowledge: clamp(raw.knowledge || 3, 0, 10)
  };
}
function computeMissionImpact(carver, shock) {
  const carverWeights = { criticality: 2, accessibility: 1.5, recuperability: 1, vulnerability: 1.5, effect: 1.5, recognizability: 0.5 };
  const shockWeights = { scope: 1.5, handling: 1, operationalImpact: 2, cascadingEffects: 1.5, knowledge: 1 };
  let carverSum = 0, carverW = 0;
  for (const [k, w] of Object.entries(carverWeights)) {
    carverSum += carver[k] * w;
    carverW += w;
  }
  const carverScore = carverSum / carverW;
  let shockSum = 0, shockW = 0;
  for (const [k, w] of Object.entries(shockWeights)) {
    shockSum += shock[k] * w;
    shockW += w;
  }
  const shockScore = shockSum / shockW;
  return (carverScore + shockScore) / 2;
}
function computeHybridRisk(cvss, missionImpact, ctx, confirmedVulnScore, portLikelihoodBoost) {
  const impact = clamp(missionImpact / 10, 0, 1);
  let likelihoodBase;
  if (confirmedVulnScore !== void 0) {
    const vulnNorm = clamp(confirmedVulnScore / 100, 0, 1);
    if (vulnNorm === 0) {
      likelihoodBase = clamp(ctx.exposure * 0.1 + ctx.recognizability * 0.05, 0, 0.15);
    } else {
      likelihoodBase = vulnNorm;
      likelihoodBase += (ctx.exposure - 0.5) * 0.2;
      likelihoodBase += (ctx.recognizability - 0.5) * 0.1;
    }
  } else {
    likelihoodBase = clamp(ctx.exposure * 0.1 + ctx.recognizability * 0.05, 0, 0.15);
  }
  likelihoodBase = clamp(likelihoodBase, 0, 1);
  if (portLikelihoodBoost && portLikelihoodBoost > 0) {
    likelihoodBase = clamp(likelihoodBase + portLikelihoodBoost, 0, 1);
  }
  const confidenceDampening = 0.55 + ctx.confidence * 0.45;
  const likelihood = clamp(likelihoodBase * confidenceDampening, 0, 1);
  const score = clamp(Math.round(Math.sqrt(impact * likelihood) * 100), 0, 100);
  const band = riskBand2(score);
  return { score, band, impactScore: Math.round(impact * 100), likelihoodScore: Math.round(likelihood * 100) };
}
function computePortRisk(asset, passiveObservations) {
  const assetPorts = /* @__PURE__ */ new Map();
  const assetHostname = asset.hostname?.toLowerCase() || "";
  const assetIps = /* @__PURE__ */ new Set();
  if (asset.dnsRecords) {
    for (const [type, records] of Object.entries(asset.dnsRecords)) {
      if (type === "A" || type === "AAAA") {
        const arr = Array.isArray(records) ? records : [records];
        for (const r of arr) {
          if (typeof r === "string") assetIps.add(r);
          else if (r?.address) assetIps.add(r.address);
        }
      }
    }
  }
  for (const obs of passiveObservations) {
    const obsName = (obs.name || "").toLowerCase();
    const obsIp = obs.ip || "";
    const isMatch = assetHostname && (obsName.includes(assetHostname) || assetHostname.includes(obsName.split(" ")[0])) || obsIp && assetIps.has(obsIp) || obsIp && assetHostname.includes(obsIp);
    if (!isMatch) continue;
    if (obs.evidence?.ports && Array.isArray(obs.evidence.ports)) {
      for (const p of obs.evidence.ports) {
        if (typeof p === "number" && !assetPorts.has(p)) {
          assetPorts.set(p, { ip: obsIp || void 0 });
        }
      }
    }
    if (obs.evidence?.all_ports && Array.isArray(obs.evidence.all_ports)) {
      for (const p of obs.evidence.all_ports) {
        if (typeof p === "number" && !assetPorts.has(p)) {
          assetPorts.set(p, { ip: obsIp || void 0 });
        }
      }
    }
    if (obs.evidence?.port && typeof obs.evidence.port === "number") {
      const p = obs.evidence.port;
      if (!assetPorts.has(p)) {
        assetPorts.set(p, {
          ip: obsIp || void 0,
          service: obs.evidence.product || void 0
        });
      }
    }
    for (const tag of obs.tags) {
      const portMatch = tag.match(/^port:(\d+)$/);
      if (portMatch) {
        const p = parseInt(portMatch[1], 10);
        if (!assetPorts.has(p)) {
          assetPorts.set(p, { ip: obsIp || void 0 });
        }
      }
    }
  }
  if (assetPorts.size === 0) {
    return {
      portExposureScore: 0,
      portExposureBand: "low",
      highRiskPortCount: 0,
      mediumRiskPortCount: 0,
      totalOpenPorts: 0,
      portFindings: [],
      accessibilityBoost: 0,
      likelihoodBoost: 0
    };
  }
  const portFindings = [];
  let highRiskCount = 0;
  let mediumRiskCount = 0;
  let maxSeverity = 0;
  let severitySum = 0;
  for (const [port, info] of Array.from(assetPorts.entries())) {
    const highRisk = HIGH_RISK_PORTS[port];
    const medRisk = MEDIUM_RISK_PORTS[port];
    if (highRisk) {
      highRiskCount++;
      portFindings.push({ port, ...highRisk, ip: info.ip, riskLevel: "high" });
      maxSeverity = Math.max(maxSeverity, highRisk.severity);
      severitySum += highRisk.severity;
    } else if (medRisk) {
      mediumRiskCount++;
      portFindings.push({ port, ...medRisk, ip: info.ip, riskLevel: "medium" });
      maxSeverity = Math.max(maxSeverity, medRisk.severity);
      severitySum += medRisk.severity;
    } else {
      portFindings.push({
        port,
        service: info.service || `Port ${port}`,
        severity: 2,
        category: "unknown",
        rationale: `Open port ${port} detected \u2014 service unknown`,
        ip: info.ip,
        riskLevel: "low"
      });
      severitySum += 2;
    }
  }
  portFindings.sort((a, b) => b.severity - a.severity);
  const avgSeverity = portFindings.length > 0 ? severitySum / portFindings.length : 0;
  const portCountFactor = Math.min(assetPorts.size / 10, 1) * 10;
  const portExposureScore = clamp(
    Math.round(maxSeverity / 10 * 60 + avgSeverity / 10 * 20 + portCountFactor * 2),
    0,
    100
  );
  const accessibilityBoost = clamp(
    highRiskCount >= 3 ? 3 : highRiskCount >= 2 ? 2 : highRiskCount >= 1 ? 1.5 : mediumRiskCount >= 3 ? 1 : mediumRiskCount >= 1 ? 0.5 : 0,
    0,
    3
  );
  const likelihoodBoost = clamp(
    highRiskCount >= 3 ? 0.3 : highRiskCount >= 2 ? 0.2 : highRiskCount >= 1 ? 0.15 : mediumRiskCount >= 3 ? 0.1 : mediumRiskCount >= 1 ? 0.05 : 0,
    0,
    0.3
  );
  return {
    portExposureScore,
    portExposureBand: riskBand2(portExposureScore),
    highRiskPortCount: highRiskCount,
    mediumRiskPortCount: mediumRiskCount,
    totalOpenPorts: assetPorts.size,
    portFindings,
    accessibilityBoost,
    likelihoodBoost
  };
}
function generatePortPostureFindings(asset, portRisk) {
  const findings = [];
  const significantPorts = portRisk.portFindings.filter(
    (f) => f.riskLevel === "high" || f.riskLevel === "medium" && f.severity >= 5
  );
  for (const pf of significantPorts) {
    const findingId = `port-${asset.assetId}-${pf.port}`;
    const isHighRisk = pf.riskLevel === "high";
    findings.push({
      id: findingId,
      assetRef: asset.assetId,
      assetHostname: asset.hostname,
      category: "network_exposure",
      title: `${pf.service} (port ${pf.port}) exposed to internet`,
      severity: pf.severity,
      likelihood: isHighRisk ? 8 : 5,
      confidence: 1,
      // Directly observed from passive recon
      recommendedControls: [
        `Restrict ${pf.service} access via firewall rules or security groups`,
        isHighRisk ? `Move ${pf.service} behind VPN or bastion host` : `Review necessity of ${pf.service} exposure`,
        `Implement network segmentation to isolate ${pf.service}`,
        ...pf.category === "database" ? ["Ensure strong authentication is configured", "Enable encryption in transit"] : [],
        ...pf.category === "remote_access" ? ["Enable multi-factor authentication", "Implement account lockout policies"] : []
      ],
      cveIds: [],
      kevListed: false,
      exploitAvailable: isHighRisk,
      // High-risk ports have well-known exploit tooling
      affectedAssets: [asset.hostname],
      evidenceBasis: "passive_recon",
      evidenceDetail: `Port ${pf.port}/${pf.service} detected open via passive reconnaissance (Shodan/InternetDB/Censys). ${pf.rationale}`,
      corroborationTier: "confirmed",
      // Directly observed = confirmed
      evidenceChain: [
        `Passive reconnaissance detected port ${pf.port} (${pf.service}) open on ${asset.hostname}${pf.ip ? ` (${pf.ip})` : ""}`,
        `Service identified as ${pf.service} in category: ${pf.category}`,
        pf.rationale,
        `Finding corroboration: CONFIRMED \u2014 directly observed from internet-wide scan data`
      ]
    });
  }
  const highRiskPorts = portRisk.portFindings.filter((f) => f.riskLevel === "high");
  if (highRiskPorts.length >= 2) {
    findings.push({
      id: `port-compound-${asset.assetId}`,
      assetRef: asset.assetId,
      assetHostname: asset.hostname,
      category: "network_exposure",
      title: `Multiple high-risk services exposed (${highRiskPorts.map((p) => p.service).join(", ")})`,
      severity: Math.min(10, Math.max(...highRiskPorts.map((p) => p.severity)) + 1),
      likelihood: 9,
      confidence: 1,
      recommendedControls: [
        "Conduct immediate network exposure audit",
        "Implement defense-in-depth with network segmentation",
        "Deploy host-based firewall rules on all exposed assets",
        "Move all management services behind VPN",
        "Enable comprehensive logging and monitoring on all exposed ports"
      ],
      cveIds: [],
      kevListed: false,
      exploitAvailable: true,
      affectedAssets: [asset.hostname],
      evidenceBasis: "passive_recon",
      evidenceDetail: `${highRiskPorts.length} high-risk ports exposed simultaneously: ${highRiskPorts.map((p) => `${p.port}/${p.service}`).join(", ")}. Combined exposure dramatically increases attack surface.`,
      corroborationTier: "confirmed",
      evidenceChain: [
        `${highRiskPorts.length} high-risk services detected exposed on ${asset.hostname}`,
        ...highRiskPorts.map((p) => `Port ${p.port} (${p.service}): ${p.rationale}`),
        "Combined exposure creates compound risk \u2014 attackers can pivot between services",
        "Finding corroboration: CONFIRMED \u2014 all ports directly observed from passive reconnaissance"
      ]
    });
  }
  return findings;
}
function riskBand2(score) {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}
function riskTier(score) {
  if (score >= 90) return "tier0_critical";
  if (score >= 70) return "tier1_high";
  if (score >= 40) return "tier2_medium";
  return "tier3_low";
}
function inferTier(riskScore) {
  return riskTier(riskScore);
}
function computeAssetCriticality(missionImpact) {
  const score = clamp(Math.round(missionImpact * 10), 0, 100);
  return { score, band: riskBand2(score) };
}
function computeVulnRisk(findings) {
  const actionable = findings.filter((f) => f.corroborationTier === "confirmed" || f.corroborationTier === "probable");
  if (actionable.length === 0) return { score: 0, band: "low" };
  let maxSeverity = 0;
  let weightedSum = 0;
  for (const f of actionable) {
    const weight = f.corroborationTier === "confirmed" ? 1 : 0.6;
    const findingScore = f.severity / 10 * 100 * weight;
    weightedSum += findingScore;
    if (f.severity > maxSeverity) maxSeverity = f.severity;
  }
  const avgWeighted = weightedSum / actionable.length;
  const maxNorm = maxSeverity / 10 * 100;
  const score = clamp(Math.round(maxNorm * 0.6 + avgWeighted * 0.4), 0, 100);
  return { score, band: riskBand2(score) };
}
function createDefaultAnalysis(asset) {
  const carver = normalizeCarver({});
  const shock = normalizeShock({});
  const mission = computeMissionImpact(carver, shock);
  const hybrid = computeHybridRisk(3, mission, { exposure: 0.3, recognizability: 0.3, confidence: 0.2 });
  const criticality = computeAssetCriticality(mission);
  return {
    asset,
    carverScores: carver,
    shockScores: shock,
    missionImpactScore: Math.round(mission * 10) / 10,
    suggestedTier: inferTier(hybrid.score),
    hybridRiskScore: Math.round(hybrid.score),
    riskBand: hybrid.band,
    cvssEstimate: 3,
    contextIndicators: { exposure: 0.3, recognizability: 0.3, confidence: 0.2 },
    postureFindings: [],
    testVectors: [],
    confidence: 40,
    assetCriticalityScore: criticality.score,
    assetCriticalityBand: criticality.band,
    vulnRiskScore: 0,
    vulnRiskBand: "low",
    impactScore: hybrid.impactScore,
    likelihoodScore: hybrid.likelihoodScore,
    // Mission Function Classification defaults
    missionFunction: "public_facing_services",
    essentialService: "general_server",
    businessImpactLevel: "moderate",
    deviceType: "unknown",
    platformType: "unknown",
    missionJustification: ""
  };
}
async function generateCampaignRecommendations(analyses, org, kevEnrichment) {
  const sorted = [...analyses].sort((a, b) => b.hybridRiskScore - a.hybridRiskScore);
  const topAssets = sorted.slice(0, 15);
  const prompt = `You are a red team campaign designer. Based on the following asset analysis and risk scoring, design tailored offensive security campaigns.

Organization: ${org.customerName} (${org.sector}, ${org.clientType})
Critical Functions: ${(org.criticalFunctions || []).join(", ") || "none specified"}
Compliance: ${(org.complianceFlags || []).join(", ") || "none"}

Top Risk Assets (sorted by hybrid risk score):
${JSON.stringify(topAssets.map((a) => {
    const actionableFindings = a.postureFindings.filter((f) => f.corroborationTier === "confirmed" || f.corroborationTier === "probable");
    return {
      id: a.asset.assetId,
      hostname: a.asset.hostname,
      type: a.asset.assetType,
      riskScore: a.hybridRiskScore,
      riskBand: a.riskBand,
      tier: a.suggestedTier,
      classes: a.asset.assetClasses,
      tags: a.asset.tags,
      confirmedFindings: actionableFindings.filter((f) => f.corroborationTier === "confirmed").map((f) => ({ title: f.title, cves: f.cveIds, severity: f.severity, version: f.detectedVersion })),
      probableFindings: actionableFindings.filter((f) => f.corroborationTier === "probable").map((f) => ({ title: f.title, cves: f.cveIds, severity: f.severity, note: "version not confirmed" })),
      vectors: a.testVectors.map((v) => ({ type: v.vectorType, hypothesis: v.hypothesis }))
    };
  }), null, 2)}

IMPORTANT CORROBORATION RULES:
- Only design campaigns targeting CONFIRMED or PROBABLE findings. Do NOT target POTENTIAL-only findings.
- CONFIRMED findings have a detected version that matches a known vulnerable version range \u2014 these are highest priority.
- PROBABLE findings have a real CVE but the specific version on the target is unconfirmed \u2014 include these but note the version uncertainty.
- Do NOT invent vulnerabilities or assume versions that have not been detected.

Design 4-8 campaigns that:
1. Target the highest-risk assets first
2. Map to specific MITRE ATT&CK techniques
3. Include specific Caldera adversary emulation abilities (reference real ATT&CK technique IDs like T1566.001, T1078, T1021.001, etc.)
4. Include GoPhish phishing template designs tailored to this organization
5. Define complete attack chains with step-by-step phases
6. Consider the client type (${org.clientType}) for realistic scenarios

Campaign types to consider:
- Phishing campaigns targeting discovered email infrastructure
- Credential harvesting via SSO/VPN portals
- Lateral movement chains based on discovered internal assets
- Supply chain attack simulations for ${org.clientType} environments
- Purple team validation of specific posture findings
${kevEnrichment && kevEnrichment.matches.length > 0 ? `
CISA KEV ALERT: The following actively exploited vulnerabilities were found in the target's technology stack:
${kevEnrichment.matches.slice(0, 20).map((m) => `- ${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [KNOWN RANSOMWARE]" : ""}`).join("\n")}

You MUST incorporate these KEV vulnerabilities into your campaign designs. Prioritize campaigns that exploit these known-exploited CVEs. Include specific exploitation steps for KEV-listed vulnerabilities in attack chains.
${kevEnrichment.ransomwareExposure ? "WARNING: Some KEV entries are linked to known ransomware campaigns. Design campaigns that simulate ransomware attack paths." : ""}
` : ""}
For each campaign, provide:
{
  "id": "camp-001",
  "name": "Campaign Name",
  "type": "red_team|phishing|purple_team|pentest",
  "priority": "critical|high|medium|low",
  "description": "Detailed campaign description",
  "targetAssets": ["a-001", "a-002"],
  "calderaAbilities": [
    { "name": "Ability name", "tactic": "initial-access", "technique": "T1566.001", "rationale": "Why this ability" }
  ],
  "gophishTemplates": [
    { "name": "Template name", "subject": "Email subject", "theme": "password_reset|invoice|it_support|etc", "targetPersona": "Who receives this", "rationale": "Why this template" }
  ],
  "attackChain": [
    { "step": 1, "phase": "Initial Access", "action": "Send phishing email", "technique": "T1566.001", "tool": "GoPhish" },
    { "step": 2, "phase": "Execution", "action": "Execute payload", "technique": "T1059.001", "tool": "Cyber C2" }
  ],
  "estimatedRisk": 85,
  "mitreTactics": ["initial-access", "execution", "persistence"]
}

Return JSON: { "campaigns": [...] }`;
  try {
    const response = await invokeLLMWithTimeout({
      _priority: "bulk",
      messages: [
        { role: "system", content: "You are a red team campaign designer. Return only valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" }
    });
    const content = response.choices?.[0]?.message?.content;
    const parsed = safeParseLLMJson(content, { campaigns: [] });
    return (parsed.campaigns || []).map((c) => ({
      id: c.id || `camp-${Date.now()}`,
      name: c.name || "Unnamed Campaign",
      type: c.type || "red_team",
      priority: c.priority || "medium",
      description: c.description || "",
      targetAssets: c.targetAssets || [],
      calderaAbilities: c.calderaAbilities || [],
      gophishTemplates: c.gophishTemplates || [],
      attackChain: c.attackChain || [],
      estimatedRisk: c.estimatedRisk || 50,
      mitreTactics: c.mitreTactics || []
    }));
  } catch (err) {
    console.error("[DomainIntel] Campaign recommendation failed:", err);
    return [];
  }
}
async function generateScanOnlySummary(analyses, org, opts) {
  const ownershipFilter = createAssetOwnershipFilter({
    managedProviderName: opts?.managedProviderName,
    primaryDomain: org.primaryDomain
  });
  const { clientOwned: clientAnalyses, excluded: managedAnalyses } = partitionByOwnership(
    analyses,
    (a) => ({ hostname: a.asset.hostname, tags: a.asset.tags }),
    ownershipFilter
  );
  const managedAssetHostnames = new Set(managedAnalyses.map((a) => a.asset.hostname?.toLowerCase()));
  const mpName = ownershipFilter.managedProviderName;
  const clientRiskScores = clientAnalyses.map((a) => a.hybridRiskScore);
  const prelimOverallRisk = clientRiskScores.length > 0 ? Math.round(clientRiskScores.reduce((s, v) => s + v, 0) / clientRiskScores.length) : 0;
  const prelimRiskBand = prelimOverallRisk >= 90 ? "critical" : prelimOverallRisk >= 70 ? "high" : prelimOverallRisk >= 40 ? "medium" : "low";
  const maxAssetRisk = clientRiskScores.length > 0 ? Math.max(...clientRiskScores) : 0;
  const maxRiskBand = maxAssetRisk >= 90 ? "critical" : maxAssetRisk >= 70 ? "high" : maxAssetRisk >= 40 ? "medium" : "low";
  const criticalAssets = clientAnalyses.filter((a) => a.riskBand === "critical" || a.riskBand === "high");
  const clientFindings = clientAnalyses.flatMap((a) => a.postureFindings);
  const managedFindings = managedAnalyses.flatMap((a) => a.postureFindings);
  const allFindings = clientFindings;
  const kevFindings = allFindings.filter((f) => f.kevListed);
  const confirmedFindings = allFindings.filter((f) => f.corroborationTier === "confirmed");
  const probableFindings = allFindings.filter((f) => f.corroborationTier === "probable");
  const unconfirmedFindings = allFindings.filter((f) => f.corroborationTier !== "confirmed" && f.corroborationTier !== "probable");
  const versionConfirmedCount = allFindings.filter((f) => f.versionMatchConfirmed).length;
  const kevConfirmed = kevFindings.filter((f) => f.versionMatchConfirmed);
  const kevProbable = kevFindings.filter((f) => !f.versionMatchConfirmed);
  const blufAllCves = /* @__PURE__ */ new Set();
  const blufKevCves = /* @__PURE__ */ new Set();
  const blufConfirmedCves = /* @__PURE__ */ new Set();
  for (const f of allFindings) {
    if (f.cveIds) {
      for (const cve of f.cveIds) {
        blufAllCves.add(cve);
        if (f.kevListed) blufKevCves.add(cve);
        if (f.corroborationTier === "confirmed") blufConfirmedCves.add(cve);
      }
    }
  }
  const corroborationBlock = `
FINDINGS CONFIDENCE BREAKDOWN:
IMPORTANT: When reporting vulnerability counts, use UNIQUE CVE counts (not total instances).
Many of the same vulnerabilities appear across multiple assets \u2014 report the unique count and note how many assets are affected.
- Unique vulnerabilities identified: ${blufAllCves.size} distinct CVEs across ${allFindings.length} finding instances on ${clientAnalyses.length} assets
- High-confidence (software version verified): ${confirmedFindings.length} instances (${blufConfirmedCves.size} unique CVEs)
- Moderate-confidence (software detected, version unverified): ${probableFindings.length} instances
- Low-confidence (inferred from technology patterns): ${unconfirmedFindings.length} instances
- Actively exploited vulnerabilities (CISA alerts): ${blufKevCves.size} unique CVEs across ${kevFindings.length} instances (${kevConfirmed.length} verified, ${kevProbable.length} require further investigation)

WRITING RULES \u2014 THIS IS FOR A NON-TECHNICAL EXECUTIVE AUDIENCE:
1. Write in plain business English. Avoid acronyms like CVE, KEV, CVSS, DMARC, SPF, DKIM unless absolutely necessary \u2014 and if used, explain them in parentheses on first use.
2. Focus on BUSINESS IMPACT: what could go wrong, what data is at risk, what operations could be disrupted.
3. Use confidence levels ("verified", "likely", "possible") instead of technical terms like "confirmed", "probable", "corroboration tier".
4. Do NOT overstate risk. If most findings are unverified, say so clearly: "Several potential issues were identified that require further investigation to confirm."
5. Frame recommendations as business decisions, not technical tasks: "We recommend authorizing a deeper assessment" rather than "Run active version enumeration."
6. If email infrastructure is managed by a third party (e.g., Microsoft 365), note that those systems are the provider's responsibility and focus on what the organization controls.
7. Third-party assets (e.g., outlook.com) are NOT part of the organization's risk profile.
8. End with a brief "Confidence Note" explaining the proportion of verified vs. unverified findings.
9. Do NOT use the word "corroboration" anywhere in the summary.

OVERALL RISK SCORE CONTEXT:
- Overall Risk Score: ${prelimOverallRisk}/100 (${prelimRiskBand.toUpperCase()})
- Highest Individual Asset Risk: ${maxAssetRisk}/100 (${maxRiskBand.toUpperCase()})
- Scale: LOW (0-39), MEDIUM (40-69), HIGH (70-89), CRITICAL (90-100)

TONE RULES:
- LOW risk: Calm, reassuring. Frame findings as improvement opportunities, not emergencies.
- MEDIUM risk: Moderate concern. Acknowledge areas needing attention without alarm.
- HIGH risk: Clear concern with specific urgency for remediation.
- CRITICAL risk: Urgent language with immediate action recommendations.
- Your overall tone MUST match the ${prelimRiskBand.toUpperCase()} rating.
`;
  const confirmedFindingsList = confirmedFindings.slice(0, 5).map(
    (f) => `- [Verified] ${f.title} (risk level: ${f.severity}/10)`
  ).join("\n");
  const probableFindingsList = probableFindings.slice(0, 5).map(
    (f) => `- [Requires investigation] ${f.title} (risk level: ${f.severity}/10)`
  ).join("\n");
  const managedProviderContext = (() => {
    const parts = [];
    if (managedAnalyses.length > 0) {
      parts.push(`MANAGED/THIRD-PARTY ASSET EXCLUSION:`);
      parts.push(`${managedAnalyses.length} asset(s) excluded from this analysis because they are managed provider or third-party infrastructure:`);
      managedAnalyses.forEach((a) => {
        const findingCount = a.postureFindings.length;
        parts.push(`- ${a.asset.hostname} (${findingCount} findings excluded \u2014 NOT the client's responsibility)`);
      });
      if (mpName) {
        parts.push(`
Mail infrastructure is managed by ${mpName}. Mail server CVEs (e.g., Exchange, SharePoint) on these hosts are the provider's responsibility, NOT the client's.`);
      }
      parts.push(`Only customer-controlled DNS authentication settings (SPF/DKIM/DMARC) are actionable for the client.`);
      parts.push(`DO NOT mention these excluded assets or their CVEs as client risks.
`);
    }
    return parts.join("\n");
  })();
  const prompt = `Generate an executive-level summary for a preliminary security assessment:

Organization: ${org.customerName} (${org.sector})
Digital Assets Discovered: ${clientAnalyses.length} (${managedAnalyses.length} third-party managed assets excluded)
High-Risk Assets: ${criticalAssets.length}
Security Findings: ${allFindings.length}
Actively Exploited Vulnerabilities (per government alerts): ${kevFindings.length}
${corroborationBlock}
${managedProviderContext}
${(() => {
    const bd = opts?.breachData;
    const sigs = opts?.riskSignals || [];
    const credSignals = sigs.filter((s) => s.signalType === "credential_exposure" || s.signalType === "high_volume_breach");
    if (!bd && credSignals.length === 0) return "";
    const parts = ["CREDENTIAL & BREACH EXPOSURE:"];
    if (bd) {
      parts.push(`- Total breach records found: ${bd.totalExposures.toLocaleString()}`);
      parts.push(`- Unique breach sources: ${bd.uniqueBreachSources}${bd.breachSources?.length > 0 ? ` (${bd.breachSources.slice(0, 8).join(", ")}${bd.breachSources.length > 8 ? ` +${bd.breachSources.length - 8} more` : ""})` : ""}`);
      parts.push(`- Credentials exposed (email/password pairs): ${bd.credentialPairs}`);
      if (bd.passwordsExposed > 0) parts.push(`- Passwords exposed (plaintext or crackable): ${bd.passwordsExposed}`);
      if (bd.hashedPasswordsExposed > 0) parts.push(`- Hashed passwords found: ${bd.hashedPasswordsExposed}`);
    }
    if (credSignals.length > 0) {
      const plaintextCount = credSignals.filter((s) => s.credentialEvidence?.hasPlaintextPasswords).length;
      const hashTypes = [...new Set(credSignals.flatMap((s) => s.credentialEvidence?.hashTypes || []))];
      if (plaintextCount > 0) parts.push(`- \u26A0 ${plaintextCount} breach source(s) contain PLAINTEXT PASSWORDS \u2014 immediate risk for credential stuffing attacks`);
      if (hashTypes.length > 0) parts.push(`- Hash types found: ${hashTypes.join(", ")}`);
    }
    parts.push("IMPORTANT: Include credential exposure findings in the executive summary. Explain in plain language that employee login credentials were found in data breaches, quantify the exposure, and recommend credential rotation and multi-factor authentication if not already in place.");
    return parts.join("\n") + "\n";
  })()}
Highest-Risk Assets:
${criticalAssets.slice(0, 5).map((a) => `- ${a.asset.hostname} (${a.asset.assetType}): Risk ${a.hybridRiskScore}/100`).join("\n")}

Verified Findings (confirmed through software version detection):
${confirmedFindingsList || "(none \u2014 no vulnerabilities verified at this stage)"}

Findings Requiring Further Investigation:
${probableFindingsList || "(none)"}

Provide:
1. "executiveSummary": A 2-3 paragraph summary written for a CEO or board member with NO cybersecurity background. Describe what was found in plain language: how many digital assets were discovered, what risks they pose to the business, credential exposure risks (if any breach data was found), and whether a deeper assessment is recommended. Avoid technical jargon. End with a "Confidence Note" stating how many findings are verified vs. requiring further investigation. Written for AC3 by AceofCloud.
2. "threatModelSummary": A brief technical summary for the security team covering attack surface details, risk posture, and credential exposure statistics (if applicable). This can use technical language. Note that this is a preliminary assessment \u2014 detailed threat actor profiling has not yet been performed.

Return JSON: { "executiveSummary": "...", "threatModelSummary": "..." }`;
  try {
    const response = await invokeLLMWithTimeout({
      _priority: "bulk",
      messages: [
        { role: "system", content: "You are a business risk advisor writing for non-technical executives. Use clear, plain language. Avoid cybersecurity jargon. Return only valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "scan_summaries",
          strict: true,
          schema: {
            type: "object",
            properties: {
              executiveSummary: { type: "string" },
              threatModelSummary: { type: "string" }
            },
            required: ["executiveSummary", "threatModelSummary"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    return safeParseLLMJson(content, {
      executiveSummary: `Reconnaissance scan of ${org.primaryDomain} identified ${analyses.length} assets with ${criticalAssets.length} classified as critical or high risk. Review the findings below to decide whether to proceed with a full engagement.`,
      threatModelSummary: `Attack surface scan for ${org.customerName} reveals ${analyses.length} discoverable assets across the ${org.primaryDomain} domain. Campaign design and threat actor profiling are available upon engagement start.`
    });
  } catch (err) {
    console.error("[DomainIntel] Scan-only summary generation failed:", err);
    return {
      executiveSummary: `Reconnaissance scan of ${org.primaryDomain} identified ${analyses.length} assets with ${criticalAssets.length} classified as critical or high risk and ${allFindings.length} posture findings. Review the results to decide whether to proceed with a full engagement.`,
      threatModelSummary: `Attack surface scan for ${org.customerName} reveals ${analyses.length} discoverable assets across the ${org.primaryDomain} domain infrastructure. Campaign design and threat actor profiling have not yet been performed.`
    };
  }
}
async function generateSummaries(analyses, campaigns, org, historicalContext, opts) {
  const ownershipFilter = createAssetOwnershipFilter({
    managedProviderName: opts?.managedProviderName,
    primaryDomain: org.primaryDomain
  });
  const { clientOwned: clientAnalyses, excluded: managedAnalyses } = partitionByOwnership(
    analyses,
    (a) => ({ hostname: a.asset.hostname, tags: a.asset.tags }),
    ownershipFilter
  );
  const mpName = ownershipFilter.managedProviderName;
  const clientRiskScores = clientAnalyses.map((a) => a.hybridRiskScore);
  const prelimOverallRisk = clientRiskScores.length > 0 ? Math.round(clientRiskScores.reduce((s, v) => s + v, 0) / clientRiskScores.length) : 0;
  const prelimRiskBand = prelimOverallRisk >= 90 ? "critical" : prelimOverallRisk >= 70 ? "high" : prelimOverallRisk >= 40 ? "medium" : "low";
  const maxAssetRisk = clientRiskScores.length > 0 ? Math.max(...clientRiskScores) : 0;
  const maxRiskBand = maxAssetRisk >= 90 ? "critical" : maxAssetRisk >= 70 ? "high" : maxAssetRisk >= 40 ? "medium" : "low";
  const criticalAssets = clientAnalyses.filter((a) => a.riskBand === "critical" || a.riskBand === "high");
  const clientFindings = clientAnalyses.flatMap((a) => a.postureFindings);
  const allFindings = clientFindings;
  const confirmedFindings = allFindings.filter((f) => f.corroborationTier === "confirmed");
  const probableFindings = allFindings.filter((f) => f.corroborationTier === "probable");
  const unconfirmedFindings = allFindings.filter((f) => f.corroborationTier !== "confirmed" && f.corroborationTier !== "probable");
  const versionConfirmedCount = allFindings.filter((f) => f.versionMatchConfirmed).length;
  const kevFindings = allFindings.filter((f) => f.kevListed);
  const kevConfirmed = kevFindings.filter((f) => f.versionMatchConfirmed);
  const kevProbable = kevFindings.filter((f) => !f.versionMatchConfirmed);
  const corroborationBlock = `
FINDINGS CONFIDENCE BREAKDOWN:
- High-confidence findings (software version verified): ${confirmedFindings.length}
- Moderate-confidence findings (software detected but version not yet verified): ${probableFindings.length}
- Low-confidence findings (inferred from technology patterns): ${unconfirmedFindings.length}
- Actively exploited vulnerabilities (per government alerts): ${kevFindings.length} (${kevConfirmed.length} verified, ${kevProbable.length} require further investigation)

WRITING RULES \u2014 THIS IS FOR A NON-TECHNICAL EXECUTIVE AUDIENCE:
1. Write in plain business English. Avoid acronyms like CVE, KEV, CVSS, DMARC, SPF, DKIM unless absolutely necessary \u2014 and if used, explain them in parentheses on first use.
2. Focus on BUSINESS IMPACT: what could go wrong, what data is at risk, what operations could be disrupted.
3. Use confidence levels ("verified", "likely", "possible") instead of technical terms like "confirmed", "probable", "corroboration tier".
4. Do NOT overstate risk. If most findings are unverified, say so clearly.
5. Frame recommendations as business decisions, not technical tasks.
6. If email infrastructure is managed by a third party (e.g., Microsoft 365), note that those systems are the provider's responsibility and focus on what the organization controls.
7. Third-party assets (e.g., outlook.com) are NOT part of the organization's risk profile.
8. End with a brief "Confidence Note" explaining the proportion of verified vs. unverified findings.
9. Do NOT use the word "corroboration" anywhere in the summary.

OVERALL RISK SCORE CONTEXT:
- Overall Risk Score: ${prelimOverallRisk}/100 (${prelimRiskBand.toUpperCase()})
- Highest Individual Asset Risk: ${maxAssetRisk}/100 (${maxRiskBand.toUpperCase()})
- Scale: LOW (0-39), MEDIUM (40-69), HIGH (70-89), CRITICAL (90-100)

TONE RULES:
- LOW risk: Calm, reassuring. Frame findings as improvement opportunities, not emergencies.
- MEDIUM risk: Moderate concern. Acknowledge areas needing attention without alarm.
- HIGH risk: Clear concern with specific urgency for remediation.
- CRITICAL risk: Urgent language with immediate action recommendations.
- Your overall tone MUST match the ${prelimRiskBand.toUpperCase()} rating.
`;
  const confirmedFindingsList = confirmedFindings.slice(0, 5).map(
    (f) => `- [Verified] ${f.title} (risk level: ${f.severity}/10)`
  ).join("\n");
  const probableFindingsList = probableFindings.slice(0, 5).map(
    (f) => `- [Requires investigation] ${f.title} (risk level: ${f.severity}/10)`
  ).join("\n");
  const managedProviderContext = (() => {
    const parts = [];
    if (managedAnalyses.length > 0) {
      parts.push(`MANAGED/THIRD-PARTY ASSET EXCLUSION:`);
      parts.push(`${managedAnalyses.length} asset(s) excluded from this analysis because they are managed provider or third-party infrastructure:`);
      managedAnalyses.forEach((a) => {
        const findingCount = a.postureFindings.length;
        parts.push(`- ${a.asset.hostname} (${findingCount} findings excluded \u2014 NOT the client's responsibility)`);
      });
      if (mpName) {
        parts.push(`
Mail infrastructure is managed by ${mpName}. Mail server CVEs (e.g., Exchange, SharePoint) on these hosts are the provider's responsibility, NOT the client's.`);
      }
      parts.push(`Only customer-controlled DNS authentication settings (SPF/DKIM/DMARC) are actionable for the client.`);
      parts.push(`DO NOT mention these excluded assets or their CVEs as client risks.
`);
    }
    return parts.join("\n");
  })();
  const prompt = `Generate an executive-level summary for a comprehensive security assessment:

Organization: ${org.customerName} (${org.sector})
Digital Assets Discovered: ${clientAnalyses.length} (${managedAnalyses.length} third-party managed assets excluded)
High-Risk Assets: ${criticalAssets.length}
Security Findings: ${allFindings.length}
Recommended Security Exercises: ${campaigns.length}
Actively Exploited Vulnerabilities (per government alerts): ${kevFindings.length}
${corroborationBlock}
${managedProviderContext}
${(() => {
    const bd = opts?.breachData;
    const sigs = opts?.riskSignals || [];
    const credSignals = sigs.filter((s) => s.signalType === "credential_exposure" || s.signalType === "high_volume_breach");
    if (!bd && credSignals.length === 0) return "";
    const parts = ["CREDENTIAL & BREACH EXPOSURE:"];
    if (bd) {
      parts.push(`- Total breach records found: ${bd.totalExposures.toLocaleString()}`);
      parts.push(`- Unique breach sources: ${bd.uniqueBreachSources}${bd.breachSources?.length > 0 ? ` (${bd.breachSources.slice(0, 8).join(", ")}${bd.breachSources.length > 8 ? ` +${bd.breachSources.length - 8} more` : ""})` : ""}`);
      parts.push(`- Credentials exposed (email/password pairs): ${bd.credentialPairs}`);
      if (bd.passwordsExposed > 0) parts.push(`- Passwords exposed (plaintext or crackable): ${bd.passwordsExposed}`);
      if (bd.hashedPasswordsExposed > 0) parts.push(`- Hashed passwords found: ${bd.hashedPasswordsExposed}`);
    }
    if (credSignals.length > 0) {
      const plaintextCount = credSignals.filter((s) => s.credentialEvidence?.hasPlaintextPasswords).length;
      const hashTypes = [...new Set(credSignals.flatMap((s) => s.credentialEvidence?.hashTypes || []))];
      if (plaintextCount > 0) parts.push(`- \u26A0 ${plaintextCount} breach source(s) contain PLAINTEXT PASSWORDS \u2014 immediate risk for credential stuffing attacks`);
      if (hashTypes.length > 0) parts.push(`- Hash types found: ${hashTypes.join(", ")}`);
    }
    parts.push("IMPORTANT: Include credential exposure findings in the executive summary. Explain in plain language that employee login credentials were found in data breaches, quantify the exposure, and recommend credential rotation and multi-factor authentication if not already in place.");
    return parts.join("\n") + "\n";
  })()}
Highest-Risk Assets:
${criticalAssets.slice(0, 5).map((a) => `- ${a.asset.hostname} (${a.asset.assetType}): Risk ${a.hybridRiskScore}/100`).join("\n")}

Verified Findings (confirmed through software version detection):
${confirmedFindingsList || "(none \u2014 no vulnerabilities verified at this stage)"}

Findings Requiring Further Investigation:
${probableFindingsList || "(none)"}

Recommended Security Exercises:
${campaigns.map((c) => `- ${c.name} [${c.type}] - Priority: ${c.priority}`).join("\n")}
${historicalContext ? `

${historicalContext}` : ""}

Provide:
1. "executiveSummary": A 2-3 paragraph summary written for a CEO or board member with NO cybersecurity background. Describe what was found in plain language: how many digital assets were discovered, what risks they pose to the business, credential exposure risks (if any breach data was found), what security exercises are recommended, and what actions leadership should authorize. Avoid technical jargon. End with a "Confidence Note" stating how many findings are verified vs. requiring further investigation. Written for AC3 by AceofCloud.
2. "threatModelSummary": A technical threat model summary for the security team covering attack surface analysis, likely threat actors for this sector, prioritized attack paths, and credential exposure statistics (if applicable). This can use technical language.

Return JSON: { "executiveSummary": "...", "threatModelSummary": "..." }`;
  try {
    const response = await invokeLLMWithTimeout({
      _priority: "bulk",
      messages: [
        { role: "system", content: "You are a business risk advisor writing for non-technical executives. Use clear, plain language. Avoid cybersecurity jargon. Return only valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "summaries",
          strict: true,
          schema: {
            type: "object",
            properties: {
              executiveSummary: { type: "string" },
              threatModelSummary: { type: "string" }
            },
            required: ["executiveSummary", "threatModelSummary"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    return safeParseLLMJson(content, {
      executiveSummary: `Domain intelligence analysis of ${org.primaryDomain} identified ${analyses.length} assets.`,
      threatModelSummary: `Attack surface analysis for ${org.customerName} reveals ${analyses.length} discoverable assets.`
    });
  } catch (err) {
    console.error("[DomainIntel] Summary generation failed:", err);
    return {
      executiveSummary: `Domain intelligence analysis of ${org.primaryDomain} identified ${analyses.length} assets with ${criticalAssets.length} classified as critical or high risk. ${campaigns.length} tailored campaigns have been recommended.`,
      threatModelSummary: `Attack surface analysis for ${org.customerName} reveals ${analyses.length} discoverable assets across the ${org.primaryDomain} domain infrastructure.`
    };
  }
}
async function runDomainIntelPipeline(org, onProgress, options) {
  const yieldEventLoop = () => new Promise((resolve) => setImmediate(resolve));
  org.criticalFunctions = org.criticalFunctions || [];
  org.complianceFlags = org.complianceFlags || [];
  org.additionalDomains = org.additionalDomains || [];
  const scanMode = options?.scanMode || "standard";
  const isScopedScan = options?.scopedAssets && options.scopedAssets.length > 0;
  let fpContext;
  let fpHashes;
  try {
    const db = await import("./db-LSUZDHGJ.js");
    fpContext = await db.getFPContextForLLM();
    if (fpContext.totalFPs > 0) {
      const activeFPs = await db.getActiveFPHashes();
      fpHashes = new Set(activeFPs.map((fp) => fp.hash));
      console.log(`[DomainIntel] FP Learning: Loaded ${fpContext.totalFPs} false positive patterns across ${fpContext.categorySummary.length} categories`);
    }
  } catch (err) {
    console.error(`[DomainIntel] FP context load failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  let historicalContext = "";
  try {
    const db = await import("./db-LSUZDHGJ.js");
    const histCtx = await db.getHistoricalScanContext(org.primaryDomain);
    if (histCtx) {
      historicalContext = db.buildHistoricalContextString(histCtx);
      console.log(`[DomainIntel] Historical Context: Loaded scan #${histCtx.scanCount} context from ${histCtx.previousScanDate} (prev risk: ${histCtx.previousRiskScore}, assets: ${histCtx.previousTotalAssets}, findings: ${histCtx.previousTotalFindings})`);
    } else {
      console.log(`[DomainIntel] Historical Context: No previous scans found for ${org.primaryDomain} \u2014 this is the first scan`);
    }
  } catch (err) {
    console.error(`[DomainIntel] Historical context load failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  await onProgress?.("passive_recon");
  let passiveRecon;
  let passiveContext = "";
  try {
    passiveRecon = await runPassiveRecon(org.primaryDomain, {
      scanMode,
      apiKeys: {
        shodan: ENV.SHODAN_API_KEY || void 0,
        censys_id: ENV.CENSYS_API_ID || void 0,
        censys_secret: ENV.CENSYS_API_SECRET || void 0,
        urlscan: ENV.URLSCAN_API_KEY || void 0,
        securitytrails: ENV.SECURITYTRAILS_API_KEY || void 0,
        dehashed: ENV.DEHASHED_API_KEY || void 0,
        binaryedge: ENV.BINARYEDGE_API_KEY || void 0,
        greynoise: ENV.GREYNOISE_API_KEY || void 0,
        abuseipdb: ENV.ABUSEIPDB_API_KEY || void 0,
        github: ENV.GITHUB_PAT || ENV.GITHUB_CLASSIC_TOKEN || void 0,
        virustotal: ENV.VIRUSTOTAL_API_KEY || void 0,
        hibp: ENV.HIBP_API_KEY || void 0,
        whoisxml: ENV.WHOISXML_API_KEY || void 0,
        leakix: ENV.LEAKIX_API_KEY || void 0,
        fullhunt: ENV.FULLHUNT_API_KEY || void 0,
        netlas: ENV.NETLAS_API_KEY || void 0,
        hunter: ENV.HUNTER_API_KEY || void 0,
        passivetotal: ENV.PASSIVETOTAL_API_KEY || void 0,
        intelx: ENV.INTELX_API_KEY || void 0,
        hudson_rock: ENV.HUDSON_ROCK_API_KEY || void 0,
        leakcheck: ENV.LEAKCHECK_API_KEY || void 0
      },
      timeout: 15e3,
      maxConcurrent: 5,
      onConnectorProgress: options?.onConnectorProgress
    });
    console.log(`[DomainIntel] Passive Recon: ${passiveRecon.summary.totalObservations} observations from ${passiveRecon.connectorResults.filter((r) => r.observations.length > 0).length} connectors, ${passiveRecon.summary.totalSignals} risk signals detected`);
    if (passiveRecon.allObservations.length > 0) {
      const subdomains = passiveRecon.allObservations.filter((o) => o.assetType === "subdomain").map((o) => o.name);
      const ips = passiveRecon.allObservations.filter((o) => o.assetType === "ip").map((o) => `${o.name} (${o.tags.filter((t) => t.startsWith("port:") || t.startsWith("service:")).join(", ")})`);
      const urls = passiveRecon.allObservations.filter((o) => o.assetType === "url").map((o) => o.name).slice(0, 30);
      const certs = passiveRecon.allObservations.filter((o) => o.assetType === "certificate").map((o) => o.name);
      const nsRecords = passiveRecon.allObservations.filter((o) => o.assetType === "ns").map((o) => o.name);
      const mxRecords = passiveRecon.allObservations.filter((o) => o.assetType === "mx").map((o) => o.name);
      const parts = ["\n--- PASSIVE RECONNAISSANCE DATA (verified from external sources) ---"];
      if (subdomains.length > 0) parts.push(`Confirmed subdomains (${subdomains.length}): ${subdomains.slice(0, 50).join(", ")}${subdomains.length > 50 ? ` ... and ${subdomains.length - 50} more` : ""}`);
      if (ips.length > 0) parts.push(`Discovered IPs/services (${ips.length}): ${ips.slice(0, 20).join("; ")}`);
      if (urls.length > 0) parts.push(`Historical URLs from Wayback (${urls.length}): ${urls.join(", ")}`);
      if (certs.length > 0) parts.push(`Certificate subjects (${certs.length}): ${certs.slice(0, 20).join(", ")}`);
      if (nsRecords.length > 0) parts.push(`Nameservers: ${nsRecords.join(", ")}`);
      if (mxRecords.length > 0) parts.push(`Mail servers: ${mxRecords.join(", ")}`);
      const shodanObs = passiveRecon.allObservations.filter((o) => o.source === "shodan" && o.assetType === "ip");
      if (shodanObs.length > 0) {
        const shodanServices = shodanObs.filter((o) => o.evidence?.product).map((o) => `${o.name || o.ip} \u2014 ${o.evidence?.product}${o.evidence?.version ? "/" + o.evidence.version : ""} on port ${o.evidence?.port}/${o.evidence?.transport || "tcp"}${o.evidence?.vulns?.length > 0 ? ` [CVEs: ${o.evidence.vulns.slice(0, 3).join(", ")}]` : ""}`).slice(0, 20);
        if (shodanServices.length > 0) {
          parts.push(`Shodan service banners (${shodanServices.length}): ${shodanServices.join("; ")}`);
        }
      }
      if (passiveRecon.riskSignals.length > 0) {
        parts.push(`
Risk signals detected (${passiveRecon.riskSignals.length}):`);
        for (const sig of passiveRecon.riskSignals.slice(0, 15)) {
          parts.push(`  - [${sig.severity.toUpperCase()}] ${sig.rationale.substring(0, 150)}`);
        }
      }
      parts.push("--- END PASSIVE RECON DATA ---\n");
      passiveContext = parts.join("\n");
    }
  } catch (err) {
    console.error(`[DomainIntel] Passive recon failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  let orgDiscoveryResult;
  try {
    const orgEmail = passiveRecon?.allObservations?.find((o) => o.evidence?.registrant?.organization || o.evidence?.contactEmail)?.evidence?.contactEmail || null;
    orgDiscoveryResult = await discoverOrgDomains(
      org.primaryDomain,
      org.customerName,
      orgEmail || null,
      {
        minConfidenceThreshold: 40,
        maxCandidates: 50,
        enableWebVerification: false,
        enableSpfPivoting: true,
        lookupTimeoutMs: 1e4
      }
    );
    console.log(`[DomainIntel] Org Discovery: ${orgDiscoveryResult.verifiedDomains.length} verified, ${orgDiscoveryResult.unverifiedDomains.length} unverified related domains found`);
  } catch (err) {
    console.error(`[DomainIntel] Org domain discovery failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  await onProgress?.("discovering");
  const combinedContext = [passiveContext, historicalContext].filter(Boolean).join("\n");
  const rawAssets = await discoverAssets(org, fpContext ? { patterns: fpContext.patterns } : void 0, combinedContext);
  await yieldEventLoop();
  {
    const beforeCount = rawAssets.length;
    const byHostname = /* @__PURE__ */ new Map();
    const duplicateIds = /* @__PURE__ */ new Set();
    for (let i = 0; i < rawAssets.length; i++) {
      const a = rawAssets[i];
      let hostname = (a.hostname || "").toLowerCase().replace(/\.$/, "");
      if (!hostname && a.url) {
        try {
          hostname = new URL(a.url).hostname.toLowerCase();
        } catch {
        }
      }
      if (a.url) {
        try {
          const u = new URL(a.url);
          a.url = `${u.protocol}//${u.hostname}`;
        } catch {
        }
      }
      a.hostname = hostname;
      if (!hostname) continue;
      if (byHostname.has(hostname)) {
        const existing = byHostname.get(hostname);
        const existingTechs = new Set((existing.technologies || []).map((t) => t.toLowerCase()));
        for (const tech of a.technologies || []) {
          if (!existingTechs.has(tech.toLowerCase())) {
            existing.technologies.push(tech);
          }
        }
        const existingTags = new Set((existing.tags || []).map((t) => t.toLowerCase()));
        for (const tag of a.tags || []) {
          if (!existingTags.has(tag.toLowerCase())) {
            existing.tags.push(tag);
          }
        }
        if (a.technologyVersions) {
          existing.technologyVersions = { ...existing.technologyVersions || {}, ...a.technologyVersions };
        }
        if (existing.assetType === "other" && a.assetType !== "other") {
          existing.assetType = a.assetType;
        }
        if (existing.discoveryMethod === "inferred" && a.discoveryMethod !== "inferred") {
          existing.discoveryMethod = a.discoveryMethod;
          existing.discoveryEvidence = a.discoveryEvidence;
        }
        duplicateIds.add(i);
      } else {
        byHostname.set(hostname, a);
      }
    }
    for (let i = rawAssets.length - 1; i >= 0; i--) {
      if (duplicateIds.has(i)) rawAssets.splice(i, 1);
    }
    const THIRD_PARTY_HOSTNAME_PATTERNS = [
      // Microsoft
      /\.office365\.com$/i,
      /\.outlook\.com$/i,
      /\.microsoftonline\.com$/i,
      /\.microsoft\.com$/i,
      /\.live\.com$/i,
      /\.sharepoint\.com$/i,
      /\.office\.com$/i,
      /\.onmicrosoft\.com$/i,
      // Google
      /\.google\.com$/i,
      /\.googleapis\.com$/i,
      /\.gstatic\.com$/i,
      /\.gmail\.com$/i,
      /\.googlemail\.com$/i,
      // Salesforce
      /\.salesforce\.com$/i,
      /\.force\.com$/i,
      // Cloudflare
      /\.cloudflare\.com$/i,
      /\.cloudflare-dns\.com$/i,
      // AWS infrastructure (not customer-owned)
      /\.amazonaws\.com$/i,
      /\.cloudfront\.net$/i,
      // Zendesk, Atlassian, etc.
      /\.zendesk\.com$/i,
      /\.atlassian\.net$/i,
      /\.atlassian\.com$/i,
      // DNS providers
      /\.nsone\.net$/i,
      /\.cloudns\.net$/i,
      /\.awsdns-\d+/i,
      /\.ultradns\.com$/i,
      /\.dynect\.net$/i,
      /\.domaincontrol\.com$/i,
      /\.registrar-servers\.com$/i,
      // CDN/hosting infra
      /\.akamai\.net$/i,
      /\.akamaiedge\.net$/i,
      /\.fastly\.net$/i,
      /\.edgekey\.net$/i
    ];
    const thirdPartyRemoved = [];
    for (let i = rawAssets.length - 1; i >= 0; i--) {
      const hostname = (rawAssets[i].hostname || "").toLowerCase();
      if (THIRD_PARTY_HOSTNAME_PATTERNS.some((pattern) => pattern.test(hostname))) {
        thirdPartyRemoved.push(hostname);
        const rootAsset = rawAssets.find(
          (a) => (a.hostname || "").toLowerCase() === org.primaryDomain.toLowerCase() || (a.assetClasses || []).includes("dns_root")
        );
        if (rootAsset) {
          const depTag = `saas_dep:${hostname}`;
          if (!(rootAsset.tags || []).includes(depTag)) {
            rootAsset.tags = [...rootAsset.tags || [], depTag];
          }
        }
        rawAssets.splice(i, 1);
      }
    }
    const infraRemoved = [];
    for (let i = rawAssets.length - 1; i >= 0; i--) {
      const a = rawAssets[i];
      const hostname = (a.hostname || "").toLowerCase();
      const assetId = (a.assetId || "").toLowerCase();
      const isMalformedDnsRecord = hostname.startsWith("ns:") || hostname.startsWith("soa:") || hostname.startsWith("mx:") || assetId.startsWith("passive-ns:") || assetId.startsWith("passive-soa:") || assetId.startsWith("passive-mx:");
      const isDnsNameserver = /^(ns\d*|dns\d*)\./.test(hostname) && THIRD_PARTY_HOSTNAME_PATTERNS.some((p) => p.test(hostname));
      if (isMalformedDnsRecord || isDnsNameserver) {
        infraRemoved.push(hostname);
        rawAssets.splice(i, 1);
      }
    }
    const totalRemoved = beforeCount - rawAssets.length;
    if (totalRemoved > 0) {
      console.log(`[DomainIntel] Stage 1.1 Dedup & Filter: Removed ${totalRemoved} assets (${duplicateIds.size} duplicates, ${thirdPartyRemoved.length} third-party SaaS, ${infraRemoved.length} DNS infrastructure). ${rawAssets.length} assets remain.`);
      if (thirdPartyRemoved.length > 0) console.log(`[DomainIntel]   Third-party removed: ${thirdPartyRemoved.join(", ")}`);
      if (infraRemoved.length > 0) console.log(`[DomainIntel]   Infrastructure removed: ${infraRemoved.join(", ")}`);
    }
  }
  await yieldEventLoop();
  if (passiveRecon?.allObservations) {
    const existingHostnames = new Set(rawAssets.map((a) => (a.hostname || "").toLowerCase()));
    const seenSubdomains = /* @__PURE__ */ new Set();
    const passiveSubdomainAssets = [];
    const THIRD_PARTY_PATTERNS_PASSIVE = [
      /\.office365\.com$/i,
      /\.outlook\.com$/i,
      /\.microsoftonline\.com$/i,
      /\.microsoft\.com$/i,
      /\.live\.com$/i,
      /\.sharepoint\.com$/i,
      /\.office\.com$/i,
      /\.onmicrosoft\.com$/i,
      /\.google\.com$/i,
      /\.googleapis\.com$/i,
      /\.gstatic\.com$/i,
      /\.gmail\.com$/i,
      /\.salesforce\.com$/i,
      /\.force\.com$/i,
      /\.cloudflare\.com$/i,
      /\.amazonaws\.com$/i,
      /\.cloudfront\.net$/i,
      /\.zendesk\.com$/i,
      /\.atlassian\.net$/i,
      /\.nsone\.net$/i,
      /\.cloudns\.net$/i,
      /\.ultradns\.com$/i,
      /\.domaincontrol\.com$/i,
      /\.akamai\.net$/i,
      /\.fastly\.net$/i
    ];
    for (const obs of passiveRecon.allObservations) {
      if (obs.assetType !== "subdomain" || !obs.name) continue;
      const hostname = obs.name.toLowerCase().replace(/\.$/, "");
      if (existingHostnames.has(hostname) || seenSubdomains.has(hostname)) continue;
      if (THIRD_PARTY_PATTERNS_PASSIVE.some((p) => p.test(hostname))) continue;
      if (hostname.startsWith("ns:") || hostname.startsWith("soa:") || hostname.startsWith("mx:")) continue;
      if (/[\s:]/.test(hostname) || hostname.length > 253 || !hostname.includes(".")) continue;
      seenSubdomains.add(hostname);
      const tags = [...obs.tags || []];
      if (obs.source) tags.push(`source:${obs.source}`);
      const technologies = [];
      const technologyVersions = {};
      if (obs.evidence?.product) {
        technologies.push(obs.evidence.product);
        if (obs.evidence.version && !isProtocolVersion(obs.evidence.product, obs.evidence.version)) {
          technologyVersions[obs.evidence.product] = obs.evidence.version;
        }
      }
      if (obs.evidence?.technologies) {
        for (const t of obs.evidence.technologies) {
          if (typeof t === "string") technologies.push(t);
          else if (t?.name) {
            technologies.push(t.name);
            if (t.version && !isProtocolVersion(t.name, t.version)) {
              technologyVersions[t.name] = t.version;
            }
          }
        }
      }
      passiveSubdomainAssets.push({
        assetId: `passive-${hostname.replace(/\./g, "-")}-${Date.now().toString(36)}`,
        hostname,
        url: `https://${hostname}`,
        assetType: obs.evidence?.port ? "service" : "web_application",
        assetClasses: ["subdomain", "passive_recon"],
        tags,
        technologies,
        technologyVersions,
        description: `Subdomain discovered via passive recon (${obs.source}): ${obs.attribution?.method || hostname}`,
        discoveryMethod: "cert_transparency",
        discoveryEvidence: `Passive recon source: ${obs.source}. ${obs.attribution?.method || ""} ${obs.attribution?.url ? `Verify: ${obs.attribution.url}` : ""}`.trim()
      });
    }
    if (passiveSubdomainAssets.length > 0) {
      rawAssets.push(...passiveSubdomainAssets);
      console.log(`[DomainIntel] Merged ${passiveSubdomainAssets.length} passive recon subdomains into asset pipeline (${rawAssets.length} total assets now)`);
    }
  }
  await yieldEventLoop();
  if (isScopedScan && options?.scopedAssets) {
    const scopedSet = new Set(options.scopedAssets.map((a) => a.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "")));
    const beforeCount = rawAssets.length;
    const filtered = rawAssets.filter((a) => {
      const hostname = (a.hostname || "").toLowerCase();
      const url = (a.url || "").toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (scopedSet.has(hostname) || scopedSet.has(url)) return true;
      if (a.dnsRecords) {
        const aRecords = Array.isArray(a.dnsRecords.A) ? a.dnsRecords.A : [];
        const aaaaRecords = Array.isArray(a.dnsRecords.AAAA) ? a.dnsRecords.AAAA : [];
        for (const ip of [...aRecords, ...aaaaRecords]) {
          if (scopedSet.has(ip.toLowerCase())) return true;
        }
      }
      return false;
    });
    if (filtered.length === 0) {
      for (const scopedHost of options.scopedAssets) {
        const clean = scopedHost.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
        filtered.push({
          assetId: `scoped-${clean.replace(/[^a-z0-9]/g, "-")}-${Date.now().toString(36)}`,
          hostname: clean,
          url: `https://${clean}`,
          assetType: "web_application",
          assetClasses: ["scoped_asset"],
          tags: ["scoped_scan", "roe_restricted"],
          technologies: [],
          technologyVersions: {},
          description: `Asset specified in scoped scan (RoE restricted)`,
          discoveryMethod: "manual",
          discoveryEvidence: "User-specified asset for scoped/RoE-restricted scan"
        });
      }
    }
    rawAssets.length = 0;
    rawAssets.push(...filtered);
    console.log(`[DomainIntel] Scoped Scan: Filtered ${beforeCount} discovered assets down to ${rawAssets.length} matching RoE scope (${options.scopedAssets.join(", ")})`);
  }
  await yieldEventLoop();
  let verifiedAssets;
  let unresolvedHypotheses = [];
  try {
    const { verifyAllAssets } = await import("./dns-banner-verify-MIWMYN64.js");
    const verification = await verifyAllAssets(rawAssets, 5);
    const passiveReconSources = /* @__PURE__ */ new Set(["shodan", "censys", "crtsh", "securitytrails", "dehashed", "urlscan", "abuseipdb"]);
    verifiedAssets = [];
    for (const asset of verification.assets) {
      const isLlmInferred = asset.discoveryMethod === "inferred";
      const isUnresolved = asset.dnsStatus === "unresolved";
      const hasPassiveReconEvidence = passiveReconSources.has(asset.source || "");
      if (isLlmInferred && isUnresolved && !hasPassiveReconEvidence) {
        unresolvedHypotheses.push(asset);
      } else {
        verifiedAssets.push(asset);
      }
    }
    const filteredCount = unresolvedHypotheses.length;
    console.log(`[DomainIntel] Verification: ${verification.summary.dnsVerified} DNS verified, ${verification.summary.bannerDetected} banner detected, ${verification.summary.unresolved} unresolved. ${verification.summary.versionsFound} versions found.`);
    if (filteredCount > 0) {
      console.log(`[DomainIntel] DNS Gate: Filtered out ${filteredCount} LLM-inferred subdomains that failed DNS resolution. Only verified assets proceed to analysis.`);
    }
  } catch (err) {
    console.error(`[DomainIntel] DNS/banner verification failed (non-fatal): ${err.message}`);
    verifiedAssets = rawAssets;
  }
  await yieldEventLoop();
  if (passiveRecon) {
    try {
      const shodanObs = passiveRecon.allObservations.filter((o) => o.source === "shodan");
      if (shodanObs.length > 0) {
        const shodanEnrichment = enrichAssetsWithShodanData(verifiedAssets, shodanObs);
        console.log(`[DomainIntel] ${shodanEnrichment.summary}`);
      }
    } catch (err) {
      console.error(`[DomainIntel] Shodan enrichment failed (non-fatal): ${err.message}`);
    }
  }
  await yieldEventLoop();
  let wafNgfwAssessment;
  try {
    console.log(`[DomainIntel] Stage 1.8: Running WAF/NGFW detection for ${org.primaryDomain}`);
    const shodanBanners = [];
    const certOrgs = [];
    const dnsChain = [];
    if (passiveRecon) {
      for (const obs of passiveRecon.allObservations) {
        if (obs.source === "shodan" && obs.evidence?.banner) {
          shodanBanners.push(String(obs.evidence.banner));
        }
        if (obs.source === "shodan" && obs.evidence?.ssl?.cert?.subject?.O) {
          certOrgs.push(String(obs.evidence.ssl.cert.subject.O));
        }
        if (obs.source === "dns" && obs.evidence?.cname) {
          if (Array.isArray(obs.evidence.cname)) dnsChain.push(...obs.evidence.cname.map(String));
          else dnsChain.push(String(obs.evidence.cname));
        }
      }
    }
    wafNgfwAssessment = await runWafNgfwAssessment(org.primaryDomain, {
      timeout: 8e3,
      shodanBanners,
      certOrgs,
      dnsChain
    });
    const wafNames = wafNgfwAssessment.wafDetections.map((w) => `${w.productName} (${w.confidence})`).join(", ");
    const ngfwNames = wafNgfwAssessment.ngfwDetections.map((n) => `${n.productName} (${n.confidence})`).join(", ");
    console.log(`[DomainIntel] Stage 1.8 complete \u2014 WAF: ${wafNames || "none detected"}, NGFW: ${ngfwNames || "none detected"}`);
    console.log(`[DomainIntel]   Scan tuning: ${wafNgfwAssessment.scanTuningProfile.aggressiveness} mode, defensive posture: ${wafNgfwAssessment.defensivePostureScore}/100`);
    const discoveryCmd = buildScanForgeDiscoveryCommand(wafNgfwAssessment.scanTuningProfile, [org.primaryDomain]);
    console.log(`[DomainIntel]   Suggested ScanForge: ${discoveryCmd.substring(0, 200)}...`);
    const nucleiCmd = buildNucleiCommand(wafNgfwAssessment.scanTuningProfile, [`https://${org.primaryDomain}`]);
    console.log(`[DomainIntel]   Suggested Nuclei: ${nucleiCmd.substring(0, 200)}...`);
  } catch (err) {
    console.error(`[DomainIntel] Stage 1.8 WAF/NGFW detection failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  await onProgress?.("analyzing");
  const analyses = await analyzeAssets(verifiedAssets, org, fpContext ? {
    patterns: fpContext.patterns,
    categorySummary: fpContext.categorySummary.map((c) => ({ type: c.type, count: c.count }))
  } : void 0, historicalContext || void 0);
  const rescoringTimeline = [];
  function snapshotScores() {
    const snap = /* @__PURE__ */ new Map();
    for (const a of analyses) {
      snap.set(a.asset.assetId, {
        score: a.hybridRiskScore,
        band: a.riskBand,
        carver: { ...a.carverScores },
        shock: { ...a.shockScores },
        impact: a.impactScore,
        likelihood: a.likelihoodScore
      });
    }
    return snap;
  }
  function recordPhaseDeltas(phase, triggerType, before, description) {
    for (const a of analyses) {
      const prev = before.get(a.asset.assetId);
      if (!prev) continue;
      const delta = a.hybridRiskScore - prev.score;
      if (delta === 0 && a.riskBand === prev.band) continue;
      const factorChanges = [];
      for (const k of Object.keys(prev.carver)) {
        if (a.carverScores[k] !== prev.carver[k]) {
          factorChanges.push({ factor: `CARVER.${k}`, previousValue: prev.carver[k], newValue: a.carverScores[k], reason: description });
        }
      }
      for (const k of Object.keys(prev.shock)) {
        if (a.shockScores[k] !== prev.shock[k]) {
          factorChanges.push({ factor: `SHOCK.${k}`, previousValue: prev.shock[k], newValue: a.shockScores[k], reason: description });
        }
      }
      if (a.impactScore !== prev.impact) {
        factorChanges.push({ factor: "impactScore", previousValue: prev.impact, newValue: a.impactScore, reason: description });
      }
      if (a.likelihoodScore !== prev.likelihood) {
        factorChanges.push({ factor: "likelihoodScore", previousValue: prev.likelihood, newValue: a.likelihoodScore, reason: description });
      }
      rescoringTimeline.push({
        assetId: a.asset.assetId,
        hostname: a.asset.hostname,
        phase,
        triggerType,
        previousScore: prev.score,
        newScore: a.hybridRiskScore,
        delta,
        previousBand: prev.band,
        newBand: a.riskBand,
        changeDescription: `${description}: ${a.asset.hostname} ${delta > 0 ? "+" : ""}${delta} (${prev.band} \u2192 ${a.riskBand})`,
        factorChanges,
        timestamp: Date.now()
      });
    }
  }
  for (const a of analyses) {
    rescoringTimeline.push({
      assetId: a.asset.assetId,
      hostname: a.asset.hostname,
      phase: "initial_scan",
      triggerType: "initial_scan",
      previousScore: 0,
      newScore: a.hybridRiskScore,
      delta: a.hybridRiskScore,
      previousBand: "low",
      newBand: a.riskBand,
      changeDescription: `Initial BIA assessment: ${a.asset.hostname} scored ${a.hybridRiskScore} (${a.riskBand})`,
      factorChanges: [],
      timestamp: Date.now()
    });
  }
  let emailSecurityReport = void 0;
  let hasMx = false;
  await yieldEventLoop();
  {
    const EXCLUSIVE_GROUPS = [
      {
        label: "CDN/WAF provider",
        members: [/^akamai$/i, /^cloudflare$/i, /^cloudfront$/i, /^fastly$/i, /^incapsula$/i, /^sucuri$/i]
      },
      {
        label: "Backend framework",
        members: [/^django$/i, /^flask$/i, /^rails$/i, /^laravel$/i, /^express$/i, /^spring$/i, /^asp\.net$/i]
      },
      {
        label: "CMS platform",
        members: [/^wordpress$/i, /^drupal$/i, /^joomla$/i, /^magento$/i, /^shopify$/i, /^squarespace$/i, /^wix$/i]
      },
      {
        label: "Backend language",
        members: [/^php$/i, /^python$/i, /^ruby$/i, /^java$/i, /^node\.?js$/i, /^go$/i, /^rust$/i]
      }
    ];
    const INCOMPATIBLE_PAIRS = [
      [/^django$/i, /^wordpress$/i, "Django (Python) cannot coexist with WordPress (PHP)"],
      [/^django$/i, /^drupal$/i, "Django (Python) cannot coexist with Drupal (PHP)"],
      [/^flask$/i, /^wordpress$/i, "Flask (Python) cannot coexist with WordPress (PHP)"],
      [/^flask$/i, /^drupal$/i, "Flask (Python) cannot coexist with Drupal (PHP)"],
      [/^rails$/i, /^wordpress$/i, "Rails (Ruby) cannot coexist with WordPress (PHP)"],
      [/^rails$/i, /^drupal$/i, "Rails (Ruby) cannot coexist with Drupal (PHP)"],
      [/^express$/i, /^wordpress$/i, "Express (Node.js) cannot coexist with WordPress (PHP)"],
      [/^spring$/i, /^wordpress$/i, "Spring (Java) cannot coexist with WordPress (PHP)"]
    ];
    let techContradictionsFixed = 0;
    for (const a of analyses) {
      if (!a.asset.technologies || !Array.isArray(a.asset.technologies)) continue;
      const techs = a.asset.technologies;
      const toRemove = /* @__PURE__ */ new Set();
      for (const group of EXCLUSIVE_GROUPS) {
        const matched = techs.filter((t) => group.members.some((re) => re.test(t)));
        if (matched.length > 1) {
          const freq = (tech) => analyses.filter(
            (aa) => (aa.asset.technologies || []).some((t) => t.toLowerCase() === tech.toLowerCase())
          ).length;
          matched.sort((a2, b) => freq(b) - freq(a2));
          for (let i = 1; i < matched.length; i++) {
            toRemove.add(matched[i]);
            console.log(`[TechValidation] ${a.asset.hostname}: removing '${matched[i]}' \u2014 conflicts with '${matched[0]}' in ${group.label} group`);
          }
        }
      }
      for (const [reA, reB, reason] of INCOMPATIBLE_PAIRS) {
        const matchA = techs.find((t) => reA.test(t));
        const matchB = techs.find((t) => reB.test(t));
        if (matchA && matchB && !toRemove.has(matchA) && !toRemove.has(matchB)) {
          const phpSignals = techs.some((t) => /^php$/i.test(t));
          const pythonSignals = techs.some((t) => /^python$/i.test(t));
          const rubySignals = techs.some((t) => /^ruby$/i.test(t));
          const nodeSignals = techs.some((t) => /^node\.?js$/i.test(t));
          let remove;
          if (/wordpress|drupal|joomla/i.test(matchB) && (pythonSignals || rubySignals || nodeSignals) && !phpSignals) {
            remove = matchB;
          } else if (/django|flask/i.test(matchA) && phpSignals && !pythonSignals) {
            remove = matchA;
          } else {
            const freqA = analyses.filter((aa) => (aa.asset.technologies || []).some((t) => t.toLowerCase() === matchA.toLowerCase())).length;
            const freqB = analyses.filter((aa) => (aa.asset.technologies || []).some((t) => t.toLowerCase() === matchB.toLowerCase())).length;
            remove = freqA >= freqB ? matchB : matchA;
          }
          toRemove.add(remove);
          console.log(`[TechValidation] ${a.asset.hostname}: removing '${remove}' \u2014 ${reason}`);
        }
      }
      if (toRemove.size > 0) {
        a.asset.technologies = techs.filter((t) => !toRemove.has(t));
        techContradictionsFixed += toRemove.size;
      }
    }
    if (techContradictionsFixed > 0) {
      console.log(`[DomainIntel] Stage 3.45 Tech Validation: Resolved ${techContradictionsFixed} contradictory technology detections`);
    }
  }
  let kevEnrichment;
  const { parallelWithRetry } = await import("./retry-with-backoff-YHQBYFVA.js");
  const [kevRetry, vulnFeedRetry] = await parallelWithRetry([
    {
      name: "Stage 3.5 KEV Enrichment",
      fn: async () => {
        const preKevSnapshot = snapshotScores();
        await onProgress?.("scoring");
        try {
          const allTechnologies = analyses.flatMap((a) => a.asset.technologies || []);
          const uniqueTechs = Array.from(new Set(allTechnologies.filter(Boolean)));
          if (uniqueTechs.length > 0) {
            const kevCatalog = await fetchKevCatalog();
            const kevMatchesRaw = matchTechnologiesAgainstKev(uniqueTechs, kevCatalog);
            const _globalMpName = emailSecurityReport?.managedProvider?.name || emailSecurityReport?.mx?.provider || null;
            const GLOBAL_MANAGED_PRODUCTS = {
              "Microsoft 365": ["exchange server", "exchange", "outlook"],
              "Google Workspace": ["gmail"],
              "Proofpoint": ["proofpoint"],
              "Mimecast": ["mimecast"]
            };
            const globalManagedProducts = _globalMpName ? GLOBAL_MANAGED_PRODUCTS[_globalMpName] || [] : [];
            const kevMatches = globalManagedProducts.length > 0 ? kevMatchesRaw.filter((m) => {
              const p = (m.product || "").toLowerCase();
              const isManaged = globalManagedProducts.some((mp) => p.includes(mp));
              if (isManaged) {
                console.log(`[KEV] Global filter: removing ${m.cveID} (${m.product}) \u2014 managed by ${_globalMpName}`);
              }
              return !isManaged;
            }) : kevMatchesRaw;
            if (kevMatches.length > 0) {
              const boost = calculateKevRiskBoost(kevMatches);
              const chainSteps = getKevChainSteps(kevMatches);
              kevEnrichment = {
                matches: kevMatches,
                riskBoost: boost.riskBoost,
                ransomwareExposure: boost.ransomwareExposure,
                criticalKevCount: boost.criticalKevCount,
                summary: boost.summary,
                chainSteps
              };
              const _mpName = emailSecurityReport?.managedProvider?.name || emailSecurityReport?.mx?.provider || null;
              const MANAGED_PROVIDER_PRODUCTS = {
                "Microsoft 365": ["exchange server", "exchange", "outlook", "sharepoint"],
                "Google Workspace": ["gmail"],
                "Proofpoint": ["proofpoint"],
                "Mimecast": ["mimecast"]
              };
              const managedProducts = _mpName ? MANAGED_PROVIDER_PRODUCTS[_mpName] || [] : [];
              const isManagedProviderProduct = (kevProduct) => {
                if (managedProducts.length === 0) return false;
                const p = kevProduct.toLowerCase();
                return managedProducts.some((mp) => p.includes(mp));
              };
              let kevIdx = 0;
              for (const a of analyses) {
                kevIdx++;
                if (kevIdx % 10 === 0) await yieldEventLoop();
                const assetTechs = (a.asset.technologies || []).filter(Boolean);
                if (assetTechs.length === 0) continue;
                const assetKevMatches = matchTechnologiesAgainstKev(assetTechs, kevCatalog, a.asset.technologyVersions);
                const existingCves = new Set(a.postureFindings.flatMap((f) => f.cveIds || []));
                const uniqueAssetKevMatches = assetKevMatches.filter((m) => !existingCves.has(m.cveID));
                if (assetKevMatches.length > 0) {
                  const versions = a.asset.technologyVersions || {};
                  const confirmedKevMatches = assetKevMatches.filter((m) => {
                    if (isManagedProviderProduct(m.product || "")) return false;
                    const kevProductLower = (m.product || "").toLowerCase();
                    return Object.entries(versions).some(([tech]) => {
                      const techLower = tech.toLowerCase();
                      return techLower.includes(kevProductLower) || kevProductLower.includes(techLower);
                    });
                  });
                  if (confirmedKevMatches.length > 0) {
                    const assetBoost = Math.min(confirmedKevMatches.reduce((s, m) => s + Math.min(m.severityBoost, 8), 0), 15);
                    a.hybridRiskScore = Math.min(100, a.hybridRiskScore + assetBoost);
                    a.riskBand = riskBand2(a.hybridRiskScore);
                    a.suggestedTier = riskTier(a.hybridRiskScore);
                  }
                  let _isVersionAffected = null;
                  try {
                    const cpeMod = await import("./dynamic-cpe-matcher-HNVLLGIO.js");
                    _isVersionAffected = cpeMod.isVersionAffected;
                  } catch {
                  }
                  uniqueAssetKevMatches.forEach((m) => {
                    if (isManagedProviderProduct(m.product || "")) {
                      console.log(`[DomainIntel] KEV skip: ${m.cveID} (${m.product}) on ${a.asset.hostname} \u2014 product managed by ${_mpName}`);
                      return;
                    }
                    const PRODUCT_ALIASES = {
                      "apache": ["http server", "httpd", "apache2"],
                      "nginx": ["nginx"],
                      "iis": ["internet information services", "iis"],
                      "openssl": ["openssl"],
                      "jquery": ["jquery"]
                    };
                    const versions2 = a.asset.technologyVersions || {};
                    const kevProductLower = (m.product || "").toLowerCase();
                    const kevVendorLower = (m.vendorProject || "").toLowerCase();
                    const matchedOnLower = (m.matchedOn || "").toLowerCase();
                    let detectedVersion;
                    let productSpecificMatch = false;
                    for (const [tech, ver] of Object.entries(versions2)) {
                      const techLower = tech.toLowerCase();
                      const directMatch = techLower.includes(kevProductLower) || kevProductLower.includes(techLower);
                      const aliases = PRODUCT_ALIASES[techLower] || [];
                      const aliasMatch = aliases.some((alias) => kevProductLower.includes(alias) || alias.includes(kevProductLower));
                      if (directMatch || aliasMatch) {
                        detectedVersion = ver;
                        productSpecificMatch = true;
                        break;
                      }
                    }
                    if (!productSpecificMatch) {
                      for (const [tech, ver] of Object.entries(versions2)) {
                        const techLower = tech.toLowerCase();
                        if (techLower.includes(matchedOnLower) || matchedOnLower.includes(techLower)) {
                          break;
                        }
                      }
                    }
                    let versionInRange = true;
                    if (productSpecificMatch && detectedVersion && m.affectedVersionRange) {
                      try {
                        if (_isVersionAffected) {
                          versionInRange = _isVersionAffected(detectedVersion, m.affectedVersionRange);
                          if (!versionInRange) {
                            console.log(`[DomainIntel] KEV version filter: ${m.cveID} skipped \u2014 ${m.product} v${detectedVersion} is NOT in affected range (${m.affectedVersionRange})`);
                          }
                        }
                      } catch {
                      }
                    }
                    if (productSpecificMatch && detectedVersion && !versionInRange) return;
                    let tier;
                    if (productSpecificMatch && detectedVersion) {
                      tier = "confirmed";
                    } else if (detectedVersion || productSpecificMatch) {
                      tier = "probable";
                    } else {
                      tier = "potential";
                    }
                    const severityCap = tier === "confirmed" ? 10 : tier === "probable" ? 6 : 4;
                    const rawSeverity = m.knownRansomware ? 10 : 9;
                    const cappedSeverity = Math.min(rawSeverity, severityCap);
                    const evidenceChain = [
                      `Technology "${m.matchedOn}" detected on asset "${a.asset.hostname}"`,
                      `Matched against CISA KEV entry ${m.cveID} (${m.vendorProject} ${m.product})`
                    ];
                    if (productSpecificMatch && detectedVersion) {
                      evidenceChain.push(`Detected version: ${detectedVersion} of ${m.product} \u2014 product-specific match CONFIRMED`);
                    } else if (detectedVersion && !productSpecificMatch) {
                      evidenceChain.push(`Technology "${m.matchedOn}" detected but version belongs to a different ${kevVendorLower} product \u2014 not ${m.product}. Severity capped.`);
                    } else {
                      evidenceChain.push(`No specific version detected for ${m.product} \u2014 product-family match only (severity capped at ${severityCap}/10)`);
                    }
                    evidenceChain.push(`KEV status: actively exploited in the wild. Due date: ${m.dueDate}`);
                    if (m.knownRansomware) evidenceChain.push(`Ransomware association confirmed`);
                    a.postureFindings.push({
                      id: `kev-${m.cveID}-${a.asset.assetId}`,
                      assetRef: a.asset.assetId,
                      assetHostname: a.asset.hostname,
                      category: "CISA KEV",
                      title: `${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [RANSOMWARE]" : ""}`,
                      severity: cappedSeverity,
                      likelihood: detectedVersion ? 9 : productSpecificMatch ? 5 : 3,
                      // Scale with evidence quality
                      confidence: detectedVersion ? 0.95 : productSpecificMatch ? 0.6 : 0.35,
                      recommendedControls: [m.requiredAction, `Patch ${m.product} immediately`, "Monitor for exploitation indicators"],
                      cveIds: [m.cveID],
                      kevListed: true,
                      exploitAvailable: true,
                      cvssScore: m.knownRansomware ? 9.8 : 9,
                      affectedAssets: [a.asset.hostname],
                      evidenceBasis: "kev_match",
                      evidenceDetail: productSpecificMatch && detectedVersion ? `CONFIRMED: ${m.product} v${detectedVersion} on ${a.asset.hostname} matches CISA KEV entry ${m.cveID}. Due date: ${m.dueDate}. Note: Version-based match \u2014 backported patches may apply on managed hosting.` : `${tier === "probable" ? "PROBABLE" : "POTENTIAL"}: Technology "${m.matchedOn}" on ${a.asset.hostname} matches ${m.vendorProject} product family but specific product ${m.product} not individually confirmed. ${detectedVersion ? `Detected version ${detectedVersion} belongs to a different product.` : "Version not detected \u2014 product family match only."} Severity capped at ${severityCap}/10. Due date: ${m.dueDate}.`,
                      corroborationTier: tier,
                      detectedVersion,
                      versionMatchConfirmed: !!(detectedVersion && versionInRange),
                      evidenceChain
                    });
                  });
                }
              }
              const MAX_KEV_PER_ASSET = 15;
              let kevCapped = 0;
              for (const a of analyses) {
                const kevFindings = a.postureFindings.filter((f) => f.category === "CISA KEV");
                if (kevFindings.length > MAX_KEV_PER_ASSET) {
                  kevFindings.sort((x, y) => y.severity - x.severity || (y.confidence || 0) - (x.confidence || 0));
                  const keep = new Set(kevFindings.slice(0, MAX_KEV_PER_ASSET).map((f) => f.id));
                  const removed = kevFindings.filter((f) => !keep.has(f.id));
                  a.postureFindings = a.postureFindings.filter((f) => f.category !== "CISA KEV" || keep.has(f.id));
                  const removedCves = removed.map((f) => f.cveIds?.[0]).filter(Boolean);
                  a.postureFindings.push({
                    id: `kev-summary-${a.asset.assetId}`,
                    assetRef: a.asset.assetId,
                    assetHostname: a.asset.hostname,
                    category: "CISA KEV",
                    title: `${removed.length} additional KEV entries affect this asset's technology stack`,
                    severity: Math.max(...removed.map((f) => f.severity), 1),
                    likelihood: 3,
                    confidence: 0.3,
                    recommendedControls: ["Review full CISA KEV catalog for this technology stack", "Prioritize patching based on CVSS score and exploit availability"],
                    cveIds: removedCves,
                    kevListed: true,
                    exploitAvailable: false,
                    affectedAssets: [a.asset.hostname],
                    evidenceBasis: "kev_match",
                    evidenceDetail: `SUMMARY: ${removed.length} additional CISA KEV entries match technologies on ${a.asset.hostname}. Top ${MAX_KEV_PER_ASSET} shown individually above. Full list: ${removedCves.slice(0, 10).join(", ")}${removedCves.length > 10 ? ` and ${removedCves.length - 10} more` : ""}.`,
                    corroborationTier: "potential",
                    evidenceChain: [`${removed.length} additional KEV entries consolidated into summary to prevent report inflation`]
                  });
                  kevCapped += removed.length;
                }
              }
              if (kevCapped > 0) {
                console.log(`[DomainIntel] KEV cap: consolidated ${kevCapped} excess KEV findings across assets (max ${MAX_KEV_PER_ASSET} per asset)`);
              }
              console.log(`[DomainIntel] KEV enrichment: ${kevMatches.length} matches, ${chainSteps.length} chain steps, boost=${boost.riskBoost}`);
            }
          }
          recordPhaseDeltas("kev_enrichment", "kev_match", preKevSnapshot, "CISA KEV catalog match");
        } catch (err) {
          console.error(`[DomainIntel] KEV enrichment failed (non-fatal): ${err.message}`);
        }
      },
      options: { maxRetries: 2, initialDelayMs: 2e3 }
      // CISA KEV API can be slow
    },
    {
      name: "Stage 3.6 Vuln Feed Enrichment",
      fn: async () => {
        try {
          const { matchTechnologiesAgainstAllFeeds } = await import("./vuln-feeds-3ZYWGLNW.js");
          const vulnFeedCache = /* @__PURE__ */ new Map();
          let totalVulnsFound = 0;
          let totalTechsMatched = 0;
          let vfIdx = 0;
          for (const a of analyses) {
            vfIdx++;
            if (vfIdx % 10 === 0) await yieldEventLoop();
            const assetTechs = (a.asset.technologies || []).filter(Boolean);
            if (assetTechs.length === 0) continue;
            const uniqueAssetTechs = Array.from(new Set(assetTechs));
            const versionSuffix = Object.entries(a.asset.technologyVersions || {}).sort(([a2], [b]) => a2.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join("&");
            const cacheKey = uniqueAssetTechs.sort().join("|").toLowerCase() + (versionSuffix ? `#${versionSuffix}` : "");
            let vulnResult = vulnFeedCache.get(cacheKey);
            if (!vulnResult) {
              vulnResult = await matchTechnologiesAgainstAllFeeds(uniqueAssetTechs, a.asset.technologyVersions || {});
              vulnFeedCache.set(cacheKey, vulnResult);
            }
            const techVulnMap = /* @__PURE__ */ new Map();
            for (const match of vulnResult.matches) {
              techVulnMap.set(match.technology.toLowerCase(), match);
            }
            const assetTechsLower = assetTechs.map((t) => t.toLowerCase());
            for (const techLower of assetTechsLower) {
              const vulnMatch = techVulnMap.get(techLower);
              if (!vulnMatch) continue;
              const topVulns = vulnMatch.vulns.slice(0, 5);
              for (const vuln of topVulns) {
                if (a.postureFindings.some((f) => f.cveIds?.includes(vuln.cveId))) continue;
                const VULN_PRODUCT_ALIASES = {
                  "apache": ["http server", "httpd", "apache2"],
                  "nginx": ["nginx"],
                  "iis": ["internet information services", "iis"],
                  "openssl": ["openssl"],
                  "jquery": ["jquery"]
                };
                const versions = a.asset.technologyVersions || {};
                const vulnProductLower = (vuln.product || "").toLowerCase();
                const vulnVendorLower = (vuln.vendor || "").toLowerCase();
                let detectedVersion;
                let isProductSpecificVuln = false;
                const matchSpec = vulnMatch._matchSpecificity;
                if (matchSpec === "vendor_only") {
                  isProductSpecificVuln = false;
                } else {
                  for (const [tech, ver] of Object.entries(versions)) {
                    if (isProtocolVersion(tech, ver)) continue;
                    const tl = tech.toLowerCase();
                    const directMatch = tl.includes(vulnProductLower) || vulnProductLower.includes(tl);
                    const aliases = VULN_PRODUCT_ALIASES[tl] || [];
                    const aliasMatch = aliases.some((a2) => vulnProductLower.includes(a2) || a2.includes(vulnProductLower));
                    if (directMatch || aliasMatch) {
                      detectedVersion = ver;
                      isProductSpecificVuln = true;
                      break;
                    }
                  }
                  if (!isProductSpecificVuln) {
                    const techEntry = Object.entries(versions).find(
                      ([tech]) => tech.toLowerCase().includes(techLower) || techLower.includes(tech.toLowerCase())
                    );
                    if (techEntry) {
                      const techName = techEntry[0].toLowerCase();
                      const isVendorOnly = (techName === vulnVendorLower || vulnVendorLower.includes(techName)) && !techName.includes(vulnProductLower) && !vulnProductLower.includes(techName);
                      if (!isVendorOnly) {
                        detectedVersion = techEntry[1];
                        isProductSpecificVuln = true;
                      }
                    }
                  }
                }
                if (detectedVersion && vuln.affectedVersionRange) {
                  const { isVersionAffected } = await import("./dynamic-cpe-matcher-HNVLLGIO.js");
                  if (!isVersionAffected(detectedVersion, vuln.affectedVersionRange)) {
                    continue;
                  }
                }
                let tier;
                if (isProductSpecificVuln && detectedVersion) {
                  tier = "confirmed";
                } else if (detectedVersion || isProductSpecificVuln) {
                  tier = "probable";
                } else {
                  tier = "potential";
                }
                const severityCap = tier === "confirmed" ? 10 : tier === "probable" ? 6 : 4;
                const rawSeverity = vuln.cvssScore ? Math.round(vuln.cvssScore) : 5;
                const cappedSeverity = Math.min(rawSeverity, severityCap);
                const evidenceChain = [
                  `Technology "${vulnMatch.technology}" detected on asset "${a.asset.hostname}"`,
                  `${vuln.cveId} affects ${[vuln.vendor, vuln.product].filter(Boolean).join(" ") || vulnMatch.technology} (CVSS: ${vuln.cvssScore || "N/A"})`,
                  `Sources: ${vuln.sources.join(", ")}`
                ];
                if (isProductSpecificVuln && detectedVersion) {
                  if (vuln.affectedVersionRange) {
                    evidenceChain.push(`Detected version: ${detectedVersion} of ${vuln.product || vulnMatch.technology} \u2014 CONFIRMED within affected range (${vuln.affectedVersionRange})`);
                  } else {
                    evidenceChain.push(`Detected version: ${detectedVersion} of ${vuln.product || vulnMatch.technology} \u2014 product-specific match CONFIRMED`);
                  }
                } else if (!isProductSpecificVuln) {
                  evidenceChain.push(`Technology "${vulnMatch.technology}" matches ${vulnVendorLower} vendor but specific product ${vuln.product || "unknown"} not individually confirmed \u2014 severity capped at ${severityCap}/10`);
                } else {
                  evidenceChain.push(`No specific version detected for ${vuln.product || vulnMatch.technology} \u2014 product-family match only (severity capped at ${severityCap}/10)`);
                }
                if (vuln.kevListed) evidenceChain.push(`Listed on CISA KEV \u2014 actively exploited in the wild`);
                if (vuln.exploitAvailable) evidenceChain.push(`Public exploit available`);
                if (vuln.inTheWild) evidenceChain.push(`Confirmed 0-day exploitation in the wild`);
                a.postureFindings.push({
                  id: `vf-${vuln.cveId}-${a.asset.assetId}`,
                  assetRef: a.asset.assetId,
                  assetHostname: a.asset.hostname,
                  category: vuln.kevListed ? "CISA KEV" : vuln.inTheWild ? "0-Day" : vuln.exploitAvailable ? "Exploitable CVE" : "Known CVE",
                  title: `${vuln.cveId}: ${vuln.title || vuln.description?.substring(0, 100) || "Vulnerability"}${vuln.vendor || vuln.product ? ` (${[vuln.vendor, vuln.product].filter(Boolean).join(" ")})` : ""}`,
                  severity: cappedSeverity,
                  likelihood: detectedVersion ? vuln.kevListed ? 9 : vuln.inTheWild ? 8 : vuln.exploitAvailable ? 7 : 5 : isProductSpecificVuln ? Math.min(vuln.kevListed ? 5 : vuln.exploitAvailable ? 4 : 3, 5) : Math.min(vuln.kevListed ? 3 : vuln.exploitAvailable ? 2 : 2, 3),
                  confidence: detectedVersion ? vuln.cvssScore ? 0.9 : 0.75 : isProductSpecificVuln ? vuln.cvssScore ? 0.55 : 0.4 : 0.3,
                  recommendedControls: [
                    vuln.patchAvailable ? `Apply patch for ${vuln.cveId}` : `Mitigate ${vuln.cveId} \u2014 no patch available`,
                    `Monitor for exploitation of ${vuln.cveId}`,
                    ...!detectedVersion ? [`Verify ${[vuln.vendor, vuln.product].filter(Boolean).join(" ") || vulnMatch.technology} version on ${a.asset.hostname} to confirm vulnerability`] : []
                  ],
                  cveIds: [vuln.cveId],
                  kevListed: vuln.kevListed,
                  exploitAvailable: vuln.exploitAvailable,
                  cvssScore: vuln.cvssScore || void 0,
                  affectedAssets: [a.asset.hostname],
                  evidenceBasis: vuln.kevListed ? "kev_match" : vuln.exploitAvailable ? "confirmed_cve" : "vuln_feed",
                  evidenceDetail: isProductSpecificVuln && detectedVersion ? `CONFIRMED: ${vuln.cveId} affects ${vuln.product || vulnMatch.technology} v${detectedVersion}${vuln.affectedVersionRange ? ` (affected range: ${vuln.affectedVersionRange})` : ""}. Detected on ${a.asset.hostname}. CVSS: ${vuln.cvssScore || "N/A"}. Sources: ${vuln.sources.join(", ")}.` : `${tier === "probable" ? "PROBABLE" : "POTENTIAL"}: ${vuln.cveId} affects ${[vuln.vendor, vuln.product].filter(Boolean).join(" ") || vulnMatch.technology} product family. Technology "${vulnMatch.technology}" detected on ${a.asset.hostname} but ${!isProductSpecificVuln ? `specific product ${vuln.product || "unknown"} not individually confirmed` : "version not detected \u2014 product family match only"}. Severity capped at ${severityCap}/10. CVSS: ${vuln.cvssScore || "N/A"}. Sources: ${vuln.sources.join(", ")}.`,
                  corroborationTier: tier,
                  detectedVersion,
                  versionMatchConfirmed: !!detectedVersion,
                  evidenceChain
                });
              }
            }
            totalVulnsFound += vulnResult.totalVulns;
            totalTechsMatched += vulnResult.matches.length;
          }
          const MAX_VULN_PER_ASSET = 15;
          let vulnCapped = 0;
          for (const a of analyses) {
            const vulnFindings = a.postureFindings.filter(
              (f) => f.evidenceBasis === "vuln_feed" || f.evidenceBasis === "confirmed_cve"
            );
            if (vulnFindings.length > MAX_VULN_PER_ASSET) {
              vulnFindings.sort((x, y) => (y.cvssScore || 0) - (x.cvssScore || 0) || y.severity - x.severity);
              const keep = new Set(vulnFindings.slice(0, MAX_VULN_PER_ASSET).map((f) => f.id));
              const removed = vulnFindings.filter((f) => !keep.has(f.id));
              a.postureFindings = a.postureFindings.filter(
                (f) => f.evidenceBasis !== "vuln_feed" && f.evidenceBasis !== "confirmed_cve" || keep.has(f.id)
              );
              const removedCves = removed.map((f) => f.cveIds?.[0]).filter(Boolean);
              a.postureFindings.push({
                id: `vf-summary-${a.asset.assetId}`,
                assetRef: a.asset.assetId,
                assetHostname: a.asset.hostname,
                category: "Known CVE",
                title: `${removed.length} additional CVEs affect this asset's technology stack`,
                severity: Math.max(...removed.map((f) => f.severity), 1),
                likelihood: 3,
                confidence: 0.3,
                recommendedControls: ["Review full CVE list for this technology stack", "Prioritize patching by CVSS score"],
                cveIds: removedCves,
                kevListed: false,
                exploitAvailable: false,
                affectedAssets: [a.asset.hostname],
                evidenceBasis: "vuln_feed",
                evidenceDetail: `SUMMARY: ${removed.length} additional CVEs match technologies on ${a.asset.hostname}. Top ${MAX_VULN_PER_ASSET} shown individually above. Full list: ${removedCves.slice(0, 10).join(", ")}${removedCves.length > 10 ? ` and ${removedCves.length - 10} more` : ""}.`,
                corroborationTier: "potential",
                evidenceChain: [`${removed.length} additional CVE findings consolidated into summary to prevent report inflation`]
              });
              vulnCapped += removed.length;
            }
          }
          if (vulnCapped > 0) {
            console.log(`[DomainIntel] Vuln feed cap: consolidated ${vulnCapped} excess vuln findings across assets (max ${MAX_VULN_PER_ASSET} per asset)`);
          }
          console.log(`[DomainIntel] Vuln feed enrichment: ${totalVulnsFound} vulns across ${totalTechsMatched} technologies (per-asset matching)`);
        } catch (err) {
          console.error(`[DomainIntel] Vuln feed enrichment failed (non-fatal): ${err.message}`);
        }
      },
      options: { maxRetries: 2, initialDelayMs: 3e3 }
      // NVD/vuln feeds rate-limit aggressively
    }
  ], { maxRetries: 2, initialDelayMs: 2e3 });
  for (const r of [kevRetry, vulnFeedRetry]) {
    if (!r.success) {
      console.error(`[DomainIntel] ${r.stageName} failed after ${r.attempts} attempt(s): ${r.error?.message || "unknown"}`);
    } else if (r.retried) {
      console.log(`[DomainIntel] ${r.stageName} succeeded after ${r.attempts} attempts (${r.totalDurationMs}ms total)`);
    }
  }
  await yieldEventLoop();
  if (passiveRecon) {
    try {
      const shodanObs = passiveRecon.allObservations.filter((o) => o.source === "shodan");
      if (shodanObs.length > 0) {
        const shodanFindings = createShodanPostureFindings(analyses, shodanObs);
        if (shodanFindings.findingsAdded > 0) {
          console.log(`[DomainIntel] ${shodanFindings.summary}`);
        }
        const shodanVerification = verifyCvesWithShodanData(analyses, shodanObs);
        if (shodanVerification.upgraded > 0) {
          console.log(`[DomainIntel] ${shodanVerification.summary}`);
        }
      }
    } catch (err) {
      console.error(`[DomainIntel] Shodan CVE verification failed (non-fatal): ${err.message}`);
    }
  }
  await yieldEventLoop();
  try {
    const { batchLookupCves } = await import("./nvd-cve-lookup-C5TEZRQF.js");
    const allCveIds2 = /* @__PURE__ */ new Set();
    for (const a of analyses) {
      for (const f of a.postureFindings) {
        if (f.cveIds) f.cveIds.forEach((id) => allCveIds2.add(id));
      }
    }
    if (allCveIds2.size > 0) {
      const cveList = Array.from(allCveIds2).slice(0, 50);
      console.log(`[DomainIntel] NVD enrichment: looking up ${cveList.length} CVEs (of ${allCveIds2.size} total)`);
      const nvdResults = await batchLookupCves(cveList);
      const nvdMap = /* @__PURE__ */ new Map();
      for (const r of nvdResults) {
        if (!r.error) nvdMap.set(r.cveId, r);
      }
      let enrichedCount = 0;
      for (const a of analyses) {
        for (const f of a.postureFindings) {
          if (!f.cveIds || f.cveIds.length === 0) continue;
          for (const cveId of f.cveIds) {
            const nvd = nvdMap.get(cveId);
            if (!nvd) continue;
            if (nvd.description && !f.evidenceDetail?.includes(nvd.description.substring(0, 40))) {
              f.evidenceDetail = (f.evidenceDetail || "") + ` NVD: ${nvd.description}`;
            }
            if (nvd.description && !f.nvdDescription) {
              f.nvdDescription = nvd.description;
            }
            if (nvd.cvssV3Score && (!f.cvssScore || f.evidenceBasis === "kev_match")) {
              f.cvssScore = nvd.cvssScore;
            }
            if (nvd.description && f.evidenceChain) {
              f.evidenceChain.push(`NVD Description: ${nvd.description.substring(0, 200)}`);
            }
            if (nvd.cvssV3Vector && f.evidenceChain) {
              f.evidenceChain.push(`CVSS v3.1 Vector: ${nvd.cvssV3Vector}`);
            }
            enrichedCount++;
          }
        }
      }
      console.log(`[DomainIntel] NVD enrichment complete: ${nvdMap.size}/${cveList.length} CVEs resolved, ${enrichedCount} findings enriched`);
    }
  } catch (err) {
    console.error(`[DomainIntel] NVD CVE enrichment failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  let exploitMatchResult;
  const prePortSnapshot = snapshotScores();
  let portRiskStats = { totalAssetsWithPorts: 0, totalHighRiskPorts: 0, totalPortFindings: 0 };
  await Promise.allSettled([
    // Branch A: Stage 3.8 (Exploit Matching) + Stage 3.81 (Cross-link)
    (async () => {
      try {
        const allFindings = analyses.flatMap((a) => a.postureFindings.map((f) => ({
          title: f.title,
          cveIds: f.cveIds,
          corroborationTier: f.corroborationTier,
          severity: f.severity,
          description: f.evidenceDetail
        })));
        const findingsWithCves = allFindings.filter((f) => f.cveIds && f.cveIds.length > 0);
        if (findingsWithCves.length > 0) {
          exploitMatchResult = await matchExploitsToFindings(findingsWithCves);
          console.log(`[DomainIntel] Exploit matching: ${exploitMatchResult.matches.length} CVEs matched \u2192 ${exploitMatchResult.totalMetasploit} MSF modules, ${exploitMatchResult.totalExploitDb} EDB entries, ${exploitMatchResult.totalCalderaAbilities} emulation abilities, ${exploitMatchResult.remoteAccessCount} remote access`);
        }
      } catch (err) {
        console.error(`[DomainIntel] Exploit matching failed (non-fatal): ${err.message}`);
      }
      await yieldEventLoop();
      if (exploitMatchResult && exploitMatchResult.matches.length > 0) {
        const cveToExploit = /* @__PURE__ */ new Map();
        for (const match of exploitMatchResult.matches) {
          cveToExploit.set(match.cveId, match);
        }
        let linkedCount = 0;
        let linkIdx = 0;
        for (const a of analyses) {
          linkIdx++;
          if (linkIdx % 10 === 0) await yieldEventLoop();
          for (const finding of a.postureFindings) {
            if (!finding.cveIds || finding.cveIds.length === 0) continue;
            const matchedExploits = [];
            for (const cveId of finding.cveIds) {
              const exploit = cveToExploit.get(cveId);
              if (exploit) {
                matchedExploits.push({
                  cveId: exploit.cveId,
                  metasploitCount: exploit.metasploitModules.length,
                  exploitDbCount: exploit.exploitDbEntries.length,
                  bestExploit: exploit.bestExploit,
                  calderaAbility: exploit.calderaAbility,
                  isRemoteAccess: exploit.isRemoteAccess
                });
              }
            }
            if (matchedExploits.length > 0) {
              finding.linkedExploits = matchedExploits;
              finding.exploitCount = matchedExploits.reduce(
                (sum, e) => sum + e.metasploitCount + e.exploitDbCount,
                0
              );
              finding.hasRemoteExploit = matchedExploits.some((e) => e.isRemoteAccess);
              finding.hasCalderaAbility = matchedExploits.some((e) => e.calderaAbility != null);
              if (finding.kevListed) {
                finding.evidenceChain = [
                  ...finding.evidenceChain || [],
                  `Exploit validation: ${matchedExploits.reduce((s, e) => s + e.metasploitCount, 0)} Metasploit modules, ${matchedExploits.reduce((s, e) => s + e.exploitDbCount, 0)} ExploitDB entries available`,
                  matchedExploits.some((e) => e.isRemoteAccess) ? "Remote access exploit available \u2014 HIGH PRIORITY for validation testing" : "Local/DoS exploits only",
                  matchedExploits.some((e) => e.calderaAbility) ? "Caldera ability auto-generated for automated validation" : ""
                ].filter(Boolean);
              }
              linkedCount++;
            }
          }
        }
        if (linkedCount > 0) {
          console.log(`[DomainIntel] Cross-linked exploits to ${linkedCount} posture findings (${exploitMatchResult.matches.length} CVEs with exploits)`);
        }
      }
    })(),
    // Branch B: Stage 3.85 (Port-Based Risk Scoring)
    (async () => {
      if (passiveRecon) {
        try {
          const allObs = passiveRecon.allObservations;
          let portIdx = 0;
          for (const a of analyses) {
            portIdx++;
            if (portIdx % 10 === 0) await yieldEventLoop();
            const portRisk = computePortRisk(a.asset, allObs);
            if (portRisk.totalOpenPorts > 0) {
              portRiskStats.totalAssetsWithPorts++;
              portRiskStats.totalHighRiskPorts += portRisk.highRiskPortCount;
              if (portRisk.accessibilityBoost > 0) {
                a.carverScores = {
                  ...a.carverScores,
                  accessibility: clamp(a.carverScores.accessibility + portRisk.accessibilityBoost, 0, 10)
                };
              }
              const portFindings = generatePortPostureFindings(a.asset, portRisk);
              if (portFindings.length > 0) {
                a.postureFindings.push(...portFindings);
                portRiskStats.totalPortFindings += portFindings.length;
              }
              a._portLikelihoodBoost = portRisk.likelihoodBoost;
              a._portExposureScore = portRisk.portExposureScore;
            }
          }
          console.log(`[DomainIntel] Port risk scoring: ${portRiskStats.totalAssetsWithPorts} assets with open ports, ${portRiskStats.totalHighRiskPorts} high-risk ports, ${portRiskStats.totalPortFindings} port findings generated`);
          recordPhaseDeltas("port_risk", "new_port_service", prePortSnapshot, "Port-based risk scoring");
        } catch (err) {
          console.error(`[DomainIntel] Port risk scoring failed (non-fatal): ${err.message}`);
        }
      }
    })()
  ]);
  await yieldEventLoop();
  try {
    const { analyzeEmailSecurity, generateEmailPostureFindings } = await import("./email-security-analyzer-72NPBS7G.js");
    emailSecurityReport = await analyzeEmailSecurity(org.primaryDomain);
    hasMx = emailSecurityReport.mx?.records?.length > 0;
    console.log(`[DomainIntel] Email security: grade=${emailSecurityReport.overallGrade}, score=${emailSecurityReport.overallScore}, weaknesses=${emailSecurityReport.totalWeaknesses}, phishing=${emailSecurityReport.phishingDifficultyRating}, hasMX=${hasMx}`);
    if (!hasMx) {
      console.log(`[DomainIntel] No MX records for ${org.primaryDomain} \u2014 SPF/DKIM findings suppressed (not a mail server)`);
    }
    const emailFindings = generateEmailPostureFindings(org.primaryDomain, emailSecurityReport);
    if (emailFindings.length > 0) {
      const { isMailAsset } = await import("./email-security-analyzer-72NPBS7G.js");
      const mailAsset = analyses.find((a) => isMailAsset({
        hostname: a.asset.hostname,
        assetType: a.asset.assetType,
        essentialService: a.essentialService,
        missionFunction: a.missionFunction,
        tags: a.asset.tags
      }));
      const rootDomainAsset = !mailAsset && hasMx ? analyses.find(
        (a) => a.asset.hostname === org.primaryDomain && (a.asset.assetType === "other" || a.asset.assetClasses?.includes("dns_root"))
      ) : null;
      const targetAsset = mailAsset || rootDomainAsset;
      if (targetAsset) {
        for (const ef of emailFindings) {
          targetAsset.postureFindings.push({
            id: ef.id,
            assetRef: ef.assetRef,
            assetHostname: org.primaryDomain,
            category: ef.category,
            title: ef.title,
            severity: ef.severity,
            confidence: ef.confidence,
            evidenceDetail: ef.evidenceDetail,
            corroborationTier: ef.corroborationTier,
            evidenceChain: [`DNS lookup verified: ${ef.evidenceDetail}`, `Phishing relevance: ${ef.phishingRelevance}`],
            remediation: ef.remediation
          });
        }
        console.log(`[DomainIntel] Added ${emailFindings.length} email security findings to mail asset ${targetAsset.asset.hostname}`);
      } else {
        console.log(`[DomainIntel] Suppressed ${emailFindings.length} email security findings \u2014 no mail-related asset found to assign them to`);
      }
    }
  } catch (err) {
    console.error(`[DomainIntel] Email security analysis failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  try {
    const { isMailAsset } = await import("./email-security-analyzer-72NPBS7G.js");
    let emailIdx = 0;
    for (const a of analyses) {
      emailIdx++;
      if (emailIdx % 10 === 0) await yieldEventLoop();
      const hostname = a.asset.hostname || "";
      const assetIsMailRelated = isMailAsset({
        hostname: a.asset.hostname,
        assetType: a.asset.assetType,
        essentialService: a.essentialService,
        missionFunction: a.missionFunction,
        tags: a.asset.tags
      });
      const isRootDomainWithMail = (a.asset.assetClasses?.includes("dns_root") || a.asset.assetType === "other" && a.asset.hostname === org.primaryDomain) && emailSecurityReport?.mx?.records?.length > 0;
      if (!assetIsMailRelated && !isRootDomainWithMail) {
        const before = a.postureFindings.length;
        a.postureFindings = a.postureFindings.filter((f) => {
          const cat = (f.category || "").toLowerCase();
          const title = (f.title || "").toLowerCase();
          if (cat.includes("email security")) return false;
          if (title.includes("no dmarc") || title.includes("no spf") || title.includes("no dkim")) return false;
          if (title.includes("missing dmarc") || title.includes("missing spf") || title.includes("missing dkim")) return false;
          if (title.includes("dmarc missing") || title.includes("spf missing") || title.includes("dkim missing")) return false;
          if (title.includes("dmarc policy") || title.includes("dmarc record")) return false;
          if (title.includes("email spoofing") || title.includes("email impersonation")) return false;
          if (title.includes("spf record") || title.includes("dkim selector") || title.includes("dkim key")) return false;
          if (title.includes("mail") && (title.includes("security") || title.includes("authentication") || title.includes("record"))) return false;
          return true;
        });
        const removed = before - a.postureFindings.length;
        if (removed > 0) {
          console.log(`[DomainIntel] Suppressed ${removed} email security finding(s) from non-mail asset ${hostname}`);
        }
      }
    }
  } catch (err) {
    console.warn(`[DomainIntel] Non-mail asset filter failed (non-fatal): ${err.message}`);
  }
  {
    const _detectedMailProvider = emailSecurityReport?.managedProvider?.name || emailSecurityReport?.mx?.provider || null;
    const MANAGED_TECH_REPLACEMENTS = {
      "Microsoft 365": {
        strip: [/^microsoft exchange$/i, /^exchange server$/i, /^exchange$/i, /^outlook\.com$/i],
        replace: "Microsoft 365"
      },
      "Google Workspace": {
        strip: [/^gmail server$/i, /^google mail$/i],
        replace: "Google Workspace"
      }
    };
    const techRule = _detectedMailProvider ? MANAGED_TECH_REPLACEMENTS[_detectedMailProvider] : null;
    if (techRule) {
      let techStripped = 0;
      for (const a of analyses) {
        if (!a.asset.technologies || !Array.isArray(a.asset.technologies)) continue;
        const before = a.asset.technologies.length;
        a.asset.technologies = a.asset.technologies.filter((t) => {
          const shouldStrip = techRule.strip.some((re) => re.test(t));
          if (shouldStrip) techStripped++;
          return !shouldStrip;
        });
        if (techRule.replace && before !== a.asset.technologies.length) {
          if (!a.asset.technologies.some((t) => t.toLowerCase() === techRule.replace.toLowerCase())) {
            a.asset.technologies.push(techRule.replace);
          }
        }
        if (a.asset.technologyVersions) {
          for (const key of Object.keys(a.asset.technologyVersions)) {
            if (techRule.strip.some((re) => re.test(key))) {
              delete a.asset.technologyVersions[key];
            }
          }
        }
      }
      if (techStripped > 0) {
        console.log(`[DomainIntel] Stage 3.95 Tech Cleanup: Stripped ${techStripped} managed-provider technologies from asset lists (${_detectedMailProvider} detected as mail provider)`);
      }
    }
  }
  await yieldEventLoop();
  for (const a of analyses) {
    const vulnRisk = computeVulnRisk(a.postureFindings);
    a.vulnRiskScore = vulnRisk.score;
    a.vulnRiskBand = vulnRisk.band;
  }
  console.log(`[DomainIntel] Separated scores computed: criticality (CARVER+SHOCK) vs vulnRisk (confirmed/probable findings only)`);
  const preRecalcSnapshot = snapshotScores();
  try {
    const { applyMissionBaselines } = await import("./scoring-engine-IKNL2BXG.js");
    let missionIdx = 0;
    for (const a of analyses) {
      missionIdx++;
      if (missionIdx % 10 === 0) await yieldEventLoop();
      const normalizedMission = normalizeMissionFunction(a.missionFunction || "public_facing_services");
      const normalizedService = normalizeEssentialService(a.essentialService || "general_server");
      const baselines = applyMissionBaselines(
        a.carverScores,
        a.shockScores,
        normalizedMission,
        normalizedService
      );
      const missionImpact = computeMissionImpact(baselines.carver, baselines.shock);
      const portBoost = a._portLikelihoodBoost || 0;
      const hybrid = computeHybridRisk(
        a.cvssEstimate,
        missionImpact,
        a.contextIndicators,
        a.vulnRiskScore,
        // Pass the CONFIRMED vuln score — this overrides the LLM CVSS for Likelihood
        portBoost
        // Port exposure boost — high-risk ports increase likelihood
      );
      a.carverScores = baselines.carver;
      a.shockScores = baselines.shock;
      a.missionImpactScore = Math.round(missionImpact * 10) / 10;
      a.hybridRiskScore = hybrid.score;
      a.riskBand = hybrid.band;
      a.suggestedTier = riskTier(hybrid.score);
      a.impactScore = hybrid.impactScore;
      a.likelihoodScore = hybrid.likelihoodScore;
      a.assetCriticalityScore = computeAssetCriticality(missionImpact).score;
      a.assetCriticalityBand = computeAssetCriticality(missionImpact).band;
      delete a._portLikelihoodBoost;
      delete a._portExposureScore;
    }
    console.log(`[DomainIntel] Hybrid risk recalculated with mission function baselines + confirmed vuln data + port exposure`);
    recordPhaseDeltas("post_enrichment_recalc", "vuln_scan_complete", preRecalcSnapshot, "Post-enrichment recalculation with confirmed vuln data + mission baselines");
  } catch (err) {
    console.error(`[DomainIntel] Post-enrichment recalculation failed (non-fatal, using pre-enrichment scores): ${err.message}`);
    for (const a of analyses) {
      delete a._portLikelihoodBoost;
      delete a._portExposureScore;
    }
  }
  console.log(`[DomainIntel] Re-scoring timeline: ${rescoringTimeline.length} events recorded across ${analyses.length} assets`);
  await yieldEventLoop();
  let crossModuleEnrichment;
  try {
    console.log(`[DomainIntel] Stage 3.95: Running cross-module enrichment (Bug Bounty, Threat Intel, OpSec, Discovery)`);
    crossModuleEnrichment = await runCrossModuleEnrichment(analyses, org.primaryDomain, passiveRecon);
    console.log(
      `[DomainIntel] Cross-module enrichment complete: ${crossModuleEnrichment.summary.modulesSucceeded}/${crossModuleEnrichment.summary.modulesRun} modules, ${crossModuleEnrichment.summary.totalCorrelations} correlations, ${crossModuleEnrichment.summary.totalNewFindings} new findings, ${crossModuleEnrichment.summary.totalRiskAdjustments} risk adjustments`
    );
    for (const a of analyses) {
      delete a._threatIntelBoost;
    }
  } catch (err) {
    console.error(`[DomainIntel] Cross-module enrichment failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  let breachData;
  if (passiveRecon) {
    const dehashedResult = passiveRecon.connectorResults.find((r) => r.connector === "dehashed");
    if (dehashedResult && dehashedResult.observations.length > 0) {
      const summaryObs = dehashedResult.observations.find((o) => o.tags.includes("breach_summary"));
      const breachObs = dehashedResult.observations.filter((o) => o.tags.includes("breach_database"));
      const subdomainObs = dehashedResult.observations.filter((o) => o.assetType === "subdomain");
      const ipObs = dehashedResult.observations.filter((o) => o.assetType === "ip");
      if (summaryObs?.evidence) {
        breachData = {
          totalExposures: summaryObs.evidence.total_records || 0,
          uniqueEmails: breachObs.reduce((s, o) => s + (o.evidence?.total_records || 0), 0),
          uniqueBreachSources: summaryObs.evidence.unique_breaches || breachObs.length,
          breachSources: summaryObs.evidence.breach_databases || breachObs.map((o) => o.name || "unknown"),
          passwordsExposed: summaryObs.evidence.credentials_exposed || 0,
          hashedPasswordsExposed: breachObs.reduce((s, o) => o.evidence?.has_hashed_passwords ? s + 1 : s, 0),
          credentialPairs: summaryObs.evidence.credentials_exposed || 0,
          subdomainsDiscovered: summaryObs.evidence.unique_subdomains_found || subdomainObs.length,
          ipsDiscovered: summaryObs.evidence.unique_ips_found || ipObs.length,
          queriedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
        console.log(`[DomainIntel] Breach data (early extract): ${breachData.totalExposures} exposures across ${breachData.uniqueBreachSources} breach sources, ${breachData.credentialPairs} credentials exposed`);
      }
    }
  }
  let carverEarlyResult;
  try {
    carverEarlyResult = applyCarverFeedbackEarly(analyses, crossModuleEnrichment, passiveRecon);
    if (carverEarlyResult.summary.totalAdjustments > 0) {
      for (const a of analyses) {
        const missionImpact = computeMissionImpact(a.carverScores, a.shockScores);
        const portBoost = a._portLikelihoodBoost || 0;
        const hybrid = computeHybridRisk(
          a.cvssEstimate,
          missionImpact,
          a.contextIndicators,
          a.vulnRiskScore,
          portBoost
        );
        a.missionImpactScore = Math.round(missionImpact * 10) / 10;
        a.hybridRiskScore = hybrid.score;
        a.riskBand = hybrid.band;
      }
      console.log(
        `[DomainIntel] Stage 3.996: CARVER early pass applied ${carverEarlyResult.summary.totalAdjustments} adjustments (threat intel + discovery context) BEFORE LLM post-enrichment`
      );
    }
  } catch (earlyErr) {
    console.error(`[DomainIntel] Stage 3.996 CARVER early pass failed (non-fatal): ${earlyErr.message}`);
  }
  let postEnrichmentAnalysis;
  let campaigns = [];
  let summaries;
  if (options?.skipEngagement) {
    console.log(`[DomainIntel] Stage 3.99 + scan summary: running in parallel`);
    const [peResult, scanSummary] = await Promise.allSettled([
      (async () => {
        console.log(`[DomainIntel] Stage 3.99: Running LLM post-enrichment analysis`);
        return runPostEnrichmentAnalysis(analyses, org, crossModuleEnrichment);
      })(),
      generateScanOnlySummary(analyses, org, {
        managedProviderName: emailSecurityReport?.managedProvider?.name || emailSecurityReport?.mx?.provider || null,
        breachData: breachData || null,
        riskSignals: passiveRecon?.riskSignals || null
      })
    ]);
    if (peResult.status === "fulfilled") {
      postEnrichmentAnalysis = peResult.value;
      console.log(
        `[DomainIntel] Post-enrichment analysis complete: ${postEnrichmentAnalysis.attackPaths.length} attack paths, ${postEnrichmentAnalysis.blindSpots.length} blind spots, ${postEnrichmentAnalysis.prioritizedRecommendations.length} recommendations`
      );
    } else {
      console.error(`[DomainIntel] Post-enrichment analysis failed (non-fatal): ${peResult.reason?.message || peResult.reason}`);
    }
    summaries = scanSummary.status === "fulfilled" ? scanSummary.value : { executiveSummary: `Domain intelligence analysis of ${org.primaryDomain} identified ${analyses.length} assets.`, threatModelSummary: `Attack surface analysis for ${org.customerName} reveals ${analyses.length} discoverable assets.` };
    console.log(`[DomainIntel] Scan-only mode: skipped campaign design and threat modeling`);
  } else {
    await onProgress?.("recommending");
    console.log(`[DomainIntel] Stage 3.99 + Stage 4: running post-enrichment and campaign design in parallel`);
    const [peResult, campaignResult] = await Promise.allSettled([
      (async () => {
        console.log(`[DomainIntel] Stage 3.99: Running LLM post-enrichment analysis`);
        return runPostEnrichmentAnalysis(analyses, org, crossModuleEnrichment);
      })(),
      generateCampaignRecommendations(analyses, org, kevEnrichment)
    ]);
    if (peResult.status === "fulfilled") {
      postEnrichmentAnalysis = peResult.value;
      console.log(
        `[DomainIntel] Post-enrichment analysis complete: ${postEnrichmentAnalysis.attackPaths.length} attack paths, ${postEnrichmentAnalysis.blindSpots.length} blind spots, ${postEnrichmentAnalysis.prioritizedRecommendations.length} recommendations`
      );
    } else {
      console.error(`[DomainIntel] Post-enrichment analysis failed (non-fatal): ${peResult.reason?.message || peResult.reason}`);
    }
    campaigns = campaignResult.status === "fulfilled" ? campaignResult.value : [];
    if (campaignResult.status === "rejected") {
      console.error(`[DomainIntel] Campaign generation failed (non-fatal): ${campaignResult.reason?.message || campaignResult.reason}`);
    }
    summaries = await generateSummaries(analyses, campaigns, org, historicalContext || void 0, {
      managedProviderName: emailSecurityReport?.managedProvider?.name || emailSecurityReport?.mx?.provider || null,
      breachData: breachData || null,
      riskSignals: passiveRecon?.riskSignals || null
    });
  }
  let carverFeedback;
  try {
    carverFeedback = applyCarverFeedbackLate(
      analyses,
      postEnrichmentAnalysis,
      carverEarlyResult
      // Pass early results to maintain cumulative boost caps
    );
    if (carverFeedback.summary.totalAdjustments > 0) {
      for (const a of analyses) {
        const missionImpact = computeMissionImpact(a.carverScores, a.shockScores);
        const portBoost = a._portLikelihoodBoost || 0;
        const hybrid = computeHybridRisk(
          a.cvssEstimate,
          missionImpact,
          a.contextIndicators,
          a.vulnRiskScore,
          portBoost
        );
        a.missionImpactScore = Math.round(missionImpact * 10) / 10;
        a.hybridRiskScore = hybrid.score;
        a.riskBand = hybrid.band;
        a.suggestedTier = riskTier(hybrid.score);
        a.impactScore = hybrid.impactScore;
        a.likelihoodScore = hybrid.likelihoodScore;
        a.assetCriticalityScore = computeAssetCriticality(missionImpact).score;
        a.assetCriticalityBand = computeAssetCriticality(missionImpact).band;
      }
      console.log(
        `[DomainIntel] Stage 3.995: CARVER late pass (attack chains + blind spots) applied ${carverFeedback.summary.totalAdjustments} adjustments across ${carverFeedback.summary.assetsAffected} assets (avg delta: ${carverFeedback.summary.avgScoreChange})`
      );
    }
  } catch (err) {
    console.error(`[DomainIntel] CARVER feedback loop failed (non-fatal): ${err.message}`);
  }
  const managedProviderName = emailSecurityReport?.managedProvider?.name || emailSecurityReport?.mx?.provider || null;
  const riskOwnershipFilter = createAssetOwnershipFilter({
    managedProviderName,
    primaryDomain: org.primaryDomain,
    additionalDomains: org.additionalDomains
  });
  const { customerOwned, vendorManaged, sharedResponsibility, classifications } = partitionByOwnershipEnhanced(
    analyses,
    (a) => ({
      hostname: a.asset.hostname,
      tags: a.asset.tags,
      cnames: a.asset.dnsRecords?.CNAME ? Array.isArray(a.asset.dnsRecords.CNAME) ? a.asset.dnsRecords.CNAME.map(String) : [String(a.asset.dnsRecords.CNAME)] : void 0
    }),
    riskOwnershipFilter
  );
  const clientOwnedAnalyses = [...customerOwned, ...sharedResponsibility];
  const riskScores = clientOwnedAnalyses.map((a) => {
    const classification = classifications.get(a);
    if (classification && classification.riskMultiplier < 1) {
      return computeAdjustedRiskScore(a.hybridRiskScore, classification);
    }
    return a.hybridRiskScore;
  });
  const vendorRiskSummary = generateVendorRiskSummary(classifications);
  const maxRisk = riskScores.length > 0 ? Math.max(...riskScores) : 0;
  const avgRisk = riskScores.length > 0 ? riskScores.reduce((s, v) => s + v, 0) / riskScores.length : 0;
  const overallRisk = riskScores.length > 0 ? Math.round(maxRisk * 0.6 + avgRisk * 0.4) : 0;
  const overallBand = riskBand2(overallRisk);
  const excludedFromRiskCount = vendorManaged.length;
  if (excludedFromRiskCount > 0 || sharedResponsibility.length > 0) {
    console.log(`[DomainIntel] Risk attribution: ${customerOwned.length} customer-owned, ${sharedResponsibility.length} shared-responsibility, ${vendorManaged.length} vendor-managed (excluded). Total: ${analyses.length}`);
    if (vendorRiskSummary.vendorBreakdown.length > 0) {
      console.log(`[DomainIntel] Vendor breakdown: ${vendorRiskSummary.vendorBreakdown.slice(0, 5).map((v) => `${v.vendor}(${v.count})`).join(", ")}`);
    }
  }
  console.log(`[DomainIntel] Risk scoring: max=${maxRisk}, avg=${Math.round(avgRisk)}, blended=${overallRisk} (60% max + 40% avg), band=${overallBand}`);
  await yieldEventLoop();
  if (fpHashes && fpHashes.size > 0) {
    const { createHash } = await import("crypto");
    let autoFlagged = 0;
    let fpIdx = 0;
    for (const a of analyses) {
      fpIdx++;
      if (fpIdx % 10 === 0) await yieldEventLoop();
      for (const f of a.postureFindings) {
        const hash = createHash("sha256").update(`${f.title}|${a.asset.assetId}|${f.category || ""}`).digest("hex").slice(0, 64);
        const titleHash = createHash("sha256").update(`${f.title}||${f.category || ""}`).digest("hex").slice(0, 64);
        if (fpHashes.has(hash) || fpHashes.has(titleHash)) {
          f.previouslyMarkedFP = true;
          f.fpAutoFlagged = true;
          f.confidence = Math.max(0, f.confidence - 0.3);
          if (!f.evidenceChain) f.evidenceChain = [];
          f.evidenceChain.push("\u26A0 Previously marked as false positive by analyst \u2014 confidence reduced");
          autoFlagged++;
        }
      }
    }
    if (autoFlagged > 0) {
      console.log(`[DomainIntel] FP Auto-flag: ${autoFlagged} findings matched known FP patterns`);
    }
  }
  const totalFindingInstances = analyses.reduce((s, a) => s + a.postureFindings.length, 0);
  const confirmedInstanceCount = analyses.reduce((s, a) => s + a.postureFindings.filter((f) => f.corroborationTier === "confirmed").length, 0);
  const probableInstanceCount = analyses.reduce((s, a) => s + a.postureFindings.filter((f) => f.corroborationTier === "probable").length, 0);
  const potentialInstanceCount = analyses.reduce((s, a) => s + a.postureFindings.filter((f) => f.corroborationTier === "potential" || !f.corroborationTier).length, 0);
  const allCveIds = /* @__PURE__ */ new Set();
  const confirmedCveIds = /* @__PURE__ */ new Set();
  const probableCveIds = /* @__PURE__ */ new Set();
  const potentialCveIds = /* @__PURE__ */ new Set();
  const kevCveIds = /* @__PURE__ */ new Set();
  const cveToAssets = /* @__PURE__ */ new Map();
  let nonCveConfirmedCount = 0;
  let nonCveProbableCount = 0;
  let nonCvePotentialCount = 0;
  const nonCveFingerprintsSeen = /* @__PURE__ */ new Set();
  for (const a of analyses) {
    for (const f of a.postureFindings) {
      if (f.cveIds && f.cveIds.length > 0) {
        for (const cve of f.cveIds) {
          allCveIds.add(cve);
          if (!cveToAssets.has(cve)) cveToAssets.set(cve, /* @__PURE__ */ new Set());
          cveToAssets.get(cve).add(a.asset.hostname);
          if (f.corroborationTier === "confirmed") confirmedCveIds.add(cve);
          else if (f.corroborationTier === "probable") probableCveIds.add(cve);
          else potentialCveIds.add(cve);
          if (f.kevListed) kevCveIds.add(cve);
        }
      } else {
        const fp = (f.title || "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 60);
        if (!nonCveFingerprintsSeen.has(fp)) {
          nonCveFingerprintsSeen.add(fp);
          if (f.corroborationTier === "confirmed") nonCveConfirmedCount++;
          else if (f.corroborationTier === "probable") nonCveProbableCount++;
          else nonCvePotentialCount++;
        }
      }
    }
  }
  const totalNonCveUnique = nonCveConfirmedCount + nonCveProbableCount + nonCvePotentialCount;
  const totalFindings = allCveIds.size + totalNonCveUnique;
  const confirmedFindingsCount = confirmedCveIds.size + nonCveConfirmedCount;
  const probableFindingsCount = probableCveIds.size + nonCveProbableCount;
  const potentialFindingsCount = potentialCveIds.size + nonCvePotentialCount;
  const uniqueCveSummary = {
    uniqueCveCount: allCveIds.size,
    uniqueConfirmedCveCount: confirmedCveIds.size,
    uniqueKevCveCount: kevCveIds.size,
    totalFindingInstances,
    averageAssetsPerCve: allCveIds.size > 0 ? Math.round(Array.from(cveToAssets.values()).reduce((s, set) => s + set.size, 0) / allCveIds.size * 10) / 10 : 0,
    mostWidespreadCves: Array.from(cveToAssets.entries()).sort((a, b) => b[1].size - a[1].size).slice(0, 10).map(([cve, assets]) => ({ cveId: cve, affectedAssetCount: assets.size }))
  };
  console.log(`[DomainIntel] Finding counts: ${totalFindings} unique findings (${allCveIds.size} unique CVEs + ${totalNonCveUnique} non-CVE) from ${totalFindingInstances} instances across ${analyses.length} assets (avg ${uniqueCveSummary.averageAssetsPerCve} assets/CVE)`);
  let subdomainAssetCount = 0;
  if (passiveRecon?.allObservations) {
    const analyzedHostnames = new Set(analyses.map((a) => (a.asset.hostname || "").toLowerCase()));
    const seen = /* @__PURE__ */ new Set();
    for (const o of passiveRecon.allObservations) {
      if (o.assetType !== "subdomain" || !o.name) continue;
      const key = o.name.toLowerCase();
      if (seen.has(key) || analyzedHostnames.has(key)) continue;
      seen.add(key);
      subdomainAssetCount++;
    }
  }
  console.log(`[DomainIntel] Asset totals: ${analyses.length} analyzed + ${subdomainAssetCount} passive recon subdomains = ${analyses.length + subdomainAssetCount} total`);
  await yieldEventLoop();
  let oemCredentials = [];
  try {
    const { matchCredentialsForAssets, persistMatchedCredentials } = await import("./oem-default-creds-2GEUG3OZ.js");
    const allTechAssets = analyses.map((a) => ({
      hostname: a.asset.hostname,
      technologies: a.asset.technologies || [],
      technologyVersions: a.asset.technologyVersions || {},
      openPorts: a.asset.openPorts || []
    }));
    oemCredentials = matchCredentialsForAssets(allTechAssets);
    if (oemCredentials.length > 0) {
      console.log(`[DomainIntel] OEM credential matching: ${oemCredentials.length} default credentials matched across ${new Set(oemCredentials.map((c) => c.matchedAsset)).size} assets`);
      try {
        await persistMatchedCredentials(org.primaryDomain, oemCredentials);
      } catch (persistErr) {
        console.error(`[DomainIntel] Failed to persist OEM credentials (non-fatal): ${persistErr.message}`);
      }
    } else {
      console.log(`[DomainIntel] OEM credential matching: no default credentials matched`);
    }
  } catch (err) {
    console.error(`[DomainIntel] OEM credential matching failed (non-fatal): ${err.message}`);
  }
  await yieldEventLoop();
  let credentialTestSummary;
  if (oemCredentials.length > 0 && scanMode === "active") {
    try {
      const { runCredentialTests, getCredentialsForService } = await import("./credential-tester-5NLVLLA5.js");
      const credTestTargets = [];
      for (const analysis of analyses) {
        const asset = analysis.asset;
        const openPorts = asset.openPorts || [];
        for (const portInfo of openPorts) {
          const port = typeof portInfo === "number" ? portInfo : portInfo?.port;
          if (!port) continue;
          const protocol = port === 22 ? "ssh" : port === 21 ? "ftp" : port === 23 ? "telnet" : port === 3306 ? "mysql" : port === 5432 ? "postgresql" : port === 6379 ? "redis" : port === 27017 ? "mongodb" : port === 5900 ? "vnc" : port === 80 || port === 443 || port === 8080 || port === 8443 ? "http" : "tcp";
          credTestTargets.push({
            host: asset.hostname,
            port,
            protocol,
            product: portInfo?.service || void 0,
            technologies: (asset.technologies || []).map((t) => ({ name: t }))
          });
        }
      }
      if (credTestTargets.length > 0) {
        console.log(`[DomainIntel] Stage 3.98: Running credential tests against ${credTestTargets.length} services`);
        const testResult = await runCredentialTests(credTestTargets, {
          concurrency: 3,
          timeoutMs: 8e3,
          maxCredsPerTarget: 5
        });
        const confirmedCreds = testResult.results.filter((r) => r.status === "success").map((r) => ({
          host: r.target.host,
          port: r.target.port,
          protocol: r.credential.protocol,
          vendor: r.credential.vendor,
          product: r.credential.product,
          username: r.credential.username,
          accessLevel: r.confirmedAccess || r.credential.accessLevel
        }));
        credentialTestSummary = {
          totalTargets: testResult.totalTargets,
          totalCredentialsTested: testResult.totalCredentialsTested,
          successfulLogins: testResult.successfulLogins,
          failedAttempts: testResult.failedAttempts,
          timeouts: testResult.timeouts,
          errors: testResult.errors,
          confirmedCredentials: confirmedCreds
        };
        if (testResult.successfulLogins > 0) {
          console.log(`[DomainIntel] Stage 3.98: ${testResult.successfulLogins} default credential(s) CONFIRMED across ${new Set(confirmedCreds.map((c) => c.host)).size} hosts`);
        } else {
          console.log(`[DomainIntel] Stage 3.98: No default credentials confirmed (${testResult.totalCredentialsTested} tested)`);
        }
      }
    } catch (credTestErr) {
      console.error(`[DomainIntel] Stage 3.98 credential testing failed (non-fatal): ${credTestErr.message}`);
    }
  } else if (oemCredentials.length > 0 && scanMode !== "active") {
    console.log(`[DomainIntel] Stage 3.98: Credential testing SKIPPED (ROE gate: scanMode='${scanMode}', requires 'active'). ${oemCredentials.length} credentials collected for reference only.`);
  }
  await yieldEventLoop();
  let complianceScan;
  try {
    const { runExternalComplianceScan } = await import("./scap-compliance-scanner-AO2SH3V3.js");
    console.log(`[DomainIntel] Stage 3.991: Running external SCAP/STIG compliance scan against ${org.primaryDomain}`);
    complianceScan = await runExternalComplianceScan(org.primaryDomain, { timeout: 15e3 });
    console.log(`[DomainIntel] SCAP compliance: ${complianceScan.complianceScore}% (${complianceScan.passed}/${complianceScan.totalChecks - complianceScan.notApplicable} passed, ${complianceScan.failed} failed)`);
  } catch (scapErr) {
    console.error(`[DomainIntel] Stage 3.991 SCAP compliance scan failed (non-fatal): ${scapErr.message}`);
  }
  await yieldEventLoop();
  let containerExposure;
  try {
    const { analyzeContainerExposure } = await import("./container-discovery-ZV45LGWL.js");
    const additionalHosts = analyses.map((a) => a.asset.hostname).filter((h) => h !== org.primaryDomain);
    console.log(`[DomainIntel] Stage 3.992: Running container exposure scan (${additionalHosts.length + 1} hosts)`);
    containerExposure = await analyzeContainerExposure(org.primaryDomain, additionalHosts, 3e3, 45e3);
    if (containerExposure.totalHits > 0) {
      console.log(`[DomainIntel] Container exposure: ${containerExposure.totalHits} exposed services found (${containerExposure.criticalFindings} critical, ${containerExposure.highFindings} high)`);
    } else {
      console.log(`[DomainIntel] Container exposure: No exposed container infrastructure detected (${containerExposure.totalProbes} probes)`);
    }
  } catch (containerErr) {
    console.error(`[DomainIntel] Stage 3.992 container exposure scan failed (non-fatal): ${containerErr.message}`);
  }
  let pipelineCrawlResult;
  try {
    const { runPipelineCrawlStage, enrichOrgWithBusinessIntel, applyBusinessIntelCarverBoosts } = await import("./pipeline-crawl-stage-HJ5J3D7Y.js");
    pipelineCrawlResult = await runPipelineCrawlStage(analyses, org, org.primaryDomain);
    if (pipelineCrawlResult.businessIntelligence) {
      enrichOrgWithBusinessIntel(org, pipelineCrawlResult.businessIntelligence);
      const bizBoosts = applyBusinessIntelCarverBoosts(analyses, pipelineCrawlResult.businessIntelligence);
      console.log(`[DomainIntel] Stage 3.993: Business intel CARVER boosts applied to ${bizBoosts} assets`);
    }
    if (pipelineCrawlResult.carverAdjustmentsApplied > 0) {
      for (const a of analyses) {
        const missionImpact = computeMissionImpact(a.carverScores, a.shockScores);
        const portBoost = a._portLikelihoodBoost || 0;
        const hybrid = computeHybridRisk(
          a.cvssEstimate,
          missionImpact,
          a.contextIndicators,
          a.vulnRiskScore,
          portBoost
        );
        a.missionImpactScore = Math.round(missionImpact * 10) / 10;
        a.hybridRiskScore = hybrid.score;
        a.riskBand = hybrid.band;
        a.suggestedTier = riskTier(hybrid.score);
        a.impactScore = hybrid.impactScore;
        a.likelihoodScore = hybrid.likelihoodScore;
        a.assetCriticalityScore = computeAssetCriticality(missionImpact).score;
        a.assetCriticalityBand = computeAssetCriticality(missionImpact).band;
      }
      console.log(`[DomainIntel] Stage 3.993: Hybrid risk recalculated after ${pipelineCrawlResult.carverAdjustmentsApplied} crawl CARVER adjustments`);
    }
  } catch (crawlErr) {
    console.error(`[DomainIntel] Stage 3.993 pipeline crawl failed (non-fatal): ${crawlErr.message}`);
  }
  await yieldEventLoop();
  let carverRiskCard = null;
  try {
    const { buildExplainableRiskCard } = await import("./auto-industry-carver-YAORFIXM.js");
    const { createCarverRiskCard } = await import("./db-LSUZDHGJ.js");
    const assetSignals = [];
    if (passiveRecon) {
      const obs = passiveRecon.allObservations || [];
      if (obs.some((o) => o.assetType === "mx")) assetSignals.push("MX Record");
      if (obs.some((o) => o.name?.includes("sso") || o.name?.includes("auth") || o.name?.includes("login"))) assetSignals.push("SSO");
      if (obs.some((o) => o.name?.includes("vpn"))) assetSignals.push("VPN Gateway");
      if (obs.some((o) => o.name?.includes("api"))) assetSignals.push("API Gateway");
      if (obs.some((o) => o.name?.includes("ehr") || o.name?.includes("epic") || o.name?.includes("cerner"))) assetSignals.push("EHR System");
      if (obs.some((o) => o.name?.includes("scada") || o.name?.includes("ics") || o.name?.includes("ot"))) assetSignals.push("SCADA/ICS");
    }
    const keywords = [];
    for (const a of analyses.slice(0, 20)) {
      if (a.technology) keywords.push(...a.technology.split(",").map((t) => t.trim()));
    }
    const riskCard = buildExplainableRiskCard({
      assetId: org.primaryDomain,
      assetLabel: `${org.primaryDomain} (${org.name || "Domain Intel"})`,
      domain: org.primaryDomain,
      keywords: [...new Set(keywords)].slice(0, 20),
      assetSignals: [...new Set(assetSignals)]
    });
    carverRiskCard = riskCard;
    await createCarverRiskCard({
      domain: org.primaryDomain,
      scanTitle: `${org.primaryDomain} \u2014 Domain Intel Pipeline`,
      inferredSector: riskCard.sector,
      sectorConfidence: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : riskCard.confidence >= 0.35 ? "low" : "insufficient",
      naicsCode: riskCard.naics || null,
      naicsLabel: null,
      industry: null,
      regulatoryTags: riskCard.regulatoryProfile || [],
      country: "US",
      carverScores: { criticality: riskCard.scores?.carverShock || 0 },
      shockScores: null,
      hybridScore: riskCard.scores?.hybrid || 0,
      priorityTier: riskCard.scores?.priorityTier || "P3",
      confidenceBand: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : "low",
      topDrivers: riskCard.topDrivers || [],
      recommendedActions: riskCard.recommendedActions || [],
      calderaOps: riskCard.calderaPriority || null,
      threatLikelihood: riskCard.threatLikelihood || null,
      fullRiskCard: riskCard,
      source: "domain_intel_pipeline",
      batchId: null
    });
    console.log(`[DomainIntel] CARVER risk card generated for ${org.primaryDomain}: ${riskCard.scores?.priorityTier} (hybrid=${riskCard.scores?.hybrid})`);
  } catch (carverErr) {
    console.error(`[DomainIntel] CARVER risk card generation failed (non-fatal): ${carverErr.message}`);
  }
  let threatMatchingResult;
  let incidentSearchResult;
  let affiliatedDomainsResult;
  const retryMod = await import("./retry-with-backoff-YHQBYFVA.js");
  const [threatMatchRetry, incidentSearchRetry, affiliatedDomainsRetry] = await retryMod.parallelWithRetry([
    {
      name: "Stage 4.5 Threat Matching",
      fn: async () => {
        const result = runDIThreatMatching(analyses, org, kevEnrichment, crossModuleEnrichment);
        console.log(`[DomainIntel] Threat Matching: ${result.summary.totalMatched} groups matched (top: ${result.summary.topGroupName || "none"}, score: ${result.summary.topGroupScore}), ${result.summary.totalAttackPaths} attack paths, ${result.summary.uniqueTechniques} techniques`);
        return result;
      },
      options: { maxRetries: 2, initialDelayMs: 500 }
      // Threat matching is CPU-bound, fewer retries
    },
    {
      name: "Stage 4.55 Incident Search",
      fn: async () => {
        const { runIncidentSearchEnrichment } = await import("./incident-search-enrichment-Q3MQQFRC.js");
        console.log(`[DomainIntel] Stage 4.55: Running incident search enrichment for ${org.primaryDomain}`);
        const isResult = await runIncidentSearchEnrichment(org.primaryDomain);
        console.log(
          `[DomainIntel] Incident search: ${isResult.totalMatches} matches (${isResult.catalogMatches.length} catalog, ${isResult.webSearchMatches.length} web), ransomware=${isResult.hasRansomwareEvent}, breach=${isResult.hasRecentBreach}, risk floor contribution=${isResult.riskFloorContribution}`
        );
        let ingestResult;
        try {
          const { ingestIncidentSearchResults } = await import("./incident-search-ingest-U7DQJRXE.js");
          ingestResult = await ingestIncidentSearchResults(
            isResult.catalogMatches,
            isResult.webSearchMatches,
            org.primaryDomain
          );
        } catch (ingestErr) {
          console.error(`[DomainIntel] Stage 4.56 auto-ingest failed (non-fatal): ${ingestErr.message}`);
        }
        return { isResult, ingestResult };
      },
      options: { maxRetries: 3, initialDelayMs: 1500 }
      // I/O-bound, more retries with longer backoff
    },
    {
      name: "Stage 4.6 Affiliated Domains",
      fn: async () => {
        const { runAffiliatedDomainDiscovery } = await import("./affiliated-domain-discovery-HJMH3BED.js");
        console.log(`[DomainIntel] Stage 4.6: Running affiliated domain discovery for ${org.primaryDomain}`);
        const adResult = await runAffiliatedDomainDiscovery(
          org.primaryDomain,
          org.companyName || null
        );
        console.log(
          `[DomainIntel] Affiliated domains: ${adResult.totalDiscovered} discovered (registrant: ${adResult.registrantOrg || "unknown"})`
        );
        return adResult;
      },
      options: { maxRetries: 3, initialDelayMs: 1e3 }
      // WHOIS/DNS lookups can be flaky
    }
  ]);
  for (const r of [threatMatchRetry, incidentSearchRetry, affiliatedDomainsRetry]) {
    if (r.retried) {
      console.log(`[DomainIntel] Retry stats: ${r.attempts} attempts, ${r.totalDurationMs}ms total, success=${r.success}`);
    }
  }
  if (threatMatchRetry.success && threatMatchRetry.value) {
    threatMatchingResult = threatMatchRetry.value;
  } else {
    console.error(`[DomainIntel] Threat matching failed after ${threatMatchRetry.attempts} attempt(s): ${threatMatchRetry.error?.message}`);
  }
  if (incidentSearchRetry.success && incidentSearchRetry.value) {
    const { isResult, ingestResult } = incidentSearchRetry.value;
    incidentSearchResult = {
      domain: isResult.domain,
      searchedAt: isResult.searchedAt,
      totalMatches: isResult.totalMatches,
      hasActiveThreats: isResult.hasActiveThreats,
      hasRansomwareEvent: isResult.hasRansomwareEvent,
      hasRecentBreach: isResult.hasRecentBreach,
      riskFloorContribution: isResult.riskFloorContribution,
      summary: isResult.summary,
      catalogMatches: isResult.catalogMatches,
      webSearchMatches: isResult.webSearchMatches,
      newActorsDiscovered: isResult.newActorsDiscovered,
      newTTPsDiscovered: isResult.newTTPsDiscovered
    };
    if (ingestResult) {
      incidentSearchResult.ingestResult = {
        actorsCreated: ingestResult.actorsCreated,
        actorsUpdated: ingestResult.actorsUpdated,
        abilitiesCreated: ingestResult.abilitiesCreated,
        iocsCreated: ingestResult.iocsCreated,
        ttpKnowledgeCreated: ingestResult.ttpKnowledgeCreated
      };
    }
  } else {
    console.error(`[DomainIntel] Stage 4.55 incident search failed after ${incidentSearchRetry.attempts} attempt(s): ${incidentSearchRetry.error?.message}`);
  }
  if (affiliatedDomainsRetry.success && affiliatedDomainsRetry.value) {
    const adResult = affiliatedDomainsRetry.value;
    affiliatedDomainsResult = {
      targetDomain: adResult.targetDomain,
      searchedAt: adResult.searchedAt,
      registrantOrg: adResult.registrantOrg,
      registrantEmail: adResult.registrantEmail,
      affiliatedDomains: adResult.affiliatedDomains.map((d) => ({
        domain: d.domain,
        relationship: d.relationship,
        confidence: d.confidence,
        source: d.source,
        evidence: d.evidence,
        registrantOrg: d.registrantOrg,
        registrantEmail: d.registrantEmail
      })),
      totalDiscovered: adResult.totalDiscovered,
      sourceBreakdown: adResult.sourceBreakdown,
      summary: adResult.summary
    };
  } else {
    console.error(`[DomainIntel] Stage 4.6 affiliated domain discovery failed after ${affiliatedDomainsRetry.attempts} attempt(s): ${affiliatedDomainsRetry.error?.message}`);
  }
  try {
    const { collectTrainingData } = await import("./incident-training-collector-R5JQISSN.js");
    console.log(`[DomainIntel] Stage 4.8: Collecting training data from scan results`);
    const trainingResult = await collectTrainingData({
      scanId: 0,
      // Will be set by the router when persisting
      domain: org.primaryDomain,
      sector: org.sector || void 0,
      incidentSearch: incidentSearchResult || null,
      affiliatedDomains: affiliatedDomainsResult || void 0,
      riskScore: 0,
      // Will be updated after final scoring
      riskBand: "unknown"
    });
    console.log(`[DomainIntel] Training data: ${trainingResult.totalExamples} examples (${trainingResult.highQualityCount} high-quality)`);
  } catch (err) {
    console.error(`[DomainIntel] Stage 4.8 training data collection failed (non-fatal): ${err.message}`);
  }
  let scanDelta;
  try {
    const db = await import("./db-LSUZDHGJ.js");
    const histCtx = await db.getHistoricalScanContext(org.primaryDomain);
    if (histCtx) {
      const currentHostnames = new Set(analyses.map((a) => a.asset.hostname.toLowerCase()));
      const previousHostnames = new Set(histCtx.previousAssets.map((a) => a.hostname.toLowerCase()));
      const newAssets = [...currentHostnames].filter((h) => !previousHostnames.has(h));
      const removedAssets = [...previousHostnames].filter((h) => !currentHostnames.has(h));
      const persistentAssets = [...currentHostnames].filter((h) => previousHostnames.has(h));
      scanDelta = {
        previousScanId: histCtx.previousScanId,
        previousScanDate: histCtx.previousScanDate,
        scanNumber: histCtx.scanCount + 1,
        riskDelta: histCtx.previousRiskScore != null ? overallRisk - histCtx.previousRiskScore : null,
        previousRiskScore: histCtx.previousRiskScore,
        assetDelta: histCtx.previousTotalAssets != null ? analyses.length + subdomainAssetCount - histCtx.previousTotalAssets : null,
        previousTotalAssets: histCtx.previousTotalAssets,
        findingsDelta: histCtx.previousTotalFindings != null ? totalFindings - histCtx.previousTotalFindings : null,
        previousTotalFindings: histCtx.previousTotalFindings,
        newAssets,
        removedAssets,
        persistentAssets
      };
      console.log(`[DomainIntel] Scan Delta: risk ${scanDelta.riskDelta >= 0 ? "+" : ""}${scanDelta.riskDelta}, assets ${scanDelta.assetDelta >= 0 ? "+" : ""}${scanDelta.assetDelta}, findings ${scanDelta.findingsDelta >= 0 ? "+" : ""}${scanDelta.findingsDelta}, new=${newAssets.length}, removed=${removedAssets.length}, persistent=${persistentAssets.length}`);
    }
  } catch (err) {
    console.error(`[DomainIntel] Scan delta computation failed (non-fatal): ${err.message}`);
  }
  let adjustedRisk = overallRisk;
  let adjustedBand = overallBand;
  const floorReasons = [];
  if (kevEnrichment && kevEnrichment.matches.length > 0) {
    const confirmedKevMatches = kevEnrichment.matches.filter((m) => m.matchQuality === "exact_product");
    const confirmedRansomware = confirmedKevMatches.filter((m) => m.knownRansomware);
    const totalKev = kevEnrichment.matches.length;
    const confirmedCount = confirmedKevMatches.length;
    if (confirmedRansomware.length > 0) {
      const floor = 75;
      if (adjustedRisk < floor) {
        floorReasons.push(`KEV ransomware exposure (${confirmedRansomware.length} confirmed ransomware-linked KEV matches out of ${totalKev} total) \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    } else if (confirmedCount >= 3) {
      const floor = 55;
      if (adjustedRisk < floor) {
        floorReasons.push(`${confirmedCount} confirmed CISA KEV matches (${totalKev} total incl. unconfirmed) \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    } else if (confirmedCount > 0) {
      const floor = 45;
      if (adjustedRisk < floor) {
        floorReasons.push(`${confirmedCount} confirmed CISA KEV match(es) (${totalKev} total incl. unconfirmed) \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    } else if (totalKev > 0) {
      console.log(`[DomainIntel] ${totalKev} unconfirmed KEV matches found (advisory only \u2014 no floor adjustment applied)`);
    }
  }
  const criticalFindings = analyses.flatMap((a) => a.postureFindings).filter((f) => f.severity >= 9 && (f.corroborationTier === "confirmed" || f.corroborationTier === "probable"));
  if (criticalFindings.length >= 3) {
    const floor = 65;
    if (adjustedRisk < floor) {
      floorReasons.push(`${criticalFindings.length} critical-severity findings (sev\u22659) \u2192 floor ${floor}`);
      adjustedRisk = floor;
    }
  } else if (criticalFindings.length > 0) {
    const floor = 50;
    if (adjustedRisk < floor) {
      floorReasons.push(`${criticalFindings.length} critical-severity finding(s) \u2192 floor ${floor}`);
      adjustedRisk = floor;
    }
  }
  if (breachData) {
    if (breachData.credentialPairs >= 100) {
      const floor = 60;
      if (adjustedRisk < floor) {
        floorReasons.push(`${breachData.credentialPairs} exposed credentials across ${breachData.uniqueBreachSources} breaches \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    } else if (breachData.totalExposures >= 50) {
      const floor = 50;
      if (adjustedRisk < floor) {
        floorReasons.push(`${breachData.totalExposures} breach exposures \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    } else if (breachData.totalExposures >= 10) {
      const floor = 45;
      if (adjustedRisk < floor) {
        floorReasons.push(`${breachData.totalExposures} breach exposures \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    }
  }
  if (threatMatchingResult && threatMatchingResult.summary.totalMatched >= 2) {
    const topScore = threatMatchingResult.summary.topGroupScore || 0;
    if (topScore >= 70) {
      const floor = 65;
      if (adjustedRisk < floor) {
        floorReasons.push(`${threatMatchingResult.summary.totalMatched} threat groups matched (top: ${threatMatchingResult.summary.topGroupName}, score: ${topScore}) \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    } else {
      const floor = 55;
      if (adjustedRisk < floor) {
        floorReasons.push(`${threatMatchingResult.summary.totalMatched} threat groups matched \u2192 floor ${floor}`);
        adjustedRisk = floor;
      }
    }
  }
  if (confirmedFindingsCount >= 10) {
    const floor = 55;
    if (adjustedRisk < floor) {
      floorReasons.push(`${confirmedFindingsCount} confirmed findings \u2192 floor ${floor}`);
      adjustedRisk = floor;
    }
  }
  if (incidentSearchResult && incidentSearchResult.riskFloorContribution > 0) {
    const floor = incidentSearchResult.riskFloorContribution;
    if (adjustedRisk < floor) {
      const reasons = [];
      if (incidentSearchResult.hasRansomwareEvent) reasons.push("ransomware event");
      if (incidentSearchResult.hasRecentBreach) reasons.push("recent breach");
      if (incidentSearchResult.hasActiveThreats) reasons.push("active threats");
      floorReasons.push(`Incident search: ${incidentSearchResult.totalMatches} incidents (${reasons.join(", ")}) \u2192 floor ${floor}`);
      adjustedRisk = floor;
    }
  }
  if (adjustedRisk !== overallRisk) {
    adjustedBand = riskBand2(adjustedRisk);
    console.log(`[DomainIntel] Risk floor adjustment: ${overallRisk} (${overallBand}) \u2192 ${adjustedRisk} (${adjustedBand}). Reasons: ${floorReasons.join("; ")}`);
  }
  return {
    orgProfile: org,
    assets: analyses,
    campaignRecommendations: campaigns,
    carverRiskCard,
    overallRiskScore: adjustedRisk,
    overallRiskBand: adjustedBand,
    riskFloorApplied: floorReasons.length > 0 ? {
      originalScore: overallRisk,
      originalBand: overallBand,
      adjustedScore: adjustedRisk,
      adjustedBand,
      reasons: floorReasons
    } : void 0,
    riskScoreExclusions: excludedFromRiskCount > 0 ? {
      excludedCount: excludedFromRiskCount,
      totalAnalyzed: analyses.length,
      clientOwnedCount: clientOwnedAnalyses.length,
      sharedResponsibilityCount: sharedResponsibility.length,
      reason: "Vendor-managed assets excluded; shared-responsibility assets scored at reduced multiplier"
    } : void 0,
    vendorRiskSummary,
    executiveSummary: summaries.executiveSummary,
    threatModelSummary: summaries.threatModelSummary,
    // @ts-ignore
    totalAnalyzedAssets: analyses.length,
    totalSubdomainAssets: subdomainAssetCount,
    totalAssets: analyses.length + subdomainAssetCount,
    totalFindings,
    confirmedFindingsCount,
    probableFindingsCount,
    potentialFindingsCount,
    uniqueCveSummary,
    kevEnrichment,
    passiveRecon,
    breachData,
    exploitMatches: exploitMatchResult,
    rescoringTimeline,
    discoveryCoverage: passiveRecon?.discoveryCoverage || void 0,
    emailSecurity: emailSecurityReport || void 0,
    crossModuleEnrichment,
    postEnrichmentAnalysis,
    carverFeedback,
    orgDiscovery: orgDiscoveryResult || void 0,
    oemCredentials,
    credentialTestSummary,
    complianceScan,
    containerExposure,
    wafNgfwAssessment,
    scanDelta,
    pipelineCrawl: pipelineCrawlResult,
    threatMatching: threatMatchingResult,
    incidentSearch: incidentSearchResult,
    affiliatedDomains: affiliatedDomainsResult,
    techStackGrouping: (() => {
      try {
        console.log(`[DomainIntel] Stage 4.6: Computing technology stack grouping...`);
        const tsg = computeTechStackGrouping(analyses);
        console.log(`[DomainIntel] Tech stack grouping: ${tsg.summary.uniqueStacks} unique stacks across ${tsg.summary.totalAssets} assets (largest: ${tsg.summary.largestGroupSize} assets, overlap: ${tsg.summary.stackOverlapPercentage}%)`);
        return tsg;
      } catch (err) {
        console.error(`[DomainIntel] Tech stack grouping failed (non-fatal): ${err.message}`);
        return void 0;
      }
    })(),
    versionThresholdLearning: (() => {
      try {
        const techsWithVersions = analyses.flatMap((a) => {
          const versions = a.asset.technologyVersions || {};
          return Object.entries(versions).filter(([, v]) => v && /^\d/.test(v)).map(([name, version]) => ({ name, version, category: "detected" }));
        });
        if (techsWithVersions.length > 0) {
          const { learnFromDiScan } = (init_version_threshold_service(), __toCommonJS(version_threshold_service_exports));
          const result = learnFromDiScan(techsWithVersions);
          if (result.updated.length > 0) {
            console.log(`[DomainIntel] Stage 4.7: Version threshold learning \u2014 ${result.updated.length} thresholds bumped: ${result.updated.join(", ")}`);
          } else {
            console.log(`[DomainIntel] Stage 4.7: Version threshold learning \u2014 ${techsWithVersions.length} techs checked, no threshold bumps needed`);
          }
          return { techsChecked: techsWithVersions.length, updated: result.updated };
        }
        return void 0;
      } catch (err) {
        console.error(`[DomainIntel] Version threshold learning failed (non-fatal): ${err.message}`);
        return void 0;
      }
    })()
  };
}
var LLM_TIMEOUT_MS, HIGH_RISK_PORTS, MEDIUM_RISK_PORTS;
var init_domainIntel = __esm({
  "server/domainIntel.ts"() {
    init_llm();
    init_kev_service();
    init_passive();
    init_shodan_verifier();
    init_exploit_matcher();
    init_env();
    init_cross_module_enrichment();
    init_org_domain_discovery();
    init_llm_post_enrichment_analysis();
    init_waf_ngfw_detection();
    init_carver_feedback_loop();
    init_managed_provider_filter();
    init_di_threat_matching();
    init_tech_stack_grouping();
    init_llm_json_parser();
    LLM_TIMEOUT_MS = 18e4;
    HIGH_RISK_PORTS = {
      21: { service: "FTP", severity: 8, category: "remote_access", rationale: "FTP transmits credentials in cleartext and is frequently targeted by automated scanners" },
      23: { service: "Telnet", severity: 9, category: "remote_access", rationale: "Telnet transmits all data including credentials in cleartext \u2014 critical exposure" },
      25: { service: "SMTP", severity: 5, category: "mail", rationale: "Open SMTP relay can be abused for spam/phishing if misconfigured" },
      135: { service: "MS-RPC", severity: 7, category: "windows", rationale: "MS-RPC endpoint mapper is commonly exploited in Windows attacks" },
      139: { service: "NetBIOS", severity: 7, category: "windows", rationale: "NetBIOS session service exposes Windows file sharing and is frequently targeted" },
      445: { service: "SMB", severity: 8, category: "windows", rationale: "SMB is the primary vector for ransomware propagation (WannaCry, EternalBlue)" },
      1433: { service: "MSSQL", severity: 8, category: "database", rationale: "Exposed MSSQL server allows direct database attack attempts" },
      1521: { service: "Oracle DB", severity: 8, category: "database", rationale: "Exposed Oracle database listener allows direct database attack attempts" },
      3306: { service: "MySQL", severity: 8, category: "database", rationale: "Exposed MySQL server allows direct database attack and credential brute-force" },
      3389: { service: "RDP", severity: 9, category: "remote_access", rationale: "RDP is the #1 initial access vector for ransomware \u2014 BlueKeep, brute-force, credential stuffing" },
      5432: { service: "PostgreSQL", severity: 7, category: "database", rationale: "Exposed PostgreSQL allows direct database attack attempts" },
      5900: { service: "VNC", severity: 9, category: "remote_access", rationale: "VNC often lacks strong authentication and transmits screen data \u2014 critical exposure" },
      5901: { service: "VNC", severity: 9, category: "remote_access", rationale: "VNC display :1 \u2014 same critical exposure as port 5900" },
      6379: { service: "Redis", severity: 8, category: "database", rationale: "Redis often runs without authentication \u2014 allows arbitrary command execution" },
      8080: { service: "HTTP-Alt", severity: 4, category: "web", rationale: "Alternative HTTP port may expose admin panels or development servers" },
      8443: { service: "HTTPS-Alt", severity: 3, category: "web", rationale: "Alternative HTTPS port \u2014 lower risk but may expose management interfaces" },
      9200: { service: "Elasticsearch", severity: 8, category: "database", rationale: "Exposed Elasticsearch allows data exfiltration and cluster manipulation" },
      11211: { service: "Memcached", severity: 7, category: "database", rationale: "Exposed Memcached can be used for DDoS amplification and data leakage" },
      27017: { service: "MongoDB", severity: 8, category: "database", rationale: "MongoDB often runs without auth \u2014 #1 target for database ransomware" }
    };
    MEDIUM_RISK_PORTS = {
      22: { service: "SSH", severity: 3, category: "remote_access", rationale: "SSH is generally secure but exposed to brute-force attempts" },
      53: { service: "DNS", severity: 4, category: "infrastructure", rationale: "Open DNS resolver can be used for DDoS amplification" },
      110: { service: "POP3", severity: 5, category: "mail", rationale: "POP3 transmits credentials in cleartext" },
      143: { service: "IMAP", severity: 5, category: "mail", rationale: "IMAP transmits credentials in cleartext" },
      161: { service: "SNMP", severity: 6, category: "management", rationale: "SNMP v1/v2c uses community strings \u2014 information disclosure risk" },
      389: { service: "LDAP", severity: 6, category: "directory", rationale: "Exposed LDAP can leak directory information and user accounts" },
      636: { service: "LDAPS", severity: 4, category: "directory", rationale: "LDAPS is encrypted but still exposes directory services" },
      993: { service: "IMAPS", severity: 3, category: "mail", rationale: "Encrypted IMAP \u2014 lower risk but still exposes mail service" },
      995: { service: "POP3S", severity: 3, category: "mail", rationale: "Encrypted POP3 \u2014 lower risk but still exposes mail service" },
      2049: { service: "NFS", severity: 7, category: "file_sharing", rationale: "NFS can expose file systems if misconfigured" },
      5060: { service: "SIP", severity: 5, category: "voip", rationale: "SIP can be exploited for toll fraud and eavesdropping" },
      8888: { service: "HTTP-Alt", severity: 4, category: "web", rationale: "Alternative HTTP port may expose development or admin interfaces" }
    };
  }
});
init_domainIntel();
export {
  analyzeAssets,
  computePortRisk,
  discoverAssets,
  generateCampaignRecommendations,
  generatePortPostureFindings,
  generateScanOnlySummary,
  generateSummaries,
  runDomainIntelPipeline
};
