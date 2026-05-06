import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/passive/domain-health.ts
import { createHash } from "crypto";
import { resolve4, resolveMx, resolveNs, resolveTxt, reverse, Resolver } from "dns/promises";
import { createConnection } from "net";
function makeAssetId(domain, name, source) {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}
async function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallback), ms))
  ]);
}
function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = createConnection({ host, port, timeout: timeoutMs });
    let banner = "";
    let resolved = false;
    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ ...result, latencyMs: Date.now() - start });
    };
    socket.on("connect", () => {
      setTimeout(() => {
        if (!resolved) finish({ connected: true, banner: banner || void 0 });
      }, 2e3);
    });
    socket.on("data", (data) => {
      banner += data.toString("utf8").substring(0, 500);
      if (banner.length > 0 && !resolved) {
        finish({ connected: true, banner });
      }
    });
    socket.on("timeout", () => finish({ connected: false, error: "Connection timed out" }));
    socket.on("error", (err) => finish({ connected: false, error: err.message }));
    setTimeout(() => finish({ connected: false, error: "Hard timeout" }), timeoutMs + 500);
  });
}
function classifySpamhausCode(code, zone) {
  if (code === "127.0.0.2") return { category: "spam_source", severity: "critical", actionRequired: true };
  if (code === "127.0.0.3") return { category: "spam_source", severity: "high", actionRequired: true };
  if (code === "127.0.0.9") return { category: "drop", severity: "critical", actionRequired: true };
  if (code === "127.0.0.30") return { category: "botnet_cc", severity: "critical", actionRequired: true };
  if (code === "127.0.0.4") return { category: "exploit", severity: "high", actionRequired: true };
  if (code === "127.0.0.10" || code === "127.0.0.11") return { category: "dynamic_ip", severity: "informational", actionRequired: false };
  if (code === "127.0.1.2") return { category: "bad_reputation", severity: "high", actionRequired: true };
  if (code === "127.0.1.4" || code === "127.0.1.104") return { category: "phishing", severity: "critical", actionRequired: true };
  if (code === "127.0.1.5" || code === "127.0.1.105") return { category: "malware", severity: "critical", actionRequired: true };
  if (code === "127.0.1.6" || code === "127.0.1.106") return { category: "botnet_cc", severity: "critical", actionRequired: true };
  if (code === "127.0.1.102") return { category: "abused_legit", severity: "high", actionRequired: true };
  if (code === "127.0.1.103") return { category: "abused_legit", severity: "medium", actionRequired: true };
  if (code.startsWith("127.0.2.")) return { category: "newly_registered", severity: "medium", actionRequired: false };
  return { category: "unknown", severity: "medium", actionRequired: true };
}
function classifySorbsCode(code) {
  if (code === "127.0.0.2" || code === "127.0.0.3" || code === "127.0.0.4") return { category: "open_proxy", severity: "high", actionRequired: true };
  if (code === "127.0.0.5") return { category: "open_relay", severity: "high", actionRequired: true };
  if (code === "127.0.0.6" || code === "127.0.0.8") return { category: "spam_source", severity: "critical", actionRequired: true };
  if (code === "127.0.0.7") return { category: "exploit", severity: "critical", actionRequired: true };
  if (code === "127.0.0.9") return { category: "botnet_cc", severity: "critical", actionRequired: true };
  if (code === "127.0.0.10") return { category: "dynamic_ip", severity: "informational", actionRequired: false };
  if (code === "127.0.0.11") return { category: "bad_reputation", severity: "low", actionRequired: false };
  if (code === "127.0.0.14") return { category: "bad_reputation", severity: "low", actionRequired: false };
  return { category: "unknown", severity: "medium", actionRequired: true };
}
function classifyListing(zone, codes) {
  const primaryCode = codes[0] || "127.0.0.2";
  if (zone.includes("spamhaus")) return classifySpamhausCode(primaryCode, zone);
  if (zone.includes("sorbs")) return classifySorbsCode(primaryCode);
  if (zone === "dyna.spamrats.com" || zone === "noptr.spamrats.com") return { category: "dynamic_ip", severity: "informational", actionRequired: false };
  if (zone === "bogons.cymru.com") return { category: "bad_reputation", severity: "informational", actionRequired: false };
  if (zone.includes("barracuda")) return { category: "spam_source", severity: "critical", actionRequired: true };
  if (zone.includes("spamcop")) return { category: "spam_source", severity: "critical", actionRequired: true };
  if (zone.includes("cbl.abuseat")) return { category: "exploit", severity: "high", actionRequired: true };
  if (zone.includes("uceprotect")) {
    if (zone.includes("-3")) return { category: "bad_reputation", severity: "informational", actionRequired: false };
    if (zone.includes("-2")) return { category: "bad_reputation", severity: "low", actionRequired: false };
    return { category: "spam_source", severity: "medium", actionRequired: true };
  }
  if (zone.includes("dronebl")) return { category: "exploit", severity: "high", actionRequired: true };
  if (zone.includes("blocklist.de")) return { category: "exploit", severity: "high", actionRequired: true };
  if (zone.includes("surbl") || zone.includes("uribl")) return { category: "phishing", severity: "high", actionRequired: true };
  return { category: "bad_reputation", severity: "medium", actionRequired: true };
}
function buildLookupUrl(zone, ip) {
  if (zone.includes("spamhaus")) return `https://check.spamhaus.org/listed/?searchterm=${ip}`;
  if (zone.includes("barracuda")) return `https://www.barracudacentral.org/lookups/lookup-reputation?lookup_entry=${ip}`;
  if (zone.includes("spamcop")) return `https://www.spamcop.net/bl.shtml?${ip}`;
  if (zone.includes("sorbs")) return `http://www.sorbs.net/lookup.shtml?${ip}`;
  if (zone.includes("abuseat") || zone.includes("cbl")) return `https://www.abuseat.org/lookup.cgi?ip=${ip}`;
  if (zone.includes("dronebl")) return `https://dronebl.org/lookup?ip=${ip}`;
  if (zone.includes("blocklist.de")) return `https://www.blocklist.de/en/search.html?ip=${ip}`;
  if (zone.includes("surbl")) return `https://www.surbl.org/surbl-analysis?domain=${ip}`;
  if (zone.includes("uribl")) return `https://lookup.uribl.com/?domain=${ip}`;
  return `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${ip}&run=toolpage`;
}
function detectCloudProvider(ptrHostnames) {
  for (const hostname of ptrHostnames) {
    for (const { pattern, provider } of CLOUD_PTR_PATTERNS) {
      if (pattern.test(hostname)) return { isCloud: true, provider };
    }
  }
  return { isCloud: false, provider: null };
}
function getReturnCodeMeaning(zone, code) {
  if (zone.includes("spamhaus")) {
    const meanings = {
      "127.0.0.2": "SBL \u2014 Direct spam source, verified by Spamhaus",
      "127.0.0.3": "CSS \u2014 Spam source detected by automated heuristics",
      "127.0.0.4": "XBL \u2014 Exploited/infected machine (CBL data)",
      "127.0.0.9": "DROP \u2014 Hijacked IP space, do not route or peer",
      "127.0.0.10": "PBL \u2014 Dynamic/residential IP range (ISP-maintained), not a spam indicator",
      "127.0.0.11": "PBL \u2014 Dynamic/residential IP range (Spamhaus-maintained), not a spam indicator",
      "127.0.0.30": "BCL \u2014 Botnet command & control server",
      "127.0.1.2": "DBL \u2014 Low-reputation domain",
      "127.0.1.4": "DBL \u2014 Phishing-related domain",
      "127.0.1.5": "DBL \u2014 Malware-related domain",
      "127.0.1.6": "DBL \u2014 Botnet C&C domain",
      "127.0.1.102": "DBL \u2014 Abused legitimate domain",
      "127.0.1.103": "DBL \u2014 Abused redirector domain",
      "127.0.1.104": "DBL \u2014 Abused domain used in phishing",
      "127.0.1.105": "DBL \u2014 Abused domain used by malware",
      "127.0.1.106": "DBL \u2014 Abused domain hosting C&C"
    };
    if (code.startsWith("127.0.2.")) {
      const hours = parseInt(code.split(".")[3], 10);
      return `ZRD \u2014 Zero-reputation domain, first seen ${hours - 1}\u2013${hours} hours ago`;
    }
    return meanings[code] || `Spamhaus listing (code ${code})`;
  }
  if (zone.includes("sorbs")) {
    const meanings = {
      "127.0.0.2": "HTTP proxy detected",
      "127.0.0.3": "SOCKS proxy detected",
      "127.0.0.4": "Miscellaneous proxy detected",
      "127.0.0.5": "Open SMTP relay",
      "127.0.0.6": "Recently observed sending spam (last 48h)",
      "127.0.0.7": "Web exploit / vulnerability host",
      "127.0.0.8": "Confirmed spam source (block)",
      "127.0.0.9": "Zombie/trojan-infected machine",
      "127.0.0.10": "Dynamic IP range \u2014 not a spam indicator",
      "127.0.0.11": "Bad configuration (open relay test failed)",
      "127.0.0.14": "No reverse DNS (missing PTR record)"
    };
    return meanings[code] || `SORBS listing (code ${code})`;
  }
  if (zone.includes("barracuda")) return "Barracuda Reputation Block List \u2014 IP has sent spam to Barracuda traps";
  if (zone.includes("spamcop")) return "SpamCop \u2014 IP reported by SpamCop users for sending unsolicited email";
  if (zone.includes("cbl") || zone.includes("abuseat")) return "CBL \u2014 IP detected sending spam, likely compromised/infected";
  if (zone.includes("uceprotect")) {
    if (zone.includes("-3")) return "UCEPROTECT Level 3 \u2014 Entire /8 network block listed (very broad, often false positive)";
    if (zone.includes("-2")) return "UCEPROTECT Level 2 \u2014 /24 subnet listed due to multiple abusive IPs";
    return "UCEPROTECT Level 1 \u2014 Individual IP listed for abuse";
  }
  if (zone.includes("dronebl")) return "DroneBL \u2014 IP identified as compromised/drone host";
  if (zone.includes("blocklist.de")) return "blocklist.de \u2014 IP reported for attacks (brute-force, exploits, etc.)";
  if (zone.includes("surbl")) return "SURBL \u2014 Domain found in spam message bodies";
  if (zone.includes("uribl")) return "URIBL \u2014 Domain/URI found in spam message bodies";
  if (zone === "dyna.spamrats.com") return "SpamRATS DYNA \u2014 Dynamic/residential IP range (informational)";
  if (zone === "noptr.spamrats.com") return "SpamRATS NOPTR \u2014 IP has no reverse DNS record";
  if (zone === "spam.spamrats.com") return "SpamRATS SPAM \u2014 IP observed sending spam";
  if (zone.includes("bogons")) return "Team Cymru Bogons \u2014 IP in unallocated/reserved address space";
  return `Listed on ${zone} (return code ${code})`;
}
async function checkDnsbl(ip, timeoutMs, domain) {
  const reversed = ip.split(".").reverse().join(".");
  const now = Date.now();
  const resolver = new Resolver();
  resolver.setServers(["8.8.8.8", "1.1.1.1"]);
  const result = {
    ip,
    totalChecked: 0,
    listed: [],
    clean: [],
    errors: [],
    score: 0,
    reverseDns: [],
    isCloudHosted: false,
    cloudProvider: null,
    actionableCount: 0,
    informationalCount: 0,
    categoryBreakdown: {}
  };
  try {
    const ptrHostnames = await withTimeout(reverse(ip), Math.min(timeoutMs, 5e3), []);
    result.reverseDns = ptrHostnames;
    const cloudDetection = detectCloudProvider(ptrHostnames);
    result.isCloudHosted = cloudDetection.isCloud;
    result.cloudProvider = cloudDetection.provider;
  } catch {
  }
  const allZones = [
    ...DNSBL_ZONES.map((zone) => ({ zone, isDomainBased: false })),
    ...domain ? DOMAIN_BASED_ZONES.map((zone) => ({ zone, isDomainBased: true })) : []
  ];
  const checks = allZones.map(async ({ zone, isDomainBased }) => {
    const query = isDomainBased ? `${domain}.${zone}` : `${reversed}.${zone}`;
    try {
      let addrs = [];
      let ttl = null;
      try {
        const ttlResults = await withTimeout(
          resolver.resolve4(query, { ttl: true }),
          Math.min(timeoutMs, 5e3),
          []
        );
        if (Array.isArray(ttlResults) && ttlResults.length > 0) {
          if (typeof ttlResults[0] === "object" && ttlResults[0].address) {
            addrs = ttlResults.map((r) => r.address);
            ttl = ttlResults[0].ttl ?? null;
          } else {
            addrs = ttlResults;
          }
        }
      } catch (ttlErr) {
        if (ttlErr.code !== "ENOTFOUND" && ttlErr.code !== "ENODATA") {
          addrs = await withTimeout(resolve4(query), Math.min(timeoutMs, 5e3), []);
        }
      }
      result.totalChecked++;
      if (addrs.length > 0) {
        const classification = classifyListing(zone, addrs);
        const codeMeaning = getReturnCodeMeaning(zone, addrs[0]);
        let reason = null;
        try {
          const txtRecords = await withTimeout(
            resolveTxt(query),
            Math.min(timeoutMs, 3e3),
            []
          );
          if (txtRecords.length > 0) {
            reason = txtRecords.map((r) => r.join("")).join(" | ").substring(0, 500);
          }
        } catch {
        }
        const fpIndicators = [];
        if (result.isCloudHosted && classification.category === "dynamic_ip") {
          fpIndicators.push(`IP belongs to ${result.cloudProvider} \u2014 PBL/dynamic listings are expected for cloud-hosted IPs and do not indicate abuse`);
        }
        if (result.isCloudHosted && zone.includes("uceprotect") && (zone.includes("-2") || zone.includes("-3"))) {
          fpIndicators.push(`UCEPROTECT L2/L3 lists entire subnets/blocks \u2014 ${result.cloudProvider} IP ranges are frequently listed regardless of individual IP behavior`);
        }
        if (zone === "noptr.spamrats.com" && result.reverseDns.length > 0) {
          fpIndicators.push("SpamRATS NOPTR listing but IP actually has PTR records \u2014 may be stale listing");
        }
        if (zone.includes("bogons") && result.reverseDns.length > 0) {
          fpIndicators.push("Bogon listing but IP has valid PTR \u2014 likely allocated since last bogon list update");
        }
        if (classification.category === "dynamic_ip" && result.reverseDns.some((h) => /static|dedicated|server/i.test(h))) {
          fpIndicators.push("Listed as dynamic IP but PTR hostname suggests static/dedicated server");
        }
        if (ttl !== null && ttl > 86400) {
        }
        if (ttl !== null && ttl < 300) {
          fpIndicators.push(`Very low TTL (${ttl}s) \u2014 listing may be recently added or frequently updated`);
        }
        let finalSeverity = classification.severity;
        let finalActionRequired = classification.actionRequired;
        if (fpIndicators.length >= 2 && classification.severity !== "critical") {
          finalSeverity = "informational";
          finalActionRequired = false;
        }
        result.listed.push({
          zone,
          result: addrs,
          reason,
          lookupUrl: buildLookupUrl(zone, isDomainBased ? domain || ip : ip),
          category: classification.category,
          severity: finalSeverity,
          actionRequired: finalActionRequired,
          firstSeenAt: now,
          ttl,
          returnCodeMeaning: codeMeaning,
          falsePositiveIndicators: fpIndicators
        });
      } else {
        result.clean.push(zone);
      }
    } catch (err) {
      result.totalChecked++;
      if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
        result.clean.push(zone);
      } else {
        result.errors.push(`${zone}: ${err.code || err.message}`);
      }
    }
  });
  await Promise.all(checks);
  result.actionableCount = result.listed.filter((l) => l.actionRequired).length;
  result.informationalCount = result.listed.filter((l) => !l.actionRequired).length;
  for (const listing of result.listed) {
    result.categoryBreakdown[listing.category] = (result.categoryBreakdown[listing.category] || 0) + 1;
  }
  result.score = result.totalChecked > 0 ? Math.round(result.listed.length / result.totalChecked * 100) : 0;
  return result;
}
async function testSmtp(host, timeoutMs) {
  const result = {
    host,
    port: 25,
    connected: false,
    supportsStartTls: false,
    supportsEhlo: false,
    openRelay: false,
    latencyMs: 0,
    ehloExtensions: []
  };
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = createConnection({ host, port: 25, timeout: timeoutMs });
    let buffer = "";
    let phase = "greeting";
    let resolved = false;
    const finish = () => {
      if (resolved) return;
      resolved = true;
      result.latencyMs = Date.now() - start;
      try {
        socket.write("QUIT\r\n");
      } catch {
      }
      setTimeout(() => socket.destroy(), 500);
      resolve(result);
    };
    socket.on("connect", () => {
      result.connected = true;
    });
    socket.on("data", (data) => {
      buffer += data.toString("utf8");
      const lines = buffer.split("\r\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (phase === "greeting" && (line.startsWith("220") || line.startsWith("250"))) {
          result.banner = line;
          phase = "ehlo";
          socket.write("EHLO healthcheck.local\r\n");
        } else if (phase === "ehlo") {
          if (line.startsWith("250-") || line.startsWith("250 ")) {
            result.supportsEhlo = true;
            const ext = line.substring(4).trim();
            if (ext) result.ehloExtensions.push(ext);
            if (ext.toUpperCase() === "STARTTLS") result.supportsStartTls = true;
          }
          if (line.startsWith("250 ")) {
            phase = "done";
            finish();
          }
        }
      }
    });
    socket.on("timeout", () => {
      result.error = "Connection timed out";
      finish();
    });
    socket.on("error", (err) => {
      result.error = err.message;
      finish();
    });
    setTimeout(() => {
      if (!resolved) {
        result.error = "Hard timeout";
        finish();
      }
    }, timeoutMs + 1e3);
  });
}
async function lookupSpf(domain, timeoutMs) {
  try {
    const txtRecords = await withTimeout(resolveTxt(domain), timeoutMs, []);
    const spfRecord = txtRecords.flat().find((r) => r.startsWith("v=spf1"));
    if (!spfRecord) {
      return { found: false, record: null, mechanisms: [], policy: "none", includeCount: 0, spoofable: true };
    }
    const parts = spfRecord.split(/\s+/);
    const mechanisms = parts.filter((p) => !p.startsWith("v="));
    const allPart = parts.find((p) => /^[~?+-]?all$/.test(p)) || "";
    let policy = "unknown";
    if (allPart.startsWith("-") || allPart === "-all") policy = "hardfail";
    else if (allPart.startsWith("~") || allPart === "~all") policy = "softfail";
    else if (allPart.startsWith("?") || allPart === "?all") policy = "neutral";
    else if (allPart === "+all" || allPart === "all") policy = "none";
    else if (!allPart) policy = "none";
    const includeCount = mechanisms.filter((m) => m.startsWith("include:")).length;
    const spoofable = policy === "none" || policy === "neutral" || !spfRecord;
    return { found: true, record: spfRecord, mechanisms, policy, includeCount, spoofable };
  } catch {
    return { found: false, record: null, mechanisms: [], policy: "none", includeCount: 0, spoofable: true };
  }
}
async function lookupDmarc(domain, timeoutMs) {
  try {
    const txtRecords = await withTimeout(resolveTxt(`_dmarc.${domain}`), timeoutMs, []);
    const dmarcRecord = txtRecords.flat().find((r) => r.startsWith("v=DMARC1"));
    if (!dmarcRecord) {
      return { found: false, record: null, policy: "none", subdomainPolicy: null, reportUri: null, pct: 100, spoofable: true };
    }
    const tags = Object.fromEntries(
      dmarcRecord.split(";").map((p) => p.trim().split("=").map((s) => s.trim())).filter((p) => p.length === 2)
    );
    let policy = "unknown";
    if (tags.p === "reject") policy = "reject";
    else if (tags.p === "quarantine") policy = "quarantine";
    else if (tags.p === "none") policy = "none";
    const pct = tags.pct ? parseInt(tags.pct, 10) : 100;
    const spoofable = policy === "none" || !dmarcRecord;
    return {
      found: true,
      record: dmarcRecord,
      policy,
      subdomainPolicy: tags.sp || null,
      reportUri: tags.rua || null,
      pct,
      spoofable
    };
  } catch {
    return { found: false, record: null, policy: "none", subdomainPolicy: null, reportUri: null, pct: 100, spoofable: true };
  }
}
async function checkMailPorts(host, timeoutMs) {
  const results = await Promise.all(
    ENTERPRISE_MAIL_PORTS.map(async (mp) => {
      const tcp = await tcpConnect(host, mp.port, Math.min(timeoutMs, 5e3));
      return {
        port: mp.port,
        service: mp.service,
        protocol: mp.protocol,
        connected: tcp.connected,
        banner: tcp.banner,
        latencyMs: tcp.latencyMs,
        host,
        error: tcp.error
      };
    })
  );
  return results;
}
async function checkPtr(ip, domain, timeoutMs) {
  const result = { ip, hostnames: [], hasPtrRecord: false, matchesForwardDns: false };
  try {
    const hostnames = await withTimeout(reverse(ip), timeoutMs, []);
    result.hostnames = hostnames;
    result.hasPtrRecord = hostnames.length > 0;
    if (hostnames.length > 0) {
      for (const hostname of hostnames) {
        try {
          const ips = await withTimeout(resolve4(hostname), 3e3, []);
          if (ips.includes(ip)) {
            result.matchesForwardDns = true;
            break;
          }
        } catch {
        }
      }
    }
  } catch (err) {
    result.error = err.code || err.message;
  }
  return result;
}
async function getIpBlockInfo(ip, timeoutMs) {
  const result = { ip };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
        signal: controller.signal,
        headers: { Accept: "application/rdap+json" }
      });
      if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
      const data = await res.json();
      result.networkName = data.name;
      result.networkCidr = data.handle;
      result.startAddress = data.startAddress;
      result.endAddress = data.endAddress;
      result.country = data.country;
      if (data.entities) {
        for (const entity of data.entities) {
          if (entity.vcardArray) {
            const vcard = entity.vcardArray[1];
            for (const field of vcard) {
              if (field[0] === "fn") result.organization = field[3];
            }
          }
        }
      }
      if (data.links) {
        for (const link of data.links) {
          if (link.href?.includes("/autnum/")) {
            const asnMatch = link.href.match(/\/autnum\/(\d+)/);
            if (asnMatch) result.asn = parseInt(asnMatch[1], 10);
          }
        }
      }
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    result.error = err.message;
  }
  return result;
}
async function checkDnsHealth(domain, timeoutMs) {
  const result = {
    domain,
    nameservers: [],
    soaConsistent: true,
    soaSerials: {},
    nsConsistent: true,
    nsRecordSets: {},
    zoneTransferBlocked: true,
    zoneTransferResults: {},
    recursionDisabled: true,
    glueRecordsValid: true,
    issues: [],
    score: 100
  };
  try {
    result.nameservers = await withTimeout(resolveNs(domain), timeoutMs, []);
  } catch {
    result.issues.push("Failed to resolve NS records");
    result.score -= 30;
    return result;
  }
  if (result.nameservers.length === 0) {
    result.issues.push("No NS records found");
    result.score -= 30;
    return result;
  }
  if (result.nameservers.length < 2) {
    result.issues.push("Only 1 nameserver found \u2014 no redundancy");
    result.score -= 15;
  }
  const { Resolver: Resolver2 } = await import("dns");
  for (const ns of result.nameservers.slice(0, 4)) {
    try {
      const nsIps = await withTimeout(resolve4(ns), 3e3, []);
      if (nsIps.length === 0) continue;
      const resolver = new Resolver2();
      resolver.setServers([nsIps[0]]);
      const soaResult = await new Promise((resolve, reject) => {
        resolver.resolveSoa(domain, (err, soa) => err ? reject(err) : resolve(soa));
      });
      if (soaResult?.serial) {
        result.soaSerials[ns] = soaResult.serial;
      }
    } catch {
      result.soaSerials[ns] = -1;
    }
  }
  const serials = Object.values(result.soaSerials).filter((s) => s > 0);
  if (serials.length > 1 && new Set(serials).size > 1) {
    result.soaConsistent = false;
    result.issues.push(`SOA serial mismatch across nameservers: ${JSON.stringify(result.soaSerials)}`);
    result.score -= 20;
  }
  for (const ns of result.nameservers.slice(0, 4)) {
    try {
      const nsIps = await withTimeout(resolve4(ns), 3e3, []);
      if (nsIps.length === 0) continue;
      const resolver = new Resolver2();
      resolver.setServers([nsIps[0]]);
      const nsRecords = await new Promise((resolve, reject) => {
        resolver.resolveNs(domain, (err, addrs) => err ? reject(err) : resolve(addrs));
      });
      result.nsRecordSets[ns] = nsRecords.sort();
    } catch {
      result.nsRecordSets[ns] = [];
    }
  }
  const nsSets = Object.values(result.nsRecordSets).filter((s) => s.length > 0);
  if (nsSets.length > 1) {
    const first = JSON.stringify(nsSets[0]);
    for (let i = 1; i < nsSets.length; i++) {
      if (JSON.stringify(nsSets[i]) !== first) {
        result.nsConsistent = false;
        result.issues.push("NS records are inconsistent across nameservers");
        result.score -= 15;
        break;
      }
    }
  }
  for (const ns of result.nameservers.slice(0, 2)) {
    try {
      const nsIps = await withTimeout(resolve4(ns), 3e3, []);
      if (nsIps.length === 0) {
        result.zoneTransferResults[ns] = "error";
        continue;
      }
      const axfrResult = await tcpConnect(nsIps[0], 53, 5e3);
      if (axfrResult.connected) {
        result.zoneTransferResults[ns] = "blocked";
      } else {
        result.zoneTransferResults[ns] = "blocked";
      }
    } catch {
      result.zoneTransferResults[ns] = "error";
    }
  }
  for (const ns of result.nameservers) {
    try {
      const ips = await withTimeout(resolve4(ns), 3e3, []);
      if (ips.length === 0) {
        result.glueRecordsValid = false;
        result.issues.push(`Nameserver ${ns} has no A record \u2014 missing glue record`);
        result.score -= 10;
      }
    } catch {
      result.glueRecordsValid = false;
      result.issues.push(`Nameserver ${ns} failed to resolve`);
      result.score -= 10;
    }
  }
  result.score = Math.max(0, result.score);
  return result;
}
async function checkTcpPorts(host, ports, timeoutMs) {
  const results = await Promise.all(
    ports.map(async (port) => {
      const r = await tcpConnect(host, port, timeoutMs);
      return { host, port, ...r };
    })
  );
  return results;
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
async function runDomainHealthCheck(domain, timeoutMs = 3e4) {
  const start = Date.now();
  const issues = [];
  let primaryIps = [];
  try {
    primaryIps = await withTimeout(resolve4(domain), 5e3, []);
  } catch {
  }
  let mxRecords = [];
  try {
    mxRecords = await withTimeout(resolveMx(domain), 5e3, []);
    mxRecords.sort((a, b) => a.priority - b.priority);
  } catch {
  }
  const primaryIp = primaryIps[0];
  const primaryMx = mxRecords[0]?.exchange;
  const [dnsblResult, smtpResults, dnsHealthResult, ptrResults, ipInfoResults, tcpResults, spfResult, dmarcResult, mailPortResults] = await Promise.all([
    // DNSBL check on primary IP
    primaryIp ? checkDnsbl(primaryIp, timeoutMs, domain) : Promise.resolve(null),
    // SMTP test on all MX servers (max 3)
    Promise.all(
      mxRecords.slice(0, 3).map((mx) => testSmtp(mx.exchange, Math.min(timeoutMs, 15e3)))
    ),
    // DNS Health diagnostic
    checkDnsHealth(domain, timeoutMs),
    // PTR check on primary IP + MX IPs
    (async () => {
      const ipsToCheck = new Set(primaryIps);
      for (const mx of mxRecords.slice(0, 3)) {
        try {
          const mxIps = await withTimeout(resolve4(mx.exchange), 3e3, []);
          mxIps.forEach((ip) => ipsToCheck.add(ip));
        } catch {
        }
      }
      return Promise.all(Array.from(ipsToCheck).slice(0, 5).map((ip) => checkPtr(ip, domain, 5e3)));
    })(),
    // IP block info for primary IP
    primaryIp ? getIpBlockInfo(primaryIp, 1e4).then((r) => [r]) : Promise.resolve([]),
    // TCP connectivity check on common web ports (mail ports are checked separately via MX)
    primaryIp ? checkTcpPorts(primaryIp, [80, 443], Math.min(timeoutMs, 1e4)) : Promise.resolve([]),
    // SPF record lookup
    lookupSpf(domain, 5e3),
    // DMARC record lookup
    lookupDmarc(domain, 5e3),
    // Enterprise mail port scan on primary MX host (only if MX records exist — avoids false positives on web-only hosts)
    primaryMx ? checkMailPorts(primaryMx, Math.min(timeoutMs, 1e4)) : Promise.resolve([])
  ]);
  let blacklistScore = 100;
  if (dnsblResult) {
    const actionableListings = dnsblResult.listed.filter((l) => l.actionRequired);
    const informationalListings = dnsblResult.listed.filter((l) => !l.actionRequired);
    const severityPenalty = { critical: 10, high: 7, medium: 4, low: 2, informational: 0.5 };
    let totalPenalty = 0;
    for (const listing of dnsblResult.listed) {
      totalPenalty += severityPenalty[listing.severity] ?? 4;
    }
    blacklistScore = Math.max(0, Math.round(100 - totalPenalty));
    if (dnsblResult.listed.length > 0) {
      const criticalListings = actionableListings.filter((l) => l.severity === "critical" || l.severity === "high");
      if (criticalListings.length > 0) {
        const categoryGroups = /* @__PURE__ */ new Map();
        for (const l of criticalListings) {
          const existing = categoryGroups.get(l.category) || [];
          existing.push(l);
          categoryGroups.set(l.category, existing);
        }
        for (const [cat, listings] of Array.from(categoryGroups.entries())) {
          const zoneNames = listings.map((l) => l.zone).join(", ");
          const reasons = listings.filter((l) => l.reason).map((l) => l.reason).slice(0, 2);
          const reasonStr = reasons.length > 0 ? ` \u2014 Reason: ${reasons.join("; ")}` : "";
          issues.push({
            severity: "critical",
            category: "blacklist",
            message: `IP ${primaryIp} listed for ${cat.replace(/_/g, " ")} on ${listings.length} list(s): ${zoneNames}${reasonStr}`
          });
        }
      }
      if (informationalListings.length > 0) {
        const infoZones = informationalListings.map((l) => `${l.zone} (${l.category.replace(/_/g, " ")})`).join(", ");
        issues.push({
          severity: "info",
          category: "blacklist",
          message: `IP ${primaryIp} appears on ${informationalListings.length} informational list(s) \u2014 not indicative of abuse: ${infoZones}`
        });
      }
    }
  } else if (!primaryIp) {
    blacklistScore = 0;
    issues.push({ severity: "critical", category: "blacklist", message: "Could not resolve domain to an IP address \u2014 blacklist check skipped" });
  }
  let mailScore = 100;
  if (mxRecords.length === 0) {
    const isSubdomain = domain.split(".").length > 2;
    mailScore = isSubdomain ? 100 : 50;
    if (!isSubdomain) {
      issues.push({ severity: "warning", category: "mailServer", message: "No MX records found \u2014 domain cannot receive email (expected for non-mail domains)" });
    } else {
      issues.push({ severity: "info", category: "mailServer", message: "No MX records found \u2014 expected for subdomains" });
    }
  } else {
    const connectedMx = smtpResults.filter((r) => r.connected);
    if (connectedMx.length === 0) {
      mailScore = 30;
      issues.push({ severity: "critical", category: "mailServer", message: "None of the MX servers are reachable on port 25" });
    } else {
      const noTls = connectedMx.filter((r) => !r.supportsStartTls);
      if (noTls.length > 0) {
        mailScore -= 20;
        issues.push({ severity: "warning", category: "mailServer", message: `${noTls.length} mail server(s) do not support STARTTLS: ${noTls.map((r) => r.host).join(", ")}` });
      }
      if (connectedMx.length < mxRecords.length) {
        mailScore -= 10;
        issues.push({ severity: "warning", category: "mailServer", message: `${mxRecords.length - connectedMx.length} of ${mxRecords.length} MX servers are unreachable` });
      }
    }
  }
  const dnsScore = dnsHealthResult?.score ?? 0;
  if (dnsHealthResult) {
    for (const issue of dnsHealthResult.issues) {
      issues.push({ severity: issue.includes("mismatch") || issue.includes("No NS") ? "critical" : "warning", category: "dnsHealth", message: issue });
    }
  }
  let ptrScore = 100;
  if (ptrResults.length === 0) {
    ptrScore = 50;
    issues.push({ severity: "warning", category: "reverseDns", message: "No IPs to check for reverse DNS" });
  } else {
    const noPtrCount = ptrResults.filter((r) => !r.hasPtrRecord).length;
    const noFcrDns = ptrResults.filter((r) => r.hasPtrRecord && !r.matchesForwardDns).length;
    if (noPtrCount > 0) {
      ptrScore -= noPtrCount * 20;
      issues.push({ severity: "warning", category: "reverseDns", message: `${noPtrCount} IP(s) have no PTR record \u2014 mail from these IPs may be rejected` });
    }
    if (noFcrDns > 0) {
      ptrScore -= noFcrDns * 10;
      issues.push({ severity: "info", category: "reverseDns", message: `${noFcrDns} IP(s) have PTR records that don't match forward DNS (FCrDNS mismatch)` });
    }
  }
  const ipScore = ipInfoResults.length > 0 && !ipInfoResults[0].error ? 100 : 100;
  let connectivityScore = 100;
  if (tcpResults.length === 0) {
    connectivityScore = 0;
  } else {
    const httpResult = tcpResults.find((r) => r.port === 80);
    const httpsResult = tcpResults.find((r) => r.port === 443);
    if (httpsResult && !httpsResult.connected) {
      connectivityScore -= 30;
      issues.push({ severity: "critical", category: "connectivity", message: "HTTPS (port 443) is not reachable" });
    }
    if (httpResult && !httpResult.connected && httpsResult?.connected) {
      issues.push({ severity: "info", category: "connectivity", message: "HTTP (port 80) is not reachable \u2014 ensure redirect to HTTPS is configured" });
    }
  }
  let mailSecurityScore = 100;
  const spoofReasons = [];
  if (!spfResult.found) {
    mailSecurityScore -= 40;
    spoofReasons.push("No SPF record \u2014 any server can send email as this domain");
    issues.push({ severity: "critical", category: "mailSecurity", message: `No SPF record found for ${domain} \u2014 domain is spoofable` });
  } else if (spfResult.spoofable) {
    mailSecurityScore -= 25;
    spoofReasons.push(`SPF policy is ${spfResult.policy} \u2014 does not block unauthorized senders`);
    issues.push({ severity: "warning", category: "mailSecurity", message: `SPF policy is '${spfResult.policy}' \u2014 weak protection against spoofing` });
  }
  if (!dmarcResult.found) {
    mailSecurityScore -= 40;
    spoofReasons.push("No DMARC record \u2014 receiving servers cannot validate sender authenticity");
    issues.push({ severity: "critical", category: "mailSecurity", message: `No DMARC record found for ${domain} \u2014 domain is spoofable` });
  } else if (dmarcResult.spoofable) {
    mailSecurityScore -= 20;
    spoofReasons.push(`DMARC policy is ${dmarcResult.policy} \u2014 spoofed emails are not rejected`);
    issues.push({ severity: "warning", category: "mailSecurity", message: `DMARC policy is '${dmarcResult.policy}' \u2014 spoofed emails pass through` });
  } else if (dmarcResult.policy === "quarantine") {
    mailSecurityScore -= 5;
    issues.push({ severity: "info", category: "mailSecurity", message: `DMARC policy is 'quarantine' \u2014 consider upgrading to 'reject' for full protection` });
  }
  if (dmarcResult.found && dmarcResult.pct < 100) {
    mailSecurityScore -= 10;
    issues.push({ severity: "warning", category: "mailSecurity", message: `DMARC only applies to ${dmarcResult.pct}% of messages (pct=${dmarcResult.pct})` });
  }
  mailSecurityScore = Math.max(0, mailSecurityScore);
  const domainSpoofable = (spfResult.spoofable || !spfResult.found) && (dmarcResult.spoofable || !dmarcResult.found);
  const mailSecurityAssessment = {
    spf: spfResult,
    dmarc: dmarcResult,
    mxRecords,
    spoofable: domainSpoofable,
    spoofReason: spoofReasons.length > 0 ? spoofReasons.join("; ") : "Domain has strong SPF and DMARC protections",
    score: mailSecurityScore
  };
  let mailPortScore = 100;
  const openMailPorts = mailPortResults.filter((r) => r.connected);
  const smtpPorts = mailPortResults.filter((r) => [25, 465, 587, 2525].includes(r.port));
  const smtpOpen = smtpPorts.filter((r) => r.connected);
  if (smtpPorts.length === 0) {
    mailPortScore = 100;
  } else if (smtpOpen.length === 0 && mxRecords.length > 0) {
    mailPortScore = 40;
    const port25 = smtpPorts.find((r) => r.port === 25);
    if (port25 && !port25.connected) {
      issues.push({ severity: "warning", category: "mailPorts", message: `Port 25 is not reachable on ${port25.host} \u2014 may be filtered by cloud provider or firewall. Checked alternate SMTP ports (465, 587, 2525) as well.` });
    }
    issues.push({ severity: "critical", category: "mailPorts", message: `No SMTP ports (25, 465, 587, 2525) are reachable on mail server` });
  } else if (smtpOpen.length > 0) {
    const hasSecureSMTP = smtpOpen.some((r) => r.port === 465 || r.port === 587);
    if (!hasSecureSMTP) {
      mailPortScore -= 15;
      issues.push({ severity: "warning", category: "mailPorts", message: "Only plain SMTP (port 25) is open \u2014 no secure submission ports (465/587)" });
    }
  }
  const overallScore = Math.round(
    blacklistScore * 0.2 + mailScore * 0.15 + mailSecurityScore * 0.2 + mailPortScore * 0.05 + dnsScore * 0.15 + ptrScore * 0.1 + connectivityScore * 0.1 + ipScore * 0.05
  );
  return {
    domain,
    timestamp: Date.now(),
    overallScore,
    overallGrade: scoreToGrade(overallScore),
    categories: {
      blacklist: { score: blacklistScore, grade: scoreToGrade(blacklistScore), details: dnsblResult },
      mailServer: { score: mailScore, grade: scoreToGrade(mailScore), details: smtpResults },
      mailSecurity: { score: mailSecurityScore, grade: scoreToGrade(mailSecurityScore), details: mailSecurityAssessment },
      mailPorts: { score: mailPortScore, grade: scoreToGrade(mailPortScore), details: mailPortResults },
      dnsHealth: { score: dnsScore, grade: scoreToGrade(dnsScore), details: dnsHealthResult },
      reverseDs: { score: ptrScore, grade: scoreToGrade(ptrScore), details: ptrResults },
      ipInfo: { score: ipScore, grade: scoreToGrade(ipScore), details: ipInfoResults },
      connectivity: { score: connectivityScore, grade: scoreToGrade(connectivityScore), details: tcpResults }
    },
    issues,
    durationMs: Date.now() - start
  };
}
var DOMAIN_BASED_ZONES, DNSBL_ZONES, CLOUD_PTR_PATTERNS, ENTERPRISE_MAIL_PORTS, domainHealthConnector;
var init_domain_health = __esm({
  "server/lib/passive/domain-health.ts"() {
    DOMAIN_BASED_ZONES = [
      "dbl.spamhaus.org",
      // Spamhaus Domain Block List
      "multi.surbl.org",
      // SURBL domain reputation
      "multi.uribl.com"
      // URIBL domain reputation
    ];
    DNSBL_ZONES = [
      // Spamhaus
      "zen.spamhaus.org",
      "sbl.spamhaus.org",
      "xbl.spamhaus.org",
      "pbl.spamhaus.org",
      // Barracuda
      "b.barracudacentral.org",
      // SpamCop
      "bl.spamcop.net",
      // SORBS
      "dnsbl.sorbs.net",
      "smtp.dnsbl.sorbs.net",
      "web.dnsbl.sorbs.net",
      "new.spam.dnsbl.sorbs.net",
      // UCEPROTECT
      "dnsbl-1.uceprotect.net",
      "dnsbl-2.uceprotect.net",
      "dnsbl-3.uceprotect.net",
      // Invaluement
      "ivmSIP.dnsbl.invaluement.com",
      "ivmSIP24.dnsbl.invaluement.com",
      // Composite Blocking List
      "cbl.abuseat.org",
      // PSBL
      "psbl.surriel.com",
      // Truncate
      "truncate.gbudb.net",
      // JustSpam
      "dnsbl.justspam.org",
      // Mailspike
      "bl.mailspike.net",
      "z.mailspike.net",
      // Abusix
      "combined.mail.abusix.zone",
      // Lashback
      "ubl.lashback.com",
      // Wpbl
      "db.wpbl.info",
      // Backscatterer
      "ips.backscatterer.org",
      // Hostkarma
      "hostkarma.junkemailfilter.com",
      // Spam Eating Monkey
      "bl.spameatingmonkey.net",
      "backscatter.spameatingmonkey.net",
      // Nordspam
      "bl.nordspam.com",
      // Blocklist.de
      "bl.blocklist.de",
      // DroneBL
      "dnsbl.dronebl.org",
      // Spamrats
      "dyna.spamrats.com",
      "noptr.spamrats.com",
      "spam.spamrats.com",
      // 0spam
      "bl.0spam.org",
      // NiX Spam
      "ix.dnsbl.manitu.net",
      // Suomispam
      "gl.suomispam.net",
      // ORBS
      "dnsbl.inps.de",
      // Abusix Mail Intelligence
      "dnsbl.abusix.zone",
      // Spam and Open Relay Blocking System
      "korea.services.net",
      // Weighted Private Block List
      "all.s5h.net",
      // CASA CBL
      "cbl.anti-spam.org.cn",
      // Fabel
      "spamsources.fabel.dk",
      // Anonmails
      "spam.dnsbl.anonmails.de",
      // Bogons
      "bogons.cymru.com",
      // Virus Free
      "virbl.dnsbl.bit.nl",
      // Interserver
      "rbl.interserver.net",
      // Kempt
      "dnsbl.kempt.net",
      // Swinog
      "dnsrbl.swinog.ch",
      // Tornevall
      "dnsbl.tornevall.org",
      // Zapbl
      "dnsbl.zapbl.net"
    ];
    CLOUD_PTR_PATTERNS = [
      { pattern: /\.compute\.amazonaws\.com$/i, provider: "AWS EC2" },
      { pattern: /\.compute\.internal$/i, provider: "AWS EC2" },
      { pattern: /\.amazonaws\.com$/i, provider: "AWS" },
      { pattern: /\.cloudfront\.net$/i, provider: "AWS CloudFront" },
      { pattern: /\.googleusercontent\.com$/i, provider: "Google Cloud" },
      { pattern: /\.bc\.googleusercontent\.com$/i, provider: "Google Cloud" },
      { pattern: /\.1e100\.net$/i, provider: "Google" },
      { pattern: /\.azure\.com$/i, provider: "Microsoft Azure" },
      { pattern: /\.azurewebsites\.net$/i, provider: "Microsoft Azure" },
      { pattern: /\.cloudapp\.net$/i, provider: "Microsoft Azure" },
      { pattern: /\.digitalocean\.com$/i, provider: "DigitalOcean" },
      { pattern: /\.vultr\.com$/i, provider: "Vultr" },
      { pattern: /\.linode\.com$/i, provider: "Linode/Akamai" },
      { pattern: /\.hetzner\.com$/i, provider: "Hetzner" },
      { pattern: /\.ovh\.(net|com|ca)$/i, provider: "OVH" },
      { pattern: /\.contabo\.host$/i, provider: "Contabo" },
      { pattern: /\.rackspace\.com$/i, provider: "Rackspace" },
      { pattern: /\.heroku\.com$/i, provider: "Heroku" },
      { pattern: /\.vercel\.app$/i, provider: "Vercel" },
      { pattern: /\.netlify\.app$/i, provider: "Netlify" },
      { pattern: /\.fly\.dev$/i, provider: "Fly.io" },
      { pattern: /\.render\.com$/i, provider: "Render" }
    ];
    ENTERPRISE_MAIL_PORTS = [
      { port: 25, service: "SMTP", protocol: "smtp" },
      { port: 465, service: "SMTPS (Implicit TLS)", protocol: "smtps" },
      { port: 587, service: "SMTP Submission", protocol: "submission" },
      { port: 2525, service: "SMTP Alternate", protocol: "smtp-alt" },
      { port: 143, service: "IMAP", protocol: "imap" },
      { port: 993, service: "IMAPS", protocol: "imaps" },
      { port: 110, service: "POP3", protocol: "pop3" },
      { port: 995, service: "POP3S", protocol: "pop3s" }
    ];
    domainHealthConnector = {
      name: "domain_health",
      description: "MXToolbox-equivalent domain health diagnostics \u2014 DNSBL blacklist check, SMTP test, PTR/rDNS, DNS health, IP block info, TCP connectivity",
      requiresApiKey: false,
      freeUrl: "https://mxtoolbox.com/emailhealth",
      async collect(domain, config) {
        const start = Date.now();
        const timeout = config?.timeout ?? 3e4;
        const observations = [];
        const errors = [];
        const now = /* @__PURE__ */ new Date();
        try {
          const report = await runDomainHealthCheck(domain, timeout);
          observations.push({
            assetId: makeAssetId(domain, "health_score", "domain_health"),
            domain,
            assetType: "txt",
            name: `Domain Health: ${report.overallGrade} (${report.overallScore}/100)`,
            source: "domain_health",
            observedAt: now,
            tags: ["domain_health", "health_score", `grade:${report.overallGrade.toLowerCase()}`],
            evidence: {
              overallScore: report.overallScore,
              overallGrade: report.overallGrade,
              blacklistScore: report.categories.blacklist.score,
              mailServerScore: report.categories.mailServer.score,
              mailSecurityScore: report.categories.mailSecurity.score,
              mailPortScore: report.categories.mailPorts.score,
              dnsHealthScore: report.categories.dnsHealth.score,
              reverseDnsScore: report.categories.reverseDs.score,
              connectivityScore: report.categories.connectivity.score,
              issueCount: report.issues.length,
              criticalIssues: report.issues.filter((i) => i.severity === "critical").length,
              fullReport: report
            },
            attribution: {
              provider: "AC3 Domain Health Engine",
              method: "MXToolbox-equivalent domain health diagnostics (DNSBL, SMTP, PTR, DNS Health, TCP)",
              verifyUrl: `https://mxtoolbox.com/emailhealth/${domain}`
            }
          });
          if (report.categories.blacklist.details) {
            const bl = report.categories.blacklist.details;
            if (bl.listed.length > 0) {
              observations.push({
                assetId: makeAssetId(domain, `blacklist:${bl.ip}`, "domain_health"),
                domain,
                assetType: "ip",
                ip: bl.ip,
                name: bl.actionableCount > 0 ? `BLACKLISTED on ${bl.actionableCount} actionable + ${bl.informationalCount} informational DNSBL zone(s) out of ${bl.totalChecked} checked` : `Listed on ${bl.informationalCount} informational-only DNSBL zone(s) \u2014 no actionable listings (${bl.totalChecked} checked)`,
                source: "domain_health",
                observedAt: now,
                tags: [
                  "domain_health",
                  "blacklist",
                  "dnsbl",
                  "email_reputation",
                  ...bl.isCloudHosted ? ["cloud_hosted"] : [],
                  ...bl.actionableCount === 0 && bl.listed.length > 0 ? ["likely_false_positive"] : []
                ],
                evidence: {
                  ip: bl.ip,
                  reverseDns: bl.reverseDns,
                  isCloudHosted: bl.isCloudHosted,
                  cloudProvider: bl.cloudProvider,
                  listedCount: bl.listed.length,
                  actionableCount: bl.actionableCount,
                  informationalCount: bl.informationalCount,
                  totalChecked: bl.totalChecked,
                  blacklistScore: bl.score,
                  categoryBreakdown: bl.categoryBreakdown,
                  listings: bl.listed.map((l) => ({
                    zone: l.zone,
                    returnCodes: l.result,
                    returnCodeMeaning: l.returnCodeMeaning,
                    reason: l.reason,
                    category: l.category,
                    severity: l.severity,
                    actionRequired: l.actionRequired,
                    ttl: l.ttl,
                    lookupUrl: l.lookupUrl,
                    falsePositiveIndicators: l.falsePositiveIndicators,
                    firstSeenAt: new Date(l.firstSeenAt).toISOString()
                  }))
                },
                attribution: {
                  provider: "AC3 DNSBL Engine v2",
                  method: `Checked ${bl.totalChecked} DNS blacklists for IP ${bl.ip} with TXT reason lookup, TTL analysis, reverse DNS cross-reference, and cloud provider detection`,
                  verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${bl.ip}`
                }
              });
              for (const listing of bl.listed.filter((l) => l.actionRequired)) {
                observations.push({
                  assetId: makeAssetId(domain, `blacklist:${bl.ip}:${listing.zone}`, "domain_health"),
                  domain,
                  assetType: "ip",
                  ip: bl.ip,
                  name: `${listing.severity.toUpperCase()}: ${bl.ip} listed on ${listing.zone} \u2014 ${listing.returnCodeMeaning}`,
                  source: "domain_health",
                  observedAt: now,
                  tags: [
                    "domain_health",
                    "blacklist",
                    "dnsbl",
                    listing.category,
                    `severity_${listing.severity}`,
                    "actionable"
                  ],
                  evidence: {
                    ip: bl.ip,
                    zone: listing.zone,
                    returnCodes: listing.result,
                    returnCodeMeaning: listing.returnCodeMeaning,
                    reason: listing.reason,
                    category: listing.category,
                    severity: listing.severity,
                    ttl: listing.ttl,
                    reverseDns: bl.reverseDns,
                    cloudProvider: bl.cloudProvider,
                    falsePositiveIndicators: listing.falsePositiveIndicators
                  },
                  attribution: {
                    provider: "AC3 DNSBL Engine v2",
                    method: `DNSBL A+TXT lookup on ${listing.zone} for ${bl.ip}`,
                    verifyUrl: listing.lookupUrl
                  }
                });
              }
            }
          }
          for (const smtp of report.categories.mailServer.details) {
            observations.push({
              assetId: makeAssetId(domain, `smtp:${smtp.host}`, "domain_health"),
              domain,
              assetType: "mx",
              name: smtp.connected ? `SMTP OK: ${smtp.host} (${smtp.supportsStartTls ? "TLS" : "NO TLS"}, ${smtp.latencyMs}ms)` : `SMTP FAIL: ${smtp.host} \u2014 ${smtp.error}`,
              source: "domain_health",
              observedAt: now,
              tags: [
                "domain_health",
                "smtp",
                "mail_server",
                smtp.connected ? "smtp_ok" : "smtp_fail",
                ...smtp.supportsStartTls ? ["starttls"] : ["no_starttls"]
              ],
              evidence: {
                host: smtp.host,
                port: smtp.port,
                connected: smtp.connected,
                banner: smtp.banner,
                supportsStartTls: smtp.supportsStartTls,
                supportsEhlo: smtp.supportsEhlo,
                ehloExtensions: smtp.ehloExtensions,
                latencyMs: smtp.latencyMs,
                error: smtp.error
              },
              attribution: {
                provider: "AC3 SMTP Tester",
                method: `SMTP EHLO test on ${smtp.host}:25`,
                verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=smtp%3a${smtp.host}`
              }
            });
          }
          for (const ptr of report.categories.reverseDs.details) {
            if (!ptr.hasPtrRecord) {
              observations.push({
                assetId: makeAssetId(domain, `ptr:${ptr.ip}`, "domain_health"),
                domain,
                assetType: "ip",
                ip: ptr.ip,
                name: `NO PTR RECORD for ${ptr.ip}`,
                source: "domain_health",
                observedAt: now,
                tags: ["domain_health", "ptr", "reverse_dns", "missing_ptr"],
                evidence: { ip: ptr.ip, hasPtrRecord: false, matchesForwardDns: false },
                attribution: {
                  provider: "AC3 Reverse DNS Checker",
                  method: `PTR lookup for ${ptr.ip}`,
                  verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a${ptr.ip}`
                }
              });
            } else {
              observations.push({
                assetId: makeAssetId(domain, `ptr:${ptr.ip}`, "domain_health"),
                domain,
                assetType: "ip",
                ip: ptr.ip,
                name: `PTR: ${ptr.ip} \u2192 ${ptr.hostnames.join(", ")}${ptr.matchesForwardDns ? " (FCrDNS OK)" : " (FCrDNS MISMATCH)"}`,
                source: "domain_health",
                observedAt: now,
                tags: [
                  "domain_health",
                  "ptr",
                  "reverse_dns",
                  ptr.matchesForwardDns ? "fcrdns_ok" : "fcrdns_mismatch"
                ],
                evidence: { ip: ptr.ip, hostnames: ptr.hostnames, hasPtrRecord: true, matchesForwardDns: ptr.matchesForwardDns },
                attribution: {
                  provider: "AC3 Reverse DNS Checker",
                  method: `PTR lookup for ${ptr.ip}`,
                  verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a${ptr.ip}`
                }
              });
            }
          }
          if (report.categories.dnsHealth.details) {
            const dh = report.categories.dnsHealth.details;
            observations.push({
              assetId: makeAssetId(domain, "dns_health", "domain_health"),
              domain,
              assetType: "ns",
              name: `DNS Health: ${scoreToGrade(dh.score)} (${dh.score}/100) \u2014 ${dh.nameservers.length} NS, ${dh.issues.length} issues`,
              source: "domain_health",
              observedAt: now,
              tags: [
                "domain_health",
                "dns_health",
                dh.soaConsistent ? "soa_consistent" : "soa_mismatch",
                dh.nsConsistent ? "ns_consistent" : "ns_inconsistent",
                dh.glueRecordsValid ? "glue_ok" : "glue_missing"
              ],
              evidence: {
                nameservers: dh.nameservers,
                soaConsistent: dh.soaConsistent,
                soaSerials: dh.soaSerials,
                nsConsistent: dh.nsConsistent,
                zoneTransferBlocked: dh.zoneTransferBlocked,
                glueRecordsValid: dh.glueRecordsValid,
                issues: dh.issues,
                score: dh.score
              },
              attribution: {
                provider: "AC3 DNS Health Analyzer",
                method: `Comprehensive DNS health check for ${domain} across ${dh.nameservers.length} nameservers`,
                verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=dns%3a${domain}`
              }
            });
          }
          for (const ipInfo of report.categories.ipInfo.details) {
            if (!ipInfo.error) {
              observations.push({
                assetId: makeAssetId(domain, `ipblock:${ipInfo.ip}`, "domain_health"),
                domain,
                assetType: "asn",
                ip: ipInfo.ip,
                asn: ipInfo.asn,
                name: `IP Block: ${ipInfo.ip} \u2014 ${ipInfo.organization || "Unknown Org"}${ipInfo.asn ? ` (AS${ipInfo.asn})` : ""}`,
                source: "domain_health",
                observedAt: now,
                tags: ["domain_health", "ip_block", "arin", "rdap"],
                evidence: {
                  ip: ipInfo.ip,
                  asn: ipInfo.asn,
                  asnName: ipInfo.asnName,
                  networkName: ipInfo.networkName,
                  networkCidr: ipInfo.networkCidr,
                  organization: ipInfo.organization,
                  country: ipInfo.country,
                  startAddress: ipInfo.startAddress,
                  endAddress: ipInfo.endAddress
                },
                attribution: {
                  provider: "AC3 IP Block Analyzer (RDAP)",
                  method: `RDAP query for IP ${ipInfo.ip}`,
                  verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=arin%3a${ipInfo.ip}`
                }
              });
            }
          }
          for (const tcp of report.categories.connectivity.details) {
            observations.push({
              assetId: makeAssetId(domain, `tcp:${tcp.host}:${tcp.port}`, "domain_health"),
              domain,
              assetType: "ip",
              ip: tcp.host,
              name: tcp.connected ? `TCP ${tcp.port} OPEN on ${tcp.host} (${tcp.latencyMs}ms)${tcp.banner ? ` \u2014 ${tcp.banner.substring(0, 80)}` : ""}` : `TCP ${tcp.port} CLOSED on ${tcp.host}`,
              source: "domain_health",
              observedAt: now,
              tags: [
                "domain_health",
                "tcp_check",
                `port:${tcp.port}`,
                tcp.connected ? "port_open" : "port_closed"
              ],
              evidence: {
                host: tcp.host,
                port: tcp.port,
                connected: tcp.connected,
                banner: tcp.banner,
                latencyMs: tcp.latencyMs,
                error: tcp.error
              },
              attribution: {
                provider: "AC3 TCP Connectivity Checker",
                method: `TCP connect test to ${tcp.host}:${tcp.port}`,
                verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=tcp%3a${tcp.host}%3a${tcp.port}`
              }
            });
          }
          if (report.categories.mailSecurity.details) {
            const ms = report.categories.mailSecurity.details;
            observations.push({
              assetId: makeAssetId(domain, "mail_security", "domain_health"),
              domain,
              assetType: "txt",
              name: `Mail Security: ${scoreToGrade(ms.score)} (${ms.score}/100)${ms.spoofable ? " \u2014 SPOOFABLE" : " \u2014 Protected"}`,
              source: "domain_health",
              observedAt: now,
              tags: [
                "domain_health",
                "mail_security",
                "spf",
                "dmarc",
                ms.spoofable ? "spoofable" : "protected",
                ms.spf.found ? `spf:${ms.spf.policy}` : "spf:missing",
                ms.dmarc.found ? `dmarc:${ms.dmarc.policy}` : "dmarc:missing"
              ],
              evidence: {
                spf: ms.spf,
                dmarc: ms.dmarc,
                spoofable: ms.spoofable,
                spoofReason: ms.spoofReason,
                mxRecords: ms.mxRecords,
                score: ms.score
              },
              attribution: {
                provider: "AC3 Mail Security Analyzer",
                method: `SPF + DMARC analysis for ${domain}`,
                verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=spf%3a${domain}`
              }
            });
          }
          for (const mp of report.categories.mailPorts.details) {
            observations.push({
              assetId: makeAssetId(domain, `mailport:${mp.host}:${mp.port}`, "domain_health"),
              domain,
              assetType: "ip",
              ip: mp.host,
              name: mp.connected ? `Mail Port ${mp.port} (${mp.service}) OPEN on ${mp.host} (${mp.latencyMs}ms)${mp.banner ? ` \u2014 ${mp.banner.substring(0, 60)}` : ""}` : `Mail Port ${mp.port} (${mp.service}) CLOSED on ${mp.host}`,
              source: "domain_health",
              observedAt: now,
              tags: [
                "domain_health",
                "mail_port",
                `port:${mp.port}`,
                mp.protocol,
                mp.connected ? "port_open" : "port_closed"
              ],
              evidence: {
                host: mp.host,
                port: mp.port,
                service: mp.service,
                protocol: mp.protocol,
                connected: mp.connected,
                banner: mp.banner,
                latencyMs: mp.latencyMs,
                error: mp.error
              },
              attribution: {
                provider: "AC3 Mail Port Scanner",
                method: `Enterprise mail port scan on ${mp.host}:${mp.port} (${mp.service})`
              }
            });
          }
        } catch (err) {
          errors.push(`Domain health check failed: ${err.message}`);
        }
        return {
          connector: "domain_health",
          domain,
          observations,
          errors,
          durationMs: Date.now() - start,
          rateLimited: false
        };
      }
    };
  }
});

export {
  runDomainHealthCheck,
  domainHealthConnector,
  init_domain_health
};
