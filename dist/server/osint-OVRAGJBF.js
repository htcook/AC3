import "./chunk-KFQGP6VL.js";

// server/osint.ts
import dns from "dns";
import { promisify } from "util";
var resolveMx = promisify(dns.resolveMx);
var resolveTxt = promisify(dns.resolveTxt);
var resolveNs = promisify(dns.resolveNs);
var resolve4 = promisify(dns.resolve4);
var resolve6 = promisify(dns.resolve6);
var resolveCname = promisify(dns.resolveCname);
async function safeDnsResolve(fn, fallback) {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}
async function analyzeDns(domain) {
  const [mx, ns, a, aaaa] = await Promise.all([
    safeDnsResolve(() => resolveMx(domain), []),
    safeDnsResolve(() => resolveNs(domain), []),
    safeDnsResolve(() => resolve4(domain), []),
    safeDnsResolve(() => resolve6(domain), [])
  ]);
  const txtRecords = await safeDnsResolve(() => resolveTxt(domain), []);
  const spfRecord = txtRecords.map((r) => r.join("")).find((r) => r.startsWith("v=spf1")) || null;
  const dmarcRecords = await safeDnsResolve(() => resolveTxt(`_dmarc.${domain}`), []);
  const dmarcRecord = dmarcRecords.map((r) => r.join("")).find((r) => r.startsWith("v=DMARC1")) || null;
  let dmarcPolicy = null;
  if (dmarcRecord) {
    const policyMatch = dmarcRecord.match(/;\s*p=(\w+)/);
    if (policyMatch) dmarcPolicy = policyMatch[1];
  }
  const dkimSelectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2"];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    const dkimTxt = await safeDnsResolve(() => resolveTxt(`${sel}._domainkey.${domain}`), []);
    if (dkimTxt.length > 0) {
      dkimFound = true;
      break;
    }
  }
  return {
    mxRecords: mx.map((r) => ({ exchange: r.exchange, priority: r.priority })),
    spfRecord,
    dmarcRecord,
    dmarcPolicy,
    dkimFound,
    nsRecords: ns,
    aRecords: a,
    aaaaRecords: aaaa
  };
}
function analyzeSpoofability(dnsData) {
  let score = 0;
  const factors = [];
  if (!dnsData.spfRecord) {
    score += 35;
    factors.push({
      factor: "No SPF Record",
      impact: "critical",
      detail: "Domain has no SPF record. Any server can send email claiming to be from this domain."
    });
  } else if (dnsData.spfRecord.includes("~all")) {
    score += 20;
    factors.push({
      factor: "SPF Soft Fail (~all)",
      impact: "high",
      detail: "SPF uses soft fail (~all). Spoofed emails may still be delivered to inbox."
    });
  } else if (dnsData.spfRecord.includes("?all")) {
    score += 25;
    factors.push({
      factor: "SPF Neutral (?all)",
      impact: "high",
      detail: "SPF uses neutral policy (?all). No enforcement \u2014 spoofed emails pass SPF checks."
    });
  } else if (dnsData.spfRecord.includes("-all")) {
    score += 5;
    factors.push({
      factor: "SPF Hard Fail (-all)",
      impact: "low",
      detail: "SPF uses hard fail (-all). Spoofed emails should be rejected, but not all servers enforce."
    });
  }
  if (!dnsData.dmarcRecord) {
    score += 30;
    factors.push({
      factor: "No DMARC Record",
      impact: "critical",
      detail: "No DMARC policy. Receiving servers have no guidance on handling spoofed emails."
    });
  } else if (dnsData.dmarcPolicy === "none") {
    score += 25;
    factors.push({
      factor: "DMARC Policy: none",
      impact: "high",
      detail: "DMARC policy is set to 'none' \u2014 monitoring only, no enforcement. Spoofed emails are delivered."
    });
  } else if (dnsData.dmarcPolicy === "quarantine") {
    score += 10;
    factors.push({
      factor: "DMARC Policy: quarantine",
      impact: "medium",
      detail: "DMARC quarantines failed emails. Some may still reach spam folder."
    });
  } else if (dnsData.dmarcPolicy === "reject") {
    score += 0;
    factors.push({
      factor: "DMARC Policy: reject",
      impact: "low",
      detail: "DMARC rejects failed emails. Spoofing this domain is difficult."
    });
  }
  if (!dnsData.dkimFound) {
    score += 15;
    factors.push({
      factor: "No DKIM Detected",
      impact: "medium",
      detail: "No DKIM signing detected on common selectors. Email authenticity cannot be verified."
    });
  } else {
    score += 0;
    factors.push({
      factor: "DKIM Present",
      impact: "low",
      detail: "DKIM signing detected. Adds a layer of email authentication."
    });
  }
  if (dnsData.mxRecords.length === 0) {
    score += 10;
    factors.push({
      factor: "No MX Records",
      impact: "medium",
      detail: "Domain has no MX records. May not actively monitor email, making spoofing less likely to be detected."
    });
  }
  score = Math.min(score, 100);
  const spoofable = score >= 40;
  let recommendation;
  if (score >= 60) {
    recommendation = "spoof";
  } else if (score >= 30) {
    recommendation = "both";
  } else {
    recommendation = "buy_lookalike";
  }
  return { score, spoofable, factors, recommendation };
}
async function enumerateSubdomains(domain) {
  try {
    const response = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(15e3) }
    );
    if (!response.ok) return [];
    const data = await response.json();
    const subdomains = /* @__PURE__ */ new Set();
    for (const entry of data) {
      const names = entry.name_value.split("\n");
      for (const name of names) {
        const cleaned = name.trim().toLowerCase();
        if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
          subdomains.add(cleaned);
        }
      }
    }
    return Array.from(subdomains).sort();
  } catch {
    return [];
  }
}
var KEYBOARD_NEIGHBORS = {
  q: "wa",
  w: "qeas",
  e: "wrds",
  r: "etfs",
  t: "rygs",
  y: "tuhs",
  u: "yijs",
  i: "uoks",
  o: "ipls",
  p: "o",
  a: "qwsz",
  s: "weadxz",
  d: "ersfxc",
  f: "rtdgcv",
  g: "tyfhvb",
  h: "uygjbn",
  j: "iohknm",
  k: "opjlm",
  l: "pk",
  z: "asx",
  x: "zsdc",
  c: "xdfv",
  v: "cfgb",
  b: "vghn",
  n: "bhjm",
  m: "njk"
};
var HOMOGLYPHS = {
  a: ["\xE0", "\xE1", "\xE2", "\xE3", "\xE4", "\xE5", "\u0251", "\u0430", "\u1EA1", "\u0105"],
  b: ["d", "\u1E03", "\u0253", "\u044C", "\u0180"],
  c: ["\xE7", "\u0107", "\u0109", "\u010B", "\u0441"],
  d: ["b", "\u1E0B", "\u0257", "\u010F", "\u0111"],
  e: ["\xE8", "\xE9", "\xEA", "\xEB", "\u0113", "\u0115", "\u0117", "\u0119", "\u0435"],
  f: ["\u0192"],
  g: ["\u011F", "\u0121", "\u0123", "\u0261"],
  h: ["\u0125", "\u0127", "\u1E25"],
  i: ["\xEC", "\xED", "\xEE", "\xEF", "\u0131", "\u0129", "\u012B", "\u012D", "\u0456", "1", "l"],
  j: ["\u0135"],
  k: ["\u0137", "\u0138", "\u03BA"],
  l: ["\u013A", "\u013C", "\u013E", "\u0140", "\u0142", "1", "i"],
  m: ["\u1E41", "\u0271", "rn"],
  n: ["\xF1", "\u0144", "\u0146", "\u0148", "\u014B", "\u043F"],
  o: ["\xF2", "\xF3", "\xF4", "\xF5", "\xF6", "\xF8", "\u014D", "\u014F", "\u0151", "\u043E", "0"],
  p: ["\u1E57", "\u0440"],
  q: ["\u024B"],
  r: ["\u0155", "\u0157", "\u0159", "\u024D", "\u0433"],
  s: ["\u015B", "\u015D", "\u015F", "\u0161", "\u1E61", "\u0219", "\u0282"],
  t: ["\u0163", "\u0165", "\u0167", "\u1E6B", "\u021B"],
  u: ["\xF9", "\xFA", "\xFB", "\xFC", "\u0169", "\u016B", "\u016D", "\u016F", "\u0171", "\u0173"],
  v: ["\u1E7F", "\u03BD"],
  w: ["\u0175", "\u1E81", "\u1E83", "\u1E85", "\u03C9"],
  x: ["\u1E8B", "\u0445"],
  y: ["\xFD", "\xFF", "\u0177", "\u1E8F", "\u0443"],
  z: ["\u017A", "\u017C", "\u017E", "\u1E91"]
};
var VOWELS = "aeiou";
function splitDomain(domain) {
  const parts = domain.split(".");
  if (parts.length < 2) return { name: domain, tld: "" };
  if (parts.length > 2 && parts[parts.length - 2].length <= 3) {
    return {
      name: parts.slice(0, -2).join("."),
      tld: parts.slice(-2).join(".")
    };
  }
  return { name: parts.slice(0, -1).join("."), tld: parts[parts.length - 1] };
}
function generateTyposquats(domain, maxPerType = 20) {
  const { name, tld } = splitDomain(domain);
  const results = [];
  const seen = /* @__PURE__ */ new Set();
  function add(d, type) {
    const full = `${d}.${tld}`;
    if (full !== domain && !seen.has(full)) {
      seen.add(full);
      results.push({ domain: full, type });
    }
  }
  for (let i = 0; i < name.length && results.filter((r) => r.type === "omission").length < maxPerType; i++) {
    add(name.slice(0, i) + name.slice(i + 1), "omission");
  }
  for (let i = 0; i < name.length && results.filter((r) => r.type === "repetition").length < maxPerType; i++) {
    if (name[i].match(/[a-z]/)) {
      add(name.slice(0, i) + name[i] + name.slice(i), "repetition");
    }
  }
  for (let i = 0; i < name.length - 1 && results.filter((r) => r.type === "transposition").length < maxPerType; i++) {
    const arr = name.split("");
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    add(arr.join(""), "transposition");
  }
  for (let i = 0; i < name.length; i++) {
    const neighbors = KEYBOARD_NEIGHBORS[name[i]];
    if (neighbors && results.filter((r) => r.type === "replacement").length < maxPerType) {
      for (const n of neighbors) {
        add(name.slice(0, i) + n + name.slice(i + 1), "replacement");
      }
    }
  }
  for (let i = 0; i <= name.length && results.filter((r) => r.type === "insertion").length < maxPerType; i++) {
    for (const c of "abcdefghijklmnopqrstuvwxyz") {
      if (results.filter((r) => r.type === "insertion").length >= maxPerType) break;
      add(name.slice(0, i) + c + name.slice(i), "insertion");
    }
  }
  for (let i = 0; i < name.length && results.filter((r) => r.type === "bitsquatting").length < maxPerType; i++) {
    const code = name.charCodeAt(i);
    for (let bit = 0; bit < 8; bit++) {
      const flipped = code ^ 1 << bit;
      if (flipped >= 48 && flipped <= 122) {
        const c = String.fromCharCode(flipped);
        if (c.match(/[a-z0-9-]/)) {
          add(name.slice(0, i) + c + name.slice(i + 1), "bitsquatting");
        }
      }
    }
  }
  for (let i = 0; i < name.length && results.filter((r) => r.type === "homoglyph").length < maxPerType; i++) {
    const glyphs = HOMOGLYPHS[name[i]];
    if (glyphs) {
      for (const g of glyphs.slice(0, 3)) {
        add(name.slice(0, i) + g + name.slice(i + 1), "homoglyph");
      }
    }
  }
  for (let i = 0; i < name.length && results.filter((r) => r.type === "vowel_swap").length < maxPerType; i++) {
    if (VOWELS.includes(name[i])) {
      for (const v of VOWELS) {
        if (v !== name[i]) {
          add(name.slice(0, i) + v + name.slice(i + 1), "vowel_swap");
        }
      }
    }
  }
  for (const c of "abcdefghijklmnopqrstuvwxyz0123456789") {
    if (results.filter((r) => r.type === "addition").length >= maxPerType) break;
    add(name + c, "addition");
  }
  for (let i = 1; i < name.length && results.filter((r) => r.type === "hyphenation").length < maxPerType; i++) {
    add(name.slice(0, i) + "-" + name.slice(i), "hyphenation");
  }
  const commonTlds = ["com", "net", "org", "io", "co", "biz", "info", "xyz", "app", "dev", "us", "me"];
  for (const t of commonTlds) {
    if (t !== tld) {
      const full = `${name}.${t}`;
      if (!seen.has(full)) {
        seen.add(full);
        results.push({ domain: full, type: "tld_swap" });
      }
    }
  }
  add(`www${name}`, "subdomain_trick");
  add(`${name}login`, "subdomain_trick");
  add(`${name}secure`, "subdomain_trick");
  add(`${name}mail`, "subdomain_trick");
  return results;
}
async function checkDomainRegistration(domain) {
  try {
    const ips = await resolve4(domain);
    const mx = await safeDnsResolve(() => resolveMx(domain), []);
    return {
      resolved: true,
      ip: ips[0] || null,
      mx: mx.map((r) => ({ exchange: r.exchange, priority: r.priority }))
    };
  } catch {
    return { resolved: false, ip: null, mx: [] };
  }
}
async function runFullRecon(domain) {
  const [dnsResult, subdomains] = await Promise.all([
    analyzeDns(domain),
    enumerateSubdomains(domain)
  ]);
  const spoofability = analyzeSpoofability(dnsResult);
  const typosquats = generateTyposquats(domain);
  return {
    domain,
    dns: dnsResult,
    spoofability,
    subdomains,
    typosquats
  };
}
function extractVcardField(vcardArray, fieldName) {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return null;
  const fields = vcardArray[1];
  if (!Array.isArray(fields)) return null;
  for (const field of fields) {
    if (Array.isArray(field) && field[0] === fieldName) {
      return field[3] || null;
    }
  }
  return null;
}
async function whoisLookup(domain) {
  const result = {
    registered: false,
    available: true,
    registrar: null,
    registrationDate: null,
    expirationDate: null,
    lastChanged: null,
    nameservers: [],
    status: [],
    registrantName: null,
    registrantOrg: null,
    abuseEmail: null,
    abusePhone: null,
    rawRdap: null
  };
  try {
    const response = await fetch(`https://www.rdap.net/domain/${encodeURIComponent(domain)}`, {
      headers: { "Accept": "application/rdap+json" },
      signal: AbortSignal.timeout(15e3),
      redirect: "follow"
    });
    if (response.status === 404) {
      return { ...result, registered: false, available: true };
    }
    if (!response.ok) {
      return result;
    }
    const data = await response.json();
    result.rawRdap = data;
    result.registered = true;
    result.available = false;
    if (Array.isArray(data.status)) {
      result.status = data.status;
    }
    if (Array.isArray(data.events)) {
      for (const event of data.events) {
        switch (event.eventAction) {
          case "registration":
            result.registrationDate = event.eventDate;
            break;
          case "expiration":
            result.expirationDate = event.eventDate;
            break;
          case "last changed":
            result.lastChanged = event.eventDate;
            break;
        }
      }
    }
    if (Array.isArray(data.nameservers)) {
      result.nameservers = data.nameservers.map((ns) => ns.ldhName || ns.unicodeName || "").filter(Boolean);
    }
    if (Array.isArray(data.entities)) {
      for (const entity of data.entities) {
        const roles = entity.roles || [];
        if (roles.includes("registrar")) {
          result.registrar = extractVcardField(entity.vcardArray, "fn");
          if (Array.isArray(entity.entities)) {
            for (const sub of entity.entities) {
              if (sub.roles?.includes("abuse")) {
                result.abuseEmail = extractVcardField(sub.vcardArray, "email");
                result.abusePhone = extractVcardField(sub.vcardArray, "tel");
              }
            }
          }
        }
        if (roles.includes("registrant")) {
          result.registrantName = extractVcardField(entity.vcardArray, "fn");
          result.registrantOrg = extractVcardField(entity.vcardArray, "org");
        }
      }
    }
    return result;
  } catch (err) {
    console.error(`WHOIS/RDAP lookup failed for ${domain}:`, err);
    return result;
  }
}
async function batchWhoisCheck(domains, concurrency = 3, delayMs = 500) {
  const results = /* @__PURE__ */ new Map();
  for (let i = 0; i < domains.length; i += concurrency) {
    const batch = domains.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map((d) => whoisLookup(d))
    );
    batch.forEach((domain, idx) => {
      const r = batchResults[idx];
      if (r.status === "fulfilled") {
        results.set(domain, r.value);
      } else {
        results.set(domain, {
          registered: false,
          available: false,
          registrar: null,
          registrationDate: null,
          expirationDate: null,
          lastChanged: null,
          nameservers: [],
          status: [],
          registrantName: null,
          registrantOrg: null,
          abuseEmail: null,
          abusePhone: null,
          rawRdap: null
        });
      }
    });
    if (i + concurrency < domains.length) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  return results;
}
async function detectDomainChanges(domain, previousRecon) {
  const changes = [];
  const currentDns = await analyzeDns(domain);
  const currentSubdomains = await enumerateSubdomains(domain);
  if (previousRecon.spfRecord !== void 0 && previousRecon.spfRecord !== currentDns.spfRecord) {
    changes.push({
      type: "spf_changed",
      severity: !currentDns.spfRecord ? "critical" : "warning",
      previousValue: previousRecon.spfRecord || "NONE",
      currentValue: currentDns.spfRecord || "NONE",
      description: !currentDns.spfRecord ? "SPF record was REMOVED \u2014 domain is now more vulnerable to spoofing" : `SPF record changed from "${previousRecon.spfRecord || "NONE"}" to "${currentDns.spfRecord}"`
    });
  }
  if (previousRecon.dmarcRecord !== void 0 && previousRecon.dmarcRecord !== currentDns.dmarcRecord) {
    changes.push({
      type: "dmarc_changed",
      severity: !currentDns.dmarcRecord ? "critical" : "warning",
      previousValue: previousRecon.dmarcRecord || "NONE",
      currentValue: currentDns.dmarcRecord || "NONE",
      description: !currentDns.dmarcRecord ? "DMARC record was REMOVED \u2014 domain is now more vulnerable to spoofing" : `DMARC record changed`
    });
  }
  const prevMx = (previousRecon.mxRecords || []).map((m) => m.exchange).sort().join(",");
  const currMx = currentDns.mxRecords.map((m) => m.exchange).sort().join(",");
  if (prevMx !== currMx) {
    changes.push({
      type: "mx_changed",
      severity: "warning",
      previousValue: prevMx || "NONE",
      currentValue: currMx || "NONE",
      description: `MX records changed \u2014 mail routing may have been modified`
    });
  }
  const prevNs = (previousRecon.nsRecords || []).sort().join(",");
  const currNs = currentDns.nsRecords.sort().join(",");
  if (prevNs !== currNs) {
    changes.push({
      type: "ns_changed",
      severity: "warning",
      previousValue: prevNs || "NONE",
      currentValue: currNs || "NONE",
      description: `Nameservers changed \u2014 DNS hosting may have been migrated`
    });
  }
  const prevA = (previousRecon.aRecords || []).sort().join(",");
  const currA = currentDns.aRecords.sort().join(",");
  if (prevA !== currA) {
    changes.push({
      type: "a_record_changed",
      severity: "info",
      previousValue: prevA || "NONE",
      currentValue: currA || "NONE",
      description: `A records changed \u2014 hosting infrastructure may have been modified`
    });
  }
  const prevSubs = new Set(previousRecon.subdomains || []);
  const newSubs = currentSubdomains.filter((s) => !prevSubs.has(s));
  if (newSubs.length > 0) {
    changes.push({
      type: "new_subdomain",
      severity: "info",
      previousValue: `${prevSubs.size} subdomains`,
      currentValue: `${currentSubdomains.length} subdomains (+${newSubs.length} new)`,
      description: `New subdomains discovered: ${newSubs.slice(0, 10).join(", ")}${newSubs.length > 10 ? "..." : ""}`
    });
  }
  const currSubs = new Set(currentSubdomains);
  const removedSubs = Array.from(prevSubs).filter((s) => !currSubs.has(s));
  if (removedSubs.length > 0) {
    changes.push({
      type: "removed_subdomain",
      severity: "info",
      previousValue: `${prevSubs.size} subdomains`,
      currentValue: `${currentSubdomains.length} subdomains (-${removedSubs.length} removed)`,
      description: `Subdomains no longer found: ${removedSubs.slice(0, 10).join(", ")}${removedSubs.length > 10 ? "..." : ""}`
    });
  }
  return {
    domain,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    changes
  };
}
export {
  analyzeDns,
  analyzeSpoofability,
  batchWhoisCheck,
  checkDomainRegistration,
  detectDomainChanges,
  enumerateSubdomains,
  generateTyposquats,
  runFullRecon,
  whoisLookup
};
