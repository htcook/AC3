import {
  ENV,
  init_env
} from "./chunk-GN2OC6SU.js";
import "./chunk-KFQGP6VL.js";

// server/lib/typosquat.ts
init_env();
import dns from "dns";
import { promisify } from "util";
var resolveDns = promisify(dns.resolve);
var HOMOGLYPHS = {
  a: ["\xE0", "\xE1", "\xE2", "\xE3", "\xE4", "\xE5", "\u0251", "\u0430"],
  b: ["d", "lb"],
  c: ["\xE7", "\u0107", "\u0109", "\u010B"],
  d: ["b", "cl", "\u0257"],
  e: ["\xE8", "\xE9", "\xEA", "\xEB", "\u0113", "\u0115", "\u0117"],
  f: ["\u0192"],
  g: ["q", "\u0261"],
  h: ["lh"],
  i: ["1", "l", "\xEC", "\xED", "\xEE", "\xEF"],
  j: ["\u0135"],
  k: ["lk", "\u0138"],
  l: ["1", "i", "\u013A"],
  m: ["rn", "\u1E41"],
  n: ["\xF1", "\u0144", "\u014B"],
  o: ["0", "\xF2", "\xF3", "\xF4", "\xF5", "\xF6", "\xF8"],
  p: ["\u03C1"],
  q: ["g"],
  r: ["\u0155"],
  s: ["5", "\u015B", "\u015D", "\u015F"],
  t: ["\u0163", "\u0165"],
  u: ["\xF9", "\xFA", "\xFB", "\xFC", "\u0169"],
  v: ["\u03BD"],
  w: ["vv", "\u0175"],
  x: ["\xD7"],
  y: ["\xFD", "\xFF", "\u0177"],
  z: ["\u017A", "\u017C", "\u017E"]
};
var ADJACENT_KEYS = {
  a: ["q", "w", "s", "z"],
  b: ["v", "g", "h", "n"],
  c: ["x", "d", "f", "v"],
  d: ["s", "e", "r", "f", "c", "x"],
  e: ["w", "s", "d", "r"],
  f: ["d", "r", "t", "g", "v", "c"],
  g: ["f", "t", "y", "h", "b", "v"],
  h: ["g", "y", "u", "j", "n", "b"],
  i: ["u", "j", "k", "o"],
  j: ["h", "u", "i", "k", "n", "m"],
  k: ["j", "i", "o", "l", "m"],
  l: ["k", "o", "p"],
  m: ["n", "j", "k"],
  n: ["b", "h", "j", "m"],
  o: ["i", "k", "l", "p"],
  p: ["o", "l"],
  q: ["w", "a"],
  r: ["e", "d", "f", "t"],
  s: ["a", "w", "e", "d", "x", "z"],
  t: ["r", "f", "g", "y"],
  u: ["y", "h", "j", "i"],
  v: ["c", "f", "g", "b"],
  w: ["q", "a", "s", "e"],
  x: ["z", "s", "d", "c"],
  y: ["t", "g", "h", "u"],
  z: ["a", "s", "x"]
};
var PHISHING_TLDS = [".co", ".net", ".org", ".io", ".info", ".biz", ".us", ".cc", ".xyz"];
var COMBO_PREFIXES = ["login-", "secure-", "auth-", "mail-", "portal-", "my-", "account-", "verify-"];
var COMBO_SUFFIXES = ["-login", "-secure", "-auth", "-portal", "-verify", "-support", "-help", "-account"];
function splitDomain(domain) {
  const parts = domain.split(".");
  if (parts.length < 2) return { name: domain, tld: "" };
  const tld = "." + parts.slice(-1).join(".");
  const name = parts.slice(0, -1).join(".");
  return { name, tld };
}
function generateHomoglyphs(name, tld) {
  const variants = [];
  for (let i = 0; i < name.length; i++) {
    const char = name[i].toLowerCase();
    const glyphs = HOMOGLYPHS[char];
    if (glyphs) {
      const asciiGlyphs = glyphs.filter((g) => /^[a-z0-9]+$/.test(g));
      for (const glyph of asciiGlyphs) {
        const variant = name.slice(0, i) + glyph + name.slice(i + 1);
        if (variant !== name && variant.length <= 63) {
          variants.push({
            domain: variant + tld,
            technique: "homoglyph",
            effectiveness: 9,
            description: `Replaced '${char}' with '${glyph}' at position ${i + 1}`,
            tld
          });
        }
      }
    }
  }
  return variants;
}
function generateAdjacentSwaps(name, tld) {
  const variants = [];
  for (let i = 0; i < name.length; i++) {
    const char = name[i].toLowerCase();
    const adjacent = ADJACENT_KEYS[char];
    if (adjacent) {
      for (const adj of adjacent.slice(0, 2)) {
        const variant = name.slice(0, i) + adj + name.slice(i + 1);
        if (variant !== name) {
          variants.push({
            domain: variant + tld,
            technique: "adjacent_swap",
            effectiveness: 7,
            description: `Swapped '${char}' with adjacent key '${adj}' at position ${i + 1}`,
            tld
          });
        }
      }
    }
  }
  return variants;
}
function generateOmissions(name, tld) {
  const variants = [];
  for (let i = 0; i < name.length; i++) {
    const variant = name.slice(0, i) + name.slice(i + 1);
    if (variant.length >= 2) {
      variants.push({
        domain: variant + tld,
        technique: "omission",
        effectiveness: 6,
        description: `Omitted '${name[i]}' at position ${i + 1}`,
        tld
      });
    }
  }
  return variants;
}
function generateDoublings(name, tld) {
  const variants = [];
  for (let i = 0; i < name.length; i++) {
    const variant = name.slice(0, i) + name[i] + name.slice(i);
    if (variant.length <= 63) {
      variants.push({
        domain: variant + tld,
        technique: "doubling",
        effectiveness: 6,
        description: `Doubled '${name[i]}' at position ${i + 1}`,
        tld
      });
    }
  }
  return variants;
}
function generateTldSwaps(name, originalTld) {
  return PHISHING_TLDS.filter((tld) => tld !== originalTld).map((tld) => ({
    domain: name + tld,
    technique: "tld_swap",
    effectiveness: 8,
    description: `Changed TLD from '${originalTld}' to '${tld}'`,
    tld
  }));
}
function generateMissingDot(name, tld) {
  const variants = [];
  variants.push({
    domain: "www" + name + tld,
    technique: "missing_dot",
    effectiveness: 7,
    description: `Missing dot: www${name}${tld} (looks like www.${name}${tld})`,
    tld
  });
  return variants;
}
function generateHyphenation(name, tld) {
  const variants = [];
  for (let i = 1; i < name.length; i++) {
    const variant = name.slice(0, i) + "-" + name.slice(i);
    if (variant.length <= 63) {
      variants.push({
        domain: variant + tld,
        technique: "hyphenation",
        effectiveness: 5,
        description: `Inserted hyphen at position ${i + 1}: ${variant}`,
        tld
      });
    }
  }
  return variants.slice(0, 3);
}
function generateCombosquats(name, tld) {
  const variants = [];
  for (const prefix of COMBO_PREFIXES) {
    const domain = prefix + name + tld;
    if (domain.length <= 63 + tld.length) {
      variants.push({
        domain,
        technique: "combosquat",
        effectiveness: 8,
        description: `Added prefix '${prefix}' for phishing context`,
        tld
      });
    }
  }
  for (const suffix of COMBO_SUFFIXES) {
    const domain = name + suffix + tld;
    if (domain.length <= 63 + tld.length) {
      variants.push({
        domain,
        technique: "combosquat",
        effectiveness: 8,
        description: `Added suffix '${suffix}' for phishing context`,
        tld
      });
    }
  }
  return variants;
}
function generateTranspositions(name, tld) {
  const variants = [];
  for (let i = 0; i < name.length - 1; i++) {
    const variant = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
    if (variant !== name) {
      variants.push({
        domain: variant + tld,
        technique: "transposition",
        effectiveness: 7,
        description: `Swapped '${name[i]}' and '${name[i + 1]}' at positions ${i + 1}-${i + 2}`,
        tld
      });
    }
  }
  return variants;
}
async function checkDomainAvailability(domain) {
  try {
    await resolveDns(domain, "A");
    return false;
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      try {
        await resolveDns(domain, "NS");
        return false;
      } catch {
        return true;
      }
    }
    return true;
  }
}
async function generateTyposquatVariants(targetDomain, options) {
  const { name, tld } = splitDomain(targetDomain);
  const maxVariants = options?.maxVariants || 10;
  const checkAvail = options?.checkAvailability !== false;
  const allVariants = [
    ...generateHomoglyphs(name, tld),
    ...generateAdjacentSwaps(name, tld),
    ...generateTldSwaps(name, tld),
    ...generateCombosquats(name, tld),
    ...generateMissingDot(name, tld),
    ...generateTranspositions(name, tld),
    ...generateOmissions(name, tld),
    ...generateDoublings(name, tld),
    ...generateHyphenation(name, tld)
  ];
  const seen = /* @__PURE__ */ new Set();
  const unique = allVariants.filter((v) => {
    if (seen.has(v.domain)) return false;
    seen.add(v.domain);
    return true;
  });
  unique.sort((a, b) => b.effectiveness - a.effectiveness);
  const topCandidates = unique.slice(0, maxVariants * 3);
  if (checkAvail) {
    const BATCH_SIZE = 10;
    for (let i = 0; i < topCandidates.length; i += BATCH_SIZE) {
      const batch = topCandidates.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map((v) => checkDomainAvailability(v.domain))
      );
      results.forEach((result, idx) => {
        batch[idx].available = result.status === "fulfilled" ? result.value : void 0;
      });
    }
  }
  const recommended = topCandidates.filter((v) => v.available === true || v.available === void 0).slice(0, maxVariants);
  let canSpoof = false;
  let spoofabilityScore = 0;
  let spoofabilityReason = "";
  try {
    const { analyzeDns, analyzeSpoofability } = await import("./osint-OVRAGJBF.js");
    const dnsData = await analyzeDns(targetDomain);
    const spoofResult = analyzeSpoofability(dnsData);
    spoofabilityScore = spoofResult.score;
    canSpoof = spoofResult.score >= 50;
    spoofabilityReason = canSpoof ? `Target domain has weak email security (score: ${spoofResult.score}/100). Direct spoofing may be possible, but typosquat domains provide better deliverability.` : `Target domain has strong email security (score: ${spoofResult.score}/100). SPF/DKIM/DMARC prevent direct spoofing \u2014 typosquat domains are recommended.`;
  } catch {
    spoofabilityReason = "Could not check target domain email security. Typosquat domains recommended as a safe approach.";
  }
  return {
    targetDomain,
    canSpoof,
    spoofabilityScore,
    spoofabilityReason,
    variants: options?.includeAllTechniques ? unique : topCandidates,
    recommendedVariants: recommended,
    generatedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
var DO_API = "https://api.digitalocean.com/v2";
async function doFetch(endpoint, method = "GET", body) {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN not configured");
  const resp = await fetch(`${DO_API}${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: body ? JSON.stringify(body) : void 0
  });
  if (!resp.ok) {
    const errText = await resp.text().catch(() => "");
    throw new Error(`DigitalOcean API error ${resp.status}: ${errText}`);
  }
  if (resp.status === 204) return null;
  return resp.json();
}
async function addDomainToDO(domain, ipAddress) {
  return doFetch("/domains", "POST", {
    name: domain,
    ip_address: ipAddress || "127.0.0.1"
    // Placeholder IP
  });
}
async function createDnsRecord(domain, record) {
  return doFetch(`/domains/${domain}/records`, "POST", {
    ...record,
    ttl: record.ttl || 1800
  });
}
async function configureDomainForEmail(domain, mailServerIp = "137.184.7.224") {
  await addDomainToDO(domain, mailServerIp);
  await createDnsRecord(domain, {
    type: "MX",
    name: "@",
    data: `mail.${domain}.`,
    priority: 10
  });
  await createDnsRecord(domain, {
    type: "A",
    name: "mail",
    data: mailServerIp
  });
  const spfRecord = `v=spf1 ip4:${mailServerIp} -all`;
  await createDnsRecord(domain, {
    type: "TXT",
    name: "@",
    data: spfRecord
  });
  const dmarcRecord = `v=DMARC1; p=none; sp=none`;
  await createDnsRecord(domain, {
    type: "TXT",
    name: "_dmarc",
    data: dmarcRecord
  });
  return {
    domain,
    mxRecords: [{ exchange: `mail.${domain}`, priority: 10 }],
    spfRecord,
    dmarcRecord
  };
}
async function listDODomains() {
  const result = await doFetch("/domains");
  return result?.domains || [];
}
async function getDomainRecords(domain) {
  const result = await doFetch(`/domains/${domain}/records`);
  return result?.domain_records || [];
}
async function deleteDODomain(domain) {
  await doFetch(`/domains/${domain}`, "DELETE");
}
export {
  addDomainToDO,
  configureDomainForEmail,
  createDnsRecord,
  deleteDODomain,
  generateTyposquatVariants,
  getDomainRecords,
  listDODomains
};
