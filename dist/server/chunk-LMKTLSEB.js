import {
  analyzeTLSDeterministic,
  init_deterministic_scanner_analysis,
  useDeterministicAnalysis
} from "./chunk-EILMWEUF.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-H6H4ARI2.js";
import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-OR6TJBFA.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-RY5LYP5I.js";
import {
  getDb,
  init_db
} from "./chunk-SI4LILOM.js";
import {
  init_schema,
  scanResults
} from "./chunk-YQRYZ5JK.js";

// server/lib/scanners/tls-deep-scanner.ts
init_scan_server_executor();
init_llm();
init_llm_throttle();
init_deterministic_scanner_analysis();
init_db();
init_schema();
var PROTOCOL_GRADES = {
  "SSLv2": { grade: "critical", notes: "Completely broken, vulnerable to DROWN and many other attacks" },
  "SSLv3": { grade: "critical", notes: "Vulnerable to POODLE attack, deprecated since 2015 (RFC 7568)" },
  "TLSv1.0": { grade: "weak", notes: "Deprecated since 2021 (RFC 8996), vulnerable to BEAST" },
  "TLSv1.1": { grade: "weak", notes: "Deprecated since 2021 (RFC 8996), no modern cipher support" },
  "TLSv1.2": { grade: "good", notes: "Current standard, ensure strong cipher suites are configured" },
  "TLSv1.3": { grade: "good", notes: "Latest version, strongest security, recommended" }
};
var WEAK_CIPHERS = {
  // NULL ciphers — no encryption at all
  "NULL": { grade: "insecure", notes: "No encryption" },
  "eNULL": { grade: "insecure", notes: "No encryption" },
  "aNULL": { grade: "insecure", notes: "No authentication" },
  // Export ciphers — deliberately weakened
  "EXP": { grade: "insecure", notes: "Export-grade, trivially breakable (40/56-bit)" },
  "EXPORT": { grade: "insecure", notes: "Export-grade, trivially breakable" },
  // RC4 — broken stream cipher
  "RC4": { grade: "insecure", notes: "RC4 stream cipher is broken (RFC 7465)" },
  "ARCFOUR": { grade: "insecure", notes: "RC4 variant, broken" },
  // DES — 56-bit, trivially brute-forced
  "DES-CBC": { grade: "insecure", notes: "56-bit DES, trivially brute-forced" },
  "DES-CBC3": { grade: "weak", notes: "3DES, vulnerable to Sweet32 (CVE-2016-2183)" },
  "3DES": { grade: "weak", notes: "Triple DES, vulnerable to Sweet32 attack" },
  // MD5 MAC
  "MD5": { grade: "weak", notes: "MD5 MAC is collision-prone" },
  // Anonymous key exchange
  "ADH": { grade: "insecure", notes: "Anonymous Diffie-Hellman, no authentication" },
  "AECDH": { grade: "insecure", notes: "Anonymous ECDH, no authentication" }
};
var STRONG_CIPHERS = /* @__PURE__ */ new Set([
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "DHE-RSA-AES256-GCM-SHA384",
  "DHE-RSA-AES128-GCM-SHA256",
  "DHE-RSA-CHACHA20-POLY1305"
]);
var TLS_VULNERABILITIES = [
  {
    id: "heartbleed",
    name: "Heartbleed",
    cve: "CVE-2014-0160",
    severity: "critical",
    description: "OpenSSL TLS heartbeat extension memory disclosure. Allows remote attackers to read server memory including private keys, session tokens, and passwords.",
    detectionTemplate: "ssl-heartbleed",
    opensslCheck: null,
    recommendation: "Update OpenSSL to 1.0.1g or later. Revoke and reissue all certificates. Reset all passwords and session tokens.",
    references: ["https://heartbleed.com", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]
  },
  {
    id: "poodle",
    name: "POODLE (SSLv3)",
    cve: "CVE-2014-3566",
    severity: "high",
    description: "Padding Oracle On Downgraded Legacy Encryption. Allows MitM attackers to decrypt SSLv3 traffic one byte at a time.",
    detectionTemplate: "ssl-poodle",
    opensslCheck: "s_client -ssl3",
    recommendation: "Disable SSLv3 entirely. Configure TLS_FALLBACK_SCSV to prevent protocol downgrade.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-3566"]
  },
  {
    id: "poodle-tls",
    name: "POODLE (TLS)",
    cve: "CVE-2014-8730",
    severity: "high",
    description: "TLS implementations that don't verify padding bytes are vulnerable to POODLE-like attacks even with TLS.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Update TLS implementation to properly verify CBC padding. Prefer GCM or AEAD cipher suites.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-8730"]
  },
  {
    id: "drown",
    name: "DROWN",
    cve: "CVE-2016-0800",
    severity: "critical",
    description: "Decrypting RSA with Obsolete and Weakened eNcryption. SSLv2 support allows cross-protocol attacks on TLS sessions sharing the same RSA key.",
    detectionTemplate: null,
    opensslCheck: "s_client -ssl2",
    recommendation: "Disable SSLv2 on all servers sharing the same RSA private key. Ensure no server in the certificate's scope supports SSLv2.",
    references: ["https://drownattack.com", "https://nvd.nist.gov/vuln/detail/CVE-2016-0800"]
  },
  {
    id: "logjam",
    name: "Logjam",
    cve: "CVE-2015-4000",
    severity: "high",
    description: "TLS connections using DHE with 512-bit or 1024-bit DH groups can be downgraded by MitM attackers.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Use DH groups of at least 2048 bits. Prefer ECDHE key exchange. Disable DHE_EXPORT cipher suites.",
    references: ["https://weakdh.org", "https://nvd.nist.gov/vuln/detail/CVE-2015-4000"]
  },
  {
    id: "freak",
    name: "FREAK",
    cve: "CVE-2015-0204",
    severity: "high",
    description: "Factoring RSA Export Keys. Allows MitM attackers to force export-grade RSA key exchange, then factor the 512-bit key.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Disable all EXPORT cipher suites. Update OpenSSL/TLS libraries.",
    references: ["https://freakattack.com", "https://nvd.nist.gov/vuln/detail/CVE-2015-0204"]
  },
  {
    id: "robot",
    name: "ROBOT",
    cve: "CVE-2017-13099",
    severity: "high",
    description: "Return Of Bleichenbacher's Oracle Threat. RSA encryption key exchange vulnerable to adaptive chosen-ciphertext attack.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Disable RSA key exchange. Use only ECDHE or DHE key exchange. Update TLS implementation.",
    references: ["https://robotattack.org", "https://nvd.nist.gov/vuln/detail/CVE-2017-13099"]
  },
  {
    id: "ccs-injection",
    name: "CCS Injection",
    cve: "CVE-2014-0224",
    severity: "high",
    description: "OpenSSL ChangeCipherSpec injection. Allows MitM attackers to force use of weak keying material.",
    detectionTemplate: "ssl-ccs-injection",
    opensslCheck: null,
    recommendation: "Update OpenSSL to 0.9.8za, 1.0.0m, or 1.0.1h or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-0224"]
  },
  {
    id: "ticketbleed",
    name: "Ticketbleed",
    cve: "CVE-2016-9244",
    severity: "high",
    description: "F5 BIG-IP TLS session ticket implementation leaks 31 bytes of uninitialized memory per request.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Update F5 BIG-IP firmware. Disable session tickets as a workaround.",
    references: ["https://filippo.io/Ticketbleed/", "https://nvd.nist.gov/vuln/detail/CVE-2016-9244"]
  },
  {
    id: "crime",
    name: "CRIME",
    cve: "CVE-2012-4929",
    severity: "medium",
    description: "Compression Ratio Info-leak Made Easy. TLS-level compression allows attackers to recover secrets via compressed size oracle.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Disable TLS-level compression. Most modern servers already have this disabled.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2012-4929"]
  },
  {
    id: "breach",
    name: "BREACH",
    cve: "CVE-2013-3587",
    severity: "medium",
    description: "Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext. HTTP-level compression can leak secrets.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Disable HTTP compression for pages containing secrets. Use CSRF tokens that change per-request. Separate secret content from user-controlled content.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2013-3587"]
  },
  {
    id: "sweet32",
    name: "Sweet32",
    cve: "CVE-2016-2183",
    severity: "medium",
    description: "Birthday attacks on 64-bit block ciphers (3DES, Blowfish). Long-lived connections can be decrypted.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Disable 3DES and Blowfish cipher suites. Use AES-GCM or ChaCha20-Poly1305.",
    references: ["https://sweet32.info", "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"]
  },
  {
    id: "beast",
    name: "BEAST",
    cve: "CVE-2011-3389",
    severity: "medium",
    description: "Browser Exploit Against SSL/TLS. CBC cipher suites in TLS 1.0 vulnerable to chosen-plaintext attack.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Upgrade to TLS 1.2+ with GCM cipher suites. If TLS 1.0 must be supported, prefer RC4 (lesser evil) or implement 1/n-1 record splitting.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"]
  },
  {
    id: "lucky13",
    name: "Lucky Thirteen",
    cve: "CVE-2013-0169",
    severity: "medium",
    description: "Timing side-channel attack against CBC cipher suites in TLS. Allows plaintext recovery.",
    detectionTemplate: null,
    opensslCheck: null,
    recommendation: "Prefer AEAD cipher suites (GCM, ChaCha20-Poly1305). Update TLS implementation for constant-time CBC processing.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2013-0169"]
  },
  {
    id: "renegotiation",
    name: "Insecure Renegotiation",
    cve: "CVE-2009-3555",
    severity: "high",
    description: "TLS renegotiation vulnerability allows MitM attackers to inject data into TLS sessions.",
    detectionTemplate: "ssl-enum-ciphers",
    opensslCheck: null,
    recommendation: "Enable secure renegotiation (RFC 5746). Update TLS implementation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2009-3555"]
  }
];
function parseScanForgeSSLEnum(output) {
  const protocols = [];
  const cipherSuites = [];
  const protocolRegex = /(SSLv[23]|TLSv1\.[0-3]):/g;
  let match;
  const foundProtocols = /* @__PURE__ */ new Set();
  while ((match = protocolRegex.exec(output)) !== null) {
    const proto = match[1];
    if (foundProtocols.has(proto)) continue;
    foundProtocols.add(proto);
    const gradeInfo = PROTOCOL_GRADES[proto] || { grade: "unknown", notes: "Unknown protocol version" };
    protocols.push({
      name: proto,
      version: proto,
      supported: true,
      grade: gradeInfo.grade,
      notes: gradeInfo.notes
    });
  }
  for (const [name, info] of Object.entries(PROTOCOL_GRADES)) {
    if (!foundProtocols.has(name)) {
      protocols.push({
        name,
        version: name,
        supported: false,
        grade: info.grade,
        notes: `Not supported (${info.notes})`
      });
    }
  }
  const cipherRegex = /\|\s+(TLS_[A-Z0-9_]+|[A-Z0-9_]+-[A-Z0-9_-]+)\s+/g;
  while ((match = cipherRegex.exec(output)) !== null) {
    const name = match[1];
    const suite = gradeCipherSuite(name);
    cipherSuites.push(suite);
  }
  return { protocols, cipherSuites };
}
function parseOpenSSLOutput(output) {
  const protocol = (output.match(/Protocol\s*:\s*(TLSv[\d.]+|SSLv[\d.]+)/i) || output.match(/SSL-Session:[\s\S]*?Protocol\s*:\s*(TLSv[\d.]+)/i))?.[1] || null;
  const cipher = output.match(/Cipher\s*:\s*(\S+)/i)?.[1] || null;
  const compression = /Compression:\s*(?!NONE\b|off\b|$)\S/i.test(output);
  const secureRenegotiation = /Secure Renegotiation IS supported/i.test(output);
  const sessionTickets = /TLS session ticket/i.test(output);
  const subject = output.match(/subject\s*=\s*(.+)/i)?.[1]?.trim() || null;
  const issuer = output.match(/issuer\s*=\s*(.+)/i)?.[1]?.trim() || null;
  const serial = output.match(/Serial Number:\s*\n?\s*([a-f0-9:]+)/i)?.[1]?.trim() || null;
  const notBefore = output.match(/Not Before\s*:\s*(.+)/i)?.[1]?.trim() || null;
  const notAfter = output.match(/Not After\s*:\s*(.+)/i)?.[1]?.trim() || null;
  const sigAlg = output.match(/Signature Algorithm:\s*(\S+)/i)?.[1] || null;
  const pubKeyAlg = output.match(/Public Key Algorithm:\s*(\S+)/i)?.[1] || null;
  const pubKeyBits = parseInt(output.match(/Public-Key:\s*\((\d+)\s*bit\)/i)?.[1] || "0", 10) || null;
  const sanSection = output.match(/X509v3 Subject Alternative Name:\s*\n?\s*(.+)/i)?.[1] || "";
  const san = sanSection.split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter(Boolean);
  const selfSigned = subject !== null && issuer !== null && subject === issuer;
  let expired = false;
  let expiresWithin30Days = false;
  if (notAfter) {
    try {
      const expiryDate = new Date(notAfter);
      const now = /* @__PURE__ */ new Date();
      expired = expiryDate < now;
      expiresWithin30Days = !expired && expiryDate < new Date(now.getTime() + 30 * 24 * 60 * 60 * 1e3);
    } catch {
    }
  }
  const weakSignature = sigAlg !== null && /md5|sha1(?!WithRSAEncryption)/i.test(sigAlg);
  const weakKey = pubKeyBits !== null && (pubKeyAlg?.includes("rsa") && pubKeyBits < 2048 || pubKeyAlg?.includes("ec") && pubKeyBits < 256);
  const chainDepth = (output.match(/\d+\s+s:/g) || []).length;
  const ocspStapling = /OCSP response:[\s\S]*?Response Status: successful/i.test(output);
  const ocspResponder = output.match(/OCSP - URI:(\S+)/i)?.[1] || null;
  const certificate = {
    subject,
    issuer,
    serialNumber: serial,
    notBefore,
    notAfter,
    signatureAlgorithm: sigAlg,
    publicKeyAlgorithm: pubKeyAlg,
    publicKeyBits: pubKeyBits,
    san,
    selfSigned,
    expired,
    expiresWithin30Days,
    weakSignature,
    weakKey,
    chainDepth,
    ocspStapling,
    ocspResponder,
    issues: []
  };
  return { protocol, cipher, certificate, compression, secureRenegotiation, sessionTickets };
}
function gradeCipherSuite(name) {
  const upper = name.toUpperCase();
  for (const [pattern, info] of Object.entries(WEAK_CIPHERS)) {
    if (upper.includes(pattern)) {
      return {
        name,
        protocol: "",
        keyExchange: extractKEX(name),
        authentication: extractAuth(name),
        encryption: extractEnc(name),
        mac: extractMAC(name),
        bits: extractBits(name),
        grade: info.grade,
        forwardSecrecy: /^(ECDHE|DHE)/.test(name) || name.startsWith("TLS_"),
        notes: info.notes
      };
    }
  }
  if (STRONG_CIPHERS.has(name)) {
    return {
      name,
      protocol: "",
      keyExchange: extractKEX(name),
      authentication: extractAuth(name),
      encryption: extractEnc(name),
      mac: extractMAC(name),
      bits: extractBits(name),
      grade: "strong",
      forwardSecrecy: true,
      notes: "Modern, recommended cipher suite"
    };
  }
  const hasFS = /^(ECDHE|DHE)/.test(name) || name.startsWith("TLS_");
  const hasGCM = upper.includes("GCM");
  const hasCHACHA = upper.includes("CHACHA20");
  const hasSHA256Plus = upper.includes("SHA256") || upper.includes("SHA384") || upper.includes("SHA512");
  const hasCBC = upper.includes("CBC");
  let grade = "acceptable";
  let notes = "";
  if (hasFS && (hasGCM || hasCHACHA)) {
    grade = "strong";
    notes = "AEAD cipher with forward secrecy";
  } else if (hasFS && hasSHA256Plus) {
    grade = "acceptable";
    notes = "Forward secrecy with SHA-256+";
  } else if (hasFS && hasCBC) {
    grade = "acceptable";
    notes = "Forward secrecy but CBC mode (vulnerable to padding oracle attacks)";
  } else if (!hasFS) {
    grade = "weak";
    notes = "No forward secrecy \u2014 compromised server key decrypts all past traffic";
  }
  return {
    name,
    protocol: "",
    keyExchange: extractKEX(name),
    authentication: extractAuth(name),
    encryption: extractEnc(name),
    mac: extractMAC(name),
    bits: extractBits(name),
    grade,
    forwardSecrecy: hasFS,
    notes
  };
}
function extractKEX(name) {
  if (name.startsWith("TLS_")) return "TLS 1.3 (built-in)";
  const match = name.match(/^(ECDHE|DHE|RSA|ECDH|DH|ADH|AECDH)/);
  return match ? match[1] : null;
}
function extractAuth(name) {
  if (name.startsWith("TLS_")) return "TLS 1.3 (built-in)";
  const match = name.match(/-(ECDSA|RSA|DSS|PSK|anon)-/);
  return match ? match[1] : null;
}
function extractEnc(name) {
  if (name.includes("AES_256_GCM")) return "AES-256-GCM";
  if (name.includes("AES_128_GCM")) return "AES-128-GCM";
  if (name.includes("CHACHA20")) return "ChaCha20-Poly1305";
  if (name.includes("AES256-GCM")) return "AES-256-GCM";
  if (name.includes("AES128-GCM")) return "AES-128-GCM";
  if (name.includes("AES256")) return "AES-256";
  if (name.includes("AES128")) return "AES-128";
  if (name.includes("3DES")) return "3DES";
  if (name.includes("DES")) return "DES";
  if (name.includes("RC4")) return "RC4";
  return null;
}
function extractMAC(name) {
  if (name.includes("GCM") || name.includes("CHACHA20")) return "AEAD";
  const match = name.match(/(SHA384|SHA256|SHA|MD5)$/);
  return match ? match[1] : null;
}
function extractBits(name) {
  if (name.includes("256")) return 256;
  if (name.includes("128")) return 128;
  if (name.includes("3DES")) return 168;
  if (name.includes("DES") && !name.includes("3DES")) return 56;
  if (name.includes("RC4")) return 128;
  return null;
}
function validateCertificate(cert, hostname) {
  const issues = [];
  if (cert.expired) issues.push("Certificate has expired");
  if (cert.expiresWithin30Days) issues.push("Certificate expires within 30 days");
  if (cert.selfSigned) issues.push("Certificate is self-signed (not trusted by default)");
  if (cert.weakSignature) issues.push(`Weak signature algorithm: ${cert.signatureAlgorithm}`);
  if (cert.weakKey) issues.push(`Weak public key: ${cert.publicKeyAlgorithm} ${cert.publicKeyBits} bits`);
  const san = cert.san || [];
  if (san.length > 0) {
    const hostMatches = san.some((s) => {
      if (s.startsWith("*.")) {
        const domain = s.slice(2);
        return hostname.endsWith(domain) && hostname.split(".").length === domain.split(".").length + 1;
      }
      return s === hostname;
    });
    if (!hostMatches) {
      issues.push(`Hostname mismatch: ${hostname} not in SAN [${san.join(", ")}]`);
    }
  }
  const chainComplete = (cert.chainDepth || 0) >= 2 || cert.selfSigned === true;
  if (!chainComplete && (cert.chainDepth || 0) < 2 && !cert.selfSigned) {
    issues.push("Certificate chain may be incomplete (depth < 2)");
  }
  return {
    subject: cert.subject || null,
    issuer: cert.issuer || null,
    serialNumber: cert.serialNumber || null,
    notBefore: cert.notBefore || null,
    notAfter: cert.notAfter || null,
    signatureAlgorithm: cert.signatureAlgorithm || null,
    publicKeyAlgorithm: cert.publicKeyAlgorithm || null,
    publicKeyBits: cert.publicKeyBits || null,
    san,
    selfSigned: cert.selfSigned || false,
    expired: cert.expired || false,
    expiresWithin30Days: cert.expiresWithin30Days || false,
    weakSignature: cert.weakSignature || false,
    weakKey: cert.weakKey || false,
    chainComplete,
    chainDepth: cert.chainDepth || 0,
    ocspStapling: cert.ocspStapling || false,
    ocspResponder: cert.ocspResponder || null,
    crlDistribution: cert.crlDistribution || null,
    issues
  };
}
function generateFindings(protocols, cipherSuites, certificate, vulnerabilities, compression, secureRenegotiation) {
  const findings = [];
  const ts = Date.now();
  for (const proto of protocols) {
    if (proto.supported && (proto.grade === "critical" || proto.grade === "weak")) {
      findings.push({
        id: `tls-proto-${proto.name}-${ts}`,
        category: "protocol",
        severity: proto.grade === "critical" ? "critical" : "medium",
        title: `${proto.grade === "critical" ? "Dangerous" : "Deprecated"} Protocol: ${proto.name}`,
        description: `Server supports ${proto.name}. ${proto.notes}`,
        recommendation: proto.grade === "critical" ? `Disable ${proto.name} immediately. It is fundamentally broken.` : `Disable ${proto.name}. Migrate to TLS 1.2+ only.`,
        cve: proto.name === "SSLv3" ? "CVE-2014-3566" : null,
        evidence: `${proto.name}: supported`
      });
    }
  }
  const hasTLS12Plus = protocols.some((p) => p.supported && (p.version === "TLSv1.2" || p.version === "TLSv1.3"));
  if (!hasTLS12Plus && protocols.some((p) => p.supported)) {
    findings.push({
      id: `tls-no-modern-${ts}`,
      category: "protocol",
      severity: "high",
      title: "No Modern TLS Protocol Support",
      description: "Server does not support TLS 1.2 or TLS 1.3. Only deprecated protocols are available.",
      recommendation: "Enable TLS 1.2 and TLS 1.3. Disable all older protocols.",
      cve: null,
      evidence: `Supported: ${protocols.filter((p) => p.supported).map((p) => p.name).join(", ")}`
    });
  }
  const weakCiphers = cipherSuites.filter((c) => c.grade === "weak" || c.grade === "insecure");
  if (weakCiphers.length > 0) {
    const insecure = weakCiphers.filter((c) => c.grade === "insecure");
    const weak = weakCiphers.filter((c) => c.grade === "weak");
    if (insecure.length > 0) {
      findings.push({
        id: `tls-insecure-ciphers-${ts}`,
        category: "cipher",
        severity: "critical",
        title: `${insecure.length} Insecure Cipher Suite(s) Supported`,
        description: `Server supports fundamentally broken cipher suites: ${insecure.map((c) => c.name).join(", ")}`,
        recommendation: "Disable all NULL, EXPORT, RC4, anonymous, and DES cipher suites immediately.",
        cve: null,
        evidence: insecure.map((c) => `${c.name}: ${c.notes}`).join("; ")
      });
    }
    if (weak.length > 0) {
      findings.push({
        id: `tls-weak-ciphers-${ts}`,
        category: "cipher",
        severity: "medium",
        title: `${weak.length} Weak Cipher Suite(s) Supported`,
        description: `Server supports cipher suites with known weaknesses: ${weak.map((c) => c.name).join(", ")}`,
        recommendation: "Disable 3DES, MD5-based MACs, and non-PFS cipher suites. Use AES-GCM or ChaCha20-Poly1305 with ECDHE.",
        cve: null,
        evidence: weak.map((c) => `${c.name}: ${c.notes}`).join("; ")
      });
    }
  }
  const noFS = cipherSuites.filter((c) => !c.forwardSecrecy && c.grade !== "insecure");
  if (noFS.length > 0 && cipherSuites.length > 0) {
    const fsPct = ((cipherSuites.length - noFS.length) / cipherSuites.length * 100).toFixed(0);
    if (parseInt(fsPct) < 50) {
      findings.push({
        id: `tls-no-fs-${ts}`,
        category: "cipher",
        severity: "medium",
        title: "Limited Forward Secrecy Support",
        description: `Only ${fsPct}% of cipher suites provide forward secrecy. ${noFS.length} cipher suites use static key exchange.`,
        recommendation: "Prioritize ECDHE and DHE cipher suites. Disable RSA key exchange.",
        cve: null,
        evidence: `Non-FS ciphers: ${noFS.map((c) => c.name).slice(0, 5).join(", ")}`
      });
    }
  }
  if (certificate) {
    for (const issue of certificate.issues) {
      const isExpiry = issue.includes("expired") || issue.includes("expires");
      const isSelfSigned = issue.includes("self-signed");
      const isWeakKey = issue.includes("Weak public key") || issue.includes("Weak signature");
      const isMismatch = issue.includes("mismatch");
      findings.push({
        id: `tls-cert-${issue.replace(/\s+/g, "-").toLowerCase().slice(0, 40)}-${ts}`,
        category: "certificate",
        severity: isExpiry && issue.includes("has expired") ? "critical" : isSelfSigned ? "high" : isMismatch ? "high" : isWeakKey ? "high" : "medium",
        title: issue,
        description: issue,
        recommendation: isExpiry ? "Renew the certificate immediately." : isSelfSigned ? "Replace with a certificate from a trusted CA (e.g., Let's Encrypt)." : isMismatch ? "Reissue the certificate with the correct Subject Alternative Names." : isWeakKey ? "Reissue the certificate with RSA 2048+ or ECDSA P-256+ and SHA-256+ signature." : "Review and fix the certificate configuration.",
        cve: null,
        evidence: `Subject: ${certificate.subject}, Issuer: ${certificate.issuer}`
      });
    }
    if (!certificate.ocspStapling) {
      findings.push({
        id: `tls-no-ocsp-stapling-${ts}`,
        category: "certificate",
        severity: "low",
        title: "OCSP Stapling Not Enabled",
        description: "The server does not provide OCSP stapling. Clients must contact the CA's OCSP responder directly, which impacts privacy and performance.",
        recommendation: "Enable OCSP stapling. In nginx: ssl_stapling on; ssl_stapling_verify on;. In Apache: SSLUseStapling On.",
        cve: null,
        evidence: "OCSP stapling: not detected"
      });
    }
  }
  for (const vuln of vulnerabilities) {
    if (vuln.affected) {
      findings.push({
        id: `tls-vuln-${vuln.id}-${ts}`,
        category: "vulnerability",
        severity: vuln.severity === "info" ? "low" : vuln.severity,
        title: `${vuln.name} Vulnerability Detected`,
        description: vuln.description,
        recommendation: vuln.recommendation,
        cve: vuln.cve,
        evidence: vuln.evidence
      });
    }
  }
  if (compression) {
    findings.push({
      id: `tls-compression-${ts}`,
      category: "configuration",
      severity: "medium",
      title: "TLS Compression Enabled (CRIME Vulnerability)",
      description: "TLS-level compression is enabled, making the server vulnerable to the CRIME attack.",
      recommendation: "Disable TLS compression. In OpenSSL: SSL_OP_NO_COMPRESSION.",
      cve: "CVE-2012-4929",
      evidence: "TLS compression: enabled"
    });
  }
  if (!secureRenegotiation) {
    findings.push({
      id: `tls-insecure-reneg-${ts}`,
      category: "configuration",
      severity: "high",
      title: "Insecure TLS Renegotiation",
      description: "The server does not support secure renegotiation (RFC 5746). This allows MitM attackers to inject data into TLS sessions.",
      recommendation: "Enable secure renegotiation. Update TLS implementation to support RFC 5746.",
      cve: "CVE-2009-3555",
      evidence: "Secure renegotiation: not supported"
    });
  }
  return findings;
}
function calculateGradeScore(protocols, cipherSuites, certificate, vulnerabilities, compression, secureRenegotiation) {
  let score = 100;
  const supportedProtos = protocols.filter((p) => p.supported);
  for (const p of supportedProtos) {
    if (p.grade === "critical") score -= 20;
    if (p.grade === "weak") score -= 10;
  }
  if (!supportedProtos.some((p) => p.version === "TLSv1.2" || p.version === "TLSv1.3")) {
    score -= 15;
  }
  const insecureCiphers = cipherSuites.filter((c) => c.grade === "insecure").length;
  const weakCiphers = cipherSuites.filter((c) => c.grade === "weak").length;
  score -= Math.min(insecureCiphers * 10, 30);
  score -= Math.min(weakCiphers * 5, 15);
  if (cipherSuites.length > 0) {
    const fsPct = cipherSuites.filter((c) => c.forwardSecrecy).length / cipherSuites.length;
    if (fsPct < 0.5) score -= 10;
  }
  if (certificate) {
    if (certificate.expired) score -= 25;
    else if (certificate.expiresWithin30Days) score -= 5;
    if (certificate.selfSigned) score -= 15;
    if (certificate.weakSignature) score -= 10;
    if (certificate.weakKey) score -= 10;
    if (certificate.issues.some((i) => i.includes("mismatch"))) score -= 15;
    if (!certificate.ocspStapling) score -= 3;
  }
  const critVulns = vulnerabilities.filter((v) => v.affected && v.severity === "critical").length;
  const highVulns = vulnerabilities.filter((v) => v.affected && v.severity === "high").length;
  const medVulns = vulnerabilities.filter((v) => v.affected && v.severity === "medium").length;
  score -= Math.min(critVulns * 15, 30);
  score -= Math.min(highVulns * 8, 16);
  score -= Math.min(medVulns * 3, 9);
  if (compression) score -= 5;
  if (!secureRenegotiation) score -= 8;
  score = Math.max(0, Math.min(100, score));
  let letter;
  if (score >= 90) letter = "A";
  else if (score >= 80) letter = "B";
  else if (score >= 65) letter = "C";
  else if (score >= 50) letter = "D";
  else letter = "F";
  if (certificate?.expired || insecureCiphers > 0 || critVulns > 0 || supportedProtos.some((p) => p.grade === "critical")) {
    if (letter !== "F") letter = Math.min(score, 49) >= 40 ? "D" : "F";
    score = Math.min(score, 49);
  }
  return { score, letter };
}
async function startTLSDeepScan(config) {
  const startTime = Date.now();
  const port = config.port || 443;
  const timeout = config.timeoutSeconds || 120;
  const sni = config.sniHostname || config.host;
  const starttlsFlag = config.starttls ? `-starttls ${config.starttls}` : "";
  console.log(`[TLSDeepScan] Starting deep TLS scan of ${config.host}:${port}`);
  let rawOutput = "";
  let protocols = [];
  let cipherSuites = [];
  let certificate = null;
  const vulnerabilities = [];
  let compression = false;
  let secureRenegotiation = true;
  if (config.enumerateCiphers !== false) {
    try {
      const discoveryResult = await executeTool({
        tool: "naabu",
        args: `-p ${port} --script ssl-enum-ciphers,ssl-cert -sV ${config.host}`,
        target: config.host,
        timeoutSeconds: Math.min(timeout, 90),
        engagementId: config.engagementId
      });
      rawOutput += `=== ScanForge discovery ssl-enum-ciphers ===
${discoveryResult.stdout}
`;
      const parsed = parseScanForgeSSLEnum(discoveryResult.stdout);
      protocols = parsed.protocols;
      cipherSuites = parsed.cipherSuites;
    } catch (err) {
      console.warn(`[TLSDeepScan] ScanForge discovery ssl-enum-ciphers failed: ${err.message}`);
    }
  }
  if (config.checkCertChain !== false) {
    try {
      const opensslResult = await executeRawCommand(
        `echo | openssl s_client -connect ${config.host}:${port} -servername ${sni} ${starttlsFlag} -showcerts -status -tlsextdebug 2>&1`,
        30
      );
      rawOutput += `
=== openssl s_client ===
${opensslResult.stdout}
`;
      const parsed = parseOpenSSLOutput(opensslResult.stdout);
      compression = parsed.compression;
      secureRenegotiation = parsed.secureRenegotiation;
      if (parsed.certificate.subject || parsed.certificate.issuer) {
        certificate = validateCertificate(parsed.certificate, config.host);
      }
      if (parsed.protocol && protocols.length === 0) {
        const gradeInfo = PROTOCOL_GRADES[parsed.protocol] || { grade: "unknown", notes: "" };
        protocols.push({
          name: parsed.protocol,
          version: parsed.protocol,
          supported: true,
          grade: gradeInfo.grade,
          notes: gradeInfo.notes
        });
      }
    } catch (err) {
      console.warn(`[TLSDeepScan] openssl s_client failed: ${err.message}`);
    }
  }
  if (config.checkCertChain !== false && !certificate) {
    try {
      const certResult = await executeRawCommand(
        `echo | openssl s_client -connect ${config.host}:${port} -servername ${sni} ${starttlsFlag} 2>/dev/null | openssl x509 -noout -text 2>&1`,
        15
      );
      rawOutput += `
=== openssl x509 ===
${certResult.stdout}
`;
      const parsed = parseOpenSSLOutput(certResult.stdout);
      if (parsed.certificate.subject || parsed.certificate.issuer) {
        certificate = validateCertificate(parsed.certificate, config.host);
      }
    } catch (err) {
      console.warn(`[TLSDeepScan] openssl x509 failed: ${err.message}`);
    }
  }
  if (config.checkOCSP !== false) {
    try {
      const ocspResult = await executeRawCommand(
        `echo | openssl s_client -connect ${config.host}:${port} -servername ${sni} ${starttlsFlag} -status 2>&1 | grep -A 20 "OCSP response"`,
        15
      );
      rawOutput += `
=== OCSP stapling ===
${ocspResult.stdout}
`;
      if (certificate && /Response Status: successful/i.test(ocspResult.stdout)) {
        certificate.ocspStapling = true;
      }
    } catch (err) {
      console.warn(`[TLSDeepScan] OCSP check failed: ${err.message}`);
    }
  }
  if (config.checkCVEs !== false) {
    try {
      const hbResult = await executeTool({
        tool: "naabu",
        args: `-p ${port} --script ssl-heartbleed ${config.host}`,
        target: config.host,
        timeoutSeconds: 30,
        engagementId: config.engagementId
      });
      rawOutput += `
=== Heartbleed check ===
${hbResult.stdout}
`;
      const isVuln = /VULNERABLE/i.test(hbResult.stdout);
      const vulnDef = TLS_VULNERABILITIES.find((v) => v.id === "heartbleed");
      vulnerabilities.push({
        id: vulnDef.id,
        name: vulnDef.name,
        cve: vulnDef.cve,
        severity: vulnDef.severity,
        description: vulnDef.description,
        affected: isVuln,
        evidence: isVuln ? "ScanForge ssl-heartbleed: VULNERABLE" : "ScanForge ssl-heartbleed: not vulnerable",
        recommendation: vulnDef.recommendation,
        references: vulnDef.references
      });
    } catch (err) {
      console.warn(`[TLSDeepScan] Heartbleed check failed: ${err.message}`);
    }
    try {
      const ccsResult = await executeTool({
        tool: "naabu",
        args: `-p ${port} --script ssl-ccs-injection ${config.host}`,
        target: config.host,
        timeoutSeconds: 30,
        engagementId: config.engagementId
      });
      rawOutput += `
=== CCS Injection check ===
${ccsResult.stdout}
`;
      const isVuln = /VULNERABLE/i.test(ccsResult.stdout);
      const vulnDef = TLS_VULNERABILITIES.find((v) => v.id === "ccs-injection");
      vulnerabilities.push({
        id: vulnDef.id,
        name: vulnDef.name,
        cve: vulnDef.cve,
        severity: vulnDef.severity,
        description: vulnDef.description,
        affected: isVuln,
        evidence: isVuln ? "ScanForge ssl-ccs-injection: VULNERABLE" : "ScanForge ssl-ccs-injection: not vulnerable",
        recommendation: vulnDef.recommendation,
        references: vulnDef.references
      });
    } catch (err) {
      console.warn(`[TLSDeepScan] CCS Injection check failed: ${err.message}`);
    }
    try {
      const poodleResult = await executeRawCommand(
        `echo | openssl s_client -connect ${config.host}:${port} -ssl3 2>&1`,
        10
      );
      rawOutput += `
=== POODLE (SSLv3) check ===
${poodleResult.stdout}
`;
      const sslv3Supported = !poodleResult.stdout.includes("alert handshake failure") && !poodleResult.stdout.includes("no protocols available") && !poodleResult.stdout.includes("wrong version number");
      const vulnDef = TLS_VULNERABILITIES.find((v) => v.id === "poodle");
      vulnerabilities.push({
        id: vulnDef.id,
        name: vulnDef.name,
        cve: vulnDef.cve,
        severity: vulnDef.severity,
        description: vulnDef.description,
        affected: sslv3Supported,
        evidence: sslv3Supported ? "SSLv3 handshake succeeded" : "SSLv3 not supported",
        recommendation: vulnDef.recommendation,
        references: vulnDef.references
      });
    } catch (err) {
      console.warn(`[TLSDeepScan] POODLE check failed: ${err.message}`);
    }
    try {
      const drownResult = await executeRawCommand(
        `echo | openssl s_client -connect ${config.host}:${port} -ssl2 2>&1`,
        10
      );
      rawOutput += `
=== DROWN (SSLv2) check ===
${drownResult.stdout}
`;
      const sslv2Supported = !drownResult.stdout.includes("unknown option") && !drownResult.stdout.includes("no protocols available") && !drownResult.stdout.includes("alert handshake failure");
      const vulnDef = TLS_VULNERABILITIES.find((v) => v.id === "drown");
      vulnerabilities.push({
        id: vulnDef.id,
        name: vulnDef.name,
        cve: vulnDef.cve,
        severity: vulnDef.severity,
        description: vulnDef.description,
        affected: sslv2Supported,
        evidence: sslv2Supported ? "SSLv2 handshake succeeded" : "SSLv2 not supported",
        recommendation: vulnDef.recommendation,
        references: vulnDef.references
      });
    } catch (err) {
      console.warn(`[TLSDeepScan] DROWN check failed: ${err.message}`);
    }
    const hasTLS10 = protocols.some((p) => p.supported && p.version === "TLSv1.0");
    if (hasTLS10) {
      const beastDef = TLS_VULNERABILITIES.find((v) => v.id === "beast");
      vulnerabilities.push({
        id: beastDef.id,
        name: beastDef.name,
        cve: beastDef.cve,
        severity: beastDef.severity,
        description: beastDef.description,
        affected: true,
        evidence: "TLS 1.0 supported \u2014 CBC cipher suites vulnerable to BEAST",
        recommendation: beastDef.recommendation,
        references: beastDef.references
      });
    }
    const has3DES = cipherSuites.some((c) => c.name.includes("3DES") || c.name.includes("DES-CBC3"));
    if (has3DES) {
      const sweet32Def = TLS_VULNERABILITIES.find((v) => v.id === "sweet32");
      vulnerabilities.push({
        id: sweet32Def.id,
        name: sweet32Def.name,
        cve: sweet32Def.cve,
        severity: sweet32Def.severity,
        description: sweet32Def.description,
        affected: true,
        evidence: `3DES cipher suites found: ${cipherSuites.filter((c) => c.name.includes("3DES") || c.name.includes("DES-CBC3")).map((c) => c.name).join(", ")}`,
        recommendation: sweet32Def.recommendation,
        references: sweet32Def.references
      });
    }
    if (compression) {
      const crimeDef = TLS_VULNERABILITIES.find((v) => v.id === "crime");
      vulnerabilities.push({
        id: crimeDef.id,
        name: crimeDef.name,
        cve: crimeDef.cve,
        severity: crimeDef.severity,
        description: crimeDef.description,
        affected: true,
        evidence: "TLS compression enabled",
        recommendation: crimeDef.recommendation,
        references: crimeDef.references
      });
    }
    if (!secureRenegotiation) {
      const renegDef = TLS_VULNERABILITIES.find((v) => v.id === "renegotiation");
      vulnerabilities.push({
        id: renegDef.id,
        name: renegDef.name,
        cve: renegDef.cve,
        severity: renegDef.severity,
        description: renegDef.description,
        affected: true,
        evidence: "Secure renegotiation not supported",
        recommendation: renegDef.recommendation,
        references: renegDef.references
      });
    }
  }
  if (useDeterministicAnalysis("tls")) {
    console.log(`[TLSDeepScan] Using deterministic analysis (Tier 1 offload)`);
    const tlsAnalysis = analyzeTLSDeterministic(protocols, cipherSuites, certificate, vulnerabilities, compression, secureRenegotiation);
    rawOutput += `
=== Deterministic Analysis ===
${tlsAnalysis}
`;
  } else {
    try {
      const analysisPrompt = `Analyze this TLS/SSL deep scan result and provide additional insights:

Target: ${config.host}:${port}
Protocols: ${protocols.filter((p) => p.supported).map((p) => p.name).join(", ") || "none detected"}
Cipher suites: ${cipherSuites.length} found (${cipherSuites.filter((c) => c.grade === "insecure").length} insecure, ${cipherSuites.filter((c) => c.grade === "weak").length} weak)
Certificate: ${certificate ? `${certificate.subject}, expires ${certificate.notAfter}, self-signed: ${certificate.selfSigned}` : "not available"}
Vulnerabilities detected: ${vulnerabilities.filter((v) => v.affected).map((v) => v.name).join(", ") || "none"}
Compression: ${compression}
Secure renegotiation: ${secureRenegotiation}

Provide a brief security assessment and any additional recommendations not already covered.`;
      await throttledLLMCall(async () => {
        const response = await invokeLLM({
          _caller: "tls-deep-scanner",
          messages: [
            { role: "system", content: "You are a TLS/SSL security expert. Provide concise, actionable analysis." },
            { role: "user", content: analysisPrompt }
          ]
        });
        rawOutput += `
=== LLM Analysis ===
${response.choices?.[0]?.message?.content || ""}
`;
      });
    } catch (err) {
      console.warn(`[TLSDeepScan] LLM analysis failed: ${err.message}`);
    }
  }
  const findings = generateFindings(protocols, cipherSuites, certificate, vulnerabilities, compression, secureRenegotiation);
  const gradeResult = calculateGradeScore(protocols, cipherSuites, certificate, vulnerabilities, compression, secureRenegotiation);
  const durationSeconds = (Date.now() - startTime) / 1e3;
  let scanId = null;
  try {
    const db = await getDb();
    const severitySummary = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length
    };
    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "tls-deep-scan",
      target: `${config.host}:${port}`,
      command: `tls-deep-scan ${config.host}:${port}`,
      rawOutput: rawOutput.slice(0, 5e5),
      rawStderr: null,
      exitCode: 0,
      durationMs: Math.round(durationSeconds * 1e3),
      timedOut: 0,
      findings: JSON.stringify({
        findings,
        protocols,
        cipherSuites,
        certificate,
        vulnerabilities,
        gradeScore: gradeResult.score,
        gradeLetter: gradeResult.letter
      }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null
    });
    scanId = inserted.insertId;
  } catch (dbErr) {
    console.error(`[TLSDeepScan] Failed to store scan result:`, dbErr.message);
  }
  console.log(`[TLSDeepScan] Scan complete: ${findings.length} findings, grade ${gradeResult.letter} (${gradeResult.score}/100) in ${durationSeconds.toFixed(1)}s`);
  return {
    scanId,
    status: "completed",
    host: config.host,
    port,
    protocols,
    cipherSuites,
    certificate,
    vulnerabilities,
    findings,
    stats: {
      totalFindings: findings.length,
      protocolsSupported: protocols.filter((p) => p.supported).length,
      ciphersFound: cipherSuites.length,
      weakCiphers: cipherSuites.filter((c) => c.grade === "weak" || c.grade === "insecure").length,
      vulnerabilitiesFound: vulnerabilities.filter((v) => v.affected).length,
      gradeScore: gradeResult.score,
      gradeLetter: gradeResult.letter,
      durationSeconds
    },
    rawOutput
  };
}

export {
  PROTOCOL_GRADES,
  WEAK_CIPHERS,
  STRONG_CIPHERS,
  TLS_VULNERABILITIES,
  parseScanForgeSSLEnum,
  parseOpenSSLOutput,
  gradeCipherSuite,
  validateCertificate,
  generateFindings,
  calculateGradeScore,
  startTLSDeepScan
};
