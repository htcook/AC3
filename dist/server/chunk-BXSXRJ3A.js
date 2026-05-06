import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-LCFOC34J.js";
import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import {
  init_schema,
  scanResults
} from "./chunk-IG2G4XDA.js";

// server/lib/scanners/ssh-audit-scanner.ts
init_scan_server_executor();
init_db();
init_schema();
var WEAK_KEX = {
  "diffie-hellman-group1-sha1": { grade: "critical", note: "1024-bit DH, vulnerable to Logjam (CVE-2015-4000)" },
  "diffie-hellman-group14-sha1": { grade: "weak", note: "SHA-1 based, deprecated" },
  "diffie-hellman-group-exchange-sha1": { grade: "weak", note: "SHA-1 based, deprecated" },
  "ecdh-sha2-nistp256": { grade: "acceptable", note: "NIST curve, potential NSA backdoor concerns" },
  "ecdh-sha2-nistp384": { grade: "acceptable", note: "NIST curve" },
  "ecdh-sha2-nistp521": { grade: "acceptable", note: "NIST curve" },
  "curve25519-sha256": { grade: "good", note: "Modern, recommended" },
  "curve25519-sha256@libssh.org": { grade: "good", note: "Modern, recommended" },
  "sntrup761x25519-sha512@openssh.com": { grade: "good", note: "Post-quantum hybrid" },
  "diffie-hellman-group16-sha512": { grade: "good", note: "4096-bit DH with SHA-512" },
  "diffie-hellman-group18-sha512": { grade: "good", note: "8192-bit DH with SHA-512" }
};
var WEAK_HOST_KEY = {
  "ssh-dss": { grade: "critical", note: "DSA keys are 1024-bit, deprecated in OpenSSH 7.0" },
  "ssh-rsa": { grade: "weak", note: "SHA-1 signature, deprecated in OpenSSH 8.8" },
  "rsa-sha2-256": { grade: "good", note: "RSA with SHA-256" },
  "rsa-sha2-512": { grade: "good", note: "RSA with SHA-512" },
  "ssh-ed25519": { grade: "good", note: "Modern EdDSA, recommended" },
  "ecdsa-sha2-nistp256": { grade: "acceptable", note: "NIST curve" },
  "sk-ssh-ed25519@openssh.com": { grade: "good", note: "FIDO/U2F hardware key" }
};
var WEAK_ENC = {
  "3des-cbc": { grade: "critical", note: "Sweet32 attack (CVE-2016-2183), 64-bit block cipher" },
  "blowfish-cbc": { grade: "critical", note: "64-bit block cipher, vulnerable to Sweet32" },
  "arcfour": { grade: "critical", note: "RC4 stream cipher, multiple known attacks" },
  "arcfour128": { grade: "critical", note: "RC4 stream cipher" },
  "arcfour256": { grade: "critical", note: "RC4 stream cipher" },
  "aes128-cbc": { grade: "weak", note: "CBC mode vulnerable to padding oracle attacks" },
  "aes192-cbc": { grade: "weak", note: "CBC mode vulnerable to padding oracle attacks" },
  "aes256-cbc": { grade: "weak", note: "CBC mode vulnerable to padding oracle attacks" },
  "aes128-ctr": { grade: "acceptable", note: "CTR mode, acceptable" },
  "aes256-ctr": { grade: "acceptable", note: "CTR mode, acceptable" },
  "aes128-gcm@openssh.com": { grade: "good", note: "AEAD, recommended" },
  "aes256-gcm@openssh.com": { grade: "good", note: "AEAD, recommended" },
  "chacha20-poly1305@openssh.com": { grade: "good", note: "AEAD, recommended" }
};
var WEAK_MAC = {
  "hmac-md5": { grade: "critical", note: "MD5 is broken, collision attacks" },
  "hmac-md5-96": { grade: "critical", note: "MD5 truncated, even weaker" },
  "hmac-sha1": { grade: "weak", note: "SHA-1 deprecated" },
  "hmac-sha1-96": { grade: "weak", note: "SHA-1 truncated" },
  "hmac-sha2-256": { grade: "good", note: "SHA-256 HMAC" },
  "hmac-sha2-512": { grade: "good", note: "SHA-512 HMAC" },
  "hmac-sha2-256-etm@openssh.com": { grade: "good", note: "Encrypt-then-MAC, recommended" },
  "hmac-sha2-512-etm@openssh.com": { grade: "good", note: "Encrypt-then-MAC, recommended" },
  "umac-128-etm@openssh.com": { grade: "good", note: "UMAC with ETM" }
};
var SSH_CVES = [
  {
    id: "CVE-2023-48795",
    description: "Terrapin Attack \u2014 prefix truncation attack on SSH Binary Packet Protocol, allows MITM to downgrade connection security",
    severity: "medium",
    affectedPattern: /OpenSSH[_ ](8\.[0-9]|9\.[0-5])/i,
    references: ["https://terrapin-attack.com", "https://nvd.nist.gov/vuln/detail/CVE-2023-48795"]
  },
  {
    id: "CVE-2024-6387",
    description: "regreSSHion \u2014 Remote unauthenticated code execution in OpenSSH server (sshd) via race condition in signal handler",
    severity: "critical",
    affectedPattern: /OpenSSH[_ ](8\.[5-9]|9\.[0-7])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"]
  },
  {
    id: "CVE-2023-38408",
    description: "OpenSSH ssh-agent remote code execution via PKCS#11 provider",
    severity: "high",
    affectedPattern: /OpenSSH[_ ](5\.|6\.|7\.|8\.[0-9]|9\.[0-3])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]
  },
  {
    id: "CVE-2021-41617",
    description: "OpenSSH privilege escalation via AuthorizedKeysCommand/AuthorizedPrincipalsCommand",
    severity: "high",
    affectedPattern: /OpenSSH[_ ](6\.2|6\.3|6\.4|6\.5|6\.6|6\.7|6\.8|6\.9|7\.|8\.[0-7])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41617"]
  },
  {
    id: "CVE-2020-15778",
    description: "OpenSSH scp command injection via filenames",
    severity: "medium",
    affectedPattern: /OpenSSH[_ ](8\.[0-3]|7\.|6\.|5\.)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-15778"]
  },
  {
    id: "CVE-2019-6111",
    description: "OpenSSH SCP client file overwrite vulnerability",
    severity: "medium",
    affectedPattern: /OpenSSH[_ ]([1-7]\.|8\.0)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-6111"]
  },
  {
    id: "CVE-2016-20012",
    description: "OpenSSH user enumeration via timing side-channel",
    severity: "medium",
    affectedPattern: /OpenSSH[_ ]([1-8]\.[0-9])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2016-20012"]
  }
];
function parseSSHAuditJSON(jsonStr) {
  const algorithms = [];
  const cves = [];
  let banner = null;
  let protocolVersion = null;
  let softwareVersion = null;
  try {
    const report = JSON.parse(jsonStr);
    banner = report.banner?.raw || null;
    protocolVersion = report.banner?.protocol ? String(report.banner.protocol) : null;
    softwareVersion = report.banner?.software || null;
    if (Array.isArray(report.kex)) {
      for (const item of report.kex) {
        const name = item.algorithm || item.name || item;
        const known = WEAK_KEX[name];
        algorithms.push({
          name,
          type: "kex",
          grade: known?.grade || "acceptable",
          notes: known?.note || item.notes || null,
          cve: null
        });
      }
    }
    if (Array.isArray(report.key)) {
      for (const item of report.key) {
        const name = item.algorithm || item.name || item;
        const known = WEAK_HOST_KEY[name];
        algorithms.push({
          name,
          type: "key",
          grade: known?.grade || "acceptable",
          notes: known?.note || item.notes || null,
          cve: null
        });
      }
    }
    if (Array.isArray(report.enc)) {
      for (const item of report.enc) {
        const name = item.algorithm || item.name || item;
        const known = WEAK_ENC[name];
        algorithms.push({
          name,
          type: "enc",
          grade: known?.grade || "acceptable",
          notes: known?.note || item.notes || null,
          cve: null
        });
      }
    }
    if (Array.isArray(report.mac)) {
      for (const item of report.mac) {
        const name = item.algorithm || item.name || item;
        const known = WEAK_MAC[name];
        algorithms.push({
          name,
          type: "mac",
          grade: known?.grade || "acceptable",
          notes: known?.note || item.notes || null,
          cve: null
        });
      }
    }
    if (Array.isArray(report.cves)) {
      for (const cve of report.cves) {
        cves.push({
          id: cve.name || cve.id || "",
          description: cve.description || "",
          severity: cve.severity === 10 ? "critical" : cve.severity >= 7 ? "high" : cve.severity >= 4 ? "medium" : "low",
          affectedVersions: cve.affected_versions || "",
          references: cve.references || []
        });
      }
    }
  } catch (err) {
    console.error("[SSHAudit] Failed to parse JSON:", err);
  }
  return { banner, protocolVersion, softwareVersion, algorithms, cves };
}
function parseSSHAuditText(output) {
  const algorithms = [];
  let banner = null;
  let softwareVersion = null;
  const bannerMatch = output.match(/banner:\s*(.+)/i);
  if (bannerMatch) banner = bannerMatch[1].trim();
  const swMatch = output.match(/software:\s*(.+)/i);
  if (swMatch) softwareVersion = swMatch[1].trim();
  const algoRegex = /\((\w+)\)\s+(\S+)\s+--\s+\[(\w+)\]\s*(.*)/gm;
  let match;
  while ((match = algoRegex.exec(output)) !== null) {
    const type = match[1];
    const name = match[2];
    const grade = match[3].toLowerCase();
    const notes = match[4]?.trim() || null;
    algorithms.push({
      name,
      type: ["kex", "key", "enc", "mac", "compression"].includes(type) ? type : "kex",
      grade: grade === "fail" ? "critical" : grade === "warn" ? "weak" : grade === "good" ? "good" : "acceptable",
      notes,
      cve: null
    });
  }
  return { banner, softwareVersion, algorithms };
}
function parseScanForgeSSHOutput(output) {
  const authMethods = [];
  const hostKeys = [];
  const algorithms = [];
  const authMatch = output.match(/ssh-auth-methods:[\s\S]*?Supported authentication methods:\s*(.+)/i);
  if (authMatch) {
    authMethods.push(...authMatch[1].split(",").map((m) => m.trim()));
  }
  const keyRegex = /ssh-hostkey:[\s\S]*?(\d+)\s+(\S+)\s+\((\w+)\)/gm;
  let match;
  while ((match = keyRegex.exec(output)) !== null) {
    hostKeys.push(`${match[3]}-${match[1]}`);
  }
  const algoSections = output.match(/ssh2-enum-algos:[\s\S]*?(?=\|_|$)/);
  if (algoSections) {
    const sectionRegex = /(kex_algorithms|server_host_key_algorithms|encryption_algorithms|mac_algorithms|compression_algorithms)[\s\S]*?((?:\|\s+\S+\n)+)/gm;
    let sMatch;
    while ((sMatch = sectionRegex.exec(algoSections[0])) !== null) {
      const typeMap = {
        kex_algorithms: "kex",
        server_host_key_algorithms: "key",
        encryption_algorithms: "enc",
        mac_algorithms: "mac",
        compression_algorithms: "compression"
      };
      const type = typeMap[sMatch[1]] || "kex";
      const algos = sMatch[2].match(/\|\s+(\S+)/g) || [];
      for (const a of algos) {
        const name = a.replace(/\|\s+/, "").trim();
        const lookupMap = type === "kex" ? WEAK_KEX : type === "key" ? WEAK_HOST_KEY : type === "enc" ? WEAK_ENC : type === "mac" ? WEAK_MAC : {};
        const known = lookupMap[name];
        algorithms.push({
          name,
          type,
          grade: known?.grade || "acceptable",
          notes: known?.note || null,
          cve: null
        });
      }
    }
  }
  return { authMethods, hostKeys, algorithms };
}
function generateFindings(algorithms, cves, banner, authMethods) {
  const findings = [];
  const weakAlgos = algorithms.filter((a) => a.grade === "weak" || a.grade === "critical");
  if (weakAlgos.length > 0) {
    const criticalAlgos = weakAlgos.filter((a) => a.grade === "critical");
    const weakOnly = weakAlgos.filter((a) => a.grade === "weak");
    if (criticalAlgos.length > 0) {
      findings.push({
        id: `ssh-critical-algos-${Date.now()}`,
        category: "algorithm",
        severity: "critical",
        title: "Critical SSH Algorithms Detected",
        description: `The SSH server supports ${criticalAlgos.length} critically weak algorithm(s): ${criticalAlgos.map((a) => `${a.name} (${a.notes})`).join(", ")}`,
        recommendation: "Disable all critically weak algorithms immediately. Remove 3DES-CBC, RC4/arcfour, MD5-based MACs, DSA keys, and DH group1.",
        cve: criticalAlgos.find((a) => a.cve)?.cve || null,
        cwe: "CWE-327",
        evidence: criticalAlgos.map((a) => `${a.type}: ${a.name}`).join("\n")
      });
    }
    if (weakOnly.length > 0) {
      findings.push({
        id: `ssh-weak-algos-${Date.now()}`,
        category: "algorithm",
        severity: "medium",
        title: "Weak SSH Algorithms Detected",
        description: `The SSH server supports ${weakOnly.length} deprecated/weak algorithm(s): ${weakOnly.map((a) => a.name).join(", ")}`,
        recommendation: "Disable SHA-1 based algorithms and CBC mode ciphers. Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305) and SHA-2 MACs.",
        cve: null,
        cwe: "CWE-327",
        evidence: weakOnly.map((a) => `${a.type}: ${a.name} \u2014 ${a.notes}`).join("\n")
      });
    }
  }
  for (const cve of cves) {
    findings.push({
      id: `ssh-cve-${cve.id}`,
      category: "cve",
      severity: cve.severity,
      title: `${cve.id}: ${cve.description.slice(0, 80)}`,
      description: cve.description,
      recommendation: "Update OpenSSH to the latest patched version.",
      cve: cve.id,
      cwe: null,
      evidence: `Affected versions: ${cve.affectedVersions}`
    });
  }
  if (banner) {
    for (const knownCve of SSH_CVES) {
      if (knownCve.affectedPattern.test(banner) && !cves.some((c) => c.id === knownCve.id)) {
        findings.push({
          id: `ssh-banner-cve-${knownCve.id}`,
          category: "cve",
          severity: knownCve.severity,
          title: `${knownCve.id}: ${knownCve.description.slice(0, 80)}`,
          description: knownCve.description,
          recommendation: "Update OpenSSH to the latest patched version.",
          cve: knownCve.id,
          cwe: null,
          evidence: `Banner: ${banner}`
        });
      }
    }
    findings.push({
      id: `ssh-banner-disclosure-${Date.now()}`,
      category: "banner",
      severity: "info",
      title: "SSH Banner Information Disclosure",
      description: `SSH server exposes version information: ${banner}`,
      recommendation: "Consider customizing the SSH banner to reduce information leakage.",
      cve: null,
      cwe: "CWE-200",
      evidence: banner
    });
  }
  if (authMethods.includes("password")) {
    findings.push({
      id: `ssh-password-auth-${Date.now()}`,
      category: "authentication",
      severity: "medium",
      title: "SSH Password Authentication Enabled",
      description: "The SSH server accepts password-based authentication, which is susceptible to brute-force attacks.",
      recommendation: "Disable password authentication and use key-based authentication only. Set PasswordAuthentication no in sshd_config.",
      cve: null,
      cwe: "CWE-307",
      evidence: `Auth methods: ${authMethods.join(", ")}`
    });
  }
  if (authMethods.includes("none")) {
    findings.push({
      id: `ssh-none-auth-${Date.now()}`,
      category: "authentication",
      severity: "critical",
      title: "SSH Allows Unauthenticated Access",
      description: "The SSH server accepts 'none' authentication, potentially allowing unauthenticated access.",
      recommendation: "Immediately disable 'none' authentication method.",
      cve: null,
      cwe: "CWE-287",
      evidence: `Auth methods: ${authMethods.join(", ")}`
    });
  }
  return findings;
}
async function startSSHAudit(config) {
  const startTime = Date.now();
  const port = config.port || 22;
  const timeout = config.timeoutSeconds || 60;
  const target = `${config.host}:${port}`;
  console.log(`[SSHAudit] Starting audit of ${target}`);
  let allAlgorithms = [];
  let allCves = [];
  let banner = null;
  let protocolVersion = null;
  let softwareVersion = null;
  let authMethods = [];
  let rawOutput = "";
  try {
    const sshAuditResult = await executeRawCommand(
      `ssh-audit -j ${config.host} -p ${port} 2>&1 || python3 -m ssh_audit ${config.host} -p ${port} -j 2>&1`,
      timeout
    );
    rawOutput += `=== ssh-audit ===
${sshAuditResult.stdout}
`;
    if (sshAuditResult.exitCode === 0 && sshAuditResult.stdout.trim().startsWith("{")) {
      const parsed = parseSSHAuditJSON(sshAuditResult.stdout);
      allAlgorithms = parsed.algorithms;
      allCves = parsed.cves;
      banner = parsed.banner;
      protocolVersion = parsed.protocolVersion;
      softwareVersion = parsed.softwareVersion;
    } else {
      const textParsed = parseSSHAuditText(sshAuditResult.stdout);
      allAlgorithms = textParsed.algorithms;
      banner = textParsed.banner;
      softwareVersion = textParsed.softwareVersion;
    }
  } catch (err) {
    console.warn(`[SSHAudit] ssh-audit failed: ${err.message}, falling back to banner grab`);
  }
  if (config.detectionTemplates !== false) {
    try {
      const discoveryResult = await executeTool({
        tool: "naabu",
        args: `-p ${port} --script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,sshv1 -sV ${config.host}`,
        target: config.host,
        timeoutSeconds: timeout,
        engagementId: config.engagementId
      });
      rawOutput += `
=== ScanForge discovery SSH scripts ===
${discoveryResult.stdout}
`;
      const discoveryParsed = parseScanForgeSSHOutput(discoveryResult.stdout);
      authMethods = discoveryParsed.authMethods;
      if (allAlgorithms.length === 0) {
        allAlgorithms = discoveryParsed.algorithms;
      }
      if (!banner) {
        const serviceBanner = discoveryResult.stdout.match(/SSH-\S+/);
        if (serviceBanner) banner = serviceBanner[0];
      }
      if (!softwareVersion) {
        const versionMatch = discoveryResult.stdout.match(/OpenSSH\s+[\d.p]+/i);
        if (versionMatch) softwareVersion = versionMatch[0];
      }
    } catch (err) {
      console.warn(`[SSHAudit] ScanForge discovery SSH scripts failed: ${err.message}`);
    }
  }
  if (config.enumAuth !== false && authMethods.length === 0) {
    try {
      const authResult = await executeRawCommand(
        `ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p ${port} test@${config.host} 2>&1 || true`,
        15
      );
      rawOutput += `
=== auth enum ===
${authResult.stdout}
${authResult.stderr}
`;
      const authMatch = (authResult.stdout + authResult.stderr).match(/authentication methods[:\s]+(.+)/i);
      if (authMatch) {
        authMethods = authMatch[1].split(",").map((m) => m.trim());
      }
    } catch {
    }
  }
  const findings = generateFindings(allAlgorithms, allCves, banner || softwareVersion, authMethods);
  let osGuess = null;
  if (banner || softwareVersion) {
    const bannerStr = banner || softwareVersion || "";
    if (bannerStr.includes("Ubuntu")) osGuess = "Ubuntu Linux";
    else if (bannerStr.includes("Debian")) osGuess = "Debian Linux";
    else if (bannerStr.includes("FreeBSD")) osGuess = "FreeBSD";
    else if (bannerStr.match(/RHEL|Red Hat|CentOS/i)) osGuess = "Red Hat / CentOS";
    else if (bannerStr.includes("Windows")) osGuess = "Windows";
  }
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
      tool: "ssh-audit",
      target,
      command: `ssh-audit ${config.host} -p ${port}`,
      rawOutput: rawOutput.slice(0, 5e5),
      rawStderr: null,
      exitCode: 0,
      durationMs: Math.round(durationSeconds * 1e3),
      timedOut: 0,
      findings: JSON.stringify({ findings, algorithms: allAlgorithms, cves: allCves, authMethods }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null
    });
    scanId = inserted.insertId;
  } catch (dbErr) {
    console.error(`[SSHAudit] Failed to store scan result:`, dbErr.message);
  }
  console.log(`[SSHAudit] Audit complete: ${findings.length} findings, ${allAlgorithms.length} algorithms, ${allCves.length} CVEs in ${durationSeconds.toFixed(1)}s`);
  return {
    scanId,
    status: "completed",
    host: config.host,
    port,
    banner,
    protocolVersion,
    softwareVersion,
    osGuess,
    algorithms: allAlgorithms,
    cves: allCves,
    findings,
    authMethods,
    stats: {
      weakAlgorithms: allAlgorithms.filter((a) => a.grade === "weak" || a.grade === "critical").length,
      criticalCves: allCves.filter((c) => c.severity === "critical").length,
      totalFindings: findings.length,
      durationSeconds
    },
    rawOutput
  };
}

export {
  startSSHAudit
};
