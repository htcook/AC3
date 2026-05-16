import {
  init_llm,
  invokeLLM
} from "./chunk-TCEHBLTC.js";
import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";

// server/lib/ioc-ttp-reverse-engineer.ts
init_llm();
init_db();
import { sql } from "drizzle-orm";
var PATTERN_RULES = [
  // ── Domain IOCs ──
  {
    iocType: "domain",
    valueMatcher: (v) => /^[a-z0-9]{12,}\.(top|xyz|tk|ml|ga|cf|gq|pw|cc|ws|info|click|link|online|site|space|fun|icu|buzz)$/i.test(v),
    techniques: [
      { id: "T1568.002", name: "Domain Generation Algorithms", tactic: "command-and-control", reasoning: "Long random string with cheap TLD indicates DGA-generated C2 domain", confidence: 80 },
      { id: "T1071.001", name: "Web Protocols", tactic: "command-and-control", reasoning: "Domain likely used for HTTP/HTTPS C2 communication", confidence: 70 }
    ]
  },
  {
    iocType: "domain",
    valueMatcher: (v) => /\.(duckdns|no-ip|dynu|freedns|afraid|changeip|ddns)\./i.test(v) || /\.ngrok\./i.test(v),
    techniques: [
      { id: "T1090.004", name: "Domain Fronting", tactic: "command-and-control", reasoning: "Dynamic DNS domain used for C2 infrastructure to evade IP-based blocking", confidence: 75 },
      { id: "T1583.001", name: "Domains", tactic: "resource-development", reasoning: "Free dynamic DNS service used to establish C2 infrastructure", confidence: 85 }
    ]
  },
  {
    iocType: "domain",
    valueMatcher: (v) => /\.(onion|i2p)$/i.test(v),
    techniques: [
      { id: "T1090.003", name: "Multi-hop Proxy", tactic: "command-and-control", reasoning: "Tor/I2P hidden service used for anonymized C2 communication", confidence: 90 },
      { id: "T1573.002", name: "Asymmetric Cryptography", tactic: "command-and-control", reasoning: "Tor/I2P provides encrypted communication channel", confidence: 85 }
    ]
  },
  {
    iocType: "domain",
    valueMatcher: (v) => /pastebin|paste\.ee|hastebin|ghostbin|rentry|dpaste|justpaste/i.test(v),
    techniques: [
      { id: "T1102.002", name: "Bidirectional Communication", tactic: "command-and-control", reasoning: "Paste site used as dead drop for C2 commands or exfiltrated data", confidence: 75 },
      { id: "T1567.002", name: "Exfiltration to Cloud Storage", tactic: "exfiltration", reasoning: "Paste site may be used to exfiltrate data", confidence: 60 }
    ]
  },
  {
    iocType: "domain",
    valueMatcher: (v) => /discord(app)?\.com|telegram\.org|slack\.com|teams\.microsoft/i.test(v),
    techniques: [
      { id: "T1102.002", name: "Bidirectional Communication", tactic: "command-and-control", reasoning: "Legitimate messaging platform abused for C2 communication", confidence: 70 },
      { id: "T1567", name: "Exfiltration Over Web Service", tactic: "exfiltration", reasoning: "Messaging platform may be used for data exfiltration via webhooks/bots", confidence: 65 }
    ]
  },
  // ── IP IOCs ──
  {
    iocType: "ip",
    valueMatcher: (v) => /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(v),
    techniques: [
      { id: "T1021", name: "Remote Services", tactic: "lateral-movement", reasoning: "Internal IP address indicates lateral movement within the network", confidence: 65 },
      { id: "T1046", name: "Network Service Discovery", tactic: "discovery", reasoning: "Internal IP may be a target of network scanning during discovery phase", confidence: 60 }
    ]
  },
  {
    iocType: "ip",
    valueMatcher: (v) => {
      const c2Patterns = /^(45\.33\.|45\.56\.|104\.131\.|159\.65\.|167\.71\.|68\.183\.|134\.209\.|64\.225\.|142\.93\.|157\.245\.)/;
      return c2Patterns.test(v);
    },
    techniques: [
      { id: "T1583.003", name: "Virtual Private Server", tactic: "resource-development", reasoning: "IP belongs to VPS provider commonly used for C2 infrastructure", confidence: 70 },
      { id: "T1071.001", name: "Web Protocols", tactic: "command-and-control", reasoning: "VPS IP likely hosting C2 server communicating over HTTP/HTTPS", confidence: 65 }
    ]
  },
  // ── URL IOCs ──
  {
    iocType: "url",
    valueMatcher: (v) => /\.(php|asp|aspx|jsp|cgi)\?[a-z]+=.{20,}/i.test(v),
    techniques: [
      { id: "T1059.007", name: "JavaScript", tactic: "execution", reasoning: "URL with long query parameter to server-side script suggests webshell or C2 callback", confidence: 65 },
      { id: "T1505.003", name: "Web Shell", tactic: "persistence", reasoning: "Server-side script URL with encoded parameters may be a webshell", confidence: 70 }
    ]
  },
  {
    iocType: "url",
    valueMatcher: (v) => /\/wp-(content|admin|includes)\/.*\.(php|txt)/i.test(v),
    techniques: [
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access", reasoning: "WordPress path suggests exploitation of CMS vulnerability", confidence: 75 },
      { id: "T1505.003", name: "Web Shell", tactic: "persistence", reasoning: "PHP file in WordPress directory may be a planted webshell", confidence: 70 }
    ]
  },
  {
    iocType: "url",
    valueMatcher: (v) => /base64|eval|exec|system|passthru|shell_exec|cmd\.exe|powershell/i.test(v),
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution", reasoning: "URL contains command execution indicators", confidence: 80 },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion", reasoning: "Base64 encoding in URL suggests obfuscated payload delivery", confidence: 75 }
    ]
  },
  // ── File Path IOCs ──
  {
    iocType: "file_path",
    valueMatcher: (v) => /\\(Temp|tmp|AppData\\Local\\Temp)/i.test(v),
    techniques: [
      { id: "T1074.001", name: "Local Data Staging", tactic: "collection", reasoning: "Temp directory used for staging malware or exfiltration data", confidence: 75 },
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution", reasoning: "Executable dropped in temp directory for execution", confidence: 70 }
    ]
  },
  {
    iocType: "file_path",
    valueMatcher: (v) => /\\(Startup|Start Menu\\Programs\\Startup)/i.test(v),
    techniques: [
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "persistence", reasoning: "File placed in Startup folder for persistence across reboots", confidence: 90 }
    ]
  },
  {
    iocType: "file_path",
    valueMatcher: (v) => /\\System32\\(drivers|Tasks|spool|wbem)/i.test(v),
    techniques: [
      { id: "T1036.005", name: "Match Legitimate Name or Location", tactic: "defense-evasion", reasoning: "Malware placed in System32 subdirectory to masquerade as legitimate system file", confidence: 80 },
      { id: "T1543.003", name: "Windows Service", tactic: "persistence", reasoning: "File in drivers/services directory may install as a service for persistence", confidence: 75 }
    ]
  },
  {
    iocType: "file_path",
    valueMatcher: (v) => /\.(ps1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta)$/i.test(v),
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution", reasoning: "Script file extension indicates scripting-based execution", confidence: 85 }
    ]
  },
  {
    iocType: "file_path",
    valueMatcher: (v) => /\/(\.ssh|\.gnupg|\.aws|\.config|\.local\/share)/i.test(v),
    techniques: [
      { id: "T1552.001", name: "Credentials In Files", tactic: "credential-access", reasoning: "Access to credential/config directories indicates credential harvesting", confidence: 80 },
      { id: "T1005", name: "Data from Local System", tactic: "collection", reasoning: "Sensitive configuration directories targeted for data collection", confidence: 75 }
    ]
  },
  // ── Registry Key IOCs ──
  {
    iocType: "registry_key",
    valueMatcher: (v) => /Run\b|RunOnce/i.test(v),
    techniques: [
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "persistence", reasoning: "Registry Run key used for persistence \u2014 executes on user login", confidence: 95 }
    ]
  },
  {
    iocType: "registry_key",
    valueMatcher: (v) => /Services\\/i.test(v),
    techniques: [
      { id: "T1543.003", name: "Windows Service", tactic: "persistence", reasoning: "Registry Services key modified to install malicious service", confidence: 85 }
    ]
  },
  {
    iocType: "registry_key",
    valueMatcher: (v) => /Image File Execution Options/i.test(v),
    techniques: [
      { id: "T1546.012", name: "Image File Execution Options Injection", tactic: "persistence", reasoning: "IFEO registry key used to hijack executable launch for persistence", confidence: 90 }
    ]
  },
  {
    iocType: "registry_key",
    valueMatcher: (v) => /AppInit_DLLs|InprocServer32|ShellIconOverlayIdentifiers/i.test(v),
    techniques: [
      { id: "T1546.010", name: "AppInit DLLs", tactic: "persistence", reasoning: "DLL injection via AppInit_DLLs or COM object hijacking for persistence", confidence: 85 },
      { id: "T1546.015", name: "Component Object Model Hijacking", tactic: "persistence", reasoning: "COM object registry key modified for DLL side-loading", confidence: 80 }
    ]
  },
  {
    iocType: "registry_key",
    valueMatcher: (v) => /DisableAntiSpyware|DisableRealtimeMonitoring|SubmitSamplesConsent/i.test(v),
    techniques: [
      { id: "T1562.001", name: "Disable or Modify Tools", tactic: "defense-evasion", reasoning: "Registry key used to disable Windows Defender or security tools", confidence: 95 }
    ]
  },
  // ── Mutex IOCs ──
  {
    iocType: "mutex",
    techniques: [
      { id: "T1106", name: "Native API", tactic: "execution", reasoning: "Mutex creation indicates malware using native API for instance checking", confidence: 70 },
      { id: "T1055", name: "Process Injection", tactic: "defense-evasion", reasoning: "Mutex may be used to coordinate injected processes", confidence: 55 }
    ]
  },
  // ── Hash IOCs ──
  {
    iocType: ["hash_md5", "hash_sha1", "hash_sha256"],
    techniques: [
      { id: "T1204.002", name: "Malicious File", tactic: "execution", reasoning: "File hash indicates known malicious binary \u2014 user execution or automated delivery", confidence: 75 },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion", reasoning: "Malware binary likely uses obfuscation/packing to evade detection", confidence: 65 }
    ]
  },
  // ── User Agent IOCs ──
  {
    iocType: "user_agent",
    valueMatcher: (v) => /python-requests|curl\/|wget\/|Go-http-client|Java\/|Apache-HttpClient/i.test(v),
    techniques: [
      { id: "T1071.001", name: "Web Protocols", tactic: "command-and-control", reasoning: "Non-browser user agent indicates automated C2 communication tool", confidence: 80 }
    ]
  },
  {
    iocType: "user_agent",
    valueMatcher: (v) => v.length < 20 || /^Mozilla\/4\.0/i.test(v),
    techniques: [
      { id: "T1071.001", name: "Web Protocols", tactic: "command-and-control", reasoning: "Unusual or outdated user agent string indicates malware C2 beacon", confidence: 70 },
      { id: "T1036", name: "Masquerading", tactic: "defense-evasion", reasoning: "Minimal user agent may attempt to blend with legitimate traffic", confidence: 60 }
    ]
  },
  // ── Email IOCs ──
  {
    iocType: "email",
    valueMatcher: (v) => /protonmail|tutanota|guerrillamail|tempmail|throwaway|yopmail/i.test(v),
    techniques: [
      { id: "T1585.002", name: "Email Accounts", tactic: "resource-development", reasoning: "Privacy-focused or disposable email used for actor infrastructure", confidence: 75 },
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access", reasoning: "Disposable email likely used as sender for phishing campaigns", confidence: 70 }
    ]
  },
  // ── Certificate IOCs ──
  {
    iocType: ["certificate_hash", "certificate_serial"],
    techniques: [
      { id: "T1553.002", name: "Code Signing", tactic: "defense-evasion", reasoning: "Certificate used to sign malicious code for trust bypass", confidence: 75 },
      { id: "T1588.003", name: "Code Signing Certificates", tactic: "resource-development", reasoning: "Actor obtained or stole code signing certificate", confidence: 80 }
    ]
  },
  // ── Scheduled Task / Cron IOCs ──
  {
    iocType: "file_path",
    valueMatcher: (v) => /schtasks|Task Scheduler|cron\.d|crontab|at\.allow/i.test(v),
    techniques: [
      { id: "T1053.005", name: "Scheduled Task", tactic: "persistence", reasoning: "Scheduled task or cron job used for persistence and recurring execution", confidence: 85 }
    ]
  },
  // ── PowerShell-related IOCs ──
  {
    iocType: ["file_path", "url"],
    valueMatcher: (v) => /powershell|pwsh|\.ps1|IEX|Invoke-Expression|downloadstring|EncodedCommand/i.test(v),
    techniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "execution", reasoning: "PowerShell indicators suggest script-based execution", confidence: 85 },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion", reasoning: "Encoded PowerShell commands indicate obfuscation", confidence: 80 }
    ]
  }
];
function matchPatterns(ioc) {
  const mappings = [];
  for (const rule of PATTERN_RULES) {
    const typeMatch = Array.isArray(rule.iocType) ? rule.iocType.includes(ioc.type) : rule.iocType === ioc.type;
    if (!typeMatch) continue;
    if (rule.pattern && !rule.pattern.test(ioc.value)) continue;
    if (rule.valueMatcher && !rule.valueMatcher(ioc.value)) continue;
    for (const tech of rule.techniques) {
      mappings.push({
        techniqueId: tech.id,
        techniqueName: tech.name,
        tactic: tech.tactic,
        reasoning: tech.reasoning,
        confidence: tech.confidence,
        derivationMethod: "pattern_match",
        context: { iocType: ioc.type, matchedRule: true }
      });
    }
  }
  return mappings;
}
async function analyzeWithLLM(ioc, existingMappings) {
  const existingContext = existingMappings.length > 0 ? `
Pattern matching already identified these techniques:
${existingMappings.map((m) => `- ${m.techniqueId} (${m.techniqueName}): ${m.reasoning}`).join("\n")}
Identify ADDITIONAL techniques not already covered.` : "";
  const actorContext = ioc.actorId ? `
This IOC is attributed to threat actor: ${ioc.actorName || ioc.actorId}. Consider this actor's known TTPs when analyzing.` : "";
  const prompt = `You are a senior threat intelligence analyst specializing in IOC-to-TTP reverse engineering.

Analyze this Indicator of Compromise and identify the MITRE ATT&CK techniques it implies:

IOC Type: ${ioc.type}
IOC Value: ${ioc.value}
${ioc.description ? `Description: ${ioc.description}` : ""}${actorContext}${existingContext}

For each technique, explain:
1. The specific technique ID (e.g., T1059.001)
2. The technique name
3. The tactic it belongs to
4. Your reasoning for why this IOC implies this technique
5. Your confidence level (0-100)

Think about:
- What capability does this IOC reveal about the actor?
- What phase of the kill chain does this IOC belong to?
- What tools or methods would produce this IOC?
- What does the infrastructure pattern tell us about the actor's operational security?`;
  try {
    const response = await invokeLLM({
      _caller: "ioc-ttp-reverse-engineer:analyzeWithLLM",
      messages: [
        { role: "system", content: "You are a MITRE ATT&CK mapping specialist. Return structured JSON only." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "ioc_ttp_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              techniques: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    techniqueId: { type: "string", description: "MITRE ATT&CK technique ID" },
                    techniqueName: { type: "string", description: "Technique name" },
                    tactic: { type: "string", description: "Kill chain tactic" },
                    reasoning: { type: "string", description: "Why this IOC implies this technique" },
                    confidence: { type: "number", description: "Confidence 0-100" }
                  },
                  required: ["techniqueId", "techniqueName", "tactic", "reasoning", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["techniques"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    const parsed = JSON.parse(content);
    return (parsed.techniques || []).map((t) => ({
      techniqueId: t.techniqueId,
      techniqueName: t.techniqueName,
      tactic: t.tactic,
      reasoning: t.reasoning,
      confidence: Math.min(100, Math.max(0, t.confidence)),
      derivationMethod: "llm_analysis",
      context: { iocType: ioc.type, llmDerived: true }
    }));
  } catch (err) {
    console.error("[IOC-TTP] LLM analysis failed:", err);
    return [];
  }
}
async function persistMappings(ioc, mappings) {
  const db = await getDb();
  if (!db || mappings.length === 0) return;
  for (const m of mappings) {
    try {
      await db.execute(sql`
        INSERT INTO ioc_ttp_mappings (
          itm_ioc_type, itm_ioc_value, itm_ioc_description, itm_source_ioc_id,
          itm_actor_id, itm_actor_name,
          itm_technique_id, itm_technique_name, itm_tactic,
          itm_reasoning, itm_inference_confidence, itm_derivation_method,
          itm_context
        ) VALUES (
          ${ioc.type}, ${ioc.value}, ${ioc.description || null}, ${ioc.sourceIocId || null},
          ${ioc.actorId || null}, ${ioc.actorName || null},
          ${m.techniqueId}, ${m.techniqueName}, ${m.tactic},
          ${m.reasoning}, ${m.confidence}, ${m.derivationMethod},
          ${JSON.stringify(m.context || {})}
        )
      `);
    } catch (err) {
      console.error(`[IOC-TTP] Failed to persist mapping ${m.techniqueId}:`, err);
    }
  }
}
async function reverseEngineerIoc(ioc, options) {
  const { skipLLM = false, persist = true } = options || {};
  const patternMappings = matchPatterns(ioc);
  let llmMappings = [];
  if (!skipLLM) {
    llmMappings = await analyzeWithLLM(ioc, patternMappings);
  }
  const allMappings = [...patternMappings, ...llmMappings];
  const deduped = /* @__PURE__ */ new Map();
  for (const m of allMappings) {
    const existing = deduped.get(m.techniqueId);
    if (!existing || m.confidence > existing.confidence) {
      deduped.set(m.techniqueId, m);
    }
  }
  const finalMappings = Array.from(deduped.values());
  if (persist) {
    await persistMappings(ioc, finalMappings);
  }
  return {
    ioc,
    mappings: finalMappings,
    enriched: finalMappings.length > 0
  };
}
async function batchReverseEngineerIocs(iocs, options) {
  const { skipLLM = false, persist = true, concurrency = 3 } = options || {};
  const results = [];
  for (let i = 0; i < iocs.length; i += concurrency) {
    const batch = iocs.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map((ioc) => reverseEngineerIoc(ioc, { skipLLM, persist }))
    );
    results.push(...batchResults);
  }
  return results;
}
async function reverseEngineerActorIocs(actorId, options) {
  const db = await getDb();
  if (!db) return { actorId, totalIocs: 0, totalMappings: 0, results: [] };
  const { skipLLM = false, limit = 100 } = options || {};
  const iocRows = await db.execute(sql`
    SELECT id, iocType, iocValue, description, actorId
    FROM threat_actor_iocs
    WHERE actorId = ${actorId}
    ORDER BY id DESC
    LIMIT ${limit}
  `);
  const rows = iocRows[0] || [];
  if (rows.length === 0) return { actorId, totalIocs: 0, totalMappings: 0, results: [] };
  const actorRows = await db.execute(sql`
    SELECT name FROM threat_actors WHERE actorId = ${actorId} LIMIT 1
  `);
  const actorName = actorRows[0]?.[0]?.name || actorId;
  const iocs = rows.map((r) => ({
    type: r.iocType || "unknown",
    value: r.iocValue || "",
    description: r.description || void 0,
    actorId,
    actorName,
    sourceIocId: r.id
  }));
  const results = await batchReverseEngineerIocs(iocs, { skipLLM, persist: true });
  const totalMappings = results.reduce((sum, r) => sum + r.mappings.length, 0);
  return { actorId, totalIocs: rows.length, totalMappings, results };
}
async function getActorsByTechnique(techniqueId) {
  const db = await getDb();
  if (!db) return [];
  const rows = await db.execute(sql`
    SELECT itm_actor_id, itm_actor_name, itm_inference_confidence, itm_reasoning, itm_ioc_type
    FROM ioc_ttp_mappings
    WHERE itm_technique_id = ${techniqueId} AND itm_actor_id IS NOT NULL
    ORDER BY itm_inference_confidence DESC
  `);
  return (rows[0] || []).map((r) => ({
    actorId: r.itm_actor_id,
    actorName: r.itm_actor_name,
    confidence: r.itm_inference_confidence,
    reasoning: r.itm_reasoning,
    iocType: r.itm_ioc_type
  }));
}
async function buildIocDerivedTtpContext(actorId) {
  const db = await getDb();
  if (!db) return "";
  const rows = await db.execute(sql`
    SELECT itm_technique_id, itm_technique_name, itm_tactic, itm_reasoning,
           itm_inference_confidence, itm_ioc_type, itm_derivation_method
    FROM ioc_ttp_mappings
    WHERE itm_actor_id = ${actorId}
    ORDER BY itm_inference_confidence DESC
    LIMIT 30
  `);
  const mappings = rows[0] || [];
  if (mappings.length === 0) return "";
  const byTactic = /* @__PURE__ */ new Map();
  for (const m of mappings) {
    const tactic = m.itm_tactic || "unknown";
    if (!byTactic.has(tactic)) byTactic.set(tactic, []);
    byTactic.get(tactic).push(m);
  }
  let context = `## IOC-Derived TTP Intelligence for ${actorId}
`;
  context += `Based on reverse-engineering ${mappings.length} IOC-to-TTP mappings:

`;
  for (const [tactic, techs] of byTactic) {
    context += `### ${tactic}
`;
    for (const t of techs) {
      context += `- ${t.itm_technique_id} (${t.itm_technique_name}) [${t.itm_inference_confidence}% confidence]
`;
      context += `  Evidence: ${t.itm_reasoning}
`;
      context += `  Source: ${t.itm_derivation_method} from ${t.itm_ioc_type} IOC
`;
    }
    context += "\n";
  }
  return context;
}
async function getIocTtpStats() {
  const db = await getDb();
  if (!db) return { totalMappings: 0, byDerivationMethod: {}, byTactic: {}, topTechniques: [], actorsWithMappings: 0 };
  const [totalRows] = await db.execute(sql`SELECT COUNT(*) as cnt FROM ioc_ttp_mappings`);
  const total = totalRows?.[0]?.cnt || 0;
  const [methodRows] = await db.execute(sql`
    SELECT itm_derivation_method, COUNT(*) as cnt FROM ioc_ttp_mappings GROUP BY itm_derivation_method
  `);
  const byMethod = {};
  for (const r of methodRows || []) {
    byMethod[r.itm_derivation_method] = r.cnt;
  }
  const [tacticRows] = await db.execute(sql`
    SELECT itm_tactic, COUNT(*) as cnt FROM ioc_ttp_mappings GROUP BY itm_tactic ORDER BY cnt DESC
  `);
  const byTactic = {};
  for (const r of tacticRows || []) {
    byTactic[r.itm_tactic] = r.cnt;
  }
  const [techRows] = await db.execute(sql`
    SELECT itm_technique_id, itm_technique_name, COUNT(*) as cnt
    FROM ioc_ttp_mappings GROUP BY itm_technique_id, itm_technique_name ORDER BY cnt DESC LIMIT 10
  `);
  const topTechniques = (techRows || []).map((r) => ({
    id: r.itm_technique_id,
    name: r.itm_technique_name,
    count: r.cnt
  }));
  const [actorRows] = await db.execute(sql`
    SELECT COUNT(DISTINCT itm_actor_id) as cnt FROM ioc_ttp_mappings WHERE itm_actor_id IS NOT NULL
  `);
  const actorsWithMappings = actorRows?.[0]?.cnt || 0;
  return { totalMappings: total, byDerivationMethod: byMethod, byTactic, topTechniques, actorsWithMappings };
}

export {
  reverseEngineerIoc,
  batchReverseEngineerIocs,
  reverseEngineerActorIocs,
  getActorsByTechnique,
  buildIocDerivedTtpContext,
  getIocTtpStats
};
