import {
  buildCalderaAbility,
  buildEdbCveIndex,
  buildMsfCveIndex,
  init_exploit_matcher,
  loadExploitDatabases,
  mapCveToTechnique,
  rankToLabel
} from "./chunk-H3M2JOYG.js";
import {
  PHISHING_EXPLOITS,
  init_phishing_exploits
} from "./chunk-QMJ22FU6.js";
import {
  generateAgentStagers
} from "./chunk-TNB3JNVK.js";
import {
  getDbRequired,
  init_db
} from "./chunk-CEPCIPS7.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  init_schema,
  unifiedExploitCatalog
} from "./chunk-TAIMCRAB.js";

// server/lib/exploit-catalog.ts
init_db();
init_schema();
init_phishing_exploits();
init_exploit_matcher();
import { eq, sql, and, inArray } from "drizzle-orm";
init_env();
function phishingToCatalogEntry(exploit, calderaUrl) {
  const catalogId = `phish:${exploit.id}`;
  const calderaAbility = {
    ability_id: `phish-${exploit.id}`,
    name: `[Phishing] ${exploit.name}`,
    description: exploit.description,
    tactic: exploit.mitreTactic.toLowerCase().replace(/\s+/g, "-"),
    technique_id: exploit.mitreId,
    technique_name: exploit.mitreName,
    executors: [],
    singleton: false,
    repeatable: true
  };
  if (exploit.landingPageCode) {
    calderaAbility.executors.push({
      name: "psh",
      platform: "windows",
      command: `# Phishing Landing Page Exploit: ${exploit.name}
# Deploy via GoPhish landing page injection
# MITRE: ${exploit.mitreId} - ${exploit.mitreName}
Write-Host "Phishing exploit ${exploit.id} requires GoPhish integration"`,
      cleanup: "",
      timeout: 60
    });
  }
  if (exploit.emailTemplateCode) {
    calderaAbility.executors.push({
      name: "sh",
      platform: "linux",
      command: `# Phishing Email Exploit: ${exploit.name}
# Deploy via GoPhish email template
# MITRE: ${exploit.mitreId} - ${exploit.mitreName}
echo "Phishing exploit ${exploit.id} requires GoPhish integration"`,
      cleanup: "",
      timeout: 60
    });
  }
  let stagerType = null;
  let stagerCommand = null;
  let callbackUrl = null;
  if (exploit.enablesRemoteAccess && calderaUrl) {
    const stagers = generateAgentStagers(calderaUrl);
    const windowsStager = stagers.find((s) => s.platform === "windows" && s.type === "sandcat");
    if (windowsStager) {
      stagerType = "sandcat";
      stagerCommand = windowsStager.command;
      callbackUrl = windowsStager.callbackUrl;
    }
  }
  return {
    catalogId,
    name: exploit.name,
    description: exploit.description,
    tier: "initial_access",
    category: exploit.category,
    source: "phishing_library",
    cveIds: JSON.stringify([]),
    cvssScore: null,
    severity: null,
    mitreId: exploit.mitreId,
    mitreName: exploit.mitreName,
    mitreTactic: exploit.mitreTactic,
    platform: "multi",
    exploitType: "phishing",
    reliability: exploit.effectiveness >= 8 ? "excellent" : exploit.effectiveness >= 6 ? "good" : "normal",
    difficulty: exploit.difficulty,
    effectiveness: exploit.effectiveness,
    msfModule: null,
    msfRank: null,
    edbId: null,
    edbUrl: null,
    phishingExploitId: exploit.id,
    calderaAbilityId: calderaAbility.ability_id,
    calderaAbilityPayload: calderaAbility,
    calderaSynced: false,
    calderaSyncedAt: null,
    agentStagerType: stagerType,
    agentStagerCommand: stagerCommand,
    agentStagerPayload: null,
    agentCallbackUrl: callbackUrl,
    landingPageCode: exploit.landingPageCode || null,
    emailTemplateCode: exploit.emailTemplateCode || null,
    tags: JSON.stringify(exploit.tags),
    detectionIndicators: JSON.stringify(exploit.detectionIndicators),
    prerequisites: JSON.stringify(exploit.prerequisites),
    verified: true,
    lastVerifiedAt: null,
    enabled: true,
    author: "AceofCloud Phishing Library",
    datePublished: null
  };
}
function msfModuleToCatalogEntry(module, cveId, calderaUrl) {
  const catalogId = `msf:${module.fullname}`;
  let platform = "multi";
  if (module.fullname.includes("/windows/")) platform = "windows";
  else if (module.fullname.includes("/linux/")) platform = "linux";
  else if (module.fullname.includes("/osx/") || module.fullname.includes("/apple_ios/")) platform = "darwin";
  else if (module.fullname.includes("/unix/")) platform = "linux";
  else if (module.fullname.includes("/multi/")) platform = "multi";
  let exploitType = "remote";
  if (module.fullname.includes("local/")) exploitType = "local";
  else if (module.fullname.includes("webapps/") || module.fullname.includes("/webapp/")) exploitType = "webapps";
  else if (module.fullname.includes("dos/")) exploitType = "dos";
  const rankStr = typeof module.rank === "number" ? rankToLabel(module.rank) : module.rank;
  const rankMap = {
    excellent: "excellent",
    great: "great",
    good: "good",
    normal: "normal",
    average: "average",
    low: "low",
    manual: "low"
  };
  const reliability = rankMap[rankStr] || "normal";
  const effectivenessMap = {
    excellent: 10,
    great: 9,
    good: 8,
    normal: 7,
    average: 5,
    low: 3,
    manual: 2
  };
  const effectiveness = effectivenessMap[rankStr] || 5;
  const technique = mapCveToTechnique(module.name, module.fullname, exploitType);
  const calderaAbility = buildCalderaAbility(cveId, {
    source: "metasploit",
    name: module.name,
    description: module.description || module.name,
    platform,
    reliability,
    command: module.fullname,
    isRemote: exploitType === "remote" || exploitType === "webapps"
  }, technique, module.name);
  let stagerType = null;
  let stagerCommand = null;
  let callbackUrl = null;
  if ((exploitType === "remote" || exploitType === "webapps") && calderaUrl) {
    const stagers = generateAgentStagers(calderaUrl);
    const stager = stagers.find((s) => s.platform === (platform === "multi" ? "linux" : platform) && s.type === "sandcat");
    if (stager) {
      stagerType = "sandcat";
      stagerCommand = stager.command;
      callbackUrl = stager.callbackUrl;
    }
  }
  return {
    catalogId,
    name: module.name,
    description: module.description || `Metasploit module: ${module.fullname}`,
    tier: "initial_access",
    category: exploitType === "local" ? "privesc" : "rce",
    source: "metasploit",
    cveIds: JSON.stringify([cveId]),
    cvssScore: null,
    severity: effectiveness >= 8 ? "critical" : effectiveness >= 6 ? "high" : "medium",
    mitreId: technique.id,
    mitreName: technique.name,
    mitreTactic: technique.tactic,
    platform,
    exploitType,
    reliability,
    difficulty: effectiveness >= 8 ? "basic" : effectiveness >= 6 ? "intermediate" : "advanced",
    effectiveness,
    msfModule: module.fullname,
    msfRank: effectivenessMap[rankStr] || 5,
    edbId: null,
    edbUrl: null,
    phishingExploitId: null,
    calderaAbilityId: calderaAbility.ability_id,
    calderaAbilityPayload: calderaAbility,
    calderaSynced: false,
    calderaSyncedAt: null,
    agentStagerType: stagerType,
    agentStagerCommand: stagerCommand,
    agentStagerPayload: null,
    agentCallbackUrl: callbackUrl,
    landingPageCode: null,
    emailTemplateCode: null,
    tags: JSON.stringify([cveId, module.rank, platform, exploitType]),
    detectionIndicators: JSON.stringify([
      `Metasploit ${module.fullname} execution`,
      `Network traffic to ${platform} target on exploit port`,
      `Payload delivery via ${exploitType} vector`
    ]),
    prerequisites: JSON.stringify([
      `Target vulnerable to ${cveId}`,
      `Network access to target service`,
      exploitType === "local" ? "Local access to target system" : "Remote network access"
    ]),
    verified: true,
    lastVerifiedAt: null,
    enabled: true,
    author: module.fullname.split("/").slice(0, 3).join("/"),
    datePublished: module.disclosuredate || null
  };
}
function edbToCatalogEntry(entry, cveId) {
  const catalogId = `edb:${entry.exploitId}`;
  const exploitDbUrl = `https://www.exploit-db.com/exploits/${entry.exploitId}`;
  const technique = mapCveToTechnique(entry.description, "", entry.type);
  const calderaAbility = buildCalderaAbility(cveId, {
    source: "exploitdb",
    name: entry.description,
    description: entry.description,
    platform: entry.platform,
    reliability: "normal",
    command: exploitDbUrl,
    isRemote: entry.type === "remote" || entry.type === "webapps"
  }, technique, entry.description);
  return {
    catalogId,
    name: entry.description,
    description: `ExploitDB #${entry.exploitId}: ${entry.description}`,
    tier: "initial_access",
    category: entry.type === "local" ? "privesc" : entry.type === "dos" ? "dos" : "rce",
    source: "exploitdb",
    cveIds: JSON.stringify([cveId]),
    cvssScore: null,
    severity: null,
    mitreId: technique.id,
    mitreName: technique.name,
    mitreTactic: technique.tactic,
    platform: entry.platform || "multi",
    exploitType: entry.type,
    reliability: "normal",
    difficulty: "intermediate",
    effectiveness: entry.type === "remote" ? 7 : entry.type === "webapps" ? 6 : 5,
    msfModule: null,
    msfRank: null,
    edbId: entry.exploitId,
    edbUrl: exploitDbUrl,
    phishingExploitId: null,
    calderaAbilityId: calderaAbility.ability_id,
    calderaAbilityPayload: calderaAbility,
    calderaSynced: false,
    calderaSyncedAt: null,
    agentStagerType: null,
    agentStagerCommand: null,
    agentStagerPayload: null,
    agentCallbackUrl: null,
    landingPageCode: null,
    emailTemplateCode: null,
    tags: JSON.stringify([cveId, entry.type, entry.platform]),
    detectionIndicators: JSON.stringify([
      `Exploit matching ExploitDB #${entry.exploitId}`,
      `${entry.type} attack vector against ${entry.platform}`
    ]),
    prerequisites: JSON.stringify([
      `Target vulnerable to ${cveId}`,
      entry.type === "local" ? "Local access required" : "Remote network access"
    ]),
    verified: false,
    lastVerifiedAt: null,
    enabled: true,
    author: "ExploitDB",
    datePublished: entry.datePublished || null
  };
}
function calderaAbilityToCatalogEntry(ability) {
  const catalogId = `caldera:${ability.ability_id}`;
  const platforms = (ability.executors || []).map((e) => e.platform).filter(Boolean);
  const platform = platforms.length === 1 ? platforms[0] : "multi";
  const tacticCategoryMap = {
    "initial-access": "rce",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privesc",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "command-and-control": "c2",
    "impact": "impact"
  };
  const category = tacticCategoryMap[ability.tactic] || "other";
  return {
    catalogId,
    name: ability.name,
    description: ability.description || ability.name,
    tier: ability.tactic === "initial-access" ? "initial_access" : "post_access",
    category,
    source: "caldera_stockpile",
    cveIds: JSON.stringify([]),
    cvssScore: null,
    severity: null,
    mitreId: ability.technique_id || null,
    mitreName: ability.technique_name || null,
    mitreTactic: ability.tactic || null,
    platform,
    exploitType: ability.tactic === "initial-access" ? "remote" : "local",
    reliability: "good",
    difficulty: ability.privilege ? "advanced" : "intermediate",
    effectiveness: 7,
    msfModule: null,
    msfRank: null,
    edbId: null,
    edbUrl: null,
    phishingExploitId: null,
    calderaAbilityId: ability.ability_id,
    calderaAbilityPayload: ability,
    calderaSynced: true,
    calderaSyncedAt: /* @__PURE__ */ new Date(),
    agentStagerType: null,
    agentStagerCommand: null,
    agentStagerPayload: null,
    agentCallbackUrl: null,
    landingPageCode: null,
    emailTemplateCode: null,
    tags: JSON.stringify([ability.tactic, ability.technique_id, platform, ability.plugin || "stockpile"].filter(Boolean)),
    detectionIndicators: JSON.stringify([]),
    prerequisites: JSON.stringify(ability.privilege ? [`Requires ${ability.privilege} privilege`] : []),
    verified: true,
    lastVerifiedAt: /* @__PURE__ */ new Date(),
    enabled: true,
    author: ability.plugin || "caldera",
    datePublished: null
  };
}
async function runEnrichmentPipeline(calderaUrl) {
  const result = {
    totalProcessed: 0,
    phishingAdded: 0,
    metasploitAdded: 0,
    exploitDbAdded: 0,
    calderaStockpileAdded: 0,
    duplicatesSkipped: 0,
    errors: []
  };
  const effectiveCalderaUrl = calderaUrl || ENV.calderaBaseUrl || "";
  const dbConn = await getDbRequired();
  const existing = await dbConn.select({ catalogId: unifiedExploitCatalog.catalogId }).from(unifiedExploitCatalog);
  const existingIds = new Set(existing.map((e) => e.catalogId));
  console.log("[ExploitCatalog] Processing phishing exploits...");
  for (const exploit of PHISHING_EXPLOITS) {
    const entry = phishingToCatalogEntry(exploit, effectiveCalderaUrl);
    result.totalProcessed++;
    if (existingIds.has(entry.catalogId)) {
      result.duplicatesSkipped++;
      try {
        await dbConn.update(unifiedExploitCatalog).set({
          name: entry.name,
          description: entry.description,
          calderaAbilityPayload: entry.calderaAbilityPayload,
          agentStagerCommand: entry.agentStagerCommand,
          agentCallbackUrl: entry.agentCallbackUrl,
          tags: entry.tags,
          detectionIndicators: entry.detectionIndicators
        }).where(eq(unifiedExploitCatalog.catalogId, entry.catalogId));
      } catch (err) {
        result.errors.push(`Update phishing ${exploit.id}: ${err.message}`);
      }
      continue;
    }
    try {
      await dbConn.insert(unifiedExploitCatalog).values(entry);
      result.phishingAdded++;
      existingIds.add(entry.catalogId);
    } catch (err) {
      result.errors.push(`Insert phishing ${exploit.id}: ${err.message}`);
    }
  }
  console.log("[ExploitCatalog] Loading exploit databases...");
  try {
    const cachedData = await loadExploitDatabases();
    const msfIndex = buildMsfCveIndex(cachedData.metasploitExploits);
    const edbIndex = buildEdbCveIndex(cachedData.exploitDbEntries);
    console.log(`[ExploitCatalog] Processing ${msfIndex.size} CVE-linked Metasploit modules...`);
    for (const [cveId, modules] of Array.from(msfIndex.entries())) {
      for (const mod of modules) {
        const entry = msfModuleToCatalogEntry(mod, cveId, effectiveCalderaUrl);
        result.totalProcessed++;
        if (existingIds.has(entry.catalogId)) {
          result.duplicatesSkipped++;
          continue;
        }
        try {
          await dbConn.insert(unifiedExploitCatalog).values(entry);
          result.metasploitAdded++;
          existingIds.add(entry.catalogId);
        } catch (err) {
          result.errors.push(`Insert MSF ${mod.fullname}: ${err.message}`);
        }
      }
    }
    console.log(`[ExploitCatalog] Processing ${edbIndex.size} CVE-linked ExploitDB entries...`);
    const edbBatch = [];
    const BATCH_SIZE = 100;
    let edbProcessed = 0;
    for (const [cveId, entries] of Array.from(edbIndex.entries())) {
      for (const entry of entries) {
        const catalogEntry = edbToCatalogEntry(entry, cveId);
        result.totalProcessed++;
        if (existingIds.has(catalogEntry.catalogId)) {
          result.duplicatesSkipped++;
          continue;
        }
        edbBatch.push(catalogEntry);
        existingIds.add(catalogEntry.catalogId);
        if (edbBatch.length >= BATCH_SIZE) {
          try {
            await dbConn.insert(unifiedExploitCatalog).values(edbBatch).onDuplicateKeyUpdate({ set: { catalogId: sql`catalog_id` } });
            result.exploitDbAdded += edbBatch.length;
          } catch (err) {
            for (const item of edbBatch) {
              try {
                await dbConn.insert(unifiedExploitCatalog).values(item).onDuplicateKeyUpdate({ set: { catalogId: sql`catalog_id` } });
                result.exploitDbAdded++;
              } catch (innerErr) {
                result.errors.push(`Insert EDB ${item.edbId}: ${innerErr.message}`);
              }
            }
          }
          edbProcessed += edbBatch.length;
          if (edbProcessed % 5e3 === 0) {
            console.log(`[ExploitCatalog] ExploitDB progress: ${edbProcessed} entries processed...`);
          }
          edbBatch.length = 0;
        }
      }
    }
    if (edbBatch.length > 0) {
      try {
        await dbConn.insert(unifiedExploitCatalog).values(edbBatch).onDuplicateKeyUpdate({ set: { catalogId: sql`catalog_id` } });
        result.exploitDbAdded += edbBatch.length;
      } catch (err) {
        for (const item of edbBatch) {
          try {
            await dbConn.insert(unifiedExploitCatalog).values(item).onDuplicateKeyUpdate({ set: { catalogId: sql`catalog_id` } });
            result.exploitDbAdded++;
          } catch (innerErr) {
            result.errors.push(`Insert EDB ${item.edbId}: ${innerErr.message}`);
          }
        }
      }
    }
    console.log(`[ExploitCatalog] ExploitDB complete: ${result.exploitDbAdded} added`);
  } catch (err) {
    result.errors.push(`Exploit database loading: ${err.message}`);
  }
  if (ENV.calderaBaseUrl && ENV.calderaApiKey) {
    console.log("[ExploitCatalog] Fetching Caldera stockpile abilities...");
    try {
      const resp = await fetch(`${ENV.calderaBaseUrl}/api/v2/abilities`, {
        headers: { KEY: ENV.calderaApiKey },
        signal: AbortSignal.timeout(3e4)
      });
      if (resp.ok) {
        const abilities = await resp.json();
        console.log(`[ExploitCatalog] Processing ${abilities.length} emulation abilities...`);
        for (const ability of abilities) {
          const entry = calderaAbilityToCatalogEntry(ability);
          result.totalProcessed++;
          if (existingIds.has(entry.catalogId)) {
            result.duplicatesSkipped++;
            continue;
          }
          try {
            await dbConn.insert(unifiedExploitCatalog).values(entry);
            result.calderaStockpileAdded++;
            existingIds.add(entry.catalogId);
          } catch (err) {
            result.errors.push(`Insert Caldera ${ability.ability_id}: ${err.message}`);
          }
        }
      }
    } catch (err) {
      result.errors.push(`Caldera stockpile fetch: ${err.message}`);
    }
  }
  console.log(`[ExploitCatalog] Enrichment complete: ${result.totalProcessed} processed, ${result.phishingAdded + result.metasploitAdded + result.exploitDbAdded + result.calderaStockpileAdded} added, ${result.duplicatesSkipped} skipped, ${result.errors.length} errors`);
  return result;
}
async function getCatalogStats() {
  const dbConn = await getDbRequired();
  const all = await dbConn.select({
    tier: unifiedExploitCatalog.tier,
    source: unifiedExploitCatalog.exploitSource,
    category: unifiedExploitCatalog.exploitCategory,
    calderaSynced: unifiedExploitCatalog.calderaSynced,
    agentStagerType: unifiedExploitCatalog.agentStagerType
  }).from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.exploitEnabled, true));
  const stats = {
    total: all.length,
    byTier: { initial_access: 0, post_access: 0 },
    bySource: {},
    byCategory: {},
    calderaSynced: 0,
    withStagers: 0
  };
  for (const row of all) {
    if (row.tier === "initial_access") stats.byTier.initial_access++;
    else stats.byTier.post_access++;
    stats.bySource[row.source] = (stats.bySource[row.source] || 0) + 1;
    stats.byCategory[row.category] = (stats.byCategory[row.category] || 0) + 1;
    if (row.calderaSynced) stats.calderaSynced++;
    if (row.agentStagerType) stats.withStagers++;
  }
  return stats;
}
async function searchCatalog(params) {
  const conditions = [eq(unifiedExploitCatalog.exploitEnabled, true)];
  if (params.tier) conditions.push(eq(unifiedExploitCatalog.tier, params.tier));
  if (params.source) conditions.push(eq(unifiedExploitCatalog.exploitSource, params.source));
  if (params.category) conditions.push(eq(unifiedExploitCatalog.exploitCategory, params.category));
  if (params.platform) conditions.push(eq(unifiedExploitCatalog.exploitPlatform, params.platform));
  if (params.calderaSynced !== void 0) conditions.push(eq(unifiedExploitCatalog.calderaSynced, params.calderaSynced));
  if (params.query) {
    conditions.push(
      sql`(${unifiedExploitCatalog.exploitName} LIKE ${`%${params.query}%`} OR ${unifiedExploitCatalog.exploitDescription} LIKE ${`%${params.query}%`} OR ${unifiedExploitCatalog.catalogId} LIKE ${`%${params.query}%`})`
    );
  }
  const where = conditions.length > 1 ? and(...conditions) : conditions[0];
  const dbConn = await getDbRequired();
  const [items, countResult] = await Promise.all([
    dbConn.select().from(unifiedExploitCatalog).where(where).orderBy(sql`${unifiedExploitCatalog.exploitEffectiveness} DESC`).limit(params.limit || 50).offset(params.offset || 0),
    dbConn.select({ count: sql`count(*)` }).from(unifiedExploitCatalog).where(where)
  ]);
  return { items, total: countResult[0]?.count || 0 };
}
async function getCatalogEntry(catalogId) {
  const dbConn = await getDbRequired();
  const [entry] = await dbConn.select().from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.catalogId, catalogId)).limit(1);
  return entry || null;
}
async function syncToCaldera(catalogIds) {
  const calderaBaseUrl = ENV.calderaBaseUrl;
  const calderaApiKey = ENV.calderaApiKey;
  if (!calderaBaseUrl || !calderaApiKey) {
    return { synced: [], failed: [], skipped: catalogIds };
  }
  const dbConn = await getDbRequired();
  const entries = await dbConn.select().from(unifiedExploitCatalog).where(inArray(unifiedExploitCatalog.catalogId, catalogIds));
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
    console.warn("[ExploitCatalog] Could not fetch existing abilities");
  }
  const synced = [];
  const failed = [];
  const skipped = [];
  for (const entry of entries) {
    if (!entry.calderaAbilityPayload) {
      skipped.push(entry.catalogId);
      continue;
    }
    const abilityId = entry.calderaAbilityPayload.ability_id;
    if (existingAbilityIds.has(abilityId)) {
      try {
        const resp = await fetch(`${calderaBaseUrl}/api/v2/abilities/${abilityId}`, {
          method: "PATCH",
          headers: { KEY: calderaApiKey, "Content-Type": "application/json" },
          body: JSON.stringify(entry.calderaAbilityPayload),
          signal: AbortSignal.timeout(1e4)
        });
        if (resp.ok) {
          synced.push(entry.catalogId);
          await dbConn.update(unifiedExploitCatalog).set({ calderaSynced: true, calderaSyncedAt: /* @__PURE__ */ new Date() }).where(eq(unifiedExploitCatalog.catalogId, entry.catalogId));
        } else {
          const errText = await resp.text().catch(() => "unknown");
          failed.push({ catalogId: entry.catalogId, error: `HTTP ${resp.status}: ${errText}` });
        }
      } catch (err) {
        failed.push({ catalogId: entry.catalogId, error: err.message });
      }
    } else {
      try {
        const resp = await fetch(`${calderaBaseUrl}/api/v2/abilities`, {
          method: "POST",
          headers: { KEY: calderaApiKey, "Content-Type": "application/json" },
          body: JSON.stringify(entry.calderaAbilityPayload),
          signal: AbortSignal.timeout(1e4)
        });
        if (resp.ok) {
          synced.push(entry.catalogId);
          await dbConn.update(unifiedExploitCatalog).set({ calderaSynced: true, calderaSyncedAt: /* @__PURE__ */ new Date() }).where(eq(unifiedExploitCatalog.catalogId, entry.catalogId));
        } else {
          const errText = await resp.text().catch(() => "unknown");
          failed.push({ catalogId: entry.catalogId, error: `HTTP ${resp.status}: ${errText}` });
        }
      } catch (err) {
        failed.push({ catalogId: entry.catalogId, error: err.message });
      }
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  console.log(`[ExploitCatalog] Caldera sync: ${synced.length} synced, ${failed.length} failed, ${skipped.length} skipped`);
  return { synced, failed, skipped };
}
async function syncAllToCaldera() {
  const dbConn = await getDbRequired();
  const unsynced = await dbConn.select({ catalogId: unifiedExploitCatalog.catalogId }).from(unifiedExploitCatalog).where(and(
    eq(unifiedExploitCatalog.exploitEnabled, true),
    eq(unifiedExploitCatalog.calderaSynced, false)
  ));
  if (unsynced.length === 0) {
    return { synced: [], failed: [], skipped: [] };
  }
  return syncToCaldera(unsynced.map((u) => u.catalogId));
}

export {
  runEnrichmentPipeline,
  getCatalogStats,
  searchCatalog,
  getCatalogEntry,
  syncToCaldera,
  syncAllToCaldera
};
