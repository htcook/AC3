import {
  getDb,
  init_db
} from "./chunk-B7OU3XQL.js";
import {
  approvedExploitCatalog,
  exploitQuarantineQueue,
  exploitSelectionSnapshots,
  init_schema
} from "./chunk-TYPEU32S.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-knowledge-store.ts
import { eq, sql as dsql, desc } from "drizzle-orm";
import { createHash } from "crypto";
async function persistQuarantineEntry(entry) {
  try {
    const db = await getDb();
    if (!db) {
      console.warn("[ExploitQuarantine] DB unavailable \u2014 entry persisted in-memory only");
      return;
    }
    await db.insert(exploitQuarantineQueue).values({
      quarantineId: entry.id,
      exploitTitle: entry.exploit.title,
      exploitDescription: entry.exploit.description || null,
      exploitCode: entry.exploit.code || null,
      exploitLanguage: entry.exploit.language || null,
      exploitPlatform: entry.exploit.platform || null,
      exploitService: entry.exploit.service || null,
      exploitCveIds: entry.exploit.cveIds,
      exploitTags: entry.exploit.tags || [],
      exploitSource: entry.exploit.source,
      submittedBy: entry.submittedBy,
      sourcePipeline: entry.sourcePipeline,
      status: entry.status,
      engagementId: entry.metadata.engagementId ? parseInt(entry.metadata.engagementId, 10) : null,
      metaCveId: entry.metadata.cveId || null,
      metaSuccess: entry.metadata.success ? 1 : 0
    });
  } catch (err) {
    console.error(`[ExploitQuarantine] DB persist failed: ${err.message}`);
  }
}
async function persistQuarantineReview(quarantineId, status, reviewedBy, reviewNotes) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.update(exploitQuarantineQueue).set({ status, reviewedBy, reviewNotes: reviewNotes || null, reviewedAt: dsql`CURRENT_TIMESTAMP` }).where(eq(exploitQuarantineQueue.quarantineId, quarantineId));
  } catch (err) {
    console.error(`[ExploitQuarantine] DB review update failed: ${err.message}`);
  }
}
async function persistApprovedCatalogEntry(entry, reviewedBy, reviewNotes) {
  try {
    const db = await getDb();
    if (!db) return;
    const catalogEntryId = `approved-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    await db.insert(approvedExploitCatalog).values({
      catalogEntryId,
      quarantineId: entry.id,
      exploitTitle: entry.exploit.title,
      exploitDescription: entry.exploit.description || null,
      exploitCode: entry.exploit.code || null,
      exploitLanguage: entry.exploit.language || null,
      exploitPlatform: entry.exploit.platform || null,
      exploitService: entry.exploit.service || null,
      exploitCveIds: entry.exploit.cveIds,
      exploitTags: [...entry.exploit.tags || [], "verified", "human-reviewed"],
      exploitSource: entry.exploit.source,
      reliabilityScore: entry.exploit.reliabilityScore || 90,
      approvedBy: reviewedBy,
      approvalNotes: reviewNotes || null,
      sourcePipeline: entry.sourcePipeline,
      originalEngagementId: entry.metadata.engagementId ? parseInt(entry.metadata.engagementId, 10) : null
    });
    console.log(`[ExploitQuarantine] Catalog entry persisted: ${catalogEntryId}`);
  } catch (err) {
    console.error(`[ExploitQuarantine] DB catalog persist failed: ${err.message}`);
  }
}
async function recordExploitSelectionSnapshot(params) {
  try {
    const db = await getDb();
    if (!db) return null;
    const catalogRows = await db.select({
      id: approvedExploitCatalog.catalogEntryId,
      title: approvedExploitCatalog.exploitTitle
    }).from(approvedExploitCatalog).orderBy(approvedExploitCatalog.id);
    const catalogHash = createHash("sha256").update(JSON.stringify(catalogRows.map((r) => r.id))).digest("hex").slice(0, 64);
    const snapshotId = `snap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    await db.insert(exploitSelectionSnapshots).values({
      snapshotId,
      engagementId: params.engagementId,
      selectionEvent: params.selectionEvent,
      catalogStateHash: catalogHash,
      catalogEntryCount: catalogRows.length,
      selectedExploitIds: params.selectedExploitIds,
      ragQueryUsed: params.ragQuery,
      ragResultCount: params.ragResultCount,
      ragResultIds: params.ragResultIds
    });
    console.log(`[ExploitQuarantine] Selection snapshot recorded: ${snapshotId} (catalog: ${catalogRows.length} entries, hash: ${catalogHash.slice(0, 12)}...)`);
    return snapshotId;
  } catch (err) {
    console.error(`[ExploitQuarantine] Snapshot record failed: ${err.message}`);
    return null;
  }
}
async function loadApprovedCatalogFromDb() {
  try {
    const db = await getDb();
    if (!db) return 0;
    const rows = await db.select().from(approvedExploitCatalog).orderBy(approvedExploitCatalog.id);
    let count = 0;
    for (const row of rows) {
      const doc = {
        id: row.catalogEntryId,
        source: row.exploitSource || "ac3_history",
        cveIds: row.exploitCveIds || [],
        title: row.exploitTitle,
        description: row.exploitDescription || "",
        code: row.exploitCode || void 0,
        language: row.exploitLanguage || void 0,
        platform: row.exploitPlatform || void 0,
        service: row.exploitService || void 0,
        tags: [...row.exploitTags || [], "verified", "human-reviewed"],
        reliabilityScore: row.reliabilityScore || 90
      };
      index.addDocument(doc);
      count++;
    }
    if (count > 0) console.log(`[ExploitQuarantine] Loaded ${count} approved catalog entries from database`);
    return count;
  } catch (err) {
    console.error(`[ExploitQuarantine] Failed to load approved catalog from DB: ${err.message}`);
    return 0;
  }
}
async function loadQuarantineQueueFromDb() {
  try {
    const db = await getDb();
    if (!db) return 0;
    const rows = await db.select().from(exploitQuarantineQueue).orderBy(desc(exploitQuarantineQueue.id));
    quarantineQueue.length = 0;
    for (const row of rows) {
      const entry = {
        id: row.quarantineId,
        exploit: {
          id: `ac3-db-${row.id}`,
          source: row.exploitSource || "ac3_history",
          cveIds: row.exploitCveIds || [],
          title: row.exploitTitle,
          description: row.exploitDescription || "",
          code: row.exploitCode || void 0,
          language: row.exploitLanguage || void 0,
          platform: row.exploitPlatform || void 0,
          service: row.exploitService || void 0,
          tags: row.exploitTags || [],
          reliabilityScore: 90
        },
        submittedBy: row.submittedBy,
        sourcePipeline: row.sourcePipeline,
        status: row.status,
        quarantinedAt: row.quarantinedAt ? new Date(row.quarantinedAt).getTime() : Date.now(),
        reviewedAt: row.reviewedAt ? new Date(row.reviewedAt).getTime() : void 0,
        reviewedBy: row.reviewedBy || void 0,
        reviewNotes: row.reviewNotes || void 0,
        metadata: {
          cveId: row.metaCveId || void 0,
          engagementId: row.engagementId?.toString(),
          success: row.metaSuccess === 1,
          language: row.exploitLanguage || "unknown",
          service: row.exploitService || void 0,
          platform: row.exploitPlatform || void 0
        }
      };
      quarantineQueue.push(entry);
    }
    if (rows.length > 0) console.log(`[ExploitQuarantine] Loaded ${rows.length} quarantine entries from database`);
    return rows.length;
  } catch (err) {
    console.error(`[ExploitQuarantine] Failed to load quarantine queue from DB: ${err.message}`);
    return 0;
  }
}
async function indexExploitDb() {
  let count = 0;
  try {
    const { buildUnifiedMap } = await import("./vuln-feeds-3ZYWGLNW.js");
    const vulnMap = await buildUnifiedMap();
    for (const [cveId, entry] of vulnMap) {
      if (!entry.exploitDbId) continue;
      index.addDocument({
        id: `edb-${entry.exploitDbId}`,
        source: "exploitdb",
        cveIds: [cveId],
        title: entry.title || `ExploitDB ${entry.exploitDbId}`,
        description: entry.description || "",
        platform: "multi",
        exploitType: "remote",
        service: entry.product || "",
        author: "",
        datePublished: entry.datePublished || "",
        sourceUrl: `https://www.exploit-db.com/exploits/${entry.exploitDbId}`,
        tags: [entry.product, entry.vendor].filter(Boolean)
      });
      count++;
    }
    console.log(`[ExploitKnowledgeStore] Indexed ${count} ExploitDB entries`);
  } catch (err) {
    console.error(`[ExploitKnowledgeStore] ExploitDB indexing error: ${err.message}`);
  }
  return count;
}
async function indexExploitDbFromCsv() {
  let count = 0;
  try {
    const CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
    const res = await fetch(CSV_URL, {
      headers: { "User-Agent": "AC3-ExploitKnowledgeStore/1.0" },
      signal: AbortSignal.timeout(12e4)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const lines = text.split("\n").slice(1);
    const CHUNK_SIZE = 500;
    const yieldToEventLoop = () => new Promise((resolve) => setImmediate(resolve));
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      const fields = parseCSVLine(line);
      if (fields.length < 12) continue;
      const exploitId = (fields[0] || "").trim();
      const description = (fields[2] || "").trim();
      const datePublished = (fields[3] || "").trim();
      const author = (fields[4] || "").trim();
      const type = (fields[5] || "").trim();
      const platform = (fields[6] || "").trim();
      const codes = (fields[11] || "").trim();
      const cveIds = codes.split(";").map((c) => c.trim()).filter((c) => c.startsWith("CVE-"));
      if (!exploitId || !description) continue;
      const service = extractServiceFromDescription(description);
      index.addDocument({
        id: `edb-${exploitId}`,
        source: "exploitdb",
        cveIds,
        title: description,
        description,
        platform: platform || "multi",
        exploitType: type || "remote",
        service,
        author,
        datePublished,
        sourceUrl: `https://www.exploit-db.com/exploits/${exploitId}`,
        tags: [platform, type, service].filter(Boolean)
      });
      count++;
      if (count % CHUNK_SIZE === 0) {
        await yieldToEventLoop();
      }
    }
    console.log(`[ExploitKnowledgeStore] Indexed ${count} ExploitDB entries from CSV (chunked, ${CHUNK_SIZE}/yield)`);
  } catch (err) {
    console.error(`[ExploitKnowledgeStore] ExploitDB CSV indexing error: ${err.message}`);
  }
  return count;
}
async function indexMetasploitModules() {
  let count = 0;
  try {
    const { ingestMetasploitModules } = await import("./ttp-ingest-OFICMN5F.js");
    const result = await ingestMetasploitModules();
    for (const mod of result.exploits) {
      index.addDocument({
        id: `msf-${mod.fullname}`,
        source: "metasploit",
        cveIds: mod.cves,
        title: mod.name,
        description: mod.description,
        platform: mod.platform || "multi",
        exploitType: "remote",
        msfModulePath: mod.fullname,
        msfRank: mod.rank,
        sourceUrl: `https://github.com/rapid7/metasploit-framework/tree/master/modules/${mod.fullname}.rb`,
        tags: ["metasploit", mod.platform || "multi"],
        service: extractServiceFromMsfPath(mod.fullname)
      });
      count++;
    }
    for (const mod of result.auxiliary) {
      index.addDocument({
        id: `msf-aux-${mod.fullname}`,
        source: "metasploit",
        cveIds: [],
        title: mod.name,
        description: mod.description,
        exploitType: "auxiliary",
        msfModulePath: mod.fullname,
        sourceUrl: `https://github.com/rapid7/metasploit-framework/tree/master/modules/${mod.fullname}.rb`,
        tags: ["metasploit", "auxiliary", mod.type]
      });
      count++;
    }
    console.log(`[ExploitKnowledgeStore] Indexed ${count} Metasploit modules`);
  } catch (err) {
    console.error(`[ExploitKnowledgeStore] Metasploit indexing error: ${err.message}`);
  }
  return count;
}
async function indexGitHubPoCs() {
  let count = 0;
  try {
    const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
    const years = Array.from({ length: 6 }, (_, i) => currentYear - i);
    for (const year of years) {
      try {
        const url = `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${year}.json`;
        const res = await fetch(url, {
          headers: { "User-Agent": "AC3-ExploitKnowledgeStore/1.0" },
          signal: AbortSignal.timeout(3e4)
        });
        if (!res.ok) continue;
        const data = await res.json();
        for (const [cveId, repos] of Object.entries(data)) {
          if (!Array.isArray(repos)) continue;
          const topRepos = repos.sort((a, b) => (b.stargazers_count || 0) - (a.stargazers_count || 0)).slice(0, 3);
          for (const repo of topRepos) {
            index.addDocument({
              id: `ghpoc-${repo.id}`,
              source: "github_poc",
              cveIds: [cveId],
              title: repo.name || repo.full_name,
              description: repo.description || `PoC for ${cveId}`,
              sourceUrl: repo.html_url,
              datePublished: repo.created_at,
              author: repo.full_name?.split("/")[0] || "",
              tags: [...repo.topics || [], "poc", "github"],
              reliabilityScore: Math.min(100, (repo.stargazers_count || 0) * 2 + (repo.forks_count || 0) * 5)
            });
            count++;
          }
        }
      } catch {
      }
    }
    console.log(`[ExploitKnowledgeStore] Indexed ${count} GitHub PoC repositories`);
  } catch (err) {
    console.error(`[ExploitKnowledgeStore] GitHub PoC indexing error: ${err.message}`);
  }
  return count;
}
async function indexAc3History() {
  let count = 0;
  try {
    const { recordFeedback, getModulePerformance } = await import("./exploit-feedback-loop-WAAZNYPN.js");
    console.log(`[ExploitKnowledgeStore] AC3 history indexing ready (${count} entries)`);
  } catch (err) {
    console.error(`[ExploitKnowledgeStore] AC3 history indexing error: ${err.message}`);
  }
  return count;
}
function addExploitRecipe(recipe) {
  if (!recipe.success) return { quarantined: false };
  const id = `ac3-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const doc = {
    id,
    source: "ac3_history",
    cveIds: recipe.cveId ? [recipe.cveId] : [],
    title: recipe.title,
    description: recipe.description,
    code: recipe.code,
    language: recipe.language,
    service: recipe.service,
    platform: recipe.platform,
    tags: ["ac3", recipe.language, recipe.service || ""].filter(Boolean),
    reliabilityScore: 90
  };
  if (recipe.bypassQuarantine === true) {
    doc.tags.push("verified", "quarantine-bypassed");
    index.addDocument(doc);
    return { quarantined: false };
  }
  const quarantineId = `quarantine-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const quarantinedExploit = {
    id: quarantineId,
    exploit: doc,
    submittedBy: "llm-pipeline",
    sourcePipeline: recipe.sourcePipeline || "unknown",
    status: "pending_review",
    quarantinedAt: Date.now(),
    metadata: {
      cveId: recipe.cveId,
      engagementId: recipe.engagementId,
      success: recipe.success,
      language: recipe.language,
      service: recipe.service,
      platform: recipe.platform
    }
  };
  quarantineQueue.push(quarantinedExploit);
  if (quarantineQueue.length > MAX_QUARANTINE_SIZE) {
    const rejectedIdx = quarantineQueue.findIndex((q) => q.status === "rejected");
    if (rejectedIdx >= 0) quarantineQueue.splice(rejectedIdx, 1);
  }
  persistQuarantineEntry(quarantinedExploit).catch(() => {
  });
  console.log(`[ExploitQuarantine] Exploit quarantined: ${doc.title} (${quarantineId}) \u2014 awaiting human review`);
  return { quarantined: true, quarantineId };
}
function getQuarantineQueue(statusFilter) {
  if (statusFilter) {
    return quarantineQueue.filter((q) => q.status === statusFilter);
  }
  return [...quarantineQueue];
}
function approveQuarantinedExploit(quarantineId, reviewedBy, reviewNotes, checklist) {
  const entry = quarantineQueue.find((q) => q.id === quarantineId);
  if (!entry) return { success: false, error: "Quarantined exploit not found" };
  if (entry.status !== "pending_review") return { success: false, error: `Exploit already ${entry.status}` };
  if (checklist) {
    const checklistItems = [
      { field: "noCustomerIPs", label: "No customer IP addresses" },
      { field: "noCustomerHostnames", label: "No customer hostnames" },
      { field: "noCustomerCredentials", label: "No customer credentials" },
      { field: "noCustomerConfig", label: "No customer-specific config" },
      { field: "catalogConsentVerified", label: "Catalog consent verified" }
    ];
    const unchecked = checklistItems.filter((item) => !checklist[item.field]);
    if (unchecked.length > 0) {
      const missing = unchecked.map((i) => i.label).join(", ");
      console.warn(`[ExploitQuarantine] Approval blocked \u2014 incomplete checklist: ${missing}`);
      return { success: false, error: `Reviewer checklist incomplete: ${missing}` };
    }
    entry.reviewChecklist = { ...checklist, completedAt: Date.now() };
  } else {
    const CHECKLIST_MANDATORY_DATE = (/* @__PURE__ */ new Date("2026-07-01T00:00:00Z")).getTime();
    if (Date.now() >= CHECKLIST_MANDATORY_DATE) {
      console.error(`[ExploitQuarantine] BLOCKED: Reviewer checklist is mandatory as of 2026-07-01. Approval rejected for ${reviewedBy}.`);
      return { success: false, error: "Reviewer checklist is mandatory as of 2026-07-01. All checklist items must be completed." };
    }
    console.warn(`[ExploitQuarantine] WARNING: Exploit approved without reviewer checklist by ${reviewedBy}. Checklist becomes MANDATORY on 2026-07-01.`);
  }
  entry.status = "approved";
  entry.reviewedAt = Date.now();
  entry.reviewedBy = reviewedBy;
  entry.reviewNotes = reviewNotes;
  entry.exploit.tags.push("verified", "human-reviewed");
  index.addDocument(entry.exploit);
  persistQuarantineReview(quarantineId, "approved", reviewedBy, reviewNotes).catch(() => {
  });
  persistApprovedCatalogEntry(entry, reviewedBy, reviewNotes).catch(() => {
  });
  console.log(`[ExploitQuarantine] Exploit approved by ${reviewedBy}: ${entry.exploit.title} (${quarantineId})`);
  return { success: true };
}
function rejectQuarantinedExploit(quarantineId, reviewedBy, reviewNotes) {
  const entry = quarantineQueue.find((q) => q.id === quarantineId);
  if (!entry) return { success: false, error: "Quarantined exploit not found" };
  if (entry.status !== "pending_review") return { success: false, error: `Exploit already ${entry.status}` };
  entry.status = "rejected";
  entry.reviewedAt = Date.now();
  entry.reviewedBy = reviewedBy;
  entry.reviewNotes = reviewNotes;
  persistQuarantineReview(quarantineId, "rejected", reviewedBy, reviewNotes).catch(() => {
  });
  console.log(`[ExploitQuarantine] Exploit rejected by ${reviewedBy}: ${entry.exploit.title} (${quarantineId})`);
  return { success: true };
}
function getQuarantineStats() {
  return {
    total: quarantineQueue.length,
    pendingReview: quarantineQueue.filter((q) => q.status === "pending_review").length,
    approved: quarantineQueue.filter((q) => q.status === "approved").length,
    rejected: quarantineQueue.filter((q) => q.status === "rejected").length
  };
}
function clearQuarantineQueue() {
  quarantineQueue.length = 0;
  console.log("[ExploitQuarantine] Quarantine queue cleared");
}
async function initializeExploitKnowledgeStore() {
  if (initializing) return;
  initializing = true;
  console.log("[ExploitKnowledgeStore] \u2550\u2550\u2550 Initializing exploit knowledge store \u2550\u2550\u2550");
  const start = Date.now();
  try {
    const results = await Promise.allSettled([
      indexExploitDbFromCsv(),
      indexMetasploitModules(),
      indexGitHubPoCs(),
      indexAc3History()
    ]);
    const counts = results.map((r) => r.status === "fulfilled" ? r.value : 0);
    const total = counts.reduce((a, b) => a + b, 0);
    const approvedCount = await loadApprovedCatalogFromDb();
    const quarantineCount = await loadQuarantineQueueFromDb();
    const mem = index.getMemoryEstimate();
    console.log(
      `[ExploitKnowledgeStore] \u2550\u2550\u2550 Initialized in ${((Date.now() - start) / 1e3).toFixed(1)}s: ${total + approvedCount} documents, ${mem.terms} terms, ~${mem.estimatedMB}MB \u2550\u2550\u2550`
    );
    console.log(
      `[ExploitKnowledgeStore]   ExploitDB: ${counts[0]}, MSF: ${counts[1]}, GitHub PoCs: ${counts[2]}, AC3 History: ${counts[3]}, Approved Catalog (DB): ${approvedCount}, Quarantine Queue (DB): ${quarantineCount}`
    );
    initialized = true;
    lastRefresh = Date.now();
  } catch (err) {
    console.error(`[ExploitKnowledgeStore] Initialization error: ${err.message}`);
  } finally {
    initializing = false;
  }
}
async function refreshIfStale() {
  if (Date.now() - lastRefresh > REFRESH_INTERVAL) {
    index.clear();
    initialized = false;
    await initializeExploitKnowledgeStore();
  }
}
async function searchExploits(query, options) {
  if (!initialized) {
    await initializeExploitKnowledgeStore();
  }
  return index.search(query, options);
}
async function lookupCveExploits(cveId) {
  if (!initialized) {
    await initializeExploitKnowledgeStore();
  }
  return index.lookupByCve(cveId);
}
async function lookupServiceExploits(service) {
  if (!initialized) {
    await initializeExploitKnowledgeStore();
  }
  return index.lookupByService(service);
}
async function buildExploitRagContext(params) {
  const { cveId, vulnTitle, vulnDescription, service, platform, maxResults = 5, maxCodeLength = 3e3 } = params;
  const queryParts = [];
  if (cveId) queryParts.push(cveId);
  queryParts.push(vulnTitle);
  if (service) queryParts.push(service);
  if (vulnDescription) queryParts.push(vulnDescription.slice(0, 200));
  const query = queryParts.join(" ");
  const results = await searchExploits(query, {
    limit: maxResults,
    platform,
    boostWithCode: true,
    boostSources: ["ac3_history", "metasploit"]
    // Prefer verified exploits
  });
  if (results.length === 0) {
    return "\n## Exploit Knowledge Store\nNo matching exploits found in the knowledge store. Generate a novel exploit based on the vulnerability details.\n";
  }
  const sections = ["\n## Exploit Knowledge Store (RAG-Retrieved References)"];
  sections.push(`Found ${results.length} relevant exploit references. Use these as a basis for your exploit:
`);
  for (let i = 0; i < results.length; i++) {
    const { document: doc, score, matchReason } = results[i];
    sections.push(`### Reference ${i + 1}: ${doc.title}`);
    sections.push(`- **Source:** ${doc.source} | **Score:** ${(score * 100).toFixed(0)}% | **Reason:** ${matchReason}`);
    if (doc.cveIds.length > 0) sections.push(`- **CVEs:** ${doc.cveIds.join(", ")}`);
    if (doc.msfModulePath) sections.push(`- **MSF Module:** \`use ${doc.msfModulePath}\` (rank: ${doc.msfRank || 0})`);
    if (doc.sourceUrl) sections.push(`- **Source URL:** ${doc.sourceUrl}`);
    if (doc.platform) sections.push(`- **Platform:** ${doc.platform}`);
    if (doc.description && doc.description !== doc.title) {
      sections.push(`- **Description:** ${doc.description.slice(0, 300)}`);
    }
    if (doc.code) {
      sections.push(`\`\`\`${doc.language || "text"}
${doc.code.slice(0, maxCodeLength)}
\`\`\``);
    }
    sections.push("");
  }
  sections.push("**IMPORTANT:** Adapt the above references to the specific target. Do not copy verbatim \u2014 adjust IPs, ports, payloads, and evasion techniques for the current engagement.\n");
  return sections.join("\n");
}
function getStoreStats() {
  const mem = index.getMemoryEstimate();
  const sources = {
    exploitdb: 0,
    github_poc: 0,
    metasploit: 0,
    ac3_history: 0,
    custom: 0
  };
  return {
    initialized,
    documents: mem.documents,
    terms: mem.terms,
    estimatedMB: mem.estimatedMB,
    lastRefresh,
    sources
  };
}
function clearExploitKnowledgeStore() {
  index.clear();
  initialized = false;
  lastRefresh = 0;
  console.log("[ExploitKnowledgeStore] Store cleared");
}
function parseCSVLine(line) {
  const fields = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}
function extractServiceFromDescription(desc2) {
  const lower = desc2.toLowerCase();
  const services = [
    "apache",
    "nginx",
    "iis",
    "tomcat",
    "wordpress",
    "joomla",
    "drupal",
    "php",
    "mysql",
    "postgresql",
    "mssql",
    "oracle",
    "redis",
    "mongodb",
    "openssh",
    "proftpd",
    "vsftpd",
    "exim",
    "postfix",
    "sendmail",
    "samba",
    "smb",
    "rdp",
    "vnc",
    "jenkins",
    "gitlab",
    "grafana",
    "elasticsearch",
    "kibana",
    "docker",
    "kubernetes",
    "nextcloud",
    "exchange",
    "sharepoint",
    "outlook",
    "weblogic",
    "jboss",
    "wildfly",
    "struts",
    "spring",
    "django",
    "flask",
    "rails",
    "node",
    "express",
    "confluence",
    "bitbucket",
    "bamboo",
    "sonarqube",
    "artifactory"
  ];
  for (const svc of services) {
    if (lower.includes(svc)) return svc;
  }
  return "";
}
function extractServiceFromMsfPath(path) {
  const parts = path.split("/");
  if (parts.length >= 3) {
    const service = parts[2];
    if (["http", "https", "ssh", "ftp", "smtp", "smb", "rdp", "vnc", "mysql", "mssql", "postgres"].includes(service)) {
      return service;
    }
  }
  return "";
}
var FIELD_BOOST, InvertedIndex, index, initialized, initializing, lastRefresh, REFRESH_INTERVAL, quarantineQueue, MAX_QUARANTINE_SIZE;
var init_exploit_knowledge_store = __esm({
  "server/lib/exploit-knowledge-store.ts"() {
    init_db();
    init_schema();
    FIELD_BOOST = {
      cve: 10,
      title: 5,
      service: 4,
      tags: 3,
      description: 1.5,
      code: 0.5
    };
    InvertedIndex = class {
      constructor() {
        /** term → posting list */
        this.postings = /* @__PURE__ */ new Map();
        /** docId → document */
        this.documents = /* @__PURE__ */ new Map();
        /** CVE → docIds (fast CVE lookup) */
        this.cveIndex = /* @__PURE__ */ new Map();
        /** service → docIds (fast service lookup) */
        this.serviceIndex = /* @__PURE__ */ new Map();
        /** Total document count for IDF calculation */
        this.docCount = 0;
      }
      get size() {
        return this.docCount;
      }
      get termCount() {
        return this.postings.size;
      }
      /** Tokenize text into searchable terms */
      tokenize(text) {
        return text.toLowerCase().replace(/[^a-z0-9\-_.]/g, " ").split(/\s+/).filter((t) => t.length >= 2);
      }
      /** Add a document to the index */
      addDocument(doc) {
        if (this.documents.has(doc.id)) return;
        this.documents.set(doc.id, doc);
        this.docCount++;
        const fieldTexts = [
          { field: "title", text: doc.title },
          { field: "description", text: doc.description },
          { field: "service", text: doc.service || "" },
          { field: "tags", text: doc.tags.join(" ") }
        ];
        for (const cve of doc.cveIds) {
          const normalized = cve.toUpperCase();
          const posting = { docId: doc.id, tf: 1, field: "cve" };
          const existing = this.postings.get(normalized);
          if (existing) existing.push(posting);
          else this.postings.set(normalized, [posting]);
          const cveSet = this.cveIndex.get(normalized);
          if (cveSet) cveSet.add(doc.id);
          else this.cveIndex.set(normalized, /* @__PURE__ */ new Set([doc.id]));
        }
        if (doc.code) {
          fieldTexts.push({ field: "code", text: doc.code.slice(0, 2e3) });
        }
        for (const { field, text } of fieldTexts) {
          if (!text) continue;
          const tokens = this.tokenize(text);
          const termFreq = /* @__PURE__ */ new Map();
          for (const token of tokens) {
            termFreq.set(token, (termFreq.get(token) || 0) + 1);
          }
          for (const [term, freq] of termFreq) {
            const posting = { docId: doc.id, tf: freq, field };
            const existing = this.postings.get(term);
            if (existing) existing.push(posting);
            else this.postings.set(term, [posting]);
          }
        }
        if (doc.service) {
          const svc = doc.service.toLowerCase();
          const svcSet = this.serviceIndex.get(svc);
          if (svcSet) svcSet.add(doc.id);
          else this.serviceIndex.set(svc, /* @__PURE__ */ new Set([doc.id]));
        }
      }
      /** Search the index with TF-IDF + field boost scoring */
      search(query, options = {}) {
        const {
          limit = 10,
          minScore = 0.01,
          sources,
          platform,
          exploitType,
          boostWithCode = true,
          boostSources
        } = options;
        const cvePattern = /CVE-\d{4}-\d{4,}/gi;
        const cveMatches = query.match(cvePattern) || [];
        const queryWithoutCves = query.replace(cvePattern, "").trim();
        const queryTerms = this.tokenize(queryWithoutCves);
        const allTerms = [...cveMatches.map((c) => c.toUpperCase()), ...queryTerms];
        if (allTerms.length === 0) return [];
        const docScores = /* @__PURE__ */ new Map();
        for (const cve of cveMatches) {
          const normalized = cve.toUpperCase();
          const docIds = this.cveIndex.get(normalized);
          if (!docIds) continue;
          for (const docId of docIds) {
            const entry = docScores.get(docId) || { score: 0, matchedTerms: /* @__PURE__ */ new Set() };
            entry.score += FIELD_BOOST.cve * 10;
            entry.matchedTerms.add(normalized);
            docScores.set(docId, entry);
          }
        }
        for (const term of queryTerms) {
          const postings = this.postings.get(term);
          if (!postings) continue;
          const df = new Set(postings.map((p) => p.docId)).size;
          const idf = Math.log(1 + this.docCount / (1 + df));
          for (const posting of postings) {
            const entry = docScores.get(posting.docId) || { score: 0, matchedTerms: /* @__PURE__ */ new Set() };
            const tfIdf = (1 + Math.log(posting.tf)) * idf;
            entry.score += tfIdf * FIELD_BOOST[posting.field];
            entry.matchedTerms.add(term);
            docScores.set(posting.docId, entry);
          }
        }
        const results = [];
        for (const [docId, { score, matchedTerms }] of docScores) {
          const doc = this.documents.get(docId);
          if (!doc) continue;
          if (sources && !sources.includes(doc.source)) continue;
          if (platform && (!doc.platform || !doc.platform.toLowerCase().includes(platform.toLowerCase()))) continue;
          if (exploitType && doc.exploitType && doc.exploitType !== exploitType) continue;
          let finalScore = score;
          if (boostWithCode && doc.code) {
            finalScore *= 1.5;
          }
          if (boostSources?.includes(doc.source)) {
            finalScore *= 1.3;
          }
          if (doc.reliabilityScore !== void 0 && doc.reliabilityScore > 0) {
            finalScore *= 1 + doc.reliabilityScore / 200;
          }
          if (doc.msfRank !== void 0 && doc.msfRank > 0) {
            finalScore *= 1 + doc.msfRank / 1200;
          }
          const normalizedScore = Math.min(1, finalScore / (allTerms.length * 50));
          if (normalizedScore < minScore) continue;
          const reasons = [];
          if (matchedTerms.size > 0) {
            const cveTerms = [...matchedTerms].filter((t) => t.startsWith("CVE-"));
            const textTerms = [...matchedTerms].filter((t) => !t.startsWith("CVE-"));
            if (cveTerms.length > 0) reasons.push(`CVE match: ${cveTerms.join(", ")}`);
            if (textTerms.length > 0) reasons.push(`Text match: ${textTerms.slice(0, 5).join(", ")}`);
          }
          if (doc.code) reasons.push("Has exploit code");
          if (doc.msfRank && doc.msfRank >= 400) reasons.push(`MSF rank: ${doc.msfRank >= 600 ? "excellent" : doc.msfRank >= 500 ? "great" : "good"}`);
          results.push({
            document: doc,
            score: normalizedScore,
            matchedTerms: [...matchedTerms],
            matchReason: reasons.join("; ")
          });
        }
        results.sort((a, b) => b.score - a.score);
        return results.slice(0, limit);
      }
      /** Fast CVE lookup — returns all documents for a specific CVE */
      lookupByCve(cveId) {
        const normalized = cveId.toUpperCase();
        const docIds = this.cveIndex.get(normalized);
        if (!docIds) return [];
        return [...docIds].map((id) => this.documents.get(id)).filter(Boolean);
      }
      /** Fast service lookup */
      lookupByService(service) {
        const svc = service.toLowerCase();
        const docIds = this.serviceIndex.get(svc);
        if (!docIds) return [];
        return [...docIds].map((id) => this.documents.get(id)).filter(Boolean);
      }
      /** Clear all data */
      clear() {
        this.postings.clear();
        this.documents.clear();
        this.cveIndex.clear();
        this.serviceIndex.clear();
        this.docCount = 0;
      }
      /** Get memory usage estimate */
      getMemoryEstimate() {
        const postingCount = [...this.postings.values()].reduce((sum, p) => sum + p.length, 0);
        const estimatedBytes = this.docCount * 500 + postingCount * 100 + this.postings.size * 50;
        return {
          documents: this.docCount,
          terms: this.postings.size,
          estimatedMB: Math.round(estimatedBytes / 1024 / 1024 * 10) / 10
        };
      }
    };
    index = new InvertedIndex();
    initialized = false;
    initializing = false;
    lastRefresh = 0;
    REFRESH_INTERVAL = 6 * 60 * 60 * 1e3;
    quarantineQueue = [];
    MAX_QUARANTINE_SIZE = 500;
  }
});

export {
  recordExploitSelectionSnapshot,
  loadApprovedCatalogFromDb,
  loadQuarantineQueueFromDb,
  indexExploitDb,
  indexExploitDbFromCsv,
  indexMetasploitModules,
  indexGitHubPoCs,
  indexAc3History,
  addExploitRecipe,
  getQuarantineQueue,
  approveQuarantinedExploit,
  rejectQuarantinedExploit,
  getQuarantineStats,
  clearQuarantineQueue,
  initializeExploitKnowledgeStore,
  refreshIfStale,
  searchExploits,
  lookupCveExploits,
  lookupServiceExploits,
  buildExploitRagContext,
  getStoreStats,
  clearExploitKnowledgeStore,
  init_exploit_knowledge_store
};
