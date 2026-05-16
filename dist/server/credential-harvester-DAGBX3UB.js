import {
  getDbRequired,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  credentialFindings,
  engagementCredentialLists,
  init_schema
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/credential-harvester.ts
import { eq, sql } from "drizzle-orm";
async function harvestCredentialsFromObservations(engagementId, domain, observations) {
  const credentials = [];
  for (const obs of observations) {
    const tags = obs.tags || [];
    const evidence = obs.evidence || {};
    if (tags.includes("dehashed") && tags.includes("credential_leak")) {
      if (evidence.email || evidence.username) {
        credentials.push({
          username: evidence.email || evidence.username || "",
          password: evidence.password,
          passwordHash: evidence.hashed_password || evidence.hash,
          hashType: evidence.hash_type,
          email: evidence.email,
          source: "dehashed",
          breachName: evidence.database_name || evidence.breach_name,
          breachDate: evidence.breach_date,
          domain,
          confidence: evidence.password ? "high" : evidence.hashed_password ? "medium" : "low"
        });
      }
    }
    if (tags.includes("intelx") && (tags.includes("stealer_log") || tags.includes("credential_leak"))) {
      if (evidence.email || evidence.username) {
        credentials.push({
          username: evidence.email || evidence.username || "",
          password: evidence.password,
          email: evidence.email,
          source: "intelx",
          breachName: evidence.stealer_name || evidence.leak_name,
          breachDate: evidence.date,
          domain,
          confidence: evidence.password ? "high" : "medium"
        });
      }
    }
    if (tags.includes("hudson_rock") && (tags.includes("compromised_employee") || tags.includes("third_party_exposure"))) {
      if (evidence.email) {
        credentials.push({
          username: evidence.email,
          password: evidence.has_password ? "[REDACTED_IN_EVIDENCE]" : void 0,
          email: evidence.email,
          source: "hudson_rock",
          breachName: `Stealer: ${evidence.stealer_type || "unknown"}`,
          breachDate: evidence.date_compromised,
          domain,
          confidence: evidence.has_password ? "high" : "medium"
        });
      }
    }
    if (tags.includes("leakcheck") && tags.includes("leaked_account")) {
      if (evidence.email || evidence.username) {
        credentials.push({
          username: evidence.email || evidence.username || "",
          password: evidence.has_password ? "[AVAILABLE_VIA_API]" : void 0,
          passwordHash: evidence.has_hash ? "[AVAILABLE_VIA_API]" : void 0,
          email: evidence.email,
          source: "leakcheck",
          breachName: evidence.sources?.join(", "),
          breachDate: evidence.last_breach,
          domain,
          confidence: evidence.has_password ? "high" : evidence.has_hash ? "medium" : "low"
        });
      }
    }
  }
  if (credentials.length === 0) {
    return { inserted: 0, duplicates: 0 };
  }
  return insertCredentials(engagementId, credentials);
}
async function harvestFromExistingFindings(engagementId, domain) {
  const database = await getDbRequired();
  const findings = await database.select().from(credentialFindings).where(eq(credentialFindings.domain, domain)).limit(500);
  const credentials = findings.map((f) => ({
    username: f.email || f.username || "",
    password: f.password || void 0,
    passwordHash: f.hashedPassword || void 0,
    hashType: f.hashType || void 0,
    email: f.email || void 0,
    source: "dehashed",
    breachName: f.databaseName || void 0,
    domain,
    confidence: f.password ? "high" : f.hashedPassword ? "medium" : "low"
  }));
  if (credentials.length === 0) {
    return { inserted: 0, duplicates: 0 };
  }
  return insertCredentials(engagementId, credentials);
}
async function insertCredentials(engagementId, credentials) {
  const database = await getDbRequired();
  const existing = await database.select({
    username: engagementCredentialLists.username,
    source: engagementCredentialLists.source
  }).from(engagementCredentialLists).where(eq(engagementCredentialLists.engagementId, engagementId));
  const existingSet = new Set(
    existing.map((e) => `${e.username}::${e.source}`)
  );
  let inserted = 0;
  let duplicates = 0;
  const toInsert = credentials.filter((c) => {
    const key = `${c.username}::${c.source}`;
    if (existingSet.has(key)) {
      duplicates++;
      return false;
    }
    existingSet.add(key);
    return true;
  });
  for (let i = 0; i < toInsert.length; i += 50) {
    const batch = toInsert.slice(i, i + 50);
    await database.insert(engagementCredentialLists).values(
      batch.map((c) => ({
        engagementId,
        source: c.source,
        username: c.username,
        password: c.password,
        passwordHash: c.passwordHash,
        hashType: c.hashType,
        email: c.email,
        breachName: c.breachName,
        breachDate: c.breachDate,
        domain: c.domain,
        confidence: c.confidence
      }))
    );
    inserted += batch.length;
  }
  return { inserted, duplicates };
}
async function addManualCredentials(engagementId, credentials) {
  if (credentials.length === 0) return { inserted: 0 };
  const values = credentials.map((c) => ({
    engagementId,
    source: "manual",
    username: c.username,
    password: c.password,
    email: c.email,
    domain: "",
    confidence: "high",
    breachName: c.notes || "Manual entry"
  }));
  const database = await getDbRequired();
  await database.insert(engagementCredentialLists).values(values);
  return { inserted: values.length };
}
async function getEngagementCredentials(engagementId) {
  const database = await getDbRequired();
  const creds = await database.select().from(engagementCredentialLists).where(eq(engagementCredentialLists.engagementId, engagementId)).orderBy(sql`${engagementCredentialLists.confidence} ASC`);
  const bySource = {};
  let withPasswords = 0;
  let withHashes = 0;
  let tested = 0;
  let successful = 0;
  for (const c of creds) {
    bySource[c.source] = (bySource[c.source] || 0) + 1;
    if (c.password) withPasswords++;
    if (c.passwordHash) withHashes++;
    if (c.isUsed) tested++;
    if (c.usedResult === "success") successful++;
  }
  return {
    credentials: creds.map((c) => ({
      id: c.id,
      username: c.username,
      password: c.password,
      email: c.email,
      source: c.source,
      breachName: c.breachName,
      confidence: c.confidence,
      isUsed: c.isUsed,
      usedResult: c.usedResult
    })),
    stats: {
      total: creds.length,
      withPasswords,
      withHashes,
      bySource,
      tested,
      successful
    }
  };
}
var init_credential_harvester = __esm({
  "server/lib/credential-harvester.ts"() {
    init_db();
    init_schema();
  }
});
init_credential_harvester();
export {
  addManualCredentials,
  getEngagementCredentials,
  harvestCredentialsFromObservations,
  harvestFromExistingFindings
};
