/**
 * Threat Actor Auto-Classification Engine
 * 
 * Uses LLM structured output to classify "unknown" threat actors into proper categories
 * based on their descriptions, TTPs, tools, target sectors, and other profile data.
 */
import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import * as schema from "../../drizzle/schema";

export type ActorType = "apt" | "ransomware" | "cybercrime" | "hacktivist" | "access_broker" | "influence_ops";

export interface ClassificationInput {
  actorId: string;
  name: string;
  description: string | null;
  aliases: string[];
  origin: string | null;
  motivation: string | null;
  targetSectors: string[];
  targetRegions: string[];
  techniques: string[];
  tools: string[];
  malware: string[];
  firstSeen: string | null;
  lastActive: string | null;
  sophistication: string | null;
}

export interface ClassificationResult {
  actorId: string;
  name: string;
  previousType: string;
  classifiedType: ActorType;
  confidence: number; // 0-100
  reasoning: string;
  secondaryType: ActorType | null;
  secondaryConfidence: number;
  indicators: string[]; // key signals that drove the classification
}

export interface BatchProgress {
  total: number;
  processed: number;
  succeeded: number;
  failed: number;
  results: ClassificationResult[];
  errors: Array<{ actorId: string; name: string; error: string }>;
  status: "idle" | "running" | "completed" | "cancelled";
  startedAt: number | null;
  completedAt: number | null;
}

// In-memory progress tracker (per-session)
let currentBatchProgress: BatchProgress = {
  total: 0,
  processed: 0,
  succeeded: 0,
  failed: 0,
  results: [],
  errors: [],
  status: "idle",
  startedAt: null,
  completedAt: null,
};

let cancelRequested = false;

export function getProgress(): BatchProgress {
  return { ...currentBatchProgress };
}

export function cancelBatch(): void {
  cancelRequested = true;
}

export function resetProgress(): void {
  currentBatchProgress = {
    total: 0,
    processed: 0,
    succeeded: 0,
    failed: 0,
    results: [],
    errors: [],
    status: "idle",
    startedAt: null,
    completedAt: null,
  };
  cancelRequested = false;
}

/**
 * Classify a single threat actor using LLM structured output
 */
export async function classifyActor(actor: ClassificationInput): Promise<ClassificationResult> {
  const profileSummary = buildProfileSummary(actor);

  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a cyber threat intelligence analyst specializing in threat actor classification. 
Your task is to classify threat actors into one of these categories based on their profile data:

- **apt**: Nation-state sponsored or state-affiliated advanced persistent threat groups. Key indicators: government sponsorship, long-term espionage campaigns, sophisticated custom tooling, targeting government/military/critical infrastructure, specific nation-state attribution.
- **ransomware**: Groups primarily conducting ransomware operations. Key indicators: ransomware deployment, double/triple extortion, data leak sites, RaaS (Ransomware-as-a-Service) operations, financial motivation through encryption.
- **cybercrime**: Financially motivated criminal groups not primarily focused on ransomware. Key indicators: banking trojans, credit card fraud, BEC scams, credential theft for sale, cryptomining, general financial fraud.
- **hacktivist**: Ideologically or politically motivated groups. Key indicators: DDoS campaigns for political causes, website defacement, data leaks for activism, anti-government/corporate messaging, loose organizational structure.
- **access_broker**: Groups that specialize in selling initial access to compromised networks. Key indicators: selling RDP/VPN access, credential harvesting for resale, operating on dark web marketplaces, enabling other threat actors.
- **influence_ops**: Groups conducting information operations and disinformation campaigns. Key indicators: social media manipulation, fake news propagation, election interference, coordinated inauthentic behavior, propaganda.

Analyze ALL available data carefully. Consider:
1. Primary motivation (espionage, financial, ideological, access sales, information warfare)
2. TTPs and their alignment with known actor categories
3. Tools and malware used (custom vs commodity)
4. Target sectors and regions (government targets suggest APT, financial targets suggest cybercrime)
5. Sophistication level
6. Origin country (some countries are known for state-sponsored APT activity)

Be precise and provide clear reasoning.`
      },
      {
        role: "user",
        content: `Classify this threat actor:\n\n${profileSummary}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "threat_actor_classification",
        strict: true,
        schema: {
          type: "object",
          properties: {
            classifiedType: {
              type: "string",
              enum: ["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"],
              description: "The primary classification for this threat actor"
            },
            confidence: {
              type: "number",
              description: "Confidence level 0-100. Use 90+ for clear-cut cases, 70-89 for strong indicators, 50-69 for moderate evidence, below 50 for weak/ambiguous signals."
            },
            reasoning: {
              type: "string",
              description: "2-3 sentence explanation of why this classification was chosen, citing specific evidence from the profile."
            },
            secondaryType: {
              type: "string",
              enum: ["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops", "none"],
              description: "Secondary classification if the actor shows traits of multiple categories. Use 'none' if clearly single-category."
            },
            secondaryConfidence: {
              type: "number",
              description: "Confidence for secondary classification (0 if none)"
            },
            indicators: {
              type: "array",
              items: { type: "string" },
              description: "3-5 key signals from the profile that drove this classification decision"
            }
          },
          required: ["classifiedType", "confidence", "reasoning", "secondaryType", "secondaryConfidence", "indicators"],
          additionalProperties: false,
        }
      }
    }
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("No response from LLM");
  }

  const parsed = JSON.parse(content);

  return {
    actorId: actor.actorId,
    name: actor.name,
    previousType: "unknown",
    classifiedType: parsed.classifiedType as ActorType,
    confidence: Math.min(100, Math.max(0, parsed.confidence)),
    reasoning: parsed.reasoning,
    secondaryType: parsed.secondaryType === "none" ? null : parsed.secondaryType as ActorType,
    secondaryConfidence: parsed.secondaryConfidence || 0,
    indicators: parsed.indicators || [],
  };
}

/**
 * Classify a batch of actors with rate limiting and progress tracking
 */
export async function classifyBatch(
  actors: ClassificationInput[],
  options: {
    batchSize?: number;
    delayMs?: number;
    autoApplyThreshold?: number; // confidence threshold to auto-apply (default 75)
    onResult?: (result: ClassificationResult) => Promise<void>;
  } = {}
): Promise<BatchProgress> {
  const { batchSize = 5, delayMs = 1000, autoApplyThreshold = 75, onResult } = options;

  const batchId = `batch_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  cancelRequested = false;
  currentBatchProgress = {
    total: actors.length,
    processed: 0,
    succeeded: 0,
    failed: 0,
    results: [],
    errors: [],
    status: "running",
    startedAt: Date.now(),
    completedAt: null,
  };

  for (let i = 0; i < actors.length; i += batchSize) {
    if (cancelRequested) {
      currentBatchProgress.status = "cancelled";
      currentBatchProgress.completedAt = Date.now();
      return currentBatchProgress;
    }

    const batch = actors.slice(i, i + batchSize);

    // Process batch concurrently
    const results = await Promise.allSettled(
      batch.map(actor => classifyActor(actor))
    );

    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      currentBatchProgress.processed++;

      if (result.status === "fulfilled") {
        currentBatchProgress.succeeded++;
        currentBatchProgress.results.push(result.value);

        // Auto-apply if confidence meets threshold
        if (result.value.confidence >= autoApplyThreshold && onResult) {
          try {
            await onResult(result.value);
            // Log to audit trail
            await logClassificationAudit(result.value, 'auto_apply', batchId);
          } catch (e) {
            // Log but don't fail the batch
            console.error(`[Classifier] Failed to apply result for ${result.value.actorId}:`, e);
          }
        } else if (result.value.confidence < autoApplyThreshold) {
          // Log pending review classifications
          await logClassificationAudit(result.value, 'pending_review', batchId);
        }
      } else {
        currentBatchProgress.failed++;
        currentBatchProgress.errors.push({
          actorId: batch[j].actorId,
          name: batch[j].name,
          error: result.reason?.message || "Unknown error",
        });
      }
    }

    // Rate limiting delay between batches
    if (i + batchSize < actors.length && !cancelRequested) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  currentBatchProgress.status = "completed";
  currentBatchProgress.completedAt = Date.now();
  return currentBatchProgress;
}

/**
 * Build a human-readable profile summary for the LLM prompt
 */
function buildProfileSummary(actor: ClassificationInput): string {
  const parts: string[] = [];

  parts.push(`**Name:** ${actor.name}`);
  if (actor.aliases.length > 0) parts.push(`**Aliases:** ${actor.aliases.join(", ")}`);
  if (actor.origin) parts.push(`**Origin:** ${actor.origin}`);
  if (actor.motivation) parts.push(`**Motivation:** ${actor.motivation}`);
  if (actor.sophistication) parts.push(`**Sophistication:** ${actor.sophistication}`);
  if (actor.firstSeen) parts.push(`**First Seen:** ${actor.firstSeen}`);
  if (actor.lastActive) parts.push(`**Last Active:** ${actor.lastActive}`);
  if (actor.description) parts.push(`**Description:** ${actor.description}`);
  if (actor.targetSectors.length > 0) parts.push(`**Target Sectors:** ${actor.targetSectors.join(", ")}`);
  if (actor.targetRegions.length > 0) parts.push(`**Target Regions:** ${actor.targetRegions.join(", ")}`);
  if (actor.techniques.length > 0) parts.push(`**MITRE Techniques:** ${actor.techniques.slice(0, 20).join(", ")}${actor.techniques.length > 20 ? ` (+${actor.techniques.length - 20} more)` : ""}`);
  if (actor.tools.length > 0) parts.push(`**Tools:** ${actor.tools.join(", ")}`);
  if (actor.malware.length > 0) parts.push(`**Malware:** ${actor.malware.join(", ")}`);

  return parts.join("\n");
}

/**
 * Validate a classification result for consistency
 */
export function validateClassification(result: ClassificationResult): { valid: boolean; issues: string[] } {
  const issues: string[] = [];

  if (!["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"].includes(result.classifiedType)) {
    issues.push(`Invalid classification type: ${result.classifiedType}`);
  }
  if (result.confidence < 0 || result.confidence > 100) {
    issues.push(`Confidence out of range: ${result.confidence}`);
  }
  if (!result.reasoning || result.reasoning.length < 10) {
    issues.push("Reasoning is too short or missing");
  }
  if (result.secondaryType && result.secondaryType === result.classifiedType) {
    issues.push("Secondary type should not match primary type");
  }
  if (result.indicators.length === 0) {
    issues.push("No indicators provided");
  }

  return { valid: issues.length === 0, issues };
}


/**
 * Log a classification action to the audit trail
 */
async function logClassificationAudit(
  result: ClassificationResult,
  method: string,
  batchId?: string,
  appliedBy?: string
): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(schema.classificationAuditLog).values({
      actorId: result.actorId,
      actorName: result.name,
      previousType: result.previousType || "unknown",
      newType: result.classifiedType,
      confidence: result.confidence,
      reasoning: result.reasoning,
      source: "llm_auto",
      appliedBy: appliedBy || "system",
      appliedMethod: method,
      batchId: batchId || null,
    });
  } catch (err) {
    console.error("[Classifier] Failed to log audit:", err);
  }
}

/**
 * Log a manual classification action (for UI-triggered approvals/reverts)
 */
export async function logManualClassificationAudit(params: {
  actorId: string;
  actorName: string;
  previousType: string;
  newType: string;
  confidence: number;
  reasoning: string;
  appliedBy: string;
  method: "manual_approve" | "manual_override" | "revert";
}): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(schema.classificationAuditLog).values({
      actorId: params.actorId,
      actorName: params.actorName,
      previousType: params.previousType,
      newType: params.newType,
      confidence: params.confidence,
      reasoning: params.reasoning,
      source: "manual",
      appliedBy: params.appliedBy,
      appliedMethod: params.method,
    });
  } catch (err) {
    console.error("[Classifier] Failed to log manual audit:", err);
  }
}

/**
 * Query the classification audit log with filters
 */
export async function queryAuditLog(filters: {
  actorId?: string;
  source?: string;
  method?: string;
  batchId?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<{ entries: any[]; total: number }> {
  const db = await getDb();
  if (!db) return { entries: [], total: 0 };

  const { desc, eq, sql, and, count } = await import("drizzle-orm");
  const conditions: any[] = [];
  if (filters.actorId) conditions.push(eq(schema.classificationAuditLog.actorId, filters.actorId));
  if (filters.source) conditions.push(eq(schema.classificationAuditLog.source, filters.source));
  if (filters.method) conditions.push(eq(schema.classificationAuditLog.appliedMethod, filters.method));
  if (filters.batchId) conditions.push(eq(schema.classificationAuditLog.batchId, filters.batchId));

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [entries, totalResult] = await Promise.all([
    db.select().from(schema.classificationAuditLog)
      .where(where)
      .orderBy(desc(schema.classificationAuditLog.createdAt))
      .limit(filters.limit || 50)
      .offset(filters.offset || 0),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(where),
  ]);

  return { entries, total: totalResult[0]?.count || 0 };
}

/**
 * Get audit log summary statistics
 */
export async function getAuditSummary(): Promise<{
  totalClassifications: number;
  autoApplied: number;
  manualApproved: number;
  pendingReview: number;
  reverted: number;
  byType: Record<string, number>;
  last24h: number;
  last7d: number;
}> {
  const db = await getDb();
  if (!db) return { totalClassifications: 0, autoApplied: 0, manualApproved: 0, pendingReview: 0, reverted: 0, byType: {}, last24h: 0, last7d: 0 };

  const { count, eq, sql, gte } = await import("drizzle-orm");
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;

  const [total, autoApplied, manualApproved, pendingReview, reverted, last24h, last7d, byTypeRows] = await Promise.all([
    db.select({ count: count() }).from(schema.classificationAuditLog),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(eq(schema.classificationAuditLog.appliedMethod, "auto_apply")),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(eq(schema.classificationAuditLog.appliedMethod, "manual_approve")),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(eq(schema.classificationAuditLog.appliedMethod, "pending_review")),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(eq(schema.classificationAuditLog.wasReverted, 1)),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(gte(schema.classificationAuditLog.createdAt, now - day)),
    db.select({ count: count() }).from(schema.classificationAuditLog).where(gte(schema.classificationAuditLog.createdAt, now - 7 * day)),
    db.execute(sql`SELECT newType, COUNT(*) as cnt FROM classification_audit_log GROUP BY newType`),
  ]);

  const byType: Record<string, number> = {};
  const typeRows = (byTypeRows as any)?.[0] || byTypeRows;
  if (Array.isArray(typeRows)) {
    for (const row of typeRows) {
      byType[row.newType] = Number(row.cnt);
    }
  }

  return {
    totalClassifications: total[0]?.count || 0,
    autoApplied: autoApplied[0]?.count || 0,
    manualApproved: manualApproved[0]?.count || 0,
    pendingReview: pendingReview[0]?.count || 0,
    reverted: reverted[0]?.count || 0,
    byType,
    last24h: last24h[0]?.count || 0,
    last7d: last7d[0]?.count || 0,
  };
}
