/**
 * Engagement Builder — LLM-Powered Program Scanner
 *
 * Scans a bug bounty program page (HackerOne, Bugcrowd, etc.) and uses LLM
 * to automatically build:
 *   - Rules of Engagement (ROE) with prohibitions and requirements
 *   - Structured scope (asset list with types, tiers, and descriptions)
 *   - Test environment requirements (infrastructure, tools, users)
 *   - Engagement phases with timeline and focus areas
 *
 * The builder can work from:
 *   1. An existing synced program in the DB (uses stored scope/weakness data)
 *   2. A program URL (fetches and parses the page)
 *   3. Manual input (user provides program details)
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import {
  bugBountyPrograms,
  bugBountyProgramScopes,
  bugBountyProgramWeaknesses,
  bugBountyFindings,
  engagements,
  engagementTimelineEvents,
} from "../../drizzle/schema";
import { eq, and, sql, desc } from "drizzle-orm";

// ─── Types ───

export interface EngagementPreview {
  programName: string;
  programHandle: string;
  platform: string;
  programUrl: string;

  roe: {
    prohibitedActions: string[];
    mandatoryRequirements: string[];
    eligibleVersions: string[];
    bountyRange: { low: number; medium: number; high: number; critical: number };
    outOfScope: string[];
  };

  scope: {
    totalAssets: number;
    assets: ScopeAsset[];
    assetCategories: Record<string, number>;
  };

  testEnvironment: {
    infrastructure: string;
    primaryLab: string;
    secondaryLab: string;
    requiredServices: string[];
    testUsers: string[];
    toolingArsenal: Record<string, string[]>;
  };

  phases: EngagementPhase[];

  vulnerabilityPatterns: string[];
  successMetrics: Record<string, string>;
}

export interface ScopeAsset {
  name: string;
  type: string; // SOURCE_CODE, URL, DOMAIN, OTHER, DOWNLOADABLE_EXECUTABLES, etc.
  tier: "critical" | "high" | "medium" | "low";
  description: string;
  eligibleForBounty: boolean;
}

export interface EngagementPhase {
  name: string;
  week: string;
  focus: string;
  tools: string[];
  deliverables: string[];
}

// ─── Fetch program data from DB ───

async function fetchProgramData(programId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const [program] = await db
    .select()
    .from(bugBountyPrograms)
    .where(eq(bugBountyPrograms.id, programId))
    .limit(1);

  if (!program) throw new Error(`Program not found: ${programId}`);

  const scopes = await db
    .select()
    .from(bugBountyProgramScopes)
    .where(eq(bugBountyProgramScopes.programId, programId));

  const weaknesses = await db
    .select()
    .from(bugBountyProgramWeaknesses)
    .where(eq(bugBountyProgramWeaknesses.programId, programId));

  // Get recent findings for this program to understand vulnerability patterns
  const findings = await db
    .select()
    .from(bugBountyFindings)
    .where(eq(bugBountyFindings.programHandle, program.handle))
    .orderBy(desc(bugBountyFindings.disclosedAt))
    .limit(50);

  return { program, scopes, weaknesses, findings };
}

// ─── Fetch program page for additional context ───

async function fetchProgramPage(url: string): Promise<string> {
  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": "AC3-EngagementBuilder/1.0",
        Accept: "text/html,application/json",
      },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return `[Failed to fetch: HTTP ${res.status}]`;
    const text = await res.text();
    // Truncate to avoid token limits
    return text.substring(0, 15000);
  } catch (err: any) {
    return `[Failed to fetch: ${err.message}]`;
  }
}

// ─── LLM-Powered Engagement Builder ───

export async function buildEngagementPreview(input: {
  programId?: number;
  programUrl?: string;
  programName?: string;
  platform?: string;
}): Promise<EngagementPreview> {
  let programData: Awaited<ReturnType<typeof fetchProgramData>> | null = null;
  let pageContent = "";
  let programName = input.programName || "Unknown Program";
  let programHandle = "";
  let platform = input.platform || "hackerone";
  let programUrl = input.programUrl || "";

  // 1. Fetch from DB if we have a programId
  if (input.programId) {
    programData = await fetchProgramData(input.programId);
    programName = programData.program.name;
    programHandle = programData.program.handle;
    platform = programData.program.platform;
    programUrl = programData.program.url || `https://hackerone.com/${programHandle}`;
  }

  // 2. Fetch program page for additional context
  if (programUrl) {
    pageContent = await fetchProgramPage(programUrl);
  }

  // 3. Build the LLM prompt with all available data
  const scopeContext = programData?.scopes?.length
    ? `\n\nKNOWN SCOPE ASSETS (${programData.scopes.length} total):\n${programData.scopes
        .map(
          (s) =>
            `- [${s.assetType}] ${s.assetIdentifier} (bounty: ${s.eligibleForBounty ? "yes" : "no"}, max_severity: ${s.maxSeverity || "unknown"})`
        )
        .join("\n")}`
    : "";

  const weaknessContext = programData?.weaknesses?.length
    ? `\n\nKNOWN WEAKNESS CATEGORIES (${programData.weaknesses.length}):\n${programData.weaknesses
        .slice(0, 30)
        .map((w) => `- ${w.cweId || ""} ${w.name}`)
        .join("\n")}`
    : "";

  const findingsContext = programData?.findings?.length
    ? `\n\nRECENT DISCLOSED FINDINGS (${programData.findings.length}):\n${programData.findings
        .slice(0, 20)
        .map(
          (f) =>
            `- [${f.severityRating}] ${f.title} (CWE: ${f.cweId || "N/A"}, CVE: ${(f.cveIds as string[])?.join(",") || "N/A"}, bounty: $${f.awardedAmount || 0})`
        )
        .join("\n")}`
    : "";

  const systemPrompt = `You are an expert penetration tester and bug bounty engagement planner for AC3, a MITRE Caldera-based threat intelligence platform. Your job is to analyze a bug bounty program and generate a comprehensive engagement plan.

You must output valid JSON matching this exact schema:
{
  "roe": {
    "prohibitedActions": ["string array of things NOT allowed"],
    "mandatoryRequirements": ["string array of required practices"],
    "eligibleVersions": ["string array of eligible software versions"],
    "bountyRange": { "low": number, "medium": number, "high": number, "critical": number },
    "outOfScope": ["string array of out-of-scope items"]
  },
  "scope": {
    "totalAssets": number,
    "assets": [{ "name": "string", "type": "SOURCE_CODE|URL|DOMAIN|OTHER|DOWNLOADABLE_EXECUTABLES|HARDWARE|SMART_CONTRACT", "tier": "critical|high|medium|low", "description": "string", "eligibleForBounty": true/false }],
    "assetCategories": { "category_name": count }
  },
  "testEnvironment": {
    "infrastructure": "Docker Compose or VM description",
    "primaryLab": "Primary test environment description",
    "secondaryLab": "Secondary/fallback environment",
    "requiredServices": ["list of services needed"],
    "testUsers": ["list of test user accounts to create"],
    "toolingArsenal": { "category": ["tool1", "tool2"] }
  },
  "phases": [{ "name": "string", "week": "1", "focus": "description", "tools": ["tool1"], "deliverables": ["deliverable1"] }],
  "vulnerabilityPatterns": ["string array of likely vulnerability patterns based on the tech stack"],
  "successMetrics": { "metric_name": "target_value" }
}

IMPORTANT RULES:
- Base bounty ranges on actual program data when available, otherwise use industry standards
- Tier assets by security impact: critical (auth, crypto, RCE surfaces), high (data access, SSRF), medium (XSS, info disclosure), low (cosmetic)
- Test environment must be self-hosted — never test against production infrastructure
- Phases should follow a logical progression: recon → SAST → DAST → specialized → reporting
- Include specific tools for each phase (open source preferred)
- Vulnerability patterns should be specific to the target's technology stack
- Success metrics should be realistic and measurable`;

  const userPrompt = `Build a complete bug bounty engagement plan for:

PROGRAM: ${programName}
HANDLE: ${programHandle}
PLATFORM: ${platform}
URL: ${programUrl}
${scopeContext}
${weaknessContext}
${findingsContext}

${pageContent ? `\nPROGRAM PAGE CONTENT (partial):\n${pageContent.substring(0, 8000)}` : ""}

Generate the full engagement plan JSON. Be thorough — include all known assets, realistic tooling, and a detailed phase plan.`;

  const response = await invokeLLM({
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "engagement_plan",
        strict: false,
        schema: {
          type: "object",
          properties: {
            roe: {
              type: "object",
              properties: {
                prohibitedActions: { type: "array", items: { type: "string" } },
                mandatoryRequirements: { type: "array", items: { type: "string" } },
                eligibleVersions: { type: "array", items: { type: "string" } },
                bountyRange: {
                  type: "object",
                  properties: {
                    low: { type: "number" },
                    medium: { type: "number" },
                    high: { type: "number" },
                    critical: { type: "number" },
                  },
                },
                outOfScope: { type: "array", items: { type: "string" } },
              },
            },
            scope: {
              type: "object",
              properties: {
                totalAssets: { type: "number" },
                assets: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      name: { type: "string" },
                      type: { type: "string" },
                      tier: { type: "string" },
                      description: { type: "string" },
                      eligibleForBounty: { type: "boolean" },
                    },
                  },
                },
                assetCategories: { type: "object" },
              },
            },
            testEnvironment: {
              type: "object",
              properties: {
                infrastructure: { type: "string" },
                primaryLab: { type: "string" },
                secondaryLab: { type: "string" },
                requiredServices: { type: "array", items: { type: "string" } },
                testUsers: { type: "array", items: { type: "string" } },
                toolingArsenal: { type: "object" },
              },
            },
            phases: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  week: { type: "string" },
                  focus: { type: "string" },
                  tools: { type: "array", items: { type: "string" } },
                  deliverables: { type: "array", items: { type: "string" } },
                },
              },
            },
            vulnerabilityPatterns: { type: "array", items: { type: "string" } },
            successMetrics: { type: "object" },
          },
        },
      },
    },
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content) throw new Error("LLM returned empty response");

  let plan: any;
  try {
    plan = JSON.parse(content);
  } catch {
    // Try to extract JSON from markdown code blocks
    const match = content.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (match) {
      plan = JSON.parse(match[1]);
    } else {
      throw new Error("Failed to parse LLM response as JSON");
    }
  }

  return {
    programName,
    programHandle,
    platform,
    programUrl,
    roe: plan.roe || { prohibitedActions: [], mandatoryRequirements: [], eligibleVersions: [], bountyRange: { low: 0, medium: 0, high: 0, critical: 0 }, outOfScope: [] },
    scope: plan.scope || { totalAssets: 0, assets: [], assetCategories: {} },
    testEnvironment: plan.testEnvironment || { infrastructure: "", primaryLab: "", secondaryLab: "", requiredServices: [], testUsers: [], toolingArsenal: {} },
    phases: plan.phases || [],
    vulnerabilityPatterns: plan.vulnerabilityPatterns || [],
    successMetrics: plan.successMetrics || {},
  };
}

// ─── Create Engagement from Preview ───

export async function createEngagementFromPreview(
  preview: EngagementPreview,
  userId: number,
  options?: {
    customName?: string;
    scanMode?: "strict_passive" | "standard" | "active";
  }
): Promise<{ engagementId: number; timelineEventCount: number; scopeAssetCount: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const engagementName =
    options?.customName || `${preview.programName} Bug Bounty Engagement`;

  // Build ROE scope JSON (stored in roe_scope column)
  const roeScope = JSON.stringify({
    platform: preview.platform,
    programUrl: preview.programUrl,
    totalAssets: preview.scope.totalAssets,
    assetCategories: preview.scope.assetCategories,
    bountyRange: preview.roe.bountyRange,
    prohibitedActions: preview.roe.prohibitedActions,
    mandatoryRequirements: preview.roe.mandatoryRequirements,
    eligibleVersions: preview.roe.eligibleVersions,
    outOfScope: preview.roe.outOfScope,
    highValueTargets: categorizeAssetsByTier(preview.scope.assets),
    testEnvironment: preview.testEnvironment,
    toolingArsenal: preview.testEnvironment.toolingArsenal,
    engagementPhases: preview.phases.map((p) => ({
      week: p.week,
      phase: p.name,
      focus: p.focus,
    })),
    vulnerabilityPatterns: preview.vulnerabilityPatterns,
    successMetrics: preview.successMetrics,
  });

  const notesJson = JSON.stringify({
    programUrl: preview.programUrl,
    platform: preview.platform,
    programHandle: preview.programHandle,
    generatedAt: new Date().toISOString(),
    generatedBy: "AC3 Engagement Builder",
  });

  // 1. Create the engagement
  const [result] = await db.insert(engagements).values({
    name: engagementName,
    customerName: preview.programName,
    description: `Bug bounty engagement against ${preview.programName} via ${preview.platform}. ${preview.scope.totalAssets} in-scope assets across ${Object.keys(preview.scope.assetCategories).length} categories. Auto-generated by AC3 Engagement Builder.`,
    engagementType: "bug_bounty",
    status: "planning",
    targetDomain: extractPrimaryDomain(preview),
    roeStatus: "signed",
    roeScope,
    scanMode: options?.scanMode || "active",
    notes: notesJson,
    createdBy: userId,
    autoResumeOnRestart: 1,
  });

  const engagementId = result.insertId;

  // 2. Create timeline events for each phase
  let timelineEventCount = 0;
  for (const phase of preview.phases) {
    const ts = Date.now() + parseInt(phase.week || "1") * 7 * 24 * 60 * 60 * 1000;
    // Truncate phase name to 64 chars for the DB column
    const phaseName = phase.name.substring(0, 64);
    await db.insert(engagementTimelineEvents).values({
      engagementId: engagementId,
      eventType: "phase_started",
      phase: phaseName,
      title: `Phase: ${phaseName}`,
      description: phase.focus,
      timestamp: ts,
      metadata: JSON.stringify({
        week: phase.week,
        tools: phase.tools,
        deliverables: phase.deliverables,
      }),
    });
    timelineEventCount++;
  }

  // 3. Create scope asset timeline events
  let scopeAssetCount = 0;
  for (const asset of preview.scope.assets) {
    await db.insert(engagementTimelineEvents).values({
      engagementId: engagementId,
      eventType: "note_added",
      phase: "recon",
      title: asset.name.substring(0, 255),
      description: asset.description,
      timestamp: Date.now(),
      metadata: JSON.stringify({
        tier: asset.tier,
        type: asset.type,
        eligibleForBounty: asset.eligibleForBounty,
        program: preview.programHandle,
      }),
    });
    scopeAssetCount++;
  }

  // 4. Also populate bug_bounty_program_scopes if not already present
  if (preview.scope.assets.length > 0) {
    const [existing] = await db.execute(
      sql`SELECT COUNT(*) as cnt FROM bug_bounty_program_scopes WHERE program_handle = ${preview.programHandle}`
    );
    if ((existing as any)?.cnt === 0 || (existing as any)?.[0]?.cnt === 0) {
      for (const asset of preview.scope.assets) {
        try {
          await db.insert(bugBountyProgramScopes).values({
            platform: preview.platform as any,
            programHandle: preview.programHandle,
            assetType: asset.type,
            assetIdentifier: asset.name,
            eligibleForBounty: asset.eligibleForBounty ? 1 : 0,
            eligibleForSubmission: 1,
            maxSeverity: asset.tier,
            instruction: asset.description,
          });
        } catch {
          // Skip duplicates
        }
      }
    }
  }

  return { engagementId, timelineEventCount, scopeAssetCount };
}

// ─── Helpers ───

function categorizeAssetsByTier(assets: ScopeAsset[]): Record<string, string[]> {
  const result: Record<string, string[]> = {
    tier1_critical: [],
    tier2_high: [],
    tier3_medium: [],
    tier4_low: [],
  };
  for (const a of assets) {
    const key = `tier${a.tier === "critical" ? 1 : a.tier === "high" ? 2 : a.tier === "medium" ? 3 : 4}_${a.tier}`;
    if (result[key]) result[key].push(a.name);
  }
  return result;
}

function extractPrimaryDomain(preview: EngagementPreview): string {
  // Try to find a URL or domain asset
  const domainAsset = preview.scope.assets.find(
    (a) => a.type === "URL" || a.type === "DOMAIN"
  );
  if (domainAsset) return domainAsset.name;

  // Try to extract from program URL
  try {
    const url = new URL(preview.programUrl);
    return url.hostname;
  } catch {
    return preview.programHandle || preview.programName;
  }
}
