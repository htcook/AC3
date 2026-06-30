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
import { getH1CredentialsForUser } from "./credential-service";
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

// Asset types that require local download, build, and deployment before testing
const BUILDABLE_ASSET_TYPES = new Set([
  'SOURCE_CODE',
  'DOWNLOADABLE_EXECUTABLES',
  'HARDWARE',
  'SMART_CONTRACT',
]);

// Asset types that can be scanned directly over the network
const SCANNABLE_ASSET_TYPES = new Set([
  'URL',
  'DOMAIN',
  'WILDCARD',
  'IP_ADDRESS',
  'CIDR',
  'API',
]);

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

  /** Build/deploy requirements for non-URL assets (source code, executables, etc.) */
  buildRequirements?: BuildRequirement[];

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

export interface BuildRequirement {
  assetName: string;
  assetType: string;
  /** How to obtain the asset (git clone URL, download link, etc.) */
  acquisitionMethod: string;
  /** Build/compile instructions from program sponsor or inferred */
  buildInstructions: string[];
  /** Local deployment instructions (Docker, VM, etc.) */
  deployInstructions: string[];
  /** Dependencies required (language runtimes, databases, etc.) */
  dependencies: string[];
  /** Program sponsor's original instructions (from HackerOne scope instruction field) */
  sponsorInstructions?: string;
  /** Whether the asset can also be tested via a hosted instance */
  hasHostedInstance: boolean;
  /** Hosted instance URL if available */
  hostedInstanceUrl?: string;
}

export interface ScopeAsset {
  name: string;
  type: string; // SOURCE_CODE, URL, DOMAIN, OTHER, DOWNLOADABLE_EXECUTABLES, etc.
  tier: "critical" | "high" | "medium" | "low";
  description: string;
  eligibleForBounty: boolean;
  /** Whether this asset requires local build/deploy before testing */
  requiresBuild?: boolean;
  /** Program sponsor's testing instructions for this specific asset */
  sponsorInstruction?: string;
}

export interface ToolRequirement {
  tool: string;
  installCommand: string;
  purpose: string;
  category: 'SAST' | 'DAST' | 'fuzzer' | 'linter' | 'dependency_audit' | 'custom';
  required: boolean;
  alternatives: string[];
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

  // 2. If we have a program but no scopes in DB, try fetching from HackerOne API directly
  if (programData && (!programData.scopes || programData.scopes.length === 0) && platform === 'hackerone' && programHandle) {
    try {
      console.log(`[EngagementBuilder] No scopes in DB for ${programHandle}, fetching from HackerOne API...`);
      const h1Creds = await getH1CredentialsForUser(); // uses DB-first resolution
      
      if (h1Creds) {
        const h1Username = h1Creds.username;
        const h1Token = h1Creds.apiKey;
        const headers: Record<string, string> = {
          Accept: 'application/json',
          Authorization: 'Basic ' + Buffer.from(`${h1Username}:${h1Token}`).toString('base64'),
        };
        const scopeRes = await fetch(
          `https://api.hackerone.com/v1/hackers/programs/${encodeURIComponent(programHandle)}/structured_scopes?page[number]=1&page[size]=50`,
          { headers, signal: AbortSignal.timeout(15000) }
        );
        if (scopeRes.ok) {
          const scopeData = await scopeRes.json();
          if (scopeData?.data?.length) {
            programData.scopes = scopeData.data.map((item: any) => {
              const attrs = item.attributes || {};
              return {
                id: 0,
                platform: 'hackerone',
                programId: programData!.program.id,
                programHandle,
                externalId: String(item.id),
                assetType: attrs.asset_type || 'OTHER',
                assetIdentifier: attrs.asset_identifier || 'unknown',
                eligibleForBounty: attrs.eligible_for_bounty ? 1 : 0,
                eligibleForSubmission: attrs.eligible_for_submission !== false ? 1 : 0,
                maxSeverity: attrs.max_severity || null,
                confidentialityRequirement: attrs.confidentiality_requirement || null,
                integrityRequirement: attrs.integrity_requirement || null,
                availabilityRequirement: attrs.availability_requirement || null,
                instruction: attrs.instruction || null,
                createdAt: null,
                updatedAt: null,
              };
            });
            console.log(`[EngagementBuilder] Fetched ${programData.scopes.length} scopes from HackerOne API for ${programHandle} (creds source: ${h1Creds.source})`);
          }
        }
      }
    } catch (err: any) {
      console.warn(`[EngagementBuilder] Failed to fetch scopes from HackerOne API: ${err.message}`);
    }
  }

  // 3. Also try extracting handle from URL if not set
  if (!programHandle && programUrl) {
    try {
      const urlObj = new URL(programUrl);
      if (urlObj.hostname === 'hackerone.com') {
        const pathParts = urlObj.pathname.split('/').filter(Boolean);
        if (pathParts.length > 0) {
          programHandle = pathParts[0];
          programName = programName || programHandle;
        }
      }
    } catch {}
  }

  // 4. Fetch program page for additional context
  if (programUrl) {
    pageContent = await fetchProgramPage(programUrl);
  }

  // 5. Identify buildable vs scannable assets and include sponsor instructions
  const buildableAssets = programData?.scopes?.filter(s => BUILDABLE_ASSET_TYPES.has(s.assetType)) || [];
  const scannableAssets = programData?.scopes?.filter(s => SCANNABLE_ASSET_TYPES.has(s.assetType)) || [];
  const otherAssets = programData?.scopes?.filter(s => !BUILDABLE_ASSET_TYPES.has(s.assetType) && !SCANNABLE_ASSET_TYPES.has(s.assetType)) || [];

  // Build the LLM prompt with all available data
  const scopeContext = programData?.scopes?.length
    ? `\n\nKNOWN SCOPE ASSETS (${programData.scopes.length} total):\n${programData.scopes
        .map(
          (s) => {
            let line = `- [${s.assetType}] ${s.assetIdentifier} (bounty: ${s.eligibleForBounty ? "yes" : "no"}, max_severity: ${s.maxSeverity || "unknown"})`;
            if (s.instruction) line += `\n  SPONSOR INSTRUCTIONS: ${s.instruction}`;
            if (BUILDABLE_ASSET_TYPES.has(s.assetType)) line += `\n  ⚠️ REQUIRES LOCAL BUILD: This asset must be downloaded, built, and deployed locally before testing.`;
            return line;
          }
        )
        .join("\n")}`
    : "";

  const buildableContext = buildableAssets.length > 0
    ? `\n\n⚠️ BUILDABLE ASSETS DETECTED (${buildableAssets.length}):\nThe following assets are SOURCE_CODE or DOWNLOADABLE_EXECUTABLES and CANNOT be scanned over the network. They must be:\n1. Downloaded/cloned to a local test environment\n2. Built and compiled according to the project's build system\n3. Deployed locally (Docker, VM, or bare metal) before any scanning or exploitation\n\n${buildableAssets.map(a => `- [${a.assetType}] ${a.assetIdentifier}${a.instruction ? `\n  Program sponsor says: "${a.instruction}"` : ''}`).join('\n')}\n\nYou MUST include buildRequirements for each buildable asset in your response.`
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
    "assets": [{ "name": "string", "type": "SOURCE_CODE|URL|DOMAIN|OTHER|DOWNLOADABLE_EXECUTABLES|HARDWARE|SMART_CONTRACT", "tier": "critical|high|medium|low", "description": "string", "eligibleForBounty": true/false, "requiresBuild": true/false, "sponsorInstruction": "string or null" }],
    "assetCategories": { "category_name": count }
  },
  "buildRequirements": [
    {
      "assetName": "the asset identifier (e.g., https://github.com/nodejs/node)",
      "assetType": "SOURCE_CODE or DOWNLOADABLE_EXECUTABLES",
      "acquisitionMethod": "how to obtain (git clone URL, download link, etc.)",
      "buildInstructions": ["step-by-step build commands"],
      "deployInstructions": ["step-by-step local deployment commands (Docker preferred)"],
      "dependencies": ["language runtimes, databases, libraries needed"],
      "sponsorInstructions": "original instructions from the program sponsor if available, or null",
      "hasHostedInstance": false,
      "hostedInstanceUrl": "URL if a hosted test instance exists, or null"
    }
  ],
  "toolRequirements": [
    {
      "tool": "tool name (e.g., semgrep, gosec, slither)",
      "installCommand": "command to install the tool (e.g., pip install semgrep)",
      "purpose": "why this tool is needed for this specific program",
      "category": "SAST|DAST|fuzzer|linter|dependency_audit|custom",
      "required": true/false,
      "alternatives": ["alternative tools if primary is unavailable"]
    }
  ],
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
- Success metrics should be realistic and measurable

BUILDABLE ASSET RULES:
- For SOURCE_CODE assets: set requiresBuild=true, include git clone + build + deploy steps in buildRequirements
- For DOWNLOADABLE_EXECUTABLES: set requiresBuild=true, include download + setup steps
- For SMART_CONTRACT assets: set requiresBuild=true, include local chain deployment steps
- For URL/DOMAIN assets: set requiresBuild=false
- If the program sponsor provided testing instructions (in the scope instruction field), include them verbatim in sponsorInstructions
- buildRequirements MUST include realistic build commands based on the project's actual tech stack (check README, package.json, Makefile, etc.)
- deployInstructions should prefer Docker containerization for isolation

TOOL REQUIREMENTS RULES:
- Analyze the target's tech stack and determine what specialized tools are needed beyond the standard arsenal
- For JavaScript/TypeScript: include semgrep, eslint-security, retire.js, npm audit
- For Python: include bandit, safety, semgrep
- For Go: include gosec, staticcheck
- For Rust: include cargo-audit, cargo-deny
- For Solidity/Smart Contracts: include slither, mythril, echidna
- For C/C++: include cppcheck, flawfinder, AFL++
- Include installCommand that works on Ubuntu 22.04
- Mark tools as required=true if they are essential for the target's primary language
- Include alternatives for each tool in case the primary is unavailable`;

  const userPrompt = `Build a complete bug bounty engagement plan for:

PROGRAM: ${programName}
HANDLE: ${programHandle}
PLATFORM: ${platform}
URL: ${programUrl}
${scopeContext}
${weaknessContext}
${findingsContext}

${buildableContext}
${pageContent ? `\nPROGRAM PAGE CONTENT (partial):\n${pageContent.substring(0, 8000)}` : ""}

Generate the full engagement plan JSON. Be thorough — include all known assets, realistic tooling, and a detailed phase plan.
${buildableAssets.length > 0 ? '\nCRITICAL: This program has SOURCE_CODE/DOWNLOADABLE assets. You MUST include buildRequirements with real build/deploy instructions. Do NOT attempt to scan these as live URLs.' : ''}
Always include toolRequirements based on the target tech stack — analyze what specialized security tools are needed beyond standard web scanners.`;

  const response = await invokeLLM({
    _caller: "engagement-builder:buildEngagementPlan",
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
                      requiresBuild: { type: "boolean" },
                      sponsorInstruction: { type: "string" },
                    },
                  },
                },
                assetCategories: { type: "object" },
              },
            },
            buildRequirements: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  assetName: { type: "string" },
                  assetType: { type: "string" },
                  acquisitionMethod: { type: "string" },
                  buildInstructions: { type: "array", items: { type: "string" } },
                  deployInstructions: { type: "array", items: { type: "string" } },
                  dependencies: { type: "array", items: { type: "string" } },
                  sponsorInstructions: { type: "string" },
                  hasHostedInstance: { type: "boolean" },
                  hostedInstanceUrl: { type: "string" },
                },
              },
            },
            toolRequirements: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  tool: { type: "string" },
                  installCommand: { type: "string" },
                  purpose: { type: "string" },
                  category: { type: "string" },
                  required: { type: "boolean" },
                  alternatives: { type: "array", items: { type: "string" } },
                },
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

  // Post-process: mark buildable assets and attach sponsor instructions
  const scopeAssets = (plan.scope?.assets || []).map((a: any) => ({
    ...a,
    requiresBuild: a.requiresBuild ?? BUILDABLE_ASSET_TYPES.has(a.type),
    sponsorInstruction: a.sponsorInstruction || null,
  }));

  return {
    programName,
    programHandle,
    platform,
    programUrl,
    roe: plan.roe || { prohibitedActions: [], mandatoryRequirements: [], eligibleVersions: [], bountyRange: { low: 0, medium: 0, high: 0, critical: 0 }, outOfScope: [] },
    scope: { ...(plan.scope || { totalAssets: 0, assetCategories: {} }), assets: scopeAssets },
    buildRequirements: plan.buildRequirements || [],
    testEnvironment: plan.testEnvironment || { infrastructure: "", primaryLab: "", secondaryLab: "", requiredServices: [], testUsers: [], toolingArsenal: {} },
    phases: plan.phases || [],
    vulnerabilityPatterns: plan.vulnerabilityPatterns || [],
    successMetrics: plan.successMetrics || {},
    toolRequirements: plan.toolRequirements || [],
  } as EngagementPreview & { toolRequirements: ToolRequirement[] };
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

  // Identify buildable assets and tool requirements
  const buildableAssets = preview.scope.assets.filter(a => a.requiresBuild || BUILDABLE_ASSET_TYPES.has(a.type));
  const hasBuildableAssets = buildableAssets.length > 0;
  const extPreview = preview as EngagementPreview & { toolRequirements?: ToolRequirement[] };

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
    // Build & deploy requirements for downloadable assets
    buildRequirements: preview.buildRequirements || [],
    // Specialized tool requirements from LLM analysis
    toolRequirements: extPreview.toolRequirements || [],
    // Flag indicating this engagement has assets that need local build/deploy
    requiresAssetProvisioning: hasBuildableAssets,
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

  // 4. Create provisioning timeline events for buildable assets
  if (hasBuildableAssets && preview.buildRequirements) {
    for (const br of preview.buildRequirements) {
      await db.insert(engagementTimelineEvents).values({
        engagementId: engagementId,
        eventType: "note_added",
        phase: "setup",
        title: `Build Required: ${br.assetName}`.substring(0, 255),
        description: `Asset type: ${br.assetType}. Acquisition: ${br.acquisitionMethod}. Dependencies: ${br.dependencies?.join(', ') || 'none'}. ${br.sponsorInstructions ? 'Sponsor instructions: ' + br.sponsorInstructions : ''}`,
        timestamp: Date.now(),
        metadata: JSON.stringify({
          type: 'build_requirement',
          assetName: br.assetName,
          assetType: br.assetType,
          acquisitionMethod: br.acquisitionMethod,
          buildInstructions: br.buildInstructions,
          deployInstructions: br.deployInstructions,
          dependencies: br.dependencies,
          sponsorInstructions: br.sponsorInstructions,
          hasHostedInstance: br.hasHostedInstance,
          hostedInstanceUrl: br.hostedInstanceUrl,
        }),
      });
      timelineEventCount++;
    }
  }

  // 4b. Create tool installation timeline events
  if (extPreview.toolRequirements && extPreview.toolRequirements.length > 0) {
    const requiredTools = extPreview.toolRequirements.filter(t => t.required);
    const optionalTools = extPreview.toolRequirements.filter(t => !t.required);
    if (requiredTools.length > 0) {
      await db.insert(engagementTimelineEvents).values({
        engagementId: engagementId,
        eventType: "note_added",
        phase: "setup",
        title: `Required Tools: ${requiredTools.map(t => t.tool).join(', ')}`.substring(0, 255),
        description: requiredTools.map(t => `${t.tool} (${t.category}): ${t.purpose} — Install: ${t.installCommand}`).join('\n'),
        timestamp: Date.now(),
        metadata: JSON.stringify({
          type: 'tool_requirements',
          required: true,
          tools: requiredTools,
        }),
      });
      timelineEventCount++;
    }
    if (optionalTools.length > 0) {
      await db.insert(engagementTimelineEvents).values({
        engagementId: engagementId,
        eventType: "note_added",
        phase: "setup",
        title: `Optional Tools: ${optionalTools.map(t => t.tool).join(', ')}`.substring(0, 255),
        description: optionalTools.map(t => `${t.tool} (${t.category}): ${t.purpose} — Install: ${t.installCommand}`).join('\n'),
        timestamp: Date.now(),
        metadata: JSON.stringify({
          type: 'tool_requirements',
          required: false,
          tools: optionalTools,
        }),
      });
      timelineEventCount++;
    }
  }

  // 5. Also populate bug_bounty_program_scopes if not already present
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
  // Try to find a URL or domain asset from scope
  const domainAsset = preview.scope.assets.find(
    (a) => a.type === "URL" || a.type === "DOMAIN"
  );
  if (domainAsset) return domainAsset.name;

  // Try SOURCE_CODE assets (e.g., GitHub repos)
  const sourceAsset = preview.scope.assets.find(
    (a) => a.type === "SOURCE_CODE"
  );
  if (sourceAsset) {
    // Extract domain from source code URL (e.g., github.com/nodejs/node → github.com)
    try {
      const url = new URL(sourceAsset.name);
      return url.hostname;
    } catch {
      return sourceAsset.name;
    }
  }

  // Any asset at all
  if (preview.scope.assets.length > 0) {
    return preview.scope.assets[0].name;
  }

  // IMPORTANT: Do NOT extract hostname from programUrl — that gives us the platform
  // domain (e.g., hackerone.com) instead of the actual target.
  // Use the program handle or name as the engagement identifier.
  return preview.programHandle || preview.programName;
}
