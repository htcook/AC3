/**
 * Auto-Engagement Creator
 *
 * Automatically creates engagements from parsed bug bounty programs when
 * sufficient supporting data exists. Works with any URL — known platforms
 * (HackerOne, Bugcrowd, etc.) and custom/unknown program pages.
 *
 * Criteria for auto-creation:
 *   1. At least 1 in-scope target (domain, URL, IP, or other asset)
 *   2. Program name is resolved (not just a slug)
 *   3. parseConfidence >= 0.5 (meaning real data was fetched, not just skeleton)
 *
 * Flow:
 *   parseBugBountyPolicy → sufficient data? → buildEngagementPreview (LLM) →
 *   createEngagementFromPreview → return engagement ID + all synced assets
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import { engagements, engagementTimelineEvents } from "../../drizzle/schema";
import { eq, and, sql } from "drizzle-orm";

// ─── Types ───

export interface ParsedPolicyResult {
  programName: string;
  platform: string;
  programUrl: string;
  scope: {
    inScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }>;
    outOfScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }>;
  };
  rules: string[];
  rewardRange?: { low: number; high: number; currency: string };
  safeHarbor: boolean;
  responseTimeSla?: { firstResponse: string; triage: string; bountyDecision: string };
  parsedAt: string;
  parseConfidence?: number;
}

export interface AutoEngagementResult {
  created: boolean;
  engagementId?: number;
  engagementName?: string;
  totalAssetsAdded: number;
  reason?: string; // Why it was or wasn't created
  domains: string[];
  ips: string[];
  urls: string[];
}

// ─── Sufficiency Check ───

/**
 * Determine if a parsed policy has enough data to auto-create an engagement.
 */
export function hasSufficientData(policy: ParsedPolicyResult, confidence?: number): { sufficient: boolean; reason: string } {
  const inScopeCount = policy.scope?.inScope?.length || 0;
  const effectiveConfidence = confidence ?? 0.6; // default to 0.6 if not provided

  if (inScopeCount === 0) {
    return { sufficient: false, reason: 'No in-scope targets found' };
  }

  if (!policy.programName || policy.programName === 'unknown') {
    return { sufficient: false, reason: 'Program name could not be resolved' };
  }

  if (effectiveConfidence < 0.5) {
    return { sufficient: false, reason: `Parse confidence too low (${effectiveConfidence}). Need at least 0.5` };
  }

  return { sufficient: true, reason: `${inScopeCount} in-scope targets with confidence ${effectiveConfidence}` };
}

// ─── Duplicate Check ───

/**
 * Check if an engagement already exists for this program URL to avoid duplicates.
 */
async function existingEngagementForProgram(programUrl: string): Promise<number | null> {
  const db = await getDb();
  if (!db) return null;

  try {
    const [existing] = await db
      .select({ id: engagements.id })
      .from(engagements)
      .where(
        and(
          sql`${engagements.bugBountyProgramUrl} = ${programUrl}`,
          sql`${engagements.status} != 'archived'`
        )
      )
      .limit(1);

    return existing?.id || null;
  } catch {
    return null;
  }
}

// ─── Extract Targets ───

/**
 * Extract domains, IPs, and URLs from in-scope targets.
 */
function extractTargets(inScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }>) {
  const domains: string[] = [];
  const ips: string[] = [];
  const urls: string[] = [];

  for (const target of inScope) {
    const val = target.value.trim();
    if (!val || val === 'unknown') continue;

    const lowerType = target.type.toLowerCase();

    if (lowerType === 'ip' || lowerType === 'cidr' || /^\d{1,3}(\.\d{1,3}){3}/.test(val)) {
      ips.push(val);
    } else if (lowerType === 'url' || /^https?:\/\//i.test(val)) {
      urls.push(val);
      // Also extract the hostname
      try {
        const hostname = new URL(val.startsWith('http') ? val : `https://${val}`).hostname;
        if (hostname && !domains.includes(hostname)) domains.push(hostname);
      } catch { /* not a valid URL */ }
    } else if (lowerType === 'domain' || lowerType === 'wildcard' || val.includes('.')) {
      // Strip wildcard prefix for domain matching
      const clean = val.replace(/^\*\./, '');
      if (clean && !domains.includes(clean)) domains.push(clean);
      // Also keep the wildcard version if present
      if (val.startsWith('*.') && !domains.includes(val)) domains.push(val);
    } else if (lowerType === 'source_code' || lowerType === 'hardware' || lowerType === 'other') {
      // Non-network targets — still track them but don't add to domain/IP lists
      // They'll be included in the engagement via the LLM preview
      continue;
    } else {
      // Default: treat as domain if it has a dot
      if (val.includes('.')) domains.push(val);
    }
  }

  return { domains: [...new Set(domains)], ips: [...new Set(ips)], urls: [...new Set(urls)] };
}

// ─── Auto-Create Engagement ───

/**
 * Automatically create an engagement from a parsed bug bounty policy.
 * Uses the LLM engagement builder to generate a full plan, then persists it.
 *
 * @param policy - The parsed policy result from parseBugBountyPolicy
 * @param userId - The user ID creating the engagement
 * @param parseConfidence - The confidence level from the parser (0-1)
 * @returns AutoEngagementResult with creation status and details
 */
export async function autoCreateEngagement(
  policy: ParsedPolicyResult,
  userId: number,
  parseConfidence: number = 0.6,
): Promise<AutoEngagementResult> {
  // 1. Check sufficiency
  const check = hasSufficientData(policy, parseConfidence);
  if (!check.sufficient) {
    return {
      created: false,
      totalAssetsAdded: 0,
      reason: check.reason,
      domains: [],
      ips: [],
      urls: [],
    };
  }

  // 2. Check for duplicate
  const existingId = await existingEngagementForProgram(policy.programUrl);
  if (existingId) {
    return {
      created: false,
      engagementId: existingId,
      totalAssetsAdded: 0,
      reason: `Engagement already exists for this program (ID: ${existingId})`,
      domains: [],
      ips: [],
      urls: [],
    };
  }

  // 3. Extract targets
  const { domains, ips, urls } = extractTargets(policy.scope.inScope);

  // 4. Build engagement preview via LLM
  let preview: any;
  try {
    const { buildEngagementPreview } = await import("./engagement-builder");
    preview = await buildEngagementPreview({
      programUrl: policy.programUrl,
      programName: policy.programName,
      platform: policy.platform,
    });
  } catch (err: any) {
    console.warn(`[AutoEngagement] LLM preview failed for ${policy.programName}:`, err.message);
    // Fallback: create a lightweight engagement without LLM
    return await createLightweightEngagement(policy, userId, domains, ips, urls);
  }

  // 5. Ensure ALL in-scope assets from the parsed policy are in the preview
  // The LLM might miss some — merge them in
  const previewAssetNames = new Set((preview.scope?.assets || []).map((a: any) => a.name?.toLowerCase()));
  for (const target of policy.scope.inScope) {
    const val = target.value.trim();
    if (!val || val === 'unknown') continue;
    if (!previewAssetNames.has(val.toLowerCase())) {
      // Asset was missed by LLM — add it manually
      preview.scope.assets.push({
        name: val,
        type: mapTypeToEngagementType(target.type),
        tier: target.eligible ? 'medium' : 'low',
        description: target.notes || `In-scope ${target.type} target from program policy`,
        eligibleForBounty: target.eligible,
        requiresBuild: false,
        sponsorInstruction: target.notes || null,
      });
    }
  }
  preview.scope.totalAssets = preview.scope.assets.length;

  // 6. Create the engagement from preview
  try {
    const { createEngagementFromPreview } = await import("./engagement-builder");
    const result = await createEngagementFromPreview(preview, userId, {
      scanMode: "active",
    });

    // 7. Also update the engagement with bug bounty metadata and all targets
    const db = await getDb();
    if (db && result.engagementId) {
      const validPlatforms = ['hackerone', 'bugcrowd', 'intigriti', 'synack', 'yeswehack', 'custom'] as const;
      const plat = policy.platform.toLowerCase();
      const updates: any = {
        bugBountyProgramUrl: policy.programUrl,
        targetDomain: domains.join(', '),
        targetIpRange: ips.join(', '),
      };
      if (validPlatforms.includes(plat as any)) {
        updates.bugBountyPlatform = plat;
      } else {
        updates.bugBountyPlatform = 'custom';
      }
      await db.update(engagements).set(updates).where(eq(engagements.id, result.engagementId));
    }

    console.log(`[AutoEngagement] Created engagement #${result.engagementId} for ${policy.programName} (${preview.scope.totalAssets} assets, ${domains.length} domains, ${ips.length} IPs)`);

    return {
      created: true,
      engagementId: result.engagementId,
      engagementName: `${policy.programName} Bug Bounty Engagement`,
      totalAssetsAdded: preview.scope.totalAssets,
      reason: `Auto-created with ${preview.scope.totalAssets} in-scope assets`,
      domains,
      ips,
      urls,
    };
  } catch (err: any) {
    console.error(`[AutoEngagement] Failed to create engagement from preview:`, err.message);
    // Fallback to lightweight
    return await createLightweightEngagement(policy, userId, domains, ips, urls);
  }
}

// ─── Lightweight Fallback ───

/**
 * Create a basic engagement without LLM when the preview fails.
 * Still captures all in-scope assets.
 */
async function createLightweightEngagement(
  policy: ParsedPolicyResult,
  userId: number,
  domains: string[],
  ips: string[],
  urls: string[],
): Promise<AutoEngagementResult> {
  const db = await getDb();
  if (!db) {
    return {
      created: false,
      totalAssetsAdded: 0,
      reason: 'Database not available',
      domains,
      ips,
      urls,
    };
  }

  const engagementName = `${policy.programName} Bug Bounty Engagement`;
  const validPlatforms = ['hackerone', 'bugcrowd', 'intigriti', 'synack', 'yeswehack', 'custom'] as const;
  const plat = policy.platform.toLowerCase();

  // Build ROE scope JSON
  const roeScope = JSON.stringify({
    platform: policy.platform,
    programUrl: policy.programUrl,
    totalAssets: policy.scope.inScope.length,
    rules: policy.rules,
    rewardRange: policy.rewardRange,
    safeHarbor: policy.safeHarbor,
    inScopeTargets: policy.scope.inScope,
    outOfScopeTargets: policy.scope.outOfScope,
  });

  try {
    const [result] = await db.insert(engagements).values({
      name: engagementName,
      customerName: policy.programName,
      description: `Bug bounty engagement against ${policy.programName} via ${policy.platform}. ${policy.scope.inScope.length} in-scope targets. Auto-created by AC3 Auto-Engagement Creator.`,
      engagementType: "bug_bounty",
      status: "planning",
      targetDomain: domains.join(', ') || policy.programName,
      targetIpRange: ips.join(', ') || null,
      roeStatus: "signed",
      roeScope,
      scanMode: "active",
      bugBountyProgramUrl: policy.programUrl,
      bugBountyPlatform: validPlatforms.includes(plat as any) ? plat as any : 'custom',
      notes: JSON.stringify({
        programUrl: policy.programUrl,
        platform: policy.platform,
        generatedAt: new Date().toISOString(),
        generatedBy: "AC3 Auto-Engagement Creator (lightweight)",
        parseConfidence: 'fallback',
      }),
      createdBy: userId,
      autoResumeOnRestart: 1,
    });

    const engagementId = result.insertId;

    // Add timeline events for each in-scope asset
    for (const target of policy.scope.inScope) {
      const val = target.value.trim();
      if (!val || val === 'unknown') continue;

      await db.insert(engagementTimelineEvents).values({
        engagementId,
        eventType: "note_added",
        phase: "recon",
        title: val.substring(0, 255),
        description: `[${target.type}] ${target.eligible ? 'Bounty eligible' : 'No bounty'}${target.notes ? '. ' + target.notes : ''}`,
        timestamp: Date.now(),
        metadata: JSON.stringify({
          type: target.type,
          eligible: target.eligible,
          notes: target.notes,
          source: 'auto-engagement-creator',
        }),
      });
    }

    console.log(`[AutoEngagement] Created lightweight engagement #${engagementId} for ${policy.programName} (${policy.scope.inScope.length} assets)`);

    return {
      created: true,
      engagementId,
      engagementName,
      totalAssetsAdded: policy.scope.inScope.length,
      reason: `Auto-created (lightweight fallback) with ${policy.scope.inScope.length} in-scope assets`,
      domains,
      ips,
      urls,
    };
  } catch (err: any) {
    console.error(`[AutoEngagement] Lightweight creation failed:`, err.message);
    return {
      created: false,
      totalAssetsAdded: 0,
      reason: `Creation failed: ${err.message}`,
      domains,
      ips,
      urls,
    };
  }
}

// ─── Parse Any URL (LLM-powered for unknown platforms) ───

/**
 * Parse any URL for bug bounty program data using LLM.
 * This handles URLs that don't match known platforms (HackerOne, Bugcrowd, etc.)
 * by fetching the page content and using LLM to extract scope information.
 */
export async function parseUnknownProgramUrl(url: string): Promise<ParsedPolicyResult | null> {
  // Fetch the page content
  let pageContent = '';
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'AC3-BugBountyParser/1.0 (Security Research Platform)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) {
      console.warn(`[AutoEngagement] Failed to fetch ${url}: HTTP ${res.status}`);
      return null;
    }
    pageContent = await res.text();
  } catch (err: any) {
    console.warn(`[AutoEngagement] Failed to fetch ${url}: ${err.message}`);
    return null;
  }

  // Truncate to avoid token limits
  const truncated = pageContent.substring(0, 20000);

  // Use LLM to extract program data
  const systemPrompt = `You are a bug bounty program parser. Given the HTML content of a security/bug bounty program page, extract:
1. Program name
2. In-scope targets (domains, URLs, IPs, source code repos, APIs, mobile apps)
3. Out-of-scope targets
4. Rules/restrictions
5. Reward ranges if available
6. Safe harbor status

Return valid JSON matching this schema:
{
  "programName": "string",
  "platform": "custom",
  "inScope": [{ "type": "domain|url|ip|cidr|source_code|mobile_app|other", "value": "string", "eligible": true/false, "notes": "string or null" }],
  "outOfScope": [{ "type": "string", "value": "string", "notes": "string or null" }],
  "rules": ["string array of rules/restrictions"],
  "rewardRange": { "low": number, "high": number, "currency": "$" } or null,
  "safeHarbor": true/false,
  "confidence": 0.0-1.0
}

If the page doesn't appear to be a bug bounty or security program, set confidence to 0 and return empty arrays.
Be thorough — extract ALL in-scope targets mentioned on the page. Include wildcards (*.example.com), specific subdomains, API endpoints, mobile apps, and source code repos.`;

  try {
    const response = await invokeLLM({
      _caller: "auto-engagement-creator:parseUnknownUrl",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Parse this bug bounty/security program page:\n\nURL: ${url}\n\nPAGE CONTENT:\n${truncated}` },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "bug_bounty_program",
          strict: false,
          schema: {
            type: "object",
            properties: {
              programName: { type: "string" },
              platform: { type: "string" },
              inScope: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    type: { type: "string" },
                    value: { type: "string" },
                    eligible: { type: "boolean" },
                    notes: { type: "string" },
                  },
                },
              },
              outOfScope: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    type: { type: "string" },
                    value: { type: "string" },
                    notes: { type: "string" },
                  },
                },
              },
              rules: { type: "array", items: { type: "string" } },
              rewardRange: {
                type: "object",
                properties: {
                  low: { type: "number" },
                  high: { type: "number" },
                  currency: { type: "string" },
                },
              },
              safeHarbor: { type: "boolean" },
              confidence: { type: "number" },
            },
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;

    let parsed: any;
    try {
      parsed = JSON.parse(content);
    } catch {
      const match = content.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (match) parsed = JSON.parse(match[1]);
      else return null;
    }

    if (!parsed.programName || parsed.confidence === 0) {
      return null;
    }

    // Build the PolicyResult format
    const result: ParsedPolicyResult = {
      programName: parsed.programName || 'Unknown Program',
      platform: 'custom',
      programUrl: url,
      scope: {
        inScope: (parsed.inScope || []).map((s: any) => ({
          type: s.type || 'other',
          value: s.value || 'unknown',
          eligible: s.eligible !== false,
          notes: s.notes || undefined,
        })),
        outOfScope: (parsed.outOfScope || []).map((s: any) => ({
          type: s.type || 'other',
          value: s.value || 'unknown',
          eligible: false,
          notes: s.notes || undefined,
        })),
      },
      rules: parsed.rules || [],
      rewardRange: parsed.rewardRange && parsed.rewardRange.high > 0 ? {
        low: parsed.rewardRange.low || 0,
        high: parsed.rewardRange.high || 0,
        currency: parsed.rewardRange.currency || '$',
      } : undefined,
      safeHarbor: !!parsed.safeHarbor,
      parsedAt: new Date().toISOString(),
      parseConfidence: parsed.confidence || 0.5,
    };

    return result;
  } catch (err: any) {
    console.error(`[AutoEngagement] LLM parse failed for ${url}:`, err.message);
    return null;
  }
}

// ─── Helpers ───

function mapTypeToEngagementType(type: string): string {
  const mapping: Record<string, string> = {
    'domain': 'DOMAIN',
    'url': 'URL',
    'ip': 'IP_ADDRESS',
    'cidr': 'CIDR',
    'source_code': 'SOURCE_CODE',
    'mobile_app': 'MOBILE_APPLICATION',
    'wildcard': 'WILDCARD',
    'other': 'OTHER',
  };
  return mapping[type.toLowerCase()] || 'OTHER';
}
