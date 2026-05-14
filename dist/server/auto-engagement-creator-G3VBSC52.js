import {
  init_llm,
  invokeLLM
} from "./chunk-L5VXSJ4F.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-JZVHFV6D.js";
import "./chunk-GN2OC6SU.js";
import {
  engagementTimelineEvents,
  engagements,
  init_schema
} from "./chunk-IG2G4XDA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/auto-engagement-creator.ts
init_llm();
init_db();
init_schema();
import { eq, and, sql } from "drizzle-orm";
function hasSufficientData(policy, confidence) {
  const inScopeCount = policy.scope?.inScope?.length || 0;
  const effectiveConfidence = confidence ?? 0.6;
  if (inScopeCount === 0) {
    return { sufficient: false, reason: "No in-scope targets found" };
  }
  if (!policy.programName || policy.programName === "unknown") {
    return { sufficient: false, reason: "Program name could not be resolved" };
  }
  if (effectiveConfidence < 0.5) {
    return { sufficient: false, reason: `Parse confidence too low (${effectiveConfidence}). Need at least 0.5` };
  }
  return { sufficient: true, reason: `${inScopeCount} in-scope targets with confidence ${effectiveConfidence}` };
}
async function existingEngagementForProgram(programUrl) {
  const db = await getDb();
  if (!db) return null;
  try {
    const [existing] = await db.select({ id: engagements.id }).from(engagements).where(
      and(
        sql`${engagements.bugBountyProgramUrl} = ${programUrl}`,
        sql`${engagements.status} != 'archived'`
      )
    ).limit(1);
    return existing?.id || null;
  } catch {
    return null;
  }
}
function extractTargets(inScope) {
  const domains = [];
  const ips = [];
  const urls = [];
  for (const target of inScope) {
    const val = target.value.trim();
    if (!val || val === "unknown") continue;
    const lowerType = target.type.toLowerCase();
    if (lowerType === "ip" || lowerType === "cidr" || /^\d{1,3}(\.\d{1,3}){3}/.test(val)) {
      ips.push(val);
    } else if (lowerType === "url" || /^https?:\/\//i.test(val)) {
      urls.push(val);
      try {
        const hostname = new URL(val.startsWith("http") ? val : `https://${val}`).hostname;
        if (hostname && !domains.includes(hostname)) domains.push(hostname);
      } catch {
      }
    } else if (lowerType === "domain" || lowerType === "wildcard" || val.includes(".")) {
      const clean = val.replace(/^\*\./, "");
      if (clean && !domains.includes(clean)) domains.push(clean);
      if (val.startsWith("*.") && !domains.includes(val)) domains.push(val);
    } else if (lowerType === "source_code" || lowerType === "hardware" || lowerType === "other") {
      continue;
    } else {
      if (val.includes(".")) domains.push(val);
    }
  }
  return { domains: [...new Set(domains)], ips: [...new Set(ips)], urls: [...new Set(urls)] };
}
async function autoCreateEngagement(policy, userId, parseConfidence = 0.6) {
  const check = hasSufficientData(policy, parseConfidence);
  if (!check.sufficient) {
    return {
      created: false,
      totalAssetsAdded: 0,
      reason: check.reason,
      domains: [],
      ips: [],
      urls: []
    };
  }
  const existingId = await existingEngagementForProgram(policy.programUrl);
  if (existingId) {
    return {
      created: false,
      engagementId: existingId,
      totalAssetsAdded: 0,
      reason: `Engagement already exists for this program (ID: ${existingId})`,
      domains: [],
      ips: [],
      urls: []
    };
  }
  const { domains, ips, urls } = extractTargets(policy.scope.inScope);
  let preview;
  try {
    const { buildEngagementPreview } = await import("./engagement-builder-J3L33PDU.js");
    preview = await buildEngagementPreview({
      programUrl: policy.programUrl,
      programName: policy.programName,
      platform: policy.platform
    });
  } catch (err) {
    console.warn(`[AutoEngagement] LLM preview failed for ${policy.programName}:`, err.message);
    return await createLightweightEngagement(policy, userId, domains, ips, urls);
  }
  const previewAssetNames = new Set((preview.scope?.assets || []).map((a) => a.name?.toLowerCase()));
  for (const target of policy.scope.inScope) {
    const val = target.value.trim();
    if (!val || val === "unknown") continue;
    if (!previewAssetNames.has(val.toLowerCase())) {
      preview.scope.assets.push({
        name: val,
        type: mapTypeToEngagementType(target.type),
        tier: target.eligible ? "medium" : "low",
        description: target.notes || `In-scope ${target.type} target from program policy`,
        eligibleForBounty: target.eligible,
        requiresBuild: false,
        sponsorInstruction: target.notes || null
      });
    }
  }
  preview.scope.totalAssets = preview.scope.assets.length;
  try {
    const { createEngagementFromPreview } = await import("./engagement-builder-J3L33PDU.js");
    const result = await createEngagementFromPreview(preview, userId, {
      scanMode: "active"
    });
    const db = await getDb();
    if (db && result.engagementId) {
      const validPlatforms = ["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "custom"];
      const plat = policy.platform.toLowerCase();
      const updates = {
        bugBountyProgramUrl: policy.programUrl,
        targetDomain: domains.join(", "),
        targetIpRange: ips.join(", ")
      };
      if (validPlatforms.includes(plat)) {
        updates.bugBountyPlatform = plat;
      } else {
        updates.bugBountyPlatform = "custom";
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
      urls
    };
  } catch (err) {
    console.error(`[AutoEngagement] Failed to create engagement from preview:`, err.message);
    return await createLightweightEngagement(policy, userId, domains, ips, urls);
  }
}
async function createLightweightEngagement(policy, userId, domains, ips, urls) {
  const db = await getDb();
  if (!db) {
    return {
      created: false,
      totalAssetsAdded: 0,
      reason: "Database not available",
      domains,
      ips,
      urls
    };
  }
  const engagementName = `${policy.programName} Bug Bounty Engagement`;
  const validPlatforms = ["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "custom"];
  const plat = policy.platform.toLowerCase();
  const roeScope = JSON.stringify({
    platform: policy.platform,
    programUrl: policy.programUrl,
    totalAssets: policy.scope.inScope.length,
    rules: policy.rules,
    rewardRange: policy.rewardRange,
    safeHarbor: policy.safeHarbor,
    inScopeTargets: policy.scope.inScope,
    outOfScopeTargets: policy.scope.outOfScope
  });
  try {
    const [result] = await db.insert(engagements).values({
      name: engagementName,
      customerName: policy.programName,
      description: `Bug bounty engagement against ${policy.programName} via ${policy.platform}. ${policy.scope.inScope.length} in-scope targets. Auto-created by AC3 Auto-Engagement Creator.`,
      engagementType: "bug_bounty",
      status: "planning",
      targetDomain: domains.join(", ") || policy.programName,
      targetIpRange: ips.join(", ") || null,
      roeStatus: "signed",
      roeScope,
      scanMode: "active",
      bugBountyProgramUrl: policy.programUrl,
      bugBountyPlatform: validPlatforms.includes(plat) ? plat : "custom",
      notes: JSON.stringify({
        programUrl: policy.programUrl,
        platform: policy.platform,
        generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        generatedBy: "AC3 Auto-Engagement Creator (lightweight)",
        parseConfidence: "fallback"
      }),
      createdBy: userId,
      autoResumeOnRestart: 1
    });
    const engagementId = result.insertId;
    for (const target of policy.scope.inScope) {
      const val = target.value.trim();
      if (!val || val === "unknown") continue;
      await db.insert(engagementTimelineEvents).values({
        engagementId,
        eventType: "note_added",
        phase: "recon",
        title: val.substring(0, 255),
        description: `[${target.type}] ${target.eligible ? "Bounty eligible" : "No bounty"}${target.notes ? ". " + target.notes : ""}`,
        timestamp: Date.now(),
        metadata: JSON.stringify({
          type: target.type,
          eligible: target.eligible,
          notes: target.notes,
          source: "auto-engagement-creator"
        })
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
      urls
    };
  } catch (err) {
    console.error(`[AutoEngagement] Lightweight creation failed:`, err.message);
    return {
      created: false,
      totalAssetsAdded: 0,
      reason: `Creation failed: ${err.message}`,
      domains,
      ips,
      urls
    };
  }
}
async function parseUnknownProgramUrl(url) {
  let pageContent = "";
  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": "AC3-BugBountyParser/1.0 (Security Research Platform)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: AbortSignal.timeout(2e4)
    });
    if (!res.ok) {
      console.warn(`[AutoEngagement] Failed to fetch ${url}: HTTP ${res.status}`);
      return null;
    }
    pageContent = await res.text();
  } catch (err) {
    console.warn(`[AutoEngagement] Failed to fetch ${url}: ${err.message}`);
    return null;
  }
  const truncated = pageContent.substring(0, 2e4);
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
Be thorough \u2014 extract ALL in-scope targets mentioned on the page. Include wildcards (*.example.com), specific subdomains, API endpoints, mobile apps, and source code repos.`;
  try {
    const response = await invokeLLM({
      _caller: "auto-engagement-creator:parseUnknownUrl",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Parse this bug bounty/security program page:

URL: ${url}

PAGE CONTENT:
${truncated}` }
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
                    notes: { type: "string" }
                  }
                }
              },
              outOfScope: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    type: { type: "string" },
                    value: { type: "string" },
                    notes: { type: "string" }
                  }
                }
              },
              rules: { type: "array", items: { type: "string" } },
              rewardRange: {
                type: "object",
                properties: {
                  low: { type: "number" },
                  high: { type: "number" },
                  currency: { type: "string" }
                }
              },
              safeHarbor: { type: "boolean" },
              confidence: { type: "number" }
            }
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;
    let parsed;
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
    const result = {
      programName: parsed.programName || "Unknown Program",
      platform: "custom",
      programUrl: url,
      scope: {
        inScope: (parsed.inScope || []).map((s) => ({
          type: s.type || "other",
          value: s.value || "unknown",
          eligible: s.eligible !== false,
          notes: s.notes || void 0
        })),
        outOfScope: (parsed.outOfScope || []).map((s) => ({
          type: s.type || "other",
          value: s.value || "unknown",
          eligible: false,
          notes: s.notes || void 0
        }))
      },
      rules: parsed.rules || [],
      rewardRange: parsed.rewardRange && parsed.rewardRange.high > 0 ? {
        low: parsed.rewardRange.low || 0,
        high: parsed.rewardRange.high || 0,
        currency: parsed.rewardRange.currency || "$"
      } : void 0,
      safeHarbor: !!parsed.safeHarbor,
      parsedAt: (/* @__PURE__ */ new Date()).toISOString(),
      parseConfidence: parsed.confidence || 0.5
    };
    return result;
  } catch (err) {
    console.error(`[AutoEngagement] LLM parse failed for ${url}:`, err.message);
    return null;
  }
}
function mapTypeToEngagementType(type) {
  const mapping = {
    "domain": "DOMAIN",
    "url": "URL",
    "ip": "IP_ADDRESS",
    "cidr": "CIDR",
    "source_code": "SOURCE_CODE",
    "mobile_app": "MOBILE_APPLICATION",
    "wildcard": "WILDCARD",
    "other": "OTHER"
  };
  return mapping[type.toLowerCase()] || "OTHER";
}
export {
  autoCreateEngagement,
  hasSufficientData,
  parseUnknownProgramUrl
};
