import {
  init_llm,
  invokeLLM
} from "./chunk-4BQS7LEI.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import "./chunk-NRYVRXXR.js";
import {
  attackChainsCatalog,
  dfirObservations,
  exploitPlaybooks,
  init_schema
} from "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/hacking-articles-ingestion.ts
import { eq } from "drizzle-orm";
async function fetchArticleContent(url) {
  try {
    const resp = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
      },
      signal: AbortSignal.timeout(15e3)
    });
    if (!resp.ok) return null;
    const html = await resp.text();
    const bodyMatch = html.match(/<div[^>]*class="[^"]*entry-content[^"]*"[^>]*>([\s\S]*?)<\/div>\s*<div/);
    const body = bodyMatch ? bodyMatch[1] : html;
    let text = body.replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, (_, code) => `
\`\`\`
${code.replace(/<[^>]+>/g, "")}
\`\`\`
`).replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_, code) => `\`${code.replace(/<[^>]+>/g, "")}\``).replace(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/gi, (_, h) => `
## ${h.replace(/<[^>]+>/g, "")}
`).replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_, li) => `- ${li.replace(/<[^>]+>/g, "").trim()}
`).replace(/<br\s*\/?>/gi, "\n").replace(/<p[^>]*>/gi, "\n").replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/&nbsp;/g, " ").replace(/\n{3,}/g, "\n\n").trim();
    if (text.length > 12e3) {
      text = text.substring(0, 12e3) + "\n\n[TRUNCATED]";
    }
    return text;
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to fetch ${url}:`, e);
    return null;
  }
}
async function extractPlaybookFromArticle(articleText, title, category) {
  try {
    const response = await invokeLLM({
      _caller: "hacking-articles:extractPlaybook",
      messages: [
        {
          role: "system",
          content: `You are an expert cybersecurity analyst specializing in offensive security technique extraction. Your job is to read security articles and extract structured, actionable exploit playbooks.

CRITICAL RULES:
- Extract EXACT commands as written in the article \u2014 do not generalize or sanitize
- Identify the specific MITRE ATT&CK technique ID (e.g., T1574.009)
- Capture the full attack chain: enumeration \u2192 exploitation \u2192 post-exploitation
- Note every tool mentioned with its purpose
- Identify prerequisites (access level, permissions, conditions)
- Extract detection indicators and mitigations
- Identify what privilege level is gained upon success
- Rate difficulty based on prerequisites and complexity

Return valid JSON matching the schema exactly.`
        },
        {
          role: "user",
          content: `Extract a structured exploit playbook from this security article.

ARTICLE TITLE: ${title}
CATEGORY: ${category}

ARTICLE CONTENT:
${articleText}

Return a JSON object with this exact structure:
{
  "technique_name": "Human-readable technique name",
  "mitre_id": "T####.### or T#### format",
  "platform": "windows|linux|macos|multi",
  "description": "Concise description of the technique and how it works",
  "prerequisites": ["List of conditions needed before exploitation"],
  "enumeration_commands": [
    {
      "order": 1,
      "command": "exact command from article",
      "tool": "tool name",
      "description": "what this step does",
      "expected_output": "what to look for in output",
      "platform": "windows|linux",
      "requires_admin": false
    }
  ],
  "exploitation_commands": [
    {
      "order": 1,
      "command": "exact exploit command",
      "tool": "tool name",
      "description": "what this step does",
      "expected_output": "what success looks like",
      "platform": "windows|linux",
      "requires_admin": false
    }
  ],
  "post_exploitation_commands": [
    {
      "order": 1,
      "command": "post-exploit command",
      "tool": "tool name",
      "description": "what this step does",
      "expected_output": "expected result",
      "platform": "windows|linux",
      "requires_admin": true
    }
  ],
  "tools_used": [
    {
      "name": "Tool name",
      "category": "enumeration|exploitation|post-exploitation|delivery",
      "url": "download/repo URL if mentioned",
      "description": "What the tool does in this context"
    }
  ],
  "detection_indicators": ["How defenders can detect this technique"],
  "mitigations": ["How to prevent or mitigate this technique"],
  "success_indicators": ["Signs that exploitation succeeded"],
  "related_techniques": ["T####.### IDs of related MITRE techniques"],
  "difficulty": "beginner|intermediate|advanced|expert",
  "requires_credentials": true/false,
  "requires_local_access": true/false,
  "privilege_gained": "What access level is achieved (e.g., NT AUTHORITY\\SYSTEM, root)"
}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "exploit_playbook",
          strict: false,
          schema: {
            type: "object",
            properties: {
              technique_name: { type: "string" },
              mitre_id: { type: "string" },
              platform: { type: "string" },
              description: { type: "string" },
              prerequisites: { type: "array", items: { type: "string" } },
              enumeration_commands: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    order: { type: "integer" },
                    command: { type: "string" },
                    tool: { type: "string" },
                    description: { type: "string" },
                    expected_output: { type: "string" },
                    platform: { type: "string" },
                    requires_admin: { type: "boolean" }
                  }
                }
              },
              exploitation_commands: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    order: { type: "integer" },
                    command: { type: "string" },
                    tool: { type: "string" },
                    description: { type: "string" },
                    expected_output: { type: "string" },
                    platform: { type: "string" },
                    requires_admin: { type: "boolean" }
                  }
                }
              },
              post_exploitation_commands: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    order: { type: "integer" },
                    command: { type: "string" },
                    tool: { type: "string" },
                    description: { type: "string" },
                    expected_output: { type: "string" },
                    platform: { type: "string" },
                    requires_admin: { type: "boolean" }
                  }
                }
              },
              tools_used: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    category: { type: "string" },
                    url: { type: "string" },
                    description: { type: "string" }
                  }
                }
              },
              detection_indicators: { type: "array", items: { type: "string" } },
              mitigations: { type: "array", items: { type: "string" } },
              success_indicators: { type: "array", items: { type: "string" } },
              related_techniques: { type: "array", items: { type: "string" } },
              difficulty: { type: "string" },
              requires_credentials: { type: "boolean" },
              requires_local_access: { type: "boolean" },
              privilege_gained: { type: "string" }
            }
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = repairAndParseJSON(content);
    if (parsed) return parsed;
    console.warn(`[ArticleIngestion] JSON repair failed for "${title}", retrying with compact prompt...`);
    return await extractPlaybookCompact(articleText.slice(0, 6e3), title, category);
  } catch (e) {
    console.error(`[ArticleIngestion] LLM extraction failed for "${title}":`, e);
    return null;
  }
}
function repairAndParseJSON(raw) {
  if (!raw || typeof raw !== "string") return null;
  try {
    return JSON.parse(raw);
  } catch {
  }
  let text = raw.trim();
  text = text.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "").trim();
  text = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "");
  if (!text.includes('"') && text.includes("'")) {
    text = text.replace(/'/g, '"');
  }
  text = text.replace(/,\s*([}\]])/g, "$1");
  try {
    return JSON.parse(text);
  } catch {
  }
  let openBraces = 0;
  let openBrackets = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (ch === "{") openBraces++;
    else if (ch === "}") openBraces--;
    else if (ch === "[") openBrackets++;
    else if (ch === "]") openBrackets--;
  }
  for (let attempt = 0; attempt < 10; attempt++) {
    let ob = 0, obrk = 0, inStr = false, esc = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (esc) {
        esc = false;
        continue;
      }
      if (ch === "\\") {
        esc = true;
        continue;
      }
      if (ch === '"') {
        inStr = !inStr;
        continue;
      }
      if (inStr) continue;
      if (ch === "{") ob++;
      else if (ch === "}") ob--;
      else if (ch === "[") obrk++;
      else if (ch === "]") obrk--;
    }
    let candidate = text;
    if (inStr) candidate += '"';
    candidate = candidate.replace(/,\s*$/g, "");
    for (let i = 0; i < obrk; i++) candidate += "]";
    for (let i = 0; i < ob; i++) candidate += "}";
    candidate = candidate.replace(/,\s*([}\]])/g, "$1");
    try {
      return JSON.parse(candidate);
    } catch {
      const trimPoints = [
        text.lastIndexOf(","),
        text.lastIndexOf(': "'),
        text.lastIndexOf(": {"),
        text.lastIndexOf(": [")
      ].filter((p) => p > 0);
      if (trimPoints.length === 0) break;
      const bestTrim = Math.max(...trimPoints);
      if (bestTrim <= 1) break;
      if (text[bestTrim] === ",") {
        text = text.slice(0, bestTrim);
      } else {
        const keyEnd = text.lastIndexOf('"', bestTrim - 1);
        const keyStart = keyEnd > 0 ? text.lastIndexOf('"', keyEnd - 1) : -1;
        const commaBeforeKey = keyStart > 0 ? text.lastIndexOf(",", keyStart) : -1;
        if (commaBeforeKey > 0) {
          text = text.slice(0, commaBeforeKey);
        } else {
          text = text.slice(0, bestTrim);
        }
      }
    }
  }
  console.warn("[ArticleIngestion] JSON repair exhausted all attempts");
  return null;
}
async function extractPlaybookCompact(articleText, title, category) {
  try {
    const response = await invokeLLM({
      _caller: "hacking-articles:extractPlaybookCompact",
      messages: [
        {
          role: "system",
          content: "Extract a compact exploit playbook from the article. Return ONLY valid JSON. Keep command arrays short (max 5 items each). Omit empty arrays."
        },
        {
          role: "user",
          content: `Article: "${title}" [${category}]

${articleText}

Return JSON:
{"technique_name":"","mitre_id":"","platform":"","description":"","prerequisites":[],"enumeration_commands":[{"order":1,"command":"","tool":"","description":""}],"exploitation_commands":[{"order":1,"command":"","tool":"","description":""}],"tools_used":[{"name":"","category":""}],"detection_indicators":[],"difficulty":"","privilege_gained":""}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "compact_playbook",
          strict: false,
          schema: {
            type: "object",
            properties: {
              technique_name: { type: "string" },
              mitre_id: { type: "string" },
              platform: { type: "string" },
              description: { type: "string" },
              prerequisites: { type: "array", items: { type: "string" } },
              enumeration_commands: { type: "array", items: { type: "object", properties: { order: { type: "integer" }, command: { type: "string" }, tool: { type: "string" }, description: { type: "string" } } } },
              exploitation_commands: { type: "array", items: { type: "object", properties: { order: { type: "integer" }, command: { type: "string" }, tool: { type: "string" }, description: { type: "string" } } } },
              tools_used: { type: "array", items: { type: "object", properties: { name: { type: "string" }, category: { type: "string" } } } },
              detection_indicators: { type: "array", items: { type: "string" } },
              difficulty: { type: "string" },
              privilege_gained: { type: "string" }
            }
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = repairAndParseJSON(content);
    if (parsed) {
      console.log(`[ArticleIngestion] Compact retry succeeded for "${title}"`);
      return parsed;
    }
    return null;
  } catch (e) {
    console.error(`[ArticleIngestion] Compact retry failed for "${title}":`, e);
    return null;
  }
}
async function storePlaybook(playbook, sourceUrl, sourceTitle) {
  try {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const toolNames = (playbook.tools_used || []).map((t) => t.name);
    const codeBlock = [
      ...(playbook.enumeration_commands || []).map((c) => `# Enum: ${c.description}
${c.command}`),
      ...(playbook.exploitation_commands || []).map((c) => `# Exploit: ${c.description}
${c.command}`),
      ...(playbook.post_exploitation_commands || []).map((c) => `# Post: ${c.description}
${c.command}`)
    ].join("\n\n");
    await db.insert(exploitPlaybooks).values({
      // id: auto-increment, omit
      actorId: "hacking-articles",
      actorName: "Hacking Articles Knowledge Base",
      playbookTitle: sourceTitle,
      techniqueId: playbook.mitre_id || "T0000",
      techniqueName: playbook.technique_name,
      tactic: playbook.related_techniques?.[0]?.split(".")?.[0] || playbook.mitre_id?.split(".")?.[0] || "unknown",
      code: codeBlock || "N/A",
      language: "bash",
      toolName: toolNames[0] || null,
      targetConditions: JSON.stringify({
        prerequisites: playbook.prerequisites || [],
        platform: playbook.platform,
        difficulty: playbook.difficulty,
        requiresCredentials: playbook.requires_credentials,
        requiresLocalAccess: playbook.requires_local_access,
        privilegeGained: playbook.privilege_gained
      }),
      exploitedCves: JSON.stringify([]),
      targetServices: JSON.stringify([]),
      targetPlatforms: JSON.stringify([playbook.platform]),
      evasionTechniques: JSON.stringify(playbook.detection_indicators || []),
      successIndicators: JSON.stringify(playbook.success_indicators || []),
      sourceType: "osint",
      sourceReference: sourceUrl,
      confidence: 85,
      observedDate: (/* @__PURE__ */ new Date()).toISOString().slice(0, 10)
    });
    const playbookId = `ha-${playbook.mitre_id}-${Date.now()}`;
    return playbookId;
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to store playbook:`, e);
    return null;
  }
}
async function storeObservations(playbook, sourceUrl, sourceTitle) {
  try {
    const phaseToObsType = {
      enumeration: "discovery",
      exploitation: "execution",
      post_exploitation: "privilege_escalation"
    };
    const allCommands = [
      ...(playbook.enumeration_commands || []).map((c) => ({ ...c, phase: "enumeration" })),
      ...(playbook.exploitation_commands || []).map((c) => ({ ...c, phase: "exploitation" })),
      ...(playbook.post_exploitation_commands || []).map((c) => ({ ...c, phase: "post_exploitation" }))
    ];
    const reportId = `ha-report-${playbook.mitre_id || "unknown"}-${Date.now()}`;
    for (const cmd of allCommands) {
      const dbObs = await getDb();
      if (!dbObs) throw new Error("Database not available");
      await dbObs.insert(dfirObservations).values({
        // id: auto-increment, omit
        reportId,
        reportTitle: sourceTitle,
        reportSource: "Hacking Articles",
        reportUrl: sourceUrl,
        reportDate: (/* @__PURE__ */ new Date()).toISOString().slice(0, 10),
        actorId: "hacking-articles",
        actorName: "Hacking Articles Knowledge Base",
        observationType: phaseToObsType[cmd.phase] || "execution",
        techniqueId: playbook.mitre_id,
        techniqueName: playbook.technique_name,
        description: `${cmd.description}

Command: ${cmd.command}
Tool: ${cmd.tool}
Expected Output: ${cmd.expected_output}`,
        artifacts: JSON.stringify([{ type: "command", value: cmd.command, tool: cmd.tool }]),
        toolsObserved: JSON.stringify([cmd.tool]),
        associatedIocs: null,
        impactDescription: null,
        victimSector: null,
        victimRegion: null,
        detectionMethods: JSON.stringify(playbook.detection_indicators || []),
        mitigations: JSON.stringify(playbook.mitigations || []),
        confidence: 85
      });
    }
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to store observations:`, e);
  }
}
async function storeAttackChain(playbook, sourceUrl, sourceTitle) {
  try {
    const allSteps = [
      ...(playbook.enumeration_commands || []).map((c) => ({
        order: c.order,
        phase: "enumeration",
        technique: playbook.mitre_id,
        command: c.command,
        tool: c.tool,
        description: c.description
      })),
      ...(playbook.exploitation_commands || []).map((c) => ({
        order: c.order + 100,
        phase: "exploitation",
        technique: playbook.mitre_id,
        command: c.command,
        tool: c.tool,
        description: c.description
      })),
      ...(playbook.post_exploitation_commands || []).map((c) => ({
        order: c.order + 200,
        phase: "post_exploitation",
        technique: playbook.mitre_id,
        command: c.command,
        tool: c.tool,
        description: c.description
      }))
    ];
    if (allSteps.length < 2) return;
    const dbChain = await getDb();
    if (!dbChain) throw new Error("Database not available");
    await dbChain.insert(attackChainsCatalog).values({
      // id: auto-increment, omit
      actorId: "hacking-articles",
      actorName: "Hacking Articles Knowledge Base",
      chainName: `${playbook.technique_name} \u2014 Full Exploitation Chain`,
      description: playbook.description,
      steps: JSON.stringify(allSteps),
      tacticsTraversed: JSON.stringify([
        playbook.mitre_id,
        ...playbook.related_techniques
      ]),
      riskScore: playbook.difficulty === "expert" ? 90 : playbook.difficulty === "advanced" ? 75 : playbook.difficulty === "intermediate" ? 60 : 40,
      targetSectors: null,
      targetTechnologies: JSON.stringify([playbook.platform]),
      exploitedCves: JSON.stringify([]),
      toolsUsed: JSON.stringify((playbook.tools_used || []).map((t) => t.name)),
      typicalDuration: null,
      sourceType: "osint",
      sourceReference: sourceUrl,
      confidence: 85,
      observedDate: (/* @__PURE__ */ new Date()).toISOString().slice(0, 10)
    });
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to store attack chain:`, e);
  }
}
async function ingestArticle(url, title, category) {
  console.log(`[ArticleIngestion] Processing: ${title}`);
  const content = await fetchArticleContent(url);
  if (!content || content.length < 200) {
    return { success: false, error: "Failed to fetch or empty content" };
  }
  const playbook = await extractPlaybookFromArticle(content, title, category);
  if (!playbook) {
    return { success: false, error: "LLM extraction failed" };
  }
  const playbookId = await storePlaybook(playbook, url, title);
  if (!playbookId) {
    return { success: false, error: "Database storage failed" };
  }
  await storeObservations(playbook, url, title);
  await storeAttackChain(playbook, url, title);
  const totalCommands = (playbook.enumeration_commands || []).length + (playbook.exploitation_commands || []).length + (playbook.post_exploitation_commands || []).length;
  console.log(
    `[ArticleIngestion] \u2713 ${title} \u2192 ${playbook.mitre_id} | ${totalCommands} commands | ${(playbook.tools_used || []).length} tools`
  );
  return {
    success: true,
    playbookId,
    technique: playbook.technique_name,
    mitreId: playbook.mitre_id,
    commandsExtracted: totalCommands
  };
}
async function batchIngestArticles(options) {
  const { categories, maxArticles = 50, delayMs = 2e3 } = options;
  let catalog;
  try {
    const catalogPath = new URL(
      "./knowledge/hacking-articles-catalog.json",
      import.meta.url
    );
    const raw = await import("fs").then(
      (fs) => fs.readFileSync(catalogPath, "utf-8")
    );
    catalog = JSON.parse(raw);
  } catch (e) {
    console.error("[ArticleIngestion] Failed to load catalog:", e);
    return { processed: 0, succeeded: 0, failed: 0, results: [] };
  }
  let articles = catalog.articles;
  if (categories?.length) {
    articles = articles.filter(
      (a) => categories.some((c) => a.category.toLowerCase().includes(c.toLowerCase()))
    );
  }
  articles = articles.slice(0, maxArticles);
  const results = [];
  let succeeded = 0;
  let failed = 0;
  for (const article of articles) {
    const result = await ingestArticle(article.url, article.title, article.category);
    results.push({
      title: article.title,
      success: result.success,
      mitreId: result.mitreId,
      error: result.error
    });
    if (result.success) succeeded++;
    else failed++;
    if (delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  console.log(
    `[ArticleIngestion] Batch complete: ${succeeded}/${articles.length} succeeded, ${failed} failed`
  );
  return {
    processed: articles.length,
    succeeded,
    failed,
    results
  };
}
async function getIngestionStats() {
  try {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const playbooks = await db.select().from(exploitPlaybooks);
    const observations = await db.select().from(dfirObservations);
    const chains = await db.select().from(attackChainsCatalog);
    const bySource = {};
    const byPlatform = {};
    const byDifficulty = {};
    for (const p of playbooks) {
      bySource[p.sourceType || "unknown"] = (bySource[p.sourceType || "unknown"] || 0) + 1;
      byPlatform[p.platform || "unknown"] = (byPlatform[p.platform || "unknown"] || 0) + 1;
      if (p.difficulty) {
        byDifficulty[p.difficulty] = (byDifficulty[p.difficulty] || 0) + 1;
      }
    }
    return {
      totalPlaybooks: playbooks.length,
      totalObservations: observations.length,
      totalChains: chains.length,
      bySource,
      byPlatform,
      byDifficulty
    };
  } catch (e) {
    console.error("[ArticleIngestion] Failed to get stats:", e);
    return {
      totalPlaybooks: 0,
      totalObservations: 0,
      totalChains: 0,
      bySource: {},
      byPlatform: {},
      byDifficulty: {}
    };
  }
}
async function getPlaybooksByMitreId(mitreId) {
  try {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const results = await db.select().from(exploitPlaybooks).where(eq(exploitPlaybooks.mitreId, mitreId));
    return results.map((r) => ({
      id: r.id,
      techniqueName: r.techniqueName || "",
      platform: r.platform || "unknown",
      enumerationCommands: JSON.parse(r.enumerationCommands || "[]"),
      exploitationCommands: JSON.parse(r.exploitationCommands || "[]"),
      toolsUsed: JSON.parse(r.toolsUsed || "[]"),
      difficulty: r.difficulty || "unknown",
      privilegeGained: r.privilegeGained || "unknown"
    }));
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to query playbooks for ${mitreId}:`, e);
    return [];
  }
}
function buildPlaybookContext(playbooks) {
  if (playbooks.length === 0) return "";
  let context = "## Known Exploit Playbooks from Security Research\n\n";
  for (const pb of playbooks.slice(0, 5)) {
    context += `### ${pb.techniqueName} (${pb.platform})
`;
    context += `Difficulty: ${pb.difficulty} | Privilege gained: ${pb.privilegeGained}
`;
    context += `Tools: ${pb.toolsUsed.map((t) => t.name).join(", ")}

`;
    if (pb.enumerationCommands.length > 0) {
      context += "**Enumeration:**\n";
      for (const cmd of pb.enumerationCommands) {
        context += `  ${cmd.order}. \`${cmd.command}\` \u2014 ${cmd.description}
`;
      }
      context += "\n";
    }
    if (pb.exploitationCommands.length > 0) {
      context += "**Exploitation:**\n";
      for (const cmd of pb.exploitationCommands) {
        context += `  ${cmd.order}. \`${cmd.command}\` \u2014 ${cmd.description}
`;
      }
      context += "\n";
    }
  }
  return context;
}
var init_hacking_articles_ingestion = __esm({
  "server/lib/hacking-articles-ingestion.ts"() {
    init_llm();
    init_db();
    init_schema();
  }
});
init_hacking_articles_ingestion();
export {
  batchIngestArticles,
  buildPlaybookContext,
  getIngestionStats,
  getPlaybooksByMitreId,
  ingestArticle,
  repairAndParseJSON
};
