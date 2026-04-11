/**
 * Hacking Articles Ingestion Pipeline
 * 
 * Automated scraper + LLM-powered extraction that processes security articles
 * from hackingarticles.in into structured exploit playbooks, technique observations,
 * and attack chain data for the threat actor catalog.
 * 
 * Flow:
 * 1. Load article catalog (pre-crawled JSON)
 * 2. Fetch article HTML and extract clean text
 * 3. LLM-powered extraction of techniques, commands, tools, chains
 * 4. Store as exploit_playbooks, dfir_observations, attack_chains_catalog
 * 5. Cross-reference with MITRE ATT&CK and threat actor catalog
 */

import { invokeLLM } from "../_core/llm";
import { db } from "../db";
import { exploitPlaybooks, dfirObservations, attackChainsCatalog } from "../../drizzle/schema";
import { eq } from "drizzle-orm";

// ─── Types ───────────────────────────────────────────────────────────────────

interface ArticleCatalogEntry {
  title: string;
  url: string;
  category: string;
  category_slug: string;
}

interface ExtractedPlaybook {
  technique_name: string;
  mitre_id: string;
  platform: "windows" | "linux" | "macos" | "multi";
  description: string;
  prerequisites: string[];
  enumeration_commands: CommandStep[];
  exploitation_commands: CommandStep[];
  post_exploitation_commands: CommandStep[];
  tools_used: ToolReference[];
  detection_indicators: string[];
  mitigations: string[];
  success_indicators: string[];
  related_techniques: string[];
  difficulty: "beginner" | "intermediate" | "advanced" | "expert";
  requires_credentials: boolean;
  requires_local_access: boolean;
  privilege_gained: string;
}

interface CommandStep {
  order: number;
  command: string;
  tool: string;
  description: string;
  expected_output: string;
  platform: string;
  requires_admin: boolean;
}

interface ToolReference {
  name: string;
  category: string; // enumeration, exploitation, post-exploitation, delivery
  url?: string;
  description: string;
}

interface ArticleCatalog {
  source: string;
  crawled_at: string;
  total_articles: number;
  categories_crawled: number;
  articles: ArticleCatalogEntry[];
}

// ─── Article Fetcher ─────────────────────────────────────────────────────────

/**
 * Fetch and extract clean text from an article URL.
 * Uses simple HTML-to-text extraction focusing on article body content.
 */
async function fetchArticleContent(url: string): Promise<string | null> {
  try {
    const resp = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      },
      signal: AbortSignal.timeout(15000),
    });
    
    if (!resp.ok) return null;
    
    const html = await resp.text();
    
    // Extract article body - Hacking Articles uses entry-content class
    const bodyMatch = html.match(/<div[^>]*class="[^"]*entry-content[^"]*"[^>]*>([\s\S]*?)<\/div>\s*<div/);
    const body = bodyMatch ? bodyMatch[1] : html;
    
    // Strip HTML tags but preserve code blocks and structure
    let text = body
      .replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, (_, code) => `\n\`\`\`\n${code.replace(/<[^>]+>/g, "")}\n\`\`\`\n`)
      .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_, code) => `\`${code.replace(/<[^>]+>/g, "")}\``)
      .replace(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/gi, (_, h) => `\n## ${h.replace(/<[^>]+>/g, "")}\n`)
      .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_, li) => `- ${li.replace(/<[^>]+>/g, "").trim()}\n`)
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<p[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, "")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#039;/g, "'")
      .replace(/&nbsp;/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
    
    // Truncate if too long for LLM context
    if (text.length > 12000) {
      text = text.substring(0, 12000) + "\n\n[TRUNCATED]";
    }
    
    return text;
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to fetch ${url}:`, e);
    return null;
  }
}

// ─── LLM Extraction ─────────────────────────────────────────────────────────

/**
 * Use LLM to extract structured exploit playbook data from article text.
 */
async function extractPlaybookFromArticle(
  articleText: string,
  title: string,
  category: string
): Promise<ExtractedPlaybook | null> {
  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: `You are an expert cybersecurity analyst specializing in offensive security technique extraction. Your job is to read security articles and extract structured, actionable exploit playbooks.

CRITICAL RULES:
- Extract EXACT commands as written in the article — do not generalize or sanitize
- Identify the specific MITRE ATT&CK technique ID (e.g., T1574.009)
- Capture the full attack chain: enumeration → exploitation → post-exploitation
- Note every tool mentioned with its purpose
- Identify prerequisites (access level, permissions, conditions)
- Extract detection indicators and mitigations
- Identify what privilege level is gained upon success
- Rate difficulty based on prerequisites and complexity

Return valid JSON matching the schema exactly.`,
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
}`,
        },
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
                    requires_admin: { type: "boolean" },
                  },
                },
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
                    requires_admin: { type: "boolean" },
                  },
                },
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
                    requires_admin: { type: "boolean" },
                  },
                },
              },
              tools_used: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    category: { type: "string" },
                    url: { type: "string" },
                    description: { type: "string" },
                  },
                },
              },
              detection_indicators: { type: "array", items: { type: "string" } },
              mitigations: { type: "array", items: { type: "string" } },
              success_indicators: { type: "array", items: { type: "string" } },
              related_techniques: { type: "array", items: { type: "string" } },
              difficulty: { type: "string" },
              requires_credentials: { type: "boolean" },
              requires_local_access: { type: "boolean" },
              privilege_gained: { type: "string" },
            },
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;

    return JSON.parse(content) as ExtractedPlaybook;
  } catch (e) {
    console.error(`[ArticleIngestion] LLM extraction failed for "${title}":`, e);
    return null;
  }
}

// ─── Database Storage ────────────────────────────────────────────────────────

/**
 * Store an extracted playbook in the exploit_playbooks table.
 */
async function storePlaybook(
  playbook: ExtractedPlaybook,
  sourceUrl: string,
  sourceTitle: string
): Promise<string | null> {
  try {
    const playbookId = `ha-${playbook.mitre_id}-${Date.now()}`;
    
    await db.insert(exploitPlaybooks).values({
      id: playbookId,
      threatActorId: null, // Not actor-specific — generic technique knowledge
      mitreId: playbook.mitre_id,
      techniqueName: playbook.technique_name,
      platform: playbook.platform,
      description: playbook.description,
      prerequisites: JSON.stringify(playbook.prerequisites),
      enumerationCommands: JSON.stringify(playbook.enumeration_commands),
      exploitationCommands: JSON.stringify(playbook.exploitation_commands),
      postExploitationCommands: JSON.stringify(playbook.post_exploitation_commands),
      toolsUsed: JSON.stringify(playbook.tools_used),
      successIndicators: JSON.stringify(playbook.success_indicators),
      detectionIndicators: JSON.stringify(playbook.detection_indicators),
      mitigations: JSON.stringify(playbook.mitigations),
      relatedTechniques: JSON.stringify(playbook.related_techniques),
      difficulty: playbook.difficulty,
      requiresCredentials: playbook.requires_credentials,
      requiresLocalAccess: playbook.requires_local_access,
      privilegeGained: playbook.privilege_gained,
      sourceUrl,
      sourceTitle,
      sourceType: "hacking_articles",
      confidence: 0.85, // High-quality structured walkthroughs
      lastValidated: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    return playbookId;
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to store playbook:`, e);
    return null;
  }
}

/**
 * Store technique observations extracted from the article.
 */
async function storeObservations(
  playbook: ExtractedPlaybook,
  sourceUrl: string,
  sourceTitle: string
): Promise<void> {
  try {
    // Store each enumeration + exploitation command as an observation
    const allCommands = [
      ...playbook.enumeration_commands.map(c => ({ ...c, phase: "enumeration" })),
      ...playbook.exploitation_commands.map(c => ({ ...c, phase: "exploitation" })),
      ...playbook.post_exploitation_commands.map(c => ({ ...c, phase: "post_exploitation" })),
    ];

    for (const cmd of allCommands) {
      await db.insert(dfirObservations).values({
        id: `ha-obs-${playbook.mitre_id}-${cmd.phase}-${cmd.order}-${Date.now()}`,
        threatActorId: null,
        mitreId: playbook.mitre_id,
        observationType: cmd.phase as "enumeration" | "exploitation" | "post_exploitation",
        platform: cmd.platform || playbook.platform,
        description: cmd.description,
        commandObserved: cmd.command,
        toolUsed: cmd.tool,
        expectedOutput: cmd.expected_output,
        detectionMethod: playbook.detection_indicators.join("; "),
        sourceUrl,
        sourceTitle,
        sourceType: "security_article",
        confidence: 0.85,
        observedAt: new Date(),
        createdAt: new Date(),
      });
    }
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to store observations:`, e);
  }
}

/**
 * Store the full attack chain if the article describes a multi-step process.
 */
async function storeAttackChain(
  playbook: ExtractedPlaybook,
  sourceUrl: string,
  sourceTitle: string
): Promise<void> {
  try {
    const allSteps = [
      ...playbook.enumeration_commands.map(c => ({
        order: c.order,
        phase: "enumeration",
        technique: playbook.mitre_id,
        command: c.command,
        tool: c.tool,
        description: c.description,
      })),
      ...playbook.exploitation_commands.map(c => ({
        order: c.order + 100,
        phase: "exploitation",
        technique: playbook.mitre_id,
        command: c.command,
        tool: c.tool,
        description: c.description,
      })),
      ...playbook.post_exploitation_commands.map(c => ({
        order: c.order + 200,
        phase: "post_exploitation",
        technique: playbook.mitre_id,
        command: c.command,
        tool: c.tool,
        description: c.description,
      })),
    ];

    if (allSteps.length < 2) return; // Not a chain if only 1 step

    await db.insert(attackChainsCatalog).values({
      id: `ha-chain-${playbook.mitre_id}-${Date.now()}`,
      threatActorId: null,
      chainName: `${playbook.technique_name} — Full Exploitation Chain`,
      description: playbook.description,
      platform: playbook.platform,
      initialAccess: playbook.requires_local_access ? "local_shell" : "remote",
      finalObjective: playbook.privilege_gained || "privilege_escalation",
      steps: JSON.stringify(allSteps),
      prerequisites: JSON.stringify(playbook.prerequisites),
      toolsRequired: JSON.stringify(playbook.tools_used.map(t => t.name)),
      mitreMapping: JSON.stringify([
        playbook.mitre_id,
        ...playbook.related_techniques,
      ]),
      difficulty: playbook.difficulty,
      successRate: null, // Unknown until tested
      sourceUrl,
      sourceTitle,
      sourceType: "security_article",
      confidence: 0.85,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to store attack chain:`, e);
  }
}

// ─── Main Ingestion Pipeline ─────────────────────────────────────────────────

/**
 * Ingest a single article: fetch → extract → store.
 */
export async function ingestArticle(
  url: string,
  title: string,
  category: string
): Promise<{
  success: boolean;
  playbookId?: string;
  technique?: string;
  mitreId?: string;
  commandsExtracted?: number;
  error?: string;
}> {
  console.log(`[ArticleIngestion] Processing: ${title}`);

  // 1. Fetch article content
  const content = await fetchArticleContent(url);
  if (!content || content.length < 200) {
    return { success: false, error: "Failed to fetch or empty content" };
  }

  // 2. LLM extraction
  const playbook = await extractPlaybookFromArticle(content, title, category);
  if (!playbook) {
    return { success: false, error: "LLM extraction failed" };
  }

  // 3. Store playbook
  const playbookId = await storePlaybook(playbook, url, title);
  if (!playbookId) {
    return { success: false, error: "Database storage failed" };
  }

  // 4. Store observations
  await storeObservations(playbook, url, title);

  // 5. Store attack chain
  await storeAttackChain(playbook, url, title);

  const totalCommands =
    playbook.enumeration_commands.length +
    playbook.exploitation_commands.length +
    playbook.post_exploitation_commands.length;

  console.log(
    `[ArticleIngestion] ✓ ${title} → ${playbook.mitre_id} | ${totalCommands} commands | ${playbook.tools_used.length} tools`
  );

  return {
    success: true,
    playbookId,
    technique: playbook.technique_name,
    mitreId: playbook.mitre_id,
    commandsExtracted: totalCommands,
  };
}

/**
 * Batch ingest articles from the catalog by category priority.
 * Processes articles with rate limiting to avoid overwhelming the LLM.
 */
export async function batchIngestArticles(options: {
  categories?: string[];
  maxArticles?: number;
  delayMs?: number;
}): Promise<{
  processed: number;
  succeeded: number;
  failed: number;
  results: Array<{ title: string; success: boolean; mitreId?: string; error?: string }>;
}> {
  const { categories, maxArticles = 50, delayMs = 2000 } = options;

  // Load catalog
  let catalog: ArticleCatalog;
  try {
    const catalogPath = new URL(
      "./knowledge/hacking-articles-catalog.json",
      import.meta.url
    );
    const raw = await import("fs").then(fs =>
      fs.readFileSync(catalogPath, "utf-8")
    );
    catalog = JSON.parse(raw);
  } catch (e) {
    console.error("[ArticleIngestion] Failed to load catalog:", e);
    return { processed: 0, succeeded: 0, failed: 0, results: [] };
  }

  // Filter by categories if specified
  let articles = catalog.articles;
  if (categories?.length) {
    articles = articles.filter(a =>
      categories.some(c => a.category.toLowerCase().includes(c.toLowerCase()))
    );
  }

  // Limit batch size
  articles = articles.slice(0, maxArticles);

  const results: Array<{ title: string; success: boolean; mitreId?: string; error?: string }> = [];
  let succeeded = 0;
  let failed = 0;

  for (const article of articles) {
    const result = await ingestArticle(article.url, article.title, article.category);
    results.push({
      title: article.title,
      success: result.success,
      mitreId: result.mitreId,
      error: result.error,
    });

    if (result.success) succeeded++;
    else failed++;

    // Rate limit
    if (delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  console.log(
    `[ArticleIngestion] Batch complete: ${succeeded}/${articles.length} succeeded, ${failed} failed`
  );

  return {
    processed: articles.length,
    succeeded,
    failed,
    results,
  };
}

/**
 * Get ingestion statistics — how many playbooks, observations, chains we have.
 */
export async function getIngestionStats(): Promise<{
  totalPlaybooks: number;
  totalObservations: number;
  totalChains: number;
  bySource: Record<string, number>;
  byPlatform: Record<string, number>;
  byDifficulty: Record<string, number>;
}> {
  try {
    const playbooks = await db.select().from(exploitPlaybooks);
    const observations = await db.select().from(dfirObservations);
    const chains = await db.select().from(attackChainsCatalog);

    const bySource: Record<string, number> = {};
    const byPlatform: Record<string, number> = {};
    const byDifficulty: Record<string, number> = {};

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
      byDifficulty,
    };
  } catch (e) {
    console.error("[ArticleIngestion] Failed to get stats:", e);
    return {
      totalPlaybooks: 0,
      totalObservations: 0,
      totalChains: 0,
      bySource: {},
      byPlatform: {},
      byDifficulty: {},
    };
  }
}

/**
 * Query playbooks by MITRE technique ID for use in exploit reasoning.
 */
export async function getPlaybooksByMitreId(mitreId: string): Promise<Array<{
  id: string;
  techniqueName: string;
  platform: string;
  enumerationCommands: CommandStep[];
  exploitationCommands: CommandStep[];
  toolsUsed: ToolReference[];
  difficulty: string;
  privilegeGained: string;
}>> {
  try {
    const results = await db
      .select()
      .from(exploitPlaybooks)
      .where(eq(exploitPlaybooks.mitreId, mitreId));

    return results.map(r => ({
      id: r.id,
      techniqueName: r.techniqueName || "",
      platform: r.platform || "unknown",
      enumerationCommands: JSON.parse(r.enumerationCommands || "[]"),
      exploitationCommands: JSON.parse(r.exploitationCommands || "[]"),
      toolsUsed: JSON.parse(r.toolsUsed || "[]"),
      difficulty: r.difficulty || "unknown",
      privilegeGained: r.privilegeGained || "unknown",
    }));
  } catch (e) {
    console.error(`[ArticleIngestion] Failed to query playbooks for ${mitreId}:`, e);
    return [];
  }
}

/**
 * Build a knowledge context string for the exploit LLM from stored playbooks.
 * This is what gets injected into the exploit generation prompt.
 */
export function buildPlaybookContext(
  playbooks: Array<{
    techniqueName: string;
    platform: string;
    enumerationCommands: CommandStep[];
    exploitationCommands: CommandStep[];
    toolsUsed: ToolReference[];
    difficulty: string;
    privilegeGained: string;
  }>
): string {
  if (playbooks.length === 0) return "";

  let context = "## Known Exploit Playbooks from Security Research\n\n";

  for (const pb of playbooks.slice(0, 5)) { // Limit to top 5 to fit context
    context += `### ${pb.techniqueName} (${pb.platform})\n`;
    context += `Difficulty: ${pb.difficulty} | Privilege gained: ${pb.privilegeGained}\n`;
    context += `Tools: ${pb.toolsUsed.map(t => t.name).join(", ")}\n\n`;

    if (pb.enumerationCommands.length > 0) {
      context += "**Enumeration:**\n";
      for (const cmd of pb.enumerationCommands) {
        context += `  ${cmd.order}. \`${cmd.command}\` — ${cmd.description}\n`;
      }
      context += "\n";
    }

    if (pb.exploitationCommands.length > 0) {
      context += "**Exploitation:**\n";
      for (const cmd of pb.exploitationCommands) {
        context += `  ${cmd.order}. \`${cmd.command}\` — ${cmd.description}\n`;
      }
      context += "\n";
    }
  }

  return context;
}
