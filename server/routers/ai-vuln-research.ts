/**
 * AI Vulnerability Research Router
 * LLM-powered code auditing, 0-day discovery, and PoC generation.
 * Inspired by the Calif team's approach: give an LLM a natural-language prompt
 * and let it autonomously discover vulnerabilities in source code.
 * Integrated with Bug Bounty Hub for finding export and program correlation.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { invokeLLM } from "../_core/llm";
import { ENV } from "../_core/env";
import {
  aiVulnResearchSessions,
  aiVulnResearchFindings,
  aiVulnResearchCodeSnippets,
  bugBountyFindings,
} from "../../drizzle/schema";
import { eq, desc, sql, and, count } from "drizzle-orm";

// ─── System Prompts ─────────────────────────────────────────────────────────

const VULN_RESEARCH_SYSTEM_PROMPT = `You are an elite vulnerability researcher and exploit developer. Your task is to analyze source code for security vulnerabilities with the depth and precision of a world-class security auditor.

ANALYSIS METHODOLOGY:
1. First, understand the code's purpose, architecture, and attack surface
2. Identify all input vectors (user input, file parsing, network data, environment variables)
3. Trace data flow from inputs through processing to outputs
4. Look for common vulnerability classes: memory corruption, injection, authentication bypass, race conditions, deserialization, path traversal, SSRF, command injection, type confusion, integer overflow/underflow
5. For each vulnerability found, determine exploitability and impact
6. Generate a working proof-of-concept exploit when possible

FOCUS AREAS:
- Parser code (file format parsers, protocol parsers, markup processors)
- Input validation and sanitization routines
- Authentication and authorization logic
- Cryptographic implementations
- Memory management (buffer operations, pointer arithmetic)
- Deserialization of untrusted data
- Command/query construction from user input
- File system operations with user-controlled paths
- Race conditions in concurrent code
- Integer arithmetic that could overflow/underflow

OUTPUT FORMAT:
For each vulnerability found, provide:
- A clear title describing the vulnerability
- The vulnerability type (e.g., "Buffer Overflow", "SQL Injection", "RCE via Deserialization")
- Severity rating (critical/high/medium/low/informational)
- CVSS 3.1 score and vector string
- CWE ID
- Detailed description of the vulnerability
- The exact affected code (copy the vulnerable lines)
- File path and line numbers
- Root cause analysis
- Impact assessment
- Exploitability rating (trivial/easy/moderate/difficult/theoretical)
- Proof-of-concept exploit code
- Remediation guidance
- MITRE ATT&CK technique IDs if applicable
- Attack vector description

Be thorough but precise. Only report real vulnerabilities with clear evidence. Rate your confidence for each finding.`;

const POC_GENERATION_PROMPT = `You are an expert exploit developer. Given a vulnerability description and the affected code, generate a working proof-of-concept (PoC) exploit.

REQUIREMENTS:
1. The PoC must demonstrate the vulnerability clearly
2. Include setup instructions and prerequisites
3. Add comments explaining each step of the exploit
4. Include cleanup/safety measures where applicable
5. Specify the programming language and any dependencies
6. The PoC should be self-contained and runnable

OUTPUT: Return ONLY the PoC code with detailed comments. No markdown formatting around the code block.`;

// ─── Helper: Fetch GitHub file contents ─────────────────────────────────────

async function fetchGitHubContents(
  repoUrl: string,
  path: string = "",
  maxFiles: number = 20,
  maxSizePerFile: number = 100000,
): Promise<Array<{ path: string; content: string; language: string }>> {
  const token = ENV.GITHUB_PAT || ENV.GITHUB_CLASSIC_TOKEN;
  // Parse owner/repo from URL
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) throw new Error("Invalid GitHub URL");
  const [, owner, repo] = match;
  const cleanRepo = repo.replace(/\.git$/, "");

  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "AC3-VulnResearch",
  };
  if (token) headers.Authorization = `token ${token}`;

  // Get repo tree recursively
  const treeRes = await fetch(
    `https://api.github.com/repos/${owner}/${cleanRepo}/git/trees/HEAD?recursive=1`,
    { headers, signal: AbortSignal.timeout(15000) },
  );
  if (!treeRes.ok) throw new Error(`GitHub API error: ${treeRes.status} ${treeRes.statusText}`);
  const treeData = (await treeRes.json()) as { tree: Array<{ path: string; type: string; size?: number }> };

  // Filter for source code files
  const codeExtensions = new Set([
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".py", ".rb", ".php", ".java", ".go", ".rs",
    ".js", ".ts", ".jsx", ".tsx",
    ".cs", ".swift", ".kt", ".scala",
    ".pl", ".pm", ".lua", ".sh", ".bash",
    ".sql", ".xml", ".yaml", ".yml", ".json",
    ".conf", ".cfg", ".ini", ".toml",
  ]);

  const sourceFiles = treeData.tree
    .filter((f) => {
      if (f.type !== "blob") return false;
      if (f.size && f.size > maxSizePerFile) return false;
      if (path && !f.path.startsWith(path)) return false;
      const ext = f.path.substring(f.path.lastIndexOf(".")).toLowerCase();
      return codeExtensions.has(ext);
    })
    .slice(0, maxFiles);

  // Fetch file contents in parallel (batched)
  const results: Array<{ path: string; content: string; language: string }> = [];
  const batchSize = 5;
  for (let i = 0; i < sourceFiles.length; i += batchSize) {
    const batch = sourceFiles.slice(i, i + batchSize);
    const fetches = batch.map(async (file) => {
      try {
        const res = await fetch(
          `https://api.github.com/repos/${owner}/${cleanRepo}/contents/${file.path}`,
          { headers, signal: AbortSignal.timeout(10000) },
        );
        if (!res.ok) return null;
        const data = (await res.json()) as { content?: string; encoding?: string };
        if (data.content && data.encoding === "base64") {
          const content = Buffer.from(data.content, "base64").toString("utf-8");
          const ext = file.path.substring(file.path.lastIndexOf(".") + 1);
          return { path: file.path, content, language: ext };
        }
        return null;
      } catch {
        return null;
      }
    });
    const batchResults = await Promise.all(fetches);
    results.push(...batchResults.filter((r): r is NonNullable<typeof r> => r !== null));
  }

  return results;
}

// ─── Helper: Detect language from extension ─────────────────────────────────

function detectLanguage(filename: string): string {
  const ext = filename.substring(filename.lastIndexOf(".") + 1).toLowerCase();
  const langMap: Record<string, string> = {
    c: "c", h: "c", cpp: "cpp", hpp: "cpp", cc: "cpp", cxx: "cpp",
    py: "python", rb: "ruby", php: "php", java: "java", go: "go", rs: "rust",
    js: "javascript", ts: "typescript", jsx: "javascript", tsx: "typescript",
    cs: "csharp", swift: "swift", kt: "kotlin", scala: "scala",
    pl: "perl", pm: "perl", lua: "lua", sh: "bash", bash: "bash",
    sql: "sql", xml: "xml", yaml: "yaml", yml: "yaml", json: "json",
  };
  return langMap[ext] || ext;
}

// ─── Helper: Parse LLM vulnerability findings ──────────────────────────────

interface ParsedFinding {
  title: string;
  vulnType: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cvssScore: number | null;
  cvssVector: string | null;
  cweId: string | null;
  description: string;
  affectedCode: string | null;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  rootCause: string | null;
  impact: string | null;
  exploitability: "trivial" | "easy" | "moderate" | "difficult" | "theoretical" | null;
  pocCode: string | null;
  pocLanguage: string | null;
  remediation: string | null;
  mitreTechniques: string[] | null;
  attackVector: string | null;
  confidenceScore: number | null;
  llmReasoning: string | null;
}

// ─── Router ─────────────────────────────────────────────────────────────────

export const aiVulnResearchRouter = router({
  // ─── List research sessions ───────────────────────────────────────────
  listSessions: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(25),
      offset: z.number().min(0).default(0),
      status: z.enum(["pending", "analyzing", "completed", "failed", "cancelled"]).optional(),
      targetType: z.enum(["source_code", "github_repo", "binary", "config", "protocol", "firmware", "custom"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { limit = 25, offset = 0, status, targetType } = input ?? {};

      const conditions = [];
      if (status) conditions.push(eq(aiVulnResearchSessions.status, status));
      if (targetType) conditions.push(eq(aiVulnResearchSessions.targetType, targetType));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const sessions = await db
        .select()
        .from(aiVulnResearchSessions)
        .where(where)
        .orderBy(desc(aiVulnResearchSessions.createdAt))
        .limit(limit)
        .offset(offset);

      const [totalRow] = await db
        .select({ count: count() })
        .from(aiVulnResearchSessions)
        .where(where);

      return { sessions, total: totalRow?.count ?? 0 };
    }),

  // ─── Get session detail with findings ─────────────────────────────────
  getSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [session] = await db
        .select()
        .from(aiVulnResearchSessions)
        .where(eq(aiVulnResearchSessions.id, input.sessionId));

      if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });

      const findings = await db
        .select()
        .from(aiVulnResearchFindings)
        .where(eq(aiVulnResearchFindings.sessionId, input.sessionId))
        .orderBy(desc(aiVulnResearchFindings.cvssScore));

      const snippets = await db
        .select()
        .from(aiVulnResearchCodeSnippets)
        .where(eq(aiVulnResearchCodeSnippets.sessionId, input.sessionId));

      return { session, findings, snippets };
    }),

  // ─── Start a new vulnerability research session ───────────────────────
  startResearch: protectedProcedure
    .input(z.object({
      title: z.string().min(1).max(512),
      description: z.string().optional(),
      targetType: z.enum(["source_code", "github_repo", "binary", "config", "protocol", "firmware", "custom"]),
      targetName: z.string().min(1).max(512),
      targetVersion: z.string().max(128).optional(),
      githubUrl: z.string().url().optional(),
      language: z.string().max(64).optional(),
      researchPrompt: z.string().min(1).max(10000),
      sourceCode: z.string().max(500000).optional(),
      sourceFiles: z.array(z.object({
        filename: z.string(),
        content: z.string(),
      })).max(30).optional(),
      bugBountyProgramId: z.number().optional(),
      engagementId: z.number().optional(),
      githubPath: z.string().optional(),
      maxGithubFiles: z.number().min(1).max(50).default(20),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const startTime = Date.now();

      // Create session record
      const [insertResult] = await db.insert(aiVulnResearchSessions).values({
        userId: ctx.user.id,
        title: input.title,
        description: input.description ?? null,
        targetType: input.targetType,
        targetName: input.targetName,
        targetVersion: input.targetVersion ?? null,
        githubUrl: input.githubUrl ?? null,
        language: input.language ?? null,
        researchPrompt: input.researchPrompt,
        status: "analyzing",
        bugBountyProgramId: input.bugBountyProgramId ?? null,
        engagementId: input.engagementId ?? null,
      });
      const sessionId = insertResult.insertId;

      try {
        // ─── Gather source code ───────────────────────────────────────
        let codeBlocks: Array<{ filename: string; content: string; language: string }> = [];

        if (input.targetType === "github_repo" && input.githubUrl) {
          // Fetch from GitHub
          const files = await fetchGitHubContents(
            input.githubUrl,
            input.githubPath || "",
            input.maxGithubFiles,
          );
          codeBlocks = files.map((f) => ({
            filename: f.path,
            content: f.content,
            language: f.language,
          }));
        } else if (input.sourceFiles && input.sourceFiles.length > 0) {
          codeBlocks = input.sourceFiles.map((f) => ({
            filename: f.filename,
            content: f.content,
            language: detectLanguage(f.filename),
          }));
        } else if (input.sourceCode) {
          codeBlocks = [{
            filename: input.targetName,
            content: input.sourceCode,
            language: input.language || "unknown",
          }];
        }

        if (codeBlocks.length === 0) {
          throw new Error("No source code provided for analysis");
        }

        // Store code snippets
        for (const block of codeBlocks) {
          await db.insert(aiVulnResearchCodeSnippets).values({
            sessionId,
            filename: block.filename,
            language: block.language,
            content: block.content,
            lineCount: block.content.split("\n").length,
          });
        }

        // ─── Build LLM prompt ─────────────────────────────────────────
        const codeContext = codeBlocks
          .map((b) => `\n--- FILE: ${b.filename} (${b.language}) ---\n${b.content}`)
          .join("\n");

        // Truncate if too large (keep under ~120k chars for context window)
        const maxCodeLen = 120000;
        const truncatedCode = codeContext.length > maxCodeLen
          ? codeContext.substring(0, maxCodeLen) + "\n\n[... truncated due to size ...]"
          : codeContext;

        const userPrompt = `${input.researchPrompt}

TARGET: ${input.targetName}${input.targetVersion ? ` v${input.targetVersion}` : ""}
TYPE: ${input.targetType}
${input.language ? `LANGUAGE: ${input.language}` : ""}

SOURCE CODE:
${truncatedCode}

Analyze this code thoroughly for security vulnerabilities. For each vulnerability found, provide your analysis in the following JSON format:

{
  "findings": [
    {
      "title": "...",
      "vulnType": "...",
      "severity": "critical|high|medium|low|informational",
      "cvssScore": 9.8,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cweId": "CWE-XXX",
      "description": "...",
      "affectedCode": "paste the vulnerable code lines here",
      "filePath": "...",
      "lineStart": 42,
      "lineEnd": 55,
      "rootCause": "...",
      "impact": "...",
      "exploitability": "trivial|easy|moderate|difficult|theoretical",
      "pocCode": "working proof-of-concept exploit code",
      "pocLanguage": "python",
      "remediation": "...",
      "mitreTechniques": ["T1190", "T1059"],
      "attackVector": "...",
      "confidenceScore": 0.95,
      "reasoning": "step-by-step reasoning for this finding"
    }
  ],
  "summary": "overall analysis summary",
  "codeQualityNotes": "general observations about code quality and security posture"
}

Return ONLY valid JSON. Be thorough but precise — only report real vulnerabilities with evidence.`;

        // ─── Call LLM ─────────────────────────────────────────────────
        const response = await invokeLLM({
          _caller: "ai-vuln-research",
          _priority: "essential",
          messages: [
            { role: "system", content: VULN_RESEARCH_SYSTEM_PROMPT },
            { role: "user", content: userPrompt },
          ],
          response_format: { type: "json_object" },
        });

        const rawContent = response.choices?.[0]?.message?.content || "{}";
        const tokensUsed = response.usage?.total_tokens || 0;

        // ─── Parse findings ───────────────────────────────────────────
        let parsed: { findings?: ParsedFinding[]; summary?: string; codeQualityNotes?: string };
        try {
          parsed = JSON.parse(rawContent);
        } catch {
          // Try to extract JSON from markdown code blocks
          const jsonMatch = rawContent.match(/```(?:json)?\s*([\s\S]*?)```/);
          if (jsonMatch) {
            parsed = JSON.parse(jsonMatch[1]);
          } else {
            parsed = { findings: [], summary: "Failed to parse LLM response" };
          }
        }

        const findings = parsed.findings || [];
        let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;

        // ─── Store findings ───────────────────────────────────────────
        for (const finding of findings) {
          const sev = (finding.severity || "informational").toLowerCase() as "critical" | "high" | "medium" | "low" | "informational";
          if (sev === "critical") criticalCount++;
          else if (sev === "high") highCount++;
          else if (sev === "medium") mediumCount++;
          else if (sev === "low") lowCount++;

          const exploitability = ["trivial", "easy", "moderate", "difficult", "theoretical"].includes(finding.exploitability || "")
            ? finding.exploitability as "trivial" | "easy" | "moderate" | "difficult" | "theoretical"
            : null;

          await db.insert(aiVulnResearchFindings).values({
            sessionId,
            title: finding.title || "Unnamed Finding",
            vulnType: finding.vulnType || "Unknown",
            severity: sev,
            cvssScore: finding.cvssScore ?? null,
            cvssVector: finding.cvssVector ?? null,
            cweId: finding.cweId ?? null,
            description: finding.description || "",
            affectedCode: finding.affectedCode ?? null,
            filePath: finding.filePath ?? null,
            lineStart: finding.lineStart ?? null,
            lineEnd: finding.lineEnd ?? null,
            rootCause: finding.rootCause ?? null,
            impact: finding.impact ?? null,
            exploitability,
            pocCode: finding.pocCode ?? null,
            pocLanguage: finding.pocLanguage ?? null,
            pocStatus: finding.pocCode ? "generated" : "not_generated",
            remediation: finding.remediation ?? null,
            mitreTechniques: finding.mitreTechniques ?? null,
            attackVector: finding.attackVector ?? null,
            confidenceScore: finding.confidenceScore ?? null,
            llmReasoning: finding.reasoning ?? null,
          });
        }

        // ─── Update session ───────────────────────────────────────────
        const analysisTimeMs = Date.now() - startTime;
        await db
          .update(aiVulnResearchSessions)
          .set({
            status: "completed",
            totalFindings: findings.length,
            criticalCount,
            highCount,
            mediumCount,
            lowCount,
            llmModel: "gpt-4o",
            tokensUsed,
            analysisTimeMs,
            metadata: {
              summary: parsed.summary,
              codeQualityNotes: parsed.codeQualityNotes,
              filesAnalyzed: codeBlocks.length,
              totalLines: codeBlocks.reduce((sum, b) => sum + b.content.split("\n").length, 0),
            },
          })
          .where(eq(aiVulnResearchSessions.id, sessionId));

        return {
          sessionId,
          status: "completed",
          totalFindings: findings.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          analysisTimeMs,
          summary: parsed.summary,
        };
      } catch (error: any) {
        // Mark session as failed
        await db
          .update(aiVulnResearchSessions)
          .set({
            status: "failed",
            metadata: { error: error.message },
            analysisTimeMs: Date.now() - startTime,
          })
          .where(eq(aiVulnResearchSessions.id, sessionId));

        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Analysis failed: ${error.message}`,
        });
      }
    }),

  // ─── Generate PoC for a specific finding ──────────────────────────────
  generatePoc: protectedProcedure
    .input(z.object({ findingId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [finding] = await db
        .select()
        .from(aiVulnResearchFindings)
        .where(eq(aiVulnResearchFindings.id, input.findingId));

      if (!finding) throw new TRPCError({ code: "NOT_FOUND", message: "Finding not found" });

      // Update status
      await db
        .update(aiVulnResearchFindings)
        .set({ pocStatus: "generating" })
        .where(eq(aiVulnResearchFindings.id, input.findingId));

      try {
        const userPrompt = `Vulnerability: ${finding.title}
Type: ${finding.vulnType}
Severity: ${finding.severity} (CVSS: ${finding.cvssScore || "N/A"})
CWE: ${finding.cweId || "N/A"}

Description: ${finding.description}

Affected Code:
${finding.affectedCode || "Not available"}

File: ${finding.filePath || "Unknown"}
Lines: ${finding.lineStart || "?"}-${finding.lineEnd || "?"}

Root Cause: ${finding.rootCause || "See description"}

Generate a complete, working proof-of-concept exploit for this vulnerability. Include:
1. All necessary imports/dependencies
2. Setup instructions as comments
3. The exploit code with detailed comments
4. Expected output/behavior
5. Cleanup steps if applicable`;

        const response = await invokeLLM({
          _caller: "ai-vuln-research-poc",
          _priority: "essential",
          messages: [
            { role: "system", content: POC_GENERATION_PROMPT },
            { role: "user", content: userPrompt },
          ],
        });

        const pocCode = response.choices?.[0]?.message?.content || "";
        // Detect language from the PoC
        const shebangRe = new RegExp('^#!.*?(python|bash|sh|ruby|perl|node)', 'i');
        const importRe = new RegExp('^(import |from )', 'im');
        const langMatch = pocCode.match(shebangRe) || pocCode.match(importRe);
        const pocLanguage = langMatch ? "python" : (finding.pocLanguage || "python");

        await db
          .update(aiVulnResearchFindings)
          .set({
            pocCode,
            pocLanguage,
            pocStatus: "generated",
          })
          .where(eq(aiVulnResearchFindings.id, input.findingId));

        return { pocCode, pocLanguage, status: "generated" };
      } catch (error: any) {
        await db
          .update(aiVulnResearchFindings)
          .set({ pocStatus: "failed" })
          .where(eq(aiVulnResearchFindings.id, input.findingId));

        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `PoC generation failed: ${error.message}`,
        });
      }
    }),

  // ─── Export finding to Bug Bounty Hub ─────────────────────────────────
  exportToBugBounty: protectedProcedure
    .input(z.object({
      findingId: z.number(),
      platform: z.string().default("manual"),
      programHandle: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [finding] = await db
        .select()
        .from(aiVulnResearchFindings)
        .where(eq(aiVulnResearchFindings.id, input.findingId));

      if (!finding) throw new TRPCError({ code: "NOT_FOUND", message: "Finding not found" });

      // Map severity
      const severityMap: Record<string, string> = {
        critical: "critical",
        high: "high",
        medium: "medium",
        low: "low",
        informational: "none",
      };

      // Create bug bounty finding
      const [bbResult] = await db.insert(bugBountyFindings).values({
        platform: input.platform as any,
        externalId: `avr-${finding.id}-${Date.now()}`,
        title: finding.title,
        severityRating: severityMap[finding.severity] || "medium",
        cveIds: finding.cveId ? JSON.stringify([finding.cveId]) : null,
        cweId: finding.cweId,
        assetIdentifier: finding.filePath || "N/A",
        summary: finding.description,
        cvssScore: finding.cvssScore ? String(finding.cvssScore) : null,
        state: "new",
        programHandle: input.programHandle || "ai-vuln-research",
      } as any);

      // Update finding to mark as exported
      await db
        .update(aiVulnResearchFindings)
        .set({
          exportedToBugBounty: 1,
          bugBountyFindingId: bbResult.insertId,
        })
        .where(eq(aiVulnResearchFindings.id, input.findingId));

      return { bugBountyFindingId: bbResult.insertId, status: "exported" };
    }),

  // ─── Delete a research session ────────────────────────────────────────
  deleteSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Delete findings first
      await db.delete(aiVulnResearchFindings).where(eq(aiVulnResearchFindings.sessionId, input.sessionId));
      await db.delete(aiVulnResearchCodeSnippets).where(eq(aiVulnResearchCodeSnippets.sessionId, input.sessionId));
      await db.delete(aiVulnResearchSessions).where(eq(aiVulnResearchSessions.id, input.sessionId));

      return { deleted: true };
    }),

  // ─── Stats for the research module ────────────────────────────────────
  stats: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return { totalSessions: 0, totalFindings: 0, criticalFindings: 0, highFindings: 0, pocGenerated: 0, exportedToBugBounty: 0 };

    const [sessionStats] = await db
      .select({
        total: count(),
        completed: sql<number>`SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)`,
        analyzing: sql<number>`SUM(CASE WHEN status = 'analyzing' THEN 1 ELSE 0 END)`,
      })
      .from(aiVulnResearchSessions);

    const [findingStats] = await db
      .select({
        total: count(),
        critical: sql<number>`SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)`,
        high: sql<number>`SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END)`,
        medium: sql<number>`SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END)`,
        low: sql<number>`SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)`,
        pocGenerated: sql<number>`SUM(CASE WHEN poc_status = 'generated' OR poc_status = 'validated' THEN 1 ELSE 0 END)`,
        exported: sql<number>`SUM(CASE WHEN exported_to_bug_bounty = 1 THEN 1 ELSE 0 END)`,
      })
      .from(aiVulnResearchFindings);

    return {
      totalSessions: Number(sessionStats?.total ?? 0),
      completedSessions: Number(sessionStats?.completed ?? 0),
      analyzingSessions: Number(sessionStats?.analyzing ?? 0),
      totalFindings: Number(findingStats?.total ?? 0),
      criticalFindings: Number(findingStats?.critical ?? 0),
      highFindings: Number(findingStats?.high ?? 0),
      mediumFindings: Number(findingStats?.medium ?? 0),
      lowFindings: Number(findingStats?.low ?? 0),
      pocGenerated: Number(findingStats?.pocGenerated ?? 0),
      exportedToBugBounty: Number(findingStats?.exported ?? 0),
    };
  }),

  // ─── Verify/toggle a finding's verified status ────────────────────────
  toggleVerified: protectedProcedure
    .input(z.object({ findingId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [finding] = await db
        .select()
        .from(aiVulnResearchFindings)
        .where(eq(aiVulnResearchFindings.id, input.findingId));

      if (!finding) throw new TRPCError({ code: "NOT_FOUND", message: "Finding not found" });

      const newVerified = finding.verified === 1 ? 0 : 1;
      await db
        .update(aiVulnResearchFindings)
        .set({ verified: newVerified })
        .where(eq(aiVulnResearchFindings.id, input.findingId));

      return { verified: newVerified === 1 };
    }),

  // ─── Fetch GitHub repo structure (for UI file picker) ─────────────────
  fetchGithubTree: protectedProcedure
    .input(z.object({
      repoUrl: z.string().url(),
      path: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const token = ENV.GITHUB_PAT || ENV.GITHUB_CLASSIC_TOKEN;
      const match = input.repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (!match) throw new TRPCError({ code: "BAD_REQUEST", message: "Invalid GitHub URL" });
      const [, owner, repo] = match;
      const cleanRepo = repo.replace(/\.git$/, "");

      const headers: Record<string, string> = {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "AC3-VulnResearch",
      };
      if (token) headers.Authorization = `token ${token}`;

      const treeRes = await fetch(
        `https://api.github.com/repos/${owner}/${cleanRepo}/git/trees/HEAD?recursive=1`,
        { headers, signal: AbortSignal.timeout(10000) },
      );
      if (!treeRes.ok) throw new TRPCError({ code: "BAD_REQUEST", message: `GitHub API: ${treeRes.status}` });
      const data = (await treeRes.json()) as { tree: Array<{ path: string; type: string; size?: number }> };

      const codeExtensions = new Set([
        ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".py", ".rb", ".php",
        ".java", ".go", ".rs", ".js", ".ts", ".jsx", ".tsx", ".cs",
        ".swift", ".kt", ".scala", ".pl", ".pm", ".lua", ".sh", ".bash",
        ".sql", ".xml", ".yaml", ".yml", ".json", ".conf", ".cfg", ".ini", ".toml",
      ]);

      const files = data.tree
        .filter((f) => {
          if (f.type !== "blob") return false;
          if (input.path && !f.path.startsWith(input.path)) return false;
          const ext = f.path.substring(f.path.lastIndexOf(".")).toLowerCase();
          return codeExtensions.has(ext);
        })
        .map((f) => ({
          path: f.path,
          size: f.size || 0,
          language: detectLanguage(f.path),
        }));

      const dirs = [...new Set(
        data.tree
          .filter((f) => f.type === "tree")
          .map((f) => f.path),
      )];

      return { files, dirs, totalFiles: files.length };
    }),
});
