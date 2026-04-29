/**
 * Customer Stack Profile Router
 * ==============================
 * tRPC procedures for managing customer technology stack profiles,
 * generating tailored test plans from scanner modules, and running
 * live HTTP probes against target infrastructure.
 *
 * @author Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { customerStackProfiles } from "../../drizzle/schema";
import { eq, desc } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";

// ─── Scanner Module Registry ────────────────────────────────────────────────

const SCANNER_REGISTRY: Record<string, {
  name: string;
  technologies: string[];
  description: string;
  importPath: string;
}> = {
  "streamlit-scanner": {
    name: "Streamlit Security Scanner",
    technologies: ["streamlit", "python", "flask"],
    description: "Fingerprinting, CVEs, HTML injection, widget manipulation, session poisoning",
    importPath: "../lib/scanners/streamlit-scanner",
  },
  "jupyter-scanner": {
    name: "Jupyter Notebook Scanner",
    technologies: ["jupyter", "jupyterlab", "jupyterhub", "ipython", "python"],
    description: "Kernel access, token brute-force, notebook exposure, path traversal, RCE",
    importPath: "../lib/scanners/jupyter-scanner",
  },
  "langchain-agent-scanner": {
    name: "LangChain Agent Scanner",
    technologies: ["langchain", "langserve", "langsmith", "openai", "anthropic", "llm", "rag"],
    description: "Tool injection, memory poisoning, guardrail bypass, RAG manipulation",
    importPath: "../lib/scanners/langchain-agent-scanner",
  },
  "faiss-vector-scanner": {
    name: "FAISS Vector DB Scanner",
    technologies: ["faiss", "vector", "embedding", "pinecone", "chroma", "weaviate", "qdrant"],
    description: "Index exposure, pickle RCE, embedding extraction, vector poisoning",
    importPath: "../lib/scanners/faiss-vector-scanner",
  },
  "firebase-scanner": {
    name: "Firebase Security Scanner",
    technologies: ["firebase", "firestore", "google cloud functions", "gcp"],
    description: "Config extraction, Firestore rules, auth bypass, Cloud Functions enumeration",
    importPath: "../lib/scanners/firebase-scanner",
  },
  "github-actions-scanner": {
    name: "GitHub Actions Scanner",
    technologies: ["github actions", "github", "ci/cd", "github workflows"],
    description: "Expression injection, pull_request_target abuse, unpinned actions, secret exposure",
    importPath: "../lib/scanners/github-actions-scanner",
  },
};

// ─── Technology Matching ────────────────────────────────────────────────────

function matchScannersToStack(stack: string[]): {
  matched: string[];
  coveragePercent: number;
  gaps: string[];
} {
  const normalizedStack = stack.map(t => t.toLowerCase().trim());
  const matched: string[] = [];
  const coveredTechs = new Set<string>();

  for (const [scannerKey, scanner] of Object.entries(SCANNER_REGISTRY)) {
    const hasMatch = scanner.technologies.some(scannerTech =>
      normalizedStack.some(stackTech =>
        stackTech.includes(scannerTech) || scannerTech.includes(stackTech)
      )
    );
    if (hasMatch) {
      matched.push(scannerKey);
      for (const tech of scanner.technologies) {
        for (const stackTech of normalizedStack) {
          if (stackTech.includes(tech) || tech.includes(stackTech)) {
            coveredTechs.add(stackTech);
          }
        }
      }
    }
  }

  const gaps = normalizedStack.filter(t => !coveredTechs.has(t));
  const coveragePercent = normalizedStack.length > 0
    ? Math.round((coveredTechs.size / normalizedStack.length) * 100)
    : 0;

  return { matched, coveragePercent, gaps };
}

function flattenStack(profile: {
  languages?: string[] | null;
  webFrameworks?: string[] | null;
  dataAndMl?: string[] | null;
  genaiAndLlm?: string[] | null;
  cloudServices?: string[] | null;
  securityTools?: string[] | null;
  devopsAndCi?: string[] | null;
  databasesList?: string[] | null;
  infrastructure?: string[] | null;
  other?: string[] | null;
}): string[] {
  return [
    ...(profile.languages || []),
    ...(profile.webFrameworks || []),
    ...(profile.dataAndMl || []),
    ...(profile.genaiAndLlm || []),
    ...(profile.cloudServices || []),
    ...(profile.securityTools || []),
    ...(profile.devopsAndCi || []),
    ...(profile.databasesList || []),
    ...(profile.infrastructure || []),
    ...(profile.other || []),
  ].filter(Boolean);
}

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const stackProfileInput = z.object({
  customerName: z.string().min(1),
  engagementId: z.number().optional(),
  languages: z.array(z.string()).optional(),
  webFrameworks: z.array(z.string()).optional(),
  dataAndMl: z.array(z.string()).optional(),
  genaiAndLlm: z.array(z.string()).optional(),
  cloudServices: z.array(z.string()).optional(),
  securityTools: z.array(z.string()).optional(),
  devopsAndCi: z.array(z.string()).optional(),
  databasesList: z.array(z.string()).optional(),
  infrastructure: z.array(z.string()).optional(),
  other: z.array(z.string()).optional(),
  notes: z.string().optional(),
});

// ─── Router ─────────────────────────────────────────────────────────────────

export const stackProfileRouter = router({
  /** List all stack profiles */
  list: protectedProcedure.query(async () => {
    const db = await getDb();
    const profiles = await db.select().from(customerStackProfiles).orderBy(desc(customerStackProfiles.updatedAt));
    return profiles;
  }),

  /** Get a single stack profile by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [profile] = await db.select().from(customerStackProfiles).where(eq(customerStackProfiles.id, input.id));
      if (!profile) throw new TRPCError({ code: "NOT_FOUND", message: "Stack profile not found" });
      return profile;
    }),

  /** Get stack profile by engagement ID */
  getByEngagement: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const profiles = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.engagementId, input.engagementId))
        .orderBy(desc(customerStackProfiles.updatedAt));
      return profiles;
    }),

  /** Create a new stack profile */
  create: protectedProcedure
    .input(stackProfileInput)
    .mutation(async ({ input, ctx }) => {
      const allTechs = flattenStack(input);
      const { matched, coveragePercent, gaps } = matchScannersToStack(allTechs);

      const db = await getDb();
      const [result] = await db.insert(customerStackProfiles).values({
        customerName: input.customerName,
        engagementId: input.engagementId || null,
        languages: input.languages || null,
        webFrameworks: input.webFrameworks || null,
        dataAndMl: input.dataAndMl || null,
        genaiAndLlm: input.genaiAndLlm || null,
        cloudServices: input.cloudServices || null,
        securityTools: input.securityTools || null,
        devopsAndCi: input.devopsAndCi || null,
        databasesList: input.databasesList || null,
        infrastructure: input.infrastructure || null,
        other: input.other || null,
        matchedScanners: matched,
        coveragePercent,
        gaps,
        notes: input.notes || null,
        createdBy: ctx.user?.id || null,
      });

      return { id: result.insertId, matchedScanners: matched, coveragePercent, gaps };
    }),

  /** Update an existing stack profile */
  update: protectedProcedure
    .input(z.object({ id: z.number() }).merge(stackProfileInput.partial()))
    .mutation(async ({ input }) => {
      const { id, ...updates } = input;
      const allTechs = flattenStack(updates as any);
      let matchData: any = {};
      if (allTechs.length > 0) {
        const { matched, coveragePercent, gaps } = matchScannersToStack(allTechs);
        matchData = { matchedScanners: matched, coveragePercent, gaps };
      }

      const db = await getDb();
      await db.update(customerStackProfiles)
        .set({ ...updates, ...matchData })
        .where(eq(customerStackProfiles.id, id));

      return { success: true, ...matchData };
    }),

  /** Delete a stack profile */
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.delete(customerStackProfiles).where(eq(customerStackProfiles.id, input.id));
      return { success: true };
    }),

  /** Get scanner registry (available modules) */
  getScannerRegistry: protectedProcedure.query(() => {
    return Object.entries(SCANNER_REGISTRY).map(([key, scanner]) => ({
      key,
      ...scanner,
    }));
  }),

  /** Match technologies to scanners (preview without saving) */
  matchScanners: protectedProcedure
    .input(z.object({ technologies: z.array(z.string()) }))
    .mutation(({ input }) => {
      return matchScannersToStack(input.technologies);
    }),

  /** Generate a tailored test plan from the stack profile using LLM + scanner modules */
  generateTestPlan: protectedProcedure
    .input(z.object({ profileId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [profile] = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.id, input.profileId));
      if (!profile) throw new TRPCError({ code: "NOT_FOUND", message: "Stack profile not found" });

      const allTechs = flattenStack(profile);
      const { matched } = matchScannersToStack(allTechs);

      // Gather test plan items from each matched scanner module
      const scannerTestPlans: Array<{ scanner: string; items: string[] }> = [];
      for (const scannerKey of matched) {
        try {
          const scanner = SCANNER_REGISTRY[scannerKey];
          if (!scanner) continue;
          const mod = require(scanner.importPath);
          // Each scanner has a generateXxxTestPlan function
          const genFn = Object.values(mod).find((v: any) => typeof v === 'function' && v.name?.includes('TestPlan'));
          if (typeof genFn === 'function') {
            const items = (genFn as Function)({});
            scannerTestPlans.push({ scanner: scanner.name, items: Array.isArray(items) ? items : [] });
          }
        } catch (e: any) {
          scannerTestPlans.push({ scanner: scannerKey, items: [`Error loading scanner: ${e.message}`] });
        }
      }

      // Use LLM to synthesize a comprehensive test plan
      const prompt = `You are a senior penetration tester creating a tailored security test plan for a customer.

Customer: ${profile.customerName}
Technology Stack:
${allTechs.map(t => `- ${t}`).join('\n')}

Matched Scanner Modules (${matched.length}):
${scannerTestPlans.map(sp => `\n### ${sp.scanner}\n${sp.items.map(i => `- ${i}`).join('\n')}`).join('\n')}

Coverage Gaps (technologies without dedicated scanners):
${(profile.gaps as string[] || []).map(g => `- ${g}`).join('\n') || 'None'}

Generate a comprehensive, prioritized test plan with 15-25 items. Each item should have:
- title: Short action title
- description: What to test and why
- scannerModule: Which scanner module handles this (or "manual" if no scanner)
- priority: "critical", "high", "medium", or "low"

Return ONLY a JSON array of objects with these fields.`;

      try {
        const response = await invokeLLM({
          messages: [
            { role: "system", content: "You are a security testing expert. Return only valid JSON arrays." },
            { role: "user", content: prompt },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "test_plan",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  items: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        title: { type: "string" },
                        description: { type: "string" },
                        scannerModule: { type: "string" },
                        priority: { type: "string" },
                      },
                      required: ["title", "description", "scannerModule", "priority"],
                      additionalProperties: false,
                    },
                  },
                },
                required: ["items"],
                additionalProperties: false,
              },
            },
          },
        });

        const content = response.choices?.[0]?.message?.content || '{"items":[]}';
        const parsed = JSON.parse(content);
        const testPlan = parsed.items || parsed;

        // Save the generated test plan back to the profile
        await db.update(customerStackProfiles)
          .set({ generatedTestPlan: testPlan })
          .where(eq(customerStackProfiles.id, input.profileId));

        return { testPlan, scannerTestPlans };
      } catch (e: any) {
        // Fallback: return scanner-generated test plans without LLM synthesis
        const fallbackPlan = scannerTestPlans.flatMap(sp =>
          sp.items.map(item => ({
            title: item.substring(0, 80),
            description: item,
            scannerModule: sp.scanner,
            priority: "medium",
          }))
        );
        await db.update(customerStackProfiles)
          .set({ generatedTestPlan: fallbackPlan })
          .where(eq(customerStackProfiles.id, input.profileId));
        return { testPlan: fallbackPlan, scannerTestPlans, llmError: e.message };
      }
    }),

  /** Run live HTTP probes against a target URL */
  runLiveProbes: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      categories: z.array(z.enum(["faiss", "langchain", "rag", "firebase", "jupyter"])).optional(),
    }))
    .mutation(async ({ input }) => {
      const { buildProbeSpecs, analyzeProbeResponse, generateProbeReport } = require('../lib/scanners/live-probe-engine');
      const url = new URL(input.targetUrl);
      const target = {
        baseUrl: `${url.protocol}//${url.host}`,
        hostname: url.hostname,
        port: url.port ? parseInt(url.port) : undefined,
      };

      const allSpecs = buildProbeSpecs(target);
      // Filter by categories if specified
      const specs = input.categories
        ? allSpecs.filter((s: any) => input.categories!.includes(s.category))
        : allSpecs;

      const startTime = Date.now();
      const results: any[] = [];
      const axios = require('axios');

      // Run probes with concurrency limit
      const CONCURRENCY = 5;
      for (let i = 0; i < specs.length; i += CONCURRENCY) {
        const batch = specs.slice(i, i + CONCURRENCY);
        const batchResults = await Promise.allSettled(
          batch.map(async (spec: any) => {
            try {
              const response = await axios({
                method: spec.method,
                url: `${target.baseUrl}${spec.path}`,
                data: spec.body,
                headers: {
                  ...spec.headers,
                  'User-Agent': 'Mozilla/5.0 (compatible; AC3-SecurityScanner/1.0)',
                },
                timeout: 5000,
                maxRedirects: 3,
                validateStatus: () => true, // Accept all status codes
              });

              const result = analyzeProbeResponse(
                spec.category,
                spec.path,
                response.status,
                typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
                response.headers || {},
                spec.expectedIndicators,
                spec.severity,
              );

              if (result) {
                result.target = target.baseUrl;
                results.push(result);
              }
            } catch (e: any) {
              // Network errors are expected for many probes — skip silently
            }
          })
        );
      }

      const report = generateProbeReport(target, results, Date.now() - startTime);
      return report;
    }),

  /** Run technology auto-detection against a target URL */
  detectTechnologies: protectedProcedure
    .input(z.object({ targetUrl: z.string().url() }))
    .mutation(async ({ input }) => {
      const { detectTechnologies } = require('../lib/scanners/tech-auto-detector');
      const axios = require('axios');
      const url = new URL(input.targetUrl);

      try {
        // Fetch the target to get headers and HTML
        const response = await axios.get(input.targetUrl, {
          timeout: 10000,
          maxRedirects: 5,
          validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; AC3-SecurityScanner/1.0)' },
        });

        const signals = [{
          hostname: url.hostname,
          headers: response.headers || {},
          html: typeof response.data === 'string' ? response.data.substring(0, 50000) : '',
          technologies: [],
          ports: [],
          responseSnippets: [typeof response.data === 'string' ? response.data.substring(0, 10000) : ''],
        }];

        const result = detectTechnologies(signals);
        return result;
      } catch (e: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to detect technologies: ${e.message}`,
        });
      }
    }),
});
