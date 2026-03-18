/**
 * NEXUS Shadow Testing Module
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Routes a configurable percentage of LLM requests to an experimental model
 * in parallel with the primary model. Results are compared using an
 * LLM-as-Judge evaluation, providing data-driven insights for model
 * migration decisions.
 *
 * Shadow tests are fire-and-forget — they never block or affect the
 * primary response path. All results are stored in the database for
 * analytics and comparison.
 *
 * Architecture:
 *   1. shouldShadowTest() — probabilistic gate based on config
 *   2. executeShadowTest() — runs experimental model in parallel
 *   3. judgeShadowTest() — LLM-as-Judge compares both responses
 *   4. recordShadowResult() — persists results to DB
 */

import { invokeLLM, type InvokeParams, type InvokeResult } from "../_core/llm";
import { getDb } from "../db";
import { nexusShadowConfigs, nexusShadowTests } from "../../drizzle/schema";
import { eq, and, desc, sql, gte } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ShadowTestResult {
  testId: number;
  configId: number;
  caller: string;
  primaryModel: string;
  experimentalModel: string;
  primaryLatencyMs: number;
  experimentalLatencyMs: number;
  primaryTokens: { in: number; out: number };
  experimentalTokens: { in: number; out: number };
  verdict: 'primary_better' | 'experimental_better' | 'tie' | 'error';
  judgeReasoning: string;
  judgeScore: number;
}

export interface ShadowConfig {
  id: number;
  configName: string;
  enabled: boolean;
  shadowPercentage: number;
  primaryModel: string;
  experimentalModel: string;
  callerFilter: string;
  priorityFilter: string;
  maxConcurrent: number;
  activeShadowTests: number;
  totalRuns: number;
}

// ─── In-memory state for active shadow tests ────────────────────────────────

let activeShadowCount = 0;
const MAX_ACTIVE_DEFAULT = 10;

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Check if a given LLM call should be shadow-tested.
 * Returns the matching config if yes, null if no.
 */
export async function shouldShadowTest(
  caller: string,
  priority: string = 'standard',
): Promise<ShadowConfig | null> {
  try {
    const db = await getDb();
    if (!db) return null;

    // Get all enabled shadow configs
    const configs = await db
      .select()
      .from(nexusShadowConfigs)
      .where(eq(nexusShadowConfigs.enabled, 1));

    if (configs.length === 0) return null;

    for (const config of configs) {
      // Check caller filter
      if (config.callerFilter && config.callerFilter.length > 0) {
        if (!caller.startsWith(config.callerFilter)) continue;
      }

      // Check priority filter
      if (config.priorityFilter && config.priorityFilter !== 'all') {
        if (config.priorityFilter !== priority) continue;
      }

      // Check concurrency limit
      if (activeShadowCount >= (config.maxConcurrent || MAX_ACTIVE_DEFAULT)) continue;

      // Probabilistic gate
      const roll = Math.random() * 100;
      if (roll > (config.shadowPercentage || 5)) continue;

      // This call should be shadow-tested
      return {
        id: config.id,
        configName: config.configName,
        enabled: config.enabled === 1,
        shadowPercentage: config.shadowPercentage,
        primaryModel: config.primaryModel,
        experimentalModel: config.experimentalModel,
        callerFilter: config.callerFilter || '',
        priorityFilter: config.priorityFilter || 'all',
        maxConcurrent: config.maxConcurrent,
        activeShadowTests: config.activeShadowTests,
        totalRuns: config.totalRuns,
      };
    }

    return null;
  } catch (err) {
    console.warn('[ShadowTest] Error checking shadow test eligibility:', err);
    return null;
  }
}

/**
 * Execute a shadow test: run the same prompt against the experimental model
 * and compare results using LLM-as-Judge. This is fire-and-forget.
 */
export async function executeShadowTest(
  config: ShadowConfig,
  originalParams: InvokeParams,
  primaryResult: InvokeResult,
): Promise<void> {
  activeShadowCount++;
  const caller = originalParams._caller || 'unknown';
  let testId: number | undefined;

  try {
    const db = await getDb();
    if (!db) return;

    // Create shadow test record
    const [insertResult] = await db.insert(nexusShadowTests).values({
      configId: config.id,
      caller,
      promptSnippet: extractPromptSnippet(originalParams),
      primaryModel: config.primaryModel,
      primaryLatencyMs: null,
      primaryTokensIn: primaryResult.usage?.prompt_tokens ?? 0,
      primaryTokensOut: primaryResult.usage?.completion_tokens ?? 0,
      primaryScore: null,
      experimentalModel: config.experimentalModel,
      experimentalLatencyMs: null,
      experimentalTokensIn: null,
      experimentalTokensOut: null,
      experimentalScore: null,
      status: 'running',
    });
    testId = insertResult.insertId;

    // Increment active count in DB
    await db.update(nexusShadowConfigs)
      .set({
        activeShadowTests: sql`${nexusShadowConfigs.activeShadowTests} + 1`,
        totalRuns: sql`${nexusShadowConfigs.totalRuns} + 1`,
      })
      .where(eq(nexusShadowConfigs.id, config.id));

    // Run the experimental model
    const expStart = Date.now();
    const experimentalResult = await invokeLLM({
      ...originalParams,
      _caller: `shadow-test:${caller}`,
      _priority: 'bulk', // Always use bulk priority for shadow tests to save costs
    });
    const expLatencyMs = Date.now() - expStart;

    // Extract primary response content
    const primaryContent = extractResponseContent(primaryResult);
    const experimentalContent = extractResponseContent(experimentalResult);

    // Run LLM-as-Judge comparison
    const judgeResult = await judgeShadowTest(
      caller,
      extractPromptSnippet(originalParams),
      primaryContent,
      experimentalContent,
      config.primaryModel,
      config.experimentalModel,
    );

    // Update shadow test record with results
    await db.update(nexusShadowTests)
      .set({
        primaryLatencyMs: primaryResult.usage ? Math.round((primaryResult.usage.total_tokens || 0) * 0.05) : null, // estimate
        experimentalLatencyMs: expLatencyMs,
        experimentalTokensIn: experimentalResult.usage?.prompt_tokens ?? 0,
        experimentalTokensOut: experimentalResult.usage?.completion_tokens ?? 0,
        primaryScore: judgeResult.primaryScore,
        experimentalScore: judgeResult.experimentalScore,
        judgeVerdict: judgeResult.verdict,
        judgeReasoning: judgeResult.reasoning,
        judgeScore: judgeResult.confidenceScore,
        status: 'completed',
        completedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
      })
      .where(eq(nexusShadowTests.id, testId));

    console.log(
      `[ShadowTest] Completed: ${caller} | verdict=${judgeResult.verdict} | ` +
      `primary=${judgeResult.primaryScore}/100 experimental=${judgeResult.experimentalScore}/100`
    );

  } catch (err: any) {
    console.warn(`[ShadowTest] Error executing shadow test for ${caller}:`, err.message);

    // Record error
    if (testId) {
      try {
        const db = await getDb();
        if (db) {
          await db.update(nexusShadowTests)
            .set({
              status: 'error',
              errorMessage: err.message?.slice(0, 1000),
              completedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
            })
            .where(eq(nexusShadowTests.id, testId));
        }
      } catch { /* ignore */ }
    }
  } finally {
    activeShadowCount--;

    // Decrement active count in DB
    try {
      const db = await getDb();
      if (db) {
        await db.update(nexusShadowConfigs)
          .set({
            activeShadowTests: sql`GREATEST(${nexusShadowConfigs.activeShadowTests} - 1, 0)`,
          })
          .where(eq(nexusShadowConfigs.id, config.id));
      }
    } catch { /* ignore */ }
  }
}

/**
 * LLM-as-Judge: Compare primary and experimental model responses.
 */
async function judgeShadowTest(
  caller: string,
  prompt: string,
  primaryResponse: string,
  experimentalResponse: string,
  primaryModel: string,
  experimentalModel: string,
): Promise<{
  verdict: 'primary_better' | 'experimental_better' | 'tie' | 'error';
  reasoning: string;
  primaryScore: number;
  experimentalScore: number;
  confidenceScore: number;
}> {
  try {
    const resp = await invokeLLM({
      _caller: 'shadow-test:judge',
      _priority: 'bulk',
      messages: [
        {
          role: 'system',
          content: `You are an impartial LLM output quality judge for an offensive security platform. Compare two model responses to the same prompt and evaluate which is better.

Evaluation criteria (weighted):
1. **Accuracy** (30%): Factual correctness, no hallucinations
2. **Completeness** (25%): Covers all aspects of the request
3. **Specificity** (20%): Provides actionable, specific details vs. generic advice
4. **Security Awareness** (15%): Appropriate handling of sensitive security topics
5. **Format Quality** (10%): Well-structured, clear, professional output

Score each response 0-100 on these criteria, then provide an overall verdict.`,
        },
        {
          role: 'user',
          content: `Caller: ${caller}
Prompt: ${prompt.slice(0, 1500)}

--- Response A (${primaryModel}) ---
${primaryResponse.slice(0, 3000)}

--- Response B (${experimentalModel}) ---
${experimentalResponse.slice(0, 3000)}

Compare these responses and provide your judgment.`,
        },
      ],
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'shadow_test_judgment',
          strict: true,
          schema: {
            type: 'object',
            properties: {
              primaryScore: { type: 'number', description: 'Score for Response A (0-100)' },
              experimentalScore: { type: 'number', description: 'Score for Response B (0-100)' },
              verdict: {
                type: 'string',
                enum: ['primary_better', 'experimental_better', 'tie'],
                description: 'Which response is better overall',
              },
              reasoning: { type: 'string', description: 'Detailed reasoning for the verdict' },
              confidenceScore: { type: 'number', description: 'Confidence in the verdict (0-100)' },
            },
            required: ['primaryScore', 'experimentalScore', 'verdict', 'reasoning', 'confidenceScore'],
            additionalProperties: false,
          },
        },
      },
    });

    const result = JSON.parse(resp.choices[0].message.content ?? '{}');
    return {
      verdict: result.verdict || 'tie',
      reasoning: result.reasoning || 'No reasoning provided',
      primaryScore: Math.min(100, Math.max(0, result.primaryScore || 50)),
      experimentalScore: Math.min(100, Math.max(0, result.experimentalScore || 50)),
      confidenceScore: Math.min(100, Math.max(0, result.confidenceScore || 50)),
    };
  } catch (err: any) {
    console.warn('[ShadowTest] Judge evaluation failed:', err.message);
    return {
      verdict: 'error',
      reasoning: `Judge evaluation failed: ${err.message}`,
      primaryScore: 0,
      experimentalScore: 0,
      confidenceScore: 0,
    };
  }
}

// ─── Analytics Helpers ──────────────────────────────────────────────────────

/**
 * Get shadow testing analytics for a given time window.
 */
export async function getShadowTestAnalytics(windowDays: number = 30) {
  const db = await getDb();
  if (!db) return null;

  const cutoff = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000);
  const cutoffStr = cutoff.toISOString().slice(0, 19).replace('T', ' ');

  // Overall verdict distribution
  const verdicts = await db
    .select({
      verdict: nexusShadowTests.judgeVerdict,
      count: sql<number>`COUNT(*)`,
      avgPrimaryScore: sql<number>`AVG(${nexusShadowTests.primaryScore})`,
      avgExperimentalScore: sql<number>`AVG(${nexusShadowTests.experimentalScore})`,
      avgConfidence: sql<number>`AVG(${nexusShadowTests.judgeScore})`,
    })
    .from(nexusShadowTests)
    .where(
      and(
        eq(nexusShadowTests.status, 'completed'),
        gte(nexusShadowTests.createdAt, cutoffStr),
      )
    )
    .groupBy(nexusShadowTests.judgeVerdict);

  // Daily trend
  const daily = await db
    .select({
      day: sql<string>`DATE(${nexusShadowTests.createdAt})`.as('day'),
      total: sql<number>`COUNT(*)`,
      primaryWins: sql<number>`SUM(CASE WHEN ${nexusShadowTests.judgeVerdict} = 'primary_better' THEN 1 ELSE 0 END)`,
      experimentalWins: sql<number>`SUM(CASE WHEN ${nexusShadowTests.judgeVerdict} = 'experimental_better' THEN 1 ELSE 0 END)`,
      ties: sql<number>`SUM(CASE WHEN ${nexusShadowTests.judgeVerdict} = 'tie' THEN 1 ELSE 0 END)`,
      errors: sql<number>`SUM(CASE WHEN ${nexusShadowTests.judgeVerdict} = 'error' THEN 1 ELSE 0 END)`,
      avgPrimaryScore: sql<number>`AVG(${nexusShadowTests.primaryScore})`,
      avgExperimentalScore: sql<number>`AVG(${nexusShadowTests.experimentalScore})`,
    })
    .from(nexusShadowTests)
    .where(gte(nexusShadowTests.createdAt, cutoffStr))
    .groupBy(sql`DATE(${nexusShadowTests.createdAt})`)
    .orderBy(sql`day`);

  // Top callers by shadow test count
  const topCallers = await db
    .select({
      caller: nexusShadowTests.caller,
      total: sql<number>`COUNT(*)`,
      primaryWins: sql<number>`SUM(CASE WHEN ${nexusShadowTests.judgeVerdict} = 'primary_better' THEN 1 ELSE 0 END)`,
      experimentalWins: sql<number>`SUM(CASE WHEN ${nexusShadowTests.judgeVerdict} = 'experimental_better' THEN 1 ELSE 0 END)`,
      avgPrimaryScore: sql<number>`AVG(${nexusShadowTests.primaryScore})`,
      avgExperimentalScore: sql<number>`AVG(${nexusShadowTests.experimentalScore})`,
    })
    .from(nexusShadowTests)
    .where(
      and(
        eq(nexusShadowTests.status, 'completed'),
        gte(nexusShadowTests.createdAt, cutoffStr),
      )
    )
    .groupBy(nexusShadowTests.caller)
    .orderBy(desc(sql`COUNT(*)`))
    .limit(15);

  // Latency comparison
  const latencyComparison = await db
    .select({
      avgPrimaryLatency: sql<number>`AVG(${nexusShadowTests.primaryLatencyMs})`,
      avgExperimentalLatency: sql<number>`AVG(${nexusShadowTests.experimentalLatencyMs})`,
      avgPrimaryTokensIn: sql<number>`AVG(${nexusShadowTests.primaryTokensIn})`,
      avgPrimaryTokensOut: sql<number>`AVG(${nexusShadowTests.primaryTokensOut})`,
      avgExperimentalTokensIn: sql<number>`AVG(${nexusShadowTests.experimentalTokensIn})`,
      avgExperimentalTokensOut: sql<number>`AVG(${nexusShadowTests.experimentalTokensOut})`,
    })
    .from(nexusShadowTests)
    .where(
      and(
        eq(nexusShadowTests.status, 'completed'),
        gte(nexusShadowTests.createdAt, cutoffStr),
      )
    );

  // Recent tests
  const recentTests = await db
    .select()
    .from(nexusShadowTests)
    .where(gte(nexusShadowTests.createdAt, cutoffStr))
    .orderBy(desc(nexusShadowTests.createdAt))
    .limit(20);

  return {
    verdicts: verdicts.map(v => ({
      verdict: v.verdict,
      count: Number(v.count),
      avgPrimaryScore: Math.round(Number(v.avgPrimaryScore) || 0),
      avgExperimentalScore: Math.round(Number(v.avgExperimentalScore) || 0),
      avgConfidence: Math.round(Number(v.avgConfidence) || 0),
    })),
    daily: daily.map(d => ({
      day: d.day,
      total: Number(d.total),
      primaryWins: Number(d.primaryWins),
      experimentalWins: Number(d.experimentalWins),
      ties: Number(d.ties),
      errors: Number(d.errors),
      avgPrimaryScore: Math.round(Number(d.avgPrimaryScore) || 0),
      avgExperimentalScore: Math.round(Number(d.avgExperimentalScore) || 0),
    })),
    topCallers: topCallers.map(c => ({
      caller: c.caller,
      total: Number(c.total),
      primaryWins: Number(c.primaryWins),
      experimentalWins: Number(c.experimentalWins),
      avgPrimaryScore: Math.round(Number(c.avgPrimaryScore) || 0),
      avgExperimentalScore: Math.round(Number(c.avgExperimentalScore) || 0),
    })),
    latencyComparison: latencyComparison[0] ? {
      avgPrimaryLatency: Math.round(Number(latencyComparison[0].avgPrimaryLatency) || 0),
      avgExperimentalLatency: Math.round(Number(latencyComparison[0].avgExperimentalLatency) || 0),
      avgPrimaryTokensIn: Math.round(Number(latencyComparison[0].avgPrimaryTokensIn) || 0),
      avgPrimaryTokensOut: Math.round(Number(latencyComparison[0].avgPrimaryTokensOut) || 0),
      avgExperimentalTokensIn: Math.round(Number(latencyComparison[0].avgExperimentalTokensIn) || 0),
      avgExperimentalTokensOut: Math.round(Number(latencyComparison[0].avgExperimentalTokensOut) || 0),
    } : null,
    recentTests,
    windowDays,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function extractPromptSnippet(params: InvokeParams): string {
  const lastUserMsg = [...params.messages].reverse().find(m => m.role === 'user');
  if (!lastUserMsg) return '';
  const content = typeof lastUserMsg.content === 'string'
    ? lastUserMsg.content
    : lastUserMsg.content?.map((c: any) => c.text || '').join(' ') || '';
  return content.slice(0, 2000);
}

function extractResponseContent(result: InvokeResult): string {
  const content = result.choices?.[0]?.message?.content;
  if (!content) return '';
  if (typeof content === 'string') return content;
  return content.map((c: any) => c.text || '').join(' ');
}
