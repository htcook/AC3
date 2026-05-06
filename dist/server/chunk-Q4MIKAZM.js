import {
  init_llm,
  invokeLLM
} from "./chunk-RY5LYP5I.js";
import {
  getDb,
  init_db
} from "./chunk-SI4LILOM.js";
import {
  init_schema,
  nexusShadowConfigs,
  nexusShadowTests
} from "./chunk-YQRYZ5JK.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/shadow-testing.ts
import { eq, and, desc, sql, gte } from "drizzle-orm";
async function shouldShadowTest(caller, priority = "standard") {
  try {
    const db = await getDb();
    if (!db) return null;
    const configs = await db.select().from(nexusShadowConfigs).where(eq(nexusShadowConfigs.nscEnabled, 1));
    if (configs.length === 0) return null;
    for (const config of configs) {
      if (config.nscCallerFilter && config.nscCallerFilter.length > 0) {
        if (!caller.startsWith(config.nscCallerFilter)) continue;
      }
      if (config.nscPriorityFilter && config.nscPriorityFilter !== "all") {
        if (config.nscPriorityFilter !== priority) continue;
      }
      if (activeShadowCount >= (config.nscMaxConcurrent || MAX_ACTIVE_DEFAULT)) continue;
      const roll = Math.random() * 100;
      if (roll > (config.nscShadowPercentage || 5)) continue;
      return {
        id: config.id,
        configName: config.nscConfigName,
        enabled: config.nscEnabled === 1,
        shadowPercentage: config.nscShadowPercentage,
        primaryModel: config.nscPrimaryModel,
        experimentalModel: config.nscExperimentalModel,
        callerFilter: config.nscCallerFilter || "",
        priorityFilter: config.nscPriorityFilter || "all",
        maxConcurrent: config.nscMaxConcurrent,
        activeShadowTests: config.nscActiveShadowTests,
        totalRuns: config.nscTotalRuns
      };
    }
    return null;
  } catch (err) {
    console.warn("[ShadowTest] Error checking shadow test eligibility:", err);
    return null;
  }
}
async function executeShadowTest(config, originalParams, primaryResult) {
  activeShadowCount++;
  const caller = originalParams._caller || "unknown";
  let testId;
  try {
    const db = await getDb();
    if (!db) return;
    const [insertResult] = await db.insert(nexusShadowTests).values({
      nstConfigId: config.id,
      nstCaller: caller,
      nstPromptSnippet: extractPromptSnippet(originalParams),
      nstPrimaryModel: config.primaryModel,
      nstPrimaryLatencyMs: null,
      nstPrimaryTokensIn: primaryResult.usage?.prompt_tokens ?? 0,
      nstPrimaryTokensOut: primaryResult.usage?.completion_tokens ?? 0,
      nstPrimaryScore: null,
      nstExperimentalModel: config.experimentalModel,
      nstExperimentalLatencyMs: null,
      nstExperimentalTokensIn: null,
      nstExperimentalTokensOut: null,
      nstExperimentalScore: null,
      nstStatus: "running"
    });
    testId = insertResult.insertId;
    await db.update(nexusShadowConfigs).set({
      nscActiveShadowTests: sql`${nexusShadowConfigs.nscActiveShadowTests} + 1`,
      nscTotalRuns: sql`${nexusShadowConfigs.nscTotalRuns} + 1`
    }).where(eq(nexusShadowConfigs.id, config.id));
    const expStart = Date.now();
    const experimentalResult = await invokeLLM({
      ...originalParams,
      _caller: `shadow-test:${caller}`,
      _priority: "bulk"
      // Always use bulk priority for shadow tests to save costs
    });
    const expLatencyMs = Date.now() - expStart;
    const primaryContent = extractResponseContent(primaryResult);
    const experimentalContent = extractResponseContent(experimentalResult);
    const judgeResult = await judgeShadowTest(
      caller,
      extractPromptSnippet(originalParams),
      primaryContent,
      experimentalContent,
      config.primaryModel,
      config.experimentalModel
    );
    await db.update(nexusShadowTests).set({
      nstPrimaryLatencyMs: primaryResult.usage ? Math.round((primaryResult.usage.total_tokens || 0) * 0.05) : null,
      // estimate
      nstExperimentalLatencyMs: expLatencyMs,
      nstExperimentalTokensIn: experimentalResult.usage?.prompt_tokens ?? 0,
      nstExperimentalTokensOut: experimentalResult.usage?.completion_tokens ?? 0,
      nstPrimaryScore: judgeResult.primaryScore,
      nstExperimentalScore: judgeResult.experimentalScore,
      nstJudgeVerdict: judgeResult.verdict,
      nstJudgeReasoning: judgeResult.reasoning,
      nstJudgeScore: judgeResult.confidenceScore,
      nstStatus: "completed",
      nstCompletedAt: (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace("T", " ")
    }).where(eq(nexusShadowTests.id, testId));
    console.log(
      `[ShadowTest] Completed: ${caller} | verdict=${judgeResult.verdict} | primary=${judgeResult.primaryScore}/100 experimental=${judgeResult.experimentalScore}/100`
    );
  } catch (err) {
    console.warn(`[ShadowTest] Error executing shadow test for ${caller}:`, err.message);
    if (testId) {
      try {
        const db = await getDb();
        if (db) {
          await db.update(nexusShadowTests).set({
            nstStatus: "error",
            nstErrorMessage: err.message?.slice(0, 1e3),
            nstCompletedAt: (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace("T", " ")
          }).where(eq(nexusShadowTests.id, testId));
        }
      } catch {
      }
    }
  } finally {
    activeShadowCount--;
    try {
      const db = await getDb();
      if (db) {
        await db.update(nexusShadowConfigs).set({
          nscActiveShadowTests: sql`GREATEST(${nexusShadowConfigs.nscActiveShadowTests} - 1, 0)`
        }).where(eq(nexusShadowConfigs.id, config.id));
      }
    } catch {
    }
  }
}
async function judgeShadowTest(caller, prompt, primaryResponse, experimentalResponse, primaryModel, experimentalModel) {
  try {
    const resp = await invokeLLM({
      _caller: "shadow-test:judge",
      _priority: "bulk",
      messages: [
        {
          role: "system",
          content: `You are an impartial LLM output quality judge for an offensive security platform. Compare two model responses to the same prompt and evaluate which is better.

Evaluation criteria (weighted):
1. **Accuracy** (30%): Factual correctness, no hallucinations
2. **Completeness** (25%): Covers all aspects of the request
3. **Specificity** (20%): Provides actionable, specific details vs. generic advice
4. **Security Awareness** (15%): Appropriate handling of sensitive security topics
5. **Format Quality** (10%): Well-structured, clear, professional output

Score each response 0-100 on these criteria, then provide an overall verdict.`
        },
        {
          role: "user",
          content: `Caller: ${caller}
Prompt: ${prompt.slice(0, 1500)}

--- Response A (${primaryModel}) ---
${primaryResponse.slice(0, 3e3)}

--- Response B (${experimentalModel}) ---
${experimentalResponse.slice(0, 3e3)}

Compare these responses and provide your judgment.`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "shadow_test_judgment",
          strict: true,
          schema: {
            type: "object",
            properties: {
              primaryScore: { type: "number", description: "Score for Response A (0-100)" },
              experimentalScore: { type: "number", description: "Score for Response B (0-100)" },
              verdict: {
                type: "string",
                enum: ["primary_better", "experimental_better", "tie"],
                description: "Which response is better overall"
              },
              reasoning: { type: "string", description: "Detailed reasoning for the verdict" },
              confidenceScore: { type: "number", description: "Confidence in the verdict (0-100)" }
            },
            required: ["primaryScore", "experimentalScore", "verdict", "reasoning", "confidenceScore"],
            additionalProperties: false
          }
        }
      }
    });
    const result = JSON.parse(resp.choices[0].message.content ?? "{}");
    return {
      verdict: result.verdict || "tie",
      reasoning: result.reasoning || "No reasoning provided",
      primaryScore: Math.min(100, Math.max(0, result.primaryScore || 50)),
      experimentalScore: Math.min(100, Math.max(0, result.experimentalScore || 50)),
      confidenceScore: Math.min(100, Math.max(0, result.confidenceScore || 50))
    };
  } catch (err) {
    console.warn("[ShadowTest] Judge evaluation failed:", err.message);
    return {
      verdict: "error",
      reasoning: `Judge evaluation failed: ${err.message}`,
      primaryScore: 0,
      experimentalScore: 0,
      confidenceScore: 0
    };
  }
}
async function getShadowTestAnalytics(windowDays = 30) {
  const db = await getDb();
  if (!db) return null;
  const cutoff = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1e3);
  const cutoffStr = cutoff.toISOString().slice(0, 19).replace("T", " ");
  const verdicts = await db.select({
    verdict: nexusShadowTests.nstJudgeVerdict,
    count: sql`COUNT(*)`,
    avgPrimaryScore: sql`AVG(${nexusShadowTests.nstPrimaryScore})`,
    avgExperimentalScore: sql`AVG(${nexusShadowTests.nstExperimentalScore})`,
    avgConfidence: sql`AVG(${nexusShadowTests.nstJudgeScore})`
  }).from(nexusShadowTests).where(
    and(
      eq(nexusShadowTests.nstStatus, "completed"),
      gte(nexusShadowTests.nstCreatedAt, cutoffStr)
    )
  ).groupBy(nexusShadowTests.nstJudgeVerdict);
  const daily = await db.select({
    day: sql`DATE(${nexusShadowTests.nstCreatedAt})`.as("day"),
    total: sql`COUNT(*)`,
    primaryWins: sql`SUM(CASE WHEN ${nexusShadowTests.nstJudgeVerdict} = 'primary_better' THEN 1 ELSE 0 END)`,
    experimentalWins: sql`SUM(CASE WHEN ${nexusShadowTests.nstJudgeVerdict} = 'experimental_better' THEN 1 ELSE 0 END)`,
    ties: sql`SUM(CASE WHEN ${nexusShadowTests.nstJudgeVerdict} = 'tie' THEN 1 ELSE 0 END)`,
    errors: sql`SUM(CASE WHEN ${nexusShadowTests.nstJudgeVerdict} = 'error' THEN 1 ELSE 0 END)`,
    avgPrimaryScore: sql`AVG(${nexusShadowTests.nstPrimaryScore})`,
    avgExperimentalScore: sql`AVG(${nexusShadowTests.nstExperimentalScore})`
  }).from(nexusShadowTests).where(gte(nexusShadowTests.nstCreatedAt, cutoffStr)).groupBy(sql`DATE(${nexusShadowTests.nstCreatedAt})`).orderBy(sql`day`);
  const topCallers = await db.select({
    caller: nexusShadowTests.nstCaller,
    total: sql`COUNT(*)`,
    primaryWins: sql`SUM(CASE WHEN ${nexusShadowTests.nstJudgeVerdict} = 'primary_better' THEN 1 ELSE 0 END)`,
    experimentalWins: sql`SUM(CASE WHEN ${nexusShadowTests.nstJudgeVerdict} = 'experimental_better' THEN 1 ELSE 0 END)`,
    avgPrimaryScore: sql`AVG(${nexusShadowTests.nstPrimaryScore})`,
    avgExperimentalScore: sql`AVG(${nexusShadowTests.nstExperimentalScore})`
  }).from(nexusShadowTests).where(
    and(
      eq(nexusShadowTests.nstStatus, "completed"),
      gte(nexusShadowTests.nstCreatedAt, cutoffStr)
    )
  ).groupBy(nexusShadowTests.nstCaller).orderBy(desc(sql`COUNT(*)`)).limit(15);
  const latencyComparison = await db.select({
    avgPrimaryLatency: sql`AVG(${nexusShadowTests.nstPrimaryLatencyMs})`,
    avgExperimentalLatency: sql`AVG(${nexusShadowTests.nstExperimentalLatencyMs})`,
    avgPrimaryTokensIn: sql`AVG(${nexusShadowTests.nstPrimaryTokensIn})`,
    avgPrimaryTokensOut: sql`AVG(${nexusShadowTests.nstPrimaryTokensOut})`,
    avgExperimentalTokensIn: sql`AVG(${nexusShadowTests.nstExperimentalTokensIn})`,
    avgExperimentalTokensOut: sql`AVG(${nexusShadowTests.nstExperimentalTokensOut})`
  }).from(nexusShadowTests).where(
    and(
      eq(nexusShadowTests.nstStatus, "completed"),
      gte(nexusShadowTests.nstCreatedAt, cutoffStr)
    )
  );
  const recentTests = await db.select().from(nexusShadowTests).where(gte(nexusShadowTests.nstCreatedAt, cutoffStr)).orderBy(desc(nexusShadowTests.nstCreatedAt)).limit(20);
  return {
    verdicts: verdicts.map((v) => ({
      verdict: v.verdict,
      count: Number(v.count),
      avgPrimaryScore: Math.round(Number(v.avgPrimaryScore) || 0),
      avgExperimentalScore: Math.round(Number(v.avgExperimentalScore) || 0),
      avgConfidence: Math.round(Number(v.avgConfidence) || 0)
    })),
    daily: daily.map((d) => ({
      day: d.day,
      total: Number(d.total),
      primaryWins: Number(d.primaryWins),
      experimentalWins: Number(d.experimentalWins),
      ties: Number(d.ties),
      errors: Number(d.errors),
      avgPrimaryScore: Math.round(Number(d.avgPrimaryScore) || 0),
      avgExperimentalScore: Math.round(Number(d.avgExperimentalScore) || 0)
    })),
    topCallers: topCallers.map((c) => ({
      caller: c.caller,
      total: Number(c.total),
      primaryWins: Number(c.primaryWins),
      experimentalWins: Number(c.experimentalWins),
      avgPrimaryScore: Math.round(Number(c.avgPrimaryScore) || 0),
      avgExperimentalScore: Math.round(Number(c.avgExperimentalScore) || 0)
    })),
    latencyComparison: latencyComparison[0] ? {
      avgPrimaryLatency: Math.round(Number(latencyComparison[0].avgPrimaryLatency) || 0),
      avgExperimentalLatency: Math.round(Number(latencyComparison[0].avgExperimentalLatency) || 0),
      avgPrimaryTokensIn: Math.round(Number(latencyComparison[0].avgPrimaryTokensIn) || 0),
      avgPrimaryTokensOut: Math.round(Number(latencyComparison[0].avgPrimaryTokensOut) || 0),
      avgExperimentalTokensIn: Math.round(Number(latencyComparison[0].avgExperimentalTokensIn) || 0),
      avgExperimentalTokensOut: Math.round(Number(latencyComparison[0].avgExperimentalTokensOut) || 0)
    } : null,
    recentTests,
    windowDays
  };
}
function extractPromptSnippet(params) {
  const lastUserMsg = [...params.messages].reverse().find((m) => m.role === "user");
  if (!lastUserMsg) return "";
  const content = typeof lastUserMsg.content === "string" ? lastUserMsg.content : lastUserMsg.content?.map((c) => c.text || "").join(" ") || "";
  return content.slice(0, 2e3);
}
function extractResponseContent(result) {
  const content = result.choices?.[0]?.message?.content;
  if (!content) return "";
  if (typeof content === "string") return content;
  return content.map((c) => c.text || "").join(" ");
}
var activeShadowCount, MAX_ACTIVE_DEFAULT;
var init_shadow_testing = __esm({
  "server/lib/shadow-testing.ts"() {
    init_llm();
    init_db();
    init_schema();
    activeShadowCount = 0;
    MAX_ACTIVE_DEFAULT = 10;
  }
});

export {
  shouldShadowTest,
  executeShadowTest,
  getShadowTestAnalytics,
  init_shadow_testing
};
