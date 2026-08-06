/**
 * Correlation Thresholds Router
 * Provides chain telemetry data aggregated from vuln_attack_chains and vuln_attack_chain_steps.
 */
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { vulnAttackChains, vulnAttackChainSteps } from "../../drizzle/schema";
import { sql, desc, count, eq } from "drizzle-orm";

export const correlationThresholdsRouter = router({
  /**
   * getChainTelemetry — returns aggregated telemetry for the Chain Telemetry dashboard widget.
   * Summarizes total chains, correlation success rate, top patterns, and recent results.
   */
  getChainTelemetry: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) {
      return {
        totalChains: 0,
        successRate: 0,
        topPatterns: [] as Array<{ name: string; count: number; severity: string }>,
        recentResults: [] as Array<{ chainName: string; steps: number; score: number | null }>,
      };
    }

    // Total chains
    const [totalRow] = await db
      .select({ total: count() })
      .from(vulnAttackChains);
    const totalChains = totalRow?.total || 0;

    // Success rate: chains with status 'mitigated' vs total
    const [mitigatedRow] = await db
      .select({ total: count() })
      .from(vulnAttackChains)
      .where(eq(vulnAttackChains.status, "mitigated"));
    const mitigatedCount = mitigatedRow?.total || 0;
    const successRate = totalChains > 0 ? Math.round((mitigatedCount / totalChains) * 100) : 0;

    // Top patterns: group by entry point, count occurrences, take top 5
    const topPatternsRaw = await db
      .select({
        name: vulnAttackChains.entryPoint,
        severity: vulnAttackChains.compositeSeverity,
        cnt: count(),
      })
      .from(vulnAttackChains)
      .groupBy(vulnAttackChains.entryPoint, vulnAttackChains.compositeSeverity)
      .orderBy(desc(count()))
      .limit(5);

    const topPatterns = topPatternsRaw
      .filter(p => p.name)
      .map(p => ({
        name: p.name || "Unknown",
        count: p.cnt,
        severity: p.severity,
      }));

    // Recent results: last 5 chains with step count
    const recentChains = await db
      .select({
        chainId: vulnAttackChains.chainId,
        chainName: vulnAttackChains.name,
        score: vulnAttackChains.compositeRiskScore,
      })
      .from(vulnAttackChains)
      .orderBy(desc(vulnAttackChains.createdAt))
      .limit(5);

    const recentResults = await Promise.all(
      recentChains.map(async (chain) => {
        const [stepRow] = await db
          .select({ total: count() })
          .from(vulnAttackChainSteps)
          .where(eq(vulnAttackChainSteps.chainId, chain.chainId));
        return {
          chainName: chain.chainName,
          steps: stepRow?.total || 0,
          score: chain.score,
        };
      })
    );

    return {
      totalChains,
      successRate,
      topPatterns,
      recentResults,
    };
  }),
});
