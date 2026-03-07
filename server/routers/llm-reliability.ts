import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";
import {
  getCircuitState,
  getCircuitBreakerStats,
  resetCircuitBreaker,
  configureCircuitBreaker,
  getCacheStats,
  clearPromptCache,
  configureCaching,
  getLLMHealthMetrics,
  isLLMAvailable,
  recordPerformanceSample,
  type CircuitBreakerConfig,
} from "../lib/llm-reliability";

export const llmReliabilityRouter = router({
  /** Get LLM health metrics including latency, error rate, and availability */
  getHealthMetrics: protectedProcedure.query(() => {
    return getLLMHealthMetrics();
  }),

  /** Check if LLM is currently available */
  isAvailable: protectedProcedure.query(() => {
    return { available: isLLMAvailable(), circuitState: getCircuitState() };
  }),

  /** Get circuit breaker state and stats */
  getCircuitBreaker: protectedProcedure.query(() => {
    return {
      state: getCircuitState(),
      stats: getCircuitBreakerStats(),
    };
  }),

  /** Reset the circuit breaker (admin only) */
  resetCircuitBreaker: adminProcedure.mutation(() => {
    resetCircuitBreaker();
    return { success: true, state: getCircuitState() };
  }),

  /** Configure circuit breaker settings (admin only) */
  configureCircuitBreaker: adminProcedure
    .input(z.object({
      failureThreshold: z.number().min(1).max(50).optional(),
      resetTimeoutMs: z.number().min(5000).max(600000).optional(),
      halfOpenMaxAttempts: z.number().min(1).max(10).optional(),
    }))
    .mutation(({ input }) => {
      configureCircuitBreaker(input as Partial<CircuitBreakerConfig>);
      return { success: true, stats: getCircuitBreakerStats() };
    }),

  /** Get prompt cache statistics */
  getCacheStats: protectedProcedure.query(() => {
    return getCacheStats();
  }),

  /** Clear the prompt cache (admin only) */
  clearCache: adminProcedure.mutation(() => {
    clearPromptCache();
    return { success: true, message: "Prompt cache cleared" };
  }),

  /** Configure caching settings (admin only) */
  configureCaching: adminProcedure
    .input(z.object({
      ttlMs: z.number().min(0).max(3600000).optional(),
      enabled: z.boolean().optional(),
      maxSize: z.number().min(0).max(10000).optional(),
    }))
    .mutation(({ input }) => {
      configureCaching(input);
      return { success: true, stats: getCacheStats() };
    }),

  /** Get full health dashboard with all metrics */
  getDashboard: protectedProcedure.query(() => {
    return {
      health: getLLMHealthMetrics(),
      circuitBreaker: {
        state: getCircuitState(),
        stats: getCircuitBreakerStats(),
      },
      cache: getCacheStats(),
      available: isLLMAvailable(),
    };
  }),
});
