/**
 * Agent Manager Router — Composed from sub-routers
 *
 * Merges c2-lifecycle and fips-mtls sub-routers into a single flat namespace
 * so the frontend can continue using `trpc.agentManager.*` without changes.
 */

import { router } from "../../_core/trpc";
import { c2LifecycleRouter } from "./c2-lifecycle";
import { fipsMtlsRouter } from "./fips-mtls";

// Merge all sub-router procedures into one flat router.
// tRPC's `router()` accepts procedure maps, so we spread them.
export const agentManagerRouter = router({
  ...c2LifecycleRouter._def.procedures,
  ...fipsMtlsRouter._def.procedures,
});

// Re-export the logAgentEvent helper for use by other modules
export { logAgentEvent } from "./c2-lifecycle";
