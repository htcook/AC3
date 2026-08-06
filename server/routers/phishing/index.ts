/**
 * Phishing Operations Router — Merged Index
 *
 * Merges three sub-routers (campaign management, template/arsenal, reporting/exploits)
 * into a single `phishingOpsRouter` so the frontend namespace `trpc.phishingOps.*`
 * remains unchanged.
 */

import { router } from "../../_core/trpc";
import { campaignMgmtRouter } from "./campaign-mgmt";
import { templateArsenalRouter } from "./template-arsenal";
import { reportingExploitsRouter } from "./reporting-exploits";

export const phishingOpsRouter = router({
  // Campaign lifecycle
  ...campaignMgmtRouter._def.procedures,
  // Template & arsenal management
  ...templateArsenalRouter._def.procedures,
  // Reporting & exploit library
  ...reportingExploitsRouter._def.procedures,
});
