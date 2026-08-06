/**
 * Scope Enforcement Middleware — Automatic ROE boundary validation for all active operations.
 *
 * This middleware intercepts tRPC mutations that contain target parameters
 * (targetUrl, targetHost, targetIp, RHOSTS, etc.) and validates them against
 * the engagement's ROE scope before allowing execution.
 *
 * Architecture:
 *   tRPC mutation → scope-enforcement-middleware → enforceScope() → actual handler
 *
 * The middleware extracts targets from the input, resolves the engagement context,
 * and calls the centralized scope guard. If any target is out of scope, the
 * mutation is blocked with a PRECONDITION_FAILED error and the violation is logged.
 */

import { enforceSingleTarget, enforceScope, filterInScopeTargets, type ScopeTarget, type PermissionFlag } from "./scope-guard";

// ─── Target Extraction ──────────────────────────────────────────────────────

/**
 * Known input field names that contain target addresses.
 * The middleware scans mutation inputs for these fields and extracts targets.
 */
const TARGET_FIELDS = [
  "targetUrl",
  "targetHost",
  "targetIp",
  "targetIps",
  "targetUrls",
  "target",
  "targets",
  "RHOSTS",
  "rhost",
  "rhosts",
  "host",
  "hostname",
  "domain",
  "domains",
  "url",
  "urls",
  "ipAddress",
  "ipAddresses",
  "ipRange",
  "targetIpRange",
  "cidr",
  "subnet",
  "endpoint",
  "endpointUrl",
  "wsdlUrl",
  "graphqlEndpointUrl",
  "openApiSpecUrl",
  "soapWsdlUrl",
] as const;

/**
 * Known input field names that contain the engagement context.
 */
const ENGAGEMENT_FIELDS = [
  "engagementId",
  "engagement_id",
  "pipelineId",
] as const;

/**
 * Tools/procedures that are EXEMPT from scope enforcement because they are:
 * - Read-only / passive (queries, not mutations)
 * - Internal management operations
 * - ROE management itself
 */
const EXEMPT_PROCEDURES = new Set([
  // ROE management
  "roe.create",
  "roe.update",
  "roe.sign",
  "roe.list",
  "roe.get",
  "roeBuilder.create",
  "roeBuilder.update",
  "roeBuilder.sign",
  "roeAudit.list",
  "roeAudit.get",
  // Engagement management (creating engagements, not executing)
  "engagement.create",
  "engagement.update",
  "engagement.list",
  // Passive-only operations
  "threatIntel.search",
  "threatIntel.enrich",
  "darkwebIntel.search",
  "bugBounty.search",
  "credentialAlerts.check",
  // Reporting
  "reportTemplates.generate",
  "stixExport.export",
  "oscalExport.export",
  // System
  "auth.me",
  "auth.logout",
  "system.notifyOwner",
]);

/**
 * Tool name mapping — maps procedure paths to human-readable tool names for audit logs.
 */
const PROCEDURE_TO_TOOL: Record<string, string> = {
  "metasploitCatalog.executeExploit": "Metasploit",
  "metasploitCatalog.runAuxiliary": "Metasploit Auxiliary",
  "msfSessions.runCommand": "Meterpreter",
  "msfSessions.runModule": "Metasploit Module",
  "msfSessions.routeAdd": "Metasploit Pivot",
  "sliverC2.deploy": "Sliver C2",
  "sliverC2.executeTask": "Sliver C2",
  "webAppScanning.startScan": "OWASP ZAP",
  "webAppScanning.importOpenApiSpec": "ZAP OpenAPI Import",
  "nucleiScanner.scan": "Nuclei",
  "nucleiScanner.startScan": "Nuclei",
  "vulnScanner.scan": "Nmap/Vuln Scanner",
  "discoveryEngine.scan": "Discovery Engine",
  "projectdiscovery.subfinder": "Subfinder",
  "projectdiscovery.httpx": "httpx",
  "projectdiscovery.naabu": "Naabu Port Scanner",
  "activeVerification.runProbe": "Active Verification Probe",
  "activeVerification.runBatchProbes": "Active Verification Batch",
  "phishingOps.launchCampaign": "GoPhish",
  "phishingOps.sendTestEmail": "GoPhish Test",
  "evasionEngine.probeDefenses": "Evasion Engine",
  "evasionEngine.testPayload": "Evasion Engine",
  "exploitArsenal.execute": "Exploit Arsenal",
  "payloadGenerator.generate": "Payload Generator",
  "emulationPlaybooks.execute": "Caldera Emulation",
  "atomicRedTeam.execute": "Atomic Red Team",
  "adAttackSim.execute": "AD Attack Simulation",
  "postExploitPlaybooks.execute": "Post-Exploit Playbook",
  "bloodhoundImport.import": "BloodHound/SharpHound",
  "agentlessBas.execute": "Agentless BAS",
  "edrValidation.test": "EDR Validation",
  "ngfwValidation.test": "NGFW Validation",
  "emailSecurity.test": "Email Security Test",
  "icsOtSecurity.scan": "ICS/OT Scanner",
  "cloudAttackPaths.execute": "Cloud Attack Path",
  "cicdPipeline.scan": "CI/CD Pipeline Scanner",
  "configBaseline.scan": "Config Baseline Scanner",
  "remediationVerification.verify": "Remediation Verification",
  "webCrawler.crawl": "Web Crawler",
  "webCrawler.deepCrawl": "Deep Web Crawler",
  "apiSecurity.test": "API Security Tester",
  "engagementAutomation.launch": "Engagement Automation",
  "unifiedPipeline.start": "Unified Pipeline",
  "unifiedPipeline.advancePhase": "Unified Pipeline Phase",
  "aiAttackPlanner.generatePlan": "AI Attack Planner",
  "aiAttackPlanner.executePlan": "AI Attack Planner",
};

/**
 * Permission requirements by tool category.
 */
const TOOL_PERMISSIONS: Record<string, PermissionFlag[]> = {
  "GoPhish": ["socialEngineering"],
  "GoPhish Test": ["socialEngineering"],
  "Evasion Engine": ["dosAllowed"],
  "Metasploit Pivot": ["pivotingAllowed"],
  "Meterpreter": ["pivotingAllowed"],
};

// ─── Extraction Logic ───────────────────────────────────────────────────────

interface ExtractedTargets {
  targets: ScopeTarget[];
  engagementId: number | null;
}

/**
 * Extract target addresses and engagement ID from a tRPC mutation input.
 */
export function extractTargetsFromInput(input: unknown): ExtractedTargets {
  const result: ExtractedTargets = { targets: [], engagementId: null };
  if (!input || typeof input !== "object") return result;

  const obj = input as Record<string, unknown>;

  // Extract engagement ID
  for (const field of ENGAGEMENT_FIELDS) {
    if (typeof obj[field] === "number") {
      result.engagementId = obj[field] as number;
      break;
    }
    if (typeof obj[field] === "string" && !isNaN(Number(obj[field]))) {
      result.engagementId = Number(obj[field]);
      break;
    }
  }

  // Extract targets
  for (const field of TARGET_FIELDS) {
    const value = obj[field];
    if (!value) continue;

    if (typeof value === "string" && value.trim()) {
      // Handle comma-separated values and CIDR ranges
      const parts = value.includes(",") ? value.split(",").map(s => s.trim()) : [value.trim()];
      for (const part of parts) {
        if (part) result.targets.push({ value: part });
      }
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string" && item.trim()) {
          result.targets.push({ value: item.trim() });
        } else if (typeof item === "object" && item !== null) {
          // Handle objects like { ip: "1.2.3.4" } or { url: "https://..." }
          const nested = item as Record<string, unknown>;
          for (const nField of ["ip", "url", "host", "domain", "address", "value"]) {
            if (typeof nested[nField] === "string" && (nested[nField] as string).trim()) {
              result.targets.push({ value: (nested[nField] as string).trim() });
            }
          }
        }
      }
    }
  }

  // Deduplicate targets
  const seen = new Set<string>();
  result.targets = result.targets.filter(t => {
    const key = t.value.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return result;
}

// ─── Middleware Function ────────────────────────────────────────────────────

export interface ScopeEnforcementContext {
  user?: { id: number; name: string; role: string } | null;
}

/**
 * Create a scope enforcement check function that can be called from any tRPC procedure.
 *
 * Usage in a router:
 * ```ts
 * import { checkScopeForMutation } from "../lib/scope-enforcement-middleware";
 *
 * myMutation: protectedProcedure
 *   .input(z.object({ targetUrl: z.string(), engagementId: z.number() }))
 *   .mutation(async ({ input, ctx }) => {
 *     await checkScopeForMutation(input, ctx, "webAppScanning.startScan");
 *     // ... proceed with mutation
 *   }),
 * ```
 */
export async function checkScopeForMutation(
  input: unknown,
  ctx: ScopeEnforcementContext,
  procedurePath: string,
): Promise<void> {
  // Skip exempt procedures
  if (EXEMPT_PROCEDURES.has(procedurePath)) return;

  const { targets, engagementId } = extractTargetsFromInput(input);

  // If no targets found in input, nothing to validate
  if (targets.length === 0) return;

  // If no engagement context, we can't validate scope — log warning but allow
  // (the engagement context should be required for active operations)
  if (!engagementId) {
    console.warn(
      `[Scope Enforcement] No engagementId found in input for ${procedurePath}. ` +
      `Targets: [${targets.map(t => t.value).join(", ")}]. ` +
      `Cannot validate scope without engagement context.`
    );
    return;
  }

  const toolName = PROCEDURE_TO_TOOL[procedurePath] || procedurePath;
  const permissions = TOOL_PERMISSIONS[toolName] || [];

  await enforceScope({
    engagementId,
    targets,
    tool: toolName,
    operatorId: String(ctx.user?.id || "unknown"),
    operatorName: ctx.user?.name,
    requiredPermissions: permissions.length > 0 ? permissions : undefined,
  });
}

/**
 * Batch check: filter targets to only in-scope ones (non-blocking).
 * Returns only the targets that are within the ROE scope.
 * Useful for discovery operations that may find targets outside scope.
 */
export async function filterToInScope(
  input: unknown,
  ctx: ScopeEnforcementContext,
  procedurePath: string,
): Promise<string[]> {
  const { targets, engagementId } = extractTargetsFromInput(input);
  if (targets.length === 0 || !engagementId) return targets.map(t => t.value);

  const toolName = PROCEDURE_TO_TOOL[procedurePath] || procedurePath;
  const result = await filterInScopeTargets(engagementId, targets, toolName);
  return result.map(t => t.value);
}

// ─── Router-Level Enforcement Helpers ───────────────────────────────────────

/**
 * Quick enforcement for routers that have a single target and engagement ID.
 * Throws TRPCError if target is out of scope.
 */
export async function enforceTargetScope(
  engagementId: number,
  target: string,
  tool: string,
  ctx: ScopeEnforcementContext,
  requiredPermissions?: PermissionFlag[],
): Promise<void> {
  await enforceSingleTarget(
    engagementId,
    target,
    tool,
    String(ctx.user?.id || "unknown"),
    ctx.user?.name,
    requiredPermissions,
  );
}

/**
 * Batch enforcement for routers that have multiple targets.
 * Throws TRPCError if ANY target is out of scope.
 */
export async function enforceMultiTargetScope(
  engagementId: number,
  targets: string[],
  tool: string,
  ctx: ScopeEnforcementContext,
  requiredPermissions?: PermissionFlag[],
): Promise<void> {
  await enforceScope({
    engagementId,
    targets: targets.map(t => ({ value: t })),
    tool,
    operatorId: String(ctx.user?.id || "unknown"),
    operatorName: ctx.user?.name,
    requiredPermissions,
  });
}
