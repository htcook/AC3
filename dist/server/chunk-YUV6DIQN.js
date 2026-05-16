import {
  enforceScope,
  enforceSingleTarget,
  filterInScopeTargets,
  init_scope_guard
} from "./chunk-OLSOWELZ.js";

// server/lib/scope-enforcement-middleware.ts
init_scope_guard();
var TARGET_FIELDS = [
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
  "soapWsdlUrl"
];
var ENGAGEMENT_FIELDS = [
  "engagementId",
  "engagement_id",
  "pipelineId"
];
var EXEMPT_PROCEDURES = /* @__PURE__ */ new Set([
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
  "system.notifyOwner"
]);
var PROCEDURE_TO_TOOL = {
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
  "aiAttackPlanner.executePlan": "AI Attack Planner"
};
var TOOL_PERMISSIONS = {
  "GoPhish": ["socialEngineering"],
  "GoPhish Test": ["socialEngineering"],
  "Evasion Engine": ["dosAllowed"],
  "Metasploit Pivot": ["pivotingAllowed"],
  "Meterpreter": ["pivotingAllowed"]
};
function extractTargetsFromInput(input) {
  const result = { targets: [], engagementId: null };
  if (!input || typeof input !== "object") return result;
  const obj = input;
  for (const field of ENGAGEMENT_FIELDS) {
    if (typeof obj[field] === "number") {
      result.engagementId = obj[field];
      break;
    }
    if (typeof obj[field] === "string" && !isNaN(Number(obj[field]))) {
      result.engagementId = Number(obj[field]);
      break;
    }
  }
  for (const field of TARGET_FIELDS) {
    const value = obj[field];
    if (!value) continue;
    if (typeof value === "string" && value.trim()) {
      const parts = value.includes(",") ? value.split(",").map((s) => s.trim()) : [value.trim()];
      for (const part of parts) {
        if (part) result.targets.push({ value: part });
      }
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string" && item.trim()) {
          result.targets.push({ value: item.trim() });
        } else if (typeof item === "object" && item !== null) {
          const nested = item;
          for (const nField of ["ip", "url", "host", "domain", "address", "value"]) {
            if (typeof nested[nField] === "string" && nested[nField].trim()) {
              result.targets.push({ value: nested[nField].trim() });
            }
          }
        }
      }
    }
  }
  const seen = /* @__PURE__ */ new Set();
  result.targets = result.targets.filter((t) => {
    const key = t.value.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return result;
}
async function checkScopeForMutation(input, ctx, procedurePath) {
  if (EXEMPT_PROCEDURES.has(procedurePath)) return;
  const { targets, engagementId } = extractTargetsFromInput(input);
  if (targets.length === 0) return;
  if (!engagementId) {
    console.warn(
      `[Scope Enforcement] No engagementId found in input for ${procedurePath}. Targets: [${targets.map((t) => t.value).join(", ")}]. Cannot validate scope without engagement context.`
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
    requiredPermissions: permissions.length > 0 ? permissions : void 0
  });
}
async function filterToInScope(input, ctx, procedurePath) {
  const { targets, engagementId } = extractTargetsFromInput(input);
  if (targets.length === 0 || !engagementId) return targets.map((t) => t.value);
  const toolName = PROCEDURE_TO_TOOL[procedurePath] || procedurePath;
  const result = await filterInScopeTargets(engagementId, targets, toolName);
  return result.map((t) => t.value);
}
async function enforceTargetScope(engagementId, target, tool, ctx, requiredPermissions) {
  await enforceSingleTarget(
    engagementId,
    target,
    tool,
    String(ctx.user?.id || "unknown"),
    ctx.user?.name,
    requiredPermissions
  );
}
async function enforceMultiTargetScope(engagementId, targets, tool, ctx, requiredPermissions) {
  await enforceScope({
    engagementId,
    targets: targets.map((t) => ({ value: t })),
    tool,
    operatorId: String(ctx.user?.id || "unknown"),
    operatorName: ctx.user?.name,
    requiredPermissions
  });
}

export {
  extractTargetsFromInput,
  checkScopeForMutation,
  filterToInScope,
  enforceTargetScope,
  enforceMultiTargetScope
};
