import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/core-policy.ts
function buildCustomerContext(engagement) {
  const lines = [
    `Engagement type: ${engagement.engagementType}`,
    engagement.clientName ? `Client: ${engagement.clientName}` : null,
    engagement.industry ? `Industry: ${engagement.industry}` : null,
    engagement.scope ? `Scope: ${engagement.scope}` : null,
    `Targets in scope: ${engagement.targetCount}`
  ].filter(Boolean);
  return lines.join("\n");
}
function buildAssetContext(assets) {
  return assets.map((a) => {
    const parts = [`${a.hostname}${a.ip ? " (" + a.ip + ")" : ""} [${a.type}]`];
    if (a.status) parts.push(`status:${a.status}`);
    if (a.wafDetected && a.wafDetected !== "none") parts.push(`WAF:${a.wafDetected}`);
    if (a.cloudProvider) parts.push(`cloud:${a.cloudProvider}`);
    if (a.ports?.length) {
      parts.push(`ports:${a.ports.map((p) => `${p.port}/${p.service || "?"}${p.version ? "(" + p.version + ")" : ""}`).join(",")}`);
    }
    if (a.technologies?.length) parts.push(`tech:${a.technologies.slice(0, 8).join(",")}`);
    if (a.riskSignals?.length) parts.push(`risks:${a.riskSignals.length}`);
    return parts.join(" | ");
  }).join("\n");
}
function assembleSystemPrompt(parts) {
  const sections = [CORE_POLICY, "", parts.rolePrompt];
  if (parts.customerContext) {
    sections.push("", "## Engagement Context", parts.customerContext);
  }
  if (parts.assetContext) {
    sections.push("", "## Assets in Scope", parts.assetContext);
  }
  if (parts.additionalContext) {
    sections.push("", parts.additionalContext);
  }
  return sections.join("\n");
}
var CORE_POLICY;
var init_core_policy = __esm({
  "server/lib/llm-specialists/core-policy.ts"() {
    "use strict";
    CORE_POLICY = `You are the AC3 Security Reasoning Engine.

You reason like a senior penetration tester, red team planner, and threat intelligence analyst.

Your job is to transform raw security telemetry into operationally useful analysis.

Core objectives:
\u2022 Identify what each asset or finding most likely represents
\u2022 Distinguish signal from noise
\u2022 Assess exploitability realistically
\u2022 Determine business impact based on asset role
\u2022 Map relevant attacker behaviors
\u2022 Recommend safe validation actions

Rules:
\u2022 Do not assume compromise without evidence
\u2022 Clearly separate facts, inferences, and hypotheses
\u2022 Prefer conservative reasoning over speculation
\u2022 Explain uncertainty
\u2022 Consider asset role in business operations
\u2022 Identity systems, CI/CD, admin panels, VPNs, and cloud control planes have elevated importance

Evidence tags:
[OBSERVED] \u2014 directly seen in scan/recon data
[INFERRED] \u2014 logically derived from observed data
[HYPOTHESIS] \u2014 plausible but unconfirmed

Confidence scale: High / Medium / Low`;
  }
});

export {
  buildCustomerContext,
  buildAssetContext,
  assembleSystemPrompt,
  init_core_policy
};
