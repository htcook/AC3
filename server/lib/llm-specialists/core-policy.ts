/**
 * AC3 LLM Specialist Architecture — Core Policy
 *
 * Universal policy prompt prepended to ALL specialist LLM calls.
 * Establishes reasoning framework, evidence classification, and confidence scale.
 */

export const CORE_POLICY = `You are the AC3 Security Reasoning Engine.

You reason like a senior penetration tester, red team planner, and threat intelligence analyst.

Your job is to transform raw security telemetry into operationally useful analysis.

Core objectives:
• Identify what each asset or finding most likely represents
• Distinguish signal from noise
• Assess exploitability realistically
• Determine business impact based on asset role
• Map relevant attacker behaviors
• Recommend safe validation actions

Rules:
• Do not assume compromise without evidence
• Clearly separate facts, inferences, and hypotheses
• Prefer conservative reasoning over speculation
• Explain uncertainty
• Consider asset role in business operations
• Identity systems, CI/CD, admin panels, VPNs, and cloud control planes have elevated importance

Evidence tags:
[OBSERVED] — directly seen in scan/recon data
[INFERRED] — logically derived from observed data
[HYPOTHESIS] — plausible but unconfirmed

Confidence scale: High / Medium / Low`;

/**
 * Build a customer context block from engagement metadata.
 */
export function buildCustomerContext(engagement: {
  engagementType: string;
  clientName?: string;
  industry?: string;
  scope?: string;
  targetCount: number;
}): string {
  const lines = [
    `Engagement type: ${engagement.engagementType}`,
    engagement.clientName ? `Client: ${engagement.clientName}` : null,
    engagement.industry ? `Industry: ${engagement.industry}` : null,
    engagement.scope ? `Scope: ${engagement.scope}` : null,
    `Targets in scope: ${engagement.targetCount}`,
  ].filter(Boolean);
  return lines.join('\n');
}

/**
 * Build a compact asset context block from asset data.
 */
export function buildAssetContext(assets: Array<{
  hostname: string;
  ip?: string;
  type: string;
  status?: string;
  ports?: Array<{ port: number; service?: string; version?: string }>;
  technologies?: string[];
  wafDetected?: string;
  cloudProvider?: string;
  riskSignals?: Array<{ severity: string; rationale: string }>;
}>): string {
  return assets.map(a => {
    const parts = [`${a.hostname}${a.ip ? ' (' + a.ip + ')' : ''} [${a.type}]`];
    if (a.status) parts.push(`status:${a.status}`);
    if (a.wafDetected && a.wafDetected !== 'none') parts.push(`WAF:${a.wafDetected}`);
    if (a.cloudProvider) parts.push(`cloud:${a.cloudProvider}`);
    if (a.ports?.length) {
      parts.push(`ports:${a.ports.map(p => `${p.port}/${p.service || '?'}${p.version ? '(' + p.version + ')' : ''}`).join(',')}`);
    }
    if (a.technologies?.length) parts.push(`tech:${a.technologies.slice(0, 8).join(',')}`);
    if (a.riskSignals?.length) parts.push(`risks:${a.riskSignals.length}`);
    return parts.join(' | ');
  }).join('\n');
}

/**
 * Assemble a complete prompt from modular components.
 * Pattern: CORE_POLICY + ROLE_PROMPT + CUSTOMER_CONTEXT + ASSET_CONTEXT + SCAN_DATA
 */
export function assembleSystemPrompt(parts: {
  rolePrompt: string;
  customerContext?: string;
  assetContext?: string;
  additionalContext?: string;
}): string {
  const sections = [CORE_POLICY, '', parts.rolePrompt];
  if (parts.customerContext) {
    sections.push('', '## Engagement Context', parts.customerContext);
  }
  if (parts.assetContext) {
    sections.push('', '## Assets in Scope', parts.assetContext);
  }
  if (parts.additionalContext) {
    sections.push('', parts.additionalContext);
  }
  return sections.join('\n');
}
