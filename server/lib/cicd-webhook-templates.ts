/**
 * CI/CD Webhook Payload Templates
 * 
 * Pre-built formatters for Slack and Microsoft Teams so webhook
 * deliveries render as rich cards instead of raw JSON.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type WebhookFormat = "raw" | "slack" | "teams";

export interface CicdRunPayload {
  pipelineId: number;
  pipelineName: string;
  runId: number;
  status: "passed" | "failed" | "error";
  targetUrl?: string;
  branch?: string;
  commitSha?: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  maxCvss: number;
  failThreshold: number;
  duration?: string;
  newFindings?: number;
  fixedFindings?: number;
  gateEscalationReason?: string;
  threatContext?: {
    uniqueActorsMatched: number;
    actorExposureScore: number;
    ransomwareRiskFindings: number;
    aptRiskFindings: number;
    killChainCoverage: number;
    topActors: Array<{ name: string; type: string; findingCount: number }>;
  };
  dashboardUrl?: string;
}

// ─── Severity Helpers ────────────────────────────────────────────────────────

function statusEmoji(status: string): string {
  switch (status) {
    case "passed": return "\u2705";
    case "failed": return "\u274c";
    case "error": return "\u26a0\ufe0f";
    default: return "\u2753";
  }
}

function statusColor(status: string): string {
  switch (status) {
    case "passed": return "#22c55e";
    case "failed": return "#ef4444";
    case "error": return "#f59e0b";
    default: return "#6b7280";
  }
}

function teamsStatusColor(status: string): string {
  switch (status) {
    case "passed": return "good";
    case "failed": return "attention";
    case "error": return "warning";
    default: return "default";
  }
}

// ─── Slack Block Kit Formatter ───────────────────────────────────────────────

export function formatSlackPayload(data: CicdRunPayload): Record<string, any> {
  const emoji = statusEmoji(data.status);
  const color = statusColor(data.status);
  const totalFindings = data.criticalCount + data.highCount + data.mediumCount + data.lowCount;

  const blocks: any[] = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${emoji} CI/CD Gate ${data.status.toUpperCase()}: ${data.pipelineName}`,
        emoji: true,
      },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Pipeline:*\n${data.pipelineName}` },
        { type: "mrkdwn", text: `*Run:*\n#${data.runId}` },
        { type: "mrkdwn", text: `*Status:*\n${emoji} ${data.status.toUpperCase()}` },
        { type: "mrkdwn", text: `*Max CVSS:*\n${data.maxCvss.toFixed(1)} / ${data.failThreshold}` },
      ],
    },
    { type: "divider" },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: [
          `*Findings:* ${totalFindings} total`,
          `\u2022 :red_circle: Critical: ${data.criticalCount}`,
          `\u2022 :large_orange_circle: High: ${data.highCount}`,
          `\u2022 :large_yellow_circle: Medium: ${data.mediumCount}`,
          `\u2022 :large_blue_circle: Low: ${data.lowCount}`,
        ].join("\n"),
      },
    },
  ];

  // Target and branch info
  const contextElements: any[] = [];
  if (data.targetUrl) contextElements.push({ type: "mrkdwn", text: `*Target:* ${data.targetUrl}` });
  if (data.branch) contextElements.push({ type: "mrkdwn", text: `*Branch:* ${data.branch}` });
  if (data.commitSha) contextElements.push({ type: "mrkdwn", text: `*Commit:* \`${data.commitSha.substring(0, 7)}\`` });
  if (data.duration) contextElements.push({ type: "mrkdwn", text: `*Duration:* ${data.duration}` });
  if (contextElements.length > 0) {
    blocks.push({ type: "context", elements: contextElements.slice(0, 10) });
  }

  // Delta info
  if (data.newFindings !== undefined || data.fixedFindings !== undefined) {
    const deltaLines: string[] = [];
    if (data.newFindings) deltaLines.push(`:arrow_up: ${data.newFindings} new finding(s)`);
    if (data.fixedFindings) deltaLines.push(`:arrow_down: ${data.fixedFindings} fixed finding(s)`);
    if (deltaLines.length > 0) {
      blocks.push({
        type: "section",
        text: { type: "mrkdwn", text: `*Baseline Comparison:*\n${deltaLines.join("\n")}` },
      });
    }
  }

  // Gate escalation
  if (data.gateEscalationReason) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `:rotating_light: *THREAT ESCALATION*\n${data.gateEscalationReason}`,
      },
    });
  }

  // Threat intelligence
  if (data.threatContext) {
    const tc = data.threatContext;
    const threatLines = [
      `*Threat Intelligence:*`,
      `\u2022 Actors Matched: ${tc.uniqueActorsMatched} | Exposure Score: ${tc.actorExposureScore}/100`,
      `\u2022 Kill Chain Coverage: ${tc.killChainCoverage}%`,
    ];
    if (tc.ransomwareRiskFindings > 0) threatLines.push(`:warning: Ransomware Risk: ${tc.ransomwareRiskFindings} findings`);
    if (tc.aptRiskFindings > 0) threatLines.push(`:shield: APT Risk: ${tc.aptRiskFindings} findings`);
    if (tc.topActors?.length > 0) {
      threatLines.push(`\n*Top Actors:*`);
      for (const actor of tc.topActors.slice(0, 3)) {
        threatLines.push(`\u2022 ${actor.name} (${actor.type}) \u2014 ${actor.findingCount} findings`);
      }
    }
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: threatLines.join("\n") },
    });
  }

  // Dashboard link
  if (data.dashboardUrl) {
    blocks.push({
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "View in Dashboard", emoji: true },
          url: data.dashboardUrl,
          style: data.status === "failed" ? "danger" : "primary",
        },
      ],
    });
  }

  return {
    text: `${emoji} CI/CD Gate ${data.status.toUpperCase()}: ${data.pipelineName} (Run #${data.runId})`,
    attachments: [{ color, blocks }],
  };
}

// ─── Microsoft Teams Adaptive Card Formatter ─────────────────────────────────

export function formatTeamsPayload(data: CicdRunPayload): Record<string, any> {
  const emoji = statusEmoji(data.status);
  const color = teamsStatusColor(data.status);
  const totalFindings = data.criticalCount + data.highCount + data.mediumCount + data.lowCount;

  const facts: Array<{ title: string; value: string }> = [
    { title: "Pipeline", value: data.pipelineName },
    { title: "Run", value: `#${data.runId}` },
    { title: "Status", value: `${emoji} ${data.status.toUpperCase()}` },
    { title: "Max CVSS", value: `${data.maxCvss.toFixed(1)} / ${data.failThreshold}` },
    { title: "Total Findings", value: String(totalFindings) },
    { title: "Critical", value: String(data.criticalCount) },
    { title: "High", value: String(data.highCount) },
    { title: "Medium", value: String(data.mediumCount) },
    { title: "Low", value: String(data.lowCount) },
  ];

  if (data.targetUrl) facts.push({ title: "Target", value: data.targetUrl });
  if (data.branch) facts.push({ title: "Branch", value: data.branch });
  if (data.commitSha) facts.push({ title: "Commit", value: data.commitSha.substring(0, 7) });
  if (data.duration) facts.push({ title: "Duration", value: data.duration });
  if (data.newFindings !== undefined) facts.push({ title: "New Findings", value: String(data.newFindings) });
  if (data.fixedFindings !== undefined) facts.push({ title: "Fixed Findings", value: String(data.fixedFindings) });

  const body: any[] = [
    {
      type: "TextBlock",
      size: "Large",
      weight: "Bolder",
      text: `${emoji} CI/CD Gate ${data.status.toUpperCase()}: ${data.pipelineName}`,
      color: color,
      wrap: true,
    },
    {
      type: "FactSet",
      facts: facts.map(f => ({ title: f.title, value: f.value })),
    },
  ];

  // Gate escalation
  if (data.gateEscalationReason) {
    body.push({
      type: "TextBlock",
      text: `\u26a0\ufe0f **THREAT ESCALATION:** ${data.gateEscalationReason}`,
      color: "attention",
      wrap: true,
      weight: "Bolder",
    });
  }

  // Threat intelligence
  if (data.threatContext) {
    const tc = data.threatContext;
    const threatFacts: Array<{ title: string; value: string }> = [
      { title: "Actors Matched", value: String(tc.uniqueActorsMatched) },
      { title: "Exposure Score", value: `${tc.actorExposureScore}/100` },
      { title: "Kill Chain Coverage", value: `${tc.killChainCoverage}%` },
    ];
    if (tc.ransomwareRiskFindings > 0) threatFacts.push({ title: "Ransomware Risk", value: `${tc.ransomwareRiskFindings} findings` });
    if (tc.aptRiskFindings > 0) threatFacts.push({ title: "APT Risk", value: `${tc.aptRiskFindings} findings` });

    body.push({
      type: "TextBlock",
      text: "**Threat Intelligence**",
      weight: "Bolder",
      spacing: "Medium",
    });
    body.push({
      type: "FactSet",
      facts: threatFacts.map(f => ({ title: f.title, value: f.value })),
    });

    if (tc.topActors?.length > 0) {
      body.push({
        type: "TextBlock",
        text: `**Top Actors:** ${tc.topActors.slice(0, 3).map(a => `${a.name} (${a.type})`).join(", ")}`,
        wrap: true,
      });
    }
  }

  // Dashboard action
  const actions: any[] = [];
  if (data.dashboardUrl) {
    actions.push({
      type: "Action.OpenUrl",
      title: "View in Dashboard",
      url: data.dashboardUrl,
    });
  }

  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        contentUrl: null,
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body,
          actions: actions.length > 0 ? actions : undefined,
        },
      },
    ],
  };
}

// ─── Format Dispatcher ───────────────────────────────────────────────────────

/**
 * Format a CI/CD run payload for the specified webhook platform.
 */
export function formatWebhookPayload(data: CicdRunPayload, format: WebhookFormat): Record<string, any> {
  switch (format) {
    case "slack": return formatSlackPayload(data);
    case "teams": return formatTeamsPayload(data);
    case "raw":
    default:
      return {
        event: "cicd.run.completed",
        pipeline: { id: data.pipelineId, name: data.pipelineName },
        run: {
          id: data.runId,
          status: data.status,
          targetUrl: data.targetUrl,
          branch: data.branch,
          commitSha: data.commitSha,
          findings: {
            critical: data.criticalCount,
            high: data.highCount,
            medium: data.mediumCount,
            low: data.lowCount,
            total: data.criticalCount + data.highCount + data.mediumCount + data.lowCount,
          },
          maxCvss: data.maxCvss,
          failThreshold: data.failThreshold,
          duration: data.duration,
          newFindings: data.newFindings,
          fixedFindings: data.fixedFindings,
        },
        gateEscalation: data.gateEscalationReason || null,
        threatContext: data.threatContext || null,
        dashboardUrl: data.dashboardUrl || null,
        timestamp: new Date().toISOString(),
      };
  }
}

/**
 * Auto-detect webhook format from URL patterns
 */
export function detectWebhookFormat(url: string): WebhookFormat {
  const lower = url.toLowerCase();
  if (lower.includes("hooks.slack.com") || lower.includes("slack.com/api")) return "slack";
  if (lower.includes("webhook.office.com") || lower.includes("microsoft.com") || lower.includes("teams")) return "teams";
  return "raw";
}

/**
 * Get available webhook format options
 */
export function getWebhookFormatOptions(): Array<{ value: WebhookFormat; label: string; description: string }> {
  return [
    { value: "raw", label: "Raw JSON", description: "Standard JSON payload with all fields" },
    { value: "slack", label: "Slack", description: "Slack Block Kit with rich formatting and action buttons" },
    { value: "teams", label: "Microsoft Teams", description: "Adaptive Card with facts, colors, and actions" },
  ];
}
