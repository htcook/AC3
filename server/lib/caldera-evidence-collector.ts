/**
 * Caldera Evidence Collector
 *
 * Automatically captures forensic-grade evidence from Caldera C2 operations
 * during pentest and red team engagements. Every evidence artifact includes:
 *   - Source IP/URL (attacker / C2 server)
 *   - Destination IP/URL (target / compromised host)
 *   - Precise UTC timestamp
 *
 * Evidence types captured:
 *   1. Agent Check-In Table  — all C2 agents with connection metadata
 *   2. Operation Timeline    — ability executions with MITRE ATT&CK mapping
 *   3. Adversary Profile     — adversary configuration and kill-chain coverage
 *   4. Attack Chain Summary  — end-to-end exploitation → C2 → pivot narrative
 *
 * Each evidence type is rendered as a styled HTML table and converted to a
 * PNG screenshot via the built-in renderer, then stored as an artifact
 * attached to the engagement's report findings.
 */

import { ENV } from "../_core/env";

// ─── Types ──────────────────────────────────────────────────────────────

export interface EvidenceMetadata {
  /** Source of the action (attacker IP, C2 server URL) */
  sourceIp: string;
  sourceUrl: string;
  /** Destination of the action (target host IP, target URL) */
  destinationIp: string;
  destinationUrl: string;
  /** UTC ISO-8601 timestamp when the evidence was captured */
  capturedAt: string;
  /** UTC ISO-8601 timestamp of the original event (if different from capture) */
  eventTimestamp: string;
}

export interface AgentEvidence {
  paw: string;
  host: string;
  platform: string;
  username: string;
  privilege: string;
  pid: number;
  exeName: string;
  contact: string;
  hostIp: string;
  executors: string[];
  created: string;
  lastSeen: string;
  displayName: string;
  linksExecuted: number;
}

export interface OperationLinkEvidence {
  linkId: string;
  paw: string;
  agentHost: string;
  abilityName: string;
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  status: "success" | "failed" | "queued" | "discarded" | "collecting" | "timeout" | "unknown";
  decidedAt: string;
  output?: string;
}

export interface OperationEvidence {
  operationId: string;
  operationName: string;
  state: string;
  startedAt: string;
  adversaryName: string;
  adversaryId: string;
  plannerName: string;
  agentCount: number;
  links: OperationLinkEvidence[];
}

export interface AdversaryEvidence {
  adversaryId: string;
  name: string;
  description: string;
  abilities: Array<{
    abilityId: string;
    name: string;
    tactic: string;
    techniqueId: string;
    techniqueName: string;
  }>;
}

export interface CalderaEvidenceSnapshot {
  /** Engagement context */
  engagementId: number;
  engagementName: string;
  /** Network context — always present on every artifact */
  calderaServerUrl: string;
  calderaServerIp: string;
  /** Captured data */
  agents: AgentEvidence[];
  operations: OperationEvidence[];
  adversaryProfile: AdversaryEvidence | null;
  /** Capture metadata */
  capturedAt: string;
  /** Rendered HTML evidence panels (ready for PNG conversion) */
  renderedHtml: {
    agentTable: string;
    operationTimeline: string;
    adversaryProfile: string;
    attackChainSummary: string;
  };
}

// ─── Caldera API Client ─────────────────────────────────────────────────

const getCalderaUrl = () => ENV.calderaBaseUrl || "";
const getCalderaKey = () => ENV.calderaApiKey || "";

async function calderaApiFetch(endpoint: string): Promise<any | null> {
  const baseUrl = getCalderaUrl();
  const apiKey = getCalderaKey();
  if (!baseUrl || !apiKey) return null;

  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      headers: { KEY: apiKey, "Content-Type": "application/json" },
      signal: AbortSignal.timeout(20000),
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

// ─── Status Code Mapping ────────────────────────────────────────────────

const STATUS_MAP: Record<number, OperationLinkEvidence["status"]> = {
  0: "queued",
  1: "success",
  [-1]: "failed",
  [-2]: "discarded",
  [-3]: "collecting",
  [-4]: "unknown",
  124: "timeout",
};

function mapLinkStatus(code: number): OperationLinkEvidence["status"] {
  return STATUS_MAP[code] || "unknown";
}

// ─── Core Collector Functions ───────────────────────────────────────────

/**
 * Collect all active C2 agents from Caldera.
 */
export async function collectAgents(): Promise<AgentEvidence[]> {
  const raw = await calderaApiFetch("/api/v2/agents");
  if (!Array.isArray(raw)) return [];

  return raw.map((a: any) => ({
    paw: a.paw || "",
    host: a.host || "",
    platform: a.platform || "",
    username: a.username || "",
    privilege: a.privilege || "User",
    pid: a.pid || 0,
    exeName: a.exe_name || "",
    contact: a.contact || "HTTP",
    hostIp: (a.host_ip_addrs || [])[0] || "",
    executors: a.executors || [],
    created: a.created || "",
    lastSeen: a.last_seen || "",
    displayName: a.display_name || `${a.host}$${a.username}`,
    linksExecuted: (a.links || []).length,
  }));
}

/**
 * Collect operation details including the full execution chain.
 */
export async function collectOperation(operationId: string): Promise<OperationEvidence | null> {
  const op = await calderaApiFetch(`/api/v2/operations/${operationId}`);
  if (!op) return null;

  // Build ability lookup from the chain
  const links: OperationLinkEvidence[] = (op.chain || []).map((link: any) => {
    const ability = link.ability || {};
    // Resolve agent host from host_group
    const agentHost = (op.host_group || []).find((h: any) => h.paw === link.paw)?.host || link.paw;

    return {
      linkId: link.id || "",
      paw: link.paw || "",
      agentHost,
      abilityName: ability.name || "Unknown",
      tactic: ability.tactic || "unknown",
      techniqueId: ability.technique_id || "",
      techniqueName: ability.technique_name || "",
      status: mapLinkStatus(link.status),
      decidedAt: link.decide || "",
      output: link.output ? Buffer.from(link.output, "base64").toString("utf-8").slice(0, 2000) : undefined,
    };
  });

  return {
    operationId: String(op.id),
    operationName: op.name || "",
    state: op.state || "unknown",
    startedAt: op.start || "",
    adversaryName: op.adversary?.name || "Unknown",
    adversaryId: op.adversary?.adversary_id || "",
    plannerName: op.planner?.name || "atomic",
    agentCount: (op.host_group || []).length,
    links,
  };
}

/**
 * Collect adversary profile with full ability details.
 */
export async function collectAdversary(adversaryId: string): Promise<AdversaryEvidence | null> {
  const adv = await calderaApiFetch(`/api/v2/adversaries/${adversaryId}`);
  if (!adv) return null;

  // Fetch all abilities to resolve names
  const allAbilities = await calderaApiFetch("/api/v2/abilities");
  const abilityMap = new Map<string, any>();
  if (Array.isArray(allAbilities)) {
    for (const ab of allAbilities) {
      abilityMap.set(ab.ability_id, ab);
    }
  }

  const abilities = (adv.atomic_ordering || []).map((abilityId: string) => {
    const ab = abilityMap.get(abilityId);
    return {
      abilityId,
      name: ab?.name || "Unknown",
      tactic: ab?.tactic || "unknown",
      techniqueId: ab?.technique_id || "",
      techniqueName: ab?.technique_name || "",
    };
  });

  return {
    adversaryId: adv.adversary_id || adversaryId,
    name: adv.name || "Unknown",
    description: adv.description || "",
    abilities,
  };
}

// ─── Full Evidence Snapshot ─────────────────────────────────────────────

/**
 * Capture a complete evidence snapshot for an engagement.
 * This is the main entry point called by the ops-orchestrator.
 */
export async function captureCalderaEvidence(params: {
  engagementId: number;
  engagementName: string;
  operationId?: string;
  adversaryId?: string;
  /** Target assets — used for destination IP/URL context */
  targets?: Array<{ hostname: string; ip: string }>;
}): Promise<CalderaEvidenceSnapshot | null> {
  const calderaUrl = getCalderaUrl();
  if (!calderaUrl) {
    console.log("[CalderaEvidence] No Caldera URL configured, skipping evidence capture");
    return null;
  }

  const capturedAt = new Date().toISOString();
  const calderaIp = extractIpFromUrl(calderaUrl);

  // Collect all data in parallel
  const [agents, operation, adversary] = await Promise.all([
    collectAgents(),
    params.operationId ? collectOperation(params.operationId) : Promise.resolve(null),
    params.adversaryId ? collectAdversary(params.adversaryId) : Promise.resolve(null),
  ]);

  // Build the target context for evidence metadata
  const targetContext = params.targets || [];

  // Render HTML evidence panels
  const renderedHtml = {
    agentTable: renderAgentTable(agents, calderaUrl, calderaIp, capturedAt),
    operationTimeline: operation
      ? renderOperationTimeline(operation, calderaUrl, calderaIp, targetContext, capturedAt)
      : renderNoDataPanel("Operation Timeline", "No operation data available"),
    adversaryProfile: adversary
      ? renderAdversaryProfile(adversary, capturedAt)
      : renderNoDataPanel("Adversary Profile", "No adversary profile available"),
    attackChainSummary: renderAttackChainSummary(agents, operation, adversary, calderaUrl, calderaIp, targetContext, capturedAt),
  };

  return {
    engagementId: params.engagementId,
    engagementName: params.engagementName,
    calderaServerUrl: calderaUrl,
    calderaServerIp: calderaIp,
    agents,
    operations: operation ? [operation] : [],
    adversaryProfile: adversary,
    capturedAt,
    renderedHtml,
  };
}

// ─── HTML Evidence Renderers ────────────────────────────────────────────

const EVIDENCE_CSS = `
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
  .evidence-panel { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .evidence-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #30363d; }
  .evidence-title { font-size: 16px; font-weight: 600; color: #f0f6fc; }
  .evidence-badge { font-size: 11px; padding: 3px 8px; border-radius: 12px; font-weight: 500; }
  .badge-red { background: #da3633; color: #fff; }
  .badge-green { background: #238636; color: #fff; }
  .badge-yellow { background: #d29922; color: #fff; }
  .badge-blue { background: #1f6feb; color: #fff; }
  .badge-gray { background: #484f58; color: #c9d1d9; }
  .meta-row { display: flex; gap: 24px; margin-bottom: 12px; font-size: 12px; color: #8b949e; }
  .meta-label { font-weight: 600; color: #c9d1d9; }
  .meta-value { font-family: 'Cascadia Code', 'Fira Code', monospace; color: #58a6ff; }
  .ip-highlight { color: #f85149; font-weight: 600; }
  .url-highlight { color: #58a6ff; font-weight: 600; }
  .timestamp { color: #d29922; font-family: 'Cascadia Code', monospace; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #21262d; color: #f0f6fc; padding: 8px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #30363d; }
  td { padding: 6px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }
  tr:hover td { background: #1c2128; }
  .status-success { color: #3fb950; font-weight: 600; }
  .status-failed { color: #f85149; font-weight: 600; }
  .status-queued { color: #d29922; }
  .status-unknown { color: #8b949e; }
  .tactic-badge { display: inline-block; font-size: 10px; padding: 2px 6px; border-radius: 4px; background: #1f6feb22; color: #58a6ff; border: 1px solid #1f6feb44; margin-right: 4px; }
  .chain-arrow { color: #484f58; font-size: 18px; margin: 0 8px; }
  .chain-node { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 500; }
  .chain-attacker { background: #da363322; color: #f85149; border: 1px solid #da363366; }
  .chain-target { background: #23863622; color: #3fb950; border: 1px solid #23863666; }
  .chain-action { background: #1f6feb22; color: #58a6ff; border: 1px solid #1f6feb44; }
  .watermark { text-align: right; font-size: 10px; color: #484f58; margin-top: 8px; }
  .section-divider { border-top: 1px solid #30363d; margin: 12px 0; }
</style>
`;

function renderEvidenceWrapper(title: string, badge: string, badgeClass: string, metadata: EvidenceMetadata, bodyHtml: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">${EVIDENCE_CSS}</head>
<body>
<div class="evidence-panel">
  <div class="evidence-header">
    <span class="evidence-title">${escHtml(title)}</span>
    <span class="evidence-badge ${badgeClass}">${escHtml(badge)}</span>
  </div>
  <div class="meta-row">
    <span><span class="meta-label">Source:</span> <span class="ip-highlight">${escHtml(metadata.sourceIp)}</span> <span class="url-highlight">${escHtml(metadata.sourceUrl)}</span></span>
    <span><span class="meta-label">Destination:</span> <span class="ip-highlight">${escHtml(metadata.destinationIp)}</span> <span class="url-highlight">${escHtml(metadata.destinationUrl)}</span></span>
  </div>
  <div class="meta-row">
    <span><span class="meta-label">Event Time:</span> <span class="timestamp">${escHtml(metadata.eventTimestamp)}</span></span>
    <span><span class="meta-label">Captured:</span> <span class="timestamp">${escHtml(metadata.capturedAt)}</span></span>
  </div>
  <div class="section-divider"></div>
  ${bodyHtml}
  <div class="watermark">AC3 Caldera Evidence Collector — ${escHtml(metadata.capturedAt)}</div>
</div>
</body></html>`;
}

function renderAgentTable(agents: AgentEvidence[], calderaUrl: string, calderaIp: string, capturedAt: string): string {
  if (agents.length === 0) return renderNoDataPanel("C2 Agent Check-Ins", "No agents detected");

  const rows = agents.map(a => `
    <tr>
      <td><code>${escHtml(a.paw)}</code></td>
      <td>${escHtml(a.displayName)}</td>
      <td><span class="ip-highlight">${escHtml(a.hostIp)}</span></td>
      <td>${escHtml(a.platform)}</td>
      <td>${escHtml(a.username)} (${escHtml(a.privilege)})</td>
      <td><code>${escHtml(a.exeName)}</code> (PID ${a.pid})</td>
      <td>${escHtml(a.contact)}</td>
      <td>${a.executors.map(e => `<span class="tactic-badge">${escHtml(e)}</span>`).join("")}</td>
      <td class="timestamp">${escHtml(a.created)}</td>
      <td class="timestamp">${escHtml(a.lastSeen)}</td>
      <td>${a.linksExecuted}</td>
    </tr>`).join("");

  const metadata: EvidenceMetadata = {
    sourceIp: calderaIp,
    sourceUrl: calderaUrl,
    destinationIp: agents.map(a => a.hostIp).filter(Boolean).join(", ") || "N/A",
    destinationUrl: agents.map(a => a.host).join(", "),
    capturedAt,
    eventTimestamp: agents[0]?.created || capturedAt,
  };

  return renderEvidenceWrapper(
    `C2 Agent Check-Ins — ${agents.length} Agent${agents.length !== 1 ? "s" : ""}`,
    `${agents.length} ACTIVE`,
    "badge-red",
    metadata,
    `<table>
      <thead><tr>
        <th>PAW</th><th>Display Name</th><th>Host IP</th><th>Platform</th>
        <th>User (Priv)</th><th>Process</th><th>Contact</th><th>Executors</th>
        <th>First Seen</th><th>Last Seen</th><th>Links</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`
  );
}

function renderOperationTimeline(
  op: OperationEvidence,
  calderaUrl: string,
  calderaIp: string,
  targets: Array<{ hostname: string; ip: string }>,
  capturedAt: string,
): string {
  const statusCounts = {
    success: op.links.filter(l => l.status === "success").length,
    failed: op.links.filter(l => l.status === "failed").length,
    queued: op.links.filter(l => l.status === "queued").length,
    other: op.links.filter(l => !["success", "failed", "queued"].includes(l.status)).length,
  };

  const targetIps = targets.map(t => t.ip).filter(Boolean).join(", ") || "N/A";
  const targetUrls = targets.map(t => t.hostname).filter(Boolean).join(", ") || "N/A";

  const metadata: EvidenceMetadata = {
    sourceIp: calderaIp,
    sourceUrl: calderaUrl,
    destinationIp: targetIps,
    destinationUrl: targetUrls,
    capturedAt,
    eventTimestamp: op.startedAt || capturedAt,
  };

  const rows = op.links.map(link => {
    const statusClass = link.status === "success" ? "status-success"
      : link.status === "failed" ? "status-failed"
      : link.status === "queued" ? "status-queued"
      : "status-unknown";

    return `<tr>
      <td class="timestamp">${escHtml(link.decidedAt)}</td>
      <td><code>${escHtml(link.paw)}</code><br><small>${escHtml(link.agentHost)}</small></td>
      <td><span class="tactic-badge">${escHtml(link.tactic)}</span></td>
      <td>${escHtml(link.techniqueId)}<br><small>${escHtml(link.techniqueName)}</small></td>
      <td>${escHtml(link.abilityName)}</td>
      <td class="${statusClass}">${link.status.toUpperCase()}</td>
    </tr>`;
  }).join("");

  return renderEvidenceWrapper(
    `Operation Timeline — ${escHtml(op.operationName)}`,
    op.state.toUpperCase(),
    op.state === "finished" ? "badge-green" : op.state === "running" ? "badge-yellow" : "badge-gray",
    metadata,
    `<div class="meta-row">
      <span><span class="meta-label">Operation ID:</span> <span class="meta-value">${escHtml(op.operationId)}</span></span>
      <span><span class="meta-label">Adversary:</span> <span class="meta-value">${escHtml(op.adversaryName)}</span></span>
      <span><span class="meta-label">Planner:</span> <span class="meta-value">${escHtml(op.plannerName)}</span></span>
      <span><span class="meta-label">Agents:</span> <span class="meta-value">${op.agentCount}</span></span>
    </div>
    <div class="meta-row">
      <span><span class="evidence-badge badge-green">${statusCounts.success} SUCCESS</span></span>
      <span><span class="evidence-badge badge-red">${statusCounts.failed} FAILED</span></span>
      <span><span class="evidence-badge badge-yellow">${statusCounts.queued} QUEUED</span></span>
    </div>
    <div class="section-divider"></div>
    <table>
      <thead><tr>
        <th>Timestamp</th><th>Agent</th><th>Tactic</th><th>Technique</th><th>Ability</th><th>Status</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`
  );
}

function renderAdversaryProfile(adv: AdversaryEvidence, capturedAt: string): string {
  // Group abilities by tactic
  const tacticGroups = new Map<string, typeof adv.abilities>();
  for (const ab of adv.abilities) {
    const tactic = ab.tactic || "unknown";
    if (!tacticGroups.has(tactic)) tacticGroups.set(tactic, []);
    tacticGroups.get(tactic)!.push(ab);
  }

  const tacticOrder = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact", "multiple", "unknown",
  ];

  const sortedTactics = [...tacticGroups.entries()].sort((a, b) => {
    const ai = tacticOrder.indexOf(a[0]);
    const bi = tacticOrder.indexOf(b[0]);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  const rows = sortedTactics.flatMap(([tactic, abilities]) =>
    abilities.map((ab, i) => `<tr>
      ${i === 0 ? `<td rowspan="${abilities.length}"><span class="tactic-badge">${escHtml(tactic)}</span></td>` : ""}
      <td>${escHtml(ab.techniqueId)}</td>
      <td>${escHtml(ab.techniqueName)}</td>
      <td>${escHtml(ab.name)}</td>
    </tr>`)
  ).join("");

  const metadata: EvidenceMetadata = {
    sourceIp: "N/A",
    sourceUrl: "Caldera Adversary Library",
    destinationIp: "N/A",
    destinationUrl: "Target Environment",
    capturedAt,
    eventTimestamp: capturedAt,
  };

  return renderEvidenceWrapper(
    `Adversary Profile — ${escHtml(adv.name)}`,
    `${adv.abilities.length} ABILITIES`,
    "badge-blue",
    metadata,
    `<div class="meta-row">
      <span><span class="meta-label">Adversary ID:</span> <span class="meta-value">${escHtml(adv.adversaryId)}</span></span>
      <span><span class="meta-label">Tactics:</span> <span class="meta-value">${tacticGroups.size}</span></span>
    </div>
    <div class="meta-row" style="margin-bottom:12px;">
      <span>${escHtml(adv.description)}</span>
    </div>
    <div class="section-divider"></div>
    <table>
      <thead><tr><th>Tactic</th><th>Technique ID</th><th>Technique</th><th>Ability</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`
  );
}

function renderAttackChainSummary(
  agents: AgentEvidence[],
  operation: OperationEvidence | null,
  adversary: AdversaryEvidence | null,
  calderaUrl: string,
  calderaIp: string,
  targets: Array<{ hostname: string; ip: string }>,
  capturedAt: string,
): string {
  const targetIps = targets.map(t => t.ip).filter(Boolean).join(", ") || agents.map(a => a.hostIp).filter(Boolean).join(", ") || "N/A";
  const targetUrls = targets.map(t => t.hostname).filter(Boolean).join(", ") || agents.map(a => a.host).join(", ") || "N/A";

  const metadata: EvidenceMetadata = {
    sourceIp: calderaIp,
    sourceUrl: calderaUrl,
    destinationIp: targetIps,
    destinationUrl: targetUrls,
    capturedAt,
    eventTimestamp: operation?.startedAt || capturedAt,
  };

  // Build the attack chain visualization
  const chainSteps: string[] = [];

  // Step 1: Initial access (exploitation)
  chainSteps.push(`<div style="margin-bottom:12px;">
    <span class="chain-node chain-attacker">Attacker (${escHtml(calderaIp)})</span>
    <span class="chain-arrow">&rarr;</span>
    <span class="chain-node chain-action">SSH Exploitation</span>
    <span class="chain-arrow">&rarr;</span>
    <span class="chain-node chain-target">Target (${escHtml(targetIps)})</span>
  </div>`);

  // Step 2: C2 deployment
  if (agents.length > 0) {
    for (const agent of agents) {
      chainSteps.push(`<div style="margin-bottom:8px;">
        <span class="chain-node chain-target">${escHtml(agent.host)} (${escHtml(agent.hostIp)})</span>
        <span class="chain-arrow">&larr;</span>
        <span class="chain-node chain-action">C2 Beacon (${escHtml(agent.contact)})</span>
        <span class="chain-arrow">&rarr;</span>
        <span class="chain-node chain-attacker">C2 Server (${escHtml(calderaIp)})</span>
        <span class="timestamp" style="margin-left:8px;">First: ${escHtml(agent.created)} | Last: ${escHtml(agent.lastSeen)}</span>
      </div>`);
    }
  }

  // Step 3: Adversary operations
  if (operation && operation.links.length > 0) {
    const successLinks = operation.links.filter(l => l.status === "success");
    chainSteps.push(`<div class="section-divider"></div>`);
    chainSteps.push(`<div style="margin-top:8px;margin-bottom:8px;"><strong>Adversary Operations (${operation.links.length} abilities, ${successLinks.length} succeeded):</strong></div>`);
    for (const link of operation.links.slice(0, 20)) {
      const statusIcon = link.status === "success" ? "&#x2705;" : link.status === "failed" ? "&#x274C;" : "&#x23F3;";
      chainSteps.push(`<div style="margin-left:24px;margin-bottom:4px;">
        ${statusIcon} <span class="tactic-badge">${escHtml(link.tactic)}</span>
        <strong>${escHtml(link.abilityName)}</strong>
        <small>(${escHtml(link.techniqueId)})</small>
        on <code>${escHtml(link.paw)}</code>
        <span class="timestamp">${escHtml(link.decidedAt)}</span>
      </div>`);
    }
    if (operation.links.length > 20) {
      chainSteps.push(`<div style="margin-left:24px;color:#8b949e;">... and ${operation.links.length - 20} more abilities</div>`);
    }
  }

  // Summary stats
  const summaryHtml = `
    <div class="meta-row" style="margin-top:12px;">
      <span><span class="evidence-badge badge-red">${agents.length} C2 Agents</span></span>
      <span><span class="evidence-badge badge-blue">${operation?.links.length || 0} Abilities Executed</span></span>
      <span><span class="evidence-badge badge-green">${operation?.links.filter(l => l.status === "success").length || 0} Succeeded</span></span>
      <span><span class="evidence-badge badge-yellow">${adversary?.abilities.length || 0} Profile Abilities</span></span>
    </div>`;

  return renderEvidenceWrapper(
    "Attack Chain Summary",
    "COMPLETE",
    "badge-red",
    metadata,
    chainSteps.join("\n") + summaryHtml
  );
}

function renderNoDataPanel(title: string, message: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">${EVIDENCE_CSS}</head>
<body>
<div class="evidence-panel">
  <div class="evidence-header">
    <span class="evidence-title">${escHtml(title)}</span>
    <span class="evidence-badge badge-gray">NO DATA</span>
  </div>
  <p style="color:#8b949e;text-align:center;padding:24px;">${escHtml(message)}</p>
</div>
</body></html>`;
}

// ─── Utility ────────────────────────────────────────────────────────────

function escHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function extractIpFromUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    const match = url.match(/(\d+\.\d+\.\d+\.\d+)/);
    return match ? match[1] : "unknown";
  }
}

// ─── PNG Rendering Helper ───────────────────────────────────────────────

/**
 * Convert an HTML evidence panel to a PNG screenshot.
 * Uses WeasyPrint (pre-installed) to render HTML → PDF → PNG.
 * Falls back to saving raw HTML if rendering tools are unavailable.
 */
export async function renderEvidenceToFile(
  html: string,
  outputPath: string,
): Promise<{ success: boolean; path: string; format: "png" | "html" }> {
  const fs = await import("fs/promises");
  const { execSync } = await import("child_process");
  const path = await import("path");

  // Write HTML to temp file
  const htmlPath = outputPath.replace(/\.(png|jpg|jpeg)$/i, ".html");
  await fs.writeFile(htmlPath, html, "utf-8");

  // Try to render to PNG using wkhtmltoimage or chromium
  try {
    // Try wkhtmltoimage first (fast, lightweight)
    execSync(`which wkhtmltoimage`, { stdio: "pipe" });
    execSync(`wkhtmltoimage --width 1400 --quality 95 "${htmlPath}" "${outputPath}"`, {
      stdio: "pipe",
      timeout: 30000,
    });
    return { success: true, path: outputPath, format: "png" };
  } catch {
    // wkhtmltoimage not available
  }

  try {
    // Try chromium headless screenshot
    execSync(`which chromium-browser || which chromium || which google-chrome`, { stdio: "pipe" });
    const chromeBin = execSync(`which chromium-browser || which chromium || which google-chrome`, { encoding: "utf-8" }).trim();
    execSync(
      `${chromeBin} --headless --disable-gpu --no-sandbox --screenshot="${outputPath}" --window-size=1400,900 "file://${path.resolve(htmlPath)}"`,
      { stdio: "pipe", timeout: 30000 },
    );
    return { success: true, path: outputPath, format: "png" };
  } catch {
    // Chromium not available either
  }

  // Fallback: keep as HTML (still useful as evidence)
  console.log(`[CalderaEvidence] PNG rendering unavailable, keeping HTML at ${htmlPath}`);
  return { success: true, path: htmlPath, format: "html" };
}
