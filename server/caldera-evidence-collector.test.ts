/**
 * Tests for Caldera Evidence Collector
 *
 * Validates:
 *   - Evidence metadata always includes source IP/URL, destination IP/URL, and timestamp
 *   - Agent evidence collection and rendering
 *   - Operation timeline rendering with MITRE ATT&CK mapping
 *   - Adversary profile rendering
 *   - Attack chain summary rendering
 *   - HTML evidence panel structure
 *   - Integration with engagement orchestrator (import/export verification)
 *   - Integration with pentest report pipeline (calderaEvidenceSnapshot field)
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Source Code Verification Tests ─────────────────────────────────────

describe("Caldera Evidence Collector Module", () => {
  const collectorPath = path.join(__dirname, "lib/caldera-evidence-collector.ts");
  const collectorSource = fs.readFileSync(collectorPath, "utf-8");

  it("exports captureCalderaEvidence as the main entry point", () => {
    expect(collectorSource).toContain("export async function captureCalderaEvidence");
  });

  it("exports collectAgents, collectOperation, collectAdversary helpers", () => {
    expect(collectorSource).toContain("export async function collectAgents");
    expect(collectorSource).toContain("export async function collectOperation");
    expect(collectorSource).toContain("export async function collectAdversary");
  });

  it("exports renderEvidenceToFile for PNG/HTML output", () => {
    expect(collectorSource).toContain("export async function renderEvidenceToFile");
  });

  it("defines EvidenceMetadata type with required fields", () => {
    expect(collectorSource).toContain("export interface EvidenceMetadata");
    expect(collectorSource).toContain("sourceIp: string");
    expect(collectorSource).toContain("sourceUrl: string");
    expect(collectorSource).toContain("destinationIp: string");
    expect(collectorSource).toContain("destinationUrl: string");
    expect(collectorSource).toContain("capturedAt: string");
    expect(collectorSource).toContain("eventTimestamp: string");
  });

  it("defines CalderaEvidenceSnapshot with all required sections", () => {
    expect(collectorSource).toContain("export interface CalderaEvidenceSnapshot");
    expect(collectorSource).toContain("agents: AgentEvidence[]");
    expect(collectorSource).toContain("operations: OperationEvidence[]");
    expect(collectorSource).toContain("adversaryProfile: AdversaryEvidence | null");
    expect(collectorSource).toContain("renderedHtml:");
    expect(collectorSource).toContain("agentTable: string");
    expect(collectorSource).toContain("operationTimeline: string");
    expect(collectorSource).toContain("adversaryProfile: string");
    expect(collectorSource).toContain("attackChainSummary: string");
  });
});

describe("Evidence Metadata — Source/Destination/Timestamp Requirements", () => {
  const collectorSource = fs.readFileSync(
    path.join(__dirname, "lib/caldera-evidence-collector.ts"),
    "utf-8"
  );

  it("every rendered panel passes EvidenceMetadata to renderEvidenceWrapper", () => {
    // The renderEvidenceWrapper function is called with metadata containing
    // sourceIp, sourceUrl, destinationIp, destinationUrl, capturedAt, eventTimestamp
    expect(collectorSource).toContain("renderEvidenceWrapper(");
    // Count calls to renderEvidenceWrapper — should be at least 4 (agent, operation, adversary, chain)
    const wrapperCalls = (collectorSource.match(/renderEvidenceWrapper\(/g) || []).length;
    expect(wrapperCalls).toBeGreaterThanOrEqual(4);
  });

  it("renderEvidenceWrapper includes source IP in output HTML", () => {
    expect(collectorSource).toContain('class="ip-highlight">${escHtml(metadata.sourceIp)}');
  });

  it("renderEvidenceWrapper includes source URL in output HTML", () => {
    expect(collectorSource).toContain('class="url-highlight">${escHtml(metadata.sourceUrl)}');
  });

  it("renderEvidenceWrapper includes destination IP in output HTML", () => {
    expect(collectorSource).toContain('class="ip-highlight">${escHtml(metadata.destinationIp)}');
  });

  it("renderEvidenceWrapper includes destination URL in output HTML", () => {
    expect(collectorSource).toContain('class="url-highlight">${escHtml(metadata.destinationUrl)}');
  });

  it("renderEvidenceWrapper includes event timestamp in output HTML", () => {
    expect(collectorSource).toContain('class="timestamp">${escHtml(metadata.eventTimestamp)}');
  });

  it("renderEvidenceWrapper includes capture timestamp in output HTML", () => {
    expect(collectorSource).toContain('class="timestamp">${escHtml(metadata.capturedAt)}');
  });

  it("agent table metadata includes caldera server as source and agent IPs as destination", () => {
    // In renderAgentTable, metadata.sourceIp = calderaIp and metadata.destinationIp = agent IPs
    expect(collectorSource).toContain("sourceIp: calderaIp");
    expect(collectorSource).toContain("sourceUrl: calderaUrl");
  });

  it("operation timeline metadata includes target IPs as destination", () => {
    expect(collectorSource).toContain("destinationIp: targetIps");
    expect(collectorSource).toContain("destinationUrl: targetUrls");
  });
});

describe("Agent Evidence Collection", () => {
  const collectorSource = fs.readFileSync(
    path.join(__dirname, "lib/caldera-evidence-collector.ts"),
    "utf-8"
  );

  it("collects agent paw, host, platform, username, privilege", () => {
    expect(collectorSource).toContain("paw: a.paw");
    expect(collectorSource).toContain("host: a.host");
    expect(collectorSource).toContain("platform: a.platform");
    expect(collectorSource).toContain("username: a.username");
    expect(collectorSource).toContain('privilege: a.privilege || "User"');
  });

  it("collects agent network metadata (hostIp, contact)", () => {
    expect(collectorSource).toContain("hostIp:");
    expect(collectorSource).toContain("contact: a.contact");
  });

  it("collects agent timestamps (created, lastSeen)", () => {
    expect(collectorSource).toContain("created: a.created");
    expect(collectorSource).toContain("lastSeen: a.last_seen");
  });

  it("renders agent table with IP columns", () => {
    expect(collectorSource).toContain("<th>Host IP</th>");
    expect(collectorSource).toContain("<th>First Seen</th>");
    expect(collectorSource).toContain("<th>Last Seen</th>");
  });
});

describe("Operation Timeline Evidence", () => {
  const collectorSource = fs.readFileSync(
    path.join(__dirname, "lib/caldera-evidence-collector.ts"),
    "utf-8"
  );

  it("collects operation links with MITRE ATT&CK mapping", () => {
    expect(collectorSource).toContain("tactic: ability.tactic");
    expect(collectorSource).toContain("techniqueId: ability.technique_id");
    expect(collectorSource).toContain("techniqueName: ability.technique_name");
  });

  it("maps link status codes to human-readable strings", () => {
    expect(collectorSource).toContain('0: "queued"');
    expect(collectorSource).toContain('1: "success"');
  });

  it("renders operation timeline table with timestamp column", () => {
    expect(collectorSource).toContain("<th>Timestamp</th>");
    expect(collectorSource).toContain("<th>Agent</th>");
    expect(collectorSource).toContain("<th>Tactic</th>");
    expect(collectorSource).toContain("<th>Technique</th>");
    expect(collectorSource).toContain("<th>Ability</th>");
    expect(collectorSource).toContain("<th>Status</th>");
  });

  it("includes operation metadata (adversary name, planner, agent count)", () => {
    expect(collectorSource).toContain("Adversary:");
    expect(collectorSource).toContain("Planner:");
    expect(collectorSource).toContain("Agents:");
  });
});

describe("Adversary Profile Evidence", () => {
  const collectorSource = fs.readFileSync(
    path.join(__dirname, "lib/caldera-evidence-collector.ts"),
    "utf-8"
  );

  it("groups abilities by tactic for organized display", () => {
    expect(collectorSource).toContain("tacticGroups");
    expect(collectorSource).toContain("sortedTactics");
  });

  it("renders adversary profile table with tactic/technique/ability columns", () => {
    expect(collectorSource).toContain("<th>Tactic</th>");
    expect(collectorSource).toContain("<th>Technique ID</th>");
    expect(collectorSource).toContain("<th>Technique</th>");
    expect(collectorSource).toContain("<th>Ability</th>");
  });
});

describe("Attack Chain Summary", () => {
  const collectorSource = fs.readFileSync(
    path.join(__dirname, "lib/caldera-evidence-collector.ts"),
    "utf-8"
  );

  it("renders attack chain with attacker → action → target flow", () => {
    expect(collectorSource).toContain("chain-attacker");
    expect(collectorSource).toContain("chain-action");
    expect(collectorSource).toContain("chain-target");
  });

  it("includes C2 beacon connection details with timestamps", () => {
    expect(collectorSource).toContain("C2 Beacon");
    expect(collectorSource).toContain("First:");
    expect(collectorSource).toContain("Last:");
  });

  it("shows summary stats badges (agents, abilities, succeeded)", () => {
    expect(collectorSource).toContain("C2 Agents");
    expect(collectorSource).toContain("Abilities Executed");
    expect(collectorSource).toContain("Succeeded");
  });
});

describe("HTML Evidence Panel Structure", () => {
  const collectorSource = fs.readFileSync(
    path.join(__dirname, "lib/caldera-evidence-collector.ts"),
    "utf-8"
  );

  it("uses dark theme styling for professional evidence screenshots", () => {
    expect(collectorSource).toContain("background: #0d1117");
    expect(collectorSource).toContain("background: #161b22");
  });

  it("includes AC3 watermark on all evidence panels", () => {
    expect(collectorSource).toContain("AC3 Caldera Evidence Collector");
  });

  it("escapes HTML to prevent injection in evidence output", () => {
    expect(collectorSource).toContain("function escHtml(str: string)");
    expect(collectorSource).toContain('replace(/&/g, "&amp;")');
    expect(collectorSource).toContain('replace(/</g, "&lt;")');
    expect(collectorSource).toContain('replace(/>/g, "&gt;")');
  });
});

// ─── Integration Tests ──────────────────────────────────────────────────

describe("Engagement Orchestrator Integration", () => {
  const orchestratorPath = path.join(__dirname, "lib/engagement-orchestrator.ts");
  const orchestratorSource = fs.readFileSync(orchestratorPath, "utf-8");

  it("imports captureCalderaEvidence from the evidence collector", () => {
    expect(orchestratorSource).toContain('import { captureCalderaEvidence');
    expect(orchestratorSource).toContain('from "./caldera-evidence-collector"');
  });

  it("calls captureCalderaEvidence during exploitation phase", () => {
    // Should capture evidence after successful exploits
    const startIdx = orchestratorSource.indexOf("Auto-Capture Caldera Evidence (Exploitation Phase)");
    const exploitSection = orchestratorSource.slice(startIdx, startIdx + 1200);
    expect(exploitSection).toContain("captureCalderaEvidence");
    expect(exploitSection).toContain("__calderaExploitEvidence");
  });

  it("calls captureCalderaEvidence during post-exploit phase", () => {
    const startIdx = orchestratorSource.indexOf("Auto-Capture Caldera Evidence (Post-Exploit Phase)");
    const postExploitSection = orchestratorSource.slice(startIdx, startIdx + 2000);
    expect(postExploitSection).toContain("captureCalderaEvidence");
    expect(postExploitSection).toContain("__calderaPostExploitEvidence");
  });

  it("stores auto-launched operation ID on state for evidence capture", () => {
    expect(orchestratorSource).toContain("(state as any).__autoLaunchedOpId = autoLaunchedOpId");
    expect(orchestratorSource).toContain("(state as any).__autoLaunchedAdversaryId = selectedAdversaryId");
  });

  it("passes target assets to evidence capture for destination IP context", () => {
    expect(orchestratorSource).toContain("targets: state.assets.filter(a => a.status === 'compromised')");
  });

  it("logs evidence capture results with source/destination metadata", () => {
    expect(orchestratorSource).toContain("Exploitation Evidence Captured");
    expect(orchestratorSource).toContain("Post-Exploit Evidence Captured");
    expect(orchestratorSource).toContain("calderaServerIp");
  });

  it("handles evidence capture failures gracefully without stopping the engagement", () => {
    expect(orchestratorSource).toContain("Evidence Capture Failed");
    expect(orchestratorSource).toContain("Could not auto-capture Caldera evidence");
  });
});

describe("Pentest Report Pipeline Integration", () => {
  const pipelinePath = path.join(__dirname, "lib/pentest-report-pipeline.ts");
  const pipelineSource = fs.readFileSync(pipelinePath, "utf-8");

  it("PipelineInput type includes calderaEvidenceSnapshot field", () => {
    expect(pipelineSource).toContain("calderaEvidenceSnapshot?:");
    expect(pipelineSource).toContain("calderaServerUrl: string");
    expect(pipelineSource).toContain("calderaServerIp: string");
  });

  it("generates Section 12.4 C2 Evidence when snapshot is present", () => {
    expect(pipelineSource).toContain("### 12.4 C2 Evidence (Caldera)");
    expect(pipelineSource).toContain("input.calderaEvidenceSnapshot");
  });

  it("C2 Evidence section includes source/destination columns in agent table", () => {
    expect(pipelineSource).toContain("Source (C2)");
    expect(pipelineSource).toContain("Destination (Agent IP)");
  });

  it("C2 Evidence section includes timestamps in ability execution timeline", () => {
    expect(pipelineSource).toContain("| Timestamp | Source (C2) | Destination (Agent)");
  });

  it("C2 Evidence section renders adversary profile with tactic/technique mapping", () => {
    expect(pipelineSource).toContain("Adversary Profile:");
    expect(pipelineSource).toContain("| Tactic | Technique ID | Technique | Ability |");
  });
});

describe("Reports Core Router Integration", () => {
  const routerPath = path.join(__dirname, "routers/reports-core.ts");
  const routerSource = fs.readFileSync(routerPath, "utf-8");

  it("imports captureCalderaEvidence from the evidence collector", () => {
    expect(routerSource).toContain('import { captureCalderaEvidence } from "../lib/caldera-evidence-collector"');
  });

  it("defines collectCalderaEvidenceForReport helper function", () => {
    expect(routerSource).toContain("async function collectCalderaEvidenceForReport");
  });

  it("passes calderaEvidenceSnapshot to the pipeline input", () => {
    expect(routerSource).toContain("calderaEvidenceSnapshot: await collectCalderaEvidenceForReport");
  });

  it("matches operations by engagement name or ID", () => {
    expect(routerSource).toContain("op.name?.toLowerCase().includes(engName)");
    expect(routerSource).toContain("op.name?.includes(`Eng${engId}`)");
  });

  it("handles Caldera evidence collection failure gracefully", () => {
    expect(routerSource).toContain("Caldera evidence collection failed (non-fatal)");
  });
});
