/**
 * Evidence Integrity Guardrails & Chain-of-Custody Controls
 *
 * Forensic-grade integrity enforcement for the entire evidence pipeline.
 * Prevents hallucination, fabrication, and tampering across all evidence
 * collection, storage, retrieval, and reporting stages.
 *
 * Controls implemented:
 *   1. Cryptographic Chain of Custody — SHA-256 hash chain with HMAC anchors
 *   2. Provenance Validation — verify evidence matches its claimed source tool
 *   3. Hallucination Guardrails — cross-reference LLM output against ground truth
 *   4. Tamper Detection — verify integrity on every evidence read/export
 *   5. Custody Event Logging — immutable audit trail of all evidence mutations
 *   6. Evidence Lifecycle Gates — enforce state machine transitions
 *
 * @module evidence-integrity-guardrails
 */

import * as crypto from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Every custody event is one of these actions */
export type CustodyAction =
  | "created"
  | "captured"
  | "hashed"
  | "validated"
  | "exported"
  | "accessed"
  | "modified"
  | "archived"
  | "quarantined"
  | "released"
  | "deleted";

/** Valid state transitions for evidence lifecycle */
const VALID_TRANSITIONS: Record<string, CustodyAction[]> = {
  "": ["created", "captured"],                                    // genesis
  created: ["hashed", "validated", "quarantined"],
  captured: ["hashed", "validated", "quarantined"],
  hashed: ["validated", "exported", "accessed", "quarantined"],
  validated: ["exported", "accessed", "archived", "quarantined"],
  exported: ["accessed", "archived"],
  accessed: ["exported", "accessed", "archived"],
  archived: ["accessed", "deleted"],
  quarantined: ["released", "deleted"],
  released: ["validated", "exported"],
};

/** Provenance source tool identifiers */
export type EvidenceSourceTool =
  | "scanforge-discovery"
  | "nuclei"
  | "zap"
  | "nikto"
  | "httpx"
  | "gobuster"
  | "ffuf"
  | "testssl"
  | "hydra"
  | "caldera"
  | "metasploit"
  | "manual"
  | "llm_analysis"
  | "system";

/** Provenance record — proves where evidence came from */
export interface EvidenceProvenance {
  /** Tool that produced the evidence */
  sourceTool: EvidenceSourceTool;
  /** Tool version (if available) */
  toolVersion?: string;
  /** Command or API call that produced the output */
  sourceCommand?: string;
  /** Hostname/IP of the machine that ran the tool */
  collectorHost: string;
  /** Timestamp when the tool produced the output (not when we captured it) */
  toolOutputTimestamp: string;
  /** Raw output hash — SHA-256 of the original tool output before any processing */
  rawOutputHash: string;
  /** Size of raw output in bytes */
  rawOutputSize: number;
  /** Target that was scanned/tested */
  targetHost: string;
  targetPort?: number;
  /** Network context */
  sourceIp: string;
  destinationIp: string;
}

/** Integrity envelope wrapping every evidence artifact */
export interface IntegrityEnvelope {
  /** Unique evidence artifact ID */
  evidenceId: string;
  /** Engagement this evidence belongs to */
  engagementId: string;
  /** SHA-256 of the evidence content */
  contentHash: string;
  /** Chain hash linking to previous evidence in the chain */
  chainHash: string;
  /** Previous chain hash (null for genesis) */
  previousChainHash: string | null;
  /** Provenance record */
  provenance: EvidenceProvenance;
  /** Custody trail */
  custodyTrail: CustodyEvent[];
  /** Current lifecycle state */
  currentState: CustodyAction;
  /** Creation timestamp */
  createdAt: number;
  /** Last verification timestamp */
  lastVerifiedAt: number | null;
  /** Verification status */
  verificationStatus: "unverified" | "verified" | "tampered" | "quarantined";
}

/** Single custody event in the audit trail */
export interface CustodyEvent {
  action: CustodyAction;
  performedBy: string;
  timestamp: number;
  integrityHash: string;
  details: string;
  ipAddress?: string;
}

/** Result of a hallucination check */
export interface HallucinationCheckResult {
  passed: boolean;
  score: number; // 0.0 (total hallucination) to 1.0 (fully grounded)
  groundedClaims: GroundedClaim[];
  ungroundedClaims: UngroundedClaim[];
  warnings: string[];
  recommendation: "accept" | "review" | "reject" | "quarantine";
}

export interface GroundedClaim {
  claim: string;
  groundTruthSource: string;
  confidence: number;
}

export interface UngroundedClaim {
  claim: string;
  reason: string;
  severity: "critical" | "high" | "medium" | "low";
}

/** Provenance validation result */
export interface ProvenanceValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  toolSignatureMatch: boolean;
  timestampConsistent: boolean;
  networkContextValid: boolean;
  contentFormatValid: boolean;
}

/** Chain validation result */
export interface ChainValidationResult {
  valid: boolean;
  totalLinks: number;
  validLinks: number;
  brokenAt: number | null;
  brokenEvidenceId: string | null;
  merkleRoot: string | null;
  errors: string[];
  lastVerified: number;
}

// ─── In-Memory Chain Store (for runtime; persisted to DB on flush) ──────────

const chainStore = new Map<string, IntegrityEnvelope[]>();

// ─── Cryptographic Primitives ───────────────────────────────────────────────

/**
 * Compute SHA-256 hash of content.
 */
export function sha256(content: Buffer | string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * Compute chain hash: SHA-256(contentHash | previousChainHash | timestamp | provenanceHash).
 * Includes provenance in the chain to prevent provenance tampering.
 */
export function computeChainHash(
  contentHash: string,
  previousChainHash: string | null,
  timestamp: number,
  provenanceHash: string,
): string {
  const payload = `${contentHash}|${previousChainHash || "GENESIS"}|${timestamp}|${provenanceHash}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}

/**
 * Compute HMAC-SHA256 anchor for a Merkle root.
 */
export function computeAnchorHMAC(merkleRoot: string, engagementId: string): string {
  const secret = process.env.JWT_SECRET || "evidence-integrity-default-key";
  return crypto.createHmac("sha256", secret).update(`${merkleRoot}|${engagementId}`).digest("hex");
}

/**
 * Compute Merkle root from chain hashes.
 */
export function computeMerkleRoot(chainHashes: string[]): string {
  if (chainHashes.length === 0) return sha256("EMPTY_CHAIN");
  if (chainHashes.length === 1) return chainHashes[0];

  let layer = [...chainHashes];
  while (layer.length > 1) {
    const nextLayer: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      nextLayer.push(sha256(left + right));
    }
    layer = nextLayer;
  }
  return layer[0];
}

/**
 * Hash a provenance record for inclusion in the chain hash.
 */
export function hashProvenance(provenance: EvidenceProvenance): string {
  const canonical = JSON.stringify({
    sourceTool: provenance.sourceTool,
    collectorHost: provenance.collectorHost,
    toolOutputTimestamp: provenance.toolOutputTimestamp,
    rawOutputHash: provenance.rawOutputHash,
    targetHost: provenance.targetHost,
    sourceIp: provenance.sourceIp,
    destinationIp: provenance.destinationIp,
  });
  return sha256(canonical);
}

// ─── Evidence Lifecycle State Machine ───────────────────────────────────────

/**
 * Validate that a state transition is allowed.
 */
export function isValidTransition(currentState: CustodyAction | "", nextAction: CustodyAction): boolean {
  const allowed = VALID_TRANSITIONS[currentState] || [];
  return allowed.includes(nextAction);
}

/**
 * Get allowed next actions from current state.
 */
export function getAllowedTransitions(currentState: CustodyAction | ""): CustodyAction[] {
  return VALID_TRANSITIONS[currentState] || [];
}

// ─── Chain of Custody Operations ────────────────────────────────────────────

/**
 * Create a new integrity envelope for an evidence artifact.
 * This is the entry point for all new evidence entering the system.
 */
export function createIntegrityEnvelope(params: {
  evidenceId: string;
  engagementId: string;
  content: Buffer | string;
  provenance: EvidenceProvenance;
  performedBy: string;
  ipAddress?: string;
}): IntegrityEnvelope {
  const contentHash = sha256(params.content);
  const provenanceHash = hashProvenance(params.provenance);
  const timestamp = Date.now();

  // Get the chain for this engagement
  const chain = chainStore.get(params.engagementId) || [];
  const previousChainHash = chain.length > 0 ? chain[chain.length - 1].chainHash : null;

  const chainHash = computeChainHash(contentHash, previousChainHash, timestamp, provenanceHash);

  const custodyEvent: CustodyEvent = {
    action: "created",
    performedBy: params.performedBy,
    timestamp,
    integrityHash: chainHash,
    details: `Evidence created: ${params.provenance.sourceTool} output from ${params.provenance.targetHost}`,
    ipAddress: params.ipAddress,
  };

  const envelope: IntegrityEnvelope = {
    evidenceId: params.evidenceId,
    engagementId: params.engagementId,
    contentHash,
    chainHash,
    previousChainHash,
    provenance: params.provenance,
    custodyTrail: [custodyEvent],
    currentState: "created",
    createdAt: timestamp,
    lastVerifiedAt: null,
    verificationStatus: "unverified",
  };

  // Append to chain
  chain.push(envelope);
  chainStore.set(params.engagementId, chain);

  return envelope;
}

/**
 * Record a custody event on an existing evidence envelope.
 * Enforces state machine transitions.
 */
export function recordCustodyEvent(
  envelope: IntegrityEnvelope,
  action: CustodyAction,
  performedBy: string,
  details: string,
  ipAddress?: string,
): { success: boolean; error?: string } {
  if (!isValidTransition(envelope.currentState, action)) {
    return {
      success: false,
      error: `Invalid transition: ${envelope.currentState} → ${action}. Allowed: ${getAllowedTransitions(envelope.currentState).join(", ")}`,
    };
  }

  const event: CustodyEvent = {
    action,
    performedBy,
    timestamp: Date.now(),
    integrityHash: sha256(`${envelope.chainHash}|${action}|${Date.now()}`),
    details,
    ipAddress,
  };

  envelope.custodyTrail.push(event);
  envelope.currentState = action;

  if (action === "validated") {
    envelope.lastVerifiedAt = Date.now();
    envelope.verificationStatus = "verified";
  } else if (action === "quarantined") {
    envelope.verificationStatus = "quarantined";
  }

  return { success: true };
}

/**
 * Verify the integrity of an evidence artifact by re-computing its hash.
 */
export function verifyEvidenceIntegrity(
  envelope: IntegrityEnvelope,
  content: Buffer | string,
): { valid: boolean; error?: string } {
  const currentHash = sha256(content);
  if (currentHash !== envelope.contentHash) {
    envelope.verificationStatus = "tampered";
    return {
      valid: false,
      error: `Content hash mismatch: expected ${envelope.contentHash}, got ${currentHash}. Evidence may have been tampered with.`,
    };
  }

  envelope.lastVerifiedAt = Date.now();
  envelope.verificationStatus = "verified";
  return { valid: true };
}

/**
 * Validate the entire evidence chain for an engagement.
 */
export function validateChain(engagementId: string): ChainValidationResult {
  const chain = chainStore.get(engagementId) || [];

  if (chain.length === 0) {
    return {
      valid: true,
      totalLinks: 0,
      validLinks: 0,
      brokenAt: null,
      brokenEvidenceId: null,
      merkleRoot: sha256("EMPTY_CHAIN"),
      errors: [],
      lastVerified: Date.now(),
    };
  }

  const errors: string[] = [];
  let validLinks = 0;
  const chainHashes: string[] = [];

  for (let i = 0; i < chain.length; i++) {
    const envelope = chain[i];
    const prevEnvelope = i > 0 ? chain[i - 1] : null;

    // Verify chain linkage
    const expectedPrevHash = prevEnvelope ? prevEnvelope.chainHash : null;
    if (envelope.previousChainHash !== expectedPrevHash) {
      errors.push(`Link ${i} (${envelope.evidenceId}): previousChainHash mismatch`);
      return {
        valid: false,
        totalLinks: chain.length,
        validLinks,
        brokenAt: i,
        brokenEvidenceId: envelope.evidenceId,
        merkleRoot: null,
        errors,
        lastVerified: Date.now(),
      };
    }

    // Verify chain hash computation
    const provenanceHash = hashProvenance(envelope.provenance);
    const expectedChainHash = computeChainHash(
      envelope.contentHash,
      envelope.previousChainHash,
      envelope.createdAt,
      provenanceHash,
    );
    if (envelope.chainHash !== expectedChainHash) {
      errors.push(`Link ${i} (${envelope.evidenceId}): chainHash recomputation mismatch`);
      return {
        valid: false,
        totalLinks: chain.length,
        validLinks,
        brokenAt: i,
        brokenEvidenceId: envelope.evidenceId,
        merkleRoot: null,
        errors,
        lastVerified: Date.now(),
      };
    }

    chainHashes.push(envelope.chainHash);
    validLinks++;
  }

  return {
    valid: true,
    totalLinks: chain.length,
    validLinks,
    brokenAt: null,
    brokenEvidenceId: null,
    merkleRoot: computeMerkleRoot(chainHashes),
    errors: [],
    lastVerified: Date.now(),
  };
}

// ─── Provenance Validation ──────────────────────────────────────────────────

/** Tool output signature patterns — used to verify evidence matches its claimed source */
const TOOL_SIGNATURES: Record<EvidenceSourceTool, {
  patterns: RegExp[];
  requiredFields: string[];
  outputFormats: string[];
}> = {
  discovery: {
    patterns: [
      /ScanForge scan report for/i,
      /\d+\/tcp\s+(open|closed|filtered)/,
      /PORT\s+STATE\s+SERVICE/i,
      /Starting ScanForge/i,
      /Host is up/i,
    ],
    requiredFields: ["host", "ports"],
    outputFormats: ["text", "xml", "json"],
  },
  nuclei: {
    patterns: [
      /\[INF\]|^\[.*\]\s+\[.*\]\s+\[.*\]/m,
      /nuclei/i,
      /\[critical\]|\[high\]|\[medium\]|\[low\]|\[info\]/i,
      /template-id|matched-at|type:/i,
    ],
    requiredFields: ["template", "matched-at"],
    outputFormats: ["text", "json", "jsonl"],
  },
  zap: {
    patterns: [
      /ZAP|OWASP/i,
      /alert|risk|confidence/i,
      /pluginid|cweid|wascid/i,
    ],
    requiredFields: ["alert", "risk"],
    outputFormats: ["json", "xml", "html"],
  },
  nikto: {
    patterns: [
      /Nikto/i,
      /\+ Target IP:/i,
      /\+ Server:/i,
      /OSVDB-/,
    ],
    requiredFields: ["target"],
    outputFormats: ["text", "json", "xml"],
  },
  httpx: {
    patterns: [
      /status.code|content.length|title/i,
      /\d{3}\s+\w+/,
    ],
    requiredFields: ["url"],
    outputFormats: ["text", "json"],
  },
  gobuster: {
    patterns: [
      /Gobuster/i,
      /Status:\s*\d{3}/,
      /Found:/i,
    ],
    requiredFields: ["url"],
    outputFormats: ["text"],
  },
  ffuf: {
    patterns: [
      /ffuf|FUZZ/i,
      /Status:\s*\d{3}/,
    ],
    requiredFields: ["url"],
    outputFormats: ["text", "json"],
  },
  testssl: {
    patterns: [
      /testssl|Testing protocols|Testing cipher/i,
      /TLS|SSL/i,
    ],
    requiredFields: ["host"],
    outputFormats: ["text", "json"],
  },
  hydra: {
    patterns: [
      /Hydra/i,
      /\[DATA\]|\[ATTEMPT\]|\[\d+\]\[/,
      /login:|password:/i,
    ],
    requiredFields: ["host", "service"],
    outputFormats: ["text"],
  },
  caldera: {
    patterns: [
      /paw|ability|operation|adversary/i,
      /technique_id|tactic/i,
    ],
    requiredFields: ["operation"],
    outputFormats: ["json"],
  },
  metasploit: {
    patterns: [
      /msf|meterpreter|exploit|payload/i,
      /session\s+\d+\s+opened/i,
      /RHOSTS|RPORT|LHOST/i,
    ],
    requiredFields: ["module"],
    outputFormats: ["text"],
  },
  manual: {
    patterns: [], // Manual evidence has no automatic signature
    requiredFields: [],
    outputFormats: ["text", "json", "html", "png", "pdf"],
  },
  llm_analysis: {
    patterns: [
      /\[OBSERVED\]|\[INFERRED\]|\[HYPOTHESIS\]/,
    ],
    requiredFields: [],
    outputFormats: ["json", "text"],
  },
  system: {
    patterns: [],
    requiredFields: [],
    outputFormats: ["json", "text"],
  },
};

/**
 * Validate that evidence content matches its claimed provenance.
 * Checks tool output signatures, timestamp consistency, and network context.
 */
export function validateProvenance(
  content: string,
  provenance: EvidenceProvenance,
): ProvenanceValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const sig = TOOL_SIGNATURES[provenance.sourceTool];
  if (!sig) {
    errors.push(`Unknown source tool: ${provenance.sourceTool}`);
    return { valid: false, errors, warnings, toolSignatureMatch: false, timestampConsistent: false, networkContextValid: false, contentFormatValid: false };
  }

  // 1. Tool signature matching (skip for manual/system/llm_analysis)
  let toolSignatureMatch = true;
  if (sig.patterns.length > 0) {
    const matchCount = sig.patterns.filter(p => p.test(content)).length;
    const matchRatio = matchCount / sig.patterns.length;

    if (matchRatio === 0) {
      errors.push(`No ${provenance.sourceTool} output signatures found in content. Evidence may not be from claimed source.`);
      toolSignatureMatch = false;
    } else if (matchRatio < 0.3) {
      warnings.push(`Only ${Math.round(matchRatio * 100)}% of ${provenance.sourceTool} signatures matched. Evidence may be incomplete or modified.`);
      toolSignatureMatch = false;
    }
  }

  // 2. Timestamp consistency
  let timestampConsistent = true;
  const toolTs = new Date(provenance.toolOutputTimestamp).getTime();
  const now = Date.now();
  if (isNaN(toolTs)) {
    errors.push("Invalid tool output timestamp");
    timestampConsistent = false;
  } else if (toolTs > now + 60_000) {
    errors.push(`Tool output timestamp is in the future: ${provenance.toolOutputTimestamp}`);
    timestampConsistent = false;
  } else if (now - toolTs > 365 * 24 * 60 * 60 * 1000) {
    warnings.push("Tool output timestamp is more than 1 year old");
  }

  // 3. Network context validation
  let networkContextValid = true;
  if (!provenance.sourceIp || provenance.sourceIp === "unknown") {
    warnings.push("Source IP is unknown — network provenance incomplete");
    networkContextValid = false;
  }
  if (!provenance.destinationIp || provenance.destinationIp === "unknown") {
    warnings.push("Destination IP is unknown — network provenance incomplete");
    networkContextValid = false;
  }

  // 4. Content format validation
  let contentFormatValid = true;
  if (content.length === 0) {
    errors.push("Evidence content is empty");
    contentFormatValid = false;
  }

  // 5. Raw output hash verification
  const actualHash = sha256(content);
  if (provenance.rawOutputHash && provenance.rawOutputHash !== actualHash) {
    errors.push(`Raw output hash mismatch: provenance says ${provenance.rawOutputHash}, actual is ${actualHash}`);
    contentFormatValid = false;
  }

  // 6. Size verification
  const actualSize = Buffer.byteLength(content, "utf-8");
  if (provenance.rawOutputSize > 0 && Math.abs(actualSize - provenance.rawOutputSize) > 100) {
    warnings.push(`Content size differs from provenance: expected ~${provenance.rawOutputSize}B, got ${actualSize}B`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    toolSignatureMatch,
    timestampConsistent,
    networkContextValid,
    contentFormatValid,
  };
}

// ─── Hallucination Guardrails ───────────────────────────────────────────────

/**
 * Cross-reference LLM-generated evidence claims against ground truth data.
 *
 * Ground truth sources:
 *   - Raw tool output (ScanForge discovery, nuclei, ZAP, etc.)
 *   - Caldera API responses (agents, operations)
 *   - Engagement state (assets, ports, vulns)
 *   - Known CVE databases
 *
 * This function does NOT call the LLM — it performs deterministic validation.
 */
export function checkHallucination(params: {
  /** The LLM-generated content to validate */
  llmContent: string;
  /** Ground truth: raw tool outputs keyed by tool name */
  groundTruth: Record<string, string>;
  /** Ground truth: known assets from engagement state */
  knownAssets?: Array<{ hostname: string; ip: string; ports?: number[] }>;
  /** Ground truth: known CVEs from scan results */
  knownCves?: string[];
  /** Ground truth: known services from enumeration */
  knownServices?: Array<{ port: number; service: string; version?: string }>;
  /** Strictness level */
  strictness?: "strict" | "moderate" | "lenient";
}): HallucinationCheckResult {
  const {
    llmContent,
    groundTruth,
    knownAssets = [],
    knownCves = [],
    knownServices = [],
    strictness = "moderate",
  } = params;

  const groundedClaims: GroundedClaim[] = [];
  const ungroundedClaims: UngroundedClaim[] = [];
  const warnings: string[] = [];

  // ── 1. Extract IP addresses from LLM content and verify against ground truth ──
  const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const mentionedIps = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = ipPattern.exec(llmContent)) !== null) {
    mentionedIps.add(match[1]);
  }

  const knownIps = new Set(knownAssets.map(a => a.ip).filter(Boolean));
  // Also extract IPs from ground truth tool outputs
  for (const output of Object.values(groundTruth)) {
    let m: RegExpExecArray | null;
    const ipRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    while ((m = ipRe.exec(output)) !== null) {
      knownIps.add(m[1]);
    }
  }

  for (const ip of mentionedIps) {
    // Skip common non-routable IPs
    if (ip.startsWith("127.") || ip.startsWith("0.") || ip === "255.255.255.255") continue;

    if (knownIps.has(ip)) {
      groundedClaims.push({
        claim: `IP address ${ip}`,
        groundTruthSource: "engagement_assets / tool_output",
        confidence: 1.0,
      });
    } else {
      ungroundedClaims.push({
        claim: `IP address ${ip} mentioned but not found in any ground truth source`,
        reason: "IP not observed in scan data, engagement assets, or tool output",
        severity: strictness === "strict" ? "high" : "medium",
      });
    }
  }

  // ── 2. Extract CVE references and verify ──
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const mentionedCves = new Set<string>();
  while ((match = cvePattern.exec(llmContent)) !== null) {
    mentionedCves.add(match[0].toUpperCase());
  }

  const knownCveSet = new Set(knownCves.map(c => c.toUpperCase()));
  // Also extract CVEs from ground truth
  for (const output of Object.values(groundTruth)) {
    let m: RegExpExecArray | null;
    const cveRe = /CVE-\d{4}-\d{4,}/gi;
    while ((m = cveRe.exec(output)) !== null) {
      knownCveSet.add(m[0].toUpperCase());
    }
  }

  for (const cve of mentionedCves) {
    if (knownCveSet.has(cve)) {
      groundedClaims.push({
        claim: `CVE reference ${cve}`,
        groundTruthSource: "scan_results / known_cves",
        confidence: 1.0,
      });
    } else {
      ungroundedClaims.push({
        claim: `CVE ${cve} referenced but not found in scan results`,
        reason: "CVE not discovered by any scanning tool in this engagement",
        severity: "high",
      });
    }
  }

  // ── 3. Extract port references and verify ──
  const portPattern = /\bport\s*(\d{1,5})\b/gi;
  const mentionedPorts = new Set<number>();
  while ((match = portPattern.exec(llmContent)) !== null) {
    const port = parseInt(match[1], 10);
    if (port > 0 && port <= 65535) mentionedPorts.add(port);
  }
  // Also match "80/tcp" style
  const portSlashPattern = /\b(\d{1,5})\/(tcp|udp)\b/gi;
  while ((match = portSlashPattern.exec(llmContent)) !== null) {
    const port = parseInt(match[1], 10);
    if (port > 0 && port <= 65535) mentionedPorts.add(port);
  }

  const knownPorts = new Set([
    ...knownAssets.flatMap(a => a.ports || []),
    ...knownServices.map(s => s.port),
  ]);
  // Extract ports from ScanForge discovery output in ground truth
  for (const [tool, output] of Object.entries(groundTruth)) {
    if (tool === "scanforge-discovery" || tool.includes("scanforge-discovery")) {
      let m: RegExpExecArray | null;
      const portRe = /(\d{1,5})\/tcp\s+(open|closed|filtered)/g;
      while ((m = portRe.exec(output)) !== null) {
        knownPorts.add(parseInt(m[1], 10));
      }
    }
  }

  for (const port of mentionedPorts) {
    if (knownPorts.has(port)) {
      groundedClaims.push({
        claim: `Port ${port}`,
        groundTruthSource: "discovery_scan / enumeration",
        confidence: 1.0,
      });
    } else {
      // Common ports (80, 443, 22, etc.) get a warning, not an error
      const commonPorts = [80, 443, 22, 21, 25, 53, 8080, 8443, 3306, 5432, 27017, 6379];
      if (commonPorts.includes(port)) {
        warnings.push(`Port ${port} mentioned but not confirmed in scan data (common port, may be assumed)`);
      } else {
        ungroundedClaims.push({
          claim: `Port ${port} referenced but not found in scan results`,
          reason: "Port not discovered during enumeration phase",
          severity: "medium",
        });
      }
    }
  }

  // ── 4. Extract hostnames and verify ──
  const hostnamePattern = /\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
  const mentionedHostnames = new Set<string>();
  while ((match = hostnamePattern.exec(llmContent)) !== null) {
    // Skip common non-target domains
    const hostname = match[0].toLowerCase();
    if (hostname.endsWith(".example.com") || hostname.endsWith(".test") || hostname.endsWith(".local")) continue;
    if (hostname.includes("owasp.org") || hostname.includes("mitre.org") || hostname.includes("nist.gov")) continue;
    if (hostname.includes("cve.org") || hostname.includes("nvd.nist.gov") || hostname.includes("github.com")) continue;
    mentionedHostnames.add(hostname);
  }

  const knownHostnames = new Set(knownAssets.map(a => a.hostname.toLowerCase()));
  for (const output of Object.values(groundTruth)) {
    // Extract hostnames from tool output
    let m: RegExpExecArray | null;
    const hostRe = /\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
    while ((m = hostRe.exec(output)) !== null) {
      knownHostnames.add(m[0].toLowerCase());
    }
  }

  for (const hostname of mentionedHostnames) {
    if (knownHostnames.has(hostname)) {
      groundedClaims.push({
        claim: `Hostname ${hostname}`,
        groundTruthSource: "engagement_assets / tool_output",
        confidence: 1.0,
      });
    } else {
      ungroundedClaims.push({
        claim: `Hostname ${hostname} mentioned but not in scope or scan data`,
        reason: "Hostname not found in engagement assets or tool output",
        severity: strictness === "strict" ? "high" : "low",
      });
    }
  }

  // ── 5. Check for fabricated exploit claims ──
  const exploitPatterns = [
    /successfully\s+exploit/i,
    /remote\s+code\s+execution\s+(confirmed|achieved|verified)/i,
    /shell\s+(obtained|established|gained)/i,
    /session\s+\d+\s+opened/i,
    /meterpreter\s+session/i,
    /root\s+access\s+(obtained|gained|confirmed)/i,
    /privilege\s+escalation\s+(successful|confirmed)/i,
  ];

  for (const pattern of exploitPatterns) {
    if (pattern.test(llmContent)) {
      // Check if any ground truth supports this claim
      const hasExploitEvidence = Object.values(groundTruth).some(output =>
        pattern.test(output) ||
        /session.*opened/i.test(output) ||
        /exploit.*completed/i.test(output) ||
        /SUCCESS/i.test(output)
      );

      if (hasExploitEvidence) {
        groundedClaims.push({
          claim: `Exploit success claim matching: ${pattern.source}`,
          groundTruthSource: "tool_output",
          confidence: 0.9,
        });
      } else {
        ungroundedClaims.push({
          claim: `Exploit success claimed ("${llmContent.match(pattern)?.[0]}") but no supporting tool output found`,
          reason: "No tool output confirms successful exploitation. This may be a hallucinated exploit result.",
          severity: "critical",
        });
      }
    }
  }

  // ── 6. Check for fabricated CVSS scores ──
  const cvssPattern = /CVSS[:\s]*(\d+\.?\d*)/gi;
  while ((match = cvssPattern.exec(llmContent)) !== null) {
    const score = parseFloat(match[1]);
    if (score < 0 || score > 10) {
      ungroundedClaims.push({
        claim: `Invalid CVSS score: ${score}`,
        reason: "CVSS scores must be between 0.0 and 10.0",
        severity: "high",
      });
    }
  }

  // ── Compute overall score ──
  const totalClaims = groundedClaims.length + ungroundedClaims.length;
  const score = totalClaims === 0 ? 1.0 : groundedClaims.length / totalClaims;

  const criticalUngrounded = ungroundedClaims.filter(c => c.severity === "critical").length;
  const highUngrounded = ungroundedClaims.filter(c => c.severity === "high").length;

  // Determine recommendation
  let recommendation: HallucinationCheckResult["recommendation"];
  if (criticalUngrounded > 0) {
    recommendation = "quarantine";
  } else if (highUngrounded > 2 || score < 0.5) {
    recommendation = "reject";
  } else if (highUngrounded > 0 || score < 0.8) {
    recommendation = "review";
  } else {
    recommendation = "accept";
  }

  // Apply strictness adjustments
  if (strictness === "strict" && score < 0.9) {
    recommendation = recommendation === "accept" ? "review" : recommendation;
  }
  if (strictness === "lenient" && recommendation === "review" && criticalUngrounded === 0) {
    recommendation = score >= 0.6 ? "accept" : "review";
  }

  return {
    passed: recommendation === "accept" || recommendation === "review",
    score,
    groundedClaims,
    ungroundedClaims,
    warnings,
    recommendation,
  };
}

// ─── Evidence Sanitization ──────────────────────────────────────────────────

/**
 * Sanitize LLM-generated evidence content by removing ungrounded claims.
 * Returns the sanitized content with annotations about what was removed.
 */
export function sanitizeEvidence(
  content: string,
  checkResult: HallucinationCheckResult,
): { sanitized: string; removedClaims: string[]; annotations: string[] } {
  let sanitized = content;
  const removedClaims: string[] = [];
  const annotations: string[] = [];

  for (const claim of checkResult.ungroundedClaims) {
    if (claim.severity === "critical" || claim.severity === "high") {
      // For IPs, CVEs, and hostnames — add [UNVERIFIED] tag
      const ipMatch = claim.claim.match(/IP address (\S+)/);
      if (ipMatch) {
        sanitized = sanitized.replace(
          new RegExp(`\\b${escapeRegex(ipMatch[1])}\\b`, "g"),
          `${ipMatch[1]} [UNVERIFIED]`,
        );
        annotations.push(`IP ${ipMatch[1]} not found in ground truth — marked as UNVERIFIED`);
      }

      const cveMatch = claim.claim.match(/(CVE-\d{4}-\d+)/);
      if (cveMatch) {
        sanitized = sanitized.replace(
          new RegExp(escapeRegex(cveMatch[1]), "gi"),
          `${cveMatch[1]} [UNVERIFIED]`,
        );
        annotations.push(`${cveMatch[1]} not found in scan results — marked as UNVERIFIED`);
      }

      // For exploit claims — add strong warning
      if (claim.claim.includes("Exploit success")) {
        annotations.push(`WARNING: Exploit success claim not supported by tool output — requires manual verification`);
      }

      removedClaims.push(claim.claim);
    }
  }

  // Add integrity footer
  if (annotations.length > 0) {
    sanitized += `\n\n--- INTEGRITY ANNOTATIONS ---\n`;
    for (const ann of annotations) {
      sanitized += `⚠ ${ann}\n`;
    }
    sanitized += `\nHallucination check score: ${(checkResult.score * 100).toFixed(1)}% grounded\n`;
    sanitized += `Recommendation: ${checkResult.recommendation.toUpperCase()}\n`;
  }

  return { sanitized, removedClaims, annotations };
}

// ─── Batch Operations ───────────────────────────────────────────────────────

/**
 * Get the evidence chain for an engagement.
 */
export function getChain(engagementId: string): IntegrityEnvelope[] {
  return chainStore.get(engagementId) || [];
}

/**
 * Get a specific evidence envelope by ID.
 */
export function getEnvelope(engagementId: string, evidenceId: string): IntegrityEnvelope | null {
  const chain = chainStore.get(engagementId) || [];
  return chain.find(e => e.evidenceId === evidenceId) || null;
}

/**
 * Create an integrity anchor (signed Merkle root) for an engagement's evidence chain.
 */
export function createAnchor(engagementId: string): {
  merkleRoot: string;
  hmacSignature: string;
  chainLength: number;
  anchoredAt: number;
} | null {
  const validation = validateChain(engagementId);
  if (!validation.valid || !validation.merkleRoot) return null;

  return {
    merkleRoot: validation.merkleRoot,
    hmacSignature: computeAnchorHMAC(validation.merkleRoot, engagementId),
    chainLength: validation.totalLinks,
    anchoredAt: Date.now(),
  };
}

/**
 * Verify an integrity anchor against the current chain state.
 */
export function verifyAnchor(
  engagementId: string,
  anchor: { merkleRoot: string; hmacSignature: string },
): { valid: boolean; error?: string } {
  const validation = validateChain(engagementId);
  if (!validation.valid) {
    return { valid: false, error: `Chain is broken: ${validation.errors.join("; ")}` };
  }

  if (validation.merkleRoot !== anchor.merkleRoot) {
    return { valid: false, error: "Merkle root mismatch — chain has been modified since anchor was created" };
  }

  const expectedHmac = computeAnchorHMAC(anchor.merkleRoot, engagementId);
  if (expectedHmac !== anchor.hmacSignature) {
    return { valid: false, error: "HMAC signature mismatch — anchor may have been tampered with" };
  }

  return { valid: true };
}

/**
 * Flush the in-memory chain to the database for persistence.
 */
export async function flushChainToDb(engagementId: string): Promise<{ flushed: number; errors: string[] }> {
  const chain = chainStore.get(engagementId) || [];
  if (chain.length === 0) return { flushed: 0, errors: [] };

  const errors: string[] = [];
  let flushed = 0;

  try {
    const { getDb } = await import("../db");
    const { evidenceItems, evidenceChainOfCustody } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) {
      errors.push("Database unavailable");
      return { flushed, errors };
    }

    for (const envelope of chain) {
      try {
        // Upsert integrity data into evidence_chain_of_custody
        for (const event of envelope.custodyTrail) {
          await db.insert(evidenceChainOfCustody).values({
            evidenceId: envelope.evidenceId,
            action: event.action,
            performedBy: event.performedBy,
            details: JSON.stringify({
              contentHash: envelope.contentHash,
              chainHash: envelope.chainHash,
              previousChainHash: envelope.previousChainHash,
              provenanceHash: hashProvenance(envelope.provenance),
              provenance: envelope.provenance,
              verificationStatus: envelope.verificationStatus,
              eventDetails: event.details,
            }),
            integrityHash: event.integrityHash,
            previousHash: envelope.previousChainHash,
            ipAddress: event.ipAddress,
          });
        }
        flushed++;
      } catch (err: any) {
        errors.push(`Failed to flush ${envelope.evidenceId}: ${err.message}`);
      }
    }
  } catch (err: any) {
    errors.push(`DB connection error: ${err.message}`);
  }

  return { flushed, errors };
}

/**
 * Clear the in-memory chain for an engagement (e.g., after flushing to DB).
 */
export function clearChain(engagementId: string): void {
  chainStore.delete(engagementId);
}

/**
 * Get summary statistics for all active chains.
 */
export function getChainStats(): {
  totalEngagements: number;
  totalEnvelopes: number;
  byEngagement: Array<{ engagementId: string; count: number; lastAction: CustodyAction }>;
} {
  const byEngagement: Array<{ engagementId: string; count: number; lastAction: CustodyAction }> = [];
  let totalEnvelopes = 0;

  for (const [engagementId, chain] of chainStore.entries()) {
    totalEnvelopes += chain.length;
    byEngagement.push({
      engagementId,
      count: chain.length,
      lastAction: chain.length > 0 ? chain[chain.length - 1].currentState : "created",
    });
  }

  return {
    totalEngagements: chainStore.size,
    totalEnvelopes,
    byEngagement,
  };
}

// ─── Utility ────────────────────────────────────────────────────────────────

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build a provenance record from engagement context.
 * Convenience helper for the orchestrator.
 */
export function buildProvenance(params: {
  tool: EvidenceSourceTool;
  toolVersion?: string;
  command?: string;
  collectorHost: string;
  rawOutput: string;
  targetHost: string;
  targetPort?: number;
  sourceIp: string;
  destinationIp: string;
}): EvidenceProvenance {
  return {
    sourceTool: params.tool,
    toolVersion: params.toolVersion,
    sourceCommand: params.command,
    collectorHost: params.collectorHost,
    toolOutputTimestamp: new Date().toISOString(),
    rawOutputHash: sha256(params.rawOutput),
    rawOutputSize: Buffer.byteLength(params.rawOutput, "utf-8"),
    targetHost: params.targetHost,
    targetPort: params.targetPort,
    sourceIp: params.sourceIp,
    destinationIp: params.destinationIp,
  };
}

/**
 * Quick integrity check: hash content + validate provenance + check hallucination.
 * Returns a pass/fail with details. Use this as a gate before evidence enters reports.
 */
export function evidenceGate(params: {
  content: string;
  provenance: EvidenceProvenance;
  groundTruth?: Record<string, string>;
  knownAssets?: Array<{ hostname: string; ip: string; ports?: number[] }>;
  knownCves?: string[];
  strictness?: "strict" | "moderate" | "lenient";
}): {
  passed: boolean;
  contentHash: string;
  provenanceValid: boolean;
  hallucinationCheck: HallucinationCheckResult | null;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // 1. Hash content
  const contentHash = sha256(params.content);

  // 2. Validate provenance
  const provenanceResult = validateProvenance(params.content, params.provenance);
  errors.push(...provenanceResult.errors);
  warnings.push(...provenanceResult.warnings);

  // 3. Hallucination check (only if ground truth provided and source is LLM)
  let hallucinationCheck: HallucinationCheckResult | null = null;
  if (params.groundTruth && (params.provenance.sourceTool === "llm_analysis" || Object.keys(params.groundTruth).length > 0)) {
    hallucinationCheck = checkHallucination({
      llmContent: params.content,
      groundTruth: params.groundTruth,
      knownAssets: params.knownAssets,
      knownCves: params.knownCves,
      strictness: params.strictness,
    });

    if (hallucinationCheck.recommendation === "quarantine") {
      errors.push("Evidence quarantined: critical hallucination detected");
    } else if (hallucinationCheck.recommendation === "reject") {
      errors.push("Evidence rejected: too many ungrounded claims");
    }
    warnings.push(...hallucinationCheck.warnings);
  }

  const passed = errors.length === 0 && provenanceResult.valid;

  return {
    passed,
    contentHash,
    provenanceValid: provenanceResult.valid,
    hallucinationCheck,
    errors,
    warnings,
  };
}
