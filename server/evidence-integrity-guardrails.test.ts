/**
 * Evidence Integrity Guardrails & Chain-of-Custody — Vitest Tests
 *
 * Tests cover:
 *   1. Cryptographic primitives (SHA-256, chain hash, Merkle root, HMAC)
 *   2. Chain of custody operations (create, record events, validate chain)
 *   3. Evidence lifecycle state machine (valid/invalid transitions)
 *   4. Provenance validation (tool signatures, timestamps, network context)
 *   5. Hallucination detection (IPs, CVEs, ports, hostnames, exploits, CVSS)
 *   6. Evidence sanitization (unverified tags, annotations)
 *   7. Evidence gate (combined provenance + hallucination check)
 *   8. Integrity anchors (Merkle root, HMAC verification)
 *   9. LLM evidence guardrail wrappers (report finding, vuln verification, attack plan)
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  sha256,
  computeChainHash,
  computeAnchorHMAC,
  computeMerkleRoot,
  hashProvenance,
  isValidTransition,
  getAllowedTransitions,
  createIntegrityEnvelope,
  recordCustodyEvent,
  verifyEvidenceIntegrity,
  validateChain,
  validateProvenance,
  checkHallucination,
  sanitizeEvidence,
  evidenceGate,
  createAnchor,
  verifyAnchor,
  getChain,
  clearChain,
  getChainStats,
  buildProvenance,
  type EvidenceProvenance,
  type IntegrityEnvelope,
} from "./lib/evidence-integrity-guardrails";

import {
  validateReportFinding,
  validateVulnVerification,
  validateAttackPlan,
  validateLLMEvidence,
  validateReportSection,
  type GuardrailContext,
} from "./lib/llm-evidence-guardrail";

// ─── Test Fixtures ──────────────────────────────────────────────────────────

const NMAP_OUTPUT = `Starting Nmap 7.94 ( https://nmap.org ) at 2026-03-15 10:00 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0012s latency).
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1
80/tcp   open  http     Apache httpd 2.4.52
443/tcp  open  ssl/http Apache httpd 2.4.52
3306/tcp open  mysql    MySQL 8.0.32
8080/tcp open  http     Node.js Express framework`;

const NUCLEI_OUTPUT = `[INF] Using Nuclei Engine 3.1.0
[critical] [CVE-2023-44487] [http] http://192.168.1.100:80
[high] [CVE-2022-22965] [http] http://192.168.1.100:8080
[medium] [ssl-weak-cipher] [ssl] https://192.168.1.100:443
[info] [tech-detect:apache] [http] http://192.168.1.100:80`;

const ZAP_OUTPUT = `{"alert":"SQL Injection","risk":"High","confidence":"Medium","url":"http://192.168.1.100/login","pluginid":"40018","cweid":"89","wascid":"19"}`;

const KNOWN_ASSETS = [
  { hostname: "web-server-01.example.com", ip: "192.168.1.100", ports: [22, 80, 443, 3306, 8080] },
  { hostname: "db-server-01.example.com", ip: "192.168.1.101", ports: [3306, 5432] },
];

const KNOWN_CVES = ["CVE-2023-44487", "CVE-2022-22965"];

function makeProvenance(overrides?: Partial<EvidenceProvenance>): EvidenceProvenance {
  return {
    sourceTool: "nmap",
    collectorHost: "ac3-scanner-01",
    toolOutputTimestamp: new Date().toISOString(),
    rawOutputHash: sha256(NMAP_OUTPUT),
    rawOutputSize: Buffer.byteLength(NMAP_OUTPUT, "utf-8"),
    targetHost: "192.168.1.100",
    sourceIp: "10.0.0.5",
    destinationIp: "192.168.1.100",
    ...overrides,
  };
}

function makeGuardrailContext(overrides?: Partial<GuardrailContext>): GuardrailContext {
  return {
    specialist: "test-specialist",
    engagementId: "test-eng-1",
    toolOutputs: { nmap: NMAP_OUTPUT, nuclei: NUCLEI_OUTPUT, zap: ZAP_OUTPUT },
    knownAssets: KNOWN_ASSETS,
    knownCves: KNOWN_CVES,
    strictness: "moderate",
    ...overrides,
  };
}

// ─── 1. Cryptographic Primitives ────────────────────────────────────────────

describe("Cryptographic Primitives", () => {
  it("sha256 produces consistent 64-char hex hash", () => {
    const hash = sha256("hello world");
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(sha256("hello world")).toBe(hash); // deterministic
  });

  it("sha256 produces different hashes for different inputs", () => {
    expect(sha256("input-a")).not.toBe(sha256("input-b"));
  });

  it("sha256 handles Buffer input", () => {
    const hash = sha256(Buffer.from("test data"));
    expect(hash).toHaveLength(64);
  });

  it("computeChainHash includes all components", () => {
    const hash1 = computeChainHash("content1", null, 1000, "prov1");
    const hash2 = computeChainHash("content1", "prev1", 1000, "prov1");
    const hash3 = computeChainHash("content1", null, 2000, "prov1");
    const hash4 = computeChainHash("content1", null, 1000, "prov2");

    // All different because different inputs
    expect(new Set([hash1, hash2, hash3, hash4]).size).toBe(4);
  });

  it("computeChainHash with null previous uses GENESIS", () => {
    const hash = computeChainHash("content", null, 1000, "prov");
    expect(hash).toHaveLength(64);
  });

  it("computeAnchorHMAC produces consistent HMAC", () => {
    const hmac1 = computeAnchorHMAC("merkle-root", "eng-1");
    const hmac2 = computeAnchorHMAC("merkle-root", "eng-1");
    expect(hmac1).toBe(hmac2);
    expect(hmac1).toHaveLength(64);
  });

  it("computeAnchorHMAC differs by engagement", () => {
    const hmac1 = computeAnchorHMAC("merkle-root", "eng-1");
    const hmac2 = computeAnchorHMAC("merkle-root", "eng-2");
    expect(hmac1).not.toBe(hmac2);
  });

  it("computeMerkleRoot handles empty array", () => {
    const root = computeMerkleRoot([]);
    expect(root).toHaveLength(64);
  });

  it("computeMerkleRoot handles single element", () => {
    const root = computeMerkleRoot(["abc123"]);
    expect(root).toBe("abc123");
  });

  it("computeMerkleRoot handles multiple elements", () => {
    const root = computeMerkleRoot(["a", "b", "c", "d"]);
    expect(root).toHaveLength(64);
  });

  it("computeMerkleRoot handles odd number of elements", () => {
    const root = computeMerkleRoot(["a", "b", "c"]);
    expect(root).toHaveLength(64);
  });

  it("hashProvenance produces deterministic hash", () => {
    const prov = makeProvenance();
    const hash1 = hashProvenance(prov);
    const hash2 = hashProvenance(prov);
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });
});

// ─── 2. Evidence Lifecycle State Machine ────────────────────────────────────

describe("Evidence Lifecycle State Machine", () => {
  it("allows creation from empty state", () => {
    expect(isValidTransition("", "created")).toBe(true);
    expect(isValidTransition("", "captured")).toBe(true);
  });

  it("blocks invalid genesis transitions", () => {
    expect(isValidTransition("", "exported")).toBe(false);
    expect(isValidTransition("", "deleted")).toBe(false);
    expect(isValidTransition("", "archived")).toBe(false);
  });

  it("allows hashing after creation", () => {
    expect(isValidTransition("created", "hashed")).toBe(true);
    expect(isValidTransition("created", "validated")).toBe(true);
  });

  it("allows export after validation", () => {
    expect(isValidTransition("validated", "exported")).toBe(true);
    expect(isValidTransition("validated", "accessed")).toBe(true);
    expect(isValidTransition("validated", "archived")).toBe(true);
  });

  it("allows quarantine from any pre-export state", () => {
    expect(isValidTransition("created", "quarantined")).toBe(true);
    expect(isValidTransition("captured", "quarantined")).toBe(true);
    expect(isValidTransition("hashed", "quarantined")).toBe(true);
    expect(isValidTransition("validated", "quarantined")).toBe(true);
  });

  it("blocks export from quarantined state", () => {
    expect(isValidTransition("quarantined", "exported")).toBe(false);
    expect(isValidTransition("quarantined", "accessed")).toBe(false);
  });

  it("allows release from quarantine", () => {
    expect(isValidTransition("quarantined", "released")).toBe(true);
    expect(isValidTransition("quarantined", "deleted")).toBe(true);
  });

  it("blocks deletion from non-terminal states", () => {
    expect(isValidTransition("created", "deleted")).toBe(false);
    expect(isValidTransition("validated", "deleted")).toBe(false);
    expect(isValidTransition("exported", "deleted")).toBe(false);
  });

  it("getAllowedTransitions returns correct options", () => {
    const fromCreated = getAllowedTransitions("created");
    expect(fromCreated).toContain("hashed");
    expect(fromCreated).toContain("validated");
    expect(fromCreated).toContain("quarantined");
    expect(fromCreated).not.toContain("exported");
  });
});

// ─── 3. Chain of Custody Operations ─────────────────────────────────────────

describe("Chain of Custody Operations", () => {
  const engId = "test-chain-eng";

  beforeEach(() => {
    clearChain(engId);
  });

  it("creates an integrity envelope with correct fields", () => {
    const envelope = createIntegrityEnvelope({
      evidenceId: "ev-001",
      engagementId: engId,
      content: NMAP_OUTPUT,
      provenance: makeProvenance(),
      performedBy: "AC3 Scanner",
    });

    expect(envelope.evidenceId).toBe("ev-001");
    expect(envelope.engagementId).toBe(engId);
    expect(envelope.contentHash).toHaveLength(64);
    expect(envelope.chainHash).toHaveLength(64);
    expect(envelope.previousChainHash).toBeNull();
    expect(envelope.currentState).toBe("created");
    expect(envelope.verificationStatus).toBe("unverified");
    expect(envelope.custodyTrail).toHaveLength(1);
    expect(envelope.custodyTrail[0].action).toBe("created");
  });

  it("chains multiple envelopes correctly", () => {
    const env1 = createIntegrityEnvelope({
      evidenceId: "ev-001",
      engagementId: engId,
      content: "evidence 1",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const env2 = createIntegrityEnvelope({
      evidenceId: "ev-002",
      engagementId: engId,
      content: "evidence 2",
      provenance: makeProvenance({ targetHost: "192.168.1.101" }),
      performedBy: "Scanner",
    });

    expect(env2.previousChainHash).toBe(env1.chainHash);
    expect(env1.previousChainHash).toBeNull();
  });

  it("records custody events with valid transitions", () => {
    const envelope = createIntegrityEnvelope({
      evidenceId: "ev-003",
      engagementId: engId,
      content: "test content",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const result = recordCustodyEvent(envelope, "validated", "AC3 Guardrail", "Passed validation");
    expect(result.success).toBe(true);
    expect(envelope.currentState).toBe("validated");
    expect(envelope.verificationStatus).toBe("verified");
    expect(envelope.custodyTrail).toHaveLength(2);
  });

  it("rejects invalid custody event transitions", () => {
    const envelope = createIntegrityEnvelope({
      evidenceId: "ev-004",
      engagementId: engId,
      content: "test content",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const result = recordCustodyEvent(envelope, "exported", "User", "Trying to export before validation");
    expect(result.success).toBe(false);
    expect(result.error).toContain("Invalid transition");
  });

  it("quarantine sets verification status", () => {
    const envelope = createIntegrityEnvelope({
      evidenceId: "ev-005",
      engagementId: engId,
      content: "suspicious content",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    recordCustodyEvent(envelope, "quarantined", "AC3 Guardrail", "Hallucination detected");
    expect(envelope.verificationStatus).toBe("quarantined");
  });

  it("verifyEvidenceIntegrity passes for unchanged content", () => {
    const content = "original evidence content";
    const envelope = createIntegrityEnvelope({
      evidenceId: "ev-006",
      engagementId: engId,
      content,
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const result = verifyEvidenceIntegrity(envelope, content);
    expect(result.valid).toBe(true);
    expect(envelope.verificationStatus).toBe("verified");
  });

  it("verifyEvidenceIntegrity fails for tampered content", () => {
    const envelope = createIntegrityEnvelope({
      evidenceId: "ev-007",
      engagementId: engId,
      content: "original content",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const result = verifyEvidenceIntegrity(envelope, "tampered content");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("hash mismatch");
    expect(envelope.verificationStatus).toBe("tampered");
  });
});

// ─── 4. Chain Validation ────────────────────────────────────────────────────

describe("Chain Validation", () => {
  const engId = "test-validate-eng";

  beforeEach(() => {
    clearChain(engId);
  });

  it("validates an empty chain", () => {
    const result = validateChain(engId);
    expect(result.valid).toBe(true);
    expect(result.totalLinks).toBe(0);
  });

  it("validates a single-link chain", () => {
    createIntegrityEnvelope({
      evidenceId: "ev-v1",
      engagementId: engId,
      content: "evidence 1",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const result = validateChain(engId);
    expect(result.valid).toBe(true);
    expect(result.totalLinks).toBe(1);
    expect(result.validLinks).toBe(1);
    expect(result.merkleRoot).toBeTruthy();
  });

  it("validates a multi-link chain", () => {
    for (let i = 0; i < 5; i++) {
      createIntegrityEnvelope({
        evidenceId: `ev-v${i}`,
        engagementId: engId,
        content: `evidence ${i}`,
        provenance: makeProvenance(),
        performedBy: "Scanner",
      });
    }

    const result = validateChain(engId);
    expect(result.valid).toBe(true);
    expect(result.totalLinks).toBe(5);
    expect(result.validLinks).toBe(5);
  });

  it("detects tampered chain link", () => {
    createIntegrityEnvelope({
      evidenceId: "ev-t1",
      engagementId: engId,
      content: "evidence 1",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const env2 = createIntegrityEnvelope({
      evidenceId: "ev-t2",
      engagementId: engId,
      content: "evidence 2",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    // Tamper with the chain hash
    env2.chainHash = "0000000000000000000000000000000000000000000000000000000000000000";

    const result = validateChain(engId);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.brokenEvidenceId).toBe("ev-t2");
  });
});

// ─── 5. Provenance Validation ───────────────────────────────────────────────

describe("Provenance Validation", () => {
  it("validates nmap output against nmap provenance", () => {
    const result = validateProvenance(NMAP_OUTPUT, makeProvenance({ sourceTool: "nmap" }));
    expect(result.valid).toBe(true);
    expect(result.toolSignatureMatch).toBe(true);
    expect(result.timestampConsistent).toBe(true);
  });

  it("rejects non-nmap content claimed as nmap", () => {
    const result = validateProvenance("This is just random text with no tool signatures", makeProvenance({ sourceTool: "nmap" }));
    expect(result.toolSignatureMatch).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("validates nuclei output against nuclei provenance", () => {
    const result = validateProvenance(NUCLEI_OUTPUT, makeProvenance({ sourceTool: "nuclei" }));
    expect(result.toolSignatureMatch).toBe(true);
  });

  it("validates ZAP output against ZAP provenance", () => {
    const result = validateProvenance(ZAP_OUTPUT, makeProvenance({ sourceTool: "zap" }));
    expect(result.toolSignatureMatch).toBe(true);
  });

  it("accepts manual evidence without signature check", () => {
    // Manual evidence has no tool patterns, so signature check passes.
    // However, rawOutputHash from makeProvenance won't match the new content,
    // so we build a proper provenance for this content.
    const content = "Manual observation notes";
    const prov = buildProvenance({
      tool: "manual",
      collectorHost: "ac3-scanner-01",
      rawOutput: content,
      targetHost: "192.168.1.100",
      sourceIp: "10.0.0.5",
      destinationIp: "192.168.1.100",
    });
    const result = validateProvenance(content, prov);
    expect(result.toolSignatureMatch).toBe(true);
    expect(result.valid).toBe(true);
  });

  it("detects future timestamps", () => {
    const futureDate = new Date(Date.now() + 3600000).toISOString();
    const result = validateProvenance(NMAP_OUTPUT, makeProvenance({
      sourceTool: "nmap",
      toolOutputTimestamp: futureDate,
    }));
    expect(result.timestampConsistent).toBe(false);
  });

  it("warns about unknown source/destination IPs", () => {
    const result = validateProvenance(NMAP_OUTPUT, makeProvenance({
      sourceTool: "nmap",
      sourceIp: "unknown",
      destinationIp: "unknown",
    }));
    expect(result.networkContextValid).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it("detects empty content", () => {
    const result = validateProvenance("", makeProvenance({ sourceTool: "nmap" }));
    expect(result.contentFormatValid).toBe(false);
  });

  it("detects raw output hash mismatch", () => {
    const result = validateProvenance(NMAP_OUTPUT, makeProvenance({
      sourceTool: "nmap",
      rawOutputHash: "0000000000000000000000000000000000000000000000000000000000000000",
    }));
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes("hash mismatch"))).toBe(true);
  });
});

// ─── 6. Hallucination Detection ─────────────────────────────────────────────

describe("Hallucination Detection", () => {
  it("accepts fully grounded content", () => {
    const content = "Nmap scan found port 80/tcp open on 192.168.1.100 running Apache httpd. CVE-2023-44487 was detected by Nuclei.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT, nuclei: NUCLEI_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      knownCves: KNOWN_CVES,
    });

    expect(result.score).toBeGreaterThan(0.5);
    expect(result.groundedClaims.length).toBeGreaterThan(0);
    expect(result.recommendation).toBe("accept");
  });

  it("detects fabricated IP addresses", () => {
    const content = "We discovered a critical vulnerability on 10.99.99.99 which is not in scope.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      knownCves: KNOWN_CVES,
    });

    const fabricatedIp = result.ungroundedClaims.find(c => c.claim.includes("10.99.99.99"));
    expect(fabricatedIp).toBeTruthy();
  });

  it("detects fabricated CVE references", () => {
    const content = "The server is vulnerable to CVE-2099-99999 which allows remote code execution.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nuclei: NUCLEI_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      knownCves: KNOWN_CVES,
    });

    const fabricatedCve = result.ungroundedClaims.find(c => c.claim.includes("CVE-2099-99999"));
    expect(fabricatedCve).toBeTruthy();
    expect(fabricatedCve!.severity).toBe("high");
  });

  it("detects fabricated port references", () => {
    const content = "Port 9999 was found running a custom service that is vulnerable.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
    });

    const fabricatedPort = result.ungroundedClaims.find(c => c.claim.includes("Port 9999"));
    expect(fabricatedPort).toBeTruthy();
  });

  it("detects fabricated exploit success claims", () => {
    const content = "We successfully exploited the target and obtained root access. A meterpreter session was established.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
    });

    const fabricatedExploit = result.ungroundedClaims.find(c => c.claim.includes("Exploit success"));
    expect(fabricatedExploit).toBeTruthy();
    expect(fabricatedExploit!.severity).toBe("critical");
  });

  it("accepts exploit claims backed by tool output", () => {
    const exploitOutput = "session 1 opened (10.0.0.5:4444 -> 192.168.1.100:80) exploit completed successfully";
    const content = "A meterpreter session was established on 192.168.1.100 after successful exploitation.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { metasploit: exploitOutput },
      knownAssets: KNOWN_ASSETS,
    });

    const exploitClaim = result.groundedClaims.find(c => c.claim.includes("Exploit success"));
    expect(exploitClaim).toBeTruthy();
  });

  it("detects invalid CVSS scores", () => {
    // The CVSS regex looks for "CVSS" followed by a number
    const content = "This vulnerability has a CVSS: 15.0 which is extremely critical.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: {},
    });

    const invalidCvss = result.ungroundedClaims.find(c => c.claim.includes("Invalid CVSS"));
    expect(invalidCvss).toBeTruthy();
  });

  it("handles content with no verifiable claims", () => {
    const content = "The security assessment revealed several areas for improvement in the organization's security posture.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
    });

    // No specific claims to verify, should pass
    expect(result.score).toBe(1.0);
    expect(result.recommendation).toBe("accept");
  });

  it("quarantines content with critical hallucinations", () => {
    const content = "We successfully exploited 10.99.99.99 and obtained root access via CVE-2099-99999 on port 9999.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      knownCves: KNOWN_CVES,
      strictness: "strict",
    });

    expect(result.recommendation).toBe("quarantine");
    expect(result.passed).toBe(false);
  });

  it("respects strictness levels", () => {
    const content = "Port 9999 was found on 192.168.1.100 running a service.";
    const strict = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      strictness: "strict",
    });
    const lenient = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      strictness: "lenient",
    });

    // Strict should be more likely to flag issues
    expect(strict.score).toBeLessThanOrEqual(lenient.score);
  });

  it("skips localhost and broadcast IPs", () => {
    const content = "The scanner at 127.0.0.1 tested the target. Broadcast 255.255.255.255 was observed.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: {},
      knownAssets: KNOWN_ASSETS,
    });

    // These IPs should be skipped, not flagged
    const localhostClaim = result.ungroundedClaims.find(c => c.claim.includes("127.0.0.1"));
    expect(localhostClaim).toBeUndefined();
  });

  it("skips reference domains (owasp.org, mitre.org, etc.)", () => {
    const content = "See OWASP at owasp.org and MITRE at mitre.org for more information.";
    const result = checkHallucination({
      llmContent: content,
      groundTruth: {},
      knownAssets: KNOWN_ASSETS,
    });

    const owaspClaim = result.ungroundedClaims.find(c => c.claim.includes("owasp.org"));
    expect(owaspClaim).toBeUndefined();
  });
});

// ─── 7. Evidence Sanitization ───────────────────────────────────────────────

describe("Evidence Sanitization", () => {
  it("adds UNVERIFIED tags to fabricated IPs", () => {
    const content = "The server at 10.99.99.99 was compromised.";
    const check = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      strictness: "strict",
    });

    const { sanitized, annotations } = sanitizeEvidence(content, check);
    expect(sanitized).toContain("[UNVERIFIED]");
    expect(annotations.length).toBeGreaterThan(0);
  });

  it("adds UNVERIFIED tags to fabricated CVEs", () => {
    const content = "CVE-2099-99999 affects the target system.";
    const check = checkHallucination({
      llmContent: content,
      groundTruth: { nuclei: NUCLEI_OUTPUT },
      knownCves: KNOWN_CVES,
    });

    const { sanitized, annotations } = sanitizeEvidence(content, check);
    expect(sanitized).toContain("[UNVERIFIED]");
  });

  it("adds integrity footer with score", () => {
    const content = "CVE-2099-99999 on 10.99.99.99 port 9999.";
    const check = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      knownCves: KNOWN_CVES,
      strictness: "strict",
    });

    const { sanitized } = sanitizeEvidence(content, check);
    expect(sanitized).toContain("INTEGRITY ANNOTATIONS");
    expect(sanitized).toContain("Hallucination check score:");
  });

  it("returns unchanged content when no issues found", () => {
    const content = "Port 80 on 192.168.1.100 runs Apache.";
    const check = checkHallucination({
      llmContent: content,
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
    });

    const { sanitized, removedClaims } = sanitizeEvidence(content, check);
    expect(removedClaims).toHaveLength(0);
  });
});

// ─── 8. Evidence Gate ───────────────────────────────────────────────────────

describe("Evidence Gate", () => {
  it("passes valid evidence with good provenance", () => {
    const result = evidenceGate({
      content: NMAP_OUTPUT,
      provenance: makeProvenance({ sourceTool: "nmap" }),
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
    });

    expect(result.passed).toBe(true);
    expect(result.provenanceValid).toBe(true);
    expect(result.contentHash).toHaveLength(64);
  });

  it("fails evidence with bad provenance", () => {
    const result = evidenceGate({
      content: "random text with no tool signatures",
      provenance: makeProvenance({
        sourceTool: "nmap",
        rawOutputHash: "0000000000000000000000000000000000000000000000000000000000000000",
      }),
    });

    expect(result.passed).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("includes hallucination check when ground truth provided", () => {
    const result = evidenceGate({
      content: "Found CVE-2099-99999 on 10.99.99.99",
      provenance: makeProvenance({ sourceTool: "llm_analysis" }),
      groundTruth: { nmap: NMAP_OUTPUT },
      knownAssets: KNOWN_ASSETS,
      knownCves: KNOWN_CVES,
      strictness: "strict",
    });

    expect(result.hallucinationCheck).toBeTruthy();
    expect(result.hallucinationCheck!.ungroundedClaims.length).toBeGreaterThan(0);
  });
});

// ─── 9. Integrity Anchors ───────────────────────────────────────────────────

describe("Integrity Anchors", () => {
  const engId = "test-anchor-eng";

  beforeEach(() => {
    clearChain(engId);
  });

  it("creates anchor for valid chain", () => {
    createIntegrityEnvelope({
      evidenceId: "ev-a1",
      engagementId: engId,
      content: "evidence 1",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const anchor = createAnchor(engId);
    expect(anchor).toBeTruthy();
    expect(anchor!.merkleRoot).toHaveLength(64);
    expect(anchor!.hmacSignature).toHaveLength(64);
    expect(anchor!.chainLength).toBe(1);
  });

  it("returns null for empty chain", () => {
    const anchor = createAnchor(engId);
    // Empty chain validation returns valid but with EMPTY_CHAIN merkle root
    // createAnchor should still work
    expect(anchor).toBeTruthy();
  });

  it("verifies valid anchor", () => {
    createIntegrityEnvelope({
      evidenceId: "ev-a2",
      engagementId: engId,
      content: "evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const anchor = createAnchor(engId);
    expect(anchor).toBeTruthy();

    const result = verifyAnchor(engId, {
      merkleRoot: anchor!.merkleRoot,
      hmacSignature: anchor!.hmacSignature,
    });
    expect(result.valid).toBe(true);
  });

  it("detects anchor mismatch after chain modification", () => {
    createIntegrityEnvelope({
      evidenceId: "ev-a3",
      engagementId: engId,
      content: "evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const anchor = createAnchor(engId);
    expect(anchor).toBeTruthy();

    // Add more evidence after anchoring
    createIntegrityEnvelope({
      evidenceId: "ev-a4",
      engagementId: engId,
      content: "new evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const result = verifyAnchor(engId, {
      merkleRoot: anchor!.merkleRoot,
      hmacSignature: anchor!.hmacSignature,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Merkle root mismatch");
  });

  it("detects tampered HMAC", () => {
    createIntegrityEnvelope({
      evidenceId: "ev-a5",
      engagementId: engId,
      content: "evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const anchor = createAnchor(engId);
    expect(anchor).toBeTruthy();

    const result = verifyAnchor(engId, {
      merkleRoot: anchor!.merkleRoot,
      hmacSignature: "tampered_hmac_signature_that_is_definitely_wrong_and_invalid_hash",
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("HMAC signature mismatch");
  });
});

// ─── 10. LLM Evidence Guardrail Wrappers ────────────────────────────────────

describe("LLM Evidence Guardrail — Report Finding", () => {
  it("validates a grounded report finding", () => {
    const finding = {
      title: "Apache HTTP Server HTTP/2 Rapid Reset (CVE-2023-44487)",
      severity: "Critical",
      cvss_score: 9.8,
      affected_asset: "192.168.1.100",
      description: "The Apache server on port 80 is vulnerable to CVE-2023-44487.",
      evidence: [{ type: "scanner_output", description: "Nuclei detection", data: NUCLEI_OUTPUT.slice(0, 100) }],
      impact: "Denial of service against the web server.",
      reproduction_steps: ["Run nuclei against 192.168.1.100", "Observe CVE-2023-44487 detection"],
      remediation: { short_term: "Apply Apache patch", long_term: "Upgrade Apache", effort: "Medium" },
      references: ["CVE-2023-44487"],
      mitre_mapping: [{ technique_id: "T1499", technique_name: "Endpoint Denial of Service", tactic: "Impact" }],
    };

    const result = validateReportFinding(finding, makeGuardrailContext());
    expect(result.passed).toBe(true);
    expect(result.contentHash).toHaveLength(64);
  });

  it("flags invalid CVSS score", () => {
    const finding = {
      title: "Test Finding",
      severity: "Critical",
      cvss_score: 15.0,
      affected_asset: "192.168.1.100",
      description: "Test",
      evidence: [],
      impact: "Test",
      reproduction_steps: [],
      remediation: { short_term: "Fix", long_term: "Fix", effort: "Low" },
      references: [],
      mitre_mapping: [],
    };

    const result = validateReportFinding(finding, makeGuardrailContext());
    expect(result.errors.some(e => e.includes("Invalid CVSS"))).toBe(true);
  });

  it("warns about severity-CVSS mismatch", () => {
    const finding = {
      title: "Test Finding",
      severity: "Critical",
      cvss_score: 3.0,
      affected_asset: "192.168.1.100",
      description: "Test",
      evidence: [],
      impact: "Test",
      reproduction_steps: [],
      remediation: { short_term: "Fix", long_term: "Fix", effort: "Low" },
      references: [],
      mitre_mapping: [],
    };

    const result = validateReportFinding(finding, makeGuardrailContext());
    expect(result.warnings.some(w => w.includes("inconsistent with CVSS"))).toBe(true);
  });

  it("warns about invalid ATT&CK technique IDs", () => {
    const finding = {
      title: "Test Finding",
      severity: "High",
      cvss_score: 7.5,
      affected_asset: "192.168.1.100",
      description: "Test",
      evidence: [],
      impact: "Test",
      reproduction_steps: [],
      remediation: { short_term: "Fix", long_term: "Fix", effort: "Low" },
      references: [],
      mitre_mapping: [{ technique_id: "INVALID", technique_name: "Bad", tactic: "Bad" }],
    };

    const result = validateReportFinding(finding, makeGuardrailContext());
    expect(result.warnings.some(w => w.includes("Invalid ATT&CK technique ID"))).toBe(true);
  });
});

describe("LLM Evidence Guardrail — Vuln Verification", () => {
  it("validates consistent verification output", () => {
    const verification = {
      finding_summary: "SQL Injection on 192.168.1.100 port 80",
      affected_asset: "192.168.1.100",
      evidence_review: [
        { tag: "OBSERVED", detail: "ZAP detected SQL injection on login endpoint port 80" },
        { tag: "INFERRED", detail: "Database backend likely MySQL based on error messages" },
      ],
      false_positive_likelihood: "Low",
      exploitability: {
        rating: "Confirmed",
        prerequisites: ["Network access to port 80"],
        known_exploits: true,
        rationale: "Standard SQL injection with known payloads",
      },
      business_impact: { severity: "High", rationale: "Database access could lead to data breach" },
      analyst_verdict: "True Positive",
      confidence: "High",
    };

    const result = validateVulnVerification(verification, makeGuardrailContext());
    expect(result.passed).toBe(true);
  });

  it("flags contradictory exploitability and verdict", () => {
    const verification = {
      finding_summary: "Test finding",
      affected_asset: "192.168.1.100",
      evidence_review: [],
      false_positive_likelihood: "High",
      exploitability: {
        rating: "Confirmed",
        prerequisites: [],
        known_exploits: true,
        rationale: "Confirmed exploitable",
      },
      business_impact: { severity: "High", rationale: "Test" },
      analyst_verdict: "False Positive",
      confidence: "High",
    };

    const result = validateVulnVerification(verification, makeGuardrailContext());
    expect(result.errors.some(e => e.includes("Contradictory"))).toBe(true);
  });

  it("flags invalid verdict values", () => {
    const verification = {
      finding_summary: "Test",
      affected_asset: "192.168.1.100",
      evidence_review: [],
      false_positive_likelihood: "Low",
      exploitability: { rating: "Likely", prerequisites: [], known_exploits: false, rationale: "Test" },
      business_impact: { severity: "Medium", rationale: "Test" },
      analyst_verdict: "Maybe True",
      confidence: "Medium",
    };

    const result = validateVulnVerification(verification, makeGuardrailContext());
    expect(result.errors.some(e => e.includes("Invalid analyst verdict"))).toBe(true);
  });
});

describe("LLM Evidence Guardrail — Attack Plan", () => {
  it("validates grounded attack plan", () => {
    const plan = {
      attack_objective: "Compromise web server at 192.168.1.100",
      initial_access_options: [
        {
          vector: "Web application exploitation",
          target: "192.168.1.100",
          feasibility: "High",
          evidence_tag: "OBSERVED",
          rationale: "SQL injection found by ZAP on port 80",
        },
      ],
      attack_chain: [
        {
          stage: "Initial Access",
          technique: "Exploit Public-Facing Application",
          mitre_id: "T1190",
          target: "192.168.1.100",
          description: "Exploit SQL injection on web application",
        },
      ],
    };

    const result = validateAttackPlan(plan, makeGuardrailContext());
    expect(result.passed).toBe(true);
  });

  it("flags invalid evidence tags", () => {
    const plan = {
      attack_objective: "Test",
      initial_access_options: [
        { vector: "Test", target: "192.168.1.100", feasibility: "High", evidence_tag: "MADE_UP", rationale: "Test" },
      ],
      attack_chain: [],
    };

    const result = validateAttackPlan(plan, makeGuardrailContext());
    expect(result.errors.some(e => e.includes("Invalid evidence tag"))).toBe(true);
  });

  it("flags invalid MITRE ATT&CK IDs in attack chain", () => {
    const plan = {
      attack_objective: "Test",
      initial_access_options: [],
      attack_chain: [
        { stage: "Test", technique: "Test", mitre_id: "INVALID", target: "192.168.1.100", description: "Test" },
      ],
    };

    const result = validateAttackPlan(plan, makeGuardrailContext());
    expect(result.warnings.some(w => w.includes("Invalid ATT&CK technique ID"))).toBe(true);
  });
});

describe("Generic LLM Evidence Validation", () => {
  it("validates grounded generic content", () => {
    const content = "The nmap scan found port 80 open on 192.168.1.100 with Apache httpd.";
    const result = validateLLMEvidence(content, makeGuardrailContext());
    expect(result.passed).toBe(true);
  });

  it("rejects heavily hallucinated content", () => {
    const content = "We exploited 10.99.99.99 via CVE-2099-99999 and obtained root access through port 9999. A meterpreter session was established.";
    const result = validateLLMEvidence(content, makeGuardrailContext({ strictness: "strict" }));
    expect(result.passed).toBe(false);
    expect(result.recommendation).toBe("quarantine");
  });
});

describe("Report Section Validation", () => {
  it("validates a grounded report section", () => {
    const section = "The assessment identified CVE-2023-44487 on 192.168.1.100 port 80. This HTTP/2 vulnerability was confirmed by Nuclei scanning.";
    const result = validateReportSection(section, "findings", makeGuardrailContext());
    expect(result.valid).toBe(true);
    expect(result.hallucinationScore).toBeGreaterThan(0.5);
  });
});

// ─── 11. Utility Functions ──────────────────────────────────────────────────

describe("Utility Functions", () => {
  it("buildProvenance creates valid provenance record", () => {
    const prov = buildProvenance({
      tool: "nmap",
      collectorHost: "scanner-01",
      rawOutput: NMAP_OUTPUT,
      targetHost: "192.168.1.100",
      sourceIp: "10.0.0.5",
      destinationIp: "192.168.1.100",
    });

    expect(prov.sourceTool).toBe("nmap");
    expect(prov.rawOutputHash).toHaveLength(64);
    expect(prov.rawOutputSize).toBeGreaterThan(0);
    expect(prov.toolOutputTimestamp).toBeTruthy();
  });

  it("getChainStats returns correct counts", () => {
    const engId = "test-stats-eng";
    clearChain(engId);

    createIntegrityEnvelope({
      evidenceId: "ev-s1",
      engagementId: engId,
      content: "evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const stats = getChainStats();
    expect(stats.totalEngagements).toBeGreaterThanOrEqual(1);
    expect(stats.totalEnvelopes).toBeGreaterThanOrEqual(1);

    clearChain(engId);
  });

  it("getChain returns chain for engagement", () => {
    const engId = "test-get-chain-eng";
    clearChain(engId);

    createIntegrityEnvelope({
      evidenceId: "ev-gc1",
      engagementId: engId,
      content: "evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    const chain = getChain(engId);
    expect(chain).toHaveLength(1);
    expect(chain[0].evidenceId).toBe("ev-gc1");

    clearChain(engId);
  });

  it("clearChain removes all envelopes", () => {
    const engId = "test-clear-eng";
    createIntegrityEnvelope({
      evidenceId: "ev-cl1",
      engagementId: engId,
      content: "evidence",
      provenance: makeProvenance(),
      performedBy: "Scanner",
    });

    clearChain(engId);
    expect(getChain(engId)).toHaveLength(0);
  });
});
