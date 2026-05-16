import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/evidence-integrity-guardrails.ts
import * as crypto from "crypto";
function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}
function computeChainHash(contentHash, previousChainHash, timestamp, provenanceHash) {
  const payload = `${contentHash}|${previousChainHash || "GENESIS"}|${timestamp}|${provenanceHash}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}
function computeAnchorHMAC(merkleRoot, engagementId) {
  const secret = process.env.JWT_SECRET || "evidence-integrity-default-key";
  return crypto.createHmac("sha256", secret).update(`${merkleRoot}|${engagementId}`).digest("hex");
}
function computeMerkleRoot(chainHashes) {
  if (chainHashes.length === 0) return sha256("EMPTY_CHAIN");
  if (chainHashes.length === 1) return chainHashes[0];
  let layer = [...chainHashes];
  while (layer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      nextLayer.push(sha256(left + right));
    }
    layer = nextLayer;
  }
  return layer[0];
}
function hashProvenance(provenance) {
  const canonical = JSON.stringify({
    sourceTool: provenance.sourceTool,
    collectorHost: provenance.collectorHost,
    toolOutputTimestamp: provenance.toolOutputTimestamp,
    rawOutputHash: provenance.rawOutputHash,
    targetHost: provenance.targetHost,
    sourceIp: provenance.sourceIp,
    destinationIp: provenance.destinationIp
  });
  return sha256(canonical);
}
function isValidTransition(currentState, nextAction) {
  const allowed = VALID_TRANSITIONS[currentState] || [];
  return allowed.includes(nextAction);
}
function getAllowedTransitions(currentState) {
  return VALID_TRANSITIONS[currentState] || [];
}
function createIntegrityEnvelope(params) {
  const contentHash = sha256(params.content);
  const provenanceHash = hashProvenance(params.provenance);
  const timestamp = Date.now();
  const chain = chainStore.get(params.engagementId) || [];
  const previousChainHash = chain.length > 0 ? chain[chain.length - 1].chainHash : null;
  const chainHash = computeChainHash(contentHash, previousChainHash, timestamp, provenanceHash);
  const custodyEvent = {
    action: "created",
    performedBy: params.performedBy,
    timestamp,
    integrityHash: chainHash,
    details: `Evidence created: ${params.provenance.sourceTool} output from ${params.provenance.targetHost}`,
    ipAddress: params.ipAddress
  };
  const envelope = {
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
    verificationStatus: "unverified"
  };
  chain.push(envelope);
  chainStore.set(params.engagementId, chain);
  return envelope;
}
function recordCustodyEvent(envelope, action, performedBy, details, ipAddress) {
  if (!isValidTransition(envelope.currentState, action)) {
    return {
      success: false,
      error: `Invalid transition: ${envelope.currentState} \u2192 ${action}. Allowed: ${getAllowedTransitions(envelope.currentState).join(", ")}`
    };
  }
  const event = {
    action,
    performedBy,
    timestamp: Date.now(),
    integrityHash: sha256(`${envelope.chainHash}|${action}|${Date.now()}`),
    details,
    ipAddress
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
function verifyEvidenceIntegrity(envelope, content) {
  const currentHash = sha256(content);
  if (currentHash !== envelope.contentHash) {
    envelope.verificationStatus = "tampered";
    return {
      valid: false,
      error: `Content hash mismatch: expected ${envelope.contentHash}, got ${currentHash}. Evidence may have been tampered with.`
    };
  }
  envelope.lastVerifiedAt = Date.now();
  envelope.verificationStatus = "verified";
  return { valid: true };
}
function validateChain(engagementId) {
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
      lastVerified: Date.now()
    };
  }
  const errors = [];
  let validLinks = 0;
  const chainHashes = [];
  for (let i = 0; i < chain.length; i++) {
    const envelope = chain[i];
    const prevEnvelope = i > 0 ? chain[i - 1] : null;
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
        lastVerified: Date.now()
      };
    }
    const provenanceHash = hashProvenance(envelope.provenance);
    const expectedChainHash = computeChainHash(
      envelope.contentHash,
      envelope.previousChainHash,
      envelope.createdAt,
      provenanceHash
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
        lastVerified: Date.now()
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
    lastVerified: Date.now()
  };
}
function validateProvenance(content, provenance) {
  const errors = [];
  const warnings = [];
  const sig = TOOL_SIGNATURES[provenance.sourceTool];
  if (!sig) {
    errors.push(`Unknown source tool: ${provenance.sourceTool}`);
    return { valid: false, errors, warnings, toolSignatureMatch: false, timestampConsistent: false, networkContextValid: false, contentFormatValid: false };
  }
  let toolSignatureMatch = true;
  if (sig.patterns.length > 0) {
    const matchCount = sig.patterns.filter((p) => p.test(content)).length;
    const matchRatio = matchCount / sig.patterns.length;
    if (matchRatio === 0) {
      errors.push(`No ${provenance.sourceTool} output signatures found in content. Evidence may not be from claimed source.`);
      toolSignatureMatch = false;
    } else if (matchRatio < 0.3) {
      warnings.push(`Only ${Math.round(matchRatio * 100)}% of ${provenance.sourceTool} signatures matched. Evidence may be incomplete or modified.`);
      toolSignatureMatch = false;
    }
  }
  let timestampConsistent = true;
  const toolTs = new Date(provenance.toolOutputTimestamp).getTime();
  const now = Date.now();
  if (isNaN(toolTs)) {
    errors.push("Invalid tool output timestamp");
    timestampConsistent = false;
  } else if (toolTs > now + 6e4) {
    errors.push(`Tool output timestamp is in the future: ${provenance.toolOutputTimestamp}`);
    timestampConsistent = false;
  } else if (now - toolTs > 365 * 24 * 60 * 60 * 1e3) {
    warnings.push("Tool output timestamp is more than 1 year old");
  }
  let networkContextValid = true;
  if (!provenance.sourceIp || provenance.sourceIp === "unknown") {
    warnings.push("Source IP is unknown \u2014 network provenance incomplete");
    networkContextValid = false;
  }
  if (!provenance.destinationIp || provenance.destinationIp === "unknown") {
    warnings.push("Destination IP is unknown \u2014 network provenance incomplete");
    networkContextValid = false;
  }
  let contentFormatValid = true;
  if (content.length === 0) {
    errors.push("Evidence content is empty");
    contentFormatValid = false;
  }
  const actualHash = sha256(content);
  if (provenance.rawOutputHash && provenance.rawOutputHash !== actualHash) {
    errors.push(`Raw output hash mismatch: provenance says ${provenance.rawOutputHash}, actual is ${actualHash}`);
    contentFormatValid = false;
  }
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
    contentFormatValid
  };
}
function checkHallucination(params) {
  const {
    llmContent,
    groundTruth,
    knownAssets = [],
    knownCves = [],
    knownServices = [],
    strictness = "moderate"
  } = params;
  const groundedClaims = [];
  const ungroundedClaims = [];
  const warnings = [];
  const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const mentionedIps = /* @__PURE__ */ new Set();
  let match;
  while ((match = ipPattern.exec(llmContent)) !== null) {
    mentionedIps.add(match[1]);
  }
  const knownIps = new Set(knownAssets.map((a) => a.ip).filter(Boolean));
  for (const output of Object.values(groundTruth)) {
    let m;
    const ipRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    while ((m = ipRe.exec(output)) !== null) {
      knownIps.add(m[1]);
    }
  }
  for (const ip of mentionedIps) {
    if (ip.startsWith("127.") || ip.startsWith("0.") || ip === "255.255.255.255") continue;
    if (knownIps.has(ip)) {
      groundedClaims.push({
        claim: `IP address ${ip}`,
        groundTruthSource: "engagement_assets / tool_output",
        confidence: 1
      });
    } else {
      ungroundedClaims.push({
        claim: `IP address ${ip} mentioned but not found in any ground truth source`,
        reason: "IP not observed in scan data, engagement assets, or tool output",
        severity: strictness === "strict" ? "high" : "medium"
      });
    }
  }
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const mentionedCves = /* @__PURE__ */ new Set();
  while ((match = cvePattern.exec(llmContent)) !== null) {
    mentionedCves.add(match[0].toUpperCase());
  }
  const knownCveSet = new Set(knownCves.map((c) => c.toUpperCase()));
  for (const output of Object.values(groundTruth)) {
    let m;
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
        confidence: 1
      });
    } else {
      ungroundedClaims.push({
        claim: `CVE ${cve} referenced but not found in scan results`,
        reason: "CVE not discovered by any scanning tool in this engagement",
        severity: "high"
      });
    }
  }
  const portPattern = /\bport\s*(\d{1,5})\b/gi;
  const mentionedPorts = /* @__PURE__ */ new Set();
  while ((match = portPattern.exec(llmContent)) !== null) {
    const port = parseInt(match[1], 10);
    if (port > 0 && port <= 65535) mentionedPorts.add(port);
  }
  const portSlashPattern = /\b(\d{1,5})\/(tcp|udp)\b/gi;
  while ((match = portSlashPattern.exec(llmContent)) !== null) {
    const port = parseInt(match[1], 10);
    if (port > 0 && port <= 65535) mentionedPorts.add(port);
  }
  const knownPorts = /* @__PURE__ */ new Set([
    ...knownAssets.flatMap((a) => a.ports || []),
    ...knownServices.map((s) => s.port)
  ]);
  for (const [tool, output] of Object.entries(groundTruth)) {
    if (tool === "scanforge-discovery" || tool.includes("scanforge-discovery")) {
      let m;
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
        confidence: 1
      });
    } else {
      const commonPorts = [80, 443, 22, 21, 25, 53, 8080, 8443, 3306, 5432, 27017, 6379];
      if (commonPorts.includes(port)) {
        warnings.push(`Port ${port} mentioned but not confirmed in scan data (common port, may be assumed)`);
      } else {
        ungroundedClaims.push({
          claim: `Port ${port} referenced but not found in scan results`,
          reason: "Port not discovered during enumeration phase",
          severity: "medium"
        });
      }
    }
  }
  const hostnamePattern = /\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
  const mentionedHostnames = /* @__PURE__ */ new Set();
  while ((match = hostnamePattern.exec(llmContent)) !== null) {
    const hostname = match[0].toLowerCase();
    if (hostname.endsWith(".example.com") || hostname.endsWith(".test") || hostname.endsWith(".local")) continue;
    if (hostname.includes("owasp.org") || hostname.includes("mitre.org") || hostname.includes("nist.gov")) continue;
    if (hostname.includes("cve.org") || hostname.includes("nvd.nist.gov") || hostname.includes("github.com")) continue;
    mentionedHostnames.add(hostname);
  }
  const knownHostnames = new Set(knownAssets.map((a) => a.hostname.toLowerCase()));
  for (const output of Object.values(groundTruth)) {
    let m;
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
        confidence: 1
      });
    } else {
      ungroundedClaims.push({
        claim: `Hostname ${hostname} mentioned but not in scope or scan data`,
        reason: "Hostname not found in engagement assets or tool output",
        severity: strictness === "strict" ? "high" : "low"
      });
    }
  }
  const exploitPatterns = [
    /successfully\s+exploit/i,
    /remote\s+code\s+execution\s+(confirmed|achieved|verified)/i,
    /shell\s+(obtained|established|gained)/i,
    /session\s+\d+\s+opened/i,
    /meterpreter\s+session/i,
    /root\s+access\s+(obtained|gained|confirmed)/i,
    /privilege\s+escalation\s+(successful|confirmed)/i
  ];
  for (const pattern of exploitPatterns) {
    if (pattern.test(llmContent)) {
      const hasExploitEvidence = Object.values(groundTruth).some(
        (output) => pattern.test(output) || /session.*opened/i.test(output) || /exploit.*completed/i.test(output) || /SUCCESS/i.test(output)
      );
      if (hasExploitEvidence) {
        groundedClaims.push({
          claim: `Exploit success claim matching: ${pattern.source}`,
          groundTruthSource: "tool_output",
          confidence: 0.9
        });
      } else {
        ungroundedClaims.push({
          claim: `Exploit success claimed ("${llmContent.match(pattern)?.[0]}") but no supporting tool output found`,
          reason: "No tool output confirms successful exploitation. This may be a hallucinated exploit result.",
          severity: "critical"
        });
      }
    }
  }
  const cvssPattern = /CVSS[:\s]*(\d+\.?\d*)/gi;
  while ((match = cvssPattern.exec(llmContent)) !== null) {
    const score2 = parseFloat(match[1]);
    if (score2 < 0 || score2 > 10) {
      ungroundedClaims.push({
        claim: `Invalid CVSS score: ${score2}`,
        reason: "CVSS scores must be between 0.0 and 10.0",
        severity: "high"
      });
    }
  }
  const totalClaims = groundedClaims.length + ungroundedClaims.length;
  const score = totalClaims === 0 ? 1 : groundedClaims.length / totalClaims;
  const criticalUngrounded = ungroundedClaims.filter((c) => c.severity === "critical").length;
  const highUngrounded = ungroundedClaims.filter((c) => c.severity === "high").length;
  let recommendation;
  if (criticalUngrounded > 0) {
    recommendation = "quarantine";
  } else if (highUngrounded > 2 || score < 0.5) {
    recommendation = "reject";
  } else if (highUngrounded > 0 || score < 0.8) {
    recommendation = "review";
  } else {
    recommendation = "accept";
  }
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
    recommendation
  };
}
function sanitizeEvidence(content, checkResult) {
  let sanitized = content;
  const removedClaims = [];
  const annotations = [];
  for (const claim of checkResult.ungroundedClaims) {
    if (claim.severity === "critical" || claim.severity === "high") {
      const ipMatch = claim.claim.match(/IP address (\S+)/);
      if (ipMatch) {
        sanitized = sanitized.replace(
          new RegExp(`\\b${escapeRegex(ipMatch[1])}\\b`, "g"),
          `${ipMatch[1]} [UNVERIFIED]`
        );
        annotations.push(`IP ${ipMatch[1]} not found in ground truth \u2014 marked as UNVERIFIED`);
      }
      const cveMatch = claim.claim.match(/(CVE-\d{4}-\d+)/);
      if (cveMatch) {
        sanitized = sanitized.replace(
          new RegExp(escapeRegex(cveMatch[1]), "gi"),
          `${cveMatch[1]} [UNVERIFIED]`
        );
        annotations.push(`${cveMatch[1]} not found in scan results \u2014 marked as UNVERIFIED`);
      }
      if (claim.claim.includes("Exploit success")) {
        annotations.push(`WARNING: Exploit success claim not supported by tool output \u2014 requires manual verification`);
      }
      removedClaims.push(claim.claim);
    }
  }
  if (annotations.length > 0) {
    sanitized += `

--- INTEGRITY ANNOTATIONS ---
`;
    for (const ann of annotations) {
      sanitized += `\u26A0 ${ann}
`;
    }
    sanitized += `
Hallucination check score: ${(checkResult.score * 100).toFixed(1)}% grounded
`;
    sanitized += `Recommendation: ${checkResult.recommendation.toUpperCase()}
`;
  }
  return { sanitized, removedClaims, annotations };
}
function getChain(engagementId) {
  return chainStore.get(engagementId) || [];
}
function getEnvelope(engagementId, evidenceId) {
  const chain = chainStore.get(engagementId) || [];
  return chain.find((e) => e.evidenceId === evidenceId) || null;
}
function createAnchor(engagementId) {
  const validation = validateChain(engagementId);
  if (!validation.valid || !validation.merkleRoot) return null;
  return {
    merkleRoot: validation.merkleRoot,
    hmacSignature: computeAnchorHMAC(validation.merkleRoot, engagementId),
    chainLength: validation.totalLinks,
    anchoredAt: Date.now()
  };
}
function verifyAnchor(engagementId, anchor) {
  const validation = validateChain(engagementId);
  if (!validation.valid) {
    return { valid: false, error: `Chain is broken: ${validation.errors.join("; ")}` };
  }
  if (validation.merkleRoot !== anchor.merkleRoot) {
    return { valid: false, error: "Merkle root mismatch \u2014 chain has been modified since anchor was created" };
  }
  const expectedHmac = computeAnchorHMAC(anchor.merkleRoot, engagementId);
  if (expectedHmac !== anchor.hmacSignature) {
    return { valid: false, error: "HMAC signature mismatch \u2014 anchor may have been tampered with" };
  }
  return { valid: true };
}
function mapProvenanceToEvidenceType(provenance) {
  if (!provenance) return "tool_output";
  const tool = provenance.sourceTool?.toLowerCase() || "";
  if (tool.includes("zap") || tool.includes("burp")) return "http_capture";
  if (tool.includes("naabu") || tool.includes("masscan") || tool.includes("nerva")) return "scan_output";
  if (tool.includes("nuclei") || tool.includes("nikto")) return "scan_output";
  if (tool.includes("sqlmap") || tool.includes("hydra")) return "exploit_output";
  if (tool.includes("metasploit")) return "exploit_output";
  if (tool.includes("screenshot")) return "screenshot";
  return "tool_output";
}
async function flushChainToDb(engagementId) {
  const chain = chainStore.get(engagementId) || [];
  if (chain.length === 0) return { flushed: 0, errors: [] };
  const errors = [];
  let flushed = 0;
  try {
    const { getDb } = await import("./db-LSUZDHGJ.js");
    const { evidenceItems, evidenceChainOfCustody } = await import("./schema-RDUWS2ES.js");
    const db = await getDb();
    if (!db) {
      errors.push("Database unavailable");
      return { flushed, errors };
    }
    const { eq } = await import("drizzle-orm");
    for (const envelope of chain) {
      try {
        const existing = await db.select({ id: evidenceItems.id }).from(evidenceItems).where(eq(evidenceItems.evidenceId, envelope.evidenceId)).limit(1);
        if (existing.length === 0) {
          await db.insert(evidenceItems).values({
            evidenceId: envelope.evidenceId,
            engagementId: envelope.engagementId,
            title: `Evidence: ${envelope.provenance?.sourceTool || "unknown"} \u2014 ${envelope.provenance?.targetHost || "unknown"}`,
            description: envelope.custodyTrail?.[0]?.details || "Auto-created from integrity chain",
            type: mapProvenanceToEvidenceType(envelope.provenance),
            category: envelope.provenance?.sourceTool || "general",
            sha256Hash: envelope.contentHash,
            collectedBy: envelope.custodyTrail?.[0]?.performedBy || "system",
            collectedAt: new Date(envelope.createdAt).toISOString().slice(0, 19).replace("T", " "),
            tags: JSON.stringify([
              envelope.provenance?.sourceTool,
              envelope.provenance?.targetHost,
              envelope.verificationStatus
            ].filter(Boolean)),
            metadata: JSON.stringify({
              contentHash: envelope.contentHash,
              chainHash: envelope.chainHash,
              provenance: envelope.provenance,
              verificationStatus: envelope.verificationStatus
            }),
            classification: "confidential"
          });
        }
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
              eventDetails: event.details
            }),
            integrityHash: event.integrityHash,
            previousHash: envelope.previousChainHash,
            ipAddress: event.ipAddress
          });
        }
        flushed++;
      } catch (err) {
        errors.push(`Failed to flush ${envelope.evidenceId}: ${err.message}`);
      }
    }
  } catch (err) {
    errors.push(`DB connection error: ${err.message}`);
  }
  return { flushed, errors };
}
function clearChain(engagementId) {
  chainStore.delete(engagementId);
}
function getChainStats() {
  const byEngagement = [];
  let totalEnvelopes = 0;
  for (const [engagementId, chain] of chainStore.entries()) {
    totalEnvelopes += chain.length;
    byEngagement.push({
      engagementId,
      count: chain.length,
      lastAction: chain.length > 0 ? chain[chain.length - 1].currentState : "created"
    });
  }
  return {
    totalEngagements: chainStore.size,
    totalEnvelopes,
    byEngagement
  };
}
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function buildProvenance(params) {
  return {
    sourceTool: params.tool,
    toolVersion: params.toolVersion,
    sourceCommand: params.command,
    collectorHost: params.collectorHost,
    toolOutputTimestamp: (/* @__PURE__ */ new Date()).toISOString(),
    rawOutputHash: sha256(params.rawOutput),
    rawOutputSize: Buffer.byteLength(params.rawOutput, "utf-8"),
    targetHost: params.targetHost,
    targetPort: params.targetPort,
    sourceIp: params.sourceIp,
    destinationIp: params.destinationIp
  };
}
function evidenceGate(params) {
  const errors = [];
  const warnings = [];
  const contentHash = sha256(params.content);
  const provenanceResult = validateProvenance(params.content, params.provenance);
  errors.push(...provenanceResult.errors);
  warnings.push(...provenanceResult.warnings);
  let hallucinationCheck = null;
  if (params.groundTruth && (params.provenance.sourceTool === "llm_analysis" || Object.keys(params.groundTruth).length > 0)) {
    hallucinationCheck = checkHallucination({
      llmContent: params.content,
      groundTruth: params.groundTruth,
      knownAssets: params.knownAssets,
      knownCves: params.knownCves,
      strictness: params.strictness
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
    warnings
  };
}
var VALID_TRANSITIONS, chainStore, TOOL_SIGNATURES;
var init_evidence_integrity_guardrails = __esm({
  "server/lib/evidence-integrity-guardrails.ts"() {
    VALID_TRANSITIONS = {
      "": ["created", "captured"],
      // genesis
      created: ["hashed", "validated", "quarantined"],
      captured: ["hashed", "validated", "quarantined"],
      hashed: ["validated", "exported", "accessed", "quarantined"],
      validated: ["exported", "accessed", "archived", "quarantined"],
      exported: ["accessed", "archived"],
      accessed: ["exported", "accessed", "archived"],
      archived: ["accessed", "deleted"],
      quarantined: ["released", "deleted"],
      released: ["validated", "exported"]
    };
    chainStore = /* @__PURE__ */ new Map();
    TOOL_SIGNATURES = {
      "scanforge-discovery": {
        patterns: [
          /ScanForge scan report for/i,
          /\d+\/tcp\s+(open|closed|filtered)/,
          /PORT\s+STATE\s+SERVICE/i,
          /Starting ScanForge/i,
          /Host is up/i
        ],
        requiredFields: ["host", "ports"],
        outputFormats: ["text", "xml", "json"]
      },
      nuclei: {
        patterns: [
          /\[INF\]|^\[.*\]\s+\[.*\]\s+\[.*\]/m,
          /nuclei/i,
          /\[critical\]|\[high\]|\[medium\]|\[low\]|\[info\]/i,
          /template-id|matched-at|type:/i
        ],
        requiredFields: ["template", "matched-at"],
        outputFormats: ["text", "json", "jsonl"]
      },
      zap: {
        patterns: [
          /ZAP|OWASP/i,
          /alert|risk|confidence/i,
          /pluginid|cweid|wascid/i
        ],
        requiredFields: ["alert", "risk"],
        outputFormats: ["json", "xml", "html"]
      },
      nikto: {
        patterns: [
          /Nikto/i,
          /\+ Target IP:/i,
          /\+ Server:/i,
          /OSVDB-/
        ],
        requiredFields: ["target"],
        outputFormats: ["text", "json", "xml"]
      },
      httpx: {
        patterns: [
          /status.code|content.length|title/i,
          /\d{3}\s+\w+/
        ],
        requiredFields: ["url"],
        outputFormats: ["text", "json"]
      },
      gobuster: {
        patterns: [
          /Gobuster/i,
          /Status:\s*\d{3}/,
          /Found:/i
        ],
        requiredFields: ["url"],
        outputFormats: ["text"]
      },
      ffuf: {
        patterns: [
          /ffuf|FUZZ/i,
          /Status:\s*\d{3}/
        ],
        requiredFields: ["url"],
        outputFormats: ["text", "json"]
      },
      testssl: {
        patterns: [
          /testssl|Testing protocols|Testing cipher/i,
          /TLS|SSL/i
        ],
        requiredFields: ["host"],
        outputFormats: ["text", "json"]
      },
      hydra: {
        patterns: [
          /Hydra/i,
          /\[DATA\]|\[ATTEMPT\]|\[\d+\]\[/,
          /login:|password:/i
        ],
        requiredFields: ["host", "service"],
        outputFormats: ["text"]
      },
      caldera: {
        patterns: [
          /paw|ability|operation|adversary/i,
          /technique_id|tactic/i
        ],
        requiredFields: ["operation"],
        outputFormats: ["json"]
      },
      metasploit: {
        patterns: [
          /msf|meterpreter|exploit|payload/i,
          /session\s+\d+\s+opened/i,
          /RHOSTS|RPORT|LHOST/i
        ],
        requiredFields: ["module"],
        outputFormats: ["text"]
      },
      manual: {
        patterns: [],
        // Manual evidence has no automatic signature
        requiredFields: [],
        outputFormats: ["text", "json", "html", "png", "pdf"]
      },
      llm_analysis: {
        patterns: [
          /\[OBSERVED\]|\[INFERRED\]|\[HYPOTHESIS\]/
        ],
        requiredFields: [],
        outputFormats: ["json", "text"]
      },
      system: {
        patterns: [],
        requiredFields: [],
        outputFormats: ["json", "text"]
      }
    };
  }
});

export {
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
  getChain,
  getEnvelope,
  createAnchor,
  verifyAnchor,
  flushChainToDb,
  clearChain,
  getChainStats,
  buildProvenance,
  evidenceGate,
  init_evidence_integrity_guardrails
};
