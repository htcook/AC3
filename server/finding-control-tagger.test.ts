import { describe, it, expect } from "vitest";
import {
  mapSeverity,
  mapFindingType,
  deriveControlIds,
  buildFindingPayload,
  buildEvidencePayload,
} from "./lib/finding-control-tagger";

describe("severity mapping (AC3 → SDR)", () => {
  it("collapses critical/high → high", () => {
    expect(mapSeverity("critical")).toBe("high");
    expect(mapSeverity("high")).toBe("high");
  });
  it("maps medium → moderate", () => {
    expect(mapSeverity("medium")).toBe("moderate");
  });
  it("maps low/info/unknown → low", () => {
    expect(mapSeverity("low")).toBe("low");
    expect(mapSeverity("info")).toBe("low");
    expect(mapSeverity(null)).toBe("low");
    expect(mapSeverity(undefined)).toBe("low");
  });
});

describe("finding type", () => {
  it("confirmed → condition, else coverage", () => {
    expect(mapFindingType("confirmed")).toBe("condition");
    expect(mapFindingType("corroborated")).toBe("coverage");
    expect(mapFindingType("unverified")).toBe("coverage");
    expect(mapFindingType(null)).toBe("coverage");
  });
});

describe("control tagging", () => {
  it("tags a known CWE with NIST controls", () => {
    const { controlIds, untaggedReason } = deriveControlIds({ cwe: "CWE-89" }); // SQL injection
    expect(controlIds.length).toBeGreaterThan(0);
    expect(untaggedReason).toBeUndefined();
  });

  it("maps OWASP A06 to RA-5 and SI-2", () => {
    const { controlIds } = deriveControlIds({ owaspCategory: "A06:2021" });
    expect(controlIds).toContain("RA-5");
    expect(controlIds).toContain("SI-2");
  });

  it("dedupes and sorts across signals", () => {
    const { controlIds } = deriveControlIds({ owaspCategory: "A06", mitreTechnique: "T1190" });
    const sorted = [...controlIds].sort();
    expect(controlIds).toEqual(sorted);
    expect(new Set(controlIds).size).toBe(controlIds.length);
  });

  it("returns an untagged_reason when there are no signals", () => {
    const { controlIds, untaggedReason } = deriveControlIds({});
    expect(controlIds).toEqual([]);
    expect(untaggedReason).toMatch(/no CWE, MITRE technique, or OWASP category/);
  });

  it("returns an untagged_reason when signals have no mapping", () => {
    const { controlIds, untaggedReason } = deriveControlIds({ cwe: "CWE-9999999" });
    expect(controlIds).toEqual([]);
    expect(untaggedReason).toMatch(/no NIST mapping for/);
  });
});

describe("payload builders", () => {
  const finding = {
    id: 88123,
    title: "Outdated OpenSSL",
    description: "1.0.2 on api.host",
    severity: "critical",
    corroborationTier: "confirmed",
    cve: "CVE-2021-3711",
    cwe: "CWE-327",
    mitreTechnique: null,
    owaspCategory: "A02:2021",
    tool: "nuclei",
    source: "ac3-scan",
    createdAt: 1721476800000, // epoch ms
  };

  it("builds a stable, control-tagged finding payload", () => {
    const p = buildFindingPayload(finding, 1042);
    expect(p.source_finding_id).toBe("ac3:eng:1042:finding:88123");
    expect(p.severity).toBe("high");
    expect(p.finding_type).toBe("condition");
    expect(p.gap_statement).toBe("Outdated OpenSSL — 1.0.2 on api.host");
    expect(p.control_ids.length).toBeGreaterThan(0); // CWE-327 + OWASP A02
    expect(p.detected_at).toBe(new Date(1721476800000).toISOString());
    expect(p).not.toHaveProperty("untagged_reason");
  });

  it("is idempotent — same finding yields the same id", () => {
    expect(buildFindingPayload(finding, 1042).source_finding_id).toBe(
      buildFindingPayload(finding, 1042).source_finding_id
    );
  });

  it("normalizes evidence provenance hashes and keeps KSI control id", () => {
    const p = buildEvidencePayload({
      evidenceId: "EVD-3c81",
      ksiId: "KSI-CNA-EIS",
      title: "nuclei-scan.json",
      description: "authenticated scan",
      sourceModule: "nuclei-runner",
      sourceId: "org/x/evidence/1",
      collectionMethod: "automated",
      integrityHash: "9a1f",
      previousHash: "47bd",
      hashAlgorithm: "SHA-256",
      createdAt: "2026-07-20T12:03:00.000Z",
    });
    expect(p.source_evidence_id).toBe("EVD-3c81");
    expect(p.control_ids).toEqual(["KSI-CNA-EIS"]);
    expect(p.provenance.integrity_hash).toBe("sha256:9a1f");
    expect(p.provenance.previous_hash).toBe("sha256:47bd");
    expect(p.provenance.source_module).toBe("nuclei-runner");
  });
});
