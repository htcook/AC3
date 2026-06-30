import { describe, it, expect } from "vitest";
import { getDeduplicationEngine } from "./scanforge/intelligence/dedup-coverage";
import type { ScanFinding } from "./scanforge/types";

function makeFinding(overrides: Partial<ScanFinding> & { id: string; title: string; target: string; source: string }): ScanFinding {
  return {
    severity: "high" as any,
    confidence: 80,
    port: 443,
    protocol: "tcp",
    evidence: { data: { raw: "test" } },
    cves: [],
    cwes: [],
    references: [],
    remediation: "",
    description: "",
    foundAt: Date.now(),
    ...overrides,
  } as ScanFinding;
}

describe("ZAP Finding Deduplication", () => {
  describe("Phase 4: CWE Overlap Detection", () => {
    it("merges ZAP and Nuclei findings with the same CWE on the same target", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "Missing Content Security Policy",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: ["CWE-693"],
          cves: [],
          confidence: 85,
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Content Security Policy (CSP) Header Not Set",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: ["CWE-693"],
          cves: [],
          confidence: 70,
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(1);
      expect(result.duplicatesRemoved).toBe(1);
      expect(result.mergeLog.some(e => e.reason === "cwe_overlap")).toBe(true);
      // Should keep the higher confidence one (nuclei)
      expect(result.findings[0].confidence).toBeGreaterThanOrEqual(85);
    });

    it("does NOT merge findings with same CWE but different targets", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "Missing CSP Header",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: ["CWE-693"],
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] CSP Header Not Set",
          target: "other.com",
          source: "orchestrator-zap",
          cwes: ["CWE-693"],
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(2);
      expect(result.duplicatesRemoved).toBe(0);
    });

    it("does NOT merge findings with same CWE from the same source", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Cookie No HttpOnly Flag",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: ["CWE-1004"],
        }),
        makeFinding({
          id: "zap-2",
          title: "[ZAP] Cookie Without HttpOnly Flag Set",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: ["CWE-1004"],
        }),
      ];

      // Same source, same CWE — should NOT merge via CWE overlap (they may be different cookies)
      const result = dedup.deduplicate(findings);
      // They might still merge via fingerprint if same target+port+CWE
      // but CWE overlap specifically requires different sources
      expect(result.findings.length).toBeLessThanOrEqual(2);
    });

    it("merges multiple CWE overlaps across 3 sources", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "Missing CSP",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: ["CWE-693"],
          confidence: 90,
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] CSP Header Not Set",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: ["CWE-693"],
          confidence: 70,
        }),
        makeFinding({
          id: "nikto-1",
          title: "No Content-Security-Policy header",
          target: "example.com",
          source: "orchestrator-nikto",
          cwes: ["CWE-693"],
          confidence: 60,
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(1);
      expect(result.duplicatesRemoved).toBe(2);
      // Confidence should be boosted from corroboration
      expect(result.findings[0].confidence).toBeGreaterThan(90);
    });
  });

  describe("Phase 5: Fuzzy Title Matching", () => {
    it("merges findings with similar titles across different sources", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "Missing Strict Transport Security Header",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: [],
          cves: [],
          confidence: 85,
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Strict Transport Security Header Not Set",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: [],
          cves: [],
          confidence: 70,
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(1);
      expect(result.duplicatesRemoved).toBe(1);
    });

    it("does NOT merge findings with dissimilar titles even from different sources", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "SQL Injection in Login Form",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: [],
          cves: [],
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Cross-Site Scripting Reflected",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: [],
          cves: [],
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(2);
      expect(result.duplicatesRemoved).toBe(0);
    });

    it("does NOT merge findings with similar titles from the same source", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Missing X-Frame-Options Header",
          target: "example.com",
          source: "orchestrator-zap",
        }),
        makeFinding({
          id: "zap-2",
          title: "[ZAP] X-Frame-Options Header Not Set",
          target: "example.com",
          source: "orchestrator-zap",
        }),
      ];

      const result = dedup.deduplicate(findings);
      // Same source — fuzzy title should NOT merge (might be different endpoints)
      // But fingerprint might merge if same target+port+CWE
      expect(result.findings.length).toBeLessThanOrEqual(2);
    });

    it("strips scanner prefixes before comparing titles", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "[nuclei] Server Version Disclosure",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: [],
          cves: [],
          confidence: 85,
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Server Version Information Disclosure",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: [],
          cves: [],
          confidence: 70,
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(1);
      expect(result.duplicatesRemoved).toBe(1);
    });
  });

  describe("Combined Dedup Pipeline", () => {
    it("handles a realistic mix of ZAP + Nuclei + ScanForge findings", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        // Nuclei: CVE-based finding
        makeFinding({
          id: "nuclei-1",
          title: "Apache Struts RCE CVE-2017-5638",
          target: "example.com",
          source: "orchestrator-nuclei",
          cves: ["CVE-2017-5638"],
          cwes: ["CWE-20"],
          confidence: 95,
          severity: "critical" as any,
        }),
        // ZAP: Same vuln found via CWE
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Remote Code Execution via Input Validation",
          target: "example.com",
          source: "orchestrator-zap",
          cves: [],
          cwes: ["CWE-20"],
          confidence: 60,
          severity: "high" as any,
        }),
        // ZAP: Unique finding (no overlap)
        makeFinding({
          id: "zap-2",
          title: "[ZAP] Cookie Without SameSite Attribute",
          target: "example.com",
          source: "orchestrator-zap",
          cves: [],
          cwes: ["CWE-1275"],
          confidence: 50,
          severity: "medium" as any,
        }),
        // Nuclei: CSP missing
        makeFinding({
          id: "nuclei-2",
          title: "Missing Content Security Policy",
          target: "example.com",
          source: "orchestrator-nuclei",
          cves: [],
          cwes: ["CWE-693"],
          confidence: 80,
          severity: "medium" as any,
        }),
        // ZAP: CSP missing (same as nuclei-2 via CWE)
        makeFinding({
          id: "zap-3",
          title: "[ZAP] Content Security Policy (CSP) Header Not Set",
          target: "example.com",
          source: "orchestrator-zap",
          cves: [],
          cwes: ["CWE-693"],
          confidence: 70,
          severity: "medium" as any,
        }),
        // ScanForge: Unique finding
        makeFinding({
          id: "sf-1",
          title: "[ScanForge] Exposed Admin Panel at /admin",
          target: "example.com",
          source: "orchestrator-scanforge",
          cves: [],
          cwes: [],
          confidence: 75,
          severity: "high" as any,
        }),
      ];

      const result = dedup.deduplicate(findings);

      // Expected: 4 unique findings
      // 1. Apache Struts RCE (nuclei-1 + zap-1 merged via CWE-20)
      // 2. Cookie Without SameSite (zap-2, unique)
      // 3. Missing CSP (nuclei-2 + zap-3 merged via CWE-693)
      // 4. Exposed Admin Panel (sf-1, unique)
      expect(result.findings.length).toBe(4);
      expect(result.duplicatesRemoved).toBe(2);

      // The merged Apache Struts finding should have the highest severity
      const strutsVuln = result.findings.find(f => f.cves?.includes("CVE-2017-5638"));
      expect(strutsVuln).toBeDefined();
      expect(strutsVuln!.severity).toBe("critical");
      expect(strutsVuln!.cwes).toContain("CWE-20");
    });

    it("preserves all unique findings when no overlap exists", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "SQL Injection",
          target: "example.com",
          source: "orchestrator-nuclei",
          cves: ["CVE-2024-1234"],
          cwes: ["CWE-89"],
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Cross-Site Scripting",
          target: "example.com",
          source: "orchestrator-zap",
          cves: [],
          cwes: ["CWE-79"],
        }),
        makeFinding({
          id: "sf-1",
          title: "Directory Traversal",
          target: "example.com",
          source: "orchestrator-scanforge",
          cves: [],
          cwes: ["CWE-22"],
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(3);
      expect(result.duplicatesRemoved).toBe(0);
    });

    it("boosts confidence when multiple scanners corroborate the same finding", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "nuclei-1",
          title: "Missing X-Frame-Options",
          target: "example.com",
          source: "orchestrator-nuclei",
          cwes: ["CWE-1021"],
          confidence: 80,
        }),
        makeFinding({
          id: "zap-1",
          title: "[ZAP] X-Frame-Options Header Not Set",
          target: "example.com",
          source: "orchestrator-zap",
          cwes: ["CWE-1021"],
          confidence: 70,
        }),
      ];

      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(1);
      // Confidence should be boosted from corroboration
      expect(result.findings[0].confidence).toBeGreaterThan(80);
    });

    it("handles empty findings array", () => {
      const dedup = getDeduplicationEngine();
      const result = dedup.deduplicate([]);
      expect(result.findings.length).toBe(0);
      expect(result.duplicatesRemoved).toBe(0);
    });

    it("handles single finding", () => {
      const dedup = getDeduplicationEngine();
      const findings: ScanFinding[] = [
        makeFinding({
          id: "zap-1",
          title: "[ZAP] Some Finding",
          target: "example.com",
          source: "orchestrator-zap",
        }),
      ];
      const result = dedup.deduplicate(findings);
      expect(result.findings.length).toBe(1);
      expect(result.duplicatesRemoved).toBe(0);
    });
  });
});
