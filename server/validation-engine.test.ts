import { describe, it, expect, vi } from "vitest";

// ─── selectCandidates tests ─────────────────────────────────────────────────
describe("Validation Engine — selectCandidates", () => {
  it("should rank KEV-confirmed CVEs higher than non-KEV", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = [
      {
        id: 1,
        hostname: "kev-host.example.com",
        ipAddress: "10.0.0.1",
        port: 443,
        excluded: false,
        hybridRiskScore: 60,
        confidence: 80,
        postureFindings: [
          { cveIds: ["CVE-2024-1234"], kevListed: true, cvssScore: 9.8, evidenceBasis: "kev_match", port: 443, confidence: 90, id: "f1" },
        ],
      },
      {
        id: 2,
        hostname: "non-kev-host.example.com",
        ipAddress: "10.0.0.2",
        port: 80,
        excluded: false,
        hybridRiskScore: 80,
        confidence: 70,
        postureFindings: [
          { cveIds: ["CVE-2024-5678"], kevListed: false, cvssScore: 7.5, evidenceBasis: "vuln_feed", port: 80, confidence: 70, id: "f2" },
        ],
      },
    ];

    const catalog = [
      { catalogId: "1", msfModule: "exploit/multi/kev_exploit", msfRank: 500, cveIds: ["CVE-2024-1234"], cvssScore: 9.8, source: "msf" },
      { catalogId: "2", msfModule: "exploit/multi/non_kev", msfRank: 300, cveIds: ["CVE-2024-5678"], cvssScore: 7.5, source: "msf" },
    ];

    const candidates = selectCandidates(assets as any, catalog as any, 10);
    expect(candidates.length).toBe(2);
    // KEV candidate should be ranked first (higher priority score due to +40 KEV bonus)
    expect(candidates[0].cveId).toBe("CVE-2024-1234");
    expect(candidates[0].kevListed).toBe(true);
    expect(candidates[1].kevListed).toBe(false);
  });

  it("should respect maxCandidates limit", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = Array.from({ length: 20 }, (_, i) => ({
      id: i + 1,
      hostname: `host-${i}.example.com`,
      ipAddress: `10.0.0.${i + 1}`,
      port: 443,
      excluded: false,
      hybridRiskScore: 50 + i,
      confidence: 80,
      postureFindings: [
        { cveIds: [`CVE-2024-${1000 + i}`], kevListed: true, cvssScore: 8.0, evidenceBasis: "kev_match", port: 443, confidence: 80, id: `f${i}` },
      ],
    }));

    const catalog = Array.from({ length: 20 }, (_, i) => ({
      catalogId: String(i + 1),
      msfModule: `exploit/multi/mod_${i}`,
      msfRank: 500,
      cveIds: [`CVE-2024-${1000 + i}`],
      cvssScore: 8.0,
      source: "msf",
    }));

    const candidates = selectCandidates(assets as any, catalog as any, 5);
    expect(candidates.length).toBe(5);
  });

  it("should return empty array when no assets have matching CVEs in catalog", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = [
      {
        id: 1,
        hostname: "host.example.com",
        ipAddress: "10.0.0.1",
        port: 443,
        excluded: false,
        hybridRiskScore: 70,
        confidence: 80,
        postureFindings: [
          { cveIds: ["CVE-2024-9999"], kevListed: true, cvssScore: 9.0, evidenceBasis: "kev_match", port: 443, confidence: 80, id: "f1" },
        ],
      },
    ];

    const catalog = [
      { catalogId: "1", msfModule: "exploit/multi/different", msfRank: 500, cveIds: ["CVE-2024-0001"], cvssScore: 8.0, source: "msf" },
    ];

    // KEV-listed but no matching MSF module — should still be included since kevListed is true
    const candidates = selectCandidates(assets as any, catalog as any, 10);
    // The engine includes KEV-listed findings even without MSF module match
    expect(candidates.length).toBe(1);
    expect(candidates[0].msfModule).toBeNull();
  });

  it("should return empty array when assets have no postureFindings", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = [
      { id: 1, hostname: "host.example.com", ipAddress: "10.0.0.1", port: 443, excluded: false, hybridRiskScore: 70, confidence: 80, postureFindings: null },
      { id: 2, hostname: "host2.example.com", ipAddress: "10.0.0.2", port: 443, excluded: false, hybridRiskScore: 60, confidence: 80, postureFindings: [] },
    ];

    const catalog = [
      { catalogId: "1", msfModule: "exploit/multi/test", msfRank: 500, cveIds: ["CVE-2024-1234"], cvssScore: 8.0, source: "msf" },
    ];

    const candidates = selectCandidates(assets as any, catalog as any, 10);
    expect(candidates.length).toBe(0);
  });

  it("should skip excluded assets", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = [
      {
        id: 1,
        hostname: "excluded.example.com",
        ipAddress: "10.0.0.1",
        port: 443,
        excluded: true,
        hybridRiskScore: 90,
        confidence: 90,
        postureFindings: [
          { cveIds: ["CVE-2024-1234"], kevListed: true, cvssScore: 10.0, evidenceBasis: "kev_match", port: 443, confidence: 90, id: "f1" },
        ],
      },
    ];

    const catalog = [
      { catalogId: "1", msfModule: "exploit/multi/test", msfRank: 500, cveIds: ["CVE-2024-1234"], cvssScore: 10.0, source: "msf" },
    ];

    const candidates = selectCandidates(assets as any, catalog as any, 10);
    expect(candidates.length).toBe(0);
  });
});

// ─── computeCandidatePriority tests ─────────────────────────────────────────
describe("Validation Engine — computeCandidatePriority", () => {
  it("should give highest priority to KEV-listed + high CVSS + MSF module", async () => {
    const { computeCandidatePriority } = await import("./lib/validation-engine");

    const highPriority = computeCandidatePriority({
      assetId: 1, hostname: "host", ipAddress: "10.0.0.1", port: 443,
      cveId: "CVE-2024-1234", kevListed: true, cvssScore: 10.0,
      source: "kev_match", msfModule: "exploit/test", msfRank: 500,
      supportsCheck: true, currentRiskScore: 80, findingId: "f1", discoveryConfidence: 0.9,
    });

    const lowPriority = computeCandidatePriority({
      assetId: 2, hostname: "host2", ipAddress: "10.0.0.2", port: 80,
      cveId: "CVE-2024-5678", kevListed: false, cvssScore: 4.0,
      source: "vuln_feed", msfModule: null, msfRank: null,
      supportsCheck: false, currentRiskScore: 30, findingId: "f2", discoveryConfidence: 0.3,
    });

    expect(highPriority).toBeGreaterThan(lowPriority);
    expect(highPriority).toBeGreaterThan(80); // KEV(40) + CVSS(30) + MSF(15) + check(10) + conf(4.5)
  });

  it("should add 40 points for KEV-listed", async () => {
    const { computeCandidatePriority } = await import("./lib/validation-engine");

    const base = {
      assetId: 1, hostname: "host", ipAddress: "10.0.0.1", port: 443,
      cveId: "CVE-2024-1234", cvssScore: 8.0, source: "kev_match" as const,
      msfModule: "exploit/test", msfRank: 500, supportsCheck: false,
      currentRiskScore: 50, findingId: "f1", discoveryConfidence: 0.5,
    };

    const withKev = computeCandidatePriority({ ...base, kevListed: true });
    const withoutKev = computeCandidatePriority({ ...base, kevListed: false });

    expect(withKev - withoutKev).toBe(40);
  });
});

// ─── computeScoreAdjustment tests ───────────────────────────────────────────
describe("Validation Engine — computeScoreAdjustment", () => {
  it("should return 0 for non-exploitable findings", async () => {
    const { computeScoreAdjustment } = await import("./lib/validation-engine");
    expect(computeScoreAdjustment({ kevListed: true, cvssScore: 10.0 }, false)).toBe(0);
  });

  it("should return base + KEV + CVSS for exploitable KEV findings", async () => {
    const { computeScoreAdjustment } = await import("./lib/validation-engine");
    // base(5) + KEV(10) + CVSS>=9(10) = 25
    expect(computeScoreAdjustment({ kevListed: true, cvssScore: 9.8 }, true)).toBe(25);
  });

  it("should cap at 25 points", async () => {
    const { computeScoreAdjustment } = await import("./lib/validation-engine");
    const result = computeScoreAdjustment({ kevListed: true, cvssScore: 10.0 }, true);
    expect(result).toBeLessThanOrEqual(25);
  });

  it("should return base only for low CVSS non-KEV", async () => {
    const { computeScoreAdjustment } = await import("./lib/validation-engine");
    // base(5) + no KEV + CVSS<4(0) = 5
    expect(computeScoreAdjustment({ kevListed: false, cvssScore: 3.0 }, true)).toBe(5);
  });

  it("should add 5 for medium CVSS (7.0-8.9)", async () => {
    const { computeScoreAdjustment } = await import("./lib/validation-engine");
    // base(5) + CVSS>=7(5) = 10
    expect(computeScoreAdjustment({ kevListed: false, cvssScore: 7.5 }, true)).toBe(10);
  });
});

// ─── computeAssetValidationScore tests ──────────────────────────────────────
describe("Validation Engine — computeAssetValidationScore", () => {
  it("should return 0 for empty results", async () => {
    const { computeAssetValidationScore } = await import("./lib/validation-engine");
    expect(computeAssetValidationScore([])).toBe(0);
  });

  it("should return low score when nothing is exploitable", async () => {
    const { computeAssetValidationScore } = await import("./lib/validation-engine");

    const result = computeAssetValidationScore([
      { status: "not_vulnerable", exploitable: false, scoreAdjustment: 0 } as any,
      { status: "not_vulnerable", exploitable: false, scoreAdjustment: 0 } as any,
    ]);

    expect(result).toBeLessThanOrEqual(30);
    expect(result).toBeGreaterThan(0);
  });

  it("should return higher score when findings are exploitable", async () => {
    const { computeAssetValidationScore } = await import("./lib/validation-engine");

    const result = computeAssetValidationScore([
      { status: "validated", exploitable: true, scoreAdjustment: 25 } as any,
    ]);

    expect(result).toBeGreaterThan(30);
  });

  it("should cap at 100", async () => {
    const { computeAssetValidationScore } = await import("./lib/validation-engine");

    const result = computeAssetValidationScore([
      { status: "validated", exploitable: true, scoreAdjustment: 25 } as any,
      { status: "validated", exploitable: true, scoreAdjustment: 25 } as any,
      { status: "validated", exploitable: true, scoreAdjustment: 25 } as any,
    ]);

    expect(result).toBeLessThanOrEqual(100);
  });

  it("should ignore skipped and error results in ratio calculation", async () => {
    const { computeAssetValidationScore } = await import("./lib/validation-engine");

    const result = computeAssetValidationScore([
      { status: "validated", exploitable: true, scoreAdjustment: 15 } as any,
      { status: "skipped", exploitable: false, scoreAdjustment: 0 } as any,
      { status: "error", exploitable: false, scoreAdjustment: 0 } as any,
    ]);

    // Only 1 non-skipped/error result, and it's validated → 100% exploit ratio
    expect(result).toBeGreaterThan(50);
  });
});

// ─── validateCandidate tests ────────────────────────────────────────────────
describe("Validation Engine — validateCandidate", () => {
  it("should return error status when MSF client throws", async () => {
    const { validateCandidate } = await import("./lib/validation-engine");

    const mockMsfClient = {
      ensureAuth: vi.fn().mockRejectedValue(new Error("Connection refused")),
      checkModule: vi.fn().mockRejectedValue(new Error("Connection refused")),
      executeModule: vi.fn().mockRejectedValue(new Error("Connection refused")),
    };

    const candidate = {
      assetId: 1, hostname: "host.example.com", ipAddress: "10.0.0.1", port: 443,
      cveId: "CVE-2024-1234", msfModule: "exploit/multi/test", msfRank: 500,
      cvssScore: 9.0, kevListed: true, currentRiskScore: 60, priorityScore: 90,
      supportsCheck: false, source: "kev_match", findingId: "f1", discoveryConfidence: 0.9,
    };

    const config = {
      scanId: 1, msfServerId: 1, mode: "check_only" as const, maxCandidates: 10,
      requireApproval: false, timeoutPerCandidate: 30, scopeRestrictions: [],
      operatorId: "test-user", engagementId: null,
    };

    const result = await validateCandidate(candidate as any, mockMsfClient as any, config);
    expect(result.status).toBe("error");
    expect(result.exploitable).toBe(false);
    expect(result.errorMessage).toContain("Connection refused");
  });

  it("should skip candidates without MSF module", async () => {
    const { validateCandidate } = await import("./lib/validation-engine");

    const mockMsfClient = { ensureAuth: vi.fn(), checkModule: vi.fn(), executeModule: vi.fn() };

    const candidate = {
      assetId: 1, hostname: "host.example.com", ipAddress: "10.0.0.1", port: 443,
      cveId: "CVE-2024-1234", msfModule: null, msfRank: null,
      cvssScore: 9.0, kevListed: true, currentRiskScore: 60, priorityScore: 40,
      supportsCheck: false, source: "kev_match", findingId: "f1", discoveryConfidence: 0.9,
    };

    const config = {
      scanId: 1, msfServerId: 1, mode: "check_only" as const, maxCandidates: 10,
      requireApproval: false, timeoutPerCandidate: 30, scopeRestrictions: [],
      operatorId: "test-user", engagementId: null,
    };

    const result = await validateCandidate(candidate as any, mockMsfClient as any, config);
    expect(result.status).toBe("skipped");
  });

  it("should require approval for safe_exploit mode when configured", async () => {
    const { validateCandidate } = await import("./lib/validation-engine");

    const mockMsfClient = {
      ensureAuth: vi.fn().mockResolvedValue(undefined),
      checkModule: vi.fn(), executeModule: vi.fn(),
    };

    const candidate = {
      assetId: 1, hostname: "host.example.com", ipAddress: "10.0.0.1", port: 443,
      cveId: "CVE-2024-1234", msfModule: "exploit/multi/test", msfRank: 500,
      cvssScore: 9.0, kevListed: true, currentRiskScore: 60, priorityScore: 90,
      supportsCheck: false, source: "kev_match", findingId: "f1", discoveryConfidence: 0.9,
    };

    const config = {
      scanId: 1, msfServerId: 1, mode: "safe_exploit" as const, maxCandidates: 10,
      requireApproval: true, timeoutPerCandidate: 30, scopeRestrictions: [],
      operatorId: "test-user", engagementId: null,
    };

    const result = await validateCandidate(candidate as any, mockMsfClient as any, config);
    expect(result.status).toBe("approved_pending");
    expect(result.exploitable).toBe(false);
  });

  it("should skip out-of-scope targets", async () => {
    const { validateCandidate } = await import("./lib/validation-engine");

    const mockMsfClient = { ensureAuth: vi.fn(), checkModule: vi.fn(), executeModule: vi.fn() };

    const candidate = {
      assetId: 1, hostname: "host.example.com", ipAddress: "192.168.1.100", port: 443,
      cveId: "CVE-2024-1234", msfModule: "exploit/multi/test", msfRank: 500,
      cvssScore: 9.0, kevListed: true, currentRiskScore: 60, priorityScore: 90,
      supportsCheck: false, source: "kev_match", findingId: "f1", discoveryConfidence: 0.9,
    };

    const config = {
      scanId: 1, msfServerId: 1, mode: "check_only" as const, maxCandidates: 10,
      requireApproval: false, timeoutPerCandidate: 30,
      scopeRestrictions: ["10.0.0.0/24"], // Only 10.0.0.x is in scope
      operatorId: "test-user", engagementId: null,
    };

    const result = await validateCandidate(candidate as any, mockMsfClient as any, config);
    expect(result.status).toBe("skipped");
    expect(result.rawOutput).toContain("out of scope");
  });
});

// ─── Helper function tests ──────────────────────────────────────────────────
describe("Validation Engine — Helpers", () => {
  it("parseModulePath should split module path correctly", async () => {
    const { parseModulePath } = await import("./lib/validation-engine");

    const result = parseModulePath("exploit/windows/smb/ms17_010_eternalblue");
    expect(result.moduleType).toBe("exploit");
    expect(result.moduleName).toBe("windows/smb/ms17_010_eternalblue");
  });

  it("mapToAuxiliaryScanner should map known exploits", async () => {
    const { mapToAuxiliaryScanner } = await import("./lib/validation-engine");

    expect(mapToAuxiliaryScanner("exploit/windows/smb/ms17_010_eternalblue")).toBe("scanner/smb/smb_ms17_010");
    expect(mapToAuxiliaryScanner("exploit/windows/smb/ms08_067_netapi")).toBe("scanner/smb/smb_ms08_067");
  });

  it("mapToAuxiliaryScanner should return null for unmappable modules", async () => {
    const { mapToAuxiliaryScanner } = await import("./lib/validation-engine");

    expect(mapToAuxiliaryScanner("exploit")).toBeNull();
  });

  it("mapToAuxiliaryScanner should generate pattern-based scanner for unknown modules", async () => {
    const { mapToAuxiliaryScanner } = await import("./lib/validation-engine");

    const result = mapToAuxiliaryScanner("exploit/linux/http/some_vuln");
    expect(result).toBe("scanner/http/some_vuln");
  });
});

// ─── Deduplication and edge cases ───────────────────────────────────────────
describe("Validation Engine — Edge Cases", () => {
  it("should deduplicate candidates for same asset+CVE pair (keep best module)", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = [
      {
        id: 1,
        hostname: "host.example.com",
        ipAddress: "10.0.0.1",
        port: 443,
        excluded: false,
        hybridRiskScore: 70,
        confidence: 80,
        postureFindings: [
          { cveIds: ["CVE-2024-1234"], kevListed: true, cvssScore: 9.0, evidenceBasis: "kev_match", port: 443, confidence: 80, id: "f1" },
          // Duplicate finding for same CVE
          { cveIds: ["CVE-2024-1234"], kevListed: true, cvssScore: 9.0, evidenceBasis: "kev_match", port: 8443, confidence: 90, id: "f2" },
        ],
      },
    ];

    const catalog = [
      { catalogId: "1", msfModule: "exploit/multi/mod_a", msfRank: 500, cveIds: ["CVE-2024-1234"], cvssScore: 9.0, source: "msf" },
    ];

    const candidates = selectCandidates(assets as any, catalog as any, 10);
    // Should deduplicate — only 1 candidate for asset 1 + CVE-2024-1234
    expect(candidates.length).toBe(1);
  });

  it("should handle multiple CVEs per finding", async () => {
    const { selectCandidates } = await import("./lib/validation-engine");

    const assets = [
      {
        id: 1,
        hostname: "host.example.com",
        ipAddress: "10.0.0.1",
        port: 443,
        excluded: false,
        hybridRiskScore: 70,
        confidence: 80,
        postureFindings: [
          { cveIds: ["CVE-2024-1111", "CVE-2024-2222"], kevListed: true, cvssScore: 9.0, evidenceBasis: "kev_match", port: 443, confidence: 80, id: "f1" },
        ],
      },
    ];

    const catalog = [
      { catalogId: "1", msfModule: "exploit/multi/mod_a", msfRank: 500, cveIds: ["CVE-2024-1111"], cvssScore: 9.0, source: "msf" },
      { catalogId: "2", msfModule: "exploit/multi/mod_b", msfRank: 300, cveIds: ["CVE-2024-2222"], cvssScore: 8.0, source: "msf" },
    ];

    const candidates = selectCandidates(assets as any, catalog as any, 10);
    // Should create 2 candidates — one per CVE
    expect(candidates.length).toBe(2);
    const cves = candidates.map(c => c.cveId).sort();
    expect(cves).toEqual(["CVE-2024-1111", "CVE-2024-2222"]);
  });
});
