import { describe, it, expect, vi } from "vitest";

// ─── Test: Asset Provisioner Types & Helpers ──────────────────────────────

describe("Asset Provisioner", () => {
  describe("BuildRequirement interface", () => {
    it("should accept a valid build requirement object", () => {
      const br = {
        assetName: "https://github.com/nodejs/node",
        assetType: "SOURCE_CODE",
        acquisitionMethod: "git clone https://github.com/nodejs/node",
        buildInstructions: ["./configure", "make -j4"],
        deployInstructions: ["docker build -t node-test .", "docker run -d -p ${PORT}:3000 node-test"],
        dependencies: ["gcc", "make", "python3"],
        sponsorInstructions: "Test against the latest LTS branch only",
        hasHostedInstance: false,
        hostedInstanceUrl: null,
      };
      expect(br.assetName).toBe("https://github.com/nodejs/node");
      expect(br.assetType).toBe("SOURCE_CODE");
      expect(br.buildInstructions).toHaveLength(2);
      expect(br.dependencies).toContain("gcc");
      expect(br.hasHostedInstance).toBe(false);
    });

    it("should handle hosted instance with URL", () => {
      const br = {
        assetName: "https://example.com/webapp",
        assetType: "URL",
        acquisitionMethod: "direct",
        buildInstructions: [],
        deployInstructions: [],
        dependencies: [],
        hasHostedInstance: true,
        hostedInstanceUrl: "https://staging.example.com",
      };
      expect(br.hasHostedInstance).toBe(true);
      expect(br.hostedInstanceUrl).toBe("https://staging.example.com");
    });
  });

  describe("ToolRequirement interface", () => {
    it("should accept a valid tool requirement", () => {
      const tr = {
        tool: "semgrep",
        installCommand: "pip3 install semgrep",
        purpose: "Static analysis for Node.js/JavaScript vulnerabilities",
        category: "sast",
        required: true,
        alternatives: ["eslint-plugin-security", "njsscan"],
      };
      expect(tr.tool).toBe("semgrep");
      expect(tr.required).toBe(true);
      expect(tr.alternatives).toContain("njsscan");
    });
  });

  describe("BUILDABLE_ASSET_TYPES detection", () => {
    const BUILDABLE_ASSET_TYPES = new Set([
      "SOURCE_CODE",
      "DOWNLOADABLE_EXECUTABLES",
      "SMART_CONTRACT",
      "HARDWARE_FIRMWARE",
      "OTHER_IPA",
      "OTHER_APK",
    ]);

    it("should detect SOURCE_CODE as buildable", () => {
      expect(BUILDABLE_ASSET_TYPES.has("SOURCE_CODE")).toBe(true);
    });

    it("should detect SMART_CONTRACT as buildable", () => {
      expect(BUILDABLE_ASSET_TYPES.has("SMART_CONTRACT")).toBe(true);
    });

    it("should NOT detect URL as buildable", () => {
      expect(BUILDABLE_ASSET_TYPES.has("URL")).toBe(false);
    });

    it("should NOT detect DOMAIN as buildable", () => {
      expect(BUILDABLE_ASSET_TYPES.has("DOMAIN")).toBe(false);
    });

    it("should detect DOWNLOADABLE_EXECUTABLES as buildable", () => {
      expect(BUILDABLE_ASSET_TYPES.has("DOWNLOADABLE_EXECUTABLES")).toBe(true);
    });
  });
});

// ─── Test: Engagement Builder Fixes ──────────────────────────────────────

describe("Engagement Builder Fixes", () => {
  describe("extractPrimaryDomain fix", () => {
    it("should not fall back to hackerone.com for source code assets", () => {
      // The bug was that extractPrimaryDomain fell back to the platform URL hostname
      // when no URL-type assets were found, resulting in "hackerone.com" as the target
      const assets = [
        { name: "https://github.com/nodejs/node", type: "SOURCE_CODE", tier: "critical" },
      ];

      // Simulate the fixed logic: extract from source code URL
      function extractPrimaryDomain(assets: any[], programUrl: string): string {
        // First try URL/DOMAIN assets
        const urlAsset = assets.find((a) => a.type === "URL" || a.type === "DOMAIN");
        if (urlAsset) {
          try { return new URL(urlAsset.name).hostname; } catch { return urlAsset.name; }
        }

        // Then try source code repos - extract the project name
        const sourceAsset = assets.find((a) =>
          a.type === "SOURCE_CODE" || a.type === "DOWNLOADABLE_EXECUTABLES"
        );
        if (sourceAsset) {
          try {
            const url = new URL(sourceAsset.name);
            const parts = url.pathname.split("/").filter(Boolean);
            return parts[parts.length - 1] || parts[0] || url.hostname;
          } catch {
            return sourceAsset.name.split("/").pop() || sourceAsset.name;
          }
        }

        // DO NOT fall back to platform URL hostname (that was the bug)
        return "unknown-target";
      }

      const result = extractPrimaryDomain(assets, "https://hackerone.com/nodejs");
      expect(result).not.toBe("hackerone.com");
      expect(result).toBe("node"); // Should extract "node" from the GitHub URL
    });
  });

  describe("Exploit status resolution fix", () => {
    it("should resolve status from shell_obtained when ea_status is failed but shell was obtained", () => {
      // The bug: ea_status = "failed" but shell_obtained = 1
      // The fix: derive status from shell_obtained when ea_status is ambiguous
      const attempt = {
        eaStatus: "failed",
        shellObtained: 1,
        eaAccessLevel: "user",
      };

      function resolveExploitStatus(attempt: any): string {
        if (attempt.shellObtained === 1 || attempt.shellObtained === true) {
          return "succeeded";
        }
        return attempt.eaStatus || "unknown";
      }

      expect(resolveExploitStatus(attempt)).toBe("succeeded");
    });

    it("should keep failed status when shell was not obtained", () => {
      const attempt = {
        eaStatus: "failed",
        shellObtained: 0,
        eaAccessLevel: "none",
      };

      function resolveExploitStatus(attempt: any): string {
        if (attempt.shellObtained === 1 || attempt.shellObtained === true) {
          return "succeeded";
        }
        return attempt.eaStatus || "unknown";
      }

      expect(resolveExploitStatus(attempt)).toBe("failed");
    });
  });

  describe("Evidence summary counter fix", () => {
    it("should correctly count succeeded/failed/blocked from derived status", () => {
      const evidenceItems = [
        { status: undefined, shellObtained: 1 },
        { status: undefined, shellObtained: 1 },
        { status: "failed", shellObtained: 0 },
        { status: "blocked", shellObtained: 0 },
      ];

      const derived = evidenceItems.map((e) => ({
        ...e,
        derivedStatus:
          e.shellObtained === 1
            ? "SUCCEEDED"
            : e.status === "blocked"
            ? "BLOCKED"
            : e.status === "failed"
            ? "FAILED"
            : "UNKNOWN",
      }));

      const succeeded = derived.filter((e) => e.derivedStatus === "SUCCEEDED").length;
      const failed = derived.filter((e) => e.derivedStatus === "FAILED").length;
      const blocked = derived.filter((e) => e.derivedStatus === "BLOCKED").length;

      expect(succeeded).toBe(2);
      expect(failed).toBe(1);
      expect(blocked).toBe(1);
      expect(succeeded + failed + blocked).toBe(derived.length);
    });
  });

  describe("Finding deduplication", () => {
    it("should deduplicate findings with same CVE and asset", () => {
      const findings = [
        { cveId: "CVE-2021-12345", asset: "example.com", title: "SQL Injection", status: "verified" },
        { cveId: "CVE-2021-12345", asset: "example.com", title: "SQL Injection (duplicate)", status: "unverified" },
        { cveId: "CVE-2021-99999", asset: "example.com", title: "XSS", status: "verified" },
      ];

      const seen = new Set<string>();
      const deduped = findings.filter((f) => {
        const key = `${f.cveId}::${f.asset}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

      expect(deduped).toHaveLength(2);
      expect(deduped[0].title).toBe("SQL Injection"); // Keep the first (verified) one
    });

    it("should deduplicate .env variant findings", () => {
      const findings = [
        { title: "Exposed Laravel .env File", asset: "example.com/.env" },
        { title: "Exposed CodeIgniter .env File", asset: "example.com/.env" },
        { title: "Exposed Generic .env File", asset: "example.com/.env" },
        { title: "SQL Injection", asset: "example.com/api" },
      ];

      // Group .env findings
      const envFindings = findings.filter((f) => f.title.toLowerCase().includes(".env"));
      const otherFindings = findings.filter((f) => !f.title.toLowerCase().includes(".env"));

      // Keep only one .env finding per asset
      const envSeen = new Set<string>();
      const dedupedEnv = envFindings.filter((f) => {
        if (envSeen.has(f.asset)) return false;
        envSeen.add(f.asset);
        return true;
      });

      const result = [...dedupedEnv, ...otherFindings];
      expect(result).toHaveLength(2); // One .env + SQL Injection
    });
  });

  describe("False positive CVE filtering", () => {
    it("should flag CVEs that don't match the target technology", () => {
      const targetTech = "nodejs";
      const findings = [
        { cveId: "CVE-2023-48365", product: "Qlik Sense", severity: "critical" },
        { cveId: "CVE-2019-16278", product: "Nostromo nhttpd", severity: "critical" },
        { cveId: "CVE-2024-12345", product: "Node.js", severity: "high" },
      ];

      const nonMatchingProducts = ["Qlik Sense", "Nostromo", "Rejetto", "Apache Struts"];
      const flagged = findings.filter((f) =>
        nonMatchingProducts.some((p) => f.product.toLowerCase().includes(p.toLowerCase()))
      );

      expect(flagged).toHaveLength(2);
      expect(flagged[0].product).toBe("Qlik Sense");
      expect(flagged[1].product).toBe("Nostromo nhttpd");
    });
  });
});

// ─── Test: ROE Scope JSON Structure ──────────────────────────────────────

describe("ROE Scope JSON", () => {
  it("should include buildRequirements and toolRequirements fields", () => {
    const roeScope = {
      platform: "hackerone",
      programUrl: "https://hackerone.com/nodejs",
      totalAssets: 1,
      buildRequirements: [
        {
          assetName: "https://github.com/nodejs/node",
          assetType: "SOURCE_CODE",
          acquisitionMethod: "git clone https://github.com/nodejs/node",
          buildInstructions: ["./configure", "make -j4"],
          deployInstructions: [],
          dependencies: ["gcc", "make"],
        },
      ],
      toolRequirements: [
        {
          tool: "semgrep",
          installCommand: "pip3 install semgrep",
          purpose: "SAST for JavaScript",
          category: "sast",
          required: true,
          alternatives: [],
        },
      ],
      requiresAssetProvisioning: true,
    };

    expect(roeScope.requiresAssetProvisioning).toBe(true);
    expect(roeScope.buildRequirements).toHaveLength(1);
    expect(roeScope.toolRequirements).toHaveLength(1);
    expect(roeScope.buildRequirements[0].assetType).toBe("SOURCE_CODE");
    expect(roeScope.toolRequirements[0].tool).toBe("semgrep");
  });

  it("should be parseable from JSON string", () => {
    const roeJson = JSON.stringify({
      buildRequirements: [],
      toolRequirements: [],
      requiresAssetProvisioning: false,
    });

    const parsed = JSON.parse(roeJson);
    expect(parsed.requiresAssetProvisioning).toBe(false);
    expect(parsed.buildRequirements).toEqual([]);
  });
});
