import { describe, it, expect } from "vitest";
import {
  extractShodanVersionEvidence,
  enrichAssetsWithShodanData,
  verifyCvesWithShodanData,
  createShodanPostureFindings,
  matchShodanProductToTech,
  techMatchesShodanProduct,
} from "./lib/shodan-verifier";
import type { AssetObservation } from "./lib/passive/types";
import type { DiscoveredAssetRaw, AssetAnalysis, PostureFinding } from "./domainIntel";

// ─── Helpers ────────────────────────────────────────────────────────────

function makeShodanObservation(overrides: Partial<AssetObservation> & { evidence?: Record<string, any> }): AssetObservation {
  return {
    assetId: "test-obs-1",
    domain: "example.com",
    assetType: "ip",
    name: "web.example.com",
    ip: "1.2.3.4",
    source: "shodan",
    observedAt: new Date(),
    tags: [],
    evidence: {
      port: 443,
      transport: "tcp",
      product: "nginx",
      version: "1.18.0",
      cpe: ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"],
      vulns: [],
      banner_snippet: "HTTP/1.1 200 OK\nServer: nginx/1.18.0",
      hostnames: ["web.example.com"],
    },
    attribution: {
      provider: "Shodan",
      method: "test",
    },
    ...overrides,
  };
}

function makeAsset(overrides: Partial<DiscoveredAssetRaw> = {}): DiscoveredAssetRaw {
  return {
    assetId: "asset-001",
    hostname: "web.example.com",
    assetType: "web_server",
    technologies: ["nginx"],
    technologyVersions: {},
    assetClasses: ["web_server"],
    tags: ["internet_exposed"],
    dnsRecords: { A: ["1.2.3.4"] },
    dnsStatus: "verified",
    discoveryMethod: "dns_verified",
    ...overrides,
  };
}

function makeAnalysis(overrides: Partial<AssetAnalysis> = {}): AssetAnalysis {
  return {
    asset: makeAsset(),
    carverScores: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
    shockScores: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
    missionImpactScore: 5,
    suggestedTier: "tier2_medium",
    hybridRiskScore: 50,
    riskBand: "medium",
    cvssEstimate: 5,
    contextIndicators: { exposure: 0.5, recognizability: 0.5, confidence: 0.5 },
    postureFindings: [],
    testVectors: [],
    confidence: 50,
    assetCriticalityScore: 50,
    assetCriticalityBand: "medium",
    vulnRiskScore: 0,
    vulnRiskBand: "low",
    impactScore: 50,
    likelihoodScore: 50,
    ...overrides,
  };
}

// ─── Product Name Matching ──────────────────────────────────────────────

describe("Shodan Product Name Matching", () => {
  it("should match nginx product name", () => {
    expect(matchShodanProductToTech("nginx")).toBe("nginx");
  });

  it("should match Apache httpd to apache", () => {
    expect(matchShodanProductToTech("Apache httpd")).toBe("apache");
  });

  it("should match Microsoft-IIS to iis", () => {
    expect(matchShodanProductToTech("Microsoft-IIS")).toBe("iis");
  });

  it("should match OpenSSH", () => {
    expect(matchShodanProductToTech("OpenSSH")).toBe("openssh");
  });

  it("should return null for empty/unknown products", () => {
    expect(matchShodanProductToTech("")).toBeNull();
    expect(matchShodanProductToTech("unknown")).toBeNull();
  });

  it("should match FortiGate to fortinet", () => {
    expect(matchShodanProductToTech("FortiGate")).toBe("fortinet");
  });

  it("should match case-insensitively", () => {
    expect(matchShodanProductToTech("NGINX")).toBe("nginx");
    expect(matchShodanProductToTech("apache HTTPD")).toBe("apache");
  });

  it("techMatchesShodanProduct should match nginx variants", () => {
    expect(techMatchesShodanProduct("nginx", "nginx")).toBe(true);
    expect(techMatchesShodanProduct("Nginx", "nginx")).toBe(true);
  });

  it("techMatchesShodanProduct should match Apache variants", () => {
    expect(techMatchesShodanProduct("Apache", "Apache httpd")).toBe(true);
    expect(techMatchesShodanProduct("apache", "httpd")).toBe(true);
  });

  it("techMatchesShodanProduct should NOT match unrelated products", () => {
    expect(techMatchesShodanProduct("nginx", "Apache httpd")).toBe(false);
    expect(techMatchesShodanProduct("MySQL", "nginx")).toBe(false);
  });
});

// ─── Version Evidence Extraction ────────────────────────────────────────

describe("Shodan Version Evidence Extraction", () => {
  it("should extract version evidence from Shodan IP observations", () => {
    const obs = [
      makeShodanObservation({
        evidence: {
          port: 443,
          transport: "tcp",
          product: "nginx",
          version: "1.18.0",
          cpe: ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"],
          vulns: ["CVE-2021-23017"],
          banner_snippet: "Server: nginx/1.18.0",
          hostnames: ["web.example.com"],
          os: "Ubuntu",
        },
      }),
    ];

    const evidence = extractShodanVersionEvidence(obs);
    expect(evidence).toHaveLength(1);
    expect(evidence[0].product).toBe("nginx");
    expect(evidence[0].version).toBe("1.18.0");
    expect(evidence[0].vulns).toContain("CVE-2021-23017");
    expect(evidence[0].cpe).toHaveLength(1);
    expect(evidence[0].ip).toBe("1.2.3.4");
    expect(evidence[0].port).toBe(443);
  });

  it("should skip non-Shodan observations", () => {
    const obs = [
      makeShodanObservation({ source: "censys" }),
    ];
    const evidence = extractShodanVersionEvidence(obs);
    expect(evidence).toHaveLength(0);
  });

  it("should skip observations without product/version/cpe/vulns", () => {
    const obs = [
      makeShodanObservation({
        evidence: {
          port: 80,
          transport: "tcp",
          product: "",
          version: "",
          cpe: [],
          vulns: [],
          banner_snippet: "",
        },
      }),
    ];
    const evidence = extractShodanVersionEvidence(obs);
    expect(evidence).toHaveLength(0);
  });

  it("should deduplicate by ip:port:product", () => {
    const obs = [
      makeShodanObservation({
        assetId: "obs-1",
        evidence: { port: 443, product: "nginx", version: "1.18.0", cpe: [], vulns: [], banner_snippet: "" },
      }),
      makeShodanObservation({
        assetId: "obs-2",
        evidence: { port: 443, product: "nginx", version: "1.18.0", cpe: [], vulns: [], banner_snippet: "" },
      }),
    ];
    const evidence = extractShodanVersionEvidence(obs);
    expect(evidence).toHaveLength(1);
  });

  it("should extract multiple services on different ports", () => {
    const obs = [
      makeShodanObservation({
        assetId: "obs-1",
        evidence: { port: 443, product: "nginx", version: "1.18.0", cpe: [], vulns: [], banner_snippet: "" },
      }),
      makeShodanObservation({
        assetId: "obs-2",
        evidence: { port: 22, product: "OpenSSH", version: "8.2p1", cpe: [], vulns: [], banner_snippet: "" },
      }),
    ];
    const evidence = extractShodanVersionEvidence(obs);
    expect(evidence).toHaveLength(2);
    expect(evidence.map(e => e.product)).toContain("nginx");
    expect(evidence.map(e => e.product)).toContain("OpenSSH");
  });
});

// ─── Asset Enrichment ───────────────────────────────────────────────────

describe("Shodan Asset Enrichment", () => {
  it("should enrich asset with Shodan version data by hostname match", () => {
    const assets = [makeAsset({ technologyVersions: {} })];
    const obs = [
      makeShodanObservation({
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: [],
          banner_snippet: "Server: nginx/1.18.0",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = enrichAssetsWithShodanData(assets, obs);
    expect(result.assetsEnriched).toBe(1);
    expect(result.versionsAdded).toBeGreaterThanOrEqual(1);
    // Check that the asset now has the version
    expect(assets[0].technologyVersions).toBeDefined();
    const versions = assets[0].technologyVersions!;
    // Should have nginx version (either under "nginx" or the canonical name)
    const hasNginxVersion = Object.entries(versions).some(
      ([k, v]) => k.toLowerCase().includes("nginx") && v === "1.18.0"
    );
    expect(hasNginxVersion).toBe(true);
  });

  it("should enrich asset by IP match when hostname doesn't match", () => {
    const assets = [makeAsset({
      hostname: "server1.example.com",
      dnsRecords: { A: ["1.2.3.4"] },
      technologyVersions: {},
    })];
    const obs = [
      makeShodanObservation({
        name: "other.example.com",
        ip: "1.2.3.4",
        evidence: {
          port: 22,
          product: "OpenSSH",
          version: "8.2p1",
          cpe: [],
          vulns: [],
          banner_snippet: "SSH-2.0-OpenSSH_8.2p1",
          hostnames: ["other.example.com"],
        },
      }),
    ];

    const result = enrichAssetsWithShodanData(assets, obs);
    expect(result.assetsEnriched).toBe(1);
    const versions = assets[0].technologyVersions!;
    const hasSSHVersion = Object.entries(versions).some(
      ([k, v]) => k.toLowerCase().includes("openssh") && v === "8.2p1"
    );
    expect(hasSSHVersion).toBe(true);
  });

  it("should NOT overwrite existing version data", () => {
    const assets = [makeAsset({
      technologyVersions: { nginx: "1.20.0" }, // Already has a version
    })];
    const obs = [
      makeShodanObservation({
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0", // Older version from Shodan
          cpe: [],
          vulns: [],
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    enrichAssetsWithShodanData(assets, obs);
    // Should keep the existing version
    expect(assets[0].technologyVersions!.nginx).toBe("1.20.0");
  });

  it("should extract versions from CPE strings", () => {
    const assets = [makeAsset({
      technologies: ["PHP"],
      technologyVersions: {},
    })];
    const obs = [
      makeShodanObservation({
        evidence: {
          port: 443,
          product: "",
          version: "",
          cpe: ["cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*"],
          vulns: [],
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = enrichAssetsWithShodanData(assets, obs);
    expect(result.versionsAdded).toBeGreaterThanOrEqual(1);
    const versions = assets[0].technologyVersions!;
    const hasPHPVersion = Object.entries(versions).some(
      ([k, v]) => k.toLowerCase().includes("php") && v === "7.4.3"
    );
    expect(hasPHPVersion).toBe(true);
  });

  it("should not enrich assets with no matching Shodan data", () => {
    const assets = [makeAsset({ hostname: "unrelated.example.com", dnsRecords: { A: ["9.9.9.9"] } })];
    const obs = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: [],
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = enrichAssetsWithShodanData(assets, obs);
    expect(result.assetsEnriched).toBe(0);
  });
});

// ─── CVE Verification ───────────────────────────────────────────────────

describe("Shodan CVE Verification", () => {
  it("should upgrade probable finding to confirmed when Shodan detects the CVE", () => {
    const finding: PostureFinding = {
      id: "kev-CVE-2021-23017",
      assetRef: "asset-001",
      assetHostname: "web.example.com",
      category: "CISA KEV",
      title: "CVE-2021-23017: nginx resolver vulnerability",
      severity: 6, // Capped at 6 for probable
      likelihood: 6,
      confidence: 0.7,
      recommendedControls: ["Patch nginx"],
      cveIds: ["CVE-2021-23017"],
      kevListed: true,
      corroborationTier: "probable",
      versionMatchConfirmed: false,
      evidenceChain: ["Technology nginx detected", "No version confirmed"],
    };

    const analysis = makeAnalysis({
      asset: makeAsset({ dnsRecords: { A: ["1.2.3.4"] } }),
      postureFindings: [finding],
    });

    const obs = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: ["CVE-2021-23017"],
          banner_snippet: "Server: nginx/1.18.0",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = verifyCvesWithShodanData([analysis], obs);
    expect(result.upgraded).toBe(1);
    expect(result.verified).toHaveLength(1);
    expect(result.verified[0].shodanConfirmed).toBe(true);
    expect(result.verified[0].cveId).toBe("CVE-2021-23017");

    // Check the finding was upgraded
    expect(finding.corroborationTier).toBe("confirmed");
    expect(finding.versionMatchConfirmed).toBe(true);
    expect(finding.confidence).toBeGreaterThanOrEqual(0.95);
    expect(finding.evidenceChain).toBeDefined();
    expect(finding.evidenceChain!.some(e => e.includes("SHODAN VERIFICATION"))).toBe(true);
  });

  it("should NOT upgrade already-confirmed findings", () => {
    const finding: PostureFinding = {
      id: "kev-CVE-2021-23017",
      assetRef: "asset-001",
      assetHostname: "web.example.com",
      category: "CISA KEV",
      title: "CVE-2021-23017: nginx resolver vulnerability",
      severity: 9,
      likelihood: 9,
      confidence: 0.95,
      recommendedControls: ["Patch nginx"],
      cveIds: ["CVE-2021-23017"],
      corroborationTier: "confirmed",
      versionMatchConfirmed: true,
      detectedVersion: "1.18.0",
    };

    const analysis = makeAnalysis({ postureFindings: [finding] });
    const obs = [
      makeShodanObservation({
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: ["CVE-2021-23017"],
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = verifyCvesWithShodanData([analysis], obs);
    expect(result.upgraded).toBe(0); // Already confirmed, no upgrade needed
  });

  it("should handle findings with no CVE IDs gracefully", () => {
    const finding: PostureFinding = {
      id: "misc-finding",
      assetRef: "asset-001",
      category: "Misconfiguration",
      title: "Weak TLS configuration",
      severity: 4,
      likelihood: 5,
      confidence: 0.6,
      recommendedControls: ["Upgrade TLS"],
      corroborationTier: "probable",
    };

    const analysis = makeAnalysis({ postureFindings: [finding] });
    const obs = [makeShodanObservation()];

    const result = verifyCvesWithShodanData([analysis], obs);
    expect(result.upgraded).toBe(0);
  });
});

// ─── Shodan Posture Findings ────────────────────────────────────────────

describe("Shodan Posture Findings", () => {
  it("should create confirmed findings from Shodan-detected CVEs", () => {
    const analysis = makeAnalysis({
      asset: makeAsset({ dnsRecords: { A: ["1.2.3.4"] } }),
      postureFindings: [],
    });

    const obs = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: ["CVE-2021-23017", "CVE-2022-41741"],
          banner_snippet: "Server: nginx/1.18.0",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = createShodanPostureFindings([analysis], obs);
    expect(result.findingsAdded).toBe(2);
    expect(analysis.postureFindings).toHaveLength(2);

    // Check first finding
    const f1 = analysis.postureFindings[0];
    expect(f1.corroborationTier).toBe("confirmed");
    expect(f1.versionMatchConfirmed).toBe(true);
    expect(f1.cveIds).toContain("CVE-2021-23017");
    expect(f1.confidence).toBe(0.95);
    expect(f1.category).toBe("Shodan Detected CVE");
    expect(f1.evidenceBasis).toBe("confirmed_cve");
  });

  it("should NOT duplicate existing CVE findings", () => {
    const existingFinding: PostureFinding = {
      id: "kev-CVE-2021-23017",
      assetRef: "asset-001",
      category: "CISA KEV",
      title: "CVE-2021-23017",
      severity: 9,
      likelihood: 9,
      confidence: 0.95,
      recommendedControls: [],
      cveIds: ["CVE-2021-23017"],
      corroborationTier: "confirmed",
    };

    const analysis = makeAnalysis({
      asset: makeAsset({ dnsRecords: { A: ["1.2.3.4"] } }),
      postureFindings: [existingFinding],
    });

    const obs = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: ["CVE-2021-23017", "CVE-2022-41741"], // One existing, one new
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = createShodanPostureFindings([analysis], obs);
    expect(result.findingsAdded).toBe(1); // Only the new CVE
    expect(analysis.postureFindings).toHaveLength(2); // 1 existing + 1 new
  });

  it("should not create findings when no Shodan CVEs detected", () => {
    const analysis = makeAnalysis({
      asset: makeAsset({ dnsRecords: { A: ["1.2.3.4"] } }),
    });

    const obs = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: [], // No CVEs detected
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    const result = createShodanPostureFindings([analysis], obs);
    expect(result.findingsAdded).toBe(0);
  });
});

// ─── Integration: Full Pipeline Flow ────────────────────────────────────

describe("Shodan Verifier Integration", () => {
  it("should handle empty Shodan observations gracefully", () => {
    const assets = [makeAsset()];
    const result = enrichAssetsWithShodanData(assets, []);
    expect(result.assetsEnriched).toBe(0);
    expect(result.versionsAdded).toBe(0);
  });

  it("should handle multiple assets with mixed Shodan coverage", () => {
    const assets = [
      makeAsset({
        assetId: "a1",
        hostname: "web.example.com",
        dnsRecords: { A: ["1.2.3.4"] },
        technologyVersions: {},
      }),
      makeAsset({
        assetId: "a2",
        hostname: "mail.example.com",
        dnsRecords: { A: ["5.6.7.8"] },
        technologyVersions: {},
      }),
      makeAsset({
        assetId: "a3",
        hostname: "internal.example.com",
        dnsRecords: { A: ["10.0.0.1"] }, // Not in Shodan
        technologyVersions: {},
      }),
    ];

    const obs = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: [],
          vulns: [],
          banner_snippet: "",
          hostnames: ["web.example.com"],
        },
      }),
      makeShodanObservation({
        assetId: "obs-2",
        ip: "5.6.7.8",
        name: "mail.example.com",
        evidence: {
          port: 25,
          product: "Postfix",
          version: "3.4.13",
          cpe: [],
          vulns: [],
          banner_snippet: "",
          hostnames: ["mail.example.com"],
        },
      }),
    ];

    const result = enrichAssetsWithShodanData(assets, obs);
    expect(result.assetsEnriched).toBe(2); // web + mail enriched, internal not
  });

  it("full flow: enrich → create findings → verify → all confirmed", () => {
    // Step 1: Create assets with no versions
    const assets = [makeAsset({
      hostname: "web.example.com",
      technologies: ["nginx"],
      technologyVersions: {},
      dnsRecords: { A: ["1.2.3.4"] },
    })];

    // Step 2: Shodan observations with version + CVE data
    const obs: AssetObservation[] = [
      makeShodanObservation({
        ip: "1.2.3.4",
        evidence: {
          port: 443,
          product: "nginx",
          version: "1.18.0",
          cpe: ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"],
          vulns: ["CVE-2021-23017"],
          banner_snippet: "Server: nginx/1.18.0",
          hostnames: ["web.example.com"],
        },
      }),
    ];

    // Step 3: Enrich assets with Shodan data
    const enrichResult = enrichAssetsWithShodanData(assets, obs);
    expect(enrichResult.assetsEnriched).toBe(1);

    // Step 4: Create analysis with a probable KEV finding
    const analysis = makeAnalysis({
      asset: assets[0],
      postureFindings: [{
        id: "kev-CVE-2021-23017",
        assetRef: "asset-001",
        assetHostname: "web.example.com",
        category: "CISA KEV",
        title: "CVE-2021-23017: nginx resolver vulnerability",
        severity: 6,
        likelihood: 6,
        confidence: 0.7,
        recommendedControls: ["Patch nginx"],
        cveIds: ["CVE-2021-23017"],
        kevListed: true,
        corroborationTier: "probable",
        versionMatchConfirmed: false,
        evidenceChain: ["Technology nginx detected"],
      }],
    });

    // Step 5: Create Shodan posture findings (for CVEs not already in findings)
    // CVE-2021-23017 is already in findings, so nothing new should be added
    const shodanFindings = createShodanPostureFindings([analysis], obs);
    expect(shodanFindings.findingsAdded).toBe(0); // Already exists

    // Step 6: Verify CVEs with Shodan data
    const verifyResult = verifyCvesWithShodanData([analysis], obs);
    expect(verifyResult.upgraded).toBe(1);

    // Step 7: Check the finding is now confirmed
    const finding = analysis.postureFindings[0];
    expect(finding.corroborationTier).toBe("confirmed");
    expect(finding.versionMatchConfirmed).toBe(true);
    expect(finding.confidence).toBeGreaterThanOrEqual(0.95);
  });
});
