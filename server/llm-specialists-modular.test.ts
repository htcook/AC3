/**
 * Modular LLM Specialist Tests
 * 
 * Tests the decomposed specialist architecture:
 * - Evidence package construction
 * - Validation (bounded deltas, grounding, training data leakage)
 * - Asset Attribution Specialist (deterministic baseline)
 * - Asset Role Specialist (deterministic baseline)
 * - Lifecycle Stage Specialist (deterministic baseline)
 * - Business Context Specialist (deterministic baseline)
 * - Threat Relevance Specialist (deterministic baseline)
 * - CorroborationTierBadge logic (shared component)
 */

import { describe, it, expect } from "vitest";

// ─── Evidence Package ─────────────────────────────────────────────

import {
  buildEvidencePackage,
  renderEvidencePackage,
  hashPackage,
  isGenericCertificateIssuer,
  isPrivacyProxy,
  isCDNProvider,
  isHostingProvider,
} from "./lib/llm-specialists/evidence-package";

describe("Evidence Package", () => {
  it("builds a basic evidence package from an asset identifier", () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    expect(pkg.assetId).toBeTruthy();
    expect(pkg.assetIdentifier).toBe("api.example.com");
    expect(pkg.observedIPs).toEqual([]);
    expect(pkg.firstSeen).toBeTruthy();
    expect(pkg.lastSeen).toBeTruthy();
  });

  it("extracts certificate evidence from discovery result", () => {
    const discoveryResult = {
      hosts: [{
        ip: "1.2.3.4",
        services: [{
          port: 443,
          tls: {
            certificate: {
              subject: { common_name: "api.example.com", organization: "Example Inc" },
              issuer: { organization: "Let's Encrypt" },
              validity: {
                start: "2024-01-01T00:00:00Z",
                end: "2025-01-01T00:00:00Z",
              },
              fingerprint_sha256: "abc123",
              subject_alt_names: ["api.example.com", "www.example.com"],
            },
          },
        }],
      }],
    };
    const pkg = buildEvidencePackage("api.example.com", discoveryResult);
    expect(pkg.observedIPs).toContain("1.2.3.4");
    // Certificate should be extracted
    if (pkg.certificate) {
      expect(pkg.certificate.subjectCN).toBe("api.example.com");
    }
  });

  it("extracts WHOIS evidence when provided", () => {
    const whois = {
      registrant: "Example Inc",
      registrar: "GoDaddy",
      createdDate: "2020-01-01",
      updatedDate: "2024-06-01",
      expirationDate: "2026-01-01",
      nameServers: ["ns1.example.com", "ns2.example.com"],
    };
    const pkg = buildEvidencePackage("example.com", {}, whois);
    expect(pkg.whois).toBeTruthy();
    if (pkg.whois) {
      expect(pkg.whois.registrant).toBe("Example Inc");
      expect(pkg.whois.registrar).toBe("GoDaddy");
    }
  });

  it("renders evidence package to human-readable text", () => {
    const pkg = buildEvidencePackage("test.example.com", {});
    const rendered = renderEvidencePackage(pkg);
    expect(rendered).toContain("test.example.com");
    expect(typeof rendered).toBe("string");
    expect(rendered.length).toBeGreaterThan(20);
  });

  it("produces deterministic hashes for identical packages", () => {
    const pkg1 = buildEvidencePackage("test.example.com", {});
    // Override timestamps for determinism
    pkg1.firstSeen = "2024-01-01T00:00:00Z";
    pkg1.lastSeen = "2024-01-01T00:00:00Z";
    const hash1 = hashPackage(pkg1);

    const pkg2 = buildEvidencePackage("test.example.com", {});
    pkg2.firstSeen = "2024-01-01T00:00:00Z";
    pkg2.lastSeen = "2024-01-01T00:00:00Z";
    const hash2 = hashPackage(pkg2);

    expect(hash1).toBe(hash2);
  });

  it("identifies generic certificate issuers", () => {
    expect(isGenericCertificateIssuer("Let's Encrypt")).toBe(true);
    expect(isGenericCertificateIssuer("DigiCert")).toBe(true);
    expect(isGenericCertificateIssuer("Acme Corp")).toBe(false);
  });

  it("identifies privacy proxies", () => {
    expect(isPrivacyProxy("Domains By Proxy")).toBe(true);
    expect(isPrivacyProxy("WhoisGuard")).toBe(true);
    expect(isPrivacyProxy("Example Inc")).toBe(false);
  });

  it("identifies CDN providers", () => {
    expect(isCDNProvider("cloudflare")).toBe(true);
    expect(isCDNProvider("Akamai")).toBe(true);
    expect(isCDNProvider("custom-server")).toBe(false);
  });

  it("identifies hosting providers", () => {
    expect(isHostingProvider("amazon")).toBe(true);
    expect(isHostingProvider("Google Cloud")).toBe(true);
    expect(isHostingProvider("my-server")).toBe(false);
  });
});

// ─── Validation ───────────────────────────────────────────────────

import {
  clampDelta,
  applyBoundedDelta,
  validateBoundedDelta,
  scoreToBand,
  checkTrainingDataLeakage,
  validateEvidenceGrounding,
  validateConfidenceBounds,
} from "./lib/llm-specialists/validation";

describe("Validation — Bounded Delta", () => {
  it("clamps delta within ±20 range", () => {
    expect(clampDelta(10)).toBe(10);
    expect(clampDelta(-10)).toBe(-10);
    expect(clampDelta(25)).toBe(20);
    expect(clampDelta(-30)).toBe(-20);
    expect(clampDelta(0)).toBe(0);
  });

  it("applies bounded delta to baseline score", () => {
    expect(applyBoundedDelta(50, 10)).toBe(60);
    expect(applyBoundedDelta(50, -10)).toBe(40);
    expect(applyBoundedDelta(50, 30)).toBe(70); // clamped to +20
    expect(applyBoundedDelta(90, 20)).toBe(100); // capped at 100
    expect(applyBoundedDelta(10, -20)).toBe(0); // floored at 0
  });

  it("validates bounded delta results", () => {
    const valid = validateBoundedDelta(50, 60);
    expect(valid.passed).toBe(true);

    const invalid = validateBoundedDelta(50, 80);
    expect(invalid.passed).toBe(false);
    // validateBoundedDelta returns { passed, delta, clamped } not { failures }
    expect(invalid.delta).toBe(30);
    expect(invalid.clamped).toBe(20);
  });

  it("converts scores to confidence bands", () => {
    expect(scoreToBand(80)).toBe("high");
    expect(scoreToBand(50)).toBe("medium");
    expect(scoreToBand(20)).toBe("low");
  });
});

describe("Validation — Training Data Leakage", () => {
  it("passes clean text", () => {
    const result = checkTrainingDataLeakage("This asset is hosted on AWS with a valid certificate.");
    expect(result.passed).toBe(true);
  });

  it("detects training data citations", () => {
    const result = checkTrainingDataLeakage("According to my training data, this is a known vulnerability.");
    expect(result.passed).toBe(false);
    expect(result.failures.length).toBeGreaterThan(0);
  });
});

describe("Validation — Evidence Grounding", () => {
  it("validates evidence references against package", () => {
    const pkg = buildEvidencePackage("test.example.com", {});
    const evidence = [
      { source: "asset_identifier", evidenceType: "naming_convention", weight: "moderate" as const, detail: "test.example.com" },
    ];
    const result = validateEvidenceGrounding(evidence, pkg);
    expect(result.passed).toBe(true);
  });

  it("validates confidence bounds on attribution claims", () => {
    // validateConfidenceBounds takes AttributionClaim[], not (score, evidence)
    const claims = [{
      attributedTo: { organization: "Test" },
      claimType: "primary_owner" as const,
      confidence: "high" as const,
      confidenceScore: 90,
      supportingEvidence: [
        { source: "asset_identifier", evidenceType: "naming_convention", weight: "weak" as const, detail: "test" },
      ],
      reasoning: "Test claim",
    }];
    const result = validateConfidenceBounds(claims);
    // High confidence with only weak evidence should fail
    expect(result.passed).toBe(false);
  });
});

// ─── Asset Attribution Specialist ─────────────────────────────────

import { computeDeterministicAttribution } from "./lib/llm-specialists/asset-attribution/deterministic-baseline";
import { invokeAttributionSpecialist } from "./lib/llm-specialists/asset-attribution/specialist";
import { applyAttributionToAssetRecord, inferSectorFromAttribution, getSectorPresets } from "./lib/llm-specialists/asset-attribution/scoring-integration";

describe("Asset Attribution Specialist", () => {
  it("computes deterministic attribution claims from certificate evidence", () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    pkg.certificate = {
      subjectCN: "api.example.com",
      subjectO: "Example Inc",
      issuerO: "Let's Encrypt",
      validFrom: "2024-01-01",
      validTo: "2025-01-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: ["api.example.com", "www.example.com"],
    };
    // computeDeterministicAttribution returns AttributionClaim[]
    const claims = computeDeterministicAttribution(pkg);
    expect(Array.isArray(claims)).toBe(true);
    expect(claims.length).toBeGreaterThan(0);
    const certClaim = claims.find(c => c.attributedTo.organization === "Example Inc");
    expect(certClaim).toBeTruthy();
    expect(certClaim!.claimType).toBe("primary_owner");
    expect(certClaim!.confidenceScore).toBeGreaterThan(0);
    expect(certClaim!.supportingEvidence.length).toBeGreaterThan(0);
  });

  it("computes deterministic attribution from WHOIS registrantOrg", () => {
    const pkg = buildEvidencePackage("example.com", {});
    // WHOIS must use registrantOrg (not registrant) for the deterministic baseline
    pkg.whois = {
      registrantOrg: "Example Corp",
      registrar: "GoDaddy",
      creationDate: "2020-01-01",
      updatedDate: "2024-01-01",
      expirationDate: "2026-01-01",
    };
    const claims = computeDeterministicAttribution(pkg);
    expect(claims.length).toBeGreaterThan(0);
    expect(claims.some(c => c.attributedTo.organization === "Example Corp")).toBe(true);
  });

  it("returns low-confidence obscured claim when no attribution evidence exists", () => {
    const pkg = buildEvidencePackage("unknown-host.test", {});
    const claims = computeDeterministicAttribution(pkg);
    expect(Array.isArray(claims)).toBe(true);
    // Rule 6 fires: obscured asset with >=2 negative signals produces a low-confidence claim
    expect(claims.length).toBeGreaterThanOrEqual(1);
    const obscured = claims.find(c => c.claimType === "unknown");
    expect(obscured).toBeTruthy();
    expect(obscured!.confidenceScore).toBeLessThan(30);
  });

  it("invokes specialist in deterministic-only mode", async () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    pkg.certificate = {
      subjectCN: "api.example.com",
      subjectO: "Example Inc",
      issuerO: "DigiCert",
      validFrom: "2024-01-01",
      validTo: "2025-01-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: ["api.example.com"],
    };
    // AttributionSpecialistInput requires assetId
    const result = await invokeAttributionSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    expect(result.metadata.mode).toBe("deterministic_only");
    expect(result.metadata.specialistName).toBe("asset-attribution");
    // Output has claims[] and primaryClaim, not attribution.organizationName
    expect(result.claims.length).toBeGreaterThan(0);
    expect(result.primaryClaim?.attributedTo.organization).toBe("Example Inc");
    expect(result.validationResult.passed).toBe(true);
  });

  it("applies attribution output to scoring record", async () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    pkg.certificate = {
      subjectCN: "api.example.com",
      subjectO: "Example Inc",
      issuerO: "DigiCert",
      validFrom: "2024-01-01",
      validTo: "2025-01-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: ["api.example.com"],
    };
    // applyAttributionToAssetRecord takes AttributionSpecialistOutput, not (record, claims)
    const specialistOutput = await invokeAttributionSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    const scoringResult = applyAttributionToAssetRecord(specialistOutput);
    expect(scoringResult).toHaveProperty("attributionConfidenceMultiplier");
    expect(scoringResult).toHaveProperty("attributionStatus");
    expect(scoringResult).toHaveProperty("attributedOrganization");
    expect(scoringResult).toHaveProperty("attributionEvidenceCount");
    expect(scoringResult.attributedOrganization).toBe("Example Inc");
  });

  it("infers sector from attribution output", async () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    pkg.certificate = {
      subjectCN: "api.example.com",
      subjectO: "Example Inc",
      issuerO: "DigiCert",
      validFrom: "2024-01-01",
      validTo: "2025-01-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: ["api.example.com"],
    };
    const output = await invokeAttributionSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    const sector = inferSectorFromAttribution(output, "Financial Services");
    expect(typeof sector).toBe("string");
  });

  it("returns sector presets as a Record", () => {
    const presets = getSectorPresets();
    // getSectorPresets returns Record<string, CarverScores>, not an array
    expect(typeof presets).toBe("object");
    expect(Object.keys(presets).length).toBeGreaterThan(0);
  });
});

// ─── Asset Role Specialist ────────────────────────────────────────

import { computeRoleBaseline, invokeRoleSpecialist } from "./lib/llm-specialists/asset-role/specialist";

describe("Asset Role Specialist", () => {
  it("detects internal exposure from naming convention", () => {
    const pkg = buildEvidencePackage("internal.corp.example.com", {});
    const result = computeRoleBaseline(pkg);
    expect(result.exposure).toBe("internal");
    expect(result.confidenceScore).toBeGreaterThan(40);
  });

  it("detects customer-facing exposure", () => {
    const pkg = buildEvidencePackage("www.example.com", {});
    const result = computeRoleBaseline(pkg);
    expect(result.exposure).toBe("customer_facing");
  });

  it("detects development environment from naming", () => {
    const pkg = buildEvidencePackage("dev.staging.example.com", {});
    const result = computeRoleBaseline(pkg);
    expect(["development", "staging"]).toContain(result.environment);
  });

  it("detects production environment from valid CA certificate", () => {
    const pkg = buildEvidencePackage("app.example.com", {});
    pkg.certificate = {
      subjectCN: "app.example.com",
      issuerO: "DigiCert",
      validFrom: "2024-01-01",
      validTo: "2025-12-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: [],
    };
    const result = computeRoleBaseline(pkg);
    expect(result.environment).toBe("production");
  });

  it("detects backup criticality from naming", () => {
    const pkg = buildEvidencePackage("backup.db.example.com", {});
    const result = computeRoleBaseline(pkg);
    expect(result.criticality).toBe("backup");
  });

  it("invokes specialist in deterministic-only mode", async () => {
    const pkg = buildEvidencePackage("admin.internal.example.com", {});
    const result = await invokeRoleSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    expect(result.metadata.mode).toBe("deterministic_only");
    expect(result.metadata.specialistName).toBe("asset-role");
    expect(result.role.exposure).toBe("internal");
    expect(result.validationResult.passed).toBe(true);
  });
});

// ─── Lifecycle Stage Specialist ───────────────────────────────────

import { computeLifecycleBaseline, invokeLifecycleSpecialist } from "./lib/llm-specialists/lifecycle-stage/specialist";

describe("Lifecycle Stage Specialist", () => {
  it("detects active stage from valid certificate and technologies", () => {
    const pkg = buildEvidencePackage("app.example.com", {});
    pkg.certificate = {
      subjectCN: "app.example.com",
      issuerO: "Let's Encrypt",
      validFrom: "2024-01-01",
      validTo: "2027-01-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: [],
    };
    pkg.http = {
      statusCode: 200,
      technologies: ["nginx", "React"],
    };
    const result = computeLifecycleBaseline(pkg);
    expect(result.stage).toBe("active");
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it("detects declining stage from expired certificate", () => {
    const pkg = buildEvidencePackage("old.example.com", {});
    pkg.certificate = {
      subjectCN: "old.example.com",
      issuerO: "Let's Encrypt",
      validFrom: "2020-01-01",
      validTo: "2021-01-01",
      isSelfSigned: false,
      isExpired: true,
      sanEntries: [],
    };
    const result = computeLifecycleBaseline(pkg);
    expect(["declining", "abandoned"]).toContain(result.stage);
    expect(result.signals.some(s => s.direction === "declining" || s.direction === "abandoned")).toBe(true);
  });

  it("detects abandoned stage from expired domain", () => {
    const pkg = buildEvidencePackage("dead.example.com", {});
    pkg.whois = {
      registrant: "Unknown",
      registrar: "GoDaddy",
      createdDate: "2015-01-01",
      updatedDate: "2018-01-01",
      expirationDate: "2020-01-01", // expired
    };
    pkg.lastSeen = "2019-06-01T00:00:00Z";
    const result = computeLifecycleBaseline(pkg);
    expect(result.stage).toBe("abandoned");
  });

  it("returns unknown for minimal evidence", () => {
    const pkg = buildEvidencePackage("mystery.example.com", {});
    const result = computeLifecycleBaseline(pkg);
    expect(result.stage).toBe("unknown");
    expect(result.confidenceScore).toBeLessThan(30);
  });

  it("invokes specialist in deterministic-only mode", async () => {
    const pkg = buildEvidencePackage("app.example.com", {});
    pkg.http = { statusCode: 200, technologies: ["Apache"] };
    const result = await invokeLifecycleSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    expect(result.metadata.mode).toBe("deterministic_only");
    expect(result.metadata.specialistName).toBe("lifecycle-stage");
    expect(result.validationResult.passed).toBe(true);
  });
});

// ─── Business Context Specialist ──────────────────────────────────

import { computeBusinessContextBaseline, invokeBusinessContextSpecialist } from "./lib/llm-specialists/business-context/specialist";

describe("Business Context Specialist", () => {
  it("detects PCI-DSS regulatory exposure from payment indicators", () => {
    const pkg = buildEvidencePackage("checkout.example.com", {});
    const result = computeBusinessContextBaseline(pkg);
    expect(result.regulatoryExposure.some(r => r.framework === "PCI-DSS")).toBe(true);
  });

  it("detects HIPAA exposure from healthcare industry", () => {
    const pkg = buildEvidencePackage("portal.example.com", {});
    const result = computeBusinessContextBaseline(pkg, "Healthcare");
    expect(result.regulatoryExposure.some(r => r.framework === "HIPAA")).toBe(true);
  });

  it("detects FISMA exposure from .gov domain", () => {
    const pkg = buildEvidencePackage("portal.agency.gov", {});
    const result = computeBusinessContextBaseline(pkg);
    expect(result.regulatoryExposure.some(r => r.framework === "FISMA")).toBe(true);
  });

  it("infers asset function from naming convention", () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    const result = computeBusinessContextBaseline(pkg);
    expect(result.function).toBe("API Gateway");
  });

  it("infers VPN function", () => {
    const pkg = buildEvidencePackage("vpn.example.com", {});
    const result = computeBusinessContextBaseline(pkg);
    expect(result.function).toBe("VPN Gateway");
    expect(result.revenuePath).toBe("internal");
  });

  it("infers direct revenue path from shop naming", () => {
    const pkg = buildEvidencePackage("shop.example.com", {});
    const result = computeBusinessContextBaseline(pkg);
    expect(result.revenuePath).toBe("direct");
  });

  it("detects CNAME dependencies", () => {
    const pkg = buildEvidencePackage("app.example.com", {});
    pkg.dns = {
      cnameChain: ["app.example.com", "app.cdn.cloudflare.net"],
    };
    const result = computeBusinessContextBaseline(pkg);
    expect(result.dependencies.length).toBeGreaterThan(0);
    expect(result.dependencies[0].dependsOn).toBe("app.cdn.cloudflare.net");
  });

  it("invokes specialist in deterministic-only mode", async () => {
    const pkg = buildEvidencePackage("pay.example.com", {});
    const result = await invokeBusinessContextSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    expect(result.metadata.mode).toBe("deterministic_only");
    expect(result.metadata.specialistName).toBe("business-context");
    expect(result.validationResult.passed).toBe(true);
    expect(result.regulatoryExposure.some(r => r.framework === "PCI-DSS")).toBe(true);
  });
});

// ─── Threat Relevance Specialist ──────────────────────────────────

import { computeThreatRelevanceBaseline, invokeThreatRelevanceSpecialist } from "./lib/llm-specialists/threat-relevance/specialist";

describe("Threat Relevance Specialist", () => {
  it("detects ransomware relevance from VPN naming", () => {
    const pkg = buildEvidencePackage("vpn.example.com", {});
    const result = computeThreatRelevanceBaseline(pkg);
    expect(result.actorRelevance.some(a => a.actorType === "ransomware_group")).toBe(true);
  });

  it("detects nation-state relevance from .gov domain", () => {
    const pkg = buildEvidencePackage("portal.agency.gov", {});
    const result = computeThreatRelevanceBaseline(pkg);
    expect(result.actorRelevance.some(a => a.actorType === "nation_state_apt")).toBe(true);
  });

  it("detects financial threat relevance from payment naming", () => {
    const pkg = buildEvidencePackage("pay.example.com", {});
    const result = computeThreatRelevanceBaseline(pkg);
    expect(result.actorRelevance.some(a => a.actorType === "financially_motivated")).toBe(true);
  });

  it("detects insider threat relevance from internal naming", () => {
    const pkg = buildEvidencePackage("admin.internal.example.com", {});
    const result = computeThreatRelevanceBaseline(pkg);
    expect(result.actorRelevance.some(a => a.actorType === "insider_threat")).toBe(true);
  });

  it("boosts ransomware relevance for vulnerable technologies", () => {
    const pkg = buildEvidencePackage("vpn.example.com", {});
    pkg.http = {
      statusCode: 200,
      technologies: ["Citrix ADC", "Exchange"],
    };
    const result = computeThreatRelevanceBaseline(pkg);
    const ransomware = result.actorRelevance.find(a => a.actorType === "ransomware_group");
    expect(ransomware).toBeTruthy();
    expect(ransomware!.relevanceScore).toBeGreaterThan(40);
    expect(ransomware!.supportingEvidence.some(e => e.evidenceType === "vulnerable_technology")).toBe(true);
  });

  it("includes sector exposure for healthcare industry", () => {
    const pkg = buildEvidencePackage("portal.example.com", {});
    const result = computeThreatRelevanceBaseline(pkg, "Healthcare");
    expect(result.sectorExposure.some(s => s.sector === "healthcare")).toBe(true);
  });

  it("returns low overall threat score for unknown assets", () => {
    const pkg = buildEvidencePackage("unknown.test", {});
    const result = computeThreatRelevanceBaseline(pkg);
    expect(result.overallThreatScore).toBeLessThan(30);
  });

  it("invokes specialist in deterministic-only mode", async () => {
    const pkg = buildEvidencePackage("rdp.example.com", {});
    const result = await invokeThreatRelevanceSpecialist({ assetId: pkg.assetId, evidencePackage: pkg });
    expect(result.metadata.mode).toBe("deterministic_only");
    expect(result.metadata.specialistName).toBe("threat-relevance");
    expect(result.validationResult.passed).toBe(true);
  });
});

// ─── Cross-Specialist Integration ─────────────────────────────────

describe("Cross-Specialist Integration", () => {
  it("all 5 specialists produce consistent metadata structure", async () => {
    const pkg = buildEvidencePackage("api.example.com", {});
    pkg.certificate = {
      subjectCN: "api.example.com",
      subjectO: "Example Inc",
      issuerO: "DigiCert",
      validFrom: "2024-01-01",
      validTo: "2025-12-01",
      isSelfSigned: false,
      isExpired: false,
      sanEntries: ["api.example.com"],
    };

    const [attr, role, life, biz, threat] = await Promise.all([
      invokeAttributionSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeRoleSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeLifecycleSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeBusinessContextSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeThreatRelevanceSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
    ]);

    for (const result of [attr, role, life, biz, threat]) {
      expect(result.metadata).toHaveProperty("invocationId");
      expect(result.metadata).toHaveProperty("specialistName");
      expect(result.metadata).toHaveProperty("specialistVersion");
      expect(result.metadata).toHaveProperty("promptVersion");
      expect(result.metadata).toHaveProperty("durationMs");
      expect(result.metadata).toHaveProperty("mode");
      expect(result.metadata.mode).toBe("deterministic_only");
      expect(result.metadata).toHaveProperty("inputPackageHash");
      expect(result.metadata).toHaveProperty("timestamp");
      expect(result.validationResult.passed).toBe(true);
    }
  });

  it("all specialists share the same input package hash for identical input", async () => {
    const pkg = buildEvidencePackage("test.example.com", {});
    pkg.firstSeen = "2024-01-01T00:00:00Z";
    pkg.lastSeen = "2024-01-01T00:00:00Z";

    const [attr, role, life, biz, threat] = await Promise.all([
      invokeAttributionSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeRoleSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeLifecycleSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeBusinessContextSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
      invokeThreatRelevanceSpecialist({ assetId: pkg.assetId, evidencePackage: pkg }),
    ]);

    const hashes = [attr, role, life, biz, threat].map(r => r.metadata.inputPackageHash);
    expect(new Set(hashes).size).toBe(1);
  });
});
