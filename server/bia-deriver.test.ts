import { describe, it, expect } from "vitest";
import {
  deriveAssetBia,
  biaToScoringInputs,
  biaToReportInputs,
  highWaterMark,
  type BiaEvidence,
} from "./lib/bia-deriver";

describe("deriveAssetBia — confidentiality from data classification", () => {
  it("PHI/HIPAA → confidentiality high + PHI class", () => {
    const bia = deriveAssetBia({ regulatoryFrameworks: ["HIPAA"], signals: "patient portal ehr" });
    expect(bia.fips199.confidentiality).toBe("high");
    expect(bia.dataClassification).toContain("PHI");
  });

  it("payment/PCI → confidentiality high + PCI class", () => {
    const bia = deriveAssetBia({ signals: "checkout stripe card payment", regulatoryFrameworks: ["PCI-DSS"] });
    expect(bia.fips199.confidentiality).toBe("high");
    expect(bia.dataClassification).toContain("PCI");
  });

  it("identity provider → confidentiality high (credentials)", () => {
    const bia = deriveAssetBia({ assetRole: "identity_provider", signals: "saml sso oauth login" });
    expect(bia.fips199.confidentiality).toBe("high");
    expect(bia.dataClassification).toContain("credentials");
  });

  it("PII only → confidentiality moderate", () => {
    const bia = deriveAssetBia({ regulatoryFrameworks: ["GDPR"], signals: "user account email newsletter" });
    expect(bia.fips199.confidentiality).toBe("moderate");
    expect(bia.dataClassification).toContain("PII");
  });

  it("public marketing → confidentiality low + public class", () => {
    const bia = deriveAssetBia({ assetFunction: "marketing", signals: "landing page brochure cdn static" });
    expect(bia.fips199.confidentiality).toBe("low");
    expect(bia.dataClassification).toContain("public");
  });
});

describe("deriveAssetBia — integrity & availability", () => {
  it("payment surface → integrity high", () => {
    const bia = deriveAssetBia({ signals: "payment transaction checkout" });
    expect(bia.fips199.integrity).toBe("high");
  });

  it("direct revenue path → availability high", () => {
    const bia = deriveAssetBia({ revenuePath: "direct", signals: "store" });
    expect(bia.fips199.availability).toBe("high");
  });

  it("HA topology alone → availability high (org treats loss as high-impact)", () => {
    const bia = deriveAssetBia({ revenuePath: "internal", multiRegion: true, loadBalanced: true, aRecordCount: 4 });
    expect(bia.fips199.availability).toBe("high");
  });

  it("internal, no HA → availability low", () => {
    const bia = deriveAssetBia({ revenuePath: "internal", signals: "internal wiki" });
    expect(bia.fips199.availability).toBe("low");
  });
});

describe("deriveAssetBia — business impact level", () => {
  it("identity provider → mission_critical", () => {
    const bia = deriveAssetBia({ assetRole: "identity_provider", signals: "sso" });
    expect(bia.businessImpactLevel).toBe("mission_critical");
  });

  it("high dependency in-degree → mission_critical (keystone)", () => {
    const bia = deriveAssetBia({ dependencyInDegree: 7, signals: "shared api" });
    expect(bia.businessImpactLevel).toBe("mission_critical");
  });

  it("public marketing → administrative", () => {
    const bia = deriveAssetBia({ assetFunction: "marketing", signals: "brochure public static" });
    expect(bia.businessImpactLevel).toBe("administrative");
  });
});

describe("overall high-water-mark + tier", () => {
  it("overall is the max of the CIA triad", () => {
    const bia = deriveAssetBia({ regulatoryFrameworks: ["HIPAA"], revenuePath: "internal" });
    expect(bia.overall).toBe("high"); // confidentiality high dominates
    expect(highWaterMark(["low", "moderate", "high"])).toBe("high");
    expect(highWaterMark(["low", "low"])).toBe("low");
  });

  it("mission_critical → availability tier 1", () => {
    const bia = deriveAssetBia({ assetRole: "payment", revenuePath: "direct", signals: "checkout" });
    expect(bia.availabilityTier).toBe(1);
  });
});

describe("confidence + provenance", () => {
  it("more signals → higher confidence, capped below 1", () => {
    const sparse = deriveAssetBia({ signals: "x" });
    const rich = deriveAssetBia({
      regulatoryFrameworks: ["HIPAA"],
      revenuePath: "direct",
      assetRole: "payment",
      dependencyInDegree: 6,
      signals: "checkout stripe",
      loadBalanced: true,
    });
    expect(rich.confidence).toBeGreaterThan(sparse.confidence);
    expect(rich.confidence).toBeLessThanOrEqual(0.9);
  });

  it("records which signals drove the derivation", () => {
    const bia = deriveAssetBia({ regulatoryFrameworks: ["PCI-DSS"], revenuePath: "direct" });
    expect(bia.provenance.signalsUsed).toContain("regulatory_exposure");
    expect(bia.provenance.signalsUsed).toContain("revenue_path");
  });

  it("every dimension carries a rationale (for SDR citation)", () => {
    const bia = deriveAssetBia({ regulatoryFrameworks: ["HIPAA"] });
    expect(bia.rationale.confidentiality).toBeTruthy();
    expect(bia.rationale.integrity).toBeTruthy();
    expect(bia.rationale.availability).toBeTruthy();
    expect(bia.rationale.businessImpact).toBeTruthy();
  });
});

describe("adapters plug into existing consumers", () => {
  const bia = deriveAssetBia({ regulatoryFrameworks: ["HIPAA"], revenuePath: "direct", assetRole: "payment" });

  it("biaToScoringInputs → Layer 4 shape (asset.fips199Category + businessImpactLevel)", () => {
    const s = biaToScoringInputs(bia);
    expect(s.fips199Category).toEqual(bia.fips199);
    expect(["mission_critical", "business_essential", "operational", "administrative"]).toContain(
      s.businessImpactLevel
    );
  });

  it("biaToReportInputs → bia-report-generator subset", () => {
    const r = biaToReportInputs(bia);
    expect(r.fips199Category.confidentiality).toBe("high");
    expect(typeof r.businessImpactLevel).toBe("string");
  });
});
