import { describe, expect, it } from "vitest";
import {
  assertActiveEngagementAuthorization,
  assertTargetWithinEngagementScope,
} from "./engagement-tenant-access";

const signedWhitelistedEngagement = {
  targetDomain: "scan.aceofcloud.io",
  targetIpRange: null,
  roeStatus: "signed",
  roeExpiryDate: null,
  activeScanOverride: 0,
};

describe("assertActiveEngagementAuthorization", () => {
  it("permits a signed, in-date engagement with whitelisted targets", () => {
    expect(() => assertActiveEngagementAuthorization(signedWhitelistedEngagement)).not.toThrow();
  });

  it("requires a signed RoE for all active work", () => {
    expect(() => assertActiveEngagementAuthorization({
      ...signedWhitelistedEngagement,
      roeStatus: "pending",
    })).toThrow(/signed Rules of Engagement/i);
  });

  it("rejects an expired signed RoE", () => {
    expect(() => assertActiveEngagementAuthorization({
      ...signedWhitelistedEngagement,
      roeExpiryDate: "2020-01-01T00:00:00.000Z",
    })).toThrow(/expired/i);
  });

  it("requires a persisted override for a non-whitelisted signed target", () => {
    expect(() => assertActiveEngagementAuthorization({
      ...signedWhitelistedEngagement,
      targetDomain: "customer.example",
    })).toThrow(/approved active-scan override/i);

    expect(() => assertActiveEngagementAuthorization({
      ...signedWhitelistedEngagement,
      targetDomain: "customer.example",
      activeScanOverride: 1,
    })).not.toThrow();
  });
});

describe("assertTargetWithinEngagementScope", () => {
  it("accepts an exact scoped host and an authorized subdomain", () => {
    const engagement = { targetDomain: "scan.aceofcloud.io", targetIpRange: null };
    expect(() => assertTargetWithinEngagementScope(engagement, "https://scan.aceofcloud.io/login")).not.toThrow();
    expect(() => assertTargetWithinEngagementScope(engagement, "app.scan.aceofcloud.io")).not.toThrow();
  });

  it("accepts an IPv4 address within an explicitly authorized CIDR", () => {
    const engagement = { targetDomain: null, targetIpRange: "10.20.0.0/16" };
    expect(() => assertTargetWithinEngagementScope(engagement, "10.20.42.8")).not.toThrow();
  });

  it("rejects out-of-scope and lookalike targets", () => {
    const engagement = { targetDomain: "scan.aceofcloud.io", targetIpRange: "10.20.0.0/16" };
    expect(() => assertTargetWithinEngagementScope(engagement, "scan.aceofcloud.io.attacker.example")).toThrow(/outside this engagement's authorized scope/i);
    expect(() => assertTargetWithinEngagementScope(engagement, "10.21.42.8")).toThrow(/outside this engagement's authorized scope/i);
  });
});
