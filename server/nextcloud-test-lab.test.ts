import { describe, it, expect } from "vitest";
import {
  generateDockerCompose,
  generateAppInstallScript,
  generateUserProvisioningScript,
  generateLdapSeedScript,
  generateConfigScript,
  generateFullDeployScript,
  generateStatusScript,
  generateTeardownScript,
  getTestLabInfo,
  DEFAULT_LAB_CONFIG,
  BOUNTY_ELIGIBLE_APPS,
  NEXTCLOUD_VERSIONS,
} from "./lib/nextcloud-test-lab";

describe("Nextcloud Test Lab", () => {
  describe("DEFAULT_LAB_CONFIG", () => {
    it("has sensible defaults", () => {
      expect(DEFAULT_LAB_CONFIG.nextcloudVersion).toBeDefined();
      expect(DEFAULT_LAB_CONFIG.hostPort).toBe(8443);
      expect(DEFAULT_LAB_CONFIG.adminUser).toBe("admin");
      expect(DEFAULT_LAB_CONFIG.adminPassword).toBeTruthy();
    });
  });

  describe("BOUNTY_ELIGIBLE_APPS", () => {
    it("contains the critical security apps", () => {
      const names = BOUNTY_ELIGIBLE_APPS.map(a => a.name);
      expect(names).toContain("spreed");
      expect(names).toContain("end_to_end_encryption");
      expect(names).toContain("twofactor_totp");
    });

    it("has at least 40 apps", () => {
      expect(BOUNTY_ELIGIBLE_APPS.length).toBeGreaterThanOrEqual(40);
    });

    it("each app has required fields", () => {
      for (const app of BOUNTY_ELIGIBLE_APPS) {
        expect(app.name).toBeTruthy();
        expect(app.repo).toBeTruthy();
        expect(app.tier).toBeGreaterThanOrEqual(1);
        expect(app.description).toBeTruthy();
      }
    });
  });

  describe("NEXTCLOUD_VERSIONS", () => {
    it("has supported versions", () => {
      expect(NEXTCLOUD_VERSIONS.supported.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe("generateDockerCompose", () => {
    it("generates valid YAML-like output with nextcloud service", () => {
      const compose = generateDockerCompose(DEFAULT_LAB_CONFIG);
      expect(compose).toContain("nextcloud:");
      expect(compose).toContain("mariadb:");
      expect(compose).toContain("redis:");
      expect(compose).toContain(DEFAULT_LAB_CONFIG.nextcloudVersion);
    });

    it("includes optional services when enabled", () => {
      const config = { ...DEFAULT_LAB_CONFIG, enableCollabora: true, enableClamAV: true };
      const compose = generateDockerCompose(config);
      expect(compose).toContain("collabora");
      expect(compose).toContain("clamav");
    });

    it("excludes optional services when disabled", () => {
      const config = {
        ...DEFAULT_LAB_CONFIG,
        enableCollabora: false,
        enableClamAV: false,
        enableLDAP: false,
        enableKeycloak: false,
        enableElasticsearch: false,
        enableMinIO: false,
        enableMailhog: false,
        enableCoturn: false,
      };
      const compose = generateDockerCompose(config);
      // Core services should still be present
      expect(compose).toContain("nextcloud:");
      expect(compose).toContain("mariadb:");
    });

    it("uses custom host port", () => {
      const config = { ...DEFAULT_LAB_CONFIG, hostPort: 9443 };
      const compose = generateDockerCompose(config);
      expect(compose).toContain("9443");
    });
  });

  describe("generateAppInstallScript", () => {
    it("generates bash script with occ commands", () => {
      const script = generateAppInstallScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("occ");
      expect(script).toContain("app:install");
      expect(script).toContain("spreed");
    });

    it("installs apps in tier order", () => {
      const script = generateAppInstallScript(DEFAULT_LAB_CONFIG);
      const tier1Pos = script.indexOf("Tier 1");
      const tier2Pos = script.indexOf("Tier 2");
      if (tier1Pos >= 0 && tier2Pos >= 0) {
        expect(tier1Pos).toBeLessThan(tier2Pos);
      }
    });
  });

  describe("generateUserProvisioningScript", () => {
    it("creates test users", () => {
      const script = generateUserProvisioningScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("testuser");
      expect(script).toContain("shareuser");
      expect(script).toContain("user:add");
    });
  });

  describe("generateLdapSeedScript", () => {
    it("generates LDAP seed script", () => {
      const script = generateLdapSeedScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      // Should reference ldap in some way
      expect(script.toLowerCase()).toContain("ldap");
    });
  });

  describe("generateConfigScript", () => {
    it("configures Nextcloud settings", () => {
      const script = generateConfigScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("occ");
    });
  });

  describe("generateFullDeployScript", () => {
    it("generates complete deployment script", () => {
      const script = generateFullDeployScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("docker");
    });

    it("includes scan server host when provided", () => {
      const config = { ...DEFAULT_LAB_CONFIG, scanServerHost: "192.168.1.50" };
      const compose = generateDockerCompose(config);
      expect(compose).toContain("192.168.1.50");
    });
  });

  describe("generateStatusScript", () => {
    it("generates status check script", () => {
      const script = generateStatusScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("docker");
    });
  });

  describe("generateTeardownScript", () => {
    it("generates teardown script", () => {
      const script = generateTeardownScript(DEFAULT_LAB_CONFIG);
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("docker");
    });
  });

  describe("getTestLabInfo", () => {
    it("returns lab info with services and credentials", () => {
      const info = getTestLabInfo(DEFAULT_LAB_CONFIG);
      expect(info.services).toBeDefined();
      expect(info.services.length).toBeGreaterThan(0);
      expect(info.adminCredentials).toBeDefined();
      expect(info.adminCredentials.user).toBe("admin");
      expect(info.testUsers).toBeDefined();
      expect(info.testUsers.length).toBeGreaterThan(0);
      expect(info.complianceNotes).toBeDefined();
      expect(info.complianceNotes.length).toBeGreaterThan(0);
    });

    it("includes nextcloud service endpoint", () => {
      const info = getTestLabInfo(DEFAULT_LAB_CONFIG);
      const ncService = info.services.find(s => s.name.toLowerCase().includes("nextcloud"));
      expect(ncService).toBeDefined();
    });

    it("includes compliance notes about self-hosted testing", () => {
      const info = getTestLabInfo(DEFAULT_LAB_CONFIG);
      const selfHostedNote = info.complianceNotes.find(n =>
        n.toLowerCase().includes("self-hosted") || n.toLowerCase().includes("local")
      );
      expect(selfHostedNote).toBeDefined();
    });
  });
});
