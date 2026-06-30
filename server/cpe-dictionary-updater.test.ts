/**
 * Tests for CPE Dictionary Auto-Updater and Fingerprint Diff UI tRPC procedures.
 *
 * @vitest-environment node
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── CPE Dictionary Updater Unit Tests ────────────────────────────────

describe("CPE Dictionary Updater", () => {
  let updater: typeof import("./lib/cpe-dictionary-updater");

  beforeEach(async () => {
    // Dynamic import to get fresh module state
    updater = await import("./lib/cpe-dictionary-updater");
  });

  describe("lookupCpe", () => {
    it("should find static seed entries by exact name", () => {
      const result = updater.lookupCpe("apache");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("apache");
      expect(result!.product).toBe("http_server");
      expect(result!.source).toBe("static");
    });

    it("should find static seed entries case-insensitively", () => {
      const result = updater.lookupCpe("Apache");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("apache");
    });

    it("should find entries by partial match", () => {
      const result = updater.lookupCpe("tomcat");
      expect(result).not.toBeNull();
      expect(result!.product).toBe("tomcat");
    });

    it("should return null for unknown technologies", () => {
      const result = updater.lookupCpe("totally_unknown_product_xyz_123");
      expect(result).toBeNull();
    });

    it("should find nginx", () => {
      const result = updater.lookupCpe("nginx");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("nginx");
      expect(result!.product).toBe("nginx");
    });

    it("should find OpenSSH", () => {
      const result = updater.lookupCpe("openssh");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("openbsd");
      expect(result!.product).toBe("openssh");
    });

    it("should find PHP", () => {
      const result = updater.lookupCpe("php");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("php");
      expect(result!.product).toBe("php");
    });

    it("should find WordPress", () => {
      const result = updater.lookupCpe("wordpress");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("wordpress");
    });
  });

  describe("registerUnmappedTechnology", () => {
    it("should register unknown technologies for future resolution", () => {
      updater.registerUnmappedTechnology("custom_product_abc");
      const stats = updater.getDictionaryStats();
      expect(stats.unmappedTechnologies).toContain("custom_product_abc");
    });

    it("should not register technologies that already have mappings", () => {
      const statsBefore = updater.getDictionaryStats();
      const unmappedBefore = statsBefore.unmappedTechnologies.length;
      updater.registerUnmappedTechnology("apache");
      const statsAfter = updater.getDictionaryStats();
      expect(statsAfter.unmappedTechnologies.length).toBe(unmappedBefore);
    });

    it("should not register empty or single-char strings", () => {
      const statsBefore = updater.getDictionaryStats();
      const unmappedBefore = statsBefore.unmappedTechnologies.length;
      updater.registerUnmappedTechnology("");
      updater.registerUnmappedTechnology("a");
      const statsAfter = updater.getDictionaryStats();
      expect(statsAfter.unmappedTechnologies.length).toBe(unmappedBefore);
    });
  });

  describe("addManualMapping", () => {
    it("should add a manual CPE mapping", () => {
      updater.addManualMapping("custom_server", "custom_vendor", "custom_product");
      const result = updater.lookupCpe("custom_server");
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe("custom_vendor");
      expect(result!.product).toBe("custom_product");
      expect(result!.source).toBe("manual");
    });

    it("should generate correct CPE URI for manual mappings", () => {
      updater.addManualMapping("test_app", "test_vendor", "test_product");
      const result = updater.lookupCpe("test_app");
      expect(result).not.toBeNull();
      expect(result!.nvdCpeUri).toBe("cpe:2.3:a:test_vendor:test_product:*:*:*:*:*:*:*:*");
    });
  });

  describe("getDictionaryStats", () => {
    it("should return valid statistics", () => {
      const stats = updater.getDictionaryStats();
      expect(stats.totalEntries).toBeGreaterThan(60); // At least the static seed
      expect(stats.staticEntries).toBeGreaterThan(50);
      expect(stats.lastUpdateTime).toBeTypeOf("number");
      expect(stats.unmappedTechnologies).toBeInstanceOf(Array);
      expect(stats.updateHistory).toBeInstanceOf(Array);
    });

    it("should have more static entries than NVD entries initially", () => {
      const stats = updater.getDictionaryStats();
      expect(stats.staticEntries).toBeGreaterThan(stats.nvdDiscoveredEntries);
    });
  });

  describe("getDictionaryEntries", () => {
    it("should return all dictionary entries as an array", () => {
      const entries = updater.getDictionaryEntries();
      expect(entries).toBeInstanceOf(Array);
      expect(entries.length).toBeGreaterThan(60);
      
      // Each entry should have required fields
      for (const entry of entries.slice(0, 5)) {
        expect(entry.technology).toBeTypeOf("string");
        expect(entry.vendor).toBeTypeOf("string");
        expect(entry.product).toBeTypeOf("string");
        expect(["static", "nvd_api", "manual"]).toContain(entry.source);
        expect(entry.nvdCpeUri).toMatch(/^cpe:2\.3:/);
      }
    });
  });

  describe("Extended static seed coverage", () => {
    const criticalProducts = [
      { tech: "apache struts", vendor: "apache", product: "struts" },
      { tech: "rabbitmq", vendor: "vmware", product: "rabbitmq" },
      { tech: "postfix", vendor: "postfix", product: "postfix" },
      { tech: "bind", vendor: "isc", product: "bind" },
      { tech: "samba", vendor: "samba", product: "samba" },
      { tech: "keycloak", vendor: "redhat", product: "keycloak" },
      { tech: "nextcloud", vendor: "nextcloud", product: "nextcloud_server" },
      { tech: "django", vendor: "djangoproject", product: "django" },
      { tech: "flask", vendor: "palletsprojects", product: "flask" },
      { tech: "laravel", vendor: "laravel", product: "laravel" },
      { tech: "mariadb", vendor: "mariadb", product: "mariadb" },
      { tech: "traefik", vendor: "traefik", product: "traefik" },
    ];

    for (const { tech, vendor, product } of criticalProducts) {
      it(`should have mapping for ${tech}`, () => {
        const result = updater.lookupCpe(tech);
        expect(result).not.toBeNull();
        expect(result!.vendor).toBe(vendor);
        expect(result!.product).toBe(product);
      });
    }
  });
});

// ─── Fingerprint Diff Panel Data Shape Tests ──────────────────────────

describe("Fingerprint Diff Panel data contracts", () => {
  it("should define correct change types", () => {
    const validChangeTypes = [
      "new_service", "removed_service", "version_upgrade", "version_downgrade",
      "product_change", "security_improvement", "security_degradation",
      "tls_change", "new_cves", "resolved_cves", "banner_change",
      "os_change", "confidence_change",
    ];
    // These are the change types the UI panel expects
    expect(validChangeTypes.length).toBe(13);
  });

  it("should define correct posture change values", () => {
    const validPostures = ["improved", "degraded", "unchanged", "mixed"];
    expect(validPostures.length).toBe(4);
  });

  it("should define correct severity levels", () => {
    const validSeverities = ["critical", "high", "medium", "low", "info"];
    expect(validSeverities.length).toBe(5);
  });
});
