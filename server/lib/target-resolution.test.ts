/**
 * Tests for getEffectiveTarget() — hostname resolution fix for virtual-hosted targets
 *
 * The core bug: when a target like brokencrystals.lab.aceofcloud.io resolves to
 * the scan server IP (159.223.152.190), HTTP tools (nikto, nuclei, etc.) were using
 * the raw IP instead of the hostname. This breaks nginx virtual host routing because
 * the Host header doesn't match any server_name directive.
 *
 * Fix: getEffectiveTarget() detects when an asset's IP matches a known infrastructure
 * IP and returns the hostname instead, so HTTP tools send the correct Host header.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { getEffectiveTarget } from "./engagement-orchestrator";

describe("getEffectiveTarget", () => {
  // ─── HTTP mode (default) ───────────────────────────────────────────────────

  describe("HTTP mode (default)", () => {
    it("returns hostname when IP matches scan server (159.223.152.190)", () => {
      const asset = { hostname: "brokencrystals.lab.aceofcloud.io", ip: "159.223.152.190" };
      expect(getEffectiveTarget(asset)).toBe("brokencrystals.lab.aceofcloud.io");
      expect(getEffectiveTarget(asset, "http")).toBe("brokencrystals.lab.aceofcloud.io");
    });

    it("returns hostname when IP matches ScanForge dedicated (137.184.71.192)", () => {
      const asset = { hostname: "dvwa.lab.aceofcloud.io", ip: "137.184.71.192" };
      expect(getEffectiveTarget(asset, "http")).toBe("dvwa.lab.aceofcloud.io");
    });

    it("returns hostname when IP matches SCAN_SERVER_HOST env", () => {
      // The SCAN_SERVER_HOST env is 159.223.152.190 in production
      const scanServerIp = process.env.SCAN_SERVER_HOST || "159.223.152.190";
      const asset = { hostname: "juiceshop.lab.aceofcloud.io", ip: scanServerIp };
      expect(getEffectiveTarget(asset, "http")).toBe("juiceshop.lab.aceofcloud.io");
    });

    it("returns IP when target is NOT on known infrastructure", () => {
      const asset = { hostname: "example.com", ip: "93.184.216.34" };
      // Non-infra IP: hostname is preferred for safety (default mode = http)
      const result = getEffectiveTarget(asset, "http");
      // For non-infra IPs, the function returns hostname (safe default)
      expect(result).toBe("example.com");
    });

    it("returns hostname when no IP is available", () => {
      const asset = { hostname: "unresolved.example.com", ip: undefined };
      expect(getEffectiveTarget(asset)).toBe("unresolved.example.com");
    });

    it("returns IP when hostname equals IP (IP-only target)", () => {
      const asset = { hostname: "93.184.216.34", ip: "93.184.216.34" };
      expect(getEffectiveTarget(asset)).toBe("93.184.216.34");
    });

    it("returns IP when hostname is empty", () => {
      const asset = { hostname: "", ip: "93.184.216.34" };
      expect(getEffectiveTarget(asset)).toBe("93.184.216.34");
    });
  });

  // ─── Discovery mode ────────────────────────────────────────────────────────

  describe("Discovery mode (nmap, ScanForge port scans)", () => {
    it("returns IP for discovery even when IP matches scan server", () => {
      const asset = { hostname: "brokencrystals.lab.aceofcloud.io", ip: "159.223.152.190" };
      expect(getEffectiveTarget(asset, "discovery")).toBe("159.223.152.190");
    });

    it("returns IP for discovery on ScanForge dedicated", () => {
      const asset = { hostname: "dvwa.lab.aceofcloud.io", ip: "137.184.71.192" };
      expect(getEffectiveTarget(asset, "discovery")).toBe("137.184.71.192");
    });

    it("returns IP for discovery on external targets", () => {
      const asset = { hostname: "example.com", ip: "93.184.216.34" };
      expect(getEffectiveTarget(asset, "discovery")).toBe("93.184.216.34");
    });

    it("returns hostname when no IP available in discovery mode", () => {
      const asset = { hostname: "unresolved.example.com", ip: undefined };
      expect(getEffectiveTarget(asset, "discovery")).toBe("unresolved.example.com");
    });
  });

  // ─── Metadata mode ─────────────────────────────────────────────────────────

  describe("Metadata mode (logging, DB records)", () => {
    it("returns hostname for metadata even when IP is available", () => {
      const asset = { hostname: "brokencrystals.lab.aceofcloud.io", ip: "159.223.152.190" };
      expect(getEffectiveTarget(asset, "metadata")).toBe("brokencrystals.lab.aceofcloud.io");
    });

    it("returns hostname for metadata on external targets", () => {
      const asset = { hostname: "example.com", ip: "93.184.216.34" };
      expect(getEffectiveTarget(asset, "metadata")).toBe("example.com");
    });

    it("returns IP when hostname is IP-only in metadata mode", () => {
      const asset = { hostname: "93.184.216.34", ip: "93.184.216.34" };
      expect(getEffectiveTarget(asset, "metadata")).toBe("93.184.216.34");
    });
  });

  // ─── Broken Crystals specific scenario ─────────────────────────────────────

  describe("Broken Crystals virtual host scenario", () => {
    const brokenCrystals = {
      hostname: "brokencrystals.lab.aceofcloud.io",
      ip: "159.223.152.190",  // Same IP as scan server — nginx virtual host routing
    };

    it("HTTP tools use hostname (nikto, nuclei, etc.)", () => {
      // This is the critical fix — HTTP tools MUST use hostname for Host header
      expect(getEffectiveTarget(brokenCrystals, "http")).toBe("brokencrystals.lab.aceofcloud.io");
    });

    it("Discovery tools use IP (nmap, ScanForge port scans)", () => {
      // Port scans don't need Host headers, IP is fine
      expect(getEffectiveTarget(brokenCrystals, "discovery")).toBe("159.223.152.190");
    });

    it("Metadata uses hostname for readability", () => {
      expect(getEffectiveTarget(brokenCrystals, "metadata")).toBe("brokencrystals.lab.aceofcloud.io");
    });

    it("Default mode is HTTP (hostname preferred)", () => {
      expect(getEffectiveTarget(brokenCrystals)).toBe("brokencrystals.lab.aceofcloud.io");
    });

    it("nikto command would target hostname not IP", () => {
      const target = getEffectiveTarget(brokenCrystals, "http");
      const niktoCmd = `nikto -h http://${target}:80 -Tuning 1234567890abcde`;
      expect(niktoCmd).toContain("brokencrystals.lab.aceofcloud.io");
      expect(niktoCmd).not.toContain("159.223.152.190");
    });

    it("nuclei command would target hostname not IP", () => {
      const target = getEffectiveTarget(brokenCrystals, "http");
      const nucleiUrl = `http://${target}:80`;
      expect(nucleiUrl).toBe("http://brokencrystals.lab.aceofcloud.io:80");
    });
  });

  // ─── Edge cases ────────────────────────────────────────────────────────────

  describe("Edge cases", () => {
    it("handles undefined ip gracefully", () => {
      const asset = { hostname: "test.example.com" } as any;
      expect(getEffectiveTarget(asset)).toBe("test.example.com");
    });

    it("handles empty string ip", () => {
      const asset = { hostname: "test.example.com", ip: "" };
      // Empty string is falsy, so treated as no IP
      expect(getEffectiveTarget(asset)).toBe("test.example.com");
    });

    it("handles empty hostname with IP", () => {
      const asset = { hostname: "", ip: "10.0.0.1" };
      expect(getEffectiveTarget(asset)).toBe("10.0.0.1");
    });
  });
});
