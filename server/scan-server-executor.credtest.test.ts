/**
 * Tests for vendor/OEM default credential integration in suggestToolCommands.
 * Verifies that when technologies are provided, OEM default credentials are
 * injected as high-priority credential tests before generic wordlist fallback.
 */
import { describe, it, expect } from "vitest";
import { suggestToolCommands } from "./lib/scan-server-executor";

describe("suggestToolCommands — OEM default credential testing", () => {
  it("should include OEM default credentials for Cisco SSH when technology is detected", () => {
    const commands = suggestToolCommands({
      hostname: "router.example.com",
      ip: "10.0.0.1",
      type: "network_device",
      ports: [{ port: 22, service: "ssh" }],
      technologies: [{ name: "Cisco IOS Router", vendor: "Cisco" }],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]") && c.purpose.includes("Cisco"));
    expect(oemCmds.length).toBeGreaterThan(0);
    expect(oemCmds[0].tool).toBe("hydra");
    expect(oemCmds[0].priority).toBe(3);
  });

  it("should include OEM default credentials for Apache Tomcat on port 8080", () => {
    const commands = suggestToolCommands({
      hostname: "app.example.com",
      ip: "10.0.0.2",
      type: "web_app",
      ports: [{ port: 8080, service: "http" }],
      technologies: [{ name: "Apache Tomcat", vendor: "Apache" }],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]") && c.purpose.includes("Tomcat"));
    expect(oemCmds.length).toBeGreaterThan(0);
    // Should have tomcat:tomcat, admin:admin, manager:manager
    const usernames = oemCmds.map(c => c.purpose);
    expect(usernames.some(u => u.includes("tomcat"))).toBe(true);
  });

  it("should include OEM default credentials for MySQL on port 3306", () => {
    const commands = suggestToolCommands({
      hostname: "db.example.com",
      ip: "10.0.0.3",
      type: "database",
      ports: [{ port: 3306, service: "mysql" }],
      technologies: [{ name: "MySQL Server", vendor: "MySQL" }],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]") && c.purpose.includes("MySQL"));
    expect(oemCmds.length).toBeGreaterThan(0);
    expect(oemCmds.some(c => c.purpose.includes("root"))).toBe(true);
  });

  it("should still include generic wordlist fallback even when OEM creds are present", () => {
    const commands = suggestToolCommands({
      hostname: "server.example.com",
      ip: "10.0.0.4",
      type: "server",
      ports: [{ port: 22, service: "ssh" }],
      technologies: [{ name: "Cisco IOS Router", vendor: "Cisco" }],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]"));
    const genericCmds = commands.filter(c => c.purpose.includes("generic wordlist"));
    expect(oemCmds.length).toBeGreaterThan(0);
    expect(genericCmds.length).toBeGreaterThan(0);
  });

  it("should not include OEM credentials when no technologies are provided", () => {
    const commands = suggestToolCommands({
      hostname: "server.example.com",
      ip: "10.0.0.5",
      type: "server",
      ports: [{ port: 22, service: "ssh" }],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]"));
    expect(oemCmds.length).toBe(0);
  });

  it("should not include OEM credentials when technologies don't match any known vendor", () => {
    const commands = suggestToolCommands({
      hostname: "server.example.com",
      ip: "10.0.0.6",
      type: "server",
      ports: [{ port: 22, service: "ssh" }],
      technologies: [{ name: "CustomApp", vendor: "UnknownVendor" }],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]"));
    expect(oemCmds.length).toBe(0);
  });

  it("should skip OEM credentials when the matched port is not open on the asset", () => {
    const commands = suggestToolCommands({
      hostname: "web.example.com",
      ip: "10.0.0.7",
      type: "web_app",
      ports: [{ port: 80, service: "http" }], // Only port 80 open, not 8080
      technologies: [{ name: "Apache Tomcat", vendor: "Apache" }],
    });

    // Tomcat defaults are on port 8080, which isn't open
    const tomcatOemCmds = commands.filter(c => c.purpose.includes("[OEM Default]") && c.purpose.includes("Tomcat") && c.purpose.includes("8080"));
    expect(tomcatOemCmds.length).toBe(0);
  });

  it("should include OEM credentials for FortiGate on HTTPS port 443", () => {
    const commands = suggestToolCommands({
      hostname: "fw.example.com",
      ip: "10.0.0.8",
      type: "network_device",
      ports: [{ port: 443, service: "https" }, { port: 22, service: "ssh" }],
      technologies: [{ name: "Fortinet FortiGate", vendor: "Fortinet" }],
    });

    const fortiCmds = commands.filter(c => c.purpose.includes("[OEM Default]") && c.purpose.includes("Fortinet"));
    expect(fortiCmds.length).toBeGreaterThan(0);
    // FortiGate defaults include empty password
    expect(fortiCmds.some(c => c.purpose.includes("(empty)"))).toBe(true);
  });

  it("should handle multiple technologies on the same asset", () => {
    const commands = suggestToolCommands({
      hostname: "multi.example.com",
      ip: "10.0.0.9",
      type: "server",
      ports: [
        { port: 22, service: "ssh" },
        { port: 3306, service: "mysql" },
        { port: 8080, service: "http" },
      ],
      technologies: [
        { name: "Cisco IOS Router", vendor: "Cisco" },
        { name: "MySQL Server", vendor: "MySQL" },
        { name: "Apache Tomcat", vendor: "Apache" },
      ],
    });

    const oemCmds = commands.filter(c => c.purpose.includes("[OEM Default]"));
    // Should have credentials for Cisco (SSH), MySQL, and Tomcat
    expect(oemCmds.some(c => c.purpose.includes("Cisco"))).toBe(true);
    expect(oemCmds.some(c => c.purpose.includes("MySQL"))).toBe(true);
    expect(oemCmds.some(c => c.purpose.includes("Tomcat"))).toBe(true);
  });

  it("OEM credential commands should come before generic wordlist commands in the sorted output", () => {
    const commands = suggestToolCommands({
      hostname: "server.example.com",
      ip: "10.0.0.10",
      type: "server",
      ports: [{ port: 22, service: "ssh" }],
      technologies: [{ name: "Cisco IOS Router", vendor: "Cisco" }],
    });

    const credCmds = commands.filter(c => c.priority === 3);
    const firstOemIdx = credCmds.findIndex(c => c.purpose.includes("[OEM Default]"));
    const firstGenericIdx = credCmds.findIndex(c => c.purpose.includes("generic wordlist"));

    // OEM commands should appear before generic ones (both are priority 3, but OEM is pushed first)
    if (firstOemIdx >= 0 && firstGenericIdx >= 0) {
      expect(firstOemIdx).toBeLessThan(firstGenericIdx);
    }
  });
});
