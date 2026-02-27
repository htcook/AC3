/**
 * Tests for Nuclei Credential Mapper
 *
 * Validates that OEM default credentials are correctly mapped to
 * Nuclei default-login template IDs and that the injection pipeline
 * produces correct CLI arguments and summaries.
 */

import { describe, it, expect } from "vitest";
import {
  buildNucleiCredentialInjection,
  buildNucleiCliArgs,
  getCredentialInjectionSummary,
  getCredentialInjectionForTargets,
} from "./lib/nuclei-credential-mapper";
import type { CredentialCandidate } from "./lib/credential-tester";

// ─── Test Fixtures ──────────────────────────────────────────────────────────

const tomcatCred: CredentialCandidate = {
  vendor: "Apache",
  product: "Tomcat",
  protocol: "http",
  username: "tomcat",
  password: "tomcat",
  accessLevel: "admin",
  source: "OEM database",
};

const jenkinsCred: CredentialCandidate = {
  vendor: "Jenkins",
  product: "Jenkins",
  protocol: "http",
  username: "admin",
  password: "admin",
  accessLevel: "admin",
  source: "OEM database",
};

const sshCred: CredentialCandidate = {
  vendor: "Generic",
  product: "OpenSSH",
  protocol: "ssh",
  username: "root",
  password: "root",
  accessLevel: "root",
  source: "OEM database",
};

const mysqlCred: CredentialCandidate = {
  vendor: "Oracle",
  product: "MySQL",
  protocol: "mysql",
  username: "root",
  password: "",
  accessLevel: "admin",
  source: "OEM database",
};

const redisCred: CredentialCandidate = {
  vendor: "Redis",
  product: "Redis",
  protocol: "redis",
  username: "",
  password: "",
  accessLevel: "admin",
  source: "OEM database",
};

const ciscoCred: CredentialCandidate = {
  vendor: "Cisco",
  product: "IOS",
  protocol: "http",
  username: "admin",
  password: "cisco",
  accessLevel: "admin",
  source: "OEM database",
};

const grafanaCred: CredentialCandidate = {
  vendor: "Grafana",
  product: "Grafana",
  protocol: "http",
  username: "admin",
  password: "admin",
  accessLevel: "admin",
  source: "OEM database",
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("buildNucleiCredentialInjection", () => {
  it("maps Tomcat credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["https://target.com:8080"],
      [tomcatCred]
    );

    expect(result.templates.length).toBeGreaterThan(0);
    expect(result.templateIds).toContain("default-logins/apache/tomcat-default-login");
    expect(result.templates[0].variables.username).toBe("tomcat");
    expect(result.templates[0].variables.password).toBe("tomcat");
    expect(result.templates[0].severity).toBe("high");
  });

  it("maps Jenkins credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["https://jenkins.target.com"],
      [jenkinsCred]
    );

    expect(result.templateIds).toContain("default-logins/jenkins/jenkins-default-login");
    expect(result.templates.some(t => t.name === "Jenkins Default Login")).toBe(true);
  });

  it("maps SSH credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["10.0.0.1:22"],
      [sshCred]
    );

    expect(result.templateIds).toContain("default-logins/ssh/ssh-default-login");
    expect(result.templates[0].protocol).toBe("ssh");
  });

  it("maps MySQL credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["10.0.0.1:3306"],
      [mysqlCred]
    );

    expect(result.templateIds).toContain("default-logins/mysql/mysql-default-login");
    expect(result.templates[0].severity).toBe("critical");
  });

  it("maps Redis credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["10.0.0.1:6379"],
      [redisCred]
    );

    expect(result.templateIds).toContain("default-logins/redis/redis-default-login");
  });

  it("maps Cisco credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["https://192.168.1.1"],
      [ciscoCred]
    );

    expect(result.templateIds).toContain("default-logins/cisco/cisco-default-login");
    expect(result.templates[0].severity).toBe("critical");
  });

  it("maps Grafana credentials to the correct Nuclei template", () => {
    const result = buildNucleiCredentialInjection(
      ["https://grafana.internal.com:3000"],
      [grafanaCred]
    );

    expect(result.templateIds).toContain("default-logins/grafana/grafana-default-login");
  });

  it("handles multiple credentials for the same target", () => {
    const result = buildNucleiCredentialInjection(
      ["https://target.com"],
      [tomcatCred, jenkinsCred, grafanaCred]
    );

    expect(result.stats.totalCredentials).toBe(3);
    expect(result.stats.totalTemplates).toBe(3);
    expect(result.templateIds).toContain("default-logins/apache/tomcat-default-login");
    expect(result.templateIds).toContain("default-logins/jenkins/jenkins-default-login");
    expect(result.templateIds).toContain("default-logins/grafana/grafana-default-login");
  });

  it("deduplicates template IDs when same credential appears twice", () => {
    const result = buildNucleiCredentialInjection(
      ["https://target.com"],
      [tomcatCred, { ...tomcatCred }] // duplicate
    );

    // Should deduplicate
    const tomcatTemplates = result.templateIds.filter(
      id => id === "default-logins/apache/tomcat-default-login"
    );
    expect(tomcatTemplates.length).toBe(1);
  });

  it("returns empty injection when no credentials match", () => {
    const unknownCred: CredentialCandidate = {
      vendor: "UnknownVendor",
      product: "UnknownProduct",
      protocol: "unknown",
      username: "admin",
      password: "admin",
      accessLevel: "admin",
      source: "test",
    };

    const result = buildNucleiCredentialInjection(
      ["https://target.com"],
      [unknownCred]
    );

    expect(result.templates.length).toBe(0);
    expect(result.templateIds.length).toBe(0);
    expect(result.stats.totalTemplates).toBe(0);
  });

  it("returns empty injection when no credentials provided", () => {
    const result = buildNucleiCredentialInjection(
      ["https://target.com"],
      []
    );

    expect(result.templates.length).toBe(0);
    expect(result.stats.totalCredentials).toBe(0);
  });

  it("tracks protocol distribution in stats", () => {
    const result = buildNucleiCredentialInjection(
      ["https://target.com", "10.0.0.1:22", "10.0.0.1:3306"],
      [tomcatCred, sshCred, mysqlCred]
    );

    expect(result.stats.byProtocol).toHaveProperty("http");
    expect(result.stats.byProtocol).toHaveProperty("ssh");
    expect(result.stats.byProtocol).toHaveProperty("mysql");
  });

  it("marks all targets as having credentials when templates are found", () => {
    const targets = ["https://target1.com", "https://target2.com"];
    const result = buildNucleiCredentialInjection(targets, [tomcatCred]);

    // When credentials exist, all targets get tested
    expect(result.targets.length).toBe(2);
    expect(result.stats.targetsWithCredentials).toBe(2);
  });
});

describe("buildNucleiCliArgs", () => {
  it("generates correct CLI arguments for a single template", () => {
    const injection = buildNucleiCredentialInjection(
      ["https://target.com"],
      [tomcatCred]
    );

    const args = buildNucleiCliArgs(injection);

    expect(args).toContain("-t");
    expect(args).toContain("default-logins/apache/tomcat-default-login");
    expect(args).toContain("-var");
    expect(args.some(a => a.includes("username=tomcat"))).toBe(true);
    expect(args.some(a => a.includes("password=tomcat"))).toBe(true);
  });

  it("generates correct CLI arguments for multiple templates", () => {
    const injection = buildNucleiCredentialInjection(
      ["https://target.com"],
      [tomcatCred, jenkinsCred]
    );

    const args = buildNucleiCliArgs(injection);

    // Should have -t flags for both templates
    const tFlags = args.filter((_, i) => i > 0 && args[i - 1] === "-t");
    expect(tFlags.length).toBe(2);
  });

  it("returns empty array when no templates matched", () => {
    const injection = buildNucleiCredentialInjection([], []);
    const args = buildNucleiCliArgs(injection);
    expect(args.length).toBe(0);
  });
});

describe("getCredentialInjectionSummary", () => {
  it("returns descriptive summary when credentials are found", () => {
    const injection = buildNucleiCredentialInjection(
      ["https://target.com"],
      [tomcatCred, jenkinsCred]
    );

    const summary = getCredentialInjectionSummary(injection);

    expect(summary).toContain("2 credential(s)");
    expect(summary).toContain("Nuclei template(s)");
    expect(summary).toContain("Tomcat");
    expect(summary).toContain("Jenkins");
  });

  it("returns 'no credentials' message when none found", () => {
    const injection = buildNucleiCredentialInjection([], []);
    const summary = getCredentialInjectionSummary(injection);
    expect(summary).toContain("No default credentials");
  });
});

describe("getCredentialInjectionForTargets", () => {
  it("parses URL targets and returns injection data", async () => {
    const result = await getCredentialInjectionForTargets([
      "https://target.com",
      "http://10.0.0.1:8080",
    ]);

    // Should return a valid injection structure
    expect(result).toHaveProperty("targets");
    expect(result).toHaveProperty("templateIds");
    expect(result).toHaveProperty("variables");
    expect(result).toHaveProperty("templates");
    expect(result).toHaveProperty("stats");
    expect(result.stats).toHaveProperty("totalTargets", 2);
  });

  it("parses host:port targets correctly", async () => {
    const result = await getCredentialInjectionForTargets([
      "10.0.0.1:22",
      "10.0.0.1:3306",
    ]);

    expect(result.stats.totalTargets).toBe(2);
  });

  it("handles plain hostname targets", async () => {
    const result = await getCredentialInjectionForTargets([
      "example.com",
    ]);

    expect(result.stats.totalTargets).toBe(1);
  });

  it("handles empty target list", async () => {
    const result = await getCredentialInjectionForTargets([]);
    expect(result.stats.totalTargets).toBe(0);
    expect(result.templates.length).toBe(0);
  });
});
