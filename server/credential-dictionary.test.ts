/**
 * Tests for expanded credential dictionary and enhanced technology matching.
 * Covers: dictionary coverage, matching by name/vendor/CPE/banner/title/port,
 * DVWA-specific matching, generic fallback, and deduplication.
 */
import { describe, it, expect } from "vitest";
import {
  BUILTIN_DEFAULT_CREDS,
  matchCredentialsForTechnology,
  matchCredentialsForAsset,
} from "./lib/oem-default-creds";
import { getCredentialsForService } from "./lib/credential-tester";

describe("Credential Dictionary Coverage", () => {
  it("should contain 300+ credential entries", () => {
    expect(BUILTIN_DEFAULT_CREDS.length).toBeGreaterThanOrEqual(300);
  });

  it("should cover all major categories", () => {
    const vendors = new Set(BUILTIN_DEFAULT_CREDS.map(c => c.vendor));
    // Web apps
    expect(vendors.has("DVWA")).toBe(true);
    expect(vendors.has("WordPress")).toBe(true);
    expect(vendors.has("Apache")).toBe(true); // Tomcat is under vendor "Apache"
    expect(vendors.has("Jenkins")).toBe(true);
    // Databases
    expect(vendors.has("MySQL")).toBe(true);
    expect(vendors.has("PostgreSQL")).toBe(true);
    expect(vendors.has("MongoDB")).toBe(true);
    expect(vendors.has("Redis")).toBe(true);
    // Network devices
    expect(vendors.has("Cisco")).toBe(true);
    expect(vendors.has("MikroTik")).toBe(true);
    // Management
    expect(vendors.has("Grafana")).toBe(true);
    expect(vendors.has("Portainer")).toBe(true);
  });

  it("should have required fields on every entry", () => {
    for (const cred of BUILTIN_DEFAULT_CREDS) {
      expect(cred.vendor).toBeTruthy();
      expect(cred.product).toBeTruthy();
      expect(cred.protocol).toBeTruthy();
      expect(typeof cred.port).toBe("number");
      expect(typeof cred.username).toBe("string");
      expect(typeof cred.password).toBe("string");
      expect(cred.accessLevel).toBeTruthy();
      expect(Array.isArray(cred.tags)).toBe(true);
      expect(cred.tags.length).toBeGreaterThan(0);
    }
  });

  it("should have unique vendor+product+username+password combinations (no exact dupes)", () => {
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const cred of BUILTIN_DEFAULT_CREDS) {
      const key = `${cred.vendor}:${cred.product}:${cred.port}:${cred.username}:${cred.password}`;
      if (seen.has(key)) dupes.push(key);
      seen.add(key);
    }
    expect(dupes).toEqual([]);
  });
});

describe("matchCredentialsForTechnology — Name/Vendor Matching", () => {
  it("should match DVWA by name", () => {
    const matches = matchCredentialsForTechnology({ name: "DVWA", port: 80, protocol: "http" });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.vendor === "DVWA")).toBe(true);
    expect(matches.some(m => m.username === "admin" && m.password === "password")).toBe(true);
  });

  it("should match Tomcat by name", () => {
    const matches = matchCredentialsForTechnology({ name: "Apache Tomcat", port: 8080, protocol: "http" });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.vendor === "Apache" && m.product === "Tomcat")).toBe(true);
    expect(matches.some(m => m.username === "tomcat" && m.password === "tomcat")).toBe(true);
  });

  it("should match Jenkins by name", () => {
    const matches = matchCredentialsForTechnology({ name: "Jenkins", port: 8080, protocol: "http" });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.vendor === "Jenkins")).toBe(true);
  });

  it("should match WordPress by vendor", () => {
    const matches = matchCredentialsForTechnology({ vendor: "WordPress", port: 80, protocol: "http" });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.vendor === "WordPress")).toBe(true);
  });

  it("should match MySQL by name", () => {
    const matches = matchCredentialsForTechnology({ name: "MySQL", port: 3306, protocol: "mysql" });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.vendor === "MySQL")).toBe(true);
    expect(matches.some(m => m.username === "root" && m.password === "")).toBe(true);
  });

  it("should match by CPE string", () => {
    const matches = matchCredentialsForTechnology({ cpe: "cpe:/a:apache:tomcat:9.0", port: 8080, protocol: "http" });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.vendor === "Apache" && m.product === "Tomcat")).toBe(true);
  });
});

describe("matchCredentialsForTechnology — Banner/Title Matching", () => {
  it("should match DVWA from page title", () => {
    const matches = matchCredentialsForTechnology({
      name: "PHP Web Application",
      port: 80,
      protocol: "http",
      pageTitle: "Damn Vulnerable Web Application (DVWA)",
    });
    expect(matches.some(m => m.vendor === "DVWA")).toBe(true);
  });

  it("should match Tomcat from banner", () => {
    const matches = matchCredentialsForTechnology({
      name: "HTTP Server",
      port: 8080,
      protocol: "http",
      banner: "Apache-Coyote/1.1 Tomcat/9.0.50",
    });
    expect(matches.some(m => m.vendor === "Apache" && m.product === "Tomcat")).toBe(true);
  });

  it("should match phpMyAdmin from page title", () => {
    const matches = matchCredentialsForTechnology({
      name: "PHP Application",
      port: 80,
      protocol: "http",
      pageTitle: "phpMyAdmin - Login",
    });
    expect(matches.some(m => m.vendor === "phpMyAdmin")).toBe(true);
  });

  it("should match Grafana from banner", () => {
    const matches = matchCredentialsForTechnology({
      name: "Web Application",
      port: 3000,
      protocol: "http",
      banner: "Grafana v10.2.0",
    });
    expect(matches.some(m => m.vendor === "Grafana")).toBe(true);
  });
});

describe("matchCredentialsForTechnology — Port-Based Generic Fallback", () => {
  it("should return generic web creds for port 80 when no specific match", () => {
    const matches = matchCredentialsForTechnology({ name: "unknown", port: 80, protocol: "http" });
    expect(matches.some(m => m.vendor === "Generic" && m.product === "Web Admin")).toBe(true);
  });

  it("should return generic SSH creds for port 22", () => {
    const matches = matchCredentialsForTechnology({ name: "unknown", port: 22, protocol: "ssh" });
    expect(matches.some(m => m.vendor === "Generic" && m.product === "Linux SSH")).toBe(true);
  });

  it("should return generic RDP creds for port 3389", () => {
    const matches = matchCredentialsForTechnology({ name: "unknown", port: 3389, protocol: "rdp" });
    expect(matches.some(m => m.vendor === "Generic" && m.product === "Windows RDP")).toBe(true);
  });

  it("should return generic web creds for common web ports", () => {
    for (const port of [8080, 8443, 8000, 3000, 5000]) {
      const matches = matchCredentialsForTechnology({ name: "unknown", port, protocol: "http" });
      expect(matches.some(m => m.vendor === "Generic")).toBe(true);
    }
  });
});

describe("getCredentialsForService — Integration", () => {
  it("should return DVWA creds when technology name includes DVWA", () => {
    const creds = getCredentialsForService({
      host: "192.168.1.100",
      port: 80,
      protocol: "http",
      technologies: [{ name: "DVWA" }],
    });
    expect(creds.some(c => c.username === "admin" && c.password === "password")).toBe(true);
  });

  it("should return Tomcat creds when banner mentions Tomcat", () => {
    const creds = getCredentialsForService({
      host: "192.168.1.100",
      port: 8080,
      protocol: "http",
      product: "Apache Tomcat",
      banner: "Apache-Coyote/1.1 Tomcat",
    });
    expect(creds.some(c => c.username === "tomcat" && c.password === "tomcat")).toBe(true);
  });

  it("should return generic creds as fallback when no specific match", () => {
    const creds = getCredentialsForService({
      host: "192.168.1.100",
      port: 80,
      protocol: "http",
    });
    expect(creds.length).toBeGreaterThan(0);
    expect(creds.every(c => c.vendor === "Generic")).toBe(true);
  });

  it("should deduplicate credentials across multiple matching sources", () => {
    const creds = getCredentialsForService({
      host: "192.168.1.100",
      port: 80,
      protocol: "http",
      technologies: [{ name: "DVWA" }],
      product: "DVWA",
      banner: "DVWA Login Page",
    });
    // Check no duplicate username:password:protocol combos
    const seen = new Set<string>();
    for (const c of creds) {
      const key = `${c.username}:${c.password}:${c.protocol}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
  });

  it("should pass banner data through to matchCredentialsForTechnology", () => {
    const creds = getCredentialsForService({
      host: "192.168.1.100",
      port: 3000,
      protocol: "http",
      technologies: [{ name: "Web Application" }],
      banner: "Grafana v10.2.0",
    });
    expect(creds.some(c => c.vendor === "Grafana")).toBe(true);
  });
});

describe("matchCredentialsForAsset — Grouped Output", () => {
  it("should group credentials by service", () => {
    const result = matchCredentialsForAsset([
      { name: "DVWA", port: 80, protocol: "http" },
      { name: "MySQL", port: 3306, protocol: "mysql" },
    ]);
    expect(result.length).toBeGreaterThanOrEqual(2);
    // Should have at least one web service and one database service
    const services = result.map(r => r.service);
    expect(services.some(s => s.includes("DVWA"))).toBe(true);
    expect(services.some(s => s.includes("MySQL"))).toBe(true);
  });

  it("should deduplicate credentials within each service group", () => {
    const result = matchCredentialsForAsset([
      { name: "DVWA", port: 80, protocol: "http" },
    ]);
    for (const group of result) {
      const seen = new Set<string>();
      for (const c of group.credentials) {
        const key = `${c.username}:${c.password}`;
        expect(seen.has(key)).toBe(false);
        seen.add(key);
      }
    }
  });
});

describe("Credential Dictionary — Security Training Apps", () => {
  it("should have DVWA default credentials", () => {
    const dvwa = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "DVWA");
    expect(dvwa.length).toBeGreaterThanOrEqual(2);
    expect(dvwa.some(c => c.username === "admin" && c.password === "password")).toBe(true);
  });

  it("should have bWAPP default credentials", () => {
    const bwapp = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "bWAPP");
    expect(bwapp.length).toBeGreaterThanOrEqual(1);
    expect(bwapp.some(c => c.username === "bee" && c.password === "bug")).toBe(true);
  });

  it("should have OWASP Juice Shop default credentials", () => {
    const juice = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "OWASP");
    expect(juice.some(c => c.product.includes("Juice Shop"))).toBe(true);
  });

  it("should have WebGoat default credentials", () => {
    const wg = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "OWASP" && c.product.includes("WebGoat"));
    expect(wg.length).toBeGreaterThanOrEqual(1);
  });

  it("should have Metasploitable default credentials", () => {
    const meta = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "Metasploitable");
    expect(meta.length).toBeGreaterThanOrEqual(1);
    expect(meta.some(c => c.username === "msfadmin" && c.password === "msfadmin")).toBe(true);
  });
});

describe("Credential Dictionary — Network Devices", () => {
  it("should have Cisco default credentials", () => {
    const cisco = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "Cisco");
    expect(cisco.length).toBeGreaterThanOrEqual(3);
  });

  it("should have MikroTik default credentials", () => {
    const mikrotik = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "MikroTik");
    expect(mikrotik.length).toBeGreaterThanOrEqual(1);
    expect(mikrotik.some(c => c.username === "admin" && c.password === "")).toBe(true);
  });

  it("should have Ubiquiti default credentials", () => {
    const ubnt = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "Ubiquiti");
    expect(ubnt.length).toBeGreaterThanOrEqual(1);
    expect(ubnt.some(c => c.username === "ubnt" && c.password === "ubnt")).toBe(true);
  });
});

describe("Credential Dictionary — Databases", () => {
  it("should have MySQL root with empty password", () => {
    const mysql = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "MySQL");
    expect(mysql.some(c => c.username === "root" && c.password === "")).toBe(true);
  });

  it("should have PostgreSQL default", () => {
    const pg = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "PostgreSQL");
    expect(pg.some(c => c.username === "postgres" && c.password === "postgres")).toBe(true);
  });

  it("should have MongoDB no-auth entry", () => {
    const mongo = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "MongoDB");
    expect(mongo.length).toBeGreaterThanOrEqual(1);
  });

  it("should have Redis no-auth entry", () => {
    const redis = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "Redis");
    expect(redis.length).toBeGreaterThanOrEqual(1);
  });
});

describe("Credential Dictionary — Container & DevOps", () => {
  it("should have Portainer default credentials", () => {
    const portainer = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "Portainer");
    expect(portainer.length).toBeGreaterThanOrEqual(1);
  });

  it("should have Grafana default credentials", () => {
    const grafana = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "Grafana");
    expect(grafana.length).toBeGreaterThanOrEqual(1);
    expect(grafana.some(c => c.username === "admin" && c.password === "admin")).toBe(true);
  });

  it("should have GitLab default credentials", () => {
    const gitlab = BUILTIN_DEFAULT_CREDS.filter(c => c.vendor === "GitLab");
    expect(gitlab.length).toBeGreaterThanOrEqual(1);
  });
});
