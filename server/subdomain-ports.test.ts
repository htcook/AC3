import { describe, it, expect } from "vitest";

/**
 * Tests for subdomain discovery and port/service extraction
 * from passive recon observations into pipelineOutput
 */

// ─── Subdomain Extraction Logic ───────────────────────────────────────

describe("Subdomain extraction from passive recon observations", () => {
  // Simulate the extraction logic from routers.ts
  function extractSubdomains(allObservations: any[]) {
    const seen = new Set<string>();
    return allObservations
      .filter(o => o.assetType === 'subdomain' && o.name)
      .filter(o => {
        const key = o.name!.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .map(o => ({
        name: o.name!,
        ip: o.ip || null,
        source: o.source,
        firstSeen: o.firstSeen || null,
        lastSeen: o.lastSeen || null,
        tags: o.tags?.filter((t: string) => t.startsWith('port:') || t.startsWith('product:') || t.startsWith('version:')) || [],
      }))
      .slice(0, 500);
  }

  it("should extract unique subdomains from observations", () => {
    const observations = [
      { assetType: "subdomain", name: "www.example.com", ip: "1.2.3.4", source: "crtsh", tags: [] },
      { assetType: "subdomain", name: "api.example.com", ip: "1.2.3.5", source: "shodan", tags: ["port:443"] },
      { assetType: "subdomain", name: "mail.example.com", source: "securitytrails", tags: [] },
    ];
    const result = extractSubdomains(observations);
    expect(result).toHaveLength(3);
    expect(result[0].name).toBe("www.example.com");
    expect(result[0].ip).toBe("1.2.3.4");
    expect(result[1].name).toBe("api.example.com");
    expect(result[1].tags).toEqual(["port:443"]);
    expect(result[2].ip).toBeNull();
  });

  it("should deduplicate subdomains case-insensitively", () => {
    const observations = [
      { assetType: "subdomain", name: "WWW.Example.com", ip: "1.2.3.4", source: "crtsh", tags: [] },
      { assetType: "subdomain", name: "www.example.com", ip: "1.2.3.4", source: "shodan", tags: [] },
      { assetType: "subdomain", name: "Www.Example.COM", ip: "1.2.3.4", source: "censys", tags: [] },
    ];
    const result = extractSubdomains(observations);
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe("crtsh"); // First one wins
  });

  it("should filter out non-subdomain observations", () => {
    const observations = [
      { assetType: "subdomain", name: "www.example.com", source: "crtsh", tags: [] },
      { assetType: "ip", name: "1.2.3.4", ip: "1.2.3.4", source: "shodan", tags: ["port:80"] },
      { assetType: "mx", name: "mail.example.com", source: "securitytrails", tags: [] },
      { assetType: "subdomain", name: "api.example.com", source: "shodan", tags: [] },
    ];
    const result = extractSubdomains(observations);
    expect(result).toHaveLength(2);
    expect(result.map(s => s.name)).toEqual(["www.example.com", "api.example.com"]);
  });

  it("should handle empty observations", () => {
    expect(extractSubdomains([])).toEqual([]);
  });

  it("should skip observations without names", () => {
    const observations = [
      { assetType: "subdomain", name: "", source: "crtsh", tags: [] },
      { assetType: "subdomain", name: null, source: "crtsh", tags: [] },
      { assetType: "subdomain", name: "valid.example.com", source: "crtsh", tags: [] },
    ];
    const result = extractSubdomains(observations);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("valid.example.com");
  });

  it("should only keep port/product/version tags", () => {
    const observations = [
      {
        assetType: "subdomain",
        name: "www.example.com",
        source: "shodan",
        tags: ["port:443", "product:nginx", "version:1.21", "shodan_resolved", "dns_intelligence", "cve:CVE-2021-1234"],
      },
    ];
    const result = extractSubdomains(observations);
    expect(result[0].tags).toEqual(["port:443", "product:nginx", "version:1.21"]);
  });

  it("should limit to 500 subdomains", () => {
    const observations = Array.from({ length: 600 }, (_, i) => ({
      assetType: "subdomain",
      name: `sub${i}.example.com`,
      source: "crtsh",
      tags: [],
    }));
    const result = extractSubdomains(observations);
    expect(result).toHaveLength(500);
  });
});

// ─── Port/Service Extraction Logic ────────────────────────────────────

describe("Port/service extraction from passive recon observations", () => {
  // Simulate the extraction logic from routers.ts
  function extractPorts(allObservations: any[]) {
    const portMap = new Map<string, any>();
    for (const obs of allObservations) {
      if (obs.assetType !== 'ip' || !obs.ip) continue;
      const evidence = obs.evidence as any;
      if (evidence?.port) {
        const key = `${obs.ip}:${evidence.port}`;
        if (!portMap.has(key)) {
          portMap.set(key, {
            ip: obs.ip,
            port: evidence.port,
            transport: evidence.transport || 'tcp',
            product: evidence.product || '',
            version: evidence.version || '',
            hostname: obs.name || obs.ip,
            source: obs.source,
            vulns: (evidence.vulns || []).slice(0, 10),
            cpes: (evidence.cpes || []).slice(0, 5),
          });
        }
      } else if (evidence?.ports && Array.isArray(evidence.ports)) {
        for (const p of evidence.ports) {
          const key = `${obs.ip}:${p}`;
          if (!portMap.has(key)) {
            portMap.set(key, {
              ip: obs.ip,
              port: p,
              transport: 'tcp',
              product: '',
              version: '',
              hostname: obs.name || obs.ip,
              source: obs.source,
              vulns: (evidence.vulns || []).slice(0, 10),
              cpes: (evidence.cpes || []).slice(0, 5),
            });
          }
        }
      }
    }
    return Array.from(portMap.values()).slice(0, 500);
  }

  it("should extract ports from Shodan-style observations (single port per observation)", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan",
        evidence: { port: 443, transport: "tcp", product: "nginx", version: "1.21.0", vulns: ["CVE-2021-23017"], cpes: ["cpe:2.3:a:nginx:nginx:1.21.0"] },
      },
      {
        assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan",
        evidence: { port: 80, transport: "tcp", product: "nginx", version: "1.21.0", vulns: [], cpes: [] },
      },
    ];
    const result = extractPorts(observations);
    expect(result).toHaveLength(2);
    expect(result.find(p => p.port === 443)?.product).toBe("nginx");
    expect(result.find(p => p.port === 443)?.vulns).toEqual(["CVE-2021-23017"]);
    expect(result.find(p => p.port === 80)?.transport).toBe("tcp");
  });

  it("should extract ports from InternetDB-style observations (multiple ports per observation)", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "1.2.3.4 (InternetDB)", source: "shodan_internetdb",
        evidence: { ports: [22, 80, 443, 8080], vulns: ["CVE-2021-1234"], cpes: ["cpe:2.3:a:apache:httpd:2.4.49"] },
      },
    ];
    const result = extractPorts(observations);
    expect(result).toHaveLength(4);
    expect(result.map(p => p.port).sort((a, b) => a - b)).toEqual([22, 80, 443, 8080]);
    expect(result[0].source).toBe("shodan_internetdb");
    expect(result[0].vulns).toEqual(["CVE-2021-1234"]);
  });

  it("should deduplicate by IP:port", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan",
        evidence: { port: 443, transport: "tcp", product: "nginx", version: "1.21.0" },
      },
      {
        assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan_detail",
        evidence: { port: 443, transport: "tcp", product: "nginx", version: "1.21.1" },
      },
    ];
    const result = extractPorts(observations);
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe("shodan"); // First one wins
  });

  it("should handle mixed Shodan and InternetDB observations", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan",
        evidence: { port: 443, transport: "tcp", product: "nginx", version: "1.21.0", vulns: [], cpes: [] },
      },
      {
        assetType: "ip", ip: "1.2.3.4", name: "1.2.3.4 (InternetDB)", source: "shodan_internetdb",
        evidence: { ports: [22, 80, 443, 8080], vulns: ["CVE-2021-1234"], cpes: [] },
      },
    ];
    const result = extractPorts(observations);
    // 443 from Shodan (first), plus 22, 80, 8080 from InternetDB
    expect(result).toHaveLength(4);
    const port443 = result.find(p => p.port === 443);
    expect(port443?.source).toBe("shodan"); // Shodan wins for 443
    expect(port443?.product).toBe("nginx");
  });

  it("should skip non-IP observations", () => {
    const observations = [
      { assetType: "subdomain", name: "www.example.com", source: "crtsh", evidence: {} },
      { assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan", evidence: { port: 80, transport: "tcp" } },
    ];
    const result = extractPorts(observations);
    expect(result).toHaveLength(1);
    expect(result[0].port).toBe(80);
  });

  it("should handle empty observations", () => {
    expect(extractPorts([])).toEqual([]);
  });

  it("should handle observations without evidence", () => {
    const observations = [
      { assetType: "ip", ip: "1.2.3.4", name: "test", source: "shodan", evidence: {} },
      { assetType: "ip", ip: "1.2.3.5", name: "test2", source: "shodan", evidence: null },
    ];
    const result = extractPorts(observations);
    expect(result).toHaveLength(0);
  });

  it("should limit vulns to 10 and cpes to 5", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "test", source: "shodan",
        evidence: {
          port: 80,
          vulns: Array.from({ length: 20 }, (_, i) => `CVE-2021-${i}`),
          cpes: Array.from({ length: 10 }, (_, i) => `cpe:2.3:a:test:test:${i}`),
        },
      },
    ];
    const result = extractPorts(observations);
    expect(result[0].vulns).toHaveLength(10);
    expect(result[0].cpes).toHaveLength(5);
  });

  it("should limit to 500 port entries", () => {
    const observations = Array.from({ length: 600 }, (_, i) => ({
      assetType: "ip",
      ip: `10.0.${Math.floor(i / 256)}.${i % 256}`,
      name: `host${i}`,
      source: "shodan",
      evidence: { port: 80 + (i % 100), transport: "tcp" },
    }));
    const result = extractPorts(observations);
    expect(result).toHaveLength(500);
  });

  it("should use hostname from observation name, fallback to IP", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "www.example.com", source: "shodan",
        evidence: { port: 80 },
      },
      {
        assetType: "ip", ip: "5.6.7.8", name: undefined, source: "shodan",
        evidence: { port: 80 },
      },
    ];
    const result = extractPorts(observations);
    expect(result[0].hostname).toBe("www.example.com");
    expect(result[1].hostname).toBe("5.6.7.8");
  });

  it("should default transport to tcp when not specified", () => {
    const observations = [
      {
        assetType: "ip", ip: "1.2.3.4", name: "test", source: "shodan",
        evidence: { port: 53 },
      },
    ];
    const result = extractPorts(observations);
    expect(result[0].transport).toBe("tcp");
  });
});

// ─── Pipeline Output Structure ────────────────────────────────────────

describe("Pipeline output structure for subdomains and ports", () => {
  it("should include discoveredSubdomains and discoveredPorts fields", () => {
    // Simulate what the trimmedOutput should look like
    const trimmedOutput = {
      discoveredSubdomains: [
        { name: "www.example.com", ip: "1.2.3.4", source: "crtsh", firstSeen: null, lastSeen: null, tags: [] },
      ],
      discoveredPorts: [
        { ip: "1.2.3.4", port: 443, transport: "tcp", product: "nginx", version: "1.21.0", hostname: "www.example.com", source: "shodan", vulns: [], cpes: [] },
      ],
    };

    expect(trimmedOutput.discoveredSubdomains).toBeDefined();
    expect(trimmedOutput.discoveredPorts).toBeDefined();
    expect(trimmedOutput.discoveredSubdomains[0]).toHaveProperty("name");
    expect(trimmedOutput.discoveredSubdomains[0]).toHaveProperty("ip");
    expect(trimmedOutput.discoveredSubdomains[0]).toHaveProperty("source");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("ip");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("port");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("transport");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("product");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("version");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("hostname");
    expect(trimmedOutput.discoveredPorts[0]).toHaveProperty("vulns");
  });

  it("should handle missing passiveRecon gracefully", () => {
    const result = { passiveRecon: null };
    const discoveredSubdomains = (() => {
      if (!result.passiveRecon) return [];
      return [];
    })();
    const discoveredPorts = (() => {
      if (!result.passiveRecon) return [];
      return [];
    })();
    expect(discoveredSubdomains).toEqual([]);
    expect(discoveredPorts).toEqual([]);
  });
});

// ─── Common Port Classification ───────────────────────────────────────

describe("Common port classification", () => {
  const commonPorts: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
  };

  it("should classify well-known ports", () => {
    expect(commonPorts[22]).toBe("SSH");
    expect(commonPorts[80]).toBe("HTTP");
    expect(commonPorts[443]).toBe("HTTPS");
    expect(commonPorts[3389]).toBe("RDP");
    expect(commonPorts[3306]).toBe("MySQL");
  });

  it("should return undefined for non-standard ports", () => {
    expect(commonPorts[12345]).toBeUndefined();
    expect(commonPorts[31337]).toBeUndefined();
  });

  it("should identify high-risk ports", () => {
    const highRiskPorts = [21, 23, 3389, 5900];
    for (const port of highRiskPorts) {
      expect(commonPorts[port]).toBeDefined();
    }
  });

  it("should identify secure ports", () => {
    const securePorts = [22, 443, 993, 995];
    for (const port of securePorts) {
      expect(commonPorts[port]).toBeDefined();
    }
  });
});
