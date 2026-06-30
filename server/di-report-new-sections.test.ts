import { describe, it, expect } from "vitest";

/**
 * Tests for the new DI report sections:
 * - Domain Registration Details (RDAP/WHOIS)
 * - SSL Certificate Health
 * - Risky Service Exposure
 *
 * These sections are rendered client-side via jsPDF, so we test the data
 * extraction logic that feeds them from the pipeline output (server-side).
 */

describe("Domain Registration Data Extraction", () => {
  it("should extract RDAP registration data from allObservations", () => {
    const allObservations = [
      {
        source: "rdap",
        tags: ["registration_data", "clientTransferProhibited"],
        evidence: {
          handle: "EXAMPLE-DOM",
          ldhName: "example.com",
          status: ["clientTransferProhibited", "clientDeleteProhibited"],
          registrar: "Example Registrar Inc.",
          nameservers: ["ns1.example.com", "ns2.example.com"],
          events: {
            registration: "2020-01-15T00:00:00Z",
            expiration: "2027-01-15T00:00:00Z",
            last_changed: "2025-06-01T00:00:00Z",
          },
          secureDNS: { delegationSigned: true },
        },
      },
      {
        source: "shodan",
        tags: ["port:443"],
        evidence: { port: 443, product: "nginx" },
      },
    ];

    // Simulate the extraction logic from domain-intel-core.ts
    const rdapObs = allObservations.find(
      (o: any) => o.source === "rdap" && o.tags?.includes("registration_data")
    );
    expect(rdapObs).toBeDefined();
    expect(rdapObs!.evidence).toBeDefined();

    const ev = rdapObs!.evidence as any;
    const domainRegistration = {
      registrar: ev.registrar || null,
      registrationDate: ev.events?.registration || null,
      expirationDate: ev.events?.expiration || null,
      lastChanged: ev.events?.last_changed || null,
      status: ev.status || [],
      nameservers: ev.nameservers || [],
      dnssec: ev.secureDNS?.delegationSigned || false,
      handle: ev.handle || ev.ldhName || null,
    };

    expect(domainRegistration.registrar).toBe("Example Registrar Inc.");
    expect(domainRegistration.registrationDate).toBe("2020-01-15T00:00:00Z");
    expect(domainRegistration.expirationDate).toBe("2027-01-15T00:00:00Z");
    expect(domainRegistration.lastChanged).toBe("2025-06-01T00:00:00Z");
    expect(domainRegistration.status).toEqual([
      "clientTransferProhibited",
      "clientDeleteProhibited",
    ]);
    expect(domainRegistration.nameservers).toEqual([
      "ns1.example.com",
      "ns2.example.com",
    ]);
    expect(domainRegistration.dnssec).toBe(true);
    expect(domainRegistration.handle).toBe("EXAMPLE-DOM");
  });

  it("should return null when no RDAP observation exists", () => {
    const allObservations = [
      {
        source: "shodan",
        tags: ["port:443"],
        evidence: { port: 443 },
      },
    ];

    const rdapObs = allObservations.find(
      (o: any) => o.source === "rdap" && o.tags?.includes("registration_data")
    );
    expect(rdapObs).toBeUndefined();
  });

  it("should handle missing DNSSEC and status fields gracefully", () => {
    const allObservations = [
      {
        source: "rdap",
        tags: ["registration_data"],
        evidence: {
          registrar: "Minimal Registrar",
          events: { registration: "2022-03-01T00:00:00Z" },
        },
      },
    ];

    const rdapObs = allObservations.find(
      (o: any) => o.source === "rdap" && o.tags?.includes("registration_data")
    );
    const ev = rdapObs!.evidence as any;
    const domainRegistration = {
      registrar: ev.registrar || null,
      registrationDate: ev.events?.registration || null,
      expirationDate: ev.events?.expiration || null,
      lastChanged: ev.events?.last_changed || null,
      status: ev.status || [],
      nameservers: ev.nameservers || [],
      dnssec: ev.secureDNS?.delegationSigned || false,
      handle: ev.handle || ev.ldhName || null,
    };

    expect(domainRegistration.registrar).toBe("Minimal Registrar");
    expect(domainRegistration.expirationDate).toBeNull();
    expect(domainRegistration.status).toEqual([]);
    expect(domainRegistration.nameservers).toEqual([]);
    expect(domainRegistration.dnssec).toBe(false);
    expect(domainRegistration.handle).toBeNull();
  });
});

describe("SSL Certificate Data Extraction", () => {
  it("should extract and deduplicate SSL certificates from observations", () => {
    const allObservations = [
      {
        name: "web.example.com",
        ip: "1.2.3.4",
        tags: ["port:443"],
        evidence: {
          port: 443,
          ssl_subject: "CN=*.example.com",
          ssl_issuer: "CN=Let's Encrypt Authority X3",
          ssl_expires: "2026-06-15T00:00:00Z",
        },
      },
      {
        name: "mail.example.com",
        ip: "1.2.3.5",
        tags: ["port:443"],
        evidence: {
          port: 443,
          ssl_subject: "CN=*.example.com",
          ssl_issuer: "CN=Let's Encrypt Authority X3",
          ssl_expires: "2026-06-15T00:00:00Z",
        },
      },
      {
        name: "api.example.com",
        ip: "1.2.3.6",
        tags: ["port:8443"],
        evidence: {
          port: 8443,
          ssl_subject: "CN=api.example.com",
          ssl_issuer: "CN=DigiCert SHA2 Extended Validation Server CA",
          ssl_expires: "2026-12-01T00:00:00Z",
        },
      },
      {
        name: "ftp.example.com",
        tags: ["port:21"],
        evidence: { port: 21, product: "vsftpd" },
      },
    ];

    const certMap = new Map<string, any>();
    for (const obs of allObservations) {
      const ev = obs.evidence as any;
      if (!ev?.ssl_subject && !ev?.ssl_issuer) continue;
      const key = `${ev.ssl_subject || ""}|${ev.ssl_issuer || ""}`;
      if (certMap.has(key)) {
        const ex = certMap.get(key);
        if (!ex.hosts.includes(obs.name || obs.ip))
          ex.hosts.push(obs.name || obs.ip);
        if (!ex.ports.includes(ev.port)) ex.ports.push(ev.port);
        continue;
      }
      certMap.set(key, {
        subject: ev.ssl_subject || null,
        issuer: ev.ssl_issuer || null,
        expires: ev.ssl_expires || null,
        hosts: [obs.name || obs.ip],
        ports: ev.port ? [ev.port] : [],
      });
    }
    const sslCertificates = Array.from(certMap.values()).slice(0, 20);

    // Should have 2 unique certs (wildcard deduped, api separate)
    expect(sslCertificates).toHaveLength(2);

    // Wildcard cert should have 2 hosts
    const wildcardCert = sslCertificates.find(
      (c) => c.subject === "CN=*.example.com"
    );
    expect(wildcardCert).toBeDefined();
    expect(wildcardCert!.hosts).toEqual([
      "web.example.com",
      "mail.example.com",
    ]);
    expect(wildcardCert!.ports).toEqual([443]);

    // API cert should have 1 host
    const apiCert = sslCertificates.find(
      (c) => c.subject === "CN=api.example.com"
    );
    expect(apiCert).toBeDefined();
    expect(apiCert!.hosts).toEqual(["api.example.com"]);
    expect(apiCert!.ports).toEqual([8443]);
  });

  it("should return empty array when no SSL observations exist", () => {
    const allObservations = [
      {
        name: "ftp.example.com",
        tags: ["port:21"],
        evidence: { port: 21, product: "vsftpd" },
      },
    ];

    const certMap = new Map<string, any>();
    for (const obs of allObservations) {
      const ev = obs.evidence as any;
      if (!ev?.ssl_subject && !ev?.ssl_issuer) continue;
      const key = `${ev.ssl_subject || ""}|${ev.ssl_issuer || ""}`;
      certMap.set(key, {
        subject: ev.ssl_subject || null,
        issuer: ev.ssl_issuer || null,
        expires: ev.ssl_expires || null,
        hosts: [obs.name || obs.ip],
        ports: ev.port ? [ev.port] : [],
      });
    }
    expect(Array.from(certMap.values())).toHaveLength(0);
  });

  it("should detect self-signed certificates", () => {
    const certs = [
      {
        subject: "CN=internal.example.com",
        issuer: "CN=internal.example.com",
        expires: "2026-12-01T00:00:00Z",
        hosts: ["internal.example.com"],
        ports: [443],
      },
      {
        subject: "CN=*.example.com",
        issuer: "CN=Let's Encrypt Authority X3",
        expires: "2026-06-15T00:00:00Z",
        hosts: ["web.example.com"],
        ports: [443],
      },
    ];

    const selfSigned = certs.filter(
      (c) => c.subject && c.issuer && c.subject === c.issuer
    );
    expect(selfSigned).toHaveLength(1);
    expect(selfSigned[0].subject).toBe("CN=internal.example.com");
  });
});

describe("Risky Service Exposure Classification", () => {
  it("should classify high-risk and medium-risk ports correctly", () => {
    const discoveredPorts = [
      { port: 22, hostname: "ssh.example.com", ip: "1.2.3.4" },
      { port: 80, hostname: "web.example.com", ip: "1.2.3.4" },
      { port: 443, hostname: "web.example.com", ip: "1.2.3.4" },
      { port: 3389, hostname: "rdp.example.com", ip: "1.2.3.5" },
      { port: 3306, hostname: "db.example.com", ip: "1.2.3.6" },
      { port: 6379, hostname: "cache.example.com", ip: "1.2.3.7" },
      { port: 161, hostname: "switch.example.com", ip: "1.2.3.8" },
    ];

    const highRiskPorts = [
      21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901,
      6379, 9200, 11211, 27017,
    ];
    const mediumRiskPorts = [53, 110, 143, 161, 389, 636, 2049, 5060];

    const riskyPorts = discoveredPorts.filter(
      (p) => highRiskPorts.includes(p.port) || mediumRiskPorts.includes(p.port)
    );

    // SSH (22) is NOT in either list, HTTP (80) and HTTPS (443) are NOT risky
    // RDP (3389), MySQL (3306), Redis (6379) are high-risk
    // SNMP (161) is medium-risk
    expect(riskyPorts).toHaveLength(4);

    const highRiskFound = riskyPorts.filter((p) =>
      highRiskPorts.includes(p.port)
    );
    const medRiskFound = riskyPorts.filter((p) =>
      mediumRiskPorts.includes(p.port)
    );

    expect(highRiskFound).toHaveLength(3); // RDP, MySQL, Redis
    expect(medRiskFound).toHaveLength(1); // SNMP
  });

  it("should return empty risky ports when only standard web ports exist", () => {
    const discoveredPorts = [
      { port: 80, hostname: "web.example.com" },
      { port: 443, hostname: "web.example.com" },
      { port: 8080, hostname: "proxy.example.com" },
    ];

    const highRiskPorts = [
      21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901,
      6379, 9200, 11211, 27017,
    ];
    const mediumRiskPorts = [53, 110, 143, 161, 389, 636, 2049, 5060];

    const riskyPorts = discoveredPorts.filter(
      (p) => highRiskPorts.includes(p.port) || mediumRiskPorts.includes(p.port)
    );

    // 8080 is in HIGH_RISK_PORTS in domainIntel.ts but NOT in the report's
    // risky port filter (which only flags the most dangerous services)
    expect(riskyPorts).toHaveLength(0);
  });

  it("should sort risky ports by severity descending", () => {
    const serviceRiskMap: Record<number, { severity: number }> = {
      3389: { severity: 9 },
      3306: { severity: 8 },
      6379: { severity: 8 },
      161: { severity: 6 },
      110: { severity: 5 },
    };

    const riskyPorts = [
      { port: 161 },
      { port: 3306 },
      { port: 3389 },
      { port: 110 },
      { port: 6379 },
    ];

    const sorted = riskyPorts.sort(
      (a, b) =>
        (serviceRiskMap[b.port]?.severity || 0) -
        (serviceRiskMap[a.port]?.severity || 0)
    );

    expect(sorted[0].port).toBe(3389); // RDP severity 9
    expect(sorted[1].port).toBe(3306); // MySQL severity 8
    expect(sorted[2].port).toBe(6379); // Redis severity 8
    expect(sorted[3].port).toBe(161); // SNMP severity 6
    expect(sorted[4].port).toBe(110); // POP3 severity 5
  });
});

describe("Registration Risk Assessment Logic", () => {
  it("should flag missing DNSSEC", () => {
    const domainRegistration = {
      dnssec: false,
      status: ["clientTransferProhibited"],
      expirationDate: "2027-01-15T00:00:00Z",
    };

    const risks: string[] = [];
    if (!domainRegistration.dnssec) {
      risks.push("DNSSEC is not enabled");
    }
    expect(risks).toHaveLength(1);
    expect(risks[0]).toContain("DNSSEC");
  });

  it("should flag missing transfer lock", () => {
    const domainRegistration = {
      dnssec: true,
      status: ["clientDeleteProhibited"],
      expirationDate: "2027-01-15T00:00:00Z",
    };

    const hasTransferLock = domainRegistration.status?.some((s: string) =>
      s.toLowerCase().includes("clienttransferprohibited")
    );
    expect(hasTransferLock).toBe(false);
  });

  it("should flag missing delete lock", () => {
    const domainRegistration = {
      dnssec: true,
      status: ["clientTransferProhibited"],
      expirationDate: "2027-01-15T00:00:00Z",
    };

    const hasDeleteLock = domainRegistration.status?.some((s: string) =>
      s.toLowerCase().includes("clientdeleteprohibited")
    );
    expect(hasDeleteLock).toBe(false);
  });

  it("should flag domain expiring within 30 days", () => {
    const soon = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString();
    const domainRegistration = {
      dnssec: true,
      status: ["clientTransferProhibited", "clientDeleteProhibited"],
      expirationDate: soon,
    };

    const daysLeft = Math.ceil(
      (new Date(domainRegistration.expirationDate).getTime() - Date.now()) /
        (1000 * 60 * 60 * 24)
    );
    expect(daysLeft).toBeLessThan(30);
    expect(daysLeft).toBeGreaterThan(0);
  });

  it("should not flag well-configured domain", () => {
    const farFuture = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    ).toISOString();
    const domainRegistration = {
      dnssec: true,
      status: ["clientTransferProhibited", "clientDeleteProhibited"],
      expirationDate: farFuture,
    };

    const risks: string[] = [];
    if (!domainRegistration.dnssec) risks.push("DNSSEC");
    const daysLeft = Math.ceil(
      (new Date(domainRegistration.expirationDate).getTime() - Date.now()) /
        (1000 * 60 * 60 * 24)
    );
    if (daysLeft < 90) risks.push("Expiry");
    const hasTransferLock = domainRegistration.status.some((s) =>
      s.toLowerCase().includes("clienttransferprohibited")
    );
    if (!hasTransferLock) risks.push("Transfer lock");
    const hasDeleteLock = domainRegistration.status.some((s) =>
      s.toLowerCase().includes("clientdeleteprohibited")
    );
    if (!hasDeleteLock) risks.push("Delete lock");

    expect(risks).toHaveLength(0);
  });

  it("should correctly match status codes with spaces (e.g. 'client transfer prohibited')", () => {
    // This was the root cause of false positives: RDAP returns space-separated status codes
    // but the old code checked for camelCase 'clienttransferprohibited' without stripping spaces
    const domainRegistration = {
      dnssec: true,
      status: ["client delete prohibited", "client renew prohibited", "client transfer prohibited", "client update prohibited"],
      expirationDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    };

    // Normalize: strip spaces and lowercase (the fix)
    const normalizedStatuses = domainRegistration.status.map((s: string) => s.toLowerCase().replace(/\s+/g, ''));
    const hasTransferLock = normalizedStatuses.some((s: string) => s.includes('clienttransferprohibited'));
    const hasDeleteLock = normalizedStatuses.some((s: string) => s.includes('clientdeleteprohibited'));

    expect(hasTransferLock).toBe(true);
    expect(hasDeleteLock).toBe(true);
  });

  it("should detect missing locks even with other space-separated status codes present", () => {
    const domainRegistration = {
      dnssec: false,
      status: ["client renew prohibited", "client update prohibited"],
      expirationDate: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(),
    };

    const normalizedStatuses = domainRegistration.status.map((s: string) => s.toLowerCase().replace(/\s+/g, ''));
    const hasTransferLock = normalizedStatuses.some((s: string) => s.includes('clienttransferprohibited'));
    const hasDeleteLock = normalizedStatuses.some((s: string) => s.includes('clientdeleteprohibited'));

    expect(hasTransferLock).toBe(false);
    expect(hasDeleteLock).toBe(false);
  });

  it("should handle mixed camelCase and space-separated status codes", () => {
    const domainRegistration = {
      dnssec: true,
      status: ["clientTransferProhibited", "client delete prohibited"],
      expirationDate: new Date(Date.now() + 200 * 24 * 60 * 60 * 1000).toISOString(),
    };

    const normalizedStatuses = domainRegistration.status.map((s: string) => s.toLowerCase().replace(/\s+/g, ''));
    const hasTransferLock = normalizedStatuses.some((s: string) => s.includes('clienttransferprohibited'));
    const hasDeleteLock = normalizedStatuses.some((s: string) => s.includes('clientdeleteprohibited'));

    expect(hasTransferLock).toBe(true);
    expect(hasDeleteLock).toBe(true);
  });
});
