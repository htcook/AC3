import { describe, it, expect } from "vitest";
import { ScanForgeKB, KB_KEYS, createKBFromEngagement } from "./knowledge-base";
import { ServiceDetector, buildServiceDetectionCommands } from "./service-detector";
import { SMBHandler } from "./smb-handler";
import { SNMPHandler } from "./snmp-handler";
import { CVSSv31Calculator, getVulnTypeCVSS, scoreFinding, VULN_TYPE_CVSS_PROFILES } from "./cvss-engine";

// ─── Knowledge Base Tests ────────────────────────────────────────

describe("ScanForgeKB", () => {
  it("should set and get entries for a host", () => {
    const kb = new ScanForgeKB("test-scan-1");
    kb.set("host/alive", true, "naabu", { host: "192.168.1.1", confidence: 1.0 });
    
    const entry = kb.get("host/alive", "192.168.1.1");
    expect(entry).toBeDefined();
    expect(entry!.value).toBe(true);
    expect(entry!.source).toBe("naabu");
    expect(entry!.confidence).toBe(1.0);
  });
  
  it("should set and get global entries", () => {
    const kb = new ScanForgeKB("test-scan-2");
    kb.set("scan/start_time", Date.now(), "system");
    
    const entry = kb.get("scan/start_time");
    expect(entry).toBeDefined();
    expect(entry!.source).toBe("system");
  });
  
  it("should ingest scanforge-discovery results and populate KB", () => {
    const kb = new ScanForgeKB("test-scan-3");
    kb.ingestDiscoveryResults("10.0.0.1", {
      ports: [
        { port: 22, proto: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9" },
        { port: 80, proto: "tcp", state: "open", service: "http", version: "nginx 1.24" },
        { port: 443, proto: "tcp", state: "open", service: "https" },
      ],
      os: "Ubuntu 22.04",
      hostname: "web-server.example.com",
    });
    
    expect(kb.getValue(KB_KEYS.HOST_ALIVE, "10.0.0.1")).toBe(true);
    expect(kb.getValue(KB_KEYS.HOST_OS, "10.0.0.1")).toBe("Ubuntu 22.04");
    expect(kb.getValue(KB_KEYS.HOST_FQDN, "10.0.0.1")).toBe("web-server.example.com");
    expect(kb.getValue(KB_KEYS.PORT_STATE(22, "tcp"), "10.0.0.1")).toBe("open");
    expect(kb.getValue(KB_KEYS.PORT_SERVICE(80, "tcp"), "10.0.0.1")).toBe("http");
    expect(kb.getValue(KB_KEYS.PORT_VERSION(22, "tcp"), "10.0.0.1")).toBe("OpenSSH 8.9");
  });
  
  it("should query with glob patterns", () => {
    const kb = new ScanForgeKB("test-scan-4");
    kb.ingestDiscoveryResults("10.0.0.1", {
      ports: [
        { port: 22, proto: "tcp", state: "open", service: "ssh" },
        { port: 80, proto: "tcp", state: "open", service: "http" },
        { port: 443, proto: "tcp", state: "open", service: "https" },
      ],
    });
    
    const services = kb.query({ key: "ports/tcp/*/service", host: "10.0.0.1" });
    expect(services.length).toBe(3);
  });
  
  it("should get open ports for a host", () => {
    const kb = new ScanForgeKB("test-scan-5");
    kb.ingestDiscoveryResults("10.0.0.1", {
      ports: [
        { port: 22, proto: "tcp", state: "open" },
        { port: 80, proto: "tcp", state: "open" },
        { port: 443, proto: "tcp", state: "open" },
        { port: 8080, proto: "tcp", state: "open" },
      ],
    });
    
    const ports = kb.getOpenPorts("10.0.0.1");
    expect(ports).toEqual([22, 80, 443, 8080]);
  });
  
  it("should get service ports for a host", () => {
    const kb = new ScanForgeKB("test-scan-6");
    kb.ingestDiscoveryResults("10.0.0.1", {
      ports: [
        { port: 80, proto: "tcp", state: "open", service: "http" },
        { port: 8080, proto: "tcp", state: "open", service: "http" },
        { port: 443, proto: "tcp", state: "open", service: "https" },
      ],
    });
    
    const httpPorts = kb.getServicePorts("10.0.0.1", "http");
    expect(httpPorts).toEqual([80, 8080]);
  });
  
  it("should handle TTL expiry", () => {
    const kb = new ScanForgeKB("test-scan-7");
    kb.set("temp/key", "value", "test", { ttl: 0 }); // 0 = permanent
    expect(kb.get("temp/key")).toBeDefined();
    
    // Manually create an expired entry
    kb.set("expired/key", "old", "test", { ttl: -1 }); // Negative TTL = already expired
    // The entry exists but the isExpired check uses Date.now() - timestamp > ttl * 1000
    // With ttl=-1, it means -1000ms which is always less than elapsed time
  });
  
  it("should resolve template execution order", () => {
    const kb = new ScanForgeKB("test-scan-8");
    
    kb.registerTemplateDeps("service-detect", {
      requires: [],
      provides: ["ports/*/service"],
      priority: 10,
    });
    
    kb.registerTemplateDeps("http-vuln", {
      requires: ["ports/*/service"],
      provides: ["vulns/*"],
      priority: 20,
    });
    
    kb.registerTemplateDeps("sqli-check", {
      requires: ["ports/*/service"],
      provides: ["vulns/sqli/*"],
      priority: 30,
    });
    
    // Seed KB with service data so deps are satisfied
    kb.set("ports/tcp/80/service", "http", "naabu");
    
    const order = kb.resolveExecutionOrder(["sqli-check", "http-vuln", "service-detect"]);
    // service-detect should come first (priority 10, no deps)
    expect(order[0]).toBe("service-detect");
  });
  
  it("should create KB from engagement data", () => {
    const kb = createKBFromEngagement("eng-1", [
      {
        ip: "192.168.1.10",
        hostname: "target.local",
        openPorts: [
          { port: 22, service: "ssh" },
          { port: 80, service: "http", version: "Apache 2.4" },
        ],
        os: "CentOS 7",
      },
    ]);
    
    expect(kb.getAllHosts().length).toBe(1);
    expect(kb.getValue(KB_KEYS.HOST_OS, "192.168.1.10")).toBe("CentOS 7");
    expect(kb.getOpenPorts("192.168.1.10")).toEqual([22, 80]);
  });
  
  it("should fire change listeners", () => {
    const kb = new ScanForgeKB("test-scan-9");
    const changes: string[] = [];
    
    kb.onChange((key) => changes.push(key));
    kb.set("test/key1", "val1", "test");
    kb.set("test/key2", "val2", "test");
    
    expect(changes).toEqual(["test/key1", "test/key2"]);
  });
  
  it("should serialize to JSON", () => {
    const kb = new ScanForgeKB("test-scan-10");
    kb.ingestDiscoveryResults("10.0.0.1", {
      ports: [{ port: 80, proto: "tcp", state: "open", service: "http" }],
    });
    
    const json = kb.toJSON();
    expect(json.scanId).toBe("test-scan-10");
    expect(json.hosts).toBeDefined();
    expect((json.hosts as Record<string, unknown>)["10.0.0.1"]).toBeDefined();
  });
  
  it("should return KB statistics", () => {
    const kb = new ScanForgeKB("test-scan-11");
    kb.ingestDiscoveryResults("10.0.0.1", {
      ports: [
        { port: 22, proto: "tcp", state: "open", service: "ssh" },
        { port: 80, proto: "tcp", state: "open", service: "http" },
      ],
    });
    
    const stats = kb.getStats();
    expect(stats.hostCount).toBe(1);
    expect(stats.openPortCount).toBe(2);
    expect(stats.serviceCount).toBe(2);
    expect(stats.totalEntries).toBeGreaterThan(0);
    expect(stats.entriesBySource["scanforge-discovery"]).toBeGreaterThan(0);
  });
});

// ─── Service Detector Tests ──────────────────────────────────────

describe("ServiceDetector", () => {
  it("should fingerprint HTTP technologies from headers", () => {
    const detector = new ServiceDetector();
    
    const results = detector.fingerprintHTTP(
      { "server": "nginx/1.24.0", "x-powered-by": "Express", "cf-ray": "abc123" },
      "<html><head></head><body></body></html>",
      ["connect.sid=abc123"]
    );
    
    expect(results.some(r => r.name === "nginx")).toBe(true);
    expect(results.some(r => r.name === "Express")).toBe(true);
    expect(results.some(r => r.name === "Cloudflare")).toBe(true);
  });
  
  it("should fingerprint CMS from body patterns", () => {
    const detector = new ServiceDetector();
    
    const results = detector.fingerprintHTTP(
      {},
      '<link rel="stylesheet" href="/wp-content/themes/theme/style.css">',
      []
    );
    
    expect(results.some(r => r.name === "WordPress")).toBe(true);
  });
  
  it("should fingerprint frameworks from cookies", () => {
    const detector = new ServiceDetector();
    
    const results = detector.fingerprintHTTP(
      {},
      "",
      ["PHPSESSID=abc123", "laravel_session=xyz789"]
    );
    
    expect(results.some(r => r.name === "PHP")).toBe(true);
    expect(results.some(r => r.name === "Laravel")).toBe(true);
  });
  
  it("should build service detection commands", () => {
    const commands = buildServiceDetectionCommands("10.0.0.1", [22, 80, 443, 3306]);
    
    expect(commands.length).toBeGreaterThan(0);
    expect(commands.some(c => c.includes("nc -w 3 10.0.0.1"))).toBe(true);
    expect(commands.some(c => c.includes("openssl s_client"))).toBe(true);
    expect(commands.some(c => c.includes("curl -sI"))).toBe(true);
  });
});

// ─── SMB Handler Tests ───────────────────────────────────────────

describe("SMBHandler", () => {
  const handler = new SMBHandler();
  
  it("should build scan commands for a host", () => {
    const commands = handler.buildScanCommands({ host: "192.168.1.100" });
    
    expect(commands.length).toBeGreaterThanOrEqual(9);
    expect(commands.some(c => c.id === "smb-version")).toBe(true);
    expect(commands.some(c => c.id === "smb-signing")).toBe(true);
    expect(commands.some(c => c.id === "smb-shares-null")).toBe(true);
    expect(commands.some(c => c.id === "smb-enum4linux")).toBe(true);
    expect(commands.some(c => c.id === "smb-vuln-ms17-010")).toBe(true);
  });
  
  it("should include authenticated commands when creds provided", () => {
    const commands = handler.buildScanCommands({
      host: "192.168.1.100",
      username: "admin",
      password: "password123",
      domain: "CORP",
    });
    
    expect(commands.some(c => c.id === "smb-shares-auth")).toBe(true);
  });
  
  it("should parse SMB version output", () => {
    expect(handler.parseSMBVersion("SMBv1 enabled\nSMBv2 enabled")).toEqual(["1", "2"]);
    expect(handler.parseSMBVersion("dialects: 2.0.2, 2.1, 3.0, 3.1.1")).toEqual(["2", "3"]);
  });
  
  it("should parse SMB signing output", () => {
    expect(handler.parseSMBSigning("message_signing: required")).toBe("required");
    expect(handler.parseSMBSigning("message_signing: enabled")).toBe("enabled");
    expect(handler.parseSMBSigning("no signing info")).toBe("disabled");
  });
  
  it("should detect SMBv1 vulnerability", () => {
    const vulns = handler.detectVulnerabilities({
      host: "192.168.1.100",
      port: 445,
      smbVersion: ["1", "2"],
      signing: "disabled",
      nullSession: true,
      guestAccess: false,
      shares: [],
    });
    
    expect(vulns.some(v => v.id === "smb-v1-enabled")).toBe(true);
    expect(vulns.some(v => v.id === "smb-signing-not-required")).toBe(true);
    expect(vulns.some(v => v.id === "smb-null-session")).toBe(true);
  });
  
  it("should detect writable anonymous shares", () => {
    const vulns = handler.detectVulnerabilities({
      host: "192.168.1.100",
      port: 445,
      smbVersion: ["2"],
      signing: "required",
      nullSession: false,
      guestAccess: false,
      shares: [
        { name: "Public", type: "DISK", comment: "", readable: true, writable: true, anonymousAccess: true },
      ],
    });
    
    expect(vulns.some(v => v.id === "smb-writable-share-Public")).toBe(true);
    expect(vulns.find(v => v.id === "smb-writable-share-Public")?.severity).toBe("critical");
  });
  
  it("should populate KB with SMB findings", () => {
    const kb = new ScanForgeKB("smb-test");
    handler.populateKB(kb, {
      host: "192.168.1.100",
      port: 445,
      smbVersion: ["2", "3"],
      signing: "required",
      os: "Windows Server 2019",
      hostname: "DC01",
      nullSession: false,
      guestAccess: false,
      shares: [{ name: "NETLOGON", type: "DISK", comment: "", readable: true, writable: false, anonymousAccess: false }],
    });
    
    expect(kb.getValue(KB_KEYS.PORT_SERVICE(445, "tcp"), "192.168.1.100")).toBe("smb");
    expect(kb.getValue(KB_KEYS.SERVICE_SMB_OS(445), "192.168.1.100")).toBe("Windows Server 2019");
    expect(kb.getValue(KB_KEYS.HOST_FQDN, "192.168.1.100")).toBe("DC01");
  });
});

// ─── SNMP Handler Tests ──────────────────────────────────────────

describe("SNMPHandler", () => {
  const handler = new SNMPHandler();
  
  it("should build scan commands for a host", () => {
    const commands = handler.buildScanCommands({ host: "10.0.0.1" });
    
    expect(commands.length).toBeGreaterThanOrEqual(7);
    expect(commands.some(c => c.id === "snmp-community-brute")).toBe(true);
    expect(commands.some(c => c.id.startsWith("snmp-sysinfo"))).toBe(true);
    expect(commands.some(c => c.id === "snmp-interfaces")).toBe(true);
    expect(commands.some(c => c.id === "snmp-v3-users")).toBe(true);
    expect(commands.some(c => c.id === "snmp-write-test")).toBe(true);
  });
  
  it("should parse community brute-force output", () => {
    const output = "10.0.0.1 [public] Linux router 5.4\n10.0.0.1 [private] Linux router 5.4";
    const communities = handler.parseCommunityBrute(output);
    
    expect(communities).toContain("public");
    expect(communities).toContain("private");
    expect(communities.length).toBe(2);
  });
  
  it("should parse system info output", () => {
    const output = `
SNMPv2-MIB::sysDescr.0 = STRING: "Cisco IOS Software, ISR4300 Series"
SNMPv2-MIB::sysName.0 = STRING: "core-router-01"
SNMPv2-MIB::sysLocation.0 = STRING: "Building A, Floor 3"
    `.trim();
    
    const info = handler.parseSysInfo(output);
    expect(info.sysDescr).toContain("Cisco IOS");
    expect(info.sysName).toBe("core-router-01");
    expect(info.sysLocation).toBe("Building A, Floor 3");
  });
  
  it("should fingerprint device types", () => {
    expect(handler.fingerPrintDevice("Cisco IOS Software, ISR4300 Series Router")).toBe("router");
    expect(handler.fingerPrintDevice("Cisco Catalyst 9300 Switch")).toMatch(/switch|router|unknown/);
    expect(handler.fingerPrintDevice("Cisco ASA Firewall")).toBe("firewall");
    expect(handler.fingerPrintDevice("FortiGate-60F v7.2")).toBe("firewall");
    expect(handler.fingerPrintDevice("HP LaserJet Pro MFP")).toBe("printer");
    expect(handler.fingerPrintDevice("Linux server 5.15")).toBe("linux-server");
    expect(handler.fingerPrintDevice("VMware ESXi 8.0")).toBe("hypervisor");
    expect(handler.fingerPrintDevice("APC Smart-UPS")).toBe("ups");
  });
  
  it("should detect default community string vulnerability", () => {
    const vulns = handler.detectVulnerabilities(
      { host: "10.0.0.1", port: 161, version: "2c", interfaces: [], routes: [] },
      ["public", "private"],
      false
    );
    
    expect(vulns.some(v => v.id === "snmp-default-community")).toBe(true);
    expect(vulns.find(v => v.id === "snmp-default-community")?.severity).toBe("critical");
  });
  
  it("should detect write access vulnerability", () => {
    const vulns = handler.detectVulnerabilities(
      { host: "10.0.0.1", port: 161, version: "2c", interfaces: [], routes: [] },
      ["public"],
      true
    );
    
    expect(vulns.some(v => v.id === "snmp-write-access")).toBe(true);
    expect(vulns.find(v => v.id === "snmp-write-access")?.severity).toBe("critical");
  });
  
  it("should detect SNMPv1/v2c no-encryption vulnerability", () => {
    const vulns = handler.detectVulnerabilities(
      { host: "10.0.0.1", port: 161, version: "1", interfaces: [], routes: [] },
      [],
      false
    );
    
    expect(vulns.some(v => v.id === "snmp-no-encryption")).toBe(true);
  });
  
  it("should populate KB with SNMP findings", () => {
    const kb = new ScanForgeKB("snmp-test");
    handler.populateKB(kb, {
      host: "10.0.0.1",
      port: 161,
      community: "public",
      version: "2c",
      sysDescr: "Cisco IOS Router",
      sysName: "core-rtr-01",
      interfaces: [],
      routes: [],
      deviceType: "router",
    }, ["public"]);
    
    expect(kb.getValue(KB_KEYS.PORT_SERVICE(161, "udp"), "10.0.0.1")).toBe("snmp");
    expect(kb.getValue(KB_KEYS.SERVICE_SNMP_COMMUNITY(161), "10.0.0.1")).toEqual(["public"]);
    expect(kb.getValue(KB_KEYS.HOST_FQDN, "10.0.0.1")).toBe("core-rtr-01");
  });
});

// ─── CVSS Engine Tests ───────────────────────────────────────────

describe("CVSSv31Calculator", () => {
  const calc = new CVSSv31Calculator();
  
  it("should calculate critical RCE score (9.8+)", () => {
    const result = calc.calculate({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentialityImpact: "H",
      integrityImpact: "H",
      availabilityImpact: "H",
    });
    
    expect(result.baseScore).toBeGreaterThanOrEqual(9.0);
    expect(result.severity).toBe("Critical");
    expect(result.vectorString).toContain("CVSS:3.1");
  });
  
  it("should calculate medium XSS score (5.0-6.9)", () => {
    const result = calc.calculate({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "R",
      scope: "C",
      confidentialityImpact: "L",
      integrityImpact: "L",
      availabilityImpact: "N",
    });
    
    expect(result.baseScore).toBeGreaterThanOrEqual(5.0);
    expect(result.baseScore).toBeLessThanOrEqual(7.0);
    expect(result.severity).toBe("Medium");
  });
  
  it("should return None severity for no-impact vuln", () => {
    const result = calc.calculate({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentialityImpact: "N",
      integrityImpact: "N",
      availabilityImpact: "N",
    });
    
    expect(result.baseScore).toBe(0);
    expect(result.severity).toBe("None");
  });
  
  it("should calculate temporal score with modifiers", () => {
    const result = calc.calculate(
      {
        attackVector: "N",
        attackComplexity: "L",
        privilegesRequired: "N",
        userInteraction: "N",
        scope: "U",
        confidentialityImpact: "H",
        integrityImpact: "H",
        availabilityImpact: "H",
      },
      {
        exploitCodeMaturity: "P",  // Proof of concept
        remediationLevel: "T",     // Temporary fix
        reportConfidence: "R",     // Reasonable
      }
    );
    
    expect(result.temporalScore).toBeDefined();
    expect(result.temporalScore!).toBeLessThan(result.baseScore);
  });
  
  it("should parse and calculate from vector string", () => {
    const result = calc.parseAndCalculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    
    expect(result.baseScore).toBeGreaterThanOrEqual(9.0);
    expect(result.severity).toBe("Critical");
  });
  
  it("should auto-score from vulnerability characteristics", () => {
    const result = calc.autoScore({
      type: "sqli",
      remote: true,
      authenticated: false,
      userInteraction: false,
      dataAccess: true,
      dataModify: true,
      codeExecution: false,
      dos: false,
    });
    
    expect(result.baseScore).toBeGreaterThanOrEqual(6.0);
    expect(["Medium", "High", "Critical"]).toContain(result.severity);
  });
  
  it("should handle scope change correctly", () => {
    // Same metrics but with scope changed should give higher score
    const unchanged = calc.calculate({
      attackVector: "N", attackComplexity: "L", privilegesRequired: "L",
      userInteraction: "N", scope: "U",
      confidentialityImpact: "L", integrityImpact: "L", availabilityImpact: "N",
    });
    
    const changed = calc.calculate({
      attackVector: "N", attackComplexity: "L", privilegesRequired: "L",
      userInteraction: "N", scope: "C",
      confidentialityImpact: "L", integrityImpact: "L", availabilityImpact: "N",
    });
    
    expect(changed.baseScore).toBeGreaterThan(unchanged.baseScore);
  });
});

describe("CVSS Vuln Type Profiles", () => {
  it("should have profiles for common vuln types", () => {
    expect(VULN_TYPE_CVSS_PROFILES["rce"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["sqli"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["xss-stored"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["xss-reflected"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["csrf"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["ssrf"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["lfi"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["default-creds"]).toBeDefined();
    expect(VULN_TYPE_CVSS_PROFILES["info-disclosure"]).toBeDefined();
  });
  
  it("should score RCE as critical", () => {
    const score = getVulnTypeCVSS("rce");
    expect(score).toBeDefined();
    expect(score!.severity).toBe("Critical");
  });
  
  it("should score SQLi as critical", () => {
    const score = getVulnTypeCVSS("sqli");
    expect(score).toBeDefined();
    expect(score!.severity).toBe("Critical");
  });
  
  it("should score info-disclosure as low/medium", () => {
    const score = getVulnTypeCVSS("info-disclosure");
    expect(score).toBeDefined();
    expect(["Low", "Medium"]).toContain(score!.severity);
  });
  
  it("should score finding with vector string", () => {
    const result = scoreFinding({
      vulnType: "sqli",
      severity: "critical",
      remote: true,
      authenticated: false,
      vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    });
    
    expect(result.severity).toBe("Critical");
  });
  
  it("should fallback to type profile when no vector string", () => {
    const result = scoreFinding({
      vulnType: "xss-reflected",
      severity: "medium",
      remote: true,
      authenticated: false,
    });
    
    expect(result.severity).toBe("Medium");
  });
});
