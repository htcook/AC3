/**
 * ScanForge Protocol Scanner Registry
 *
 * Manages protocol-specific scanners that perform deep inspection
 * of discovered services. Each scanner implements the ProtocolScanner
 * interface and handles connection, authentication testing, version
 * detection, and vulnerability checks for its protocol.
 *
 * New protocol scanners are registered here and automatically invoked
 * by the scan orchestrator when matching services are discovered.
 */

import type { ProtocolScanner, ScanTarget, ScanConfig, ScanFinding } from "../types";

// ─── Registry ──────────────────────────────────────────────────────────────

export class ProtocolRegistry {
  private scanners: Map<string, ProtocolScanner> = new Map();

  constructor() {
    registerBuiltinScanners(this);
  }

  /**
   * Register a protocol scanner.
   */
  register(scanner: ProtocolScanner): void {
    this.scanners.set(scanner.protocol, scanner);
  }

  /**
   * Get a scanner by protocol name.
   */
  get(protocol: string): ProtocolScanner | undefined {
    return this.scanners.get(protocol);
  }

  /**
   * Get all registered scanners.
   */
  getAll(): ProtocolScanner[] {
    return Array.from(this.scanners.values());
  }

  /**
   * Find scanners that handle a given port number.
   */
  getByPort(port: number): ProtocolScanner[] {
    return this.getAll().filter(s => s.defaultPorts.includes(port));
  }

  /**
   * Get scanner count.
   */
  get count(): number {
    return this.scanners.size;
  }

  /**
   * List registered protocol names.
   */
  listProtocols(): string[] {
    return Array.from(this.scanners.keys());
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _registry: ProtocolRegistry | null = null;

export function getProtocolRegistry(): ProtocolRegistry {
  if (!_registry) {
    _registry = new ProtocolRegistry();
  }
  return _registry;
}

// ─── Built-in Scanner Registration ─────────────────────────────────────────

function registerBuiltinScanners(registry: ProtocolRegistry): void {
  // Import and register all protocol scanners
  // These are lazy-loaded to avoid circular dependencies

  registry.register(new ToolWrappedScanner({
    name: "MySQL Scanner",
    protocol: "mysql",
    defaultPorts: [3306],
    tool: "nmap",
    argsTemplate: "--script mysql-info,mysql-enum,mysql-vuln-cve2012-2122,mysql-brute -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "PostgreSQL Scanner",
    protocol: "postgresql",
    defaultPorts: [5432],
    tool: "nmap",
    argsTemplate: "--script pgsql-brute -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "Redis Scanner",
    protocol: "redis",
    defaultPorts: [6379],
    tool: "nmap",
    argsTemplate: "--script redis-info,redis-brute -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "MongoDB Scanner",
    protocol: "mongodb",
    defaultPorts: [27017],
    tool: "nmap",
    argsTemplate: "--script mongodb-info,mongodb-databases,mongodb-brute -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "SMB Scanner",
    protocol: "smb",
    defaultPorts: [445, 139],
    tool: "nmap",
    argsTemplate: "--script smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "LDAP Scanner",
    protocol: "ldap",
    defaultPorts: [389, 636],
    tool: "nmap",
    argsTemplate: "--script ldap-rootdse,ldap-search,ldap-brute -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "RDP Scanner",
    protocol: "rdp",
    defaultPorts: [3389],
    tool: "nmap",
    argsTemplate: "--script rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "VNC Scanner",
    protocol: "vnc",
    defaultPorts: [5900, 5901],
    tool: "nmap",
    argsTemplate: "--script vnc-info,vnc-brute -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "AMQP/RabbitMQ Scanner",
    protocol: "amqp",
    defaultPorts: [5672, 15672],
    tool: "nmap",
    argsTemplate: "--script amqp-info -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new ToolWrappedScanner({
    name: "Telnet Scanner",
    protocol: "telnet",
    defaultPorts: [23],
    tool: "nmap",
    argsTemplate: "--script telnet-brute,telnet-ntlm-info -p {port} {host}",
    parseOutput: parseNmapScriptOutput,
  }));

  registry.register(new HTTPSecurityScanner());
  registry.register(new TLSScanner());
  registry.register(new DNSScanner());
}

// ─── Tool-Wrapped Scanner (Generic) ───────────────────────────────────────
// Wraps existing tools (nmap scripts, nuclei, etc.) as protocol scanners.

interface ToolWrappedConfig {
  name: string;
  protocol: string;
  defaultPorts: number[];
  tool: string;
  argsTemplate: string;
  parseOutput: (stdout: string, target: ScanTarget, protocol: string) => ScanFinding[];
}

class ToolWrappedScanner implements ProtocolScanner {
  name: string;
  protocol: string;
  defaultPorts: number[];
  private config: ToolWrappedConfig;

  constructor(config: ToolWrappedConfig) {
    this.name = config.name;
    this.protocol = config.protocol;
    this.defaultPorts = config.defaultPorts;
    this.config = config;
  }

  async scan(target: ScanTarget, scanConfig?: ScanConfig): Promise<ScanFinding[]> {
    const { executeTool } = await import("../../lib/scan-server-executor");
    const host = target.value;
    const port = target.ports?.find(p => this.defaultPorts.includes(p)) || this.defaultPorts[0];

    const args = this.config.argsTemplate
      .replace(/{host}/g, host)
      .replace(/{port}/g, String(port));

    const result = await executeTool({
      tool: this.config.tool,
      args,
      target: host,
      timeoutSeconds: scanConfig?.scannerTimeoutSeconds || 120,
    });

    if (result.exitCode !== 0 && !result.stdout) {
      return [];
    }

    return this.config.parseOutput(result.stdout, target, this.protocol);
  }

  async probe(host: string, port: number): Promise<boolean> {
    const { executeTool } = await import("../../lib/scan-server-executor");
    const result = await executeTool({
      tool: "nmap",
      args: `-sT -p ${port} --open -T4 ${host}`,
      target: host,
      timeoutSeconds: 15,
    });
    return result.stdout.includes("open");
  }
}

// ─── HTTP Security Scanner ─────────────────────────────────────────────────

class HTTPSecurityScanner implements ProtocolScanner {
  name = "HTTP Security Scanner";
  protocol = "http";
  defaultPorts = [80, 443, 8080, 8443];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const baseUrl = target.type === "url" ? target.value : `https://${target.value}`;

    try {
      const response = await fetch(baseUrl, {
        method: "GET",
        headers: { "User-Agent": config?.userAgent || "AC3-ScanForge/1.0" },
        redirect: "follow",
        signal: AbortSignal.timeout(15000),
      });

      const headers: Record<string, string> = {};
      response.headers.forEach((v, k) => { headers[k] = v; });

      // Check security headers
      const securityHeaders = [
        { header: "strict-transport-security", name: "HSTS", severity: "medium" as const, cwe: "CWE-319" },
        { header: "x-content-type-options", name: "X-Content-Type-Options", severity: "low" as const, cwe: "CWE-16" },
        { header: "x-frame-options", name: "X-Frame-Options", severity: "medium" as const, cwe: "CWE-1021" },
        { header: "content-security-policy", name: "Content-Security-Policy", severity: "medium" as const, cwe: "CWE-79" },
        { header: "x-xss-protection", name: "X-XSS-Protection", severity: "low" as const, cwe: "CWE-79" },
        { header: "referrer-policy", name: "Referrer-Policy", severity: "low" as const, cwe: "CWE-200" },
        { header: "permissions-policy", name: "Permissions-Policy", severity: "low" as const, cwe: "CWE-16" },
      ];

      for (const sh of securityHeaders) {
        if (!headers[sh.header]) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-security-headers",
            title: `Missing Security Header: ${sh.name}`,
            description: `The ${sh.name} header is not set on ${target.value}. This header helps protect against common web attacks.`,
            severity: sh.severity,
            confidence: 95,
            target: target.value,
            port: 443,
            protocol: "https",
            cwes: [sh.cwe],
            evidence: {
              request: `GET ${baseUrl}`,
              data: { missingHeader: sh.header, allHeaders: headers },
            },
            remediation: `Add the ${sh.name} header to your web server configuration.`,
            foundAt: Date.now(),
          });
        }
      }

      // Check for information disclosure headers
      const infoHeaders = ["server", "x-powered-by", "x-aspnet-version"];
      for (const h of infoHeaders) {
        if (headers[h]) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-security-headers",
            title: `Information Disclosure: ${h} header`,
            description: `The ${h} header reveals server technology: "${headers[h]}". This information can help attackers target known vulnerabilities.`,
            severity: "info",
            confidence: 100,
            target: target.value,
            port: 443,
            protocol: "https",
            cwes: ["CWE-200"],
            evidence: {
              matchedPattern: `${h}: ${headers[h]}`,
              data: { header: h, value: headers[h] },
            },
            remediation: `Remove or obfuscate the ${h} header in your web server configuration.`,
            foundAt: Date.now(),
          });
        }
      }

      // Check for insecure cookies
      const setCookie = headers["set-cookie"];
      if (setCookie) {
        if (!setCookie.toLowerCase().includes("secure")) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-cookie-security",
            title: "Cookie Missing Secure Flag",
            description: "A cookie is set without the Secure flag, allowing it to be transmitted over unencrypted HTTP connections.",
            severity: "medium",
            confidence: 95,
            target: target.value,
            protocol: "https",
            cwes: ["CWE-614"],
            evidence: { matchedPattern: setCookie.substring(0, 200) },
            remediation: "Add the Secure flag to all cookies.",
            foundAt: Date.now(),
          });
        }
        if (!setCookie.toLowerCase().includes("httponly")) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-cookie-security",
            title: "Cookie Missing HttpOnly Flag",
            description: "A cookie is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS attacks.",
            severity: "medium",
            confidence: 95,
            target: target.value,
            protocol: "https",
            cwes: ["CWE-1004"],
            evidence: { matchedPattern: setCookie.substring(0, 200) },
            remediation: "Add the HttpOnly flag to session cookies.",
            foundAt: Date.now(),
          });
        }
      }

    } catch (err: any) {
      // Connection failure is itself a finding for availability
      console.debug(`[HTTPScanner] Failed to connect to ${target.value}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const proto = port === 443 || port === 8443 ? "https" : "http";
      await fetch(`${proto}://${host}:${port}/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });
      return true;
    } catch {
      return false;
    }
  }
}

// ─── TLS Scanner ───────────────────────────────────────────────────────────

class TLSScanner implements ProtocolScanner {
  name = "TLS Scanner";
  protocol = "tls";
  defaultPorts = [443, 8443, 993, 995, 465];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const { executeTool } = await import("../../lib/scan-server-executor");
    const host = target.value;
    const port = target.ports?.find(p => this.defaultPorts.includes(p)) || 443;

    const result = await executeTool({
      tool: "sslscan",
      args: `--no-colour ${host}:${port}`,
      target: host,
      timeoutSeconds: 60,
    });

    return this.parseSslscanOutput(result.stdout, target);
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      await fetch(`https://${host}:${port}/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });
      return true;
    } catch {
      return false;
    }
  }

  private parseSslscanOutput(stdout: string, target: ScanTarget): ScanFinding[] {
    const findings: ScanFinding[] = [];

    // Check for weak protocols
    if (stdout.includes("SSLv3") && stdout.includes("Enabled")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "tls-scanner",
        title: "SSLv3 Protocol Enabled (POODLE)",
        description: "SSLv3 is enabled on this server. This protocol is vulnerable to the POODLE attack (CVE-2014-3566).",
        severity: "high",
        confidence: 100,
        target: target.value,
        protocol: "tls",
        cves: ["CVE-2014-3566"],
        cwes: ["CWE-327"],
        evidence: { matchedPattern: "SSLv3 Enabled" },
        remediation: "Disable SSLv3 and use TLS 1.2 or higher.",
        foundAt: Date.now(),
      });
    }

    if (stdout.includes("TLSv1.0") && stdout.includes("Enabled")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "tls-scanner",
        title: "TLS 1.0 Protocol Enabled",
        description: "TLS 1.0 is enabled. This protocol version has known weaknesses and is deprecated by NIST and PCI DSS.",
        severity: "medium",
        confidence: 100,
        target: target.value,
        protocol: "tls",
        cwes: ["CWE-327"],
        evidence: { matchedPattern: "TLSv1.0 Enabled" },
        remediation: "Disable TLS 1.0 and use TLS 1.2 or higher.",
        foundAt: Date.now(),
      });
    }

    // Check for weak ciphers
    const weakCiphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"];
    for (const cipher of weakCiphers) {
      if (stdout.includes(cipher) && stdout.includes("Accepted")) {
        findings.push({
          id: crypto.randomUUID(),
          source: "tls-scanner",
          title: `Weak Cipher Suite: ${cipher}`,
          description: `The server accepts the weak cipher suite ${cipher}. This can be exploited to decrypt traffic.`,
          severity: cipher === "NULL" || cipher === "EXPORT" ? "critical" : "high",
          confidence: 100,
          target: target.value,
          protocol: "tls",
          cwes: ["CWE-327"],
          evidence: { matchedPattern: `${cipher} Accepted` },
          remediation: `Disable ${cipher} cipher suites and use only strong ciphers (AES-GCM, ChaCha20).`,
          foundAt: Date.now(),
        });
      }
    }

    // Check certificate expiry
    const expiryMatch = stdout.match(/Not valid after:\s+(.+)/);
    if (expiryMatch) {
      const expiry = new Date(expiryMatch[1]);
      const daysUntilExpiry = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      if (daysUntilExpiry < 0) {
        findings.push({
          id: crypto.randomUUID(),
          source: "tls-scanner",
          title: "Expired TLS Certificate",
          description: `The TLS certificate expired ${Math.abs(daysUntilExpiry)} days ago.`,
          severity: "critical",
          confidence: 100,
          target: target.value,
          protocol: "tls",
          cwes: ["CWE-295"],
          evidence: { data: { expiryDate: expiryMatch[1], daysExpired: Math.abs(daysUntilExpiry) } },
          remediation: "Renew the TLS certificate immediately.",
          foundAt: Date.now(),
        });
      } else if (daysUntilExpiry < 30) {
        findings.push({
          id: crypto.randomUUID(),
          source: "tls-scanner",
          title: "TLS Certificate Expiring Soon",
          description: `The TLS certificate expires in ${daysUntilExpiry} days.`,
          severity: "medium",
          confidence: 100,
          target: target.value,
          protocol: "tls",
          cwes: ["CWE-295"],
          evidence: { data: { expiryDate: expiryMatch[1], daysRemaining: daysUntilExpiry } },
          remediation: "Renew the TLS certificate before it expires.",
          foundAt: Date.now(),
        });
      }
    }

    return findings;
  }
}

// ─── DNS Scanner ───────────────────────────────────────────────────────────

class DNSScanner implements ProtocolScanner {
  name = "DNS Scanner";
  protocol = "dns";
  defaultPorts = [53];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const { executeTool } = await import("../../lib/scan-server-executor");
    const findings: ScanFinding[] = [];
    const host = target.value;

    // Check for zone transfer
    const axfrResult = await executeTool({
      tool: "dig",
      args: `AXFR ${host}`,
      target: host,
      timeoutSeconds: 15,
    });

    if (axfrResult.stdout.includes("ANSWER SECTION") && !axfrResult.stdout.includes("Transfer failed")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "dns-scanner",
        title: "DNS Zone Transfer Allowed",
        description: `DNS zone transfer (AXFR) is allowed for ${host}. This exposes all DNS records to unauthorized parties.`,
        severity: "high",
        confidence: 100,
        target: host,
        port: 53,
        protocol: "dns",
        cwes: ["CWE-200"],
        techniqueIds: ["T1590.002"],
        evidence: { response: axfrResult.stdout.substring(0, 2000) },
        remediation: "Restrict zone transfers to authorized secondary DNS servers only.",
        foundAt: Date.now(),
      });
    }

    // Check for DNSSEC
    const dnssecResult = await executeTool({
      tool: "dig",
      args: `+dnssec ${host} DNSKEY`,
      target: host,
      timeoutSeconds: 10,
    });

    if (!dnssecResult.stdout.includes("DNSKEY") || dnssecResult.stdout.includes("SERVFAIL")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "dns-scanner",
        title: "DNSSEC Not Configured",
        description: `DNSSEC is not configured for ${host}. This makes the domain vulnerable to DNS spoofing and cache poisoning attacks.`,
        severity: "medium",
        confidence: 85,
        target: host,
        port: 53,
        protocol: "dns",
        cwes: ["CWE-350"],
        evidence: { data: { dnssecEnabled: false } },
        remediation: "Enable DNSSEC for the domain to protect against DNS spoofing.",
        foundAt: Date.now(),
      });
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    const { executeTool } = await import("../../lib/scan-server-executor");
    const result = await executeTool({
      tool: "dig",
      args: `+short ${host} A`,
      target: host,
      timeoutSeconds: 5,
    });
    return result.exitCode === 0 && result.stdout.trim().length > 0;
  }
}

// ─── Nmap Script Output Parser ─────────────────────────────────────────────

function parseNmapScriptOutput(stdout: string, target: ScanTarget, protocol: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  // Parse nmap script output for vulnerabilities
  const vulnBlocks = stdout.split(/\|_?\s*/);

  for (const block of vulnBlocks) {
    // Look for VULNERABLE state
    if (block.includes("VULNERABLE") || block.includes("State: VULNERABLE")) {
      const titleMatch = block.match(/^(\S+):/);
      const title = titleMatch ? titleMatch[1] : "Unknown Vulnerability";

      const cveMatch = block.match(/CVE-\d{4}-\d+/g);
      const descMatch = block.match(/Description:\s*(.+)/);

      findings.push({
        id: crypto.randomUUID(),
        source: `nmap-script:${protocol}`,
        title: `${protocol.toUpperCase()} Vulnerability: ${title}`,
        description: descMatch ? descMatch[1] : `Nmap script detected a vulnerability in ${protocol} service on ${target.value}.`,
        severity: cveMatch ? "high" : "medium",
        confidence: 85,
        target: target.value,
        protocol,
        cves: cveMatch || undefined,
        evidence: { response: block.substring(0, 2000) },
        remediation: `Update the ${protocol} service to the latest version and apply security patches.`,
        foundAt: Date.now(),
      });
    }

    // Look for brute-force results
    if (block.includes("Valid credentials") || block.includes("Accounts:")) {
      findings.push({
        id: crypto.randomUUID(),
        source: `nmap-script:${protocol}`,
        title: `${protocol.toUpperCase()} Weak Credentials Detected`,
        description: `Default or weak credentials were found for the ${protocol} service on ${target.value}.`,
        severity: "critical",
        confidence: 95,
        target: target.value,
        protocol,
        cwes: ["CWE-521", "CWE-798"],
        techniqueIds: ["T1110"],
        evidence: { response: block.substring(0, 1000) },
        remediation: "Change default credentials immediately and enforce strong password policies.",
        foundAt: Date.now(),
      });
    }

    // Look for information disclosure
    if (block.includes("Version:") || block.includes("version:")) {
      const versionMatch = block.match(/[Vv]ersion:\s*(.+)/);
      if (versionMatch) {
        findings.push({
          id: crypto.randomUUID(),
          source: `nmap-script:${protocol}`,
          title: `${protocol.toUpperCase()} Version Disclosure`,
          description: `The ${protocol} service on ${target.value} discloses its version: ${versionMatch[1].trim()}.`,
          severity: "info",
          confidence: 100,
          target: target.value,
          protocol,
          cwes: ["CWE-200"],
          evidence: { matchedPattern: versionMatch[0] },
          remediation: "Consider hiding version information to reduce the attack surface.",
          foundAt: Date.now(),
        });
      }
    }
  }

  return findings;
}
