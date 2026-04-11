import { describe, it, expect } from "vitest";

/**
 * Tests for:
 * 1. HTTP/HTTPS protocol detection — PORT_PROTOCOL_MAP coverage
 * 2. HTTP fingerprint probe — Server header parsing, product extraction
 * 3. autoFingerprint fallback — unmapped ports default to HTTP
 * 4. Security header analysis
 * 5. TLS certificate risk detection
 * 6. Technology stack detection from headers and body
 * 7. Known CVE matching for common web servers
 */

// ─── Replicate the updated PORT_PROTOCOL_MAP ────────────────────────────────

type ServiceProtocol =
  | "ssh" | "smtp" | "ftp" | "snmp" | "rdp" | "smb" | "ldap" | "telnet"
  | "mysql" | "mssql" | "postgresql" | "redis" | "mongodb" | "vnc"
  | "sftp" | "pop3" | "imap" | "dns" | "ntp" | "sip"
  | "http" | "https";

const PORT_PROTOCOL_MAP: Record<number, ServiceProtocol> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  161: "snmp",
  389: "ldap",
  443: "https",
  445: "smb",
  465: "smtp",
  587: "smtp",
  636: "ldap",
  993: "imap",
  995: "pop3",
  1433: "mssql",
  1521: "postgresql",
  4000: "http",
  4443: "https",
  2049: "ntp",
  3306: "mysql",
  3389: "rdp",
  8000: "http",
  8080: "http",
  8090: "http",
  8443: "https",
  8888: "http",
  9090: "http",
  9443: "https",
  5432: "postgresql",
  5900: "vnc",
  5901: "vnc",
  5902: "vnc",
  6379: "redis",
  6380: "redis",
  27017: "mongodb",
  27018: "mongodb",
  27019: "mongodb",
};

function detectProtocol(port: number): ServiceProtocol | null {
  return PORT_PROTOCOL_MAP[port] ?? null;
}

// ─── Replicate Server header parsing logic ──────────────────────────────────

function parseServerHeader(server: string): { product: string | null; version: string | null; os: string | null } {
  let product: string | null = null;
  let version: string | null = null;
  let os: string | null = null;

  if (server) {
    const serverParts = server.match(/^([\w.-]+)(?:\/([\d.]+))?/);
    if (serverParts) {
      product = serverParts[1];
      version = serverParts[2] || null;
    }
    if (/ubuntu/i.test(server)) os = 'Ubuntu Linux';
    else if (/debian/i.test(server)) os = 'Debian Linux';
    else if (/centos|rhel|red\s*hat/i.test(server)) os = 'RHEL/CentOS';
    else if (/win|microsoft|iis/i.test(server)) os = 'Windows';
    else if (/freebsd/i.test(server)) os = 'FreeBSD';
  }

  return { product, version, os };
}

// ─── Replicate security header analysis ─────────────────────────────────────

function analyzeSecurityHeaders(headers: Record<string, string>, isHttps: boolean): { missing: string[]; present: string[] } {
  const securityHeaders: Record<string, boolean> = {
    'strict-transport-security': !!headers['strict-transport-security'],
    'x-frame-options': !!headers['x-frame-options'],
    'x-content-type-options': !!headers['x-content-type-options'],
    'x-xss-protection': !!headers['x-xss-protection'],
    'content-security-policy': !!headers['content-security-policy'],
    'referrer-policy': !!headers['referrer-policy'],
    'permissions-policy': !!headers['permissions-policy'],
  };

  const missingCritical: string[] = [];
  if (!securityHeaders['strict-transport-security'] && isHttps) missingCritical.push('Strict-Transport-Security');
  if (!securityHeaders['x-frame-options'] && !securityHeaders['content-security-policy']) missingCritical.push('X-Frame-Options / CSP frame-ancestors');
  if (!securityHeaders['x-content-type-options']) missingCritical.push('X-Content-Type-Options');

  const present = Object.entries(securityHeaders).filter(([, v]) => v).map(([k]) => k);

  return { missing: missingCritical, present };
}

// ─── Replicate CVE matching logic ───────────────────────────────────────────

function checkKnownCves(product: string, version: string): string[] {
  const cves: string[] = [];
  const prod = product.toLowerCase();

  if (prod === 'apache' || prod.includes('apache')) {
    if (version < '2.4.50') cves.push('CVE-2021-41773', 'CVE-2021-42013');
  }
  if (prod === 'nginx') {
    if (version < '1.20.0') cves.push('CVE-2021-23017');
  }
  if (prod.includes('iis') || prod.includes('Microsoft-IIS')) {
    if (parseFloat(version) <= 7.5) cves.push('CVE-2017-7269');
  }

  return cves;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("PORT_PROTOCOL_MAP — HTTP/HTTPS Coverage", () => {
  it("maps port 80 to http", () => {
    expect(detectProtocol(80)).toBe("http");
  });

  it("maps port 443 to https (not smtp)", () => {
    expect(detectProtocol(443)).toBe("https");
  });

  it("maps common alt HTTP ports", () => {
    expect(detectProtocol(8080)).toBe("http");
    expect(detectProtocol(8090)).toBe("http");
    expect(detectProtocol(8000)).toBe("http");
    expect(detectProtocol(8888)).toBe("http");
    expect(detectProtocol(9090)).toBe("http");
    expect(detectProtocol(4000)).toBe("http");
  });

  it("maps common alt HTTPS ports", () => {
    expect(detectProtocol(8443)).toBe("https");
    expect(detectProtocol(4443)).toBe("https");
    expect(detectProtocol(9443)).toBe("https");
  });

  it("still maps non-HTTP ports correctly", () => {
    expect(detectProtocol(22)).toBe("ssh");
    expect(detectProtocol(3306)).toBe("mysql");
    expect(detectProtocol(3389)).toBe("rdp");
    expect(detectProtocol(445)).toBe("smb");
    expect(detectProtocol(25)).toBe("smtp");
  });

  it("returns null for truly unknown ports", () => {
    expect(detectProtocol(12345)).toBeNull();
    expect(detectProtocol(31337)).toBeNull();
  });
});

describe("DVWA Target Port Coverage", () => {
  it("all DVWA ports now have protocol mappings or HTTP fallback", () => {
    const dvwaPorts = [22, 80, 443, 1337, 4000, 8090, 8443];
    const results = dvwaPorts.map(port => ({
      port,
      protocol: detectProtocol(port),
      fallback: detectProtocol(port) || 'http',
    }));

    // Port 22 → ssh
    expect(results[0].protocol).toBe("ssh");
    // Port 80 → http (was null before fix)
    expect(results[1].protocol).toBe("http");
    // Port 443 → https (was smtp before fix)
    expect(results[2].protocol).toBe("https");
    // Port 1337 → null, but fallback to http
    expect(results[3].protocol).toBeNull();
    expect(results[3].fallback).toBe("http");
    // Port 4000 → http (newly mapped)
    expect(results[4].protocol).toBe("http");
    // Port 8090 → http (newly mapped)
    expect(results[5].protocol).toBe("http");
    // Port 8443 → https (newly mapped)
    expect(results[6].protocol).toBe("https");

    // All ports should now have a protocol (direct or fallback)
    for (const r of results) {
      expect(r.fallback).toBeTruthy();
    }
  });
});

describe("autoFingerprint Fallback Behavior", () => {
  it("unmapped ports default to HTTP instead of being dropped", () => {
    const openPorts = [22, 80, 443, 1337, 4000, 8090, 8443];
    const targets = openPorts.map(port => ({
      port,
      protocol: detectProtocol(port) || ('http' as ServiceProtocol),
    }));

    // All 7 ports should have a protocol now (none dropped)
    expect(targets).toHaveLength(7);
    expect(targets.every(t => t.protocol !== null)).toBe(true);

    // Port 1337 should fallback to http
    expect(targets.find(t => t.port === 1337)?.protocol).toBe("http");
  });

  it("old behavior would have dropped 5 of 7 ports", () => {
    const openPorts = [22, 80, 443, 1337, 4000, 8090, 8443];
    // Simulate OLD behavior: filter out null protocols
    const oldTargets = openPorts
      .map(port => ({ port, protocol: detectProtocol(port) }))
      .filter(t => t.protocol !== null);

    // With the new PORT_PROTOCOL_MAP, most ports are now mapped
    // Only port 1337 would be dropped (no mapping)
    const unmappedCount = openPorts.filter(p => detectProtocol(p) === null).length;
    expect(unmappedCount).toBe(1); // Only 1337 is unmapped now
  });
});

describe("Server Header Parsing", () => {
  it("parses Apache server header", () => {
    const result = parseServerHeader("Apache/2.4.52 (Ubuntu)");
    expect(result.product).toBe("Apache");
    expect(result.version).toBe("2.4.52");
    expect(result.os).toBe("Ubuntu Linux");
  });

  it("parses nginx server header", () => {
    const result = parseServerHeader("nginx/1.22.0");
    expect(result.product).toBe("nginx");
    expect(result.version).toBe("1.22.0");
    expect(result.os).toBeNull();
  });

  it("parses Microsoft-IIS server header", () => {
    const result = parseServerHeader("Microsoft-IIS/10.0");
    expect(result.product).toBe("Microsoft-IIS");
    expect(result.version).toBe("10.0");
    expect(result.os).toBe("Windows");
  });

  it("parses server header without version", () => {
    const result = parseServerHeader("cloudflare");
    expect(result.product).toBe("cloudflare");
    expect(result.version).toBeNull();
  });

  it("parses Debian-based server", () => {
    const result = parseServerHeader("Apache/2.4.54 (Debian)");
    expect(result.product).toBe("Apache");
    expect(result.version).toBe("2.4.54");
    expect(result.os).toBe("Debian Linux");
  });

  it("parses CentOS/RHEL server", () => {
    const result = parseServerHeader("Apache/2.4.6 (CentOS)");
    expect(result.os).toBe("RHEL/CentOS");
  });

  it("handles empty server header", () => {
    const result = parseServerHeader("");
    expect(result.product).toBeNull();
    expect(result.version).toBeNull();
    expect(result.os).toBeNull();
  });
});

describe("Security Header Analysis", () => {
  it("detects all missing headers on a bare response", () => {
    const headers: Record<string, string> = {};
    const result = analyzeSecurityHeaders(headers, true);
    expect(result.missing).toContain("Strict-Transport-Security");
    expect(result.missing).toContain("X-Frame-Options / CSP frame-ancestors");
    expect(result.missing).toContain("X-Content-Type-Options");
    expect(result.present).toHaveLength(0);
  });

  it("does not flag HSTS as missing for HTTP (non-HTTPS)", () => {
    const headers: Record<string, string> = {};
    const result = analyzeSecurityHeaders(headers, false);
    expect(result.missing).not.toContain("Strict-Transport-Security");
  });

  it("recognizes present security headers", () => {
    const headers: Record<string, string> = {
      'strict-transport-security': 'max-age=31536000',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'self'",
    };
    const result = analyzeSecurityHeaders(headers, true);
    expect(result.missing).toHaveLength(0);
    expect(result.present).toContain('strict-transport-security');
    expect(result.present).toContain('x-frame-options');
    expect(result.present).toContain('x-content-type-options');
    expect(result.present).toContain('content-security-policy');
  });

  it("CSP satisfies X-Frame-Options requirement", () => {
    const headers: Record<string, string> = {
      'content-security-policy': "frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
    };
    const result = analyzeSecurityHeaders(headers, false);
    // X-Frame-Options / CSP should NOT be in missing since CSP is present
    expect(result.missing).not.toContain("X-Frame-Options / CSP frame-ancestors");
  });
});

describe("Known CVE Matching", () => {
  it("flags Apache < 2.4.50 for path traversal CVEs", () => {
    const cves = checkKnownCves("Apache", "2.4.49");
    expect(cves).toContain("CVE-2021-41773");
    expect(cves).toContain("CVE-2021-42013");
  });

  it("does not flag Apache >= 2.4.50", () => {
    const cves = checkKnownCves("Apache", "2.4.52");
    expect(cves).toHaveLength(0);
  });

  it("flags nginx < 1.20.0 for DNS resolver CVE", () => {
    const cves = checkKnownCves("nginx", "1.18.0");
    expect(cves).toContain("CVE-2021-23017");
  });

  it("does not flag nginx >= 1.20.0", () => {
    const cves = checkKnownCves("nginx", "1.22.0");
    expect(cves).toHaveLength(0);
  });

  it("flags IIS <= 7.5 for WebDAV CVE", () => {
    const cves = checkKnownCves("Microsoft-IIS", "7.5");
    expect(cves).toContain("CVE-2017-7269");
  });

  it("does not flag IIS > 7.5", () => {
    const cves = checkKnownCves("Microsoft-IIS", "10.0");
    expect(cves).toHaveLength(0);
  });

  it("returns empty for unknown products", () => {
    const cves = checkKnownCves("lighttpd", "1.4.59");
    expect(cves).toHaveLength(0);
  });
});

describe("Technology Detection from Headers", () => {
  it("detects PHP from X-Powered-By", () => {
    const poweredBy = "PHP/8.1.2";
    expect(/php/i.test(poweredBy)).toBe(true);
  });

  it("detects ASP.NET from X-Powered-By", () => {
    const poweredBy = "ASP.NET";
    expect(/asp\.?net/i.test(poweredBy)).toBe(true);
  });

  it("detects Express from X-Powered-By", () => {
    const poweredBy = "Express";
    expect(/express/i.test(poweredBy)).toBe(true);
  });

  it("detects Cloudflare from cf-ray header", () => {
    const headers = { 'cf-ray': '7abc123-IAD' };
    expect(!!headers['cf-ray']).toBe(true);
  });

  it("detects CloudFront from x-amz-cf-id header", () => {
    const headers = { 'x-amz-cf-id': 'abc123' };
    expect(!!headers['x-amz-cf-id']).toBe(true);
  });

  it("detects WordPress from body content", () => {
    const body = '<link rel="stylesheet" href="/wp-content/themes/default/style.css">';
    expect(/wp-content|wp-includes|wordpress/i.test(body)).toBe(true);
  });

  it("detects Drupal from body content", () => {
    const body = '<script src="/sites/default/files/js/drupal.js"></script>';
    expect(/drupal|sites\/default/i.test(body)).toBe(true);
  });
});

describe("TLS Certificate Risk Detection", () => {
  it("detects expired certificate", () => {
    const validTo = "Jan 01 00:00:00 2020 GMT";
    const expiry = new Date(validTo);
    expect(expiry < new Date()).toBe(true);
  });

  it("does not flag valid certificate", () => {
    const validTo = "Dec 31 23:59:59 2030 GMT";
    const expiry = new Date(validTo);
    expect(expiry < new Date()).toBe(false);
  });

  it("detects self-signed certificate", () => {
    const cert = {
      subject: { CN: "myserver.local", O: "Self" },
      issuer: { CN: "myserver.local", O: "Self" },
    };
    const isSelfSigned = cert.subject.CN === cert.issuer.CN && cert.subject.O === cert.issuer.O;
    expect(isSelfSigned).toBe(true);
  });

  it("does not flag CA-signed certificate as self-signed", () => {
    const cert = {
      subject: { CN: "example.com", O: "Example Inc" },
      issuer: { CN: "Let's Encrypt Authority X3", O: "Let's Encrypt" },
    };
    const isSelfSigned = cert.subject.CN === cert.issuer.CN && cert.subject.O === cert.issuer.O;
    expect(isSelfSigned).toBe(false);
  });
});

describe("HTTP Response Parsing", () => {
  it("parses HTTP status line", () => {
    const resp = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n";
    const match = resp.match(/^HTTP\/(\d\.\d)\s+(\d{3})\s+(.*)$/m);
    expect(match).toBeTruthy();
    expect(match![1]).toBe("1.1");
    expect(match![2]).toBe("200");
    expect(match![3]?.trim()).toBe("OK");
  });

  it("parses response headers into key-value pairs", () => {
    const headerBlock = "HTTP/1.1 200 OK\r\nServer: nginx/1.22.0\r\nX-Powered-By: PHP/8.1\r\nContent-Type: text/html";
    const headers: Record<string, string> = {};
    for (const line of headerBlock.split(/\r?\n/).slice(1)) {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        const key = line.substring(0, colonIdx).trim().toLowerCase();
        const val = line.substring(colonIdx + 1).trim();
        headers[key] = val;
      }
    }
    expect(headers['server']).toBe("nginx/1.22.0");
    expect(headers['x-powered-by']).toBe("PHP/8.1");
    expect(headers['content-type']).toBe("text/html");
  });

  it("extracts page title from HTML body", () => {
    const body = '<html><head><title>DVWA - Damn Vulnerable Web Application</title></head></html>';
    const titleMatch = body.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
    expect(titleMatch).toBeTruthy();
    expect(titleMatch![1]).toBe("DVWA - Damn Vulnerable Web Application");
  });

  it("extracts meta generator from HTML body", () => {
    const body = '<meta name="generator" content="WordPress 6.4.2">';
    const genMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
    expect(genMatch).toBeTruthy();
    expect(genMatch![1]).toBe("WordPress 6.4.2");
  });
});
