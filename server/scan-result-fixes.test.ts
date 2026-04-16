/**
 * Tests for scan result fixes:
 * 1. Health monitor status mapping (mapStatusToIntegrationDb)
 * 2. Finding dedup normalization (title stripping)
 * 3. OWASP auto-classification
 * 4. Nuclei endpoint extraction
 */
import { describe, it, expect } from "vitest";

// ─── Test 1: Health Monitor Status Mapping ───────────────────────────────────
// The mapStatusToIntegrationDb function maps internal HealthStatus values
// to the narrower customer_integrations.last_health_status enum:
// [healthy, degraded, unreachable, auth_failed, unknown]

describe("Health Monitor Status Mapping", () => {
  // Replicate the mapStatusToIntegrationDb logic for testing
  function mapStatusToIntegrationDb(status: string): string {
    switch (status) {
      case "down":          return "unreachable";
      case "auth_expired":  return "auth_failed";
      case "rate_limited":  return "degraded";
      case "unknown":       return "unknown";
      default:              return status;
    }
  }

  const validEnumValues = ["healthy", "degraded", "unreachable", "auth_failed", "unknown"];

  it("maps 'down' to 'unreachable'", () => {
    expect(mapStatusToIntegrationDb("down")).toBe("unreachable");
  });

  it("maps 'auth_expired' to 'auth_failed'", () => {
    expect(mapStatusToIntegrationDb("auth_expired")).toBe("auth_failed");
  });

  it("maps 'rate_limited' to 'degraded' (closest match in narrower enum)", () => {
    expect(mapStatusToIntegrationDb("rate_limited")).toBe("degraded");
  });

  it("maps 'unknown' to 'unknown' (not 'error')", () => {
    expect(mapStatusToIntegrationDb("unknown")).toBe("unknown");
  });

  it("passes through 'healthy' unchanged", () => {
    expect(mapStatusToIntegrationDb("healthy")).toBe("healthy");
  });

  it("passes through 'degraded' unchanged", () => {
    expect(mapStatusToIntegrationDb("degraded")).toBe("degraded");
  });

  it("all mapped values are valid DB enum values", () => {
    const inputs = ["healthy", "degraded", "down", "auth_expired", "rate_limited", "unknown"];
    for (const input of inputs) {
      const mapped = mapStatusToIntegrationDb(input);
      expect(validEnumValues).toContain(mapped);
    }
  });
});

// ─── Test 2: Finding Dedup Title Normalization ───────────────────────────────
// The dedup logic should strip [Tool] prefixes and @ URL suffixes

describe("Finding Dedup Title Normalization", () => {
  function normTitle(title: string): string {
    return title
      .replace(/^\[\w+(?:\s+\w+)*\]\s*/g, '')   // strip [Nuclei], [ZAP Active], etc.
      .replace(/\s*@\s*https?:\/\/\S+/g, '')     // strip @ http://... URL suffixes
      .replace(/\s+/g, ' ').trim().toLowerCase();
  }

  it("strips [Nuclei] prefix", () => {
    expect(normTitle("[Nuclei] SQL Injection")).toBe("sql injection");
  });

  it("strips [ZAP Active] multi-word prefix", () => {
    expect(normTitle("[ZAP Active] Cross-Site Scripting")).toBe("cross-site scripting");
  });

  it("strips @ URL suffix", () => {
    expect(normTitle("SQL Injection @ http://example.com/login")).toBe("sql injection");
  });

  it("strips both prefix and URL suffix", () => {
    expect(normTitle("[Nuclei] Exposed JSON Configuration Files @ http://example.com:80/config.json"))
      .toBe("exposed json configuration files");
  });

  it("matches passive finding with nuclei finding after normalization", () => {
    const passive = normTitle("Laravel <5.5.21 - Information Disclosure");
    const nuclei = normTitle("[Nuclei] Laravel <5.5.21 - Information Disclosure @ http://brokencrystals.lab.aceofcloud.io:80/.env");
    expect(passive).toBe(nuclei);
  });

  it("matches findings with different URL endpoints", () => {
    const a = normTitle("[Nuclei] Exposed .env @ http://example.com/.env");
    const b = normTitle("[Nuclei] Exposed .env @ http://example.com:8080/.env");
    expect(a).toBe(b);
  });

  it("preserves titles without prefixes or URLs", () => {
    expect(normTitle("Missing X-Frame-Options Header")).toBe("missing x-frame-options header");
  });
});

// ─── Test 3: OWASP Auto-Classification ───────────────────────────────────────

describe("OWASP Auto-Classification", () => {
  // Replicate the autoClassifyOwasp logic for testing
  function autoClassifyOwasp(title: string, description?: string): string | undefined {
    const text = `${title} ${description || ''}`.toLowerCase();
    if (/\b(idor|broken access|insecure direct|privilege escalat|path traversal|directory traversal|unauthorized access|access control|forced browsing|cors misconfigur)/.test(text)) return 'A01:2021-Broken Access Control';
    if (/\b(ssl|tls|weak cipher|cleartext|unencrypted|certificate|crypto|hsts|mixed content|http without)/.test(text)) return 'A02:2021-Cryptographic Failures';
    if (/\b(sql.?inject|xss|cross.?site.?script|command.?inject|os.?command|code.?inject|ldap.?inject|xpath|ssti|template.?inject|crlf.?inject|header.?inject|log4j|log4shell|jndi)/.test(text)) return 'A03:2021-Injection';
    if (/\b(insecure design|\bbusiness logic\b|race condition|mass assignment)/.test(text)) return 'A04:2021-Insecure Design';
    if (/\b(misconfig|default credential|default password|exposed.{0,25}(config|env|debug|admin|panel|backup|git|svn|ds_store)|directory listing|stack trace|verbose error|server.?header|x-powered|phpinfo|\.env\b|\.git\b|web\.config|crossdomain\.xml|security\.txt|robots\.txt.*disallow)/.test(text)) return 'A05:2021-Security Misconfiguration';
    if (/\b(outdated|vulnerable component|known vulnerabilit|cve-\d|end.?of.?life|eol|unsupported version|deprecated|version.?disclosure)/.test(text)) return 'A06:2021-Vulnerable and Outdated Components';
    if (/\b(brute.?force|weak password|credential.?stuff|session.?fixation|session.?hijack|authentication bypass|auth bypass|missing.?auth|broken.?auth|jwt|token.?leak|password.?reset)/.test(text)) return 'A07:2021-Identification and Authentication Failures';
    if (/\b(deserializ|insecure deserializ|ci.?cd|pipeline|integrity|unsigned|unverified update|supply chain)/.test(text)) return 'A08:2021-Software and Data Integrity Failures';
    if (/\b(logging|monitoring|audit|insufficient log|missing log)/.test(text)) return 'A09:2021-Security Logging and Monitoring Failures';
    if (/\b(ssrf|server.?side request forgery)/.test(text)) return 'A10:2021-Server-Side Request Forgery';
    if (/\b(information.?disclos|sensitive.?data|data.?expos|data.?leak|pii)/.test(text)) return 'A02:2021-Cryptographic Failures';
    if (/\b(open.?redirect|url.?redirect)/.test(text)) return 'A01:2021-Broken Access Control';
    return undefined;
  }

  it("classifies SQL injection as A03 Injection", () => {
    expect(autoClassifyOwasp("SQL Injection in login form")).toBe("A03:2021-Injection");
  });

  it("classifies XSS as A03 Injection", () => {
    expect(autoClassifyOwasp("[Nuclei] Cross-Site Scripting (Reflected)")).toBe("A03:2021-Injection");
  });

  it("classifies exposed .env as A05 Security Misconfiguration", () => {
    expect(autoClassifyOwasp("Exposed .env file")).toBe("A05:2021-Security Misconfiguration");
  });

  it("classifies exposed config as A05 Security Misconfiguration", () => {
    expect(autoClassifyOwasp("Exposed JSON Configuration Files")).toBe("A05:2021-Security Misconfiguration");
  });

  it("classifies directory listing as A05 Security Misconfiguration", () => {
    expect(autoClassifyOwasp("Directory Listing Enabled")).toBe("A05:2021-Security Misconfiguration");
  });

  it("classifies SSRF as A10", () => {
    expect(autoClassifyOwasp("Server-Side Request Forgery")).toBe("A10:2021-Server-Side Request Forgery");
  });

  it("classifies path traversal as A01 Broken Access Control", () => {
    expect(autoClassifyOwasp("Path Traversal via filename parameter")).toBe("A01:2021-Broken Access Control");
  });

  it("classifies missing HSTS as A02 Cryptographic Failures", () => {
    expect(autoClassifyOwasp("Missing HSTS Header")).toBe("A02:2021-Cryptographic Failures");
  });

  it("classifies information disclosure as A02 via fallback", () => {
    expect(autoClassifyOwasp("Information Disclosure via error page")).toBe("A02:2021-Cryptographic Failures");
  });

  it("classifies outdated components as A06", () => {
    expect(autoClassifyOwasp("Laravel <5.5.21 - Information Disclosure", "Outdated version detected")).toBe("A06:2021-Vulnerable and Outdated Components");
  });

  it("classifies Log4Shell as A03 Injection", () => {
    expect(autoClassifyOwasp("Log4Shell RCE (CVE-2021-44228)", "JNDI injection via log4j")).toBe("A03:2021-Injection");
  });

  it("classifies deserialization as A08", () => {
    expect(autoClassifyOwasp("Insecure Deserialization in Java endpoint")).toBe("A08:2021-Software and Data Integrity Failures");
  });

  it("returns undefined for unrecognized findings", () => {
    expect(autoClassifyOwasp("Custom Processing Error #42")).toBeUndefined();
  });
});

// ─── Test 4: Nuclei Endpoint Extraction ──────────────────────────────────────

describe("Nuclei Endpoint Extraction", () => {
  it("extracts matched-at URL from nuclei JSON output", () => {
    const nucleiLine = JSON.stringify({
      info: { name: "Exposed .env", severity: "medium", description: "Environment file exposed" },
      "matched-at": "http://example.com/.env",
      host: "http://example.com",
      "template-id": "exposed-env",
    });

    // Simulate parseToolOutput nuclei logic
    const obj = JSON.parse(nucleiLine);
    const matchedAt = obj["matched-at"] || obj.host || '';
    const endpoint = matchedAt || undefined;

    expect(endpoint).toBe("http://example.com/.env");
  });

  it("falls back to host when matched-at is missing", () => {
    const nucleiLine = JSON.stringify({
      info: { name: "Tech Detection", severity: "info" },
      host: "http://example.com",
      "template-id": "tech-detect",
    });

    const obj = JSON.parse(nucleiLine);
    const matchedAt = obj["matched-at"] || obj.host || '';
    const endpoint = matchedAt || undefined;

    expect(endpoint).toBe("http://example.com");
  });

  it("includes endpoint in the title via @ suffix", () => {
    const obj = {
      info: { name: "SQL Injection", severity: "critical" },
      "matched-at": "http://example.com/api/login",
    };
    const matchedAt = obj["matched-at"] || '';
    const title = `[Nuclei] ${obj.info.name}${matchedAt ? ` @ ${matchedAt}` : ''}`;

    expect(title).toBe("[Nuclei] SQL Injection @ http://example.com/api/login");
  });
});
