/**
 * PoC Generator — Transform scan findings into reproducible proof-of-concept commands
 *
 * Shannon-inspired: "No Exploit, No Report" — every finding should have a reproduction step.
 * This module generates curl/HTTP commands that operators can copy-paste to verify findings.
 */

import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PoCStep {
  /** Human-readable description of what this step does */
  description: string;
  /** The actual command to run (curl, nmap, etc.) */
  command: string;
  /** Expected output pattern that confirms the vulnerability */
  expectedOutput?: string;
  /** Risk level of running this command */
  risk: "safe" | "low" | "medium" | "high";
}

export interface ProofOfConcept {
  /** Finding ID this PoC is for */
  findingId: string;
  /** One-line summary */
  title: string;
  /** Vulnerability class */
  vulnClass: string;
  /** Target URL or host:port */
  target: string;
  /** Ordered reproduction steps */
  steps: PoCStep[];
  /** Impact statement */
  impact: string;
  /** Remediation recommendation */
  remediation: string;
  /** Whether this PoC was auto-generated or LLM-enhanced */
  source: "auto" | "llm";
  /** Generation timestamp */
  generatedAt: number;
}

// ─── Auto-generated PoCs for common finding types ────────────────────────

/**
 * Generate a PoC from a scan finding without LLM (fast, deterministic).
 * Covers the most common finding types from nuclei, nikto, nmap, gobuster.
 */
export function generateAutoPoC(finding: {
  id: string;
  severity: string;
  title: string;
  cve?: string;
  tool?: string;
  target?: string;
  port?: number;
  rawOutput?: string;
}): ProofOfConcept | null {
  const target = finding.target || "TARGET";
  const title = (finding.title || "").toLowerCase();
  const cve = finding.cve || "";

  // ── Missing Security Headers ──
  if (title.includes("x-frame-options") || title.includes("clickjacking")) {
    return {
      findingId: finding.id,
      title: `Missing X-Frame-Options Header on ${target}`,
      vulnClass: "missing-header",
      target,
      steps: [
        {
          description: "Check for missing X-Frame-Options header",
          command: `curl -sI ${target} | grep -i "x-frame-options"`,
          expectedOutput: "No output = header is missing (vulnerable to clickjacking)",
          risk: "safe",
        },
        {
          description: "Verify with an iframe embed test",
          command: `echo '<html><body><iframe src="${target}" width="100%" height="500"></iframe></body></html>' > /tmp/clickjack-test.html && echo "Open /tmp/clickjack-test.html in a browser"`,
          expectedOutput: "If the page loads in the iframe, clickjacking is possible",
          risk: "safe",
        },
      ],
      impact: "Attackers can embed this page in an iframe on a malicious site, tricking users into clicking hidden buttons or links (clickjacking).",
      remediation: "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` response header.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  if (title.includes("x-content-type") || title.includes("mime sniffing")) {
    return {
      findingId: finding.id,
      title: `Missing X-Content-Type-Options Header on ${target}`,
      vulnClass: "missing-header",
      target,
      steps: [
        {
          description: "Check for missing X-Content-Type-Options header",
          command: `curl -sI ${target} | grep -i "x-content-type-options"`,
          expectedOutput: "No output = header is missing",
          risk: "safe",
        },
      ],
      impact: "Browser may MIME-sniff responses, potentially executing uploaded files as scripts.",
      remediation: "Add `X-Content-Type-Options: nosniff` response header.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  if (title.includes("strict-transport") || title.includes("hsts")) {
    return {
      findingId: finding.id,
      title: `Missing HSTS Header on ${target}`,
      vulnClass: "missing-header",
      target,
      steps: [
        {
          description: "Check for missing Strict-Transport-Security header",
          command: `curl -sI ${target} | grep -i "strict-transport-security"`,
          expectedOutput: "No output = HSTS not configured",
          risk: "safe",
        },
      ],
      impact: "Users may be vulnerable to SSL stripping attacks (MITM downgrade from HTTPS to HTTP).",
      remediation: "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` response header.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  if (title.includes("content-security-policy") || title.includes("csp")) {
    return {
      findingId: finding.id,
      title: `Missing Content-Security-Policy Header on ${target}`,
      vulnClass: "missing-header",
      target,
      steps: [
        {
          description: "Check for missing CSP header",
          command: `curl -sI ${target} | grep -i "content-security-policy"`,
          expectedOutput: "No output = CSP not configured",
          risk: "safe",
        },
      ],
      impact: "Without CSP, the application is more vulnerable to XSS attacks as browsers cannot restrict script sources.",
      remediation: "Implement a Content-Security-Policy header with appropriate directives.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  // ── Server Version Disclosure ──
  if (title.includes("server version") || title.includes("server banner") || title.includes("server header")) {
    return {
      findingId: finding.id,
      title: `Server Version Disclosure on ${target}`,
      vulnClass: "information-disclosure",
      target,
      steps: [
        {
          description: "Extract server version from response headers",
          command: `curl -sI ${target} | grep -i "^server:"`,
          expectedOutput: "Server header reveals version information",
          risk: "safe",
        },
      ],
      impact: "Exposed server version helps attackers identify known vulnerabilities for that specific version.",
      remediation: "Configure the web server to suppress version information in the Server header.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  // ── Directory Listing ──
  if (title.includes("directory listing") || title.includes("directory index") || title.includes("indexing")) {
    return {
      findingId: finding.id,
      title: `Directory Listing Enabled on ${target}`,
      vulnClass: "information-disclosure",
      target,
      steps: [
        {
          description: "Check if directory listing is enabled",
          command: `curl -s ${target} | grep -i "index of\\|directory listing\\|parent directory"`,
          expectedOutput: "Output containing 'Index of' or 'Directory listing' confirms the vulnerability",
          risk: "safe",
        },
      ],
      impact: "Attackers can browse the directory structure and discover sensitive files, backup files, or configuration files.",
      remediation: "Disable directory listing in the web server configuration (e.g., `Options -Indexes` in Apache).",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  // ── Open Ports / Services ──
  if (title.includes("open port") || title.includes("exposed service")) {
    const port = finding.port || "PORT";
    return {
      findingId: finding.id,
      title: `Exposed Service on ${target}:${port}`,
      vulnClass: "exposed-service",
      target: `${target}:${port}`,
      steps: [
        {
          description: "Verify the service is accessible",
          command: `nmap -sV -p ${port} ${target}`,
          expectedOutput: "Port shows as open with service version",
          risk: "safe",
        },
        {
          description: "Attempt banner grab",
          command: `echo "" | nc -w 5 ${target} ${port}`,
          expectedOutput: "Service banner or response",
          risk: "safe",
        },
      ],
      impact: "Exposed services increase the attack surface and may have known vulnerabilities.",
      remediation: "Restrict access to this port using firewall rules. Only expose services that need to be publicly accessible.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  // ── SSL/TLS Issues ──
  if (title.includes("ssl") || title.includes("tls") || title.includes("certificate")) {
    return {
      findingId: finding.id,
      title: `SSL/TLS Issue on ${target}`,
      vulnClass: "ssl-tls",
      target,
      steps: [
        {
          description: "Check SSL/TLS configuration",
          command: `echo | openssl s_client -connect ${target.replace(/^https?:\/\//, '')}:443 -servername ${target.replace(/^https?:\/\//, '').split(':')[0]} 2>/dev/null | openssl x509 -noout -dates -subject`,
          expectedOutput: "Certificate details including expiry and subject",
          risk: "safe",
        },
        {
          description: "Check supported TLS versions",
          command: `nmap --script ssl-enum-ciphers -p 443 ${target.replace(/^https?:\/\//, '').split(':')[0]}`,
          expectedOutput: "Lists supported TLS versions and cipher suites",
          risk: "safe",
        },
      ],
      impact: "Weak SSL/TLS configuration may allow man-in-the-middle attacks or data interception.",
      remediation: "Ensure TLS 1.2+ is enforced, disable weak ciphers, and use valid certificates.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  // ── CVE-based findings ──
  if (cve) {
    return {
      findingId: finding.id,
      title: `${cve}: ${finding.title} on ${target}`,
      vulnClass: "cve",
      target,
      steps: [
        {
          description: `Verify ${cve} with nuclei`,
          command: `nuclei -u ${target} -id ${cve.toLowerCase().replace('cve-', 'CVE-')} -jsonl`,
          expectedOutput: `Nuclei confirms ${cve} is present`,
          risk: "low",
        },
        {
          description: "Check CVE details for exploitation guidance",
          command: `curl -s "https://cveawg.mitre.org/api/cve/${cve}" | python3 -m json.tool | head -50`,
          expectedOutput: "CVE description and affected versions",
          risk: "safe",
        },
      ],
      impact: finding.title,
      remediation: `Patch or upgrade the affected component. See https://nvd.nist.gov/vuln/detail/${cve} for details.`,
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  // ── Generic nuclei finding ──
  if (finding.tool === "nuclei") {
    return {
      findingId: finding.id,
      title: `${finding.title} on ${target}`,
      vulnClass: "nuclei-detection",
      target,
      steps: [
        {
          description: "Reproduce with curl",
          command: `curl -sI ${target}`,
          expectedOutput: "Check response headers and body for the reported issue",
          risk: "safe",
        },
      ],
      impact: finding.title,
      remediation: "Review the nuclei template documentation for specific remediation guidance.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }

  return null;
}

// ─── LLM-Enhanced PoC Generation ─────────────────────────────────────────

/**
 * Generate a detailed PoC using LLM for complex findings.
 * Falls back to auto-generation if LLM fails.
 */
export async function generateLLMPoC(finding: {
  id: string;
  severity: string;
  title: string;
  cve?: string;
  tool?: string;
  target?: string;
  port?: number;
  rawOutput?: string;
  service?: string;
}): Promise<ProofOfConcept> {
  const target = finding.target || "TARGET";

  try {
    const response = await invokeLLM({ _caller: "poc-generator",
      _caller: "poc-generator.generateLLMPoC",
      messages: [
        {
          role: "system",
          content: `You are a senior penetration tester generating proof-of-concept (PoC) reproduction steps for security findings.
Generate practical, copy-paste ready commands that an operator can use to verify the vulnerability.
Rules:
- Use curl, nmap, openssl, or standard CLI tools only
- Each step must be a single command that can be copy-pasted
- Mark risk level: "safe" (read-only), "low" (minor changes), "medium" (may trigger alerts), "high" (may cause disruption)
- Be specific about expected output that confirms the vulnerability
- Include remediation advice
Return valid JSON only.`,
        },
        {
          role: "user",
          content: `Generate a PoC for this finding:
Title: ${finding.title}
Severity: ${finding.severity}
CVE: ${finding.cve || "N/A"}
Target: ${target}
Port: ${finding.port || "N/A"}
Service: ${finding.service || "N/A"}
Tool: ${finding.tool || "N/A"}
Raw Output (first 500 chars): ${(finding.rawOutput || "").slice(0, 500)}

Return JSON with this structure:
{
  "steps": [{ "description": "...", "command": "...", "expectedOutput": "...", "risk": "safe|low|medium|high" }],
  "impact": "...",
  "remediation": "...",
  "vulnClass": "..."
}`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "poc_generation",
          strict: true,
          schema: {
            type: "object",
            properties: {
              steps: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    description: { type: "string" },
                    command: { type: "string" },
                    expectedOutput: { type: "string" },
                    risk: { type: "string", enum: ["safe", "low", "medium", "high"] },
                  },
                  required: ["description", "command", "expectedOutput", "risk"],
                  additionalProperties: false,
                },
              },
              impact: { type: "string" },
              remediation: { type: "string" },
              vulnClass: { type: "string" },
            },
            required: ["steps", "impact", "remediation", "vulnClass"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);

    return {
      findingId: finding.id,
      title: `${finding.cve ? finding.cve + ": " : ""}${finding.title} on ${target}`,
      vulnClass: parsed.vulnClass || "unknown",
      target,
      steps: parsed.steps.map((s: any) => ({
        description: s.description,
        command: s.command,
        expectedOutput: s.expectedOutput,
        risk: s.risk as PoCStep["risk"],
      })),
      impact: parsed.impact,
      remediation: parsed.remediation,
      source: "llm",
      generatedAt: Date.now(),
    };
  } catch (e: any) {
    console.error(`[PoCGenerator] LLM generation failed for ${finding.title}:`, e.message);
    // Fall back to auto-generation
    const autoPoC = generateAutoPoC(finding);
    if (autoPoC) return autoPoC;

    // Last resort: generic PoC
    return {
      findingId: finding.id,
      title: `${finding.title} on ${target}`,
      vulnClass: "unknown",
      target,
      steps: [
        {
          description: "Verify the finding manually",
          command: `curl -sI ${target}`,
          expectedOutput: "Review response for the reported issue",
          risk: "safe",
        },
      ],
      impact: finding.title,
      remediation: "Review the finding details and apply appropriate patches or configuration changes.",
      source: "auto",
      generatedAt: Date.now(),
    };
  }
}

/**
 * Generate PoCs for all findings on an asset.
 * Uses auto-generation for common types, LLM for complex/CVE findings.
 */
export async function generatePoCsForAsset(asset: {
  hostname: string;
  ip?: string;
  vulns: Array<{ id: string; severity: string; title: string; cve?: string }>;
  toolResults: Array<{ tool: string; findings: Array<{ severity: string; title: string; cve?: string }>; outputPreview: string }>;
}): Promise<ProofOfConcept[]> {
  const pocs: ProofOfConcept[] = [];
  const target = asset.hostname || asset.ip || "unknown";

  for (const vuln of asset.vulns) {
    // Try auto-generation first (fast, no LLM call)
    const autoPoC = generateAutoPoC({
      ...vuln,
      target,
      tool: asset.toolResults.find(tr => tr.findings.some(f => f.title === vuln.title))?.tool,
    });

    if (autoPoC) {
      pocs.push(autoPoC);
    } else if (vuln.severity === "critical" || vuln.severity === "high" || vuln.cve) {
      // Use LLM for critical/high findings or CVE-based findings
      try {
        const llmPoC = await generateLLMPoC({
          ...vuln,
          target,
          tool: asset.toolResults.find(tr => tr.findings.some(f => f.title === vuln.title))?.tool,
          rawOutput: asset.toolResults.find(tr => tr.findings.some(f => f.title === vuln.title))?.outputPreview,
        });
        pocs.push(llmPoC);
      } catch (e: any) {
        console.error(`[PoCGenerator] Failed to generate PoC for ${vuln.title}:`, e.message);
      }
    }
  }

  return pocs;
}
