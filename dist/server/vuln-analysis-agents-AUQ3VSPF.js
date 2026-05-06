import {
  init_llm,
  invokeLLM
} from "./chunk-4BQS7LEI.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-analysis-agents.ts
function classifyVulnerability(finding) {
  const text = `${finding.title} ${finding.description || ""} ${finding.cve || ""}`.toLowerCase();
  if (/sql.?inject|sqli|union.?select|blind.?inject|command.?inject|os.?command|ssti|template.?inject|xxe|xml.?extern|nosql.?inject|ldap.?inject/i.test(text)) {
    return "injection";
  }
  if (/cross.?site.?script|xss|reflected.?xss|stored.?xss|dom.?xss|script.?inject|csp.?bypass/i.test(text)) {
    return "xss";
  }
  if (/ssrf|server.?side.?request|url.?redirect|open.?redirect|dns.?rebind|metadata.?service/i.test(text)) {
    return "ssrf";
  }
  if (/auth.?bypass|brute.?force|credential|password|login.?bypass|session.?fixat|jwt|token.?manipul|mfa.?bypass|default.?password|weak.?password/i.test(text)) {
    return "auth";
  }
  if (/idor|insecure.?direct|privilege.?escalat|access.?control|unauthorized.?access|rbac|horizontal.?escalat|vertical.?escalat|broken.?access/i.test(text)) {
    return "authz";
  }
  if (/ssl|tls|cipher|certificate|crypto|encrypt|weak.?key|heartbleed|poodle|beast|drown|sweet32|rc4|sha1|md5.*(hash|crypt)|padding.?oracle/i.test(text)) {
    return "crypto";
  }
  if (/misconfig|default.?cred|admin.?panel|directory.?list|debug.?mode|cors|security.?header|x-frame|x-content|hsts|clickjack|server.?info|phpinfo/i.test(text)) {
    return "config";
  }
  if (/info.?disclos|info.?leak|version.?disclos|stack.?trace|error.?message|source.?code|backup.?file|\.bak|\.old|internal.?ip|server.?banner|technology.?detect/i.test(text)) {
    return "info_leak";
  }
  return "config";
}
async function analyzeVulnerability(finding, context) {
  const agentClass = classifyVulnerability(finding);
  const agentPrompt = AGENT_PROMPTS[agentClass];
  const contextStr = context ? `

ADDITIONAL CONTEXT:
- Asset: ${context.asset || finding.asset}
- Services: ${context.services?.join(", ") || "unknown"}
- Other findings on this asset: ${context.otherFindings?.map((f) => f.title).join(", ") || "none"}` : "";
  const userMessage = `Analyze this vulnerability finding and provide your expert assessment:

FINDING:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Asset: ${finding.asset}${finding.port ? `:${finding.port}` : ""}
- Service: ${finding.service || "unknown"}
- Tool: ${finding.tool || "unknown"}
- CVE: ${finding.cve || "none"}
- Description: ${finding.description || "No description available"}
${finding.rawOutput ? `- Raw Output (first 500 chars): ${finding.rawOutput.substring(0, 500)}` : ""}
${contextStr}

Respond in JSON format with this exact structure:
{
  "technicalAnalysis": "detailed technical analysis",
  "exploitationPath": ["step 1", "step 2", ...],
  "impactAssessment": "real-world impact description",
  "riskScore": 7.5,
  "chainable": true,
  "remediation": ["fix 1", "fix 2", ...],
  "poc": "curl command or HTTP request",
  "relatedCves": ["CVE-2024-XXXX"],
  "confidence": "high"
}`;
  try {
    const response = await invokeLLM({
      _caller: "vuln-analysis-agents.analyzeVulnerability",
      messages: [
        { role: "system", content: agentPrompt },
        { role: "user", content: userMessage }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "vuln_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              technicalAnalysis: { type: "string", description: "Detailed technical analysis" },
              exploitationPath: { type: "array", items: { type: "string" }, description: "Step-by-step exploitation" },
              impactAssessment: { type: "string", description: "Real-world impact" },
              riskScore: { type: "number", description: "Risk score 0-10" },
              chainable: { type: "boolean", description: "Can be chained with other vulns" },
              remediation: { type: "array", items: { type: "string" }, description: "Remediation steps" },
              poc: { type: "string", description: "Proof of concept command" },
              relatedCves: { type: "array", items: { type: "string" }, description: "Related CVEs" },
              confidence: { type: "string", description: "Confidence level: high, medium, or low" }
            },
            required: ["technicalAnalysis", "exploitationPath", "impactAssessment", "riskScore", "chainable", "remediation", "poc", "relatedCves", "confidence"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const analysis = JSON.parse(content);
    return {
      agentClass,
      finding,
      analysis: {
        technicalAnalysis: analysis.technicalAnalysis || "Analysis unavailable",
        exploitationPath: analysis.exploitationPath || [],
        impactAssessment: analysis.impactAssessment || "Impact assessment unavailable",
        riskScore: Math.min(10, Math.max(0, analysis.riskScore || 5)),
        chainable: analysis.chainable || false,
        remediation: analysis.remediation || [],
        poc: analysis.poc || void 0,
        relatedCves: analysis.relatedCves || [],
        confidence: ["high", "medium", "low"].includes(analysis.confidence) ? analysis.confidence : "medium"
      }
    };
  } catch (error) {
    console.error(`[VulnAgent:${agentClass}] Analysis failed for "${finding.title}":`, error.message);
    return {
      agentClass,
      finding,
      analysis: {
        technicalAnalysis: `Automated analysis failed: ${error.message}. Manual review recommended for: ${finding.title}`,
        exploitationPath: ["Manual verification required"],
        impactAssessment: `Severity: ${finding.severity}. Further manual analysis needed.`,
        riskScore: finding.severity === "critical" ? 9 : finding.severity === "high" ? 7 : finding.severity === "medium" ? 5 : 3,
        chainable: false,
        remediation: ["Perform manual vulnerability assessment", "Review vendor security advisories"],
        relatedCves: finding.cve ? [finding.cve] : [],
        confidence: "low"
      }
    };
  }
}
async function batchAnalyzeFindings(findings, options) {
  const concurrency = options?.maxConcurrency || 3;
  const results = [];
  const grouped = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const cls = classifyVulnerability(finding);
    if (!grouped.has(cls)) grouped.set(cls, []);
    grouped.get(cls).push(finding);
  }
  console.log(`[VulnAgents] Analyzing ${findings.length} findings across ${grouped.size} agent classes: ${[...grouped.keys()].join(", ")}`);
  const allTasks = [];
  for (const [, classFindings] of grouped) {
    for (const finding of classFindings) {
      allTasks.push(
        () => analyzeVulnerability(finding, {
          asset: finding.asset,
          services: options?.services?.[finding.asset],
          otherFindings: classFindings.filter((f) => f.id !== finding.id)
        })
      );
    }
  }
  for (let i = 0; i < allTasks.length; i += concurrency) {
    const batch = allTasks.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(batch.map((fn) => fn()));
    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        results.push(result.value);
      }
    }
  }
  console.log(`[VulnAgents] Completed: ${results.length}/${findings.length} analyses (${results.filter((r) => r.analysis.confidence === "high").length} high confidence)`);
  return results;
}
function generateAnalysisSummary(results) {
  const byClass = {};
  const bySeverity = {};
  let totalRisk = 0;
  let chainableCount = 0;
  for (const r of results) {
    byClass[r.agentClass] = (byClass[r.agentClass] || 0) + 1;
    bySeverity[r.finding.severity] = (bySeverity[r.finding.severity] || 0) + 1;
    totalRisk += r.analysis.riskScore;
    if (r.analysis.chainable) chainableCount++;
  }
  const sorted = [...results].sort((a, b) => b.analysis.riskScore - a.analysis.riskScore);
  const topRisks = sorted.slice(0, 10).map((r) => ({
    title: r.finding.title,
    riskScore: r.analysis.riskScore,
    agentClass: r.agentClass
  }));
  const remediationCounts = /* @__PURE__ */ new Map();
  for (const r of results) {
    for (const step of r.analysis.remediation) {
      remediationCounts.set(step, (remediationCounts.get(step) || 0) + 1);
    }
  }
  const remediationPriority = [...remediationCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([step]) => step);
  return {
    totalFindings: results.length,
    byClass,
    bySeverity,
    avgRiskScore: results.length > 0 ? Math.round(totalRisk / results.length * 10) / 10 : 0,
    chainableCount,
    topRisks,
    remediationPriority
  };
}
var AGENT_PROMPTS;
var init_vuln_analysis_agents = __esm({
  "server/lib/vuln-analysis-agents.ts"() {
    init_llm();
    AGENT_PROMPTS = {
      injection: `You are a specialized Injection Vulnerability Analysis Agent. You are an expert in:
- SQL Injection (Union-based, Blind, Time-based, Error-based, Second-order)
- Command Injection (OS command injection, argument injection)
- LDAP Injection
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE) Injection
- NoSQL Injection
- Expression Language Injection

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify the exact injection type, the vulnerable parameter/endpoint, and the underlying cause
2. EXPLOITATION PATH: Step-by-step commands or requests to exploit (sqlmap commands, manual payloads, etc.)
3. IMPACT: What data can be extracted, what commands can be run, lateral movement potential
4. RISK SCORE: 0-10 based on exploitability and impact (most injection vulns are 7-10)
5. CHAINABILITY: Can this be chained with other vulns for deeper access?
6. REMEDIATION: Specific code-level fixes (parameterized queries, input validation, WAF rules)
7. POC: A concrete curl command or HTTP request that demonstrates the vulnerability
8. RELATED CVEs: Known CVEs for the same software/version if applicable`,
      xss: `You are a specialized Cross-Site Scripting (XSS) Analysis Agent. You are an expert in:
- Reflected XSS
- Stored/Persistent XSS
- DOM-based XSS
- Mutation XSS (mXSS)
- Content Security Policy (CSP) bypass techniques
- XSS filter evasion
- Browser-specific XSS vectors

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify XSS type, injection point, sink/source for DOM XSS, encoding context
2. EXPLOITATION PATH: Payload construction, filter bypass techniques, cookie theft/session hijacking steps
3. IMPACT: Session hijacking, credential theft, keylogging, defacement, worm propagation potential
4. RISK SCORE: 0-10 (Stored XSS typically 7-9, Reflected 5-7, DOM-based 4-7)
5. CHAINABILITY: Can this XSS be used to escalate (e.g., admin account takeover via stored XSS)?
6. REMEDIATION: Output encoding strategy, CSP headers, HttpOnly cookies, DOMPurify usage
7. POC: Working XSS payload and delivery mechanism
8. RELATED CVEs: Known XSS CVEs for the framework/CMS`,
      auth: `You are a specialized Authentication Vulnerability Analysis Agent. You are an expert in:
- Authentication bypass techniques
- Brute force and credential stuffing
- Password reset flaws
- Multi-factor authentication bypass
- Session management weaknesses
- JWT/token vulnerabilities
- OAuth/OIDC misconfigurations
- Default/weak credentials

CRITICAL FALSE POSITIVE PATTERN \u2014 Hydra http-get/https-get:
Hydra http-get mode tests HTTP Basic Authentication (Authorization header). Many modern web apps (SPAs, Nuxt.js, React, Angular behind CloudFront/CDN) do NOT use HTTP Basic Auth \u2014 they use form-based login, OAuth, or JWT. These servers return HTTP 200 for ALL requests regardless of the Authorization header, causing Hydra to report every tested credential as "valid." If Hydra reports multiple different username:password combinations as valid via http-get/https-get, this is ALWAYS a false positive. Rate these as risk score 0-1 with false positive confidence High.

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify the auth mechanism, the specific weakness, and why it's exploitable
2. EXPLOITATION PATH: Step-by-step to bypass auth (timing attacks, token manipulation, etc.)
3. IMPACT: Account takeover scope, admin access potential, data exposure
4. RISK SCORE: 0-10 (auth bypass is typically 8-10)
5. CHAINABILITY: Can this lead to privilege escalation or lateral movement?
6. REMEDIATION: Specific fixes (rate limiting, MFA enforcement, session configuration, password policy)
7. POC: Authentication bypass request/command
8. RELATED CVEs: Known auth bypass CVEs for the technology stack`,
      authz: `You are a specialized Authorization Vulnerability Analysis Agent. You are an expert in:
- Insecure Direct Object References (IDOR)
- Horizontal privilege escalation
- Vertical privilege escalation
- Missing function-level access control
- Path traversal for authorization bypass
- Role-based access control (RBAC) flaws
- API authorization issues

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify the authorization model, the bypass mechanism, and affected resources
2. EXPLOITATION PATH: How to access other users' data, escalate to admin, bypass access controls
3. IMPACT: Data exposure scope, admin functionality access, multi-tenant isolation breach
4. RISK SCORE: 0-10 (IDOR typically 6-8, privilege escalation 8-10)
5. CHAINABILITY: Can this be combined with auth issues for full account takeover?
6. REMEDIATION: Server-side authorization checks, object-level permissions, RBAC implementation
7. POC: Request showing unauthorized access to another user's resource
8. RELATED CVEs: Known authorization bypass CVEs`,
      ssrf: `You are a specialized Server-Side Request Forgery (SSRF) Analysis Agent. You are an expert in:
- Basic SSRF (internal service access)
- Blind SSRF
- SSRF via URL parsers
- DNS rebinding
- Cloud metadata service access (AWS IMDSv1/v2, GCP, Azure)
- Internal network scanning via SSRF
- Protocol smuggling (gopher://, file://, dict://)

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify the SSRF type, vulnerable parameter, URL parsing behavior
2. EXPLOITATION PATH: Internal service enumeration, cloud metadata extraction, port scanning
3. IMPACT: Internal network access, cloud credential theft, service interaction
4. RISK SCORE: 0-10 (cloud SSRF typically 9-10, basic internal 6-8)
5. CHAINABILITY: Can SSRF be used to pivot to internal services or extract cloud credentials?
6. REMEDIATION: URL allowlisting, disable unnecessary protocols, IMDSv2 enforcement, network segmentation
7. POC: SSRF request targeting internal service or cloud metadata
8. RELATED CVEs: Known SSRF CVEs for the framework`,
      crypto: `You are a specialized Cryptographic Vulnerability Analysis Agent. You are an expert in:
- Weak TLS/SSL configurations
- Deprecated cipher suites
- Certificate issues (expired, self-signed, wrong CN)
- Weak key sizes
- Insecure random number generation
- Hash function weaknesses
- Key management issues
- Padding oracle attacks

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify the specific crypto weakness, affected protocol/algorithm, and exposure
2. EXPLOITATION PATH: How to exploit (BEAST, POODLE, Heartbleed, downgrade attacks, etc.)
3. IMPACT: Data interception, man-in-the-middle potential, credential exposure
4. RISK SCORE: 0-10 (varies widely: expired cert 3-4, weak cipher 5-7, padding oracle 8-9)
5. CHAINABILITY: Can this enable MitM for further attacks?
6. REMEDIATION: TLS configuration, cipher suite ordering, certificate renewal, key rotation
7. POC: OpenSSL/discovery command showing the weakness
8. RELATED CVEs: Known crypto CVEs (Heartbleed, ROBOT, etc.)`,
      config: `You are a specialized Misconfiguration Analysis Agent. You are an expert in:
- Default credentials
- Exposed admin panels
- Directory listing enabled
- Debug mode in production
- Missing security headers
- CORS misconfigurations
- Unnecessary services/ports
- Cloud storage misconfigurations

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: Identify the specific misconfiguration, affected component, and root cause
2. EXPLOITATION PATH: How to leverage the misconfiguration for access or information
3. IMPACT: Data exposure, unauthorized access, service disruption potential
4. RISK SCORE: 0-10 (default creds 8-9, missing headers 2-4, debug mode 6-8)
5. CHAINABILITY: Can this misconfiguration enable other attacks?
6. REMEDIATION: Specific configuration changes, hardening steps, security header implementation
7. POC: Request/command demonstrating the misconfiguration
8. RELATED CVEs: Known CVEs for the specific software version`,
      info_leak: `You are a specialized Information Disclosure Analysis Agent. You are an expert in:
- Verbose error messages
- Stack traces in production
- Server version disclosure
- Technology fingerprinting
- Source code exposure
- Backup file exposure
- API documentation exposure
- Internal IP/hostname leakage

When analyzing a finding, provide:
1. TECHNICAL ANALYSIS: What information is exposed, through what mechanism, and its sensitivity
2. EXPLOITATION PATH: How the leaked information aids further attacks (version \u2192 CVE lookup, etc.)
3. IMPACT: Attack surface expansion, targeted exploit selection, social engineering enablement
4. RISK SCORE: 0-10 (version disclosure 2-3, source code 7-8, credentials in errors 9-10)
5. CHAINABILITY: How does this information enable other vulnerability classes?
6. REMEDIATION: Error handling, response header configuration, file access controls
7. POC: Request showing the information disclosure
8. RELATED CVEs: CVEs matching the disclosed software versions`
    };
  }
});
init_vuln_analysis_agents();
export {
  analyzeVulnerability,
  batchAnalyzeFindings,
  classifyVulnerability,
  generateAnalysisSummary
};
