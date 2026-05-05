import "./chunk-KFQGP6VL.js";

// server/lib/bounty-submission-optimizer.ts
var VULN_CVSS_DEFAULTS = {
  rce: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    score: 10,
    severity: "critical",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Changed", confidentiality: "High", integrity: "High", availability: "High" }
  },
  command_injection: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    score: 9.8,
    severity: "critical",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Unchanged", confidentiality: "High", integrity: "High", availability: "High" }
  },
  sqli_classic: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    score: 9.1,
    severity: "critical",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Unchanged", confidentiality: "High", integrity: "High", availability: "None" }
  },
  ssrf: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    score: 9.1,
    severity: "critical",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Changed", confidentiality: "High", integrity: "Low", availability: "None" }
  },
  idor: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    score: 8.1,
    severity: "high",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "Low", userInteraction: "None", scope: "Unchanged", confidentiality: "High", integrity: "High", availability: "None" }
  },
  xss_stored: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
    score: 5.4,
    severity: "medium",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "Low", userInteraction: "Required", scope: "Changed", confidentiality: "Low", integrity: "Low", availability: "None" }
  },
  xss_reflected: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    score: 6.1,
    severity: "medium",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "Required", scope: "Changed", confidentiality: "Low", integrity: "Low", availability: "None" }
  },
  auth_bypass: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    score: 9.1,
    severity: "critical",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Unchanged", confidentiality: "High", integrity: "High", availability: "None" }
  },
  open_redirect: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    score: 6.1,
    severity: "medium",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "Required", scope: "Changed", confidentiality: "Low", integrity: "Low", availability: "None" }
  },
  csrf: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    score: 6.5,
    severity: "medium",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "Required", scope: "Unchanged", confidentiality: "None", integrity: "High", availability: "None" }
  },
  info_disclosure: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    score: 5.3,
    severity: "medium",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Unchanged", confidentiality: "Low", integrity: "None", availability: "None" }
  },
  subdomain_takeover: {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    score: 7.2,
    severity: "high",
    breakdown: { attackVector: "Network", attackComplexity: "Low", privilegesRequired: "None", userInteraction: "None", scope: "Changed", confidentiality: "Low", integrity: "Low", availability: "None" }
  }
};
var VULN_CWE_MAP = {
  xss_reflected: { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation" },
  xss_stored: { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation" },
  xss_dom: { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation" },
  sqli_classic: { id: "CWE-89", name: "SQL Injection" },
  sqli_blind: { id: "CWE-89", name: "SQL Injection" },
  ssrf: { id: "CWE-918", name: "Server-Side Request Forgery" },
  ssrf_blind: { id: "CWE-918", name: "Server-Side Request Forgery" },
  idor: { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key" },
  bola: { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key" },
  auth_bypass: { id: "CWE-287", name: "Improper Authentication" },
  broken_auth: { id: "CWE-287", name: "Improper Authentication" },
  rce: { id: "CWE-94", name: "Improper Control of Generation of Code" },
  command_injection: { id: "CWE-78", name: "OS Command Injection" },
  path_traversal: { id: "CWE-22", name: "Path Traversal" },
  lfi: { id: "CWE-98", name: "Improper Control of Filename for Include/Require" },
  open_redirect: { id: "CWE-601", name: "URL Redirection to Untrusted Site" },
  csrf: { id: "CWE-352", name: "Cross-Site Request Forgery" },
  info_disclosure: { id: "CWE-200", name: "Exposure of Sensitive Information" },
  sensitive_data_exposure: { id: "CWE-200", name: "Exposure of Sensitive Information" },
  xxe: { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference" },
  ssti: { id: "CWE-1336", name: "Improper Neutralization of Special Elements Used in a Template Engine" },
  deserialization: { id: "CWE-502", name: "Deserialization of Untrusted Data" },
  cors_misconfiguration: { id: "CWE-942", name: "Permissive Cross-domain Policy with Untrusted Domains" },
  jwt_weakness: { id: "CWE-347", name: "Improper Verification of Cryptographic Signature" },
  subdomain_takeover: { id: "CWE-284", name: "Improper Access Control" },
  privilege_escalation: { id: "CWE-269", name: "Improper Privilege Management" },
  race_condition: { id: "CWE-362", name: "Concurrent Execution Using Shared Resource with Improper Synchronization" },
  graphql_introspection: { id: "CWE-200", name: "Exposure of Sensitive Information" },
  api_mass_assignment: { id: "CWE-915", name: "Improperly Controlled Modification of Dynamically-Determined Object Attributes" },
  business_logic: { id: "CWE-840", name: "Business Logic Errors" },
  cache_poisoning: { id: "CWE-444", name: "Inconsistent Interpretation of HTTP Requests" },
  http_request_smuggling: { id: "CWE-444", name: "Inconsistent Interpretation of HTTP Requests" }
};
var REMEDIATION_TEMPLATES = {
  xss_reflected: "Implement context-aware output encoding for all user-supplied input rendered in HTML responses. Use a Content Security Policy (CSP) that disallows inline scripts. Consider using a templating engine with auto-escaping enabled by default.",
  xss_stored: "Sanitize all user input on the server side before storage. Implement context-aware output encoding when rendering stored content. Deploy a strict Content Security Policy. Consider using DOMPurify or similar libraries for HTML sanitization.",
  sqli_classic: "Use parameterized queries (prepared statements) for all database interactions. Implement an ORM or query builder that handles parameterization automatically. Apply the principle of least privilege to database accounts used by the application.",
  ssrf: "Implement a URL allowlist for outbound requests. Validate and sanitize all user-supplied URLs. Block requests to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254). Use a dedicated egress proxy for outbound requests.",
  idor: "Implement proper authorization checks on every data access operation. Use indirect reference maps instead of exposing internal object IDs. Validate that the authenticated user has permission to access the requested resource.",
  auth_bypass: "Review and strengthen authentication logic. Ensure all endpoints require proper authentication. Implement multi-factor authentication for sensitive operations. Use established authentication frameworks rather than custom implementations.",
  rce: "Avoid executing user-supplied input as code. Use sandboxed execution environments when dynamic code execution is required. Implement strict input validation and sanitization. Apply the principle of least privilege to application processes.",
  open_redirect: "Validate redirect URLs against an allowlist of trusted domains. Use relative URLs for internal redirects. Implement a redirect warning page for external URLs. Avoid using user-supplied input directly in redirect targets.",
  csrf: "Implement anti-CSRF tokens (synchronizer token pattern) for all state-changing operations. Use the SameSite cookie attribute. Verify the Origin and Referer headers on sensitive requests.",
  cors_misconfiguration: "Configure CORS to only allow trusted origins. Avoid reflecting the Origin header directly. Do not use wildcard (*) with credentials. Implement a strict allowlist of permitted origins.",
  jwt_weakness: "Use asymmetric algorithms (RS256/ES256) instead of symmetric (HS256). Validate the algorithm header server-side. Use strong, unique secrets for signing. Implement proper token expiration and rotation.",
  subdomain_takeover: "Remove dangling DNS records (CNAMEs pointing to unclaimed services). Implement monitoring for DNS record changes. Regularly audit subdomain DNS configurations. Claim or reserve service endpoints before creating DNS records.",
  info_disclosure: "Remove or restrict access to debug endpoints, status pages, and verbose error messages in production. Configure web servers to suppress version information. Implement proper error handling that does not leak internal details.",
  path_traversal: "Validate and sanitize file paths. Use a chroot or jail for file operations. Implement an allowlist of permitted file paths. Avoid using user input directly in file system operations."
};
var PLATFORM_GUIDELINES = {
  hackerone: {
    titleFormat: (title, severity) => `[${severity.toUpperCase()}] ${title}`,
    severityScale: ["none", "low", "medium", "high", "critical"],
    requiresCWE: true,
    requiresCVSS: true,
    maxTitleLength: 150,
    notes: [
      "HackerOne uses CVSS 3.0 for severity calculation",
      "Include clear reproduction steps \u2014 triagers test submissions manually",
      "Reference the specific asset from the program scope",
      "Avoid submitting findings outside the defined scope"
    ]
  },
  bugcrowd: {
    titleFormat: (title, severity) => `${title} - ${severity.charAt(0).toUpperCase() + severity.slice(1)}`,
    severityScale: ["P5", "P4", "P3", "P2", "P1"],
    requiresCWE: true,
    requiresCVSS: false,
    maxTitleLength: 200,
    notes: [
      "Bugcrowd uses P1-P5 priority scale (P1 = critical)",
      "Bugcrowd Vulnerability Rating Taxonomy (VRT) determines baseline severity",
      "Include business impact in the description",
      "Screenshots and video PoCs significantly improve triage speed"
    ]
  },
  intigriti: {
    titleFormat: (title, severity) => `${title}`,
    severityScale: ["none", "low", "medium", "high", "critical", "exceptional"],
    requiresCWE: true,
    requiresCVSS: true,
    maxTitleLength: 200,
    notes: [
      "Intigriti uses CVSS 3.1 for severity",
      "Include domain/asset in the title for clarity",
      "Provide step-by-step reproduction with screenshots"
    ]
  },
  other: {
    titleFormat: (title) => title,
    severityScale: ["info", "low", "medium", "high", "critical"],
    requiresCWE: false,
    requiresCVSS: false,
    maxTitleLength: 250,
    notes: ["Follow the program-specific submission guidelines"]
  }
};
function assessSubmissionQuality(submission, input) {
  let score = 100;
  const issues = [];
  if (submission.title.length < 20) {
    score -= 10;
    issues.push("Title is too short \u2014 should clearly describe the vulnerability");
  }
  if (submission.title.length > 150) {
    score -= 5;
    issues.push("Title is too long \u2014 consider shortening for readability");
  }
  if (submission.reproductionSteps.length < 2) {
    score -= 20;
    issues.push("Too few reproduction steps \u2014 include at least 3 clear steps");
  }
  if (submission.reproductionSteps.length < 3) {
    score -= 10;
    issues.push("Consider adding more detailed reproduction steps");
  }
  if (!input.reproductionEvidence || input.reproductionEvidence.length === 0) {
    score -= 15;
    issues.push("No reproduction evidence provided \u2014 add request/response pairs or screenshots");
  }
  if (submission.impactStatement.length < 50) {
    score -= 10;
    issues.push("Impact statement is too brief \u2014 explain the real-world consequences");
  }
  if (submission.severityJustification.length < 30) {
    score -= 10;
    issues.push("Severity justification needs more detail");
  }
  if (!submission.cweId || submission.cweId === "CWE-0") {
    score -= 5;
    issues.push("Missing CWE classification");
  }
  if (submission.technicalDetails.length < 100) {
    score -= 10;
    issues.push("Technical details section needs more depth");
  }
  if (submission.remediation.length < 50) {
    score -= 5;
    issues.push("Remediation guidance could be more specific");
  }
  return { score: Math.max(score, 0), issues };
}
function generateReproductionSteps(input) {
  const steps = [];
  let stepNum = 1;
  steps.push({
    stepNumber: stepNum++,
    action: `Navigate to ${input.affectedEndpoint}`,
    expectedResult: "The target endpoint loads successfully"
  });
  const payloadStep = getPayloadStep(input.vulnClass, input.affectedEndpoint);
  if (payloadStep) {
    steps.push({ ...payloadStep, stepNumber: stepNum++ });
  }
  steps.push({
    stepNumber: stepNum++,
    action: `Submit the crafted request to ${input.affectedEndpoint}`,
    expectedResult: `Observe the ${input.vulnClass.replace(/_/g, " ")} vulnerability trigger`
  });
  steps.push({
    stepNumber: stepNum++,
    action: "Verify the impact of the vulnerability",
    expectedResult: `Confirm that ${getImpactDescription(input.vulnClass)} is achievable`
  });
  if (input.reproductionEvidence) {
    for (const evidence of input.reproductionEvidence) {
      steps.push({
        stepNumber: stepNum++,
        action: `[Evidence] ${evidence.description}`,
        expectedResult: "See attached evidence",
        evidence: evidence.content
      });
    }
  }
  return steps;
}
function getPayloadStep(vulnClass, endpoint) {
  const payloads = {
    xss_reflected: { action: "Inject XSS payload into the vulnerable parameter (e.g., ?param=<script>alert(document.domain)</script>)", expectedResult: "The payload is reflected in the response without sanitization" },
    xss_stored: { action: "Submit the XSS payload through the input form/field", expectedResult: "The payload is stored and rendered when other users view the content" },
    sqli_classic: { action: "Inject SQL payload into the vulnerable parameter (e.g., ' OR 1=1--)", expectedResult: "The application returns data indicating SQL injection success" },
    ssrf: { action: "Replace the URL parameter with an internal address (e.g., http://169.254.169.254/latest/meta-data/)", expectedResult: "The server makes a request to the internal address and returns the response" },
    idor: { action: "Modify the object ID in the request to reference another user's resource", expectedResult: "The application returns data belonging to another user without authorization check" },
    open_redirect: { action: "Modify the redirect parameter to point to an external domain (e.g., ?redirect=https://attacker.com)", expectedResult: "The application redirects to the attacker-controlled domain" },
    csrf: { action: "Create an HTML page with a form that auto-submits to the vulnerable endpoint", expectedResult: "The state-changing action is performed without the user's explicit consent" },
    path_traversal: { action: "Inject path traversal sequences into the file parameter (e.g., ../../etc/passwd)", expectedResult: "The application returns the contents of the traversed file" },
    auth_bypass: { action: "Access the protected endpoint without valid authentication credentials", expectedResult: "The application grants access without proper authentication" },
    cors_misconfiguration: { action: "Send a request with a crafted Origin header (e.g., Origin: https://attacker.com)", expectedResult: "The response includes Access-Control-Allow-Origin reflecting the attacker origin with credentials allowed" }
  };
  return payloads[vulnClass] || null;
}
function getImpactDescription(vulnClass) {
  const impacts = {
    xss_reflected: "arbitrary JavaScript execution in the context of the victim's browser session",
    xss_stored: "persistent JavaScript execution affecting all users who view the affected content",
    sqli_classic: "unauthorized access to the database, potentially including sensitive user data",
    ssrf: "access to internal services and potential data exfiltration from the server's network",
    idor: "unauthorized access to other users' data and potential data manipulation",
    auth_bypass: "unauthorized access to protected functionality without valid credentials",
    rce: "arbitrary command execution on the server, leading to full system compromise",
    open_redirect: "phishing attacks leveraging the trusted domain to redirect users to malicious sites",
    csrf: "unauthorized state-changing actions performed on behalf of authenticated users",
    info_disclosure: "exposure of sensitive internal information that aids further attacks",
    path_traversal: "reading arbitrary files from the server file system",
    cors_misconfiguration: "cross-origin data theft from authenticated user sessions",
    jwt_weakness: "forging authentication tokens to impersonate any user",
    subdomain_takeover: "serving malicious content from a trusted subdomain",
    privilege_escalation: "elevating from a low-privilege account to administrative access"
  };
  return impacts[vulnClass] || "security impact as described";
}
function generateImpactStatement(input) {
  const impact = getImpactDescription(input.vulnClass);
  const severityContext = input.severity === "critical" || input.severity === "high" ? "This vulnerability poses a significant risk to the application and its users." : "This vulnerability could be leveraged by an attacker to compromise user security.";
  return `An attacker can exploit this ${input.vulnClass.replace(/_/g, " ")} vulnerability at ${input.affectedEndpoint} to achieve ${impact}. ${severityContext}${input.impactDescription ? ` Specifically: ${input.impactDescription}` : ""}`;
}
function generateSeverityJustification(input) {
  const cvss = VULN_CVSS_DEFAULTS[input.vulnClass];
  const cwe = VULN_CWE_MAP[input.vulnClass];
  let justification = `This finding is rated ${input.severity.toUpperCase()} severity based on the ${input.vulnClass.replace(/_/g, " ")} vulnerability class.`;
  if (cvss) {
    justification += ` CVSS 3.1 base score: ${cvss.score} (${cvss.severity}). Attack vector: ${cvss.breakdown.attackVector}, Attack complexity: ${cvss.breakdown.attackComplexity}, Privileges required: ${cvss.breakdown.privilegesRequired}, User interaction: ${cvss.breakdown.userInteraction}.`;
  }
  if (cwe) {
    justification += ` Classified as ${cwe.id}: ${cwe.name}.`;
  }
  return justification;
}
function optimizeSubmission(input) {
  const platform = input.platform || "other";
  const guidelines = PLATFORM_GUIDELINES[platform] || PLATFORM_GUIDELINES.other;
  const formattedTitle = guidelines.titleFormat(input.title, input.severity);
  const truncatedTitle = formattedTitle.length > guidelines.maxTitleLength ? formattedTitle.substring(0, guidelines.maxTitleLength - 3) + "..." : formattedTitle;
  const cweMapping = VULN_CWE_MAP[input.vulnClass];
  const cweId = input.cweId || cweMapping?.id || "CWE-0";
  const cvssEstimate = VULN_CVSS_DEFAULTS[input.vulnClass];
  const reproductionSteps = generateReproductionSteps(input);
  const impactStatement = generateImpactStatement(input);
  const severityJustification = generateSeverityJustification(input);
  const remediation = REMEDIATION_TEMPLATES[input.vulnClass] || "Implement appropriate security controls to mitigate this vulnerability. Consult OWASP guidelines for the specific vulnerability class.";
  const technicalDetails = [
    `Vulnerability Type: ${input.vulnClass.replace(/_/g, " ").toUpperCase()}`,
    `Affected Endpoint: ${input.affectedEndpoint}`,
    input.technology ? `Technology: ${input.technology}` : null,
    cweMapping ? `CWE: ${cweMapping.id} - ${cweMapping.name}` : null,
    cvssEstimate ? `CVSS Vector: ${cvssEstimate.vector}` : null,
    "",
    input.description
  ].filter(Boolean).join("\n");
  const references = [];
  if (cweMapping) references.push(`https://cwe.mitre.org/data/definitions/${cweMapping.id.replace("CWE-", "")}.html`);
  references.push(`https://owasp.org/www-community/attacks/${input.vulnClass.replace(/_/g, "-")}`);
  const summary = `A ${input.severity} severity ${input.vulnClass.replace(/_/g, " ")} vulnerability was identified at ${input.affectedEndpoint}${input.technology ? ` (${input.technology})` : ""}. ${input.description}`;
  const submission = {
    title: truncatedTitle,
    severity: input.severity,
    severityJustification,
    summary,
    impactStatement,
    reproductionSteps,
    technicalDetails,
    remediation,
    references,
    cweId,
    cvssEstimate,
    qualityScore: 0,
    qualityIssues: [],
    platformSpecificNotes: guidelines.notes
  };
  const quality = assessSubmissionQuality(submission, input);
  submission.qualityScore = quality.score;
  submission.qualityIssues = quality.issues;
  return submission;
}
function batchOptimizeSubmissions(inputs) {
  return inputs.map((input) => optimizeSubmission(input));
}
function getSubmissionQualityStats(submissions) {
  const totalQuality = submissions.reduce((sum, s) => sum + s.qualityScore, 0);
  const issueMap = /* @__PURE__ */ new Map();
  for (const s of submissions) {
    for (const issue of s.qualityIssues) {
      issueMap.set(issue, (issueMap.get(issue) || 0) + 1);
    }
  }
  const commonIssues = Array.from(issueMap.entries()).map(([issue, count]) => ({ issue, count })).sort((a, b) => b.count - a.count);
  return {
    averageQuality: submissions.length > 0 ? Math.round(totalQuality / submissions.length) : 0,
    highQuality: submissions.filter((s) => s.qualityScore >= 80).length,
    needsImprovement: submissions.filter((s) => s.qualityScore < 60).length,
    commonIssues
  };
}
export {
  batchOptimizeSubmissions,
  getSubmissionQualityStats,
  optimizeSubmission
};
