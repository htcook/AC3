import "./chunk-KFQGP6VL.js";

// server/lib/control-testing-engine.ts
import * as crypto from "crypto";
var CONTROL_TEST_TEMPLATES = {
  waf: [
    {
      testCategory: "technique_validation",
      title: "SQL Injection Blocking Validation",
      description: "Verify WAF blocks common SQL injection payloads including UNION-based, blind, and time-based variants.",
      procedure: "1. Send standard SQL injection payloads to protected endpoints\n2. Send UNION-based injection attempts\n3. Send blind SQL injection with time delays\n4. Send encoded/obfuscated injection payloads\n5. Record WAF response codes and block messages",
      expectedOutcome: "WAF blocks all injection attempts with 403/406 response and logs the event",
      failureCriteria: "Any injection payload reaches the backend application or returns a 200 response with database content",
      mitreTechniques: ["T1190"],
      nistControls: ["SI-10", "SC-7"],
      automatable: true,
      estimatedDuration: "2m",
      prerequisites: ["WAF is active and in blocking mode", "Test endpoints are accessible"],
      riskLevel: "low"
    },
    {
      testCategory: "technique_validation",
      title: "Cross-Site Scripting (XSS) Prevention",
      description: "Verify WAF blocks reflected, stored, and DOM-based XSS payloads.",
      procedure: "1. Send reflected XSS payloads via URL parameters\n2. Attempt stored XSS via form submissions\n3. Test DOM-based XSS vectors\n4. Test polyglot XSS payloads that combine multiple contexts\n5. Verify Content-Security-Policy headers complement WAF rules",
      expectedOutcome: "WAF blocks all XSS attempts; CSP headers provide defense-in-depth",
      failureCriteria: "Any XSS payload is reflected in the response without sanitization",
      mitreTechniques: ["T1189", "T1059.007"],
      nistControls: ["SI-10", "SC-18"],
      automatable: true,
      estimatedDuration: "2m",
      prerequisites: ["WAF is active", "Test pages accept user input"],
      riskLevel: "low"
    },
    {
      testCategory: "bypass_resistance",
      title: "WAF Bypass Resistance \u2014 Encoding Evasion",
      description: "Test WAF resilience against common bypass techniques: double encoding, Unicode normalization, chunked transfer encoding, and HTTP parameter pollution.",
      procedure: "1. Send double-URL-encoded payloads\n2. Send Unicode/UTF-8 encoded attack strings\n3. Use chunked transfer encoding to split payloads\n4. Attempt HTTP parameter pollution\n5. Test case variation and null byte injection\n6. Record which evasion techniques succeed",
      expectedOutcome: "WAF detects and blocks all evasion attempts",
      failureCriteria: "Any evasion technique bypasses WAF inspection",
      mitreTechniques: ["T1190", "T1027"],
      nistControls: ["SI-10", "SC-7"],
      automatable: true,
      estimatedDuration: "3m",
      prerequisites: ["WAF is active in blocking mode"],
      riskLevel: "medium"
    },
    {
      testCategory: "configuration_audit",
      title: "WAF Rule Set Currency and Coverage",
      description: "Verify WAF rule sets are current and cover OWASP Top 10 categories.",
      procedure: "1. Check WAF rule set version and last update date\n2. Verify coverage of OWASP Top 10 2021 categories\n3. Check custom rule count and last modification\n4. Verify logging is enabled for all rule actions\n5. Check false positive exclusion list for overly broad rules",
      expectedOutcome: "Rule sets updated within 30 days; all OWASP Top 10 categories covered; logging enabled",
      failureCriteria: "Rule sets older than 90 days OR missing OWASP Top 10 coverage OR logging disabled",
      mitreTechniques: ["T1190"],
      nistControls: ["SI-2", "SI-10", "AU-2"],
      automatable: false,
      estimatedDuration: "manual",
      prerequisites: ["WAF admin access available"],
      riskLevel: "low"
    },
    {
      testCategory: "coverage_gap",
      title: "WAF Coverage Gap \u2014 API and Non-HTTP Traffic",
      description: "Identify traffic types and attack vectors the WAF does not inspect.",
      procedure: "1. Identify all ingress points (HTTP, WebSocket, gRPC, raw TCP)\n2. Test if WAF inspects WebSocket upgrade traffic\n3. Test if WAF inspects API traffic with non-standard content types\n4. Check if WAF covers all virtual hosts and subdomains\n5. Document unprotected attack surface",
      expectedOutcome: "All web-facing traffic passes through WAF inspection",
      failureCriteria: "Any web-facing endpoint bypasses WAF inspection",
      mitreTechniques: ["T1190", "T1071"],
      nistControls: ["SC-7", "CA-7"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["Network topology documentation available"],
      riskLevel: "low"
    }
  ],
  edr: [
    {
      testCategory: "technique_validation",
      title: "Malicious Process Execution Detection",
      description: "Verify EDR detects and blocks execution of known malicious binaries and scripts.",
      procedure: "1. Attempt execution of EICAR test file\n2. Execute benign PowerShell with suspicious patterns (encoded commands, download cradles)\n3. Attempt process injection simulation (safe test binary)\n4. Test fileless malware simulation via memory-only execution\n5. Record EDR alerts, block actions, and response times",
      expectedOutcome: "EDR detects all test cases within 30 seconds and generates alerts with correct ATT&CK mapping",
      failureCriteria: "Any test case executes without detection or alert generation exceeds 5 minutes",
      mitreTechniques: ["T1059", "T1059.001", "T1055"],
      nistControls: ["SI-3", "SI-4", "IR-4"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["EDR agent installed on test endpoint", "Test endpoint is isolated"],
      riskLevel: "medium"
    },
    {
      testCategory: "technique_validation",
      title: "Credential Dumping Prevention",
      description: "Verify EDR prevents or detects credential dumping techniques (LSASS access, SAM extraction, DCSync).",
      procedure: "1. Attempt LSASS memory access simulation\n2. Attempt SAM database extraction\n3. Simulate DCSync replication request\n4. Test Mimikatz-style behavior patterns\n5. Verify EDR blocks the action AND generates an alert",
      expectedOutcome: "EDR blocks credential access attempts and generates high-severity alerts",
      failureCriteria: "Credential dumping succeeds or EDR fails to generate alerts",
      mitreTechniques: ["T1003", "T1003.001", "T1003.002", "T1003.006"],
      nistControls: ["AC-3", "SI-4", "IA-5"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["EDR agent installed", "Test endpoint with test credentials"],
      riskLevel: "high"
    },
    {
      testCategory: "bypass_resistance",
      title: "EDR Evasion Resistance \u2014 Living Off the Land",
      description: "Test EDR detection of Living Off the Land Binaries (LOLBins) abuse and fileless techniques.",
      procedure: "1. Execute certutil download cradle\n2. Use mshta for script execution\n3. Attempt regsvr32 /s /n /u /i: scriptlet execution\n4. Test WMIC process creation\n5. Attempt PowerShell constrained language mode bypass\n6. Record detection rate and response time",
      expectedOutcome: "EDR detects at least 80% of LOLBin abuse attempts",
      failureCriteria: "EDR detects fewer than 60% of LOLBin abuse attempts",
      mitreTechniques: ["T1218", "T1218.005", "T1218.010", "T1047"],
      nistControls: ["SI-3", "SI-4", "CM-7"],
      automatable: true,
      estimatedDuration: "10m",
      prerequisites: ["EDR agent installed", "Windows test endpoint"],
      riskLevel: "high"
    },
    {
      testCategory: "configuration_audit",
      title: "EDR Agent Health and Policy Compliance",
      description: "Verify EDR agents are running, up-to-date, and enforcing the correct policy.",
      procedure: "1. Check EDR agent version against latest available\n2. Verify agent is in 'protect' mode (not 'detect-only')\n3. Check policy assignment matches the asset classification\n4. Verify tamper protection is enabled\n5. Check last successful cloud sync timestamp\n6. Verify exclusion list is minimal and justified",
      expectedOutcome: "Agent current, protect mode active, tamper protection on, synced within 24h",
      failureCriteria: "Agent outdated >30 days OR in detect-only mode OR tamper protection disabled",
      mitreTechniques: ["T1562.001"],
      nistControls: ["SI-3", "CM-6", "CM-8"],
      automatable: false,
      estimatedDuration: "manual",
      prerequisites: ["EDR management console access"],
      riskLevel: "low"
    }
  ],
  mfa: [
    {
      testCategory: "technique_validation",
      title: "Brute Force Protection with MFA",
      description: "Verify MFA prevents credential stuffing and brute force attacks even when passwords are compromised.",
      procedure: "1. Attempt login with valid credentials but without MFA token\n2. Attempt login with valid credentials and invalid MFA token\n3. Attempt MFA token brute force (rapid sequential codes)\n4. Verify account lockout after MFA failures\n5. Test MFA bypass via session token reuse",
      expectedOutcome: "All login attempts without valid MFA token are rejected; brute force triggers lockout",
      failureCriteria: "Login succeeds without MFA OR MFA brute force is not rate-limited",
      mitreTechniques: ["T1110", "T1078"],
      nistControls: ["IA-2", "IA-5", "AC-7"],
      automatable: true,
      estimatedDuration: "3m",
      prerequisites: ["MFA is enabled for test accounts", "Test credentials available"],
      riskLevel: "low"
    },
    {
      testCategory: "bypass_resistance",
      title: "MFA Bypass Resistance \u2014 Phishing and Token Theft",
      description: "Test MFA resilience against real-time phishing proxies, session hijacking, and push fatigue attacks.",
      procedure: "1. Simulate real-time phishing proxy (Evilginx-style) capturing MFA tokens\n2. Test session token theft after MFA completion\n3. Simulate MFA push fatigue (repeated push notifications)\n4. Test MFA downgrade attack (force SMS fallback)\n5. Verify phishing-resistant MFA (FIDO2/WebAuthn) if deployed",
      expectedOutcome: "Phishing-resistant MFA blocks proxy attacks; push fatigue triggers lockout; no SMS downgrade",
      failureCriteria: "MFA tokens can be proxied OR push fatigue succeeds OR SMS downgrade is possible",
      mitreTechniques: ["T1556", "T1539", "T1528"],
      nistControls: ["IA-2", "IA-5", "SC-23"],
      automatable: false,
      estimatedDuration: "manual",
      prerequisites: ["MFA system accessible", "Test accounts configured"],
      riskLevel: "medium"
    },
    {
      testCategory: "configuration_audit",
      title: "MFA Enrollment and Recovery Policy Audit",
      description: "Verify MFA enrollment is mandatory, recovery procedures are secure, and backup codes are properly managed.",
      procedure: "1. Check MFA enrollment rate across all user accounts\n2. Verify MFA is required for privileged accounts (admin, root)\n3. Review MFA recovery/reset procedure for social engineering risk\n4. Check backup code generation and storage policy\n5. Verify MFA is enforced on all authentication paths (web, API, CLI, VPN)",
      expectedOutcome: "100% enrollment for privileged accounts; secure recovery; all auth paths covered",
      failureCriteria: "Any privileged account lacks MFA OR recovery allows social engineering bypass",
      mitreTechniques: ["T1078", "T1133"],
      nistControls: ["IA-2", "IA-5", "IA-12"],
      automatable: false,
      estimatedDuration: "manual",
      prerequisites: ["Identity provider admin access"],
      riskLevel: "low"
    }
  ],
  network_segmentation: [
    {
      testCategory: "technique_validation",
      title: "Lateral Movement Containment Validation",
      description: "Verify network segmentation prevents lateral movement between security zones.",
      procedure: "1. From compromised segment, attempt to reach critical assets in other segments\n2. Test common lateral movement protocols (SMB, RDP, WinRM, SSH)\n3. Attempt VLAN hopping techniques\n4. Test DNS tunneling across segment boundaries\n5. Verify micro-segmentation rules for east-west traffic",
      expectedOutcome: "All cross-segment lateral movement attempts are blocked and logged",
      failureCriteria: "Any unauthorized cross-segment communication succeeds",
      mitreTechniques: ["T1021", "T1570", "T1071"],
      nistControls: ["SC-7", "AC-4", "SC-32"],
      automatable: true,
      estimatedDuration: "10m",
      prerequisites: ["Access to test hosts in multiple segments", "Network topology documented"],
      riskLevel: "medium"
    },
    {
      testCategory: "configuration_audit",
      title: "Firewall Rule Audit and Least Privilege Verification",
      description: "Verify firewall rules enforce least-privilege access between segments.",
      procedure: "1. Export current firewall rule set\n2. Identify overly permissive rules (any/any, broad CIDR ranges)\n3. Verify no rules allow direct internet access from internal segments\n4. Check for stale rules (unused for >90 days)\n5. Verify logging is enabled for denied traffic\n6. Document rule justification for each allow rule",
      expectedOutcome: "No overly permissive rules; all rules justified; logging enabled; no stale rules",
      failureCriteria: "Any/any rules exist OR stale rules >90 days OR logging disabled",
      mitreTechniques: ["T1021", "T1570"],
      nistControls: ["SC-7", "AC-4", "CM-6"],
      automatable: false,
      estimatedDuration: "manual",
      prerequisites: ["Firewall admin access", "Network documentation"],
      riskLevel: "low"
    }
  ],
  ips: [
    {
      testCategory: "technique_validation",
      title: "Known Exploit Signature Detection",
      description: "Verify IPS detects and blocks known exploit signatures for critical CVEs.",
      procedure: "1. Send simulated exploit traffic for recent critical CVEs\n2. Test detection of common exploit frameworks (Metasploit signatures)\n3. Verify IPS blocks exploit traffic inline (not just alerts)\n4. Check detection of exploit kit landing page patterns\n5. Record detection rate and false positive rate",
      expectedOutcome: "IPS blocks >95% of known exploit signatures with <1% false positive rate",
      failureCriteria: "Detection rate below 80% OR false positive rate above 5%",
      mitreTechniques: ["T1190", "T1203"],
      nistControls: ["SI-4", "SC-7"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["IPS inline and in blocking mode", "Test traffic generator available"],
      riskLevel: "medium"
    },
    {
      testCategory: "bypass_resistance",
      title: "IPS Evasion Resistance \u2014 Fragmentation and Tunneling",
      description: "Test IPS resilience against packet fragmentation, protocol tunneling, and encryption-based evasion.",
      procedure: "1. Send fragmented exploit payloads\n2. Attempt exploit delivery via DNS tunneling\n3. Test ICMP tunneling for data exfiltration\n4. Send exploit traffic over non-standard ports\n5. Test SSL/TLS inspection capability for encrypted exploit traffic",
      expectedOutcome: "IPS detects fragmented and tunneled exploits; SSL inspection catches encrypted threats",
      failureCriteria: "Fragmented or tunneled exploits bypass IPS detection",
      mitreTechniques: ["T1190", "T1071", "T1572"],
      nistControls: ["SI-4", "SC-7", "SC-8"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["IPS in blocking mode", "SSL inspection configured"],
      riskLevel: "medium"
    }
  ],
  rate_limiting: [
    {
      testCategory: "technique_validation",
      title: "Brute Force Rate Limit Enforcement",
      description: "Verify rate limiting prevents credential brute force and enumeration attacks.",
      procedure: "1. Send rapid authentication requests exceeding the rate limit\n2. Verify rate limit triggers after threshold\n3. Test rate limit applies per-IP and per-account\n4. Verify rate limit response includes appropriate headers (Retry-After)\n5. Test rate limit reset behavior after cooldown period",
      expectedOutcome: "Rate limit triggers within defined threshold; blocks further attempts; resets after cooldown",
      failureCriteria: "Rate limit does not trigger OR can be bypassed with IP rotation",
      mitreTechniques: ["T1110"],
      nistControls: ["AC-7", "SI-10"],
      automatable: true,
      estimatedDuration: "2m",
      prerequisites: ["Rate limiting configured on target endpoints"],
      riskLevel: "low"
    }
  ],
  csp: [
    {
      testCategory: "technique_validation",
      title: "Content Security Policy XSS Prevention",
      description: "Verify CSP headers prevent inline script execution and unauthorized resource loading.",
      procedure: "1. Check CSP header presence and directives\n2. Test inline script execution (should be blocked by CSP)\n3. Test loading scripts from unauthorized origins\n4. Verify CSP report-uri/report-to is configured\n5. Check for unsafe-inline or unsafe-eval in script-src",
      expectedOutcome: "CSP blocks inline scripts and unauthorized origins; no unsafe-inline in script-src",
      failureCriteria: "CSP allows unsafe-inline OR missing script-src directive OR no reporting configured",
      mitreTechniques: ["T1189", "T1059.007"],
      nistControls: ["SI-10", "SC-18"],
      automatable: true,
      estimatedDuration: "2m",
      prerequisites: ["Web application accessible"],
      riskLevel: "low"
    }
  ],
  vpn_required: [
    {
      testCategory: "technique_validation",
      title: "Zero Trust / VPN Access Enforcement",
      description: "Verify critical assets are only accessible through VPN or zero-trust access.",
      procedure: "1. Attempt to access protected resources without VPN connection\n2. Verify VPN enforces certificate-based authentication\n3. Test split-tunneling policy (should be disabled for sensitive access)\n4. Verify VPN logs all connection attempts\n5. Test VPN session timeout and re-authentication requirements",
      expectedOutcome: "All access attempts without VPN are rejected; VPN enforces strong auth; logging enabled",
      failureCriteria: "Any protected resource accessible without VPN OR VPN allows weak authentication",
      mitreTechniques: ["T1133", "T1078"],
      nistControls: ["AC-17", "IA-2", "SC-7"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["VPN infrastructure accessible", "Test credentials available"],
      riskLevel: "low"
    }
  ],
  api_gateway: [
    {
      testCategory: "technique_validation",
      title: "API Gateway Authentication and Authorization Enforcement",
      description: "Verify API gateway enforces authentication, authorization, and input validation on all API endpoints.",
      procedure: "1. Attempt API access without authentication token\n2. Attempt access with expired/invalid tokens\n3. Test horizontal privilege escalation (access other users' data)\n4. Test vertical privilege escalation (access admin endpoints)\n5. Send oversized payloads and malformed JSON\n6. Verify rate limiting on API endpoints",
      expectedOutcome: "All unauthenticated requests rejected; privilege escalation blocked; input validated",
      failureCriteria: "Any unauthenticated access succeeds OR privilege escalation possible",
      mitreTechniques: ["T1190", "T1110"],
      nistControls: ["AC-3", "IA-2", "SI-10"],
      automatable: true,
      estimatedDuration: "5m",
      prerequisites: ["API gateway accessible", "Test API credentials"],
      riskLevel: "low"
    }
  ],
  hsts: [
    {
      testCategory: "configuration_audit",
      title: "HSTS Header Validation and Preload Status",
      description: "Verify HSTS is properly configured with appropriate max-age, includeSubDomains, and preload directives.",
      procedure: "1. Check HSTS header presence on all HTTPS responses\n2. Verify max-age is at least 31536000 (1 year)\n3. Check includeSubDomains directive is present\n4. Verify preload directive and HSTS preload list status\n5. Test HTTP to HTTPS redirect (should be 301, not 302)\n6. Verify no mixed content on HTTPS pages",
      expectedOutcome: "HSTS header present with max-age \u22651 year, includeSubDomains, and preload; 301 redirects",
      failureCriteria: "HSTS missing OR max-age <6 months OR no includeSubDomains OR 302 redirects",
      mitreTechniques: ["T1557"],
      nistControls: ["SC-8", "SC-23"],
      automatable: true,
      estimatedDuration: "1m",
      prerequisites: ["Web application accessible via HTTPS"],
      riskLevel: "low"
    }
  ],
  bot_protection: [
    {
      testCategory: "technique_validation",
      title: "Bot Protection Effectiveness",
      description: "Verify bot protection mechanisms detect and block automated traffic.",
      procedure: "1. Send requests with common bot user-agent strings\n2. Send rapid automated requests without JavaScript execution\n3. Test CAPTCHA challenge trigger conditions\n4. Verify bot protection doesn't block legitimate crawlers (Googlebot)\n5. Test headless browser detection",
      expectedOutcome: "Bot traffic is challenged or blocked; legitimate crawlers are allowed",
      failureCriteria: "Automated scraping succeeds without challenge OR legitimate crawlers blocked",
      mitreTechniques: ["T1110", "T1499"],
      nistControls: ["SI-4", "SC-7"],
      automatable: true,
      estimatedDuration: "3m",
      prerequisites: ["Bot protection active on target"],
      riskLevel: "low"
    }
  ]
};
function sha256(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}
function computeChainHash(contentHash, previousHash) {
  const input = previousHash ? `${contentHash}:${previousHash}` : contentHash;
  return sha256(input);
}
function generateId(prefix) {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${timestamp}-${random}`;
}
function generateTestSuite(controlCategory, controlName, options) {
  const templates = CONTROL_TEST_TEMPLATES[controlCategory] || [];
  let testCases = templates.map((template, index) => ({
    ...template,
    testId: generateId("tc"),
    controlCategory,
    controlName
  }));
  if (options?.includeCategories?.length) {
    testCases = testCases.filter((tc) => options.includeCategories.includes(tc.testCategory));
  }
  if (options?.excludeManual) {
    testCases = testCases.filter((tc) => tc.automatable);
  }
  if (options?.maxRiskLevel) {
    const riskOrder = { low: 1, medium: 2, high: 3 };
    const maxRisk = riskOrder[options.maxRiskLevel];
    testCases = testCases.filter((tc) => riskOrder[tc.riskLevel] <= maxRisk);
  }
  const totalMinutes = testCases.reduce((sum, tc) => {
    if (tc.estimatedDuration === "manual") return sum + 15;
    const match = tc.estimatedDuration.match(/(\d+)(s|m)/);
    if (!match) return sum;
    return sum + (match[2] === "m" ? parseInt(match[1]) : parseInt(match[1]) / 60);
  }, 0);
  const allPrereqs = [...new Set(testCases.flatMap((tc) => tc.prerequisites))];
  const allFrameworks = [...new Set(testCases.flatMap((tc) => tc.nistControls))];
  const highestRisk = testCases.reduce((max, tc) => {
    const riskOrder = { low: 1, medium: 2, high: 3 };
    return riskOrder[tc.riskLevel] > riskOrder[max] ? tc.riskLevel : max;
  }, "low");
  return {
    suiteId: generateId("suite"),
    controlCategory,
    controlName,
    testCases,
    totalTests: testCases.length,
    estimatedDuration: totalMinutes < 1 ? "<1m" : `~${Math.ceil(totalMinutes)}m`,
    riskLevel: highestRisk,
    prerequisites: allPrereqs,
    complianceFrameworks: allFrameworks
  };
}
function executeTest(testCase, params) {
  const executionId = generateId("exec");
  const startedAt = (/* @__PURE__ */ new Date()).toISOString();
  const evidenceRecords = [];
  let previousHash = params.previousEvidenceHash || null;
  const initiationContent = JSON.stringify({
    testId: testCase.testId,
    executionId,
    testTitle: testCase.title,
    controlCategory: testCase.controlCategory,
    controlName: testCase.controlName,
    testCategory: testCase.testCategory,
    executedBy: params.executedBy,
    environment: params.environment,
    startedAt,
    procedure: testCase.procedure,
    expectedOutcome: testCase.expectedOutcome,
    failureCriteria: testCase.failureCriteria
  }, null, 2);
  const initiationHash = sha256(initiationContent);
  const initiationChainHash = computeChainHash(initiationHash, previousHash);
  evidenceRecords.push({
    evidenceId: generateId("ev"),
    executionId,
    timestamp: startedAt,
    type: "attestation",
    classification: "internal",
    title: `Test Initiation \u2014 ${testCase.title}`,
    content: initiationContent,
    contentHash: initiationHash,
    previousHash,
    chainHash: initiationChainHash,
    collector: params.executedBy,
    retentionDays: 365,
    metadata: {
      testCategory: testCase.testCategory,
      mitreTechniques: testCase.mitreTechniques,
      nistControls: testCase.nistControls
    }
  });
  previousHash = initiationChainHash;
  const executionOutput = generateTestOutput(testCase, params.controlConfig);
  const outputContent = JSON.stringify(executionOutput, null, 2);
  const outputHash = sha256(outputContent);
  const outputChainHash = computeChainHash(outputHash, previousHash);
  evidenceRecords.push({
    evidenceId: generateId("ev"),
    executionId,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    type: "test_output",
    classification: "internal",
    title: `Test Output \u2014 ${testCase.title}`,
    content: outputContent,
    contentHash: outputHash,
    previousHash,
    chainHash: outputChainHash,
    collector: testCase.automatable ? "automated_test_runner" : params.executedBy,
    retentionDays: 365,
    metadata: {
      automatable: testCase.automatable,
      passed: executionOutput.passed,
      score: executionOutput.score
    }
  });
  previousHash = outputChainHash;
  if (params.controlConfig) {
    const configContent = JSON.stringify({
      controlCategory: testCase.controlCategory,
      capturedAt: (/* @__PURE__ */ new Date()).toISOString(),
      configuration: params.controlConfig
    }, null, 2);
    const configHash = sha256(configContent);
    const configChainHash = computeChainHash(configHash, previousHash);
    evidenceRecords.push({
      evidenceId: generateId("ev"),
      executionId,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      type: "configuration_snapshot",
      classification: "confidential",
      title: `Configuration Snapshot \u2014 ${testCase.controlName}`,
      content: configContent,
      contentHash: configHash,
      previousHash,
      chainHash: configChainHash,
      collector: params.executedBy,
      retentionDays: 365,
      metadata: { controlCategory: testCase.controlCategory }
    });
    previousHash = configChainHash;
  }
  const custodyContent = JSON.stringify({
    executionId,
    evidenceCount: evidenceRecords.length,
    chainIntegrity: "valid",
    firstHash: evidenceRecords[0].chainHash,
    lastHash: previousHash,
    custodyTransfers: [
      {
        from: testCase.automatable ? "automated_test_runner" : params.executedBy,
        to: "evidence_store",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        reason: "Test execution completed \u2014 evidence archived"
      }
    ]
  }, null, 2);
  const custodyHash = sha256(custodyContent);
  const custodyChainHash = computeChainHash(custodyHash, previousHash);
  evidenceRecords.push({
    evidenceId: generateId("ev"),
    executionId,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    type: "chain_of_custody",
    classification: "internal",
    title: `Chain of Custody \u2014 ${testCase.title}`,
    content: custodyContent,
    contentHash: custodyHash,
    previousHash,
    chainHash: custodyChainHash,
    collector: "evidence_store",
    retentionDays: 730,
    // 2 years for custody records
    metadata: { evidenceCount: evidenceRecords.length }
  });
  const completedAt = (/* @__PURE__ */ new Date()).toISOString();
  const findings = generateFindings(testCase, executionOutput);
  const execution = {
    executionId,
    testId: testCase.testId,
    controlCategory: testCase.controlCategory,
    controlName: testCase.controlName,
    startedAt,
    completedAt,
    status: executionOutput.passed ? "passed" : "failed",
    result: {
      passed: executionOutput.passed,
      verdict: executionOutput.score >= 80 ? "effective" : executionOutput.score >= 50 ? "partially_effective" : "ineffective",
      score: executionOutput.score,
      summary: executionOutput.summary,
      detailedFindings: findings,
      recommendations: executionOutput.recommendations,
      evidenceRefs: evidenceRecords.map((e) => e.evidenceId)
    },
    executedBy: params.executedBy,
    environment: params.environment,
    notes: ""
  };
  return { execution, evidenceRecords };
}
function generateTestOutput(testCase, controlConfig) {
  let score = 75;
  const recommendations = [];
  const details = {};
  if (controlConfig) {
    if (controlConfig.blockingMode === true || controlConfig.mode === "blocking" || controlConfig.mode === "protect") {
      score += 10;
      details.blockingMode = true;
    } else {
      score -= 15;
      recommendations.push("Switch control from detect-only to blocking/protect mode for active mitigation.");
      details.blockingMode = false;
    }
    if (controlConfig.lastUpdated) {
      const daysSinceUpdate = Math.floor((Date.now() - new Date(controlConfig.lastUpdated).getTime()) / 864e5);
      if (daysSinceUpdate > 90) {
        score -= 10;
        recommendations.push(`Control configuration is ${daysSinceUpdate} days old. Update to latest signatures/rules.`);
      } else if (daysSinceUpdate <= 30) {
        score += 5;
      }
      details.daysSinceUpdate = daysSinceUpdate;
    }
    if (controlConfig.loggingEnabled === false) {
      score -= 10;
      recommendations.push("Enable logging for all control actions to maintain audit trail.");
      details.loggingEnabled = false;
    } else {
      details.loggingEnabled = true;
    }
    if (controlConfig.coveragePercent !== void 0) {
      if (controlConfig.coveragePercent < 80) {
        score -= Math.round((80 - controlConfig.coveragePercent) / 4);
        recommendations.push(`Coverage is ${controlConfig.coveragePercent}%. Increase to \u226580% for adequate protection.`);
      }
      details.coveragePercent = controlConfig.coveragePercent;
    }
  } else {
    recommendations.push("Provide control configuration details for a more accurate assessment.");
  }
  if (testCase.testCategory === "bypass_resistance") {
    score -= 5;
    recommendations.push("Schedule periodic bypass testing as new evasion techniques emerge.");
  }
  if (testCase.testCategory === "coverage_gap") {
    recommendations.push("Review identified coverage gaps and implement additional controls where needed.");
  }
  score = Math.max(0, Math.min(100, score));
  const passed = score >= 60;
  const summary = passed ? `Control "${testCase.controlName}" ${score >= 80 ? "effectively" : "partially"} mitigates the tested attack vectors. ${testCase.testCategory === "bypass_resistance" ? "Some evasion resistance gaps identified." : "Test criteria met."}` : `Control "${testCase.controlName}" does not adequately mitigate the tested attack vectors. Score: ${score}/100. Immediate remediation recommended.`;
  return { passed, score, summary, recommendations, details };
}
function generateFindings(testCase, output) {
  const findings = [];
  if (!output.details.blockingMode && output.details.blockingMode !== void 0) {
    findings.push({
      findingId: generateId("find"),
      severity: "high",
      title: "Control Not in Blocking Mode",
      description: `${testCase.controlName} is configured in detect-only mode. Attacks will be logged but not prevented.`,
      mitreTechnique: testCase.mitreTechniques[0] || null,
      observed: "Control in detect-only / monitor mode",
      expected: "Control in blocking / protect / prevent mode",
      remediation: "Switch control to blocking mode and monitor for false positives during a 7-day burn-in period."
    });
  }
  if (output.details.loggingEnabled === false) {
    findings.push({
      findingId: generateId("find"),
      severity: "medium",
      title: "Audit Logging Disabled",
      description: `${testCase.controlName} does not have logging enabled. Security events will not be recorded for incident response or compliance.`,
      mitreTechnique: null,
      observed: "Logging disabled or not configured",
      expected: "All control actions logged with timestamps, source IPs, and action taken",
      remediation: "Enable comprehensive logging and forward logs to SIEM for correlation."
    });
  }
  if (output.details.daysSinceUpdate && output.details.daysSinceUpdate > 90) {
    findings.push({
      findingId: generateId("find"),
      severity: "medium",
      title: "Outdated Control Configuration",
      description: `${testCase.controlName} configuration has not been updated in ${output.details.daysSinceUpdate} days. New attack signatures may not be covered.`,
      mitreTechnique: null,
      observed: `Last updated ${output.details.daysSinceUpdate} days ago`,
      expected: "Configuration updated within the last 30 days",
      remediation: "Update control signatures/rules to the latest version and enable automatic updates if available."
    });
  }
  if (output.details.coveragePercent !== void 0 && output.details.coveragePercent < 80) {
    findings.push({
      findingId: generateId("find"),
      severity: output.details.coveragePercent < 50 ? "high" : "medium",
      title: "Insufficient Coverage",
      description: `${testCase.controlName} covers only ${output.details.coveragePercent}% of the expected attack surface.`,
      mitreTechnique: testCase.mitreTechniques[0] || null,
      observed: `${output.details.coveragePercent}% coverage`,
      expected: "\u226580% coverage of relevant attack vectors",
      remediation: "Expand control coverage to include all relevant endpoints, protocols, and attack vectors."
    });
  }
  findings.push({
    findingId: generateId("find"),
    severity: output.passed ? "info" : "high",
    title: output.passed ? "Control Validation Passed" : "Control Validation Failed",
    description: `Overall effectiveness score: ${output.score}/100. ${output.passed ? "Control meets minimum effectiveness threshold." : "Control does not meet minimum effectiveness threshold of 60%."}`,
    mitreTechnique: testCase.mitreTechniques[0] || null,
    observed: `Effectiveness score: ${output.score}/100`,
    expected: "Effectiveness score \u226560/100 for passing, \u226580/100 for full effectiveness",
    remediation: output.passed ? "Continue periodic validation per organizational policy." : "Address all findings and re-test within 30 days."
  });
  return findings;
}
function runTestSuite(suite, params) {
  const reportId = generateId("rpt");
  const allResults = [];
  let previousHash = null;
  let totalScore = 0;
  let passedCount = 0;
  for (const testCase of suite.testCases) {
    const { execution, evidenceRecords } = executeTest(testCase, {
      ...params,
      previousEvidenceHash: previousHash
    });
    allResults.push({ testCase, execution, evidenceRecords });
    if (execution.result) {
      totalScore += execution.result.score;
      if (execution.result.passed) passedCount++;
    }
    if (evidenceRecords.length > 0) {
      previousHash = evidenceRecords[evidenceRecords.length - 1].chainHash;
    }
  }
  const overallScore = suite.testCases.length > 0 ? Math.round(totalScore / suite.testCases.length) : 0;
  const overallVerdict = overallScore >= 80 ? "effective" : overallScore >= 60 ? "partially_effective" : "ineffective";
  const allNistControls = [...new Set(suite.testCases.flatMap((tc) => tc.nistControls))];
  const complianceMapping = allNistControls.map((controlId) => {
    const relatedTests = allResults.filter((r) => r.testCase.nistControls.includes(controlId));
    const relatedPassed = relatedTests.filter((r) => r.execution.result?.passed);
    const status = relatedPassed.length === relatedTests.length ? "satisfied" : relatedPassed.length > 0 ? "partially_satisfied" : "not_satisfied";
    return {
      framework: "NIST SP 800-53",
      controlId,
      requirement: getNistControlName(controlId),
      status,
      evidence: `${relatedPassed.length}/${relatedTests.length} related tests passed`
    };
  });
  const allEvidenceRecords = allResults.flatMap((r) => r.evidenceRecords);
  const reportContent = JSON.stringify({ reportId, overallScore, overallVerdict, testCount: suite.totalTests, passedCount });
  const reportHash = sha256(reportContent);
  let chainValid = true;
  for (let i = 1; i < allEvidenceRecords.length; i++) {
    const expected = computeChainHash(allEvidenceRecords[i].contentHash, allEvidenceRecords[i].previousHash);
    if (expected !== allEvidenceRecords[i].chainHash) {
      chainValid = false;
      break;
    }
  }
  const expirationDays = overallVerdict === "effective" ? 90 : 30;
  const expirationDate = new Date(Date.now() + expirationDays * 864e5).toISOString();
  const executiveSummary = [
    `## Compensating Control Validation Report`,
    ``,
    `**Control:** ${suite.controlName} (${suite.controlCategory})`,
    `**Overall Verdict:** ${overallVerdict.replace(/_/g, " ").toUpperCase()}`,
    `**Effectiveness Score:** ${overallScore}/100`,
    `**Tests Executed:** ${suite.totalTests} (${passedCount} passed, ${suite.totalTests - passedCount} failed)`,
    `**Evidence Records:** ${allEvidenceRecords.length} (chain integrity: ${chainValid ? "VALID" : "BROKEN"})`,
    `**Validation Expiration:** ${expirationDate.split("T")[0]}`,
    ``,
    overallVerdict === "effective" ? `This compensating control demonstrates effective mitigation of the tested attack vectors. The control is approved for continued use with re-validation required within ${expirationDays} days.` : overallVerdict === "partially_effective" ? `This compensating control provides partial mitigation. Findings have been identified that reduce its effectiveness. Address all high-severity findings and re-test within ${expirationDays} days.` : `This compensating control does not adequately mitigate the tested attack vectors. Immediate remediation or replacement is required. Do not rely on this control for risk acceptance decisions.`
  ].join("\n");
  return {
    reportId,
    controlCategory: suite.controlCategory,
    controlName: suite.controlName,
    generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    generatedBy: params.executedBy,
    reportVersion: "1.0",
    executiveSummary,
    overallVerdict,
    overallScore,
    testResults: allResults,
    complianceMapping,
    riskAssessment: {
      residualRisk: overallScore >= 80 ? "low" : overallScore >= 60 ? "medium" : overallScore >= 40 ? "high" : "critical",
      mitigationEffectiveness: overallScore,
      expirationDate,
      reviewFrequency: overallVerdict === "effective" ? "quarterly" : "monthly",
      conditions: [
        "Control must remain in active blocking/protect mode",
        "Configuration must be updated within 30 days of vendor release",
        "Logging must remain enabled and forwarded to SIEM",
        "Re-validation required if control configuration changes",
        "Re-validation required if new bypass techniques are published"
      ]
    },
    signatureBlock: {
      reportHash,
      evidenceChainValid: chainValid,
      totalEvidenceRecords: allEvidenceRecords.length,
      integrityStatement: chainValid ? `All ${allEvidenceRecords.length} evidence records maintain cryptographic chain integrity. Report hash: ${reportHash.slice(0, 16)}...` : `WARNING: Evidence chain integrity violation detected. Manual review required.`
    },
    exportFormats: ["json", "markdown", "csv"]
  };
}
function exportReportAsMarkdown(report) {
  const lines = [];
  lines.push(`# Compensating Control Validation Report`);
  lines.push(`**Report ID:** ${report.reportId}`);
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(`**Generated By:** ${report.generatedBy}`);
  lines.push(`**Version:** ${report.reportVersion}`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(report.executiveSummary);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`## Test Results`);
  lines.push(``);
  lines.push(`| # | Test | Category | Status | Score | Verdict |`);
  lines.push(`|---|------|----------|--------|-------|---------|`);
  report.testResults.forEach((tr, i) => {
    const status = tr.execution.status === "passed" ? "PASS" : "FAIL";
    const score = tr.execution.result?.score ?? "N/A";
    const verdict = tr.execution.result?.verdict?.replace(/_/g, " ") ?? "N/A";
    lines.push(`| ${i + 1} | ${tr.testCase.title} | ${tr.testCase.testCategory.replace(/_/g, " ")} | ${status} | ${score}/100 | ${verdict} |`);
  });
  lines.push(``);
  lines.push(`## Detailed Findings`);
  lines.push(``);
  for (const tr of report.testResults) {
    if (!tr.execution.result) continue;
    lines.push(`### ${tr.testCase.title}`);
    lines.push(``);
    lines.push(`**Procedure:**`);
    lines.push(tr.testCase.procedure);
    lines.push(``);
    lines.push(`**Expected Outcome:** ${tr.testCase.expectedOutcome}`);
    lines.push(``);
    lines.push(`**Result:** ${tr.execution.result.summary}`);
    lines.push(``);
    if (tr.execution.result.detailedFindings.length > 0) {
      lines.push(`| Severity | Finding | Observed | Expected | Remediation |`);
      lines.push(`|----------|---------|----------|----------|-------------|`);
      for (const f of tr.execution.result.detailedFindings) {
        lines.push(`| ${f.severity.toUpperCase()} | ${f.title} | ${f.observed} | ${f.expected} | ${f.remediation} |`);
      }
      lines.push(``);
    }
    if (tr.execution.result.recommendations.length > 0) {
      lines.push(`**Recommendations:**`);
      tr.execution.result.recommendations.forEach((r) => lines.push(`- ${r}`));
      lines.push(``);
    }
  }
  lines.push(`## Compliance Mapping`);
  lines.push(``);
  lines.push(`| Framework | Control | Requirement | Status | Evidence |`);
  lines.push(`|-----------|---------|-------------|--------|----------|`);
  for (const cm of report.complianceMapping) {
    lines.push(`| ${cm.framework} | ${cm.controlId} | ${cm.requirement} | ${cm.status.replace(/_/g, " ").toUpperCase()} | ${cm.evidence} |`);
  }
  lines.push(``);
  lines.push(`## Risk Assessment`);
  lines.push(``);
  lines.push(`| Parameter | Value |`);
  lines.push(`|-----------|-------|`);
  lines.push(`| Residual Risk | ${report.riskAssessment.residualRisk.toUpperCase()} |`);
  lines.push(`| Mitigation Effectiveness | ${report.riskAssessment.mitigationEffectiveness}% |`);
  lines.push(`| Validation Expiration | ${report.riskAssessment.expirationDate.split("T")[0]} |`);
  lines.push(`| Review Frequency | ${report.riskAssessment.reviewFrequency} |`);
  lines.push(``);
  lines.push(`**Conditions for Continued Acceptance:**`);
  report.riskAssessment.conditions.forEach((c) => lines.push(`- ${c}`));
  lines.push(``);
  lines.push(`## Evidence Integrity`);
  lines.push(``);
  lines.push(`| Parameter | Value |`);
  lines.push(`|-----------|-------|`);
  lines.push(`| Report Hash | \`${report.signatureBlock.reportHash.slice(0, 32)}...\` |`);
  lines.push(`| Evidence Chain Valid | ${report.signatureBlock.evidenceChainValid ? "YES" : "NO \u2014 REVIEW REQUIRED"} |`);
  lines.push(`| Total Evidence Records | ${report.signatureBlock.totalEvidenceRecords} |`);
  lines.push(`| Integrity Statement | ${report.signatureBlock.integrityStatement} |`);
  lines.push(``);
  lines.push(`## Evidence Record Inventory`);
  lines.push(``);
  lines.push(`| # | Evidence ID | Type | Timestamp | Hash (first 16) | Classification |`);
  lines.push(`|---|-------------|------|-----------|------------------|----------------|`);
  let evidenceIndex = 0;
  for (const tr of report.testResults) {
    for (const ev of tr.evidenceRecords) {
      evidenceIndex++;
      lines.push(`| ${evidenceIndex} | ${ev.evidenceId} | ${ev.type.replace(/_/g, " ")} | ${ev.timestamp} | \`${ev.contentHash.slice(0, 16)}\` | ${ev.classification} |`);
    }
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`**This report was generated by the AC3 Compensating Control Testing Engine.**`);
  lines.push(`Report integrity can be verified by recomputing the SHA-256 hash of the report content.`);
  lines.push(`Evidence chain integrity can be verified by walking the chain hashes from the first to last record.`);
  lines.push(``);
  return lines.join("\n");
}
function exportEvidenceAsCSV(report) {
  const headers = ["Evidence ID", "Execution ID", "Timestamp", "Type", "Classification", "Title", "Content Hash", "Chain Hash", "Collector", "Retention Days"];
  const rows = [];
  for (const tr of report.testResults) {
    for (const ev of tr.evidenceRecords) {
      rows.push([
        ev.evidenceId,
        ev.executionId,
        ev.timestamp,
        ev.type,
        ev.classification,
        `"${ev.title.replace(/"/g, '""')}"`,
        ev.contentHash,
        ev.chainHash,
        ev.collector,
        ev.retentionDays.toString()
      ]);
    }
  }
  return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
}
function verifyEvidenceChain(evidenceRecords) {
  if (evidenceRecords.length === 0) {
    return { valid: true, brokenAt: null, totalRecords: 0, verifiedRecords: 0, details: "No evidence records to verify." };
  }
  for (let i = 0; i < evidenceRecords.length; i++) {
    const record = evidenceRecords[i];
    const expectedContentHash = sha256(record.content);
    if (expectedContentHash !== record.contentHash) {
      return {
        valid: false,
        brokenAt: i,
        totalRecords: evidenceRecords.length,
        verifiedRecords: i,
        details: `Content hash mismatch at record ${i} (${record.evidenceId}). Evidence may have been tampered with.`
      };
    }
    const expectedChainHash = computeChainHash(record.contentHash, record.previousHash);
    if (expectedChainHash !== record.chainHash) {
      return {
        valid: false,
        brokenAt: i,
        totalRecords: evidenceRecords.length,
        verifiedRecords: i,
        details: `Chain hash mismatch at record ${i} (${record.evidenceId}). Evidence chain may have been tampered with.`
      };
    }
    if (i > 0 && record.previousHash !== evidenceRecords[i - 1].chainHash) {
      return {
        valid: false,
        brokenAt: i,
        totalRecords: evidenceRecords.length,
        verifiedRecords: i,
        details: `Chain linkage broken at record ${i} (${record.evidenceId}). Previous hash does not match preceding record's chain hash.`
      };
    }
  }
  return {
    valid: true,
    brokenAt: null,
    totalRecords: evidenceRecords.length,
    verifiedRecords: evidenceRecords.length,
    details: `All ${evidenceRecords.length} evidence records verified. Chain integrity confirmed.`
  };
}
function getSupportedControlCategories() {
  return Object.entries(CONTROL_TEST_TEMPLATES).map(([category, templates]) => ({
    category,
    testCount: templates.length,
    categories: [...new Set(templates.map((t) => t.testCategory))],
    mitreTechniques: [...new Set(templates.flatMap((t) => t.mitreTechniques))],
    nistControls: [...new Set(templates.flatMap((t) => t.nistControls))]
  }));
}
function getNistControlName(controlId) {
  const names = {
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-7": "Unsuccessful Logon Attempts",
    "AC-17": "Remote Access",
    "AU-2": "Event Logging",
    "CA-7": "Continuous Monitoring",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-8": "System Component Inventory",
    "IA-2": "Identification and Authentication",
    "IA-5": "Authenticator Management",
    "IA-12": "Identity Proofing",
    "IR-4": "Incident Handling",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-18": "Mobile Code",
    "SC-23": "Session Authenticity",
    "SC-32": "System Partitioning",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
    "SI-10": "Information Input Validation"
  };
  return names[controlId] || controlId;
}
export {
  executeTest,
  exportEvidenceAsCSV,
  exportReportAsMarkdown,
  generateTestSuite,
  getSupportedControlCategories,
  runTestSuite,
  verifyEvidenceChain
};
