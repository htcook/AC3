/**
 * AC3 Banking Domain Knowledge Module
 *
 * Provides banking-specific vulnerability taxonomy, exploit categories,
 * regulatory context, and attack scenarios for LLM specialist injection.
 *
 * Injected into all LLM specialist prompts when the engagement sector
 * is detected as banking_financial_services.
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — BANKING VULNERABILITY TAXONOMY
// ═══════════════════════════════════════════════════════════════════════

export const BANKING_VULN_TAXONOMY = {
  authentication_authorization: {
    label: "Authentication & Authorization Flaws",
    vulns: [
      { id: "BANK-AUTH-001", name: "Weak/Default Credentials on Admin Portals", severity: "critical", owasp: "A07:2021", cwe: "CWE-798" },
      { id: "BANK-AUTH-002", name: "Missing Multi-Factor Authentication on High-Value Transactions", severity: "critical", owasp: "A07:2021", cwe: "CWE-308" },
      { id: "BANK-AUTH-003", name: "Session Fixation / Token Reuse", severity: "high", owasp: "A07:2021", cwe: "CWE-384" },
      { id: "BANK-AUTH-004", name: "Insecure Password Reset / Recovery Flow", severity: "high", owasp: "A07:2021", cwe: "CWE-640" },
      { id: "BANK-AUTH-005", name: "Broken Access Control on Account Management APIs", severity: "critical", owasp: "A01:2021", cwe: "CWE-639" },
      { id: "BANK-AUTH-006", name: "Horizontal Privilege Escalation (IDOR) on Account Data", severity: "critical", owasp: "A01:2021", cwe: "CWE-639" },
      { id: "BANK-AUTH-007", name: "Vertical Privilege Escalation to Admin Functions", severity: "critical", owasp: "A01:2021", cwe: "CWE-269" },
      { id: "BANK-AUTH-008", name: "JWT/Token Manipulation for Account Impersonation", severity: "critical", owasp: "A02:2021", cwe: "CWE-347" },
      { id: "BANK-AUTH-009", name: "OAuth/OIDC Misconfiguration Allowing Account Takeover", severity: "critical", owasp: "A07:2021", cwe: "CWE-287" },
      { id: "BANK-AUTH-010", name: "Concurrent Session Abuse (Session Riding)", severity: "medium", owasp: "A07:2021", cwe: "CWE-384" },
    ],
  },
  injection_attacks: {
    label: "Injection Attacks",
    vulns: [
      { id: "BANK-INJ-001", name: "SQL Injection in Account Lookup / Search", severity: "critical", owasp: "A03:2021", cwe: "CWE-89" },
      { id: "BANK-INJ-002", name: "SQL Injection in Transaction History Queries", severity: "critical", owasp: "A03:2021", cwe: "CWE-89" },
      { id: "BANK-INJ-003", name: "Blind SQL Injection in Login Forms", severity: "critical", owasp: "A03:2021", cwe: "CWE-89" },
      { id: "BANK-INJ-004", name: "Stored XSS in Account Notes / Messages", severity: "high", owasp: "A03:2021", cwe: "CWE-79" },
      { id: "BANK-INJ-005", name: "Reflected XSS in Search / Error Pages", severity: "medium", owasp: "A03:2021", cwe: "CWE-79" },
      { id: "BANK-INJ-006", name: "DOM-Based XSS in Client-Side Banking App", severity: "high", owasp: "A03:2021", cwe: "CWE-79" },
      { id: "BANK-INJ-007", name: "LDAP Injection in Directory Lookups", severity: "high", owasp: "A03:2021", cwe: "CWE-90" },
      { id: "BANK-INJ-008", name: "XML External Entity (XXE) in Payment Processing", severity: "critical", owasp: "A05:2021", cwe: "CWE-611" },
      { id: "BANK-INJ-009", name: "Server-Side Template Injection (SSTI)", severity: "critical", owasp: "A03:2021", cwe: "CWE-94" },
      { id: "BANK-INJ-010", name: "Command Injection via File Upload / Processing", severity: "critical", owasp: "A03:2021", cwe: "CWE-78" },
    ],
  },
  business_logic: {
    label: "Business Logic Flaws",
    vulns: [
      { id: "BANK-BL-001", name: "Transaction Amount Manipulation (Negative/Overflow)", severity: "critical", owasp: "A04:2021", cwe: "CWE-20" },
      { id: "BANK-BL-002", name: "Race Condition in Fund Transfer (Double Spending)", severity: "critical", owasp: "A04:2021", cwe: "CWE-362" },
      { id: "BANK-BL-003", name: "Insufficient Transaction Validation (Missing Server-Side Checks)", severity: "critical", owasp: "A04:2021", cwe: "CWE-20" },
      { id: "BANK-BL-004", name: "Account Enumeration via Error Messages", severity: "medium", owasp: "A07:2021", cwe: "CWE-203" },
      { id: "BANK-BL-005", name: "Insufficient Rate Limiting on Login / OTP", severity: "high", owasp: "A07:2021", cwe: "CWE-307" },
      { id: "BANK-BL-006", name: "Bypass of Transaction Limits via API Manipulation", severity: "critical", owasp: "A04:2021", cwe: "CWE-20" },
      { id: "BANK-BL-007", name: "Currency Rounding Exploitation (Salami Attack)", severity: "medium", owasp: "A04:2021", cwe: "CWE-682" },
      { id: "BANK-BL-008", name: "Workflow Bypass (Skip Approval Steps)", severity: "critical", owasp: "A04:2021", cwe: "CWE-841" },
      { id: "BANK-BL-009", name: "Insufficient Logging of High-Value Transactions", severity: "high", owasp: "A09:2021", cwe: "CWE-778" },
      { id: "BANK-BL-010", name: "Mass Assignment on Account Profile / Settings", severity: "high", owasp: "A08:2021", cwe: "CWE-915" },
    ],
  },
  data_exposure: {
    label: "Sensitive Data Exposure",
    vulns: [
      { id: "BANK-DATA-001", name: "PII/PAN Exposure in API Responses", severity: "critical", owasp: "A02:2021", cwe: "CWE-200" },
      { id: "BANK-DATA-002", name: "Account Numbers in URL Parameters", severity: "high", owasp: "A02:2021", cwe: "CWE-598" },
      { id: "BANK-DATA-003", name: "Unencrypted Sensitive Data in Transit (Missing TLS)", severity: "critical", owasp: "A02:2021", cwe: "CWE-319" },
      { id: "BANK-DATA-004", name: "Sensitive Data in Client-Side Storage (localStorage/cookies)", severity: "high", owasp: "A02:2021", cwe: "CWE-922" },
      { id: "BANK-DATA-005", name: "Verbose Error Messages Leaking Internal Architecture", severity: "medium", owasp: "A05:2021", cwe: "CWE-209" },
      { id: "BANK-DATA-006", name: "Directory Listing Exposing Sensitive Files", severity: "high", owasp: "A05:2021", cwe: "CWE-548" },
      { id: "BANK-DATA-007", name: "Backup/Config Files Accessible via Web", severity: "critical", owasp: "A05:2021", cwe: "CWE-530" },
      { id: "BANK-DATA-008", name: "API Documentation / Swagger Exposed Publicly", severity: "medium", owasp: "A05:2021", cwe: "CWE-200" },
      { id: "BANK-DATA-009", name: "Hardcoded Credentials in Client-Side JavaScript", severity: "critical", owasp: "A02:2021", cwe: "CWE-798" },
      { id: "BANK-DATA-010", name: "Insufficient Data Masking on Account Statements", severity: "medium", owasp: "A02:2021", cwe: "CWE-200" },
    ],
  },
  infrastructure_config: {
    label: "Infrastructure & Configuration",
    vulns: [
      { id: "BANK-INFRA-001", name: "Outdated TLS Configuration (TLS 1.0/1.1, Weak Ciphers)", severity: "high", owasp: "A02:2021", cwe: "CWE-326" },
      { id: "BANK-INFRA-002", name: "Missing Security Headers (CSP, HSTS, X-Frame-Options)", severity: "medium", owasp: "A05:2021", cwe: "CWE-693" },
      { id: "BANK-INFRA-003", name: "Server Version Disclosure", severity: "low", owasp: "A05:2021", cwe: "CWE-200" },
      { id: "BANK-INFRA-004", name: "Default/Exposed Admin Interfaces (phpMyAdmin, Tomcat Manager)", severity: "critical", owasp: "A05:2021", cwe: "CWE-1188" },
      { id: "BANK-INFRA-005", name: "Unrestricted File Upload", severity: "critical", owasp: "A04:2021", cwe: "CWE-434" },
      { id: "BANK-INFRA-006", name: "CORS Misconfiguration Allowing Cross-Origin Data Access", severity: "high", owasp: "A05:2021", cwe: "CWE-942" },
      { id: "BANK-INFRA-007", name: "SSRF via Internal Service Calls", severity: "critical", owasp: "A10:2021", cwe: "CWE-918" },
      { id: "BANK-INFRA-008", name: "Clickjacking on Transaction Pages", severity: "medium", owasp: "A05:2021", cwe: "CWE-1021" },
      { id: "BANK-INFRA-009", name: "CSRF on State-Changing Operations (Transfers, Settings)", severity: "high", owasp: "A01:2021", cwe: "CWE-352" },
      { id: "BANK-INFRA-010", name: "Insecure Deserialization in Java-Based Banking Apps", severity: "critical", owasp: "A08:2021", cwe: "CWE-502" },
    ],
  },
  api_mobile: {
    label: "API & Mobile Banking",
    vulns: [
      { id: "BANK-API-001", name: "Broken Object Level Authorization (BOLA) on Account APIs", severity: "critical", owasp: "A01:2021", cwe: "CWE-639" },
      { id: "BANK-API-002", name: "Excessive Data Exposure in API Responses", severity: "high", owasp: "A02:2021", cwe: "CWE-200" },
      { id: "BANK-API-003", name: "Missing Rate Limiting on Authentication APIs", severity: "high", owasp: "A07:2021", cwe: "CWE-307" },
      { id: "BANK-API-004", name: "Broken Function Level Authorization (BFLA)", severity: "critical", owasp: "A01:2021", cwe: "CWE-285" },
      { id: "BANK-API-005", name: "Mass Assignment via API Parameter Pollution", severity: "high", owasp: "A08:2021", cwe: "CWE-915" },
      { id: "BANK-API-006", name: "Insecure Direct Object Reference in REST Endpoints", severity: "critical", owasp: "A01:2021", cwe: "CWE-639" },
      { id: "BANK-API-007", name: "GraphQL Introspection Enabled in Production", severity: "medium", owasp: "A05:2021", cwe: "CWE-200" },
      { id: "BANK-API-008", name: "API Key Exposure in Mobile App Binary", severity: "high", owasp: "A02:2021", cwe: "CWE-798" },
    ],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §2 — BANKING ATTACK SCENARIOS
// ═══════════════════════════════════════════════════════════════════════

export const BANKING_ATTACK_SCENARIOS = [
  {
    name: "Account Takeover via Credential Stuffing",
    mitre: ["T1078", "T1110.004"],
    description: "Attacker uses leaked credential databases to attempt login on online banking portals. Successful logins lead to unauthorized fund transfers, PII theft, and account manipulation.",
    impact: "Direct financial loss, regulatory notification requirements under GLBA/FFIEC",
    indicators: ["High-volume login attempts", "Geographically anomalous logins", "Multiple failed auth from same IP range"],
  },
  {
    name: "SQL Injection to Database Exfiltration",
    mitre: ["T1190", "T1005"],
    description: "Attacker exploits SQL injection in account search, transaction history, or loan application forms to extract customer PII, account numbers, and transaction records.",
    impact: "Mass PII breach, PCI-DSS violation, potential wire fraud using extracted account details",
    indicators: ["SQL error messages", "Unusual query patterns", "Large data transfers from DB servers"],
  },
  {
    name: "Business Logic Exploitation — Wire Transfer Manipulation",
    mitre: ["T1190", "T1565.001"],
    description: "Attacker manipulates transaction parameters (amount, destination account, currency) via intercepted API calls or parameter tampering to redirect or inflate wire transfers.",
    impact: "Direct financial loss, potential SWIFT network compromise, regulatory sanctions",
    indicators: ["Unusual transaction amounts", "Modified API parameters", "Transactions outside business hours"],
  },
  {
    name: "Session Hijacking on Online Banking",
    mitre: ["T1539", "T1550.004"],
    description: "Attacker steals session tokens via XSS, network sniffing, or session fixation to impersonate authenticated banking users and perform unauthorized operations.",
    impact: "Unauthorized transactions, account data exposure, customer trust erosion",
    indicators: ["Session token reuse from different IPs", "Concurrent sessions from different geolocations"],
  },
  {
    name: "IDOR-Based Account Data Harvesting",
    mitre: ["T1190", "T1530"],
    description: "Attacker enumerates predictable account identifiers in API endpoints to access other customers' account details, statements, and transaction histories.",
    impact: "Mass customer data breach, GLBA/FFIEC violations, class action liability",
    indicators: ["Sequential ID enumeration in API logs", "Unusual data access patterns"],
  },
  {
    name: "Admin Panel Compromise via Default Credentials",
    mitre: ["T1078.001", "T1059"],
    description: "Attacker discovers exposed admin interfaces (Tomcat Manager, phpMyAdmin, application admin panels) with default or weak credentials, gaining full control of banking infrastructure.",
    impact: "Complete system compromise, ability to modify transactions, deploy backdoors, exfiltrate all data",
    indicators: ["Login to admin panels from external IPs", "New admin accounts created"],
  },
  {
    name: "Cross-Site Scripting for Credential Theft",
    mitre: ["T1189", "T1539"],
    description: "Attacker injects malicious JavaScript into banking application pages (stored XSS in messages, reflected XSS in search) to steal credentials, session tokens, or redirect to phishing pages.",
    impact: "Credential theft, session hijacking, phishing amplification",
    indicators: ["Script tags in user input fields", "Unusual JavaScript execution", "Cookie exfiltration attempts"],
  },
  {
    name: "API Abuse for Unauthorized Fund Transfers",
    mitre: ["T1190", "T1565"],
    description: "Attacker reverse-engineers mobile banking API to bypass client-side validation, manipulate transfer parameters, or exploit missing server-side authorization checks.",
    impact: "Unauthorized transfers, bypass of transaction limits, regulatory violations",
    indicators: ["API calls without corresponding UI activity", "Modified request headers/parameters"],
  },
  {
    name: "Insecure Deserialization in Java Banking Apps",
    mitre: ["T1190", "T1059"],
    description: "Attacker exploits Java deserialization vulnerabilities in J2EE-based banking applications (common in legacy core banking) to achieve remote code execution.",
    impact: "Full server compromise, access to core banking systems, lateral movement to internal networks",
    indicators: ["Unusual serialized objects in HTTP requests", "Unexpected process execution on app servers"],
  },
  {
    name: "SSRF to Internal Banking Network Pivot",
    mitre: ["T1190", "T1021"],
    description: "Attacker exploits SSRF vulnerability in web-facing banking application to scan and access internal services (databases, admin panels, SWIFT interfaces) not exposed to the internet.",
    impact: "Access to internal banking infrastructure, potential SWIFT/ACH system compromise",
    indicators: ["Requests to internal IP ranges from web app", "Unusual DNS lookups from DMZ servers"],
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — REGULATORY CONTEXT FOR BANKING PENTESTS
// ═══════════════════════════════════════════════════════════════════════

export const BANKING_REGULATORY_CONTEXT = `
## Banking Regulatory & Compliance Context

### PCI-DSS v4.0 Requirements (Payment Card Industry)
- Req 6.2: Develop secure software (OWASP Top 10 coverage mandatory)
- Req 6.4: Public-facing web apps must be protected against known attacks
- Req 11.3: External and internal penetration testing at least annually
- Req 11.4: Network intrusion detection/prevention systems
- Req 8.3: Strong authentication for all access to cardholder data

### GLBA (Gramm-Leach-Bliley Act)
- Safeguards Rule: Financial institutions must implement security programs
- Risk assessment must include penetration testing of customer information systems
- Notification requirements for breaches affecting 500+ customers

### FFIEC (Federal Financial Institutions Examination Council)
- IT Examination Handbook requires regular penetration testing
- Tests must cover both external and internal attack vectors
- Social engineering testing recommended for financial institutions
- Business continuity testing must include cyber scenarios

### SOX (Sarbanes-Oxley Act)
- Section 404: Internal controls over financial reporting
- IT general controls (ITGC) must be tested including access controls
- Change management and segregation of duties are key focus areas

### FedRAMP (for cloud-hosted banking systems)
- AC-3: Access enforcement testing
- RA-5: Vulnerability scanning requirements
- CA-8: Penetration testing requirements (annual minimum)
- SI-10: Information input validation testing

### OCC (Office of the Comptroller of the Currency)
- Heightened Standards: Banks must maintain effective risk management
- Third-party risk management requires vendor security assessments
- Cyber resilience expectations include regular penetration testing

### Key Banking-Specific Testing Focus Areas
1. **Transaction Integrity**: Verify all financial transactions maintain ACID properties
2. **Authentication Strength**: Test MFA implementation on all high-value operations
3. **Authorization Boundaries**: Verify role-based access prevents unauthorized operations
4. **Data Protection**: Ensure PII/PAN data is encrypted at rest and in transit
5. **Session Management**: Test session timeout, concurrent session handling, token security
6. **API Security**: Test all banking APIs for OWASP API Top 10 vulnerabilities
7. **Business Logic**: Test transaction limits, approval workflows, and fraud controls
8. **Audit Trail**: Verify comprehensive logging of all financial operations
`;

// ═══════════════════════════════════════════════════════════════════════
// §4 — BANKING TECHNOLOGY STACK AWARENESS
// ═══════════════════════════════════════════════════════════════════════

export const BANKING_TECH_STACK_CONTEXT = `
## Banking Technology Stack — Common Components & Attack Surface

### Core Banking Systems
- **Temenos T24/Transact**: Java-based, REST APIs, common in mid-size banks
- **FIS Profile/Horizon**: Legacy mainframe + web interface, COBOL backend
- **Jack Henry Symitar/SilverLake**: Credit union focused, API-first architecture
- **Fiserv DNA/Precision**: Widely deployed, known for legacy integration points

### Online Banking Platforms
- **Backbase**: Digital banking platform, Angular/React frontends, Java backend
- **Q2 Digital Banking**: Cloud-hosted, API-driven, mobile-first
- **NCR Digital Banking**: Formerly Digital Insight, J2EE-based
- **Custom J2EE/Spring**: Many banks run custom Java applications (like AltoroJ)

### Payment Processing
- **SWIFT Alliance**: Messaging for international wire transfers
- **FedACH/FedWire**: Federal Reserve payment systems
- **ISO 8583**: Card transaction message format
- **PCI-DSS Scope**: Any system touching cardholder data

### Common Vulnerable Technologies in Banking
- **Apache Struts**: Historically exploited in financial sector (Equifax breach)
- **Java Deserialization**: Common in J2EE banking apps
- **Legacy SSL/TLS**: Many banking systems still support TLS 1.0/1.1
- **SOAP/XML Services**: Common in B2B banking integrations (XXE risk)
- **Tomcat Manager**: Often exposed on banking app servers
- **phpMyAdmin**: Sometimes left accessible on database servers
- **Jenkins/CI**: Build servers with access to production credentials
`;

// ═══════════════════════════════════════════════════════════════════════
// §5 — CONTEXT INJECTION FUNCTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a banking-specific context block for LLM injection.
 * Called when engagement sector is banking_financial_services.
 */
export function buildBankingDomainContext(options?: {
  phase?: string;
  includeRegulatory?: boolean;
  includeTechStack?: boolean;
  includeAttackScenarios?: boolean;
  includeVulnTaxonomy?: boolean;
}): string {
  const phase = options?.phase || 'general';
  const sections: string[] = [];

  sections.push(`## Banking Domain Intelligence\n`);
  sections.push(`This is a BANKING / FINANCIAL SERVICES engagement. Apply banking-specific security knowledge throughout your analysis.\n`);

  // Always include high-priority banking vuln categories
  sections.push(`### Priority Vulnerability Categories for Banking`);
  sections.push(`Focus on these banking-critical vulnerability types:`);
  for (const [_key, category] of Object.entries(BANKING_VULN_TAXONOMY)) {
    const criticals = category.vulns.filter(v => v.severity === 'critical');
    if (criticals.length > 0) {
      sections.push(`\n**${category.label}** (${criticals.length} critical):`);
      for (const v of criticals.slice(0, 3)) {
        sections.push(`  • ${v.name} [${v.owasp}/${v.cwe}]`);
      }
    }
  }

  // Phase-specific context
  if (phase === 'recon' || phase === 'enumeration') {
    sections.push(`\n### Banking Recon Priorities`);
    sections.push(`• Look for online banking portals, admin interfaces, API endpoints`);
    sections.push(`• Identify Java application servers (Tomcat, JBoss, WebLogic) — common in banking`);
    sections.push(`• Check for exposed SWIFT/payment processing interfaces`);
    sections.push(`• Enumerate all web applications — banking often runs multiple apps on same infrastructure`);
    sections.push(`• Check for legacy protocols and services (SOAP, XML-RPC, old TLS versions)`);
  }

  if (phase === 'vuln_detection') {
    sections.push(`\n### Banking Vulnerability Detection Focus`);
    sections.push(`• SQL Injection: Test ALL input fields, especially account search, transaction queries, login forms`);
    sections.push(`• XSS: Test stored XSS in messaging, reflected XSS in search/error pages`);
    sections.push(`• IDOR: Test account ID enumeration in API endpoints`);
    sections.push(`• Business Logic: Test transaction amount manipulation, negative values, overflow`);
    sections.push(`• Authentication: Test password policy, lockout mechanisms, MFA bypass`);
    sections.push(`• Session Management: Test session timeout, fixation, concurrent sessions`);
    sections.push(`• Java Deserialization: Test if J2EE endpoints accept serialized objects`);
    sections.push(`• SSRF: Test URL parameters that might access internal banking services`);
  }

  if (phase === 'exploitation') {
    sections.push(`\n### Banking Exploitation Priorities`);
    sections.push(`• Prioritize SQL injection for data exfiltration (account records, PII)`);
    sections.push(`• Attempt IDOR exploitation to demonstrate cross-account access`);
    sections.push(`• Test business logic flaws: transfer manipulation, limit bypass`);
    sections.push(`• Exploit XSS for session hijacking demonstration`);
    sections.push(`• Test admin panel access with default/common credentials`);
    sections.push(`• Attempt Java deserialization RCE if applicable`);
    sections.push(`• Document all findings with banking-specific impact assessment`);
  }

  if (phase === 'post_exploit') {
    sections.push(`\n### Banking Post-Exploitation Assessment`);
    sections.push(`• Assess impact on customer data (PII, account numbers, transaction history)`);
    sections.push(`• Evaluate potential for unauthorized fund transfers`);
    sections.push(`• Map lateral movement paths to core banking systems`);
    sections.push(`• Assess regulatory notification requirements (GLBA, PCI-DSS)`);
    sections.push(`• Document compliance gaps against FFIEC, SOX, PCI-DSS requirements`);
    sections.push(`• Calculate potential financial impact of each finding`);
  }

  // Include attack scenarios for exploitation and post-exploit phases
  if (options?.includeAttackScenarios !== false && (phase === 'exploitation' || phase === 'post_exploit' || phase === 'vuln_detection')) {
    sections.push(`\n### Realistic Banking Attack Scenarios`);
    for (const scenario of BANKING_ATTACK_SCENARIOS.slice(0, 5)) {
      sections.push(`\n**${scenario.name}** [${scenario.mitre.join(', ')}]`);
      sections.push(`${scenario.description}`);
      sections.push(`Impact: ${scenario.impact}`);
    }
  }

  // Include regulatory context
  if (options?.includeRegulatory !== false) {
    sections.push(BANKING_REGULATORY_CONTEXT);
  }

  // Include tech stack awareness
  if (options?.includeTechStack !== false && (phase === 'recon' || phase === 'enumeration' || phase === 'vuln_detection')) {
    sections.push(BANKING_TECH_STACK_CONTEXT);
  }

  return sections.join('\n');
}

/**
 * Get a compact banking context summary (for token-constrained prompts).
 */
export function getBankingContextCompact(): string {
  return `BANKING SECTOR ENGAGEMENT — Focus on: SQL injection (account queries), IDOR (account enumeration), XSS (session hijacking), business logic (transaction manipulation), authentication bypass, Java deserialization (J2EE apps), SSRF (internal network pivot), default admin credentials. Regulatory: PCI-DSS, GLBA, FFIEC, SOX. Crown jewels: Core banking, SWIFT, online banking portal, customer database, payment processing.`;
}
