/**
 * Import Ontic NMAP scan findings into AC3 engagement_findings table
 * Engagement ID: 2220001 (Ontic FedRAMP High Red Team Exercise 2026)
 * Source: /home/ubuntu/upload/Ontic.xml
 * Scan Date: July 26, 2026 20:43 EDT (Unix: 1785113007)
 */

import mysql from 'mysql2/promise';
import fs from 'fs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

const ENGAGEMENT_ID = 2220001;
const SCAN_TIMESTAMP = 1785113007000; // Jul 26, 2026 20:43:27 EDT in ms

// Parsed findings from the NMAP scan analysis
const nmapFindings = [
  {
    title: "HSTS Not Configured on Authentication Endpoint",
    severity: "medium",
    cwe: "CWE-16",
    description: "The Strict-Transport-Security header is not configured on login.ontic-tech.com. Without HSTS, browsers will not enforce HTTPS connections, leaving users vulnerable to SSL-stripping and man-in-the-middle attacks during the initial connection to the authentication endpoint. This is particularly concerning as this is the login/authentication service.",
    endpoint: "https://login.ontic-tech.com:443",
    hostname: "login.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap ssl-enum-ciphers + http-security-headers",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `Nmap scan report for login.ontic-tech.com (172.65.90.26)
PORT    STATE SERVICE  REASON         VERSION
443/tcp open  ssl/http syn-ack ttl 56 Cloudflare http proxy

| http-security-headers: 
|   Strict_Transport_Security: 
|     HSTS not configured in HTTPS Server
|   X_Frame_Options: 
|     Header: X-Frame-Options: SAMEORIGIN

Scan timestamp: Sun Jul 26 20:44:08 2026 (UTC: Mon, 27 Jul 2026 00:44:08 GMT)
CF-RAY: a2179d2808974160-IAD`,
    mitreTechnique: "T1557 (Adversary-in-the-Middle)",
  },
  {
    title: "Content Security Policy (CSP) Not Configured",
    severity: "medium",
    cwe: "CWE-693",
    description: "No Content-Security-Policy header was detected on any of the 6 scanned hosts. Without CSP, the browser cannot restrict which resources (scripts, styles, images) may be loaded, significantly increasing the risk and impact of any Cross-Site Scripting (XSS) vulnerability. If an XSS flaw exists or is introduced, attackers can execute arbitrary JavaScript with no browser-level mitigation.",
    endpoint: "https://*.ontic-tech.com:443",
    hostname: "prod5.ontic-tech.com, prod6.ontic-tech.com, qa-prod6.ontic-tech.com, qa2-prod6.ontic-tech.com, login.ontic-tech.com, gc1pr-scon.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-security-headers",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `All 6 hosts scanned — CSP header absent from every response.

Example from qa2-prod6.ontic-tech.com (104.18.12.121):
| http-security-headers: 
|   Strict_Transport_Security: 
|     Header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
|   X_Frame_Options: 
|     Header: X-Frame-Options: DENY
|   X_XSS_Protection: 
|     Header: X-XSS-Protection: 1; mode=block
|   X_Content_Type_Options: 
|     Header: X-Content-Type-Options: nosniff
|   Cache_Control: 
|     Header: Cache-Control: public, max-age=0
[NO Content-Security-Policy header present]

Scan timestamp: Sun Jul 26 20:43:52 2026 (UTC: Mon, 27 Jul 2026 00:43:52 GMT)`,
    mitreTechnique: "T1059.007 (Command & Scripting Interpreter: JavaScript)",
  },
  {
    title: "Server Technology Disclosure (X-Powered-By: Express)",
    severity: "low",
    cwe: "CWE-200",
    description: "The QA environments (qa-prod6.ontic-tech.com and qa2-prod6.ontic-tech.com) disclose the backend server technology via the X-Powered-By: Express header. This information aids attackers in fingerprinting the application stack and selecting targeted exploits for Node.js/Express vulnerabilities (e.g., prototype pollution, SSRF, template injection).",
    endpoint: "https://qa-prod6.ontic-tech.com:443, https://qa2-prod6.ontic-tech.com:443",
    hostname: "qa-prod6.ontic-tech.com, qa2-prod6.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-headers",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `Nmap scan report for qa2-prod6.ontic-tech.com (104.18.12.121)
| http-headers: 
|   Date: Mon, 27 Jul 2026 00:43:52 GMT
|   Content-Type: text/html; charset=UTF-8
|   Connection: close
|   x-powered-by: Express
|   x-frame-options: DENY
|   x-xss-protection: 1; mode=block
|   x-content-type-options: nosniff
|   strict-transport-security: max-age=31536000; includeSubDomains; preload
|   Accept-Ranges: bytes
|   Cache-Control: public, max-age=0
|   last-modified: Tue, 12 May 2026 03:07:01 GMT
|   cf-cache-status: DYNAMIC
|   Server: cloudflare
|   CF-RAY: a2179cc69b201eec-IAD

Nmap scan report for qa-prod6.ontic-tech.com (172.65.90.27)
| http-headers:
|   x-powered-by: Express
|   CF-RAY: a2179d273a8d82e7-IAD

Scan timestamp: Sun Jul 26 20:43-20:44 2026`,
    mitreTechnique: "T1592.004 (Gather Victim Host Information: Client Configurations)",
  },
  {
    title: "QA/Staging Environments Publicly Accessible",
    severity: "medium",
    cwe: "CWE-668",
    description: "Two QA/staging environments (qa-prod6.ontic-tech.com and qa2-prod6.ontic-tech.com) are publicly accessible over the internet and serve the application login page. QA environments typically have weaker authentication controls, test accounts, debug endpoints, and less restrictive WAF rules. Public exposure of pre-production environments expands the attack surface and may allow access to test data or functionality not intended for production.",
    endpoint: "https://qa-prod6.ontic-tech.com:443/login.html, https://qa2-prod6.ontic-tech.com:443/login.html",
    hostname: "qa-prod6.ontic-tech.com, qa2-prod6.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-title + http-methods",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `Nmap scan report for qa2-prod6.ontic-tech.com (104.18.12.121)
PORT    STATE SERVICE  REASON         VERSION
443/tcp open  ssl/http syn-ack ttl 56 Cloudflare http proxy
| http-title: Ontic
|_Requested resource was /login.html
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Nmap scan report for qa-prod6.ontic-tech.com (172.65.90.27)
PORT    STATE SERVICE  REASON         VERSION
443/tcp open  ssl/http syn-ack ttl 56 Cloudflare http proxy
| http-title: Ontic
|_Requested resource was /login.html
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Both environments respond with the Ontic application login page.
Production hosts (prod5, prod6) return Cloudflare challenge pages ("Attention Required!").
QA hosts bypass this challenge and serve the application directly.

Scan timestamp: Sun Jul 26 20:43:52-20:44:08 2026`,
    mitreTechnique: "T1190 (Exploit Public-Facing Application)",
  },
  {
    title: "Inconsistent X-Frame-Options Header (SAMEORIGIN vs DENY)",
    severity: "low",
    cwe: "CWE-1021",
    description: "The X-Frame-Options header is inconsistently configured across the Ontic infrastructure. Production hosts (prod5, prod6) and the login endpoint use SAMEORIGIN, while QA environments use DENY. The gc1pr-scon API endpoint has no X-Frame-Options header at all. Inconsistent clickjacking protection may allow framing attacks against specific endpoints.",
    endpoint: "https://*.ontic-tech.com:443",
    hostname: "prod5.ontic-tech.com, prod6.ontic-tech.com, login.ontic-tech.com, qa-prod6.ontic-tech.com, qa2-prod6.ontic-tech.com, gc1pr-scon.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-security-headers",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `X-Frame-Options by host:
- prod5.ontic-tech.com: SAMEORIGIN
- prod6.ontic-tech.com: SAMEORIGIN
- qa-prod6.ontic-tech.com: DENY
- qa2-prod6.ontic-tech.com: DENY
- login.ontic-tech.com: SAMEORIGIN
- gc1pr-scon.ontic-tech.com: NOT PRESENT

Evidence from prod5:
|   X_Frame_Options: 
|     Header: X-Frame-Options: SAMEORIGIN

Evidence from qa2-prod6:
|   X_Frame_Options: 
|     Header: X-Frame-Options: DENY

Evidence from gc1pr-scon (absent):
| http-security-headers: 
|   Strict_Transport_Security: 
|     Header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
|   X_Content_Type_Options: 
|     Header: X-Content-Type-Options: nosniff
[No X-Frame-Options header]

Scan timestamp: Sun Jul 26 20:43:51-20:44:23 2026`,
    mitreTechnique: "T1189 (Drive-by Compromise)",
  },
  {
    title: "Dual-CDN Architecture Detected (Cloudflare + CloudFront)",
    severity: "info",
    cwe: null,
    description: "The gc1pr-scon.ontic-tech.com endpoint routes through both Cloudflare (edge proxy) and AWS CloudFront (origin). Response headers include both Cloudflare CF-RAY identifiers and CloudFront x-amz-cf-pop/x-amz-cf-id headers. This dual-CDN architecture is unusual and may indicate a misconfiguration or transitional state. It also presents a potential avenue for origin IP discovery via CloudFront error pages or misconfigured cache behaviors.",
    endpoint: "https://gc1pr-scon.ontic-tech.com:443",
    hostname: "gc1pr-scon.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-headers",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `Nmap scan report for gc1pr-scon.ontic-tech.com (172.65.90.27)
PORT    STATE SERVICE  REASON         VERSION
443/tcp open  ssl/http syn-ack ttl 56 Cloudflare http proxy
|_http-title: Site doesn't have a title (application/xml).
| http-headers: 
|   Date: Mon, 27 Jul 2026 00:44:23 GMT
|   Content-Type: application/xml
|   Transfer-Encoding: chunked
|   Connection: close
|   Server: cloudflare
|   x-cache: Error from cloudfront
|   via: 1.1 fb5457d63c2bae82c659669b952f7d52.cloudfront.net (CloudFront)
|   x-amz-cf-pop: IAD61-P9
|   x-amz-cf-id: hl8adj5Qex5iR7Oo3uFw3paZLXDjU9cEmyQOFhQQ6KKhh3tAr7njsg==
|   cf-cache-status: DYNAMIC
|   X-Content-Type-Options: nosniff
|   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
|   CF-RAY: a2179d88ee0bd6c8-IAD

Note: "x-cache: Error from cloudfront" indicates the CloudFront origin returned an error.
The endpoint serves application/xml content — likely an API or data feed endpoint.

Scan timestamp: Sun Jul 26 20:44:23 2026`,
    mitreTechnique: "T1590.004 (Gather Victim Network Information: Network Topology)",
  },
  {
    title: "XML API Endpoint Publicly Exposed (gc1pr-scon)",
    severity: "medium",
    cwe: "CWE-668",
    description: "The gc1pr-scon.ontic-tech.com endpoint serves application/xml content directly without authentication challenge (no Cloudflare challenge page like production hosts). This appears to be a SOAP or REST API endpoint. Publicly exposed XML APIs are susceptible to XXE injection, IDOR, authentication bypass, and data enumeration attacks. The endpoint should be evaluated for proper authentication and input validation.",
    endpoint: "https://gc1pr-scon.ontic-tech.com:443",
    hostname: "gc1pr-scon.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-headers + http-title",
    corroborationTier: "unverified",
    sourceType: "scanner",
    rawEvidence: `Nmap scan report for gc1pr-scon.ontic-tech.com (172.65.90.27)
|_http-title: Site doesn't have a title (application/xml).
| http-headers: 
|   Content-Type: application/xml
|   Transfer-Encoding: chunked
|   x-cache: Error from cloudfront
|   via: 1.1 fb5457d63c2bae82c659669b952f7d52.cloudfront.net (CloudFront)

Unlike prod5/prod6 which return "Attention Required! | Cloudflare" challenge pages,
gc1pr-scon responds directly with XML content (no WAF challenge).

Scan timestamp: Sun Jul 26 20:44:23 2026`,
    mitreTechnique: "T1190 (Exploit Public-Facing Application)",
  },
  {
    title: "Missing X-Content-Type-Options on Authentication Endpoint",
    severity: "low",
    cwe: "CWE-16",
    description: "The login.ontic-tech.com endpoint does not include the X-Content-Type-Options: nosniff header. Without this header, browsers may MIME-sniff responses away from the declared content-type, potentially enabling content-type confusion attacks.",
    endpoint: "https://login.ontic-tech.com:443",
    hostname: "login.ontic-tech.com",
    port: 443,
    source: "nmap",
    tool: "nmap http-security-headers",
    corroborationTier: "confirmed",
    sourceType: "scanner",
    rawEvidence: `Nmap scan report for login.ontic-tech.com (172.65.90.26)
| http-security-headers: 
|   Strict_Transport_Security: 
|     HSTS not configured in HTTPS Server
|   X_Frame_Options: 
|     Header: X-Frame-Options: SAMEORIGIN
|   Cache_Control: 
|     Header: Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate
|   Expires: 
|     Header: Expires: Thu, 01 Jan 1970 00:00:01 GMT
[No X-Content-Type-Options header present]
[No Referrer-Policy header present on other hosts but present on prod5/prod6]

Scan timestamp: Sun Jul 26 20:44:08 2026`,
    mitreTechnique: null,
  },
];

async function importFindings() {
  const conn = await mysql.createConnection(DATABASE_URL);
  
  console.log(`Importing ${nmapFindings.length} NMAP findings into Ontic engagement (ID: ${ENGAGEMENT_ID})...`);
  
  for (const finding of nmapFindings) {
    const [result] = await conn.execute(
      `INSERT INTO engagement_findings 
       (engagement_id, title, severity, cwe, description, endpoint, hostname, port, source, tool, 
        corroboration_tier, raw_evidence, mitre_technique, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ENGAGEMENT_ID,
        finding.title,
        finding.severity,
        finding.cwe,
        finding.description,
        finding.endpoint,
        finding.hostname,
        finding.port,
        finding.source,
        finding.tool,
        finding.corroborationTier,
        finding.rawEvidence,
        finding.mitreTechnique,
        SCAN_TIMESTAMP,
      ]
    );
    console.log(`  ✓ Imported: ${finding.title} (${finding.severity})`);
  }
  
  // Verify import
  const [rows] = await conn.execute(
    'SELECT severity, COUNT(*) as count FROM engagement_findings WHERE engagement_id = ? GROUP BY severity ORDER BY FIELD(severity, "critical", "high", "medium", "low", "info")',
    [ENGAGEMENT_ID]
  );
  
  console.log('\n--- Import Summary ---');
  console.log(`Engagement: Ontic FedRAMP High Red Team Exercise 2026 (ID: ${ENGAGEMENT_ID})`);
  console.log(`Scan source: NMAP (nmap -sS -sV -p 443 -T3 -Pn)`);
  console.log(`Scan date: Sun Jul 26 20:43:27 2026 EDT`);
  console.log(`Findings by severity:`);
  for (const row of rows) {
    console.log(`  ${row.severity}: ${row.count}`);
  }
  
  await conn.end();
  console.log('\nDone. Findings are now visible in the Ontic engagement on AC3.');
}

importFindings().catch(err => {
  console.error('Import failed:', err);
  process.exit(1);
});
