#!/usr/bin/env node
/**
 * test-llm-knowledge.mjs — Comprehensive LLM Knowledge Stack Test
 * 
 * Tests the full knowledge injection pipeline against real free test targets:
 * 1. Scan Plan Generation — tech detection + tool selection + evasion + cloud awareness
 * 2. Vuln Correlation — KEV matching + cloud misconfig + CVSS scoring
 * 3. Hunt Hypothesis Generation — attack path modeling + MITRE mapping
 * 4. Asset Classification — CARVER scoring + cloud risk factors
 * 
 * Targets: testphp.vulnweb.com, demo.testfire.net, scanme.nmap.org, testasp.vulnweb.com
 */

const API_URL = process.env.BUILT_IN_FORGE_API_URL?.replace(/\/$/, '') + '/v1/chat/completions';
const API_KEY = process.env.BUILT_IN_FORGE_API_KEY;

if (!API_KEY) {
  console.error('ERROR: BUILT_IN_FORGE_API_KEY not set');
  process.exit(1);
}

// ─── Simulated Recon Data (based on real probe results) ────────────────────

const TARGET_PROFILES = {
  'testphp.vulnweb.com': {
    ip: '44.228.249.3',
    cloudProvider: 'AWS',
    headers: {
      'Server': 'nginx/1.19.0',
      'X-Powered-By': 'PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    technologies: ['nginx', 'PHP', 'Ubuntu', 'MySQL'],
    ports: [
      { port: 80, service: 'http', version: 'nginx 1.19.0' },
      { port: 443, service: 'https', version: 'nginx 1.19.0' },
    ],
    htmlHints: 'Acunetix PHP test site, login form, search form, file upload, SQL injection test pages',
    wafDetected: 'none',
    passiveRiskSignals: [
      'PHP 5.6 is end-of-life since 2018',
      'Known SQL injection test endpoints',
      'File upload functionality detected',
    ],
  },
  'demo.testfire.net': {
    ip: '65.61.137.117',
    cloudProvider: null,
    headers: {
      'Server': 'Apache-Coyote/1.1',
      'Content-Type': 'text/html',
      'Set-Cookie': 'JSESSIONID=...',
    },
    technologies: ['Apache Tomcat', 'Java', 'JSP'],
    ports: [
      { port: 80, service: 'http', version: 'Apache-Coyote/1.1' },
      { port: 443, service: 'https', version: 'Apache-Coyote/1.1' },
      { port: 8080, service: 'http-proxy', version: 'Apache-Coyote/1.1' },
    ],
    htmlHints: 'Altoro Mutual banking application, login form, account management, fund transfer, JSESSIONID cookie',
    wafDetected: 'none',
    passiveRiskSignals: [
      'Java/Tomcat application server',
      'Banking application with fund transfer functionality',
      'JSESSIONID session management',
    ],
  },
  'scanme.nmap.org': {
    ip: '45.33.32.156',
    cloudProvider: null,
    headers: {
      'Server': 'Apache/2.4.7 (Ubuntu)',
      'Content-Type': 'text/html',
    },
    technologies: ['Apache', 'Ubuntu', 'OpenSSH'],
    ports: [
      { port: 22, service: 'ssh', version: 'OpenSSH 6.6.1p1' },
      { port: 80, service: 'http', version: 'Apache/2.4.7' },
      { port: 9929, service: 'nping-echo', version: 'Nping echo' },
      { port: 31337, service: 'tcpwrapped', version: '' },
    ],
    htmlHints: 'Nmap test host, authorized for scanning, multiple open services',
    wafDetected: 'none',
    passiveRiskSignals: [
      'OpenSSH 6.6.1 is outdated (2014 release)',
      'Apache 2.4.7 is outdated',
      'Unusual port 31337 open (hacker culture port)',
      'Port 9929 nping-echo service exposed',
    ],
  },
  'testasp.vulnweb.com': {
    ip: '44.228.249.3',
    cloudProvider: 'AWS',
    headers: {
      'Server': 'Microsoft-IIS/10.0',
      'X-Powered-By': 'ASP.NET',
      'X-AspNet-Version': '4.0.30319',
    },
    technologies: ['IIS', 'ASP.NET', 'Windows Server', 'MSSQL'],
    ports: [
      { port: 80, service: 'http', version: 'Microsoft-IIS/10.0' },
      { port: 443, service: 'https', version: 'Microsoft-IIS/10.0' },
    ],
    htmlHints: 'Acunetix ASP.NET test site, .aspx pages, ViewState, SQL injection test pages',
    wafDetected: 'none',
    passiveRiskSignals: [
      'ASP.NET version disclosure in headers',
      'IIS 10.0 with default configuration',
      'ViewState potentially unencrypted',
    ],
  },
};

// ─── Knowledge Module Context Builders ─────────────────────────────────────

function buildNmapScanPlanContext(detectedTech, cloudProvider) {
  // Simplified version of the server-side getNmapScanPlanContext
  const evasionTable = `### Evasion Technique Selection Guide

| Scenario | Recommended Evasion | Flags |
|----------|-------------------|-------|
| No IDS/firewall detected | None needed — use -sS -sV for speed | -sS -sV -T4 |
| Basic firewall (stateless) | FIN/NULL/XMAS scan bypasses packet filters | -sF or -sN or -sX |
| Stateful firewall | ACK scan to map rules, then targeted SYN | -sA first, then -sS on unfiltered |
| IDS/IPS present | Slow timing + fragmentation + source port spoof | -T1 -f --source-port 53 |
| Heavily monitored SOC | Full layered evasion: decoys + fragment + timing + DNS | -sS -T1 -f -D RND:3 -g 53 -n --data-length 24 |
| Cloud WAF (CloudFlare/AWS) | Very slow with rate limiting | -T2 --max-rate 10 --scan-delay 2s |

Key principles:
1. Layer techniques — each defeats a different detection mechanism
2. ACK scan first to map firewall rules before targeted scanning
3. Source port 53 is the most effective single evasion flag (DNS trust)
4. -Pn -n always for stealth (skip ping, skip DNS)
5. --data-length changes packet signature to evade pattern matching`;

  const techScripts = {
    'PHP': 'http-vuln-cve2012-1823, http-phpself-xss, http-phpmyadmin-dir-traversal, http-sql-injection, http-enum',
    'nginx': 'http-enum, http-methods, http-security-headers, http-cors, ssl-enum-ciphers',
    'Apache': 'http-shellshock, http-vuln-cve2011-3192, http-vuln-cve2011-3368, http-enum, http-methods, http-slowloris-check',
    'Apache Tomcat': 'http-vuln-cve2017-5638, http-vuln-cve2010-0738, http-default-accounts, http-enum, rmi-vuln-classloader',
    'Java': 'http-vuln-cve2017-5638, http-vuln-cve2010-0738, http-default-accounts, rmi-vuln-classloader',
    'IIS': 'http-aspnet-debug, http-iis-webdav-vuln, http-vuln-cve2015-1635, http-enum, http-methods',
    'ASP.NET': 'http-aspnet-debug, http-iis-webdav-vuln, http-vuln-cve2015-1635, http-enum, http-methods',
    'OpenSSH': 'ssh2-enum-algos, ssh-auth-methods, ssh-hostkey',
    'MySQL': 'mysql-info, mysql-enum, mysql-vuln-cve2012-2122, mysql-empty-password',
    'MSSQL': 'ms-sql-info, ms-sql-brute',
  };

  let techContext = '';
  for (const tech of detectedTech) {
    if (techScripts[tech]) {
      techContext += `\n**${tech}:** ${techScripts[tech]}`;
    }
  }

  const scanProfiles = `### Scan Profile Templates
- **Stealth Recon**: nmap -sS -T1 -f --source-port 53 -D RND:3 --data-length 24 -n -Pn --max-rate 10 {target}
- **Web Application**: nmap -sV --script "http-* and safe" -p 80,443,8080,8443 {target}
- **Full Vulnerability**: nmap -sV --script vuln -p- --open {target}
- **Cloud Infrastructure**: nmap -sS -sV -T2 --script "ssl-* or http-security-headers or http-cors or http-git or http-enum" -p 80,443,8080,8443,22 --max-rate 50 {target}
- **SSL/TLS Deep Audit**: nmap --script "ssl-heartbleed or ssl-poodle or ssl-enum-ciphers or ssl-cert or ssl-dh-params" -p 443,8443 {target}`;

  let cloudNote = '';
  if (cloudProvider) {
    cloudNote = `\n### Cloud-Specific Notes (${cloudProvider})
- Cloud security groups are stateful — ACK scans less effective
- Use -T2 with --max-rate 50 to avoid rate limiting
- Check for IMDS at 169.254.169.254 via SSRF
- Look for exposed storage (S3 buckets)
- SSL cert SANs reveal infrastructure scope
- DO NOT use -f (fragmentation) — cloud firewalls DROP fragmented packets`;
  }

  return `## Nmap Expert Knowledge\n\n${evasionTable}\n\n### Technology-Specific Scripts${techContext}\n\n${scanProfiles}${cloudNote}`;
}

function buildCloudSecurityContext(cloudProvider) {
  if (!cloudProvider) return '';
  return `## Cloud Security Intelligence
Known cloud misconfigurations to check:
- S3 bucket public access (list/read/write)
- IMDS v1 without hop limit (SSRF → credential theft)
- Security group allowing 0.0.0.0/0 on management ports
- CloudFront/ALB with permissive CORS
- Exposed .env, .git, /debug, /status endpoints
- IAM role with excessive permissions attached to EC2

Cloud attack paths:
1. SSRF → IMDS → IAM credentials → S3 data exfiltration
2. Exposed .git → source code → hardcoded secrets → lateral movement
3. Public S3 bucket → sensitive data exposure → credential harvesting`;
}

function buildKevContext() {
  return `## CISA Known Exploited Vulnerabilities (KEV) Intelligence
- CVE-2014-6271 (Shellshock): GNU Bash RCE — actively exploited, RANSOMWARE-linked
- CVE-2014-0160 (Heartbleed): OpenSSL memory disclosure — actively exploited
- CVE-2017-0144 (EternalBlue): SMBv1 RCE — RANSOMWARE-linked (WannaCry, NotPetya)
- CVE-2017-5638 (Struts RCE): Apache Struts Content-Type RCE — actively exploited
- CVE-2015-1635 (HTTP.sys): IIS RCE via Range header — actively exploited
- CVE-2012-2122 (MySQL auth bypass): MySQL/MariaDB auth bypass — actively exploited
- CVE-2014-3704 (Drupalgeddon): Drupal SQLi — actively exploited

Rule: Any finding matching a KEV entry MUST be scored CRITICAL regardless of base CVSS.`;
}

function buildBugBountyContext() {
  return `## Bug Bounty Methodology Context
- Always check for IDOR in API endpoints (change user ID in request)
- Test file upload for unrestricted types (.php, .jsp, .aspx)
- Check for rate limiting on authentication endpoints
- Test for SSRF via URL parameters, webhooks, image fetchers
- Check for information disclosure in error messages, stack traces, debug endpoints
- Test for broken access control on admin/management endpoints`;
}

function buildNmapVulnCorrelationContext() {
  return `## Nmap NSE Vulnerability Correlation Guide

### Critical Findings (Immediate Action)
- smb-vuln-ms17-010: VULNERABLE → EternalBlue RCE. Wormable.
- ssl-heartbleed: VULNERABLE → Memory disclosure. Rotate all certs.
- http-vuln-cve2017-5638: VULNERABLE → Struts RCE. Full server compromise.
- http-vuln-cve2015-1635: VULNERABLE → IIS HTTP.sys RCE.

### High Findings
- ssl-enum-ciphers: Grade F → Weak ciphers. MITM possible.
- mysql-vuln-cve2012-2122: VULNERABLE → Auth bypass.
- http-vuln-cve2014-3704: VULNERABLE → Drupalgeddon SQLi.
- ftp-anon: Anonymous login → Data exposure.

### Medium Findings
- http-security-headers: missing HSTS → Downgrade attacks.
- http-cors: wildcard origin → Cross-origin data theft.
- http-git: .git exposed → Source code disclosure.
- http-internal-ip-disclosure → Information leak.

### False Positive Indicators
- http-slowloris-check often reports vulnerable when target has connection limits
- http-sql-injection has high false positive rate — verify manually`;
}

// ─── LLM Call Helper ───────────────────────────────────────────────────────

async function callLLM(messages, responseFormat) {
  const payload = {
    model: 'gemini-2.5-flash',
    messages,
    max_tokens: 16384,
    thinking: { budget_tokens: 128 },
  };
  if (responseFormat) {
    payload.response_format = responseFormat;
  }

  const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${API_KEY}`,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`LLM API error ${response.status}: ${errText.slice(0, 500)}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || '';
}

// ─── Test Functions ────────────────────────────────────────────────────────

async function testScanPlanGeneration() {
  console.log('\n' + '='.repeat(80));
  console.log('TEST 1: SCAN PLAN GENERATION — Tech Detection + Tool Selection + Evasion');
  console.log('='.repeat(80));

  const targets = Object.entries(TARGET_PROFILES);
  const assetSummaries = targets.map(([hostname, profile]) => ({
    hostname,
    ip: profile.ip,
    type: 'web_app',
    status: 'active',
    knownPorts: profile.ports.map(p => `${p.port}/${p.service} (${p.version})`),
    technologies: profile.technologies,
    wafDetected: profile.wafDetected,
    cloudProvider: profile.cloudProvider,
    passiveRiskSignals: profile.passiveRiskSignals,
    htmlHints: profile.htmlHints,
    headers: profile.headers,
  }));

  const allTech = targets.flatMap(([_, p]) => p.technologies);
  const nmapCtx = buildNmapScanPlanContext([...new Set(allTech)], 'AWS');
  const cloudCtx = buildCloudSecurityContext('AWS');
  const kevCtx = buildKevContext();
  const bbCtx = buildBugBountyContext();

  const systemPrompt = `You are an expert penetration tester planning active scanning.

Two-phase approach:
- Phase A: Discovery (nmap + httpx)
- Phase B: Targeted tools per tech stack

Tools: nmap, nuclei, nikto, gobuster, httpx, hydra, whatweb, wpscan, sqlmap, testssl, ffuf, feroxbuster, cloud_enum, s3scanner

### Nmap Evasion Rules
- Cloud targets (AWS/Azure/GCP): DO NOT use -f, -D, --data-length, --source-port. Use '-Pn -sV -sC' only.
- On-premise: Use evasion flags freely (-f, -D RND:3, --source-port 53, -T2)
- Source port 53 is the most effective single evasion flag

### Tech-Specific NSE Scripts
- PHP: http-vuln-cve2012-1823, http-phpself-xss, http-sql-injection, http-enum
- nginx: http-enum, http-methods, http-security-headers, ssl-enum-ciphers
- Apache Tomcat/Java: http-vuln-cve2017-5638, http-default-accounts, rmi-vuln-classloader
- IIS/ASP.NET: http-aspnet-debug, http-iis-webdav-vuln, http-vuln-cve2015-1635
- OpenSSH: ssh2-enum-algos, ssh-auth-methods, ssh-hostkey
- MySQL: mysql-info, mysql-vuln-cve2012-2122

### Cloud Security
- Check for IMDS at 169.254.169.254 via SSRF
- Look for exposed S3 buckets, .git, .env
- Use nuclei -tags cloud,s3,misconfig for cloud targets
- Use cloud_enum for cloud-hosted targets

### KEV Awareness
- CVE-2017-5638 (Struts RCE): CRITICAL, actively exploited
- CVE-2015-1635 (HTTP.sys): CRITICAL, actively exploited
- CVE-2012-2122 (MySQL auth bypass): actively exploited

Respond with JSON matching this schema:
{
  "overallStrategy": "string",
  "assetPlans": [
    {
      "hostname": "string",
      "detectedTechnologies": ["list of detected tech from headers/hints"],
      "discoveryNmapFlags": "nmap flags for Phase A",
      "discoveryNmapRationale": "why these flags",
      "nmapScripts": ["list of NSE scripts for Phase B"],
      "nmapScriptRationale": "why these scripts",
      "activeTools": [
        { "tool": "name", "command": "full command", "rationale": "why" }
      ],
      "evasionProfile": "stealth level and technique",
      "riskNotes": "any concerns"
    }
  ]
}`;

  const result = await callLLM([
    { role: 'system', content: systemPrompt },
    { role: 'user', content: `## Target Assets\n${JSON.stringify(assetSummaries, null, 2)}\n\nGenerate the two-phase scan plan.` },
  ], {
    type: 'json_schema',
    json_schema: {
      name: 'scan_plan_test',
      strict: true,
      schema: {
        type: 'object',
        properties: {
          overallStrategy: { type: 'string' },
          assetPlans: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                hostname: { type: 'string' },
                detectedTechnologies: { type: 'array', items: { type: 'string' } },
                discoveryNmapFlags: { type: 'string' },
                discoveryNmapRationale: { type: 'string' },
                nmapScripts: { type: 'array', items: { type: 'string' } },
                nmapScriptRationale: { type: 'string' },
                activeTools: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      tool: { type: 'string' },
                      command: { type: 'string' },
                      rationale: { type: 'string' },
                    },
                    required: ['tool', 'command', 'rationale'],
                    additionalProperties: false,
                  },
                },
                evasionProfile: { type: 'string' },
                riskNotes: { type: 'string' },
              },
              required: ['hostname', 'detectedTechnologies', 'discoveryNmapFlags', 'discoveryNmapRationale', 'nmapScripts', 'nmapScriptRationale', 'activeTools', 'evasionProfile', 'riskNotes'],
              additionalProperties: false,
            },
          },
        },
        required: ['overallStrategy', 'assetPlans'],
        additionalProperties: false,
      },
    },
  });

  const plan = JSON.parse(result);
  
  // ── Scoring ──
  const scores = { techDetection: 0, toolSelection: 0, evasion: 0, cloud: 0, nseScripts: 0, total: 0 };
  const maxScores = { techDetection: 20, toolSelection: 25, evasion: 20, cloud: 15, nseScripts: 20, total: 100 };
  const details = [];

  for (const ap of plan.assetPlans) {
    const profile = TARGET_PROFILES[ap.hostname];
    if (!profile) continue;

    // Tech detection scoring
    const expectedTech = profile.technologies;
    const detectedTech = ap.detectedTechnologies || [];
    const techHits = expectedTech.filter(t => detectedTech.some(d => d.toLowerCase().includes(t.toLowerCase())));
    const techScore = Math.min(5, (techHits.length / expectedTech.length) * 5);
    scores.techDetection += techScore;
    details.push(`  ${ap.hostname}: Detected ${techHits.length}/${expectedTech.length} techs (${techHits.join(', ')})`);

    // Tool selection scoring
    const tools = ap.activeTools.map(t => t.tool);
    let toolScore = 0;
    if (profile.technologies.includes('PHP') && tools.some(t => ['nuclei', 'sqlmap', 'nikto'].includes(t))) toolScore += 2;
    if (profile.technologies.includes('Apache Tomcat') && tools.some(t => ['nuclei', 'nikto'].includes(t))) toolScore += 2;
    if (profile.technologies.includes('IIS') && tools.some(t => ['nuclei', 'nikto'].includes(t))) toolScore += 2;
    if (tools.includes('httpx')) toolScore += 1;
    if (tools.includes('whatweb')) toolScore += 1;
    if (tools.includes('testssl')) toolScore += 0.5;
    scores.toolSelection += Math.min(6.25, toolScore);
    details.push(`  ${ap.hostname}: Selected tools: ${tools.join(', ')} (score: ${toolScore})`);

    // Evasion scoring
    const flags = ap.discoveryNmapFlags || '';
    let evasionScore = 0;
    if (profile.cloudProvider === 'AWS') {
      // Cloud target: should NOT use fragmentation/decoys
      if (!flags.includes('-f') && !flags.includes('--data-length') && !flags.includes('-D RND')) evasionScore += 3;
      if (flags.includes('-Pn')) evasionScore += 1;
      if (flags.includes('-sV')) evasionScore += 1;
    } else {
      // Non-cloud: evasion is appropriate
      if (flags.includes('-Pn')) evasionScore += 1;
      if (flags.includes('-sV') || flags.includes('-sC')) evasionScore += 1;
      if (flags.includes('-T2') || flags.includes('-T3')) evasionScore += 1;
    }
    scores.evasion += Math.min(5, evasionScore);
    details.push(`  ${ap.hostname}: Evasion flags: ${flags} (score: ${evasionScore})`);

    // Cloud awareness scoring
    if (profile.cloudProvider === 'AWS') {
      let cloudScore = 0;
      const allText = JSON.stringify(ap).toLowerCase();
      if (allText.includes('cloud') || allText.includes('aws') || allText.includes('s3')) cloudScore += 2;
      if (allText.includes('imds') || allText.includes('metadata') || allText.includes('169.254')) cloudScore += 2;
      if (tools.some(t => ['cloud_enum', 's3scanner'].includes(t))) cloudScore += 3;
      scores.cloud += Math.min(7.5, cloudScore);
      details.push(`  ${ap.hostname}: Cloud awareness score: ${cloudScore}`);
    }

    // NSE script scoring
    const scripts = ap.nmapScripts || [];
    let nseScore = 0;
    if (profile.technologies.includes('PHP') && scripts.some(s => s.includes('php') || s.includes('sql-injection'))) nseScore += 2;
    if (profile.technologies.includes('Apache Tomcat') && scripts.some(s => s.includes('struts') || s.includes('default-accounts'))) nseScore += 2;
    if (profile.technologies.includes('IIS') && scripts.some(s => s.includes('iis') || s.includes('aspnet'))) nseScore += 2;
    if (scripts.some(s => s.includes('ssl-') || s.includes('http-security'))) nseScore += 1;
    if (scripts.some(s => s.includes('http-enum') || s.includes('http-git'))) nseScore += 1;
    scores.nseScripts += Math.min(5, nseScore);
    details.push(`  ${ap.hostname}: NSE scripts: ${scripts.join(', ')} (score: ${nseScore})`);
  }

  scores.total = scores.techDetection + scores.toolSelection + scores.evasion + scores.cloud + scores.nseScripts;

  console.log('\n📊 SCAN PLAN GENERATION RESULTS:');
  console.log(`  Overall Strategy: ${plan.overallStrategy?.slice(0, 200)}`);
  console.log('\n  Per-Asset Details:');
  details.forEach(d => console.log(d));
  console.log('\n  SCORES:');
  console.log(`  Tech Detection:  ${scores.techDetection.toFixed(1)}/${maxScores.techDetection} ${scores.techDetection >= 15 ? '✅' : '⚠️'}`);
  console.log(`  Tool Selection:  ${scores.toolSelection.toFixed(1)}/${maxScores.toolSelection} ${scores.toolSelection >= 18 ? '✅' : '⚠️'}`);
  console.log(`  Evasion:         ${scores.evasion.toFixed(1)}/${maxScores.evasion} ${scores.evasion >= 14 ? '✅' : '⚠️'}`);
  console.log(`  Cloud Awareness: ${scores.cloud.toFixed(1)}/${maxScores.cloud} ${scores.cloud >= 10 ? '✅' : '⚠️'}`);
  console.log(`  NSE Scripts:     ${scores.nseScripts.toFixed(1)}/${maxScores.nseScripts} ${scores.nseScripts >= 14 ? '✅' : '⚠️'}`);
  console.log(`  ────────────────────────────`);
  console.log(`  TOTAL:           ${scores.total.toFixed(1)}/${maxScores.total} ${scores.total >= 70 ? '✅ PASS' : '⚠️ NEEDS IMPROVEMENT'}`);

  return { test: 'Scan Plan Generation', scores, maxScores, plan };
}

async function testVulnCorrelation() {
  console.log('\n' + '='.repeat(80));
  console.log('TEST 2: VULNERABILITY CORRELATION — KEV + Cloud + CVSS + NSE Findings');
  console.log('='.repeat(80));

  const nmapVulnCtx = buildNmapVulnCorrelationContext();
  const kevCtx = buildKevContext();
  const cloudCtx = buildCloudSecurityContext('AWS');

  // Simulated scan findings from the test targets
  const scanFindings = [
    { target: 'testphp.vulnweb.com', tool: 'nmap', finding: 'http-sql-injection: Possible SQL injection in /search.php?q=test', severity: 'unknown' },
    { target: 'testphp.vulnweb.com', tool: 'nmap', finding: 'http-phpself-xss: Reflected XSS via PHP_SELF in /guestbook.php', severity: 'unknown' },
    { target: 'testphp.vulnweb.com', tool: 'nmap', finding: 'http-enum: /phpmyadmin/ found', severity: 'unknown' },
    { target: 'testphp.vulnweb.com', tool: 'nmap', finding: 'http-git: .git repository found at /.git/', severity: 'unknown' },
    { target: 'testphp.vulnweb.com', tool: 'nmap', finding: 'http-security-headers: Missing HSTS, CSP, X-Frame-Options', severity: 'unknown' },
    { target: 'testphp.vulnweb.com', tool: 'nmap', finding: 'ssl-enum-ciphers: Grade C — TLS 1.0 supported with weak ciphers', severity: 'unknown' },
    { target: 'demo.testfire.net', tool: 'nmap', finding: 'http-vuln-cve2017-5638: VULNERABLE — Apache Struts RCE', severity: 'unknown' },
    { target: 'demo.testfire.net', tool: 'nmap', finding: 'http-default-accounts: Tomcat manager accessible with tomcat:tomcat', severity: 'unknown' },
    { target: 'demo.testfire.net', tool: 'nmap', finding: 'http-cookie-flags: JSESSIONID missing secure and httponly flags', severity: 'unknown' },
    { target: 'scanme.nmap.org', tool: 'nmap', finding: 'ssh2-enum-algos: Weak key exchange algorithms (diffie-hellman-group1-sha1)', severity: 'unknown' },
    { target: 'scanme.nmap.org', tool: 'nmap', finding: 'http-slowloris-check: VULNERABLE — potential DoS', severity: 'unknown' },
    { target: 'testasp.vulnweb.com', tool: 'nmap', finding: 'http-aspnet-debug: ASP.NET debug mode enabled', severity: 'unknown' },
    { target: 'testasp.vulnweb.com', tool: 'nmap', finding: 'http-iis-webdav-vuln: WebDAV authentication bypass possible', severity: 'unknown' },
    { target: 'testasp.vulnweb.com', tool: 'nmap', finding: 'http-vuln-cve2015-1635: VULNERABLE — IIS HTTP.sys RCE', severity: 'unknown' },
  ];

  const result = await callLLM([
    { role: 'system', content: `You are an expert vulnerability analyst correlating scan findings with known vulnerability databases and threat intelligence.

${nmapVulnCtx}

${kevCtx}

${cloudCtx}

For each finding, determine:
1. The correct severity (critical/high/medium/low/info)
2. Whether it matches a KEV entry (actively exploited)
3. Whether it's a likely false positive
4. The recommended remediation priority
5. CVSS score estimate

Respond with JSON.` },
    { role: 'user', content: `Correlate these scan findings:\n${JSON.stringify(scanFindings, null, 2)}` },
  ], {
    type: 'json_schema',
    json_schema: {
      name: 'vuln_correlation_test',
      strict: true,
      schema: {
        type: 'object',
        properties: {
          correlations: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                target: { type: 'string' },
                finding: { type: 'string' },
                assignedSeverity: { type: 'string' },
                cvssEstimate: { type: 'number' },
                kevMatch: { type: 'boolean' },
                isFalsePositive: { type: 'boolean' },
                falsePositiveReason: { type: 'string' },
                remediationPriority: { type: 'integer' },
                reasoning: { type: 'string' },
              },
              required: ['target', 'finding', 'assignedSeverity', 'cvssEstimate', 'kevMatch', 'isFalsePositive', 'falsePositiveReason', 'remediationPriority', 'reasoning'],
              additionalProperties: false,
            },
          },
        },
        required: ['correlations'],
        additionalProperties: false,
      },
    },
  });

  const corr = JSON.parse(result);

  // Scoring
  const scores = { severityAccuracy: 0, kevDetection: 0, falsePositive: 0, total: 0 };
  const maxScores = { severityAccuracy: 40, kevDetection: 30, falsePositive: 30, total: 100 };

  const expectedSeverities = {
    'http-vuln-cve2017-5638': 'critical',
    'http-vuln-cve2015-1635': 'critical',
    'http-default-accounts': 'high',
    'http-iis-webdav-vuln': 'high',
    'http-sql-injection': 'high',
    'http-git': 'medium',
    'http-security-headers': 'medium',
    'http-aspnet-debug': 'medium',
    'ssl-enum-ciphers': 'medium',
    'http-phpself-xss': 'medium',
    'http-cookie-flags': 'medium',
    'ssh2-enum-algos': 'medium',
    'http-slowloris-check': 'low',
    'http-enum': 'low',
  };

  const expectedKev = ['http-vuln-cve2017-5638', 'http-vuln-cve2015-1635'];
  const expectedFP = ['http-slowloris-check'];

  for (const c of corr.correlations) {
    // Severity accuracy
    for (const [key, expected] of Object.entries(expectedSeverities)) {
      if (c.finding.includes(key)) {
        if (c.assignedSeverity.toLowerCase() === expected) scores.severityAccuracy += (40 / 14);
        else if (['critical', 'high'].includes(expected) && ['critical', 'high'].includes(c.assignedSeverity.toLowerCase())) scores.severityAccuracy += (20 / 14);
      }
    }

    // KEV detection
    for (const kevKey of expectedKev) {
      if (c.finding.includes(kevKey) && c.kevMatch) scores.kevDetection += 15;
    }

    // False positive detection
    for (const fpKey of expectedFP) {
      if (c.finding.includes(fpKey) && c.isFalsePositive) scores.falsePositive += 30;
    }
  }

  scores.total = Math.min(100, scores.severityAccuracy + scores.kevDetection + scores.falsePositive);

  console.log('\n📊 VULNERABILITY CORRELATION RESULTS:');
  console.log(`  Total findings correlated: ${corr.correlations.length}`);
  for (const c of corr.correlations) {
    console.log(`  ${c.target}: ${c.finding.slice(0, 50)}... → ${c.assignedSeverity} (CVSS ${c.cvssEstimate}) ${c.kevMatch ? '[KEV]' : ''} ${c.isFalsePositive ? '[FP]' : ''}`);
  }
  console.log('\n  SCORES:');
  console.log(`  Severity Accuracy: ${scores.severityAccuracy.toFixed(1)}/${maxScores.severityAccuracy} ${scores.severityAccuracy >= 28 ? '✅' : '⚠️'}`);
  console.log(`  KEV Detection:     ${scores.kevDetection.toFixed(1)}/${maxScores.kevDetection} ${scores.kevDetection >= 20 ? '✅' : '⚠️'}`);
  console.log(`  False Positive:    ${scores.falsePositive.toFixed(1)}/${maxScores.falsePositive} ${scores.falsePositive >= 20 ? '✅' : '⚠️'}`);
  console.log(`  ────────────────────────────`);
  console.log(`  TOTAL:             ${scores.total.toFixed(1)}/${maxScores.total} ${scores.total >= 70 ? '✅ PASS' : '⚠️ NEEDS IMPROVEMENT'}`);

  return { test: 'Vuln Correlation', scores, maxScores, correlations: corr };
}

async function testHuntHypotheses() {
  console.log('\n' + '='.repeat(80));
  console.log('TEST 3: HUNT HYPOTHESIS GENERATION — Attack Paths + MITRE + Nmap Context');
  console.log('='.repeat(80));

  const result = await callLLM([
    { role: 'system', content: `You are an elite threat hunter. Generate testable hypotheses based on the scan findings.

## Nmap-Based Threat Hunting Context

| Finding | MITRE Technique | Hunt Hypothesis |
|---------|----------------|-----------------|
| Exposed .git | T1213 (Data from Information Repositories) | Adversary may extract credentials from git history |
| Weak SSL ciphers | T1557 (Adversary-in-the-Middle) | Adversary may perform TLS downgrade for interception |
| Docker API exposed | T1610 (Deploy Container) | Adversary may deploy malicious containers |
| IMDS accessible | T1552 (Unsecured Credentials: Cloud Instance Metadata) | Adversary may steal cloud credentials via SSRF |
| Default credentials | T1078 (Valid Accounts) | Adversary may use default creds for initial access |
| PHP/ASP debug mode | T1190 (Exploit Public-Facing Application) | Adversary may exploit debug endpoints for RCE |

${buildKevContext()}
${buildCloudSecurityContext('AWS')}

Respond with JSON.` },
    { role: 'user', content: `Generate 6 hunt hypotheses for these findings:
- testphp.vulnweb.com: PHP 5.6 EOL, SQL injection in /search.php, exposed .git, phpMyAdmin exposed, AWS-hosted
- demo.testfire.net: Tomcat with default creds, Struts RCE (CVE-2017-5638), banking app
- scanme.nmap.org: Outdated OpenSSH 6.6.1, weak SSH algorithms, port 31337 open
- testasp.vulnweb.com: IIS with debug mode, WebDAV bypass, HTTP.sys RCE (CVE-2015-1635), AWS-hosted

Organization: Security Testing Corp, Sector: Technology
SIEM: Splunk, Data Sources: Windows Event Log, Sysmon, Network Flow, Web Access Logs` },
  ], {
    type: 'json_schema',
    json_schema: {
      name: 'hunt_hypotheses_test',
      strict: true,
      schema: {
        type: 'object',
        properties: {
          hypotheses: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                statement: { type: 'string' },
                mitreTechniqueId: { type: 'string' },
                mitreTechniqueName: { type: 'string' },
                mitreTactic: { type: 'string' },
                confidence: { type: 'string' },
                priority: { type: 'integer' },
                splQuery: { type: 'string' },
                reasoning: { type: 'string' },
              },
              required: ['statement', 'mitreTechniqueId', 'mitreTechniqueName', 'mitreTactic', 'confidence', 'priority', 'splQuery', 'reasoning'],
              additionalProperties: false,
            },
          },
        },
        required: ['hypotheses'],
        additionalProperties: false,
      },
    },
  });

  const hunt = JSON.parse(result);

  // Scoring
  const scores = { mitreMapping: 0, queryQuality: 0, attackPaths: 0, total: 0 };
  const maxScores = { mitreMapping: 35, queryQuality: 35, attackPaths: 30, total: 100 };

  for (const h of hunt.hypotheses) {
    // MITRE mapping quality
    if (h.mitreTechniqueId && h.mitreTechniqueId.match(/^T\d{4}/)) scores.mitreMapping += (35 / 6);
    // Query quality
    if (h.splQuery && h.splQuery.length > 30 && h.splQuery.includes('index=')) scores.queryQuality += (35 / 6);
    // Attack path reasoning
    if (h.reasoning && h.reasoning.length > 50) scores.attackPaths += (30 / 6);
  }

  scores.total = scores.mitreMapping + scores.queryQuality + scores.attackPaths;

  console.log('\n📊 HUNT HYPOTHESIS RESULTS:');
  for (const h of hunt.hypotheses) {
    console.log(`  [P${h.priority}] ${h.mitreTechniqueId} (${h.mitreTactic}): ${h.statement.slice(0, 100)}`);
    console.log(`       SPL: ${h.splQuery.slice(0, 100)}...`);
  }
  console.log('\n  SCORES:');
  console.log(`  MITRE Mapping:  ${scores.mitreMapping.toFixed(1)}/${maxScores.mitreMapping} ${scores.mitreMapping >= 25 ? '✅' : '⚠️'}`);
  console.log(`  Query Quality:  ${scores.queryQuality.toFixed(1)}/${maxScores.queryQuality} ${scores.queryQuality >= 25 ? '✅' : '⚠️'}`);
  console.log(`  Attack Paths:   ${scores.attackPaths.toFixed(1)}/${maxScores.attackPaths} ${scores.attackPaths >= 20 ? '✅' : '⚠️'}`);
  console.log(`  ────────────────────────────`);
  console.log(`  TOTAL:           ${scores.total.toFixed(1)}/${maxScores.total} ${scores.total >= 70 ? '✅ PASS' : '⚠️ NEEDS IMPROVEMENT'}`);

  return { test: 'Hunt Hypotheses', scores, maxScores, hypotheses: hunt };
}

async function testAssetClassification() {
  console.log('\n' + '='.repeat(80));
  console.log('TEST 4: ASSET CLASSIFICATION — CARVER + Cloud Risk + Tech Stack Analysis');
  console.log('='.repeat(80));

  const result = await callLLM([
    { role: 'system', content: `You are an expert asset classifier using the CARVER methodology (Criticality, Accessibility, Recuperability, Vulnerability, Effect, Recognizability).

${buildCloudSecurityContext('AWS')}
${buildKevContext()}
${buildNmapVulnCorrelationContext()}

Score each asset 1-10 on each CARVER dimension. Also identify the primary attack vector and estimated time-to-compromise.

Respond with JSON.` },
    { role: 'user', content: `Classify these assets. For AWS-hosted targets, you MUST identify cloud-specific risk factors (IMDS exposure, S3 bucket risks, security group misconfigurations, IAM role risks, etc.).

1. testphp.vulnweb.com (CLOUD: AWS EC2, IP 44.228.249.3)
   - PHP 5.6 EOL, nginx 1.19, MySQL
   - SQL injection confirmed → potential SSRF to IMDS (169.254.169.254)
   - .git exposed → may contain AWS credentials
   - phpMyAdmin exposed
   - No WAF, no rate limiting
   - Cloud risks: EC2 instance may have IMDSv1, attached IAM role, S3 access

2. demo.testfire.net (On-premise, IP 65.61.137.117)
   - Tomcat with default creds (tomcat:tomcat), Struts RCE (CVE-2017-5638)
   - Banking application with fund transfer
   - JSESSIONID without secure/httponly flags

3. scanme.nmap.org (On-premise, IP 45.33.32.156)
   - OpenSSH 6.6.1 (2014), Apache 2.4.7
   - Port 31337 open, weak SSH algorithms
   - Authorized test host

4. testasp.vulnweb.com (CLOUD: AWS EC2, IP 44.228.249.3)
   - IIS 10.0, ASP.NET 4.0, MSSQL
   - Debug mode enabled → may leak cloud config
   - WebDAV bypass, HTTP.sys RCE (CVE-2015-1635)
   - Cloud risks: Same EC2 as testphp, potential lateral movement, IMDS access
   - No WAF` },
  ], {
    type: 'json_schema',
    json_schema: {
      name: 'asset_classification_test',
      strict: true,
      schema: {
        type: 'object',
        properties: {
          classifications: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                hostname: { type: 'string' },
                carverScores: {
                  type: 'object',
                  properties: {
                    criticality: { type: 'integer' },
                    accessibility: { type: 'integer' },
                    recuperability: { type: 'integer' },
                    vulnerability: { type: 'integer' },
                    effect: { type: 'integer' },
                    recognizability: { type: 'integer' },
                  },
                  required: ['criticality', 'accessibility', 'recuperability', 'vulnerability', 'effect', 'recognizability'],
                  additionalProperties: false,
                },
                totalCarverScore: { type: 'integer' },
                primaryAttackVector: { type: 'string' },
                estimatedTimeToCompromise: { type: 'string' },
                cloudRiskFactors: { type: 'array', items: { type: 'string' } },
                kevExposure: { type: 'array', items: { type: 'string' } },
                reasoning: { type: 'string' },
              },
              required: ['hostname', 'carverScores', 'totalCarverScore', 'primaryAttackVector', 'estimatedTimeToCompromise', 'cloudRiskFactors', 'kevExposure', 'reasoning'],
              additionalProperties: false,
            },
          },
        },
        required: ['classifications'],
        additionalProperties: false,
      },
    },
  });

  const cls = JSON.parse(result);

  // Scoring
  const scores = { carverQuality: 0, attackVector: 0, cloudRisk: 0, kevAwareness: 0, total: 0 };
  const maxScores = { carverQuality: 30, attackVector: 25, cloudRisk: 20, kevAwareness: 25, total: 100 };

  for (const c of cls.classifications) {
    // CARVER quality — scores should be reasonable (not all 10s or all 1s)
    const carverValues = Object.values(c.carverScores);
    const hasVariance = new Set(carverValues).size >= 3;
    const inRange = carverValues.every(v => v >= 1 && v <= 10);
    if (hasVariance && inRange) scores.carverQuality += (30 / 4);

    // Attack vector identification
    if (c.primaryAttackVector && c.primaryAttackVector.length > 10) scores.attackVector += (25 / 4);

    // Cloud risk factors
    if (c.hostname.includes('vulnweb') && c.cloudRiskFactors.length > 0) scores.cloudRisk += (20 / 2);

    // KEV awareness
    if (c.kevExposure.length > 0) scores.kevAwareness += (25 / 4);
  }

  scores.total = scores.carverQuality + scores.attackVector + scores.cloudRisk + scores.kevAwareness;

  console.log('\n📊 ASSET CLASSIFICATION RESULTS:');
  for (const c of cls.classifications) {
    const cv = c.carverScores;
    console.log(`  ${c.hostname}: CARVER=${c.totalCarverScore} (C:${cv.criticality} A:${cv.accessibility} R:${cv.recuperability} V:${cv.vulnerability} E:${cv.effect} R:${cv.recognizability})`);
    console.log(`    Attack: ${c.primaryAttackVector.slice(0, 80)}`);
    console.log(`    Time: ${c.estimatedTimeToCompromise}`);
    console.log(`    Cloud: ${c.cloudRiskFactors.join(', ') || 'N/A'}`);
    console.log(`    KEV: ${c.kevExposure.join(', ') || 'none'}`);
  }
  console.log('\n  SCORES:');
  console.log(`  CARVER Quality:  ${scores.carverQuality.toFixed(1)}/${maxScores.carverQuality} ${scores.carverQuality >= 22 ? '✅' : '⚠️'}`);
  console.log(`  Attack Vector:   ${scores.attackVector.toFixed(1)}/${maxScores.attackVector} ${scores.attackVector >= 18 ? '✅' : '⚠️'}`);
  console.log(`  Cloud Risk:      ${scores.cloudRisk.toFixed(1)}/${maxScores.cloudRisk} ${scores.cloudRisk >= 14 ? '✅' : '⚠️'}`);
  console.log(`  KEV Awareness:   ${scores.kevAwareness.toFixed(1)}/${maxScores.kevAwareness} ${scores.kevAwareness >= 18 ? '✅' : '⚠️'}`);
  console.log(`  ────────────────────────────`);
  console.log(`  TOTAL:           ${scores.total.toFixed(1)}/${maxScores.total} ${scores.total >= 70 ? '✅ PASS' : '⚠️ NEEDS IMPROVEMENT'}`);

  return { test: 'Asset Classification', scores, maxScores, classifications: cls };
}

// ─── Main Runner ───────────────────────────────────────────────────────────

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════════════════════╗');
  console.log('║  CALDERA LLM KNOWLEDGE STACK — COMPREHENSIVE TEST SUITE                     ║');
  console.log('║  Testing: Nmap Evasion + NSE Scripts + Cloud Security + KEV + Bug Bounty    ║');
  console.log('║  Targets: testphp.vulnweb.com, demo.testfire.net, scanme.nmap.org,          ║');
  console.log('║           testasp.vulnweb.com                                               ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════╝');

  const results = [];

  try {
    console.log('\n🚀 Starting Test 1/4: Scan Plan Generation...');
    results.push(await testScanPlanGeneration());
  } catch (e) {
    console.error('❌ Test 1 failed:', e.message);
    results.push({ test: 'Scan Plan Generation', scores: { total: 0 }, maxScores: { total: 100 }, error: e.message });
  }

  try {
    console.log('\n🚀 Starting Test 2/4: Vulnerability Correlation...');
    results.push(await testVulnCorrelation());
  } catch (e) {
    console.error('❌ Test 2 failed:', e.message);
    results.push({ test: 'Vuln Correlation', scores: { total: 0 }, maxScores: { total: 100 }, error: e.message });
  }

  try {
    console.log('\n🚀 Starting Test 3/4: Hunt Hypothesis Generation...');
    results.push(await testHuntHypotheses());
  } catch (e) {
    console.error('❌ Test 3 failed:', e.message);
    results.push({ test: 'Hunt Hypotheses', scores: { total: 0 }, maxScores: { total: 100 }, error: e.message });
  }

  try {
    console.log('\n🚀 Starting Test 4/4: Asset Classification...');
    results.push(await testAssetClassification());
  } catch (e) {
    console.error('❌ Test 4 failed:', e.message);
    results.push({ test: 'Asset Classification', scores: { total: 0 }, maxScores: { total: 100 }, error: e.message });
  }

  // ── Final Summary ──
  console.log('\n' + '═'.repeat(80));
  console.log('FINAL RESULTS SUMMARY');
  console.log('═'.repeat(80));

  let grandTotal = 0;
  let grandMax = 0;
  for (const r of results) {
    const pct = (r.scores.total / r.maxScores.total * 100).toFixed(0);
    const status = r.scores.total >= r.maxScores.total * 0.7 ? '✅ PASS' : '⚠️ NEEDS WORK';
    console.log(`  ${r.test.padEnd(25)} ${r.scores.total.toFixed(1).padStart(6)}/${r.maxScores.total} (${pct}%) ${status}`);
    grandTotal += r.scores.total;
    grandMax += r.maxScores.total;
  }

  const grandPct = (grandTotal / grandMax * 100).toFixed(0);
  console.log('  ' + '─'.repeat(60));
  console.log(`  ${'OVERALL'.padEnd(25)} ${grandTotal.toFixed(1).padStart(6)}/${grandMax} (${grandPct}%) ${grandTotal >= grandMax * 0.7 ? '✅ PASS' : '⚠️ NEEDS IMPROVEMENT'}`);
  console.log('\n' + '═'.repeat(80));

  // Write results to file
  const fs = await import('fs');
  fs.writeFileSync('/home/ubuntu/caldera-dashboard/llm-test-results.json', JSON.stringify(results, null, 2));
  console.log('\nDetailed results saved to llm-test-results.json');
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
