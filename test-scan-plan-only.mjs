#!/usr/bin/env node
/**
 * test-scan-plan-only.mjs — Focused Scan Plan Generation Test
 * Smaller prompt to avoid API 403 errors.
 */

const API_URL = process.env.BUILT_IN_FORGE_API_URL?.replace(/\/$/, '') + '/v1/chat/completions';
const API_KEY = process.env.BUILT_IN_FORGE_API_KEY;

async function callLLM(messages, responseFormat) {
  const payload = {
    model: 'gemini-2.5-flash',
    messages,
    max_tokens: 8192,
    thinking: { budget_tokens: 128 },
  };
  if (responseFormat) payload.response_format = responseFormat;

  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'authorization': `Bearer ${API_KEY}` },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`LLM API error ${response.status}: ${errText.slice(0, 300)}`);
  }
  const data = await response.json();
  return data.choices?.[0]?.message?.content || '';
}

async function main() {
  console.log('TEST: SCAN PLAN GENERATION — Tech Detection + Tool Selection + Evasion + NSE Scripts');
  console.log('='.repeat(80));

  // Test with 2 targets to keep prompt small
  const result = await callLLM([
    { role: 'system', content: `You are an expert pentester planning nmap scans. For each target, select:
1. Discovery nmap flags (Phase A)
2. NSE scripts for Phase B
3. Additional tools (nuclei, nikto, etc.)

Nmap evasion rules:
- Cloud (AWS): NO -f, -D, --data-length, --source-port. Use '-Pn -sV -sC'.
- On-premise: Use evasion freely (-f, -D RND:3, --source-port 53, -T2).

Tech-specific NSE scripts:
- PHP: http-vuln-cve2012-1823, http-phpself-xss, http-sql-injection, http-enum
- Apache Tomcat: http-vuln-cve2017-5638, http-default-accounts
- IIS/ASP.NET: http-aspnet-debug, http-iis-webdav-vuln, http-vuln-cve2015-1635
- OpenSSH: ssh2-enum-algos, ssh-auth-methods
- All web: http-security-headers, ssl-enum-ciphers, http-git, http-cors

Cloud targets: You MUST include cloud_enum and s3scanner in activeTools for any AWS/Azure/GCP target. Also add nuclei -tags cloud,s3,misconfig.
KEV: CVE-2017-5638 (Struts), CVE-2015-1635 (HTTP.sys) are actively exploited.

OWASP Top 10:2025 Coverage Rules:
- A01 Broken Access Control: Test auth bypass, IDOR, path traversal (feroxbuster, nuclei -tags idor)
- A03 Injection: Test SQLi, XSS, SSTI, command injection (sqlmap, nuclei -tags sqli,xss,ssti)
- A05 Security Misconfiguration: Test default creds, debug endpoints, exposed admin (nuclei -tags misconfig,default-login)
- A06 Vulnerable Components: Check versions against KEV catalog
- A08 Integrity Failures: Test deserialization (ysoserial for Java targets)
- A10 SSRF: Test IMDS access on cloud targets (nuclei -tags ssrf)

For EVERY target, ensure at least 3 OWASP categories are covered by the selected tools.

Respond with JSON.` },
    { role: 'user', content: `Plan scans for:

1. testphp.vulnweb.com (AWS, 44.228.249.3)
   Headers: Server: nginx/1.19.0, X-Powered-By: PHP/5.6.40
   Tech: PHP, nginx, MySQL, Ubuntu
   Findings: SQL injection in /search.php, .git exposed, phpMyAdmin found

2. demo.testfire.net (On-premise, 65.61.137.117)
   Headers: Server: Apache-Coyote/1.1, Set-Cookie: JSESSIONID
   Tech: Apache Tomcat, Java, JSP
   Findings: Banking app, fund transfer, default creds suspected

3. scanme.nmap.org (On-premise, 45.33.32.156)
   Ports: 22/ssh (OpenSSH 6.6.1), 80/http (Apache 2.4.7), 9929/nping-echo, 31337/tcpwrapped
   Tech: Apache, Ubuntu, OpenSSH

4. testasp.vulnweb.com (AWS, 44.228.249.3)
   Headers: Server: Microsoft-IIS/10.0, X-Powered-By: ASP.NET
   Tech: IIS, ASP.NET, MSSQL, Windows Server
   Findings: Debug mode enabled, WebDAV accessible` }
  ], {
    type: 'json_schema',
    json_schema: {
      name: 'scan_plan',
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

  console.log(`\nOverall Strategy: ${plan.overallStrategy}\n`);

  const TARGET_PROFILES = {
    'testphp.vulnweb.com': { technologies: ['nginx', 'PHP', 'MySQL', 'Ubuntu'], cloudProvider: 'AWS' },
    'demo.testfire.net': { technologies: ['Apache Tomcat', 'Java', 'JSP'], cloudProvider: null },
    'scanme.nmap.org': { technologies: ['Apache', 'Ubuntu', 'OpenSSH'], cloudProvider: null },
    'testasp.vulnweb.com': { technologies: ['IIS', 'ASP.NET', 'MSSQL', 'Windows Server'], cloudProvider: 'AWS' },
  };

  let totalScore = 0;
  const maxScore = 100;

  for (const ap of plan.assetPlans) {
    const profile = TARGET_PROFILES[ap.hostname];
    if (!profile) continue;

    console.log(`─── ${ap.hostname} ───`);
    console.log(`  Detected Tech: ${(ap.detectedTechnologies || []).join(', ')}`);
    console.log(`  Discovery Flags: ${ap.discoveryNmapFlags}`);
    console.log(`  Rationale: ${ap.discoveryNmapRationale?.slice(0, 120)}`);
    console.log(`  NSE Scripts: ${(ap.nmapScripts || []).join(', ')}`);
    console.log(`  Tools: ${(ap.activeTools || []).map(t => t.tool).join(', ')}`);
    console.log(`  Evasion: ${ap.evasionProfile}`);
    console.log(`  Risk: ${ap.riskNotes?.slice(0, 100)}`);
    console.log('');

    let assetScore = 0;

    // Tech detection (5 pts per target)
    const expectedTech = profile.technologies;
    const detectedTech = ap.detectedTechnologies || [];
    const techHits = expectedTech.filter(t => detectedTech.some(d => d.toLowerCase().includes(t.toLowerCase())));
    const techPct = techHits.length / expectedTech.length;
    assetScore += techPct * 5;
    console.log(`  [Tech] ${techHits.length}/${expectedTech.length} detected (${(techPct * 100).toFixed(0)}%) → ${(techPct * 5).toFixed(1)}/5`);

    // Evasion correctness (5 pts per target)
    const flags = ap.discoveryNmapFlags || '';
    let evasionScore = 0;
    if (profile.cloudProvider === 'AWS') {
      if (!flags.includes('-f') && !flags.includes('-D') && !flags.includes('--data-length') && !flags.includes('--source-port')) evasionScore += 3;
      if (flags.includes('-Pn')) evasionScore += 1;
      if (flags.includes('-sV') || flags.includes('-sC')) evasionScore += 1;
    } else {
      if (flags.includes('-Pn') || flags.includes('-sS')) evasionScore += 1;
      if (flags.includes('-sV') || flags.includes('-sC')) evasionScore += 1;
      // On-premise can use evasion — bonus if they do
      if (flags.includes('-f') || flags.includes('-D') || flags.includes('--source-port') || flags.includes('-T2')) evasionScore += 3;
      else evasionScore += 1; // Still OK not to use evasion
    }
    assetScore += evasionScore;
    console.log(`  [Evasion] Score: ${evasionScore}/5 ${profile.cloudProvider ? '(cloud: no -f/-D)' : '(on-prem: evasion OK)'}`);

    // NSE script selection (5 pts per target)
    const scripts = ap.nmapScripts || [];
    let nseScore = 0;
    if (ap.hostname === 'testphp.vulnweb.com') {
      if (scripts.some(s => s.includes('php') || s.includes('sql-injection'))) nseScore += 2;
      if (scripts.some(s => s.includes('http-enum') || s.includes('http-git'))) nseScore += 2;
      if (scripts.some(s => s.includes('ssl-') || s.includes('security-headers'))) nseScore += 1;
    } else if (ap.hostname === 'demo.testfire.net') {
      if (scripts.some(s => s.includes('struts') || s.includes('cve2017-5638'))) nseScore += 2;
      if (scripts.some(s => s.includes('default-accounts'))) nseScore += 2;
      if (scripts.some(s => s.includes('http-enum') || s.includes('http-methods'))) nseScore += 1;
    } else if (ap.hostname === 'scanme.nmap.org') {
      if (scripts.some(s => s.includes('ssh'))) nseScore += 2;
      if (scripts.some(s => s.includes('http-') || s.includes('ssl-'))) nseScore += 2;
      if (scripts.length >= 2) nseScore += 1;
    } else if (ap.hostname === 'testasp.vulnweb.com') {
      if (scripts.some(s => s.includes('aspnet') || s.includes('iis'))) nseScore += 2;
      if (scripts.some(s => s.includes('webdav') || s.includes('cve2015-1635'))) nseScore += 2;
      if (scripts.some(s => s.includes('http-enum') || s.includes('http-methods'))) nseScore += 1;
    }
    assetScore += nseScore;
    console.log(`  [NSE] Score: ${nseScore}/5`);

    // Tool selection (5 pts per target)
    const tools = (ap.activeTools || []).map(t => t.tool);
    let toolScore = 0;
    if (tools.some(t => ['nuclei', 'nikto'].includes(t))) toolScore += 2;
    if (tools.includes('httpx') || tools.includes('whatweb')) toolScore += 1;
    if (profile.cloudProvider && tools.some(t => ['cloud_enum', 's3scanner'].includes(t))) toolScore += 2;
    else if (!profile.cloudProvider) toolScore += 1; // No cloud tools needed
    if (tools.includes('testssl')) toolScore += 0.5;
    if (tools.includes('gobuster') || tools.includes('ffuf') || tools.includes('feroxbuster')) toolScore += 0.5;
    toolScore = Math.min(5, toolScore);
    assetScore += toolScore;
    console.log(`  [Tools] Score: ${toolScore}/5 (${tools.join(', ')})`);

    // Cloud awareness (5 pts for cloud targets only)
    if (profile.cloudProvider) {
      let cloudScore = 0;
      const allText = JSON.stringify(ap).toLowerCase();
      if (allText.includes('cloud') || allText.includes('aws')) cloudScore += 1;
      if (allText.includes('imds') || allText.includes('metadata') || allText.includes('169.254')) cloudScore += 2;
      if (tools.some(t => ['cloud_enum', 's3scanner'].includes(t)) || scripts.some(s => s.includes('cloud'))) cloudScore += 2;
      assetScore += Math.min(5, cloudScore);
      console.log(`  [Cloud] Score: ${Math.min(5, cloudScore)}/5`);
    } else {
      assetScore += 5; // Non-cloud targets get full marks
      console.log(`  [Cloud] N/A (on-premise) → 5/5`);
    }

    totalScore += assetScore;
    console.log(`  ASSET TOTAL: ${assetScore.toFixed(1)}/25\n`);
  }

  console.log('═'.repeat(60));
  console.log(`SCAN PLAN GENERATION TOTAL: ${totalScore.toFixed(1)}/${maxScore} (${(totalScore / maxScore * 100).toFixed(0)}%) ${totalScore >= 70 ? '✅ PASS' : '⚠️ NEEDS IMPROVEMENT'}`);
  console.log('═'.repeat(60));

  // Save results
  const fs = await import('fs');
  fs.writeFileSync('/home/ubuntu/caldera-dashboard/scan-plan-test-results.json', JSON.stringify(plan, null, 2));
  console.log('\nDetailed plan saved to scan-plan-test-results.json');
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
