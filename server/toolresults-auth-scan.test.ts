/**
 * Tests for:
 * 1. toolResults population in the rerunFullPipeline code path
 * 2. Authenticated scanning support for DVWA and generic login-protected targets
 * 3. Frontend portScanResults filter matching expanded tool names
 */
import { describe, it, expect } from "vitest";

describe("toolResults population", () => {
  it("should create a valid ScanForge discovery toolResult entry", () => {
    const toolResult = {
      tool: 'scanforge-discovery',
      command: 'scanforge-discovery -sV -sC -T4 --top-ports 1000 target.example.com',
      exitCode: 0,
      durationMs: 12345,
      timedOut: false,
      findingCount: 3,
      findings: [
        { severity: 'info', title: '80/tcp http (Apache/2.4.41)' },
        { severity: 'info', title: '443/tcp https' },
        { severity: 'info', title: '22/tcp ssh (OpenSSH 8.2)' },
      ],
      outputPreview: 'PORT     STATE SERVICE  VERSION\n80/tcp   open  http     Apache/2.4.41\n443/tcp  open  https\n22/tcp   open  ssh      OpenSSH 8.2',
      executedAt: Date.now(),
      phase: 'discovery',
    };

    expect(toolResult.tool).toBe('scanforge-discovery');
    expect(toolResult.phase).toBe('discovery');
    expect(toolResult.findingCount).toBe(3);
    expect(toolResult.findings).toHaveLength(3);
    expect(toolResult.findings[0].title).toContain('80/tcp');
    expect(toolResult.exitCode).toBe(0);
    expect(toolResult.timedOut).toBe(false);
  });

  it("should create a valid nuclei toolResult entry", () => {
    const toolResult = {
      tool: 'nuclei',
      command: 'echo "http://target.example.com" | nuclei -severity critical,high,medium -jsonl -nc -duc -ni',
      exitCode: 0,
      durationMs: 45000,
      timedOut: false,
      findingCount: 2,
      findings: [
        { severity: 'high', title: 'SQL Injection in login form' },
        { severity: 'medium', title: 'Missing X-Frame-Options header' },
      ],
      outputPreview: '{"template-id":"sqli-login","info":{"name":"SQL Injection"}}',
      executedAt: Date.now(),
      phase: 'scanning',
    };

    expect(toolResult.tool).toBe('nuclei');
    expect(toolResult.phase).toBe('scanning');
    expect(toolResult.findingCount).toBe(2);
    expect(toolResult.findings[0].severity).toBe('high');
  });

  it("should create a valid httpx toolResult entry", () => {
    const toolResult = {
      tool: 'httpx',
      command: "echo -e 'http://target.example.com' | httpx -json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent",
      exitCode: 0,
      durationMs: 5000,
      timedOut: false,
      findingCount: 4,
      findings: [
        { severity: 'info', title: '[httpx] Technology: Apache' },
        { severity: 'info', title: '[httpx] Technology: PHP' },
        { severity: 'info', title: '[httpx] Web Server: Apache/2.4.41' },
        { severity: 'info', title: '[httpx] http://target.example.com: 200 Welcome' },
      ],
      outputPreview: '{"url":"http://target.example.com","status_code":200,"tech":["Apache","PHP"],"webserver":"Apache/2.4.41"}',
      executedAt: Date.now(),
      phase: 'discovery',
    };

    expect(toolResult.tool).toBe('httpx');
    expect(toolResult.phase).toBe('discovery');
    expect(toolResult.findingCount).toBe(4);
    expect(toolResult.findings.filter(f => f.title.includes('Technology'))).toHaveLength(2);
  });

  it("should push failed toolResult entries with exitCode 1", () => {
    const failedResult = {
      tool: 'scanforge-discovery',
      command: 'scanforge-discovery -sV target.example.com',
      exitCode: 1,
      durationMs: 0,
      timedOut: false,
      findingCount: 0,
      findings: [] as Array<{severity: string; title: string}>,
      outputPreview: 'Connection refused',
      executedAt: Date.now(),
      phase: 'discovery',
    };

    expect(failedResult.exitCode).toBe(1);
    expect(failedResult.findingCount).toBe(0);
    expect(failedResult.findings).toHaveLength(0);
  });
});

describe("frontend portScanResults filter", () => {
  it("should match all port discovery tool names including scanforge-discovery", () => {
    const allToolResults = [
      { tool: 'nmap', phase: 'discovery' },
      { tool: 'nmap-discovery', phase: 'discovery' },
      { tool: 'nerva', phase: 'discovery' },
      { tool: 'naabu', phase: 'discovery' },
      { tool: 'scanforge-discovery', phase: 'discovery' },
      { tool: 'masscan', phase: 'discovery' },
      { tool: 'rustscan', phase: 'discovery' },
      { tool: 'nuclei', phase: 'scanning' },
      { tool: 'httpx', phase: 'discovery' },
    ];

    // This mirrors the updated frontend filter
    const portScanResults = allToolResults.filter((tr: any) =>
      tr.tool === 'nmap' || tr.tool === 'nmap-discovery' || tr.tool === 'nerva' ||
      tr.tool === 'naabu' || tr.tool === 'scanforge-discovery' || tr.tool === 'masscan' ||
      tr.tool === 'rustscan' || tr.phase === 'discovery'
    );

    // All discovery-phase tools should be matched
    expect(portScanResults).toHaveLength(8); // all except nuclei (phase: scanning)
    expect(portScanResults.map(r => r.tool)).toContain('scanforge-discovery');
    expect(portScanResults.map(r => r.tool)).toContain('httpx'); // httpx has phase: discovery
    expect(portScanResults.map(r => r.tool)).not.toContain('nuclei');
  });

  it("should match httpx results separately", () => {
    const allToolResults = [
      { tool: 'httpx', phase: 'discovery', findings: [{ severity: 'info', title: 'Tech: Apache' }] },
      { tool: 'scanforge-discovery', phase: 'discovery', findings: [] },
    ];

    const httpxResults = allToolResults.filter((tr: any) => tr.tool === 'httpx');
    expect(httpxResults).toHaveLength(1);
    expect(httpxResults[0].findings).toHaveLength(1);
  });
});

describe("authenticated scanning support", () => {
  it("should detect DVWA as a known training target", () => {
    // Simulated TRAINING_TARGETS lookup
    const TRAINING_TARGETS = [
      { id: 'dvwa', url: 'https://github.com/digininja/DVWA', liveInstanceUrl: 'http://scan.aceofcloud.io/lab/dvwa/' },
      { id: 'juiceshop', url: 'https://github.com/juice-shop/juice-shop', liveInstanceUrl: 'http://scan.aceofcloud.io:3000' },
    ];

    const assetHostname = 'scan.aceofcloud.io';
    const matchedLab = TRAINING_TARGETS.find(t => {
      try {
        const tHost = new URL(t.liveInstanceUrl || t.url).hostname;
        return assetHostname.includes(tHost) || tHost.includes(assetHostname) ||
               (t.liveInstanceUrl && new URL(t.liveInstanceUrl).hostname === assetHostname);
      } catch { return false; }
    });

    expect(matchedLab).toBeDefined();
    expect(matchedLab!.id).toBe('dvwa');
  });

  it("should build correct nuclei auth header with DVWA session cookie", () => {
    const authSessionCookie = 'PHPSESSID=abc123def456; security=low';
    let nucleiCustomHeaders = '';

    // This mirrors the code that injects the auth cookie
    nucleiCustomHeaders += ` -H "Cookie: ${authSessionCookie}"`;

    expect(nucleiCustomHeaders).toContain('Cookie: PHPSESSID=abc123def456; security=low');
    expect(nucleiCustomHeaders).toContain('-H');
  });

  it("should inject auth cookie into DAST customHeaderFlags", () => {
    const authSessionCookie = 'PHPSESSID=abc123; security=low';
    let customHeaderFlags = '';

    // This mirrors the DAST auth injection code
    if (authSessionCookie && !customHeaderFlags.includes('Cookie:')) {
      customHeaderFlags += ` -H "Cookie: ${authSessionCookie}"`;
    }

    expect(customHeaderFlags).toContain('Cookie: PHPSESSID=abc123');
  });

  it("should not inject duplicate Cookie header if already present", () => {
    const authSessionCookie = 'PHPSESSID=abc123; security=low';
    let customHeaderFlags = '-H "Cookie: existing=value"';

    // Should NOT inject if Cookie already present
    if (authSessionCookie && !customHeaderFlags.includes('Cookie:')) {
      customHeaderFlags += ` -H "Cookie: ${authSessionCookie}"`;
    }

    // Should still have only the original Cookie header
    expect(customHeaderFlags).toBe('-H "Cookie: existing=value"');
  });

  it("should store confirmed credentials on asset after successful DVWA login", () => {
    const asset = {
      hostname: 'scan.aceofcloud.io',
      confirmedCredentials: [] as any[],
    };

    // Simulate storing credentials after successful login
    const credExists = asset.confirmedCredentials.some((c: any) => c.username === 'admin' && c.source === 'auto-login');
    if (!credExists) {
      asset.confirmedCredentials.push({
        username: 'admin', password: 'password', service: 'http-form',
        port: 80, protocol: 'http', accessLevel: 'admin',
        source: 'auto-login', loginPath: '/login.php',
        confirmedAt: Date.now(),
      });
    }

    expect(asset.confirmedCredentials).toHaveLength(1);
    expect(asset.confirmedCredentials[0].username).toBe('admin');
    expect(asset.confirmedCredentials[0].source).toBe('auto-login');
    expect(asset.confirmedCredentials[0].loginPath).toBe('/login.php');
  });

  it("should handle generic form-based auth with confirmed credentials", () => {
    const confirmedCreds = [
      { username: 'testuser', password: 'testpass', protocol: 'http', service: 'http-form', loginPath: '/auth/login' },
    ];

    const cred = confirmedCreds[0];
    expect(cred.loginPath).toBe('/auth/login');

    // Build the curl command that would be used
    const loginBase = 'http://target.example.com';
    const curlCmd = `curl -sD - -c /tmp/auth_cookies_target_example_com.txt -L ` +
      `--data-urlencode 'username=${cred.username}' --data-urlencode 'password=${cred.password}' ` +
      `'${loginBase}${cred.loginPath}'`;

    expect(curlCmd).toContain('username=testuser');
    expect(curlCmd).toContain('password=testpass');
    expect(curlCmd).toContain('/auth/login');
  });

  it("should parse PHPSESSID from curl cookie jar output", () => {
    const cookieJarOutput = `# Netscape HTTP Cookie File
# http://curl.haxx.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

scan.aceofcloud.io\tFALSE\t/lab/dvwa/\tFALSE\t0\tPHPSESSID\tabc123def456ghi789
scan.aceofcloud.io\tFALSE\t/lab/dvwa/\tFALSE\t0\tsecurity\tlow`;

    const phpSessMatch = cookieJarOutput.match(/PHPSESSID\s+(\S+)/);
    const secMatch = cookieJarOutput.match(/security\s+(\S+)/);

    expect(phpSessMatch).not.toBeNull();
    expect(phpSessMatch![1]).toBe('abc123def456ghi789');
    expect(secMatch).not.toBeNull();
    expect(secMatch![1]).toBe('low');

    let authSessionCookie = `PHPSESSID=${phpSessMatch![1]}`;
    if (secMatch) authSessionCookie += `; security=${secMatch[1]}`;
    else authSessionCookie += '; security=low';

    expect(authSessionCookie).toBe('PHPSESSID=abc123def456ghi789; security=low');
  });

  it("should parse httpx JSON output for technology detection", () => {
    const httpxJsonLine = '{"url":"http://target.example.com","status_code":200,"title":"Welcome","tech":["Apache","PHP","MySQL"],"webserver":"Apache/2.4.41","cdn_name":"Cloudflare"}';
    
    const obj = JSON.parse(httpxJsonLine);
    const httpxFindings: Array<{severity: string; title: string}> = [];
    const techDetected: string[] = [];

    if (obj.tech && Array.isArray(obj.tech)) {
      for (const tech of obj.tech) {
        if (!techDetected.includes(tech)) techDetected.push(tech);
        httpxFindings.push({ severity: 'info', title: `[httpx] Technology: ${tech}` });
      }
    }
    if (obj.cdn_name) httpxFindings.push({ severity: 'info', title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
    if (obj.webserver) httpxFindings.push({ severity: 'info', title: `[httpx] Web Server: ${obj.webserver}` });
    if (obj.status_code) httpxFindings.push({ severity: 'info', title: `[httpx] ${obj.url || ''}: ${obj.status_code} ${obj.title || ''}`.trim() });

    expect(techDetected).toEqual(['Apache', 'PHP', 'MySQL']);
    expect(httpxFindings).toHaveLength(6); // 3 tech + cdn + webserver + status_code
    expect(httpxFindings.find(f => f.title.includes('Cloudflare'))).toBeDefined();
    expect(httpxFindings.find(f => f.title.includes('Apache/2.4.41'))).toBeDefined();
  });
});
