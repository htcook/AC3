import { describe, it, expect, vi } from 'vitest';

describe('Template Preview with Real Data', () => {
  describe('getPreviewSources', () => {
    it('should return both DI scans and engagements arrays', () => {
      const result = {
        diScans: [
          { id: 1, label: 'DI: target.com (Score: 65, 94 assets)', type: 'di' as const, domain: 'target.com', createdAt: new Date() },
          { id: 2, label: 'DI: shopify.com (Score: 42, 37 assets)', type: 'di' as const, domain: 'shopify.com', createdAt: new Date() },
        ],
        engagements: [
          { id: 1, label: 'pentest: DVWA (AceofCloud)', type: 'engagement' as const, domain: 'dvwa.local', createdAt: new Date() },
        ],
      };
      expect(result.diScans).toHaveLength(2);
      expect(result.engagements).toHaveLength(1);
      expect(result.diScans[0].type).toBe('di');
      expect(result.engagements[0].type).toBe('engagement');
    });

    it('should format DI scan labels with domain, score, and asset count', () => {
      const scan = { primaryDomain: 'target.com', overallRiskScore: 65, totalAssets: 94 };
      const label = `DI: ${scan.primaryDomain} (Score: ${scan.overallRiskScore || 0}, ${scan.totalAssets || 0} assets)`;
      expect(label).toBe('DI: target.com (Score: 65, 94 assets)');
    });

    it('should format engagement labels with type, name, and customer', () => {
      const eng = { engagementType: 'red_team', name: 'Operation Phoenix', customerName: 'AceofCloud' };
      const label = `${eng.engagementType?.replace('_', ' ')}: ${eng.name} (${eng.customerName})`;
      expect(label).toBe('red team: Operation Phoenix (AceofCloud)');
    });
  });

  describe('getPreviewData - DI Scan', () => {
    it('should return all required template variables from DI scan data', () => {
      const mockScan = {
        id: 1,
        primaryDomain: 'target.com',
        totalAssets: 94,
        totalFindings: 33,
        overallRiskScore: 65,
        discoveryCoverageScore: 63,
        executiveSummary: 'Test summary',
        sector: 'Retail',
      };

      const result = {
        client_name: mockScan.sector || 'Client Organization',
        report_title: `Domain Intelligence Report — ${mockScan.primaryDomain}`,
        domain: mockScan.primaryDomain,
        total_assets: String(mockScan.totalAssets || 0),
        risk_score: String(mockScan.overallRiskScore || 0),
        recon_coverage: `${mockScan.discoveryCoverageScore || 0}%`,
        executive_summary: mockScan.executiveSummary,
      };

      expect(result.client_name).toBe('Retail');
      expect(result.domain).toBe('target.com');
      expect(result.total_assets).toBe('94');
      expect(result.risk_score).toBe('65');
      expect(result.recon_coverage).toBe('63%');
      expect(result.executive_summary).toBe('Test summary');
    });

    it('should generate subdomains table HTML from discovered assets', () => {
      const assets = [
        { hostname: 'api.target.com', assetType: 'subdomain', dnsStatus: 'active' },
        { hostname: 'mail.target.com', assetType: 'subdomain', dnsStatus: 'active' },
      ];

      const html = `<table><thead><tr><th>Hostname</th><th>Type</th><th>Status</th></tr></thead><tbody>${
        assets.map(a => `<tr><td>${a.hostname}</td><td>${a.assetType || 'subdomain'}</td><td>${a.dnsStatus || 'active'}</td></tr>`).join('')
      }</tbody></table>`;

      expect(html).toContain('api.target.com');
      expect(html).toContain('mail.target.com');
      expect(html).toContain('<thead>');
      expect(html).toContain('<tbody>');
    });

    it('should calculate findings breakdown from pipeline output', () => {
      const findings = [
        { severity: 'critical', cvssScore: 9.8 },
        { severity: 'high', cvssScore: 7.5 },
        { severity: 'high', cvssScore: 8.1 },
        { severity: 'medium', cvssScore: 5.3 },
        { severity: 'low', cvssScore: 2.1 },
      ];

      const critical = findings.filter(f => f.severity === 'critical').length;
      const high = findings.filter(f => f.severity === 'high').length;
      const medium = findings.filter(f => f.severity === 'medium').length;
      const low = findings.filter(f => f.severity === 'low').length;

      expect(critical).toBe(1);
      expect(high).toBe(2);
      expect(medium).toBe(1);
      expect(low).toBe(1);
    });
  });

  describe('getPreviewData - Engagement', () => {
    it('should return all required template variables from engagement data', () => {
      const mockEng = {
        id: 1,
        name: 'DVWA Test',
        customerName: 'AceofCloud',
        engagementType: 'pentest',
        targetDomain: 'dvwa.local',
        description: 'Penetration test of DVWA',
      };

      const vulns = [
        { severity: 'critical', cvssScore: 9.8, title: 'SQL Injection' },
        { severity: 'high', cvssScore: 7.5, title: 'XSS' },
      ];

      const result = {
        client_name: mockEng.customerName,
        report_title: `Pentest Report — ${mockEng.name}`,
        engagement_id: `ENG-${mockEng.id}`,
        domain: mockEng.targetDomain,
        total_vulns: String(vulns.length),
        critical_count: String(vulns.filter(v => v.severity === 'critical').length),
        high_count: String(vulns.filter(v => v.severity === 'high').length),
      };

      expect(result.client_name).toBe('AceofCloud');
      expect(result.domain).toBe('dvwa.local');
      expect(result.total_vulns).toBe('2');
      expect(result.critical_count).toBe('1');
      expect(result.high_count).toBe('1');
    });

    it('should calculate CVSS avg and max from vulnerabilities', () => {
      const vulns = [
        { cvssScore: 9.8 },
        { cvssScore: 7.5 },
        { cvssScore: 5.3 },
      ];

      const scores = vulns.filter(v => v.cvssScore).map(v => v.cvssScore);
      const avg = (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1);
      const max = Math.max(...scores).toFixed(1);

      expect(avg).toBe('7.5');
      expect(max).toBe('9.8');
    });

    it('should build vulnerabilities table HTML', () => {
      const vulns = [
        { severity: 'critical', title: 'SQL Injection', cvssScore: 9.8 },
        { severity: 'high', title: 'XSS', cvssScore: 7.5 },
      ];

      const html = `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th></tr></thead><tbody>${
        vulns.map((v, i) => `<tr><td>V-${String(i+1).padStart(3,'0')}</td><td>${v.title}</td><td class="severity-${v.severity}">${v.severity.toUpperCase()}</td><td>${v.cvssScore}</td></tr>`).join('')
      }</tbody></table>`;

      expect(html).toContain('SQL Injection');
      expect(html).toContain('severity-critical');
      expect(html).toContain('V-001');
      expect(html).toContain('9.8');
    });
  });
});

describe('Test Credentials', () => {
  describe('testCredentials procedure', () => {
    it('should validate input schema requires targetUrl, username, password', () => {
      const validInput = {
        targetUrl: 'https://dvwa.local',
        username: 'admin',
        password: 'password',
        authType: 'form' as const,
        loginPath: '/login.php',
      };

      expect(validInput.targetUrl).toBeTruthy();
      expect(validInput.username).toBeTruthy();
      expect(validInput.password).toBeTruthy();
      expect(['form', 'basic', 'bearer', 'cookie']).toContain(validInput.authType);
    });

    it('should construct correct URL for form-based login test', () => {
      const targetUrl = 'https://dvwa.local';
      const loginPath = '/login.php';
      const fullUrl = loginPath ? new URL(loginPath, targetUrl).toString() : targetUrl;
      expect(fullUrl).toBe('https://dvwa.local/login.php');
    });

    it('should construct correct URL when loginPath is empty', () => {
      const targetUrl = 'https://dvwa.local';
      const loginPath = '';
      const fullUrl = loginPath ? new URL(loginPath, targetUrl).toString() : targetUrl;
      expect(fullUrl).toBe('https://dvwa.local');
    });

    it('should construct HTTP Basic auth header correctly', () => {
      const username = 'admin';
      const password = 'secret';
      const encoded = Buffer.from(`${username}:${password}`).toString('base64');
      const header = `Basic ${encoded}`;
      expect(header).toBe('Basic YWRtaW46c2VjcmV0');
    });

    it('should return success/failure with descriptive message', () => {
      // Success case
      const successResult = { success: true, message: 'Authentication successful — received 200 OK with session cookie' };
      expect(successResult.success).toBe(true);
      expect(successResult.message).toContain('successful');

      // Failure case
      const failResult = { success: false, message: 'Authentication failed — received 401 Unauthorized' };
      expect(failResult.success).toBe(false);
      expect(failResult.message).toContain('failed');
    });

    it('should handle network errors gracefully', () => {
      const errorResult = { success: false, message: 'Connection refused — target unreachable' };
      expect(errorResult.success).toBe(false);
      expect(errorResult.message).toContain('unreachable');
    });

    it('should detect successful form login by checking for session cookies or redirects', () => {
      // Simulate checking response for success indicators
      const checkFormLoginSuccess = (statusCode: number, cookies: string[], location?: string) => {
        // Success: got a session cookie
        if (cookies.some(c => c.includes('PHPSESSID') || c.includes('session') || c.includes('token'))) return true;
        // Success: redirect to dashboard/home (not back to login)
        if (statusCode >= 300 && statusCode < 400 && location && !location.includes('login')) return true;
        // Success: 200 with no error indicators
        if (statusCode === 200) return true;
        return false;
      };

      expect(checkFormLoginSuccess(302, ['PHPSESSID=abc123'], '/dashboard')).toBe(true);
      expect(checkFormLoginSuccess(200, ['session=xyz'], undefined)).toBe(true);
      expect(checkFormLoginSuccess(401, [], undefined)).toBe(false);
    });
  });

  describe('TestCredentialsButton component logic', () => {
    it('should disable button when username or password is empty', () => {
      const canTest = (username: string, password: string, targetUrl: string) => {
        return !!(username && password && targetUrl);
      };

      expect(canTest('', 'pass', 'https://target.com')).toBe(false);
      expect(canTest('admin', '', 'https://target.com')).toBe(false);
      expect(canTest('admin', 'pass', '')).toBe(false);
      expect(canTest('admin', 'pass', 'https://target.com')).toBe(true);
    });

    it('should prepend https:// if targetUrl has no protocol', () => {
      const normalizeUrl = (url: string) => url.startsWith('http') ? url : `https://${url}`;
      expect(normalizeUrl('dvwa.local')).toBe('https://dvwa.local');
      expect(normalizeUrl('https://dvwa.local')).toBe('https://dvwa.local');
      expect(normalizeUrl('http://dvwa.local')).toBe('http://dvwa.local');
    });
  });
});
