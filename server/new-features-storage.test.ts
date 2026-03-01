import { describe, it, expect, vi } from 'vitest';

// ─── ZAP Proxy Session UI Page Tests ───
describe('ZAP Proxy Session UI Page', () => {
  it('should have the ZapProxySessions page component', async () => {
    const fs = await import('fs');
    const pagePath = '/home/ubuntu/caldera-dashboard/client/src/pages/ZapProxySessions.tsx';
    expect(fs.existsSync(pagePath)).toBe(true);
    const content = fs.readFileSync(pagePath, 'utf-8');
    expect(content).toContain('ZAP PROXY SESSIONS');
  });

  it('should include proxy session management controls', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/ZapProxySessions.tsx', 'utf-8');
    // Session creation form
    expect(content).toContain('targetUrl');
    expect(content).toContain('8080'); // proxy port reference
    // Session list
    expect(content).toContain('SESSION');
  });

  it('should include authenticated crawl configuration', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/ZapProxySessions.tsx', 'utf-8');
    expect(content).toContain('auth');
    expect(content).toContain('crawl');
  });

  it('should include WAF evasion presets', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/ZapProxySessions.tsx', 'utf-8');
    expect(content).toContain('WAF');
    expect(content).toContain('evasion');
  });

  it('should include CA certificate section', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/ZapProxySessions.tsx', 'utf-8');
    expect(content).toContain('CA');
    expect(content).toContain('certificate');
  });

  it('should include proxy traffic viewer', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/ZapProxySessions.tsx', 'utf-8');
    expect(content).toContain('traffic');
  });

  it('should be registered in App.tsx routes', async () => {
    const fs = await import('fs');
    const appContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/App.tsx', 'utf-8');
    expect(appContent).toContain('ZapProxySessions');
    expect(appContent).toContain('/zap-proxy');
  });

  it('should be in the AppShell sidebar navigation', async () => {
    const fs = await import('fs');
    const shellContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/components/AppShell.tsx', 'utf-8');
    expect(shellContent).toContain('zap-proxy');
    expect(shellContent).toContain('ZAP PROXY');
  });
});

// ─── Pentest Report UI Page Tests ───
describe('Pentest Report UI Page', () => {
  it('should have the PentestReport page component', async () => {
    const fs = await import('fs');
    const pagePath = '/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx';
    expect(fs.existsSync(pagePath)).toBe(true);
    const content = fs.readFileSync(pagePath, 'utf-8');
    expect(content).toContain('UNIFIED PENTEST REPORT');
  });

  it('should include report configuration form', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('REPORT CONFIGURATION');
    expect(content).toContain('reportTitle');
    expect(content).toContain('preparedFor');
    expect(content).toContain('preparedBy');
    expect(content).toContain('clientType');
  });

  it('should include section selector with all 14 report sections', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('REPORT SECTIONS');
    expect(content).toContain('executive_summary');
    expect(content).toContain('vulnerability_findings');
    expect(content).toContain('credential_findings');
    expect(content).toContain('mitre_mapping');
    expect(content).toContain('carver_analysis');
    expect(content).toContain('waf_ngfw');
    expect(content).toContain('github_exposure');
    expect(content).toContain('cloud_exposure');
    expect(content).toContain('remediation');
  });

  it('should include quick templates', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('Executive Brief');
    expect(content).toContain('Technical Deep Dive');
    expect(content).toContain('Compliance Report');
    expect(content).toContain('Full Engagement');
  });

  it('should include report preview dialog', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('REPORT PREVIEW');
    expect(content).toContain('handleDownloadHtml');
    expect(content).toContain('previewHtml');
  });

  it('should include data sources tab', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('DATA SOURCES');
    expect(content).toContain('DOMAIN INTEL SCANS');
    expect(content).toContain('CREDENTIAL FINDINGS');
    expect(content).toContain('ZAP SCAN RESULTS');
  });

  it('should include classification level selector', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('classificationLevel');
    expect(content).toContain('confidential');
    expect(content).toContain('restricted');
  });

  it('should include branding color picker', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('brandingColor');
    expect(content).toContain('#00E5CC');
  });

  it('should be registered in App.tsx routes', async () => {
    const fs = await import('fs');
    const appContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/App.tsx', 'utf-8');
    expect(appContent).toContain('PentestReport');
    expect(appContent).toContain('/pentest-report');
  });

  it('should be in the AppShell sidebar navigation', async () => {
    const fs = await import('fs');
    const shellContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/components/AppShell.tsx', 'utf-8');
    expect(shellContent).toContain('pentest-report');
    expect(shellContent).toContain('PENTEST REPORT');
  });
});

// ─── Credential Attack Result Storage Tests ───
describe('Credential Attack Result Storage', () => {
  it('should have credential_attack_runs table in schema', async () => {
    const fs = await import('fs');
    const schema = fs.readFileSync('/home/ubuntu/caldera-dashboard/drizzle/schema.ts', 'utf-8');
    expect(schema).toContain('credentialAttackRuns');
    expect(schema).toContain('targetHost');
    expect(schema).toContain('targetPort');
    expect(schema).toContain('attackMode');
    expect(schema).toContain('totalAttempts');
    expect(schema).toContain('successfulAttempts');
  });

  it('should have credential_findings table in schema', async () => {
    const fs = await import('fs');
    const schema = fs.readFileSync('/home/ubuntu/caldera-dashboard/drizzle/schema.ts', 'utf-8');
    expect(schema).toContain('credentialFindings');
    expect(schema).toContain('attackRunId');
    expect(schema).toContain('username');
    expect(schema).toContain('password');
    expect(schema).toContain('success');
  });

  it('should have zap_proxy_sessions table in schema', async () => {
    const fs = await import('fs');
    const schema = fs.readFileSync('/home/ubuntu/caldera-dashboard/drizzle/schema.ts', 'utf-8');
    expect(schema).toContain('zapProxySessions');
    expect(schema).toContain('proxyPort');
    expect(schema).toContain('targetUrl');
    expect(schema).toContain('sessionName');
    expect(schema).toContain('authType');
  });

  it('should have pentest_reports table in schema', async () => {
    const fs = await import('fs');
    const schema = fs.readFileSync('/home/ubuntu/caldera-dashboard/drizzle/schema.ts', 'utf-8');
    expect(schema).toContain('pentestReports');
    expect(schema).toContain('reportHtml'); // actual field name for HTML content
    expect(schema).toContain('classification');
    expect(schema).toContain('reportType');
  });

  it('should have DB helper functions for credential attack runs', async () => {
    const fs = await import('fs');
    const dbContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/db.ts', 'utf-8');
    expect(dbContent).toContain('createCredentialAttackRun');
    expect(dbContent).toContain('updateCredentialAttackRun');
    expect(dbContent).toContain('getCredentialAttackRuns');
    expect(dbContent).toContain('getCredentialAttackRunById');
    expect(dbContent).toContain('getCredentialAttackRunsByDomainScan');
  });

  it('should have DB helper functions for credential findings', async () => {
    const fs = await import('fs');
    const dbContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/db.ts', 'utf-8');
    expect(dbContent).toContain('createCredentialFinding');
    expect(dbContent).toContain('createCredentialFindings');
    expect(dbContent).toContain('getCredentialFindingsByRun');
    expect(dbContent).toContain('getCredentialFindingsByDomainScan');
    expect(dbContent).toContain('getAllCredentialFindings');
  });

  it('should have DB helper functions for ZAP proxy sessions', async () => {
    const fs = await import('fs');
    const dbContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/db.ts', 'utf-8');
    expect(dbContent).toContain('createZapProxySession');
    expect(dbContent).toContain('updateZapProxySession');
    expect(dbContent).toContain('getZapProxySessions');
    expect(dbContent).toContain('getZapProxySessionById');
    expect(dbContent).toContain('getZapSessionsByDomainScan');
  });

  it('should have DB helper functions for pentest reports', async () => {
    const fs = await import('fs');
    const dbContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/db.ts', 'utf-8');
    expect(dbContent).toContain('createPentestReport');
    expect(dbContent).toContain('updatePentestReport');
    expect(dbContent).toContain('getPentestReports');
    expect(dbContent).toContain('getPentestReportById');
    expect(dbContent).toContain('deletePentestReport');
  });
});

// ─── Router Endpoint Tests ───
describe('Web App Scanning Router - New Endpoints', () => {
  it('should have saveCredentialFindings endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('saveCredentialFindings');
    expect(routerContent).toContain('attackRunId');
    expect(routerContent).toContain('createCredentialAttackRun');
    expect(routerContent).toContain('createCredentialFindings');
  });

  it('should have listCredentialRuns endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('listCredentialRuns');
    expect(routerContent).toContain('getCredentialAttackRuns');
  });

  it('should have getCredentialRunFindings endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('getCredentialRunFindings');
    expect(routerContent).toContain('getCredentialFindingsByRun');
  });

  it('should have saveZapSession endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('saveZapSession');
    expect(routerContent).toContain('createZapProxySession');
  });

  it('should have listZapSessions endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('listZapSessions');
    expect(routerContent).toContain('getZapProxySessions');
  });

  it('should have savePentestReport endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('savePentestReport');
    expect(routerContent).toContain('createPentestReport');
    expect(routerContent).toContain('classification');
  });

  it('should have listPentestReports endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('listPentestReports');
    expect(routerContent).toContain('getPentestReports');
  });

  it('should have getPentestReport endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('getPentestReport');
    expect(routerContent).toContain('getPentestReportById');
  });

  it('should have deletePentestReport endpoint', async () => {
    const fs = await import('fs');
    const routerContent = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/routers/web-app-scanning.ts', 'utf-8');
    expect(routerContent).toContain('deletePentestReport');
  });
});

// ─── Report Template Tests ───
describe('Report Templates Configuration', () => {
  it('should define all 14 report sections', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    const sectionIds = [
      'executive_summary', 'scope_methodology', 'roe_compliance',
      'domain_intel', 'waf_ngfw', 'vulnerability_findings',
      'credential_findings', 'github_exposure', 'cloud_exposure',
      'attack_narrative', 'mitre_mapping', 'carver_analysis',
      'remediation', 'appendix'
    ];
    for (const id of sectionIds) {
      expect(content).toContain(id);
    }
  });

  it('should have 6 report type templates', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/pages/PentestReport.tsx', 'utf-8');
    expect(content).toContain('Executive Summary');
    expect(content).toContain('Technical Assessment');
    expect(content).toContain('Compliance Report');
    expect(content).toContain('Red Team Assessment');
    expect(content).toContain('Purple Team Report');
    expect(content).toContain('OSINT Assessment');
  });
});

// ─── Cross-linking Tests ───
describe('Cross-linking between modules', () => {
  it('should link credential findings to domain scans via scan IDs', async () => {
    const fs = await import('fs');
    const schema = fs.readFileSync('/home/ubuntu/caldera-dashboard/drizzle/schema.ts', 'utf-8');
    // credentialAttackRuns should have domain_intel_scan_id
    const credSection = schema.substring(schema.indexOf('credentialAttackRuns'));
    expect(credSection).toContain('domain_intel_scan_id');
    // zapProxySessions should also have domain_intel_scan_id
    const zapSection = schema.substring(schema.indexOf('zapProxySessions'));
    expect(zapSection).toContain('domain_intel_scan_id');
  });

  it('should link pentest reports to engagements and domain scans', async () => {
    const fs = await import('fs');
    const schema = fs.readFileSync('/home/ubuntu/caldera-dashboard/drizzle/schema.ts', 'utf-8');
    const pentestSection = schema.substring(schema.indexOf('pentestReports'));
    // Uses JSON arrays for linking to multiple scans
    expect(pentestSection).toContain('domain_intel_scan_ids');
    expect(pentestSection).toContain('zap_session_ids');
    expect(pentestSection).toContain('credential_attack_run_ids');
  });
});
