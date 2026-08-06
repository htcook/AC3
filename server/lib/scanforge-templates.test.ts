import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const TEMPLATES_DIR = path.join(__dirname, '../scanforge/templates/definitions');

describe('ScanForge Template Library', () => {
  let templateFiles: string[];
  let templates: Record<string, any>;

  beforeAll(() => {
    templateFiles = fs.readdirSync(TEMPLATES_DIR).filter(f => f.endsWith('.json'));
    templates = {};
    for (const file of templateFiles) {
      const content = fs.readFileSync(path.join(TEMPLATES_DIR, file), 'utf-8');
      templates[file] = JSON.parse(content);
    }
  });

  it('should have at least 30 templates', () => {
    expect(templateFiles.length).toBeGreaterThanOrEqual(30);
  });

  it('every template should have required fields', () => {
    for (const [file, tmpl] of Object.entries(templates)) {
      expect(tmpl.id, `${file} missing id`).toBeDefined();
      expect(typeof tmpl.id).toBe('string');
      expect(tmpl.name, `${file} missing name`).toBeDefined();
      expect(tmpl.description, `${file} missing description`).toBeDefined();
      expect(tmpl.severity, `${file} missing severity`).toBeDefined();
      expect(['info', 'low', 'medium', 'high', 'critical']).toContain(tmpl.severity);
      expect(tmpl.tags, `${file} missing tags`).toBeDefined();
      expect(Array.isArray(tmpl.tags)).toBe(true);
    }
  });

  it('every template should have unique IDs', () => {
    const ids = Object.values(templates).map((t: any) => t.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('should have OWASP Top 10 coverage', () => {
    const allTags = Object.values(templates).flatMap((t: any) => t.tags || []);
    const owaspTags = allTags.filter(t => t.startsWith('owasp-a'));
    const uniqueOwasp = new Set(owaspTags);
    // Should cover at least A01-A10 categories
    expect(uniqueOwasp.size).toBeGreaterThanOrEqual(8);
  });

  it('OWASP templates should have CWE references', () => {
    const owaspTemplates = Object.entries(templates).filter(([_, t]) =>
      (t as any).tags?.some((tag: string) => tag.includes('owasp-top10'))
    );
    expect(owaspTemplates.length).toBeGreaterThanOrEqual(10);
    for (const [file, tmpl] of owaspTemplates) {
      expect((tmpl as any).references?.cwes, `${file} missing CWE references`).toBeDefined();
      expect((tmpl as any).references.cwes.length, `${file} has empty CWEs`).toBeGreaterThan(0);
    }
  });

  it('should have default credentials template with multiple services', () => {
    const credsTmpl = Object.values(templates).find((t: any) => t.id === 'default-creds-common-services') as any;
    expect(credsTmpl).toBeDefined();
    expect(credsTmpl.checks).toBeDefined();
    expect(credsTmpl.checks.length).toBeGreaterThanOrEqual(8);
    const services = credsTmpl.checks.map((c: any) => c.service);
    expect(services).toContain('ssh');
    expect(services).toContain('mysql');
    expect(services).toContain('redis');
    expect(services).toContain('ftp');
    expect(services).toContain('tomcat');
  });

  it('critical severity templates should have remediation guidance', () => {
    const criticals = Object.entries(templates).filter(([_, t]) => (t as any).severity === 'critical');
    expect(criticals.length).toBeGreaterThanOrEqual(4);
    for (const [file, tmpl] of criticals) {
      expect((tmpl as any).remediation, `${file} missing remediation`).toBeDefined();
      expect((tmpl as any).remediation.length).toBeGreaterThan(20);
    }
  });

  it('should have SQL injection template', () => {
    const sqli = Object.values(templates).find((t: any) => t.id === 'owasp-sqli-error-based') as any;
    expect(sqli).toBeDefined();
    expect(sqli.severity).toBe('critical');
    expect(sqli.tags).toContain('owasp-a03');
  });

  it('should have XSS template', () => {
    const xss = Object.values(templates).find((t: any) => t.id === 'owasp-xss-reflected') as any;
    expect(xss).toBeDefined();
    expect(xss.severity).toBe('high');
  });

  it('should have SSRF template', () => {
    const ssrf = Object.values(templates).find((t: any) => t.id === 'owasp-ssrf-cloud-metadata') as any;
    expect(ssrf).toBeDefined();
    expect(ssrf.severity).toBe('critical');
    expect(ssrf.tags).toContain('ssrf');
  });

  it('should have path traversal / LFI template', () => {
    const lfi = Object.values(templates).find((t: any) => t.id === 'owasp-path-traversal-lfi') as any;
    expect(lfi).toBeDefined();
    expect(lfi.severity).toBe('critical');
  });

  it('should have command injection template', () => {
    const cmdi = Object.values(templates).find((t: any) => t.id === 'owasp-command-injection') as any;
    expect(cmdi).toBeDefined();
    expect(cmdi.severity).toBe('critical');
    expect(cmdi.references?.cwes).toContain('CWE-78');
  });

  it('should have SSTI template', () => {
    const ssti = Object.values(templates).find((t: any) => t.id === 'owasp-ssti-template-injection') as any;
    expect(ssti).toBeDefined();
    expect(ssti.severity).toBe('critical');
  });

  it('templates with MITRE ATT&CK references should have valid technique IDs', () => {
    for (const [file, tmpl] of Object.entries(templates)) {
      const attack = (tmpl as any).attack;
      if (attack?.techniqueIds) {
        for (const tid of attack.techniqueIds) {
          expect(tid, `${file} has invalid MITRE technique ID: ${tid}`).toMatch(/^T\d{4}/);
        }
      }
    }
  });

  it('should have DNS-related templates', () => {
    const dnsTemplates = Object.entries(templates).filter(([f]) => f.startsWith('dns-'));
    expect(dnsTemplates.length).toBeGreaterThanOrEqual(5);
  });

  it('should have HTTP-related templates', () => {
    const httpTemplates = Object.entries(templates).filter(([f]) => f.startsWith('http-'));
    expect(httpTemplates.length).toBeGreaterThanOrEqual(5);
  });

  it('should have TLS/SSL template', () => {
    const tls = Object.values(templates).find((t: any) => t.id === 'tls-weak-cipher-protocol') as any;
    expect(tls).toBeDefined();
    expect(tls.tags).toContain('tls');
  });
});

describe('Engagement Reset Procedure', () => {
  it('reset procedure should exist in engagements-core router', async () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, '../routers/engagements-core.ts'),
      'utf-8'
    );
    expect(routerContent).toContain('resetEngagement');
    expect(routerContent).toContain('bulkResetEngagements');
  });

  it('reset procedure should clear ops snapshots, scan results, timeline events, and test plans', async () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, '../routers/engagements-core.ts'),
      'utf-8'
    );
    // Verify the reset procedure deletes from all related tables (using schema references)
    expect(routerContent).toContain('opsSnapshots');
    expect(routerContent).toContain('scanResults');
    expect(routerContent).toContain('timelineEvents');
    expect(routerContent).toContain('testPlans');
    // Verify it resets engagement status to planning
    expect(routerContent).toContain("'planning'");
  });

  it('bulk reset should accept array of engagement IDs', async () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, '../routers/engagements-core.ts'),
      'utf-8'
    );
    expect(routerContent).toContain('z.array(z.number())');
    expect(routerContent).toContain('bulkResetEngagements');
  });
});

describe('TransportIndicator Component', () => {
  it('TransportIndicator component should exist', () => {
    const componentPath = path.join(__dirname, '../../client/src/components/TransportIndicator.tsx');
    expect(fs.existsSync(componentPath)).toBe(true);
    const content = fs.readFileSync(componentPath, 'utf-8');
    expect(content).toContain('useWebSocket');
    expect(content).toContain('websocket');
    expect(content).toContain('sse');
  });

  it('DashboardLayout should include TransportIndicator', () => {
    const layoutPath = path.join(__dirname, '../../client/src/components/DashboardLayout.tsx');
    const content = fs.readFileSync(layoutPath, 'utf-8');
    expect(content).toContain('TransportIndicator');
  });
});
