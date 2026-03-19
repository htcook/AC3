import { describe, it, expect } from 'vitest';
import {
  BANKING_VULN_TAXONOMY,
  BANKING_ATTACK_SCENARIOS,
  BANKING_REGULATORY_CONTEXT,
  BANKING_TECH_STACK_CONTEXT,
  buildBankingDomainContext,
  getBankingContextCompact,
} from './lib/llm-specialists/banking-domain-knowledge';

describe('Banking Domain Knowledge Module', () => {
  describe('Vulnerability Taxonomy', () => {
    it('should contain all 6 vulnerability categories', () => {
      const categories = Object.keys(BANKING_VULN_TAXONOMY);
      expect(categories).toContain('authentication_authorization');
      expect(categories).toContain('injection_attacks');
      expect(categories).toContain('business_logic');
      expect(categories).toContain('data_exposure');
      expect(categories).toContain('infrastructure_config');
      expect(categories).toContain('api_mobile');
      expect(categories.length).toBe(6);
    });

    it('should have critical vulns in each category', () => {
      for (const [key, category] of Object.entries(BANKING_VULN_TAXONOMY)) {
        const criticals = category.vulns.filter(v => v.severity === 'critical');
        expect(criticals.length, `${key} should have critical vulns`).toBeGreaterThan(0);
      }
    });

    it('should include OWASP and CWE references for all vulns', () => {
      for (const category of Object.values(BANKING_VULN_TAXONOMY)) {
        for (const vuln of category.vulns) {
          expect(vuln.owasp).toMatch(/^A\d{2}:\d{4}$/);
          expect(vuln.cwe).toMatch(/^CWE-\d+$/);
        }
      }
    });

    it('should include SQL injection, XSS, IDOR, and business logic vulns', () => {
      const allVulnNames = Object.values(BANKING_VULN_TAXONOMY)
        .flatMap(c => c.vulns.map(v => v.name.toLowerCase()));
      expect(allVulnNames.some(n => n.includes('sql injection'))).toBe(true);
      expect(allVulnNames.some(n => n.includes('xss'))).toBe(true);
      expect(allVulnNames.some(n => n.includes('idor') || n.includes('direct object'))).toBe(true);
      expect(allVulnNames.some(n => n.includes('transaction'))).toBe(true);
    });
  });

  describe('Attack Scenarios', () => {
    it('should contain at least 8 banking attack scenarios', () => {
      expect(BANKING_ATTACK_SCENARIOS.length).toBeGreaterThanOrEqual(8);
    });

    it('should include MITRE ATT&CK IDs for all scenarios', () => {
      for (const scenario of BANKING_ATTACK_SCENARIOS) {
        expect(scenario.mitre.length).toBeGreaterThan(0);
        for (const id of scenario.mitre) {
          expect(id).toMatch(/^T\d{4}/);
        }
      }
    });

    it('should include account takeover, SQL injection, and wire transfer scenarios', () => {
      const names = BANKING_ATTACK_SCENARIOS.map(s => s.name.toLowerCase());
      expect(names.some(n => n.includes('account takeover') || n.includes('credential'))).toBe(true);
      expect(names.some(n => n.includes('sql injection'))).toBe(true);
      expect(names.some(n => n.includes('wire transfer') || n.includes('transaction'))).toBe(true);
    });
  });

  describe('Regulatory Context', () => {
    it('should reference PCI-DSS, GLBA, FFIEC, SOX, and FedRAMP', () => {
      expect(BANKING_REGULATORY_CONTEXT).toContain('PCI-DSS');
      expect(BANKING_REGULATORY_CONTEXT).toContain('GLBA');
      expect(BANKING_REGULATORY_CONTEXT).toContain('FFIEC');
      expect(BANKING_REGULATORY_CONTEXT).toContain('SOX');
      expect(BANKING_REGULATORY_CONTEXT).toContain('FedRAMP');
    });
  });

  describe('Tech Stack Context', () => {
    it('should reference common banking technologies', () => {
      expect(BANKING_TECH_STACK_CONTEXT).toContain('SWIFT');
      expect(BANKING_TECH_STACK_CONTEXT).toContain('Tomcat');
      expect(BANKING_TECH_STACK_CONTEXT).toContain('Java');
      expect(BANKING_TECH_STACK_CONTEXT).toContain('Apache Struts');
    });
  });

  describe('buildBankingDomainContext', () => {
    it('should include banking domain intelligence header', () => {
      const ctx = buildBankingDomainContext();
      expect(ctx).toContain('Banking Domain Intelligence');
      expect(ctx).toContain('BANKING / FINANCIAL SERVICES');
    });

    it('should include phase-specific context for recon', () => {
      const ctx = buildBankingDomainContext({ phase: 'recon' });
      expect(ctx).toContain('Banking Recon Priorities');
      expect(ctx).toContain('online banking portals');
    });

    it('should include phase-specific context for vuln_detection', () => {
      const ctx = buildBankingDomainContext({ phase: 'vuln_detection' });
      expect(ctx).toContain('Banking Vulnerability Detection Focus');
      expect(ctx).toContain('SQL Injection');
    });

    it('should include phase-specific context for exploitation', () => {
      const ctx = buildBankingDomainContext({ phase: 'exploitation' });
      expect(ctx).toContain('Banking Exploitation Priorities');
      expect(ctx).toContain('Realistic Banking Attack Scenarios');
    });

    it('should include phase-specific context for post_exploit', () => {
      const ctx = buildBankingDomainContext({ phase: 'post_exploit' });
      expect(ctx).toContain('Banking Post-Exploitation Assessment');
      expect(ctx).toContain('regulatory notification');
    });

    it('should include regulatory context by default', () => {
      const ctx = buildBankingDomainContext();
      expect(ctx).toContain('PCI-DSS');
      expect(ctx).toContain('GLBA');
    });

    it('should exclude regulatory context when disabled', () => {
      const ctx = buildBankingDomainContext({ includeRegulatory: false });
      expect(ctx).not.toContain('Gramm-Leach-Bliley');
    });
  });

  describe('getBankingContextCompact', () => {
    it('should return a single-line compact context', () => {
      const ctx = getBankingContextCompact();
      expect(ctx).toContain('BANKING SECTOR');
      expect(ctx).toContain('SQL injection');
      expect(ctx).toContain('IDOR');
      expect(ctx).toContain('PCI-DSS');
      expect(ctx).toContain('SWIFT');
    });
  });
});
