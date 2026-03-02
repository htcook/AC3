import { describe, it, expect } from 'vitest';
import {
  ENGAGEMENT_TEMPLATES,
  getTemplateById,
  getTemplatesByCategory,
  type EngagementTemplate,
} from './lib/engagement-templates';

describe('Engagement Templates', () => {
  describe('ENGAGEMENT_TEMPLATES constant', () => {
    it('should contain at least 5 templates', () => {
      expect(ENGAGEMENT_TEMPLATES.length).toBeGreaterThanOrEqual(5);
    });

    it('should have unique IDs across all templates', () => {
      const ids = ENGAGEMENT_TEMPLATES.map(t => t.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('should have unique names across all templates', () => {
      const names = ENGAGEMENT_TEMPLATES.map(t => t.name);
      expect(new Set(names).size).toBe(names.length);
    });

    it('each template should have all required fields', () => {
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        expect(tmpl.id).toBeTruthy();
        expect(tmpl.name).toBeTruthy();
        expect(tmpl.shortName).toBeTruthy();
        expect(tmpl.description).toBeTruthy();
        expect(tmpl.icon).toBeTruthy();
        expect(tmpl.category).toBeTruthy();
        expect(tmpl.engagementType).toBeTruthy();
        expect(tmpl.defaultDescription).toBeTruthy();
        expect(tmpl.defaultNotes).toBeTruthy();
        expect(tmpl.scopeGuidance).toBeTruthy();
        expect(tmpl.estimatedDuration).toBeTruthy();
        expect(tmpl.teamSize).toBeTruthy();
        expect(tmpl.difficulty).toBeTruthy();
        expect(tmpl.tags.length).toBeGreaterThan(0);
      }
    });

    it('each template should have valid engagement type', () => {
      const validTypes = ['pentest', 'red_team', 'phishing', 'purple_team', 'tabletop'];
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        expect(validTypes).toContain(tmpl.engagementType);
      }
    });

    it('each template should have valid difficulty level', () => {
      const validDifficulties = ['beginner', 'intermediate', 'advanced', 'expert'];
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        expect(validDifficulties).toContain(tmpl.difficulty);
      }
    });
  });

  describe('Scan Config', () => {
    it('each template should have a complete scan config', () => {
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        const sc = tmpl.scanConfig;
        expect(sc).toBeDefined();
        expect(typeof sc.nmapProfile).toBe('string');
        expect(typeof sc.nmapFlags).toBe('string');
        expect(Array.isArray(sc.nucleiTemplates)).toBe(true);
        expect(Array.isArray(sc.nucleiSeverity)).toBe(true);
        expect(typeof sc.zapPolicy).toBe('string');
        expect(['low', 'medium', 'high', 'insane']).toContain(sc.zapStrength);
        expect(['low', 'medium', 'high']).toContain(sc.zapThreshold);
        expect(typeof sc.wafEvasion).toBe('boolean');
        expect(typeof sc.throttleMs).toBe('number');
      }
    });

    it('tabletop template should have empty scan config', () => {
      const tabletop = getTemplateById('tabletop-exercise');
      expect(tabletop).toBeDefined();
      expect(tabletop!.scanConfig.nmapFlags).toBe('');
      expect(tabletop!.scanConfig.nucleiTemplates).toEqual([]);
    });

    it('red team template should have stealth nmap profile', () => {
      const redTeam = getTemplateById('full-scope-red-team');
      expect(redTeam).toBeDefined();
      expect(redTeam!.scanConfig.nmapProfile).toBe('stealth');
      expect(redTeam!.scanConfig.wafEvasion).toBe(true);
      expect(redTeam!.scanConfig.throttleMs).toBeGreaterThanOrEqual(500);
    });

    it('web app pentest should have WAF evasion enabled', () => {
      const webapp = getTemplateById('ext-webapp-pentest');
      expect(webapp).toBeDefined();
      expect(webapp!.scanConfig.wafEvasion).toBe(true);
    });
  });

  describe('Phase Config', () => {
    it('each template should have a complete phase config', () => {
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        const pc = tmpl.phaseConfig;
        expect(typeof pc.recon).toBe('boolean');
        expect(typeof pc.enumeration).toBe('boolean');
        expect(typeof pc.vulnDetection).toBe('boolean');
        expect(typeof pc.exploitation).toBe('boolean');
        expect(typeof pc.postExploit).toBe('boolean');
        expect(typeof pc.reporting).toBe('boolean');
        expect(typeof pc.autoAdvance).toBe('boolean');
        expect(typeof pc.requireApprovalForExploits).toBe('boolean');
        expect(typeof pc.requireApprovalForC2).toBe('boolean');
      }
    });

    it('tabletop should have all active phases disabled', () => {
      const tabletop = getTemplateById('tabletop-exercise');
      expect(tabletop!.phaseConfig.recon).toBe(false);
      expect(tabletop!.phaseConfig.enumeration).toBe(false);
      expect(tabletop!.phaseConfig.vulnDetection).toBe(false);
      expect(tabletop!.phaseConfig.exploitation).toBe(false);
      expect(tabletop!.phaseConfig.postExploit).toBe(false);
      expect(tabletop!.phaseConfig.reporting).toBe(true);
    });

    it('red team should require approval for C2 deployment', () => {
      const redTeam = getTemplateById('full-scope-red-team');
      expect(redTeam!.phaseConfig.requireApprovalForC2).toBe(true);
      expect(redTeam!.phaseConfig.requireApprovalForExploits).toBe(true);
    });

    it('phishing should not require exploit or C2 approval', () => {
      const phishing = getTemplateById('phishing-social-engineering');
      expect(phishing!.phaseConfig.requireApprovalForExploits).toBe(false);
      expect(phishing!.phaseConfig.requireApprovalForC2).toBe(false);
    });
  });

  describe('RoE Defaults', () => {
    it('each template should have complete RoE defaults', () => {
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        const roe = tmpl.roeDefaults;
        expect(roe.purpose).toBeTruthy();
        expect(roe.testingDays.length).toBeGreaterThan(0);
        expect(roe.testTimezone).toBeTruthy();
        expect(roe.testingHoursStart).toMatch(/^\d{2}:\d{2}$/);
        expect(roe.testingHoursEnd).toMatch(/^\d{2}:\d{2}$/);
        expect(roe.restrictions.length).toBeGreaterThan(0);
        expect(roe.allowedTechniques.length).toBeGreaterThan(0);
        expect(roe.prohibitedTechniques.length).toBeGreaterThan(0);
        expect(typeof roe.deconflictionProcess).toBe('string');
      }
    });

    it('red team should allow 24/7 testing', () => {
      const redTeam = getTemplateById('full-scope-red-team');
      expect(redTeam!.roeDefaults.testingDays).toContain('saturday');
      expect(redTeam!.roeDefaults.testingDays).toContain('sunday');
      expect(redTeam!.roeDefaults.testingHoursStart).toBe('00:00');
      expect(redTeam!.roeDefaults.testingHoursEnd).toBe('23:59');
    });

    it('no template RoE should contain customer-specific information', () => {
      for (const tmpl of ENGAGEMENT_TEMPLATES) {
        const roe = tmpl.roeDefaults;
        // RoE templates should be generic — no company names, no PII
        expect(roe.purpose).not.toMatch(/Acme|Example Corp|John Doe/i);
        expect(roe.deconflictionProcess).not.toMatch(/Acme|Example Corp|John Doe/i);
      }
    });
  });

  describe('getTemplateById', () => {
    it('should return the correct template by ID', () => {
      const result = getTemplateById('ext-webapp-pentest');
      expect(result).toBeDefined();
      expect(result!.name).toBe('External Web Application Pentest');
    });

    it('should return undefined for non-existent ID', () => {
      const result = getTemplateById('non-existent-template');
      expect(result).toBeUndefined();
    });

    it('should return each known template', () => {
      const knownIds = [
        'ext-webapp-pentest',
        'internal-network-pentest',
        'full-scope-red-team',
        'phishing-social-engineering',
        'cloud-infra-assessment',
        'purple-team-exercise',
        'tabletop-exercise',
      ];
      for (const id of knownIds) {
        expect(getTemplateById(id)).toBeDefined();
      }
    });
  });

  describe('getTemplatesByCategory', () => {
    it('should return pentest templates', () => {
      const pentests = getTemplatesByCategory('pentest');
      expect(pentests.length).toBeGreaterThanOrEqual(2);
      for (const t of pentests) {
        expect(t.category).toBe('pentest');
      }
    });

    it('should return red team templates', () => {
      const redTeam = getTemplatesByCategory('red_team');
      expect(redTeam.length).toBeGreaterThanOrEqual(1);
      for (const t of redTeam) {
        expect(t.category).toBe('red_team');
      }
    });

    it('should return empty array for unknown category', () => {
      const result = getTemplatesByCategory('unknown_category');
      expect(result).toEqual([]);
    });
  });

  describe('Template coverage', () => {
    it('should cover all 5 engagement types', () => {
      const types = new Set(ENGAGEMENT_TEMPLATES.map(t => t.engagementType));
      expect(types.has('pentest')).toBe(true);
      expect(types.has('red_team')).toBe(true);
      expect(types.has('phishing')).toBe(true);
      expect(types.has('purple_team')).toBe(true);
      expect(types.has('tabletop')).toBe(true);
    });

    it('should cover all difficulty levels', () => {
      const difficulties = new Set(ENGAGEMENT_TEMPLATES.map(t => t.difficulty));
      expect(difficulties.has('beginner')).toBe(true);
      expect(difficulties.has('intermediate')).toBe(true);
      expect(difficulties.has('advanced')).toBe(true);
      expect(difficulties.has('expert')).toBe(true);
    });
  });
});
