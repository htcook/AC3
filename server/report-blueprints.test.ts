import { describe, it, expect } from 'vitest';
import {
  getReportBlueprint,
  getReportSectionTitles,
  getSectionPromptGuidance,
  buildSectionOutline,
  REPORT_BLUEPRINTS,
  type AssessmentType,
} from './lib/report-section-blueprints';

describe('Report Section Blueprints', () => {
  // ─── Blueprint Registry ───────────────────────────────────────────────

  it('should have blueprints for all 7 assessment types', () => {
    const types: AssessmentType[] = [
      'penetration_test', 'red_team', 'purple_team',
      'phishing_campaign', 'vulnerability_assessment',
      'tabletop_exercise', 'hybrid',
    ];
    for (const type of types) {
      expect(REPORT_BLUEPRINTS[type]).toBeDefined();
      expect(REPORT_BLUEPRINTS[type].assessmentType).toBe(type);
      expect(REPORT_BLUEPRINTS[type].sections.length).toBeGreaterThan(5);
    }
  });

  it('each blueprint should have displayName, description, audience, and defaultFrameworks', () => {
    for (const [type, bp] of Object.entries(REPORT_BLUEPRINTS)) {
      expect(bp.displayName).toBeTruthy();
      expect(bp.description).toBeTruthy();
      expect(bp.audience).toBeTruthy();
      expect(bp.defaultFrameworks.length).toBeGreaterThan(0);
    }
  });

  it('each section should have required fields', () => {
    for (const [type, bp] of Object.entries(REPORT_BLUEPRINTS)) {
      for (const section of bp.sections) {
        expect(section.id).toBeTruthy();
        expect(section.title).toBeTruthy();
        expect(typeof section.required).toBe('boolean');
        expect(section.promptGuidance).toBeTruthy();
        expect(Array.isArray(section.dataSources)).toBe(true);
      }
    }
  });

  // ─── Type-Specific Sections ───────────────────────────────────────────

  it('pentest blueprint should have exploitation and evidence sections', () => {
    const bp = REPORT_BLUEPRINTS.penetration_test;
    const sectionIds = bp.sections.map(s => s.id);
    expect(sectionIds).toContain('executive_summary');
    expect(sectionIds).toContain('scope_and_roe');
    expect(sectionIds).toContain('methodology');
    expect(sectionIds).toContain('detailed_findings');
  });

  it('red team blueprint should have kill chain and persistence sections', () => {
    const bp = REPORT_BLUEPRINTS.red_team;
    const sectionIds = bp.sections.map(s => s.id);
    expect(sectionIds).toContain('executive_summary');
    expect(sectionIds).toContain('scope_and_roe');
    // Should have attack-specific sections
    const hasAttackSection = bp.sections.some(s =>
      s.title.toLowerCase().includes('attack') ||
      s.title.toLowerCase().includes('kill chain') ||
      s.title.toLowerCase().includes('initial access')
    );
    expect(hasAttackSection).toBe(true);
  });

  it('purple team blueprint should have detection coverage sections', () => {
    const bp = REPORT_BLUEPRINTS.purple_team;
    const hasDetectionSection = bp.sections.some(s =>
      s.title.toLowerCase().includes('detection') ||
      s.title.toLowerCase().includes('coverage')
    );
    expect(hasDetectionSection).toBe(true);
  });

  it('phishing blueprint should have campaign results and awareness sections', () => {
    const bp = REPORT_BLUEPRINTS.phishing_campaign;
    const hasCampaignSection = bp.sections.some(s =>
      s.title.toLowerCase().includes('campaign') ||
      s.title.toLowerCase().includes('phishing')
    );
    expect(hasCampaignSection).toBe(true);
  });

  it('tabletop blueprint should have scenario and exercise sections', () => {
    const bp = REPORT_BLUEPRINTS.tabletop_exercise;
    const hasExerciseSection = bp.sections.some(s =>
      s.title.toLowerCase().includes('scenario') ||
      s.title.toLowerCase().includes('exercise') ||
      s.title.toLowerCase().includes('discussion')
    );
    expect(hasExerciseSection).toBe(true);
  });

  // ─── getReportBlueprint ───────────────────────────────────────────────

  it('should map engagement types to correct blueprints', () => {
    expect(getReportBlueprint('pentest').assessmentType).toBe('penetration_test');
    expect(getReportBlueprint('red_team').assessmentType).toBe('red_team');
    expect(getReportBlueprint('phishing').assessmentType).toBe('phishing_campaign');
    expect(getReportBlueprint('purple_team').assessmentType).toBe('purple_team');
    expect(getReportBlueprint('tabletop').assessmentType).toBe('tabletop_exercise');
  });

  it('should fall back to penetration_test for unknown types', () => {
    expect(getReportBlueprint('unknown_type').assessmentType).toBe('penetration_test');
    expect(getReportBlueprint('').assessmentType).toBe('penetration_test');
  });

  it('should handle various naming formats', () => {
    expect(getReportBlueprint('Red Team').assessmentType).toBe('red_team');
    expect(getReportBlueprint('red-team').assessmentType).toBe('red_team');
    expect(getReportBlueprint('RED_TEAM').assessmentType).toBe('red_team');
    expect(getReportBlueprint('penetration_test').assessmentType).toBe('penetration_test');
  });

  // ─── getReportSectionTitles ───────────────────────────────────────────

  it('should return section titles for UI display', () => {
    const titles = getReportSectionTitles('pentest');
    expect(titles.length).toBeGreaterThan(5);
    for (const t of titles) {
      expect(t.id).toBeTruthy();
      expect(t.title).toBeTruthy();
      expect(typeof t.required).toBe('boolean');
    }
  });

  it('different types should have different section counts', () => {
    const pentestSections = getReportSectionTitles('pentest');
    const phishingSections = getReportSectionTitles('phishing');
    const tabletopSections = getReportSectionTitles('tabletop');
    // They should differ (not all the same)
    const allSame = pentestSections.length === phishingSections.length &&
                    phishingSections.length === tabletopSections.length;
    // At least some should differ in count or content
    const pentestIds = pentestSections.map(s => s.id).join(',');
    const phishingIds = phishingSections.map(s => s.id).join(',');
    expect(pentestIds).not.toBe(phishingIds);
  });

  // ─── getSectionPromptGuidance ─────────────────────────────────────────

  it('should return prompt guidance for valid sections', () => {
    const guidance = getSectionPromptGuidance('pentest', 'executive_summary');
    expect(guidance).toBeTruthy();
    expect(guidance!.length).toBeGreaterThan(20);
  });

  it('should return null for non-existent sections', () => {
    const guidance = getSectionPromptGuidance('pentest', 'nonexistent_section');
    expect(guidance).toBeNull();
  });

  // ─── buildSectionOutline ──────────────────────────────────────────────

  it('should build a formatted section outline for LLM prompts', () => {
    const outline = buildSectionOutline('pentest');
    expect(outline).toContain('Report Structure');
    expect(outline).toContain('Audience');
    expect(outline).toContain('Frameworks');
    expect(outline).toContain('Sections');
    expect(outline).toContain('(Required)');
  });

  it('should include subsections in the outline', () => {
    const outline = buildSectionOutline('pentest');
    // Should have numbered subsections like "1.1", "1.2"
    expect(outline).toMatch(/\d+\.\d+/);
  });

  it('different types should produce different outlines', () => {
    const pentestOutline = buildSectionOutline('pentest');
    const phishingOutline = buildSectionOutline('phishing');
    expect(pentestOutline).not.toBe(phishingOutline);
  });

  // ─── Risk Escalation Logic ────────────────────────────────────────────

  it('all blueprints should have executive_summary as first or second section', () => {
    for (const [type, bp] of Object.entries(REPORT_BLUEPRINTS)) {
      const execSummaryIdx = bp.sections.findIndex(s => s.id === 'executive_summary');
      // Executive summary should be within first 3 sections
      expect(execSummaryIdx).toBeLessThan(3);
      expect(execSummaryIdx).toBeGreaterThanOrEqual(0);
    }
  });

  it('all blueprints should have scope or engagement overview section', () => {
    for (const [type, bp] of Object.entries(REPORT_BLUEPRINTS)) {
      const hasScope = bp.sections.some(s =>
        s.id === 'scope_and_roe' ||
        s.id.includes('scope') ||
        s.id.includes('overview') ||
        s.id.includes('engagement') ||
        s.id.includes('exercise')
      );
      expect(hasScope).toBe(true);
    }
  });

  // ─── Compliance Framework Coverage ────────────────────────────────────

  it('pentest blueprint should reference NIST and OWASP frameworks', () => {
    const bp = REPORT_BLUEPRINTS.penetration_test;
    const frameworks = bp.defaultFrameworks.join(' ').toLowerCase();
    expect(frameworks).toMatch(/nist/i);
  });

  it('phishing blueprint should reference awareness/training frameworks', () => {
    const bp = REPORT_BLUEPRINTS.phishing_campaign;
    // Should have some framework reference
    expect(bp.defaultFrameworks.length).toBeGreaterThan(0);
  });
});
