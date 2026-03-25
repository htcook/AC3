// @ts-nocheck
import { describe, it, expect } from 'vitest';
import {
  GROUND_TRUTH_LIBRARY,
  scoreAgainstGroundTruth,
} from './lib/llm-self-learning';

// ─── Ground Truth Expansion Tests ──────────────────────────────────────────

describe('Ground Truth Library Expansion', () => {
  it('should have WebGoat ground truth entries', () => {
    const webgoat = GROUND_TRUTH_LIBRARY['webgoat'];
    expect(webgoat).toBeDefined();
    expect(webgoat.length).toBeGreaterThanOrEqual(20);
  });

  it('should have bWAPP ground truth with autoDetectable tags', () => {
    const bwapp = GROUND_TRUTH_LIBRARY['bwapp'];
    expect(bwapp).toBeDefined();
    expect(bwapp.length).toBeGreaterThan(0);
    // Every entry should have autoDetectable defined
    for (const entry of bwapp) {
      expect(typeof entry.autoDetectable).toBe('boolean');
    }
  });

  it('should have Mutillidae ground truth with autoDetectable tags', () => {
    const mutillidae = GROUND_TRUTH_LIBRARY['mutillidae'];
    expect(mutillidae).toBeDefined();
    expect(mutillidae.length).toBeGreaterThan(0);
    for (const entry of mutillidae) {
      expect(typeof entry.autoDetectable).toBe('boolean');
    }
  });

  it('should have crAPI ground truth with autoDetectable tags', () => {
    const crapi = GROUND_TRUTH_LIBRARY['crapi'];
    expect(crapi).toBeDefined();
    expect(crapi.length).toBeGreaterThan(0);
    for (const entry of crapi) {
      expect(typeof entry.autoDetectable).toBe('boolean');
    }
  });

  it('should have WebGoat ground truth with autoDetectable tags', () => {
    const webgoat = GROUND_TRUTH_LIBRARY['webgoat'];
    expect(webgoat).toBeDefined();
    for (const entry of webgoat) {
      expect(typeof entry.autoDetectable).toBe('boolean');
    }
  });

  it('should have DVWA ground truth with autoDetectable tags', () => {
    const dvwa = GROUND_TRUTH_LIBRARY['dvwa'];
    expect(dvwa).toBeDefined();
    for (const entry of dvwa) {
      expect(typeof entry.autoDetectable).toBe('boolean');
    }
  });

  it('should have Juice Shop ground truth with autoDetectable tags', () => {
    const juiceshop = GROUND_TRUTH_LIBRARY['juice-shop'];
    expect(juiceshop).toBeDefined();
    for (const entry of juiceshop) {
      expect(typeof entry.autoDetectable).toBe('boolean');
    }
  });
});

// ─── AutoDetectable Tiering Tests ──────────────────────────────────────────

describe('AutoDetectable Tiering', () => {
  it('DVWA should have correct autoDetectable distribution', () => {
    const dvwa = GROUND_TRUTH_LIBRARY['dvwa'];
    const autoDetectable = dvwa.filter(v => v.autoDetectable === true);
    const manualOnly = dvwa.filter(v => v.autoDetectable === false);
    // DVWA has 11 auto-detectable and 3 manual-only
    expect(autoDetectable.length).toBeGreaterThanOrEqual(10);
    expect(manualOnly.length).toBeGreaterThanOrEqual(2);
    expect(autoDetectable.length + manualOnly.length).toBe(dvwa.length);
  });

  it('Juice Shop should have correct autoDetectable distribution', () => {
    const js = GROUND_TRUTH_LIBRARY['juice-shop'];
    const autoDetectable = js.filter(v => v.autoDetectable === true);
    const manualOnly = js.filter(v => v.autoDetectable === false);
    // Juice Shop has many manual-only vulns (business logic, 2FA bypass, etc.)
    expect(autoDetectable.length).toBeGreaterThanOrEqual(10);
    expect(manualOnly.length).toBeGreaterThanOrEqual(10);
  });

  it('WebGoat should have correct autoDetectable distribution', () => {
    const wg = GROUND_TRUTH_LIBRARY['webgoat'];
    const autoDetectable = wg.filter(v => v.autoDetectable === true);
    const manualOnly = wg.filter(v => v.autoDetectable === false);
    // WebGoat has ~12 auto-detectable (SQLi, XSS, CSRF, SSRF) and ~14 manual-only
    expect(autoDetectable.length).toBeGreaterThanOrEqual(10);
    expect(manualOnly.length).toBeGreaterThanOrEqual(10);
  });

  it('bWAPP should have mostly auto-detectable vulns', () => {
    const bwapp = GROUND_TRUTH_LIBRARY['bwapp'];
    const autoDetectable = bwapp.filter(v => v.autoDetectable === true);
    // bWAPP is designed for automated testing, so most should be auto-detectable
    expect(autoDetectable.length).toBeGreaterThan(bwapp.length * 0.5);
  });

  it('crAPI should have mostly manual-only vulns (API testing)', () => {
    const crapi = GROUND_TRUTH_LIBRARY['crapi'];
    const manualOnly = crapi.filter(v => v.autoDetectable === false);
    // crAPI is API-focused, most vulns need manual testing
    expect(manualOnly.length).toBeGreaterThan(crapi.length * 0.5);
  });
});

// ─── AutoDetectable Scoring Tests ──────────────────────────────────────────

describe('scoreAgainstGroundTruth with autoDetectableOnly', () => {
  it('should score against all ground truth when autoDetectableOnly is false', () => {
    const findings = [
      { title: 'SQL Injection', severity: 'critical' },
      { title: 'XSS - Reflected', severity: 'high' },
    ];
    const fullScore = scoreAgainstGroundTruth('dvwa', findings, { autoDetectableOnly: false });
    expect(fullScore).not.toBeNull();
    expect(fullScore!.autoDetectableOnly).toBe(false);
    // Full ground truth includes manual-only vulns, so more FN
    expect(fullScore!.totalGroundTruth).toBe(GROUND_TRUTH_LIBRARY['dvwa'].length);
  });

  it('should score against only auto-detectable ground truth when autoDetectableOnly is true', () => {
    const findings = [
      { title: 'SQL Injection', severity: 'critical' },
      { title: 'XSS - Reflected', severity: 'high' },
    ];
    const autoScore = scoreAgainstGroundTruth('dvwa', findings, { autoDetectableOnly: true });
    expect(autoScore).not.toBeNull();
    expect(autoScore!.autoDetectableOnly).toBe(true);
    // Auto-detectable ground truth should be smaller than full
    const autoDetectableCount = GROUND_TRUTH_LIBRARY['dvwa'].filter(v => v.autoDetectable !== false).length;
    expect(autoScore!.totalGroundTruth).toBe(autoDetectableCount);
    expect(autoScore!.totalGroundTruth).toBeLessThan(GROUND_TRUTH_LIBRARY['dvwa'].length);
  });

  it('autoDetectable scoring should give higher recall than full scoring', () => {
    // Same findings should have higher recall against smaller ground truth
    const findings = [
      { title: 'SQL Injection', severity: 'critical' },
      { title: 'XSS - Reflected', severity: 'high' },
      { title: 'Command Injection', severity: 'critical' },
      { title: 'CSRF', severity: 'medium' },
    ];
    const fullScore = scoreAgainstGroundTruth('dvwa', findings, { autoDetectableOnly: false });
    const autoScore = scoreAgainstGroundTruth('dvwa', findings, { autoDetectableOnly: true });
    expect(fullScore).not.toBeNull();
    expect(autoScore).not.toBeNull();
    // Recall should be higher (or equal) with autoDetectable-only since fewer FN
    expect(autoScore!.recall).toBeGreaterThanOrEqual(fullScore!.recall);
  });

  it('should return totalGroundTruthFull for reference', () => {
    const findings = [{ title: 'SQL Injection', severity: 'critical' }];
    const autoScore = scoreAgainstGroundTruth('dvwa', findings, { autoDetectableOnly: true });
    expect(autoScore).not.toBeNull();
    expect(autoScore!.totalGroundTruthFull).toBe(GROUND_TRUTH_LIBRARY['dvwa'].length);
  });
});

// ─── WebGoat Scoring Tests ──────────────────────────────────────────────────

describe('WebGoat Ground Truth Scoring', () => {
  it('should match WebGoat SQL Injection findings', () => {
    const findings = [
      { title: 'SQL Injection', severity: 'critical' },
      { title: 'Cross-Site Scripting (Reflected)', severity: 'high' },
      { title: 'XML External Entity (XXE)', severity: 'critical' },
      { title: 'Server-Side Request Forgery', severity: 'high' },
      { title: 'Cross-Site Request Forgery', severity: 'high' },
    ];
    const score = scoreAgainstGroundTruth('webgoat', findings, { autoDetectableOnly: true });
    expect(score).not.toBeNull();
    expect(score!.truePositives).toBeGreaterThanOrEqual(3);
  });

  it('should correctly filter WebGoat manual-only vulns', () => {
    const wg = GROUND_TRUTH_LIBRARY['webgoat'];
    const manualVulns = wg.filter(v => v.autoDetectable === false);
    // JWT, Auth Bypass, IDOR, Client-Side, Crypto should be manual-only
    const manualTitles = manualVulns.map(v => v.title);
    expect(manualTitles).toContain('JWT Token Manipulation');
    expect(manualTitles).toContain('Authentication Bypass');
    expect(manualTitles).toContain('Insecure Direct Object Reference (IDOR)');
  });
});

// ─── Cross-Target Consistency Tests ──────────────────────────────────────────

describe('Cross-Target Ground Truth Consistency', () => {
  const allTargets = Object.keys(GROUND_TRUTH_LIBRARY);

  it('should have at least 6 training targets', () => {
    // dvwa, juice-shop, webgoat, bwapp, mutillidae, crapi, scanme-nmap
    expect(allTargets.length).toBeGreaterThanOrEqual(6);
  });

  it('every entry should have required fields', () => {
    for (const target of allTargets) {
      const vulns = GROUND_TRUTH_LIBRARY[target];
      for (const vuln of vulns) {
        expect(vuln.title).toBeDefined();
        expect(vuln.title.length).toBeGreaterThan(0);
        expect(vuln.category).toBeDefined();
        expect(vuln.severity).toBeDefined();
        expect(vuln.description).toBeDefined();
      }
    }
  });

  it('training targets (not scanme-nmap) should all have autoDetectable tags', () => {
    const trainingTargets = allTargets.filter(t => t !== 'scanme-nmap');
    for (const target of trainingTargets) {
      const vulns = GROUND_TRUTH_LIBRARY[target];
      for (const vuln of vulns) {
        expect(typeof vuln.autoDetectable).toBe('boolean');
      }
    }
  });
});
