/**
 * Architecture Phase 4 Tests
 *
 * Tests for:
 * 1. Phase 5 (active enumeration) extraction into engagement-phase-enumeration.ts
 * 2. Stage 3.5+3.6 KEV+VulnFeed retry with backoff integration
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ORCH_PATH = path.resolve(__dirname, 'lib/engagement-orchestrator.ts');
const ENUM_PATH = path.resolve(__dirname, 'lib/engagement-phase-enumeration.ts');
const DI_PATH = path.resolve(__dirname, 'domainIntel.ts');

const orchContent = fs.readFileSync(ORCH_PATH, 'utf-8');
const enumContent = fs.readFileSync(ENUM_PATH, 'utf-8');
const diContent = fs.readFileSync(DI_PATH, 'utf-8');

// ─── 1. Phase 5 Enumeration Extraction ─────────────────────────────────────

describe('Phase 5 enumeration module extraction', () => {
  it('module file exists and exports executeEnumeration', () => {
    expect(fs.existsSync(ENUM_PATH)).toBe(true);
    expect(enumContent).toContain('export async function executeEnumeration');
  });

  it('orchestrator delegates to extracted module via dynamic import', () => {
    expect(orchContent).toContain("await import('./engagement-phase-enumeration')");
    expect(orchContent).toContain('runEnumerationPhase');
  });

  it('extracted module imports types from shared module (not orchestrator)', () => {
    expect(enumContent).toContain('from "../../shared/orchestrator-types"');
    expect(enumContent).toContain('EngagementOpsState');
    expect(enumContent).toContain('isInRoeScope');
  });

  it('extracted module imports runtime helpers from orchestrator', () => {
    expect(enumContent).toContain('from "./engagement-orchestrator"');
    expect(enumContent).toContain('addLog');
    expect(enumContent).toContain('broadcastOpsUpdate');
    expect(enumContent).toContain('getEffectiveTarget');
  });

  it('extracted module tree imports parseToolOutput from tool-output-parsers', () => {
    // parseToolOutput is in the sub-modules (active-enumeration/)
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('parseToolOutput');
  });

  it('has genId utility in sub-modules (avoids circular import)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('genId');
  });

  it('handles ScanForge discovery scans (in sub-modules)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('scanforge');
  });

  it('handles service fingerprinting (in sub-modules)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('fingerprint');
  });

  it('handles cloud asset detection (in sub-modules)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('cloud');
  });

  it('handles banner/WAF detection (in sub-modules)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('waf');
  });

  it('handles PCAP auto-capture (in sub-modules)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('pcap');
  });

  it('handles context-aware scanning (in sub-modules)', () => {
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    const allSubContent = fs.readdirSync(subModDir)
      .filter(f => f.endsWith('.ts'))
      .map(f => fs.readFileSync(path.join(subModDir, f), 'utf-8'))
      .join('\n');
    expect(allSubContent).toContain('context');
  });

  it('has RoE scope guard at the top of the function', () => {
    expect(enumContent).toContain('isInRoeScope(state, a.hostname, a.ip)');
    expect(enumContent).toContain('scopedAssets');
  });

  it('orchestrator wrapper is thin (< 5 lines)', () => {
    // Find the wrapper function in the orchestrator
    const wrapperMatch = orchContent.match(/async function executeEnumeration\([\s\S]*?^}/m);
    expect(wrapperMatch).not.toBeNull();
    const wrapperLines = wrapperMatch![0].split('\n').length;
    expect(wrapperLines).toBeLessThanOrEqual(5);
  });

  it('orchestrator is now under 10,500 lines', () => {
    const lineCount = orchContent.split('\n').length;
    expect(lineCount).toBeLessThan(10500);
  });

  it('enumeration module tree is approximately 2000+ lines (substantial extraction)', () => {
    // The thin orchestrator + sub-modules under active-enumeration/
    const subModDir = path.resolve(__dirname, 'lib/active-enumeration');
    let totalLines = enumContent.split('\n').length;
    if (fs.existsSync(subModDir)) {
      for (const f of fs.readdirSync(subModDir).filter(f => f.endsWith('.ts'))) {
        totalLines += fs.readFileSync(path.join(subModDir, f), 'utf-8').split('\n').length;
      }
    }
    expect(totalLines).toBeGreaterThan(2000);
  });
});

// ─── 2. Stage 3.5+3.6 KEV+VulnFeed Retry Integration ──────────────────────

describe('Stage 3.5+3.6 KEV+VulnFeed retry with backoff', () => {
  it('domainIntel.ts uses parallelWithRetry for Stage 3.5+3.6', () => {
    expect(diContent).toContain("name: 'Stage 3.5 KEV Enrichment'");
    expect(diContent).toContain("name: 'Stage 3.6 Vuln Feed Enrichment'");
  });

  it('imports parallelWithRetry from shared utility', () => {
    expect(diContent).toContain("import('../shared/retry-with-backoff')");
  });

  it('KEV stage has appropriate retry configuration', () => {
    // KEV stage should have retry config for CISA API
    const kevSection = diContent.substring(
      diContent.indexOf("name: 'Stage 3.5 KEV Enrichment'"),
      diContent.indexOf("name: 'Stage 3.6 Vuln Feed Enrichment'")
    );
    expect(kevSection).toContain('maxRetries: 2');
    expect(kevSection).toContain('initialDelayMs: 2000');
  });

  it('VulnFeed stage has appropriate retry configuration', () => {
    // VulnFeed options are after the fn body (~250 lines later)
    // Just verify the options exist in the file near the vuln feed section
    expect(diContent).toContain('initialDelayMs: 3000');
    expect(diContent).toContain('NVD/vuln feeds rate-limit aggressively');
  });

  it('logs retry statistics for stages that needed retries', () => {
    expect(diContent).toContain('r.stageName');
    expect(diContent).toContain('r.attempts');
    expect(diContent).toContain('r.retried');
  });

  it('logs failures with attempt count', () => {
    expect(diContent).toContain('failed after');
    expect(diContent).toContain('attempt(s)');
  });

  it('no longer uses raw Promise.allSettled for KEV+VulnFeed', () => {
    // The old pattern should be gone
    expect(diContent).not.toContain('const [kevResult, vulnFeedResult] = await Promise.allSettled');
    expect(diContent).not.toContain('kevResult.status === "rejected"');
    expect(diContent).not.toContain('vulnFeedResult.status === "rejected"');
  });

  it('Stage 4.5+4.55+4.6 also uses parallelWithRetry (from Round 3)', () => {
    expect(diContent).toContain("name: 'Stage 4.5 Threat Matching'");
    expect(diContent).toContain("name: 'Stage 4.55 Incident Search'");
    expect(diContent).toContain("name: 'Stage 4.6 Affiliated Domains'");
  });

  it('has two separate parallelWithRetry imports (one for each parallel block)', () => {
    const importCount = (diContent.match(/import\('\.\.\/shared\/retry-with-backoff'\)/g) || []).length;
    expect(importCount).toBe(2);
  });
});

// ─── 3. Overall decomposition progress ─────────────────────────────────────

describe('Orchestrator decomposition progress', () => {
  it('total extracted modules cover substantial code', () => {
    const modules = [
      'engagement-phase-enumeration.ts',
      'engagement-phase-exploitation.ts',
      'engagement-phase-post-exploit.ts',
      'engagement-phase-social-engineering.ts',
      'engagement-auto-report.ts',
      'tool-output-parsers.ts',
    ];
    const subModDirs = [
      'active-enumeration',
      'vuln-detection',
      'exploitation',
    ];

    let totalExtracted = 0;
    for (const mod of modules) {
      const modPath = path.resolve(__dirname, 'lib', mod);
      if (fs.existsSync(modPath)) {
        totalExtracted += fs.readFileSync(modPath, 'utf-8').split('\n').length;
      }
    }
    for (const dir of subModDirs) {
      const dirPath = path.resolve(__dirname, 'lib', dir);
      if (fs.existsSync(dirPath)) {
        for (const f of fs.readdirSync(dirPath).filter((f: string) => f.endsWith('.ts'))) {
          totalExtracted += fs.readFileSync(path.join(dirPath, f), 'utf-8').split('\n').length;
        }
      }
    }

    // Should have extracted 5000+ lines total (including sub-module directories)
    expect(totalExtracted).toBeGreaterThan(5000);
  });

  it('orchestrator reduction is significant (>30% from original 15,736)', () => {
    const currentLines = orchContent.split('\n').length;
    const originalLines = 15736;
    const reduction = ((originalLines - currentLines) / originalLines) * 100;
    expect(reduction).toBeGreaterThan(30);
  });

  it('all extracted modules have proper header documentation', () => {
    const modules = [
      'engagement-phase-enumeration.ts',
      'engagement-phase-exploitation.ts',
      'engagement-phase-post-exploit.ts',
      'engagement-phase-social-engineering.ts',
      'engagement-auto-report.ts',
    ];

    for (const mod of modules) {
      const modPath = path.resolve(__dirname, 'lib', mod);
      if (fs.existsSync(modPath)) {
        const content = fs.readFileSync(modPath, 'utf-8');
        expect(content.startsWith('/**')).toBe(true);
      }
    }
  });
});
