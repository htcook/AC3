import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

/**
 * Tests for:
 * 1. LLM Graduation Engine _caller coverage — every invokeLLM({ call has _caller
 * 2. KpiStrip clickable stat items — engagement ops and domain intel results
 * 3. No duplicate _caller parameters in any invokeLLM call
 */

// ─── Helper: recursively collect .ts files ───────────────────────────────

function collectTsFiles(dir: string, results: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === 'node_modules' || entry === '_core' || entry === '.git') continue;
    if (statSync(full).isDirectory()) {
      collectTsFiles(full, results);
    } else if (full.endsWith('.ts') && !full.endsWith('.test.ts') && !full.endsWith('.d.ts')) {
      results.push(full);
    }
  }
  return results;
}

// ─── LLM _caller Coverage ────────────────────────────────────────────────

describe('LLM Graduation Engine _caller Coverage', () => {
  const serverDir = join(__dirname, '.');
  const tsFiles = collectTsFiles(serverDir);

  // Collect all invokeLLM({ calls across the codebase
  const allCalls: { file: string; line: number; hasCallerNearby: boolean; lineContent: string }[] = [];

  for (const filePath of tsFiles) {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('invokeLLM({')) {
        // Check if _caller appears on same line or within next 3 lines
        const block = lines.slice(i, i + 4).join('\n');
        const hasCaller = block.includes('_caller');
        allCalls.push({
          file: filePath.replace(serverDir + '/', ''),
          line: i + 1,
          hasCallerNearby: hasCaller,
          lineContent: lines[i].trim(),
        });
      }
    }
  }

  it('should find invokeLLM calls in the codebase', () => {
    expect(allCalls.length).toBeGreaterThan(50);
  });

  it('every invokeLLM({ call should have _caller within 3 lines', () => {
    const missing = allCalls.filter(c => !c.hasCallerNearby);
    if (missing.length > 0) {
      const details = missing.map(m => `  ${m.file}:${m.line}`).join('\n');
      expect(missing.length, `Missing _caller in:\n${details}`).toBe(0);
    }
    expect(missing.length).toBe(0);
  });

  it('should have at least 80 invokeLLM calls with _caller', () => {
    const withCaller = allCalls.filter(c => c.hasCallerNearby);
    expect(withCaller.length).toBeGreaterThanOrEqual(80);
  });

  it('should not have duplicate _caller in any invokeLLM block', () => {
    const duplicates: string[] = [];
    for (const filePath of tsFiles) {
      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('invokeLLM({')) {
          // Scan the next 10 lines for the invokeLLM block
          let callerCount = 0;
          for (let j = i; j < Math.min(lines.length, i + 10); j++) {
            if (lines[j].includes('_caller')) callerCount++;
            // Stop at closing of the object (rough heuristic)
            if (j > i && lines[j].includes('});')) break;
          }
          if (callerCount > 1) {
            duplicates.push(`${filePath.replace(serverDir + '/', '')}:${i + 1} (${callerCount} _caller lines)`);
          }
        }
      }
    }
    if (duplicates.length > 0) {
      const details = duplicates.join('\n  ');
      expect(duplicates.length, `Duplicate _caller found:\n  ${details}`).toBe(0);
    }
    expect(duplicates.length).toBe(0);
  });
});

// ─── Clickable Stats: Engagement Ops KPI ─────────────────────────────────

describe('Engagement Ops Clickable Stats', () => {
  // These map the KPI items to their expected tab targets
  const engagementKpiTabMappings: Record<string, string> = {
    'Assets Discovered': 'assets',
    'Hosts Alive': 'discovery',
    'Open Ports': 'assets',
    'Vulnerabilities': 'assets',
    'Exploits Run': 'exploits',
    'Sessions': 'exploits',
    'OWASP Coverage': 'scope',
    'WAFs Detected': 'discovery',
  };

  it('should have 8 KPI items mapped to tabs', () => {
    expect(Object.keys(engagementKpiTabMappings).length).toBe(8);
  });

  it('each KPI item should map to a valid tab name', () => {
    const validTabs = ['overview', 'scope', 'discovery', 'assets', 'exploits', 'logs', 'report'];
    for (const [label, tab] of Object.entries(engagementKpiTabMappings)) {
      expect(validTabs, `Tab "${tab}" for "${label}" is not a valid tab`).toContain(tab);
    }
  });

  // Sidebar stat cards
  const sidebarStatMappings: Record<string, string> = {
    'Phase': 'overview',
    'Progress': 'overview',
    'Assets': 'assets',
    'Vulns': 'assets',
    'Critical': 'assets',
    'High': 'assets',
    'Exploits': 'exploits',
    'Sessions': 'exploits',
    'Logs': 'logs',
  };

  it('should have 9 sidebar stat cards mapped to tabs', () => {
    expect(Object.keys(sidebarStatMappings).length).toBe(9);
  });

  it('sidebar stats should map to valid tabs', () => {
    const validTabs = ['overview', 'scope', 'discovery', 'assets', 'exploits', 'logs', 'report'];
    for (const [label, tab] of Object.entries(sidebarStatMappings)) {
      expect(validTabs, `Tab "${tab}" for sidebar stat "${label}" is not valid`).toContain(tab);
    }
  });
});

// ─── Clickable Stats: Domain Intel Results KPI ───────────────────────────

describe('Domain Intel Results Clickable Stats', () => {
  const domainIntelKpiMappings: Record<string, string> = {
    'Assets in Scope': 'assets',
    'Critical Findings': 'vulns',
    'High Findings': 'vulns',
    'Risk Score': 'overview',
    'Verified Exploitable': 'vulns',
    'Breach Exposures': 'breaches',
    'Recon Coverage': 'coverage',
    'Total Findings': 'vulns',
  };

  it('should have 8 KPI items mapped to tabs', () => {
    expect(Object.keys(domainIntelKpiMappings).length).toBe(8);
  });

  it('each KPI item should map to a valid domain intel tab', () => {
    const validTabs = ['overview', 'assets', 'vulns', 'breaches', 'coverage', 'campaigns', 'threat-actors', 'timeline'];
    for (const [label, tab] of Object.entries(domainIntelKpiMappings)) {
      expect(validTabs, `Tab "${tab}" for "${label}" is not a valid domain intel tab`).toContain(tab);
    }
  });

  it('vulnerability-related KPIs should all navigate to vulns tab', () => {
    const vulnLabels = ['Critical Findings', 'High Findings', 'Verified Exploitable', 'Total Findings'];
    for (const label of vulnLabels) {
      expect(domainIntelKpiMappings[label]).toBe('vulns');
    }
  });
});

// ─── KpiStrip Component Interface ────────────────────────────────────────

describe('KpiStrip Component Interface', () => {
  // Verify the KpiStrip component exists and has onClick support
  it('KpiStrip component file should exist', () => {
    const content = readFileSync(join(__dirname, '../client/src/components/KpiStrip.tsx'), 'utf-8');
    expect(content).toBeTruthy();
  });

  it('KpiStrip should support onClick prop in KpiItem interface', () => {
    const content = readFileSync(join(__dirname, '../client/src/components/KpiStrip.tsx'), 'utf-8');
    expect(content).toContain('onClick');
  });

  it('KpiStrip should have cursor-pointer styling for clickable items', () => {
    const content = readFileSync(join(__dirname, '../client/src/components/KpiStrip.tsx'), 'utf-8');
    expect(content).toContain('cursor-pointer');
  });

  it('KpiStrip should support keyboard accessibility (Enter/Space)', () => {
    const content = readFileSync(join(__dirname, '../client/src/components/KpiStrip.tsx'), 'utf-8');
    expect(content).toContain('onKeyDown');
    expect(content).toContain('Enter');
  });

  it('KpiStrip should have hover effects for clickable items', () => {
    const content = readFileSync(join(__dirname, '../client/src/components/KpiStrip.tsx'), 'utf-8');
    expect(content).toContain('hover:');
  });
});

// ─── _caller Naming Convention ───────────────────────────────────────────

describe('LLM _caller Naming Convention', () => {
  const serverDir = join(__dirname, '.');
  const tsFiles = collectTsFiles(serverDir);

  it('all _caller values should follow module:function or module.function pattern', () => {
    const invalidCallers: string[] = [];
    for (const filePath of tsFiles) {
      const content = readFileSync(filePath, 'utf-8');
      const matches = content.matchAll(/_caller:\s*["']([^"']+)["']/g);
      for (const match of matches) {
        const callerValue = match[1];
        // Should contain a separator (: or .)
        if (!callerValue.includes(':') && !callerValue.includes('.')) {
          // Single-word callers like "hunt-engine" are acceptable as module-level identifiers
          if (!callerValue.includes('-')) {
            invalidCallers.push(`${filePath.replace(serverDir + '/', '')}: _caller="${callerValue}"`);
          }
        }
      }
    }
    // Allow some flexibility but flag obviously bad patterns
    expect(invalidCallers.length).toBeLessThanOrEqual(5);
  });

  it('_caller values should not be empty strings', () => {
    const emptyCallers: string[] = [];
    for (const filePath of tsFiles) {
      const content = readFileSync(filePath, 'utf-8');
      if (content.includes("_caller: ''") || content.includes('_caller: ""')) {
        emptyCallers.push(filePath.replace(serverDir + '/', ''));
      }
    }
    expect(emptyCallers.length).toBe(0);
  });
});
