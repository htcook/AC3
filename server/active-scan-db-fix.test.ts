import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('Active Scan db.default Fix', () => {
  it('engagement-orchestrator.ts does NOT use db.default pattern', () => {
    const filePath = path.join(__dirname, 'lib/engagement-orchestrator.ts');
    const content = fs.readFileSync(filePath, 'utf-8');
    // The bug was: db.default.getEngagementById — should be db.getEngagementById
    expect(content).not.toContain('db.default.');
  });

  it('executeEngagement uses db.getEngagementById (not db.default)', () => {
    const filePath = path.join(__dirname, 'lib/engagement-orchestrator.ts');
    const content = fs.readFileSync(filePath, 'utf-8');
    // Find the executeEngagement function and verify the correct import pattern
    const execEngIdx = content.indexOf('export async function executeEngagement');
    expect(execEngIdx).toBeGreaterThan(-1);
    const execEngBlock = content.slice(execEngIdx, execEngIdx + 800);
    expect(execEngBlock).toContain('await db.getEngagementById(engagementId)');
  });

  it('no router files use db.default pattern', () => {
    const routersDir = path.join(__dirname, 'routers');
    const files = fs.readdirSync(routersDir).filter(f => f.endsWith('.ts') && !f.includes('.test.'));
    for (const file of files) {
      const content = fs.readFileSync(path.join(routersDir, file), 'utf-8');
      expect(content, `${file} should not use db.default`).not.toContain('db.default.');
    }
  });

  it('no lib files use db.default pattern', () => {
    const libDir = path.join(__dirname, 'lib');
    const files = fs.readdirSync(libDir).filter(f => f.endsWith('.ts') && !f.includes('.test.'));
    for (const file of files) {
      const content = fs.readFileSync(path.join(libDir, file), 'utf-8');
      expect(content, `${file} should not use db.default`).not.toContain('db.default.');
    }
  });

  it('broadcastOpsUpdate is exported from engagement-orchestrator', () => {
    const filePath = path.join(__dirname, 'lib/engagement-orchestrator.ts');
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toContain('export function broadcastOpsUpdate');
  });

  it('all dynamic imports in engagement-ops-core.ts use correct relative paths', () => {
    const filePath = path.join(__dirname, 'routers/engagement-ops-core.ts');
    const content = fs.readFileSync(filePath, 'utf-8');
    const dynamicImports = content.match(/await import\(['"]([^'"]+)['"]\)/g) || [];
    for (const imp of dynamicImports) {
      const importPath = imp.match(/['"]([^'"]+)['"]/)?.[1] || '';
      // All imports from engagement-ops-core.ts (in server/routers/) should use ../
      if (importPath.startsWith('.')) {
        expect(importPath, `Dynamic import path should start with ../`).toMatch(/^\.\.\//);
      }
    }
  });
});
