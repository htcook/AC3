/**
 * Frontend Tab Additions Tests
 * 
 * Validates that the new LLM Synthesis and Exploit Code tabs
 * are properly integrated into the EngagementOps page.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

const engagementOpsPath = join(__dirname, '../client/src/pages/EngagementOps.tsx');
const source = readFileSync(engagementOpsPath, 'utf-8');

describe('LLM Synthesis Tab', () => {
  it('should have a TabsTrigger for llmsynthesis', () => {
    expect(source).toContain('value="llmsynthesis"');
  });

  it('should have a TabsContent for llmsynthesis', () => {
    expect(source).toContain('TabsContent value="llmsynthesis"');
  });

  it('should display Brain icon for LLM Synthesis tab', () => {
    // The Brain icon should be in the tab trigger
    const tabTriggerMatch = source.match(/TabsTrigger value="llmsynthesis"[\s\S]*?<Brain/);
    expect(tabTriggerMatch).toBeTruthy();
  });

  it('should count synthesized vulns by filtering tool === llm-synthesis', () => {
    expect(source).toContain("v.tool === 'llm-synthesis'");
  });

  it('should display per-asset synthesized vulnerability cards', () => {
    // Should filter vulns by llm-synthesis tool and render per-asset
    expect(source).toContain('synthVulns.length === 0');
    expect(source).toContain('synthesized');
  });

  it('should show confidence scores for synthesized vulns', () => {
    expect(source).toContain('v.confidence');
    expect(source).toContain('conf');
  });

  it('should show vulnerability categories', () => {
    expect(source).toContain('v.category');
  });

  it('should have a Re-Synthesize button per asset', () => {
    expect(source).toContain('Re-Synthesize');
  });

  it('should trigger rerunMut with passive + llmAnalysis phases on Re-Synthesize', () => {
    // The Re-Synthesize button should call rerunMut with specific phases
    const reSynthMatch = source.match(/Re-Synthesize[\s\S]*?rerunMut\.mutate/);
    expect(reSynthMatch).toBeTruthy();
    expect(source).toContain('passive: true, active: false, llmAnalysis: true, exploitGeneration: false');
  });

  it('should display LLM Analysis summary with attack paths and blind spots', () => {
    expect(source).toContain('llmAnalysis.attackPaths');
    expect(source).toContain('llmAnalysis.blindSpots');
    expect(source).toContain('LLM Post-Enrichment Analysis');
  });

  it('should show empty state when no synthesized vulns exist', () => {
    expect(source).toContain('No LLM-synthesized vulnerabilities yet');
  });

  it('should sort synthesized vulns by severity', () => {
    expect(source).toContain('synthVulns.sort');
    expect(source).toContain('critical: 4, high: 3, medium: 2, low: 1');
  });
});

describe('Generated Exploit Code Tab', () => {
  it('should have a TabsTrigger for genexploits', () => {
    expect(source).toContain('value="genexploits"');
  });

  it('should have a TabsContent for genexploits', () => {
    expect(source).toContain('TabsContent value="genexploits"');
  });

  it('should display Bolt icon for Exploit Code tab', () => {
    const tabTriggerMatch = source.match(/TabsTrigger value="genexploits"[\s\S]*?<Bolt/);
    expect(tabTriggerMatch).toBeTruthy();
  });

  it('should use generatedExploitsQ query data', () => {
    expect(source).toContain('generatedExploitsQ.data');
  });

  it('should display summary stats grid (total, avg confidence, assets, languages)', () => {
    expect(source).toContain('Total Exploits');
    expect(source).toContain('Avg Confidence');
    expect(source).toContain('Assets Covered');
    expect(source).toContain('Languages');
  });

  it('should display exploit cards with filename, confidence, and description', () => {
    expect(source).toContain('exploit.filename');
    expect(source).toContain('exploit.confidence');
    expect(source).toContain('exploit.description');
  });

  it('should have View Code button that sets viewingExploitIdx', () => {
    expect(source).toContain('View Code');
    expect(source).toContain('setViewingExploitIdx');
  });

  it('should have Validate button using validateExploitMut', () => {
    expect(source).toContain('validateExploitMut.mutate');
  });

  it('should have Improve button using improveExploitMut', () => {
    expect(source).toContain('improveExploitMut.mutate');
  });

  it('should display MITRE ATT&CK technique badges', () => {
    expect(source).toContain('mitreTechniques');
  });

  it('should show chained exploit indicator', () => {
    expect(source).toContain('exploit.isChained');
    expect(source).toContain('Chained');
  });

  it('should show empty state when no exploits generated', () => {
    expect(source).toContain('No exploit code generated yet');
  });

  it('should display exploit language and target asset', () => {
    expect(source).toContain('exploit.language');
    expect(source).toContain('exploit.asset');
  });
});

describe('Tab Order and Integration', () => {
  it('should have llmsynthesis tab between feedback and planhistory triggers', () => {
    const feedbackIdx = source.indexOf('value="feedback"');
    const llmSynthIdx = source.indexOf('value="llmsynthesis"');
    const genExploitsIdx = source.indexOf('value="genexploits"');
    const planHistoryIdx = source.indexOf('value="planhistory"');
    
    expect(feedbackIdx).toBeLessThan(llmSynthIdx);
    expect(llmSynthIdx).toBeLessThan(genExploitsIdx);
    expect(genExploitsIdx).toBeLessThan(planHistoryIdx);
  });

  it('should have all required icon imports', () => {
    expect(source).toContain('Brain');
    expect(source).toContain('Bolt');
    expect(source).toContain('Sparkles');
    expect(source).toContain('Skull');
    expect(source).toContain('AlertTriangle');
  });

  it('should have ScrollArea wrapper for both new tabs', () => {
    // Both tabs should use ScrollArea for overflow handling
    const llmContent = source.slice(
      source.indexOf('TabsContent value="llmsynthesis"'),
      source.indexOf('TabsContent value="genexploits"')
    );
    expect(llmContent).toContain('ScrollArea');

    const exploitContent = source.slice(
      source.indexOf('TabsContent value="genexploits"'),
      source.indexOf('TabsContent value="planhistory"')
    );
    expect(exploitContent).toContain('ScrollArea');
  });
});
