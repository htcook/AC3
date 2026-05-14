/**
 * Tests for Attack Planner Specialist prompt size management.
 *
 * Validates that the attack planner correctly:
 * 1. Caps total prompt size to prevent 429 "Request too large" errors
 * 2. Uses compact domain context instead of full knowledge base
 * 3. Truncates passiveReconSummary when it exceeds budget
 * 4. Does not duplicate asset data in system prompt
 * 5. Falls back gracefully with budget-aware truncation
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the LLM call to capture what gets sent
const mockThrottledLLMCall = vi.fn().mockResolvedValue({
  choices: [{ message: { content: JSON.stringify({
    attack_objective: 'Test objective',
    initial_access_options: [],
    attack_chain: [],
    scan_plan: { discovery_targets: [], nuclei_targets: [], web_scan_targets: [] },
    detection_opportunities: [],
    estimated_impact: 'Low',
    confidence: 'Medium',
  }) } }],
});

vi.mock('../server/lib/llm-throttle', () => ({
  throttledLLMCall: (...args: any[]) => mockThrottledLLMCall(...args),
}));

vi.mock('../server/_core/llm', () => ({
  invokeLLM: vi.fn(),
}));

describe('Attack Planner Prompt Size Management', () => {
  beforeEach(() => {
    mockThrottledLLMCall.mockClear();
  });

  const makeInput = (assetCount: number, reconSize: number) => ({
    passiveReconSummary: 'A'.repeat(reconSize),
    engagement: {
      engagementType: 'pentest',
      clientName: 'TestCorp',
      targetCount: assetCount,
    },
    assets: Array.from({ length: assetCount }, (_, i) => ({
      hostname: `host${i}.testcorp.com`,
      ip: `10.0.0.${i}`,
      type: 'web_server',
      ports: [{ port: 80, service: 'http' }, { port: 443, service: 'https' }],
      technologies: ['nginx', 'php'],
    })),
    engagementId: 1,
  });

  it('should cap total prompt under MAX_SPECIALIST_CHARS (40K)', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    // Send a very large passiveReconSummary (100K chars)
    await planAttack(makeInput(15, 100_000));

    expect(mockThrottledLLMCall).toHaveBeenCalledTimes(1);
    const call = mockThrottledLLMCall.mock.calls[0][0];
    const systemLen = call.messages[0].content.length;
    const userLen = call.messages[1].content.length;
    const totalLen = systemLen + userLen;

    // Total should be under 42K (40K budget + some overhead from markers)
    expect(totalLen).toBeLessThan(42_000);
    // User message should contain truncation marker
    expect(call.messages[1].content).toContain('[...truncated to fit token budget]');
  });

  it('should NOT include buildAssetContext in system prompt (assets are in passiveReconSummary)', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(5, 5000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const systemPrompt = call.messages[0].content;

    // System prompt should NOT contain "## Assets in Scope" section
    // (that's what buildAssetContext adds via assembleSystemPrompt)
    expect(systemPrompt).not.toContain('## Assets in Scope');
    // But it should contain the role prompt
    expect(systemPrompt).toContain('Attack Path Planner');
  });

  it('should use compact banking context for banking targets', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    const input = makeInput(3, 5000);
    input.assets[0].hostname = 'altoro-mutual.bank.com';

    await planAttack(input);

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const systemPrompt = call.messages[0].content;

    // Should contain compact banking hint, NOT full taxonomy
    expect(systemPrompt).toContain('BANKING SECTOR ENGAGEMENT');
    // Should NOT contain the full banking vuln taxonomy
    expect(systemPrompt).not.toContain('BANK-AUTH-001');
    expect(systemPrompt).not.toContain('BANKING_REGULATORY_CONTEXT');
  });

  it('should limit missed vuln context to top 5 patterns', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(3, 5000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const systemPrompt = call.messages[0].content;

    // Count the number of missed vuln pattern lines (each starts with "- **")
    const missedVulnSection = systemPrompt.split('## Key Missed Vulnerabilities')[1] || '';
    const patternLines = missedVulnSection.split('\n').filter((l: string) => l.trim().startsWith('- **'));
    expect(patternLines.length).toBeLessThanOrEqual(5);
  });

  it('should not truncate small passiveReconSummary', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(3, 2000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const userMessage = call.messages[1].content;

    // Small recon should not be truncated
    expect(userMessage).not.toContain('[...truncated');
  });

  it('should always include engagement context in system prompt', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(5, 5000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const systemPrompt = call.messages[0].content;

    expect(systemPrompt).toContain('## Engagement Context');
    expect(systemPrompt).toContain('Engagement type: pentest');
    expect(systemPrompt).toContain('Client: TestCorp');
    expect(systemPrompt).toContain('Targets in scope: 5');
  });

  it('should use correct _caller tag for specialist path', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(3, 5000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    expect(call._caller).toBe('specialist:attack-planner');
    expect(call._priority).toBe('essential');
  });

  it('should include response_format schema', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(3, 5000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    expect(call.response_format).toBeDefined();
    expect(call.response_format.type).toBe('json_schema');
    expect(call.response_format.json_schema.name).toBe('attack_plan');
  });

  it('should handle 50+ assets without exceeding budget', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    // 50 assets with large recon summary
    await planAttack(makeInput(50, 50_000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const totalLen = call.messages[0].content.length + call.messages[1].content.length;

    // Should still be under budget
    expect(totalLen).toBeLessThan(42_000);
  });

  it('should preserve user message prefix for LLM instruction', async () => {
    const { planAttack } = await import('../server/lib/llm-specialists/attack-planner');

    await planAttack(makeInput(3, 5000));

    const call = mockThrottledLLMCall.mock.calls[0][0];
    const userMessage = call.messages[1].content;

    expect(userMessage).toContain('Based on the following passive reconnaissance results');
    expect(userMessage).toContain('design an attack path and active scanning strategy');
  });
});

describe('Fallback Path Budget Management', () => {
  it('should have budget-aware truncation in the fallback code pattern', () => {
    // This is a structural test — verify the fallback code exists
    // by checking the engagement-orchestrator has the budget-aware fallback
    const fs = require('fs');
    const orchestratorCode = fs.readFileSync(
      require('path').join(__dirname, 'lib/engagement-orchestrator.ts'),
      'utf-8'
    );

    // Verify fallback has budget-aware truncation
    expect(orchestratorCode).toContain('FALLBACK_MAX_CHARS');
    expect(orchestratorCode).toContain('fallbackUserBudget');
    expect(orchestratorCode).toContain('truncated to fit token budget');
    // Verify logging exists
    expect(orchestratorCode).toContain('[ScanPlan Fallback]');
  });

  it('should have prompt size logging in specialist call path', () => {
    const fs = require('fs');
    const orchestratorCode = fs.readFileSync(
      require('path').join(__dirname, 'lib/engagement-orchestrator.ts'),
      'utf-8'
    );

    expect(orchestratorCode).toContain('passiveReconSummary size:');
  });
});
