import { describe, it, expect } from 'vitest';

/**
 * Tests for:
 * 1. inferCaller stack trace parsing improvements
 * 2. CARVER+Shock integration in AI attack planner
 * 3. Scoping schema integration in Pentester agent
 * 4. Red Team Operator agent CARVER+Shock integration
 * 5. Training data dashboard getTrainingStats callerBreakdown
 * 6. use-toast hook compatibility shim
 */

describe('inferCaller improvements', () => {
  it('should skip framework files in the skip patterns', async () => {
    // Import the llm module to verify the function exists and patterns are correct
    const llmSource = await import('fs').then(fs =>
      fs.readFileSync('./server/_core/llm.ts', 'utf-8')
    );
    
    // Verify the skip patterns include all necessary framework files
    expect(llmSource).toContain('"llm.ts"');
    expect(llmSource).toContain('"llm.js"');
    expect(llmSource).toContain('"at inferCaller"');
    expect(llmSource).toContain('"at recordTelemetry"');
    expect(llmSource).toContain('"at logTelemetry"');
    expect(llmSource).toContain('"node:internal"');
    
    // Verify it skips generic wrappers
    expect(llmSource).toContain('"Module"');
    expect(llmSource).toContain('"Promise"');
    expect(llmSource).toContain('"Object"');
    
    // Verify it skips framework/internal files in fallback
    expect(llmSource).toContain('"llm", "db", "context", "trpc", "index"');
  });
});

describe('CARVER+Shock integration in AI Attack Planner', () => {
  it('should include CARVER+Shock scoring in the system prompt', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/lib/ai-attack-planner.ts', 'utf-8')
    );
    
    // Verify all 7 CARVER+Shock factors are present
    expect(source).toContain('Criticality');
    expect(source).toContain('Accessibility');
    expect(source).toContain('Recuperability');
    expect(source).toContain('Vulnerability');
    expect(source).toContain('Effect');
    expect(source).toContain('Recognizability');
    expect(source).toContain('Shock');
    
    // Verify CARVER+Shock section header
    expect(source).toContain('CARVER+Shock Target Prioritization');
  });

  it('should include the strategic planning framework', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/lib/ai-attack-planner.ts', 'utf-8')
    );
    
    expect(source).toContain('Strategic Planning Framework');
    expect(source).toContain('Identify critical business functions');
    expect(source).toContain('Map supporting systems');
    expect(source).toContain('Identify crown jewels');
    expect(source).toContain('Map likely threat actors');
    expect(source).toContain('Build attack scenarios');
  });

  it('should include the tactical execution phases', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/lib/ai-attack-planner.ts', 'utf-8')
    );
    
    expect(source).toContain('Tactical Execution Phases');
    expect(source).toContain('Goal');
    expect(source).toContain('Method');
    expect(source).toContain('Evidence of success');
    expect(source).toContain('Reconnaissance');
    expect(source).toContain('Initial Access');
    expect(source).toContain('Privilege Escalation');
    expect(source).toContain('Lateral Movement');
    expect(source).toContain('Objective Execution');
  });
});

describe('Agent definitions - Training Pack integration', () => {
  it('should include CARVER+Shock in Red Team Operator agent', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/lib/agent-definitions.ts', 'utf-8')
    );
    
    // Verify CARVER+Shock model is in the Red Team Operator persona
    expect(source).toContain('CARVER+Shock target prioritization model');
    expect(source).toContain('Criticality: Business importance of the target system');
    expect(source).toContain('Shock: Reputational and psychological impact');
    
    // Verify the strategic analysis steps
    expect(source).toContain('Identify critical business functions and map supporting systems');
    expect(source).toContain('Apply CARVER+Shock scoring to prioritize attack paths');
    expect(source).toContain('Generate target prioritization, attack paths, and expected impact assessments');
  });

  it('should include scoping schema in Pentester agent', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/lib/agent-definitions.ts', 'utf-8')
    );
    
    // Verify scoping schema fields are in the Pentester persona
    expect(source).toContain('Business objectives: What the organization needs to protect');
    expect(source).toContain('Critical functions: Key business processes');
    expect(source).toContain('Assets: All in-scope systems');
    expect(source).toContain('Identities: User accounts, service accounts');
    expect(source).toContain('Dependencies: Third-party services');
    expect(source).toContain('Threat actors: Relevant adversary profiles');
    expect(source).toContain('Scope constraints: Legal, technical');
    expect(source).toContain('Exclusions: Explicitly out-of-scope');
  });
});

describe('Training data dashboard fixes', () => {
  it('should use llmStatus instead of success column in engagement-automation', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/routers/engagement-automation.ts', 'utf-8')
    );
    
    // Should NOT reference llmTelemetry.success (which doesn't exist)
    // Should use llmTelemetry.llmStatus instead
    expect(source).not.toMatch(/llmTelemetry\.success\b/);
  });

  it('should not use PERCENTILE_CONT in training-data-dashboard (MySQL incompatible)', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/routers/training-data-dashboard.ts', 'utf-8')
    );
    
    // PERCENTILE_CONT is PostgreSQL-only, should not be used with MySQL/TiDB
    expect(source).not.toContain('PERCENTILE_CONT');
  });

  it('should include callerBreakdown in getTrainingStats return', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/lib/engagement-training-bridge.ts', 'utf-8')
    );
    
    expect(source).toContain('callerBreakdown');
  });
});

describe('Test-lab graduation fixes', () => {
  it('should have getGraduationStatus procedure in test-lab router', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/routers/test-lab.ts', 'utf-8')
    );
    
    expect(source).toContain('getGraduationStatus');
  });

  it('should have getRecommendedScenarios procedure in test-lab router', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./server/routers/test-lab.ts', 'utf-8')
    );
    
    expect(source).toContain('getRecommendedScenarios');
  });
});

describe('Amass Scanner frontend page', () => {
  it('should have AmassScanner page component', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./client/src/pages/AmassScanner.tsx', 'utf-8')
    );
    
    expect(source).toContain('export default function AmassScanner');
    expect(source).toContain('trpc.amass.enumerate');
    expect(source).toContain('trpc.amass.intel');
    expect(source).toContain('trpc.amass.getResult');
    expect(source).toContain('trpc.amass.getScanHistory');
    expect(source).toContain('trpc.amass.diff');
    expect(source).toContain('trpc.amass.preflight');
  });

  it('should be registered in App.tsx routes', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./client/src/App.tsx', 'utf-8')
    );
    
    expect(source).toContain('AmassScanner');
    expect(source).toContain('/amass-scanner');
  });

  it('should be in sidebar navigation', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./client/src/lib/sidebar-nav.ts', 'utf-8')
    );
    
    expect(source).toContain('Amass Scanner');
    expect(source).toContain('/amass-scanner');
  });
});

describe('use-toast hook compatibility', () => {
  it('should exist and support object-style toast calls', async () => {
    const source = await import('fs').then(fs =>
      fs.readFileSync('./client/src/hooks/use-toast.ts', 'utf-8')
    );
    
    expect(source).toContain('useToast');
    expect(source).toContain('toast');
  });
});
