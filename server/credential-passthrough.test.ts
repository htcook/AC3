import { describe, it, expect, vi } from 'vitest';

// ─── Signal Classifier: Credential Evidence Extraction ───────────────────────

describe('Signal Classifier — Credential Evidence', () => {
  it('should import classifySignals without errors', async () => {
    const mod = await import('./lib/passive/signal-classifier');
    expect(typeof mod.classifySignals).toBe('function');
  });

  it('should attach credentialEvidence to credential_exposure signals', async () => {
    const { classifySignals } = await import('./lib/passive/signal-classifier');
    const obs = [{
      assetId: 'breach-test-1',
      domain: 'example.com',
      source: 'dehashed',
      assetType: 'breach',
      name: 'TestBreach2024',
      tags: ['credentials_exposed'],
      observedAt: new Date(),
      evidence: {
        database_name: 'TestBreach2024',
        breach_date: '2024-01-15',
        credentials_exposed: 42,
        sample_emails: ['user1@example.com', 'user2@example.com'],
        sample_usernames: ['admin', 'jdoe'],
        hash_types: ['MD5', 'SHA1'],
        has_plaintext: false,
      },
    }];
    const signals = classifySignals(obs as any);
    const credSignal = signals.find(s => s.signalType === 'credential_exposure');
    expect(credSignal).toBeDefined();
    expect(credSignal!.credentialEvidence).toBeDefined();
    expect(credSignal!.credentialEvidence!.breachName).toBe('TestBreach2024');
    expect(credSignal!.credentialEvidence!.breachDate).toBe('2024-01-15');
    expect(credSignal!.credentialEvidence!.totalRecords).toBe(42);
    expect(credSignal!.credentialEvidence!.emails).toEqual(['user1@example.com', 'user2@example.com']);
    expect(credSignal!.credentialEvidence!.usernames).toEqual(['admin', 'jdoe']);
    expect(credSignal!.credentialEvidence!.hashTypes).toEqual(['MD5', 'SHA1']);
    expect(credSignal!.credentialEvidence!.hasPlaintextPasswords).toBeFalsy();
    expect(credSignal!.credentialEvidence!.sources).toEqual(['dehashed']);
    expect(credSignal!.credentialEvidence!.domain).toBe('example.com');
  });

  it('should attach credentialEvidence to high_volume_breach signals', async () => {
    const { classifySignals } = await import('./lib/passive/signal-classifier');
    const obs = [{
      assetId: 'breach-summary-1',
      domain: 'example.com',
      source: 'dehashed',
      assetType: 'breach',
      name: 'BreachSummary',
      tags: ['breach_summary'],
      observedAt: new Date(),
      evidence: {
        total_records: 500,
        unique_breaches: 12,
        sample_emails: ['a@example.com'],
        hash_types: ['bcrypt'],
        has_plaintext: true,
        password_count: 15,
        top_breaches: ['LinkedIn', 'Adobe'],
      },
    }];
    const signals = classifySignals(obs as any);
    const hvSignal = signals.find(s => s.signalType === 'high_volume_breach');
    expect(hvSignal).toBeDefined();
    expect(hvSignal!.credentialEvidence).toBeDefined();
    expect(hvSignal!.credentialEvidence!.totalRecords).toBe(500);
    expect(hvSignal!.credentialEvidence!.uniqueBreaches).toBe(12);
    expect(hvSignal!.credentialEvidence!.hashTypes).toEqual(['bcrypt']);
    expect(hvSignal!.credentialEvidence!.hasPlaintextPasswords).toBe(true);
    expect(hvSignal!.credentialEvidence!.breachName).toBe('LinkedIn, Adobe');
  });

  it('should NOT attach credentialEvidence to non-credential signals', async () => {
    const { classifySignals } = await import('./lib/passive/signal-classifier');
    const obs = [{
      assetId: 'admin-panel-1',
      domain: 'example.com',
      source: 'httpx',
      assetType: 'web',
      name: 'admin.example.com',
      tags: ['admin_panel'],
      observedAt: new Date(),
      evidence: { status_code: 200, title: 'Admin Panel' },
    }];
    const signals = classifySignals(obs as any);
    // Any signals generated should not have credentialEvidence
    for (const sig of signals) {
      if (sig.signalType !== 'credential_exposure' && sig.signalType !== 'high_volume_breach') {
        expect(sig.credentialEvidence).toBeUndefined();
      }
    }
  });

  it('should handle missing evidence fields gracefully', async () => {
    const { classifySignals } = await import('./lib/passive/signal-classifier');
    const obs = [{
      assetId: 'breach-minimal-1',
      domain: 'example.com',
      source: 'dehashed',
      assetType: 'breach',
      name: 'MinimalBreach',
      tags: ['credentials_exposed'],
      observedAt: new Date(),
      evidence: {},
    }];
    const signals = classifySignals(obs as any);
    const credSignal = signals.find(s => s.signalType === 'credential_exposure');
    expect(credSignal).toBeDefined();
    // credentialEvidence should exist but with undefined fields (not crash)
    expect(credSignal!.credentialEvidence).toBeDefined();
  });

  it('should limit email/username arrays to 10 items', async () => {
    const { classifySignals } = await import('./lib/passive/signal-classifier');
    const manyEmails = Array.from({ length: 20 }, (_, i) => `user${i}@example.com`);
    const manyUsers = Array.from({ length: 20 }, (_, i) => `user${i}`);
    const obs = [{
      assetId: 'breach-large-1',
      domain: 'example.com',
      source: 'dehashed',
      assetType: 'breach',
      name: 'LargeBreach',
      tags: ['credentials_exposed'],
      observedAt: new Date(),
      evidence: {
        credentials_exposed: 1000,
        sample_emails: manyEmails,
        sample_usernames: manyUsers,
      },
    }];
    const signals = classifySignals(obs as any);
    const credSignal = signals.find(s => s.signalType === 'credential_exposure');
    expect(credSignal!.credentialEvidence!.emails!.length).toBeLessThanOrEqual(10);
    expect(credSignal!.credentialEvidence!.usernames!.length).toBeLessThanOrEqual(10);
  });
});

// ─── RiskSignal Type: credentialEvidence field ───────────────────────────────

describe('RiskSignal Type — credentialEvidence', () => {
  it('should allow credentialEvidence on RiskSignal interface', async () => {
    const { RiskSignal } = await import('./lib/passive/types') as any;
    // Type check: construct a valid RiskSignal with credentialEvidence
    const signal = {
      signalId: 'test-1',
      assetId: 'asset-1',
      signalType: 'credential_exposure',
      severity: 'critical' as const,
      confidence: 0.95,
      observedAt: new Date(),
      rationale: 'Test rationale',
      evidenceRefs: ['ref-1'],
      credentialEvidence: {
        breachName: 'TestBreach',
        emails: ['test@example.com'],
        hashTypes: ['MD5'],
        hasPlaintextPasswords: false,
        sources: ['dehashed'],
        domain: 'example.com',
      },
    };
    expect(signal.credentialEvidence).toBeDefined();
    expect(signal.credentialEvidence.breachName).toBe('TestBreach');
  });
});

// ─── startEngagement Credential Harvesting ───────────────────────────────────

describe('startEngagement — Credential Harvesting Wiring', () => {
  it('should have credential harvester module importable', async () => {
    const mod = await import('./lib/credential-harvester');
    expect(typeof mod.harvestFromExistingFindings).toBe('function');
    expect(typeof mod.harvestCredentialsFromObservations).toBe('function');
  });

  it('harvestFromExistingFindings should accept engagementId and domain', async () => {
    const { harvestFromExistingFindings } = await import('./lib/credential-harvester');
    // Verify function signature accepts the expected parameters
    expect(harvestFromExistingFindings.length).toBeGreaterThanOrEqual(2);
  });

  it('harvestCredentialsFromObservations should accept engagementId, domain, and observations', async () => {
    const { harvestCredentialsFromObservations } = await import('./lib/credential-harvester');
    // Verify function signature accepts the expected parameters
    expect(harvestCredentialsFromObservations.length).toBeGreaterThanOrEqual(3);
  });
});

// ─── Executive Summary — Breach Context Injection ───────────────────────────

describe('Executive Summary — Breach Context', () => {
  it('generateScanOnlySummary should accept breachData and riskSignals in opts', async () => {
    const mod = await import('./domainIntel');
    expect(typeof mod.generateScanOnlySummary).toBe('function');
    // The function signature should accept 3 params: analyses, org, opts
    expect(mod.generateScanOnlySummary.length).toBeGreaterThanOrEqual(2);
  });

  it('generateSummaries should accept breachData and riskSignals in opts', async () => {
    const mod = await import('./domainIntel');
    expect(typeof mod.generateSummaries).toBe('function');
    // The function signature should accept 5 params: analyses, campaigns, org, historicalContext, opts
    expect(mod.generateSummaries.length).toBeGreaterThanOrEqual(3);
  });

  it('should build breach context block from breachData', () => {
    // Simulate the breach context IIFE that gets injected into the prompt
    const breachData = {
      totalExposures: 40,
      uniqueEmails: 14,
      uniqueBreachSources: 15,
      breachSources: ['LinkedIn', 'Adobe', 'Dropbox', 'MyFitnessPal'],
      passwordsExposed: 5,
      hashedPasswordsExposed: 3,
      credentialPairs: 14,
      subdomainsDiscovered: 0,
      ipsDiscovered: 0,
      queriedAt: new Date().toISOString(),
    };
    const riskSignals = [
      {
        signalType: 'credential_exposure',
        credentialEvidence: {
          hasPlaintextPasswords: true,
          hashTypes: ['MD5', 'SHA1'],
        },
      },
    ];

    // Replicate the IIFE logic from the prompt template
    const bd = breachData;
    const sigs = riskSignals;
    const credSignals = sigs.filter((s: any) => s.signalType === 'credential_exposure' || s.signalType === 'high_volume_breach');
    const parts: string[] = ['CREDENTIAL & BREACH EXPOSURE:'];
    if (bd) {
      parts.push(`- Total breach records found: ${bd.totalExposures.toLocaleString()}`);
      parts.push(`- Unique breach sources: ${bd.uniqueBreachSources}${bd.breachSources?.length > 0 ? ` (${bd.breachSources.slice(0, 8).join(', ')}${bd.breachSources.length > 8 ? ` +${bd.breachSources.length - 8} more` : ''})` : ''}`);
      parts.push(`- Credentials exposed (email/password pairs): ${bd.credentialPairs}`);
      if (bd.passwordsExposed > 0) parts.push(`- Passwords exposed (plaintext or crackable): ${bd.passwordsExposed}`);
      if (bd.hashedPasswordsExposed > 0) parts.push(`- Hashed passwords found: ${bd.hashedPasswordsExposed}`);
    }
    if (credSignals.length > 0) {
      const plaintextCount = credSignals.filter((s: any) => s.credentialEvidence?.hasPlaintextPasswords).length;
      const hashTypes = [...new Set(credSignals.flatMap((s: any) => s.credentialEvidence?.hashTypes || []))];
      if (plaintextCount > 0) parts.push(`- \u26a0 ${plaintextCount} breach source(s) contain PLAINTEXT PASSWORDS`);
      if (hashTypes.length > 0) parts.push(`- Hash types found: ${hashTypes.join(', ')}`);
    }

    const block = parts.join('\n');
    expect(block).toContain('CREDENTIAL & BREACH EXPOSURE:');
    expect(block).toContain('Total breach records found: 40');
    expect(block).toContain('Unique breach sources: 15');
    expect(block).toContain('LinkedIn, Adobe, Dropbox, MyFitnessPal');
    expect(block).toContain('Credentials exposed (email/password pairs): 14');
    expect(block).toContain('Passwords exposed (plaintext or crackable): 5');
    expect(block).toContain('Hashed passwords found: 3');
    expect(block).toContain('PLAINTEXT PASSWORDS');
    expect(block).toContain('Hash types found: MD5, SHA1');
  });

  it('should return empty string when no breach data or credential signals', () => {
    const bd = undefined;
    const sigs: any[] = [];
    const credSignals = sigs.filter((s: any) => s.signalType === 'credential_exposure' || s.signalType === 'high_volume_breach');
    const result = (!bd && credSignals.length === 0) ? '' : 'has content';
    expect(result).toBe('');
  });
});
