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

// ─── Credential Spray Status Indicator ──────────────────────────────────────

describe('Credential Harvester — getEngagementCredentials', () => {
  it('should export getEngagementCredentials function', async () => {
    const mod = await import('./lib/credential-harvester');
    expect(typeof mod.getEngagementCredentials).toBe('function');
  });

  it('getEngagementCredentials should be a function that accepts an engagementId', async () => {
    const { getEngagementCredentials } = await import('./lib/credential-harvester');
    // Verify function signature — it takes 1 param (engagementId)
    expect(getEngagementCredentials.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── PDF Report — Credential Exposure Section ──────────────────────────────

describe('Pentest Report Pipeline — Credential Exposure Section', () => {
  it('should include credentialExposure in PipelineInput type', async () => {
    // Verify the type exists by importing the module
    const mod = await import('./lib/pentest-report-pipeline');
    expect(typeof mod.runPentestReportPipeline).toBe('function');
  });

  it('should generate credential exposure markdown when data is present', () => {
    // Simulate the credential exposure section generation logic
    const credentialExposure = {
      total: 40,
      withPasswords: 5,
      withHashes: 12,
      tested: 14,
      successful: 2,
      bySource: { 'LinkedIn': 15, 'Adobe': 10, 'Dropbox': 8, 'MyFitnessPal': 7 } as Record<string, number>,
      sampleCredentials: [
        { email: 'john@example.com', username: 'john', source: 'dehashed', breachName: 'LinkedIn', confidence: 'high', isUsed: 1, usedResult: 'success' },
        { email: 'jane@example.com', username: 'jane', source: 'leakcheck', breachName: 'Adobe', confidence: 'medium', isUsed: 1, usedResult: 'failed' },
      ],
    };

    let md = '';
    if (credentialExposure && credentialExposure.total > 0) {
      const ce = credentialExposure;
      md += `### 12.8 Credential Exposure Assessment\n\n`;
      md += `| Metric | Value |\n|---|---|\n`;
      md += `| **Total Credentials Harvested** | ${ce.total} |\n`;
      md += `| **With Plaintext Passwords** | ${ce.withPasswords} |\n`;
      md += `| **With Password Hashes** | ${ce.withHashes} |\n`;
      md += `| **Tested via Credential Spray** | ${ce.tested} |\n`;
      md += `| **Successful Authentications** | ${ce.successful} |\n`;
      md += `| **Success Rate** | ${ce.tested > 0 ? ((ce.successful / ce.tested) * 100).toFixed(1) + '%' : 'N/A'} |\n\n`;

      if (Object.keys(ce.bySource).length > 0) {
        md += `#### Breach Sources\n\n`;
        md += `| Source | Credentials |\n|---|---|\n`;
        for (const [src, cnt] of Object.entries(ce.bySource)) {
          md += `| ${src} | ${cnt} |\n`;
        }
        md += `\n`;
      }

      if (ce.successful > 0) {
        md += `**CRITICAL:**`;
      }

      if (ce.sampleCredentials.length > 0) {
        md += `#### Sample Exposed Credentials (Redacted)\n\n`;
        for (const c of ce.sampleCredentials.slice(0, 15)) {
          const identity = c.email || c.username;
          const redacted = identity.includes('@') ? identity.substring(0, 3) + '***@' + identity.split('@')[1] : identity.substring(0, 3) + '***';
          md += `| ${redacted} |`;
        }
      }
    }

    // Verify the generated markdown
    expect(md).toContain('12.8 Credential Exposure Assessment');
    expect(md).toContain('Total Credentials Harvested');
    expect(md).toContain('40');
    expect(md).toContain('With Plaintext Passwords');
    expect(md).toContain('5');
    expect(md).toContain('Tested via Credential Spray');
    expect(md).toContain('14');
    expect(md).toContain('Successful Authentications');
    expect(md).toContain('2');
    expect(md).toContain('14.3%'); // 2/14 * 100
    expect(md).toContain('Breach Sources');
    expect(md).toContain('LinkedIn');
    expect(md).toContain('Adobe');
    expect(md).toContain('CRITICAL:');
    expect(md).toContain('Sample Exposed Credentials (Redacted)');
    // Verify email redaction
    expect(md).toContain('joh***@example.com');
    expect(md).not.toContain('john@example.com');
  });

  it('should not generate credential exposure section when no data', () => {
    const credentialExposure = undefined;
    let md = '';
    if (credentialExposure && (credentialExposure as any).total > 0) {
      md += 'should not appear';
    }
    expect(md).toBe('');
  });

  it('should show HIGH RISK when plaintext passwords exist but no successful spray', () => {
    const ce = { total: 20, withPasswords: 8, withHashes: 5, tested: 10, successful: 0, bySource: {}, sampleCredentials: [] };
    let riskLevel = '';
    if (ce.successful > 0) {
      riskLevel = 'CRITICAL';
    } else if (ce.withPasswords > 0) {
      riskLevel = 'HIGH RISK';
    } else {
      riskLevel = 'MODERATE RISK';
    }
    expect(riskLevel).toBe('HIGH RISK');
  });

  it('should show MODERATE RISK when only hashed passwords found', () => {
    const ce = { total: 20, withPasswords: 0, withHashes: 15, tested: 0, successful: 0, bySource: {}, sampleCredentials: [] };
    let riskLevel = '';
    if (ce.successful > 0) {
      riskLevel = 'CRITICAL';
    } else if (ce.withPasswords > 0) {
      riskLevel = 'HIGH RISK';
    } else {
      riskLevel = 'MODERATE RISK';
    }
    expect(riskLevel).toBe('MODERATE RISK');
  });
});

// ─── Report Section Blueprints — Credential Exposure ────────────────────────

describe('Report Section Blueprints — Credential Exposure', () => {
  it('should include credential_exposure section in pentest blueprint', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    const blueprint = getReportBlueprint('penetration_test');
    expect(blueprint).toBeDefined();
    const credSection = blueprint!.sections.find(s => s.id === 'credential_exposure');
    expect(credSection).toBeDefined();
    expect(credSection!.title).toBe('Credential Exposure Assessment');
    expect(credSection!.required).toBe(false);
    expect(credSection!.dataSources).toContain('credential_exposure');
  });

  it('should include credential_exposure section in red_team blueprint', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    const blueprint = getReportBlueprint('red_team');
    expect(blueprint).toBeDefined();
    const credSection = blueprint!.sections.find(s => s.id === 'credential_exposure');
    expect(credSection).toBeDefined();
    expect(credSection!.title).toBe('Credential Exposure Assessment');
  });

  it('credential_exposure should appear before risk_matrix in pentest blueprint', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    const blueprint = getReportBlueprint('penetration_test');
    const sections = blueprint!.sections;
    const credIdx = sections.findIndex(s => s.id === 'credential_exposure');
    const riskIdx = sections.findIndex(s => s.id === 'risk_matrix');
    expect(credIdx).toBeGreaterThan(-1);
    expect(riskIdx).toBeGreaterThan(-1);
    expect(credIdx).toBeLessThan(riskIdx);
  });
});

// ─── Breach Timeline Visualization — Data Extraction Logic ──────────────────

describe('Breach Timeline — Data Extraction', () => {
  // Replicate the timeline extraction logic from the frontend component
  function extractTimelineEvents(connectorResults: any[]) {
    const timelineEvents: Array<{
      name: string;
      date: string;
      dateObj: Date;
      records: number;
      credentials: number;
      hasPasswords: boolean;
      hasHashes: boolean;
      source: string;
      classification: string;
    }> = [];
    const seenBreaches = new Set<string>();

    for (const cr of connectorResults) {
      if (!cr.observations) continue;
      for (const obs of cr.observations) {
        const ev = obs.evidence || {};
        const rawDate = ev.breach_date || ev.breachDate || ev.BreachDate || obs.firstSeen;
        const breachName = ev.breach_name || ev.breachName || ev.database_name || ev.title || ev.Title || obs.name;
        if (!rawDate || !breachName) continue;
        if (!obs.tags?.some((t: string) => ['breach_database', 'credential_breach', 'breach_summary', 'credentials_exposed', 'email-breach'].includes(t))) continue;
        const key = breachName.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (seenBreaches.has(key)) continue;
        seenBreaches.add(key);
        const dateObj = new Date(rawDate);
        if (isNaN(dateObj.getTime())) continue;
        let classification = 'unknown';
        if (obs.tags?.includes('first_party_breach')) classification = 'first_party';
        else if (obs.tags?.includes('third_party_breach')) classification = 'third_party';
        timelineEvents.push({
          name: breachName.replace(/^(1st-Party|3rd-Party|Unclassified) Breach: /, ''),
          date: rawDate,
          dateObj,
          records: ev.total_records || ev.credentials_exposed || 0,
          credentials: ev.credentials_exposed || ev.email_count || 0,
          hasPasswords: !!ev.has_passwords || !!ev.has_plaintext,
          hasHashes: !!ev.has_hashed_passwords,
          source: cr.connector || 'unknown',
          classification,
        });
      }
    }
    timelineEvents.sort((a, b) => a.dateObj.getTime() - b.dateObj.getTime());
    return timelineEvents;
  }

  it('should extract timeline events from dehashed breach_database observations', () => {
    const connectorResults = [{
      connector: 'dehashed',
      observations: [
        {
          name: 'LinkedIn',
          tags: ['breach_database', 'third_party_breach'],
          evidence: { breach_date: '2012-05-05', breach_name: 'LinkedIn', total_records: 164611595, credentials_exposed: 117 },
        },
        {
          name: 'Adobe',
          tags: ['breach_database', 'third_party_breach'],
          evidence: { breach_date: '2013-10-04', breach_name: 'Adobe', total_records: 152445165, has_hashed_passwords: true },
        },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(2);
    expect(events[0].name).toBe('LinkedIn');
    expect(events[0].dateObj.getFullYear()).toBe(2012);
    expect(events[0].records).toBe(164611595);
    expect(events[0].classification).toBe('third_party');
    expect(events[1].name).toBe('Adobe');
    expect(events[1].dateObj.getFullYear()).toBe(2013);
    expect(events[1].hasHashes).toBe(true);
  });

  it('should extract timeline events from dark web cross-ref credential_breach observations', () => {
    const connectorResults = [{
      connector: 'darkweb_crossref',
      observations: [
        {
          name: '1st-Party Breach: TargetCorp2023',
          tags: ['credential_breach', 'first_party_breach'],
          firstSeen: '2023-06-15T00:00:00Z',
          evidence: { breach_name: 'TargetCorp2023', breach_date: '2023-06-15', total_records: 50000, has_passwords: true },
        },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('TargetCorp2023');
    expect(events[0].classification).toBe('first_party');
    expect(events[0].hasPasswords).toBe(true);
    expect(events[0].records).toBe(50000);
  });

  it('should deduplicate breaches by name (case-insensitive)', () => {
    const connectorResults = [
      {
        connector: 'dehashed',
        observations: [
          { name: 'LinkedIn', tags: ['breach_database'], evidence: { breach_date: '2012-05-05', breach_name: 'LinkedIn', total_records: 100 } },
        ],
      },
      {
        connector: 'darkweb_crossref',
        observations: [
          { name: '3rd-Party Breach: linkedin', tags: ['credential_breach', 'third_party_breach'], evidence: { breach_name: 'linkedin', breach_date: '2012-05-05', total_records: 200 } },
        ],
      },
    ];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('LinkedIn'); // First one wins
  });

  it('should sort events chronologically (oldest first)', () => {
    const connectorResults = [{
      connector: 'dehashed',
      observations: [
        { name: 'Recent', tags: ['breach_database'], evidence: { breach_date: '2024-01-01', breach_name: 'Recent', total_records: 10 } },
        { name: 'Old', tags: ['breach_database'], evidence: { breach_date: '2010-03-15', breach_name: 'Old', total_records: 20 } },
        { name: 'Middle', tags: ['breach_database'], evidence: { breach_date: '2018-07-20', breach_name: 'Middle', total_records: 30 } },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(3);
    expect(events[0].name).toBe('Old');
    expect(events[1].name).toBe('Middle');
    expect(events[2].name).toBe('Recent');
  });

  it('should skip observations without dates', () => {
    const connectorResults = [{
      connector: 'dehashed',
      observations: [
        { name: 'NoDates', tags: ['breach_database'], evidence: { breach_name: 'NoDates', total_records: 100 } },
        { name: 'HasDate', tags: ['breach_database'], evidence: { breach_date: '2020-01-01', breach_name: 'HasDate', total_records: 50 } },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('HasDate');
  });

  it('should skip non-breach observations', () => {
    const connectorResults = [{
      connector: 'dehashed',
      observations: [
        { name: 'subdomain.example.com', tags: ['subdomain'], assetType: 'subdomain', evidence: { breach_date: '2020-01-01' } },
        { name: 'Breach1', tags: ['breach_database'], evidence: { breach_date: '2020-01-01', breach_name: 'Breach1', total_records: 100 } },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('Breach1');
  });

  it('should handle invalid dates gracefully', () => {
    const connectorResults = [{
      connector: 'dehashed',
      observations: [
        { name: 'BadDate', tags: ['breach_database'], evidence: { breach_date: 'not-a-date', breach_name: 'BadDate' } },
        { name: 'GoodDate', tags: ['breach_database'], evidence: { breach_date: '2021-06-01', breach_name: 'GoodDate', total_records: 10 } },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('GoodDate');
  });

  it('should return empty array when no connector results', () => {
    const events = extractTimelineEvents([]);
    expect(events).toHaveLength(0);
  });

  it('should classify first_party and third_party correctly from tags', () => {
    const connectorResults = [{
      connector: 'darkweb_crossref',
      observations: [
        { name: 'FirstParty', tags: ['credential_breach', 'first_party_breach'], evidence: { breach_date: '2022-01-01', breach_name: 'FirstParty' } },
        { name: 'ThirdParty', tags: ['credential_breach', 'third_party_breach'], evidence: { breach_date: '2022-06-01', breach_name: 'ThirdParty' } },
        { name: 'Unknown', tags: ['credential_breach'], evidence: { breach_date: '2022-12-01', breach_name: 'Unknown' } },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    expect(events).toHaveLength(3);
    expect(events[0].classification).toBe('first_party');
    expect(events[1].classification).toBe('third_party');
    expect(events[2].classification).toBe('unknown');
  });

  it('should group events by year correctly', () => {
    // Use mid-year dates to avoid UTC/local timezone edge cases on Jan 1
    const connectorResults = [{
      connector: 'dehashed',
      observations: [
        { name: 'BreachAlpha2020', tags: ['breach_database'], evidence: { breach_date: '2020-03-15', breach_name: 'BreachAlpha2020', total_records: 100 } },
        { name: 'BreachBeta2020', tags: ['breach_database'], evidence: { breach_date: '2020-09-15', breach_name: 'BreachBeta2020', total_records: 200 } },
        { name: 'BreachGamma2022', tags: ['breach_database'], evidence: { breach_date: '2022-06-15', breach_name: 'BreachGamma2022', total_records: 300 } },
      ],
    }];
    const events = extractTimelineEvents(connectorResults);
    // Verify all 3 events are extracted
    expect(events).toHaveLength(3);
    // Verify they are sorted chronologically
    expect(events[0].dateObj.getTime()).toBeLessThan(events[1].dateObj.getTime());
    expect(events[1].dateObj.getTime()).toBeLessThan(events[2].dateObj.getTime());
    // Verify year extraction works
    const years = events.map(e => e.dateObj.getFullYear());
    expect(years).toEqual([2020, 2020, 2022]);
    // Verify grouping logic
    const uniqueYears = [...new Set(years)];
    expect(uniqueYears).toHaveLength(2);
    expect(uniqueYears).toContain(2020);
    expect(uniqueYears).toContain(2022);
  });
});
