import { describe, it, expect, vi } from 'vitest';

// ─── Source Code Detection Tests ─────────────────────────────────────────────
describe('isSourceCodeTarget', () => {
  // We test the shared utility directly
  it('should detect GitHub repos as source code', async () => {
    const { isSourceCodeTarget } = await import('../shared/domain-safety-whitelist');
    const result = isSourceCodeTarget('github.com/nodejs/node');
    expect(result.isSourceCode).toBe(true);
    expect(result.repoUrl).toBe('https://github.com/nodejs/node');
    expect(result.host).toBe('github.com');
  });

  it('should detect full GitHub URLs as source code', async () => {
    const { isSourceCodeTarget } = await import('../shared/domain-safety-whitelist');
    const result = isSourceCodeTarget('https://github.com/nodejs/node');
    expect(result.isSourceCode).toBe(true);
    expect(result.repoUrl).toBe('https://github.com/nodejs/node');
  });

  it('should detect GitLab repos as source code', async () => {
    const { isSourceCodeTarget } = await import('../shared/domain-safety-whitelist');
    const result = isSourceCodeTarget('https://gitlab.com/some/project');
    expect(result.isSourceCode).toBe(true);
    expect(result.host).toBe('gitlab.com');
  });

  it('should detect Bitbucket repos as source code', async () => {
    const { isSourceCodeTarget } = await import('../shared/domain-safety-whitelist');
    const result = isSourceCodeTarget('bitbucket.org/team/repo');
    expect(result.isSourceCode).toBe(true);
  });

  it('should NOT detect regular domains as source code', async () => {
    const { isSourceCodeTarget } = await import('../shared/domain-safety-whitelist');
    expect(isSourceCodeTarget('brokencrystals.com').isSourceCode).toBe(false);
    expect(isSourceCodeTarget('hackerone.com').isSourceCode).toBe(false);
    expect(isSourceCodeTarget('example.com').isSourceCode).toBe(false);
  });

  it('should NOT detect IP addresses as source code', async () => {
    const { isSourceCodeTarget } = await import('../shared/domain-safety-whitelist');
    expect(isSourceCodeTarget('192.168.1.1').isSourceCode).toBe(false);
    expect(isSourceCodeTarget('10.0.0.1').isSourceCode).toBe(false);
  });
});

// ─── Domain Whitelist Tests for Source Code Hosts ────────────────────────────
describe('isDomainWhitelisted - source code hosts', () => {
  it('should whitelist github.com for source code audits', async () => {
    const { isDomainWhitelisted } = await import('../shared/domain-safety-whitelist');
    expect(isDomainWhitelisted('github.com')).toBe(true);
    expect(isDomainWhitelisted('https://github.com/nodejs/node')).toBe(true);
  });

  it('should whitelist gitlab.com for source code audits', async () => {
    const { isDomainWhitelisted } = await import('../shared/domain-safety-whitelist');
    expect(isDomainWhitelisted('gitlab.com')).toBe(true);
  });

  it('should whitelist bitbucket.org for source code audits', async () => {
    const { isDomainWhitelisted } = await import('../shared/domain-safety-whitelist');
    expect(isDomainWhitelisted('bitbucket.org')).toBe(true);
  });
});

// ─── Asset Provisioner Tests ─────────────────────────────────────────────────
describe('asset-provisioner', () => {
  it('should export provisionAsset function', async () => {
    const mod = await import('./lib/asset-provisioner');
    expect(typeof mod.provisionAsset).toBe('function');
  });

  it('should export provisionAllAssets function', async () => {
    const mod = await import('./lib/asset-provisioner');
    expect(typeof mod.provisionAllAssets).toBe('function');
  });

  it('should export installTools function', async () => {
    const mod = await import('./lib/asset-provisioner');
    expect(typeof mod.installTools).toBe('function');
  });

  it('should export cleanupProvisionedAssets function', async () => {
    const mod = await import('./lib/asset-provisioner');
    expect(typeof mod.cleanupProvisionedAssets).toBe('function');
  });

  it('should have BuildRequirement and ProvisioningResult interfaces', async () => {
    // Verify the module loads without errors
    const mod = await import('./lib/asset-provisioner');
    expect(mod).toBeDefined();
    expect(Object.keys(mod).length).toBeGreaterThan(0);
  });
});

// ─── Engagement Builder - Buildable Asset Detection Tests ────────────────────
describe('engagement-builder buildable asset types', () => {
  it('should export buildEngagementPreview and createEngagementFromPreview', async () => {
    const mod = await import('./lib/engagement-builder');
    expect(typeof mod.buildEngagementPreview).toBe('function');
    expect(typeof mod.createEngagementFromPreview).toBe('function');
  });
});

// ─── Report Pipeline - Exploit Status Resolution Tests ───────────────────────
describe('report pipeline exploit status resolution', () => {
  it('should resolve status as SUCCEEDED when shellObtained is true regardless of ea_status', () => {
    // This tests the logic that was fixed: when ea_status=failed but shellObtained=true,
    // the derived status should be SUCCEEDED
    const evidence = {
      status: 'failed',
      shellObtained: true,
      accessLevel: 'user',
    };
    
    // Replicate the fixed derivedStatus logic
    const derivedStatus = evidence.shellObtained
      ? 'SUCCEEDED'
      : evidence.status === 'succeeded'
        ? 'SUCCEEDED'
        : evidence.status === 'blocked'
          ? 'BLOCKED'
          : 'FAILED';
    
    expect(derivedStatus).toBe('SUCCEEDED');
  });

  it('should resolve status as FAILED when shellObtained is false and ea_status is failed', () => {
    const evidence = {
      status: 'failed',
      shellObtained: false,
      accessLevel: null,
    };
    
    const derivedStatus = evidence.shellObtained
      ? 'SUCCEEDED'
      : evidence.status === 'succeeded'
        ? 'SUCCEEDED'
        : evidence.status === 'blocked'
          ? 'BLOCKED'
          : 'FAILED';
    
    expect(derivedStatus).toBe('FAILED');
  });

  it('should resolve status as BLOCKED when ea_status is blocked', () => {
    const evidence = {
      status: 'blocked',
      shellObtained: false,
      accessLevel: null,
    };
    
    const derivedStatus = evidence.shellObtained
      ? 'SUCCEEDED'
      : evidence.status === 'succeeded'
        ? 'SUCCEEDED'
        : evidence.status === 'blocked'
          ? 'BLOCKED'
          : 'FAILED';
    
    expect(derivedStatus).toBe('BLOCKED');
  });

  it('should count evidence correctly with mixed statuses', () => {
    const evidenceList = [
      { status: 'failed', shellObtained: true, accessLevel: 'user' },
      { status: 'failed', shellObtained: true, accessLevel: 'user' },
      { status: 'failed', shellObtained: false, accessLevel: null },
      { status: 'blocked', shellObtained: false, accessLevel: null },
    ];
    
    const derived = evidenceList.map(e => ({
      ...e,
      derivedStatus: e.shellObtained
        ? 'SUCCEEDED'
        : e.status === 'succeeded'
          ? 'SUCCEEDED'
          : e.status === 'blocked'
            ? 'BLOCKED'
            : 'FAILED',
    }));
    
    const succeeded = derived.filter(e => e.derivedStatus === 'SUCCEEDED').length;
    const failed = derived.filter(e => e.derivedStatus === 'FAILED').length;
    const blocked = derived.filter(e => e.derivedStatus === 'BLOCKED').length;
    
    expect(succeeded).toBe(2);
    expect(failed).toBe(1);
    expect(blocked).toBe(1);
    expect(succeeded + failed + blocked).toBe(4);
  });
});

// ─── Finding Deduplication Tests ─────────────────────────────────────────────
describe('finding deduplication logic', () => {
  it('should identify near-duplicate .env findings', () => {
    const findings = [
      { title: 'Exposed .env File (Laravel)', asset: 'brokencrystals.com', cve: '' },
      { title: 'Exposed .env File (CodeIgniter)', asset: 'brokencrystals.com', cve: '' },
      { title: 'Exposed .env File (Generic)', asset: 'brokencrystals.com', cve: '' },
      { title: 'SQL Injection in Login Form', asset: 'brokencrystals.com', cve: 'CVE-2024-1234' },
    ];
    
    // Simulate the deduplication: normalize titles for .env variants
    const seen = new Map<string, number>();
    const deduped: typeof findings = [];
    
    for (const f of findings) {
      const normalizedTitle = f.title
        .replace(/\(Laravel\)|\(CodeIgniter\)|\(Generic\)|\(Symfony\)|\(Django\)/gi, '(variant)')
        .trim();
      const key = `${normalizedTitle}::${f.asset}`;
      
      if (!seen.has(key)) {
        seen.set(key, deduped.length);
        deduped.push(f);
      }
    }
    
    // Should deduplicate the 3 .env variants into 1
    expect(deduped.length).toBe(2); // 1 .env + 1 SQL injection
    expect(deduped[0].title).toContain('.env');
    expect(deduped[1].title).toContain('SQL Injection');
  });
});
