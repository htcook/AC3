/**
 * Sprint 11D — Lateral Movement Module Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests credential harvesting, pivot target discovery, pivot execution,
 * and multi-hop orchestration with evidence chain integration.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock fetch globally ────────────────────────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// ─── Import module under test ───────────────────────────────────────────────
import {
  harvestCredentials,
  discoverPivotTargets,
  attemptPivot,
  executeLateralMovement,
  LINUX_CREDENTIAL_PATHS,
  WINDOWS_CREDENTIAL_PATHS,
  CREDENTIAL_PATTERNS,
  PIVOT_MAX_DEPTH,
  PIVOT_MAX_TARGETS,
} from './lib/post-exploit/lateral-movement';

// Also test internal helpers via named exports
import {
  extractCredentials,
  parseHistoryForCredentials,
  classifySource,
  inferUsername,
} from './lib/post-exploit/lateral-movement';

import type {
  LateralMovementResult,
  HarvestedCredential,
  PivotTarget,
  PivotAttempt,
  CredentialSource,
} from './lib/post-exploit/lateral-movement';

// ─── Test Fixtures ──────────────────────────────────────────────────────────

function makeCtx(overrides?: Partial<any>) {
  return {
    state: {
      engagementId: 'eng-test-001',
      phase: 'post_exploit',
      engagementType: 'red_team',
      currentAction: '',
      progress: 0,
      assets: [],
    },
    engagement: { id: 'eng-test-001', name: 'Test Engagement' },
    operatorCtx: { id: 'op-1', name: 'TestOperator' },
    scanServerHost: '10.0.0.1',
    helpers: {
      addLog: vi.fn(),
      broadcastOpsUpdate: vi.fn(),
      requestApproval: vi.fn().mockResolvedValue({ approved: true }),
      auditLog: vi.fn(),
      getEffectiveTarget: (a: any) => a.ip || a.hostname || '10.0.0.50',
      fmtTarget: (a: any) => a.ip || a.hostname || '10.0.0.50',
      genId: () => `id-${Math.random().toString(36).substring(2, 8)}`,
    },
    evidence: {
      evidenceGate: vi.fn().mockResolvedValue({ id: 'ev-001', passed: true }),
      createIntegrityEnvelope: vi.fn().mockReturnValue({ hash: 'abc123', content: {} }),
      buildProvenance: vi.fn().mockReturnValue({ phase: 'lateral_movement', tool: 'test' }),
      recordCustodyEvent: vi.fn(),
    },
    ...overrides,
  };
}

function makeAsset(ip: string, os = 'linux') {
  return {
    ip,
    hostname: `host-${ip.split('.').pop()}`,
    os,
    compromised: true,
    services: os === 'windows' ? [{ name: 'smb' }, { name: 'winrm' }] : [{ name: 'ssh' }],
  };
}

function mockSshResponse(stdout: string, exitCode = 0) {
  return {
    ok: true,
    json: () => Promise.resolve({ stdout, stderr: '', exitCode }),
  };
}

// ─── Unit Tests: Credential Extraction ──────────────────────────────────────

describe('extractCredentials', () => {
  it('extracts user:password format', () => {
    const content = 'admin:SuperSecret123\nroot:toor\nbackup:B4ckup!Pass';
    const creds = extractCredentials(content, '/tmp/credentials.txt', '10.0.0.50');

    expect(creds.length).toBeGreaterThanOrEqual(2);
    const adminCred = creds.find(c => c.username === 'admin');
    expect(adminCred).toBeDefined();
    expect(adminCred!.value).toBe('SuperSecret123');
    expect(adminCred!.type).toBe('password');
  });

  it('extracts SSH private keys', () => {
    const content = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnop
qrstuvwxyz1234567890abcdefghijklmnopqrstuv
-----END RSA PRIVATE KEY-----`;
    const creds = extractCredentials(content, '/root/.ssh/id_rsa', '10.0.0.50');

    expect(creds.length).toBe(1);
    expect(creds[0].type).toBe('ssh_key');
    expect(creds[0].value).toContain('BEGIN RSA PRIVATE KEY');
  });

  it('extracts DB_PASSWORD from .env files', () => {
    const content = `DB_HOST=localhost\nDB_USER=app\nDB_PASSWORD=s3cr3t_db_p4ss\nDB_NAME=production`;
    const creds = extractCredentials(content, '/var/www/html/.env', '10.0.0.50');

    const dbCred = creds.find(c => c.value === 's3cr3t_db_p4ss');
    expect(dbCred).toBeDefined();
    expect(dbCred!.type).toBe('password');
  });

  it('extracts shadow file hashes', () => {
    const content = 'root:$6$rounds=5000$salt$hashvalue123456789abcdef:19000:0:99999:7:::';
    const creds = extractCredentials(content, '/etc/shadow', '10.0.0.50');

    const hashCred = creds.find(c => c.type === 'hash');
    expect(hashCred).toBeDefined();
    expect(hashCred!.username).toBe('root');
    expect(hashCred!.value).toContain('$6$');
  });

  it('extracts username=X password=Y format', () => {
    const content = 'username=dbadmin\npassword=Pr0duction_P@ss!';
    const creds = extractCredentials(content, '/opt/app/.env', '10.0.0.50');

    const cred = creds.find(c => c.username === 'dbadmin');
    expect(cred).toBeDefined();
    expect(cred!.value).toBe('Pr0duction_P@ss!');
  });

  it('skips trivial passwords', () => {
    const content = 'test:ab\nshort:xy';
    const creds = extractCredentials(content, '/tmp/test.txt', '10.0.0.50');
    // Values less than 3 chars should be skipped
    expect(creds.length).toBe(0);
  });
});

describe('parseHistoryForCredentials', () => {
  it('extracts mysql credentials from history', () => {
    const history = 'mysql -u dbuser -pMyDBPass123 production_db\nls -la\ncd /tmp';
    const creds = parseHistoryForCredentials(history, '10.0.0.50');

    expect(creds.length).toBe(1);
    expect(creds[0].username).toBe('dbuser');
    expect(creds[0].value).toBe('MyDBPass123');
    expect(creds[0].source.method).toBe('history_parse');
  });

  it('extracts sshpass credentials from history', () => {
    const history = "sshpass -p 'RemotePass456' ssh admin@192.168.1.100\nwhoami";
    const creds = parseHistoryForCredentials(history, '10.0.0.50');

    expect(creds.length).toBe(1);
    expect(creds[0].username).toBe('admin');
    expect(creds[0].value).toBe('RemotePass456');
  });

  it('extracts curl basic auth from history', () => {
    const history = 'curl -u apiuser:ApiKey789 https://api.example.com/data';
    const creds = parseHistoryForCredentials(history, '10.0.0.50');

    expect(creds.length).toBe(1);
    expect(creds[0].username).toBe('apiuser');
    expect(creds[0].value).toBe('ApiKey789');
  });

  it('returns empty for no credentials in history', () => {
    const history = 'ls -la\ncd /home\ncat /etc/hostname';
    const creds = parseHistoryForCredentials(history, '10.0.0.50');
    expect(creds.length).toBe(0);
  });
});

describe('classifySource', () => {
  it('classifies SSH key paths', () => {
    const source = classifySource('/root/.ssh/id_rsa');
    expect(source.method).toBe('ssh_key_harvest');
    expect(source.mitreId).toBe('T1552.004');
  });

  it('classifies shadow file', () => {
    const source = classifySource('/etc/shadow');
    expect(source.method).toBe('config_parse');
    expect(source.mitreId).toBe('T1003.008');
  });

  it('classifies SMB share files', () => {
    const source = classifySource('/srv/samba/share/credentials.txt');
    expect(source.method).toBe('smb_share');
  });

  it('classifies .env config files', () => {
    const source = classifySource('/var/www/html/.env');
    expect(source.method).toBe('config_parse');
  });

  it('classifies history files', () => {
    const source = classifySource('/root/.bash_history');
    expect(source.method).toBe('history_parse');
  });
});

describe('inferUsername', () => {
  it('infers root from /root/ paths', () => {
    expect(inferUsername('/root/.ssh/id_rsa')).toBe('root');
  });

  it('infers username from /home/user/ paths', () => {
    expect(inferUsername('/home/appuser/.bash_history')).toBe('appuser');
  });

  it('returns unknown for unrecognized paths', () => {
    expect(inferUsername('/etc/redis/redis.conf')).toBe('unknown');
  });
});

// ─── Unit Tests: Constants ──────────────────────────────────────────────────

describe('Module constants', () => {
  it('has comprehensive Linux credential paths', () => {
    expect(LINUX_CREDENTIAL_PATHS.length).toBeGreaterThan(15);
    expect(LINUX_CREDENTIAL_PATHS).toContain('/root/.ssh/id_rsa');
    expect(LINUX_CREDENTIAL_PATHS).toContain('/etc/shadow');
    expect(LINUX_CREDENTIAL_PATHS).toContain('/var/www/html/.env');
  });

  it('has Windows-equivalent credential paths', () => {
    expect(WINDOWS_CREDENTIAL_PATHS.length).toBeGreaterThan(5);
    expect(WINDOWS_CREDENTIAL_PATHS).toContain('/srv/samba/share/credentials.txt');
  });

  it('has credential patterns for all types', () => {
    const types = CREDENTIAL_PATTERNS.map(p => p.type);
    expect(types).toContain('password');
    expect(types).toContain('ssh_key');
    expect(types).toContain('hash');
    expect(types).toContain('token');
  });

  it('has reasonable pivot limits', () => {
    expect(PIVOT_MAX_DEPTH).toBe(3);
    expect(PIVOT_MAX_TARGETS).toBe(10);
  });
});

// ─── Integration Tests: Credential Harvesting ───────────────────────────────

describe('harvestCredentials', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('harvests credentials from found files', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // Mock: file search finds credentials.txt
    mockFetch
      .mockResolvedValueOnce(mockSshResponse('FOUND:/tmp/credentials.txt\nFOUND:/root/.bash_history'))
      .mockResolvedValueOnce(mockSshResponse('')) // glob results
      .mockResolvedValueOnce(mockSshResponse('admin:P@ssw0rd123\nroot:toor123')) // read credentials.txt
      .mockResolvedValueOnce(mockSshResponse('mysql -u dbuser -pSecret99 mydb')) // read history
      .mockResolvedValueOnce(mockSshResponse('')) // env vars
      .mockResolvedValueOnce(mockSshResponse('mysql -u appuser -pAppPass123 appdb')); // bash history grep

    const creds = await harvestCredentials(ctx, asset);

    expect(creds.length).toBeGreaterThan(0);
    expect(creds.some(c => c.type === 'password')).toBe(true);
  });

  it('deduplicates credentials by username+value', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // Return same credentials from multiple sources
    mockFetch
      .mockResolvedValueOnce(mockSshResponse('FOUND:/tmp/credentials.txt'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('admin:DuplicatePass\nadmin:DuplicatePass'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''));

    const creds = await harvestCredentials(ctx, asset);

    const adminCreds = creds.filter(c => c.username === 'admin' && c.value === 'DuplicatePass');
    expect(adminCreds.length).toBeLessThanOrEqual(1);
  });

  it('handles SSH relay failure gracefully', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // When fetch rejects, the inner .catch() swallows errors and returns empty results
    mockFetch.mockRejectedValue(new Error('Connection refused'));

    const creds = await harvestCredentials(ctx, asset);
    // Should return empty array without crashing
    expect(creds).toEqual([]);
  });

  it('uses Windows paths for Windows-like hosts', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.60', 'windows');
    asset.services = [{ name: 'smb' }];

    mockFetch
      .mockResolvedValueOnce(mockSshResponse('FOUND:/srv/samba/share/credentials.txt'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('Administrator:WinP@ss2024'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''));

    const creds = await harvestCredentials(ctx, asset);
    expect(creds.some(c => c.username === 'Administrator')).toBe(true);
  });
});

// ─── Integration Tests: Pivot Target Discovery ──────────────────────────────

describe('discoverPivotTargets', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('discovers targets from ARP table and port scans them', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    mockFetch
      // ARP scan
      .mockResolvedValueOnce(mockSshResponse('10.0.0.60\n10.0.0.70'))
      // /etc/hosts + known_hosts
      .mockResolvedValueOnce(mockSshResponse(''))
      // Ping sweep
      .mockResolvedValueOnce(mockSshResponse('10.0.0.60\n10.0.0.70'))
      // Port scan 10.0.0.60
      .mockResolvedValueOnce(mockSshResponse('22:ssh\n445:smb'))
      // Port scan 10.0.0.70
      .mockResolvedValueOnce(mockSshResponse('22:ssh\n3306:mysql'));

    const targets = await discoverPivotTargets(ctx, asset);

    expect(targets.length).toBe(2);
    expect(targets[0].ip).toBe('10.0.0.60');
    expect(targets[0].services).toContain('ssh');
    expect(targets[0].services).toContain('smb');
    expect(targets[1].ip).toBe('10.0.0.70');
    expect(targets[1].services).toContain('mysql');
  });

  it('includes known hosts in discovery', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    mockFetch
      .mockResolvedValueOnce(mockSshResponse('')) // ARP
      .mockResolvedValueOnce(mockSshResponse('')) // hosts/known_hosts
      .mockResolvedValueOnce(mockSshResponse('')) // ping sweep
      // Port scan for known host 10.0.0.99
      .mockResolvedValueOnce(mockSshResponse('22:ssh'));

    const targets = await discoverPivotTargets(ctx, asset, ['10.0.0.99']);

    expect(targets.length).toBe(1);
    expect(targets[0].ip).toBe('10.0.0.99');
  });

  it('excludes the source host from targets', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    mockFetch
      .mockResolvedValueOnce(mockSshResponse('10.0.0.50\n10.0.0.60')) // ARP includes self
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('22:ssh')); // Only 10.0.0.60 scanned

    const targets = await discoverPivotTargets(ctx, asset);

    expect(targets.every(t => t.ip !== '10.0.0.50')).toBe(true);
  });

  it('handles network scan failure gracefully', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    mockFetch.mockResolvedValue({ ok: false, statusText: 'timeout' });

    const targets = await discoverPivotTargets(ctx, asset);
    expect(targets).toEqual([]);
  });
});

// ─── Integration Tests: Pivot Execution ─────────────────────────────────────

describe('attemptPivot', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('successfully pivots via SSH with password credential', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');
    const target: PivotTarget = {
      ip: '10.0.0.60',
      openPorts: [22],
      services: ['ssh'],
      reachableFrom: '10.0.0.50',
      hopCount: 1,
    };
    const creds: HarvestedCredential[] = [{
      id: 'cred-1',
      type: 'password',
      username: 'admin',
      value: 'P@ssw0rd',
      source: { method: 'file_search', description: 'Test', mitreId: 'T1552.001' },
      sourceHost: '10.0.0.50',
      reused: false,
      validOn: [],
      harvestedAt: Date.now(),
    }];

    // SSH pivot succeeds
    mockFetch.mockResolvedValueOnce(mockSshResponse('uid=0(root) gid=0(root) groups=0(root)\nroot\nhostname-60'));

    const attempts = await attemptPivot(ctx, asset, target, creds);

    expect(attempts.length).toBe(1);
    expect(attempts[0].success).toBe(true);
    expect(attempts[0].protocol).toBe('ssh');
    expect(attempts[0].accessLevel).toBe('root');
    expect(attempts[0].mitreId).toBe('T1021.004');
    expect(creds[0].reused).toBe(true);
    expect(creds[0].validOn).toContain('10.0.0.60');
  });

  it('tries multiple protocols when available', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');
    const target: PivotTarget = {
      ip: '10.0.0.60',
      openPorts: [22, 445],
      services: ['ssh', 'smb'],
      reachableFrom: '10.0.0.50',
      hopCount: 1,
    };
    const creds: HarvestedCredential[] = [{
      id: 'cred-1',
      type: 'password',
      username: 'admin',
      value: 'TestPass',
      source: { method: 'file_search', description: 'Test', mitreId: 'T1552.001' },
      sourceHost: '10.0.0.50',
      reused: false,
      validOn: [],
      harvestedAt: Date.now(),
    }];

    // SSH fails, SMB succeeds
    mockFetch
      .mockResolvedValueOnce(mockSshResponse('Permission denied', 1)) // SSH fails
      .mockResolvedValueOnce(mockSshResponse('Sharename   Type      Comment\n---------   ----      -------\nIPC$        IPC       IPC Service')); // SMB succeeds

    const attempts = await attemptPivot(ctx, asset, target, creds);

    expect(attempts.length).toBe(2);
    expect(attempts[0].protocol).toBe('ssh');
    expect(attempts[0].success).toBe(false);
    expect(attempts[1].protocol).toBe('smb');
    expect(attempts[1].success).toBe(true);
  });

  it('skips hash and token credentials for SSH', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');
    const target: PivotTarget = {
      ip: '10.0.0.60',
      openPorts: [22],
      services: ['ssh'],
      reachableFrom: '10.0.0.50',
      hopCount: 1,
    };
    const creds: HarvestedCredential[] = [
      {
        id: 'cred-hash',
        type: 'hash',
        username: 'root',
        value: '$6$salt$hashvalue',
        source: { method: 'config_parse', description: 'Shadow', mitreId: 'T1003.008' },
        sourceHost: '10.0.0.50',
        reused: false,
        validOn: [],
        harvestedAt: Date.now(),
      },
      {
        id: 'cred-token',
        type: 'token',
        username: 'api',
        value: 'tok_1234567890abcdefghij',
        source: { method: 'env_vars', description: 'API token', mitreId: 'T1552.001' },
        sourceHost: '10.0.0.50',
        reused: false,
        validOn: [],
        harvestedAt: Date.now(),
      },
    ];

    const attempts = await attemptPivot(ctx, asset, target, creds);

    // No attempts should be made since hash and token are skipped for SSH
    expect(attempts.length).toBe(0);
  });

  it('stops trying credentials after first success per protocol', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');
    const target: PivotTarget = {
      ip: '10.0.0.60',
      openPorts: [22],
      services: ['ssh'],
      reachableFrom: '10.0.0.50',
      hopCount: 1,
    };
    const creds: HarvestedCredential[] = [
      {
        id: 'cred-1',
        type: 'password',
        username: 'admin',
        value: 'FirstPass',
        source: { method: 'file_search', description: 'Test', mitreId: 'T1552.001' },
        sourceHost: '10.0.0.50',
        reused: false,
        validOn: [],
        harvestedAt: Date.now(),
      },
      {
        id: 'cred-2',
        type: 'password',
        username: 'root',
        value: 'SecondPass',
        source: { method: 'file_search', description: 'Test', mitreId: 'T1552.001' },
        sourceHost: '10.0.0.50',
        reused: false,
        validOn: [],
        harvestedAt: Date.now(),
      },
    ];

    // First credential succeeds
    mockFetch.mockResolvedValueOnce(mockSshResponse('uid=1000(admin) gid=1000(admin)\nadmin\nhost-60'));

    const attempts = await attemptPivot(ctx, asset, target, creds);

    // Only 1 attempt because first succeeded
    expect(attempts.length).toBe(1);
    expect(attempts[0].success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('records timing for each attempt', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');
    const target: PivotTarget = {
      ip: '10.0.0.60',
      openPorts: [22],
      services: ['ssh'],
      reachableFrom: '10.0.0.50',
      hopCount: 1,
    };
    const creds: HarvestedCredential[] = [{
      id: 'cred-1',
      type: 'password',
      username: 'test',
      value: 'TestPass',
      source: { method: 'file_search', description: 'Test', mitreId: 'T1552.001' },
      sourceHost: '10.0.0.50',
      reused: false,
      validOn: [],
      harvestedAt: Date.now(),
    }];

    mockFetch.mockResolvedValueOnce(mockSshResponse('uid=0(root)\nroot\nhost'));

    const attempts = await attemptPivot(ctx, asset, target, creds);

    expect(attempts[0].durationMs).toBeGreaterThanOrEqual(0);
    expect(attempts[0].timestamp).toBeGreaterThan(0);
  });
});

// ─── Integration Tests: Full Lateral Movement Orchestrator ──────────────────

describe('executeLateralMovement', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('executes full harvest → discover → pivot cycle', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // Call sequence:
    // 1. harvestCredentials: file search
    mockFetch
      .mockResolvedValueOnce(mockSshResponse('FOUND:/tmp/credentials.txt')) // fixed paths
      .mockResolvedValueOnce(mockSshResponse('')) // glob paths
      .mockResolvedValueOnce(mockSshResponse('admin:PivotPass123')) // read credentials.txt
      .mockResolvedValueOnce(mockSshResponse('')) // env vars
      .mockResolvedValueOnce(mockSshResponse('')) // bash history
      // 2. discoverPivotTargets
      .mockResolvedValueOnce(mockSshResponse('10.0.0.60')) // ARP
      .mockResolvedValueOnce(mockSshResponse('')) // hosts
      .mockResolvedValueOnce(mockSshResponse('10.0.0.60')) // ping sweep
      .mockResolvedValueOnce(mockSshResponse('22:ssh')) // port scan 10.0.0.60
      // 3. attemptPivot to 10.0.0.60
      .mockResolvedValueOnce(mockSshResponse('uid=0(root) gid=0(root)\nroot\nhost-60'))
      // 4. harvestCredentials on 10.0.0.60 (second hop)
      .mockResolvedValueOnce(mockSshResponse('')) // fixed paths
      .mockResolvedValueOnce(mockSshResponse('')) // glob paths
      .mockResolvedValueOnce(mockSshResponse('')) // env vars
      .mockResolvedValueOnce(mockSshResponse('')) // bash history
      // 5. discoverPivotTargets from 10.0.0.60
      .mockResolvedValueOnce(mockSshResponse('')) // ARP
      .mockResolvedValueOnce(mockSshResponse('')) // hosts
      .mockResolvedValueOnce(mockSshResponse('')); // ping sweep (no new targets)

    const result = await executeLateralMovement(ctx, asset);

    expect(result.credentialsHarvested.length).toBeGreaterThan(0);
    expect(result.pivotTargetsDiscovered.length).toBe(1);
    expect(result.successfulPivots.length).toBe(1);
    expect(result.hostsCompromised).toContain('10.0.0.60');
    expect(result.totalHops).toBe(1);
    expect(result.maxDepth).toBe(1);
    expect(result.pivotGraph.length).toBe(1);
    expect(result.pivotGraph[0].from).toBe('10.0.0.50');
    expect(result.pivotGraph[0].to).toBe('10.0.0.60');
    expect(result.durationMs).toBeGreaterThan(0);
  });

  it('respects maxDepth limit', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // Only allow depth 1
    mockFetch
      .mockResolvedValueOnce(mockSshResponse('FOUND:/tmp/credentials.txt'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('admin:Pass123'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('10.0.0.60'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('10.0.0.60'))
      .mockResolvedValueOnce(mockSshResponse('22:ssh'))
      .mockResolvedValueOnce(mockSshResponse('uid=0(root)\nroot\nhost-60'))
      // Depth 1 reached — should NOT continue harvesting on 10.0.0.60
      .mockResolvedValue(mockSshResponse(''));

    const result = await executeLateralMovement(ctx, asset, { maxDepth: 1 });

    expect(result.maxDepth).toBeLessThanOrEqual(1);
  });

  it('records evidence for credential harvest and pivot', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    mockFetch
      .mockResolvedValueOnce(mockSshResponse('FOUND:/tmp/credentials.txt'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('root:RootPass'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('10.0.0.70'))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('10.0.0.70'))
      .mockResolvedValueOnce(mockSshResponse('22:ssh'))
      .mockResolvedValueOnce(mockSshResponse('uid=0(root)\nroot\nhost-70'))
      .mockResolvedValue(mockSshResponse(''));

    const result = await executeLateralMovement(ctx, asset);

    // Should have called evidenceGate for harvest + pivot
    expect(ctx.evidence.evidenceGate).toHaveBeenCalled();
    expect(ctx.evidence.createIntegrityEnvelope).toHaveBeenCalled();
    expect(ctx.evidence.buildProvenance).toHaveBeenCalledWith('lateral_movement', expect.any(String), ctx.operatorCtx);
    expect(result.evidenceIds.length).toBeGreaterThan(0);
  });

  it('logs progress via addLog and broadcastOpsUpdate', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // No credentials found, no targets
    mockFetch
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''));

    await executeLateralMovement(ctx, asset);

    expect(ctx.helpers.addLog).toHaveBeenCalledWith(
      ctx.state,
      expect.objectContaining({ title: expect.stringContaining('Lateral Movement Starting') }),
    );
    expect(ctx.helpers.addLog).toHaveBeenCalledWith(
      ctx.state,
      expect.objectContaining({ title: expect.stringContaining('Lateral Movement Complete') }),
    );
    expect(ctx.helpers.broadcastOpsUpdate).toHaveBeenCalledWith(
      'eng-test-001',
      expect.objectContaining({ type: 'lateral_movement', action: 'credential_harvest' }),
    );
  });

  it('handles complete failure gracefully', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // All calls fail
    mockFetch.mockResolvedValue({ ok: false, statusText: 'Network unreachable' });

    const result = await executeLateralMovement(ctx, asset);

    expect(result.credentialsHarvested).toEqual([]);
    expect(result.pivotTargetsDiscovered).toEqual([]);
    expect(result.successfulPivots).toEqual([]);
    expect(result.hostsCompromised).toEqual([]);
    expect(result.totalHops).toBe(0);
  });

  it('does not revisit already-compromised hosts', async () => {
    const ctx = makeCtx();
    const asset = makeAsset('10.0.0.50');

    // Discover target that is already the source
    mockFetch
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse('10.0.0.50')) // ARP returns self
      .mockResolvedValueOnce(mockSshResponse(''))
      .mockResolvedValueOnce(mockSshResponse(''));

    const result = await executeLateralMovement(ctx, asset);

    // Should not have any pivot targets (self excluded)
    expect(result.pivotTargetsDiscovered.length).toBe(0);
  });
});

// ─── Type Safety Tests ──────────────────────────────────────────────────────

describe('Type safety', () => {
  it('LateralMovementResult has all required fields', () => {
    const result: LateralMovementResult = {
      credentialsHarvested: [],
      pivotTargetsDiscovered: [],
      pivotAttempts: [],
      successfulPivots: [],
      pivotGraph: [],
      hostsCompromised: [],
      totalHops: 0,
      maxDepth: 0,
      evidenceIds: [],
      durationMs: 0,
    };
    expect(result).toBeDefined();
  });

  it('HarvestedCredential covers all credential types', () => {
    const types: HarvestedCredential['type'][] = ['password', 'ssh_key', 'hash', 'token', 'certificate'];
    expect(types.length).toBe(5);
  });

  it('PivotAttempt includes MITRE ATT&CK mapping', () => {
    const attempt: PivotAttempt = {
      id: 'test',
      sourceHost: '10.0.0.1',
      targetHost: '10.0.0.2',
      protocol: 'ssh',
      credential: {} as any,
      success: true,
      accessLevel: 'root',
      output: 'test',
      durationMs: 100,
      mitreId: 'T1021.004',
      timestamp: Date.now(),
    };
    expect(attempt.mitreId).toMatch(/^T\d{4}/);
  });
});
