import { describe, it, expect, vi } from 'vitest';

// Test the timeline aggregation service types and logic
describe('Engagement Timeline Service', () => {
  describe('Kill Chain Phase Ordering', () => {
    const PHASE_ORDER = [
      'reconnaissance',
      'weaponization',
      'delivery',
      'exploitation',
      'installation',
      'command_control',
      'actions_on_objectives',
    ];

    it('should have exactly 7 kill chain phases', () => {
      expect(PHASE_ORDER).toHaveLength(7);
    });

    it('should follow the correct MITRE ATT&CK kill chain order', () => {
      expect(PHASE_ORDER[0]).toBe('reconnaissance');
      expect(PHASE_ORDER[1]).toBe('weaponization');
      expect(PHASE_ORDER[2]).toBe('delivery');
      expect(PHASE_ORDER[3]).toBe('exploitation');
      expect(PHASE_ORDER[4]).toBe('installation');
      expect(PHASE_ORDER[5]).toBe('command_control');
      expect(PHASE_ORDER[6]).toBe('actions_on_objectives');
    });
  });

  describe('Timeline Event Structure', () => {
    it('should validate a well-formed timeline event', () => {
      const event = {
        id: 'domain_recon:42',
        engagementId: 1,
        timestamp: Date.now(),
        phase: 'reconnaissance',
        source: 'domain_recon',
        severity: 'high',
        title: 'Domain Recon: example.com',
        description: 'DNS analysis complete. 15 subdomains, 8 emails discovered.',
        icon: 'Search',
        color: 'cyan',
        sourceRecordId: 42,
        targetDomain: 'example.com',
        status: 'success',
        details: {
          domain: 'example.com',
          spoofable: true,
          spoofScore: 85,
          subdomainCount: 15,
          emailCount: 8,
        },
      };

      expect(event.id).toMatch(/^[a-z_]+:\d+$/);
      expect(event.phase).toBe('reconnaissance');
      expect(event.source).toBe('domain_recon');
      expect(event.severity).toMatch(/^(info|low|medium|high|critical)$/);
      expect(event.status).toMatch(/^(pending|running|success|failed|info)$/);
      expect(event.timestamp).toBeGreaterThan(0);
      expect(event.details).toBeDefined();
    });

    it('should validate exploitation event with agent deployment', () => {
      const exploitEvent = {
        id: 'exploit_job:7',
        engagementId: null,
        timestamp: Date.now(),
        phase: 'exploitation',
        source: 'exploit_job',
        severity: 'critical',
        title: 'MSF Exploit: ms17_010/eternalblue',
        description: 'exploit/windows/smb/ms17_010_eternalblue → 10.0.0.5:445. SUCCESS',
        icon: 'Zap',
        color: 'red',
        sourceRecordId: 7,
        targetDomain: 'target.com',
        msfModule: 'exploit/windows/smb/ms17_010_eternalblue',
        status: 'success',
        details: {
          exploitModule: 'exploit/windows/smb/ms17_010_eternalblue',
          payloadModule: 'windows/x64/meterpreter/reverse_tcp',
          targetIp: '10.0.0.5',
          targetPort: 445,
          msfSessionId: 1,
          sessionType: 'meterpreter',
        },
      };

      const agentEvent = {
        id: 'exploit_job_agent:7',
        engagementId: null,
        timestamp: Date.now() + 5000,
        phase: 'installation',
        source: 'exploit_job',
        severity: 'critical',
        title: 'Agent Deployed: abc123',
        description: 'Caldera agent installed on 10.0.0.5 via ms17_010/eternalblue',
        icon: 'Bot',
        color: 'red',
        sourceRecordId: 7,
        status: 'success',
        details: {
          calderaAgentPaw: 'abc123',
          sessionType: 'meterpreter',
          targetIp: '10.0.0.5',
        },
      };

      // Exploit event should be in exploitation phase
      expect(exploitEvent.phase).toBe('exploitation');
      expect(exploitEvent.msfModule).toContain('eternalblue');

      // Agent event should be in installation phase
      expect(agentEvent.phase).toBe('installation');
      expect(agentEvent.details.calderaAgentPaw).toBe('abc123');

      // Agent event should come after exploit event
      expect(agentEvent.timestamp).toBeGreaterThan(exploitEvent.timestamp);
    });
  });

  describe('Timeline Stats Computation', () => {
    function computeStats(events: any[]) {
      const byPhase: Record<string, number> = {
        reconnaissance: 0, weaponization: 0, delivery: 0,
        exploitation: 0, installation: 0, command_control: 0,
        actions_on_objectives: 0,
      };
      const bySeverity: Record<string, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
      const byStatus: Record<string, number> = {};
      const bySource: Record<string, number> = {};

      let firstEventTime: number | null = null;
      let lastEventTime: number | null = null;
      let firstRecon: number | null = null;
      let firstExploit: number | null = null;
      let firstAgent: number | null = null;

      for (const e of events) {
        byPhase[e.phase] = (byPhase[e.phase] || 0) + 1;
        bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
        byStatus[e.status] = (byStatus[e.status] || 0) + 1;
        bySource[e.source] = (bySource[e.source] || 0) + 1;

        if (firstEventTime === null || e.timestamp < firstEventTime) firstEventTime = e.timestamp;
        if (lastEventTime === null || e.timestamp > lastEventTime) lastEventTime = e.timestamp;

        if (e.phase === 'reconnaissance' && (firstRecon === null || e.timestamp < firstRecon)) firstRecon = e.timestamp;
        if (e.phase === 'exploitation' && (firstExploit === null || e.timestamp < firstExploit)) firstExploit = e.timestamp;
        if (e.phase === 'installation' && (firstAgent === null || e.timestamp < firstAgent)) firstAgent = e.timestamp;
      }

      const PHASE_ORDER = ['reconnaissance', 'weaponization', 'delivery', 'exploitation', 'installation', 'command_control', 'actions_on_objectives'];
      const phasesReached = PHASE_ORDER.filter(p => byPhase[p] > 0);
      const furthestPhase = phasesReached.length > 0 ? phasesReached[phasesReached.length - 1] : null;

      return {
        totalEvents: events.length,
        byPhase, bySeverity, byStatus, bySource,
        phasesReached, furthestPhase,
        firstEventTime, lastEventTime,
        timeToFirstExploit: firstRecon && firstExploit ? firstExploit - firstRecon : null,
        timeToFirstAgent: firstRecon && firstAgent ? firstAgent - firstRecon : null,
      };
    }

    it('should compute correct stats for a full kill chain', () => {
      const now = Date.now();
      const events = [
        { phase: 'reconnaissance', severity: 'info', status: 'success', source: 'domain_recon', timestamp: now },
        { phase: 'reconnaissance', severity: 'high', status: 'success', source: 'domain_intel_scan', timestamp: now + 1000 },
        { phase: 'weaponization', severity: 'medium', status: 'success', source: 'phishing_draft', timestamp: now + 60000 },
        { phase: 'delivery', severity: 'medium', status: 'success', source: 'gophish_campaign', timestamp: now + 120000 },
        { phase: 'exploitation', severity: 'critical', status: 'success', source: 'exploit_job', timestamp: now + 180000 },
        { phase: 'installation', severity: 'critical', status: 'success', source: 'exploit_job', timestamp: now + 240000 },
        { phase: 'command_control', severity: 'medium', status: 'info', source: 'activity_log', timestamp: now + 300000 },
      ];

      const stats = computeStats(events);

      expect(stats.totalEvents).toBe(7);
      expect(stats.phasesReached).toHaveLength(6); // no actions_on_objectives
      expect(stats.furthestPhase).toBe('command_control');
      expect(stats.byPhase.reconnaissance).toBe(2);
      expect(stats.byPhase.exploitation).toBe(1);
      expect(stats.timeToFirstExploit).toBe(180000);
      expect(stats.timeToFirstAgent).toBe(240000);
    });

    it('should handle empty event list', () => {
      const stats = computeStats([]);
      expect(stats.totalEvents).toBe(0);
      expect(stats.phasesReached).toHaveLength(0);
      expect(stats.furthestPhase).toBeNull();
      expect(stats.timeToFirstExploit).toBeNull();
      expect(stats.timeToFirstAgent).toBeNull();
    });

    it('should handle recon-only engagement', () => {
      const now = Date.now();
      const events = [
        { phase: 'reconnaissance', severity: 'info', status: 'success', source: 'domain_recon', timestamp: now },
        { phase: 'reconnaissance', severity: 'low', status: 'success', source: 'domain_intel_scan', timestamp: now + 5000 },
      ];

      const stats = computeStats(events);
      expect(stats.totalEvents).toBe(2);
      expect(stats.phasesReached).toEqual(['reconnaissance']);
      expect(stats.furthestPhase).toBe('reconnaissance');
      expect(stats.timeToFirstExploit).toBeNull();
    });

    it('should correctly count severity distribution', () => {
      const now = Date.now();
      const events = [
        { phase: 'reconnaissance', severity: 'info', status: 'success', source: 'domain_recon', timestamp: now },
        { phase: 'exploitation', severity: 'critical', status: 'success', source: 'exploit_job', timestamp: now + 1000 },
        { phase: 'exploitation', severity: 'critical', status: 'failed', source: 'exploit_job', timestamp: now + 2000 },
        { phase: 'delivery', severity: 'high', status: 'success', source: 'gophish_campaign', timestamp: now + 3000 },
      ];

      const stats = computeStats(events);
      expect(stats.bySeverity.critical).toBe(2);
      expect(stats.bySeverity.high).toBe(1);
      expect(stats.bySeverity.info).toBe(1);
      expect(stats.byStatus.success).toBe(3);
      expect(stats.byStatus.failed).toBe(1);
    });

    it('should correctly count source distribution', () => {
      const now = Date.now();
      const events = [
        { phase: 'reconnaissance', severity: 'info', status: 'success', source: 'domain_recon', timestamp: now },
        { phase: 'reconnaissance', severity: 'info', status: 'success', source: 'domain_recon', timestamp: now + 1000 },
        { phase: 'exploitation', severity: 'critical', status: 'success', source: 'exploit_job', timestamp: now + 2000 },
        { phase: 'delivery', severity: 'medium', status: 'success', source: 'gophish_campaign', timestamp: now + 3000 },
      ];

      const stats = computeStats(events);
      expect(stats.bySource.domain_recon).toBe(2);
      expect(stats.bySource.exploit_job).toBe(1);
      expect(stats.bySource.gophish_campaign).toBe(1);
    });
  });

  describe('Event ID Format', () => {
    it('should generate unique IDs from source and record ID', () => {
      const makeId = (source: string, recordId: number | string) => `${source}:${recordId}`;

      expect(makeId('domain_recon', 42)).toBe('domain_recon:42');
      expect(makeId('exploit_job', 7)).toBe('exploit_job:7');
      expect(makeId('exploit_job_agent', 7)).toBe('exploit_job_agent:7');
      expect(makeId('activity_log', 100)).toBe('activity_log:100');
    });

    it('should differentiate exploit events from agent deployment events', () => {
      const exploitId = `exploit_job:7`;
      const agentId = `exploit_job_agent:7`;

      expect(exploitId).not.toBe(agentId);
      expect(exploitId).toContain('exploit_job:');
      expect(agentId).toContain('exploit_job_agent:');
    });
  });

  describe('Event Source to Phase Mapping', () => {
    const SOURCE_PHASE_MAP: Record<string, string> = {
      domain_recon: 'reconnaissance',
      domain_intel_scan: 'reconnaissance',
      phishing_draft: 'weaponization',
      gophish_campaign: 'delivery',
      typosquat_domain: 'delivery',
      exploit_job: 'exploitation',
      // exploit_job can also produce 'installation' events (agent deployment)
      caldera_operation: 'command_control',
      caldera_agent: 'installation',
      activity_log: 'command_control', // default, can vary
      engagement_pipeline: 'reconnaissance',
    };

    it('should map all event sources to valid kill chain phases', () => {
      const validPhases = [
        'reconnaissance', 'weaponization', 'delivery', 'exploitation',
        'installation', 'command_control', 'actions_on_objectives',
      ];

      for (const [source, phase] of Object.entries(SOURCE_PHASE_MAP)) {
        expect(validPhases).toContain(phase);
      }
    });

    it('should have recon sources map to reconnaissance', () => {
      expect(SOURCE_PHASE_MAP.domain_recon).toBe('reconnaissance');
      expect(SOURCE_PHASE_MAP.domain_intel_scan).toBe('reconnaissance');
    });

    it('should have delivery sources map to delivery', () => {
      expect(SOURCE_PHASE_MAP.gophish_campaign).toBe('delivery');
      expect(SOURCE_PHASE_MAP.typosquat_domain).toBe('delivery');
    });
  });

  describe('Duration Formatting', () => {
    function formatDuration(ms: number | null): string {
      if (!ms) return '—';
      const seconds = Math.floor(ms / 1000);
      if (seconds < 60) return `${seconds}s`;
      const minutes = Math.floor(seconds / 60);
      if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
      const hours = Math.floor(minutes / 60);
      if (hours < 24) return `${hours}h ${minutes % 60}m`;
      const days = Math.floor(hours / 24);
      return `${days}d ${hours % 24}h`;
    }

    it('should format null as dash', () => {
      expect(formatDuration(null)).toBe('—');
    });

    it('should format seconds', () => {
      expect(formatDuration(30000)).toBe('30s');
    });

    it('should format minutes', () => {
      expect(formatDuration(180000)).toBe('3m 0s');
    });

    it('should format hours', () => {
      expect(formatDuration(7200000)).toBe('2h 0m');
    });

    it('should format days', () => {
      expect(formatDuration(172800000)).toBe('2d 0h');
    });

    it('should format mixed durations', () => {
      expect(formatDuration(3661000)).toBe('1h 1m');
      expect(formatDuration(90000)).toBe('1m 30s');
    });
  });
});
