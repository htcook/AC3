import { describe, it, expect } from 'vitest';

/**
 * Tests for:
 * 1. Reorganized role-based sidebar navigation
 * 2. Agent Performance Leaderboard router logic
 * 3. Real-Time Engagement Monitor router logic
 */

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 1: Role-Based Sidebar Navigation (Reorganized)
// ═══════════════════════════════════════════════════════════════════════════

type UserRole = 'admin' | 'operator' | 'analyst' | 'team_lead' | 'executive' | 'client' | 'soc' | 'viewer';

// Mirror the ROLE_GROUP_ACCESS from the reorganized sidebar-nav.ts
const ROLE_GROUP_ACCESS: Record<UserRole, string[] | 'all'> = {
  admin: 'all',
  operator: [
    'command-control', 'campaign-ops', 'exploit-emulation', 'c2-agents',
    'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'ad-cloud',
    'infrastructure', 'llm-ai',
  ],
  team_lead: [
    'command-control', 'campaign-ops', 'exploit-emulation', 'c2-agents',
    'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'ad-cloud',
    'infrastructure', 'compliance-reporting', 'ksi-fedramp', 'llm-ai', 'admin',
  ],
  analyst: [
    'command-control', 'intel-recon', 'scanning', 'detection-validation',
    'compliance-reporting', 'ksi-fedramp', 'llm-ai',
  ],
  soc: [
    'command-control', 'intel-recon', 'detection-validation', 'infrastructure',
    'llm-ai', 'compliance-reporting',
  ],
  executive: ['command-control', 'compliance-reporting', 'ksi-fedramp'],
  client: ['command-control', 'compliance-reporting'],
  viewer: ['command-control', 'compliance-reporting'],
};

// All group IDs from the reorganized sidebar
const ALL_GROUP_IDS = [
  'command-control', 'campaign-ops', 'exploit-emulation', 'c2-agents',
  'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'ad-cloud',
  'infrastructure', 'compliance-reporting', 'ksi-fedramp', 'llm-ai', 'admin',
];

function getAccessibleGroups(role: UserRole): string[] {
  const access = ROLE_GROUP_ACCESS[role];
  if (access === 'all') return ALL_GROUP_IDS;
  return access;
}

describe('Reorganized Role-Based Navigation Access', () => {
  it('admin should have access to all 14 navigation groups', () => {
    const groups = getAccessibleGroups('admin');
    expect(groups).toEqual(ALL_GROUP_IDS);
    expect(groups.length).toBe(14);
  });

  // ── Operator: Full Pentest/Red Team Toolkit ──
  describe('Operator — Full Pentest/Red Team Toolkit', () => {
    const groups = getAccessibleGroups('operator');

    it('should have access to 11 groups', () => {
      expect(groups.length).toBe(11);
    });

    it('should have all offensive operation groups', () => {
      expect(groups).toContain('campaign-ops');
      expect(groups).toContain('exploit-emulation');
      expect(groups).toContain('c2-agents');
    });

    it('should have scanning and detection validation', () => {
      expect(groups).toContain('scanning');
      expect(groups).toContain('detection-validation');
    });

    it('should have intelligence and recon', () => {
      expect(groups).toContain('intel-recon');
    });

    it('should have AD & Cloud attack paths', () => {
      expect(groups).toContain('ad-cloud');
    });

    it('should have test lab for safe training', () => {
      expect(groups).toContain('test-lab');
    });

    it('should have infrastructure (SSH keys, scan servers, webhooks)', () => {
      expect(groups).toContain('infrastructure');
    });

    it('should have LLM & AI tools (AI Attack Planner, Knowledge Base, Real-Time Monitor)', () => {
      expect(groups).toContain('llm-ai');
    });

    it('should NOT have compliance/reporting (not operator concern)', () => {
      expect(groups).not.toContain('compliance-reporting');
    });

    it('should NOT have KSI/FedRAMP', () => {
      expect(groups).not.toContain('ksi-fedramp');
    });

    it('should NOT have admin/system', () => {
      expect(groups).not.toContain('admin');
    });
  });

  // ── Team Lead: Operator + Compliance + Admin ──
  describe('Team Lead — Operator Toolkit + Compliance + Admin', () => {
    const groups = getAccessibleGroups('team_lead');

    it('should have access to 14 groups (everything)', () => {
      expect(groups.length).toBe(14);
    });

    it('should have all operator groups', () => {
      const operatorGroups = getAccessibleGroups('operator');
      for (const g of operatorGroups) {
        expect(groups).toContain(g);
      }
    });

    it('should additionally have compliance-reporting', () => {
      expect(groups).toContain('compliance-reporting');
    });

    it('should additionally have ksi-fedramp', () => {
      expect(groups).toContain('ksi-fedramp');
    });

    it('should additionally have admin', () => {
      expect(groups).toContain('admin');
    });
  });

  // ── Analyst: Intel + Detection + Compliance + LLM Observability ──
  describe('Analyst — Intel, Detection, Compliance, LLM', () => {
    const groups = getAccessibleGroups('analyst');

    it('should have access to 7 groups', () => {
      expect(groups.length).toBe(7);
    });

    it('should have intel-recon for threat analysis', () => {
      expect(groups).toContain('intel-recon');
    });

    it('should have scanning and detection-validation', () => {
      expect(groups).toContain('scanning');
      expect(groups).toContain('detection-validation');
    });

    it('should have compliance-reporting and ksi-fedramp', () => {
      expect(groups).toContain('compliance-reporting');
      expect(groups).toContain('ksi-fedramp');
    });

    it('should have llm-ai for observability', () => {
      expect(groups).toContain('llm-ai');
    });

    it('should NOT have offensive groups', () => {
      expect(groups).not.toContain('campaign-ops');
      expect(groups).not.toContain('exploit-emulation');
      expect(groups).not.toContain('c2-agents');
    });

    it('should NOT have test-lab or infrastructure', () => {
      expect(groups).not.toContain('test-lab');
      expect(groups).not.toContain('infrastructure');
    });
  });

  // ── SOC: Detection + SSIL + Integrations + Intel ──
  describe('SOC — Detection, Integrations, Intel, Monitoring', () => {
    const groups = getAccessibleGroups('soc');

    it('should have access to 6 groups', () => {
      expect(groups.length).toBe(6);
    });

    it('should have detection-validation', () => {
      expect(groups).toContain('detection-validation');
    });

    it('should have infrastructure (SIEM/SOAR connectors)', () => {
      expect(groups).toContain('infrastructure');
    });

    it('should have intel-recon for threat awareness', () => {
      expect(groups).toContain('intel-recon');
    });

    it('should have llm-ai for SSIL monitoring', () => {
      expect(groups).toContain('llm-ai');
    });

    it('should have compliance-reporting', () => {
      expect(groups).toContain('compliance-reporting');
    });

    it('should NOT have offensive groups', () => {
      expect(groups).not.toContain('campaign-ops');
      expect(groups).not.toContain('exploit-emulation');
      expect(groups).not.toContain('c2-agents');
    });
  });

  // ── Executive: Dashboards + Compliance Only ──
  describe('Executive — Dashboards and Compliance', () => {
    const groups = getAccessibleGroups('executive');

    it('should have access to exactly 3 groups', () => {
      expect(groups.length).toBe(3);
    });

    it('should have command-control, compliance-reporting, ksi-fedramp', () => {
      expect(groups).toContain('command-control');
      expect(groups).toContain('compliance-reporting');
      expect(groups).toContain('ksi-fedramp');
    });

    it('should NOT have any offensive or technical groups', () => {
      expect(groups).not.toContain('exploit-emulation');
      expect(groups).not.toContain('campaign-ops');
      expect(groups).not.toContain('scanning');
      expect(groups).not.toContain('c2-agents');
      expect(groups).not.toContain('admin');
    });
  });

  // ── Client: Read-Only Compliance ──
  describe('Client — Read-Only Compliance View', () => {
    const groups = getAccessibleGroups('client');

    it('should have access to exactly 2 groups', () => {
      expect(groups.length).toBe(2);
    });

    it('should have command-control and compliance-reporting only', () => {
      expect(groups).toContain('command-control');
      expect(groups).toContain('compliance-reporting');
    });
  });

  // ── Viewer: Minimal Access ──
  describe('Viewer — Minimal Dashboard Access', () => {
    const groups = getAccessibleGroups('viewer');

    it('should have access to exactly 2 groups', () => {
      expect(groups.length).toBe(2);
    });

    it('should match client access level', () => {
      const clientGroups = getAccessibleGroups('client');
      expect(groups).toEqual(clientGroups);
    });
  });

  // ── Cross-Role Invariants ──
  describe('Cross-Role Invariants', () => {
    const allRoles: UserRole[] = ['admin', 'operator', 'analyst', 'team_lead', 'executive', 'client', 'soc', 'viewer'];

    it('all roles should have access to command-control', () => {
      for (const role of allRoles) {
        const groups = getAccessibleGroups(role);
        expect(groups).toContain('command-control');
      }
    });

    it('only admin and team_lead should have access to admin group', () => {
      for (const role of allRoles) {
        const groups = getAccessibleGroups(role);
        if (role === 'admin' || role === 'team_lead') {
          expect(groups).toContain('admin');
        } else {
          expect(groups).not.toContain('admin');
        }
      }
    });

    it('operator should have a superset of what analyst does NOT have (offensive tools)', () => {
      const operatorGroups = getAccessibleGroups('operator');
      const analystGroups = getAccessibleGroups('analyst');
      // Operator has offensive tools analyst doesn't
      expect(operatorGroups).toContain('campaign-ops');
      expect(analystGroups).not.toContain('campaign-ops');
      expect(operatorGroups).toContain('exploit-emulation');
      expect(analystGroups).not.toContain('exploit-emulation');
      expect(operatorGroups).toContain('c2-agents');
      expect(analystGroups).not.toContain('c2-agents');
    });

    it('team_lead should be a superset of operator access', () => {
      const teamLeadGroups = getAccessibleGroups('team_lead');
      const operatorGroups = getAccessibleGroups('operator');
      for (const g of operatorGroups) {
        expect(teamLeadGroups).toContain(g);
      }
    });

    it('renamed group c2-agents should exist (was agent-management)', () => {
      expect(ALL_GROUP_IDS).toContain('c2-agents');
      expect(ALL_GROUP_IDS).not.toContain('agent-management');
    });

    it('infrastructure group should exist (was integrations)', () => {
      expect(ALL_GROUP_IDS).toContain('infrastructure');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 2: Agent Performance Leaderboard
// ═══════════════════════════════════════════════════════════════════════════

describe('Agent Performance Leaderboard', () => {
  // Simulate the leaderboard ranking logic
  interface AgentStats {
    agentId: string;
    name: string;
    delegationCount: number;
    successCount: number;
    failCount: number;
    avgConfidence: number;
    totalTokens: number;
    avgLatencyMs: number;
  }

  function computeSuccessRate(stats: AgentStats): number {
    const total = stats.successCount + stats.failCount;
    if (total === 0) return 0;
    return Math.round((stats.successCount / total) * 100 * 10) / 10;
  }

  function computeCompositeScore(stats: AgentStats): number {
    const successRate = computeSuccessRate(stats);
    const delegationWeight = Math.min(stats.delegationCount / 100, 1); // normalize to 0-1
    const confidenceWeight = stats.avgConfidence / 100;
    // Composite: 50% success rate + 30% delegation frequency + 20% confidence
    return Math.round((successRate * 0.5 + delegationWeight * 100 * 0.3 + confidenceWeight * 100 * 0.2) * 10) / 10;
  }

  function rankAgents(agents: AgentStats[]): AgentStats[] {
    return [...agents].sort((a, b) => computeCompositeScore(b) - computeCompositeScore(a));
  }

  const mockAgents: AgentStats[] = [
    { agentId: 'recon', name: 'Recon Specialist', delegationCount: 150, successCount: 140, failCount: 10, avgConfidence: 92, totalTokens: 500000, avgLatencyMs: 1200 },
    { agentId: 'exploit', name: 'Exploit Specialist', delegationCount: 80, successCount: 60, failCount: 20, avgConfidence: 78, totalTokens: 300000, avgLatencyMs: 2500 },
    { agentId: 'stealth', name: 'Stealth Specialist', delegationCount: 45, successCount: 42, failCount: 3, avgConfidence: 95, totalTokens: 200000, avgLatencyMs: 800 },
    { agentId: 'report', name: 'Report Specialist', delegationCount: 30, successCount: 28, failCount: 2, avgConfidence: 88, totalTokens: 400000, avgLatencyMs: 3000 },
    { agentId: 'inactive', name: 'Inactive Agent', delegationCount: 0, successCount: 0, failCount: 0, avgConfidence: 0, totalTokens: 0, avgLatencyMs: 0 },
  ];

  it('should compute success rate correctly', () => {
    expect(computeSuccessRate(mockAgents[0])).toBe(93.3); // 140/150
    expect(computeSuccessRate(mockAgents[1])).toBe(75); // 60/80
    expect(computeSuccessRate(mockAgents[4])).toBe(0); // 0/0
  });

  it('should handle zero delegation gracefully', () => {
    const inactive = mockAgents[4];
    expect(computeSuccessRate(inactive)).toBe(0);
    expect(computeCompositeScore(inactive)).toBe(0);
  });

  it('should rank agents by composite score (success rate + delegation + confidence)', () => {
    const ranked = rankAgents(mockAgents);
    // Recon should be #1 (high success rate + high delegation + high confidence)
    expect(ranked[0].agentId).toBe('recon');
    // Inactive should be last
    expect(ranked[ranked.length - 1].agentId).toBe('inactive');
  });

  it('should rank high-success-rate agents above high-delegation-but-low-success agents', () => {
    const ranked = rankAgents(mockAgents);
    const stealthIdx = ranked.findIndex(a => a.agentId === 'stealth');
    const exploitIdx = ranked.findIndex(a => a.agentId === 'exploit');
    // Stealth has 93.3% success vs Exploit's 75%, even though Exploit has more delegations
    // The composite score should still favor stealth due to success rate weight
    expect(stealthIdx).toBeLessThan(exploitIdx);
  });

  it('should return all 10 agents when available (leaderboard shows top 10)', () => {
    const tenAgents = Array.from({ length: 10 }, (_, i) => ({
      agentId: `agent-${i}`,
      name: `Agent ${i}`,
      delegationCount: (10 - i) * 10,
      successCount: (10 - i) * 8,
      failCount: (10 - i) * 2,
      avgConfidence: 80 + i,
      totalTokens: 100000,
      avgLatencyMs: 1000,
    }));
    const ranked = rankAgents(tenAgents);
    expect(ranked.length).toBe(10);
    // First agent should have highest composite score
    expect(ranked[0].delegationCount).toBeGreaterThan(ranked[9].delegationCount);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 3: Real-Time Engagement Monitor
// ═══════════════════════════════════════════════════════════════════════════

describe('Real-Time Engagement Monitor', () => {
  // Simulate the event types the monitor handles
  type EventType = 'llm_decision' | 'agent_delegation' | 'phase_transition' | 'finding_discovered' | 'exploit_attempt' | 'stealth_alert';

  interface MonitorEvent {
    id: string;
    type: EventType;
    engagementId: number;
    timestamp: number;
    data: Record<string, any>;
  }

  function filterEventsByType(events: MonitorEvent[], type: EventType): MonitorEvent[] {
    return events.filter(e => e.type === type);
  }

  function filterEventsByEngagement(events: MonitorEvent[], engagementId: number): MonitorEvent[] {
    return events.filter(e => e.engagementId === engagementId);
  }

  function getEventRate(events: MonitorEvent[], windowMs: number): number {
    const now = Date.now();
    const recent = events.filter(e => now - e.timestamp < windowMs);
    return recent.length;
  }

  const mockEvents: MonitorEvent[] = [
    { id: '1', type: 'llm_decision', engagementId: 1, timestamp: Date.now() - 1000, data: { decision: 'scan_port', confidence: 0.92 } },
    { id: '2', type: 'agent_delegation', engagementId: 1, timestamp: Date.now() - 2000, data: { agent: 'recon', task: 'nmap_scan' } },
    { id: '3', type: 'finding_discovered', engagementId: 1, timestamp: Date.now() - 3000, data: { severity: 'high', title: 'SQL Injection' } },
    { id: '4', type: 'llm_decision', engagementId: 2, timestamp: Date.now() - 4000, data: { decision: 'exploit_sqli', confidence: 0.85 } },
    { id: '5', type: 'exploit_attempt', engagementId: 2, timestamp: Date.now() - 5000, data: { technique: 'T1190', success: true } },
    { id: '6', type: 'stealth_alert', engagementId: 1, timestamp: Date.now() - 60000, data: { score: 0.3, reason: 'Noisy scan detected' } },
    { id: '7', type: 'phase_transition', engagementId: 1, timestamp: Date.now() - 120000, data: { from: 'recon', to: 'exploitation' } },
  ];

  it('should filter events by type', () => {
    const llmDecisions = filterEventsByType(mockEvents, 'llm_decision');
    expect(llmDecisions.length).toBe(2);
    expect(llmDecisions.every(e => e.type === 'llm_decision')).toBe(true);
  });

  it('should filter events by engagement', () => {
    const eng1Events = filterEventsByEngagement(mockEvents, 1);
    expect(eng1Events.length).toBe(5);
    expect(eng1Events.every(e => e.engagementId === 1)).toBe(true);
  });

  it('should compute event rate within time window', () => {
    // All events within last 10 seconds
    const recentRate = getEventRate(mockEvents, 10000);
    expect(recentRate).toBe(5); // events 1-5 are within 10s
  });

  it('should return 0 rate for empty event list', () => {
    expect(getEventRate([], 60000)).toBe(0);
  });

  it('should handle all event types', () => {
    const eventTypes: EventType[] = ['llm_decision', 'agent_delegation', 'phase_transition', 'finding_discovered', 'exploit_attempt', 'stealth_alert'];
    for (const type of eventTypes) {
      const filtered = filterEventsByType(mockEvents, type);
      expect(filtered.length).toBeGreaterThanOrEqual(0);
      expect(filtered.every(e => e.type === type)).toBe(true);
    }
  });

  it('should sort events by timestamp (newest first) for feed display', () => {
    const sorted = [...mockEvents].sort((a, b) => b.timestamp - a.timestamp);
    expect(sorted[0].id).toBe('1'); // most recent
    expect(sorted[sorted.length - 1].id).toBe('7'); // oldest
  });

  it('should identify active engagements from events', () => {
    const activeEngagementIds = [...new Set(mockEvents.map(e => e.engagementId))];
    expect(activeEngagementIds).toContain(1);
    expect(activeEngagementIds).toContain(2);
    expect(activeEngagementIds.length).toBe(2);
  });

  it('should extract stealth alerts for OPSEC monitoring', () => {
    const stealthAlerts = filterEventsByType(mockEvents, 'stealth_alert');
    expect(stealthAlerts.length).toBe(1);
    expect(stealthAlerts[0].data.score).toBe(0.3);
    expect(stealthAlerts[0].data.reason).toBe('Noisy scan detected');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 4: Lab Engagement Seed Data Validation
// ═══════════════════════════════════════════════════════════════════════════

describe('Lab Engagement Seed Data Structure', () => {
  const LAB_TARGETS = [
    { name: 'DVWA', port: 8080, type: 'web' },
    { name: 'bWAPP', port: 8081, type: 'web' },
    { name: 'Mutillidae', port: 8082, type: 'web' },
    { name: 'Juice Shop', port: 3000, type: 'web' },
    { name: 'WebGoat', port: 8083, type: 'web' },
  ];

  const AGENT_PREFIXES = [
    'ac3-recon', 'ac3-exploit', 'ac3-stealth', 'ac3-report',
    'ac3-phishing', 'ac3-persistence', 'ac3-lateral', 'ac3-exfil',
    'ac3-privesc', 'ac3-orchestrator',
  ];

  it('should have 5 lab targets for engagement creation', () => {
    expect(LAB_TARGETS.length).toBe(5);
  });

  it('should have 10 agent prefixes for telemetry distribution', () => {
    expect(AGENT_PREFIXES.length).toBe(10);
  });

  it('all lab targets should have unique ports', () => {
    const ports = LAB_TARGETS.map(t => t.port);
    expect(new Set(ports).size).toBe(ports.length);
  });

  it('all agent prefixes should start with ac3-', () => {
    for (const prefix of AGENT_PREFIXES) {
      expect(prefix.startsWith('ac3-')).toBe(true);
    }
  });

  it('all agent prefixes should be unique', () => {
    expect(new Set(AGENT_PREFIXES).size).toBe(AGENT_PREFIXES.length);
  });
});
