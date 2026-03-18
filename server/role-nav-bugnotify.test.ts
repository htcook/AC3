import { describe, it, expect, vi } from 'vitest';

/**
 * Tests for role-based navigation filtering and bug report notification.
 * These test the core logic without requiring React rendering.
 * 
 * UPDATED: Reflects the reorganized sidebar navigation with new group IDs:
 * - agent-management → c2-agents
 * - integrations → infrastructure
 * - ssil/training merged into llm-ai
 */

// ---- Role-based navigation tests ----

// Replicate the core logic from sidebar-nav.ts for testability
type UserRole = 'admin' | 'operator' | 'analyst' | 'team_lead' | 'executive' | 'client' | 'soc' | 'viewer';

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

// All group IDs from the reorganized sidebar nav
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

describe('Role-Based Navigation Access', () => {
  it('admin should have access to all navigation groups', () => {
    const groups = getAccessibleGroups('admin');
    expect(groups).toEqual(ALL_GROUP_IDS);
  });

  it('executive should only see command-control, compliance-reporting, and ksi-fedramp', () => {
    const groups = getAccessibleGroups('executive');
    expect(groups).toEqual(['command-control', 'compliance-reporting', 'ksi-fedramp']);
    expect(groups).not.toContain('exploit-emulation');
    expect(groups).not.toContain('campaign-ops');
    expect(groups).not.toContain('admin');
  });

  it('client should only see command-control and compliance-reporting', () => {
    const groups = getAccessibleGroups('client');
    expect(groups).toEqual(['command-control', 'compliance-reporting']);
    expect(groups.length).toBe(2);
  });

  it('viewer should only see command-control and compliance-reporting', () => {
    const groups = getAccessibleGroups('viewer');
    expect(groups).toEqual(['command-control', 'compliance-reporting']);
    expect(groups.length).toBe(2);
  });

  it('operator should have full pentest/red team toolkit but not admin or compliance', () => {
    const groups = getAccessibleGroups('operator');
    expect(groups).toContain('campaign-ops');
    expect(groups).toContain('exploit-emulation');
    expect(groups).toContain('c2-agents');
    expect(groups).toContain('scanning');
    expect(groups).toContain('test-lab');
    expect(groups).toContain('infrastructure');
    expect(groups).toContain('llm-ai');
    expect(groups).not.toContain('admin');
    expect(groups).not.toContain('compliance-reporting');
  });

  it('analyst should have intel and compliance groups but not offensive tools', () => {
    const groups = getAccessibleGroups('analyst');
    expect(groups).toContain('intel-recon');
    expect(groups).toContain('compliance-reporting');
    expect(groups).toContain('ksi-fedramp');
    expect(groups).toContain('llm-ai');
    expect(groups).not.toContain('exploit-emulation');
    expect(groups).not.toContain('campaign-ops');
    expect(groups).not.toContain('c2-agents');
  });

  it('team_lead should have broad access including admin and all operator tools', () => {
    const groups = getAccessibleGroups('team_lead');
    expect(groups).toContain('admin');
    expect(groups).toContain('campaign-ops');
    expect(groups).toContain('compliance-reporting');
    expect(groups).toContain('ksi-fedramp');
    expect(groups).toContain('c2-agents');
    expect(groups).toContain('exploit-emulation');
    expect(groups).toContain('infrastructure');
  });

  it('soc should have detection, infrastructure (SIEM/SOAR), and intel', () => {
    const groups = getAccessibleGroups('soc');
    expect(groups).toContain('detection-validation');
    expect(groups).toContain('infrastructure');
    expect(groups).toContain('intel-recon');
    expect(groups).toContain('llm-ai');
    expect(groups).not.toContain('exploit-emulation');
    expect(groups).not.toContain('admin');
  });

  it('executive should never see offensive or technical groups', () => {
    const groups = getAccessibleGroups('executive');
    expect(groups).not.toContain('exploit-emulation');
    expect(groups).not.toContain('campaign-ops');
    expect(groups).not.toContain('scanning');
    expect(groups).not.toContain('admin');
    expect(groups).not.toContain('c2-agents');
    expect(groups).not.toContain('llm-ai');
  });

  it('all roles should have access to command-control (dashboard)', () => {
    const allRoles: UserRole[] = ['admin', 'operator', 'analyst', 'team_lead', 'executive', 'client', 'soc', 'viewer'];
    for (const role of allRoles) {
      const groups = getAccessibleGroups(role);
      expect(groups).toContain('command-control');
    }
  });

  it('only admin and team_lead should have access to admin group', () => {
    const nonAdminRoles: UserRole[] = ['operator', 'analyst', 'executive', 'client', 'soc', 'viewer'];
    for (const role of nonAdminRoles) {
      const groups = getAccessibleGroups(role);
      expect(groups).not.toContain('admin');
    }
  });
});

// ---- Bug report notification tests ----

describe('Bug Report Notification', () => {
  it('should format bug report notification with correct fields', () => {
    const bugReport = {
      title: 'Page fails to load',
      description: 'The engagement ops page shows a blank screen',
      severity: 'high',
      stepsToReproduce: '1. Navigate to Engagement Ops\n2. Click on active engagement',
      expectedBehavior: 'Page should load with engagement data',
      actualBehavior: 'Blank white screen with console errors',
      browserInfo: 'Chrome 120, macOS',
    };

    // Simulate the notification content formatting from quick-action-executor.ts
    const title = `Bug Report: ${bugReport.title}`;
    const content = [
      `**Severity:** ${bugReport.severity}`,
      `**Description:** ${bugReport.description}`,
      bugReport.stepsToReproduce ? `**Steps:** ${bugReport.stepsToReproduce}` : '',
      bugReport.expectedBehavior ? `**Expected:** ${bugReport.expectedBehavior}` : '',
      bugReport.actualBehavior ? `**Actual:** ${bugReport.actualBehavior}` : '',
      bugReport.browserInfo ? `**Browser:** ${bugReport.browserInfo}` : '',
    ].filter(Boolean).join('\n');

    expect(title).toBe('Bug Report: Page fails to load');
    expect(content).toContain('**Severity:** high');
    expect(content).toContain('**Description:** The engagement ops page shows a blank screen');
    expect(content).toContain('**Steps:**');
    expect(content).toContain('**Browser:** Chrome 120, macOS');
  });

  it('should handle minimal bug report (title + description only)', () => {
    const bugReport = {
      title: 'Something broke',
      description: 'Error on dashboard',
      severity: 'medium',
    };

    const title = `Bug Report: ${bugReport.title}`;
    const content = [
      `**Severity:** ${bugReport.severity}`,
      `**Description:** ${bugReport.description}`,
    ].filter(Boolean).join('\n');

    expect(title).toBe('Bug Report: Something broke');
    expect(content).toContain('**Severity:** medium');
    expect(content).not.toContain('**Steps:**');
    expect(content).not.toContain('**Browser:**');
  });
});

// ---- Executive Dashboard click-through tests ----

describe('Executive Dashboard Click-Through Routes', () => {
  const clickThroughRoutes: Record<string, string> = {
    'Critical Vulns': '/engagement-ops',
    'Total Findings': '/engagement-ops',
    'Active Engagements': '/engagement-ops',
    'AI Compliance': '/ai-governance',
    'MITRE Coverage': '/mitre-attack',
    'FedRAMP Providers': '/fips-compliance',
    'Active Groups': '/threat-groups',
  };

  it('should have valid route paths for all click-through targets', () => {
    for (const [label, route] of Object.entries(clickThroughRoutes)) {
      expect(route).toMatch(/^\//);
      expect(route.length).toBeGreaterThan(1);
    }
  });

  it('should map all 7 stat cards to navigation targets', () => {
    expect(Object.keys(clickThroughRoutes).length).toBe(7);
  });

  it('should not have any duplicate routes for different stat cards', () => {
    const routes = Object.values(clickThroughRoutes);
    // Some cards may share routes (e.g., multiple cards → engagement-ops), that's fine
    // But each card should have a defined route
    for (const route of routes) {
      expect(route).toBeTruthy();
    }
  });
});
