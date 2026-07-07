/**
 * Role-Based Access Control (RBAC) Configuration
 * Granular per-route access control for the AC3 platform.
 *
 * Design Principles:
 *   operator   — Full attack toolkit: all scan types, engagements, exploit tools, C2, manual execution
 *   team_lead  — Operator capabilities + team management + engagement oversight + risk analysis
 *   analyst    — Analysis-focused: scan results, evidence, intel, defense validation (no active exploitation)
 *   soc        — Blue team: detection coverage, defense validation, threat intel, SIEM/SOAR
 *   executive  — Minimal: risk dashboards, KSI, compliance, reports
 *   client     — Assessment portal: RoE approval/sign-off, scan results, evidence, reports
 *   viewer     — Reports only
 *   admin      — Platform administration: users, integrations, infrastructure (NOT offensive tools)
 *   user       — Legacy default (same as operator)
 */

export type UserRole = 'operator' | 'team_lead' | 'analyst' | 'executive' | 'client' | 'admin' | 'user' | 'viewer' | 'soc';

// ─── Per-Route Access Lists ─────────────────────────────────────────────────
// Each role has an explicit allowlist of routes they can access.

const OPERATOR_ROUTES: string[] = [
  // Command Center — Mission Operations
  '/dashboard',
  '/workflows',
  '/engagements',
  '/engagement-ops',
  '/engagement-timeline',
  '/kill-chain',
  '/opsec-dashboard',
  '/engagement-automation',
  '/roe-builder',
  '/roe-self-service',
  '/campaign-archetypes',
  '/hunt-ops',
  '/training-lab',
  '/bug-bounty',
  // Command Center — Risk & Analysis
  '/scoring',
  '/ai-attack-planner',
  '/preflight-checks',
  '/attack-coverage',
  '/corroboration-engine',
  // Attack Surface — Discovery & Recon
  '/discovery-chain',
  '/domain-intel',
  '/domain-intel/history',
  '/web-crawler',
  '/osint-monitor',
  '/email-security',
  // Attack Surface — Scanning & Enumeration
  '/tools/subfinder',
  '/tools/httpx',
  '/tools/naabu',
  '/nuclei-scanner',
  '/vuln-scanner',
  '/dast-scanners',
  '/packet-analysis',
  '/scan-scheduler',
  '/config-baseline',
  '/scanforge-dashboard',
  '/commercial-scanners',
  // Attack Surface — Attack Paths
  '/attack-paths',
  '/attack-path-discovery',
  '/attack-vector-engine',
  '/cloud-attack-paths',
  '/cloud-security-validation',
  '/cloud-workload-testing',
  '/ad-attack-sim',
  '/ad-attack-path-graph',
  '/ad-domain-connector',
  '/bloodhound-import',
  '/forest-mapper',
  // Emulation & Testing — Agents & Emulation
  '/agents',
  '/emulation-playbooks',
  '/ability-graph',
  '/atomic-red-team',
  '/evasion-engine',
  '/agentless-bas',
  '/agent-manager',
  '/agent-installer',
  // Emulation & Testing — Defense Validation
  '/purple-team',
  '/edr-validation',
  '/detection-coverage',
  '/continuous-validation',
  '/ngfw-validation',
  '/ai-security-validation',
  '/remediation-verification',
  // Emulation & Testing — Ember C2
  '/ember',
  '/ember/deploy',
  '/ember/tasks',
  '/ember/payloads',
  '/ember/swarm',
  '/ember/intelligence',
  '/ember/capabilities',
  '/ember/cognitive',
  // Emulation & Testing — Test Lab
  '/test-lab',
  '/test-lab/environments',
  '/test-lab/scenarios',
  '/test-lab/implant',
  '/test-lab/training',
  '/test-lab/graduation',
  // Exploit Ops — Phishing
  '/phishing-ops',
  '/landing-page-builder',
  // Exploit Ops — Exploit Tooling
  '/exploit-catalog',
  '/exploit-knowledge',
  '/exploit-arsenal',
  '/payload-generator',
  '/api-security-testing',
  '/web-app-scanner',
  '/zap-proxy',
  '/credential-attacks',
  '/auth-assessment',
  '/auth-pipeline',
  '/exploitation-bridge',
  '/privilege-escalation',
  '/lateral-movement',
  '/data-exfil-simulation',
  '/campaign-advisor',
  '/tool-comparison',
  // Exploit Ops — C2 & Post-Exploit
  '/c2-command-center',
  '/c2-knowledge-base',
  '/server-access',
  '/empire',
  '/msf-sessions',
  '/session-recordings',
  '/ssh-keys',
  '/post-exploit-playbooks',
  '/file-transfers',
  '/sliver-c2',
  '/credential-alerts',
  '/credential-auto-rotation',
  // Intelligence — Threat Intelligence
  '/threat-intel-hub',
  '/vuln-intel',
  '/darkweb-intel',
  '/threat-actor-crawler',
  '/threat-enrichment',
  '/context-engine',
  '/threat-group-browser',
  '/nvd-cve-matcher',
  '/kev-catalog',
  '/zero-day-tracker',
  // Intelligence — Credentials & Export
  '/cloud-credentials',
  '/export-center',
  // Reports & Knowledge
  '/reports/generate',
  '/ac3-reports',
  '/pentest-report',
  '/guide/gophish',
  '/ttp-knowledge',
  '/knowledge-base',
  '/llm-learning',
  '/learning-dashboard',
  '/exploit-learning',
  '/training-dashboard',
  '/evidence',
  '/evidence-gallery',
  '/evidence-integrity',
  // Platform — ICS (operator-relevant)
  '/ics-ot-security',
  '/ics-intelligence',
];

const TEAM_LEAD_ROUTES: string[] = [
  // Everything the operator has
  ...OPERATOR_ROUTES,
  // Additional Command Center items
  '/executive-dashboard',
  '/ksi-dashboard',
  '/risk-trending',
  // Additional Intelligence
  '/breach-events',
  '/ransomware-groups',
  '/stix-export',
  '/oscal-export',
  // KSI & Compliance
  '/ksi-auto-collector',
  '/ksi-evidence-chain',
  '/ksi-threat-map',
  '/compliance',
  '/compliance-mapper',
  '/compensating-controls',
  '/control-testing',
  // Reports extras
  '/report-templates',
  // Platform — Team Management
  '/team',
  '/invitations',
  '/audit-log',
  '/mssp-analytics',
  '/compliance-dashboard',
  '/review-queue',
  '/account-settings',
];

const ANALYST_ROUTES: string[] = [
  // Command Center — limited
  '/ksi-dashboard',
  '/engagements',
  '/engagement-timeline',
  '/kill-chain',
  // Command Center — Risk & Analysis
  '/scoring',
  '/ai-attack-planner',
  '/attack-coverage',
  '/risk-trending',
  '/corroboration-engine',
  // Attack Surface — Discovery & Recon
  '/discovery-chain',
  '/domain-intel',
  '/domain-intel/history',
  '/web-crawler',
  '/osint-monitor',
  '/email-security',
  // Attack Surface — Scanning (results-focused)
  '/nuclei-scanner',
  '/vuln-scanner',
  '/scanforge-dashboard',
  // Attack Surface — Attack Paths
  '/attack-paths',
  '/attack-path-discovery',
  '/attack-vector-engine',
  '/cloud-attack-paths',
  '/ad-attack-sim',
  '/ad-attack-path-graph',
  '/bloodhound-import',
  '/forest-mapper',
  // Emulation — Analysis-relevant
  '/emulation-playbooks',
  '/ability-graph',
  '/atomic-red-team',
  '/purple-team',
  '/detection-coverage',
  '/ai-security-validation',
  '/remediation-verification',
  '/sigma-rules',
  '/ember/intelligence',
  // Exploit Ops — Knowledge only (no active tools)
  '/exploit-catalog',
  '/exploit-knowledge',
  '/api-security-testing',
  '/auth-assessment',
  '/tool-comparison',
  '/c2-knowledge-base',
  '/session-recordings',
  // Intelligence — Full access
  '/threat-intel-hub',
  '/vuln-intel',
  '/darkweb-intel',
  '/breach-events',
  '/ioc-feed',
  '/threat-actor-crawler',
  '/threat-enrichment',
  '/context-engine',
  '/threat-group-browser',
  '/conflict-theater',
  '/ransomware-groups',
  '/nvd-cve-matcher',
  '/kev-catalog',
  '/zero-day-tracker',
  '/stix-export',
  '/oscal-export',
  '/export-center',
  // KSI & Compliance
  '/ksi-auto-collector',
  '/ksi-evidence-chain',
  '/ksi-threat-map',
  '/compliance',
  '/compliance-mapper',
  '/compensating-controls',
  '/control-testing',
  // Reports & Knowledge
  '/reports/generate',
  '/ac3-reports',
  '/pentest-report',
  '/guide/gophish',
  '/ttp-knowledge',
  '/knowledge-base',
  '/training-dashboard',
  '/report-templates',
  '/evidence',
  '/evidence-gallery',
  '/evidence-integrity',
  // Platform — limited
  '/compliance-dashboard',
  '/review-queue',
  '/ics-intelligence',
];

const SOC_ROUTES: string[] = [
  // Command Center — Operations & Risk
  '/hunt-ops',
  '/ksi-dashboard',
  '/scoring',
  '/attack-coverage',
  '/risk-trending',
  // Attack Surface — Discovery (monitoring-relevant)
  '/domain-intel/history',
  '/osint-monitor',
  '/email-security',
  '/config-baseline',
  '/cloud-security-validation',
  // Emulation — Defense Validation (core SOC function)
  '/emulation-playbooks',
  '/atomic-red-team',
  '/agentless-bas',
  '/purple-team',
  '/edr-validation',
  '/detection-coverage',
  '/continuous-validation',
  '/ngfw-validation',
  '/remediation-verification',
  '/sigma-rules',
  // Intelligence — Threat Intel
  '/threat-intel-hub',
  '/vuln-intel',
  '/darkweb-intel',
  '/breach-events',
  '/ioc-feed',
  '/threat-actor-crawler',
  '/threat-enrichment',
  '/threat-group-browser',
  '/conflict-theater',
  '/ransomware-groups',
  '/nvd-cve-matcher',
  '/kev-catalog',
  '/zero-day-tracker',
  '/stix-export',
  // KSI & Compliance
  '/ksi-threat-map',
  '/control-testing',
  // Reports
  '/reports/generate',
  '/ac3-reports',
  '/guide/gophish',
  '/ttp-knowledge',
  // Platform — SOC Integration
  '/soc-integration-hub',
  '/soar-connectors',
  '/siem-feedback',
  '/incident-response',
  '/credential-alerts',
  '/ics-intelligence',
];

const EXECUTIVE_ROUTES: string[] = [
  '/executive-dashboard',
  '/ksi-dashboard',
  '/scoring',
  '/risk-trending',
  '/breach-events',
  '/ksi-threat-map',
  '/compliance',
  '/compliance-dashboard',
  '/mssp-analytics',
  // Reports
  '/reports/generate',
  '/ac3-reports',
  '/pentest-report',
];

const CLIENT_ROUTES: string[] = [
  // Engagement collaboration
  '/engagements',
  '/roe-builder',
  '/roe-self-service',
  // Scan results & evidence
  '/domain-intel/history',
  '/evidence',
  '/evidence-gallery',
  '/evidence-integrity',
  '/export-center',
  // Reports
  '/reports/generate',
  '/ac3-reports',
  '/pentest-report',
];

const VIEWER_ROUTES: string[] = [
  '/reports/generate',
  '/ac3-reports',
  '/pentest-report',
];

const ADMIN_ROUTES: string[] = [
  // Command Center — Oversight dashboards
  '/executive-dashboard',
  '/dashboard',
  '/ksi-dashboard',
  '/workflows',
  '/engagements',
  '/engagement-ops',
  '/engagement-timeline',
  '/kill-chain',
  '/opsec-dashboard',
  '/engagement-automation',
  '/roe-builder',
  '/roe-self-service',
  '/campaign-archetypes',
  '/hunt-ops',
  '/training-lab',
  '/bug-bounty',
  '/scoring',
  '/ai-attack-planner',
  '/preflight-checks',
  '/attack-coverage',
  '/risk-trending',
  '/corroboration-engine',
  // Attack Surface — Admin visibility
  '/scanforge-dashboard',
  '/commercial-scanners',
  '/ad-domain-connector',
  // Emulation — Admin visibility
  '/agent-manager',
  '/test-lab/environments',
  '/test-lab/training',
  '/test-lab/graduation',
  // Intelligence — Credentials
  '/cloud-credentials',
  '/stix-export',
  '/oscal-export',
  '/export-center',
  // KSI & Compliance
  '/ksi-auto-collector',
  '/ksi-evidence-chain',
  '/ksi-threat-map',
  '/compliance',
  '/compliance-mapper',
  '/compensating-controls',
  '/control-testing',
  // Reports & Knowledge
  '/reports/generate',
  '/ac3-reports',
  '/pentest-report',
  '/knowledge-base',
  '/llm-learning',
  '/learning-dashboard',
  '/exploit-learning',
  '/training-dashboard',
  '/report-templates',
  '/evidence',
  '/evidence-gallery',
  '/evidence-integrity',
  // Platform — Full Administration
  '/account-settings',
  '/team',
  '/invitations',
  '/saml-config',
  '/sessions',
  '/audit-log',
  '/siem-connectors',
  '/soc-integration-hub',
  '/ssil',
  '/live-infra',
  '/scan-server',
  '/monitoring-deploy',
  '/api-health',
  '/incident-response',
  '/dns-security',
  '/error-dashboard',
  '/llm-telemetry',
  '/llm-reliability',
  '/ai-governance',
  '/oem-credentials',
  '/webhooks',
  '/vendor-integrations',
  '/soar-connectors',
  '/siem-feedback',
  '/tenants',
  '/mssp-analytics',
  '/onboarding',
  '/compliance-dashboard',
  '/scan-webhooks',
  '/cicd-pipeline',
  '/cloud-setup-wizard',
  '/ics-ot-security',
  '/ics-intelligence',
  '/unified-pipeline',
  '/infra-wiki',
  '/review-queue',
  '/job-queue',
  '/fips-compliance',
  '/ssh-keys',
  '/credential-auto-rotation',
];

// ─── Compiled Route Access Map ──────────────────────────────────────────────

const ROLE_ROUTE_ACCESS: Record<UserRole, string[]> = {
  operator: OPERATOR_ROUTES,
  team_lead: TEAM_LEAD_ROUTES,
  analyst: ANALYST_ROUTES,
  soc: SOC_ROUTES,
  executive: EXECUTIVE_ROUTES,
  client: CLIENT_ROUTES,
  viewer: VIEWER_ROUTES,
  admin: ADMIN_ROUTES,
  user: OPERATOR_ROUTES, // Legacy: same as operator
};

// Routes accessible to ALL roles regardless of assignment
const UNIVERSAL_ROUTES = [
  '/',
  '/account-settings',
  '/home/operator',
  '/home/team-lead',
  '/home/analyst',
  '/home/executive',
  '/home/client',
  '/home/soc',
  '/home/admin',
];

// ─── Group-Level Access (for sidebar group visibility) ──────────────────────
// Determines which top-level nav groups are shown in the sidebar

const ROLE_GROUP_ACCESS: Record<UserRole, string[]> = {
  operator: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'reports'],
  team_lead: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'ksi', 'reports', 'platform'],
  analyst: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'ksi', 'reports', 'platform'],
  soc: ['command', 'surface', 'emulation', 'intelligence', 'ksi', 'reports', 'platform'],
  executive: ['command', 'ksi', 'reports'],
  client: ['command', 'reports'],
  viewer: ['reports'],
  admin: ['command', 'surface', 'emulation', 'intelligence', 'ksi', 'reports', 'platform'],
  user: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'reports'],
};

// Sub-section visibility per role (within allowed groups)
// If a role is not listed here, all sub-sections within allowed groups are visible
const ROLE_SUBSECTION_ACCESS: Record<UserRole, string[]> = {
  operator: [
    'cmd-ops', 'cmd-scoring',
    'surf-discovery', 'surf-tools', 'surf-paths',
    'emu-agents', 'emu-validation', 'emu-ember', 'emu-testlab',
    'exp-phishing', 'exp-tools', 'exp-c2',
    'intel-threats', 'intel-credentials',
    'rpt-all',
  ],
  team_lead: [
    'cmd-ops', 'cmd-scoring',
    'surf-discovery', 'surf-tools', 'surf-paths',
    'emu-agents', 'emu-validation', 'emu-ember', 'emu-testlab',
    'exp-phishing', 'exp-tools', 'exp-c2',
    'intel-threats', 'intel-credentials',
    'ksi-core',
    'rpt-all',
    'plat-admin',
  ],
  analyst: [
    'cmd-ops', 'cmd-scoring',
    'surf-discovery', 'surf-tools', 'surf-paths',
    'emu-agents', 'emu-validation',
    'exp-tools',
    'intel-threats', 'intel-credentials',
    'ksi-core',
    'rpt-all',
    'plat-admin',
  ],
  soc: [
    'cmd-ops', 'cmd-scoring',
    'surf-discovery', 'surf-tools', 'surf-paths',
    'emu-agents', 'emu-validation',
    'intel-threats', 'intel-credentials',
    'ksi-core',
    'rpt-all',
    'plat-admin',
  ],
  executive: [
    'cmd-ops', 'cmd-scoring',
    'ksi-core',
    'rpt-all',
  ],
  client: [
    'cmd-ops',
    'rpt-all',
  ],
  viewer: [
    'rpt-all',
  ],
  admin: [
    'cmd-ops', 'cmd-scoring',
    'surf-tools',
    'emu-agents', 'emu-testlab',
    'intel-credentials',
    'ksi-core',
    'rpt-all',
    'plat-admin',
  ],
  user: [
    'cmd-ops', 'cmd-scoring',
    'surf-discovery', 'surf-tools', 'surf-paths',
    'emu-agents', 'emu-validation', 'emu-ember', 'emu-testlab',
    'exp-phishing', 'exp-tools', 'exp-c2',
    'intel-threats', 'intel-credentials',
    'rpt-all',
  ],
};

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Check if a user role has access to a specific nav group
 */
export function canAccessGroup(role: UserRole, groupId: string): boolean {
  return ROLE_GROUP_ACCESS[role]?.includes(groupId) ?? false;
}

/**
 * Check if a user role has access to a specific sub-section
 */
export function canAccessSubSection(role: UserRole, subSectionId: string): boolean {
  const allowed = ROLE_SUBSECTION_ACCESS[role];
  if (!allowed) return true; // No restrictions defined = all visible
  return allowed.includes(subSectionId);
}

/**
 * Check if a user role can access a specific route.
 * Uses the per-route allowlist for precise control.
 */
export function canAccessRoute(role: UserRole, route: string): boolean {
  if (UNIVERSAL_ROUTES.includes(route)) return true;
  const allowedRoutes = ROLE_ROUTE_ACCESS[role];
  if (!allowedRoutes) return false;
  // Exact match
  if (allowedRoutes.includes(route)) return true;
  // Prefix match for nested routes (e.g., /ember/deploy matches /ember)
  return allowedRoutes.some(allowed => route.startsWith(allowed + '/'));
}

/**
 * Get all allowed routes for a role (useful for filtering nav items)
 */
export function getAllowedRoutes(role: UserRole): string[] {
  return [...UNIVERSAL_ROUTES, ...(ROLE_ROUTE_ACCESS[role] || [])];
}

/**
 * Check if a specific nav item (by href) should be visible to a role
 */
export function canAccessNavItem(role: UserRole, href: string): boolean {
  return canAccessRoute(role, href);
}

/**
 * Get the home dashboard path for a given role
 */
export function getHomeDashboardPath(role: UserRole): string {
  switch (role) {
    case 'operator':
    case 'user':
      return '/home/operator';
    case 'team_lead':
      return '/home/team-lead';
    case 'analyst':
      return '/home/analyst';
    case 'executive':
      return '/home/executive';
    case 'client':
    case 'viewer':
      return '/home/client';
    case 'soc':
      return '/home/soc';
    case 'admin':
      return '/home/admin';
    default:
      return '/home/operator';
  }
}

/**
 * Get display name for a role
 */
export function getRoleDisplayName(role: UserRole): string {
  const names: Record<UserRole, string> = {
    operator: 'Operator',
    team_lead: 'Team Lead',
    analyst: 'Analyst',
    executive: 'Executive',
    client: 'Client',
    admin: 'Administrator',
    user: 'Operator',
    viewer: 'Viewer',
    soc: 'SOC Analyst',
  };
  return names[role] ?? 'Operator';
}

/**
 * Get role badge color class
 */
export function getRoleBadgeClass(role: UserRole): string {
  const colors: Record<UserRole, string> = {
    operator: 'bg-red-500/20 text-red-400 border-red-500/30',
    team_lead: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    analyst: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    executive: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    client: 'bg-green-500/20 text-green-400 border-green-500/30',
    admin: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    user: 'bg-red-500/20 text-red-400 border-red-500/30',
    viewer: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    soc: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  };
  return colors[role] ?? colors.operator;
}

/**
 * All available roles for the role switcher
 */
export const ALL_ROLES: { value: UserRole; label: string; description: string }[] = [
  { value: 'operator', label: 'Operator', description: 'Red team operator — full attack toolkit' },
  { value: 'team_lead', label: 'Team Lead', description: 'Engagement manager — pipeline + team oversight' },
  { value: 'analyst', label: 'Analyst', description: 'Threat/vuln analyst — intel, emulation & analysis focus' },
  { value: 'executive', label: 'Executive', description: 'CISO view — business risk KPIs' },
  { value: 'client', label: 'Client', description: 'External client — RoE approval & assessment portal' },
  { value: 'admin', label: 'Administrator', description: 'Platform admin — user & infrastructure management' },
  { value: 'soc', label: 'SOC Analyst', description: 'Security Operations Center — detection, monitoring & defense validation' },
];
