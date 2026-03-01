/**
 * Role-Based Access Control (RBAC) Configuration
 * Maps user roles to allowed navigation groups, sub-sections, and specific routes.
 * 
 * Roles:
 *   operator   — Red team operator (attack-focused)
 *   team_lead  — Team lead / engagement manager
 *   analyst    — Threat/vuln analyst
 *   executive  — CISO / executive (business risk view)
 *   client     — External client (read-only portal)
 *   admin      — Platform administrator (full access)
 *   user       — Legacy default (same as operator)
 *   viewer     — Legacy viewer (same as client)
 */

export type UserRole = 'operator' | 'team_lead' | 'analyst' | 'executive' | 'client' | 'admin' | 'user' | 'viewer' | 'soc';

// Which top-level nav groups each role can see
const ROLE_GROUP_ACCESS: Record<UserRole, string[]> = {
  operator: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'reports'],
  team_lead: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'ksi', 'reports', 'platform'],
  analyst: ['command', 'surface', 'emulation', 'intelligence', 'ksi', 'reports'],
  executive: ['command', 'ksi', 'reports'],
  client: ['reports'],
  admin: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'ksi', 'reports', 'platform'],
  user: ['command', 'surface', 'emulation', 'exploits', 'intelligence', 'reports'],
  viewer: ['reports'],
  soc: ['command', 'surface', 'emulation', 'intelligence', 'ksi', 'reports'],
};

// Sub-section restrictions per role (if a group is allowed, these sub-sections are further filtered)
// If a role is not listed here, all sub-sections within allowed groups are visible
const ROLE_SUBSECTION_RESTRICTIONS: Partial<Record<UserRole, string[]>> = {
  executive: ['cmd-scoring', 'ksi-core', 'rpt-all'],
  client: ['rpt-all'],
  analyst: ['cmd-scoring', 'surf-discovery', 'surf-tools', 'surf-paths', 'emu-agents', 'emu-validation', 'intel-threats', 'intel-credentials', 'ksi-core', 'rpt-all'],
  viewer: ['rpt-all'],
  soc: [
    'cmd-ops', 'cmd-scoring',
    'surf-discovery', 'surf-tools', 'surf-paths',
    'emu-agents', 'emu-validation',
    'intel-threats', 'intel-credentials',
    'ksi-core',
    'rpt-all',
  ],
};

// Specific routes that are always accessible regardless of role (e.g., home, profile)
const UNIVERSAL_ROUTES = ['/', '/dashboard'];

// Routes that require admin role
const ADMIN_ONLY_ROUTES = [
  '/team',
  '/audit-log',
  '/tenants',
  '/error-dashboard',
  '/webhooks',
  '/vendor-integrations',
  '/soar-connectors',
  '/siem-feedback',
  '/cicd-pipeline',
];

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
  const restrictions = ROLE_SUBSECTION_RESTRICTIONS[role];
  if (!restrictions) return true; // No restrictions = all sub-sections visible
  return restrictions.includes(subSectionId);
}

/**
 * Check if a user role can access a specific route
 */
export function canAccessRoute(role: UserRole, route: string): boolean {
  if (UNIVERSAL_ROUTES.includes(route)) return true;
  if (ADMIN_ONLY_ROUTES.includes(route) && role !== 'admin' && role !== 'team_lead') return false;
  return true;
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
  { value: 'client', label: 'Client', description: 'External client — read-only assessment portal' },
  { value: 'admin', label: 'Administrator', description: 'Platform admin — full system access' },
  { value: 'soc', label: 'SOC Analyst', description: 'Security Operations Center — detection, monitoring & defense validation' },
];
