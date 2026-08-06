/**
 * Pipeline RBAC Module
 * Per-pipeline access controls with owner/editor/viewer roles.
 * Manages team member assignment and permission checking.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type PipelineRole = "owner" | "editor" | "viewer";

export interface PipelineAccess {
  pipelineId: number;
  userId: number;
  role: PipelineRole;
  grantedBy: number;
  grantedAt: string;
}

export interface PipelinePermissions {
  canView: boolean;
  canEdit: boolean;
  canTrigger: boolean;
  canDelete: boolean;
  canManageAccess: boolean;
  canPinBaseline: boolean;
  canConfigureSchedule: boolean;
  canExportSbom: boolean;
  canViewCompliance: boolean;
  role: PipelineRole | "admin" | "none";
}

// ─── Permission Matrix ──────────────────────────────────────────────────────

const ROLE_PERMISSIONS: Record<PipelineRole, Omit<PipelinePermissions, "role">> = {
  owner: {
    canView: true,
    canEdit: true,
    canTrigger: true,
    canDelete: true,
    canManageAccess: true,
    canPinBaseline: true,
    canConfigureSchedule: true,
    canExportSbom: true,
    canViewCompliance: true,
  },
  editor: {
    canView: true,
    canEdit: true,
    canTrigger: true,
    canDelete: false,
    canManageAccess: false,
    canPinBaseline: true,
    canConfigureSchedule: true,
    canExportSbom: true,
    canViewCompliance: true,
  },
  viewer: {
    canView: true,
    canEdit: false,
    canTrigger: false,
    canDelete: false,
    canManageAccess: false,
    canPinBaseline: false,
    canConfigureSchedule: false,
    canExportSbom: true,
    canViewCompliance: true,
  },
};

// Admin gets all permissions
const ADMIN_PERMISSIONS: PipelinePermissions = {
  canView: true,
  canEdit: true,
  canTrigger: true,
  canDelete: true,
  canManageAccess: true,
  canPinBaseline: true,
  canConfigureSchedule: true,
  canExportSbom: true,
  canViewCompliance: true,
  role: "admin",
};

const NO_PERMISSIONS: PipelinePermissions = {
  canView: false,
  canEdit: false,
  canTrigger: false,
  canDelete: false,
  canManageAccess: false,
  canPinBaseline: false,
  canConfigureSchedule: false,
  canExportSbom: false,
  canViewCompliance: false,
  role: "none",
};

// ─── Permission Resolution ──────────────────────────────────────────────────

/**
 * Resolve effective permissions for a user on a pipeline.
 * Admin users always get full access. Pipeline creator is auto-owner.
 */
export function resolvePermissions(params: {
  userRole: string; // Global user role from users table
  userId: number;
  pipelineCreatedBy?: string; // openId of pipeline creator
  userOpenId: string;
  pipelineAccess?: PipelineAccess | null;
}): PipelinePermissions {
  const { userRole, pipelineAccess, pipelineCreatedBy, userOpenId } = params;

  // Global admins get full access
  if (userRole === "admin") {
    return ADMIN_PERMISSIONS;
  }

  // Pipeline creator is auto-owner
  if (pipelineCreatedBy && pipelineCreatedBy === userOpenId) {
    return { ...ROLE_PERMISSIONS.owner, role: "owner" };
  }

  // Check explicit pipeline access
  if (pipelineAccess) {
    const perms = ROLE_PERMISSIONS[pipelineAccess.role];
    return { ...perms, role: pipelineAccess.role };
  }

  // Team leads and operators get viewer access by default
  if (["team_lead", "operator", "analyst"].includes(userRole)) {
    return { ...ROLE_PERMISSIONS.viewer, role: "viewer" };
  }

  // No access
  return NO_PERMISSIONS;
}

/**
 * Check if a user has a specific permission on a pipeline
 */
export function checkPermission(
  permissions: PipelinePermissions,
  action: keyof Omit<PipelinePermissions, "role">
): boolean {
  return permissions[action] === true;
}

/**
 * Get available roles that a user can grant to others.
 * Owners can grant owner/editor/viewer. Admins can grant all.
 */
export function getGrantableRoles(granterPermissions: PipelinePermissions): PipelineRole[] {
  if (granterPermissions.role === "admin" || granterPermissions.role === "owner") {
    return ["owner", "editor", "viewer"];
  }
  return [];
}

/**
 * Validate a role change. Returns error message or null if valid.
 */
export function validateRoleChange(params: {
  granterPermissions: PipelinePermissions;
  targetCurrentRole?: PipelineRole;
  newRole: PipelineRole;
  isTargetSelf: boolean;
}): string | null {
  const { granterPermissions, targetCurrentRole, newRole, isTargetSelf } = params;

  if (!granterPermissions.canManageAccess) {
    return "You don't have permission to manage access for this pipeline";
  }

  if (isTargetSelf && targetCurrentRole === "owner") {
    return "Cannot change your own owner role. Transfer ownership first.";
  }

  // Can't promote someone above your own role (except admin)
  if (granterPermissions.role !== "admin") {
    const roleHierarchy: Record<string, number> = { owner: 3, editor: 2, viewer: 1 };
    const granterLevel = roleHierarchy[granterPermissions.role] || 0;
    const newLevel = roleHierarchy[newRole] || 0;
    if (newLevel > granterLevel) {
      return `Cannot grant ${newRole} role — exceeds your own access level`;
    }
  }

  return null;
}

// ─── Access Summary ─────────────────────────────────────────────────────────

export interface PipelineAccessSummary {
  pipelineId: number;
  totalMembers: number;
  owners: number;
  editors: number;
  viewers: number;
  members: Array<{
    userId: number;
    userName: string;
    userEmail?: string;
    role: PipelineRole;
    grantedAt: string;
    grantedBy: string;
  }>;
}

/**
 * Build an access summary from raw access records and user data
 */
export function buildAccessSummary(
  pipelineId: number,
  accessRecords: Array<PipelineAccess & { userName?: string; userEmail?: string; grantedByName?: string }>,
): PipelineAccessSummary {
  const members = accessRecords.map(r => ({
    userId: r.userId,
    userName: r.userName || `User #${r.userId}`,
    userEmail: r.userEmail,
    role: r.role,
    grantedAt: r.grantedAt,
    grantedBy: r.grantedByName || `User #${r.grantedBy}`,
  }));

  return {
    pipelineId,
    totalMembers: members.length,
    owners: members.filter(m => m.role === "owner").length,
    editors: members.filter(m => m.role === "editor").length,
    viewers: members.filter(m => m.role === "viewer").length,
    members,
  };
}

/**
 * Filter a list of pipelines to only those the user can view
 */
export function filterAccessiblePipelines(
  pipelines: Array<{ id: number; createdBy?: string }>,
  userOpenId: string,
  userRole: string,
  accessRecords: PipelineAccess[],
): number[] {
  // Admins see everything
  if (userRole === "admin") {
    return pipelines.map(p => p.id);
  }

  const accessMap = new Map<number, PipelineAccess>();
  for (const record of accessRecords) {
    accessMap.set(record.pipelineId, record);
  }

  return pipelines.filter(p => {
    // Creator always has access
    if (p.createdBy === userOpenId) return true;
    // Explicit access
    if (accessMap.has(p.id)) return true;
    // Team leads/operators/analysts get default viewer access
    if (["team_lead", "operator", "analyst"].includes(userRole)) return true;
    return false;
  }).map(p => p.id);
}
