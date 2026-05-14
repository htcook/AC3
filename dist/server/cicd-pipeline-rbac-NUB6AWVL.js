import "./chunk-KFQGP6VL.js";

// server/lib/cicd-pipeline-rbac.ts
var ROLE_PERMISSIONS = {
  owner: {
    canView: true,
    canEdit: true,
    canTrigger: true,
    canDelete: true,
    canManageAccess: true,
    canPinBaseline: true,
    canConfigureSchedule: true,
    canExportSbom: true,
    canViewCompliance: true
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
    canViewCompliance: true
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
    canViewCompliance: true
  }
};
var ADMIN_PERMISSIONS = {
  canView: true,
  canEdit: true,
  canTrigger: true,
  canDelete: true,
  canManageAccess: true,
  canPinBaseline: true,
  canConfigureSchedule: true,
  canExportSbom: true,
  canViewCompliance: true,
  role: "admin"
};
var NO_PERMISSIONS = {
  canView: false,
  canEdit: false,
  canTrigger: false,
  canDelete: false,
  canManageAccess: false,
  canPinBaseline: false,
  canConfigureSchedule: false,
  canExportSbom: false,
  canViewCompliance: false,
  role: "none"
};
function resolvePermissions(params) {
  const { userRole, pipelineAccess, pipelineCreatedBy, userOpenId } = params;
  if (userRole === "admin") {
    return ADMIN_PERMISSIONS;
  }
  if (pipelineCreatedBy && pipelineCreatedBy === userOpenId) {
    return { ...ROLE_PERMISSIONS.owner, role: "owner" };
  }
  if (pipelineAccess) {
    const perms = ROLE_PERMISSIONS[pipelineAccess.role];
    return { ...perms, role: pipelineAccess.role };
  }
  if (["team_lead", "operator", "analyst"].includes(userRole)) {
    return { ...ROLE_PERMISSIONS.viewer, role: "viewer" };
  }
  return NO_PERMISSIONS;
}
function checkPermission(permissions, action) {
  return permissions[action] === true;
}
function getGrantableRoles(granterPermissions) {
  if (granterPermissions.role === "admin" || granterPermissions.role === "owner") {
    return ["owner", "editor", "viewer"];
  }
  return [];
}
function validateRoleChange(params) {
  const { granterPermissions, targetCurrentRole, newRole, isTargetSelf } = params;
  if (!granterPermissions.canManageAccess) {
    return "You don't have permission to manage access for this pipeline";
  }
  if (isTargetSelf && targetCurrentRole === "owner") {
    return "Cannot change your own owner role. Transfer ownership first.";
  }
  if (granterPermissions.role !== "admin") {
    const roleHierarchy = { owner: 3, editor: 2, viewer: 1 };
    const granterLevel = roleHierarchy[granterPermissions.role] || 0;
    const newLevel = roleHierarchy[newRole] || 0;
    if (newLevel > granterLevel) {
      return `Cannot grant ${newRole} role \u2014 exceeds your own access level`;
    }
  }
  return null;
}
function buildAccessSummary(pipelineId, accessRecords) {
  const members = accessRecords.map((r) => ({
    userId: r.userId,
    userName: r.userName || `User #${r.userId}`,
    userEmail: r.userEmail,
    role: r.role,
    grantedAt: r.grantedAt,
    grantedBy: r.grantedByName || `User #${r.grantedBy}`
  }));
  return {
    pipelineId,
    totalMembers: members.length,
    owners: members.filter((m) => m.role === "owner").length,
    editors: members.filter((m) => m.role === "editor").length,
    viewers: members.filter((m) => m.role === "viewer").length,
    members
  };
}
function filterAccessiblePipelines(pipelines, userOpenId, userRole, accessRecords) {
  if (userRole === "admin") {
    return pipelines.map((p) => p.id);
  }
  const accessMap = /* @__PURE__ */ new Map();
  for (const record of accessRecords) {
    accessMap.set(record.pipelineId, record);
  }
  return pipelines.filter((p) => {
    if (p.createdBy === userOpenId) return true;
    if (accessMap.has(p.id)) return true;
    if (["team_lead", "operator", "analyst"].includes(userRole)) return true;
    return false;
  }).map((p) => p.id);
}
export {
  buildAccessSummary,
  checkPermission,
  filterAccessiblePipelines,
  getGrantableRoles,
  resolvePermissions,
  validateRoleChange
};
