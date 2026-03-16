/**
 * Cloud IAM Live Enumeration Engine
 * Connects to AWS IAM, Azure Entra ID, and GCP IAM using provided credentials
 * to enumerate users, roles, policies, groups, and service accounts.
 */

// ── Types ───────────────────────────────────────────────────────────────────

export interface CloudIdentityResult {
  identityType: "user" | "role" | "service_account" | "group" | "app_registration";
  arn?: string;
  name: string;
  email?: string;
  isPrivileged: boolean;
  lastActivity?: Date | null;
  permissions?: any;
  policies?: any;
  metadata?: any;
}

export interface CloudEnumerationResult {
  provider: "aws" | "azure" | "gcp";
  users: CloudIdentityResult[];
  roles: CloudIdentityResult[];
  groups: CloudIdentityResult[];
  serviceAccounts: CloudIdentityResult[];
  policies: any[];
  misconfigurations: any[];
  summary: {
    totalUsers: number;
    totalRoles: number;
    totalGroups: number;
    totalPolicies: number;
    totalServiceAccounts: number;
    totalMisconfigs: number;
    privilegedIdentities: number;
  };
  errors: string[];
}

export interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
  roleArn?: string;
  externalId?: string;
}

export interface AzureCredentials {
  clientId: string;
  clientSecret: string;
  tenantId: string;
  subscriptionId?: string;
}

export interface GCPCredentials {
  projectId: string;
  serviceAccountKey: string; // JSON string of the SA key file
}

// ── AWS IAM Enumeration ─────────────────────────────────────────────────────

const PRIVILEGED_AWS_POLICIES = [
  "arn:aws:iam::aws:policy/AdministratorAccess",
  "arn:aws:iam::aws:policy/IAMFullAccess",
  "arn:aws:iam::aws:policy/PowerUserAccess",
  "arn:aws:iam::aws:policy/SecurityAudit",
];

const PRIVILEGED_AWS_ACTIONS = [
  "iam:*", "sts:*", "s3:*", "ec2:*", "lambda:*", "organizations:*",
];

export async function enumerateAWS(creds: AWSCredentials): Promise<CloudEnumerationResult> {
  const errors: string[] = [];
  const result: CloudEnumerationResult = {
    provider: "aws",
    users: [], roles: [], groups: [], serviceAccounts: [], policies: [],
    misconfigurations: [],
    summary: { totalUsers: 0, totalRoles: 0, totalGroups: 0, totalPolicies: 0, totalServiceAccounts: 0, totalMisconfigs: 0, privilegedIdentities: 0 },
    errors,
  };

  try {
    const { IAMClient, ListUsersCommand, ListRolesCommand, ListGroupsCommand,
      ListPoliciesCommand, ListAccessKeysCommand, GetLoginProfileCommand,
      ListAttachedUserPoliciesCommand, ListAttachedRolePoliciesCommand,
      GetAccountAuthorizationDetailsCommand } = await import("@aws-sdk/client-iam");
    const { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } = await import("@aws-sdk/client-sts");

    let credentials: any = {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      ...(creds.sessionToken ? { sessionToken: creds.sessionToken } : {}),
    };

    const region = creds.region || "us-east-1";

    // If role ARN provided, assume it first
    if (creds.roleArn) {
      try {
        const stsClient = new STSClient({ region, credentials });
        const assumeResult = await stsClient.send(new AssumeRoleCommand({
          RoleArn: creds.roleArn,
          RoleSessionName: "ac3-enum",
          ...(creds.externalId ? { ExternalId: creds.externalId } : {}),
          DurationSeconds: 3600,
        }));
        if (assumeResult.Credentials) {
          credentials = {
            accessKeyId: assumeResult.Credentials.AccessKeyId!,
            secretAccessKey: assumeResult.Credentials.SecretAccessKey!,
            sessionToken: assumeResult.Credentials.SessionToken!,
          };
        }
      } catch (e: any) {
        errors.push(`AssumeRole failed: ${e.message}`);
      }
    }

    // Verify identity
    const stsClient = new STSClient({ region, credentials });
    try {
      const identity = await stsClient.send(new GetCallerIdentityCommand({}));
      console.log(`[AWS Enum] Authenticated as: ${identity.Arn}`);
    } catch (e: any) {
      errors.push(`Identity verification failed: ${e.message}`);
      return result;
    }

    const iamClient = new IAMClient({ region, credentials });

    // Enumerate users
    try {
      const usersResp = await iamClient.send(new ListUsersCommand({ MaxItems: 1000 }));
      for (const user of usersResp.Users || []) {
        let isPrivileged = false;
        let attachedPolicies: any[] = [];
        try {
          const policiesResp = await iamClient.send(new ListAttachedUserPoliciesCommand({ UserName: user.UserName! }));
          attachedPolicies = policiesResp.AttachedPolicies || [];
          isPrivileged = attachedPolicies.some(p => PRIVILEGED_AWS_POLICIES.includes(p.PolicyArn || ""));
        } catch (e: any) {
          errors.push(`Failed to list policies for user ${user.UserName}: ${e.message}`);
        }

        let accessKeys: any[] = [];
        try {
          const keysResp = await iamClient.send(new ListAccessKeysCommand({ UserName: user.UserName! }));
          accessKeys = (keysResp.AccessKeyMetadata || []).map(k => ({
            keyId: k.AccessKeyId,
            status: k.Status,
            createDate: k.CreateDate,
          }));
        } catch (e: any) { /* skip */ }

        let hasConsoleAccess = false;
        try {
          await iamClient.send(new GetLoginProfileCommand({ UserName: user.UserName! }));
          hasConsoleAccess = true;
        } catch { /* no console access */ }

        result.users.push({
          identityType: "user",
          arn: user.Arn,
          name: user.UserName || "unknown",
          isPrivileged,
          lastActivity: user.PasswordLastUsed || null,
          policies: attachedPolicies.map(p => p.PolicyName),
          metadata: { accessKeys, hasConsoleAccess, createDate: user.CreateDate, userId: user.UserId },
        });
        if (isPrivileged) result.summary.privilegedIdentities++;
      }
      result.summary.totalUsers = result.users.length;
    } catch (e: any) {
      errors.push(`User enumeration failed: ${e.message}`);
    }

    // Enumerate roles
    try {
      const rolesResp = await iamClient.send(new ListRolesCommand({ MaxItems: 1000 }));
      for (const role of rolesResp.Roles || []) {
        let isPrivileged = false;
        let attachedPolicies: any[] = [];
        try {
          const policiesResp = await iamClient.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! }));
          attachedPolicies = policiesResp.AttachedPolicies || [];
          isPrivileged = attachedPolicies.some(p => PRIVILEGED_AWS_POLICIES.includes(p.PolicyArn || ""));
        } catch (e: any) {
          errors.push(`Failed to list policies for role ${role.RoleName}: ${e.message}`);
        }

        result.roles.push({
          identityType: "role",
          arn: role.Arn,
          name: role.RoleName || "unknown",
          isPrivileged,
          policies: attachedPolicies.map(p => p.PolicyName),
          metadata: {
            createDate: role.CreateDate,
            maxSessionDuration: role.MaxSessionDuration,
            trustPolicy: role.AssumeRolePolicyDocument ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : null,
          },
        });
        if (isPrivileged) result.summary.privilegedIdentities++;
      }
      result.summary.totalRoles = result.roles.length;
    } catch (e: any) {
      errors.push(`Role enumeration failed: ${e.message}`);
    }

    // Enumerate groups
    try {
      const groupsResp = await iamClient.send(new ListGroupsCommand({ MaxItems: 1000 }));
      for (const group of groupsResp.Groups || []) {
        result.groups.push({
          identityType: "group",
          arn: group.Arn,
          name: group.GroupName || "unknown",
          isPrivileged: false,
          metadata: { createDate: group.CreateDate, groupId: group.GroupId },
        });
      }
      result.summary.totalGroups = result.groups.length;
    } catch (e: any) {
      errors.push(`Group enumeration failed: ${e.message}`);
    }

    // Enumerate policies
    try {
      const policiesResp = await iamClient.send(new ListPoliciesCommand({ Scope: "Local", MaxItems: 1000 }));
      result.policies = (policiesResp.Policies || []).map(p => ({
        arn: p.Arn,
        name: p.PolicyName,
        attachmentCount: p.AttachmentCount,
        isAttachable: p.IsAttachable,
        createDate: p.CreateDate,
        updateDate: p.UpdateDate,
      }));
      result.summary.totalPolicies = result.policies.length;
    } catch (e: any) {
      errors.push(`Policy enumeration failed: ${e.message}`);
    }

    // Check for misconfigurations
    const misconfigChecks = [];
    // Check for users without MFA
    const usersWithoutMFA = result.users.filter(u => !u.metadata?.mfaDevices?.length);
    if (usersWithoutMFA.length > 0) {
      misconfigChecks.push({
        type: "users_without_mfa",
        severity: "critical",
        description: `${usersWithoutMFA.length} users without MFA enabled`,
        affectedResources: usersWithoutMFA.map(u => u.name),
      });
    }
    // Check for old access keys
    const oldKeyUsers = result.users.filter(u =>
      u.metadata?.accessKeys?.some((k: any) => {
        if (!k.createDate) return false;
        const age = Date.now() - new Date(k.createDate).getTime();
        return age > 90 * 24 * 60 * 60 * 1000; // 90 days
      })
    );
    if (oldKeyUsers.length > 0) {
      misconfigChecks.push({
        type: "access_key_rotation",
        severity: "high",
        description: `${oldKeyUsers.length} users with access keys older than 90 days`,
        affectedResources: oldKeyUsers.map(u => u.name),
      });
    }
    // Check for cross-account trust without ExternalId
    const unsafeTrustRoles = result.roles.filter(r => {
      const trust = r.metadata?.trustPolicy;
      if (!trust?.Statement) return false;
      return trust.Statement.some((s: any) =>
        s.Principal?.AWS && !s.Condition?.StringEquals?.["sts:ExternalId"]
      );
    });
    if (unsafeTrustRoles.length > 0) {
      misconfigChecks.push({
        type: "cross_account_trust_no_external_id",
        severity: "high",
        description: `${unsafeTrustRoles.length} roles with cross-account trust lacking ExternalId`,
        affectedResources: unsafeTrustRoles.map(r => r.name),
      });
    }

    result.misconfigurations = misconfigChecks;
    result.summary.totalMisconfigs = misconfigChecks.length;

  } catch (e: any) {
    errors.push(`AWS enumeration error: ${e.message}`);
  }

  return result;
}

// ── Azure Entra ID Enumeration ──────────────────────────────────────────────

const PRIVILEGED_AZURE_ROLES = [
  "Global Administrator", "Privileged Role Administrator",
  "Application Administrator", "Cloud Application Administrator",
  "Exchange Administrator", "SharePoint Administrator",
  "User Administrator", "Security Administrator",
];

export async function enumerateAzure(creds: AzureCredentials): Promise<CloudEnumerationResult> {
  const errors: string[] = [];
  const result: CloudEnumerationResult = {
    provider: "azure",
    users: [], roles: [], groups: [], serviceAccounts: [], policies: [],
    misconfigurations: [],
    summary: { totalUsers: 0, totalRoles: 0, totalGroups: 0, totalPolicies: 0, totalServiceAccounts: 0, totalMisconfigs: 0, privilegedIdentities: 0 },
    errors,
  };

  try {
    const { ClientSecretCredential } = await import("@azure/identity");
    const credential = new ClientSecretCredential(creds.tenantId, creds.clientId, creds.clientSecret);

    // Get an access token for Microsoft Graph
    const tokenResponse = await credential.getToken("https://graph.microsoft.com/.default");
    const accessToken = tokenResponse.token;

    const graphFetch = async (path: string) => {
      const resp = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!resp.ok) throw new Error(`Graph API ${path}: ${resp.status} ${resp.statusText}`);
      return resp.json() as any;
    };

    // Enumerate users
    try {
      const usersData = await graphFetch("/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,signInActivity,userType");
      for (const user of usersData.value || []) {
        result.users.push({
          identityType: "user",
          name: user.displayName || user.userPrincipalName,
          email: user.userPrincipalName,
          isPrivileged: false, // will be updated after role assignment check
          lastActivity: user.signInActivity?.lastSignInDateTime ? new Date(user.signInActivity.lastSignInDateTime) : null,
          metadata: {
            id: user.id,
            accountEnabled: user.accountEnabled,
            userType: user.userType,
            createdDateTime: user.createdDateTime,
          },
        });
      }
      result.summary.totalUsers = result.users.length;
    } catch (e: any) {
      errors.push(`User enumeration failed: ${e.message}`);
    }

    // Enumerate groups
    try {
      const groupsData = await graphFetch("/groups?$top=999&$select=id,displayName,groupTypes,securityEnabled,membershipRule");
      for (const group of groupsData.value || []) {
        result.groups.push({
          identityType: "group",
          name: group.displayName,
          isPrivileged: false,
          metadata: {
            id: group.id,
            groupTypes: group.groupTypes,
            securityEnabled: group.securityEnabled,
            membershipRule: group.membershipRule,
          },
        });
      }
      result.summary.totalGroups = result.groups.length;
    } catch (e: any) {
      errors.push(`Group enumeration failed: ${e.message}`);
    }

    // Enumerate directory roles (active role assignments)
    try {
      const rolesData = await graphFetch("/directoryRoles?$expand=members");
      for (const role of rolesData.value || []) {
        const memberNames = (role.members || []).map((m: any) => m.displayName || m.userPrincipalName);
        const isPriv = PRIVILEGED_AZURE_ROLES.includes(role.displayName);

        result.roles.push({
          identityType: "role",
          name: role.displayName,
          isPrivileged: isPriv,
          metadata: {
            id: role.id,
            description: role.description,
            memberCount: (role.members || []).length,
            members: memberNames,
          },
        });

        // Mark users who hold privileged roles
        if (isPriv) {
          for (const member of role.members || []) {
            const user = result.users.find(u => u.metadata?.id === member.id);
            if (user) {
              user.isPrivileged = true;
              result.summary.privilegedIdentities++;
            }
          }
        }
      }
      result.summary.totalRoles = result.roles.length;
    } catch (e: any) {
      errors.push(`Role enumeration failed: ${e.message}`);
    }

    // Enumerate app registrations (service principals)
    try {
      const appsData = await graphFetch("/applications?$top=999&$select=id,displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess");
      for (const app of appsData.value || []) {
        const hasSecrets = (app.passwordCredentials || []).length > 0;
        const hasCerts = (app.keyCredentials || []).length > 0;

        result.serviceAccounts.push({
          identityType: "app_registration",
          name: app.displayName,
          isPrivileged: false,
          metadata: {
            appId: app.appId,
            id: app.id,
            hasSecrets,
            hasCerts,
            secretCount: (app.passwordCredentials || []).length,
            certCount: (app.keyCredentials || []).length,
            requiredResourceAccess: app.requiredResourceAccess,
          },
        });
      }
      result.summary.totalServiceAccounts = result.serviceAccounts.length;
    } catch (e: any) {
      errors.push(`App registration enumeration failed: ${e.message}`);
    }

    // Misconfiguration checks
    const misconfigChecks = [];
    const guestUsers = result.users.filter(u => u.metadata?.userType === "Guest");
    if (guestUsers.length > 5) {
      misconfigChecks.push({
        type: "excessive_guest_users",
        severity: "medium",
        description: `${guestUsers.length} guest users in the directory`,
        affectedResources: guestUsers.map(u => u.name),
      });
    }
    const disabledUsers = result.users.filter(u => u.metadata?.accountEnabled === false);
    if (disabledUsers.length > 0) {
      misconfigChecks.push({
        type: "disabled_accounts_present",
        severity: "low",
        description: `${disabledUsers.length} disabled accounts still in directory`,
        affectedResources: disabledUsers.map(u => u.name),
      });
    }
    const appsWithSecrets = result.serviceAccounts.filter(sa => sa.metadata?.hasSecrets);
    if (appsWithSecrets.length > 0) {
      misconfigChecks.push({
        type: "app_registrations_with_secrets",
        severity: "medium",
        description: `${appsWithSecrets.length} app registrations with password credentials`,
        affectedResources: appsWithSecrets.map(sa => sa.name),
      });
    }

    result.misconfigurations = misconfigChecks;
    result.summary.totalMisconfigs = misconfigChecks.length;

  } catch (e: any) {
    errors.push(`Azure enumeration error: ${e.message}`);
  }

  return result;
}

// ── GCP IAM Enumeration ─────────────────────────────────────────────────────

const PRIVILEGED_GCP_ROLES = [
  "roles/owner", "roles/editor", "roles/iam.securityAdmin",
  "roles/iam.serviceAccountAdmin", "roles/resourcemanager.organizationAdmin",
];

export async function enumerateGCP(creds: GCPCredentials): Promise<CloudEnumerationResult> {
  const errors: string[] = [];
  const result: CloudEnumerationResult = {
    provider: "gcp",
    users: [], roles: [], groups: [], serviceAccounts: [], policies: [],
    misconfigurations: [],
    summary: { totalUsers: 0, totalRoles: 0, totalGroups: 0, totalPolicies: 0, totalServiceAccounts: 0, totalMisconfigs: 0, privilegedIdentities: 0 },
    errors,
  };

  try {
    // Parse the service account key
    const keyData = JSON.parse(creds.serviceAccountKey);
    const projectId = creds.projectId || keyData.project_id;

    // Use Google Auth to get access token
    const { GoogleAuth } = await import("google-auth-library");
    const auth = new GoogleAuth({
      credentials: keyData,
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
    });
    const client = await auth.getClient();
    const tokenResp = await client.getAccessToken();
    const accessToken = tokenResp.token;

    const gcpFetch = async (url: string) => {
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!resp.ok) throw new Error(`GCP API ${url}: ${resp.status} ${resp.statusText}`);
      return resp.json() as any;
    };

    // Enumerate service accounts
    try {
      const saData = await gcpFetch(`https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts`);
      for (const sa of saData.accounts || []) {
        // List keys for each SA
        let keys: any[] = [];
        try {
          const keysData = await gcpFetch(`https://iam.googleapis.com/v1/${sa.name}/keys`);
          keys = (keysData.keys || []).map((k: any) => ({
            keyId: k.name?.split("/").pop(),
            keyType: k.keyType,
            validAfter: k.validAfterTime,
            validBefore: k.validBeforeTime,
          }));
        } catch { /* skip */ }

        result.serviceAccounts.push({
          identityType: "service_account",
          name: sa.displayName || sa.email,
          email: sa.email,
          isPrivileged: false,
          metadata: {
            uniqueId: sa.uniqueId,
            projectId: sa.projectId,
            disabled: sa.disabled,
            keyCount: keys.length,
            keys,
          },
        });
      }
      result.summary.totalServiceAccounts = result.serviceAccounts.length;
    } catch (e: any) {
      errors.push(`Service account enumeration failed: ${e.message}`);
    }

    // Enumerate IAM policy (role bindings)
    try {
      const policyData = await gcpFetch(`https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getIamPolicy`);
      const bindings = policyData.bindings || [];

      for (const binding of bindings) {
        const isPriv = PRIVILEGED_GCP_ROLES.includes(binding.role);
        result.roles.push({
          identityType: "role",
          name: binding.role,
          isPrivileged: isPriv,
          metadata: {
            members: binding.members,
            memberCount: binding.members?.length || 0,
            condition: binding.condition,
          },
        });

        if (isPriv) {
          result.summary.privilegedIdentities += (binding.members?.length || 0);
        }

        // Extract individual users/SAs from bindings
        for (const member of binding.members || []) {
          if (member.startsWith("user:")) {
            const email = member.replace("user:", "");
            if (!result.users.find(u => u.email === email)) {
              result.users.push({
                identityType: "user",
                name: email.split("@")[0],
                email,
                isPrivileged: isPriv,
              });
            }
          }
        }
      }
      result.summary.totalRoles = result.roles.length;
      result.summary.totalUsers = result.users.length;
    } catch (e: any) {
      errors.push(`IAM policy enumeration failed: ${e.message}`);
    }

    // Misconfiguration checks
    const misconfigChecks = [];
    const defaultSAs = result.serviceAccounts.filter(sa =>
      sa.email?.includes("-compute@developer.gserviceaccount.com") ||
      sa.email?.includes("@appspot.gserviceaccount.com")
    );
    if (defaultSAs.length > 0) {
      misconfigChecks.push({
        type: "default_service_accounts",
        severity: "high",
        description: `${defaultSAs.length} default service accounts found (should use custom SAs)`,
        affectedResources: defaultSAs.map(sa => sa.email || sa.name),
      });
    }
    const oldKeySAs = result.serviceAccounts.filter(sa =>
      sa.metadata?.keys?.some((k: any) => {
        if (!k.validAfter || k.keyType === "SYSTEM_MANAGED") return false;
        const age = Date.now() - new Date(k.validAfter).getTime();
        return age > 90 * 24 * 60 * 60 * 1000;
      })
    );
    if (oldKeySAs.length > 0) {
      misconfigChecks.push({
        type: "sa_key_rotation",
        severity: "high",
        description: `${oldKeySAs.length} service accounts with keys older than 90 days`,
        affectedResources: oldKeySAs.map(sa => sa.email || sa.name),
      });
    }
    const primitiveRoleBindings = result.roles.filter(r =>
      ["roles/owner", "roles/editor", "roles/viewer"].includes(r.name)
    );
    if (primitiveRoleBindings.length > 0) {
      misconfigChecks.push({
        type: "primitive_roles_used",
        severity: "medium",
        description: `${primitiveRoleBindings.length} primitive role bindings found (prefer predefined roles)`,
        affectedResources: primitiveRoleBindings.map(r => r.name),
      });
    }

    result.misconfigurations = misconfigChecks;
    result.summary.totalMisconfigs = misconfigChecks.length;

  } catch (e: any) {
    errors.push(`GCP enumeration error: ${e.message}`);
  }

  return result;
}

// ── Credential Validation ───────────────────────────────────────────────────

export async function validateAWSCredentials(creds: AWSCredentials): Promise<{ valid: boolean; identity?: string; error?: string }> {
  try {
    const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
    const client = new STSClient({
      region: creds.region || "us-east-1",
      credentials: {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        ...(creds.sessionToken ? { sessionToken: creds.sessionToken } : {}),
      },
    });
    const identity = await client.send(new GetCallerIdentityCommand({}));
    return { valid: true, identity: identity.Arn };
  } catch (e: any) {
    return { valid: false, error: e.message };
  }
}

export async function validateAzureCredentials(creds: AzureCredentials): Promise<{ valid: boolean; identity?: string; error?: string }> {
  try {
    const { ClientSecretCredential } = await import("@azure/identity");
    const credential = new ClientSecretCredential(creds.tenantId, creds.clientId, creds.clientSecret);
    const token = await credential.getToken("https://graph.microsoft.com/.default");
    return { valid: true, identity: `Azure App (tenant: ${creds.tenantId})` };
  } catch (e: any) {
    return { valid: false, error: e.message };
  }
}

export async function validateGCPCredentials(creds: GCPCredentials): Promise<{ valid: boolean; identity?: string; error?: string }> {
  try {
    const keyData = JSON.parse(creds.serviceAccountKey);
    const { GoogleAuth } = await import("google-auth-library");
    const auth = new GoogleAuth({
      credentials: keyData,
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
    });
    const client = await auth.getClient();
    await client.getAccessToken();
    return { valid: true, identity: `GCP SA: ${keyData.client_email}` };
  } catch (e: any) {
    return { valid: false, error: e.message };
  }
}
