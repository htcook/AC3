/**
 * Credential Auto-Rotation Engine
 *
 * Live cloud SDK integration for rotating credentials:
 *   - AWS IAM: CreateAccessKey → validate via STS → update vault → DeleteAccessKey (old key)
 *   - Azure: MS Graph addPassword → validate via ClientSecretCredential → update vault → removePassword
 *   - GCP: IAM createServiceAccountKey → update vault → deleteServiceAccountKey (old key)
 *
 * Each rotation is fully audited and the encrypted vault is updated atomically.
 */

import {
  IAMClient,
  CreateAccessKeyCommand,
  DeleteAccessKeyCommand,
  ListAccessKeysCommand,
  GetUserCommand,
} from "@aws-sdk/client-iam";
import {
  STSClient,
  GetCallerIdentityCommand,
} from "@aws-sdk/client-sts";
import { ClientSecretCredential } from "@azure/identity";
import { Client as GraphClient } from "@microsoft/microsoft-graph-client";
import { IAMCredentialsClient } from "@google-cloud/iam-credentials";

// ─── Types ───────────────────────────────────────────────────────────────────

export type RotationProvider = "aws" | "azure" | "gcp";

export type RotationStatus =
  | "pending"
  | "in_progress"
  | "success"
  | "failed"
  | "rollback";

export interface RotationPolicy {
  id: number;
  credentialId: number;
  provider: RotationProvider;
  credentialName: string;
  enabled: boolean;
  rotationIntervalDays: number;
  lastRotatedAt: Date | null;
  nextRotationAt: Date | null;
  maxRetries: number;
  retryCount: number;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface RotationAuditEntry {
  id: number;
  policyId: number;
  credentialId: number;
  provider: RotationProvider;
  status: RotationStatus;
  oldKeyIdentifier: string | null;
  newKeyIdentifier: string | null;
  errorMessage: string | null;
  durationMs: number;
  initiatedBy: string;
  createdAt: Date;
}

export interface RotationResult {
  success: boolean;
  provider: RotationProvider;
  oldKeyId: string | null;
  newKeyId: string | null;
  newCredentials: Record<string, string> | null;
  error: string | null;
  durationMs: number;
}

// ─── AWS IAM Key Rotation ────────────────────────────────────────────────────

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

/**
 * Rotate an AWS IAM access key using the real AWS SDK.
 *
 * Flow:
 *   1. Authenticate with current credentials and resolve the IAM user name
 *   2. IAM.CreateAccessKey(UserName) → new key pair
 *   3. Validate new key via STS.GetCallerIdentity
 *   4. Return new credentials for vault update
 *   5. Caller deletes old key after vault update succeeds (via deleteAwsAccessKey)
 */
export async function rotateAwsAccessKey(
  currentCreds: AwsCredentials,
  userName?: string
): Promise<RotationResult> {
  const startTime = Date.now();

  try {
    if (!currentCreds.accessKeyId || !currentCreds.secretAccessKey) {
      throw new Error("Current AWS credentials are incomplete");
    }

    const region = currentCreds.region || "us-east-1";
    const oldKeyId = currentCreds.accessKeyId;

    const credentials = {
      accessKeyId: currentCreds.accessKeyId,
      secretAccessKey: currentCreds.secretAccessKey,
    };

    const iamClient = new IAMClient({ region, credentials });

    // Step 1: Resolve the IAM user name if not provided
    let resolvedUserName = userName;
    if (!resolvedUserName) {
      try {
        const getUserResp = await iamClient.send(new GetUserCommand({}));
        resolvedUserName = getUserResp.User?.UserName;
      } catch {
        // If GetUser fails (e.g. assumed role), try STS to get the ARN
        const stsClient = new STSClient({ region, credentials });
        const identity = await stsClient.send(new GetCallerIdentityCommand({}));
        // Extract user name from ARN: arn:aws:iam::123456789012:user/MyUser
        const arnParts = identity.Arn?.split("/");
        resolvedUserName = arnParts?.[arnParts.length - 1];
      }
    }

    if (!resolvedUserName) {
      throw new Error("Could not resolve IAM user name for key rotation");
    }

    // Step 2: Create new access key
    const createResp = await iamClient.send(
      new CreateAccessKeyCommand({ UserName: resolvedUserName })
    );

    const newKey = createResp.AccessKey;
    if (!newKey?.AccessKeyId || !newKey?.SecretAccessKey) {
      throw new Error("AWS CreateAccessKey returned incomplete key data");
    }

    // Step 3: Validate new key works via STS GetCallerIdentity
    const newStsClient = new STSClient({
      region,
      credentials: {
        accessKeyId: newKey.AccessKeyId,
        secretAccessKey: newKey.SecretAccessKey,
      },
    });

    // New keys can take a few seconds to propagate; retry up to 3 times
    let validated = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await newStsClient.send(new GetCallerIdentityCommand({}));
        validated = true;
        break;
      } catch {
        // Wait 2 seconds before retrying (eventual consistency)
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    if (!validated) {
      // Rollback: delete the newly created key since it failed validation
      try {
        await iamClient.send(
          new DeleteAccessKeyCommand({
            UserName: resolvedUserName,
            AccessKeyId: newKey.AccessKeyId,
          })
        );
      } catch {
        // Best-effort rollback
      }
      throw new Error("New AWS access key failed STS validation after 3 attempts");
    }

    return {
      success: true,
      provider: "aws",
      oldKeyId,
      newKeyId: newKey.AccessKeyId,
      newCredentials: {
        accessKeyId: newKey.AccessKeyId,
        secretAccessKey: newKey.SecretAccessKey,
        region,
        userName: resolvedUserName,
      },
      error: null,
      durationMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      success: false,
      provider: "aws",
      oldKeyId: currentCreds.accessKeyId || null,
      newKeyId: null,
      newCredentials: null,
      error: err.message || "AWS key rotation failed",
      durationMs: Date.now() - startTime,
    };
  }
}

/**
 * Delete an old AWS access key after the vault has been updated with the new one.
 * Should be called only after the new key has been validated and persisted.
 */
export async function deleteAwsAccessKey(
  creds: AwsCredentials,
  oldAccessKeyId: string,
  userName: string
): Promise<{ success: boolean; error: string | null }> {
  try {
    const iamClient = new IAMClient({
      region: creds.region || "us-east-1",
      credentials: {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
      },
    });

    await iamClient.send(
      new DeleteAccessKeyCommand({
        UserName: userName,
        AccessKeyId: oldAccessKeyId,
      })
    );

    return { success: true, error: null };
  } catch (err: any) {
    return { success: false, error: err.message || "Failed to delete old AWS key" };
  }
}

/**
 * List all access keys for an IAM user (useful for pre-rotation checks).
 * AWS limits each user to 2 active keys.
 */
export async function listAwsAccessKeys(
  creds: AwsCredentials,
  userName?: string
): Promise<{ keys: Array<{ accessKeyId: string; status: string; createDate: Date | undefined }>; error: string | null }> {
  try {
    const iamClient = new IAMClient({
      region: creds.region || "us-east-1",
      credentials: {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
      },
    });

    const resp = await iamClient.send(
      new ListAccessKeysCommand({ UserName: userName })
    );

    const keys = (resp.AccessKeyMetadata || []).map(k => ({
      accessKeyId: k.AccessKeyId || "",
      status: k.Status || "Unknown",
      createDate: k.CreateDate,
    }));

    return { keys, error: null };
  } catch (err: any) {
    return { keys: [], error: err.message || "Failed to list AWS access keys" };
  }
}

// ─── Azure Credential Reset ──────────────────────────────────────────────────

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

/**
 * Rotate an Azure service principal client secret using MS Graph API.
 *
 * Flow:
 *   1. Authenticate with current credentials via ClientSecretCredential
 *   2. MS Graph: POST /applications/{objectId}/addPassword → new secret
 *   3. Validate new secret by acquiring a token
 *   4. Return new credentials for vault update
 *   5. Caller removes old password after vault update (via removeAzurePassword)
 */
export async function rotateAzureClientSecret(
  currentCreds: AzureCredentials,
  applicationObjectId?: string
): Promise<RotationResult> {
  const startTime = Date.now();

  try {
    if (!currentCreds.tenantId || !currentCreds.clientId || !currentCreds.clientSecret) {
      throw new Error("Current Azure credentials are incomplete");
    }

    // Step 1: Authenticate with current credentials
    const credential = new ClientSecretCredential(
      currentCreds.tenantId,
      currentCreds.clientId,
      currentCreds.clientSecret
    );

    // Acquire token to verify current credentials and get auth for Graph API
    const tokenResponse = await credential.getToken("https://graph.microsoft.com/.default");
    if (!tokenResponse?.token) {
      throw new Error("Failed to authenticate with current Azure credentials");
    }

    // Step 2: Initialize MS Graph client
    const graphClient = GraphClient.init({
      authProvider: (done) => {
        done(null, tokenResponse.token);
      },
    });

    // Step 3: Resolve the application object ID if not provided
    let resolvedObjectId = applicationObjectId;
    if (!resolvedObjectId) {
      // Look up the application by its clientId (appId)
      const apps = await graphClient
        .api("/applications")
        .filter(`appId eq '${currentCreds.clientId}'`)
        .select("id")
        .get();

      if (!apps?.value?.[0]?.id) {
        throw new Error(
          `Could not find Azure application with appId ${currentCreds.clientId}. ` +
          `Provide the applicationObjectId parameter or ensure the service principal has Application.ReadWrite.All permission.`
        );
      }
      resolvedObjectId = apps.value[0].id;
    }

    // Step 4: Add a new password credential to the application
    const passwordPayload = {
      passwordCredential: {
        displayName: `auto-rotated-${new Date().toISOString().slice(0, 10)}`,
        endDateTime: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
      },
    };

    const addPasswordResp = await graphClient
      .api(`/applications/${resolvedObjectId}/addPassword`)
      .post(passwordPayload);

    const newSecret = addPasswordResp?.secretText;
    const newKeyId = addPasswordResp?.keyId;

    if (!newSecret || !newKeyId) {
      throw new Error("Azure addPassword returned incomplete response (no secretText or keyId)");
    }

    // Step 5: Validate the new secret by acquiring a token with it
    const newCredential = new ClientSecretCredential(
      currentCreds.tenantId,
      currentCreds.clientId,
      newSecret
    );

    let validated = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const newToken = await newCredential.getToken("https://graph.microsoft.com/.default");
        if (newToken?.token) {
          validated = true;
          break;
        }
      } catch {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    if (!validated) {
      // Rollback: remove the newly added password
      try {
        const freshToken = await credential.getToken("https://graph.microsoft.com/.default");
        const rollbackClient = GraphClient.init({
          authProvider: (done) => done(null, freshToken!.token),
        });
        await rollbackClient
          .api(`/applications/${resolvedObjectId}/removePassword`)
          .post({ keyId: newKeyId });
      } catch {
        // Best-effort rollback
      }
      throw new Error("New Azure client secret failed token validation after 3 attempts");
    }

    return {
      success: true,
      provider: "azure",
      oldKeyId: `current-secret`,
      newKeyId,
      newCredentials: {
        tenantId: currentCreds.tenantId,
        clientId: currentCreds.clientId,
        clientSecret: newSecret,
        applicationObjectId: resolvedObjectId || "",
        keyId: newKeyId,
      },
      error: null,
      durationMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      success: false,
      provider: "azure",
      oldKeyId: null,
      newKeyId: null,
      newCredentials: null,
      error: err.message || "Azure credential reset failed",
      durationMs: Date.now() - startTime,
    };
  }
}

/**
 * Remove an old Azure password credential after the vault has been updated.
 */
export async function removeAzurePassword(
  creds: AzureCredentials,
  applicationObjectId: string,
  oldKeyId: string
): Promise<{ success: boolean; error: string | null }> {
  try {
    const credential = new ClientSecretCredential(
      creds.tenantId,
      creds.clientId,
      creds.clientSecret
    );

    const tokenResponse = await credential.getToken("https://graph.microsoft.com/.default");
    if (!tokenResponse?.token) {
      throw new Error("Failed to authenticate for old password removal");
    }

    const graphClient = GraphClient.init({
      authProvider: (done) => done(null, tokenResponse.token),
    });

    await graphClient
      .api(`/applications/${applicationObjectId}/removePassword`)
      .post({ keyId: oldKeyId });

    return { success: true, error: null };
  } catch (err: any) {
    return { success: false, error: err.message || "Failed to remove old Azure password" };
  }
}

// ─── GCP Service Account Key Rotation ────────────────────────────────────────

export interface GcpCredentials {
  projectId: string;
  clientEmail: string;
  privateKey: string;
  privateKeyId?: string;
}

/**
 * Rotate a GCP service account key using the real IAM Credentials API.
 *
 * Flow:
 *   1. Authenticate with current service account credentials
 *   2. IAM: projects.serviceAccounts.keys.create → new key JSON
 *   3. Return new credentials for vault update
 *   4. Caller deletes old key after vault update (via deleteGcpServiceAccountKey)
 */
export async function rotateGcpServiceAccountKey(
  currentCreds: GcpCredentials
): Promise<RotationResult> {
  const startTime = Date.now();

  try {
    if (!currentCreds.projectId || !currentCreds.clientEmail || !currentCreds.privateKey) {
      throw new Error("Current GCP credentials are incomplete");
    }

    const oldKeyId = currentCreds.privateKeyId || null;

    // The service account resource name for IAM API
    const serviceAccountName = `projects/-/serviceAccounts/${currentCreds.clientEmail}`;

    // Authenticate using the current service account credentials
    const { GoogleAuth } = await import("google-auth-library");
    const auth = new GoogleAuth({
      credentials: {
        client_email: currentCreds.clientEmail,
        private_key: currentCreds.privateKey,
        type: "service_account",
      },
      scopes: ["https://www.googleapis.com/auth/iam"],
    });

    const authClient = await auth.getClient();
    const accessToken = await authClient.getAccessToken();

    if (!accessToken?.token) {
      throw new Error("Failed to authenticate with current GCP credentials");
    }

    // Step 2: Create a new service account key via REST API
    // Using REST directly for more control over the key creation
    const createKeyUrl = `https://iam.googleapis.com/v1/projects/${currentCreds.projectId}/serviceAccounts/${currentCreds.clientEmail}/keys`;

    const createResp = await fetch(createKeyUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        privateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE",
        keyAlgorithm: "KEY_ALG_RSA_2048",
      }),
    });

    if (!createResp.ok) {
      const errBody = await createResp.text();
      throw new Error(`GCP IAM createKey failed (${createResp.status}): ${errBody}`);
    }

    const createData = await createResp.json();

    // The response contains the full key JSON as base64-encoded privateKeyData
    if (!createData.privateKeyData) {
      throw new Error("GCP createKey returned no privateKeyData");
    }

    // Decode the base64 key JSON
    const keyJsonStr = Buffer.from(createData.privateKeyData, "base64").toString("utf-8");
    const keyJson = JSON.parse(keyJsonStr);

    // Extract the new key name (format: projects/{project}/serviceAccounts/{email}/keys/{keyId})
    const newKeyResourceName = createData.name || "";
    const newKeyId = newKeyResourceName.split("/").pop() || createData.name;

    return {
      success: true,
      provider: "gcp",
      oldKeyId,
      newKeyId,
      newCredentials: {
        projectId: keyJson.project_id || currentCreds.projectId,
        clientEmail: keyJson.client_email || currentCreds.clientEmail,
        privateKey: keyJson.private_key,
        privateKeyId: keyJson.private_key_id || newKeyId,
        type: "service_account",
        tokenUri: keyJson.token_uri || "https://oauth2.googleapis.com/token",
      },
      error: null,
      durationMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      success: false,
      provider: "gcp",
      oldKeyId: currentCreds.privateKeyId || null,
      newKeyId: null,
      newCredentials: null,
      error: err.message || "GCP key rotation failed",
      durationMs: Date.now() - startTime,
    };
  }
}

/**
 * Delete an old GCP service account key after the vault has been updated.
 */
export async function deleteGcpServiceAccountKey(
  creds: GcpCredentials,
  keyResourceName: string
): Promise<{ success: boolean; error: string | null }> {
  try {
    const { GoogleAuth } = await import("google-auth-library");
    const auth = new GoogleAuth({
      credentials: {
        client_email: creds.clientEmail,
        private_key: creds.privateKey,
        type: "service_account",
      },
      scopes: ["https://www.googleapis.com/auth/iam"],
    });

    const authClient = await auth.getClient();
    const accessToken = await authClient.getAccessToken();

    if (!accessToken?.token) {
      throw new Error("Failed to authenticate for old key deletion");
    }

    // Construct the full resource name if only a key ID was provided
    let fullKeyName = keyResourceName;
    if (!keyResourceName.startsWith("projects/")) {
      fullKeyName = `projects/${creds.projectId}/serviceAccounts/${creds.clientEmail}/keys/${keyResourceName}`;
    }

    const deleteUrl = `https://iam.googleapis.com/v1/${fullKeyName}`;
    const deleteResp = await fetch(deleteUrl, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${accessToken.token}`,
      },
    });

    if (!deleteResp.ok) {
      const errBody = await deleteResp.text();
      throw new Error(`GCP IAM deleteKey failed (${deleteResp.status}): ${errBody}`);
    }

    return { success: true, error: null };
  } catch (err: any) {
    return { success: false, error: err.message || "Failed to delete old GCP key" };
  }
}

/**
 * List all keys for a GCP service account (useful for pre-rotation checks).
 */
export async function listGcpServiceAccountKeys(
  creds: GcpCredentials
): Promise<{ keys: Array<{ name: string; validAfterTime: string; validBeforeTime: string; keyType: string }>; error: string | null }> {
  try {
    const { GoogleAuth } = await import("google-auth-library");
    const auth = new GoogleAuth({
      credentials: {
        client_email: creds.clientEmail,
        private_key: creds.privateKey,
        type: "service_account",
      },
      scopes: ["https://www.googleapis.com/auth/iam"],
    });

    const authClient = await auth.getClient();
    const accessToken = await authClient.getAccessToken();

    if (!accessToken?.token) {
      throw new Error("Failed to authenticate for key listing");
    }

    const listUrl = `https://iam.googleapis.com/v1/projects/${creds.projectId}/serviceAccounts/${creds.clientEmail}/keys`;
    const resp = await fetch(listUrl, {
      headers: { Authorization: `Bearer ${accessToken.token}` },
    });

    if (!resp.ok) {
      const errBody = await resp.text();
      throw new Error(`GCP IAM listKeys failed (${resp.status}): ${errBody}`);
    }

    const data = await resp.json();
    const keys = (data.keys || []).map((k: any) => ({
      name: k.name || "",
      validAfterTime: k.validAfterTime || "",
      validBeforeTime: k.validBeforeTime || "",
      keyType: k.keyType || "UNKNOWN",
    }));

    return { keys, error: null };
  } catch (err: any) {
    return { keys: [], error: err.message || "Failed to list GCP service account keys" };
  }
}

// ─── Policy Evaluation ───────────────────────────────────────────────────────

/**
 * Determine if a rotation policy is due for execution.
 */
export function isPolicyDueForRotation(policy: RotationPolicy): boolean {
  if (!policy.enabled) return false;

  // Never rotated → due immediately
  if (!policy.lastRotatedAt) return true;

  // Check if next rotation date has passed
  if (policy.nextRotationAt) {
    return new Date() >= policy.nextRotationAt;
  }

  // Calculate based on interval
  const lastRotated = policy.lastRotatedAt.getTime();
  const intervalMs = policy.rotationIntervalDays * 24 * 60 * 60 * 1000;
  return Date.now() >= lastRotated + intervalMs;
}

/**
 * Calculate the next rotation date for a policy.
 */
export function calculateNextRotation(
  lastRotatedAt: Date,
  intervalDays: number
): Date {
  const next = new Date(lastRotatedAt.getTime());
  next.setDate(next.getDate() + intervalDays);
  return next;
}

/**
 * Evaluate all policies and return those that are due.
 */
export function evaluatePolicies(policies: RotationPolicy[]): RotationPolicy[] {
  return policies.filter(isPolicyDueForRotation);
}

// ─── Default Rotation Intervals ──────────────────────────────────────────────

export const DEFAULT_ROTATION_INTERVALS: Record<RotationProvider, number> = {
  aws: 90,
  azure: 180,
  gcp: 90,
};

// ─── Rotation Summary ────────────────────────────────────────────────────────

export interface RotationSummary {
  totalPolicies: number;
  enabledPolicies: number;
  duePolicies: number;
  recentRotations: number;
  failedRotations: number;
  nextRotationDate: Date | null;
}

/**
 * Generate a summary of rotation policy status.
 */
export function generateRotationSummary(
  policies: RotationPolicy[],
  recentAuditEntries: RotationAuditEntry[]
): RotationSummary {
  const enabled = policies.filter(p => p.enabled);
  const due = evaluatePolicies(policies);

  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const recent = recentAuditEntries.filter(
    e => e.createdAt >= oneDayAgo && e.status === "success"
  );
  const failed = recentAuditEntries.filter(
    e => e.createdAt >= oneDayAgo && e.status === "failed"
  );

  // Find next upcoming rotation
  const upcomingDates = enabled
    .map(p => p.nextRotationAt)
    .filter((d): d is Date => d !== null)
    .sort((a, b) => a.getTime() - b.getTime());

  return {
    totalPolicies: policies.length,
    enabledPolicies: enabled.length,
    duePolicies: due.length,
    recentRotations: recent.length,
    failedRotations: failed.length,
    nextRotationDate: upcomingDates[0] || null,
  };
}
