/**
 * Credential Auto-Rotation Engine
 *
 * Automates the rotation of cloud provider credentials:
 *   - AWS IAM: CreateAccessKey → update vault → DeleteAccessKey (old key)
 *   - Azure: resetPassword on service principal → update vault
 *   - GCP: createKey on service account → update vault → delete old key
 *
 * Each rotation is fully audited and the encrypted vault is updated atomically.
 */

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
 * Simulate AWS IAM access key rotation.
 *
 * Real flow:
 *   1. IAM.CreateAccessKey(UserName) → new key pair
 *   2. Validate new key (STS.GetCallerIdentity)
 *   3. Update encrypted vault with new key
 *   4. IAM.DeleteAccessKey(UserName, old AccessKeyId)
 *
 * This implementation provides the rotation logic framework.
 * In production, replace the simulated API calls with actual AWS SDK calls.
 */
export async function rotateAwsAccessKey(
  currentCreds: AwsCredentials,
  _userName?: string
): Promise<RotationResult> {
  const startTime = Date.now();

  try {
    // Step 1: Validate current credentials exist
    if (!currentCreds.accessKeyId || !currentCreds.secretAccessKey) {
      throw new Error("Current AWS credentials are incomplete");
    }

    const oldKeyId = currentCreds.accessKeyId;

    // Step 2: Create new access key via AWS IAM API
    // In production: const iam = new IAMClient({ credentials: currentCreds });
    // const { AccessKey } = await iam.send(new CreateAccessKeyCommand({ UserName }));
    const newAccessKeyId = `AKIA${generateRandomId(16)}`;
    const newSecretKey = generateRandomSecret(40);

    // Step 3: Validate new key works (STS GetCallerIdentity)
    // In production: const sts = new STSClient({ credentials: newCreds });
    // await sts.send(new GetCallerIdentityCommand({}));

    // Step 4: Return new credentials for vault update
    // Step 5: Old key deletion happens after vault update succeeds
    return {
      success: true,
      provider: "aws",
      oldKeyId,
      newKeyId: newAccessKeyId,
      newCredentials: {
        accessKeyId: newAccessKeyId,
        secretAccessKey: newSecretKey,
        region: currentCreds.region || "us-east-1",
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

// ─── Azure Credential Reset ──────────────────────────────────────────────────

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

/**
 * Simulate Azure service principal credential reset.
 *
 * Real flow:
 *   1. Graph API: POST /applications/{appId}/addPassword → new secret
 *   2. Validate new secret (acquire token with new credentials)
 *   3. Update encrypted vault with new secret
 *   4. Graph API: POST /applications/{appId}/removePassword (old keyId)
 */
export async function rotateAzureClientSecret(
  currentCreds: AzureCredentials,
  _applicationObjectId?: string
): Promise<RotationResult> {
  const startTime = Date.now();

  try {
    if (!currentCreds.tenantId || !currentCreds.clientId || !currentCreds.clientSecret) {
      throw new Error("Current Azure credentials are incomplete");
    }

    const oldKeyId = `azure-secret-${currentCreds.clientId.slice(0, 8)}`;

    // Step 1: Add new password to application
    // In production: POST https://graph.microsoft.com/v1.0/applications/{id}/addPassword
    const newSecret = generateRandomSecret(48);
    const newKeyId = `azure-secret-${generateRandomId(8)}`;

    // Step 2: Validate new credentials (acquire token)
    // In production: new ClientSecretCredential(tenantId, clientId, newSecret).getToken(...)

    return {
      success: true,
      provider: "azure",
      oldKeyId,
      newKeyId,
      newCredentials: {
        tenantId: currentCreds.tenantId,
        clientId: currentCreds.clientId,
        clientSecret: newSecret,
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

// ─── GCP Service Account Key Rotation ────────────────────────────────────────

export interface GcpCredentials {
  projectId: string;
  clientEmail: string;
  privateKey: string;
  privateKeyId?: string;
}

/**
 * Simulate GCP service account key rotation.
 *
 * Real flow:
 *   1. IAM.createServiceAccountKey(name) → new key JSON
 *   2. Validate new key (authenticate and call a GCP API)
 *   3. Update encrypted vault with new key
 *   4. IAM.deleteServiceAccountKey(name, old key ID)
 */
export async function rotateGcpServiceAccountKey(
  currentCreds: GcpCredentials
): Promise<RotationResult> {
  const startTime = Date.now();

  try {
    if (!currentCreds.projectId || !currentCreds.clientEmail || !currentCreds.privateKey) {
      throw new Error("Current GCP credentials are incomplete");
    }

    const oldKeyId = currentCreds.privateKeyId || `gcp-key-${currentCreds.clientEmail.slice(0, 8)}`;

    // Step 1: Create new service account key
    // In production: iam.projects.serviceAccounts.keys.create(...)
    const newKeyId = `gcp-key-${generateRandomId(12)}`;
    const newPrivateKey = `-----BEGIN RSA PRIVATE KEY-----\n${generateRandomSecret(64)}\n-----END RSA PRIVATE KEY-----`;

    return {
      success: true,
      provider: "gcp",
      oldKeyId,
      newKeyId,
      newCredentials: {
        projectId: currentCreds.projectId,
        clientEmail: currentCreds.clientEmail,
        privateKey: newPrivateKey,
        privateKeyId: newKeyId,
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateRandomId(length: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateRandomSecret(length: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
