/**
 * Customer Authentication Service
 * 
 * Provides separate auth for customer organizations (not admin OAuth).
 * Uses bcrypt password hashing, JWT tokens with expiration, and
 * audit logging for all customer portal actions (NIST 800-53 AU/AC).
 */
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { getDbRequired } from "../db";
import { customerAccounts, customerAuditLog } from "../../drizzle/schema";
import { eq, and } from "drizzle-orm";
import { ENV } from "../_core/env";

const BCRYPT_ROUNDS = 12;
const TOKEN_EXPIRY = "8h";
const REFRESH_EXPIRY = "7d";

export interface CustomerTokenPayload {
  customerId: string;
  tenantId: string;
  engagementId: string | null;
  email: string;
  role: string;
  type: "customer";
}

// ── Password Hashing ─────────────────────────────────────────────────

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ── JWT Token Management ─────────────────────────────────────────────

export function generateCustomerToken(payload: CustomerTokenPayload): string {
  return jwt.sign(payload, ENV.jwtSecret, { expiresIn: TOKEN_EXPIRY });
}

export function generateRefreshToken(payload: CustomerTokenPayload): string {
  return jwt.sign({ ...payload, refresh: true }, ENV.jwtSecret, { expiresIn: REFRESH_EXPIRY });
}

export function verifyCustomerToken(token: string): CustomerTokenPayload | null {
  try {
    const decoded = jwt.verify(token, ENV.jwtSecret) as CustomerTokenPayload & { exp?: number };
    if (decoded.type !== "customer") return null;
    return decoded;
  } catch {
    return null;
  }
}

// ── Customer Account Management ──────────────────────────────────────

export async function createCustomerAccount(params: {
  tenantId: string;
  engagementId?: string;
  contactName: string;
  email: string;
  password: string;
  role?: string;
}): Promise<{ id: string; email: string }> {
  const database = await getDbRequired();
  const passwordHash = await hashPassword(params.password);
  const id = crypto.randomUUID();

  await database.insert(customerAccounts).values({
    tenantId: parseInt(params.tenantId),
    caEmail: params.email.toLowerCase().trim(),
    passwordHash,
    caName: params.contactName,
    caRole: (params.role as any) || "viewer",
    caStatus: "active",
  });

  await logCustomerAction({
    customerId: id,
    tenantId: params.tenantId,
    action: "account_created",
    resource: "customer_account",
    details: { email: params.email, role: params.role || "viewer" },
  });

  return { id, email: params.email };
}

export async function authenticateCustomer(email: string, password: string): Promise<{
  success: boolean;
  token?: string;
  refreshToken?: string;
  customer?: {
    id: string;
    tenantId: string;
    engagementId: string | null;
    contactName: string;
    email: string;
    role: string;
  };
  error?: string;
}> {
  const database = await getDbRequired();
  const normalizedEmail = email.toLowerCase().trim();

  const [account] = await database
    .select()
    .from(customerAccounts)
    .where(and(
      eq(customerAccounts.caEmail, normalizedEmail),
      eq(customerAccounts.caStatus, "active")
    ))
    .limit(1);

  if (!account) {
    return { success: false, error: "Invalid email or password" };
  }

  const passwordValid = await verifyPassword(password, account.passwordHash);
  if (!passwordValid) {
    await logCustomerAction({
      customerId: String(account.id),
      tenantId: String(account.tenantId),
      action: "login_failed",
      resource: "customer_auth",
      details: { reason: "invalid_password" },
    });
    return { success: false, error: "Invalid email or password" };
  }

  // Update last login
  await database
    .update(customerAccounts)
    .set({ caLastLoginAt: new Date().toISOString() })
    .where(eq(customerAccounts.id, account.id));

  const payload: CustomerTokenPayload = {
    customerId: String(account.id),
    tenantId: String(account.tenantId),
    engagementId: null,
    email: account.caEmail,
    role: account.caRole,
    type: "customer",
  };

  const token = generateCustomerToken(payload);
  const refreshToken = generateRefreshToken(payload);

  await logCustomerAction({
    customerId: String(account.id),
    tenantId: String(account.tenantId),
    action: "login_success",
    resource: "customer_auth",
    details: {},
  });

  return {
    success: true,
    token,
    refreshToken,
    customer: {
      id: String(account.id),
      tenantId: String(account.tenantId),
      engagementId: null,
      contactName: account.caName,
      email: account.caEmail,
      role: account.caRole,
    },
  };
}

export async function refreshCustomerSession(refreshToken: string): Promise<{
  success: boolean;
  token?: string;
  error?: string;
}> {
  try {
    const decoded = jwt.verify(refreshToken, ENV.jwtSecret) as CustomerTokenPayload & { refresh?: boolean };
    if (decoded.type !== "customer" || !decoded.refresh) {
      return { success: false, error: "Invalid refresh token" };
    }

    // Verify account still active
    const database = await getDbRequired();
    const [account] = await database
      .select()
      .from(customerAccounts)
      .where(and(
        eq(customerAccounts.id, parseInt(decoded.customerId)),
        eq(customerAccounts.caStatus, "active")
      ))
      .limit(1);

    if (!account) {
      return { success: false, error: "Account not found or inactive" };
    }

    const newPayload: CustomerTokenPayload = {
      customerId: String(account.id),
      tenantId: String(account.tenantId),
      engagementId: null,
      email: account.caEmail,
      role: account.caRole,
      type: "customer",
    };

    return { success: true, token: generateCustomerToken(newPayload) };
  } catch {
    return { success: false, error: "Token expired or invalid" };
  }
}

export async function changeCustomerPassword(customerId: string, currentPassword: string, newPassword: string): Promise<{
  success: boolean;
  error?: string;
}> {
  const database = await getDbRequired();
  const [account] = await database
    .select()
    .from(customerAccounts)
    .where(eq(customerAccounts.id, customerId))
    .limit(1);

  if (!account) return { success: false, error: "Account not found" };

  const valid = await verifyPassword(currentPassword, account.passwordHash);
  if (!valid) return { success: false, error: "Current password is incorrect" };

  const newHash = await hashPassword(newPassword);
  await database
    .update(customerAccounts)
    .set({ passwordHash: newHash })
    .where(eq(customerAccounts.id, customerId));

  await logCustomerAction({
    customerId,
    tenantId: String(account.tenantId),
    action: "password_changed",
    resource: "customer_account",
    details: {},
  });

  return { success: true };
}

// ── Audit Logging (NIST 800-53 AU) ──────────────────────────────────

export async function logCustomerAction(params: {
  customerId: string;
  tenantId: string;
  action: string;
  resource: string;
  resourceId?: string;
  details?: Record<string, any>;
  ipAddress?: string;
}): Promise<void> {
  try {
    const database = await getDbRequired();
    await database.insert(customerAuditLog).values({
      customerAccountId: parseInt(params.customerId) || 0,
      calTenantId: parseInt(params.tenantId) || 0,
      calAction: params.action,
      calResource: params.resource,
      calResourceId: params.resourceId || null,
      calDetails: params.details ? JSON.stringify(params.details) : null,
      calIpAddress: params.ipAddress || null,
    });
  } catch (err) {
    // Audit logging should never break the main flow
    console.error("[CustomerAudit] Failed to log action:", err);
  }
}
