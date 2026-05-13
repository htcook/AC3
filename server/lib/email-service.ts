/**
 * Email Service Module
 * 
 * Dual-provider support:
 *   1. Microsoft Graph API (recommended for M365) — OAuth2 app-only auth
 *   2. SMTP via nodemailer (fallback) — smtp.office365.com:587
 * 
 * Environment variables:
 *   EMAIL_PROVIDER        — "graph" | "smtp" (default: "smtp")
 *   EMAIL_FROM            — Sender address (default: ac3@aceofcloud.com)
 *   EMAIL_FROM_NAME       — Sender display name (default: AC3 Platform)
 * 
 *   # For SMTP:
 *   SMTP_HOST             — SMTP server (default: smtp.office365.com)
 *   SMTP_PORT             — SMTP port (default: 587)
 *   SMTP_USER             — SMTP username (usually the email address)
 *   SMTP_PASSWORD          — SMTP password or app password
 * 
 *   # For Microsoft Graph:
 *   AZURE_TENANT_ID       — Azure AD tenant ID
 *   AZURE_CLIENT_ID       — Azure AD app registration client ID
 *   AZURE_CLIENT_SECRET   — Azure AD app registration client secret
 */

import nodemailer from "nodemailer";
import type { Transporter } from "nodemailer";
import { ConfidentialClientApplication } from "@azure/msal-node";

// ─── Configuration ──────────────────────────────────────────────────────────

interface EmailConfig {
  provider: "smtp" | "graph";
  from: string;
  fromName: string;
  smtp: {
    host: string;
    port: number;
    user: string;
    password: string;
  };
  graph: {
    tenantId: string;
    clientId: string;
    clientSecret: string;
  };
}

function getEmailConfig(): EmailConfig {
  return {
    provider: (process.env.EMAIL_PROVIDER as "smtp" | "graph") || "smtp",
    from: process.env.EMAIL_FROM || "ac3@aceofcloud.com",
    fromName: process.env.EMAIL_FROM_NAME || "AC3 Platform",
    smtp: {
      host: process.env.SMTP_HOST || "smtp.office365.com",
      port: parseInt(process.env.SMTP_PORT || "587", 10),
      user: process.env.SMTP_USER || process.env.EMAIL_FROM || "ac3@aceofcloud.com",
      password: process.env.SMTP_PASSWORD || "",
    },
    graph: {
      tenantId: process.env.AZURE_TENANT_ID || "",
      clientId: process.env.AZURE_CLIENT_ID || "",
      clientSecret: process.env.AZURE_CLIENT_SECRET || "",
    },
  };
}

// ─── Email Message Interface ────────────────────────────────────────────────

export interface EmailMessage {
  to: string | string[];
  subject: string;
  html: string;
  text?: string; // Plain text fallback
  cc?: string | string[];
  bcc?: string | string[];
  replyTo?: string;
}

export interface EmailResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

// ─── SMTP Transport ─────────────────────────────────────────────────────────

let smtpTransporter: Transporter | null = null;

function getSmtpTransporter(): Transporter {
  if (smtpTransporter) return smtpTransporter;
  const config = getEmailConfig();

  if (!config.smtp.password) {
    throw new Error("SMTP_PASSWORD is required for SMTP email provider");
  }

  smtpTransporter = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.port === 465,
    auth: {
      user: config.smtp.user,
      pass: config.smtp.password,
    },
    tls: {
      ciphers: "SSLv3",
      rejectUnauthorized: true,
    },
  });

  return smtpTransporter;
}

async function sendViaSMTP(message: EmailMessage): Promise<EmailResult> {
  try {
    const config = getEmailConfig();
    const transporter = getSmtpTransporter();

    const result = await transporter.sendMail({
      from: `"${config.fromName}" <${config.from}>`,
      to: Array.isArray(message.to) ? message.to.join(", ") : message.to,
      cc: message.cc ? (Array.isArray(message.cc) ? message.cc.join(", ") : message.cc) : undefined,
      bcc: message.bcc ? (Array.isArray(message.bcc) ? message.bcc.join(", ") : message.bcc) : undefined,
      replyTo: message.replyTo,
      subject: message.subject,
      html: message.html,
      text: message.text,
    });

    console.log(`[EmailService] SMTP sent: ${result.messageId} to ${message.to}`);
    return { success: true, messageId: result.messageId };
  } catch (err: any) {
    console.error("[EmailService] SMTP send failed:", err.message);
    return { success: false, error: err.message };
  }
}

// ─── Microsoft Graph API Transport ──────────────────────────────────────────

let msalClient: ConfidentialClientApplication | null = null;

function getMsalClient(): ConfidentialClientApplication {
  if (msalClient) return msalClient;
  const config = getEmailConfig();

  if (!config.graph.tenantId || !config.graph.clientId || !config.graph.clientSecret) {
    throw new Error("AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required for Graph email provider");
  }

  msalClient = new ConfidentialClientApplication({
    auth: {
      clientId: config.graph.clientId,
      clientSecret: config.graph.clientSecret,
      authority: `https://login.microsoftonline.com/${config.graph.tenantId}`,
    },
  });

  return msalClient;
}

async function getGraphAccessToken(): Promise<string> {
  const client = getMsalClient();
  const result = await client.acquireTokenByClientCredential({
    scopes: ["https://graph.microsoft.com/.default"],
  });

  if (!result?.accessToken) {
    throw new Error("Failed to acquire Graph API access token");
  }

  return result.accessToken;
}

async function sendViaGraph(message: EmailMessage): Promise<EmailResult> {
  try {
    const config = getEmailConfig();
    const accessToken = await getGraphAccessToken();

    const toRecipients = (Array.isArray(message.to) ? message.to : [message.to]).map((email) => ({
      emailAddress: { address: email },
    }));

    const ccRecipients = message.cc
      ? (Array.isArray(message.cc) ? message.cc : [message.cc]).map((email) => ({
          emailAddress: { address: email },
        }))
      : [];

    const bccRecipients = message.bcc
      ? (Array.isArray(message.bcc) ? message.bcc : [message.bcc]).map((email) => ({
          emailAddress: { address: email },
        }))
      : [];

    const graphMessage = {
      message: {
        subject: message.subject,
        body: {
          contentType: "HTML",
          content: message.html,
        },
        from: {
          emailAddress: {
            address: config.from,
            name: config.fromName,
          },
        },
        toRecipients,
        ccRecipients,
        bccRecipients,
        replyTo: message.replyTo
          ? [{ emailAddress: { address: message.replyTo } }]
          : [],
      },
      saveToSentItems: true,
    };

    const response = await fetch(
      `https://graph.microsoft.com/v1.0/users/${config.from}/sendMail`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(graphMessage),
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Graph API error ${response.status}: ${errorBody}`);
    }

    console.log(`[EmailService] Graph sent to ${message.to}`);
    return { success: true, messageId: `graph-${Date.now()}` };
  } catch (err: any) {
    console.error("[EmailService] Graph send failed:", err.message);
    return { success: false, error: err.message };
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Send an email using the configured provider (SMTP or Microsoft Graph).
 */
export async function sendEmail(message: EmailMessage): Promise<EmailResult> {
  const config = getEmailConfig();

  if (config.provider === "graph") {
    return sendViaGraph(message);
  }

  return sendViaSMTP(message);
}

/**
 * Verify the email transport is configured and reachable.
 * Returns true if the connection test succeeds.
 */
export async function verifyEmailTransport(): Promise<{ ok: boolean; provider: string; error?: string }> {
  const config = getEmailConfig();

  try {
    if (config.provider === "graph") {
      // Test Graph API by acquiring a token
      await getGraphAccessToken();
      return { ok: true, provider: "graph" };
    }

    // Test SMTP connection
    const transporter = getSmtpTransporter();
    await transporter.verify();
    return { ok: true, provider: "smtp" };
  } catch (err: any) {
    return { ok: false, provider: config.provider, error: err.message };
  }
}

/**
 * Check if email sending is configured (credentials present).
 */
export function isEmailConfigured(): boolean {
  const config = getEmailConfig();

  if (config.provider === "graph") {
    return !!(config.graph.tenantId && config.graph.clientId && config.graph.clientSecret);
  }

  return !!config.smtp.password;
}

/**
 * Get the sender address for display purposes.
 */
export function getSenderAddress(): string {
  const config = getEmailConfig();
  return config.from;
}
