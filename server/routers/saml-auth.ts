import * as db from "../db";
import { CALDERA_JWT_SECRET } from "../lib/api-helpers";
/**
 * SAML 2.0 Authentication Router
 * 
 * Provides tRPC procedures for IdP configuration management and
 * Express routes for SAML protocol endpoints (metadata, ACS, SLO).
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";
import { getDb } from "../db";
import { samlIdpConfigs, samlAuthEvents, users, userSessions } from "../../drizzle/schema";
import { eq, desc, and } from "drizzle-orm";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import {
  generateSPMetadata,
  generateAuthnRequest,
  parseSAMLResponse,
  extractUserAttributes,
  PROVIDER_TEMPLATES,
  getSPEntityId,
  getSPAcsUrl,
} from "../lib/saml-service";
import type { Express, Request, Response } from "express";

// ─── tRPC Router ────────────────────────────────────────────────────────────

export const samlRouter = router({
  /** Get SP metadata info for display */
  getSpInfo: protectedProcedure.query(() => {
    return {
      entityId: getSPEntityId(),
      acsUrl: getSPAcsUrl(),
      metadataUrl: `${getSPAcsUrl().replace("/acs", "/metadata")}`,
      supportedBindings: ["HTTP-POST", "HTTP-Redirect"],
      nameIdFormats: [
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      ],
    };
  }),

  /** Get provider templates for IdP setup */
  getProviderTemplates: protectedProcedure.query(() => {
    return PROVIDER_TEMPLATES;
  }),

  /** List all configured IdPs */
  listIdps: adminProcedure.query(async () => {
    const db = await getDb();
    const configs = await db
      .select({
        id: samlIdpConfigs.id,
        name: samlIdpConfigs.name,
        providerType: samlIdpConfigs.providerType,
        entityId: samlIdpConfigs.entityId,
        ssoUrl: samlIdpConfigs.ssoUrl,
        isActive: samlIdpConfigs.isActive,
        jitProvisioning: samlIdpConfigs.jitProvisioning,
        defaultRole: samlIdpConfigs.defaultRole,
        forceAuthn: samlIdpConfigs.forceAuthn,
        createdAt: samlIdpConfigs.createdAt,
        updatedAt: samlIdpConfigs.updatedAt,
      })
      .from(samlIdpConfigs)
      .orderBy(desc(samlIdpConfigs.createdAt));
    return configs;
  }),

  /** Get a single IdP config (full details) */
  getIdp: adminProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [config] = await db
        .select()
        .from(samlIdpConfigs)
        .where(eq(samlIdpConfigs.id, input.id))
        .limit(1);
      if (!config) throw new TRPCError({ code: "NOT_FOUND", message: "IdP configuration not found" });
      return config;
    }),

  /** Create a new IdP configuration */
  createIdp: adminProcedure
    .input(z.object({
      name: z.string().min(1).max(256),
      providerType: z.enum(["okta", "azure_ad", "ping_federate", "google_workspace", "onelogin", "generic"]),
      entityId: z.string().min(1).max(512),
      ssoUrl: z.string().url().max(1024),
      sloUrl: z.string().url().max(1024).optional(),
      certificate: z.string().min(1),
      metadataXml: z.string().optional(),
      nameIdFormat: z.string().optional(),
      attributeMapping: z.object({
        email: z.string().optional(),
        name: z.string().optional(),
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        role: z.string().optional(),
        department: z.string().optional(),
        groups: z.string().optional(),
      }).optional(),
      defaultRole: z.enum(["user", "admin", "viewer", "operator", "team_lead", "analyst", "executive", "client"]).default("operator"),
      jitProvisioning: z.boolean().default(true),
      forceAuthn: z.boolean().default(false),
      wantAssertionsSigned: z.boolean().default(true),
      wantResponseSigned: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const [result] = await db.insert(samlIdpConfigs).values({
        name: input.name,
        providerType: input.providerType,
        entityId: input.entityId,
        ssoUrl: input.ssoUrl,
        sloUrl: input.sloUrl || null,
        certificate: input.certificate,
        metadataXml: input.metadataXml || null,
        nameIdFormat: input.nameIdFormat || "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        attributeMapping: input.attributeMapping || null,
        defaultRole: input.defaultRole,
        jitProvisioning: input.jitProvisioning,
        forceAuthn: input.forceAuthn,
        wantAssertionsSigned: input.wantAssertionsSigned,
        wantResponseSigned: input.wantResponseSigned,
        createdBy: ctx.user.id,
      });
      return { id: result.insertId, success: true };
    }),

  /** Update an IdP configuration */
  updateIdp: adminProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().min(1).max(256).optional(),
      ssoUrl: z.string().url().max(1024).optional(),
      sloUrl: z.string().url().max(1024).optional().nullable(),
      certificate: z.string().min(1).optional(),
      metadataXml: z.string().optional().nullable(),
      nameIdFormat: z.string().optional(),
      attributeMapping: z.object({
        email: z.string().optional(),
        name: z.string().optional(),
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        role: z.string().optional(),
        department: z.string().optional(),
        groups: z.string().optional(),
      }).optional(),
      defaultRole: z.enum(["user", "admin", "viewer", "operator", "team_lead", "analyst", "executive", "client"]).optional(),
      isActive: z.boolean().optional(),
      jitProvisioning: z.boolean().optional(),
      forceAuthn: z.boolean().optional(),
      wantAssertionsSigned: z.boolean().optional(),
      wantResponseSigned: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const { id, ...updates } = input;
      const cleanUpdates = Object.fromEntries(
        Object.entries(updates).filter(([, v]) => v !== undefined)
      );
      if (Object.keys(cleanUpdates).length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "No updates provided" });
      }
      await db.update(samlIdpConfigs).set(cleanUpdates).where(eq(samlIdpConfigs.id, id));
      return { success: true };
    }),

  /** Delete an IdP configuration */
  deleteIdp: adminProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.delete(samlIdpConfigs).where(eq(samlIdpConfigs.id, input.id));
      return { success: true };
    }),

  /** Test IdP connectivity */
  testIdp: adminProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [config] = await db
        .select()
        .from(samlIdpConfigs)
        .where(eq(samlIdpConfigs.id, input.id))
        .limit(1);
      if (!config) throw new TRPCError({ code: "NOT_FOUND" });

      const checks = {
        ssoUrlReachable: false,
        certificateValid: false,
        certificateExpiry: null as string | null,
        metadataValid: !!config.metadataXml,
      };

      // Test SSO URL reachability
      try {
        const resp = await fetch(config.ssoUrl, { method: "HEAD", signal: AbortSignal.timeout(5000) });
        checks.ssoUrlReachable = resp.status < 500;
      } catch {
        checks.ssoUrlReachable = false;
      }

      // Validate certificate
      try {
        const certPem = normalizeCert(config.certificate);
        const x509 = new crypto.X509Certificate(certPem);
        checks.certificateValid = new Date(x509.validTo) > new Date();
        checks.certificateExpiry = x509.validTo;
      } catch {
        checks.certificateValid = false;
      }

      return checks;
    }),

  /** Get SAML auth event log */
  getAuthEvents: adminProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      idpId: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      let query = db
        .select()
        .from(samlAuthEvents)
        .orderBy(desc(samlAuthEvents.createdAt))
        .limit(input.limit);
      
      if (input.idpId) {
        query = query.where(eq(samlAuthEvents.idpConfigId, input.idpId)) as any;
      }
      return query;
    }),

  /** Get active IdPs for login page */
  getActiveIdps: protectedProcedure.query(async () => {
    const db = await getDb();
    return db
      .select({
        id: samlIdpConfigs.id,
        name: samlIdpConfigs.name,
        providerType: samlIdpConfigs.providerType,
      })
      .from(samlIdpConfigs)
      .where(eq(samlIdpConfigs.isActive, true));
  }),

  /** Initiate SAML SSO login */
  initiateSso: protectedProcedure
    .input(z.object({ idpId: z.number(), relayState: z.string().optional() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [config] = await db
        .select()
        .from(samlIdpConfigs)
        .where(and(eq(samlIdpConfigs.id, input.idpId), eq(samlIdpConfigs.isActive, true)))
        .limit(1);
      if (!config) throw new TRPCError({ code: "NOT_FOUND", message: "IdP not found or inactive" });

      const { url, requestId } = generateAuthnRequest(config as any, input.relayState);
      return { redirectUrl: url, requestId };
    }),
});

// ─── Express Routes for SAML Protocol ───────────────────────────────────────

export function registerSAMLRoutes(app: Express) {
  // SP Metadata endpoint
  app.get("/api/saml/metadata", (_req: Request, res: Response) => {
    const metadata = generateSPMetadata();
    res.set("Content-Type", "application/xml");
    res.send(metadata);
  });

  // Assertion Consumer Service (ACS) — receives SAML responses via HTTP-POST
  app.post("/api/saml/acs", async (req: Request, res: Response) => {
    const db = await getDb();
    const samlResponse = req.body?.SAMLResponse;
    const relayState = req.body?.RelayState;

    if (!samlResponse) {
      return res.status(400).json({ error: "Missing SAMLResponse" });
    }

    try {
      // Decode to find the issuer and match to an IdP config
      const responseXml = Buffer.from(samlResponse, "base64").toString("utf-8");
      const issuerMatch = responseXml.match(/<(?:saml:)?Issuer[^>]*>([^<]*)<\/(?:saml:)?Issuer>/);
      const issuer = issuerMatch?.[1]?.trim();

      if (!issuer) {
        await logSamlEvent(db, "assertion_error", null, null, null, req.ip || "", "Missing Issuer in SAML response");
        return res.status(400).json({ error: "Invalid SAML response: missing Issuer" });
      }

      // Find matching IdP config
      const [idpConfig] = await db
        .select()
        .from(samlIdpConfigs)
        .where(and(eq(samlIdpConfigs.entityId, issuer), eq(samlIdpConfigs.isActive, true)))
        .limit(1);

      if (!idpConfig) {
        await logSamlEvent(db, "assertion_error", null, null, null, req.ip || "", `No active IdP config for issuer: ${issuer}`);
        return res.status(400).json({ error: "Unknown identity provider" });
      }

      // Parse and validate the SAML response
      const { assertion, signatureValid } = parseSAMLResponse(samlResponse, idpConfig as any);

      if (idpConfig.wantAssertionsSigned && !signatureValid) {
        await logSamlEvent(db, "signature_invalid", idpConfig.id, null, assertion.nameId, req.ip || "", "Assertion signature validation failed");
        return res.status(400).json({ error: "SAML assertion signature validation failed" });
      }

      // Extract user attributes
      const userAttrs = extractUserAttributes(assertion, idpConfig.attributeMapping as any);

      // Find or create user (JIT provisioning)
      let [existingUser] = await db
        .select()
        .from(users)
        .where(eq(users.email, userAttrs.email))
        .limit(1);

      if (!existingUser && idpConfig.jitProvisioning) {
        // JIT provision new user
        const openId = `saml_${crypto.randomBytes(16).toString("hex")}`;
        const [insertResult] = await db.insert(users).values({
          openId,
          name: userAttrs.name || userAttrs.email.split("@")[0],
          email: userAttrs.email,
          loginMethod: "saml",
          role: (userAttrs.role as any) || idpConfig.defaultRole,
          department: userAttrs.department || null,
          status: "active",
          invitedBy: null,
        });

        [existingUser] = await db
          .select()
          .from(users)
          .where(eq(users.id, insertResult.insertId))
          .limit(1);

        await logSamlEvent(db, "jit_provision", idpConfig.id, existingUser!.id, assertion.nameId, req.ip || "", `JIT provisioned user: ${userAttrs.email}`);
      }

      if (!existingUser) {
        await logSamlEvent(db, "login_failure", idpConfig.id, null, assertion.nameId, req.ip || "", `User not found and JIT provisioning disabled: ${userAttrs.email}`);
        return res.status(403).json({ error: "User not found. Contact your administrator." });
      }

      // Update last sign-in
      await db.update(users).set({ lastSignedIn: new Date() }).where(eq(users.id, existingUser.id));

      // Create session
      const AUTH_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
      const token = jwt.sign(
        {
          userId: existingUser.id,
          openId: existingUser.openId,
          email: existingUser.email,
          role: existingUser.role,
          loginMethod: "saml",
          samlIdpId: idpConfig.id,
        },
        AUTH_SECRET,
        { expiresIn: "7d" }
      );

      // Set session cookie
      res.cookie("caldera_session", token, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        domain: process.env.COOKIE_DOMAIN || undefined,
      });

      // Create session record
      const sessionHash = crypto.createHash("sha256").update(token).digest("hex");
      await db.insert(userSessions).values({
        sessionHash,
        userId: existingUser.id,
        loginMethod: "saml",
        samlIdpId: idpConfig.id,
        ipAddress: req.ip || req.headers["x-forwarded-for"]?.toString() || "",
        userAgent: req.headers["user-agent"] || "",
        browserName: parseBrowserName(req.headers["user-agent"] || ""),
        osName: parseOSName(req.headers["user-agent"] || ""),
        deviceType: parseDeviceType(req.headers["user-agent"] || ""),
        status: "active",
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      await logSamlEvent(db, "login_success", idpConfig.id, existingUser.id, assertion.nameId, req.ip || "");

      // Redirect to dashboard or relay state
      const redirectTo = relayState || "/";
      return res.redirect(redirectTo);
    } catch (err: any) {
      console.error("[SAML ACS] Error processing SAML response:", err);
      await logSamlEvent(db, "assertion_error", null, null, null, req.ip || "", err.message);
      return res.status(400).json({ error: "Failed to process SAML response", details: err.message });
    }
  });

  // SSO initiation endpoint (for login page redirect)
  app.get("/api/saml/login/:idpId", async (req: Request, res: Response) => {
    const db = await getDb();
    const idpId = parseInt(req.params.idpId, 10);
    if (isNaN(idpId)) return res.status(400).json({ error: "Invalid IdP ID" });

    const [config] = await db
      .select()
      .from(samlIdpConfigs)
      .where(and(eq(samlIdpConfigs.id, idpId), eq(samlIdpConfigs.isActive, true)))
      .limit(1);

    if (!config) return res.status(404).json({ error: "IdP not found or inactive" });

    const { url } = generateAuthnRequest(config as any, req.query.returnTo as string);
    return res.redirect(url);
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function logSamlEvent(
  db: any,
  eventType: "login_success" | "login_failure" | "logout" | "jit_provision" | "assertion_error" | "signature_invalid",
  idpConfigId: number | null,
  userId: number | null,
  nameId: string | null,
  ipAddress: string,
  errorDetails?: string
) {
  try {
    await db.insert(samlAuthEvents).values({
      eventType,
      idpConfigId,
      userId,
      nameId,
      ipAddress,
      errorDetails: errorDetails || null,
      assertionId: null,
    });
  } catch (err) {
    console.error("[SAML] Failed to log auth event:", err);
  }
}

function normalizeCert(cert: string): string {
  const cleaned = cert
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const lines = cleaned.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

function parseBrowserName(ua: string): string {
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("Chrome")) return "Chrome";
  if (ua.includes("Safari")) return "Safari";
  if (ua.includes("Opera") || ua.includes("OPR")) return "Opera";
  return "Unknown";
}

function parseOSName(ua: string): string {
  if (ua.includes("Windows")) return "Windows";
  if (ua.includes("Mac OS")) return "macOS";
  if (ua.includes("Linux")) return "Linux";
  if (ua.includes("Android")) return "Android";
  if (ua.includes("iPhone") || ua.includes("iPad")) return "iOS";
  return "Unknown";
}

function parseDeviceType(ua: string): string {
  if (ua.includes("Mobile") || ua.includes("Android") || ua.includes("iPhone")) return "mobile";
  if (ua.includes("iPad") || ua.includes("Tablet")) return "tablet";
  return "desktop";
}
