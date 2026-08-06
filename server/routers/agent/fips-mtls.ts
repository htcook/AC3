/**
 * FIPS & mTLS Sub-Router
 *
 * Manages FIPS 140-3 compliance auditing, TLS enforcement verification,
 * credential migration, and mTLS certificate lifecycle.
 * Extracted from agent-manager.ts for maintainability.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, adminProcedure, router } from "../../_core/trpc";
import { getDb } from "../../db";
import { fipsComplianceRecords } from "../../../drizzle/schema";
import { desc } from "drizzle-orm";
import { getFIPSCrypto } from "../../lib/fips-crypto";
import { runScheduledFipsAudit } from "../../lib/fips-audit-scheduler";
import { scanCredentials, runFullMigration } from "../../lib/credential-migration";
import {
  ensureCA,
  issueClientCertForServer,
  listCertificates,
  revokeCertificate,
  getCertificateWithKey,
  getMTLSConfigForServer,
} from "../../lib/mtls-certs";

// ─── Router ──────────────────────────────────────────────────────────

export const fipsMtlsRouter = router({
  // ─── FIPS Compliance ────────────────────────────────────────────────

  fipsStatus: protectedProcedure.query(async () => {
    const fips = getFIPSCrypto();
    return fips.getComplianceReport();
  }),

  fipsAudit: protectedProcedure.mutation(async () => {
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const fips = getFIPSCrypto();
    const report = fips.getComplianceReport();

    const checks: Array<{
      checkType: "tls_cipher" | "algorithm_usage" | "key_strength" | "provider_status" | "full_audit";
      status: "compliant" | "non_compliant" | "warning";
      component: string;
      details: Record<string, unknown>;
    }> = [];

    // Provider status
    checks.push({
      checkType: "provider_status",
      status: report.fipsProviderActive ? "compliant" : "warning",
      component: "openssl-fips-provider",
      details: {
        active: report.fipsProviderActive,
        opensslVersion: report.opensslVersion,
        note: report.fipsProviderActive
          ? "FIPS provider active"
          : "FIPS provider not active — using software-only mode with FIPS-approved algorithms.",
      },
    });

    // Test AES-256-GCM
    try {
      const testData = "FIPS compliance test payload";
      const encrypted = fips.encrypt(testData, "fips-audit");
      const decrypted = fips.decrypt(encrypted, "fips-audit");
      checks.push({
        checkType: "algorithm_usage",
        status: decrypted.toString() === testData ? "compliant" : "non_compliant",
        component: "aes-256-gcm",
        details: { algorithm: "aes-256-gcm", operation: "encrypt-decrypt", result: "pass" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "algorithm_usage",
        status: "non_compliant",
        component: "aes-256-gcm",
        details: { error: e.message },
      });
    }

    // Test ECDSA P-256
    try {
      const kp = fips.generateKeyPair("P-256");
      const sig = fips.sign("test", kp.privateKey);
      const valid = fips.verify("test", sig, kp.publicKey);
      checks.push({
        checkType: "key_strength",
        status: valid ? "compliant" : "non_compliant",
        component: "ecdsa-p256",
        details: { curve: "P-256", signVerify: valid ? "pass" : "fail" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "key_strength",
        status: "non_compliant",
        component: "ecdsa-p256",
        details: { error: e.message },
      });
    }

    // Test HMAC-SHA256
    try {
      const hmacResult = fips.hmac("test data");
      const verified = fips.verifyHmac("test data", hmacResult);
      checks.push({
        checkType: "algorithm_usage",
        status: verified ? "compliant" : "non_compliant",
        component: "hmac-sha256",
        details: { algorithm: "hmac-sha256", result: verified ? "pass" : "fail" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "algorithm_usage",
        status: "non_compliant",
        component: "hmac-sha256",
        details: { error: e.message },
      });
    }

    // Test PBKDF2
    try {
      const pw = fips.hashPassword("test-password-123");
      const valid = fips.verifyPassword("test-password-123", pw);
      checks.push({
        checkType: "algorithm_usage",
        status: valid ? "compliant" : "non_compliant",
        component: "pbkdf2-sha256",
        details: { iterations: pw.iterations, result: valid ? "pass" : "fail" },
      });
    } catch (e: any) {
      checks.push({
        checkType: "algorithm_usage",
        status: "non_compliant",
        component: "pbkdf2-sha256",
        details: { error: e.message },
      });
    }

    // Full audit summary
    const allCompliant = checks.every((c) => c.status === "compliant");
    const hasNonCompliant = checks.some((c) => c.status === "non_compliant");
    checks.push({
      checkType: "full_audit",
      status: hasNonCompliant ? "non_compliant" : allCompliant ? "compliant" : "warning",
      component: "platform-wide",
      details: {
        totalChecks: checks.length,
        compliant: checks.filter((c) => c.status === "compliant").length,
        warnings: checks.filter((c) => c.status === "warning").length,
        nonCompliant: checks.filter((c) => c.status === "non_compliant").length,
      },
    });

    // Store results
    const now = Date.now();
    for (const check of checks) {
      await db.insert(fipsComplianceRecords).values({
        checkType: check.checkType,
        status: check.status,
        component: check.component,
        details: check.details,
        opensslVersion: report.opensslVersion,
        fipsProviderActive: report.fipsProviderActive,
        createdAt: now,
      });
    }

    return { checks, overallStatus: hasNonCompliant ? "non_compliant" : allCompliant ? "compliant" : "warning" };
  }),

  fipsHistory: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(50) }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      return db.select().from(fipsComplianceRecords).orderBy(desc(fipsComplianceRecords.id)).limit(input.limit);
    }),

  runScheduledFipsAudit: adminProcedure.mutation(async () => {
    return runScheduledFipsAudit();
  }),

  // ─── TLS Audit ──────────────────────────────────────────────────────

  auditTLS: protectedProcedure.query(async () => {
    const { auditTLSConfiguration } = await import("../../lib/fips-tls");
    const { isFIPSTLSEnforced } = await import("../../lib/fips-tls-global");
    const audit = auditTLSConfiguration();
    return { ...audit, globalEnforcement: isFIPSTLSEnforced(), timestamp: Date.now() };
  }),

  testTLSConnection: protectedProcedure
    .input(z.object({
      hostname: z.string().min(1),
      port: z.number().min(1).max(65535).default(443),
    }))
    .mutation(async ({ input }) => {
      const { testFIPSTLSConnection } = await import("../../lib/fips-tls");
      return testFIPSTLSConnection(input.hostname, input.port);
    }),

  // ─── Credential Migration ─────────────────────────────────────────────

  scanCredentialMigration: adminProcedure.query(async () => {
    const scan = await scanCredentials();
    const totalLegacy =
      scan.serverCredentials.legacy + scan.serverCredentials.plaintext +
      scan.sshKeys.legacy + scan.sshKeys.plaintext +
      scan.cloudCredentials.legacy;
    const totalFips =
      scan.serverCredentials.fips + scan.sshKeys.fips + scan.cloudCredentials.fips;
    const totalAll =
      scan.serverCredentials.total + scan.sshKeys.total + scan.cloudCredentials.total;

    return {
      ...scan,
      summary: {
        totalCredentials: totalAll,
        totalFips,
        totalLegacy,
        migrationNeeded: totalLegacy > 0,
        fipsPercentage: totalAll > 0 ? Math.round((totalFips / totalAll) * 100) : 100,
      },
      timestamp: Date.now(),
    };
  }),

  runCredentialMigration: adminProcedure.mutation(async () => {
    return runFullMigration();
  }),

  // ─── mTLS Certificate Management ──────────────────────────────────────

  ensureMTLSCA: adminProcedure.mutation(async () => {
    const ca = await ensureCA();
    const { privateKey, ...info } = ca;
    return info;
  }),

  issueClientCert: adminProcedure
    .input(z.object({ c2ServerId: z.string().min(1), serverName: z.string().min(1) }))
    .mutation(async ({ input }) => {
      const cert = await issueClientCertForServer(input.c2ServerId, input.serverName);
      const { privateKey, ...info } = cert;
      return info;
    }),

  listMTLSCerts: protectedProcedure.query(async () => {
    return listCertificates();
  }),

  revokeMTLSCert: adminProcedure
    .input(z.object({ id: z.string().min(1) }))
    .mutation(async ({ input }) => {
      const success = await revokeCertificate(input.id);
      if (!success) throw new TRPCError({ code: "NOT_FOUND", message: "Certificate not found" });
      return { success: true };
    }),

  downloadCert: adminProcedure
    .input(z.object({ id: z.string().min(1) }))
    .query(async ({ input }) => {
      const cert = await getCertificateWithKey(input.id);
      if (!cert) throw new TRPCError({ code: "NOT_FOUND", message: "Certificate not found" });
      return { certificate: cert.certificate, commonName: cert.commonName, fingerprint: cert.fingerprint };
    }),

  getMTLSStatus: protectedProcedure
    .input(z.object({ c2ServerId: z.string().min(1) }))
    .query(async ({ input }) => {
      const config = await getMTLSConfigForServer(input.c2ServerId);
      return { enabled: config !== null, hasCert: config !== null, hasCA: config !== null };
    }),
});
