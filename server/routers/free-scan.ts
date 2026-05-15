import { z } from "zod";
import { router, publicProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { freeScanRequests } from "../../drizzle/schema";
import { eq, and, sql, desc } from "drizzle-orm";
import { randomBytes } from "crypto";

// ─── SES Email Helper ──────────────────────────────────────────────────────────
async function sendVerificationEmail(params: {
  email: string;
  name: string;
  domain: string;
  verificationToken: string;
}) {
  // Use AWS SES via SDK — the ECS task role will have SES permissions in production
  // For now, use the environment's AWS credentials
  const baseUrl = process.env.APP_BASE_URL || process.env.VITE_APP_URL || "https://app.aceofcloud.io";
  const verificationUrl = `${baseUrl}/verify-scan/${params.verificationToken}`;

  try {
    // Dynamic import to avoid issues if aws-sdk isn't available in dev
    const { SESClient, SendTemplatedEmailCommand } = await import("@aws-sdk/client-ses");
    const ses = new SESClient({ region: "us-east-1" });

    const command = new SendTemplatedEmailCommand({
      Source: "AceofCloud Security <noreply@aceofcloud.io>",
      Destination: { ToAddresses: [params.email] },
      Template: "DIScanVerification",
      TemplateData: JSON.stringify({
        name: params.name,
        domain: params.domain,
        verificationUrl,
      }),
      ConfigurationSetName: "ac3-production",
    });

    await ses.send(command);
    console.log(`[FreeScan] Verification email sent to ${params.email} for domain ${params.domain}`);
    return true;
  } catch (error: any) {
    console.error(`[FreeScan] Failed to send verification email:`, error?.message || error);
    // Fallback: log the verification URL for testing
    console.log(`[FreeScan] FALLBACK - Verification URL: ${verificationUrl}`);
    return false;
  }
}

async function sendScanCompleteEmail(params: {
  email: string;
  name: string;
  domain: string;
  resultsToken: string;
  findingsSummary: string;
}) {
  const baseUrl = process.env.APP_BASE_URL || process.env.VITE_APP_URL || "https://app.aceofcloud.io";
  const resultsUrl = `${baseUrl}/scan-results/${params.resultsToken}`;
  const demoUrl = `${baseUrl}/#demo`;

  try {
    const { SESClient, SendTemplatedEmailCommand } = await import("@aws-sdk/client-ses");
    const ses = new SESClient({ region: "us-east-1" });

    const command = new SendTemplatedEmailCommand({
      Source: "AceofCloud Security <noreply@aceofcloud.io>",
      Destination: { ToAddresses: [params.email] },
      Template: "DIScanComplete",
      TemplateData: JSON.stringify({
        name: params.name,
        domain: params.domain,
        resultsUrl,
        demoUrl,
        findingsSummary: params.findingsSummary,
      }),
      ConfigurationSetName: "ac3-production",
    });

    await ses.send(command);
    console.log(`[FreeScan] Scan complete email sent to ${params.email}`);
    return true;
  } catch (error: any) {
    console.error(`[FreeScan] Failed to send scan complete email:`, error?.message || error);
    return false;
  }
}

// ─── Free Scan Router ──────────────────────────────────────────────────────────
export const freeScanRouter = router({
  // PUBLIC: Submit a free scan request (rate-limited by email)
  submit: publicProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      email: z.string().email().max(255),
      organization: z.string().max(255).optional(),
      jobTitle: z.string().max(255).optional(),
      targetDomain: z.string().min(3).max(255)
        .refine((d) => /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(d), {
          message: "Please enter a valid domain (e.g., example.com)",
        }),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();

      // Rate limiting: 1 scan per email per 24 hours
      const recentRequest = await db
        .select({ id: freeScanRequests.id })
        .from(freeScanRequests)
        .where(
          and(
            eq(freeScanRequests.email, input.email),
            sql`${freeScanRequests.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`
          )
        )
        .limit(1);

      if (recentRequest.length > 0) {
        throw new TRPCError({
          code: "TOO_MANY_REQUESTS",
          message: "You've already requested a scan in the last 24 hours. Please check your email for the verification link.",
        });
      }

      // Rate limiting: max 3 scans per IP per 24 hours
      const clientIp = (ctx as any).req?.headers?.["x-forwarded-for"]?.split(",")[0]?.trim()
        || (ctx as any).req?.socket?.remoteAddress || "unknown";

      if (clientIp !== "unknown") {
        const recentFromIp = await db
          .select({ id: freeScanRequests.id })
          .from(freeScanRequests)
          .where(
            and(
              eq(freeScanRequests.ipAddress, clientIp),
              sql`${freeScanRequests.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`
            )
          );

        if (recentFromIp.length >= 3) {
          throw new TRPCError({
            code: "TOO_MANY_REQUESTS",
            message: "Too many scan requests from your network. Please try again later.",
          });
        }
      }

      // Generate tokens
      const verificationToken = randomBytes(32).toString("hex");
      const resultsToken = randomBytes(32).toString("hex");

      // Verification expires in 24 hours, results expire in 30 days
      const now = new Date();
      const verificationExpires = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      const resultsExpires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

      const userAgent = (ctx as any).req?.headers?.["user-agent"] || null;

      // Insert the request
      const [result] = await db.insert(freeScanRequests).values({
        name: input.name,
        email: input.email,
        organization: input.organization || null,
        jobTitle: input.jobTitle || null,
        targetDomain: input.targetDomain.toLowerCase(),
        verificationToken,
        verificationExpiresAt: verificationExpires.toISOString().slice(0, 19).replace("T", " "),
        resultsToken,
        resultsExpiresAt: resultsExpires.toISOString().slice(0, 19).replace("T", " "),
        ipAddress: clientIp,
        userAgent: userAgent?.substring(0, 512) || null,
      });

      // Send verification email
      await sendVerificationEmail({
        email: input.email,
        name: input.name,
        domain: input.targetDomain,
        verificationToken,
      });

      // Notify owner of new lead
      try {
        const { notifyOwner } = await import("../_core/notification");
        await notifyOwner({
          title: `New Free Scan Lead: ${input.organization || input.name}`,
          content: [
            `**Name:** ${input.name}`,
            input.jobTitle ? `**Title:** ${input.jobTitle}` : null,
            input.organization ? `**Organization:** ${input.organization}` : null,
            `**Email:** ${input.email}`,
            `**Target Domain:** ${input.targetDomain}`,
            `---`,
            `*Submitted at ${new Date().toISOString()}*`,
          ].filter(Boolean).join("\n"),
        });
      } catch (e) {
        console.error("[FreeScan] Failed to notify owner:", e);
      }

      return {
        success: true,
        message: "Please check your email to verify and start the scan. The link expires in 24 hours.",
      };
    }),

  // PUBLIC: Verify email and trigger scan
  verify: publicProcedure
    .input(z.object({
      token: z.string().min(1).max(128),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();

      // Find the request by verification token
      const [request] = await db
        .select()
        .from(freeScanRequests)
        .where(eq(freeScanRequests.verificationToken, input.token))
        .limit(1);

      if (!request) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Invalid or expired verification link.",
        });
      }

      // Check if already verified
      if (request.status !== "pending_verification") {
        return {
          success: true,
          alreadyVerified: true,
          resultsToken: request.resultsToken,
          status: request.status,
          message: request.status === "completed"
            ? "Your scan is already complete! Redirecting to results..."
            : "Your email has already been verified. Scan is in progress.",
        };
      }

      // Check expiration
      const expiresAt = new Date(request.verificationExpiresAt);
      if (expiresAt < new Date()) {
        await db
          .update(freeScanRequests)
          .set({ status: "expired" })
          .where(eq(freeScanRequests.id, request.id));

        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "This verification link has expired. Please submit a new scan request.",
        });
      }

      // Mark as verified
      await db
        .update(freeScanRequests)
        .set({
          status: "verified",
          verifiedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
        })
        .where(eq(freeScanRequests.id, request.id));

      // Trigger the DI scan in the background
      setImmediate(async () => {
        try {
          await triggerFreeScan(request.id, request.targetDomain, request.name, request.email, request.resultsToken);
        } catch (error) {
          console.error(`[FreeScan] Failed to trigger scan for request ${request.id}:`, error);
          const db2 = await getDb();
          await db2
            .update(freeScanRequests)
            .set({ status: "failed" })
            .where(eq(freeScanRequests.id, request.id));
        }
      });

      return {
        success: true,
        alreadyVerified: false,
        resultsToken: request.resultsToken,
        status: "scanning",
        message: "Email verified! Your Domain Intelligence scan is starting. We'll email you when results are ready.",
      };
    }),

  // PUBLIC: Get scan results by token
  getResults: publicProcedure
    .input(z.object({
      token: z.string().min(1).max(128),
    }))
    .query(async ({ input }) => {
      const db = await getDb();

      const [request] = await db
        .select()
        .from(freeScanRequests)
        .where(eq(freeScanRequests.resultsToken, input.token))
        .limit(1);

      if (!request) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Invalid results link.",
        });
      }

      // Check results expiration
      const expiresAt = new Date(request.resultsExpiresAt);
      if (expiresAt < new Date()) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "These scan results have expired. Please request a new scan.",
        });
      }

      // If scan is still in progress, return status
      if (request.status === "scanning" || request.status === "verified") {
        return {
          status: "scanning",
          domain: request.targetDomain,
          name: request.name,
          message: "Your scan is still in progress. This usually takes 2-5 minutes.",
        };
      }

      if (request.status === "failed") {
        return {
          status: "failed",
          domain: request.targetDomain,
          name: request.name,
          message: "We encountered an issue running your scan. Please try again or contact us.",
        };
      }

      if (request.status !== "completed" || !request.scanId) {
        return {
          status: request.status,
          domain: request.targetDomain,
          name: request.name,
          message: "Scan has not completed yet.",
        };
      }

      // Fetch the scan results from domain_intel_scans
      const { domainIntelScans } = await import("../../drizzle/schema");
      const [scan] = await db
        .select()
        .from(domainIntelScans)
        .where(eq(domainIntelScans.id, request.scanId))
        .limit(1);

      if (!scan) {
        return {
          status: "failed",
          domain: request.targetDomain,
          name: request.name,
          message: "Scan results not found. Please contact support.",
        };
      }

      // Return sanitized results (no internal IDs, user info, etc.)
      return {
        status: "completed",
        domain: request.targetDomain,
        name: request.name,
        scanResults: {
          primaryDomain: scan.primaryDomain,
          totalAssets: scan.totalAssets,
          totalFindings: scan.totalFindings,
          confirmedFindings: scan.confirmedFindings,
          probableFindings: scan.probableFindings,
          potentialFindings: scan.potentialFindings,
          overallRiskScore: scan.overallRiskScore,
          overallRiskBand: scan.overallRiskBand,
          executiveSummary: scan.executiveSummary,
          threatModelSummary: scan.threatModelSummary,
          completedAt: scan.updatedAt,
        },
        expiresAt: request.resultsExpiresAt,
      };
    }),

  // PUBLIC: Check scan status by results token (for polling)
  checkStatus: publicProcedure
    .input(z.object({
      token: z.string().min(1).max(128),
    }))
    .query(async ({ input }) => {
      const db = await getDb();

      const [request] = await db
        .select({
          status: freeScanRequests.status,
          targetDomain: freeScanRequests.targetDomain,
        })
        .from(freeScanRequests)
        .where(eq(freeScanRequests.resultsToken, input.token))
        .limit(1);

      if (!request) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Invalid token." });
      }

      return { status: request.status, domain: request.targetDomain };
    }),
});

// ─── Background Scan Trigger ───────────────────────────────────────────────────
async function triggerFreeScan(
  requestId: number,
  targetDomain: string,
  name: string,
  email: string,
  resultsToken: string,
) {
  const db = await getDb();

  // Update status to scanning
  await db
    .update(freeScanRequests)
    .set({ status: "scanning" })
    .where(eq(freeScanRequests.id, requestId));

  console.log(`[FreeScan] Triggering DI scan for ${targetDomain} (request ${requestId})`);

  try {
    // Use the existing DI pipeline
    const { runDomainIntelPipeline } = await import("../domainIntel");
    const { createDomainIntelScan } = await import("../db");

    // Create a scan record (no engagement, no user — it's a free scan)
    const scanId = await createDomainIntelScan({
      primaryDomain: targetDomain,
      additionalDomains: [],
      clientType: "enterprise",
      sector: "unknown",
      engagementId: undefined,
      orgProfile: {
        customerName: name,
        primaryDomain: targetDomain,
        sector: "unknown",
        clientType: "enterprise",
        criticalFunctions: [],
        complianceFlags: [],
        scopedAssets: [],
        scanMode: "strict_passive",
      },
      criticalFunctions: [],
      complianceFlags: [],
      notes: `Free scan request from ${email}`,
      status: "discovering",
      createdBy: undefined,
    });

    // Link scan to the free scan request
    await db
      .update(freeScanRequests)
      .set({ scanId })
      .where(eq(freeScanRequests.id, requestId));

    // Run the pipeline in strict passive mode (no active scanning on external targets)
    await runDomainIntelPipeline({
      scanId,
      primaryDomain: targetDomain,
      additionalDomains: [],
      clientType: "enterprise",
      sector: "unknown",
      customerName: name,
      criticalFunctions: [],
      complianceFlags: [],
      scanMode: "strict_passive",
      scopedAssets: [],
    });

    // Mark as completed
    await db
      .update(freeScanRequests)
      .set({ status: "completed" })
      .where(eq(freeScanRequests.id, requestId));

    // Get scan summary for email
    const { domainIntelScans } = await import("../../drizzle/schema");
    const [scan] = await db
      .select()
      .from(domainIntelScans)
      .where(eq(domainIntelScans.id, scanId))
      .limit(1);

    const findingsSummary = scan
      ? `${scan.totalAssets || 0} assets discovered, ${scan.totalFindings || 0} findings (${scan.confirmedFindings || 0} confirmed, ${scan.probableFindings || 0} probable). Risk: ${scan.overallRiskBand || "N/A"}`
      : "Scan completed successfully.";

    // Send completion email
    await sendScanCompleteEmail({
      email,
      name,
      domain: targetDomain,
      resultsToken,
      findingsSummary,
    });

    console.log(`[FreeScan] Scan completed for ${targetDomain} (request ${requestId}, scan ${scanId})`);
  } catch (error: any) {
    console.error(`[FreeScan] Scan failed for ${targetDomain}:`, error?.message || error);

    await db
      .update(freeScanRequests)
      .set({ status: "failed" })
      .where(eq(freeScanRequests.id, requestId));
  }
}
