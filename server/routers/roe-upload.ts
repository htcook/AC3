/**
 * roe-upload.ts — tRPC Router for RoE/Test Plan Document Upload
 * ═══════════════════════════════════════════════════════════════
 * Handles document upload, parsing, preview, and auto-engagement creation.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { storagePut } from "../storage";
import { parseRoeDocument, persistUploadedDocument, markUploadedDocFailed } from "../roe-document-parser";
import { autoDesignEngagement } from "../roe-auto-engagement";
import type { ParsedRoeDocument } from "../roe-document-parser";

export const roeUploadRouter = router({
  /**
   * Upload and parse a RoE/Test Plan document.
   * Returns the parsed data for preview before engagement creation.
   */
  uploadAndParse: protectedProcedure
    .input(z.object({
      filename: z.string().min(1),
      mimeType: z.string().min(1),
      fileBase64: z.string().min(1),
    }))
    .mutation(async ({ input, ctx }) => {
      // Validate MIME type
      const allowedTypes = [
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/msword',
      ];
      if (!allowedTypes.includes(input.mimeType)) {
        throw new TRPCError({
          code: 'BAD_REQUEST',
          message: `Unsupported file type: ${input.mimeType}. Only PDF and Word (.docx) files are supported.`,
        });
      }

      // Decode base64 to buffer
      const buffer = Buffer.from(input.fileBase64, 'base64');
      if (buffer.length > 50 * 1024 * 1024) {
        throw new TRPCError({
          code: 'BAD_REQUEST',
          message: 'File too large. Maximum size is 50MB.',
        });
      }

      // Upload to S3
      const randomSuffix = Math.random().toString(36).substring(2, 10);
      const ext = input.filename.split('.').pop() || 'bin';
      const storageKey = `roe-uploads/${ctx.user.id}/${Date.now()}-${randomSuffix}.${ext}`;
      const { url: storageUrl } = await storagePut(storageKey, buffer, input.mimeType);

      try {
        // Parse the document
        const { text, parsed } = await parseRoeDocument(buffer, input.mimeType, input.filename);

        // Persist the uploaded document record
        const uploadedDocId = await persistUploadedDocument({
          filename: input.filename,
          mimeType: input.mimeType,
          fileSize: buffer.length,
          storageUrl,
          storageKey,
          documentType: parsed.documentType,
          extractedText: text,
          parsedData: parsed,
          uploadedBy: ctx.user.id,
        });

        return {
          uploadedDocId,
          storageUrl,
          parsed,
        };
      } catch (err: any) {
        // Still save the upload record even if parsing fails
        try {
          const { getDb } = await import("../db");
          const db = await getDb();
          if (db) {
            const { uploadedRoeDocuments } = await import("../../drizzle/schema");
            await db.insert(uploadedRoeDocuments).values({
              filename: input.filename,
              mimeType: input.mimeType,
              fileSize: buffer.length,
              storageUrl,
              storageKey,
              documentType: 'unknown' as any,
              parseStatus: 'failed' as any,
              parseError: err.message || 'Unknown parsing error',
              uploadedBy: ctx.user.id,
            });
          }
        } catch {
          // Ignore persistence errors
        }

        throw new TRPCError({
          code: 'INTERNAL_SERVER_ERROR',
          message: `Failed to parse document: ${err.message}`,
        });
      }
    }),

  /**
   * Create an engagement from a previously parsed document.
   * Accepts the uploadedDocId and optional overrides.
   */
  createEngagementFromDoc: protectedProcedure
    .input(z.object({
      uploadedDocId: z.number(),
      // Optional overrides — user can adjust parsed data before creation
      overrides: z.object({
        engagementName: z.string().optional(),
        customerName: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).optional(),
        startDate: z.string().optional(),
        endDate: z.string().optional(),
      }).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database not available' });

      const { uploadedRoeDocuments } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      // Fetch the uploaded document
      const [doc] = await db.select().from(uploadedRoeDocuments).where(eq(uploadedRoeDocuments.id, input.uploadedDocId)).limit(1);
      if (!doc) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Uploaded document not found' });
      }
      if (doc.parseStatus !== 'parsed') {
        throw new TRPCError({ code: 'BAD_REQUEST', message: `Document has not been parsed yet (status: ${doc.parseStatus})` });
      }
      if (doc.createdEngagementId) {
        throw new TRPCError({ code: 'BAD_REQUEST', message: `An engagement has already been created from this document (engagement #${doc.createdEngagementId})` });
      }

      const parsed = doc.parsedData as unknown as ParsedRoeDocument;
      if (!parsed) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Parsed data is missing from document record' });
      }

      // Apply overrides
      if (input.overrides) {
        if (input.overrides.engagementName) parsed.engagement.engagementName = input.overrides.engagementName;
        if (input.overrides.customerName) parsed.engagement.customerName = input.overrides.customerName;
        if (input.overrides.engagementType) parsed.engagement.engagementType = input.overrides.engagementType as any;
        if (input.overrides.startDate) parsed.engagement.startDate = input.overrides.startDate;
        if (input.overrides.endDate) parsed.engagement.endDate = input.overrides.endDate;
      }

      // Auto-design the engagement
      const result = await autoDesignEngagement(parsed, input.uploadedDocId, ctx.user.id);

      return result;
    }),

  /**
   * List all uploaded RoE documents.
   */
  listUploaded: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const db = await getDb();
    if (!db) return [];

    const { uploadedRoeDocuments } = await import("../../drizzle/schema");
    const { desc } = await import("drizzle-orm");

    return db.select().from(uploadedRoeDocuments).orderBy(desc(uploadedRoeDocuments.createdAt)).limit(50);
  }),

  /**
   * Get a specific uploaded document with its parsed data.
   */
  getUploaded: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) return null;

      const { uploadedRoeDocuments } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const [doc] = await db.select().from(uploadedRoeDocuments).where(eq(uploadedRoeDocuments.id, input.id)).limit(1);
      return doc || null;
    }),

  /**
   * Get the comms protocol for an engagement.
   */
  getCommsProtocol: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) return null;

      const { engagementCommsProtocols } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const [protocol] = await db.select().from(engagementCommsProtocols).where(eq(engagementCommsProtocols.engagementId, input.engagementId)).limit(1);
      return protocol || null;
    }),

  /**
   * Get the scope constraints for an engagement.
   */
  getScopeConstraints: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) return null;

      const { engagementScopeConstraints } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const [constraints] = await db.select().from(engagementScopeConstraints).where(eq(engagementScopeConstraints.engagementId, input.engagementId)).limit(1);
      return constraints || null;
    }),

  /**
   * Re-parse a previously uploaded document (e.g., after fixing extraction issues).
   */
  reParse: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database not available' });

      const { uploadedRoeDocuments } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const [doc] = await db.select().from(uploadedRoeDocuments).where(eq(uploadedRoeDocuments.id, input.id)).limit(1);
      if (!doc) throw new TRPCError({ code: 'NOT_FOUND', message: 'Document not found' });

      // Fetch the file from S3
      const response = await fetch(doc.storageUrl);
      if (!response.ok) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Failed to fetch document from storage' });
      const buffer = Buffer.from(await response.arrayBuffer());

      try {
        const { text, parsed } = await parseRoeDocument(buffer, doc.mimeType, doc.filename);

        await db.update(uploadedRoeDocuments)
          .set({
            extractedText: text,
            extractedTextLength: text.length,
            parsedData: parsed as any,
            parseStatus: 'parsed' as any,
            parseError: null,
            parsedAt: new Date().toISOString(),
            documentType: parsed.documentType as any,
          })
          .where(eq(uploadedRoeDocuments.id, input.id));

        return { success: true, parsed };
      } catch (err: any) {
        await markUploadedDocFailed(input.id, err.message);
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `Re-parse failed: ${err.message}` });
      }
    }),
});
