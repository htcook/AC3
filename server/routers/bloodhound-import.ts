/**
 * BloodHound Data Import Router
 * Handles SharpHound JSON/ZIP file uploads, parsing, and import into the AD Attack Path Graph.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  importBloodHoundData,
  parseSharpHoundJSON,
  detectCollectionType,
  type BloodHoundParseResult,
} from "../lib/bloodhound-parser";
import { getDb } from "../db";
import { adEnvironments, adObjects } from "../../drizzle/schema";
import { eq } from "drizzle-orm";

export const bloodhoundImportRouter = router({
  /**
   * Preview a SharpHound file without importing.
   * Accepts base64-encoded file data, returns parse stats.
   */
  preview: protectedProcedure
    .input(z.object({
      files: z.array(z.object({
        filename: z.string(),
        data: z.string(), // base64
      })).min(1).max(20),
    }))
    .mutation(async ({ input }): Promise<BloodHoundParseResult> => {
      const fileData = input.files.map(f => ({
        filename: f.filename,
        data: Buffer.from(f.data, "base64"),
      }));
      const result = await importBloodHoundData(fileData);
      return result;
    }),

  /**
   * Import SharpHound data into an AD environment.
   * Creates the environment if it doesn't exist, then inserts all nodes/edges.
   */
  import: protectedProcedure
    .input(z.object({
      environmentName: z.string().min(1).max(200),
      environmentId: z.number().optional(),
      files: z.array(z.object({
        filename: z.string(),
        data: z.string(), // base64
      })).min(1).max(20),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();

      // Parse the files
      const fileData = input.files.map(f => ({
        filename: f.filename,
        data: Buffer.from(f.data, "base64"),
      }));
      const result = await importBloodHoundData(fileData);

      if (result.nodes.length === 0) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: `No valid objects found. Parse errors: ${result.stats.parseErrors.join("; ")}`,
        });
      }

      // Create or use existing environment
      let envId = input.environmentId;
      if (!envId) {
        const [env] = await db!.insert(adEnvironments).values({
          domainName: result.nodes.find(n => n.type === "domain")?.label || input.environmentName,
          domainController: "imported-from-bloodhound",
          status: "connected" as const,
          connectionConfig: JSON.stringify({ source: "bloodhound", importedBy: ctx.user.id, environmentName: input.environmentName }),
        }).$returningId();
        envId = env.id;
      }

      // Insert AD objects from parsed nodes
      let importedObjects = 0;
      const batchSize = 100;
      const nodeArray = result.nodes;

      for (let i = 0; i < nodeArray.length; i += batchSize) {
        const batch = nodeArray.slice(i, i + batchSize);
        const values = batch.map(node => ({
          environmentId: envId!,
          objectType: mapNodeTypeToADObjectType(node.type),
          objectName: node.label,
          distinguishedName: node.properties.distinguishedName || `CN=${node.label}`,
          objectSid: node.id,
          isPrivileged: node.isHighValue,
          riskScore: node.riskScore,
          attributes: JSON.stringify({
            ...node.properties,
            bloodhoundImport: true,
            nodeType: node.type,
            isEnabled: node.isEnabled,
          }),
        }));

        try {
          await db!.insert(adObjects).values(values);
          importedObjects += batch.length;
        } catch (e: any) {
          // Skip duplicates, continue with rest
          for (const val of values) {
            try {
              await db!.insert(adObjects).values([val]);
              importedObjects++;
            } catch {
              // Duplicate or constraint violation, skip
            }
          }
        }
      }

      return {
        environmentId: envId,
        environmentName: input.environmentName,
        importedObjects,
        totalNodes: result.nodes.length,
        totalEdges: result.edges.length,
        stats: result.stats,
        graphData: {
          nodes: result.nodes,
          edges: result.edges,
        },
      };
    }),

  /**
   * Get supported file formats and instructions.
   */
  getInfo: protectedProcedure.query(() => {
    return {
      supportedFormats: [
        { extension: ".zip", description: "SharpHound ZIP collection (recommended)" },
        { extension: ".json", description: "Individual SharpHound JSON files" },
      ],
      collectionTypes: [
        "users", "groups", "computers", "domains", "gpos", "ous", "containers",
      ],
      maxFileSize: "50MB per file",
      maxFiles: 20,
      instructions: [
        "Run SharpHound with: SharpHound.exe --CollectionMethods All",
        "Upload the resulting ZIP file or individual JSON files",
        "Preview to verify data before importing",
        "Import into a new or existing AD environment",
      ],
      bloodhoundVersions: ["v4 (SharpHound)", "v5 (SharpHound)"],
    };
  }),
});

type ADObjectType = "user" | "group" | "computer" | "ou" | "gpo" | "trust" | "spn" | "certificate_template";

function mapNodeTypeToADObjectType(nodeType: string): ADObjectType {
  const map: Record<string, ADObjectType> = {
    user: "user",
    group: "group",
    computer: "computer",
    dc: "computer",
    domain: "ou",
    gpo: "gpo",
    ou: "ou",
    service_account: "user",
  };
  return map[nodeType] || "user";
}
