/**
 * Detection Rule Generation Router
 * ─────────────────────────────────
 * Auto-generates SIEM detection rules (Sigma, Splunk SPL, KQL)
 * from emulation results that reveal detection gaps.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { detectionTests } from "../../drizzle/schema";
import { eq, and, sql } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

const RULE_FORMATS = ["sigma", "splunk_spl", "kql"] as const;
type RuleFormat = typeof RULE_FORMATS[number];

// ─── Sigma Template ───
function buildSigmaTemplate(techniqueId: string, techniqueName: string, tactic: string): string {
  return `title: Detection for ${techniqueName} (${techniqueId})
id: ${crypto.randomUUID ? crypto.randomUUID() : `rule-${Date.now()}`}
status: experimental
level: medium
description: Auto-generated detection rule for MITRE ATT&CK technique ${techniqueId} - ${techniqueName}
author: Ace C3 Detection Engine
date: ${new Date().toISOString().split("T")[0]}
references:
  - https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/
tags:
  - attack.${tactic}
  - attack.${techniqueId.toLowerCase()}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    # TODO: Refine selection criteria based on environment
    EventID: 1
  condition: selection
falsepositives:
  - Legitimate administrative activity
`;
}

// ─── Splunk SPL Template ───
function buildSplunkTemplate(techniqueId: string, techniqueName: string, tactic: string): string {
  return `\`\`\`spl
| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where Processes.process_name=*
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| \`drop_dm_object_name(Processes)\`
| \`security_content_ctime(firstTime)\`
| \`security_content_ctime(lastTime)\`
\`\`\`

\`\`\`
# Detection: ${techniqueName} (${techniqueId})
# Tactic: ${tactic}
# MITRE: https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/
# Status: Experimental - requires tuning for environment
\`\`\``;
}

// ─── KQL Template ───
function buildKqlTemplate(techniqueId: string, techniqueName: string, tactic: string): string {
  return `// Detection: ${techniqueName} (${techniqueId})
// Tactic: ${tactic}
// MITRE: https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/

SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
// TODO: Add specific process/command filters for ${techniqueId}
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
| sort by TimeGenerated desc`;
}

export const detectionRulesRouter = router({
  // ─── Generate rules for a specific detection test gap ───
  generateForTest: protectedProcedure
    .input(z.object({
      testId: z.string(),
      formats: z.array(z.enum(RULE_FORMATS)).default(["sigma", "splunk_spl", "kql"]),
      useLLM: z.boolean().default(true),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [test] = await db.select().from(detectionTests)
        .where(eq(detectionTests.testId, input.testId));

      if (!test) throw new TRPCError({ code: "NOT_FOUND", message: "Detection test not found" });

      const techniqueId = test.techniqueId;
      const techniqueName = test.techniqueName || techniqueId;
      const tactic = test.tactic || "unknown";

      const rules: Record<string, string> = {};

      if (input.useLLM) {
        // Use LLM to generate intelligent detection rules
        try {
          const response = await invokeLLM({
            messages: [
              {
                role: "system",
                content: `You are a SIEM detection engineering expert. Generate detection rules for the given MITRE ATT&CK technique. Return ONLY valid JSON with the requested formats. Each rule should be production-ready with proper field mappings, realistic detection logic, and low false positive rates. Include comments explaining the detection logic.`
              },
              {
                role: "user",
                content: `Generate detection rules for:
- Technique: ${techniqueId} - ${techniqueName}
- Tactic: ${tactic}
- Context: This technique was executed during a red team exercise and was NOT detected by the blue team. We need rules to detect this in the future.
${test.notes ? `- Execution notes: ${test.notes}` : ""}
${test.executionResult ? `- Execution result: ${test.executionResult}` : ""}

Generate rules in these formats: ${input.formats.join(", ")}

Return JSON with keys matching the format names. Each value should be the complete rule as a string.`
              }
            ],
            response_format: {
              type: "json_schema",
              json_schema: {
                name: "detection_rules",
                strict: true,
                schema: {
                  type: "object",
                  properties: {
                    sigma: { type: "string", description: "Sigma rule in YAML format" },
                    splunk_spl: { type: "string", description: "Splunk SPL query" },
                    kql: { type: "string", description: "KQL query for Microsoft Sentinel/Defender" },
                  },
                  required: ["sigma", "splunk_spl", "kql"],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = response.choices?.[0]?.message?.content;
          if (content && typeof content === "string") {
            const parsed = JSON.parse(content);
            for (const fmt of input.formats) {
              if (parsed[fmt]) rules[fmt] = parsed[fmt];
            }
          }
        } catch (err) {
          // Fallback to templates if LLM fails
          console.error("[DetectionRules] LLM generation failed, using templates:", err);
        }
      }

      // Fill in any missing formats with templates
      for (const fmt of input.formats) {
        if (!rules[fmt]) {
          switch (fmt) {
            case "sigma":
              rules[fmt] = buildSigmaTemplate(techniqueId, techniqueName, tactic);
              break;
            case "splunk_spl":
              rules[fmt] = buildSplunkTemplate(techniqueId, techniqueName, tactic);
              break;
            case "kql":
              rules[fmt] = buildKqlTemplate(techniqueId, techniqueName, tactic);
              break;
          }
        }
      }

      return {
        testId: input.testId,
        techniqueId,
        techniqueName,
        tactic,
        rules,
        generatedAt: Date.now(),
        usedLLM: input.useLLM,
      };
    }),

  // ─── Bulk generate rules for all gaps ───
  generateForGaps: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
      format: z.enum(RULE_FORMATS).default("sigma"),
      limit: z.number().min(1).max(50).default(20),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [eq(detectionTests.isGap, true)];
      if (input.engagementId) filters.push(eq(detectionTests.engagementId, input.engagementId));

      const gaps = await db.select().from(detectionTests)
        .where(and(...filters))
        .limit(input.limit);

      if (gaps.length === 0) {
        return { rules: [], totalGaps: 0 };
      }

      // Generate rules using LLM for all gaps in one batch
      const techniqueList = gaps.map(g =>
        `${g.techniqueId} - ${g.techniqueName || g.techniqueId} (${g.tactic || "unknown"})`
      ).join("\n");

      let batchRules: Record<string, string> = {};

      try {
        const response = await invokeLLM({
          messages: [
            {
              role: "system",
              content: `You are a SIEM detection engineering expert. Generate ${input.format} detection rules for multiple MITRE ATT&CK techniques that were not detected during a red team exercise. Return ONLY valid JSON where each key is the technique ID and the value is the complete rule.`
            },
            {
              role: "user",
              content: `Generate ${input.format} detection rules for these undetected techniques:\n${techniqueList}\n\nReturn JSON with technique IDs as keys and complete ${input.format} rules as string values.`
            }
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "batch_rules",
              strict: false,
              schema: {
                type: "object",
                additionalProperties: { type: "string" },
              },
            },
          },
        });

        const content = response.choices?.[0]?.message?.content;
        if (content && typeof content === "string") {
          batchRules = JSON.parse(content);
        }
      } catch (err) {
        console.error("[DetectionRules] Batch LLM generation failed:", err);
      }

      // Build results with fallback templates
      const results = gaps.map(gap => {
        const techniqueId = gap.techniqueId;
        const techniqueName = gap.techniqueName || techniqueId;
        const tactic = gap.tactic || "unknown";

        let rule = batchRules[techniqueId] || "";
        if (!rule) {
          switch (input.format) {
            case "sigma":
              rule = buildSigmaTemplate(techniqueId, techniqueName, tactic);
              break;
            case "splunk_spl":
              rule = buildSplunkTemplate(techniqueId, techniqueName, tactic);
              break;
            case "kql":
              rule = buildKqlTemplate(techniqueId, techniqueName, tactic);
              break;
          }
        }

        return {
          testId: gap.testId,
          techniqueId,
          techniqueName,
          tactic,
          rule,
          format: input.format,
        };
      });

      return {
        rules: results,
        totalGaps: gaps.length,
        format: input.format,
        generatedAt: Date.now(),
      };
    }),

  // ─── Get available gap count for rule generation ───
  gapCount: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [eq(detectionTests.isGap, true)];
      if (input?.engagementId) filters.push(eq(detectionTests.engagementId, input.engagementId));

      const [result] = await db.select({ count: sql<number>`count(*)` })
        .from(detectionTests)
        .where(and(...filters));

      return { count: Number(result?.count ?? 0) };
    }),
});
