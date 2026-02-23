/**
 * Detection Rules Router
 * 
 * Generates SIEM detection rules (Sigma, Splunk SPL, KQL) from
 * emulation results and detection gaps using LLM or template fallback.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";

const SIGMA_TEMPLATE = (technique: string, name: string) => `title: Detection for ${name} (${technique})
id: auto-generated
status: experimental
level: high
description: Auto-generated detection rule for MITRE ATT&CK technique ${technique}
author: Ace C3 Detection Engine
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
falsepositives:
  - Legitimate administrative activity
tags:
  - attack.${technique.toLowerCase().replace(".", "")}`;

const SPL_TEMPLATE = (technique: string, name: string) =>
  `index=* sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:Sysmon
| where EventCode IN (1, 4688)
| eval technique="${technique}"
| eval technique_name="${name}"
| stats count by host, user, process_name, parent_process_name, technique
| where count > 0
| sort -count`;

const KQL_TEMPLATE = (technique: string, name: string) =>
  `DeviceProcessEvents
| where Timestamp > ago(24h)
| extend TechniqueId = "${technique}"
| extend TechniqueName = "${name}"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, TechniqueId, TechniqueName
| sort by Timestamp desc`;

export const detectionRulesRouter = router({
  generateForTechnique: protectedProcedure
    .input(z.object({
      techniqueId: z.string(),
      techniqueName: z.string(),
      format: z.enum(["sigma", "splunk_spl", "kql", "all"]).default("all"),
      context: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const rules: Record<string, string> = {};

      try {
        const { invokeLLM } = await import("../_core/llm");
        const formats = input.format === "all"
          ? ["sigma", "splunk_spl", "kql"]
          : [input.format];

        for (const fmt of formats) {
          const formatLabel = fmt === "sigma" ? "Sigma YAML" : fmt === "splunk_spl" ? "Splunk SPL" : "KQL (Microsoft Sentinel)";
          const response = await invokeLLM({
            messages: [
              { role: "system", content: `You are an expert SIEM detection engineer. Generate a production-ready ${formatLabel} detection rule for the given MITRE ATT&CK technique. Output ONLY the rule content, no explanations or markdown fences.` },
              { role: "user", content: `Generate a ${formatLabel} detection rule for:\n- Technique: ${input.techniqueId} - ${input.techniqueName}\n${input.context ? `- Additional context: ${input.context}` : ""}` },
            ],
          });
          const content = response?.choices?.[0]?.message?.content;
          rules[fmt] = typeof content === "string" ? content.trim() : getFallbackRule(fmt, input.techniqueId, input.techniqueName);
        }
      } catch {
        if (input.format === "all" || input.format === "sigma") rules.sigma = SIGMA_TEMPLATE(input.techniqueId, input.techniqueName);
        if (input.format === "all" || input.format === "splunk_spl") rules.splunk_spl = SPL_TEMPLATE(input.techniqueId, input.techniqueName);
        if (input.format === "all" || input.format === "kql") rules.kql = KQL_TEMPLATE(input.techniqueId, input.techniqueName);
      }

      return {
        techniqueId: input.techniqueId,
        techniqueName: input.techniqueName,
        rules,
        generatedAt: new Date().toISOString(),
        method: Object.keys(rules).length > 0 ? "llm" : "template",
      };
    }),

  generateBulk: protectedProcedure
    .input(z.object({
      techniques: z.array(z.object({ id: z.string(), name: z.string() })),
      format: z.enum(["sigma", "splunk_spl", "kql"]).default("sigma"),
    }))
    .mutation(async ({ input }) => {
      const results: Array<{ techniqueId: string; techniqueName: string; rule: string }> = [];
      for (const tech of input.techniques) {
        try {
          const { invokeLLM } = await import("../_core/llm");
          const formatLabel = input.format === "sigma" ? "Sigma YAML" : input.format === "splunk_spl" ? "Splunk SPL" : "KQL";
          const response = await invokeLLM({
            messages: [
              { role: "system", content: `You are an expert SIEM detection engineer. Generate a production-ready ${formatLabel} detection rule. Output ONLY the rule content.` },
              { role: "user", content: `Generate a ${formatLabel} detection rule for: ${tech.id} - ${tech.name}` },
            ],
          });
          const content = response?.choices?.[0]?.message?.content;
          results.push({ techniqueId: tech.id, techniqueName: tech.name, rule: typeof content === "string" ? content.trim() : getFallbackRule(input.format, tech.id, tech.name) });
        } catch {
          results.push({ techniqueId: tech.id, techniqueName: tech.name, rule: getFallbackRule(input.format, tech.id, tech.name) });
        }
      }
      return { format: input.format, rules: results, generatedAt: new Date().toISOString(), totalGenerated: results.length };
    }),

  listSaved: protectedProcedure.query(async () => []),
});

function getFallbackRule(format: string, techniqueId: string, techniqueName: string): string {
  switch (format) {
    case "sigma": return SIGMA_TEMPLATE(techniqueId, techniqueName);
    case "splunk_spl": return SPL_TEMPLATE(techniqueId, techniqueName);
    case "kql": return KQL_TEMPLATE(techniqueId, techniqueName);
    default: return SIGMA_TEMPLATE(techniqueId, techniqueName);
  }
}
