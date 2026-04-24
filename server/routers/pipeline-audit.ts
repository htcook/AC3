/**
 * Pipeline Audit Router
 *
 * Generates LLM-powered recommendations for improving the exploit pipeline,
 * C2/Caldera handoff, and post-exploitation success rates.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { invokeLLM } from "../_core/llm";
import { readFileSync } from "fs";
import { join } from "path";

// ─── Types ──────────────────────────────────────────────────────────────────
export interface AuditRecommendation {
  id: string;
  category: "exploit_chaining" | "c2_handoff" | "post_exploitation" | "opsec" | "payload_delivery" | "credential_reuse" | "privilege_escalation" | "resilience";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  currentState: string;
  gap: string;
  recommendation: string;
  implementationSteps: string[];
  estimatedEffort: "small" | "medium" | "large";
  impactOnSuccessRate: string;
  relatedModules: string[];
  mitreTechniques: string[];
}

export interface PipelineAuditReport {
  generatedAt: string;
  executiveSummary: string;
  overallMaturityScore: number; // 1-10
  recommendations: AuditRecommendation[];
  architectureDiagram: string; // mermaid diagram
  priorityMatrix: Array<{
    recommendation: string;
    effort: string;
    impact: string;
    priority: number;
  }>;
}

// ─── Architecture Summary Loader ────────────────────────────────────────────
function getArchitectureSummary(): string {
  try {
    return readFileSync(
      join(__dirname, "../lib/exploit-pipeline-architecture.md"),
      "utf-8"
    );
  } catch {
    return "Architecture summary not available. Generate from codebase analysis.";
  }
}

// ─── LLM Prompt ─────────────────────────────────────────────────────────────
const AUDIT_SYSTEM_PROMPT = `You are an elite red team architect and offensive security engineer reviewing a penetration testing platform's exploit pipeline. You have deep expertise in:
- MITRE ATT&CK framework and kill chain methodology
- C2 framework operations (Caldera, Metasploit, Sliver, Cobalt Strike, Empire)
- Exploit development and weaponization
- Post-exploitation tradecraft
- OPSEC and evasion techniques
- Automated attack orchestration

Your task is to analyze the platform's exploit pipeline architecture and provide actionable recommendations to improve exploit and post-exploit success rates during official engagements.

Focus areas:
1. EXPLOIT CHAINING: How findings flow from discovery → exploit selection → execution → validation
2. C2 HANDOFF: How initial access transitions to persistent C2 (Caldera/Sliver/etc.)
3. POST-EXPLOITATION: Automation of post-exploit activities (credential harvesting, lateral movement, persistence)
4. OPSEC: Detection avoidance, traffic blending, artifact cleanup
5. PAYLOAD DELIVERY: Payload generation, staging, and delivery reliability
6. CREDENTIAL REUSE: Automated credential spray, pass-the-hash, Kerberos attacks
7. PRIVILEGE ESCALATION: Automated privesc detection and execution
8. RESILIENCE: Beacon loss recovery, fallback C2 channels, session persistence

For each recommendation, provide:
- Current state assessment
- Specific gap identified
- Detailed implementation recommendation
- Step-by-step implementation plan
- Estimated effort (small/medium/large)
- Expected impact on engagement success rate
- Related MITRE ATT&CK techniques

Be specific and technical. Reference actual module names and functions from the architecture. Do not be vague.`;

// ─── In-Memory Cache ────────────────────────────────────────────────────────
let cachedReport: PipelineAuditReport | null = null;

export const pipelineAuditRouter = router({
  /** Generate a new pipeline audit report */
  generateReport: protectedProcedure
    .input(z.object({
      focusAreas: z.array(z.enum([
        "exploit_chaining", "c2_handoff", "post_exploitation",
        "opsec", "payload_delivery", "credential_reuse",
        "privilege_escalation", "resilience",
      ])).optional(),
      includeArchitectureDiagram: z.boolean().default(true),
    }).optional())
    .mutation(async ({ input }) => {
      const architecture = getArchitectureSummary();
      const focusAreas = input?.focusAreas?.join(", ") || "all areas";

      const userPrompt = `Analyze the following exploit pipeline architecture and generate a comprehensive audit report with specific, actionable recommendations.

FOCUS AREAS: ${focusAreas}

ARCHITECTURE:
${architecture}

Generate your response as a JSON object with this exact structure:
{
  "executiveSummary": "2-3 paragraph executive summary of the pipeline's current state, strengths, and critical gaps",
  "overallMaturityScore": <number 1-10>,
  "recommendations": [
    {
      "id": "REC-001",
      "category": "<one of: exploit_chaining, c2_handoff, post_exploitation, opsec, payload_delivery, credential_reuse, privilege_escalation, resilience>",
      "severity": "<critical|high|medium|low>",
      "title": "Short descriptive title",
      "currentState": "What the platform currently does in this area",
      "gap": "What is missing or broken",
      "recommendation": "Detailed technical recommendation",
      "implementationSteps": ["Step 1", "Step 2", ...],
      "estimatedEffort": "<small|medium|large>",
      "impactOnSuccessRate": "Expected improvement description",
      "relatedModules": ["module-name.ts", ...],
      "mitreTechniques": ["T1234", ...]
    }
  ],
  "architectureDiagram": "Mermaid diagram showing the recommended pipeline flow",
  "priorityMatrix": [
    {"recommendation": "REC-001: title", "effort": "small|medium|large", "impact": "high|medium|low", "priority": <1-10>}
  ]
}

Provide at least 12 specific recommendations covering all focus areas. Be brutally honest about gaps. Reference specific module names and functions.`;

      const response = await invokeLLM({
        messages: [
          { role: "system", content: AUDIT_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "pipeline_audit_report",
            strict: true,
            schema: {
              type: "object",
              properties: {
                executiveSummary: { type: "string" },
                overallMaturityScore: { type: "number" },
                recommendations: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      id: { type: "string" },
                      category: { type: "string" },
                      severity: { type: "string" },
                      title: { type: "string" },
                      currentState: { type: "string" },
                      gap: { type: "string" },
                      recommendation: { type: "string" },
                      implementationSteps: { type: "array", items: { type: "string" } },
                      estimatedEffort: { type: "string" },
                      impactOnSuccessRate: { type: "string" },
                      relatedModules: { type: "array", items: { type: "string" } },
                      mitreTechniques: { type: "array", items: { type: "string" } },
                    },
                    required: ["id", "category", "severity", "title", "currentState", "gap", "recommendation", "implementationSteps", "estimatedEffort", "impactOnSuccessRate", "relatedModules", "mitreTechniques"],
                    additionalProperties: false,
                  },
                },
                architectureDiagram: { type: "string" },
                priorityMatrix: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      recommendation: { type: "string" },
                      effort: { type: "string" },
                      impact: { type: "string" },
                      priority: { type: "number" },
                    },
                    required: ["recommendation", "effort", "impact", "priority"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["executiveSummary", "overallMaturityScore", "recommendations", "architectureDiagram", "priorityMatrix"],
              additionalProperties: false,
            },
          },
        },
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) throw new Error("LLM returned empty response");

      const parsed = JSON.parse(content) as Omit<PipelineAuditReport, "generatedAt">;
      const report: PipelineAuditReport = {
        ...parsed,
        generatedAt: new Date().toISOString(),
      };

      cachedReport = report;
      return report;
    }),

  /** Get the cached report (if available) */
  getCachedReport: protectedProcedure.query(() => {
    return cachedReport;
  }),

  /** Get the raw architecture summary */
  getArchitectureSummary: protectedProcedure.query(() => {
    return getArchitectureSummary();
  }),

  /** Get pipeline module inventory */
  getModuleInventory: protectedProcedure.query(() => {
    return {
      layers: [
        {
          name: "C2 Framework Abstraction",
          modules: [
            { name: "c2-abstraction.ts", loc: 2115, description: "Unified C2 interface across 6 frameworks", frameworks: ["Caldera", "Metasploit", "Sliver", "Empire", "Cobalt Strike", "Manjusaka"] },
            { name: "cobalt-strike-adapter.ts", loc: 734, description: "Cobalt Strike Team Server integration" },
          ],
        },
        {
          name: "Exploit Knowledge",
          modules: [
            { name: "exploit-knowledge-store.ts", loc: 1359, description: "TF-IDF indexed exploit database (3,976+ modules)" },
          ],
        },
        {
          name: "Attack Planning & Chaining",
          modules: [
            { name: "ai-attack-planner.ts", loc: 684, description: "Hybrid graph + LLM attack planning" },
            { name: "attack-chain-validation.ts", loc: 948, description: "Kill chain pattern matching and validation" },
            { name: "attack-sequence-learner.ts", loc: 1208, description: "ML-based attack sequence learning" },
          ],
        },
        {
          name: "Ability Graph Engine",
          modules: [
            { name: "ability-graph-engine.ts", loc: 1457, description: "DAG-based Caldera ability execution" },
          ],
        },
        {
          name: "ScanForge Engine",
          modules: [
            { name: "scan-orchestrator.ts", loc: 762, description: "5-phase scan lifecycle management" },
            { name: "engagement-integration.ts", loc: 814, description: "Finding-to-engagement bridge" },
            { name: "proof-engine.ts", loc: 747, description: "Finding verification engine" },
            { name: "exploit-reasoning-prompts.ts", loc: 801, description: "LLM exploit hypothesis generation" },
            { name: "exploit-reasoning-narratives.ts", loc: 228, description: "Reasoning scenario tracking" },
            { name: "dynamic-attack-mapper.ts", loc: 240, description: "MITRE ATT&CK coverage analysis" },
            { name: "oob-server.ts", loc: 308, description: "Out-of-band interaction server" },
          ],
        },
        {
          name: "Payload & Delivery",
          modules: [
            { name: "payload-generator.ts", loc: 732, description: "msfvenom payload generation via SSH" },
            { name: "agent-installer-generator.ts", loc: 614, description: "Multi-platform agent generation" },
          ],
        },
        {
          name: "Post-Exploitation",
          modules: [
            { name: "post-exploit-playbooks.ts", loc: 508, description: "8 built-in post-exploit playbooks" },
            { name: "lateral-movement.ts", loc: 141, description: "Lateral movement planning" },
            { name: "auto-persistence.ts", loc: 339, description: "Automatic timeline and OPSEC tracking" },
          ],
        },
        {
          name: "Safety & Governance",
          modules: [
            { name: "safety-engine.ts", loc: 169, description: "Phase gating and command assessment" },
            { name: "scan-policy-engine.ts", loc: 1008, description: "60+ tool tier classification" },
          ],
        },
        {
          name: "Agent Definitions",
          modules: [
            { name: "agent-definitions.ts", loc: 1116, description: "OSINT recon agent with evidence classification" },
          ],
        },
      ],
      totalModules: 20,
      totalLOC: 14837,
    };
  }),
});
