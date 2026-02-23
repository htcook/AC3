/**
 * AI-Driven Attack Planning
 * Uses LLM to generate attack sequences based on environment context,
 * threat actor profiles, and available techniques.
 */

export interface AttackPlanRequest {
  targetDescription: string;
  threatActorProfile?: string;
  environmentContext?: {
    operatingSystem?: string[];
    adDomain?: boolean;
    cloudProviders?: string[];
    securityTools?: string[];
    networkSegmentation?: string;
    knownVulnerabilities?: string[];
    crownJewels?: string[];
  };
  constraints?: {
    maxSteps?: number;
    avoidTechniques?: string[];
    stealthLevel?: "low" | "medium" | "high";
    timeConstraint?: string;
  };
}

export interface AttackStep {
  order: number;
  phase: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  description: string;
  prerequisites: string[];
  expectedOutcome: string;
  detectionRisk: "low" | "medium" | "high";
  tools: string[];
  mitigations: string[];
}

export interface AttackPlan {
  name: string;
  summary: string;
  threatActorEmulated: string;
  estimatedRiskScore: number;
  phases: {
    name: string;
    objective: string;
    steps: AttackStep[];
  }[];
  totalSteps: number;
  estimatedDuration: string;
  detectionOpportunities: string[];
  recommendations: string[];
}

const ATTACK_PLANNING_SYSTEM_PROMPT = `You are an expert red team attack planner. Given a target environment description, threat actor profile, and constraints, generate a detailed, realistic attack plan following the MITRE ATT&CK framework.

Your response MUST be valid JSON matching this schema:
{
  "name": "string - descriptive name for the attack plan",
  "summary": "string - 2-3 sentence executive summary",
  "threatActorEmulated": "string - the threat actor being emulated",
  "estimatedRiskScore": "number 1-10",
  "phases": [
    {
      "name": "string - phase name (e.g., Initial Access, Execution, etc.)",
      "objective": "string - what this phase aims to achieve",
      "steps": [
        {
          "order": "number",
          "phase": "string - ATT&CK tactic",
          "techniqueId": "string - e.g., T1566.001",
          "techniqueName": "string - e.g., Spearphishing Attachment",
          "tactic": "string - ATT&CK tactic name",
          "description": "string - detailed step description",
          "prerequisites": ["string array"],
          "expectedOutcome": "string",
          "detectionRisk": "low|medium|high",
          "tools": ["string array - tools to use"],
          "mitigations": ["string array - how defenders can prevent this"]
        }
      ]
    }
  ],
  "totalSteps": "number",
  "estimatedDuration": "string - e.g., 2-3 weeks",
  "detectionOpportunities": ["string array - where blue team can detect"],
  "recommendations": ["string array - defensive recommendations"]
}

Guidelines:
- Use real MITRE ATT&CK technique IDs
- Consider the specific environment (OS, cloud, AD, security tools)
- Adapt to the threat actor's known TTPs if specified
- Respect stealth constraints
- Include realistic tool recommendations
- Provide actionable detection opportunities for the blue team`;

export async function generateAttackPlan(
  request: AttackPlanRequest,
  invokeLLM: Function
): Promise<AttackPlan> {
  const userPrompt = buildUserPrompt(request);

  const response = await invokeLLM({
    messages: [
      { role: "system", content: ATTACK_PLANNING_SYSTEM_PROMPT },
      { role: "user", content: userPrompt },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "attack_plan",
        strict: true,
        schema: {
          type: "object",
          properties: {
            name: { type: "string" },
            summary: { type: "string" },
            threatActorEmulated: { type: "string" },
            estimatedRiskScore: { type: "number" },
            phases: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  objective: { type: "string" },
                  steps: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        order: { type: "number" },
                        phase: { type: "string" },
                        techniqueId: { type: "string" },
                        techniqueName: { type: "string" },
                        tactic: { type: "string" },
                        description: { type: "string" },
                        prerequisites: { type: "array", items: { type: "string" } },
                        expectedOutcome: { type: "string" },
                        detectionRisk: { type: "string" },
                        tools: { type: "array", items: { type: "string" } },
                        mitigations: { type: "array", items: { type: "string" } },
                      },
                      required: ["order", "phase", "techniqueId", "techniqueName", "tactic", "description", "prerequisites", "expectedOutcome", "detectionRisk", "tools", "mitigations"],
                      additionalProperties: false,
                    },
                  },
                },
                required: ["name", "objective", "steps"],
                additionalProperties: false,
              },
            },
            totalSteps: { type: "number" },
            estimatedDuration: { type: "string" },
            detectionOpportunities: { type: "array", items: { type: "string" } },
            recommendations: { type: "array", items: { type: "string" } },
          },
          required: ["name", "summary", "threatActorEmulated", "estimatedRiskScore", "phases", "totalSteps", "estimatedDuration", "detectionOpportunities", "recommendations"],
          additionalProperties: false,
        },
      },
    },
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content) throw new Error("LLM returned empty response");

  return JSON.parse(content) as AttackPlan;
}

function buildUserPrompt(request: AttackPlanRequest): string {
  let prompt = `Generate a detailed attack plan for the following target:\n\n`;
  prompt += `**Target:** ${request.targetDescription}\n\n`;

  if (request.threatActorProfile) {
    prompt += `**Threat Actor Profile:** ${request.threatActorProfile}\n\n`;
  }

  if (request.environmentContext) {
    prompt += `**Environment Context:**\n`;
    const ctx = request.environmentContext;
    if (ctx.operatingSystem?.length) prompt += `- Operating Systems: ${ctx.operatingSystem.join(", ")}\n`;
    if (ctx.adDomain !== undefined) prompt += `- Active Directory: ${ctx.adDomain ? "Yes" : "No"}\n`;
    if (ctx.cloudProviders?.length) prompt += `- Cloud Providers: ${ctx.cloudProviders.join(", ")}\n`;
    if (ctx.securityTools?.length) prompt += `- Security Tools: ${ctx.securityTools.join(", ")}\n`;
    if (ctx.networkSegmentation) prompt += `- Network Segmentation: ${ctx.networkSegmentation}\n`;
    if (ctx.knownVulnerabilities?.length) prompt += `- Known Vulnerabilities: ${ctx.knownVulnerabilities.join(", ")}\n`;
    if (ctx.crownJewels?.length) prompt += `- Crown Jewels: ${ctx.crownJewels.join(", ")}\n`;
    prompt += `\n`;
  }

  if (request.constraints) {
    prompt += `**Constraints:**\n`;
    const c = request.constraints;
    if (c.maxSteps) prompt += `- Maximum ${c.maxSteps} attack steps\n`;
    if (c.avoidTechniques?.length) prompt += `- Avoid techniques: ${c.avoidTechniques.join(", ")}\n`;
    if (c.stealthLevel) prompt += `- Stealth level: ${c.stealthLevel}\n`;
    if (c.timeConstraint) prompt += `- Time constraint: ${c.timeConstraint}\n`;
  }

  return prompt;
}

// Pre-built threat actor profiles for common emulations
export const THREAT_ACTOR_PROFILES: Record<string, string> = {
  apt29: "APT29 (Cozy Bear / The Dukes) - Russian SVR-linked group. Known for spearphishing, supply chain attacks, cloud exploitation, and long-term persistence. Uses custom malware (WellMess, WellMail) and living-off-the-land techniques.",
  apt28: "APT28 (Fancy Bear / Sofacy) - Russian GRU Unit 26165. Known for credential harvesting, zero-day exploitation, and destructive operations. Uses X-Agent, Zebrocy, and OAuth token theft.",
  apt41: "APT41 (Winnti / Double Dragon) - Chinese state-sponsored group. Dual espionage and financial crime. Known for supply chain compromise, rootkits, and extensive use of publicly available tools.",
  lazarus: "Lazarus Group (Hidden Cobra) - North Korean RGB-linked. Known for destructive attacks, cryptocurrency theft, and social engineering. Uses custom malware families and watering hole attacks.",
  fin7: "FIN7 (Carbanak) - Financially motivated group. Known for spearphishing with malicious documents, POS malware, and Cobalt Strike. Targets retail, hospitality, and financial sectors.",
  conti: "Conti Ransomware Group - Known for double extortion, BazarLoader initial access, Cobalt Strike for lateral movement, and rapid encryption. Targets healthcare, manufacturing, and government.",
  alphv: "ALPHV/BlackCat - Ransomware-as-a-Service. Uses Rust-based ransomware, triple extortion, and targets ESXi/Linux. Known for data leak sites and affiliate model.",
};
