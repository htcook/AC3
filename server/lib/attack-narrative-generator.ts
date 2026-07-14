/**
 * Attack Narrative Generator
 * 
 * Produces professional, evidence-backed kill chain narratives from engagement
 * findings. Each narrative follows the structure used by commercial pentest
 * reports (Cobalt, Pentera, NodeZero):
 * 
 * 1. Attack Path Summary — high-level kill chain description
 * 2. Step-by-Step Walkthrough — each step with tool, command, evidence
 * 3. Business Impact Assessment — what an attacker could achieve
 * 4. Remediation Priority — ordered fix recommendations with effort estimates
 * 
 * Narratives are generated per-finding and per-attack-chain (multi-step exploits).
 */

import { invokeLLM } from "../_core/llm";

export interface AttackStep {
  stepNumber: number;
  phase: string; // recon | enumeration | vuln_detection | exploitation | post_exploitation
  tool: string;
  command?: string;
  target: string;
  finding: string;
  evidence: string; // raw tool output or HTTP capture
  screenshotPath?: string;
  timestamp?: number;
}

export interface AttackNarrative {
  id: string;
  engagementId: number;
  title: string;
  severity: string;
  attackPath: string; // high-level kill chain summary
  steps: AttackStep[];
  businessImpact: string;
  technicalImpact: string;
  remediationSteps: Array<{
    priority: number;
    action: string;
    effort: 'low' | 'medium' | 'high';
    timeEstimate: string;
  }>;
  affectedAssets: string[];
  mitreTechniques: string[];
  cvssScore?: number;
  generatedAt: number;
}

export interface NarrativeInput {
  engagementId: number;
  engagementName: string;
  targetProfile?: {
    orgName?: string;
    orgSource?: string; // 'whois' | 'engagement_config' | 'inferred'
    industry?: string;
    waf?: string;
    cdn?: string;
    techStack?: string[];
  };
  assets: Array<{
    hostname: string;
    ip?: string;
    ports?: Array<{ port: number; service: string }>;
    vulns: Array<{
      id?: string;
      title: string;
      severity: string;
      description?: string;
      tool?: string;
      cve?: string;
      endpoint?: string;
      rawEvidence?: string;
      corroborationTier?: string;
      screenshotPath?: string;
    }>;
    exploitAttempts?: Array<{
      id?: string;
      technique: string;
      tool: string;
      command?: string;
      succeeded: boolean;
      rawEvidence?: string;
      target?: string;
    }>;
    toolResults?: Array<{
      tool: string;
      command?: string;
      output?: string;
      exitCode?: number;
      findingCount?: number;
    }>;
  }>;
}

/**
 * Generate attack narratives for all significant findings in an engagement.
 * Groups related findings into attack chains where possible.
 */
export async function generateAttackNarratives(
  input: NarrativeInput
): Promise<AttackNarrative[]> {
  const narratives: AttackNarrative[] = [];

  // Collect all findings with evidence
  const allFindings: Array<{
    asset: string;
    vuln: NarrativeInput['assets'][0]['vulns'][0];
    exploits: NarrativeInput['assets'][0]['exploitAttempts'];
    toolResults: NarrativeInput['assets'][0]['toolResults'];
  }> = [];

  for (const asset of input.assets) {
    const evidencedVulns = (asset.vulns || []).filter(v =>
      v.rawEvidence || v.corroborationTier === 'confirmed' || v.screenshotPath
    );
    for (const vuln of evidencedVulns) {
      allFindings.push({
        asset: asset.hostname || asset.ip || 'unknown',
        vuln,
        exploits: (asset.exploitAttempts || []).filter(e =>
          e.target?.includes(vuln.endpoint || '') || e.technique?.includes(vuln.title || '')
        ),
        toolResults: asset.toolResults || [],
      });
    }
  }

  // Sort by severity for prioritized narrative generation
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  allFindings.sort((a, b) =>
    (severityOrder[b.vuln.severity?.toLowerCase()] || 0) - (severityOrder[a.vuln.severity?.toLowerCase()] || 0)
  );

  // Generate narratives for top findings (limit to 20 to manage LLM costs)
  const topFindings = allFindings.slice(0, 20);

  // Batch findings by severity for efficient LLM calls
  const criticalHighFindings = topFindings.filter(f =>
    f.vuln.severity === 'critical' || f.vuln.severity === 'high'
  );
  const mediumFindings = topFindings.filter(f => f.vuln.severity === 'medium');

  // Generate detailed narratives for critical/high findings
  for (const finding of criticalHighFindings) {
    try {
      const narrative = await generateSingleNarrative(input, finding);
      if (narrative) narratives.push(narrative);
    } catch (err: any) {
      console.warn(`[AttackNarrative] Failed for ${finding.vuln.title}:`, err.message);
    }
  }

  // Generate batch narratives for medium findings
  if (mediumFindings.length > 0) {
    try {
      const batchNarratives = await generateBatchNarratives(input, mediumFindings);
      narratives.push(...batchNarratives);
    } catch (err: any) {
      console.warn('[AttackNarrative] Batch generation failed:', err.message);
    }
  }

  return narratives;
}

/**
 * Generate a detailed narrative for a single critical/high finding.
 */
async function generateSingleNarrative(
  input: NarrativeInput,
  finding: {
    asset: string;
    vuln: NarrativeInput['assets'][0]['vulns'][0];
    exploits: NarrativeInput['assets'][0]['exploitAttempts'];
    toolResults: NarrativeInput['assets'][0]['toolResults'];
  }
): Promise<AttackNarrative | null> {
  const evidenceContext = [
    `## Finding: ${finding.vuln.title}`,
    `Severity: ${finding.vuln.severity}`,
    `Asset: ${finding.asset}`,
    finding.vuln.cve ? `CVE: ${finding.vuln.cve}` : '',
    finding.vuln.endpoint ? `Endpoint: ${finding.vuln.endpoint}` : '',
    finding.vuln.tool ? `Detected by: ${finding.vuln.tool}` : '',
    finding.vuln.description ? `Description: ${finding.vuln.description}` : '',
    '',
    '## Raw Evidence:',
    finding.vuln.rawEvidence?.slice(0, 2000) || 'No raw evidence captured',
    '',
    finding.exploits && finding.exploits.length > 0 ? [
      '## Exploit Attempts:',
      ...finding.exploits.map(e =>
        `- ${e.technique} via ${e.tool}: ${e.succeeded ? 'SUCCEEDED' : 'FAILED'}${e.rawEvidence ? `\n  Evidence: ${e.rawEvidence.slice(0, 500)}` : ''}`
      ),
    ].join('\n') : '',
    '',
    finding.toolResults && finding.toolResults.length > 0 ? [
      '## Related Tool Results:',
      ...finding.toolResults.slice(0, 5).map(tr =>
        `- ${tr.tool}: ${tr.findingCount || 0} findings (exit: ${tr.exitCode})`
      ),
    ].join('\n') : '',
  ].filter(Boolean).join('\n');

  const targetContext = input.targetProfile ? [
    input.targetProfile.orgName ? `Organization: ${input.targetProfile.orgName} (source: ${input.targetProfile.orgSource || 'unknown'})` : '',
    `Industry: ${input.targetProfile.industry || 'Unknown (DO NOT infer sector from hostnames — "grid" in a hostname does NOT mean utilities/energy)'}`,
    input.targetProfile.waf ? `WAF: ${input.targetProfile.waf}` : '',
    input.targetProfile.cdn ? `CDN: ${input.targetProfile.cdn}` : '',
    input.targetProfile.techStack?.length ? `Tech Stack: ${input.targetProfile.techStack.join(', ')}` : '',
  ].filter(Boolean).join(' | ') : '';

  try {
     const response = await invokeLLM({
      _caller: 'attack-narrative-generator:generateNarrative',
      messages: [
        {
          role: 'system',
          content: `You are an expert penetration tester writing detailed attack narratives for a pentest report. Your narratives must be:
1. Evidence-based — every claim must reference specific tool output or captured data
2. Technically precise — include exact commands, endpoints, parameters, and responses
3. Business-relevant — explain what an attacker could achieve and the real-world impact
4. Actionable — provide specific, prioritized remediation steps with effort estimates

Write in a professional but direct style. No filler text. Every sentence must add value.

Target context: ${targetContext}`,
        },
        {
          role: 'user',
          content: `Generate a detailed attack narrative for this finding. Return valid JSON matching this schema:
{
  "title": "string - concise attack path title",
  "attackPath": "string - 2-3 sentence kill chain summary",
  "businessImpact": "string - what an attacker could achieve in business terms",
  "technicalImpact": "string - technical consequences (data access, system control, etc.)",
  "steps": [
    {
      "stepNumber": 1,
      "phase": "recon|enumeration|vuln_detection|exploitation|post_exploitation",
      "tool": "string",
      "command": "string or null",
      "target": "string",
      "finding": "string - what was discovered",
      "evidence": "string - specific evidence from tool output"
    }
  ],
  "remediationSteps": [
    {
      "priority": 1,
      "action": "string - specific fix",
      "effort": "low|medium|high",
      "timeEstimate": "string - e.g. '2 hours', '1 day'"
    }
  ],
  "mitreTechniques": ["T1190", "T1059", etc.],
  // IMPORTANT: Use correct MITRE ATT&CK technique IDs. Common mappings:
  // - Credential brute force: T1110.001 (Password Guessing)
  // - Default credentials: T1078.001 (Valid Accounts: Default Accounts)
  // - Open/external redirect: T1204.001 (User Execution: Malicious Link)
  // - SQL injection: T1190 (Exploit Public-Facing Application)
  // - XSS: T1059.007 (Command and Scripting Interpreter: JavaScript)
  // - SSRF: T1090 (Proxy) or T1190
  // - DO NOT use T1182 (deprecated - was AppInit DLLs, now T1546.010)
  // - DO NOT use T1562 (Impair Defenses) unless finding actually disables security tools
  "cvssScore": number or null
}

Finding data:
${evidenceContext}`,
        },
      ],
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'attack_narrative',
          strict: true,
          schema: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              attackPath: { type: 'string' },
              businessImpact: { type: 'string' },
              technicalImpact: { type: 'string' },
              steps: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    stepNumber: { type: 'integer' },
                    phase: { type: 'string' },
                    tool: { type: 'string' },
                    command: { type: ['string', 'null'] },
                    target: { type: 'string' },
                    finding: { type: 'string' },
                    evidence: { type: 'string' },
                  },
                  required: ['stepNumber', 'phase', 'tool', 'target', 'finding', 'evidence'],
                  additionalProperties: false,
                },
              },
              remediationSteps: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    priority: { type: 'integer' },
                    action: { type: 'string' },
                    effort: { type: 'string' },
                    timeEstimate: { type: 'string' },
                  },
                  required: ['priority', 'action', 'effort', 'timeEstimate'],
                  additionalProperties: false,
                },
              },
              mitreTechniques: { type: 'array', items: { type: 'string' } },
              cvssScore: { type: ['number', 'null'] },
            },
            required: ['title', 'attackPath', 'businessImpact', 'technicalImpact', 'steps', 'remediationSteps', 'mitreTechniques', 'cvssScore'],
            additionalProperties: false,
          },
        },
       },
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = JSON.parse(content);
    return {
      id: `narr-${input.engagementId}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      engagementId: input.engagementId,
      title: parsed.title,
      severity: finding.vuln.severity,
      attackPath: parsed.attackPath,
      steps: parsed.steps.map((s: any) => ({
        ...s,
        screenshotPath: finding.vuln.screenshotPath,
      })),
      businessImpact: parsed.businessImpact,
      technicalImpact: parsed.technicalImpact,
      remediationSteps: parsed.remediationSteps,
      affectedAssets: [finding.asset],
      mitreTechniques: parsed.mitreTechniques || [],
      cvssScore: parsed.cvssScore,
      generatedAt: Date.now(),
    };
  } catch (err: any) {
    console.warn(`[AttackNarrative] LLM generation failed:`, err.message);
    return null;
  }
}

/**
 * Generate batch narratives for medium-severity findings (more efficient).
 */
async function generateBatchNarratives(
  input: NarrativeInput,
  findings: Array<{
    asset: string;
    vuln: NarrativeInput['assets'][0]['vulns'][0];
    exploits: NarrativeInput['assets'][0]['exploitAttempts'];
    toolResults: NarrativeInput['assets'][0]['toolResults'];
  }>
): Promise<AttackNarrative[]> {
  const findingSummaries = findings.map((f, i) => [
    `### Finding ${i + 1}: ${f.vuln.title}`,
    `Severity: ${f.vuln.severity} | Asset: ${f.asset}`,
    f.vuln.cve ? `CVE: ${f.vuln.cve}` : '',
    f.vuln.endpoint ? `Endpoint: ${f.vuln.endpoint}` : '',
    `Evidence: ${(f.vuln.rawEvidence || 'No raw evidence').slice(0, 500)}`,
  ].filter(Boolean).join('\n')).join('\n\n');

  try {
    const response = await invokeLLM({
      _caller: 'attack-narrative-generator:batchNarratives',
      messages: [
        {
          role: 'system',
          content: `You are an expert penetration tester. Generate concise attack narratives for multiple medium-severity findings. Each narrative should include: attack path, business impact, and top remediation action. Return a JSON array.`,
        },
        {
          role: 'user',
          content: `Generate narratives for these ${findings.length} findings. Return JSON array where each element has: title, attackPath, businessImpact, technicalImpact, remediationAction, effort (low/medium/high), mitreTechniques (array of strings).
${findingSummaries}`,
        },
      ],
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return [];

    // Try to parse as JSON array
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return [];

    const parsed = JSON.parse(jsonMatch[0]);
    return parsed.map((n: any, i: number) => ({
      id: `narr-${input.engagementId}-batch-${Date.now()}-${i}`,
      engagementId: input.engagementId,
      title: n.title || findings[i]?.vuln.title || 'Unknown',
      severity: findings[i]?.vuln.severity || 'medium',
      attackPath: n.attackPath || '',
      steps: [],
      businessImpact: n.businessImpact || '',
      technicalImpact: n.technicalImpact || '',
      remediationSteps: [{
        priority: 1,
        action: n.remediationAction || 'Review and patch',
        effort: n.effort || 'medium',
        timeEstimate: n.effort === 'low' ? '1-2 hours' : n.effort === 'high' ? '1-2 days' : '4-8 hours',
      }],
      affectedAssets: [findings[i]?.asset || 'unknown'],
      mitreTechniques: n.mitreTechniques || [],
      generatedAt: Date.now(),
    }));
  } catch (err: any) {
    console.warn('[AttackNarrative] Batch generation failed:', err.message);
    return [];
  }
}

/**
 * Generate an executive summary narrative for the entire engagement.
 */
export async function generateExecutiveSummary(
  input: NarrativeInput & {
    stats: {
      vulnsFound: number;
      verifiedVulns?: number;
      exploitsAttempted: number;
      exploitsSucceeded: number;
      portsFound: number;
    };
    narratives: AttackNarrative[];
  }
): Promise<string> {
  const criticalCount = input.assets.flatMap(a => a.vulns).filter(v => v.severity === 'critical').length;
  const highCount = input.assets.flatMap(a => a.vulns).filter(v => v.severity === 'high').length;

  const topNarratives = input.narratives
    .filter(n => n.severity === 'critical' || n.severity === 'high')
    .slice(0, 5)
    .map(n => `- **${n.title}** (${n.severity}): ${n.attackPath}`)
    .join('\n');

  try {
    const response = await invokeLLM({
      _caller: 'attack-narrative-generator:executiveSummary',
      messages: [
        {
          role: 'system',
          content: `You are a senior penetration testing consultant writing an executive summary for a pentest report. The summary should be 3-5 paragraphs, written for C-level executives and security leadership. Focus on business risk, not technical details. Be direct and specific about what was found and what needs to happen next.

IMPORTANT RULES:
- DO NOT infer the client's industry sector from hostnames (e.g., "grid" does NOT mean utilities/energy, "cdn" does NOT mean media company)
- If industry is "Unknown", write sector-neutral business impact language
- DO NOT claim compliance frameworks were "assessed" — an external scan can only identify "implications for" specific controls
- DO NOT reference HIPAA, NERC CIP, or other sector-specific frameworks unless the industry is explicitly confirmed
- Use qualitative risk language (High/Medium/Low) not precise percentages for threat likelihood`,
        },
        {
          role: 'user',
          content: `Write an executive summary for this penetration test engagement:

Engagement: ${input.engagementName}
Assets tested: ${input.assets.length}
Total vulnerabilities: ${input.stats.vulnsFound} (${input.stats.verifiedVulns || 0} verified with evidence)
Critical: ${criticalCount} | High: ${highCount}
Exploit attempts: ${input.stats.exploitsAttempted} (${input.stats.exploitsSucceeded} succeeded)
Ports discovered: ${input.stats.portsFound}

Top attack paths:
${topNarratives || 'No critical/high attack paths identified'}

Organization: ${input.targetProfile?.orgName || 'Unknown'}
Industry: ${input.targetProfile?.industry || 'Unknown (DO NOT infer from hostnames)'}
WAF/CDN: ${input.targetProfile?.waf || 'None detected'} / ${input.targetProfile?.cdn || 'None detected'}`,
        },
      ],
    });
    return response.choices?.[0]?.message?.content || 'Executive summary generation failed.';
  } catch (err: any) {
    return `Executive summary generation failed: ${err.message}`;
  }
}
