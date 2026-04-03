/**
 * ScanForge Enhanced Exploitation Pipeline
 * ═════════════════════════════════════════
 * Unified integration layer that wires the 10 gap analysis modules
 * into the existing ScanForge exploitation flow.
 *
 * This module provides a single entry point for enhanced exploit execution
 * that applies all gap improvements in the correct order:
 *
 *   Pre-execution:
 *     Gap 9  — Quality scoring & validation
 *     Gap 6  — Dependency resolution
 *     Gap 5  — Bug bounty safe mode filtering
 *     Gap 8  — Vuln class template enrichment
 *     Gap 10 — External exploit DB enrichment
 *     Gap 2  — Payload encoding & WAF evasion
 *     Gap 7  — Stealth controls (rate limiting, timing)
 *
 *   Execution:
 *     Gap 3  — Iterative exploitation loop (retry with adaptation)
 *     Gap 1  — Exploit success verification
 *
 *   Post-execution:
 *     Gap 4  — Exploit chain planning (next steps)
 *     Gap 1  — Evidence collection & verification
 */

import { scoreExploit, quickValidate, generateQualityReport } from './exploit-quality-scorer';
import type { ExploitInput, ExploitQualityScore } from './exploit-quality-scorer';
import { verifyExploitSuccess, collectEvidence } from './exploit-verification-engine';
import type { VerificationResult } from './exploit-verification-engine';
import { encodePayload, selectEvasionStrategy, applyWafEvasion } from './payload-encoding-engine';
import type { EncodingResult, EvasionStrategy } from './payload-encoding-engine';
import { createIterativeLoop, IterativeExploitLoop } from './iterative-exploit-loop';
import type { IterationResult, IterativeConfig } from './iterative-exploit-loop';
import { planExploitChain, ExploitChainPlanner } from './exploit-chain-planner';
import type { ExploitChain, ChainStep } from './exploit-chain-planner';
import { BugBountySafeMode, createSafeMode } from './bug-bounty-safe-mode';
import type { SafeModeConfig, SafetyCheckResult } from './bug-bounty-safe-mode';
import { resolveDependencies, checkDependencies } from './exploit-dependency-manager';
import type { DependencyManifest, DependencyCheckResult } from './exploit-dependency-manager';
import { StealthController, createStealthController } from './stealth-controls';
import type { StealthConfig, StealthDecision } from './stealth-controls';
import { generateTemplateContext, getTemplate } from './vuln-class-templates';
import type { ExploitTemplate } from './vuln-class-templates';
import { enrichVulnerability, quickCveLookup } from './external-exploit-db';
import type { ExploitEnrichment } from './external-exploit-db';

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface EnhancedExploitRequest {
  /** Exploit code */
  code: string;
  /** Language */
  language: 'bash' | 'python' | 'ruby' | 'powershell' | 'curl' | 'raw_http';
  /** Target host */
  targetHost: string;
  /** Target port */
  targetPort?: number;
  /** Vulnerability class (sqli, xss, ssrf, cmdi, ssti, lfi, etc.) */
  vulnClass?: string;
  /** CVE ID if known */
  cveId?: string;
  /** Engagement ID for DB persistence */
  engagementId: number;
  /** Exploit ID */
  exploitId: string;

  // ── Enhancement Options ──
  /** Enable bug bounty safe mode */
  bugBountySafeMode?: boolean;
  /** Bug bounty program rules */
  bugBountyRules?: SafeModeConfig;
  /** Enable WAF evasion */
  enableWafEvasion?: boolean;
  /** Detected WAF type */
  detectedWaf?: string;
  /** Enable iterative exploitation (retry with adaptation) */
  enableIterative?: boolean;
  /** Max iterations for iterative loop */
  maxIterations?: number;
  /** Enable exploit chaining */
  enableChaining?: boolean;
  /** Enable stealth controls */
  enableStealth?: boolean;
  /** Stealth configuration */
  stealthConfig?: Partial<StealthConfig>;
  /** Enable external exploit DB enrichment */
  enableExternalEnrichment?: boolean;
  /** Enable quality scoring (always recommended) */
  enableQualityScoring?: boolean;
  /** Minimum quality score to proceed (0-100) */
  minQualityScore?: number;
  /** Timeout per execution attempt */
  timeoutSeconds?: number;
  /** Dry run mode */
  dryRun?: boolean;
  /** Expected outcome description */
  expectedOutcome?: string;
}

export interface EnhancedExploitResult {
  /** Overall status */
  status: 'success' | 'partial' | 'failed' | 'blocked' | 'skipped';
  /** Quality score (if scoring enabled) */
  qualityScore?: ExploitQualityScore;
  /** Quality report (human-readable) */
  qualityReport?: string;
  /** Safety check result (if safe mode enabled) */
  safetyCheck?: SafetyCheckResult;
  /** WAF evasion applied */
  evasionApplied?: EvasionStrategy;
  /** Encoding result */
  encodingResult?: EncodingResult;
  /** Stealth decision */
  stealthDecision?: StealthDecision;
  /** External enrichment data */
  enrichment?: ExploitEnrichment;
  /** Template context used */
  templateContext?: string;
  /** Verification result */
  verification?: VerificationResult;
  /** Iteration results (if iterative enabled) */
  iterations?: IterationResult[];
  /** Exploit chain plan (if chaining enabled) */
  chainPlan?: ExploitChain;
  /** Final exploit code (after all transformations) */
  finalCode: string;
  /** Execution output */
  stdout: string;
  stderr: string;
  exitCode: number;
  /** Duration */
  durationMs: number;
  /** Pipeline stages completed */
  pipelineStages: PipelineStage[];
  /** Errors encountered */
  errors: PipelineError[];
}

export interface PipelineStage {
  name: string;
  status: 'completed' | 'skipped' | 'failed';
  durationMs: number;
  details?: string;
}

export interface PipelineError {
  stage: string;
  message: string;
  recoverable: boolean;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — ENHANCED PIPELINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Execute an exploit through the enhanced ScanForge pipeline.
 * Applies all gap analysis improvements in the correct order.
 */
export async function executeEnhancedExploit(
  request: EnhancedExploitRequest,
): Promise<EnhancedExploitResult> {
  const startTime = Date.now();
  const stages: PipelineStage[] = [];
  const errors: PipelineError[] = [];
  let currentCode = request.code;

  const result: Partial<EnhancedExploitResult> = {
    finalCode: currentCode,
    stdout: '',
    stderr: '',
    exitCode: -1,
    pipelineStages: stages,
    errors,
  };

  console.log(`[EnhancedPipeline] Starting enhanced exploit execution: ${request.exploitId}`);
  console.log(`[EnhancedPipeline] Options: safeMode=${request.bugBountySafeMode}, wafEvasion=${request.enableWafEvasion}, iterative=${request.enableIterative}, stealth=${request.enableStealth}`);

  // ── Stage 1: Quality Scoring (Gap 9) ──────────────────────────────
  if (request.enableQualityScoring !== false) {
    const stageStart = Date.now();
    try {
      const exploitInput: ExploitInput = {
        code: currentCode,
        language: request.language === 'curl' || request.language === 'raw_http'
          ? request.language
          : request.language as any,
        vulnClass: request.vulnClass,
        target: `${request.targetHost}${request.targetPort ? ':' + request.targetPort : ''}`,
        isBugBounty: request.bugBountySafeMode,
        safeMode: request.bugBountySafeMode,
        expectedOutcome: request.expectedOutcome,
      };

      const qualityScore = scoreExploit(exploitInput);
      result.qualityScore = qualityScore;
      result.qualityReport = generateQualityReport(qualityScore);

      const minScore = request.minQualityScore || 30;
      if (qualityScore.overall < minScore) {
        stages.push({ name: 'quality-scoring', status: 'failed', durationMs: Date.now() - stageStart, details: `Score ${qualityScore.overall} below minimum ${minScore}` });
        return {
          ...result,
          status: 'blocked',
          finalCode: currentCode,
          stdout: '',
          stderr: `Exploit quality score (${qualityScore.overall}) below minimum threshold (${minScore}). ${qualityScore.suggestions.join('; ')}`,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          pipelineStages: stages,
          errors: [{ stage: 'quality-scoring', message: `Score ${qualityScore.overall} < ${minScore}`, recoverable: true }],
        } as EnhancedExploitResult;
      }

      if (!qualityScore.executeRecommendation) {
        console.warn(`[EnhancedPipeline] Quality scorer does not recommend execution (score: ${qualityScore.overall}, verdict: ${qualityScore.verdict})`);
      }

      stages.push({ name: 'quality-scoring', status: 'completed', durationMs: Date.now() - stageStart, details: `Score: ${qualityScore.overall}/100 [${qualityScore.verdict}]` });
    } catch (err: any) {
      errors.push({ stage: 'quality-scoring', message: err.message, recoverable: true });
      stages.push({ name: 'quality-scoring', status: 'failed', durationMs: Date.now() - stageStart });
    }
  }

  // ── Stage 2: Bug Bounty Safe Mode (Gap 5) ─────────────────────────
  if (request.bugBountySafeMode) {
    const stageStart = Date.now();
    try {
      const safeMode = createSafeMode(request.bugBountyRules || {
        programName: 'default',
        scope: { inScope: [request.targetHost], outOfScope: [] },
        maxSeverity: 'critical',
        allowedActions: ['read', 'enumerate', 'exploit_poc'],
        prohibitedActions: ['data_destruction', 'service_disruption', 'lateral_movement'],
      });

      const safetyCheck = safeMode.checkExploit(currentCode, request.vulnClass || 'unknown');
      result.safetyCheck = safetyCheck;

      if (!safetyCheck.safe) {
        stages.push({ name: 'bug-bounty-safe-mode', status: 'failed', durationMs: Date.now() - stageStart, details: `Blocked: ${safetyCheck.violations.join('; ')}` });
        return {
          ...result,
          status: 'blocked',
          finalCode: currentCode,
          stdout: '',
          stderr: `Bug bounty safe mode blocked execution: ${safetyCheck.violations.join('; ')}`,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          pipelineStages: stages,
          errors: [{ stage: 'bug-bounty-safe-mode', message: safetyCheck.violations.join('; '), recoverable: false }],
        } as EnhancedExploitResult;
      }

      stages.push({ name: 'bug-bounty-safe-mode', status: 'completed', durationMs: Date.now() - stageStart, details: 'Passed safety checks' });
    } catch (err: any) {
      errors.push({ stage: 'bug-bounty-safe-mode', message: err.message, recoverable: true });
      stages.push({ name: 'bug-bounty-safe-mode', status: 'failed', durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: 'bug-bounty-safe-mode', status: 'skipped', durationMs: 0 });
  }

  // ── Stage 3: External Enrichment (Gap 10) ─────────────────────────
  if (request.enableExternalEnrichment && request.cveId) {
    const stageStart = Date.now();
    try {
      const enrichment = await enrichVulnerability({ cveId: request.cveId, vulnType: request.vulnClass });
      result.enrichment = enrichment;
      stages.push({ name: 'external-enrichment', status: 'completed', durationMs: Date.now() - stageStart, details: `Maturity: ${enrichment.maturityAssessment.level}, KEV: ${enrichment.kevStatus?.isKnownExploited || false}` });
    } catch (err: any) {
      errors.push({ stage: 'external-enrichment', message: err.message, recoverable: true });
      stages.push({ name: 'external-enrichment', status: 'failed', durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: 'external-enrichment', status: 'skipped', durationMs: 0 });
  }

  // ── Stage 4: Vuln Class Template Context (Gap 8) ──────────────────
  if (request.vulnClass) {
    const stageStart = Date.now();
    try {
      const templateContext = generateTemplateContext(request.vulnClass, 'exploitation');
      result.templateContext = templateContext;
      stages.push({ name: 'vuln-template-context', status: 'completed', durationMs: Date.now() - stageStart, details: `Template loaded for ${request.vulnClass}` });
    } catch (err: any) {
      errors.push({ stage: 'vuln-template-context', message: err.message, recoverable: true });
      stages.push({ name: 'vuln-template-context', status: 'failed', durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: 'vuln-template-context', status: 'skipped', durationMs: 0 });
  }

  // ── Stage 5: Dependency Resolution (Gap 6) ────────────────────────
  {
    const stageStart = Date.now();
    try {
      const depCheck = await checkDependencies(currentCode, request.language);
      if (!depCheck.satisfied) {
        console.log(`[EnhancedPipeline] Resolving ${depCheck.missing.length} missing dependencies`);
        await resolveDependencies(depCheck.missing, request.language);
      }
      stages.push({ name: 'dependency-resolution', status: 'completed', durationMs: Date.now() - stageStart, details: depCheck.satisfied ? 'All deps satisfied' : `Resolved ${depCheck.missing.length} deps` });
    } catch (err: any) {
      errors.push({ stage: 'dependency-resolution', message: err.message, recoverable: true });
      stages.push({ name: 'dependency-resolution', status: 'failed', durationMs: Date.now() - stageStart });
    }
  }

  // ── Stage 6: WAF Evasion & Payload Encoding (Gap 2) ───────────────
  if (request.enableWafEvasion && request.detectedWaf) {
    const stageStart = Date.now();
    try {
      const evasionStrategy = selectEvasionStrategy(request.detectedWaf, request.vulnClass || 'generic');
      result.evasionApplied = evasionStrategy;

      const encoded = applyWafEvasion(currentCode, evasionStrategy);
      if (encoded.success) {
        currentCode = encoded.encodedPayload;
        result.encodingResult = encoded;
      }

      stages.push({ name: 'waf-evasion', status: 'completed', durationMs: Date.now() - stageStart, details: `Strategy: ${evasionStrategy.name}, WAF: ${request.detectedWaf}` });
    } catch (err: any) {
      errors.push({ stage: 'waf-evasion', message: err.message, recoverable: true });
      stages.push({ name: 'waf-evasion', status: 'failed', durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: 'waf-evasion', status: 'skipped', durationMs: 0 });
  }

  // ── Stage 7: Stealth Controls (Gap 7) ─────────────────────────────
  if (request.enableStealth) {
    const stageStart = Date.now();
    try {
      const stealthController = createStealthController(request.stealthConfig || {});
      const decision = stealthController.evaluate(request.targetHost, request.vulnClass || 'generic');
      result.stealthDecision = decision;

      if (decision.shouldDelay && decision.delayMs > 0) {
        console.log(`[EnhancedPipeline] Stealth delay: ${decision.delayMs}ms`);
        await new Promise(resolve => setTimeout(resolve, decision.delayMs));
      }

      stages.push({ name: 'stealth-controls', status: 'completed', durationMs: Date.now() - stageStart, details: `Delay: ${decision.delayMs}ms, Risk: ${decision.detectionRisk}` });
    } catch (err: any) {
      errors.push({ stage: 'stealth-controls', message: err.message, recoverable: true });
      stages.push({ name: 'stealth-controls', status: 'failed', durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: 'stealth-controls', status: 'skipped', durationMs: 0 });
  }

  // ── Stage 8: Execution (Gap 3 — Iterative Loop) ───────────────────
  result.finalCode = currentCode;

  const executionStart = Date.now();
  try {
    if (request.enableIterative && request.maxIterations && request.maxIterations > 1) {
      // Use iterative exploitation loop
      const iterativeConfig: IterativeConfig = {
        maxIterations: request.maxIterations,
        adaptOnFailure: true,
        vulnClass: request.vulnClass,
        targetHost: request.targetHost,
        targetPort: request.targetPort,
      };

      const loop = createIterativeLoop(iterativeConfig);
      const iterResult = await loop.execute(currentCode, request.language, request.engagementId, request.exploitId, request.timeoutSeconds);

      result.iterations = iterResult.iterations;
      result.stdout = iterResult.finalResult?.stdout || '';
      result.stderr = iterResult.finalResult?.stderr || '';
      result.exitCode = iterResult.finalResult?.exitCode ?? -1;

      if (iterResult.succeeded) {
        currentCode = iterResult.successfulCode || currentCode;
      }

      stages.push({ name: 'iterative-execution', status: iterResult.succeeded ? 'completed' : 'failed', durationMs: Date.now() - executionStart, details: `${iterResult.iterations.length} iterations, success: ${iterResult.succeeded}` });
    } else {
      // Single execution via existing exploit-sandbox
      const { executeExploit } = await import('./exploit-sandbox');
      const execResult = await executeExploit(request.engagementId, {
        exploitId: request.exploitId,
        code: currentCode,
        language: request.language === 'curl' || request.language === 'raw_http' ? 'bash' : request.language,
        targetHost: request.targetHost,
        targetPort: request.targetPort,
        timeoutSeconds: request.timeoutSeconds || 60,
        dryRun: request.dryRun || false,
        vulnerabilityCve: request.cveId,
        exploitModule: request.exploitId,
      });

      result.stdout = execResult.stdout;
      result.stderr = execResult.stderr;
      result.exitCode = execResult.exitCode;

      stages.push({ name: 'single-execution', status: execResult.status === 'success' ? 'completed' : 'failed', durationMs: Date.now() - executionStart, details: `Exit: ${execResult.exitCode}, Status: ${execResult.status}` });
    }
  } catch (err: any) {
    result.stdout = '';
    result.stderr = err.message;
    result.exitCode = -1;
    errors.push({ stage: 'execution', message: err.message, recoverable: false });
    stages.push({ name: 'execution', status: 'failed', durationMs: Date.now() - executionStart });
  }

  // ── Stage 9: Exploit Success Verification (Gap 1) ─────────────────
  {
    const stageStart = Date.now();
    try {
      const verification = await verifyExploitSuccess({
        exploitCode: currentCode,
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        exitCode: result.exitCode || -1,
        vulnClass: request.vulnClass,
        targetHost: request.targetHost,
        targetPort: request.targetPort,
        expectedOutcome: request.expectedOutcome,
      });

      result.verification = verification;
      stages.push({ name: 'success-verification', status: 'completed', durationMs: Date.now() - stageStart, details: `Verified: ${verification.verified}, Confidence: ${verification.confidence}%` });
    } catch (err: any) {
      errors.push({ stage: 'success-verification', message: err.message, recoverable: true });
      stages.push({ name: 'success-verification', status: 'failed', durationMs: Date.now() - stageStart });
    }
  }

  // ── Stage 10: Exploit Chain Planning (Gap 4) ──────────────────────
  if (request.enableChaining && result.exitCode === 0) {
    const stageStart = Date.now();
    try {
      const chainPlan = await planExploitChain({
        currentVuln: request.vulnClass || 'unknown',
        currentAccess: result.verification?.achievedAccess || 'none',
        targetHost: request.targetHost,
        targetPort: request.targetPort,
        exploitOutput: result.stdout || '',
        engagementId: request.engagementId,
      });

      result.chainPlan = chainPlan;
      stages.push({ name: 'chain-planning', status: 'completed', durationMs: Date.now() - stageStart, details: `${chainPlan.steps.length} chain steps planned` });
    } catch (err: any) {
      errors.push({ stage: 'chain-planning', message: err.message, recoverable: true });
      stages.push({ name: 'chain-planning', status: 'failed', durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: 'chain-planning', status: 'skipped', durationMs: 0 });
  }

  // ── Determine overall status ──────────────────────────────────────
  let status: EnhancedExploitResult['status'];
  if (result.exitCode === 0 && result.verification?.verified) {
    status = 'success';
  } else if (result.exitCode === 0) {
    status = 'partial';
  } else if (errors.some(e => !e.recoverable)) {
    status = 'failed';
  } else {
    status = 'failed';
  }

  const totalDuration = Date.now() - startTime;
  console.log(`[EnhancedPipeline] Completed: status=${status}, duration=${totalDuration}ms, stages=${stages.length}, errors=${errors.length}`);

  return {
    ...result,
    status,
    finalCode: currentCode,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    exitCode: result.exitCode ?? -1,
    durationMs: totalDuration,
    pipelineStages: stages,
    errors,
  } as EnhancedExploitResult;
}

/**
 * Generate an LLM prompt enriched with all gap analysis context.
 * Use this when generating new exploits via LLM to include
 * template context, external intelligence, and quality guidelines.
 */
export async function generateEnrichedExploitPrompt(params: {
  vulnClass: string;
  cveId?: string;
  targetHost: string;
  targetPort?: number;
  vulnDescription: string;
  detectedWaf?: string;
  isBugBounty?: boolean;
}): Promise<string> {
  const sections: string[] = [];

  // Vuln class template (Gap 8)
  const templateContext = generateTemplateContext(params.vulnClass, 'all');
  if (templateContext) {
    sections.push(templateContext);
  }

  // External enrichment (Gap 10)
  if (params.cveId) {
    try {
      const enrichment = await enrichVulnerability({ cveId: params.cveId });
      sections.push(enrichment.llmContext);
    } catch {
      // Non-fatal
    }
  }

  // WAF evasion notes (Gap 2)
  if (params.detectedWaf) {
    const template = getTemplate(params.vulnClass);
    if (template) {
      sections.push(`\n=== WAF Evasion Notes (${params.detectedWaf}) ===`);
      sections.push(template.exploitation.wafBypassNotes.join('\n'));
    }
  }

  // Bug bounty constraints (Gap 5)
  if (params.isBugBounty) {
    sections.push('\n=== Bug Bounty Constraints ===');
    sections.push('- DO NOT use destructive payloads');
    sections.push('- DO NOT attempt lateral movement');
    sections.push('- DO NOT exfiltrate real user data');
    sections.push('- Minimize impact to target systems');
    sections.push('- Focus on proof-of-concept demonstration');
    sections.push('- Include cleanup/restoration steps');
  }

  // Quality guidelines (Gap 9)
  sections.push('\n=== Exploit Quality Requirements ===');
  sections.push('- Include error handling and conditional logic');
  sections.push('- Capture output for evidence (save to files, print results)');
  sections.push('- Include timestamps and logging');
  sections.push('- Use encoding/obfuscation for stealth');
  sections.push('- Add verification steps to confirm success');
  sections.push('- Include cleanup/restoration where appropriate');

  return sections.join('\n\n');
}

/**
 * Quick pre-flight check before exploit execution.
 * Returns pass/fail without running the full pipeline.
 */
export function preflightCheck(request: EnhancedExploitRequest): {
  pass: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];

  // Quick quality validation
  const qv = quickValidate({
    code: request.code,
    language: request.language as any,
    vulnClass: request.vulnClass,
    isBugBounty: request.bugBountySafeMode,
    safeMode: request.bugBountySafeMode,
  });

  if (!qv.pass) {
    reasons.push(qv.reason || 'Quality validation failed');
  }

  // Check code length
  if (request.code.trim().length < 10) {
    reasons.push('Exploit code too short');
  }

  // Check target
  if (!request.targetHost) {
    reasons.push('No target host specified');
  }

  return {
    pass: reasons.length === 0,
    reasons,
  };
}
