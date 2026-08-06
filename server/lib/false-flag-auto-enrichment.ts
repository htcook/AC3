/**
 * False Flag Auto-Enrichment Module
 *
 * Automatically detects and classifies potential false flag operations from
 * ingested advisories, threat reports, and OSINT feeds. Uses pattern matching
 * and LLM-powered analysis to identify deception indicators and generate
 * candidate case library entries for operator review.
 *
 * Integrates with the advisory ingestion scheduler (6h cycle) to continuously
 * monitor for new false flag disclosures.
 */

import { invokeLLM } from "../_core/llm";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AdvisoryReport {
  id: string;
  title: string;
  source: string; // CISA, FBI, NSA, Mandiant, Kaspersky, etc.
  publishDate: number;
  content: string;
  url?: string;
  cves?: string[];
  affectedProducts?: string[];
  attributedActor?: string;
  tags?: string[];
}

export interface FalseFlagCandidate {
  id: string;
  sourceReportId: string;
  sourceReportTitle: string;
  sourceReportUrl?: string;
  detectedAt: number;
  status: "pending_review" | "approved" | "rejected" | "needs_more_data";

  // Detected operation details
  operationName: string;
  year: number;
  description: string;

  // Attribution analysis
  claimedActor: string | null;
  suspectedTrueActor: string | null;
  intendedScapegoat: string | null;

  // Deception techniques detected
  deceptionTechniques: DetectedDeceptionTechnique[];

  // Confidence and evidence
  overallConfidence: number; // 0-100
  evidenceChain: string[];
  contradictions: string[];

  // Classification metadata
  classificationMethod: "pattern_match" | "llm_analysis" | "hybrid";
  patternMatchScore: number;
  llmAnalysisScore: number;

  // For operator review
  analystNotes?: string;
  reviewedBy?: string;
  reviewedAt?: number;
}

export interface DetectedDeceptionTechnique {
  category: string;
  technique: string;
  confidence: number;
  evidence: string;
  historicalPrecedent?: string; // Reference to existing case library entry
}

export interface EnrichmentCycleResult {
  cycleId: string;
  timestamp: number;
  reportsProcessed: number;
  candidatesGenerated: number;
  candidates: FalseFlagCandidate[];
  errors: string[];
  duration: number;
}

export interface EnrichmentStatus {
  lastCycleAt: number | null;
  totalCyclesRun: number;
  totalCandidatesGenerated: number;
  pendingReview: number;
  approved: number;
  rejected: number;
  nextScheduledCycle: number | null;
}

// ─── Pattern Detection ───────────────────────────────────────────────────────

/**
 * Keyword patterns that indicate potential false flag discussion in reports.
 * Grouped by confidence level.
 */
const FALSE_FLAG_INDICATORS = {
  high: [
    /false[\s-]?flag/i,
    /deliberate\s+misdirection/i,
    /planted\s+(evidence|iocs?|indicators?|artifacts?)/i,
    /attribution\s+(confusion|deception|manipulation)/i,
    /masquerad(e|ing)\s+as\s+/i,
    /impersonat(e|ing|ion)\s+.*\s+(group|actor|apt)/i,
    /borrowed\s+(tools?|techniques?|ttps?)/i,
    /staged\s+(evidence|artifacts?)/i,
    /deception\s+operation/i,
    /fabricated\s+(claim|evidence|persona)/i,
  ],
  medium: [
    /attribution\s+(challenge|difficulty|uncertainty|debate)/i,
    /conflicting\s+(evidence|indicators?|signals?)/i,
    /inconsistent\s+(with|attribution)/i,
    /disputed\s+attribution/i,
    /multiple\s+(groups?\s+)?claim(ed|ing)/i,
    /unlikely\s+attribution/i,
    /proxy\s+(group|actor|operation)/i,
    /front\s+(group|organization)/i,
    /cutout\s+(group|actor)/i,
    /overlap(ping)?\s+(tools?|infrastructure|ttps?)/i,
  ],
  low: [
    /attribution/i,
    /claimed\s+responsibility/i,
    /suspected\s+(actor|group|origin)/i,
    /possibly\s+(linked|connected|associated)/i,
    /unconfirmed\s+(attribution|claim)/i,
    /shared\s+(infrastructure|tools?|code)/i,
    /reused\s+(malware|tools?|infrastructure)/i,
  ],
};

/**
 * Deception technique patterns for classification.
 */
const DECEPTION_TECHNIQUE_PATTERNS: Record<string, RegExp[]> = {
  code_dna_mimicry: [
    /code\s+(similarity|overlap|reuse)\s+.*\s+(different|another|unrelated)/i,
    /shared\s+code\s+.*\s+(deliberate|planted)/i,
    /malware\s+(variant|fork)\s+.*\s+(attributed|linked)\s+to\s+different/i,
  ],
  tool_borrowing: [
    /used\s+tools?\s+(typically|commonly|previously)\s+(associated|attributed|linked)\s+with/i,
    /borrowed\s+(tools?|techniques?|procedures?)/i,
    /adopted\s+.*\s+ttps?\s+from/i,
    /mimick(ed|ing)\s+.*\s+(tradecraft|techniques?)/i,
  ],
  language_artifact_planting: [
    /language\s+(artifacts?|strings?|comments?)\s+.*\s+(planted|deliberate|inconsistent)/i,
    /(russian|chinese|korean|persian|arabic)\s+(strings?|text|comments?)\s+.*\s+(embedded|found|discovered)/i,
    /linguistic\s+(analysis|evidence)\s+.*\s+(contradict|inconsistent)/i,
  ],
  timestamp_manipulation: [
    /compile\s+time(stamp)?s?\s+.*\s+(manipulated|forged|inconsistent|spoofed)/i,
    /timezone\s+.*\s+(inconsisten|mismatch|spoofed)/i,
    /operating\s+hours?\s+.*\s+(contradict|inconsistent|unexpected)/i,
    /metadata\s+.*\s+(altered|modified|forged)/i,
  ],
  infrastructure_hijacking: [
    /hijack(ed|ing)\s+.*\s+infrastructure/i,
    /compromised\s+.*\s+(c2|command|control)\s+.*\s+(another|different)\s+(group|actor)/i,
    /tunneled\s+through\s+.*\s+(another|existing)\s+(actor|group)/i,
    /piggybacked?\s+on\s+.*\s+infrastructure/i,
  ],
  victimology_misdirection: [
    /target(ed|ing)\s+.*\s+(inconsistent|unusual|unexpected)\s+.*\s+(for|with)\s+.*\s+(actor|group)/i,
    /victim\s+(selection|profile)\s+.*\s+(atypical|unusual|inconsistent)/i,
    /sector\s+targeting\s+.*\s+(mismatch|inconsistent)/i,
  ],
  operational_tempo_spoofing: [
    /operational\s+(tempo|cadence|rhythm)\s+.*\s+(inconsistent|unusual|unexpected)/i,
    /activity\s+pattern\s+.*\s+(mismatch|contradict)/i,
    /campaign\s+(timing|schedule)\s+.*\s+(inconsistent|suspicious)/i,
  ],
  persona_fabrication: [
    /fabricated\s+(persona|identity|group)/i,
    /fake\s+(hacktivist|group|persona|identity)/i,
    /front\s+(group|organization|persona)/i,
    /sock\s*puppet/i,
    /created\s+.*\s+(persona|identity)\s+.*\s+(claim|responsibility)/i,
  ],
  claim_behavior_divergence: [
    /claim(ed|s)?\s+.*\s+(inconsistent|contradict|mismatch)\s+.*\s+(capability|evidence|behavior)/i,
    /capability\s+.*\s+(exceed|beyond|inconsistent)\s+.*\s+claim/i,
    /sophistication\s+.*\s+(mismatch|inconsistent|unexpected)/i,
  ],
};

/**
 * Pattern-based detection of false flag indicators in advisory text.
 */
export function detectFalseFlagPatterns(report: AdvisoryReport): {
  score: number;
  matchedIndicators: { level: string; pattern: string; match: string }[];
  detectedTechniques: DetectedDeceptionTechnique[];
} {
  const matchedIndicators: { level: string; pattern: string; match: string }[] = [];
  let score = 0;

  const content = `${report.title} ${report.content}`;

  // Check high-confidence indicators
  for (const pattern of FALSE_FLAG_INDICATORS.high) {
    const match = content.match(pattern);
    if (match) {
      matchedIndicators.push({ level: "high", pattern: pattern.source, match: match[0] });
      score += 30;
    }
  }

  // Check medium-confidence indicators
  for (const pattern of FALSE_FLAG_INDICATORS.medium) {
    const match = content.match(pattern);
    if (match) {
      matchedIndicators.push({ level: "medium", pattern: pattern.source, match: match[0] });
      score += 15;
    }
  }

  // Check low-confidence indicators
  for (const pattern of FALSE_FLAG_INDICATORS.low) {
    const match = content.match(pattern);
    if (match) {
      matchedIndicators.push({ level: "low", pattern: pattern.source, match: match[0] });
      score += 5;
    }
  }

  // Cap score at 100
  score = Math.min(100, score);

  // Detect specific deception techniques
  const detectedTechniques: DetectedDeceptionTechnique[] = [];
  for (const [category, patterns] of Object.entries(DECEPTION_TECHNIQUE_PATTERNS)) {
    for (const pattern of patterns) {
      const match = content.match(pattern);
      if (match) {
        detectedTechniques.push({
          category,
          technique: category.replace(/_/g, " "),
          confidence: score > 50 ? 0.8 : score > 25 ? 0.5 : 0.3,
          evidence: `Pattern match: "${match[0]}" in report "${report.title}"`,
        });
        break; // One match per category is sufficient
      }
    }
  }

  return { score, matchedIndicators, detectedTechniques };
}

// ─── LLM-Powered Classification ──────────────────────────────────────────────

/**
 * Use LLM to analyze a report for false flag indicators and generate
 * a structured classification.
 */
export async function classifyWithLLM(report: AdvisoryReport): Promise<{
  isFalseFlag: boolean;
  confidence: number;
  operationName: string | null;
  claimedActor: string | null;
  suspectedTrueActor: string | null;
  intendedScapegoat: string | null;
  deceptionTechniques: string[];
  evidenceChain: string[];
  contradictions: string[];
  summary: string;
}> {
  const prompt = `You are a cyber threat intelligence analyst specializing in attribution analysis and deception detection.

Analyze the following threat advisory/report for indicators of a false flag operation — where one threat actor deliberately impersonates or frames another actor.

REPORT:
Title: ${report.title}
Source: ${report.source}
Date: ${new Date(report.publishDate).toISOString().split("T")[0]}
Attributed Actor: ${report.attributedActor || "Unknown"}
Content: ${report.content.slice(0, 4000)}

ANALYSIS INSTRUCTIONS:
1. Determine if this report describes or reveals a false flag operation
2. If yes, identify the deception techniques used
3. Assess confidence level (0-100)
4. Identify the claimed actor, suspected true actor, and intended scapegoat
5. List evidence supporting the false flag assessment
6. List any contradictions or alternative explanations

Respond in JSON format only:
{
  "isFalseFlag": boolean,
  "confidence": number (0-100),
  "operationName": string or null,
  "claimedActor": string or null,
  "suspectedTrueActor": string or null,
  "intendedScapegoat": string or null,
  "deceptionTechniques": ["technique1", "technique2"],
  "evidenceChain": ["evidence1", "evidence2"],
  "contradictions": ["contradiction1"],
  "summary": "Brief explanation"
}`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a cyber threat intelligence analyst. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "false_flag_classification",
          strict: true,
          schema: {
            type: "object",
            properties: {
              isFalseFlag: { type: "boolean" },
              confidence: { type: "integer" },
              operationName: { type: ["string", "null"] },
              claimedActor: { type: ["string", "null"] },
              suspectedTrueActor: { type: ["string", "null"] },
              intendedScapegoat: { type: ["string", "null"] },
              deceptionTechniques: { type: "array", items: { type: "string" } },
              evidenceChain: { type: "array", items: { type: "string" } },
              contradictions: { type: "array", items: { type: "string" } },
              summary: { type: "string" },
            },
            required: [
              "isFalseFlag", "confidence", "operationName", "claimedActor",
              "suspectedTrueActor", "intendedScapegoat", "deceptionTechniques",
              "evidenceChain", "contradictions", "summary"
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) {
      return {
        isFalseFlag: false,
        confidence: 0,
        operationName: null,
        claimedActor: null,
        suspectedTrueActor: null,
        intendedScapegoat: null,
        deceptionTechniques: [],
        evidenceChain: [],
        contradictions: [],
        summary: "LLM analysis failed — no response content",
      };
    }

    return JSON.parse(content);
  } catch (error) {
    console.error("[FalseFlagEnrichment] LLM classification error:", error);
    return {
      isFalseFlag: false,
      confidence: 0,
      operationName: null,
      claimedActor: null,
      suspectedTrueActor: null,
      intendedScapegoat: null,
      deceptionTechniques: [],
      evidenceChain: [],
      contradictions: [],
      summary: `LLM analysis error: ${error instanceof Error ? error.message : "Unknown error"}`,
    };
  }
}

// ─── Enrichment Pipeline ─────────────────────────────────────────────────────

// In-memory store for candidates (production would use DB)
let candidates: FalseFlagCandidate[] = [];
let enrichmentStatus: EnrichmentStatus = {
  lastCycleAt: null,
  totalCyclesRun: 0,
  totalCandidatesGenerated: 0,
  pendingReview: 0,
  approved: 0,
  rejected: 0,
  nextScheduledCycle: null,
};

/**
 * Process a batch of advisory reports through the enrichment pipeline.
 * This is called by the advisory ingestion scheduler every 6 hours.
 */
export async function runEnrichmentCycle(reports: AdvisoryReport[]): Promise<EnrichmentCycleResult> {
  const cycleId = `enrich_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const startTime = Date.now();
  const newCandidates: FalseFlagCandidate[] = [];
  const errors: string[] = [];

  for (const report of reports) {
    try {
      // Step 1: Pattern-based pre-screening
      const patternResult = detectFalseFlagPatterns(report);

      // Skip reports with very low pattern scores (unlikely to be false flag related)
      if (patternResult.score < 15) continue;

      // Step 2: LLM classification for reports that pass pre-screening
      let llmResult = null;
      if (patternResult.score >= 25) {
        llmResult = await classifyWithLLM(report);
      }

      // Step 3: Determine if this is a candidate
      const isCandidate =
        (patternResult.score >= 50) || // High pattern match alone
        (llmResult?.isFalseFlag && llmResult.confidence >= 40) || // LLM says yes with moderate confidence
        (patternResult.score >= 30 && llmResult?.confidence && llmResult.confidence >= 30); // Hybrid threshold

      if (!isCandidate) continue;

      // Step 4: Generate candidate entry
      const candidate: FalseFlagCandidate = {
        id: `ff_cand_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        sourceReportId: report.id,
        sourceReportTitle: report.title,
        sourceReportUrl: report.url,
        detectedAt: Date.now(),
        status: "pending_review",

        operationName: llmResult?.operationName || `Unnamed Operation (${report.title.slice(0, 50)})`,
        year: new Date(report.publishDate).getFullYear(),
        description: llmResult?.summary || `Potential false flag detected in "${report.title}" via pattern analysis.`,

        claimedActor: llmResult?.claimedActor || report.attributedActor || null,
        suspectedTrueActor: llmResult?.suspectedTrueActor || null,
        intendedScapegoat: llmResult?.intendedScapegoat || null,

        deceptionTechniques: [
          ...patternResult.detectedTechniques,
          ...(llmResult?.deceptionTechniques || []).map((t) => ({
            category: t.toLowerCase().replace(/\s+/g, "_"),
            technique: t,
            confidence: (llmResult?.confidence || 50) / 100,
            evidence: `LLM classification from ${report.source} report`,
          })),
        ],

        overallConfidence: Math.round(
          llmResult
            ? (patternResult.score * 0.4 + llmResult.confidence * 0.6)
            : patternResult.score
        ),
        evidenceChain: [
          `Pattern match score: ${patternResult.score}/100 (${patternResult.matchedIndicators.length} indicators)`,
          ...(llmResult?.evidenceChain || []),
          ...patternResult.matchedIndicators
            .filter((i) => i.level === "high")
            .map((i) => `High-confidence pattern: "${i.match}"`),
        ],
        contradictions: llmResult?.contradictions || [],

        classificationMethod: llmResult ? "hybrid" : "pattern_match",
        patternMatchScore: patternResult.score,
        llmAnalysisScore: llmResult?.confidence || 0,
      };

      newCandidates.push(candidate);
    } catch (error) {
      errors.push(`Error processing report "${report.title}": ${error instanceof Error ? error.message : "Unknown"}`);
    }
  }

  // Update state
  candidates = [...candidates, ...newCandidates];
  enrichmentStatus.lastCycleAt = Date.now();
  enrichmentStatus.totalCyclesRun++;
  enrichmentStatus.totalCandidatesGenerated += newCandidates.length;
  enrichmentStatus.pendingReview = candidates.filter((c) => c.status === "pending_review").length;
  enrichmentStatus.nextScheduledCycle = Date.now() + 6 * 60 * 60 * 1000; // 6 hours

  return {
    cycleId,
    timestamp: Date.now(),
    reportsProcessed: reports.length,
    candidatesGenerated: newCandidates.length,
    candidates: newCandidates,
    errors,
    duration: Date.now() - startTime,
  };
}

// ─── Operator Review Workflow ────────────────────────────────────────────────

/**
 * Get all candidates pending operator review.
 */
export function getPendingCandidates(): FalseFlagCandidate[] {
  return candidates.filter((c) => c.status === "pending_review");
}

/**
 * Get all candidates (with optional status filter).
 */
export function getAllCandidates(status?: FalseFlagCandidate["status"]): FalseFlagCandidate[] {
  if (status) return candidates.filter((c) => c.status === status);
  return [...candidates];
}

/**
 * Get a specific candidate by ID.
 */
export function getCandidateById(id: string): FalseFlagCandidate | null {
  return candidates.find((c) => c.id === id) || null;
}

/**
 * Approve a candidate — marks it for inclusion in the production case library.
 * Returns the approved candidate with updated status.
 */
export function approveCandidate(
  id: string,
  reviewerNotes: string,
  reviewerId: string
): FalseFlagCandidate | null {
  const candidate = candidates.find((c) => c.id === id);
  if (!candidate) return null;

  candidate.status = "approved";
  candidate.analystNotes = reviewerNotes;
  candidate.reviewedBy = reviewerId;
  candidate.reviewedAt = Date.now();

  enrichmentStatus.pendingReview = candidates.filter((c) => c.status === "pending_review").length;
  enrichmentStatus.approved = candidates.filter((c) => c.status === "approved").length;

  return candidate;
}

/**
 * Reject a candidate — marks it as not a valid false flag operation.
 */
export function rejectCandidate(
  id: string,
  reviewerNotes: string,
  reviewerId: string
): FalseFlagCandidate | null {
  const candidate = candidates.find((c) => c.id === id);
  if (!candidate) return null;

  candidate.status = "rejected";
  candidate.analystNotes = reviewerNotes;
  candidate.reviewedBy = reviewerId;
  candidate.reviewedAt = Date.now();

  enrichmentStatus.pendingReview = candidates.filter((c) => c.status === "pending_review").length;
  enrichmentStatus.rejected = candidates.filter((c) => c.status === "rejected").length;

  return candidate;
}

/**
 * Mark a candidate as needing more data before a decision can be made.
 */
export function markNeedsMoreData(
  id: string,
  reviewerNotes: string,
  reviewerId: string
): FalseFlagCandidate | null {
  const candidate = candidates.find((c) => c.id === id);
  if (!candidate) return null;

  candidate.status = "needs_more_data";
  candidate.analystNotes = reviewerNotes;
  candidate.reviewedBy = reviewerId;
  candidate.reviewedAt = Date.now();

  enrichmentStatus.pendingReview = candidates.filter((c) => c.status === "pending_review").length;

  return candidate;
}

/**
 * Get the current enrichment status.
 */
export function getEnrichmentStatus(): EnrichmentStatus {
  return { ...enrichmentStatus };
}

// ─── Integration with Advisory Ingestion Scheduler ───────────────────────────

/**
 * Hook called by the advisory ingestion scheduler after each advisory pull.
 * Converts raw advisory data into AdvisoryReport format and runs enrichment.
 */
export async function onAdvisoryIngested(advisories: {
  id: string;
  title: string;
  source: string;
  publishDate: number;
  content: string;
  url?: string;
  cves?: string[];
  attributedActor?: string;
}[]): Promise<EnrichmentCycleResult> {
  const reports: AdvisoryReport[] = advisories.map((a) => ({
    id: a.id,
    title: a.title,
    source: a.source,
    publishDate: a.publishDate,
    content: a.content,
    url: a.url,
    cves: a.cves,
    attributedActor: a.attributedActor,
  }));

  return runEnrichmentCycle(reports);
}

/**
 * Convert an approved candidate into a case library entry format.
 * This produces the structure needed by false-flag-case-library.ts.
 */
export function candidateToCaseEntry(candidate: FalseFlagCandidate) {
  if (candidate.status !== "approved") {
    throw new Error("Only approved candidates can be converted to case entries");
  }

  return {
    id: `auto_${candidate.id}`,
    name: candidate.operationName,
    year: candidate.year,
    description: candidate.description,
    actualActor: {
      name: candidate.suspectedTrueActor || "Unknown",
      country: "Unknown", // Would need enrichment
      motivation: "unknown" as const,
    },
    claimedActor: candidate.claimedActor
      ? { name: candidate.claimedActor, country: "Unknown" }
      : null,
    intendedScapegoat: candidate.intendedScapegoat
      ? { name: candidate.intendedScapegoat, country: "Unknown" }
      : null,
    deceptionTechniques: candidate.deceptionTechniques.map((t) => ({
      category: t.category,
      description: t.evidence,
      effectiveness: t.confidence * 100,
      detectionDifficulty: t.confidence > 0.7 ? "hard" : t.confidence > 0.4 ? "medium" : "easy",
    })),
    resolution: {
      howDiscovered: `Auto-detected by AC3 enrichment pipeline from ${candidate.sourceReportTitle}`,
      timeToAttribution: "auto-detected",
      confidence: candidate.overallConfidence,
      keyEvidence: candidate.evidenceChain,
    },
    lessonsLearned: [
      `Auto-enriched from advisory: ${candidate.sourceReportTitle}`,
      `Classification method: ${candidate.classificationMethod}`,
      `Pattern score: ${candidate.patternMatchScore}, LLM score: ${candidate.llmAnalysisScore}`,
    ],
    sources: candidate.sourceReportUrl ? [candidate.sourceReportUrl] : [],
    autoEnriched: true,
    enrichedAt: candidate.detectedAt,
    approvedBy: candidate.reviewedBy,
    approvedAt: candidate.reviewedAt,
  };
}
