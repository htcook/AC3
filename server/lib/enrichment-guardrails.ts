/**
 * Enrichment Hallucination Guardrails
 * 
 * Post-LLM validation layer that cross-references enrichment output against
 * local database events, validates MITRE technique codes, enforces source
 * citation requirements, and applies confidence thresholds before data is
 * written to the threat actor catalog.
 * 
 * Design principles for LE use:
 * - No fabricated data: every field must have a verifiable source
 * - Cross-reference against internal DB (TGE, UIE, IOCs) for corroboration
 * - MITRE T-codes must match known ATT&CK patterns
 * - Low-confidence LLM-only data is flagged, not silently accepted
 * - Full audit trail of what was accepted, flagged, or rejected
 */

// ─── Configuration ─────────────────────────────────────────────────────

export const GUARDRAIL_CONFIG = {
  /** Minimum confidence to accept a field without flagging */
  CONFIDENCE_ACCEPT_THRESHOLD: 60,
  /** Minimum confidence to keep a field (flagged). Below this = rejected */
  CONFIDENCE_REJECT_THRESHOLD: 25,
  /** Fields sourced only from "llm_knowledge" must meet this confidence */
  LLM_ONLY_MIN_CONFIDENCE: 70,
  /** Maximum number of aliases to accept (prevents hallucinated lists) */
  MAX_ALIASES: 30,
  /** Maximum number of techniques to accept */
  MAX_TECHNIQUES: 50,
  /** Maximum number of tools to accept */
  MAX_TOOLS: 30,
  /** Maximum number of notable attacks to accept */
  MAX_NOTABLE_ATTACKS: 50,
  /** Maximum number of activity timeline entries */
  MAX_TIMELINE_ENTRIES: 100,
  /** Minimum description length to accept (prevents trivial descriptions) */
  MIN_DESCRIPTION_LENGTH: 50,
  /** Known valid MITRE ATT&CK technique ID patterns */
  MITRE_TECHNIQUE_REGEX: /^T\d{4}(\.\d{3})?$/,
  /** Known valid MITRE tactic names */
  VALID_MITRE_TACTICS: new Set([
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
    // Also accept title case and spaces
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
  ]),
  /** Source types that count as "verifiable" (not just LLM knowledge) */
  VERIFIABLE_SOURCE_TYPES: new Set(["osint", "darkweb", "government", "vendor_report", "academic", "internal_db"]),
  /** Known bogus/hallucinated source patterns */
  SUSPICIOUS_SOURCE_PATTERNS: [
    /^https?:\/\/example\.com/i,
    /^https?:\/\/localhost/i,
    /^https?:\/\/www\.example\./i,
    /lorem ipsum/i,
    /^N\/A$/i,
    /^none$/i,
    /^unknown$/i,
    /^not available$/i,
  ],
};

// ─── Types ─────────────────────────────────────────────────────────────

export interface GuardrailVerdict {
  field: string;
  status: "accepted" | "flagged" | "rejected";
  reason: string;
  confidence: number;
  hasVerifiableSource: boolean;
  corroboratedByLocalDb: boolean;
}

export interface GuardrailReport {
  totalFields: number;
  accepted: number;
  flagged: number;
  rejected: number;
  verdicts: GuardrailVerdict[];
  overallTrustScore: number;  // 0-100
  warnings: string[];
  rejectedFields: string[];
  flaggedFields: string[];
}

export interface LocalDbContext {
  tgeEvents: any[];
  uieEvents: any[];
  iocs: any[];
}

// ─── Source Validation ─────────────────────────────────────────────────

/**
 * Check if a source attribution looks suspicious or fabricated.
 */
function isSourceSuspicious(source: any): boolean {
  if (!source) return true;
  const name = (source.sourceName || source.source || "").toString();
  const url = (source.sourceUrl || "").toString();

  // Empty source name
  if (!name || name.length < 3) return true;

  // Check suspicious patterns
  for (const pattern of GUARDRAIL_CONFIG.SUSPICIOUS_SOURCE_PATTERNS) {
    if (pattern.test(name) || pattern.test(url)) return true;
  }

  return false;
}

/**
 * Check if a field has at least one verifiable (non-LLM-knowledge) source.
 */
function hasVerifiableSource(fieldName: string, sources: any[]): boolean {
  const fieldSources = sources.filter((s: any) => s.field === fieldName || s.field === "*");
  return fieldSources.some((s: any) =>
    GUARDRAIL_CONFIG.VERIFIABLE_SOURCE_TYPES.has(s.sourceType) && !isSourceSuspicious(s)
  );
}

/**
 * Get the average confidence for a field from its sources.
 */
function getFieldConfidence(fieldName: string, sources: any[]): number {
  const fieldSources = sources.filter((s: any) => s.field === fieldName || s.field === "*");
  if (fieldSources.length === 0) return 0;
  const total = fieldSources.reduce((sum: number, s: any) => sum + (s.confidence || 0), 0);
  return Math.round(total / fieldSources.length);
}

/**
 * Check if a field is only sourced from "llm_knowledge" (no external verification).
 */
function isLlmOnlySourced(fieldName: string, sources: any[]): boolean {
  const fieldSources = sources.filter((s: any) => s.field === fieldName);
  if (fieldSources.length === 0) return true;
  return fieldSources.every((s: any) => s.sourceType === "llm_knowledge");
}

// ─── MITRE ATT&CK Validation ──────────────────────────────────────────

/**
 * Validate a MITRE ATT&CK technique entry.
 */
function validateMitreTechnique(tech: any): { valid: boolean; issues: string[] } {
  const issues: string[] = [];

  if (!tech.id || !GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test(tech.id)) {
    issues.push(`Invalid technique ID: "${tech.id}" (expected format: T####[.###])`);
  }

  if (!tech.name || tech.name.length < 3) {
    issues.push(`Missing or too short technique name: "${tech.name}"`);
  }

  if (tech.tactic) {
    const normalizedTactic = tech.tactic.toLowerCase().replace(/\s+/g, "-");
    const validTactics = new Set([
      "reconnaissance", "resource-development", "initial-access", "execution",
      "persistence", "privilege-escalation", "defense-evasion", "credential-access",
      "discovery", "lateral-movement", "collection", "command-and-control",
      "exfiltration", "impact",
    ]);
    if (!validTactics.has(normalizedTactic)) {
      issues.push(`Unknown MITRE tactic: "${tech.tactic}"`);
    }
  } else {
    issues.push("Missing tactic for technique");
  }

  return { valid: issues.length === 0, issues };
}

// ─── Cross-Reference with Local DB ─────────────────────────────────────

/**
 * Check if LLM-provided data is corroborated by local database events.
 */
function crossReferenceLocalDb(
  fieldName: string,
  value: any,
  localContext: LocalDbContext,
): boolean {
  const { tgeEvents, uieEvents, iocs } = localContext;
  const allEvents = [...tgeEvents, ...uieEvents];

  switch (fieldName) {
    case "targetSectors": {
      if (!Array.isArray(value)) return false;
      // Check if any sector appears in local event victim sectors
      const localSectors = new Set(
        allEvents
          .map((e: any) => (e.victimSector || e.tgeVictimSector || e.uieVictimSector || "").toLowerCase())
          .filter(Boolean)
      );
      return value.some((s: string) =>
        localSectors.has(s.toLowerCase()) ||
        [...localSectors].some(ls => ls.includes(s.toLowerCase()) || s.toLowerCase().includes(ls))
      );
    }

    case "targetRegions": {
      if (!Array.isArray(value)) return false;
      const localCountries = new Set(
        allEvents
          .map((e: any) => (e.victimCountry || e.tgeVictimCountry || e.uieVictimCountry || "").toLowerCase())
          .filter(Boolean)
      );
      return value.some((r: string) =>
        localCountries.has(r.toLowerCase()) ||
        [...localCountries].some(lc => lc.includes(r.toLowerCase()) || r.toLowerCase().includes(lc))
      );
    }

    case "techniques": {
      if (!Array.isArray(value)) return false;
      // Check if any technique IDs appear in local event MITRE techniques
      const localTechStrings = allEvents
        .map((e: any) => (e.mitreTechniques || e.tgeMitreTechniques || e.uieMitreTechniques || "").toString().toLowerCase())
        .filter(Boolean)
        .join(" ");
      return value.some((t: any) => {
        const techId = (typeof t === "object" ? t.id : t || "").toString();
        return localTechStrings.includes(techId.toLowerCase());
      });
    }

    case "tools":
    case "malware": {
      if (!Array.isArray(value)) return false;
      // Check if any tools/malware appear in local event descriptions
      const localDescriptions = allEvents
        .map((e: any) => (e.description || e.tgeDescription || e.uieDescription || "").toLowerCase())
        .filter(Boolean)
        .join(" ");
      return value.some((t: string) => localDescriptions.includes(t.toLowerCase()));
    }

    case "notableAttacks": {
      if (!Array.isArray(value)) return false;
      // Check if any victim names appear in local events
      const localVictims = new Set(
        allEvents
          .map((e: any) => (e.victimName || e.tgeVictimName || e.uieVictimName || "").toLowerCase())
          .filter(Boolean)
      );
      return value.some((a: any) =>
        localVictims.has((a.victimName || "").toLowerCase()) ||
        [...localVictims].some(lv => lv.includes((a.victimName || "").toLowerCase()))
      );
    }

    case "aliases": {
      if (!Array.isArray(value)) return false;
      // Check if any aliases appear in local event actor names or descriptions
      const localText = allEvents
        .map((e: any) => `${e.title || e.tgeTitle || e.uieTitle || ""} ${e.description || e.tgeDescription || e.uieDescription || ""}`.toLowerCase())
        .join(" ");
      return value.some((a: string) => localText.includes(a.toLowerCase()));
    }

    default:
      return false;
  }
}

// ─── Main Guardrail Validator ──────────────────────────────────────────

/**
 * Validate LLM enrichment output against guardrails.
 * Returns a report with per-field verdicts and an overall trust score.
 */
export function validateEnrichmentOutput(
  parsed: any,
  sources: any[],
  localContext: LocalDbContext,
  existingActor: any,
): GuardrailReport {
  const verdicts: GuardrailVerdict[] = [];
  const warnings: string[] = [];

  // ─── Validate scalar fields ──────────────────────────────────────────

  const scalarFields = [
    { name: "description", value: parsed.description },
    { name: "motivation", value: parsed.motivation },
    { name: "origin", value: parsed.origin },
    { name: "firstSeen", value: parsed.firstSeen },
    { name: "lastActive", value: parsed.lastActive },
    { name: "threatLevel", value: parsed.threatLevel },
    { name: "sophistication", value: parsed.sophistication },
  ];

  for (const { name, value } of scalarFields) {
    if (!value || (typeof value === "string" && value.length === 0)) {
      // No data provided — skip, not a rejection
      continue;
    }

    const confidence = getFieldConfidence(name, sources);
    const verifiable = hasVerifiableSource(name, sources);
    const llmOnly = isLlmOnlySourced(name, sources);
    const corroborated = crossReferenceLocalDb(name, value, localContext);

    let status: "accepted" | "flagged" | "rejected" = "accepted";
    let reason = "Meets confidence threshold";

    // Description-specific checks
    if (name === "description" && typeof value === "string") {
      if (value.length < GUARDRAIL_CONFIG.MIN_DESCRIPTION_LENGTH) {
        status = "rejected";
        reason = `Description too short (${value.length} chars, min ${GUARDRAIL_CONFIG.MIN_DESCRIPTION_LENGTH})`;
      }
    }

    // FirstSeen/LastActive date validation
    if ((name === "firstSeen" || name === "lastActive") && typeof value === "string") {
      const datePattern = /^\d{4}(-\d{2})?(-\d{2})?$/;
      if (!datePattern.test(value)) {
        status = "flagged";
        reason = `Date format may be invalid: "${value}"`;
      }
      // Reject future dates
      const year = parseInt(value.substring(0, 4));
      if (year > new Date().getFullYear() + 1) {
        status = "rejected";
        reason = `Future date detected: "${value}"`;
      }
      // Reject implausibly old dates
      if (year < 1990) {
        status = "flagged";
        reason = `Unusually old date: "${value}" — verify accuracy`;
      }
    }

    // LLM-only source check
    if (status === "accepted" && llmOnly && !corroborated) {
      if (confidence < GUARDRAIL_CONFIG.LLM_ONLY_MIN_CONFIDENCE) {
        status = "flagged";
        reason = `LLM-only source with confidence ${confidence}% (threshold: ${GUARDRAIL_CONFIG.LLM_ONLY_MIN_CONFIDENCE}%). No external verification.`;
      }
    }

    // General confidence check
    if (status === "accepted" && confidence < GUARDRAIL_CONFIG.CONFIDENCE_ACCEPT_THRESHOLD) {
      if (confidence < GUARDRAIL_CONFIG.CONFIDENCE_REJECT_THRESHOLD) {
        status = "rejected";
        reason = `Confidence too low: ${confidence}% (min: ${GUARDRAIL_CONFIG.CONFIDENCE_REJECT_THRESHOLD}%)`;
      } else {
        status = "flagged";
        reason = `Below confidence threshold: ${confidence}% (accept: ${GUARDRAIL_CONFIG.CONFIDENCE_ACCEPT_THRESHOLD}%)`;
      }
    }

    // Corroboration bonus
    if (status === "flagged" && corroborated) {
      status = "accepted";
      reason += " — corroborated by local database events";
    }

    verdicts.push({
      field: name,
      status,
      reason,
      confidence,
      hasVerifiableSource: verifiable,
      corroboratedByLocalDb: corroborated,
    });
  }

  // ─── Validate array fields ───────────────────────────────────────────

  const arrayFields = [
    { name: "aliases", value: parsed.aliases, max: GUARDRAIL_CONFIG.MAX_ALIASES },
    { name: "targetSectors", value: parsed.targetSectors, max: 30 },
    { name: "targetRegions", value: parsed.targetRegions, max: 30 },
    { name: "tools", value: parsed.tools, max: GUARDRAIL_CONFIG.MAX_TOOLS },
    { name: "malware", value: parsed.malware, max: GUARDRAIL_CONFIG.MAX_TOOLS },
    { name: "conflicts", value: parsed.conflicts, max: 10 },
  ];

  for (const { name, value, max } of arrayFields) {
    if (!Array.isArray(value) || value.length === 0) continue;

    const confidence = getFieldConfidence(name, sources);
    const verifiable = hasVerifiableSource(name, sources);
    const llmOnly = isLlmOnlySourced(name, sources);
    const corroborated = crossReferenceLocalDb(name, value, localContext);

    let status: "accepted" | "flagged" | "rejected" = "accepted";
    let reason = "Meets confidence threshold";

    // Size limit check
    if (value.length > max) {
      warnings.push(`${name}: truncated from ${value.length} to ${max} items`);
    }

    // Empty string check
    const emptyCount = value.filter((v: any) => !v || (typeof v === "string" && v.trim().length === 0)).length;
    if (emptyCount > 0) {
      warnings.push(`${name}: ${emptyCount} empty entries removed`);
    }

    // LLM-only with low confidence
    if (llmOnly && !corroborated && confidence < GUARDRAIL_CONFIG.LLM_ONLY_MIN_CONFIDENCE) {
      status = "flagged";
      reason = `LLM-only source, confidence ${confidence}%, no local DB corroboration`;
    }

    // General confidence
    if (status === "accepted" && confidence < GUARDRAIL_CONFIG.CONFIDENCE_REJECT_THRESHOLD) {
      status = "rejected";
      reason = `Confidence too low: ${confidence}%`;
    } else if (status === "accepted" && confidence < GUARDRAIL_CONFIG.CONFIDENCE_ACCEPT_THRESHOLD) {
      status = corroborated ? "accepted" : "flagged";
      reason = corroborated
        ? `Below threshold but corroborated by local DB`
        : `Below confidence threshold: ${confidence}%`;
    }

    verdicts.push({
      field: name,
      status,
      reason,
      confidence,
      hasVerifiableSource: verifiable,
      corroboratedByLocalDb: corroborated,
    });
  }

  // ─── Validate MITRE techniques ───────────────────────────────────────

  if (Array.isArray(parsed.techniques) && parsed.techniques.length > 0) {
    const confidence = getFieldConfidence("techniques", sources);
    const corroborated = crossReferenceLocalDb("techniques", parsed.techniques, localContext);
    let invalidCount = 0;
    const techIssues: string[] = [];

    for (const tech of parsed.techniques.slice(0, GUARDRAIL_CONFIG.MAX_TECHNIQUES)) {
      const { valid, issues } = validateMitreTechnique(tech);
      if (!valid) {
        invalidCount++;
        techIssues.push(...issues);
      }
    }

    let status: "accepted" | "flagged" | "rejected" = "accepted";
    let reason = `${parsed.techniques.length} techniques, ${invalidCount} invalid`;

    if (invalidCount > parsed.techniques.length * 0.5) {
      status = "rejected";
      reason = `More than 50% of techniques have invalid T-codes (${invalidCount}/${parsed.techniques.length})`;
    } else if (invalidCount > 0) {
      status = "flagged";
      reason = `${invalidCount} techniques have validation issues: ${techIssues.slice(0, 3).join("; ")}`;
    }

    if (status === "flagged" && corroborated) {
      reason += " — some techniques corroborated by local events";
    }

    verdicts.push({
      field: "techniques",
      status,
      reason,
      confidence,
      hasVerifiableSource: hasVerifiableSource("techniques", sources),
      corroboratedByLocalDb: corroborated,
    });
  }

  // ─── Validate notable attacks ────────────────────────────────────────

  if (Array.isArray(parsed.notableAttacks) && parsed.notableAttacks.length > 0) {
    const confidence = getFieldConfidence("notableAttacks", sources);
    const corroborated = crossReferenceLocalDb("notableAttacks", parsed.notableAttacks, localContext);

    let status: "accepted" | "flagged" | "rejected" = "accepted";
    let reason = `${parsed.notableAttacks.length} notable attacks`;

    // Check for attacks with missing sources
    const unsourcedAttacks = parsed.notableAttacks.filter((a: any) => !a.source || a.source.length < 3);
    if (unsourcedAttacks.length > parsed.notableAttacks.length * 0.5) {
      status = "flagged";
      reason = `${unsourcedAttacks.length}/${parsed.notableAttacks.length} attacks lack source attribution`;
    }

    // Check for implausible dates
    const futureAttacks = parsed.notableAttacks.filter((a: any) => {
      const year = parseInt((a.date || "").substring(0, 4));
      return year > new Date().getFullYear() + 1;
    });
    if (futureAttacks.length > 0) {
      status = "flagged";
      reason += `; ${futureAttacks.length} attacks have future dates`;
      warnings.push(`notableAttacks: ${futureAttacks.length} entries with future dates removed`);
    }

    verdicts.push({
      field: "notableAttacks",
      status,
      reason,
      confidence,
      hasVerifiableSource: hasVerifiableSource("notableAttacks", sources),
      corroboratedByLocalDb: corroborated,
    });
  }

  // ─── Validate source attributions themselves ─────────────────────────

  const suspiciousSources = sources.filter(isSourceSuspicious);
  if (suspiciousSources.length > 0) {
    warnings.push(`${suspiciousSources.length} suspicious source attributions detected and excluded`);
  }

  // Check for excessive "llm_knowledge" reliance
  const llmOnlySources = sources.filter((s: any) => s.sourceType === "llm_knowledge");
  const verifiableSources = sources.filter((s: any) => GUARDRAIL_CONFIG.VERIFIABLE_SOURCE_TYPES.has(s.sourceType));
  if (llmOnlySources.length > sources.length * 0.7 && sources.length > 3) {
    warnings.push(`High LLM-knowledge reliance: ${llmOnlySources.length}/${sources.length} sources are LLM-only. Data may be less reliable.`);
  }

  // ─── Compute overall trust score ─────────────────────────────────────

  const accepted = verdicts.filter(v => v.status === "accepted").length;
  const flagged = verdicts.filter(v => v.status === "flagged").length;
  const rejected = verdicts.filter(v => v.status === "rejected").length;
  const totalFields = verdicts.length;

  // Trust score: accepted fields contribute fully, flagged at 50%, rejected at 0%
  const trustScore = totalFields > 0
    ? Math.round(((accepted + flagged * 0.5) / totalFields) * 100)
    : 0;

  // Bonus for verifiable sources
  const verifiableRatio = sources.length > 0 ? verifiableSources.length / sources.length : 0;
  const adjustedTrust = Math.round(trustScore * (0.7 + 0.3 * verifiableRatio));

  return {
    totalFields,
    accepted,
    flagged,
    rejected,
    verdicts,
    overallTrustScore: adjustedTrust,
    warnings,
    rejectedFields: verdicts.filter(v => v.status === "rejected").map(v => v.field),
    flaggedFields: verdicts.filter(v => v.status === "flagged").map(v => v.field),
  };
}

// ─── Apply Guardrails to Enrichment Data ───────────────────────────────

/**
 * Filter enrichment data based on guardrail verdicts.
 * Rejected fields are removed. Flagged fields are kept but marked.
 * Returns the sanitized data and the guardrail report.
 */
export function applyGuardrails(
  parsed: any,
  sources: any[],
  localContext: LocalDbContext,
  existingActor: any,
): { sanitizedData: any; report: GuardrailReport } {
  const report = validateEnrichmentOutput(parsed, sources, localContext, existingActor);
  const sanitized = { ...parsed };

  // Remove rejected fields
  for (const field of report.rejectedFields) {
    if (field in sanitized) {
      sanitized[field] = undefined;
    }
  }

  // Truncate oversized arrays
  if (Array.isArray(sanitized.aliases)) {
    sanitized.aliases = sanitized.aliases.filter(Boolean).slice(0, GUARDRAIL_CONFIG.MAX_ALIASES);
  }
  if (Array.isArray(sanitized.techniques)) {
    // Remove techniques with invalid T-codes
    sanitized.techniques = sanitized.techniques
      .filter((t: any) => GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test(t.id))
      .slice(0, GUARDRAIL_CONFIG.MAX_TECHNIQUES);
  }
  if (Array.isArray(sanitized.tools)) {
    sanitized.tools = sanitized.tools.filter(Boolean).slice(0, GUARDRAIL_CONFIG.MAX_TOOLS);
  }
  if (Array.isArray(sanitized.malware)) {
    sanitized.malware = sanitized.malware.filter(Boolean).slice(0, GUARDRAIL_CONFIG.MAX_TOOLS);
  }
  if (Array.isArray(sanitized.notableAttacks)) {
    // Remove attacks with future dates
    sanitized.notableAttacks = sanitized.notableAttacks
      .filter((a: any) => {
        const year = parseInt((a.date || "").substring(0, 4));
        return year <= new Date().getFullYear() + 1;
      })
      .slice(0, GUARDRAIL_CONFIG.MAX_NOTABLE_ATTACKS);
  }
  if (Array.isArray(sanitized.activityTimeline)) {
    sanitized.activityTimeline = sanitized.activityTimeline
      .slice(0, GUARDRAIL_CONFIG.MAX_TIMELINE_ENTRIES);
  }

  // Remove suspicious sources from the source list
  const cleanedSources = sources.filter(s => !isSourceSuspicious(s));

  // Tag flagged fields in the source attributions
  for (const flaggedField of report.flaggedFields) {
    const fieldSources = cleanedSources.filter((s: any) => s.field === flaggedField);
    for (const s of fieldSources) {
      (s as any)._flagged = true;
      (s as any)._flagReason = report.verdicts.find(v => v.field === flaggedField)?.reason;
    }
  }

  return { sanitizedData: sanitized, report };
}
