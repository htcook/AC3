/**
 * Finding → compliance-control tagging + evidence-export payload builders.
 *
 * Phase 1 of the AC3 ⇄ SSP Generator integration (see COMBINED_PLATFORM_DESIGN):
 * turns an AC3 engagement finding into the control-tagged "Payload A" shape and
 * a KSI evidence-chain row into the provenance-carrying "Payload B" shape that
 * the compliance service's POST /findings/import consumes.
 *
 * Control tagging reuses the existing NIST/MITRE/CWE mapper — we do not invent a
 * second mapping. CWE and MITRE technique come from the mapper; OWASP category
 * uses a small, explicit top-10 → NIST seed below (extend as needed). When no
 * control can be derived, the finding is emitted with an `untagged_reason` so
 * the gap is visible rather than silently dropped.
 *
 * These functions are PURE (no DB / no I/O) so they are unit-testable in
 * isolation; the tRPC endpoint in routers/evidence-export.ts loads the rows and
 * calls them.
 */
import { getNistControlsForCwe, getNistControlsForMitre } from "./nist-mitre-cwe-mapper";

export type ComplianceSeverity = "high" | "moderate" | "low";

/** AC3 severity (critical/high/medium/low/info) → SDR severity (high/moderate/low). */
export function mapSeverity(severity: string | null | undefined): ComplianceSeverity {
  switch ((severity || "").toLowerCase()) {
    case "critical":
    case "high":
      return "high";
    case "medium":
    case "moderate":
      return "moderate";
    default:
      return "low"; // low, info, unknown → low
  }
}

/** A confirmed (corroborated-and-verified) finding is a control condition; else coverage. */
export function mapFindingType(corroborationTier: string | null | undefined): "condition" | "coverage" {
  return corroborationTier === "confirmed" ? "condition" : "coverage";
}

// OWASP Top-10 (2021) → representative NIST 800-53 controls. Deliberately small
// and explicit; the CWE/MITRE mapper carries the deep coverage.
const OWASP_TO_NIST: Record<string, string[]> = {
  A01: ["AC-3", "AC-6"],            // Broken Access Control
  A02: ["SC-8", "SC-13", "SC-28"],  // Cryptographic Failures
  A03: ["SI-10", "SI-3"],           // Injection
  A04: ["PL-8", "SA-8"],            // Insecure Design
  A05: ["CM-6", "CM-7"],            // Security Misconfiguration
  A06: ["RA-5", "SI-2"],            // Vulnerable & Outdated Components
  A07: ["IA-2", "IA-5"],            // Identification & Authentication Failures
  A08: ["SI-7"],                    // Software & Data Integrity Failures
  A09: ["AU-2", "AU-6", "SI-4"],    // Logging & Monitoring Failures
  A10: ["SC-7"],                    // SSRF
};

export interface ControlTagInput {
  cwe?: string | null;
  mitreTechnique?: string | null;
  owaspCategory?: string | null;
}

/**
 * Derive the NIST/KSI control ids for a finding from its CWE, MITRE technique,
 * and OWASP category. Returns the deduped, sorted control ids; when none can be
 * derived, returns an `untaggedReason` instead of an empty tag with no context.
 */
export function deriveControlIds(f: ControlTagInput): { controlIds: string[]; untaggedReason?: string } {
  const set = new Set<string>();

  if (f.cwe) {
    for (const c of getNistControlsForCwe(f.cwe)) set.add(c.controlId);
  }
  if (f.mitreTechnique) {
    for (const id of getNistControlsForMitre(f.mitreTechnique)) set.add(id);
  }
  if (f.owaspCategory) {
    const key = f.owaspCategory.split(":")[0].trim().toUpperCase(); // "A06:2021" → "A06"
    for (const id of OWASP_TO_NIST[key] || []) set.add(id);
  }

  const controlIds = [...set].sort();
  if (controlIds.length > 0) return { controlIds };

  const signals = [f.cwe, f.mitreTechnique, f.owaspCategory].filter(Boolean);
  const untaggedReason =
    signals.length === 0
      ? "no CWE, MITRE technique, or OWASP category on finding"
      : `no NIST mapping for ${signals.join(", ")}`;
  return { controlIds: [], untaggedReason };
}

/** epoch (ms, bigint/number/string) → ISO 8601, or null when absent/invalid. */
function epochToIso(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n).toISOString();
}

/** normalize a bare hash into "<alg>:<hash>" (e.g. "sha256:9a1f…"). */
function normalizeHash(hash: string | null | undefined, algorithm: string | null | undefined): string | null {
  if (!hash) return null;
  if (hash.includes(":")) return hash;
  const alg = (algorithm || "SHA-256").toLowerCase().replace(/-/g, "");
  return `${alg}:${hash}`;
}

/** Build Payload A (finding → gap_findings) from an AC3 engagementFindings row. */
export function buildFindingPayload(f: any, engagementId: number) {
  const tag = deriveControlIds({ cwe: f.cwe, mitreTechnique: f.mitreTechnique, owaspCategory: f.owaspCategory });
  const gapStatement = f.description ? `${f.title} — ${f.description}` : f.title;
  return {
    source_finding_id: `ac3:eng:${engagementId}:finding:${f.id}`,
    system_ref: null as string | null, // engagement↔system map lands in Phase 2
    control_ids: tag.controlIds,
    ...(tag.untaggedReason ? { untagged_reason: tag.untaggedReason } : {}),
    gap_statement: gapStatement,
    severity: mapSeverity(f.severity),
    finding_type: mapFindingType(f.corroborationTier),
    cve: f.cve ?? null,
    cwe: f.cwe ?? null,
    mitre_technique: f.mitreTechnique ?? null,
    owasp_category: f.owaspCategory ?? null,
    tool: f.tool ?? null,
    source: f.source ?? null,
    detected_at: epochToIso(f.createdAt),
  };
}

/** Build Payload B (evidence → poam_evidence + links) from a ksiEvidence row. */
export function buildEvidencePayload(e: any) {
  return {
    source_evidence_id: e.evidenceId,
    system_ref: null as string | null,
    control_ids: e.ksiId ? [e.ksiId] : [],
    linked_source_finding_ids: [] as string[], // wired in Phase 2 via sourceId
    file_name: e.title,
    artifact: {
      storage: "s3" as const,
      path: e.sourceId ?? "",
      mime_type: "application/json",
      size: null as number | null,
    },
    provenance: {
      integrity_hash: normalizeHash(e.integrityHash, e.hashAlgorithm),
      previous_hash: normalizeHash(e.previousHash, e.hashAlgorithm),
      collection_method: e.collectionMethod ?? "automated",
      source_module: e.sourceModule,
      timestamp: e.createdAt ?? null,
    },
    notes: e.description ?? null,
  };
}
