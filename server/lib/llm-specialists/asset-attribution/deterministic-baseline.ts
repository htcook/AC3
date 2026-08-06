/**
 * Asset Attribution Specialist — Deterministic Baseline
 * 
 * Rule-based attribution that runs without LLM. Produces baseline claims
 * that the LLM augments within bounded deltas. If the LLM is unavailable,
 * the deterministic baseline is the final output.
 */

import type {
  AttributionClaim,
  StructuredEvidencePackage,
  EvidenceReference,
} from "../types";
import { isGenericCertificateIssuer, isPrivacyProxy, isCDNProvider, isHostingProvider } from "../evidence-package";

// ─── Convergence Detection ────────────────────────────────────────

interface ConvergenceResult {
  allClaimsAgreeOnOrganization: boolean;
  normalizedOrg?: string;
  sourceCount: number;
}

function normalizeForComparison(name: string): string {
  return name
    .toLowerCase()
    .replace(/[,.\-_'"]/g, " ")
    .replace(/\b(inc|llc|ltd|corp|co|na|n\.a\.|plc|gmbh|ag|sa|the)\b/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function detectConvergence(claims: AttributionClaim[]): ConvergenceResult {
  if (claims.length < 2) {
    return { allClaimsAgreeOnOrganization: false, sourceCount: claims.length };
  }

  const normalized = claims.map(c => normalizeForComparison(c.attributedTo.organization));
  const unique = [...new Set(normalized)];

  return {
    allClaimsAgreeOnOrganization: unique.length === 1,
    normalizedOrg: unique.length === 1 ? unique[0] : undefined,
    sourceCount: claims.length,
  };
}

// ─── Deterministic Attribution Rules ──────────────────────────────

export function computeDeterministicAttribution(
  pkg: StructuredEvidencePackage
): AttributionClaim[] {
  const claims: AttributionClaim[] = [];

  // Rule 1: Certificate Subject O is strong identity signal
  if (pkg.certificate?.subjectO) {
    const subjectO = pkg.certificate.subjectO;
    if (!isGenericCertificateIssuer(subjectO)) {
      claims.push({
        attributedTo: { organization: subjectO },
        claimType: "primary_owner",
        confidence: "medium",
        confidenceScore: 55,
        supportingEvidence: [{
          source: "certificate.subject_o",
          evidenceType: "direct_identity",
          weight: "strong",
          detail: subjectO,
        }],
        reasoning: "Certificate Subject O field provides direct identity attribution.",
      });
    }
  }

  // Rule 2: WHOIS/RDAP registrant is strong identity signal (unless privacy-masked)
  if (pkg.whois?.registrantOrg && !isPrivacyProxy(pkg.whois.registrantOrg)) {
    const registrantOrg = pkg.whois.registrantOrg;
    claims.push({
      attributedTo: { organization: registrantOrg },
      claimType: "primary_owner",
      confidence: "medium",
      confidenceScore: 50,
      supportingEvidence: [{
        source: "whois.registrant_org",
        evidenceType: "direct_identity",
        weight: "strong",
        detail: registrantOrg,
      }],
      reasoning: "WHOIS registrant organization provides direct identity attribution.",
    });
  } else if (pkg.whois?.registrant && !isPrivacyProxy(pkg.whois.registrant)) {
    const registrant = pkg.whois.registrant;
    claims.push({
      attributedTo: { organization: registrant },
      claimType: "primary_owner",
      confidence: "low",
      confidenceScore: 35,
      supportingEvidence: [{
        source: "whois.registrant",
        evidenceType: "direct_identity",
        weight: "moderate",
        detail: registrant,
      }],
      reasoning: "WHOIS registrant name (individual, not org) provides partial identity attribution.",
    });
  }

  // Rule 3: BGP AS holder is moderate identity signal
  if (pkg.bgp?.asHolder) {
    const asHolder = pkg.bgp.asHolder;
    // Check if this is a hosting/CDN provider (different claim type)
    if (isCDNProvider(asHolder) || isHostingProvider(asHolder)) {
      claims.push({
        attributedTo: { organization: asHolder },
        claimType: "third_party_hosted",
        confidence: "medium",
        confidenceScore: 60,
        supportingEvidence: [{
          source: "bgp.as_holder",
          evidenceType: "infrastructure_identity",
          weight: "moderate",
          detail: asHolder,
        }],
        reasoning: `BGP AS holder "${asHolder}" is a known hosting/CDN provider, indicating third-party hosting.`,
      });
    } else {
      claims.push({
        attributedTo: { organization: asHolder },
        claimType: "primary_owner",
        confidence: "medium",
        confidenceScore: 45,
        supportingEvidence: [{
          source: "bgp.as_holder",
          evidenceType: "network_identity",
          weight: "moderate",
          detail: asHolder,
        }],
        reasoning: "BGP AS holder provides network-level identity attribution.",
      });
    }
  }

  // Rule 4: SEC EDGAR match is corroborating signal
  if (pkg.businessIntel?.secEdgarMatch) {
    const sec = pkg.businessIntel.secEdgarMatch;
    claims.push({
      attributedTo: {
        organization: sec.companyName,
        organizationType: "public_company",
      },
      claimType: "primary_owner",
      confidence: "medium",
      confidenceScore: 50,
      supportingEvidence: [{
        source: "businessIntel.secEdgarMatch",
        evidenceType: "corroborating_business",
        weight: "moderate",
        detail: `${sec.companyName} (CIK: ${sec.cik})`,
      }],
      reasoning: "SEC EDGAR filing match provides corroborating business identity.",
    });
  }

  // Rule 5: Cross-reference convergence elevates confidence
  const convergence = detectConvergence(claims);
  if (convergence.allClaimsAgreeOnOrganization && claims.length >= 2) {
    // Find the strongest claim and boost it
    const strongest = claims.reduce((a, b) =>
      a.confidenceScore > b.confidenceScore ? a : b
    );

    // Merge all supporting evidence into the strongest claim
    const allEvidence: EvidenceReference[] = [];
    for (const claim of claims) {
      if (claim !== strongest) {
        allEvidence.push(...claim.supportingEvidence);
      }
    }
    strongest.supportingEvidence.push(...allEvidence);

    strongest.confidence = "high";
    strongest.confidenceScore = Math.min(
      80 + (claims.length - 2) * 5,  // +5 per additional converging source
      95
    );
    strongest.reasoning += ` Multi-source convergence detected across ${claims.length} independent sources.`;
  }

  // Rule 6: Handle intentionally obscured assets
  if (claims.length === 0) {
    const obscurationSignals: string[] = [];
    if (pkg.whois?.privacyProtected) {
      obscurationSignals.push("WHOIS privacy protection enabled");
    }
    if (!pkg.certificate?.subjectO || isGenericCertificateIssuer(pkg.certificate?.subjectO || "")) {
      obscurationSignals.push("Generic or missing certificate Subject O");
    }
    if (!pkg.bgp?.asHolder) {
      obscurationSignals.push("No BGP AS holder information");
    }

    if (obscurationSignals.length >= 2) {
      claims.push({
        attributedTo: { organization: "Unknown (intentionally obscured)" },
        claimType: "unknown",
        confidence: "low",
        confidenceScore: 10,
        supportingEvidence: obscurationSignals.map((signal, i) => ({
          source: `negative_evidence.signal_${i}`,
          evidenceType: "absence_of_evidence",
          weight: "weak" as const,
          detail: signal,
        })),
        reasoning: `Asset ownership appears intentionally obscured. ${obscurationSignals.length} standard attribution sources are missing or masked: ${obscurationSignals.join("; ")}.`,
      });
    }
  }

  // Rule 7: Detect multi-tenant / hosted-but-branded patterns
  const primaryOwnerClaims = claims.filter(c => c.claimType === "primary_owner");
  const hostedClaims = claims.filter(c => c.claimType === "third_party_hosted");

  if (primaryOwnerClaims.length > 0 && hostedClaims.length > 0) {
    // Mark the primary owner as the service brand owner
    for (const claim of primaryOwnerClaims) {
      claim.reasoning += " Note: asset is hosted on third-party infrastructure — this claim covers service/brand ownership.";
    }
    for (const claim of hostedClaims) {
      claim.reasoning += " Note: this claim covers infrastructure ownership only.";
    }
  }

  return claims;
}
