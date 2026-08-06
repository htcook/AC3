/**
 * Evidence Package Construction
 * 
 * Assembles raw discovery data into structured evidence packages
 * consumed by all specialists. The package is the single input format
 * that every specialist receives — no specialist accesses raw data directly.
 */

import type {
  StructuredEvidencePackage,
  CertificateEvidence,
  DNSEvidence,
  BGPEvidence,
  WHOISEvidence,
  HTTPEvidence,
  BusinessIntelEvidence,
} from "./types";
import { createHash } from "crypto";

// ─── Generic Issuer Detection ─────────────────────────────────────
const GENERIC_ISSUERS = [
  "let's encrypt", "letsencrypt", "cloudflare", "amazon", "google trust",
  "digicert", "comodo", "sectigo", "godaddy", "globalsign", "entrust",
  "r3", "e1", "isrg root",
];

export function isGenericCertificateIssuer(subjectO: string): boolean {
  const lower = subjectO.toLowerCase().trim();
  return GENERIC_ISSUERS.some(g => lower.includes(g)) || lower.length < 3;
}

// ─── Privacy Proxy Detection ──────────────────────────────────────
const PRIVACY_PROXIES = [
  "whoisguard", "domains by proxy", "contact privacy", "privacy protect",
  "redacted for privacy", "data protected", "withheld for privacy",
  "identity protection", "perfect privacy", "whois privacy",
  "domain protection", "private registration",
];

export function isPrivacyProxy(registrant: string): boolean {
  const lower = registrant.toLowerCase().trim();
  return PRIVACY_PROXIES.some(p => lower.includes(p));
}

// ─── CDN / Hosting Detection ──────────────────────────────────────
const CDN_PROVIDERS = [
  "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
  "sucuri", "stackpath", "keycdn", "bunnycdn", "cdn77",
];

const HOSTING_PROVIDERS = [
  "amazon", "aws", "google cloud", "gcp", "microsoft azure", "azure",
  "digitalocean", "linode", "vultr", "hetzner", "ovh", "rackspace",
  "heroku", "vercel", "netlify", "render", "fly.io",
];

export function isCDNProvider(name: string): boolean {
  const lower = name.toLowerCase();
  return CDN_PROVIDERS.some(c => lower.includes(c));
}

export function isHostingProvider(name: string): boolean {
  const lower = name.toLowerCase();
  return HOSTING_PROVIDERS.some(h => lower.includes(h));
}

// ─── Evidence Package Builder ─────────────────────────────────────

/**
 * Build a structured evidence package from raw discovery data.
 * This is the canonical entry point — all specialists consume this format.
 */
export function buildEvidencePackage(
  assetIdentifier: string,
  discoveryResult: any,
  whoisData?: any,
  httpFingerprint?: any,
  businessIntelData?: any
): StructuredEvidencePackage {
  const pkg: StructuredEvidencePackage = {
    assetId: generateAssetId(assetIdentifier),
    assetIdentifier,
    observedIPs: [],
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  };

  // Extract from discovery result (Shodan/Censys/SecurityTrails format)
  if (discoveryResult) {
    if (discoveryResult.hosts) {
      pkg.observedIPs = discoveryResult.hosts
        .map((h: any) => h.ip || h.ip_str)
        .filter(Boolean);
    }
    if (discoveryResult.ip_str) {
      pkg.observedIPs = [discoveryResult.ip_str, ...(pkg.observedIPs || [])];
    }

    // Certificate evidence
    pkg.certificate = extractCertificateEvidence(discoveryResult);

    // DNS evidence
    pkg.dns = extractDNSEvidence(discoveryResult);

    // BGP evidence
    pkg.bgp = extractBGPEvidence(discoveryResult);
  }

  // WHOIS evidence
  if (whoisData) {
    pkg.whois = extractWHOISEvidence(whoisData);
  }

  // HTTP evidence
  if (httpFingerprint) {
    pkg.http = extractHTTPEvidence(httpFingerprint);
  } else if (discoveryResult) {
    pkg.http = extractHTTPEvidence(discoveryResult);
  }

  // Business intelligence
  if (businessIntelData) {
    pkg.businessIntel = extractBusinessIntelEvidence(businessIntelData);
  }

  // Cross-reference convergence analysis
  pkg.crossReferenceConvergence = computeCrossReferenceConvergence(pkg);

  // Negative evidence (what was checked but not found)
  pkg.negativeEvidence = computeNegativeEvidence(pkg);

  return pkg;
}

// ─── Evidence Extractors ──────────────────────────────────────────

function extractCertificateEvidence(data: any): CertificateEvidence | undefined {
  const cert = data.ssl?.cert || data.tls?.certificate || data.certificate;
  if (!cert) return undefined;

  const subject = cert.subject || {};
  const issuer = cert.issuer || {};
  const validity = cert.validity || {};

  return {
    subjectO: subject.O || subject.organization || cert.subject_o,
    subjectCN: subject.CN || subject.common_name || cert.subject_cn,
    issuerO: issuer.O || issuer.organization || cert.issuer_o,
    issuerCN: issuer.CN || issuer.common_name || cert.issuer_cn,
    san: cert.extensions?.subjectAltName || cert.san || cert.names,
    validFrom: validity.start || validity.notBefore || cert.valid_from,
    validTo: validity.end || validity.notAfter || cert.valid_to,
    serialNumber: cert.serial || cert.serialNumber,
    signatureAlgorithm: cert.sig_alg || cert.signatureAlgorithm,
    isExpired: validity.end ? new Date(validity.end) < new Date() : undefined,
    isSelfSigned: subject.O === issuer.O && subject.CN === issuer.CN,
    isWildcard: (subject.CN || "").startsWith("*."),
  };
}

function extractDNSEvidence(data: any): DNSEvidence | undefined {
  const dns = data.dns || data.dnsRecords || {};
  if (!dns && !data.hostnames) return undefined;

  return {
    aRecords: dns.a || dns.A,
    aaaaRecords: dns.aaaa || dns.AAAA,
    cnameChain: dns.cname || dns.CNAME,
    mxRecords: dns.mx || dns.MX,
    nsRecords: dns.ns || dns.NS,
    txtRecords: dns.txt || dns.TXT,
    soaRecord: dns.soa || dns.SOA,
    reversePtr: data.hostnames?.[0] || dns.ptr,
    registrar: dns.registrar,
    creationDate: dns.creation_date || dns.creationDate,
    expirationDate: dns.expiration_date || dns.expirationDate,
  };
}

function extractBGPEvidence(data: any): BGPEvidence | undefined {
  const bgp = data.bgp || data.asn_info || {};
  const asn = data.asn || bgp.asn;
  if (!asn && !bgp.asHolder) return undefined;

  return {
    asn: typeof asn === "number" ? asn : parseInt(asn, 10) || undefined,
    asHolder: bgp.asHolder || bgp.org || data.org,
    prefix: bgp.prefix || bgp.network,
    rir: bgp.rir,
    country: bgp.country || data.country_code,
    peerCount: bgp.peerCount,
  };
}

function extractWHOISEvidence(whois: any): WHOISEvidence {
  return {
    registrant: whois.registrant || whois.registrant_name,
    registrantOrg: whois.registrant_org || whois.registrantOrganization || whois.org,
    registrantCountry: whois.registrant_country || whois.country,
    adminContact: whois.admin_contact || whois.adminName,
    techContact: whois.tech_contact || whois.techName,
    nameServers: whois.name_servers || whois.nameServers,
    creationDate: whois.creation_date || whois.creationDate,
    updatedDate: whois.updated_date || whois.updatedDate,
    expirationDate: whois.expiration_date || whois.expirationDate,
    privacyProtected: whois.privacy_protected ?? isPrivacyProxy(whois.registrant || ""),
    registrar: whois.registrar,
  };
}

function extractHTTPEvidence(data: any): HTTPEvidence | undefined {
  const http = data.http || data.httpFingerprint || {};
  if (!http.server && !http.title && !http.technologies) return undefined;

  return {
    serverHeader: http.server || http.serverHeader,
    poweredBy: http.poweredBy || http["x-powered-by"],
    technologies: http.technologies || http.components
      ? Object.keys(http.components || {})
      : undefined,
    title: http.title || http.html_title,
    metaGenerator: http.metaGenerator,
    securityHeaders: http.securityHeaders,
    statusCode: http.status || http.statusCode,
    redirectChain: http.redirectChain || http.redirect_chain,
    responseTimeMs: http.responseTimeMs,
    contentLength: http.contentLength,
  };
}

function extractBusinessIntelEvidence(data: any): BusinessIntelEvidence {
  return {
    secEdgarMatch: data.secEdgar || data.sec_edgar,
    publicReferences: data.publicReferences || data.public_references,
    linkedinMatch: data.linkedin || data.linkedinMatch,
    crunchbaseMatch: data.crunchbase || data.crunchbaseMatch,
    sector: data.sector,
    industry: data.industry,
    employeeCount: data.employeeCount || data.employee_count,
  };
}

// ─── Cross-Reference Convergence ──────────────────────────────────

function computeCrossReferenceConvergence(pkg: StructuredEvidencePackage) {
  const sources: string[] = [];
  const orgNames: string[] = [];

  if (pkg.certificate?.subjectO && !isGenericCertificateIssuer(pkg.certificate.subjectO)) {
    sources.push("certificate.subject_o");
    orgNames.push(normalizeOrgName(pkg.certificate.subjectO));
  }
  if (pkg.whois?.registrantOrg && !isPrivacyProxy(pkg.whois.registrantOrg)) {
    sources.push("whois.registrant_org");
    orgNames.push(normalizeOrgName(pkg.whois.registrantOrg));
  }
  if (pkg.bgp?.asHolder) {
    sources.push("bgp.as_holder");
    orgNames.push(normalizeOrgName(pkg.bgp.asHolder));
  }
  if (pkg.businessIntel?.secEdgarMatch) {
    sources.push("sec_edgar.company_name");
    orgNames.push(normalizeOrgName(pkg.businessIntel.secEdgarMatch.companyName));
  }

  const uniqueNormalized = [...new Set(orgNames)];
  const divergences = uniqueNormalized.length > 1 ? orgNames : undefined;

  return {
    sourcesChecked: sources,
    convergingOn: uniqueNormalized.length === 1 ? orgNames[0] : undefined,
    divergences,
  };
}

function normalizeOrgName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[,.\-_]/g, " ")
    .replace(/\b(inc|llc|ltd|corp|co|na|n\.a\.|plc|gmbh|ag|sa)\b/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

// ─── Negative Evidence ────────────────────────────────────────────

function computeNegativeEvidence(pkg: StructuredEvidencePackage) {
  const checkedButNotFound: string[] = [];

  if (!pkg.certificate?.subjectO) {
    checkedButNotFound.push("No organization in certificate Subject O field");
  }
  if (!pkg.whois || pkg.whois.privacyProtected) {
    checkedButNotFound.push("WHOIS registrant privacy-protected or unavailable");
  }
  if (!pkg.bgp?.asHolder) {
    checkedButNotFound.push("No BGP AS holder information available");
  }
  if (!pkg.businessIntel?.secEdgarMatch) {
    checkedButNotFound.push("No SEC EDGAR match found");
  }
  if (!pkg.http?.technologies?.length) {
    checkedButNotFound.push("No technology stack detected from HTTP fingerprint");
  }
  if (!pkg.dns?.mxRecords?.length) {
    checkedButNotFound.push("No MX records found (no email infrastructure)");
  }

  return { checkedButNotFound };
}

// ─── Package Rendering for LLM Prompts ────────────────────────────

/**
 * Render an evidence package into a human-readable format for LLM consumption.
 * This is the text the LLM actually sees as its input.
 */
export function renderEvidencePackage(pkg: StructuredEvidencePackage): string {
  const sections: string[] = [];

  sections.push(`# EVIDENCE PACKAGE FOR: ${pkg.assetIdentifier}`);
  sections.push(`Asset ID: ${pkg.assetId}`);
  if (pkg.observedIPs?.length) {
    sections.push(`Observed IPs: ${pkg.observedIPs.join(", ")}`);
  }
  sections.push(`First Seen: ${pkg.firstSeen || "unknown"}`);
  sections.push(`Last Seen: ${pkg.lastSeen || "unknown"}`);

  // Section 1: Direct Identity Evidence
  sections.push("\n## 1. DIRECT IDENTITY EVIDENCE");

  if (pkg.certificate) {
    sections.push("\n### Certificate");
    if (pkg.certificate.subjectO) sections.push(`Subject O: ${pkg.certificate.subjectO}`);
    if (pkg.certificate.subjectCN) sections.push(`Subject CN: ${pkg.certificate.subjectCN}`);
    if (pkg.certificate.issuerO) sections.push(`Issuer O: ${pkg.certificate.issuerO}`);
    if (pkg.certificate.issuerCN) sections.push(`Issuer CN: ${pkg.certificate.issuerCN}`);
    if (pkg.certificate.san?.length) sections.push(`SAN: ${pkg.certificate.san.join(", ")}`);
    if (pkg.certificate.validFrom) sections.push(`Valid From: ${pkg.certificate.validFrom}`);
    if (pkg.certificate.validTo) sections.push(`Valid To: ${pkg.certificate.validTo}`);
    if (pkg.certificate.isExpired) sections.push(`Status: EXPIRED`);
    if (pkg.certificate.isSelfSigned) sections.push(`Type: Self-signed`);
    if (pkg.certificate.isWildcard) sections.push(`Type: Wildcard`);
  } else {
    sections.push("No certificate data available.");
  }

  if (pkg.whois) {
    sections.push("\n### WHOIS / RDAP");
    if (pkg.whois.registrant) sections.push(`Registrant: ${pkg.whois.registrant}`);
    if (pkg.whois.registrantOrg) sections.push(`Registrant Org: ${pkg.whois.registrantOrg}`);
    if (pkg.whois.registrantCountry) sections.push(`Country: ${pkg.whois.registrantCountry}`);
    if (pkg.whois.registrar) sections.push(`Registrar: ${pkg.whois.registrar}`);
    if (pkg.whois.creationDate) sections.push(`Created: ${pkg.whois.creationDate}`);
    if (pkg.whois.expirationDate) sections.push(`Expires: ${pkg.whois.expirationDate}`);
    if (pkg.whois.privacyProtected) sections.push(`Privacy: PROTECTED`);
    if (pkg.whois.nameServers?.length) sections.push(`Name Servers: ${pkg.whois.nameServers.join(", ")}`);
  } else {
    sections.push("\n### WHOIS / RDAP\nNo WHOIS data available.");
  }

  if (pkg.bgp) {
    sections.push("\n### BGP / Network Attribution");
    if (pkg.bgp.asn) sections.push(`ASN: AS${pkg.bgp.asn}`);
    if (pkg.bgp.asHolder) sections.push(`AS Holder: ${pkg.bgp.asHolder}`);
    if (pkg.bgp.prefix) sections.push(`Prefix: ${pkg.bgp.prefix}`);
    if (pkg.bgp.rir) sections.push(`RIR: ${pkg.bgp.rir}`);
    if (pkg.bgp.country) sections.push(`Country: ${pkg.bgp.country}`);
  } else {
    sections.push("\n### BGP / Network Attribution\nNo BGP data available.");
  }

  // Section 2: DNS Evidence
  sections.push("\n## 2. DNS EVIDENCE");
  if (pkg.dns) {
    if (pkg.dns.aRecords?.length) sections.push(`A Records: ${pkg.dns.aRecords.join(", ")}`);
    if (pkg.dns.cnameChain?.length) sections.push(`CNAME Chain: ${pkg.dns.cnameChain.join(" → ")}`);
    if (pkg.dns.mxRecords?.length) sections.push(`MX Records: ${pkg.dns.mxRecords.join(", ")}`);
    if (pkg.dns.nsRecords?.length) sections.push(`NS Records: ${pkg.dns.nsRecords.join(", ")}`);
    if (pkg.dns.txtRecords?.length) sections.push(`TXT Records: ${pkg.dns.txtRecords.join("; ")}`);
    if (pkg.dns.reversePtr) sections.push(`Reverse PTR: ${pkg.dns.reversePtr}`);
  } else {
    sections.push("No DNS data available.");
  }

  // Section 3: HTTP Evidence
  sections.push("\n## 3. HTTP EVIDENCE");
  if (pkg.http) {
    if (pkg.http.serverHeader) sections.push(`Server: ${pkg.http.serverHeader}`);
    if (pkg.http.poweredBy) sections.push(`Powered By: ${pkg.http.poweredBy}`);
    if (pkg.http.technologies?.length) sections.push(`Technologies: ${pkg.http.technologies.join(", ")}`);
    if (pkg.http.title) sections.push(`Title: ${pkg.http.title}`);
    if (pkg.http.statusCode) sections.push(`Status Code: ${pkg.http.statusCode}`);
    if (pkg.http.redirectChain?.length) sections.push(`Redirect Chain: ${pkg.http.redirectChain.join(" → ")}`);
  } else {
    sections.push("No HTTP data available.");
  }

  // Section 4: Business Intelligence
  sections.push("\n## 4. BUSINESS INTELLIGENCE");
  if (pkg.businessIntel) {
    if (pkg.businessIntel.secEdgarMatch) {
      const sec = pkg.businessIntel.secEdgarMatch;
      sections.push(`SEC EDGAR: ${sec.companyName} (CIK: ${sec.cik})`);
      if (sec.sicDescription) sections.push(`SIC: ${sec.sicDescription}`);
      if (sec.revenue) sections.push(`Revenue: ${sec.revenue}`);
    }
    if (pkg.businessIntel.sector) sections.push(`Sector: ${pkg.businessIntel.sector}`);
    if (pkg.businessIntel.industry) sections.push(`Industry: ${pkg.businessIntel.industry}`);
    if (pkg.businessIntel.employeeCount) sections.push(`Employees: ${pkg.businessIntel.employeeCount}`);
    if (pkg.businessIntel.publicReferences?.length) {
      sections.push(`Public References: ${pkg.businessIntel.publicReferences.join("; ")}`);
    }
  } else {
    sections.push("No business intelligence available.");
  }

  // Section 5: Cross-Reference Convergence
  sections.push("\n## 5. CROSS-REFERENCE CONVERGENCE");
  if (pkg.crossReferenceConvergence) {
    const xref = pkg.crossReferenceConvergence;
    sections.push(`Sources Checked: ${xref.sourcesChecked.join(", ") || "none"}`);
    if (xref.convergingOn) {
      sections.push(`Convergence: All sources converge on "${xref.convergingOn}"`);
    } else if (xref.divergences?.length) {
      sections.push(`Divergences: ${xref.divergences.join(", ")}`);
    } else {
      sections.push("No convergence pattern detected (insufficient sources).");
    }
  }

  // Section 6: Negative Evidence
  sections.push("\n## 6. NEGATIVE EVIDENCE (checked but not found)");
  if (pkg.negativeEvidence?.checkedButNotFound?.length) {
    pkg.negativeEvidence.checkedButNotFound.forEach(item => {
      sections.push(`- ${item}`);
    });
  } else {
    sections.push("All expected evidence sources returned data.");
  }

  return sections.join("\n");
}

// ─── Utilities ────────────────────────────────────────────────────

function generateAssetId(identifier: string): string {
  return createHash("sha256").update(identifier).digest("hex").slice(0, 16);
}

/**
 * Hash an evidence package for caching and evidence chain tracking.
 */
export function hashPackage(pkg: StructuredEvidencePackage): string {
  const content = JSON.stringify(pkg, Object.keys(pkg).sort());
  return createHash("sha256").update(content).digest("hex").slice(0, 32);
}
