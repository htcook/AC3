import "./chunk-KFQGP6VL.js";

// server/lib/discovery-context-engine.ts
function buildEvidencePackage(assetIdentifier, discoveryResult, whoisData, httpFingerprint, businessIntelData) {
  const host = discoveryResult.hosts.find(
    (h) => h.hostnames.includes(assetIdentifier) || h.ip === assetIdentifier
  );
  const subdomain = discoveryResult.subdomains.find(
    (s) => s.subdomain === assetIdentifier
  );
  const matchingCerts = discoveryResult.certificates.filter(
    (c) => c.subject.includes(assetIdentifier) || c.sans.some((san) => san === assetIdentifier || san === `*.${assetIdentifier.split(".").slice(1).join(".")}`)
  );
  const primaryCert = matchingCerts[0] || null;
  const certEvidence = primaryCert ? {
    issuer: primaryCert.issuer,
    subjectCN: primaryCert.subject,
    sanEntries: primaryCert.sans,
    organizationInSubject: extractOrgFromCertSubject(primaryCert.subject),
    validFrom: primaryCert.validFrom,
    validTo: primaryCert.validTo,
    isExpired: primaryCert.isExpired,
    isWildcard: primaryCert.isWildcard,
    firstObservedInCTLogs: null
    // Would come from CT log data
  } : null;
  const relevantDNS = discoveryResult.dnsRecords;
  const aRecords = relevantDNS.filter((r) => r.type === "A" || r.type === "AAAA").map((r) => ({ value: r.value, firstSeen: r.firstSeen, lastSeen: r.lastSeen }));
  const mxRecords = relevantDNS.filter((r) => r.type === "MX").map((r) => ({ value: r.value }));
  const nsRecords = relevantDNS.filter((r) => r.type === "NS").map((r) => r.value);
  const txtRecords = relevantDNS.filter((r) => r.type === "TXT").map((r) => r.value);
  const cnameRecords = relevantDNS.filter((r) => r.type === "CNAME").map((r) => r.value);
  const soaRecord = relevantDNS.find((r) => r.type === "SOA")?.value || null;
  const allFirstSeen = relevantDNS.map((r) => r.firstSeen).filter((d) => d !== null).sort();
  const stableSince = allFirstSeen[0] || null;
  const dnsEvidence = {
    aRecords,
    mxRecords,
    nsRecords,
    txtRecords,
    soaRecord,
    cnameChain: cnameRecords,
    stableSince
  };
  const bgpEvidence = {
    asn: host?.asn || null,
    asnOrganization: host?.organization || null,
    isp: host?.isp || null,
    ipRange: null,
    adjacentIPs: []
  };
  const whoisEvidence = whoisData ? {
    registrantOrganization: whoisData.registrant?.organization || null,
    registrantName: whoisData.registrant?.name || null,
    registrantCountry: whoisData.registrant?.country || null,
    registrationDate: whoisData.created_date || whoisData.creationDate || null,
    expirationDate: whoisData.expiry_date || whoisData.expirationDate || null,
    adminContact: whoisData.admin?.email || null,
    nameServers: whoisData.nameservers || [],
    lastUpdated: whoisData.updated_date || null
  } : null;
  const httpEvidence = httpFingerprint ? {
    statusCode: httpFingerprint.statusCode || null,
    serverHeader: httpFingerprint.server || null,
    poweredByHeader: httpFingerprint.poweredBy || null,
    technologies: httpFingerprint.technologies || [],
    faviconHash: httpFingerprint.faviconHash || null,
    hostnamePattern: extractHostnamePattern(assetIdentifier),
    contentKeywords: httpFingerprint.keywords || [],
    responseHeaders: httpFingerprint.headers || {}
  } : null;
  const bizEvidence = businessIntelData ? {
    secEdgarCIK: businessIntelData.cik || null,
    businessSegments: businessIntelData.segments || [],
    industry: businessIntelData.industry || null,
    employeeCount: businessIntelData.employeeCount || null,
    headquarters: businessIntelData.headquarters || null,
    subsidiaries: businessIntelData.subsidiaries || [],
    regulatoryRegimes: businessIntelData.regulatoryRegimes || []
  } : null;
  const scanTargetDomain = discoveryResult.targets?.[0]?.domain || discoveryResult.targets?.[0]?.ip || assetIdentifier;
  return {
    assetIdentifier,
    resolvedIPs: subdomain?.ips || (host ? [host.ip] : []),
    certificate: certEvidence,
    dns: dnsEvidence,
    bgp: bgpEvidence,
    whois: whoisEvidence,
    http: httpEvidence,
    businessIntel: bizEvidence,
    externalContext: {
      customerStatedIndustry: null,
      customerStatedSize: null,
      scanTargetDomain
    },
    assembledAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function computeAttributionBaseline(pkg) {
  const claims = [];
  let baseConfidence = 0;
  const evidence = [];
  const contradictions = [];
  let orgName = null;
  if (pkg.certificate?.organizationInSubject) {
    orgName = pkg.certificate.organizationInSubject;
    baseConfidence += 25;
    evidence.push({
      source: "CERTIFICATE",
      evidenceType: "subject_organization",
      weight: "strong",
      detail: `Certificate subject organization: ${orgName}`
    });
  }
  if (pkg.whois?.registrantOrganization) {
    const whoisOrg = pkg.whois.registrantOrganization;
    if (orgName && normalizeOrgName(orgName) === normalizeOrgName(whoisOrg)) {
      baseConfidence += 25;
      evidence.push({
        source: "WHOIS",
        evidenceType: "registrant_organization",
        weight: "strong",
        detail: `WHOIS registrant matches certificate: ${whoisOrg}`
      });
    } else if (orgName && normalizeOrgName(orgName) !== normalizeOrgName(whoisOrg)) {
      contradictions.push({
        source: "WHOIS",
        evidenceType: "registrant_mismatch",
        detail: `WHOIS registrant (${whoisOrg}) differs from certificate org (${orgName})`
      });
      baseConfidence += 10;
    } else {
      orgName = whoisOrg;
      baseConfidence += 20;
      evidence.push({
        source: "WHOIS",
        evidenceType: "registrant_organization",
        weight: "moderate",
        detail: `WHOIS registrant organization: ${whoisOrg}`
      });
    }
  }
  if (pkg.bgp.asnOrganization) {
    const asnOrg = pkg.bgp.asnOrganization;
    if (orgName && normalizeOrgName(orgName).includes(normalizeOrgName(asnOrg).slice(0, 8))) {
      baseConfidence += 15;
      evidence.push({
        source: "BGP",
        evidenceType: "asn_organization",
        weight: "moderate",
        detail: `ASN organization corroborates: ${asnOrg} (AS${pkg.bgp.asn})`
      });
    } else if (!orgName) {
      orgName = asnOrg;
      baseConfidence += 10;
      evidence.push({
        source: "BGP",
        evidenceType: "asn_organization",
        weight: "weak",
        detail: `ASN organization: ${asnOrg} (AS${pkg.bgp.asn})`
      });
    }
  }
  if (pkg.dns.nsRecords.length > 0) {
    const nsDomain = pkg.dns.nsRecords[0].split(".").slice(-2).join(".");
    const assetDomain = pkg.assetIdentifier.split(".").slice(-2).join(".");
    if (nsDomain === assetDomain) {
      baseConfidence += 10;
      evidence.push({
        source: "DNS",
        evidenceType: "nameserver_self_hosted",
        weight: "moderate",
        detail: `Self-hosted nameservers on same domain: ${pkg.dns.nsRecords.join(", ")}`
      });
    }
  }
  const targetDomain = pkg.externalContext.scanTargetDomain;
  if (pkg.assetIdentifier.endsWith(`.${targetDomain}`) || pkg.assetIdentifier === targetDomain) {
    baseConfidence += 15;
    evidence.push({
      source: "DNS",
      evidenceType: "domain_pattern_match",
      weight: "strong",
      detail: `Asset domain matches scan target: ${targetDomain}`
    });
  }
  baseConfidence = Math.min(baseConfidence, 100);
  let claimType = "unknown";
  if (baseConfidence >= 60) claimType = "primary_owner";
  else if (baseConfidence >= 30) claimType = "third_party_hosted";
  if (isCDNProvider(pkg.bgp.asnOrganization || "") || isCDNProvider(pkg.certificate?.issuer || "")) {
    claimType = "cdn_fronted";
  }
  if (orgName) {
    claims.push({
      attributedTo: { organization: orgName },
      claimType,
      confidence: baseConfidence >= 70 ? "high" : baseConfidence >= 40 ? "medium" : "low",
      confidenceScore: baseConfidence,
      supportingEvidence: evidence,
      contradictingEvidence: contradictions,
      alternativeAttributions: []
    });
  }
  return claims;
}
function computeRoleBaseline(pkg) {
  const hostnameSignals = extractHostnameSignals(pkg.assetIdentifier);
  const technologies = pkg.http?.technologies || [];
  let exposure = "unknown";
  let exposureConfidence = 30;
  const exposureEvidence = [];
  if (hostnameSignals.includes("api.") || hostnameSignals.includes("www.") || hostnameSignals.includes("app.")) {
    exposure = "customer_facing";
    exposureConfidence = 70;
    exposureEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "moderate",
      detail: `Hostname pattern suggests customer-facing: ${hostnameSignals.join(", ")}`
    });
  } else if (hostnameSignals.includes("admin.") || hostnameSignals.includes("internal.") || hostnameSignals.includes("vpn.")) {
    exposure = "internal";
    exposureConfidence = 65;
    exposureEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "moderate",
      detail: `Hostname pattern suggests internal: ${hostnameSignals.join(", ")}`
    });
  } else if (hostnameSignals.includes("partner.") || hostnameSignals.includes("b2b.")) {
    exposure = "partner";
    exposureConfidence = 60;
    exposureEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "moderate",
      detail: `Hostname pattern suggests partner-facing: ${hostnameSignals.join(", ")}`
    });
  }
  let environment = "unknown";
  let envConfidence = 30;
  const envEvidence = [];
  if (hostnameSignals.includes("staging.") || hostnameSignals.includes("stg.")) {
    environment = "staging";
    envConfidence = 80;
    envEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "strong",
      detail: `Hostname contains staging indicator: ${hostnameSignals.join(", ")}`
    });
  } else if (hostnameSignals.includes("dev.") || hostnameSignals.includes("development.")) {
    environment = "development";
    envConfidence = 80;
    envEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "strong",
      detail: `Hostname contains development indicator`
    });
  } else if (hostnameSignals.includes("test.") || hostnameSignals.includes("qa.") || hostnameSignals.includes("uat.")) {
    environment = "testing";
    envConfidence = 75;
    envEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "strong",
      detail: `Hostname contains testing indicator`
    });
  } else if (!hostnameSignals.some((s) => ["staging.", "stg.", "dev.", "test.", "qa.", "uat."].includes(s))) {
    environment = "production";
    envConfidence = 50;
    envEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern_absence",
      weight: "weak",
      detail: `No non-production indicators in hostname \u2014 assumed production`
    });
  }
  let criticality = "unknown";
  let critConfidence = 30;
  const critEvidence = [];
  if (hostnameSignals.includes("backup.") || hostnameSignals.includes("dr.") || hostnameSignals.includes("failover.")) {
    criticality = "backup";
    critConfidence = 70;
    critEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "moderate",
      detail: `Hostname suggests backup/DR system`
    });
  } else if (hostnameSignals.includes("www.") || hostnameSignals.includes("api.") || hostnameSignals.includes("mail.")) {
    criticality = "primary";
    critConfidence = 65;
    critEvidence.push({
      source: "DNS",
      evidenceType: "hostname_pattern",
      weight: "moderate",
      detail: `Hostname suggests primary service endpoint`
    });
  }
  let inferredFunction = null;
  if (technologies.some((t) => /mail|smtp|exchange/i.test(t)) || hostnameSignals.includes("mail.")) {
    inferredFunction = "email server";
  } else if (hostnameSignals.includes("api.")) {
    inferredFunction = "API gateway";
  } else if (hostnameSignals.includes("cdn.") || hostnameSignals.includes("static.")) {
    inferredFunction = "CDN edge / static assets";
  } else if (hostnameSignals.includes("vpn.")) {
    inferredFunction = "VPN gateway";
  } else if (hostnameSignals.includes("ftp.")) {
    inferredFunction = "file transfer server";
  } else if (technologies.some((t) => /mysql|postgres|mongo|redis/i.test(t))) {
    inferredFunction = "database server";
  }
  return {
    exposure: { value: exposure, confidence: exposureConfidence, evidence: exposureEvidence },
    environment: { value: environment, confidence: envConfidence, evidence: envEvidence },
    criticality: { value: criticality, confidence: critConfidence, evidence: critEvidence },
    inferredFunction,
    hostnameSignals,
    technologyStack: technologies
  };
}
function computeLifecycleBaseline(pkg) {
  const signals = [];
  let activeScore = 0;
  let abandonedScore = 0;
  if (pkg.certificate) {
    const validTo = new Date(pkg.certificate.validTo);
    const now = /* @__PURE__ */ new Date();
    const daysUntilExpiry = (validTo.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24);
    if (pkg.certificate.isExpired) {
      abandonedScore += 30;
      signals.push({
        signalType: "cert_expired",
        value: pkg.certificate.validTo,
        interpretation: "Certificate is expired \u2014 strong indicator of abandonment",
        weight: "strong"
      });
    } else if (daysUntilExpiry < 30) {
      abandonedScore += 15;
      signals.push({
        signalType: "cert_near_expiry",
        value: `${Math.round(daysUntilExpiry)} days remaining`,
        interpretation: "Certificate near expiry without renewal \u2014 possible declining maintenance",
        weight: "moderate"
      });
    } else if (daysUntilExpiry > 180) {
      activeScore += 15;
      signals.push({
        signalType: "cert_well_maintained",
        value: `${Math.round(daysUntilExpiry)} days remaining`,
        interpretation: "Certificate has significant validity remaining \u2014 actively maintained",
        weight: "moderate"
      });
    }
  }
  if (pkg.dns.stableSince) {
    const stableDate = new Date(pkg.dns.stableSince);
    const now = /* @__PURE__ */ new Date();
    const daysSinceChange = (now.getTime() - stableDate.getTime()) / (1e3 * 60 * 60 * 24);
    if (daysSinceChange > 730) {
      abandonedScore += 20;
      signals.push({
        signalType: "dns_staleness",
        value: `${Math.round(daysSinceChange)} days since last DNS change`,
        interpretation: "DNS records unchanged for 2+ years \u2014 possible forgotten infrastructure",
        weight: "moderate"
      });
    } else if (daysSinceChange < 90) {
      activeScore += 15;
      signals.push({
        signalType: "dns_recent_update",
        value: `${Math.round(daysSinceChange)} days since last DNS change`,
        interpretation: "Recent DNS changes indicate active management",
        weight: "moderate"
      });
    }
  }
  if (pkg.http?.technologies && pkg.http.technologies.length > 0) {
    activeScore += 10;
    signals.push({
      signalType: "tech_detected",
      value: pkg.http.technologies.join(", "),
      interpretation: "Active technology stack detected",
      weight: "weak"
    });
  }
  if (pkg.http?.statusCode) {
    if (pkg.http.statusCode >= 200 && pkg.http.statusCode < 400) {
      activeScore += 10;
      signals.push({
        signalType: "http_responsive",
        value: `HTTP ${pkg.http.statusCode}`,
        interpretation: "Asset responding with success status",
        weight: "weak"
      });
    } else if (pkg.http.statusCode >= 500) {
      abandonedScore += 10;
      signals.push({
        signalType: "http_error",
        value: `HTTP ${pkg.http.statusCode}`,
        interpretation: "Server error may indicate unmaintained infrastructure",
        weight: "weak"
      });
    }
  }
  if (pkg.whois?.lastUpdated) {
    const lastUpdated = new Date(pkg.whois.lastUpdated);
    const now = /* @__PURE__ */ new Date();
    const daysSinceUpdate = (now.getTime() - lastUpdated.getTime()) / (1e3 * 60 * 60 * 24);
    if (daysSinceUpdate > 365 * 3) {
      abandonedScore += 10;
      signals.push({
        signalType: "whois_stale",
        value: `Last WHOIS update: ${pkg.whois.lastUpdated}`,
        interpretation: "WHOIS not updated in 3+ years",
        weight: "weak"
      });
    }
  }
  const netScore = activeScore - abandonedScore;
  let stage;
  let confidence;
  let riskMultiplier;
  if (netScore > 20) {
    stage = "active";
    confidence = Math.min(70 + netScore, 95);
    riskMultiplier = 1;
  } else if (netScore > -10) {
    stage = "declining";
    confidence = 50;
    riskMultiplier = 1.3;
  } else if (netScore <= -10) {
    stage = "abandoned";
    confidence = Math.min(60 + Math.abs(netScore), 90);
    riskMultiplier = 1.8;
  } else {
    stage = "unknown";
    confidence = 30;
    riskMultiplier = 1.2;
  }
  if (signals.length === 0) {
    stage = "unknown";
    confidence = 20;
    riskMultiplier = 1.2;
  }
  return { stage, confidence, signals, riskMultiplier };
}
function computeThreatRelevanceBaseline(pkg, sectorContext) {
  const sectorExposures = [];
  const activeCampaigns = [];
  let threatScore = 30;
  const technologies = pkg.http?.technologies || [];
  const hostnameSignals = extractHostnameSignals(pkg.assetIdentifier);
  if (sectorContext) {
    const sector = sectorContext.toLowerCase();
    if (sector.includes("finance") || sector.includes("banking")) {
      if (hostnameSignals.some((s) => /payment|swift|transaction|banking/i.test(s))) {
        threatScore += 20;
        sectorExposures.push({
          sector: "Financial Services",
          pattern: "Payment/transaction infrastructure exposure",
          matchStrength: "strong",
          indicators: hostnameSignals.filter((s) => /payment|swift|transaction|banking/i.test(s))
        });
      }
    }
    if (sector.includes("health")) {
      if (hostnameSignals.some((s) => /ehr|patient|telehealth|medical|fhir/i.test(s)) || technologies.some((t) => /epic|cerner|meditech/i.test(t))) {
        threatScore += 20;
        sectorExposures.push({
          sector: "Healthcare",
          pattern: "EHR/patient data system exposure",
          matchStrength: "strong",
          indicators: [...hostnameSignals, ...technologies].filter((s) => /ehr|patient|telehealth|medical|fhir|epic|cerner/i.test(s))
        });
      }
    }
    if (sector.includes("defense") || sector.includes("government")) {
      threatScore += 15;
      sectorExposures.push({
        sector: "Defense/Government",
        pattern: "Government sector asset \u2014 elevated nation-state interest",
        matchStrength: "moderate",
        indicators: []
      });
    }
    if (sector.includes("energy") || sector.includes("utility")) {
      if (hostnameSignals.some((s) => /scada|ot|plc|hmi|modbus/i.test(s))) {
        threatScore += 25;
        sectorExposures.push({
          sector: "Energy/Utilities",
          pattern: "SCADA/OT infrastructure exposure",
          matchStrength: "strong",
          indicators: hostnameSignals.filter((s) => /scada|ot|plc|hmi|modbus/i.test(s))
        });
      }
    }
  }
  const riskyTech = technologies.filter(
    (t) => /citrix|pulse|fortinet|sonicwall|palo alto|f5|exchange|sharepoint|confluence|jira/i.test(t)
  );
  if (riskyTech.length > 0) {
    threatScore += 15;
    activeCampaigns.push({
      campaignName: "Common Initial Access Targets",
      source: "KEV/CISA",
      matchedCharacteristics: riskyTech,
      urgency: "high"
    });
  }
  if (hostnameSignals.some((s) => /vpn|remote|rdp|citrix|gateway/i.test(s))) {
    threatScore += 10;
    activeCampaigns.push({
      campaignName: "Remote Access Targeting",
      source: "Threat Intelligence",
      matchedCharacteristics: hostnameSignals.filter((s) => /vpn|remote|rdp|citrix|gateway/i.test(s)),
      urgency: "medium"
    });
  }
  return {
    overallThreatScore: Math.min(threatScore, 100),
    sectorExposures,
    activeCampaigns
  };
}
function buildAttributionPrompt(pkg, baseline) {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  const baselineBlock = baseline.length > 0 ? `
DETERMINISTIC BASELINE:
Organization: ${baseline[0].attributedTo.organization}
Baseline Confidence: ${baseline[0].confidenceScore}/100
Claim Type: ${baseline[0].claimType}
Evidence Count: ${baseline[0].supportingEvidence.length} supporting, ${baseline[0].contradictingEvidence.length} contradicting
` : "\nDETERMINISTIC BASELINE:\nNo baseline attribution could be established from rule-based analysis.\n";
  return `You are a Discovery Context Analyst. Your role is to analyze structured discovery evidence and produce grounded attribution claims about digital assets. Your analysis should reflect 25 years of hands-on practitioner experience in penetration testing and security assessment. You prioritize verifiable evidence over plausible inference, and you explicitly flag uncertainty rather than producing confident-sounding speculation.

EVIDENCE GROUNDING REQUIREMENTS:
- Every claim must cite supporting evidence from the input package below.
- Claims without supporting evidence must not be made; instead, state that the evidence is insufficient.
- If multiple pieces of evidence contradict each other, surface the contradiction rather than picking a side.
- Do NOT use your training data to make attribution claims. Only use the evidence provided.
- You may adjust the baseline confidence by at most \xB120 points based on your synthesis of the evidence.

${evidenceBlock}
${baselineBlock}
EXTERNAL CONTEXT (do not cite as evidence):
- Customer stated industry: ${pkg.externalContext.customerStatedIndustry || "Not provided"}
- Customer stated size: ${pkg.externalContext.customerStatedSize || "Not provided"}
- Scan target domain: ${pkg.externalContext.scanTargetDomain}

CALIBRATION EXAMPLES:
1. When certificate org, WHOIS registrant, and ASN org all name the same entity \u2192 confidence 85-95, claim_type "primary_owner"
2. When certificate names one org but ASN belongs to AWS/Azure/GCP \u2192 confidence 60-75, claim_type "third_party_hosted"
3. When only domain pattern matches scan target, no other evidence \u2192 confidence 40-55, claim_type "primary_owner" (tentative)
4. When WHOIS is privacy-protected and certificate is Let's Encrypt \u2192 confidence 20-35, claim_type "unknown"

OUTPUT FORMAT: Respond with valid JSON matching this schema:
{
  "claims": [{
    "attributedTo": { "organization": "string", "legalEntity": "string|null", "parentOrganization": "string|null" },
    "claimType": "primary_owner|subsidiary|third_party_hosted|vendor_managed|cdn_fronted|shared_hosting|unknown",
    "confidenceScore": number_0_to_100,
    "confidence": "high|medium|low",
    "supportingEvidence": [{ "source": "string", "evidenceType": "string", "weight": "strong|moderate|weak", "detail": "string" }],
    "contradictingEvidence": [{ "source": "string", "evidenceType": "string", "detail": "string" }],
    "alternativeAttributions": [{ "organization": "string", "confidenceScore": number, "rationale": "string" }]
  }],
  "adjustmentRationale": "string explaining why you adjusted from baseline",
  "confidenceDelta": number_minus20_to_plus20
}`;
}
function buildRolePrompt(pkg, baseline) {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  return `You are an Asset Role Analyst. Your role is to determine the functional role, exposure level, and operational environment of a discovered digital asset based on structured evidence. You have 25 years of experience in infrastructure assessment and understand how organizations deploy and manage their systems.

EVIDENCE GROUNDING REQUIREMENTS:
- Every inference must cite supporting evidence from the input package.
- If evidence is insufficient for a determination, return "unknown" with an explanation.
- Do NOT guess based on training data. Only use the evidence provided.

${evidenceBlock}

DETERMINISTIC BASELINE:
- Exposure: ${baseline.exposure.value} (confidence: ${baseline.exposure.confidence})
- Environment: ${baseline.environment.value} (confidence: ${baseline.environment.confidence})
- Criticality: ${baseline.criticality.value} (confidence: ${baseline.criticality.confidence})
- Inferred function: ${baseline.inferredFunction || "None"}
- Hostname signals: ${baseline.hostnameSignals.join(", ") || "None"}
- Technology stack: ${baseline.technologyStack.join(", ") || "None"}

OUTPUT FORMAT: Respond with valid JSON:
{
  "exposure": { "value": "customer_facing|internal|partner|unknown", "confidence": number_0_to_100, "rationale": "string" },
  "environment": { "value": "production|staging|development|testing|unknown", "confidence": number_0_to_100, "rationale": "string" },
  "criticality": { "value": "primary|backup|auxiliary|unknown", "confidence": number_0_to_100, "rationale": "string" },
  "inferredFunction": "string|null",
  "adjustmentRationale": "string"
}`;
}
function buildLifecyclePrompt(pkg, baseline) {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  const signalsBlock = baseline.signals.map(
    (s) => `- ${s.signalType}: ${s.value} \u2192 ${s.interpretation} (${s.weight})`
  ).join("\n");
  return `You are a Lifecycle Stage Analyst. Your role is to determine whether a discovered digital asset is actively maintained, declining in maintenance, or abandoned. Forgotten infrastructure is where most catastrophic compromises start \u2014 your analysis directly impacts security prioritization.

EVIDENCE GROUNDING REQUIREMENTS:
- Every determination must cite temporal signals from the evidence.
- If evidence is insufficient, return "unknown" with explanation of what additional data would help.

${evidenceBlock}

DETERMINISTIC BASELINE:
- Stage: ${baseline.stage} (confidence: ${baseline.confidence})
- Temporal signals detected:
${signalsBlock || "  None"}

OUTPUT FORMAT: Respond with valid JSON:
{
  "stage": "active|declining|abandoned|unknown",
  "confidence": number_0_to_100,
  "riskMultiplier": number_1_to_2,
  "additionalSignals": [{ "signalType": "string", "value": "string", "interpretation": "string", "weight": "strong|moderate|weak" }],
  "adjustmentRationale": "string",
  "lastMaintenanceEstimate": "ISO date string|null"
}`;
}
function buildBusinessContextPrompt(pkg) {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  return `You are a Business Context Analyst. Your role is to infer the business significance of a discovered digital asset \u2014 which business unit it serves, what function it performs, whether it sits on a revenue path, and what regulatory regimes may apply. Your analysis enables the platform to say "these systems run your billing pipeline" rather than "we found 47 servers."

EVIDENCE GROUNDING REQUIREMENTS:
- Every business attribution must cite evidence from the input package.
- Regulatory exposure claims must cite specific indicators (payment keywords \u2192 PCI, health data \u2192 HIPAA).
- If no business context can be inferred, return null values with explanation.
- Do NOT fabricate business relationships from training data.

${evidenceBlock}

OUTPUT FORMAT: Respond with valid JSON:
{
  "businessUnit": { "name": "string|null", "function": "string|null", "revenuePath": "string|null", "confidence": number_0_to_100, "evidence": [{ "source": "string", "evidenceType": "string", "weight": "strong|moderate|weak", "detail": "string" }] },
  "regulatoryExposures": [{ "regime": "string", "indicators": ["string"], "confidence": number_0_to_100 }],
  "dependencies": [{ "targetAsset": "string", "relationshipType": "dns_chain|api_reference|cert_trust|bgp_adjacency|hosting_shared|code_reference", "confidence": number_0_to_100, "evidence": "string" }],
  "customerAttribution": { "servesTopCustomers": boolean, "customerIndicators": ["string"], "concentrationRisk": "high|medium|low|unknown" }
}`;
}
function buildThreatRelevancePrompt(pkg, baseline) {
  const evidenceBlock = formatEvidencePackageForPrompt(pkg);
  return `You are a Threat Relevance Analyst. Your role is to assess how relevant specific threat actors and attack campaigns are to a discovered digital asset. You correlate asset characteristics with known threat actor TTPs, sector-specific targeting patterns, and active campaigns. Your analysis should reflect deep knowledge of the threat landscape.

EVIDENCE GROUNDING REQUIREMENTS:
- Threat actor relevance claims must cite specific asset characteristics that match known TTPs.
- Active campaign correlations must reference specific campaign characteristics.
- Do NOT invent threat actor associations from training data alone.
- You may adjust the baseline threat score by at most \xB120 points.

${evidenceBlock}

DETERMINISTIC BASELINE:
- Overall threat score: ${baseline.overallThreatScore}/100
- Sector exposures detected: ${baseline.sectorExposures.length}
- Active campaign correlations: ${baseline.activeCampaigns.length}

OUTPUT FORMAT: Respond with valid JSON:
{
  "overallThreatScore": number_0_to_100,
  "actorRelevance": [{ "actorName": "string", "actorType": "apt|ransomware|hacktivist|cybercrime|unknown", "relevanceScore": number_0_to_100, "matchedTTPs": ["string"], "rationale": "string" }],
  "sectorExposures": [{ "sector": "string", "pattern": "string", "matchStrength": "strong|moderate|weak", "indicators": ["string"] }],
  "activeCampaigns": [{ "campaignName": "string", "source": "string", "matchedCharacteristics": ["string"], "urgency": "critical|high|medium|low" }],
  "geopoliticalExposure": { "nationStateInterest": "high|medium|low|none", "rationale": "string" },
  "adjustmentRationale": "string",
  "confidenceDelta": number_minus20_to_plus20
}`;
}
function validateEvidenceGrounding(llmOutput, pkg) {
  const ungroundedClaims = [];
  const warnings = [];
  const validSources = /* @__PURE__ */ new Set();
  if (pkg.certificate) validSources.add("CERTIFICATE");
  if (pkg.dns.aRecords.length > 0 || pkg.dns.nsRecords.length > 0) validSources.add("DNS");
  if (pkg.bgp.asn) validSources.add("BGP");
  if (pkg.whois) validSources.add("WHOIS");
  if (pkg.http) validSources.add("HTTP");
  if (pkg.businessIntel) validSources.add("BUSINESS_INTEL");
  if (llmOutput.claims && Array.isArray(llmOutput.claims)) {
    for (const claim of llmOutput.claims) {
      if (claim.supportingEvidence && Array.isArray(claim.supportingEvidence)) {
        for (const ev of claim.supportingEvidence) {
          if (!validSources.has(ev.source)) {
            ungroundedClaims.push(
              `Claim cites "${ev.source}" but no ${ev.source} evidence was in the package`
            );
          }
        }
      }
      if (llmOutput.confidenceDelta !== void 0) {
        if (Math.abs(llmOutput.confidenceDelta) > 20) {
          warnings.push(
            `Confidence delta ${llmOutput.confidenceDelta} exceeds \xB120 bound \u2014 clamping`
          );
        }
      }
    }
  }
  return {
    valid: ungroundedClaims.length === 0,
    ungroundedClaims,
    warnings
  };
}
function clampDelta(delta) {
  return Math.max(-20, Math.min(20, delta));
}
function applyBoundedDelta(baseline, delta) {
  const clampedDelta = clampDelta(delta);
  return Math.max(0, Math.min(100, baseline + clampedDelta));
}
function classifyDiscoveryTier(attribution, role, lifecycle, threatRelevance) {
  const attrConfidence = attribution.claims[0]?.confidenceScore || 0;
  const isProduction = role.role.environment.value === "production";
  const isCustomerFacing = role.role.exposure.value === "customer_facing";
  const isPrimary = role.role.criticality.value === "primary";
  const threatScore = threatRelevance.overallThreatScore;
  const isAbandoned = lifecycle.stage === "abandoned";
  if (attrConfidence >= 60 && isProduction && (isCustomerFacing || isPrimary) && threatScore >= 50) {
    return "bullseye";
  }
  if (attrConfidence >= 40 && isAbandoned && threatScore >= 30) {
    return "bullseye";
  }
  if (attrConfidence >= 40 && (isProduction || threatScore >= 30)) {
    return "perimeter";
  }
  if (attrConfidence >= 20) {
    return "peripheral";
  }
  return "unknown";
}
function generateNegativeFindings(pkg) {
  const negatives = [];
  if (!pkg.certificate) {
    negatives.push({
      checkedFor: "TLS certificate",
      result: "not_found",
      significance: "No TLS certificate found \u2014 asset may not serve HTTPS or certificate data unavailable"
    });
  }
  if (!pkg.whois) {
    negatives.push({
      checkedFor: "WHOIS registration data",
      result: "not_found",
      significance: "No WHOIS data available \u2014 domain registration details could not be verified"
    });
  }
  if (!pkg.http) {
    negatives.push({
      checkedFor: "HTTP response fingerprint",
      result: "not_found",
      significance: "No HTTP response captured \u2014 asset may not serve web content or was unreachable"
    });
  }
  if (!pkg.businessIntel) {
    negatives.push({
      checkedFor: "Business intelligence (SEC EDGAR, corporate registry)",
      result: "not_found",
      significance: "No public business intelligence found \u2014 organization may be private or data unavailable"
    });
  }
  if (pkg.dns.aRecords.length === 0) {
    negatives.push({
      checkedFor: "DNS A/AAAA records",
      result: "not_found",
      significance: "No DNS resolution \u2014 asset may be decommissioned or DNS not configured"
    });
  }
  if (!pkg.bgp.asn) {
    negatives.push({
      checkedFor: "BGP/ASN attribution",
      result: "not_found",
      significance: "No ASN data \u2014 IP-level attribution could not be established"
    });
  }
  return negatives;
}
async function analyzeAssetContext(assetIdentifier, discoveryResult, options = {}, whoisData, httpFingerprint, businessIntelData) {
  const startTime = Date.now();
  const pkg = buildEvidencePackage(
    assetIdentifier,
    discoveryResult,
    whoisData,
    httpFingerprint,
    businessIntelData
  );
  if (options.customerIndustry) pkg.externalContext.customerStatedIndustry = options.customerIndustry;
  if (options.customerSize) pkg.externalContext.customerStatedSize = options.customerSize;
  const attrBaseline = computeAttributionBaseline(pkg);
  const roleBaseline = computeRoleBaseline(pkg);
  const lifecycleBaseline = computeLifecycleBaseline(pkg);
  const threatBaseline = computeThreatRelevanceBaseline(pkg, options.customerIndustry);
  let attrMode = "deterministic_only";
  let roleMode = "deterministic_only";
  let lifecycleMode = "deterministic_only";
  let businessMode = "deterministic_only";
  let threatMode = "deterministic_only";
  let llmAttrDelta = 0;
  let llmThreatDelta = 0;
  if (!options.deterministicOnly && options.llmInvoke) {
    try {
      const attrPrompt = buildAttributionPrompt(pkg, attrBaseline);
      const attrResponse = await options.llmInvoke([
        { role: "system", content: "You are a Discovery Context Analyst. Respond only with valid JSON." },
        { role: "user", content: attrPrompt }
      ]);
      const attrParsed = JSON.parse(attrResponse.choices[0].message.content);
      const validation = validateEvidenceGrounding(attrParsed, pkg);
      if (validation.valid) {
        llmAttrDelta = clampDelta(attrParsed.confidenceDelta || 0);
        if (attrBaseline[0]) {
          attrBaseline[0].confidenceScore = applyBoundedDelta(attrBaseline[0].confidenceScore, llmAttrDelta);
          attrBaseline[0].confidence = attrBaseline[0].confidenceScore >= 70 ? "high" : attrBaseline[0].confidenceScore >= 40 ? "medium" : "low";
        }
        attrMode = "full_llm";
      } else {
        attrMode = "confidence_degraded";
        console.warn(`[DiscoveryContext] Attribution grounding failed for ${assetIdentifier}:`, validation.ungroundedClaims);
      }
    } catch (err) {
      attrMode = "confidence_degraded";
      console.warn(`[DiscoveryContext] Attribution LLM failed for ${assetIdentifier}:`, err.message);
    }
    try {
      const threatPrompt = buildThreatRelevancePrompt(pkg, threatBaseline);
      const threatResponse = await options.llmInvoke([
        { role: "system", content: "You are a Threat Relevance Analyst. Respond only with valid JSON." },
        { role: "user", content: threatPrompt }
      ]);
      const threatParsed = JSON.parse(threatResponse.choices[0].message.content);
      llmThreatDelta = clampDelta(threatParsed.confidenceDelta || 0);
      threatBaseline.overallThreatScore = applyBoundedDelta(threatBaseline.overallThreatScore, llmThreatDelta);
      if (threatParsed.actorRelevance) {
      }
      if (threatParsed.sectorExposures) {
        threatBaseline.sectorExposures.push(...threatParsed.sectorExposures);
      }
      threatMode = "full_llm";
    } catch (err) {
      threatMode = "confidence_degraded";
      console.warn(`[DiscoveryContext] Threat relevance LLM failed for ${assetIdentifier}:`, err.message);
    }
  }
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const processingTime = Date.now() - startTime;
  const attributionResult = {
    assetIdentifier,
    claims: attrBaseline,
    mode: attrMode,
    deterministicBaseline: attrBaseline[0]?.confidenceScore || 0,
    llmDelta: llmAttrDelta,
    processingTimeMs: processingTime,
    timestamp: now
  };
  const roleResult = {
    assetIdentifier,
    role: roleBaseline,
    mode: roleMode,
    processingTimeMs: processingTime,
    timestamp: now
  };
  const lifecycleResult = {
    assetIdentifier,
    stage: lifecycleBaseline.stage,
    confidence: lifecycleBaseline.confidence,
    signals: lifecycleBaseline.signals,
    riskMultiplier: lifecycleBaseline.riskMultiplier,
    lastMaintenanceEstimate: null,
    mode: lifecycleMode,
    processingTimeMs: processingTime,
    timestamp: now
  };
  const businessContextResult = {
    assetIdentifier,
    businessUnit: {
      businessUnit: pkg.businessIntel?.businessSegments?.[0]?.name || null,
      function: roleBaseline.inferredFunction,
      revenuePath: pkg.businessIntel?.businessSegments?.[0]?.revenue || null,
      confidence: pkg.businessIntel ? 40 : 10,
      evidence: pkg.businessIntel ? [{
        source: "BUSINESS_INTEL",
        evidenceType: "sec_edgar_segment",
        weight: "moderate",
        detail: `Business segment: ${pkg.businessIntel.businessSegments?.[0]?.name || "unknown"}`
      }] : []
    },
    regulatoryExposures: inferRegulatoryExposures(pkg),
    dependencies: [],
    customerAttribution: {
      servesTopCustomers: false,
      customerIndicators: [],
      concentrationRisk: "unknown"
    },
    mode: businessMode,
    processingTimeMs: processingTime,
    timestamp: now
  };
  const threatRelevanceResult = {
    assetIdentifier,
    overallThreatScore: threatBaseline.overallThreatScore,
    actorRelevance: [],
    sectorExposures: threatBaseline.sectorExposures,
    activeCampaigns: threatBaseline.activeCampaigns,
    geopoliticalExposure: { nationStateInterest: "none", rationale: "No specific geopolitical indicators detected" },
    mode: threatMode,
    processingTimeMs: processingTime,
    timestamp: now
  };
  const discoveryTier = classifyDiscoveryTier(
    attributionResult,
    roleResult,
    lifecycleResult,
    threatRelevanceResult
  );
  const negativeFindings = generateNegativeFindings(pkg);
  const overallConfidence = Math.round(
    (attributionResult.claims[0]?.confidenceScore || 0) * 0.3 + roleResult.role.exposure.confidence * 0.2 + lifecycleResult.confidence * 0.2 + businessContextResult.businessUnit.confidence * 0.15 + threatRelevanceResult.overallThreatScore * 0.15
  );
  return {
    assetIdentifier,
    evidencePackage: pkg,
    attribution: attributionResult,
    role: roleResult,
    lifecycle: lifecycleResult,
    businessContext: businessContextResult,
    threatRelevance: threatRelevanceResult,
    discoveryTier,
    overallConfidence,
    negativeFindings,
    processedAt: now
  };
}
async function analyzeDiscoveryContext(discoveryResult, options = {}, whoisData, httpFingerprints, businessIntelData) {
  const assetIds = /* @__PURE__ */ new Set();
  for (const host of discoveryResult.hosts) {
    assetIds.add(host.ip);
    for (const hostname of host.hostnames) {
      assetIds.add(hostname);
    }
  }
  for (const sub of discoveryResult.subdomains) {
    assetIds.add(sub.subdomain);
  }
  const results = [];
  const concurrency = 5;
  const queue = Array.from(assetIds);
  for (let i = 0; i < queue.length; i += concurrency) {
    const batch = queue.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(
        (id) => analyzeAssetContext(
          id,
          discoveryResult,
          options,
          whoisData,
          httpFingerprints?.[id],
          businessIntelData
        )
      )
    );
    results.push(...batchResults);
  }
  return results;
}
function extractOrgFromCertSubject(subject) {
  const match = subject.match(/O=([^,/]+)/);
  return match ? match[1].trim() : null;
}
function normalizeOrgName(name) {
  return name.toLowerCase().replace(/\b(inc|corp|ltd|llc|co|company|group|holdings|plc|gmbh|sa|ag)\b\.?/gi, "").replace(/[^a-z0-9]/g, "").trim();
}
function extractHostnamePattern(hostname) {
  const parts = hostname.split(".");
  if (parts.length >= 3) {
    return parts[0] + ".";
  }
  return null;
}
function extractHostnameSignals(hostname) {
  const signals = [];
  const parts = hostname.split(".");
  const patterns = [
    "api.",
    "www.",
    "app.",
    "admin.",
    "internal.",
    "vpn.",
    "mail.",
    "smtp.",
    "ftp.",
    "staging.",
    "stg.",
    "dev.",
    "development.",
    "test.",
    "qa.",
    "uat.",
    "backup.",
    "dr.",
    "failover.",
    "cdn.",
    "static.",
    "partner.",
    "b2b.",
    "payment.",
    "billing.",
    "portal.",
    "dashboard.",
    "monitor.",
    "status.",
    "git.",
    "ci.",
    "jenkins.",
    "grafana.",
    "kibana.",
    "elastic."
  ];
  for (const part of parts) {
    const prefix = part + ".";
    if (patterns.includes(prefix)) {
      signals.push(prefix);
    }
  }
  return signals;
}
function isCDNProvider(name) {
  const cdnProviders = [
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "amazon",
    "google",
    "microsoft",
    "azure",
    "incapsula",
    "imperva",
    "sucuri",
    "stackpath",
    "limelight",
    "edgecast",
    "keycdn",
    "bunny"
  ];
  const lower = name.toLowerCase();
  return cdnProviders.some((cdn) => lower.includes(cdn));
}
function inferRegulatoryExposures(pkg) {
  const exposures = [];
  const hostname = pkg.assetIdentifier.toLowerCase();
  const technologies = pkg.http?.technologies?.map((t) => t.toLowerCase()) || [];
  const keywords = pkg.http?.contentKeywords?.map((k) => k.toLowerCase()) || [];
  const allSignals = [hostname, ...technologies, ...keywords].join(" ");
  if (/payment|pci|card|checkout|stripe|braintree|adyen/i.test(allSignals)) {
    exposures.push({
      regime: "PCI-DSS",
      indicators: ["Payment-related keywords detected in hostname/technology"],
      confidence: 60
    });
  }
  if (/patient|hipaa|ehr|medical|health|fhir|hl7/i.test(allSignals)) {
    exposures.push({
      regime: "HIPAA",
      indicators: ["Healthcare-related keywords detected"],
      confidence: 55
    });
  }
  if (/financial|sox|audit|accounting|ledger/i.test(allSignals)) {
    exposures.push({
      regime: "SOX",
      indicators: ["Financial reporting keywords detected"],
      confidence: 45
    });
  }
  if (/gdpr|privacy|consent|eu\.|\.eu/i.test(allSignals)) {
    exposures.push({
      regime: "GDPR",
      indicators: ["EU/privacy-related keywords detected"],
      confidence: 50
    });
  }
  if (/cmmc|nist|fedramp|gov\.|\.gov|\.mil/i.test(allSignals)) {
    exposures.push({
      regime: "CMMC",
      indicators: ["Government/defense compliance keywords detected"],
      confidence: 55
    });
  }
  return exposures;
}
function formatEvidencePackageForPrompt(pkg) {
  const sections = [];
  sections.push(`ASSET: ${pkg.assetIdentifier} (resolved to ${pkg.resolvedIPs.join(", ") || "unknown"})`);
  if (pkg.certificate) {
    sections.push(`
CERTIFICATE EVIDENCE:
- Issuer: ${pkg.certificate.issuer}
- Subject CN: ${pkg.certificate.subjectCN}
- SAN entries: ${pkg.certificate.sanEntries.join(", ")}
- Organization in subject: ${pkg.certificate.organizationInSubject || "Not present"}
- Valid: ${pkg.certificate.validFrom} to ${pkg.certificate.validTo}
- Expired: ${pkg.certificate.isExpired}
- Wildcard: ${pkg.certificate.isWildcard}
- First observed in CT logs: ${pkg.certificate.firstObservedInCTLogs || "Unknown"}`);
  }
  sections.push(`
DNS EVIDENCE:
- A records: ${pkg.dns.aRecords.map((r) => `${r.value} (first seen: ${r.firstSeen || "unknown"})`).join(", ") || "None"}
- MX records: ${pkg.dns.mxRecords.map((r) => r.value).join(", ") || "None"}
- NS records: ${pkg.dns.nsRecords.join(", ") || "None"}
- TXT records: ${pkg.dns.txtRecords.length} entries
- SOA: ${pkg.dns.soaRecord || "None"}
- CNAME chain: ${pkg.dns.cnameChain.join(" \u2192 ") || "None"}
- Stable since: ${pkg.dns.stableSince || "Unknown"}`);
  if (pkg.bgp.asn) {
    sections.push(`
BGP/AS EVIDENCE:
- ASN: AS${pkg.bgp.asn} (${pkg.bgp.asnOrganization || "Unknown"})
- ISP: ${pkg.bgp.isp || "Unknown"}`);
  }
  if (pkg.whois) {
    sections.push(`
WHOIS EVIDENCE:
- Registrant: ${pkg.whois.registrantOrganization || pkg.whois.registrantName || "Privacy protected"}
- Country: ${pkg.whois.registrantCountry || "Unknown"}
- Registered: ${pkg.whois.registrationDate || "Unknown"}
- Expires: ${pkg.whois.expirationDate || "Unknown"}
- Last updated: ${pkg.whois.lastUpdated || "Unknown"}
- Nameservers: ${pkg.whois.nameServers.join(", ") || "None"}`);
  }
  if (pkg.http) {
    sections.push(`
HTTP EVIDENCE:
- Status: ${pkg.http.statusCode || "Unknown"}
- Server: ${pkg.http.serverHeader || "Not disclosed"}
- Powered by: ${pkg.http.poweredByHeader || "Not disclosed"}
- Technologies: ${pkg.http.technologies.join(", ") || "None detected"}
- Hostname pattern: ${pkg.http.hostnamePattern || "None"}
- Content keywords: ${pkg.http.contentKeywords.join(", ") || "None"}`);
  }
  if (pkg.businessIntel) {
    sections.push(`
BUSINESS INTELLIGENCE:
- SEC EDGAR CIK: ${pkg.businessIntel.secEdgarCIK || "Not found"}
- Industry: ${pkg.businessIntel.industry || "Unknown"}
- Employees: ${pkg.businessIntel.employeeCount || "Unknown"}
- Headquarters: ${pkg.businessIntel.headquarters || "Unknown"}
- Business segments: ${pkg.businessIntel.businessSegments.map((s) => `${s.name} (${s.revenue || "revenue unknown"})`).join(", ") || "None"}
- Subsidiaries: ${pkg.businessIntel.subsidiaries.join(", ") || "None"}
- Regulatory regimes: ${pkg.businessIntel.regulatoryRegimes.join(", ") || "None identified"}`);
  }
  return sections.join("\n");
}
export {
  analyzeAssetContext,
  analyzeDiscoveryContext,
  applyBoundedDelta,
  buildAttributionPrompt,
  buildBusinessContextPrompt,
  buildEvidencePackage,
  buildLifecyclePrompt,
  buildRolePrompt,
  buildThreatRelevancePrompt,
  clampDelta,
  classifyDiscoveryTier,
  computeAttributionBaseline,
  computeLifecycleBaseline,
  computeRoleBaseline,
  computeThreatRelevanceBaseline,
  generateNegativeFindings,
  validateEvidenceGrounding
};
