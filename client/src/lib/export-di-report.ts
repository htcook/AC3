/**
 * Domain Intelligence EASM PDF Report Export
 * 
 * Generates a comprehensive, client-ready External Attack Surface Management
 * report from DI scan results. Designed for proposal delivery, client
 * presentations, and compliance documentation.
 * 
 * Sections:
 *   1. Cover Page — branded, domain, date, classification
 *   2. Executive Summary — risk gauge, key metrics, narrative
 *   3. Attack Surface Inventory — assets by type, criticality, risk band
 *   4. Domain Health & Blacklist Status — DNS, SSL, DNSBL, email security
 *   5. Breach & Credential Exposure — 1st-party vs 3rd-party classification
 *   6. Dark Web & Ransomware Intelligence — threat group attribution
 *   7. Vulnerability & Technology Landscape — CVEs, tech stack, WAF/NGFW
 *   8. Threat Actor Assessment — attributed groups, TTPs, IOCs
 *  8b. Provider-Managed Infrastructure — excluded assets, CVEs, risk impact
 *   9. Prioritized Recommendations — CARVER-ranked remediation actions
 *  10. Appendix — data sources, scan metadata, methodology
 */

import { createAssetOwnershipFilter } from '../../../shared/managed-provider-filter';

// Dynamic imports to reduce bundle size
let _jsPDF: typeof import('jspdf').default | null = null;
let _autoTable: typeof import('jspdf-autotable').default | null = null;
async function loadPdfLibs() {
  if (!_jsPDF) _jsPDF = (await import('jspdf')).default;
  if (!_autoTable) _autoTable = (await import('jspdf-autotable')).default;
  return { jsPDF: _jsPDF, autoTable: _autoTable };
}

function dateStamp(): string {
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

function getRiskColor(band: string): [number, number, number] {
  switch (band?.toLowerCase()) {
    case 'critical': return [220, 38, 38];
    case 'high': return [234, 88, 12];
    case 'medium': return [202, 138, 4];
    case 'low': return [22, 163, 74];
    default: return [113, 113, 122];
  }
}

function getSeverityLabel(score: number): string {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function truncate(str: string | null | undefined, max: number): string {
  if (!str) return '';
  return str.length > max ? str.substring(0, max - 3) + '...' : str;
}

/**
 * Export a comprehensive Domain Intelligence EASM PDF report
 */
export async function exportDiEasmReport(
  domain: string,
  scan: any,
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  // ── Data Normalization Layer ──
  // The pipeline output uses different field names/structures than what the report
  // sections expect. This layer maps the actual pipeline data to the expected shape.
  const assets = scan.assets || [];

  // Build synthetic observations from asset postureFindings when observations array is empty
  const rawObservations = scan.observations || [];

  // Detect managed mail provider for CVE filtering
  const _emailSecReportForProvider = scan.emailSecurityReport || scan.pipelineOutput?.emailSecurityReport || scan.pipelineOutput?.emailSecurity || null;
  const _managedMailProvider = _emailSecReportForProvider?.managedProvider?.isManaged
    ? _emailSecReportForProvider.managedProvider.name
    : (['Microsoft 365', 'Google Workspace', 'Proofpoint', 'Mimecast', 'Zoho Mail', 'ProtonMail']
        .find(p => p === _emailSecReportForProvider?.mx?.provider) || null);
  // Use the shared ownership filter to identify managed provider hosts
  const _ownershipFilter = createAssetOwnershipFilter({
    managedProviderName: _managedMailProvider,
    primaryDomain: scan.primaryDomain || scan.pipelineOutput?.orgProfile?.primaryDomain || '',
  });
  const _managedMailHosts = new Set<string>();
  for (const asset of (scan.assets || [])) {
    if (!_ownershipFilter.isClientOwned({ hostname: asset.hostname, tags: asset.tags })) {
      _managedMailHosts.add(asset.hostname);
    }
  }

  const observations: any[] = rawObservations.length > 0 ? rawObservations : (() => {
    const synth: any[] = [];
    // Track CVE deduplication: same CVE across multiple assets → single observation with asset list
    const cveDedup = new Map<string, any>();

    for (const asset of assets) {
      const findings = asset.postureFindings || (asset.analysis ? (() => { try { return JSON.parse(asset.analysis)?.postureFindings || []; } catch { return []; } })() : []);
      for (const f of (findings as any[])) {
        const tags: string[] = [];
        // Use title field (which has the full CVE title) or fall back to finding
        const titleOrFinding = f.title || f.finding || '';
        if (f.category === 'vulnerability' || f.category === 'CISA KEV' || f.category === 'Known CVE' || f.category === 'Exploitable CVE' || f.category === '0-Day' || titleOrFinding.includes('CVE-')) tags.push('vulnerability');
        if (titleOrFinding.match(/CVE-\d{4}-\d+/)) tags.push('cve');
        if (f.kevListed) tags.push('kev');
        if (f.category === 'credential' || titleOrFinding.toLowerCase().includes('credential')) tags.push('leaked_credential');
        if (f.category === 'darkweb') tags.push('darkweb');

        // Extract CVE ID from title (e.g. "CVE-2013-0431: Oracle JRE Sandbox Bypass...")
        const cveMatch = titleOrFinding.match(/CVE-\d{4}-\d+/);
        const cveId = (f.cveIds && f.cveIds[0]) || cveMatch?.[0] || undefined;

        // Build a proper description from available evidence fields
        const description = f.evidenceDetail || f.evidenceChain?.join(' \u2192 ') || f.remediation || titleOrFinding;

        // Use the numeric severity directly (posture findings already have numeric severity)
        const severity = typeof f.severity === 'number' ? f.severity
          : f.severity === 'critical' ? 9 : f.severity === 'high' ? 7 : f.severity === 'medium' ? 5 : 3;

        // Build corroboration label for the report
        const corroborationLabel = f.corroborationTier === 'confirmed' ? '[CONFIRMED]'
          : f.corroborationTier === 'probable' ? '[PROBABLE]'
          : f.versionMatchConfirmed === false ? '[UNCONFIRMED VERSION]' : '';

        // Check if this CVE is on a managed provider host
        const assetHostname = f.assetHostname || asset.hostname || '';
        const isOnManagedHost = _managedMailHosts.has(assetHostname);

        // Deduplicate CVEs: merge same CVE across assets into one observation
        if (cveId && cveDedup.has(cveId)) {
          const existing = cveDedup.get(cveId);
          if (!existing.evidence.affectedHosts.includes(assetHostname)) {
            existing.evidence.affectedHosts.push(assetHostname);
          }
          // Upgrade tier if this instance is confirmed
          if (corroborationLabel === '[CONFIRMED]' && existing.evidence.corroboration !== '[CONFIRMED]') {
            existing.evidence.corroboration = '[CONFIRMED]';
            existing.evidence.detectedVersion = f.detectedVersion || existing.evidence.detectedVersion;
            existing.evidence.affectedVersions = f.affectedVersions || existing.evidence.affectedVersions;
            existing.evidence.severity = severity;
          }
          // Merge NVD description if not already present
          if (f.nvdDescription && !existing.evidence.nvdDescription) {
            existing.evidence.nvdDescription = f.nvdDescription;
          }
          // Track managed host status
          if (isOnManagedHost) existing.evidence.hasProviderManagedInstance = true;
          continue;
        }

        const obs = {
          name: titleOrFinding,
          source: f.source || f.evidenceBasis || 'posture_analysis',
          domain: assetHostname || domain,
          tags,
          assetType: f.category || 'finding',
          evidence: {
            severity,
            cve_id: cveId,
            hostname: assetHostname,
            affectedHosts: [assetHostname],
            description: truncate(description, 200),
            title: titleOrFinding,
            corroboration: corroborationLabel,
            kevListed: f.kevListed || false,
            exploitAvailable: f.exploitAvailable || false,
            detectedVersion: f.detectedVersion || undefined,
            affectedVersions: f.affectedVersions || undefined,
            cvssScore: f.cvssScore || undefined,
            nvdDescription: f.nvdDescription || undefined,
            hasProviderManagedInstance: isOnManagedHost,
            providerManagedOnly: false, // will be set after dedup
          },
          firstSeen: asset.createdAt || null,
        };
        if (cveId) cveDedup.set(cveId, obs);
        synth.push(obs);
      }
    }

    // Post-process: mark CVEs that ONLY appear on managed hosts
    for (const obs of synth) {
      if (obs.evidence?.cve_id && obs.evidence.hasProviderManagedInstance) {
        const allHostsManaged = obs.evidence.affectedHosts.every((h: string) => _managedMailHosts.has(h));
        obs.evidence.providerManagedOnly = allHostsManaged;
        if (allHostsManaged) obs.tags.push('provider_managed');
      }
    }

    return synth;
  })();

  // Normalize domainHealth: pipeline stores categories as dnsHealth/mailSecurity/blacklist
  // but report expects dns/emailSecurity/ssl/blacklist.
  // Data sources:
  //   - domainHealth.categories.dnsHealth.details → NS records, SOA, zone transfer
  //   - domainHealth.categories.mailSecurity.details → MX records, SPF, DMARC
  //   - domainHealth.categories.reverseDs.details → IP addresses with PTR records
  //   - domainHealth.categories.connectivity.details → port connectivity status
  //   - scan.emailSecurityReport → full email security analysis (SPF/DKIM/DMARC with records)
  //   - scan.discoveredSubdomains → subdomain IPs (A record proxies)
  //   - scan.discoveredPorts → open ports from Shodan/Censys
  const rawDomainHealth = scan.domainHealth || {};
  // Prefer emailSecurityReport from the pipeline trimmedOutput (stored as emailSecurityReport)
  const emailSecReport = scan.emailSecurityReport || scan.pipelineOutput?.emailSecurityReport || scan.pipelineOutput?.emailSecurity || null;
  const domainHealth = (() => {
    const cats = rawDomainHealth.categories || {};
    const normalized: any = { ...rawDomainHealth };

    // Map dnsHealth → dns
    // dnsHealth.details has: nameservers (NS records), soaConsistent, nsConsistent, etc.
    // A records come from reverseDs.details (IPs with PTR records)
    // MX records come from mailSecurity.details.mxRecords
    if (cats.dnsHealth && !normalized.dns) {
      const dh = cats.dnsHealth.details || {};
      const ms = cats.mailSecurity?.details || {};
      // Extract A record IPs from reverseDs (these are the resolved IPs for the domain)
      const reverseDsDetails = Array.isArray(cats.reverseDs?.details) ? cats.reverseDs.details : [];
      const aRecordIps = reverseDsDetails
        .filter((r: any) => r.ip && r.matchesForwardDns)
        .map((r: any) => r.ip);
      // Also pull IPs from discoveredSubdomains for the primary domain
      const primaryDomainSubs = (scan.discoveredSubdomains || [])
        .filter((s: any) => s.ip && s.name?.toLowerCase() === domain.toLowerCase())
        .map((s: any) => s.ip);
      const allARecords = [...new Set([...aRecordIps, ...primaryDomainSubs])];

      normalized.dns = {
        aRecords: allARecords.length > 0 ? allARecords : [],
        nsRecords: dh.nameservers?.map((ns: any) => ns.name || ns) || [],
        mxRecords: ms.mxRecords || emailSecReport?.mx?.records || [],
        soaConsistent: dh.soaConsistent,
        nsConsistent: dh.nsConsistent,
        zoneTransferBlocked: dh.zoneTransferBlocked,
        recursionDisabled: dh.recursionDisabled,
        score: cats.dnsHealth.score,
        grade: cats.dnsHealth.grade,
      };
    }

    // Map emailSecurity — prefer the full emailSecurityReport over mailSecurity category
    // emailSecurityReport has richer data: full SPF record, DKIM selector results, DMARC with policy details
    if (!normalized.emailSecurity) {
      if (emailSecReport) {
        // Use the full email security report (has SPF records, DKIM selectors, DMARC policy)
        const spf = emailSecReport.spf || {};
        const dkim = emailSecReport.dkim || {};
        const dmarc = emailSecReport.dmarc || {};
        const dkimFound = Array.isArray(dkim.selectorResults)
          ? dkim.selectorResults.some((s: any) => s.exists)
          : false;
        normalized.emailSecurity = {
          spf: { present: spf.exists || !!spf.record, record: spf.record || '', score: spf.score },
          dkim: { present: dkimFound, selectors: dkim.selectorResults?.filter((s: any) => s.exists) || [], score: dkim.score },
          dmarc: { present: dmarc.exists || !!dmarc.record, policy: dmarc.policy || 'none', record: dmarc.record || '', score: dmarc.score },
          spoofable: emailSecReport.phishingDifficultyRating === 'easy' || emailSecReport.phishingDifficultyRating === 'trivial',
          overallScore: emailSecReport.overallScore,
          overallGrade: emailSecReport.overallGrade,
          phishingDifficulty: emailSecReport.phishingDifficultyRating,
          score: emailSecReport.overallScore,
          grade: emailSecReport.overallGrade,
        };
      } else if (cats.mailSecurity) {
        // Fallback to mailSecurity category from domainHealth connector
        const ms = cats.mailSecurity.details || {};
        normalized.emailSecurity = {
          spf: ms.spf ? { present: ms.spf.exists || !!ms.spf.record, record: ms.spf.record || '' } : { present: false },
          dkim: { present: false },
          dmarc: ms.dmarc ? { present: ms.dmarc.exists || !!ms.dmarc.record, policy: ms.dmarc.policy || 'none', record: ms.dmarc.record || '' } : { present: false },
          spoofable: ms.spoofable,
          spoofReason: ms.spoofReason,
          score: cats.mailSecurity.score,
          grade: cats.mailSecurity.grade,
        };
      }
    }

    // Map blacklist category
    if (cats.blacklist && !normalized.blacklist) {
      const bl = cats.blacklist.details || {};
      normalized.blacklist = {
        listings: (bl.listed || []).map((l: any) => ({
          zone: typeof l === 'string' ? l : l.zone || l.name || 'Unknown',
          category: typeof l === 'string' ? 'listed' : l.category || 'listed',
          severity: typeof l === 'string' ? 'medium' : l.severity || 'medium',
          reason: typeof l === 'string' ? l : l.reason || l.txtReason || '',
        })),
        clean: bl.clean || [],
        totalChecked: bl.totalChecked || 0,
        score: cats.blacklist.score,
        grade: cats.blacklist.grade,
      };
    }

    // Map connectivity category — port reachability status
    if (cats.connectivity && !normalized.connectivity) {
      const connDetails = Array.isArray(cats.connectivity.details) ? cats.connectivity.details : [];
      normalized.connectivity = {
        ports: connDetails.map((c: any) => ({
          host: c.host || c.ip,
          port: c.port,
          connected: c.connected,
          latencyMs: c.latencyMs,
        })),
        score: cats.connectivity.score,
        grade: cats.connectivity.grade,
      };
    }

    // Map reverseDs category — PTR records and IP resolution
    if (cats.reverseDs && !normalized.reverseDns) {
      const rdDetails = Array.isArray(cats.reverseDs.details) ? cats.reverseDs.details : [];
      normalized.reverseDns = {
        records: rdDetails.map((r: any) => ({
          ip: r.ip,
          hostnames: r.hostnames || [],
          hasPtrRecord: r.hasPtrRecord,
          matchesForwardDns: r.matchesForwardDns,
        })),
        score: cats.reverseDs.score,
        grade: cats.reverseDs.grade,
      };
    }

    // Add overall health summary
    normalized.overallScore = rawDomainHealth.overallScore;
    normalized.overallGrade = rawDomainHealth.overallGrade;
    return normalized;
  })();

  const enrichment = scan.enrichment || {};

  // Map postEnrichmentAnalysis → llmAnalysis expected shape
  const postEnrichment = scan.postEnrichmentAnalysis || {};
  const llmAnalysis = scan.llmAnalysis || {
    executiveBrief: postEnrichment.executiveAnalysis || postEnrichment.overallAssessment || '',
    recommendations: (postEnrichment.prioritizedRecommendations || []).map((r: any, i: number) => ({
      recommendation: r.description || r.recommendation || r.title || (typeof r === 'string' ? r : ''),
      title: r.title || r.recommendation || `Recommendation ${i + 1}`,
      category: r.category || 'General',
      effort: r.effort || r.priority || 'N/A',
    })),
    attackChains: (postEnrichment.attackPaths || []).map((p: any) => ({
      name: p.name || p.title || 'Attack Path',
      title: p.title || p.name || 'Attack Path',
      description: p.description || p.narrative || '',
      narrative: p.narrative || p.description || '',
    })),
    blindSpots: postEnrichment.blindSpots || [],
    confidenceStatement: postEnrichment.confidenceStatement || '',
  };

  const reputationEngine = scan.reputationEngine || {};
  const discoveryCoverage = scan.discoveryCoverage || {};
  const wafNgfw = scan.wafNgfwDetection || {};
  const crossModuleEnrichment = scan.crossModuleEnrichment || {};

  // ─── Table of Contents tracking ──────────────────────────────────────
  const tocEntries: { title: string; pageNum: number; sectionNum: string }[] = [];
  let sectionCounter = 0;

  // Helper: add page with header (also records TOC entry)
  function addSectionPage(title: string, opts?: { skipToc?: boolean }): number {
    doc.addPage();
    const pageNum = (doc as any).internal.getNumberOfPages();
    if (!opts?.skipToc) {
      sectionCounter++;
      tocEntries.push({ title, pageNum, sectionNum: String(sectionCounter) });
    }
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 22, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(title, margin, 14);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(domain, pageWidth - margin - doc.getTextWidth(domain), 14);
    return 30;
  }

  // Helper: check page break
  function checkPageBreak(y: number, needed: number = 30): number {
    if (y > pageHeight - needed) {
      doc.addPage();
      return 20;
    }
    return y;
  }

  // Helper: write wrapped text
  function writeText(text: string, x: number, y: number, maxWidth: number, fontSize: number = 9): number {
    doc.setFontSize(fontSize);
    const lines = doc.splitTextToSize(text, maxWidth);
    for (const line of lines) {
      y = checkPageBreak(y, 10);
      doc.text(line, x, y);
      y += fontSize * 0.45;
    }
    return y;
  }

  // Helper: section subheading
  function subheading(text: string, y: number): number {
    y = checkPageBreak(y, 18);
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(text, margin, y);
    y += 5;
    return y;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 1. COVER PAGE
  // ═══════════════════════════════════════════════════════════════════════
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, pageHeight, 'F');

  // Title block
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('External Attack Surface', margin, 55);
  doc.text('Management Report', margin, 67);

  doc.setFontSize(16);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text(domain, margin, 82);

  // Risk score box
  let y = 100;
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, y, contentWidth, 50, 3, 3, 'F');

  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('OVERALL RISK ASSESSMENT', margin + 5, y + 8);

  // Risk gauge
  const riskScore = scan.overallRiskScore ?? 0;
  const riskBand = scan.overallRiskBand || 'unknown';
  const riskColor = getRiskColor(riskBand);
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(margin + 5, y + 12, 35, 30, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text(String(riskScore), margin + 12, y + 28);
  doc.setFontSize(8);
  doc.text(riskBand.toUpperCase(), margin + 10, y + 37);

  // Key metrics
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const metricsX = margin + 50;
  doc.text(`Total Assets Discovered: ${scan.totalAssets ?? assets.length ?? 0}`, metricsX, y + 18);
  // Count only confirmed (version-matched) findings — probable/unconfirmed excluded from client reports
  const _clientFindings = observations.filter((o: any) => !o.evidence?.providerManagedOnly);
  const _confirmedCount = _clientFindings.filter((o: any) => o.evidence?.corroboration === '[CONFIRMED]').length;
  doc.text(`Confirmed Findings: ${_confirmedCount}`, metricsX, y + 25);
  const connectorCount = scan.passiveRecon?.connectorResults?.filter((c: any) => c.observationCount > 0)?.length ?? scan.connectorResults?.length ?? 0;
  doc.text(`Data Sources Queried: ${connectorCount}`, metricsX, y + 32);
  // Calculate scan duration: sum all connector durations for accurate total
  // (scan.durationMs is root-level and often undefined; domainHealth.durationMs is just one connector)
  const connectorResultsForDuration = scan.passiveRecon?.connectorResults || scan.connectorResults || [];
  const totalConnectorDurationMs = connectorResultsForDuration.reduce(
    (sum: number, cr: any) => sum + (cr.durationMs || 0), 0
  );
  const scanDuration = scan.durationMs || (totalConnectorDurationMs > 0 ? totalConnectorDurationMs : null);
  doc.text(`Scan Duration: ${scanDuration ? `${(scanDuration / 1000).toFixed(1)}s` : 'N/A'}`, metricsX, y + 39);

  // Risk score exclusion footnote
  const riskExclusions = scan.riskScoreExclusions || scan.pipelineOutput?.riskScoreExclusions;
  if (riskExclusions && riskExclusions.excludedCount > 0) {
    y += 54; // below the risk box
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.setFont('helvetica', 'italic');
    doc.text(
      `\u2020 Risk score calculated from ${riskExclusions.clientOwnedCount} client-owned assets. ` +
      `${riskExclusions.excludedCount} managed provider / third-party asset(s) excluded from scoring.`,
      margin, y
    );
    doc.setFont('helvetica', 'normal');
  }

  // Classification & metadata
  y = 165;
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Scan Date: ${scan.createdAt ? new Date(scan.createdAt).toLocaleString() : new Date().toLocaleString()}`, margin, y);
  doc.text(`Scan Mode: ${scan.scanMode || 'standard'}`, margin, y + 7);
  if (scan.orgProfile?.sector) {
    doc.text(`Sector: ${scan.orgProfile.sector}`, margin, y + 14);
  }
  if (scan.orgProfile?.clientType) {
    doc.text(`Client Type: ${scan.orgProfile.clientType}`, margin, y + 21);
  }

  // Footer
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text('CONFIDENTIAL — For authorized recipients only', margin, pageHeight - 15);
  doc.text('AC3 Platform — Domain Intelligence Module', margin, pageHeight - 10);

  // ═══════════════════════════════════════════════════════════════════════
  // TABLE OF CONTENTS (placeholder page — filled in after all sections render)
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  const tocPageNum = (doc as any).internal.getNumberOfPages();

  // ═══════════════════════════════════════════════════════════════════════
  // 2. EXECUTIVE SUMMARY
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Executive Summary');

  // Executive summary narrative
  if (scan.executiveSummary) {
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    y = writeText(scan.executiveSummary, margin, y, contentWidth);
    y += 3;
  }

  // Threat model summary
  if (scan.threatModelSummary) {
    y = subheading('Threat Model Assessment', y);
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    y = writeText(scan.threatModelSummary, margin, y, contentWidth);
    y += 3;
  }

  // LLM post-enrichment analysis
  if (llmAnalysis.executiveBrief) {
    y = subheading('AI-Enhanced Analysis', y);
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    y = writeText(llmAnalysis.executiveBrief, margin, y, contentWidth);
    y += 3;
  }

  // Organization Profile section (from DI pipeline orgProfile)
  const orgProfile = scan.orgProfile;
  if (orgProfile && (orgProfile.sector || orgProfile.clientType || orgProfile.complianceFlags?.length > 0 || orgProfile.criticalFunctions?.length > 0)) {
    y = subheading('Organization Profile', y);
    const orgRows: string[][] = [];
    orgRows.push(['Organization', orgProfile.customerName || scan.primaryDomain || 'N/A']);
    orgRows.push(['Primary Domain', orgProfile.primaryDomain || scan.primaryDomain || 'N/A']);
    if (orgProfile.sector) orgRows.push(['Industry Sector', orgProfile.sector]);
    if (orgProfile.clientType) orgRows.push(['Organization Type', orgProfile.clientType.charAt(0).toUpperCase() + orgProfile.clientType.slice(1)]);
    if (orgProfile.complianceFlags?.length > 0) orgRows.push(['Compliance Frameworks', orgProfile.complianceFlags.join(', ')]);
    if (orgProfile.criticalFunctions?.length > 0) orgRows.push(['Critical Business Functions', orgProfile.criticalFunctions.join(', ')]);
    if (orgProfile.additionalDomains?.length > 0) orgRows.push(['Additional Domains', orgProfile.additionalDomains.join(', ')]);
    autoTable!(doc, {
      startY: y,
      head: [['Attribute', 'Detail']],
      body: orgRows,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 8, cellPadding: 2, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      columnStyles: { 0: { fontStyle: 'bold', cellWidth: 50 } },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  // Business Intelligence section (from pipeline crawl)
  const bizIntel = scan.pipelineCrawl?.businessIntelligence;
  if (bizIntel && (bizIntel.services?.length > 0 || bizIntel.products?.length > 0 || bizIntel.businessSummary)) {
    y = subheading('Business Intelligence (Web Crawl)', y);
    // Business summary
    if (bizIntel.businessSummary) {
      doc.setFontSize(8);
      doc.setTextColor(51, 65, 85);
      const summaryLines = doc.splitTextToSize(bizIntel.businessSummary, contentWidth);
      if (y + summaryLines.length * 4 > pageHeight - 25) { doc.addPage(); y = 20; }
      doc.text(summaryLines, margin, y);
      y += summaryLines.length * 4 + 2;
    }
    const bizRows: string[][] = [];
    if (bizIntel.services?.length > 0) bizRows.push(['Services', bizIntel.services.join(', ')]);
    if (bizIntel.products?.length > 0) bizRows.push(['Products / Solutions', bizIntel.products.join(', ')]);
    if (bizIntel.industryIndicators?.length > 0) bizRows.push(['Industry Indicators', bizIntel.industryIndicators.join(', ')]);
    if (bizIntel.targetMarket?.length > 0) bizRows.push(['Target Market', bizIntel.targetMarket.join(', ')]);
    if (bizIntel.partnerships?.length > 0) bizRows.push(['Partnerships / Integrations', bizIntel.partnerships.join(', ')]);
    if (bizIntel.complianceMentions?.length > 0) bizRows.push(['Compliance Mentions', bizIntel.complianceMentions.join(', ')]);
    if (bizIntel.geographicPresence?.length > 0) bizRows.push(['Geographic Presence', (bizIntel as any).geographicPresence.join(', ')]);
    if (bizIntel.pricingModel) bizRows.push(['Pricing Model', (bizIntel as any).pricingModel]);
    if (bizRows.length > 0) {
      if (y + bizRows.length * 10 > pageHeight - 25) { doc.addPage(); y = 20; }
      autoTable!(doc, {
        startY: y,
        head: [['Category', 'Details']],
        body: bizRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7.5, cellPadding: 2, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 }, 1: { cellWidth: contentWidth - 45 } },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    }
    // Confidence indicator
    if (bizIntel.confidence != null) {
      doc.setFontSize(6.5);
      doc.setTextColor(148, 163, 184);
      doc.text(`Business intelligence confidence: ${Math.round(bizIntel.confidence * 100)}% (source: passive web crawl of public pages)`, margin, y);
      y += 4;
    }
  }

  // Key risk findings summary table
  const criticalAssets = assets.filter((a: any) => a.riskBand === 'critical' || a.hybridRiskScore >= 80);
  const highAssets = assets.filter((a: any) => a.riskBand === 'high' || (a.hybridRiskScore >= 60 && a.hybridRiskScore < 80));

  if (criticalAssets.length > 0 || highAssets.length > 0) {
    y = subheading('Critical & High Risk Assets', y);

    autoTable!(doc, {
      startY: y,
      head: [['Asset', 'Risk Score', 'Risk Band', 'Mission Function', 'Key Findings']],
      body: [...criticalAssets, ...highAssets].slice(0, 20).map((a: any) => [
        truncate(a.hostname || a.name, 40),
        String(a.hybridRiskScore ?? 0),
        (a.riskBand || 'unknown').toUpperCase(),
        truncate(a.missionFunction, 25),
        String(Array.isArray(a.postureFindings) ? a.postureFindings.length : 0),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 2) {
          const text = String(data.cell.text).toUpperCase();
          if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 3. ATTACK SURFACE INVENTORY
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Attack Surface Inventory');

  // Asset type breakdown
  const assetTypeCounts: Record<string, number> = {};
  const riskBandCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const asset of assets) {
    const aType = asset.assetType || 'unknown';
    assetTypeCounts[aType] = (assetTypeCounts[aType] || 0) + 1;
    const band = (asset.riskBand || 'low').toLowerCase();
    if (band in riskBandCounts) riskBandCounts[band]++;
  }

  y = subheading('Asset Distribution', y);

  // Asset type table
  autoTable!(doc, {
    startY: y,
    head: [['Asset Type', 'Count', '% of Total']],
    body: Object.entries(assetTypeCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([type, count]) => [
        type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        String(count),
        `${assets.length > 0 ? ((count / assets.length) * 100).toFixed(1) : 0}%`,
      ]),
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
    alternateRowStyles: { fillColor: [241, 245, 249] },
    margin: { left: margin, right: margin },
  });
  y = (doc as any).lastAutoTable.finalY + 4;

  // Risk distribution table
  y = subheading('Risk Distribution', y);

  autoTable!(doc, {
    startY: y,
    head: [['Risk Band', 'Count', '% of Total']],
    body: Object.entries(riskBandCounts)
      .filter(([, count]) => count > 0)
      .sort(([a], [b]) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a] ?? 4) - (order[b] ?? 4);
      })
      .map(([band, count]) => [
        band.toUpperCase(),
        String(count),
        `${assets.length > 0 ? ((count / assets.length) * 100).toFixed(1) : 0}%`,
      ]),
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
    alternateRowStyles: { fillColor: [241, 245, 249] },
    margin: { left: margin, right: margin },
    didParseCell: (data: any) => {
      if (data.section === 'body' && data.column.index === 0) {
        const text = String(data.cell.text).toUpperCase();
        if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
        else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
        else if (text === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
        else if (text === 'LOW') data.cell.styles.textColor = [22, 163, 74];
      }
    },
  });
  y = (doc as any).lastAutoTable.finalY + 4;

  // Full asset inventory table
  if (assets.length > 0) {
    y = subheading('Discovered Assets', y);

    autoTable!(doc, {
      startY: y,
      head: [['Hostname', 'Type', 'Risk', 'Band', 'Mission Function', 'Technologies']],
      body: assets.slice(0, 50).map((a: any) => [
        truncate(a.hostname || a.name, 35),
        (a.assetType || 'unknown').replace(/_/g, ' '),
        String(a.hybridRiskScore ?? 0),
        (a.riskBand || 'N/A').toUpperCase(),
        truncate(a.missionFunction, 20),
        truncate(Array.isArray(a.technologies) ? a.technologies.join(', ') : '', 30),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const text = String(data.cell.text).toUpperCase();
          if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
        }
      },
      didDrawPage: () => addFooter(doc, margin, pageWidth, pageHeight),
    });
    y = (doc as any).lastAutoTable.finalY + 4;

    if (assets.length > 50) {
      doc.setTextColor(113, 113, 122);
      doc.setFontSize(7);
      doc.text(`Showing top 50 of ${assets.length} assets. Full inventory available in CSV export.`, margin, y);
      y += 4;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 4. DOMAIN HEALTH & BLACKLIST STATUS
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Domain Health & Blacklist Status');

  // Overall health score summary
  if (domainHealth.overallScore !== undefined) {
    const healthScore = domainHealth.overallScore;
    const healthGrade = domainHealth.overallGrade || 'N/A';
    const gradeColor = healthGrade === 'A' ? [22, 163, 74] : healthGrade === 'B' ? [59, 130, 246] : healthGrade === 'C' ? [202, 138, 4] : healthGrade === 'D' ? [234, 88, 12] : [220, 38, 38];
    doc.setFillColor(30, 41, 59);
    doc.roundedRect(margin, y, contentWidth, 30, 3, 3, 'F');
    doc.setTextColor(148, 163, 184);
    doc.setFontSize(9);
    doc.text('OVERALL DOMAIN HEALTH', margin + 5, y + 8);
    doc.setFillColor(gradeColor[0], gradeColor[1], gradeColor[2]);
    doc.roundedRect(margin + 5, y + 12, 30, 14, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(`${healthGrade} (${healthScore})`, margin + 8, y + 22);
    // Category grades
    const cats = rawDomainHealth.categories || {};
    const catEntries = Object.entries(cats).map(([k, v]: [string, any]) => `${k.replace(/([A-Z])/g, ' $1').trim()}: ${v.grade || 'N/A'} (${v.score || 0})`);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(200, 210, 220);
    const catText = catEntries.join(' | ');
    doc.text(truncate(catText, 120), margin + 40, y + 18);
    doc.text(truncate(catText.slice(catText.indexOf('|', 60) + 2), 120), margin + 40, y + 23);
    y += 34;
  }

  // DNS configuration
  if (domainHealth.dns) {
    y = subheading('DNS Configuration', y);
    const dns = domainHealth.dns;
    const dnsRows: string[][] = [];
    if (dns.aRecords?.length) dnsRows.push(['A Records', dns.aRecords.join(', ')]);
    if (dns.aaaaRecords?.length) dnsRows.push(['AAAA Records', dns.aaaaRecords.join(', ')]);
    if (dns.mxRecords?.length) dnsRows.push(['MX Records', dns.mxRecords.map((r: any) => `${r.exchange} (pri: ${r.priority})`).join(', ')]);
    if (dns.nsRecords?.length) dnsRows.push(['NS Records', dns.nsRecords.join(', ')]);
    if (dns.txtRecords?.length) dnsRows.push(['TXT Records', truncate(dns.txtRecords.join('; '), 100)]);

    if (dnsRows.length > 0) {
      autoTable!(doc, {
        startY: y,
        head: [['Record Type', 'Values']],
        body: dnsRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { cellWidth: 30 }, 1: { cellWidth: contentWidth - 30 } },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    }
  }

  // Email security
  if (domainHealth.emailSecurity) {
    y = subheading('Email Security Posture', y);
    const email = domainHealth.emailSecurity;
    const emailRows: string[][] = [];
    // Check for managed provider context — try managedProvider field first,
    // then infer from mx.provider for scans that predate the managedProvider feature
    const managedProvider = emailSecReport?.managedProvider;
    const mxProvider = emailSecReport?.mx?.provider;
    // Known managed providers for inference when managedProvider field is absent
    const KNOWN_MANAGED_PROVIDERS: Record<string, { serverNote: string; responsibilities: string[] }> = {
      'Microsoft 365': { serverNote: 'Mail server infrastructure (Exchange Online) is managed by Microsoft. Server-level CVEs are Microsoft\'s responsibility.', responsibilities: ['SPF/DKIM/DMARC configuration', 'Tenant configuration', 'Conditional Access policies'] },
      'Google Workspace': { serverNote: 'Mail server infrastructure (Gmail) is managed by Google. Server-level CVEs are Google\'s responsibility.', responsibilities: ['SPF/DKIM/DMARC configuration', 'Workspace admin console', 'Security settings'] },
      'Proofpoint': { serverNote: 'Email filtering is managed by Proofpoint. Gateway-level security is Proofpoint\'s responsibility.', responsibilities: ['SPF/DKIM/DMARC configuration', 'Policy configuration'] },
      'Mimecast': { serverNote: 'Email security is managed by Mimecast. Gateway-level security is Mimecast\'s responsibility.', responsibilities: ['SPF/DKIM/DMARC configuration', 'Policy configuration'] },
      'Zoho Mail': { serverNote: 'Mail server infrastructure is managed by Zoho. Server-level security is Zoho\'s responsibility.', responsibilities: ['SPF/DKIM/DMARC configuration'] },
      'ProtonMail': { serverNote: 'Mail server infrastructure is managed by Proton AG with end-to-end encryption.', responsibilities: ['SPF/DKIM/DMARC configuration'] },
    };

    if (managedProvider?.isManaged) {
      emailRows.push(['Mail Provider', `${managedProvider.name} (Managed Service)`]);
      emailRows.push(['Server Security', `Managed by ${managedProvider.name} — server-level CVEs are provider responsibility`]);
      emailRows.push(['Customer Scope', managedProvider.customerResponsibilities?.slice(0, 3).join(', ') || 'SPF/DKIM/DMARC configuration']);
    } else if (mxProvider && KNOWN_MANAGED_PROVIDERS[mxProvider]) {
      // Infer managed provider from mx.provider when managedProvider field is absent
      const inferred = KNOWN_MANAGED_PROVIDERS[mxProvider];
      emailRows.push(['Mail Provider', `${mxProvider} (Managed Service)`]);
      emailRows.push(['Server Security', inferred.serverNote]);
      emailRows.push(['Customer Scope', inferred.responsibilities.join(', ')]);
    } else if (mxProvider) {
      emailRows.push(['Mail Provider', mxProvider]);
    }
    emailRows.push(['SPF', email.spf?.present ? `Present — ${truncate(email.spf.record, 60)}` : 'MISSING']);
    // Show DKIM with selector details if available
    const dkimStatus = email.dkim?.present
      ? `Present${email.dkim.selectors?.length ? ` (${email.dkim.selectors.map((s: any) => s.selector).join(', ')})` : ''}`
      : 'NOT DETECTED';
    emailRows.push(['DKIM', dkimStatus]);
    emailRows.push(['DMARC', email.dmarc?.present ? `Present — Policy: ${email.dmarc.policy || 'none'}${email.dmarc.record ? ` — ${truncate(email.dmarc.record, 50)}` : ''}` : 'MISSING']);
    // Add phishing difficulty if available
    if (email.phishingDifficulty) {
      const phishColor = email.phishingDifficulty === 'hard' || email.phishingDifficulty === 'very_hard' ? 'LOW RISK' : email.phishingDifficulty === 'moderate' ? 'MODERATE RISK' : 'HIGH RISK';
      emailRows.push(['Phishing Difficulty', `${email.phishingDifficulty.replace(/_/g, ' ').toUpperCase()} (${phishColor})`]);
    }
    // Add email security score if available
    if (email.overallScore !== undefined) {
      emailRows.push(['Email Security Score', `${email.overallScore}/100 (Grade: ${email.overallGrade || 'N/A'})`]);
    }

    autoTable!(doc, {
      startY: y,
      head: [['Control', 'Status']],
      body: emailRows,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 1) {
          const text = String(data.cell.text);
          if (text.startsWith('MISSING') || text.startsWith('NOT DETECTED')) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // SSL/TLS
  if (domainHealth.ssl) {
    y = subheading('SSL/TLS Certificate', y);
    const ssl = domainHealth.ssl;
    const sslRows: string[][] = [];
    sslRows.push(['Subject', ssl.subject || 'N/A']);
    sslRows.push(['Issuer', ssl.issuer || 'N/A']);
    sslRows.push(['Valid From', ssl.validFrom || 'N/A']);
    sslRows.push(['Valid To', ssl.validTo || 'N/A']);
    sslRows.push(['Days Until Expiry', String(ssl.daysUntilExpiry ?? 'N/A')]);
    sslRows.push(['Protocol', ssl.protocol || 'N/A']);
    if (ssl.sans?.length) sslRows.push(['SANs', truncate(ssl.sans.join(', '), 80)]);

    autoTable!(doc, {
      startY: y,
      head: [['Property', 'Value']],
      body: sslRows,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
      columnStyles: { 0: { cellWidth: 35 } },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.row.index === 4) {
          const days = parseInt(String(data.cell.text));
          if (!isNaN(days) && days < 30) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Blacklist / DNSBL status
  if (domainHealth.blacklist) {
    y = subheading('Blacklist / DNSBL Status', y);
    const bl = domainHealth.blacklist;

    if (bl.listings && bl.listings.length > 0) {
      // Warning box
      doc.setFillColor(254, 242, 242);
      doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
      doc.setTextColor(220, 38, 38);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text(`LISTED ON ${bl.listings.length} BLACKLIST(S)`, margin + 5, y + 7);
      y += 16;

      autoTable!(doc, {
        startY: y,
        head: [['Zone', 'Category', 'Severity', 'Reason', 'False Positive?']],
        body: bl.listings.slice(0, 20).map((l: any) => [
          l.zone || 'N/A',
          (l.category || 'unknown').replace(/_/g, ' '),
          (l.severity || 'unknown').toUpperCase(),
          truncate(l.reason || l.txtReason || 'No reason provided', 50),
          l.isFalsePositive ? `Yes — ${truncate(l.falsePositiveReason, 30)}` : 'No',
        ]),
        theme: 'grid',
        headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [254, 242, 242] },
        margin: { left: margin, right: margin },
        didParseCell: (data: any) => {
          if (data.section === 'body' && data.column.index === 2) {
            const text = String(data.cell.text).toUpperCase();
            if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
            else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    } else {
      doc.setFillColor(240, 253, 244);
      doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
      doc.setTextColor(22, 163, 74);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('NOT LISTED ON ANY MONITORED BLACKLISTS', margin + 5, y + 7);
      y += 12;
    }
  }

  // DNS Security Details (zone transfer, recursion, SOA consistency)
  if (domainHealth.dns) {
    const dns = domainHealth.dns;
    const securityRows: string[][] = [];
    if (dns.zoneTransferBlocked !== undefined) securityRows.push(['Zone Transfer', dns.zoneTransferBlocked ? 'Blocked (Secure)' : 'ALLOWED (Insecure)']);
    if (dns.recursionDisabled !== undefined) securityRows.push(['Open Recursion', dns.recursionDisabled ? 'Disabled (Secure)' : 'ENABLED (Insecure)']);
    if (dns.soaConsistent !== undefined) securityRows.push(['SOA Consistency', dns.soaConsistent ? 'Consistent' : 'INCONSISTENT']);
    if (dns.nsConsistent !== undefined) securityRows.push(['NS Consistency', dns.nsConsistent ? 'Consistent' : 'INCONSISTENT']);
    if (securityRows.length > 0) {
      y = checkPageBreak(y, 30);
      y = subheading('DNS Security Configuration', y);
      autoTable!(doc, {
        startY: y,
        head: [['Check', 'Status']],
        body: securityRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { cellWidth: 35 } },
        didParseCell: (data: any) => {
          if (data.section === 'body' && data.column.index === 1) {
            const text = String(data.cell.text);
            if (text.includes('ALLOWED') || text.includes('ENABLED') || text.includes('INCONSISTENT')) {
              data.cell.styles.textColor = [220, 38, 38];
              data.cell.styles.fontStyle = 'bold';
            }
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    }
  }

  // Reverse DNS / PTR Records
  if (domainHealth.reverseDns?.records?.length > 0) {
    y = checkPageBreak(y, 30);
    y = subheading('Reverse DNS (PTR Records)', y);
    autoTable!(doc, {
      startY: y,
      head: [['IP Address', 'PTR Hostname(s)', 'Forward Match']],
      body: domainHealth.reverseDns.records.slice(0, 15).map((r: any) => [
        r.ip || 'N/A',
        truncate((r.hostnames || []).join(', '), 50),
        r.matchesForwardDns ? 'Yes' : 'No',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Port Connectivity Status
  if (domainHealth.connectivity?.ports?.length > 0) {
    y = checkPageBreak(y, 30);
    y = subheading('Port Connectivity', y);
    autoTable!(doc, {
      startY: y,
      head: [['Host', 'Port', 'Status', 'Latency']],
      body: domainHealth.connectivity.ports.slice(0, 20).map((p: any) => [
        p.host || 'N/A',
        String(p.port),
        p.connected ? 'Open' : 'Closed/Filtered',
        p.latencyMs ? `${p.latencyMs}ms` : 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 2) {
          const text = String(data.cell.text);
          if (text === 'Open') data.cell.styles.textColor = [22, 163, 74];
          else data.cell.styles.textColor = [220, 38, 38];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 5. BREACH & CREDENTIAL EXPOSURE
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Breach & Credential Exposure');

  // Filter credential observations
  const credentialObs = observations.filter((o: any) =>
    o.assetType === 'credential' ||
    o.tags?.includes('leaked_credential') ||
    o.tags?.includes('credential_breach')
  );

  // Dehashed breach database summaries
  const breachDbObs = observations.filter((o: any) =>
    o.tags?.includes('breach_database') && o.source === 'dehashed'
  );

  // Dehashed overall breach summary
  const breachSummaryObs = observations.find((o: any) =>
    o.tags?.includes('breach_summary') && o.source === 'dehashed'
  );

  const firstPartyObs = credentialObs.filter((o: any) =>
    o.evidence?.credential_source === 'first_party' || o.tags?.includes('first_party_breach')
  );
  const thirdPartyObs = credentialObs.filter((o: any) =>
    o.evidence?.credential_source === 'third_party' || o.tags?.includes('third_party_breach')
  );
  const unknownSourceObs = credentialObs.filter((o: any) =>
    !o.tags?.includes('first_party_breach') && !o.tags?.includes('third_party_breach')
  );

  // Fallback: use scan.breachData if observations don't have breach info
  const breachDataFallback = scan.breachData || {};
  const totalLeaked = credentialObs.length || breachDataFallback.totalExposures || 0;
  const uniqueEmails = breachDataFallback.uniqueEmails || 0;
  const uniqueBreachSources = breachDataFallback.uniqueBreachSources || 0;

  // Breach overview box
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, y, contentWidth, 30, 3, 3, 'F');
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('CREDENTIAL EXPOSURE SUMMARY', margin + 5, y + 8);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text(`Total Leaked Credentials: ${totalLeaked}`, margin + 5, y + 17);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');

  if (firstPartyObs.length > 0) {
    doc.setTextColor(220, 38, 38);
    doc.text(`1st-Party Breaches: ${firstPartyObs.length}`, margin + 5, y + 24);
  } else if (uniqueEmails > 0) {
    doc.setTextColor(202, 138, 4);
    doc.text(`${uniqueEmails} unique emails across ${uniqueBreachSources} breach sources`, margin + 5, y + 24);
  } else {
    doc.setTextColor(34, 197, 94);
    doc.text('No 1st-Party Breaches Detected', margin + 5, y + 24);
  }
  if (thirdPartyObs.length > 0) {
    doc.setTextColor(202, 138, 4);
    doc.text(`3rd-Party Credential Reuse: ${thirdPartyObs.length}`, margin + 80, y + 24);
  }
  if (unknownSourceObs.length > 0) {
    doc.setTextColor(148, 163, 184);
    doc.text(`Unclassified: ${unknownSourceObs.length}`, margin + 145, y + 24);
  }
  y += 34;

  // Breach data summary from pipeline (when observations are empty but breachData exists)
  if (credentialObs.length === 0 && breachDataFallback.totalExposures > 0) {
    y = subheading('Breach Intelligence Summary', y);

    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, y, contentWidth, 22, 2, 2, 'F');
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const col1X = margin + 5;
    const col2X = margin + 55;
    const col3X = margin + 110;
    doc.text(`Total Exposures: ${breachDataFallback.totalExposures}`, col1X, y + 7);
    doc.text(`Unique Emails: ${breachDataFallback.uniqueEmails || 0}`, col2X, y + 7);
    doc.text(`Breach Sources: ${breachDataFallback.uniqueBreachSources || 0}`, col3X, y + 7);
    doc.text(`Passwords Exposed: ${breachDataFallback.passwordsExposed || 0}`, col1X, y + 14);
    doc.text(`Hashed Passwords: ${breachDataFallback.hashedPasswordsExposed || 0}`, col2X, y + 14);
    doc.text(`Credential Pairs: ${breachDataFallback.credentialPairs || 0}`, col3X, y + 14);
    y += 24;

    // Breach sources table
    if (breachDataFallback.breachSources?.length > 0) {
      y = subheading('Breach Sources', y);
      autoTable!(doc, {
        startY: y,
        head: [['Breach Source']],
        body: breachDataFallback.breachSources.slice(0, 30).map((s: string) => [s]),
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        margin: { left: margin, right: margin },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    }
  }

  // Dehashed breach summary statistics
  if (breachSummaryObs) {
    const bsEvidence = breachSummaryObs.evidence || {};
    y = subheading('Breach Intelligence Summary (Dehashed)', y);

    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, y, contentWidth, 22, 2, 2, 'F');
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const col1X = margin + 5;
    const col2X = margin + 55;
    const col3X = margin + 110;
    doc.text(`Total Records: ${bsEvidence.total_records || 0}`, col1X, y + 7);
    doc.text(`Unique Breaches: ${bsEvidence.unique_breaches || 0}`, col2X, y + 7);
    doc.text(`Leaked Accounts: ${bsEvidence.unique_leaked_accounts || 0}`, col3X, y + 7);
    doc.text(`Subdomains Found: ${bsEvidence.unique_subdomains_found || 0}`, col1X, y + 14);
    doc.text(`Unique IPs: ${bsEvidence.unique_ips_found || 0}`, col2X, y + 14);
    doc.text(`Credentials Exposed: ${bsEvidence.credentials_exposed || 0}`, col3X, y + 14);
    y += 24;
  }

  // Dehashed breach database breakdown
  if (breachDbObs.length > 0) {
    y = subheading('Breach Database Attribution', y);

    doc.setTextColor(113, 113, 122);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.text('Individual breach databases where organization credentials were found.', margin, y);
    y += 4;

    autoTable!(doc, {
      startY: y,
      head: [['Breach Database', 'Records Found', 'Credentials Exposed', 'Has Passwords', 'Has Hashes']],
      body: breachDbObs
        .sort((a: any, b: any) => (b.evidence?.total_records || 0) - (a.evidence?.total_records || 0))
        .slice(0, 30)
        .map((o: any) => [
          o.evidence?.database_name || 'Unknown',
          String(o.evidence?.total_records || 0),
          String(o.evidence?.credentials_exposed || 0),
          o.evidence?.has_passwords ? 'YES' : 'No',
          o.evidence?.has_hashed_passwords ? 'YES' : 'No',
        ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && (data.column.index === 3 || data.column.index === 4)) {
          const text = String(data.cell.text);
          if (text === 'YES') {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // 1st-party breaches (critical — these are breaches of the target's own systems)
  if (firstPartyObs.length > 0) {
    y = subheading('1st-Party Breaches (Target Infrastructure Compromised)', y);

    doc.setTextColor(220, 38, 38);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.text('These credentials were leaked from breaches of the target organization\'s own systems.', margin, y);
    y += 6;

    autoTable!(doc, {
      startY: y,
      head: [['Email', 'Credential Type', 'Breach Source', 'Confidence', 'Reasoning']],
      body: firstPartyObs.slice(0, 30).map((o: any) => [
        truncate(o.evidence?.email || o.name, 30),
        (o.evidence?.credential_type || 'unknown').replace(/_/g, ' '),
        truncate(o.evidence?.database_name || o.evidence?.breach_name || 'N/A', 25),
        `${o.evidence?.credential_source_confidence || 0}%`,
        truncate(o.evidence?.credential_source_reasoning, 40),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 1) {
          const text = String(data.cell.text).toLowerCase();
          if (text.includes('plaintext')) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // 3rd-party credential reuse
  if (thirdPartyObs.length > 0) {
    y = subheading('3rd-Party Credential Reuse', y);

    doc.setTextColor(113, 113, 122);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.text('Employees used their corporate email on external services that were subsequently breached.', margin, y);
    y += 6;

    autoTable!(doc, {
      startY: y,
      head: [['Email', 'Credential Type', 'External Service', 'Confidence']],
      body: thirdPartyObs.slice(0, 25).map((o: any) => [
        truncate(o.evidence?.email || o.name, 30),
        (o.evidence?.credential_type || 'unknown').replace(/_/g, ' '),
        truncate(o.evidence?.database_name || o.evidence?.breach_name || 'N/A', 30),
        `${o.evidence?.credential_source_confidence || 0}%`,
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;

    if (thirdPartyObs.length > 25) {
      doc.setTextColor(113, 113, 122);
      doc.setFontSize(7);
      doc.text(`Showing 25 of ${thirdPartyObs.length} third-party credential exposures.`, margin, y);
      y += 6;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 6. DARK WEB & RANSOMWARE INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Dark Web & Ransomware Intelligence');

  const darkwebObs = observations.filter((o: any) =>
    o.tags?.includes('darkweb') ||
    o.tags?.includes('ransomware_listing') ||
    o.tags?.includes('ransomware_live') ||
    o.tags?.includes('ransomware_victim') ||
    o.tags?.includes('iab_listing') ||
    o.tags?.includes('data_leak') ||
    o.tags?.includes('stealer_log') ||
    o.tags?.includes('underground_intel')
  );

  const ransomwareObs = darkwebObs.filter((o: any) =>
    o.tags?.includes('ransomware_listing') ||
    o.tags?.includes('ransomware_live') ||
    o.tags?.includes('ransomware_victim')
  );
  const iabObs = darkwebObs.filter((o: any) => o.tags?.includes('iab_listing') || o.tags?.includes('access_sale'));
  const dataLeakObs = darkwebObs.filter((o: any) => o.tags?.includes('data_leak'));
  const stealerObs = darkwebObs.filter((o: any) => o.tags?.includes('stealer_log') || o.tags?.includes('compromised_employee'));
  const threatGroupObs = darkwebObs.filter((o: any) => o.tags?.includes('threat_group'));

  // Summary box
  const hasDarkwebHits = darkwebObs.length > 0;
  if (hasDarkwebHits) {
    doc.setFillColor(50, 20, 20);
    doc.roundedRect(margin, y, contentWidth, 25, 3, 3, 'F');
    doc.setTextColor(220, 38, 38);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`${darkwebObs.length} DARK WEB MENTIONS DETECTED`, margin + 5, y + 10);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(255, 200, 200);
    const parts = [];
    if (ransomwareObs.length > 0) parts.push(`${ransomwareObs.length} ransomware`);
    if (iabObs.length > 0) parts.push(`${iabObs.length} IAB`);
    if (dataLeakObs.length > 0) parts.push(`${dataLeakObs.length} data leak`);
    if (stealerObs.length > 0) parts.push(`${stealerObs.length} stealer log`);
    if (threatGroupObs.length > 0) parts.push(`${threatGroupObs.length} threat group`);
    doc.text(parts.join(' | '), margin + 5, y + 18);
  } else {
    doc.setFillColor(240, 253, 244);
    doc.roundedRect(margin, y, contentWidth, 15, 3, 3, 'F');
    doc.setTextColor(22, 163, 74);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text('NO DARK WEB MENTIONS DETECTED', margin + 5, y + 10);
  }
  y += hasDarkwebHits ? 32 : 22;

  // Ransomware listings
  if (ransomwareObs.length > 0) {
    y = subheading('Ransomware Leak Site Listings', y);

    autoTable!(doc, {
      startY: y,
      head: [['Listing', 'Threat Actor / Group', 'Victim', 'Date', 'Match Type', 'Source']],
      body: ransomwareObs.slice(0, 20).map((o: any) => [
        truncate(o.evidence?.title || o.name, 35),
        o.evidence?.actor_name || o.evidence?.group_name || 'Unknown',
        truncate(o.evidence?.victim_name || o.evidence?.victim, 20),
        o.evidence?.event_date || o.evidence?.discovered || 'N/A',
        (o.evidence?.match_type || (o.tags?.includes('fuzzy_match') ? 'fuzzy' : 'exact')).replace(/_/g, ' '),
        o.source === 'ransomware_live' ? 'Ransomware.live' : 'DarkWeb CrossRef',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // IAB listings
  if (iabObs.length > 0) {
    y = subheading('Initial Access Broker (IAB) Listings', y);

    autoTable!(doc, {
      startY: y,
      head: [['Listing', 'Actor', 'Date', 'Source']],
      body: iabObs.slice(0, 10).map((o: any) => [
        truncate(o.evidence?.title || o.name, 50),
        o.evidence?.actor_name || 'Unknown',
        o.evidence?.event_date || 'N/A',
        o.evidence?.source_feed || 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Stealer log & compromised employee data
  if (stealerObs.length > 0) {
    y = subheading('Stealer Log & Compromised Employee Data', y);

    autoTable!(doc, {
      startY: y,
      head: [['Source', 'Details', 'Severity', 'Date']],
      body: stealerObs.slice(0, 15).map((o: any) => [
        o.source || 'N/A',
        truncate(o.name || o.evidence?.title, 50),
        getSeverityLabel(o.evidence?.severity || 5),
        o.firstSeen ? new Date(o.firstSeen).toLocaleDateString() : 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 7. THREAT ACTOR ASSESSMENT
  // ═══════════════════════════════════════════════════════════════════════
  if (threatGroupObs.length > 0) {
    y = addSectionPage('Threat Actor Assessment');

    for (const tg of threatGroupObs.slice(0, 5)) {
      y = checkPageBreak(y, 60);

      // Actor profile card
      doc.setFillColor(30, 41, 59);
      const cardHeight = 45;
      doc.roundedRect(margin, y, contentWidth, cardHeight, 3, 3, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(tg.evidence?.actor_name || 'Unknown Actor', margin + 5, y + 8);

      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(148, 163, 184);
      const profileParts = [];
      if (tg.evidence?.actor_type) profileParts.push(`Type: ${tg.evidence.actor_type}`);
      if (tg.evidence?.origin) profileParts.push(`Origin: ${tg.evidence.origin}`);
      if (tg.evidence?.threat_level) profileParts.push(`Threat Level: ${tg.evidence.threat_level.toUpperCase()}`);
      if (tg.evidence?.sophistication) profileParts.push(`Sophistication: ${tg.evidence.sophistication}`);
      doc.text(profileParts.join(' | '), margin + 5, y + 14);

      if (tg.evidence?.motivation) {
        doc.text(`Motivation: ${tg.evidence.motivation}`, margin + 5, y + 20);
      }

      if (tg.evidence?.description) {
        doc.setTextColor(200, 210, 220);
        doc.setFontSize(7);
        const descLines = doc.splitTextToSize(truncate(tg.evidence.description, 300), contentWidth - 10);
        doc.text(descLines, margin + 5, y + 26);
      }

      // TTPs
      doc.setTextColor(148, 163, 184);
      doc.setFontSize(7);
      if (tg.evidence?.techniques) {
        const techniques = Array.isArray(tg.evidence.techniques) ? tg.evidence.techniques : [];
        if (techniques.length > 0) {
          doc.text(`TTPs: ${truncate(techniques.join(', '), 100)}`, margin + 5, y + 36);
        }
      }
      if (tg.evidence?.tools) {
        const tools = Array.isArray(tg.evidence.tools) ? tg.evidence.tools : [];
        if (tools.length > 0) {
          doc.text(`Tools: ${truncate(tools.join(', '), 100)}`, margin + 5, y + 40);
        }
      }

      y += cardHeight + 5;

      // Attributed events table
      if (tg.evidence?.attributed_events?.length > 0) {
        y = checkPageBreak(y, 30);
        doc.setTextColor(51, 65, 85);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(`Attributed Incidents (${tg.evidence.attributed_events_count} total)`, margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Type', 'Title', 'Victim', 'Sector', 'Date']],
          body: tg.evidence.attributed_events.slice(0, 10).map((e: any) => [
            (e.type || 'unknown').replace(/_/g, ' '),
            truncate(e.title, 40),
            truncate(e.victim, 20),
            truncate(e.sector, 15),
            e.date || 'N/A',
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 4;
      }

      // Relevant IOCs
      if (tg.evidence?.relevant_iocs?.length > 0) {
        y = checkPageBreak(y, 30);
        doc.setTextColor(51, 65, 85);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(`Indicators of Compromise (${tg.evidence.relevant_iocs_count} total)`, margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Type', 'Value', 'Confidence', 'First Seen', 'Last Seen']],
          body: tg.evidence.relevant_iocs.slice(0, 10).map((i: any) => [
            (i.type || 'unknown').replace(/_/g, ' '),
            truncate(i.value, 50),
            i.confidence || 'N/A',
            i.first_seen || 'N/A',
            i.last_seen || 'N/A',
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 10;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 8. VULNERABILITY & TECHNOLOGY LANDSCAPE
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Vulnerability & Technology Landscape');

  // Technology stack
  const allTechs = new Map<string, number>();
  for (const asset of assets) {
    if (Array.isArray(asset.technologies)) {
      for (const tech of asset.technologies) {
        allTechs.set(tech, (allTechs.get(tech) || 0) + 1);
      }
    }
  }

  if (allTechs.size > 0) {
    y = subheading('Technology Stack', y);

    autoTable!(doc, {
      startY: y,
      head: [['Technology', 'Assets Using', '% Coverage']],
      body: Array.from(allTechs.entries())
        .sort(([, a], [, b]) => b - a)
        .slice(0, 25)
        .map(([tech, count]) => [
          tech,
          String(count),
          `${assets.length > 0 ? ((count / assets.length) * 100).toFixed(1) : 0}%`,
        ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // WAF/NGFW detection
  if (wafNgfw.detections?.length > 0) {
    y = subheading('WAF / NGFW Detection', y);

    autoTable!(doc, {
      startY: y,
      head: [['Asset', 'WAF/NGFW', 'Vendor', 'Confidence']],
      body: wafNgfw.detections.slice(0, 15).map((d: any) => [
        truncate(d.hostname || d.asset, 35),
        d.product || 'Unknown',
        d.vendor || 'Unknown',
        `${d.confidence || 0}%`,
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Vulnerability observations — separated into tiers with managed provider filtering
  const vulnObs = observations.filter((o: any) =>
    o.tags?.includes('vulnerability') || o.tags?.includes('cve') || o.evidence?.cve_id
  );

  // Helper: render a grouped CVE card (header bar + finding name + evidence + affected hosts)
  const renderCveCard = (
    o: any,
    headerColor: [number, number, number],
    _textColor: [number, number, number],
    _hostLabelColor: [number, number, number],
    showVersion: boolean,
    showKev: boolean,
  ): void => {
    const cveId = o.evidence?.cve_id || 'N/A';
    const findingName = o.name?.replace(/^CVE-\d{4}-\d+:\s*/, '') || 'Unknown';
    const sev = getSeverityLabel(o.evidence?.severity || 5);
    const cvss = o.evidence?.cvssScore ? String(o.evidence.cvssScore) : 'N/A';
    const version = o.evidence?.detectedVersion || 'N/A';
    const hosts: string[] = o.evidence?.affectedHosts || [o.evidence?.hostname || domain];
    const kevListed = o.evidence?.kevListed;
    const description = o.evidence?.description || '';
    const corroboration = o.evidence?.corroboration || '';
    const affectedVersions = o.evidence?.affectedVersions || '';

    // Build evidence summary line from available data
    const evidenceParts: string[] = [];
    if (corroboration === '[CONFIRMED]' && version && version !== 'N/A') {
      if (affectedVersions) {
        evidenceParts.push(`Version ${version} confirmed within affected range (${affectedVersions})`);
      } else {
        evidenceParts.push(`Version ${version} detected and confirmed vulnerable`);
      }
    }
    if (kevListed) evidenceParts.push('Listed in CISA Known Exploited Vulnerabilities catalog');
    if (o.evidence?.exploitAvailable) evidenceParts.push('Public exploit available');
    const evidenceSummary = evidenceParts.length > 0 ? evidenceParts.join(' \u2022 ') : '';

    // Get NVD description: prefer dedicated field, fall back to parsing from evidenceDetail
    let nvdDesc = o.evidence?.nvdDescription || '';
    if (!nvdDesc && description) {
      const nvdMatch = description.match(/NVD:\s*(.+)$/s);
      if (nvdMatch) {
        nvdDesc = nvdMatch[1].trim();
      } else if (!description.startsWith('CONFIRMED:') && !description.startsWith('PROBABLE:')) {
        nvdDesc = description;
      }
    }

    // Estimate card height: header(10) + name(5) + evidence(4) + nvd(8) + hosts(hosts.length * 3.5) + padding(6)
    const hasEvidence = evidenceSummary.length > 0;
    const hasNvd = nvdDesc.length > 0;
    const estimatedHeight = 10 + 6 + (hasEvidence ? 5 : 0) + (hasNvd ? 10 : 0) + Math.max(hosts.length * 3.5, 4) + 6;
    y = checkPageBreak(y, estimatedHeight);

    // ── Header bar (taller for readability) ──
    doc.setFillColor(headerColor[0], headerColor[1], headerColor[2]);
    doc.roundedRect(margin, y, contentWidth, 9, 1.5, 1.5, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text(cveId, margin + 3, y + 6);
    // Right-aligned metadata chips
    const chips: string[] = [`Sev: ${sev}`, `CVSS: ${cvss}`];
    if (showVersion && version !== 'N/A') chips.push(`Ver: ${version}`);
    if (showKev && kevListed) chips.push('KEV');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    let chipX = pageWidth - margin - 3;
    for (let i = chips.length - 1; i >= 0; i--) {
      const cw = doc.getTextWidth(chips[i]) + 4;
      chipX -= cw;
      doc.setFillColor(255, 255, 255, 0.2 as any);
      doc.roundedRect(chipX, y + 2, cw, 5, 1, 1, 'F');
      doc.setTextColor(255, 255, 255);
      doc.text(chips[i], chipX + 2, y + 5.5);
      chipX -= 2;
    }
    y += 12; // Clear gap below header bar

    // ── Finding name ──
    doc.setTextColor(20, 20, 20);
    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'bold');
    const nameLines = doc.splitTextToSize(findingName, contentWidth - 6);
    for (const line of nameLines) {
      y = checkPageBreak(y, 5);
      doc.text(line, margin + 3, y);
      y += 3.5;
    }
    y += 1;

    // ── NVD Description (if available) ──
    if (hasNvd) {
      doc.setTextColor(60, 60, 60);
      doc.setFontSize(6.5);
      doc.setFont('helvetica', 'normal');
      const nvdLines = doc.splitTextToSize(nvdDesc, contentWidth - 8);
      const maxNvdLines = Math.min(nvdLines.length, 3); // Cap at 3 lines
      for (let i = 0; i < maxNvdLines; i++) {
        y = checkPageBreak(y, 4);
        doc.text(nvdLines[i] + (i === maxNvdLines - 1 && nvdLines.length > 3 ? '...' : ''), margin + 3, y);
        y += 2.8;
      }
      y += 1;
    }

    // ── Evidence / Corroboration summary ──
    if (hasEvidence) {
      doc.setFontSize(6);
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(22, 101, 52); // green-800 for confirmed evidence
      y = checkPageBreak(y, 4);
      const evidenceLines = doc.splitTextToSize(`Evidence: ${evidenceSummary}`, contentWidth - 8);
      for (const line of evidenceLines.slice(0, 2)) {
        doc.text(line, margin + 3, y);
        y += 2.8;
      }
      y += 1;
    }

    // ── Affected hosts ──
    doc.setFontSize(6.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(50, 50, 50);
    y = checkPageBreak(y, 5);
    doc.text(`Affected Assets (${hosts.length}):`, margin + 3, y);
    y += 3.5;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(60, 60, 60);
    for (const host of hosts) {
      y = checkPageBreak(y, 4);
      doc.text(`\u2022  ${host}`, margin + 5, y);
      y += 3;
    }
    y += 4; // Clear gap before next card
  };

  if (vulnObs.length > 0) {
    // Tier 1: Confirmed (version-matched) — NOT on provider-managed-only hosts
    const confirmedVulns = vulnObs.filter((o: any) =>
      o.evidence?.corroboration === '[CONFIRMED]' && !o.evidence?.providerManagedOnly
    );
    // Tier 2: Probable vulns excluded from client-facing reports (only confirmed shown)
    // Tier 3: Provider-managed CVEs removed — unproven product-family KEV matches

    if (confirmedVulns.length > 0) {
      y = subheading(`Confirmed Vulnerabilities (${confirmedVulns.length})`, y);

      for (const vuln of confirmedVulns) {
        const sevScore = vuln.evidence?.severity || 5;
        const headerColor: [number, number, number] = sevScore >= 9 ? [153, 27, 27] : sevScore >= 7 ? [194, 65, 12] : [30, 41, 59];
        renderCveCard(vuln, headerColor, [51, 65, 85], [30, 41, 59], true, true);
      }
      y += 2;
    }

    // Probable findings — show count and version enumeration recommendation
    const probableVulns = vulnObs.filter((o: any) =>
      o.evidence?.corroboration === '[PROBABLE]' && !o.evidence?.providerManagedOnly
    );
    if (probableVulns.length > 0) {
      y = checkPageBreak(y, 30);
      // Yellow recommendation box
      const boxY = y;
      doc.setFillColor(255, 251, 235); // warm yellow bg
      doc.setDrawColor(234, 179, 8); // yellow border
      doc.roundedRect(margin, boxY, contentWidth, 24, 2, 2, 'FD');
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(146, 64, 14); // amber-800
      doc.text(`Version Enumeration Recommended — ${probableVulns.length} Probable Finding${probableVulns.length !== 1 ? 's' : ''}`, margin + 4, boxY + 6);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(120, 53, 15); // amber-900
      const recText = `${probableVulns.length} additional finding${probableVulns.length !== 1 ? 's' : ''} matched known products (e.g., ${probableVulns.slice(0, 3).map((v: any) => v.evidence?.findingName?.split(':')[0] || v.evidence?.cveIds?.[0] || 'CVE').join(', ')}${probableVulns.length > 3 ? '...' : ''}) but the installed version could not be confirmed passively. Run active version enumeration (nmap -sV, banner grab, or authenticated scan) to confirm versions and upgrade these to confirmed findings.`;
      const recLines = doc.splitTextToSize(recText, contentWidth - 8);
      doc.text(recLines, margin + 4, boxY + 11);
      y = boxY + 26;
    }

    // Provider-managed CVEs removed from report — these are unproven product-family
    // KEV matches without version confirmation and cannot be verified as client vulnerabilities.
    // Managed provider infrastructure patching is the provider's responsibility.
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 8b. PROVIDER-MANAGED INFRASTRUCTURE
  // ═══════════════════════════════════════════════════════════════════════
  if (_managedMailProvider || _managedMailHosts.size > 0) {
    y = addSectionPage('Provider-Managed Infrastructure');

    // Intro paragraph
    doc.setFontSize(9);
    doc.setTextColor(80, 80, 80);
    const managedIntro = `The following assets are hosted on infrastructure managed by a third-party provider${_managedMailProvider ? ` (${_managedMailProvider})` : ''}. Vulnerabilities on these assets are the responsibility of the managed service provider, not the client organization. These assets and their associated CVEs have been excluded from the client risk score calculation.`;
    const introLines = doc.splitTextToSize(managedIntro, contentWidth);
    doc.text(introLines, margin, y);
    y += introLines.length * 4 + 3;

    // Managed assets table
    const managedAssets = assets.filter((a: any) => _managedMailHosts.has(a.hostname));
    if (managedAssets.length > 0) {
      y = subheading('Managed Assets', y);
      autoTable!(doc, {
        startY: y,
        head: [['Hostname', 'Asset Type', 'Provider', 'Risk Exclusion Reason']],
        body: managedAssets.map((a: any) => [
          truncate(a.hostname, 35),
          a.assetType || a.type || 'Infrastructure',
          _managedMailProvider || 'Third-Party Provider',
          a.tags?.includes('reverse_whois') ? 'Reverse WHOIS — third-party registrant'
            : a.tags?.includes('related_domain') ? 'Related domain — different registrant'
            : `Managed by ${_managedMailProvider || 'provider'}`,
        ]),
        theme: 'grid',
        headStyles: { fillColor: [100, 116, 139], textColor: [255, 255, 255], fontSize: 7.5 },
        bodyStyles: { fontSize: 7, textColor: [60, 60, 60] },
        columnStyles: { 0: { cellWidth: 45 }, 1: { cellWidth: 30 }, 2: { cellWidth: 35 } },
        margin: { left: margin, right: margin },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    }

    // Managed CVEs removed from report — unproven product-family KEV matches
    // without version confirmation. Provider is responsible for their own patching.

    // Risk score exclusion note
    const exclusions = scan.pipelineOutput?.riskScoreExclusions || scan.riskScoreExclusions || [];
    if (exclusions.length > 0) {
      y = subheading('Risk Score Impact', y);
      doc.setFontSize(8);
      doc.setTextColor(80, 80, 80);
      const impactText = `${exclusions.length} asset(s) excluded from the overall risk score: ${exclusions.map((e: any) => `${e.hostname} (${e.reason})`).join('; ')}. The reported risk score of ${scan.overallRiskScore ?? 'N/A'}/100 reflects only client-owned infrastructure.`;
      const impactLines = doc.splitTextToSize(impactText, contentWidth);
      doc.text(impactLines, margin, y);
      y += impactLines.length * 4 + 3;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 9. PRIORITIZED RECOMMENDATIONS
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Prioritized Recommendations');

  // LLM-generated recommendations
  if (llmAnalysis.recommendations?.length > 0) {
    autoTable!(doc, {
      startY: y,
      head: [['Priority', 'Recommendation', 'Category', 'Effort']],
      body: llmAnalysis.recommendations.slice(0, 20).map((r: any, i: number) => [
        `P${i + 1}`,
        truncate(r.recommendation || r.title || r, 60),
        truncate(r.category || 'General', 20),
        r.effort || 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 0) {
          const text = String(data.cell.text);
          if (text === 'P1') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'P2') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'P3') data.cell.styles.textColor = [202, 138, 4];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Attack chains / blind spots from LLM analysis
  if (llmAnalysis.attackChains?.length > 0) {
    y = subheading('Identified Attack Chains', y);

    for (const chain of llmAnalysis.attackChains.slice(0, 5)) {
      y = checkPageBreak(y, 20);
      doc.setTextColor(51, 65, 85);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text(`Chain: ${truncate(chain.name || chain.title, 60)}`, margin, y);
      y += 4;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      y = writeText(truncate(chain.description || chain.narrative, 300), margin + 3, y, contentWidth - 6, 7);
      y += 3;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 10. APPENDIX — DATA SOURCES & METHODOLOGY
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Appendix: Data Sources & Methodology');

  // Connector results — use passiveRecon.connectorResults (trimmed summary) or scan.connectorResults
  const connectorResults = scan.passiveRecon?.connectorResults || scan.connectorResults || [];
  if (connectorResults.length > 0) {
    y = subheading('Data Sources Queried', y);

    autoTable!(doc, {
      startY: y,
      head: [['Source', 'Observations', 'Duration', 'Status']],
      body: connectorResults
        .sort((a: any, b: any) => (b.observationCount || b.observations?.length || 0) - (a.observationCount || a.observations?.length || 0))
        .slice(0, 40)
        .map((cr: any) => [
          (cr.connector || 'unknown').replace(/_/g, ' '),
          String(cr.observationCount ?? cr.observations?.length ?? 0),
          cr.durationMs ? `${(cr.durationMs / 1000).toFixed(1)}s` : 'N/A',
          cr.errors?.length > 0 ? `Error: ${truncate(cr.errors[0], 30)}` : cr.rateLimited ? 'Rate Limited' : 'OK',
        ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const text = String(data.cell.text);
          if (text.startsWith('Error')) data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'Rate Limited') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'OK') data.cell.styles.textColor = [22, 163, 74];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Discovery coverage
  if (discoveryCoverage.coveragePercentage !== undefined) {
    y = subheading('Discovery Coverage', y);
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(`Overall Coverage: ${discoveryCoverage.coveragePercentage}%`, margin, y);
    y += 5;
    if (discoveryCoverage.gaps?.length > 0) {
      doc.text(`Identified Gaps: ${discoveryCoverage.gaps.join(', ')}`, margin, y);
      y += 5;
    }
  }

  // Scan metadata
  y = checkPageBreak(y, 30);
  y = subheading('Scan Metadata', y);
  const metaRows: string[][] = [
    ['Scan ID', String(scan.id || 'N/A')],
    ['Domain', domain],
    ['Scan Mode', scan.scanMode || 'standard'],
    ['Started', scan.createdAt ? new Date(scan.createdAt).toLocaleString() : 'N/A'],
    ['Duration', scanDuration ? `${(scanDuration / 1000).toFixed(1)} seconds` : 'N/A'],
    ['Confirmed Findings', String(_confirmedCount)],
    ['Total Assets', String(scan.totalAssets || assets.length)],
    ['Data Sources', String(connectorCount)],
    ['Web Crawl', scan.pipelineCrawl ? `${scan.pipelineCrawl.totalCrawled}/${scan.pipelineCrawl.totalAssets} assets crawled (${scan.pipelineCrawl.totalFindings} findings, grade: ${scan.pipelineCrawl.worstGrade})` : 'Not run'],
    ['CARVER Adjustments (Crawl)', scan.pipelineCrawl?.carverAdjustmentsApplied ? `${scan.pipelineCrawl.carverAdjustmentsApplied} assets adjusted` : 'N/A'],
    ['Report Generated', new Date().toLocaleString()],
  ];

  autoTable!(doc, {
    startY: y,
    head: [['Property', 'Value']],
    body: metaRows,
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
    margin: { left: margin, right: margin },
    columnStyles: { 0: { cellWidth: 40 } },
  });

  // ═══════════════════════════════════════════════════════════════════════
  // RENDER TABLE OF CONTENTS (go back to the reserved TOC page)
  // ═══════════════════════════════════════════════════════════════════════
  doc.setPage(tocPageNum);

  // Dark header bar
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 22, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('Table of Contents', margin, 14);
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text(domain, pageWidth - margin - doc.getTextWidth(domain), 14);

  let tocY = 35;
  const tocPageCount = (doc as any).internal.getNumberOfPages();

  for (const entry of tocEntries) {
    // Section number
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    const numText = `${entry.sectionNum}.`;
    doc.text(numText, margin, tocY);

    // Section title
    const titleX = margin + 12;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(30, 41, 59);
    doc.text(entry.title, titleX, tocY);

    // Dotted leader line
    const titleWidth = doc.getTextWidth(entry.title);
    const leaderStartX = titleX + titleWidth + 2;
    const pageNumText = String(entry.pageNum);
    doc.setFontSize(10);
    const pageNumWidth = doc.getTextWidth(pageNumText);
    const leaderEndX = pageWidth - margin - pageNumWidth - 2;

    if (leaderEndX > leaderStartX + 5) {
      doc.setTextColor(180, 180, 180);
      doc.setFontSize(8);
      let dotX = leaderStartX;
      while (dotX < leaderEndX) {
        doc.text('.', dotX, tocY);
        dotX += 2;
      }
    }

    // Page number (right-aligned)
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(100, 116, 139);
    doc.text(pageNumText, pageWidth - margin - pageNumWidth, tocY);

    // Clickable link area covering the entire row
    doc.link(margin, tocY - 4, contentWidth, 6, { pageNumber: entry.pageNum });

    tocY += 8;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // FOOTER ON ALL PAGES
  // ═══════════════════════════════════════════════════════════════════════
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 30, pageHeight - 8);
    doc.text('CONFIDENTIAL — For authorized recipients only', margin, pageHeight - 8);
  }

  doc.save(`EASM_Report_${domain}_${dateStamp()}.pdf`);
}

// Helper: add footer to current page
function addFooter(doc: any, margin: number, pageWidth: number, pageHeight: number) {
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text(`Page ${doc.getCurrentPageInfo().pageNumber}`, pageWidth - 30, pageHeight - 8);
  doc.text('CONFIDENTIAL', margin, pageHeight - 8);
}
