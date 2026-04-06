/**
 * Domain Intelligence PDF Report Export
 * 
 * Generates a comprehensive, client-ready Domain Intelligence
 * report from DI scan results. Designed for proposal delivery, client
 * presentations, and compliance documentation.
 * 
 * Sections:
 *   1. Cover Page — branded, domain, date, classification
 *   2. Executive Summary — risk gauge, key metrics, narrative
 *   3. Attack Surface Inventory — assets by type, criticality, risk band
 *   4. Domain Health & Blacklist Status — DNS, SSL, DNSBL, email security
 *  4b. Domain Registration Details — RDAP/WHOIS registrar, expiry, DNSSEC, locks
 *  4c. SSL Certificate Health — primary cert, discovered certs, expiry warnings
 *  4d. Risky Service Exposure — high/medium risk ports, service classification
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
 * Export a comprehensive Domain Intelligence PDF report
 */
export async function exportDiReport(
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
        // CRITICAL: Every finding MUST get an explicit tier label. Findings without a label
        // would fall through filters and incorrectly appear in the wrong section.
        const corroborationLabel = f.corroborationTier === 'confirmed' ? '[CONFIRMED]'
          : f.corroborationTier === 'probable' ? '[PROBABLE]'
          : f.corroborationTier === 'potential' ? '[POTENTIAL]'
          : f.versionMatchConfirmed === false ? '[POTENTIAL]'
          : '[POTENTIAL]'; // Default: anything without explicit tier is potential

        // Check if this CVE is on a managed provider host
        const assetHostname = f.assetHostname || asset.hostname || '';
        const isOnManagedHost = _managedMailHosts.has(assetHostname);

        // Deduplicate CVEs: merge same CVE across assets into one observation
        if (cveId && cveDedup.has(cveId)) {
          const existing = cveDedup.get(cveId);
          if (!existing.evidence.affectedHosts.includes(assetHostname)) {
            existing.evidence.affectedHosts.push(assetHostname);
          }
          // Track per-tier instance counts for this CVE
          if (!existing.evidence._tierCounts) existing.evidence._tierCounts = { confirmed: 0, probable: 0, potential: 0 };
          if (corroborationLabel === '[CONFIRMED]') existing.evidence._tierCounts.confirmed++;
          else if (corroborationLabel === '[PROBABLE]') existing.evidence._tierCounts.probable++;
          else existing.evidence._tierCounts.potential++;
          // Upgrade tier if this instance has stronger evidence
          // Priority: CONFIRMED > PROBABLE > POTENTIAL
          const tierRank = (t: string) => t === '[CONFIRMED]' ? 3 : t === '[PROBABLE]' ? 2 : 1;
          if (tierRank(corroborationLabel) > tierRank(existing.evidence.corroboration || '[POTENTIAL]')) {
            existing.evidence.corroboration = corroborationLabel;
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

    // Map blacklist category — preserve all rich data fields from the DNSBL engine
    if (cats.blacklist && !normalized.blacklist) {
      const bl = cats.blacklist.details || {};
      normalized.blacklist = {
        listings: (bl.listed || []).map((l: any) => {
          if (typeof l === 'string') {
            return { zone: l, category: 'listed', severity: 'medium', reason: l, returnCodeMeaning: '', returnCodes: [], lookupUrl: '', actionRequired: true, falsePositiveIndicators: [], ip: bl.ip || '' };
          }
          return {
            zone: l.zone || l.name || 'Unknown',
            category: l.category || 'listed',
            severity: l.severity || 'medium',
            reason: l.reason || l.txtReason || '',
            returnCodeMeaning: l.returnCodeMeaning || '',
            returnCodes: l.returnCodes || l.result || [],
            lookupUrl: l.lookupUrl || '',
            actionRequired: l.actionRequired !== false,
            falsePositiveIndicators: l.falsePositiveIndicators || [],
            ip: l.ip || bl.ip || '',
          };
        }),
        clean: bl.clean || [],
        totalChecked: bl.totalChecked || 0,
        ip: bl.ip || '',
        reverseDns: bl.reverseDns || [],
        isCloudHosted: bl.isCloudHosted || false,
        cloudProvider: bl.cloudProvider || null,
        actionableCount: bl.actionableCount || 0,
        informationalCount: bl.informationalCount || 0,
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

  // Helper: smart section start — only adds a new page if remaining space is insufficient.
  // minContentHeight = minimum space (in mm) needed below the header for meaningful content.
  // If enough space remains on the current page, renders a section header inline with a divider.
  // Returns the new y position after the header.
  function startSection(title: string, currentY: number, minContentHeight: number = 80, opts?: { skipToc?: boolean }): number {
    const headerHeight = 22;
    const spaceNeeded = headerHeight + minContentHeight;
    const remainingSpace = pageHeight - currentY - 15; // 15mm bottom margin

    if (remainingSpace < spaceNeeded) {
      // Not enough space — force a new page with full-width header bar
      return addSectionPage(title, opts);
    }

    // Enough space — render inline section header with divider
    const pageNum = (doc as any).internal.getNumberOfPages();
    if (!opts?.skipToc) {
      sectionCounter++;
      tocEntries.push({ title, pageNum, sectionNum: String(sectionCounter) });
    }

    // Separator line
    currentY += 6;
    doc.setDrawColor(203, 213, 225); // slate-300
    doc.setLineWidth(0.3);
    doc.line(margin, currentY, pageWidth - margin, currentY);
    currentY += 8;

    // Section header bar (inline, narrower than full-page version)
    doc.setFillColor(15, 23, 42);
    doc.roundedRect(margin, currentY, contentWidth, 16, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text(title, margin + 5, currentY + 11);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(domain, margin + contentWidth - doc.getTextWidth(domain) - 5, currentY + 11);
    return currentY + 22;
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
  doc.text('Domain Intelligence', margin, 55);
  doc.text('Report', margin, 67);

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
  // Count confirmed findings — use observation-level counting (same as vuln section)
  // This ensures the cover page number matches what the vulnerability details section shows
  const _clientFindings = observations.filter((o: any) => !o.evidence?.providerManagedOnly);
  const _coverConfirmedCount = _clientFindings.filter((o: any) =>
    o.evidence?.corroboration === '[CONFIRMED]' || o.confidence === 'confirmed'
  ).length;
  // Fallback to scan-level count only if observation counting yields zero
  const _confirmedCount = _coverConfirmedCount > 0 ? _coverConfirmedCount : (scan.confirmedFindingsCount || 0);
  doc.text(`Confirmed Findings: ${_confirmedCount}`, metricsX, y + 25);
  // Count data sources: prefer connectors with observations, fallback to total connectors, then unique observation sources
  const _connectorResultsWithObs = scan.passiveRecon?.connectorResults?.filter((c: any) => c.observationCount > 0);
  const connectorCount = (_connectorResultsWithObs?.length > 0)
    ? _connectorResultsWithObs.length
    : (scan.connectorResults?.length > 0)
      ? scan.connectorResults.length
      : (scan.passiveRecon?.connectorResults?.length > 0)
        ? scan.passiveRecon.connectorResults.length
        : new Set(observations.map((o: any) => o.source || o.connector || 'unknown')).size || 0;
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

  // Pre-compute critical/high asset lists (used in BLUF and later sections)
  const criticalAssets = assets.filter((a: any) => a.riskBand === 'critical' || a.hybridRiskScore >= 80);
  const highAssets = assets.filter((a: any) => a.riskBand === 'high' || (a.hybridRiskScore >= 60 && a.hybridRiskScore < 80));

  // ─── BLUF (Bottom Line Up Front) ─────────────────────────────────────
  // Build a single data-driven paragraph that concisely summarizes the entire report.
  const _totalAssets = scan.totalAssets ?? assets.length ?? 0;
  // Compute findings breakdown — ALWAYS use observation-level counting to ensure
  // consistency between the BLUF, cover page, and vulnerability details section.
  // The observation synthesis deduplicates CVEs across assets, so these counts
  // represent unique vulnerabilities, not (CVE × asset) instance pairs.
  const _clientObs = observations.filter((o: any) => !o.evidence?.providerManagedOnly);
  let _confirmedFc = _clientObs.filter((o: any) =>
    o.evidence?.corroboration === '[CONFIRMED]' ||
    o.confidence === 'confirmed'
  ).length;
  let _probableFc = _clientObs.filter((o: any) =>
    o.evidence?.corroboration === '[PROBABLE]' ||
    o.confidence === 'probable'
  ).length;
  let _potentialFc = _clientObs.filter((o: any) =>
    o.evidence?.corroboration === '[POTENTIAL]' ||
    o.evidence?.corroboration === '[UNCONFIRMED VERSION]' ||
    o.confidence === 'potential'
  ).length;
  // Anything unclassified goes into potential
  const _classifiedTotal = _confirmedFc + _probableFc + _potentialFc;
  const _unclassified = _clientObs.length - _classifiedTotal;
  if (_unclassified > 0) _potentialFc += _unclassified;
  // Total findings = observation count (deduplicated)
  const _totalFindings = _clientObs.length;

  // KEV count — require explicit kevListed evidence flag; tag-only matching is too loose
  const _kevCount = observations.filter((o: any) =>
    o.evidence?.kevListed === true ||
    o.evidence?.kevMatch === true ||
    (o.evidence?.kevData && Object.keys(o.evidence.kevData).length > 0)
  ).length;
  const _breachExposures = scan.breachData?.totalExposures ?? 0;
  const _breachEmails = scan.breachData?.uniqueEmails ?? 0;
  const _emailGrade = scan.emailSecurity?.overallGrade || (domainHealth.emailSecurity as any)?.grade || null;
  const _complianceScore = scan.complianceScan?.complianceScore ?? null;
  const _containerHits = scan.containerExposure?.totalHits ?? 0;
  const _exploitTotal = scan.exploitMatches ? (scan.exploitMatches.totalMetasploit + scan.exploitMatches.totalExploitDb + scan.exploitMatches.totalCalderaAbilities) : 0;
  const _oemCredCount = scan.oemCredentials?.length ?? 0;
  const _confirmedLogins = scan.credentialTestSummary?.successfulLogins ?? 0;
  const _scanDelta = scan.scanDelta;
  const _blCritical = criticalAssets.length;
  const _blHigh = highAssets.length;
  const _blacklistCount = domainHealth.blacklist?.listings?.length ?? 0;
  const _blacklistActionable = domainHealth.blacklist?.listings?.filter((l: any) => l.actionRequired !== false)?.length ?? 0;

  // Compose BLUF
  const blufParts: string[] = [];

  // Opening: risk posture
  blufParts.push(`${domain} presents a ${riskBand.toUpperCase()} risk posture (${riskScore}/100) based on passive analysis of ${_totalAssets} discovered asset(s) across ${connectorCount} intelligence sources.`);

  // Findings breakdown — prefer unique CVE counts for clarity
  const _uniqueCve = scan.uniqueCveSummary;
  if (_totalFindings > 0) {
    const findingBreakdown: string[] = [];
    if (_confirmedFc > 0) findingBreakdown.push(`${_confirmedFc} confirmed`);
    if (_probableFc > 0) findingBreakdown.push(`${_probableFc} probable`);
    if (_potentialFc > 0) findingBreakdown.push(`${_potentialFc} potential`);
    if (_uniqueCve && _uniqueCve.uniqueCveCount > 0 && _uniqueCve.uniqueCveCount < _totalFindings) {
      // Show unique CVEs prominently, total instances as context
      blufParts.push(`The scan identified ${_uniqueCve.uniqueCveCount} unique vulnerabilities across ${_totalAssets} asset(s) (${_totalFindings} total finding instances: ${findingBreakdown.join(', ')}). On average, each vulnerability affects ${_uniqueCve.averageAssetsPerCve} asset(s).`);
    } else {
      blufParts.push(`The scan identified ${_totalFindings} total finding(s) (${findingBreakdown.join(', ')}).`);
    }
  }

  // Critical/high assets
  if (_blCritical > 0 || _blHigh > 0) {
    const riskParts: string[] = [];
    if (_blCritical > 0) riskParts.push(`${_blCritical} critical`);
    if (_blHigh > 0) riskParts.push(`${_blHigh} high`);
    blufParts.push(`${riskParts.join(' and ')} risk asset(s) require immediate attention.`);
  }

  // KEV — use unique CVE count when available
  if (_kevCount > 0) {
    if (_uniqueCve && _uniqueCve.uniqueKevCveCount > 0 && _uniqueCve.uniqueKevCveCount < _kevCount) {
      blufParts.push(`${_uniqueCve.uniqueKevCveCount} unique CISA KEV vulnerabilities were identified across ${_kevCount} finding instance(s).`);
    } else {
      blufParts.push(`${_kevCount} finding(s) are listed in CISA's Known Exploited Vulnerabilities catalog.`);
    }
  }

  // Exploit availability
  if (_exploitTotal > 0) {
    blufParts.push(`${_exploitTotal} public exploit(s) were matched (${scan.exploitMatches?.totalMetasploit || 0} Metasploit, ${scan.exploitMatches?.totalExploitDb || 0} ExploitDB, ${scan.exploitMatches?.totalCalderaAbilities || 0} Caldera).`);
  }

  // Breach exposure
  if (_breachExposures > 0) {
    blufParts.push(`Breach intelligence shows ${_breachExposures} credential exposure(s) across ${_breachEmails} unique email(s).`);
  }

  // Default credentials
  if (_oemCredCount > 0) {
    const loginNote = _confirmedLogins > 0 ? ` — ${_confirmedLogins} confirmed accessible` : '';
    blufParts.push(`${_oemCredCount} default/OEM credential set(s) matched to discovered services${loginNote}.`);
  }

  // Email security
  if (_emailGrade) {
    blufParts.push(`Email security posture is grade ${_emailGrade}.`);
  }

  // Blacklist — include the actual IP address for specificity
  const _blIp = domainHealth.blacklist?.ip || '';
  if (_blacklistCount > 0) {
    blufParts.push(`${_blIp ? `IP ${_blIp}` : 'Primary IP'} is listed on ${_blacklistCount} DNSBL(s) (${_blacklistActionable} actionable).`);
  } else if (domainHealth.blacklist) {
    blufParts.push(`${_blIp ? `IP ${_blIp}` : 'Primary IP'} is clean across all ${domainHealth.blacklist.totalChecked || ''} monitored blacklists.`);
  }

  // Compliance
  if (_complianceScore !== null) {
    blufParts.push(`External compliance scan scored ${_complianceScore}% (${scan.complianceScan?.passed}/${scan.complianceScan?.totalChecks} checks passed).`);
  }

  // Container exposure
  if (_containerHits > 0) {
    blufParts.push(`${_containerHits} exposed container service(s) detected (${scan.containerExposure?.criticalFindings || 0} critical).`);
  }

  // Scan delta trend
  if (_scanDelta && _scanDelta.riskDelta !== null) {
    const direction = _scanDelta.riskDelta > 0 ? 'increased' : _scanDelta.riskDelta < 0 ? 'decreased' : 'unchanged';
    const deltaAbs = Math.abs(_scanDelta.riskDelta);
    blufParts.push(`Compared to the previous scan (#${_scanDelta.scanNumber - 1}), risk has ${direction}${deltaAbs > 0 ? ` by ${deltaAbs} points` : ''} (${_scanDelta.previousRiskScore} → ${riskScore}).`);
  }

  // Threat actor matching
  const _tmData = scan.threatMatching;
  if (_tmData && _tmData.summary.totalMatched > 0) {
    const topGroup = _tmData.matchedGroups[0];
    const groupTypes = [...new Set(_tmData.matchedGroups.map((g: any) => g.groupType))];
    blufParts.push(`Threat intelligence catalog matching identified ${_tmData.summary.totalMatched} threat group(s) with TTP overlap (${groupTypes.map((t: string) => t.toUpperCase()).join(', ')}), led by ${topGroup.groupName} (score: ${topGroup.matchScore}/100). ${_tmData.summary.totalAttackPaths} viable attack path(s) were synthesized from confirmed findings across ${_tmData.summary.uniqueTechniques} MITRE ATT&CK techniques.`);
  }

  // Top recommendation
  if (llmAnalysis.recommendations?.length > 0) {
    const topRec = llmAnalysis.recommendations[0];
    const recText = topRec.recommendation || topRec.title || (typeof topRec === 'string' ? topRec : '');
    if (recText) blufParts.push(`Top priority: ${truncate(recText, 120)}.`);
  }

  // Sanity check: flag when LOW score contradicts high-severity findings
  const _hasHighSevFindings = _confirmedFc > 5 || _kevCount > 5 || _confirmedLogins > 0 || _blCritical > 0;
  if (riskScore <= 30 && _hasHighSevFindings) {
    blufParts.push(`Note: The overall risk score is a blended average across all ${_totalAssets} asset(s). Individual high-risk assets may present significantly greater exposure than the aggregate score suggests. Version-based CVE matching may overcount vulnerabilities on systems with backported security patches (common on managed hosting). Active verification is recommended.`);
  }

  // Render BLUF
  const blufText = blufParts.join(' ');
  // Section header already rendered by addSectionPage — go straight to BLUF text
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(8.5);
  y = writeText(blufText, margin, y, contentWidth, 8.5);
  y += 5;

  // ─── Key Metrics Dashboard (compact table) ───────────────────────────
  // Compute peak asset risk for context
  const peakAssetScore = assets.length > 0 ? Math.max(...assets.map((a: any) => a.hybridRiskScore || 0)) : 0;
  const peakBand = peakAssetScore >= 80 ? 'CRITICAL' : peakAssetScore >= 60 ? 'HIGH' : peakAssetScore >= 40 ? 'MEDIUM' : peakAssetScore >= 20 ? 'LOW' : 'MINIMAL';
  const dashboardRows: string[][] = [
    ['Risk Score (Avg)', `${riskScore}/100 (${riskBand.toUpperCase()})`],
    ['Peak Asset Risk', `${peakAssetScore}/100 (${peakBand})`],
    ['Total Assets', String(_totalAssets)],
    ['Findings (Unique)', `${_totalFindings} unique (${_confirmedFc} confirmed, ${_probableFc} probable, ${_potentialFc} potential)${_uniqueCve && _uniqueCve.totalFindingInstances > _totalFindings ? ` — ${_uniqueCve.totalFindingInstances} instances across ${_totalAssets} assets` : ''}`],
  ];
  if (_kevCount > 0) dashboardRows.push(['CISA KEV Matches', _uniqueCve && _uniqueCve.uniqueKevCveCount > 0 && _uniqueCve.uniqueKevCveCount < _kevCount
    ? `${_uniqueCve.uniqueKevCveCount} unique (${_kevCount} instances)`
    : String(_kevCount)]);
  if (_exploitTotal > 0) dashboardRows.push(['Public Exploits Matched', String(_exploitTotal)]);
  if (_breachExposures > 0) dashboardRows.push(['Breach Exposures', `${_breachExposures} exposures, ${_breachEmails} emails`]);
  if (_oemCredCount > 0) dashboardRows.push(['Default Credentials', `${_oemCredCount} matched${_confirmedLogins > 0 ? `, ${_confirmedLogins} confirmed` : ''}`]);
  if (_emailGrade) dashboardRows.push(['Email Security', `Grade ${_emailGrade}`]);
  if (_complianceScore !== null) dashboardRows.push(['Compliance Score', `${_complianceScore}%`]);
  if (_blacklistCount > 0) dashboardRows.push(['Blacklist Status', `${_blacklistActionable} actionable / ${_blacklistCount} total`]);
  else if (domainHealth.blacklist) dashboardRows.push(['Blacklist Status', 'Clean']);
  if (_containerHits > 0) dashboardRows.push(['Container Exposure', `${_containerHits} services (${scan.containerExposure?.criticalFindings || 0} critical)`]);
  if (_scanDelta && _scanDelta.riskDelta !== null) {
    const arrow = _scanDelta.riskDelta > 0 ? '\u2191' : _scanDelta.riskDelta < 0 ? '\u2193' : '\u2192';
    dashboardRows.push(['Trend vs Previous', `${arrow} ${Math.abs(_scanDelta.riskDelta)} pts (scan #${_scanDelta.scanNumber})`]);
  }
  if (_tmData && _tmData.summary.totalMatched > 0) {
    dashboardRows.push(['Threat Groups Matched', `${_tmData.summary.totalMatched} groups (top: ${_tmData.matchedGroups[0]?.groupName || 'N/A'})`]);
    dashboardRows.push(['Attack Paths Identified', `${_tmData.summary.totalAttackPaths} paths, ${_tmData.summary.uniqueTechniques} techniques`]);
  }
  dashboardRows.push(['Data Sources', String(connectorCount)]);
  dashboardRows.push(['Scan Duration', scanDuration ? `${(scanDuration / 1000).toFixed(1)}s` : 'N/A']);

  autoTable!(doc, {
    startY: y,
    head: [['Metric', 'Value']],
    body: dashboardRows,
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7.5, cellPadding: 2, textColor: [30, 41, 59] },
    alternateRowStyles: { fillColor: [241, 245, 249] },
    margin: { left: margin, right: margin },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
  });
  y = (doc as any).lastAutoTable.finalY + 5;

  // ─── Confidence Statement ────────────────────────────────────────────
  if (llmAnalysis.confidenceStatement) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    y = writeText(llmAnalysis.confidenceStatement, margin, y, contentWidth, 7);
    y += 3;
    doc.setFont('helvetica', 'normal');
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

  // Key risk findings summary table (criticalAssets/highAssets already computed above)

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

  // Full asset inventory table — comprehensive subdomain & asset listing
  if (assets.length > 0) {
    y = subheading('Discovered Subdomains & Assets', y);

    // Helper: extract primary IP from DNS A records
    const extractIp = (a: any): string => {
      if (a.dnsRecords) {
        const aRecs = Array.isArray(a.dnsRecords.A) ? a.dnsRecords.A : [];
        if (aRecs.length > 0) return String(aRecs[0]);
        const aaaaRecs = Array.isArray(a.dnsRecords.AAAA) ? a.dnsRecords.AAAA : [];
        if (aaaaRecs.length > 0) return String(aaaaRecs[0]);
      }
      return '—';
    };

    // Helper: infer hosting provider from hostname, CNAME, or IP reverse DNS patterns
    const inferProvider = (a: any): string => {
      const hostname = (a.hostname || '').toLowerCase();
      const cnames = Array.isArray(a.dnsRecords?.CNAME) ? a.dnsRecords.CNAME.map((c: any) => String(c).toLowerCase()) : [];
      const ip = extractIp(a);
      const allText = [hostname, ...cnames, ip].join(' ');
      if (allText.includes('amazonaws') || allText.includes('aws') || allText.includes('cloudfront')) return 'AWS';
      if (allText.includes('azure') || allText.includes('microsoft') || allText.includes('outlook') || allText.includes('.live.')) return 'Microsoft';
      if (allText.includes('google') || allText.includes('gcp') || allText.includes('googleapis') || allText.includes('ghs.')) return 'Google Cloud';
      if (allText.includes('cloudflare')) return 'Cloudflare';
      if (allText.includes('digitalocean')) return 'DigitalOcean';
      if (allText.includes('netlify')) return 'Netlify';
      if (allText.includes('vercel')) return 'Vercel';
      if (allText.includes('heroku')) return 'Heroku';
      if (allText.includes('siteground')) return 'SiteGround';
      if (allText.includes('godaddy')) return 'GoDaddy';
      if (allText.includes('github')) return 'GitHub';
      if (allText.includes('fastly')) return 'Fastly';
      if (allText.includes('akamai')) return 'Akamai';
      return '—';
    };

    // Sort by risk score descending
    const sortedAssets = [...assets].sort((a: any, b: any) => (b.hybridRiskScore ?? 0) - (a.hybridRiskScore ?? 0));

    autoTable!(doc, {
      startY: y,
      head: [['Hostname', 'IP Address', 'Type', 'Risk', 'Band', 'Hosting', 'Technologies']],
      body: sortedAssets.map((a: any) => [
        truncate(a.hostname || a.name, 30),
        extractIp(a),
        (a.assetType || 'unknown').replace(/_/g, ' '),
        String(a.hybridRiskScore ?? 0),
        (a.riskBand || 'N/A').toUpperCase(),
        inferProvider(a),
        truncate(Array.isArray(a.technologies) ? a.technologies.join(', ') : '', 25),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      columnStyles: {
        0: { cellWidth: 42 },  // Hostname
        1: { cellWidth: 25 },  // IP
        2: { cellWidth: 22 },  // Type
        3: { cellWidth: 12 },  // Risk
        4: { cellWidth: 16 },  // Band
        5: { cellWidth: 22 },  // Hosting
        6: { cellWidth: 'auto' },  // Technologies
      },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 4) {
          const text = String(data.cell.text).toUpperCase();
          if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
          else if (text === 'LOW') data.cell.styles.textColor = [22, 163, 74];
        }
      },
      didDrawPage: () => addFooter(doc, margin, pageWidth, pageHeight),
    });
    y = (doc as any).lastAutoTable.finalY + 4;

    // Summary line
    doc.setTextColor(113, 113, 122);
    doc.setFontSize(7);
    const critCount = assets.filter((a: any) => (a.riskBand || '').toLowerCase() === 'critical').length;
    const highCount = assets.filter((a: any) => (a.riskBand || '').toLowerCase() === 'high').length;
    const medCount = assets.filter((a: any) => (a.riskBand || '').toLowerCase() === 'medium').length;
    doc.text(`Total: ${assets.length} assets discovered — ${critCount} critical, ${highCount} high, ${medCount} medium risk`, margin, y);
    y += 6;
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
      // Phishing difficulty = how hard it is to spoof. Hard = good (low risk). Easy = bad (high risk).
      const diffLabel = email.phishingDifficulty.replace(/_/g, ' ').toUpperCase();
      let phishDesc: string;
      if (email.phishingDifficulty === 'hard' || email.phishingDifficulty === 'very_hard') {
        phishDesc = `${diffLabel} to spoof — strong protections in place`;
      } else if (email.phishingDifficulty === 'moderate') {
        phishDesc = `${diffLabel} to spoof — some protections but gaps remain`;
      } else {
        phishDesc = `${diffLabel} to spoof — domain is vulnerable to impersonation`;
      }
      emailRows.push(['Phishing Difficulty', phishDesc]);
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

    // Summary context line: IP checked, total zones, cloud hosting
    const checkedIp = bl.ip || '';
    const totalChecked = bl.totalChecked || 0;
    if (checkedIp || totalChecked) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(100, 116, 139);
      const parts: string[] = [];
      if (checkedIp) parts.push(`IP checked: ${checkedIp}`);
      if (totalChecked) parts.push(`${totalChecked} DNSBL zones queried`);
      if (bl.isCloudHosted && bl.cloudProvider) parts.push(`Cloud-hosted: ${bl.cloudProvider}`);
      doc.text(parts.join('  |  '), margin, y);
      y += 4;
    }

    if (bl.listings && bl.listings.length > 0) {
      // Separate actionable vs informational listings
      const actionable = bl.listings.filter((l: any) => l.actionRequired !== false);
      const informational = bl.listings.filter((l: any) => l.actionRequired === false);

      // Summary box — differentiate actionable vs informational
      if (actionable.length > 0) {
        doc.setFillColor(254, 242, 242);
        doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
        doc.setTextColor(220, 38, 38);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        const summaryText = informational.length > 0
          ? `${actionable.length} ACTIONABLE LISTING(S) + ${informational.length} INFORMATIONAL`
          : `LISTED ON ${actionable.length} BLACKLIST(S)`;
        doc.text(summaryText, margin + 5, y + 7);
        y += 16;
      } else {
        // All listings are informational — show as amber/info, not red
        doc.setFillColor(255, 251, 235);
        doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
        doc.setTextColor(146, 64, 14);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text(`${informational.length} INFORMATIONAL LISTING(S) — NO ACTION REQUIRED`, margin + 5, y + 7);
        y += 16;
      }

      // Main listings table — show returnCodeMeaning as primary reason, with evidence
      autoTable!(doc, {
        startY: y,
        head: [['Zone', 'Return Code', 'Meaning', 'Severity', 'Action?']],
        body: bl.listings.map((l: any) => [
          l.zone || 'N/A',
          (l.returnCodes || []).join(', ') || 'N/A',
          truncate(l.returnCodeMeaning || l.reason || 'No classification available', 60),
          (l.severity || 'unknown').toUpperCase(),
          l.actionRequired !== false ? 'Required' : 'Informational',
        ]),
        theme: 'grid',
        headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [254, 242, 242] },
        columnStyles: { 0: { cellWidth: 35 }, 1: { cellWidth: 22 }, 2: { cellWidth: 65 }, 3: { cellWidth: 18 }, 4: { cellWidth: 22 } },
        margin: { left: margin, right: margin },
        didParseCell: (data: any) => {
          if (data.section === 'body') {
            // Color severity column
            if (data.column.index === 3) {
              const text = String(data.cell.text).toUpperCase();
              if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
              else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
              else if (text === 'INFORMATIONAL') data.cell.styles.textColor = [100, 116, 139];
            }
            // Color action column
            if (data.column.index === 4) {
              const text = String(data.cell.text);
              if (text === 'Informational') {
                data.cell.styles.textColor = [100, 116, 139];
                data.cell.styles.fontStyle = 'italic';
              }
            }
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 4;

      // TXT reason evidence table (if any listings have TXT reasons from the blacklist)
      const listingsWithTxtReason = bl.listings.filter((l: any) => l.reason && l.reason.trim());
      if (listingsWithTxtReason.length > 0) {
        y = checkPageBreak(y, 25);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(30, 41, 59);
        doc.text('Blacklist TXT Record Evidence (raw responses from DNS)', margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Zone', 'TXT Record Response']],
          body: listingsWithTxtReason.map((l: any) => [
            l.zone || 'N/A',
            truncate(l.reason, 90),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 5.5, cellPadding: 1.5, textColor: [71, 85, 105], fontStyle: 'italic' },
          columnStyles: { 0: { cellWidth: 35 } },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 4;
      }

      // False positive analysis (if any listings have FP indicators)
      const listingsWithFp = bl.listings.filter((l: any) => l.falsePositiveIndicators && l.falsePositiveIndicators.length > 0);
      if (listingsWithFp.length > 0) {
        y = checkPageBreak(y, 25);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(146, 64, 14);
        doc.text('False Positive Analysis', margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Zone', 'False Positive Indicator']],
          body: listingsWithFp.flatMap((l: any) =>
            (l.falsePositiveIndicators || []).map((fp: string) => [
              l.zone || 'N/A',
              truncate(fp, 90),
            ])
          ),
          theme: 'grid',
          headStyles: { fillColor: [146, 64, 14], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [146, 64, 14] },
          alternateRowStyles: { fillColor: [255, 251, 235] },
          columnStyles: { 0: { cellWidth: 35 } },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 4;
      }

      // Verification links
      y = checkPageBreak(y, 12);
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(5.5);
      doc.setTextColor(100, 116, 139);
      const verifyUrl = checkedIp
        ? `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${checkedIp}`
        : 'https://mxtoolbox.com/blacklists.aspx';
      doc.text(`Verify results: ${verifyUrl}`, margin, y);
      y += 4;
    } else {
      doc.setFillColor(240, 253, 244);
      doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
      doc.setTextColor(22, 163, 74);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      const cleanText = totalChecked > 0
        ? `NOT LISTED ON ANY OF ${totalChecked} MONITORED BLACKLISTS`
        : 'NOT LISTED ON ANY MONITORED BLACKLISTS';
      doc.text(cleanText, margin + 5, y + 7);
      y += 12;
      if (checkedIp) {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(5.5);
        doc.setTextColor(100, 116, 139);
        doc.text(`IP checked: ${checkedIp}  |  Verify: https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${checkedIp}`, margin, y);
        y += 4;
      }
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
  // 4b. DOMAIN REGISTRATION DETAILS (RDAP/WHOIS)
  // ═══════════════════════════════════════════════════════════════════════
  const domainRegistration = scan.domainRegistration || scan.pipelineOutput?.domainRegistration || null;
  if (domainRegistration) {
    y = startSection('Domain Registration Details', y, 60);

    // Registration data table
    const regRows: string[][] = [];
    regRows.push(['Registrar', domainRegistration.registrar || 'N/A']);
    regRows.push(['Domain Handle', domainRegistration.handle || domainRegistration.ldhName || domain]);
    regRows.push(['Registration Date', domainRegistration.registrationDate ? new Date(domainRegistration.registrationDate).toLocaleDateString() : 'N/A']);
    regRows.push(['Expiration Date', domainRegistration.expirationDate ? new Date(domainRegistration.expirationDate).toLocaleDateString() : 'N/A']);
    regRows.push(['Last Changed', domainRegistration.lastChanged ? new Date(domainRegistration.lastChanged).toLocaleDateString() : 'N/A']);
    // Calculate days until expiration
    if (domainRegistration.expirationDate) {
      const daysUntilExpiry = Math.ceil((new Date(domainRegistration.expirationDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      regRows.push(['Days Until Expiry', String(daysUntilExpiry)]);
    }
    regRows.push(['DNSSEC', domainRegistration.dnssec ? 'Enabled (Delegation Signed)' : 'Not Enabled']);
    if (domainRegistration.nameservers?.length > 0) {
      regRows.push(['Nameservers', domainRegistration.nameservers.join(', ')]);
    }
    if (domainRegistration.status?.length > 0) {
      regRows.push(['Status Codes', domainRegistration.status.join(', ')]);
    }

    autoTable!(doc, {
      startY: y,
      head: [['Property', 'Value']],
      body: regRows,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
      columnStyles: { 0: { cellWidth: 40 } },
      didParseCell: (data: any) => {
        if (data.section === 'body') {
          const label = String(data.row.cells[0]?.text || '');
          const value = String(data.cell.text);
          // Highlight expiring domains
          if (label === 'Days Until Expiry') {
            const days = parseInt(value);
            if (!isNaN(days) && days < 30) {
              data.cell.styles.textColor = [220, 38, 38];
              data.cell.styles.fontStyle = 'bold';
            } else if (!isNaN(days) && days < 90) {
              data.cell.styles.textColor = [234, 88, 12];
            }
          }
          // Highlight DNSSEC not enabled
          if (label === 'DNSSEC' && value === 'Not Enabled') {
            data.cell.styles.textColor = [234, 88, 12];
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;

    // Registration risk assessment — with evidence citations and correct status matching
    y = checkPageBreak(y, 50);
    y = subheading('Registration Risk Assessment', y);

    // Normalize status codes: strip spaces and lowercase for reliable matching
    const normalizedStatuses = (domainRegistration.status || []).map((s: string) => s.toLowerCase().replace(/\s+/g, ''));
    const rawStatuses = (domainRegistration.status || []);

    // Check each security control
    const hasTransferLock = normalizedStatuses.some((s: string) => s.includes('clienttransferprohibited'));
    const hasDeleteLock = normalizedStatuses.some((s: string) => s.includes('clientdeleteprohibited'));
    const hasDnssec = !!domainRegistration.dnssec;

    // Build risk items: { status: 'risk'|'ok', title, detail, evidence }
    interface RegRiskItem { status: 'risk' | 'warning' | 'ok'; title: string; detail: string; evidence: string; }
    const regItems: RegRiskItem[] = [];

    // 1. DNSSEC
    if (!hasDnssec) {
      regItems.push({
        status: 'risk',
        title: 'DNSSEC is not enabled',
        detail: 'Without DNSSEC, DNS responses for this domain cannot be cryptographically verified. This leaves the domain vulnerable to DNS spoofing and cache poisoning attacks, where an attacker could redirect visitors to malicious servers.',
        evidence: `RDAP query returned dnssecData: unsigned (no delegation signer records found).`,
      });
    } else {
      regItems.push({
        status: 'ok',
        title: 'DNSSEC is enabled',
        detail: 'DNS responses are cryptographically signed, protecting against spoofing and cache poisoning.',
        evidence: `RDAP query confirmed dnssecData: signed (delegation signer records present).`,
      });
    }

    // 2. Domain expiry
    if (domainRegistration.expirationDate) {
      const expiryDate = new Date(domainRegistration.expirationDate);
      const daysLeft = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      const expiryStr = expiryDate.toLocaleDateString();
      if (daysLeft < 30) {
        regItems.push({
          status: 'risk',
          title: `Domain expires in ${daysLeft} days`,
          detail: 'Immediate renewal is required. If the domain lapses, it becomes available for anyone to register, which could lead to domain hijacking, brand impersonation, or loss of email and web services.',
          evidence: `RDAP expiration date: ${expiryStr} (${daysLeft} days from report date).`,
        });
      } else if (daysLeft < 90) {
        regItems.push({
          status: 'warning',
          title: `Domain expires in ${daysLeft} days`,
          detail: 'Schedule renewal soon to prevent accidental lapse. Domain expiry can disrupt all services tied to this domain.',
          evidence: `RDAP expiration date: ${expiryStr} (${daysLeft} days from report date).`,
        });
      } else {
        regItems.push({
          status: 'ok',
          title: `Domain registration is current`,
          detail: `The domain is registered for another ${daysLeft} days, providing adequate time before renewal is needed.`,
          evidence: `RDAP expiration date: ${expiryStr} (${daysLeft} days from report date).`,
        });
      }
    }

    // 3. Transfer lock
    if (!hasTransferLock) {
      regItems.push({
        status: 'risk',
        title: 'Transfer lock is not set',
        detail: 'Without the clientTransferProhibited status code, the domain could be transferred to another registrar without authorization. An attacker with access to the registrar account could move the domain.',
        evidence: `RDAP status codes: [${rawStatuses.join(', ')}]. The clientTransferProhibited flag is absent.`,
      });
    } else {
      const matchedStatus = rawStatuses.find((s: string) => s.toLowerCase().replace(/\s+/g, '').includes('clienttransferprohibited')) || 'clientTransferProhibited';
      regItems.push({
        status: 'ok',
        title: 'Transfer lock is enabled',
        detail: 'The domain is protected against unauthorized transfers to other registrars.',
        evidence: `RDAP status codes include "${matchedStatus}".`,
      });
    }

    // 4. Delete lock
    if (!hasDeleteLock) {
      regItems.push({
        status: 'risk',
        title: 'Delete lock is not set',
        detail: 'Without the clientDeleteProhibited status code, the domain could be accidentally or maliciously deleted from the registry, causing complete loss of all DNS-dependent services.',
        evidence: `RDAP status codes: [${rawStatuses.join(', ')}]. The clientDeleteProhibited flag is absent.`,
      });
    } else {
      const matchedStatus = rawStatuses.find((s: string) => s.toLowerCase().replace(/\s+/g, '').includes('clientdeleteprohibited')) || 'clientDeleteProhibited';
      regItems.push({
        status: 'ok',
        title: 'Delete lock is enabled',
        detail: 'The domain is protected against accidental or malicious deletion.',
        evidence: `RDAP status codes include "${matchedStatus}".`,
      });
    }

    // Render each item as a styled card
    for (const item of regItems) {
      y = checkPageBreak(y, 22);

      // Status indicator and title
      const statusColors: Record<string, [number, number, number]> = {
        risk: [220, 38, 38],    // red
        warning: [234, 88, 12], // orange
        ok: [22, 163, 74],      // green
      };
      const statusIcons: Record<string, string> = {
        risk: '[RISK]',
        warning: '[WARNING]',
        ok: '[OK]',
      };
      const color = statusColors[item.status] || [113, 113, 122];

      // Draw a thin colored left border
      doc.setDrawColor(color[0], color[1], color[2]);
      doc.setLineWidth(0.8);
      doc.line(margin + 1, y - 2.5, margin + 1, y + 12);

      // Status label + title
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(color[0], color[1], color[2]);
      doc.text(statusIcons[item.status], margin + 3, y);
      doc.setTextColor(30, 30, 30);
      doc.text(item.title, margin + 3 + doc.getTextWidth(statusIcons[item.status]) + 2, y);
      y += 3.5;

      // Detail text
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(60, 60, 60);
      const detailLines = doc.splitTextToSize(item.detail, contentWidth - 8);
      for (const line of detailLines) {
        doc.text(line, margin + 3, y);
        y += 2.8;
      }

      // Evidence citation
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(6);
      doc.setTextColor(100, 116, 139);
      const evidenceLines = doc.splitTextToSize(`Evidence: ${item.evidence}`, contentWidth - 8);
      for (const line of evidenceLines) {
        y = checkPageBreak(y, 6);
        doc.text(line, margin + 3, y);
        y += 2.5;
      }

      y += 3;
    }

    // Summary count
    const riskCount = regItems.filter(i => i.status === 'risk').length;
    const warnCount = regItems.filter(i => i.status === 'warning').length;
    const okCount = regItems.filter(i => i.status === 'ok').length;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(113, 113, 122);
    doc.text(`Assessment: ${riskCount} risk${riskCount !== 1 ? 's' : ''}, ${warnCount} warning${warnCount !== 1 ? 's' : ''}, ${okCount} passed`, margin, y);
    y += 5;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 4c. SSL CERTIFICATE HEALTH
  // ═══════════════════════════════════════════════════════════════════════
  const sslCertificates = scan.sslCertificates || scan.pipelineOutput?.sslCertificates || [];
  // Also include the domainHealth SSL data if available
  const domainHealthSsl = domainHealth.ssl;
  if (sslCertificates.length > 0 || domainHealthSsl) {
    y = startSection('SSL Certificate Health', y, 60);

    // Primary domain SSL from domain health check
    if (domainHealthSsl) {
      y = subheading('Primary Domain Certificate', y);
      const sslRows: string[][] = [];
      sslRows.push(['Subject', domainHealthSsl.subject || 'N/A']);
      sslRows.push(['Issuer', domainHealthSsl.issuer || 'N/A']);
      sslRows.push(['Valid From', domainHealthSsl.validFrom || 'N/A']);
      sslRows.push(['Valid To', domainHealthSsl.validTo || 'N/A']);
      sslRows.push(['Days Until Expiry', String(domainHealthSsl.daysUntilExpiry ?? 'N/A')]);
      sslRows.push(['Protocol', domainHealthSsl.protocol || 'N/A']);
      if (domainHealthSsl.sans?.length) sslRows.push(['SANs', truncate(domainHealthSsl.sans.join(', '), 80)]);

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
          if (data.section === 'body') {
            const label = String(data.row.cells[0]?.text || '');
            if (label === 'Days Until Expiry') {
              const days = parseInt(String(data.cell.text));
              if (!isNaN(days) && days < 30) {
                data.cell.styles.textColor = [220, 38, 38];
                data.cell.styles.fontStyle = 'bold';
              } else if (!isNaN(days) && days < 90) {
                data.cell.styles.textColor = [234, 88, 12];
              }
            }
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 4;
    }

    // Certificates discovered via Shodan/Censys passive recon
    if (sslCertificates.length > 0) {
      y = checkPageBreak(y, 30);
      y = subheading(`Discovered Certificates (${sslCertificates.length})`, y);

      autoTable!(doc, {
        startY: y,
        head: [['Subject (CN)', 'Issuer', 'Expires', 'Hosts', 'Ports']],
        body: sslCertificates.map((cert: any) => [
          truncate(cert.subject || 'N/A', 30),
          truncate(cert.issuer || 'N/A', 25),
          cert.expires ? new Date(cert.expires).toLocaleDateString() : 'N/A',
          truncate((cert.hosts || []).join(', '), 30),
          (cert.ports || []).join(', ') || 'N/A',
        ]),
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        margin: { left: margin, right: margin },
        didParseCell: (data: any) => {
          if (data.section === 'body' && data.column.index === 2) {
            const text = String(data.cell.text);
            if (text !== 'N/A') {
              const expiryDate = new Date(text);
              const daysLeft = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
              if (daysLeft < 0) {
                data.cell.styles.textColor = [220, 38, 38];
                data.cell.styles.fontStyle = 'bold';
              } else if (daysLeft < 30) {
                data.cell.styles.textColor = [234, 88, 12];
                data.cell.styles.fontStyle = 'bold';
              }
            }
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 4;

      // SSL risk assessment
      const sslRisks: string[] = [];
      for (const cert of sslCertificates) {
        if (cert.expires) {
          const daysLeft = Math.ceil((new Date(cert.expires).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          if (daysLeft < 0) sslRisks.push(`Certificate for ${cert.subject || 'unknown'} EXPIRED ${Math.abs(daysLeft)} days ago — immediate replacement required.`);
          else if (daysLeft < 30) sslRisks.push(`Certificate for ${cert.subject || 'unknown'} expires in ${daysLeft} days — schedule renewal.`);
        }
      }
      const selfSigned = sslCertificates.filter((c: any) => c.subject && c.issuer && c.subject === c.issuer);
      if (selfSigned.length > 0) {
        sslRisks.push(`${selfSigned.length} self-signed certificate(s) detected — browsers will show security warnings and MITM attacks are possible.`);
      }

      if (sslRisks.length > 0) {
        y = checkPageBreak(y, 20);
        y = subheading('Certificate Risk Assessment', y);
        for (const risk of sslRisks) {
          y = checkPageBreak(y, 8);
          doc.setFontSize(7);
          doc.setTextColor(146, 64, 14);
          doc.setFont('helvetica', 'normal');
          const riskLines = doc.splitTextToSize(`\u26A0  ${risk}`, contentWidth - 4);
          for (const line of riskLines) {
            doc.text(line, margin + 2, y);
            y += 3.5;
          }
          y += 1;
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 4d. RISKY SERVICE EXPOSURE
  // ═══════════════════════════════════════════════════════════════════════
  const discoveredPorts = scan.discoveredPorts || scan.pipelineOutput?.discoveredPorts || [];
  const riskyPorts = discoveredPorts.filter((p: any) => {
    // Flag high-risk and medium-risk services
    const highRisk = [21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 9200, 11211, 27017];
    const mediumRisk = [53, 110, 143, 161, 389, 636, 2049, 5060];
    return highRisk.includes(p.port) || mediumRisk.includes(p.port);
  });

  if (riskyPorts.length > 0) {
    y = startSection('Risky Service Exposure', y, 50);

    // Summary box
    const highRiskCount = riskyPorts.filter((p: any) => [21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 9200, 11211, 27017].includes(p.port)).length;
    const medRiskCount = riskyPorts.length - highRiskCount;
    const summaryColor: [number, number, number] = highRiskCount > 0 ? [153, 27, 27] : [234, 88, 12];
    doc.setFillColor(summaryColor[0], summaryColor[1], summaryColor[2]);
    doc.roundedRect(margin, y, contentWidth, 20, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(`${riskyPorts.length} Risky Service${riskyPorts.length !== 1 ? 's' : ''} Exposed`, margin + 5, y + 8);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(`${highRiskCount} High Risk  \u2022  ${medRiskCount} Medium Risk  \u2022  ${discoveredPorts.length} Total Open Ports`, margin + 5, y + 15);
    y += 24;

    // Service risk classification reference
    const serviceRiskMap: Record<number, { service: string; severity: number; riskLevel: string; rationale: string }> = {
      21:   { service: 'FTP', severity: 8, riskLevel: 'HIGH', rationale: 'Cleartext credential transmission, automated scanner target' },
      23:   { service: 'Telnet', severity: 9, riskLevel: 'CRITICAL', rationale: 'All data including credentials transmitted in cleartext' },
      25:   { service: 'SMTP', severity: 5, riskLevel: 'HIGH', rationale: 'Open relay abuse for spam/phishing if misconfigured' },
      53:   { service: 'DNS', severity: 4, riskLevel: 'MEDIUM', rationale: 'Open resolver — DDoS amplification risk' },
      110:  { service: 'POP3', severity: 5, riskLevel: 'MEDIUM', rationale: 'Cleartext credential transmission' },
      135:  { service: 'MS-RPC', severity: 7, riskLevel: 'HIGH', rationale: 'Windows RPC endpoint mapper — common exploit target' },
      139:  { service: 'NetBIOS', severity: 7, riskLevel: 'HIGH', rationale: 'Windows file sharing exposure' },
      143:  { service: 'IMAP', severity: 5, riskLevel: 'MEDIUM', rationale: 'Cleartext credential transmission' },
      161:  { service: 'SNMP', severity: 6, riskLevel: 'MEDIUM', rationale: 'Community string auth — information disclosure' },
      389:  { service: 'LDAP', severity: 6, riskLevel: 'MEDIUM', rationale: 'Directory information and user account leakage' },
      445:  { service: 'SMB', severity: 8, riskLevel: 'HIGH', rationale: 'Primary ransomware propagation vector (EternalBlue)' },
      636:  { service: 'LDAPS', severity: 4, riskLevel: 'MEDIUM', rationale: 'Encrypted but still exposes directory services' },
      1433: { service: 'MSSQL', severity: 8, riskLevel: 'HIGH', rationale: 'Direct database attack vector' },
      1521: { service: 'Oracle DB', severity: 8, riskLevel: 'HIGH', rationale: 'Direct database attack vector' },
      2049: { service: 'NFS', severity: 7, riskLevel: 'MEDIUM', rationale: 'File system exposure if misconfigured' },
      3306: { service: 'MySQL', severity: 8, riskLevel: 'HIGH', rationale: 'Direct database attack and credential brute-force' },
      3389: { service: 'RDP', severity: 9, riskLevel: 'CRITICAL', rationale: '#1 ransomware initial access vector' },
      5060: { service: 'SIP', severity: 5, riskLevel: 'MEDIUM', rationale: 'Toll fraud and eavesdropping risk' },
      5432: { service: 'PostgreSQL', severity: 7, riskLevel: 'HIGH', rationale: 'Direct database attack vector' },
      5900: { service: 'VNC', severity: 9, riskLevel: 'CRITICAL', rationale: 'Weak auth, screen data exposure' },
      5901: { service: 'VNC', severity: 9, riskLevel: 'CRITICAL', rationale: 'Weak auth, screen data exposure' },
      6379: { service: 'Redis', severity: 8, riskLevel: 'HIGH', rationale: 'Often unauthenticated — arbitrary command execution' },
      9200: { service: 'Elasticsearch', severity: 8, riskLevel: 'HIGH', rationale: 'Data exfiltration and cluster manipulation' },
      11211: { service: 'Memcached', severity: 7, riskLevel: 'HIGH', rationale: 'DDoS amplification and data leakage' },
      27017: { service: 'MongoDB', severity: 8, riskLevel: 'HIGH', rationale: '#1 database ransomware target' },
    };

    // Risky services table
    autoTable!(doc, {
      startY: y,
      head: [['Port', 'Service', 'Host', 'Risk', 'Sev', 'Rationale']],
      body: riskyPorts
        .sort((a: any, b: any) => (serviceRiskMap[b.port]?.severity || 0) - (serviceRiskMap[a.port]?.severity || 0))
        .map((p: any) => {
          const risk = serviceRiskMap[p.port] || { service: p.product || `Port ${p.port}`, severity: 5, riskLevel: 'MEDIUM', rationale: 'Unknown service exposure' };
          return [
            String(p.port),
            risk.service,
            truncate(p.hostname || p.ip || 'N/A', 30),
            risk.riskLevel,
            `${risk.severity}/10`,
            truncate(risk.rationale, 50),
          ];
        }),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      columnStyles: { 0: { cellWidth: 14 }, 1: { cellWidth: 22 }, 3: { cellWidth: 18 }, 4: { cellWidth: 14 } },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const text = String(data.cell.text);
          if (text === 'CRITICAL') { data.cell.styles.textColor = [153, 27, 27]; data.cell.styles.fontStyle = 'bold'; }
          else if (text === 'HIGH') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
          else if (text === 'MEDIUM') { data.cell.styles.textColor = [234, 88, 12]; }
        }
        if (data.section === 'body' && data.column.index === 4) {
          const sev = parseInt(String(data.cell.text));
          if (sev >= 9) data.cell.styles.textColor = [153, 27, 27];
          else if (sev >= 7) data.cell.styles.textColor = [220, 38, 38];
          else if (sev >= 5) data.cell.styles.textColor = [234, 88, 12];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 4;

    // Exposure narrative
    y = checkPageBreak(y, 30);
    y = subheading('Exposure Analysis', y);
    const criticalPorts = riskyPorts.filter((p: any) => (serviceRiskMap[p.port]?.severity || 0) >= 9);
    const dbPorts = riskyPorts.filter((p: any) => [1433, 1521, 3306, 5432, 6379, 9200, 27017].includes(p.port));
    const remoteAccessPorts = riskyPorts.filter((p: any) => [21, 23, 3389, 5900, 5901].includes(p.port));

    const narrativeParts: string[] = [];
    if (criticalPorts.length > 0) {
      narrativeParts.push(`${criticalPorts.length} critical-severity service(s) are directly exposed to the internet (${criticalPorts.map((p: any) => serviceRiskMap[p.port]?.service || `Port ${p.port}`).join(', ')}). These represent the highest-priority remediation targets as they are commonly exploited in ransomware and targeted attacks.`);
    }
    if (dbPorts.length > 0) {
      narrativeParts.push(`${dbPorts.length} database service(s) are externally accessible (${dbPorts.map((p: any) => serviceRiskMap[p.port]?.service || `Port ${p.port}`).join(', ')}). Exposed databases are primary targets for data exfiltration and database ransomware campaigns.`);
    }
    if (remoteAccessPorts.length > 0) {
      narrativeParts.push(`${remoteAccessPorts.length} remote access service(s) detected (${remoteAccessPorts.map((p: any) => serviceRiskMap[p.port]?.service || `Port ${p.port}`).join(', ')}). These services should be restricted to VPN access or replaced with more secure alternatives.`);
    }

    if (narrativeParts.length > 0) {
      doc.setFontSize(8);
      doc.setTextColor(51, 65, 85);
      doc.setFont('helvetica', 'normal');
      for (const part of narrativeParts) {
        y = checkPageBreak(y, 15);
        const lines = doc.splitTextToSize(part, contentWidth - 4);
        for (const line of lines) {
          doc.text(line, margin + 2, y);
          y += 3.5;
        }
        y += 2;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 5. BREACH & CREDENTIAL EXPOSURE
  // ═══════════════════════════════════════════════════════════════════════

  // Pre-compute breach data to decide whether to render a full page
  const credentialObs = observations.filter((o: any) =>
    o.assetType === 'credential' ||
    o.tags?.includes('leaked_credential') ||
    o.tags?.includes('credential_breach')
  );
  const breachDbObs = observations.filter((o: any) =>
    o.tags?.includes('breach_database') && o.source === 'dehashed'
  );
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
  const breachDataFallback = scan.breachData || {};
  const totalLeaked = credentialObs.length || breachDataFallback.totalExposures || 0;
  const uniqueEmails = breachDataFallback.uniqueEmails || 0;
  const uniqueBreachSources = breachDataFallback.uniqueBreachSources || 0;

  // Only create a full section page if there is breach data to show
  const _hasBreachData = totalLeaked > 0 || breachDbObs.length > 0 || breachSummaryObs;
  if (!_hasBreachData) {
    // Compact inline note — no wasted page
    y = checkPageBreak(y, 20);
    doc.setFillColor(240, 253, 244);
    doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
    doc.setTextColor(22, 163, 74);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text('Breach & Credential Exposure: No leaked credentials or breach data detected.', margin + 5, y + 8);
    y += 16;
  }

  if (_hasBreachData) {
  y = startSection('Breach & Credential Exposure', y, 60);

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
  } // end _hasBreachData

  // ═══════════════════════════════════════════════════════════════════════
  // 6. DARK WEB & RANSOMWARE INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════════════

  // Pre-compute dark web data
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

  const hasDarkwebHits = darkwebObs.length > 0;

  if (!hasDarkwebHits) {
    // Compact inline note — no wasted page
    y = checkPageBreak(y, 20);
    doc.setFillColor(240, 253, 244);
    doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
    doc.setTextColor(22, 163, 74);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text('Dark Web & Ransomware Intelligence: No dark web mentions detected.', margin + 5, y + 8);
    y += 16;
  }

  if (hasDarkwebHits) {
  y = startSection('Dark Web & Ransomware Intelligence', y, 60);

  // Summary box
    doc.setFillColor(50, 20, 20);
    doc.roundedRect(margin, y, contentWidth, 25, 3, 3, 'F');
    doc.setTextColor(220, 38, 38);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`${darkwebObs.length} DARK WEB MENTIONS DETECTED`, margin + 5, y + 10);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(255, 200, 200);
    const parts: string[] = [];
    if (ransomwareObs.length > 0) parts.push(`${ransomwareObs.length} ransomware`);
    if (iabObs.length > 0) parts.push(`${iabObs.length} IAB`);
    if (dataLeakObs.length > 0) parts.push(`${dataLeakObs.length} data leak`);
    if (stealerObs.length > 0) parts.push(`${stealerObs.length} stealer log`);
    if (threatGroupObs.length > 0) parts.push(`${threatGroupObs.length} threat group`);
    doc.text(parts.join(' | '), margin + 5, y + 18);
  y += 32;

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
    y = startSection('Threat Actor Assessment', y, 80);

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
  } // end hasDarkwebHits

  // ═══════════════════════════════════════════════════════════════════════
  // 8. VULNERABILITY & TECHNOLOGY LANDSCAPE
  // ═══════════════════════════════════════════════════════════════════════
  y = startSection('Vulnerability & Technology Landscape', y, 60);

  // Technology stack — deduplicate similar technologies
  const _techAliases: Record<string, string> = {
    'Express.js': 'Express', 'express.js': 'Express', 'express': 'Express',
    'Node.js': 'Node.js', 'node.js': 'Node.js', 'node': 'Node.js',
    'Next.js': 'Next.js', 'next.js': 'Next.js', 'nextjs': 'Next.js',
    'Nuxt.js': 'Nuxt.js', 'nuxt.js': 'Nuxt.js', 'nuxtjs': 'Nuxt.js',
    'React.js': 'React', 'react.js': 'React', 'ReactJS': 'React',
    'Vue.js': 'Vue.js', 'vue.js': 'Vue.js', 'VueJS': 'Vue.js',
    'Tailwind CSS': 'Tailwind CSS', 'tailwindcss': 'Tailwind CSS', 'TailwindCSS': 'Tailwind CSS',
    'jQuery': 'jQuery', 'jquery': 'jQuery', 'JQuery': 'jQuery',
  };
  const allTechs = new Map<string, number>();
  for (const asset of assets) {
    if (Array.isArray(asset.technologies)) {
      for (const tech of asset.technologies) {
        const normalized = _techAliases[tech] || tech;
        allTechs.set(normalized, (allTechs.get(normalized) || 0) + 1);
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
    // Filter out managed provider hosts from the display list
    const rawHosts: string[] = o.evidence?.affectedHosts || [o.evidence?.hostname || domain];
    const hosts: string[] = rawHosts.filter((h: string) => !_managedMailHosts.has(h));
    if (hosts.length === 0) hosts.push(domain); // Fallback if all hosts were managed
    const kevListed = o.evidence?.kevListed;
    const description = o.evidence?.description || '';
    const corroboration = o.evidence?.corroboration || '';
    const affectedVersions = o.evidence?.affectedVersions || '';

    // Build evidence summary line from available data
    // Suppress protocol-like versions (1.0, 1.1, 2.0, 2, 3) that are likely HTTP protocol, not product versions
    const isProtocolVersion = /^[123](\.\d)?$/.test(version);
    const evidenceParts: string[] = [];
    if (corroboration === '[CONFIRMED]' && version && version !== 'N/A' && !isProtocolVersion) {
      if (affectedVersions) {
        evidenceParts.push(`Version ${version} confirmed within affected range (${affectedVersions})`);
      } else {
        evidenceParts.push(`Version ${version} detected and confirmed vulnerable`);
      }
    } else if (corroboration === '[CONFIRMED]') {
      evidenceParts.push('Confirmed vulnerable based on product detection');
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
    if (showVersion && version !== 'N/A' && !isProtocolVersion) chips.push(`Ver: ${version}`);
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

    // ── Affected hosts (compact: inline for 4+ hosts, bullets for 1-3) ──
    doc.setFontSize(6.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(50, 50, 50);
    y = checkPageBreak(y, 5);
    if (hosts.length <= 3) {
      doc.text(`Affected Assets (${hosts.length}):`, margin + 3, y);
      y += 3.5;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(60, 60, 60);
      for (const host of hosts) {
        y = checkPageBreak(y, 4);
        doc.text(`\u2022  ${host}`, margin + 5, y);
        y += 3;
      }
    } else {
      // Compact inline: "Affected Assets (10): host1, host2, host3, ... +7 more"
      const MAX_INLINE = 3;
      const shown = hosts.slice(0, MAX_INLINE).join(', ');
      const remaining = hosts.length - MAX_INLINE;
      const inlineText = remaining > 0 ? `${shown}, +${remaining} more` : shown;
      doc.text(`Affected Assets (${hosts.length}): `, margin + 3, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(60, 60, 60);
      const labelWidth = doc.getTextWidth(`Affected Assets (${hosts.length}): `);
      const assetLines = doc.splitTextToSize(inlineText, contentWidth - 6 - labelWidth);
      doc.text(assetLines[0], margin + 3 + labelWidth, y);
      y += 3.5;
      for (let i = 1; i < assetLines.length; i++) {
        y = checkPageBreak(y, 4);
        doc.text(assetLines[i], margin + 5, y);
        y += 3;
      }
    }
    y += 4; // Clear gap before next card
  };

  if (vulnObs.length > 0) {
    // Tier 1: Confirmed (version-matched) — NOT on provider-managed-only hosts
    const confirmedVulns = vulnObs.filter((o: any) =>
      o.evidence?.corroboration === '[CONFIRMED]' && !o.evidence?.providerManagedOnly
    );
    // Tier 2: Probable — product detected but version not confirmed
    const probableVulns = vulnObs.filter((o: any) =>
      o.evidence?.corroboration === '[PROBABLE]' && !o.evidence?.providerManagedOnly
    );
    // Tier 3: Potential — product-family match only, no version evidence
    const potentialVulns = vulnObs.filter((o: any) =>
      (o.evidence?.corroboration === '[POTENTIAL]' || o.evidence?.corroboration === '[UNCONFIRMED VERSION]' || !o.evidence?.corroboration) && !o.evidence?.providerManagedOnly
    );

    if (confirmedVulns.length > 0) {
      y = subheading(`Confirmed Vulnerabilities (${confirmedVulns.length})`, y);

      // Backport disclaimer
      doc.setFontSize(6.5);
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(100, 116, 139);
      y = checkPageBreak(y, 5);
      const disclaimerText = 'Note: Vulnerabilities are matched by detected software version. Systems with backported security patches (common on managed hosting, RHEL, Ubuntu) may not be affected despite version match. Active verification recommended.';
      const disclaimerLines = doc.splitTextToSize(disclaimerText, contentWidth - 6);
      for (const line of disclaimerLines) {
        doc.text(line, margin + 3, y);
        y += 2.8;
      }
      y += 2;

      for (const vuln of confirmedVulns) {
        const sevScore = vuln.evidence?.severity || 5;
        const headerColor: [number, number, number] = sevScore >= 9 ? [153, 27, 27] : sevScore >= 7 ? [194, 65, 12] : [30, 41, 59];
        renderCveCard(vuln, headerColor, [51, 65, 85], [30, 41, 59], true, true);
      }
      y += 2;
    }

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

    // Potential findings — show count and investigation recommendation
    if (potentialVulns.length > 0) {
      y = checkPageBreak(y, 30);
      // Blue recommendation box
      const potBoxY = y;
      doc.setFillColor(239, 246, 255); // blue-50 bg
      doc.setDrawColor(59, 130, 246); // blue-500 border
      doc.roundedRect(margin, potBoxY, contentWidth, 24, 2, 2, 'FD');
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 64, 175); // blue-800
      doc.text(`Investigation Recommended \u2014 ${potentialVulns.length} Potential Finding${potentialVulns.length !== 1 ? 's' : ''}`, margin + 4, potBoxY + 6);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(30, 58, 138); // blue-900
      const potText = `${potentialVulns.length} finding${potentialVulns.length !== 1 ? 's' : ''} matched technology product families (e.g., ${potentialVulns.slice(0, 3).map((v: any) => v.evidence?.cve_id || v.evidence?.title?.match(/CVE-\d+-\d+/)?.[0] || 'CVE').join(', ')}${potentialVulns.length > 3 ? '...' : ''}) but the specific product and version could not be confirmed from external observation. These require internal verification to determine applicability.`;
      const potLines = doc.splitTextToSize(potText, contentWidth - 8);
      doc.text(potLines, margin + 4, potBoxY + 11);
      y = potBoxY + 26;
    }

    // Provider-managed CVEs removed from report — these are unproven product-family
    // KEV matches without version confirmation and cannot be verified as client vulnerabilities.
    // Managed provider infrastructure patching is the provider's responsibility.
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 8b. PROVIDER-MANAGED INFRASTRUCTURE
  // ═══════════════════════════════════════════════════════════════════════
  if (_managedMailProvider || _managedMailHosts.size > 0) {
    y = startSection('Provider-Managed Infrastructure', y, 60);

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
  // 9. EXPLOIT AVAILABILITY & DEFAULT CREDENTIALS
  // ═══════════════════════════════════════════════════════════════════════
  const _hasExploits = scan.exploitMatches && (scan.exploitMatches.totalMetasploit > 0 || scan.exploitMatches.totalExploitDb > 0 || scan.exploitMatches.totalCalderaAbilities > 0);
  const _hasOemCreds = (scan.oemCredentials?.length ?? 0) > 0;
  const _hasCredTests = scan.credentialTestSummary && scan.credentialTestSummary.totalTargets > 0;
  if (_hasExploits || _hasOemCreds || _hasCredTests) {
    y = startSection('Exploit Availability & Default Credentials', y, 50);

    // Exploit matches
    if (_hasExploits) {
      y = subheading('Public Exploit Availability', y);
      const em = scan.exploitMatches!;
      doc.setFontSize(8);
      doc.setTextColor(30, 41, 59);
      y = writeText(
        `${em.totalMetasploit + em.totalExploitDb + em.totalCalderaAbilities} public exploit(s) matched to discovered technologies. ` +
        `${em.remoteAccessCount} provide remote access capability. ` +
        `Breakdown: ${em.totalMetasploit} Metasploit module(s), ${em.totalExploitDb} ExploitDB entry(ies), ${em.totalCalderaAbilities} Caldera ability(ies).`,
        margin, y, contentWidth, 8
      );
      y += 3;

      // Individual exploit matches table
      // Filter out exploit entries with no meaningful data (no source, module, or technology)
      const meaningfulMatches = (em.matches || []).filter((m: any) => {
        const hasSource = m.source && m.source !== 'Unknown' && m.source !== 'N/A';
        const hasModule = m.moduleName || m.exploitId || m.abilityName;
        const hasTech = m.matchedTechnology || m.cve;
        const hasSeverity = m.severity && m.severity !== 'N/A' && m.severity !== 'Unknown';
        // Require at least source + one of module/tech to be meaningful
        return (hasSource && (hasModule || hasTech)) || (hasModule && hasTech) || hasSeverity;
      });
      if (meaningfulMatches.length > 0) {
        if (meaningfulMatches.length < (em.matches?.length || 0)) {
          doc.setFontSize(7);
          doc.setFont('helvetica', 'italic');
          doc.setTextColor(100, 116, 139);
          y = checkPageBreak(y, 5);
          doc.text(`Showing ${meaningfulMatches.length} exploit(s) with verified source data (${(em.matches?.length || 0) - meaningfulMatches.length} unattributed entries omitted).`, margin, y);
          y += 4;
        }
        autoTable!(doc, {
          startY: y,
          head: [['Source', 'Module / ID', 'Technology', 'Severity', 'Remote Access']],
          body: meaningfulMatches.slice(0, 30).map((m: any) => [
            m.source || 'Unknown',
            truncate(m.moduleName || m.exploitId || m.abilityName || 'N/A', 50),
            truncate(m.matchedTechnology || m.cve || 'N/A', 25),
            m.severity || m.rank || 'N/A',
            m.remoteAccess ? 'Yes' : 'No',
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
          didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 4) {
              if (String(data.cell.text) === 'Yes') data.cell.styles.textColor = [220, 38, 38];
            }
          },
        });
        y = (doc as any).lastAutoTable.finalY + 5;
      }
    }

    // OEM / Default Credentials
    if (_hasOemCreds) {
      y = checkPageBreak(y, 30);
      y = subheading('Default / OEM Credential Matches', y);
      const creds = scan.oemCredentials!;
      doc.setFontSize(8);
      doc.setTextColor(30, 41, 59);
      y = writeText(
        `${creds.length} default credential set(s) matched to discovered services. ` +
        `These are vendor-shipped credentials that may not have been changed during deployment.`,
        margin, y, contentWidth, 8
      );
      y += 3;

      autoTable!(doc, {
        startY: y,
        head: [['Vendor', 'Product', 'Protocol', 'Port', 'Username', 'Access Level', 'Matched Asset']],
        body: creds.slice(0, 25).map((c: any) => [
          c.vendor || 'N/A',
          truncate(c.product || 'N/A', 20),
          c.protocol || 'N/A',
          c.port ? String(c.port) : 'N/A',
          c.username || 'N/A',
          c.accessLevel || 'N/A',
          truncate(c.matchedAsset || 'N/A', 30),
        ]),
        theme: 'grid',
        headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
        bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [254, 242, 242] },
        margin: { left: margin, right: margin },
      });
      y = (doc as any).lastAutoTable.finalY + 5;
    }

    // Credential Test Results
    if (_hasCredTests) {
      y = checkPageBreak(y, 30);
      y = subheading('Automated Credential Testing Results', y);
      const ct = scan.credentialTestSummary!;
      const ctSummaryRows: string[][] = [
        ['Targets Tested', String(ct.totalTargets)],
        ['Credentials Tested', String(ct.totalCredentialsTested)],
        ['Successful Logins', String(ct.successfulLogins)],
        ['Failed Attempts', String(ct.failedAttempts)],
        ['Timeouts', String(ct.timeouts)],
        ['Errors', String(ct.errors)],
      ];
      autoTable!(doc, {
        startY: y,
        head: [['Metric', 'Count']],
        body: ctSummaryRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7.5, cellPadding: 2, textColor: [30, 41, 59] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
        didParseCell: (data: any) => {
          if (data.section === 'body' && data.row.index === 2) { // Successful Logins row
            const val = parseInt(String(data.cell.text), 10);
            if (val > 0 && data.column.index === 1) data.cell.styles.textColor = [220, 38, 38];
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 4;

      // Confirmed credentials detail
      if (ct.confirmedCredentials?.length > 0) {
        y = checkPageBreak(y, 20);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(220, 38, 38);
        doc.text('CONFIRMED ACCESSIBLE CREDENTIALS:', margin, y);
        y += 4;
        doc.setFont('helvetica', 'normal');

        autoTable!(doc, {
          startY: y,
          head: [['Host', 'Port', 'Protocol', 'Vendor', 'Product', 'Username', 'Access']],
          body: ct.confirmedCredentials.map((cc: any) => [
            cc.host || 'N/A',
            String(cc.port || 'N/A'),
            cc.protocol || 'N/A',
            cc.vendor || 'N/A',
            truncate(cc.product || 'N/A', 15),
            cc.username || 'N/A',
            cc.accessLevel || 'N/A',
          ]),
          theme: 'grid',
          headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [254, 242, 242] },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 5;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 10. COMPLIANCE & CONTAINER EXPOSURE
  // ═══════════════════════════════════════════════════════════════════════
  const _hasCompliance = scan.complianceScan && scan.complianceScan.totalChecks > 0;
  const _hasContainers = scan.containerExposure && scan.containerExposure.totalHits > 0;
  if (_hasCompliance || _hasContainers) {
    y = startSection('Compliance & Container Exposure', y, 50);

    // SCAP/STIG Compliance
    if (_hasCompliance) {
      const cs = scan.complianceScan!;
      y = subheading(`Compliance Assessment (${cs.scanType || 'SCAP'})`, y);

      // Score summary
      const csRows: string[][] = [
        ['Compliance Score', `${cs.complianceScore}%`],
        ['Benchmark', cs.benchmarkProfile || 'N/A'],
        ['Total Checks', String(cs.totalChecks)],
        ['Passed', String(cs.passed)],
        ['Failed', String(cs.failed)],
        ['Not Applicable', String(cs.notApplicable)],
        ['Manual Review', String(cs.manualReview)],
      ];
      autoTable!(doc, {
        startY: y,
        head: [['Metric', 'Value']],
        body: csRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7.5, cellPadding: 2, textColor: [30, 41, 59] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
      });
      y = (doc as any).lastAutoTable.finalY + 4;

      // Failed checks detail
      const failedChecks = cs.checks?.filter((c: any) => c.status === 'fail' || c.status === 'failed') || [];
      if (failedChecks.length > 0) {
        y = checkPageBreak(y, 20);
        y = subheading('Failed Compliance Checks', y);
        autoTable!(doc, {
          startY: y,
          head: [['Check ID', 'Title', 'Severity', 'Category', 'Remediation']],
          body: failedChecks.slice(0, 25).map((c: any) => [
            c.stigId || c.checkId || 'N/A',
            truncate(c.title || 'N/A', 50),
            c.severity || 'N/A',
            (c.category || 'N/A').replace(/_/g, ' '),
            truncate(c.remediation || 'N/A', 80),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
          didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 2) {
              const sev = String(data.cell.text).toLowerCase();
              if (sev === 'high' || sev === 'critical') data.cell.styles.textColor = [220, 38, 38];
              else if (sev === 'medium') data.cell.styles.textColor = [234, 88, 12];
            }
          },
        });
        y = (doc as any).lastAutoTable.finalY + 5;
      }
    }

    // Container Exposure
    if (_hasContainers) {
      y = checkPageBreak(y, 30);
      const ce = scan.containerExposure!;
      y = subheading('Container Infrastructure Exposure', y);
      doc.setFontSize(8);
      doc.setTextColor(30, 41, 59);
      y = writeText(
        `${ce.totalHits} exposed container service(s) detected across ${ce.subdomainsProbed?.length || 0} probed host(s) ` +
        `(${ce.totalProbes} total probes). ${ce.criticalFindings} critical and ${ce.highFindings} high severity finding(s).`,
        margin, y, contentWidth, 8
      );
      y += 3;

      if (ce.findings?.length > 0) {
        autoTable!(doc, {
          startY: y,
          head: [['Service', 'Category', 'Port', 'Severity', 'Auth', 'Risk Description']],
          body: ce.findings.slice(0, 20).map((f: any) => [
            f.service || 'N/A',
            f.category || 'N/A',
            String(f.port || 'N/A'),
            f.severity || 'N/A',
            f.authenticated ? 'Yes' : 'No',
            truncate(f.riskDescription || 'N/A', 45),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
          didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 3) {
              const sev = String(data.cell.text).toLowerCase();
              if (sev === 'critical') data.cell.styles.textColor = [220, 38, 38];
              else if (sev === 'high') data.cell.styles.textColor = [234, 88, 12];
            }
            if (data.section === 'body' && data.column.index === 4) {
              if (String(data.cell.text) === 'No') data.cell.styles.textColor = [220, 38, 38];
            }
          },
        });
        y = (doc as any).lastAutoTable.finalY + 5;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 11. CROSS-MODULE INTELLIGENCE & CARVER PROFILE
  // ═══════════════════════════════════════════════════════════════════════
  const cme = scan.crossModuleEnrichment;
  const carver = scan.carverRiskCard;
  const carverFb = scan.carverFeedback;
  const _hasCme = cme && cme.summary && cme.summary.modulesRun > 0;
  const _hasCarver = carver && (carver.scores || carver.sector);
  const _hasScanDelta = scan.scanDelta && scan.scanDelta.previousScanId;
  if (_hasCme || _hasCarver || _hasScanDelta) {
    y = startSection('Cross-Module Intelligence & CARVER Profile', y, 60);

    // CARVER Risk Card
    if (_hasCarver) {
      y = subheading('CARVER Risk Profile', y);
      const carverRows: string[][] = [];
      if (carver.sector) carverRows.push(['Inferred Sector', carver.sector]);
      if (carver.naics) carverRows.push(['NAICS Code', carver.naics]);
      if (carver.regulatoryProfile?.length > 0) carverRows.push(['Regulatory Profile', carver.regulatoryProfile.join(', ')]);
      if (carver.scores) {
        if (carver.scores.hybrid !== undefined) carverRows.push(['Hybrid Risk Score', String(carver.scores.hybrid)]);
        if (carver.scores.carverShock !== undefined) carverRows.push(['CARVER+Shock Score', String(carver.scores.carverShock)]);
        if (carver.scores.priorityTier) carverRows.push(['Priority Tier', carver.scores.priorityTier]);
      }
      if (carver.confidence !== undefined) carverRows.push(['Confidence', `${(carver.confidence * 100).toFixed(0)}%`]);
      if (carver.threatLikelihood) carverRows.push(['Threat Likelihood', carver.threatLikelihood]);
      if (carver.calderaPriority) carverRows.push(['Caldera Priority', carver.calderaPriority]);

      if (carverRows.length > 0) {
        autoTable!(doc, {
          startY: y,
          head: [['Attribute', 'Value']],
          body: carverRows,
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 7.5, cellPadding: 2, textColor: [30, 41, 59] },
          margin: { left: margin, right: margin },
          columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
        });
        y = (doc as any).lastAutoTable.finalY + 4;
      }

      // Top drivers
      if (carver.topDrivers?.length > 0) {
        y = checkPageBreak(y, 15);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text('Top Risk Drivers:', margin, y);
        y += 3;
        doc.setFont('helvetica', 'normal');
        for (const driver of carver.topDrivers.slice(0, 5)) {
          y = checkPageBreak(y, 4);
          doc.setFontSize(7);
          doc.text(`\u2022 ${truncate(typeof driver === 'string' ? driver : driver.description || driver.name || JSON.stringify(driver), 100)}`, margin + 3, y);
          y += 3.5;
        }
        y += 2;
      }

      // Recommended actions
      if (carver.recommendedActions?.length > 0) {
        y = checkPageBreak(y, 15);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.text('CARVER Recommended Actions:', margin, y);
        y += 3;
        doc.setFont('helvetica', 'normal');
        for (const action of carver.recommendedActions.slice(0, 5)) {
          y = checkPageBreak(y, 4);
          doc.setFontSize(7);
          doc.text(`\u2022 ${truncate(typeof action === 'string' ? action : action.description || action.action || JSON.stringify(action), 100)}`, margin + 3, y);
          y += 3.5;
        }
        y += 2;
      }
    }

    // Cross-Module Enrichment Summary
    if (_hasCme) {
      y = checkPageBreak(y, 30);
      y = subheading('Cross-Module Enrichment', y);
      const cmeSummary = cme!.summary;
      doc.setFontSize(8);
      doc.setTextColor(30, 41, 59);
      y = writeText(
        `${cmeSummary.modulesSucceeded}/${cmeSummary.modulesRun} enrichment modules completed successfully. ` +
        `${cmeSummary.totalCorrelations} cross-module correlation(s) identified, ` +
        `${cmeSummary.totalNewFindings} new finding(s) generated, ` +
        `${cmeSummary.totalRiskAdjustments} risk adjustment(s) applied.`,
        margin, y, contentWidth, 8
      );
      y += 4;

      // Bug Bounty
      if (cme!.bugBounty?.status === 'success') {
        y = checkPageBreak(y, 15);
        const bb = cme!.bugBounty;
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text(`Bug Bounty: ${bb.hasBugBountyProgram ? `Active (${bb.programName || 'Unknown program'})` : 'No program detected'}`, margin, y);
        y += 3.5;
        doc.setFont('helvetica', 'normal');
        if (bb.inScopeAssets?.length > 0) {
          doc.setFontSize(7);
          doc.text(`In-scope assets: ${bb.inScopeAssets.slice(0, 5).join(', ')}${bb.inScopeAssets.length > 5 ? ` (+${bb.inScopeAssets.length - 5} more)` : ''}`, margin + 3, y);
          y += 3.5;
        }
        if (bb.historicalVulnPatterns?.length > 0) {
          doc.setFontSize(7);
          doc.text(`Historical vuln patterns: ${bb.historicalVulnPatterns.slice(0, 3).map((p: any) => `${p.cwe} (${p.count}x)`).join(', ')}`, margin + 3, y);
          y += 3.5;
        }
        y += 2;
      }

      // OpSec Gaps
      if (cme!.opsec?.status === 'success' && cme!.opsec.defensiveGaps?.length > 0) {
        y = checkPageBreak(y, 20);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text('Operational Security Gaps:', margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Category', 'Severity', 'Description', 'Affected Assets']],
          body: cme!.opsec.defensiveGaps.slice(0, 10).map((g: any) => [
            g.category || 'N/A',
            g.severity || 'N/A',
            truncate(g.description || 'N/A', 50),
            truncate((g.affectedAssets || []).join(', '), 30),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
          didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 1) {
              const sev = String(data.cell.text).toLowerCase();
              if (sev === 'high' || sev === 'critical') data.cell.styles.textColor = [220, 38, 38];
              else if (sev === 'medium') data.cell.styles.textColor = [234, 88, 12];
            }
          },
        });
        y = (doc as any).lastAutoTable.finalY + 4;
      }

      // Discovery Deep Dive
      const dd = cme!.discoveryDeepDive;
      if (dd?.status === 'success') {
        // DNS History Changes
        if (dd.dnsHistoryChanges?.length > 0) {
          y = checkPageBreak(y, 20);
          doc.setFontSize(7.5);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(30, 41, 59);
          doc.text('DNS History Changes:', margin, y);
          y += 4;

          autoTable!(doc, {
            startY: y,
            head: [['Domain', 'Previous IP', 'Current IP', 'Changed']],
            body: dd.dnsHistoryChanges.slice(0, 10).map((c: any) => [
              truncate(c.domain || 'N/A', 35),
              c.oldIp || 'N/A',
              c.newIp || 'N/A',
              c.changedAt || 'N/A',
            ]),
            theme: 'grid',
            headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
            bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
            alternateRowStyles: { fillColor: [241, 245, 249] },
            margin: { left: margin, right: margin },
          });
          y = (doc as any).lastAutoTable.finalY + 4;
        }

        // Certificate Findings
        if (dd.certificateFindings?.length > 0) {
          y = checkPageBreak(y, 20);
          doc.setFontSize(7.5);
          doc.setFont('helvetica', 'bold');
          doc.text('Certificate Findings:', margin, y);
          y += 4;

          autoTable!(doc, {
            startY: y,
            head: [['Subject', 'Issue', 'Severity']],
            body: dd.certificateFindings.slice(0, 10).map((f: any) => [
              truncate(f.subject || 'N/A', 40),
              truncate(f.issue || 'N/A', 50),
              f.severity || 'N/A',
            ]),
            theme: 'grid',
            headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
            bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
            alternateRowStyles: { fillColor: [241, 245, 249] },
            margin: { left: margin, right: margin },
          });
          y = (doc as any).lastAutoTable.finalY + 4;
        }

        // Infrastructure Insights
        if (dd.infrastructureInsights?.length > 0) {
          y = checkPageBreak(y, 15);
          doc.setFontSize(7.5);
          doc.setFont('helvetica', 'bold');
          doc.text('Infrastructure Insights:', margin, y);
          y += 3.5;
          doc.setFont('helvetica', 'normal');
          for (const insight of dd.infrastructureInsights.slice(0, 5)) {
            y = checkPageBreak(y, 4);
            doc.setFontSize(7);
            doc.text(`\u2022 [${insight.type || 'info'}] ${truncate(insight.detail || '', 90)} (confidence: ${((insight.confidence || 0) * 100).toFixed(0)}%)`, margin + 3, y);
            y += 3.5;
          }
          y += 2;
        }
      }

      // Cross-module correlations
      const allCorrelations: any[] = [
        ...(cme!.bugBounty?.correlations || []),
        ...(cme!.opsec?.correlations || []),
        ...(cme!.discoveryDeepDive?.correlations || []),
        ...(cme!.threatIntel?.correlations || []),
      ];
      if (allCorrelations.length > 0) {
        y = checkPageBreak(y, 20);
        y = subheading('Cross-Module Correlations', y);
        autoTable!(doc, {
          startY: y,
          head: [['Source', 'Target', 'Type', 'Description', 'Confidence', 'Risk Impact']],
          body: allCorrelations.slice(0, 15).map((c: any) => [
            c.sourceModule || 'N/A',
            c.targetModule || 'N/A',
            c.correlationType || 'N/A',
            truncate(c.description || 'N/A', 40),
            `${((c.confidence || 0) * 100).toFixed(0)}%`,
            c.riskImpact > 0 ? `+${c.riskImpact}` : String(c.riskImpact || 0),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
          didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 5) {
              const val = parseInt(String(data.cell.text), 10);
              if (val > 0) data.cell.styles.textColor = [220, 38, 38];
              else if (val < 0) data.cell.styles.textColor = [22, 163, 74];
            }
          },
        });
        y = (doc as any).lastAutoTable.finalY + 4;
      }
    }

    // Scan Delta / Trend Analysis
    if (_hasScanDelta) {
      y = checkPageBreak(y, 30);
      y = subheading('Scan Trend Analysis', y);
      const sd = scan.scanDelta!;
      doc.setFontSize(8);
      doc.setTextColor(30, 41, 59);
      y = writeText(
        `This is scan #${sd.scanNumber} for ${domain}. Previous scan was conducted on ${sd.previousScanDate || 'unknown date'}.`,
        margin, y, contentWidth, 8
      );
      y += 3;

      const deltaRows: string[][] = [];
      if (sd.riskDelta !== null) {
        const arrow = sd.riskDelta > 0 ? '\u2191' : sd.riskDelta < 0 ? '\u2193' : '\u2192';
        deltaRows.push(['Risk Score', `${sd.previousRiskScore} \u2192 ${riskScore} (${arrow} ${Math.abs(sd.riskDelta)} pts)`]);
      }
      if (sd.assetDelta !== null) {
        deltaRows.push(['Total Assets', `${sd.previousTotalAssets} \u2192 ${_totalAssets} (${sd.assetDelta >= 0 ? '+' : ''}${sd.assetDelta})`]);
      }
      if (sd.findingsDelta !== null) {
        deltaRows.push(['Total Findings', `${sd.previousTotalFindings} \u2192 ${_totalFindings} (${sd.findingsDelta >= 0 ? '+' : ''}${sd.findingsDelta})`]);
      }
      deltaRows.push(['New Assets', String(sd.newAssets?.length ?? 0)]);
      deltaRows.push(['Removed Assets', String(sd.removedAssets?.length ?? 0)]);
      deltaRows.push(['Persistent Assets', String(sd.persistentAssets?.length ?? 0)]);

      autoTable!(doc, {
        startY: y,
        head: [['Metric', 'Change']],
        body: deltaRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7.5, cellPadding: 2, textColor: [30, 41, 59] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
      });
      y = (doc as any).lastAutoTable.finalY + 4;

      // New assets list
      if (sd.newAssets?.length > 0) {
        y = checkPageBreak(y, 15);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.text('Newly Discovered Assets:', margin, y);
        y += 3;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        for (const asset of sd.newAssets.slice(0, 15)) {
          y = checkPageBreak(y, 4);
          doc.text(`\u2022 ${truncate(asset, 80)}`, margin + 3, y);
          y += 3.5;
        }
        if (sd.newAssets.length > 15) {
          doc.setFont('helvetica', 'italic');
          doc.text(`... and ${sd.newAssets.length - 15} more`, margin + 3, y);
          y += 3.5;
        }
        y += 2;
      }

      // Removed assets list
      if (sd.removedAssets?.length > 0) {
        y = checkPageBreak(y, 15);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.text('Assets No Longer Detected:', margin, y);
        y += 3;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        for (const asset of sd.removedAssets.slice(0, 15)) {
          y = checkPageBreak(y, 4);
          doc.text(`\u2022 ${truncate(asset, 80)}`, margin + 3, y);
          y += 3.5;
        }
        if (sd.removedAssets.length > 15) {
          doc.setFont('helvetica', 'italic');
          doc.text(`... and ${sd.removedAssets.length - 15} more`, margin + 3, y);
          y += 3.5;
        }
        y += 2;
      }
    }
  }

   // ═════════════════════════════════════════════════════════════════════
  // 12. THREAT LANDSCAPE & ATTACK PATH ANALYSIS
  // ═════════════════════════════════════════════════════════════════════
  if (_tmData && _tmData.summary.totalMatched > 0) {
    y = startSection('Threat Landscape & Attack Path Analysis', y, 80);

    // Context paragraph explaining what this section is and why it matters
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(30, 41, 59);
    doc.setFontSize(8);
    const tmIntro = `This section cross-references the discovered attack surface against the Ace C3 master threat group catalog — a curated intelligence repository of ${_tmData.summary.totalGroupsAnalyzed} APT, ransomware, cybercrime, and hacktivist groups with their associated TTPs, tools, exploited CVEs, and target sectors. Unlike generic threat feeds, this analysis is deterministic: each match is grounded in specific overlap between the target’s confirmed vulnerabilities, detected technologies, and exposed services and the threat group’s documented operational patterns. ${_tmData.summary.totalMatched} group(s) were identified with meaningful TTP overlap, and ${_tmData.summary.totalAttackPaths} realistic attack path(s) were synthesized from confirmed scan findings.`;
    y = writeText(tmIntro, margin, y, contentWidth, 8);
    y += 4;

    // ─── 12a. Matched Threat Groups ────────────────────────────────────
    y = subheading('Matched Threat Groups', y);

    // Summary table of top matched groups
    const tmGroupRows: string[][] = _tmData.matchedGroups.slice(0, 10).map((g: any) => [
      g.groupName,
      g.groupType.toUpperCase(),
      g.origin || 'Unknown',
      `${g.matchScore}/100`,
      g.riskLevel.toUpperCase(),
      String(g.matchedCVEs?.length || 0),
      String(g.matchedTechniques?.length || 0),
      g.active ? 'Active' : 'Inactive',
    ]);

    autoTable!(doc, {
      startY: y,
      head: [['Group', 'Type', 'Origin', 'Score', 'Risk', 'CVE Overlap', 'TTP Overlap', 'Status']],
      body: tmGroupRows,
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [30, 41, 59] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 28 },
        1: { cellWidth: 18 },
        2: { cellWidth: 18 },
        3: { cellWidth: 16 },
        4: { cellWidth: 14 },
        5: { cellWidth: 18 },
        6: { cellWidth: 18 },
        7: { cellWidth: 14 },
      },
    });
    y = (doc as any).lastAutoTable.finalY + 5;

    // ─── 12b. Detailed Group Profiles with Reasoning ──────────────────
    const topGroups = _tmData.matchedGroups.slice(0, 5);
    for (const group of topGroups) {
      y = checkPageBreak(y, 60);

      // Group header bar
      const riskColors: Record<string, [number, number, number]> = {
        critical: [220, 38, 38], high: [234, 88, 12], medium: [202, 138, 4], low: [22, 163, 74],
      };
      const gColor = riskColors[group.riskLevel] || [113, 113, 122];

      doc.setFillColor(gColor[0], gColor[1], gColor[2]);
      doc.roundedRect(margin, y, contentWidth, 10, 1, 1, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text(`${group.groupName} (${group.groupType.toUpperCase()})`, margin + 3, y + 7);
      doc.setFontSize(7);
      doc.text(`Score: ${group.matchScore}/100 | ${group.riskLevel.toUpperCase()}`, margin + contentWidth - 55, y + 7);
      y += 13;

      // Aliases and origin
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.setFontSize(7);
      if (group.aliases?.length > 0) {
        doc.text(`Also known as: ${group.aliases.slice(0, 5).join(', ')}`, margin, y);
        y += 3.5;
      }
      doc.text(`Origin: ${group.origin || 'Unknown'} | Motivation: ${group.motivation || 'Unknown'} | Targets: ${(group.targetSectors || []).slice(0, 4).join(', ')}`, margin, y);
      y += 5;

      // Match rationale — the key reasoning paragraph
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text('Match Rationale:', margin, y);
      y += 3.5;
      doc.setFont('helvetica', 'normal');
      y = writeText(group.matchRationale || 'General profile overlap based on sector and technique applicability.', margin + 2, y, contentWidth - 4, 7.5);
      y += 2;

      // Scoring breakdown table
      y = checkPageBreak(y, 30);
      const breakdownRows: string[][] = [
        ['CVE Exploitation Overlap (30%)', `${group.scoreBreakdown?.cveScore || 0}/100`, group.matchedCVEs?.length > 0 ? group.matchedCVEs.slice(0, 3).join(', ') : 'No direct CVE overlap'],
        ['MITRE Technique Alignment (25%)', `${group.scoreBreakdown?.techniqueScore || 0}/100`, group.matchedTechniques?.length > 0 ? `${group.matchedTechniques.length} techniques across ${[...new Set(group.matchedTechniques.map((t: any) => t.tactic))].length} tactics` : 'No technique overlap'],
        ['Tool/Technology Correlation (20%)', `${group.scoreBreakdown?.toolScore || 0}/100`, group.matchedTools?.length > 0 ? group.matchedTools.slice(0, 3).join(', ') : 'No tool overlap'],
        ['Sector Targeting (15%)', `${group.scoreBreakdown?.sectorScore || 0}/100`, `${group.sectorRelevance || 0}% sector relevance`],
        ['Initial Access Viability (10%)', `${group.scoreBreakdown?.initialAccessScore || 0}/100`, group.matchedInitialAccess?.length > 0 ? group.matchedInitialAccess.slice(0, 2).join(', ') : 'No viable IA methods'],
      ];

      autoTable!(doc, {
        startY: y,
        head: [['Scoring Dimension', 'Score', 'Evidence']],
        body: breakdownRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
        bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [30, 41, 59] },
        alternateRowStyles: { fillColor: [248, 250, 252] },
        margin: { left: margin + 2, right: margin + 2 },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 48 },
          1: { cellWidth: 20 },
        },
      });
      y = (doc as any).lastAutoTable.finalY + 3;

      // Defense recommendations
      if (group.defenseRecommendations?.length > 0) {
        y = checkPageBreak(y, 15);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text('Priority Defense Recommendations:', margin, y);
        y += 3.5;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        for (const rec of group.defenseRecommendations.slice(0, 3)) {
          y = checkPageBreak(y, 5);
          doc.text(`\u2022 ${truncate(rec, 120)}`, margin + 3, y);
          y += 3.5;
        }
      }
      y += 4;
    }

    // ─── 12c. Synthesized Attack Paths ─────────────────────────────────
    if (_tmData.attackPaths?.length > 0) {
      y = subheading('Synthesized Attack Paths', y);

      // Context paragraph
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(7.5);
      const apIntro = `The following attack paths were synthesized by chaining confirmed scan findings through MITRE ATT&CK kill chain phases. Each step is grounded in an actual discovery from the scan — a confirmed CVE, an exposed service, or a detected technology — and attributed to threat groups whose TTPs match the path. These are not theoretical; they represent realistic adversary workflows against this specific attack surface.`;
      y = writeText(apIntro, margin, y, contentWidth, 7.5);
      y += 4;

      for (const path of _tmData.attackPaths.slice(0, 4)) {
        y = checkPageBreak(y, 50);

        // Path header
        const pathRiskColor = path.overallRisk >= 70 ? [220, 38, 38] : path.overallRisk >= 50 ? [234, 88, 12] : path.overallRisk >= 30 ? [202, 138, 4] : [22, 163, 74];
        doc.setFillColor(pathRiskColor[0] as number, pathRiskColor[1] as number, pathRiskColor[2] as number);
        doc.roundedRect(margin, y, contentWidth, 8, 1, 1, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(`${path.id}: ${truncate(path.name, 70)}`, margin + 3, y + 5.5);
        doc.setFontSize(6.5);
        doc.text(`Risk: ${path.overallRisk}/100 | Likelihood: ${path.likelihood}/5 | Impact: ${path.impact}/5`, margin + contentWidth - 65, y + 5.5);
        y += 11;

        // Path description
        doc.setTextColor(30, 41, 59);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        y = writeText(path.description, margin + 2, y, contentWidth - 4, 7.5);
        y += 2;

        // Attribution
        if (path.attributedGroups?.length > 0) {
          doc.setFontSize(7);
          doc.setFont('helvetica', 'italic');
          doc.setTextColor(100, 116, 139);
          doc.text(`Attributed to: ${path.attributedGroups.join(', ')}`, margin + 2, y);
          y += 4;
        }

        // Kill chain steps table
        const stepRows: string[][] = path.steps.map((s: any) => [
          String(s.order),
          s.phase,
          `${s.mitreTechnique}\n${s.techniqueName}`,
          truncate(s.targetAsset, 30),
          truncate(s.evidence, 80),
          s.difficulty?.toUpperCase() || 'N/A',
        ]);

        autoTable!(doc, {
          startY: y,
          head: [['#', 'Kill Chain Phase', 'MITRE Technique', 'Target', 'Evidence', 'Difficulty']],
          body: stepRows,
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
          bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [30, 41, 59] },
          alternateRowStyles: { fillColor: [248, 250, 252] },
          margin: { left: margin + 2, right: margin + 2 },
          columnStyles: {
            0: { cellWidth: 8 },
            1: { cellWidth: 25, fontStyle: 'bold' },
            2: { cellWidth: 28 },
            3: { cellWidth: 25 },
            5: { cellWidth: 18 },
          },
        });
        y = (doc as any).lastAutoTable.finalY + 5;
      }
    }

    // ─── 12d. MITRE ATT&CK Technique Heatmap ──────────────────────────
    const surfaceRelevantTechniques = (_tmData.techniqueHeatmap || []).filter((t: any) => t.surfaceRelevant);
    if (surfaceRelevantTechniques.length > 0) {
      y = checkPageBreak(y, 40);
      y = subheading('MITRE ATT&CK Technique Coverage (Surface-Relevant)', y);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(7.5);
      y = writeText(`${surfaceRelevantTechniques.length} of ${_tmData.techniqueHeatmap.length} total techniques from matched threat groups are directly relevant to the discovered attack surface. These techniques have corresponding services, technologies, or vulnerabilities on the target.`, margin, y, contentWidth, 7.5);
      y += 3;

      const heatmapRows: string[][] = surfaceRelevantTechniques.slice(0, 20).map((t: any) => [
        t.techniqueId,
        truncate(t.techniqueName, 35),
        t.tactic,
        t.groups.slice(0, 3).join(', '),
        t.relatedFinding ? truncate(t.relatedFinding, 40) : 'Service-level match',
      ]);

      autoTable!(doc, {
        startY: y,
        head: [['Technique ID', 'Technique Name', 'Tactic', 'Used By', 'Related Finding']],
        body: heatmapRows,
        theme: 'grid',
        headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
        bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [30, 41, 59] },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        margin: { left: margin, right: margin },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 22 },
          1: { cellWidth: 35 },
          2: { cellWidth: 28 },
        },
      });
      y = (doc as any).lastAutoTable.finalY + 5;
    }
  }

  // ═════════════════════════════════════════════════════════════════════
  // 13. TECHNOLOGY STACK ANALYSIS & MOST WIDESPREAD VULNERABILITIES
  // ═══════════════════════════════════════════════════════════════════════
  const _tsg = scan.techStackGrouping;
  if (_tsg && _tsg.summary.totalGroups > 0) {
    y = startSection('Technology Stack Analysis', y, 80);

    // Intro paragraph with context
    const stackIntro = _tsg.summary.stackOverlapPercentage > 30
      ? `Across ${_tsg.summary.totalAssets} analyzed assets, ${_tsg.summary.uniqueStacks} unique technology stacks were identified. ${_tsg.summary.stackOverlapPercentage}% of assets share a stack with at least one other asset, meaning vulnerabilities in common technologies have a multiplied blast radius. The largest group (${_tsg.summary.largestGroupSize} assets) runs ${truncate(_tsg.summary.largestGroupLabel, 80)}.`
      : `Across ${_tsg.summary.totalAssets} analyzed assets, ${_tsg.summary.uniqueStacks} unique technology stacks were identified. Technology diversity is relatively high, with an average of ${_tsg.summary.averageGroupSize} assets per stack.`;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(8.5);
    y = writeText(stackIntro, margin, y, contentWidth, 8.5);
    y += 4;

    // Stack Groups table (top 10)
    y = subheading('Technology Stack Groups (Top 10 by Size)', y);
    const stackRows = _tsg.groups.slice(0, 10).map((g: any) => [
      truncate(g.stackLabel, 50),
      String(g.assetCount),
      String(g.totalUniqueCves),
      String(g.sharedCves?.length || 0),
      `${g.avgRiskScore}/100 (${g.riskBand.toUpperCase()})`,
    ]);

    autoTable!(doc, {
      startY: y,
      head: [['Technology Stack', 'Assets', 'Total CVEs', 'Shared CVEs', 'Avg Risk']],
      body: stackRows,
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 1.5 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [30, 41, 59] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      columnStyles: {
        0: { cellWidth: 60 },
        1: { cellWidth: 18, halign: 'center' as const },
        2: { cellWidth: 22, halign: 'center' as const },
        3: { cellWidth: 22, halign: 'center' as const },
        4: { cellWidth: 35 },
      },
    });
    y = (doc as any).lastAutoTable.finalY + 5;

    // Shared Vulnerabilities detail for the largest group
    const largestGroup = _tsg.groups[0];
    if (largestGroup && largestGroup.sharedCves?.length > 0) {
      y = checkPageBreak(y, 40);
      y = subheading(`Shared Vulnerabilities: ${truncate(largestGroup.stackLabel, 50)} (${largestGroup.assetCount} assets)`, y);
      const sharedContext = `These ${largestGroup.sharedCves.length} vulnerabilities affect ALL ${largestGroup.assetCount} assets in this stack group. Patching or mitigating any of these addresses the risk across the entire group simultaneously.`;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.setFontSize(8);
      y = writeText(sharedContext, margin, y, contentWidth, 8);
      y += 3;

      const sharedRows = largestGroup.sharedCves.slice(0, 10).map((c: any) => [
        c.cveId,
        truncate(c.title, 50),
        String(c.severity) + '/10',
        c.cvssScore ? String(c.cvssScore) : 'N/A',
        c.kevListed ? 'YES' : 'No',
        c.exploitAvailable ? 'YES' : 'No',
        c.corroborationTier?.toUpperCase() || 'N/A',
      ]);

      autoTable!(doc, {
        startY: y,
        head: [['CVE ID', 'Description', 'Severity', 'CVSS', 'KEV', 'Exploit', 'Confidence']],
        body: sharedRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
        bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [30, 41, 59] },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        margin: { left: margin, right: margin },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 24 },
          1: { cellWidth: 50 },
          2: { cellWidth: 16, halign: 'center' as const },
          3: { cellWidth: 14, halign: 'center' as const },
          4: { cellWidth: 12, halign: 'center' as const },
          5: { cellWidth: 14, halign: 'center' as const },
          6: { cellWidth: 20, halign: 'center' as const },
        },
      });
      y = (doc as any).lastAutoTable.finalY + 5;
    }

    // Most Widespread Vulnerabilities
    if (_tsg.mostWidespreadVulns?.length > 0) {
      y = checkPageBreak(y, 40);
      y = subheading('Most Widespread Vulnerabilities', y);
      const widespreadContext = `These vulnerabilities affect the highest number of assets. Remediating them provides the greatest reduction in aggregate exposure.`;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.setFontSize(8);
      y = writeText(widespreadContext, margin, y, contentWidth, 8);
      y += 3;

      const widespreadRows = _tsg.mostWidespreadVulns.slice(0, 15).map((v: any) => [
        v.cveId,
        truncate(v.title, 45),
        String(v.severity) + '/10',
        v.cvssScore ? String(v.cvssScore) : 'N/A',
        `${v.affectedAssetCount} (${v.affectedPercentage}%)`,
        v.kevListed ? 'YES' : 'No',
        v.exploitAvailable ? 'YES' : 'No',
      ]);

      autoTable!(doc, {
        startY: y,
        head: [['CVE ID', 'Description', 'Severity', 'CVSS', 'Affected Assets', 'KEV', 'Exploit']],
        body: widespreadRows,
        theme: 'grid',
        headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 6, fontStyle: 'bold', cellPadding: 1.5 },
        bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [30, 41, 59] },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        margin: { left: margin, right: margin },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 24 },
          1: { cellWidth: 48 },
          2: { cellWidth: 16, halign: 'center' as const },
          3: { cellWidth: 14, halign: 'center' as const },
          4: { cellWidth: 25, halign: 'center' as const },
          5: { cellWidth: 12, halign: 'center' as const },
          6: { cellWidth: 14, halign: 'center' as const },
        },
      });
      y = (doc as any).lastAutoTable.finalY + 5;
    }

    // Remediation efficiency note
    y = checkPageBreak(y, 25);
    const remediationNote = _tsg.summary.stackOverlapPercentage > 30
      ? `Remediation Efficiency: Because ${_tsg.summary.stackOverlapPercentage}% of assets share technology stacks, patching common components (e.g., updating ${truncate(_tsg.summary.largestGroupLabel, 40)}) can address vulnerabilities across ${_tsg.summary.largestGroupSize} assets simultaneously. Prioritize stack-level remediation over per-asset patching for maximum efficiency.`
      : `Remediation Note: Technology diversity across the asset base means most vulnerabilities are isolated to specific assets. Per-asset remediation plans are recommended.`;
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 116, 139);
    doc.setFontSize(7.5);
    y = writeText(remediationNote, margin, y, contentWidth, 7.5);
    y += 5;
  }

  // ═════════════════════════════════════════════════════════════════════
  // 14. PRIORITIZED RECOMMENDATIONS
  // ═══════════════════════════════════════════════════════════════════════
  y = startSection('Prioritized Recommendations', y, 60);

  // Build recommendations: prefer LLM-generated, fallback to data-driven from scan findings
  let finalRecommendations = llmAnalysis.recommendations || [];
  if (finalRecommendations.length === 0) {
    // Generate data-driven recommendations from actual scan data
    const autoRecs: any[] = [];
    // From compliance failed checks
    const _compFailedChecks = scan.complianceScan?.checks?.filter((c: any) => c.status === 'fail' || c.status === 'failed') || [];
    for (const fc of _compFailedChecks.slice(0, 8)) {
      autoRecs.push({
        recommendation: fc.remediation || `Remediate: ${fc.title}`,
        title: fc.title || fc.stigId || fc.checkId || 'Compliance Fix',
        category: fc.category || 'Compliance',
        effort: fc.severity === 'high' || fc.severity === 'critical' ? 'Immediate' : fc.severity === 'medium' ? 'Short-term' : 'Medium-term',
      });
    }
    // From registration risks
    if (domainHealth.registration) {
      const reg = domainHealth.registration;
      if (reg.dnssecEnabled === false || reg.dnssec === 'unsigned' || reg.dnssec === 'Not Enabled') {
        autoRecs.push({ recommendation: 'Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks.', title: 'Enable DNSSEC', category: 'DNS Security', effort: 'Short-term' });
      }
      const daysLeft = reg.daysUntilExpiry ?? reg.daysToExpiry;
      if (daysLeft !== undefined && daysLeft <= 30) {
        autoRecs.push({ recommendation: `Domain expires in ${daysLeft} days. Renew immediately and enable auto-renewal to prevent domain hijacking.`, title: 'Renew Domain', category: 'Domain Management', effort: 'Immediate' });
      }
    }
    // From email security
    if (email.dmarc?.policy === 'none') {
      autoRecs.push({ recommendation: 'Upgrade DMARC policy from "none" to "quarantine" or "reject" to prevent email spoofing.', title: 'Enforce DMARC Policy', category: 'Email Security', effort: 'Short-term' });
    }
    // From blacklist
    if (_blacklistCount > 0) {
      autoRecs.push({ recommendation: `Investigate and remediate ${_blacklistCount} DNSBL listing(s) to restore email deliverability and IP reputation.`, title: 'Address Blacklist Listings', category: 'IP Reputation', effort: 'Immediate' });
    }
    // From exploit matches
    if (_exploitTotal > 0) {
      autoRecs.push({ recommendation: `${_exploitTotal} public exploit(s) map to discovered technologies. Prioritize patching affected components.`, title: 'Patch Exploitable Components', category: 'Vulnerability Management', effort: 'Immediate' });
    }
    // From OEM credentials
    if (scan.oemCredentials?.length > 0) {
      autoRecs.push({ recommendation: `${scan.oemCredentials.length} default credential match(es) detected. Change all default passwords immediately.`, title: 'Change Default Credentials', category: 'Access Control', effort: 'Immediate' });
    }
    finalRecommendations = autoRecs;
  }

  // Humanize underscore/snake_case values for display
  const humanize = (s: string) => s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

  if (finalRecommendations.length > 0) {
    autoTable!(doc, {
      startY: y,
      head: [['Priority', 'Recommendation', 'Category', 'Effort']],
      body: finalRecommendations.slice(0, 20).map((r: any, i: number) => [
        `P${i + 1}`,
        truncate(r.recommendation || r.title || r, 150),
        humanize(truncate(r.category || 'General', 30)),
        humanize(r.effort || 'N/A'),
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
    ['Total Findings (Unique)', `${_totalFindings} unique findings (${_confirmedFc} confirmed, ${_probableFc} probable, ${_potentialFc} potential)${_uniqueCve && _uniqueCve.totalFindingInstances > _totalFindings ? ` — ${_uniqueCve.totalFindingInstances} total instances across ${_totalAssets} assets` : ''}`],
    ['Confirmed Findings', String(_confirmedFc)],
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
    if (i === 1) continue; // Cover page has its own footer — skip to avoid double footer
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 30, pageHeight - 8);
    doc.text('CONFIDENTIAL — For authorized recipients only', margin, pageHeight - 8);
  }

  doc.save(`DI_Report_${domain}_${dateStamp()}.pdf`);
}

// Helper: add footer to current page
function addFooter(doc: any, margin: number, pageWidth: number, pageHeight: number) {
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text(`Page ${doc.getCurrentPageInfo().pageNumber}`, pageWidth - 30, pageHeight - 8);
  doc.text('CONFIDENTIAL', margin, pageHeight - 8);
}
