/**
 * Vulnerability Detection — Preparation Phase
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 3365-4067).
 *
 * Responsibilities:
 *   1. Promote pending vulns from passive recon into confirmed vulns
 *   2. Taxonomy-based vulnerability enrichment (exploit source taxonomy)
 *   3. Customer stack profile auto-load and version CVE matching
 *   4. Technology auto-detection engine (Streamlit, Jupyter, LangChain, etc.)
 *   5. Merge stack profile + live detection results
 *   6. Training lab credential injection
 *   7. Register Burp completion callback
 *   8. Aggregate harvested credentials (DeHashed, IntelX, etc.)
 *   9. Extract app login for Burp authenticated scanning
 *   10. Launch Burp Suite auto-scan
 *   11. ZAP → Burp cross-tool pipeline
 *   12. Severity escalation (cross-tool confirmation)
 */

import type { VulnDetectionContext } from "./index";

export interface VulnPrepResult {
  /** Number of passive recon findings promoted to confirmed vulns */
  promotedCount: number;
  /** Number of taxonomy-hypothesized vulnerabilities */
  taxonomyHypothesized: number;
  /** Burp app login extracted for authenticated scanning */
  burpAppLogin?: { username: string; password: string; loginUrl?: string };
  /** Initial ZAP→Burp pipeline result (stored on state for deferred re-feed) */
  initialPipelineResult?: any;
}

/**
 * Execute the vulnerability preparation phase.
 * This runs before active scanning tools (Nuclei, ZAP, SQLMap) to:
 *   - Promote passive findings
 *   - Enrich with taxonomy data
 *   - Load stack profiles and detect technologies
 *   - Inject training lab credentials
 *   - Launch Burp auto-scan
 *   - Run ZAP→Burp cross-tool pipeline
 */
export async function executeVulnPrep(ctx: VulnDetectionContext): Promise<VulnPrepResult> {
  const { state, engagement, operatorCtx, helpers } = ctx;
  const { addLog, broadcastOpsUpdate, pushVulnDeduped, persistOpsStateDebounced } = helpers;

  const result: VulnPrepResult = {
    promotedCount: 0,
    taxonomyHypothesized: 0,
  };

  // ── 1. Promote pendingVulns from passive recon into confirmed vulns ──
  for (const asset of state.assets) {
    if (asset.pendingVulns && asset.pendingVulns.length > 0) {
      for (const pv of asset.pendingVulns) {
        if (pushVulnDeduped(asset, pv as any)) {
          state.stats.vulnsFound++;
          result.promotedCount++;
        }
      }
      asset.pendingVulns = [];
    }
  }
  if (result.promotedCount > 0) {
    addLog(state, {
      phase: "vuln_detection", type: "info",
      title: `📋 Promoted ${result.promotedCount} passive recon findings to confirmed vulns`,
      detail: `${result.promotedCount} risk signals from passive recon (Shodan, Censys, posture analysis) are now included in the vulnerability count for correlation with active scan results.`,
    });
  }

  // ── 2. Taxonomy-based vulnerability enrichment ──
  try {
    const { getVulnsForTechnology, getMisconfigsForTechnology } = require('../exploit-source-taxonomy');
    for (const asset of state.assets) {
      const techs = [
        ...(asset.type !== 'unknown' ? [asset.type] : []),
        ...asset.ports.map((p: any) => p.service).filter(Boolean),
        ...(asset.technologies || []),
      ];
      for (const tech of techs) {
        const taxVulns = getVulnsForTechnology(tech);
        for (const tv of taxVulns) {
          const alreadyFound = asset.vulns.some((v: any) =>
            v.title.toLowerCase().includes(tv.name.toLowerCase().split(' ')[0]) ||
            (v.__vulnClassId && v.__vulnClassId === tv.id)
          );
          if (!alreadyFound) {
            if (!asset.taxonomyHints) asset.taxonomyHints = [];
            asset.taxonomyHints.push({
              title: `[Taxonomy] ${tv.name} (hypothesized for ${tech})`,
              severity: tv.severity,
              source: 'exploit-taxonomy',
              __taxonomyHint: true,
              __vulnClassId: tv.id,
              __category: tv.category,
              __layer: tv.layer,
            });
            result.taxonomyHypothesized++;
          }
        }
        const misconfigs = getMisconfigsForTechnology(tech);
        for (const mc of misconfigs) {
          if (!asset.taxonomyHints) asset.taxonomyHints = [];
          asset.taxonomyHints.push({
            title: `[Taxonomy] Potential misconfiguration: ${mc}`,
            severity: 'medium',
            source: 'exploit-taxonomy',
            __taxonomyHint: true,
          });
          result.taxonomyHypothesized++;
        }
      }
    }
    if (result.taxonomyHypothesized > 0) {
      addLog(state, {
        phase: 'vuln_detection', type: 'info',
        title: `🧬 Taxonomy enrichment: ${result.taxonomyHypothesized} hypothesized vulnerabilities`,
        detail: `Exploit source taxonomy identified ${result.taxonomyHypothesized} potential vulnerabilities based on detected technologies. These will guide active scanning and be available for cross-layer reasoning during exploitation.`,
      });
    }
  } catch (e: any) {
    console.warn(`[ExploitTaxonomy] Enrichment failed: ${e.message}`);
  }

  // ── 3. Customer Stack Profile Auto-Load ──
  try {
    const { getDb: getDbForProfile } = require('../../db');
    const { customerStackProfiles } = require('../../../drizzle/schema');
    const { eq: eqOp, desc: descOp } = require('drizzle-orm');
    const dbForProfile = await getDbForProfile();
    const linkedProfiles = await dbForProfile.select().from(customerStackProfiles)
      .where(eqOp(customerStackProfiles.engagementId, state.engagementId))
      .orderBy(descOp(customerStackProfiles.updatedAt))
      .limit(1);
    if (linkedProfiles.length > 0) {
      const profile = linkedProfiles[0];
      const profileTechs: string[] = [
        ...(profile.languages || []),
        ...(profile.webFrameworks || []),
        ...(profile.dataAndMl || []),
        ...(profile.genaiAndLlm || []),
        ...(profile.cloudServices || []),
        ...(profile.securityTools || []),
        ...(profile.devopsAndCi || []),
        ...(profile.databasesList || []),
        ...(profile.infrastructure || []),
        ...(profile.other || []),
      ].filter(Boolean);
      (state as any).__linkedStackProfile = {
        id: profile.id,
        customerName: profile.customerName,
        technologies: profileTechs,
        technologyVersions: profile.technologyVersions || {},
        matchedScanners: profile.matchedScanners || [],
      };
      if (profile.technologyVersions && Object.keys(profile.technologyVersions).length > 0) {
        const { matchVersionCves } = require('../../routers/stack-profile');
        const versionCves = matchVersionCves(profile.technologyVersions);
        (state as any).__versionCves = versionCves;
        if (versionCves.length > 0) {
          addLog(state, {
            phase: 'vuln_detection', type: 'warning',
            title: `⚠️ Stack Profile: ${versionCves.length} version-specific CVEs identified`,
            detail: `Customer "${profile.customerName}" stack profile pre-loaded.\n` +
              versionCves.map((c: any) => `• ${c.cveId} (${c.severity.toUpperCase()}) — ${c.technology} ${c.version} < ${c.affectedBelow}: ${c.title}`).join('\n'),
          });
        }
      }
      addLog(state, {
        phase: 'vuln_detection', type: 'info',
        title: `📋 Stack Profile Loaded: ${profile.customerName}`,
        detail: `Pre-seeded ${profileTechs.length} technologies and ${(profile.matchedScanners || []).length} scanner modules from linked stack profile #${profile.id}.\n` +
          `Technologies: ${profileTechs.slice(0, 15).join(', ')}${profileTechs.length > 15 ? ` (+${profileTechs.length - 15} more)` : ''}`,
      });
    }
  } catch (e: any) {
    console.warn(`[StackProfileAutoLoad] Failed to load linked profile: ${e.message}`);
  }

  // ── 4. Technology Auto-Detection Engine ──
  try {
    const { detectTechnologies, formatDetectionSummary, buildScannerActivations } = require('../scanners/tech-auto-detector');
    const assetSignals = state.assets.map((asset: any) => ({
      hostname: asset.hostname || asset.target || '',
      ip: asset.ip,
      headers: asset.headers || {},
      html: asset.html || '',
      technologies: asset.technologies || [],
      ports: asset.ports || [],
      passiveRecon: {
        technologies: asset.passiveReconTechs || [],
        cloudProvider: asset.cloudProvider,
        riskSignals: asset.riskSignals || [],
      },
      repoUrl: asset.repoUrl || asset.url || '',
      responseSnippets: asset.responseSnippets || [],
    }));
    const techResult = detectTechnologies(assetSignals);
    if (techResult.confirmedTechnologies.length > 0) {
      const summary = formatDetectionSummary(techResult);
      addLog(state, {
        phase: 'vuln_detection', type: 'info',
        title: `🔍 Tech Auto-Detection: ${techResult.confirmedTechnologies.length} specialized technologies found`,
        detail: summary,
      });
      (state as any).__detectedTechnologies = techResult.confirmedTechnologies;
      (state as any).__scannerActivations = buildScannerActivations(techResult);
      (state as any).__techTestPlanItems = techResult.testPlanItems;
      if (techResult.detectedVersions && Object.keys(techResult.detectedVersions).length > 0) {
        (state as any).__detectedVersions = techResult.detectedVersions;
        const versionSummary = Object.entries(techResult.detectedVersions)
          .map(([t, v]) => `${t}: ${v}`).join(', ');
        addLog(state, {
          phase: 'vuln_detection', type: 'info',
          title: `📋 Version Auto-Detection: ${Object.keys(techResult.detectedVersions).length} versions extracted`,
          detail: `Detected versions: ${versionSummary}`,
        });
        try {
          const { matchVersionCves } = require('../../routers/stack-profile');
          const versionCves = matchVersionCves(techResult.detectedVersions);
          if (versionCves.length > 0) {
            (state as any).__autoDetectedCves = versionCves;
            addLog(state, {
              phase: 'vuln_detection', type: 'warning',
              title: `🚨 Version CVE Alert: ${versionCves.length} known CVEs for detected versions`,
              detail: versionCves.slice(0, 5).map((c: any) => `${c.cveId} (${c.severity}) — ${c.technology} ${c.version} < ${c.affectedBelow}`).join('\n'),
            });
          }
        } catch (e: any) {
          console.warn(`[VersionCVE] Auto-match failed: ${e.message}`);
        }
      }
      for (const activation of buildScannerActivations(techResult)) {
        addLog(state, {
          phase: 'vuln_detection', type: 'info',
          title: `🧩 Scanner activated: ${activation.module} (${activation.technology})`,
          detail: `Priority ${activation.priority} — ${activation.testPlanItems.length} test plan items generated`,
        });
      }
    } else {
      addLog(state, {
        phase: 'vuln_detection', type: 'info',
        title: '🔍 Tech Auto-Detection: No specialized technologies detected',
        detail: 'Checked for Streamlit, Jupyter, LangChain, FAISS, Firebase, GitHub Actions — none confirmed above threshold.',
      });
    }
  } catch (e: any) {
    console.warn(`[TechAutoDetector] Detection failed: ${e.message}`);
    addLog(state, {
      phase: 'vuln_detection', type: 'warning',
      title: '⚠️ Tech Auto-Detection failed',
      detail: e.message,
    });
  }

  // ── 5. Merge Stack Profile + Live Detection ──
  try {
    const profileData = (state as any).__linkedStackProfile;
    const liveDetected = (state as any).__detectedTechnologies || [];
    if (profileData && profileData.technologies.length > 0) {
      const combinedTechs = new Set<string>([
        ...liveDetected.map((t: any) => (typeof t === 'string' ? t : t.technology || '').toLowerCase()),
        ...profileData.technologies.map((t: string) => t.toLowerCase()),
      ]);
      const profileOnly = profileData.technologies.filter((t: string) =>
        !liveDetected.some((ld: any) => {
          const ldName = (typeof ld === 'string' ? ld : ld.technology || '').toLowerCase();
          return ldName.includes(t.toLowerCase()) || t.toLowerCase().includes(ldName);
        })
      );
      if (profileOnly.length > 0) {
        addLog(state, {
          phase: 'vuln_detection', type: 'info',
          title: `🔗 Stack Profile added ${profileOnly.length} technologies not found by live detection`,
          detail: `Profile-only technologies: ${profileOnly.join(', ')}\nTotal combined: ${combinedTechs.size} unique technologies`,
        });
      }
      const existingActivations = (state as any).__scannerActivations || [];
      const existingModules = new Set(existingActivations.map((a: any) => a.module));
      for (const scanner of profileData.matchedScanners || []) {
        if (!existingModules.has(scanner)) {
          existingActivations.push({
            module: scanner,
            technology: 'stack-profile',
            priority: 'high',
            testPlanItems: [],
            source: 'customer-stack-profile',
          });
          addLog(state, {
            phase: 'vuln_detection', type: 'info',
            title: `🧩 Scanner activated from profile: ${scanner}`,
            detail: `Added by linked stack profile (not detected in live scan)`,
          });
        }
      }
      (state as any).__scannerActivations = existingActivations;
    }
  } catch (e: any) {
    console.warn(`[StackProfileMerge] Merge failed: ${e.message}`);
  }

  // ── 6. Log Nuclei fast-path hint coverage ──
  const nucleiHintedVulns = state.assets.reduce((sum, a) => sum + a.vulns.filter((v: any) => v.__nucleiHint).length, 0);
  if (nucleiHintedVulns > 0) {
    addLog(state, {
      phase: "vuln_detection", type: "info",
      title: `⚡ ${nucleiHintedVulns} vulns have Nuclei fast-path hints`,
      detail: `${nucleiHintedVulns} vulnerabilities from DI pipeline have pre-resolved Nuclei templates. These will skip LLM exploit generation and run targeted Nuclei scans directly during the exploitation phase.`,
    });
  }

  // ── 7. Inject training lab default credentials for authenticated scanning ──
  {
    const TRAINING_LAB_CREDS: Record<string, Array<{ username: string; password: string; service: string; loginPath?: string }>> = {
      dvwa: [
        { username: "admin", password: "password", service: "http-form", loginPath: "/login.php" },
        { username: "gordonb", password: "abc123", service: "http-form", loginPath: "/login.php" },
        { username: "1337", password: "charley", service: "http-form", loginPath: "/login.php" },
        { username: "pablo", password: "lettering", service: "http-form", loginPath: "/login.php" },
        { username: "smithy", password: "password", service: "http-form", loginPath: "/login.php" },
      ],
      'juice-shop': [
        { username: "admin@juice-sh.op", password: "admin123", service: "http-post", loginPath: "/rest/user/login" },
        { username: "jim@juice-sh.op", password: "ncc-1701", service: "http-post", loginPath: "/rest/user/login" },
        { username: "bender@juice-sh.op", password: "OhG0dPlease1nsertLiquworHere!", service: "http-post", loginPath: "/rest/user/login" },
      ],
      webgoat: [{ username: "guest", password: "guest", service: "http-form", loginPath: "/WebGoat/login" }],
      bwapp: [{ username: "bee", password: "bug", service: "http-form", loginPath: "/login.php" }],
      mutillidae: [{ username: "admin", password: "admin", service: "http-form", loginPath: "/index.php?page=login.php" }],
      hackazon: [{ username: "test_user", password: "test_user", service: "http-form", loginPath: "/user/login" }],
      bodgeit: [{ username: "test@test.com", password: "test", service: "http-form", loginPath: "/bodgeit/login.jsp" }],
      gruyere: [{ username: "test", password: "test", service: "http-form", loginPath: "/login" }],
      'broken-crystals': [
        { username: "bc", password: "bc", service: "postgresql", loginPath: "/api/auth/login" },
        { username: "john@mail.com", password: "Admin123!", service: "http-post", loginPath: "/api/auth/login" },
        { username: "admin@mail.com", password: "Admin123!", service: "http-post", loginPath: "/api/auth/login" },
      ],
    };

    const targetHostnames = state.assets.map(a => a.hostname.toLowerCase());
    for (const [labName, creds] of Object.entries(TRAINING_LAB_CREDS)) {
      const matchesLab = targetHostnames.some(h => h.includes(labName.replace('-', '')));
      if (matchesLab) {
        if (!state.trainingLabMode) {
          state.trainingLabMode = true;
          addLog(state, {
            phase: "vuln_detection", type: "info",
            title: `🎯 Auto-detected Training Lab: ${labName}`,
            detail: `Hostname matches known training lab pattern. Enabling trainingLabMode for authenticated scanning.`,
          });
        }
        let injectedCount = 0;
        for (const asset of state.assets) {
          if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
          for (const cred of creds) {
            const exists = asset.confirmedCredentials.some(
              (c: any) => c.username === cred.username && c.password === cred.password
            );
            if (!exists) {
              asset.confirmedCredentials.push({
                ...cred,
                protocol: 'https',
                port: 443,
                source: 'training_lab_defaults',
                testedAt: Date.now(),
                status: 'confirmed',
              } as any);
              injectedCount++;
            }
          }
        }
        if (injectedCount > 0) {
          addLog(state, {
            phase: "vuln_detection", type: "info",
            title: `🔑 Training Lab Creds Injected: ${labName} (${injectedCount} credentials)`,
            detail: `Pre-loaded ${injectedCount} known default credentials for ${labName} to enable authenticated ZAP crawling and scanning.`,
          });
        }
      }
    }
  }

  // ── 8. Register Burp completion callback ──
  try {
    const { onBurpScanComplete } = await import("../burp-auto-scan");
    onBurpScanComplete(async (burpConfig, burpState) => {
      if (burpConfig.engagementId !== state.engagementId) return;
      const deduped = (burpState as any).deduplicatedCount || 0;
      console.log(`[EngagementOps] Burp scan ${burpState.scanId} completed for engagement #${state.engagementId}: ${burpState.issueCount} issues, ${burpState.importedCount} imported, ${deduped} deduplicated`);

      if (state.completedScans) {
        const burpTarget = burpConfig.targetUrl || burpConfig.baseUrl || 'unknown';
        state.completedScans.burpCompleted.add(burpTarget);
        state.completedScans.lastCheckpointAt = Date.now();
      }
      addLog(state, {
        phase: "vuln_detection", type: "scan_result",
        title: `✅ Burp Scan Complete: ${burpState.importedCount} findings imported${deduped > 0 ? ` (${deduped} duplicates skipped)` : ''}`,
        detail: `Scan ${burpState.scanId} finished in ${Math.round(((burpState.completedAt || Date.now()) - burpState.startedAt) / 1000)}s. ` +
          `${burpState.issueCount} issues found, ${burpState.importedCount} imported as findings. ` +
          `Severity escalation and exploit matching ran automatically.`,
        data: { scanId: burpState.scanId, issueCount: burpState.issueCount, importedCount: burpState.importedCount, deduplicatedCount: deduped },
      });

      // Inject Burp findings into asset vulns for exploitation phase
      const normalizedFindings = (burpState as any).normalizedFindings as Array<{
        title: string; severityRating: string; assetIdentifier: string;
        cweId: string | null; metadata?: { path?: string; confidence?: string };
      }> | undefined;

      if (normalizedFindings && normalizedFindings.length > 0) {
        let injected = 0;
        for (const finding of normalizedFindings) {
          if (finding.severityRating === 'none') continue;
          const findingHost = finding.assetIdentifier?.replace(/^https?:\/\//, '').replace(/[:\/].*$/, '') || '';
          const matchingAsset = state.assets.find(a =>
            a.hostname === findingHost ||
            a.ip === findingHost ||
            (a.hostname && findingHost.includes(a.hostname)) ||
            (findingHost && a.hostname?.includes(findingHost))
          );
          if (matchingAsset) {
            const alreadyExists = matchingAsset.vulns.some(v =>
              v.title === `[Burp] ${finding.title}` || v.title === finding.title
            );
            if (alreadyExists) continue;
            matchingAsset.vulns.push({
              id: `burp-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
              severity: finding.severityRating === 'none' ? 'low' : finding.severityRating,
              title: `[Burp] ${finding.title}`,
              source: 'burp' as any,
              cve: finding.cweId || undefined,
              corroborationTier: 'confirmed' as any,
              evidenceDetail: `Burp Suite confirmed: ${finding.title}${finding.metadata?.path ? ` at ${finding.metadata.path}` : ''}${finding.metadata?.confidence ? ` (confidence: ${finding.metadata.confidence})` : ''}`,
            } as any);
            injected++;
          }
        }
        if (injected > 0) {
          state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
          addLog(state, {
            phase: "vuln_detection", type: "info",
            title: `🔗 Burp → Exploit Pipeline: ${injected} findings injected`,
            detail: `${injected} Burp findings added to asset vuln lists as exploit candidates.`,
            data: { injectedCount: injected },
          });
          broadcastOpsUpdate(state.engagementId, { type: 'stats_update', stats: state.stats });
        }
      }

      // Persist Burp findings to engagement_findings DB table
      if (normalizedFindings && normalizedFindings.length > 0) {
        try {
          const { saveEngagementFindings } = await import('../../db');
          const burpDbFindings = normalizedFindings
            .filter(f => f.severityRating !== 'none')
            .map(f => {
              const findingHost = f.assetIdentifier?.replace(/^https?:\/\//, '').replace(/[:\/].*$/, '') || '';
              const matchingAsset = state.assets.find(a =>
                a.hostname === findingHost || a.ip === findingHost ||
                (a.hostname && findingHost.includes(a.hostname)) ||
                (findingHost && a.hostname?.includes(findingHost))
              );
              return {
                engagementId: burpConfig.engagementId,
                title: `[Burp] ${f.title}`,
                severity: f.severityRating === 'none' ? 'low' : f.severityRating,
                description: f.metadata?.path ? `Burp Suite confirmed at ${f.metadata.path}` : `Burp Suite confirmed: ${f.title}`,
                hostname: matchingAsset?.hostname || findingHost,
                source: 'burp',
                tool: 'burp',
                cwe: f.cweId || undefined,
                corroborationTier: 'confirmed' as const,
                endpoint: f.metadata?.path,
              };
            });
          if (burpDbFindings.length > 0) {
            const saved = await saveEngagementFindings(burpDbFindings);
            console.log(`[EngagementOps] Persisted ${saved} Burp findings to engagement_findings DB`);
          }
        } catch (dbErr: any) {
          console.warn(`[EngagementOps] Failed to persist Burp findings to DB: ${dbErr.message}`);
        }
      }
      persistOpsStateDebounced(state.engagementId, 500);
    });
  } catch (cbErr: any) {
    console.warn(`[EngagementOps] Failed to register Burp completion callback: ${cbErr.message}`);
  }

  // ── 9. Aggregate Harvested Credentials ──
  try {
    const { getEngagementCredentials } = await import("../credential-harvester");
    const { credentials: harvestedCreds, stats: credStats } = await getEngagementCredentials(state.engagementId);
    if (harvestedCreds.length > 0) {
      const usableCreds = harvestedCreds.filter(c =>
        c.password && !c.password.startsWith('[') && c.password.length > 0
      );
      if (usableCreds.length > 0) {
        let injectedCount = 0;
        for (const asset of state.assets) {
          if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
          const assetDomain = asset.hostname?.toLowerCase() || '';
          for (const cred of usableCreds) {
            const credDomain = cred.email?.split('@')[1]?.toLowerCase() || '';
            const isRelevant = credDomain && assetDomain.includes(credDomain.split('.')[0]);
            const isWebAsset = asset.ports?.some((p: any) => [80, 443, 8080, 8443, 3000, 8000].includes(p.port));
            const isHighConf = cred.confidence === 'high';
            if (isRelevant || (isWebAsset && isHighConf)) {
              const exists = asset.confirmedCredentials.some(
                (c: any) => c.username === cred.username && c.password === cred.password
              );
              if (!exists) {
                asset.confirmedCredentials.push({
                  username: cred.username,
                  password: cred.password,
                  service: 'http-form',
                  port: 80,
                  protocol: 'http',
                  accessLevel: 'unconfirmed',
                  source: `harvested_${cred.source}`,
                  confirmedAt: Date.now(),
                } as any);
                injectedCount++;
              }
            }
          }
        }
        if (injectedCount > 0) {
          addLog(state, {
            phase: "vuln_detection", type: "info",
            title: `🔑 Credential Aggregation: ${injectedCount} breach creds injected`,
            detail: `Pulled ${usableCreds.length} usable credentials from breach databases (${Object.entries(credStats.bySource).map(([s, n]) => `${s}: ${n}`).join(', ')}) and injected ${injectedCount} into asset confirmed credentials for authenticated ZAP/Burp scanning.`,
          });
        }
      } else {
        addLog(state, {
          phase: "vuln_detection", type: "info",
          title: `🔑 Credential Harvest: ${harvestedCreds.length} found, 0 usable`,
          detail: `Found ${harvestedCreds.length} harvested credentials but none had cleartext passwords.`,
        });
      }
    }
  } catch (credAggErr: any) {
    console.warn(`[EngagementOps] Credential aggregation failed (non-fatal): ${credAggErr.message}`);
  }

  // ── 10. Extract app login for Burp authenticated scanning ──
  let burpAppLogin: { username: string; password: string; loginUrl?: string } | undefined;
  if (state.trainingLabMode) {
    const BURP_TRAINING_LAB_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
      'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php' },
      'altoro': { username: 'admin', password: 'admin', loginPath: '/altoromutual/login.jsp' },
      'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/#/login' },
      'hackazon': { username: 'test_user', password: 'test_user', loginPath: '/user/login' },
      'testphp': { username: 'test', password: 'test', loginPath: '/login.php' },
      'brokencrystals': { username: 'admin', password: 'admin', loginPath: '/api/auth/login' },
    };
    for (const asset of state.assets) {
      const hostname = (asset.hostname || '').toLowerCase();
      for (const [labKey, creds] of Object.entries(BURP_TRAINING_LAB_CREDS)) {
        if (hostname.includes(labKey)) {
          const proto = asset.ports?.some((p: any) => p.port === 443) ? 'https' : 'http';
          burpAppLogin = {
            username: creds.username,
            password: creds.password,
            loginUrl: `${proto}://${asset.hostname}${creds.loginPath}`,
          };
          break;
        }
      }
      if (burpAppLogin) break;
    }
  }
  if (!burpAppLogin) {
    for (const asset of state.assets) {
      const assetCreds = (asset as any).confirmedCredentials || [];
      const webCred = assetCreds.find((c: any) => c.protocol === 'http' || c.protocol === 'https');
      if (webCred) {
        const proto = asset.ports?.some((p: any) => p.port === 443) ? 'https' : 'http';
        burpAppLogin = {
          username: webCred.username,
          password: webCred.password,
          loginUrl: webCred.loginPath ? `${proto}://${asset.hostname}${webCred.loginPath}` : undefined,
        };
        break;
      }
    }
  }
  result.burpAppLogin = burpAppLogin;

  // ── 11. Burp Suite Auto-Scan ──
  try {
    const { onEngagementVulnDetectionPhase, extractScopeUrls } = await import("../burp-auto-scan");
    const scopeUrls = extractScopeUrls(engagement, state);
    if (scopeUrls.length > 0) {
      const allTechHints: string[] = [];
      for (const asset of state.assets) {
        if (asset.passiveRecon?.technologies) allTechHints.push(...asset.passiveRecon.technologies);
        if (asset.ports) {
          for (const p of asset.ports) {
            if (p.version) allTechHints.push(p.version);
          }
        }
        const profile = state.targetProfiles?.[asset.hostname];
        if (profile?.fingerprint) {
          if (profile.fingerprint.cms?.name) allTechHints.push(profile.fingerprint.cms.name);
          if (profile.fingerprint.appFramework?.name) allTechHints.push(profile.fingerprint.appFramework.name);
          if (profile.fingerprint.databases?.length) allTechHints.push(...profile.fingerprint.databases);
        }
      }
      const burpResults = await onEngagementVulnDetectionPhase(
        state.engagementId,
        operatorCtx.id,
        engagement.handle || engagement.name || `eng-${state.engagementId}`,
        scopeUrls,
        engagement.scanMode || state.scanMode,
        burpAppLogin,
        [...new Set(allTechHints)],
      );
      if (burpResults.length > 0) {
        addLog(state, {
          phase: "vuln_detection", type: "scan_start",
          title: `🔥 Burp Suite Auto-Scan Launched (${burpResults.length} instance${burpResults.length > 1 ? 's' : ''})`,
          detail: `Automatically triggered Burp Suite scans against ${scopeUrls.length} in-scope web targets. Findings will be imported on completion.`,
        });
      }
    }
  } catch (burpErr: any) {
    console.warn(`[EngagementOps] Burp auto-scan hook failed: ${burpErr.message}`);
  }

  // ── 12. ZAP → Burp Cross-Tool Pipeline ──
  try {
    const { runZapToBurpPipeline } = await import("../zap-burp-pipeline");
    const pipelineResult = await runZapToBurpPipeline({
      engagementId: state.engagementId,
      userId: operatorCtx.id,
      engagementHandle: engagement.handle || engagement.name || `eng-${state.engagementId}`,
      appLogin: burpAppLogin,
    });
    result.initialPipelineResult = pipelineResult;
    (state as any)._initialZapBurpPipelineResult = pipelineResult;
    if (pipelineResult.burpScanLaunched) {
      const sourceLabel = pipelineResult.urlSource === 'zap_scan'
        ? `Extracted ${pipelineResult.zapUrlsDiscovered} URLs from ZAP scan #${pipelineResult.zapScanId}`
        : pipelineResult.urlSource === 'scope_fallback'
          ? `ZAP scan ${pipelineResult.zapScanId ? `#${pipelineResult.zapScanId} still in progress` : 'not yet started'} — used ${pipelineResult.urlsFedToBurp} engagement scope URLs`
          : `Override: ${pipelineResult.urlsFedToBurp} target URLs provided`;
      addLog(state, {
        phase: "vuln_detection", type: "info",
        title: `🔗 ZAP → Burp Pipeline: ${pipelineResult.urlsFedToBurp} URLs cross-fed`,
        detail: `${sourceLabel}, fed ${pipelineResult.urlsFedToBurp} to Burp. ` +
          `Tech: ${pipelineResult.fingerprint.technologies.slice(0, 3).join(", ") || "none"}. ` +
          `Correlations: ${pipelineResult.correlatedFindings.filter(f => f.confidenceBoost).length} confirmed by both tools.`,
      });
    } else if (pipelineResult.error) {
      addLog(state, {
        phase: "vuln_detection", type: "info",
        title: "ZAP → Burp Pipeline: Skipped",
        detail: pipelineResult.error,
      });
    }
  } catch (pipelineErr: any) {
    console.warn(`[EngagementOps] ZAP→Burp pipeline failed: ${pipelineErr.message}`);
  }

  // ── 13. Severity Escalation ──
  try {
    const { runSeverityEscalation } = await import("../zap-burp-pipeline");
    const escalation = await runSeverityEscalation(state.engagementId);
    if (escalation.escalatedCount > 0 || escalation.priorityFlaggedCount > 0) {
      addLog(state, {
        phase: "vuln_detection", type: "info",
        title: `⚡ Severity Escalation: ${escalation.escalatedCount} promoted, ${escalation.priorityFlaggedCount} flagged for exploit`,
        detail: `Cross-tool confirmation boosted ${escalation.escalatedCount} findings. ` +
          `${escalation.priorityFlaggedCount} flagged for priority exploitation. ` +
          `Breakdown: ${Object.entries(escalation.severityBreakdown).map(([k, v]) => `${k}:${v}`).join(", ")}`,
      });
    }
  } catch (escErr: any) {
    console.warn(`[EngagementOps] Severity escalation failed: ${escErr.message}`);
  }

  return result;
}
