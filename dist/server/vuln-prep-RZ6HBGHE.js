import {
  exploit_source_taxonomy_exports,
  init_exploit_source_taxonomy
} from "./chunk-GP7VIGWZ.js";
import {
  init_stack_profile,
  init_tech_auto_detector,
  stack_profile_exports,
  tech_auto_detector_exports
} from "./chunk-GISYHDRA.js";
import "./chunk-YLOGWPLS.js";
import "./chunk-WJ24GKGB.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-SOJRLK5Z.js";
import {
  db_exports,
  init_db
} from "./chunk-26A2QP6T.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  schema_exports
} from "./chunk-NWJ2JNWL.js";
import {
  __esm,
  __require,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-detection/vuln-prep.ts
async function executeVulnPrep(ctx) {
  const { state, engagement, operatorCtx, helpers } = ctx;
  const { addLog, broadcastOpsUpdate, pushVulnDeduped, persistOpsStateDebounced } = helpers;
  const result = {
    promotedCount: 0,
    taxonomyHypothesized: 0
  };
  for (const asset of state.assets) {
    if (asset.pendingVulns && asset.pendingVulns.length > 0) {
      for (const pv of asset.pendingVulns) {
        if (pushVulnDeduped(asset, pv)) {
          state.stats.vulnsFound++;
          result.promotedCount++;
        }
      }
      asset.pendingVulns = [];
    }
  }
  if (result.promotedCount > 0) {
    addLog(state, {
      phase: "vuln_detection",
      type: "info",
      title: `\u{1F4CB} Promoted ${result.promotedCount} passive recon findings to confirmed vulns`,
      detail: `${result.promotedCount} risk signals from passive recon (Shodan, Censys, posture analysis) are now included in the vulnerability count for correlation with active scan results.`
    });
  }
  try {
    const { getVulnsForTechnology, getMisconfigsForTechnology } = (init_exploit_source_taxonomy(), __toCommonJS(exploit_source_taxonomy_exports));
    for (const asset of state.assets) {
      const techs = [
        ...asset.type !== "unknown" ? [asset.type] : [],
        ...asset.ports.map((p) => p.service).filter(Boolean),
        ...asset.technologies || []
      ];
      for (const tech of techs) {
        const taxVulns = getVulnsForTechnology(tech);
        for (const tv of taxVulns) {
          const alreadyFound = asset.vulns.some(
            (v) => v.title.toLowerCase().includes(tv.name.toLowerCase().split(" ")[0]) || v.__vulnClassId && v.__vulnClassId === tv.id
          );
          if (!alreadyFound) {
            if (!asset.taxonomyHints) asset.taxonomyHints = [];
            asset.taxonomyHints.push({
              title: `[Taxonomy] ${tv.name} (hypothesized for ${tech})`,
              severity: tv.severity,
              source: "exploit-taxonomy",
              __taxonomyHint: true,
              __vulnClassId: tv.id,
              __category: tv.category,
              __layer: tv.layer
            });
            result.taxonomyHypothesized++;
          }
        }
        const misconfigs = getMisconfigsForTechnology(tech);
        for (const mc of misconfigs) {
          if (!asset.taxonomyHints) asset.taxonomyHints = [];
          asset.taxonomyHints.push({
            title: `[Taxonomy] Potential misconfiguration: ${mc}`,
            severity: "medium",
            source: "exploit-taxonomy",
            __taxonomyHint: true
          });
          result.taxonomyHypothesized++;
        }
      }
    }
    if (result.taxonomyHypothesized > 0) {
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: `\u{1F9EC} Taxonomy enrichment: ${result.taxonomyHypothesized} hypothesized vulnerabilities`,
        detail: `Exploit source taxonomy identified ${result.taxonomyHypothesized} potential vulnerabilities based on detected technologies. These will guide active scanning and be available for cross-layer reasoning during exploitation.`
      });
    }
  } catch (e) {
    console.warn(`[ExploitTaxonomy] Enrichment failed: ${e.message}`);
  }
  try {
    const { getDb: getDbForProfile } = (init_db(), __toCommonJS(db_exports));
    const { customerStackProfiles } = (init_schema(), __toCommonJS(schema_exports));
    const { eq: eqOp, desc: descOp } = __require("drizzle-orm");
    const dbForProfile = await getDbForProfile();
    const linkedProfiles = await dbForProfile.select().from(customerStackProfiles).where(eqOp(customerStackProfiles.engagementId, state.engagementId)).orderBy(descOp(customerStackProfiles.updatedAt)).limit(1);
    if (linkedProfiles.length > 0) {
      const profile = linkedProfiles[0];
      const profileTechs = [
        ...profile.languages || [],
        ...profile.webFrameworks || [],
        ...profile.dataAndMl || [],
        ...profile.genaiAndLlm || [],
        ...profile.cloudServices || [],
        ...profile.securityTools || [],
        ...profile.devopsAndCi || [],
        ...profile.databasesList || [],
        ...profile.infrastructure || [],
        ...profile.other || []
      ].filter(Boolean);
      state.__linkedStackProfile = {
        id: profile.id,
        customerName: profile.customerName,
        technologies: profileTechs,
        technologyVersions: profile.technologyVersions || {},
        matchedScanners: profile.matchedScanners || []
      };
      if (profile.technologyVersions && Object.keys(profile.technologyVersions).length > 0) {
        const { matchVersionCves } = (init_stack_profile(), __toCommonJS(stack_profile_exports));
        const versionCves = matchVersionCves(profile.technologyVersions);
        state.__versionCves = versionCves;
        if (versionCves.length > 0) {
          addLog(state, {
            phase: "vuln_detection",
            type: "warning",
            title: `\u26A0\uFE0F Stack Profile: ${versionCves.length} version-specific CVEs identified`,
            detail: `Customer "${profile.customerName}" stack profile pre-loaded.
` + versionCves.map((c) => `\u2022 ${c.cveId} (${c.severity.toUpperCase()}) \u2014 ${c.technology} ${c.version} < ${c.affectedBelow}: ${c.title}`).join("\n")
          });
        }
      }
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: `\u{1F4CB} Stack Profile Loaded: ${profile.customerName}`,
        detail: `Pre-seeded ${profileTechs.length} technologies and ${(profile.matchedScanners || []).length} scanner modules from linked stack profile #${profile.id}.
Technologies: ${profileTechs.slice(0, 15).join(", ")}${profileTechs.length > 15 ? ` (+${profileTechs.length - 15} more)` : ""}`
      });
    }
  } catch (e) {
    console.warn(`[StackProfileAutoLoad] Failed to load linked profile: ${e.message}`);
  }
  try {
    const { detectTechnologies, formatDetectionSummary, buildScannerActivations } = (init_tech_auto_detector(), __toCommonJS(tech_auto_detector_exports));
    const assetSignals = state.assets.map((asset) => ({
      hostname: asset.hostname || asset.target || "",
      ip: asset.ip,
      headers: asset.headers || {},
      html: asset.html || "",
      technologies: asset.technologies || [],
      ports: asset.ports || [],
      passiveRecon: {
        technologies: asset.passiveReconTechs || [],
        cloudProvider: asset.cloudProvider,
        riskSignals: asset.riskSignals || []
      },
      repoUrl: asset.repoUrl || asset.url || "",
      responseSnippets: asset.responseSnippets || []
    }));
    const techResult = detectTechnologies(assetSignals);
    if (techResult.confirmedTechnologies.length > 0) {
      const summary = formatDetectionSummary(techResult);
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: `\u{1F50D} Tech Auto-Detection: ${techResult.confirmedTechnologies.length} specialized technologies found`,
        detail: summary
      });
      state.__detectedTechnologies = techResult.confirmedTechnologies;
      state.__scannerActivations = buildScannerActivations(techResult);
      state.__techTestPlanItems = techResult.testPlanItems;
      if (techResult.detectedVersions && Object.keys(techResult.detectedVersions).length > 0) {
        state.__detectedVersions = techResult.detectedVersions;
        const versionSummary = Object.entries(techResult.detectedVersions).map(([t, v]) => `${t}: ${v}`).join(", ");
        addLog(state, {
          phase: "vuln_detection",
          type: "info",
          title: `\u{1F4CB} Version Auto-Detection: ${Object.keys(techResult.detectedVersions).length} versions extracted`,
          detail: `Detected versions: ${versionSummary}`
        });
        try {
          const { matchVersionCves } = (init_stack_profile(), __toCommonJS(stack_profile_exports));
          const versionCves = matchVersionCves(techResult.detectedVersions);
          if (versionCves.length > 0) {
            state.__autoDetectedCves = versionCves;
            addLog(state, {
              phase: "vuln_detection",
              type: "warning",
              title: `\u{1F6A8} Version CVE Alert: ${versionCves.length} known CVEs for detected versions`,
              detail: versionCves.slice(0, 5).map((c) => `${c.cveId} (${c.severity}) \u2014 ${c.technology} ${c.version} < ${c.affectedBelow}`).join("\n")
            });
          }
        } catch (e) {
          console.warn(`[VersionCVE] Auto-match failed: ${e.message}`);
        }
      }
      for (const activation of buildScannerActivations(techResult)) {
        addLog(state, {
          phase: "vuln_detection",
          type: "info",
          title: `\u{1F9E9} Scanner activated: ${activation.module} (${activation.technology})`,
          detail: `Priority ${activation.priority} \u2014 ${activation.testPlanItems.length} test plan items generated`
        });
      }
    } else {
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: "\u{1F50D} Tech Auto-Detection: No specialized technologies detected",
        detail: "Checked for Streamlit, Jupyter, LangChain, FAISS, Firebase, GitHub Actions \u2014 none confirmed above threshold."
      });
    }
  } catch (e) {
    console.warn(`[TechAutoDetector] Detection failed: ${e.message}`);
    addLog(state, {
      phase: "vuln_detection",
      type: "warning",
      title: "\u26A0\uFE0F Tech Auto-Detection failed",
      detail: e.message
    });
  }
  try {
    const profileData = state.__linkedStackProfile;
    const liveDetected = state.__detectedTechnologies || [];
    if (profileData && profileData.technologies.length > 0) {
      const combinedTechs = /* @__PURE__ */ new Set([
        ...liveDetected.map((t) => (typeof t === "string" ? t : t.technology || "").toLowerCase()),
        ...profileData.technologies.map((t) => t.toLowerCase())
      ]);
      const profileOnly = profileData.technologies.filter(
        (t) => !liveDetected.some((ld) => {
          const ldName = (typeof ld === "string" ? ld : ld.technology || "").toLowerCase();
          return ldName.includes(t.toLowerCase()) || t.toLowerCase().includes(ldName);
        })
      );
      if (profileOnly.length > 0) {
        addLog(state, {
          phase: "vuln_detection",
          type: "info",
          title: `\u{1F517} Stack Profile added ${profileOnly.length} technologies not found by live detection`,
          detail: `Profile-only technologies: ${profileOnly.join(", ")}
Total combined: ${combinedTechs.size} unique technologies`
        });
      }
      const existingActivations = state.__scannerActivations || [];
      const existingModules = new Set(existingActivations.map((a) => a.module));
      for (const scanner of profileData.matchedScanners || []) {
        if (!existingModules.has(scanner)) {
          existingActivations.push({
            module: scanner,
            technology: "stack-profile",
            priority: "high",
            testPlanItems: [],
            source: "customer-stack-profile"
          });
          addLog(state, {
            phase: "vuln_detection",
            type: "info",
            title: `\u{1F9E9} Scanner activated from profile: ${scanner}`,
            detail: `Added by linked stack profile (not detected in live scan)`
          });
        }
      }
      state.__scannerActivations = existingActivations;
    }
  } catch (e) {
    console.warn(`[StackProfileMerge] Merge failed: ${e.message}`);
  }
  const nucleiHintedVulns = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.__nucleiHint).length, 0);
  if (nucleiHintedVulns > 0) {
    addLog(state, {
      phase: "vuln_detection",
      type: "info",
      title: `\u26A1 ${nucleiHintedVulns} vulns have Nuclei fast-path hints`,
      detail: `${nucleiHintedVulns} vulnerabilities from DI pipeline have pre-resolved Nuclei templates. These will skip LLM exploit generation and run targeted Nuclei scans directly during the exploitation phase.`
    });
  }
  {
    const TRAINING_LAB_CREDS = {
      dvwa: [
        { username: "admin", password: "password", service: "http-form", loginPath: "/login.php" },
        { username: "gordonb", password: "abc123", service: "http-form", loginPath: "/login.php" },
        { username: "1337", password: "charley", service: "http-form", loginPath: "/login.php" },
        { username: "pablo", password: "lettering", service: "http-form", loginPath: "/login.php" },
        { username: "smithy", password: "password", service: "http-form", loginPath: "/login.php" }
      ],
      "juice-shop": [
        { username: "admin@juice-sh.op", password: "admin123", service: "http-post", loginPath: "/rest/user/login" },
        { username: "jim@juice-sh.op", password: "ncc-1701", service: "http-post", loginPath: "/rest/user/login" },
        { username: "bender@juice-sh.op", password: "OhG0dPlease1nsertLiquworHere!", service: "http-post", loginPath: "/rest/user/login" }
      ],
      webgoat: [{ username: "guest", password: "guest", service: "http-form", loginPath: "/WebGoat/login" }],
      bwapp: [{ username: "bee", password: "bug", service: "http-form", loginPath: "/login.php" }],
      mutillidae: [{ username: "admin", password: "admin", service: "http-form", loginPath: "/index.php?page=login.php" }],
      hackazon: [{ username: "test_user", password: "test_user", service: "http-form", loginPath: "/user/login" }],
      bodgeit: [{ username: "test@test.com", password: "test", service: "http-form", loginPath: "/bodgeit/login.jsp" }],
      gruyere: [{ username: "test", password: "test", service: "http-form", loginPath: "/login" }],
      "broken-crystals": [
        { username: "bc", password: "bc", service: "postgresql", loginPath: "/api/auth/login" },
        { username: "john@mail.com", password: "Admin123!", service: "http-post", loginPath: "/api/auth/login" },
        { username: "admin@mail.com", password: "Admin123!", service: "http-post", loginPath: "/api/auth/login" }
      ]
    };
    const targetHostnames = state.assets.map((a) => a.hostname.toLowerCase());
    for (const [labName, creds] of Object.entries(TRAINING_LAB_CREDS)) {
      const matchesLab = targetHostnames.some((h) => h.includes(labName.replace("-", "")));
      if (matchesLab) {
        if (!state.trainingLabMode) {
          state.trainingLabMode = true;
          addLog(state, {
            phase: "vuln_detection",
            type: "info",
            title: `\u{1F3AF} Auto-detected Training Lab: ${labName}`,
            detail: `Hostname matches known training lab pattern. Enabling trainingLabMode for authenticated scanning.`
          });
        }
        let injectedCount = 0;
        for (const asset of state.assets) {
          if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
          for (const cred of creds) {
            const exists = asset.confirmedCredentials.some(
              (c) => c.username === cred.username && c.password === cred.password
            );
            if (!exists) {
              asset.confirmedCredentials.push({
                ...cred,
                protocol: "https",
                port: 443,
                source: "training_lab_defaults",
                testedAt: Date.now(),
                status: "confirmed"
              });
              injectedCount++;
            }
          }
        }
        if (injectedCount > 0) {
          addLog(state, {
            phase: "vuln_detection",
            type: "info",
            title: `\u{1F511} Training Lab Creds Injected: ${labName} (${injectedCount} credentials)`,
            detail: `Pre-loaded ${injectedCount} known default credentials for ${labName} to enable authenticated ZAP crawling and scanning.`
          });
        }
      }
    }
  }
  try {
    const { onBurpScanComplete } = await import("./burp-auto-scan-6FGOB67D.js");
    onBurpScanComplete(async (burpConfig, burpState) => {
      if (burpConfig.engagementId !== state.engagementId) return;
      const deduped = burpState.deduplicatedCount || 0;
      console.log(`[EngagementOps] Burp scan ${burpState.scanId} completed for engagement #${state.engagementId}: ${burpState.issueCount} issues, ${burpState.importedCount} imported, ${deduped} deduplicated`);
      if (state.completedScans) {
        const burpTarget = burpConfig.targetUrl || burpConfig.baseUrl || "unknown";
        state.completedScans.burpCompleted.add(burpTarget);
        state.completedScans.lastCheckpointAt = Date.now();
      }
      addLog(state, {
        phase: "vuln_detection",
        type: "scan_result",
        title: `\u2705 Burp Scan Complete: ${burpState.importedCount} findings imported${deduped > 0 ? ` (${deduped} duplicates skipped)` : ""}`,
        detail: `Scan ${burpState.scanId} finished in ${Math.round(((burpState.completedAt || Date.now()) - burpState.startedAt) / 1e3)}s. ${burpState.issueCount} issues found, ${burpState.importedCount} imported as findings. Severity escalation and exploit matching ran automatically.`,
        data: { scanId: burpState.scanId, issueCount: burpState.issueCount, importedCount: burpState.importedCount, deduplicatedCount: deduped }
      });
      const normalizedFindings = burpState.normalizedFindings;
      if (normalizedFindings && normalizedFindings.length > 0) {
        let injected = 0;
        for (const finding of normalizedFindings) {
          if (finding.severityRating === "none") continue;
          const findingHost = finding.assetIdentifier?.replace(/^https?:\/\//, "").replace(/[:\/].*$/, "") || "";
          const matchingAsset = state.assets.find(
            (a) => a.hostname === findingHost || a.ip === findingHost || a.hostname && findingHost.includes(a.hostname) || findingHost && a.hostname?.includes(findingHost)
          );
          if (matchingAsset) {
            const alreadyExists = matchingAsset.vulns.some(
              (v) => v.title === `[Burp] ${finding.title}` || v.title === finding.title
            );
            if (alreadyExists) continue;
            matchingAsset.vulns.push({
              id: `burp-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
              severity: finding.severityRating === "none" ? "low" : finding.severityRating,
              title: `[Burp] ${finding.title}`,
              source: "burp",
              cve: finding.cweId || void 0,
              corroborationTier: "confirmed",
              evidenceDetail: `Burp Suite confirmed: ${finding.title}${finding.metadata?.path ? ` at ${finding.metadata.path}` : ""}${finding.metadata?.confidence ? ` (confidence: ${finding.metadata.confidence})` : ""}`
            });
            injected++;
          }
        }
        if (injected > 0) {
          state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
          addLog(state, {
            phase: "vuln_detection",
            type: "info",
            title: `\u{1F517} Burp \u2192 Exploit Pipeline: ${injected} findings injected`,
            detail: `${injected} Burp findings added to asset vuln lists as exploit candidates.`,
            data: { injectedCount: injected }
          });
          broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: state.stats });
        }
      }
      if (normalizedFindings && normalizedFindings.length > 0) {
        try {
          const { saveEngagementFindings } = await import("./db-65DPEQYH.js");
          const burpDbFindings = normalizedFindings.filter((f) => f.severityRating !== "none").map((f) => {
            const findingHost = f.assetIdentifier?.replace(/^https?:\/\//, "").replace(/[:\/].*$/, "") || "";
            const matchingAsset = state.assets.find(
              (a) => a.hostname === findingHost || a.ip === findingHost || a.hostname && findingHost.includes(a.hostname) || findingHost && a.hostname?.includes(findingHost)
            );
            return {
              engagementId: burpConfig.engagementId,
              title: `[Burp] ${f.title}`,
              severity: f.severityRating === "none" ? "low" : f.severityRating,
              description: f.metadata?.path ? `Burp Suite confirmed at ${f.metadata.path}` : `Burp Suite confirmed: ${f.title}`,
              hostname: matchingAsset?.hostname || findingHost,
              source: "burp",
              tool: "burp",
              cwe: f.cweId || void 0,
              corroborationTier: "confirmed",
              endpoint: f.metadata?.path
            };
          });
          if (burpDbFindings.length > 0) {
            const saved = await saveEngagementFindings(burpDbFindings);
            console.log(`[EngagementOps] Persisted ${saved} Burp findings to engagement_findings DB`);
          }
        } catch (dbErr) {
          console.warn(`[EngagementOps] Failed to persist Burp findings to DB: ${dbErr.message}`);
        }
      }
      persistOpsStateDebounced(state.engagementId, 500);
    });
  } catch (cbErr) {
    console.warn(`[EngagementOps] Failed to register Burp completion callback: ${cbErr.message}`);
  }
  try {
    const { getEngagementCredentials } = await import("./credential-harvester-BFNF5MQY.js");
    const { credentials: harvestedCreds, stats: credStats } = await getEngagementCredentials(state.engagementId);
    if (harvestedCreds.length > 0) {
      const usableCreds = harvestedCreds.filter(
        (c) => c.password && !c.password.startsWith("[") && c.password.length > 0
      );
      if (usableCreds.length > 0) {
        let injectedCount = 0;
        for (const asset of state.assets) {
          if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
          const assetDomain = asset.hostname?.toLowerCase() || "";
          for (const cred of usableCreds) {
            const credDomain = cred.email?.split("@")[1]?.toLowerCase() || "";
            const isRelevant = credDomain && assetDomain.includes(credDomain.split(".")[0]);
            const isWebAsset = asset.ports?.some((p) => [80, 443, 8080, 8443, 3e3, 8e3].includes(p.port));
            const isHighConf = cred.confidence === "high";
            if (isRelevant || isWebAsset && isHighConf) {
              const exists = asset.confirmedCredentials.some(
                (c) => c.username === cred.username && c.password === cred.password
              );
              if (!exists) {
                asset.confirmedCredentials.push({
                  username: cred.username,
                  password: cred.password,
                  service: "http-form",
                  port: 80,
                  protocol: "http",
                  accessLevel: "unconfirmed",
                  source: `harvested_${cred.source}`,
                  confirmedAt: Date.now()
                });
                injectedCount++;
              }
            }
          }
        }
        if (injectedCount > 0) {
          addLog(state, {
            phase: "vuln_detection",
            type: "info",
            title: `\u{1F511} Credential Aggregation: ${injectedCount} breach creds injected`,
            detail: `Pulled ${usableCreds.length} usable credentials from breach databases (${Object.entries(credStats.bySource).map(([s, n]) => `${s}: ${n}`).join(", ")}) and injected ${injectedCount} into asset confirmed credentials for authenticated ZAP/Burp scanning.`
          });
        }
      } else {
        addLog(state, {
          phase: "vuln_detection",
          type: "info",
          title: `\u{1F511} Credential Harvest: ${harvestedCreds.length} found, 0 usable`,
          detail: `Found ${harvestedCreds.length} harvested credentials but none had cleartext passwords.`
        });
      }
    }
  } catch (credAggErr) {
    console.warn(`[EngagementOps] Credential aggregation failed (non-fatal): ${credAggErr.message}`);
  }
  let burpAppLogin;
  if (state.trainingLabMode) {
    const BURP_TRAINING_LAB_CREDS = {
      "dvwa": { username: "admin", password: "password", loginPath: "/login.php" },
      "altoro": { username: "admin", password: "admin", loginPath: "/altoromutual/login.jsp" },
      "juiceshop": { username: "admin@juice-sh.op", password: "admin123", loginPath: "/#/login" },
      "hackazon": { username: "test_user", password: "test_user", loginPath: "/user/login" },
      "testphp": { username: "test", password: "test", loginPath: "/login.php" },
      "brokencrystals": { username: "admin", password: "admin", loginPath: "/api/auth/login" }
    };
    for (const asset of state.assets) {
      const hostname = (asset.hostname || "").toLowerCase();
      for (const [labKey, creds] of Object.entries(BURP_TRAINING_LAB_CREDS)) {
        if (hostname.includes(labKey)) {
          const proto = asset.ports?.some((p) => p.port === 443) ? "https" : "http";
          burpAppLogin = {
            username: creds.username,
            password: creds.password,
            loginUrl: `${proto}://${asset.hostname}${creds.loginPath}`
          };
          break;
        }
      }
      if (burpAppLogin) break;
    }
  }
  if (!burpAppLogin) {
    for (const asset of state.assets) {
      const assetCreds = asset.confirmedCredentials || [];
      const webCred = assetCreds.find((c) => c.protocol === "http" || c.protocol === "https");
      if (webCred) {
        const proto = asset.ports?.some((p) => p.port === 443) ? "https" : "http";
        burpAppLogin = {
          username: webCred.username,
          password: webCred.password,
          loginUrl: webCred.loginPath ? `${proto}://${asset.hostname}${webCred.loginPath}` : void 0
        };
        break;
      }
    }
  }
  result.burpAppLogin = burpAppLogin;
  try {
    const { onEngagementVulnDetectionPhase, extractScopeUrls } = await import("./burp-auto-scan-6FGOB67D.js");
    const scopeUrls = extractScopeUrls(engagement, state);
    if (scopeUrls.length > 0) {
      const allTechHints = [];
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
        [...new Set(allTechHints)]
      );
      if (burpResults.length > 0) {
        addLog(state, {
          phase: "vuln_detection",
          type: "scan_start",
          title: `\u{1F525} Burp Suite Auto-Scan Launched (${burpResults.length} instance${burpResults.length > 1 ? "s" : ""})`,
          detail: `Automatically triggered Burp Suite scans against ${scopeUrls.length} in-scope web targets. Findings will be imported on completion.`
        });
      }
    }
  } catch (burpErr) {
    console.warn(`[EngagementOps] Burp auto-scan hook failed: ${burpErr.message}`);
  }
  try {
    const { runZapToBurpPipeline } = await import("./zap-burp-pipeline-C56HUMAL.js");
    const pipelineResult = await runZapToBurpPipeline({
      engagementId: state.engagementId,
      userId: operatorCtx.id,
      engagementHandle: engagement.handle || engagement.name || `eng-${state.engagementId}`,
      appLogin: burpAppLogin
    });
    result.initialPipelineResult = pipelineResult;
    state._initialZapBurpPipelineResult = pipelineResult;
    if (pipelineResult.burpScanLaunched) {
      const sourceLabel = pipelineResult.urlSource === "zap_scan" ? `Extracted ${pipelineResult.zapUrlsDiscovered} URLs from ZAP scan #${pipelineResult.zapScanId}` : pipelineResult.urlSource === "scope_fallback" ? `ZAP scan ${pipelineResult.zapScanId ? `#${pipelineResult.zapScanId} still in progress` : "not yet started"} \u2014 used ${pipelineResult.urlsFedToBurp} engagement scope URLs` : `Override: ${pipelineResult.urlsFedToBurp} target URLs provided`;
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: `\u{1F517} ZAP \u2192 Burp Pipeline: ${pipelineResult.urlsFedToBurp} URLs cross-fed`,
        detail: `${sourceLabel}, fed ${pipelineResult.urlsFedToBurp} to Burp. Tech: ${pipelineResult.fingerprint.technologies.slice(0, 3).join(", ") || "none"}. Correlations: ${pipelineResult.correlatedFindings.filter((f) => f.confidenceBoost).length} confirmed by both tools.`
      });
    } else if (pipelineResult.error) {
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: "ZAP \u2192 Burp Pipeline: Skipped",
        detail: pipelineResult.error
      });
    }
  } catch (pipelineErr) {
    console.warn(`[EngagementOps] ZAP\u2192Burp pipeline failed: ${pipelineErr.message}`);
  }
  try {
    const { runSeverityEscalation } = await import("./zap-burp-pipeline-C56HUMAL.js");
    const escalation = await runSeverityEscalation(state.engagementId);
    if (escalation.escalatedCount > 0 || escalation.priorityFlaggedCount > 0) {
      addLog(state, {
        phase: "vuln_detection",
        type: "info",
        title: `\u26A1 Severity Escalation: ${escalation.escalatedCount} promoted, ${escalation.priorityFlaggedCount} flagged for exploit`,
        detail: `Cross-tool confirmation boosted ${escalation.escalatedCount} findings. ${escalation.priorityFlaggedCount} flagged for priority exploitation. Breakdown: ${Object.entries(escalation.severityBreakdown).map(([k, v]) => `${k}:${v}`).join(", ")}`
      });
    }
  } catch (escErr) {
    console.warn(`[EngagementOps] Severity escalation failed: ${escErr.message}`);
  }
  return result;
}
var init_vuln_prep = __esm({
  "server/lib/vuln-detection/vuln-prep.ts"() {
  }
});
init_vuln_prep();
export {
  executeVulnPrep
};
