/**
 * Phase 5 Sub-module: Context-Aware Target Profiling (Phase A.6)
 *
 * Builds target profiles from discovery data:
 * - WAF detection (HTTP headers, cookies, response patterns)
 * - CDN detection (CNAME, headers)
 * - Asset role classification
 * - Topology mapping
 * - Adaptive scan strategy generation
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";
import { addLog, fmtTarget } from "./enumeration-context";

/**
 * Run context-aware profiling on all scoped assets.
 * Stores profiles in state.targetProfiles for Phase B tool selection.
 */
export async function runTargetProfiling(
  state: EngagementOpsState,
  scopedAssets: any[],
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const {
      detectWAF, detectCDN, classifyAssetRole, selectEvasionProfile,
      generateScanStrategy, getDefaultScopeConstraints, buildTargetProfileContext,
    } = await import("../context-aware-scanner");
    type TargetProfile = import("../context-aware-scanner").TargetProfile;
    type TargetFingerprint = import("../context-aware-scanner").TargetFingerprint;
    type TopologyNode = import("../context-aware-scanner").TopologyNode;

    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: "🔍 Phase A.6: Context-Aware Target Profiling",
      detail: "Building target profiles from discovery data — detecting WAF, CDN, firewall, topology, and generating adaptive scan strategies",
    });

    if (!state.targetProfiles) state.targetProfiles = {};

    // Map engagement type to scope type
    const scopeTypeMap: Record<string, "pentest" | "red_team" | "vuln_assessment" | "bug_bounty"> = {
      pentest: "pentest",
      red_team: "red_team",
      purple_team: "red_team",
      phishing: "vuln_assessment",
      tabletop: "vuln_assessment",
    };
    const scopeEngType = scopeTypeMap[state.engagementType] || "pentest";
    const baseScopeConstraints = getDefaultScopeConstraints(scopeEngType);

    for (const asset of scopedAssets) {
      try {
        // ── Collect httpx response headers ──
        const httpxResult = asset.toolResults.find((tr: any) => tr.tool === "httpx");
        const responseHeaders: Record<string, string> = {
          ...((asset as any).httpxResponseHeaders || {}),
          ...(httpxResult?.fingerprints?.httpHeaders || {}),
        };
        if (httpxResult?.fingerprints?.webServer && !responseHeaders["server"]) {
          responseHeaders["server"] = httpxResult.fingerprints.webServer;
        }

        // ── Extract cookies ──
        const cookies: string[] = httpxResult?.fingerprints?.cookies || [];
        if (responseHeaders["set-cookie"]) {
          cookies.push(...responseHeaders["set-cookie"].split(/,\s*(?=[^;]*=)/));
        }

        // ── Extract status code ──
        let statusCode = 200;
        if (httpxResult?.rawOutput) {
          const scMatch = httpxResult.rawOutput.match(/"status.code":(\d+)|"status_code":(\d+)/);
          if (scMatch) statusCode = parseInt(scMatch[1] || scMatch[2]);
        }

        // ── Build TargetFingerprint ──
        const technologies = asset.passiveRecon?.technologies || [];
        const webServerStr = httpxResult?.fingerprints?.webServer || responseHeaders["server"] || null;
        const poweredBy = httpxResult?.fingerprints?.poweredBy || responseHeaders["x-powered-by"] || null;

        let webServerParsed: TargetFingerprint["webServer"] = null;
        if (webServerStr) {
          const wsMatch = webServerStr.match(/^([\w.-]+)\/?([\d.]+)?/);
          webServerParsed = { name: wsMatch?.[1] || webServerStr, version: wsMatch?.[2] || null, role: "unknown" };
        }

        let appFramework: TargetFingerprint["appFramework"] = null;
        if (poweredBy) {
          const fwMatch = poweredBy.match(/^([\w.-]+)\/?([\d.]+)?/);
          const lang = /PHP/i.test(poweredBy) ? "PHP"
            : /ASP/i.test(poweredBy) ? "C#"
            : /Express|Node/i.test(poweredBy) ? "JavaScript"
            : /JSF|Servlet/i.test(poweredBy) ? "Java"
            : "unknown";
          appFramework = { name: fwMatch?.[1] || poweredBy, version: fwMatch?.[2] || null, language: lang };
        }

        // Detect CMS
        let cms: TargetFingerprint["cms"] = null;
        const cmsNames = ["WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix", "Squarespace", "Ghost", "Typo3", "PrestaShop"];
        for (const cmsName of cmsNames) {
          const found = technologies.find((t: string) => t.toLowerCase().includes(cmsName.toLowerCase()));
          if (found) {
            const vMatch = found.match(/([\d.]+)/);
            cms = { name: cmsName, version: vMatch?.[1] || null };
            break;
          }
        }

        // Detect languages
        const langPatterns: Record<string, RegExp> = {
          PHP: /php/i, Java: /java|jsp|servlet/i, Python: /python|django|flask/i,
          "C#": /asp\.net|c#/i, Ruby: /ruby|rails/i, JavaScript: /node|express|next|react|angular|vue/i,
          Go: /\bgo\b|golang/i, Rust: /\brust\b/i,
        };
        const detectedLangs: string[] = [];
        for (const [lang, pat] of Object.entries(langPatterns)) {
          if (technologies.some((t: string) => pat.test(t)) || (poweredBy && pat.test(poweredBy))) {
            detectedLangs.push(lang);
          }
        }

        // Build TLS info
        let tlsData: TargetFingerprint["tls"] = null;
        if (httpxResult?.fingerprints?.tlsInfo) {
          const ti = httpxResult.fingerprints.tlsInfo;
          tlsData = {
            version: ti.protocol || "unknown",
            cipher: ti.cipherSuite || null,
            certIssuer: ti.issuerOrg || null,
            certExpiry: ti.notAfter || null,
            hsts: !!responseHeaders["strict-transport-security"],
            protocols: ti.protocol ? [ti.protocol] : [],
          };
        }

        // Build service banners
        const serviceBanners: TargetFingerprint["serviceBanners"] = {};
        for (const p of asset.ports || []) {
          serviceBanners[p.port] = {
            service: p.service || "unknown",
            version: p.version || null,
            banner: null,
            protocol: "tcp",
          };
        }

        const fingerprint: TargetFingerprint = {
          serverHeader: webServerStr,
          webServer: webServerParsed,
          appFramework,
          cms,
          os: null,
          tls: tlsData,
          languages: detectedLangs,
          jsFrameworks: technologies.filter((t: string) => /react|angular|vue|svelte|next|nuxt|gatsby/i.test(t)),
          databases: technologies.filter((t: string) => /mysql|postgres|mongo|redis|elastic|sqlite|mariadb|oracle|mssql/i.test(t)),
          techTags: technologies,
          serviceBanners,
        };

        // ── WAF detection ──
        const wafProfile = detectWAF(responseHeaders, cookies, "", statusCode);
        if (wafProfile.detected) {
          asset.wafDetected = wafProfile.vendor || "unknown";
          addLog(state, {
            phase: "enumeration",
            type: "waf_detected",
            title: `🛡️ WAF Detected: ${fmtTarget(asset)} → ${wafProfile.vendor} (${wafProfile.type})`,
            detail: `Confidence: ${wafProfile.confidence}% | Detection: ${wafProfile.detectionMethod}\nBypass techniques: ${wafProfile.bypassTechniques.slice(0, 3).join(", ")}`,
          });
        }

        // ── CDN detection ──
        const cnames = (asset as any).cnames || (asset.passiveRecon?.dnsRecords?.["CNAME"] || []);
        const cdnProfile = detectCDN(responseHeaders, cnames);
        if (cdnProfile.detected) {
          addLog(state, {
            phase: "enumeration",
            type: "info",
            title: `🌐 CDN Detected: ${fmtTarget(asset)} → ${cdnProfile.provider}`,
            detail: `Evidence: ${cdnProfile.evidence.join(", ")}${cdnProfile.originIp ? ` | Origin IP: ${cdnProfile.originIp}` : ""}${cdnProfile.hasBuiltInWAF ? " | Has built-in WAF" : ""}`,
          });
        }

        // ── Classify asset role ──
        const openPorts = (asset.ports || []).map((p: any) => p.port);
        const roleResult = classifyAssetRole(fingerprint, openPorts, responseHeaders);

        // ── Build topology node ──
        const topologyNode: TopologyNode = {
          host: asset.hostname,
          role: roleResult.role,
          confidence: roleResult.confidence,
          backend: null,
          services: (asset.ports || []).map((p: any) => ({ port: p.port, service: p.service, version: p.version || null })),
          directlyReachable: true,
        };

        // ── Determine environment ──
        const cloudProviders = (asset as any).cloudProviders || [];
        const environment: TargetProfile["environment"] = cloudProviders.length > 0
          ? "cloud"
          : technologies.some((t: string) => /docker|kubernetes|k8s|container/i.test(t))
          ? "containerized"
          : technologies.some((t: string) => /lambda|serverless|cloud.function/i.test(t))
          ? "serverless"
          : "traditional";

        // ── Determine risk profile ──
        const riskProfile: TargetProfile["riskProfile"] =
          wafProfile.detected && cdnProfile.detected
            ? "high_security"
            : wafProfile.detected || cdnProfile.detected
            ? "standard"
            : (asset.ports || []).length > 20
            ? "legacy"
            : "standard";

        // ── Build scope constraints ──
        const scopeConstraints = { ...baseScopeConstraints };
        if (cdnProfile.detected) scopeConstraints.sharedInfrastructure = true;
        if (wafProfile.detected)
          scopeConstraints.wafBypassAuthorized = scopeEngType === "pentest" || scopeEngType === "red_team";

        // ── Build partial profile ──
        const partialProfile: Omit<TargetProfile, "recommendedStrategy"> = {
          hostname: asset.hostname,
          ips: asset.ip ? [asset.ip] : [],
          fingerprint,
          waf: wafProfile,
          cdn: cdnProfile,
          firewall: {
            detected: false,
            type: "unknown",
            filteredPorts: [],
            rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null },
            geoBlocking: false,
            ipReputationBlocking: false,
          },
          topology: topologyNode,
          environment,
          riskProfile,
          scopeConstraints,
          profiledAt: Date.now(),
        };

        // ── Generate scan strategy ──
        const strategy = generateScanStrategy(partialProfile);
        const fullProfile: TargetProfile = { ...partialProfile, recommendedStrategy: strategy };
        state.targetProfiles[asset.hostname] = fullProfile;

        addLog(state, {
          phase: "enumeration",
          type: "info",
          title: `📋 Profile: ${fmtTarget(asset)} → ${roleResult.role} (${environment})`,
          detail: `Strategy: ${strategy.name} (${strategy.riskLevel} risk, ~${strategy.estimatedTimeMinutes}min)\nEvasion: ${strategy.evasionProfile.name} (${strategy.evasionProfile.rateLimit} req/s)\nPhases: ${strategy.phases.map((p: any) => p.name).join(" → ")}`,
        });
      } catch (profileErr: any) {
        addLog(state, {
          phase: "enumeration",
          type: "warning",
          title: `⚠️ Profiling Failed: ${fmtTarget(asset)}`,
          detail: `Context-aware profiling error: ${profileErr.message}. Proceeding with default scan strategy.`,
        });
      }
    }

    const profiledCount = Object.keys(state.targetProfiles).length;
    const wafCount = Object.values(state.targetProfiles).filter((p: any) => p.waf.detected).length;
    const cdnCount = Object.values(state.targetProfiles).filter((p: any) => p.cdn.detected).length;

    addLog(state, {
      phase: "enumeration",
      type: "phase_complete",
      title: `✅ Context-Aware Profiling Complete: ${profiledCount} targets profiled`,
      detail: `WAF detected: ${wafCount} | CDN detected: ${cdnCount}\nProfiles stored for adaptive Phase B tool selection and downstream vuln scanning.`,
    });
  } catch (profileEngineErr: any) {
    console.error("[ContextAwareScanner] Error:", profileEngineErr.message);
    addLog(state, {
      phase: "enumeration",
      type: "warning",
      title: "⚠️ Context-Aware Profiling Skipped",
      detail: `Profiling engine error: ${profileEngineErr.message}. Proceeding to Phase B with default strategies.`,
    });
  }
}
