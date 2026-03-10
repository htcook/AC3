/**
 * Passive-to-Active Handoff Module
 *
 * Analyzes passive reconnaissance findings and generates targeted active scan
 * configurations. This module bridges the gap between passive discovery and
 * active scanning by:
 *
 * 1. Analyzing passive observations to identify what needs active verification
 * 2. Generating tool-specific scan configs (Nmap, Nuclei, ZAP, DAST)
 * 3. Enforcing Rules of Engagement (RoE) scope restrictions
 * 4. Prioritizing assets by risk score for efficient scanning
 * 5. Tracking provenance: which passive finding triggered which active scan
 *
 * Two modes:
 * - Domain Intel (Operations Dashboard): Passive-only. This module is NOT invoked.
 * - Engagement with RoE: Full lifecycle. Passive → this module → active scans.
 */

import type { AssetObservation } from "./types";

// ─── Types ─────────────────────────────────────────────────────────

export interface RulesOfEngagement {
  /** Hostnames/IPs explicitly in scope */
  scopedAssets: string[];
  /** Hostnames/IPs explicitly excluded */
  excludedAssets: string[];
  /** Allowed scan types */
  allowedScanTypes: ("nmap" | "nuclei" | "zap" | "dast" | "manual")[];
  /** Maximum scan intensity (1-5, where 5 is most aggressive) */
  maxIntensity: number;
  /** Time window restrictions */
  scanWindow?: {
    startHour: number; // 0-23
    endHour: number;   // 0-23
    timezone: string;
  };
  /** Whether social engineering is permitted */
  socialEngineeringAllowed: boolean;
  /** Whether DoS testing is permitted */
  dosTestingAllowed: boolean;
  /** Custom exclusion patterns (regex) */
  exclusionPatterns?: string[];
  /** Maximum concurrent scans */
  maxConcurrentScans: number;
}

export interface ActiveScanTarget {
  /** The hostname or IP to scan */
  hostname: string;
  /** Resolved IP address if known */
  ip?: string;
  /** Priority score (0-100, higher = scan first) */
  priority: number;
  /** Why this target was selected for active scanning */
  rationale: string;
  /** Technologies detected during passive recon */
  technologies: string[];
  /** Ports discovered during passive recon */
  knownPorts: { port: number; service: string; version: string }[];
  /** Risk signals from passive recon that triggered active scanning */
  triggeringSignals: string[];
  /** Whether WAF was detected */
  wafDetected: boolean;
}

export interface NmapScanConfig {
  target: string;
  /** Nmap flags tailored to what passive found */
  flags: string;
  /** Specific ports to focus on (from passive recon) */
  portSpec?: string;
  /** Timeout in seconds */
  timeout: number;
  /** Rationale for this specific nmap configuration */
  rationale: string;
}

export interface NucleiScanConfig {
  target: string;
  /** Template tags to use (based on detected technologies) */
  tags: string[];
  /** Severity filter */
  severityFilter: string;
  /** Whether to use DAST mode with crawling */
  dastMode: boolean;
  /** Crawl depth for DAST mode */
  crawlDepth: number;
  /** Rate limit (requests per second) */
  rateLimit: number;
  /** Whether to use headless browser */
  headless: boolean;
  /** Custom headers (e.g., for authenticated scanning) */
  customHeaders?: Record<string, string>;
  /** Rationale for this configuration */
  rationale: string;
}

export interface ZapScanConfig {
  target: string;
  /** Whether to use AJAX spider (for SPAs) */
  useAjaxSpider: boolean;
  /** Scan policy strength */
  scanStrength: "low" | "medium" | "high" | "insane";
  /** Specific scan rules to enable */
  enabledRules: number[];
  /** Authentication config if needed */
  authConfig?: {
    type: "form" | "json" | "bearer" | "basic";
    loginUrl?: string;
    credentials?: { username: string; password: string };
    bearerToken?: string;
  };
  /** Rationale */
  rationale: string;
}

export interface ActiveScanPlan {
  /** When this plan was generated */
  generatedAt: Date;
  /** Total targets to scan */
  totalTargets: number;
  /** Targets sorted by priority */
  targets: ActiveScanTarget[];
  /** Nmap scan configs per target */
  nmapConfigs: NmapScanConfig[];
  /** Nuclei scan configs per target */
  nucleiConfigs: NucleiScanConfig[];
  /** ZAP scan configs (only for web application targets) */
  zapConfigs: ZapScanConfig[];
  /** Assets that were excluded by RoE */
  excludedByRoE: { hostname: string; reason: string }[];
  /** Summary statistics */
  stats: {
    totalPassiveObservations: number;
    targetsInScope: number;
    targetsExcluded: number;
    estimatedScanDuration: string;
    riskCoverage: number; // % of high-risk assets covered
  };
  /** Provenance records: which passive finding triggered which scan */
  provenance: HandoffProvenance[];
}

export interface HandoffProvenance {
  /** The passive observation that triggered this scan */
  passiveObservationId: string;
  /** What was observed */
  passiveSignal: string;
  /** The active scan tool selected */
  activeTool: "nmap" | "nuclei" | "zap" | "dast";
  /** The target being scanned */
  target: string;
  /** Why this passive finding requires active verification */
  rationale: string;
}

// ─── Technology → Nuclei Tag Mapping ───────────────────────────────

const TECH_TO_NUCLEI_TAGS: Record<string, string[]> = {
  // Web servers
  "apache": ["apache", "cve", "misconfig"],
  "nginx": ["nginx", "cve", "misconfig"],
  "iis": ["iis", "cve", "misconfig"],
  "tomcat": ["tomcat", "cve", "default-login"],
  "jetty": ["jetty", "cve"],
  // Frameworks
  "wordpress": ["wordpress", "wp-plugin", "cve"],
  "drupal": ["drupal", "cve"],
  "joomla": ["joomla", "cve"],
  "laravel": ["laravel", "cve"],
  "django": ["django", "cve"],
  "spring": ["spring", "springboot", "cve"],
  "struts": ["struts", "cve"],
  "rails": ["rails", "cve"],
  "express": ["express", "nodejs", "cve"],
  "nextjs": ["nextjs", "cve"],
  "react": ["react", "cve"],
  "angular": ["angular", "cve"],
  "vue": ["vue", "cve"],
  // CMS / Platforms
  "sharepoint": ["sharepoint", "cve"],
  "confluence": ["confluence", "cve"],
  "jira": ["jira", "cve"],
  "gitlab": ["gitlab", "cve"],
  "jenkins": ["jenkins", "cve", "default-login"],
  "grafana": ["grafana", "cve", "default-login"],
  "kibana": ["kibana", "cve"],
  "elasticsearch": ["elasticsearch", "cve", "misconfig"],
  // Languages
  "php": ["php", "cve"],
  "java": ["java", "cve", "log4j"],
  "python": ["python", "cve"],
  "dotnet": ["dotnet", "cve"],
  // Databases
  "mysql": ["mysql", "cve", "default-login"],
  "postgresql": ["postgresql", "cve"],
  "mongodb": ["mongodb", "cve", "misconfig"],
  "redis": ["redis", "cve", "misconfig"],
  "mssql": ["mssql", "cve", "default-login"],
  // Cloud / Infrastructure
  "aws": ["aws", "cloud", "misconfig"],
  "azure": ["azure", "cloud", "misconfig"],
  "gcp": ["gcp", "cloud", "misconfig"],
  "docker": ["docker", "cve", "misconfig"],
  "kubernetes": ["kubernetes", "cve", "misconfig"],
  // Security
  "cloudflare": ["cloudflare", "waf"],
  "fortinet": ["fortinet", "cve"],
  "paloalto": ["paloalto", "cve"],
  "citrix": ["citrix", "cve"],
  "f5": ["f5", "bigip", "cve"],
  // Mail
  "exchange": ["exchange", "cve"],
  "zimbra": ["zimbra", "cve"],
};

// ─── Core Handoff Logic ────────────────────────────────────────────

/**
 * Check if a hostname/IP is within the Rules of Engagement scope.
 */
function isInScope(target: string, roe: RulesOfEngagement): { inScope: boolean; reason?: string } {
  // Check explicit exclusions first
  if (roe.excludedAssets.some(e => target.includes(e) || e.includes(target))) {
    return { inScope: false, reason: `Explicitly excluded by RoE: ${target}` };
  }

  // Check exclusion patterns
  if (roe.exclusionPatterns) {
    for (const pattern of roe.exclusionPatterns) {
      try {
        if (new RegExp(pattern, "i").test(target)) {
          return { inScope: false, reason: `Matches exclusion pattern: ${pattern}` };
        }
      } catch {
        // Invalid regex, skip
      }
    }
  }

  // Check if in scoped assets (if scoped assets are defined, only those are in scope)
  if (roe.scopedAssets.length > 0) {
    const isScoped = roe.scopedAssets.some(s => {
      // Exact match
      if (s === target) return true;
      // Wildcard subdomain match (e.g., *.example.com)
      if (s.startsWith("*.") && target.endsWith(s.slice(1))) return true;
      // Parent domain match
      if (target.endsWith(`.${s}`)) return true;
      return false;
    });
    if (!isScoped) {
      return { inScope: false, reason: `Not in RoE scoped assets list` };
    }
  }

  return { inScope: true };
}

/**
 * Compute a priority score for an asset based on passive recon findings.
 * Higher score = scan first.
 */
function computeAssetPriority(
  hostname: string,
  observations: AssetObservation[],
  riskSignals: Array<{ severity: string; rationale: string }>,
): number {
  let score = 50; // Base score

  // Risk signal severity boost
  for (const signal of riskSignals) {
    switch (signal.severity) {
      case "critical": score += 15; break;
      case "high": score += 10; break;
      case "medium": score += 5; break;
      case "low": score += 2; break;
    }
  }

  // Observation count boost (more observations = more attack surface)
  score += Math.min(20, observations.length * 2);

  // Technology diversity boost (more tech = more potential vulns)
  const techTags = new Set<string>();
  for (const obs of observations) {
    for (const tag of obs.tags) {
      if (tag.startsWith("tech:")) techTags.add(tag);
    }
  }
  score += Math.min(10, techTags.size * 2);

  // Open ports boost
  const portTags = observations.filter(o => o.tags.some(t => t.startsWith("port:")));
  score += Math.min(10, portTags.length);

  // Cap at 100
  return Math.min(100, score);
}

/**
 * Determine Nmap scan flags based on passive recon findings.
 */
function generateNmapConfig(target: ActiveScanTarget, roe: RulesOfEngagement): NmapScanConfig {
  const flags: string[] = [];
  const rationale: string[] = [];

  // Base flags
  flags.push("-sV"); // Service version detection
  flags.push("-sC"); // Default scripts

  // Intensity-based timing
  const timing = Math.min(roe.maxIntensity, 4);
  flags.push(`-T${timing}`);

  // If we know specific ports from passive, focus on those + common extras
  if (target.knownPorts.length > 0) {
    const knownPortNums = target.knownPorts.map(p => p.port);
    // Add common ports that passive might have missed
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443];
    const allPorts = [...new Set([...knownPortNums, ...commonPorts])].sort((a, b) => a - b);
    flags.push(`-p ${allPorts.join(",")}`);
    rationale.push(`Targeting ${knownPortNums.length} known ports + ${commonPorts.length} common ports`);
  } else {
    flags.push("--top-ports 1000");
    rationale.push("No ports from passive recon; scanning top 1000");
  }

  // OS detection if intensity allows
  if (roe.maxIntensity >= 3) {
    flags.push("-O");
    rationale.push("OS detection enabled (intensity >= 3)");
  }

  // Vulnerability scripts if intensity allows
  if (roe.maxIntensity >= 4) {
    flags.push("--script=vuln");
    rationale.push("Vulnerability scripts enabled (intensity >= 4)");
  }

  return {
    target: target.hostname,
    flags: flags.join(" "),
    portSpec: target.knownPorts.length > 0 ? target.knownPorts.map(p => p.port).join(",") : undefined,
    timeout: 300,
    rationale: rationale.join("; "),
  };
}

/**
 * Generate Nuclei scan config based on detected technologies.
 */
function generateNucleiConfig(target: ActiveScanTarget, roe: RulesOfEngagement): NucleiScanConfig {
  const tags = new Set<string>(["cve"]);
  const rationale: string[] = [];

  // Map detected technologies to nuclei tags
  for (const tech of target.technologies) {
    const techLower = tech.toLowerCase();
    for (const [key, nucleiTags] of Object.entries(TECH_TO_NUCLEI_TAGS)) {
      if (techLower.includes(key)) {
        for (const tag of nucleiTags) tags.add(tag);
        rationale.push(`${tech} detected → adding ${nucleiTags.join(", ")} templates`);
      }
    }
  }

  // Always include common vulnerability tags
  tags.add("sqli");
  tags.add("xss");
  tags.add("lfi");
  tags.add("rce");
  tags.add("ssrf");
  tags.add("ssti");
  tags.add("crlf");
  tags.add("traversal");

  // If WAF detected, add WAF bypass tags
  if (target.wafDetected) {
    tags.add("waf");
    rationale.push("WAF detected — including bypass templates");
  }

  // Determine DAST mode based on technology (SPAs need crawling)
  const isSPA = target.technologies.some(t =>
    /react|angular|vue|nextjs|nuxt|svelte|ember/i.test(t)
  );
  const dastMode = isSPA && roe.maxIntensity >= 3;
  if (dastMode) {
    rationale.push("SPA detected — enabling DAST mode with headless crawling");
  }

  // Rate limit based on intensity
  const rateLimit = roe.maxIntensity >= 4 ? 100 : roe.maxIntensity >= 3 ? 50 : 25;

  return {
    target: target.hostname,
    tags: Array.from(tags),
    severityFilter: "critical,high,medium",
    dastMode,
    crawlDepth: dastMode ? 3 : 0,
    rateLimit,
    headless: dastMode,
    rationale: rationale.length > 0 ? rationale.join("; ") : "Standard vulnerability scan with common templates",
  };
}

/**
 * Generate ZAP scan config for web application targets.
 */
function generateZapConfig(target: ActiveScanTarget, roe: RulesOfEngagement): ZapScanConfig | null {
  // Only generate ZAP config for web application targets
  const hasWebPorts = target.knownPorts.some(p =>
    [80, 443, 8080, 8443, 3000, 5000, 8000, 8888].includes(p.port)
  );
  const hasWebTech = target.technologies.some(t =>
    /apache|nginx|iis|wordpress|drupal|laravel|django|spring|express|react|angular|vue|nextjs/i.test(t)
  );

  if (!hasWebPorts && !hasWebTech) return null;

  const isSPA = target.technologies.some(t =>
    /react|angular|vue|nextjs|nuxt|svelte/i.test(t)
  );

  // Map intensity to scan strength
  const strengthMap: Record<number, ZapScanConfig["scanStrength"]> = {
    1: "low",
    2: "medium",
    3: "high",
    4: "insane",
    5: "insane",
  };

  return {
    target: target.hostname,
    useAjaxSpider: isSPA,
    scanStrength: strengthMap[roe.maxIntensity] || "medium",
    enabledRules: [], // Will be populated by ZAP scanner based on tech
    rationale: `Web application detected (${isSPA ? "SPA" : "traditional"}). ${target.wafDetected ? "WAF present — using evasion techniques." : ""}`,
  };
}

// ─── Main Handoff Function ─────────────────────────────────────────

/**
 * Generate an active scan plan from passive reconnaissance results.
 *
 * This is the core handoff function that bridges passive → active.
 * It should ONLY be called for Engagement scans with RoE, NOT for
 * Domain Intelligence scans from the Operations Dashboard.
 *
 * @param passiveResults - All observations from passive recon
 * @param riskSignals - Risk signals classified from observations
 * @param technologies - Technologies detected per hostname
 * @param roe - Rules of Engagement for the engagement
 * @returns ActiveScanPlan with tool-specific configs
 */
export function generateActiveScanPlan(
  passiveResults: {
    observations: AssetObservation[];
    riskSignals: Array<{ severity: string; rationale: string; assetId?: string; type?: string }>;
    technologies: Record<string, string[]>;
    services: Array<{ hostname: string; port: number; service: string; version: string }>;
    wafDetected?: Record<string, boolean>;
  },
  roe: RulesOfEngagement,
): ActiveScanPlan {
  const provenance: HandoffProvenance[] = [];
  const excludedByRoE: { hostname: string; reason: string }[] = [];

  // ─── Step 1: Extract unique targets from observations ────────────
  const targetMap = new Map<string, {
    observations: AssetObservation[];
    signals: Array<{ severity: string; rationale: string }>;
    technologies: string[];
    ports: { port: number; service: string; version: string }[];
    wafDetected: boolean;
  }>();

  for (const obs of passiveResults.observations) {
    const hostname = obs.name || obs.domain || "";
    if (!hostname) continue;

    if (!targetMap.has(hostname)) {
      targetMap.set(hostname, {
        observations: [],
        signals: [],
        technologies: passiveResults.technologies[hostname] || [],
        ports: passiveResults.services
          .filter(s => s.hostname === hostname)
          .map(s => ({ port: s.port, service: s.service, version: s.version })),
        wafDetected: passiveResults.wafDetected?.[hostname] || false,
      });
    }
    targetMap.get(hostname)!.observations.push(obs);
  }

  // Add risk signals to their respective targets
  for (const signal of passiveResults.riskSignals) {
    const assetId = signal.assetId || "";
    for (const [hostname, data] of targetMap) {
      if (assetId.includes(hostname) || hostname.includes(assetId)) {
        data.signals.push(signal);
      }
    }
  }

  // ─── Step 2: Filter by RoE scope ────────────────────────────────
  const targets: ActiveScanTarget[] = [];

  for (const [hostname, data] of targetMap) {
    const scopeCheck = isInScope(hostname, roe);
    if (!scopeCheck.inScope) {
      excludedByRoE.push({ hostname, reason: scopeCheck.reason || "Out of scope" });
      continue;
    }

    const priority = computeAssetPriority(hostname, data.observations, data.signals);
    const triggeringSignals = data.signals.map(s => s.rationale).slice(0, 5);

    targets.push({
      hostname,
      ip: data.observations.find(o => o.ip)?.ip,
      priority,
      rationale: `${data.signals.length} risk signals, ${data.observations.length} observations, ${data.technologies.length} technologies detected`,
      technologies: data.technologies,
      knownPorts: data.ports,
      triggeringSignals,
      wafDetected: data.wafDetected,
    });
  }

  // Sort by priority (highest first)
  targets.sort((a, b) => b.priority - a.priority);

  // ─── Step 3: Generate tool-specific configs ─────────────────────
  const nmapConfigs: NmapScanConfig[] = [];
  const nucleiConfigs: NucleiScanConfig[] = [];
  const zapConfigs: ZapScanConfig[] = [];

  for (const target of targets) {
    // Nmap config
    if (roe.allowedScanTypes.includes("nmap")) {
      nmapConfigs.push(generateNmapConfig(target, roe));
      // Provenance: link passive port observations to nmap scan
      for (const port of target.knownPorts) {
        provenance.push({
          passiveObservationId: `port-${target.hostname}-${port.port}`,
          passiveSignal: `Port ${port.port}/${port.service} detected via passive recon`,
          activeTool: "nmap",
          target: target.hostname,
          rationale: `Verify service version and check for vulnerabilities on port ${port.port}`,
        });
      }
    }

    // Nuclei config
    if (roe.allowedScanTypes.includes("nuclei")) {
      nucleiConfigs.push(generateNucleiConfig(target, roe));
      // Provenance: link technology detections to nuclei scan
      for (const tech of target.technologies.slice(0, 3)) {
        provenance.push({
          passiveObservationId: `tech-${target.hostname}-${tech}`,
          passiveSignal: `Technology "${tech}" detected via passive recon`,
          activeTool: "nuclei",
          target: target.hostname,
          rationale: `Run ${tech}-specific vulnerability templates`,
        });
      }
    }

    // ZAP config (only for web apps)
    if (roe.allowedScanTypes.includes("zap")) {
      const zapConfig = generateZapConfig(target, roe);
      if (zapConfig) {
        zapConfigs.push(zapConfig);
        provenance.push({
          passiveObservationId: `webapp-${target.hostname}`,
          passiveSignal: `Web application detected at ${target.hostname}`,
          activeTool: "zap",
          target: target.hostname,
          rationale: `Deep web application scan with ${zapConfig.useAjaxSpider ? "AJAX spider (SPA)" : "traditional spider"}`,
        });
      }
    }
  }

  // ─── Step 4: Estimate scan duration ─────────────────────────────
  const nmapMinutes = nmapConfigs.length * 5;
  const nucleiMinutes = nucleiConfigs.length * 3;
  const zapMinutes = zapConfigs.length * 15;
  const totalMinutes = nmapMinutes + nucleiMinutes + zapMinutes;
  const estimatedDuration = totalMinutes < 60
    ? `${totalMinutes} minutes`
    : `${Math.round(totalMinutes / 60 * 10) / 10} hours`;

  // ─── Step 5: Compute risk coverage ──────────────────────────────
  const highRiskSignals = passiveResults.riskSignals.filter(s =>
    s.severity === "critical" || s.severity === "high"
  );
  const coveredHighRisk = highRiskSignals.filter(s => {
    const assetId = s.assetId || "";
    return targets.some(t => assetId.includes(t.hostname) || t.hostname.includes(assetId));
  });
  const riskCoverage = highRiskSignals.length > 0
    ? Math.round((coveredHighRisk.length / highRiskSignals.length) * 100)
    : 100;

  return {
    generatedAt: new Date(),
    totalTargets: targets.length,
    targets,
    nmapConfigs,
    nucleiConfigs,
    zapConfigs,
    excludedByRoE,
    stats: {
      totalPassiveObservations: passiveResults.observations.length,
      targetsInScope: targets.length,
      targetsExcluded: excludedByRoE.length,
      estimatedScanDuration: estimatedDuration,
      riskCoverage,
    },
    provenance,
  };
}

/**
 * Build a default RoE from engagement data.
 * Used when the engagement doesn't have explicit RoE configured.
 */
export function buildDefaultRoE(
  targetDomains: string[],
  engagementType: string,
  options?: {
    excludedAssets?: string[];
    maxIntensity?: number;
    allowedTools?: string[];
  },
): RulesOfEngagement {
  return {
    scopedAssets: targetDomains,
    excludedAssets: options?.excludedAssets || [],
    allowedScanTypes: (options?.allowedTools as RulesOfEngagement["allowedScanTypes"]) || ["nmap", "nuclei", "zap", "dast"],
    maxIntensity: options?.maxIntensity || (engagementType === "red_team" ? 4 : 3),
    socialEngineeringAllowed: engagementType === "red_team",
    dosTestingAllowed: false,
    maxConcurrentScans: 3,
  };
}

/**
 * Format an active scan plan as a human-readable summary for logging.
 */
export function formatScanPlanSummary(plan: ActiveScanPlan): string {
  const lines: string[] = [];
  lines.push(`Active Scan Plan — ${plan.totalTargets} targets`);
  lines.push(`Generated: ${plan.generatedAt.toISOString()}`);
  lines.push(`Estimated duration: ${plan.stats.estimatedScanDuration}`);
  lines.push(`Risk coverage: ${plan.stats.riskCoverage}%`);
  lines.push("");
  lines.push("Targets (by priority):");
  for (const t of plan.targets.slice(0, 10)) {
    lines.push(`  [${t.priority}] ${t.hostname} — ${t.technologies.slice(0, 3).join(", ") || "unknown tech"} — ${t.knownPorts.length} ports — ${t.triggeringSignals.length} signals`);
  }
  if (plan.targets.length > 10) {
    lines.push(`  ... and ${plan.targets.length - 10} more`);
  }
  if (plan.excludedByRoE.length > 0) {
    lines.push("");
    lines.push(`Excluded by RoE: ${plan.excludedByRoE.length} targets`);
    for (const e of plan.excludedByRoE.slice(0, 5)) {
      lines.push(`  - ${e.hostname}: ${e.reason}`);
    }
  }
  lines.push("");
  lines.push(`Scan configs: ${plan.nmapConfigs.length} nmap, ${plan.nucleiConfigs.length} nuclei, ${plan.zapConfigs.length} ZAP`);
  lines.push(`Provenance records: ${plan.provenance.length}`);
  return lines.join("\n");
}
