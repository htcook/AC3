/**
 * Scan Profiles — Operator-selectable presets that control scan depth, speed, evasion, and tool selection.
 *
 * Shannon-inspired: Let operators choose the right balance of speed vs depth for each engagement.
 *
 * Profiles:
 *   - Quick:    Fast recon + top-100 ports + critical vulns only. ~5-10 min per asset.
 *   - Standard: Full recon + top-1000 ports + all severity levels. ~15-30 min per asset.
 *   - Deep:     Exhaustive recon + all 65535 ports + all templates + brute force. ~45-90 min per asset.
 *   - Stealth:  Slow timing + fragmentation + decoys + minimal fingerprinting. ~30-60 min per asset.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type ScanProfileName = "quick" | "standard" | "deep" | "stealth";

export interface ScanProfile {
  name: ScanProfileName;
  displayName: string;
  description: string;
  estimatedTimePerAsset: string;

  // ScanForge configuration
  discovery: {
    /** Port range for discovery scan */
    discoveryPorts: string;
    /** Port range for targeted scan */
    targetedPorts: string;
    /** Timing template (T0-T5) */
    timing: string;
    /** Additional discovery flags */
    extraFlags: string[];
    /** Enable OS detection */
    osDetection: boolean;
    /** Enable script scanning */
    scriptScan: boolean;
    /** Service version detection intensity (0-9) */
    versionIntensity: number;
  };

  // Nuclei configuration
  nuclei: {
    /** Severity levels to scan for */
    severityFilter: string;
    /** Max templates to load (0 = unlimited) */
    maxTemplates: number;
    /** Rate limit (requests per second) */
    rateLimit: number;
    /** Timeout per template in seconds */
    templateTimeout: number;
    /** Additional nuclei flags */
    extraFlags: string[];
  };

  // Tool selection
  tools: {
    /** Run nikto web scanner */
    nikto: boolean;
    /** Run gobuster directory brute-force */
    gobuster: boolean;
    /** Run httpx HTTP probing */
    httpx: boolean;
    /** Run ZAP active scan */
    zap: boolean;
    /** Run hydra brute-force */
    hydra: boolean;
    /** Max concurrent tools per asset */
    concurrency: number;
  };

  // Timeouts
  timeouts: {
    /** Per-tool timeout in seconds */
    toolTimeout: number;
    /** Nuclei-specific timeout in seconds */
    nucleiTimeout: number;
    /** ZAP scan timeout in seconds */
    zapTimeout: number;
    /** Overall phase timeout in seconds (0 = unlimited) */
    phaseTimeout: number;
  };

  // Evasion
  evasion: {
    /** Use packet fragmentation */
    fragmentation: boolean;
    /** Use decoy IPs */
    decoys: boolean;
    /** Randomize host scan order */
    randomizeHosts: boolean;
    /** Add data length padding */
    dataLengthPadding: boolean;
    /** Spoof source port */
    sourcePortSpoofing: boolean;
    /** Delay between requests (ms) */
    requestDelay: number;
  };

  // Gobuster configuration
  gobuster: {
    /** Wordlist path */
    wordlist: string;
    /** Number of threads */
    threads: number;
    /** File extensions to enumerate (empty = none) */
    extensions: string;
    /** Follow redirects */
    followRedirects: boolean;
    /** Use random user-agent */
    randomAgent: boolean;
    /** Status codes to exclude (empty = default Gobuster behavior) */
    excludeStatusCodes: string;
    /** HTTP method (GET, POST, PUT, etc.) — empty = default GET */
    httpMethod: string;
    /** Pass authenticated cookies when available */
    useAuthCookies: boolean;
    /** Additional flags */
    extraFlags: string[];
  };
}

// ─── Profile Definitions ────────────────────────────────────────────────────

export const SCAN_PROFILES: Record<ScanProfileName, ScanProfile> = {
  quick: {
    name: "quick",
    displayName: "Quick Scan",
    description: "Fast reconnaissance with top-100 ports and critical/high vulnerabilities only. Best for initial triage or time-sensitive assessments.",
    estimatedTimePerAsset: "5-10 minutes",
    discovery: {
      discoveryPorts: "--top-ports 100",
      targetedPorts: "--top-ports 100",
      timing: "-T4",
      extraFlags: ["-sV", "--version-intensity", "5"],
      osDetection: false,
      scriptScan: false,
      versionIntensity: 5,
    },
    nuclei: {
      severityFilter: "critical,high",
      maxTemplates: 500,
      rateLimit: 150,
      templateTimeout: 8,
      extraFlags: ["-duc", "-ni", "-nc"],
    },
    tools: {
      nikto: false,
      gobuster: false,
      httpx: true,
      zap: false,
      hydra: false,
      concurrency: 4,
    },
    timeouts: {
      toolTimeout: 120,
      nucleiTimeout: 180,
      zapTimeout: 0,
      phaseTimeout: 600,
    },
    evasion: {
      fragmentation: false,
      decoys: false,
      randomizeHosts: false,
      dataLengthPadding: false,
      sourcePortSpoofing: false,
      requestDelay: 0,
    },
    gobuster: {
      wordlist: "/opt/SecLists/Discovery/Web-Content/common.txt",
      threads: 50,
      extensions: "",
      followRedirects: false,
      randomAgent: false,
      excludeStatusCodes: "",
      httpMethod: "",
      useAuthCookies: false,
      extraFlags: ["-q", "--no-error"],
    },
  },

  standard: {
    name: "standard",
    displayName: "Standard Scan",
    description: "Comprehensive scan with top-1000 ports, all severity levels, and full tool suite. The default for most engagements.",
    estimatedTimePerAsset: "15-30 minutes",
    discovery: {
      discoveryPorts: "--top-ports 1000",
      targetedPorts: "--top-ports 1000",
      timing: "-T3",
      extraFlags: ["-sV", "-sC", "--version-intensity", "7"],
      osDetection: true,
      scriptScan: true,
      versionIntensity: 7,
    },
    nuclei: {
      severityFilter: "critical,high,medium",
      maxTemplates: 0,
      rateLimit: 100,
      templateTimeout: 10,
      extraFlags: ["-duc", "-ni", "-nc", "-jsonl"],
    },
    tools: {
      nikto: true,
      gobuster: true,
      httpx: true,
      zap: true,
      hydra: false,
      concurrency: 3,
    },
    timeouts: {
      toolTimeout: 180,
      nucleiTimeout: 300,
      zapTimeout: 300,
      phaseTimeout: 1800,
    },
    evasion: {
      fragmentation: false,
      decoys: false,
      randomizeHosts: true,
      dataLengthPadding: false,
      sourcePortSpoofing: false,
      requestDelay: 0,
    },
    gobuster: {
      wordlist: "/opt/SecLists/Discovery/Web-Content/common.txt",
      threads: 30,
      extensions: "php,html,js,txt,bak,env,conf",
      followRedirects: true,
      randomAgent: true,
      excludeStatusCodes: "",
      httpMethod: "",
      useAuthCookies: true,
      extraFlags: ["-q", "--no-error"],
    },
  },

  deep: {
    name: "deep",
    displayName: "Deep Scan",
    description: "Exhaustive scan of all 65535 ports with all nuclei templates, directory brute-force, and credential testing. For thorough assessments with no time pressure.",
    estimatedTimePerAsset: "45-90 minutes",
    discovery: {
      discoveryPorts: "-p-",
      targetedPorts: "-p-",
      timing: "-T3",
      extraFlags: ["-sV", "-sC", "-O", "--version-intensity", "9", "-A"],
      osDetection: true,
      scriptScan: true,
      versionIntensity: 9,
    },
    nuclei: {
      severityFilter: "critical,high,medium,low",
      maxTemplates: 0,
      rateLimit: 75,
      templateTimeout: 15,
      extraFlags: ["-duc", "-ni", "-nc", "-jsonl"],
    },
    tools: {
      nikto: true,
      gobuster: true,
      httpx: true,
      zap: true,
      hydra: true,
      concurrency: 3,
    },
    timeouts: {
      toolTimeout: 300,
      nucleiTimeout: 600,
      zapTimeout: 600,
      phaseTimeout: 3600,
    },
    evasion: {
      fragmentation: false,
      decoys: false,
      randomizeHosts: true,
      dataLengthPadding: false,
      sourcePortSpoofing: false,
      requestDelay: 0,
    },
    gobuster: {
      wordlist: "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
      threads: 20,
      extensions: "php,html,js,txt,bak,old,conf,env,swp,zip,tar.gz,sql,xml,json,yml,yaml,log",
      followRedirects: true,
      randomAgent: true,
      excludeStatusCodes: "",
      httpMethod: "",
      useAuthCookies: true,
      extraFlags: ["-q", "--no-error"],
    },
  },

  stealth: {
    name: "stealth",
    displayName: "Stealth Scan",
    description: "Low-and-slow scanning with maximum evasion techniques. Fragmentation, decoys, timing delays, and randomization to avoid detection by IDS/IPS/WAF.",
    estimatedTimePerAsset: "30-60 minutes",
    discovery: {
      discoveryPorts: "--top-ports 1000",
      targetedPorts: "--top-ports 1000",
      timing: "-T1",
      extraFlags: [
        "-sV", "--version-intensity", "5",
        "-f", "--mtu", "24",
        "-D", "RND:5",
        "--data-length", "50",
        "--randomize-hosts",
        "-g", "53",
      ],
      osDetection: false,
      scriptScan: false,
      versionIntensity: 5,
    },
    nuclei: {
      severityFilter: "critical,high,medium",
      maxTemplates: 0,
      rateLimit: 25,
      templateTimeout: 15,
      extraFlags: ["-duc", "-ni", "-nc", "-jsonl", "-rl", "25"],
    },
    tools: {
      nikto: true,
      gobuster: false, // Too noisy for stealth
      httpx: true,
      zap: false, // Too noisy for stealth
      hydra: false, // Too noisy for stealth
      concurrency: 2,
    },
    timeouts: {
      toolTimeout: 300,
      nucleiTimeout: 600,
      zapTimeout: 0,
      phaseTimeout: 3600,
    },
    evasion: {
      fragmentation: true,
      decoys: true,
      randomizeHosts: true,
      dataLengthPadding: true,
      sourcePortSpoofing: true,
      requestDelay: 500,
    },
    gobuster: {
      wordlist: "/opt/SecLists/Discovery/Web-Content/common.txt",
      threads: 5,
      extensions: "",
      followRedirects: false,
      randomAgent: true,
      excludeStatusCodes: "",
      httpMethod: "",
      useAuthCookies: false,
      extraFlags: ["-q", "--no-error", "--delay", "500ms"],
    },
  },
};

// ─── Helper Functions ───────────────────────────────────────────────────────

/**
 * Get a scan profile by name, defaulting to "standard" if not found.
 */
export function getScanProfile(name?: string): ScanProfile {
  if (name && name in SCAN_PROFILES) {
    return SCAN_PROFILES[name as ScanProfileName];
  }
  return SCAN_PROFILES.standard;
}

/**
 * Get all available scan profiles for display in the UI.
 */
export function getAllScanProfiles(): Array<{
  name: ScanProfileName;
  displayName: string;
  description: string;
  estimatedTimePerAsset: string;
}> {
  return Object.values(SCAN_PROFILES).map(p => ({
    name: p.name,
    displayName: p.displayName,
    description: p.description,
    estimatedTimePerAsset: p.estimatedTimePerAsset,
  }));
}

/**
 * Build discovery flags from a scan profile for discovery phase.
 */
export function buildDiscoveryScanForgeFlags(profile: ScanProfile, target: string): string {
  const flags = [
    profile.discovery.discoveryPorts,
    profile.discovery.timing,
    "-sV",
    "--version-intensity", String(profile.discovery.versionIntensity),
  ];

  if (profile.discovery.osDetection) flags.push("-O");
  if (profile.discovery.scriptScan) flags.push("-sC");

  // Evasion flags
  if (profile.evasion.fragmentation) flags.push("-f", "--mtu", "24");
  if (profile.evasion.decoys) flags.push("-D", "RND:5");
  if (profile.evasion.dataLengthPadding) flags.push("--data-length", "50");
  if (profile.evasion.randomizeHosts) flags.push("--randomize-hosts");
  if (profile.evasion.sourcePortSpoofing) flags.push("-g", "53");

  flags.push(target);
  return flags.join(" ");
}

/**
 * Build nuclei flags from a scan profile.
 */
export function buildNucleiFlags(profile: ScanProfile, targetUrl: string): string {
  const flags = [
    "-u", targetUrl,
    "-severity", profile.nuclei.severityFilter,
    "-rl", String(profile.nuclei.rateLimit),
    "-timeout", String(profile.nuclei.templateTimeout),
    "-retries", "1",
    ...profile.nuclei.extraFlags,
  ];

  return `nuclei ${flags.join(" ")}`;
}

/**
 * Get the list of tools to run for a given profile.
 */
export function getProfileTools(profile: ScanProfile): string[] {
  const tools: string[] = [];
  if (profile.tools.httpx) tools.push("httpx");
  if (profile.tools.nikto) tools.push("nikto");
  if (profile.tools.gobuster) tools.push("gobuster");
  // nuclei is always included
  tools.push("nuclei");
  return tools;
}

/**
 * Build a complete Gobuster command from profile config + runtime context.
 *
 * @param profile - The active scan profile
 * @param targetUrl - The target URL to scan
 * @param options - Runtime options (WAF detection, auth cookies, detected tech)
 * @returns The full gobuster command string ready for execution
 */
export function buildGobusterCommand(
  profile: ScanProfile,
  targetUrl: string,
  options: {
    wafDetected?: boolean;
    authCookie?: string;
    detectedTech?: string[];
    isApiTarget?: boolean;
  } = {}
): string {
  const cfg = profile.gobuster;
  const flags: string[] = ["gobuster", "dir", "-u", targetUrl];

  // Wordlist
  flags.push("-w", cfg.wordlist);

  // Threads — adaptive: reduce if WAF detected
  const threads = options.wafDetected ? Math.min(cfg.threads, 10) : cfg.threads;
  flags.push("-t", String(threads));

  // Extensions — profile-defined or tech-adaptive
  let extensions = cfg.extensions;
  if (!extensions && options.detectedTech?.length) {
    // Auto-detect extensions based on technology stack
    const techExtMap: Record<string, string> = {
      php: "php,phtml,php5,php7",
      asp: "asp,aspx,ashx,asmx",
      java: "jsp,jsf,do,action",
      python: "py,pyc",
      ruby: "rb,erb",
      node: "js,json,ts",
    };
    const techExts: string[] = [];
    for (const tech of options.detectedTech) {
      const key = tech.toLowerCase();
      for (const [pattern, exts] of Object.entries(techExtMap)) {
        if (key.includes(pattern)) techExts.push(exts);
      }
    }
    if (techExts.length) extensions = [...new Set(techExts.join(",").split(","))].join(",");
  }
  if (extensions) flags.push("-x", extensions);

  // Follow redirects
  if (cfg.followRedirects) flags.push("-r");

  // Random user-agent
  if (cfg.randomAgent) flags.push("--random-agent");

  // Status code exclusion — adaptive for WAF
  let excludeCodes = cfg.excludeStatusCodes;
  if (!excludeCodes && options.wafDetected) {
    // WAF often returns 403 for everything — exclude to reduce noise
    excludeCodes = "403";
  }
  if (excludeCodes) flags.push("-b", excludeCodes);

  // HTTP method — use POST/PUT for API targets
  const method = options.isApiTarget ? (cfg.httpMethod || "GET,POST") : cfg.httpMethod;
  if (method) flags.push("-m", method);

  // Authenticated scanning — pass cookies when available and profile allows
  if (cfg.useAuthCookies && options.authCookie) {
    flags.push("-c", options.authCookie);
  }

  // Delay for WAF evasion (even if profile doesn't specify, add 200ms when WAF detected)
  if (options.wafDetected && !cfg.extraFlags.some(f => f.includes("--delay"))) {
    flags.push("--delay", "200ms");
  }

  // Extra flags from profile
  flags.push(...cfg.extraFlags);

  return flags.join(" ");
}
