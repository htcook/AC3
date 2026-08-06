/**
 * Tool Adapter Architecture
 *
 * Provides a swappable integration layer for security tools. Instead of hardcoding
 * tool-specific commands throughout the orchestrator, adapters normalize the interface
 * so tools can be swapped (e.g., gobuster ↔ ffuf, nmap ↔ masscan) without changing
 * orchestration logic.
 *
 * Also includes the Wordlist Intelligence Module for context-aware wordlist selection.
 */

// ─── Tool Adapter Interface ─────────────────────────────────────────────────

export type ToolCategory =
  | "directory_bruteforce"
  | "subdomain_enum"
  | "port_scan"
  | "vuln_scan"
  | "xss_scan"
  | "ssrf_scan"
  | "brute_force"
  | "web_crawl"
  | "dns_enum"
  | "takeover_check"
  | "fuzzer";

export interface ToolCapability {
  category: ToolCategory;
  /** Whether this tool supports authenticated scanning */
  supportsAuth: boolean;
  /** Whether this tool supports proxy routing */
  supportsProxy: boolean;
  /** Whether this tool supports JSON output */
  supportsJsonOutput: boolean;
  /** Whether this tool supports rate limiting */
  supportsRateLimit: boolean;
  /** Whether this tool supports custom headers */
  supportsCustomHeaders: boolean;
  /** Whether this tool supports recursive scanning */
  supportsRecursive: boolean;
  /** Relative speed: 1 (slow) to 10 (fast) */
  speedRating: number;
  /** Relative accuracy: 1 (noisy) to 10 (precise) */
  accuracyRating: number;
  /** Relative stealth: 1 (loud) to 10 (quiet) */
  stealthRating: number;
}

export interface ToolAdapterConfig {
  target: string;
  threads?: number;
  timeout?: number;
  rateLimit?: number;
  proxy?: string;
  authCookie?: string;
  customHeaders?: Record<string, string>;
  outputFormat?: "json" | "text" | "csv";
  wordlist?: string;
  extensions?: string[];
  recursive?: boolean;
  /** Scan profile intensity */
  intensity?: "quick" | "standard" | "deep" | "stealth";
}

export interface ToolAdapterResult {
  command: string;
  estimatedDuration: string;
  resourceUsage: "low" | "medium" | "high";
  noiseLevel: "quiet" | "moderate" | "loud";
}

export interface ToolAdapter {
  name: string;
  version: string;
  capabilities: ToolCapability;
  /** Build the command for this tool given the config */
  buildCommand(config: ToolAdapterConfig): ToolAdapterResult;
  /** Parse raw output into normalized findings */
  parseOutput(rawOutput: string): NormalizedFinding[];
  /** Check if this tool is available on the system */
  isAvailable(): boolean;
}

export interface NormalizedFinding {
  type: "path" | "subdomain" | "port" | "vulnerability" | "credential" | "parameter";
  value: string;
  status?: number;
  size?: number;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  metadata?: Record<string, unknown>;
}

// ─── Concrete Adapters ──────────────────────────────────────────────────────

export class GobusterAdapter implements ToolAdapter {
  name = "gobuster";
  version = "3.6";
  capabilities: ToolCapability = {
    category: "directory_bruteforce",
    supportsAuth: true,
    supportsProxy: true,
    supportsJsonOutput: false,
    supportsRateLimit: true,
    supportsCustomHeaders: true,
    supportsRecursive: false,
    speedRating: 7,
    accuracyRating: 7,
    stealthRating: 4,
  };

  buildCommand(config: ToolAdapterConfig): ToolAdapterResult {
    const parts = ["gobuster", "dir", "-u", config.target];

    parts.push("-w", config.wordlist || "/usr/share/wordlists/dirb/common.txt");

    if (config.threads) parts.push("-t", String(config.threads));
    if (config.timeout) parts.push("--timeout", `${config.timeout}s`);
    if (config.rateLimit) parts.push("--delay", `${Math.floor(1000 / config.rateLimit)}ms`);
    if (config.proxy) parts.push("--proxy", config.proxy);
    if (config.authCookie) parts.push("-c", config.authCookie);
    if (config.extensions?.length) parts.push("-x", config.extensions.join(","));
    if (config.customHeaders) {
      for (const [k, v] of Object.entries(config.customHeaders)) {
        parts.push("-H", `${k}: ${v}`);
      }
    }

    parts.push("-s", "200,204,301,302,307,401,403");
    parts.push("--no-error");

    const intensity = config.intensity || "standard";
    const estimatedDuration = intensity === "quick" ? "1-3 min" : intensity === "standard" ? "5-15 min" : intensity === "deep" ? "15-45 min" : "30-90 min";
    const noiseLevel = intensity === "stealth" ? "quiet" : intensity === "quick" ? "moderate" : "loud";

    return {
      command: parts.join(" "),
      estimatedDuration,
      resourceUsage: intensity === "deep" ? "high" : "medium",
      noiseLevel,
    };
  }

  parseOutput(rawOutput: string): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const lines = rawOutput.split("\n");

    for (const line of lines) {
      const match = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]/);
      if (match) {
        const [, path, statusStr, sizeStr] = match;
        const status = parseInt(statusStr, 10);
        const size = parseInt(sizeStr, 10);

        findings.push({
          type: "path",
          value: path,
          status,
          size,
          severity: classifyPathSeverity(path, status),
          confidence: status === 200 ? 0.95 : status === 403 ? 0.7 : 0.6,
        });
      }
    }

    return findings;
  }

  isAvailable(): boolean {
    return true; // Assume available on scan server
  }
}

export class FfufAdapter implements ToolAdapter {
  name = "ffuf";
  version = "2.1";
  capabilities: ToolCapability = {
    category: "directory_bruteforce",
    supportsAuth: true,
    supportsProxy: true,
    supportsJsonOutput: true,
    supportsRateLimit: true,
    supportsCustomHeaders: true,
    supportsRecursive: true,
    speedRating: 9,
    accuracyRating: 8,
    stealthRating: 5,
  };

  buildCommand(config: ToolAdapterConfig): ToolAdapterResult {
    const parts = ["ffuf", "-u", `${config.target}/FUZZ`];

    parts.push("-w", config.wordlist || "/usr/share/wordlists/dirb/common.txt");

    if (config.threads) parts.push("-t", String(config.threads));
    if (config.timeout) parts.push("-timeout", String(config.timeout));
    if (config.rateLimit) parts.push("-rate", String(config.rateLimit));
    if (config.proxy) parts.push("-x", config.proxy);
    if (config.authCookie) parts.push("-b", config.authCookie);
    if (config.recursive) parts.push("-recursion", "-recursion-depth", "2");
    if (config.extensions?.length) parts.push("-e", config.extensions.join(","));
    if (config.customHeaders) {
      for (const [k, v] of Object.entries(config.customHeaders)) {
        parts.push("-H", `${k}: ${v}`);
      }
    }

    parts.push("-mc", "200,204,301,302,307,401,403");
    parts.push("-ac"); // Auto-calibrate filtering
    parts.push("-o", "/tmp/ffuf-output.json", "-of", "json");

    const intensity = config.intensity || "standard";
    const estimatedDuration = intensity === "quick" ? "30s-2 min" : intensity === "standard" ? "3-10 min" : intensity === "deep" ? "10-30 min" : "20-60 min";

    return {
      command: parts.join(" "),
      estimatedDuration,
      resourceUsage: intensity === "deep" ? "high" : "medium",
      noiseLevel: intensity === "stealth" ? "quiet" : "moderate",
    };
  }

  parseOutput(rawOutput: string): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];

    try {
      const data = JSON.parse(rawOutput);
      const results = data.results || [];

      for (const r of results) {
        findings.push({
          type: "path",
          value: r.input?.FUZZ || r.url || "",
          status: r.status,
          size: r.length,
          severity: classifyPathSeverity(r.input?.FUZZ || "", r.status),
          confidence: r.status === 200 ? 0.95 : 0.7,
          metadata: { words: r.words, lines: r.lines, redirectlocation: r.redirectlocation },
        });
      }
    } catch {
      // Fall back to line-based parsing
      const lines = rawOutput.split("\n");
      for (const line of lines) {
        const match = line.match(/(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)/);
        if (match) {
          findings.push({
            type: "path",
            value: match[1],
            status: parseInt(match[2], 10),
            size: parseInt(match[3], 10),
            severity: "info",
            confidence: 0.8,
          });
        }
      }
    }

    return findings;
  }

  isAvailable(): boolean {
    return true;
  }
}

export class KatanaAdapter implements ToolAdapter {
  name = "katana";
  version = "1.0";
  capabilities: ToolCapability = {
    category: "web_crawl",
    supportsAuth: true,
    supportsProxy: true,
    supportsJsonOutput: true,
    supportsRateLimit: true,
    supportsCustomHeaders: true,
    supportsRecursive: true,
    speedRating: 8,
    accuracyRating: 9,
    stealthRating: 6,
  };

  buildCommand(config: ToolAdapterConfig): ToolAdapterResult {
    const parts = ["katana", "-u", config.target];

    if (config.threads) parts.push("-c", String(config.threads));
    if (config.timeout) parts.push("-timeout", String(config.timeout));
    if (config.rateLimit) parts.push("-rl", String(config.rateLimit));
    if (config.proxy) parts.push("-proxy", config.proxy);
    if (config.authCookie) parts.push("-H", `Cookie: ${config.authCookie}`);
    if (config.customHeaders) {
      for (const [k, v] of Object.entries(config.customHeaders)) {
        parts.push("-H", `${k}: ${v}`);
      }
    }

    const depth = config.intensity === "quick" ? "2" : config.intensity === "deep" ? "5" : "3";
    parts.push("-d", depth);
    parts.push("-jc"); // JavaScript crawling
    parts.push("-jsonl");

    const estimatedDuration = config.intensity === "quick" ? "1-3 min" : config.intensity === "deep" ? "10-30 min" : "3-10 min";

    return {
      command: parts.join(" "),
      estimatedDuration,
      resourceUsage: config.intensity === "deep" ? "high" : "medium",
      noiseLevel: "moderate",
    };
  }

  parseOutput(rawOutput: string): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const lines = rawOutput.split("\n").filter(Boolean);

    for (const line of lines) {
      try {
        const data = JSON.parse(line);
        findings.push({
          type: "path",
          value: data.request?.endpoint || data.url || line,
          status: data.response?.status_code,
          severity: "info",
          confidence: 0.9,
          metadata: { source: data.source, method: data.request?.method },
        });
      } catch {
        if (line.startsWith("http")) {
          findings.push({
            type: "path",
            value: line.trim(),
            severity: "info",
            confidence: 0.8,
          });
        }
      }
    }

    return findings;
  }

  isAvailable(): boolean {
    return true;
  }
}

export class DalfoxAdapter implements ToolAdapter {
  name = "dalfox";
  version = "2.9";
  capabilities: ToolCapability = {
    category: "xss_scan",
    supportsAuth: true,
    supportsProxy: true,
    supportsJsonOutput: true,
    supportsRateLimit: true,
    supportsCustomHeaders: true,
    supportsRecursive: false,
    speedRating: 7,
    accuracyRating: 9,
    stealthRating: 3,
  };

  buildCommand(config: ToolAdapterConfig): ToolAdapterResult {
    const parts = ["dalfox", "url", config.target];

    if (config.proxy) parts.push("--proxy", config.proxy);
    if (config.authCookie) parts.push("-C", config.authCookie);
    if (config.customHeaders) {
      for (const [k, v] of Object.entries(config.customHeaders)) {
        parts.push("-H", `${k}: ${v}`);
      }
    }
    if (config.rateLimit) parts.push("--delay", String(Math.floor(1000 / config.rateLimit)));

    parts.push("--silence", "--format", "json");

    if (config.intensity === "deep") {
      parts.push("--deep-domxss", "--follow-redirects", "--mining-dict");
    } else if (config.intensity === "stealth") {
      parts.push("--delay", "500", "--only-discovery");
    }

    return {
      command: parts.join(" "),
      estimatedDuration: config.intensity === "deep" ? "10-30 min" : "3-10 min",
      resourceUsage: "medium",
      noiseLevel: config.intensity === "stealth" ? "quiet" : "loud",
    };
  }

  parseOutput(rawOutput: string): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];

    try {
      const data = JSON.parse(rawOutput);
      const results = Array.isArray(data) ? data : data.results || [];

      for (const r of results) {
        findings.push({
          type: "vulnerability",
          value: r.data || r.payload || "",
          severity: r.severity === "High" ? "high" : r.severity === "Medium" ? "medium" : "low",
          confidence: r.type === "Verified" ? 0.95 : 0.7,
          metadata: {
            param: r.param,
            type: r.type,
            poc: r.poc_type,
            cwe: "CWE-79",
          },
        });
      }
    } catch {
      // Line-based fallback
      const lines = rawOutput.split("\n");
      for (const line of lines) {
        if (line.includes("[POC]") || line.includes("[V]")) {
          findings.push({
            type: "vulnerability",
            value: line.trim(),
            severity: "high",
            confidence: 0.85,
            metadata: { cwe: "CWE-79" },
          });
        }
      }
    }

    return findings;
  }

  isAvailable(): boolean {
    return true;
  }
}

// ─── Tool Registry ──────────────────────────────────────────────────────────

const ADAPTER_REGISTRY: Map<string, ToolAdapter> = new Map();

export function registerAdapter(adapter: ToolAdapter): void {
  ADAPTER_REGISTRY.set(adapter.name, adapter);
}

export function getAdapter(name: string): ToolAdapter | undefined {
  return ADAPTER_REGISTRY.get(name);
}

export function getAdaptersForCategory(category: ToolCategory): ToolAdapter[] {
  return Array.from(ADAPTER_REGISTRY.values()).filter(
    (a) => a.capabilities.category === category
  );
}

/**
 * Select the best adapter for a category based on requirements
 */
export function selectBestAdapter(
  category: ToolCategory,
  requirements: {
    needsAuth?: boolean;
    needsJson?: boolean;
    needsStealth?: boolean;
    needsSpeed?: boolean;
    needsAccuracy?: boolean;
  }
): ToolAdapter | undefined {
  const adapters = getAdaptersForCategory(category);
  if (adapters.length === 0) return undefined;

  let bestScore = -1;
  let bestAdapter: ToolAdapter | undefined;

  for (const adapter of adapters) {
    let score = 0;
    const cap = adapter.capabilities;

    if (requirements.needsAuth && !cap.supportsAuth) continue;
    if (requirements.needsJson && !cap.supportsJsonOutput) continue;

    if (requirements.needsStealth) score += cap.stealthRating * 2;
    if (requirements.needsSpeed) score += cap.speedRating * 2;
    if (requirements.needsAccuracy) score += cap.accuracyRating * 2;

    // Default balanced scoring
    score += cap.speedRating + cap.accuracyRating + cap.stealthRating;

    if (score > bestScore) {
      bestScore = score;
      bestAdapter = adapter;
    }
  }

  return bestAdapter;
}

// Register default adapters
registerAdapter(new GobusterAdapter());
registerAdapter(new FfufAdapter());
registerAdapter(new KatanaAdapter());
registerAdapter(new DalfoxAdapter());

// ─── Wordlist Intelligence Module ───────────────────────────────────────────

export interface WordlistProfile {
  name: string;
  path: string;
  description: string;
  entryCount: number;
  /** What this wordlist is best for */
  bestFor: string[];
  /** Technologies this wordlist targets */
  techTargets: string[];
  /** Estimated scan time multiplier (1.0 = baseline) */
  timeMultiplier: number;
}

export const WORDLIST_PROFILES: Record<string, WordlistProfile> = {
  // General purpose
  common: {
    name: "Common",
    path: "/usr/share/wordlists/dirb/common.txt",
    description: "Standard common paths — good baseline for quick scans",
    entryCount: 4614,
    bestFor: ["quick_scan", "initial_recon"],
    techTargets: ["generic"],
    timeMultiplier: 1.0,
  },
  big: {
    name: "Big",
    path: "/usr/share/wordlists/dirb/big.txt",
    description: "Extended common paths — standard scan depth",
    entryCount: 20469,
    bestFor: ["standard_scan", "thorough_recon"],
    techTargets: ["generic"],
    timeMultiplier: 4.4,
  },
  directory_list_medium: {
    name: "Directory List Medium",
    path: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    description: "DirBuster medium list — comprehensive directory enumeration",
    entryCount: 220560,
    bestFor: ["deep_scan", "comprehensive_enum"],
    techTargets: ["generic"],
    timeMultiplier: 47.8,
  },

  // Technology-specific
  raft_files: {
    name: "RAFT Files",
    path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    description: "RAFT file names — catches common files across technologies",
    entryCount: 17129,
    bestFor: ["file_discovery", "sensitive_file_hunt"],
    techTargets: ["generic"],
    timeMultiplier: 3.7,
  },
  api_endpoints: {
    name: "API Endpoints",
    path: "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    description: "Common API endpoint patterns for REST/GraphQL APIs",
    entryCount: 12500,
    bestFor: ["api_enum", "api_discovery"],
    techTargets: ["api", "rest", "graphql"],
    timeMultiplier: 2.7,
  },
  php_files: {
    name: "PHP Files",
    path: "/usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt",
    description: "Common PHP filenames and admin panels",
    entryCount: 5163,
    bestFor: ["php_enum", "admin_panel_hunt"],
    techTargets: ["php", "wordpress", "drupal", "joomla"],
    timeMultiplier: 1.1,
  },
  asp_files: {
    name: "ASP/ASPX Files",
    path: "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt",
    description: "IIS/ASP.NET specific paths and files",
    entryCount: 4200,
    bestFor: ["iis_enum", "dotnet_enum"],
    techTargets: ["iis", "aspnet", "dotnet"],
    timeMultiplier: 0.9,
  },
  java_paths: {
    name: "Java/Tomcat Paths",
    path: "/usr/share/seclists/Discovery/Web-Content/tomcat.txt",
    description: "Tomcat/Java specific paths including manager and status endpoints",
    entryCount: 1500,
    bestFor: ["java_enum", "tomcat_enum"],
    techTargets: ["java", "tomcat", "spring", "struts"],
    timeMultiplier: 0.3,
  },
  wordpress: {
    name: "WordPress",
    path: "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    description: "WordPress-specific paths including plugins, themes, and admin",
    entryCount: 7500,
    bestFor: ["wordpress_enum", "cms_enum"],
    techTargets: ["wordpress"],
    timeMultiplier: 1.6,
  },
  spring_boot: {
    name: "Spring Boot Actuator",
    path: "/usr/share/seclists/Discovery/Web-Content/spring-boot.txt",
    description: "Spring Boot actuator endpoints and common Spring paths",
    entryCount: 800,
    bestFor: ["spring_enum", "actuator_discovery"],
    techTargets: ["spring", "spring-boot", "java"],
    timeMultiplier: 0.2,
  },

  // Specialized
  backup_files: {
    name: "Backup Files",
    path: "/usr/share/seclists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt",
    description: "Common backup, config, and sensitive file patterns",
    entryCount: 3500,
    bestFor: ["sensitive_file_hunt", "backup_discovery"],
    techTargets: ["generic"],
    timeMultiplier: 0.8,
  },
  git_exposed: {
    name: "Git Exposure",
    path: "/usr/share/seclists/Discovery/Web-Content/source-code-management.txt",
    description: "Source code management exposure patterns (.git, .svn, .hg)",
    entryCount: 250,
    bestFor: ["source_code_exposure", "scm_discovery"],
    techTargets: ["generic"],
    timeMultiplier: 0.05,
  },

  // Subdomain wordlists
  subdomains_top: {
    name: "Subdomains Top",
    path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    description: "Top 5000 most common subdomains",
    entryCount: 5000,
    bestFor: ["quick_subdomain_enum"],
    techTargets: ["dns"],
    timeMultiplier: 1.0,
  },
  subdomains_full: {
    name: "Subdomains Full",
    path: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    description: "Top 110K subdomains — thorough enumeration",
    entryCount: 114532,
    bestFor: ["deep_subdomain_enum"],
    techTargets: ["dns"],
    timeMultiplier: 22.9,
  },

  // Credential wordlists
  passwords_common: {
    name: "Common Passwords",
    path: "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    description: "Top 1000 most common passwords",
    entryCount: 1000,
    bestFor: ["quick_brute", "password_spray"],
    techTargets: ["auth"],
    timeMultiplier: 0.2,
  },
  usernames_common: {
    name: "Common Usernames",
    path: "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    description: "Top common usernames for brute force",
    entryCount: 17,
    bestFor: ["username_enum", "brute_force"],
    techTargets: ["auth"],
    timeMultiplier: 0.01,
  },
};

/**
 * Select optimal wordlists based on detected technology and scan intensity
 */
export function selectWordlists(context: {
  technologies: string[];
  scanType: "directory" | "subdomain" | "credential";
  intensity: "quick" | "standard" | "deep";
  maxTimeMinutes?: number;
}): WordlistProfile[] {
  const selected: WordlistProfile[] = [];
  const profiles = Object.values(WORDLIST_PROFILES);

  // Filter by scan type
  let candidates: WordlistProfile[];
  if (context.scanType === "subdomain") {
    candidates = profiles.filter((p) => p.techTargets.includes("dns"));
  } else if (context.scanType === "credential") {
    candidates = profiles.filter((p) => p.techTargets.includes("auth"));
  } else {
    candidates = profiles.filter((p) => !p.techTargets.includes("dns") && !p.techTargets.includes("auth"));
  }

  // Always include a baseline wordlist
  if (context.scanType === "directory") {
    const baseline = context.intensity === "quick" ? "common" : context.intensity === "standard" ? "big" : "directory_list_medium";
    const baselineProfile = WORDLIST_PROFILES[baseline];
    if (baselineProfile) selected.push(baselineProfile);
  } else if (context.scanType === "subdomain") {
    const baseline = context.intensity === "deep" ? "subdomains_full" : "subdomains_top";
    const baselineProfile = WORDLIST_PROFILES[baseline];
    if (baselineProfile) selected.push(baselineProfile);
  } else {
    const baselineProfile = WORDLIST_PROFILES["passwords_common"];
    if (baselineProfile) selected.push(baselineProfile);
    const usernameProfile = WORDLIST_PROFILES["usernames_common"];
    if (usernameProfile) selected.push(usernameProfile);
  }

  // Add technology-specific wordlists
  const techLower = context.technologies.map((t) => t.toLowerCase());

  for (const profile of candidates) {
    if (selected.includes(profile)) continue;

    const matchesTech = profile.techTargets.some((target) =>
      techLower.some((tech) => tech.includes(target) || target.includes(tech))
    );

    if (matchesTech) {
      selected.push(profile);
    }
  }

  // Add specialized wordlists for deeper scans
  if (context.intensity !== "quick" && context.scanType === "directory") {
    const gitProfile = WORDLIST_PROFILES["git_exposed"];
    if (gitProfile && !selected.includes(gitProfile)) selected.push(gitProfile);

    if (context.intensity === "deep") {
      const raftProfile = WORDLIST_PROFILES["raft_files"];
      if (raftProfile && !selected.includes(raftProfile)) selected.push(raftProfile);
      const backupProfile = WORDLIST_PROFILES["backup_files"];
      if (backupProfile && !selected.includes(backupProfile)) selected.push(backupProfile);
    }
  }

  // Filter by time budget if specified
  if (context.maxTimeMinutes) {
    const baseTime = 5; // minutes per baseline scan
    let totalTime = 0;
    return selected.filter((profile) => {
      const estimatedTime = baseTime * profile.timeMultiplier;
      if (totalTime + estimatedTime <= context.maxTimeMinutes!) {
        totalTime += estimatedTime;
        return true;
      }
      return false;
    });
  }

  return selected;
}

/**
 * Build a combined wordlist strategy for the LLM scan planner
 */
export function buildWordlistStrategy(context: {
  technologies: string[];
  intensity: "quick" | "standard" | "deep";
  targetType: "web_app" | "api" | "cms" | "infrastructure";
}): string {
  const dirWordlists = selectWordlists({
    technologies: context.technologies,
    scanType: "directory",
    intensity: context.intensity,
  });

  const subWordlists = selectWordlists({
    technologies: context.technologies,
    scanType: "subdomain",
    intensity: context.intensity,
  });

  const sections: string[] = [];

  sections.push("## Wordlist Strategy\n");
  sections.push(`**Target Type:** ${context.targetType}`);
  sections.push(`**Intensity:** ${context.intensity}`);
  sections.push(`**Detected Tech:** ${context.technologies.join(", ") || "generic"}\n`);

  sections.push("### Directory Enumeration Wordlists");
  for (const wl of dirWordlists) {
    sections.push(`- **${wl.name}** (${wl.entryCount.toLocaleString()} entries, ~${(5 * wl.timeMultiplier).toFixed(1)} min)`);
    sections.push(`  ${wl.description}`);
  }

  sections.push("\n### Subdomain Enumeration Wordlists");
  for (const wl of subWordlists) {
    sections.push(`- **${wl.name}** (${wl.entryCount.toLocaleString()} entries)`);
    sections.push(`  ${wl.description}`);
  }

  return sections.join("\n");
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function classifyPathSeverity(path: string, status: number): "critical" | "high" | "medium" | "low" | "info" {
  const pathLower = path.toLowerCase();

  // Critical: admin panels, config files, backups
  if (/\.(env|bak|sql|dump|tar\.gz|zip)$/i.test(pathLower)) return "critical";
  if (/\/(admin|manager|phpmyadmin|wp-admin|console)\b/.test(pathLower)) return "high";
  if (/\/(\.git|\.svn|\.hg|\.env|web\.config|wp-config)/.test(pathLower)) return "critical";

  // High: server status, debug endpoints
  if (/\/(server-status|server-info|debug|trace|actuator)/.test(pathLower)) return "high";
  if (/\/(api|graphql|swagger|openapi)/.test(pathLower)) return "medium";

  // Status-based
  if (status === 403) return "low";
  if (status === 401) return "medium";
  if (status === 500) return "medium";

  return "info";
}
