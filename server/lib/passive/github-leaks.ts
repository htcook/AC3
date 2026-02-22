/**
 * GitHub Code Leak Connector — Red Team Discovery Priority #10
 * ─────────────────────────────────────────────────────────────
 * Searches GitHub's public code search API for leaked credentials,
 * configuration files, internal IPs, API keys, and architecture
 * diagrams associated with a target domain.
 *
 * Covers: T1593.003 (Search Open Technical Databases: Code Repositories)
 *         T1596.004 (Search Open Technical Databases: CDN)
 *
 * Method: GitHub Code Search API (authenticated, rate-limited)
 * Data Source: Public GitHub repositories
 * Requires: GitHub personal access token (optional, but recommended
 *           for higher rate limits — 30 req/min vs 10 req/min)
 */

import { createHash } from "crypto";
import type {
  AssetObservation,
  ConnectorConfig,
  ConnectorResult,
  PassiveConnector,
} from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256")
    .update(`${domain}|${name}|${source}`)
    .digest("hex")
    .slice(0, 20);
}

// ═══════════════════════════════════════════════════════════════════════
// §1 — SEARCH PATTERNS
// ═══════════════════════════════════════════════════════════════════════

/** Categories of code leaks to search for */
interface LeakPattern {
  id: string;
  name: string;
  description: string;
  /** GitHub code search query template — {{domain}} is replaced */
  queryTemplate: string;
  /** Severity of findings in this category */
  severity: "critical" | "high" | "medium" | "low";
  /** Tags to apply to observations */
  tags: string[];
}

const LEAK_PATTERNS: LeakPattern[] = [
  // ── Credential Leaks ──────────────────────────────────────────────
  {
    id: "env_files",
    name: "Environment Files (.env)",
    description: "Exposed .env files with API keys, database credentials, and secrets",
    queryTemplate: "{{domain}} filename:.env",
    severity: "critical",
    tags: ["code_leak", "env_file", "credential", "config_leak"],
  },
  {
    id: "api_keys",
    name: "API Keys & Tokens",
    description: "Hardcoded API keys, access tokens, and secret keys in source code",
    queryTemplate: "{{domain}} API_KEY OR api_key OR apikey OR secret_key OR access_token",
    severity: "critical",
    tags: ["code_leak", "api_key_leak", "credential"],
  },
  {
    id: "passwords",
    name: "Hardcoded Passwords",
    description: "Passwords embedded in configuration files or source code",
    queryTemplate: "{{domain}} password OR passwd OR pwd NOT example NOT test",
    severity: "critical",
    tags: ["code_leak", "credential", "password"],
  },
  // ── Configuration Leaks ───────────────────────────────────────────
  {
    id: "config_files",
    name: "Configuration Files",
    description: "Exposed config files (YAML, JSON, XML) with internal settings",
    queryTemplate: "{{domain}} filename:config.yml OR filename:config.json OR filename:settings.py",
    severity: "high",
    tags: ["code_leak", "config_leak"],
  },
  {
    id: "docker_compose",
    name: "Docker Compose / Infrastructure",
    description: "Docker Compose files revealing service architecture and internal ports",
    queryTemplate: "{{domain}} filename:docker-compose.yml OR filename:Dockerfile",
    severity: "high",
    tags: ["code_leak", "config_leak", "infrastructure"],
  },
  {
    id: "terraform",
    name: "Terraform / IaC Files",
    description: "Infrastructure-as-Code files exposing cloud architecture",
    queryTemplate: "{{domain}} filename:.tf OR filename:terraform.tfvars",
    severity: "high",
    tags: ["code_leak", "config_leak", "infrastructure", "cloud"],
  },
  // ── Network & Architecture ────────────────────────────────────────
  {
    id: "internal_ips",
    name: "Internal IP Addresses",
    description: "References to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x)",
    queryTemplate: "{{domain}} \"10.\" OR \"172.16\" OR \"192.168\" filename:.conf OR filename:.cfg",
    severity: "medium",
    tags: ["code_leak", "internal_ip", "network"],
  },
  {
    id: "database_strings",
    name: "Database Connection Strings",
    description: "Exposed database URIs with host, port, and credential information",
    queryTemplate: "{{domain}} \"mongodb://\" OR \"mysql://\" OR \"postgresql://\" OR \"redis://\"",
    severity: "critical",
    tags: ["code_leak", "credential", "database"],
  },
  // ── SSH & Certificates ────────────────────────────────────────────
  {
    id: "ssh_keys",
    name: "SSH Private Keys",
    description: "Exposed SSH private keys that could grant server access",
    queryTemplate: "{{domain}} \"BEGIN RSA PRIVATE KEY\" OR \"BEGIN OPENSSH PRIVATE KEY\"",
    severity: "critical",
    tags: ["code_leak", "credential", "ssh_key"],
  },
  {
    id: "ssl_certs",
    name: "SSL/TLS Certificates & Keys",
    description: "Exposed SSL certificates and private keys",
    queryTemplate: "{{domain}} \"BEGIN CERTIFICATE\" filename:.pem OR filename:.key",
    severity: "high",
    tags: ["code_leak", "credential", "certificate"],
  },
  // ── CI/CD & Deployment ────────────────────────────────────────────
  {
    id: "ci_cd",
    name: "CI/CD Pipeline Configs",
    description: "GitHub Actions, Jenkins, GitLab CI configs with deployment secrets",
    queryTemplate: "{{domain}} filename:.github/workflows OR filename:Jenkinsfile OR filename:.gitlab-ci.yml",
    severity: "medium",
    tags: ["code_leak", "config_leak", "ci_cd"],
  },
  {
    id: "aws_credentials",
    name: "AWS Credentials",
    description: "AWS access key IDs and secret access keys",
    queryTemplate: "{{domain}} AKIA OR aws_access_key_id OR aws_secret_access_key",
    severity: "critical",
    tags: ["code_leak", "credential", "cloud", "aws"],
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §2 — GITHUB API CLIENT
// ═══════════════════════════════════════════════════════════════════════

interface GitHubSearchResult {
  total_count: number;
  incomplete_results: boolean;
  items: GitHubCodeItem[];
}

interface GitHubCodeItem {
  name: string;
  path: string;
  sha: string;
  url: string;
  html_url: string;
  repository: {
    id: number;
    name: string;
    full_name: string;
    html_url: string;
    description: string | null;
    private: boolean;
    fork: boolean;
    stargazers_count: number;
    updated_at: string;
    owner: {
      login: string;
      type: string;
    };
  };
  score: number;
  text_matches?: Array<{
    fragment: string;
    matches: Array<{ text: string; indices: number[] }>;
  }>;
}

async function searchGitHubCode(
  query: string,
  token?: string,
  timeout = 10000
): Promise<GitHubSearchResult | null> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.text-match+json",
    "User-Agent": "Caldera-Dashboard-OSINT/1.0",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30&sort=indexed&order=desc`;

  try {
    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(timeout),
    });

    if (response.status === 403) {
      // Rate limited
      const resetHeader = response.headers.get("X-RateLimit-Reset");
      const resetTime = resetHeader ? new Date(parseInt(resetHeader) * 1000).toISOString() : "unknown";
      throw new Error(`GitHub rate limit exceeded. Resets at ${resetTime}`);
    }

    if (response.status === 422) {
      // Validation error (query too complex)
      return { total_count: 0, incomplete_results: false, items: [] };
    }

    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      throw new Error(`GitHub search timed out after ${timeout}ms`);
    }
    throw err;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — OBSERVATION BUILDER
// ═══════════════════════════════════════════════════════════════════════

function buildObservation(
  domain: string,
  pattern: LeakPattern,
  item: GitHubCodeItem,
  now: Date
): AssetObservation {
  const repoFullName = item.repository.full_name;
  const filePath = item.path;
  const textSnippet =
    item.text_matches?.[0]?.fragment?.slice(0, 200) || "";

  return {
    assetId: makeAssetId(domain, `github:${repoFullName}:${filePath}`, "github_leaks"),
    domain,
    assetType: "url",
    name: `[${pattern.name}] ${repoFullName}/${filePath}`,
    source: "github_leaks",
    observedAt: now,
    lastSeen: item.repository.updated_at
      ? new Date(item.repository.updated_at)
      : now,
    tags: [
      "github",
      ...pattern.tags,
      `severity:${pattern.severity}`,
      item.repository.fork ? "forked_repo" : "original_repo",
      ...(item.repository.stargazers_count > 100 ? ["popular_repo"] : []),
    ],
    evidence: {
      patternId: pattern.id,
      patternName: pattern.name,
      severity: pattern.severity,
      repository: repoFullName,
      repoUrl: item.repository.html_url,
      repoDescription: item.repository.description,
      repoStars: item.repository.stargazers_count,
      repoOwner: item.repository.owner.login,
      repoOwnerType: item.repository.owner.type,
      filePath,
      fileUrl: item.html_url,
      textSnippet,
      isFork: item.repository.fork,
      lastUpdated: item.repository.updated_at,
    },
    attribution: {
      provider: "GitHub Code Search API",
      method: `Searched GitHub public code for "${pattern.name}" patterns referencing ${domain}`,
      url: item.html_url,
      verifyUrl: item.html_url,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — CONNECTOR EXPORT
// ═══════════════════════════════════════════════════════════════════════

export const githubLeaksConnector: PassiveConnector = {
  name: "github_leaks",
  description:
    "GitHub code leak scanner — searches public repositories for exposed credentials, configuration files, API keys, and infrastructure details (Red Team Priority #10)",
  requiresApiKey: false, // Works without token, but rate-limited
  freeUrl: "https://github.com/search",

  async collect(
    domain: string,
    config?: ConnectorConfig
  ): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 10000;
    const token = config?.apiKey;
    const now = new Date();
    const maxResults = config?.maxResults ?? 30;

    // Rate-limit: GitHub allows ~10 req/min unauthenticated, ~30 authenticated
    // We search a subset of patterns to stay within limits
    const patternsToSearch = LEAK_PATTERNS.slice(0, 8); // Top 8 most critical

    const seenRepoFiles = new Set<string>();

    for (const pattern of patternsToSearch) {
      const query = pattern.queryTemplate.replace("{{domain}}", domain);

      try {
        // Delay between requests to respect rate limits
        if (patternsToSearch.indexOf(pattern) > 0) {
          await new Promise((r) => setTimeout(r, 2200)); // ~2.2s between requests
        }

        const result = await searchGitHubCode(query, token, timeout);
        if (!result) continue;

        for (const item of result.items) {
          // Deduplicate by repo + file path
          const key = `${item.repository.full_name}:${item.path}`;
          if (seenRepoFiles.has(key)) continue;
          seenRepoFiles.add(key);

          // Skip forks of the target's own repos (usually not leaks)
          if (
            item.repository.owner.login.toLowerCase() ===
            domain.split(".")[0].toLowerCase()
          ) {
            continue;
          }

          observations.push(buildObservation(domain, pattern, item, now));

          if (observations.length >= maxResults) break;
        }

        if (observations.length >= maxResults) break;
      } catch (err: any) {
        errors.push(`[${pattern.id}] ${err.message}`);
        // If rate-limited, stop searching
        if (err.message.includes("rate limit")) break;
      }
    }

    return {
      connector: "github_leaks",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: errors.some((e) => e.includes("rate limit")),
    };
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §5 — STANDALONE ANALYSIS FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** Severity score mapping */
const SEVERITY_SCORES: Record<string, number> = {
  critical: 90,
  high: 70,
  medium: 50,
  low: 25,
};

/** Summarize GitHub leak findings for the UI */
export function summarizeGitHubLeaks(observations: AssetObservation[]) {
  const bySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const byCategory: Record<string, number> = {};
  const uniqueRepos = new Set<string>();
  const uniqueOwners = new Set<string>();

  for (const obs of observations) {
    const severity = obs.evidence?.severity || "low";
    bySeverity[severity] = (bySeverity[severity] || 0) + 1;

    const patternName = obs.evidence?.patternName || "Unknown";
    byCategory[patternName] = (byCategory[patternName] || 0) + 1;

    if (obs.evidence?.repository) {
      uniqueRepos.add(obs.evidence.repository);
    }
    if (obs.evidence?.repoOwner) {
      uniqueOwners.add(obs.evidence.repoOwner);
    }
  }

  // Risk score (0-100)
  let riskScore = 0;
  for (const [sev, count] of Object.entries(bySeverity)) {
    riskScore += (SEVERITY_SCORES[sev] || 0) * count;
  }
  riskScore = Math.min(100, Math.round(riskScore / Math.max(observations.length, 1)));

  return {
    totalFindings: observations.length,
    bySeverity,
    byCategory,
    uniqueRepos: uniqueRepos.size,
    uniqueOwners: uniqueOwners.size,
    riskScore,
    riskBand:
      riskScore >= 80
        ? "critical"
        : riskScore >= 60
          ? "high"
          : riskScore >= 40
            ? "medium"
            : "low",
  };
}

/** Get all available leak patterns (for UI display) */
export function getLeakPatterns() {
  return LEAK_PATTERNS.map((p) => ({
    id: p.id,
    name: p.name,
    description: p.description,
    severity: p.severity,
    tags: p.tags,
  }));
}
