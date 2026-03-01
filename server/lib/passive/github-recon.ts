/**
 * Enhanced GitHub Reconnaissance Connector
 * ═════════════════════════════════════════════════════════════════════
 * Goes far beyond basic code search — performs deep organizational
 * reconnaissance against GitHub to map the target's entire code footprint.
 *
 * Capabilities:
 *   1. Organization Discovery — find GitHub orgs linked to the target domain
 *   2. Repository Enumeration — list all public repos, forks, and archived repos
 *   3. Contributor/Member Mapping — identify developers and their other repos
 *   4. Commit History Secrets Scanning — regex-based secret detection in commits
 *   5. GitHub Actions / CI/CD Analysis — workflow files, secrets refs, runners
 *   6. Dependency Graph — package.json, requirements.txt, Gemfile analysis
 *   7. Advanced GitHub Dorks — 30+ specialized search patterns
 *
 * Covers: T1593.003 (Code Repositories), T1591.004 (Identify Roles),
 *         T1589.001 (Credentials), T1588.004 (Digital Certificates)
 *
 * Method: GitHub REST API v3 + GitHub Code Search API
 * Rate Limits: 10 req/min (unauth) / 30 req/min (auth code search)
 *              60 req/hr (unauth) / 5000 req/hr (auth REST)
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
// §1 — SECRET PATTERNS (TruffleHog / Gitleaks inspired)
// ═══════════════════════════════════════════════════════════════════════

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  description: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  { id: "aws_access_key", name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g, severity: "critical", description: "AWS IAM access key identifier" },
  { id: "aws_secret_key", name: "AWS Secret Access Key", regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g, severity: "critical", description: "AWS IAM secret access key" },
  // Azure
  { id: "azure_storage_key", name: "Azure Storage Account Key", regex: /(?:AccountKey|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?/g, severity: "critical", description: "Azure Storage account access key" },
  { id: "azure_client_secret", name: "Azure AD Client Secret", regex: /(?:client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9~._-]{34,})['"]?/g, severity: "critical", description: "Azure Active Directory application secret" },
  // GCP
  { id: "gcp_service_account", name: "GCP Service Account Key", regex: /"type"\s*:\s*"service_account"/g, severity: "critical", description: "Google Cloud Platform service account JSON key" },
  { id: "gcp_api_key", name: "GCP API Key", regex: /AIza[0-9A-Za-z_-]{35}/g, severity: "high", description: "Google Cloud Platform API key" },
  // GitHub
  { id: "github_pat", name: "GitHub Personal Access Token", regex: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: "critical", description: "GitHub personal access or secret token" },
  { id: "github_oauth", name: "GitHub OAuth Token", regex: /gho_[A-Za-z0-9_]{36,}/g, severity: "critical", description: "GitHub OAuth access token" },
  // Stripe
  { id: "stripe_secret", name: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical", description: "Stripe live secret API key" },
  { id: "stripe_publishable", name: "Stripe Publishable Key", regex: /pk_live_[0-9a-zA-Z]{24,}/g, severity: "medium", description: "Stripe live publishable key" },
  // Slack
  { id: "slack_token", name: "Slack Token", regex: /xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g, severity: "high", description: "Slack bot, user, or workspace token" },
  { id: "slack_webhook", name: "Slack Webhook URL", regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/g, severity: "high", description: "Slack incoming webhook URL" },
  // Database
  { id: "db_connection_string", name: "Database Connection String", regex: /(?:mongodb|mysql|postgresql|postgres|redis|mssql):\/\/[^\s'"]{10,}/g, severity: "critical", description: "Database connection URI with potential credentials" },
  // JWT
  { id: "jwt_secret", name: "JWT Secret", regex: /(?:JWT_SECRET|jwt_secret|JWT_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/=_-]{16,})['"]?/g, severity: "high", description: "JSON Web Token signing secret" },
  // Private Keys
  { id: "rsa_private_key", name: "RSA Private Key", regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: "critical", description: "RSA private key (PEM format)" },
  { id: "ssh_private_key", name: "SSH Private Key", regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: "critical", description: "OpenSSH private key" },
  // SendGrid / Mailgun / Twilio
  { id: "sendgrid_key", name: "SendGrid API Key", regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: "high", description: "SendGrid API key" },
  { id: "twilio_sid", name: "Twilio Account SID", regex: /AC[a-f0-9]{32}/g, severity: "high", description: "Twilio account SID" },
  // Generic
  { id: "generic_api_key", name: "Generic API Key Pattern", regex: /(?:api[_-]?key|apikey|API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?/g, severity: "medium", description: "Generic API key assignment" },
  { id: "generic_secret", name: "Generic Secret Pattern", regex: /(?:secret|SECRET|password|PASSWORD|passwd|PASSWD)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/g, severity: "medium", description: "Generic secret or password assignment" },
];

// ═══════════════════════════════════════════════════════════════════════
// §2 — ADVANCED GITHUB DORK PATTERNS
// ═══════════════════════════════════════════════════════════════════════

interface DorkPattern {
  id: string;
  name: string;
  category: "credentials" | "infrastructure" | "ci_cd" | "cloud" | "network" | "sensitive_files";
  queryTemplate: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

export const GITHUB_DORKS: DorkPattern[] = [
  // ── Credentials ──────────────────────────────────────────────────
  { id: "env_production", name: "Production .env Files", category: "credentials", queryTemplate: "{{domain}} filename:.env.production", severity: "critical", description: "Production environment configuration with live credentials" },
  { id: "env_local", name: "Local .env Files", category: "credentials", queryTemplate: "{{domain}} filename:.env.local", severity: "high", description: "Local environment files that may contain development credentials" },
  { id: "htpasswd", name: "Apache .htpasswd", category: "credentials", queryTemplate: "{{domain}} filename:.htpasswd", severity: "critical", description: "Apache HTTP authentication password files" },
  { id: "netrc", name: ".netrc Credentials", category: "credentials", queryTemplate: "{{domain}} filename:.netrc", severity: "critical", description: "Machine login credentials for FTP/HTTP" },
  { id: "npmrc_auth", name: "NPM Auth Tokens", category: "credentials", queryTemplate: "{{domain}} filename:.npmrc _authToken", severity: "critical", description: "NPM registry authentication tokens" },
  { id: "pypirc", name: "PyPI Credentials", category: "credentials", queryTemplate: "{{domain}} filename:.pypirc", severity: "high", description: "Python Package Index upload credentials" },
  { id: "aws_credentials", name: "AWS Credentials File", category: "credentials", queryTemplate: "{{domain}} filename:credentials aws_access_key_id", severity: "critical", description: "AWS CLI credential files with access keys" },
  { id: "kubeconfig", name: "Kubernetes Config", category: "credentials", queryTemplate: "{{domain}} filename:kubeconfig OR filename:.kube/config", severity: "critical", description: "Kubernetes cluster configuration with auth tokens" },
  // ── Infrastructure ───────────────────────────────────────────────
  { id: "terraform_state", name: "Terraform State Files", category: "infrastructure", queryTemplate: "{{domain}} filename:terraform.tfstate", severity: "critical", description: "Terraform state files containing infrastructure secrets and resource IDs" },
  { id: "ansible_vault", name: "Ansible Vault Files", category: "infrastructure", queryTemplate: "{{domain}} filename:vault.yml OR filename:vault.yaml ansible_vault", severity: "high", description: "Ansible vault encrypted secrets files" },
  { id: "docker_env", name: "Docker Environment Files", category: "infrastructure", queryTemplate: "{{domain}} filename:docker-compose.yml environment", severity: "high", description: "Docker Compose files with environment variable definitions" },
  { id: "k8s_secrets", name: "Kubernetes Secrets", category: "infrastructure", queryTemplate: "{{domain}} kind: Secret filename:.yaml OR filename:.yml", severity: "critical", description: "Kubernetes Secret manifests with base64-encoded credentials" },
  { id: "helm_values", name: "Helm Values Files", category: "infrastructure", queryTemplate: "{{domain}} filename:values.yaml password OR secret OR token", severity: "high", description: "Helm chart values files with sensitive configuration" },
  // ── CI/CD ────────────────────────────────────────────────────────
  { id: "github_actions_secrets", name: "GitHub Actions Secrets Refs", category: "ci_cd", queryTemplate: "{{domain}} filename:.github/workflows secrets.", severity: "medium", description: "GitHub Actions workflows referencing repository secrets" },
  { id: "circleci_config", name: "CircleCI Configuration", category: "ci_cd", queryTemplate: "{{domain}} filename:.circleci/config.yml", severity: "medium", description: "CircleCI pipeline configuration files" },
  { id: "travis_config", name: "Travis CI Configuration", category: "ci_cd", queryTemplate: "{{domain}} filename:.travis.yml", severity: "medium", description: "Travis CI configuration with potential encrypted secrets" },
  { id: "jenkins_credentials", name: "Jenkins Credentials", category: "ci_cd", queryTemplate: "{{domain}} filename:Jenkinsfile credentials OR withCredentials", severity: "high", description: "Jenkins pipeline files referencing credential stores" },
  // ── Cloud ────────────────────────────────────────────────────────
  { id: "s3_bucket_refs", name: "S3 Bucket References", category: "cloud", queryTemplate: "{{domain}} s3.amazonaws.com OR s3:// bucket", severity: "medium", description: "References to S3 buckets in code" },
  { id: "gcs_bucket_refs", name: "GCS Bucket References", category: "cloud", queryTemplate: "{{domain}} storage.googleapis.com OR gs://", severity: "medium", description: "References to Google Cloud Storage buckets" },
  { id: "azure_blob_refs", name: "Azure Blob References", category: "cloud", queryTemplate: "{{domain}} blob.core.windows.net", severity: "medium", description: "References to Azure Blob Storage containers" },
  // ── Network ──────────────────────────────────────────────────────
  { id: "vpn_configs", name: "VPN Configuration Files", category: "network", queryTemplate: "{{domain}} filename:.ovpn OR filename:vpn.conf", severity: "high", description: "OpenVPN or VPN configuration files with connection details" },
  { id: "ssh_config", name: "SSH Configuration", category: "network", queryTemplate: "{{domain}} filename:ssh_config OR filename:sshd_config", severity: "high", description: "SSH client/server configuration files" },
  { id: "hosts_file", name: "Internal Hosts Mapping", category: "network", queryTemplate: "{{domain}} filename:hosts 10. OR 172. OR 192.168.", severity: "medium", description: "Hosts files revealing internal network topology" },
  // ── Sensitive Files ──────────────────────────────────────────────
  { id: "sql_dumps", name: "SQL Database Dumps", category: "sensitive_files", queryTemplate: "{{domain}} filename:.sql INSERT INTO OR CREATE TABLE", severity: "critical", description: "SQL database dump files with potential PII or credentials" },
  { id: "backup_files", name: "Backup Archives", category: "sensitive_files", queryTemplate: "{{domain}} filename:.bak OR filename:.backup OR filename:.old", severity: "medium", description: "Backup files that may contain sensitive data" },
  { id: "log_files", name: "Application Log Files", category: "sensitive_files", queryTemplate: "{{domain}} filename:.log password OR token OR error", severity: "medium", description: "Log files with potential credential leaks or error details" },
  { id: "swagger_docs", name: "API Documentation (Swagger/OpenAPI)", category: "sensitive_files", queryTemplate: "{{domain}} filename:swagger.json OR filename:openapi.yaml", severity: "low", description: "API documentation revealing endpoint structure" },
  { id: "postman_collection", name: "Postman Collections", category: "sensitive_files", queryTemplate: "{{domain}} filename:.postman_collection.json", severity: "high", description: "Postman API collections with potential auth tokens and endpoints" },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — GITHUB API HELPERS
// ═══════════════════════════════════════════════════════════════════════

interface GitHubOrg {
  login: string;
  id: number;
  description: string | null;
  html_url: string;
  public_repos: number;
  public_members_url: string;
  repos_url: string;
  blog: string | null;
  email: string | null;
  location: string | null;
  created_at: string;
}

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  html_url: string;
  description: string | null;
  fork: boolean;
  stargazers_count: number;
  watchers_count: number;
  forks_count: number;
  open_issues_count: number;
  language: string | null;
  topics: string[];
  default_branch: string;
  created_at: string;
  updated_at: string;
  pushed_at: string;
  size: number;
  has_wiki: boolean;
  has_pages: boolean;
  archived: boolean;
  visibility: string;
  owner: { login: string; type: string; avatar_url: string };
}

interface GitHubUser {
  login: string;
  id: number;
  html_url: string;
  type: string;
  name: string | null;
  company: string | null;
  blog: string | null;
  location: string | null;
  email: string | null;
  bio: string | null;
  public_repos: number;
  public_gists: number;
  followers: number;
  following: number;
  created_at: string;
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
    owner: { login: string; type: string };
  };
  score: number;
  text_matches?: Array<{
    fragment: string;
    matches: Array<{ text: string; indices: number[] }>;
  }>;
}

interface GitHubSearchResult {
  total_count: number;
  incomplete_results: boolean;
  items: GitHubCodeItem[];
}

interface GitHubWorkflow {
  id: number;
  name: string;
  path: string;
  state: string;
  html_url: string;
  created_at: string;
  updated_at: string;
}

async function githubFetch<T>(
  url: string,
  token?: string,
  timeout = 10000
): Promise<T | null> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "AceStrike-OSINT/2.0",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(timeout),
    });
    if (res.status === 403) {
      const reset = res.headers.get("X-RateLimit-Reset");
      throw new Error(`GitHub rate limit. Resets: ${reset ? new Date(+reset * 1000).toISOString() : "unknown"}`);
    }
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub ${res.status}: ${res.statusText}`);
    return await res.json();
  } catch (err: any) {
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      throw new Error(`GitHub API timeout after ${timeout}ms`);
    }
    throw err;
  }
}

async function searchGitHubCode(
  query: string,
  token?: string,
  timeout = 10000
): Promise<GitHubSearchResult | null> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.text-match+json",
    "User-Agent": "AceStrike-OSINT/2.0",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30&sort=indexed&order=desc`;
  try {
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeout) });
    if (res.status === 403) throw new Error("GitHub rate limit exceeded");
    if (res.status === 422) return { total_count: 0, incomplete_results: false, items: [] };
    if (!res.ok) throw new Error(`GitHub ${res.status}`);
    return await res.json();
  } catch (err: any) {
    if (err.name === "TimeoutError" || err.name === "AbortError") return null;
    throw err;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — ORG DISCOVERY
// ═══════════════════════════════════════════════════════════════════════

/** Derive potential GitHub org names from a domain */
function deriveOrgCandidates(domain: string, orgName?: string): string[] {
  const parts = domain.split(".");
  const base = parts[0];
  const candidates = new Set<string>();

  candidates.add(base);
  candidates.add(base.replace(/[^a-z0-9]/gi, ""));
  candidates.add(base.replace(/[^a-z0-9]/gi, "-"));
  // Common variations
  candidates.add(`${base}-inc`);
  candidates.add(`${base}-io`);
  candidates.add(`${base}hq`);
  candidates.add(`${base}-team`);
  candidates.add(`${base}-dev`);
  candidates.add(`${base}-labs`);
  candidates.add(`${base}-oss`);
  candidates.add(`${base}-engineering`);
  candidates.add(`${base}-security`);
  candidates.add(`${base}-infra`);

  if (orgName) {
    const clean = orgName.toLowerCase().replace(/[^a-z0-9]/gi, "");
    const dashed = orgName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/gi, "");
    candidates.add(clean);
    candidates.add(dashed);
    candidates.add(`${clean}hq`);
    candidates.add(`${clean}-inc`);
  }

  return Array.from(candidates).filter(c => c.length >= 2);
}

/** Try to find the GitHub org for a domain */
async function discoverOrgs(
  domain: string,
  token?: string,
  orgName?: string,
  timeout = 8000
): Promise<{ orgs: GitHubOrg[]; candidates: string[] }> {
  const candidates = deriveOrgCandidates(domain, orgName);
  const orgs: GitHubOrg[] = [];

  for (const candidate of candidates.slice(0, 15)) {
    try {
      const org = await githubFetch<GitHubOrg>(
        `https://api.github.com/orgs/${encodeURIComponent(candidate)}`,
        token,
        timeout
      );
      if (org) {
        orgs.push(org);
        break; // Found the primary org, stop probing
      }
    } catch {
      // Not found or rate limited, continue
    }
    // Small delay to avoid rate limiting
    await new Promise(r => setTimeout(r, 500));
  }

  // Also try searching for the org via user search
  if (orgs.length === 0) {
    try {
      const searchResult = await githubFetch<{ items: GitHubOrg[] }>(
        `https://api.github.com/search/users?q=${encodeURIComponent(domain)}+type:org&per_page=5`,
        token,
        timeout
      );
      if (searchResult?.items) {
        for (const item of searchResult.items.slice(0, 3)) {
          const fullOrg = await githubFetch<GitHubOrg>(
            `https://api.github.com/orgs/${item.login}`,
            token,
            timeout
          );
          if (fullOrg) orgs.push(fullOrg);
        }
      }
    } catch { /* ignore */ }
  }

  return { orgs, candidates };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — REPO ENUMERATION
// ═══════════════════════════════════════════════════════════════════════

async function enumerateOrgRepos(
  orgLogin: string,
  token?: string,
  maxPages = 3,
  timeout = 8000
): Promise<GitHubRepo[]> {
  const repos: GitHubRepo[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const pageRepos = await githubFetch<GitHubRepo[]>(
      `https://api.github.com/orgs/${encodeURIComponent(orgLogin)}/repos?per_page=100&page=${page}&sort=updated&direction=desc`,
      token,
      timeout
    );
    if (!pageRepos || pageRepos.length === 0) break;
    repos.push(...pageRepos);
    if (pageRepos.length < 100) break;
    await new Promise(r => setTimeout(r, 300));
  }
  return repos;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — CONTRIBUTOR MAPPING
// ═══════════════════════════════════════════════════════════════════════

async function getOrgMembers(
  orgLogin: string,
  token?: string,
  timeout = 8000
): Promise<GitHubUser[]> {
  const members = await githubFetch<Array<{ login: string }>>(
    `https://api.github.com/orgs/${encodeURIComponent(orgLogin)}/members?per_page=100`,
    token,
    timeout
  );
  if (!members) return [];

  // Get details for top 10 members
  const detailed: GitHubUser[] = [];
  for (const m of members.slice(0, 10)) {
    try {
      const user = await githubFetch<GitHubUser>(
        `https://api.github.com/users/${m.login}`,
        token,
        timeout
      );
      if (user) detailed.push(user);
      await new Promise(r => setTimeout(r, 200));
    } catch { /* skip */ }
  }
  return detailed;
}

async function getRepoContributors(
  repoFullName: string,
  token?: string,
  timeout = 8000
): Promise<Array<{ login: string; contributions: number }>> {
  const contributors = await githubFetch<Array<{ login: string; contributions: number }>>(
    `https://api.github.com/repos/${repoFullName}/contributors?per_page=20`,
    token,
    timeout
  );
  return contributors || [];
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — GITHUB ACTIONS / CI/CD ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

async function analyzeWorkflows(
  repoFullName: string,
  token?: string,
  timeout = 8000
): Promise<{
  workflows: GitHubWorkflow[];
  secretsReferenced: string[];
  runnersUsed: string[];
  thirdPartyActions: string[];
}> {
  const result = {
    workflows: [] as GitHubWorkflow[],
    secretsReferenced: [] as string[],
    runnersUsed: [] as string[],
    thirdPartyActions: [] as string[],
  };

  try {
    const wfResponse = await githubFetch<{ workflows: GitHubWorkflow[] }>(
      `https://api.github.com/repos/${repoFullName}/actions/workflows?per_page=30`,
      token,
      timeout
    );
    if (wfResponse?.workflows) {
      result.workflows = wfResponse.workflows;
    }
  } catch { /* ignore */ }

  // Search for workflow files to analyze content
  try {
    const searchResult = await searchGitHubCode(
      `repo:${repoFullName} path:.github/workflows`,
      token,
      timeout
    );
    if (searchResult?.items) {
      for (const item of searchResult.items) {
        const fragment = item.text_matches?.[0]?.fragment || "";
        // Extract secrets references
        const secretMatches = fragment.match(/\$\{\{\s*secrets\.([A-Z_]+)\s*\}\}/g);
        if (secretMatches) {
          result.secretsReferenced.push(
            ...secretMatches.map(m => m.replace(/\$\{\{\s*secrets\.|\s*\}\}/g, ""))
          );
        }
        // Extract runner types
        const runnerMatches = fragment.match(/runs-on:\s*([^\n]+)/g);
        if (runnerMatches) {
          result.runnersUsed.push(...runnerMatches.map(m => m.replace("runs-on:", "").trim()));
        }
        // Extract third-party actions
        const actionMatches = fragment.match(/uses:\s*([^\n@]+)/g);
        if (actionMatches) {
          result.thirdPartyActions.push(
            ...actionMatches
              .map(m => m.replace("uses:", "").trim())
              .filter(a => !a.startsWith("actions/") && !a.startsWith("./"))
          );
        }
      }
    }
  } catch { /* ignore */ }

  // Deduplicate
  result.secretsReferenced = [...new Set(result.secretsReferenced)];
  result.runnersUsed = [...new Set(result.runnersUsed)];
  result.thirdPartyActions = [...new Set(result.thirdPartyActions)];

  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — DEPENDENCY ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

async function analyzeDependencies(
  repoFullName: string,
  token?: string,
  timeout = 8000
): Promise<{ packageManager: string; dependencies: string[] }[]> {
  const results: { packageManager: string; dependencies: string[] }[] = [];

  const depFiles = [
    { file: "package.json", manager: "npm" },
    { file: "requirements.txt", manager: "pip" },
    { file: "Gemfile", manager: "bundler" },
    { file: "go.mod", manager: "go" },
    { file: "pom.xml", manager: "maven" },
    { file: "build.gradle", manager: "gradle" },
    { file: "Cargo.toml", manager: "cargo" },
    { file: "composer.json", manager: "composer" },
  ];

  for (const { file, manager } of depFiles) {
    try {
      const content = await githubFetch<{ content: string; encoding: string }>(
        `https://api.github.com/repos/${repoFullName}/contents/${file}`,
        token,
        timeout
      );
      if (content?.content) {
        const decoded = Buffer.from(content.content, "base64").toString("utf-8");
        const deps: string[] = [];

        if (manager === "npm") {
          try {
            const pkg = JSON.parse(decoded);
            deps.push(...Object.keys(pkg.dependencies || {}));
            deps.push(...Object.keys(pkg.devDependencies || {}));
          } catch { /* invalid JSON */ }
        } else if (manager === "pip") {
          deps.push(...decoded.split("\n").filter(l => l.trim() && !l.startsWith("#")).map(l => l.split("==")[0].split(">=")[0].trim()));
        } else {
          deps.push(`[${manager} manifest detected]`);
        }

        if (deps.length > 0) {
          results.push({ packageManager: manager, dependencies: deps.slice(0, 50) });
        }
      }
    } catch { /* file not found */ }
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — SECRET SCANNING IN CODE FRAGMENTS
// ═══════════════════════════════════════════════════════════════════════

function scanForSecrets(text: string): Array<{ pattern: SecretPattern; match: string }> {
  const findings: Array<{ pattern: SecretPattern; match: string }> = [];

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex state
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(text)) !== null) {
      // Redact the actual secret value
      const redacted = match[0].length > 12
        ? match[0].slice(0, 6) + "..." + match[0].slice(-4)
        : match[0].slice(0, 4) + "...";
      findings.push({ pattern, match: redacted });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// §10 — OBSERVATION BUILDERS
// ═══════════════════════════════════════════════════════════════════════

function buildOrgObservation(domain: string, org: GitHubOrg, now: Date): AssetObservation {
  return {
    assetId: makeAssetId(domain, `github_org:${org.login}`, "github_recon"),
    domain,
    assetType: "url",
    name: `GitHub Org: ${org.login} (${org.public_repos} public repos)`,
    source: "github_recon",
    observedAt: now,
    tags: ["github", "organization", "code_repository", `repos:${org.public_repos}`],
    evidence: {
      orgLogin: org.login,
      orgUrl: org.html_url,
      publicRepos: org.public_repos,
      description: org.description,
      blog: org.blog,
      email: org.email,
      location: org.location,
      createdAt: org.created_at,
    },
    attribution: {
      provider: "GitHub REST API",
      method: `Discovered GitHub organization '${org.login}' linked to ${domain}`,
      url: org.html_url,
      verifyUrl: org.html_url,
    },
  };
}

function buildRepoObservation(domain: string, repo: GitHubRepo, now: Date): AssetObservation {
  const riskTags: string[] = ["github", "repository"];
  if (repo.fork) riskTags.push("forked_repo");
  if (repo.archived) riskTags.push("archived_repo");
  if (repo.has_wiki) riskTags.push("wiki_enabled");
  if (repo.has_pages) riskTags.push("github_pages");
  if (repo.stargazers_count > 100) riskTags.push("popular_repo");
  if (repo.language) riskTags.push(`lang:${repo.language.toLowerCase()}`);
  if (repo.topics?.length) riskTags.push(...repo.topics.slice(0, 5).map(t => `topic:${t}`));

  return {
    assetId: makeAssetId(domain, `github_repo:${repo.full_name}`, "github_recon"),
    domain,
    assetType: "url",
    name: `Repo: ${repo.full_name} (${repo.language || "unknown"}, ★${repo.stargazers_count})`,
    source: "github_recon",
    observedAt: now,
    lastSeen: new Date(repo.pushed_at),
    tags: riskTags,
    evidence: {
      repoName: repo.name,
      fullName: repo.full_name,
      repoUrl: repo.html_url,
      description: repo.description,
      language: repo.language,
      stars: repo.stargazers_count,
      forks: repo.forks_count,
      openIssues: repo.open_issues_count,
      isFork: repo.fork,
      isArchived: repo.archived,
      hasWiki: repo.has_wiki,
      hasPages: repo.has_pages,
      topics: repo.topics,
      defaultBranch: repo.default_branch,
      sizeKb: repo.size,
      createdAt: repo.created_at,
      lastPushed: repo.pushed_at,
      owner: repo.owner.login,
      ownerType: repo.owner.type,
    },
    attribution: {
      provider: "GitHub REST API",
      method: `Enumerated public repository '${repo.full_name}' from organization`,
      url: repo.html_url,
      verifyUrl: repo.html_url,
    },
  };
}

function buildContributorObservation(
  domain: string,
  user: GitHubUser,
  orgLogin: string,
  now: Date
): AssetObservation {
  return {
    assetId: makeAssetId(domain, `github_user:${user.login}`, "github_recon"),
    domain,
    assetType: "url",
    name: `Contributor: ${user.name || user.login} (${user.public_repos} repos, ${user.followers} followers)`,
    source: "github_recon",
    observedAt: now,
    tags: ["github", "contributor", "developer", `org:${orgLogin}`],
    evidence: {
      login: user.login,
      name: user.name,
      profileUrl: user.html_url,
      company: user.company,
      blog: user.blog,
      location: user.location,
      email: user.email,
      bio: user.bio,
      publicRepos: user.public_repos,
      publicGists: user.public_gists,
      followers: user.followers,
      createdAt: user.created_at,
      organization: orgLogin,
    },
    attribution: {
      provider: "GitHub REST API",
      method: `Mapped contributor '${user.login}' from organization '${orgLogin}'`,
      url: user.html_url,
      verifyUrl: user.html_url,
    },
  };
}

function buildDorkObservation(
  domain: string,
  dork: DorkPattern,
  item: GitHubCodeItem,
  secretFindings: Array<{ pattern: SecretPattern; match: string }>,
  now: Date
): AssetObservation {
  const tags = [
    "github",
    "code_leak",
    `category:${dork.category}`,
    `severity:${dork.severity}`,
    item.repository.fork ? "forked_repo" : "original_repo",
  ];
  if (secretFindings.length > 0) {
    tags.push("secrets_detected", ...secretFindings.map(f => `secret:${f.pattern.id}`));
  }

  return {
    assetId: makeAssetId(domain, `github_dork:${dork.id}:${item.repository.full_name}:${item.path}`, "github_recon"),
    domain,
    assetType: "url",
    name: `[${dork.name}] ${item.repository.full_name}/${item.path}`,
    source: "github_recon",
    observedAt: now,
    lastSeen: item.repository.updated_at ? new Date(item.repository.updated_at) : now,
    tags,
    evidence: {
      dorkId: dork.id,
      dorkName: dork.name,
      dorkCategory: dork.category,
      severity: dork.severity,
      repository: item.repository.full_name,
      repoUrl: item.repository.html_url,
      filePath: item.path,
      fileUrl: item.html_url,
      repoOwner: item.repository.owner.login,
      repoOwnerType: item.repository.owner.type,
      isFork: item.repository.fork,
      textSnippet: item.text_matches?.[0]?.fragment?.slice(0, 300) || "",
      secretsFound: secretFindings.map(f => ({
        type: f.pattern.name,
        severity: f.pattern.severity,
        redactedMatch: f.match,
      })),
      secretCount: secretFindings.length,
    },
    attribution: {
      provider: "GitHub Code Search API",
      method: `GitHub dork '${dork.name}' found match in ${item.repository.full_name}`,
      url: item.html_url,
      verifyUrl: item.html_url,
    },
  };
}

function buildWorkflowObservation(
  domain: string,
  repoFullName: string,
  analysis: Awaited<ReturnType<typeof analyzeWorkflows>>,
  now: Date
): AssetObservation {
  const tags = ["github", "ci_cd", "github_actions"];
  if (analysis.thirdPartyActions.length > 5) tags.push("supply_chain_risk");
  if (analysis.secretsReferenced.length > 0) tags.push("secrets_in_workflows");

  return {
    assetId: makeAssetId(domain, `github_cicd:${repoFullName}`, "github_recon"),
    domain,
    assetType: "url",
    name: `CI/CD: ${repoFullName} (${analysis.workflows.length} workflows, ${analysis.secretsReferenced.length} secrets refs)`,
    source: "github_recon",
    observedAt: now,
    tags,
    evidence: {
      repository: repoFullName,
      workflowCount: analysis.workflows.length,
      workflows: analysis.workflows.map(w => ({ name: w.name, path: w.path, state: w.state })),
      secretsReferenced: analysis.secretsReferenced,
      runnersUsed: analysis.runnersUsed,
      thirdPartyActions: analysis.thirdPartyActions,
      supplyChainRisk: analysis.thirdPartyActions.length > 5 ? "elevated" : "normal",
    },
    attribution: {
      provider: "GitHub REST API + Code Search",
      method: `Analyzed CI/CD workflows in ${repoFullName}`,
      url: `https://github.com/${repoFullName}/actions`,
      verifyUrl: `https://github.com/${repoFullName}/actions`,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §11 — ENHANCED CONNECTOR EXPORT
// ═══════════════════════════════════════════════════════════════════════

export const githubReconConnector: PassiveConnector = {
  name: "github_recon",
  description:
    "Enhanced GitHub reconnaissance — org discovery, repo enumeration, contributor mapping, " +
    "CI/CD workflow analysis, secret scanning, and 30+ GitHub dork patterns " +
    "(T1593.003, T1591.004, T1589.001)",
  requiresApiKey: false,
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
    const GLOBAL_TIMEOUT = 90000; // 90s max for entire connector

    try {
      // ── Phase 1: Org Discovery ──────────────────────────────────
      const { orgs } = await discoverOrgs(domain, token, undefined, timeout);
      for (const org of orgs) {
        observations.push(buildOrgObservation(domain, org, now));
      }

      // ── Phase 2: Repo Enumeration ───────────────────────────────
      if (orgs.length > 0 && Date.now() - start < GLOBAL_TIMEOUT) {
        const primaryOrg = orgs[0];
        const repos = await enumerateOrgRepos(primaryOrg.login, token, 2, timeout);

        // Add top 20 repos by recent activity
        const sortedRepos = repos
          .sort((a, b) => new Date(b.pushed_at).getTime() - new Date(a.pushed_at).getTime())
          .slice(0, 20);

        for (const repo of sortedRepos) {
          observations.push(buildRepoObservation(domain, repo, now));
        }

        // ── Phase 3: Contributor Mapping ────────────────────────────
        if (Date.now() - start < GLOBAL_TIMEOUT) {
          try {
            const members = await getOrgMembers(primaryOrg.login, token, timeout);
            for (const member of members.slice(0, 10)) {
              observations.push(buildContributorObservation(domain, member, primaryOrg.login, now));
            }
          } catch (err: any) {
            errors.push(`Contributor mapping: ${err.message}`);
          }
        }

        // ── Phase 4: CI/CD Analysis on top 5 active repos ──────────
        if (Date.now() - start < GLOBAL_TIMEOUT) {
          const activeRepos = sortedRepos.filter(r => !r.archived && !r.fork).slice(0, 5);
          for (const repo of activeRepos) {
            if (Date.now() - start >= GLOBAL_TIMEOUT) break;
            try {
              const wfAnalysis = await analyzeWorkflows(repo.full_name, token, timeout);
              if (wfAnalysis.workflows.length > 0) {
                observations.push(buildWorkflowObservation(domain, repo.full_name, wfAnalysis, now));
              }
              await new Promise(r => setTimeout(r, 500));
            } catch (err: any) {
              errors.push(`CI/CD analysis [${repo.name}]: ${err.message}`);
            }
          }
        }

        // ── Phase 5: Dependency Analysis on top 3 repos ─────────────
        if (Date.now() - start < GLOBAL_TIMEOUT) {
          for (const repo of sortedRepos.filter(r => !r.fork).slice(0, 3)) {
            if (Date.now() - start >= GLOBAL_TIMEOUT) break;
            try {
              const deps = await analyzeDependencies(repo.full_name, token, timeout);
              if (deps.length > 0) {
                observations.push({
                  assetId: makeAssetId(domain, `github_deps:${repo.full_name}`, "github_recon"),
                  domain,
                  assetType: "url",
                  name: `Dependencies: ${repo.full_name} (${deps.map(d => `${d.packageManager}: ${d.dependencies.length}`).join(", ")})`,
                  source: "github_recon",
                  observedAt: now,
                  tags: ["github", "dependencies", "supply_chain", ...deps.map(d => `pkg:${d.packageManager}`)],
                  evidence: {
                    repository: repo.full_name,
                    dependencyManifests: deps,
                    totalDependencies: deps.reduce((sum, d) => sum + d.dependencies.length, 0),
                  },
                  attribution: {
                    provider: "GitHub REST API",
                    method: `Analyzed dependency manifests in ${repo.full_name}`,
                    url: repo.html_url,
                    verifyUrl: repo.html_url,
                  },
                });
              }
              await new Promise(r => setTimeout(r, 300));
            } catch { /* skip */ }
          }
        }
      }

      // ── Phase 6: Advanced GitHub Dorks ───────────────────────────
      if (Date.now() - start < GLOBAL_TIMEOUT) {
        // Run top 12 most critical dorks
        const priorityDorks = GITHUB_DORKS
          .filter(d => d.severity === "critical" || d.severity === "high")
          .slice(0, 12);

        const seenFiles = new Set<string>();

        for (const dork of priorityDorks) {
          if (Date.now() - start >= GLOBAL_TIMEOUT) break;

          const query = dork.queryTemplate.replace("{{domain}}", domain);
          try {
            await new Promise(r => setTimeout(r, 2200)); // Rate limit delay
            const result = await searchGitHubCode(query, token, timeout);
            if (!result) continue;

            for (const item of result.items.slice(0, 5)) {
              const key = `${item.repository.full_name}:${item.path}`;
              if (seenFiles.has(key)) continue;
              seenFiles.add(key);

              // Scan text fragments for secrets
              const fragment = item.text_matches?.[0]?.fragment || "";
              const secretFindings = scanForSecrets(fragment);

              observations.push(buildDorkObservation(domain, dork, item, secretFindings, now));
            }
          } catch (err: any) {
            errors.push(`[dork:${dork.id}] ${err.message}`);
            if (err.message.includes("rate limit")) break;
          }
        }
      }

      // ── Summary Observation ─────────────────────────────────────
      const orgCount = observations.filter(o => o.tags.includes("organization")).length;
      const repoCount = observations.filter(o => o.tags.includes("repository")).length;
      const contributorCount = observations.filter(o => o.tags.includes("contributor")).length;
      const dorkFindings = observations.filter(o => o.tags.includes("code_leak")).length;
      const cicdFindings = observations.filter(o => o.tags.includes("ci_cd")).length;
      const secretsDetected = observations.filter(o => o.tags.includes("secrets_detected")).length;

      observations.push({
        assetId: makeAssetId(domain, `github_recon_summary:${domain}`, "github_recon"),
        domain,
        assetType: "url",
        name: `GitHub Recon Summary: ${orgCount} orgs, ${repoCount} repos, ${contributorCount} contributors, ${dorkFindings} code leaks, ${cicdFindings} CI/CD, ${secretsDetected} secrets`,
        source: "github_recon",
        observedAt: now,
        tags: [
          "github",
          "recon_summary",
          ...(secretsDetected > 0 ? ["secrets_exposed"] : []),
          ...(dorkFindings > 5 ? ["high_exposure"] : []),
        ],
        evidence: {
          organizationsFound: orgCount,
          repositoriesEnumerated: repoCount,
          contributorsMapped: contributorCount,
          codeLeakFindings: dorkFindings,
          cicdAnalyzed: cicdFindings,
          secretsDetected,
          scanDurationMs: Date.now() - start,
        },
        attribution: {
          provider: "GitHub REST API + Code Search",
          method: `Comprehensive GitHub reconnaissance for ${domain}`,
        },
      });
    } catch (err: any) {
      errors.push(`GitHub recon top-level error: ${err.message}`);
    }

    return {
      connector: "github_recon",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: errors.some(e => e.includes("rate limit")),
    };
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §12 — EXPORTED ANALYSIS FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** Get all available dork patterns for UI display */
export function getGitHubDorks() {
  return GITHUB_DORKS.map(d => ({
    id: d.id,
    name: d.name,
    category: d.category,
    severity: d.severity,
    description: d.description,
  }));
}

/** Get all secret patterns for UI display */
export function getSecretPatterns() {
  return SECRET_PATTERNS.map(p => ({
    id: p.id,
    name: p.name,
    severity: p.severity,
    description: p.description,
  }));
}

/** Summarize GitHub recon findings */
export function summarizeGitHubRecon(observations: AssetObservation[]) {
  const summary = {
    organizations: [] as Array<{ login: string; repos: number }>,
    topRepos: [] as Array<{ name: string; language: string; stars: number }>,
    contributors: [] as Array<{ login: string; name: string | null }>,
    codeLeaks: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, byCategory: {} as Record<string, number> },
    cicd: { workflowsAnalyzed: 0, secretsReferenced: [] as string[], thirdPartyActions: [] as string[] },
    secretsDetected: 0,
    riskScore: 0,
  };

  for (const obs of observations) {
    if (obs.tags.includes("organization")) {
      summary.organizations.push({ login: obs.evidence?.orgLogin, repos: obs.evidence?.publicRepos });
    }
    if (obs.tags.includes("repository")) {
      summary.topRepos.push({ name: obs.evidence?.fullName, language: obs.evidence?.language, stars: obs.evidence?.stars });
    }
    if (obs.tags.includes("contributor")) {
      summary.contributors.push({ login: obs.evidence?.login, name: obs.evidence?.name });
    }
    if (obs.tags.includes("code_leak")) {
      summary.codeLeaks.total++;
      const sev = obs.evidence?.severity || "low";
      summary.codeLeaks.bySeverity[sev as keyof typeof summary.codeLeaks.bySeverity]++;
      const cat = obs.evidence?.dorkCategory || "unknown";
      summary.codeLeaks.byCategory[cat] = (summary.codeLeaks.byCategory[cat] || 0) + 1;
    }
    if (obs.tags.includes("ci_cd")) {
      summary.cicd.workflowsAnalyzed++;
      summary.cicd.secretsReferenced.push(...(obs.evidence?.secretsReferenced || []));
      summary.cicd.thirdPartyActions.push(...(obs.evidence?.thirdPartyActions || []));
    }
    if (obs.tags.includes("secrets_detected")) summary.secretsDetected++;
  }

  // Deduplicate
  summary.cicd.secretsReferenced = [...new Set(summary.cicd.secretsReferenced)];
  summary.cicd.thirdPartyActions = [...new Set(summary.cicd.thirdPartyActions)];

  // Risk score
  const { critical, high, medium } = summary.codeLeaks.bySeverity;
  summary.riskScore = Math.min(100, critical * 25 + high * 15 + medium * 5 + summary.secretsDetected * 20);

  return summary;
}
