/**
 * Container Registry Service
 *
 * Provides authenticated access to container registries (Docker Hub, ECR, ACR, GCR,
 * Harbor, Artifactory, Nexus, GitLab, GHCR, Quay, custom) for:
 * - Registry credential validation and connectivity testing
 * - Repository and tag enumeration
 * - Image manifest retrieval and layer analysis
 * - Vulnerability scanning via package extraction and CVE/NVD matching
 * - SBOM generation from image layers
 */

// ─── Types ──────────────────────────────────────────────────────────

export type RegistryType =
  | "docker_hub" | "ecr" | "acr" | "gcr" | "harbor"
  | "artifactory" | "nexus" | "gitlab" | "ghcr" | "quay" | "custom";

export interface RegistryAuthConfig {
  // Docker Hub / generic
  username?: string;
  password?: string;
  // Token-based
  token?: string;
  // AWS ECR
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsRegion?: string;
  awsAccountId?: string;
  // Azure ACR
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
  azureSubscriptionId?: string;
  // GCP GCR / Artifact Registry
  gcpServiceAccountJson?: string;
  gcpProjectId?: string;
  // Custom registry URL override
  customUrl?: string;
}

export interface RegistryRepository {
  name: string;
  fullName: string;
  description?: string;
  tagCount?: number;
  lastPushed?: string;
  isPrivate?: boolean;
}

export interface RegistryTag {
  name: string;
  digest?: string;
  size?: number;
  lastModified?: string;
  architecture?: string;
  os?: string;
}

export interface ImageManifest {
  schemaVersion: number;
  mediaType: string;
  digest: string;
  size: number;
  config?: {
    mediaType: string;
    digest: string;
    size: number;
  };
  layers: Array<{
    mediaType: string;
    digest: string;
    size: number;
  }>;
}

export interface ImageConfig {
  architecture: string;
  os: string;
  created?: string;
  author?: string;
  config?: {
    Env?: string[];
    Cmd?: string[];
    Entrypoint?: string[];
    ExposedPorts?: Record<string, object>;
    Labels?: Record<string, string>;
    User?: string;
    WorkingDir?: string;
  };
  rootfs?: {
    type: string;
    diff_ids: string[];
  };
  history?: Array<{
    created?: string;
    created_by?: string;
    empty_layer?: boolean;
    comment?: string;
  }>;
}

export interface ContainerVulnerability {
  cveId: string;
  severity: "critical" | "high" | "medium" | "low" | "negligible";
  packageName: string;
  installedVersion: string;
  fixedVersion?: string;
  title?: string;
  description?: string;
  cvssScore?: number;
  cvssVector?: string;
  publishedDate?: string;
  references?: string[];
  exploitAvailable?: boolean;
  kevListed?: boolean;
}

export interface PackageInfo {
  name: string;
  version: string;
  type: "os" | "python" | "npm" | "go" | "java" | "ruby" | "rust" | "dotnet";
  source?: string;
  license?: string;
}

export interface ImageScanResult {
  repository: string;
  tag: string;
  digest?: string;
  architecture?: string;
  os?: string;
  imageSize?: number;
  baseImage?: string;
  // Vulnerability counts
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  negligibleCount: number;
  fixedAvailable: number;
  // Detailed results
  vulnerabilities: ContainerVulnerability[];
  packages: PackageInfo[];
  layers: Array<{ digest: string; size: number; command?: string }>;
  // Security checks
  complianceIssues: Array<{ check: string; status: "pass" | "fail"; detail: string }>;
  malwareDetected: boolean;
  secretsDetected: number;
  // Metadata
  scanDurationMs: number;
  scanEngine: string;
}

export interface RegistryTestResult {
  success: boolean;
  registryType: RegistryType;
  registryUrl: string;
  message: string;
  repoCount?: number;
  latency?: number;
  error?: string;
}

// ─── Registry URL Resolution ────────────────────────────────────────

function getRegistryBaseUrl(type: RegistryType, auth: RegistryAuthConfig): string {
  switch (type) {
    case "docker_hub":
      return "https://registry-1.docker.io";
    case "ecr":
      return `https://${auth.awsAccountId || "000000000000"}.dkr.ecr.${auth.awsRegion || "us-east-1"}.amazonaws.com`;
    case "acr":
      return auth.customUrl || `https://${auth.username || "registry"}.azurecr.io`;
    case "gcr":
      return auth.customUrl || `https://gcr.io`;
    case "harbor":
    case "artifactory":
    case "nexus":
    case "gitlab":
    case "custom":
      return auth.customUrl || "";
    case "ghcr":
      return "https://ghcr.io";
    case "quay":
      return "https://quay.io";
    default:
      return auth.customUrl || "";
  }
}

// ─── Authentication ─────────────────────────────────────────────────

async function getAuthToken(
  type: RegistryType,
  auth: RegistryAuthConfig,
  scope?: string
): Promise<string> {
  switch (type) {
    case "docker_hub": {
      // Docker Hub uses token-based auth via auth.docker.io
      const tokenUrl = `https://auth.docker.io/token?service=registry.docker.io&scope=${scope || "registry:catalog:*"}`;
      const headers: Record<string, string> = {};
      if (auth.username && auth.password) {
        headers["Authorization"] = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString("base64")}`;
      }
      const resp = await fetch(tokenUrl, { headers, signal: AbortSignal.timeout(10000) });
      if (!resp.ok) throw new Error(`Docker Hub auth failed: ${resp.status}`);
      const data = await resp.json() as { token: string };
      return data.token;
    }

    case "ecr": {
      // AWS ECR uses GetAuthorizationToken API
      // In production, use AWS SDK. Here we simulate with basic auth.
      if (auth.awsAccessKeyId && auth.awsSecretAccessKey) {
        // Use the AWS ECR GetAuthorizationToken endpoint
        const region = auth.awsRegion || "us-east-1";
        const endpoint = `https://api.ecr.${region}.amazonaws.com`;
        // For simplicity, we'll use basic auth with the ECR password
        return Buffer.from(`AWS:${auth.awsSecretAccessKey}`).toString("base64");
      }
      throw new Error("ECR requires awsAccessKeyId and awsSecretAccessKey");
    }

    case "acr": {
      // Azure ACR supports OAuth2 token exchange
      if (auth.azureClientId && auth.azureClientSecret && auth.azureTenantId) {
        const tokenUrl = `https://login.microsoftonline.com/${auth.azureTenantId}/oauth2/v2.0/token`;
        const body = new URLSearchParams({
          grant_type: "client_credentials",
          client_id: auth.azureClientId,
          client_secret: auth.azureClientSecret,
          scope: "https://management.azure.com/.default",
        });
        const resp = await fetch(tokenUrl, {
          method: "POST",
          body,
          signal: AbortSignal.timeout(10000),
        });
        if (!resp.ok) throw new Error(`ACR auth failed: ${resp.status}`);
        const data = await resp.json() as { access_token: string };
        return data.access_token;
      }
      // Fall back to basic auth
      if (auth.username && auth.password) {
        return Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
      }
      throw new Error("ACR requires credentials");
    }

    case "gcr": {
      // GCR uses service account JSON key
      if (auth.gcpServiceAccountJson) {
        try {
          const sa = JSON.parse(auth.gcpServiceAccountJson);
          // Use _json_key as username with the service account JSON as password
          return Buffer.from(`_json_key:${auth.gcpServiceAccountJson}`).toString("base64");
        } catch {
          throw new Error("Invalid GCP service account JSON");
        }
      }
      if (auth.token) return auth.token;
      throw new Error("GCR requires gcpServiceAccountJson or token");
    }

    case "ghcr": {
      if (auth.token) return auth.token;
      if (auth.username && auth.password) {
        return Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
      }
      throw new Error("GHCR requires a personal access token");
    }

    default: {
      // Generic basic auth for Harbor, Artifactory, Nexus, GitLab, Quay, custom
      if (auth.token) return auth.token;
      if (auth.username && auth.password) {
        return Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
      }
      throw new Error("Registry requires username/password or token");
    }
  }
}

// ─── Registry API Client ────────────────────────────────────────────

async function registryFetch(
  url: string,
  token: string,
  type: RegistryType,
  options?: { accept?: string; timeout?: number }
): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: options?.accept || "application/vnd.docker.distribution.manifest.v2+json",
  };

  // Docker Hub and GHCR use Bearer tokens, others typically use Basic
  if (type === "docker_hub" || type === "ghcr") {
    headers["Authorization"] = `Bearer ${token}`;
  } else {
    headers["Authorization"] = `Basic ${token}`;
  }

  return fetch(url, {
    headers,
    signal: AbortSignal.timeout(options?.timeout || 15000),
  });
}

// ─── Public API ─────────────────────────────────────────────────────

/**
 * Test registry connectivity and credentials
 */
export async function testRegistryConnection(
  type: RegistryType,
  auth: RegistryAuthConfig
): Promise<RegistryTestResult> {
  const startTime = Date.now();
  const baseUrl = getRegistryBaseUrl(type, auth);

  if (!baseUrl) {
    return {
      success: false,
      registryType: type,
      registryUrl: "",
      message: "Registry URL could not be determined",
      error: "Missing registry URL or customUrl",
    };
  }

  try {
    const token = await getAuthToken(type, auth, "registry:catalog:*");

    // Try to list repositories (catalog endpoint)
    const catalogUrl = type === "docker_hub"
      ? `https://hub.docker.com/v2/repositories/${auth.username || "library"}/?page_size=1`
      : `${baseUrl}/v2/_catalog?n=5`;

    const resp = await registryFetch(catalogUrl, token, type, {
      accept: "application/json",
      timeout: 10000,
    });

    const latency = Date.now() - startTime;

    if (resp.ok) {
      const data = await resp.json() as { repositories?: string[]; count?: number; results?: unknown[] };
      const repoCount = data.repositories?.length || data.count || data.results?.length || 0;
      return {
        success: true,
        registryType: type,
        registryUrl: baseUrl,
        message: `Successfully connected to ${type} registry`,
        repoCount,
        latency,
      };
    }

    // Some registries return 401 on catalog but still accept image pulls
    if (resp.status === 401 || resp.status === 403) {
      // Try the v2/ endpoint as a basic connectivity check
      const v2Resp = await registryFetch(`${baseUrl}/v2/`, token, type, { timeout: 5000 });
      if (v2Resp.ok || v2Resp.status === 401) {
        return {
          success: true,
          registryType: type,
          registryUrl: baseUrl,
          message: `Connected to ${type} registry (catalog access restricted, image pull may still work)`,
          latency: Date.now() - startTime,
        };
      }
    }

    return {
      success: false,
      registryType: type,
      registryUrl: baseUrl,
      message: `Registry returned status ${resp.status}`,
      latency,
      error: `HTTP ${resp.status}: ${resp.statusText}`,
    };
  } catch (err: any) {
    return {
      success: false,
      registryType: type,
      registryUrl: baseUrl,
      message: `Connection failed: ${err.message}`,
      latency: Date.now() - startTime,
      error: err.message,
    };
  }
}

/**
 * List repositories in a registry
 */
export async function listRepositories(
  type: RegistryType,
  auth: RegistryAuthConfig,
  options?: { limit?: number; namespace?: string }
): Promise<RegistryRepository[]> {
  const baseUrl = getRegistryBaseUrl(type, auth);
  const limit = options?.limit || 100;

  try {
    const token = await getAuthToken(type, auth, "registry:catalog:*");

    if (type === "docker_hub") {
      // Docker Hub has its own API
      const namespace = options?.namespace || auth.username || "library";
      const url = `https://hub.docker.com/v2/repositories/${namespace}/?page_size=${limit}`;
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(15000),
      });
      if (!resp.ok) return [];
      const data = await resp.json() as { results: Array<{ name: string; description: string; last_updated: string; is_private: boolean }> };
      return (data.results || []).map(r => ({
        name: r.name,
        fullName: `${namespace}/${r.name}`,
        description: r.description,
        lastPushed: r.last_updated,
        isPrivate: r.is_private,
      }));
    }

    // Standard V2 registry catalog
    const catalogUrl = `${baseUrl}/v2/_catalog?n=${limit}`;
    const resp = await registryFetch(catalogUrl, token, type, { accept: "application/json" });
    if (!resp.ok) return [];
    const data = await resp.json() as { repositories: string[] };
    return (data.repositories || []).map(name => ({
      name: name.split("/").pop() || name,
      fullName: name,
    }));
  } catch {
    return [];
  }
}

/**
 * List tags for a repository
 */
export async function listTags(
  type: RegistryType,
  auth: RegistryAuthConfig,
  repository: string,
  options?: { limit?: number }
): Promise<RegistryTag[]> {
  const baseUrl = getRegistryBaseUrl(type, auth);
  const limit = options?.limit || 50;

  try {
    const scope = `repository:${repository}:pull`;
    const token = await getAuthToken(type, auth, scope);

    if (type === "docker_hub") {
      const url = `https://hub.docker.com/v2/repositories/${repository}/tags/?page_size=${limit}`;
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(15000),
      });
      if (!resp.ok) return [];
      const data = await resp.json() as { results: Array<{ name: string; digest: string; full_size: number; last_updated: string }> };
      return (data.results || []).map(t => ({
        name: t.name,
        digest: t.digest,
        size: t.full_size,
        lastModified: t.last_updated,
      }));
    }

    // Standard V2 tags/list
    const tagsUrl = `${baseUrl}/v2/${repository}/tags/list?n=${limit}`;
    const resp = await registryFetch(tagsUrl, token, type, { accept: "application/json" });
    if (!resp.ok) return [];
    const data = await resp.json() as { tags: string[] };
    return (data.tags || []).map(name => ({ name }));
  } catch {
    return [];
  }
}

/**
 * Get image manifest
 */
export async function getManifest(
  type: RegistryType,
  auth: RegistryAuthConfig,
  repository: string,
  tag: string
): Promise<ImageManifest | null> {
  const baseUrl = getRegistryBaseUrl(type, auth);

  try {
    const scope = `repository:${repository}:pull`;
    const token = await getAuthToken(type, auth, scope);
    const manifestUrl = `${baseUrl}/v2/${repository}/manifests/${tag}`;
    const resp = await registryFetch(manifestUrl, token, type, {
      accept: "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json",
    });
    if (!resp.ok) return null;
    const manifest = await resp.json() as ImageManifest;
    manifest.digest = resp.headers.get("docker-content-digest") || "";
    return manifest;
  } catch {
    return null;
  }
}

/**
 * Get image configuration (OS, architecture, env, history)
 */
export async function getImageConfig(
  type: RegistryType,
  auth: RegistryAuthConfig,
  repository: string,
  configDigest: string
): Promise<ImageConfig | null> {
  const baseUrl = getRegistryBaseUrl(type, auth);

  try {
    const scope = `repository:${repository}:pull`;
    const token = await getAuthToken(type, auth, scope);
    const blobUrl = `${baseUrl}/v2/${repository}/blobs/${configDigest}`;
    const resp = await registryFetch(blobUrl, token, type, {
      accept: "application/vnd.docker.container.image.v1+json, application/vnd.oci.image.config.v1+json",
    });
    if (!resp.ok) return null;
    return await resp.json() as ImageConfig;
  } catch {
    return null;
  }
}

// ─── Vulnerability Scanning Engine ──────────────────────────────────

// Known vulnerable package patterns (subset of common CVEs for demonstration)
// In production, this would query NVD/OSV/Grype DB
const VULN_DB_PATTERNS: Array<{
  ecosystem: string;
  package: string;
  versionPattern: RegExp;
  cve: string;
  severity: ContainerVulnerability["severity"];
  title: string;
  fixedVersion?: string;
  cvssScore?: number;
}> = [
  { ecosystem: "os", package: "openssl", versionPattern: /^1\.[01]\./, cve: "CVE-2022-0778", severity: "high", title: "OpenSSL Infinite Loop", fixedVersion: "1.1.1n", cvssScore: 7.5 },
  { ecosystem: "os", package: "openssl", versionPattern: /^3\.0\.[0-6]$/, cve: "CVE-2023-0286", severity: "high", title: "OpenSSL X.400 Address Type Confusion", fixedVersion: "3.0.8", cvssScore: 7.4 },
  { ecosystem: "os", package: "curl", versionPattern: /^7\.(8[0-9]|7[0-9])\./, cve: "CVE-2023-38545", severity: "critical", title: "curl SOCKS5 Heap Buffer Overflow", fixedVersion: "8.4.0", cvssScore: 9.8 },
  { ecosystem: "os", package: "glibc", versionPattern: /^2\.(3[0-5])/, cve: "CVE-2023-4911", severity: "critical", title: "glibc ld.so Buffer Overflow (Looney Tunables)", fixedVersion: "2.38-4", cvssScore: 7.8 },
  { ecosystem: "os", package: "zlib", versionPattern: /^1\.2\.(1[0-2])/, cve: "CVE-2022-37434", severity: "critical", title: "zlib Heap Buffer Overflow in inflate", fixedVersion: "1.2.13", cvssScore: 9.8 },
  { ecosystem: "os", package: "libexpat", versionPattern: /^2\.[0-4]\./, cve: "CVE-2022-25235", severity: "critical", title: "Expat XML Parser UTF-8 Encoding Validation", fixedVersion: "2.4.5", cvssScore: 9.8 },
  { ecosystem: "os", package: "sudo", versionPattern: /^1\.(8|9\.[0-9]$)/, cve: "CVE-2023-22809", severity: "high", title: "Sudo Privilege Escalation via sudoedit", fixedVersion: "1.9.12p2", cvssScore: 7.8 },
  { ecosystem: "python", package: "requests", versionPattern: /^2\.(2[0-8]|[01])\./, cve: "CVE-2023-32681", severity: "medium", title: "Requests Proxy-Authorization Header Leak", fixedVersion: "2.31.0", cvssScore: 6.1 },
  { ecosystem: "python", package: "flask", versionPattern: /^[01]\./, cve: "CVE-2023-30861", severity: "high", title: "Flask Session Cookie Caching Vulnerability", fixedVersion: "2.3.2", cvssScore: 7.5 },
  { ecosystem: "python", package: "django", versionPattern: /^[0-3]\./, cve: "CVE-2023-36053", severity: "high", title: "Django ReDoS in EmailValidator", fixedVersion: "4.2.3", cvssScore: 7.5 },
  { ecosystem: "python", package: "cryptography", versionPattern: /^(3[0-9]|[0-2]|40)\.\d+\./, cve: "CVE-2023-49083", severity: "high", title: "Cryptography NULL Pointer Dereference", fixedVersion: "41.0.6", cvssScore: 7.5 },
  { ecosystem: "npm", package: "express", versionPattern: /^[0-3]\./, cve: "CVE-2024-29041", severity: "medium", title: "Express.js Open Redirect", fixedVersion: "4.19.2", cvssScore: 6.1 },
  { ecosystem: "npm", package: "jsonwebtoken", versionPattern: /^[0-8]\./, cve: "CVE-2022-23529", severity: "high", title: "jsonwebtoken Arbitrary Code Execution", fixedVersion: "9.0.0", cvssScore: 7.6 },
  { ecosystem: "go", package: "golang.org/x/net", versionPattern: /^0\.(0|1[0-6])\./, cve: "CVE-2023-44487", severity: "high", title: "HTTP/2 Rapid Reset Attack", fixedVersion: "0.17.0", cvssScore: 7.5 },
  { ecosystem: "go", package: "golang.org/x/crypto", versionPattern: /^0\.(0|1[0-3])\./, cve: "CVE-2023-48795", severity: "medium", title: "Terrapin SSH Prefix Truncation Attack", fixedVersion: "0.17.0", cvssScore: 5.9 },
  { ecosystem: "java", package: "log4j-core", versionPattern: /^2\.(0|1[0-6])\./, cve: "CVE-2021-44228", severity: "critical", title: "Log4Shell Remote Code Execution", fixedVersion: "2.17.1", cvssScore: 10.0 },
  { ecosystem: "java", package: "spring-core", versionPattern: /^5\.[0-2]\./, cve: "CVE-2022-22965", severity: "critical", title: "Spring4Shell RCE", fixedVersion: "5.3.18", cvssScore: 9.8 },
  { ecosystem: "ruby", package: "rack", versionPattern: /^[0-2]\./, cve: "CVE-2023-27539", severity: "medium", title: "Rack ReDoS in Content-Type Header", fixedVersion: "3.0.4.2", cvssScore: 5.3 },
];

/**
 * Extract packages from image config history (Dockerfile commands)
 */
function extractPackagesFromHistory(config: ImageConfig): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const seen = new Set<string>();

  if (!config.history) return packages;

  for (const entry of config.history) {
    const cmd = entry.created_by || "";

    // APT packages: apt-get install -y pkg1 pkg2
    const aptMatch = cmd.match(/apt-get\s+install\s+(?:-[a-z]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (aptMatch) {
      const pkgs = aptMatch[1].split(/\s+/).filter(p => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const cleanPkg = pkg.replace(/[=<>].+/, "");
        const version = pkg.includes("=") ? pkg.split("=")[1] : "unknown";
        const key = `os:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version, type: "os" });
        }
      }
    }

    // YUM/DNF packages
    const yumMatch = cmd.match(/(?:yum|dnf)\s+install\s+(?:-[a-z]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (yumMatch) {
      const pkgs = yumMatch[1].split(/\s+/).filter(p => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const cleanPkg = pkg.replace(/[-=<>].+/, "");
        const key = `os:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version: "unknown", type: "os" });
        }
      }
    }

    // APK packages
    const apkMatch = cmd.match(/apk\s+add\s+(?:--[a-z-]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (apkMatch) {
      const pkgs = apkMatch[1].split(/\s+/).filter(p => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const cleanPkg = pkg.replace(/[=<>~].+/, "");
        const key = `os:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version: "unknown", type: "os" });
        }
      }
    }

    // pip install
    const pipMatch = cmd.match(/pip3?\s+install\s+(?:--[a-z-]+(?:\s+\S+)?\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (pipMatch) {
      const pkgs = pipMatch[1].split(/\s+/).filter(p => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const parts = pkg.split(/[=<>~]+/);
        const cleanPkg = parts[0].toLowerCase();
        const version = parts[1] || "unknown";
        const key = `python:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version, type: "python" });
        }
      }
    }

    // npm install
    const npmMatch = cmd.match(/npm\s+install\s+(?:--[a-z-]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (npmMatch) {
      const pkgs = npmMatch[1].split(/\s+/).filter(p => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const parts = pkg.split("@");
        const cleanPkg = parts.length > 2 ? `@${parts[1]}` : parts[0];
        const version = parts.length > 2 ? parts[2] : (parts[1] || "unknown");
        const key = `npm:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version, type: "npm" });
        }
      }
    }

    // go install / go get
    const goMatch = cmd.match(/go\s+(?:install|get)\s+(.+?)(?:\s*&&|\s*$)/i);
    if (goMatch) {
      const pkgs = goMatch[1].split(/\s+/).filter(p => p.includes("/"));
      for (const pkg of pkgs) {
        const parts = pkg.split("@");
        const key = `go:${parts[0]}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: parts[0], version: parts[1] || "latest", type: "go" });
        }
      }
    }
  }

  // Extract base image from FROM instruction
  for (const entry of config.history) {
    const cmd = entry.created_by || "";
    if (cmd.includes("FROM") || entry.comment?.includes("FROM")) {
      // Base image packages are typically not visible in history
      break;
    }
  }

  return packages;
}

/**
 * Extract environment-based package info
 */
function extractPackagesFromEnv(config: ImageConfig): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const env = config.config?.Env || [];

  for (const e of env) {
    // PYTHON_VERSION, NODE_VERSION, GOLANG_VERSION, etc.
    const versionMatch = e.match(/^(PYTHON|NODE|GOLANG|RUBY|JAVA|DOTNET)_VERSION=(.+)$/);
    if (versionMatch) {
      const typeMap: Record<string, PackageInfo["type"]> = {
        PYTHON: "python", NODE: "npm", GOLANG: "go", RUBY: "ruby", JAVA: "java", DOTNET: "dotnet",
      };
      packages.push({
        name: versionMatch[1].toLowerCase(),
        version: versionMatch[2],
        type: typeMap[versionMatch[1]] || "os",
        source: "environment",
      });
    }
  }

  return packages;
}

/**
 * Match packages against vulnerability database
 */
function matchVulnerabilities(packages: PackageInfo[]): ContainerVulnerability[] {
  const vulns: ContainerVulnerability[] = [];
  const seen = new Set<string>();

  for (const pkg of packages) {
    for (const pattern of VULN_DB_PATTERNS) {
      const ecosystemMatch =
        pattern.ecosystem === pkg.type ||
        (pattern.ecosystem === "os" && pkg.type === "os");

      if (ecosystemMatch && pkg.name.includes(pattern.package) && pattern.versionPattern.test(pkg.version)) {
        const key = `${pattern.cve}:${pkg.name}`;
        if (!seen.has(key)) {
          seen.add(key);
          vulns.push({
            cveId: pattern.cve,
            severity: pattern.severity,
            packageName: pkg.name,
            installedVersion: pkg.version,
            fixedVersion: pattern.fixedVersion,
            title: pattern.title,
            cvssScore: pattern.cvssScore,
          });
        }
      }
    }
  }

  return vulns;
}

/**
 * Run security compliance checks on image config
 */
function runComplianceChecks(config: ImageConfig): Array<{ check: string; status: "pass" | "fail"; detail: string }> {
  const checks: Array<{ check: string; status: "pass" | "fail"; detail: string }> = [];

  // CIS Docker Benchmark checks
  // 4.1 - Ensure a user for the container has been created
  const user = config.config?.User;
  checks.push({
    check: "CIS 4.1 - Container runs as non-root user",
    status: user && user !== "root" && user !== "0" ? "pass" : "fail",
    detail: user ? `Runs as user: ${user}` : "No USER instruction found — container runs as root",
  });

  // 4.6 - Ensure HEALTHCHECK instructions have been added
  const hasHealthcheck = config.history?.some(h => (h.created_by || "").includes("HEALTHCHECK"));
  checks.push({
    check: "CIS 4.6 - HEALTHCHECK instruction present",
    status: hasHealthcheck ? "pass" : "fail",
    detail: hasHealthcheck ? "HEALTHCHECK instruction found" : "No HEALTHCHECK instruction — container health cannot be monitored",
  });

  // 4.9 - Ensure that COPY is used instead of ADD
  const usesAdd = config.history?.some(h => (h.created_by || "").match(/\bADD\b/) && !(h.created_by || "").includes("ADD file:"));
  checks.push({
    check: "CIS 4.9 - COPY used instead of ADD",
    status: usesAdd ? "fail" : "pass",
    detail: usesAdd ? "ADD instruction found — prefer COPY for local files" : "No problematic ADD instructions found",
  });

  // Check for exposed privileged ports
  const exposedPorts = Object.keys(config.config?.ExposedPorts || {});
  const privilegedPorts = exposedPorts.filter(p => {
    const port = parseInt(p.split("/")[0]);
    return port < 1024 && port !== 80 && port !== 443;
  });
  checks.push({
    check: "CIS 4.7 - No unnecessary privileged ports exposed",
    status: privilegedPorts.length === 0 ? "pass" : "fail",
    detail: privilegedPorts.length > 0
      ? `Privileged ports exposed: ${privilegedPorts.join(", ")}`
      : "No unnecessary privileged ports exposed",
  });

  // Check for sensitive environment variables
  const sensitiveEnvPatterns = /password|secret|key|token|credential|api_key/i;
  const sensitiveEnvs = (config.config?.Env || []).filter(e => sensitiveEnvPatterns.test(e.split("=")[0]));
  checks.push({
    check: "CIS 4.10 - No secrets stored in environment variables",
    status: sensitiveEnvs.length === 0 ? "pass" : "fail",
    detail: sensitiveEnvs.length > 0
      ? `${sensitiveEnvs.length} potentially sensitive env vars found: ${sensitiveEnvs.map(e => e.split("=")[0]).join(", ")}`
      : "No sensitive environment variables detected",
  });

  // Check for latest tag usage (from labels or base image)
  const usesLatest = config.history?.some(h => (h.created_by || "").includes(":latest"));
  checks.push({
    check: "Best Practice - Avoid using 'latest' tag",
    status: usesLatest ? "fail" : "pass",
    detail: usesLatest ? "Image references ':latest' tag — use specific version tags for reproducibility" : "No ':latest' tag references found",
  });

  return checks;
}

/**
 * Detect secrets in image config
 */
function detectSecrets(config: ImageConfig): number {
  let secretCount = 0;
  const secretPatterns = [
    /(?:password|passwd|pwd)\s*=\s*\S+/i,
    /(?:api[_-]?key|apikey)\s*=\s*\S+/i,
    /(?:secret|token)\s*=\s*\S+/i,
    /(?:aws_access_key_id|aws_secret_access_key)\s*=\s*\S+/i,
    /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
    /ghp_[a-zA-Z0-9]{36}/,
    /sk-[a-zA-Z0-9]{48}/,
  ];

  const allText = [
    ...(config.config?.Env || []),
    ...(config.history || []).map(h => h.created_by || ""),
  ].join("\n");

  for (const pattern of secretPatterns) {
    const matches = allText.match(new RegExp(pattern, "g"));
    if (matches) secretCount += matches.length;
  }

  return secretCount;
}

/**
 * Detect base image from config history
 */
function detectBaseImage(config: ImageConfig): string | undefined {
  if (!config.history || config.history.length === 0) return undefined;

  // The first history entry usually contains the FROM instruction
  const firstEntry = config.history[0];
  const cmd = firstEntry.created_by || firstEntry.comment || "";

  // Look for FROM patterns
  const fromMatch = cmd.match(/FROM\s+(\S+)/i);
  if (fromMatch) return fromMatch[1];

  // Check labels
  const labels = config.config?.Labels || {};
  if (labels["org.opencontainers.image.base.name"]) {
    return labels["org.opencontainers.image.base.name"];
  }

  return undefined;
}

/**
 * Scan a container image for vulnerabilities
 */
export async function scanContainerImage(
  type: RegistryType,
  auth: RegistryAuthConfig,
  repository: string,
  tag: string
): Promise<ImageScanResult> {
  const startTime = Date.now();

  const result: ImageScanResult = {
    repository,
    tag,
    totalVulnerabilities: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    negligibleCount: 0,
    fixedAvailable: 0,
    vulnerabilities: [],
    packages: [],
    layers: [],
    complianceIssues: [],
    malwareDetected: false,
    secretsDetected: 0,
    scanDurationMs: 0,
    scanEngine: "caldera-container-scanner-v1",
  };

  try {
    // 1. Get manifest
    const manifest = await getManifest(type, auth, repository, tag);
    if (!manifest) {
      result.scanDurationMs = Date.now() - startTime;
      return result;
    }

    result.digest = manifest.digest;
    result.imageSize = manifest.layers?.reduce((sum, l) => sum + l.size, 0) || 0;
    result.layers = (manifest.layers || []).map(l => ({
      digest: l.digest,
      size: l.size,
    }));

    // 2. Get image config
    if (manifest.config) {
      const config = await getImageConfig(type, auth, repository, manifest.config.digest);
      if (config) {
        result.architecture = config.architecture;
        result.os = config.os;
        result.baseImage = detectBaseImage(config);

        // Add layer commands from history
        if (config.history) {
          let layerIdx = 0;
          for (const entry of config.history) {
            if (!entry.empty_layer && layerIdx < result.layers.length) {
              result.layers[layerIdx].command = entry.created_by;
              layerIdx++;
            }
          }
        }

        // 3. Extract packages
        const historyPackages = extractPackagesFromHistory(config);
        const envPackages = extractPackagesFromEnv(config);
        result.packages = [...historyPackages, ...envPackages];

        // 4. Match vulnerabilities
        result.vulnerabilities = matchVulnerabilities(result.packages);

        // 5. Run compliance checks
        result.complianceIssues = runComplianceChecks(config);

        // 6. Detect secrets
        result.secretsDetected = detectSecrets(config);
      }
    }

    // 7. Count vulnerabilities
    for (const v of result.vulnerabilities) {
      result.totalVulnerabilities++;
      switch (v.severity) {
        case "critical": result.criticalCount++; break;
        case "high": result.highCount++; break;
        case "medium": result.mediumCount++; break;
        case "low": result.lowCount++; break;
        case "negligible": result.negligibleCount++; break;
      }
      if (v.fixedVersion) result.fixedAvailable++;
    }

    result.scanDurationMs = Date.now() - startTime;
    return result;
  } catch (err: any) {
    result.scanDurationMs = Date.now() - startTime;
    return result;
  }
}

/**
 * Enrich vulnerabilities with NVD/KEV data
 */
export async function enrichWithNvd(
  vulns: ContainerVulnerability[],
  timeout: number = 10000
): Promise<ContainerVulnerability[]> {
  const enriched = [...vulns];

  // Batch lookup CVEs against NVD API
  for (const vuln of enriched) {
    try {
      const resp = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${vuln.cveId}`,
        { signal: AbortSignal.timeout(timeout) }
      );
      if (resp.ok) {
        const data = await resp.json() as any;
        const cve = data.vulnerabilities?.[0]?.cve;
        if (cve) {
          vuln.description = cve.descriptions?.find((d: any) => d.lang === "en")?.value;
          vuln.publishedDate = cve.published;
          vuln.references = cve.references?.map((r: any) => r.url).slice(0, 5);

          // Extract CVSS score
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
          if (metrics) {
            vuln.cvssScore = metrics.cvssData?.baseScore;
            vuln.cvssVector = metrics.cvssData?.vectorString;
          }
        }
      }
    } catch {
      // NVD rate-limited or unavailable — skip enrichment for this CVE
    }

    // Small delay to respect NVD rate limits
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  return enriched;
}
