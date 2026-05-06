// server/lib/container-registry-service.ts
function getRegistryBaseUrl(type, auth) {
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
async function getAuthToken(type, auth, scope) {
  switch (type) {
    case "docker_hub": {
      const tokenUrl = `https://auth.docker.io/token?service=registry.docker.io&scope=${scope || "registry:catalog:*"}`;
      const headers = {};
      if (auth.username && auth.password) {
        headers["Authorization"] = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString("base64")}`;
      }
      const resp = await fetch(tokenUrl, { headers, signal: AbortSignal.timeout(1e4) });
      if (!resp.ok) throw new Error(`Docker Hub auth failed: ${resp.status}`);
      const data = await resp.json();
      return data.token;
    }
    case "ecr": {
      if (auth.awsAccessKeyId && auth.awsSecretAccessKey) {
        const region = auth.awsRegion || "us-east-1";
        const endpoint = `https://api.ecr.${region}.amazonaws.com`;
        return Buffer.from(`AWS:${auth.awsSecretAccessKey}`).toString("base64");
      }
      throw new Error("ECR requires awsAccessKeyId and awsSecretAccessKey");
    }
    case "acr": {
      if (auth.azureClientId && auth.azureClientSecret && auth.azureTenantId) {
        const tokenUrl = `https://login.microsoftonline.com/${auth.azureTenantId}/oauth2/v2.0/token`;
        const body = new URLSearchParams({
          grant_type: "client_credentials",
          client_id: auth.azureClientId,
          client_secret: auth.azureClientSecret,
          scope: "https://management.azure.com/.default"
        });
        const resp = await fetch(tokenUrl, {
          method: "POST",
          body,
          signal: AbortSignal.timeout(1e4)
        });
        if (!resp.ok) throw new Error(`ACR auth failed: ${resp.status}`);
        const data = await resp.json();
        return data.access_token;
      }
      if (auth.username && auth.password) {
        return Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
      }
      throw new Error("ACR requires credentials");
    }
    case "gcr": {
      if (auth.gcpServiceAccountJson) {
        try {
          const sa = JSON.parse(auth.gcpServiceAccountJson);
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
      if (auth.token) return auth.token;
      if (auth.username && auth.password) {
        return Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
      }
      throw new Error("Registry requires username/password or token");
    }
  }
}
async function registryFetch(url, token, type, options) {
  const headers = {
    Accept: options?.accept || "application/vnd.docker.distribution.manifest.v2+json"
  };
  if (type === "docker_hub" || type === "ghcr") {
    headers["Authorization"] = `Bearer ${token}`;
  } else {
    headers["Authorization"] = `Basic ${token}`;
  }
  return fetch(url, {
    headers,
    signal: AbortSignal.timeout(options?.timeout || 15e3)
  });
}
async function testRegistryConnection(type, auth) {
  const startTime = Date.now();
  const baseUrl = getRegistryBaseUrl(type, auth);
  if (!baseUrl) {
    return {
      success: false,
      registryType: type,
      registryUrl: "",
      message: "Registry URL could not be determined",
      error: "Missing registry URL or customUrl"
    };
  }
  try {
    const token = await getAuthToken(type, auth, "registry:catalog:*");
    const catalogUrl = type === "docker_hub" ? `https://hub.docker.com/v2/repositories/${auth.username || "library"}/?page_size=1` : `${baseUrl}/v2/_catalog?n=5`;
    const resp = await registryFetch(catalogUrl, token, type, {
      accept: "application/json",
      timeout: 1e4
    });
    const latency = Date.now() - startTime;
    if (resp.ok) {
      const data = await resp.json();
      const repoCount = data.repositories?.length || data.count || data.results?.length || 0;
      return {
        success: true,
        registryType: type,
        registryUrl: baseUrl,
        message: `Successfully connected to ${type} registry`,
        repoCount,
        latency
      };
    }
    if (resp.status === 401 || resp.status === 403) {
      const v2Resp = await registryFetch(`${baseUrl}/v2/`, token, type, { timeout: 5e3 });
      if (v2Resp.ok || v2Resp.status === 401) {
        return {
          success: true,
          registryType: type,
          registryUrl: baseUrl,
          message: `Connected to ${type} registry (catalog access restricted, image pull may still work)`,
          latency: Date.now() - startTime
        };
      }
    }
    return {
      success: false,
      registryType: type,
      registryUrl: baseUrl,
      message: `Registry returned status ${resp.status}`,
      latency,
      error: `HTTP ${resp.status}: ${resp.statusText}`
    };
  } catch (err) {
    return {
      success: false,
      registryType: type,
      registryUrl: baseUrl,
      message: `Connection failed: ${err.message}`,
      latency: Date.now() - startTime,
      error: err.message
    };
  }
}
async function listRepositories(type, auth, options) {
  const baseUrl = getRegistryBaseUrl(type, auth);
  const limit = options?.limit || 100;
  try {
    const token = await getAuthToken(type, auth, "registry:catalog:*");
    if (type === "docker_hub") {
      const namespace = options?.namespace || auth.username || "library";
      const url = `https://hub.docker.com/v2/repositories/${namespace}/?page_size=${limit}`;
      const resp2 = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(15e3)
      });
      if (!resp2.ok) return [];
      const data2 = await resp2.json();
      return (data2.results || []).map((r) => ({
        name: r.name,
        fullName: `${namespace}/${r.name}`,
        description: r.description,
        lastPushed: r.last_updated,
        isPrivate: r.is_private
      }));
    }
    const catalogUrl = `${baseUrl}/v2/_catalog?n=${limit}`;
    const resp = await registryFetch(catalogUrl, token, type, { accept: "application/json" });
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data.repositories || []).map((name) => ({
      name: name.split("/").pop() || name,
      fullName: name
    }));
  } catch {
    return [];
  }
}
async function listTags(type, auth, repository, options) {
  const baseUrl = getRegistryBaseUrl(type, auth);
  const limit = options?.limit || 50;
  try {
    const scope = `repository:${repository}:pull`;
    const token = await getAuthToken(type, auth, scope);
    if (type === "docker_hub") {
      const url = `https://hub.docker.com/v2/repositories/${repository}/tags/?page_size=${limit}`;
      const resp2 = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(15e3)
      });
      if (!resp2.ok) return [];
      const data2 = await resp2.json();
      return (data2.results || []).map((t) => ({
        name: t.name,
        digest: t.digest,
        size: t.full_size,
        lastModified: t.last_updated
      }));
    }
    const tagsUrl = `${baseUrl}/v2/${repository}/tags/list?n=${limit}`;
    const resp = await registryFetch(tagsUrl, token, type, { accept: "application/json" });
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data.tags || []).map((name) => ({ name }));
  } catch {
    return [];
  }
}
async function getManifest(type, auth, repository, tag) {
  const baseUrl = getRegistryBaseUrl(type, auth);
  try {
    const scope = `repository:${repository}:pull`;
    const token = await getAuthToken(type, auth, scope);
    const manifestUrl = `${baseUrl}/v2/${repository}/manifests/${tag}`;
    const resp = await registryFetch(manifestUrl, token, type, {
      accept: "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
    });
    if (!resp.ok) return null;
    const manifest = await resp.json();
    manifest.digest = resp.headers.get("docker-content-digest") || "";
    return manifest;
  } catch {
    return null;
  }
}
async function getImageConfig(type, auth, repository, configDigest) {
  const baseUrl = getRegistryBaseUrl(type, auth);
  try {
    const scope = `repository:${repository}:pull`;
    const token = await getAuthToken(type, auth, scope);
    const blobUrl = `${baseUrl}/v2/${repository}/blobs/${configDigest}`;
    const resp = await registryFetch(blobUrl, token, type, {
      accept: "application/vnd.docker.container.image.v1+json, application/vnd.oci.image.config.v1+json"
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}
var VULN_DB_PATTERNS = [
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
  { ecosystem: "java", package: "log4j-core", versionPattern: /^2\.(0|1[0-6])\./, cve: "CVE-2021-44228", severity: "critical", title: "Log4Shell Remote Code Execution", fixedVersion: "2.17.1", cvssScore: 10 },
  { ecosystem: "java", package: "spring-core", versionPattern: /^5\.[0-2]\./, cve: "CVE-2022-22965", severity: "critical", title: "Spring4Shell RCE", fixedVersion: "5.3.18", cvssScore: 9.8 },
  { ecosystem: "ruby", package: "rack", versionPattern: /^[0-2]\./, cve: "CVE-2023-27539", severity: "medium", title: "Rack ReDoS in Content-Type Header", fixedVersion: "3.0.4.2", cvssScore: 5.3 }
];
function extractPackagesFromHistory(config) {
  const packages = [];
  const seen = /* @__PURE__ */ new Set();
  if (!config.history) return packages;
  for (const entry of config.history) {
    const cmd = entry.created_by || "";
    const aptMatch = cmd.match(/apt-get\s+install\s+(?:-[a-z]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (aptMatch) {
      const pkgs = aptMatch[1].split(/\s+/).filter((p) => !p.startsWith("-") && p.length > 1);
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
    const yumMatch = cmd.match(/(?:yum|dnf)\s+install\s+(?:-[a-z]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (yumMatch) {
      const pkgs = yumMatch[1].split(/\s+/).filter((p) => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const cleanPkg = pkg.replace(/[-=<>].+/, "");
        const key = `os:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version: "unknown", type: "os" });
        }
      }
    }
    const apkMatch = cmd.match(/apk\s+add\s+(?:--[a-z-]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (apkMatch) {
      const pkgs = apkMatch[1].split(/\s+/).filter((p) => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const cleanPkg = pkg.replace(/[=<>~].+/, "");
        const key = `os:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version: "unknown", type: "os" });
        }
      }
    }
    const pipMatch = cmd.match(/pip3?\s+install\s+(?:--[a-z-]+(?:\s+\S+)?\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (pipMatch) {
      const pkgs = pipMatch[1].split(/\s+/).filter((p) => !p.startsWith("-") && p.length > 1);
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
    const npmMatch = cmd.match(/npm\s+install\s+(?:--[a-z-]+\s+)*(.+?)(?:\s*&&|\s*$)/i);
    if (npmMatch) {
      const pkgs = npmMatch[1].split(/\s+/).filter((p) => !p.startsWith("-") && p.length > 1);
      for (const pkg of pkgs) {
        const parts = pkg.split("@");
        const cleanPkg = parts.length > 2 ? `@${parts[1]}` : parts[0];
        const version = parts.length > 2 ? parts[2] : parts[1] || "unknown";
        const key = `npm:${cleanPkg}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: cleanPkg, version, type: "npm" });
        }
      }
    }
    const goMatch = cmd.match(/go\s+(?:install|get)\s+(.+?)(?:\s*&&|\s*$)/i);
    if (goMatch) {
      const pkgs = goMatch[1].split(/\s+/).filter((p) => p.includes("/"));
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
  for (const entry of config.history) {
    const cmd = entry.created_by || "";
    if (cmd.includes("FROM") || entry.comment?.includes("FROM")) {
      break;
    }
  }
  return packages;
}
function extractPackagesFromEnv(config) {
  const packages = [];
  const env = config.config?.Env || [];
  for (const e of env) {
    const versionMatch = e.match(/^(PYTHON|NODE|GOLANG|RUBY|JAVA|DOTNET)_VERSION=(.+)$/);
    if (versionMatch) {
      const typeMap = {
        PYTHON: "python",
        NODE: "npm",
        GOLANG: "go",
        RUBY: "ruby",
        JAVA: "java",
        DOTNET: "dotnet"
      };
      packages.push({
        name: versionMatch[1].toLowerCase(),
        version: versionMatch[2],
        type: typeMap[versionMatch[1]] || "os",
        source: "environment"
      });
    }
  }
  return packages;
}
function matchVulnerabilities(packages) {
  const vulns = [];
  const seen = /* @__PURE__ */ new Set();
  for (const pkg of packages) {
    for (const pattern of VULN_DB_PATTERNS) {
      const ecosystemMatch = pattern.ecosystem === pkg.type || pattern.ecosystem === "os" && pkg.type === "os";
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
            cvssScore: pattern.cvssScore
          });
        }
      }
    }
  }
  return vulns;
}
function runComplianceChecks(config) {
  const checks = [];
  const user = config.config?.User;
  checks.push({
    check: "CIS 4.1 - Container runs as non-root user",
    status: user && user !== "root" && user !== "0" ? "pass" : "fail",
    detail: user ? `Runs as user: ${user}` : "No USER instruction found \u2014 container runs as root"
  });
  const hasHealthcheck = config.history?.some((h) => (h.created_by || "").includes("HEALTHCHECK"));
  checks.push({
    check: "CIS 4.6 - HEALTHCHECK instruction present",
    status: hasHealthcheck ? "pass" : "fail",
    detail: hasHealthcheck ? "HEALTHCHECK instruction found" : "No HEALTHCHECK instruction \u2014 container health cannot be monitored"
  });
  const usesAdd = config.history?.some((h) => (h.created_by || "").match(/\bADD\b/) && !(h.created_by || "").includes("ADD file:"));
  checks.push({
    check: "CIS 4.9 - COPY used instead of ADD",
    status: usesAdd ? "fail" : "pass",
    detail: usesAdd ? "ADD instruction found \u2014 prefer COPY for local files" : "No problematic ADD instructions found"
  });
  const exposedPorts = Object.keys(config.config?.ExposedPorts || {});
  const privilegedPorts = exposedPorts.filter((p) => {
    const port = parseInt(p.split("/")[0]);
    return port < 1024 && port !== 80 && port !== 443;
  });
  checks.push({
    check: "CIS 4.7 - No unnecessary privileged ports exposed",
    status: privilegedPorts.length === 0 ? "pass" : "fail",
    detail: privilegedPorts.length > 0 ? `Privileged ports exposed: ${privilegedPorts.join(", ")}` : "No unnecessary privileged ports exposed"
  });
  const sensitiveEnvPatterns = /password|secret|key|token|credential|api_key/i;
  const sensitiveEnvs = (config.config?.Env || []).filter((e) => sensitiveEnvPatterns.test(e.split("=")[0]));
  checks.push({
    check: "CIS 4.10 - No secrets stored in environment variables",
    status: sensitiveEnvs.length === 0 ? "pass" : "fail",
    detail: sensitiveEnvs.length > 0 ? `${sensitiveEnvs.length} potentially sensitive env vars found: ${sensitiveEnvs.map((e) => e.split("=")[0]).join(", ")}` : "No sensitive environment variables detected"
  });
  const usesLatest = config.history?.some((h) => (h.created_by || "").includes(":latest"));
  checks.push({
    check: "Best Practice - Avoid using 'latest' tag",
    status: usesLatest ? "fail" : "pass",
    detail: usesLatest ? "Image references ':latest' tag \u2014 use specific version tags for reproducibility" : "No ':latest' tag references found"
  });
  return checks;
}
function detectSecrets(config) {
  let secretCount = 0;
  const secretPatterns = [
    /(?:password|passwd|pwd)\s*=\s*\S+/i,
    /(?:api[_-]?key|apikey)\s*=\s*\S+/i,
    /(?:secret|token)\s*=\s*\S+/i,
    /(?:aws_access_key_id|aws_secret_access_key)\s*=\s*\S+/i,
    /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
    /ghp_[a-zA-Z0-9]{36}/,
    /sk-[a-zA-Z0-9]{48}/
  ];
  const allText = [
    ...config.config?.Env || [],
    ...(config.history || []).map((h) => h.created_by || "")
  ].join("\n");
  for (const pattern of secretPatterns) {
    const matches = allText.match(new RegExp(pattern, "g"));
    if (matches) secretCount += matches.length;
  }
  return secretCount;
}
function detectBaseImage(config) {
  if (!config.history || config.history.length === 0) return void 0;
  const firstEntry = config.history[0];
  const cmd = firstEntry.created_by || firstEntry.comment || "";
  const fromMatch = cmd.match(/FROM\s+(\S+)/i);
  if (fromMatch) return fromMatch[1];
  const labels = config.config?.Labels || {};
  if (labels["org.opencontainers.image.base.name"]) {
    return labels["org.opencontainers.image.base.name"];
  }
  return void 0;
}
async function scanContainerImage(type, auth, repository, tag) {
  const startTime = Date.now();
  const result = {
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
    scanEngine: "caldera-container-scanner-v1"
  };
  try {
    const manifest = await getManifest(type, auth, repository, tag);
    if (!manifest) {
      result.scanDurationMs = Date.now() - startTime;
      return result;
    }
    result.digest = manifest.digest;
    result.imageSize = manifest.layers?.reduce((sum, l) => sum + l.size, 0) || 0;
    result.layers = (manifest.layers || []).map((l) => ({
      digest: l.digest,
      size: l.size
    }));
    if (manifest.config) {
      const config = await getImageConfig(type, auth, repository, manifest.config.digest);
      if (config) {
        result.architecture = config.architecture;
        result.os = config.os;
        result.baseImage = detectBaseImage(config);
        if (config.history) {
          let layerIdx = 0;
          for (const entry of config.history) {
            if (!entry.empty_layer && layerIdx < result.layers.length) {
              result.layers[layerIdx].command = entry.created_by;
              layerIdx++;
            }
          }
        }
        const historyPackages = extractPackagesFromHistory(config);
        const envPackages = extractPackagesFromEnv(config);
        result.packages = [...historyPackages, ...envPackages];
        result.vulnerabilities = matchVulnerabilities(result.packages);
        result.complianceIssues = runComplianceChecks(config);
        result.secretsDetected = detectSecrets(config);
      }
    }
    for (const v of result.vulnerabilities) {
      result.totalVulnerabilities++;
      switch (v.severity) {
        case "critical":
          result.criticalCount++;
          break;
        case "high":
          result.highCount++;
          break;
        case "medium":
          result.mediumCount++;
          break;
        case "low":
          result.lowCount++;
          break;
        case "negligible":
          result.negligibleCount++;
          break;
      }
      if (v.fixedVersion) result.fixedAvailable++;
    }
    result.scanDurationMs = Date.now() - startTime;
    return result;
  } catch (err) {
    result.scanDurationMs = Date.now() - startTime;
    return result;
  }
}
async function enrichWithNvd(vulns, timeout = 1e4) {
  const enriched = [...vulns];
  for (const vuln of enriched) {
    try {
      const resp = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${vuln.cveId}`,
        { signal: AbortSignal.timeout(timeout) }
      );
      if (resp.ok) {
        const data = await resp.json();
        const cve = data.vulnerabilities?.[0]?.cve;
        if (cve) {
          vuln.description = cve.descriptions?.find((d) => d.lang === "en")?.value;
          vuln.publishedDate = cve.published;
          vuln.references = cve.references?.map((r) => r.url).slice(0, 5);
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
          if (metrics) {
            vuln.cvssScore = metrics.cvssData?.baseScore;
            vuln.cvssVector = metrics.cvssData?.vectorString;
          }
        }
      }
    } catch {
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return enriched;
}

export {
  testRegistryConnection,
  listRepositories,
  listTags,
  getManifest,
  getImageConfig,
  scanContainerImage,
  enrichWithNvd
};
