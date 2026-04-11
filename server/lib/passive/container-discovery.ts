/**
 * Container Infrastructure Discovery Connector
 *
 * Detects exposed container infrastructure during passive/active recon:
 * - Docker Registry API v2 (port 5000, custom ports)
 * - Kubernetes API servers (port 6443, 8443, 443)
 * - Kubernetes Dashboard UI
 * - Portainer management UI (port 9000, 9443)
 * - Rancher management UI
 * - etcd key-value store (port 2379, 2380)
 * - Kubelet API (port 10250, 10255)
 * - Container runtime APIs (containerd, CRI-O)
 * - Harbor / Artifactory / Nexus registries
 *
 * Method: HTTP probing of known container service endpoints
 * Data Source: Direct HTTP/HTTPS requests to target infrastructure
 * Free: Yes, no API key required
 *
 * @module container-discovery
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// ─── Container Service Definitions ─────────────────────────────────

interface ContainerProbe {
  id: string;
  name: string;
  description: string;
  category: "registry" | "orchestrator" | "dashboard" | "runtime" | "storage";
  defaultPorts: number[];
  paths: { path: string; method: "GET" | "HEAD"; description: string }[];
  /** Response patterns that confirm the service is present */
  signatures: { type: "header" | "body" | "status"; pattern: RegExp; description: string }[];
  severity: "critical" | "high" | "medium" | "low" | "info";
  cveRefs: string[];
  mitreTechniques: string[];
  riskDescription: string;
}

const CONTAINER_PROBES: ContainerProbe[] = [
  // ── Docker Registry v2 ──
  {
    id: "docker-registry-v2",
    name: "Docker Registry API v2",
    description: "Open Docker Registry allowing image pull/push without authentication",
    category: "registry",
    defaultPorts: [5000, 5001, 443, 8080],
    paths: [
      { path: "/v2/", method: "GET", description: "Registry API root" },
      { path: "/v2/_catalog", method: "GET", description: "Image catalog listing" },
    ],
    signatures: [
      { type: "header", pattern: /docker-distribution-api-version/i, description: "Docker Distribution API header" },
      { type: "body", pattern: /"repositories"\s*:\s*\[/i, description: "Repository catalog JSON" },
      { type: "header", pattern: /registry\/2/i, description: "Registry v2 version header" },
    ],
    severity: "critical",
    cveRefs: ["CVE-2022-24769"],
    mitreTechniques: ["T1610", "T1525"],
    riskDescription: "Unauthenticated Docker Registry exposes container images, potentially containing secrets, source code, and credentials. Attackers can pull images to extract sensitive data or push malicious images for supply chain attacks.",
  },
  // ── Kubernetes API Server ──
  {
    id: "k8s-api-server",
    name: "Kubernetes API Server",
    description: "Exposed Kubernetes API server allowing cluster enumeration or control",
    category: "orchestrator",
    defaultPorts: [6443, 8443, 443, 8080],
    paths: [
      { path: "/api", method: "GET", description: "API root" },
      { path: "/api/v1", method: "GET", description: "Core API v1" },
      { path: "/version", method: "GET", description: "Cluster version info" },
      { path: "/apis", method: "GET", description: "API group listing" },
      { path: "/healthz", method: "GET", description: "Health check endpoint" },
    ],
    signatures: [
      { type: "body", pattern: /"major"\s*:\s*"\d+".*"minor"/i, description: "Kubernetes version JSON" },
      { type: "body", pattern: /apiVersion.*v1/i, description: "Kubernetes API version response" },
      { type: "body", pattern: /"kind"\s*:\s*"(APIVersions|APIGroupList|APIResourceList)"/i, description: "Kubernetes API resource response" },
      { type: "body", pattern: /kubernetes/i, description: "Kubernetes identifier in response" },
    ],
    severity: "critical",
    cveRefs: ["CVE-2018-1002105", "CVE-2019-11247", "CVE-2021-25741"],
    mitreTechniques: ["T1610", "T1609", "T1613"],
    riskDescription: "Exposed Kubernetes API server allows attackers to enumerate namespaces, pods, secrets, and potentially gain full cluster control. This is the highest-value container infrastructure target.",
  },
  // ── Kubelet API ──
  {
    id: "kubelet-api",
    name: "Kubelet API",
    description: "Exposed Kubelet API allowing pod execution and container access",
    category: "runtime",
    defaultPorts: [10250, 10255],
    paths: [
      { path: "/pods", method: "GET", description: "Running pods listing" },
      { path: "/healthz", method: "GET", description: "Kubelet health check" },
      { path: "/metrics", method: "GET", description: "Kubelet metrics (Prometheus)" },
      { path: "/spec/", method: "GET", description: "Node specification" },
    ],
    signatures: [
      { type: "body", pattern: /"kind"\s*:\s*"PodList"/i, description: "Kubernetes PodList response" },
      { type: "body", pattern: /kubelet/i, description: "Kubelet identifier" },
      { type: "body", pattern: /"metadata"\s*:.*"namespace"/i, description: "Pod metadata with namespace" },
    ],
    severity: "critical",
    cveRefs: ["CVE-2020-8558", "CVE-2021-25741"],
    mitreTechniques: ["T1609", "T1610", "T1552.007"],
    riskDescription: "Exposed Kubelet API allows attackers to list running pods, execute commands inside containers, and access mounted secrets. Port 10255 (read-only) exposes pod specs; port 10250 allows full exec access.",
  },
  // ── etcd ──
  {
    id: "etcd-exposed",
    name: "etcd Key-Value Store",
    description: "Exposed etcd cluster storing Kubernetes secrets and cluster state",
    category: "storage",
    defaultPorts: [2379, 2380, 4001],
    paths: [
      { path: "/version", method: "GET", description: "etcd version info" },
      { path: "/v2/keys/", method: "GET", description: "etcd v2 key listing" },
      { path: "/v3/kv/range", method: "GET", description: "etcd v3 key range" },
      { path: "/health", method: "GET", description: "etcd health check" },
    ],
    signatures: [
      { type: "body", pattern: /"etcdserver"\s*:/i, description: "etcd server version" },
      { type: "body", pattern: /"etcdcluster"\s*:/i, description: "etcd cluster version" },
      { type: "body", pattern: /"action"\s*:\s*"(get|set)"/i, description: "etcd v2 action response" },
    ],
    severity: "critical",
    cveRefs: ["CVE-2020-15106", "CVE-2020-15112"],
    mitreTechniques: ["T1552.007", "T1005"],
    riskDescription: "Exposed etcd stores all Kubernetes cluster state including secrets, service account tokens, and TLS certificates. Unauthenticated access grants full cluster compromise.",
  },
  // ── Kubernetes Dashboard ──
  {
    id: "k8s-dashboard",
    name: "Kubernetes Dashboard",
    description: "Exposed Kubernetes Dashboard web UI",
    category: "dashboard",
    defaultPorts: [8443, 443, 30000, 31000, 32000],
    paths: [
      { path: "/", method: "GET", description: "Dashboard root" },
      { path: "/api/v1/login/status", method: "GET", description: "Login status check" },
      { path: "/#/login", method: "GET", description: "Dashboard login page" },
    ],
    signatures: [
      { type: "body", pattern: /kubernetes.dashboard/i, description: "Kubernetes Dashboard identifier" },
      { type: "body", pattern: /dashboard.*kubernetes/i, description: "Dashboard title" },
      { type: "header", pattern: /kubernetes-dashboard/i, description: "Dashboard cookie/header" },
    ],
    severity: "high",
    cveRefs: ["CVE-2018-18264"],
    mitreTechniques: ["T1610", "T1078.004"],
    riskDescription: "Exposed Kubernetes Dashboard may allow unauthenticated cluster management. Older versions had skip-login vulnerabilities granting full admin access.",
  },
  // ── Portainer ──
  {
    id: "portainer",
    name: "Portainer Container Management",
    description: "Exposed Portainer UI for Docker/Kubernetes management",
    category: "dashboard",
    defaultPorts: [9000, 9443, 8000],
    paths: [
      { path: "/api/status", method: "GET", description: "Portainer status API" },
      { path: "/api/system/version", method: "GET", description: "Portainer version" },
      { path: "/", method: "GET", description: "Portainer UI root" },
    ],
    signatures: [
      { type: "body", pattern: /portainer/i, description: "Portainer identifier" },
      { type: "body", pattern: /"Version"\s*:\s*"/i, description: "Portainer version JSON" },
      { type: "header", pattern: /portainer/i, description: "Portainer header" },
    ],
    severity: "high",
    cveRefs: ["CVE-2022-26134", "CVE-2023-47108"],
    mitreTechniques: ["T1610", "T1078"],
    riskDescription: "Exposed Portainer allows container management including creating, starting, and accessing containers. Default installations may have weak or no authentication.",
  },
  // ── Rancher ──
  {
    id: "rancher",
    name: "Rancher Kubernetes Management",
    description: "Exposed Rancher multi-cluster Kubernetes management platform",
    category: "dashboard",
    defaultPorts: [443, 8443, 80],
    paths: [
      { path: "/v3", method: "GET", description: "Rancher API v3" },
      { path: "/v3/settings", method: "GET", description: "Rancher settings" },
      { path: "/dashboard/", method: "GET", description: "Rancher Dashboard" },
      { path: "/ping", method: "GET", description: "Rancher health ping" },
    ],
    signatures: [
      { type: "body", pattern: /rancher/i, description: "Rancher identifier" },
      { type: "body", pattern: /"type"\s*:\s*"(collection|setting)"/i, description: "Rancher API response" },
      { type: "header", pattern: /rancher/i, description: "Rancher header" },
    ],
    severity: "high",
    cveRefs: ["CVE-2021-36782", "CVE-2022-21947"],
    mitreTechniques: ["T1610", "T1078.004"],
    riskDescription: "Exposed Rancher provides multi-cluster Kubernetes management. Vulnerabilities have allowed unauthenticated admin access and credential exposure across managed clusters.",
  },
  // ── Harbor Registry ──
  {
    id: "harbor-registry",
    name: "Harbor Container Registry",
    description: "Exposed Harbor enterprise container registry",
    category: "registry",
    defaultPorts: [443, 80, 8080],
    paths: [
      { path: "/api/v2.0/systeminfo", method: "GET", description: "Harbor system info" },
      { path: "/api/v2.0/projects", method: "GET", description: "Harbor projects listing" },
      { path: "/api/v2.0/registries", method: "GET", description: "Harbor registries" },
    ],
    signatures: [
      { type: "body", pattern: /harbor/i, description: "Harbor identifier" },
      { type: "body", pattern: /"harbor_version"\s*:/i, description: "Harbor version field" },
      { type: "body", pattern: /"auth_mode"\s*:/i, description: "Harbor auth mode" },
    ],
    severity: "high",
    cveRefs: ["CVE-2019-16097", "CVE-2022-31671"],
    mitreTechniques: ["T1525", "T1610"],
    riskDescription: "Exposed Harbor registry may allow unauthenticated image browsing, pulling, or admin registration. Contains enterprise container images with potential secrets.",
  },
  // ── Docker Engine API ──
  {
    id: "docker-engine-api",
    name: "Docker Engine API",
    description: "Exposed Docker daemon API allowing full container control",
    category: "runtime",
    defaultPorts: [2375, 2376, 4243],
    paths: [
      { path: "/version", method: "GET", description: "Docker version" },
      { path: "/info", method: "GET", description: "Docker system info" },
      { path: "/containers/json", method: "GET", description: "Running containers" },
      { path: "/images/json", method: "GET", description: "Available images" },
    ],
    signatures: [
      { type: "body", pattern: /"ApiVersion"\s*:\s*"/i, description: "Docker API version" },
      { type: "body", pattern: /"Os"\s*:\s*"linux"/i, description: "Docker OS info" },
      { type: "body", pattern: /"KernelVersion"\s*:/i, description: "Docker kernel version" },
      { type: "body", pattern: /"Containers"\s*:\s*\d+/i, description: "Docker container count" },
    ],
    severity: "critical",
    cveRefs: ["CVE-2019-5736", "CVE-2020-15257"],
    mitreTechniques: ["T1610", "T1609", "T1611"],
    riskDescription: "Exposed Docker Engine API grants full control over the Docker daemon — create containers, mount host filesystem, execute commands. This is equivalent to root access on the host.",
  },
  // ── Nexus Repository ──
  {
    id: "nexus-repository",
    name: "Sonatype Nexus Repository",
    description: "Exposed Nexus repository manager with container registry support",
    category: "registry",
    defaultPorts: [8081, 8082, 8083, 443],
    paths: [
      { path: "/service/rest/v1/status", method: "GET", description: "Nexus status" },
      { path: "/service/rest/v1/repositories", method: "GET", description: "Repository listing" },
      { path: "/v2/", method: "GET", description: "Docker registry endpoint" },
    ],
    signatures: [
      { type: "body", pattern: /nexus/i, description: "Nexus identifier" },
      { type: "body", pattern: /"edition"\s*:/i, description: "Nexus edition info" },
      { type: "header", pattern: /nexus/i, description: "Nexus server header" },
    ],
    severity: "high",
    cveRefs: ["CVE-2020-36518", "CVE-2019-7238"],
    mitreTechniques: ["T1525", "T1195.002"],
    riskDescription: "Exposed Nexus Repository may allow anonymous browsing of container images, Maven artifacts, npm packages, and other software components. Supply chain attack vector.",
  },
  // ── JFrog Artifactory ──
  {
    id: "artifactory",
    name: "JFrog Artifactory",
    description: "Exposed JFrog Artifactory with container registry capabilities",
    category: "registry",
    defaultPorts: [8081, 8082, 443, 80],
    paths: [
      { path: "/api/system/ping", method: "GET", description: "Artifactory health" },
      { path: "/api/system/version", method: "GET", description: "Artifactory version" },
      { path: "/api/repositories", method: "GET", description: "Repository listing" },
    ],
    signatures: [
      { type: "body", pattern: /artifactory/i, description: "Artifactory identifier" },
      { type: "body", pattern: /"version"\s*:\s*"\d+\.\d+/i, description: "Artifactory version" },
      { type: "header", pattern: /artifactory/i, description: "Artifactory header" },
    ],
    severity: "high",
    cveRefs: ["CVE-2019-9733", "CVE-2022-0543"],
    mitreTechniques: ["T1525", "T1195.002"],
    riskDescription: "Exposed Artifactory may allow anonymous access to container images, build artifacts, and software packages. Critical supply chain risk.",
  },
];

// ─── Probe Execution ───────────────────────────────────────────────

interface ProbeHit {
  probe: ContainerProbe;
  port: number;
  path: string;
  matchedSignatures: string[];
  responseSnippet: string;
  statusCode: number;
  authenticated: boolean;
  version?: string;
}

async function probeEndpoint(
  host: string,
  port: number,
  path: string,
  method: "GET" | "HEAD",
  timeout: number
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  const protocol = [443, 6443, 8443, 9443, 2376].includes(port) ? "https" : "http";
  const url = `${protocol}://${host}:${port}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      method,
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Accept": "application/json, text/html, */*",
      },
    });
    clearTimeout(timer);
    const body = await res.text().catch(() => "");
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, headers, body: body.slice(0, 4096) };
  } catch {
    clearTimeout(timer);
    return null;
  }
}

function checkSignatures(
  probe: ContainerProbe,
  response: { status: number; headers: Record<string, string>; body: string }
): string[] {
  const matched: string[] = [];
  for (const sig of probe.signatures) {
    if (sig.type === "header") {
      const headerStr = Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
      if (sig.pattern.test(headerStr)) matched.push(sig.description);
    } else if (sig.type === "body") {
      if (sig.pattern.test(response.body)) matched.push(sig.description);
    } else if (sig.type === "status") {
      if (sig.pattern.test(String(response.status))) matched.push(sig.description);
    }
  }
  return matched;
}

function extractVersion(body: string): string | undefined {
  // Try common version patterns in JSON responses
  const patterns = [
    /"(?:version|gitVersion|harbor_version|ApiVersion|etcdserver)"\s*:\s*"([^"]+)"/i,
    /"(?:major|Minor)"\s*:\s*"(\d+)"/i,
    /Version:\s*v?(\d+\.\d+[.\d]*)/i,
  ];
  for (const p of patterns) {
    const m = p.exec(body);
    if (m) return m[1];
  }
  return undefined;
}

async function runProbe(
  host: string,
  probe: ContainerProbe,
  timeout: number
): Promise<ProbeHit[]> {
  const hits: ProbeHit[] = [];

  for (const port of probe.defaultPorts) {
    for (const { path, method, description } of probe.paths) {
      const response = await probeEndpoint(host, port, path, method, timeout);
      if (!response) continue;

      // Skip 404, 502, 503 — service not present
      if ([404, 502, 503].includes(response.status)) continue;

      const matchedSignatures = checkSignatures(probe, response);
      if (matchedSignatures.length === 0) continue;

      const authenticated = response.status !== 401 && response.status !== 403;
      const version = extractVersion(response.body);

      hits.push({
        probe,
        port,
        path,
        matchedSignatures,
        responseSnippet: response.body.slice(0, 512),
        statusCode: response.status,
        authenticated,
        version,
      });

      // Found on this port, skip remaining paths for this port
      break;
    }
  }

  return hits;
}

// ─── Subdomain Candidates for Container Infrastructure ─────────────

function generateContainerSubdomains(domain: string): string[] {
  const prefixes = [
    "registry", "docker", "containers", "images",
    "k8s", "kubernetes", "kube", "cluster",
    "rancher", "portainer", "harbor",
    "nexus", "artifactory", "repo",
    "etcd", "api", "dashboard",
    "docker-registry", "container-registry",
    "cr", "gcr", "ecr", "acr",
  ];
  return prefixes.map(p => `${p}.${domain}`);
}

// ─── Main Connector ────────────────────────────────────────────────

export const containerDiscoveryConnector: PassiveConnector = {
  name: "container-discovery",
  description: "Discovers exposed container infrastructure (Docker registries, Kubernetes APIs, management dashboards, etcd, Kubelet)",
  requiresApiKey: false,
  freeUrl: "https://kubernetes.io/docs/reference/",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const timeout = Math.min(config?.timeout ?? 3000, 2000); // Cap per-probe at 2s
    const globalTimeout = Math.min(config?.timeout ? config.timeout * 8 : 25000, 25000); // 25s max
    const startTime = Date.now();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];

    // Generate candidate hostnames and DNS-filter to skip non-resolving ones
    const rawCandidates = [domain, ...generateContainerSubdomains(domain)];
    const candidates: string[] = [];
    
    // Phase 1: Quick DNS resolution check — only probe hosts that actually resolve
    // This eliminates ~90% of probes on external targets with no container subdomains
    const DNS_CHECK_CONCURRENCY = 15;
    for (let i = 0; i < rawCandidates.length; i += DNS_CHECK_CONCURRENCY) {
      if (Date.now() - startTime > globalTimeout * 0.3) break; // Don't spend >30% of budget on DNS
      const batch = rawCandidates.slice(i, i + DNS_CHECK_CONCURRENCY);
      const results = await Promise.allSettled(
        batch.map(async (host) => {
          try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 1500);
            // Quick HEAD to check if host resolves at all
            await fetch(`https://${host}`, { method: 'HEAD', signal: controller.signal, redirect: 'manual' }).catch(() => 
              fetch(`http://${host}`, { method: 'HEAD', signal: controller.signal, redirect: 'manual' })
            );
            clearTimeout(timer);
            return host;
          } catch {
            return null;
          }
        })
      );
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) candidates.push(r.value);
      }
    }
    
    // Always include the primary domain even if DNS check failed
    if (!candidates.includes(domain)) candidates.unshift(domain);
    
    console.log(`[ContainerDiscovery] DNS pre-check: ${candidates.length}/${rawCandidates.length} candidates resolve`);
    
    const allHits: ProbeHit[] = [];

    // Probe each candidate with all container probes
    // Limit concurrency to avoid overwhelming targets
    const CONCURRENCY = 10;
    const probeQueue: Array<{ host: string; probe: ContainerProbe }> = [];
    for (const host of candidates) {
      for (const probe of CONTAINER_PROBES) {
        probeQueue.push({ host, probe });
      }
    }

    // Process in batches with global timeout
    let probesCompleted = 0;
    for (let i = 0; i < probeQueue.length; i += CONCURRENCY) {
      const elapsed = Date.now() - startTime;
      if (elapsed > globalTimeout) {
        console.log(`[ContainerDiscovery] Global timeout reached after ${probesCompleted}/${probeQueue.length} probes (${elapsed}ms)`);
        errors.push(`Scan truncated: completed ${probesCompleted}/${probeQueue.length} probes before ${globalTimeout}ms timeout`);
        break;
      }
      const batch = probeQueue.slice(i, i + CONCURRENCY);
      const results = await Promise.allSettled(
        batch.map(({ host, probe }) => runProbe(host, probe, timeout))
      );
      probesCompleted += batch.length;
      for (const result of results) {
        if (result.status === "fulfilled") {
          allHits.push(...result.value);
        }
      }
      // Respect rate limiting
      if (i + CONCURRENCY < probeQueue.length) {
        await new Promise(r => setTimeout(r, 100));
      }
    }

    // Convert hits to observations
    for (const hit of allHits) {
      const host = candidates.find(c =>
        allHits.some(h => h === hit)
      ) || domain;

      const assetId = makeAssetId(domain, `${hit.probe.id}:${hit.port}`, "container-discovery");

      const accessLevel = hit.authenticated ? "UNAUTHENTICATED_ACCESS" : "AUTHENTICATION_REQUIRED";
      const severityLabel = hit.authenticated ? hit.probe.severity : "medium";

      observations.push({
        assetId,
        domain,
        assetType: "url",
        name: `${hit.probe.name} (port ${hit.port})`,
        source: "container-discovery",
        observedAt: new Date(),
        tags: [
          "container-infrastructure",
          hit.probe.category,
          accessLevel.toLowerCase().replace(/_/g, "-"),
          ...hit.probe.mitreTechniques.map(t => `mitre:${t}`),
          ...(hit.version ? [`version:${hit.version}`] : []),
        ],
        evidence: {
          probeId: hit.probe.id,
          probeName: hit.probe.name,
          category: hit.probe.category,
          port: hit.port,
          path: hit.path,
          statusCode: hit.statusCode,
          authenticated: hit.authenticated,
          accessLevel,
          matchedSignatures: hit.matchedSignatures,
          responseSnippet: hit.responseSnippet,
          version: hit.version,
          severity: severityLabel,
          riskDescription: hit.probe.riskDescription,
          cveRefs: hit.probe.cveRefs,
          mitreTechniques: hit.probe.mitreTechniques,
        },
        attribution: {
          provider: "Container Infrastructure Scanner",
          method: `HTTP ${hit.path} probe on port ${hit.port} matched ${hit.matchedSignatures.length} signature(s): ${hit.matchedSignatures.join(", ")}`,
          url: `https://${domain}:${hit.port}${hit.path}`,
        },
      });
    }

    return {
      connector: "container-discovery",
      domain,
      observations,
      errors,
      durationMs: Date.now() - startTime,
      rateLimited: false,
    };
  },
};

// ─── Standalone Analysis Function ──────────────────────────────────

export interface ContainerDiscoveryResult {
  totalProbes: number;
  totalHits: number;
  criticalFindings: number;
  highFindings: number;
  findings: Array<{
    service: string;
    category: string;
    port: number;
    path: string;
    severity: string;
    authenticated: boolean;
    version?: string;
    matchedSignatures: string[];
    riskDescription: string;
    cveRefs: string[];
    mitreTechniques: string[];
  }>;
  subdomainsProbed: string[];
  durationMs: number;
}

export async function analyzeContainerExposure(
  domain: string,
  additionalHosts?: string[],
  timeout = 3000,
  globalTimeoutMs = 60000
): Promise<ContainerDiscoveryResult> {
  const startTime = Date.now();
  const candidates = [
    domain,
    ...generateContainerSubdomains(domain),
    ...(additionalHosts || []),
  ];
  const uniqueCandidates = Array.from(new Set(candidates)).slice(0, 5); // Cap at 5 hosts to limit probe count

  const allHits: ProbeHit[] = [];
  const CONCURRENCY = 5;
  const MAX_TOTAL_PROBES = 60; // Safety cap: 5 hosts x 11 probes = 55 max
  const probeQueue: Array<{ host: string; probe: ContainerProbe }> = [];
  for (const host of uniqueCandidates) {
    for (const probe of CONTAINER_PROBES) {
      if (probeQueue.length >= MAX_TOTAL_PROBES) break;
      probeQueue.push({ host, probe });
    }
    if (probeQueue.length >= MAX_TOTAL_PROBES) break;
  }

  let probesCompleted = 0;
  for (let i = 0; i < probeQueue.length; i += CONCURRENCY) {
    // Global timeout check — stop probing if we've exceeded the time budget
    if (Date.now() - startTime > globalTimeoutMs) {
      console.log(`[ContainerDiscovery] Global timeout (${globalTimeoutMs}ms) reached after ${probesCompleted}/${probeQueue.length} probes`);
      break;
    }

    const batch = probeQueue.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(({ host, probe }) => runProbe(host, probe, timeout))
    );
    probesCompleted += batch.length;
    for (const result of results) {
      if (result.status === "fulfilled") {
        allHits.push(...result.value);
      }
    }
    // Small delay between batches to avoid overwhelming targets
    if (i + CONCURRENCY < probeQueue.length) {
      await new Promise(r => setTimeout(r, 100));
    }
  }

  return {
    totalProbes: probesCompleted,
    totalHits: allHits.length,
    criticalFindings: allHits.filter(h => h.probe.severity === "critical" && h.authenticated).length,
    highFindings: allHits.filter(h => h.probe.severity === "high").length,
    findings: allHits.map(h => ({
      service: h.probe.name,
      category: h.probe.category,
      port: h.port,
      path: h.path,
      severity: h.authenticated ? h.probe.severity : "medium",
      authenticated: h.authenticated,
      version: h.version,
      matchedSignatures: h.matchedSignatures,
      riskDescription: h.probe.riskDescription,
      cveRefs: h.probe.cveRefs,
      mitreTechniques: h.probe.mitreTechniques,
    })),
    subdomainsProbed: uniqueCandidates,
    durationMs: Date.now() - startTime,
  };
}
