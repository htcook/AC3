/**
 * ScanForge Cloud Infrastructure Scanners
 *
 * Protocol scanners for cloud-native services and misconfigurations:
 *   - AWS IMDS (Instance Metadata Service) — SSRF to metadata endpoint
 *   - Cloud Storage (S3/GCS/Azure Blob) — Public bucket enumeration
 *   - Cloud API Gateway — Misconfigured endpoints
 *   - Kubernetes API — Unauthenticated access
 *   - Docker API — Exposed daemon
 *   - Container Registry — Anonymous pull access
 *   - etcd — Unauthenticated key-value store
 *
 * These scanners detect cloud-specific misconfigurations that traditional
 * network scanners miss. They use HTTP-based probing (no cloud SDK required)
 * to identify exposed cloud services from an external attacker perspective.
 */

import { randomUUID } from "crypto";
import type { ProtocolScanner, ScanTarget, ScanConfig, ScanFinding } from "../types";

// ─── AWS IMDS Scanner ─────────────────────────────────────────────────────

export class AWSIMDSScanner implements ProtocolScanner {
  name = "AWS IMDS Scanner";
  protocol = "aws-imds";
  defaultPorts = [80, 443];
  environments = ["cloud" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 10) * 1000;

    // Check for SSRF to IMDS v1 (no token required)
    const imdsEndpoints = [
      { path: "/latest/meta-data/", desc: "Instance metadata root" },
      { path: "/latest/meta-data/iam/security-credentials/", desc: "IAM role credentials" },
      { path: "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", desc: "EC2 identity credentials" },
      { path: "/latest/user-data", desc: "User data (may contain secrets)" },
    ];

    for (const endpoint of imdsEndpoints) {
      try {
        const response = await fetch(`http://${host}${endpoint.path}`, {
          headers: { "Host": "169.254.169.254" },
          signal: AbortSignal.timeout(timeout),
          redirect: "manual",
        });

        if (response.status === 200) {
          const body = await response.text();
          if (body.length > 0 && !body.includes("<!DOCTYPE")) {
            findings.push({
              id: randomUUID(),
              source: "cloud:aws-imds",
              title: `AWS IMDS Accessible: ${endpoint.desc}`,
              description: `The AWS Instance Metadata Service (IMDS) endpoint ${endpoint.path} is accessible via ${host}. This indicates either a direct IMDS exposure or an SSRF vulnerability that can reach the metadata service. IMDSv1 does not require a token, allowing credential theft.`,
              severity: endpoint.path.includes("security-credentials") ? "critical" : "high",
              confidence: 90,
              target: host,
              port: 80,
              protocol: "http",
              cves: [],
              cwes: ["CWE-918", "CWE-200"],
              techniqueIds: ["T1552.005", "T1078.004"],
              evidence: {
                request: `GET ${endpoint.path} HTTP/1.1\nHost: 169.254.169.254`,
                response: body.substring(0, 2000),
                matchedPattern: "IMDS response with metadata content",
              },
              remediation: "Enforce IMDSv2 (token-required) on all EC2 instances. Block IMDS access from containers. Use VPC endpoints and security groups to restrict metadata access. Patch SSRF vulnerabilities in web applications.",
              environment: "cloud",
              foundAt: Date.now(),
            });
          }
        }
      } catch {
        // Connection failure is expected for non-AWS targets
      }
    }

    // Check for IMDSv2 enforcement
    try {
      const tokenResponse = await fetch(`http://${host}/latest/api/token`, {
        method: "PUT",
        headers: {
          "Host": "169.254.169.254",
          "X-aws-ec2-metadata-token-ttl-seconds": "21600",
        },
        signal: AbortSignal.timeout(timeout),
      });

      if (tokenResponse.status === 200) {
        findings.push({
          id: randomUUID(),
          source: "cloud:aws-imds",
          title: "AWS IMDSv2 Token Endpoint Accessible",
          description: "The IMDSv2 token endpoint is accessible. While IMDSv2 is more secure than v1, the metadata service should not be reachable from external networks.",
          severity: "high",
          confidence: 85,
          target: host,
          protocol: "http",
          cwes: ["CWE-918"],
          techniqueIds: ["T1552.005"],
          evidence: { matchedPattern: "IMDSv2 PUT /latest/api/token returned 200" },
          remediation: "Ensure IMDS is only accessible from the instance itself. Use hop limit of 1 for IMDSv2.",
          environment: "cloud",
          foundAt: Date.now(),
        });
      }
    } catch {
      // Expected for non-AWS targets
    }

    return findings;
  }

  async probe(host: string, _port: number): Promise<boolean> {
    try {
      const r = await fetch(`http://${host}/latest/meta-data/`, {
        headers: { "Host": "169.254.169.254" },
        signal: AbortSignal.timeout(3000),
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
}

// ─── Cloud Storage Scanner ────────────────────────────────────────────────

export class CloudStorageScanner implements ProtocolScanner {
  name = "Cloud Storage Scanner";
  protocol = "cloud-storage";
  defaultPorts = [80, 443];
  environments = ["cloud" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1000;

    // S3 bucket checks
    const s3Patterns = [
      `https://${host}.s3.amazonaws.com/`,
      `https://s3.amazonaws.com/${host}/`,
    ];

    for (const url of s3Patterns) {
      try {
        const response = await fetch(url, {
          method: "GET",
          signal: AbortSignal.timeout(timeout),
        });

        if (response.status === 200) {
          const body = await response.text();
          if (body.includes("<ListBucketResult") || body.includes("<Contents>")) {
            findings.push({
              id: randomUUID(),
              source: "cloud:s3-bucket",
              title: `Public S3 Bucket: ${host}`,
              description: `The S3 bucket "${host}" allows public listing. This exposes all objects in the bucket to unauthenticated users and may leak sensitive data.`,
              severity: "critical",
              confidence: 100,
              target: host,
              protocol: "https",
              cwes: ["CWE-284", "CWE-732"],
              techniqueIds: ["T1530"],
              evidence: {
                request: `GET ${url}`,
                response: body.substring(0, 2000),
                matchedPattern: "ListBucketResult XML response",
              },
              remediation: "Enable S3 Block Public Access at the account level. Review bucket policies and ACLs. Enable S3 access logging. Use AWS Config rules to detect public buckets.",
              environment: "cloud",
              foundAt: Date.now(),
            });
          }
        } else if (response.status === 403) {
          // Bucket exists but is not public — still useful info
          findings.push({
            id: randomUUID(),
            source: "cloud:s3-bucket",
            title: `S3 Bucket Exists (Access Denied): ${host}`,
            description: `The S3 bucket "${host}" exists but returns 403 Forbidden. The bucket name is confirmed, which could be useful for targeted attacks.`,
            severity: "info",
            confidence: 95,
            target: host,
            protocol: "https",
            cwes: ["CWE-200"],
            evidence: { matchedPattern: "S3 bucket exists (403 response)" },
            remediation: "Consider using randomized bucket names to prevent enumeration.",
            environment: "cloud",
            foundAt: Date.now(),
          });
        }
      } catch {
        // Not an S3 bucket
      }
    }

    // Azure Blob Storage checks
    try {
      const azureUrl = `https://${host}.blob.core.windows.net/?comp=list`;
      const response = await fetch(azureUrl, { signal: AbortSignal.timeout(timeout) });
      if (response.status === 200) {
        const body = await response.text();
        if (body.includes("<EnumerationResults") || body.includes("<Containers>")) {
          findings.push({
            id: randomUUID(),
            source: "cloud:azure-blob",
            title: `Public Azure Blob Storage: ${host}`,
            description: `The Azure Blob Storage account "${host}" allows public container listing.`,
            severity: "critical",
            confidence: 100,
            target: host,
            protocol: "https",
            cwes: ["CWE-284", "CWE-732"],
            techniqueIds: ["T1530"],
            evidence: {
              request: `GET ${azureUrl}`,
              response: body.substring(0, 2000),
            },
            remediation: "Disable public access on the storage account. Review container access policies. Enable Azure Storage analytics logging.",
            environment: "cloud",
            foundAt: Date.now(),
          });
        }
      }
    } catch {
      // Not Azure storage
    }

    // GCS checks
    try {
      const gcsUrl = `https://storage.googleapis.com/${host}/`;
      const response = await fetch(gcsUrl, { signal: AbortSignal.timeout(timeout) });
      if (response.status === 200) {
        const body = await response.text();
        if (body.includes("<ListBucketResult") || body.includes("<Contents>")) {
          findings.push({
            id: randomUUID(),
            source: "cloud:gcs-bucket",
            title: `Public GCS Bucket: ${host}`,
            description: `The Google Cloud Storage bucket "${host}" allows public listing.`,
            severity: "critical",
            confidence: 100,
            target: host,
            protocol: "https",
            cwes: ["CWE-284", "CWE-732"],
            techniqueIds: ["T1530"],
            evidence: {
              request: `GET ${gcsUrl}`,
              response: body.substring(0, 2000),
            },
            remediation: "Set uniform bucket-level access. Remove allUsers and allAuthenticatedUsers IAM bindings. Enable Cloud Audit Logs.",
            environment: "cloud",
            foundAt: Date.now(),
          });
        }
      }
    } catch {
      // Not GCS
    }

    return findings;
  }

  async probe(host: string, _port: number): Promise<boolean> {
    try {
      const r = await fetch(`https://${host}.s3.amazonaws.com/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });
      return r.status !== 404;
    } catch {
      return false;
    }
  }
}

// ─── Kubernetes API Scanner ───────────────────────────────────────────────

export class KubernetesAPIScanner implements ProtocolScanner {
  name = "Kubernetes API Scanner";
  protocol = "kubernetes";
  defaultPorts = [6443, 8443, 10250, 10255];
  environments = ["container" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1000;

    // Check K8s API server (unauthenticated)
    const k8sEndpoints = [
      { port: 6443, path: "/api", desc: "Kubernetes API root" },
      { port: 6443, path: "/api/v1/namespaces", desc: "Namespace listing" },
      { port: 6443, path: "/api/v1/pods", desc: "Pod listing" },
      { port: 6443, path: "/api/v1/secrets", desc: "Secrets listing" },
      { port: 6443, path: "/version", desc: "Version info" },
      { port: 8443, path: "/api", desc: "K8s API (alt port)" },
    ];

    for (const ep of k8sEndpoints) {
      try {
        const url = `https://${host}:${ep.port}${ep.path}`;
        const response = await fetch(url, {
          signal: AbortSignal.timeout(timeout),
          // @ts-ignore - Node fetch supports rejectUnauthorized via agent
        });

        if (response.status === 200) {
          const body = await response.text();
          if (body.includes('"kind"') || body.includes('"apiVersion"') || body.includes('"major"')) {
            const isSensitive = ep.path.includes("secrets") || ep.path.includes("pods");
            findings.push({
              id: randomUUID(),
              source: "cloud:kubernetes-api",
              title: `Unauthenticated Kubernetes API Access: ${ep.desc}`,
              description: `The Kubernetes API endpoint ${ep.path} on ${host}:${ep.port} is accessible without authentication. ${isSensitive ? "This exposes sensitive cluster data including secrets and pod configurations." : "This exposes cluster information."}`,
              severity: isSensitive ? "critical" : "high",
              confidence: 95,
              target: host,
              port: ep.port,
              protocol: "https",
              cwes: ["CWE-306", "CWE-284"],
              techniqueIds: ["T1613", "T1552"],
              evidence: {
                request: `GET ${url}`,
                response: body.substring(0, 2000),
                matchedPattern: "Kubernetes API JSON response",
              },
              remediation: "Enable RBAC and disable anonymous authentication. Use network policies to restrict API server access. Enable audit logging. Use admission controllers.",
              environment: "container",
              foundAt: Date.now(),
            });
          }
        }
      } catch {
        // Expected for non-K8s targets
      }
    }

    // Check Kubelet API (read-only port)
    try {
      const kubeletUrl = `http://${host}:10255/pods`;
      const response = await fetch(kubeletUrl, { signal: AbortSignal.timeout(timeout) });
      if (response.status === 200) {
        const body = await response.text();
        if (body.includes('"items"') || body.includes('"metadata"')) {
          findings.push({
            id: randomUUID(),
            source: "cloud:kubelet-readonly",
            title: "Kubelet Read-Only Port Exposed",
            description: `The Kubelet read-only port (10255) on ${host} is accessible. This exposes pod information, environment variables, and potentially secrets.`,
            severity: "high",
            confidence: 95,
            target: host,
            port: 10255,
            protocol: "http",
            cwes: ["CWE-200", "CWE-306"],
            techniqueIds: ["T1613"],
            evidence: {
              request: `GET ${kubeletUrl}`,
              response: body.substring(0, 2000),
            },
            remediation: "Disable the read-only port (--read-only-port=0). Use authenticated Kubelet API on port 10250.",
            environment: "container",
            foundAt: Date.now(),
          });
        }
      }
    } catch {
      // Expected
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const proto = port === 10255 ? "http" : "https";
      const r = await fetch(`${proto}://${host}:${port}/version`, {
        signal: AbortSignal.timeout(5000),
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
}

// ─── Docker API Scanner ───────────────────────────────────────────────────

export class DockerAPIScanner implements ProtocolScanner {
  name = "Docker API Scanner";
  protocol = "docker";
  defaultPorts = [2375, 2376, 4243];
  environments = ["container" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 10) * 1000;

    const dockerPorts = [2375, 2376, 4243];

    for (const port of dockerPorts) {
      const proto = port === 2376 ? "https" : "http";

      // Check Docker API version
      try {
        const versionUrl = `${proto}://${host}:${port}/version`;
        const response = await fetch(versionUrl, { signal: AbortSignal.timeout(timeout) });

        if (response.status === 200) {
          const body = await response.text();
          if (body.includes('"ApiVersion"') || body.includes('"Version"')) {
            findings.push({
              id: randomUUID(),
              source: "cloud:docker-api",
              title: `Exposed Docker API: ${host}:${port}`,
              description: `The Docker daemon API is exposed on ${host}:${port} without authentication. An attacker can create privileged containers, access host filesystem, and achieve full host compromise.`,
              severity: "critical",
              confidence: 100,
              target: host,
              port,
              protocol: proto,
              cwes: ["CWE-306", "CWE-250"],
              techniqueIds: ["T1610", "T1611"],
              evidence: {
                request: `GET ${versionUrl}`,
                response: body.substring(0, 2000),
                matchedPattern: "Docker API version response",
              },
              remediation: "Never expose the Docker socket to the network. Use TLS mutual authentication. Use Docker socket proxy with read-only access. Implement network segmentation.",
              environment: "container",
              foundAt: Date.now(),
            });
          }
        }
      } catch {
        // Expected
      }

      // Check for running containers
      try {
        const containersUrl = `${proto}://${host}:${port}/containers/json`;
        const response = await fetch(containersUrl, { signal: AbortSignal.timeout(timeout) });

        if (response.status === 200) {
          const body = await response.text();
          try {
            const containers = JSON.parse(body);
            if (Array.isArray(containers) && containers.length > 0) {
              findings.push({
                id: randomUUID(),
                source: "cloud:docker-containers",
                title: `Docker Containers Enumerated: ${containers.length} running`,
                description: `${containers.length} running containers were enumerated via the exposed Docker API on ${host}:${port}. Container names, images, and configurations are exposed.`,
                severity: "high",
                confidence: 100,
                target: host,
                port,
                protocol: proto,
                cwes: ["CWE-200"],
                techniqueIds: ["T1613"],
                evidence: {
                  data: {
                    containerCount: containers.length,
                    containers: containers.slice(0, 5).map((c: any) => ({
                      id: c.Id?.substring(0, 12),
                      image: c.Image,
                      state: c.State,
                      names: c.Names,
                    })),
                  },
                },
                remediation: "Secure the Docker API with TLS authentication. Use Docker socket proxy.",
                environment: "container",
                foundAt: Date.now(),
              });
            }
          } catch {
            // Invalid JSON
          }
        }
      } catch {
        // Expected
      }
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const proto = port === 2376 ? "https" : "http";
      const r = await fetch(`${proto}://${host}:${port}/version`, {
        signal: AbortSignal.timeout(3000),
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
}

// ─── etcd Scanner ─────────────────────────────────────────────────────────

export class EtcdScanner implements ProtocolScanner {
  name = "etcd Scanner";
  protocol = "etcd";
  defaultPorts = [2379, 2380];
  environments = ["container" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 10) * 1000;

    // Check etcd v2 API
    try {
      const v2Url = `http://${host}:2379/v2/keys/`;
      const response = await fetch(v2Url, { signal: AbortSignal.timeout(timeout) });

      if (response.status === 200) {
        const body = await response.text();
        if (body.includes('"node"') || body.includes('"key"')) {
          findings.push({
            id: randomUUID(),
            source: "cloud:etcd",
            title: "Unauthenticated etcd Access (v2 API)",
            description: `The etcd key-value store on ${host}:2379 is accessible without authentication via the v2 API. etcd often stores Kubernetes secrets, certificates, and configuration data.`,
            severity: "critical",
            confidence: 100,
            target: host,
            port: 2379,
            protocol: "http",
            cwes: ["CWE-306", "CWE-200"],
            techniqueIds: ["T1552.001"],
            evidence: {
              request: `GET ${v2Url}`,
              response: body.substring(0, 2000),
              matchedPattern: "etcd v2 key listing response",
            },
            remediation: "Enable client certificate authentication for etcd. Restrict network access to etcd ports. Use etcd encryption at rest.",
            environment: "container",
            foundAt: Date.now(),
          });
        }
      }
    } catch {
      // Expected
    }

    // Check etcd v3 health
    try {
      const healthUrl = `http://${host}:2379/health`;
      const response = await fetch(healthUrl, { signal: AbortSignal.timeout(timeout) });

      if (response.status === 200) {
        const body = await response.text();
        if (body.includes('"health"') || body.includes("true")) {
          findings.push({
            id: randomUUID(),
            source: "cloud:etcd",
            title: "etcd Health Endpoint Exposed",
            description: `The etcd health endpoint on ${host}:2379 is publicly accessible, confirming an etcd instance is running.`,
            severity: "medium",
            confidence: 90,
            target: host,
            port: 2379,
            protocol: "http",
            cwes: ["CWE-200"],
            evidence: { matchedPattern: "etcd health endpoint accessible" },
            remediation: "Restrict network access to etcd. Use TLS for all etcd communication.",
            environment: "container",
            foundAt: Date.now(),
          });
        }
      }
    } catch {
      // Expected
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const r = await fetch(`http://${host}:${port}/health`, {
        signal: AbortSignal.timeout(3000),
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
}

// ─── Container Registry Scanner ───────────────────────────────────────────

export class ContainerRegistryScanner implements ProtocolScanner {
  name = "Container Registry Scanner";
  protocol = "container-registry";
  defaultPorts = [5000, 443];
  environments = ["container" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1000;

    // Check Docker Registry v2 API
    const registryPorts = [5000, 443];

    for (const port of registryPorts) {
      const proto = port === 443 ? "https" : "http";

      try {
        const catalogUrl = `${proto}://${host}:${port}/v2/_catalog`;
        const response = await fetch(catalogUrl, { signal: AbortSignal.timeout(timeout) });

        if (response.status === 200) {
          const body = await response.text();
          if (body.includes('"repositories"')) {
            const data = JSON.parse(body);
            findings.push({
              id: randomUUID(),
              source: "cloud:container-registry",
              title: `Anonymous Container Registry Access: ${host}:${port}`,
              description: `The container registry on ${host}:${port} allows anonymous catalog listing. ${data.repositories?.length || 0} repositories are exposed.`,
              severity: "high",
              confidence: 100,
              target: host,
              port,
              protocol: proto,
              cwes: ["CWE-284", "CWE-200"],
              techniqueIds: ["T1525"],
              evidence: {
                request: `GET ${catalogUrl}`,
                data: {
                  repositoryCount: data.repositories?.length || 0,
                  repositories: data.repositories?.slice(0, 20),
                },
              },
              remediation: "Enable authentication for the container registry. Use TLS. Implement access control policies. Consider using a managed registry service.",
              environment: "container",
              foundAt: Date.now(),
            });
          }
        }
      } catch {
        // Expected
      }
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const proto = port === 443 ? "https" : "http";
      const r = await fetch(`${proto}://${host}:${port}/v2/`, {
        signal: AbortSignal.timeout(3000),
      });
      return r.status === 200 || r.status === 401;
    } catch {
      return false;
    }
  }
}
