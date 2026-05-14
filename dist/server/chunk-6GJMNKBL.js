import {
  getTemplateEngine,
  init_template_engine
} from "./chunk-R4LF5PWF.js";

// server/scanforge/queue/scan-queue.ts
import { EventEmitter } from "events";
var PRIORITY_WEIGHT = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};
var DEFAULT_CONFIG = {
  maxConcurrency: 3,
  maxQueueDepth: 50,
  jobTimeoutMs: 30 * 60 * 1e3,
  // 30 minutes
  cleanupIntervalMs: 60 * 1e3
  // 1 minute
};
var ScanQueue = class extends EventEmitter {
  constructor(config = {}) {
    super();
    this.queue = [];
    this.running = /* @__PURE__ */ new Map();
    this.completed = /* @__PURE__ */ new Map();
    this.cleanupTimer = null;
    this.processorFn = null;
    const normalized = { ...config };
    if (config.maxConcurrent !== void 0) normalized.maxConcurrency = config.maxConcurrent;
    if (config.maxQueueSize !== void 0) normalized.maxQueueDepth = config.maxQueueSize;
    this.config = { ...DEFAULT_CONFIG, ...normalized };
    this.startCleanup();
  }
  // ─── Public API ────────────────────────────────────────────────────────
  /**
   * Register the scan processor function.
   * Called when a job is dequeued and ready to execute.
   */
  setProcessor(fn) {
    this.processorFn = fn;
  }
  /**
   * Enqueue a new scan request. Returns the created ScanJob.
   */
  enqueue(request) {
    if (this.queue.length >= this.config.maxQueueDepth) {
      throw new Error(`Queue full (${this.config.maxQueueDepth} jobs). Try again later.`);
    }
    const job = {
      request,
      status: "queued",
      progress: 0,
      findings: [],
      scannerResults: []
    };
    const weight = PRIORITY_WEIGHT[request.priority] || 1;
    let inserted = false;
    for (let i = 0; i < this.queue.length; i++) {
      const existingWeight = PRIORITY_WEIGHT[this.queue[i].request.priority] || 1;
      if (weight > existingWeight) {
        this.queue.splice(i, 0, job);
        inserted = true;
        break;
      }
    }
    if (!inserted) {
      this.queue.push(job);
    }
    const position = this.queue.indexOf(job) + 1;
    this.emitEvent({
      type: "scan:queued",
      scanId: request.id,
      position
    });
    console.log(`[ScanQueue] Enqueued scan ${request.id} (priority=${request.priority}, position=${position}, queue=${this.queue.length})`);
    this.processNext();
    return job;
  }
  /**
   * Cancel a scan by ID. Works for queued or running scans.
   */
  cancel(scanId) {
    const queueIdx = this.queue.findIndex((j) => j.request.id === scanId);
    if (queueIdx >= 0) {
      const job = this.queue.splice(queueIdx, 1)[0];
      job.status = "cancelled";
      job.completedAt = Date.now();
      this.completed.set(scanId, job);
      this.emitEvent({ type: "scan:cancelled", scanId });
      console.log(`[ScanQueue] Cancelled queued scan ${scanId}`);
      return true;
    }
    const runningJob = this.running.get(scanId);
    if (runningJob) {
      runningJob.status = "cancelled";
      runningJob.completedAt = Date.now();
      this.running.delete(scanId);
      this.completed.set(scanId, runningJob);
      this.emitEvent({ type: "scan:cancelled", scanId });
      console.log(`[ScanQueue] Cancelled running scan ${scanId}`);
      this.processNext();
      return true;
    }
    return false;
  }
  /**
   * Pause a running scan.
   */
  pause(scanId) {
    const job = this.running.get(scanId);
    if (job) {
      job.status = "paused";
      this.running.delete(scanId);
      this.queue.unshift(job);
      console.log(`[ScanQueue] Paused scan ${scanId}`);
      return true;
    }
    return false;
  }
  /**
   * Resume a paused scan.
   */
  resume(scanId) {
    const idx = this.queue.findIndex((j) => j.request.id === scanId && j.status === "paused");
    if (idx >= 0) {
      this.queue[idx].status = "queued";
      this.processNext();
      return true;
    }
    return false;
  }
  /**
   * Get a scan job by ID (from any state).
   */
  getJob(scanId) {
    const queued = this.queue.find((j) => j.request.id === scanId);
    if (queued) return queued;
    const running = this.running.get(scanId);
    if (running) return running;
    return this.completed.get(scanId) || null;
  }
  /**
   * Get queue status.
   */
  getStatus() {
    return {
      queued: this.queue.length,
      running: this.running.size,
      completed: this.completed.size,
      maxConcurrency: this.config.maxConcurrency
    };
  }
  /**
   * Get queue stats (alias for getStatus with additional fields).
   */
  getStats() {
    const status = this.getStatus();
    const allCompleted = Array.from(this.completed.values());
    return {
      ...status,
      failed: allCompleted.filter((j) => j.status === "failed").length,
      totalProcessed: allCompleted.length
    };
  }
  /**
   * List jobs by status (alias for filtered getAllJobs).
   */
  listJobs(status) {
    const all = this.getAllJobs();
    if (!status) return all;
    return all.filter((j) => j.status === status);
  }
  /**
   * Cancel a job by ID (alias for cancel).
   */
  cancelJob(scanId) {
    return this.cancel(scanId);
  }
  /**
   * Get all jobs (for dashboard).
   */
  getAllJobs() {
    return [
      ...this.queue,
      ...Array.from(this.running.values()),
      ...Array.from(this.completed.values())
    ];
  }
  /**
   * Update job progress (called by the scan engine during execution).
   */
  updateProgress(scanId, progress, scanner) {
    const job = this.running.get(scanId);
    if (job) {
      job.progress = Math.min(100, Math.max(0, progress));
      if (scanner) job.currentScanner = scanner;
      this.emitEvent({
        type: "scan:progress",
        scanId,
        progress: job.progress,
        scanner: scanner || "unknown"
      });
    }
  }
  /**
   * Add a finding to a running job.
   */
  addFinding(scanId, finding) {
    const job = this.running.get(scanId);
    if (job) {
      job.findings.push(finding);
      this.emitEvent({ type: "scan:finding", scanId, finding });
    }
  }
  /**
   * Record a scanner result.
   */
  addScannerResult(scanId, result) {
    const job = this.running.get(scanId);
    if (job) {
      job.scannerResults.push(result);
      this.emitEvent({ type: "scan:scanner_complete", scanId, result });
    }
  }
  /**
   * Update scan phase.
   */
  setPhase(scanId, phase) {
    const job = this.running.get(scanId);
    if (job) {
      job.phase = phase;
      this.emitEvent({ type: "scan:phase_change", scanId, phase });
    }
  }
  /**
   * Mark a job as completed.
   */
  completeJob(scanId) {
    const job = this.running.get(scanId);
    if (job) {
      job.status = "completed";
      job.progress = 100;
      job.completedAt = Date.now();
      this.running.delete(scanId);
      this.completed.set(scanId, job);
      const summary = this.buildSummary(job);
      this.emitEvent({ type: "scan:completed", scanId, summary });
      console.log(`[ScanQueue] Scan ${scanId} completed: ${summary.totalFindings} findings in ${summary.durationMs}ms`);
      if (job.request.callbackUrl) {
        this.deliverCallback(job.request.callbackUrl, summary).catch(() => {
        });
      }
      this.processNext();
    }
  }
  /**
   * Mark a job as failed.
   */
  failJob(scanId, error) {
    const job = this.running.get(scanId);
    if (job) {
      job.status = "failed";
      job.error = error;
      job.completedAt = Date.now();
      this.running.delete(scanId);
      this.completed.set(scanId, job);
      this.emitEvent({ type: "scan:failed", scanId, error });
      console.error(`[ScanQueue] Scan ${scanId} failed: ${error}`);
      this.processNext();
    }
  }
  /**
   * Shutdown the queue gracefully.
   */
  shutdown() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    for (const job of this.queue) {
      job.status = "cancelled";
      job.completedAt = Date.now();
    }
    this.queue = [];
    console.log("[ScanQueue] Shutdown complete");
  }
  // ─── Internal ──────────────────────────────────────────────────────────
  processNext() {
    if (!this.processorFn) return;
    if (this.running.size >= this.config.maxConcurrency) return;
    const nextJob = this.queue.find((j) => j.status === "queued");
    if (!nextJob) return;
    const idx = this.queue.indexOf(nextJob);
    this.queue.splice(idx, 1);
    nextJob.status = "running";
    nextJob.startedAt = Date.now();
    nextJob.phase = "recon";
    this.running.set(nextJob.request.id, nextJob);
    this.emitEvent({
      type: "scan:started",
      scanId: nextJob.request.id,
      phase: "recon"
    });
    console.log(`[ScanQueue] Starting scan ${nextJob.request.id} (running=${this.running.size}/${this.config.maxConcurrency})`);
    const processor = this.processorFn;
    const scanId = nextJob.request.id;
    const timeoutMs = this.config.jobTimeoutMs;
    const timeout = setTimeout(() => {
      if (this.running.has(scanId)) {
        this.failJob(scanId, `Scan timed out after ${timeoutMs / 1e3}s`);
      }
    }, timeoutMs);
    processor(nextJob).then(() => {
      clearTimeout(timeout);
      if (this.running.has(scanId)) {
        this.completeJob(scanId);
      }
    }).catch((err) => {
      clearTimeout(timeout);
      if (this.running.has(scanId)) {
        this.failJob(scanId, err.message || "Unknown error");
      }
    });
    if (this.running.size < this.config.maxConcurrency) {
      this.processNext();
    }
  }
  buildSummary(job) {
    const bySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    for (const f of job.findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }
    return {
      scanId: job.request.id,
      totalFindings: job.findings.length,
      bySeverity,
      scannersRun: job.scannerResults.length,
      scannersCompleted: job.scannerResults.filter((r) => r.status === "completed").length,
      scannersFailed: job.scannerResults.filter((r) => r.status === "failed").length,
      durationMs: (job.completedAt || Date.now()) - (job.startedAt || Date.now()),
      topFindings: job.findings.sort((a, b) => (b.riskScore?.composite || 0) - (a.riskScore?.composite || 0)).slice(0, 10)
    };
  }
  emitEvent(event) {
    this.emit("scan_event", event);
  }
  async deliverCallback(url, summary) {
    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(summary),
        signal: AbortSignal.timeout(1e4)
      });
    } catch (err) {
      console.warn(`[ScanQueue] Callback delivery failed: ${err.message}`);
    }
  }
  startCleanup() {
    this.cleanupTimer = setInterval(() => {
      const cutoff = Date.now() - 2 * 60 * 60 * 1e3;
      for (const [id, job] of this.completed) {
        if (job.completedAt && job.completedAt < cutoff) {
          this.completed.delete(id);
        }
      }
    }, this.config.cleanupIntervalMs);
  }
};
var _queue = null;
function getScanQueue(config) {
  if (!_queue) {
    _queue = new ScanQueue(config);
  }
  return _queue;
}

// server/scanforge/protocols/cloud-scanners.ts
import { randomUUID } from "crypto";
var AWSIMDSScanner = class {
  constructor() {
    this.name = "AWS IMDS Scanner";
    this.protocol = "aws-imds";
    this.defaultPorts = [80, 443];
    this.environments = ["cloud"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 10) * 1e3;
    const imdsEndpoints = [
      { path: "/latest/meta-data/", desc: "Instance metadata root" },
      { path: "/latest/meta-data/iam/security-credentials/", desc: "IAM role credentials" },
      { path: "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", desc: "EC2 identity credentials" },
      { path: "/latest/user-data", desc: "User data (may contain secrets)" }
    ];
    for (const endpoint of imdsEndpoints) {
      try {
        const response = await fetch(`http://${host}${endpoint.path}`, {
          headers: { "Host": "169.254.169.254" },
          signal: AbortSignal.timeout(timeout),
          redirect: "manual"
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
                request: `GET ${endpoint.path} HTTP/1.1
Host: 169.254.169.254`,
                response: body.substring(0, 2e3),
                matchedPattern: "IMDS response with metadata content"
              },
              remediation: "Enforce IMDSv2 (token-required) on all EC2 instances. Block IMDS access from containers. Use VPC endpoints and security groups to restrict metadata access. Patch SSRF vulnerabilities in web applications.",
              environment: "cloud",
              foundAt: Date.now()
            });
          }
        }
      } catch {
      }
    }
    try {
      const tokenResponse = await fetch(`http://${host}/latest/api/token`, {
        method: "PUT",
        headers: {
          "Host": "169.254.169.254",
          "X-aws-ec2-metadata-token-ttl-seconds": "21600"
        },
        signal: AbortSignal.timeout(timeout)
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
          foundAt: Date.now()
        });
      }
    } catch {
    }
    return findings;
  }
  async probe(host, _port) {
    try {
      const r = await fetch(`http://${host}/latest/meta-data/`, {
        headers: { "Host": "169.254.169.254" },
        signal: AbortSignal.timeout(3e3)
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
};
var CloudStorageScanner = class {
  constructor() {
    this.name = "Cloud Storage Scanner";
    this.protocol = "cloud-storage";
    this.defaultPorts = [80, 443];
    this.environments = ["cloud"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1e3;
    const s3Patterns = [
      `https://${host}.s3.amazonaws.com/`,
      `https://s3.amazonaws.com/${host}/`
    ];
    for (const url of s3Patterns) {
      try {
        const response = await fetch(url, {
          method: "GET",
          signal: AbortSignal.timeout(timeout)
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
                response: body.substring(0, 2e3),
                matchedPattern: "ListBucketResult XML response"
              },
              remediation: "Enable S3 Block Public Access at the account level. Review bucket policies and ACLs. Enable S3 access logging. Use AWS Config rules to detect public buckets.",
              environment: "cloud",
              foundAt: Date.now()
            });
          }
        } else if (response.status === 403) {
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
            foundAt: Date.now()
          });
        }
      } catch {
      }
    }
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
              response: body.substring(0, 2e3)
            },
            remediation: "Disable public access on the storage account. Review container access policies. Enable Azure Storage analytics logging.",
            environment: "cloud",
            foundAt: Date.now()
          });
        }
      }
    } catch {
    }
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
              response: body.substring(0, 2e3)
            },
            remediation: "Set uniform bucket-level access. Remove allUsers and allAuthenticatedUsers IAM bindings. Enable Cloud Audit Logs.",
            environment: "cloud",
            foundAt: Date.now()
          });
        }
      }
    } catch {
    }
    return findings;
  }
  async probe(host, _port) {
    try {
      const r = await fetch(`https://${host}.s3.amazonaws.com/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5e3)
      });
      return r.status !== 404;
    } catch {
      return false;
    }
  }
};
var KubernetesAPIScanner = class {
  constructor() {
    this.name = "Kubernetes API Scanner";
    this.protocol = "kubernetes";
    this.defaultPorts = [6443, 8443, 10250, 10255];
    this.environments = ["container"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1e3;
    const k8sEndpoints = [
      { port: 6443, path: "/api", desc: "Kubernetes API root" },
      { port: 6443, path: "/api/v1/namespaces", desc: "Namespace listing" },
      { port: 6443, path: "/api/v1/pods", desc: "Pod listing" },
      { port: 6443, path: "/api/v1/secrets", desc: "Secrets listing" },
      { port: 6443, path: "/version", desc: "Version info" },
      { port: 8443, path: "/api", desc: "K8s API (alt port)" }
    ];
    for (const ep of k8sEndpoints) {
      try {
        const url = `https://${host}:${ep.port}${ep.path}`;
        const response = await fetch(url, {
          signal: AbortSignal.timeout(timeout)
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
                response: body.substring(0, 2e3),
                matchedPattern: "Kubernetes API JSON response"
              },
              remediation: "Enable RBAC and disable anonymous authentication. Use network policies to restrict API server access. Enable audit logging. Use admission controllers.",
              environment: "container",
              foundAt: Date.now()
            });
          }
        }
      } catch {
      }
    }
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
              response: body.substring(0, 2e3)
            },
            remediation: "Disable the read-only port (--read-only-port=0). Use authenticated Kubelet API on port 10250.",
            environment: "container",
            foundAt: Date.now()
          });
        }
      }
    } catch {
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const proto = port === 10255 ? "http" : "https";
      const r = await fetch(`${proto}://${host}:${port}/version`, {
        signal: AbortSignal.timeout(5e3)
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
};
var DockerAPIScanner = class {
  constructor() {
    this.name = "Docker API Scanner";
    this.protocol = "docker";
    this.defaultPorts = [2375, 2376, 4243];
    this.environments = ["container"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 10) * 1e3;
    const dockerPorts = [2375, 2376, 4243];
    for (const port of dockerPorts) {
      const proto = port === 2376 ? "https" : "http";
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
                response: body.substring(0, 2e3),
                matchedPattern: "Docker API version response"
              },
              remediation: "Never expose the Docker socket to the network. Use TLS mutual authentication. Use Docker socket proxy with read-only access. Implement network segmentation.",
              environment: "container",
              foundAt: Date.now()
            });
          }
        }
      } catch {
      }
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
                    containers: containers.slice(0, 5).map((c) => ({
                      id: c.Id?.substring(0, 12),
                      image: c.Image,
                      state: c.State,
                      names: c.Names
                    }))
                  }
                },
                remediation: "Secure the Docker API with TLS authentication. Use Docker socket proxy.",
                environment: "container",
                foundAt: Date.now()
              });
            }
          } catch {
          }
        }
      } catch {
      }
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const proto = port === 2376 ? "https" : "http";
      const r = await fetch(`${proto}://${host}:${port}/version`, {
        signal: AbortSignal.timeout(3e3)
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
};
var EtcdScanner = class {
  constructor() {
    this.name = "etcd Scanner";
    this.protocol = "etcd";
    this.defaultPorts = [2379, 2380];
    this.environments = ["container"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 10) * 1e3;
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
              response: body.substring(0, 2e3),
              matchedPattern: "etcd v2 key listing response"
            },
            remediation: "Enable client certificate authentication for etcd. Restrict network access to etcd ports. Use etcd encryption at rest.",
            environment: "container",
            foundAt: Date.now()
          });
        }
      }
    } catch {
    }
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
            foundAt: Date.now()
          });
        }
      }
    } catch {
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const r = await fetch(`http://${host}:${port}/health`, {
        signal: AbortSignal.timeout(3e3)
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
};
var ContainerRegistryScanner = class {
  constructor() {
    this.name = "Container Registry Scanner";
    this.protocol = "container-registry";
    this.defaultPorts = [5e3, 443];
    this.environments = ["container"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1e3;
    const registryPorts = [5e3, 443];
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
                  repositories: data.repositories?.slice(0, 20)
                }
              },
              remediation: "Enable authentication for the container registry. Use TLS. Implement access control policies. Consider using a managed registry service.",
              environment: "container",
              foundAt: Date.now()
            });
          }
        }
      } catch {
      }
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const proto = port === 443 ? "https" : "http";
      const r = await fetch(`${proto}://${host}:${port}/v2/`, {
        signal: AbortSignal.timeout(3e3)
      });
      return r.status === 200 || r.status === 401;
    } catch {
      return false;
    }
  }
};

// server/scanforge/protocols/iot-scanners.ts
import { randomUUID as randomUUID2 } from "crypto";
var MQTTScanner = class {
  constructor() {
    this.name = "MQTT Scanner";
    this.protocol = "mqtt";
    this.defaultPorts = [1883, 8883, 8083, 8084];
    this.environments = ["iot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1e3;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const mqttResult = await executeTool({
        tool: "naabu",
        args: `--script mqtt-subscribe -p 1883,8883 ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (mqttResult.stdout.includes("mqtt-subscribe")) {
        if (mqttResult.stdout.includes("Anonymous") || !mqttResult.stdout.includes("Authentication")) {
          findings.push({
            id: randomUUID2(),
            source: "iot:mqtt",
            title: "MQTT Broker Allows Anonymous Access",
            description: `The MQTT broker on ${host} allows anonymous connections. An attacker can subscribe to all topics (#) and intercept IoT device telemetry, commands, and potentially credentials.`,
            severity: "critical",
            confidence: 90,
            target: host,
            port: 1883,
            protocol: "mqtt",
            cwes: ["CWE-306", "CWE-319"],
            techniqueIds: ["T1040", "T1557"],
            evidence: {
              response: mqttResult.stdout.substring(0, 2e3),
              matchedPattern: "Anonymous MQTT access permitted"
            },
            remediation: "Enable MQTT authentication (username/password or client certificates). Implement topic-level ACLs. Use TLS (port 8883) for all MQTT connections. Disable anonymous access in broker configuration.",
            environment: "iot",
            foundAt: Date.now()
          });
        }
      }
      const wsEndpoints = [
        `http://${host}:8083/mqtt`,
        `http://${host}:8084/mqtt`,
        `https://${host}:8084/mqtt`
      ];
      for (const wsUrl of wsEndpoints) {
        try {
          const response = await fetch(wsUrl, {
            method: "GET",
            headers: { "Upgrade": "websocket", "Connection": "Upgrade" },
            signal: AbortSignal.timeout(timeout)
          });
          if (response.status === 101 || response.status === 200 || response.status === 426) {
            findings.push({
              id: randomUUID2(),
              source: "iot:mqtt-ws",
              title: `MQTT WebSocket Endpoint Exposed: ${wsUrl}`,
              description: `An MQTT-over-WebSocket endpoint is accessible at ${wsUrl}. This allows browser-based MQTT clients to connect, potentially bypassing network-level access controls.`,
              severity: "medium",
              confidence: 80,
              target: host,
              protocol: "mqtt",
              cwes: ["CWE-284"],
              evidence: { matchedPattern: `MQTT WebSocket endpoint at ${wsUrl}` },
              remediation: "Restrict WebSocket MQTT access. Require authentication for WebSocket connections. Use WSS (TLS) instead of WS.",
              environment: "iot",
              foundAt: Date.now()
            });
          }
        } catch {
        }
      }
    } catch (err) {
      console.debug(`[MQTTScanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};
var CoAPScanner = class {
  constructor() {
    this.name = "CoAP Scanner";
    this.protocol = "coap";
    this.defaultPorts = [5683, 5684];
    this.environments = ["iot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const coapResult = await executeTool({
        tool: "naabu",
        args: `-sU -p 5683,5684 --script coap-resources ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (coapResult.stdout.includes("coap-resources") || coapResult.stdout.includes("5683/udp")) {
        if (coapResult.stdout.includes("open")) {
          findings.push({
            id: randomUUID2(),
            source: "iot:coap",
            title: `CoAP Service Exposed: ${host}`,
            description: `A CoAP (Constrained Application Protocol) service is running on ${host}. CoAP is commonly used by IoT devices for resource-constrained communication. If unauthenticated, device resources may be readable or writable.`,
            severity: "medium",
            confidence: 85,
            target: host,
            port: 5683,
            protocol: "coap",
            cwes: ["CWE-306", "CWE-311"],
            techniqueIds: ["T1071"],
            evidence: {
              response: coapResult.stdout.substring(0, 2e3),
              matchedPattern: "CoAP service detected"
            },
            remediation: "Implement DTLS for CoAP security. Use CoAP authentication (PSK or certificate). Restrict CoAP access to authorized clients only. Implement resource-level access control.",
            environment: "iot",
            foundAt: Date.now()
          });
        }
      }
    } catch (err) {
      console.debug(`[CoAPScanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sU -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};
var UPnPScanner = class {
  constructor() {
    this.name = "UPnP/SSDP Scanner";
    this.protocol = "upnp";
    this.defaultPorts = [1900, 5e3, 8080, 49152];
    this.environments = ["iot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1e3;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const upnpResult = await executeTool({
        tool: "naabu",
        args: `--script upnp-info -p 1900,5000,8080,49152 ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (upnpResult.stdout.includes("upnp-info") && upnpResult.stdout.includes("Server:")) {
        findings.push({
          id: randomUUID2(),
          source: "iot:upnp",
          title: `UPnP Service Exposed: ${host}`,
          description: `A UPnP service is running on ${host}. UPnP allows automatic device discovery and port forwarding, which can be exploited for unauthorized access, NAT traversal, and DDoS amplification.`,
          severity: "high",
          confidence: 90,
          target: host,
          port: 1900,
          protocol: "upnp",
          cwes: ["CWE-284", "CWE-918"],
          techniqueIds: ["T1557", "T1498"],
          evidence: {
            response: upnpResult.stdout.substring(0, 2e3),
            matchedPattern: "UPnP service information disclosed"
          },
          remediation: "Disable UPnP on all internet-facing devices. If UPnP is required internally, restrict it to trusted network segments. Disable IGD (Internet Gateway Device) protocol on routers.",
          environment: "iot",
          foundAt: Date.now()
        });
      }
      const descPorts = [5e3, 8080, 49152, 1900];
      for (const port of descPorts) {
        try {
          const descUrl = `http://${host}:${port}/rootDesc.xml`;
          const response = await fetch(descUrl, { signal: AbortSignal.timeout(timeout) });
          if (response.status === 200) {
            const body = await response.text();
            if (body.includes("<device>") || body.includes("<deviceType>")) {
              findings.push({
                id: randomUUID2(),
                source: "iot:upnp-desc",
                title: `UPnP Device Description Exposed: ${host}:${port}`,
                description: `The UPnP device description XML is accessible at ${host}:${port}/rootDesc.xml. This reveals device type, manufacturer, model, firmware version, and available services.`,
                severity: "medium",
                confidence: 95,
                target: host,
                port,
                protocol: "http",
                cwes: ["CWE-200"],
                evidence: {
                  request: `GET ${descUrl}`,
                  response: body.substring(0, 2e3)
                },
                remediation: "Restrict access to UPnP description documents. Disable UPnP on internet-facing interfaces.",
                environment: "iot",
                foundAt: Date.now()
              });
              break;
            }
          }
        } catch {
        }
      }
    } catch (err) {
      console.debug(`[UPnPScanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const r = await fetch(`http://${host}:${port}/rootDesc.xml`, {
        method: "HEAD",
        signal: AbortSignal.timeout(3e3)
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
};

// server/scanforge/protocols/ics-scanners.ts
import { randomUUID as randomUUID3 } from "crypto";
var ModbusScanner = class {
  constructor() {
    this.name = "Modbus TCP Scanner";
    this.protocol = "modbus";
    this.defaultPorts = [502, 503];
    this.environments = ["ics_ot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const safeMode = config?.icsSafeMode !== false;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const modbusResult = await executeTool({
        tool: "naabu",
        args: `--script modbus-discover -p 502,503 ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (modbusResult.stdout.includes("modbus-discover")) {
        if (modbusResult.stdout.includes("open") && (modbusResult.stdout.includes("Device Identification") || modbusResult.stdout.includes("Slave ID"))) {
          findings.push({
            id: randomUUID3(),
            source: "ics:modbus",
            title: `Modbus TCP Service Exposed: ${host}`,
            description: `A Modbus TCP service is running on ${host}:502. Modbus has no built-in authentication \u2014 any client that can reach this port can read/write PLC registers, potentially disrupting physical processes. This is a critical ICS security finding per NIST 800-82 and IEC 62443.`,
            severity: "critical",
            confidence: 95,
            target: host,
            port: 502,
            protocol: "modbus",
            cwes: ["CWE-306", "CWE-284"],
            techniqueIds: ["T0801", "T0831", "T0855"],
            evidence: {
              response: modbusResult.stdout.substring(0, 2e3),
              matchedPattern: "Modbus TCP service with device identification"
            },
            remediation: "Implement network segmentation (Purdue Model Level 1-2 isolation). Deploy an industrial firewall or Modbus-aware IDS. Use Modbus/TCP security extensions (TLS wrapper). Implement allowlisting for Modbus client IPs. Monitor for anomalous Modbus function codes.",
            environment: "ics_ot",
            references: [
              "https://nvd.nist.gov/800-82",
              "https://www.cisa.gov/ics"
            ],
            foundAt: Date.now()
          });
        }
        if (!safeMode) {
          const readResult = await executeTool({
            tool: "naabu",
            args: `--script modbus-discover --script-args modbus-discover.aggressive=true -p 502 ${host}`,
            target: host,
            timeoutSeconds: 20
          });
          if (readResult.stdout.includes("Coils") || readResult.stdout.includes("Holding Registers")) {
            findings.push({
              id: randomUUID3(),
              source: "ics:modbus-registers",
              title: "Modbus Registers Readable Without Authentication",
              description: `Modbus holding registers and coils on ${host} are readable without authentication. An attacker can read process values and potentially write to control registers.`,
              severity: "critical",
              confidence: 95,
              target: host,
              port: 502,
              protocol: "modbus",
              cwes: ["CWE-306", "CWE-693"],
              techniqueIds: ["T0801", "T0861"],
              evidence: {
                response: readResult.stdout.substring(0, 2e3)
              },
              remediation: "Implement Modbus access control. Use industrial firewall with deep packet inspection for Modbus. Segment the Modbus network from IT networks.",
              environment: "ics_ot",
              foundAt: Date.now()
            });
          }
        }
      }
    } catch (err) {
      console.debug(`[ModbusScanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};
var DNP3Scanner = class {
  constructor() {
    this.name = "DNP3 Scanner";
    this.protocol = "dnp3";
    this.defaultPorts = [2e4, 20001];
    this.environments = ["ics_ot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const dnp3Result = await executeTool({
        tool: "naabu",
        args: `-sT -p 20000,20001 --script dnp3-info ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (dnp3Result.stdout.includes("open") && (dnp3Result.stdout.includes("dnp3") || dnp3Result.stdout.includes("20000/tcp"))) {
        findings.push({
          id: randomUUID3(),
          source: "ics:dnp3",
          title: `DNP3 Service Exposed: ${host}`,
          description: `A DNP3 (Distributed Network Protocol 3) service is running on ${host}. DNP3 is used in SCADA systems for communication between control centers and outstations (RTUs). Exposure of this protocol to untrusted networks allows manipulation of power grid, water treatment, and other critical infrastructure systems.`,
          severity: "critical",
          confidence: 90,
          target: host,
          port: 2e4,
          protocol: "dnp3",
          cwes: ["CWE-306", "CWE-284"],
          techniqueIds: ["T0831", "T0855", "T0814"],
          evidence: {
            response: dnp3Result.stdout.substring(0, 2e3),
            matchedPattern: "DNP3 service detected on open port"
          },
          remediation: "Implement DNP3 Secure Authentication (SA). Use encrypted VPN tunnels for DNP3 traffic. Deploy industrial firewall with DNP3 deep packet inspection. Segment SCADA networks per NERC CIP requirements. Monitor for anomalous DNP3 function codes.",
          environment: "ics_ot",
          references: [
            "https://www.cisa.gov/ics-cert",
            "https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx"
          ],
          foundAt: Date.now()
        });
      }
    } catch (err) {
      console.debug(`[DNP3Scanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};
var BACnetScanner = class {
  constructor() {
    this.name = "BACnet Scanner";
    this.protocol = "bacnet";
    this.defaultPorts = [47808];
    this.environments = ["ics_ot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const bacnetResult = await executeTool({
        tool: "naabu",
        args: `-sU -p 47808 --script bacnet-info ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (bacnetResult.stdout.includes("bacnet-info") || bacnetResult.stdout.includes("47808") && bacnetResult.stdout.includes("open")) {
        const hasDeviceInfo = bacnetResult.stdout.includes("Vendor") || bacnetResult.stdout.includes("Object-name") || bacnetResult.stdout.includes("Model");
        findings.push({
          id: randomUUID3(),
          source: "ics:bacnet",
          title: `BACnet Service Exposed: ${host}`,
          description: `A BACnet (Building Automation and Control Networks) service is running on ${host}:47808. BACnet controls HVAC, lighting, fire systems, and physical access control in buildings. ${hasDeviceInfo ? "Device information was disclosed, revealing building automation infrastructure details." : ""}`,
          severity: "high",
          confidence: 85,
          target: host,
          port: 47808,
          protocol: "bacnet",
          cwes: ["CWE-306", "CWE-284"],
          techniqueIds: ["T0855", "T0801"],
          evidence: {
            response: bacnetResult.stdout.substring(0, 2e3),
            matchedPattern: "BACnet service detected"
          },
          remediation: "Segment BACnet networks from IT networks. Implement BACnet Secure Connect (BACnet/SC) for authentication and encryption. Use BACnet firewalls. Disable BACnet broadcast on internet-facing interfaces. Monitor for unauthorized BACnet commands.",
          environment: "ics_ot",
          foundAt: Date.now()
        });
      }
    } catch (err) {
      console.debug(`[BACnetScanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sU -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};
var EtherNetIPScanner = class {
  constructor() {
    this.name = "EtherNet/IP Scanner";
    this.protocol = "ethernetip";
    this.defaultPorts = [44818, 2222];
    this.environments = ["ics_ot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const enipResult = await executeTool({
        tool: "naabu",
        args: `-sT -p 44818,2222 --script enip-info ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30
      });
      if (enipResult.stdout.includes("enip-info") || enipResult.stdout.includes("44818") && enipResult.stdout.includes("open")) {
        findings.push({
          id: randomUUID3(),
          source: "ics:ethernetip",
          title: `EtherNet/IP Service Exposed: ${host}`,
          description: `An EtherNet/IP (CIP) service is running on ${host}:44818. EtherNet/IP is used by Allen-Bradley/Rockwell Automation PLCs and other industrial devices. Exposure allows device enumeration, configuration reading, and potentially firmware manipulation.`,
          severity: "critical",
          confidence: 90,
          target: host,
          port: 44818,
          protocol: "ethernetip",
          cwes: ["CWE-306", "CWE-284"],
          techniqueIds: ["T0801", "T0855", "T0839"],
          evidence: {
            response: enipResult.stdout.substring(0, 2e3),
            matchedPattern: "EtherNet/IP CIP service detected"
          },
          remediation: "Implement CIP Security (EtherNet/IP encryption and authentication). Segment industrial networks. Use industrial-grade firewalls with CIP deep packet inspection. Restrict access to authorized engineering workstations only.",
          environment: "ics_ot",
          foundAt: Date.now()
        });
      }
    } catch (err) {
      console.debug(`[EtherNetIPScanner] Error scanning ${host}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};
var OPCUAScanner = class {
  constructor() {
    this.name = "OPC UA Scanner";
    this.protocol = "opcua";
    this.defaultPorts = [4840, 4843, 48010];
    this.environments = ["ics_ot"];
  }
  async scan(target, config) {
    const findings = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1e3;
    const opcuaPorts = [4840, 4843, 48010];
    for (const port of opcuaPorts) {
      try {
        const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
        const result = await executeTool({
          tool: "naabu",
          args: `-sT -sV -p ${port} ${host}`,
          target: host,
          timeoutSeconds: 20
        });
        if (result.stdout.includes("open") && (result.stdout.includes("opc") || result.stdout.includes("OPC") || result.stdout.includes("4840") || result.stdout.includes("opcua"))) {
          findings.push({
            id: randomUUID3(),
            source: "ics:opcua",
            title: `OPC UA Service Exposed: ${host}:${port}`,
            description: `An OPC UA (Open Platform Communications Unified Architecture) server is running on ${host}:${port}. OPC UA provides access to industrial process data, historian data, and device configuration. Unauthenticated access can expose entire SCADA/DCS system architectures.`,
            severity: "critical",
            confidence: 85,
            target: host,
            port,
            protocol: "opcua",
            cwes: ["CWE-306", "CWE-284"],
            techniqueIds: ["T0801", "T0845"],
            evidence: {
              response: result.stdout.substring(0, 2e3),
              matchedPattern: "OPC UA service detected"
            },
            remediation: "Enable OPC UA security policies (Basic256Sha256 or Aes256_Sha256_RsaPss). Require certificate-based authentication. Implement application-level access control. Segment OPC UA servers from IT networks. Use OPC UA firewall/proxy for cross-zone communication.",
            environment: "ics_ot",
            foundAt: Date.now()
          });
        }
      } catch {
      }
    }
    try {
      const discoveryUrl = `http://${host}:4840/`;
      const response = await fetch(discoveryUrl, { signal: AbortSignal.timeout(timeout) });
      if (response.status === 200) {
        const body = await response.text();
        if (body.includes("OPC") || body.includes("opc.tcp")) {
          findings.push({
            id: randomUUID3(),
            source: "ics:opcua-discovery",
            title: `OPC UA Discovery Service Exposed: ${host}`,
            description: `An OPC UA Local Discovery Server (LDS) is accessible on ${host}. This reveals all registered OPC UA servers and their endpoints, providing a map of the industrial automation infrastructure.`,
            severity: "high",
            confidence: 80,
            target: host,
            port: 4840,
            protocol: "opcua",
            cwes: ["CWE-200"],
            evidence: {
              request: `GET ${discoveryUrl}`,
              response: body.substring(0, 2e3)
            },
            remediation: "Restrict OPC UA Discovery Server access to authorized clients. Use certificate-based authentication for discovery.",
            environment: "ics_ot",
            foundAt: Date.now()
          });
        }
      }
    } catch {
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
      const result = await executeTool({
        tool: "naabu",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
};

// server/scanforge/protocols/registry.ts
var ProtocolRegistry = class {
  constructor() {
    this.scanners = /* @__PURE__ */ new Map();
    registerBuiltinScanners(this);
  }
  /**
   * Register a protocol scanner.
   */
  register(scanner) {
    this.scanners.set(scanner.protocol, scanner);
  }
  /**
   * Get a scanner by protocol name.
   */
  get(protocol) {
    return this.scanners.get(protocol);
  }
  /**
   * Get all registered scanners.
   */
  getAll() {
    return Array.from(this.scanners.values());
  }
  /**
   * List all registered scanners (alias for getAll).
   */
  listAll() {
    return this.getAll();
  }
  /**
   * Find scanners that handle a given port number.
   */
  getByPort(port) {
    return this.getAll().filter((s) => s.defaultPorts.includes(port));
  }
  /**
   * Get scanners applicable to a specific environment.
   */
  getByEnvironment(env) {
    return this.getAll().filter((s) => {
      if (!s.environments || s.environments.length === 0) return env === "traditional";
      return s.environments.includes(env);
    });
  }
  /**
   * Get scanner count.
   */
  get count() {
    return this.scanners.size;
  }
  /**
   * List registered protocol names.
   */
  listProtocols() {
    return Array.from(this.scanners.keys());
  }
};
var _registry = null;
function getProtocolRegistry() {
  if (!_registry) {
    _registry = new ProtocolRegistry();
  }
  return _registry;
}
function registerBuiltinScanners(registry) {
  registry.register(new ToolWrappedScanner({
    name: "MySQL Scanner",
    protocol: "mysql",
    defaultPorts: [3306],
    tool: "naabu",
    argsTemplate: "--script mysql-info,mysql-enum,mysql-vuln-cve2012-2122,mysql-brute -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "PostgreSQL Scanner",
    protocol: "postgresql",
    defaultPorts: [5432],
    tool: "naabu",
    argsTemplate: "--script pgsql-brute -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "Redis Scanner",
    protocol: "redis",
    defaultPorts: [6379],
    tool: "naabu",
    argsTemplate: "--script redis-info,redis-brute -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "MongoDB Scanner",
    protocol: "mongodb",
    defaultPorts: [27017],
    tool: "naabu",
    argsTemplate: "--script mongodb-info,mongodb-databases,mongodb-brute -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "SMB Scanner",
    protocol: "smb",
    defaultPorts: [445, 139],
    tool: "naabu",
    argsTemplate: "--script smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "LDAP Scanner",
    protocol: "ldap",
    defaultPorts: [389, 636],
    tool: "naabu",
    argsTemplate: "--script ldap-rootdse,ldap-search,ldap-brute -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "RDP Scanner",
    protocol: "rdp",
    defaultPorts: [3389],
    tool: "naabu",
    argsTemplate: "--script rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "VNC Scanner",
    protocol: "vnc",
    defaultPorts: [5900, 5901],
    tool: "naabu",
    argsTemplate: "--script vnc-info,vnc-brute -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "AMQP/RabbitMQ Scanner",
    protocol: "amqp",
    defaultPorts: [5672, 15672],
    tool: "naabu",
    argsTemplate: "--script amqp-info -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new ToolWrappedScanner({
    name: "Telnet Scanner",
    protocol: "telnet",
    defaultPorts: [23],
    tool: "naabu",
    argsTemplate: "--script telnet-brute,telnet-ntlm-info -p {port} {host}",
    parseOutput: parseScanForgeScriptOutput
  }));
  registry.register(new HTTPSecurityScanner());
  registry.register(new TLSScanner());
  registry.register(new DNSScanner());
  registry.register(new AWSIMDSScanner());
  registry.register(new CloudStorageScanner());
  registry.register(new KubernetesAPIScanner());
  registry.register(new DockerAPIScanner());
  registry.register(new EtcdScanner());
  registry.register(new ContainerRegistryScanner());
  registry.register(new MQTTScanner());
  registry.register(new CoAPScanner());
  registry.register(new UPnPScanner());
  registry.register(new ModbusScanner());
  registry.register(new DNP3Scanner());
  registry.register(new BACnetScanner());
  registry.register(new EtherNetIPScanner());
  registry.register(new OPCUAScanner());
}
var ToolWrappedScanner = class {
  constructor(config) {
    this.name = config.name;
    this.protocol = config.protocol;
    this.defaultPorts = config.defaultPorts;
    this.config = config;
  }
  async scan(target, scanConfig) {
    const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
    const host = target.value;
    const port = target.ports?.find((p) => this.defaultPorts.includes(p)) || this.defaultPorts[0];
    const args = this.config.argsTemplate.replace(/{host}/g, host).replace(/{port}/g, String(port));
    const result = await executeTool({
      tool: this.config.tool,
      args,
      target: host,
      timeoutSeconds: scanConfig?.scannerTimeoutSeconds || 120
    });
    if (result.exitCode !== 0 && !result.stdout) {
      return [];
    }
    return this.config.parseOutput(result.stdout, target, this.protocol);
  }
  async probe(host, port) {
    const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
    const result = await executeTool({
      tool: "naabu",
      args: `-sT -p ${port} --open -T4 ${host}`,
      target: host,
      timeoutSeconds: 15
    });
    return result.stdout.includes("open");
  }
};
var HTTPSecurityScanner = class {
  constructor() {
    this.name = "HTTP Security Scanner";
    this.protocol = "http";
    this.defaultPorts = [80, 443, 8080, 8443];
  }
  async scan(target, config) {
    const findings = [];
    const baseUrl = target.type === "url" ? target.value : `https://${target.value}`;
    try {
      const response = await fetch(baseUrl, {
        method: "GET",
        headers: { "User-Agent": config?.userAgent || "AC3-ScanForge/1.0" },
        redirect: "follow",
        signal: AbortSignal.timeout(15e3)
      });
      const headers = {};
      response.headers.forEach((v, k) => {
        headers[k] = v;
      });
      const securityHeaders = [
        { header: "strict-transport-security", name: "HSTS", severity: "medium", cwe: "CWE-319" },
        { header: "x-content-type-options", name: "X-Content-Type-Options", severity: "low", cwe: "CWE-16" },
        { header: "x-frame-options", name: "X-Frame-Options", severity: "medium", cwe: "CWE-1021" },
        { header: "content-security-policy", name: "Content-Security-Policy", severity: "medium", cwe: "CWE-79" },
        { header: "x-xss-protection", name: "X-XSS-Protection", severity: "low", cwe: "CWE-79" },
        { header: "referrer-policy", name: "Referrer-Policy", severity: "low", cwe: "CWE-200" },
        { header: "permissions-policy", name: "Permissions-Policy", severity: "low", cwe: "CWE-16" }
      ];
      for (const sh of securityHeaders) {
        if (!headers[sh.header]) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-security-headers",
            title: `Missing Security Header: ${sh.name}`,
            description: `The ${sh.name} header is not set on ${target.value}. This header helps protect against common web attacks.`,
            severity: sh.severity,
            confidence: 95,
            target: target.value,
            port: 443,
            protocol: "https",
            cwes: [sh.cwe],
            evidence: {
              request: `GET ${baseUrl}`,
              data: { missingHeader: sh.header, allHeaders: headers }
            },
            remediation: `Add the ${sh.name} header to your web server configuration.`,
            foundAt: Date.now()
          });
        }
      }
      const infoHeaders = ["server", "x-powered-by", "x-aspnet-version"];
      for (const h of infoHeaders) {
        if (headers[h]) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-security-headers",
            title: `Information Disclosure: ${h} header`,
            description: `The ${h} header reveals server technology: "${headers[h]}". This information can help attackers target known vulnerabilities.`,
            severity: "info",
            confidence: 100,
            target: target.value,
            port: 443,
            protocol: "https",
            cwes: ["CWE-200"],
            evidence: {
              matchedPattern: `${h}: ${headers[h]}`,
              data: { header: h, value: headers[h] }
            },
            remediation: `Remove or obfuscate the ${h} header in your web server configuration.`,
            foundAt: Date.now()
          });
        }
      }
      const setCookie = headers["set-cookie"];
      if (setCookie) {
        if (!setCookie.toLowerCase().includes("secure")) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-cookie-security",
            title: "Cookie Missing Secure Flag",
            description: "A cookie is set without the Secure flag, allowing it to be transmitted over unencrypted HTTP connections.",
            severity: "medium",
            confidence: 95,
            target: target.value,
            protocol: "https",
            cwes: ["CWE-614"],
            evidence: { matchedPattern: setCookie.substring(0, 200) },
            remediation: "Add the Secure flag to all cookies.",
            foundAt: Date.now()
          });
        }
        if (!setCookie.toLowerCase().includes("httponly")) {
          findings.push({
            id: crypto.randomUUID(),
            source: "http-cookie-security",
            title: "Cookie Missing HttpOnly Flag",
            description: "A cookie is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS attacks.",
            severity: "medium",
            confidence: 95,
            target: target.value,
            protocol: "https",
            cwes: ["CWE-1004"],
            evidence: { matchedPattern: setCookie.substring(0, 200) },
            remediation: "Add the HttpOnly flag to session cookies.",
            foundAt: Date.now()
          });
        }
      }
    } catch (err) {
      console.debug(`[HTTPScanner] Failed to connect to ${target.value}: ${err.message}`);
    }
    return findings;
  }
  async probe(host, port) {
    try {
      const proto = port === 443 || port === 8443 ? "https" : "http";
      await fetch(`${proto}://${host}:${port}/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5e3)
      });
      return true;
    } catch {
      return false;
    }
  }
};
var TLSScanner = class {
  constructor() {
    this.name = "TLS Scanner";
    this.protocol = "tls";
    this.defaultPorts = [443, 8443, 993, 995, 465];
  }
  async scan(target, config) {
    const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
    const host = target.value;
    const port = target.ports?.find((p) => this.defaultPorts.includes(p)) || 443;
    const result = await executeTool({
      tool: "sslscan",
      args: `--no-colour ${host}:${port}`,
      target: host,
      timeoutSeconds: 60
    });
    return this.parseSslscanOutput(result.stdout, target);
  }
  async probe(host, port) {
    try {
      await fetch(`https://${host}:${port}/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5e3)
      });
      return true;
    } catch {
      return false;
    }
  }
  parseSslscanOutput(stdout, target) {
    const findings = [];
    if (stdout.includes("SSLv3") && stdout.includes("Enabled")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "tls-scanner",
        title: "SSLv3 Protocol Enabled (POODLE)",
        description: "SSLv3 is enabled on this server. This protocol is vulnerable to the POODLE attack (CVE-2014-3566).",
        severity: "high",
        confidence: 100,
        target: target.value,
        protocol: "tls",
        cves: ["CVE-2014-3566"],
        cwes: ["CWE-327"],
        evidence: { matchedPattern: "SSLv3 Enabled" },
        remediation: "Disable SSLv3 and use TLS 1.2 or higher.",
        foundAt: Date.now()
      });
    }
    if (stdout.includes("TLSv1.0") && stdout.includes("Enabled")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "tls-scanner",
        title: "TLS 1.0 Protocol Enabled",
        description: "TLS 1.0 is enabled. This protocol version has known weaknesses and is deprecated by NIST and PCI DSS.",
        severity: "medium",
        confidence: 100,
        target: target.value,
        protocol: "tls",
        cwes: ["CWE-327"],
        evidence: { matchedPattern: "TLSv1.0 Enabled" },
        remediation: "Disable TLS 1.0 and use TLS 1.2 or higher.",
        foundAt: Date.now()
      });
    }
    const weakCiphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"];
    for (const cipher of weakCiphers) {
      if (stdout.includes(cipher) && stdout.includes("Accepted")) {
        findings.push({
          id: crypto.randomUUID(),
          source: "tls-scanner",
          title: `Weak Cipher Suite: ${cipher}`,
          description: `The server accepts the weak cipher suite ${cipher}. This can be exploited to decrypt traffic.`,
          severity: cipher === "NULL" || cipher === "EXPORT" ? "critical" : "high",
          confidence: 100,
          target: target.value,
          protocol: "tls",
          cwes: ["CWE-327"],
          evidence: { matchedPattern: `${cipher} Accepted` },
          remediation: `Disable ${cipher} cipher suites and use only strong ciphers (AES-GCM, ChaCha20).`,
          foundAt: Date.now()
        });
      }
    }
    const expiryMatch = stdout.match(/Not valid after:\s+(.+)/);
    if (expiryMatch) {
      const expiry = new Date(expiryMatch[1]);
      const daysUntilExpiry = Math.floor((expiry.getTime() - Date.now()) / (1e3 * 60 * 60 * 24));
      if (daysUntilExpiry < 0) {
        findings.push({
          id: crypto.randomUUID(),
          source: "tls-scanner",
          title: "Expired TLS Certificate",
          description: `The TLS certificate expired ${Math.abs(daysUntilExpiry)} days ago.`,
          severity: "critical",
          confidence: 100,
          target: target.value,
          protocol: "tls",
          cwes: ["CWE-295"],
          evidence: { data: { expiryDate: expiryMatch[1], daysExpired: Math.abs(daysUntilExpiry) } },
          remediation: "Renew the TLS certificate immediately.",
          foundAt: Date.now()
        });
      } else if (daysUntilExpiry < 30) {
        findings.push({
          id: crypto.randomUUID(),
          source: "tls-scanner",
          title: "TLS Certificate Expiring Soon",
          description: `The TLS certificate expires in ${daysUntilExpiry} days.`,
          severity: "medium",
          confidence: 100,
          target: target.value,
          protocol: "tls",
          cwes: ["CWE-295"],
          evidence: { data: { expiryDate: expiryMatch[1], daysRemaining: daysUntilExpiry } },
          remediation: "Renew the TLS certificate before it expires.",
          foundAt: Date.now()
        });
      }
    }
    return findings;
  }
};
var DNSScanner = class {
  constructor() {
    this.name = "DNS Scanner";
    this.protocol = "dns";
    this.defaultPorts = [53];
  }
  async scan(target, config) {
    const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
    const findings = [];
    const host = target.value;
    const axfrResult = await executeTool({
      tool: "dig",
      args: `AXFR ${host}`,
      target: host,
      timeoutSeconds: 15
    });
    if (axfrResult.stdout.includes("ANSWER SECTION") && !axfrResult.stdout.includes("Transfer failed")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "dns-scanner",
        title: "DNS Zone Transfer Allowed",
        description: `DNS zone transfer (AXFR) is allowed for ${host}. This exposes all DNS records to unauthorized parties.`,
        severity: "high",
        confidence: 100,
        target: host,
        port: 53,
        protocol: "dns",
        cwes: ["CWE-200"],
        techniqueIds: ["T1590.002"],
        evidence: { response: axfrResult.stdout.substring(0, 2e3) },
        remediation: "Restrict zone transfers to authorized secondary DNS servers only.",
        foundAt: Date.now()
      });
    }
    const dnssecResult = await executeTool({
      tool: "dig",
      args: `+dnssec ${host} DNSKEY`,
      target: host,
      timeoutSeconds: 10
    });
    if (!dnssecResult.stdout.includes("DNSKEY") || dnssecResult.stdout.includes("SERVFAIL")) {
      findings.push({
        id: crypto.randomUUID(),
        source: "dns-scanner",
        title: "DNSSEC Not Configured",
        description: `DNSSEC is not configured for ${host}. This makes the domain vulnerable to DNS spoofing and cache poisoning attacks.`,
        severity: "medium",
        confidence: 85,
        target: host,
        port: 53,
        protocol: "dns",
        cwes: ["CWE-350"],
        evidence: { data: { dnssecEnabled: false } },
        remediation: "Enable DNSSEC for the domain to protect against DNS spoofing.",
        foundAt: Date.now()
      });
    }
    return findings;
  }
  async probe(host, port) {
    const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
    const result = await executeTool({
      tool: "dig",
      args: `+short ${host} A`,
      target: host,
      timeoutSeconds: 5
    });
    return result.exitCode === 0 && result.stdout.trim().length > 0;
  }
};
function parseScanForgeScriptOutput(stdout, target, protocol) {
  const findings = [];
  const vulnBlocks = stdout.split(/\|_?\s*/);
  for (const block of vulnBlocks) {
    if (block.includes("VULNERABLE") || block.includes("State: VULNERABLE")) {
      const titleMatch = block.match(/^(\S+):/);
      const title = titleMatch ? titleMatch[1] : "Unknown Vulnerability";
      const cveMatch = block.match(/CVE-\d{4}-\d+/g);
      const descMatch = block.match(/Description:\s*(.+)/);
      findings.push({
        id: crypto.randomUUID(),
        source: `nuclei-template:${protocol}`,
        title: `${protocol.toUpperCase()} Vulnerability: ${title}`,
        description: descMatch ? descMatch[1] : `ScanForge script detected a vulnerability in ${protocol} service on ${target.value}.`,
        severity: cveMatch ? "high" : "medium",
        confidence: 85,
        target: target.value,
        protocol,
        cves: cveMatch || void 0,
        evidence: { response: block.substring(0, 2e3) },
        remediation: `Update the ${protocol} service to the latest version and apply security patches.`,
        foundAt: Date.now()
      });
    }
    if (block.includes("Valid credentials") || block.includes("Accounts:")) {
      findings.push({
        id: crypto.randomUUID(),
        source: `nuclei-template:${protocol}`,
        title: `${protocol.toUpperCase()} Weak Credentials Detected`,
        description: `Default or weak credentials were found for the ${protocol} service on ${target.value}.`,
        severity: "critical",
        confidence: 95,
        target: target.value,
        protocol,
        cwes: ["CWE-521", "CWE-798"],
        techniqueIds: ["T1110"],
        evidence: { response: block.substring(0, 1e3) },
        remediation: "Change default credentials immediately and enforce strong password policies.",
        foundAt: Date.now()
      });
    }
    if (block.includes("Version:") || block.includes("version:")) {
      const versionMatch = block.match(/[Vv]ersion:\s*(.+)/);
      if (versionMatch) {
        findings.push({
          id: crypto.randomUUID(),
          source: `nuclei-template:${protocol}`,
          title: `${protocol.toUpperCase()} Version Disclosure`,
          description: `The ${protocol} service on ${target.value} discloses its version: ${versionMatch[1].trim()}.`,
          severity: "info",
          confidence: 100,
          target: target.value,
          protocol,
          cwes: ["CWE-200"],
          evidence: { matchedPattern: versionMatch[0] },
          remediation: "Consider hiding version information to reduce the attack surface.",
          foundAt: Date.now()
        });
      }
    }
  }
  return findings;
}

// server/scanforge/intelligence/ti-engine.ts
var DFIR_ARTIFACTS = [
  // Persistence mechanisms
  {
    category: "persistence",
    indicator: "web_shell",
    description: "Web shells in common upload directories or writable paths",
    attackTechniques: ["T1505.003"],
    scanChecks: ["webshell-detection", "file-upload-vuln", "directory-listing"]
  },
  {
    category: "persistence",
    indicator: "cron_backdoor",
    description: "Cron jobs or scheduled tasks creating reverse shells",
    attackTechniques: ["T1053.003"],
    scanChecks: ["ssh-weak-auth", "command-injection"]
  },
  {
    category: "persistence",
    indicator: "ssh_authorized_keys",
    description: "Unauthorized SSH keys in authorized_keys files",
    attackTechniques: ["T1098.004"],
    scanChecks: ["ssh-key-enum", "ssh-weak-config"]
  },
  {
    category: "persistence",
    indicator: "startup_script_modification",
    description: "Modified startup scripts or init.d entries",
    attackTechniques: ["T1037"],
    scanChecks: ["os-command-injection", "privilege-escalation"]
  },
  // Lateral movement
  {
    category: "lateral_movement",
    indicator: "smb_relay",
    description: "SMB relay attacks via NTLM authentication",
    attackTechniques: ["T1557.001"],
    scanChecks: ["smb-signing", "ntlm-relay", "smb-vuln"]
  },
  {
    category: "lateral_movement",
    indicator: "rdp_hijack",
    description: "RDP session hijacking or BlueKeep exploitation",
    attackTechniques: ["T1563.002"],
    scanChecks: ["rdp-vuln", "rdp-nla-check"]
  },
  {
    category: "lateral_movement",
    indicator: "pass_the_hash",
    description: "Pass-the-hash attacks using stolen NTLM hashes",
    attackTechniques: ["T1550.002"],
    scanChecks: ["smb-brute", "ntlm-info", "kerberos-enum"]
  },
  {
    category: "lateral_movement",
    indicator: "wmi_exec",
    description: "Remote code execution via WMI",
    attackTechniques: ["T1047"],
    scanChecks: ["smb-enum", "wmi-access"]
  },
  // Credential access
  {
    category: "credential_access",
    indicator: "credential_dumping",
    description: "Credential dumping from memory or registry",
    attackTechniques: ["T1003"],
    scanChecks: ["smb-vuln", "rdp-vuln", "default-creds"]
  },
  {
    category: "credential_access",
    indicator: "kerberoasting",
    description: "Kerberoasting attacks against Active Directory",
    attackTechniques: ["T1558.003"],
    scanChecks: ["ldap-enum", "kerberos-enum", "ad-enum"]
  },
  {
    category: "credential_access",
    indicator: "database_credential_theft",
    description: "Extraction of credentials from database servers",
    attackTechniques: ["T1555"],
    scanChecks: ["mysql-brute", "postgres-brute", "mongodb-brute", "redis-noauth"]
  },
  // Exfiltration
  {
    category: "exfiltration",
    indicator: "dns_tunneling",
    description: "Data exfiltration via DNS queries",
    attackTechniques: ["T1048.003"],
    scanChecks: ["dns-zone-transfer", "dns-enum"]
  },
  {
    category: "exfiltration",
    indicator: "cloud_storage_exfil",
    description: "Exfiltration to misconfigured cloud storage",
    attackTechniques: ["T1567.002"],
    scanChecks: ["s3-bucket-enum", "cloud-storage-misconfig"]
  },
  // Defense evasion
  {
    category: "defense_evasion",
    indicator: "log_tampering",
    description: "Log file deletion or modification",
    attackTechniques: ["T1070"],
    scanChecks: ["file-inclusion", "command-injection"]
  },
  {
    category: "defense_evasion",
    indicator: "waf_bypass",
    description: "WAF bypass techniques for payload delivery",
    attackTechniques: ["T1562.001"],
    scanChecks: ["waf-detection", "xss-bypass", "sqli-bypass"]
  }
];
var IntelligenceEngine = class {
  constructor() {
    this.kevCatalog = /* @__PURE__ */ new Map();
    this.epssScores = /* @__PURE__ */ new Map();
    this.threatActors = [];
    this.initialized = false;
    this.lastFeedUpdate = 0;
    this.feedUpdateIntervalMs = 24 * 60 * 60 * 1e3;
  }
  // 24 hours
  /**
   * Initialize the intelligence engine by loading TI feeds.
   */
  async initialize() {
    if (this.initialized && Date.now() - this.lastFeedUpdate < this.feedUpdateIntervalMs) {
      return;
    }
    await Promise.allSettled([
      this.loadKEV(),
      this.loadThreatActors()
    ]);
    this.initialized = true;
    this.lastFeedUpdate = Date.now();
    console.log(`[TIEngine] Initialized: ${this.kevCatalog.size} KEV entries, ${this.threatActors.length} threat actors`);
  }
  /**
   * Pre-scan: Prioritize templates based on target context and TI data.
   * Returns templates sorted by relevance (most important first).
   */
  async prioritizeTemplates(templates, target, config) {
    const scored = templates.map((t) => ({
      template: t,
      score: this.scoreTemplateRelevance(t, target, config)
    }));
    scored.sort((a, b) => b.score - a.score);
    return scored.map((s) => s.template);
  }
  /**
   * Post-scan: Enrich a finding with TI data and compute risk score.
   */
  async enrichFinding(finding) {
    const riskScore = {
      composite: 0
    };
    riskScore.cvss = finding.severity === "critical" ? 9.5 : finding.severity === "high" ? 7.5 : finding.severity === "medium" ? 5 : finding.severity === "low" ? 3 : 1;
    if (finding.cves?.length) {
      for (const cve of finding.cves) {
        const kev = this.kevCatalog.get(cve);
        if (kev) {
          riskScore.kevListed = true;
          riskScore.kevDueDate = kev.dueDate;
          riskScore.ransomwareUse = kev.knownRansomwareCampaignUse === "Known";
          riskScore.cvss = Math.max(riskScore.cvss || 0, 8);
          break;
        }
      }
    }
    if (finding.cves?.length) {
      for (const cve of finding.cves) {
        const epss = this.epssScores.get(cve);
        if (epss) {
          riskScore.epss = epss.epss;
          riskScore.epssPercentile = epss.percentile;
          break;
        }
      }
    }
    if (finding.techniqueIds?.length) {
      const dfirMatches = DFIR_ARTIFACTS.filter(
        (a) => a.attackTechniques.some((t) => finding.techniqueIds.includes(t))
      );
      if (dfirMatches.length > 0) {
        riskScore.dfirPrecedent = true;
        riskScore.dfirCategories = [...new Set(dfirMatches.map((d) => d.category))];
      }
    }
    if (finding.cves?.length) {
      const relevantActors = this.threatActors.filter(
        (actor) => actor.commonCVEs.some((cve) => finding.cves.includes(cve))
      );
      if (relevantActors.length > 0) {
        riskScore.threatActorRelevance = relevantActors.map((a) => a.name);
      }
    }
    riskScore.composite = this.computeCompositeScore(riskScore, finding);
    finding.riskScore = riskScore;
    return finding;
  }
  /**
   * Get DFIR-informed scan checks for a target.
   * Returns additional template IDs/tags that should be run based on
   * DFIR artifact knowledge.
   */
  getDFIRInformedChecks(target) {
    const checks = [];
    if (target.services) {
      const serviceStr = Object.values(target.services).join(" ").toLowerCase();
      if (serviceStr.includes("smb") || serviceStr.includes("microsoft-ds")) {
        checks.push(...DFIR_ARTIFACTS.filter((a) => a.category === "lateral_movement" && a.scanChecks.some((c) => c.includes("smb"))).flatMap((a) => a.scanChecks));
      }
      if (serviceStr.includes("rdp")) {
        checks.push(...DFIR_ARTIFACTS.filter((a) => a.scanChecks.some((c) => c.includes("rdp"))).flatMap((a) => a.scanChecks));
      }
      if (serviceStr.includes("ldap")) {
        checks.push(...DFIR_ARTIFACTS.filter((a) => a.scanChecks.some((c) => c.includes("ldap") || c.includes("kerberos"))).flatMap((a) => a.scanChecks));
      }
      if (serviceStr.includes("mysql") || serviceStr.includes("postgres") || serviceStr.includes("redis") || serviceStr.includes("mongo")) {
        checks.push(...DFIR_ARTIFACTS.filter((a) => a.category === "credential_access" && a.scanChecks.some((c) => c.includes("brute") || c.includes("noauth"))).flatMap((a) => a.scanChecks));
      }
      if (serviceStr.includes("http") || serviceStr.includes("nginx") || serviceStr.includes("apache")) {
        checks.push(...DFIR_ARTIFACTS.filter((a) => a.indicator === "web_shell" || a.indicator === "waf_bypass").flatMap((a) => a.scanChecks));
      }
      if (serviceStr.includes("dns")) {
        checks.push(...DFIR_ARTIFACTS.filter((a) => a.indicator === "dns_tunneling").flatMap((a) => a.scanChecks));
      }
    }
    return [...new Set(checks)];
  }
  /**
   * Get count of KEV catalog entries.
   */
  getKEVCount() {
    return this.kevCatalog.size;
  }
  /**
   * Get count of loaded threat actor profiles.
   */
  getThreatActorCount() {
    return this.threatActors.length;
  }
  /**
   * Refresh TI feeds (KEV, threat actors, EPSS).
   */
  async refreshFeeds() {
    this.initialized = false;
    await this.initialize();
  }
  /**
   * Calculate a risk score for a target based on TI context.
   */
  calculateRiskScore(params) {
    let score = 30;
    const highRiskIndustries = ["finance", "healthcare", "government", "critical_infrastructure", "defense"];
    if (params.industry && highRiskIndustries.includes(params.industry)) {
      score += 20;
    }
    if (params.services?.length) {
      const riskyServices = ["smb", "rdp", "telnet", "ftp", "vnc", "redis", "mongodb", "mysql", "postgres"];
      const riskyCount = params.services.filter(
        (s) => riskyServices.some((r) => s.toLowerCase().includes(r))
      ).length;
      score += Math.min(30, riskyCount * 10);
    }
    if (params.industry) {
      const targetingActors = this.threatActors.filter(
        (a) => a.targetIndustries.includes(params.industry)
      );
      score += Math.min(20, targetingActors.length * 5);
    }
    return Math.min(100, score);
  }
  // ─── Internal ──────────────────────────────────────────────────────────
  scoreTemplateRelevance(template, target, config) {
    let score = 50;
    if (template.severity === "critical") score += 30;
    else if (template.severity === "high") score += 20;
    else if (template.severity === "medium") score += 10;
    if (template.references?.cves?.some((cve) => this.kevCatalog.has(cve))) {
      score += 40;
    }
    if (template.attack?.techniqueIds?.length) {
      const dfirMatch = DFIR_ARTIFACTS.some(
        (a) => a.attackTechniques.some((t) => template.attack.techniqueIds.includes(t))
      );
      if (dfirMatch) score += 25;
    }
    if (config?.targetIndustry) {
      const relevantActors = this.threatActors.filter(
        (a) => a.targetIndustries.includes(config.targetIndustry)
      );
      if (template.references?.cves?.some(
        (cve) => relevantActors.some((a) => a.commonCVEs.includes(cve))
      )) {
        score += 35;
      }
    }
    if (target.services) {
      const serviceStr = Object.values(target.services).join(" ").toLowerCase();
      if (serviceStr.includes(template.protocol)) score += 15;
    }
    if (template.intelligence?.feeds?.length) {
      score += 10;
    }
    return Math.min(100, score);
  }
  computeCompositeScore(riskScore, finding) {
    let score = 0;
    score += (riskScore.cvss || 5) / 10 * 40;
    if (riskScore.epss !== void 0) {
      score += riskScore.epss * 20;
    } else {
      score += 5;
    }
    if (riskScore.kevListed) {
      score += 15;
      if (riskScore.ransomwareUse) score += 5;
    }
    if (riskScore.dfirPrecedent) {
      score += 10;
    }
    if (riskScore.threatActorRelevance?.length) {
      score += Math.min(10, riskScore.threatActorRelevance.length * 3);
    }
    score += finding.confidence / 100 * 5;
    return Math.round(Math.min(100, score));
  }
  async loadKEV() {
    try {
      const response = await fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        { signal: AbortSignal.timeout(3e4) }
      );
      if (!response.ok) throw new Error(`KEV feed HTTP ${response.status}`);
      const data = await response.json();
      this.kevCatalog.clear();
      for (const vuln of data.vulnerabilities || []) {
        this.kevCatalog.set(vuln.cveID, vuln);
      }
      console.log(`[TIEngine] Loaded ${this.kevCatalog.size} KEV entries`);
    } catch (err) {
      console.warn(`[TIEngine] Failed to load KEV feed: ${err.message}`);
    }
  }
  async loadThreatActors() {
    this.threatActors = [
      {
        name: "APT28 (Fancy Bear)",
        aliases: ["Sofacy", "Sednit", "STRONTIUM"],
        targetIndustries: ["government", "defense", "energy", "media"],
        targetRegions: ["US", "EU", "NATO"],
        commonTechniques: ["T1566.001", "T1203", "T1059.001", "T1071.001"],
        commonCVEs: ["CVE-2017-0199", "CVE-2017-11882", "CVE-2023-23397"],
        tools: ["X-Agent", "Zebrocy", "Koadic"]
      },
      {
        name: "APT29 (Cozy Bear)",
        aliases: ["NOBELIUM", "Midnight Blizzard", "The Dukes"],
        targetIndustries: ["government", "technology", "healthcare", "think_tanks"],
        targetRegions: ["US", "EU", "UK"],
        commonTechniques: ["T1195.002", "T1078", "T1550.001", "T1071.001"],
        commonCVEs: ["CVE-2021-21972", "CVE-2021-26855", "CVE-2023-42793"],
        tools: ["SUNBURST", "TEARDROP", "EnvyScout"]
      },
      {
        name: "Lazarus Group",
        aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
        targetIndustries: ["finance", "cryptocurrency", "defense", "technology"],
        targetRegions: ["US", "KR", "JP", "Global"],
        commonTechniques: ["T1566.001", "T1059.007", "T1055", "T1486"],
        commonCVEs: ["CVE-2021-44228", "CVE-2022-47966", "CVE-2023-42793"],
        tools: ["DTrack", "BLINDINGCAN", "AppleJeus"]
      },
      {
        name: "LockBit",
        aliases: ["LockBit 3.0", "LockBit Black"],
        targetIndustries: ["healthcare", "finance", "manufacturing", "education"],
        targetRegions: ["Global"],
        commonTechniques: ["T1486", "T1490", "T1078", "T1021.001"],
        commonCVEs: ["CVE-2021-22986", "CVE-2023-0669", "CVE-2023-4966"],
        tools: ["StealBit", "Cobalt Strike"]
      },
      {
        name: "ALPHV/BlackCat",
        aliases: ["BlackCat", "Noberus"],
        targetIndustries: ["healthcare", "finance", "legal", "technology"],
        targetRegions: ["US", "EU", "Global"],
        commonTechniques: ["T1486", "T1567", "T1078", "T1048"],
        commonCVEs: ["CVE-2021-27065", "CVE-2023-27350", "CVE-2023-22515"],
        tools: ["ExMatter", "Eamfo"]
      },
      {
        name: "Volt Typhoon",
        aliases: ["BRONZE SILHOUETTE", "Vanguard Panda"],
        targetIndustries: ["critical_infrastructure", "telecommunications", "government"],
        targetRegions: ["US", "Guam", "Pacific"],
        commonTechniques: ["T1190", "T1133", "T1078", "T1059"],
        commonCVEs: ["CVE-2021-40539", "CVE-2021-27860", "CVE-2023-46805"],
        tools: ["Living-off-the-land", "Impacket", "Fast Reverse Proxy"]
      }
    ];
  }
};
var _engine = null;
function getIntelligenceEngine() {
  if (!_engine) {
    _engine = new IntelligenceEngine();
  }
  return _engine;
}

// server/scanforge/intelligence/context-engine.ts
var invokeLLM;
async function getLLM() {
  if (!invokeLLM) {
    const mod = await import("./llm-HOOAP2ZQ.js");
    invokeLLM = mod.invokeLLM;
  }
  return invokeLLM;
}
var CACHE_CONFIG = {
  /** Default TTL for classification results: 24 hours */
  DEFAULT_TTL_MS: 24 * 60 * 60 * 1e3,
  /** Reduced TTL for low-confidence classifications: 4 hours */
  LOW_CONFIDENCE_TTL_MS: 4 * 60 * 60 * 1e3,
  /** TTL for heuristic (non-LLM) classifications: 1 hour */
  HEURISTIC_TTL_MS: 1 * 60 * 60 * 1e3,
  /** Confidence threshold below which reduced TTL applies */
  LOW_CONFIDENCE_THRESHOLD: 50,
  /** Maximum cache entries before LRU eviction */
  MAX_ENTRIES: 2e3
};
var ClassificationCache = class {
  constructor() {
    this.entries = /* @__PURE__ */ new Map();
    this.infraVersion = 0;
    this.stats = { hits: 0, misses: 0, evictions: 0, invalidations: 0 };
  }
  get(key) {
    const entry = this.entries.get(key);
    if (!entry) {
      this.stats.misses++;
      return void 0;
    }
    if (Date.now() - entry.cachedAt > entry.ttlMs) {
      this.entries.delete(key);
      this.stats.misses++;
      return void 0;
    }
    if (entry.infraVersion < this.infraVersion) {
      this.entries.delete(key);
      this.stats.invalidations++;
      return void 0;
    }
    this.stats.hits++;
    return entry.value;
  }
  set(key, value, ttlMs = CACHE_CONFIG.DEFAULT_TTL_MS) {
    if (this.entries.size >= CACHE_CONFIG.MAX_ENTRIES) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey) {
        this.entries.delete(oldestKey);
        this.stats.evictions++;
      }
    }
    this.entries.set(key, {
      value,
      cachedAt: Date.now(),
      ttlMs,
      infraVersion: this.infraVersion
    });
  }
  /**
   * Invalidate all entries for a specific target (e.g., when infrastructure change detected).
   * Use when a specific host's infrastructure is known to have changed.
   */
  invalidateTarget(targetKey) {
    const deleted = this.entries.delete(targetKey);
    if (deleted) this.stats.invalidations++;
  }
  /**
   * Invalidate ALL cached classifications globally.
   * Use when a broad infrastructure change is detected (e.g., cloud migration,
   * new CDN deployment, DNS changes affecting multiple targets).
   */
  invalidateAll() {
    this.infraVersion++;
    this.stats.invalidations += this.entries.size;
  }
  /**
   * Signal that infrastructure has changed for a subset of targets matching a pattern.
   * Useful for invalidating all targets in a specific domain or subnet.
   */
  invalidateByPattern(pattern) {
    let count = 0;
    for (const key of this.entries.keys()) {
      if (pattern.test(key)) {
        this.entries.delete(key);
        count++;
      }
    }
    this.stats.invalidations += count;
    return count;
  }
  /** Get cache statistics for monitoring */
  getStats() {
    const now = Date.now();
    let expired = 0;
    for (const entry of this.entries.values()) {
      if (now - entry.cachedAt > entry.ttlMs) expired++;
    }
    return {
      ...this.stats,
      size: this.entries.size,
      expired,
      hitRate: this.stats.hits + this.stats.misses > 0 ? (this.stats.hits / (this.stats.hits + this.stats.misses) * 100).toFixed(1) + "%" : "N/A",
      infraVersion: this.infraVersion
    };
  }
  /** Clear all entries and reset stats */
  clear() {
    this.entries.clear();
    this.stats = { hits: 0, misses: 0, evictions: 0, invalidations: 0 };
  }
};
var ContextEngine = class {
  constructor() {
    this.classificationCache = new ClassificationCache();
    this.initialized = false;
  }
  async initialize() {
    try {
      await getLLM();
      this.initialized = true;
      console.log("[ContextEngine] LLM context engine initialized");
    } catch (err) {
      console.warn(`[ContextEngine] LLM not available, falling back to heuristic mode: ${err.message}`);
      this.initialized = true;
    }
  }
  // ─── 1. Asset Classification ──────────────────────────────────────────
  /**
   * Classify a target's environment using LLM analysis of recon data.
   * Falls back to heuristic classification if LLM is unavailable.
   */
  async classifyTarget(target, reconData) {
    const cacheKey = `${target.value}:${target.type}`;
    const cached = this.classificationCache.get(cacheKey);
    if (cached) return cached;
    try {
      const llm = await getLLM();
      const classification = await this.llmClassify(llm, target, reconData);
      const ttl = classification.confidence < CACHE_CONFIG.LOW_CONFIDENCE_THRESHOLD ? CACHE_CONFIG.LOW_CONFIDENCE_TTL_MS : CACHE_CONFIG.DEFAULT_TTL_MS;
      this.classificationCache.set(cacheKey, classification, ttl);
      return classification;
    } catch {
      const classification = this.heuristicClassify(target, reconData);
      this.classificationCache.set(cacheKey, classification, CACHE_CONFIG.HEURISTIC_TTL_MS);
      return classification;
    }
  }
  async llmClassify(llm, target, reconData) {
    const prompt = this.buildClassificationPrompt(target, reconData);
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert cybersecurity analyst specializing in asset classification and attack surface analysis. Analyze the provided target information and classify the asset environment. Be precise and evidence-based in your classification.`
        },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "asset_classification",
          strict: true,
          schema: {
            type: "object",
            properties: {
              environment: {
                type: "string",
                enum: ["traditional", "cloud", "iot", "ics_ot", "container", "hybrid", "unknown"],
                description: "Primary environment type of the target"
              },
              cloudProvider: {
                type: "string",
                enum: ["aws", "azure", "gcp", "digitalocean", "unknown", "none"],
                description: "Cloud provider if applicable, 'none' if not cloud"
              },
              confidence: {
                type: "integer",
                description: "Confidence in classification (0-100)"
              },
              reasoning: {
                type: "string",
                description: "Detailed reasoning for the classification"
              },
              technologies: {
                type: "array",
                items: { type: "string" },
                description: "Detected technologies and frameworks"
              },
              inferredIndustry: {
                type: "string",
                description: "Inferred industry vertical"
              },
              inferredCriticality: {
                type: "string",
                enum: ["critical", "high", "medium", "low"],
                description: "Inferred asset criticality"
              },
              recommendedProfiles: {
                type: "array",
                items: { type: "string" },
                description: "Recommended scan profiles to run"
              },
              applicableCompliance: {
                type: "array",
                items: { type: "string" },
                description: "Applicable compliance frameworks"
              }
            },
            required: [
              "environment",
              "cloudProvider",
              "confidence",
              "reasoning",
              "technologies",
              "inferredIndustry",
              "inferredCriticality",
              "recommendedProfiles",
              "applicableCompliance"
            ],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    return {
      environment: parsed.environment,
      cloudProvider: parsed.cloudProvider === "none" ? void 0 : parsed.cloudProvider,
      confidence: parsed.confidence,
      reasoning: parsed.reasoning,
      technologies: parsed.technologies,
      inferredIndustry: parsed.inferredIndustry,
      inferredCriticality: parsed.inferredCriticality,
      recommendedProfiles: parsed.recommendedProfiles,
      applicableCompliance: parsed.applicableCompliance
    };
  }
  buildClassificationPrompt(target, reconData) {
    const parts = [
      `Classify the following target asset:`,
      ``,
      `Target: ${target.value}`,
      `Type: ${target.type}`
    ];
    if (reconData?.ports?.length) {
      parts.push(`Open Ports: ${reconData.ports.join(", ")}`);
    }
    if (reconData?.services) {
      parts.push(`Services:`);
      for (const [port, service] of Object.entries(reconData.services)) {
        parts.push(`  Port ${port}: ${service}`);
      }
    }
    if (reconData?.headers) {
      parts.push(`HTTP Headers:`);
      for (const [key, value] of Object.entries(reconData.headers)) {
        parts.push(`  ${key}: ${value}`);
      }
    }
    if (reconData?.banners?.length) {
      parts.push(`Service Banners:`);
      for (const banner of reconData.banners) {
        parts.push(`  ${banner}`);
      }
    }
    if (target.cloudMeta) {
      parts.push(`Cloud Metadata: ${JSON.stringify(target.cloudMeta)}`);
    }
    if (target.iotMeta) {
      parts.push(`IoT Metadata: ${JSON.stringify(target.iotMeta)}`);
    }
    if (target.icsMeta) {
      parts.push(`ICS Metadata: ${JSON.stringify(target.icsMeta)}`);
    }
    if (target.containerMeta) {
      parts.push(`Container Metadata: ${JSON.stringify(target.containerMeta)}`);
    }
    parts.push(``);
    parts.push(`Based on the above information, classify this asset's environment type, identify the cloud provider (if any), list detected technologies, infer the industry vertical, assess criticality, recommend scan profiles, and identify applicable compliance frameworks.`);
    return parts.join("\n");
  }
  /**
   * Heuristic classification when LLM is unavailable.
   */
  heuristicClassify(target, reconData) {
    const ports = reconData?.ports || target.ports || [];
    const services = reconData?.services || target.services || {};
    const serviceStr = Object.values(services).join(" ").toLowerCase();
    const host = target.value.toLowerCase();
    const cloudPorts = [6443, 8443, 2379, 10250, 10255];
    const cloudServices = ["kubernetes", "k8s", "docker", "etcd", "consul", "vault"];
    const awsIndicators = ["amazonaws.com", "aws", "ec2", "s3"];
    const azureIndicators = ["azure", "microsoft", "blob.core.windows.net"];
    const gcpIndicators = ["googleapis.com", "gcp", "google"];
    const iotPorts = [1883, 8883, 5683, 5684, 1900];
    const iotServices = ["mqtt", "coap", "upnp", "ssdp", "zigbee"];
    const icsPorts = [502, 503, 2e4, 47808, 44818, 4840, 2222, 4843];
    const icsServices = ["modbus", "dnp3", "bacnet", "ethernetip", "opcua", "opc", "scada", "plc"];
    const containerPorts = [2375, 2376, 4243, 5e3, 6443, 10250];
    const containerServices = ["docker", "containerd", "registry", "kubelet"];
    let environment = "traditional";
    let cloudProvider;
    let confidence = 60;
    const technologies = [];
    const recommendedProfiles = [];
    const applicableCompliance = [];
    const icsPortMatch = ports.some((p) => icsPorts.includes(p));
    const icsServiceMatch = icsServices.some((s) => serviceStr.includes(s));
    if (icsPortMatch || icsServiceMatch || target.type === "ics_endpoint") {
      environment = "ics_ot";
      confidence = icsServiceMatch ? 90 : 75;
      recommendedProfiles.push("ics_ot", "network");
      applicableCompliance.push("iec_62443", "nerc_cip", "nist_800_53");
      if (icsServiceMatch) technologies.push(...icsServices.filter((s) => serviceStr.includes(s)));
    } else if (ports.some((p) => iotPorts.includes(p)) || iotServices.some((s) => serviceStr.includes(s)) || target.type === "iot_device") {
      environment = "iot";
      confidence = 80;
      recommendedProfiles.push("iot", "network");
      applicableCompliance.push("nist_csf");
      if (iotServices.some((s) => serviceStr.includes(s))) technologies.push(...iotServices.filter((s) => serviceStr.includes(s)));
    } else if (awsIndicators.some((i) => host.includes(i)) || azureIndicators.some((i) => host.includes(i)) || gcpIndicators.some((i) => host.includes(i)) || target.type === "cloud_resource") {
      environment = "cloud";
      confidence = 85;
      if (awsIndicators.some((i) => host.includes(i))) cloudProvider = "aws";
      else if (azureIndicators.some((i) => host.includes(i))) cloudProvider = "azure";
      else if (gcpIndicators.some((i) => host.includes(i))) cloudProvider = "gcp";
      recommendedProfiles.push("cloud", "web");
      applicableCompliance.push("fedramp", "nist_800_53", "cis_benchmark");
    } else if (ports.some((p) => containerPorts.includes(p)) || containerServices.some((s) => serviceStr.includes(s)) || target.type === "container") {
      environment = "container";
      confidence = 80;
      recommendedProfiles.push("container", "cloud");
      applicableCompliance.push("cis_benchmark", "nist_800_53");
      if (containerServices.some((s) => serviceStr.includes(s))) technologies.push(...containerServices.filter((s) => serviceStr.includes(s)));
    } else if ((ports.some((p) => cloudPorts.includes(p)) || cloudServices.some((s) => serviceStr.includes(s))) && ports.some((p) => [80, 443, 22, 3306].includes(p))) {
      environment = "hybrid";
      confidence = 65;
      recommendedProfiles.push("full");
      applicableCompliance.push("nist_800_53", "nist_csf");
    } else {
      environment = "traditional";
      confidence = 70;
      recommendedProfiles.push("network", "web");
      applicableCompliance.push("nist_800_53", "pci_dss");
    }
    return {
      environment,
      cloudProvider,
      confidence,
      reasoning: `Heuristic classification based on port analysis (${ports.length} ports), service fingerprinting, and hostname patterns.`,
      technologies,
      inferredCriticality: environment === "ics_ot" ? "critical" : environment === "cloud" ? "high" : "medium",
      recommendedProfiles,
      applicableCompliance
    };
  }
  // ─── 2. Adaptive Scan Planning ────────────────────────────────────────
  /**
   * Generate an adaptive scan plan based on target classification.
   */
  async planScan(target, classification, availableScanners, availableTemplateIds) {
    try {
      const llm = await getLLM();
      return await this.llmPlanScan(llm, target, classification, availableScanners, availableTemplateIds);
    } catch {
      return this.heuristicPlanScan(target, classification, availableScanners, availableTemplateIds);
    }
  }
  async llmPlanScan(llm, target, classification, availableScanners, availableTemplateIds) {
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester planning a security assessment. Based on the target classification and available tools, create an optimal scan plan. Prioritize scanners and templates that are most relevant to the target environment. Consider safety constraints for ICS/OT environments.`
        },
        {
          role: "user",
          content: [
            `Target: ${target.value} (${target.type})`,
            `Classification: ${JSON.stringify(classification, null, 2)}`,
            `Available Scanners: ${availableScanners.join(", ")}`,
            `Available Templates: ${availableTemplateIds.slice(0, 50).join(", ")}${availableTemplateIds.length > 50 ? ` ... and ${availableTemplateIds.length - 50} more` : ""}`,
            ``,
            `Create a scan plan selecting the most relevant scanners and templates. For ICS/OT targets, exclude aggressive scanners. For IoT targets, prefer gentle scanning. For cloud targets, include cloud-specific checks.`
          ].join("\n")
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "scan_plan",
          strict: true,
          schema: {
            type: "object",
            properties: {
              recommendedScanType: {
                type: "string",
                enum: ["full", "quick", "web", "network", "compliance", "cloud", "iot", "ics_ot", "container", "hybrid"]
              },
              recommendedScanners: {
                type: "array",
                items: { type: "string" }
              },
              recommendedTemplateIds: {
                type: "array",
                items: { type: "string" }
              },
              riskFactors: {
                type: "array",
                items: { type: "string" }
              },
              reasoning: {
                type: "string"
              }
            },
            required: ["recommendedScanType", "recommendedScanners", "recommendedTemplateIds", "riskFactors", "reasoning"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    return {
      target: target.value,
      classification,
      recommendedScanType: parsed.recommendedScanType,
      recommendedScanners: parsed.recommendedScanners,
      recommendedTemplateIds: parsed.recommendedTemplateIds,
      riskFactors: parsed.riskFactors,
      reasoning: parsed.reasoning,
      analyzedAt: Date.now()
    };
  }
  heuristicPlanScan(target, classification, availableScanners, availableTemplateIds) {
    const env = classification.environment;
    let recommendedScanType = "full";
    const recommendedScanners = [];
    const riskFactors = [];
    const scannerMap = {
      traditional: ["http", "tls", "dns", "mysql", "postgresql", "redis", "mongodb", "smb", "ldap", "rdp", "vnc", "telnet", "amqp"],
      cloud: ["http", "tls", "dns", "aws-imds", "cloud-storage", "kubernetes", "docker", "etcd", "container-registry"],
      iot: ["http", "tls", "mqtt", "coap", "upnp", "dns"],
      ics_ot: ["modbus", "dnp3", "bacnet", "ethernetip", "opcua"],
      container: ["kubernetes", "docker", "etcd", "container-registry", "http", "tls"],
      hybrid: ["http", "tls", "dns", "aws-imds", "cloud-storage", "kubernetes", "docker", "mysql", "postgresql"],
      unknown: ["http", "tls", "dns"]
    };
    const envScanners = scannerMap[env] || scannerMap.unknown;
    for (const s of envScanners) {
      if (availableScanners.includes(s)) {
        recommendedScanners.push(s);
      }
    }
    const typeMap = {
      traditional: "full",
      cloud: "cloud",
      iot: "iot",
      ics_ot: "ics_ot",
      container: "container",
      hybrid: "hybrid",
      unknown: "full"
    };
    recommendedScanType = typeMap[env] || "full";
    if (env === "ics_ot") {
      riskFactors.push(
        "ICS/OT environment \u2014 physical safety implications",
        "Modbus/DNP3 protocols lack authentication by design",
        "Disruption could affect critical infrastructure"
      );
    }
    if (env === "cloud") {
      riskFactors.push(
        "Cloud misconfigurations are the #1 cause of data breaches",
        "IMDS credential theft enables lateral movement",
        "Public storage buckets expose sensitive data"
      );
    }
    if (env === "iot") {
      riskFactors.push(
        "IoT devices often lack security updates",
        "Default credentials are prevalent",
        "Constrained devices may crash under heavy scanning"
      );
    }
    if (env === "container") {
      riskFactors.push(
        "Exposed Docker/K8s APIs enable full cluster compromise",
        "Container escape vulnerabilities affect host security",
        "etcd exposure leaks all cluster secrets"
      );
    }
    return {
      target: target.value,
      classification,
      recommendedScanType,
      recommendedScanners,
      recommendedTemplateIds: availableTemplateIds.slice(0, 20),
      riskFactors,
      reasoning: `Heuristic scan plan for ${env} environment targeting ${target.value}. Selected ${recommendedScanners.length} scanners optimized for this environment type.`,
      analyzedAt: Date.now()
    };
  }
  // ─── 3. Finding Correlation (Attack Path Analysis) ────────────────────
  /**
   * Correlate findings into attack paths using LLM reasoning.
   */
  async correlateFindings(findings, target, classification) {
    if (findings.length < 2) {
      return {
        attackPaths: [],
        uncorrelatedFindings: findings.map((f) => f.id),
        reasoning: "Insufficient findings for correlation (minimum 2 required)."
      };
    }
    try {
      const llm = await getLLM();
      return await this.llmCorrelate(llm, findings, target, classification);
    } catch {
      return this.heuristicCorrelate(findings, target, classification);
    }
  }
  async llmCorrelate(llm, findings, target, classification) {
    const findingSummaries = findings.slice(0, 30).map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      port: f.port,
      protocol: f.protocol,
      cves: f.cves,
      cwes: f.cwes,
      techniqueIds: f.techniqueIds
    }));
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester analyzing scan findings to identify attack paths. An attack path is a chain of vulnerabilities that, when exploited in sequence, lead to a significant security impact (e.g., initial access \u2192 lateral movement \u2192 privilege escalation \u2192 data exfiltration). Identify realistic attack paths from the provided findings. Each path should have at least 2 findings in the chain.`
        },
        {
          role: "user",
          content: [
            `Target: ${target.value} (${classification.environment})`,
            `Total Findings: ${findings.length}`,
            ``,
            `Findings:`,
            JSON.stringify(findingSummaries, null, 2),
            ``,
            `Identify attack paths by chaining related findings. Consider MITRE ATT&CK tactics progression.`
          ].join("\n")
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "correlation_result",
          strict: true,
          schema: {
            type: "object",
            properties: {
              attackPaths: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    description: { type: "string" },
                    findingChain: { type: "array", items: { type: "string" } },
                    tacticsTraversed: { type: "array", items: { type: "string" } },
                    riskScore: { type: "integer" },
                    exploitability: { type: "integer" },
                    businessImpact: { type: "string" },
                    narrative: { type: "string" }
                  },
                  required: ["name", "description", "findingChain", "tacticsTraversed", "riskScore", "exploitability", "businessImpact", "narrative"],
                  additionalProperties: false
                }
              },
              uncorrelatedFindings: {
                type: "array",
                items: { type: "string" }
              },
              reasoning: { type: "string" }
            },
            required: ["attackPaths", "uncorrelatedFindings", "reasoning"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    return {
      attackPaths: parsed.attackPaths.map((ap) => ({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        ...ap
      })),
      uncorrelatedFindings: parsed.uncorrelatedFindings,
      reasoning: parsed.reasoning
    };
  }
  heuristicCorrelate(findings, target, classification) {
    const attackPaths = [];
    const correlatedIds = /* @__PURE__ */ new Set();
    const initialAccess = findings.filter(
      (f) => f.techniqueIds?.some((t) => t.startsWith("T1190") || t.startsWith("T1133") || t.startsWith("T1078")) || f.cwes?.includes("CWE-306") || f.title.toLowerCase().includes("unauthenticated")
    );
    const credentialTheft = findings.filter(
      (f) => f.techniqueIds?.some((t) => t.startsWith("T1552") || t.startsWith("T1110")) || f.title.toLowerCase().includes("credential") || f.title.toLowerCase().includes("password")
    );
    const lateralMovement = findings.filter(
      (f) => f.techniqueIds?.some((t) => t.startsWith("T1021") || t.startsWith("T1570")) || f.protocol === "smb" || f.protocol === "rdp" || f.protocol === "ssh"
    );
    if (initialAccess.length > 0 && credentialTheft.length > 0) {
      const chain = [initialAccess[0].id, credentialTheft[0].id];
      if (lateralMovement.length > 0) chain.push(lateralMovement[0].id);
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "Credential Theft via Exposed Service",
        description: `An attacker can gain initial access through ${initialAccess[0].title}, then steal credentials via ${credentialTheft[0].title}${lateralMovement.length > 0 ? `, and move laterally through ${lateralMovement[0].title}` : ""}.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Credential Access", ...lateralMovement.length > 0 ? ["Lateral Movement"] : []],
        riskScore: 85,
        exploitability: 75,
        businessImpact: "Full network compromise through credential theft and lateral movement."
      });
      chain.forEach((id) => correlatedIds.add(id));
    }
    const imdsFindings = findings.filter((f) => f.source.includes("aws-imds") || f.source.includes("cloud"));
    const storageFindings = findings.filter(
      (f) => f.source.includes("s3") || f.source.includes("blob") || f.source.includes("gcs") || f.techniqueIds?.includes("T1530")
    );
    if (imdsFindings.length > 0 && storageFindings.length > 0) {
      const chain = [imdsFindings[0].id, storageFindings[0].id];
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "Cloud Credential Theft to Data Exfiltration",
        description: `An attacker can exploit ${imdsFindings[0].title} to steal cloud credentials, then access ${storageFindings[0].title} to exfiltrate data.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Credential Access", "Collection", "Exfiltration"],
        riskScore: 95,
        exploitability: 80,
        businessImpact: "Cloud credential compromise leading to data exfiltration from storage services."
      });
      chain.forEach((id) => correlatedIds.add(id));
    }
    const dockerFindings = findings.filter((f) => f.source.includes("docker") || f.source.includes("kubernetes"));
    const containerSecrets = findings.filter(
      (f) => f.source.includes("etcd") || f.title.toLowerCase().includes("secret")
    );
    if (dockerFindings.length > 0 && containerSecrets.length > 0) {
      const chain = [dockerFindings[0].id, containerSecrets[0].id];
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "Container Escape to Secret Theft",
        description: `An attacker can exploit ${dockerFindings[0].title} to gain container access, then extract secrets via ${containerSecrets[0].title}.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Privilege Escalation", "Credential Access"],
        riskScore: 90,
        exploitability: 70,
        businessImpact: "Full cluster compromise through container escape and secret extraction."
      });
      chain.forEach((id) => correlatedIds.add(id));
    }
    const icsFindings = findings.filter(
      (f) => f.environment === "ics_ot" || ["modbus", "dnp3", "bacnet", "ethernetip", "opcua"].includes(f.protocol || "")
    );
    if (icsFindings.length >= 2) {
      const chain = icsFindings.slice(0, 3).map((f) => f.id);
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "ICS/OT Process Manipulation",
        description: `Multiple ICS protocol exposures (${icsFindings.map((f) => f.protocol).join(", ")}) allow an attacker to enumerate and manipulate industrial control processes.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Discovery", "Impair Process Control"],
        riskScore: 98,
        exploitability: 60,
        businessImpact: "Physical process disruption with potential safety implications for critical infrastructure."
      });
      chain.forEach((id) => correlatedIds.add(id));
    }
    const uncorrelatedFindings = findings.filter((f) => !correlatedIds.has(f.id)).map((f) => f.id);
    return {
      attackPaths,
      uncorrelatedFindings,
      reasoning: `Heuristic correlation identified ${attackPaths.length} attack paths from ${findings.length} findings. ${uncorrelatedFindings.length} findings could not be correlated into attack chains.`
    };
  }
  // ─── 4. Enriched Narratives ───────────────────────────────────────────
  /**
   * Generate enriched narratives for findings using LLM.
   */
  async enrichFinding(finding, classification) {
    try {
      const llm = await getLLM();
      return await this.llmEnrichFinding(llm, finding, classification);
    } catch {
      return this.heuristicEnrichFinding(finding, classification);
    }
  }
  async llmEnrichFinding(llm, finding, classification) {
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert cybersecurity analyst writing finding narratives for a penetration test report. Write clear, actionable narratives that explain the technical impact and business risk. Tailor the language to the target environment (cloud/IoT/ICS/container/traditional).`
        },
        {
          role: "user",
          content: [
            `Generate an enriched narrative for this finding:`,
            ``,
            `Title: ${finding.title}`,
            `Severity: ${finding.severity}`,
            `Description: ${finding.description}`,
            `Target: ${finding.target}`,
            `Protocol: ${finding.protocol || "N/A"}`,
            `CVEs: ${finding.cves?.join(", ") || "None"}`,
            `CWEs: ${finding.cwes?.join(", ") || "None"}`,
            `MITRE ATT&CK: ${finding.techniqueIds?.join(", ") || "None"}`,
            `Environment: ${classification?.environment || finding.environment || "unknown"}`,
            `Industry: ${classification?.inferredIndustry || "unknown"}`,
            `Applicable Compliance Frameworks: ${classification?.applicableCompliance?.join(", ") || "general best practices"}`,
            ``,
            `Provide: technical narrative, executive summary, prioritized remediation steps, business impact assessment, and compliance implications (explicitly reference the applicable compliance frameworks listed above in the complianceImplications array).`
          ].join("\n")
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "enriched_narrative",
          strict: true,
          schema: {
            type: "object",
            properties: {
              technicalNarrative: { type: "string" },
              executiveSummary: { type: "string" },
              remediationSteps: { type: "array", items: { type: "string" } },
              businessImpact: { type: "string" },
              complianceImplications: { type: "array", items: { type: "string" } }
            },
            required: ["technicalNarrative", "executiveSummary", "remediationSteps", "businessImpact", "complianceImplications"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    return {
      findingId: finding.id,
      ...parsed
    };
  }
  heuristicEnrichFinding(finding, classification) {
    const env = classification?.environment || finding.environment || "traditional";
    const envContext = {
      traditional: "standard IT infrastructure",
      cloud: "cloud-hosted infrastructure",
      iot: "IoT device ecosystem",
      ics_ot: "industrial control system environment",
      container: "containerized infrastructure",
      hybrid: "hybrid multi-environment infrastructure",
      unknown: "the target infrastructure"
    };
    return {
      findingId: finding.id,
      technicalNarrative: `${finding.description} This finding was detected in ${envContext[env] || envContext.unknown}. ${finding.cves?.length ? `The vulnerability is tracked as ${finding.cves.join(", ")}.` : ""} ${finding.cwes?.length ? `The underlying weakness is classified as ${finding.cwes.join(", ")}.` : ""}`,
      executiveSummary: `A ${finding.severity}-severity security issue was identified: ${finding.title}. This affects ${finding.target} and could impact the confidentiality, integrity, or availability of ${envContext[env] || envContext.unknown}.`,
      remediationSteps: finding.remediation ? finding.remediation.split(". ").filter((s) => s.trim().length > 0).map((s) => s.trim() + (s.endsWith(".") ? "" : ".")) : ["Review the finding details and apply vendor-recommended patches.", "Implement compensating controls if immediate patching is not possible."],
      businessImpact: `This ${finding.severity}-severity finding in ${envContext[env] || envContext.unknown} could lead to ${finding.severity === "critical" || finding.severity === "high" ? "significant data breach, service disruption, or regulatory non-compliance" : "information disclosure or reduced security posture"}.`,
      complianceImplications: this.getComplianceImplications(finding, classification)
    };
  }
  getComplianceImplications(finding, classification) {
    const implications = [];
    const frameworks = classification?.applicableCompliance || [];
    if (frameworks.includes("nist_800_53") || frameworks.includes("fedramp")) {
      implications.push(`NIST 800-53: Potential violation of ${finding.cwes?.includes("CWE-306") ? "IA-2 (Identification and Authentication)" : "SC-7 (Boundary Protection)"}`);
    }
    if (frameworks.includes("pci_dss")) {
      implications.push(`PCI DSS: May violate Requirement ${finding.cwes?.includes("CWE-327") ? "4 (Encrypt transmission of cardholder data)" : "6 (Develop and maintain secure systems)"}`);
    }
    if (frameworks.includes("iec_62443")) {
      implications.push(`IEC 62443: Potential non-compliance with ${finding.severity === "critical" ? "SR 1.1 (Human user identification and authentication)" : "SR 3.1 (Communication integrity)"}`);
    }
    if (frameworks.includes("hipaa")) {
      implications.push("HIPAA: Potential violation of the Security Rule technical safeguards");
    }
    if (implications.length === 0) {
      implications.push("Review against applicable organizational security policies and regulatory requirements.");
    }
    return implications;
  }
  // ─── 5. Compliance Mapping ────────────────────────────────────────────
  /**
   * Map a finding to applicable compliance framework controls.
   */
  async mapToCompliance(finding, frameworks) {
    try {
      const llm = await getLLM();
      return await this.llmMapCompliance(llm, finding, frameworks);
    } catch {
      return this.heuristicMapCompliance(finding, frameworks);
    }
  }
  async llmMapCompliance(llm, finding, frameworks) {
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are a compliance expert mapping security findings to regulatory framework controls. Provide accurate control mappings with confidence levels.`
        },
        {
          role: "user",
          content: [
            `Map this finding to the specified compliance frameworks:`,
            ``,
            `Finding: ${finding.title}`,
            `Severity: ${finding.severity}`,
            `CWEs: ${finding.cwes?.join(", ") || "None"}`,
            `CVEs: ${finding.cves?.join(", ") || "None"}`,
            `Protocol: ${finding.protocol || "N/A"}`,
            ``,
            `Frameworks: ${frameworks.join(", ")}`
          ].join("\n")
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "compliance_mappings",
          strict: true,
          schema: {
            type: "object",
            properties: {
              mappings: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    framework: { type: "string" },
                    controlId: { type: "string" },
                    controlTitle: { type: "string" },
                    status: { type: "string", enum: ["compliant", "non_compliant", "partially_compliant", "not_applicable"] },
                    confidence: { type: "integer" }
                  },
                  required: ["framework", "controlId", "controlTitle", "status", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["mappings"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    return parsed.mappings;
  }
  heuristicMapCompliance(finding, frameworks) {
    const mappings = [];
    const cweToNist = {
      "CWE-306": { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)" },
      "CWE-284": { controlId: "AC-3", controlTitle: "Access Enforcement" },
      "CWE-327": { controlId: "SC-13", controlTitle: "Cryptographic Protection" },
      "CWE-200": { controlId: "SC-28", controlTitle: "Protection of Information at Rest" },
      "CWE-79": { controlId: "SI-10", controlTitle: "Information Input Validation" },
      "CWE-89": { controlId: "SI-10", controlTitle: "Information Input Validation" },
      "CWE-918": { controlId: "SC-7", controlTitle: "Boundary Protection" },
      "CWE-732": { controlId: "AC-6", controlTitle: "Least Privilege" },
      "CWE-319": { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" },
      "CWE-295": { controlId: "SC-12", controlTitle: "Cryptographic Key Establishment and Management" },
      "CWE-521": { controlId: "IA-5", controlTitle: "Authenticator Management" },
      "CWE-798": { controlId: "IA-5", controlTitle: "Authenticator Management" },
      "CWE-311": { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" },
      "CWE-250": { controlId: "AC-6", controlTitle: "Least Privilege" }
    };
    for (const framework of frameworks) {
      if (framework === "nist_800_53" || framework === "fedramp") {
        for (const cwe of finding.cwes || []) {
          const mapping = cweToNist[cwe];
          if (mapping) {
            mappings.push({
              framework,
              controlId: mapping.controlId,
              controlTitle: mapping.controlTitle,
              status: "non_compliant",
              confidence: 80
            });
          }
        }
      }
      if (framework === "pci_dss") {
        if (finding.cwes?.some((c) => ["CWE-327", "CWE-319", "CWE-311"].includes(c))) {
          mappings.push({
            framework: "pci_dss",
            controlId: "4.1",
            controlTitle: "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission",
            status: "non_compliant",
            confidence: 75
          });
        }
        if (finding.cwes?.some((c) => ["CWE-306", "CWE-521", "CWE-798"].includes(c))) {
          mappings.push({
            framework: "pci_dss",
            controlId: "8.2",
            controlTitle: "Employ at least one method to authenticate all users",
            status: "non_compliant",
            confidence: 75
          });
        }
      }
      if (framework === "iec_62443") {
        if (finding.cwes?.some((c) => ["CWE-306", "CWE-284"].includes(c))) {
          mappings.push({
            framework: "iec_62443",
            controlId: "SR 1.1",
            controlTitle: "Human user identification and authentication",
            status: "non_compliant",
            confidence: 70
          });
        }
      }
    }
    return mappings;
  }
  // ─── 6. Risk Contextualization ────────────────────────────────────────
  /**
   * Adjust risk scores based on environmental context.
   */
  contextualizeRisk(finding, classification) {
    let modifier = 1;
    switch (classification.environment) {
      case "ics_ot":
        modifier *= 1.3;
        if (finding.protocol && ["modbus", "dnp3", "bacnet", "ethernetip", "opcua"].includes(finding.protocol)) {
          modifier *= 1.2;
        }
        break;
      case "cloud":
        if (finding.techniqueIds?.some((t) => t.startsWith("T1552"))) {
          modifier *= 1.2;
        }
        break;
      case "iot":
        if (classification.inferredIndustry === "healthcare" || classification.inferredIndustry === "manufacturing") {
          modifier *= 1.15;
        }
        break;
      case "container":
        if (finding.techniqueIds?.some((t) => t === "T1611")) {
          modifier *= 1.25;
        }
        break;
    }
    switch (classification.inferredCriticality) {
      case "critical":
        modifier *= 1.2;
        break;
      case "high":
        modifier *= 1.1;
        break;
      case "low":
        modifier *= 0.8;
        break;
    }
    const baseScore = finding.riskScore?.composite || 50;
    return Math.min(100, Math.round(baseScore * modifier));
  }
  // ─── Cache Management (public API for external invalidation triggers) ────
  /**
   * Invalidate classification cache for a specific target.
   * Call when infrastructure change is detected for a single host.
   */
  invalidateClassification(targetValue, targetType) {
    this.classificationCache.invalidateTarget(`${targetValue}:${targetType}`);
  }
  /**
   * Invalidate all classifications matching a domain/subnet pattern.
   * Call when DNS changes, CDN migration, or cloud provider changes affect multiple targets.
   */
  invalidateByDomain(domainPattern) {
    return this.classificationCache.invalidateByPattern(new RegExp(domainPattern.replace(/\./g, "\\.").replace(/\*/g, ".*")));
  }
  /**
   * Invalidate ALL cached classifications (global infrastructure change).
   * Uses version bumping to avoid thundering herd.
   */
  invalidateAllClassifications() {
    this.classificationCache.invalidateAll();
  }
  /** Get cache statistics for monitoring and dashboards */
  getCacheStats() {
    return this.classificationCache.getStats();
  }
};
var _contextEngine = null;
function getContextEngine() {
  if (!_contextEngine) {
    _contextEngine = new ContextEngine();
  }
  return _contextEngine;
}

// server/scanforge/engine/scan-orchestrator.ts
init_template_engine();
import { randomUUID as randomUUID4 } from "crypto";
var PHASE_DEFAULTS = {
  recon: { timeoutMs: 12e4, concurrency: 5 },
  enumeration: { timeoutMs: 18e4, concurrency: 3 },
  detection: { timeoutMs: 6e5, concurrency: 5 },
  verification: { timeoutMs: 12e4, concurrency: 3 },
  reporting: { timeoutMs: 3e4, concurrency: 1 }
};
var ScanOrchestrator = class {
  constructor(queue) {
    this.queue = queue;
    this.templates = getTemplateEngine();
    this.protocols = getProtocolRegistry();
    this.intelligence = getIntelligenceEngine();
    this.contextEngine = getContextEngine();
    this.queue.setProcessor(this.processJob.bind(this));
  }
  /**
   * Initialize the orchestrator — load templates, TI feeds, and context engine.
   */
  async initialize() {
    await this.templates.loadTemplates();
    await this.intelligence.initialize();
    await this.contextEngine.initialize();
    console.log(`[ScanOrchestrator] Initialized: ${this.templates.count} templates, ${this.protocols.count} protocol scanners, context engine ready`);
  }
  /**
   * Process a scan job through all phases.
   */
  async processJob(job) {
    const scanId = job.request.id;
    const config = job.request.config || {};
    console.log(`[ScanOrchestrator] Processing scan ${scanId}: type=${job.request.type}, targets=${job.request.targets.length}`);
    try {
      if (!job.request.skipContextEngine && job.request.intelligence?.useLLMContext !== false) {
        await this.runPhase(job, "recon", async () => {
          await this.phaseContextClassification(job);
        });
      }
      await this.runPhase(job, "recon", async () => {
        await this.phaseRecon(job);
      });
      if (!job.request.skipContextEngine && job.request.intelligence?.useLLMContext !== false) {
        for (const target of job.request.targets) {
          try {
            const refined = await this.contextEngine.classifyTarget(target, {
              ports: target.ports,
              services: target.services
            });
            target.classification = refined;
            console.log(`[ScanOrchestrator] Refined classification for ${target.value}: ${refined.environment} (${refined.confidence}% confidence)`);
          } catch (err) {
            console.debug(`[ScanOrchestrator] Context refinement failed for ${target.value}: ${err.message}`);
          }
        }
      }
      if (job.request.type !== "quick" && job.request.type !== "recon") {
        await this.runPhase(job, "enumeration", async () => {
          await this.phaseEnumeration(job);
        });
      }
      if (job.request.type !== "recon") {
        await this.runPhase(job, "detection", async () => {
          await this.phaseDetection(job);
        });
      }
      if (job.request.type !== "quick" && job.request.type !== "recon") {
        await this.runPhase(job, "verification", async () => {
          await this.phaseVerification(job);
        });
      }
      if (!job.request.skipContextEngine && job.request.intelligence?.useLLMContext !== false && job.findings.length > 0) {
        await this.runPhase(job, "reporting", async () => {
          await this.phaseContextCorrelation(job);
        });
      }
      await this.runPhase(job, "reporting", async () => {
        await this.phaseReporting(job);
      });
    } catch (err) {
      console.error(`[ScanOrchestrator] Scan ${scanId} error: ${err.message}`);
      throw err;
    }
  }
  // ─── Phase Implementations ─────────────────────────────────────────────
  /**
   * Phase 1: Reconnaissance
   * - Port scanning via Naabu/Masscan
   * - Service detection
   * - Technology fingerprinting
   */
  async phaseRecon(job) {
    const scanId = job.request.id;
    for (const target of job.request.targets) {
      const startTime = Date.now();
      try {
        const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
        const discoveryResult = await executeTool({
          tool: "naabu",
          args: `-sV -sC --top-ports 1000 -T4 --open ${target.value}`,
          target: target.value,
          timeoutSeconds: 90,
          engagementId: job.request.engagementId
        });
        const discovered = this.parseScanForgeOutput(discoveryResult.stdout);
        target.ports = discovered.ports;
        target.services = discovered.services;
        this.queue.addScannerResult(scanId, {
          scanner: "discovery-recon",
          status: discoveryResult.exitCode === 0 ? "completed" : "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: discoveryResult.exitCode !== 0 ? discoveryResult.stderr : void 0
        });
        if (target.type === "domain" || target.type === "url") {
          const httpxResult = await executeTool({
            tool: "httpx",
            args: `-u ${target.value} -tech-detect -status-code -title -json`,
            target: target.value,
            timeoutSeconds: 30,
            engagementId: job.request.engagementId
          });
          if (httpxResult.exitCode === 0 && httpxResult.stdout) {
            try {
              const lines = httpxResult.stdout.trim().split("\n");
              for (const line of lines) {
                const data = JSON.parse(line);
                if (data.tech) {
                  target.services = target.services || {};
                  target.services[443] = `https (${data.tech.join(", ")})`;
                }
              }
            } catch {
            }
          }
        }
        console.log(`[ScanOrchestrator] Recon for ${target.value}: ${target.ports?.length || 0} ports, ${Object.keys(target.services || {}).length} services`);
      } catch (err) {
        console.warn(`[ScanOrchestrator] Recon failed for ${target.value}: ${err.message}`);
        this.queue.addScannerResult(scanId, {
          scanner: "discovery-recon",
          status: "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: err.message
        });
      }
    }
  }
  /**
   * Phase 2: Enumeration
   * - Directory brute-force
   * - Subdomain enumeration
   * - DNS records
   */
  async phaseEnumeration(job) {
    const scanId = job.request.id;
    for (const target of job.request.targets) {
      if (target.type !== "domain" && target.type !== "url") continue;
      const startTime = Date.now();
      try {
        const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
        const gobusterResult = await executeTool({
          tool: "gobuster",
          args: `dir -u https://${target.value} -w /usr/share/wordlists/dirb/common.txt -t 20 -q --no-error`,
          target: target.value,
          timeoutSeconds: 120,
          engagementId: job.request.engagementId
        });
        const dirFindings = this.parseGobusterOutput(gobusterResult.stdout, target);
        for (const f of dirFindings) {
          this.queue.addFinding(scanId, f);
        }
        this.queue.addScannerResult(scanId, {
          scanner: "gobuster-enum",
          status: gobusterResult.exitCode === 0 ? "completed" : "failed",
          durationMs: Date.now() - startTime,
          findingCount: dirFindings.length
        });
      } catch (err) {
        this.queue.addScannerResult(scanId, {
          scanner: "gobuster-enum",
          status: "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: err.message
        });
      }
    }
  }
  /**
   * Phase 3: Detection
   * - Execute relevant templates based on discovered services
   * - Run protocol-specific scanners
   * - Apply TI-informed template selection
   */
  async phaseDetection(job) {
    const scanId = job.request.id;
    const config = job.request.config || {};
    for (const target of job.request.targets) {
      let selectedTemplates = this.selectTemplates(job, target);
      if (job.request.intelligence) {
        selectedTemplates = await this.intelligence.prioritizeTemplates(
          selectedTemplates,
          target,
          job.request.intelligence
        );
      }
      console.log(`[ScanOrchestrator] Detection for ${target.value}: ${selectedTemplates.length} templates selected`);
      const concurrency = config.maxConcurrency || PHASE_DEFAULTS.detection.concurrency;
      const batches = this.chunk(selectedTemplates, concurrency);
      let completed = 0;
      for (const batch of batches) {
        const results = await Promise.allSettled(
          batch.map(async (template) => {
            const startTime = Date.now();
            try {
              const findings = await this.templates.execute(template, target, config);
              for (const f of findings) {
                this.queue.addFinding(scanId, f);
              }
              return { scanner: template.id, findings: findings.length, durationMs: Date.now() - startTime };
            } catch (err) {
              return { scanner: template.id, findings: 0, durationMs: Date.now() - startTime, error: err.message };
            }
          })
        );
        for (const r of results) {
          if (r.status === "fulfilled") {
            completed++;
            this.queue.addScannerResult(scanId, {
              scanner: r.value.scanner,
              status: r.value.error ? "failed" : "completed",
              durationMs: r.value.durationMs,
              findingCount: r.value.findings,
              error: r.value.error
            });
          }
        }
        const progress = Math.round(completed / selectedTemplates.length * 60) + 20;
        this.queue.updateProgress(scanId, progress, `templates (${completed}/${selectedTemplates.length})`);
      }
      await this.runProtocolScanners(job, target);
    }
  }
  /**
   * Phase 4: Verification
   * - Re-test high/critical findings to reduce false positives
   * - Cross-reference with TI data
   */
  async phaseVerification(job) {
    const scanId = job.request.id;
    const highFindings = job.findings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    console.log(`[ScanOrchestrator] Verifying ${highFindings.length} high/critical findings`);
    for (const finding of highFindings) {
      const enriched = await this.intelligence.enrichFinding(finding);
      if (enriched.riskScore) {
        finding.riskScore = enriched.riskScore;
      }
    }
    for (const finding of job.findings) {
      if (!finding.riskScore) {
        finding.riskScore = this.computeBaseRiskScore(finding);
      }
    }
  }
  /**
   * Phase 5: Reporting
   * - Sort findings by risk score
   * - Generate summary statistics
   */
  async phaseReporting(job) {
    job.findings.sort((a, b) => {
      const scoreA = a.riskScore?.composite || this.severityToScore(a.severity);
      const scoreB = b.riskScore?.composite || this.severityToScore(b.severity);
      return scoreB - scoreA;
    });
    const seen = /* @__PURE__ */ new Set();
    job.findings = job.findings.filter((f) => {
      const key = `${f.title}:${f.target}:${f.port || ""}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    console.log(`[ScanOrchestrator] Reporting: ${job.findings.length} unique findings after dedup`);
  }
  // ─── Context Engine Phases ─────────────────────────────────────────────
  /**
   * Phase 0: Context Classification
   * Uses LLM to classify target environments before scanning.
   * This enables adaptive scanner selection and safety-aware scanning.
   */
  async phaseContextClassification(job) {
    for (const target of job.request.targets) {
      try {
        const classification = await this.contextEngine.classifyTarget(target);
        target.classification = classification;
        console.log(`[ScanOrchestrator] Context: ${target.value} \u2192 ${classification.environment} (${classification.confidence}% confidence)`);
        if (classification.environment === "ics_ot") {
          job.request.config = job.request.config || {};
          job.request.config.icsSafeMode = true;
          job.request.config.mode = "passive";
          console.log(`[ScanOrchestrator] ICS/OT detected \u2014 enabling safe mode for ${target.value}`);
        }
        if (classification.environment === "iot") {
          job.request.config = job.request.config || {};
          job.request.config.iotGentleMode = true;
          job.request.config.rateLimit = Math.min(job.request.config.rateLimit || 5, 5);
          console.log(`[ScanOrchestrator] IoT detected \u2014 enabling gentle mode for ${target.value}`);
        }
        if (!job.contextClassification) job.contextClassification = [];
        job.contextClassification.push(classification);
      } catch (err) {
        console.debug(`[ScanOrchestrator] Context classification failed for ${target.value}: ${err.message}`);
      }
    }
  }
  /**
   * Phase 4.5: Context Correlation
   * Uses LLM to correlate findings into attack paths and generate
   * enriched narratives for high-severity findings.
   */
  async phaseContextCorrelation(job) {
    const scanId = job.request.id;
    for (const target of job.request.targets) {
      const targetFindings = job.findings.filter((f) => f.target === target.value);
      if (targetFindings.length < 2) continue;
      const classification = target.classification || {
        environment: "traditional",
        confidence: 50
      };
      try {
        const correlation = await this.contextEngine.correlateFindings(
          targetFindings,
          target,
          classification
        );
        if (!job.attackPaths) job.attackPaths = [];
        job.attackPaths.push(...correlation.attackPaths);
        for (const path of correlation.attackPaths) {
          for (let i = 0; i < path.findingChain.length; i++) {
            const finding = job.findings.find((f) => f.id === path.findingChain[i]);
            if (finding) {
              finding.attackPathChain = path.findingChain;
              if (i === 0) finding.attackPathRole = "initial_access";
              else if (i === path.findingChain.length - 1) finding.attackPathRole = "impact";
              else finding.attackPathRole = "lateral_movement";
            }
          }
        }
        console.log(`[ScanOrchestrator] Correlation: ${correlation.attackPaths.length} attack paths for ${target.value}`);
      } catch (err) {
        console.debug(`[ScanOrchestrator] Correlation failed for ${target.value}: ${err.message}`);
      }
      const highFindings = targetFindings.filter(
        (f) => f.severity === "critical" || f.severity === "high"
      );
      for (const finding of highFindings.slice(0, 10)) {
        try {
          const narrative = await this.contextEngine.enrichFinding(finding, classification);
          finding.enrichedNarrative = narrative.technicalNarrative;
          if (job.request.complianceFrameworks?.length) {
            finding.compliance = await this.contextEngine.mapToCompliance(
              finding,
              job.request.complianceFrameworks
            );
          }
          const contextualScore = this.contextEngine.contextualizeRisk(finding, classification);
          finding.riskScore = {
            composite: contextualScore,
            cvss: finding.riskScore?.cvss || (finding.severity === "critical" ? 9 : 7.5)
          };
        } catch (err) {
          console.debug(`[ScanOrchestrator] Enrichment failed for finding ${finding.id}: ${err.message}`);
        }
      }
    }
  }
  // ─── Helpers ───────────────────────────────────────────────────────────
  async runPhase(job, phase, fn) {
    if (job.status === "cancelled") return;
    this.queue.setPhase(job.request.id, phase);
    const phaseConfig = PHASE_DEFAULTS[phase];
    const timeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`Phase ${phase} timed out`)), phaseConfig.timeoutMs);
    });
    try {
      await Promise.race([fn(), timeout]);
    } catch (err) {
      console.warn(`[ScanOrchestrator] Phase ${phase} error: ${err.message}`);
    }
  }
  selectTemplates(job, target) {
    const scanType = job.request.type;
    if (job.request.templateIds?.length) {
      return job.request.templateIds.map((id) => this.templates.get(id)).filter(Boolean);
    }
    const protocols = [];
    if (scanType === "web" || scanType === "full" || scanType === "quick") {
      protocols.push("http", "https");
    }
    if (scanType === "network" || scanType === "full") {
      if (target.services) {
        for (const [port, service] of Object.entries(target.services)) {
          const proto = this.serviceToProtocol(service);
          if (proto && !protocols.includes(proto)) {
            protocols.push(proto);
          }
        }
      }
    }
    let templates = protocols.flatMap((p) => this.templates.query({ protocol: p }));
    if (scanType === "quick") {
      templates = templates.filter((t) => t.severity === "critical" || t.severity === "high");
    }
    return templates;
  }
  async runProtocolScanners(job, target) {
    const scanId = job.request.id;
    if (!target.services || !target.ports?.length) return;
    for (const [portStr, service] of Object.entries(target.services)) {
      const port = parseInt(portStr, 10);
      const protocol = this.serviceToProtocol(service);
      if (!protocol) continue;
      const scanner = this.protocols.get(protocol);
      if (!scanner) continue;
      const startTime = Date.now();
      try {
        const findings = await scanner.scan(target, job.request.config);
        for (const f of findings) {
          f.port = port;
          this.queue.addFinding(scanId, f);
        }
        this.queue.addScannerResult(scanId, {
          scanner: `protocol:${protocol}`,
          status: "completed",
          durationMs: Date.now() - startTime,
          findingCount: findings.length
        });
      } catch (err) {
        this.queue.addScannerResult(scanId, {
          scanner: `protocol:${protocol}`,
          status: "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: err.message
        });
      }
    }
  }
  parseScanForgeOutput(stdout) {
    const ports = [];
    const services = {};
    const lines = stdout.split("\n");
    for (const line of lines) {
      const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
      if (match) {
        const port = parseInt(match[1], 10);
        const service = `${match[3]} ${match[4] || ""}`.trim();
        ports.push(port);
        services[port] = service;
      }
    }
    return { ports, services };
  }
  parseGobusterOutput(stdout, target) {
    const findings = [];
    const lines = stdout.split("\n");
    const sensitivePatterns = [
      /\/(admin|login|dashboard|config|backup|\.env|\.git|phpinfo|server-status)/i,
      /\/(wp-admin|wp-login|xmlrpc\.php|wp-config)/i,
      /\/(api|graphql|swagger|docs|debug)/i
    ];
    for (const line of lines) {
      const match = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
      if (!match) continue;
      const path = match[1];
      const status = parseInt(match[2], 10);
      if (sensitivePatterns.some((p) => p.test(path))) {
        findings.push({
          id: randomUUID4(),
          source: "gobuster-enum",
          title: `Sensitive Path Discovered: ${path}`,
          description: `The path ${path} was discovered on ${target.value} with HTTP status ${status}. This may expose sensitive functionality or information.`,
          severity: path.match(/\.(env|git|config|backup)/i) ? "high" : "medium",
          confidence: 90,
          target: target.value,
          port: 443,
          protocol: "https",
          cwes: ["CWE-538"],
          evidence: {
            matchedPattern: path,
            data: { statusCode: status }
          },
          remediation: "Restrict access to sensitive paths using authentication or IP whitelisting. Remove unnecessary files and directories from the web root.",
          foundAt: Date.now()
        });
      }
    }
    return findings;
  }
  serviceToProtocol(service) {
    const s = service.toLowerCase();
    if (s.includes("ssh")) return "ssh";
    if (s.includes("ftp")) return "ftp";
    if (s.includes("smtp") || s.includes("mail")) return "smtp";
    if (s.includes("dns") || s.includes("domain")) return "dns";
    if (s.includes("http") || s.includes("nginx") || s.includes("apache")) return "http";
    if (s.includes("mysql") || s.includes("mariadb")) return "mysql";
    if (s.includes("postgres")) return "postgresql";
    if (s.includes("redis")) return "redis";
    if (s.includes("mongo")) return "mongodb";
    if (s.includes("smb") || s.includes("microsoft-ds") || s.includes("netbios")) return "smb";
    if (s.includes("ldap")) return "ldap";
    if (s.includes("snmp")) return "snmp";
    if (s.includes("rdp") || s.includes("ms-wbt")) return "rdp";
    if (s.includes("vnc")) return "vnc";
    if (s.includes("telnet")) return "telnet";
    if (s.includes("rabbitmq") || s.includes("amqp")) return "amqp";
    if (s.includes("kafka")) return "kafka";
    if (s.includes("docker")) return "docker";
    if (s.includes("kubernetes") || s.includes("k8s")) return "kubernetes";
    if (s.includes("etcd")) return "etcd";
    if (s.includes("registry") && s.includes("container")) return "container-registry";
    if (s.includes("mqtt")) return "mqtt";
    if (s.includes("coap")) return "coap";
    if (s.includes("upnp") || s.includes("ssdp")) return "upnp";
    if (s.includes("modbus")) return "modbus";
    if (s.includes("dnp3") || s.includes("dnp")) return "dnp3";
    if (s.includes("bacnet")) return "bacnet";
    if (s.includes("ethernet/ip") || s.includes("enip") || s.includes("cip")) return "ethernetip";
    if (s.includes("opcua") || s.includes("opc-ua") || s.includes("opc ua")) return "opcua";
    return null;
  }
  computeBaseRiskScore(finding) {
    const severityScore = this.severityToScore(finding.severity);
    return {
      composite: Math.round(severityScore * (finding.confidence / 100)),
      cvss: finding.severity === "critical" ? 9 : finding.severity === "high" ? 7.5 : finding.severity === "medium" ? 5 : 3
    };
  }
  severityToScore(severity) {
    switch (severity) {
      case "critical":
        return 95;
      case "high":
        return 75;
      case "medium":
        return 50;
      case "low":
        return 25;
      case "info":
        return 10;
    }
  }
  chunk(arr, size) {
    const chunks = [];
    for (let i = 0; i < arr.length; i += size) {
      chunks.push(arr.slice(i, i + size));
    }
    return chunks;
  }
};

// server/scanforge/intelligence/fp-fn-prevention.ts
var DEFAULT_CONFIG2 = {
  minReportingConfidence: 60,
  confirmedThreshold: 80,
  enableProofValidation: true,
  enableCorroboration: true,
  enableContextualFiltering: true,
  enableAdaptiveThresholds: true,
  suppressionProfile: "balanced",
  cacheMaxAgeMs: 36e5
};
var KNOWN_FP_PATTERNS = [
  {
    id: "fp-generic-info-disclosure",
    titlePattern: /information\s*disclosure|server\s*version|technology\s*detection/i,
    conditions: [{ type: "header_present", value: "x-powered-by" }],
    reason: "Generic information disclosure from standard headers \u2014 not exploitable",
    confirmedCount: 0
  },
  {
    id: "fp-ssl-self-signed-internal",
    titlePattern: /self[- ]signed\s*certificate|untrusted\s*certificate/i,
    conditions: [{ type: "cloud_managed", value: "internal" }],
    reason: "Self-signed certificates on internal/management interfaces are expected",
    environments: ["cloud", "container"],
    confirmedCount: 0
  },
  {
    id: "fp-default-page-vuln",
    titlePattern: /default\s*(web\s*)?page|welcome\s*page|test\s*page/i,
    conditions: [{ type: "default_page", value: "true" }],
    reason: "Default page detection is informational, not a vulnerability",
    confirmedCount: 0
  },
  {
    id: "fp-cdn-cached-headers",
    titlePattern: /missing.*header|security\s*header/i,
    conditions: [{ type: "cdn_cached", value: "true" }],
    reason: "CDN-cached responses may strip security headers \u2014 test origin directly",
    confirmedCount: 0
  },
  {
    id: "fp-waf-false-sqli",
    titlePattern: /sql\s*injection|sqli/i,
    conditions: [{ type: "waf_present", value: "true" }, { type: "generic_error", value: "true" }],
    reason: "WAF may generate SQL-error-like responses that trigger SQLi false positives",
    confirmedCount: 0
  },
  {
    id: "fp-managed-service-vuln",
    titlePattern: /outdated|end[- ]of[- ]life|eol|unsupported\s*version/i,
    conditions: [{ type: "cloud_managed", value: "true" }],
    reason: "Managed cloud services handle patching \u2014 version detection may not reflect actual patch level",
    environments: ["cloud"],
    confirmedCount: 0
  },
  {
    id: "fp-ics-safe-mode-probe",
    titlePattern: /modbus|dnp3|bacnet|ethernetip|opcua/i,
    conditions: [{ type: "port_mismatch", value: "true" }],
    reason: "ICS protocol detected on non-standard port \u2014 likely a false identification",
    environments: ["ics_ot"],
    confirmedCount: 0
  },
  {
    id: "fp-container-host-leak",
    titlePattern: /container\s*escape|host\s*mount|privileged\s*container/i,
    conditions: [{ type: "technology_absent", value: "docker" }],
    reason: "Container escape finding on non-containerized target",
    environments: ["traditional"],
    confirmedCount: 0
  },
  {
    id: "fp-version-backport",
    titlePattern: /CVE-\d{4}-\d+/i,
    conditions: [{ type: "patch_level", value: "backported" }],
    reason: "Linux distribution backports security patches without changing major version \u2014 CVE may not apply",
    confirmedCount: 0
  },
  {
    id: "fp-cors-wildcard-internal",
    titlePattern: /cors.*wildcard|access-control-allow-origin.*\*/i,
    conditions: [{ type: "cloud_managed", value: "internal" }],
    reason: "CORS wildcard on internal APIs is often intentional for microservice communication",
    environments: ["cloud", "container"],
    confirmedCount: 0
  }
];
var SIGNAL_WEIGHTS = {
  exploit_proof: { base: 40, max: 50 },
  scanner_corroboration: { base: 25, max: 35 },
  multi_matcher: { base: 20, max: 30 },
  kev_listed: { base: 20, max: 25 },
  cve_correlation: { base: 15, max: 20 },
  version_match: { base: 15, max: 20 },
  epss_high: { base: 10, max: 15 },
  config_evidence: { base: 15, max: 20 },
  network_evidence: { base: 10, max: 15 },
  banner_match: { base: 10, max: 15 },
  response_analysis: { base: 10, max: 15 },
  technology_match: { base: 8, max: 12 },
  contextual_boost: { base: 5, max: 15 },
  historical_pattern: { base: 10, max: 20 },
  contextual_penalty: { base: -10, max: -25 },
  negative_signal: { base: -15, max: -30 },
  waf_interference: { base: -10, max: -20 },
  version_mismatch: { base: -20, max: -35 },
  compensating_control: { base: -15, max: -25 },
  patch_detected: { base: -25, max: -40 }
};
var PROFILE_THRESHOLDS = {
  conservative: { minConfidence: 75, confirmedThreshold: 90, fpPatternSensitivity: 0.6 },
  balanced: { minConfidence: 60, confirmedThreshold: 80, fpPatternSensitivity: 0.8 },
  aggressive: { minConfidence: 40, confirmedThreshold: 70, fpPatternSensitivity: 1 }
};
var FPFNPreventionEngine = class {
  constructor(config) {
    this.feedbackHistory = [];
    this.validationCache = /* @__PURE__ */ new Map();
    this.adaptiveWeights = /* @__PURE__ */ new Map();
    this.stats = {
      totalValidated: 0,
      confirmed: 0,
      likely: 0,
      possible: 0,
      unconfirmed: 0,
      suppressed: 0,
      falsePositive: 0,
      operatorOverrides: 0
    };
    this.config = { ...DEFAULT_CONFIG2, ...config };
    this.fpPatterns = [...KNOWN_FP_PATTERNS];
  }
  // ─── Main Validation Pipeline ────────────────────────────────────────
  /**
   * Validate a single finding through the full FP/FN prevention pipeline.
   * Returns a ValidationResult with confidence score, verdict, and all signals.
   */
  async validateFinding(finding, context) {
    const cacheKey = `${finding.id}-${finding.target}-${finding.title}`;
    const cached = this.validationCache.get(cacheKey);
    if (cached && Date.now() - cached.cachedAt < this.config.cacheMaxAgeMs) {
      return cached.result;
    }
    const signals = [];
    const now = Date.now();
    this.collectBaseSignals(finding, signals, now);
    this.collectVersionSignals(finding, context, signals, now);
    let corroboration;
    if (this.config.enableCorroboration && context.otherScannerFindings) {
      corroboration = this.evaluateCorroboration(finding, context.otherScannerFindings, signals, now);
    }
    if (this.config.enableContextualFiltering) {
      this.collectContextualSignals(finding, context, signals, now);
    }
    this.collectThreatIntelSignals(finding, signals, now);
    if (this.config.enableAdaptiveThresholds) {
      this.collectAdaptiveSignals(finding, signals, now);
    }
    const suppressionRule = this.checkFPPatterns(finding, context, signals, now);
    const finalConfidence = this.calculateFinalConfidence(finding, signals);
    const verdict = this.determineVerdict(finalConfidence, signals, suppressionRule);
    const result = {
      finding,
      finalConfidence,
      verdict,
      signals,
      positiveSignals: signals.filter((s) => s.weight > 0).length,
      negativeSignals: signals.filter((s) => s.weight < 0).length,
      corroboration,
      suppressionRule: suppressionRule || void 0,
      validatedAt: now
    };
    this.stats.totalValidated++;
    this.stats[verdict === "false_positive" ? "falsePositive" : verdict]++;
    this.validationCache.set(cacheKey, { result, cachedAt: now });
    return result;
  }
  /**
   * Validate a batch of findings. Returns validated findings sorted by confidence.
   * Findings below the minimum reporting confidence are filtered out.
   */
  async validateBatch(findings, context) {
    const results = [];
    const crossRef = this.buildCrossReferenceMap(findings);
    const enrichedContext = {
      ...context,
      otherScannerFindings: findings
    };
    for (const finding of findings) {
      const result = await this.validateFinding(finding, enrichedContext);
      results.push(result);
    }
    const profile = PROFILE_THRESHOLDS[this.config.suppressionProfile] || PROFILE_THRESHOLDS.balanced;
    const validated = results.filter(
      (r) => r.verdict !== "suppressed" && r.verdict !== "false_positive" && r.finalConfidence >= profile.minConfidence
    );
    const suppressed = results.filter(
      (r) => r.verdict === "suppressed" || r.verdict === "false_positive" || r.finalConfidence < profile.minConfidence
    );
    validated.sort((a, b) => b.finalConfidence - a.finalConfidence);
    const stats = {
      totalInput: findings.length,
      totalValidated: validated.length,
      totalSuppressed: suppressed.length,
      byVerdict: {
        confirmed: results.filter((r) => r.verdict === "confirmed").length,
        likely: results.filter((r) => r.verdict === "likely").length,
        possible: results.filter((r) => r.verdict === "possible").length,
        unconfirmed: results.filter((r) => r.verdict === "unconfirmed").length,
        suppressed: results.filter((r) => r.verdict === "suppressed").length,
        false_positive: results.filter((r) => r.verdict === "false_positive").length
      },
      avgConfidence: validated.length > 0 ? validated.reduce((sum, r) => sum + r.finalConfidence, 0) / validated.length : 0,
      suppressionRate: findings.length > 0 ? suppressed.length / findings.length : 0,
      corroborationRate: results.filter((r) => r.corroboration && r.corroboration.tier !== "none").length / Math.max(1, results.length)
    };
    return { validated, suppressed, stats };
  }
  // ─── Signal Collection Methods ───────────────────────────────────────
  collectBaseSignals(finding, signals, now) {
    if (finding.confidence > 0) {
      signals.push({
        source: "response_analysis",
        weight: Math.min(finding.confidence * 0.3, 15),
        description: `Scanner-reported confidence: ${finding.confidence}%`,
        collectedAt: now
      });
    }
    if (finding.evidence?.request && finding.evidence?.response) {
      signals.push({
        source: "response_analysis",
        weight: 10,
        description: "Full request/response evidence captured",
        evidence: `Request: ${finding.evidence.request.substring(0, 100)}...`,
        collectedAt: now
      });
    }
    if (finding.evidence?.matchedPattern) {
      signals.push({
        source: "multi_matcher",
        weight: 8,
        description: `Pattern matched: ${finding.evidence.matchedPattern}`,
        collectedAt: now
      });
    }
    if (finding.cves && finding.cves.length > 0) {
      signals.push({
        source: "cve_correlation",
        weight: 12,
        description: `CVE(s) associated: ${finding.cves.join(", ")}`,
        collectedAt: now
      });
    }
    if (finding.cwes && finding.cwes.length > 0) {
      signals.push({
        source: "technology_match",
        weight: 5,
        description: `CWE(s) mapped: ${finding.cwes.join(", ")}`,
        collectedAt: now
      });
    }
  }
  collectVersionSignals(finding, context, signals, now) {
    const versionMatch = finding.title?.match(/(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)/);
    if (!versionMatch) return;
    const detectedVersion = versionMatch[1];
    if (context.detectedTechnologies) {
      const techVersions = context.detectedTechnologies;
      const findingTech = finding.title?.toLowerCase() || "";
      for (const [tech, version] of Object.entries(techVersions)) {
        if (findingTech.includes(tech.toLowerCase())) {
          if (version === detectedVersion || this.versionInRange(version, detectedVersion)) {
            signals.push({
              source: "version_match",
              weight: 18,
              description: `Detected ${tech} version ${version} matches vulnerable range`,
              evidence: `Technology: ${tech}, Detected: ${version}, Finding version: ${detectedVersion}`,
              collectedAt: now
            });
          } else {
            signals.push({
              source: "version_mismatch",
              weight: -25,
              description: `Detected ${tech} version ${version} does NOT match vulnerable version ${detectedVersion}`,
              evidence: `Technology: ${tech}, Detected: ${version}, Expected vulnerable: ${detectedVersion}`,
              collectedAt: now
            });
          }
        }
      }
    }
  }
  evaluateCorroboration(finding, otherFindings, signals, now) {
    const corroboratingFindings = otherFindings.filter((other) => {
      if (other.id === finding.id) return false;
      if (finding.cves?.length && other.cves?.length) {
        if (finding.cves.some((c) => other.cves.includes(c))) return true;
      }
      if (this.titleSimilarity(finding.title, other.title) > 0.7) return true;
      if (finding.cwes?.length && other.cwes?.length && finding.cwes.some((c) => other.cwes.includes(c)) && finding.target === other.target && finding.port === other.port) return true;
      return false;
    });
    const scanners = [...new Set(corroboratingFindings.map((f) => f.source))];
    const uniqueScannerCount = scanners.filter((s) => s !== finding.source).length + 1;
    let tier = "none";
    let confidenceBoost = 0;
    if (uniqueScannerCount >= 3) {
      tier = "strong";
      confidenceBoost = 30;
    } else if (uniqueScannerCount === 2) {
      tier = "moderate";
      confidenceBoost = 20;
    } else if (corroboratingFindings.length > 0) {
      tier = "weak";
      confidenceBoost = 8;
    }
    if (confidenceBoost > 0) {
      signals.push({
        source: "scanner_corroboration",
        weight: confidenceBoost,
        description: `${tier} corroboration: ${uniqueScannerCount} scanners agree (${scanners.join(", ")})`,
        collectedAt: now
      });
    }
    return {
      scannerCount: uniqueScannerCount,
      scanners: [.../* @__PURE__ */ new Set([finding.source, ...scanners])],
      tier,
      confidenceBoost
    };
  }
  collectContextualSignals(finding, context, signals, now) {
    if (context.environment) {
      if (context.environment === "traditional" && finding.title?.match(/modbus|dnp3|bacnet|scada|plc|hmi/i)) {
        signals.push({
          source: "contextual_penalty",
          weight: -20,
          description: "ICS/OT finding on traditional IT infrastructure \u2014 likely misidentification",
          collectedAt: now
        });
      }
      if (context.environment === "cloud" && context.isManaged && finding.title?.match(/outdated|end.of.life|unsupported/i)) {
        signals.push({
          source: "compensating_control",
          weight: -15,
          description: "Managed cloud service \u2014 vendor handles patching, version may not reflect actual patch level",
          collectedAt: now
        });
      }
      if (context.environment !== "container" && finding.title?.match(/container\s*escape|docker|kubernetes|k8s/i)) {
        signals.push({
          source: "contextual_penalty",
          weight: -20,
          description: "Container-specific finding on non-containerized target",
          collectedAt: now
        });
      }
    }
    if (context.wafDetected) {
      const isInjectionFinding = finding.title?.match(/injection|sqli|xss|rce|command\s*injection/i);
      if (isInjectionFinding) {
        signals.push({
          source: "waf_interference",
          weight: -10,
          description: `WAF detected (${context.wafDetected}) \u2014 injection findings may be false positives from WAF error pages`,
          collectedAt: now
        });
      }
    }
    if (context.compensatingControls) {
      for (const control of context.compensatingControls) {
        if (this.controlMitigatesFinding(control, finding)) {
          signals.push({
            source: "compensating_control",
            weight: -12,
            description: `Compensating control detected: ${control}`,
            collectedAt: now
          });
        }
      }
    }
    if (context.networkSegmented && finding.severity === "critical") {
      signals.push({
        source: "contextual_penalty",
        weight: -5,
        description: "Network segmentation reduces exploitability \u2014 risk may be lower than reported",
        collectedAt: now
      });
    }
  }
  collectThreatIntelSignals(finding, signals, now) {
    if (finding.riskScore?.kevListed) {
      signals.push({
        source: "kev_listed",
        weight: 25,
        description: "Listed in CISA Known Exploited Vulnerabilities catalog \u2014 confirmed exploitable in the wild",
        collectedAt: now
      });
    }
    if (finding.riskScore?.epss && finding.riskScore.epss > 0.5) {
      signals.push({
        source: "epss_high",
        weight: Math.min(15, Math.round(finding.riskScore.epss * 20)),
        description: `EPSS score ${(finding.riskScore.epss * 100).toFixed(1)}% \u2014 high probability of exploitation`,
        collectedAt: now
      });
    }
    if (finding.riskScore?.ransomwareUse) {
      signals.push({
        source: "cve_correlation",
        weight: 20,
        description: "Known ransomware campaign exploitation \u2014 high-priority confirmed threat",
        collectedAt: now
      });
    }
    if (finding.riskScore?.threatActorRelevance?.length) {
      signals.push({
        source: "cve_correlation",
        weight: 12,
        description: `Exploited by threat actors: ${finding.riskScore.threatActorRelevance.join(", ")}`,
        collectedAt: now
      });
    }
  }
  collectAdaptiveSignals(finding, signals, now) {
    const similarFeedback = this.feedbackHistory.filter((fb) => {
      const titleKey = this.normalizeFindingTitle(finding.title);
      const fbTitleKey = this.normalizeFindingTitle(fb.findingId);
      return titleKey === fbTitleKey;
    });
    if (similarFeedback.length === 0) return;
    const tpCount = similarFeedback.filter((f) => f.verdict === "true_positive").length;
    const fpCount = similarFeedback.filter((f) => f.verdict === "false_positive").length;
    const total = tpCount + fpCount;
    if (total >= 3) {
      const tpRate = tpCount / total;
      if (tpRate > 0.8) {
        signals.push({
          source: "historical_pattern",
          weight: 15,
          description: `Historical pattern: ${(tpRate * 100).toFixed(0)}% true positive rate (${total} samples)`,
          collectedAt: now
        });
      } else if (tpRate < 0.3) {
        signals.push({
          source: "historical_pattern",
          weight: -15,
          description: `Historical pattern: ${((1 - tpRate) * 100).toFixed(0)}% false positive rate (${total} samples)`,
          collectedAt: now
        });
      }
    }
  }
  checkFPPatterns(finding, context, signals, now) {
    const profile = PROFILE_THRESHOLDS[this.config.suppressionProfile] || PROFILE_THRESHOLDS.balanced;
    for (const pattern of this.fpPatterns) {
      if (!pattern.titlePattern.test(finding.title)) continue;
      if (pattern.environments && context.environment && !pattern.environments.includes(context.environment)) continue;
      const conditionsMet = pattern.conditions.filter((cond) => {
        switch (cond.type) {
          case "waf_present":
            return !!context.wafDetected;
          case "cloud_managed":
            return context.isManaged || context.environment === "cloud";
          case "port_mismatch":
            return finding.port && !this.isStandardPort(finding.port, finding.protocol || "");
          case "technology_absent":
            return !context.detectedTechnologies?.[cond.value];
          case "header_present":
            return finding.evidence?.response?.toLowerCase().includes(cond.value.toLowerCase());
          case "default_page":
            return finding.evidence?.response?.match(/welcome|default|it works|test page/i);
          case "generic_error":
            return finding.evidence?.response?.match(/error|exception|500|403/i);
          case "cdn_cached":
            return finding.evidence?.response?.match(/x-cache|cf-cache|x-cdn/i);
          case "patch_level":
            return context.patchLevel === cond.value;
          default:
            return false;
        }
      });
      const conditionRatio = conditionsMet.length / pattern.conditions.length;
      if (conditionRatio >= profile.fpPatternSensitivity) {
        signals.push({
          source: "negative_signal",
          weight: -20,
          description: `FP pattern match: ${pattern.reason} (${conditionsMet.length}/${pattern.conditions.length} conditions met)`,
          collectedAt: now
        });
        return pattern.id;
      }
    }
    return null;
  }
  // ─── Confidence Calculation ──────────────────────────────────────────
  calculateFinalConfidence(finding, signals) {
    let confidence = Math.max(20, finding.confidence || 50);
    for (const signal of signals) {
      const weightConfig = SIGNAL_WEIGHTS[signal.source];
      if (weightConfig) {
        const clampedWeight = signal.weight > 0 ? Math.min(signal.weight, weightConfig.max) : Math.max(signal.weight, weightConfig.max);
        confidence += clampedWeight;
      } else {
        confidence += signal.weight;
      }
    }
    const adaptiveKey = this.normalizeFindingTitle(finding.title);
    const adaptiveAdjustment = this.adaptiveWeights.get(adaptiveKey);
    if (adaptiveAdjustment) {
      confidence += adaptiveAdjustment;
    }
    return Math.max(0, Math.min(100, Math.round(confidence)));
  }
  determineVerdict(confidence, signals, suppressionRule) {
    const profile = PROFILE_THRESHOLDS[this.config.suppressionProfile] || PROFILE_THRESHOLDS.balanced;
    const strongNegatives = signals.filter((s) => s.weight <= -20);
    const hasExploitProof = signals.some((s) => s.source === "exploit_proof" && s.weight > 0);
    if (hasExploitProof) {
      return confidence >= profile.confirmedThreshold ? "confirmed" : "likely";
    }
    if (strongNegatives.length >= 2 && confidence < 40) {
      return "false_positive";
    }
    if (suppressionRule && confidence < profile.minConfidence) {
      return "suppressed";
    }
    if (confidence >= profile.confirmedThreshold) return "confirmed";
    if (confidence >= profile.minConfidence + 10) return "likely";
    if (confidence >= profile.minConfidence) return "possible";
    if (confidence >= profile.minConfidence - 15) return "unconfirmed";
    return "suppressed";
  }
  // ─── Operator Feedback Integration ───────────────────────────────────
  /**
   * Record operator feedback on a finding. This feeds the adaptive threshold system.
   */
  recordFeedback(feedback) {
    this.feedbackHistory.push(feedback);
    this.stats.operatorOverrides++;
    const titleKey = this.normalizeFindingTitle(feedback.findingId);
    const currentWeight = this.adaptiveWeights.get(titleKey) || 0;
    if (feedback.verdict === "false_positive") {
      this.adaptiveWeights.set(titleKey, currentWeight - 5);
      for (const pattern of this.fpPatterns) {
        if (pattern.titlePattern.test(feedback.findingId)) {
          pattern.confirmedCount++;
        }
      }
    } else if (feedback.verdict === "true_positive") {
      this.adaptiveWeights.set(titleKey, currentWeight + 3);
    }
    for (const [key] of this.validationCache) {
      if (key.includes(feedback.findingId)) {
        this.validationCache.delete(key);
      }
    }
  }
  /**
   * Add a custom FP pattern from operator experience.
   */
  addFPPattern(pattern) {
    this.fpPatterns.push({ ...pattern, confirmedCount: 0 });
  }
  // ─── Utility Methods ─────────────────────────────────────────────────
  titleSimilarity(a, b) {
    const normalize = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, " ").replace(/\s+/g, " ").trim();
    const na = normalize(a);
    const nb = normalize(b);
    if (na === nb) return 1;
    const wordsA = new Set(na.split(" "));
    const wordsB = new Set(nb.split(" "));
    const intersection = new Set([...wordsA].filter((w) => wordsB.has(w)));
    const union = /* @__PURE__ */ new Set([...wordsA, ...wordsB]);
    return intersection.size / union.size;
  }
  normalizeFindingTitle(title) {
    return title.toLowerCase().replace(/\[.*?\]/g, "").replace(/CVE-\d{4}-\d+/gi, "CVE").replace(/\d+\.\d+\.\d+/g, "VERSION").replace(/\s+/g, " ").trim();
  }
  versionInRange(detected, vulnerable) {
    const parse = (v2) => v2.split(/[.-]/).map((p) => parseInt(p, 10) || 0);
    const d = parse(detected);
    const v = parse(vulnerable);
    for (let i = 0; i < Math.max(d.length, v.length); i++) {
      const dPart = d[i] || 0;
      const vPart = v[i] || 0;
      if (dPart < vPart) return true;
      if (dPart > vPart) return false;
    }
    return true;
  }
  isStandardPort(port, protocol) {
    const standardPorts = {
      http: [80, 8080, 8443, 443],
      https: [443, 8443],
      ssh: [22],
      ftp: [21],
      smtp: [25, 587, 465],
      dns: [53],
      modbus: [502],
      dnp3: [2e4],
      bacnet: [47808],
      mqtt: [1883, 8883],
      coap: [5683, 5684],
      opcua: [4840]
    };
    return standardPorts[protocol.toLowerCase()]?.includes(port) ?? false;
  }
  controlMitigatesFinding(control, finding) {
    const controlLower = control.toLowerCase();
    const titleLower = (finding.title || "").toLowerCase();
    if (controlLower.includes("waf") && titleLower.match(/injection|xss|sqli/)) return true;
    if (controlLower.includes("mfa") && titleLower.match(/credential|password|auth/)) return true;
    if (controlLower.includes("encrypt") && titleLower.match(/cleartext|plain.?text|unencrypted/)) return true;
    if (controlLower.includes("segment") && titleLower.match(/lateral|pivot|internal/)) return true;
    return false;
  }
  buildCrossReferenceMap(findings) {
    const map = /* @__PURE__ */ new Map();
    for (const f of findings) {
      const key = `${f.target}:${f.port || "any"}`;
      const existing = map.get(key) || [];
      existing.push(f);
      map.set(key, existing);
    }
    return map;
  }
  // ─── Statistics & Reporting ──────────────────────────────────────────
  getStats() {
    return {
      ...this.stats,
      feedbackCount: this.feedbackHistory.length,
      fpPatternCount: this.fpPatterns.length,
      cacheSize: this.validationCache.size
    };
  }
  getConfig() {
    return { ...this.config };
  }
  updateConfig(updates) {
    this.config = { ...this.config, ...updates };
    this.validationCache.clear();
  }
  clearCache() {
    this.validationCache.clear();
  }
};
var engineInstance = null;
function getFPFNEngine(config) {
  if (!engineInstance) {
    engineInstance = new FPFNPreventionEngine(config);
  }
  return engineInstance;
}

export {
  ScanQueue,
  getScanQueue,
  ProtocolRegistry,
  getProtocolRegistry,
  IntelligenceEngine,
  getIntelligenceEngine,
  ContextEngine,
  getContextEngine,
  ScanOrchestrator,
  FPFNPreventionEngine,
  getFPFNEngine
};
