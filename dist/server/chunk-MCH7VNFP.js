import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/job-queue.ts
import crypto from "crypto";
import { EventEmitter } from "events";
function signJobPayload(payload) {
  return crypto.createHmac("sha256", JOB_ENCRYPTION_KEY).update(payload).digest("hex");
}
function verifyJobSignature(payload, signature) {
  const expected = signJobPayload(payload);
  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(signature, "hex")
  );
}
function enqueueJob(job) {
  const jobId = `job_${job.type}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  const payloadStr = JSON.stringify(job.payload);
  const fullJob = {
    ...job,
    id: jobId,
    metadata: {
      dispatchedAt: Date.now(),
      dispatchedBy: job.metadata?.dispatchedBy || "system",
      roeScope: job.metadata?.roeScope || [],
      fipsCompliant: true,
      hmacSignature: signJobPayload(payloadStr)
    }
  };
  if (fullJob.metadata.roeScope.length > 0) {
    const outOfScope = fullJob.payload.targets.filter(
      (t) => !fullJob.metadata.roeScope.includes(t)
    );
    if (outOfScope.length > 0) {
      console.error(`[JobQueue] SCOPE VIOLATION: ${outOfScope.join(", ")} not in RoE scope`);
      throw new Error(`Scope violation: ${outOfScope.length} target(s) not in RoE scope`);
    }
  }
  const queue = jobQueues[job.type];
  const priorityOrder = { critical: 0, high: 1, normal: 2, low: 3 };
  const insertIdx = queue.findIndex(
    (e) => priorityOrder[e.job.priority] > priorityOrder[fullJob.priority]
  );
  const entry = { job: fullJob, enqueuedAt: Date.now(), attempts: 0 };
  if (insertIdx === -1) {
    queue.push(entry);
  } else {
    queue.splice(insertIdx, 0, entry);
  }
  console.log(`[JobQueue] Enqueued ${job.type} job ${jobId} (priority: ${job.priority}, targets: ${job.payload.targets.length})`);
  jobEventEmitter.emit("job:enqueued", fullJob);
  return jobId;
}
function dequeueJob(type) {
  const queue = jobQueues[type];
  if (queue.length === 0) return null;
  const entry = queue.shift();
  entry.attempts++;
  activeJobs.set(entry.job.id, entry.job);
  console.log(`[JobQueue] Dequeued ${type} job ${entry.job.id} (attempt ${entry.attempts})`);
  jobEventEmitter.emit("job:dispatched", entry.job);
  return entry.job;
}
function submitJobResult(result) {
  const job = activeJobs.get(result.jobId);
  if (job) {
    const payloadStr = JSON.stringify(job.payload);
    if (!verifyJobSignature(payloadStr, job.metadata.hmacSignature)) {
      console.error(`[JobQueue] INTEGRITY VIOLATION: HMAC mismatch for job ${result.jobId}`);
    }
  }
  jobResults.set(result.jobId, result);
  activeJobs.delete(result.jobId);
  console.log(`[JobQueue] Result received for job ${result.jobId}: ${result.status} (${result.results.length} tool results)`);
  jobEventEmitter.emit("job:completed", result);
}
function getJobResult(jobId) {
  return jobResults.get(jobId) || null;
}
function getJobStatus(jobId) {
  const result = jobResults.get(jobId);
  if (result) {
    return { status: result.status === "completed" ? "completed" : "failed", result };
  }
  const active = activeJobs.get(jobId);
  if (active) {
    return { status: "running", job: active };
  }
  for (const type of Object.keys(jobQueues)) {
    const entry = jobQueues[type].find((e) => e.job.id === jobId);
    if (entry) {
      return { status: "queued", job: entry.job };
    }
  }
  return { status: "cancelled" };
}
function cancelJob(jobId) {
  for (const type of Object.keys(jobQueues)) {
    const idx = jobQueues[type].findIndex((e) => e.job.id === jobId);
    if (idx !== -1) {
      jobQueues[type].splice(idx, 1);
      console.log(`[JobQueue] Cancelled queued job ${jobId}`);
      jobEventEmitter.emit("job:cancelled", { jobId });
      return true;
    }
  }
  if (activeJobs.has(jobId)) {
    activeJobs.delete(jobId);
    jobResults.set(jobId, {
      jobId,
      status: "failed",
      results: [],
      metadata: { completedAt: Date.now(), workerHost: "cancelled", workerRegion: "n/a", fipsVerified: false }
    });
    console.log(`[JobQueue] Cancelled active job ${jobId}`);
    jobEventEmitter.emit("job:cancelled", { jobId });
    return true;
  }
  return false;
}
function registerWorker(worker) {
  workerRegistry.set(worker.id, worker);
  console.log(`[JobQueue] Worker registered: ${worker.id} (${worker.host}, types: ${worker.type.join(",")})`);
}
function workerHeartbeat(workerId, activeJobs2) {
  const worker = workerRegistry.get(workerId);
  if (worker) {
    worker.lastHeartbeat = Date.now();
    worker.activeJobs = activeJobs2;
    worker.healthy = true;
  }
}
function getWorkers() {
  const now = Date.now();
  return Array.from(workerRegistry.values()).map((w) => ({
    ...w,
    healthy: now - w.lastHeartbeat < WORKER_TIMEOUT
  }));
}
function hasHealthyWorker(type) {
  const now = Date.now();
  return Array.from(workerRegistry.values()).some(
    (w) => w.type.includes(type) && now - w.lastHeartbeat < WORKER_TIMEOUT && w.activeJobs < w.maxJobs
  );
}
function getQueueStats() {
  const now = Date.now();
  const workers = Array.from(workerRegistry.values());
  return {
    queued: {
      scan: jobQueues.scan.length,
      recon: jobQueues.recon.length,
      feed: jobQueues.feed.length,
      c2: jobQueues.c2.length
    },
    active: activeJobs.size,
    completed: jobResults.size,
    workers: {
      total: workers.length,
      healthy: workers.filter((w) => now - w.lastHeartbeat < WORKER_TIMEOUT).length
    }
  };
}
async function dispatchScanJob(config) {
  if (hasHealthyWorker("scan")) {
    const jobId2 = enqueueJob({
      type: "scan",
      engagementId: config.engagementId,
      priority: "high",
      payload: {
        targets: config.targets,
        tools: [config.tool],
        options: {
          args: config.args,
          timeoutSeconds: config.timeoutSeconds || 300,
          sudo: config.sudo || false,
          scanType: config.tool
        }
      },
      metadata: {
        dispatchedBy: config.operatorId || "system",
        roeScope: config.roeScope
      },
      ttlSeconds: config.timeoutSeconds || 600
    });
    return { jobId: jobId2, mode: "queue" };
  }
  console.log(`[JobQueue] No healthy scan workers \u2014 falling back to local SSH execution`);
  const { executeTool } = await import("./scan-server-executor-7HE5BT5W.js");
  const result = await executeTool({
    tool: config.tool,
    args: config.args,
    target: config.targets[0],
    timeoutSeconds: config.timeoutSeconds || 300,
    engagementId: config.engagementId,
    sudo: config.sudo
  });
  const jobId = `local_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  submitJobResult({
    jobId,
    status: result.exitCode === 0 ? "completed" : "failed",
    results: [{
      tool: config.tool,
      target: config.targets[0],
      findings: [],
      duration_ms: result.durationMs,
      severity_summary: {}
    }],
    metadata: {
      completedAt: Date.now(),
      workerHost: "local-ssh",
      workerRegion: "manus",
      fipsVerified: true
    }
  });
  return { jobId, mode: "local" };
}
async function dispatchReconJob(config) {
  if (hasHealthyWorker("recon")) {
    const jobId2 = enqueueJob({
      type: "recon",
      engagementId: config.engagementId,
      priority: "normal",
      payload: {
        targets: config.targets,
        tools: config.connectors,
        options: {
          depth: config.depth,
          includePassive: true,
          connectors: config.connectors
        }
      },
      metadata: {
        dispatchedBy: config.operatorId || "system",
        roeScope: config.roeScope
      },
      ttlSeconds: 600
    });
    return { jobId: jobId2, mode: "queue" };
  }
  console.log(`[JobQueue] No healthy recon workers \u2014 running passive recon locally`);
  const jobId = `local_recon_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  return { jobId, mode: "local" };
}
function dispatchFeedJob(config) {
  if (hasHealthyWorker("feed")) {
    const jobId2 = enqueueJob({
      type: "feed",
      engagementId: 0,
      priority: "low",
      payload: {
        targets: [],
        tools: [config.feedType],
        options: {
          feedType: config.feedType,
          schedule: config.schedule,
          lastSyncTimestamp: config.lastSyncTimestamp
        }
      },
      ttlSeconds: 300
    });
    return { jobId: jobId2, mode: "queue" };
  }
  const jobId = `local_feed_${Date.now()}`;
  return { jobId, mode: "local" };
}
function onJobEvent(event, handler) {
  jobEventEmitter.on(event, handler);
}
function offJobEvent(event, handler) {
  jobEventEmitter.off(event, handler);
}
function cleanupJobResults() {
  if (jobResults.size <= 1e3) return 0;
  const entries = Array.from(jobResults.entries()).sort((a, b) => (a[1].metadata.completedAt || 0) - (b[1].metadata.completedAt || 0));
  const toRemove = entries.slice(0, entries.length - 1e3);
  for (const [key] of toRemove) {
    jobResults.delete(key);
  }
  return toRemove.length;
}
function isVPCConnection(remoteAddress) {
  if (!remoteAddress) return false;
  const parts = remoteAddress.split(".");
  if (parts.length !== 4) return false;
  return parts[0] === "10" && parts[1] === "132" && parseInt(parts[2]) < 16;
}
function getDOFirewallConfig(name, dropletIds) {
  return {
    name: `caldera-${name}-fw`,
    droplet_ids: dropletIds,
    inbound_rules: NETWORK_ISOLATION_CONFIG.firewallRules[name]?.inbound.map((rule) => ({
      protocol: rule.protocol,
      ports: rule.ports,
      sources: rule.sources
    })) || [],
    outbound_rules: NETWORK_ISOLATION_CONFIG.firewallRules[name]?.outbound?.map((rule) => ({
      protocol: rule.protocol,
      ports: rule.ports,
      destinations: rule.sources
    })) || []
  };
}
var JOB_ENCRYPTION_KEY, workerRegistry, WORKER_TIMEOUT, jobQueues, jobResults, activeJobs, jobEventEmitter, NETWORK_ISOLATION_CONFIG;
var init_job_queue = __esm({
  "server/lib/job-queue.ts"() {
    init_env();
    JOB_ENCRYPTION_KEY = crypto.createHash("sha256").update(ENV.JWT_SECRET || "caldera-job-queue-key").digest();
    workerRegistry = /* @__PURE__ */ new Map();
    WORKER_TIMEOUT = 9e4;
    jobQueues = {
      scan: [],
      recon: [],
      feed: [],
      c2: []
    };
    jobResults = /* @__PURE__ */ new Map();
    activeJobs = /* @__PURE__ */ new Map();
    jobEventEmitter = new EventEmitter();
    NETWORK_ISOLATION_CONFIG = {
      vpc: {
        name: "caldera-vpc",
        ipRange: "10.132.0.0/20",
        region: "nyc1",
        description: "Private VPC for Caldera scan infrastructure \u2014 no public endpoints"
      },
      firewallRules: {
        // Redis: VPC-only access
        redis: {
          inbound: [
            {
              protocol: "tcp",
              ports: "6379",
              sources: { tags: ["caldera-worker", "caldera-api"] },
              description: "Redis access from Cyber C2 workers and API only (VPC)"
            }
          ],
          outbound: []
        },
        // Scan worker: VPC-only + SSH from operator IPs
        scanWorker: {
          inbound: [
            {
              protocol: "tcp",
              ports: "22",
              sources: { tags: ["caldera-api"] },
              description: "SSH from Manus backend only"
            },
            {
              protocol: "tcp",
              ports: "8080",
              sources: { tags: ["caldera-api"] },
              description: "Health check from Manus backend"
            }
          ],
          outbound: [
            {
              protocol: "tcp",
              ports: "6379",
              sources: { tags: ["caldera-redis"] },
              description: "Redis connection (VPC only)"
            },
            {
              protocol: "tcp",
              ports: "443",
              sources: { addresses: ["0.0.0.0/0"] },
              description: "HTTPS for scanning targets (outbound only)"
            }
          ]
        },
        // C2 droplet: operator-only SSH, no public services
        c2Droplet: {
          inbound: [
            {
              protocol: "tcp",
              ports: "22",
              sources: { tags: ["caldera-operator"] },
              description: "SSH from operator IPs only"
            },
            {
              protocol: "tcp",
              ports: "8443",
              sources: { tags: ["caldera-api"] },
              description: "C2 API from Manus backend only"
            }
          ],
          outbound: [
            {
              protocol: "tcp",
              ports: "443",
              sources: { addresses: ["0.0.0.0/0"] },
              description: "C2 callback channels (outbound only)"
            }
          ]
        },
        // OSINT worker: VPC-only + outbound HTTPS for API calls
        osintWorker: {
          inbound: [
            {
              protocol: "tcp",
              ports: "8080",
              sources: { tags: ["caldera-api"] },
              description: "Health check from Manus backend"
            }
          ],
          outbound: [
            {
              protocol: "tcp",
              ports: "6379",
              sources: { tags: ["caldera-redis"] },
              description: "Redis connection (VPC only)"
            },
            {
              protocol: "tcp",
              ports: "443",
              sources: { addresses: ["0.0.0.0/0"] },
              description: "HTTPS for OSINT API calls (outbound only)"
            }
          ]
        }
      },
      // Tags for resource grouping
      tags: [
        "caldera-api",
        // Manus backend
        "caldera-worker",
        // Scan/recon workers
        "caldera-redis",
        // Redis instance
        "caldera-c2",
        // C2 droplet
        "caldera-operator"
        // Operator machines (SSH whitelist)
      ]
    };
  }
});

export {
  enqueueJob,
  dequeueJob,
  submitJobResult,
  getJobResult,
  getJobStatus,
  cancelJob,
  registerWorker,
  workerHeartbeat,
  getWorkers,
  hasHealthyWorker,
  getQueueStats,
  dispatchScanJob,
  dispatchReconJob,
  dispatchFeedJob,
  onJobEvent,
  offJobEvent,
  cleanupJobResults,
  NETWORK_ISOLATION_CONFIG,
  isVPCConnection,
  getDOFirewallConfig,
  init_job_queue
};
