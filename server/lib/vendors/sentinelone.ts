/**
 * SentinelOne Integration Client
 * Auth: API Token (Authorization: ApiToken <token>)
 * Endpoints: Agents, Threats, Activities, Groups, Remote Scripts
 */
import { BaseVendorClient, VendorError } from "./base-client";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorQueryOptions,
} from "./base-client";

// ─── SentinelOne-specific types ──────────────────────────────────────────────

interface S1Agent {
  id: string;
  computerName: string;
  externalIp: string;
  lastIpToMgmt: string;
  osName: string;
  osType: string;
  agentVersion: string;
  isActive: boolean;
  infected: boolean;
  networkStatus: string;
  machineType: string;
  domain: string;
  groupName: string;
  siteName: string;
  lastActiveDate: string;
  registeredAt: string;
  threatRebootRequired: boolean;
  totalMemory: number;
}

interface S1Threat {
  id: string;
  agentComputerName: string;
  agentId: string;
  agentOsType: string;
  classification: string;
  classificationSource: string;
  confidenceLevel: string;
  threatName: string;
  mitigationStatus: string;
  analystVerdict: string;
  initiatedBy: string;
  filePath: string;
  fileContentHash: string;
  engines: string[];
  indicators: Array<{ category: string; description: string; ids: string[] }>;
  createdDate: string;
  updatedAt: string;
}

interface S1Activity {
  id: string;
  activityType: number;
  primaryDescription: string;
  secondaryDescription: string;
  data: Record<string, unknown>;
  agentId: string;
  createdAt: string;
  threatId: string;
  userId: string;
}

export class SentinelOneClient extends BaseVendorClient {
  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    super("sentinelone", authConfig, connectionConfig);
  }

  getDisplayName(): string {
    return "SentinelOne";
  }

  // ─── Token Authentication ──────────────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.apiToken) {
      throw new VendorError("sentinelone", "Missing API token", "AUTH_CONFIG_MISSING");
    }
    this.setAuthHeader(this.authConfig.apiToken, "ApiToken");
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/web/api/v2.1/system/info" });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "SentinelOne management console is reachable and authenticated",
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: (error as Error).message,
      };
    }
  }

  // ─── Agents ────────────────────────────────────────────────────────────────

  async queryAgents(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const params: Record<string, unknown> = { limit };
    if (options?.filter) params.computerName__contains = options.filter;
    if (options?.sort) params.sortBy = options.sort;

    const response = await this.request<{ data: S1Agent[] }>({
      method: "GET",
      url: "/web/api/v2.1/agents",
      params,
    });

    return (response.data || []).map((a) => this.normalizeAgent(a));
  }

  async getAgent(agentId: string): Promise<NormalizedVendorData | null> {
    const response = await this.request<{ data: S1Agent[] }>({
      method: "GET",
      url: "/web/api/v2.1/agents",
      params: { ids: agentId },
    });
    const agent = response.data?.[0];
    return agent ? this.normalizeAgent(agent) : null;
  }

  private normalizeAgent(a: S1Agent): NormalizedVendorData {
    return {
      id: a.id,
      type: "host",
      title: a.computerName || a.id,
      status: a.isActive ? (a.infected ? "infected" : "healthy") : "offline",
      hostname: a.computerName,
      ipAddress: a.lastIpToMgmt || a.externalIp,
      domain: a.domain,
      raw: a,
    };
  }

  // ─── Threats ───────────────────────────────────────────────────────────────

  async queryThreats(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const params: Record<string, unknown> = { limit };
    if (options?.timeRange) {
      params.createdAt__gte = new Date(options.timeRange.start).toISOString();
      params.createdAt__lte = new Date(options.timeRange.end).toISOString();
    }

    const response = await this.request<{ data: S1Threat[] }>({
      method: "GET",
      url: "/web/api/v2.1/threats",
      params,
    });

    return (response.data || []).map((t) => this.normalizeThreat(t));
  }

  private normalizeThreat(t: S1Threat): NormalizedVendorData {
    const severity = t.confidenceLevel === "malicious" ? "critical"
      : t.confidenceLevel === "suspicious" ? "high"
      : "medium";

    return {
      id: t.id,
      type: "threat",
      title: t.threatName || `Threat on ${t.agentComputerName}`,
      severity,
      status: t.mitigationStatus,
      hostname: t.agentComputerName,
      detectedAt: new Date(t.createdDate).getTime(),
      raw: t,
    };
  }

  // ─── Activities ────────────────────────────────────────────────────────────

  async queryActivities(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const params: Record<string, unknown> = { limit };

    const response = await this.request<{ data: S1Activity[] }>({
      method: "GET",
      url: "/web/api/v2.1/activities",
      params,
    });

    return (response.data || []).map((a) => ({
      id: a.id,
      type: "alert" as const,
      title: a.primaryDescription || `Activity ${a.activityType}`,
      status: "active",
      detectedAt: new Date(a.createdAt).getTime(),
      raw: a,
    }));
  }

  // ─── Threat Actions ────────────────────────────────────────────────────────

  async mitigateThreat(threatId: string, action: "kill" | "quarantine" | "remediate" | "rollback"): Promise<void> {
    await this.request({
      method: "POST",
      url: `/web/api/v2.1/threats/mitigate/${action}`,
      data: { filter: { ids: [threatId] } },
    });
  }

  async disconnectAgent(agentId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/web/api/v2.1/agents/actions/disconnect",
      data: { filter: { ids: [agentId] } },
    });
  }

  async reconnectAgent(agentId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/web/api/v2.1/agents/actions/connect",
      data: { filter: { ids: [agentId] } },
    });
  }
}

export function createSentinelOneClient(
  authConfig: VendorAuthConfig,
  connectionConfig: VendorConnectionConfig
): SentinelOneClient {
  return new SentinelOneClient(authConfig, connectionConfig);
}
