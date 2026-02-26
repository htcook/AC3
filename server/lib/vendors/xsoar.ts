/**
 * Palo Alto Cortex XSOAR Integration Client
 * Auth: API Key (Authorization: <api_key>) or Advanced Auth (api_key_id + api_key)
 * Endpoints: Incidents, Indicators, War Room, Playbooks, Entry/Evidence
 */
import { BaseVendorClient, VendorError } from "./base-client";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorQueryOptions,
} from "./base-client";

// ─── XSOAR-specific types ────────────────────────────────────────────────────

interface XSOARIncident {
  id: string;
  name: string;
  type: string;
  severity: number; // 0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical
  status: number;   // 0=Active, 1=Done, 2=Archive
  owner: string;
  phase: string;
  playbooks: string[];
  labels: Array<{ type: string; value: string }>;
  CustomFields: Record<string, unknown>;
  created: string;
  modified: string;
  occurred: string;
  closed: string;
  closeReason: string;
  closeNotes: string;
  rawCategory: string;
  sourceBrand: string;
  sourceInstance: string;
}

interface XSOARIndicator {
  id: string;
  value: string;
  indicator_type: string;
  score: number; // 0=Unknown, 1=Good, 2=Suspicious, 3=Bad
  source: string;
  investigationIDs: string[];
  relatedIncCount: number;
  firstSeen: string;
  lastSeen: string;
  modified: string;
  CustomFields: Record<string, unknown>;
}

interface XSOARPlaybook {
  id: string;
  name: string;
  description: string;
  version: number;
  startTaskId: string;
  tasks: Record<string, unknown>;
  system: boolean;
  deprecated: boolean;
}

export class XSOARClient extends BaseVendorClient {
  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    super("xsoar", authConfig, connectionConfig);
  }

  getDisplayName(): string {
    return "Palo Alto Cortex XSOAR";
  }

  // ─── API Key Authentication ────────────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.apiToken) {
      throw new VendorError("xsoar", "Missing XSOAR API key", "AUTH_CONFIG_MISSING");
    }

    // XSOAR uses a custom Authorization header format
    if (this.authConfig.apiKeyId) {
      // Advanced auth: api_key_id:api_key
      this.httpClient.defaults.headers.common["Authorization"] = this.authConfig.apiToken;
      this.httpClient.defaults.headers.common["x-xdr-auth-id"] = this.authConfig.apiKeyId;
    } else {
      // Standard auth
      this.httpClient.defaults.headers.common["Authorization"] = this.authConfig.apiToken;
    }
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/user" });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "Cortex XSOAR API is reachable and authenticated",
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: (error as Error).message,
      };
    }
  }

  // ─── Incidents ─────────────────────────────────────────────────────────────

  async queryIncidents(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const size = options?.limit ?? 100;
    const page = options?.offset ? Math.floor(options.offset / size) : 0;

    const body: Record<string, unknown> = { size, page };
    if (options?.filter) {
      body.filter = { query: options.filter };
    }
    if (options?.sort) {
      body.sort = [{ field: options.sort, asc: false }];
    }

    const response = await this.request<{ data: XSOARIncident[]; total: number }>({
      method: "POST",
      url: "/incidents/search",
      data: body,
    });

    return (response.data || []).map((i) => this.normalizeIncident(i));
  }

  async getIncident(incidentId: string): Promise<NormalizedVendorData | null> {
    try {
      const response = await this.request<XSOARIncident>({
        method: "GET",
        url: `/incident/${incidentId}`,
      });
      return this.normalizeIncident(response);
    } catch {
      return null;
    }
  }

  private normalizeIncident(i: XSOARIncident): NormalizedVendorData {
    const severity = i.severity === 4 ? "critical"
      : i.severity === 3 ? "high"
      : i.severity === 2 ? "medium"
      : i.severity === 1 ? "low"
      : "informational";

    const status = i.status === 0 ? "active"
      : i.status === 1 ? "closed"
      : "archived";

    return {
      id: i.id,
      type: "incident",
      title: i.name || `Incident ${i.id}`,
      severity,
      status,
      detectedAt: new Date(i.occurred || i.created).getTime(),
      raw: i,
    };
  }

  // ─── Indicators ────────────────────────────────────────────────────────────

  async queryIndicators(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const size = options?.limit ?? 100;
    const page = options?.offset ? Math.floor(options.offset / size) : 0;

    const body: Record<string, unknown> = { size, page };
    if (options?.filter) {
      body.filter = { query: options.filter };
    }

    const response = await this.request<{ iocObjects: XSOARIndicator[] }>({
      method: "POST",
      url: "/indicators/search",
      data: body,
    });

    return (response.iocObjects || []).map((ind) => this.normalizeIndicator(ind));
  }

  private normalizeIndicator(ind: XSOARIndicator): NormalizedVendorData {
    const severity = ind.score === 3 ? "critical"
      : ind.score === 2 ? "high"
      : ind.score === 1 ? "low"
      : "informational";

    // Try to extract IP/domain from indicator value
    const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ind.value);
    const isDomain = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(ind.value);

    return {
      id: ind.id,
      type: "indicator",
      title: `${ind.indicator_type}: ${ind.value}`,
      severity,
      status: ind.score === 3 ? "malicious" : ind.score === 2 ? "suspicious" : "unknown",
      ipAddress: isIp ? ind.value : undefined,
      domain: isDomain ? ind.value : undefined,
      detectedAt: new Date(ind.firstSeen).getTime(),
      raw: ind,
    };
  }

  // ─── Playbooks ─────────────────────────────────────────────────────────────

  async listPlaybooks(): Promise<Array<{ id: string; name: string; description: string }>> {
    const response = await this.request<{ playbooks: XSOARPlaybook[] }>({
      method: "POST",
      url: "/playbook/search",
      data: { size: 100 },
    });

    return (response.playbooks || [])
      .filter((p) => !p.deprecated)
      .map((p) => ({
        id: p.id,
        name: p.name,
        description: p.description,
      }));
  }

  async runPlaybook(playbookId: string, incidentId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: `/incident/${incidentId}/playbook/${playbookId}/run`,
    });
  }

  // ─── Create Incident ───────────────────────────────────────────────────────

  async createIncident(data: {
    name: string;
    type?: string;
    severity?: number;
    labels?: Array<{ type: string; value: string }>;
    customFields?: Record<string, unknown>;
  }): Promise<string> {
    const response = await this.request<{ id: string }>({
      method: "POST",
      url: "/incident",
      data: {
        name: data.name,
        type: data.type || "Unclassified",
        severity: data.severity ?? 2,
        labels: data.labels || [],
        CustomFields: data.customFields || {},
        createInvestigation: true,
      },
    });
    return response.id;
  }

  // ─── War Room Notes ────────────────────────────────────────────────────────

  async addWarRoomNote(incidentId: string, note: string): Promise<void> {
    await this.request({
      method: "POST",
      url: `/entry/note`,
      data: {
        investigationId: incidentId,
        data: note,
      },
    });
  }
}

export function createXSOARClient(
  authConfig: VendorAuthConfig,
  connectionConfig: VendorConnectionConfig
): XSOARClient {
  return new XSOARClient(authConfig, connectionConfig);
}
