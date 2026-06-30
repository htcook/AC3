/**
 * CrowdStrike Falcon Integration Client
 * Auth: OAuth2 Client Credentials (client_id + client_secret → bearer token, 30min TTL)
 * Endpoints: Hosts, Detections, Incidents, IOCs, RTR
 */
import axios from "axios";
import { BaseVendorClient, VendorError } from "./base-client";
import { getFIPSHttpsAgent } from "../fips-tls";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorQueryOptions,
} from "./base-client";

// ─── CrowdStrike-specific types ──────────────────────────────────────────────

interface CSHost {
  device_id: string;
  hostname: string;
  local_ip: string;
  external_ip: string;
  os_version: string;
  platform_name: string;
  status: string;
  last_seen: string;
  agent_version: string;
  system_manufacturer?: string;
  system_product_name?: string;
  tags?: string[];
}

interface CSDetection {
  detection_id: string;
  display_name?: string;
  description?: string;
  max_severity_displayname: string;
  max_severity: number;
  status: string;
  hostname: string;
  device_id: string;
  behaviors?: Array<{
    tactic: string;
    technique: string;
    technique_id: string;
    display_name: string;
    severity: number;
    timestamp: string;
  }>;
  first_behavior: string;
  last_behavior: string;
  created_timestamp: string;
}

interface CSIncident {
  incident_id: string;
  name?: string;
  description?: string;
  state: string;
  status: number;
  fine_score: number;
  host_ids: string[];
  hosts?: Array<{ hostname: string; local_ip: string }>;
  tactics?: string[];
  techniques?: string[];
  created: string;
  start: string;
  end?: string;
}

// Region-to-URL mapping
const CS_REGIONS: Record<string, string> = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
};

export class CrowdStrikeClient extends BaseVendorClient {
  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    // Resolve region to base URL if not explicitly set
    const baseUrl = connectionConfig.baseUrl || CS_REGIONS[authConfig.region || "us-1"] || CS_REGIONS["us-1"];
    super("crowdstrike", authConfig, { ...connectionConfig, baseUrl });
  }

  getDisplayName(): string {
    return "CrowdStrike Falcon";
  }

  // ─── OAuth2 Authentication ─────────────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.clientId || !this.authConfig.clientSecret) {
      throw new VendorError("crowdstrike", "Missing clientId or clientSecret", "AUTH_CONFIG_MISSING");
    }

    try {
      const response = await axios.post(
        `${this.connectionConfig.baseUrl}/oauth2/token`,
        new URLSearchParams({
          client_id: this.authConfig.clientId,
          client_secret: this.authConfig.clientSecret,
        }).toString(),
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          timeout: 15_000,
          httpsAgent: getFIPSHttpsAgent(),
        }
      );

      this.accessToken = response.data.access_token;
      // CrowdStrike tokens are valid for 30 minutes
      this.tokenExpiresAt = Date.now() + (response.data.expires_in || 1800) * 1000;
      this.setAuthHeader(this.accessToken!);
    } catch (error) {
      if (error instanceof VendorError) throw error;
      const msg = (error as any)?.response?.data?.errors?.[0]?.message || (error as Error).message;
      throw new VendorError("crowdstrike", `OAuth2 token exchange failed: ${msg}`, "AUTH_FAILED");
    }
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/sensors/queries/installers/ccid/v1" });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "CrowdStrike Falcon API is reachable and authenticated",
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: (error as Error).message,
      };
    }
  }

  // ─── Hosts ─────────────────────────────────────────────────────────────────

  async queryHosts(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const filter = options?.filter || "";

    // Step 1: Get host IDs
    const idsResponse = await this.request<{ resources: string[] }>({
      method: "GET",
      url: "/devices/queries/devices/v1",
      params: { limit, offset, filter: filter || undefined },
    });

    if (!idsResponse.resources?.length) return [];

    // Step 2: Get host details
    const detailsResponse = await this.request<{ resources: CSHost[] }>({
      method: "POST",
      url: "/devices/entities/devices/v2",
      data: { ids: idsResponse.resources },
    });

    return (detailsResponse.resources || []).map((h) => this.normalizeHost(h));
  }

  async getHost(deviceId: string): Promise<NormalizedVendorData | null> {
    const response = await this.request<{ resources: CSHost[] }>({
      method: "POST",
      url: "/devices/entities/devices/v2",
      data: { ids: [deviceId] },
    });
    const host = response.resources?.[0];
    return host ? this.normalizeHost(host) : null;
  }

  private normalizeHost(h: CSHost): NormalizedVendorData {
    return {
      id: h.device_id,
      type: "host",
      title: h.hostname || h.device_id,
      status: h.status,
      hostname: h.hostname,
      ipAddress: h.local_ip || h.external_ip,
      raw: h,
    };
  }

  // ─── Detections ────────────────────────────────────────────────────────────

  async queryDetections(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const filter = options?.filter || "";

    const idsResponse = await this.request<{ resources: string[] }>({
      method: "GET",
      url: "/detects/queries/detects/v1",
      params: { limit, offset, filter: filter || undefined },
    });

    if (!idsResponse.resources?.length) return [];

    const detailsResponse = await this.request<{ resources: CSDetection[] }>({
      method: "POST",
      url: "/detects/entities/summaries/GET/v1",
      data: { ids: idsResponse.resources },
    });

    return (detailsResponse.resources || []).map((d) => this.normalizeDetection(d));
  }

  private normalizeDetection(d: CSDetection): NormalizedVendorData {
    const severity = d.max_severity >= 80 ? "critical"
      : d.max_severity >= 60 ? "high"
      : d.max_severity >= 40 ? "medium"
      : d.max_severity >= 20 ? "low"
      : "informational";

    const mitreId = d.behaviors?.[0]?.technique_id;

    return {
      id: d.detection_id,
      type: "detection",
      title: d.display_name || d.behaviors?.[0]?.display_name || `Detection on ${d.hostname}`,
      severity,
      status: d.status,
      hostname: d.hostname,
      mitreAttackId: mitreId,
      detectedAt: new Date(d.created_timestamp).getTime(),
      raw: d,
    };
  }

  // ─── Incidents ─────────────────────────────────────────────────────────────

  async queryIncidents(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const filter = options?.filter || "";

    const idsResponse = await this.request<{ resources: string[] }>({
      method: "GET",
      url: "/incidents/queries/incidents/v1",
      params: { limit, offset, filter: filter || undefined },
    });

    if (!idsResponse.resources?.length) return [];

    const detailsResponse = await this.request<{ resources: CSIncident[] }>({
      method: "POST",
      url: "/incidents/entities/incidents/GET/v1",
      data: { ids: idsResponse.resources },
    });

    return (detailsResponse.resources || []).map((i) => this.normalizeIncident(i));
  }

  private normalizeIncident(i: CSIncident): NormalizedVendorData {
    const severity = i.fine_score >= 80 ? "critical"
      : i.fine_score >= 60 ? "high"
      : i.fine_score >= 40 ? "medium"
      : i.fine_score >= 20 ? "low"
      : "informational";

    return {
      id: i.incident_id,
      type: "incident",
      title: i.name || `Incident ${i.incident_id.slice(0, 8)}`,
      severity,
      status: i.state,
      hostname: i.hosts?.[0]?.hostname,
      ipAddress: i.hosts?.[0]?.local_ip,
      mitreAttackId: i.techniques?.[0],
      detectedAt: new Date(i.created).getTime(),
      raw: i,
    };
  }

  // ─── IOCs ──────────────────────────────────────────────────────────────────

  async queryIOCs(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    const response = await this.request<{ resources: any[] }>({
      method: "GET",
      url: "/iocs/combined/indicator/v1",
      params: { limit, offset },
    });

    return (response.resources || []).map((ioc: any) => ({
      id: ioc.id,
      type: "indicator" as const,
      title: `${ioc.type}: ${ioc.value}`,
      severity: ioc.severity === "critical" ? "critical" as const
        : ioc.severity === "high" ? "high" as const
        : ioc.severity === "medium" ? "medium" as const
        : "low" as const,
      status: ioc.action,
      raw: ioc,
    }));
  }

  // ─── Containment ───────────────────────────────────────────────────────────

  async containHost(deviceId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/devices/entities/devices-actions/v2",
      params: { action_name: "contain" },
      data: { ids: [deviceId] },
    });
  }

  async liftContainment(deviceId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/devices/entities/devices-actions/v2",
      params: { action_name: "lift_containment" },
      data: { ids: [deviceId] },
    });
  }
}

export function createCrowdStrikeClient(
  authConfig: VendorAuthConfig,
  connectionConfig?: Partial<VendorConnectionConfig>
): CrowdStrikeClient {
  return new CrowdStrikeClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || CS_REGIONS[authConfig.region || "us-1"],
    timeout: connectionConfig?.timeout ?? 30_000,
    ...connectionConfig,
  });
}
