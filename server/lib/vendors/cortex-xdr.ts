/**
 * Palo Alto Cortex XDR Integration Client
 * Auth: API Key + API Key ID (Advanced or Standard security level)
 * Endpoints: Incidents, Alerts, Endpoints, XQL Queries, Response Actions
 *
 * Cortex XDR is the XDR layer — distinct from XSOAR (SOAR).
 * Uses POST-based API with JSON request bodies for all operations.
 */
import crypto from "crypto";
import { BaseVendorClient, VendorError } from "./base-client";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorQueryOptions,
} from "./base-client";

// ─── Cortex XDR-specific types ───────────────────────────────────────────────

interface XDRIncident {
  incident_id: string;
  incident_name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "new" | "under_investigation" | "resolved_threat_handled" | "resolved_known_issue" | "resolved_duplicate" | "resolved_false_positive" | "resolved_other";
  assigned_user_mail: string | null;
  assigned_user_pretty_name: string | null;
  creation_time: number;
  modification_time: number;
  detection_time: number | null;
  alert_count: number;
  low_severity_alert_count: number;
  med_severity_alert_count: number;
  high_severity_alert_count: number;
  host_count: number;
  user_count: number;
  starred: boolean;
  mitre_tactics_ids_and_names: string[];
  mitre_techniques_ids_and_names: string[];
}

interface XDRAlert {
  alert_id: string;
  internal_id: string;
  name: string;
  description: string;
  severity: string;
  category: string;
  action_status: string;
  host_name: string;
  host_ip: string[];
  source: string;
  action: string;
  detection_timestamp: number;
  mitre_tactic_id_and_name: string;
  mitre_technique_id_and_name: string;
}

interface XDREndpoint {
  endpoint_id: string;
  endpoint_name: string;
  endpoint_type: string;
  endpoint_status: string;
  os_type: string;
  ip: string[];
  domain: string;
  alias: string;
  first_seen: number;
  last_seen: number;
  content_version: string;
  installation_package: string;
  active_directory: string | null;
  install_date: number;
  endpoint_version: string;
  is_isolated: string;
  group_name: string[];
}

interface XQLQueryResult {
  status: string;
  number_of_results: number;
  query_cost: Record<string, number>;
  remaining_quota: number;
  results: {
    data: any[];
  };
}

// ─── Cortex XDR Client ───────────────────────────────────────────────────────

export class CortexXDRClient extends BaseVendorClient {
  private apiKeyId: string;
  private securityLevel: "advanced" | "standard";

  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    super("cortex_xdr" as any, authConfig, connectionConfig);

    this.apiKeyId = authConfig.apiKeyId || "";
    this.securityLevel = authConfig.region === "standard" ? "standard" : "advanced";
  }

  // ─── Auth ──────────────────────────────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.apiToken || !this.apiKeyId) {
      throw new VendorError("cortex_xdr" as any, "Missing API Key or API Key ID", "AUTH_CONFIG");
    }

    // For advanced security level, generate HMAC nonce headers
    // For standard, just set the API key header
    if (this.securityLevel === "standard") {
      this.httpClient.defaults.headers.common["x-xdr-auth-id"] = this.apiKeyId;
      this.httpClient.defaults.headers.common["Authorization"] = this.authConfig.apiToken;
    }
    // Advanced auth headers are generated per-request in getAdvancedHeaders()
  }

  getDisplayName(): string {
    return "Palo Alto Cortex XDR";
  }

  // ─── Advanced Auth Headers (per-request nonce) ─────────────────────────────

  private getAdvancedHeaders(): Record<string, string> {
    if (this.securityLevel !== "advanced") return {};

    const nonce = crypto.randomBytes(32).toString("hex");
    const timestamp = Date.now().toString();
    const authString = `${this.authConfig.apiToken}${nonce}${timestamp}`;
    const hash = crypto.createHash("sha256").update(authString).digest("hex");

    return {
      "x-xdr-auth-id": this.apiKeyId,
      "x-xdr-nonce": nonce,
      "x-xdr-timestamp": timestamp,
      "Authorization": hash,
    };
  }

  // ─── Override request to inject advanced auth headers ──────────────────────

  protected async request<T = unknown>(config: any): Promise<T> {
    if (this.securityLevel === "advanced") {
      config.headers = { ...config.headers, ...this.getAdvancedHeaders() };
    }
    return super.request<T>(config);
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.ensureAuthenticated();
      const endpoints = await this.listEndpoints({ limit: 1 });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: `Cortex XDR connected — ${endpoints.length} endpoint(s) visible`,
        details: {
          securityLevel: this.securityLevel,
          endpointCount: endpoints.length,
        },
      };
    } catch (error: any) {
      return {
        status: "error",
        latencyMs: Date.now() - start,
        message: error.message || "Health check failed",
      };
    }
  }

  // ─── Incidents ─────────────────────────────────────────────────────────────

  async listIncidents(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 50;
    const filters: any[] = [];

    if (options?.timeRange) {
      filters.push({
        field: "creation_time",
        operator: "gte",
        value: options.timeRange.start,
      });
      filters.push({
        field: "creation_time",
        operator: "lte",
        value: options.timeRange.end,
      });
    }

    const data = await this.request<{ reply: { incidents: XDRIncident[]; total_count: number } }>({
      method: "POST",
      url: "/public_api/v1/incidents/get_incidents",
      data: {
        request_data: {
          filters,
          search_from: options?.offset ?? 0,
          search_to: (options?.offset ?? 0) + limit,
          sort: { field: "creation_time", keyword: "desc" },
        },
      },
    });

    return (data.reply?.incidents || []).map((inc) => ({
      id: inc.incident_id,
      type: "incident" as const,
      title: inc.incident_name,
      severity: inc.severity as any,
      status: inc.status,
      detectedAt: inc.creation_time,
      mitreAttackId: inc.mitre_techniques_ids_and_names?.join(", "),
      raw: inc,
    }));
  }

  async getIncidentDetails(incidentId: string): Promise<XDRIncident & { alerts: XDRAlert[] }> {
    const data = await this.request<{ reply: { incident: XDRIncident; alerts: { data: XDRAlert[] } } }>({
      method: "POST",
      url: "/public_api/v1/incidents/get_incident_extra_data",
      data: {
        request_data: { incident_id: incidentId },
      },
    });
    return { ...data.reply.incident, alerts: data.reply.alerts?.data || [] };
  }

  // ─── Alerts ────────────────────────────────────────────────────────────────

  async listAlerts(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 50;
    const filters: any[] = [];

    if (options?.timeRange) {
      filters.push({
        field: "detection_timestamp",
        operator: "gte",
        value: options.timeRange.start,
      });
    }

    const data = await this.request<{ reply: { alerts: XDRAlert[]; total_count: number } }>({
      method: "POST",
      url: "/public_api/v1/alerts/get_alerts_multi_events",
      data: {
        request_data: {
          filters,
          search_from: options?.offset ?? 0,
          search_to: (options?.offset ?? 0) + limit,
          sort: { field: "detection_timestamp", keyword: "desc" },
        },
      },
    });

    return (data.reply?.alerts || []).map((alert) => ({
      id: alert.alert_id,
      type: "alert" as const,
      title: alert.name,
      severity: this.normalizeSeverity(alert.severity),
      status: alert.action_status,
      hostname: alert.host_name,
      ipAddress: alert.host_ip?.[0],
      detectedAt: alert.detection_timestamp,
      mitreAttackId: alert.mitre_technique_id_and_name,
      raw: alert,
    }));
  }

  // ─── Endpoints ─────────────────────────────────────────────────────────────

  async listEndpoints(options?: VendorQueryOptions): Promise<XDREndpoint[]> {
    const limit = options?.limit ?? 100;
    const data = await this.request<{ reply: XDREndpoint[] }>({
      method: "POST",
      url: "/public_api/v1/endpoints/get_endpoint",
      data: {
        request_data: {
          filters: [],
          search_from: options?.offset ?? 0,
          search_to: (options?.offset ?? 0) + limit,
        },
      },
    });
    return data.reply || [];
  }

  async getEndpoint(endpointId: string): Promise<XDREndpoint | null> {
    const data = await this.request<{ reply: XDREndpoint[] }>({
      method: "POST",
      url: "/public_api/v1/endpoints/get_endpoint",
      data: {
        request_data: {
          filters: [{ field: "endpoint_id", operator: "in", value: [endpointId] }],
        },
      },
    });
    return data.reply?.[0] || null;
  }

  // ─── XQL Queries ───────────────────────────────────────────────────────────

  async runXQLQuery(query: string, timeframe?: { from: number; to: number }): Promise<XQLQueryResult> {
    const startData = await this.request<{ reply: string }>({
      method: "POST",
      url: "/public_api/v1/xql/start_xql_query",
      data: {
        request_data: {
          query,
          tenants: [],
          timeframe: timeframe || {
            from: Date.now() - 7 * 24 * 60 * 60 * 1000,
            to: Date.now(),
          },
        },
      },
    });

    const queryId = startData.reply;

    // Poll for results (max 30 seconds)
    for (let i = 0; i < 15; i++) {
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const result = await this.request<{ reply: XQLQueryResult }>({
        method: "POST",
        url: "/public_api/v1/xql/get_query_results",
        data: {
          request_data: { query_id: queryId, pending_result: true },
        },
      });

      if (result.reply.status === "SUCCESS" || result.reply.status === "PARTIAL_SUCCESS") {
        return result.reply;
      }
      if (result.reply.status === "FAIL") {
        throw new VendorError("cortex_xdr" as any, "XQL query failed", "QUERY_FAILED");
      }
    }

    throw new VendorError("cortex_xdr" as any, "XQL query timed out", "TIMEOUT");
  }

  // ─── Response Actions ──────────────────────────────────────────────────────

  async isolateEndpoint(endpointId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/isolate",
      data: {
        request_data: { endpoint_id: endpointId },
      },
    });
  }

  async unisolateEndpoint(endpointId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/unisolate",
      data: {
        request_data: { endpoint_id: endpointId },
      },
    });
  }

  async scanEndpoint(endpointId: string): Promise<void> {
    await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/scan",
      data: {
        request_data: {
          filters: [{ field: "endpoint_id", operator: "in", value: [endpointId] }],
        },
      },
    });
  }

  // ─── IOC Management ────────────────────────────────────────────────────────

  async pushIOCs(indicators: Array<{
    type: "DOMAIN" | "IP" | "HASH";
    value: string;
    reputation: "GOOD" | "BAD" | "SUSPICIOUS";
    comment: string;
    expiration?: number;
  }>): Promise<{ created: number; failed: number }> {
    try {
      await this.request({
        method: "POST",
        url: "/public_api/v1/indicators/insert_jsons",
        data: {
          request_data: indicators.map((ioc) => ({
            indicator: ioc.value,
            type: ioc.type,
            reputation: ioc.reputation,
            comment: `[Ace C3] ${ioc.comment}`,
            expiration_date: ioc.expiration || Date.now() + 30 * 24 * 60 * 60 * 1000,
            severity: ioc.reputation === "BAD" ? "HIGH" : "MEDIUM",
            vendors: [{ vendor_name: "Ace C3", reliability: "A", reputation: ioc.reputation }],
            class: "Malware",
          })),
        },
      });
      return { created: indicators.length, failed: 0 };
    } catch {
      return { created: 0, failed: indicators.length };
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private normalizeSeverity(severity: string): "critical" | "high" | "medium" | "low" | "informational" {
    switch (severity?.toLowerCase()) {
      case "critical": return "critical";
      case "high": return "high";
      case "medium": return "medium";
      case "low": return "low";
      case "informational": return "informational";
      default: return "medium";
    }
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createCortexXDRClient(
  authConfig: VendorAuthConfig,
  connectionConfig?: Partial<VendorConnectionConfig>
): CortexXDRClient {
  return new CortexXDRClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || "",
    timeout: connectionConfig?.timeout ?? 30_000,
    ...connectionConfig,
  });
}
