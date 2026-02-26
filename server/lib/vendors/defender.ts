/**
 * Microsoft Defender for Endpoint Integration Client
 * Auth: Azure AD OAuth2 (tenant_id, client_id, client_secret → bearer token)
 * Endpoints: Machines, Alerts, Vulnerabilities, Advanced Hunting, Live Response
 */
import axios from "axios";
import { BaseVendorClient, VendorError } from "./base-client";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorQueryOptions,
} from "./base-client";

// ─── Defender-specific types ─────────────────────────────────────────────────

interface MdeMachine {
  id: string;
  computerDnsName: string;
  osPlatform: string;
  osVersion: string;
  lastIpAddress: string;
  lastExternalIpAddress: string;
  healthStatus: string;
  riskScore: string;
  exposureLevel: string;
  machineTags: string[];
  lastSeen: string;
  firstSeen: string;
  agentVersion: string;
  rbacGroupName: string;
}

interface MdeAlert {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  category: string;
  classification: string;
  determination: string;
  machineId: string;
  computerDnsName: string;
  alertCreationTime: string;
  lastEventTime: string;
  resolvedTime: string;
  threatFamilyName: string;
  mitreTechniques: string[];
  evidence: Array<{
    entityType: string;
    sha256: string;
    fileName: string;
    filePath: string;
    processId: number;
    ipAddress: string;
    url: string;
  }>;
}

interface MdeVulnerability {
  id: string;
  name: string;
  description: string;
  severity: string;
  cvssV3: number;
  exposedMachines: number;
  publishedOn: string;
  updatedOn: string;
  publicExploit: boolean;
  exploitVerified: boolean;
}

export class DefenderClient extends BaseVendorClient {
  private static readonly BASE_URL = "https://api.securitycenter.microsoft.com/api";
  private static readonly TOKEN_URL = "https://login.microsoftonline.com";
  private static readonly SCOPE = "https://api.securitycenter.microsoft.com/.default";

  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    super("defender", authConfig, {
      ...connectionConfig,
      baseUrl: connectionConfig.baseUrl || DefenderClient.BASE_URL,
    });
  }

  getDisplayName(): string {
    return "Microsoft Defender for Endpoint";
  }

  // ─── Azure AD OAuth2 Authentication ────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.tenantId || !this.authConfig.clientId || !this.authConfig.clientSecret) {
      throw new VendorError("defender", "Missing tenantId, clientId, or clientSecret", "AUTH_CONFIG_MISSING");
    }

    try {
      const tokenUrl = `${DefenderClient.TOKEN_URL}/${this.authConfig.tenantId}/oauth2/v2.0/token`;
      const response = await axios.post(
        tokenUrl,
        new URLSearchParams({
          client_id: this.authConfig.clientId,
          client_secret: this.authConfig.clientSecret,
          scope: DefenderClient.SCOPE,
          grant_type: "client_credentials",
        }).toString(),
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          timeout: 15_000,
        }
      );

      this.accessToken = response.data.access_token;
      this.tokenExpiresAt = Date.now() + (response.data.expires_in || 3600) * 1000;
      this.setAuthHeader(this.accessToken!);
    } catch (error) {
      if (error instanceof VendorError) throw error;
      const msg = (error as any)?.response?.data?.error_description || (error as Error).message;
      throw new VendorError("defender", `Azure AD token exchange failed: ${msg}`, "AUTH_FAILED");
    }
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/machines", params: { "$top": 1 } });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "Microsoft Defender for Endpoint API is reachable and authenticated",
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: (error as Error).message,
      };
    }
  }

  // ─── Machines ──────────────────────────────────────────────────────────────

  async queryMachines(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const top = options?.limit ?? 100;
    const skip = options?.offset ?? 0;
    const params: Record<string, unknown> = { "$top": top, "$skip": skip };
    if (options?.filter) params["$filter"] = options.filter;

    const response = await this.request<{ value: MdeMachine[] }>({
      method: "GET",
      url: "/machines",
      params,
    });

    return (response.value || []).map((m) => this.normalizeMachine(m));
  }

  private normalizeMachine(m: MdeMachine): NormalizedVendorData {
    const severity = m.riskScore === "High" ? "high"
      : m.riskScore === "Medium" ? "medium"
      : m.riskScore === "Low" ? "low"
      : "informational";

    return {
      id: m.id,
      type: "host",
      title: m.computerDnsName || m.id,
      severity,
      status: m.healthStatus,
      hostname: m.computerDnsName,
      ipAddress: m.lastIpAddress || m.lastExternalIpAddress,
      raw: m,
    };
  }

  // ─── Alerts ────────────────────────────────────────────────────────────────

  async queryAlerts(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const top = options?.limit ?? 100;
    const skip = options?.offset ?? 0;
    const params: Record<string, unknown> = { "$top": top, "$skip": skip };
    if (options?.filter) params["$filter"] = options.filter;
    if (options?.timeRange) {
      params["$filter"] = `alertCreationTime ge ${new Date(options.timeRange.start).toISOString()} and alertCreationTime le ${new Date(options.timeRange.end).toISOString()}`;
    }

    const response = await this.request<{ value: MdeAlert[] }>({
      method: "GET",
      url: "/alerts",
      params,
    });

    return (response.value || []).map((a) => this.normalizeAlert(a));
  }

  private normalizeAlert(a: MdeAlert): NormalizedVendorData {
    const severity = a.severity?.toLowerCase() as "critical" | "high" | "medium" | "low" | "informational" || "medium";

    return {
      id: a.id,
      type: "alert",
      title: a.title || `Alert ${a.id}`,
      severity,
      status: a.status,
      hostname: a.computerDnsName,
      mitreAttackId: a.mitreTechniques?.[0],
      detectedAt: new Date(a.alertCreationTime).getTime(),
      raw: a,
    };
  }

  // ─── Vulnerabilities ───────────────────────────────────────────────────────

  async queryVulnerabilities(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const top = options?.limit ?? 100;
    const skip = options?.offset ?? 0;

    const response = await this.request<{ value: MdeVulnerability[] }>({
      method: "GET",
      url: "/vulnerabilities",
      params: { "$top": top, "$skip": skip },
    });

    return (response.value || []).map((v) => this.normalizeVulnerability(v));
  }

  private normalizeVulnerability(v: MdeVulnerability): NormalizedVendorData {
    const severity = v.cvssV3 >= 9.0 ? "critical"
      : v.cvssV3 >= 7.0 ? "high"
      : v.cvssV3 >= 4.0 ? "medium"
      : "low";

    return {
      id: v.id,
      type: "vulnerability",
      title: `${v.name}: ${v.description?.slice(0, 100)}`,
      severity,
      status: v.publicExploit ? "exploit_available" : "no_exploit",
      detectedAt: new Date(v.publishedOn).getTime(),
      raw: v,
    };
  }

  // ─── Advanced Hunting (KQL) ────────────────────────────────────────────────

  async advancedHunting(query: string): Promise<NormalizedVendorData[]> {
    const response = await this.request<{ Results: any[] }>({
      method: "POST",
      url: "/advancedqueries/run",
      data: { Query: query },
    });

    return (response.Results || []).map((r: any, i: number) => ({
      id: `kql-${i}`,
      type: "search_result" as const,
      title: r.DeviceName || r.FileName || `Result ${i + 1}`,
      hostname: r.DeviceName,
      ipAddress: r.LocalIP || r.RemoteIP,
      raw: r,
    }));
  }

  // ─── Machine Actions ───────────────────────────────────────────────────────

  async isolateMachine(machineId: string, comment: string = "Isolated via Ace C3"): Promise<void> {
    await this.request({
      method: "POST",
      url: `/machines/${machineId}/isolate`,
      data: { Comment: comment, IsolationType: "Full" },
    });
  }

  async unisolateMachine(machineId: string, comment: string = "Released via Ace C3"): Promise<void> {
    await this.request({
      method: "POST",
      url: `/machines/${machineId}/unisolate`,
      data: { Comment: comment },
    });
  }
}

export function createDefenderClient(
  authConfig: VendorAuthConfig,
  connectionConfig?: Partial<VendorConnectionConfig>
): DefenderClient {
  return new DefenderClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || DefenderClient["BASE_URL"],
    timeout: connectionConfig?.timeout ?? 30_000,
    ...connectionConfig,
  });
}
