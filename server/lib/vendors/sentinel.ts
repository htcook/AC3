/**
 * Microsoft Sentinel (Azure SIEM) Integration Client
 * Auth: Azure AD OAuth2 (tenant_id, client_id, client_secret → bearer token)
 * Endpoints: Incidents, Hunting Queries (KQL), Watchlists, Analytics Rules, Bookmarks
 * 
 * Sentinel uses Azure Resource Manager (ARM) API + Log Analytics workspace queries.
 * This is distinct from Microsoft Defender for Endpoint — Sentinel is the SIEM layer.
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

// ─── Sentinel-specific types ─────────────────────────────────────────────────

interface SentinelIncident {
  id: string;
  name: string;
  properties: {
    title: string;
    description: string;
    severity: "High" | "Medium" | "Low" | "Informational";
    status: "New" | "Active" | "Closed";
    classification?: string;
    classificationReason?: string;
    owner: { assignedTo?: string; email?: string };
    incidentNumber: number;
    incidentUrl: string;
    labels: Array<{ labelName: string }>;
    firstActivityTimeUtc: string;
    lastActivityTimeUtc: string;
    createdTimeUtc: string;
    lastModifiedTimeUtc: string;
    additionalData: {
      alertsCount: number;
      bookmarksCount: number;
      commentsCount: number;
      alertProductNames: string[];
      tactics: string[];
      techniques: string[];
    };
    relatedAnalyticRuleIds: string[];
  };
}

interface SentinelAlertRule {
  id: string;
  name: string;
  kind: "Scheduled" | "MicrosoftSecurityIncidentCreation" | "Fusion" | "MLBehaviorAnalytics" | "NRT";
  properties: {
    displayName: string;
    description: string;
    severity: string;
    enabled: boolean;
    query?: string;
    queryFrequency?: string;
    queryPeriod?: string;
    triggerOperator?: string;
    triggerThreshold?: number;
    tactics?: string[];
    techniques?: string[];
    lastModifiedUtc: string;
  };
}

interface SentinelWatchlist {
  id: string;
  name: string;
  properties: {
    displayName: string;
    description: string;
    provider: string;
    source: string;
    itemsSearchKey: string;
    numberOfLinesToSkip: number;
    created: string;
    updated: string;
  };
}

interface LogAnalyticsQueryResult {
  tables: Array<{
    name: string;
    columns: Array<{ name: string; type: string }>;
    rows: any[][];
  }>;
}

// ─── Sentinel Client ─────────────────────────────────────────────────────────

export class SentinelClient extends BaseVendorClient {
  private static readonly ARM_BASE = "https://management.azure.com";
  private static readonly TOKEN_URL = "https://login.microsoftonline.com";
  private static readonly ARM_SCOPE = "https://management.azure.com/.default";
  private static readonly LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default";

  // Sentinel workspace identifiers (from connectionConfig.baseUrl or custom fields)
  private subscriptionId: string;
  private resourceGroup: string;
  private workspaceName: string;
  private workspaceId: string; // Log Analytics workspace ID for KQL queries

  // Separate token for Log Analytics API
  private logAnalyticsToken: string | null = null;
  private logAnalyticsTokenExpiry: number = 0;

  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    super("sentinel" as any, authConfig, {
      ...connectionConfig,
      baseUrl: connectionConfig.baseUrl || SentinelClient.ARM_BASE,
    });

    // Parse workspace identifiers from connection config
    // Expected baseUrl format: subscriptionId/resourceGroup/workspaceName/workspaceId
    const parts = (connectionConfig.baseUrl || "").split("/").filter(Boolean);
    this.subscriptionId = parts[0] || "";
    this.resourceGroup = parts[1] || "";
    this.workspaceName = parts[2] || "";
    this.workspaceId = parts[3] || "";

    // Override httpClient base URL to ARM
    this.httpClient.defaults.baseURL = SentinelClient.ARM_BASE;
  }

  // ─── Auth ──────────────────────────────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.tenantId || !this.authConfig.clientId || !this.authConfig.clientSecret) {
      throw new VendorError("sentinel" as any, "Missing Azure AD credentials (tenantId, clientId, clientSecret)", "AUTH_CONFIG");
    }

    try {
      const tokenUrl = `${SentinelClient.TOKEN_URL}/${this.authConfig.tenantId}/oauth2/v2.0/token`;
      const httpsAgent = getFIPSHttpsAgent();

      // ARM token
      const armResponse = await axios.post(tokenUrl, new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.authConfig.clientId,
        client_secret: this.authConfig.clientSecret,
        scope: SentinelClient.ARM_SCOPE,
      }).toString(), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        httpsAgent,
      });

      this.accessToken = armResponse.data.access_token;
      this.tokenExpiresAt = Date.now() + (armResponse.data.expires_in * 1000);
      this.setAuthHeader(this.accessToken!);

      // Log Analytics token (for KQL queries)
      const laResponse = await axios.post(tokenUrl, new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.authConfig.clientId,
        client_secret: this.authConfig.clientSecret,
        scope: SentinelClient.LOG_ANALYTICS_SCOPE,
      }).toString(), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        httpsAgent,
      });

      this.logAnalyticsToken = laResponse.data.access_token;
      this.logAnalyticsTokenExpiry = Date.now() + (laResponse.data.expires_in * 1000);
    } catch (error: any) {
      throw new VendorError("sentinel" as any, `Azure AD auth failed: ${error.message}`, "AUTH_FAILED");
    }
  }

  getDisplayName(): string {
    return "Microsoft Sentinel";
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.ensureAuthenticated();
      const incidents = await this.listIncidents({ limit: 1 });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: `Sentinel workspace "${this.workspaceName}" connected`,
        details: {
          workspace: this.workspaceName,
          subscriptionId: this.subscriptionId,
          incidentCount: incidents.length,
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

  // ─── Sentinel API Path Builder ─────────────────────────────────────────────

  private get sentinelBasePath(): string {
    return `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}/providers/Microsoft.SecurityInsights`;
  }

  // ─── Incidents ─────────────────────────────────────────────────────────────

  async listIncidents(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const limit = options?.limit ?? 50;
    const filter = options?.filter ? `&$filter=${encodeURIComponent(options.filter)}` : "";
    const orderBy = "&$orderby=properties/createdTimeUtc desc";

    const data = await this.request<{ value: SentinelIncident[] }>({
      method: "GET",
      url: `${this.sentinelBasePath}/incidents?api-version=2023-11-01&$top=${limit}${filter}${orderBy}`,
    });

    return (data.value || []).map((inc) => ({
      id: inc.name,
      type: "incident" as const,
      title: inc.properties.title,
      severity: this.normalizeSeverity(inc.properties.severity),
      status: inc.properties.status.toLowerCase(),
      detectedAt: new Date(inc.properties.createdTimeUtc).getTime(),
      mitreAttackId: inc.properties.additionalData?.tactics?.join(", "),
      raw: inc,
    }));
  }

  async getIncident(incidentId: string): Promise<SentinelIncident> {
    return this.request<SentinelIncident>({
      method: "GET",
      url: `${this.sentinelBasePath}/incidents/${incidentId}?api-version=2023-11-01`,
    });
  }

  async updateIncidentStatus(incidentId: string, status: "New" | "Active" | "Closed", classification?: string): Promise<void> {
    const incident = await this.getIncident(incidentId);
    await this.request({
      method: "PUT",
      url: `${this.sentinelBasePath}/incidents/${incidentId}?api-version=2023-11-01`,
      data: {
        ...incident,
        properties: {
          ...incident.properties,
          status,
          ...(classification && { classification }),
        },
      },
    });
  }

  // ─── Analytics Rules ───────────────────────────────────────────────────────

  async listAnalyticsRules(options?: VendorQueryOptions): Promise<SentinelAlertRule[]> {
    const data = await this.request<{ value: SentinelAlertRule[] }>({
      method: "GET",
      url: `${this.sentinelBasePath}/alertRules?api-version=2023-11-01`,
    });
    return data.value || [];
  }

  async toggleAnalyticsRule(ruleId: string, enabled: boolean): Promise<void> {
    const rules = await this.listAnalyticsRules();
    const rule = rules.find((r) => r.name === ruleId);
    if (!rule) throw new VendorError("sentinel" as any, `Rule ${ruleId} not found`, "NOT_FOUND");

    await this.request({
      method: "PUT",
      url: `${this.sentinelBasePath}/alertRules/${ruleId}?api-version=2023-11-01`,
      data: {
        ...rule,
        properties: { ...rule.properties, enabled },
      },
    });
  }

  // ─── Hunting Queries (KQL via Log Analytics) ───────────────────────────────

  async runHuntingQuery(kqlQuery: string, timespan?: string): Promise<LogAnalyticsQueryResult> {
    // Ensure Log Analytics token is valid
    if (!this.logAnalyticsToken || Date.now() >= this.logAnalyticsTokenExpiry - 60_000) {
      await this.authenticate();
    }

    const httpsAgent = getFIPSHttpsAgent();
    const response = await axios.post(
      `https://api.loganalytics.io/v1/workspaces/${this.workspaceId}/query`,
      {
        query: kqlQuery,
        timespan: timespan || "P7D", // default 7 days
      },
      {
        headers: {
          Authorization: `Bearer ${this.logAnalyticsToken}`,
          "Content-Type": "application/json",
        },
        httpsAgent,
        timeout: 60_000,
      }
    );

    return response.data;
  }

  // ─── Watchlists ────────────────────────────────────────────────────────────

  async listWatchlists(): Promise<SentinelWatchlist[]> {
    const data = await this.request<{ value: SentinelWatchlist[] }>({
      method: "GET",
      url: `${this.sentinelBasePath}/watchlists?api-version=2023-11-01`,
    });
    return data.value || [];
  }

  async addWatchlistItems(watchlistAlias: string, items: Record<string, string>[]): Promise<void> {
    for (const item of items) {
      const itemId = `ace-c3-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      await this.request({
        method: "PUT",
        url: `${this.sentinelBasePath}/watchlists/${watchlistAlias}/watchlistItems/${itemId}?api-version=2023-11-01`,
        data: {
          properties: {
            itemsKeyValue: item,
          },
        },
      });
    }
  }

  // ─── IOC Push (via TI Indicators) ──────────────────────────────────────────

  async pushIndicators(indicators: Array<{
    type: "ipv4" | "ipv6" | "domain" | "url" | "file_hash_sha256";
    value: string;
    description: string;
    confidence: number;
    threatType: string;
    validUntil: string;
  }>): Promise<{ created: number; failed: number }> {
    let created = 0;
    let failed = 0;

    for (const ioc of indicators) {
      try {
        const indicatorId = `ace-c3-ioc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const patternMap: Record<string, string> = {
          ipv4: `[ipv4-addr:value = '${ioc.value}']`,
          ipv6: `[ipv6-addr:value = '${ioc.value}']`,
          domain: `[domain-name:value = '${ioc.value}']`,
          url: `[url:value = '${ioc.value}']`,
          file_hash_sha256: `[file:hashes.'SHA-256' = '${ioc.value}']`,
        };

        await this.request({
          method: "PUT",
          url: `${this.sentinelBasePath}/threatIntelligence/main/indicators/${indicatorId}?api-version=2023-11-01`,
          data: {
            kind: "indicator",
            properties: {
              source: "Ace C3 Platform",
              displayName: `[Ace C3] ${ioc.type}: ${ioc.value}`,
              description: ioc.description,
              confidence: ioc.confidence,
              pattern: patternMap[ioc.type] || `[artifact:payload_bin = '${ioc.value}']`,
              patternType: "stix",
              threatTypes: [ioc.threatType],
              validFrom: new Date().toISOString(),
              validUntil: ioc.validUntil,
            },
          },
        });
        created++;
      } catch {
        failed++;
      }
    }

    return { created, failed };
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private normalizeSeverity(severity: string): "critical" | "high" | "medium" | "low" | "informational" {
    switch (severity.toLowerCase()) {
      case "high": return "high";
      case "medium": return "medium";
      case "low": return "low";
      case "informational": return "informational";
      default: return "medium";
    }
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createSentinelClient(
  authConfig: VendorAuthConfig,
  connectionConfig?: Partial<VendorConnectionConfig>
): SentinelClient {
  return new SentinelClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || "",
    timeout: connectionConfig?.timeout ?? 30_000,
    ...connectionConfig,
  });
}
