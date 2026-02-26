/**
 * Splunk Enterprise / Splunk Cloud Integration Client
 * Auth: Bearer Token (Splunk auth token) or Basic Auth
 * Endpoints: Search Jobs, Notable Events (ES), Saved Searches, KV Store
 */
import { BaseVendorClient, VendorError } from "./base-client";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorQueryOptions,
} from "./base-client";

// ─── Splunk-specific types ───────────────────────────────────────────────────

interface SplunkSearchJob {
  sid: string;
  dispatchState: string;
  doneProgress: number;
  resultCount: number;
  eventCount: number;
  scanCount: number;
  runDuration: number;
}

interface SplunkSearchResult {
  _raw: string;
  _time: string;
  host: string;
  source: string;
  sourcetype: string;
  [key: string]: unknown;
}

interface SplunkNotableEvent {
  event_id: string;
  rule_name: string;
  rule_title: string;
  security_domain: string;
  severity: string;
  urgency: string;
  status: string;
  owner: string;
  src: string;
  dest: string;
  src_ip: string;
  dest_ip: string;
  _time: string;
  description: string;
  drilldown_search: string;
}

export class SplunkClient extends BaseVendorClient {
  constructor(authConfig: VendorAuthConfig, connectionConfig: VendorConnectionConfig) {
    super("splunk", authConfig, connectionConfig);
  }

  getDisplayName(): string {
    return "Splunk Enterprise Security";
  }

  // ─── Token Authentication ──────────────────────────────────────────────────

  async authenticate(): Promise<void> {
    if (!this.authConfig.apiToken) {
      throw new VendorError("splunk", "Missing Splunk auth token", "AUTH_CONFIG_MISSING");
    }
    // Splunk uses "Bearer <token>" for API tokens
    this.setAuthHeader(this.authConfig.apiToken, "Bearer");
  }

  // ─── Health Check ──────────────────────────────────────────────────────────

  async healthCheck(): Promise<VendorHealthResult> {
    const start = Date.now();
    try {
      await this.request({
        method: "GET",
        url: "/services/server/info",
        params: { output_mode: "json" },
      });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "Splunk REST API is reachable and authenticated",
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: (error as Error).message,
      };
    }
  }

  // ─── Search Jobs ───────────────────────────────────────────────────────────

  async createSearchJob(spl: string, options?: { earliest?: string; latest?: string }): Promise<string> {
    const data: Record<string, string> = {
      search: spl.startsWith("search ") || spl.startsWith("|") ? spl : `search ${spl}`,
      output_mode: "json",
      exec_mode: "normal",
    };
    if (options?.earliest) data.earliest_time = options.earliest;
    if (options?.latest) data.latest_time = options.latest;

    const response = await this.request<{ sid: string }>({
      method: "POST",
      url: "/services/search/jobs",
      data: new URLSearchParams(data).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    return response.sid;
  }

  async getSearchJobStatus(sid: string): Promise<SplunkSearchJob> {
    const response = await this.request<{ entry: Array<{ content: SplunkSearchJob }> }>({
      method: "GET",
      url: `/services/search/jobs/${sid}`,
      params: { output_mode: "json" },
    });
    return response.entry?.[0]?.content;
  }

  async getSearchResults(sid: string, options?: { count?: number; offset?: number }): Promise<NormalizedVendorData[]> {
    const count = options?.count ?? 100;
    const offset = options?.offset ?? 0;

    const response = await this.request<{ results: SplunkSearchResult[] }>({
      method: "GET",
      url: `/services/search/jobs/${sid}/results`,
      params: { output_mode: "json", count, offset },
    });

    return (response.results || []).map((r, i) => this.normalizeSearchResult(r, i));
  }

  private normalizeSearchResult(r: SplunkSearchResult, index: number): NormalizedVendorData {
    return {
      id: `splunk-${index}-${Date.now()}`,
      type: "search_result",
      title: r.source || r.sourcetype || `Result ${index + 1}`,
      hostname: r.host,
      detectedAt: r._time ? new Date(r._time).getTime() : undefined,
      raw: r,
    };
  }

  // ─── One-shot Search (create + poll + return) ──────────────────────────────

  async search(spl: string, options?: { earliest?: string; latest?: string; maxWaitMs?: number; limit?: number }): Promise<NormalizedVendorData[]> {
    const sid = await this.createSearchJob(spl, options);
    const maxWait = options?.maxWaitMs ?? 60_000;
    const pollInterval = 2_000;
    let elapsed = 0;

    while (elapsed < maxWait) {
      const status = await this.getSearchJobStatus(sid);
      if (status.dispatchState === "DONE" || status.dispatchState === "FINALIZED") {
        return this.getSearchResults(sid, { count: options?.limit ?? 100 });
      }
      if (status.dispatchState === "FAILED") {
        throw new VendorError("splunk", `Search job ${sid} failed`, "SEARCH_FAILED");
      }
      await new Promise((r) => setTimeout(r, pollInterval));
      elapsed += pollInterval;
    }

    throw new VendorError("splunk", `Search job ${sid} timed out after ${maxWait}ms`, "SEARCH_TIMEOUT");
  }

  // ─── Notable Events (Enterprise Security) ─────────────────────────────────

  async queryNotableEvents(options?: VendorQueryOptions): Promise<NormalizedVendorData[]> {
    const earliest = options?.timeRange
      ? new Date(options.timeRange.start).toISOString()
      : "-24h";
    const latest = options?.timeRange
      ? new Date(options.timeRange.end).toISOString()
      : "now";

    const spl = `\`notable\` | head ${options?.limit ?? 100}`;
    const results = await this.search(spl, { earliest, latest, limit: options?.limit });

    return results.map((r) => {
      const raw = r.raw as SplunkNotableEvent;
      const severity = raw.urgency === "critical" ? "critical"
        : raw.urgency === "high" ? "high"
        : raw.urgency === "medium" ? "medium"
        : raw.urgency === "low" ? "low"
        : "informational";

      return {
        ...r,
        type: "alert" as const,
        title: raw.rule_title || raw.rule_name || r.title,
        severity,
        status: raw.status,
        hostname: raw.dest,
        ipAddress: raw.dest_ip || raw.src_ip,
      };
    });
  }

  // ─── Saved Searches ────────────────────────────────────────────────────────

  async listSavedSearches(): Promise<Array<{ name: string; search: string; description: string }>> {
    const response = await this.request<{ entry: Array<{ name: string; content: { search: string; description: string } }> }>({
      method: "GET",
      url: "/services/saved/searches",
      params: { output_mode: "json", count: 100 },
    });

    return (response.entry || []).map((e) => ({
      name: e.name,
      search: e.content.search,
      description: e.content.description,
    }));
  }

  async runSavedSearch(name: string): Promise<string> {
    const response = await this.request<{ sid: string }>({
      method: "POST",
      url: `/services/saved/searches/${encodeURIComponent(name)}/dispatch`,
      params: { output_mode: "json" },
    });
    return response.sid;
  }
}

export function createSplunkClient(
  authConfig: VendorAuthConfig,
  connectionConfig: VendorConnectionConfig
): SplunkClient {
  return new SplunkClient(authConfig, connectionConfig);
}
